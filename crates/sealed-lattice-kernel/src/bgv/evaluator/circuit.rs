use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::{collections::BTreeMap, sync::RwLock};

use crate::{
    bgv::{
        evaluator::{
            engine::{
                Ciphertext, DevelopmentBgvKey, add_plaintext_coefficients, ciphertext_add,
                ciphertext_tensor, modulus_switch, scalar_mul,
            },
            key_switch::{
                KeySwitchKey, generate_galois_key, generate_relinearization_key, relinearize,
                rotate,
            },
        },
        modular_arithmetic::mul_mod,
        parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

// The evaluator context owns the development key set and the evaluation keys
// needed by homomorphic multiplication and rotation. One relinearization key
// at the working level serves every reachable level: lower levels retain the
// active data-prime block prefix and the complete special basis. Native runs
// retain one rotation key per Galois element at the working level; lower-level
// rotations project that same key through the active CRT prefix.
pub(crate) struct EvaluatorContext {
    key: DevelopmentBgvKey,
    working_level: usize,
    relinearization_key: KeySwitchKey,
    galois_key_seed_hex: String,
    #[cfg(not(target_arch = "wasm32"))]
    generated_rotation_keys: RwLock<BTreeMap<usize, Arc<KeySwitchKey>>>,
}

impl EvaluatorContext {
    #[cfg(test)]
    pub(crate) fn new(seed_hex: &str, working_level: usize) -> CanonicalResult<Self> {
        let key = DevelopmentBgvKey::generate(seed_hex)?;
        Self::from_key(key, seed_hex, working_level)
    }

    pub(crate) fn from_key(
        key: DevelopmentBgvKey,
        key_switch_seed_hex: &str,
        working_level: usize,
    ) -> CanonicalResult<Self> {
        let relinearization_key = generate_relinearization_key(
            &key,
            working_level,
            &format!("{key_switch_seed_hex}-relin"),
        )?;
        let galois_key_seed_hex =
            format!("{key_switch_seed_hex}-galois-keys-level-{working_level}");

        Ok(Self {
            key,
            working_level,
            relinearization_key,
            galois_key_seed_hex,
            #[cfg(not(target_arch = "wasm32"))]
            generated_rotation_keys: RwLock::new(BTreeMap::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn key(&self) -> &DevelopmentBgvKey {
        &self.key
    }

    pub(crate) fn working_level(&self) -> usize {
        self.working_level
    }

    fn relinearization_key(&self, level: usize) -> CanonicalResult<&KeySwitchKey> {
        if self.relinearization_key.level < level {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "no relinearization key for the requested level",
            ));
        }

        Ok(&self.relinearization_key)
    }

    pub(crate) fn resolve_galois_key(
        &self,
        galois_element: usize,
        requested_level: usize,
    ) -> CanonicalResult<Arc<KeySwitchKey>> {
        if requested_level > self.working_level {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "requested Galois-key level exceeds the evaluator working level",
            ));
        }

        #[cfg(target_arch = "wasm32")]
        {
            // Browser runs keep only the key needed by the current rotation.
            // Generating the requested active prefix avoids retaining the
            // working-level schedule in constrained WASM memory. The stable
            // context seed makes that prefix identical to the native cached
            // working-level key under CRT truncation.
            Ok(Arc::new(generate_galois_key(
                &self.key,
                galois_element,
                requested_level,
                &self.galois_key_seed_hex,
            )?))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            // The read guard must drop before the write acquisition below, or
            // the first cache miss deadlocks on the same thread.
            {
                let generated_rotation_keys =
                    self.generated_rotation_keys.read().map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidProtocolObject,
                            "generated rotation-key cache is poisoned",
                        )
                    })?;
                if let Some(rotation_key) = generated_rotation_keys.get(&galois_element) {
                    return Ok(Arc::clone(rotation_key));
                }
            }

            let mut generated_rotation_keys =
                self.generated_rotation_keys.write().map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidProtocolObject,
                        "generated rotation-key cache is poisoned",
                    )
                })?;
            if let Some(rotation_key) = generated_rotation_keys.get(&galois_element) {
                return Ok(Arc::clone(rotation_key));
            }
            // Keep generation under the exclusive guard so concurrent callers
            // cannot materialize duplicate giant keys on the same cache miss.
            let scheduled_key = Arc::new(generate_galois_key(
                &self.key,
                galois_element,
                self.working_level,
                &self.galois_key_seed_hex,
            )?);
            generated_rotation_keys.insert(galois_element, Arc::clone(&scheduled_key));

            Ok(scheduled_key)
        }
    }

    pub(crate) fn rotate_ciphertext(
        &self,
        ciphertext: &Ciphertext,
        galois_element: usize,
    ) -> CanonicalResult<Ciphertext> {
        let generated_rotation_key = self.resolve_galois_key(galois_element, ciphertext.level)?;

        rotate(ciphertext, galois_element, generated_rotation_key.as_ref())
    }
}

// Modulus switch a ciphertext down to a target level (no-op if already at or
// below the target).
pub(crate) fn modulus_switch_to(
    ciphertext: &Ciphertext,
    target_level: usize,
) -> CanonicalResult<Ciphertext> {
    let mut current = ciphertext.clone();
    while current.level > target_level {
        current = modulus_switch(&current)?;
    }

    Ok(current)
}

// Rewrite a ciphertext so its scaling factor is one, by multiplying every
// polynomial coefficient by the tracked scaling. After this the logical message
// is unchanged but the raw decryption equals the message, so ciphertexts at the
// same level become additively compatible.
pub(crate) fn normalize_scaling(ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
    if ciphertext.decrypt_scaling == 1 {
        return Ok(ciphertext.clone());
    }
    let primes = ciphertext.primes();
    let factor = ciphertext.decrypt_scaling;
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .enumerate()
                .map(|(limb_index, limb)| {
                    let modulus = primes[limb_index];
                    let factor_in_limb = factor % modulus;
                    limb.iter()
                        .map(|value| mul_mod(*value, factor_in_limb, modulus))
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: 1,
    })
}

// Homomorphic ciphertext multiplication that consumes one modulus level:
// level-match the operands, tensor, relinearize back to two components, then
// modulus switch once to keep the noise bounded.
pub(crate) fn multiply(
    context: &EvaluatorContext,
    left: &Ciphertext,
    right: &Ciphertext,
) -> CanonicalResult<Ciphertext> {
    let target_level = left.level.min(right.level);
    let left_matched = modulus_switch_to(left, target_level)?;
    let right_matched = modulus_switch_to(right, target_level)?;
    let product = ciphertext_tensor(&left_matched, &right_matched)?;
    let relinearized = relinearize(&product, context.relinearization_key(target_level)?)?;

    modulus_switch(&relinearized)
}

// A plaintext polynomial whose every slot holds the same constant value.
pub(crate) fn broadcast_constant_coefficients(value: u64) -> Vec<u64> {
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    coefficients[0] = value % PLAINTEXT_MODULUS;

    coefficients
}

// Evaluate a univariate polynomial (plaintext coefficients in the plaintext
// field, lowest degree first) on an encrypted input, slot-wise. Powers are
// computed with a balanced multiplication tree so the multiplicative depth is
// logarithmic in the degree; the terms are then brought to a common level and
// scaling before the linear combination.
pub(crate) fn evaluate_polynomial_with_fixed_baby_step_count_and_deferred_terminal_switch(
    context: &EvaluatorContext,
    input: &Ciphertext,
    coefficients: &[u64],
    baby_step_count: usize,
) -> CanonicalResult<Ciphertext> {
    evaluate_polynomial_paterson_stockmeyer_with_baby_step_count(
        context,
        input,
        coefficients,
        baby_step_count,
        true,
    )
}

fn evaluate_polynomial_by_power_table(
    context: &EvaluatorContext,
    input: &Ciphertext,
    coefficients: &[u64],
) -> CanonicalResult<Ciphertext> {
    if coefficients.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "polynomial evaluation requires at least the constant coefficient",
        ));
    }
    let degree = coefficients.len() - 1;
    let working_input = modulus_switch_to(input, context.working_level())?;
    let mut powers: Vec<Option<Ciphertext>> = vec![None; degree + 1];
    if degree >= 1 {
        powers[1] = Some(working_input.clone());
    }
    for power in 2..=degree {
        if coefficients[power] == 0 && !higher_power_needed(coefficients, power) {
            continue;
        }
        let low = power / 2;
        let high = power - low;
        let low_power = powers[low].as_ref().ok_or_else(missing_power)?;
        let high_power = powers[high].as_ref().ok_or_else(missing_power)?;
        powers[power] = Some(multiply(context, low_power, high_power)?);
    }

    let target_level = (1..=degree)
        .filter(|power| coefficients[*power] != 0)
        .filter_map(|power| powers[power].as_ref().map(|ciphertext| ciphertext.level))
        .min();

    // The constant term anchors the accumulator at the target level and scaling.
    let anchor_level = target_level.unwrap_or(working_input.level);
    let anchor = normalize_scaling(&modulus_switch_to(&working_input, anchor_level)?)?;
    // scalar_mul(anchor, 0) materializes an encrypted zero at the target level
    // and scaling so the plaintext constant term is added into a shape-compatible
    // ciphertext.
    let mut result = add_plaintext_coefficients(
        &scalar_mul(&anchor, 0)?,
        &broadcast_constant_coefficients(coefficients[0]),
    )?;
    for power in 1..=degree {
        if coefficients[power] == 0 {
            continue;
        }
        let power_ciphertext = powers[power].as_ref().ok_or_else(missing_power)?;
        let leveled = normalize_scaling(&modulus_switch_to(power_ciphertext, anchor_level)?)?;
        let scaled = scalar_mul(
            &leveled,
            i64::try_from(coefficients[power]).expect("coefficient fits i64"),
        )?;
        result = ciphertext_add(&result, &scaled)?;
    }

    Ok(result)
}

fn evaluate_polynomial_paterson_stockmeyer_with_baby_step_count(
    context: &EvaluatorContext,
    input: &Ciphertext,
    coefficients: &[u64],
    baby_step_count: usize,
    defer_terminal_modulus_switch: bool,
) -> CanonicalResult<Ciphertext> {
    if coefficients.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "polynomial evaluation requires at least the constant coefficient",
        ));
    }
    if baby_step_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "Paterson-Stockmeyer baby-step count must be at least two",
        ));
    }
    let degree = coefficients.len() - 1;
    if degree == 0 || degree < baby_step_count {
        return evaluate_polynomial_by_power_table(context, input, coefficients);
    }

    let block_count = coefficients.len().div_ceil(baby_step_count);
    let working_input = modulus_switch_to(input, context.working_level())?;

    let baby_powers = build_power_table(context, &working_input, baby_step_count)?;
    let giant_base = baby_powers[baby_step_count]
        .as_ref()
        .ok_or_else(missing_power)?
        .clone();
    let giant_powers = build_power_table(context, &giant_base, block_count.saturating_sub(1))?;

    let mut terms = Vec::new();
    for (block_index, giant_power) in giant_powers.iter().enumerate().take(block_count) {
        let start = block_index * baby_step_count;
        let end = coefficients.len().min(start + baby_step_count);
        let block_coefficients = &coefficients[start..end];
        if block_coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            continue;
        }
        let block_value =
            linear_combination_from_powers(&working_input, &baby_powers, block_coefficients)?;
        // Paterson-Stockmeyer: block 0 multiplies the identity giant power (skip
        // the product), and a block with only a constant term folds into a
        // scalar multiply rather than a ciphertext multiply.
        if block_index == 0 {
            terms.push(block_value);
            continue;
        }
        let giant_power = giant_power.as_ref().ok_or_else(missing_power)?;
        if block_coefficients[1..]
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            terms.push(scalar_mul(
                giant_power,
                i64::try_from(block_coefficients[0]).expect("coefficient fits i64"),
            )?);
        } else {
            let product = if defer_terminal_modulus_switch {
                multiply_without_immediate_modulus_switch(context, &block_value, giant_power)?
            } else {
                multiply(context, &block_value, giant_power)?
            };
            terms.push(product);
        }
    }

    if terms.is_empty() {
        return evaluate_polynomial_by_power_table(context, input, &[0]);
    }

    sum_ciphertexts_at_common_level(&terms)
}

// Defer the terminal modulus switch so the comparison output keeps one extra
// level for the downstream rank-prefix projection; noise is still bounded
// because no further multiply follows in this block.
pub(crate) fn multiply_without_immediate_modulus_switch(
    context: &EvaluatorContext,
    left: &Ciphertext,
    right: &Ciphertext,
) -> CanonicalResult<Ciphertext> {
    let target_level = left.level.min(right.level);
    let left_matched = modulus_switch_to(left, target_level)?;
    let right_matched = modulus_switch_to(right, target_level)?;
    let product = ciphertext_tensor(&left_matched, &right_matched)?;

    relinearize(&product, context.relinearization_key(target_level)?)
}

fn build_power_table(
    context: &EvaluatorContext,
    base: &Ciphertext,
    highest_power: usize,
) -> CanonicalResult<Vec<Option<Ciphertext>>> {
    let mut powers: Vec<Option<Ciphertext>> = vec![None; highest_power + 1];
    if highest_power >= 1 {
        powers[1] = Some(base.clone());
    }
    for power in 2..=highest_power {
        let low = power / 2;
        let high = power - low;
        let low_power = powers[low].as_ref().ok_or_else(missing_power)?;
        let high_power = powers[high].as_ref().ok_or_else(missing_power)?;
        powers[power] = Some(multiply(context, low_power, high_power)?);
    }

    Ok(powers)
}

fn linear_combination_from_powers(
    reference: &Ciphertext,
    powers: &[Option<Ciphertext>],
    coefficients: &[u64],
) -> CanonicalResult<Ciphertext> {
    let target_level = coefficients
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, coefficient)| **coefficient != 0)
        .filter_map(|(power, _)| powers[power].as_ref().map(|ciphertext| ciphertext.level))
        .min();
    let anchor_level = target_level.unwrap_or(reference.level);
    let anchor = normalize_scaling(&modulus_switch_to(reference, anchor_level)?)?;
    let mut result = add_plaintext_coefficients(
        &scalar_mul(&anchor, 0)?,
        &broadcast_constant_coefficients(coefficients[0]),
    )?;
    for power in 1..coefficients.len() {
        if coefficients[power] == 0 {
            continue;
        }
        let power_ciphertext = powers[power].as_ref().ok_or_else(missing_power)?;
        let leveled = normalize_scaling(&modulus_switch_to(power_ciphertext, anchor_level)?)?;
        let scaled = scalar_mul(
            &leveled,
            i64::try_from(coefficients[power]).expect("coefficient fits i64"),
        )?;
        result = ciphertext_add(&result, &scaled)?;
    }

    Ok(result)
}

fn sum_ciphertexts_at_common_level(ciphertexts: &[Ciphertext]) -> CanonicalResult<Ciphertext> {
    if ciphertexts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "cannot sum an empty ciphertext set",
        ));
    }
    let target_level = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.level)
        .min()
        .expect("non-empty set has a minimum level");
    let mut accumulator = normalize_scaling(&modulus_switch_to(&ciphertexts[0], target_level)?)?;
    for ciphertext in &ciphertexts[1..] {
        let aligned = normalize_scaling(&modulus_switch_to(ciphertext, target_level)?)?;
        accumulator = ciphertext_add(&accumulator, &aligned)?;
    }

    Ok(accumulator)
}

fn higher_power_needed(coefficients: &[u64], power: usize) -> bool {
    // A power is needed if it is itself used or if it is a building block for a
    // larger used power. The balanced tree only ever splits into halves, so any
    // power up to the degree may be required; keep it simple and always build.
    coefficients[power..]
        .iter()
        .any(|coefficient| *coefficient != 0)
}

fn missing_power() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "polynomial evaluation reached a power that was not built",
    )
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_arch = "wasm32"))]
    use std::sync::Arc;

    #[cfg(not(target_arch = "wasm32"))]
    use super::EvaluatorContext;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn evaluator_context_reuses_one_scheduled_galois_key_across_requested_levels() {
        let context =
            EvaluatorContext::new("scheduled-galois-key-reuse", 2).expect("evaluator context");
        let working_level_key = context
            .resolve_galois_key(3, 2)
            .expect("working-level Galois key");
        let lower_level_key = context
            .resolve_galois_key(3, 0)
            .expect("lower-level Galois-key use");

        assert!(Arc::ptr_eq(&working_level_key, &lower_level_key));
        assert_eq!(working_level_key.level, 2);
        assert_eq!(
            context
                .generated_rotation_keys
                .read()
                .expect("rotation-key cache")
                .len(),
            1
        );

        let error = context
            .resolve_galois_key(3, 3)
            .err()
            .expect("a level above the context must be refused");
        assert!(
            error
                .message
                .contains("exceeds the evaluator working level")
        );
    }
}
