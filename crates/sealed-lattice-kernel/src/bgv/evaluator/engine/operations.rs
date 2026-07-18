use super::*;
use crate::bgv::{
    ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
    parameters::PLAINTEXT_MODULUS,
};

fn require_same_level(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<()> {
    if left.level != right.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV evaluator operation requires ciphertexts at the same modulus level",
        ));
    }

    Ok(())
}

fn require_same_shape(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<()> {
    require_same_level(left, right)?;
    if left.decrypt_scaling != right.decrypt_scaling {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV evaluator addition requires ciphertexts with the same scaling factor",
        ));
    }

    Ok(())
}

pub(crate) fn ciphertext_add(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<Ciphertext> {
    require_same_shape(left, right)?;
    let component_count = left.components.len().max(right.components.len());
    let primes = left.primes();
    let mut components = Vec::with_capacity(component_count);
    for component_index in 0..component_count {
        let mut limbs = Vec::with_capacity(primes.len());
        for (limb_index, modulus) in primes.iter().enumerate() {
            let left_limb = left
                .components
                .get(component_index)
                .map(|component| &component[limb_index]);
            let right_limb = right
                .components
                .get(component_index)
                .map(|component| &component[limb_index]);
            let limb = (0..POLYNOMIAL_DEGREE)
                .map(|coefficient_index| {
                    let left_value = left_limb.map_or(0, |limb| limb[coefficient_index]);
                    let right_value = right_limb.map_or(0, |limb| limb[coefficient_index]);
                    add_mod(left_value, right_value, *modulus)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            limbs.push(limb);
        }
        components.push(limbs);
    }

    Ok(Ciphertext {
        components,
        level: left.level,
        decrypt_scaling: left.decrypt_scaling,
    })
}

pub(crate) fn ciphertext_negate(ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .enumerate()
                .map(|(limb_index, limb)| {
                    let modulus = primes[limb_index];
                    limb.iter()
                        .map(|value| sub_mod(0, *value, modulus))
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

pub(crate) fn ciphertext_sub(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<Ciphertext> {
    ciphertext_add(left, &ciphertext_negate(right)?)
}

fn centered_plaintext_scalar(scalar: i64) -> i64 {
    let residue = signed_residue(scalar, PLAINTEXT_MODULUS);
    if residue > PLAINTEXT_MODULUS / 2 {
        i64::try_from(i128::from(residue) - i128::from(PLAINTEXT_MODULUS))
            .expect("centered plaintext scalar fits i64")
    } else {
        i64::try_from(residue).expect("centered plaintext scalar fits i64")
    }
}

pub(crate) fn scalar_mul(ciphertext: &Ciphertext, scalar: i64) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let centered_scalar = centered_plaintext_scalar(scalar);
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .enumerate()
                .map(|(limb_index, limb)| {
                    let modulus = primes[limb_index];
                    let scalar_lift = signed_residue(centered_scalar, modulus);
                    limb.iter()
                        .map(|value| mul_mod(*value, scalar_lift, modulus))
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

pub(crate) fn add_plaintext_coefficients(
    ciphertext: &Ciphertext,
    plaintext_coefficients: &[u64],
) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let mut result = ciphertext.clone();
    for (limb_index, modulus) in primes.iter().enumerate() {
        for (target, plaintext) in result.components[0][limb_index]
            .iter_mut()
            .zip(plaintext_coefficients.iter())
        {
            *target = add_mod(*target, plaintext % modulus, *modulus)?;
        }
    }

    Ok(result)
}

pub(crate) fn plaintext_mul(
    ciphertext: &Ciphertext,
    plaintext_coefficients: &[u64],
) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    #[cfg(not(target_arch = "wasm32"))]
    let limb_products = primes
        .par_iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            plaintext_mul_limb(ciphertext, plaintext_coefficients, limb_index, *modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let limb_products = primes
        .iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            plaintext_mul_limb(ciphertext, plaintext_coefficients, limb_index, *modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut components = (0..ciphertext.components.len())
        .map(|_| Vec::with_capacity(limb_products.len()))
        .collect::<Vec<_>>();
    for limb_product in limb_products {
        for (component_index, product) in limb_product.into_iter().enumerate() {
            components[component_index].push(product);
        }
    }

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

fn plaintext_mul_limb(
    ciphertext: &Ciphertext,
    plaintext_coefficients: &[u64],
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let lifted_plaintext = plaintext_coefficients
        .iter()
        .map(|coefficient| centered_plaintext_lift(*coefficient, modulus))
        .collect::<Vec<_>>();
    let plaintext_ntt = forward_negacyclic_ntt(&lifted_plaintext, modulus)?;
    ciphertext
        .components
        .iter()
        .map(|component| {
            let component_ntt = forward_negacyclic_ntt(&component[limb_index], modulus)?;
            let product_ntt = component_ntt
                .iter()
                .zip(plaintext_ntt.iter())
                .map(|(component_value, plaintext_value)| {
                    mul_mod_fast(*component_value, *plaintext_value, modulus)
                })
                .collect::<Vec<_>>();

            inverse_negacyclic_ntt(&product_ntt, modulus)
        })
        .collect()
}

// Center mod t before the RNS lift so a coefficient like t-1 multiplies as -1,
// not about t; the uncentered lift would blow up multiplicative noise by a
// factor of about t.
fn centered_plaintext_lift(coefficient: u64, modulus: u64) -> u64 {
    let coefficient = coefficient % PLAINTEXT_MODULUS;
    if coefficient > PLAINTEXT_MODULUS / 2 {
        signed_residue(
            i64::try_from(coefficient).expect("plaintext coefficient fits i64")
                - i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
            modulus,
        )
    } else {
        coefficient % modulus
    }
}

pub(crate) fn ciphertext_tensor(
    left: &Ciphertext,
    right: &Ciphertext,
) -> CanonicalResult<Ciphertext> {
    require_same_level(left, right)?;
    left.assert_two_components()?;
    right.assert_two_components()?;
    let primes = left.primes();

    #[cfg(not(target_arch = "wasm32"))]
    let tensor_limbs = primes
        .par_iter()
        .enumerate()
        .map(|(limb_index, modulus)| ciphertext_tensor_limb(left, right, limb_index, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let tensor_limbs = primes
        .iter()
        .enumerate()
        .map(|(limb_index, modulus)| ciphertext_tensor_limb(left, right, limb_index, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut component_zero = Vec::with_capacity(tensor_limbs.len());
    let mut component_one = Vec::with_capacity(tensor_limbs.len());
    let mut component_two = Vec::with_capacity(tensor_limbs.len());
    for (zero, one, two) in tensor_limbs {
        component_zero.push(zero);
        component_one.push(one);
        component_two.push(two);
    }

    Ok(Ciphertext {
        components: vec![component_zero, component_one, component_two],
        level: left.level,
        decrypt_scaling: mul_mod(
            left.decrypt_scaling,
            right.decrypt_scaling,
            PLAINTEXT_MODULUS,
        )?,
    })
}

fn ciphertext_tensor_limb(
    left: &Ciphertext,
    right: &Ciphertext,
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<(Vec<u64>, Vec<u64>, Vec<u64>)> {
    let left_zero_ntt = forward_negacyclic_ntt(&left.components[0][limb_index], modulus)?;
    let left_one_ntt = forward_negacyclic_ntt(&left.components[1][limb_index], modulus)?;
    let right_zero_ntt = forward_negacyclic_ntt(&right.components[0][limb_index], modulus)?;
    let right_one_ntt = forward_negacyclic_ntt(&right.components[1][limb_index], modulus)?;

    let mut zero_ntt = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut one_ntt = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut two_ntt = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for evaluation_index in 0..POLYNOMIAL_DEGREE {
        let left_zero = left_zero_ntt[evaluation_index];
        let left_one = left_one_ntt[evaluation_index];
        let right_zero = right_zero_ntt[evaluation_index];
        let right_one = right_one_ntt[evaluation_index];
        zero_ntt.push(mul_mod_fast(left_zero, right_zero, modulus));
        let cross = add_mod_fast(
            mul_mod_fast(left_zero, right_one, modulus),
            mul_mod_fast(left_one, right_zero, modulus),
            modulus,
        );
        one_ntt.push(cross);
        two_ntt.push(mul_mod_fast(left_one, right_one, modulus));
    }

    Ok((
        inverse_negacyclic_ntt(&zero_ntt, modulus)?,
        inverse_negacyclic_ntt(&one_ntt, modulus)?,
        inverse_negacyclic_ntt(&two_ntt, modulus)?,
    ))
}

pub(crate) fn modulus_switch(ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
    if ciphertext.level == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV evaluator cannot modulus switch below the smallest level",
        ));
    }
    let dropped_modulus = DATA_PRIMES[ciphertext.level];
    let remaining_primes = &DATA_PRIMES[..ciphertext.level];
    let dropped_inverses = remaining_primes
        .iter()
        .map(|modulus| inverse_mod(dropped_modulus % modulus, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let plaintext_inverse_mod_dropped =
        inverse_mod(PLAINTEXT_MODULUS % dropped_modulus, dropped_modulus)?;
    let half_dropped_modulus = dropped_modulus / 2;

    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            let dropped_limb = &component[ciphertext.level];
            let corrections = dropped_limb
                .iter()
                .map(|dropped_value| {
                    // BGV modulus switch: the correction is t * round((c_drop /
                    // t) / q_drop) so the plaintext residue mod t is preserved
                    // exactly; centering implements the rounding that minimizes
                    // added noise.
                    let scaled = mul_mod(
                        *dropped_value,
                        plaintext_inverse_mod_dropped,
                        dropped_modulus,
                    )?;
                    let centered = if scaled > half_dropped_modulus {
                        i128::from(scaled) - i128::from(dropped_modulus)
                    } else {
                        i128::from(scaled)
                    };
                    Ok(i128::from(PLAINTEXT_MODULUS) * centered)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            remaining_primes
                .iter()
                .enumerate()
                .map(|(limb_index, modulus)| {
                    let dropped_inverse = dropped_inverses[limb_index];
                    (0..POLYNOMIAL_DEGREE)
                        .map(|coefficient_index| {
                            let correction =
                                signed_residue_i128(corrections[coefficient_index], *modulus);
                            let difference = sub_mod(
                                component[limb_index][coefficient_index],
                                correction,
                                *modulus,
                            )?;
                            mul_mod(difference, dropped_inverse, *modulus)
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level - 1,
        decrypt_scaling: mul_mod(
            ciphertext.decrypt_scaling,
            dropped_modulus % PLAINTEXT_MODULUS,
            PLAINTEXT_MODULUS,
        )?,
    })
}

// Bring a ciphertext to an exact active data-basis prefix. A ciphertext already
// at or below the requested level is returned unchanged; the compiled evaluator
// validates its monotone level schedule before execution.
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

// Rewrite a ciphertext so its tracked plaintext-field scaling is one. BGV
// modulus switching leaves the raw plaintext multiplied by the inverse of the
// tracked factor; multiplying every residue by that factor restores the
// unscaled plaintext and makes same-level ciphertexts additively compatible.
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

fn signed_residue_i128(value: i128, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = ((value % modulus_i128) + modulus_i128) % modulus_i128;

    u64::try_from(reduced).expect("residue below a u64 modulus fits u64")
}
