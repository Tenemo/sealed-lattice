use super::*;

// A plaintext polynomial whose every slot holds the same constant value.
pub(crate) fn broadcast_constant(value: u64) -> Vec<u64> {
    broadcast_constant_coefficients(value)
}

// Add the slot-wise constant `value` to a scaling-one ciphertext.
#[cfg(test)]
pub(crate) fn add_constant(ciphertext: &Ciphertext, value: u64) -> CanonicalResult<Ciphertext> {
    let normalized = normalize_scaling(ciphertext)?;

    add_plaintext_coefficients(&normalized, &broadcast_constant(value))
}

// Logical NOT of an encrypted boolean (1 - bit), valid for scaling-one inputs.
#[cfg(test)]
pub(crate) fn boolean_not(ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
    let negated = ciphertext_negate(&normalize_scaling(ciphertext)?)?;

    add_plaintext_coefficients(&negated, &broadcast_constant(1))
}

// Bring several ciphertexts to a common level and scaling, then add them.
pub(crate) fn sum_aligned(ciphertexts: &[Ciphertext]) -> CanonicalResult<Ciphertext> {
    if ciphertexts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
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

pub(crate) fn add_to_aligned_sum(
    accumulator: &mut Option<Ciphertext>,
    term: Ciphertext,
) -> CanonicalResult<()> {
    *accumulator = Some(match accumulator.take() {
        Some(current) => sum_aligned(&[current, term])?,
        None => term,
    });

    Ok(())
}

pub(crate) fn require_aligned_sum(
    accumulator: Option<Ciphertext>,
    empty_message: &'static str,
) -> CanonicalResult<Ciphertext> {
    accumulator
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidFixture, empty_message))
}
