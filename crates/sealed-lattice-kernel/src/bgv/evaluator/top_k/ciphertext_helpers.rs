use super::*;

pub(crate) fn add_to_aligned_sum(
    accumulator: &mut Option<Ciphertext>,
    term: Ciphertext,
) -> CanonicalResult<()> {
    *accumulator = Some(match accumulator.take() {
        Some(current) => sum_aligned_ciphertexts(&[current, term])?,
        None => term,
    });

    Ok(())
}

pub(crate) fn require_aligned_sum(
    accumulator: Option<Ciphertext>,
    empty_message: &'static str,
) -> CanonicalResult<Ciphertext> {
    accumulator.ok_or_else(|| {
        CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, empty_message)
    })
}
