use super::*;

pub(crate) fn packed_score_slot_selector(logical_indices: &[usize]) -> CanonicalResult<Vec<u64>> {
    let weights = logical_indices
        .iter()
        .map(|logical_index| (*logical_index, 1_u64))
        .collect::<Vec<_>>();

    packed_score_weighted_selector(&weights)
}

pub(crate) fn packed_score_weighted_selector(
    weights: &[(usize, u64)],
) -> CanonicalResult<Vec<u64>> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    for (logical_index, weight) in weights {
        slots[*logical_index] = weight % PLAINTEXT_MODULUS;
    }

    encode_slots_to_coefficients(&slots)
}

pub(crate) fn packed_pair_lower_mask(
    option_count: usize,
    shift: usize,
) -> CanonicalResult<Vec<u64>> {
    let logical_indices = (0..(option_count - shift)).collect::<Vec<_>>();

    packed_score_slot_selector(&logical_indices)
}
