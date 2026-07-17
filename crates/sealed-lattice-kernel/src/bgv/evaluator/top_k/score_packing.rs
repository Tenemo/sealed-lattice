use super::*;

pub(crate) fn galois_element_moving_slot_to_target(
    source_slot: usize,
    target_slot: usize,
) -> CanonicalResult<usize> {
    if source_slot >= POLYNOMIAL_DEGREE || target_slot >= POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "slot move requires source and target slots inside the selected ring",
        ));
    }
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let source_exponent = logical_slot_galois_element(source_slot)?;
    let target_exponent = logical_slot_galois_element(target_slot)?;
    let inverse_target_exponent = inverse_galois_element(target_exponent)?;

    Ok((source_exponent * inverse_target_exponent) % ring_order)
}

pub(crate) fn direct_score_packing_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "direct score packing requires at least two options and a valid packed window",
        ));
    }
    Ok(vec![galois_element_moving_slot_to_target(0, option_count)?])
}

pub(crate) fn pack_direct_score_slots(
    context: &EvaluatorContext,
    direct_scores: &Ciphertext,
    option_count: usize,
) -> CanonicalResult<Ciphertext> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "direct score-slot packing requires at least two options and a valid packed window",
        ));
    }
    let option_indices = (0..option_count).collect::<Vec<_>>();
    let selected_scores = plaintext_mul(
        &normalize_scaling(direct_scores)?,
        &packed_score_slot_selector(&option_indices)?,
    )?;
    let duplicated_scores =
        rotate_with_compact_inverse_generator_basis(context, &selected_scores, option_count)?;

    sum_aligned_ciphertexts(&[selected_scores, duplicated_scores])
}

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
