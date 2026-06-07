use super::*;

// The plaintext selector polynomial placing a broadcast value into a single
// target slot.
pub(crate) fn slot_selector(slot: usize) -> CanonicalResult<Vec<u64>> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    slots[slot] = 1;

    encode_slots_to_coefficients(&slots)
}

pub(crate) fn packed_score_slot(logical_index: usize) -> usize {
    (galois_power(logical_index) - 1) / 2
}

pub(crate) fn galois_element_moving_slot_to_target(
    source_slot: usize,
    target_slot: usize,
) -> CanonicalResult<usize> {
    if source_slot >= POLYNOMIAL_DEGREE || target_slot >= POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "slot move requires source and target slots inside the selected ring",
        ));
    }
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let source_odd = 2 * source_slot + 1;
    let target_odd = 2 * target_slot + 1;
    let inverse_target_odd = inverse_galois_element(target_odd)?;

    Ok((source_odd * inverse_target_odd) % ring_order)
}

pub(crate) fn direct_score_packing_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct score packing requires at least two options and a valid packed window",
        ));
    }
    let mut elements = BTreeSet::new();
    for option_index in 0..option_count {
        let source_slot = option_index;
        for target_logical_index in [option_index, option_index + option_count] {
            let target_slot = packed_score_slot(target_logical_index);
            let galois_element = galois_element_moving_slot_to_target(source_slot, target_slot)?;
            if galois_element != 1 {
                elements.insert(galois_element);
            }
        }
    }

    Ok(elements.into_iter().collect())
}

pub(crate) fn pack_direct_score_slots(
    context: &EvaluatorContext,
    direct_scores: &Ciphertext,
    option_count: usize,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct score-slot packing requires at least two options and a valid packed window",
        ));
    }
    let normalized_scores = normalize_scaling(direct_scores)?;
    let mut packed_terms = Vec::with_capacity(option_count * 2);
    let rotation_seed = format!("{seed_hex}-direct-score-pack-rotation");
    for option in 0..option_count {
        for logical_index in [option, option + option_count] {
            packed_terms.push(move_single_slot_value(
                context,
                &normalized_scores,
                option,
                packed_score_slot(logical_index),
                &rotation_seed,
            )?);
        }
    }

    sum_aligned(&packed_terms)
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
        slots[packed_score_slot(*logical_index)] = weight % PLAINTEXT_MODULUS;
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
