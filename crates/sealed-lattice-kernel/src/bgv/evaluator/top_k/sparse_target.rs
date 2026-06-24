use super::*;

pub(crate) fn project_packed_sparse_target_from_rank_evaluation(
    context: &EvaluatorContext,
    rank_evaluation: &PackedRankEvaluation,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<EncryptedSparseTarget> {
    let id_weights = (0..option_count)
        .map(|option| {
            (
                option,
                u64::try_from(option + 1).expect("option identifier fits u64"),
            )
        })
        .collect::<Vec<_>>();
    let option_indices = (0..option_count).collect::<Vec<_>>();
    let id_selector = packed_score_weighted_selector(&id_weights)?;
    let option_slot_mask = packed_score_slot_selector(&option_indices)?;

    if top_count == option_count {
        let normalized_ranks = normalize_scaling(&rank_evaluation.packed_ranks)?;
        let encrypted_zero = scalar_mul(&normalized_ranks, 0)?;

        return Ok(EncryptedSparseTarget {
            target_id: add_plaintext_coefficients(&encrypted_zero, &id_selector)?,
            target_order: add_plaintext_coefficients(&normalized_ranks, &option_slot_mask)?,
        });
    }

    let (indicators, order_values) = if rank_evaluation.exact_rank_indicators.len() >= top_count {
        let indicator_terms = rank_evaluation.exact_rank_indicators[..top_count].to_vec();
        let indicators = sum_aligned(&indicator_terms)?;
        let order_terms = rank_evaluation.exact_rank_indicators[..top_count]
            .iter()
            .enumerate()
            .map(|(rank_value, indicator)| {
                scalar_mul(
                    &normalize_scaling(indicator)?,
                    i64::try_from(rank_value + 1).expect("rank value fits i64"),
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let order_values = sum_aligned(&order_terms)?;

        (indicators, order_values)
    } else {
        top_k_indicator_and_order_value(
            context,
            &rank_evaluation.packed_ranks,
            option_count,
            top_count,
        )?
    };

    Ok(EncryptedSparseTarget {
        target_id: plaintext_mul(&normalize_scaling(&indicators)?, &id_selector)?,
        target_order: plaintext_mul(&normalize_scaling(&order_values)?, &option_slot_mask)?,
    })
}

pub(crate) fn move_single_slot_value(
    context: &EvaluatorContext,
    ciphertext: &Ciphertext,
    source_slot: usize,
    target_slot: usize,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    if source_slot >= POLYNOMIAL_DEGREE || target_slot >= POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "single-slot move requires source and target slots inside the ring",
        ));
    }
    let selected = plaintext_mul(
        &normalize_scaling(ciphertext)?,
        &slot_selector(source_slot)?,
    )?;
    if source_slot == target_slot {
        return Ok(selected);
    }
    let galois_element = galois_element_moving_slot_to_target(source_slot, target_slot)?;

    // Decompose the slot move through the compact generator basis so the
    // evaluator only ever requests scheduled basis rotation keys.
    rotate_with_compact_positive_generator_basis(
        context,
        &selected,
        galois_element,
        selected.level,
        seed_hex,
    )
}
