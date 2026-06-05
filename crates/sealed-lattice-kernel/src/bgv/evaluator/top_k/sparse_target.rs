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

// Project encrypted ranks and indicators into the sparse WinnerRankTopK-v1
// target layout: TargetIdSlot[a] = (a+1)*indicator, TargetOrderSlot[a] =
// (rank+1)*indicator, packed into per-option slots with all other slots zero.
#[cfg(test)]
pub(crate) fn project_sparse_target(
    context: &EvaluatorContext,
    ranks: &[Ciphertext],
    indicators: &[Ciphertext],
    top_count: usize,
) -> CanonicalResult<EncryptedSparseTarget> {
    let option_count = ranks.len();
    if indicators.len() != option_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sparse target projection requires one indicator per option",
        ));
    }
    let mut id_slots = Vec::with_capacity(option_count);
    let mut order_slots = Vec::with_capacity(option_count);
    for option in 0..option_count {
        let indicator = &indicators[option];
        // TargetIdSlot[a] = (a + 1) * indicator (public scalar times indicator).
        let id_value = scalar_mul(
            indicator,
            i64::try_from(option + 1).expect("option fits i64"),
        )?;
        // TargetOrderSlot[a] is evaluated directly as rank + 1 inside the
        // selected prefix and zero outside it, avoiding an extra depth level.
        let order_value = top_k_order_value(context, &ranks[option], option_count, top_count)?;
        // Place each broadcast value into its option slot with a plaintext mask.
        id_slots.push(plaintext_mul(
            &normalize_scaling(&id_value)?,
            &slot_selector(option)?,
        )?);
        order_slots.push(plaintext_mul(
            &normalize_scaling(&order_value)?,
            &slot_selector(option)?,
        )?);
    }

    Ok(EncryptedSparseTarget {
        target_id: sum_aligned(&id_slots)?,
        target_order: sum_aligned(&order_slots)?,
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

    context.rotate_ciphertext(&selected, galois_element, selected.level, seed_hex)
}

// Run the encrypted top-k evaluation using the depth-efficient difference
// comparator (the reserved comparison-input derivation path) instead of per-bit
// extraction plus a bit-sliced comparator. The ahead indicator for an ordered
// pair is computed directly: greater-or-equal when the challenger has the lower
// index (tie goes to the lower index) and strictly-greater otherwise.
#[cfg(test)]
pub(crate) fn evaluate_top_k_via_difference(
    context: &EvaluatorContext,
    scores: &[Ciphertext],
    top_count: usize,
    score_domain_max: u64,
) -> CanonicalResult<TopKEvaluationOutputs> {
    let option_count = scores.len();
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "top-k evaluation requires at least two options",
        ));
    }
    let (greater_polynomial, greater_or_equal_polynomial) =
        comparison_polynomials(score_domain_max)?;
    let shift_constant = broadcast_constant(score_domain_max);

    let mut ranks = Vec::with_capacity(option_count);
    for option in 0..option_count {
        let mut ahead = Vec::with_capacity(option_count - 1);
        for challenger in 0..option_count {
            if challenger == option {
                continue;
            }
            let difference = ciphertext_sub(&scores[challenger], &scores[option])?;
            let shifted =
                add_plaintext_coefficients(&normalize_scaling(&difference)?, &shift_constant)?;
            let polynomial = if challenger < option {
                &greater_or_equal_polynomial
            } else {
                &greater_polynomial
            };
            let indicator = evaluate_direct_comparison_polynomial(context, &shifted, polynomial)?;
            ahead.push(indicator);
        }
        ranks.push(accumulate_rank(&ahead)?);
    }

    let indicators = ranks
        .iter()
        .map(|rank| top_k_indicator(context, rank, option_count, top_count))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let target = project_sparse_target(context, &ranks, &indicators, top_count)?;

    Ok(TopKEvaluationOutputs { ranks, target })
}
