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

    let (indicators, order_values) = top_k_indicator_and_order_value(
        context,
        &rank_evaluation.packed_ranks,
        option_count,
        top_count,
    )?;

    Ok(EncryptedSparseTarget {
        target_id: plaintext_mul(&normalize_scaling(&indicators)?, &id_selector)?,
        target_order: plaintext_mul(&normalize_scaling(&order_values)?, &option_slot_mask)?,
    })
}
