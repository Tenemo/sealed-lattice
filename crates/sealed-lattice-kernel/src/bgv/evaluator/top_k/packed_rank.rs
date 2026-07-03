use super::*;

pub(crate) fn evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
    context: &EvaluatorContext,
    packed_scores: &Ciphertext,
    option_count: usize,
    score_domain_max: u64,
    seed_hex: &str,
) -> CanonicalResult<PackedRankEvaluation> {
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "batched packed-rank evaluation requires at least two options",
        ));
    }
    if option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "batched packed-rank evaluation exceeds the generator-ordered slot window",
        ));
    }
    let pair_count = option_count * option_count.saturating_sub(1) / 2;
    if pair_count > GENERATOR_SUBGROUP_ORDER {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "batched packed-rank evaluation exceeds the generator subgroup slot window",
        ));
    }
    // Only greater_or_equal is evaluated, so on a tie the lower option index
    // wins; its complement (mask minus the indicator) is the strict-less
    // indicator for the higher index, realizing the tie policy.
    let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_max)?;
    let shift_constant = broadcast_constant(score_domain_max);
    let mut comparison_input_sum = None;
    let mut pair_windows = Vec::with_capacity(option_count - 1);
    // Pack pair windows contiguously: the forward pass rotates each shift-s
    // window to next_window_offset for one batched comparison, the return pass
    // rotates each result back to its pair's generator slot, and offset 0 needs
    // no realigning rotation in either direction.
    let mut next_window_offset = 0_usize;
    for shift in 1..option_count {
        let pair_window_size = option_count - shift;
        pair_windows.push((shift, next_window_offset, pair_window_size));
        let shifted_scores = rotate_with_compact_positive_generator_basis(
            context,
            packed_scores,
            galois_power(shift),
            packed_scores.level,
            &format!("{seed_hex}-batched-pair-score-shift-{shift}"),
        )?;
        let difference = ciphertext_sub(packed_scores, &shifted_scores)?;
        // Shift the signed difference into [0, 2*score_domain_max] so the
        // order-less plaintext field can be compared by a step polynomial; this
        // requires 2*score_domain_max < t to avoid wraparound.
        let shifted_difference =
            add_plaintext_coefficients(&normalize_scaling(&difference)?, &shift_constant)?;
        let lower_pair_inputs = plaintext_mul(
            &normalize_scaling(&shifted_difference)?,
            &packed_pair_lower_mask(option_count, shift)?,
        )?;
        let windowed_inputs = if next_window_offset == 0 {
            lower_pair_inputs
        } else {
            rotate_with_compact_inverse_generator_basis(
                context,
                &lower_pair_inputs,
                next_window_offset,
                lower_pair_inputs.level,
                &format!("{seed_hex}-batched-pair-window-{shift}"),
            )?
        };
        add_to_aligned_sum(&mut comparison_input_sum, windowed_inputs)?;
        next_window_offset += pair_window_size;
    }
    let comparison_inputs = require_aligned_sum(
        comparison_input_sum,
        "batched packed-rank evaluation did not produce comparison inputs",
    )?;
    let refreshed_comparison_inputs = modulus_switch_to(
        &comparison_inputs,
        comparison_inputs.level.saturating_sub(1),
    )?;
    drop(comparison_inputs);
    let comparison_baby_step_count = direct_comparison_baby_step_count(score_domain_max)?;
    let comparison_outputs = evaluate_direct_comparison_polynomial_with_baby_step_count(
        context,
        &refreshed_comparison_inputs,
        &greater_or_equal_polynomial,
        comparison_baby_step_count,
    )?;
    drop(refreshed_comparison_inputs);
    drop(greater_or_equal_polynomial);

    let mut rank_sum = None;
    for (shift, window_offset, pair_window_size) in pair_windows {
        let window_logical_indices =
            (window_offset..(window_offset + pair_window_size)).collect::<Vec<_>>();
        let windowed_lower_beats_higher = plaintext_mul(
            &normalize_scaling(&comparison_outputs)?,
            &packed_score_slot_selector(&window_logical_indices)?,
        )?;
        let lower_beats_higher = if window_offset == 0 {
            windowed_lower_beats_higher
        } else {
            rotate_with_compact_positive_generator_basis(
                context,
                &windowed_lower_beats_higher,
                galois_power(window_offset),
                windowed_lower_beats_higher.level,
                &format!("{seed_hex}-batched-pair-window-return-{shift}"),
            )?
        };
        let lower_pair_mask = packed_pair_lower_mask(option_count, shift)?;
        let lower_beats_higher_for_lower_slots =
            plaintext_mul(&normalize_scaling(&lower_beats_higher)?, &lower_pair_mask)?;
        let higher_beats_lower_for_lower_slots = add_plaintext_coefficients(
            &ciphertext_negate(&normalize_scaling(&lower_beats_higher_for_lower_slots)?)?,
            &lower_pair_mask,
        )?;
        let lower_beats_higher_for_return = modulus_switch_to(
            &lower_beats_higher_for_lower_slots,
            DIRECT_COMPARISON_OUTPUT_LEVEL,
        )?;
        let lower_beats_higher_at_higher_slot = rotate_with_compact_inverse_generator_basis(
            context,
            &lower_beats_higher_for_return,
            shift,
            lower_beats_higher_for_return.level,
            &format!("{seed_hex}-batched-pair-rank-return-{shift}"),
        )?;
        add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }
    drop(comparison_outputs);

    let packed_ranks = require_aligned_sum(
        rank_sum,
        "batched packed-rank evaluation did not produce rank terms",
    )?;

    Ok(PackedRankEvaluation { packed_ranks })
}
