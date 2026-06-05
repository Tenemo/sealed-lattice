use super::*;

#[cfg(test)]
pub(crate) fn evaluate_packed_ranks_via_difference(
    context: &EvaluatorContext,
    scores: &[Ciphertext],
    score_domain_max: u64,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    let option_count = scores.len();
    let packed_scores = pack_broadcast_scores(scores)?;

    evaluate_packed_ranks_from_packed_scores(
        context,
        &packed_scores,
        option_count,
        score_domain_max,
        seed_hex,
    )
}

#[cfg(test)]
pub(crate) fn evaluate_packed_ranks_from_packed_scores(
    context: &EvaluatorContext,
    packed_scores: &Ciphertext,
    option_count: usize,
    score_domain_max: u64,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    Ok(evaluate_packed_rank_evaluation_from_packed_scores(
        context,
        packed_scores,
        option_count,
        score_domain_max,
        seed_hex,
        0,
    )?
    .packed_ranks)
}

#[cfg(test)]
pub(crate) fn evaluate_packed_rank_evaluation_from_packed_scores(
    context: &EvaluatorContext,
    packed_scores: &Ciphertext,
    option_count: usize,
    score_domain_max: u64,
    seed_hex: &str,
    exact_rank_count: usize,
) -> CanonicalResult<PackedRankEvaluation> {
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "packed top-k rank evaluation requires at least two options",
        ));
    }
    if option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "packed top-k rank evaluation exceeds the generator-ordered slot window",
        ));
    }
    if exact_rank_count > option_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "exact rank derivation cannot request more ranks than options",
        ));
    }
    let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_max)?;
    let shift_constant = broadcast_constant(score_domain_max);
    let mut rank_terms = Vec::with_capacity(2 * (option_count - 1));
    let mut ahead_terms_by_option = vec![Vec::with_capacity(option_count - 1); option_count];
    for shift in 1..option_count {
        let galois_element = galois_power(shift);
        let shifted_scores = rotate_with_compact_positive_generator_basis(
            context,
            packed_scores,
            galois_element,
            packed_scores.level,
            &format!("{seed_hex}-packed-rank-galois-{shift}"),
        )?;
        let difference = ciphertext_sub(packed_scores, &shifted_scores)?;
        let shifted_difference =
            add_plaintext_coefficients(&normalize_scaling(&difference)?, &shift_constant)?;
        let refreshed_shifted_difference = modulus_switch_to(
            &shifted_difference,
            shifted_difference.level.saturating_sub(1),
        )?;
        let greater_or_equal = evaluate_direct_comparison_polynomial(
            context,
            &refreshed_shifted_difference,
            &greater_or_equal_polynomial,
        )?;
        let lower_pair_mask = packed_pair_lower_mask(option_count, shift)?;
        let lower_beats_higher =
            plaintext_mul(&normalize_scaling(&greater_or_equal)?, &lower_pair_mask)?;
        let negated_lower_beats_higher =
            ciphertext_negate(&normalize_scaling(&lower_beats_higher)?)?;
        let higher_beats_lower =
            add_plaintext_coefficients(&negated_lower_beats_higher, &lower_pair_mask)?;
        let lower_beats_higher_for_return =
            modulus_switch_to(&lower_beats_higher, DIRECT_COMPARISON_OUTPUT_LEVEL)?;
        let lower_beats_higher_at_higher_slot = rotate_with_compact_inverse_generator_basis(
            context,
            &lower_beats_higher_for_return,
            shift,
            lower_beats_higher_for_return.level,
            &format!("{seed_hex}-packed-rank-inverse-galois-{shift}"),
        )?;
        for lower_option in 0..(option_count - shift) {
            let higher_option = lower_option + shift;
            ahead_terms_by_option[lower_option].push(higher_beats_lower.clone());
            ahead_terms_by_option[higher_option].push(lower_beats_higher_at_higher_slot.clone());
        }
        rank_terms.push(higher_beats_lower);
        rank_terms.push(lower_beats_higher_at_higher_slot);
    }

    let packed_ranks = sum_aligned(&rank_terms)?;
    let exact_rank_indicators = if exact_rank_count == 0 {
        Vec::new()
    } else {
        exact_rank_indicators_from_ahead_terms(
            context,
            &ahead_terms_by_option,
            option_count,
            exact_rank_count,
        )?
    };

    Ok(PackedRankEvaluation {
        packed_ranks,
        exact_rank_indicators,
    })
}

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
    let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_max)?;
    let shift_constant = broadcast_constant(score_domain_max);
    let mut comparison_input_sum = None;
    let mut pair_windows = Vec::with_capacity(option_count - 1);
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

    Ok(PackedRankEvaluation {
        packed_ranks,
        exact_rank_indicators: Vec::new(),
    })
}

#[cfg(test)]
pub(crate) fn exact_rank_indicators_from_ahead_terms(
    context: &EvaluatorContext,
    ahead_terms_by_option: &[Vec<Ciphertext>],
    option_count: usize,
    exact_rank_count: usize,
) -> CanonicalResult<Vec<Ciphertext>> {
    let mut masked_terms_by_rank = vec![Vec::with_capacity(option_count); exact_rank_count];
    for (option_index, ahead_terms) in ahead_terms_by_option.iter().enumerate() {
        if ahead_terms.len() != option_count - 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "exact rank derivation requires one ahead indicator for every other option",
            ));
        }
        let option_rank_indicators =
            exact_rank_indicators_for_option(context, ahead_terms, exact_rank_count)?;
        let option_selector = packed_score_slot_selector(&[option_index])?;
        for (rank_value, indicator) in option_rank_indicators.iter().enumerate() {
            masked_terms_by_rank[rank_value].push(plaintext_mul(
                &normalize_scaling(indicator)?,
                &option_selector,
            )?);
        }
    }

    masked_terms_by_rank
        .into_iter()
        .map(|rank_terms| sum_aligned(&rank_terms))
        .collect()
}

#[cfg(test)]
pub(crate) fn exact_rank_indicators_for_option(
    context: &EvaluatorContext,
    ahead_terms: &[Ciphertext],
    exact_rank_count: usize,
) -> CanonicalResult<Vec<Ciphertext>> {
    if exact_rank_count == 0 {
        return Ok(Vec::new());
    }
    let factors = ahead_terms
        .iter()
        .map(|ahead| {
            let bit = normalize_scaling(ahead)?;
            let one = encrypted_one_like(&bit)?;
            let not_bit = ciphertext_sub(&one, &bit)?;

            Ok(vec![not_bit, bit])
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    multiply_ciphertext_polynomials_balanced(context, factors, exact_rank_count - 1)
}

#[cfg(test)]
pub(crate) fn multiply_ciphertext_polynomials_balanced(
    context: &EvaluatorContext,
    factors: Vec<Vec<Ciphertext>>,
    max_degree: usize,
) -> CanonicalResult<Vec<Ciphertext>> {
    if factors.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "exact rank derivation requires at least one factor",
        ));
    }
    let mut current = factors;
    while current.len() > 1 {
        let defer_terminal_switch = current.len() == 2;
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0].clone());
            } else {
                next.push(multiply_ciphertext_polynomials(
                    context,
                    &pair[0],
                    &pair[1],
                    max_degree,
                    defer_terminal_switch,
                )?);
            }
        }
        current = next;
    }

    let mut coefficients = current.pop().expect("non-empty product has one result");
    while coefficients.len() <= max_degree {
        coefficients.push(scalar_mul(&coefficients[0], 0)?);
    }

    Ok(coefficients)
}

#[cfg(test)]
pub(crate) fn multiply_ciphertext_polynomials(
    context: &EvaluatorContext,
    left: &[Ciphertext],
    right: &[Ciphertext],
    max_degree: usize,
    defer_modulus_switch: bool,
) -> CanonicalResult<Vec<Ciphertext>> {
    let mut accumulated_products_by_degree = (0..=max_degree)
        .map(|_| None)
        .collect::<Vec<Option<Ciphertext>>>();
    for (left_degree, left_coefficient) in left.iter().enumerate() {
        for (right_degree, right_coefficient) in right.iter().enumerate() {
            let degree = left_degree + right_degree;
            if degree > max_degree {
                continue;
            }
            let product = if defer_modulus_switch {
                multiply_without_immediate_modulus_switch(
                    context,
                    left_coefficient,
                    right_coefficient,
                )?
            } else {
                multiply(context, left_coefficient, right_coefficient)?
            };
            accumulated_products_by_degree[degree] =
                if let Some(accumulated_product) = accumulated_products_by_degree[degree].take() {
                    let terms = [accumulated_product, product];
                    Some(sum_aligned(&terms)?)
                } else {
                    Some(product)
                };
        }
    }

    accumulated_products_by_degree
        .into_iter()
        .map(|product| product.map_or_else(|| scalar_mul(&left[0], 0), Ok))
        .collect()
}
