use super::*;

// Derive the encrypted score bits of a broadcast score ciphertext.
#[cfg(test)]
pub(crate) fn derive_score_bits(
    context: &EvaluatorContext,
    score: &Ciphertext,
    bit_polynomials: &[Vec<u64>],
) -> CanonicalResult<Vec<Ciphertext>> {
    bit_polynomials
        .iter()
        .map(|polynomial| evaluate_polynomial(context, score, polynomial))
        .collect()
}

// Bit-sliced greater-than and equality of two encrypted bit decompositions
// (least-significant bit first). Returns (greater_than, equal) encrypted
// booleans.
#[cfg(test)]
pub(crate) fn bit_sliced_greater_than_and_equal(
    context: &EvaluatorContext,
    left_bits: &[Ciphertext],
    right_bits: &[Ciphertext],
) -> CanonicalResult<(Ciphertext, Ciphertext)> {
    let bit_count = left_bits.len();
    if bit_count == 0 || right_bits.len() != bit_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "bit-sliced comparison requires matching non-empty bit decompositions",
        ));
    }
    // Per-bit equality: eq_k = 1 - (a_k - b_k)^2.
    let mut bit_equal = Vec::with_capacity(bit_count);
    for bit in 0..bit_count {
        let difference = ciphertext_sub(&left_bits[bit], &right_bits[bit])?;
        let squared = multiply(context, &difference, &difference)?;
        bit_equal.push(boolean_not(&squared)?);
    }
    // Suffix equality above each bit: prefix_above[bit] = product of eq_k for
    // k > bit. Computed from the most-significant bit downward.
    let mut suffix_equal = vec![None; bit_count];
    for bit in (0..bit_count).rev() {
        if bit == bit_count - 1 {
            // Empty product is the encrypted constant one; represent it as
            // eq over no bits by reusing the top equality's all-ones structure.
            suffix_equal[bit] = Some(encrypted_one_like(&bit_equal[bit])?);
        } else {
            let higher = suffix_equal[bit + 1]
                .clone()
                .expect("higher suffix present");
            suffix_equal[bit] = Some(multiply(context, &higher, &bit_equal[bit + 1])?);
        }
    }
    // greater_than = sum_bit a_bit * (1 - b_bit) * suffix_equal[bit].
    let mut terms = Vec::with_capacity(bit_count);
    for bit in 0..bit_count {
        let not_right = boolean_not(&right_bits[bit])?;
        let strictly_greater = multiply(context, &left_bits[bit], &not_right)?;
        let suffix = suffix_equal[bit].clone().expect("suffix present");
        terms.push(multiply(context, &strictly_greater, &suffix)?);
    }
    let greater_than = sum_aligned(&terms)?;
    // equal = product of all per-bit equalities = suffix below the lowest bit.
    let lowest_suffix = suffix_equal[0].clone().expect("lowest suffix present");
    let equal = multiply(context, &lowest_suffix, &bit_equal[0])?;

    Ok((greater_than, equal))
}

// An encrypted constant one at the same level and scaling as a reference
// ciphertext: zero the reference, then add the plaintext constant one.
#[cfg(test)]
pub(crate) fn encrypted_one_like(reference: &Ciphertext) -> CanonicalResult<Ciphertext> {
    add_constant(&scalar_mul(reference, 0)?, 1)
}

// Encrypted ahead indicator for the ordered pair (challenger, option):
// ahead = GT(challenger, option) + tie * EQ(challenger, option), where tie is
// the public bit that the challenger's index is lower than the option's.
#[cfg(test)]
pub(crate) fn ahead_indicator(
    greater_than: &Ciphertext,
    equal: &Ciphertext,
    challenger_index: usize,
    option_index: usize,
) -> CanonicalResult<Ciphertext> {
    let greater_aligned = normalize_scaling(greater_than)?;
    let equal_aligned = normalize_scaling(&modulus_switch_to(
        equal,
        greater_than.level.min(equal.level),
    )?)?;
    let greater_at_level = normalize_scaling(&modulus_switch_to(
        &greater_aligned,
        greater_than.level.min(equal.level),
    )?)?;
    if challenger_index < option_index {
        ciphertext_add(&greater_at_level, &equal_aligned)
    } else {
        Ok(greater_at_level)
    }
}

// The encrypted rank of an option: the number of other options that are ahead
// of it under the tie policy.
#[cfg(test)]
pub(crate) fn accumulate_rank(ahead_indicators: &[Ciphertext]) -> CanonicalResult<Ciphertext> {
    sum_aligned(ahead_indicators)
}

// The encrypted top-k indicator [rank < top_count] over the rank domain
// [0, option_count - 1].
#[cfg(test)]
pub(crate) fn top_k_indicator(
    context: &EvaluatorContext,
    rank: &Ciphertext,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<Ciphertext> {
    let (indicator, _) = top_k_indicator_and_order_value(context, rank, option_count, top_count)?;

    Ok(indicator)
}

// The encrypted target-order value: rank + 1 when rank is inside the selected
// top-k prefix, and zero otherwise. Evaluating this directly avoids the extra
// ciphertext multiplication `(rank + 1) * indicator` during sparse projection.
#[cfg(test)]
pub(crate) fn top_k_order_value(
    context: &EvaluatorContext,
    rank: &Ciphertext,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<Ciphertext> {
    let (_, order_value) = top_k_indicator_and_order_value(context, rank, option_count, top_count)?;

    Ok(order_value)
}

pub(crate) fn top_k_indicator_and_order_value(
    context: &EvaluatorContext,
    rank: &Ciphertext,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<(Ciphertext, Ciphertext)> {
    if top_count == 0 || top_count > option_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "top-k prefix evaluation requires 1 <= top_count <= option_count",
        ));
    }
    let normalized_rank = normalize_scaling(&modulus_switch_to(rank, context.working_level())?)?;
    if top_count == option_count {
        let selected_every_slot =
            add_plaintext_coefficients(&scalar_mul(&normalized_rank, 0)?, &broadcast_constant(1))?;
        let rank_plus_one = add_plaintext_coefficients(&normalized_rank, &broadcast_constant(1))?;

        return Ok((selected_every_slot, rank_plus_one));
    }

    let indicator_values = (0..option_count)
        .map(|rank_value| u64::from(rank_value < top_count))
        .collect::<Vec<_>>();
    let order_values = (0..option_count)
        .map(|rank_value| {
            if rank_value < top_count {
                u64::try_from(rank_value + 1).expect("rank value fits u64")
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let indicator = evaluate_rank_lookup(context, &normalized_rank, &indicator_values)?;
    let order_value = evaluate_rank_lookup(context, &normalized_rank, &order_values)?;

    Ok((indicator, order_value))
}

pub(crate) fn evaluate_rank_lookup(
    context: &EvaluatorContext,
    normalized_rank: &Ciphertext,
    values: &[u64],
) -> CanonicalResult<Ciphertext> {
    if values.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank lookup values must contain at least one value",
        ));
    }
    let polynomial = interpolate_coefficients(values)?;
    evaluate_polynomial_with_fixed_baby_step_count_and_deferred_terminal_switch(
        context,
        normalized_rank,
        &polynomial,
        RANK_LOOKUP_BABY_STEP_COUNT,
    )
}
