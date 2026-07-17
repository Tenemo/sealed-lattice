use super::*;

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
            CanonicalErrorCode::InvalidProtocolObject,
            "top-k prefix evaluation requires 1 <= top_count <= option_count",
        ));
    }
    let normalized_rank = normalize_scaling(&modulus_switch_to(rank, context.working_level())?)?;
    if top_count == option_count {
        let selected_every_slot = add_plaintext_coefficients(
            &scalar_mul(&normalized_rank, 0)?,
            &broadcast_constant_coefficients(1),
        )?;
        let rank_plus_one =
            add_plaintext_coefficients(&normalized_rank, &broadcast_constant_coefficients(1))?;

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
    evaluate_polynomial_with_fixed_baby_step_count(
        context,
        normalized_rank,
        &polynomial,
        RANK_LOOKUP_BABY_STEP_COUNT,
    )
}
