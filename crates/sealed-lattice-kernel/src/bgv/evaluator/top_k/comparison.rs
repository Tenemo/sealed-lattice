use super::*;

// Depth-efficient comparison polynomials over the shifted score-difference
// domain [0, 2*score_domain_max]: `greater` is 1 exactly when the shifted value
// exceeds score_domain_max (i.e. challenger score > option score) and
// `greater_or_equal` is 1 when it is at least score_domain_max. Evaluating one of
// these on (Score_challenger - Score_option + score_domain_max) compares at
// multiplicative depth close to ceil(log2(2*score_domain_max + 1)) with no
// per-bit extraction. Per Iliashenko-Zucca this depth is the floor for
// comparison; their digit method reduces the multiplication count, not the
// depth. The active implementation uses a fixed baby-step
// Paterson-Stockmeyer split to reduce multiplication count while preserving
// enough level for rank-prefix projection.
pub(crate) fn comparison_polynomials(
    score_domain_max: u64,
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    let shift = score_domain_max;
    let point_count = usize::try_from(2 * shift).expect("comparison domain fits usize") + 1;
    let greater = (0..point_count)
        .map(|value| u64::from(value as u64 > shift))
        .collect::<Vec<_>>();
    let greater_or_equal = (0..point_count)
        .map(|value| u64::from(value as u64 >= shift))
        .collect::<Vec<_>>();

    Ok((
        interpolate_coefficients(&greater)?,
        interpolate_coefficients(&greater_or_equal)?,
    ))
}

pub(crate) fn direct_comparison_baby_step_count(score_domain_max: u64) -> CanonicalResult<usize> {
    let point_count = usize::try_from(
        score_domain_max
            .checked_mul(2)
            .and_then(|maximum| maximum.checked_add(1))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "direct comparison domain overflowed",
                )
            })?,
    )
    .map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct comparison domain does not fit usize",
        )
    })?;

    Ok(integer_square_root_ceil(point_count).max(2))
}
