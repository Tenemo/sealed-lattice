use super::*;

pub(super) fn refuse_target_decryption_result_release() -> CanonicalResult<Value> {
    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "target result release is unavailable until accepted compact setup, proof-backed target shares, production smudging evidence, quorum interpolation checks, and final release verification are implemented",
    ))
}

#[cfg(test)]
pub(super) fn release_target_role_slots(
    ciphertext: &Ciphertext,
    interpolation_points: &[u64],
    partials_by_share: &[&[Vec<u64>]],
) -> CanonicalResult<Vec<u64>> {
    let active_limb_count = ciphertext.level + 1;
    if partials_by_share.len() != interpolation_points.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result release partial count must match interpolation points",
        ));
    }
    let mut accumulator = ciphertext.components[0].clone();
    if accumulator.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result release ciphertext accumulator has the wrong active limb count",
        ));
    }

    for rns_limb_index in 0..active_limb_count {
        let modulus = DATA_PRIMES[rns_limb_index];
        let lagrange_weights = lagrange_weights_at_zero(interpolation_points, modulus)?;
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            let mut interpolated_partial = 0_u64;
            for (share_index, share_partials) in partials_by_share.iter().enumerate() {
                if share_partials.len() != active_limb_count {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result release share partials have the wrong active limb count",
                    ));
                }
                let share_limb = share_partials.get(rns_limb_index).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result release share partials are missing an active limb",
                    )
                })?;
                if share_limb.len() != POLYNOMIAL_DEGREE {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result release share partial limb has the wrong coefficient count",
                    ));
                }
                let weighted_partial = mul_mod_fast(
                    share_limb[coefficient_index],
                    lagrange_weights[share_index],
                    modulus,
                );
                interpolated_partial =
                    add_mod_fast(interpolated_partial, weighted_partial, modulus);
            }
            accumulator[rns_limb_index][coefficient_index] = add_mod_fast(
                accumulator[rns_limb_index][coefficient_index],
                interpolated_partial,
                modulus,
            );
        }
    }

    let coefficients = decryption_accumulator_to_coefficients(ciphertext, &accumulator)?;
    forward_negacyclic_ntt(&coefficients, PLAINTEXT_MODULUS)
}

#[cfg(test)]
fn lagrange_weights_at_zero(
    interpolation_points: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    interpolation_points
        .iter()
        .enumerate()
        .map(|(selected_index, selected_point)| {
            let selected_point = *selected_point % modulus;
            let mut numerator = 1_u64;
            let mut denominator = 1_u64;
            for (other_index, other_point) in interpolation_points.iter().enumerate() {
                if other_index == selected_index {
                    continue;
                }
                let other_point = *other_point % modulus;
                numerator = mul_mod(numerator, sub_mod(0, other_point, modulus)?, modulus)?;
                denominator = mul_mod(
                    denominator,
                    sub_mod(selected_point, other_point, modulus)?,
                    modulus,
                )?;
            }
            mul_mod(numerator, inverse_mod(denominator, modulus)?, modulus)
        })
        .collect()
}

#[cfg(test)]
pub(super) fn packed_target_option_values(
    slots: &[u64],
    top_count: usize,
) -> CanonicalResult<Vec<u64>> {
    if top_count == 0 || top_count > MAXIMUM_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result topCount is outside the supported option count",
        ));
    }
    if slots.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result slots must match the selected ring degree",
        ));
    }

    (0..MAXIMUM_OPTION_COUNT)
        .map(|option_index| {
            slots
                .get(packed_score_slot(option_index))
                .copied()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result packed option slot is outside the selected ring",
                    )
                })
        })
        .collect()
}
