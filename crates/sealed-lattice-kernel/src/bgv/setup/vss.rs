#[cfg(test)]
use crate::encoding::CanonicalResult;
#[cfg(test)]
use crate::encoding::{CanonicalError, CanonicalErrorCode};

#[cfg(test)]
use super::{
    commitment::{
        SetupCommitmentOpeningVerification, SetupCommitmentValue,
        linear_combination_setup_commitments, setup_coefficient_fits_commitment_modulus_product,
        verify_setup_lifted_commitment_opening,
    },
    sharing::{canonical_trustee_point, evaluate_shamir_polynomial},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct CarryAwareVssShareOpeningVerification {
    pub(super) trustee_point: u64,
    pub(super) unreduced_evaluation: u128,
    pub(super) reduced_evaluation: u64,
    pub(super) expected_carry: u128,
    pub(super) carry_bound: u128,
    pub(super) lifted_share: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct CarryAwareVssCommitmentOpeningVerification {
    pub(super) lifted_share_openings: Vec<CarryAwareVssShareOpeningVerification>,
    pub(super) commitment_opening: SetupCommitmentOpeningVerification,
    pub(super) trustee_point: u64,
    pub(super) homomorphic_randomness_bound: i128,
}

#[cfg(test)]
pub(super) struct CarryAwareVssCommitmentOpeningInput<'a> {
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) coefficient_commitments: &'a [SetupCommitmentValue],
    pub(super) coefficient_messages_by_shamir_index: &'a [Vec<u64>],
    pub(super) coefficient_randomness_by_shamir_index: &'a [Vec<Vec<i128>>],
    pub(super) recipient_roster_position: usize,
    pub(super) share_values: &'a [u64],
    pub(super) carry_witnesses: &'a [u128],
    pub(super) modulus: u64,
    pub(super) fresh_randomness_bound: i128,
}

#[cfg(test)]
pub(super) fn evaluate_unreduced_shamir_polynomial(
    coefficient_values: &[u64],
    trustee_point: u64,
    modulus: u64,
) -> CanonicalResult<u128> {
    if coefficient_values.is_empty() {
        return Err(invalid_vss_input(
            "Shamir polynomial must contain at least the constant coefficient",
        ));
    }
    if trustee_point == 0 || trustee_point >= modulus {
        return Err(invalid_vss_input(
            "trustee point must be non-zero and less than the sharing modulus",
        ));
    }

    let mut unreduced_evaluation = 0_u128;
    let mut trustee_point_power = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for (coefficient_index, coefficient_value) in coefficient_values.iter().enumerate() {
        if *coefficient_value >= modulus {
            return Err(invalid_vss_input(
                "Shamir coefficient is outside the sharing field",
            ));
        }

        let term = u128::from(*coefficient_value)
            .checked_mul(trustee_point_power)
            .ok_or_else(|| invalid_vss_input("unreduced Shamir term overflow"))?;
        unreduced_evaluation = unreduced_evaluation
            .checked_add(term)
            .ok_or_else(|| invalid_vss_input("unreduced Shamir evaluation overflow"))?;
        if coefficient_index + 1 < coefficient_values.len() {
            trustee_point_power = trustee_point_power
                .checked_mul(trustee_point_wide)
                .ok_or_else(|| invalid_vss_input("trustee-point power overflow"))?;
        }
    }

    Ok(unreduced_evaluation)
}

#[cfg(test)]
pub(super) fn verify_carry_aware_vss_share_opening(
    coefficient_values: &[u64],
    recipient_roster_position: usize,
    share_value: u64,
    carry_witness: u128,
    modulus: u64,
) -> CanonicalResult<CarryAwareVssShareOpeningVerification> {
    if share_value >= modulus {
        return Err(invalid_vss_input(
            "VSS share value is outside the sharing field",
        ));
    }

    let trustee_point = canonical_trustee_point(recipient_roster_position, modulus)?;
    let unreduced_evaluation =
        evaluate_unreduced_shamir_polynomial(coefficient_values, trustee_point, modulus)?;
    let reduced_evaluation =
        evaluate_shamir_polynomial(coefficient_values, trustee_point, modulus)?;
    if reduced_evaluation != share_value {
        return Err(invalid_vss_input(
            "VSS share value does not match the reduced Shamir evaluation",
        ));
    }

    let modulus_wide = u128::from(modulus);
    let expected_carry = unreduced_evaluation / modulus_wide;
    if expected_carry != carry_witness {
        return Err(invalid_vss_input(
            "VSS carry witness does not match the unreduced Shamir evaluation",
        ));
    }

    let carry_bound = carry_bound_for_coefficient_count(coefficient_values.len(), trustee_point)?;
    if carry_witness > carry_bound {
        return Err(invalid_vss_input(
            "VSS carry witness is outside the derived bound",
        ));
    }

    let lifted_share = u128::from(share_value)
        .checked_add(
            modulus_wide
                .checked_mul(carry_witness)
                .ok_or_else(|| invalid_vss_input("lifted VSS share multiplication overflow"))?,
        )
        .ok_or_else(|| invalid_vss_input("lifted VSS share overflow"))?;
    if lifted_share != unreduced_evaluation {
        return Err(invalid_vss_input(
            "lifted VSS share does not match the unreduced Shamir evaluation",
        ));
    }

    Ok(CarryAwareVssShareOpeningVerification {
        trustee_point,
        unreduced_evaluation,
        reduced_evaluation,
        expected_carry,
        carry_bound,
        lifted_share,
    })
}

#[cfg(test)]
pub(super) fn verify_carry_aware_vss_commitment_opening(
    input: CarryAwareVssCommitmentOpeningInput<'_>,
) -> CanonicalResult<CarryAwareVssCommitmentOpeningVerification> {
    let CarryAwareVssCommitmentOpeningInput {
        public_matrix_seed_hash,
        coefficient_commitments,
        coefficient_messages_by_shamir_index,
        coefficient_randomness_by_shamir_index,
        recipient_roster_position,
        share_values,
        carry_witnesses,
        modulus,
        fresh_randomness_bound,
    } = input;
    let coefficient_count = coefficient_messages_by_shamir_index.len();
    if coefficient_count == 0
        || coefficient_commitments.len() != coefficient_count
        || coefficient_randomness_by_shamir_index.len() != coefficient_count
    {
        return Err(invalid_vss_input(
            "VSS commitment opening must provide matching coefficient messages, commitments, and openings",
        ));
    }
    let ring_degree = share_values.len();
    if ring_degree == 0 || carry_witnesses.len() != ring_degree {
        return Err(invalid_vss_input(
            "VSS share and carry vectors must be non-empty and have the same length",
        ));
    }
    for coefficient_values in coefficient_messages_by_shamir_index {
        if coefficient_values.len() != ring_degree {
            return Err(invalid_vss_input(
                "VSS coefficient message vector length must match the share vector length",
            ));
        }
    }

    let trustee_point = canonical_trustee_point(recipient_roster_position, modulus)?;
    let scalar_powers = trustee_point_powers(coefficient_count, trustee_point)?;
    let mut lifted_share_openings = Vec::with_capacity(ring_degree);
    let mut lifted_message_coefficients = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let coefficient_values = coefficient_messages_by_shamir_index
            .iter()
            .map(|coefficient_vector| coefficient_vector[coefficient_position])
            .collect::<Vec<_>>();
        let share_opening = verify_carry_aware_vss_share_opening(
            &coefficient_values,
            recipient_roster_position,
            share_values[coefficient_position],
            carry_witnesses[coefficient_position],
            modulus,
        )?;
        lifted_message_coefficients.push(share_opening.lifted_share);
        lifted_share_openings.push(share_opening);
    }
    // The lifted share coefficient must stay below the commitment modulus product so the cross-field CRT lift of the share is unique (the two-prime window rule in the accounting).
    if lifted_message_coefficients
        .iter()
        .any(|coefficient| !setup_coefficient_fits_commitment_modulus_product(*coefficient))
    {
        return Err(invalid_vss_input(
            "lifted VSS share coefficient wraps in the commitment modulus product",
        ));
    }

    for (coefficient_index, commitment) in coefficient_commitments.iter().enumerate() {
        if commitment.source_message_modulus != modulus || commitment.ring_degree != ring_degree {
            return Err(invalid_vss_input(
                "VSS coefficient commitment domain does not match the share opening",
            ));
        }
        if commitment.shamir_coefficient_index != coefficient_index as u64 {
            return Err(invalid_vss_input(
                "VSS coefficient commitment index does not match coefficient order",
            ));
        }
    }

    let combined_commitment_terms = coefficient_commitments
        .iter()
        .zip(scalar_powers.iter())
        .map(|(commitment, scalar)| (commitment, *scalar))
        .collect::<Vec<_>>();
    let combined_commitment = linear_combination_setup_commitments(&combined_commitment_terms)?;
    let combined_randomness =
        combine_vss_commitment_randomness(coefficient_randomness_by_shamir_index, &scalar_powers)?;
    let homomorphic_randomness_bound =
        homomorphic_randomness_bound(fresh_randomness_bound, &scalar_powers)?;
    let commitment_opening = verify_setup_lifted_commitment_opening(
        public_matrix_seed_hash,
        &combined_commitment,
        &lifted_message_coefficients,
        &combined_randomness,
        homomorphic_randomness_bound,
    )?;

    Ok(CarryAwareVssCommitmentOpeningVerification {
        lifted_share_openings,
        commitment_opening,
        trustee_point,
        homomorphic_randomness_bound,
    })
}

#[cfg(test)]
fn carry_bound_for_coefficient_count(
    coefficient_count: usize,
    trustee_point: u64,
) -> CanonicalResult<u128> {
    if coefficient_count == 0 {
        return Err(invalid_vss_input(
            "Shamir polynomial must contain at least the constant coefficient",
        ));
    }

    // Because the trustee point and coefficient count are far smaller than the sharing prime, ceil(sum / modulus) is exactly 1, so the maximum carry floor((modulus-1)*S/modulus) equals (sum of alpha^k) - 1.
    let mut power_sum = 0_u128;
    let mut trustee_point_power = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for coefficient_index in 0..coefficient_count {
        power_sum = power_sum
            .checked_add(trustee_point_power)
            .ok_or_else(|| invalid_vss_input("VSS carry bound overflow"))?;
        if coefficient_index + 1 < coefficient_count {
            trustee_point_power = trustee_point_power
                .checked_mul(trustee_point_wide)
                .ok_or_else(|| invalid_vss_input("VSS carry bound power overflow"))?;
        }
    }

    Ok(power_sum.saturating_sub(1))
}

#[cfg(test)]
fn trustee_point_powers(
    coefficient_count: usize,
    trustee_point: u64,
) -> CanonicalResult<Vec<u128>> {
    let mut powers = Vec::with_capacity(coefficient_count);
    let mut power = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for coefficient_index in 0..coefficient_count {
        powers.push(power);
        if coefficient_index + 1 < coefficient_count {
            power = power
                .checked_mul(trustee_point_wide)
                .ok_or_else(|| invalid_vss_input("VSS trustee-point power overflow"))?;
        }
    }

    Ok(powers)
}

#[cfg(test)]
// The combined opening randomness is the same alpha^k-weighted sum as the messages, so the combined commitment opens to the evaluated share f(alpha); the noise bound grows by the sum of alpha^k.
fn combine_vss_commitment_randomness(
    coefficient_randomness_by_shamir_index: &[Vec<Vec<i128>>],
    scalar_powers: &[u128],
) -> CanonicalResult<Vec<Vec<i128>>> {
    let Some(first_randomness) = coefficient_randomness_by_shamir_index.first() else {
        return Err(invalid_vss_input(
            "VSS commitment opening randomness is empty",
        ));
    };
    let randomness_width = first_randomness.len();
    if randomness_width == 0 {
        return Err(invalid_vss_input(
            "VSS commitment opening randomness width is empty",
        ));
    }
    let ring_degree = first_randomness
        .first()
        .ok_or_else(|| invalid_vss_input("VSS commitment opening randomness column is missing"))?
        .len();
    let mut combined_randomness = vec![vec![0_i128; ring_degree]; randomness_width];
    for (coefficient_randomness, scalar) in coefficient_randomness_by_shamir_index
        .iter()
        .zip(scalar_powers.iter())
    {
        if coefficient_randomness.len() != randomness_width {
            return Err(invalid_vss_input(
                "VSS commitment opening randomness width mismatch",
            ));
        }
        let scalar_i128 = i128::try_from(*scalar)
            .map_err(|_| invalid_vss_input("VSS scalar does not fit signed integer"))?;
        for (column_index, randomness_column) in coefficient_randomness.iter().enumerate() {
            if randomness_column.len() != ring_degree {
                return Err(invalid_vss_input(
                    "VSS commitment opening randomness degree mismatch",
                ));
            }
            for (coefficient_index, randomness_value) in randomness_column.iter().enumerate() {
                let scaled_value = randomness_value
                    .checked_mul(scalar_i128)
                    .ok_or_else(|| invalid_vss_input("VSS randomness scalar overflow"))?;
                combined_randomness[column_index][coefficient_index] = combined_randomness
                    [column_index][coefficient_index]
                    .checked_add(scaled_value)
                    .ok_or_else(|| invalid_vss_input("VSS combined randomness overflow"))?;
            }
        }
    }

    Ok(combined_randomness)
}

#[cfg(test)]
fn homomorphic_randomness_bound(
    fresh_randomness_bound: i128,
    scalar_powers: &[u128],
) -> CanonicalResult<i128> {
    if fresh_randomness_bound < 0 {
        return Err(invalid_vss_input(
            "fresh commitment randomness bound must be non-negative",
        ));
    }
    let scalar_sum = scalar_powers.iter().try_fold(0_u128, |sum, scalar| {
        sum.checked_add(*scalar)
            .ok_or_else(|| invalid_vss_input("VSS scalar bound overflow"))
    })?;
    let scalar_sum_i128 = i128::try_from(scalar_sum)
        .map_err(|_| invalid_vss_input("VSS scalar bound does not fit signed integer"))?;
    fresh_randomness_bound
        .checked_mul(scalar_sum_i128)
        .ok_or_else(|| invalid_vss_input("VSS homomorphic randomness bound overflow"))
}

#[cfg(test)]
fn invalid_vss_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
