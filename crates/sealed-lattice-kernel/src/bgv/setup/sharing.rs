#[cfg(test)]
use std::collections::BTreeSet;

#[cfg(test)]
use crate::bgv::modular_arithmetic::{add_mod, inverse_mod, mul_mod, sub_mod};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct RnsShamirShare {
    pub(super) roster_position: usize,
    pub(super) value: u64,
}

pub(super) fn canonical_trustee_point(
    roster_position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    let trustee_point = u64::try_from(roster_position)
        .map_err(|_| invalid_sharing_input("roster position does not fit u64"))?
        .checked_add(1)
        .ok_or_else(|| invalid_sharing_input("roster position overflows trustee point"))?;
    if trustee_point == 0 || trustee_point >= modulus {
        return Err(invalid_sharing_input(
            "canonical trustee point must be non-zero and less than every Q_share prime",
        ));
    }

    Ok(trustee_point)
}

#[cfg(test)]
pub(super) fn evaluate_shamir_polynomial(
    coefficients: &[u64],
    trustee_point: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    if coefficients.is_empty() {
        return Err(invalid_sharing_input(
            "Shamir polynomial must contain at least the constant coefficient",
        ));
    }
    if trustee_point == 0 || trustee_point >= modulus {
        return Err(invalid_sharing_input(
            "trustee point must be non-zero and less than the sharing modulus",
        ));
    }

    let mut evaluated_value = 0_u64;
    let mut trustee_point_power = 1_u64;
    for coefficient in coefficients {
        if *coefficient >= modulus {
            return Err(invalid_sharing_input(
                "Shamir coefficient is outside the sharing field",
            ));
        }
        evaluated_value = add_mod(
            evaluated_value,
            mul_mod(*coefficient, trustee_point_power, modulus)?,
            modulus,
        )?;
        trustee_point_power = mul_mod(trustee_point_power, trustee_point, modulus)?;
    }

    Ok(evaluated_value)
}

#[cfg(test)]
pub(super) fn interpolate_shamir_constant_with_threshold(
    shares: &[RnsShamirShare],
    threshold: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    if threshold == 0 {
        return Err(invalid_sharing_input("Shamir threshold must be positive"));
    }
    if shares.len() < threshold {
        return Err(invalid_sharing_input(
            "not enough Shamir shares for the required threshold",
        ));
    }

    interpolate_shamir_constant(shares, modulus)
}

#[cfg(test)]
fn interpolate_shamir_constant(shares: &[RnsShamirShare], modulus: u64) -> CanonicalResult<u64> {
    if shares.is_empty() {
        return Err(invalid_sharing_input(
            "at least one Shamir share is required",
        ));
    }
    let mut seen_trustee_points = BTreeSet::new();
    let mut share_points = Vec::with_capacity(shares.len());
    for share in shares {
        if share.value >= modulus {
            return Err(invalid_sharing_input(
                "Shamir share value is outside the sharing field",
            ));
        }
        let trustee_point = canonical_trustee_point(share.roster_position, modulus)?;
        if !seen_trustee_points.insert(trustee_point) {
            return Err(invalid_sharing_input(
                "Shamir interpolation points must be distinct",
            ));
        }
        share_points.push((trustee_point, share.value));
    }

    let mut interpolated_constant = 0_u64;
    for (selected_trustee_point, selected_share_value) in &share_points {
        let mut numerator = 1_u64;
        let mut denominator = 1_u64;
        for (other_trustee_point, _) in &share_points {
            if other_trustee_point == selected_trustee_point {
                continue;
            }
            numerator = mul_mod(numerator, modulus - other_trustee_point, modulus)?;
            let difference = sub_mod(*selected_trustee_point, *other_trustee_point, modulus)?;
            denominator = mul_mod(denominator, difference, modulus)?;
        }
        let lagrange_coefficient = mul_mod(numerator, inverse_mod(denominator, modulus)?, modulus)?;
        let weighted_share = mul_mod(*selected_share_value, lagrange_coefficient, modulus)?;
        interpolated_constant = add_mod(interpolated_constant, weighted_share, modulus)?;
    }

    Ok(interpolated_constant)
}

fn invalid_sharing_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
