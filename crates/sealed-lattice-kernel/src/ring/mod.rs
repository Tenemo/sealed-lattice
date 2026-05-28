use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[cfg(test)]
pub const MODULE_MARKER: &str = "ring";
pub const FIELD_MODULUS: u64 = 65_537;
pub const MAXIMUM_TOTAL_SCORE_FACTOR: u64 = 10;
pub const MAXIMUM_SUPPORTED_ROSTER_SIZE: u64 = 50;
pub const MAXIMUM_SHAMIR_INTERPOLATION_POINTS: usize = MAXIMUM_SUPPORTED_ROSTER_SIZE as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShamirSharePoint {
    pub roster_position: u64,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextComparison {
    pub greater_than: u64,
    pub equal: u64,
    pub score_difference: i64,
}

fn invalid_ring_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

pub fn assert_field_element(value: u64) -> CanonicalResult<u64> {
    if value >= FIELD_MODULUS {
        return Err(invalid_ring_input(
            "field element must be in the canonical GF(65537) range",
        ));
    }

    Ok(value)
}

fn assert_roster_position(value: u64) -> CanonicalResult<u64> {
    if value == 0 || value >= FIELD_MODULUS {
        return Err(invalid_ring_input(
            "roster interpolation points must be positive GF(65537) elements",
        ));
    }
    if value > MAXIMUM_SUPPORTED_ROSTER_SIZE {
        return Err(invalid_ring_input(
            "roster interpolation points must be in 1..50",
        ));
    }

    Ok(value)
}

fn add_field_elements(left: u64, right: u64) -> u64 {
    (left + right) % FIELD_MODULUS
}

fn subtract_field_elements(left: u64, right: u64) -> u64 {
    (FIELD_MODULUS + left - right) % FIELD_MODULUS
}

fn multiply_field_elements(left: u64, right: u64) -> u64 {
    (left * right) % FIELD_MODULUS
}

fn negate_field_element(value: u64) -> u64 {
    if value == 0 { 0 } else { FIELD_MODULUS - value }
}

fn invert_field_element(value: u64) -> CanonicalResult<u64> {
    let mut previous_remainder = FIELD_MODULUS as i64;
    let mut current_remainder = assert_field_element(value)? as i64;
    let mut previous_coefficient = 0_i64;
    let mut current_coefficient = 1_i64;

    if current_remainder == 0 {
        return Err(invalid_ring_input("zero has no inverse in GF(65537)"));
    }

    while current_remainder != 0 {
        let quotient = previous_remainder / current_remainder;
        let next_remainder = previous_remainder - quotient * current_remainder;
        previous_remainder = current_remainder;
        current_remainder = next_remainder;

        let next_coefficient = previous_coefficient - quotient * current_coefficient;
        previous_coefficient = current_coefficient;
        current_coefficient = next_coefficient;
    }

    Ok(
        ((previous_coefficient % FIELD_MODULUS as i64 + FIELD_MODULUS as i64)
            % FIELD_MODULUS as i64) as u64,
    )
}

fn divide_field_elements(numerator: u64, denominator: u64) -> CanonicalResult<u64> {
    Ok(multiply_field_elements(
        numerator,
        invert_field_element(denominator)?,
    ))
}

fn derive_lagrange_coefficients_at_zero(
    share_points: &[ShamirSharePoint],
) -> CanonicalResult<Vec<(u64, u64)>> {
    let mut coefficients = Vec::with_capacity(share_points.len());

    for selected_share in share_points {
        let mut coefficient = 1_u64;
        for other_share in share_points {
            if other_share.roster_position == selected_share.roster_position {
                continue;
            }
            coefficient = multiply_field_elements(
                coefficient,
                divide_field_elements(
                    negate_field_element(other_share.roster_position),
                    subtract_field_elements(
                        selected_share.roster_position,
                        other_share.roster_position,
                    ),
                )?,
            );
        }
        coefficients.push((selected_share.roster_position, coefficient));
    }

    Ok(coefficients)
}

pub fn interpolate_shamir_constant_term(share_points: &[ShamirSharePoint]) -> CanonicalResult<u64> {
    if share_points.is_empty() {
        return Err(invalid_ring_input("at least one Shamir share is required"));
    }
    if share_points.len() > MAXIMUM_SHAMIR_INTERPOLATION_POINTS {
        return Err(invalid_ring_input("at most 50 Shamir shares are supported"));
    }

    let mut seen_roster_positions = Vec::with_capacity(share_points.len());
    for share_point in share_points {
        assert_roster_position(share_point.roster_position)?;
        assert_field_element(share_point.value)?;
        if seen_roster_positions.contains(&share_point.roster_position) {
            return Err(invalid_ring_input(
                "Shamir interpolation points must be distinct",
            ));
        }
        seen_roster_positions.push(share_point.roster_position);
    }

    let coefficients = derive_lagrange_coefficients_at_zero(share_points)?;
    let mut interpolated_value = 0_u64;

    for share_point in share_points {
        let (_, coefficient) = coefficients
            .iter()
            .find(|(roster_position, _)| roster_position == &share_point.roster_position)
            .ok_or_else(|| invalid_ring_input("missing Lagrange coefficient"))?;
        interpolated_value = add_field_elements(
            interpolated_value,
            multiply_field_elements(share_point.value, *coefficient),
        );
    }

    Ok(interpolated_value)
}

pub fn evaluate_plaintext_comparison(
    left_total_score: u64,
    right_total_score: u64,
    roster_size: u64,
) -> CanonicalResult<PlaintextComparison> {
    if roster_size == 0 || roster_size > MAXIMUM_SUPPORTED_ROSTER_SIZE {
        return Err(invalid_ring_input("roster size must be in 1..50"));
    }
    let maximum_total_score = roster_size * MAXIMUM_TOTAL_SCORE_FACTOR;
    if left_total_score > maximum_total_score || right_total_score > maximum_total_score {
        return Err(invalid_ring_input(
            "plaintext comparison totals must fit the score domain",
        ));
    }

    Ok(PlaintextComparison {
        greater_than: u64::from(left_total_score > right_total_score),
        equal: u64::from(left_total_score == right_total_score),
        score_difference: left_total_score as i64 - right_total_score as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ShamirSharePoint, evaluate_plaintext_comparison, interpolate_shamir_constant_term,
    };

    #[test]
    fn interpolates_constant_term_from_distinct_shares() {
        let secret = interpolate_shamir_constant_term(&[
            ShamirSharePoint {
                roster_position: 1,
                value: 15,
            },
            ShamirSharePoint {
                roster_position: 2,
                value: 25,
            },
        ])
        .expect("valid shares should interpolate");

        assert_eq!(secret, 5);
    }

    #[test]
    fn rejects_duplicate_interpolation_points() {
        let result = interpolate_shamir_constant_term(&[
            ShamirSharePoint {
                roster_position: 1,
                value: 15,
            },
            ShamirSharePoint {
                roster_position: 1,
                value: 25,
            },
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_out_of_domain_interpolation_inputs() {
        let too_many_shares: Vec<ShamirSharePoint> = (1..=51)
            .map(|roster_position| ShamirSharePoint {
                roster_position,
                value: roster_position,
            })
            .collect();

        assert!(interpolate_shamir_constant_term(&too_many_shares).is_err());
        assert!(
            interpolate_shamir_constant_term(&[ShamirSharePoint {
                roster_position: 51,
                value: 1,
            }])
            .is_err()
        );
    }

    #[test]
    fn compares_plaintext_scores_inside_the_supported_domain() {
        let comparison = evaluate_plaintext_comparison(41, 40, 5)
            .expect("comparison should accept in-domain totals");

        assert_eq!(comparison.greater_than, 1);
        assert_eq!(comparison.equal, 0);
        assert_eq!(comparison.score_difference, 1);
        assert!(evaluate_plaintext_comparison(51, 0, 5).is_err());
    }
}
