//! Distinct-point reduction for relation-owned opening claims.
//!
//! The phase commitments and every claimed evaluation are fixed before this
//! reduction is materialized. For source polynomials `F_i`, distinct points
//! `z_i`, and claimed values `v_i`, the reduced polynomial is
//!
//! `G(X) = sum_i (F_i(X) - v_i) / (X - z_i)`.
//!
//! Honest division is exact. If any claim is false, multiplying the verifier's
//! query equation by `prod_i (X - z_i)` gives a nonzero polynomial. Its exact
//! degree bounds the finite-population agreement event over the shared outer
//! query vector. The reduction weights are all one: distinct poles prevent
//! cancellation, so no additional batching challenge or batching-failure term
//! is needed.

#[cfg(test)]
use p3_field::Field;
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
use p3_goldilocks::Goldilocks;

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
use super::ChallengeField;
#[cfg(test)]
use super::opening_schedule::divide_polynomial_opening;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OpeningClaimQuotientBatchGeometry {
    source_degree_bound_exclusive: usize,
    opening_claim_count: usize,
    batched_quotient_degree_bound_exclusive: usize,
    discrepancy_numerator_degree_bound_inclusive: usize,
    query_domain_size: usize,
    query_count: usize,
    agreement_ceiling: usize,
}

impl OpeningClaimQuotientBatchGeometry {
    pub(super) fn derive(
        source_degree_bound_exclusive: usize,
        opening_claim_count: usize,
        query_domain_size: usize,
        query_count: usize,
    ) -> Result<Self, String> {
        if source_degree_bound_exclusive < 2
            || opening_claim_count == 0
            || query_domain_size == 0
            || !query_domain_size.is_power_of_two()
            || query_count == 0
            || query_count > query_domain_size
        {
            return Err("opening-claim quotient geometry is invalid".to_owned());
        }
        let batched_quotient_degree_bound_exclusive = source_degree_bound_exclusive
            .checked_sub(1)
            .ok_or_else(|| "opening-claim quotient degree underflowed".to_owned())?;
        let discrepancy_numerator_degree_bound_inclusive = source_degree_bound_exclusive
            .checked_add(opening_claim_count)
            .and_then(|degree| degree.checked_sub(2))
            .ok_or_else(|| "opening-claim discrepancy degree overflowed".to_owned())?;
        if discrepancy_numerator_degree_bound_inclusive >= query_domain_size {
            return Err("opening-claim discrepancy can cover the complete query domain".to_owned());
        }
        Ok(Self {
            source_degree_bound_exclusive,
            opening_claim_count,
            batched_quotient_degree_bound_exclusive,
            discrepancy_numerator_degree_bound_inclusive,
            query_domain_size,
            query_count,
            agreement_ceiling: discrepancy_numerator_degree_bound_inclusive,
        })
    }

    pub(super) const fn source_degree_bound_exclusive(self) -> usize {
        self.source_degree_bound_exclusive
    }

    pub(super) const fn opening_claim_count(self) -> usize {
        self.opening_claim_count
    }

    pub(super) const fn batched_quotient_degree_bound_exclusive(self) -> usize {
        self.batched_quotient_degree_bound_exclusive
    }

    pub(super) const fn discrepancy_numerator_degree_bound_inclusive(self) -> usize {
        self.discrepancy_numerator_degree_bound_inclusive
    }

    pub(super) const fn query_domain_size(self) -> usize {
        self.query_domain_size
    }

    pub(super) const fn query_count(self) -> usize {
        self.query_count
    }

    pub(super) const fn agreement_ceiling(self) -> usize {
        self.agreement_ceiling
    }
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(super) fn validate_distinct_opening_claim_points(
    opening_points: &[ChallengeField],
) -> Result<(), String> {
    if opening_points.is_empty() {
        return Err("opening-claim quotient has no points".to_owned());
    }
    for (opening_point_ordinal, opening_point) in opening_points.iter().enumerate() {
        if opening_points[..opening_point_ordinal].contains(opening_point) {
            return Err("opening-claim quotient points are not distinct".to_owned());
        }
    }
    Ok(())
}

/// Adds one physical row to the distinct-point quotient batch without
/// materializing any of its point-specific aggregate columns.
///
/// For row polynomial `P`, point `z_i`, and row weight `w_i`, this adds
/// `sum_i w_i * (P(X) - P(z_i)) / (X - z_i)` to the destination. Synthetic
/// division is evaluated from high coefficient to low coefficient while one
/// carry per opening point is reused. The final physical coefficient remains
/// untouched and is therefore the canonical zero above the quotient degree.
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(super) fn accumulate_weighted_opening_claim_quotient_row(
    accumulated_quotient: &mut [ChallengeField],
    source_coefficients: &[Goldilocks],
    opening_points: &[ChallengeField],
    row_weights: &[ChallengeField],
    synthetic_division_carries: &mut [ChallengeField],
) -> Result<(), String> {
    if source_coefficients.len() < 2
        || accumulated_quotient.len() != source_coefficients.len()
        || opening_points.len() != row_weights.len()
        || opening_points.len() != synthetic_division_carries.len()
    {
        return Err("weighted opening-claim quotient geometry is invalid".to_owned());
    }
    synthetic_division_carries.fill(ChallengeField::ZERO);
    validate_distinct_opening_claim_points(opening_points)?;

    let highest_coefficient_ordinal = source_coefficients.len() - 1;
    for coefficient_ordinal in (1..=highest_coefficient_ordinal).rev() {
        let source_coefficient = ChallengeField::from(source_coefficients[coefficient_ordinal]);
        let mut weighted_coefficient = ChallengeField::ZERO;
        for ((opening_point, row_weight), carry) in opening_points
            .iter()
            .copied()
            .zip(row_weights.iter().copied())
            .zip(synthetic_division_carries.iter_mut())
        {
            *carry = if coefficient_ordinal == highest_coefficient_ordinal {
                source_coefficient
            } else {
                source_coefficient + opening_point * *carry
            };
            weighted_coefficient += row_weight * *carry;
        }
        accumulated_quotient[coefficient_ordinal - 1] += weighted_coefficient;
    }
    synthetic_division_carries.fill(ChallengeField::ZERO);
    Ok(())
}

#[cfg(test)]
pub(super) fn accumulate_opening_claim_quotient(
    accumulated_quotient: &mut [ChallengeField],
    source_coefficients: &[ChallengeField],
    opening_point: ChallengeField,
    claimed_evaluation: ChallengeField,
) -> Result<(), String> {
    if source_coefficients.len() != accumulated_quotient.len().saturating_add(1) {
        return Err("opening-claim quotient coefficient geometry is invalid".to_owned());
    }
    let (quotient, remainder) = divide_polynomial_opening(
        source_coefficients.len(),
        |coefficient_ordinal| source_coefficients[coefficient_ordinal],
        opening_point,
        claimed_evaluation,
    )?;
    if remainder != ChallengeField::ZERO {
        return Err("opening-claim quotient has a nonzero remainder".to_owned());
    }
    for (accumulated, coefficient) in accumulated_quotient.iter_mut().zip(quotient) {
        *accumulated += coefficient;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn expected_opening_claim_quotient_evaluation(
    query_point: ChallengeField,
    opening_points: &[ChallengeField],
    claimed_evaluations: &[ChallengeField],
    source_evaluations_at_query: &[ChallengeField],
) -> Result<ChallengeField, String> {
    if opening_points.len() != claimed_evaluations.len()
        || opening_points.len() != source_evaluations_at_query.len()
    {
        return Err("opening-claim quotient evaluation vectors have different lengths".to_owned());
    }
    validate_distinct_opening_claim_points(opening_points)?;
    opening_points
        .iter()
        .copied()
        .zip(claimed_evaluations.iter().copied())
        .zip(source_evaluations_at_query.iter().copied())
        .try_fold(
            ChallengeField::ZERO,
            |accumulated, ((opening_point, claimed_evaluation), source_evaluation)| {
                let denominator = query_point - opening_point;
                if denominator == ChallengeField::ZERO {
                    return Err(
                        "opening-claim quotient query collides with a claimed point".to_owned()
                    );
                }
                Ok(accumulated + (source_evaluation - claimed_evaluation) * denominator.inverse())
            },
        )
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::One;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    fn field(value: u64) -> ChallengeField {
        ChallengeField::from_u64(value)
    }

    fn evaluate_polynomial(
        coefficients: &[ChallengeField],
        point: ChallengeField,
    ) -> ChallengeField {
        coefficients
            .iter()
            .rev()
            .fold(ChallengeField::ZERO, |evaluation, coefficient| {
                evaluation * point + *coefficient
            })
    }

    fn binomial_coefficient(total: usize, selected: usize) -> BigUint {
        if selected > total {
            return BigUint::ZERO;
        }
        let selected = selected.min(total - selected);
        (0..selected).fold(BigUint::one(), |coefficient, ordinal| {
            coefficient * BigUint::from(total - ordinal) / BigUint::from(ordinal + 1)
        })
    }

    #[test]
    fn distinct_point_quotient_matches_every_source_claim_at_shared_queries() {
        let first_source = [field(3), field(2), field(1), field(4)];
        let second_source = [field(7), field(5), field(4), field(2)];
        let opening_points = [field(2), field(3)];
        let claimed_evaluations = [
            evaluate_polynomial(&first_source, opening_points[0]),
            evaluate_polynomial(&second_source, opening_points[1]),
        ];
        let mut accumulated_quotient = vec![ChallengeField::ZERO; first_source.len() - 1];
        accumulate_opening_claim_quotient(
            &mut accumulated_quotient,
            &first_source,
            opening_points[0],
            claimed_evaluations[0],
        )
        .expect("the first exact quotient accumulates");
        accumulate_opening_claim_quotient(
            &mut accumulated_quotient,
            &second_source,
            opening_points[1],
            claimed_evaluations[1],
        )
        .expect("the second exact quotient accumulates");

        for query_point in [field(5), field(9), field(17)] {
            let expected = expected_opening_claim_quotient_evaluation(
                query_point,
                &opening_points,
                &claimed_evaluations,
                &[
                    evaluate_polynomial(&first_source, query_point),
                    evaluate_polynomial(&second_source, query_point),
                ],
            )
            .expect("the verifier quotient evaluation derives");
            assert_eq!(
                evaluate_polynomial(&accumulated_quotient, query_point),
                expected
            );
        }
    }

    #[test]
    fn quotient_refuses_wrong_claims_duplicate_points_and_colliding_queries() {
        let source = [field(11), field(7), field(3)];
        let opening_point = field(4);
        let claimed_evaluation = evaluate_polynomial(&source, opening_point);
        let mut quotient = vec![ChallengeField::ZERO; source.len() - 1];
        assert!(
            accumulate_opening_claim_quotient(
                &mut quotient,
                &source,
                opening_point,
                claimed_evaluation + ChallengeField::ONE,
            )
            .is_err()
        );
        assert!(
            expected_opening_claim_quotient_evaluation(
                field(8),
                &[opening_point, opening_point],
                &[claimed_evaluation; 2],
                &[field(1), field(2)],
            )
            .is_err()
        );
        assert!(
            expected_opening_claim_quotient_evaluation(
                opening_point,
                &[opening_point],
                &[claimed_evaluation],
                &[field(1)],
            )
            .is_err()
        );
        assert!(
            expected_opening_claim_quotient_evaluation(
                field(8),
                &[opening_point],
                &[],
                &[field(1)],
            )
            .is_err()
        );
    }

    #[test]
    fn streaming_weighted_rows_equal_materialized_point_columns() {
        let source_rows = [
            vec![
                Goldilocks::from_u64(3),
                Goldilocks::from_u64(2),
                Goldilocks::from_u64(1),
                Goldilocks::from_u64(4),
            ],
            vec![
                Goldilocks::from_u64(7),
                Goldilocks::from_u64(5),
                Goldilocks::from_u64(4),
                Goldilocks::from_u64(2),
            ],
            vec![
                Goldilocks::from_u64(9),
                Goldilocks::from_u64(0),
                Goldilocks::from_u64(6),
                Goldilocks::from_u64(8),
            ],
        ];
        let opening_points = [field(2), field(3), field(11)];
        let weights_by_row = [
            [field(5), field(0), field(13)],
            [field(7), field(17), field(0)],
            [field(0), field(19), field(23)],
        ];
        let mut streaming = vec![ChallengeField::ZERO; source_rows[0].len()];
        let mut carries = vec![field(91); opening_points.len()];
        for (source_row, row_weights) in source_rows.iter().zip(weights_by_row) {
            accumulate_weighted_opening_claim_quotient_row(
                &mut streaming,
                source_row,
                &opening_points,
                &row_weights,
                &mut carries,
            )
            .expect("the weighted row quotient accumulates");
            assert_eq!(carries, vec![ChallengeField::ZERO; opening_points.len()]);
        }

        let mut materialized = vec![ChallengeField::ZERO; source_rows[0].len() - 1];
        for (point_ordinal, opening_point) in opening_points.iter().copied().enumerate() {
            let aggregate_column = (0..source_rows[0].len())
                .map(|coefficient_ordinal| {
                    source_rows.iter().zip(weights_by_row).fold(
                        ChallengeField::ZERO,
                        |coefficient, (source_row, row_weights)| {
                            coefficient
                                + row_weights[point_ordinal]
                                    * ChallengeField::from(source_row[coefficient_ordinal])
                        },
                    )
                })
                .collect::<Vec<_>>();
            let claimed_evaluation = evaluate_polynomial(&aggregate_column, opening_point);
            accumulate_opening_claim_quotient(
                &mut materialized,
                &aggregate_column,
                opening_point,
                claimed_evaluation,
            )
            .expect("the materialized point column divides exactly");
        }
        assert_eq!(&streaming[..materialized.len()], materialized);
        assert_eq!(streaming.last(), Some(&ChallengeField::ZERO));
    }

    #[test]
    fn streaming_weighted_rows_refuse_ambiguous_or_mismatched_geometry() {
        let source = [Goldilocks::from_u64(1), Goldilocks::from_u64(2)];
        let point = field(3);
        let mut destination = vec![ChallengeField::ZERO; source.len()];
        let mut carries = vec![ChallengeField::ZERO; 1];
        assert!(
            accumulate_weighted_opening_claim_quotient_row(
                &mut destination[..1],
                &source,
                &[point],
                &[field(5)],
                &mut carries,
            )
            .is_err()
        );
        let mut duplicate_point_carries = [field(11), field(13)];
        assert!(
            accumulate_weighted_opening_claim_quotient_row(
                &mut destination,
                &source,
                &[point, point],
                &[field(5), field(7)],
                &mut duplicate_point_carries,
            )
            .is_err()
        );
        assert_eq!(duplicate_point_carries, [ChallengeField::ZERO; 2]);
        assert!(
            accumulate_weighted_opening_claim_quotient_row(
                &mut destination,
                &source,
                &[point],
                &[],
                &mut carries,
            )
            .is_err()
        );
        assert!(
            accumulate_weighted_opening_claim_quotient_row(
                &mut destination,
                &[Goldilocks::from_u64(1)],
                &[point],
                &[field(5)],
                &mut carries,
            )
            .is_err()
        );
    }

    #[test]
    fn production_shaped_finite_population_term_exceeds_774_bits() {
        let geometry = OpeningClaimQuotientBatchGeometry::derive(4_194_304, 24, 16_777_216, 387)
            .expect("the production-shaped quotient geometry derives");
        assert_eq!(geometry.source_degree_bound_exclusive(), 4_194_304);
        assert_eq!(geometry.opening_claim_count(), 24);
        assert_eq!(
            geometry.batched_quotient_degree_bound_exclusive(),
            4_194_303
        );
        assert_eq!(
            geometry.discrepancy_numerator_degree_bound_inclusive(),
            4_194_326
        );
        assert_eq!(geometry.query_domain_size(), 16_777_216);
        assert_eq!(geometry.query_count(), 387);
        assert_eq!(geometry.agreement_ceiling(), 4_194_326);

        let numerator = binomial_coefficient(geometry.agreement_ceiling(), geometry.query_count());
        let denominator =
            binomial_coefficient(geometry.query_domain_size(), geometry.query_count());
        assert!((&numerator << 774_usize) < denominator);
        assert!((&numerator << 775_usize) > denominator);
    }

    #[test]
    fn quotient_geometry_refuses_vacuous_or_domain_covering_bounds() {
        assert!(OpeningClaimQuotientBatchGeometry::derive(1, 1, 8, 1).is_err());
        assert!(OpeningClaimQuotientBatchGeometry::derive(2, 0, 8, 1).is_err());
        assert!(OpeningClaimQuotientBatchGeometry::derive(8, 2, 8, 1).is_err());
        assert!(OpeningClaimQuotientBatchGeometry::derive(2, 1, 8, 0).is_err());
        assert!(OpeningClaimQuotientBatchGeometry::derive(2, 1, 8, 9).is_err());
    }
}
