//! Exact normalized opening-batch evaluation for the common proof.

use super::{
    field::{ProofBaseFieldElement, ProofChallengeExtensionElement, ProofFieldError},
    fri::OpenedFriLayerPair,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofOpeningError {
    InvalidOpeningDegree,
    #[cfg(any(test, feature = "proof-storage-width-browser-evidence"))]
    EmptyOpeningBatch,
    OpeningPointOnEvaluationPair,
    Field(ProofFieldError),
}

impl From<ProofFieldError> for ProofOpeningError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofOpeningClaimEvaluation {
    source_degree_bound_exclusive: u64,
    opening_point: ProofChallengeExtensionElement,
    opened_value: ProofChallengeExtensionElement,
    source_pair: OpenedFriLayerPair,
    batching_coefficient: ProofChallengeExtensionElement,
}

impl ProofOpeningClaimEvaluation {
    pub(crate) fn new(
        source_degree_bound_exclusive: u64,
        opening_point: ProofChallengeExtensionElement,
        opened_value: ProofChallengeExtensionElement,
        source_pair: OpenedFriLayerPair,
        batching_coefficient: ProofChallengeExtensionElement,
    ) -> Self {
        Self {
            source_degree_bound_exclusive,
            opening_point,
            opened_value,
            source_pair,
            batching_coefficient,
        }
    }
}

/// Evaluates the one normalized initial-FRI polynomial at an authenticated
/// evaluation-domain point and its opposite.  `opening_batch_mask_pair` is
/// present exactly for a secret-bearing relation and absent for a public-only
/// relation; the caller enforces the plan mode before invoking this function.
#[cfg(any(test, feature = "proof-storage-width-browser-evidence"))]
pub(crate) fn evaluate_initial_fri_pair(
    opening_degree_bound_exclusive: u64,
    evaluation_point: ProofBaseFieldElement,
    claims: &[ProofOpeningClaimEvaluation],
    opening_batch_mask_pair: Option<OpenedFriLayerPair>,
) -> Result<OpenedFriLayerPair, ProofOpeningError> {
    if opening_degree_bound_exclusive <= 1 {
        return Err(ProofOpeningError::InvalidOpeningDegree);
    }
    if claims.is_empty() {
        return Err(ProofOpeningError::EmptyOpeningBatch);
    }

    let mut positive = opening_batch_mask_pair
        .map(OpenedFriLayerPair::first)
        .unwrap_or(ProofChallengeExtensionElement::ZERO);
    let mut opposite = opening_batch_mask_pair
        .map(OpenedFriLayerPair::opposite)
        .unwrap_or(ProofChallengeExtensionElement::ZERO);

    for claim in claims {
        let term = evaluate_normalized_opening_claim_pair(
            opening_degree_bound_exclusive,
            evaluation_point,
            *claim,
        )?;
        positive = positive.add(term.first());
        opposite = opposite.add(term.opposite());
    }
    Ok(OpenedFriLayerPair::new(positive, opposite))
}

pub(crate) fn evaluate_normalized_opening_claim_pair(
    opening_degree_bound_exclusive: u64,
    evaluation_point: ProofBaseFieldElement,
    claim: ProofOpeningClaimEvaluation,
) -> Result<OpenedFriLayerPair, ProofOpeningError> {
    if opening_degree_bound_exclusive <= 1
        || claim.source_degree_bound_exclusive == 0
        || claim.source_degree_bound_exclusive > opening_degree_bound_exclusive
    {
        return Err(ProofOpeningError::InvalidOpeningDegree);
    }
    let positive_point = ProofChallengeExtensionElement::from_base(evaluation_point);
    let opposite_point = ProofChallengeExtensionElement::from_base(evaluation_point.negate());
    let normalization_exponent =
        opening_degree_bound_exclusive - claim.source_degree_bound_exclusive;
    let positive_denominator = positive_point.subtract(claim.opening_point);
    let opposite_denominator = opposite_point.subtract(claim.opening_point);
    if positive_denominator.is_zero() || opposite_denominator.is_zero() {
        return Err(ProofOpeningError::OpeningPointOnEvaluationPair);
    }

    let positive_term = positive_point.power(normalization_exponent).multiply(
        claim
            .source_pair
            .first()
            .subtract(claim.opened_value)
            .divide(positive_denominator)?,
    );
    let opposite_term = opposite_point.power(normalization_exponent).multiply(
        claim
            .source_pair
            .opposite()
            .subtract(claim.opened_value)
            .divide(opposite_denominator)?,
    );
    Ok(OpenedFriLayerPair::new(
        claim.batching_coefficient.multiply(positive_term),
        claim.batching_coefficient.multiply(opposite_term),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::polynomial::evaluate_extension_at;

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("small canonical value")
    }

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(base(value))
    }

    #[test]
    fn normalized_batch_matches_direct_polynomial_evaluation() {
        let evaluation_point = base(7);
        let positive_point = extension(7);
        let opposite_point = ProofChallengeExtensionElement::from_base(base(7).negate());
        let first_coefficients = [extension(3), extension(4), extension(2)];
        let second_coefficients = [extension(9), extension(1)];
        let first_opening_point = extension(13);
        let second_opening_point = extension(17);
        let first_opened = evaluate_extension_at(&first_coefficients, first_opening_point);
        let second_opened = evaluate_extension_at(&second_coefficients, second_opening_point);
        let claims = [
            ProofOpeningClaimEvaluation::new(
                3,
                first_opening_point,
                first_opened,
                OpenedFriLayerPair::new(
                    evaluate_extension_at(&first_coefficients, positive_point),
                    evaluate_extension_at(&first_coefficients, opposite_point),
                ),
                extension(5),
            ),
            ProofOpeningClaimEvaluation::new(
                2,
                second_opening_point,
                second_opened,
                OpenedFriLayerPair::new(
                    evaluate_extension_at(&second_coefficients, positive_point),
                    evaluate_extension_at(&second_coefficients, opposite_point),
                ),
                extension(11),
            ),
        ];
        let mask = OpenedFriLayerPair::new(extension(19), extension(23));
        let actual = evaluate_initial_fri_pair(8, evaluation_point, &claims, Some(mask))
            .expect("valid normalized batch");

        let direct_term = |coefficients: &[ProofChallengeExtensionElement],
                           opening_point: ProofChallengeExtensionElement,
                           opened_value: ProofChallengeExtensionElement,
                           source_degree: u64,
                           batching_coefficient: ProofChallengeExtensionElement,
                           point: ProofChallengeExtensionElement| {
            batching_coefficient.multiply(
                point.power(8 - source_degree).multiply(
                    evaluate_extension_at(coefficients, point)
                        .subtract(opened_value)
                        .divide(point.subtract(opening_point))
                        .expect("test denominator is nonzero"),
                ),
            )
        };
        assert_eq!(
            actual.first(),
            mask.first()
                .add(direct_term(
                    &first_coefficients,
                    first_opening_point,
                    first_opened,
                    3,
                    extension(5),
                    positive_point,
                ))
                .add(direct_term(
                    &second_coefficients,
                    second_opening_point,
                    second_opened,
                    2,
                    extension(11),
                    positive_point,
                )),
        );
        assert_eq!(
            actual.opposite(),
            mask.opposite()
                .add(direct_term(
                    &first_coefficients,
                    first_opening_point,
                    first_opened,
                    3,
                    extension(5),
                    opposite_point,
                ))
                .add(direct_term(
                    &second_coefficients,
                    second_opening_point,
                    second_opened,
                    2,
                    extension(11),
                    opposite_point,
                )),
        );
    }

    #[test]
    fn rejects_a_degree_outside_the_plan_bound_and_a_zero_denominator() {
        let pair = OpenedFriLayerPair::new(extension(1), extension(2));
        let invalid_degree = [ProofOpeningClaimEvaluation::new(
            9,
            extension(3),
            extension(4),
            pair,
            extension(5),
        )];
        assert_eq!(
            evaluate_initial_fri_pair(8, base(7), &invalid_degree, None),
            Err(ProofOpeningError::InvalidOpeningDegree),
        );

        let colliding_point = [ProofOpeningClaimEvaluation::new(
            2,
            extension(7),
            extension(4),
            pair,
            extension(5),
        )];
        assert_eq!(
            evaluate_initial_fri_pair(8, base(7), &colliding_point, None),
            Err(ProofOpeningError::OpeningPointOnEvaluationPair),
        );
    }
}
