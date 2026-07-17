use super::{
    CommonProofPrivateCoinError, CommonProofPrivateCoinSource, CommonProofProverError,
    CommonProofReplayPolynomialKey, CommonProofSourcePolynomial, ProofBaseFieldElement,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofPrivacyMode,
    RelationColumnValueType, RelationMaskKind, RelationMaskTargetClass,
    RelationOpeningClaimDescriptor, RelationOpeningSourceClass, RelationPlanVariant,
    divide_extension_polynomial_by_linear_in_place, evaluate_extension_at,
    extension_polynomial_degree, fold_extension_evaluations, sample_private_extension_polynomial,
    validate_column_polynomials,
};

/// Samples the separately committed opening-batch polynomial in secret mode.
pub(crate) fn construct_opening_batch_mask<Coins>(
    variant: &RelationPlanVariant,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<Option<Vec<ProofChallengeExtensionElement>>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(None);
    }
    let mut descriptors = variant.ordered_masks().iter().copied().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::OpeningBatch
            && mask.target_class() == RelationMaskTargetClass::Batch
            && mask.target_ordinal() == 0
    });
    let descriptor = descriptors
        .next()
        .ok_or_else(|| CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidMask))?;
    if descriptors.next().is_some() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    Ok(Some(sample_private_extension_polynomial(
        coins,
        descriptor.mask_purpose(),
        descriptor.mask_degree_bound_exclusive(),
        maximum_candidate_draws_per_output,
    )?))
}

/// Emits the opening-claim-ordered DEEP values from the exact source
/// polynomials committed by the prover.
pub(crate) fn evaluate_ordered_deep_openings(
    variant: &RelationPlanVariant,
    columns: &[CommonProofSourcePolynomial],
    quotient_components: &[Vec<ProofChallengeExtensionElement>],
    opening_batch_mask: Option<&[ProofChallengeExtensionElement]>,
    opening_points: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    validate_column_polynomials(variant, columns)?;
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(variant.ordered_opening_claims().len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for claim in variant.ordered_opening_claims() {
        let point = opening_points
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        let value = match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => {
                let column_ordinal = claim
                    .column_ordinal()
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                columns
                    .get(
                        usize::try_from(column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?
                    .evaluate_at(point)
            }
            RelationOpeningSourceClass::Quotient => {
                if claim.column_ordinal().is_some() {
                    return Err(CommonProofProverError::InvalidOpening);
                }
                let coefficients = quotient_components
                    .get(
                        usize::try_from(claim.source_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                evaluate_extension_at(coefficients, point)
            }
            RelationOpeningSourceClass::BatchMask => {
                if claim.source_ordinal() != 0 || claim.column_ordinal().is_some() {
                    return Err(CommonProofProverError::InvalidOpening);
                }
                evaluate_extension_at(
                    opening_batch_mask.ok_or(CommonProofProverError::InvalidOpening)?,
                    point,
                )
            }
        };
        evaluations.push(value);
    }
    Ok(evaluations)
}

/// Constructs the exact normalized initial-FRI polynomial.  The separately
/// committed batch mask is added directly and its class-three opening claim is
/// still included in the ordered normalized sum.
pub(crate) fn construct_initial_fri_polynomial(
    variant: &RelationPlanVariant,
    columns: &[CommonProofSourcePolynomial],
    quotient_components: &[Vec<ProofChallengeExtensionElement>],
    opening_batch_mask: Option<&[ProofChallengeExtensionElement]>,
    opening_points: &[ProofChallengeExtensionElement],
    deep_evaluations: &[ProofChallengeExtensionElement],
    batching_coefficients: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    if deep_evaluations.len() != variant.ordered_opening_claims().len()
        || batching_coefficients.len() != deep_evaluations.len()
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let opening_bound = usize::try_from(variant.opening_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if opening_bound <= 1 {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let mut initial = vec![ProofChallengeExtensionElement::ZERO; opening_bound - 1];
    if let Some(mask) = opening_batch_mask {
        if mask.len() > initial.len() {
            return Err(CommonProofProverError::InvalidMask);
        }
        for (destination, coefficient) in initial.iter_mut().zip(mask) {
            *destination = destination.add(*coefficient);
        }
    } else if variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing {
        return Err(CommonProofProverError::InvalidMask);
    }

    for (claim_ordinal, claim) in variant.ordered_opening_claims().iter().enumerate() {
        let mut numerator = Vec::new();
        match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => {
                let column = columns
                    .get(
                        usize::try_from(
                            claim
                                .column_ordinal()
                                .ok_or(CommonProofProverError::InvalidOpening)?,
                        )
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                numerator
                    .try_reserve_exact(column.coefficient_count())
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                match column {
                    CommonProofSourcePolynomial::Base(coefficients) => numerator.extend(
                        coefficients
                            .iter()
                            .copied()
                            .map(ProofChallengeExtensionElement::from_base),
                    ),
                    CommonProofSourcePolynomial::Extension(coefficients) => {
                        numerator.extend_from_slice(coefficients);
                    }
                }
            }
            RelationOpeningSourceClass::Quotient => {
                let coefficients = quotient_components
                    .get(
                        usize::try_from(claim.source_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                numerator
                    .try_reserve_exact(coefficients.len())
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                numerator.extend_from_slice(coefficients);
            }
            RelationOpeningSourceClass::BatchMask => {
                let coefficients =
                    opening_batch_mask.ok_or(CommonProofProverError::InvalidOpening)?;
                numerator
                    .try_reserve_exact(coefficients.len())
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                numerator.extend_from_slice(coefficients);
            }
        }
        let source_bound = usize::try_from(claim.source_degree_bound_exclusive())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if numerator.is_empty() || numerator.len() > source_bound || source_bound > opening_bound {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let opening_point = opening_points
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        numerator[0] = numerator[0].subtract(deep_evaluations[claim_ordinal]);
        let remainder =
            divide_extension_polynomial_by_linear_in_place(&mut numerator, opening_point)?;
        if !remainder.is_zero() {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let shift = opening_bound
            .checked_sub(source_bound)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        let batching_coefficient = batching_coefficients[claim_ordinal];
        for (coefficient_ordinal, coefficient) in numerator.into_iter().enumerate() {
            let destination_ordinal = shift
                .checked_add(coefficient_ordinal)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let destination = initial
                .get_mut(destination_ordinal)
                .ok_or(CommonProofProverError::InvalidOpening)?;
            *destination = destination.add(coefficient.multiply(batching_coefficient));
        }
    }
    trim_extension_polynomial(&mut initial);
    if extension_polynomial_degree(&initial).is_some_and(|degree| degree >= opening_bound - 1) {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    Ok(initial)
}

pub(super) fn replay_polynomial_key_for_claim(
    claim: &RelationOpeningClaimDescriptor,
) -> Result<CommonProofReplayPolynomialKey, CommonProofProverError> {
    match claim.source_class() {
        RelationOpeningSourceClass::TreeColumn => {
            Ok(CommonProofReplayPolynomialKey::RelationColumn(
                claim
                    .column_ordinal()
                    .ok_or(CommonProofProverError::InvalidOpening)?,
            ))
        }
        RelationOpeningSourceClass::Quotient => {
            if claim.column_ordinal().is_some() {
                return Err(CommonProofProverError::InvalidOpening);
            }
            Ok(CommonProofReplayPolynomialKey::QuotientComponent(
                u16::try_from(claim.source_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ))
        }
        RelationOpeningSourceClass::BatchMask => {
            if claim.source_ordinal() != 0 || claim.column_ordinal().is_some() {
                return Err(CommonProofProverError::InvalidOpening);
            }
            Ok(CommonProofReplayPolynomialKey::OpeningBatchMask)
        }
    }
}

pub(super) fn evaluate_replay_polynomial_opening(
    claim: &RelationOpeningClaimDescriptor,
    polynomial: &CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
    let source_degree_bound_exclusive = usize::try_from(claim.source_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if polynomial.coefficient_count() == 0
        || polynomial.coefficient_count() > source_degree_bound_exclusive
        || (claim.source_class() != RelationOpeningSourceClass::TreeColumn
            && polynomial.value_type() != RelationColumnValueType::ChallengeExtension)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    Ok(polynomial.evaluate_at(opening_point))
}

fn into_extension_polynomial(
    polynomial: CommonProofSourcePolynomial,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    match polynomial {
        CommonProofSourcePolynomial::Base(coefficients) => {
            let mut extension_coefficients = Vec::new();
            extension_coefficients
                .try_reserve_exact(coefficients.len())
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            extension_coefficients.extend(
                coefficients
                    .into_iter()
                    .map(ProofChallengeExtensionElement::from_base),
            );
            Ok(extension_coefficients)
        }
        CommonProofSourcePolynomial::Extension(coefficients) => Ok(coefficients),
    }
}

pub(super) fn add_replay_polynomial_to_initial_fri(
    initial: &mut [ProofChallengeExtensionElement],
    opening_degree_bound_exclusive: usize,
    claim: &RelationOpeningClaimDescriptor,
    polynomial: CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
    deep_evaluation: ProofChallengeExtensionElement,
    batching_coefficient: ProofChallengeExtensionElement,
) -> Result<(), CommonProofProverError> {
    let mut numerator = into_extension_polynomial(polynomial)?;
    let source_degree_bound_exclusive = usize::try_from(claim.source_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if numerator.is_empty()
        || numerator.len() > source_degree_bound_exclusive
        || source_degree_bound_exclusive > opening_degree_bound_exclusive
        || initial.len() + 1 != opening_degree_bound_exclusive
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    numerator[0] = numerator[0].subtract(deep_evaluation);
    let remainder = divide_extension_polynomial_by_linear_in_place(&mut numerator, opening_point)?;
    if !remainder.is_zero() {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let shift = opening_degree_bound_exclusive
        .checked_sub(source_degree_bound_exclusive)
        .ok_or(CommonProofProverError::InvalidOpening)?;
    for (coefficient_ordinal, coefficient) in numerator.into_iter().enumerate() {
        let destination_ordinal = shift
            .checked_add(coefficient_ordinal)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination = initial
            .get_mut(destination_ordinal)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        *destination = destination.add(coefficient.multiply(batching_coefficient));
    }
    Ok(())
}

/// Builds one FRI layer only.  Callers persist the returned layer before
/// releasing the previous one, so peak memory is two layers rather than the
/// complete fold chain.
pub(crate) fn construct_next_fri_layer(
    current_evaluations: &[ProofChallengeExtensionElement],
    current_domain: ProofEvaluationDomain,
    challenge: ProofChallengeExtensionElement,
) -> Result<(ProofEvaluationDomain, Vec<ProofChallengeExtensionElement>), CommonProofProverError> {
    if current_evaluations.len() != current_domain.size() {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    let folded = fold_extension_evaluations(current_evaluations, current_domain, challenge)?;
    Ok((current_domain.folded()?, folded))
}

/// Interpolates the final FRI layer and pads to the schedule-fixed exclusive
/// degree bound.  Padding is part of the proof bytes and transcript.
pub(crate) fn construct_fri_terminal_coefficients(
    terminal_evaluations: &[ProofChallengeExtensionElement],
    terminal_domain: ProofEvaluationDomain,
    final_degree_bound_exclusive: u32,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    let bound = usize::try_from(final_degree_bound_exclusive)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if bound == 0 || terminal_evaluations.len() != terminal_domain.size() {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    let mut coefficients =
        terminal_domain.interpolate_extension_polynomial(terminal_evaluations)?;
    if extension_polynomial_degree(&coefficients).is_some_and(|degree| degree >= bound) {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    coefficients.resize(bound, ProofChallengeExtensionElement::ZERO);
    Ok(coefficients)
}

pub(super) fn add_shifted_extension_polynomial(
    target: &mut Vec<ProofChallengeExtensionElement>,
    addend: &[ProofChallengeExtensionElement],
    shift: usize,
) -> Result<(), CommonProofProverError> {
    let required = shift
        .checked_add(addend.len())
        .ok_or(CommonProofProverError::CountOverflow)?;
    if target.len() < required {
        target.resize(required, ProofChallengeExtensionElement::ZERO);
    }
    for (ordinal, coefficient) in addend.iter().copied().enumerate() {
        target[shift + ordinal] = target[shift + ordinal].add(coefficient);
    }
    Ok(())
}

pub(super) fn subtract_extension_polynomial(
    target: &mut Vec<ProofChallengeExtensionElement>,
    subtrahend: &[ProofChallengeExtensionElement],
) -> Result<(), CommonProofProverError> {
    if target.len() < subtrahend.len() {
        target.resize(subtrahend.len(), ProofChallengeExtensionElement::ZERO);
    }
    for (destination, coefficient) in target.iter_mut().zip(subtrahend) {
        *destination = destination.subtract(*coefficient);
    }
    Ok(())
}

pub(super) fn trim_base_polynomial(coefficients: &mut Vec<ProofBaseFieldElement>) {
    while coefficients.len() > 1 && coefficients.last() == Some(&ProofBaseFieldElement::ZERO) {
        coefficients.pop();
    }
}

pub(super) fn trim_extension_polynomial(coefficients: &mut Vec<ProofChallengeExtensionElement>) {
    while coefficients.len() > 1
        && coefficients.last() == Some(&ProofChallengeExtensionElement::ZERO)
    {
        coefficients.pop();
    }
}
