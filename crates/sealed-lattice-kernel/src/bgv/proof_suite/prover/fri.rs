use super::{
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinError, CommonProofPrivateCoinSource,
    CommonProofProverError, CommonProofReplayPolynomialKey, CommonProofSourcePolynomial,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofPrivacyMode,
    RelationColumnValueType, RelationMaskKind, RelationMaskTargetClass,
    RelationOpeningClaimDescriptor, RelationOpeningSourceClass, RelationPlanVariant, Zeroizing,
    divide_extension_polynomial_by_linear_in_place, sample_private_extension_polynomial,
};

/// Samples the separately committed opening-batch polynomial in secret mode.
pub(crate) fn construct_opening_batch_mask<Coins>(
    variant: &RelationPlanVariant,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<
    Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    CommonProofPrivateCoinError<Coins::Error>,
>
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
        CommonProofPrivateCoinCoordinate::from_mask(descriptor.mask_coordinate()),
        descriptor.mask_degree_bound_exclusive(),
        maximum_candidate_draws_per_output,
    )?))
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
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    match polynomial {
        CommonProofSourcePolynomial::Base(coefficients) => {
            let mut extension_coefficients = Zeroizing::new(Vec::new());
            extension_coefficients
                .try_reserve_exact(coefficients.len())
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            extension_coefficients.extend(
                coefficients
                    .iter()
                    .copied()
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
    out_of_domain_evaluation: ProofChallengeExtensionElement,
    batching_coefficient: ProofChallengeExtensionElement,
) -> Result<(), CommonProofProverError> {
    let source_degree_bound_exclusive = usize::try_from(claim.source_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    add_polynomial_to_initial_fri(
        initial,
        opening_degree_bound_exclusive,
        source_degree_bound_exclusive,
        polynomial,
        opening_point,
        out_of_domain_evaluation,
        batching_coefficient,
    )
}

fn add_polynomial_to_initial_fri(
    initial: &mut [ProofChallengeExtensionElement],
    opening_degree_bound_exclusive: usize,
    source_degree_bound_exclusive: usize,
    polynomial: CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
    out_of_domain_evaluation: ProofChallengeExtensionElement,
    batching_coefficient: ProofChallengeExtensionElement,
) -> Result<(), CommonProofProverError> {
    let mut numerator = into_extension_polynomial(polynomial)?;
    if numerator.is_empty()
        || numerator.len() > source_degree_bound_exclusive
        || source_degree_bound_exclusive > opening_degree_bound_exclusive
        || initial.len() + 1 != opening_degree_bound_exclusive
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    numerator[0] = numerator[0].subtract(out_of_domain_evaluation);
    let remainder = divide_extension_polynomial_by_linear_in_place(&mut numerator, opening_point)?;
    if !remainder.is_zero() {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let shift = opening_degree_bound_exclusive
        .checked_sub(source_degree_bound_exclusive)
        .ok_or(CommonProofProverError::InvalidOpening)?;
    for (coefficient_ordinal, coefficient) in numerator.iter().copied().enumerate() {
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
