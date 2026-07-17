use super::{
    BTreeSet, CommonProofColumnEvaluations, CommonProofPrivateCoinError,
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofSourcePolynomial,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofPrivacyMode,
    RelationApplicationChallengeAssignment, RelationMaskDescriptor, RelationMaskKind,
    RelationMaskTargetClass, RelationOpeningSourceClass, RelationPlanCheckContext,
    RelationPlanError, RelationPlanVariant, add_shifted_extension_polynomial,
    sample_private_extension_polynomial, subtract_extension_polynomial, trim_extension_polynomial,
};

pub(super) fn validate_column_polynomials(
    variant: &RelationPlanVariant,
    columns: &[CommonProofSourcePolynomial],
) -> Result<(), CommonProofProverError> {
    if columns.len() != variant.ordered_columns().len() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    for (descriptor, polynomial) in variant.ordered_columns().iter().zip(columns) {
        if descriptor.value_type() != polynomial.value_type()
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count()
                > usize::try_from(descriptor.source_degree_bound_exclusive())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(())
}

/// Evaluates the checked relation on the complete evaluation coset and
/// interpolates the one normalized composed quotient polynomial.
#[cfg(test)]
pub(crate) fn construct_composed_quotient_polynomial(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    evaluation_domain: ProofEvaluationDomain,
    columns: &[CommonProofSourcePolynomial],
    application_challenges: &[RelationApplicationChallengeAssignment],
    composition_challenges: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    validate_column_polynomials(variant, columns)?;
    if evaluation_domain.size()
        != usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?
        || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
        || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
        || !variant
            .evaluation_domain_size()
            .is_multiple_of(variant.trace_domain_size())
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }

    let column_evaluations = columns
        .iter()
        .map(|column| match column {
            CommonProofSourcePolynomial::Base(coefficients) => evaluation_domain
                .evaluate_base_polynomial(coefficients)
                .map(CommonProofColumnEvaluations::Base),
            CommonProofSourcePolynomial::Extension(coefficients) => evaluation_domain
                .evaluate_extension_polynomial(coefficients)
                .map(CommonProofColumnEvaluations::Extension),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evaluation_size = evaluation_domain.size();
    let trace_rotation_stride =
        usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;

    let mut quotient_evaluations = Vec::new();
    quotient_evaluations
        .try_reserve_exact(evaluation_size)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for evaluation_position in 0..evaluation_size {
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            evaluation_domain.point(evaluation_position)?,
        );
        quotient_evaluations.push(variant.evaluate_composed_quotient_at_point(
            context,
            evaluation_point,
            application_challenges,
            composition_challenges,
            |column_ordinal, rotation_is_negative, rotation_magnitude| {
                let column_index = usize::try_from(column_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                let reduced_rotation =
                    usize::try_from(rotation_magnitude % variant.trace_domain_size())
                        .map_err(|_| RelationPlanError::CountOverflow)?;
                let rotation_offset = reduced_rotation
                    .checked_mul(trace_rotation_stride)
                    .ok_or(RelationPlanError::CountOverflow)?;
                let rotated_position = if rotation_is_negative {
                    evaluation_position
                        .checked_add(evaluation_size)
                        .and_then(|position| position.checked_sub(rotation_offset))
                        .ok_or(RelationPlanError::CountOverflow)?
                        % evaluation_size
                } else {
                    evaluation_position
                        .checked_add(rotation_offset)
                        .ok_or(RelationPlanError::CountOverflow)?
                        % evaluation_size
                };
                if reduced_rotation >= trace_domain_size {
                    return Err(RelationPlanError::InvalidOpening);
                }
                column_evaluations
                    .get(column_index)
                    .ok_or(RelationPlanError::InvalidConstraint)?
                    .extension_value(rotated_position)
                    .map_err(|_| RelationPlanError::InvalidConstraint)
            },
        )?);
    }
    let mut quotient = evaluation_domain.interpolate_extension_polynomial(&quotient_evaluations)?;
    trim_extension_polynomial(&mut quotient);
    Ok(quotient)
}

pub(super) const COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH: usize = 4_096;

pub(super) fn required_relation_rotations_by_column(
    variant: &RelationPlanVariant,
) -> Result<Vec<Vec<(bool, u64)>>, CommonProofProverError> {
    let mut rotations_by_column = vec![BTreeSet::new(); variant.ordered_columns().len()];
    for claim in variant.ordered_opening_claims() {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_index = usize::try_from(
            claim
                .column_ordinal()
                .ok_or(CommonProofProverError::InvalidOpening)?,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let opening_point = variant
            .ordered_opening_points()
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidOpening)?;
        rotations_by_column
            .get_mut(column_index)
            .ok_or(CommonProofProverError::InvalidColumn)?
            .insert(opening_point.trace_rotation());
    }
    rotations_by_column
        .into_iter()
        .map(|rotations| {
            if rotations.is_empty() {
                Err(CommonProofProverError::InvalidColumn)
            } else {
                Ok(rotations.into_iter().collect())
            }
        })
        .collect()
}

fn rotated_relation_evaluation_position(
    evaluation_position: usize,
    evaluation_size: usize,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Result<usize, CommonProofProverError> {
    let reduced_rotation = usize::try_from(
        rotation_magnitude
            % u64::try_from(trace_domain_size)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
    )
    .map_err(|_| CommonProofProverError::CountOverflow)?;
    if reduced_rotation >= trace_domain_size {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let rotation_offset = reduced_rotation
        .checked_mul(trace_rotation_stride)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if rotation_is_negative {
        evaluation_position
            .checked_add(evaluation_size)
            .and_then(|position| position.checked_sub(rotation_offset))
            .map(|position| position % evaluation_size)
            .ok_or(CommonProofProverError::CountOverflow)
    } else {
        evaluation_position
            .checked_add(rotation_offset)
            .map(|position| position % evaluation_size)
            .ok_or(CommonProofProverError::CountOverflow)
    }
}

pub(super) struct CommonProofReplayQuotientBuilder {
    evaluation_domain: ProofEvaluationDomain,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    rotations_by_column: Vec<Vec<(bool, u64)>>,
    block_values_by_column: Vec<Vec<Vec<ProofChallengeExtensionElement>>>,
    block_start: usize,
    next_column_index: usize,
    quotient_evaluations: Vec<ProofChallengeExtensionElement>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
    composition_challenges: Vec<ProofChallengeExtensionElement>,
}

impl CommonProofReplayQuotientBuilder {
    pub(super) fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        evaluation_domain: ProofEvaluationDomain,
        application_challenges: Vec<RelationApplicationChallengeAssignment>,
        composition_challenges: Vec<ProofChallengeExtensionElement>,
    ) -> Result<Self, CommonProofProverError> {
        if evaluation_domain.size()
            != usize::try_from(variant.evaluation_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?
            || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
            || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
            || !variant
                .evaluation_domain_size()
                .is_multiple_of(variant.trace_domain_size())
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let trace_domain_size = usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_rotation_stride =
            usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let rotations_by_column = required_relation_rotations_by_column(variant)?;
        let mut quotient_evaluations = Vec::new();
        quotient_evaluations
            .try_reserve_exact(evaluation_domain.size())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(Self {
            evaluation_domain,
            trace_domain_size,
            trace_rotation_stride,
            rotations_by_column,
            block_values_by_column: Vec::new(),
            block_start: 0,
            next_column_index: 0,
            quotient_evaluations,
            application_challenges,
            composition_challenges,
        })
    }

    pub(super) fn next_column_index(&self) -> Option<usize> {
        (self.block_start < self.evaluation_domain.size()
            && self.next_column_index < self.rotations_by_column.len())
        .then_some(self.next_column_index)
    }

    pub(super) fn accept_column(
        &mut self,
        column_index: usize,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        if self.next_column_index() != Some(column_index) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let evaluations = match polynomial {
            CommonProofSourcePolynomial::Base(coefficients) => CommonProofColumnEvaluations::Base(
                self.evaluation_domain
                    .evaluate_base_polynomial(&coefficients)?,
            ),
            CommonProofSourcePolynomial::Extension(mut coefficients) => {
                self.evaluation_domain
                    .evaluate_extension_polynomial_in_place(&mut coefficients)?;
                CommonProofColumnEvaluations::Extension(coefficients)
            }
        };
        let block_end = self
            .block_start
            .checked_add(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(self.evaluation_domain.size());
        let rotations = self
            .rotations_by_column
            .get(column_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let mut values_by_rotation = Vec::new();
        values_by_rotation
            .try_reserve_exact(rotations.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for (rotation_is_negative, rotation_magnitude) in rotations.iter().copied() {
            let mut values = Vec::new();
            values
                .try_reserve_exact(block_end - self.block_start)
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            for evaluation_position in self.block_start..block_end {
                let rotated_position = rotated_relation_evaluation_position(
                    evaluation_position,
                    self.evaluation_domain.size(),
                    self.trace_domain_size,
                    self.trace_rotation_stride,
                    rotation_is_negative,
                    rotation_magnitude,
                )?;
                values.push(evaluations.extension_value(rotated_position)?);
            }
            values_by_rotation.push(values);
        }
        self.block_values_by_column.push(values_by_rotation);
        self.next_column_index = self
            .next_column_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    pub(super) fn evaluate_ready_block(
        &mut self,
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<bool, CommonProofProverError> {
        if self.block_start >= self.evaluation_domain.size()
            || self.next_column_index != self.rotations_by_column.len()
            || self.block_values_by_column.len() != self.rotations_by_column.len()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let block_end = self
            .block_start
            .checked_add(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(self.evaluation_domain.size());
        for evaluation_position in self.block_start..block_end {
            let block_position = evaluation_position - self.block_start;
            let evaluation_point = ProofChallengeExtensionElement::from_base(
                self.evaluation_domain.point(evaluation_position)?,
            );
            self.quotient_evaluations.push(
                variant
                    .evaluate_composed_quotient_at_point(
                        context,
                        evaluation_point,
                        &self.application_challenges,
                        &self.composition_challenges,
                        |column_ordinal, rotation_is_negative, rotation_magnitude| {
                            let column_index = usize::try_from(column_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?;
                            let rotations = self
                                .rotations_by_column
                                .get(column_index)
                                .ok_or(RelationPlanError::InvalidConstraint)?;
                            let rotation_index = rotations
                                .binary_search(&(rotation_is_negative, rotation_magnitude))
                                .map_err(|_| RelationPlanError::InvalidOpening)?;
                            self.block_values_by_column
                                .get(column_index)
                                .and_then(|values_by_rotation| {
                                    values_by_rotation.get(rotation_index)
                                })
                                .and_then(|values| values.get(block_position))
                                .copied()
                                .ok_or(RelationPlanError::InvalidConstraint)
                        },
                    )
                    .map_err(CommonProofProverError::from)?,
            );
        }
        self.block_values_by_column.clear();
        self.next_column_index = 0;
        self.block_start = block_end;
        Ok(self.block_start == self.evaluation_domain.size())
    }

    pub(super) fn finish(
        mut self,
    ) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
        if self.block_start != self.evaluation_domain.size()
            || self.quotient_evaluations.len() != self.evaluation_domain.size()
            || !self.block_values_by_column.is_empty()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.evaluation_domain
            .interpolate_extension_polynomial_in_place(&mut self.quotient_evaluations)?;
        trim_extension_polynomial(&mut self.quotient_evaluations);
        Ok(self.quotient_evaluations)
    }
}

/// Splits the unique quotient into constant-first components of width `kHat`.
#[cfg(test)]
pub(crate) fn decompose_composed_quotient(
    quotient: &[ProofChallengeExtensionElement],
    component_count: u32,
    component_stride: u64,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    let component_count =
        usize::try_from(component_count).map_err(|_| CommonProofProverError::CountOverflow)?;
    let component_stride =
        usize::try_from(component_stride).map_err(|_| CommonProofProverError::CountOverflow)?;
    if component_count < 2 || component_stride == 0 || quotient.is_empty() {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let capacity = component_count
        .checked_mul(component_stride)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if quotient.len() > capacity {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let mut components = Vec::new();
    components
        .try_reserve_exact(component_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for component_ordinal in 0..component_count {
        let start = component_ordinal
            .checked_mul(component_stride)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let end = start
            .checked_add(component_stride)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(quotient.len());
        let mut component = if start < quotient.len() {
            quotient[start..end].to_vec()
        } else {
            vec![ProofChallengeExtensionElement::ZERO]
        };
        trim_extension_polynomial(&mut component);
        components.push(component);
    }
    Ok(components)
}

/// Applies the exact neighboring telescoping randomizers to canonical quotient
/// components.  Public-only mode performs no private-randomness call.
#[cfg(test)]
pub(crate) fn construct_quotient_components<Coins>(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    quotient: &[ProofChallengeExtensionElement],
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let mut cursor = CommonProofQuotientComponentCursor::new(variant, context, quotient.to_vec())
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let component_count = cursor.component_count();
    let mut components = Vec::new();
    components.try_reserve_exact(component_count).map_err(|_| {
        CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
    })?;
    while let Some(component) = cursor.next_component(coins, maximum_candidate_draws_per_output)? {
        components.push(component);
    }
    Ok(components)
}

pub(super) struct CommonProofQuotientComponentCursor {
    quotient: Vec<ProofChallengeExtensionElement>,
    stride: usize,
    component_count: usize,
    component_degree_bound_exclusive: usize,
    telescoping_descriptors: Vec<RelationMaskDescriptor>,
    previous_randomizer: Option<Vec<ProofChallengeExtensionElement>>,
    next_component_index: usize,
}

impl CommonProofQuotientComponentCursor {
    pub(super) fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        quotient: Vec<ProofChallengeExtensionElement>,
    ) -> Result<Self, CommonProofProverError> {
        let stride = usize::try_from(variant.quotient_decomposition_stride(context)?)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let component_count = usize::try_from(context.quotient_component_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let component_degree_bound_exclusive =
            usize::try_from(context.quotient_component_degree_bound_exclusive)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        if stride == 0
            || component_count < 2
            || component_degree_bound_exclusive == 0
            || quotient.is_empty()
            || quotient.len()
                > stride
                    .checked_mul(component_count)
                    .ok_or(CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let telescoping_descriptors = variant
            .ordered_masks()
            .iter()
            .copied()
            .filter(|mask| {
                mask.mask_kind() == RelationMaskKind::Telescoping
                    && mask.target_class() == RelationMaskTargetClass::QuotientComponent
            })
            .collect::<Vec<_>>();
        match variant.proof_privacy_mode() {
            ProofPrivacyMode::PublicOnly if !variant.ordered_masks().is_empty() => {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::PublicOnly if !telescoping_descriptors.is_empty() => {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::SecretBearing
                if telescoping_descriptors.len() + 1 != component_count
                    || telescoping_descriptors
                        .iter()
                        .enumerate()
                        .any(|(ordinal, mask)| {
                            usize::try_from(mask.target_ordinal()).ok() != Some(ordinal)
                        }) =>
            {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::PublicOnly | ProofPrivacyMode::SecretBearing => {}
        }
        Ok(Self {
            quotient,
            stride,
            component_count,
            component_degree_bound_exclusive,
            telescoping_descriptors,
            previous_randomizer: None,
            next_component_index: 0,
        })
    }

    const fn component_count(&self) -> usize {
        self.component_count
    }

    pub(super) fn next_component<Coins: CommonProofPrivateCoinSource>(
        &mut self,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<
        Option<Vec<ProofChallengeExtensionElement>>,
        CommonProofPrivateCoinError<Coins::Error>,
    > {
        if self.next_component_index >= self.component_count {
            if self.previous_randomizer.is_some() {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidMask,
                ));
            }
            return Ok(None);
        }
        let component_index = self.next_component_index;
        let mut component = self
            .quotient
            .iter()
            .skip(component_index.checked_mul(self.stride).ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .take(self.stride)
            .copied()
            .collect::<Vec<_>>();
        if component.is_empty() {
            component.push(ProofChallengeExtensionElement::ZERO);
        }
        let next_randomizer =
            if let Some(descriptor) = self.telescoping_descriptors.get(component_index).copied() {
                let randomizer = sample_private_extension_polynomial(
                    coins,
                    descriptor.mask_purpose(),
                    descriptor.mask_degree_bound_exclusive(),
                    maximum_candidate_draws_per_output,
                )?;
                add_shifted_extension_polynomial(&mut component, &randomizer, self.stride)
                    .map_err(CommonProofPrivateCoinError::Prover)?;
                Some(randomizer)
            } else {
                None
            };
        if let Some(previous_randomizer) = self.previous_randomizer.take() {
            subtract_extension_polynomial(&mut component, &previous_randomizer)
                .map_err(CommonProofPrivateCoinError::Prover)?;
        }
        trim_extension_polynomial(&mut component);
        if component.len() > self.component_degree_bound_exclusive {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidQuotient,
            ));
        }
        self.previous_randomizer = next_randomizer;
        self.next_component_index = self.next_component_index.checked_add(1).ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        Ok(Some(component))
    }
}
