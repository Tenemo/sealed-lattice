use super::{
    BTreeMap, BTreeSet, CheckedRelationApplicationChallenges, CommonProofColumnEvaluations,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinError, CommonProofPrivateCoinSource,
    CommonProofProverError, CommonProofSourcePolynomial, ExternalPolynomialVector,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain, ProofPrivacyMode,
    RelationApplicationChallengeAssignment, RelationColumnValueType, RelationConstraintColumnQuery,
    RelationExpressionInstruction,
    RelationMaskDescriptor, RelationMaskKind, RelationMaskTargetClass, RelationPlanCheckContext,
    RelationPlanError, RelationPlanVariant, Zeroizing, add_shifted_extension_polynomial,
    external_value_byte_length, sample_private_extension_polynomial, subtract_extension_polynomial,
    trim_extension_polynomial,
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
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
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
                .map(|values| CommonProofColumnEvaluations::Base(Zeroizing::new(values))),
            CommonProofSourcePolynomial::Extension(coefficients) => evaluation_domain
                .evaluate_extension_polynomial(coefficients)
                .map(|values| CommonProofColumnEvaluations::Extension(Zeroizing::new(values))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evaluation_size = evaluation_domain.size();
    let trace_rotation_stride =
        usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;

    let mut quotient_evaluations = Zeroizing::new(Vec::new());
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
    let mut quotient =
        Zeroizing::new(evaluation_domain.interpolate_extension_polynomial(&quotient_evaluations)?);
    trim_extension_polynomial(&mut quotient);
    Ok(quotient)
}

/// Test oracle for the production constraint-at-a-time schedule. Each
/// constraint materializes only its own unique relation columns, while the
/// older oracle above retains the complete relation-column matrix.
#[cfg(test)]
pub(crate) fn construct_constraint_stream_composed_quotient_polynomial(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    evaluation_domain: ProofEvaluationDomain,
    columns: &[CommonProofSourcePolynomial],
    application_challenges: &[RelationApplicationChallengeAssignment],
    composition_challenges: &[ProofChallengeExtensionElement],
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    validate_column_polynomials(variant, columns)?;
    if evaluation_domain.size()
        != usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?
        || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
        || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
        || !variant
            .evaluation_domain_size()
            .is_multiple_of(variant.trace_domain_size())
        || composition_challenges.len() != variant.constraint_count()
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let checked_application_challenges =
        variant.checked_application_challenges(context, application_challenges)?;
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_rotation_stride =
        usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut quotient_evaluations = Zeroizing::new(vec![
        ProofChallengeExtensionElement::ZERO;
        evaluation_domain.size()
    ]);

    for constraint_ordinal in 0..variant.constraint_count() {
        let queries = variant.constraint_column_queries(constraint_ordinal)?;
        let mut constraint_column_evaluations = BTreeMap::new();
        for column_ordinal in queries
            .iter()
            .map(|query| query.column_ordinal())
            .collect::<BTreeSet<_>>()
        {
            let column = columns
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let evaluations = match column {
                CommonProofSourcePolynomial::Base(coefficients) => evaluation_domain
                    .evaluate_base_polynomial(coefficients)
                    .map(|values| CommonProofColumnEvaluations::Base(Zeroizing::new(values)))?,
                CommonProofSourcePolynomial::Extension(coefficients) => evaluation_domain
                    .evaluate_extension_polynomial(coefficients)
                    .map(|values| {
                        CommonProofColumnEvaluations::Extension(Zeroizing::new(values))
                    })?,
            };
            if constraint_column_evaluations
                .insert(column_ordinal, evaluations)
                .is_some()
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
        }
        let composition_challenge = composition_challenges
            .get(constraint_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        for evaluation_position in 0..evaluation_domain.size() {
            let evaluation_point = ProofChallengeExtensionElement::from_base(
                evaluation_domain.point(evaluation_position)?,
            );
            let evaluation = variant.evaluate_constraint_at_point(
                context,
                constraint_ordinal,
                evaluation_point,
                &checked_application_challenges,
                &mut |column_ordinal, rotation_is_negative, rotation_magnitude| {
                    let rotated_position = rotated_relation_evaluation_position(
                        evaluation_position,
                        evaluation_domain.size(),
                        trace_domain_size,
                        trace_rotation_stride,
                        rotation_is_negative,
                        rotation_magnitude,
                    )
                    .map_err(|error| match error {
                        CommonProofProverError::CountOverflow => RelationPlanError::CountOverflow,
                        _ => RelationPlanError::InvalidOpening,
                    })?;
                    constraint_column_evaluations
                        .get(&column_ordinal)
                        .ok_or(RelationPlanError::InvalidConstraint)?
                        .extension_value(rotated_position)
                        .map_err(|_| RelationPlanError::InvalidConstraint)
                },
            )?;
            let normalized = evaluation
                .numerator
                .divide(evaluation.zeroifier)
                .map_err(|_| RelationPlanError::InvalidZeroifier)?;
            quotient_evaluations[evaluation_position] = quotient_evaluations[evaluation_position]
                .add(normalized.multiply(composition_challenge));
        }
    }
    evaluation_domain.interpolate_extension_polynomial_in_place(&mut quotient_evaluations)?;
    trim_extension_polynomial(&mut quotient_evaluations);
    Ok(quotient_evaluations)
}

pub(super) const COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH: usize = 4_096;

pub(super) fn rotated_relation_evaluation_position(
    evaluation_position: usize,
    evaluation_size: usize,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Result<usize, CommonProofProverError> {
    if evaluation_size == 0
        || trace_domain_size == 0
        || trace_rotation_stride == 0
        || evaluation_position >= evaluation_size
        || trace_domain_size.checked_mul(trace_rotation_stride) != Some(evaluation_size)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CommonProofQuotientConstraintTransformKey {
    constraint_ordinal: u32,
    column_ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CommonProofFusedProductSumKey {
    constraint_ordinal: u32,
    instruction_ordinal: u32,
}

impl CommonProofFusedProductSumKey {
    pub(super) const fn constraint_ordinal(self) -> u32 {
        self.constraint_ordinal
    }

    pub(super) const fn instruction_ordinal(self) -> u32 {
        self.instruction_ordinal
    }
}

#[derive(Clone)]
struct CommonProofFusedProductSumDescriptor {
    key: CommonProofFusedProductSumKey,
    coefficient_period: usize,
    ordered_terms:
        Vec<crate::bgv::proof_suite::relation_plan::RelationConstantColumnVerifierSequenceProductTerm>,
    coefficient_count: usize,
}

fn common_proof_fused_product_sum_descriptors(
    variant: &RelationPlanVariant,
) -> Result<Vec<CommonProofFusedProductSumDescriptor>, CommonProofProverError> {
    let mut descriptors = Vec::new();
    for (constraint_index, constraint) in variant.ordered_constraints().iter().enumerate() {
        let constraint_ordinal = u32::try_from(constraint_index)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut instruction_ordinal = 0_u32;
        for instruction in constraint.numerator_postfix_expression() {
            let RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                coefficient_period,
                ordered_terms,
            } = instruction
            else {
                continue;
            };
            let mut maximum_product_coefficient_count = None;
            for term in ordered_terms {
                let constant_column = variant
                    .ordered_columns()
                    .get(
                        usize::try_from(term.constant_column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let verifier_sequence_column = variant
                    .ordered_columns()
                    .get(
                        usize::try_from(term.verifier_sequence_column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let coefficient_count = constant_column
                    .source_degree_bound_exclusive()
                    .checked_add(verifier_sequence_column.source_degree_bound_exclusive())
                    .and_then(|count| count.checked_sub(1))
                    .ok_or(CommonProofProverError::CountOverflow)?;
                maximum_product_coefficient_count = Some(
                    maximum_product_coefficient_count
                        .map_or(coefficient_count, |maximum: u64| maximum.max(coefficient_count)),
                );
            }
            let maximum_product_coefficient_count = maximum_product_coefficient_count
                .ok_or(CommonProofProverError::InvalidQuotient)?;
            descriptors.push(CommonProofFusedProductSumDescriptor {
                key: CommonProofFusedProductSumKey {
                    constraint_ordinal,
                    instruction_ordinal,
                },
                coefficient_period: usize::from(*coefficient_period),
                ordered_terms: ordered_terms.clone(),
                coefficient_count: usize::try_from(maximum_product_coefficient_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            });
            instruction_ordinal = instruction_ordinal
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
    }
    Ok(descriptors)
}

pub(super) fn common_proof_fused_product_sum_coefficient_counts(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<CommonProofFusedProductSumKey, usize>, CommonProofProverError> {
    common_proof_fused_product_sum_descriptors(variant).map(|descriptors| {
        descriptors
            .into_iter()
            .map(|descriptor| (descriptor.key, descriptor.coefficient_count))
            .collect()
    })
}

pub(super) fn common_proof_exclusive_fused_verifier_sequence_columns(
    variant: &RelationPlanVariant,
) -> Result<BTreeSet<u32>, CommonProofProverError> {
    let descriptors = common_proof_fused_product_sum_descriptors(variant)?;
    let candidates = descriptors
        .iter()
        .flat_map(|descriptor| {
            descriptor
                .ordered_terms
                .iter()
                .map(|term| term.verifier_sequence_column_ordinal)
        })
        .collect::<BTreeSet<_>>();
    for constraint in variant.ordered_constraints() {
        for instruction in constraint.numerator_postfix_expression() {
            if let RelationExpressionInstruction::ColumnValue { column_ordinal, .. } = instruction
                && candidates.contains(column_ordinal)
            {
                return Err(CommonProofProverError::InvalidQuotient);
            }
        }
    }
    Ok(candidates)
}

struct RetainedPeriodicVerifierSequence {
    coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
    remaining_use_count: usize,
}

pub(super) struct CommonProofFusedProductSumAccumulator {
    trace_domain_size: usize,
    trace_generator: ProofBaseFieldElement,
    descriptors: Vec<CommonProofFusedProductSumDescriptor>,
    descriptor_indices_by_constant_column: BTreeMap<u32, Vec<(usize, usize)>>,
    profile_periods: BTreeMap<u32, usize>,
    profile_use_counts: BTreeMap<u32, usize>,
    retained_profiles: BTreeMap<u32, RetainedPeriodicVerifierSequence>,
    accumulated_coefficients: Vec<Zeroizing<Vec<ProofBaseFieldElement>>>,
}

impl CommonProofFusedProductSumAccumulator {
    pub(super) fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<Option<Self>, CommonProofProverError> {
        let descriptors = common_proof_fused_product_sum_descriptors(variant)?;
        if descriptors.is_empty() {
            return Ok(None);
        }
        let trace_domain_size = usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let evaluation_generator = ProofBaseFieldElement::from_canonical(
            context.evaluation_domain_generator,
        )
        .map_err(CommonProofProverError::from)?;
        let trace_generator = evaluation_generator.power(
            variant.evaluation_domain_size() / variant.trace_domain_size(),
        );
        let mut descriptor_indices_by_constant_column = BTreeMap::<u32, Vec<_>>::new();
        let mut profile_periods = BTreeMap::new();
        let mut profile_use_counts = BTreeMap::<u32, usize>::new();
        let mut accumulated_coefficients = Vec::new();
        accumulated_coefficients
            .try_reserve_exact(descriptors.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for (descriptor_index, descriptor) in descriptors.iter().enumerate() {
            accumulated_coefficients.push(Zeroizing::new(vec![
                ProofBaseFieldElement::ZERO;
                descriptor.coefficient_count
            ]));
            for (term_index, term) in descriptor.ordered_terms.iter().enumerate() {
                descriptor_indices_by_constant_column
                    .entry(term.constant_column_ordinal)
                    .or_default()
                    .push((descriptor_index, term_index));
                match profile_periods.insert(
                    term.verifier_sequence_column_ordinal,
                    descriptor.coefficient_period,
                ) {
                    Some(period) if period != descriptor.coefficient_period => {
                        return Err(CommonProofProverError::InvalidQuotient);
                    }
                    _ => {}
                }
                *profile_use_counts
                    .entry(term.verifier_sequence_column_ordinal)
                    .or_default() += 1;
            }
        }
        Ok(Some(Self {
            trace_domain_size,
            trace_generator,
            descriptors,
            descriptor_indices_by_constant_column,
            profile_periods,
            profile_use_counts,
            retained_profiles: BTreeMap::new(),
            accumulated_coefficients,
        }))
    }

    pub(super) fn accepts_column(&self, column_ordinal: u32) -> bool {
        self.profile_periods.contains_key(&column_ordinal)
            || self
                .descriptor_indices_by_constant_column
                .contains_key(&column_ordinal)
    }

    pub(super) fn is_exclusive_profile_column(&self, column_ordinal: u32) -> bool {
        self.profile_periods.contains_key(&column_ordinal)
    }

    pub(super) fn accept_column(
        &mut self,
        column_ordinal: u32,
        polynomial: &CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        if let Some(period) = self.profile_periods.get(&column_ordinal).copied() {
            let CommonProofSourcePolynomial::Base(coefficients) = polynomial else {
                return Err(CommonProofProverError::InvalidColumn);
            };
            if coefficients.is_empty() || coefficients.len() > self.trace_domain_size {
                return Err(CommonProofProverError::InvalidColumn);
            }
            let mut padded = Zeroizing::new(coefficients.to_vec());
            padded.resize(self.trace_domain_size, ProofBaseFieldElement::ZERO);
            if period == 0
                || !self.trace_domain_size.is_multiple_of(period)
                || (period..self.trace_domain_size)
                    .any(|index| padded[index] != padded[index % period])
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            let remaining_use_count = self
                .profile_use_counts
                .get(&column_ordinal)
                .copied()
                .filter(|count| *count != 0)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            if self
                .retained_profiles
                .insert(
                    column_ordinal,
                    RetainedPeriodicVerifierSequence {
                        coefficients: padded,
                        remaining_use_count,
                    },
                )
                .is_some()
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            return Ok(());
        }
        let Some(uses) = self
            .descriptor_indices_by_constant_column
            .get(&column_ordinal)
            .cloned()
        else {
            return Ok(());
        };
        for (descriptor_index, term_index) in uses {
            let descriptor = self
                .descriptors
                .get(descriptor_index)
                .ok_or(CommonProofProverError::InvalidQuotient)?;
            let term = *descriptor
                .ordered_terms
                .get(term_index)
                .ok_or(CommonProofProverError::InvalidQuotient)?;
            let profile = self
                .retained_profiles
                .get(&term.verifier_sequence_column_ordinal)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            add_exact_constant_trace_product(
                self.accumulated_coefficients
                    .get_mut(descriptor_index)
                    .ok_or(CommonProofProverError::InvalidQuotient)?,
                polynomial,
                &profile.coefficients,
                descriptor.coefficient_period,
                self.trace_domain_size,
                self.trace_generator,
                term.verifier_sequence_rotation_is_negative,
                term.verifier_sequence_rotation_magnitude,
            )?;
            let profile = self
                .retained_profiles
                .get_mut(&term.verifier_sequence_column_ordinal)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            profile.remaining_use_count = profile
                .remaining_use_count
                .checked_sub(1)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            if profile.remaining_use_count == 0 {
                self.retained_profiles
                    .remove(&term.verifier_sequence_column_ordinal);
            }
        }
        Ok(())
    }

    pub(super) fn finish(
        self,
    ) -> Result<BTreeMap<CommonProofFusedProductSumKey, CommonProofSourcePolynomial>, CommonProofProverError>
    {
        if !self.retained_profiles.is_empty() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(self
            .descriptors
            .into_iter()
            .zip(self.accumulated_coefficients)
            .map(|(descriptor, mut coefficients)| {
                while coefficients.len() > 1
                    && coefficients.last() == Some(&ProofBaseFieldElement::ZERO)
                {
                    coefficients.pop();
                }
                (
                    descriptor.key,
                    CommonProofSourcePolynomial::from_protected_base_coefficients(coefficients),
                )
            })
            .collect())
    }
}

#[allow(clippy::too_many_arguments)]
fn add_exact_constant_trace_product(
    accumulated: &mut [ProofBaseFieldElement],
    constant_trace_polynomial: &CommonProofSourcePolynomial,
    periodic_profile: &[ProofBaseFieldElement],
    coefficient_period: usize,
    trace_domain_size: usize,
    trace_generator: ProofBaseFieldElement,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Result<(), CommonProofProverError> {
    let CommonProofSourcePolynomial::Base(constant_coefficients) = constant_trace_polynomial else {
        return Err(CommonProofProverError::InvalidColumn);
    };
    if constant_coefficients.is_empty()
        || constant_coefficients.len() >= trace_domain_size.saturating_mul(2)
        || periodic_profile.len() != trace_domain_size
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let mut constant_value = ProofBaseFieldElement::ZERO;
    for coefficient_index in 0..trace_domain_size {
        let reduced = constant_coefficients
            .get(coefficient_index)
            .copied()
            .unwrap_or(ProofBaseFieldElement::ZERO)
            .add(
                constant_coefficients
                    .get(trace_domain_size + coefficient_index)
                    .copied()
                    .unwrap_or(ProofBaseFieldElement::ZERO),
            );
        if coefficient_index == 0 {
            constant_value = reduced;
        } else if reduced != ProofBaseFieldElement::ZERO {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    let signed_rotation = if rotation_is_negative {
        let reduced = rotation_magnitude
            % u64::try_from(trace_domain_size)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        if reduced == 0 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        u64::try_from(trace_domain_size)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            - reduced
    } else {
        rotation_magnitude
            % u64::try_from(trace_domain_size)
                .map_err(|_| CommonProofProverError::CountOverflow)?
    };
    let rotation_multiplier = trace_generator.power(signed_rotation);
    let mut multiplier_power = ProofBaseFieldElement::ONE;
    let mut rotated_profile = Zeroizing::new(Vec::new());
    rotated_profile
        .try_reserve_exact(trace_domain_size)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for coefficient in periodic_profile {
        rotated_profile.push(coefficient.multiply(multiplier_power));
        multiplier_power = multiplier_power.multiply(rotation_multiplier);
    }
    if accumulated.len()
        < constant_coefficients
            .len()
            .checked_add(trace_domain_size)
            .and_then(|count| count.checked_sub(1))
            .ok_or(CommonProofProverError::CountOverflow)?
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    for (coefficient_index, profile_coefficient) in rotated_profile.iter().copied().enumerate() {
        accumulated[coefficient_index] = accumulated[coefficient_index]
            .add(profile_coefficient.multiply(constant_value));
    }
    let mask = constant_coefficients
        .get(trace_domain_size..)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    if mask.is_empty() {
        return Ok(());
    }
    let product = multiply_by_quasiperiodic_polynomial(
        mask,
        &rotated_profile,
        coefficient_period,
        rotation_multiplier.power(
            u64::try_from(coefficient_period)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        ),
    )?;
    for (coefficient_index, product_coefficient) in product.iter().copied().enumerate() {
        accumulated[coefficient_index] =
            accumulated[coefficient_index].subtract(product_coefficient);
        let shifted_index = trace_domain_size
            .checked_add(coefficient_index)
            .ok_or(CommonProofProverError::CountOverflow)?;
        accumulated[shifted_index] = accumulated[shifted_index].add(product_coefficient);
    }
    Ok(())
}

fn multiply_by_quasiperiodic_polynomial(
    left: &[ProofBaseFieldElement],
    right: &[ProofBaseFieldElement],
    coefficient_period: usize,
    period_ratio: ProofBaseFieldElement,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofProverError> {
    if left.is_empty()
        || right.is_empty()
        || coefficient_period == 0
        || right.len() <= coefficient_period
        || (coefficient_period..right.len())
            .any(|index| right[index] != right[index - coefficient_period].multiply(period_ratio))
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let product_length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let recurrence_start = left
        .len()
        .checked_add(coefficient_period)
        .and_then(|value| value.checked_sub(1))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let lower_right_length = recurrence_start.min(right.len());
    let lower = multiply_small_base_polynomials(left, &right[..lower_right_length])?;
    let mut product = Zeroizing::new(vec![ProofBaseFieldElement::ZERO; product_length]);
    let copied_lower_length = recurrence_start.min(right.len()).min(lower.len());
    product[..copied_lower_length].copy_from_slice(&lower[..copied_lower_length]);
    for coefficient_index in recurrence_start..right.len() {
        product[coefficient_index] = product[coefficient_index - coefficient_period]
            .multiply(period_ratio);
    }
    if left.len() > 1 {
        let reversed_left = left.iter().rev().copied().collect::<Vec<_>>();
        let suffix_length = left.len().min(right.len());
        let reversed_right = right[right.len() - suffix_length..]
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>();
        let reversed_tail = multiply_small_base_polynomials(&reversed_left, &reversed_right)?;
        for tail_offset in 0..left.len() - 1 {
            product[product_length - 1 - tail_offset] = reversed_tail[tail_offset];
        }
    }
    Ok(product)
}

fn multiply_small_base_polynomials(
    left: &[ProofBaseFieldElement],
    right: &[ProofBaseFieldElement],
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofProverError> {
    let product_length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let transform_size = product_length
        .checked_next_power_of_two()
        .ok_or(CommonProofProverError::CountOverflow)?;
    let domain = ProofEvaluationDomain::new_subgroup(transform_size)?;
    let mut left_evaluations = Zeroizing::new(left.to_vec());
    let mut right_evaluations = Zeroizing::new(right.to_vec());
    left_evaluations.resize(transform_size, ProofBaseFieldElement::ZERO);
    right_evaluations.resize(transform_size, ProofBaseFieldElement::ZERO);
    domain.evaluate_base_polynomial_in_place(&mut left_evaluations)?;
    domain.evaluate_base_polynomial_in_place(&mut right_evaluations)?;
    for (left_value, right_value) in left_evaluations.iter_mut().zip(right_evaluations.iter()) {
        *left_value = left_value.multiply(*right_value);
    }
    domain.interpolate_base_polynomial_in_place(&mut left_evaluations)?;
    left_evaluations.truncate(product_length);
    Ok(left_evaluations)
}

impl CommonProofQuotientConstraintTransformKey {
    pub(super) const fn new(constraint_ordinal: u32, column_ordinal: u32) -> Self {
        Self {
            constraint_ordinal,
            column_ordinal,
        }
    }

    pub(super) const fn constraint_ordinal(self) -> u32 {
        self.constraint_ordinal
    }

    pub(super) const fn column_ordinal(self) -> u32 {
        self.column_ordinal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CommonProofQuotientEvaluationReadRequest {
    transform_key: CommonProofQuotientConstraintTransformKey,
    query_ordinal: usize,
    logical_value_offset: usize,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
}

impl CommonProofQuotientEvaluationReadRequest {
    pub(super) const fn vector(self) -> ExternalPolynomialVector {
        self.vector
    }

    pub(super) const fn element_offset(self) -> usize {
        self.element_offset
    }

    pub(super) const fn element_count(self) -> usize {
        self.element_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CommonProofQuotientEvaluationProgress {
    BlockComplete,
    ConstraintComplete,
}

pub(super) struct CommonProofConstraintStreamQuotientBuilder {
    evaluation_domain: ProofEvaluationDomain,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    column_value_types: Vec<RelationColumnValueType>,
    constraint_queries: Vec<Vec<RelationConstraintColumnQuery>>,
    constraint_columns: Vec<Vec<u32>>,
    current_constraint_ordinal: usize,
    next_transform_column_index: usize,
    transformed_columns: BTreeMap<u32, ExternalPolynomialVector>,
    block_start: usize,
    next_query_ordinal: usize,
    next_query_logical_value_offset: usize,
    block_values_by_query: Vec<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    maximum_external_read_chunk_byte_length: usize,
    quotient_evaluations: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    checked_application_challenges: CheckedRelationApplicationChallenges,
    composition_challenges: Vec<ProofChallengeExtensionElement>,
}

impl CommonProofConstraintStreamQuotientBuilder {
    pub(super) fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        evaluation_domain: ProofEvaluationDomain,
        application_challenges: Vec<RelationApplicationChallengeAssignment>,
        composition_challenges: Vec<ProofChallengeExtensionElement>,
        maximum_external_read_chunk_byte_length: u32,
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
        if composition_challenges.len() != variant.constraint_count()
            || maximum_external_read_chunk_byte_length == 0
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let trace_domain_size = usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_rotation_stride =
            usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let column_value_types = variant
            .ordered_columns()
            .iter()
            .map(|column| column.value_type())
            .collect::<Vec<_>>();
        let mut constraint_queries = Vec::new();
        let mut constraint_columns = Vec::new();
        constraint_queries
            .try_reserve_exact(variant.constraint_count())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        constraint_columns
            .try_reserve_exact(variant.constraint_count())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for constraint_ordinal in 0..variant.constraint_count() {
            let queries = variant.constraint_column_queries(constraint_ordinal)?;
            let columns = queries
                .iter()
                .map(|query| query.column_ordinal())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            for column_ordinal in &columns {
                let value_type = column_value_types
                    .get(
                        usize::try_from(*column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .copied()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let value_byte_length = usize::try_from(external_value_byte_length(value_type))
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                if usize::try_from(maximum_external_read_chunk_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    < value_byte_length
                {
                    return Err(CommonProofProverError::InvalidInput);
                }
            }
            constraint_queries.push(queries);
            constraint_columns.push(columns);
        }
        let checked_application_challenges =
            variant.checked_application_challenges(context, &application_challenges)?;
        let mut quotient_evaluations = Zeroizing::new(Vec::new());
        quotient_evaluations
            .try_reserve_exact(evaluation_domain.size())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        quotient_evaluations.resize(
            evaluation_domain.size(),
            ProofChallengeExtensionElement::ZERO,
        );
        Ok(Self {
            evaluation_domain,
            trace_domain_size,
            trace_rotation_stride,
            column_value_types,
            constraint_queries,
            constraint_columns,
            current_constraint_ordinal: 0,
            next_transform_column_index: 0,
            transformed_columns: BTreeMap::new(),
            block_start: 0,
            next_query_ordinal: 0,
            next_query_logical_value_offset: 0,
            block_values_by_query: Vec::new(),
            maximum_external_read_chunk_byte_length: usize::try_from(
                maximum_external_read_chunk_byte_length,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?,
            quotient_evaluations,
            checked_application_challenges,
            composition_challenges,
        })
    }

    pub(super) fn next_transform_key(
        &self,
    ) -> Result<Option<CommonProofQuotientConstraintTransformKey>, CommonProofProverError> {
        if self.current_constraint_ordinal >= self.constraint_columns.len() {
            return Ok(None);
        }
        let Some(column_ordinal) = self
            .constraint_columns
            .get(self.current_constraint_ordinal)
            .and_then(|columns| columns.get(self.next_transform_column_index))
            .copied()
        else {
            return Ok(None);
        };
        Ok(Some(CommonProofQuotientConstraintTransformKey::new(
            u32::try_from(self.current_constraint_ordinal)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            column_ordinal,
        )))
    }

    pub(super) fn accept_transformed_column(
        &mut self,
        transform_key: CommonProofQuotientConstraintTransformKey,
        vector: ExternalPolynomialVector,
    ) -> Result<(), CommonProofProverError> {
        if self.next_transform_key()? != Some(transform_key)
            || vector.element_count() != self.evaluation_domain.size()
            || self
                .column_value_types
                .get(
                    usize::try_from(transform_key.column_ordinal())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .copied()
                != Some(vector.value_type())
            || self
                .transformed_columns
                .contains_key(&transform_key.column_ordinal())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let previous = self
            .transformed_columns
            .insert(transform_key.column_ordinal(), vector);
        debug_assert!(previous.is_none());
        self.next_transform_column_index = self
            .next_transform_column_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    fn current_block_end(&self) -> Result<usize, CommonProofProverError> {
        let block_end = self
            .block_start
            .checked_add(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(self.evaluation_domain.size());
        if block_end <= self.block_start {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        Ok(block_end)
    }

    pub(super) fn next_read_request(
        &self,
    ) -> Result<Option<CommonProofQuotientEvaluationReadRequest>, CommonProofProverError> {
        if self.current_constraint_ordinal >= self.constraint_queries.len()
            || self.next_transform_key()?.is_some()
        {
            return Ok(None);
        }
        let queries = self
            .constraint_queries
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        let Some(query) = queries.get(self.next_query_ordinal).copied() else {
            return Ok(None);
        };
        let vector = self
            .transformed_columns
            .get(&query.column_ordinal())
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let block_end = self.current_block_end()?;
        let block_element_count = block_end - self.block_start;
        if self.next_query_logical_value_offset >= block_element_count {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let rotated_block_start = rotated_relation_evaluation_position(
            self.block_start,
            self.evaluation_domain.size(),
            self.trace_domain_size,
            self.trace_rotation_stride,
            query.rotation_is_negative(),
            query.rotation_magnitude(),
        )?;
        let element_offset = rotated_block_start
            .checked_add(self.next_query_logical_value_offset)
            .ok_or(CommonProofProverError::CountOverflow)?
            % self.evaluation_domain.size();
        let maximum_chunk_element_count = self
            .maximum_external_read_chunk_byte_length
            .checked_div(
                usize::try_from(external_value_byte_length(vector.value_type()))
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .filter(|count| *count != 0)
            .ok_or(CommonProofProverError::InvalidInput)?;
        let element_count = (block_element_count - self.next_query_logical_value_offset)
            .min(self.evaluation_domain.size() - element_offset)
            .min(maximum_chunk_element_count);
        if element_count == 0 {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        Ok(Some(CommonProofQuotientEvaluationReadRequest {
            transform_key: CommonProofQuotientConstraintTransformKey::new(
                u32::try_from(self.current_constraint_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                query.column_ordinal(),
            ),
            query_ordinal: self.next_query_ordinal,
            logical_value_offset: self.next_query_logical_value_offset,
            vector,
            element_offset,
            element_count,
        }))
    }

    pub(super) fn accept_read_values(
        &mut self,
        request: CommonProofQuotientEvaluationReadRequest,
        values: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ) -> Result<(), CommonProofProverError> {
        if self.next_read_request()? != Some(request) || values.len() != request.element_count {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let block_element_count = self.current_block_end()? - self.block_start;
        if self.block_values_by_query.len() == request.query_ordinal {
            let mut query_values = Vec::new();
            query_values
                .try_reserve_exact(block_element_count)
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            self.block_values_by_query
                .push(Zeroizing::new(query_values));
        }
        let query_values = self
            .block_values_by_query
            .get_mut(request.query_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        if query_values.len() != request.logical_value_offset {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        query_values.extend(values.iter().copied());
        self.next_query_logical_value_offset = self
            .next_query_logical_value_offset
            .checked_add(values.len())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.next_query_logical_value_offset == block_element_count {
            self.next_query_ordinal = self
                .next_query_ordinal
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            self.next_query_logical_value_offset = 0;
        }
        Ok(())
    }

    pub(super) fn evaluate_ready_block(
        &mut self,
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<CommonProofQuotientEvaluationProgress, CommonProofProverError> {
        let queries = self
            .constraint_queries
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        let columns = self
            .constraint_columns
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        if self.block_start >= self.evaluation_domain.size()
            || self.next_transform_column_index != columns.len()
            || self.transformed_columns.len() != columns.len()
            || self.next_query_ordinal != queries.len()
            || self.next_query_logical_value_offset != 0
            || self.block_values_by_query.len() != queries.len()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let block_end = self.current_block_end()?;
        let composition_challenge = self
            .composition_challenges
            .get(self.current_constraint_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        for evaluation_position in self.block_start..block_end {
            let block_position = evaluation_position - self.block_start;
            let evaluation_point = ProofChallengeExtensionElement::from_base(
                self.evaluation_domain.point(evaluation_position)?,
            );
            let mut column_value = |column_ordinal, rotation_is_negative, rotation_magnitude| {
                let query_index = queries
                    .binary_search_by_key(
                        &(column_ordinal, rotation_is_negative, rotation_magnitude),
                        |query| {
                            (
                                query.column_ordinal(),
                                query.rotation_is_negative(),
                                query.rotation_magnitude(),
                            )
                        },
                    )
                    .map_err(|_| RelationPlanError::InvalidOpening)?;
                self.block_values_by_query
                    .get(query_index)
                    .and_then(|values| values.get(block_position))
                    .copied()
                    .ok_or(RelationPlanError::InvalidConstraint)
            };
            let evaluation = variant
                .evaluate_constraint_at_point(
                    context,
                    self.current_constraint_ordinal,
                    evaluation_point,
                    &self.checked_application_challenges,
                    &mut column_value,
                )
                .map_err(CommonProofProverError::from)?;
            let normalized = evaluation
                .numerator
                .divide(evaluation.zeroifier)
                .map_err(|_| CommonProofProverError::from(RelationPlanError::InvalidZeroifier))?;
            let quotient_evaluation = self
                .quotient_evaluations
                .get_mut(evaluation_position)
                .ok_or(CommonProofProverError::InvalidQuotient)?;
            *quotient_evaluation =
                quotient_evaluation.add(normalized.multiply(composition_challenge));
        }
        self.block_values_by_query.clear();
        self.next_query_ordinal = 0;
        self.next_query_logical_value_offset = 0;
        self.block_start = block_end;
        Ok(if self.block_start == self.evaluation_domain.size() {
            CommonProofQuotientEvaluationProgress::ConstraintComplete
        } else {
            CommonProofQuotientEvaluationProgress::BlockComplete
        })
    }

    pub(super) fn complete_constraint(&mut self) -> Result<bool, CommonProofProverError> {
        if self.current_constraint_ordinal >= self.constraint_queries.len()
            || self.block_start != self.evaluation_domain.size()
            || !self.block_values_by_query.is_empty()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.transformed_columns.clear();
        self.current_constraint_ordinal = self
            .current_constraint_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.next_transform_column_index = 0;
        self.block_start = 0;
        self.next_query_ordinal = 0;
        self.next_query_logical_value_offset = 0;
        Ok(self.current_constraint_ordinal == self.constraint_queries.len())
    }

    pub(super) fn finish(
        mut self,
    ) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
        if self.current_constraint_ordinal != self.constraint_queries.len()
            || self.block_start != 0
            || self.quotient_evaluations.len() != self.evaluation_domain.size()
            || !self.block_values_by_query.is_empty()
            || !self.transformed_columns.is_empty()
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
) -> Result<Vec<Zeroizing<Vec<ProofChallengeExtensionElement>>>, CommonProofProverError> {
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
        let mut component = Zeroizing::new(if start < quotient.len() {
            quotient[start..end].to_vec()
        } else {
            vec![ProofChallengeExtensionElement::ZERO]
        });
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
) -> Result<
    Vec<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    CommonProofPrivateCoinError<Coins::Error>,
>
where
    Coins: CommonProofPrivateCoinSource,
{
    let mut cursor = CommonProofQuotientComponentCursor::new(
        variant,
        context,
        Zeroizing::new(quotient.to_vec()),
    )
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
    quotient: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    stride: usize,
    component_count: usize,
    component_degree_bound_exclusive: usize,
    telescoping_descriptors: Vec<RelationMaskDescriptor>,
    previous_randomizer: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    next_component_index: usize,
}

impl CommonProofQuotientComponentCursor {
    pub(super) fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        quotient: Zeroizing<Vec<ProofChallengeExtensionElement>>,
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
        Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
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
        let mut component = Zeroizing::new(
            self.quotient
                .iter()
                .skip(component_index.checked_mul(self.stride).ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
                })?)
                .take(self.stride)
                .copied()
                .collect::<Vec<_>>(),
        );
        if component.is_empty() {
            component.push(ProofChallengeExtensionElement::ZERO);
        }
        let next_randomizer =
            if let Some(descriptor) = self.telescoping_descriptors.get(component_index).copied() {
                let randomizer = sample_private_extension_polynomial(
                    coins,
                    CommonProofPrivateCoinCoordinate::from_mask(descriptor.mask_coordinate()),
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
