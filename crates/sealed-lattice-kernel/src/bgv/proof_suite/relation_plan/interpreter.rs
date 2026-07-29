//! Exact scalar interpreter for checked relation-plan expressions.
//!
//! This interpreter is shared by every statement family.  It consumes only a
//! checked plan, plan-addressed column values, and transcript values selected
//! by the plan.  Proof bytes cannot supply instructions, tags, roles, source
//! selectors, or a replacement zeroifier.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use num_bigint::BigUint;

#[cfg(test)]
use super::super::field::{PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE};
use super::super::{
    field::{ProofBaseFieldElement, ProofChallengeExtensionElement},
    transcript::CommonProofChallenge,
};
#[cfg(test)]
use super::RelationRadixFactorDescriptor;
use super::{
    RelationChallengeRole, RelationColumnOrigin, RelationConstraintColumnQuery,
    RelationExpressionInstruction, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, modular_power, relation_column_queries, visit_relation_column_queries,
};
#[cfg(test)]
use super::{RelationPlanChecker, check_expression};

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutOfDomainPointSamplerCardinalityBound {
    field_cardinality: BigUint,
    forbidden_candidate_count_ceiling: BigUint,
    accepted_candidate_count_floor: BigUint,
}

#[cfg(test)]
impl OutOfDomainPointSamplerCardinalityBound {
    pub(crate) const fn field_cardinality(&self) -> &BigUint {
        &self.field_cardinality
    }

    pub(crate) const fn forbidden_candidate_count_ceiling(&self) -> &BigUint {
        &self.forbidden_candidate_count_ceiling
    }

    pub(crate) const fn accepted_candidate_count_floor(&self) -> &BigUint {
        &self.accepted_candidate_count_floor
    }
}

#[derive(Clone, Copy)]
struct ResolvedVerifierSequenceOpening {
    column_ordinal: u32,
    opening_point_ordinal: u32,
    value: ProofChallengeExtensionElement,
}

impl ResolvedVerifierSequenceOpening {
    const fn key(self) -> (u32, u32) {
        (self.column_ordinal, self.opening_point_ordinal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationApplicationChallengeAssignment {
    challenge: CommonProofChallenge,
    repetition_ordinal: u16,
    value: u64,
}

impl RelationApplicationChallengeAssignment {
    pub(crate) fn new(
        challenge: CommonProofChallenge,
        repetition_ordinal: u16,
        value: u64,
    ) -> Result<Self, RelationPlanError> {
        if !matches!(
            challenge,
            CommonProofChallenge::Theta { .. } | CommonProofChallenge::Alpha { .. }
        ) {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        Ok(Self {
            challenge,
            repetition_ordinal,
            value,
        })
    }

    pub(crate) fn challenge(self) -> CommonProofChallenge {
        self.challenge
    }

    pub(crate) fn value(self) -> u64 {
        self.value
    }

    pub(crate) fn repetition_ordinal(self) -> u16 {
        self.repetition_ordinal
    }
}

pub(crate) struct OutOfDomainCompositionVerificationInput<'input> {
    context: &'input RelationPlanCheckContext,
    application_challenges: &'input [RelationApplicationChallengeAssignment],
    composition_challenges: &'input [ProofChallengeExtensionElement],
    out_of_domain_points: &'input [ProofChallengeExtensionElement],
    opening_points: &'input [ProofChallengeExtensionElement],
    ordered_out_of_domain_evaluations: &'input [ProofChallengeExtensionElement],
}

impl<'input> OutOfDomainCompositionVerificationInput<'input> {
    pub(crate) const fn new(
        context: &'input RelationPlanCheckContext,
        application_challenges: &'input [RelationApplicationChallengeAssignment],
        composition_challenges: &'input [ProofChallengeExtensionElement],
        out_of_domain_points: &'input [ProofChallengeExtensionElement],
        opening_points: &'input [ProofChallengeExtensionElement],
        ordered_out_of_domain_evaluations: &'input [ProofChallengeExtensionElement],
    ) -> Self {
        Self {
            context,
            application_challenges,
            composition_challenges,
            out_of_domain_points,
            opening_points,
            ordered_out_of_domain_evaluations,
        }
    }

    pub(crate) const fn ordered_out_of_domain_evaluations(
        &self,
    ) -> &'input [ProofChallengeExtensionElement] {
        self.ordered_out_of_domain_evaluations
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationConstraintEvaluation {
    pub(crate) numerator: ProofChallengeExtensionElement,
    pub(crate) zeroifier: ProofChallengeExtensionElement,
}

#[derive(Clone, Debug)]
pub(crate) struct CheckedRelationApplicationChallenges {
    values: BTreeMap<(RelationChallengeRole, Vec<u64>), u64>,
}

impl CheckedRelationApplicationChallenges {
    fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        assignments: &[RelationApplicationChallengeAssignment],
    ) -> Result<Self, RelationPlanError> {
        let descriptors = variant
            .derived_relation_prefix_challenge_catalog(context)?
            .into_iter()
            .filter(|descriptor| {
                matches!(
                    descriptor.role,
                    RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha
                )
            })
            .collect::<Vec<_>>();
        let mut sampled_coordinates = BTreeMap::new();
        for assignment in assignments {
            let (modulus_ordinal, repetition_count, coordinate_modulus) = match assignment.challenge
            {
                CommonProofChallenge::Theta { modulus_ordinal } => (
                    modulus_ordinal,
                    context.non_native_theta_repetition_count,
                    context.base_field_modulus,
                ),
                CommonProofChallenge::Alpha { modulus_ordinal } => {
                    let modulus_reference = variant
                        .ordered_non_native_moduli
                        .get(usize::from(modulus_ordinal))
                        .copied()
                        .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                    (
                        modulus_ordinal,
                        context.non_native_alpha_repetition_count,
                        context.resolved_modulus(modulus_reference)?,
                    )
                }
                _ => return Err(RelationPlanError::InvalidChallengeCatalog),
            };
            if assignment.repetition_ordinal >= repetition_count {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            variant
                .ordered_non_native_moduli
                .get(usize::from(modulus_ordinal))
                .copied()
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            if assignment.value >= coordinate_modulus
                || sampled_coordinates
                    .insert(
                        (assignment.challenge, assignment.repetition_ordinal),
                        assignment.value,
                    )
                    .is_some()
            {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
        }

        let mut required_coordinates = BTreeSet::new();
        let mut values = BTreeMap::new();
        for descriptor in descriptors {
            let modulus_ordinal = u16::try_from(descriptor.role_coordinates[0])
                .map_err(|_| RelationPlanError::CountOverflow)?;
            let repetition_ordinal = u16::try_from(descriptor.role_coordinates[1])
                .map_err(|_| RelationPlanError::CountOverflow)?;
            let challenge = match descriptor.role {
                RelationChallengeRole::NonNativeTheta => {
                    CommonProofChallenge::Theta { modulus_ordinal }
                }
                RelationChallengeRole::NonNativeAlpha => {
                    CommonProofChallenge::Alpha { modulus_ordinal }
                }
                _ => return Err(RelationPlanError::InvalidChallengeCatalog),
            };
            required_coordinates.insert((challenge, repetition_ordinal));
            let sampled = sampled_coordinates
                .get(&(challenge, repetition_ordinal))
                .copied()
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            let sampled_coordinate_modulus = descriptor
                .resolved_sampling(variant, context)?
                .coordinate_modulus;
            if sampled >= sampled_coordinate_modulus {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            let value = match descriptor.role {
                RelationChallengeRole::NonNativeTheta => sampled,
                RelationChallengeRole::NonNativeAlpha => modular_power(
                    sampled,
                    descriptor.role_coordinates[2],
                    sampled_coordinate_modulus,
                ),
                _ => return Err(RelationPlanError::InvalidChallengeCatalog),
            };
            if values
                .insert((descriptor.role, descriptor.role_coordinates), value)
                .is_some()
            {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
        if sampled_coordinates.keys().copied().collect::<BTreeSet<_>>() != required_coordinates {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        Ok(Self { values })
    }

    fn get(
        &self,
        role: RelationChallengeRole,
        coordinates: &[u64],
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let value = self.get_u64(role, coordinates)?;
        ProofBaseFieldElement::from_canonical(value)
            .map(ProofChallengeExtensionElement::from_base)
            .map_err(|_| RelationPlanError::InvalidChallengeCatalog)
    }

    fn get_u64(
        &self,
        role: RelationChallengeRole,
        coordinates: &[u64],
    ) -> Result<u64, RelationPlanError> {
        self.values
            .get(&(role, coordinates.to_vec()))
            .copied()
            .ok_or(RelationPlanError::InvalidChallengeCatalog)
    }
}

impl RelationPlanVariant {
    pub(crate) const fn constraint_count(&self) -> usize {
        self.ordered_constraints.len()
    }

    pub(crate) fn checked_application_challenges(
        &self,
        context: &RelationPlanCheckContext,
        assignments: &[RelationApplicationChallengeAssignment],
    ) -> Result<CheckedRelationApplicationChallenges, RelationPlanError> {
        CheckedRelationApplicationChallenges::new(self, context, assignments)
    }

    pub(crate) fn constraint_column_queries(
        &self,
        constraint_ordinal: usize,
    ) -> Result<Vec<RelationConstraintColumnQuery>, RelationPlanError> {
        let constraint = self
            .ordered_constraints
            .get(constraint_ordinal)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let queries = relation_column_queries(
            &[
                &constraint.numerator_postfix_expression,
                &constraint.zeroifier_postfix_expression,
            ],
            &self.ordered_radix_convolutions,
            RelationPlanError::InvalidConstraint,
        )?;
        for query in &queries {
            if usize::try_from(query.column_ordinal)
                .ok()
                .filter(|column_index| *column_index < self.ordered_columns.len())
                .is_none()
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }
        Ok(queries.into_iter().collect())
    }

    /// Returns the first constraint ordinal using each exact checked
    /// zeroifier program. Evaluations may be reused only inside one such
    /// structural equivalence class.
    #[cfg(test)]
    pub(crate) fn constraint_zeroifier_representative_ordinals(&self) -> Vec<usize> {
        let mut representative_ordinals = Vec::<usize>::new();
        self.ordered_constraints
            .iter()
            .enumerate()
            .map(|(constraint_ordinal, constraint)| {
                if let Some(representative_ordinal) =
                    representative_ordinals
                        .iter()
                        .copied()
                        .find(|representative_ordinal| {
                            self.ordered_constraints[*representative_ordinal]
                                .zeroifier_postfix_expression
                                == constraint.zeroifier_postfix_expression
                        })
                {
                    representative_ordinal
                } else {
                    representative_ordinals.push(constraint_ordinal);
                    constraint_ordinal
                }
            })
            .collect()
    }

    pub(crate) fn evaluate_constraint_numerator_at_point<ColumnValue>(
        &self,
        context: &RelationPlanCheckContext,
        constraint_ordinal: usize,
        evaluation_point: ProofChallengeExtensionElement,
        checked_challenges: &CheckedRelationApplicationChallenges,
        column_value: &mut ColumnValue,
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError>
    where
        ColumnValue:
            FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
    {
        let constraint = self
            .ordered_constraints
            .get(constraint_ordinal)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        evaluate_program(
            self,
            context,
            &constraint.numerator_postfix_expression,
            evaluation_point,
            checked_challenges,
            column_value,
            false,
        )
    }

    pub(crate) fn evaluate_constraint_zeroifier_at_point(
        &self,
        context: &RelationPlanCheckContext,
        constraint_ordinal: usize,
        evaluation_point: ProofChallengeExtensionElement,
        checked_challenges: &CheckedRelationApplicationChallenges,
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let constraint = self
            .ordered_constraints
            .get(constraint_ordinal)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        evaluate_program(
            self,
            context,
            &constraint.zeroifier_postfix_expression,
            evaluation_point,
            checked_challenges,
            &mut |_, _, _| Err(RelationPlanError::InvalidZeroifier),
            true,
        )
    }

    pub(crate) fn evaluate_constraint_at_point<ColumnValue>(
        &self,
        context: &RelationPlanCheckContext,
        constraint_ordinal: usize,
        evaluation_point: ProofChallengeExtensionElement,
        checked_challenges: &CheckedRelationApplicationChallenges,
        column_value: &mut ColumnValue,
    ) -> Result<RelationConstraintEvaluation, RelationPlanError>
    where
        ColumnValue:
            FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
    {
        let evaluation = self.evaluate_constraint_programs_at_point(
            context,
            constraint_ordinal,
            evaluation_point,
            checked_challenges,
            column_value,
        )?;
        if evaluation.zeroifier.is_zero() {
            return Err(RelationPlanError::ZeroifierVanishesOnEvaluationCoset);
        }
        Ok(evaluation)
    }

    /// Evaluates both checked programs without imposing the out-of-domain/coset
    /// non-vanishing condition. Application extraction uses this entry point
    /// on trace roots, where a constraint is operative precisely when its
    /// checked zeroifier vanishes.
    pub(crate) fn evaluate_constraint_programs_at_point<ColumnValue>(
        &self,
        context: &RelationPlanCheckContext,
        constraint_ordinal: usize,
        evaluation_point: ProofChallengeExtensionElement,
        checked_challenges: &CheckedRelationApplicationChallenges,
        column_value: &mut ColumnValue,
    ) -> Result<RelationConstraintEvaluation, RelationPlanError>
    where
        ColumnValue:
            FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
    {
        let numerator = self.evaluate_constraint_numerator_at_point(
            context,
            constraint_ordinal,
            evaluation_point,
            checked_challenges,
            column_value,
        )?;
        let zeroifier = self.evaluate_constraint_zeroifier_at_point(
            context,
            constraint_ordinal,
            evaluation_point,
            checked_challenges,
        )?;
        Ok(RelationConstraintEvaluation {
            numerator,
            zeroifier,
        })
    }

    pub(crate) fn evaluate_constraints_at_point<ColumnValue>(
        &self,
        context: &RelationPlanCheckContext,
        evaluation_point: ProofChallengeExtensionElement,
        application_challenges: &[RelationApplicationChallengeAssignment],
        mut column_value: ColumnValue,
    ) -> Result<Vec<RelationConstraintEvaluation>, RelationPlanError>
    where
        ColumnValue:
            FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
    {
        let checked_challenges =
            self.checked_application_challenges(context, application_challenges)?;
        self.ordered_constraints
            .iter()
            .enumerate()
            .map(|(constraint_ordinal, _)| {
                self.evaluate_constraint_at_point(
                    context,
                    constraint_ordinal,
                    evaluation_point,
                    &checked_challenges,
                    &mut column_value,
                )
            })
            .collect()
    }

    pub(crate) fn evaluate_composed_quotient_at_point<ColumnValue>(
        &self,
        context: &RelationPlanCheckContext,
        evaluation_point: ProofChallengeExtensionElement,
        application_challenges: &[RelationApplicationChallengeAssignment],
        composition_challenges: &[ProofChallengeExtensionElement],
        column_value: ColumnValue,
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError>
    where
        ColumnValue:
            FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
    {
        if composition_challenges.len() != self.ordered_constraints.len() {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        let evaluations = self.evaluate_constraints_at_point(
            context,
            evaluation_point,
            application_challenges,
            column_value,
        )?;
        evaluations
            .into_iter()
            .zip(composition_challenges)
            .try_fold(
                ProofChallengeExtensionElement::ZERO,
                |sum, (evaluation, coefficient)| {
                    let normalized = evaluation
                        .numerator
                        .divide(evaluation.zeroifier)
                        .map_err(|_| RelationPlanError::InvalidZeroifier)?;
                    Ok(sum.add(normalized.multiply(*coefficient)))
                },
            )
    }

    /// Verifies the out-of-domain values against both the complete relation expression
    /// and the canonical quotient-component decomposition.  The ordered out-of-domain
    /// value list is indexed only by the checked opening-claim catalog.
    pub(crate) fn verify_out_of_domain_composition<VerifierSequenceValue>(
        &self,
        input: OutOfDomainCompositionVerificationInput<'_>,
        mut verifier_sequence_value: VerifierSequenceValue,
    ) -> Result<(), RelationPlanError>
    where
        VerifierSequenceValue:
            FnMut(u32, ProofChallengeExtensionElement) -> Option<ProofChallengeExtensionElement>,
    {
        let OutOfDomainCompositionVerificationInput {
            context,
            application_challenges,
            composition_challenges,
            out_of_domain_points,
            opening_points,
            ordered_out_of_domain_evaluations,
        } = input;
        if out_of_domain_points.len() != usize::from(context.out_of_domain_point_count)
            || opening_points.len() != self.ordered_opening_points.len()
            || ordered_out_of_domain_evaluations.len() != self.ordered_opening_claims.len()
        {
            return Err(RelationPlanError::InvalidOpening);
        }
        let quotient_decomposition_stride = self.quotient_decomposition_stride(context)?;
        let verifier_sequence_opening_keys = self.verifier_sequence_opening_keys(context)?;
        let mut resolved_verifier_sequence_openings = Vec::new();
        resolved_verifier_sequence_openings
            .try_reserve_exact(verifier_sequence_opening_keys.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for (column_ordinal, opening_point_ordinal) in verifier_sequence_opening_keys {
            resolved_verifier_sequence_openings.push(ResolvedVerifierSequenceOpening {
                column_ordinal,
                opening_point_ordinal,
                value: ProofChallengeExtensionElement::ZERO,
            });
        }
        for opening in &mut resolved_verifier_sequence_openings {
            let point = opening_points
                .get(
                    usize::try_from(opening.opening_point_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .copied()
                .ok_or(RelationPlanError::InvalidOpening)?;
            opening.value = verifier_sequence_value(opening.column_ordinal, point)
                .ok_or(RelationPlanError::InvalidOpening)?;
        }

        for (out_of_domain_point_ordinal, out_of_domain_point) in
            out_of_domain_points.iter().copied().enumerate()
        {
            let out_of_domain_point_ordinal = u16::try_from(out_of_domain_point_ordinal)
                .map_err(|_| RelationPlanError::CountOverflow)?;
            let composed_quotient = self.evaluate_composed_quotient_at_point(
                context,
                out_of_domain_point,
                application_challenges,
                composition_challenges,
                |column_ordinal, rotation_is_negative, rotation_magnitude| {
                    let opening_point_ordinal = self.opening_point_ordinal_for_rotation(
                        out_of_domain_point_ordinal,
                        rotation_is_negative,
                        rotation_magnitude,
                        0,
                    )?;
                    let column = self
                        .ordered_columns
                        .get(
                            usize::try_from(column_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::InvalidColumn)?;
                    if matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. }) {
                        resolved_verifier_sequence_openings
                            .binary_search_by_key(
                                &(column_ordinal, opening_point_ordinal),
                                |opening| opening.key(),
                            )
                            .ok()
                            .and_then(|opening_index| {
                                resolved_verifier_sequence_openings
                                    .get(opening_index)
                                    .map(|opening| opening.value)
                            })
                            .ok_or(RelationPlanError::InvalidOpening)
                    } else {
                        self.tree_column_opened_value(
                            column_ordinal,
                            opening_point_ordinal,
                            ordered_out_of_domain_evaluations,
                        )
                    }
                },
            )?;

            let raw_opening_point_ordinal =
                self.opening_point_ordinal_for_rotation(out_of_domain_point_ordinal, false, 0, 0)?;
            let mut reconstructed_quotient = ProofChallengeExtensionElement::ZERO;
            for component_ordinal in 0..context.quotient_component_count {
                let component_value = self.opened_value(
                    super::RelationOpeningSourceClass::Quotient,
                    component_ordinal,
                    None,
                    raw_opening_point_ordinal,
                    ordered_out_of_domain_evaluations,
                )?;
                let exponent = u64::from(component_ordinal)
                    .checked_mul(quotient_decomposition_stride)
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                reconstructed_quotient = reconstructed_quotient.add(
                    out_of_domain_point
                        .power(exponent)
                        .multiply(component_value),
                );
            }
            if reconstructed_quotient != composed_quotient {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }
        Ok(())
    }

    fn verifier_sequence_opening_keys(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<BTreeSet<(u32, u32)>, RelationPlanError> {
        let mut opening_keys = BTreeSet::new();
        self.visit_verifier_sequence_query_occurrences(
            context,
            |column_ordinal, opening_point_ordinal| {
                opening_keys.insert((column_ordinal, opening_point_ordinal));
                Ok(())
            },
        )?;
        Ok(opening_keys)
    }

    fn visit_verifier_sequence_query_occurrences<Visit>(
        &self,
        context: &RelationPlanCheckContext,
        mut visit: Visit,
    ) -> Result<(), RelationPlanError>
    where
        Visit: FnMut(u32, u32) -> Result<(), RelationPlanError>,
    {
        if context.out_of_domain_point_count == 0 {
            return Err(RelationPlanError::InvalidOpening);
        }
        for constraint in &self.ordered_constraints {
            visit_relation_column_queries(
                &[
                    &constraint.numerator_postfix_expression,
                    &constraint.zeroifier_postfix_expression,
                ],
                &self.ordered_radix_convolutions,
                RelationPlanError::InvalidConstraint,
                |query| {
                    let column = self
                        .ordered_columns
                        .get(
                            usize::try_from(query.column_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::InvalidColumn)?;
                    if !matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. }) {
                        return Ok(());
                    }
                    for out_of_domain_point_ordinal in 0..context.out_of_domain_point_count {
                        visit(
                            query.column_ordinal,
                            self.opening_point_ordinal_for_rotation(
                                out_of_domain_point_ordinal,
                                query.rotation_is_negative,
                                query.rotation_magnitude,
                                0,
                            )?,
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    pub(crate) fn derive_opening_points(
        &self,
        context: &RelationPlanCheckContext,
        out_of_domain_points: &[ProofChallengeExtensionElement],
    ) -> Result<Vec<ProofChallengeExtensionElement>, RelationPlanError> {
        if out_of_domain_points.len() != usize::from(context.out_of_domain_point_count)
            || self.trace_domain_size == 0
            || !self
                .evaluation_domain_size
                .is_multiple_of(self.trace_domain_size)
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let evaluation_generator =
            ProofBaseFieldElement::from_canonical(context.evaluation_domain_generator)
                .map_err(|_| RelationPlanError::InvalidDomain)?;
        let trace_generator =
            evaluation_generator.power(self.evaluation_domain_size / self.trace_domain_size);
        let mut result = Vec::with_capacity(self.ordered_opening_points.len());
        let mut canonical_points = BTreeSet::new();
        for descriptor in &self.ordered_opening_points {
            let out_of_domain_point = out_of_domain_points
                .get(usize::from(descriptor.out_of_domain_point_ordinal))
                .copied()
                .ok_or(RelationPlanError::InvalidOpening)?;
            let reduced_rotation = descriptor.trace_rotation_magnitude % self.trace_domain_size;
            let signed_exponent = if descriptor.trace_rotation_is_negative && reduced_rotation != 0
            {
                self.trace_domain_size - reduced_rotation
            } else {
                reduced_rotation
            };
            let rotated = out_of_domain_point.multiply_base(trace_generator.power(signed_exponent));
            let point = rotated.frobenius(descriptor.conjugate_index);
            if !canonical_points.insert(point.canonical_coordinates()) {
                return Err(RelationPlanError::InvalidOpening);
            }
            result.push(point);
        }
        Ok(result)
    }

    /// Bounds the candidates rejected by the production out-of-domain sampler without
    /// enumerating the challenge field.
    ///
    /// The bound applies after every lower ordinal has been accepted by the
    /// same sampler. It covers the sampler's zero and prior-point exclusions,
    /// every domain and zeroifier root tested below, short Frobenius orbits,
    /// and collisions with both current and prior translated orbits.
    #[cfg(test)]
    pub(crate) fn out_of_domain_point_sampler_cardinality_bound(
        &self,
        context: &RelationPlanCheckContext,
        point_ordinal: u16,
    ) -> Result<OutOfDomainPointSamplerCardinalityBound, RelationPlanError> {
        let checker = RelationPlanChecker::new(context);
        checker.check_context()?;
        if context.base_field_modulus != PROOF_BASE_FIELD_MODULUS
            || usize::from(context.challenge_extension_degree) != PROOF_CHALLENGE_EXTENSION_DEGREE
            || PROOF_CHALLENGE_EXTENSION_DEGREE < 2
            || self.trace_domain_size == 0
            || self.evaluation_domain_size == 0
            || !self
                .evaluation_domain_size
                .is_multiple_of(self.trace_domain_size)
            || context.evaluation_domain_generator == 0
            || context.evaluation_domain_generator >= context.base_field_modulus
            || context.evaluation_coset_offset == 0
            || context.evaluation_coset_offset >= context.base_field_modulus
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        if point_ordinal >= context.out_of_domain_point_count {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }

        let evaluation_generator =
            ProofBaseFieldElement::from_canonical(context.evaluation_domain_generator)
                .map_err(|_| RelationPlanError::InvalidDomain)?;
        let trace_generator =
            evaluation_generator.power(self.evaluation_domain_size / self.trace_domain_size);
        let mut rotation_scalars_by_point = BTreeMap::<u16, BTreeSet<u64>>::new();
        for descriptor in &self.ordered_opening_points {
            if descriptor.out_of_domain_point_ordinal >= context.out_of_domain_point_count
                || usize::from(descriptor.conjugate_index) >= PROOF_CHALLENGE_EXTENSION_DEGREE
            {
                return Err(RelationPlanError::InvalidOpening);
            }
            let rotation_exponent = signed_rotation_exponent(
                descriptor.trace_rotation_is_negative,
                descriptor.trace_rotation_magnitude,
                self.trace_domain_size,
            )?;
            let rotation_scalar = trace_generator.power(rotation_exponent).canonical();
            if !rotation_scalars_by_point
                .entry(descriptor.out_of_domain_point_ordinal)
                .or_default()
                .insert(rotation_scalar)
            {
                // Equal rotation scalars give identical translated Frobenius
                // orbits, so the live predicate would reject every candidate.
                return Err(RelationPlanError::InvalidOpening);
            }
        }
        let current_opening_count = rotation_scalars_by_point
            .get(&point_ordinal)
            .map(BTreeSet::len)
            .filter(|count| *count != 0)
            .ok_or(RelationPlanError::InvalidOpening)?;
        let prior_opening_count = rotation_scalars_by_point
            .iter()
            .filter(|(ordinal, _)| **ordinal < point_ordinal)
            .try_fold(0_usize, |count, (_, scalars)| {
                count
                    .checked_add(scalars.len())
                    .ok_or(RelationPlanError::CountOverflow)
            })?;

        let mut distinct_zeroifiers = BTreeSet::new();
        let mut zeroifier_root_count_ceiling = BigUint::default();
        for constraint in &self.ordered_constraints {
            if distinct_zeroifiers.insert(constraint.zeroifier_postfix_expression.as_slice()) {
                checker.check_zeroifier_on_coset(
                    &constraint.zeroifier_postfix_expression,
                    self.trace_domain_size,
                    self.evaluation_domain_size,
                )?;
                let shape = check_expression(
                    &constraint.zeroifier_postfix_expression,
                    self,
                    context,
                    true,
                )?;
                if shape.degree == 0 && shape.constant_value == Some(0) {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                zeroifier_root_count_ceiling += BigUint::from(shape.degree);
            }
        }

        let base_field_cardinality = BigUint::from(context.base_field_modulus);
        let extension_degree = u32::from(context.challenge_extension_degree);
        let field_cardinality = base_field_cardinality.pow(extension_degree);
        let per_point_algebraic_exclusion_ceiling = BigUint::from(self.trace_domain_size)
            + BigUint::from(self.evaluation_domain_size)
            + zeroifier_root_count_ceiling;

        // If a length-d Frobenius orbit repeats, the candidate is a root of
        // X^(p^e) - X for some 1 <= e < d. Summing those polynomial degrees is
        // a field-size-independent upper bound on all short orbits.
        let short_orbit_count_ceiling = (1..extension_degree)
            .map(|exponent| base_field_cardinality.pow(exponent))
            .fold(BigUint::default(), |sum, term| sum + term);
        let maximum_frobenius_equation_degree = base_field_cardinality.pow(extension_degree - 1);

        let current_opening_count =
            u64::try_from(current_opening_count).map_err(|_| RelationPlanError::CountOverflow)?;
        let prior_opening_count =
            u64::try_from(prior_opening_count).map_err(|_| RelationPlanError::CountOverflow)?;
        let extension_degree = u64::from(context.challenge_extension_degree);
        let orbit_pair_equation_count = extension_degree
            .checked_mul(extension_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        let current_opening_pair_count = current_opening_count
            .checked_mul(current_opening_count.saturating_sub(1))
            .and_then(|product| product.checked_div(2))
            .ok_or(RelationPlanError::CountOverflow)?;
        let current_orbit_collision_ceiling = BigUint::from(
            current_opening_pair_count
                .checked_mul(orbit_pair_equation_count)
                .ok_or(RelationPlanError::CountOverflow)?,
        ) * &maximum_frobenius_equation_degree;
        let prior_orbit_collision_ceiling = BigUint::from(
            current_opening_count
                .checked_mul(prior_opening_count)
                .and_then(|count| count.checked_mul(orbit_pair_equation_count))
                .ok_or(RelationPlanError::CountOverflow)?,
        ) * maximum_frobenius_equation_degree;

        let mut forbidden_candidate_count_ceiling = BigUint::from(1_u8)
            + &per_point_algebraic_exclusion_ceiling
            + BigUint::from(current_opening_count) * &per_point_algebraic_exclusion_ceiling
            + BigUint::from(current_opening_count) * short_orbit_count_ceiling
            + current_orbit_collision_ceiling
            + prior_orbit_collision_ceiling
            + BigUint::from(point_ordinal);
        if forbidden_candidate_count_ceiling > field_cardinality {
            forbidden_candidate_count_ceiling = field_cardinality.clone();
        }
        let accepted_candidate_count_floor =
            &field_cardinality - &forbidden_candidate_count_ceiling;
        Ok(OutOfDomainPointSamplerCardinalityBound {
            field_cardinality,
            forbidden_candidate_count_ceiling,
            accepted_candidate_count_floor,
        })
    }

    /// Derives the degree of the polynomial identity checked after clearing
    /// a common relation zeroifier at an out-of-domain point.
    ///
    /// The verifier compares the composition of the checked rational
    /// constraints with the source-ordered quotient-component reconstruction.
    /// Every accepted zeroifier grammar divides the full-trace zeroifier, so
    /// multiplying by that common multiple yields one polynomial without
    /// double-counting shared roots. This method derives both sides of its
    /// degree bound from the checked relation grammar instead of relying on a
    /// construction-specific literal.
    #[cfg(test)]
    pub(crate) fn cross_multiplied_composition_identity_degree_bound(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<u64, RelationPlanError> {
        let checker = RelationPlanChecker::new(context);
        checker.check_context()?;
        if self.ordered_constraints.is_empty()
            || context.quotient_component_count == 0
            || context.quotient_component_degree_bound_exclusive == 0
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let mut distinct_zeroifiers = Vec::<(Vec<RelationExpressionInstruction>, u64)>::new();
        let mut constraint_degrees = Vec::with_capacity(self.ordered_constraints.len());
        for constraint in &self.ordered_constraints {
            let numerator_degree = check_expression(
                &constraint.numerator_postfix_expression,
                self,
                context,
                false,
            )?
            .degree;
            let zeroifier_shape = check_expression(
                &constraint.zeroifier_postfix_expression,
                self,
                context,
                true,
            )?;
            if zeroifier_shape.degree == 0 && zeroifier_shape.constant_value == Some(0) {
                return Err(RelationPlanError::InvalidZeroifier);
            }
            if !super::zeroifier_roots_are_confined_to_trace_domain(
                &constraint.zeroifier_postfix_expression,
                self.trace_domain_size,
                context.base_field_modulus,
            ) || zeroifier_shape.degree > self.trace_domain_size
            {
                return Err(RelationPlanError::InvalidZeroifier);
            }
            if let Some((_, recorded_degree)) = distinct_zeroifiers
                .iter()
                .find(|(expression, _)| expression == &constraint.zeroifier_postfix_expression)
            {
                if *recorded_degree != zeroifier_shape.degree {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
            } else {
                checker.check_zeroifier_on_coset(
                    &constraint.zeroifier_postfix_expression,
                    self.trace_domain_size,
                    self.evaluation_domain_size,
                )?;
                distinct_zeroifiers.push((
                    constraint.zeroifier_postfix_expression.clone(),
                    zeroifier_shape.degree,
                ));
            }
            constraint_degrees.push((numerator_degree, zeroifier_shape.degree));
        }

        // Every accepted zeroifier grammar above divides X^trace_domain_size - 1.
        // That full-trace polynomial is therefore one common denominator. Using
        // the product of distinct zeroifiers would count shared trace roots more
        // than once and overstate the cross-multiplied degree.
        let common_zeroifier_degree = self.trace_domain_size;
        let cleared_constraint_degree = constraint_degrees.into_iter().try_fold(
            0_u64,
            |maximum_degree, (numerator_degree, zeroifier_degree)| {
                let degree = numerator_degree
                    .checked_add(common_zeroifier_degree)
                    .and_then(|degree| degree.checked_sub(zeroifier_degree))
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                Ok::<_, RelationPlanError>(maximum_degree.max(degree))
            },
        )?;

        let quotient_decomposition_stride = self.quotient_decomposition_stride(context)?;
        let final_component_ordinal = u64::from(context.quotient_component_count - 1);
        let reconstructed_quotient_degree = final_component_ordinal
            .checked_mul(quotient_decomposition_stride)
            .and_then(|degree| {
                degree.checked_add(context.quotient_component_degree_bound_exclusive - 1)
            })
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let cleared_reconstructed_quotient_degree = reconstructed_quotient_degree
            .checked_add(common_zeroifier_degree)
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;

        Ok(cleared_constraint_degree.max(cleared_reconstructed_quotient_degree))
    }

    pub(crate) fn out_of_domain_point_candidate_is_forbidden(
        &self,
        context: &RelationPlanCheckContext,
        point_ordinal: u16,
        candidate: ProofChallengeExtensionElement,
        prior_accepted_out_of_domain_points: &[ProofChallengeExtensionElement],
    ) -> Result<bool, RelationPlanError> {
        if self.trace_domain_size == 0
            || self.evaluation_domain_size == 0
            || !self
                .evaluation_domain_size
                .is_multiple_of(self.trace_domain_size)
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        if point_ordinal >= context.out_of_domain_point_count
            || prior_accepted_out_of_domain_points.len() != usize::from(point_ordinal)
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        if candidate.is_zero() {
            return Ok(true);
        }
        let evaluation_coset_offset =
            ProofBaseFieldElement::from_canonical(context.evaluation_coset_offset)
                .map_err(|_| RelationPlanError::InvalidDomain)?;
        let evaluation_coset_constant = ProofChallengeExtensionElement::from_base(
            evaluation_coset_offset.power(self.evaluation_domain_size),
        );

        let point_is_in_excluded_domain = |point: ProofChallengeExtensionElement| {
            point.power(self.trace_domain_size) == ProofChallengeExtensionElement::ONE
                || point.power(self.evaluation_domain_size) == evaluation_coset_constant
        };
        if point_is_in_excluded_domain(candidate)
            || !self.zeroifiers_are_nonzero_at(context, candidate)?
        {
            return Ok(true);
        }

        let evaluation_generator =
            ProofBaseFieldElement::from_canonical(context.evaluation_domain_generator)
                .map_err(|_| RelationPlanError::InvalidDomain)?;
        let trace_generator =
            evaluation_generator.power(self.evaluation_domain_size / self.trace_domain_size);
        let extension_degree = context.challenge_extension_degree;
        let frobenius_orbit = |point: ProofChallengeExtensionElement| {
            (0..extension_degree)
                .map(|conjugate_index| point.frobenius(conjugate_index).canonical_coordinates())
                .collect::<BTreeSet<_>>()
        };
        let mut prior_translated_orbits = BTreeSet::new();
        for descriptor in self
            .ordered_opening_points
            .iter()
            .filter(|descriptor| descriptor.out_of_domain_point_ordinal < point_ordinal)
        {
            let prior_out_of_domain_point = prior_accepted_out_of_domain_points
                .get(usize::from(descriptor.out_of_domain_point_ordinal))
                .copied()
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            let reduced_rotation = descriptor.trace_rotation_magnitude % self.trace_domain_size;
            let signed_exponent = if descriptor.trace_rotation_is_negative && reduced_rotation != 0
            {
                self.trace_domain_size - reduced_rotation
            } else {
                reduced_rotation
            };
            let translated = prior_out_of_domain_point
                .multiply_base(trace_generator.power(signed_exponent))
                .frobenius(descriptor.conjugate_index);
            let orbit = frobenius_orbit(translated);
            if orbit.len() != usize::from(extension_degree) {
                return Err(RelationPlanError::InvalidOpening);
            }
            for orbit_element in orbit {
                if !prior_translated_orbits.insert(orbit_element) {
                    return Err(RelationPlanError::InvalidOpening);
                }
            }
        }
        let mut translated_orbits = BTreeSet::new();
        for descriptor in self
            .ordered_opening_points
            .iter()
            .filter(|descriptor| descriptor.out_of_domain_point_ordinal == point_ordinal)
        {
            let reduced_rotation = descriptor.trace_rotation_magnitude % self.trace_domain_size;
            let signed_exponent = if descriptor.trace_rotation_is_negative && reduced_rotation != 0
            {
                self.trace_domain_size - reduced_rotation
            } else {
                reduced_rotation
            };
            let translated = candidate
                .multiply_base(trace_generator.power(signed_exponent))
                .frobenius(descriptor.conjugate_index);
            let orbit = frobenius_orbit(translated);
            if point_is_in_excluded_domain(translated)
                || !self.zeroifiers_are_nonzero_at(context, translated)?
                || orbit.len() != usize::from(extension_degree)
                || orbit.iter().any(|orbit_element| {
                    prior_translated_orbits.contains(orbit_element)
                        || translated_orbits.contains(orbit_element)
                })
            {
                return Ok(true);
            }
            translated_orbits.extend(orbit);
        }
        Ok(false)
    }

    fn zeroifiers_are_nonzero_at(
        &self,
        context: &RelationPlanCheckContext,
        evaluation_point: ProofChallengeExtensionElement,
    ) -> Result<bool, RelationPlanError> {
        let no_challenges = CheckedRelationApplicationChallenges {
            values: BTreeMap::new(),
        };
        for constraint in &self.ordered_constraints {
            let zeroifier = evaluate_program(
                self,
                context,
                &constraint.zeroifier_postfix_expression,
                evaluation_point,
                &no_challenges,
                &mut |_, _, _| Err(RelationPlanError::InvalidZeroifier),
                true,
            )?;
            if zeroifier.is_zero() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn opening_point_ordinal_for_rotation(
        &self,
        out_of_domain_point_ordinal: u16,
        rotation_is_negative: bool,
        rotation_magnitude: u64,
        conjugate_index: u16,
    ) -> Result<u32, RelationPlanError> {
        let target_exponent = signed_rotation_exponent(
            rotation_is_negative,
            rotation_magnitude,
            self.trace_domain_size,
        )?;
        let mut matches =
            self.ordered_opening_points
                .iter()
                .enumerate()
                .filter(|(_, descriptor)| {
                    descriptor.out_of_domain_point_ordinal == out_of_domain_point_ordinal
                        && descriptor.conjugate_index == conjugate_index
                        && signed_rotation_exponent(
                            descriptor.trace_rotation_is_negative,
                            descriptor.trace_rotation_magnitude,
                            self.trace_domain_size,
                        ) == Ok(target_exponent)
                });
        let (ordinal, _) = matches.next().ok_or(RelationPlanError::InvalidOpening)?;
        if matches.next().is_some() {
            return Err(RelationPlanError::InvalidOpening);
        }
        u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)
    }

    fn tree_column_opened_value(
        &self,
        column_ordinal: u32,
        opening_point_ordinal: u32,
        ordered_out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let mut matching_tree_ordinals = self
            .ordered_trees
            .iter()
            .enumerate()
            .filter(|(_, tree)| tree.ordered_column_ordinals().contains(&column_ordinal))
            .map(|(tree_ordinal, _)| {
                u32::try_from(tree_ordinal).map_err(|_| RelationPlanError::CountOverflow)
            });
        let tree_ordinal = matching_tree_ordinals
            .next()
            .ok_or(RelationPlanError::InvalidOpening)??;
        if matching_tree_ordinals.next().is_some() {
            return Err(RelationPlanError::InvalidOpening);
        }
        self.opened_value(
            super::RelationOpeningSourceClass::TreeColumn,
            tree_ordinal,
            Some(column_ordinal),
            opening_point_ordinal,
            ordered_out_of_domain_evaluations,
        )
    }

    fn opened_value(
        &self,
        source_class: super::RelationOpeningSourceClass,
        source_ordinal: u32,
        column_ordinal: Option<u32>,
        opening_point_ordinal: u32,
        ordered_out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let mut matches = self
            .ordered_opening_claims
            .iter()
            .enumerate()
            .filter(|(_, claim)| {
                claim.source_class == source_class
                    && claim.source_ordinal == source_ordinal
                    && claim.column_ordinal == column_ordinal
                    && claim.opening_point_ordinal == opening_point_ordinal
            });
        let (claim_ordinal, _) = matches.next().ok_or(RelationPlanError::InvalidOpening)?;
        if matches.next().is_some() {
            return Err(RelationPlanError::InvalidOpening);
        }
        ordered_out_of_domain_evaluations
            .get(claim_ordinal)
            .copied()
            .ok_or(RelationPlanError::InvalidOpening)
    }

    pub(crate) fn quotient_decomposition_stride(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<u64, RelationPlanError> {
        if context.quotient_component_count < 2 {
            return Err(RelationPlanError::DegreeBoundExceeded);
        }
        if self.proof_privacy_mode == super::ProofPrivacyMode::PublicOnly {
            return Ok(self.trace_domain_size);
        }
        let mut trace_mask_degrees = self
            .ordered_masks
            .iter()
            .filter(|mask| {
                mask.mask_kind == super::RelationMaskKind::Trace
                    && mask.target_class == super::RelationMaskTargetClass::Column
            })
            .map(|mask| mask.mask_degree_bound_exclusive);
        let trace_mask_degree = trace_mask_degrees
            .next()
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        if trace_mask_degrees.any(|degree| degree != trace_mask_degree) {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let component_count = u128::from(context.quotient_component_count);
        let scaled_mask_degree = component_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(u128::from(trace_mask_degree)))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let rounded_mask_degree = scaled_mask_degree
            .checked_add(component_count - 1)
            .ok_or(RelationPlanError::DegreeBoundExceeded)?
            / component_count;
        self.trace_domain_size
            .checked_add(
                u64::try_from(rounded_mask_degree)
                    .map_err(|_| RelationPlanError::DegreeBoundExceeded)?,
            )
            .ok_or(RelationPlanError::DegreeBoundExceeded)
    }
}

pub(super) fn signed_rotation_exponent(
    rotation_is_negative: bool,
    rotation_magnitude: u64,
    trace_domain_size: u64,
) -> Result<u64, RelationPlanError> {
    if trace_domain_size == 0 || (rotation_magnitude == 0 && rotation_is_negative) {
        return Err(RelationPlanError::InvalidOpening);
    }
    let reduced = rotation_magnitude % trace_domain_size;
    Ok(if rotation_is_negative && reduced != 0 {
        trace_domain_size - reduced
    } else {
        reduced
    })
}

fn evaluate_program<ColumnValue>(
    _variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    program: &[RelationExpressionInstruction],
    evaluation_point: ProofChallengeExtensionElement,
    application_challenges: &CheckedRelationApplicationChallenges,
    column_value: &mut ColumnValue,
    zeroifier_program: bool,
) -> Result<ProofChallengeExtensionElement, RelationPlanError>
where
    ColumnValue: FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
{
    let mut stack = Vec::with_capacity(program.len());
    for instruction in program {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                let value = ProofBaseFieldElement::from_canonical(*value)
                    .map_err(|_| RelationPlanError::InvalidConstraint)?;
                stack.push(ProofChallengeExtensionElement::from_base(value));
            }
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } if !zeroifier_program => {
                if *multiplier == 0 {
                    return Err(RelationPlanError::InvalidModulus);
                }
                let value = context
                    .resolved_modulus(*modulus_reference)?
                    .checked_mul(u64::from(*multiplier))
                    .filter(|value| *value < context.base_field_modulus)
                    .ok_or(RelationPlanError::NoWrapBoundViolated)?;
                let value = ProofBaseFieldElement::from_canonical(value)
                    .map_err(|_| RelationPlanError::InvalidConstraint)?;
                stack.push(ProofChallengeExtensionElement::from_base(value));
            }
            RelationExpressionInstruction::EvaluationVariable => stack.push(evaluation_point),
            RelationExpressionInstruction::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } if !zeroifier_program => stack.push(column_value(
                *column_ordinal,
                *rotation_is_negative,
                *rotation_magnitude,
            )?),
            RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                ordered_terms,
                ..
            } if !zeroifier_program => {
                let mut sum = ProofChallengeExtensionElement::ZERO;
                for term in ordered_terms {
                    let constant = column_value(term.constant_column_ordinal, false, 0)?;
                    let verifier_sequence = column_value(
                        term.verifier_sequence_column_ordinal,
                        term.verifier_sequence_rotation_is_negative,
                        term.verifier_sequence_rotation_magnitude,
                    )?;
                    sum = sum.add(constant.multiply(verifier_sequence));
                }
                stack.push(sum);
            }
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } if !zeroifier_program => {
                stack.push(application_challenges.get(*challenge_role, role_coordinates)?)
            }
            #[cfg(test)]
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } if !zeroifier_program => stack.push(evaluate_radix_convolution_coefficient(
                _variant,
                *convolution_ordinal,
                *coefficient_ordinal,
                column_value,
            )?),
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } if zeroifier_program => stack.push(evaluate_trace_domain_except_roots(
                evaluation_point,
                *trace_domain_size,
                ordered_excluded_roots,
            )?),
            RelationExpressionInstruction::Addition => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(left.add(right));
            }
            RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(left.multiply(right));
            }
            RelationExpressionInstruction::Negation => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(value.negate());
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(value.power(*exponent));
            }
            _ => {
                return Err(if zeroifier_program {
                    RelationPlanError::InvalidZeroifier
                } else {
                    RelationPlanError::InvalidConstraint
                });
            }
        }
    }
    if stack.len() != 1 {
        return Err(if zeroifier_program {
            RelationPlanError::InvalidZeroifier
        } else {
            RelationPlanError::InvalidConstraint
        });
    }
    stack.pop().ok_or(RelationPlanError::InvalidConstraint)
}

fn evaluate_trace_domain_except_roots(
    evaluation_point: ProofChallengeExtensionElement,
    trace_domain_size: u64,
    ordered_excluded_roots: &[u64],
) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
    if trace_domain_size == 0 || ordered_excluded_roots.is_empty() {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let one = ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(1)
            .map_err(|_| RelationPlanError::InvalidZeroifier)?,
    );
    let roots = ordered_excluded_roots
        .iter()
        .map(|root| {
            ProofBaseFieldElement::from_canonical(*root)
                .map(ProofChallengeExtensionElement::from_base)
                .map_err(|_| RelationPlanError::InvalidZeroifier)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let matching_root_ordinal = roots.iter().position(|root| *root == evaluation_point);
    if let Some(matching_root_ordinal) = matching_root_ordinal {
        let trace_size = ProofBaseFieldElement::from_canonical(trace_domain_size)
            .map(ProofChallengeExtensionElement::from_base)
            .map_err(|_| RelationPlanError::InvalidZeroifier)?;
        let matching_root = roots[matching_root_ordinal];
        let mut denominator = one;
        for (root_ordinal, root) in roots.iter().copied().enumerate() {
            if root_ordinal != matching_root_ordinal {
                denominator = denominator.multiply(matching_root.add(root.negate()));
            }
        }
        return trace_size
            .multiply(matching_root.power(trace_domain_size - 1))
            .divide(denominator)
            .map_err(|_| RelationPlanError::InvalidZeroifier);
    }
    let numerator = evaluation_point.power(trace_domain_size).add(one.negate());
    let denominator = roots.into_iter().fold(one, |product, root| {
        product.multiply(evaluation_point.add(root.negate()))
    });
    numerator
        .divide(denominator)
        .map_err(|_| RelationPlanError::InvalidZeroifier)
}

#[cfg(test)]
fn evaluate_radix_convolution_coefficient<ColumnValue>(
    variant: &RelationPlanVariant,
    convolution_ordinal: u32,
    coefficient_ordinal: u32,
    column_value: &mut ColumnValue,
) -> Result<ProofChallengeExtensionElement, RelationPlanError>
where
    ColumnValue: FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
{
    let convolution = variant
        .ordered_radix_convolutions
        .get(convolution_ordinal as usize)
        .ok_or(RelationPlanError::InvalidConstraint)?;
    let coefficient_ordinal =
        usize::try_from(coefficient_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
    let one = ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(1)
            .map_err(|_| RelationPlanError::InvalidConstraint)?,
    );
    let mut sum = ProofChallengeExtensionElement::ZERO;
    for term in &convolution.ordered_terms {
        let mut coefficients = vec![one];
        for factor in &term.ordered_factors {
            let factor_coefficients = match factor {
                super::RelationRadixFactorDescriptor::ColumnDigits {
                    ordered_column_ordinals,
                    rotation_is_negative,
                    rotation_magnitude,
                } => ordered_column_ordinals
                    .iter()
                    .map(|column_ordinal| {
                        column_value(*column_ordinal, *rotation_is_negative, *rotation_magnitude)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                super::RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => {
                    ordered_digits
                        .iter()
                        .map(|digit| {
                            ProofBaseFieldElement::from_canonical(*digit)
                                .map(ProofChallengeExtensionElement::from_base)
                                .map_err(|_| RelationPlanError::InvalidConstraint)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                }
                super::RelationRadixFactorDescriptor::ScalarColumn {
                    column_ordinal,
                    complement_binary_value,
                } => {
                    let value = column_value(*column_ordinal, false, 0)?;
                    vec![if *complement_binary_value {
                        one.add(value.negate())
                    } else {
                        value
                    }]
                }
            };
            coefficients = convolve_extension_coefficients(
                &coefficients,
                &factor_coefficients,
                coefficient_ordinal,
            )?;
        }
        let coefficient = coefficients
            .get(coefficient_ordinal)
            .copied()
            .unwrap_or(ProofChallengeExtensionElement::ZERO);
        sum = sum.add(if term.negative {
            coefficient.negate()
        } else {
            coefficient
        });
    }
    Ok(sum)
}

#[cfg(test)]
fn convolve_extension_coefficients(
    left: &[ProofChallengeExtensionElement],
    right: &[ProofChallengeExtensionElement],
    maximum_coefficient_ordinal: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, RelationPlanError> {
    let output_length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?
        .min(
            maximum_coefficient_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    let mut output = vec![ProofChallengeExtensionElement::ZERO; output_length];
    for (left_ordinal, left_value) in left.iter().copied().enumerate() {
        for (right_ordinal, right_value) in right.iter().copied().enumerate() {
            let output_ordinal = left_ordinal
                .checked_add(right_ordinal)
                .ok_or(RelationPlanError::CountOverflow)?;
            if output_ordinal >= output_length {
                break;
            }
            output[output_ordinal] = output[output_ordinal].add(left_value.multiply(right_value));
        }
    }
    Ok(output)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum IndependentInstructionKind {
    BaseFieldConstant,
    NonNativeModulusConstant,
    EvaluationVariable,
    ColumnValue,
    ConstantColumnVerifierSequenceProductSum,
    TranscriptChallenge,
    Addition,
    Multiplication,
    Negation,
    NonnegativePower,
    RadixConvolutionCoefficient,
    TraceDomainExceptRoots,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationCompilerInterpreterSemanticCertificate {
    canonical_variant_hash: [u8; 64],
    constraint_count: usize,
    structurally_checked_program_count: usize,
    structurally_checked_instruction_count: usize,
    covered_instruction_kind_count: usize,
    trace_domain_case_count: usize,
    randomized_extension_case_count: usize,
    compared_program_evaluation_count: usize,
    mismatch_count: usize,
}

#[cfg(test)]
impl RelationCompilerInterpreterSemanticCertificate {
    pub(crate) fn is_complete(&self) -> bool {
        let case_count = self
            .trace_domain_case_count
            .checked_add(self.randomized_extension_case_count);
        self.canonical_variant_hash != [0_u8; 64]
            && self.constraint_count > 0
            && self.structurally_checked_program_count == self.constraint_count * 2
            && self.structurally_checked_instruction_count > self.structurally_checked_program_count
            && self.covered_instruction_kind_count > 0
            && self.trace_domain_case_count > 0
            && self.randomized_extension_case_count > 0
            && case_count
                .and_then(|count| self.structurally_checked_program_count.checked_mul(count))
                == Some(self.compared_program_evaluation_count)
            && self.mismatch_count == 0
    }

    pub(crate) const fn constraint_count(&self) -> usize {
        self.constraint_count
    }

    pub(crate) const fn compared_program_evaluation_count(&self) -> usize {
        self.compared_program_evaluation_count
    }

    pub(crate) const fn canonical_variant_hash(&self) -> [u8; 64] {
        self.canonical_variant_hash
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IndependentSemanticOracleFault {
    None,
    ChangeFirstEvaluation,
}

#[cfg(test)]
enum IndependentExpression<'program> {
    BaseFieldConstant(u64),
    NonNativeModulusConstant {
        modulus_reference: super::SuiteModulusReference,
        multiplier: u16,
    },
    EvaluationVariable,
    ColumnValue {
        column_ordinal: u32,
        rotation_is_negative: bool,
        rotation_magnitude: u64,
    },
    ConstantColumnVerifierSequenceProductSum(
        &'program [super::RelationConstantColumnVerifierSequenceProductTerm],
    ),
    TranscriptChallenge {
        challenge_role: RelationChallengeRole,
        role_coordinates: &'program [u64],
    },
    Addition(Box<Self>, Box<Self>),
    Multiplication(Box<Self>, Box<Self>),
    Negation(Box<Self>),
    NonnegativePower(Box<Self>, u64),
    RadixConvolutionCoefficient {
        convolution_ordinal: u32,
        coefficient_ordinal: u32,
    },
    TraceDomainExceptRoots {
        trace_domain_size: u64,
        ordered_excluded_roots: &'program [u64],
    },
}

#[cfg(test)]
fn independent_instruction_kind(
    instruction: &RelationExpressionInstruction,
) -> IndependentInstructionKind {
    match instruction {
        RelationExpressionInstruction::BaseFieldConstant(_) => {
            IndependentInstructionKind::BaseFieldConstant
        }
        RelationExpressionInstruction::NonNativeModulusConstant { .. } => {
            IndependentInstructionKind::NonNativeModulusConstant
        }
        RelationExpressionInstruction::EvaluationVariable => {
            IndependentInstructionKind::EvaluationVariable
        }
        RelationExpressionInstruction::ColumnValue { .. } => {
            IndependentInstructionKind::ColumnValue
        }
        RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum { .. } => {
            IndependentInstructionKind::ConstantColumnVerifierSequenceProductSum
        }
        RelationExpressionInstruction::TranscriptChallenge { .. } => {
            IndependentInstructionKind::TranscriptChallenge
        }
        RelationExpressionInstruction::Addition => IndependentInstructionKind::Addition,
        RelationExpressionInstruction::Multiplication => IndependentInstructionKind::Multiplication,
        RelationExpressionInstruction::Negation => IndependentInstructionKind::Negation,
        RelationExpressionInstruction::NonnegativePower(_) => {
            IndependentInstructionKind::NonnegativePower
        }
        RelationExpressionInstruction::RadixConvolutionCoefficient { .. } => {
            IndependentInstructionKind::RadixConvolutionCoefficient
        }
        RelationExpressionInstruction::TraceDomainExceptRoots { .. } => {
            IndependentInstructionKind::TraceDomainExceptRoots
        }
    }
}

#[cfg(test)]
fn parse_independent_expression<'program>(
    program: &'program [RelationExpressionInstruction],
    zeroifier_program: bool,
    covered_instruction_kinds: &mut BTreeSet<IndependentInstructionKind>,
) -> Result<IndependentExpression<'program>, RelationPlanError> {
    let mut stack = Vec::<IndependentExpression<'program>>::new();
    for instruction in program {
        covered_instruction_kinds.insert(independent_instruction_kind(instruction));
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                stack.push(IndependentExpression::BaseFieldConstant(*value));
            }
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } if !zeroifier_program => {
                stack.push(IndependentExpression::NonNativeModulusConstant {
                    modulus_reference: *modulus_reference,
                    multiplier: *multiplier,
                });
            }
            RelationExpressionInstruction::EvaluationVariable => {
                stack.push(IndependentExpression::EvaluationVariable);
            }
            RelationExpressionInstruction::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } if !zeroifier_program => stack.push(IndependentExpression::ColumnValue {
                column_ordinal: *column_ordinal,
                rotation_is_negative: *rotation_is_negative,
                rotation_magnitude: *rotation_magnitude,
            }),
            RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                ordered_terms,
                ..
            } if !zeroifier_program => stack.push(
                IndependentExpression::ConstantColumnVerifierSequenceProductSum(ordered_terms),
            ),
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } if !zeroifier_program => stack.push(IndependentExpression::TranscriptChallenge {
                challenge_role: *challenge_role,
                role_coordinates,
            }),
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } if !zeroifier_program => {
                stack.push(IndependentExpression::RadixConvolutionCoefficient {
                    convolution_ordinal: *convolution_ordinal,
                    coefficient_ordinal: *coefficient_ordinal,
                });
            }
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } if zeroifier_program => {
                stack.push(IndependentExpression::TraceDomainExceptRoots {
                    trace_domain_size: *trace_domain_size,
                    ordered_excluded_roots,
                });
            }
            RelationExpressionInstruction::Addition => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(IndependentExpression::Addition(
                    Box::new(left),
                    Box::new(right),
                ));
            }
            RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(IndependentExpression::Multiplication(
                    Box::new(left),
                    Box::new(right),
                ));
            }
            RelationExpressionInstruction::Negation => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(IndependentExpression::Negation(Box::new(value)));
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(IndependentExpression::NonnegativePower(
                    Box::new(value),
                    *exponent,
                ));
            }
            _ => {
                return Err(if zeroifier_program {
                    RelationPlanError::InvalidZeroifier
                } else {
                    RelationPlanError::InvalidConstraint
                });
            }
        }
    }
    if stack.len() != 1 {
        return Err(if zeroifier_program {
            RelationPlanError::InvalidZeroifier
        } else {
            RelationPlanError::InvalidConstraint
        });
    }
    stack.pop().ok_or(RelationPlanError::InvalidConstraint)
}

#[cfg(test)]
fn independent_base_value(value: u64) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
    ProofBaseFieldElement::from_canonical(value)
        .map(ProofChallengeExtensionElement::from_base)
        .map_err(|_| RelationPlanError::InvalidConstraint)
}

#[cfg(test)]
fn independent_trace_domain_except_roots(
    evaluation_point: ProofChallengeExtensionElement,
    trace_domain_size: u64,
    ordered_excluded_roots: &[u64],
) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
    if trace_domain_size == 0 || ordered_excluded_roots.is_empty() {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let one = independent_base_value(1)?;
    let roots = ordered_excluded_roots
        .iter()
        .copied()
        .map(independent_base_value)
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(matching_ordinal) = roots.iter().position(|root| *root == evaluation_point) {
        let matching_root = roots[matching_ordinal];
        let derivative = independent_base_value(trace_domain_size)?
            .multiply(matching_root.power(trace_domain_size - 1));
        let denominator = roots
            .iter()
            .copied()
            .enumerate()
            .filter(|(root_ordinal, _)| *root_ordinal != matching_ordinal)
            .fold(one, |product, (_, root)| {
                product.multiply(matching_root.add(root.negate()))
            });
        return derivative
            .divide(denominator)
            .map_err(|_| RelationPlanError::InvalidZeroifier);
    }
    let numerator = evaluation_point.power(trace_domain_size).add(one.negate());
    let denominator = roots.into_iter().fold(one, |product, root| {
        product.multiply(evaluation_point.add(root.negate()))
    });
    numerator
        .divide(denominator)
        .map_err(|_| RelationPlanError::InvalidZeroifier)
}

#[cfg(test)]
fn independent_radix_factor_coefficients<ColumnValue>(
    factor: &RelationRadixFactorDescriptor,
    maximum_coefficient_ordinal: usize,
    column_value: &mut ColumnValue,
) -> Result<Vec<ProofChallengeExtensionElement>, RelationPlanError>
where
    ColumnValue: FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
{
    let one = independent_base_value(1)?;
    match factor {
        RelationRadixFactorDescriptor::ColumnDigits {
            ordered_column_ordinals,
            rotation_is_negative,
            rotation_magnitude,
        } => ordered_column_ordinals
            .iter()
            .take(maximum_coefficient_ordinal + 1)
            .map(|column_ordinal| {
                column_value(*column_ordinal, *rotation_is_negative, *rotation_magnitude)
            })
            .collect(),
        RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => ordered_digits
            .iter()
            .copied()
            .take(maximum_coefficient_ordinal + 1)
            .map(independent_base_value)
            .collect(),
        RelationRadixFactorDescriptor::ScalarColumn {
            column_ordinal,
            complement_binary_value,
        } => {
            let value = column_value(*column_ordinal, false, 0)?;
            Ok(vec![if *complement_binary_value {
                one.add(value.negate())
            } else {
                value
            }])
        }
    }
}

#[cfg(test)]
fn independent_truncated_polynomial_product(
    left: &[ProofChallengeExtensionElement],
    right: &[ProofChallengeExtensionElement],
    maximum_coefficient_ordinal: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, RelationPlanError> {
    let output_length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?
        .min(
            maximum_coefficient_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    let mut result = vec![ProofChallengeExtensionElement::ZERO; output_length];
    for output_ordinal in 0..output_length {
        let minimum_left_ordinal = output_ordinal.saturating_sub(right.len().saturating_sub(1));
        let maximum_left_ordinal = output_ordinal.min(left.len().saturating_sub(1));
        for left_ordinal in minimum_left_ordinal..=maximum_left_ordinal {
            let right_ordinal = output_ordinal - left_ordinal;
            result[output_ordinal] =
                result[output_ordinal].add(left[left_ordinal].multiply(right[right_ordinal]));
        }
    }
    Ok(result)
}

#[cfg(test)]
fn independent_radix_convolution_coefficient<ColumnValue>(
    variant: &RelationPlanVariant,
    convolution_ordinal: u32,
    coefficient_ordinal: u32,
    column_value: &mut ColumnValue,
) -> Result<ProofChallengeExtensionElement, RelationPlanError>
where
    ColumnValue: FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
{
    let convolution = variant
        .ordered_radix_convolutions
        .get(usize::try_from(convolution_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
        .ok_or(RelationPlanError::InvalidConstraint)?;
    let coefficient_ordinal =
        usize::try_from(coefficient_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
    let one = independent_base_value(1)?;
    let mut sum = ProofChallengeExtensionElement::ZERO;
    for term in &convolution.ordered_terms {
        let mut product = vec![one];
        for factor in &term.ordered_factors {
            let factor_coefficients =
                independent_radix_factor_coefficients(factor, coefficient_ordinal, column_value)?;
            product = independent_truncated_polynomial_product(
                &product,
                &factor_coefficients,
                coefficient_ordinal,
            )?;
        }
        let coefficient = product
            .get(coefficient_ordinal)
            .copied()
            .unwrap_or(ProofChallengeExtensionElement::ZERO);
        sum = sum.add(if term.negative {
            coefficient.negate()
        } else {
            coefficient
        });
    }
    Ok(sum)
}

#[cfg(test)]
fn evaluate_independent_expression<ColumnValue>(
    expression: &IndependentExpression<'_>,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    evaluation_point: ProofChallengeExtensionElement,
    application_challenges: &CheckedRelationApplicationChallenges,
    column_value: &mut ColumnValue,
) -> Result<ProofChallengeExtensionElement, RelationPlanError>
where
    ColumnValue: FnMut(u32, bool, u64) -> Result<ProofChallengeExtensionElement, RelationPlanError>,
{
    match expression {
        IndependentExpression::BaseFieldConstant(value) => independent_base_value(*value),
        IndependentExpression::NonNativeModulusConstant {
            modulus_reference,
            multiplier,
        } => {
            if *multiplier == 0 {
                return Err(RelationPlanError::InvalidModulus);
            }
            let value = context
                .resolved_modulus(*modulus_reference)?
                .checked_mul(u64::from(*multiplier))
                .filter(|value| *value < context.base_field_modulus)
                .ok_or(RelationPlanError::NoWrapBoundViolated)?;
            independent_base_value(value)
        }
        IndependentExpression::EvaluationVariable => Ok(evaluation_point),
        IndependentExpression::ColumnValue {
            column_ordinal,
            rotation_is_negative,
            rotation_magnitude,
        } => column_value(*column_ordinal, *rotation_is_negative, *rotation_magnitude),
        IndependentExpression::ConstantColumnVerifierSequenceProductSum(ordered_terms) => {
            ordered_terms
                .iter()
                .try_fold(ProofChallengeExtensionElement::ZERO, |sum, term| {
                    let constant = column_value(term.constant_column_ordinal, false, 0)?;
                    let verifier_sequence = column_value(
                        term.verifier_sequence_column_ordinal,
                        term.verifier_sequence_rotation_is_negative,
                        term.verifier_sequence_rotation_magnitude,
                    )?;
                    Ok(sum.add(constant.multiply(verifier_sequence)))
                })
        }
        IndependentExpression::TranscriptChallenge {
            challenge_role,
            role_coordinates,
        } => application_challenges.get(*challenge_role, role_coordinates),
        IndependentExpression::Addition(left, right) => Ok(evaluate_independent_expression(
            left,
            variant,
            context,
            evaluation_point,
            application_challenges,
            column_value,
        )?
        .add(evaluate_independent_expression(
            right,
            variant,
            context,
            evaluation_point,
            application_challenges,
            column_value,
        )?)),
        IndependentExpression::Multiplication(left, right) => Ok(evaluate_independent_expression(
            left,
            variant,
            context,
            evaluation_point,
            application_challenges,
            column_value,
        )?
        .multiply(evaluate_independent_expression(
            right,
            variant,
            context,
            evaluation_point,
            application_challenges,
            column_value,
        )?)),
        IndependentExpression::Negation(value) => Ok(evaluate_independent_expression(
            value,
            variant,
            context,
            evaluation_point,
            application_challenges,
            column_value,
        )?
        .negate()),
        IndependentExpression::NonnegativePower(value, exponent) => {
            Ok(evaluate_independent_expression(
                value,
                variant,
                context,
                evaluation_point,
                application_challenges,
                column_value,
            )?
            .power(*exponent))
        }
        IndependentExpression::RadixConvolutionCoefficient {
            convolution_ordinal,
            coefficient_ordinal,
        } => independent_radix_convolution_coefficient(
            variant,
            *convolution_ordinal,
            *coefficient_ordinal,
            column_value,
        ),
        IndependentExpression::TraceDomainExceptRoots {
            trace_domain_size,
            ordered_excluded_roots,
        } => independent_trace_domain_except_roots(
            evaluation_point,
            *trace_domain_size,
            ordered_excluded_roots,
        ),
    }
}

#[cfg(test)]
fn deterministic_semantic_oracle_column_value(
    case_ordinal: usize,
    column_ordinal: u32,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
    let seed = u64::try_from(case_ordinal)
        .map_err(|_| RelationPlanError::CountOverflow)?
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ u64::from(column_ordinal).wrapping_mul(0xbf58_476d_1ce4_e5b9)
        ^ rotation_magnitude.wrapping_mul(0x94d0_49bb_1331_11eb)
        ^ u64::from(rotation_is_negative);
    let coordinates = core::array::from_fn(|coordinate_ordinal| {
        seed.rotate_left(
            u32::try_from(coordinate_ordinal * 11 + 7).expect("extension coordinate fits u32"),
        )
        .wrapping_add(
            u64::try_from(coordinate_ordinal + 1)
                .expect("extension coordinate fits u64")
                .wrapping_mul(0xd6e8_feb8_6659_fd93),
        ) % PROOF_BASE_FIELD_MODULUS
    });
    ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
        .map_err(|_| RelationPlanError::InvalidConstraint)
}

#[cfg(test)]
fn deterministic_semantic_oracle_application_challenges(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationApplicationChallengeAssignment>, RelationPlanError> {
    let mut required_coordinates = BTreeMap::new();
    for descriptor in variant.derived_relation_prefix_challenge_catalog(context)? {
        if !matches!(
            descriptor.role,
            RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha
        ) {
            continue;
        }
        let modulus_ordinal = u16::try_from(
            *descriptor
                .role_coordinates
                .first()
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
        )
        .map_err(|_| RelationPlanError::CountOverflow)?;
        let repetition_ordinal = u16::try_from(
            *descriptor
                .role_coordinates
                .get(1)
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
        )
        .map_err(|_| RelationPlanError::CountOverflow)?;
        let (challenge, coordinate_modulus) = match descriptor.role {
            RelationChallengeRole::NonNativeTheta => (
                CommonProofChallenge::Theta { modulus_ordinal },
                context.base_field_modulus,
            ),
            RelationChallengeRole::NonNativeAlpha => {
                let modulus_reference = variant
                    .ordered_non_native_moduli
                    .get(usize::from(modulus_ordinal))
                    .copied()
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                (
                    CommonProofChallenge::Alpha { modulus_ordinal },
                    context.resolved_modulus(modulus_reference)?,
                )
            }
            _ => return Err(RelationPlanError::InvalidChallengeCatalog),
        };
        if coordinate_modulus <= 1 {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        match required_coordinates.insert((challenge, repetition_ordinal), coordinate_modulus) {
            Some(previous_modulus) if previous_modulus != coordinate_modulus => {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            _ => {}
        }
    }
    required_coordinates
        .into_iter()
        .map(|((challenge, repetition_ordinal), coordinate_modulus)| {
            let value_offset = 2_u64
                .checked_add(u64::from(repetition_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            let value = 1 + value_offset % (coordinate_modulus - 1);
            RelationApplicationChallengeAssignment::new(challenge, repetition_ordinal, value)
        })
        .collect()
}

#[cfg(test)]
fn semantic_oracle_evaluation_points(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(Vec<ProofChallengeExtensionElement>, usize), RelationPlanError> {
    if variant.trace_domain_size == 0
        || variant.evaluation_domain_size == 0
        || !variant
            .evaluation_domain_size
            .is_multiple_of(variant.trace_domain_size)
    {
        return Err(RelationPlanError::InvalidDomain);
    }
    let evaluation_generator =
        ProofBaseFieldElement::from_canonical(context.evaluation_domain_generator)
            .map_err(|_| RelationPlanError::InvalidDomain)?;
    let trace_generator =
        evaluation_generator.power(variant.evaluation_domain_size / variant.trace_domain_size);
    let trace_domain_points = [
        independent_base_value(1)?,
        ProofChallengeExtensionElement::from_base(trace_generator),
        ProofChallengeExtensionElement::from_base(trace_generator.power(2)),
    ];
    let randomized_extension_points = [
        [17, 11, 5, 3, 2],
        [29, 31, 37, 41, 43],
        [47, 53, 59, 61, 67],
    ]
    .map(ProofChallengeExtensionElement::from_canonical_coordinates)
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| RelationPlanError::InvalidDomain)?;
    let trace_domain_case_count = trace_domain_points.len();
    Ok((
        trace_domain_points
            .into_iter()
            .chain(randomized_extension_points)
            .collect(),
        trace_domain_case_count,
    ))
}

#[cfg(test)]
fn checked_relation_compiler_interpreter_semantics_with_fault(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    fault: IndependentSemanticOracleFault,
) -> Result<RelationCompilerInterpreterSemanticCertificate, RelationPlanError> {
    let assignments = deterministic_semantic_oracle_application_challenges(variant, context)?;
    let checked_challenges = variant.checked_application_challenges(context, &assignments)?;
    let (evaluation_points, trace_domain_case_count) =
        semantic_oracle_evaluation_points(variant, context)?;
    let randomized_extension_case_count = evaluation_points
        .len()
        .checked_sub(trace_domain_case_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut structurally_checked_instruction_count = 0_usize;
    let mut covered_instruction_kinds = BTreeSet::new();
    let mut compared_program_evaluation_count = 0_usize;
    let mut injected_fault = false;

    for constraint in &variant.ordered_constraints {
        structurally_checked_instruction_count = structurally_checked_instruction_count
            .checked_add(constraint.numerator_postfix_expression.len())
            .and_then(|count| count.checked_add(constraint.zeroifier_postfix_expression.len()))
            .ok_or(RelationPlanError::CountOverflow)?;
        let independent_numerator = parse_independent_expression(
            &constraint.numerator_postfix_expression,
            false,
            &mut covered_instruction_kinds,
        )?;
        let independent_zeroifier = parse_independent_expression(
            &constraint.zeroifier_postfix_expression,
            true,
            &mut covered_instruction_kinds,
        )?;
        for (case_ordinal, evaluation_point) in evaluation_points.iter().copied().enumerate() {
            let production_numerator = evaluate_program(
                variant,
                context,
                &constraint.numerator_postfix_expression,
                evaluation_point,
                &checked_challenges,
                &mut |column_ordinal, rotation_is_negative, rotation_magnitude| {
                    deterministic_semantic_oracle_column_value(
                        case_ordinal,
                        column_ordinal,
                        rotation_is_negative,
                        rotation_magnitude,
                    )
                },
                false,
            )?;
            let mut oracle_numerator = evaluate_independent_expression(
                &independent_numerator,
                variant,
                context,
                evaluation_point,
                &checked_challenges,
                &mut |column_ordinal, rotation_is_negative, rotation_magnitude| {
                    deterministic_semantic_oracle_column_value(
                        case_ordinal,
                        column_ordinal,
                        rotation_is_negative,
                        rotation_magnitude,
                    )
                },
            )?;
            if fault == IndependentSemanticOracleFault::ChangeFirstEvaluation && !injected_fault {
                oracle_numerator = oracle_numerator.add(independent_base_value(1)?);
                injected_fault = true;
            }
            if production_numerator != oracle_numerator {
                return Err(RelationPlanError::InvalidConstraint);
            }

            let production_zeroifier = evaluate_program(
                variant,
                context,
                &constraint.zeroifier_postfix_expression,
                evaluation_point,
                &checked_challenges,
                &mut |_, _, _| Err(RelationPlanError::InvalidZeroifier),
                true,
            )?;
            let oracle_zeroifier = evaluate_independent_expression(
                &independent_zeroifier,
                variant,
                context,
                evaluation_point,
                &checked_challenges,
                &mut |_, _, _| Err(RelationPlanError::InvalidZeroifier),
            )?;
            if production_zeroifier != oracle_zeroifier {
                return Err(RelationPlanError::InvalidConstraint);
            }
            compared_program_evaluation_count = compared_program_evaluation_count
                .checked_add(2)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
    }
    let constraint_count = variant.ordered_constraints.len();
    let certificate = RelationCompilerInterpreterSemanticCertificate {
        canonical_variant_hash: variant.canonical_hash()?,
        constraint_count,
        structurally_checked_program_count: constraint_count
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?,
        structurally_checked_instruction_count,
        covered_instruction_kind_count: covered_instruction_kinds.len(),
        trace_domain_case_count,
        randomized_extension_case_count,
        compared_program_evaluation_count,
        mismatch_count: 0,
    };
    if !certificate.is_complete() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(certificate)
}

#[cfg(test)]
pub(crate) fn checked_relation_compiler_interpreter_semantics(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<RelationCompilerInterpreterSemanticCertificate, RelationPlanError> {
    checked_relation_compiler_interpreter_semantics_with_fault(
        variant,
        context,
        IndependentSemanticOracleFault::None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::relation_plan::{
        COMMITTED_MATERIAL_TRACE_PACKING_FACTOR, CommittedMaterialRelationPlanInput,
        RelationOpeningSourceClass, RelationPlanCheckContext, RelationRadixConvolutionDescriptor,
        RelationRadixProductTermDescriptor, RelationTreeDescriptor, ResolvedSuiteModulus,
        SuiteModulusReference, compile_vss_share_linkage_relation_plan,
    };
    use crate::bgv::proof_suite::{
        PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
        PROOF_CHALLENGE_EXTENSION_DEGREE, compile_same_secret_relation_plan,
        selected_ballot_validity_relation_compilation, selected_relation_plan_check_context,
        selected_same_secret_relation_plan_input,
    };
    use crate::foundation::ProofApplicationSlotCeilings;

    #[test]
    fn selected_same_secret_compiler_and_interpreter_match_independent_arithmetic_oracle() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the selected same-secret context exists");
        let compiled = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &context,
        )
        .expect("the selected same-secret relation compiles");
        let variant = compiled
            .select_variant(None, None)
            .expect("the selected same-secret variant exists");
        let certificate = checked_relation_compiler_interpreter_semantics(variant, &context)
            .expect("the independent semantic oracle matches every emitted program");
        assert!(certificate.is_complete());
        assert_eq!(certificate.constraint_count(), 4_406);
        assert_eq!(certificate.compared_program_evaluation_count(), 52_872);
        assert_eq!(
            checked_relation_compiler_interpreter_semantics_with_fault(
                variant,
                &context,
                IndependentSemanticOracleFault::ChangeFirstEvaluation,
            ),
            Err(RelationPlanError::InvalidConstraint),
        );
    }

    fn vss_linkage_interpreter_fixture() -> (RelationPlanVariant, RelationPlanCheckContext) {
        let ring_degree = 64_u64;
        let evaluation_domain_size = 1_024_u64;
        let out_of_domain_point_count = 1_u64;
        let phase_column_query_coordinate_count = 1_u64;
        let quotient_component_count = 16_u64;
        let trace_mask_degree_bound_exclusive = COMMITTED_MATERIAL_TRACE_PACKING_FACTOR
            .checked_mul(
                u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                    .expect("the challenge-extension degree fits u64"),
            )
            .and_then(|out_of_domain_coordinate_count| {
                out_of_domain_coordinate_count.checked_add(phase_column_query_coordinate_count)
            })
            .expect("the exact trace-mask degree fits u64");
        let input = CommittedMaterialRelationPlanInput {
            ring_degree,
            evaluation_domain_size,
            opening_degree_bound_exclusive: 512,
            material_column_degree_bound_exclusive: 10,
            participant_count: 3,
            threshold: 2,
            sharing_data_modulus_indices: vec![0],
            trace_mask_degree_bound_exclusive,
        };
        let rounded_mask_degree = quotient_component_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(trace_mask_degree_bound_exclusive))
            .and_then(|degree| degree.checked_add(quotient_component_count - 1))
            .and_then(|degree| degree.checked_div(quotient_component_count))
            .expect("the quotient mask degree derives");
        let quotient_decomposition_stride = input
            .relation_trace_domain_size()
            .expect("the relation trace domain derives")
            .checked_add(rounded_mask_degree)
            .expect("the quotient decomposition stride derives");
        let minimum_telescoping_mask_degree_bound_exclusive = phase_column_query_coordinate_count
            .checked_add(out_of_domain_point_count)
            .expect("the telescoping mask degree derives");
        let context = RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            out_of_domain_point_count: u16::try_from(out_of_domain_point_count)
                .expect("the out_of_domain-point count fits u16"),
            quotient_component_count: u32::try_from(quotient_component_count)
                .expect("the quotient-component count fits u32"),
            quotient_component_degree_bound_exclusive: quotient_decomposition_stride
                .checked_add(minimum_telescoping_mask_degree_bound_exclusive)
                .expect("the quotient-component degree bound derives"),
            phase_column_query_coordinate_count: u32::try_from(phase_column_query_coordinate_count)
                .expect("the phase-column query-coordinate count fits u32"),
            non_native_theta_repetition_count: 1,
            non_native_alpha_repetition_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![ResolvedSuiteModulus::new(
                SuiteModulusReference::data(0),
                97,
            )],
        };
        let compiled = compile_vss_share_linkage_relation_plan(&input, &context)
            .expect("exact VSS share-linkage plan");
        (compiled.variants()[0].clone(), context)
    }

    #[test]
    fn vss_linkage_alpha_group_uses_arithmetic_modulus_powers_of_one_sample() {
        let (variant, context) = vss_linkage_interpreter_fixture();
        let alpha_assignment = RelationApplicationChallengeAssignment::new(
            CommonProofChallenge::Alpha { modulus_ordinal: 0 },
            0,
            96,
        )
        .expect("alpha assignment");
        let challenges =
            CheckedRelationApplicationChallenges::new(&variant, &context, &[alpha_assignment])
                .expect("one alpha sample resolves the complete coefficient group");

        let weights = (0_u64..3)
            .map(|unit_ordinal| {
                challenges
                    .get_u64(RelationChallengeRole::NonNativeAlpha, &[0, 0, unit_ordinal])
                    .expect("grouped alpha power")
            })
            .collect::<Vec<_>>();
        assert_eq!(weights, vec![1, 96, 1]);
        assert_eq!(weights[2], modular_power(96, 2, 97));
        assert_ne!(weights[2], modular_power(96, 2, PROOF_BASE_FIELD_MODULUS));

        assert!(matches!(
            CheckedRelationApplicationChallenges::new(&variant, &context, &[]),
            Err(RelationPlanError::InvalidChallengeCatalog)
        ));
        assert!(matches!(
            CheckedRelationApplicationChallenges::new(
                &variant,
                &context,
                &[alpha_assignment, alpha_assignment],
            ),
            Err(RelationPlanError::InvalidChallengeCatalog)
        ));
        let out_of_range_alpha = RelationApplicationChallengeAssignment::new(
            CommonProofChallenge::Alpha { modulus_ordinal: 0 },
            0,
            97,
        )
        .expect("the unchecked alpha assignment is structurally typed");
        assert!(matches!(
            CheckedRelationApplicationChallenges::new(&variant, &context, &[out_of_range_alpha]),
            Err(RelationPlanError::InvalidChallengeCatalog)
        ));
    }

    #[test]
    fn exact_ballot_theta_accepts_the_full_base_field_range() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the selected ballot relation context derives");
        let compilation = selected_ballot_validity_relation_compilation()
            .expect("the exact ballot relation compiles");
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("the exact ballot relation has one variant");
        let schedule = variant
            .common_proof_relation_prefix_schedule(&context)
            .expect("the exact ballot relation-prefix schedule derives");
        let mut assignments = schedule
            .ordered_application_challenge_groups()
            .iter()
            .flat_map(|group| {
                (0..group.coordinate_count()).map(move |repetition_ordinal| {
                    RelationApplicationChallengeAssignment::new(
                        group.challenge(),
                        repetition_ordinal,
                        PROOF_BASE_FIELD_MODULUS - 1,
                    )
                    .expect("the full-field theta assignment is structurally typed")
                })
            })
            .collect::<Vec<_>>();
        CheckedRelationApplicationChallenges::new(variant, &context, &assignments)
            .expect("theta p - 1 is canonical even when the arithmetic modulus is 257");

        assignments[0] = RelationApplicationChallengeAssignment::new(
            assignments[0].challenge(),
            assignments[0].repetition_ordinal(),
            PROOF_BASE_FIELD_MODULUS,
        )
        .expect("the unchecked theta assignment is structurally typed");
        assert!(matches!(
            CheckedRelationApplicationChallenges::new(variant, &context, &assignments),
            Err(RelationPlanError::InvalidChallengeCatalog)
        ));
    }

    #[test]
    fn out_of_domain_sampler_requires_full_degree_disjoint_frobenius_orbits() {
        let (variant, context) = vss_linkage_interpreter_fixture();
        let base_field_candidate = ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(17).expect("canonical base-field candidate"),
        );
        assert!(
            variant
                .out_of_domain_point_candidate_is_forbidden(&context, 0, base_field_candidate, &[])
                .expect("base-field membership is decidable")
        );

        let full_degree_candidate =
            ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
                .expect("canonical extension generator");
        assert!(
            !variant
                .out_of_domain_point_candidate_is_forbidden(&context, 0, full_degree_candidate, &[])
                .expect("full-degree candidate is decidable")
        );
    }

    #[test]
    fn exact_same_secret_out_of_domain_sampler_accepts_at_least_half_the_challenge_field() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the selected same-secret relation context derives");
        let compiled = crate::bgv::proof_suite::compile_same_secret_relation_plan(
            &crate::bgv::proof_suite::selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &context,
        )
        .expect("the exact same-secret relation compiles");
        compiled
            .check(&context)
            .expect("the exact same-secret relation is checked");
        let variant = compiled
            .select_variant(None, None)
            .expect("the exact same-secret relation has one variant");
        let cardinality = variant
            .out_of_domain_point_sampler_cardinality_bound(&context, 0)
            .expect("the exact out-of-domain forbidden set has a source-derived bound");

        let field_cardinality =
            BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(PROOF_CHALLENGE_EXTENSION_DEGREE as u32);
        assert_eq!(cardinality.field_cardinality(), &field_cardinality);
        assert!(
            cardinality.forbidden_candidate_count_ceiling() * BigUint::from(2_u8)
                <= field_cardinality
        );
        assert!(
            cardinality.accepted_candidate_count_floor() * BigUint::from(2_u8) >= field_cardinality
        );
    }

    #[test]
    fn exact_same_secret_cross_multiplied_composition_degree_is_source_derived() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the selected same-secret relation context derives");
        let compiled = crate::bgv::proof_suite::compile_same_secret_relation_plan(
            &crate::bgv::proof_suite::selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &context,
        )
        .expect("the exact same-secret relation compiles");
        compiled
            .check(&context)
            .expect("the exact same-secret relation is checked");
        let variant = compiled
            .select_variant(None, None)
            .expect("the exact same-secret relation has one variant");

        assert_eq!(variant.trace_domain_size(), 16_384);
        assert_eq!(context.quotient_component_count, 8);
        assert_eq!(context.quotient_component_degree_bound_exclusive, 34_050);
        assert_eq!(variant.quotient_decomposition_stride(&context), Ok(17_266));
        let maximum_reconstructed_quotient_degree = 7 * 17_266 + (34_050 - 1);
        assert_eq!(maximum_reconstructed_quotient_degree, 154_911);

        assert_eq!(
            variant
                .cross_multiplied_composition_identity_degree_bound(&context)
                .expect("derive the exact cross-multiplied composition degree"),
            maximum_reconstructed_quotient_degree + variant.trace_domain_size()
        );
    }

    #[test]
    fn constraint_queries_include_implicit_radix_columns_with_exact_rotations() {
        let (mut variant, _) = vss_linkage_interpreter_fixture();
        assert!(variant.ordered_columns.len() >= 5);
        variant.ordered_radix_convolutions = vec![RelationRadixConvolutionDescriptor {
            radix: 4,
            ordered_terms: vec![RelationRadixProductTermDescriptor {
                negative: false,
                ordered_factors: vec![
                    RelationRadixFactorDescriptor::ColumnDigits {
                        ordered_column_ordinals: vec![2, 1, 2],
                        rotation_is_negative: true,
                        rotation_magnitude: 7,
                    },
                    RelationRadixFactorDescriptor::ScalarColumn {
                        column_ordinal: 0,
                        complement_binary_value: true,
                    },
                    RelationRadixFactorDescriptor::ColumnDigits {
                        ordered_column_ordinals: vec![3],
                        rotation_is_negative: false,
                        rotation_magnitude: 11,
                    },
                    RelationRadixFactorDescriptor::ConstantDigits {
                        ordered_digits: vec![1, 2],
                    },
                ],
            }],
        }];
        variant.ordered_constraints[0].numerator_postfix_expression = vec![
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal: 0,
                coefficient_ordinal: 1,
            },
            RelationExpressionInstruction::ColumnValue {
                column_ordinal: 1,
                rotation_is_negative: true,
                rotation_magnitude: 7,
            },
            RelationExpressionInstruction::Addition,
            RelationExpressionInstruction::ColumnValue {
                column_ordinal: 4,
                rotation_is_negative: false,
                rotation_magnitude: 0,
            },
            RelationExpressionInstruction::Addition,
        ];
        variant.ordered_constraints[0].zeroifier_postfix_expression =
            vec![RelationExpressionInstruction::BaseFieldConstant(1)];

        let queries = variant
            .constraint_column_queries(0)
            .expect("radix factors resolve to their exact column queries");
        assert_eq!(
            queries,
            vec![
                RelationConstraintColumnQuery {
                    column_ordinal: 0,
                    rotation_is_negative: false,
                    rotation_magnitude: 0,
                },
                RelationConstraintColumnQuery {
                    column_ordinal: 1,
                    rotation_is_negative: true,
                    rotation_magnitude: 7,
                },
                RelationConstraintColumnQuery {
                    column_ordinal: 2,
                    rotation_is_negative: true,
                    rotation_magnitude: 7,
                },
                RelationConstraintColumnQuery {
                    column_ordinal: 3,
                    rotation_is_negative: false,
                    rotation_magnitude: 11,
                },
                RelationConstraintColumnQuery {
                    column_ordinal: 4,
                    rotation_is_negative: false,
                    rotation_magnitude: 0,
                },
            ]
        );
    }

    #[test]
    fn out_of_domain_composition_resolves_virtual_verifier_sequences_without_opening_claims() {
        let (mut variant, context) = vss_linkage_interpreter_fixture();
        let verifier_column_ordinal = (0..variant.constraint_count())
            .flat_map(|constraint_ordinal| {
                variant
                    .constraint_column_queries(constraint_ordinal)
                    .expect("fixture constraint queries resolve")
            })
            .find_map(|query| {
                let is_materialized_prover_column = variant.ordered_trees.iter().any(|tree| {
                    tree.ordered_column_ordinals()
                        .contains(&query.column_ordinal)
                }) && variant
                    .ordered_columns
                    .get(query.column_ordinal as usize)
                    .is_some_and(|column| matches!(column.origin, RelationColumnOrigin::Prover));
                (query.rotation_magnitude != 0 && is_materialized_prover_column)
                    .then_some(query.column_ordinal)
            })
            .expect("the fixture has a rotated prover-owned relation column");
        variant.ordered_columns[verifier_column_ordinal as usize].origin =
            RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal: 0,
                first_logical_element_index: 0,
                logical_element_stride: 1,
            };
        for tree in &mut variant.ordered_trees {
            match tree {
                RelationTreeDescriptor::ProofCreated {
                    ordered_column_ordinals,
                    ..
                }
                | RelationTreeDescriptor::BoundPublic {
                    ordered_column_ordinals,
                    ..
                } => ordered_column_ordinals
                    .retain(|column_ordinal| *column_ordinal != verifier_column_ordinal),
            }
        }
        variant
            .ordered_opening_claims
            .retain(|claim| claim.column_ordinal() != Some(verifier_column_ordinal));
        assert!(variant.ordered_trees.iter().all(|tree| {
            !tree
                .ordered_column_ordinals()
                .contains(&verifier_column_ordinal)
        }));
        assert!(variant.ordered_opening_claims.iter().all(|claim| {
            claim.source_class() != RelationOpeningSourceClass::TreeColumn
                || claim.column_ordinal() != Some(verifier_column_ordinal)
        }));

        let application_challenges = [RelationApplicationChallengeAssignment::new(
            CommonProofChallenge::Alpha { modulus_ordinal: 0 },
            0,
            96,
        )
        .expect("alpha assignment")];
        let composition_challenges =
            vec![ProofChallengeExtensionElement::ONE; variant.constraint_count()];
        let out_of_domain_point =
            ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
                .expect("canonical full-degree point");
        let out_of_domain_points = [out_of_domain_point];
        let opening_points = variant
            .derive_opening_points(&context, &out_of_domain_points)
            .expect("canonical opening points");
        let verifier_constant = ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(23).expect("canonical verifier value"),
        );
        let verifier_value_at_point =
            |point: ProofChallengeExtensionElement| point.multiply(point).add(verifier_constant);
        let composed_quotient = variant
            .evaluate_composed_quotient_at_point(
                &context,
                out_of_domain_point,
                &application_challenges,
                &composition_challenges,
                |column_ordinal, rotation_is_negative, rotation_magnitude| {
                    Ok(if column_ordinal == verifier_column_ordinal {
                        let opening_point_ordinal = variant.opening_point_ordinal_for_rotation(
                            0,
                            rotation_is_negative,
                            rotation_magnitude,
                            0,
                        )?;
                        verifier_value_at_point(
                            opening_points[usize::try_from(opening_point_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?],
                        )
                    } else {
                        ProofChallengeExtensionElement::ZERO
                    })
                },
            )
            .expect("the fixture quotient evaluates");
        let out_of_domain_evaluations = variant
            .ordered_opening_claims
            .iter()
            .map(|claim| {
                if claim.source_class() == RelationOpeningSourceClass::Quotient
                    && claim.source_ordinal() == 0
                {
                    composed_quotient
                } else {
                    ProofChallengeExtensionElement::ZERO
                }
            })
            .collect::<Vec<_>>();
        let mut resolved_points = Vec::new();
        variant
            .verify_out_of_domain_composition(
                OutOfDomainCompositionVerificationInput::new(
                    &context,
                    &application_challenges,
                    &composition_challenges,
                    &out_of_domain_points,
                    &opening_points,
                    &out_of_domain_evaluations,
                ),
                |column_ordinal, point| {
                    resolved_points.push((column_ordinal, point));
                    (column_ordinal == verifier_column_ordinal)
                        .then_some(verifier_value_at_point(point))
                },
            )
            .expect("virtual verifier values complete the checked relation");
        assert!(!resolved_points.is_empty());
        assert!(resolved_points.iter().all(|(column_ordinal, point)| {
            *column_ordinal == verifier_column_ordinal && opening_points.contains(point)
        }));
        assert_eq!(
            resolved_points.len(),
            resolved_points
                .iter()
                .map(|(column_ordinal, point)| { (*column_ordinal, point.canonical_coordinates()) })
                .collect::<BTreeSet<_>>()
                .len(),
            "each fixed column and rotated point is recomputed exactly once"
        );
        assert!(
            resolved_points
                .iter()
                .any(|(_, point)| *point != out_of_domain_point),
            "a rotated query must resolve at its canonical rotated out-of-domain point"
        );
        assert!(matches!(
            variant.verify_out_of_domain_composition(
                OutOfDomainCompositionVerificationInput::new(
                    &context,
                    &application_challenges,
                    &composition_challenges,
                    &out_of_domain_points,
                    &opening_points,
                    &out_of_domain_evaluations,
                ),
                |column_ordinal, point| (column_ordinal == verifier_column_ordinal).then_some(
                    verifier_value_at_point(point).add(ProofChallengeExtensionElement::ONE),
                ),
            ),
            Err(RelationPlanError::InvalidConstraint)
        ));
        assert!(matches!(
            variant.verify_out_of_domain_composition(
                OutOfDomainCompositionVerificationInput::new(
                    &context,
                    &application_challenges,
                    &composition_challenges,
                    &out_of_domain_points,
                    &opening_points,
                    &out_of_domain_evaluations,
                ),
                |_, _| None,
            ),
            Err(RelationPlanError::InvalidOpening)
        ));
    }
}
