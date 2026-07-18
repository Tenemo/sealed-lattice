//! Deterministic application extraction for checked relation plans.
//!
//! The upstream round-by-round commitment and low-degree extractor is assumed
//! to return, for every transcript tree in canonical order, the unique
//! degree-bounded polynomial tuple bound to that tree root, except for its
//! quantified extraction error. This module establishes the remaining
//! deterministic implication. For a checked generated plan, it recovers the
//! first-oracle semantic columns, uniquely lifts their trace residues into the
//! claimed integer intervals, rebuilds every later-oracle column from the
//! checked descriptors, evaluates every constraint program on its operative
//! trace roots, and checks the unbatched integer identities.
//!
//! Consequently, if this extraction succeeds, the returned semantic values
//! satisfy the generated application relation. A transcript accepted without
//! such a witness must therefore fall within the upstream commitment or
//! low-degree extraction error, or within the explicitly analyzed
//! challenge-dependent application error. The deterministic checks here add
//! no further acceptance event.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use zeroize::Zeroizing;

use crate::foundation::Hash512;

use super::super::prover::{
    CommonProofAuxiliaryColumnSynthesisCursor, CommonProofSourcePolynomial, base_trace_rows,
    integer_lift_derived_columns,
};
use super::super::{
    CommonProofProverError, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofEvaluationDomain, ProofPolynomialError, ProofProfileSet, ProofTreeRole,
    RelationRootConstructionKind, RelationRootEndpoint,
};
use super::{
    CompiledRelationPlan, RelationApplicationChallengeAssignment, RelationColumnOrigin,
    RelationColumnValueType, RelationIntegerLiftCoefficient, RelationIntegerLiftConvolutionKind,
    RelationIntegerLiftFullRingHalf, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, RelationTreeDescriptor, SignedIntegerInterval,
    resolved_modulus_radix_digit,
};

type ApplicationRoot = [u8; Hash512::BYTE_LENGTH];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApplicationExtractionError {
    Relation(RelationPlanError),
    Prover(CommonProofProverError),
    Polynomial(ProofPolynomialError),
    TreeCatalogMismatch,
    ColumnCatalogMismatch,
    CanonicalVerifierSequenceMismatch,
    CanonicalRootMismatch,
    ConstraintViolation,
    CoefficientLocalIdentityViolation,
    ReversedColumnMismatch,
    AuxiliaryColumnMismatch,
    NegacyclicAutomorphismMismatch,
    IntegerLiftIdentityViolation,
    SemanticLiftNotUnique,
    RootBindingMismatch,
    RootJoinMismatch,
    CountOverflow,
}

impl From<RelationPlanError> for ApplicationExtractionError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofProverError> for ApplicationExtractionError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<ProofPolynomialError> for ApplicationExtractionError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

/// One root-bound tuple returned by the upstream polynomial extractor. The
/// tuple order is the exact tree-column order fixed by the checked plan.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExtractedLowDegreeApplicationTree {
    root: ApplicationRoot,
    ordered_column_polynomials: Vec<CommonProofSourcePolynomial>,
}

impl ExtractedLowDegreeApplicationTree {
    pub(crate) fn new(
        root: ApplicationRoot,
        ordered_column_polynomials: Vec<CommonProofSourcePolynomial>,
    ) -> Self {
        Self {
            root,
            ordered_column_polynomials,
        }
    }
}

/// Canonical public material is supplied independently of the extracted
/// tuples. This prevents a low-degree tuple from choosing its own verifier
/// sequence or statement-owned root.
pub(crate) struct ApplicationExtractionInput {
    ordered_trees: Vec<ExtractedLowDegreeApplicationTree>,
    canonical_verifier_sequence_polynomials_by_column: BTreeMap<u32, CommonProofSourcePolynomial>,
    canonical_bound_roots_by_verifier_source: BTreeMap<u32, ApplicationRoot>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
}

impl ApplicationExtractionInput {
    pub(crate) fn new(
        ordered_trees: Vec<ExtractedLowDegreeApplicationTree>,
        canonical_verifier_sequence_polynomials_by_column: BTreeMap<
            u32,
            CommonProofSourcePolynomial,
        >,
        canonical_bound_roots_by_verifier_source: BTreeMap<u32, ApplicationRoot>,
        application_challenges: Vec<RelationApplicationChallengeAssignment>,
    ) -> Self {
        Self {
            ordered_trees,
            canonical_verifier_sequence_polynomials_by_column,
            canonical_bound_roots_by_verifier_source,
            application_challenges,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExtractedSemanticColumn {
    semantic_cell_ordinal: u32,
    column_ordinal: u32,
    trace_values: Zeroizing<Vec<i128>>,
}

impl ExtractedSemanticColumn {
    pub(crate) const fn semantic_cell_ordinal(&self) -> u32 {
        self.semantic_cell_ordinal
    }

    pub(crate) const fn column_ordinal(&self) -> u32 {
        self.column_ordinal
    }

    pub(crate) fn trace_values(&self) -> &[i128] {
        &self.trace_values
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExtractedApplicationWitness {
    application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    producer_sequence: Option<u64>,
    semantic_columns: Vec<ExtractedSemanticColumn>,
    bound_roots_by_verifier_source: BTreeMap<u32, ApplicationRoot>,
}

impl ExtractedApplicationWitness {
    pub(crate) fn semantic_columns(&self) -> &[ExtractedSemanticColumn] {
        &self.semantic_columns
    }

    pub(crate) fn bind_root_endpoint(
        &self,
        endpoint: RelationRootEndpoint,
    ) -> Result<ApplicationRootBinding, ApplicationExtractionError> {
        if endpoint.application_statement_schema_identifier()
            != self.application_statement_schema_identifier
            || endpoint.roster_position() != self.roster_position
            || endpoint.schedule_position() != self.schedule_position
            || endpoint.top_count() != self.top_count
            || endpoint.producer_sequence() != self.producer_sequence
        {
            return Err(ApplicationExtractionError::RootBindingMismatch);
        }
        let root = self
            .bound_roots_by_verifier_source
            .get(&endpoint.verifier_source_ordinal())
            .copied()
            .ok_or(ApplicationExtractionError::RootBindingMismatch)?;
        Ok(ApplicationRootBinding { endpoint, root })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationRootBinding {
    endpoint: RelationRootEndpoint,
    root: ApplicationRoot,
}

impl ApplicationRootBinding {
    pub(crate) const fn endpoint(self) -> RelationRootEndpoint {
        self.endpoint
    }

    pub(crate) const fn root(self) -> ApplicationRoot {
        self.root
    }
}

/// A checked, non-serialized application map. Construction rechecks the full
/// compiled plan, including expression grammar, integer bounds, no-wrap
/// bounds, tree ownership, masks, openings, and root-source typing.
#[derive(Clone, Debug)]
pub(crate) struct CheckedApplicationExtractionPlan {
    application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    producer_sequence: Option<u64>,
    variant: RelationPlanVariant,
    context: RelationPlanCheckContext,
    semantic_role_one_columns: BTreeSet<u32>,
    derived_role_one_columns_by_source: BTreeMap<u32, u32>,
    role_two_columns: BTreeSet<u32>,
}

impl CheckedApplicationExtractionPlan {
    pub(crate) fn new(
        compiled_plan: &CompiledRelationPlan,
        roster_position: Option<u16>,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        producer_sequence: Option<u64>,
        context: &RelationPlanCheckContext,
    ) -> Result<Self, ApplicationExtractionError> {
        compiled_plan.check(context)?;
        let variant = compiled_plan
            .select_variant(schedule_position, top_count)?
            .clone();
        let application_statement_schema_identifier =
            compiled_plan.application_statement_schema_identifier();
        let (derived_role_one_columns_by_source, role_two_columns) =
            integer_lift_derived_columns(&variant)?;
        let tree_roles = super::super::prover::proof_created_tree_roles_by_column(&variant)?;
        let semantic_role_one_columns = variant
            .ordered_semantic_cells
            .iter()
            .filter_map(|cell| {
                variant
                    .ordered_columns
                    .get(cell.column_ordinal as usize)
                    .is_some_and(|column| matches!(column.origin, RelationColumnOrigin::Prover))
                    .then_some(cell.column_ordinal)
            })
            .collect::<BTreeSet<_>>();
        if semantic_role_one_columns.iter().any(|column_ordinal| {
            tree_roles.get(column_ordinal) != Some(&ProofTreeRole::BaseOracle)
        }) || derived_role_one_columns_by_source
            .values()
            .any(|column_ordinal| {
                tree_roles.get(column_ordinal) != Some(&ProofTreeRole::BaseOracle)
            })
            || role_two_columns.iter().any(|column_ordinal| {
                tree_roles.get(column_ordinal) != Some(&ProofTreeRole::AuxiliaryOracle)
            })
        {
            return Err(ApplicationExtractionError::ColumnCatalogMismatch);
        }
        Ok(Self {
            application_statement_schema_identifier,
            roster_position,
            producer_sequence,
            variant,
            context: context.clone(),
            semantic_role_one_columns,
            derived_role_one_columns_by_source,
            role_two_columns,
        })
    }

    pub(crate) fn semantic_role_one_columns(&self) -> &BTreeSet<u32> {
        &self.semantic_role_one_columns
    }

    pub(super) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(super) const fn variant(&self) -> &RelationPlanVariant {
        &self.variant
    }

    pub(super) const fn context(&self) -> &RelationPlanCheckContext {
        &self.context
    }

    pub(crate) fn derived_role_one_columns_by_source(&self) -> &BTreeMap<u32, u32> {
        &self.derived_role_one_columns_by_source
    }

    pub(crate) fn role_two_columns(&self) -> &BTreeSet<u32> {
        &self.role_two_columns
    }

    pub(crate) fn extract(
        &self,
        input: ApplicationExtractionInput,
    ) -> Result<ExtractedApplicationWitness, ApplicationExtractionError> {
        let application_challenges = input.application_challenges.clone();
        let checked_challenges = self
            .variant
            .checked_application_challenges(&self.context, &application_challenges)?;
        let (trace_columns, bound_roots_by_verifier_source) = self.recover_trace_columns(input)?;
        self.check_reversed_columns(&trace_columns)?;
        self.check_auxiliary_columns(&trace_columns, &application_challenges)?;
        self.check_trace_constraints(&trace_columns, &checked_challenges)?;
        self.check_coefficient_local_identities(&trace_columns, &checked_challenges)?;
        self.check_negacyclic_automorphisms(&trace_columns)?;
        self.check_integer_lift_identities(&trace_columns)?;
        let semantic_columns = self.recover_semantic_columns(&trace_columns)?;
        Ok(ExtractedApplicationWitness {
            application_statement_schema_identifier: self.application_statement_schema_identifier,
            roster_position: self.roster_position,
            schedule_position: self.variant.schedule_position(),
            top_count: self.variant.top_count(),
            producer_sequence: self.producer_sequence,
            semantic_columns,
            bound_roots_by_verifier_source,
        })
    }

    fn recover_trace_columns(
        &self,
        input: ApplicationExtractionInput,
    ) -> Result<
        (Vec<ExtractedTraceColumn>, BTreeMap<u32, ApplicationRoot>),
        ApplicationExtractionError,
    > {
        let ApplicationExtractionInput {
            ordered_trees,
            mut canonical_verifier_sequence_polynomials_by_column,
            canonical_bound_roots_by_verifier_source,
            application_challenges: _,
        } = input;
        if ordered_trees.len() != self.variant.ordered_trees.len() {
            return Err(ApplicationExtractionError::TreeCatalogMismatch);
        }
        let mut polynomials_by_column = std::iter::repeat_with(|| None)
            .take(self.variant.ordered_columns.len())
            .collect::<Vec<Option<CommonProofSourcePolynomial>>>();
        let mut observed_bound_root_sources = BTreeSet::new();
        for (tree_descriptor, extracted_tree) in
            self.variant.ordered_trees.iter().zip(ordered_trees)
        {
            let column_ordinals = tree_descriptor.ordered_column_ordinals();
            if extracted_tree.ordered_column_polynomials.len() != column_ordinals.len() {
                return Err(ApplicationExtractionError::TreeCatalogMismatch);
            }
            if let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                ..
            } = tree_descriptor
            {
                let canonical_root = canonical_bound_roots_by_verifier_source
                    .get(expected_root_source_ordinal)
                    .ok_or(ApplicationExtractionError::CanonicalRootMismatch)?;
                if canonical_root != &extracted_tree.root {
                    return Err(ApplicationExtractionError::CanonicalRootMismatch);
                }
                observed_bound_root_sources.insert(*expected_root_source_ordinal);
            }
            for (column_ordinal, polynomial) in column_ordinals
                .iter()
                .copied()
                .zip(extracted_tree.ordered_column_polynomials)
            {
                let column_index = usize::try_from(column_ordinal)
                    .map_err(|_| ApplicationExtractionError::CountOverflow)?;
                let descriptor = self
                    .variant
                    .ordered_columns
                    .get(column_index)
                    .ok_or(ApplicationExtractionError::ColumnCatalogMismatch)?;
                validate_extracted_polynomial(
                    descriptor.value_type(),
                    descriptor.source_degree_bound_exclusive(),
                    &polynomial,
                )?;
                if matches!(
                    descriptor.origin(),
                    RelationColumnOrigin::VerifierSequence { .. }
                ) {
                    let canonical = canonical_verifier_sequence_polynomials_by_column
                        .remove(&column_ordinal)
                        .ok_or(ApplicationExtractionError::CanonicalVerifierSequenceMismatch)?;
                    if !same_source_polynomial(&polynomial, &canonical) {
                        return Err(ApplicationExtractionError::CanonicalVerifierSequenceMismatch);
                    }
                }
                let destination = polynomials_by_column
                    .get_mut(column_index)
                    .ok_or(ApplicationExtractionError::ColumnCatalogMismatch)?;
                if destination.replace(polynomial).is_some() {
                    return Err(ApplicationExtractionError::ColumnCatalogMismatch);
                }
            }
        }
        if polynomials_by_column.iter().any(Option::is_none)
            || !canonical_verifier_sequence_polynomials_by_column.is_empty()
            || observed_bound_root_sources
                != canonical_bound_roots_by_verifier_source
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
        {
            return Err(ApplicationExtractionError::ColumnCatalogMismatch);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(self.variant.trace_domain_size())
                .map_err(|_| ApplicationExtractionError::CountOverflow)?,
        )?;
        let trace_columns = polynomials_by_column
            .into_iter()
            .map(|polynomial| {
                trace_column_rows(
                    &polynomial.ok_or(ApplicationExtractionError::ColumnCatalogMismatch)?,
                    trace_domain,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((trace_columns, canonical_bound_roots_by_verifier_source))
    }

    fn check_reversed_columns(
        &self,
        trace_columns: &[ExtractedTraceColumn],
    ) -> Result<(), ApplicationExtractionError> {
        for (source_column_ordinal, reversed_column_ordinal) in
            &self.derived_role_one_columns_by_source
        {
            let source_rows = base_rows(trace_columns, *source_column_ordinal)?;
            let reversed_rows = base_rows(trace_columns, *reversed_column_ordinal)?;
            if source_rows.len() != reversed_rows.len()
                || source_rows
                    .iter()
                    .rev()
                    .copied()
                    .ne(reversed_rows.iter().copied())
            {
                return Err(ApplicationExtractionError::ReversedColumnMismatch);
            }
        }
        Ok(())
    }

    fn check_auxiliary_columns(
        &self,
        trace_columns: &[ExtractedTraceColumn],
        application_challenges: &[RelationApplicationChallengeAssignment],
    ) -> Result<(), ApplicationExtractionError> {
        let mut cursor = CommonProofAuxiliaryColumnSynthesisCursor::new(
            &self.variant,
            &self.context,
            application_challenges,
        )?;
        while !cursor.is_complete() {
            if let Some(column_ordinal) = cursor.next_input_column_ordinal() {
                cursor.accept_input_trace_rows(
                    column_ordinal,
                    base_rows(trace_columns, column_ordinal)?,
                )?;
                continue;
            }
            if let Some(column_ordinal) = cursor.pending_output_column_ordinal() {
                cursor
                    .compare_next_unmasked_output(
                        column_ordinal,
                        base_rows(trace_columns, column_ordinal)?,
                    )
                    .map_err(|_| ApplicationExtractionError::AuxiliaryColumnMismatch)?;
                continue;
            }
            if !cursor.advance_ready_task()? {
                return Err(ApplicationExtractionError::AuxiliaryColumnMismatch);
            }
        }
        Ok(())
    }

    fn check_trace_constraints(
        &self,
        trace_columns: &[ExtractedTraceColumn],
        checked_challenges: &super::CheckedRelationApplicationChallenges,
    ) -> Result<(), ApplicationExtractionError> {
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(self.variant.trace_domain_size())
                .map_err(|_| ApplicationExtractionError::CountOverflow)?,
        )?;
        for row_ordinal in 0..trace_domain.size() {
            let evaluation_point =
                ProofChallengeExtensionElement::from_base(trace_domain.point(row_ordinal)?);
            for constraint_ordinal in 0..self.variant.constraint_count() {
                let mut column_value =
                    |column_ordinal, rotation_is_negative, rotation_magnitude| {
                        trace_column_value(
                            trace_columns,
                            column_ordinal,
                            rotated_trace_row(
                                row_ordinal,
                                trace_domain.size(),
                                rotation_is_negative,
                                rotation_magnitude,
                            )?,
                        )
                    };
                let evaluation = self.variant.evaluate_constraint_programs_at_point(
                    &self.context,
                    constraint_ordinal,
                    evaluation_point,
                    checked_challenges,
                    &mut column_value,
                )?;
                if evaluation.zeroifier.is_zero() && !evaluation.numerator.is_zero() {
                    return Err(ApplicationExtractionError::ConstraintViolation);
                }
            }
        }
        Ok(())
    }

    fn check_coefficient_local_identities(
        &self,
        trace_columns: &[ExtractedTraceColumn],
        checked_challenges: &super::CheckedRelationApplicationChallenges,
    ) -> Result<(), ApplicationExtractionError> {
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(self.variant.trace_domain_size())
                .map_err(|_| ApplicationExtractionError::CountOverflow)?,
        )?;
        for batch in &self.variant.ordered_coefficient_local_identity_batches {
            let constraint_ordinal = usize::try_from(batch.constraint_ordinal)
                .map_err(|_| ApplicationExtractionError::CountOverflow)?;
            for row_ordinal in 0..trace_domain.size() {
                let evaluation_point =
                    ProofChallengeExtensionElement::from_base(trace_domain.point(row_ordinal)?);
                let mut column_value =
                    |column_ordinal, rotation_is_negative, rotation_magnitude| {
                        trace_column_value(
                            trace_columns,
                            column_ordinal,
                            rotated_trace_row(
                                row_ordinal,
                                trace_domain.size(),
                                rotation_is_negative,
                                rotation_magnitude,
                            )?,
                        )
                    };
                let constraint_evaluation = self.variant.evaluate_constraint_programs_at_point(
                    &self.context,
                    constraint_ordinal,
                    evaluation_point,
                    checked_challenges,
                    &mut column_value,
                )?;
                if !constraint_evaluation.zeroifier.is_zero() {
                    continue;
                }
                for residual in &batch.ordered_residuals {
                    let value = self.variant.evaluate_expression_program_at_point(
                        &self.context,
                        &residual.residual_postfix_expression,
                        evaluation_point,
                        checked_challenges,
                        &mut column_value,
                    )?;
                    if !value.is_zero() {
                        return Err(ApplicationExtractionError::CoefficientLocalIdentityViolation);
                    }
                }
            }
        }
        Ok(())
    }

    fn check_negacyclic_automorphisms(
        &self,
        trace_columns: &[ExtractedTraceColumn],
    ) -> Result<(), ApplicationExtractionError> {
        for batch in &self.variant.ordered_integer_lift_batches {
            for descriptor in &batch.ordered_negacyclic_automorphism_permutations {
                let source_low = base_rows(trace_columns, descriptor.source_low_column_ordinal)?;
                let source_high = base_rows(trace_columns, descriptor.source_high_column_ordinal)?;
                let target_low = base_rows(trace_columns, descriptor.target_low_column_ordinal)?;
                let target_high = base_rows(trace_columns, descriptor.target_high_column_ordinal)?;
                if !negacyclic_automorphism_rows_match(
                    source_low,
                    source_high,
                    target_low,
                    target_high,
                    descriptor.galois_element,
                )? {
                    return Err(ApplicationExtractionError::NegacyclicAutomorphismMismatch);
                }
            }
        }
        Ok(())
    }

    fn check_integer_lift_identities(
        &self,
        trace_columns: &[ExtractedTraceColumn],
    ) -> Result<(), ApplicationExtractionError> {
        let source_by_reversed_column = self
            .derived_role_one_columns_by_source
            .iter()
            .map(|(source, reversed)| (*reversed, *source))
            .collect::<BTreeMap<_, _>>();
        for batch in &self.variant.ordered_integer_lift_batches {
            for component in &batch.ordered_components {
                let mut residual = vec![
                    ProofBaseFieldElement::ZERO;
                    usize::try_from(self.variant.trace_domain_size()).map_err(
                        |_| ApplicationExtractionError::CountOverflow
                    )?
                ];
                for term in &component.ordered_linear_terms {
                    let coefficient =
                        integer_lift_coefficient_field_value(&self.context, term.coefficient)?;
                    let offset = ProofBaseFieldElement::from_canonical(term.column_offset)
                        .map_err(|_| ApplicationExtractionError::IntegerLiftIdentityViolation)?;
                    for (destination, value) in residual
                        .iter_mut()
                        .zip(base_rows(trace_columns, term.column_ordinal)?)
                    {
                        let term_value = value.subtract(offset).multiply(coefficient);
                        *destination = destination.add(if term.negative {
                            term_value.negate()
                        } else {
                            term_value
                        });
                    }
                }
                for product in &component.ordered_convolution_products {
                    let multiplier_source = source_by_reversed_column
                        .get(&product.reversed_multiplier_column_ordinal)
                        .copied()
                        .ok_or(ApplicationExtractionError::IntegerLiftIdentityViolation)?;
                    let offset = ProofBaseFieldElement::from_canonical(product.multiplier_offset)
                        .map_err(|_| {
                        ApplicationExtractionError::IntegerLiftIdentityViolation
                    })?;
                    let multiplier = base_rows(trace_columns, multiplier_source)?
                        .iter()
                        .map(|value| value.subtract(offset))
                        .collect::<Vec<_>>();
                    let product_rows = selected_convolution(
                        product.convolution_kind,
                        base_rows(trace_columns, product.multiplicand_column_ordinal)?,
                        &multiplier,
                    )?;
                    add_signed_rows(&mut residual, &product_rows, product.negative)?;
                }
                for product in &component.ordered_full_ring_negacyclic_products {
                    let low_offset =
                        ProofBaseFieldElement::from_canonical(product.multiplier_low_offset)
                            .map_err(|_| {
                                ApplicationExtractionError::IntegerLiftIdentityViolation
                            })?;
                    let high_offset =
                        ProofBaseFieldElement::from_canonical(product.multiplier_high_offset)
                            .map_err(|_| {
                                ApplicationExtractionError::IntegerLiftIdentityViolation
                            })?;
                    let multiplier_low =
                        base_rows(trace_columns, product.multiplier_low_column_ordinal)?
                            .iter()
                            .map(|value| value.subtract(low_offset))
                            .collect::<Vec<_>>();
                    let multiplier_high =
                        base_rows(trace_columns, product.multiplier_high_column_ordinal)?
                            .iter()
                            .map(|value| value.subtract(high_offset))
                            .collect::<Vec<_>>();
                    let product_rows = selected_full_ring_negacyclic_convolution(
                        product.selected_half,
                        base_rows(trace_columns, product.multiplicand_low_column_ordinal)?,
                        base_rows(trace_columns, product.multiplicand_high_column_ordinal)?,
                        &multiplier_low,
                        &multiplier_high,
                    )?;
                    add_signed_rows(&mut residual, &product_rows, product.negative)?;
                }
                if residual
                    .iter()
                    .any(|value| *value != ProofBaseFieldElement::ZERO)
                {
                    // The plan checker proves the complete integer residual
                    // interval lies strictly between -p and p. A zero field
                    // residue is therefore equivalent to an exact zero
                    // integer residual, with no modular alias.
                    return Err(ApplicationExtractionError::IntegerLiftIdentityViolation);
                }
            }
        }
        Ok(())
    }

    fn recover_semantic_columns(
        &self,
        trace_columns: &[ExtractedTraceColumn],
    ) -> Result<Vec<ExtractedSemanticColumn>, ApplicationExtractionError> {
        let mut witness_columns = Vec::new();
        for cell in &self.variant.ordered_semantic_cells {
            let rows = base_rows(trace_columns, cell.column_ordinal)?;
            let trace_values = rows
                .iter()
                .map(|value| {
                    unique_integer_lift(
                        value.canonical(),
                        self.context.base_field_modulus,
                        &cell.claimed_interval,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let origin = self
                .variant
                .ordered_columns
                .get(
                    usize::try_from(cell.column_ordinal)
                        .map_err(|_| ApplicationExtractionError::CountOverflow)?,
                )
                .ok_or(ApplicationExtractionError::ColumnCatalogMismatch)?
                .origin();
            if matches!(origin, RelationColumnOrigin::Prover) {
                witness_columns.push(ExtractedSemanticColumn {
                    semantic_cell_ordinal: cell.semantic_cell_ordinal,
                    column_ordinal: cell.column_ordinal,
                    trace_values: Zeroizing::new(trace_values),
                });
            }
        }
        Ok(witness_columns)
    }
}

fn negacyclic_automorphism_rows_match(
    source_low: &[ProofBaseFieldElement],
    source_high: &[ProofBaseFieldElement],
    target_low: &[ProofBaseFieldElement],
    target_high: &[ProofBaseFieldElement],
    galois_element: u64,
) -> Result<bool, ApplicationExtractionError> {
    let ring_degree = source_low
        .len()
        .checked_add(source_high.len())
        .ok_or(ApplicationExtractionError::CountOverflow)?;
    if source_low.len() != source_high.len()
        || target_low.len() != source_low.len()
        || target_high.len() != source_high.len()
        || ring_degree == 0
    {
        return Ok(false);
    }
    let ring_degree_u128 =
        u128::try_from(ring_degree).map_err(|_| ApplicationExtractionError::CountOverflow)?;
    let automorphism_modulus = ring_degree_u128
        .checked_mul(2)
        .ok_or(ApplicationExtractionError::CountOverflow)?;
    let mut expected = vec![ProofBaseFieldElement::ZERO; ring_degree];
    for (source_position, value) in source_low.iter().chain(source_high).copied().enumerate() {
        let mapped_exponent = u128::from(galois_element)
            .checked_mul(
                u128::try_from(source_position)
                    .map_err(|_| ApplicationExtractionError::CountOverflow)?,
            )
            .ok_or(ApplicationExtractionError::CountOverflow)?
            % automorphism_modulus;
        let mapped_position = usize::try_from(mapped_exponent % ring_degree_u128)
            .map_err(|_| ApplicationExtractionError::CountOverflow)?;
        expected[mapped_position] = if mapped_exponent >= ring_degree_u128 {
            value.negate()
        } else {
            value
        };
    }
    Ok(expected[..source_low.len()] == target_low[..]
        && expected[source_low.len()..] == target_high[..])
}

enum ExtractedTraceColumn {
    Base(Zeroizing<Vec<ProofBaseFieldElement>>),
    Extension(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

fn validate_extracted_polynomial(
    expected_value_type: RelationColumnValueType,
    degree_bound_exclusive: u64,
    polynomial: &CommonProofSourcePolynomial,
) -> Result<(), ApplicationExtractionError> {
    if polynomial.value_type() != expected_value_type
        || polynomial.coefficient_count() == 0
        || polynomial.coefficient_count()
            > usize::try_from(degree_bound_exclusive)
                .map_err(|_| ApplicationExtractionError::CountOverflow)?
    {
        return Err(ApplicationExtractionError::ColumnCatalogMismatch);
    }
    Ok(())
}

fn trace_column_rows(
    polynomial: &CommonProofSourcePolynomial,
    trace_domain: ProofEvaluationDomain,
) -> Result<ExtractedTraceColumn, ApplicationExtractionError> {
    match polynomial {
        CommonProofSourcePolynomial::Base(_) => Ok(ExtractedTraceColumn::Base(base_trace_rows(
            polynomial,
            trace_domain,
        )?)),
        CommonProofSourcePolynomial::Extension(coefficients) => {
            let mut reduced = Zeroizing::new(vec![
                ProofChallengeExtensionElement::ZERO;
                trace_domain.size()
            ]);
            for (coefficient_ordinal, coefficient) in coefficients.iter().copied().enumerate() {
                let reduced_ordinal = coefficient_ordinal % trace_domain.size();
                reduced[reduced_ordinal] = reduced[reduced_ordinal].add(coefficient);
            }
            Ok(ExtractedTraceColumn::Extension(Zeroizing::new(
                trace_domain.evaluate_extension_polynomial(&reduced)?,
            )))
        }
    }
}

fn base_rows(
    trace_columns: &[ExtractedTraceColumn],
    column_ordinal: u32,
) -> Result<&[ProofBaseFieldElement], ApplicationExtractionError> {
    match trace_columns.get(
        usize::try_from(column_ordinal).map_err(|_| ApplicationExtractionError::CountOverflow)?,
    ) {
        Some(ExtractedTraceColumn::Base(rows)) => Ok(rows),
        _ => Err(ApplicationExtractionError::ColumnCatalogMismatch),
    }
}

fn trace_column_value(
    trace_columns: &[ExtractedTraceColumn],
    column_ordinal: u32,
    row_ordinal: usize,
) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
    match trace_columns
        .get(usize::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
    {
        Some(ExtractedTraceColumn::Base(rows)) => rows
            .get(row_ordinal)
            .copied()
            .map(ProofChallengeExtensionElement::from_base)
            .ok_or(RelationPlanError::InvalidColumn),
        Some(ExtractedTraceColumn::Extension(rows)) => rows
            .get(row_ordinal)
            .copied()
            .ok_or(RelationPlanError::InvalidColumn),
        None => Err(RelationPlanError::InvalidColumn),
    }
}

fn rotated_trace_row(
    row_ordinal: usize,
    trace_size: usize,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Result<usize, RelationPlanError> {
    let reduced_rotation = usize::try_from(
        rotation_magnitude
            % u64::try_from(trace_size).map_err(|_| RelationPlanError::CountOverflow)?,
    )
    .map_err(|_| RelationPlanError::CountOverflow)?;
    if rotation_is_negative {
        row_ordinal
            .checked_add(trace_size)
            .and_then(|value| value.checked_sub(reduced_rotation))
            .map(|value| value % trace_size)
            .ok_or(RelationPlanError::CountOverflow)
    } else {
        row_ordinal
            .checked_add(reduced_rotation)
            .map(|value| value % trace_size)
            .ok_or(RelationPlanError::CountOverflow)
    }
}

fn same_source_polynomial(
    left: &CommonProofSourcePolynomial,
    right: &CommonProofSourcePolynomial,
) -> bool {
    match (left, right) {
        (CommonProofSourcePolynomial::Base(left), CommonProofSourcePolynomial::Base(right)) => {
            trimmed_base_coefficients(left) == trimmed_base_coefficients(right)
        }
        (
            CommonProofSourcePolynomial::Extension(left),
            CommonProofSourcePolynomial::Extension(right),
        ) => trimmed_extension_coefficients(left) == trimmed_extension_coefficients(right),
        _ => false,
    }
}

fn trimmed_base_coefficients(values: &[ProofBaseFieldElement]) -> &[ProofBaseFieldElement] {
    let length = values
        .iter()
        .rposition(|value| *value != ProofBaseFieldElement::ZERO)
        .map_or(0, |index| index + 1);
    &values[..length]
}

fn trimmed_extension_coefficients(
    values: &[ProofChallengeExtensionElement],
) -> &[ProofChallengeExtensionElement] {
    let length = values
        .iter()
        .rposition(|value| !value.is_zero())
        .map_or(0, |index| index + 1);
    &values[..length]
}

fn unique_integer_lift(
    residue: u64,
    modulus: u64,
    interval: &SignedIntegerInterval,
) -> Result<i128, ApplicationExtractionError> {
    if residue >= modulus || modulus == 0 {
        return Err(ApplicationExtractionError::SemanticLiftNotUnique);
    }
    let modulus = BigInt::from(modulus);
    let residue = BigInt::from(residue);
    let minimum_shift = ceil_divide(&(&interval.minimum - &residue), &modulus);
    let maximum_shift = floor_divide(&(&interval.maximum - &residue), &modulus);
    if minimum_shift != maximum_shift {
        return Err(ApplicationExtractionError::SemanticLiftNotUnique);
    }
    (&residue + minimum_shift * modulus)
        .to_i128()
        .ok_or(ApplicationExtractionError::SemanticLiftNotUnique)
}

fn floor_divide(numerator: &BigInt, positive_denominator: &BigInt) -> BigInt {
    let quotient = numerator / positive_denominator;
    let remainder = numerator % positive_denominator;
    if numerator < &BigInt::zero() && !remainder.is_zero() {
        quotient - 1
    } else {
        quotient
    }
}

fn ceil_divide(numerator: &BigInt, positive_denominator: &BigInt) -> BigInt {
    let quotient = numerator / positive_denominator;
    let remainder = numerator % positive_denominator;
    if numerator > &BigInt::zero() && !remainder.is_zero() {
        quotient + 1
    } else {
        quotient
    }
}

fn integer_lift_coefficient_field_value(
    context: &RelationPlanCheckContext,
    coefficient: RelationIntegerLiftCoefficient,
) -> Result<ProofBaseFieldElement, ApplicationExtractionError> {
    let value = match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => value,
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => context
            .resolved_modulus(modulus_reference)?
            .checked_mul(u64::from(multiplier))
            .ok_or(ApplicationExtractionError::CountOverflow)?,
        RelationIntegerLiftCoefficient::ModulusRadixDigit {
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
        } => resolved_modulus_radix_digit(
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
            context,
        )?,
    };
    ProofBaseFieldElement::from_canonical(value)
        .map_err(|_| ApplicationExtractionError::IntegerLiftIdentityViolation)
}

fn selected_convolution(
    kind: RelationIntegerLiftConvolutionKind,
    multiplicand: &[ProofBaseFieldElement],
    multiplier: &[ProofBaseFieldElement],
) -> Result<Vec<ProofBaseFieldElement>, ApplicationExtractionError> {
    if multiplicand.is_empty() || multiplicand.len() != multiplier.len() {
        return Err(ApplicationExtractionError::IntegerLiftIdentityViolation);
    }
    let coefficient_count = multiplicand.len();
    let ordinary = ordinary_convolution(multiplicand, multiplier)?;
    Ok(match kind {
        RelationIntegerLiftConvolutionKind::Negacyclic => (0..coefficient_count)
            .map(|index| ordinary[index].subtract(ordinary[index + coefficient_count]))
            .collect(),
        RelationIntegerLiftConvolutionKind::OrdinaryLowHalf => {
            ordinary[..coefficient_count].to_vec()
        }
        RelationIntegerLiftConvolutionKind::OrdinaryHighHalf => {
            ordinary[coefficient_count..].to_vec()
        }
    })
}

fn selected_full_ring_negacyclic_convolution(
    selected_half: RelationIntegerLiftFullRingHalf,
    multiplicand_low: &[ProofBaseFieldElement],
    multiplicand_high: &[ProofBaseFieldElement],
    multiplier_low: &[ProofBaseFieldElement],
    multiplier_high: &[ProofBaseFieldElement],
) -> Result<Vec<ProofBaseFieldElement>, ApplicationExtractionError> {
    let half_size = multiplicand_low.len();
    if half_size == 0
        || multiplicand_high.len() != half_size
        || multiplier_low.len() != half_size
        || multiplier_high.len() != half_size
    {
        return Err(ApplicationExtractionError::IntegerLiftIdentityViolation);
    }
    let multiplicand = multiplicand_low
        .iter()
        .chain(multiplicand_high)
        .copied()
        .collect::<Vec<_>>();
    let multiplier = multiplier_low
        .iter()
        .chain(multiplier_high)
        .copied()
        .collect::<Vec<_>>();
    let ordinary = ordinary_convolution(&multiplicand, &multiplier)?;
    let ring_size = multiplicand.len();
    let negacyclic = (0..ring_size)
        .map(|index| ordinary[index].subtract(ordinary[index + ring_size]))
        .collect::<Vec<_>>();
    Ok(match selected_half {
        RelationIntegerLiftFullRingHalf::Low => negacyclic[..half_size].to_vec(),
        RelationIntegerLiftFullRingHalf::High => negacyclic[half_size..].to_vec(),
    })
}

fn ordinary_convolution(
    left: &[ProofBaseFieldElement],
    right: &[ProofBaseFieldElement],
) -> Result<Vec<ProofBaseFieldElement>, ApplicationExtractionError> {
    if left.is_empty() || left.len() != right.len() {
        return Err(ApplicationExtractionError::IntegerLiftIdentityViolation);
    }
    let transform_size = left
        .len()
        .checked_mul(2)
        .ok_or(ApplicationExtractionError::CountOverflow)?;
    let domain = ProofEvaluationDomain::new_subgroup(transform_size)?;
    let mut left_evaluations = left.to_vec();
    let mut right_evaluations = right.to_vec();
    domain.evaluate_base_polynomial_in_place(&mut left_evaluations)?;
    domain.evaluate_base_polynomial_in_place(&mut right_evaluations)?;
    for (left_value, right_value) in left_evaluations.iter_mut().zip(right_evaluations) {
        *left_value = left_value.multiply(right_value);
    }
    domain.interpolate_base_polynomial_in_place(&mut left_evaluations)?;
    left_evaluations.resize(transform_size, ProofBaseFieldElement::ZERO);
    Ok(left_evaluations)
}

fn add_signed_rows(
    destination: &mut [ProofBaseFieldElement],
    source: &[ProofBaseFieldElement],
    negative: bool,
) -> Result<(), ApplicationExtractionError> {
    if destination.len() != source.len() {
        return Err(ApplicationExtractionError::IntegerLiftIdentityViolation);
    }
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination = destination.add(if negative { source.negate() } else { *source });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackedCommonWitnessClass {
    construction_kind: RelationRootConstructionKind,
    ordered_endpoints: Vec<RelationRootEndpoint>,
    root: ApplicationRoot,
}

impl PackedCommonWitnessClass {
    pub(crate) const fn construction_kind(&self) -> RelationRootConstructionKind {
        self.construction_kind
    }

    pub(crate) fn ordered_endpoints(&self) -> &[RelationRootEndpoint] {
        &self.ordered_endpoints
    }

    pub(crate) const fn root(&self) -> ApplicationRoot {
        self.root
    }
}

/// Equality classes induced solely by the compiler-derived root graph. Root
/// equality, together with the profile's checked construction shape and the
/// upstream commitment binding, joins the corresponding application columns
/// to one common committed witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackedCommonWitnessJoin {
    classes: Vec<PackedCommonWitnessClass>,
}

impl PackedCommonWitnessJoin {
    pub(crate) fn new(
        profile: &ProofProfileSet,
        root_bindings: &[ApplicationRootBinding],
    ) -> Result<Self, ApplicationExtractionError> {
        let edges = profile.root_compatibility_edges();
        let mut roots_by_endpoint = BTreeMap::new();
        for binding in root_bindings {
            if roots_by_endpoint
                .insert(binding.endpoint, binding.root)
                .is_some()
            {
                return Err(ApplicationExtractionError::RootJoinMismatch);
            }
        }
        let expected_endpoints = edges
            .iter()
            .flat_map(|edge| [edge.producer_endpoint(), edge.consumer_endpoint()])
            .collect::<BTreeSet<_>>();
        if roots_by_endpoint.keys().copied().collect::<BTreeSet<_>>() != expected_endpoints {
            return Err(ApplicationExtractionError::RootJoinMismatch);
        }
        let ordered_endpoints = expected_endpoints.into_iter().collect::<Vec<_>>();
        let endpoint_indexes = ordered_endpoints
            .iter()
            .copied()
            .enumerate()
            .map(|(index, endpoint)| (endpoint, index))
            .collect::<BTreeMap<_, _>>();
        let mut parents = (0..ordered_endpoints.len()).collect::<Vec<_>>();
        let mut construction_kind_by_endpoint = BTreeMap::new();
        for edge in edges {
            let producer = edge.producer_endpoint();
            let consumer = edge.consumer_endpoint();
            if roots_by_endpoint.get(&producer) != roots_by_endpoint.get(&consumer) {
                return Err(ApplicationExtractionError::RootJoinMismatch);
            }
            for endpoint in [producer, consumer] {
                match construction_kind_by_endpoint.insert(endpoint, edge.construction_kind()) {
                    Some(existing) if existing != edge.construction_kind() => {
                        return Err(ApplicationExtractionError::RootJoinMismatch);
                    }
                    _ => {}
                }
            }
            union_endpoint_classes(
                &mut parents,
                *endpoint_indexes
                    .get(&producer)
                    .ok_or(ApplicationExtractionError::RootJoinMismatch)?,
                *endpoint_indexes
                    .get(&consumer)
                    .ok_or(ApplicationExtractionError::RootJoinMismatch)?,
            );
        }
        let mut endpoints_by_class = BTreeMap::<usize, Vec<RelationRootEndpoint>>::new();
        for (index, endpoint) in ordered_endpoints.into_iter().enumerate() {
            let root_index = endpoint_class_root(&mut parents, index);
            endpoints_by_class
                .entry(root_index)
                .or_default()
                .push(endpoint);
        }
        let classes = endpoints_by_class
            .into_values()
            .map(
                |ordered_endpoints| -> Result<_, ApplicationExtractionError> {
                    let first = ordered_endpoints
                        .first()
                        .copied()
                        .ok_or(ApplicationExtractionError::RootJoinMismatch)?;
                    Ok(PackedCommonWitnessClass {
                        construction_kind: *construction_kind_by_endpoint
                            .get(&first)
                            .ok_or(ApplicationExtractionError::RootJoinMismatch)?,
                        root: *roots_by_endpoint
                            .get(&first)
                            .ok_or(ApplicationExtractionError::RootJoinMismatch)?,
                        ordered_endpoints,
                    })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { classes })
    }

    pub(crate) fn classes(&self) -> &[PackedCommonWitnessClass] {
        &self.classes
    }
}

fn endpoint_class_root(parents: &mut [usize], index: usize) -> usize {
    if parents[index] != index {
        let parent = parents[index];
        parents[index] = endpoint_class_root(parents, parent);
    }
    parents[index]
}

fn union_endpoint_classes(parents: &mut [usize], left: usize, right: usize) {
    let left_root = endpoint_class_root(parents, left);
    let right_root = endpoint_class_root(parents, right);
    if left_root != right_root {
        let (smaller, larger) = if left_root < right_root {
            (left_root, right_root)
        } else {
            (right_root, left_root)
        };
        parents[larger] = smaller;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        CommittedMaterialRelationPlanInput, RelationCoefficientLocalResidualDescriptor,
        RelationExpressionInstruction, ResolvedSuiteModulus, SuiteModulusReference,
        compile_vss_share_linkage_relation_plan,
    };
    use super::*;
    use crate::bgv::proof_suite::{
        CommonProofChallenge, FIRST_PROFILE_APPLICATION_FAMILIES,
        PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
        PROOF_CHALLENGE_EXTENSION_DEGREE, selected_proof_profile_set,
        selected_relation_plan_check_context, selected_relation_plans,
    };
    use crate::foundation::ProofApplicationSlotCeilings;

    fn modular_exponentiation_for_test(base: u64, mut exponent: u64, modulus: u64) -> u64 {
        let modulus_wide = u128::from(modulus);
        let mut result = 1_u128;
        let mut base_wide = u128::from(base) % modulus_wide;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = (result * base_wide) % modulus_wide;
            }
            base_wide = (base_wide * base_wide) % modulus_wide;
            exponent >>= 1;
        }
        u64::try_from(result).expect("the modular result is less than the modulus")
    }

    fn coefficient_local_zeroifier_test_context() -> RelationPlanCheckContext {
        let evaluation_domain_size = 1_024_u64;
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: u16::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                .expect("the challenge extension degree fits u16"),
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: modular_exponentiation_for_test(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 1,
            quotient_component_count: 16,
            quotient_component_degree_bound_exclusive: 64,
            fri_fold_count: 6,
            final_polynomial_degree_bound_exclusive: 8,
            unique_query_count: 1,
            non_native_modular_identity_challenge_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![ResolvedSuiteModulus::new(
                SuiteModulusReference::data(0),
                97,
            )],
        }
    }

    fn coefficient_local_zeroifier_test_input() -> CommittedMaterialRelationPlanInput {
        CommittedMaterialRelationPlanInput {
            ring_degree: 32,
            evaluation_domain_size: 1_024,
            opening_degree_bound_exclusive: 512,
            material_column_degree_bound_exclusive: 10,
            participant_count: 3,
            threshold: 2,
            sharing_data_modulus_indices: vec![0],
            trace_mask_degree_bound_exclusive: 14,
        }
    }

    fn base_value(value: i64) -> ProofBaseFieldElement {
        if value >= 0 {
            ProofBaseFieldElement::from_canonical(value as u64).expect("nonnegative test value")
        } else {
            ProofBaseFieldElement::from_canonical(value.unsigned_abs())
                .expect("negative test magnitude")
                .negate()
        }
    }

    fn naive_ordinary_convolution(
        left: &[ProofBaseFieldElement],
        right: &[ProofBaseFieldElement],
    ) -> Vec<ProofBaseFieldElement> {
        let mut output = vec![ProofBaseFieldElement::ZERO; left.len() * 2];
        for (left_index, left_value) in left.iter().copied().enumerate() {
            for (right_index, right_value) in right.iter().copied().enumerate() {
                output[left_index + right_index] =
                    output[left_index + right_index].add(left_value.multiply(right_value));
            }
        }
        output
    }

    fn expected_selected_convolution(
        kind: RelationIntegerLiftConvolutionKind,
        left: &[ProofBaseFieldElement],
        right: &[ProofBaseFieldElement],
    ) -> Vec<ProofBaseFieldElement> {
        let ordinary = naive_ordinary_convolution(left, right);
        match kind {
            RelationIntegerLiftConvolutionKind::Negacyclic => (0..left.len())
                .map(|index| ordinary[index].subtract(ordinary[index + left.len()]))
                .collect(),
            RelationIntegerLiftConvolutionKind::OrdinaryLowHalf => ordinary[..left.len()].to_vec(),
            RelationIntegerLiftConvolutionKind::OrdinaryHighHalf => ordinary[left.len()..].to_vec(),
        }
    }

    fn zero_application_challenges(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Vec<RelationApplicationChallengeAssignment> {
        variant
            .derived_challenge_catalog(context)
            .expect("selected challenge catalog")
            .into_iter()
            .filter_map(|descriptor| {
                let modulus_ordinal = u16::try_from(*descriptor.role_coordinates.first()?).ok()?;
                let repetition_ordinal =
                    u16::try_from(*descriptor.role_coordinates.get(1)?).ok()?;
                let challenge = match descriptor.role {
                    super::super::RelationChallengeRole::NonNativeTheta => {
                        CommonProofChallenge::Theta { modulus_ordinal }
                    }
                    super::super::RelationChallengeRole::NonNativeAlpha => {
                        CommonProofChallenge::Alpha { modulus_ordinal }
                    }
                    _ => return None,
                };
                Some((challenge, repetition_ordinal))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|(challenge, repetition_ordinal)| {
                RelationApplicationChallengeAssignment::new(challenge, repetition_ordinal, 0)
                    .expect("zero is a canonical non-native challenge coordinate")
            })
            .collect()
    }

    fn root_for_source(source_ordinal: u32) -> ApplicationRoot {
        let mut root = [0_u8; Hash512::BYTE_LENGTH];
        root[..u32::BITS as usize / u8::BITS as usize]
            .copy_from_slice(&source_ordinal.to_le_bytes());
        root[Hash512::BYTE_LENGTH - 1] = 0xa5;
        root
    }

    fn zero_extraction_input(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> ApplicationExtractionInput {
        let mut canonical_verifier_sequences = BTreeMap::new();
        let mut canonical_bound_roots = BTreeMap::new();
        let ordered_trees = variant
            .ordered_trees
            .iter()
            .enumerate()
            .map(|(tree_index, descriptor)| {
                let root = match descriptor {
                    RelationTreeDescriptor::BoundPublic {
                        expected_root_source_ordinal,
                        ..
                    } => {
                        let root = root_for_source(*expected_root_source_ordinal);
                        canonical_bound_roots.insert(*expected_root_source_ordinal, root);
                        root
                    }
                    RelationTreeDescriptor::ProofCreated { .. } => {
                        let mut root = [0_u8; Hash512::BYTE_LENGTH];
                        root[..usize::BITS as usize / u8::BITS as usize]
                            .copy_from_slice(&tree_index.to_le_bytes());
                        root[Hash512::BYTE_LENGTH - 1] = 0x5a;
                        root
                    }
                };
                let ordered_column_polynomials = descriptor
                    .ordered_column_ordinals()
                    .iter()
                    .map(|column_ordinal| {
                        if matches!(
                            variant.ordered_columns[*column_ordinal as usize].origin(),
                            RelationColumnOrigin::VerifierSequence { .. }
                        ) {
                            canonical_verifier_sequences.insert(
                                *column_ordinal,
                                CommonProofSourcePolynomial::from_base_coefficients(vec![
                                    ProofBaseFieldElement::ZERO,
                                ]),
                            );
                        }
                        CommonProofSourcePolynomial::from_base_coefficients(vec![
                            ProofBaseFieldElement::ZERO,
                        ])
                    })
                    .collect();
                ExtractedLowDegreeApplicationTree::new(root, ordered_column_polynomials)
            })
            .collect();
        ApplicationExtractionInput::new(
            ordered_trees,
            canonical_verifier_sequences,
            canonical_bound_roots,
            zero_application_challenges(variant, context),
        )
    }

    #[test]
    fn selected_grammar_has_complete_extraction_phase_ownership() {
        let artifacts = selected_relation_plans().expect("selected relation plans");
        assert_eq!(artifacts.len(), FIRST_PROFILE_APPLICATION_FAMILIES.len());
        let observed_families = artifacts
            .iter()
            .map(|artifact| artifact.application_statement_schema_identifier())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_families,
            FIRST_PROFILE_APPLICATION_FAMILIES.into_iter().collect()
        );
        for artifact in artifacts {
            let family = artifact.application_statement_schema_identifier();
            let context =
                selected_relation_plan_check_context(family).expect("selected relation context");
            for variant in artifact.compiled_plan().variants() {
                let extraction_plan = CheckedApplicationExtractionPlan::new(
                    artifact.compiled_plan(),
                    None,
                    variant.schedule_position(),
                    variant.top_count(),
                    None,
                    &context,
                )
                .expect("checked extraction plan");
                let tree_roles =
                    super::super::super::prover::proof_created_tree_roles_by_column(variant)
                        .expect("checked tree roles");
                let observed_role_one_prover_columns = variant
                    .ordered_columns
                    .iter()
                    .enumerate()
                    .filter_map(|(column_index, column)| {
                        let column_ordinal = u32::try_from(column_index).ok()?;
                        (matches!(column.origin(), RelationColumnOrigin::Prover)
                            && tree_roles.get(&column_ordinal) == Some(&ProofTreeRole::BaseOracle))
                        .then_some(column_ordinal)
                    })
                    .collect::<BTreeSet<_>>();
                let expected_role_one_prover_columns = extraction_plan
                    .semantic_role_one_columns()
                    .iter()
                    .copied()
                    .chain(
                        extraction_plan
                            .derived_role_one_columns_by_source()
                            .values()
                            .copied(),
                    )
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    observed_role_one_prover_columns,
                    expected_role_one_prover_columns
                );
                let observed_role_two_columns = tree_roles
                    .iter()
                    .filter_map(|(column_ordinal, role)| {
                        (*role == ProofTreeRole::AuxiliaryOracle).then_some(*column_ordinal)
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    &observed_role_two_columns,
                    extraction_plan.role_two_columns()
                );
            }
        }
    }

    #[test]
    fn semantic_lifting_is_unique_at_signed_boundaries() {
        assert_eq!(
            unique_integer_lift(16, 17, &SignedIntegerInterval::new(-8, 8)),
            Ok(-1)
        );
        assert_eq!(
            unique_integer_lift(8, 17, &SignedIntegerInterval::new(-8, 8)),
            Ok(8)
        );
        assert_eq!(
            unique_integer_lift(0, 17, &SignedIntegerInterval::new(-35, -34)),
            Ok(-34)
        );
        assert_eq!(
            unique_integer_lift(16, 17, &SignedIntegerInterval::new(-1, 16)),
            Err(ApplicationExtractionError::SemanticLiftNotUnique)
        );
        assert_eq!(
            unique_integer_lift(3, 17, &SignedIntegerInterval::new(0, 2)),
            Err(ApplicationExtractionError::SemanticLiftNotUnique)
        );
    }

    #[test]
    fn root_binding_requires_every_application_coordinate() {
        let family = ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
        let source_ordinal = 7;
        let root = root_for_source(source_ordinal);
        let witness = ExtractedApplicationWitness {
            application_statement_schema_identifier: family,
            roster_position: Some(4),
            schedule_position: None,
            top_count: None,
            producer_sequence: Some(19),
            semantic_columns: Vec::new(),
            bound_roots_by_verifier_source: BTreeMap::from([(source_ordinal, root)]),
        };
        let endpoint = |roster_position, producer_sequence| {
            RelationRootEndpoint::new(
                family,
                Some(roster_position),
                None,
                None,
                Some(producer_sequence),
                source_ordinal,
            )
            .expect("ballot root endpoint")
        };
        assert_eq!(
            witness.bind_root_endpoint(endpoint(4, 19)).unwrap().root(),
            root
        );
        assert_eq!(
            witness.bind_root_endpoint(endpoint(5, 19)),
            Err(ApplicationExtractionError::RootBindingMismatch)
        );
        assert_eq!(
            witness.bind_root_endpoint(endpoint(4, 20)),
            Err(ApplicationExtractionError::RootBindingMismatch)
        );
    }

    #[test]
    fn transform_convolutions_match_independent_coefficient_oracle() {
        for coefficient_count in [2_usize, 4, 8, 16] {
            let left = (0..coefficient_count)
                .map(|index| base_value(((index * 7 + 3) % 13) as i64 - 6))
                .collect::<Vec<_>>();
            let right = (0..coefficient_count)
                .map(|index| base_value(((index * index * 5 + 1) % 17) as i64 - 8))
                .collect::<Vec<_>>();
            for kind in [
                RelationIntegerLiftConvolutionKind::Negacyclic,
                RelationIntegerLiftConvolutionKind::OrdinaryLowHalf,
                RelationIntegerLiftConvolutionKind::OrdinaryHighHalf,
            ] {
                assert_eq!(
                    selected_convolution(kind, &left, &right).expect("transform convolution"),
                    expected_selected_convolution(kind, &left, &right)
                );
            }

            let left_high = left.iter().rev().copied().collect::<Vec<_>>();
            let right_high = right
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    if index % 2 == 0 {
                        value.negate()
                    } else {
                        *value
                    }
                })
                .collect::<Vec<_>>();
            let full_left = left.iter().chain(&left_high).copied().collect::<Vec<_>>();
            let full_right = right.iter().chain(&right_high).copied().collect::<Vec<_>>();
            let expected_full = expected_selected_convolution(
                RelationIntegerLiftConvolutionKind::Negacyclic,
                &full_left,
                &full_right,
            );
            assert_eq!(
                selected_full_ring_negacyclic_convolution(
                    RelationIntegerLiftFullRingHalf::Low,
                    &left,
                    &left_high,
                    &right,
                    &right_high,
                )
                .expect("low full-ring half"),
                expected_full[..coefficient_count]
            );
            assert_eq!(
                selected_full_ring_negacyclic_convolution(
                    RelationIntegerLiftFullRingHalf::High,
                    &left,
                    &left_high,
                    &right,
                    &right_high,
                )
                .expect("high full-ring half"),
                expected_full[coefficient_count..]
            );
        }
    }

    #[test]
    fn direct_automorphism_rejects_one_changed_target_coefficient() {
        let source = [1, 2, 3, 4, 5, 6, 7, 8].map(base_value).to_vec();
        let mut target = [1, -4, 7, 2, -5, 8, 3, -6].map(base_value).to_vec();
        assert!(
            negacyclic_automorphism_rows_match(
                &source[..4],
                &source[4..],
                &target[..4],
                &target[4..],
                3,
            )
            .expect("exact automorphism")
        );
        target[5] = target[5].add(ProofBaseFieldElement::ONE);
        assert!(
            !negacyclic_automorphism_rows_match(
                &source[..4],
                &source[4..],
                &target[..4],
                &target[4..],
                3,
            )
            .expect("changed automorphism")
        );
    }

    #[test]
    fn canonical_verifier_sequence_is_independent_of_extracted_columns() {
        let artifacts = selected_relation_plans().expect("selected relation plans");
        let (artifact, variant, verifier_column_ordinal) = artifacts
            .iter()
            .find_map(|artifact| {
                artifact
                    .compiled_plan()
                    .variants()
                    .iter()
                    .find_map(|variant| {
                        variant
                            .ordered_columns
                            .iter()
                            .position(|column| {
                                matches!(
                                    column.origin(),
                                    RelationColumnOrigin::VerifierSequence { .. }
                                )
                            })
                            .and_then(|column_index| {
                                u32::try_from(column_index)
                                    .ok()
                                    .map(|column_ordinal| (artifact, variant, column_ordinal))
                            })
                    })
            })
            .expect("the selected grammar contains verifier sequences");
        let context = selected_relation_plan_check_context(
            artifact.application_statement_schema_identifier(),
        )
        .expect("selected relation context");
        let extraction_plan = CheckedApplicationExtractionPlan::new(
            artifact.compiled_plan(),
            None,
            variant.schedule_position(),
            variant.top_count(),
            None,
            &context,
        )
        .expect("checked extraction plan");
        let mut input = zero_extraction_input(variant, &context);
        input
            .canonical_verifier_sequence_polynomials_by_column
            .insert(
                verifier_column_ordinal,
                CommonProofSourcePolynomial::from_base_coefficients(vec![
                    ProofBaseFieldElement::ONE,
                ]),
            );
        assert!(matches!(
            extraction_plan.extract(input),
            Err(ApplicationExtractionError::CanonicalVerifierSequenceMismatch)
        ));
    }

    #[test]
    fn auxiliary_replay_rejects_one_changed_trace_row() {
        let artifacts = selected_relation_plans().expect("selected relation plans");
        let (variant, context) = artifacts
            .iter()
            .find_map(|artifact| {
                let context = selected_relation_plan_check_context(
                    artifact.application_statement_schema_identifier(),
                )?;
                artifact
                    .compiled_plan()
                    .variants()
                    .iter()
                    .find_map(|variant| {
                        integer_lift_derived_columns(variant)
                            .ok()
                            .filter(|(_, auxiliary)| !auxiliary.is_empty())
                            .map(|_| (variant, context.clone()))
                    })
            })
            .expect("the selected grammar contains auxiliary columns");
        let challenges = zero_application_challenges(variant, &context);
        let mut cursor =
            CommonProofAuxiliaryColumnSynthesisCursor::new(variant, &context, &challenges)
                .expect("auxiliary replay cursor");
        let zero_rows = vec![
            ProofBaseFieldElement::ZERO;
            usize::try_from(variant.trace_domain_size()).expect("trace size")
        ];
        loop {
            if let Some(column_ordinal) = cursor.next_input_column_ordinal() {
                cursor
                    .accept_input_trace_rows(column_ordinal, &zero_rows)
                    .expect("zero input trace rows");
                continue;
            }
            if let Some((column_ordinal, expected_rows)) = cursor.pending_unmasked_output_rows() {
                let mut changed_rows = expected_rows.to_vec();
                let changed_index = changed_rows.len() / 2;
                changed_rows[changed_index] =
                    changed_rows[changed_index].add(ProofBaseFieldElement::ONE);
                assert_eq!(
                    cursor.compare_next_unmasked_output(column_ordinal, &changed_rows),
                    Err(CommonProofProverError::InvalidColumn)
                );
                break;
            }
            assert!(
                cursor
                    .advance_ready_task()
                    .expect("deterministic auxiliary task")
            );
        }
    }

    #[test]
    fn coefficient_local_replay_uses_the_checked_constraint_zeroifier_domain() {
        let context = coefficient_local_zeroifier_test_context();
        let compiled_plan = compile_vss_share_linkage_relation_plan(
            &coefficient_local_zeroifier_test_input(),
            &context,
        )
        .expect("small checked VSS relation plan");
        let mut extraction_plan =
            CheckedApplicationExtractionPlan::new(&compiled_plan, None, None, None, None, &context)
                .expect("small checked extraction plan");
        let assignments = zero_application_challenges(&extraction_plan.variant, &context);
        let checked_challenges = extraction_plan
            .variant
            .checked_application_challenges(&context, &assignments)
            .expect("checked non-native challenges");

        let evaluation_variable_minus_one = vec![
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::BaseFieldConstant(1),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ];
        let mut coefficient_local_batch = extraction_plan
            .variant
            .ordered_coefficient_local_identity_batches
            .first()
            .cloned()
            .expect("the VSS relation contains a coefficient-local batch");
        coefficient_local_batch.constraint_ordinal = 0;
        coefficient_local_batch.ordered_residuals =
            vec![RelationCoefficientLocalResidualDescriptor {
                unit_ordinal: 0,
                residual_postfix_expression: evaluation_variable_minus_one.clone(),
            }];
        extraction_plan
            .variant
            .ordered_coefficient_local_identity_batches = vec![coefficient_local_batch];
        extraction_plan.variant.ordered_constraints[0].numerator_postfix_expression =
            evaluation_variable_minus_one.clone();
        extraction_plan.variant.ordered_constraints[0].zeroifier_postfix_expression =
            evaluation_variable_minus_one.clone();

        assert_eq!(
            extraction_plan.check_coefficient_local_identities(&[], &checked_challenges),
            Ok(()),
            "a residual outside the checked point-zero domain is not an operative identity",
        );

        extraction_plan
            .variant
            .ordered_coefficient_local_identity_batches[0]
            .ordered_residuals[0]
            .residual_postfix_expression =
            vec![RelationExpressionInstruction::BaseFieldConstant(1)];
        assert_eq!(
            extraction_plan.check_coefficient_local_identities(&[], &checked_challenges),
            Err(ApplicationExtractionError::CoefficientLocalIdentityViolation),
            "the same residual remains mandatory where the checked zeroifier vanishes",
        );
    }

    #[test]
    fn public_aggregate_zero_relation_extracts_and_mutations_fail() {
        let family = ProofApplicationSlotCeilings::
            COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
        let artifacts = selected_relation_plans().expect("selected relation plans");
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.application_statement_schema_identifier() == family)
            .expect("collective public-key aggregate plan");
        let context =
            selected_relation_plan_check_context(family).expect("selected relation context");
        let variant = artifact
            .compiled_plan()
            .select_variant(None, None)
            .expect("unparameterized aggregate variant");
        let extraction_plan = CheckedApplicationExtractionPlan::new(
            artifact.compiled_plan(),
            None,
            None,
            None,
            None,
            &context,
        )
        .expect("aggregate extraction plan");
        let witness = extraction_plan
            .extract(zero_extraction_input(variant, &context))
            .expect("all-zero aggregate relation");
        assert!(witness.semantic_columns().is_empty());

        let mut changed_column_input = zero_extraction_input(variant, &context);
        changed_column_input.ordered_trees[0].ordered_column_polynomials[0] =
            CommonProofSourcePolynomial::from_base_coefficients(vec![ProofBaseFieldElement::ONE]);
        assert!(matches!(
            extraction_plan.extract(changed_column_input),
            Err(ApplicationExtractionError::ConstraintViolation)
        ));

        let mut changed_root_input = zero_extraction_input(variant, &context);
        let root_source = *changed_root_input
            .canonical_bound_roots_by_verifier_source
            .keys()
            .next()
            .expect("aggregate root source");
        changed_root_input
            .canonical_bound_roots_by_verifier_source
            .insert(root_source, [0xff; Hash512::BYTE_LENGTH]);
        assert_eq!(
            extraction_plan.extract(changed_root_input),
            Err(ApplicationExtractionError::CanonicalRootMismatch)
        );
    }

    #[test]
    fn packed_join_uses_exact_profile_edges_and_root_coverage() {
        let profile = selected_proof_profile_set(1).expect("selected proof profile");
        let endpoints = profile
            .root_compatibility_edges()
            .iter()
            .flat_map(|edge| [edge.producer_endpoint(), edge.consumer_endpoint()])
            .collect::<BTreeSet<_>>();
        assert!(!endpoints.is_empty());
        let root = [0x39; Hash512::BYTE_LENGTH];
        let bindings = endpoints
            .iter()
            .copied()
            .map(|endpoint| ApplicationRootBinding { endpoint, root })
            .collect::<Vec<_>>();
        let join = PackedCommonWitnessJoin::new(&profile, &bindings)
            .expect("profile-derived common-witness join");
        assert!(!join.classes().is_empty());
        assert_eq!(
            join.classes()
                .iter()
                .map(|class| class.ordered_endpoints().len())
                .sum::<usize>(),
            endpoints.len()
        );

        let mut changed = bindings.clone();
        changed[0].root = [0x93; Hash512::BYTE_LENGTH];
        assert_eq!(
            PackedCommonWitnessJoin::new(&profile, &changed),
            Err(ApplicationExtractionError::RootJoinMismatch)
        );

        let mut missing = bindings.clone();
        missing.pop();
        assert_eq!(
            PackedCommonWitnessJoin::new(&profile, &missing),
            Err(ApplicationExtractionError::RootJoinMismatch)
        );

        let mut duplicated = bindings.clone();
        duplicated.push(bindings[0]);
        assert_eq!(
            PackedCommonWitnessJoin::new(&profile, &duplicated),
            Err(ApplicationExtractionError::RootJoinMismatch)
        );
    }
}
