//! Incremental aggregate witness materialization for row-code/WHIR proofs.
//!
//! The materializer consumes one plan-addressed replay polynomial at a time.
//! It owns transcript-derived weights and the fixed physical aggregate table;
//! unused candidate-specific columns remain canonical zeros. No complete phase
//! matrix or duplicate stacked polynomial is retained.

use std::collections::BTreeMap;

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

use super::LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
use crate::bgv::proof_suite::prover::{
    CommonProofSourcePolynomialRequestContext, ordered_integer_lift_auxiliary_column_ordinals,
    persisted_pre_challenge_column_coefficient_position_counts, relation_reversed_column_bindings,
};
#[cfg(test)]
use crate::bgv::proof_suite::relation_plan::RelationColumnOrigin;
use crate::bgv::proof_suite::relation_plan::{
    RelationColumnValueType, RelationPlanCheckContext, RelationPlanVariant,
};
use crate::bgv::proof_suite::transcript::RowCodeWhirTranscript;
use crate::bgv::proof_suite::{
    CommonProofProverError, CommonProofSourcePolynomial, ProofChallengeExtensionElement,
};
use crate::hashing::hash_framed_parts_512;

use super::super::aggregate_wide_pcs::{
    aggregate_wide_challenger_from_transcript, aggregate_wide_pcs_for_construction_plan,
};
use super::super::construction_plan::{
    RowCodeWhirConstructionPlan, RowCodeWhirOpenedPolynomialSource, RowCodeWhirPhase,
};
use super::super::opening_schedule::{
    RowCodeWhirBoundOpeningClaim, RowCodeWhirOpeningSchedule,
    RowCodeWhirOpeningScheduleContinuation, RowCodeWhirPointRowWeights,
    aggregate_bound_reduction_column_index, aggregate_column_index_for_opening_point,
    derive_bound_opening_claims, derive_opening_schedule_after_observed_commitment,
    derive_point_row_weights, divide_polynomial_opening, opening_schedule_continuation,
    phase_has_private_row_padding, phase_index, reduction_block_coefficient_start,
};
use super::super::row_encoding::{
    RowCodeHighHalfSource, RowEncodingGeometry, padded_row_coefficients,
};
use super::super::same_secret_source_manifest::SameSecretAuthenticatedSourceManifest;
use super::super::{ChallengeField, ExtensionFieldChallenger};

const AGGREGATE_SOURCE_BINDING_DOMAIN: &str =
    "sealed-lattice/row-code-whir/aggregate-source-binding/v2";
const AGGREGATE_SOURCE_ACTION_CATALOG_DOMAIN: &str =
    "sealed-lattice/row-code-whir/aggregate-source-action-catalog/v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) enum ExactSameSecretAggregateSourceTarget {
    RelationColumn {
        column_ordinal: u32,
    },
    OpenedPolynomial {
        source: RowCodeWhirOpenedPolynomialSource,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactSameSecretAggregateSourceUse {
    PhaseRow {
        phase: RowCodeWhirPhase,
        row_ordinal: usize,
        logical_block_ordinal: usize,
        extension_coordinate_ordinal: Option<usize>,
        final_source_for_row: bool,
    },
    BoundReduction {
        claim_ordinal: usize,
        block_ordinal: usize,
        reduction_coefficient_count: usize,
    },
}

/// One exact replay request in the construction-plan order.
///
/// The action is returned by the materializer and must be supplied back
/// unchanged with the corresponding owned coefficient range. This prevents a
/// caller from relabeling compatible-looking bytes as another source
/// coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateSourceAction {
    action_ordinal: usize,
    target: ExactSameSecretAggregateSourceTarget,
    value_type: RelationColumnValueType,
    source_coefficient_count: usize,
    source_range_start: usize,
    source_range_length: usize,
    source_use: ExactSameSecretAggregateSourceUse,
}

impl ExactSameSecretAggregateSourceAction {
    pub(in crate::bgv::proof_suite::row_code_whir) const fn target(
        self,
    ) -> ExactSameSecretAggregateSourceTarget {
        self.target
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn value_type(
        self,
    ) -> RelationColumnValueType {
        self.value_type
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn source_coefficient_count(
        self,
    ) -> usize {
        self.source_coefficient_count
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn source_range_start(self) -> usize {
        self.source_range_start
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn source_range_length(self) -> usize {
        self.source_range_length
    }
}

/// Validated aggregate-table shape retained after both bounded materialization
/// passes finish. Source coefficients themselves live only in external
/// column objects.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateWitness {
    table_variable_count: usize,
    table_width: usize,
    folding_factor: usize,
}

impl ExactSameSecretAggregateWitness {
    pub(in crate::bgv::proof_suite::row_code_whir) const fn table_variable_count(&self) -> usize {
        self.table_variable_count
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn table_width(&self) -> usize {
        self.table_width
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn folding_factor(&self) -> usize {
        self.folding_factor
    }
}

/// One resident half of the aggregate table. The batch is moved directly into
/// canonical external writers and zeroized on every exit path.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateSourceBatch {
    first_column_index: usize,
    columns: Vec<Vec<ChallengeField>>,
}

impl ExactSameSecretAggregateSourceBatch {
    pub(in crate::bgv::proof_suite::row_code_whir) const fn first_column_index(&self) -> usize {
        self.first_column_index
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn columns(&self) -> &[Vec<ChallengeField>] {
        &self.columns
    }
}

impl Drop for ExactSameSecretAggregateSourceBatch {
    fn drop(&mut self) {
        for column in &mut self.columns {
            column.fill(ChallengeField::ZERO);
        }
    }
}

/// Transcript- and construction-bound continuation metadata. The internal
/// weights and claims are not accepted from callers; they are sampled exactly
/// once by [`ExactSameSecretAggregateSource::new`].
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateMetadata {
    binding_digest: [u8; 64],
    construction_identity_hash: [u8; 64],
    action_catalog_digest: [u8; 64],
    action_count: usize,
    opening_points: Vec<ProofChallengeExtensionElement>,
    opening_schedule_continuation: Option<RowCodeWhirOpeningScheduleContinuation>,
}

impl ExactSameSecretAggregateMetadata {
    pub(in crate::bgv::proof_suite::row_code_whir) const fn binding_digest(&self) -> [u8; 64] {
        self.binding_digest
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn construction_identity_hash(
        &self,
    ) -> [u8; 64] {
        self.construction_identity_hash
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn action_catalog_digest(
        &self,
    ) -> [u8; 64] {
        self.action_catalog_digest
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn action_count(&self) -> usize {
        self.action_count
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn derive_opening_schedule_after_observed_commitment(
        &mut self,
        construction_plan: &RowCodeWhirConstructionPlan,
        relation_context: &RelationPlanCheckContext,
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<RowCodeWhirOpeningSchedule, CommonProofProverError> {
        let continuation = self
            .opening_schedule_continuation
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        derive_opening_schedule_after_observed_commitment(
            continuation,
            construction_plan,
            relation_context,
            &self.opening_points,
            challenger,
        )
        .map_err(|_| CommonProofProverError::InvalidOpening)
    }
}

/// Completed move-only handoff to retained WHIR generation.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateMaterializedSource {
    pub(in crate::bgv::proof_suite::row_code_whir) witness: ExactSameSecretAggregateWitness,
    pub(in crate::bgv::proof_suite::row_code_whir) metadata: ExactSameSecretAggregateMetadata,
    challenger: ExtensionFieldChallenger,
    row_pad_seeds: Option<Zeroizing<[[u8; 32]; 3]>>,
}

type ExactSameSecretAggregateMaterializedParts = (
    ExactSameSecretAggregateWitness,
    ExactSameSecretAggregateMetadata,
    ExtensionFieldChallenger,
    Option<Zeroizing<[[u8; 32]; 3]>>,
);

impl ExactSameSecretAggregateMaterializedSource {
    pub(in crate::bgv::proof_suite::row_code_whir) fn into_parts(
        self,
    ) -> ExactSameSecretAggregateMaterializedParts {
        (
            self.witness,
            self.metadata,
            self.challenger,
            self.row_pad_seeds,
        )
    }
}

/// Incremental production materializer. A storage bridge services only the
/// current action, then the supplied exact range is consumed and zeroized
/// before the next action becomes visible.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateSource {
    construction_plan: RowCodeWhirConstructionPlan,
    actions: Vec<ExactSameSecretAggregateSourceAction>,
    next_action_index: usize,
    row_pad_seeds: Option<Zeroizing<[[u8; 32]; 3]>>,
    phase_row_witness: Vec<Goldilocks>,
    aggregate_columns: Option<Vec<Vec<ChallengeField>>>,
    current_batch_ordinal: usize,
    coefficient_count: usize,
    aggregate_table_width: usize,
    relation_context: Option<RelationPlanCheckContext>,
    point_row_weights: Option<Vec<RowCodeWhirPointRowWeights>>,
    bound_claims: Vec<RowCodeWhirBoundOpeningClaim>,
    metadata: Option<ExactSameSecretAggregateMetadata>,
    challenger: Option<ExtensionFieldChallenger>,
}

impl ExactSameSecretAggregateSource {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        relation_variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        source_manifest: &SameSecretAuthenticatedSourceManifest,
        source_request_context: CommonProofSourcePolynomialRequestContext,
        source_replay_identity_digest: [u8; 64],
        transcript_prefix_authority_binding_digest: [u8; 64],
        opening_points: Vec<ProofChallengeExtensionElement>,
        out_of_domain_evaluations: &[ProofChallengeExtensionElement],
        opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement],
        row_pad_seeds: Option<Zeroizing<[[u8; 32]; 3]>>,
        row_code_whir_transcript: RowCodeWhirTranscript,
    ) -> Result<Self, CommonProofProverError> {
        let expected_mask_evaluation_count = construction_plan
            .opening_batch_mask_chunk_evaluation_count()
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        if source_replay_identity_digest == [0_u8; 64]
            || transcript_prefix_authority_binding_digest == [0_u8; 64]
            || opening_points.len() != relation_variant.ordered_opening_points().len()
            || out_of_domain_evaluations.len() != relation_variant.ordered_opening_claims().len()
            || opening_batch_mask_chunk_evaluations.len() != expected_mask_evaluation_count
            || phase_has_private_row_padding(relation_variant) != row_pad_seeds.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let relation_plan_variant_hash = relation_variant
            .canonical_hash()
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        source_manifest
            .validate_against(construction_plan, relation_variant, relation_context)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        let construction_identity_hash = construction_plan
            .canonical_identity_hash()
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        if construction_identity_hash != source_manifest.construction_identity()
            || source_request_context.relation_plan_variant_hash() != relation_plan_variant_hash
            || source_request_context.relation_plan_hash() != construction_plan.relation_plan_hash()
        {
            return Err(CommonProofProverError::InvalidInput);
        }

        let pcs = aggregate_wide_pcs_for_construction_plan(construction_plan)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        let mut challenger = aggregate_wide_challenger_from_transcript(
            &pcs,
            construction_plan,
            row_code_whir_transcript,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let point_row_weights = derive_point_row_weights(
            construction_plan,
            relation_variant,
            &opening_points,
            &mut challenger,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let bound_claims = derive_bound_opening_claims(
            construction_plan,
            relation_variant,
            &opening_points,
            out_of_domain_evaluations,
            &mut challenger,
        )
        .map_err(|_| CommonProofProverError::InvalidOpening)?;
        let actions =
            exact_aggregate_source_actions(construction_plan, relation_variant, &bound_claims)?;
        let action_catalog_digest = aggregate_action_catalog_digest(&actions)?;
        let binding_digest = aggregate_source_binding_digest(
            construction_identity_hash,
            source_manifest.catalog_hash(),
            source_request_context.stable_generation_binding_hash(),
            source_replay_identity_digest,
            transcript_prefix_authority_binding_digest,
            &opening_points,
            out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations,
            action_catalog_digest,
        )?;
        let coefficient_count = 1_usize
            .checked_shl(
                u32::try_from(construction_plan.selected_parameters().table_variable_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let aggregate_table_width = construction_plan.aggregate_table_width();
        if coefficient_count == 0
            || aggregate_table_width == 0
            || !aggregate_table_width.is_power_of_two()
            || construction_plan.aggregate_logical_column_count() > aggregate_table_width
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if aggregate_table_width < 2 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let aggregate_columns =
            allocate_aggregate_batch(coefficient_count, aggregate_table_width / 2)?;
        let action_count = actions.len();
        Ok(Self {
            construction_plan: construction_plan.clone(),
            actions,
            next_action_index: 0,
            row_pad_seeds,
            phase_row_witness: Vec::new(),
            aggregate_columns: Some(aggregate_columns),
            current_batch_ordinal: 0,
            coefficient_count,
            aggregate_table_width,
            relation_context: Some(relation_context.clone()),
            point_row_weights: Some(point_row_weights),
            bound_claims,
            metadata: Some(ExactSameSecretAggregateMetadata {
                binding_digest,
                construction_identity_hash,
                action_catalog_digest,
                action_count,
                opening_points,
                opening_schedule_continuation: None,
            }),
            challenger: Some(challenger),
        })
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn next_action(
        &self,
    ) -> Option<ExactSameSecretAggregateSourceAction> {
        self.actions.get(self.next_action_index).copied()
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn supply_source_range(
        &mut self,
        action: ExactSameSecretAggregateSourceAction,
        source_range: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        let expected = self
            .next_action()
            .ok_or(CommonProofProverError::InvalidInput)?;
        if action != expected || action.action_ordinal != self.next_action_index {
            return Err(CommonProofProverError::InvalidInput);
        }
        match action.source_use {
            ExactSameSecretAggregateSourceUse::PhaseRow {
                phase,
                row_ordinal,
                logical_block_ordinal,
                extension_coordinate_ordinal,
                final_source_for_row,
            } => {
                self.consume_phase_polynomial(
                    action,
                    phase,
                    row_ordinal,
                    logical_block_ordinal,
                    extension_coordinate_ordinal,
                    source_range,
                )?;
                if final_source_for_row {
                    self.finish_phase_row(phase, row_ordinal)?;
                }
            }
            ExactSameSecretAggregateSourceUse::BoundReduction {
                claim_ordinal,
                block_ordinal,
                reduction_coefficient_count,
            } => self.consume_bound_polynomial(
                action,
                claim_ordinal,
                block_ordinal,
                reduction_coefficient_count,
                source_range,
            )?,
        }
        self.next_action_index = self
            .next_action_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    /// Moves the completed resident half into the external-storage bridge.
    pub(in crate::bgv::proof_suite::row_code_whir) fn take_completed_batch(
        &mut self,
    ) -> Result<ExactSameSecretAggregateSourceBatch, CommonProofProverError> {
        if self.next_action_index != self.actions.len() || !self.phase_row_witness.is_empty() {
            return Err(CommonProofProverError::InvalidInput);
        }
        let columns = self
            .aggregate_columns
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let first_column_index = self
            .current_batch_ordinal
            .checked_mul(self.aggregate_table_width / 2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(ExactSameSecretAggregateSourceBatch {
            first_column_index,
            columns,
        })
    }

    /// Allocates the second half only after the first half has been sealed and
    /// released by its writer.
    pub(in crate::bgv::proof_suite::row_code_whir) fn begin_second_batch(
        &mut self,
    ) -> Result<(), CommonProofProverError> {
        if self.current_batch_ordinal != 0
            || self.aggregate_columns.is_some()
            || self.next_action_index != self.actions.len()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        self.current_batch_ordinal = 1;
        self.next_action_index = 0;
        self.aggregate_columns = Some(allocate_aggregate_batch(
            self.coefficient_count,
            self.aggregate_table_width / 2,
        )?);
        Ok(())
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn finish(
        mut self,
    ) -> Result<ExactSameSecretAggregateMaterializedSource, CommonProofProverError> {
        if self.current_batch_ordinal != 1
            || self.next_action_index != self.actions.len()
            || !self.phase_row_witness.is_empty()
            || self.aggregate_columns.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let expected_coefficient_count = 1_usize
            .checked_shl(
                u32::try_from(self.construction_plan.parameters.table_variable_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let aggregate_table_width = self.construction_plan.aggregate_table_width();
        if self.coefficient_count != expected_coefficient_count
            || self.aggregate_table_width != aggregate_table_width
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let row_pad_seeds = self.row_pad_seeds.take();
        let relation_context = self
            .relation_context
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let point_row_weights = self
            .point_row_weights
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let opening_schedule_continuation = opening_schedule_continuation(
            &self.construction_plan,
            &relation_context,
            point_row_weights,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let mut metadata = self
            .metadata
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        if metadata
            .opening_schedule_continuation
            .replace(opening_schedule_continuation)
            .is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(ExactSameSecretAggregateMaterializedSource {
            witness: ExactSameSecretAggregateWitness {
                table_variable_count: self.construction_plan.parameters.table_variable_count,
                table_width: aggregate_table_width,
                folding_factor: self.construction_plan.parameters.folding_factor,
            },
            metadata,
            challenger: self
                .challenger
                .take()
                .ok_or(CommonProofProverError::InvalidInput)?,
            row_pad_seeds,
        })
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn cancel(mut self) {
        self.clear_secret_material();
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_phase_polynomial(
        &mut self,
        action: ExactSameSecretAggregateSourceAction,
        phase: RowCodeWhirPhase,
        row_ordinal: usize,
        logical_block_ordinal: usize,
        extension_coordinate_ordinal: Option<usize>,
        source_range: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        let geometry = phase_geometry(&self.construction_plan, phase)?;
        if row_ordinal >= geometry.row_count
            || action.source_range_length == 0
            || action
                .source_range_start
                .checked_add(action.source_range_length)
                .filter(|end| *end <= action.source_coefficient_count)
                .is_none()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if self.phase_row_witness.is_empty() {
            self.phase_row_witness = vec![Goldilocks::ZERO; geometry.witness_values_per_row];
        }
        if self.phase_row_witness.len() != geometry.witness_values_per_row {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let destination_start = logical_block_ordinal
            .checked_mul(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination_end = destination_start
            .checked_add(action.source_range_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination = self
            .phase_row_witness
            .get_mut(destination_start..destination_end)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        match (source_range, extension_coordinate_ordinal) {
            (CommonProofSourcePolynomial::Base(coefficients), None) => {
                if action.value_type != RelationColumnValueType::BaseField
                    || coefficients.len() != action.source_range_length
                {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                for (destination, source) in destination.iter_mut().zip(coefficients.iter()) {
                    *destination = Goldilocks::new(source.canonical());
                }
            }
            (CommonProofSourcePolynomial::Extension(coefficients), Some(coordinate_ordinal)) => {
                if action.value_type != RelationColumnValueType::ChallengeExtension
                    || coefficients.len() != action.source_range_length
                {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                for (destination, source) in destination.iter_mut().zip(coefficients.iter()) {
                    *destination = Goldilocks::new(
                        *source
                            .canonical_coordinates()
                            .get(coordinate_ordinal)
                            .ok_or(CommonProofProverError::InvalidColumn)?,
                    );
                }
            }
            _ => return Err(CommonProofProverError::InvalidColumn),
        }
        Ok(())
    }

    fn finish_phase_row(
        &mut self,
        phase: RowCodeWhirPhase,
        row_ordinal: usize,
    ) -> Result<(), CommonProofProverError> {
        let geometry = phase_geometry(&self.construction_plan, phase)?;
        let high_half_source = match self.row_pad_seeds.as_ref() {
            Some(seeds) => RowCodeHighHalfSource::PrivateMaskSeed(
                seeds
                    .get(phase_index(phase))
                    .ok_or(CommonProofProverError::InvalidInput)?,
            ),
            None => RowCodeHighHalfSource::CanonicalPublicZeros,
        };
        let mut padded_coefficients = padded_row_coefficients(
            geometry,
            row_ordinal,
            &self.phase_row_witness,
            high_half_source,
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let point_row_weights = self
            .point_row_weights
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?;
        for (opening_point_ordinal, point_weights) in point_row_weights.iter().enumerate() {
            let aggregate_column_index = aggregate_column_index_for_opening_point(
                &self.construction_plan,
                opening_point_ordinal,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
            let weight = point_weights
                .phase_rows(phase)
                .get(row_ordinal)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            if weight != ChallengeField::ZERO {
                let first_column_index = self
                    .current_batch_ordinal
                    .checked_mul(self.aggregate_table_width / 2)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if let Some(batch_column_index) = aggregate_column_index
                    .checked_sub(first_column_index)
                    .filter(|index| *index < self.aggregate_table_width / 2)
                {
                    let aggregate_column = self
                        .aggregate_columns
                        .as_mut()
                        .and_then(|columns| columns.get_mut(batch_column_index))
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    if aggregate_column.len() != padded_coefficients.len() {
                        return Err(CommonProofProverError::InvalidColumn);
                    }
                    for (destination, coefficient) in aggregate_column
                        .iter_mut()
                        .zip(padded_coefficients.iter().copied())
                    {
                        *destination += weight * ChallengeField::from(coefficient);
                    }
                }
            }
        }
        padded_coefficients.fill(Goldilocks::ZERO);
        self.phase_row_witness.fill(Goldilocks::ZERO);
        self.phase_row_witness.clear();
        Ok(())
    }

    fn consume_bound_polynomial(
        &mut self,
        action: ExactSameSecretAggregateSourceAction,
        claim_ordinal: usize,
        block_ordinal: usize,
        reduction_coefficient_count: usize,
        source_range: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        let claim = self
            .bound_claims
            .get(claim_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        if action.target
            != (ExactSameSecretAggregateSourceTarget::RelationColumn {
                column_ordinal: claim.column_ordinal,
            })
            || action.value_type != RelationColumnValueType::BaseField
            || action.source_range_start != 0
            || action.source_range_length != reduction_coefficient_count
            || action.source_coefficient_count < reduction_coefficient_count
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let CommonProofSourcePolynomial::Base(coefficients) = source_range else {
            return Err(CommonProofProverError::InvalidColumn);
        };
        if coefficients.len() != action.source_range_length {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let (quotient, remainder) = divide_polynomial_opening(
            reduction_coefficient_count,
            |coefficient_ordinal| {
                ChallengeField::from(Goldilocks::new(
                    coefficients[coefficient_ordinal].canonical(),
                ))
            },
            claim.opening_point,
            claim.claimed_value,
        )
        .map_err(|_| CommonProofProverError::InvalidOpening)?;
        if remainder != ChallengeField::ZERO {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let block = self
            .construction_plan
            .bound_reduction_blocks
            .get(block_ordinal)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        if claim.reduction_block_ordinal != block_ordinal {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let block_coefficient_count = 1_usize
            .checked_shl(
                u32::try_from(block.polynomial_variable_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if quotient.len() > block_coefficient_count {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let local_destination_start =
            reduction_block_coefficient_start(&self.construction_plan, block_ordinal)
                .map_err(|_| CommonProofProverError::InvalidOpening)?;
        let aggregate_column_index =
            aggregate_bound_reduction_column_index(&self.construction_plan)
                .map_err(|_| CommonProofProverError::InvalidOpening)?
                .ok_or(CommonProofProverError::InvalidOpening)?;
        let first_column_index = self
            .current_batch_ordinal
            .checked_mul(self.aggregate_table_width / 2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if let Some(batch_column_index) = aggregate_column_index
            .checked_sub(first_column_index)
            .filter(|index| *index < self.aggregate_table_width / 2)
        {
            let aggregate_column = self
                .aggregate_columns
                .as_mut()
                .and_then(|columns| columns.get_mut(batch_column_index))
                .ok_or(CommonProofProverError::InvalidOpening)?;
            for (coefficient_ordinal, coefficient) in quotient.into_iter().enumerate() {
                let aggregate_index = local_destination_start
                    .checked_add(coefficient_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                *aggregate_column
                    .get_mut(aggregate_index)
                    .ok_or(CommonProofProverError::InvalidOpening)? +=
                    claim.batching_weight * coefficient;
            }
        }
        Ok(())
    }

    fn clear_secret_material(&mut self) {
        self.phase_row_witness.fill(Goldilocks::ZERO);
        self.phase_row_witness.clear();
        if let Some(columns) = self.aggregate_columns.as_mut() {
            for column in columns {
                column.fill(ChallengeField::ZERO);
                column.clear();
            }
        }
        self.aggregate_columns = None;
        self.row_pad_seeds = None;
    }
}

impl Drop for ExactSameSecretAggregateSource {
    fn drop(&mut self) {
        self.clear_secret_material();
    }
}

fn exact_aggregate_source_actions(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    bound_claims: &[RowCodeWhirBoundOpeningClaim],
) -> Result<Vec<ExactSameSecretAggregateSourceAction>, CommonProofProverError> {
    let replay_coefficient_counts =
        aggregate_relation_replay_coefficient_position_counts(relation_variant)?;
    let mut actions = Vec::new();
    for phase in [RowCodeWhirPhase::Base, RowCodeWhirPhase::Auxiliary] {
        let phase_plan = match phase {
            RowCodeWhirPhase::Base => construction_plan.base_phase.as_ref(),
            RowCodeWhirPhase::Auxiliary => construction_plan.auxiliary_phase.as_ref(),
            RowCodeWhirPhase::Quotient => None,
        };
        let Some(phase_plan) = phase_plan else {
            continue;
        };
        for (row_ordinal, row) in phase_plan.rows.iter().enumerate() {
            let populated_chunks = row.logical_polynomial_chunks.iter().flatten().count();
            if populated_chunks == 0 {
                return Err(CommonProofProverError::InvalidColumn);
            }
            let mut populated_chunk_ordinal = 0_usize;
            for (logical_block_ordinal, chunk) in
                row.logical_polynomial_chunks.iter().copied().enumerate()
            {
                let Some(chunk) = chunk else { continue };
                let descriptor = relation_variant
                    .ordered_columns()
                    .get(
                        usize::try_from(chunk.column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                if descriptor.value_type() != RelationColumnValueType::BaseField {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                let source_coefficient_count = usize::try_from(
                    *replay_coefficient_counts
                        .get(&chunk.column_ordinal)
                        .ok_or(CommonProofProverError::InvalidColumn)?,
                )
                .map_err(|_| CommonProofProverError::CountOverflow)?;
                let source_range_start = usize::try_from(chunk.coefficient_chunk_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .checked_mul(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let source_range_length = source_coefficient_count
                    .checked_sub(source_range_start)
                    .map(|remaining| remaining.min(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT))
                    .filter(|length| *length > 0)
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                populated_chunk_ordinal += 1;
                actions.push(ExactSameSecretAggregateSourceAction {
                    action_ordinal: actions.len(),
                    target: ExactSameSecretAggregateSourceTarget::RelationColumn {
                        column_ordinal: chunk.column_ordinal,
                    },
                    value_type: descriptor.value_type(),
                    source_coefficient_count,
                    source_range_start,
                    source_range_length,
                    source_use: ExactSameSecretAggregateSourceUse::PhaseRow {
                        phase,
                        row_ordinal,
                        logical_block_ordinal,
                        extension_coordinate_ordinal: None,
                        final_source_for_row: populated_chunk_ordinal == populated_chunks,
                    },
                });
            }
        }
    }
    for (row_ordinal, row) in construction_plan.quotient_phase.rows.iter().enumerate() {
        let populated_chunks = row.logical_polynomial_chunks.iter().flatten().count();
        if populated_chunks == 0 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let mut populated_chunk_ordinal = 0_usize;
        for (logical_block_ordinal, chunk) in
            row.logical_polynomial_chunks.iter().copied().enumerate()
        {
            let Some(chunk) = chunk else { continue };
            let source_coefficient_count = match chunk.source {
                RowCodeWhirOpenedPolynomialSource::QuotientComponent { .. } => usize::try_from(
                    construction_plan
                        .quotient_phase
                        .quotient_component_degree_bound_exclusive,
                ),
                RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { .. } => usize::try_from(
                    construction_plan
                        .quotient_phase
                        .opening_batch_mask_degree_bound_exclusive
                        .ok_or(CommonProofProverError::InvalidMask)?,
                ),
            }
            .map_err(|_| CommonProofProverError::CountOverflow)?;
            let source_range_start = usize::try_from(chunk.coefficient_chunk_ordinal)
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .checked_mul(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let source_range_length = source_coefficient_count
                .checked_sub(source_range_start)
                .map(|remaining| remaining.min(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT))
                .filter(|length| *length > 0)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            populated_chunk_ordinal += 1;
            actions.push(ExactSameSecretAggregateSourceAction {
                action_ordinal: actions.len(),
                target: ExactSameSecretAggregateSourceTarget::OpenedPolynomial {
                    source: chunk.source,
                },
                value_type: RelationColumnValueType::ChallengeExtension,
                source_coefficient_count,
                source_range_start,
                source_range_length,
                source_use: ExactSameSecretAggregateSourceUse::PhaseRow {
                    phase: RowCodeWhirPhase::Quotient,
                    row_ordinal,
                    logical_block_ordinal,
                    extension_coordinate_ordinal: Some(usize::from(
                        row.extension_coordinate_ordinal,
                    )),
                    final_source_for_row: populated_chunk_ordinal == populated_chunks,
                },
            });
        }
    }

    for (claim_ordinal, claim) in bound_claims.iter().enumerate() {
        let block_ordinal = claim.reduction_block_ordinal;
        let block = construction_plan
            .bound_reduction_blocks
            .get(block_ordinal)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        if !block
            .ordered_bound_tree_ordinals
            .iter()
            .any(|tree_ordinal| {
                construction_plan
                    .bound_trees
                    .get(*tree_ordinal as usize)
                    .is_some_and(|tree| {
                        tree.ordered_columns
                            .iter()
                            .any(|column| column.column_ordinal == claim.column_ordinal)
                    })
            })
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let maximum_reduction_coefficient_count =
            usize::try_from(block.maximum_source_degree_bound_exclusive)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let descriptor = relation_variant
            .ordered_columns()
            .get(
                usize::try_from(claim.column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if descriptor.value_type() != RelationColumnValueType::BaseField
            || descriptor.source_degree_bound_exclusive()
                != block.maximum_source_degree_bound_exclusive
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let source_coefficient_count = usize::try_from(
            *replay_coefficient_counts
                .get(&claim.column_ordinal)
                .ok_or(CommonProofProverError::InvalidColumn)?,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        if source_coefficient_count == 0
            || source_coefficient_count > maximum_reduction_coefficient_count
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        actions.push(ExactSameSecretAggregateSourceAction {
            action_ordinal: actions.len(),
            target: ExactSameSecretAggregateSourceTarget::RelationColumn {
                column_ordinal: claim.column_ordinal,
            },
            value_type: RelationColumnValueType::BaseField,
            source_coefficient_count,
            source_range_start: 0,
            source_range_length: source_coefficient_count,
            source_use: ExactSameSecretAggregateSourceUse::BoundReduction {
                claim_ordinal,
                block_ordinal,
                reduction_coefficient_count: source_coefficient_count,
            },
        });
    }
    Ok(actions)
}

fn aggregate_relation_replay_coefficient_position_counts(
    relation_variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, u64>, CommonProofProverError> {
    let mut coefficient_counts =
        persisted_pre_challenge_column_coefficient_position_counts(relation_variant)?;
    let derived_column_ordinals = relation_reversed_column_bindings(relation_variant)?
        .into_iter()
        .map(|(_, reversed_column_ordinal)| reversed_column_ordinal)
        .chain(ordered_integer_lift_auxiliary_column_ordinals(
            relation_variant,
        )?);
    for column_ordinal in derived_column_ordinals {
        let descriptor = relation_variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let coefficient_count = descriptor.source_degree_bound_exclusive();
        if coefficient_count == 0
            || coefficient_counts
                .insert(column_ordinal, coefficient_count)
                .is_some()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(coefficient_counts)
}

fn phase_geometry(
    construction_plan: &RowCodeWhirConstructionPlan,
    phase: RowCodeWhirPhase,
) -> Result<RowEncodingGeometry, CommonProofProverError> {
    match phase {
        RowCodeWhirPhase::Base => construction_plan
            .base_phase
            .as_ref()
            .map(|phase| phase.geometry),
        RowCodeWhirPhase::Auxiliary => construction_plan
            .auxiliary_phase
            .as_ref()
            .map(|phase| phase.geometry),
        RowCodeWhirPhase::Quotient => Some(construction_plan.quotient_phase.geometry),
    }
    .ok_or(CommonProofProverError::InvalidColumn)
}

fn allocate_aggregate_batch(
    coefficient_count: usize,
    column_count: usize,
) -> Result<Vec<Vec<ChallengeField>>, CommonProofProverError> {
    let mut columns = Vec::new();
    columns
        .try_reserve_exact(column_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for _ in 0..column_count {
        let mut column = Vec::new();
        column
            .try_reserve_exact(coefficient_count)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        column.resize(coefficient_count, ChallengeField::ZERO);
        columns.push(column);
    }
    Ok(columns)
}

fn aggregate_action_catalog_digest(
    actions: &[ExactSameSecretAggregateSourceAction],
) -> Result<[u8; 64], CommonProofProverError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        &u64::try_from(actions.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .to_le_bytes(),
    );
    for action in actions {
        encoded.extend_from_slice(
            &u64::try_from(action.action_ordinal)
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .to_le_bytes(),
        );
        match action.target {
            ExactSameSecretAggregateSourceTarget::RelationColumn { column_ordinal } => {
                encoded.push(0);
                encoded.extend_from_slice(&column_ordinal.to_le_bytes());
                encoded.extend_from_slice(&0_u32.to_le_bytes());
            }
            ExactSameSecretAggregateSourceTarget::OpenedPolynomial { source } => {
                encoded.push(1);
                match source {
                    RowCodeWhirOpenedPolynomialSource::QuotientComponent { component_ordinal } => {
                        encoded.extend_from_slice(&component_ordinal.to_le_bytes());
                        encoded.extend_from_slice(&0_u32.to_le_bytes());
                    }
                    RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { mask_ordinal } => {
                        encoded.extend_from_slice(&mask_ordinal.to_le_bytes());
                        encoded.extend_from_slice(&1_u32.to_le_bytes());
                    }
                }
            }
        }
        encoded.extend_from_slice(&(action.value_type as u16).to_le_bytes());
        for value in [
            action.source_coefficient_count,
            action.source_range_start,
            action.source_range_length,
        ] {
            encoded.extend_from_slice(
                &u64::try_from(value)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .to_le_bytes(),
            );
        }
    }
    Ok(hash_framed_parts_512(
        AGGREGATE_SOURCE_ACTION_CATALOG_DOMAIN,
        &[&encoded],
    ))
}

#[allow(clippy::too_many_arguments)]
fn aggregate_source_binding_digest(
    construction_identity_hash: [u8; 64],
    source_catalog_hash: [u8; 64],
    stable_generation_binding_hash: [u8; 64],
    source_replay_identity_digest: [u8; 64],
    transcript_prefix_authority_binding_digest: [u8; 64],
    opening_points: &[ProofChallengeExtensionElement],
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement],
    action_catalog_digest: [u8; 64],
) -> Result<[u8; 64], CommonProofProverError> {
    let mut transcript_material = Vec::new();
    for values in [
        opening_points,
        out_of_domain_evaluations,
        opening_batch_mask_chunk_evaluations,
    ] {
        transcript_material.extend_from_slice(
            &u64::try_from(values.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .to_le_bytes(),
        );
        for value in values {
            for coordinate in value.canonical_coordinates() {
                transcript_material.extend_from_slice(&coordinate.to_le_bytes());
            }
        }
    }
    Ok(hash_framed_parts_512(
        AGGREGATE_SOURCE_BINDING_DOMAIN,
        &[
            &construction_identity_hash,
            &source_catalog_hash,
            &stable_generation_binding_hash,
            &source_replay_identity_digest,
            &transcript_prefix_authority_binding_digest,
            &action_catalog_digest,
            &transcript_material,
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected_plan_actions() -> (
        RowCodeWhirConstructionPlan,
        RelationPlanVariant,
        Vec<ExactSameSecretAggregateSourceAction>,
    ) {
        let (relation_plan, relation_variant, _) = super::super::production_same_secret_relation()
            .expect("compile the production same-secret relation");
        let construction_plan = relation_plan.row_code_whir_construction_plan().clone();
        let bound_claims = relation_variant
            .ordered_opening_claims()
            .iter()
            .filter_map(|claim| {
                let column_ordinal = claim.column_ordinal()?;
                relation_variant
                    .ordered_columns()
                    .get(column_ordinal as usize)
                    .is_some_and(|column| {
                        matches!(column.origin(), RelationColumnOrigin::BoundTree { .. })
                    })
                    .then_some(column_ordinal)
            })
            .map(|column_ordinal| {
                let bound_tree_ordinal = construction_plan
                    .bound_trees
                    .iter()
                    .find(|tree| {
                        tree.ordered_columns
                            .iter()
                            .any(|column| column.column_ordinal == column_ordinal)
                    })
                    .expect("bound column belongs to a planned tree")
                    .bound_tree_ordinal;
                let reduction_block_ordinal = construction_plan
                    .bound_reduction_blocks
                    .iter()
                    .position(|block| {
                        block
                            .ordered_bound_tree_ordinals
                            .contains(&bound_tree_ordinal)
                    })
                    .expect("bound tree belongs to a reduction block");
                RowCodeWhirBoundOpeningClaim {
                    column_ordinal,
                    opening_point: ChallengeField::ZERO,
                    claimed_value: ChallengeField::ZERO,
                    batching_weight: ChallengeField::ZERO,
                    reduction_block_ordinal,
                }
            })
            .collect::<Vec<_>>();
        let actions =
            exact_aggregate_source_actions(&construction_plan, &relation_variant, &bound_claims)
                .expect("derive the selected aggregate source catalog");
        (construction_plan, relation_variant, actions)
    }

    #[test]
    fn selected_action_catalog_uses_exact_replay_source_ranges_without_materializing_witness() {
        let (construction_plan, relation_variant, actions) = selected_plan_actions();
        let replay_counts =
            aggregate_relation_replay_coefficient_position_counts(&relation_variant)
                .expect("derive selected replay source counts");
        let phase_action_count = construction_plan
            .base_phase
            .iter()
            .chain(&construction_plan.auxiliary_phase)
            .flat_map(|phase| &phase.rows)
            .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
            .count()
            + construction_plan
                .quotient_phase
                .rows
                .iter()
                .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
                .count();
        assert_eq!(
            actions.len(),
            phase_action_count
                + relation_variant
                    .ordered_opening_claims()
                    .iter()
                    .filter(|claim| {
                        claim.column_ordinal().is_some_and(|column_ordinal| {
                            relation_variant
                                .ordered_columns()
                                .get(column_ordinal as usize)
                                .is_some_and(|column| {
                                    matches!(
                                        column.origin(),
                                        RelationColumnOrigin::BoundTree { .. }
                                    )
                                })
                        })
                    })
                    .count()
        );
        for (action_ordinal, action) in actions.iter().copied().enumerate() {
            assert_eq!(action.action_ordinal, action_ordinal);
            assert!(action.source_range_length() > 0);
            assert!(
                action
                    .source_range_start()
                    .checked_add(action.source_range_length())
                    .is_some_and(|end| end <= action.source_coefficient_count())
            );
            if let ExactSameSecretAggregateSourceTarget::RelationColumn { column_ordinal } =
                action.target()
            {
                assert_eq!(
                    u64::try_from(action.source_coefficient_count())
                        .expect("source count fits u64"),
                    replay_counts[&column_ordinal]
                );
            }
        }
    }

    #[test]
    fn action_catalog_digest_binds_order_target_type_count_and_range() {
        let (_, _, actions) = selected_plan_actions();
        let expected_digest =
            aggregate_action_catalog_digest(&actions).expect("hash the selected action catalog");
        assert_ne!(expected_digest, [0_u8; 64]);

        let mut changed_count = actions.clone();
        changed_count[0].source_coefficient_count += 1;
        assert_ne!(
            aggregate_action_catalog_digest(&changed_count).expect("hash changed source count"),
            expected_digest
        );
        let mut changed_range = actions.clone();
        changed_range[0].source_range_start += 1;
        assert_ne!(
            aggregate_action_catalog_digest(&changed_range).expect("hash changed source range"),
            expected_digest
        );
        let mut changed_order = actions;
        changed_order.swap(0, 1);
        assert_ne!(
            aggregate_action_catalog_digest(&changed_order).expect("hash changed action order"),
            expected_digest
        );
    }

    #[test]
    fn interleaved_witness_uses_the_same_reversed_selector_layout_as_sumcheck() {
        use crate::bgv::proof_suite::row_code_whir::oracle_geometry::interleaved_source_index;

        const TABLE_WIDTH: usize = 4;
        assert_eq!(
            (0..TABLE_WIDTH)
                .map(
                    |column_ordinal| interleaved_source_index(7, column_ordinal, TABLE_WIDTH)
                        .expect("valid aggregate coordinate")
                        % TABLE_WIDTH
                )
                .collect::<Vec<_>>(),
            vec![0, 2, 1, 3]
        );
        let all_indices = (0..5)
            .flat_map(|coefficient_ordinal| {
                (0..TABLE_WIDTH).map(move |column_ordinal| {
                    interleaved_source_index(coefficient_ordinal, column_ordinal, TABLE_WIDTH)
                        .expect("valid aggregate coordinate")
                })
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(all_indices.len(), 5 * TABLE_WIDTH);
        assert!(interleaved_source_index(0, TABLE_WIDTH, TABLE_WIDTH).is_err());
    }

    #[test]
    fn materializer_refuses_changed_action_and_wrong_polynomial_count_before_progress() {
        let (construction_plan, _, actions) = selected_plan_actions();
        let expected_action = actions[0];
        let mut materializer = ExactSameSecretAggregateSource {
            construction_plan,
            actions: vec![expected_action],
            next_action_index: 0,
            row_pad_seeds: Some(Zeroizing::new([[1_u8; 32]; 3])),
            phase_row_witness: Vec::new(),
            aggregate_columns: None,
            current_batch_ordinal: 0,
            coefficient_count: 1,
            aggregate_table_width: 2,
            relation_context: None,
            point_row_weights: Some(Vec::new()),
            bound_claims: Vec::new(),
            metadata: None,
            challenger: None,
        };
        let mut changed_action = expected_action;
        changed_action.action_ordinal += 1;
        assert!(matches!(
            materializer.supply_source_range(
                changed_action,
                CommonProofSourcePolynomial::from_base_coefficients(Vec::new()),
            ),
            Err(CommonProofProverError::InvalidInput)
        ));
        assert_eq!(materializer.next_action(), Some(expected_action));
        assert!(matches!(
            materializer.supply_source_range(
                expected_action,
                CommonProofSourcePolynomial::from_base_coefficients(Vec::new()),
            ),
            Err(CommonProofProverError::InvalidColumn)
        ));
        assert_eq!(materializer.next_action(), Some(expected_action));
    }
}
