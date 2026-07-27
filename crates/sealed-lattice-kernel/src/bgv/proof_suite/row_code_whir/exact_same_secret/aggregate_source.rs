//! Incremental aggregate witness materialization for the exact same-secret proof.
//!
//! The materializer consumes one plan-addressed replay polynomial at a time.
//! It owns the transcript-derived weights and the only four aggregate columns;
//! no complete phase matrix or duplicate stacked polynomial is retained.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::{layout::Witness, table::TableShape};
use zeroize::Zeroizing;

use super::exact_proof::{
    ExactBoundOpeningClaim, ExactPointRowWeights, ExactSameSecretOpeningScheduleContinuation,
    ExactSameSecretProofShape, bound_column_locations, checked_exact_same_secret_proof_shape,
    derive_bound_opening_claims, derive_exact_point_row_weights,
    derive_exact_same_secret_opening_schedule_after_observed_commitment, divide_polynomial_opening,
    exact_same_secret_opening_schedule_continuation,
};
use super::{
    ExactBasePhaseLayout, ExactSameSecretTranscriptPrefixAuthorityBinding,
    LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT, OPENING_BATCH_MASK_CHUNK_COUNT,
};
use crate::bgv::proof_suite::prover::{
    CommonProofSourcePolynomialRequestContext,
    persisted_pre_challenge_column_coefficient_position_counts,
};
use crate::bgv::proof_suite::relation_plan::{
    BoundTreeRootUse, RelationColumnValueType, RelationPlanCheckContext, RelationPlanVariant,
};
use crate::bgv::proof_suite::transcript::RowCodeWhirTranscript;
use crate::bgv::proof_suite::{
    CommonProofProverError, CommonProofSourcePolynomial, ProofChallengeExtensionElement,
};
use crate::hashing::hash_framed_parts_512;

use super::super::construction_plan::{
    RowCodeWhirConstructionPlan, RowCodeWhirOpenedPolynomialSource, RowCodeWhirPhase,
};
use super::super::plain_whir::{
    plain_aggregate_challenger_from_transcript, plain_aggregate_pcs_for_construction_plan,
};
use super::super::row_encoding::{RowCodeHighHalfSource, RowEncodingGeometry, encode_row};
use super::super::same_secret_source_manifest::SameSecretAuthenticatedSourceManifest;
use super::super::{ChallengeField, ExtensionFieldChallenger};

const AGGREGATE_SOURCE_BINDING_DOMAIN: &str =
    "sealed-lattice/exact-same-secret/aggregate-source-binding/v1";
const AGGREGATE_SOURCE_ACTION_CATALOG_DOMAIN: &str =
    "sealed-lattice/exact-same-secret/aggregate-source-action-catalog/v1";
const AGGREGATE_COLUMN_COUNT: usize = 4;

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

/// The only materialized aggregate columns. Each column has the selected
/// `2^19` local evaluations. The retained prover consumes these columns by
/// ownership; cloning is intentionally unavailable.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateWitness {
    stacked_polynomial: Option<Poly<ChallengeField>>,
    table_variable_count: usize,
    table_width: usize,
    folding_factor: usize,
}

impl ExactSameSecretAggregateWitness {
    pub(in crate::bgv::proof_suite::row_code_whir) fn into_witness(
        mut self,
    ) -> Result<Witness<ChallengeField>, CommonProofProverError> {
        let stacked_polynomial = self
            .stacked_polynomial
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        Witness::from_interleaved_poly(
            vec![TableShape::new(self.table_variable_count, self.table_width)],
            self.folding_factor,
            stacked_polynomial,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)
    }
}

impl Drop for ExactSameSecretAggregateWitness {
    fn drop(&mut self) {
        if let Some(polynomial) = self.stacked_polynomial.as_mut() {
            polynomial.as_mut_slice().fill(ChallengeField::ZERO);
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
    opening_schedule_continuation: Option<ExactSameSecretOpeningScheduleContinuation>,
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
    ) -> Result<super::exact_proof::ExactSameSecretOpeningSchedule, CommonProofProverError> {
        let continuation = self
            .opening_schedule_continuation
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        derive_exact_same_secret_opening_schedule_after_observed_commitment(
            continuation,
            construction_plan,
            relation_context,
            &self.opening_points,
            challenger,
        )
    }
}

/// Completed move-only handoff to retained WHIR generation.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretAggregateMaterializedSource {
    pub(in crate::bgv::proof_suite::row_code_whir) witness: ExactSameSecretAggregateWitness,
    pub(in crate::bgv::proof_suite::row_code_whir) metadata: ExactSameSecretAggregateMetadata,
    challenger: ExtensionFieldChallenger,
    row_pad_seeds: Zeroizing<[[u8; 32]; 3]>,
}

impl ExactSameSecretAggregateMaterializedSource {
    pub(in crate::bgv::proof_suite::row_code_whir) fn into_parts(
        self,
    ) -> (
        ExactSameSecretAggregateWitness,
        ExactSameSecretAggregateMetadata,
        ExtensionFieldChallenger,
        Zeroizing<[[u8; 32]; 3]>,
    ) {
        (
            self.witness,
            self.metadata,
            self.challenger,
            self.row_pad_seeds,
        )
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn into_witness(
        self,
    ) -> Result<
        (
            Witness<ChallengeField>,
            ExactSameSecretAggregateMetadata,
            ExtensionFieldChallenger,
            Zeroizing<[[u8; 32]; 3]>,
        ),
        CommonProofProverError,
    > {
        let (witness, metadata, challenger, row_pad_seeds) = self.into_parts();
        Ok((witness.into_witness()?, metadata, challenger, row_pad_seeds))
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
    aggregate_polynomial: Option<Vec<ChallengeField>>,
    checked_shape: Option<ExactSameSecretProofShape>,
    relation_context: Option<RelationPlanCheckContext>,
    point_row_weights: Option<[ExactPointRowWeights; 3]>,
    bound_claims: Vec<ExactBoundOpeningClaim>,
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
        transcript_prefix_authority_binding: &ExactSameSecretTranscriptPrefixAuthorityBinding,
        opening_points: Vec<ProofChallengeExtensionElement>,
        out_of_domain_evaluations: &[ProofChallengeExtensionElement],
        opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement],
        row_pad_seeds: Zeroizing<[[u8; 32]; 3]>,
        row_code_whir_transcript: RowCodeWhirTranscript,
    ) -> Result<Self, CommonProofProverError> {
        if source_replay_identity_digest == [0_u8; 64]
            || opening_points.len() != 3
            || opening_batch_mask_chunk_evaluations.len() != OPENING_BATCH_MASK_CHUNK_COUNT
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let relation_plan_variant_hash = relation_variant
            .canonical_hash()
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        let checked_shape = checked_exact_same_secret_proof_shape(
            construction_plan,
            relation_variant,
            relation_context,
            source_request_context.relation_plan_hash(),
            relation_plan_variant_hash,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        source_manifest
            .validate_against(construction_plan, relation_variant, relation_context)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        if checked_shape.construction_plan_identity_hash()
            != source_manifest.construction_identity()
            || source_request_context.relation_plan_variant_hash() != relation_plan_variant_hash
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let fiat_shamir_binding = transcript_prefix_authority_binding.fiat_shamir_binding();
        if fiat_shamir_binding.protocol_version() != source_request_context.protocol_version()
            || fiat_shamir_binding.suite_identifier() != source_request_context.suite_identifier()
            || fiat_shamir_binding.application_statement_schema_identifier()
                != source_request_context.application_statement_schema_identifier()
            || fiat_shamir_binding.application_statement_hash()
                != source_request_context.application_statement_hash()
            || fiat_shamir_binding.relation_plan_hash()
                != source_request_context.relation_plan_hash()
            || fiat_shamir_binding.relation_plan_variant_hash() != relation_plan_variant_hash
            || fiat_shamir_binding.construction_plan_identity_hash()
                != checked_shape.construction_plan_identity_hash()
        {
            return Err(CommonProofProverError::InvalidInput);
        }

        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        let mut challenger = plain_aggregate_challenger_from_transcript(
            &pcs,
            construction_plan.whir_plan(),
            row_code_whir_transcript,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let base_layout = ExactBasePhaseLayout::for_tree_role(
            relation_variant,
            crate::bgv::proof_suite::ProofTreeRole::BaseOracle,
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let auxiliary_layout = ExactBasePhaseLayout::for_tree_role(
            relation_variant,
            crate::bgv::proof_suite::ProofTreeRole::AuxiliaryOracle,
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let point_row_weights = derive_exact_point_row_weights(
            &mut challenger,
            &base_layout,
            &auxiliary_layout,
            opening_points[0],
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let bound_claims = derive_bound_opening_claims(
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
            checked_shape.construction_plan_identity_hash(),
            source_manifest.catalog_hash(),
            source_request_context.stable_generation_binding_hash(),
            source_replay_identity_digest,
            transcript_prefix_authority_binding,
            &opening_points,
            out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations,
            action_catalog_digest,
        )?;
        let coefficient_count = construction_plan
            .base_phase
            .as_ref()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .geometry
            .encoded_column_count;
        if coefficient_count == 0
            || construction_plan.aggregate_table_width() != AGGREGATE_COLUMN_COUNT
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let stacked_coefficient_count = coefficient_count
            .checked_mul(AGGREGATE_COLUMN_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let mut aggregate_polynomial = Vec::new();
        aggregate_polynomial
            .try_reserve_exact(stacked_coefficient_count)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        aggregate_polynomial.resize(stacked_coefficient_count, ChallengeField::ZERO);
        let action_count = actions.len();
        Ok(Self {
            construction_plan: construction_plan.clone(),
            actions,
            next_action_index: 0,
            row_pad_seeds: Some(row_pad_seeds),
            phase_row_witness: Vec::new(),
            aggregate_polynomial: Some(aggregate_polynomial),
            checked_shape: Some(checked_shape),
            relation_context: Some(relation_context.clone()),
            point_row_weights: Some(point_row_weights),
            bound_claims,
            metadata: Some(ExactSameSecretAggregateMetadata {
                binding_digest,
                construction_identity_hash: checked_shape.construction_plan_identity_hash(),
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

    pub(in crate::bgv::proof_suite::row_code_whir) fn finish(
        mut self,
    ) -> Result<ExactSameSecretAggregateMaterializedSource, CommonProofProverError> {
        if self.next_action_index != self.actions.len() || !self.phase_row_witness.is_empty() {
            return Err(CommonProofProverError::InvalidInput);
        }
        let stacked_polynomial = Poly::new(
            self.aggregate_polynomial
                .take()
                .ok_or(CommonProofProverError::InvalidInput)?,
        );
        let expected_coefficient_count = self
            .construction_plan
            .base_phase
            .as_ref()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .geometry
            .encoded_column_count;
        if stacked_polynomial.num_evals()
            != expected_coefficient_count
                .checked_mul(AGGREGATE_COLUMN_COUNT)
                .ok_or(CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let row_pad_seeds = self
            .row_pad_seeds
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let checked_shape = self
            .checked_shape
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let relation_context = self
            .relation_context
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let point_row_weights = self
            .point_row_weights
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let opening_schedule_continuation = exact_same_secret_opening_schedule_continuation(
            checked_shape,
            &relation_context,
            point_row_weights,
        );
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
                stacked_polynomial: Some(stacked_polynomial),
                table_variable_count: self.construction_plan.parameters.table_variable_count,
                table_width: AGGREGATE_COLUMN_COUNT,
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
        let row_pad_seed = self
            .row_pad_seeds
            .as_ref()
            .and_then(|seeds| seeds.get(phase_index(phase)))
            .ok_or(CommonProofProverError::InvalidInput)?;
        let mut encoded_row = encode_row(
            geometry,
            row_ordinal,
            &self.phase_row_witness,
            RowCodeHighHalfSource::PrivateMaskSeed(row_pad_seed),
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let aggregate_polynomial = self
            .aggregate_polynomial
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)?;
        for opening_point_ordinal in 0..3 {
            let point_row_weights = self
                .point_row_weights
                .as_ref()
                .ok_or(CommonProofProverError::InvalidInput)?;
            let weight = match phase {
                RowCodeWhirPhase::Base => point_row_weights[opening_point_ordinal]
                    .base
                    .get(row_ordinal),
                RowCodeWhirPhase::Auxiliary => point_row_weights[opening_point_ordinal]
                    .auxiliary
                    .get(row_ordinal),
                RowCodeWhirPhase::Quotient => point_row_weights[opening_point_ordinal]
                    .quotient
                    .get(row_ordinal),
            }
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)?;
            if weight != ChallengeField::ZERO {
                for (coefficient_ordinal, encoded) in encoded_row.iter().copied().enumerate() {
                    let aggregate_index =
                        interleaved_aggregate_index(coefficient_ordinal, opening_point_ordinal)?;
                    *aggregate_polynomial
                        .get_mut(aggregate_index)
                        .ok_or(CommonProofProverError::InvalidColumn)? +=
                        weight * ChallengeField::from(encoded);
                }
            }
        }
        encoded_row.fill(Goldilocks::ZERO);
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
        let block_coefficient_count = 1_usize
            .checked_shl(
                u32::try_from(block.polynomial_variable_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if quotient.len() > block_coefficient_count {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let local_destination_start = block_ordinal
            .checked_mul(block_coefficient_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let aggregate_polynomial = self
            .aggregate_polynomial
            .as_mut()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        for (coefficient_ordinal, coefficient) in quotient.into_iter().enumerate() {
            let aggregate_index = local_destination_start
                .checked_add(coefficient_ordinal)
                .ok_or(CommonProofProverError::CountOverflow)
                .and_then(|index| interleaved_aggregate_index(index, 3))?;
            *aggregate_polynomial
                .get_mut(aggregate_index)
                .ok_or(CommonProofProverError::InvalidOpening)? +=
                claim.batching_weight * coefficient;
        }
        Ok(())
    }

    fn clear_secret_material(&mut self) {
        self.phase_row_witness.fill(Goldilocks::ZERO);
        self.phase_row_witness.clear();
        if let Some(polynomial) = self.aggregate_polynomial.as_mut() {
            polynomial.fill(ChallengeField::ZERO);
            polynomial.clear();
        }
        self.aggregate_polynomial = None;
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
    bound_claims: &[ExactBoundOpeningClaim],
) -> Result<Vec<ExactSameSecretAggregateSourceAction>, CommonProofProverError> {
    let persisted_coefficient_counts =
        persisted_pre_challenge_column_coefficient_position_counts(relation_variant)?;
    let mut actions = Vec::new();
    for phase in [RowCodeWhirPhase::Base, RowCodeWhirPhase::Auxiliary] {
        let phase_plan = match phase {
            RowCodeWhirPhase::Base => construction_plan.base_phase.as_ref(),
            RowCodeWhirPhase::Auxiliary => construction_plan.auxiliary_phase.as_ref(),
            RowCodeWhirPhase::Quotient => None,
        }
        .ok_or(CommonProofProverError::InvalidColumn)?;
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
                    *persisted_coefficient_counts
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

    let locations = bound_column_locations(relation_variant)
        .map_err(|_| CommonProofProverError::InvalidOpening)?;
    for (claim_ordinal, claim) in bound_claims.iter().enumerate() {
        let (bound_tree_ordinal, _, root_use) = locations
            .get(&claim.column_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        let block_ordinal =
            bound_reduction_block_for_tree(construction_plan, bound_tree_ordinal, root_use)?;
        let maximum_reduction_coefficient_count = usize::try_from(
            construction_plan.bound_reduction_blocks[block_ordinal]
                .maximum_source_degree_bound_exclusive,
        )
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
                != construction_plan.bound_reduction_blocks[block_ordinal]
                    .maximum_source_degree_bound_exclusive
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let source_coefficient_count = usize::try_from(
            *persisted_coefficient_counts
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

fn bound_reduction_block_for_tree(
    construction_plan: &RowCodeWhirConstructionPlan,
    bound_tree_ordinal: usize,
    root_use: BoundTreeRootUse,
) -> Result<usize, CommonProofProverError> {
    let bound_tree_ordinal =
        u32::try_from(bound_tree_ordinal).map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut matching = construction_plan
        .bound_reduction_blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| {
            block
                .ordered_bound_tree_ordinals
                .contains(&bound_tree_ordinal)
        })
        .filter(|(_, block)| {
            block
                .ordered_bound_tree_ordinals
                .iter()
                .all(|tree_ordinal| {
                    construction_plan
                        .bound_trees
                        .get(usize::try_from(*tree_ordinal).unwrap_or(usize::MAX))
                        .is_some_and(|tree| tree.root_use == root_use)
                })
        })
        .map(|(block_ordinal, _)| block_ordinal);
    let block_ordinal = matching
        .next()
        .ok_or(CommonProofProverError::InvalidOpening)?;
    if matching.next().is_some() {
        return Err(CommonProofProverError::InvalidOpening);
    }
    Ok(block_ordinal)
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

fn interleaved_aggregate_index(
    coefficient_ordinal: usize,
    logical_column_ordinal: usize,
) -> Result<usize, CommonProofProverError> {
    if !AGGREGATE_COLUMN_COUNT.is_power_of_two() || logical_column_ordinal >= AGGREGATE_COLUMN_COUNT
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let selector_variable_count = usize::try_from(AGGREGATE_COLUMN_COUNT.ilog2())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let selector_index =
        logical_column_ordinal.reverse_bits() >> (usize::BITS as usize - selector_variable_count);
    coefficient_ordinal
        .checked_mul(AGGREGATE_COLUMN_COUNT)
        .and_then(|index| index.checked_add(selector_index))
        .ok_or(CommonProofProverError::CountOverflow)
}

const fn phase_index(phase: RowCodeWhirPhase) -> usize {
    match phase {
        RowCodeWhirPhase::Base => 0,
        RowCodeWhirPhase::Auxiliary => 1,
        RowCodeWhirPhase::Quotient => 2,
    }
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
    authority_binding: &ExactSameSecretTranscriptPrefixAuthorityBinding,
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
    let fiat_shamir_binding = authority_binding.fiat_shamir_binding();
    let protocol_version = fiat_shamir_binding.protocol_version().to_le_bytes();
    let roster_position = fiat_shamir_binding.roster_position().to_le_bytes();
    let application_statement_schema_identifier = fiat_shamir_binding
        .application_statement_schema_identifier()
        .to_le_bytes();
    let mut ordered_source_roots = Vec::with_capacity(11 * 64);
    for root in fiat_shamir_binding.ordered_source_roots() {
        ordered_source_roots.extend_from_slice(root);
    }
    let generation_binding_hash = authority_binding.generation_binding_hash();
    let attempt_identifier = authority_binding.attempt_identifier();
    Ok(hash_framed_parts_512(
        AGGREGATE_SOURCE_BINDING_DOMAIN,
        &[
            &construction_identity_hash,
            &source_catalog_hash,
            &stable_generation_binding_hash,
            &source_replay_identity_digest,
            &protocol_version,
            &fiat_shamir_binding.suite_identifier(),
            &fiat_shamir_binding.ceremony_context_hash(),
            &fiat_shamir_binding.action_context_hash(),
            &fiat_shamir_binding.participant_identity(),
            &roster_position,
            &fiat_shamir_binding.proof_application_slot_hash(),
            &application_statement_schema_identifier,
            &fiat_shamir_binding.application_statement_hash(),
            &fiat_shamir_binding.proof_header_hash(),
            &fiat_shamir_binding.relation_plan_hash(),
            &fiat_shamir_binding.relation_plan_variant_hash(),
            &fiat_shamir_binding.construction_plan_identity_hash(),
            &fiat_shamir_binding.oracle_equation_catalog_hash(),
            &fiat_shamir_binding.setup_proof_context_hash(),
            &ordered_source_roots,
            &generation_binding_hash,
            &attempt_identifier,
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
        let bound_claims = bound_column_locations(&relation_variant)
            .expect("derive selected bound column locations")
            .keys()
            .copied()
            .map(|column_ordinal| ExactBoundOpeningClaim {
                column_ordinal,
                opening_point: ChallengeField::ZERO,
                claimed_value: ChallengeField::ZERO,
                batching_weight: ChallengeField::ZERO,
            })
            .collect::<Vec<_>>();
        let actions =
            exact_aggregate_source_actions(&construction_plan, &relation_variant, &bound_claims)
                .expect("derive the selected aggregate source catalog");
        (construction_plan, relation_variant, actions)
    }

    #[test]
    fn selected_action_catalog_uses_exact_persisted_source_ranges_without_materializing_witness() {
        let (construction_plan, relation_variant, actions) = selected_plan_actions();
        let persisted_counts =
            persisted_pre_challenge_column_coefficient_position_counts(&relation_variant)
                .expect("derive selected persisted source counts");
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
                + bound_column_locations(&relation_variant)
                    .expect("derive bound locations")
                    .len()
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
                    persisted_counts[&column_ordinal]
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
        assert_eq!(
            (0..AGGREGATE_COLUMN_COUNT)
                .map(
                    |column_ordinal| interleaved_aggregate_index(7, column_ordinal)
                        .expect("valid aggregate coordinate")
                        % AGGREGATE_COLUMN_COUNT
                )
                .collect::<Vec<_>>(),
            vec![0, 2, 1, 3]
        );
        let all_indices = (0..5)
            .flat_map(|coefficient_ordinal| {
                (0..AGGREGATE_COLUMN_COUNT).map(move |column_ordinal| {
                    interleaved_aggregate_index(coefficient_ordinal, column_ordinal)
                        .expect("valid aggregate coordinate")
                })
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(all_indices.len(), 5 * AGGREGATE_COLUMN_COUNT);
        assert!(matches!(
            interleaved_aggregate_index(0, AGGREGATE_COLUMN_COUNT),
            Err(CommonProofProverError::InvalidColumn)
        ));
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
            aggregate_polynomial: None,
            checked_shape: None,
            relation_context: None,
            point_row_weights: Some(core::array::from_fn(|_| ExactPointRowWeights {
                selectors: [ChallengeField::ZERO; 3],
                base: Vec::new(),
                auxiliary: Vec::new(),
                quotient: Vec::new(),
            })),
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
