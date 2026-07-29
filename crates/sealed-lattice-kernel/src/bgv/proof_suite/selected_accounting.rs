//! Canonical proof ceilings and runtime limits for the selected suite.

use crate::foundation::{
    CanonicalDecodeLimits, MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
    MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT, ProofObjectHeader,
};

use super::external_memory::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
};
use super::relation_plan::{RelationPlanCheckContext, RelationPlanVariant};
use super::row_code_whir::RowCodeWhirConstructionPlan;
use super::{
    CommonProofRuntimeLimits, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    selected_relation_plan_check_context, selected_relation_plans,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedProofAccountingError {
    CanonicalEncoding,
    InvalidProfile,
    CountOverflow,
    ResourcePlanning,
    #[cfg(test)]
    VariantResourcePlanning {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        stage: &'static str,
        measured_byte_length: Option<u64>,
    },
}

fn require_selected_row_code_whir_runtime_geometry(
    construction_plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<(), SelectedProofAccountingError> {
    use super::row_code_whir::construction_plan::{
        RowCodeWhirCheckpointBoundary, RowCodeWhirProofSectionRole,
    };

    let proof_sections = construction_plan.proof_sections();
    let checkpoints = construction_plan.checkpoints();
    let whir_plan = construction_plan.whir_plan();
    let proof_section_count = u32::try_from(proof_sections.len())
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let transcript_operation_count = u32::try_from(construction_plan.transcript_operations().len())
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let total_proof_section_item_count =
        proof_sections.iter().try_fold(0_u64, |total, section| {
            u64::try_from(section.item_count)
                .ok()
                .and_then(|item_count| total.checked_add(item_count))
                .ok_or(SelectedProofAccountingError::CountOverflow)
        })?;
    let parameters = construction_plan.selected_parameters();
    let external_memory = super::row_code_whir::planned_row_code_whir_external_memory_requirement(
        construction_plan,
        variant,
        relation_context,
    )
    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
    let maximum_external_memory_object_count =
        u32::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;

    if proof_sections.is_empty()
        || checkpoints.is_empty()
        || total_proof_section_item_count == 0
        || proof_sections.iter().enumerate().any(|(ordinal, section)| {
            u32::try_from(ordinal).ok() != Some(section.section_ordinal) || section.item_count == 0
        })
        || !matches!(
            proof_sections.last().map(|section| section.role),
            Some(RowCodeWhirProofSectionRole::AggregateWideOpening)
        )
        || checkpoints.iter().enumerate().any(|(ordinal, checkpoint)| {
            u32::try_from(ordinal).ok() != Some(checkpoint.checkpoint_ordinal)
                || checkpoint.next_transcript_operation_ordinal > transcript_operation_count
                || checkpoint.next_proof_section_ordinal > proof_section_count
        })
        || checkpoints.windows(2).any(|pair| {
            pair[0].next_transcript_operation_ordinal > pair[1].next_transcript_operation_ordinal
                || pair[0].next_proof_section_ordinal > pair[1].next_proof_section_ordinal
        })
        || !matches!(
            checkpoints.first().map(|checkpoint| checkpoint.boundary),
            Some(RowCodeWhirCheckpointBoundary::SourcesAndConstruction)
        )
        || checkpoints.last().is_none_or(|checkpoint| {
            !matches!(
                checkpoint.boundary,
                RowCodeWhirCheckpointBoundary::CompletedProofStream
            ) || checkpoint.next_transcript_operation_ordinal != transcript_operation_count
                || checkpoint.next_proof_section_ordinal != proof_section_count
        })
        || parameters.outer_query_count != construction_plan.outer_query_count()
        || parameters.direct_bound_query_count > parameters.outer_query_count
        || parameters.prior_proof_bound_query_count > parameters.direct_bound_query_count
        || whir_plan
            .rounds
            .first()
            .is_none_or(|round| round.query_epoch.query_count != parameters.outer_query_count)
        || external_memory.distinct_physical_object_count() == 0
        || external_memory.object_lifecycle_count()
            < external_memory.distinct_physical_object_count()
        || external_memory.distinct_physical_object_count() > maximum_external_memory_object_count
        || external_memory.step_count() == 0
        || external_memory.maximum_chunk_byte_length()
            != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
        || external_memory.maximum_transaction_payload_byte_length()
            < u64::from(external_memory.maximum_chunk_byte_length())
        || external_memory.peak_stored_byte_length() == 0
        || external_memory.peak_stored_byte_length()
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        || external_memory.total_written_byte_length() == 0
        || external_memory.total_read_byte_length() == 0
        || external_memory.transaction_count()
            < u64::from(external_memory.distinct_physical_object_count())
        || external_memory.local_record_seal_invocation_count() == 0
        || external_memory.local_record_seal_invocation_count()
            > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
        || external_memory.local_record_sealed_plaintext_byte_length() == 0
        || external_memory.local_record_sealed_plaintext_byte_length()
            > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }
    Ok(())
}

pub(crate) fn selected_proof_runtime_limits(
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
    variant: &RelationPlanVariant,
) -> Result<CommonProofRuntimeLimits, SelectedProofAccountingError> {
    let relation_context =
        selected_relation_plan_check_context(application_statement_schema_identifier)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;

    let relation_plans =
        selected_relation_plans().map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let mut matching_artifacts = relation_plans.iter().filter(|artifact| {
        artifact.application_statement_schema_identifier()
            == application_statement_schema_identifier
    });
    let artifact = matching_artifacts
        .next()
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    if matching_artifacts.next().is_some() || artifact.checked_context() != &relation_context {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let checked_variant = artifact
        .compiled_plan()
        .select_variant(variant.schedule_position(), variant.top_count())
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    if checked_variant != variant {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        artifact,
        variant.schedule_position(),
        variant.top_count(),
    )
    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    construction_plan
        .canonical_identity_hash()
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    require_selected_row_code_whir_runtime_geometry(
        &construction_plan,
        checked_variant,
        &relation_context,
    )?;

    CommonProofRuntimeLimits::new(
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
    )
    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)
}

#[cfg(test)]
pub(crate) mod resource_accounting {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::OnceLock,
    };

    use crate::{
        bgv::{
            evaluator::{
                program::{EvaluatorProgramKeyPositions, selected_evaluator_program_set},
                top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            },
            serialization::two_component_data_ciphertext_canonical_byte_length_ceiling_at_level,
            target_decryption::{
                kllps_release::KLLPS_PAIRED_TARGET_ROLE_COUNT,
                selected_target_partial_decryption_stream_byte_length,
            },
        },
        foundation::{
            FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings,
            ProofFamilyApplicationInventory, SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
            selected_evaluator_resource_accounting,
        },
    };

    use super::*;
    use crate::bgv::proof_suite::prover::CommonProofExternalMemoryRequirement;
    use crate::bgv::proof_suite::row_code_whir::construction_plan::{
        RowCodeWhirCheckpointBoundary, RowCodeWhirOpeningFrontierRole, RowCodeWhirPhase,
        RowCodeWhirProofSectionRole, RowCodeWhirQueryEpochPlan,
    };
    use crate::bgv::proof_suite::{
        MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, ProofLeafVisibility, ProofTreeRole,
        RelationProofTreeInput, SelectedApplicationStatementContext, StatementOwnedProofTreeInput,
        build_relation_bound_public_tree_catalog_entries,
        canonical_selected_application_statement_for_ceiling,
        merkle::maximum_minimal_frontier_node_count,
        relation_plan::{BoundTreeConstructionKind, RelationColumnOrigin, RelationTreeDescriptor},
        row_code_whir::{
            MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH,
            canonical_row_code_whir_aggregate_opening_section_byte_ledger,
            canonical_row_code_whir_family_body_byte_length_ceiling,
            planned_row_code_whir_external_memory_requirement,
            row_code_whir_verification_resident_memory_ceiling,
        },
        selected_ballot_validity_carrier_buffer_accounting, selected_evaluator_entry_positions,
        selected_galois_key_share_batch_schedule, selected_galois_key_share_relation_plan_input,
        selected_recipient_private_vss_payload_byte_length,
    };

    const SELECTED_PROOF_SIZE_TARGET_BYTE_LENGTH: usize = 5 * 1_024 * 1_024;
    const MERKLE_DIGEST_BYTE_LENGTH: usize = 64;
    const SECTION_COUNT_BYTE_LENGTH: usize = core::mem::size_of::<u32>();

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedCompactFrontierAccounting {
        role_code: u16,
        role_name: &'static str,
        phase_code: Option<u8>,
        associated_ordinal: Option<u32>,
        leaf_count: u64,
        query_count: u32,
        opened_value_byte_length: u64,
        maximum_frontier_node_count: u32,
        frontier_byte_length: u64,
        canonical_opening_byte_length: u64,
    }

    impl SelectedCompactFrontierAccounting {
        pub(crate) const fn role_code(self) -> u16 {
            self.role_code
        }

        pub(crate) const fn role_name(self) -> &'static str {
            self.role_name
        }

        pub(crate) const fn phase_code(self) -> Option<u8> {
            self.phase_code
        }

        pub(crate) const fn associated_ordinal(self) -> Option<u32> {
            self.associated_ordinal
        }

        pub(crate) const fn leaf_count(self) -> u64 {
            self.leaf_count
        }

        pub(crate) const fn query_count(self) -> u32 {
            self.query_count
        }

        pub(crate) const fn opened_value_byte_length(self) -> u64 {
            self.opened_value_byte_length
        }

        pub(crate) const fn maximum_frontier_node_count(self) -> u32 {
            self.maximum_frontier_node_count
        }

        pub(crate) const fn frontier_byte_length(self) -> u64 {
            self.frontier_byte_length
        }

        pub(crate) const fn canonical_opening_byte_length(self) -> u64 {
            self.canonical_opening_byte_length
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedAggregateOpeningSectionAccounting {
        section_name: &'static str,
        byte_length: u64,
    }

    impl SelectedAggregateOpeningSectionAccounting {
        pub(crate) const fn section_name(self) -> &'static str {
            self.section_name
        }

        pub(crate) const fn byte_length(self) -> u64 {
            self.byte_length
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedRowCodeWhirProofSectionAccounting {
        section_ordinal: u32,
        role_code: u16,
        role_name: &'static str,
        phase_code: Option<u8>,
        associated_ordinal: Option<u32>,
        item_count: u64,
    }

    impl SelectedRowCodeWhirProofSectionAccounting {
        pub(crate) const fn section_ordinal(self) -> u32 {
            self.section_ordinal
        }

        pub(crate) const fn role_code(self) -> u16 {
            self.role_code
        }

        pub(crate) const fn role_name(self) -> &'static str {
            self.role_name
        }

        pub(crate) const fn phase_code(self) -> Option<u8> {
            self.phase_code
        }

        pub(crate) const fn associated_ordinal(self) -> Option<u32> {
            self.associated_ordinal
        }

        pub(crate) const fn item_count(self) -> u64 {
            self.item_count
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedRowCodeWhirCheckpointAccounting {
        checkpoint_ordinal: u32,
        boundary_code: u16,
        boundary_name: &'static str,
        phase_code: Option<u8>,
        round_ordinal: Option<u32>,
        next_transcript_operation_ordinal: u32,
        next_proof_section_ordinal: u32,
    }

    impl SelectedRowCodeWhirCheckpointAccounting {
        pub(crate) const fn checkpoint_ordinal(self) -> u32 {
            self.checkpoint_ordinal
        }

        pub(crate) const fn boundary_code(self) -> u16 {
            self.boundary_code
        }

        pub(crate) const fn boundary_name(self) -> &'static str {
            self.boundary_name
        }

        pub(crate) const fn phase_code(self) -> Option<u8> {
            self.phase_code
        }

        pub(crate) const fn round_ordinal(self) -> Option<u32> {
            self.round_ordinal
        }

        pub(crate) const fn next_transcript_operation_ordinal(self) -> u32 {
            self.next_transcript_operation_ordinal
        }

        pub(crate) const fn next_proof_section_ordinal(self) -> u32 {
            self.next_proof_section_ordinal
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedRowCodeWhirQueryEpochAccounting {
        epoch_ordinal: u32,
        bit_length: u32,
        domain_size: u64,
        query_count: u32,
    }

    impl SelectedRowCodeWhirQueryEpochAccounting {
        pub(crate) const fn epoch_ordinal(self) -> u32 {
            self.epoch_ordinal
        }

        pub(crate) const fn bit_length(self) -> u32 {
            self.bit_length
        }

        pub(crate) const fn domain_size(self) -> u64 {
            self.domain_size
        }

        pub(crate) const fn query_count(self) -> u32 {
            self.query_count
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedRowCodeWhirConstructionResourceAccounting {
        construction_identity_hash: [u8; Hash512::BYTE_LENGTH],
        outer_query_count: u32,
        direct_bound_query_count: u32,
        prior_proof_bound_query_count: u32,
        aggregate_logical_column_count: u32,
        aggregate_table_width: u32,
        opening_batch_count: u32,
        transcript_operation_count: u32,
        ordered_proof_sections: Box<[SelectedRowCodeWhirProofSectionAccounting]>,
        ordered_checkpoints: Box<[SelectedRowCodeWhirCheckpointAccounting]>,
        ordered_query_epochs: Box<[SelectedRowCodeWhirQueryEpochAccounting]>,
        compact_frontiers: Box<[SelectedCompactFrontierAccounting]>,
        aggregate_opening_sections: Box<[SelectedAggregateOpeningSectionAccounting]>,
    }

    impl SelectedRowCodeWhirConstructionResourceAccounting {
        pub(crate) const fn construction_identity_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
            self.construction_identity_hash
        }

        pub(crate) const fn outer_query_count(&self) -> u32 {
            self.outer_query_count
        }

        pub(crate) const fn direct_bound_query_count(&self) -> u32 {
            self.direct_bound_query_count
        }

        pub(crate) const fn prior_proof_bound_query_count(&self) -> u32 {
            self.prior_proof_bound_query_count
        }

        pub(crate) const fn aggregate_logical_column_count(&self) -> u32 {
            self.aggregate_logical_column_count
        }

        pub(crate) const fn aggregate_table_width(&self) -> u32 {
            self.aggregate_table_width
        }

        pub(crate) const fn opening_batch_count(&self) -> u32 {
            self.opening_batch_count
        }

        pub(crate) const fn transcript_operation_count(&self) -> u32 {
            self.transcript_operation_count
        }

        pub(crate) fn ordered_proof_sections(
            &self,
        ) -> &[SelectedRowCodeWhirProofSectionAccounting] {
            &self.ordered_proof_sections
        }

        pub(crate) fn ordered_checkpoints(&self) -> &[SelectedRowCodeWhirCheckpointAccounting] {
            &self.ordered_checkpoints
        }

        pub(crate) fn ordered_query_epochs(&self) -> &[SelectedRowCodeWhirQueryEpochAccounting] {
            &self.ordered_query_epochs
        }

        pub(crate) fn compact_frontiers(&self) -> &[SelectedCompactFrontierAccounting] {
            &self.compact_frontiers
        }

        pub(crate) fn aggregate_opening_sections(
            &self,
        ) -> &[SelectedAggregateOpeningSectionAccounting] {
            &self.aggregate_opening_sections
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedProofVariantResourceAccounting {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        complete_action_application_multiplicity: u32,
        logical_entry_count: u32,
        relation_column_count: u32,
        verifier_sequence_relation_column_count: u32,
        bound_tree_relation_column_count: u32,
        prover_relation_column_count: u32,
        relation_constraint_count: u32,
        opening_claim_count: u32,
        canonical_header_byte_length: u64,
        canonical_family_body_byte_length: u64,
        canonical_proof_byte_length: u64,
        proof_size_target_margin_byte_length: u64,
        maximum_verifier_resident_byte_length: u64,
        generation_wasm_resident_hard_bound_byte_length: u64,
        external_memory_requirement: CommonProofExternalMemoryRequirement,
        construction: SelectedRowCodeWhirConstructionResourceAccounting,
    }

    impl SelectedProofVariantResourceAccounting {
        pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
            self.application_statement_schema_identifier
        }

        pub(crate) const fn schedule_position(&self) -> Option<u32> {
            self.schedule_position
        }

        pub(crate) const fn top_count(&self) -> Option<u16> {
            self.top_count
        }

        pub(crate) const fn complete_action_application_multiplicity(&self) -> u32 {
            self.complete_action_application_multiplicity
        }

        pub(crate) const fn logical_entry_count(&self) -> u32 {
            self.logical_entry_count
        }

        pub(crate) const fn relation_column_count(&self) -> u32 {
            self.relation_column_count
        }

        pub(crate) const fn verifier_sequence_relation_column_count(&self) -> u32 {
            self.verifier_sequence_relation_column_count
        }

        pub(crate) const fn bound_tree_relation_column_count(&self) -> u32 {
            self.bound_tree_relation_column_count
        }

        pub(crate) const fn prover_relation_column_count(&self) -> u32 {
            self.prover_relation_column_count
        }

        pub(crate) const fn relation_constraint_count(&self) -> u32 {
            self.relation_constraint_count
        }

        pub(crate) const fn opening_claim_count(&self) -> u32 {
            self.opening_claim_count
        }

        pub(crate) const fn canonical_header_byte_length(&self) -> u64 {
            self.canonical_header_byte_length
        }

        pub(crate) const fn canonical_family_body_byte_length(&self) -> u64 {
            self.canonical_family_body_byte_length
        }

        pub(crate) const fn canonical_proof_byte_length(&self) -> u64 {
            self.canonical_proof_byte_length
        }

        pub(crate) const fn proof_size_target_margin_byte_length(&self) -> u64 {
            self.proof_size_target_margin_byte_length
        }

        pub(crate) const fn maximum_verifier_resident_byte_length(&self) -> u64 {
            self.maximum_verifier_resident_byte_length
        }

        pub(crate) const fn generation_wasm_resident_hard_bound_byte_length(&self) -> u64 {
            self.generation_wasm_resident_hard_bound_byte_length
        }

        pub(crate) const fn external_memory_requirement(
            &self,
        ) -> CommonProofExternalMemoryRequirement {
            self.external_memory_requirement
        }

        pub(crate) const fn construction(
            &self,
        ) -> &SelectedRowCodeWhirConstructionResourceAccounting {
            &self.construction
        }
    }

    fn row_code_whir_phase_code(phase: RowCodeWhirPhase) -> u8 {
        match phase {
            RowCodeWhirPhase::Base => 1,
            RowCodeWhirPhase::Auxiliary => 2,
            RowCodeWhirPhase::Quotient => 3,
        }
    }

    fn proof_section_accounting(
        section: super::super::row_code_whir::construction_plan::RowCodeWhirProofSectionPlan,
    ) -> Result<SelectedRowCodeWhirProofSectionAccounting, SelectedProofAccountingError> {
        let (role_code, role_name, phase_code, associated_ordinal) = match section.role {
            RowCodeWhirProofSectionRole::RelationCommitment { phase } => (
                1,
                "relation-commitment",
                Some(row_code_whir_phase_code(phase)),
                None,
            ),
            RowCodeWhirProofSectionRole::OutOfDomainEvaluations => {
                (2, "out-of-domain-evaluations", None, None)
            }
            RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => {
                (3, "aggregate-wide-mask-evaluations", None, None)
            }
            RowCodeWhirProofSectionRole::AggregateCommitment => {
                (4, "aggregate-commitment", None, None)
            }
            RowCodeWhirProofSectionRole::AggregateWidePadCommitment => {
                (5, "aggregate-wide-pad-commitment", None, None)
            }
            RowCodeWhirProofSectionRole::PhaseOpenings { phase } => (
                6,
                "phase-openings",
                Some(row_code_whir_phase_code(phase)),
                None,
            ),
            RowCodeWhirProofSectionRole::BoundTreeOpenings { bound_tree_ordinal } => {
                (7, "bound-tree-openings", None, Some(bound_tree_ordinal))
            }
            RowCodeWhirProofSectionRole::AggregateWideOpening => {
                (8, "aggregate-wide-opening", None, None)
            }
        };
        Ok(SelectedRowCodeWhirProofSectionAccounting {
            section_ordinal: section.section_ordinal,
            role_code,
            role_name,
            phase_code,
            associated_ordinal,
            item_count: u64::try_from(section.item_count)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        })
    }

    fn checkpoint_accounting(
        checkpoint: super::super::row_code_whir::construction_plan::RowCodeWhirCheckpointPlan,
    ) -> SelectedRowCodeWhirCheckpointAccounting {
        let (boundary_code, boundary_name, phase_code, round_ordinal) = match checkpoint.boundary {
            RowCodeWhirCheckpointBoundary::SourcesAndConstruction => {
                (1, "sources-and-construction", None, None)
            }
            RowCodeWhirCheckpointBoundary::PhaseCommitment { phase } => (
                2,
                "phase-commitment",
                Some(row_code_whir_phase_code(phase)),
                None,
            ),
            RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => {
                (3, "relation-evaluations-and-mask", None, None)
            }
            RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries => {
                (4, "aggregate-commitments-and-queries", None, None)
            }
            RowCodeWhirCheckpointBoundary::WhirRound { round_ordinal } => {
                (5, "whir-round", None, Some(round_ordinal))
            }
            RowCodeWhirCheckpointBoundary::CompletedProofStream => {
                (6, "completed-proof-stream", None, None)
            }
        };
        SelectedRowCodeWhirCheckpointAccounting {
            checkpoint_ordinal: checkpoint.checkpoint_ordinal,
            boundary_code,
            boundary_name,
            phase_code,
            round_ordinal,
            next_transcript_operation_ordinal: checkpoint.next_transcript_operation_ordinal,
            next_proof_section_ordinal: checkpoint.next_proof_section_ordinal,
        }
    }

    fn query_epoch_accounting(
        epoch: RowCodeWhirQueryEpochPlan,
    ) -> Result<SelectedRowCodeWhirQueryEpochAccounting, SelectedProofAccountingError> {
        Ok(SelectedRowCodeWhirQueryEpochAccounting {
            epoch_ordinal: epoch.epoch_ordinal,
            bit_length: u32::try_from(epoch.bit_length)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            domain_size: u64::try_from(epoch.domain_size)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            query_count: u32::try_from(epoch.query_count)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        })
    }

    fn compact_frontier_accounting(
        construction_plan: &RowCodeWhirConstructionPlan,
    ) -> Result<Box<[SelectedCompactFrontierAccounting]>, SelectedProofAccountingError> {
        construction_plan
            .opening_frontier_geometries()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
            .into_iter()
            .map(|geometry| {
                let (role_code, role_name, phase_code, associated_ordinal) = match geometry.role {
                    RowCodeWhirOpeningFrontierRole::Phase { phase } => (
                        1,
                        "phase-opening",
                        Some(row_code_whir_phase_code(phase)),
                        None,
                    ),
                    RowCodeWhirOpeningFrontierRole::BoundTree { bound_tree_ordinal } => {
                        (2, "bound-tree-opening", None, Some(bound_tree_ordinal))
                    }
                };
                let maximum_frontier_node_count =
                    maximum_minimal_frontier_node_count(geometry.leaf_count, geometry.query_count)
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let frontier_byte_length = maximum_frontier_node_count
                    .checked_mul(MERKLE_DIGEST_BYTE_LENGTH)
                    .and_then(|length| length.checked_add(SECTION_COUNT_BYTE_LENGTH))
                    .ok_or(SelectedProofAccountingError::CountOverflow)?;
                let canonical_opening_byte_length = geometry
                    .opened_value_byte_length
                    .checked_add(frontier_byte_length)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?;
                Ok(SelectedCompactFrontierAccounting {
                    role_code,
                    role_name,
                    phase_code,
                    associated_ordinal,
                    leaf_count: u64::try_from(geometry.leaf_count)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    query_count: u32::try_from(geometry.query_count)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    opened_value_byte_length: u64::try_from(geometry.opened_value_byte_length)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    maximum_frontier_node_count: u32::try_from(maximum_frontier_node_count)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    frontier_byte_length: u64::try_from(frontier_byte_length)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    canonical_opening_byte_length: u64::try_from(canonical_opening_byte_length)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Vec::into_boxed_slice)
    }

    fn construction_accounting(
        construction_plan: &RowCodeWhirConstructionPlan,
    ) -> Result<SelectedRowCodeWhirConstructionResourceAccounting, SelectedProofAccountingError>
    {
        let parameters = construction_plan.selected_parameters();
        let ordered_proof_sections = construction_plan
            .proof_sections()
            .iter()
            .copied()
            .map(proof_section_accounting)
            .collect::<Result<Vec<_>, _>>()?;
        let ordered_checkpoints = construction_plan
            .checkpoints()
            .iter()
            .copied()
            .map(checkpoint_accounting)
            .collect::<Vec<_>>();
        let mut ordered_query_epochs = construction_plan
            .whir_plan()
            .rounds
            .iter()
            .map(|round| query_epoch_accounting(round.query_epoch))
            .collect::<Result<Vec<_>, _>>()?;
        ordered_query_epochs.push(query_epoch_accounting(
            construction_plan.whir_plan().final_round.query_epoch,
        )?);
        let aggregate_opening_sections =
            canonical_row_code_whir_aggregate_opening_section_byte_ledger(construction_plan)
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?
                .into_iter()
                .map(|(section_name, byte_length)| {
                    Ok(SelectedAggregateOpeningSectionAccounting {
                        section_name,
                        byte_length: u64::try_from(byte_length)
                            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
        if ordered_proof_sections.is_empty()
            || ordered_checkpoints.is_empty()
            || ordered_query_epochs.is_empty()
            || aggregate_opening_sections.is_empty()
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok(SelectedRowCodeWhirConstructionResourceAccounting {
            construction_identity_hash: construction_plan
                .canonical_identity_hash()
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?,
            outer_query_count: u32::try_from(construction_plan.outer_query_count())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            direct_bound_query_count: u32::try_from(parameters.direct_bound_query_count)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            prior_proof_bound_query_count: u32::try_from(parameters.prior_proof_bound_query_count)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            aggregate_logical_column_count: u32::try_from(
                construction_plan.aggregate_logical_column_count(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            aggregate_table_width: u32::try_from(construction_plan.aggregate_table_width())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            opening_batch_count: u32::try_from(construction_plan.opening_batches().len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            transcript_operation_count: u32::try_from(
                construction_plan.transcript_operations().len(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            ordered_proof_sections: ordered_proof_sections.into_boxed_slice(),
            ordered_checkpoints: ordered_checkpoints.into_boxed_slice(),
            ordered_query_epochs: ordered_query_epochs.into_boxed_slice(),
            compact_frontiers: compact_frontier_accounting(construction_plan)?,
            aggregate_opening_sections: aggregate_opening_sections.into_boxed_slice(),
        })
    }

    fn selected_relation_tree_inputs(
        variant: &RelationPlanVariant,
    ) -> Result<Vec<RelationProofTreeInput>, SelectedProofAccountingError> {
        variant
            .ordered_trees()
            .iter()
            .map(|tree| match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } => {
                    let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                        usize::try_from(*column_ordinal)
                            .ok()
                            .and_then(|column_index| variant.ordered_columns().get(column_index))
                            .is_some_and(|column| {
                                matches!(column.origin(), RelationColumnOrigin::Prover)
                            })
                    }) {
                        ProofLeafVisibility::SecretBearing
                    } else {
                        ProofLeafVisibility::Public
                    };
                    Ok(RelationProofTreeInput::ProofCreated {
                        tree_role: match proof_tree_role {
                            1 => ProofTreeRole::BaseOracle,
                            2 => ProofTreeRole::AuxiliaryOracle,
                            _ => return Err(SelectedProofAccountingError::InvalidProfile),
                        },
                        row_width: u32::try_from(ordered_column_ordinals.len())
                            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                        leaf_visibility,
                    })
                }
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    ordered_column_ordinals,
                    ..
                } => Ok(RelationProofTreeInput::BoundPublic(
                    match construction_kind {
                        BoundTreeConstructionKind::CommittedMaterial => {
                            StatementOwnedProofTreeInput::CommittedMaterial {
                                material_context_hash: [0; Hash512::BYTE_LENGTH],
                                expected_root: [0; Hash512::BYTE_LENGTH],
                            }
                        }
                        BoundTreeConstructionKind::SetupPolynomial => {
                            StatementOwnedProofTreeInput::SetupPolynomial {
                                public_polynomial_context_hash: [0; Hash512::BYTE_LENGTH],
                                row_width: u32::try_from(ordered_column_ordinals.len())
                                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                                expected_root: [0; Hash512::BYTE_LENGTH],
                            }
                        }
                    },
                )),
            })
            .collect()
    }

    fn selected_variant_logical_entry_count(
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
        proof_family_inventory: &ProofFamilyApplicationInventory,
    ) -> Result<u32, SelectedProofAccountingError> {
        if application_statement_schema_identifier
            == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        {
            let top_count = variant
                .top_count()
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            return u32::try_from(
                selected_evaluator_entry_positions(top_count)
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                    .len(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow);
        }
        if application_statement_schema_identifier
            == ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        {
            return u32::try_from(
                selected_galois_key_share_relation_plan_input()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                    .ordered_entries
                    .len(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow);
        }
        let family = proof_family_inventory
            .family_entry(application_statement_schema_identifier)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let physical_count = family.physical_proof_application_count();
        let logical_count = family.logical_relation_instance_count();
        if physical_count == 0 || logical_count % physical_count != 0 {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok(logical_count / physical_count)
    }

    fn selected_complete_action_variant_multiplicity(
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
        proof_family_inventory: &ProofFamilyApplicationInventory,
        key_positions: &EvaluatorProgramKeyPositions,
    ) -> Result<u32, SelectedProofAccountingError> {
        let family_physical_count = proof_family_inventory
            .family_entry(application_statement_schema_identifier)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?
            .physical_proof_application_count();
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER =>
            {
                let schedule_count =
                    u32::try_from(key_positions.relinearization_catalog_levels().len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                if schedule_count == 0
                    || variant.schedule_position().is_none()
                    || family_physical_count % schedule_count != 0
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(family_physical_count / schedule_count)
            }
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                let schedule_count =
                    u32::try_from(selected_galois_key_share_batch_schedule().len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                if schedule_count == 0
                    || variant.schedule_position().is_none()
                    || family_physical_count % schedule_count != 0
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(family_physical_count / schedule_count)
            }
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                if variant.schedule_position().is_some() || family_physical_count != 1 {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(u32::from(
                    variant.top_count() == Some(FOUNDATION_PROFILE.option_count),
                ))
            }
            _ => {
                if variant.schedule_position().is_some() || variant.top_count().is_some() {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(family_physical_count)
            }
        }
    }

    fn relation_column_origin_counts(
        variant: &RelationPlanVariant,
    ) -> Result<(u32, u32, u32), SelectedProofAccountingError> {
        let mut verifier_sequence_count = 0_u32;
        let mut bound_tree_count = 0_u32;
        let mut prover_count = 0_u32;
        for column in variant.ordered_columns() {
            let target = match column.origin() {
                RelationColumnOrigin::VerifierSequence { .. } => &mut verifier_sequence_count,
                RelationColumnOrigin::BoundTree { .. } => &mut bound_tree_count,
                RelationColumnOrigin::Prover => &mut prover_count,
            };
            *target = target
                .checked_add(1)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        }
        Ok((verifier_sequence_count, bound_tree_count, prover_count))
    }

    static SELECTED_PROOF_VARIANT_RESOURCE_INVENTORY: OnceLock<
        Result<Box<[SelectedProofVariantResourceAccounting]>, SelectedProofAccountingError>,
    > = OnceLock::new();

    pub(crate) fn selected_proof_variant_resource_inventory()
    -> Result<&'static [SelectedProofVariantResourceAccounting], SelectedProofAccountingError> {
        SELECTED_PROOF_VARIANT_RESOURCE_INVENTORY
            .get_or_init(derive_selected_proof_variant_resource_inventory)
            .as_ref()
            .map(|inventory| inventory.as_ref())
            .map_err(|error| *error)
    }

    fn derive_selected_proof_variant_resource_inventory()
    -> Result<Box<[SelectedProofVariantResourceAccounting]>, SelectedProofAccountingError> {
        let relation_plans =
            selected_relation_plans().map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let proof_family_inventory = derive_selected_proof_family_application_inventory()?;
        let key_positions = selected_evaluator_program_set()
            .and_then(|program| program.key_positions())
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let mut rows = Vec::new();

        for relation_plan in relation_plans {
            let schema_identifier = relation_plan.application_statement_schema_identifier();
            let relation_context = selected_relation_plan_check_context(schema_identifier)
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            for variant in relation_plan.compiled_plan().variants() {
                let statement_context = SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0; Hash512::BYTE_LENGTH],
                    variant.schedule_position(),
                    variant.top_count(),
                );
                let statement_bytes = canonical_selected_application_statement_for_ceiling(
                    schema_identifier,
                    statement_context,
                )
                .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
                let proof_header = ProofObjectHeader::from_canonical_application_statement(
                    statement_bytes,
                    &CanonicalDecodeLimits::default(),
                )
                .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
                let header_byte_length = proof_header
                    .encode()
                    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
                    .len();
                let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
                    &relation_plan,
                    variant.schedule_position(),
                    variant.top_count(),
                )
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                require_selected_row_code_whir_runtime_geometry(
                    &construction_plan,
                    variant,
                    &relation_context,
                )?;
                let relation_trees = selected_relation_tree_inputs(variant)?;
                let bound_tree_entries =
                    build_relation_bound_public_tree_catalog_entries(&relation_trees)
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let body_byte_length = canonical_row_code_whir_family_body_byte_length_ceiling(
                    &construction_plan,
                    variant,
                    &bound_tree_entries,
                )
                .map_err(|_| {
                    SelectedProofAccountingError::VariantResourcePlanning {
                        application_statement_schema_identifier: schema_identifier,
                        schedule_position: variant.schedule_position(),
                        top_count: variant.top_count(),
                        stage: "canonical family-body accounting",
                        measured_byte_length: None,
                    }
                })?;
                let proof_byte_length = header_byte_length
                    .checked_add(body_byte_length)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?;
                if proof_byte_length == 0
                    || proof_byte_length >= SELECTED_PROOF_SIZE_TARGET_BYTE_LENGTH
                    || proof_byte_length >= MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH
                    || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
                {
                    return Err(SelectedProofAccountingError::VariantResourcePlanning {
                        application_statement_schema_identifier: schema_identifier,
                        schedule_position: variant.schedule_position(),
                        top_count: variant.top_count(),
                        stage: "proof-size selection ceiling",
                        measured_byte_length: u64::try_from(proof_byte_length).ok(),
                    });
                }
                let proof_size_target_margin_byte_length =
                    SELECTED_PROOF_SIZE_TARGET_BYTE_LENGTH - proof_byte_length;
                let external_memory_requirement =
                    planned_row_code_whir_external_memory_requirement(
                        &construction_plan,
                        variant,
                        &relation_context,
                    )
                    .map_err(|_| {
                        SelectedProofAccountingError::VariantResourcePlanning {
                            application_statement_schema_identifier: schema_identifier,
                            schedule_position: variant.schedule_position(),
                            top_count: variant.top_count(),
                            stage: "external-memory accounting",
                            measured_byte_length: None,
                        }
                    })?;
                let maximum_verifier_resident_byte_length =
                    row_code_whir_verification_resident_memory_ceiling(proof_byte_length).map_err(
                        |_| SelectedProofAccountingError::VariantResourcePlanning {
                            application_statement_schema_identifier: schema_identifier,
                            schedule_position: variant.schedule_position(),
                            top_count: variant.top_count(),
                            stage: "verifier-resident accounting",
                            measured_byte_length: None,
                        },
                    )?;
                if maximum_verifier_resident_byte_length
                    > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                {
                    return Err(SelectedProofAccountingError::VariantResourcePlanning {
                        application_statement_schema_identifier: schema_identifier,
                        schedule_position: variant.schedule_position(),
                        top_count: variant.top_count(),
                        stage: "verifier-resident hard bound",
                        measured_byte_length: Some(maximum_verifier_resident_byte_length),
                    });
                }
                let relation_column_count = u32::try_from(variant.ordered_columns().len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                let (
                    verifier_sequence_relation_column_count,
                    bound_tree_relation_column_count,
                    prover_relation_column_count,
                ) = relation_column_origin_counts(variant)?;
                if verifier_sequence_relation_column_count
                    .checked_add(bound_tree_relation_column_count)
                    .and_then(|count| count.checked_add(prover_relation_column_count))
                    != Some(relation_column_count)
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                rows.push(SelectedProofVariantResourceAccounting {
                    application_statement_schema_identifier: schema_identifier,
                    schedule_position: variant.schedule_position(),
                    top_count: variant.top_count(),
                    complete_action_application_multiplicity:
                        selected_complete_action_variant_multiplicity(
                            schema_identifier,
                            variant,
                            &proof_family_inventory,
                            &key_positions,
                        )?,
                    logical_entry_count: selected_variant_logical_entry_count(
                        schema_identifier,
                        variant,
                        &proof_family_inventory,
                    )?,
                    relation_column_count,
                    verifier_sequence_relation_column_count,
                    bound_tree_relation_column_count,
                    prover_relation_column_count,
                    relation_constraint_count: u32::try_from(variant.ordered_constraint_count())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    opening_claim_count: u32::try_from(variant.ordered_opening_claims().len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    canonical_header_byte_length: u64::try_from(header_byte_length)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    canonical_family_body_byte_length: u64::try_from(body_byte_length)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    canonical_proof_byte_length: u64::try_from(proof_byte_length)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    proof_size_target_margin_byte_length: u64::try_from(
                        proof_size_target_margin_byte_length,
                    )
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    maximum_verifier_resident_byte_length,
                    generation_wasm_resident_hard_bound_byte_length:
                        MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
                    external_memory_requirement,
                    construction: construction_accounting(&construction_plan)?,
                });
            }
        }
        require_selected_variant_inventory(&rows, &proof_family_inventory, &key_positions)?;
        Ok(rows.into_boxed_slice())
    }

    fn require_selected_variant_inventory(
        rows: &[SelectedProofVariantResourceAccounting],
        proof_family_inventory: &ProofFamilyApplicationInventory,
        key_positions: &EvaluatorProgramKeyPositions,
    ) -> Result<(), SelectedProofAccountingError> {
        let mut observed_selectors = BTreeMap::<u16, BTreeSet<(Option<u32>, Option<u16>)>>::new();
        for row in rows {
            if !observed_selectors
                .entry(row.application_statement_schema_identifier())
                .or_default()
                .insert((row.schedule_position(), row.top_count()))
            {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
        }
        let unselected = BTreeSet::from([(None, None)]);
        let mut expected_selectors = BTreeMap::new();
        for schema_identifier in [
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        ] {
            expected_selectors.insert(schema_identifier, unselected.clone());
        }
        let relinearization_selectors = (0..key_positions.relinearization_catalog_levels().len())
            .map(|schedule_position| {
                u32::try_from(schedule_position)
                    .map(|schedule_position| (Some(schedule_position), None))
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        for schema_identifier in [
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        ] {
            expected_selectors.insert(schema_identifier, relinearization_selectors.clone());
        }
        expected_selectors.insert(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            selected_galois_key_share_batch_schedule()
                .into_iter()
                .map(|position| (Some(position), None))
                .collect(),
        );
        expected_selectors.insert(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            (1..=FOUNDATION_PROFILE.option_count)
                .map(|top_count| (None, Some(top_count)))
                .collect(),
        );
        if observed_selectors != expected_selectors {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        for family in proof_family_inventory.ordered_family_entries() {
            let mut selected_rows = rows.iter().filter(|row| {
                row.application_statement_schema_identifier()
                    == family.application_statement_schema_identifier()
                    && row.complete_action_application_multiplicity() != 0
            });
            let observed_physical_count = selected_rows.clone().try_fold(0_u32, |total, row| {
                total
                    .checked_add(row.complete_action_application_multiplicity())
                    .ok_or(SelectedProofAccountingError::CountOverflow)
            })?;
            let observed_logical_count = selected_rows.try_fold(0_u32, |total, row| {
                row.logical_entry_count()
                    .checked_mul(row.complete_action_application_multiplicity())
                    .and_then(|count| total.checked_add(count))
                    .ok_or(SelectedProofAccountingError::CountOverflow)
            })?;
            if observed_physical_count != family.physical_proof_application_count()
                || observed_logical_count != family.logical_relation_instance_count()
            {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
        }
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedPhysicalProofFamilyResourceAccounting {
        application_statement_schema_identifier: u16,
        physical_proof_count: u32,
        compiler_variant_count: u32,
        selected_variant_count: u32,
        maximum_logical_entry_count_per_proof: u32,
        complete_action_logical_entry_count: u64,
        maximum_proof_byte_length: u64,
    }

    impl SelectedPhysicalProofFamilyResourceAccounting {
        pub(crate) const fn application_statement_schema_identifier(self) -> u16 {
            self.application_statement_schema_identifier
        }

        pub(crate) const fn physical_proof_count(self) -> u32 {
            self.physical_proof_count
        }

        pub(crate) const fn compiler_variant_count(self) -> u32 {
            self.compiler_variant_count
        }

        pub(crate) const fn selected_variant_count(self) -> u32 {
            self.selected_variant_count
        }

        pub(crate) const fn maximum_logical_entry_count_per_proof(self) -> u32 {
            self.maximum_logical_entry_count_per_proof
        }

        pub(crate) const fn complete_action_logical_entry_count(self) -> u64 {
            self.complete_action_logical_entry_count
        }

        pub(crate) const fn maximum_proof_byte_length(self) -> u64 {
            self.maximum_proof_byte_length
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedCompleteActionMaterialResourceAccounting {
        one_dealer_recipient_private_vss_payload_byte_length: u64,
        one_dealer_private_vss_payload_upload_byte_length: u64,
        one_recipient_private_vss_payload_download_byte_length: u64,
        ceremony_private_vss_payload_byte_length: u64,
        evaluator_source_wire_byte_length_per_participant: u64,
        evaluator_source_resident_byte_length_per_participant: u64,
        final_evaluator_key_store_wire_byte_length: u64,
        final_evaluator_key_store_resident_byte_length: u64,
        ceremony_evaluator_setup_wire_byte_length: u64,
        ceremony_evaluator_source_and_final_resident_volume_byte_length: u64,
        one_ballot_ciphertext_stream_byte_length: u64,
        one_ballot_ciphertext_stream_chunk_count: u32,
        complete_action_ballot_candidate_package_corpus_byte_length: u64,
        complete_action_ballot_candidate_package_corpus_chunk_count: u64,
        ballot_prover_material_live_set_peak_byte_length: u64,
        one_target_ciphertext_canonical_byte_length_ceiling: u64,
        paired_target_ciphertext_canonical_byte_length_ceiling: u64,
        one_target_partial_stream_byte_length: u64,
        one_participant_paired_target_partial_stream_byte_length: u64,
        ceremony_paired_target_partial_stream_byte_length: u64,
    }

    impl SelectedCompleteActionMaterialResourceAccounting {
        pub(crate) const fn one_dealer_recipient_private_vss_payload_byte_length(self) -> u64 {
            self.one_dealer_recipient_private_vss_payload_byte_length
        }
        pub(crate) const fn one_dealer_private_vss_payload_upload_byte_length(self) -> u64 {
            self.one_dealer_private_vss_payload_upload_byte_length
        }
        pub(crate) const fn one_recipient_private_vss_payload_download_byte_length(self) -> u64 {
            self.one_recipient_private_vss_payload_download_byte_length
        }
        pub(crate) const fn ceremony_private_vss_payload_byte_length(self) -> u64 {
            self.ceremony_private_vss_payload_byte_length
        }
        pub(crate) const fn evaluator_source_wire_byte_length_per_participant(self) -> u64 {
            self.evaluator_source_wire_byte_length_per_participant
        }
        pub(crate) const fn evaluator_source_resident_byte_length_per_participant(self) -> u64 {
            self.evaluator_source_resident_byte_length_per_participant
        }
        pub(crate) const fn final_evaluator_key_store_wire_byte_length(self) -> u64 {
            self.final_evaluator_key_store_wire_byte_length
        }
        pub(crate) const fn final_evaluator_key_store_resident_byte_length(self) -> u64 {
            self.final_evaluator_key_store_resident_byte_length
        }
        pub(crate) const fn ceremony_evaluator_setup_wire_byte_length(self) -> u64 {
            self.ceremony_evaluator_setup_wire_byte_length
        }
        pub(crate) const fn ceremony_evaluator_source_and_final_resident_volume_byte_length(
            self,
        ) -> u64 {
            self.ceremony_evaluator_source_and_final_resident_volume_byte_length
        }
        pub(crate) const fn one_ballot_ciphertext_stream_byte_length(self) -> u64 {
            self.one_ballot_ciphertext_stream_byte_length
        }
        pub(crate) const fn one_ballot_ciphertext_stream_chunk_count(self) -> u32 {
            self.one_ballot_ciphertext_stream_chunk_count
        }
        pub(crate) const fn complete_action_ballot_candidate_package_corpus_byte_length(
            self,
        ) -> u64 {
            self.complete_action_ballot_candidate_package_corpus_byte_length
        }
        pub(crate) const fn complete_action_ballot_candidate_package_corpus_chunk_count(
            self,
        ) -> u64 {
            self.complete_action_ballot_candidate_package_corpus_chunk_count
        }
        pub(crate) const fn ballot_prover_material_live_set_peak_byte_length(self) -> u64 {
            self.ballot_prover_material_live_set_peak_byte_length
        }
        pub(crate) const fn one_target_ciphertext_canonical_byte_length_ceiling(self) -> u64 {
            self.one_target_ciphertext_canonical_byte_length_ceiling
        }
        pub(crate) const fn paired_target_ciphertext_canonical_byte_length_ceiling(self) -> u64 {
            self.paired_target_ciphertext_canonical_byte_length_ceiling
        }
        pub(crate) const fn one_target_partial_stream_byte_length(self) -> u64 {
            self.one_target_partial_stream_byte_length
        }
        pub(crate) const fn one_participant_paired_target_partial_stream_byte_length(self) -> u64 {
            self.one_participant_paired_target_partial_stream_byte_length
        }
        pub(crate) const fn ceremony_paired_target_partial_stream_byte_length(self) -> u64 {
            self.ceremony_paired_target_partial_stream_byte_length
        }
    }

    pub(crate) fn derive_selected_complete_action_material_resource_accounting()
    -> Result<SelectedCompleteActionMaterialResourceAccounting, SelectedProofAccountingError> {
        let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
        let private_vss_payload_byte_length = selected_recipient_private_vss_payload_byte_length()
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let one_dealer_private_vss_payload_upload_byte_length = private_vss_payload_byte_length
            .checked_mul(participant_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let ceremony_private_vss_payload_byte_length =
            one_dealer_private_vss_payload_upload_byte_length
                .checked_mul(participant_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let evaluator = selected_evaluator_resource_accounting()
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let ballot = selected_ballot_validity_carrier_buffer_accounting()
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let complete_action_ballot_candidate_package_corpus_byte_length = ballot
            .canonical_ciphertext_byte_length()
            .checked_mul(u64::from(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let complete_action_ballot_candidate_package_corpus_chunk_count =
            u64::from(ballot.canonical_ciphertext_chunk_count())
                .checked_mul(u64::from(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let one_target_ciphertext_canonical_byte_length_ceiling =
            two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
                CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            )
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
        let paired_target_role_count = u64::try_from(KLLPS_PAIRED_TARGET_ROLE_COUNT)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let paired_target_ciphertext_canonical_byte_length_ceiling =
            one_target_ciphertext_canonical_byte_length_ceiling
                .checked_mul(paired_target_role_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let one_target_partial_stream_byte_length = u64::try_from(
            selected_target_partial_decryption_stream_byte_length()
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
        )
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let one_participant_paired_target_partial_stream_byte_length =
            one_target_partial_stream_byte_length
                .checked_mul(paired_target_role_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let ceremony_paired_target_partial_stream_byte_length =
            one_participant_paired_target_partial_stream_byte_length
                .checked_mul(participant_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        Ok(SelectedCompleteActionMaterialResourceAccounting {
            one_dealer_recipient_private_vss_payload_byte_length: private_vss_payload_byte_length,
            one_dealer_private_vss_payload_upload_byte_length,
            one_recipient_private_vss_payload_download_byte_length:
                one_dealer_private_vss_payload_upload_byte_length,
            ceremony_private_vss_payload_byte_length,
            evaluator_source_wire_byte_length_per_participant: evaluator
                .source_wire_byte_length_per_participant(),
            evaluator_source_resident_byte_length_per_participant: evaluator
                .source_resident_byte_length_per_participant(),
            final_evaluator_key_store_wire_byte_length: evaluator
                .final_evaluator_key_store_wire_byte_length(),
            final_evaluator_key_store_resident_byte_length: evaluator
                .final_evaluator_key_store_resident_byte_length(),
            ceremony_evaluator_setup_wire_byte_length: evaluator.ceremony_setup_wire_byte_length(),
            ceremony_evaluator_source_and_final_resident_volume_byte_length: evaluator
                .ceremony_source_and_final_resident_volume_byte_length(),
            one_ballot_ciphertext_stream_byte_length: ballot.canonical_ciphertext_byte_length(),
            one_ballot_ciphertext_stream_chunk_count: ballot.canonical_ciphertext_chunk_count(),
            complete_action_ballot_candidate_package_corpus_byte_length,
            complete_action_ballot_candidate_package_corpus_chunk_count,
            ballot_prover_material_live_set_peak_byte_length: ballot
                .provider_buffer_live_set_peak_byte_length(),
            one_target_ciphertext_canonical_byte_length_ceiling,
            paired_target_ciphertext_canonical_byte_length_ceiling,
            one_target_partial_stream_byte_length,
            one_participant_paired_target_partial_stream_byte_length,
            ceremony_paired_target_partial_stream_byte_length,
        })
    }

    pub(crate) fn derive_selected_proof_family_application_inventory()
    -> Result<ProofFamilyApplicationInventory, SelectedProofAccountingError> {
        let key_positions = selected_evaluator_program_set()
            .and_then(|program| program.key_positions())
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let selected_relinearization_position_count =
            u32::try_from(key_positions.relinearization_catalog_levels().len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let selected_galois_batch_count =
            u32::try_from(selected_galois_key_share_batch_schedule().len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let application_slot_ceilings = ProofApplicationSlotCeilings::derive(
            FOUNDATION_PROFILE.participant_count,
            selected_relinearization_position_count,
            selected_galois_batch_count,
            SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        )
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let galois_entries = u32::try_from(
            selected_galois_key_share_relation_plan_input()
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                .ordered_entries
                .len(),
        )
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let evaluator_entries = u32::try_from(
            selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                .len(),
        )
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        application_slot_ceilings
            .derive_proof_family_application_inventory(galois_entries, evaluator_entries)
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedCompleteProofResourceAccounting {
        ordered_families: Box<[SelectedPhysicalProofFamilyResourceAccounting]>,
        material_resources: SelectedCompleteActionMaterialResourceAccounting,
        physical_proof_count: u32,
        complete_action_logical_entry_count: u64,
        complete_action_proof_byte_ceiling: u64,
        setup_physical_proof_count: u32,
        setup_proof_byte_ceiling: u64,
        ballot_physical_proof_count: u32,
        ballot_proof_byte_ceiling: u64,
        target_release_physical_proof_count: u32,
        target_release_proof_byte_ceiling: u64,
        maximum_one_browser_wasm_resident_byte_length: u64,
    }

    impl SelectedCompleteProofResourceAccounting {
        pub(crate) fn ordered_families(&self) -> &[SelectedPhysicalProofFamilyResourceAccounting] {
            &self.ordered_families
        }
        pub(crate) const fn material_resources(
            &self,
        ) -> SelectedCompleteActionMaterialResourceAccounting {
            self.material_resources
        }
        pub(crate) const fn physical_proof_count(&self) -> u32 {
            self.physical_proof_count
        }
        pub(crate) const fn complete_action_logical_entry_count(&self) -> u64 {
            self.complete_action_logical_entry_count
        }
        pub(crate) const fn complete_action_proof_byte_ceiling(&self) -> u64 {
            self.complete_action_proof_byte_ceiling
        }
        pub(crate) const fn setup_physical_proof_count(&self) -> u32 {
            self.setup_physical_proof_count
        }
        pub(crate) const fn setup_proof_byte_ceiling(&self) -> u64 {
            self.setup_proof_byte_ceiling
        }
        pub(crate) const fn ballot_physical_proof_count(&self) -> u32 {
            self.ballot_physical_proof_count
        }
        pub(crate) const fn ballot_proof_byte_ceiling(&self) -> u64 {
            self.ballot_proof_byte_ceiling
        }
        pub(crate) const fn target_release_physical_proof_count(&self) -> u32 {
            self.target_release_physical_proof_count
        }
        pub(crate) const fn target_release_proof_byte_ceiling(&self) -> u64 {
            self.target_release_proof_byte_ceiling
        }
        pub(crate) const fn maximum_one_browser_wasm_resident_byte_length(&self) -> u64 {
            self.maximum_one_browser_wasm_resident_byte_length
        }
    }

    static SELECTED_COMPLETE_PROOF_RESOURCE_ACCOUNTING: OnceLock<
        Result<SelectedCompleteProofResourceAccounting, SelectedProofAccountingError>,
    > = OnceLock::new();

    pub(crate) fn selected_complete_proof_resource_accounting()
    -> Result<&'static SelectedCompleteProofResourceAccounting, SelectedProofAccountingError> {
        SELECTED_COMPLETE_PROOF_RESOURCE_ACCOUNTING
            .get_or_init(derive_selected_complete_proof_resource_accounting)
            .as_ref()
            .map_err(|error| *error)
    }

    fn derive_selected_complete_proof_resource_accounting()
    -> Result<SelectedCompleteProofResourceAccounting, SelectedProofAccountingError> {
        let variants = selected_proof_variant_resource_inventory()?;
        let material_resources = derive_selected_complete_action_material_resource_accounting()?;
        let family_inventory = derive_selected_proof_family_application_inventory()?;
        let physical_proof_count = family_inventory
            .total_physical_proof_application_count()
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let complete_action_logical_entry_count = u64::from(
            family_inventory
                .total_logical_relation_instance_count()
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        );
        let mut ordered_families = Vec::new();
        let mut complete_action_proof_byte_ceiling = 0_u64;
        let mut setup_physical_proof_count = 0_u32;
        let mut setup_proof_byte_ceiling = 0_u64;
        let mut ballot_physical_proof_count = 0_u32;
        let mut ballot_proof_byte_ceiling = 0_u64;
        let mut target_release_physical_proof_count = 0_u32;
        let mut target_release_proof_byte_ceiling = 0_u64;

        for family in family_inventory.ordered_family_entries() {
            let schema_identifier = family.application_statement_schema_identifier();
            let family_variants = variants
                .iter()
                .filter(|variant| {
                    variant.application_statement_schema_identifier() == schema_identifier
                })
                .collect::<Vec<_>>();
            let selected_variants = family_variants
                .iter()
                .copied()
                .filter(|variant| variant.complete_action_application_multiplicity() != 0)
                .collect::<Vec<_>>();
            if selected_variants.is_empty() {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            let family_proof_byte_ceiling =
                selected_variants.iter().try_fold(0_u64, |total, variant| {
                    variant
                        .canonical_proof_byte_length()
                        .checked_mul(u64::from(
                            variant.complete_action_application_multiplicity(),
                        ))
                        .and_then(|length| total.checked_add(length))
                        .ok_or(SelectedProofAccountingError::CountOverflow)
                })?;
            complete_action_proof_byte_ceiling = complete_action_proof_byte_ceiling
                .checked_add(family_proof_byte_ceiling)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            match schema_identifier {
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
                    ballot_physical_proof_count = ballot_physical_proof_count
                        .checked_add(family.physical_proof_application_count())
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                    ballot_proof_byte_ceiling = ballot_proof_byte_ceiling
                        .checked_add(family_proof_byte_ceiling)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                }
                ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
                    target_release_physical_proof_count = target_release_physical_proof_count
                        .checked_add(family.physical_proof_application_count())
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                    target_release_proof_byte_ceiling = target_release_proof_byte_ceiling
                        .checked_add(family_proof_byte_ceiling)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                }
                _ => {
                    setup_physical_proof_count = setup_physical_proof_count
                        .checked_add(family.physical_proof_application_count())
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                    setup_proof_byte_ceiling = setup_proof_byte_ceiling
                        .checked_add(family_proof_byte_ceiling)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                }
            }
            ordered_families.push(SelectedPhysicalProofFamilyResourceAccounting {
                application_statement_schema_identifier: schema_identifier,
                physical_proof_count: family.physical_proof_application_count(),
                compiler_variant_count: u32::try_from(family_variants.len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                selected_variant_count: u32::try_from(selected_variants.len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                maximum_logical_entry_count_per_proof: selected_variants
                    .iter()
                    .map(|variant| variant.logical_entry_count())
                    .max()
                    .ok_or(SelectedProofAccountingError::InvalidProfile)?,
                complete_action_logical_entry_count: u64::from(
                    family.logical_relation_instance_count(),
                ),
                maximum_proof_byte_length: selected_variants
                    .iter()
                    .map(|variant| variant.canonical_proof_byte_length())
                    .max()
                    .ok_or(SelectedProofAccountingError::InvalidProfile)?,
            });
        }
        if setup_physical_proof_count
            .checked_add(ballot_physical_proof_count)
            .and_then(|count| count.checked_add(target_release_physical_proof_count))
            != Some(physical_proof_count)
            || setup_proof_byte_ceiling
                .checked_add(ballot_proof_byte_ceiling)
                .and_then(|length| length.checked_add(target_release_proof_byte_ceiling))
                != Some(complete_action_proof_byte_ceiling)
        {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }
        Ok(SelectedCompleteProofResourceAccounting {
            ordered_families: ordered_families.into_boxed_slice(),
            material_resources,
            physical_proof_count,
            complete_action_logical_entry_count,
            complete_action_proof_byte_ceiling,
            setup_physical_proof_count,
            setup_proof_byte_ceiling,
            ballot_physical_proof_count,
            ballot_proof_byte_ceiling,
            target_release_physical_proof_count,
            target_release_proof_byte_ceiling,
            maximum_one_browser_wasm_resident_byte_length:
                MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn selected_row_code_whir_accounting_covers_every_variant_under_five_mebibytes() {
            let rows = selected_proof_variant_resource_inventory()
                .expect("selected row-code WHIR accounting derives");
            assert_eq!(
                rows.iter()
                    .map(|row| row.application_statement_schema_identifier())
                    .collect::<BTreeSet<_>>(),
                crate::bgv::proof_suite::FIRST_PROFILE_APPLICATION_FAMILIES
                    .into_iter()
                    .collect(),
            );
            assert!(rows.len() > crate::bgv::proof_suite::FIRST_PROFILE_APPLICATION_FAMILIES.len());
            for row in rows {
                assert!(row.canonical_header_byte_length() > 0);
                assert!(row.canonical_family_body_byte_length() > 0);
                assert!(row.canonical_proof_byte_length() < 5 * 1_024 * 1_024);
                assert_eq!(
                    row.canonical_proof_byte_length() + row.proof_size_target_margin_byte_length(),
                    5 * 1_024 * 1_024,
                );
                assert!(
                    row.maximum_verifier_resident_byte_length() > row.canonical_proof_byte_length()
                );
                assert!(
                    row.maximum_verifier_resident_byte_length()
                        <= row.generation_wasm_resident_hard_bound_byte_length()
                );
            }
        }

        #[test]
        fn candidate_specific_runtime_geometry_covers_extended_opening_catalogs() {
            use crate::bgv::proof_suite::{
                ValidatedRelationPlanArtifact, compile_aggregate_threshold_share_relation_plan,
                compile_vss_share_linkage_relation_plan,
                selected_ballot_validity_relation_compilation,
                selected_committed_material_relation_plan_input,
                selected_profile::selected_target_release_relation,
            };

            let ballot_compilation = selected_ballot_validity_relation_compilation()
                .expect("the selected ballot relation compiles");
            let target_release_compilation = selected_target_release_relation()
                .expect("the selected target-release relation compiles");
            let committed_material_input = selected_committed_material_relation_plan_input()
                .expect("the selected committed-material relation input derives");
            let committed_material_context = selected_relation_plan_check_context(
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            .expect("the selected committed-material relation context derives");
            let vss_share_linkage = compile_vss_share_linkage_relation_plan(
                &committed_material_input,
                &committed_material_context,
            )
            .expect("the selected VSS share-linkage relation compiles");
            let aggregate_threshold_share = compile_aggregate_threshold_share_relation_plan(
                &committed_material_input,
                &committed_material_context,
            )
            .expect("the selected aggregate-threshold-share relation compiles");

            for compiled_plan in [
                ballot_compilation.relation_plan().clone(),
                target_release_compilation.relation_plan().clone(),
                vss_share_linkage,
                aggregate_threshold_share,
            ] {
                let schema_identifier = compiled_plan.application_statement_schema_identifier();
                let context = selected_relation_plan_check_context(schema_identifier)
                    .expect("the selected family has a relation context");
                let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
                    compiled_plan,
                    &context,
                )
                .expect("the selected family relation validates");
                let variant = artifact
                    .compiled_plan()
                    .select_variant(None, None)
                    .expect("the selected family has one unparameterized variant");
                let construction_plan =
                    RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
                        .expect("the candidate-specific row construction derives");
                planned_row_code_whir_external_memory_requirement(
                    &construction_plan,
                    variant,
                    &context,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "schema {schema_identifier:#06x} external-memory planning failed: {error:?}"
                    )
                });
                require_selected_row_code_whir_runtime_geometry(
                    &construction_plan,
                    variant,
                    &context,
                )
                .unwrap_or_else(|error| {
                    panic!("schema {schema_identifier:#06x} runtime geometry failed: {error:?}")
                });
            }
        }

        #[test]
        fn candidate_specific_evaluator_rows_count_only_the_requested_entries() {
            let rows = selected_proof_variant_resource_inventory()
                .expect("selected row-code WHIR accounting derives")
                .iter()
                .filter(|row| {
                    row.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                })
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), usize::from(FOUNDATION_PROFILE.option_count));
            for (index, row) in rows.iter().enumerate() {
                let expected_top_count = u16::try_from(index + 1).expect("top count fits u16");
                assert_eq!(row.top_count(), Some(expected_top_count));
                assert_eq!(row.logical_entry_count(), u32::from(expected_top_count));
                assert_eq!(
                    row.complete_action_application_multiplicity(),
                    u32::from(expected_top_count == FOUNDATION_PROFILE.option_count),
                );
                assert!(
                    row.construction().aggregate_logical_column_count()
                        <= row.construction().aggregate_table_width()
                );
            }
        }

        #[test]
        fn coordinate_derived_compact_frontiers_cover_every_opening_section() {
            for row in selected_proof_variant_resource_inventory()
                .expect("selected row-code WHIR accounting derives")
            {
                let construction = row.construction();
                assert!(!construction.compact_frontiers().is_empty());
                assert!(!construction.aggregate_opening_sections().is_empty());
                for frontier in construction.compact_frontiers() {
                    assert!(frontier.leaf_count().is_power_of_two());
                    assert!(frontier.query_count() > 0);
                    assert!(frontier.maximum_frontier_node_count() > 0);
                    assert_eq!(
                        frontier.frontier_byte_length(),
                        u64::from(frontier.maximum_frontier_node_count()) * 64 + 4,
                    );
                    assert_eq!(
                        frontier.canonical_opening_byte_length(),
                        frontier.opened_value_byte_length() + frontier.frontier_byte_length(),
                    );
                }
                assert!(
                    construction
                        .aggregate_opening_sections()
                        .iter()
                        .all(|section| section.byte_length() > 0)
                );
            }
        }

        #[test]
        fn runtime_limits_match_the_common_authenticated_stream_bound() {
            let relation_plans = selected_relation_plans().expect("selected plans derive");
            for relation_plan in relation_plans {
                let schema_identifier = relation_plan.application_statement_schema_identifier();
                for variant in relation_plan.compiled_plan().variants() {
                    let statement = canonical_selected_application_statement_for_ceiling(
                        schema_identifier,
                        SelectedApplicationStatementContext::new(
                            FOUNDATION_PROFILE.protocol_version,
                            [0; Hash512::BYTE_LENGTH],
                            variant.schedule_position(),
                            variant.top_count(),
                        ),
                    )
                    .expect("selected statement derives");
                    let limits =
                        selected_proof_runtime_limits(schema_identifier, &statement, variant)
                            .expect("runtime limits derive");
                    assert_eq!(
                        limits.maximum_proof_byte_length(),
                        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
                    );
                    assert_eq!(
                        limits.external_memory_chunk_byte_length(),
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                    );
                    assert_eq!(
                        limits.prefetched_query_byte_length(),
                        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                            .expect("chunk length fits u64"),
                    );
                }
            }
        }

        #[test]
        fn checkpoint_and_external_memory_geometry_closes_for_every_variant() {
            for row in selected_proof_variant_resource_inventory()
                .expect("selected row-code WHIR accounting derives")
            {
                let construction = row.construction();
                assert!(construction.transcript_operation_count() > 0);
                assert!(construction.opening_batch_count() > 0);
                assert!(construction.outer_query_count() > 0);
                assert!(construction.direct_bound_query_count() > 0);
                assert!(
                    construction.prior_proof_bound_query_count()
                        <= construction.direct_bound_query_count()
                );
                assert!(matches!(
                    construction
                        .ordered_checkpoints()
                        .first()
                        .map(|row| row.boundary_code()),
                    Some(1)
                ));
                assert!(matches!(
                    construction
                        .ordered_checkpoints()
                        .last()
                        .map(|row| row.boundary_code()),
                    Some(6)
                ));
                let external = row.external_memory_requirement();
                assert!(external.step_count() > 0);
                assert!(external.distinct_physical_object_count() > 0);
                assert!(
                    usize::try_from(external.distinct_physical_object_count())
                        .expect("object count fits usize")
                        <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT
                );
                assert!(
                    external.peak_stored_byte_length()
                        <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                );
                assert!(!external.exceeds_active_root_seal_custody_budget());
            }
        }

        #[test]
        fn complete_action_accounting_reconciles_all_exact_roster_slots() {
            let accounting = selected_complete_proof_resource_accounting()
                .expect("complete selected accounting derives");
            let inventory = derive_selected_proof_family_application_inventory()
                .expect("proof family inventory derives");
            assert_eq!(accounting.ordered_families().len(), 12);
            assert_eq!(accounting.physical_proof_count(), 103);
            assert_eq!(
                accounting.physical_proof_count(),
                inventory
                    .total_physical_proof_application_count()
                    .expect("physical count adds"),
            );
            assert_eq!(
                accounting.complete_action_logical_entry_count(),
                u64::from(
                    inventory
                        .total_logical_relation_instance_count()
                        .expect("logical count adds"),
                ),
            );
            assert!(accounting.complete_action_proof_byte_ceiling() > 0);
            assert_eq!(
                accounting.maximum_one_browser_wasm_resident_byte_length(),
                MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
            );
        }
    }
}

#[cfg(test)]
pub(crate) use resource_accounting::selected_complete_proof_resource_accounting;
