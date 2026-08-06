//! Bounded execution lifecycle for the compact CFW reduction.
//!
//! The first sumcheck round is evaluated twice from the structured matrices:
//! once to emit the round polynomial and once, after the challenge, to persist
//! only the three half-length folds. Later rounds read those folds in bounded
//! chunks and replace one matrix at a time. This prevents three full
//! extension-field row vectors from ever occupying either the WASM heap or
//! external storage.

use crate::bgv::proof_suite::compact_cfw::{COMPACT_CFW_MATRIX_COUNT, CompactCfwGeometry};
use crate::bgv::proof_suite::compact_cfw_external::CompactCfwExternalStorageCatalog;
use crate::bgv::proof_suite::compact_cfw_external_prover::CompactCfwExternalProverMemoryGeometry;
use crate::bgv::proof_suite::external_memory::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
};
use crate::bgv::proof_suite::runtime::CommonProofStorageTransactionMemoryGeometry;
use crate::bgv::proof_suite::{
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
};

use super::cfw_reduction::CfwReductionCatalog;
use super::{
    CompactStaticCatalogError, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH, checked_add, checked_product,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;

const CFW_STREAM_CHUNK_ELEMENT_COUNT: u64 = 16_384;
const EXTERNAL_OBJECT_LIFECYCLE_TRANSACTION_COUNT: u64 = 3;
const INITIAL_STRUCTURED_MATRIX_PASS_COUNT: u64 = 2;
const ROUND_BOUNDARY_CHECKPOINT_COUNT_PER_ROUND: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CfwLifecycleCatalog {
    r1cs_row_count: u64,
    sumcheck_round_count: u32,
    matrix_count: u64,
    stream_chunk_element_count: u64,
    stream_chunk_byte_length: u64,
    initial_structured_matrix_pass_count: u64,
    structured_matrix_row_evaluation_count: u64,
    sumcheck_suffix_evaluation_count: u64,
    matrix_fold_output_element_count: u64,
    external_object_count: u64,
    maximum_active_external_object_count: u64,
    external_append_transaction_count: u64,
    external_read_transaction_count: u64,
    external_delete_transaction_count: u64,
    external_transaction_count: u64,
    external_write_extension_element_count: u64,
    external_read_extension_element_count: u64,
    external_write_byte_length: u64,
    external_read_byte_length: u64,
    maximum_external_stored_byte_length: u64,
    maximum_matrix_buffer_byte_length: u64,
    external_prover_state_inline_byte_length: u64,
    external_runtime_index_heap_byte_length: u64,
    inner_mask_heap_byte_length: u64,
    outer_mask_heap_byte_length: u64,
    equality_point_heap_byte_length: u64,
    round_challenge_heap_byte_length: u64,
    maximum_accumulator_suffix_heap_byte_length: u64,
    maximum_encoded_chunk_byte_length: u64,
    external_prover_resident_owned_byte_length: u64,
    maximum_kernel_live_byte_length: u64,
    storage_transaction_runtime_inline_byte_length: u64,
    maximum_storage_operation_vector_heap_byte_length: u64,
    maximum_append_replay_length_heap_byte_length: u64,
    maximum_read_result_vector_heap_byte_length: u64,
    storage_replay_box_byte_length: u64,
    storage_append_request_byte_length: u64,
    storage_empty_response_byte_length: u64,
    storage_read_request_byte_length: u64,
    storage_read_response_byte_length: u64,
    append_request_export_live_byte_length: u64,
    read_response_supply_live_byte_length: u64,
    read_replay_live_byte_length: u64,
    maximum_storage_transaction_live_byte_length: u64,
    maximum_cfw_runtime_live_byte_length: u64,
    maximum_boundary_transfer_live_byte_length: u64,
    deterministic_safe_boundary_count: u64,
    maximum_uninterrupted_structured_row_evaluation_count: u64,
    maximum_uninterrupted_external_element_count: u64,
    maximum_phase_recomputation_count: u64,
    validated_external_plan_step_count: u32,
    external_executor_resident_owned_payload_byte_length: u64,
    secret_seal_invocation_count: u64,
    secret_sealed_plaintext_byte_length: u64,
}

impl CfwLifecycleCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let catalog = Self::derive_without_check(relation, cfw_reduction)?;
        catalog.check(relation, cfw_reduction)?;
        Ok(catalog)
    }

    fn derive_without_check(
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let witness_length = usize::try_from(relation.padded_witness_element_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let geometry = CompactCfwGeometry::derive(witness_length)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let validated_external_plan = CompactCfwExternalStorageCatalog::derive(geometry)
            .map_err(|_| CompactStaticCatalogError::IncompleteLifecycle)?;
        let external_prover_memory = CompactCfwExternalProverMemoryGeometry::derive(geometry)
            .map_err(|_| CompactStaticCatalogError::IncompleteLifecycle)?;
        let r1cs_row_count = u64::try_from(geometry.r1cs_row_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let sumcheck_round_count = u32::try_from(geometry.sumcheck_round_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let matrix_count = u64::try_from(COMPACT_CFW_MATRIX_COUNT)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let stream_chunk_byte_length = checked_product(&[
            CFW_STREAM_CHUNK_ELEMENT_COUNT,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        if stream_chunk_byte_length
            > u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            || sumcheck_round_count != cfw_reduction.sumcheck_round_count()
            || r1cs_row_count != relation.padded_constraint_count()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let structured_matrix_row_evaluation_count = checked_product(&[
            INITIAL_STRUCTURED_MATRIX_PASS_COUNT,
            matrix_count,
            r1cs_row_count,
        ])?;
        let sumcheck_suffix_evaluation_count = r1cs_row_count
            .checked_sub(1)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let matrix_fold_output_element_count =
            checked_product(&[matrix_count, sumcheck_suffix_evaluation_count])?;

        let mut output_length = r1cs_row_count / 2;
        let mut external_object_count = 0_u64;
        let mut external_append_transaction_count = 0_u64;
        let mut external_write_extension_element_count = 0_u64;
        loop {
            external_object_count = checked_add(external_object_count, matrix_count)?;
            external_append_transaction_count = checked_add(
                external_append_transaction_count,
                checked_product(&[
                    matrix_count,
                    output_length.div_ceil(CFW_STREAM_CHUNK_ELEMENT_COUNT),
                ])?,
            )?;
            external_write_extension_element_count = checked_add(
                external_write_extension_element_count,
                checked_product(&[matrix_count, output_length])?,
            )?;
            if output_length == 1 {
                break;
            }
            output_length /= 2;
        }

        let mut current_length = r1cs_row_count / 2;
        let mut stored_round_chunk_group_count = 0_u64;
        let mut external_read_transaction_count = 0_u64;
        let mut external_read_extension_element_count = 0_u64;
        while current_length > 1 {
            let chunks_per_matrix = current_length.div_ceil(CFW_STREAM_CHUNK_ELEMENT_COUNT);
            stored_round_chunk_group_count =
                checked_add(stored_round_chunk_group_count, chunks_per_matrix)?;
            external_read_transaction_count = checked_add(
                external_read_transaction_count,
                checked_product(&[2, matrix_count, chunks_per_matrix])?,
            )?;
            external_read_extension_element_count = checked_add(
                external_read_extension_element_count,
                checked_product(&[2, matrix_count, current_length])?,
            )?;
            current_length /= 2;
        }

        let external_delete_transaction_count = external_object_count;
        let external_transaction_count = [
            checked_product(&[
                EXTERNAL_OBJECT_LIFECYCLE_TRANSACTION_COUNT,
                external_object_count,
            ])?,
            external_append_transaction_count,
            external_read_transaction_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let external_write_byte_length = checked_product(&[
            external_write_extension_element_count,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let external_read_byte_length = checked_product(&[
            external_read_extension_element_count,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;

        let first_stored_length = r1cs_row_count / 2;
        let maximum_external_stored_element_count = checked_add(
            checked_product(&[matrix_count, first_stored_length])?,
            first_stored_length / 2,
        )?;
        let maximum_external_stored_byte_length = checked_product(&[
            maximum_external_stored_element_count,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let maximum_matrix_buffer_byte_length =
            external_prover_memory.work_chunk_heap_byte_length();
        if maximum_matrix_buffer_byte_length
            != checked_product(&[matrix_count, stream_chunk_byte_length])?
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }
        let storage_transaction_memory =
            CommonProofStorageTransactionMemoryGeometry::derive(stream_chunk_byte_length)
                .map_err(|_| CompactStaticCatalogError::IncompleteLifecycle)?;
        let maximum_boundary_transfer_live_byte_length = checked_add(
            storage_transaction_memory.append_request_byte_length(),
            storage_transaction_memory.empty_response_byte_length(),
        )?
        .max(checked_add(
            storage_transaction_memory.read_request_byte_length(),
            storage_transaction_memory.read_response_byte_length(),
        )?);
        if maximum_boundary_transfer_live_byte_length
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH
            || storage_transaction_memory.maximum_payload_byte_length() != stream_chunk_byte_length
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }
        let maximum_cfw_runtime_live_byte_length = checked_add(
            external_prover_memory.resident_owned_byte_length(),
            storage_transaction_memory.maximum_live_byte_length(),
        )?;
        let initial_structured_chunk_count =
            r1cs_row_count.div_ceil(CFW_STREAM_CHUNK_ELEMENT_COUNT);
        let deterministic_safe_boundary_count = [
            initial_structured_chunk_count,
            external_append_transaction_count,
            stored_round_chunk_group_count,
            checked_product(&[
                ROUND_BOUNDARY_CHECKPOINT_COUNT_PER_ROUND,
                u64::from(sumcheck_round_count),
            ])?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let maximum_uninterrupted_structured_row_evaluation_count =
            checked_product(&[matrix_count, CFW_STREAM_CHUNK_ELEMENT_COUNT])?;

        if validated_external_plan.object_lifecycle_count() != external_object_count
            || validated_external_plan.maximum_active_object_count() != matrix_count + 1
            || validated_external_plan.append_transaction_count()
                != external_append_transaction_count
            || validated_external_plan.read_transaction_count() != external_read_transaction_count
            || validated_external_plan.delete_transaction_count()
                != external_delete_transaction_count
            || validated_external_plan.total_transaction_count() != external_transaction_count
            || validated_external_plan.written_extension_element_count()
                != external_write_extension_element_count
            || validated_external_plan.read_extension_element_count()
                != external_read_extension_element_count
            || validated_external_plan.total_written_byte_length() != external_write_byte_length
            || validated_external_plan.total_read_byte_length() != external_read_byte_length
            || validated_external_plan.peak_stored_byte_length()
                != maximum_external_stored_byte_length
            || validated_external_plan.executor_resident_owned_payload_byte_length()
                != external_prover_memory.executor_heap_byte_length()
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }

        Ok(Self {
            r1cs_row_count,
            sumcheck_round_count,
            matrix_count,
            stream_chunk_element_count: CFW_STREAM_CHUNK_ELEMENT_COUNT,
            stream_chunk_byte_length,
            initial_structured_matrix_pass_count: INITIAL_STRUCTURED_MATRIX_PASS_COUNT,
            structured_matrix_row_evaluation_count,
            sumcheck_suffix_evaluation_count,
            matrix_fold_output_element_count,
            external_object_count,
            maximum_active_external_object_count: matrix_count + 1,
            external_append_transaction_count,
            external_read_transaction_count,
            external_delete_transaction_count,
            external_transaction_count,
            external_write_extension_element_count,
            external_read_extension_element_count,
            external_write_byte_length,
            external_read_byte_length,
            maximum_external_stored_byte_length,
            maximum_matrix_buffer_byte_length,
            external_prover_state_inline_byte_length: external_prover_memory
                .state_inline_byte_length(),
            external_runtime_index_heap_byte_length: external_prover_memory
                .runtime_index_heap_byte_length(),
            inner_mask_heap_byte_length: external_prover_memory.inner_mask_heap_byte_length(),
            outer_mask_heap_byte_length: external_prover_memory.outer_mask_heap_byte_length(),
            equality_point_heap_byte_length: external_prover_memory
                .equality_point_heap_byte_length(),
            round_challenge_heap_byte_length: external_prover_memory
                .round_challenge_heap_byte_length(),
            maximum_accumulator_suffix_heap_byte_length: external_prover_memory
                .maximum_accumulator_suffix_heap_byte_length(),
            maximum_encoded_chunk_byte_length: external_prover_memory
                .maximum_encoded_chunk_byte_length(),
            external_prover_resident_owned_byte_length: external_prover_memory
                .resident_owned_byte_length(),
            maximum_kernel_live_byte_length: external_prover_memory
                .maximum_kernel_live_byte_length(),
            storage_transaction_runtime_inline_byte_length: storage_transaction_memory
                .runtime_inline_byte_length(),
            maximum_storage_operation_vector_heap_byte_length: storage_transaction_memory
                .maximum_operation_vector_heap_byte_length(),
            maximum_append_replay_length_heap_byte_length: storage_transaction_memory
                .maximum_append_replay_length_heap_byte_length(),
            maximum_read_result_vector_heap_byte_length: storage_transaction_memory
                .maximum_read_result_vector_heap_byte_length(),
            storage_replay_box_byte_length: storage_transaction_memory.replay_box_byte_length(),
            storage_append_request_byte_length: storage_transaction_memory
                .append_request_byte_length(),
            storage_empty_response_byte_length: storage_transaction_memory
                .empty_response_byte_length(),
            storage_read_request_byte_length: storage_transaction_memory.read_request_byte_length(),
            storage_read_response_byte_length: storage_transaction_memory
                .read_response_byte_length(),
            append_request_export_live_byte_length: storage_transaction_memory
                .append_request_export_live_byte_length(),
            read_response_supply_live_byte_length: storage_transaction_memory
                .read_response_supply_live_byte_length(),
            read_replay_live_byte_length: storage_transaction_memory.read_replay_live_byte_length(),
            maximum_storage_transaction_live_byte_length: storage_transaction_memory
                .maximum_live_byte_length(),
            maximum_cfw_runtime_live_byte_length,
            maximum_boundary_transfer_live_byte_length,
            deterministic_safe_boundary_count,
            maximum_uninterrupted_structured_row_evaluation_count,
            maximum_uninterrupted_external_element_count: CFW_STREAM_CHUNK_ELEMENT_COUNT,
            maximum_phase_recomputation_count: 1,
            validated_external_plan_step_count: validated_external_plan.step_count(),
            external_executor_resident_owned_payload_byte_length: external_prover_memory
                .executor_heap_byte_length(),
            secret_seal_invocation_count: validated_external_plan.secret_seal_invocation_count(),
            secret_sealed_plaintext_byte_length: validated_external_plan
                .secret_sealed_plaintext_byte_length(),
        })
    }

    pub(super) fn check(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected = Self::derive_without_check(relation, cfw_reduction)?;
        if self != &expected
            || self.r1cs_row_count == 0
            || !self.r1cs_row_count.is_power_of_two()
            || self.sumcheck_round_count == 0
            || self.matrix_count != COMPACT_CFW_MATRIX_COUNT as u64
            || self.stream_chunk_element_count == 0
            || !self.stream_chunk_element_count.is_power_of_two()
            || self.stream_chunk_byte_length
                > u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            || self.initial_structured_matrix_pass_count != 2
            || self.external_object_count == 0
            || self.maximum_active_external_object_count != self.matrix_count + 1
            || self.external_delete_transaction_count != self.external_object_count
            || self.maximum_external_stored_byte_length
                >= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
            || self.deterministic_safe_boundary_count == 0
            || self.maximum_uninterrupted_structured_row_evaluation_count == 0
            || self.maximum_uninterrupted_external_element_count > self.stream_chunk_element_count
            || self.maximum_phase_recomputation_count != 1
            || self.validated_external_plan_step_count == 0
            || self.external_executor_resident_owned_payload_byte_length == 0
            || self.external_prover_resident_owned_byte_length == 0
            || self.maximum_kernel_live_byte_length
                != checked_add(
                    self.external_prover_resident_owned_byte_length,
                    self.maximum_encoded_chunk_byte_length,
                )?
            || self.maximum_storage_transaction_live_byte_length
                != self
                    .append_request_export_live_byte_length
                    .max(self.read_response_supply_live_byte_length)
                    .max(self.read_replay_live_byte_length)
            || self.maximum_cfw_runtime_live_byte_length
                != checked_add(
                    self.external_prover_resident_owned_byte_length,
                    self.maximum_storage_transaction_live_byte_length,
                )?
            || self.maximum_boundary_transfer_live_byte_length
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH
            || self.secret_seal_invocation_count == 0
            || self.secret_sealed_plaintext_byte_length < self.external_write_byte_length
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }
        Ok(())
    }

    pub(super) fn maximum_wasm_live_byte_length(
        &self,
        ready_row_source_peak_byte_length: u64,
        proof_assembler_owned_heap_byte_length: u64,
        response_tree_kernel_heap_byte_length: u64,
        public_input_byte_length: u64,
        transport_chunk_byte_length: u64,
        cfw_transcript_handoff_byte_length: u64,
    ) -> Result<u64, CompactStaticCatalogError> {
        [
            ready_row_source_peak_byte_length,
            proof_assembler_owned_heap_byte_length,
            response_tree_kernel_heap_byte_length,
            public_input_byte_length,
            transport_chunk_byte_length,
            self.maximum_cfw_runtime_live_byte_length,
            cfw_transcript_handoff_byte_length,
            u64::try_from(COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)
    }

    pub(super) fn maximum_scratch_byte_length(&self) -> Result<u64, CompactStaticCatalogError> {
        checked_add(
            self.maximum_external_stored_byte_length,
            checked_add(
                self.maximum_boundary_transfer_live_byte_length,
                u64::try_from(COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )?,
        )
    }

    pub(super) const fn deterministic_safe_boundary_count(&self) -> u64 {
        self.deterministic_safe_boundary_count
    }

    pub(super) const fn maximum_phase_recomputation_count(&self) -> u64 {
        self.maximum_phase_recomputation_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog;

    fn selected_lifecycle() -> (
        CompactPublicKeyRelationCatalog,
        CfwReductionCatalog,
        CfwLifecycleCatalog,
    ) {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let reduction =
            CfwReductionCatalog::derive(&relation).expect("complete CFW reduction catalog");
        let lifecycle = CfwLifecycleCatalog::derive(&relation, &reduction)
            .expect("complete bounded CFW lifecycle");
        (relation, reduction, lifecycle)
    }

    #[test]
    fn selected_cfw_lifecycle_streams_the_initial_round_and_bounds_rolling_storage() {
        let (_, _, lifecycle) = selected_lifecycle();

        assert_eq!(lifecycle.r1cs_row_count, 8_388_608);
        assert_eq!(lifecycle.sumcheck_round_count, 23);
        assert_eq!(lifecycle.stream_chunk_element_count, 16_384);
        assert_eq!(lifecycle.stream_chunk_byte_length, 655_360);
        assert_eq!(lifecycle.structured_matrix_row_evaluation_count, 50_331_648);
        assert_eq!(lifecycle.sumcheck_suffix_evaluation_count, 8_388_607);
        assert_eq!(lifecycle.matrix_fold_output_element_count, 25_165_821);
        assert_eq!(lifecycle.external_object_count, 69);
        assert_eq!(lifecycle.maximum_active_external_object_count, 4);
        assert_eq!(lifecycle.external_append_transaction_count, 1_575);
        assert_eq!(lifecycle.external_read_transaction_count, 3_144);
        assert_eq!(lifecycle.external_delete_transaction_count, 69);
        assert_eq!(lifecycle.external_transaction_count, 4_926);
        assert_eq!(lifecycle.external_write_extension_element_count, 25_165_821);
        assert_eq!(lifecycle.external_read_extension_element_count, 50_331_636);
        assert_eq!(lifecycle.external_write_byte_length, 1_006_632_840);
        assert_eq!(lifecycle.external_read_byte_length, 2_013_265_440);
        assert_eq!(lifecycle.maximum_external_stored_byte_length, 587_202_560);
        assert_eq!(lifecycle.external_prover_state_inline_byte_length, 2_792);
        assert_eq!(lifecycle.external_runtime_index_heap_byte_length, 1_380);
        assert_eq!(
            lifecycle.external_executor_resident_owned_payload_byte_length,
            4_416
        );
        assert_eq!(lifecycle.inner_mask_heap_byte_length, 11_040);
        assert_eq!(lifecycle.outer_mask_heap_byte_length, 7_360);
        assert_eq!(lifecycle.equality_point_heap_byte_length, 920);
        assert_eq!(lifecycle.round_challenge_heap_byte_length, 920);
        assert_eq!(lifecycle.maximum_accumulator_suffix_heap_byte_length, 880);
        assert_eq!(lifecycle.maximum_matrix_buffer_byte_length, 1_966_080);
        assert_eq!(lifecycle.maximum_encoded_chunk_byte_length, 655_360);
        assert_eq!(
            lifecycle.external_prover_resident_owned_byte_length,
            1_995_788
        );
        assert_eq!(lifecycle.maximum_kernel_live_byte_length, 2_651_148);
        assert_eq!(
            lifecycle.storage_transaction_runtime_inline_byte_length,
            472
        );
        assert_eq!(
            lifecycle.maximum_storage_operation_vector_heap_byte_length,
            160
        );
        assert_eq!(lifecycle.maximum_append_replay_length_heap_byte_length, 64);
        assert_eq!(lifecycle.maximum_read_result_vector_heap_byte_length, 24);
        assert_eq!(lifecycle.storage_replay_box_byte_length, 608);
        assert_eq!(lifecycle.storage_append_request_byte_length, 655_548);
        assert_eq!(lifecycle.storage_empty_response_byte_length, 80);
        assert_eq!(lifecycle.storage_read_request_byte_length, 188);
        assert_eq!(lifecycle.storage_read_response_byte_length, 655_528);
        assert_eq!(lifecycle.append_request_export_live_byte_length, 1_311_604);
        assert_eq!(lifecycle.read_response_supply_live_byte_length, 1_312_216);
        assert_eq!(lifecycle.read_replay_live_byte_length, 1_312_048);
        assert_eq!(
            lifecycle.maximum_storage_transaction_live_byte_length,
            1_312_216
        );
        assert_eq!(lifecycle.maximum_cfw_runtime_live_byte_length, 3_308_004);
        assert_eq!(
            lifecycle.maximum_boundary_transfer_live_byte_length,
            655_716
        );
        assert_eq!(lifecycle.validated_external_plan_step_count, 70);
        assert_eq!(lifecycle.secret_seal_invocation_count, 1_713);
        assert_eq!(lifecycle.secret_sealed_plaintext_byte_length, 1_006_633_461);
        assert_eq!(lifecycle.deterministic_safe_boundary_count, 2_657);
        assert_eq!(
            lifecycle.maximum_uninterrupted_structured_row_evaluation_count,
            49_152,
        );
        assert_eq!(lifecycle.maximum_phase_recomputation_count, 1);
    }

    #[test]
    fn independent_lifecycle_checker_rejects_incomplete_storage_and_restart_bounds() {
        let (relation, reduction, lifecycle) = selected_lifecycle();

        let mut changed_peak = lifecycle.clone();
        changed_peak.maximum_external_stored_byte_length += 40;
        assert_eq!(
            changed_peak.check(&relation, &reduction),
            Err(CompactStaticCatalogError::IncompleteLifecycle),
        );

        let mut changed_restart = lifecycle.clone();
        changed_restart.maximum_phase_recomputation_count = 2;
        assert_eq!(
            changed_restart.check(&relation, &reduction),
            Err(CompactStaticCatalogError::IncompleteLifecycle),
        );

        let mut changed_validated_plan = lifecycle.clone();
        changed_validated_plan.validated_external_plan_step_count -= 1;
        assert_eq!(
            changed_validated_plan.check(&relation, &reduction),
            Err(CompactStaticCatalogError::IncompleteLifecycle),
        );
    }
}
