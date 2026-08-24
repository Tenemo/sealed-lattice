//! Bounded execution lifecycle for the compact CFW reduction.
//!
//! The first sumcheck round is evaluated twice from the structured matrices:
//! once to emit the round polynomial and once, after the challenge, to persist
//! only the three half-length folds. Later rounds read those folds in bounded
//! chunks and replace one matrix at a time. This prevents three full
//! extension-field row vectors from ever occupying either the WASM heap or
//! external storage.

use crate::bgv::proof_suite::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH;
use crate::bgv::proof_suite::compact_cfw::{COMPACT_CFW_MATRIX_COUNT, CompactCfwGeometry};
use crate::bgv::proof_suite::compact_cfw_external::CompactCfwExternalStorageCatalog;
use crate::bgv::proof_suite::external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH;

use super::cfw_reduction::CfwReductionCatalog;
use super::{
    CompactStaticCatalogError, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH, checked_add, checked_product,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;

const CFW_STREAM_CHUNK_ELEMENT_COUNT: u64 = 16_384;
const EXTERNAL_OBJECT_LIFECYCLE_TRANSACTION_COUNT: u64 = 3;
const ROUND_BOUNDARY_CHECKPOINT_COUNT_PER_ROUND: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CfwLifecycleCatalog {
    stream_chunk_element_count: u64,
    stream_chunk_byte_length: u64,
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
    deterministic_safe_boundary_count: u64,
    maximum_uninterrupted_structured_row_evaluation_count: u64,
    maximum_uninterrupted_external_element_count: u64,
    maximum_phase_recomputation_count: u64,
    validated_external_plan_step_count: u32,
    secret_seal_invocation_count: u64,
    secret_sealed_plaintext_byte_length: u64,
}

impl CfwLifecycleCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let witness_length = usize::try_from(relation.padded_witness_element_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let geometry = CompactCfwGeometry::derive(witness_length)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let validated_external_plan = CompactCfwExternalStorageCatalog::derive(geometry)
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
        if maximum_external_stored_byte_length
            >= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }
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
            || validated_external_plan.step_count() == 0
            || validated_external_plan.secret_seal_invocation_count() == 0
            || validated_external_plan.secret_sealed_plaintext_byte_length()
                < external_write_byte_length
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }

        Ok(Self {
            stream_chunk_element_count: CFW_STREAM_CHUNK_ELEMENT_COUNT,
            stream_chunk_byte_length,
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
            deterministic_safe_boundary_count,
            maximum_uninterrupted_structured_row_evaluation_count,
            maximum_uninterrupted_external_element_count: CFW_STREAM_CHUNK_ELEMENT_COUNT,
            maximum_phase_recomputation_count: 1,
            validated_external_plan_step_count: validated_external_plan.step_count(),
            secret_seal_invocation_count: validated_external_plan.secret_seal_invocation_count(),
            secret_sealed_plaintext_byte_length: validated_external_plan
                .secret_sealed_plaintext_byte_length(),
        })
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

    fn selected_lifecycle() -> CfwLifecycleCatalog {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let reduction =
            CfwReductionCatalog::derive(&relation).expect("complete CFW reduction catalog");
        CfwLifecycleCatalog::derive(&relation, &reduction).expect("complete bounded CFW lifecycle")
    }

    #[test]
    fn selected_cfw_lifecycle_streams_the_initial_round_and_bounds_rolling_storage() {
        let lifecycle = selected_lifecycle();

        assert_eq!(lifecycle.stream_chunk_element_count, 16_384);
        assert_eq!(lifecycle.stream_chunk_byte_length, 655_360);
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
        assert_eq!(lifecycle.validated_external_plan_step_count, 70);
        assert_eq!(lifecycle.secret_seal_invocation_count, 1_713);
        assert_eq!(lifecycle.secret_sealed_plaintext_byte_length, 1_006_633_461);
        assert_eq!(lifecycle.deterministic_safe_boundary_count, 2_657);
        assert_eq!(
            lifecycle.maximum_uninterrupted_structured_row_evaluation_count,
            49_152,
        );
        assert_eq!(
            lifecycle.maximum_uninterrupted_external_element_count,
            16_384
        );
        assert_eq!(lifecycle.maximum_phase_recomputation_count, 1);
    }
}
