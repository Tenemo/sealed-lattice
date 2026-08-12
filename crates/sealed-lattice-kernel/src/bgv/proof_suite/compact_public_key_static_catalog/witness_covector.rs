//! Independent structured-transpose ledger.
//!
//! This owner derives the blockwise matrix workload from the checked relation's
//! high-level families rather than from the structured-row compiler. It then
//! checks every count against the production transpose geometry. The ledger
//! accounts field payload only; allocator metadata and the release-WASM target
//! layout remain separate owners.

use crate::bgv::proof_suite::relation_plan::{
    COMPACT_STRUCTURED_WITNESS_COVECTOR_ELEMENT_CHUNK_COUNT, CompactPublicKeyRelationCatalog,
    CompactStructuredWitnessCovectorGeometry, CompactStructuredWitnessCovectorHostMemoryGeometry,
    CompactStructuredWitnessCovectorLifecycleGeometry,
    compact_structured_witness_covector_geometry,
    compact_structured_witness_covector_host_memory_geometry,
    compact_structured_witness_covector_lifecycle_geometry,
};

use super::{
    BASE_FIELD_ELEMENT_BYTE_LENGTH, CompactStaticCatalogError, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
    QUINTIC_EXTENSION_DEGREE, checked_add, checked_product,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WitnessCovectorCatalog {
    runtime_geometry: CompactStructuredWitnessCovectorGeometry,
    runtime_lifecycle_geometry: CompactStructuredWitnessCovectorLifecycleGeometry,
    runtime_host_memory_geometry: CompactStructuredWitnessCovectorHostMemoryGeometry,
    ring_degree: u64,
    padded_row_count: u64,
    row_variable_count: u32,
    ring_variable_count: u32,
    ring_block_count: u64,
    ring_block_variable_count: u32,
    operative_ring_block_count: u64,
    global_lookup_row_ordinal: u64,
    source_covector_element_count: u64,
    sparse_witness_update_count: u64,
    public_product_transpose_count: u64,
    distinct_public_product_vector_count: u64,
    product_fold_accumulation_count: u64,
    lookup_table_reciprocal_count: u64,
    transform_domain_size: u64,
    forward_extension_transform_count: u64,
    forward_base_transform_count: u64,
    inverse_extension_transform_count: u64,
    base_coordinate_transform_count: u64,
    transform_butterfly_count: u64,
    pointwise_extension_base_multiplication_count: u64,
    pointwise_base_multiplication_count: u64,
    negacyclic_fold_subtraction_count: u64,
    equality_weight_extension_multiplication_count: u64,
    destination_field_payload_byte_length: u64,
    row_equality_field_payload_byte_length: u64,
    lookup_phase_transient_field_payload_byte_length: u64,
    product_phase_transient_field_payload_byte_length: u64,
    maximum_transient_field_payload_byte_length: u64,
    maximum_accumulator_field_payload_byte_length: u64,
    element_chunk_count: u64,
    block_sparse_task_count: u64,
    range_sparse_task_count: u64,
    public_product_task_count: u64,
    lookup_reciprocal_task_count: u64,
    coefficient_equality_parent_expansion_count: u64,
    block_equality_parent_expansion_count: u64,
    sparse_witness_update_count_excluding_lookup_reciprocals: u64,
    coefficient_equality_poll_count: u64,
    block_equality_poll_count: u64,
    sparse_witness_poll_count: u64,
    lookup_table_prefix_poll_count: u64,
    lookup_table_inversion_poll_count: u64,
    lookup_table_reverse_poll_count: u64,
    coefficient_equality_transform_poll_count: u64,
    public_adjoint_fill_poll_count: u64,
    public_polynomial_transform_poll_count: u64,
    pointwise_product_poll_count: u64,
    product_polynomial_inverse_transform_poll_count: u64,
    negacyclic_product_fold_poll_count: u64,
    deterministic_poll_count: u64,
    maximum_uninterrupted_elementwise_work_unit_count: u64,
    maximum_uninterrupted_transform_butterfly_count: u64,
    authenticated_restart_record_count: u64,
    authenticated_restart_write_byte_length: u64,
    authenticated_restart_read_byte_length: u64,
    maximum_restart_recomputed_equality_parent_expansion_count: u64,
    maximum_restart_recomputed_sparse_witness_update_count: u64,
    maximum_restart_recomputed_transform_butterfly_count: u64,
    maximum_restart_recomputed_pointwise_multiplication_count: u64,
    maximum_restart_recomputed_fold_subtraction_count: u64,
    durable_accumulator_restart_is_implemented: bool,
    host_pointer_byte_length: u64,
    sparse_task_element_byte_length: u64,
    public_product_task_element_byte_length: u64,
    sparse_task_catalog_byte_length: u64,
    public_product_task_catalog_byte_length: u64,
    task_catalog_byte_length: u64,
    accumulator_inline_byte_length: u64,
    accumulator_control_byte_length: u64,
    initialization_point_copy_payload_byte_length: u64,
    initialization_resident_owned_byte_length: u64,
    maximum_resident_owned_byte_length: u64,
    claim_continuation_heap_payload_byte_length: u64,
    handoff_inline_byte_length: u64,
    handoff_control_byte_length: u64,
    handoff_initialization_resident_owned_byte_length: u64,
    handoff_maximum_resident_owned_byte_length: u64,
}

impl WitnessCovectorCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let runtime_geometry = compact_structured_witness_covector_geometry(relation)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let runtime_lifecycle_geometry =
            compact_structured_witness_covector_lifecycle_geometry(relation)
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let runtime_host_memory_geometry =
            compact_structured_witness_covector_host_memory_geometry(relation)
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let ring_degree = relation.ring_degree();
        let padded_row_count = relation.padded_constraint_count();
        if !ring_degree.is_power_of_two()
            || !padded_row_count.is_power_of_two()
            || !padded_row_count.is_multiple_of(ring_degree)
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let row_variable_count = padded_row_count.ilog2();
        let ring_variable_count = ring_degree.ilog2();
        let ring_block_count = padded_row_count / ring_degree;
        let ring_block_variable_count = ring_block_count.ilog2();

        let public_key_share_relation_count =
            u64::try_from(relation.public_key_share_relation_count())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let ordinary_anchor_relation_count =
            u64::try_from(relation.ordinary_anchor_relation_count())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let final_anchor_relation_count = u64::try_from(relation.final_anchor_relation_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let quotient_vector_count = relation.quotient_vector_count();
        if checked_add(
            checked_add(
                public_key_share_relation_count,
                ordinary_anchor_relation_count,
            )?,
            final_anchor_relation_count,
        )? != quotient_vector_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let shifted_ternary_vector_count = relation.shifted_ternary_vector_count();
        let shifted_eta_two_vector_count =
            u64::try_from(relation.shifted_eta_two_vector_count())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let public_product_transpose_count = relation.structured_public_ring_product_count();
        let distinct_public_product_vector_count =
            u64::try_from(relation.distinct_public_product_vector_count())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;

        let exact_sparse_ring_vector_update_count = checked_add(
            checked_product(&[
                2,
                checked_add(
                    public_key_share_relation_count,
                    ordinary_anchor_relation_count,
                )?,
            ])?,
            checked_product(&[3, final_anchor_relation_count])?,
        )?;
        let lookup_inverse_sparse_ring_vector_update_count =
            checked_product(&[2, quotient_vector_count])?;
        let ternary_sparse_ring_vector_update_count =
            checked_product(&[5, shifted_ternary_vector_count])?;
        let eta_two_sparse_ring_vector_update_count =
            checked_product(&[11, shifted_eta_two_vector_count])?;
        let blockwise_sparse_ring_vector_update_count = [
            exact_sparse_ring_vector_update_count,
            lookup_inverse_sparse_ring_vector_update_count,
            ternary_sparse_ring_vector_update_count,
            eta_two_sparse_ring_vector_update_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let lookup_inverse_element_count = checked_product(&[quotient_vector_count, ring_degree])?;
        let lookup_table_reciprocal_count = relation.quotient_lookup_table_value_count();
        let sparse_witness_update_count = [
            checked_product(&[blockwise_sparse_ring_vector_update_count, ring_degree])?,
            lookup_inverse_element_count,
            lookup_table_reciprocal_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        let operative_ring_block_count = [
            quotient_vector_count,
            quotient_vector_count,
            checked_product(&[2, shifted_ternary_vector_count])?,
            checked_product(&[4, shifted_eta_two_vector_count])?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let global_lookup_row_ordinal =
            checked_product(&[operative_ring_block_count, ring_degree])?;
        if checked_add(global_lookup_row_ordinal, 1)? != relation.operative_constraint_count() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let source_covector_element_count = relation.padded_witness_element_count();
        let transform_domain_size = checked_product(&[2, ring_degree])?;
        let forward_extension_transform_count = 1;
        let forward_base_transform_count = distinct_public_product_vector_count;
        let inverse_extension_transform_count = public_product_transpose_count;
        let base_coordinate_transform_count = checked_add(
            checked_product(&[
                checked_add(
                    forward_extension_transform_count,
                    inverse_extension_transform_count,
                )?,
                QUINTIC_EXTENSION_DEGREE,
            ])?,
            forward_base_transform_count,
        )?;
        let butterflies_per_transform = checked_product(&[
            transform_domain_size / 2,
            u64::from(transform_domain_size.ilog2()),
        ])?;
        let transform_butterfly_count =
            checked_product(&[base_coordinate_transform_count, butterflies_per_transform])?;
        let pointwise_extension_base_multiplication_count =
            checked_product(&[public_product_transpose_count, transform_domain_size])?;
        let pointwise_base_multiplication_count = checked_product(&[
            pointwise_extension_base_multiplication_count,
            QUINTIC_EXTENSION_DEGREE,
        ])?;
        let product_fold_accumulation_count =
            checked_product(&[public_product_transpose_count, ring_degree])?;
        let negacyclic_fold_subtraction_count = product_fold_accumulation_count;
        let equality_weight_extension_multiplication_count = checked_add(
            checked_product(&[2, ring_degree - 1])?,
            checked_product(&[2, ring_block_count - 1])?,
        )?;

        let destination_field_payload_byte_length = checked_product(&[
            source_covector_element_count,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let row_equality_field_payload_byte_length = checked_product(&[
            checked_add(ring_degree, ring_block_count)?,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let lookup_phase_transient_field_payload_byte_length = checked_add(
            row_equality_field_payload_byte_length,
            checked_product(&[
                lookup_table_reciprocal_count,
                EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
            ])?,
        )?;
        let product_phase_transient_field_payload_byte_length = [
            checked_product(&[transform_domain_size, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH])?,
            checked_product(&[ring_block_count, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH])?,
            checked_product(&[transform_domain_size, BASE_FIELD_ELEMENT_BYTE_LENGTH])?,
            checked_product(&[transform_domain_size, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH])?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let maximum_transient_field_payload_byte_length =
            lookup_phase_transient_field_payload_byte_length
                .max(product_phase_transient_field_payload_byte_length);
        let maximum_accumulator_field_payload_byte_length = checked_add(
            destination_field_payload_byte_length,
            maximum_transient_field_payload_byte_length,
        )?;

        let element_chunk_count = COMPACT_STRUCTURED_WITNESS_COVECTOR_ELEMENT_CHUNK_COUNT;
        let block_sparse_task_count = blockwise_sparse_ring_vector_update_count;
        let range_sparse_task_count = 1;
        let public_product_task_count = public_product_transpose_count;
        let lookup_reciprocal_task_count = 1;
        let coefficient_equality_parent_expansion_count = ring_degree - 1;
        let block_equality_parent_expansion_count = ring_block_count - 1;
        let sparse_witness_update_count_excluding_lookup_reciprocals = checked_add(
            checked_product(&[block_sparse_task_count, ring_degree])?,
            lookup_inverse_element_count,
        )?;
        let coefficient_equality_poll_count =
            equality_builder_poll_count(ring_degree, element_chunk_count)?;
        let block_equality_poll_count =
            equality_builder_poll_count(ring_block_count, element_chunk_count)?;
        let sparse_witness_poll_count = checked_add(
            checked_product(&[
                block_sparse_task_count,
                ring_degree.div_ceil(element_chunk_count),
            ])?,
            lookup_inverse_element_count.div_ceil(element_chunk_count),
        )?;
        let lookup_table_prefix_poll_count =
            lookup_table_reciprocal_count.div_ceil(element_chunk_count);
        let lookup_table_inversion_poll_count = 1;
        let lookup_table_reverse_poll_count = lookup_table_prefix_poll_count;
        let coefficient_equality_transform_poll_count = 1;
        let public_adjoint_fill_poll_count = checked_product(&[
            public_product_task_count,
            ring_degree.div_ceil(element_chunk_count),
        ])?;
        let public_polynomial_transform_poll_count = public_product_task_count;
        let pointwise_product_poll_count = checked_product(&[
            public_product_task_count,
            transform_domain_size.div_ceil(element_chunk_count),
        ])?;
        let product_polynomial_inverse_transform_poll_count = public_product_task_count;
        let negacyclic_product_fold_poll_count = public_adjoint_fill_poll_count;
        let deterministic_poll_count = [
            coefficient_equality_poll_count,
            block_equality_poll_count,
            sparse_witness_poll_count,
            lookup_table_prefix_poll_count,
            lookup_table_inversion_poll_count,
            lookup_table_reverse_poll_count,
            coefficient_equality_transform_poll_count,
            public_adjoint_fill_poll_count,
            public_polynomial_transform_poll_count,
            pointwise_product_poll_count,
            product_polynomial_inverse_transform_poll_count,
            negacyclic_product_fold_poll_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let maximum_uninterrupted_elementwise_work_unit_count = element_chunk_count;
        let maximum_uninterrupted_transform_butterfly_count = butterflies_per_transform;
        let maximum_restart_recomputed_equality_parent_expansion_count = checked_add(
            coefficient_equality_parent_expansion_count,
            block_equality_parent_expansion_count,
        )?;
        let host_pointer_byte_length = runtime_host_memory_geometry.pointer_byte_length();
        let sparse_task_element_byte_length =
            runtime_host_memory_geometry.sparse_task_element_byte_length();
        let public_product_task_element_byte_length =
            runtime_host_memory_geometry.public_product_task_element_byte_length();
        let sparse_task_catalog_byte_length = checked_product(&[
            checked_add(block_sparse_task_count, range_sparse_task_count)?,
            sparse_task_element_byte_length,
        ])?;
        let public_product_task_catalog_byte_length = checked_product(&[
            public_product_task_count,
            public_product_task_element_byte_length,
        ])?;
        let task_catalog_byte_length = checked_add(
            sparse_task_catalog_byte_length,
            public_product_task_catalog_byte_length,
        )?;
        let accumulator_inline_byte_length =
            runtime_host_memory_geometry.accumulator_inline_byte_length();
        let accumulator_control_byte_length =
            checked_add(accumulator_inline_byte_length, task_catalog_byte_length)?;
        let initialization_point_copy_payload_byte_length = checked_product(&[
            u64::from(row_variable_count),
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let initialization_resident_owned_byte_length = [
            accumulator_control_byte_length,
            destination_field_payload_byte_length,
            row_equality_field_payload_byte_length,
            initialization_point_copy_payload_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let maximum_resident_owned_byte_length = checked_add(
            accumulator_control_byte_length,
            maximum_accumulator_field_payload_byte_length,
        )?;
        let claim_continuation_heap_payload_byte_length = checked_product(&[
            2,
            u64::from(row_variable_count),
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let handoff_inline_byte_length = runtime_host_memory_geometry.handoff_inline_byte_length();
        let handoff_control_byte_length =
            checked_add(handoff_inline_byte_length, task_catalog_byte_length)?;
        let handoff_initialization_resident_owned_byte_length = [
            handoff_control_byte_length,
            destination_field_payload_byte_length,
            row_equality_field_payload_byte_length,
            initialization_point_copy_payload_byte_length,
            claim_continuation_heap_payload_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let handoff_maximum_resident_owned_byte_length = [
            handoff_control_byte_length,
            maximum_accumulator_field_payload_byte_length,
            claim_continuation_heap_payload_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        let catalog = Self {
            runtime_geometry,
            runtime_lifecycle_geometry,
            runtime_host_memory_geometry,
            ring_degree,
            padded_row_count,
            row_variable_count,
            ring_variable_count,
            ring_block_count,
            ring_block_variable_count,
            operative_ring_block_count,
            global_lookup_row_ordinal,
            source_covector_element_count,
            sparse_witness_update_count,
            public_product_transpose_count,
            distinct_public_product_vector_count,
            product_fold_accumulation_count,
            lookup_table_reciprocal_count,
            transform_domain_size,
            forward_extension_transform_count,
            forward_base_transform_count,
            inverse_extension_transform_count,
            base_coordinate_transform_count,
            transform_butterfly_count,
            pointwise_extension_base_multiplication_count,
            pointwise_base_multiplication_count,
            negacyclic_fold_subtraction_count,
            equality_weight_extension_multiplication_count,
            destination_field_payload_byte_length,
            row_equality_field_payload_byte_length,
            lookup_phase_transient_field_payload_byte_length,
            product_phase_transient_field_payload_byte_length,
            maximum_transient_field_payload_byte_length,
            maximum_accumulator_field_payload_byte_length,
            element_chunk_count,
            block_sparse_task_count,
            range_sparse_task_count,
            public_product_task_count,
            lookup_reciprocal_task_count,
            coefficient_equality_parent_expansion_count,
            block_equality_parent_expansion_count,
            sparse_witness_update_count_excluding_lookup_reciprocals,
            coefficient_equality_poll_count,
            block_equality_poll_count,
            sparse_witness_poll_count,
            lookup_table_prefix_poll_count,
            lookup_table_inversion_poll_count,
            lookup_table_reverse_poll_count,
            coefficient_equality_transform_poll_count,
            public_adjoint_fill_poll_count,
            public_polynomial_transform_poll_count,
            pointwise_product_poll_count,
            product_polynomial_inverse_transform_poll_count,
            negacyclic_product_fold_poll_count,
            deterministic_poll_count,
            maximum_uninterrupted_elementwise_work_unit_count,
            maximum_uninterrupted_transform_butterfly_count,
            authenticated_restart_record_count: 0,
            authenticated_restart_write_byte_length: 0,
            authenticated_restart_read_byte_length: 0,
            maximum_restart_recomputed_equality_parent_expansion_count,
            maximum_restart_recomputed_sparse_witness_update_count: sparse_witness_update_count,
            maximum_restart_recomputed_transform_butterfly_count: transform_butterfly_count,
            maximum_restart_recomputed_pointwise_multiplication_count:
                pointwise_extension_base_multiplication_count,
            maximum_restart_recomputed_fold_subtraction_count: negacyclic_fold_subtraction_count,
            durable_accumulator_restart_is_implemented: false,
            host_pointer_byte_length,
            sparse_task_element_byte_length,
            public_product_task_element_byte_length,
            sparse_task_catalog_byte_length,
            public_product_task_catalog_byte_length,
            task_catalog_byte_length,
            accumulator_inline_byte_length,
            accumulator_control_byte_length,
            initialization_point_copy_payload_byte_length,
            initialization_resident_owned_byte_length,
            maximum_resident_owned_byte_length,
            claim_continuation_heap_payload_byte_length,
            handoff_inline_byte_length,
            handoff_control_byte_length,
            handoff_initialization_resident_owned_byte_length,
            handoff_maximum_resident_owned_byte_length,
        };
        catalog.check(relation)?;
        Ok(catalog)
    }

    pub(super) fn check(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let runtime = compact_structured_witness_covector_geometry(relation)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let runtime_lifecycle = compact_structured_witness_covector_lifecycle_geometry(relation)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let runtime_host_memory =
            compact_structured_witness_covector_host_memory_geometry(relation)
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        if self.runtime_geometry != runtime
            || self.runtime_lifecycle_geometry != runtime_lifecycle
            || self.runtime_host_memory_geometry != runtime_host_memory
            || self.ring_degree != runtime.ring_degree()
            || self.padded_row_count != runtime.padded_row_count()
            || self.row_variable_count != runtime.row_variable_count()
            || self.ring_variable_count != runtime.ring_variable_count()
            || self.ring_block_count != runtime.ring_block_count()
            || self.ring_block_variable_count != runtime.ring_block_variable_count()
            || self.operative_ring_block_count != runtime.operative_ring_block_count()
            || self.global_lookup_row_ordinal != runtime.global_lookup_row_ordinal()
            || self.source_covector_element_count != runtime.source_covector_element_count()
            || self.sparse_witness_update_count != runtime.sparse_witness_update_count()
            || self.public_product_transpose_count != runtime.public_product_transpose_count()
            || self.distinct_public_product_vector_count
                != runtime.distinct_public_product_vector_count()
            || self.product_fold_accumulation_count != runtime.product_fold_accumulation_count()
            || self.lookup_table_reciprocal_count != runtime.lookup_table_reciprocal_count()
            || self.transform_domain_size != runtime.transform_domain_size()
            || self.forward_extension_transform_count != runtime.forward_extension_transform_count()
            || self.forward_base_transform_count != runtime.forward_base_transform_count()
            || self.inverse_extension_transform_count != runtime.inverse_extension_transform_count()
            || self.base_coordinate_transform_count != runtime.base_coordinate_transform_count()
            || self.transform_butterfly_count != runtime.transform_butterfly_count()
            || self.pointwise_extension_base_multiplication_count
                != runtime.pointwise_extension_base_multiplication_count()
            || self.pointwise_base_multiplication_count
                != runtime.pointwise_base_multiplication_count()
            || self.negacyclic_fold_subtraction_count != runtime.negacyclic_fold_subtraction_count()
            || self.equality_weight_extension_multiplication_count
                != runtime.equality_weight_extension_multiplication_count()
            || self.destination_field_payload_byte_length
                != runtime.destination_field_payload_byte_length()
            || self.row_equality_field_payload_byte_length
                != runtime.row_equality_field_payload_byte_length()
            || self.lookup_phase_transient_field_payload_byte_length
                != runtime.lookup_phase_transient_field_payload_byte_length()
            || self.product_phase_transient_field_payload_byte_length
                != runtime.product_phase_transient_field_payload_byte_length()
            || self.maximum_transient_field_payload_byte_length
                != runtime.maximum_transient_field_payload_byte_length()
            || self.maximum_accumulator_field_payload_byte_length
                != runtime.maximum_accumulator_field_payload_byte_length()
            || self.element_chunk_count != runtime_lifecycle.element_chunk_count()
            || self.block_sparse_task_count != runtime_lifecycle.block_sparse_task_count()
            || self.range_sparse_task_count != runtime_lifecycle.range_sparse_task_count()
            || self.public_product_task_count != runtime_lifecycle.public_product_task_count()
            || self.lookup_reciprocal_task_count != runtime_lifecycle.lookup_reciprocal_task_count()
            || self.coefficient_equality_parent_expansion_count
                != runtime_lifecycle.coefficient_equality_parent_expansion_count()
            || self.block_equality_parent_expansion_count
                != runtime_lifecycle.block_equality_parent_expansion_count()
            || self.sparse_witness_update_count_excluding_lookup_reciprocals
                != runtime_lifecycle.sparse_witness_update_count_excluding_lookup_reciprocals()
            || self.coefficient_equality_poll_count
                != runtime_lifecycle.coefficient_equality_poll_count()
            || self.block_equality_poll_count != runtime_lifecycle.block_equality_poll_count()
            || self.sparse_witness_poll_count != runtime_lifecycle.sparse_witness_poll_count()
            || self.lookup_table_prefix_poll_count
                != runtime_lifecycle.lookup_table_prefix_poll_count()
            || self.lookup_table_inversion_poll_count
                != runtime_lifecycle.lookup_table_inversion_poll_count()
            || self.lookup_table_reverse_poll_count
                != runtime_lifecycle.lookup_table_reverse_poll_count()
            || self.coefficient_equality_transform_poll_count
                != runtime_lifecycle.coefficient_equality_transform_poll_count()
            || self.public_adjoint_fill_poll_count
                != runtime_lifecycle.public_adjoint_fill_poll_count()
            || self.public_polynomial_transform_poll_count
                != runtime_lifecycle.public_polynomial_transform_poll_count()
            || self.pointwise_product_poll_count != runtime_lifecycle.pointwise_product_poll_count()
            || self.product_polynomial_inverse_transform_poll_count
                != runtime_lifecycle.product_polynomial_inverse_transform_poll_count()
            || self.negacyclic_product_fold_poll_count
                != runtime_lifecycle.negacyclic_product_fold_poll_count()
            || self.deterministic_poll_count != runtime_lifecycle.deterministic_poll_count()
            || self.maximum_uninterrupted_elementwise_work_unit_count
                != runtime_lifecycle.maximum_uninterrupted_elementwise_work_unit_count()
            || self.maximum_uninterrupted_transform_butterfly_count
                != runtime_lifecycle.maximum_uninterrupted_transform_butterfly_count()
            || self.authenticated_restart_record_count != 0
            || self.authenticated_restart_write_byte_length != 0
            || self.authenticated_restart_read_byte_length != 0
            || self.maximum_restart_recomputed_equality_parent_expansion_count
                != checked_add(
                    self.coefficient_equality_parent_expansion_count,
                    self.block_equality_parent_expansion_count,
                )?
            || self.maximum_restart_recomputed_sparse_witness_update_count
                != self.sparse_witness_update_count
            || self.maximum_restart_recomputed_transform_butterfly_count
                != self.transform_butterfly_count
            || self.maximum_restart_recomputed_pointwise_multiplication_count
                != self.pointwise_extension_base_multiplication_count
            || self.maximum_restart_recomputed_fold_subtraction_count
                != self.negacyclic_fold_subtraction_count
            || self.durable_accumulator_restart_is_implemented
            || self.host_pointer_byte_length != runtime_host_memory.pointer_byte_length()
            || self.sparse_task_element_byte_length
                != runtime_host_memory.sparse_task_element_byte_length()
            || self.public_product_task_element_byte_length
                != runtime_host_memory.public_product_task_element_byte_length()
            || self.sparse_task_catalog_byte_length
                != runtime_host_memory.sparse_task_catalog_byte_length()
            || self.public_product_task_catalog_byte_length
                != runtime_host_memory.public_product_task_catalog_byte_length()
            || self.task_catalog_byte_length != runtime_host_memory.task_catalog_byte_length()
            || self.accumulator_inline_byte_length
                != runtime_host_memory.accumulator_inline_byte_length()
            || self.accumulator_control_byte_length
                != runtime_host_memory.accumulator_control_byte_length()
            || self.initialization_point_copy_payload_byte_length
                != runtime_host_memory.initialization_point_copy_payload_byte_length()
            || self.initialization_resident_owned_byte_length
                != runtime_host_memory.initialization_resident_owned_byte_length()
            || self.maximum_resident_owned_byte_length
                != runtime_host_memory.maximum_resident_owned_byte_length()
            || self.claim_continuation_heap_payload_byte_length
                != runtime_host_memory.claim_continuation_heap_payload_byte_length()
            || self.handoff_inline_byte_length != runtime_host_memory.handoff_inline_byte_length()
            || self.handoff_control_byte_length != runtime_host_memory.handoff_control_byte_length()
            || self.handoff_initialization_resident_owned_byte_length
                != runtime_host_memory.handoff_initialization_resident_owned_byte_length()
            || self.handoff_maximum_resident_owned_byte_length
                != runtime_host_memory.handoff_maximum_resident_owned_byte_length()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    pub(super) const fn transform_butterfly_count(&self) -> u64 {
        self.transform_butterfly_count
    }

    pub(super) const fn maximum_transient_field_payload_byte_length(&self) -> u64 {
        self.maximum_transient_field_payload_byte_length
    }
}

fn equality_builder_poll_count(
    final_weight_count: u64,
    element_chunk_count: u64,
) -> Result<u64, CompactStaticCatalogError> {
    if final_weight_count < 2 || !final_weight_count.is_power_of_two() || element_chunk_count == 0 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let mut parent_count = 1_u64;
    let mut poll_count = 0_u64;
    while parent_count < final_weight_count {
        poll_count = checked_add(poll_count, parent_count.div_ceil(element_chunk_count))?;
        parent_count = checked_product(&[parent_count, 2])?;
    }
    Ok(poll_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog;

    #[test]
    fn selected_witness_covector_ledger_matches_the_structured_compiler() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let catalog = WitnessCovectorCatalog::derive(&relation)
            .expect("independent witness-covector catalog");

        assert_eq!(catalog.operative_ring_block_count, 82);
        assert_eq!(catalog.sparse_witness_update_count, 6_979_584);
        assert_eq!(catalog.public_product_transpose_count, 32);
        assert_eq!(catalog.distinct_public_product_vector_count, 32);
        assert_eq!(catalog.base_coordinate_transform_count, 197);
        assert_eq!(catalog.transform_butterfly_count, 103_284_736);
        assert_eq!(
            catalog.maximum_transient_field_payload_byte_length,
            6_563_840
        );
        assert_eq!(
            catalog.maximum_accumulator_field_payload_byte_length,
            174_336_000
        );
        assert_eq!(catalog.element_chunk_count, 8_192);
        assert_eq!(catalog.block_sparse_task_count, 180);
        assert_eq!(catalog.range_sparse_task_count, 1);
        assert_eq!(catalog.public_product_task_count, 32);
        assert_eq!(catalog.lookup_reciprocal_task_count, 1);
        assert_eq!(catalog.coefficient_equality_parent_expansion_count, 32_767);
        assert_eq!(catalog.block_equality_parent_expansion_count, 255);
        assert_eq!(
            catalog.sparse_witness_update_count_excluding_lookup_reciprocals,
            6_848_512
        );
        assert_eq!(catalog.coefficient_equality_poll_count, 16);
        assert_eq!(catalog.block_equality_poll_count, 8);
        assert_eq!(catalog.sparse_witness_poll_count, 836);
        assert_eq!(catalog.lookup_table_prefix_poll_count, 16);
        assert_eq!(catalog.lookup_table_inversion_poll_count, 1);
        assert_eq!(catalog.lookup_table_reverse_poll_count, 16);
        assert_eq!(catalog.coefficient_equality_transform_poll_count, 1);
        assert_eq!(catalog.public_adjoint_fill_poll_count, 128);
        assert_eq!(catalog.public_polynomial_transform_poll_count, 32);
        assert_eq!(catalog.pointwise_product_poll_count, 256);
        assert_eq!(catalog.product_polynomial_inverse_transform_poll_count, 32);
        assert_eq!(catalog.negacyclic_product_fold_poll_count, 128);
        assert_eq!(catalog.deterministic_poll_count, 1_470);
        assert_eq!(
            catalog.maximum_uninterrupted_elementwise_work_unit_count,
            8_192
        );
        assert_eq!(
            catalog.maximum_uninterrupted_transform_butterfly_count,
            524_288
        );
        assert_eq!(catalog.authenticated_restart_record_count, 0);
        assert_eq!(catalog.authenticated_restart_write_byte_length, 0);
        assert_eq!(catalog.authenticated_restart_read_byte_length, 0);
        assert_eq!(
            catalog.maximum_restart_recomputed_equality_parent_expansion_count,
            33_022
        );
        assert_eq!(
            catalog.maximum_restart_recomputed_sparse_witness_update_count,
            6_979_584
        );
        assert_eq!(
            catalog.maximum_restart_recomputed_transform_butterfly_count,
            103_284_736
        );
        assert_eq!(
            catalog.maximum_restart_recomputed_pointwise_multiplication_count,
            2_097_152
        );
        assert_eq!(
            catalog.maximum_restart_recomputed_fold_subtraction_count,
            1_048_576
        );
        assert!(!catalog.durable_accumulator_restart_is_implemented);
        assert_eq!(catalog.host_pointer_byte_length, 8);
        assert_eq!(catalog.sparse_task_element_byte_length, 64);
        assert_eq!(catalog.public_product_task_element_byte_length, 48);
        assert_eq!(catalog.sparse_task_catalog_byte_length, 11_584);
        assert_eq!(catalog.public_product_task_catalog_byte_length, 1_536);
        assert_eq!(catalog.task_catalog_byte_length, 13_120);
        assert_eq!(catalog.accumulator_inline_byte_length, 592);
        assert_eq!(catalog.accumulator_control_byte_length, 13_712);
        assert_eq!(catalog.initialization_point_copy_payload_byte_length, 920);
        assert_eq!(
            catalog.initialization_resident_owned_byte_length,
            169_107_752
        );
        assert_eq!(catalog.maximum_resident_owned_byte_length, 174_349_712);
        assert_eq!(catalog.claim_continuation_heap_payload_byte_length, 1_840);
        assert_eq!(catalog.handoff_inline_byte_length, 1_072);
        assert_eq!(catalog.handoff_control_byte_length, 14_192);
        assert_eq!(
            catalog.handoff_initialization_resident_owned_byte_length,
            169_110_072
        );
        assert_eq!(
            catalog.handoff_maximum_resident_owned_byte_length,
            174_352_032
        );
    }

    #[test]
    fn selected_witness_covector_lifecycle_refuses_mutated_counts() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let catalog = WitnessCovectorCatalog::derive(&relation)
            .expect("independent witness-covector catalog");

        let mut wrong_poll_count = catalog.clone();
        wrong_poll_count.pointwise_product_poll_count += 1;
        assert_eq!(
            wrong_poll_count.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut false_restart_claim = catalog;
        false_restart_claim.durable_accumulator_restart_is_implemented = true;
        assert_eq!(
            false_restart_claim.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
