//! Structured transpose geometry for the compact CFW-to-WHIR handoff.
//!
//! CFW folds row coordinates from least significant to most significant. The
//! selected relation therefore splits every row equality weight into a
//! ring-coefficient vector and a ring-block vector. Sparse matrix terms are
//! accumulated blockwise, while each public negacyclic band is transposed with
//! one shared extension transform, one verifier-owned public base transform,
//! and one extension inverse transform. This module accounts that production
//! path without executing a selected-size transpose.

mod accumulator;

pub(crate) const COMPACT_STRUCTURED_WITNESS_COVECTOR_ELEMENT_CHUNK_COUNT: u64 = 8_192;

use crate::bgv::proof_suite::{
    ProofBaseFieldElement, ProofChallengeExtensionElement, compact_cfw::CompactChallengeField,
    prover::CommonProofProverError,
};

use super::{
    CompactStructuredLinearForm, CompactStructuredMatrixTerm, CompactStructuredR1csCatalog,
};
use crate::bgv::proof_suite::relation_plan::compact_ring_vector::{
    CompactPublicKeyRelationCatalog, CompactR1csConstraintKind, RelationPlanError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactStructuredWitnessCovectorGeometry {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactStructuredWitnessCovectorLifecycleGeometry {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactStructuredWitnessCovectorHostMemoryGeometry {
    pointer_byte_length: u64,
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

impl CompactStructuredWitnessCovectorGeometry {
    fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
    ) -> Result<Self, CommonProofProverError> {
        let ring_degree = relation.ring_degree;
        let padded_row_count = relation.padded_constraint_count;
        if ring_degree < 2
            || !ring_degree.is_power_of_two()
            || padded_row_count < ring_degree
            || !padded_row_count.is_power_of_two()
            || padded_row_count % ring_degree != 0
            || matrices.row_count != padded_row_count
            || matrices.witness_length != relation.padded_witness_element_count
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }

        let row_variable_count = padded_row_count.ilog2();
        let ring_variable_count = ring_degree.ilog2();
        let ring_block_count = padded_row_count
            .checked_div(ring_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if !ring_block_count.is_power_of_two() {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        let ring_block_variable_count = ring_block_count.ilog2();
        if ring_variable_count
            .checked_add(ring_block_variable_count)
            .ok_or(CommonProofProverError::CountOverflow)?
            != row_variable_count
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }

        let global_lookup_segment = relation
            .ordered_constraint_segments
            .iter()
            .find(|segment| segment.kind == CompactR1csConstraintKind::LookupLogDerivativeEquality)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        if global_lookup_segment.row_count != 1
            || global_lookup_segment.first_row % ring_degree != 0
            || global_lookup_segment.first_row
                != relation
                    .operative_constraint_count
                    .checked_sub(1)
                    .ok_or(RelationPlanError::InvalidConstraint)?
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        let operative_ring_block_count = global_lookup_segment
            .first_row
            .checked_div(ring_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let global_lookup_row_ordinal = global_lookup_segment.first_row;

        let mut sparse_witness_update_count = 0_u64;
        let mut public_product_transpose_count = 0_u64;
        let mut distinct_public_product_first_columns = Vec::new();
        let mut lookup_table_reciprocal_count = 0_u64;
        for segment in &relation.ordered_constraint_segments {
            match segment.kind {
                CompactR1csConstraintKind::ZeroPadding => {
                    if segment.first_row != relation.operative_constraint_count
                        || segment
                            .first_row
                            .checked_add(segment.row_count)
                            .ok_or(CommonProofProverError::CountOverflow)?
                            != padded_row_count
                    {
                        return Err(RelationPlanError::InvalidConstraint.into());
                    }
                    let padding_row = matrices.row(relation, segment.first_row)?;
                    for form in [&padding_row.left, &padding_row.right, &padding_row.output] {
                        if !form.ordered_terms.is_empty() {
                            return Err(RelationPlanError::InvalidConstraint.into());
                        }
                    }
                }
                CompactR1csConstraintKind::LookupLogDerivativeEquality => {
                    let row = matrices.row(relation, segment.first_row)?;
                    for form in [&row.left, &row.right, &row.output] {
                        count_form_contributions(
                            form,
                            matrices,
                            1,
                            true,
                            &mut sparse_witness_update_count,
                            &mut public_product_transpose_count,
                            &mut distinct_public_product_first_columns,
                            &mut lookup_table_reciprocal_count,
                        )?;
                    }
                }
                _ => {
                    if segment.first_row % ring_degree != 0 || segment.row_count % ring_degree != 0
                    {
                        return Err(RelationPlanError::InvalidConstraint.into());
                    }
                    let block_count = segment
                        .row_count
                        .checked_div(ring_degree)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    for block_offset in 0..block_count {
                        let representative_row_ordinal = segment
                            .first_row
                            .checked_add(
                                block_offset
                                    .checked_mul(ring_degree)
                                    .ok_or(CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::CountOverflow)?;
                        let row = matrices.row(relation, representative_row_ordinal)?;
                        for form in [&row.left, &row.right, &row.output] {
                            count_form_contributions(
                                form,
                                matrices,
                                ring_degree,
                                false,
                                &mut sparse_witness_update_count,
                                &mut public_product_transpose_count,
                                &mut distinct_public_product_first_columns,
                                &mut lookup_table_reciprocal_count,
                            )?;
                        }
                    }
                }
            }
        }
        distinct_public_product_first_columns.sort_unstable();
        distinct_public_product_first_columns.dedup();
        let distinct_public_product_vector_count =
            u64::try_from(distinct_public_product_first_columns.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        if public_product_transpose_count != relation.structured_public_ring_product_count
            || lookup_table_reciprocal_count != relation.quotient_lookup_table_value_count
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }

        let source_covector_element_count = relation.padded_witness_element_count;
        let transform_domain_size = ring_degree
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let forward_extension_transform_count = 1_u64;
        let forward_base_transform_count = distinct_public_product_vector_count;
        let inverse_extension_transform_count = public_product_transpose_count;
        let extension_degree = u64::from(relation.extension_degree);
        let base_coordinate_transform_count = forward_extension_transform_count
            .checked_add(inverse_extension_transform_count)
            .and_then(|count| count.checked_mul(extension_degree))
            .and_then(|count| count.checked_add(forward_base_transform_count))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let butterflies_per_transform = transform_domain_size
            .checked_div(2)
            .and_then(|count| count.checked_mul(u64::from(transform_domain_size.ilog2())))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let transform_butterfly_count = base_coordinate_transform_count
            .checked_mul(butterflies_per_transform)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let pointwise_extension_base_multiplication_count = public_product_transpose_count
            .checked_mul(transform_domain_size)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let pointwise_base_multiplication_count = pointwise_extension_base_multiplication_count
            .checked_mul(extension_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let product_fold_accumulation_count = public_product_transpose_count
            .checked_mul(ring_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let negacyclic_fold_subtraction_count = product_fold_accumulation_count;
        let equality_weight_extension_multiplication_count = ring_degree
            .checked_sub(1)
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| {
                ring_block_count
                    .checked_sub(1)
                    .and_then(|block_count| block_count.checked_mul(2))
                    .and_then(|block_count| count.checked_add(block_count))
            })
            .ok_or(CommonProofProverError::CountOverflow)?;

        let extension_element_byte_length =
            u64::try_from(core::mem::size_of::<CompactChallengeField>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let production_extension_element_byte_length =
            u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let base_element_byte_length = u64::try_from(core::mem::size_of::<ProofBaseFieldElement>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if extension_element_byte_length != production_extension_element_byte_length
            || extension_element_byte_length
                != extension_degree
                    .checked_mul(base_element_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        let destination_field_payload_byte_length = source_covector_element_count
            .checked_mul(extension_element_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let row_equality_field_payload_byte_length = ring_degree
            .checked_add(ring_block_count)
            .and_then(|count| count.checked_mul(extension_element_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let lookup_prefix_payload_byte_length = lookup_table_reciprocal_count
            .checked_mul(extension_element_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let lookup_phase_transient_field_payload_byte_length =
            row_equality_field_payload_byte_length
                .checked_add(lookup_prefix_payload_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?;
        let transformed_low_equality_payload_byte_length = transform_domain_size
            .checked_mul(extension_element_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let high_equality_payload_byte_length = ring_block_count
            .checked_mul(extension_element_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let public_transform_payload_byte_length = transform_domain_size
            .checked_mul(base_element_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let product_transform_payload_byte_length = transformed_low_equality_payload_byte_length;
        let product_phase_transient_field_payload_byte_length = [
            transformed_low_equality_payload_byte_length,
            high_equality_payload_byte_length,
            public_transform_payload_byte_length,
            product_transform_payload_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(byte_length)
                .ok_or(CommonProofProverError::CountOverflow)
        })?;
        let maximum_transient_field_payload_byte_length =
            lookup_phase_transient_field_payload_byte_length
                .max(product_phase_transient_field_payload_byte_length);
        let maximum_accumulator_field_payload_byte_length = destination_field_payload_byte_length
            .checked_add(maximum_transient_field_payload_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;

        let geometry = Self {
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
        };
        accumulator::StructuredTransposePlan::from_production(relation, matrices, geometry)?;
        Ok(geometry)
    }

    pub(crate) const fn ring_degree(self) -> u64 {
        self.ring_degree
    }

    pub(crate) const fn padded_row_count(self) -> u64 {
        self.padded_row_count
    }

    pub(crate) const fn row_variable_count(self) -> u32 {
        self.row_variable_count
    }

    pub(crate) const fn ring_variable_count(self) -> u32 {
        self.ring_variable_count
    }

    pub(crate) const fn ring_block_count(self) -> u64 {
        self.ring_block_count
    }

    pub(crate) const fn ring_block_variable_count(self) -> u32 {
        self.ring_block_variable_count
    }

    pub(crate) const fn operative_ring_block_count(self) -> u64 {
        self.operative_ring_block_count
    }

    pub(crate) const fn global_lookup_row_ordinal(self) -> u64 {
        self.global_lookup_row_ordinal
    }

    pub(crate) const fn source_covector_element_count(self) -> u64 {
        self.source_covector_element_count
    }

    pub(crate) const fn sparse_witness_update_count(self) -> u64 {
        self.sparse_witness_update_count
    }

    pub(crate) const fn public_product_transpose_count(self) -> u64 {
        self.public_product_transpose_count
    }

    pub(crate) const fn distinct_public_product_vector_count(self) -> u64 {
        self.distinct_public_product_vector_count
    }

    pub(crate) const fn product_fold_accumulation_count(self) -> u64 {
        self.product_fold_accumulation_count
    }

    pub(crate) const fn lookup_table_reciprocal_count(self) -> u64 {
        self.lookup_table_reciprocal_count
    }

    pub(crate) const fn transform_domain_size(self) -> u64 {
        self.transform_domain_size
    }

    pub(crate) const fn forward_extension_transform_count(self) -> u64 {
        self.forward_extension_transform_count
    }

    pub(crate) const fn forward_base_transform_count(self) -> u64 {
        self.forward_base_transform_count
    }

    pub(crate) const fn inverse_extension_transform_count(self) -> u64 {
        self.inverse_extension_transform_count
    }

    pub(crate) const fn base_coordinate_transform_count(self) -> u64 {
        self.base_coordinate_transform_count
    }

    pub(crate) const fn transform_butterfly_count(self) -> u64 {
        self.transform_butterfly_count
    }

    pub(crate) const fn pointwise_extension_base_multiplication_count(self) -> u64 {
        self.pointwise_extension_base_multiplication_count
    }

    pub(crate) const fn pointwise_base_multiplication_count(self) -> u64 {
        self.pointwise_base_multiplication_count
    }

    pub(crate) const fn negacyclic_fold_subtraction_count(self) -> u64 {
        self.negacyclic_fold_subtraction_count
    }

    pub(crate) const fn equality_weight_extension_multiplication_count(self) -> u64 {
        self.equality_weight_extension_multiplication_count
    }

    pub(crate) const fn destination_field_payload_byte_length(self) -> u64 {
        self.destination_field_payload_byte_length
    }

    pub(crate) const fn row_equality_field_payload_byte_length(self) -> u64 {
        self.row_equality_field_payload_byte_length
    }

    pub(crate) const fn lookup_phase_transient_field_payload_byte_length(self) -> u64 {
        self.lookup_phase_transient_field_payload_byte_length
    }

    pub(crate) const fn product_phase_transient_field_payload_byte_length(self) -> u64 {
        self.product_phase_transient_field_payload_byte_length
    }

    pub(crate) const fn maximum_transient_field_payload_byte_length(self) -> u64 {
        self.maximum_transient_field_payload_byte_length
    }

    pub(crate) const fn maximum_accumulator_field_payload_byte_length(self) -> u64 {
        self.maximum_accumulator_field_payload_byte_length
    }
}

impl CompactStructuredWitnessCovectorLifecycleGeometry {
    fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        workload: CompactStructuredWitnessCovectorGeometry,
    ) -> Result<Self, CommonProofProverError> {
        let geometry =
            accumulator::StructuredTransposePlan::from_production(relation, matrices, workload)?
                .lifecycle_geometry(workload)?;
        geometry.check(workload)?;
        Ok(geometry)
    }

    fn check(
        self,
        workload: CompactStructuredWitnessCovectorGeometry,
    ) -> Result<(), CommonProofProverError> {
        let recomputed_poll_count = [
            self.coefficient_equality_poll_count,
            self.block_equality_poll_count,
            self.sparse_witness_poll_count,
            self.lookup_table_prefix_poll_count,
            self.lookup_table_inversion_poll_count,
            self.lookup_table_reverse_poll_count,
            self.coefficient_equality_transform_poll_count,
            self.public_adjoint_fill_poll_count,
            self.public_polynomial_transform_poll_count,
            self.pointwise_product_poll_count,
            self.product_polynomial_inverse_transform_poll_count,
            self.negacyclic_product_fold_poll_count,
        ]
        .into_iter()
        .try_fold(0_u64, |count, phase_count| {
            count
                .checked_add(phase_count)
                .ok_or(CommonProofProverError::CountOverflow)
        })?;
        if self.element_chunk_count == 0
            || !self.element_chunk_count.is_power_of_two()
            || self.block_sparse_task_count == 0
            || self.range_sparse_task_count == 0
            || self.public_product_task_count != workload.public_product_transpose_count()
            || self.lookup_reciprocal_task_count != 1
            || self.coefficient_equality_parent_expansion_count
                != workload
                    .ring_degree()
                    .checked_sub(1)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.block_equality_parent_expansion_count
                != workload
                    .ring_block_count()
                    .checked_sub(1)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self
                .sparse_witness_update_count_excluding_lookup_reciprocals
                .checked_add(workload.lookup_table_reciprocal_count())
                .ok_or(CommonProofProverError::CountOverflow)?
                != workload.sparse_witness_update_count()
            || self.lookup_table_inversion_poll_count != 1
            || self.coefficient_equality_transform_poll_count != 1
            || self.deterministic_poll_count != recomputed_poll_count
            || self.maximum_uninterrupted_elementwise_work_unit_count != self.element_chunk_count
            || self.maximum_uninterrupted_transform_butterfly_count == 0
            || self.maximum_uninterrupted_transform_butterfly_count
                > workload.transform_butterfly_count()
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        Ok(())
    }

    pub(crate) const fn element_chunk_count(self) -> u64 {
        self.element_chunk_count
    }

    pub(crate) const fn block_sparse_task_count(self) -> u64 {
        self.block_sparse_task_count
    }

    pub(crate) const fn range_sparse_task_count(self) -> u64 {
        self.range_sparse_task_count
    }

    pub(crate) const fn public_product_task_count(self) -> u64 {
        self.public_product_task_count
    }

    pub(crate) const fn lookup_reciprocal_task_count(self) -> u64 {
        self.lookup_reciprocal_task_count
    }

    pub(crate) const fn coefficient_equality_parent_expansion_count(self) -> u64 {
        self.coefficient_equality_parent_expansion_count
    }

    pub(crate) const fn block_equality_parent_expansion_count(self) -> u64 {
        self.block_equality_parent_expansion_count
    }

    pub(crate) const fn sparse_witness_update_count_excluding_lookup_reciprocals(self) -> u64 {
        self.sparse_witness_update_count_excluding_lookup_reciprocals
    }

    pub(crate) const fn coefficient_equality_poll_count(self) -> u64 {
        self.coefficient_equality_poll_count
    }

    pub(crate) const fn block_equality_poll_count(self) -> u64 {
        self.block_equality_poll_count
    }

    pub(crate) const fn sparse_witness_poll_count(self) -> u64 {
        self.sparse_witness_poll_count
    }

    pub(crate) const fn lookup_table_prefix_poll_count(self) -> u64 {
        self.lookup_table_prefix_poll_count
    }

    pub(crate) const fn lookup_table_inversion_poll_count(self) -> u64 {
        self.lookup_table_inversion_poll_count
    }

    pub(crate) const fn lookup_table_reverse_poll_count(self) -> u64 {
        self.lookup_table_reverse_poll_count
    }

    pub(crate) const fn coefficient_equality_transform_poll_count(self) -> u64 {
        self.coefficient_equality_transform_poll_count
    }

    pub(crate) const fn public_adjoint_fill_poll_count(self) -> u64 {
        self.public_adjoint_fill_poll_count
    }

    pub(crate) const fn public_polynomial_transform_poll_count(self) -> u64 {
        self.public_polynomial_transform_poll_count
    }

    pub(crate) const fn pointwise_product_poll_count(self) -> u64 {
        self.pointwise_product_poll_count
    }

    pub(crate) const fn product_polynomial_inverse_transform_poll_count(self) -> u64 {
        self.product_polynomial_inverse_transform_poll_count
    }

    pub(crate) const fn negacyclic_product_fold_poll_count(self) -> u64 {
        self.negacyclic_product_fold_poll_count
    }

    pub(crate) const fn deterministic_poll_count(self) -> u64 {
        self.deterministic_poll_count
    }

    pub(crate) const fn maximum_uninterrupted_elementwise_work_unit_count(self) -> u64 {
        self.maximum_uninterrupted_elementwise_work_unit_count
    }

    pub(crate) const fn maximum_uninterrupted_transform_butterfly_count(self) -> u64 {
        self.maximum_uninterrupted_transform_butterfly_count
    }
}

impl CompactStructuredWitnessCovectorHostMemoryGeometry {
    fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        workload: CompactStructuredWitnessCovectorGeometry,
        lifecycle: CompactStructuredWitnessCovectorLifecycleGeometry,
    ) -> Result<Self, CommonProofProverError> {
        let geometry =
            accumulator::StructuredTransposePlan::from_production(relation, matrices, workload)?
                .host_memory_geometry(workload)?;
        geometry.check(workload, lifecycle)?;
        Ok(geometry)
    }

    fn check(
        self,
        workload: CompactStructuredWitnessCovectorGeometry,
        lifecycle: CompactStructuredWitnessCovectorLifecycleGeometry,
    ) -> Result<(), CommonProofProverError> {
        let expected_sparse_task_count = lifecycle
            .block_sparse_task_count()
            .checked_add(lifecycle.range_sparse_task_count())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.pointer_byte_length == 0
            || self.sparse_task_element_byte_length == 0
            || self.public_product_task_element_byte_length == 0
            || self.sparse_task_catalog_byte_length
                != expected_sparse_task_count
                    .checked_mul(self.sparse_task_element_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.public_product_task_catalog_byte_length
                != lifecycle
                    .public_product_task_count()
                    .checked_mul(self.public_product_task_element_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.task_catalog_byte_length
                != self
                    .sparse_task_catalog_byte_length
                    .checked_add(self.public_product_task_catalog_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.accumulator_control_byte_length
                != self
                    .accumulator_inline_byte_length
                    .checked_add(self.task_catalog_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.initialization_point_copy_payload_byte_length
                != u64::from(workload.row_variable_count())
                    .checked_mul(
                        u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.initialization_resident_owned_byte_length
                != [
                    self.accumulator_control_byte_length,
                    workload.destination_field_payload_byte_length(),
                    workload.row_equality_field_payload_byte_length(),
                    self.initialization_point_copy_payload_byte_length,
                ]
                .into_iter()
                .try_fold(0_u64, |count, byte_length| {
                    count
                        .checked_add(byte_length)
                        .ok_or(CommonProofProverError::CountOverflow)
                })?
            || self.maximum_resident_owned_byte_length
                != self
                    .accumulator_control_byte_length
                    .checked_add(workload.maximum_accumulator_field_payload_byte_length())
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.initialization_resident_owned_byte_length
                > self.maximum_resident_owned_byte_length
            || self.claim_continuation_heap_payload_byte_length
                != u64::from(workload.row_variable_count())
                    .checked_mul(2)
                    .and_then(|count| {
                        count.checked_mul(
                            u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                                .ok()?,
                        )
                    })
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.handoff_control_byte_length
                != self
                    .handoff_inline_byte_length
                    .checked_add(self.task_catalog_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?
            || self.handoff_initialization_resident_owned_byte_length
                != [
                    self.handoff_control_byte_length,
                    workload.destination_field_payload_byte_length(),
                    workload.row_equality_field_payload_byte_length(),
                    self.initialization_point_copy_payload_byte_length,
                    self.claim_continuation_heap_payload_byte_length,
                ]
                .into_iter()
                .try_fold(0_u64, |count, byte_length| {
                    count
                        .checked_add(byte_length)
                        .ok_or(CommonProofProverError::CountOverflow)
                })?
            || self.handoff_maximum_resident_owned_byte_length
                != [
                    self.handoff_control_byte_length,
                    workload.maximum_accumulator_field_payload_byte_length(),
                    self.claim_continuation_heap_payload_byte_length,
                ]
                .into_iter()
                .try_fold(0_u64, |count, byte_length| {
                    count
                        .checked_add(byte_length)
                        .ok_or(CommonProofProverError::CountOverflow)
                })?
            || self.handoff_initialization_resident_owned_byte_length
                > self.handoff_maximum_resident_owned_byte_length
            || self.handoff_maximum_resident_owned_byte_length
                < self.maximum_resident_owned_byte_length
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        Ok(())
    }

    pub(crate) const fn pointer_byte_length(self) -> u64 {
        self.pointer_byte_length
    }

    pub(crate) const fn sparse_task_element_byte_length(self) -> u64 {
        self.sparse_task_element_byte_length
    }

    pub(crate) const fn public_product_task_element_byte_length(self) -> u64 {
        self.public_product_task_element_byte_length
    }

    pub(crate) const fn sparse_task_catalog_byte_length(self) -> u64 {
        self.sparse_task_catalog_byte_length
    }

    pub(crate) const fn public_product_task_catalog_byte_length(self) -> u64 {
        self.public_product_task_catalog_byte_length
    }

    pub(crate) const fn task_catalog_byte_length(self) -> u64 {
        self.task_catalog_byte_length
    }

    pub(crate) const fn accumulator_inline_byte_length(self) -> u64 {
        self.accumulator_inline_byte_length
    }

    pub(crate) const fn accumulator_control_byte_length(self) -> u64 {
        self.accumulator_control_byte_length
    }

    pub(crate) const fn initialization_point_copy_payload_byte_length(self) -> u64 {
        self.initialization_point_copy_payload_byte_length
    }

    pub(crate) const fn initialization_resident_owned_byte_length(self) -> u64 {
        self.initialization_resident_owned_byte_length
    }

    pub(crate) const fn maximum_resident_owned_byte_length(self) -> u64 {
        self.maximum_resident_owned_byte_length
    }

    pub(crate) const fn claim_continuation_heap_payload_byte_length(self) -> u64 {
        self.claim_continuation_heap_payload_byte_length
    }

    pub(crate) const fn handoff_inline_byte_length(self) -> u64 {
        self.handoff_inline_byte_length
    }

    pub(crate) const fn handoff_control_byte_length(self) -> u64 {
        self.handoff_control_byte_length
    }

    pub(crate) const fn handoff_initialization_resident_owned_byte_length(self) -> u64 {
        self.handoff_initialization_resident_owned_byte_length
    }

    pub(crate) const fn handoff_maximum_resident_owned_byte_length(self) -> u64 {
        self.handoff_maximum_resident_owned_byte_length
    }
}

#[allow(clippy::too_many_arguments)]
fn count_form_contributions(
    form: &CompactStructuredLinearForm,
    matrices: &CompactStructuredR1csCatalog,
    repeated_row_count: u64,
    global_lookup_row: bool,
    sparse_witness_update_count: &mut u64,
    public_product_transpose_count: &mut u64,
    distinct_public_product_first_columns: &mut Vec<u64>,
    lookup_table_reciprocal_count: &mut u64,
) -> Result<(), CommonProofProverError> {
    for term in &form.ordered_terms {
        match *term {
            CompactStructuredMatrixTerm::StaticEntry { column_ordinal, .. } => {
                if column_ordinal >= matrices.public_input_length {
                    *sparse_witness_update_count = sparse_witness_update_count
                        .checked_add(repeated_row_count)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                }
            }
            CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal } => {
                if column_ordinal >= matrices.public_input_length {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
            }
            CompactStructuredMatrixTerm::UniformStaticRange {
                first_column_ordinal,
                element_count,
                ..
            } => {
                if !global_lookup_row
                    || first_column_ordinal < matrices.public_input_length
                    || first_column_ordinal
                        .checked_add(element_count)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        > matrices.matrix_dimension
                {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
                *sparse_witness_update_count = sparse_witness_update_count
                    .checked_add(element_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
            }
            CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                first_column_ordinal,
                table_value_count,
            } => {
                if !global_lookup_row
                    || first_column_ordinal < matrices.public_input_length
                    || first_column_ordinal
                        .checked_add(table_value_count)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        > matrices.matrix_dimension
                    || *lookup_table_reciprocal_count != 0
                {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
                *lookup_table_reciprocal_count = table_value_count;
                *sparse_witness_update_count = sparse_witness_update_count
                    .checked_add(table_value_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
            }
            CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                public_vector_first_column_ordinal,
                private_vector_first_column_ordinal,
                output_coefficient_ordinal,
                ..
            } => {
                if global_lookup_row
                    || repeated_row_count == 0
                    || output_coefficient_ordinal != 0
                    || public_vector_first_column_ordinal >= matrices.public_input_length
                    || private_vector_first_column_ordinal < matrices.public_input_length
                {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
                *public_product_transpose_count = public_product_transpose_count
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                distinct_public_product_first_columns.push(public_vector_first_column_ordinal);
            }
        }
    }
    Ok(())
}

pub(crate) fn compact_structured_witness_covector_geometry(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactStructuredWitnessCovectorGeometry, CommonProofProverError> {
    let matrices = CompactStructuredR1csCatalog::derive(relation)?;
    CompactStructuredWitnessCovectorGeometry::derive(relation, &matrices)
}

pub(crate) fn compact_structured_witness_covector_lifecycle_geometry(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactStructuredWitnessCovectorLifecycleGeometry, CommonProofProverError> {
    let matrices = CompactStructuredR1csCatalog::derive(relation)?;
    let workload = CompactStructuredWitnessCovectorGeometry::derive(relation, &matrices)?;
    CompactStructuredWitnessCovectorLifecycleGeometry::derive(relation, &matrices, workload)
}

pub(crate) fn compact_structured_witness_covector_host_memory_geometry(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactStructuredWitnessCovectorHostMemoryGeometry, CommonProofProverError> {
    let matrices = CompactStructuredR1csCatalog::derive(relation)?;
    let workload = CompactStructuredWitnessCovectorGeometry::derive(relation, &matrices)?;
    let lifecycle =
        CompactStructuredWitnessCovectorLifecycleGeometry::derive(relation, &matrices, workload)?;
    CompactStructuredWitnessCovectorHostMemoryGeometry::derive(
        relation, &matrices, workload, lifecycle,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::relation_plan::compact_ring_vector::selected_compact_public_key_relation_catalog;

    #[test]
    fn selected_structured_transpose_geometry_is_exact_without_executing_it() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let geometry = compact_structured_witness_covector_geometry(&relation)
            .expect("selected structured transpose geometry");
        let lifecycle = compact_structured_witness_covector_lifecycle_geometry(&relation)
            .expect("selected structured transpose lifecycle");
        let host_memory = compact_structured_witness_covector_host_memory_geometry(&relation)
            .expect("selected structured transpose host memory");

        assert_eq!(geometry.ring_degree(), 32_768);
        assert_eq!(geometry.padded_row_count(), 8_388_608);
        assert_eq!(geometry.row_variable_count(), 23);
        assert_eq!(geometry.ring_variable_count(), 15);
        assert_eq!(geometry.ring_block_count(), 256);
        assert_eq!(geometry.ring_block_variable_count(), 8);
        assert_eq!(geometry.operative_ring_block_count(), 82);
        assert_eq!(geometry.global_lookup_row_ordinal(), 2_686_976);
        assert_eq!(geometry.source_covector_element_count(), 4_194_304);
        assert_eq!(geometry.sparse_witness_update_count(), 6_979_584);
        assert_eq!(geometry.public_product_transpose_count(), 32);
        assert_eq!(geometry.distinct_public_product_vector_count(), 32);
        assert_eq!(geometry.product_fold_accumulation_count(), 1_048_576);
        assert_eq!(geometry.lookup_table_reciprocal_count(), 131_072);
        assert_eq!(geometry.transform_domain_size(), 65_536);
        assert_eq!(geometry.forward_extension_transform_count(), 1);
        assert_eq!(geometry.forward_base_transform_count(), 32);
        assert_eq!(geometry.inverse_extension_transform_count(), 32);
        assert_eq!(geometry.base_coordinate_transform_count(), 197);
        assert_eq!(geometry.transform_butterfly_count(), 103_284_736);
        assert_eq!(
            geometry.pointwise_extension_base_multiplication_count(),
            2_097_152
        );
        assert_eq!(geometry.pointwise_base_multiplication_count(), 10_485_760);
        assert_eq!(geometry.negacyclic_fold_subtraction_count(), 1_048_576);
        assert_eq!(
            geometry.equality_weight_extension_multiplication_count(),
            66_044
        );
        assert_eq!(
            geometry.destination_field_payload_byte_length(),
            167_772_160
        );
        assert_eq!(geometry.row_equality_field_payload_byte_length(), 1_320_960);
        assert_eq!(
            geometry.lookup_phase_transient_field_payload_byte_length(),
            6_563_840
        );
        assert_eq!(
            geometry.product_phase_transient_field_payload_byte_length(),
            5_777_408
        );
        assert_eq!(
            geometry.maximum_transient_field_payload_byte_length(),
            6_563_840
        );
        assert_eq!(
            geometry.maximum_accumulator_field_payload_byte_length(),
            174_336_000
        );
        assert_eq!(lifecycle.element_chunk_count(), 8_192);
        assert_eq!(lifecycle.block_sparse_task_count(), 180);
        assert_eq!(lifecycle.range_sparse_task_count(), 1);
        assert_eq!(lifecycle.public_product_task_count(), 32);
        assert_eq!(lifecycle.lookup_reciprocal_task_count(), 1);
        assert_eq!(
            lifecycle.coefficient_equality_parent_expansion_count(),
            32_767
        );
        assert_eq!(lifecycle.block_equality_parent_expansion_count(), 255);
        assert_eq!(
            lifecycle.sparse_witness_update_count_excluding_lookup_reciprocals(),
            6_848_512
        );
        assert_eq!(lifecycle.coefficient_equality_poll_count(), 16);
        assert_eq!(lifecycle.block_equality_poll_count(), 8);
        assert_eq!(lifecycle.sparse_witness_poll_count(), 836);
        assert_eq!(lifecycle.lookup_table_prefix_poll_count(), 16);
        assert_eq!(lifecycle.lookup_table_inversion_poll_count(), 1);
        assert_eq!(lifecycle.lookup_table_reverse_poll_count(), 16);
        assert_eq!(lifecycle.coefficient_equality_transform_poll_count(), 1);
        assert_eq!(lifecycle.public_adjoint_fill_poll_count(), 128);
        assert_eq!(lifecycle.public_polynomial_transform_poll_count(), 32);
        assert_eq!(lifecycle.pointwise_product_poll_count(), 256);
        assert_eq!(
            lifecycle.product_polynomial_inverse_transform_poll_count(),
            32
        );
        assert_eq!(lifecycle.negacyclic_product_fold_poll_count(), 128);
        assert_eq!(lifecycle.deterministic_poll_count(), 1_470);
        assert_eq!(
            lifecycle.maximum_uninterrupted_elementwise_work_unit_count(),
            8_192
        );
        assert_eq!(
            lifecycle.maximum_uninterrupted_transform_butterfly_count(),
            524_288
        );
        assert_eq!(
            (
                host_memory.pointer_byte_length(),
                host_memory.sparse_task_element_byte_length(),
                host_memory.public_product_task_element_byte_length(),
                host_memory.sparse_task_catalog_byte_length(),
                host_memory.public_product_task_catalog_byte_length(),
                host_memory.task_catalog_byte_length(),
                host_memory.accumulator_inline_byte_length(),
                host_memory.accumulator_control_byte_length(),
                host_memory.initialization_point_copy_payload_byte_length(),
                host_memory.initialization_resident_owned_byte_length(),
                host_memory.maximum_resident_owned_byte_length(),
            ),
            (
                8,
                64,
                48,
                11_584,
                1_536,
                13_120,
                592,
                13_712,
                920,
                169_107_752,
                174_349_712,
            )
        );
        assert_eq!(
            (
                host_memory.claim_continuation_heap_payload_byte_length(),
                host_memory.handoff_inline_byte_length(),
                host_memory.handoff_control_byte_length(),
                host_memory.handoff_initialization_resident_owned_byte_length(),
                host_memory.handoff_maximum_resident_owned_byte_length(),
            ),
            (1_840, 1_040, 14_160, 169_110_040, 174_352_000,)
        );
    }
}
