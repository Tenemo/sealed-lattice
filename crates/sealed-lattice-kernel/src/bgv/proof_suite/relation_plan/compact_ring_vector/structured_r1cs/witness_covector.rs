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

#[cfg(test)]
pub(crate) use accumulator::{
    CompactStructuredWitnessCovectorAccumulator, CompactStructuredWitnessCovectorAccumulatorPoll,
    CompactStructuredWitnessCovectorHandoff, CompactStructuredWitnessCovectorHandoffPoll,
    StructuredTransposeValueSource,
};

use crate::bgv::proof_suite::prover::CommonProofProverError;

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
            || !padded_row_count.is_multiple_of(ring_degree)
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
    }
}
