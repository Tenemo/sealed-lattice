//! Pollable structured-matrix transpose accumulation.
//!
//! The accumulator keeps one destination covector, splits the CFW row equality
//! point at the ring boundary, applies sparse witness entries blockwise, builds
//! the global lookup reciprocals with one batch inversion, and transposes every
//! verifier-owned public negacyclic band with scalar browser-compatible
//! transforms. Each call performs one bounded elementwise chunk or one isolated
//! transform.

use zeroize::Zeroizing;

use crate::bgv::proof_suite::{
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain,
    compact_cfw::{
        COMPACT_CFW_MATRIX_COUNT, CompactCfwClaimCombinationContinuation,
        CompactCfwCombinedRelation, CompactCfwError, CompactCfwMatrixClaimCombination,
        CompactCfwMatrixRole, CompactChallengeField, compact_challenge_from_production,
        compact_challenge_to_production,
    },
    prover::CommonProofProverError,
};

use super::super::{
    CompactPublicKeyAssignment, CompactStructuredAssignmentSource, CompactStructuredLinearForm,
    CompactStructuredMatrixTerm, CompactStructuredR1csCatalog, CompactStructuredR1csRowSource,
    base_element_from_signed_integer,
};
use super::{
    COMPACT_STRUCTURED_WITNESS_COVECTOR_ELEMENT_CHUNK_COUNT,
    CompactStructuredWitnessCovectorGeometry, CompactStructuredWitnessCovectorHostMemoryGeometry,
    CompactStructuredWitnessCovectorLifecycleGeometry,
};
use crate::bgv::proof_suite::relation_plan::compact_ring_vector::{
    CompactPublicKeyRelationCatalog, CompactR1csConstraintKind, RelationPlanError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockStaticTask {
    row_block_ordinal: u64,
    first_destination_element: u64,
    integer_coefficient: i128,
    matrix_role: CompactCfwMatrixRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RangeStaticTask {
    row_block_ordinal: u64,
    row_coefficient_ordinal: u64,
    first_destination_element: u64,
    element_count: u64,
    integer_coefficient: i128,
    matrix_role: CompactCfwMatrixRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SparseTask {
    Block(BlockStaticTask),
    Range(RangeStaticTask),
}

impl SparseTask {
    const fn element_count(self, ring_degree: u64) -> u64 {
        match self {
            Self::Block(_) => ring_degree,
            Self::Range(task) => task.element_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PublicProductTask {
    row_block_ordinal: u64,
    public_vector_first_element: u64,
    private_vector_first_destination_element: u64,
    integer_coefficient: i128,
    matrix_role: CompactCfwMatrixRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LookupReciprocalTask {
    row_block_ordinal: u64,
    row_coefficient_ordinal: u64,
    first_destination_element: u64,
    table_value_count: u64,
    matrix_role: CompactCfwMatrixRole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StructuredTransposePlan {
    ring_degree: u64,
    ring_variable_count: u32,
    ring_block_count: u64,
    ring_block_variable_count: u32,
    source_covector_element_count: u64,
    transform_domain_size: u64,
    sparse_tasks: Box<[SparseTask]>,
    public_product_tasks: Box<[PublicProductTask]>,
    lookup_reciprocal_task: LookupReciprocalTask,
}

impl StructuredTransposePlan {
    pub(super) fn from_production(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        geometry: CompactStructuredWitnessCovectorGeometry,
    ) -> Result<Self, CommonProofProverError> {
        let mut sparse_tasks = Vec::new();
        let mut public_product_tasks = Vec::new();
        let mut lookup_reciprocal_task = None;
        for segment in &relation.ordered_constraint_segments {
            match segment.kind {
                CompactR1csConstraintKind::ZeroPadding => {}
                CompactR1csConstraintKind::LookupLogDerivativeEquality => {
                    if segment.row_count != 1 {
                        return Err(RelationPlanError::InvalidConstraint.into());
                    }
                    let row = matrices.row(relation, segment.first_row)?;
                    let row_block_ordinal = segment.first_row / relation.ring_degree;
                    let row_coefficient_ordinal = segment.first_row % relation.ring_degree;
                    for (matrix_role, form) in matrix_forms(&row) {
                        append_form_tasks(
                            form,
                            matrix_role,
                            row_block_ordinal,
                            row_coefficient_ordinal,
                            true,
                            matrices,
                            &mut sparse_tasks,
                            &mut public_product_tasks,
                            &mut lookup_reciprocal_task,
                        )?;
                    }
                }
                _ => {
                    if segment.first_row % relation.ring_degree != 0
                        || segment.row_count % relation.ring_degree != 0
                    {
                        return Err(RelationPlanError::InvalidConstraint.into());
                    }
                    let block_count = segment.row_count / relation.ring_degree;
                    for block_offset in 0..block_count {
                        let representative_row_ordinal = segment
                            .first_row
                            .checked_add(
                                block_offset
                                    .checked_mul(relation.ring_degree)
                                    .ok_or(CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::CountOverflow)?;
                        let row = matrices.row(relation, representative_row_ordinal)?;
                        let row_block_ordinal = representative_row_ordinal / relation.ring_degree;
                        for (matrix_role, form) in matrix_forms(&row) {
                            append_form_tasks(
                                form,
                                matrix_role,
                                row_block_ordinal,
                                0,
                                false,
                                matrices,
                                &mut sparse_tasks,
                                &mut public_product_tasks,
                                &mut lookup_reciprocal_task,
                            )?;
                        }
                    }
                }
            }
        }
        let lookup_reciprocal_task =
            lookup_reciprocal_task.ok_or(RelationPlanError::InvalidConstraint)?;
        let sparse_witness_update_count = sparse_tasks.iter().try_fold(
            lookup_reciprocal_task.table_value_count,
            |count, task| {
                count
                    .checked_add(task.element_count(relation.ring_degree))
                    .ok_or(CommonProofProverError::CountOverflow)
            },
        )?;
        let public_product_task_count = u64::try_from(public_product_tasks.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut distinct_public_vector_first_elements = public_product_tasks
            .iter()
            .map(|task| task.public_vector_first_element)
            .collect::<Vec<_>>();
        distinct_public_vector_first_elements.sort_unstable();
        distinct_public_vector_first_elements.dedup();
        if sparse_witness_update_count != geometry.sparse_witness_update_count()
            || public_product_task_count != geometry.public_product_transpose_count()
            || u64::try_from(distinct_public_vector_first_elements.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                != geometry.distinct_public_product_vector_count()
            || public_product_task_count != geometry.distinct_public_product_vector_count()
            || lookup_reciprocal_task.table_value_count != geometry.lookup_table_reciprocal_count()
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        let plan = Self {
            ring_degree: geometry.ring_degree(),
            ring_variable_count: geometry.ring_variable_count(),
            ring_block_count: geometry.ring_block_count(),
            ring_block_variable_count: geometry.ring_block_variable_count(),
            source_covector_element_count: geometry.source_covector_element_count(),
            transform_domain_size: geometry.transform_domain_size(),
            sparse_tasks: sparse_tasks.into_boxed_slice(),
            public_product_tasks: public_product_tasks.into_boxed_slice(),
            lookup_reciprocal_task,
        };
        plan.check()?;
        Ok(plan)
    }

    fn check(&self) -> Result<(), CommonProofProverError> {
        if self.ring_degree < 2
            || !self.ring_degree.is_power_of_two()
            || !self.ring_block_count.is_power_of_two()
            || self.ring_variable_count != self.ring_degree.ilog2()
            || self.ring_block_variable_count != self.ring_block_count.ilog2()
            || self.ring_degree.checked_mul(2) != Some(self.transform_domain_size)
            || self.source_covector_element_count == 0
            || self.sparse_tasks.is_empty()
            || self.public_product_tasks.is_empty()
            || self.lookup_reciprocal_task.table_value_count == 0
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        for task in &self.sparse_tasks {
            let (first_destination_element, element_count, row_block_ordinal) = match *task {
                SparseTask::Block(task) => (
                    task.first_destination_element,
                    self.ring_degree,
                    task.row_block_ordinal,
                ),
                SparseTask::Range(task) => (
                    task.first_destination_element,
                    task.element_count,
                    task.row_block_ordinal,
                ),
            };
            if row_block_ordinal >= self.ring_block_count
                || first_destination_element
                    .checked_add(element_count)
                    .is_none_or(|end| end > self.source_covector_element_count)
            {
                return Err(CommonProofProverError::InvalidInput);
            }
        }
        for task in &self.public_product_tasks {
            if task.row_block_ordinal >= self.ring_block_count
                || task
                    .private_vector_first_destination_element
                    .checked_add(self.ring_degree)
                    .is_none_or(|end| end > self.source_covector_element_count)
            {
                return Err(CommonProofProverError::InvalidInput);
            }
        }
        if self.lookup_reciprocal_task.row_block_ordinal >= self.ring_block_count
            || self.lookup_reciprocal_task.row_coefficient_ordinal >= self.ring_degree
            || self
                .lookup_reciprocal_task
                .first_destination_element
                .checked_add(self.lookup_reciprocal_task.table_value_count)
                .is_none_or(|end| end > self.source_covector_element_count)
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(())
    }

    pub(super) fn lifecycle_geometry(
        &self,
        workload: CompactStructuredWitnessCovectorGeometry,
    ) -> Result<CompactStructuredWitnessCovectorLifecycleGeometry, CommonProofProverError> {
        self.check()?;
        let element_chunk_count = COMPACT_STRUCTURED_WITNESS_COVECTOR_ELEMENT_CHUNK_COUNT;
        let block_sparse_task_count = u64::try_from(
            self.sparse_tasks
                .iter()
                .filter(|task| matches!(task, SparseTask::Block(_)))
                .count(),
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let range_sparse_task_count = u64::try_from(
            self.sparse_tasks
                .iter()
                .filter(|task| matches!(task, SparseTask::Range(_)))
                .count(),
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let public_product_task_count = u64::try_from(self.public_product_tasks.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let lookup_reciprocal_task_count = 1_u64;
        let coefficient_equality_parent_expansion_count = self
            .ring_degree
            .checked_sub(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let block_equality_parent_expansion_count = self
            .ring_block_count
            .checked_sub(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let sparse_witness_update_count_excluding_lookup_reciprocals =
            self.sparse_tasks.iter().try_fold(0_u64, |count, task| {
                count
                    .checked_add(task.element_count(self.ring_degree))
                    .ok_or(CommonProofProverError::CountOverflow)
            })?;
        let coefficient_equality_poll_count =
            equality_builder_poll_count(self.ring_degree, element_chunk_count)?;
        let block_equality_poll_count =
            equality_builder_poll_count(self.ring_block_count, element_chunk_count)?;
        let sparse_witness_poll_count =
            self.sparse_tasks.iter().try_fold(0_u64, |count, task| {
                count
                    .checked_add(
                        task.element_count(self.ring_degree)
                            .div_ceil(element_chunk_count),
                    )
                    .ok_or(CommonProofProverError::CountOverflow)
            })?;
        let lookup_table_prefix_poll_count = self
            .lookup_reciprocal_task
            .table_value_count
            .div_ceil(element_chunk_count);
        let lookup_table_inversion_poll_count = 1_u64;
        let lookup_table_reverse_poll_count = lookup_table_prefix_poll_count;
        let coefficient_equality_transform_poll_count = 1_u64;
        let public_adjoint_fill_poll_count = checked_product(&[
            public_product_task_count,
            self.ring_degree.div_ceil(element_chunk_count),
        ])?;
        let public_polynomial_transform_poll_count = public_product_task_count;
        let pointwise_product_poll_count = checked_product(&[
            public_product_task_count,
            self.transform_domain_size.div_ceil(element_chunk_count),
        ])?;
        let product_polynomial_inverse_transform_poll_count = public_product_task_count;
        let negacyclic_product_fold_poll_count = public_adjoint_fill_poll_count;
        let deterministic_poll_count = checked_sum(&[
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
        ])?;
        let maximum_uninterrupted_transform_butterfly_count =
            transform_butterfly_count(self.transform_domain_size)?;
        if checked_sum(&[
            sparse_witness_update_count_excluding_lookup_reciprocals,
            self.lookup_reciprocal_task.table_value_count,
        ])? != workload.sparse_witness_update_count()
            || public_product_task_count != workload.public_product_transpose_count()
            || maximum_uninterrupted_transform_butterfly_count
                > workload.transform_butterfly_count()
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }

        Ok(CompactStructuredWitnessCovectorLifecycleGeometry {
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
            maximum_uninterrupted_elementwise_work_unit_count: element_chunk_count,
            maximum_uninterrupted_transform_butterfly_count,
        })
    }

    pub(super) fn host_memory_geometry(
        &self,
        workload: CompactStructuredWitnessCovectorGeometry,
    ) -> Result<CompactStructuredWitnessCovectorHostMemoryGeometry, CommonProofProverError> {
        self.check()?;
        let pointer_byte_length = u64::try_from(core::mem::size_of::<usize>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let sparse_task_element_byte_length = u64::try_from(core::mem::size_of::<SparseTask>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let public_product_task_element_byte_length =
            u64::try_from(core::mem::size_of::<PublicProductTask>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let sparse_task_catalog_byte_length = checked_product(&[
            u64::try_from(self.sparse_tasks.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            sparse_task_element_byte_length,
        ])?;
        let public_product_task_catalog_byte_length = checked_product(&[
            u64::try_from(self.public_product_tasks.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            public_product_task_element_byte_length,
        ])?;
        let task_catalog_byte_length = checked_sum(&[
            sparse_task_catalog_byte_length,
            public_product_task_catalog_byte_length,
        ])?;
        let accumulator_inline_byte_length = u64::try_from(core::mem::size_of::<
            CompactStructuredWitnessCovectorAccumulator<
                'static,
                CompactStructuredR1csRowSource<'static, CompactPublicKeyAssignment>,
            >,
        >())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let accumulator_control_byte_length =
            checked_sum(&[accumulator_inline_byte_length, task_catalog_byte_length])?;
        let extension_element_byte_length =
            u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let initialization_point_copy_payload_byte_length = checked_product(&[
            u64::from(
                self.ring_variable_count
                    .checked_add(self.ring_block_variable_count)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            ),
            extension_element_byte_length,
        ])?;
        let initialization_resident_owned_byte_length = checked_sum(&[
            accumulator_control_byte_length,
            workload.destination_field_payload_byte_length(),
            workload.row_equality_field_payload_byte_length(),
            initialization_point_copy_payload_byte_length,
        ])?;
        let maximum_resident_owned_byte_length = checked_sum(&[
            accumulator_control_byte_length,
            workload.maximum_accumulator_field_payload_byte_length(),
        ])?;
        let claim_continuation_heap_payload_byte_length = checked_product(&[
            2,
            u64::from(workload.row_variable_count()),
            extension_element_byte_length,
        ])?;
        let handoff_inline_byte_length = u64::try_from(core::mem::size_of::<
            CompactStructuredWitnessCovectorHandoff<
                'static,
                CompactStructuredR1csRowSource<'static, CompactPublicKeyAssignment>,
            >,
        >())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let handoff_control_byte_length =
            checked_sum(&[handoff_inline_byte_length, task_catalog_byte_length])?;
        let handoff_initialization_resident_owned_byte_length = checked_sum(&[
            handoff_control_byte_length,
            workload.destination_field_payload_byte_length(),
            workload.row_equality_field_payload_byte_length(),
            initialization_point_copy_payload_byte_length,
            claim_continuation_heap_payload_byte_length,
        ])?;
        let handoff_maximum_resident_owned_byte_length = checked_sum(&[
            handoff_control_byte_length,
            workload.maximum_accumulator_field_payload_byte_length(),
            claim_continuation_heap_payload_byte_length,
        ])?;

        Ok(CompactStructuredWitnessCovectorHostMemoryGeometry {
            pointer_byte_length,
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
        })
    }
}

fn equality_builder_poll_count(
    final_weight_count: u64,
    element_chunk_count: u64,
) -> Result<u64, CommonProofProverError> {
    if final_weight_count < 2 || !final_weight_count.is_power_of_two() || element_chunk_count == 0 {
        return Err(CommonProofProverError::InvalidInput);
    }
    let mut parent_count = 1_u64;
    let mut poll_count = 0_u64;
    while parent_count < final_weight_count {
        poll_count = poll_count
            .checked_add(parent_count.div_ceil(element_chunk_count))
            .ok_or(CommonProofProverError::CountOverflow)?;
        parent_count = parent_count
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    Ok(poll_count)
}

fn checked_product(factors: &[u64]) -> Result<u64, CommonProofProverError> {
    factors.iter().try_fold(1_u64, |product, factor| {
        product
            .checked_mul(*factor)
            .ok_or(CommonProofProverError::CountOverflow)
    })
}

fn checked_sum(terms: &[u64]) -> Result<u64, CommonProofProverError> {
    terms.iter().try_fold(0_u64, |sum, term| {
        sum.checked_add(*term)
            .ok_or(CommonProofProverError::CountOverflow)
    })
}

fn matrix_forms(
    row: &super::super::CompactStructuredR1csRow,
) -> [(CompactCfwMatrixRole, &CompactStructuredLinearForm); COMPACT_CFW_MATRIX_COUNT] {
    [
        (CompactCfwMatrixRole::LeftMultiplicand, &row.left),
        (CompactCfwMatrixRole::RightMultiplicand, &row.right),
        (CompactCfwMatrixRole::Product, &row.output),
    ]
}

#[allow(clippy::too_many_arguments)]
fn append_form_tasks(
    form: &CompactStructuredLinearForm,
    matrix_role: CompactCfwMatrixRole,
    row_block_ordinal: u64,
    row_coefficient_ordinal: u64,
    global_lookup_row: bool,
    matrices: &CompactStructuredR1csCatalog,
    sparse_tasks: &mut Vec<SparseTask>,
    public_product_tasks: &mut Vec<PublicProductTask>,
    lookup_reciprocal_task: &mut Option<LookupReciprocalTask>,
) -> Result<(), CommonProofProverError> {
    for term in &form.ordered_terms {
        match *term {
            CompactStructuredMatrixTerm::StaticEntry {
                column_ordinal,
                integer_coefficient,
            } => {
                if column_ordinal < matrices.public_input_length {
                    continue;
                }
                if global_lookup_row || row_coefficient_ordinal != 0 {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
                sparse_tasks.push(SparseTask::Block(BlockStaticTask {
                    row_block_ordinal,
                    first_destination_element: column_ordinal - matrices.public_input_length,
                    integer_coefficient,
                    matrix_role,
                }));
            }
            CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal } => {
                if column_ordinal >= matrices.public_input_length {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
            }
            CompactStructuredMatrixTerm::UniformStaticRange {
                first_column_ordinal,
                element_count,
                integer_coefficient,
            } => {
                if !global_lookup_row || first_column_ordinal < matrices.public_input_length {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
                sparse_tasks.push(SparseTask::Range(RangeStaticTask {
                    row_block_ordinal,
                    row_coefficient_ordinal,
                    first_destination_element: first_column_ordinal - matrices.public_input_length,
                    element_count,
                    integer_coefficient,
                    matrix_role,
                }));
            }
            CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                first_column_ordinal,
                table_value_count,
            } => {
                if !global_lookup_row
                    || first_column_ordinal < matrices.public_input_length
                    || lookup_reciprocal_task.is_some()
                {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
                *lookup_reciprocal_task = Some(LookupReciprocalTask {
                    row_block_ordinal,
                    row_coefficient_ordinal,
                    first_destination_element: first_column_ordinal - matrices.public_input_length,
                    table_value_count,
                    matrix_role,
                });
            }
            CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                public_vector_first_column_ordinal,
                private_vector_first_column_ordinal,
                output_coefficient_ordinal,
                integer_coefficient,
                ..
            } => {
                if global_lookup_row
                    || row_coefficient_ordinal != 0
                    || output_coefficient_ordinal != 0
                    || public_vector_first_column_ordinal >= matrices.public_input_length
                    || private_vector_first_column_ordinal < matrices.public_input_length
                {
                    return Err(RelationPlanError::InvalidConstraint.into());
                }
                public_product_tasks.push(PublicProductTask {
                    row_block_ordinal,
                    public_vector_first_element: public_vector_first_column_ordinal,
                    private_vector_first_destination_element: private_vector_first_column_ordinal
                        - matrices.public_input_length,
                    integer_coefficient,
                    matrix_role,
                });
            }
        }
    }
    Ok(())
}

pub(crate) trait StructuredTransposeValueSource {
    fn lookup_challenge(&self) -> ProofChallengeExtensionElement;

    fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError>;
}

impl<Assignment: CompactStructuredAssignmentSource + ?Sized> StructuredTransposeValueSource
    for CompactStructuredR1csRowSource<'_, Assignment>
{
    fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
        self.assignment.lookup_challenge()
    }

    fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        self.assignment.public_input_base_value(element_ordinal)
    }
}

struct LittleEndianEqualityBuilder {
    point: Vec<ProofChallengeExtensionElement>,
    weights: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    completed_coordinate_count: usize,
    remaining_parent_count: usize,
}

impl LittleEndianEqualityBuilder {
    fn new(point: Vec<ProofChallengeExtensionElement>) -> Result<Self, CommonProofProverError> {
        let final_length = 1_usize
            .checked_shl(
                u32::try_from(point.len()).map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let mut weights = Vec::new();
        weights
            .try_reserve_exact(final_length)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        if weights.capacity() != final_length {
            return Err(CommonProofProverError::AllocationLimitExceeded);
        }
        weights.push(ProofChallengeExtensionElement::ONE);
        Ok(Self {
            point,
            weights: Zeroizing::new(weights),
            completed_coordinate_count: 0,
            remaining_parent_count: 0,
        })
    }

    fn is_complete(&self) -> bool {
        self.completed_coordinate_count == self.point.len() && self.remaining_parent_count == 0
    }

    fn advance(&mut self, maximum_parent_count: usize) -> Result<usize, CommonProofProverError> {
        if maximum_parent_count == 0 || self.is_complete() {
            return Err(CommonProofProverError::InvalidInput);
        }
        if self.remaining_parent_count == 0 {
            let parent_count = self.weights.len();
            let next_length = parent_count
                .checked_mul(2)
                .ok_or(CommonProofProverError::CountOverflow)?;
            self.weights
                .resize(next_length, ProofChallengeExtensionElement::ZERO);
            self.remaining_parent_count = parent_count;
        }
        let completed_parent_count = self.remaining_parent_count.min(maximum_parent_count);
        let first_parent = self
            .remaining_parent_count
            .checked_sub(completed_parent_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let point_coordinate_ordinal = self
            .point
            .len()
            .checked_sub(self.completed_coordinate_count + 1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let point_coordinate = self.point[point_coordinate_ordinal];
        for parent_ordinal in (first_parent..self.remaining_parent_count).rev() {
            let parent_weight = self.weights[parent_ordinal];
            self.weights[2 * parent_ordinal] = parent_weight
                .multiply(ProofChallengeExtensionElement::ONE.subtract(point_coordinate));
            self.weights[2 * parent_ordinal + 1] = parent_weight.multiply(point_coordinate);
        }
        self.remaining_parent_count = first_parent;
        if self.remaining_parent_count == 0 {
            self.completed_coordinate_count = self
                .completed_coordinate_count
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
        Ok(completed_parent_count)
    }

    fn finish(
        self,
    ) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
        if !self.is_complete() {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(self.weights)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompactStructuredWitnessCovectorAccumulatorStep {
    CoefficientEquality,
    BlockEquality,
    SparseWitness,
    LookupTablePrefixProduct,
    LookupTableProductInversion,
    LookupTableReversePass,
    CoefficientEqualityForwardTransform,
    PublicAdjointFill,
    PublicPolynomialForwardTransform,
    PointwiseProduct,
    ProductPolynomialInverseTransform,
    NegacyclicProductFold,
}

pub(crate) enum CompactStructuredWitnessCovectorAccumulatorPoll {
    StepCompleted {
        step: CompactStructuredWitnessCovectorAccumulatorStep,
        completed_work_unit_count: u64,
    },
    Complete(Vec<CompactChallengeField>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactStructuredWitnessCovectorHandoffError {
    ClaimCombination(CompactCfwError),
    Accumulator(CommonProofProverError),
}

impl From<CompactCfwError> for CompactStructuredWitnessCovectorHandoffError {
    fn from(error: CompactCfwError) -> Self {
        Self::ClaimCombination(error)
    }
}

impl From<CommonProofProverError> for CompactStructuredWitnessCovectorHandoffError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Accumulator(error)
    }
}

pub(crate) enum CompactStructuredWitnessCovectorHandoffPoll {
    StepCompleted {
        step: CompactStructuredWitnessCovectorAccumulatorStep,
        completed_work_unit_count: u64,
    },
    Complete(CompactCfwCombinedRelation),
}

impl CompactStructuredWitnessCovectorHandoffPoll {
    pub(crate) const fn completed_step(
        &self,
    ) -> Option<(CompactStructuredWitnessCovectorAccumulatorStep, u64)> {
        match self {
            Self::StepCompleted {
                step,
                completed_work_unit_count,
            } => Some((*step, *completed_work_unit_count)),
            Self::Complete(_) => None,
        }
    }

    pub(crate) fn into_complete(self) -> Option<CompactCfwCombinedRelation> {
        match self {
            Self::StepCompleted { .. } => None,
            Self::Complete(relation) => Some(relation),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccumulatorPhase {
    BuildCoefficientEquality,
    BuildBlockEquality,
    SparseWitness {
        task_ordinal: usize,
        next_element_offset: u64,
    },
    LookupTablePrefixProduct {
        next_table_value: u64,
        running_product: ProofChallengeExtensionElement,
    },
    LookupTableProductInversion {
        total_product: ProofChallengeExtensionElement,
    },
    LookupTableReversePass {
        remaining_table_value_count: u64,
        accumulated_inverse: ProofChallengeExtensionElement,
    },
    CoefficientEqualityForwardTransform,
    PublicAdjointFill {
        task_ordinal: usize,
        next_coefficient_ordinal: u64,
    },
    PublicPolynomialForwardTransform {
        task_ordinal: usize,
    },
    PointwiseProduct {
        task_ordinal: usize,
        next_evaluation_ordinal: u64,
    },
    ProductPolynomialInverseTransform {
        task_ordinal: usize,
    },
    NegacyclicProductFold {
        task_ordinal: usize,
        next_coefficient_ordinal: u64,
    },
    Complete,
}

pub(crate) struct CompactStructuredWitnessCovectorAccumulator<'source, Source>
where
    Source: StructuredTransposeValueSource + ?Sized,
{
    source: &'source Source,
    plan: StructuredTransposePlan,
    matrix_role_weights: [ProofChallengeExtensionElement; COMPACT_CFW_MATRIX_COUNT],
    destination: Option<Vec<CompactChallengeField>>,
    coefficient_equality_builder: Option<LittleEndianEqualityBuilder>,
    block_equality_builder: Option<LittleEndianEqualityBuilder>,
    coefficient_equality: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    block_equality: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    lookup_prefix_products: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    public_transform: Option<Zeroizing<Vec<ProofBaseFieldElement>>>,
    product_transform: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    transform_domain: ProofEvaluationDomain,
    phase: AccumulatorPhase,
}

pub(crate) struct CompactStructuredWitnessCovectorHandoff<'source, Source>
where
    Source: StructuredTransposeValueSource + ?Sized,
{
    accumulator: CompactStructuredWitnessCovectorAccumulator<'source, Source>,
    continuation: Option<CompactCfwClaimCombinationContinuation>,
}

impl<'source, Source> CompactStructuredWitnessCovectorAccumulator<'source, Source>
where
    Source: StructuredTransposeValueSource + ?Sized,
{
    fn new(
        source: &'source Source,
        plan: StructuredTransposePlan,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: Vec<CompactChallengeField>,
    ) -> Result<Self, CommonProofProverError> {
        plan.check()?;
        let expected_row_point_length = plan
            .ring_variable_count
            .checked_add(plan.ring_block_variable_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let expected_destination_length = usize::try_from(plan.source_covector_element_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if row_point.len()
            != usize::try_from(expected_row_point_length)
                .map_err(|_| CommonProofProverError::CountOverflow)?
            || destination.len() != expected_destination_length
            || destination.capacity() != expected_destination_length
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let ring_variable_count = usize::try_from(plan.ring_variable_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let coefficient_point = fallible_challenge_point_copy(&row_point[..ring_variable_count])?;
        let block_point = fallible_challenge_point_copy(&row_point[ring_variable_count..])?;
        let [
            left_multiplicand_weight,
            right_multiplicand_weight,
            product_weight,
        ] = matrix_role_weights;
        let matrix_role_weights = [
            compact_challenge_to_production(left_multiplicand_weight)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
            compact_challenge_to_production(right_multiplicand_weight)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
            compact_challenge_to_production(product_weight)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
        ];
        let transform_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(plan.transform_domain_size)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
        Ok(Self {
            source,
            plan,
            matrix_role_weights,
            destination: Some(destination),
            coefficient_equality_builder: Some(LittleEndianEqualityBuilder::new(
                coefficient_point,
            )?),
            block_equality_builder: Some(LittleEndianEqualityBuilder::new(block_point)?),
            coefficient_equality: None,
            block_equality: None,
            lookup_prefix_products: None,
            public_transform: None,
            product_transform: None,
            transform_domain,
            phase: AccumulatorPhase::BuildCoefficientEquality,
        })
    }

    pub(crate) fn advance(
        &mut self,
        maximum_element_count: u64,
    ) -> Result<CompactStructuredWitnessCovectorAccumulatorPoll, CommonProofProverError> {
        let maximum_element_count_usize = usize::try_from(maximum_element_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if maximum_element_count == 0 {
            return Err(CommonProofProverError::InvalidInput);
        }
        loop {
            match self.phase {
                AccumulatorPhase::BuildCoefficientEquality => {
                    let builder = self
                        .coefficient_equality_builder
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    if builder.is_complete() {
                        self.coefficient_equality = Some(
                            self.coefficient_equality_builder
                                .take()
                                .ok_or(CommonProofProverError::InvalidInput)?
                                .finish()?,
                        );
                        self.phase = AccumulatorPhase::BuildBlockEquality;
                        continue;
                    }
                    let completed_parent_count = builder.advance(maximum_element_count_usize)?;
                    return step_completed(
                        CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEquality,
                        completed_parent_count,
                    );
                }
                AccumulatorPhase::BuildBlockEquality => {
                    let builder = self
                        .block_equality_builder
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    if builder.is_complete() {
                        self.block_equality = Some(
                            self.block_equality_builder
                                .take()
                                .ok_or(CommonProofProverError::InvalidInput)?
                                .finish()?,
                        );
                        self.phase = AccumulatorPhase::SparseWitness {
                            task_ordinal: 0,
                            next_element_offset: 0,
                        };
                        continue;
                    }
                    let completed_parent_count = builder.advance(maximum_element_count_usize)?;
                    return step_completed(
                        CompactStructuredWitnessCovectorAccumulatorStep::BlockEquality,
                        completed_parent_count,
                    );
                }
                AccumulatorPhase::SparseWitness {
                    task_ordinal,
                    next_element_offset,
                } => {
                    let Some(&task) = self.plan.sparse_tasks.get(task_ordinal) else {
                        let table_value_count = self.plan.lookup_reciprocal_task.table_value_count;
                        self.lookup_prefix_products =
                            Some(fallible_extension_vector(table_value_count)?);
                        self.phase = AccumulatorPhase::LookupTablePrefixProduct {
                            next_table_value: 0,
                            running_product: ProofChallengeExtensionElement::ONE,
                        };
                        continue;
                    };
                    let task_element_count = task.element_count(self.plan.ring_degree);
                    if next_element_offset == task_element_count {
                        self.phase = AccumulatorPhase::SparseWitness {
                            task_ordinal: task_ordinal
                                .checked_add(1)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                            next_element_offset: 0,
                        };
                        continue;
                    }
                    let completed_element_count = task_element_count
                        .checked_sub(next_element_offset)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        .min(maximum_element_count);
                    self.accumulate_sparse_task_chunk(
                        task,
                        next_element_offset,
                        completed_element_count,
                    )?;
                    self.phase = AccumulatorPhase::SparseWitness {
                        task_ordinal,
                        next_element_offset: next_element_offset
                            .checked_add(completed_element_count)
                            .ok_or(CommonProofProverError::CountOverflow)?,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::SparseWitness,
                            completed_work_unit_count: completed_element_count,
                        },
                    );
                }
                AccumulatorPhase::LookupTablePrefixProduct {
                    next_table_value,
                    mut running_product,
                } => {
                    let table_value_count = self.plan.lookup_reciprocal_task.table_value_count;
                    if next_table_value == table_value_count {
                        self.phase = AccumulatorPhase::LookupTableProductInversion {
                            total_product: running_product,
                        };
                        continue;
                    }
                    let completed_table_value_count = table_value_count
                        .checked_sub(next_table_value)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        .min(maximum_element_count);
                    let end_table_value = next_table_value
                        .checked_add(completed_table_value_count)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let lookup_challenge = self.source.lookup_challenge();
                    let prefix_products = self
                        .lookup_prefix_products
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    for table_value in next_table_value..end_table_value {
                        let denominator =
                            lookup_challenge.add(ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)?,
                            ));
                        running_product = running_product.multiply(denominator);
                        prefix_products.push(running_product);
                    }
                    self.phase = AccumulatorPhase::LookupTablePrefixProduct {
                        next_table_value: end_table_value,
                        running_product,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::LookupTablePrefixProduct,
                            completed_work_unit_count: completed_table_value_count,
                        },
                    );
                }
                AccumulatorPhase::LookupTableProductInversion { total_product } => {
                    self.phase = AccumulatorPhase::LookupTableReversePass {
                        remaining_table_value_count: self
                            .plan
                            .lookup_reciprocal_task
                            .table_value_count,
                        accumulated_inverse: total_product.inverse()?,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::LookupTableProductInversion,
                            completed_work_unit_count: 1,
                        },
                    );
                }
                AccumulatorPhase::LookupTableReversePass {
                    remaining_table_value_count,
                    mut accumulated_inverse,
                } => {
                    if remaining_table_value_count == 0 {
                        if accumulated_inverse != ProofChallengeExtensionElement::ONE {
                            return Err(CommonProofProverError::InvalidInput);
                        }
                        self.lookup_prefix_products = None;
                        self.phase = AccumulatorPhase::CoefficientEqualityForwardTransform;
                        continue;
                    }
                    let completed_table_value_count =
                        remaining_table_value_count.min(maximum_element_count);
                    let first_table_value = remaining_table_value_count
                        .checked_sub(completed_table_value_count)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let lookup_challenge = self.source.lookup_challenge();
                    let task = self.plan.lookup_reciprocal_task;
                    let row_scale = self
                        .row_weight(task.row_block_ordinal, task.row_coefficient_ordinal)?
                        .multiply(self.matrix_role_weights[task.matrix_role.ordinal()]);
                    for table_value in (first_table_value..remaining_table_value_count).rev() {
                        let prefix_before = if table_value == 0 {
                            ProofChallengeExtensionElement::ONE
                        } else {
                            *self
                                .lookup_prefix_products
                                .as_ref()
                                .and_then(|products| {
                                    usize::try_from(table_value - 1)
                                        .ok()
                                        .and_then(|ordinal| products.get(ordinal))
                                })
                                .ok_or(CommonProofProverError::InvalidInput)?
                        };
                        let denominator_inverse = accumulated_inverse.multiply(prefix_before);
                        let denominator =
                            lookup_challenge.add(ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)?,
                            ));
                        accumulated_inverse = accumulated_inverse.multiply(denominator);
                        let contribution = row_scale.multiply(denominator_inverse.negate());
                        self.add_destination(
                            task.first_destination_element
                                .checked_add(table_value)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                            contribution,
                        )?;
                    }
                    self.phase = AccumulatorPhase::LookupTableReversePass {
                        remaining_table_value_count: first_table_value,
                        accumulated_inverse,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::LookupTableReversePass,
                            completed_work_unit_count: completed_table_value_count,
                        },
                    );
                }
                AccumulatorPhase::CoefficientEqualityForwardTransform => {
                    self.transform_domain
                        .evaluate_extension_polynomial_in_place(
                            self.coefficient_equality
                                .as_mut()
                                .ok_or(CommonProofProverError::InvalidInput)?,
                        )?;
                    self.phase = AccumulatorPhase::PublicAdjointFill {
                        task_ordinal: 0,
                        next_coefficient_ordinal: 0,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEqualityForwardTransform,
                            completed_work_unit_count: transform_butterfly_count(
                                self.plan.transform_domain_size,
                            )?,
                        },
                    );
                }
                AccumulatorPhase::PublicAdjointFill {
                    task_ordinal,
                    next_coefficient_ordinal,
                } => {
                    let Some(&task) = self.plan.public_product_tasks.get(task_ordinal) else {
                        self.coefficient_equality = None;
                        self.block_equality = None;
                        self.phase = AccumulatorPhase::Complete;
                        continue;
                    };
                    if next_coefficient_ordinal == 0 && self.public_transform.is_none() {
                        self.public_transform =
                            Some(fallible_base_vector(self.plan.transform_domain_size)?);
                    }
                    if next_coefficient_ordinal == self.plan.ring_degree {
                        self.phase =
                            AccumulatorPhase::PublicPolynomialForwardTransform { task_ordinal };
                        continue;
                    }
                    let completed_coefficient_count = self
                        .plan
                        .ring_degree
                        .checked_sub(next_coefficient_ordinal)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        .min(maximum_element_count);
                    let end_coefficient_ordinal = next_coefficient_ordinal
                        .checked_add(completed_coefficient_count)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let public_transform = self
                        .public_transform
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    for adjoint_coefficient_ordinal in
                        next_coefficient_ordinal..end_coefficient_ordinal
                    {
                        let source_coefficient_ordinal = if adjoint_coefficient_ordinal == 0 {
                            0
                        } else {
                            self.plan.ring_degree - adjoint_coefficient_ordinal
                        };
                        let mut coefficient = self.source.public_input_base_value(
                            task.public_vector_first_element
                                .checked_add(source_coefficient_ordinal)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                        )?;
                        if adjoint_coefficient_ordinal != 0 {
                            coefficient = coefficient.negate();
                        }
                        public_transform.push(coefficient);
                    }
                    self.phase = AccumulatorPhase::PublicAdjointFill {
                        task_ordinal,
                        next_coefficient_ordinal: end_coefficient_ordinal,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step:
                                CompactStructuredWitnessCovectorAccumulatorStep::PublicAdjointFill,
                            completed_work_unit_count: completed_coefficient_count,
                        },
                    );
                }
                AccumulatorPhase::PublicPolynomialForwardTransform { task_ordinal } => {
                    self.transform_domain.evaluate_base_polynomial_in_place(
                        self.public_transform
                            .as_mut()
                            .ok_or(CommonProofProverError::InvalidInput)?,
                    )?;
                    self.product_transform =
                        Some(fallible_extension_vector(self.plan.transform_domain_size)?);
                    self.phase = AccumulatorPhase::PointwiseProduct {
                        task_ordinal,
                        next_evaluation_ordinal: 0,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::PublicPolynomialForwardTransform,
                            completed_work_unit_count: transform_butterfly_count(
                                self.plan.transform_domain_size,
                            )?,
                        },
                    );
                }
                AccumulatorPhase::PointwiseProduct {
                    task_ordinal,
                    next_evaluation_ordinal,
                } => {
                    if next_evaluation_ordinal == self.plan.transform_domain_size {
                        self.phase =
                            AccumulatorPhase::ProductPolynomialInverseTransform { task_ordinal };
                        continue;
                    }
                    let completed_evaluation_count = self
                        .plan
                        .transform_domain_size
                        .checked_sub(next_evaluation_ordinal)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        .min(maximum_element_count);
                    let end_evaluation_ordinal = next_evaluation_ordinal
                        .checked_add(completed_evaluation_count)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let coefficient_equality = self
                        .coefficient_equality
                        .as_ref()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    let public_transform = self
                        .public_transform
                        .as_ref()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    let product_transform = self
                        .product_transform
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    for evaluation_ordinal in next_evaluation_ordinal..end_evaluation_ordinal {
                        let evaluation_index = usize::try_from(evaluation_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?;
                        product_transform.push(
                            coefficient_equality[evaluation_index]
                                .multiply_base(public_transform[evaluation_index]),
                        );
                    }
                    self.phase = AccumulatorPhase::PointwiseProduct {
                        task_ordinal,
                        next_evaluation_ordinal: end_evaluation_ordinal,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::PointwiseProduct,
                            completed_work_unit_count: completed_evaluation_count,
                        },
                    );
                }
                AccumulatorPhase::ProductPolynomialInverseTransform { task_ordinal } => {
                    self.transform_domain
                        .interpolate_extension_polynomial_in_place(
                            self.product_transform
                                .as_mut()
                                .ok_or(CommonProofProverError::InvalidInput)?,
                        )?;
                    self.public_transform = None;
                    self.phase = AccumulatorPhase::NegacyclicProductFold {
                        task_ordinal,
                        next_coefficient_ordinal: 0,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::ProductPolynomialInverseTransform,
                            completed_work_unit_count: transform_butterfly_count(
                                self.plan.transform_domain_size,
                            )?,
                        },
                    );
                }
                AccumulatorPhase::NegacyclicProductFold {
                    task_ordinal,
                    next_coefficient_ordinal,
                } => {
                    if next_coefficient_ordinal == self.plan.ring_degree {
                        self.product_transform = None;
                        self.phase = AccumulatorPhase::PublicAdjointFill {
                            task_ordinal: task_ordinal
                                .checked_add(1)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                            next_coefficient_ordinal: 0,
                        };
                        continue;
                    }
                    let completed_coefficient_count = self
                        .plan
                        .ring_degree
                        .checked_sub(next_coefficient_ordinal)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        .min(maximum_element_count);
                    let end_coefficient_ordinal = next_coefficient_ordinal
                        .checked_add(completed_coefficient_count)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let task = *self
                        .plan
                        .public_product_tasks
                        .get(task_ordinal)
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    let scale = self
                        .block_weight(task.row_block_ordinal)?
                        .multiply(self.matrix_role_weights[task.matrix_role.ordinal()])
                        .multiply_base(base_element_from_signed_integer(task.integer_coefficient)?);
                    for coefficient_ordinal in next_coefficient_ordinal..end_coefficient_ordinal {
                        let lower = self.product_coefficient(coefficient_ordinal)?;
                        let upper = self.product_coefficient(
                            coefficient_ordinal
                                .checked_add(self.plan.ring_degree)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                        )?;
                        self.add_destination(
                            task.private_vector_first_destination_element
                                .checked_add(coefficient_ordinal)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                            lower.subtract(upper).multiply(scale),
                        )?;
                    }
                    self.phase = AccumulatorPhase::NegacyclicProductFold {
                        task_ordinal,
                        next_coefficient_ordinal: end_coefficient_ordinal,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::NegacyclicProductFold,
                            completed_work_unit_count: completed_coefficient_count,
                        },
                    );
                }
                AccumulatorPhase::Complete => {
                    return Ok(CompactStructuredWitnessCovectorAccumulatorPoll::Complete(
                        self.destination
                            .take()
                            .ok_or(CommonProofProverError::InvalidInput)?,
                    ));
                }
            }
        }
    }

    fn accumulate_sparse_task_chunk(
        &mut self,
        task: SparseTask,
        first_element_offset: u64,
        element_count: u64,
    ) -> Result<(), CommonProofProverError> {
        let (row_block_ordinal, row_coefficient_ordinal, first_destination_element, coefficient) =
            match task {
                SparseTask::Block(task) => (
                    task.row_block_ordinal,
                    first_element_offset,
                    task.first_destination_element
                        .checked_add(first_element_offset)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                    task.integer_coefficient,
                ),
                SparseTask::Range(task) => (
                    task.row_block_ordinal,
                    task.row_coefficient_ordinal,
                    task.first_destination_element
                        .checked_add(first_element_offset)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                    task.integer_coefficient,
                ),
            };
        let matrix_role = match task {
            SparseTask::Block(task) => task.matrix_role,
            SparseTask::Range(task) => task.matrix_role,
        };
        let coefficient = base_element_from_signed_integer(coefficient)?;
        for element_offset in 0..element_count {
            let row_coefficient = match task {
                SparseTask::Block(_) => row_coefficient_ordinal
                    .checked_add(element_offset)
                    .ok_or(CommonProofProverError::CountOverflow)?,
                SparseTask::Range(_) => row_coefficient_ordinal,
            };
            let contribution = self
                .row_weight(row_block_ordinal, row_coefficient)?
                .multiply(self.matrix_role_weights[matrix_role.ordinal()])
                .multiply_base(coefficient);
            self.add_destination(
                first_destination_element
                    .checked_add(element_offset)
                    .ok_or(CommonProofProverError::CountOverflow)?,
                contribution,
            )?;
        }
        Ok(())
    }

    fn row_weight(
        &self,
        row_block_ordinal: u64,
        row_coefficient_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        Ok(self
            .block_weight(row_block_ordinal)?
            .multiply(self.coefficient_weight(row_coefficient_ordinal)?))
    }

    fn block_weight(
        &self,
        row_block_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        self.block_equality
            .as_ref()
            .and_then(|weights| {
                usize::try_from(row_block_ordinal)
                    .ok()
                    .and_then(|ordinal| weights.get(ordinal))
            })
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)
    }

    fn coefficient_weight(
        &self,
        row_coefficient_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        self.coefficient_equality
            .as_ref()
            .and_then(|weights| {
                usize::try_from(row_coefficient_ordinal)
                    .ok()
                    .and_then(|ordinal| weights.get(ordinal))
            })
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)
    }

    fn product_coefficient(
        &self,
        coefficient_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        let coefficient_index = usize::try_from(coefficient_ordinal)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        Ok(self
            .product_transform
            .as_ref()
            .and_then(|coefficients| coefficients.get(coefficient_index))
            .copied()
            .unwrap_or(ProofChallengeExtensionElement::ZERO))
    }

    fn add_destination(
        &mut self,
        destination_element: u64,
        contribution: ProofChallengeExtensionElement,
    ) -> Result<(), CommonProofProverError> {
        let destination = self
            .destination
            .as_mut()
            .and_then(|destination| {
                usize::try_from(destination_element)
                    .ok()
                    .and_then(|ordinal| destination.get_mut(ordinal))
            })
            .ok_or(CommonProofProverError::InvalidInput)?;
        *destination += compact_challenge_from_production(contribution);
        Ok(())
    }
}

impl<'handoff, 'material, Assignment>
    CompactStructuredWitnessCovectorHandoff<
        'handoff,
        CompactStructuredR1csRowSource<'material, Assignment>,
    >
where
    'material: 'handoff,
    Assignment: CompactStructuredAssignmentSource + ?Sized,
{
    pub(crate) fn from_production_row_source(
        source: &'handoff CompactStructuredR1csRowSource<'material, Assignment>,
        combination: CompactCfwMatrixClaimCombination,
    ) -> Result<Self, CompactStructuredWitnessCovectorHandoffError> {
        let workload =
            CompactStructuredWitnessCovectorGeometry::derive(source.relation, &source.matrices)?;
        let plan =
            StructuredTransposePlan::from_production(source.relation, &source.matrices, workload)?;
        let (continuation, destination) = combination.into_parts();
        if u64::try_from(destination.len()).map_err(|_| CommonProofProverError::CountOverflow)?
            != source.witness_length()
        {
            return Err(CompactCfwError::InvalidMatrixSource.into());
        }
        let accumulator = CompactStructuredWitnessCovectorAccumulator::new(
            source,
            plan,
            continuation.row_point(),
            continuation.matrix_role_weights(),
            destination,
        )?;
        Ok(Self {
            accumulator,
            continuation: Some(continuation),
        })
    }
}

impl<'source, Source> CompactStructuredWitnessCovectorHandoff<'source, Source>
where
    Source: StructuredTransposeValueSource + ?Sized,
{
    pub(crate) fn advance(
        &mut self,
        maximum_element_count: u64,
    ) -> Result<
        CompactStructuredWitnessCovectorHandoffPoll,
        CompactStructuredWitnessCovectorHandoffError,
    > {
        match self.accumulator.advance(maximum_element_count)? {
            CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                step,
                completed_work_unit_count,
            } => Ok(CompactStructuredWitnessCovectorHandoffPoll::StepCompleted {
                step,
                completed_work_unit_count,
            }),
            CompactStructuredWitnessCovectorAccumulatorPoll::Complete(source_covector) => {
                let continuation = self
                    .continuation
                    .take()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                Ok(CompactStructuredWitnessCovectorHandoffPoll::Complete(
                    continuation.finish_after_matrix_accumulation(source_covector)?,
                ))
            }
        }
    }
}

fn step_completed(
    step: CompactStructuredWitnessCovectorAccumulatorStep,
    completed_work_unit_count: usize,
) -> Result<CompactStructuredWitnessCovectorAccumulatorPoll, CommonProofProverError> {
    Ok(
        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
            step,
            completed_work_unit_count: u64::try_from(completed_work_unit_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        },
    )
}

fn transform_butterfly_count(transform_domain_size: u64) -> Result<u64, CommonProofProverError> {
    transform_domain_size
        .checked_div(2)
        .and_then(|count| count.checked_mul(u64::from(transform_domain_size.ilog2())))
        .ok_or(CommonProofProverError::CountOverflow)
}

fn fallible_extension_vector(
    capacity: u64,
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    let capacity = usize::try_from(capacity).map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    if values.capacity() != capacity {
        return Err(CommonProofProverError::AllocationLimitExceeded);
    }
    Ok(Zeroizing::new(values))
}

fn fallible_challenge_point_copy(
    point: &[CompactChallengeField],
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(point.len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    if copy.capacity() != point.len() {
        return Err(CommonProofProverError::AllocationLimitExceeded);
    }
    for coordinate in point {
        copy.push(
            compact_challenge_to_production(*coordinate)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
        );
    }
    Ok(copy)
}

fn fallible_base_vector(
    capacity: u64,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofProverError> {
    let capacity = usize::try_from(capacity).map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    if values.capacity() != capacity {
        return Err(CommonProofProverError::AllocationLimitExceeded);
    }
    Ok(Zeroizing::new(values))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_field::PrimeCharacteristicRing;

    use super::*;

    struct SmallTransposeSource {
        public_values: Vec<ProofBaseFieldElement>,
        lookup_challenge: ProofChallengeExtensionElement,
    }

    impl StructuredTransposeValueSource for SmallTransposeSource {
        fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
            self.lookup_challenge
        }

        fn public_input_base_value(
            &self,
            element_ordinal: u64,
        ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
            self.public_values
                .get(
                    usize::try_from(element_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .copied()
                .ok_or(CommonProofProverError::InvalidInput)
        }
    }

    fn challenge(seed: u64) -> CompactChallengeField {
        compact_challenge_from_production(
            ProofChallengeExtensionElement::from_canonical_coordinates([
                seed,
                seed + 1,
                seed + 2,
                seed + 3,
                seed + 4,
            ])
            .expect("small challenge is canonical"),
        )
    }

    fn signed_extension(value: i128) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(
            base_element_from_signed_integer(value).expect("small signed coefficient"),
        )
    }

    fn little_endian_row_weight(
        point: &[ProofChallengeExtensionElement],
        row_ordinal: usize,
    ) -> ProofChallengeExtensionElement {
        point.iter().enumerate().fold(
            ProofChallengeExtensionElement::ONE,
            |weight, (coordinate_ordinal, coordinate)| {
                weight.multiply(if (row_ordinal >> coordinate_ordinal) & 1 == 0 {
                    ProofChallengeExtensionElement::ONE.subtract(*coordinate)
                } else {
                    *coordinate
                })
            },
        )
    }

    #[test]
    fn production_row_source_handoff_is_type_checked_without_selected_execution() {
        type ProductionRowSource =
            CompactStructuredR1csRowSource<'static, CompactPublicKeyAssignment>;

        let production_constructor = CompactStructuredWitnessCovectorHandoff::<
            'static,
            ProductionRowSource,
        >::from_production_row_source;
        let handoff_advance =
            CompactStructuredWitnessCovectorHandoff::<'static, ProductionRowSource>::advance;
        let completed_step = CompactStructuredWitnessCovectorHandoffPoll::completed_step;
        let into_complete = CompactStructuredWitnessCovectorHandoffPoll::into_complete;

        let _production_handoff_methods = (
            production_constructor,
            handoff_advance,
            completed_step,
            into_complete,
        );
    }

    #[test]
    fn small_pollable_transpose_matches_direct_dense_matrix_interpretation() {
        let ring_degree = 4_u64;
        let public_values = [2_u64, 3, 5, 7]
            .into_iter()
            .map(|value| ProofBaseFieldElement::from_canonical(value).expect("public value"))
            .collect::<Vec<_>>();
        let lookup_challenge =
            compact_challenge_to_production(challenge(11)).expect("lookup challenge");
        let source = SmallTransposeSource {
            public_values: public_values.clone(),
            lookup_challenge,
        };
        let plan = StructuredTransposePlan {
            ring_degree,
            ring_variable_count: 2,
            ring_block_count: 2,
            ring_block_variable_count: 1,
            source_covector_element_count: 8,
            transform_domain_size: 8,
            sparse_tasks: vec![
                SparseTask::Block(BlockStaticTask {
                    row_block_ordinal: 0,
                    first_destination_element: 0,
                    integer_coefficient: 2,
                    matrix_role: CompactCfwMatrixRole::LeftMultiplicand,
                }),
                SparseTask::Block(BlockStaticTask {
                    row_block_ordinal: 0,
                    first_destination_element: 4,
                    integer_coefficient: -1,
                    matrix_role: CompactCfwMatrixRole::RightMultiplicand,
                }),
                SparseTask::Range(RangeStaticTask {
                    row_block_ordinal: 1,
                    row_coefficient_ordinal: 0,
                    first_destination_element: 1,
                    element_count: 3,
                    integer_coefficient: 1,
                    matrix_role: CompactCfwMatrixRole::LeftMultiplicand,
                }),
            ]
            .into_boxed_slice(),
            public_product_tasks: vec![PublicProductTask {
                row_block_ordinal: 0,
                public_vector_first_element: 0,
                private_vector_first_destination_element: 0,
                integer_coefficient: -3,
                matrix_role: CompactCfwMatrixRole::Product,
            }]
            .into_boxed_slice(),
            lookup_reciprocal_task: LookupReciprocalTask {
                row_block_ordinal: 1,
                row_coefficient_ordinal: 0,
                first_destination_element: 4,
                table_value_count: 4,
                matrix_role: CompactCfwMatrixRole::RightMultiplicand,
            },
        };
        let compact_row_point = [challenge(31), challenge(41), challenge(51)];
        let matrix_role_weights = [challenge(61), challenge(71), challenge(81)];
        let mut accumulator = CompactStructuredWitnessCovectorAccumulator::new(
            &source,
            plan,
            &compact_row_point,
            matrix_role_weights,
            vec![CompactChallengeField::ZERO; 8],
        )
        .expect("small accumulator");
        let mut step_work = BTreeMap::new();
        let actual = loop {
            match accumulator.advance(3).expect("bounded accumulator poll") {
                CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                    step,
                    completed_work_unit_count,
                } => {
                    *step_work.entry(step).or_insert(0_u64) += completed_work_unit_count;
                }
                CompactStructuredWitnessCovectorAccumulatorPoll::Complete(destination) => {
                    break destination;
                }
            }
        };

        let row_point = compact_row_point
            .map(|value| compact_challenge_to_production(value).expect("row point"));
        let role_weights = matrix_role_weights
            .map(|value| compact_challenge_to_production(value).expect("role weight"));
        let mut expected = vec![ProofChallengeExtensionElement::ZERO; 8];
        for row_ordinal in 0..8_usize {
            let row_weight = little_endian_row_weight(&row_point, row_ordinal);
            for destination_ordinal in 0..8_usize {
                let mut left = ProofChallengeExtensionElement::ZERO;
                let mut right = ProofChallengeExtensionElement::ZERO;
                let mut output = ProofChallengeExtensionElement::ZERO;
                if row_ordinal < 4 {
                    if destination_ordinal == row_ordinal {
                        left = left.add(signed_extension(2));
                    }
                    if destination_ordinal == 4 + row_ordinal {
                        right = right.add(signed_extension(-1));
                    }
                    for (public_coefficient_ordinal, public_value) in
                        public_values.iter().copied().enumerate()
                    {
                        let (private_coefficient_ordinal, negative) =
                            if public_coefficient_ordinal <= row_ordinal {
                                (row_ordinal - public_coefficient_ordinal, false)
                            } else {
                                (4 + row_ordinal - public_coefficient_ordinal, true)
                            };
                        if destination_ordinal == private_coefficient_ordinal {
                            let signed_product_coefficient = if negative { 3 } else { -3 };
                            output = output.add(
                                ProofChallengeExtensionElement::from_base(public_value)
                                    .multiply(signed_extension(signed_product_coefficient)),
                            );
                        }
                    }
                } else if row_ordinal == 4 {
                    if (1..4).contains(&destination_ordinal) {
                        left = left.add(ProofChallengeExtensionElement::ONE);
                    }
                    if destination_ordinal >= 4 {
                        let table_value =
                            u64::try_from(destination_ordinal - 4).expect("small table value");
                        let reciprocal = lookup_challenge
                            .add(ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)
                                    .expect("table value"),
                            ))
                            .inverse()
                            .expect("nonzero lookup denominator")
                            .negate();
                        right = right.add(reciprocal);
                    }
                }
                let combined_entry = left
                    .multiply(role_weights[0])
                    .add(right.multiply(role_weights[1]))
                    .add(output.multiply(role_weights[2]));
                expected[destination_ordinal] =
                    expected[destination_ordinal].add(row_weight.multiply(combined_entry));
            }
        }
        assert_eq!(
            actual,
            expected
                .into_iter()
                .map(compact_challenge_from_production)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            step_work,
            BTreeMap::from([
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEquality,
                    3,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::BlockEquality,
                    1,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::SparseWitness,
                    11,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::LookupTablePrefixProduct,
                    4,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::LookupTableProductInversion,
                    1,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::LookupTableReversePass,
                    4,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEqualityForwardTransform,
                    12,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::PublicAdjointFill,
                    4,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::PublicPolynomialForwardTransform,
                    12,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::PointwiseProduct,
                    8,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::ProductPolynomialInverseTransform,
                    12,
                ),
                (
                    CompactStructuredWitnessCovectorAccumulatorStep::NegacyclicProductFold,
                    4,
                ),
            ])
        );
    }
}
