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
use super::CompactStructuredWitnessCovectorGeometry;
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

impl<Source> StructuredTransposeValueSource for &Source
where
    Source: StructuredTransposeValueSource + ?Sized,
{
    fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
        Source::lookup_challenge(*self)
    }

    fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        Source::public_input_base_value(*self, element_ordinal)
    }
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
    DestinationProjection,
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
    ProjectedPublicAdjointFill,
    ProjectedPublicPolynomialForwardTransform,
    ProjectedPointwiseProduct,
    ProjectedProductPolynomialInverseTransform,
    ProjectedNegacyclicProductFold,
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
    BuildDestinationProjection,
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
    ProjectedPublicAdjointFill {
        task_ordinal: usize,
        next_coefficient_ordinal: u64,
    },
    ProjectedPublicPolynomialForwardTransform,
    ProjectedPointwiseProduct {
        next_evaluation_ordinal: u64,
    },
    ProjectedProductPolynomialInverseTransform,
    ProjectedNegacyclicProductFold {
        next_coefficient_ordinal: u64,
    },
    Complete,
}

struct DestinationBlockFold {
    builder: Option<LittleEndianEqualityBuilder>,
    weights: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
}

pub(crate) struct CompactStructuredWitnessCovectorAccumulator<Source>
where
    Source: StructuredTransposeValueSource,
{
    source: Source,
    plan: StructuredTransposePlan,
    matrix_role_weights: [ProofChallengeExtensionElement; COMPACT_CFW_MATRIX_COUNT],
    destination: Option<Vec<CompactChallengeField>>,
    destination_block_fold: Option<DestinationBlockFold>,
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
    accumulator: CompactStructuredWitnessCovectorAccumulator<&'source Source>,
    continuation: Option<CompactCfwClaimCombinationContinuation>,
}

impl<Source> CompactStructuredWitnessCovectorAccumulator<Source>
where
    Source: StructuredTransposeValueSource,
{
    /// Builds the public transpose directly in the image of one complete
    /// block fold. The projection is certified by the relation geometry: it
    /// must collapse every source block onto the single ring-sized
    /// destination, so no full witness-length covector is ever resident.
    pub(crate) fn from_projected_public_relation(
        source: Source,
        relation: &CompactPublicKeyRelationCatalog,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: Vec<CompactChallengeField>,
        block_folding_challenges: &[CompactChallengeField],
    ) -> Result<Self, CommonProofProverError> {
        let matrices = CompactStructuredR1csCatalog::derive(relation)?;
        let geometry = CompactStructuredWitnessCovectorGeometry::derive(relation, &matrices)?;
        let plan = StructuredTransposePlan::from_production(relation, &matrices, geometry)?;
        Self::new_with_block_fold(
            source,
            plan,
            row_point,
            matrix_role_weights,
            destination,
            block_folding_challenges,
        )
    }

    fn new(
        source: Source,
        plan: StructuredTransposePlan,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: Vec<CompactChallengeField>,
    ) -> Result<Self, CommonProofProverError> {
        Self::new_with_optional_block_fold(
            source,
            plan,
            row_point,
            matrix_role_weights,
            destination,
            None,
        )
    }

    fn new_with_block_fold(
        source: Source,
        plan: StructuredTransposePlan,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: Vec<CompactChallengeField>,
        block_folding_challenges: &[CompactChallengeField],
    ) -> Result<Self, CommonProofProverError> {
        Self::new_with_optional_block_fold(
            source,
            plan,
            row_point,
            matrix_role_weights,
            destination,
            Some(block_folding_challenges),
        )
    }

    fn new_with_optional_block_fold(
        source: Source,
        plan: StructuredTransposePlan,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: Vec<CompactChallengeField>,
        block_folding_challenges: Option<&[CompactChallengeField]>,
    ) -> Result<Self, CommonProofProverError> {
        plan.check()?;
        let expected_row_point_length = plan
            .ring_variable_count
            .checked_add(plan.ring_block_variable_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let source_block_count = plan
            .source_covector_element_count
            .checked_div(plan.ring_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let projected = block_folding_challenges.is_some();
        let expected_destination_length = usize::try_from(if projected {
            plan.ring_degree
        } else {
            plan.source_covector_element_count
        })
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        if row_point.len()
            != usize::try_from(expected_row_point_length)
                .map_err(|_| CommonProofProverError::CountOverflow)?
            || destination.len() != expected_destination_length
            || destination.capacity() != expected_destination_length
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let destination_block_fold = if let Some(challenges) = block_folding_challenges {
            if !plan
                .source_covector_element_count
                .is_multiple_of(plan.ring_degree)
                || source_block_count < 2
                || !source_block_count.is_power_of_two()
                || challenges.len()
                    != usize::try_from(source_block_count.ilog2())
                        .map_err(|_| CommonProofProverError::CountOverflow)?
                || plan.public_product_tasks.iter().any(|task| {
                    !task
                        .private_vector_first_destination_element
                        .is_multiple_of(plan.ring_degree)
                })
            {
                return Err(CommonProofProverError::InvalidInput);
            }
            let reversed_point = challenges
                .iter()
                .rev()
                .copied()
                .map(compact_challenge_to_production)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| CommonProofProverError::InvalidInput)?;
            Some(DestinationBlockFold {
                builder: Some(LittleEndianEqualityBuilder::new(reversed_point)?),
                weights: None,
            })
        } else {
            None
        };
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
            destination_block_fold,
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
            phase: if projected {
                AccumulatorPhase::BuildDestinationProjection
            } else {
                AccumulatorPhase::BuildCoefficientEquality
            },
        })
    }

    /// Advances through one element chunk or one isolated transform.
    ///
    /// Every returned `StepCompleted` is a deterministic orchestration
    /// checkpoint boundary. Radix-two transforms themselves are deliberately
    /// indivisible: their phase and complete input buffer are the state that a
    /// future authenticated checkpoint format would have to retain. This type
    /// does not speculate about or serialize that format.
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
                AccumulatorPhase::BuildDestinationProjection => {
                    let projection = self
                        .destination_block_fold
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    let builder = projection
                        .builder
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    if builder.is_complete() {
                        projection.weights = Some(
                            projection
                                .builder
                                .take()
                                .ok_or(CommonProofProverError::InvalidInput)?
                                .finish()?,
                        );
                        self.phase = AccumulatorPhase::BuildCoefficientEquality;
                        continue;
                    }
                    let completed_parent_count = builder.advance(maximum_element_count_usize)?;
                    return step_completed(
                        CompactStructuredWitnessCovectorAccumulatorStep::DestinationProjection,
                        completed_parent_count,
                    );
                }
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
                    self.phase = if self.destination_block_fold.is_some() {
                        self.product_transform = Some(fallible_zeroed_extension_vector(
                            self.plan.transform_domain_size,
                        )?);
                        AccumulatorPhase::ProjectedPublicAdjointFill {
                            task_ordinal: 0,
                            next_coefficient_ordinal: 0,
                        }
                    } else {
                        AccumulatorPhase::PublicAdjointFill {
                            task_ordinal: 0,
                            next_coefficient_ordinal: 0,
                        }
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
                AccumulatorPhase::ProjectedPublicAdjointFill {
                    task_ordinal,
                    next_coefficient_ordinal,
                } => {
                    let Some(&task) = self.plan.public_product_tasks.get(task_ordinal) else {
                        self.phase = AccumulatorPhase::ProjectedPublicPolynomialForwardTransform;
                        continue;
                    };
                    if next_coefficient_ordinal == self.plan.ring_degree {
                        self.phase = AccumulatorPhase::ProjectedPublicAdjointFill {
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
                    let destination_block_ordinal = task
                        .private_vector_first_destination_element
                        .checked_div(self.plan.ring_degree)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let destination_projection_weight =
                        self.destination_projection_weight(destination_block_ordinal)?;
                    let scale = self
                        .block_weight(task.row_block_ordinal)?
                        .multiply(self.matrix_role_weights[task.matrix_role.ordinal()])
                        .multiply_base(base_element_from_signed_integer(task.integer_coefficient)?)
                        .multiply(destination_projection_weight);
                    let product_transform = self
                        .product_transform
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
                        let coefficient_index = usize::try_from(adjoint_coefficient_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?;
                        product_transform[coefficient_index] = product_transform[coefficient_index]
                            .add(scale.multiply_base(coefficient));
                    }
                    self.phase = AccumulatorPhase::ProjectedPublicAdjointFill {
                        task_ordinal,
                        next_coefficient_ordinal: end_coefficient_ordinal,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::ProjectedPublicAdjointFill,
                            completed_work_unit_count: completed_coefficient_count,
                        },
                    );
                }
                AccumulatorPhase::ProjectedPublicPolynomialForwardTransform => {
                    self.transform_domain
                        .evaluate_extension_polynomial_in_place(
                            self.product_transform
                                .as_mut()
                                .ok_or(CommonProofProverError::InvalidInput)?,
                        )?;
                    self.phase = AccumulatorPhase::ProjectedPointwiseProduct {
                        next_evaluation_ordinal: 0,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::ProjectedPublicPolynomialForwardTransform,
                            completed_work_unit_count: transform_butterfly_count(
                                self.plan.transform_domain_size,
                            )?,
                        },
                    );
                }
                AccumulatorPhase::ProjectedPointwiseProduct {
                    next_evaluation_ordinal,
                } => {
                    if next_evaluation_ordinal == self.plan.transform_domain_size {
                        self.phase = AccumulatorPhase::ProjectedProductPolynomialInverseTransform;
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
                    let product_transform = self
                        .product_transform
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    for evaluation_ordinal in next_evaluation_ordinal..end_evaluation_ordinal {
                        let evaluation_index = usize::try_from(evaluation_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?;
                        product_transform[evaluation_index] = product_transform[evaluation_index]
                            .multiply(coefficient_equality[evaluation_index]);
                    }
                    self.phase = AccumulatorPhase::ProjectedPointwiseProduct {
                        next_evaluation_ordinal: end_evaluation_ordinal,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::ProjectedPointwiseProduct,
                            completed_work_unit_count: completed_evaluation_count,
                        },
                    );
                }
                AccumulatorPhase::ProjectedProductPolynomialInverseTransform => {
                    self.transform_domain
                        .interpolate_extension_polynomial_in_place(
                            self.product_transform
                                .as_mut()
                                .ok_or(CommonProofProverError::InvalidInput)?,
                        )?;
                    self.phase = AccumulatorPhase::ProjectedNegacyclicProductFold {
                        next_coefficient_ordinal: 0,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::ProjectedProductPolynomialInverseTransform,
                            completed_work_unit_count: transform_butterfly_count(
                                self.plan.transform_domain_size,
                            )?,
                        },
                    );
                }
                AccumulatorPhase::ProjectedNegacyclicProductFold {
                    next_coefficient_ordinal,
                } => {
                    if next_coefficient_ordinal == self.plan.ring_degree {
                        self.product_transform = None;
                        self.coefficient_equality = None;
                        self.block_equality = None;
                        self.phase = AccumulatorPhase::Complete;
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
                    for coefficient_ordinal in next_coefficient_ordinal..end_coefficient_ordinal {
                        let lower = self.product_coefficient(coefficient_ordinal)?;
                        let upper = self.product_coefficient(
                            coefficient_ordinal
                                .checked_add(self.plan.ring_degree)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                        )?;
                        self.add_projected_destination(coefficient_ordinal, lower.subtract(upper))?;
                    }
                    self.phase = AccumulatorPhase::ProjectedNegacyclicProductFold {
                        next_coefficient_ordinal: end_coefficient_ordinal,
                    };
                    return Ok(
                        CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                            step: CompactStructuredWitnessCovectorAccumulatorStep::ProjectedNegacyclicProductFold,
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
        if self.destination_block_fold.is_some() {
            let destination_block_ordinal = destination_element
                .checked_div(self.plan.ring_degree)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let projected_destination_element = destination_element % self.plan.ring_degree;
            let projection_weight =
                self.destination_projection_weight(destination_block_ordinal)?;
            return self.add_projected_destination(
                projected_destination_element,
                contribution.multiply(projection_weight),
            );
        }
        self.add_projected_destination(destination_element, contribution)
    }

    fn destination_projection_weight(
        &self,
        destination_block_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        self.destination_block_fold
            .as_ref()
            .and_then(|projection| projection.weights.as_ref())
            .and_then(|weights| {
                usize::try_from(destination_block_ordinal)
                    .ok()
                    .and_then(|ordinal| weights.get(ordinal))
            })
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)
    }

    fn add_projected_destination(
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

fn fallible_zeroed_extension_vector(
    length: u64,
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    let mut values = fallible_extension_vector(length)?;
    values.resize(
        usize::try_from(length).map_err(|_| CommonProofProverError::CountOverflow)?,
        ProofChallengeExtensionElement::ZERO,
    );
    Ok(values)
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
    use crate::bgv::proof_suite::relation_plan::compact_ring_vector::selected_compact_public_key_relation_catalog;

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
    fn selected_projected_transpose_has_no_full_covector_buffer() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let matrices =
            CompactStructuredR1csCatalog::derive(&relation).expect("selected structured matrices");
        let geometry = CompactStructuredWitnessCovectorGeometry::derive(&relation, &matrices)
            .expect("selected transpose geometry");
        let plan = StructuredTransposePlan::from_production(&relation, &matrices, geometry)
            .expect("selected transpose plan");
        let source_block_count = plan.source_covector_element_count / plan.ring_degree;
        let projected_destination_element_count = plan.ring_degree;

        assert_eq!(source_block_count, 128);
        assert_eq!(source_block_count.ilog2(), 7);
        assert_eq!(projected_destination_element_count, 32_768);
        assert_eq!(plan.source_covector_element_count, 4_194_304);
        assert_eq!(plan.public_product_tasks.len(), 32);
        assert!(plan.public_product_tasks.iter().all(|task| {
            task.private_vector_first_destination_element
                .is_multiple_of(plan.ring_degree)
        }));

        let lookup_phase_logical_extension_element_inventory = projected_destination_element_count
            + source_block_count
            + plan.ring_degree
            + plan.ring_block_count
            + plan.lookup_reciprocal_task.table_value_count;
        let aggregate_product_phase_logical_extension_element_inventory =
            projected_destination_element_count
                + source_block_count
                + plan.ring_block_count
                + 2 * plan.transform_domain_size;
        assert_eq!(lookup_phase_logical_extension_element_inventory, 196_992);
        assert_eq!(
            aggregate_product_phase_logical_extension_element_inventory,
            164_224
        );
        assert!(
            lookup_phase_logical_extension_element_inventory < plan.source_covector_element_count
                && aggregate_product_phase_logical_extension_element_inventory
                    < plan.source_covector_element_count
        );
    }

    #[test]
    fn small_projected_transpose_matches_dense_accumulator_and_direct_matrix() {
        let ring_degree = 4_u64;
        let public_values = [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
            .into_iter()
            .map(|value| ProofBaseFieldElement::from_canonical(value).expect("public value"))
            .collect::<Vec<_>>();
        let lookup_challenge =
            compact_challenge_to_production(challenge(11)).expect("lookup challenge");
        let plan = StructuredTransposePlan {
            ring_degree,
            ring_variable_count: 2,
            ring_block_count: 4,
            ring_block_variable_count: 2,
            source_covector_element_count: 16,
            transform_domain_size: 8,
            sparse_tasks: vec![
                SparseTask::Block(BlockStaticTask {
                    row_block_ordinal: 0,
                    first_destination_element: 4,
                    integer_coefficient: 2,
                    matrix_role: CompactCfwMatrixRole::LeftMultiplicand,
                }),
                SparseTask::Block(BlockStaticTask {
                    row_block_ordinal: 2,
                    first_destination_element: 0,
                    integer_coefficient: -1,
                    matrix_role: CompactCfwMatrixRole::RightMultiplicand,
                }),
                SparseTask::Range(RangeStaticTask {
                    row_block_ordinal: 3,
                    row_coefficient_ordinal: 0,
                    first_destination_element: 9,
                    element_count: 3,
                    integer_coefficient: 1,
                    matrix_role: CompactCfwMatrixRole::Product,
                }),
            ]
            .into_boxed_slice(),
            public_product_tasks: vec![
                PublicProductTask {
                    row_block_ordinal: 0,
                    public_vector_first_element: 0,
                    private_vector_first_destination_element: 0,
                    integer_coefficient: -3,
                    matrix_role: CompactCfwMatrixRole::Product,
                },
                PublicProductTask {
                    row_block_ordinal: 1,
                    public_vector_first_element: 4,
                    private_vector_first_destination_element: 8,
                    integer_coefficient: 2,
                    matrix_role: CompactCfwMatrixRole::LeftMultiplicand,
                },
                PublicProductTask {
                    row_block_ordinal: 3,
                    public_vector_first_element: 8,
                    private_vector_first_destination_element: 12,
                    integer_coefficient: -2,
                    matrix_role: CompactCfwMatrixRole::RightMultiplicand,
                },
            ]
            .into_boxed_slice(),
            lookup_reciprocal_task: LookupReciprocalTask {
                row_block_ordinal: 2,
                row_coefficient_ordinal: 0,
                first_destination_element: 4,
                table_value_count: 4,
                matrix_role: CompactCfwMatrixRole::RightMultiplicand,
            },
        };
        let compact_row_point = [challenge(31), challenge(41), challenge(51), challenge(57)];
        let matrix_role_weights = [challenge(61), challenge(71), challenge(81)];
        let folding_challenges = [challenge(91), challenge(101)];
        let [first_challenge, second_challenge] = folding_challenges;
        let block_weights = [
            (CompactChallengeField::ONE - first_challenge)
                * (CompactChallengeField::ONE - second_challenge),
            (CompactChallengeField::ONE - first_challenge) * second_challenge,
            first_challenge * (CompactChallengeField::ONE - second_challenge),
            first_challenge * second_challenge,
        ];
        let dense_initial = (0..16_u64)
            .map(|ordinal| challenge(131 + ordinal))
            .collect::<Vec<_>>();
        let projected_initial = (0..4)
            .map(|coefficient_ordinal| {
                block_weights.iter().enumerate().fold(
                    CompactChallengeField::ZERO,
                    |value, (block_ordinal, weight)| {
                        value + *weight * dense_initial[4 * block_ordinal + coefficient_ordinal]
                    },
                )
            })
            .collect::<Vec<_>>();
        let dense_source = SmallTransposeSource {
            public_values: public_values.clone(),
            lookup_challenge,
        };
        let (actual, step_work) = drain_accumulator(
            CompactStructuredWitnessCovectorAccumulator::new(
                dense_source,
                plan.clone(),
                &compact_row_point,
                matrix_role_weights,
                dense_initial.clone(),
            )
            .expect("small dense accumulator"),
            3,
        );

        let row_point = compact_row_point
            .map(|value| compact_challenge_to_production(value).expect("row point"));
        let role_weights = matrix_role_weights
            .map(|value| compact_challenge_to_production(value).expect("role weight"));
        let mut direct = dense_initial
            .iter()
            .copied()
            .map(|value| compact_challenge_to_production(value).expect("initial coefficient"))
            .collect::<Vec<_>>();
        for row_ordinal in 0..16_usize {
            let row_block_ordinal = row_ordinal / 4;
            let ring_row_ordinal = row_ordinal % 4;
            let row_weight = little_endian_row_weight(&row_point, row_ordinal);
            for (destination_ordinal, destination) in direct.iter_mut().enumerate() {
                let mut entries = [ProofChallengeExtensionElement::ZERO; 3];
                match row_block_ordinal {
                    0 => {
                        if destination_ordinal == 4 + ring_row_ordinal {
                            entries[0] = entries[0].add(signed_extension(2));
                        }
                        if destination_ordinal < 4 {
                            entries[2] = entries[2].add(direct_public_band_entry(
                                &public_values[0..4],
                                ring_row_ordinal,
                                destination_ordinal,
                                -3,
                            ));
                        }
                    }
                    1 if (8..12).contains(&destination_ordinal) => {
                        entries[0] = entries[0].add(direct_public_band_entry(
                            &public_values[4..8],
                            ring_row_ordinal,
                            destination_ordinal - 8,
                            2,
                        ));
                    }
                    2 => {
                        if destination_ordinal == ring_row_ordinal {
                            entries[1] = entries[1].add(signed_extension(-1));
                        }
                        if ring_row_ordinal == 0 && (4..8).contains(&destination_ordinal) {
                            let table_value =
                                u64::try_from(destination_ordinal - 4).expect("small table value");
                            entries[1] = entries[1].add(
                                lookup_challenge
                                    .add(ProofChallengeExtensionElement::from_base(
                                        ProofBaseFieldElement::from_canonical(table_value)
                                            .expect("table value"),
                                    ))
                                    .inverse()
                                    .expect("nonzero lookup denominator")
                                    .negate(),
                            );
                        }
                    }
                    3 => {
                        if ring_row_ordinal == 0 && (9..12).contains(&destination_ordinal) {
                            entries[2] = entries[2].add(ProofChallengeExtensionElement::ONE);
                        }
                        if (12..16).contains(&destination_ordinal) {
                            entries[1] = entries[1].add(direct_public_band_entry(
                                &public_values[8..12],
                                ring_row_ordinal,
                                destination_ordinal - 12,
                                -2,
                            ));
                        }
                    }
                    _ => {}
                }
                let combined_entry = entries.into_iter().zip(role_weights).fold(
                    ProofChallengeExtensionElement::ZERO,
                    |value, (entry, role)| value.add(entry.multiply(role)),
                );
                *destination = destination.add(row_weight.multiply(combined_entry));
            }
        }
        assert_eq!(
            actual,
            direct
                .into_iter()
                .map(compact_challenge_from_production)
                .collect::<Vec<_>>()
        );

        let projected_source = SmallTransposeSource {
            public_values,
            lookup_challenge,
        };
        let (projected_actual, projected_step_work) = drain_accumulator(
            CompactStructuredWitnessCovectorAccumulator::new_with_block_fold(
                projected_source,
                plan,
                &compact_row_point,
                matrix_role_weights,
                projected_initial,
                &folding_challenges,
            )
            .expect("small projected accumulator"),
            3,
        );
        let projected_expected = (0..4)
            .map(|coefficient_ordinal| {
                block_weights.iter().enumerate().fold(
                    CompactChallengeField::ZERO,
                    |value, (block_ordinal, weight)| {
                        value + *weight * actual[4 * block_ordinal + coefficient_ordinal]
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(projected_actual, projected_expected);
        assert_eq!(
            projected_step_work,
            BTreeMap::from([
                (CompactStructuredWitnessCovectorAccumulatorStep::DestinationProjection, 3),
                (CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEquality, 3),
                (CompactStructuredWitnessCovectorAccumulatorStep::BlockEquality, 3),
                (CompactStructuredWitnessCovectorAccumulatorStep::SparseWitness, 11),
                (CompactStructuredWitnessCovectorAccumulatorStep::LookupTablePrefixProduct, 4),
                (CompactStructuredWitnessCovectorAccumulatorStep::LookupTableProductInversion, 1),
                (CompactStructuredWitnessCovectorAccumulatorStep::LookupTableReversePass, 4),
                (CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEqualityForwardTransform, 12),
                (CompactStructuredWitnessCovectorAccumulatorStep::ProjectedPublicAdjointFill, 12),
                (CompactStructuredWitnessCovectorAccumulatorStep::ProjectedPublicPolynomialForwardTransform, 12),
                (CompactStructuredWitnessCovectorAccumulatorStep::ProjectedPointwiseProduct, 8),
                (CompactStructuredWitnessCovectorAccumulatorStep::ProjectedProductPolynomialInverseTransform, 12),
                (CompactStructuredWitnessCovectorAccumulatorStep::ProjectedNegacyclicProductFold, 4),
            ])
        );
        assert_eq!(
            step_work,
            BTreeMap::from([
                (CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEquality, 3),
                (CompactStructuredWitnessCovectorAccumulatorStep::BlockEquality, 3),
                (CompactStructuredWitnessCovectorAccumulatorStep::SparseWitness, 11),
                (CompactStructuredWitnessCovectorAccumulatorStep::LookupTablePrefixProduct, 4),
                (CompactStructuredWitnessCovectorAccumulatorStep::LookupTableProductInversion, 1),
                (CompactStructuredWitnessCovectorAccumulatorStep::LookupTableReversePass, 4),
                (CompactStructuredWitnessCovectorAccumulatorStep::CoefficientEqualityForwardTransform, 12),
                (CompactStructuredWitnessCovectorAccumulatorStep::PublicAdjointFill, 12),
                (CompactStructuredWitnessCovectorAccumulatorStep::PublicPolynomialForwardTransform, 36),
                (CompactStructuredWitnessCovectorAccumulatorStep::PointwiseProduct, 24),
                (CompactStructuredWitnessCovectorAccumulatorStep::ProductPolynomialInverseTransform, 36),
                (CompactStructuredWitnessCovectorAccumulatorStep::NegacyclicProductFold, 12),
            ])
        );
    }

    fn direct_public_band_entry(
        public_values: &[ProofBaseFieldElement],
        row_coefficient_ordinal: usize,
        destination_coefficient_ordinal: usize,
        integer_coefficient: i128,
    ) -> ProofChallengeExtensionElement {
        public_values.iter().copied().enumerate().fold(
            ProofChallengeExtensionElement::ZERO,
            |value, (public_coefficient_ordinal, public_value)| {
                let (private_coefficient_ordinal, wrapped) =
                    if public_coefficient_ordinal <= row_coefficient_ordinal {
                        (row_coefficient_ordinal - public_coefficient_ordinal, false)
                    } else {
                        (
                            4 + row_coefficient_ordinal - public_coefficient_ordinal,
                            true,
                        )
                    };
                if private_coefficient_ordinal != destination_coefficient_ordinal {
                    return value;
                }
                let coefficient = if wrapped {
                    -integer_coefficient
                } else {
                    integer_coefficient
                };
                value.add(
                    ProofChallengeExtensionElement::from_base(public_value)
                        .multiply(signed_extension(coefficient)),
                )
            },
        )
    }

    fn drain_accumulator<Source: StructuredTransposeValueSource>(
        mut accumulator: CompactStructuredWitnessCovectorAccumulator<Source>,
        maximum_element_count: u64,
    ) -> (
        Vec<CompactChallengeField>,
        BTreeMap<CompactStructuredWitnessCovectorAccumulatorStep, u64>,
    ) {
        let mut step_work = BTreeMap::new();
        loop {
            match accumulator
                .advance(maximum_element_count)
                .expect("bounded accumulator poll")
            {
                CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                    step,
                    completed_work_unit_count,
                } => {
                    *step_work.entry(step).or_insert(0_u64) += completed_work_unit_count;
                }
                CompactStructuredWitnessCovectorAccumulatorPoll::Complete(destination) => {
                    return (destination, step_work);
                }
            }
        }
    }
}
