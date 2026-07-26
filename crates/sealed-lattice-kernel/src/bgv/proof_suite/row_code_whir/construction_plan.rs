//! Descriptor-derived geometry for the selected row-code WHIR construction.

use std::collections::{BTreeMap, BTreeSet};

use crate::foundation::ProofApplicationSlotCeilings;
use crate::hashing::hash_framed_parts_512;

use super::super::profile::ProofProfileError;
use super::super::prover::{
    CommonProofProverError, requested_pre_challenge_source_column_ordinals,
};
#[cfg(test)]
use super::super::relation_plan::COMMITTED_MATERIAL_TRACE_PACKING_FACTOR;
use super::super::relation_plan::{
    BoundTreeConstructionKind, BoundTreeRootUse, ProofPrivacyMode, RelationColumnOrigin,
    RelationColumnValueType, RelationMaskKind, RelationMaskTargetClass, RelationOpeningSourceClass,
    RelationPlanVariant, RelationTreeDescriptor,
};
use super::super::selected_profile::{
    selected_bound_root_source_trace_domain_size, selected_relation_plan_check_context,
};
use super::super::{
    PROOF_BASE_FIELD_MODULUS, PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    ProofEvaluationDomain, ProofTreeRole, RelationPlanCheckContext, RelationPlanError,
    ValidatedRelationPlanArtifact,
};
use super::row_encoding::RowEncodingGeometry;

pub(super) const ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT: usize = 32_768;
pub(super) const ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize = 8;
pub(super) const ROW_CODE_WHIR_PHYSICAL_ROW_WITNESS_VARIABLE_COUNT: usize = 18;
pub(super) const ROW_CODE_WHIR_LOG_INVERSE_RATE: usize = 2;
pub(super) const ROW_CODE_WHIR_TABLE_VARIABLE_COUNT: usize = 19;
pub(super) const ROW_CODE_WHIR_POLYNOMIAL_COMMITMENT_VARIABLE_COUNT: usize = 21;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 =
    (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        * ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW) as u64;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE: u64 =
    1_u64 << ROW_CODE_WHIR_POLYNOMIAL_COMMITMENT_VARIABLE_COUNT;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT: u32 = 387;
pub(super) const ROW_CODE_WHIR_OUTER_QUERY_COUNT: usize =
    ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT as usize;
pub(super) const ROW_CODE_WHIR_DIRECT_BOUND_QUERY_COUNT: usize = 266;
pub(super) const ROW_CODE_WHIR_VERIFIED_VSS_BOUND_QUERY_COUNT: usize = 40;

const ROW_CODE_WHIR_FOLDING_FACTOR: usize = 3;
const ROW_CODE_WHIR_SECURITY_LEVEL: usize = 262;
const ROW_CODE_WHIR_PROOF_OF_WORK_BITS: usize = 0;
const ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_ENCODING_VERSION: u16 = 1;
const ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_HASH_DOMAIN: &str =
    "sealed-lattice/proof/row-code-whir/construction-plan/v1";

type BoundRootSourceTraceDomainSizeResolver =
    fn(u16, BoundTreeConstructionKind, u64, u64) -> Result<u64, ProofProfileError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirConstructionPlanError {
    InvalidSelectedProfile,
    InvalidVariantGeometry,
    InvalidOpeningCatalog,
    UnsupportedColumnValueType,
    CountOverflow,
    ProofProfile(ProofProfileError),
    Prover(CommonProofProverError),
    RelationPlan(RelationPlanError),
}

impl From<ProofProfileError> for RowCodeWhirConstructionPlanError {
    fn from(error: ProofProfileError) -> Self {
        Self::ProofProfile(error)
    }
}

impl From<CommonProofProverError> for RowCodeWhirConstructionPlanError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<RelationPlanError> for RowCodeWhirConstructionPlanError {
    fn from(error: RelationPlanError) -> Self {
        Self::RelationPlan(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirSoundnessAssumption {
    UniqueDecoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirSelectedParameters {
    pub(in crate::bgv::proof_suite) logical_polynomial_coefficient_count: usize,
    pub(in crate::bgv::proof_suite) logical_polynomials_per_physical_row: usize,
    pub(in crate::bgv::proof_suite) physical_row_witness_variable_count: usize,
    pub(in crate::bgv::proof_suite) row_code_log_inverse_rate: usize,
    pub(in crate::bgv::proof_suite) table_variable_count: usize,
    pub(in crate::bgv::proof_suite) polynomial_commitment_variable_count: usize,
    pub(in crate::bgv::proof_suite) starting_log_inverse_rate: usize,
    pub(in crate::bgv::proof_suite) folding_factor: usize,
    pub(in crate::bgv::proof_suite) soundness_assumption: RowCodeWhirSoundnessAssumption,
    pub(in crate::bgv::proof_suite) security_level: usize,
    pub(in crate::bgv::proof_suite) proof_of_work_bits: usize,
    pub(in crate::bgv::proof_suite) outer_query_count: usize,
    pub(in crate::bgv::proof_suite) direct_bound_query_count: usize,
    pub(in crate::bgv::proof_suite) verified_vss_bound_query_count: usize,
    pub(in crate::bgv::proof_suite) maximum_fiat_shamir_candidate_draws_per_output: u32,
}

impl RowCodeWhirSelectedParameters {
    pub(in crate::bgv::proof_suite) const fn selected() -> Self {
        Self {
            logical_polynomial_coefficient_count:
                ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT,
            logical_polynomials_per_physical_row:
                ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW,
            physical_row_witness_variable_count: ROW_CODE_WHIR_PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
            row_code_log_inverse_rate: ROW_CODE_WHIR_LOG_INVERSE_RATE,
            table_variable_count: ROW_CODE_WHIR_TABLE_VARIABLE_COUNT,
            polynomial_commitment_variable_count:
                ROW_CODE_WHIR_POLYNOMIAL_COMMITMENT_VARIABLE_COUNT,
            starting_log_inverse_rate: ROW_CODE_WHIR_LOG_INVERSE_RATE,
            folding_factor: ROW_CODE_WHIR_FOLDING_FACTOR,
            soundness_assumption: RowCodeWhirSoundnessAssumption::UniqueDecoding,
            security_level: ROW_CODE_WHIR_SECURITY_LEVEL,
            proof_of_work_bits: ROW_CODE_WHIR_PROOF_OF_WORK_BITS,
            outer_query_count: ROW_CODE_WHIR_OUTER_QUERY_COUNT,
            direct_bound_query_count: ROW_CODE_WHIR_DIRECT_BOUND_QUERY_COUNT,
            verified_vss_bound_query_count: ROW_CODE_WHIR_VERIFIED_VSS_BOUND_QUERY_COUNT,
            maximum_fiat_shamir_candidate_draws_per_output:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        }
    }

    #[cfg(test)]
    fn for_checked_fixture(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        Self::for_checked_fixture_geometry(
            variant.evaluation_domain_size(),
            context.phase_column_query_coordinate_count,
        )
    }

    #[cfg(test)]
    fn for_checked_fixture_geometry(
        evaluation_domain_size: u64,
        phase_column_query_coordinate_count: u32,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        let evaluation_domain_size = usize::try_from(evaluation_domain_size)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let row_encoding_expansion_factor = ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
            .checked_mul(2)
            .and_then(|factor| factor.checked_shl(ROW_CODE_WHIR_LOG_INVERSE_RATE as u32))
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        let logical_polynomial_coefficient_count = evaluation_domain_size
            .checked_div(row_encoding_expansion_factor)
            .filter(|coefficient_count| {
                *coefficient_count > 0
                    && coefficient_count.is_power_of_two()
                    && coefficient_count
                        .checked_mul(row_encoding_expansion_factor)
                        .is_some_and(|encoded_count| encoded_count == evaluation_domain_size)
            })
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        let witness_values_per_row = logical_polynomial_coefficient_count
            .checked_mul(ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        let padded_coefficient_count = witness_values_per_row
            .checked_mul(2)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        let physical_row_witness_variable_count =
            usize::try_from(witness_values_per_row.ilog2())
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let table_variable_count = usize::try_from(padded_coefficient_count.ilog2())
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let polynomial_commitment_variable_count = usize::try_from(evaluation_domain_size.ilog2())
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let outer_query_count = usize::try_from(phase_column_query_coordinate_count)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let direct_bound_query_count =
            outer_query_count.min(ROW_CODE_WHIR_DIRECT_BOUND_QUERY_COUNT);
        let verified_vss_bound_query_count =
            direct_bound_query_count.min(ROW_CODE_WHIR_VERIFIED_VSS_BOUND_QUERY_COUNT);
        Ok(Self {
            logical_polynomial_coefficient_count,
            logical_polynomials_per_physical_row:
                ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW,
            physical_row_witness_variable_count,
            row_code_log_inverse_rate: ROW_CODE_WHIR_LOG_INVERSE_RATE,
            table_variable_count,
            polynomial_commitment_variable_count,
            starting_log_inverse_rate: ROW_CODE_WHIR_LOG_INVERSE_RATE,
            folding_factor: ROW_CODE_WHIR_FOLDING_FACTOR,
            soundness_assumption: RowCodeWhirSoundnessAssumption::UniqueDecoding,
            security_level: ROW_CODE_WHIR_SECURITY_LEVEL,
            proof_of_work_bits: ROW_CODE_WHIR_PROOF_OF_WORK_BITS,
            outer_query_count,
            direct_bound_query_count,
            verified_vss_bound_query_count,
            maximum_fiat_shamir_candidate_draws_per_output:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RowCodeWhirRelationColumnChunk {
    pub(super) column_ordinal: u32,
    pub(super) coefficient_chunk_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowCodeWhirTracePhaseRow {
    pub(super) column_group_ordinal: u32,
    pub(super) coefficient_chunk_ordinal: u32,
    pub(super) logical_polynomial_chunks: [Option<RowCodeWhirRelationColumnChunk>;
        ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW],
    pub(super) opening_point_ordinals: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowCodeWhirTracePhasePlan {
    pub(super) tree_role: ProofTreeRole,
    pub(super) rows: Vec<RowCodeWhirTracePhaseRow>,
    pub(super) geometry: RowEncodingGeometry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RowCodeWhirOpenedPolynomialSource {
    QuotientComponent { component_ordinal: u32 },
    OpeningBatchMask { mask_ordinal: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RowCodeWhirOpenedPolynomialChunk {
    pub(super) source: RowCodeWhirOpenedPolynomialSource,
    pub(super) coefficient_chunk_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowCodeWhirQuotientPhaseRow {
    pub(super) source_class: RelationOpeningSourceClass,
    pub(super) source_group_ordinal: u32,
    pub(super) coefficient_chunk_group_start_ordinal: u32,
    pub(super) extension_coordinate_ordinal: u16,
    pub(super) logical_polynomial_chunks: [Option<RowCodeWhirOpenedPolynomialChunk>;
        ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW],
    pub(super) opening_point_ordinals: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowCodeWhirQuotientPhasePlan {
    pub(super) quotient_component_count: u32,
    pub(super) quotient_component_degree_bound_exclusive: u64,
    pub(super) opening_batch_mask_degree_bound_exclusive: Option<u64>,
    pub(super) rows: Vec<RowCodeWhirQuotientPhaseRow>,
    pub(super) geometry: RowEncodingGeometry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RowCodeWhirBoundLowDegreeMode {
    /// Static construction requirement. The verifier must still resolve the
    /// opaque positively verified VSS capability before using this query class.
    PriorVssProofRequired,
    Direct,
}

impl RowCodeWhirBoundLowDegreeMode {
    const fn query_count(self, parameters: RowCodeWhirSelectedParameters) -> usize {
        match self {
            Self::PriorVssProofRequired => parameters.verified_vss_bound_query_count,
            Self::Direct => parameters.direct_bound_query_count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowCodeWhirBoundColumnPlan {
    pub(super) column_ordinal: u32,
    pub(super) value_type: RelationColumnValueType,
    pub(super) source_degree_bound_exclusive: u64,
    pub(super) opening_point_ordinals: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowCodeWhirBoundTreePlan {
    pub(super) relation_tree_ordinal: u32,
    pub(super) bound_tree_ordinal: u32,
    pub(super) construction_kind: BoundTreeConstructionKind,
    pub(super) expected_root_source_ordinal: u32,
    pub(super) root_use: BoundTreeRootUse,
    pub(super) ordered_columns: Vec<RowCodeWhirBoundColumnPlan>,
    pub(super) source_trace_domain_size: u64,
    pub(super) evaluation_domain_size: u64,
    pub(super) leaf_count: usize,
    pub(super) low_degree_mode: RowCodeWhirBoundLowDegreeMode,
    pub(super) query_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowCodeWhirBoundReductionBlockPlan {
    pub(super) low_degree_mode: RowCodeWhirBoundLowDegreeMode,
    pub(super) ordered_bound_tree_ordinals: Vec<u32>,
    pub(super) maximum_source_degree_bound_exclusive: u64,
    pub(super) quotient_degree_bound_exclusive: u64,
    pub(super) polynomial_variable_count: usize,
    pub(super) selector_prefix: Vec<u8>,
    pub(super) degree_suffix_prefixes: Vec<Vec<u8>>,
    pub(super) query_count: usize,
}

#[cfg(test)]
impl RowCodeWhirBoundReductionBlockPlan {
    pub(super) const fn degree_test_count(&self) -> usize {
        1 + self.degree_suffix_prefixes.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RowCodeWhirAggregateColumnRole {
    OpeningPoint { opening_point_ordinal: u32 },
    BoundReduction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirConstructionPlan {
    pub(super) application_statement_schema_identifier: u16,
    pub(super) schedule_position: Option<u32>,
    pub(super) top_count: Option<u16>,
    pub(super) relation_plan_hash: [u8; 64],
    pub(super) relation_plan_variant_hash: [u8; 64],
    pub(super) trace_domain_size: u64,
    pub(super) evaluation_domain_size: u64,
    pub(super) opening_degree_bound_exclusive: u64,
    pub(super) proof_privacy_mode: ProofPrivacyMode,
    pub(super) requested_source_column_ordinals: Vec<u32>,
    pub(super) base_phase: Option<RowCodeWhirTracePhasePlan>,
    pub(super) auxiliary_phase: Option<RowCodeWhirTracePhasePlan>,
    pub(super) quotient_phase: RowCodeWhirQuotientPhasePlan,
    pub(super) bound_trees: Vec<RowCodeWhirBoundTreePlan>,
    pub(super) bound_reduction_blocks: Vec<RowCodeWhirBoundReductionBlockPlan>,
    pub(super) aggregate_column_roles: Vec<RowCodeWhirAggregateColumnRole>,
    pub(super) parameters: RowCodeWhirSelectedParameters,
}

impl RowCodeWhirConstructionPlan {
    pub(in crate::bgv::proof_suite) fn for_selected_variant(
        artifact: &ValidatedRelationPlanArtifact,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        let application_statement_schema_identifier =
            artifact.application_statement_schema_identifier();
        let context = selected_relation_plan_check_context(application_statement_schema_identifier)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidSelectedProfile)?;
        if artifact.checked_context() != &context {
            return Err(RowCodeWhirConstructionPlanError::InvalidSelectedProfile);
        }
        Self::for_context_variant(
            artifact,
            &context,
            schedule_position,
            top_count,
            RowCodeWhirSelectedParameters::selected(),
            selected_bound_root_source_trace_domain_size,
        )
    }

    #[cfg(test)]
    pub(in crate::bgv::proof_suite) fn for_checked_fixture_variant(
        artifact: &ValidatedRelationPlanArtifact,
        context: &RelationPlanCheckContext,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        if artifact.checked_context() != context {
            return Err(RowCodeWhirConstructionPlanError::InvalidSelectedProfile);
        }
        let variant = artifact
            .compiled_plan()
            .select_variant(schedule_position, top_count)?;
        let parameters = RowCodeWhirSelectedParameters::for_checked_fixture(variant, context)?;
        Self::for_context_variant(
            artifact,
            context,
            schedule_position,
            top_count,
            parameters,
            checked_fixture_bound_root_source_trace_domain_size,
        )
    }

    fn for_context_variant(
        artifact: &ValidatedRelationPlanArtifact,
        context: &RelationPlanCheckContext,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        parameters: RowCodeWhirSelectedParameters,
        bound_root_source_trace_domain_size: BoundRootSourceTraceDomainSizeResolver,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        let application_statement_schema_identifier =
            artifact.application_statement_schema_identifier();
        let compiled_plan = artifact.compiled_plan();
        if compiled_plan.application_statement_schema_identifier()
            != application_statement_schema_identifier
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidSelectedProfile);
        }
        let variant = compiled_plan.select_variant(schedule_position, top_count)?;
        if variant.schedule_position() != schedule_position || variant.top_count() != top_count {
            return Err(RowCodeWhirConstructionPlanError::InvalidSelectedProfile);
        }

        validate_domain_geometry(variant, context, parameters)?;
        let tree_column_opening_patterns = tree_column_opening_patterns(variant)?;
        let base_phase = trace_phase_plan(
            variant,
            &tree_column_opening_patterns,
            ProofTreeRole::BaseOracle,
            parameters,
        )?;
        let auxiliary_phase = trace_phase_plan(
            variant,
            &tree_column_opening_patterns,
            ProofTreeRole::AuxiliaryOracle,
            parameters,
        )?;
        let quotient_phase = quotient_phase_plan(variant, context, parameters)?;
        let bound_trees = bound_tree_plans(
            application_statement_schema_identifier,
            variant,
            &tree_column_opening_patterns,
            parameters,
            bound_root_source_trace_domain_size,
        )?;
        let bound_reduction_blocks = bound_reduction_block_plans(&bound_trees, parameters)?;

        let mut aggregate_column_roles = Vec::with_capacity(
            variant
                .ordered_opening_points()
                .len()
                .checked_add(usize::from(!bound_reduction_blocks.is_empty()))
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?,
        );
        for opening_point_index in 0..variant.ordered_opening_points().len() {
            aggregate_column_roles.push(RowCodeWhirAggregateColumnRole::OpeningPoint {
                opening_point_ordinal: u32::try_from(opening_point_index)
                    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            });
        }
        if !bound_reduction_blocks.is_empty() {
            aggregate_column_roles.push(RowCodeWhirAggregateColumnRole::BoundReduction);
        }

        Ok(Self {
            application_statement_schema_identifier,
            schedule_position,
            top_count,
            relation_plan_hash: artifact.canonical_plan_hash(),
            relation_plan_variant_hash: variant.canonical_hash()?,
            trace_domain_size: variant.trace_domain_size(),
            evaluation_domain_size: variant.evaluation_domain_size(),
            opening_degree_bound_exclusive: variant.opening_degree_bound_exclusive(),
            proof_privacy_mode: variant.proof_privacy_mode(),
            requested_source_column_ordinals: requested_pre_challenge_source_column_ordinals(
                variant,
            )?,
            base_phase,
            auxiliary_phase,
            quotient_phase,
            bound_trees,
            bound_reduction_blocks,
            aggregate_column_roles,
            parameters,
        })
    }

    pub(in crate::bgv::proof_suite) fn canonical_identity_bytes(
        &self,
    ) -> Result<Vec<u8>, RowCodeWhirConstructionPlanError> {
        let mut encoder = RowCodeWhirConstructionPlanIdentityEncoder::default();
        encoder.push_u16(ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_ENCODING_VERSION);
        encoder.push_u16(self.application_statement_schema_identifier);
        encoder.push_optional_u32(self.schedule_position);
        encoder.push_optional_u16(self.top_count);
        encoder.push_bytes(&self.relation_plan_hash)?;
        encoder.push_bytes(&self.relation_plan_variant_hash)?;
        encoder.push_u64(self.trace_domain_size);
        encoder.push_u64(self.evaluation_domain_size);
        encoder.push_u64(self.opening_degree_bound_exclusive);
        encoder.push_u16(self.proof_privacy_mode as u16);

        encoder.push_length(self.requested_source_column_ordinals.len())?;
        for column_ordinal in &self.requested_source_column_ordinals {
            encoder.push_u32(*column_ordinal);
        }

        encode_optional_trace_phase(&mut encoder, self.base_phase.as_ref())?;
        encode_optional_trace_phase(&mut encoder, self.auxiliary_phase.as_ref())?;
        encode_quotient_phase(&mut encoder, &self.quotient_phase)?;

        encoder.push_length(self.bound_trees.len())?;
        for bound_tree in &self.bound_trees {
            encode_bound_tree(&mut encoder, bound_tree)?;
        }

        encoder.push_length(self.bound_reduction_blocks.len())?;
        for reduction_block in &self.bound_reduction_blocks {
            encode_bound_reduction_block(&mut encoder, reduction_block)?;
        }

        encoder.push_length(self.aggregate_column_roles.len())?;
        for role in &self.aggregate_column_roles {
            match role {
                RowCodeWhirAggregateColumnRole::OpeningPoint {
                    opening_point_ordinal,
                } => {
                    encoder.push_u16(1);
                    encoder.push_u32(*opening_point_ordinal);
                }
                RowCodeWhirAggregateColumnRole::BoundReduction => encoder.push_u16(2),
            }
        }

        encode_selected_parameters(&mut encoder, self.parameters)?;
        Ok(encoder.finish())
    }

    pub(in crate::bgv::proof_suite) const fn relation_plan_hash(&self) -> [u8; 64] {
        self.relation_plan_hash
    }

    pub(in crate::bgv::proof_suite) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    #[cfg(test)]
    pub(in crate::bgv::proof_suite) const fn selected_parameters(
        &self,
    ) -> RowCodeWhirSelectedParameters {
        self.parameters
    }

    pub(in crate::bgv::proof_suite) fn canonical_identity_hash(
        &self,
    ) -> Result<[u8; 64], RowCodeWhirConstructionPlanError> {
        let canonical_bytes = self.canonical_identity_bytes()?;
        Ok(hash_framed_parts_512(
            ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_HASH_DOMAIN,
            &[&canonical_bytes],
        ))
    }
}

#[derive(Default)]
struct RowCodeWhirConstructionPlanIdentityEncoder {
    bytes: Vec<u8>,
}

impl RowCodeWhirConstructionPlanIdentityEncoder {
    fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn push_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_usize(&mut self, value: usize) -> Result<(), RowCodeWhirConstructionPlanError> {
        self.push_u64(
            u64::try_from(value).map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        );
        Ok(())
    }

    fn push_length(&mut self, length: usize) -> Result<(), RowCodeWhirConstructionPlanError> {
        self.push_usize(length)
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> Result<(), RowCodeWhirConstructionPlanError> {
        self.push_length(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn push_optional_u16(&mut self, value: Option<u16>) {
        match value {
            Some(value) => {
                self.push_u8(1);
                self.push_u16(value);
            }
            None => self.push_u8(0),
        }
    }

    fn push_optional_u32(&mut self, value: Option<u32>) {
        match value {
            Some(value) => {
                self.push_u8(1);
                self.push_u32(value);
            }
            None => self.push_u8(0),
        }
    }

    fn push_optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.push_u8(1);
                self.push_u64(value);
            }
            None => self.push_u8(0),
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn encode_optional_trace_phase(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    phase: Option<&RowCodeWhirTracePhasePlan>,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let Some(phase) = phase else {
        encoder.push_u8(0);
        return Ok(());
    };
    encoder.push_u8(1);
    encoder.push_u16(phase.tree_role as u16);
    encoder.push_length(phase.rows.len())?;
    for row in &phase.rows {
        encoder.push_u32(row.column_group_ordinal);
        encoder.push_u32(row.coefficient_chunk_ordinal);
        encoder.push_length(row.logical_polynomial_chunks.len())?;
        for chunk in &row.logical_polynomial_chunks {
            match chunk {
                Some(chunk) => {
                    encoder.push_u8(1);
                    encoder.push_u32(chunk.column_ordinal);
                    encoder.push_u32(chunk.coefficient_chunk_ordinal);
                }
                None => encoder.push_u8(0),
            }
        }
        encode_u32_sequence(encoder, &row.opening_point_ordinals)?;
    }
    encode_row_geometry(encoder, phase.geometry)
}

fn encode_quotient_phase(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    phase: &RowCodeWhirQuotientPhasePlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_u32(phase.quotient_component_count);
    encoder.push_u64(phase.quotient_component_degree_bound_exclusive);
    encoder.push_optional_u64(phase.opening_batch_mask_degree_bound_exclusive);
    encoder.push_length(phase.rows.len())?;
    for row in &phase.rows {
        encoder.push_u16(row.source_class as u16);
        encoder.push_u32(row.source_group_ordinal);
        encoder.push_u32(row.coefficient_chunk_group_start_ordinal);
        encoder.push_u16(row.extension_coordinate_ordinal);
        encoder.push_length(row.logical_polynomial_chunks.len())?;
        for chunk in &row.logical_polynomial_chunks {
            match chunk {
                Some(chunk) => {
                    encoder.push_u8(1);
                    match chunk.source {
                        RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                            component_ordinal,
                        } => {
                            encoder.push_u16(1);
                            encoder.push_u32(component_ordinal);
                        }
                        RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { mask_ordinal } => {
                            encoder.push_u16(2);
                            encoder.push_u32(mask_ordinal);
                        }
                    }
                    encoder.push_u32(chunk.coefficient_chunk_ordinal);
                }
                None => encoder.push_u8(0),
            }
        }
        encode_u32_sequence(encoder, &row.opening_point_ordinals)?;
    }
    encode_row_geometry(encoder, phase.geometry)
}

fn encode_bound_tree(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    tree: &RowCodeWhirBoundTreePlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_u32(tree.relation_tree_ordinal);
    encoder.push_u32(tree.bound_tree_ordinal);
    encoder.push_u16(tree.construction_kind as u16);
    encoder.push_u32(tree.expected_root_source_ordinal);
    encoder.push_u16(tree.root_use as u16);
    encoder.push_length(tree.ordered_columns.len())?;
    for column in &tree.ordered_columns {
        encoder.push_u32(column.column_ordinal);
        encoder.push_u16(column.value_type as u16);
        encoder.push_u64(column.source_degree_bound_exclusive);
        encode_u32_sequence(encoder, &column.opening_point_ordinals)?;
    }
    encoder.push_u64(tree.source_trace_domain_size);
    encoder.push_u64(tree.evaluation_domain_size);
    encoder.push_usize(tree.leaf_count)?;
    encode_bound_low_degree_mode(encoder, tree.low_degree_mode);
    encoder.push_usize(tree.query_count)
}

fn encode_bound_reduction_block(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    block: &RowCodeWhirBoundReductionBlockPlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encode_bound_low_degree_mode(encoder, block.low_degree_mode);
    encode_u32_sequence(encoder, &block.ordered_bound_tree_ordinals)?;
    encoder.push_u64(block.maximum_source_degree_bound_exclusive);
    encoder.push_u64(block.quotient_degree_bound_exclusive);
    encoder.push_usize(block.polynomial_variable_count)?;
    encoder.push_bytes(&block.selector_prefix)?;
    encoder.push_length(block.degree_suffix_prefixes.len())?;
    for prefix in &block.degree_suffix_prefixes {
        encoder.push_bytes(prefix)?;
    }
    encoder.push_usize(block.query_count)
}

fn encode_bound_low_degree_mode(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    mode: RowCodeWhirBoundLowDegreeMode,
) {
    encoder.push_u16(match mode {
        RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired => 1,
        RowCodeWhirBoundLowDegreeMode::Direct => 2,
    });
}

fn encode_u32_sequence(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    values: &[u32],
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_length(values.len())?;
    for value in values {
        encoder.push_u32(*value);
    }
    Ok(())
}

fn encode_row_geometry(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    geometry: RowEncodingGeometry,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_usize(geometry.row_count)?;
    encoder.push_usize(geometry.witness_values_per_row)?;
    encoder.push_usize(geometry.padded_coefficient_count)?;
    encoder.push_usize(geometry.encoded_column_count)
}

fn encode_selected_parameters(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_usize(parameters.logical_polynomial_coefficient_count)?;
    encoder.push_usize(parameters.logical_polynomials_per_physical_row)?;
    encoder.push_usize(parameters.physical_row_witness_variable_count)?;
    encoder.push_usize(parameters.row_code_log_inverse_rate)?;
    encoder.push_usize(parameters.table_variable_count)?;
    encoder.push_usize(parameters.polynomial_commitment_variable_count)?;
    encoder.push_usize(parameters.starting_log_inverse_rate)?;
    encoder.push_usize(parameters.folding_factor)?;
    encoder.push_u16(match parameters.soundness_assumption {
        RowCodeWhirSoundnessAssumption::UniqueDecoding => 1,
    });
    encoder.push_usize(parameters.security_level)?;
    encoder.push_usize(parameters.proof_of_work_bits)?;
    encoder.push_usize(parameters.outer_query_count)?;
    encoder.push_usize(parameters.direct_bound_query_count)?;
    encoder.push_usize(parameters.verified_vss_bound_query_count)?;
    encoder.push_u32(parameters.maximum_fiat_shamir_candidate_draws_per_output);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelationTreeColumnOwner {
    ProofCreated(ProofTreeRole),
    BoundPublic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RelationTreeColumnOpeningPattern {
    relation_tree_ordinal: u32,
    owner: RelationTreeColumnOwner,
    opening_point_ordinals: Vec<u32>,
}

fn validate_domain_geometry(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    validate_domain_geometry_values(
        variant.evaluation_domain_size(),
        variant.opening_degree_bound_exclusive(),
        context,
        parameters,
    )
}

fn validate_domain_geometry_values(
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    context: &RelationPlanCheckContext,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let evaluation_domain_size = usize::try_from(evaluation_domain_size)
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    let evaluation_domain =
        ProofEvaluationDomain::new(evaluation_domain_size, context.evaluation_coset_offset)
            .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    let encoded_column_capacity = 1_usize
        .checked_shl(
            u32::try_from(parameters.polynomial_commitment_variable_count)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        )
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    let padded_coefficient_capacity = 1_usize
        .checked_shl(
            u32::try_from(parameters.table_variable_count)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        )
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    let logical_row_capacity = parameters
        .logical_polynomial_coefficient_count
        .checked_mul(parameters.logical_polynomials_per_physical_row)
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    let logical_row_capacity_u64 = u64::try_from(logical_row_capacity)
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    let preceding_logical_row_capacity_u64 = parameters
        .logical_polynomial_coefficient_count
        .checked_div(2)
        .and_then(|coefficient_count| {
            coefficient_count.checked_mul(parameters.logical_polynomials_per_physical_row)
        })
        .and_then(|capacity| u64::try_from(capacity).ok())
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    let expected_direct_bound_query_count = parameters
        .outer_query_count
        .min(ROW_CODE_WHIR_DIRECT_BOUND_QUERY_COUNT);
    let expected_verified_vss_bound_query_count =
        expected_direct_bound_query_count.min(ROW_CODE_WHIR_VERIFIED_VSS_BOUND_QUERY_COUNT);
    let maximum_distinct_leaf_query_count = evaluation_domain_size
        .checked_div(2)
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    if context.base_field_modulus != PROOF_BASE_FIELD_MODULUS
        || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
        || !evaluation_domain_size.is_power_of_two()
        || evaluation_domain_size != encoded_column_capacity
        || parameters.logical_polynomial_coefficient_count == 0
        || !parameters
            .logical_polynomial_coefficient_count
            .is_power_of_two()
        || parameters.logical_polynomials_per_physical_row
            != ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
        || opening_degree_bound_exclusive == 0
        || opening_degree_bound_exclusive > logical_row_capacity_u64
        || opening_degree_bound_exclusive <= preceding_logical_row_capacity_u64
        || context.challenge_extension_degree != 5
        || context.out_of_domain_point_count != 1
        || context.quotient_component_count == 0
        || context.quotient_component_degree_bound_exclusive == 0
        || usize::try_from(context.phase_column_query_coordinate_count).ok()
            != Some(parameters.outer_query_count)
        || parameters.outer_query_count == 0
        || parameters.outer_query_count > maximum_distinct_leaf_query_count
        || parameters.direct_bound_query_count != expected_direct_bound_query_count
        || parameters.verified_vss_bound_query_count != expected_verified_vss_bound_query_count
        || parameters.direct_bound_query_count > maximum_distinct_leaf_query_count
        || parameters.verified_vss_bound_query_count > parameters.direct_bound_query_count
        || parameters.row_code_log_inverse_rate != ROW_CODE_WHIR_LOG_INVERSE_RATE
        || parameters.starting_log_inverse_rate != parameters.row_code_log_inverse_rate
        || parameters.folding_factor != ROW_CODE_WHIR_FOLDING_FACTOR
        || parameters.soundness_assumption != RowCodeWhirSoundnessAssumption::UniqueDecoding
        || parameters.security_level != ROW_CODE_WHIR_SECURITY_LEVEL
        || parameters.proof_of_work_bits != ROW_CODE_WHIR_PROOF_OF_WORK_BITS
        || parameters.maximum_fiat_shamir_candidate_draws_per_output
            != PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
        || parameters
            .table_variable_count
            .checked_add(parameters.row_code_log_inverse_rate)
            != Some(parameters.polynomial_commitment_variable_count)
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let row_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
        1,
        parameters.physical_row_witness_variable_count,
        parameters.row_code_log_inverse_rate,
    )
    .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    if row_geometry.witness_values_per_row != logical_row_capacity
        || row_geometry.padded_coefficient_count != padded_coefficient_capacity
        || row_geometry.encoded_column_count != evaluation_domain_size
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(())
}

fn proof_tree_role(role: u16) -> Result<ProofTreeRole, RowCodeWhirConstructionPlanError> {
    match role {
        value if value == ProofTreeRole::BaseOracle as u16 => Ok(ProofTreeRole::BaseOracle),
        value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
            Ok(ProofTreeRole::AuxiliaryOracle)
        }
        _ => Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry),
    }
}

fn tree_column_opening_patterns(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, RelationTreeColumnOpeningPattern>, RowCodeWhirConstructionPlanError> {
    let mut patterns = BTreeMap::<u32, RelationTreeColumnOpeningPattern>::new();
    for (tree_index, tree) in variant.ordered_trees().iter().enumerate() {
        let relation_tree_ordinal = u32::try_from(tree_index)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let owner = match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role: proof_tree_role_code,
                ..
            } => RelationTreeColumnOwner::ProofCreated(proof_tree_role(*proof_tree_role_code)?),
            RelationTreeDescriptor::BoundPublic { .. } => RelationTreeColumnOwner::BoundPublic,
        };
        if tree.ordered_column_ordinals().is_empty() {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        for column_ordinal in tree.ordered_column_ordinals().iter().copied() {
            let column_index = usize::try_from(column_ordinal)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            let descriptor = variant
                .ordered_columns()
                .get(column_index)
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
            if descriptor.value_type() != RelationColumnValueType::BaseField {
                return Err(RowCodeWhirConstructionPlanError::UnsupportedColumnValueType);
            }
            match (owner, descriptor.origin()) {
                (RelationTreeColumnOwner::BoundPublic, RelationColumnOrigin::BoundTree { .. }) => {}
                (RelationTreeColumnOwner::ProofCreated(_), RelationColumnOrigin::Prover) => {}
                (RelationTreeColumnOwner::ProofCreated(_), _)
                | (RelationTreeColumnOwner::BoundPublic, _) => {
                    return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
                }
            }
            if patterns
                .insert(
                    column_ordinal,
                    RelationTreeColumnOpeningPattern {
                        relation_tree_ordinal,
                        owner,
                        opening_point_ordinals: Vec::new(),
                    },
                )
                .is_some()
            {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
        }
    }

    for claim in variant.ordered_opening_claims() {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_ordinal = claim
            .column_ordinal()
            .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
        let pattern = patterns
            .get_mut(&column_ordinal)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
        let column_index = usize::try_from(column_ordinal)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
        if claim.source_ordinal() != pattern.relation_tree_ordinal
            || claim.source_degree_bound_exclusive() != column.source_degree_bound_exclusive()
            || usize::try_from(claim.opening_point_ordinal())
                .ok()
                .filter(|point_index| *point_index < variant.ordered_opening_points().len())
                .is_none()
            || pattern
                .opening_point_ordinals
                .contains(&claim.opening_point_ordinal())
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
        }
        pattern
            .opening_point_ordinals
            .push(claim.opening_point_ordinal());
    }
    for pattern in patterns.values_mut() {
        if pattern.opening_point_ordinals.is_empty() {
            return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
        }
        pattern.opening_point_ordinals.sort_unstable();
    }
    Ok(patterns)
}

fn coefficient_chunk_count(
    degree_bound_exclusive: u64,
    logical_polynomial_coefficient_count: usize,
) -> Result<usize, RowCodeWhirConstructionPlanError> {
    if degree_bound_exclusive == 0
        || logical_polynomial_coefficient_count == 0
        || !logical_polynomial_coefficient_count.is_power_of_two()
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let chunk_size = u64::try_from(logical_polynomial_coefficient_count)
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    let count = degree_bound_exclusive
        .checked_add(chunk_size - 1)
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?
        / chunk_size;
    usize::try_from(count).map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)
}

fn trace_phase_plan(
    variant: &RelationPlanVariant,
    patterns: &BTreeMap<u32, RelationTreeColumnOpeningPattern>,
    tree_role: ProofTreeRole,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<Option<RowCodeWhirTracePhasePlan>, RowCodeWhirConstructionPlanError> {
    let mut columns_by_opening_pattern_and_chunk_count =
        BTreeMap::<(Vec<u32>, usize), Vec<u32>>::new();
    for (column_ordinal, pattern) in patterns {
        if pattern.owner != RelationTreeColumnOwner::ProofCreated(tree_role) {
            continue;
        }
        let column_index = usize::try_from(*column_ordinal)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        let chunk_count = coefficient_chunk_count(
            column.source_degree_bound_exclusive(),
            parameters.logical_polynomial_coefficient_count,
        )?;
        columns_by_opening_pattern_and_chunk_count
            .entry((pattern.opening_point_ordinals.clone(), chunk_count))
            .or_default()
            .push(*column_ordinal);
    }
    if columns_by_opening_pattern_and_chunk_count.is_empty() {
        return Ok(None);
    }

    let mut rows = Vec::new();
    let mut next_column_group_ordinal = 0_u32;
    for ((opening_point_ordinals, coefficient_chunk_count), column_ordinals) in
        columns_by_opening_pattern_and_chunk_count
    {
        for column_group in
            column_ordinals.chunks(ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
        {
            let column_group_ordinal = next_column_group_ordinal;
            next_column_group_ordinal = next_column_group_ordinal
                .checked_add(1)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
            for chunk_index in 0..coefficient_chunk_count {
                let coefficient_chunk_ordinal = u32::try_from(chunk_index)
                    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
                let mut row_chunks = [None; ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW];
                for (row_position, column_ordinal) in column_group.iter().copied().enumerate() {
                    row_chunks[row_position] = Some(RowCodeWhirRelationColumnChunk {
                        column_ordinal,
                        coefficient_chunk_ordinal,
                    });
                }
                rows.push(RowCodeWhirTracePhaseRow {
                    column_group_ordinal,
                    coefficient_chunk_ordinal,
                    logical_polynomial_chunks: row_chunks,
                    opening_point_ordinals: opening_point_ordinals.clone(),
                });
            }
        }
    }
    let geometry = row_geometry(rows.len(), parameters)?;
    Ok(Some(RowCodeWhirTracePhasePlan {
        tree_role,
        rows,
        geometry,
    }))
}

fn quotient_phase_plan(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<RowCodeWhirQuotientPhasePlan, RowCodeWhirConstructionPlanError> {
    let mut quotient_points_by_component = (0..context.quotient_component_count)
        .map(|component_ordinal| (component_ordinal, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut batch_mask_opening_points = BTreeSet::new();
    for claim in variant.ordered_opening_claims() {
        match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => continue,
            RelationOpeningSourceClass::Quotient => {
                if claim.column_ordinal().is_some()
                    || claim.source_degree_bound_exclusive()
                        != context.quotient_component_degree_bound_exclusive
                    || usize::try_from(claim.opening_point_ordinal())
                        .ok()
                        .filter(|point_index| *point_index < variant.ordered_opening_points().len())
                        .is_none()
                {
                    return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
                }
                let points = quotient_points_by_component
                    .get_mut(&claim.source_ordinal())
                    .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
                if !points.insert(claim.opening_point_ordinal()) {
                    return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
                }
            }
            RelationOpeningSourceClass::BatchMask => {
                if claim.column_ordinal().is_some()
                    || claim.source_ordinal() != 0
                    || usize::try_from(claim.opening_point_ordinal())
                        .ok()
                        .filter(|point_index| *point_index < variant.ordered_opening_points().len())
                        .is_none()
                    || !batch_mask_opening_points.insert(claim.opening_point_ordinal())
                {
                    return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
                }
            }
        }
    }
    if quotient_points_by_component
        .values()
        .any(|opening_points| opening_points.is_empty())
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
    }

    let mut components_by_opening_pattern = BTreeMap::<Vec<u32>, Vec<u32>>::new();
    for (component_ordinal, opening_points) in quotient_points_by_component {
        components_by_opening_pattern
            .entry(opening_points.into_iter().collect())
            .or_default()
            .push(component_ordinal);
    }

    let quotient_chunk_count = coefficient_chunk_count(
        context.quotient_component_degree_bound_exclusive,
        parameters.logical_polynomial_coefficient_count,
    )?;
    let mut rows = Vec::new();
    let mut next_quotient_component_group_ordinal = 0_u32;
    for (opening_point_ordinals, component_ordinals) in &components_by_opening_pattern {
        let component_groups = component_ordinals
            .chunks(ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
            .collect::<Vec<_>>();
        for chunk_index in 0..quotient_chunk_count {
            let coefficient_chunk_ordinal = u32::try_from(chunk_index)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            for (component_group_index, component_group) in component_groups.iter().enumerate() {
                let source_group_ordinal = next_quotient_component_group_ordinal
                    .checked_add(
                        u32::try_from(component_group_index)
                            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                    )
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
                for extension_coordinate_ordinal in 0..context.challenge_extension_degree {
                    let mut row_chunks = [None; ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW];
                    for (row_position, component_ordinal) in
                        component_group.iter().copied().enumerate()
                    {
                        row_chunks[row_position] = Some(RowCodeWhirOpenedPolynomialChunk {
                            source: RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                                component_ordinal,
                            },
                            coefficient_chunk_ordinal,
                        });
                    }
                    rows.push(RowCodeWhirQuotientPhaseRow {
                        source_class: RelationOpeningSourceClass::Quotient,
                        source_group_ordinal,
                        coefficient_chunk_group_start_ordinal: coefficient_chunk_ordinal,
                        extension_coordinate_ordinal,
                        logical_polynomial_chunks: row_chunks,
                        opening_point_ordinals: opening_point_ordinals.clone(),
                    });
                }
            }
        }
        next_quotient_component_group_ordinal = next_quotient_component_group_ordinal
            .checked_add(
                u32::try_from(component_groups.len())
                    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            )
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    }

    let opening_batch_masks = variant
        .ordered_masks()
        .iter()
        .copied()
        .filter(|mask| mask.mask_kind() == RelationMaskKind::OpeningBatch)
        .collect::<Vec<_>>();
    let opening_batch_mask_degree_bound_exclusive = match variant.proof_privacy_mode() {
        ProofPrivacyMode::PublicOnly => {
            if !opening_batch_masks.is_empty() || !batch_mask_opening_points.is_empty() {
                return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
            }
            None
        }
        ProofPrivacyMode::SecretBearing => {
            let [mask] = opening_batch_masks.as_slice() else {
                return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
            };
            if mask.target_class() != RelationMaskTargetClass::Batch
                || mask.target_ordinal() != 0
                || batch_mask_opening_points.is_empty()
                || variant.ordered_opening_claims().iter().any(|claim| {
                    claim.source_class() == RelationOpeningSourceClass::BatchMask
                        && claim.source_degree_bound_exclusive()
                            != mask.mask_degree_bound_exclusive()
                })
            {
                return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
            }
            let mask_chunk_count = coefficient_chunk_count(
                mask.mask_degree_bound_exclusive(),
                parameters.logical_polynomial_coefficient_count,
            )?;
            let mask_ordinal = mask.mask_coordinate().mask_ordinal();
            let opening_point_ordinals = batch_mask_opening_points.into_iter().collect::<Vec<_>>();
            for chunk_group_start in
                (0..mask_chunk_count).step_by(ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
            {
                for extension_coordinate_ordinal in 0..context.challenge_extension_degree {
                    let mut row_chunks = [None; ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW];
                    let chunk_group_end = mask_chunk_count.min(
                        chunk_group_start + ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW,
                    );
                    for (row_position, chunk_index) in
                        (chunk_group_start..chunk_group_end).enumerate()
                    {
                        row_chunks[row_position] = Some(RowCodeWhirOpenedPolynomialChunk {
                            source: RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
                                mask_ordinal,
                            },
                            coefficient_chunk_ordinal: u32::try_from(chunk_index)
                                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                        });
                    }
                    rows.push(RowCodeWhirQuotientPhaseRow {
                        source_class: RelationOpeningSourceClass::BatchMask,
                        source_group_ordinal: 0,
                        coefficient_chunk_group_start_ordinal: u32::try_from(chunk_group_start)
                            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                        extension_coordinate_ordinal,
                        logical_polynomial_chunks: row_chunks,
                        opening_point_ordinals: opening_point_ordinals.clone(),
                    });
                }
            }
            Some(mask.mask_degree_bound_exclusive())
        }
    };
    let geometry = row_geometry(rows.len(), parameters)?;
    Ok(RowCodeWhirQuotientPhasePlan {
        quotient_component_count: context.quotient_component_count,
        quotient_component_degree_bound_exclusive: context
            .quotient_component_degree_bound_exclusive,
        opening_batch_mask_degree_bound_exclusive,
        rows,
        geometry,
    })
}

fn bound_tree_plans(
    application_statement_schema_identifier: u16,
    variant: &RelationPlanVariant,
    patterns: &BTreeMap<u32, RelationTreeColumnOpeningPattern>,
    parameters: RowCodeWhirSelectedParameters,
    bound_root_source_trace_domain_size: BoundRootSourceTraceDomainSizeResolver,
) -> Result<Vec<RowCodeWhirBoundTreePlan>, RowCodeWhirConstructionPlanError> {
    let evaluation_domain_size = variant.evaluation_domain_size();
    let leaf_count_u64 = evaluation_domain_size
        .checked_div(2)
        .filter(|leaf_count| leaf_count.is_power_of_two())
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    let leaf_count = usize::try_from(leaf_count_u64)
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    let mut plans = Vec::new();
    for (tree_index, tree) in variant.ordered_trees().iter().enumerate() {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            expected_root_source_ordinal,
            root_use,
            ordered_column_ordinals,
        } = tree
        else {
            continue;
        };
        let relation_tree_ordinal = u32::try_from(tree_index)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let bound_tree_ordinal = u32::try_from(plans.len())
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let source_trace_domain_size = bound_root_source_trace_domain_size(
            application_statement_schema_identifier,
            *construction_kind,
            variant.trace_domain_size(),
            evaluation_domain_size,
        )?;
        let low_degree_mode = selected_bound_low_degree_mode(
            application_statement_schema_identifier,
            *construction_kind,
            *root_use,
        );
        let mut ordered_columns = Vec::with_capacity(ordered_column_ordinals.len());
        for column_ordinal in ordered_column_ordinals.iter().copied() {
            let column_index = usize::try_from(column_ordinal)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            let column = variant
                .ordered_columns()
                .get(column_index)
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
            let RelationColumnOrigin::BoundTree {
                expected_root_source_ordinal: column_root_source_ordinal,
            } = column.origin()
            else {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            };
            let pattern = patterns
                .get(&column_ordinal)
                .filter(|pattern| {
                    pattern.owner == RelationTreeColumnOwner::BoundPublic
                        && pattern.relation_tree_ordinal == relation_tree_ordinal
                })
                .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
            if *column_root_source_ordinal != *expected_root_source_ordinal
                || column.source_degree_bound_exclusive() > variant.opening_degree_bound_exclusive()
            {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
            ordered_columns.push(RowCodeWhirBoundColumnPlan {
                column_ordinal,
                value_type: column.value_type(),
                source_degree_bound_exclusive: column.source_degree_bound_exclusive(),
                opening_point_ordinals: pattern.opening_point_ordinals.clone(),
            });
        }
        plans.push(RowCodeWhirBoundTreePlan {
            relation_tree_ordinal,
            bound_tree_ordinal,
            construction_kind: *construction_kind,
            expected_root_source_ordinal: *expected_root_source_ordinal,
            root_use: *root_use,
            ordered_columns,
            source_trace_domain_size,
            evaluation_domain_size,
            leaf_count,
            low_degree_mode,
            query_count: low_degree_mode.query_count(parameters),
        });
    }
    Ok(plans)
}

fn selected_bound_low_degree_mode(
    application_statement_schema_identifier: u16,
    construction_kind: BoundTreeConstructionKind,
    root_use: BoundTreeRootUse,
) -> RowCodeWhirBoundLowDegreeMode {
    if application_statement_schema_identifier
        == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        && construction_kind == BoundTreeConstructionKind::CommittedMaterial
        && root_use == BoundTreeRootUse::Input
    {
        RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired
    } else {
        RowCodeWhirBoundLowDegreeMode::Direct
    }
}

#[cfg(test)]
fn checked_fixture_bound_root_source_trace_domain_size(
    application_statement_schema_identifier: u16,
    construction_kind: BoundTreeConstructionKind,
    relation_trace_domain_size: u64,
    evaluation_domain_size: u64,
) -> Result<u64, ProofProfileError> {
    let source_trace_domain_size = match construction_kind {
        BoundTreeConstructionKind::SetupPolynomial => relation_trace_domain_size,
        BoundTreeConstructionKind::CommittedMaterial => {
            match application_statement_schema_identifier {
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                    relation_trace_domain_size
                        .checked_div(COMMITTED_MATERIAL_TRACE_PACKING_FACTOR)
                        .filter(|physical_trace_domain_size| {
                            physical_trace_domain_size
                                .checked_mul(COMMITTED_MATERIAL_TRACE_PACKING_FACTOR)
                                .is_some_and(|packed_trace_domain_size| {
                                    packed_trace_domain_size == relation_trace_domain_size
                                })
                        })
                        .ok_or(ProofProfileError::InvalidRelationPlan)?
                }
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
                    relation_trace_domain_size
                }
                _ => return Err(ProofProfileError::InvalidRootTopology),
            }
        }
    };
    if source_trace_domain_size == 0
        || !source_trace_domain_size.is_power_of_two()
        || !evaluation_domain_size.is_power_of_two()
        || !evaluation_domain_size.is_multiple_of(source_trace_domain_size)
    {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    Ok(source_trace_domain_size)
}

fn bound_reduction_block_plans(
    bound_trees: &[RowCodeWhirBoundTreePlan],
    parameters: RowCodeWhirSelectedParameters,
) -> Result<Vec<RowCodeWhirBoundReductionBlockPlan>, RowCodeWhirConstructionPlanError> {
    if bound_trees.is_empty() {
        return Ok(Vec::new());
    }

    let mut tree_ordinals_by_mode_and_degree =
        BTreeMap::<(RowCodeWhirBoundLowDegreeMode, u64), Vec<u32>>::new();
    for tree in bound_trees {
        let exact_source_degree_bound_exclusive = tree
            .ordered_columns
            .first()
            .map(|column| column.source_degree_bound_exclusive)
            .filter(|bound| *bound > 0)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        if tree.ordered_columns.iter().any(|column| {
            column.source_degree_bound_exclusive != exact_source_degree_bound_exclusive
        }) {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        tree_ordinals_by_mode_and_degree
            .entry((tree.low_degree_mode, exact_source_degree_bound_exclusive))
            .or_default()
            .push(tree.bound_tree_ordinal);
    }
    let block_count = tree_ordinals_by_mode_and_degree.len();
    let maximum_block_source_degree_bound_exclusive = bound_trees
        .iter()
        .flat_map(|tree| tree.ordered_columns.iter())
        .map(|column| column.source_degree_bound_exclusive)
        .max()
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    let polynomial_variable_count = usize::try_from(
        u64::BITS - (maximum_block_source_degree_bound_exclusive - 1).leading_zeros(),
    )
    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    if polynomial_variable_count > parameters.table_variable_count {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let selector_variable_count = parameters
        .table_variable_count
        .checked_sub(polynomial_variable_count)
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    let selector_capacity = 1_usize
        .checked_shl(
            u32::try_from(selector_variable_count)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        )
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    if block_count > selector_capacity {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let mut blocks = Vec::with_capacity(block_count);
    for (
        block_index,
        ((low_degree_mode, exact_source_degree_bound_exclusive), ordered_bound_tree_ordinals),
    ) in tree_ordinals_by_mode_and_degree.into_iter().enumerate()
    {
        let quotient_degree_bound_exclusive = exact_source_degree_bound_exclusive
            .checked_sub(1)
            .filter(|bound| *bound > 0)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        if block_index >= selector_capacity {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let selector_prefix = binary_prefix(
            u64::try_from(block_index)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            selector_variable_count,
        );
        let degree_suffix_prefixes =
            degree_suffix_prefixes(quotient_degree_bound_exclusive, polynomial_variable_count)?;
        blocks.push(RowCodeWhirBoundReductionBlockPlan {
            low_degree_mode,
            ordered_bound_tree_ordinals,
            maximum_source_degree_bound_exclusive: exact_source_degree_bound_exclusive,
            quotient_degree_bound_exclusive,
            polynomial_variable_count,
            selector_prefix,
            degree_suffix_prefixes,
            query_count: low_degree_mode.query_count(parameters),
        });
    }
    for left_index in 0..blocks.len() {
        for right_index in left_index + 1..blocks.len() {
            let left = &blocks[left_index].selector_prefix;
            let right = &blocks[right_index].selector_prefix;
            if left.starts_with(right) || right.starts_with(left) {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
        }
    }
    Ok(blocks)
}

fn binary_prefix(value: u64, bit_count: usize) -> Vec<u8> {
    (0..bit_count)
        .map(|bit_ordinal| {
            let shift = bit_count - 1 - bit_ordinal;
            u8::from(value & (1_u64 << shift) != 0)
        })
        .collect()
}

fn degree_suffix_prefixes(
    boundary_coefficient_ordinal: u64,
    polynomial_variable_count: usize,
) -> Result<Vec<Vec<u8>>, RowCodeWhirConstructionPlanError> {
    let coefficient_domain_size = 1_u64
        .checked_shl(
            u32::try_from(polynomial_variable_count)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        )
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    if boundary_coefficient_ordinal >= coefficient_domain_size {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let boundary_bits = binary_prefix(boundary_coefficient_ordinal, polynomial_variable_count);
    let mut prefixes = Vec::new();
    for (bit_ordinal, bit) in boundary_bits.iter().copied().enumerate() {
        if bit == 0 {
            let mut prefix = boundary_bits[..bit_ordinal].to_vec();
            prefix.push(1);
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

fn row_geometry(
    row_count: usize,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<RowEncodingGeometry, RowCodeWhirConstructionPlanError> {
    RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
        row_count,
        parameters.physical_row_witness_variable_count,
        parameters.row_code_log_inverse_rate,
    )
    .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::selected_profile::selected_relation_plans;

    #[test]
    fn checked_fixture_geometry_is_minimal_rate_one_quarter_and_fail_closed() {
        let mut checked_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("same-secret has a selected relation context");
        let fixture_evaluation_domain =
            ProofEvaluationDomain::new(4_096, checked_context.evaluation_coset_offset)
                .expect("the reduced fixture evaluation domain is valid");
        checked_context.evaluation_domain_generator =
            fixture_evaluation_domain.generator().canonical();
        checked_context.phase_column_query_coordinate_count = 16;
        let parameters = RowCodeWhirSelectedParameters::for_checked_fixture_geometry(4_096, 16)
            .expect("the reduced fixture geometry derives");
        assert_eq!(parameters.logical_polynomial_coefficient_count, 64);
        assert_eq!(parameters.logical_polynomials_per_physical_row, 8);
        assert_eq!(parameters.physical_row_witness_variable_count, 9);
        assert_eq!(parameters.row_code_log_inverse_rate, 2);
        assert_eq!(parameters.table_variable_count, 10);
        assert_eq!(parameters.polynomial_commitment_variable_count, 12);
        assert_eq!(parameters.outer_query_count, 16);
        assert_eq!(parameters.direct_bound_query_count, 16);
        assert_eq!(parameters.verified_vss_bound_query_count, 16);
        assert_eq!(
            validate_domain_geometry_values(4_096, 258, &checked_context, parameters),
            Ok(()),
        );

        assert!(
            RowCodeWhirSelectedParameters::for_checked_fixture_geometry(3_072, 16).is_err(),
            "a non-power-of-two evaluation domain has no row-code geometry",
        );
        assert!(
            validate_domain_geometry_values(8_192, 258, &checked_context, parameters).is_err(),
            "the derived parameters cannot be relabeled with another domain",
        );
        for malformed_opening_degree_bound in [0, 256, 513] {
            assert!(
                validate_domain_geometry_values(
                    4_096,
                    malformed_opening_degree_bound,
                    &checked_context,
                    parameters,
                )
                .is_err(),
                "opening bound {malformed_opening_degree_bound} must not fit the minimal 258-bound geometry",
            );
        }
        let mut mismatched_context = checked_context;
        mismatched_context.phase_column_query_coordinate_count = 15;
        assert!(
            validate_domain_geometry_values(4_096, 258, &mismatched_context, parameters).is_err(),
            "the exact checked context owns the fixture query geometry",
        );
    }

    #[test]
    fn checked_fixture_bound_geometry_uses_the_compiler_packing_factor() {
        assert_eq!(
            checked_fixture_bound_root_source_trace_domain_size(
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                BoundTreeConstructionKind::CommittedMaterial,
                2_048,
                65_536,
            ),
            Ok(512),
        );
        assert_eq!(
            checked_fixture_bound_root_source_trace_domain_size(
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                BoundTreeConstructionKind::SetupPolynomial,
                4,
                4_096,
            ),
            Ok(4),
        );
        assert!(
            checked_fixture_bound_root_source_trace_domain_size(
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                BoundTreeConstructionKind::CommittedMaterial,
                2_050,
                65_536,
            )
            .is_err(),
            "a packed trace that is not exactly divisible by the compiler factor is rejected",
        );
    }

    fn expected_requested_source_column_count(
        application_statement_schema_identifier: u16,
    ) -> usize {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => 2_018,
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 4_528,
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 506,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => 61_140,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 9_152,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => 157_508,
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 123_450,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 20_680,
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => 1_728,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => 25_670,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => 3_451,
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 2_528,
            _ => panic!("unexpected selected proof family"),
        }
    }

    fn expected_tree_counts(application_statement_schema_identifier: u16) -> (usize, usize, usize) {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => (1, 1, 11),
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => (1, 1, 4),
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => (0, 0, 11),
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => (1, 1, 5),
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => (0, 0, 22),
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => (1, 1, 8),
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => (1, 1, 9),
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => (0, 0, 77),
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => (1, 1, 0),
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => (1, 1, 8),
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => (1, 0, 112),
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => (1, 0, 88),
            _ => panic!("unexpected selected proof family"),
        }
    }

    fn expected_quotient_phase_row_count(application_statement_schema_identifier: u16) -> usize {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 10,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 20,
            _ => 15,
        }
    }

    fn descriptor_tree_counts(variant: &RelationPlanVariant) -> (usize, usize, usize) {
        let mut base_tree_count = 0;
        let mut auxiliary_tree_count = 0;
        let mut bound_tree_count = 0;
        for tree in variant.ordered_trees() {
            match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role, ..
                } if *proof_tree_role == ProofTreeRole::BaseOracle as u16 => {
                    base_tree_count += 1;
                }
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role, ..
                } if *proof_tree_role == ProofTreeRole::AuxiliaryOracle as u16 => {
                    auxiliary_tree_count += 1;
                }
                RelationTreeDescriptor::ProofCreated { .. } => {
                    panic!("selected relation has an unsupported proof-created tree role");
                }
                RelationTreeDescriptor::BoundPublic { .. } => bound_tree_count += 1,
            }
        }
        (base_tree_count, auxiliary_tree_count, bound_tree_count)
    }

    fn incumbent_same_secret_trace_rows(
        variant: &RelationPlanVariant,
        tree_role: ProofTreeRole,
    ) -> Vec<(
        [Option<u32>; ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW],
        Vec<u32>,
    )> {
        let mut opening_points_by_column = BTreeMap::<u32, Vec<u32>>::new();
        for tree in variant.ordered_trees() {
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } = tree
            else {
                continue;
            };
            if *proof_tree_role != tree_role as u16 {
                continue;
            }
            for column_ordinal in ordered_column_ordinals {
                assert!(
                    opening_points_by_column
                        .insert(*column_ordinal, Vec::new())
                        .is_none(),
                );
            }
        }
        for claim in variant.ordered_opening_claims() {
            if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
                continue;
            }
            let column_ordinal = claim.column_ordinal().expect("tree claim has a column");
            if let Some(opening_points) = opening_points_by_column.get_mut(&column_ordinal) {
                opening_points.push(claim.opening_point_ordinal());
            }
        }
        let mut columns_by_opening_pattern = BTreeMap::<Vec<u32>, Vec<u32>>::new();
        for (column_ordinal, mut opening_points) in opening_points_by_column {
            opening_points.sort_unstable();
            opening_points.dedup();
            columns_by_opening_pattern
                .entry(opening_points)
                .or_default()
                .push(column_ordinal);
        }
        let mut rows = Vec::new();
        for (opening_point_ordinals, columns) in columns_by_opening_pattern {
            for column_group in columns.chunks(ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW) {
                let mut column_ordinals =
                    [None; ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW];
                for (row_position, column_ordinal) in column_group.iter().copied().enumerate() {
                    column_ordinals[row_position] = Some(column_ordinal);
                }
                rows.push((column_ordinals, opening_point_ordinals.clone()));
            }
        }
        rows
    }

    fn assert_trace_phase_is_complete(
        variant: &RelationPlanVariant,
        tree_role: ProofTreeRole,
        phase: Option<&RowCodeWhirTracePhasePlan>,
        parameters: RowCodeWhirSelectedParameters,
    ) {
        let patterns = tree_column_opening_patterns(variant).expect("valid tree opening catalog");
        let mut expected_chunks = BTreeSet::new();
        for (column_ordinal, pattern) in &patterns {
            if pattern.owner != RelationTreeColumnOwner::ProofCreated(tree_role) {
                continue;
            }
            let descriptor = &variant.ordered_columns()[*column_ordinal as usize];
            let chunk_count = coefficient_chunk_count(
                descriptor.source_degree_bound_exclusive(),
                parameters.logical_polynomial_coefficient_count,
            )
            .expect("valid selected coefficient chunk count");
            for chunk_index in 0..chunk_count {
                expected_chunks.insert(RowCodeWhirRelationColumnChunk {
                    column_ordinal: *column_ordinal,
                    coefficient_chunk_ordinal: u32::try_from(chunk_index)
                        .expect("selected chunk ordinal fits u32"),
                });
            }
        }
        let Some(phase) = phase else {
            assert!(expected_chunks.is_empty());
            return;
        };
        assert_eq!(phase.tree_role, tree_role);
        assert_eq!(phase.geometry.row_count, phase.rows.len());
        assert_eq!(
            phase.geometry.encoded_column_count,
            1 << parameters.polynomial_commitment_variable_count,
        );
        let mut actual_chunks = BTreeSet::new();
        let mut rows_by_column_group = BTreeMap::<u32, Vec<&RowCodeWhirTracePhaseRow>>::new();
        for row in &phase.rows {
            assert!(!row.opening_point_ordinals.is_empty());
            assert!(
                row.opening_point_ordinals
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            let mut reached_padding = false;
            for logical_chunk in &row.logical_polynomial_chunks {
                if logical_chunk.is_none() {
                    reached_padding = true;
                } else {
                    assert!(!reached_padding, "row has occupied storage after padding");
                }
            }
            for logical_chunk in row.logical_polynomial_chunks.iter().flatten().copied() {
                assert_eq!(
                    logical_chunk.coefficient_chunk_ordinal,
                    row.coefficient_chunk_ordinal,
                );
                assert!(actual_chunks.insert(logical_chunk));
                assert_eq!(
                    patterns[&logical_chunk.column_ordinal].opening_point_ordinals,
                    row.opening_point_ordinals,
                );
            }
            rows_by_column_group
                .entry(row.column_group_ordinal)
                .or_default()
                .push(row);
        }
        assert_eq!(actual_chunks, expected_chunks);
        for (expected_group_ordinal, (group_ordinal, group_rows)) in
            rows_by_column_group.into_iter().enumerate()
        {
            assert_eq!(
                group_ordinal,
                u32::try_from(expected_group_ordinal).unwrap(),
            );
            let first_row = group_rows[0];
            let expected_columns = first_row
                .logical_polynomial_chunks
                .map(|chunk| chunk.map(|chunk| chunk.column_ordinal));
            for (expected_chunk_ordinal, row) in group_rows.into_iter().enumerate() {
                assert_eq!(
                    row.coefficient_chunk_ordinal,
                    u32::try_from(expected_chunk_ordinal).unwrap(),
                );
                assert_eq!(row.opening_point_ordinals, first_row.opening_point_ordinals);
                assert_eq!(
                    row.logical_polynomial_chunks
                        .map(|chunk| chunk.map(|chunk| chunk.column_ordinal)),
                    expected_columns,
                );
            }
        }
    }

    fn assert_quotient_phase_is_complete(
        variant: &RelationPlanVariant,
        plan: &RowCodeWhirConstructionPlan,
    ) {
        let context =
            selected_relation_plan_check_context(plan.application_statement_schema_identifier)
                .expect("selected relation context");
        let quotient_chunk_count = coefficient_chunk_count(
            context.quotient_component_degree_bound_exclusive,
            plan.parameters.logical_polynomial_coefficient_count,
        )
        .expect("valid quotient chunk count");
        let mut expected_chunks = BTreeSet::new();
        for extension_coordinate_ordinal in 0..context.challenge_extension_degree {
            for component_ordinal in 0..context.quotient_component_count {
                for chunk_index in 0..quotient_chunk_count {
                    expected_chunks.insert((
                        RowCodeWhirOpenedPolynomialChunk {
                            source: RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                                component_ordinal,
                            },
                            coefficient_chunk_ordinal: u32::try_from(chunk_index)
                                .expect("selected quotient chunk fits u32"),
                        },
                        extension_coordinate_ordinal,
                    ));
                }
            }
        }
        if let Some(mask_degree_bound) = plan
            .quotient_phase
            .opening_batch_mask_degree_bound_exclusive
        {
            let mask = variant
                .ordered_masks()
                .iter()
                .copied()
                .find(|mask| mask.mask_kind() == RelationMaskKind::OpeningBatch)
                .expect("secret-bearing selected relation has an opening mask");
            let mask_chunk_count = coefficient_chunk_count(
                mask_degree_bound,
                plan.parameters.logical_polynomial_coefficient_count,
            )
            .expect("valid mask chunk count");
            for extension_coordinate_ordinal in 0..context.challenge_extension_degree {
                for chunk_index in 0..mask_chunk_count {
                    expected_chunks.insert((
                        RowCodeWhirOpenedPolynomialChunk {
                            source: RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
                                mask_ordinal: mask.mask_coordinate().mask_ordinal(),
                            },
                            coefficient_chunk_ordinal: u32::try_from(chunk_index)
                                .expect("selected mask chunk fits u32"),
                        },
                        extension_coordinate_ordinal,
                    ));
                }
            }
        }
        let mut actual_chunks = BTreeSet::new();
        let mut quotient_sources_by_group = BTreeMap::<
            u32,
            [Option<u32>; ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW],
        >::new();
        for row in &plan.quotient_phase.rows {
            assert!(!row.opening_point_ordinals.is_empty());
            assert!(
                row.opening_point_ordinals
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            let mut reached_padding = false;
            for logical_chunk in &row.logical_polynomial_chunks {
                if logical_chunk.is_none() {
                    reached_padding = true;
                } else {
                    assert!(!reached_padding, "row has occupied storage after padding");
                }
            }
            for chunk in row.logical_polynomial_chunks.iter().flatten().copied() {
                match (row.source_class, chunk.source) {
                    (
                        RelationOpeningSourceClass::Quotient,
                        RowCodeWhirOpenedPolynomialSource::QuotientComponent { .. },
                    )
                    | (
                        RelationOpeningSourceClass::BatchMask,
                        RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { .. },
                    ) => {}
                    _ => panic!("quotient row mixes incompatible polynomial sources"),
                }
                assert!(actual_chunks.insert((chunk, row.extension_coordinate_ordinal,)));
            }
            match row.source_class {
                RelationOpeningSourceClass::Quotient => {
                    assert!(row.logical_polynomial_chunks.iter().flatten().all(|chunk| {
                        chunk.coefficient_chunk_ordinal == row.coefficient_chunk_group_start_ordinal
                    }));
                    let source_ordinals = row.logical_polynomial_chunks.map(|chunk| {
                        chunk.map(|chunk| match chunk.source {
                            RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                                component_ordinal,
                            } => component_ordinal,
                            RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { .. } => {
                                unreachable!()
                            }
                        })
                    });
                    if let Some(previous) =
                        quotient_sources_by_group.insert(row.source_group_ordinal, source_ordinals)
                    {
                        assert_eq!(previous, source_ordinals);
                    }
                }
                RelationOpeningSourceClass::BatchMask => {
                    for (chunk_offset, chunk) in
                        row.logical_polynomial_chunks.iter().flatten().enumerate()
                    {
                        assert_eq!(
                            chunk.coefficient_chunk_ordinal,
                            row.coefficient_chunk_group_start_ordinal
                                + u32::try_from(chunk_offset).unwrap(),
                        );
                    }
                    assert_eq!(row.source_group_ordinal, 0);
                }
                RelationOpeningSourceClass::TreeColumn => unreachable!(),
            }
        }
        assert_eq!(
            quotient_sources_by_group
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            (0..u32::try_from(quotient_sources_by_group.len()).unwrap()).collect::<Vec<_>>(),
        );
        assert_eq!(actual_chunks, expected_chunks);
        assert_eq!(
            plan.quotient_phase.geometry.row_count,
            plan.quotient_phase.rows.len(),
        );
        assert_eq!(plan.quotient_phase.geometry.encoded_column_count, 1 << 21);
    }

    fn assert_plan_identity_mutation_changes(
        plan: &RowCodeWhirConstructionPlan,
        expected_identity: [u8; 64],
        description: &str,
        mutate: impl FnOnce(&mut RowCodeWhirConstructionPlan),
    ) {
        let mut mutated_plan = plan.clone();
        mutate(&mut mutated_plan);
        assert_ne!(mutated_plan, *plan, "mutation did not change {description}");
        assert_ne!(
            mutated_plan
                .canonical_identity_hash()
                .expect("mutated plan identity"),
            expected_identity,
            "construction identity omitted {description}",
        );
    }

    fn assert_same_secret_construction_identity_is_mutation_sensitive(
        plan: &RowCodeWhirConstructionPlan,
    ) {
        let expected_identity = plan
            .canonical_identity_hash()
            .expect("same-secret construction identity");

        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "application schema",
            |mutated| mutated.application_statement_schema_identifier ^= 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "schedule selector",
            |mutated| {
                mutated.schedule_position =
                    Some(mutated.schedule_position.map_or(0, |position| position + 1));
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "top-count selector",
            |mutated| {
                mutated.top_count = Some(mutated.top_count.map_or(1, |top_count| top_count + 1));
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "relation-plan hash",
            |mutated| mutated.relation_plan_hash[0] ^= 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "relation-plan variant hash",
            |mutated| mutated.relation_plan_variant_hash[0] ^= 1,
        );
        assert_plan_identity_mutation_changes(plan, expected_identity, "trace domain", |mutated| {
            mutated.trace_domain_size += 1
        });
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "evaluation domain",
            |mutated| mutated.evaluation_domain_size += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "opening degree bound",
            |mutated| mutated.opening_degree_bound_exclusive += 1,
        );
        assert_plan_identity_mutation_changes(plan, expected_identity, "privacy mode", |mutated| {
            mutated.proof_privacy_mode = ProofPrivacyMode::PublicOnly
        });
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "requested source ordinal",
            |mutated| mutated.requested_source_column_ordinals[0] += 1,
        );

        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace phase presence",
            |mutated| mutated.auxiliary_phase = None,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "auxiliary trace row",
            |mutated| {
                mutated
                    .auxiliary_phase
                    .as_mut()
                    .expect("auxiliary phase")
                    .rows[0]
                    .column_group_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace tree role",
            |mutated| {
                mutated.base_phase.as_mut().expect("base phase").tree_role =
                    ProofTreeRole::AuxiliaryOracle;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace column group",
            |mutated| {
                mutated.base_phase.as_mut().expect("base phase").rows[0].column_group_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace row chunk ordinal",
            |mutated| {
                mutated.base_phase.as_mut().expect("base phase").rows[0]
                    .coefficient_chunk_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace row slot presence",
            |mutated| {
                mutated.base_phase.as_mut().expect("base phase").rows[0]
                    .logical_polynomial_chunks[0] = None;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace slot column ordinal",
            |mutated| {
                mutated.base_phase.as_mut().expect("base phase").rows[0]
                    .logical_polynomial_chunks[0]
                    .as_mut()
                    .expect("occupied trace slot")
                    .column_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace slot chunk ordinal",
            |mutated| {
                mutated.base_phase.as_mut().expect("base phase").rows[0]
                    .logical_polynomial_chunks[0]
                    .as_mut()
                    .expect("occupied trace slot")
                    .coefficient_chunk_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace opening point",
            |mutated| {
                mutated.base_phase.as_mut().expect("base phase").rows[0].opening_point_ordinals
                    [0] += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace geometry row count",
            |mutated| {
                mutated
                    .base_phase
                    .as_mut()
                    .expect("base phase")
                    .geometry
                    .row_count += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace geometry witness width",
            |mutated| {
                mutated
                    .base_phase
                    .as_mut()
                    .expect("base phase")
                    .geometry
                    .witness_values_per_row += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace geometry padded width",
            |mutated| {
                mutated
                    .base_phase
                    .as_mut()
                    .expect("base phase")
                    .geometry
                    .padded_coefficient_count += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "trace geometry codeword width",
            |mutated| {
                mutated
                    .base_phase
                    .as_mut()
                    .expect("base phase")
                    .geometry
                    .encoded_column_count += 1;
            },
        );

        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient component count",
            |mutated| mutated.quotient_phase.quotient_component_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient degree bound",
            |mutated| {
                mutated
                    .quotient_phase
                    .quotient_component_degree_bound_exclusive += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "opening-mask degree bound",
            |mutated| {
                *mutated
                    .quotient_phase
                    .opening_batch_mask_degree_bound_exclusive
                    .as_mut()
                    .expect("same-secret mask degree bound") += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient row source class",
            |mutated| {
                mutated.quotient_phase.rows[0].source_class = RelationOpeningSourceClass::BatchMask;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient source group",
            |mutated| mutated.quotient_phase.rows[0].source_group_ordinal += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient chunk-group start",
            |mutated| {
                mutated.quotient_phase.rows[0].coefficient_chunk_group_start_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient extension coordinate",
            |mutated| mutated.quotient_phase.rows[0].extension_coordinate_ordinal += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient row slot presence",
            |mutated| mutated.quotient_phase.rows[0].logical_polynomial_chunks[0] = None,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient component source",
            |mutated| {
                mutated.quotient_phase.rows[0].logical_polynomial_chunks[0]
                    .as_mut()
                    .expect("occupied quotient slot")
                    .source = RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                    component_ordinal: 8,
                };
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient slot chunk ordinal",
            |mutated| {
                mutated.quotient_phase.rows[0].logical_polynomial_chunks[0]
                    .as_mut()
                    .expect("occupied quotient slot")
                    .coefficient_chunk_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient opening point",
            |mutated| mutated.quotient_phase.rows[0].opening_point_ordinals[0] += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "opening-mask source",
            |mutated| {
                let mask_row = mutated
                    .quotient_phase
                    .rows
                    .iter_mut()
                    .find(|row| row.source_class == RelationOpeningSourceClass::BatchMask)
                    .expect("same-secret mask row");
                let mask_chunk = mask_row.logical_polynomial_chunks[0]
                    .as_mut()
                    .expect("occupied mask slot");
                let RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { mask_ordinal } =
                    &mut mask_chunk.source
                else {
                    panic!("mask row has a quotient source");
                };
                *mask_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "quotient geometry",
            |mutated| mutated.quotient_phase.geometry.row_count += 1,
        );

        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound relation-tree ordinal",
            |mutated| mutated.bound_trees[0].relation_tree_ordinal += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound-tree ordinal",
            |mutated| mutated.bound_trees[0].bound_tree_ordinal += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound construction kind",
            |mutated| {
                mutated.bound_trees[0].construction_kind =
                    BoundTreeConstructionKind::SetupPolynomial;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound expected-root source",
            |mutated| mutated.bound_trees[0].expected_root_source_ordinal += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound root use",
            |mutated| mutated.bound_trees[0].root_use = BoundTreeRootUse::Output,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound column ordinal",
            |mutated| mutated.bound_trees[0].ordered_columns[0].column_ordinal += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound column value type",
            |mutated| {
                mutated.bound_trees[0].ordered_columns[0].value_type =
                    RelationColumnValueType::ChallengeExtension;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound column degree",
            |mutated| {
                mutated.bound_trees[0].ordered_columns[0].source_degree_bound_exclusive += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound column opening point",
            |mutated| {
                mutated.bound_trees[0].ordered_columns[0].opening_point_ordinals[0] += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound source trace domain",
            |mutated| mutated.bound_trees[0].source_trace_domain_size += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound evaluation domain",
            |mutated| mutated.bound_trees[0].evaluation_domain_size += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound leaf count",
            |mutated| mutated.bound_trees[0].leaf_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound low-degree mode",
            |mutated| {
                mutated.bound_trees[0].low_degree_mode = RowCodeWhirBoundLowDegreeMode::Direct
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "bound query count",
            |mutated| mutated.bound_trees[0].query_count += 1,
        );

        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction mode",
            |mutated| {
                mutated.bound_reduction_blocks[0].low_degree_mode =
                    RowCodeWhirBoundLowDegreeMode::Direct;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction bound-tree ordinal",
            |mutated| mutated.bound_reduction_blocks[0].ordered_bound_tree_ordinals[0] += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction maximum degree",
            |mutated| {
                mutated.bound_reduction_blocks[0].maximum_source_degree_bound_exclusive += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction quotient degree",
            |mutated| {
                mutated.bound_reduction_blocks[0].quotient_degree_bound_exclusive += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction variable count",
            |mutated| mutated.bound_reduction_blocks[0].polynomial_variable_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction selector",
            |mutated| mutated.bound_reduction_blocks[0].selector_prefix[0] ^= 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction degree prefix",
            |mutated| mutated.bound_reduction_blocks[0].degree_suffix_prefixes[0][0] ^= 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "reduction query count",
            |mutated| mutated.bound_reduction_blocks[0].query_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "aggregate opening role",
            |mutated| {
                let RowCodeWhirAggregateColumnRole::OpeningPoint {
                    opening_point_ordinal,
                } = &mut mutated.aggregate_column_roles[0]
                else {
                    panic!("first aggregate role is not an opening point");
                };
                *opening_point_ordinal += 1;
            },
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "aggregate reduction role",
            |mutated| {
                *mutated
                    .aggregate_column_roles
                    .last_mut()
                    .expect("same-secret aggregate roles") =
                    RowCodeWhirAggregateColumnRole::OpeningPoint {
                        opening_point_ordinal: 99,
                    };
            },
        );

        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "logical polynomial capacity",
            |mutated| mutated.parameters.logical_polynomial_coefficient_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "logical polynomials per row",
            |mutated| mutated.parameters.logical_polynomials_per_physical_row += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "physical-row witness variables",
            |mutated| mutated.parameters.physical_row_witness_variable_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "row-code inverse rate",
            |mutated| mutated.parameters.row_code_log_inverse_rate += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "table variables",
            |mutated| mutated.parameters.table_variable_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "commitment variables",
            |mutated| mutated.parameters.polynomial_commitment_variable_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "starting inverse rate",
            |mutated| mutated.parameters.starting_log_inverse_rate += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "WHIR folding factor",
            |mutated| mutated.parameters.folding_factor += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "security level",
            |mutated| mutated.parameters.security_level += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "proof-of-work bits",
            |mutated| mutated.parameters.proof_of_work_bits += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "outer query count",
            |mutated| mutated.parameters.outer_query_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "direct-bound query count",
            |mutated| mutated.parameters.direct_bound_query_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "verified-VSS bound query count",
            |mutated| mutated.parameters.verified_vss_bound_query_count += 1,
        );
        assert_plan_identity_mutation_changes(
            plan,
            expected_identity,
            "maximum Fiat-Shamir candidate draws",
            |mutated| {
                mutated
                    .parameters
                    .maximum_fiat_shamir_candidate_draws_per_output += 1;
            },
        );
    }

    #[test]
    fn construction_identity_encoding_uses_fixed_little_endian_lengths_and_integers() {
        let mut encoder = RowCodeWhirConstructionPlanIdentityEncoder::default();
        encoder.push_u16(0x1234);
        encoder.push_u32(0x7856_3412);
        encoder.push_u64(0xf0de_bc9a_7856_3412);
        encoder.push_optional_u16(None);
        encoder.push_optional_u16(Some(0x1234));
        encoder.push_bytes(&[0xaa, 0xbb]).expect("two-byte value");

        assert_eq!(
            encoder.finish(),
            vec![
                0x34, 0x12, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x00, 0x01, 0x34, 0x12, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb,
            ],
        );
    }

    #[test]
    fn every_selected_variant_has_complete_descriptor_derived_geometry() {
        let artifacts = selected_relation_plans().expect("selected relation plans");
        assert_eq!(artifacts.len(), 12);
        let mut variant_count = 0;
        let mut variant_identities = BTreeSet::new();
        let mut evaluator_top_counts = BTreeSet::new();
        let mut degree_suffix_shapes = BTreeSet::new();
        let mut construction_plan_identity_hashes = BTreeSet::new();
        for artifact in &artifacts {
            let schema_identifier = artifact.application_statement_schema_identifier();
            for variant in artifact.compiled_plan().variants() {
                variant_count += 1;
                assert!(variant_identities.insert((
                    schema_identifier,
                    variant.schedule_position(),
                    variant.top_count(),
                )));
                if schema_identifier
                    == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                {
                    evaluator_top_counts.insert(variant.top_count().expect("evaluator top count"));
                }
                let plan = RowCodeWhirConstructionPlan::for_selected_variant(
                    artifact,
                    variant.schedule_position(),
                    variant.top_count(),
                )
                .expect("selected variant has supported row-code WHIR geometry");
                let canonical_identity_bytes = plan
                    .canonical_identity_bytes()
                    .expect("selected construction identity bytes");
                assert_eq!(
                    plan.canonical_identity_bytes()
                        .expect("repeated selected construction identity bytes"),
                    canonical_identity_bytes,
                );
                let construction_plan_identity_hash = plan
                    .canonical_identity_hash()
                    .expect("selected construction identity hash");
                assert_eq!(
                    plan.canonical_identity_hash()
                        .expect("repeated selected construction identity hash"),
                    construction_plan_identity_hash,
                );
                assert!(
                    construction_plan_identity_hashes.insert(construction_plan_identity_hash),
                    "selected construction identities must be unique",
                );
                if schema_identifier
                    == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
                {
                    assert_same_secret_plan_preserves_the_exact_construction_shape(
                        artifact, variant, &plan,
                    );
                    assert_same_secret_construction_identity_is_mutation_sensitive(&plan);
                }
                assert_eq!(
                    plan.application_statement_schema_identifier,
                    schema_identifier
                );
                assert_eq!(plan.schedule_position, variant.schedule_position());
                assert_eq!(plan.top_count, variant.top_count());
                assert_eq!(plan.trace_domain_size, variant.trace_domain_size());
                assert_eq!(plan.evaluation_domain_size, 1 << 21);
                assert_eq!(plan.opening_degree_bound_exclusive, 1 << 18);
                assert_eq!(plan.proof_privacy_mode, variant.proof_privacy_mode());
                assert!(
                    plan.requested_source_column_ordinals
                        .windows(2)
                        .all(|pair| pair[0] < pair[1]),
                );
                assert!(
                    plan.requested_source_column_ordinals
                        .iter()
                        .all(|column_ordinal| {
                            usize::try_from(*column_ordinal)
                                .ok()
                                .filter(|column_index| {
                                    *column_index < variant.ordered_columns().len()
                                })
                                .is_some()
                        })
                );
                assert_eq!(
                    plan.requested_source_column_ordinals.len(),
                    expected_requested_source_column_count(schema_identifier),
                    "family {schema_identifier} has the exact requested source count",
                );
                assert_eq!(
                    descriptor_tree_counts(variant),
                    expected_tree_counts(schema_identifier),
                );
                assert_trace_phase_is_complete(
                    variant,
                    ProofTreeRole::BaseOracle,
                    plan.base_phase.as_ref(),
                    plan.parameters,
                );
                assert_trace_phase_is_complete(
                    variant,
                    ProofTreeRole::AuxiliaryOracle,
                    plan.auxiliary_phase.as_ref(),
                    plan.parameters,
                );
                assert_quotient_phase_is_complete(variant, &plan);
                assert_eq!(
                    plan.quotient_phase.rows.len(),
                    expected_quotient_phase_row_count(schema_identifier),
                );
                assert_eq!(
                    plan.bound_trees.len(),
                    expected_tree_counts(schema_identifier).2,
                );
                if matches!(
                    schema_identifier,
                    ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                ) {
                    assert!(plan.base_phase.as_ref().unwrap().rows.iter().any(|row| {
                        row.logical_polynomial_chunks
                            .iter()
                            .flatten()
                            .any(|chunk| chunk.coefficient_chunk_ordinal == 2)
                    }));
                }

                let mut expected_aggregate_column_roles =
                    (0..variant.ordered_opening_points().len())
                        .map(
                            |opening_point_index| RowCodeWhirAggregateColumnRole::OpeningPoint {
                                opening_point_ordinal: u32::try_from(opening_point_index).unwrap(),
                            },
                        )
                        .collect::<Vec<_>>();
                if !plan.bound_reduction_blocks.is_empty() {
                    expected_aggregate_column_roles
                        .push(RowCodeWhirAggregateColumnRole::BoundReduction);
                }
                assert_eq!(plan.aggregate_column_roles, expected_aggregate_column_roles);

                let mut reduced_tree_ordinals = BTreeSet::new();
                for block in &plan.bound_reduction_blocks {
                    assert_eq!(
                        block.query_count,
                        block.low_degree_mode.query_count(plan.parameters),
                    );
                    for tree_ordinal in &block.ordered_bound_tree_ordinals {
                        assert!(reduced_tree_ordinals.insert(*tree_ordinal));
                    }
                    degree_suffix_shapes.insert((
                        block.quotient_degree_bound_exclusive,
                        block.polynomial_variable_count,
                        block.degree_suffix_prefixes.clone(),
                    ));
                }
                assert_eq!(reduced_tree_ordinals.len(), plan.bound_trees.len());
                for tree in &plan.bound_trees {
                    assert_eq!(tree.evaluation_domain_size, plan.evaluation_domain_size);
                    assert_eq!(tree.leaf_count, plan.evaluation_domain_size as usize / 2);
                    assert_eq!(
                        tree.query_count,
                        tree.low_degree_mode.query_count(plan.parameters),
                    );
                    if tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired
                    {
                        assert_eq!(
                            schema_identifier,
                            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                        );
                        assert_eq!(
                            tree.construction_kind,
                            BoundTreeConstructionKind::CommittedMaterial,
                        );
                        assert_eq!(tree.root_use, BoundTreeRootUse::Input);
                    }
                }
                let expected_bound_trees = variant
                    .ordered_trees()
                    .iter()
                    .enumerate()
                    .filter_map(|(relation_tree_ordinal, tree)| match tree {
                        RelationTreeDescriptor::BoundPublic {
                            construction_kind,
                            expected_root_source_ordinal,
                            root_use,
                            ordered_column_ordinals,
                        } => Some((
                            relation_tree_ordinal,
                            construction_kind,
                            expected_root_source_ordinal,
                            root_use,
                            ordered_column_ordinals,
                        )),
                        RelationTreeDescriptor::ProofCreated { .. } => None,
                    })
                    .collect::<Vec<_>>();
                for (tree, expected) in plan.bound_trees.iter().zip(expected_bound_trees) {
                    assert_eq!(tree.relation_tree_ordinal as usize, expected.0);
                    assert_eq!(&tree.construction_kind, expected.1);
                    assert_eq!(&tree.expected_root_source_ordinal, expected.2);
                    assert_eq!(&tree.root_use, expected.3);
                    let actual_column_ordinals = tree
                        .ordered_columns
                        .iter()
                        .map(|column| column.column_ordinal)
                        .collect::<Vec<_>>();
                    assert_eq!(actual_column_ordinals.as_slice(), expected.4.as_slice(),);
                }
            }
        }
        assert_eq!(variant_count, 31);
        assert_eq!(variant_identities.len(), 31);
        assert_eq!(construction_plan_identity_hashes.len(), 31);
        assert_eq!(evaluator_top_counts, (1_u16..=20).collect::<BTreeSet<_>>(),);

        for (boundary, variable_count, suffix_prefixes) in degree_suffix_shapes {
            let coefficient_domain_size = 1_u64 << variable_count;
            for coefficient_ordinal in 0..coefficient_domain_size {
                let coefficient_bits = binary_prefix(coefficient_ordinal, variable_count);
                let cover_count = usize::from(coefficient_ordinal == boundary)
                    + suffix_prefixes
                        .iter()
                        .filter(|prefix| coefficient_bits.starts_with(prefix))
                        .count();
                assert_eq!(
                    cover_count,
                    usize::from(coefficient_ordinal >= boundary),
                    "wrong degree-suffix cover at coefficient {coefficient_ordinal}",
                );
            }
        }
    }

    fn assert_same_secret_plan_preserves_the_exact_construction_shape(
        artifact: &ValidatedRelationPlanArtifact,
        variant: &RelationPlanVariant,
        plan: &RowCodeWhirConstructionPlan,
    ) {
        assert_eq!(
            plan.relation_plan_hash,
            artifact.compiled_plan().canonical_hash().unwrap(),
        );
        assert_eq!(
            plan.relation_plan_variant_hash,
            variant.canonical_hash().unwrap(),
        );
        assert_eq!(plan.requested_source_column_ordinals.len(), 2_018);
        let base_phase = plan.base_phase.as_ref().expect("same-secret base phase");
        let auxiliary_phase = plan
            .auxiliary_phase
            .as_ref()
            .expect("same-secret auxiliary phase");
        assert_eq!(base_phase.rows.len(), 247);
        assert_eq!(auxiliary_phase.rows.len(), 136);
        assert_eq!(plan.quotient_phase.rows.len(), 15);
        for (phase, tree_role) in [
            (base_phase, ProofTreeRole::BaseOracle),
            (auxiliary_phase, ProofTreeRole::AuxiliaryOracle),
        ] {
            let incumbent_rows = incumbent_same_secret_trace_rows(variant, tree_role);
            assert_eq!(phase.rows.len(), incumbent_rows.len());
            for (row_index, (row, (incumbent_column_ordinals, incumbent_opening_points))) in
                phase.rows.iter().zip(incumbent_rows).enumerate()
            {
                assert_eq!(row.column_group_ordinal, u32::try_from(row_index).unwrap(),);
                assert_eq!(row.coefficient_chunk_ordinal, 0);
                assert_eq!(row.opening_point_ordinals, incumbent_opening_points);
                assert_eq!(
                    row.logical_polynomial_chunks.map(|logical_chunk| {
                        logical_chunk.map(|logical_chunk| {
                            assert_eq!(logical_chunk.coefficient_chunk_ordinal, 0);
                            logical_chunk.column_ordinal
                        })
                    }),
                    incumbent_column_ordinals,
                );
            }
        }
        for (row_index, row) in plan.quotient_phase.rows.iter().enumerate() {
            if row_index < 10 {
                assert_eq!(row.source_class, RelationOpeningSourceClass::Quotient);
                assert_eq!(row.source_group_ordinal, 0);
                assert_eq!(
                    row.extension_coordinate_ordinal,
                    u16::try_from(row_index % 5).unwrap(),
                );
                let expected_chunk_ordinal = u32::try_from(row_index / 5).unwrap();
                assert_eq!(
                    row.coefficient_chunk_group_start_ordinal,
                    expected_chunk_ordinal,
                );
                let expected_sources: [Option<RowCodeWhirOpenedPolynomialSource>;
                    ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW] =
                    core::array::from_fn(|component_ordinal| {
                        Some(RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                            component_ordinal: u32::try_from(component_ordinal).unwrap(),
                        })
                    });
                assert_eq!(
                    row.logical_polynomial_chunks.map(|chunk| {
                        chunk.map(|chunk| {
                            assert_eq!(chunk.coefficient_chunk_ordinal, expected_chunk_ordinal);
                            chunk.source
                        })
                    }),
                    expected_sources,
                );
            } else {
                assert_eq!(row.source_class, RelationOpeningSourceClass::BatchMask);
                assert_eq!(row.source_group_ordinal, 0);
                assert_eq!(row.coefficient_chunk_group_start_ordinal, 0);
                assert_eq!(
                    row.extension_coordinate_ordinal,
                    u16::try_from(row_index - 10).unwrap(),
                );
                let expected_chunk_ordinals: [Option<u32>;
                    ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW] =
                    core::array::from_fn(|chunk_ordinal| {
                        Some(u32::try_from(chunk_ordinal).unwrap())
                    });
                assert_eq!(
                    row.logical_polynomial_chunks.map(|chunk| {
                        chunk.map(|chunk| match chunk.source {
                            RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
                                mask_ordinal,
                            } => {
                                assert_eq!(mask_ordinal, 0);
                                chunk.coefficient_chunk_ordinal
                            }
                            _ => panic!("same-secret mask row contains a quotient"),
                        })
                    }),
                    expected_chunk_ordinals,
                );
            }
        }
        assert_eq!(
            base_phase
                .rows
                .iter()
                .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
                .count(),
            1_968,
        );
        assert_eq!(
            auxiliary_phase
                .rows
                .iter()
                .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
                .count(),
            1_080,
        );
        assert!(
            base_phase
                .rows
                .iter()
                .chain(&auxiliary_phase.rows)
                .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
                .all(|chunk| chunk.coefficient_chunk_ordinal == 0),
        );
        assert_eq!(
            plan.aggregate_column_roles,
            vec![
                RowCodeWhirAggregateColumnRole::OpeningPoint {
                    opening_point_ordinal: 0,
                },
                RowCodeWhirAggregateColumnRole::OpeningPoint {
                    opening_point_ordinal: 1,
                },
                RowCodeWhirAggregateColumnRole::OpeningPoint {
                    opening_point_ordinal: 2,
                },
                RowCodeWhirAggregateColumnRole::BoundReduction,
            ],
        );
        assert_eq!(plan.bound_trees.len(), 11);
        assert!(plan.bound_trees[..8].iter().all(|tree| {
            tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired
                && tree.query_count == 40
                && tree.root_use == BoundTreeRootUse::Input
                && tree.construction_kind == BoundTreeConstructionKind::CommittedMaterial
        }));
        assert!(plan.bound_trees[8..].iter().all(|tree| {
            tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::Direct
                && tree.query_count == 266
                && tree.root_use == BoundTreeRootUse::Output
                && tree.construction_kind == BoundTreeConstructionKind::SetupPolynomial
        }));
        assert!(plan.bound_trees[..8].iter().all(|tree| {
            tree.ordered_columns.len() == 4
                && tree.source_trace_domain_size == 16_384
                && tree.leaf_count == 1 << 20
                && tree.ordered_columns.iter().all(|column| {
                    column.source_degree_bound_exclusive == 18_432
                        && column.opening_point_ordinals.len() == 1
                })
        }));
        assert!(plan.bound_trees[8..].iter().all(|tree| {
            tree.ordered_columns.len() == 4
                && tree.source_trace_domain_size == 16_384
                && tree.leaf_count == 1 << 20
                && tree.ordered_columns.iter().all(|column| {
                    column.source_degree_bound_exclusive == 16_384
                        && column.opening_point_ordinals.len() == 1
                })
        }));
        assert_eq!(plan.bound_reduction_blocks.len(), 2);
        let borrowed_input_block = &plan.bound_reduction_blocks[0];
        assert_eq!(
            borrowed_input_block.maximum_source_degree_bound_exclusive,
            18_432,
        );
        assert_eq!(borrowed_input_block.quotient_degree_bound_exclusive, 18_431);
        assert_eq!(borrowed_input_block.polynomial_variable_count, 15);
        assert_eq!(
            borrowed_input_block.degree_suffix_prefixes,
            vec![vec![1, 1], vec![1, 0, 1], vec![1, 0, 0, 1]],
        );
        assert_eq!(borrowed_input_block.degree_test_count(), 4);
        let direct_output_block = &plan.bound_reduction_blocks[1];
        assert_eq!(
            direct_output_block.maximum_source_degree_bound_exclusive,
            16_384,
        );
        assert_eq!(direct_output_block.quotient_degree_bound_exclusive, 16_383);
        assert_eq!(direct_output_block.polynomial_variable_count, 15);
        assert_eq!(direct_output_block.degree_suffix_prefixes, vec![vec![1]]);
        assert_eq!(direct_output_block.degree_test_count(), 2);
        assert_eq!(
            plan.bound_reduction_blocks[0].selector_prefix,
            vec![0, 0, 0, 0],
        );
        assert_eq!(
            plan.bound_reduction_blocks[1].selector_prefix,
            vec![0, 0, 0, 1],
        );
        assert_eq!(
            plan.bound_reduction_blocks
                .iter()
                .map(RowCodeWhirBoundReductionBlockPlan::degree_test_count)
                .sum::<usize>(),
            6,
        );
        assert_eq!(plan.parameters.table_variable_count, 19);
        assert_eq!(plan.parameters.polynomial_commitment_variable_count, 21);
        assert_eq!(plan.parameters.logical_polynomial_coefficient_count, 32_768);
        assert_eq!(plan.parameters.logical_polynomials_per_physical_row, 8);
        assert_eq!(plan.parameters.physical_row_witness_variable_count, 18);
        assert_eq!(plan.parameters.row_code_log_inverse_rate, 2);
        assert_eq!(plan.parameters.starting_log_inverse_rate, 2);
        assert_eq!(plan.parameters.folding_factor, 3);
        assert_eq!(
            plan.parameters.soundness_assumption,
            RowCodeWhirSoundnessAssumption::UniqueDecoding,
        );
        assert_eq!(plan.parameters.security_level, 262);
        assert_eq!(plan.parameters.proof_of_work_bits, 0);
        assert_eq!(plan.parameters.outer_query_count, 387);
    }
}
