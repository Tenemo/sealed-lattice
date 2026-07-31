//! Descriptor-derived geometry for the selected row-code WHIR construction.

use std::collections::{BTreeMap, BTreeSet};

use crate::foundation::ProofApplicationSlotCeilings;
use crate::hashing::hash_framed_parts_512;

use super::super::profile::ProofProfileError;
use super::super::prover::{
    CommonProofProverError, requested_pre_challenge_source_column_ordinals,
};
use super::super::relation_plan::COMMITTED_MATERIAL_TRACE_PACKING_FACTOR;
use super::super::relation_plan::{
    BoundTreeConstructionKind, BoundTreeRootUse, ProofPrivacyMode, RelationColumnOrigin,
    RelationColumnValueType, RelationMaskKind, RelationMaskTargetClass, RelationOpeningSourceClass,
    RelationPlanVariant, RelationTreeDescriptor,
};
use super::super::selected_profile::{
    selected_bound_root_source_trace_domain_size, selected_committed_material_relation_plan_input,
    selected_relation_plan_check_context,
};
use super::super::transcript::{
    CommonProofApplicationChallengeGroup, CommonProofChallenge, CommonProofRelationPrefixSchedule,
    CommonProofRound, DISTINCT_QUERY_VECTOR_SAMPLER_TYPE, FIXED_CHALLENGE_BLOCK_BYTE_LENGTH,
    PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE, RowCodeWhirChallenge, RowCodeWhirTracePhase,
    TRANSCRIPT_ABSORB_DOMAIN, TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN,
    TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN, TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
    TRANSCRIPT_INITIAL_DOMAIN, TRANSCRIPT_RESPONSE_BINDING_DOMAIN, TRANSCRIPT_RESPONSE_ROOT_DOMAIN,
};
use super::super::{
    PROOF_BASE_FIELD_MODULUS, PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofTreeRole, RelationPlanCheckContext,
    RelationPlanError, ValidatedRelationPlanArtifact,
};
use super::row_encoding::RowEncodingGeometry;
use super::{
    ROW_CODE_WHIR_AGGREGATE_LEAF_STATE_BYTE_LENGTH, ROW_CODE_WHIR_MERKLE_DIGEST_BYTE_LENGTH,
};

#[cfg(test)]
mod linear_bcs_transcript;
#[cfg(test)]
mod shared_query_partition;

pub(super) const ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT: usize = 32_768;
/// Maximum number of logical polynomials carried by one physical row.
///
/// The exact same-secret construction uses all 64 lanes. Other proof families
/// may select a narrower power-of-two row when their larger opening-point
/// catalog needs more prefix-selector variables inside the same commitment
/// domain.
pub(super) const ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize = 64;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_COMPACT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW:
    usize = 8;
pub(super) const ROW_CODE_WHIR_BALLOT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize =
    ROW_CODE_WHIR_COMPACT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
pub(super) const ROW_CODE_WHIR_COMMITTED_MATERIAL_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize =
    ROW_CODE_WHIR_COMPACT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
pub(super) const ROW_CODE_WHIR_TARGET_RELEASE_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize =
    ROW_CODE_WHIR_COMPACT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
pub(super) const ROW_CODE_WHIR_LOG_INVERSE_RATE: usize = 2;
pub(super) const ROW_CODE_WHIR_PHYSICAL_ROW_WITNESS_VARIABLE_COUNT: usize =
    ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT.ilog2() as usize
        + ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW.ilog2() as usize;
pub(super) const ROW_CODE_WHIR_TABLE_VARIABLE_COUNT: usize =
    ROW_CODE_WHIR_PHYSICAL_ROW_WITNESS_VARIABLE_COUNT + 1;
pub(super) const ROW_CODE_WHIR_POLYNOMIAL_COMMITMENT_VARIABLE_COUNT: usize =
    ROW_CODE_WHIR_TABLE_VARIABLE_COUNT + ROW_CODE_WHIR_LOG_INVERSE_RATE;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 =
    (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        * ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW) as u64;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_BALLOT_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 =
    (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        * ROW_CODE_WHIR_BALLOT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW) as u64;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE:
    u64 = (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
    * ROW_CODE_WHIR_COMMITTED_MATERIAL_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
    as u64;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_TARGET_RELEASE_OPENING_DEGREE_BOUND_EXCLUSIVE:
    u64 = (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
    * ROW_CODE_WHIR_TARGET_RELEASE_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
    as u64;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE: u64 =
    1_u64 << ROW_CODE_WHIR_POLYNOMIAL_COMMITMENT_VARIABLE_COUNT;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT: u32 = 387;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_TRACE_MASK_DEGREE_BOUND_EXCLUSIVE: u64 = 682;
pub(super) const ROW_CODE_WHIR_OUTER_QUERY_COUNT: usize =
    ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT as usize;
pub(super) const ROW_CODE_WHIR_DIRECT_BOUND_QUERY_COUNT: usize = 266;
pub(super) const ROW_CODE_WHIR_PRIOR_PROOF_BOUND_QUERY_COUNT: usize = 40;

const ROW_CODE_WHIR_FOLDING_FACTOR: usize = 3;
const ROW_CODE_WHIR_SECURITY_LEVEL: usize = 262;
const ROW_CODE_WHIR_PROOF_OF_WORK_BITS: usize = 0;
const ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_ENCODING_VERSION: u16 = 9;
const ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_HASH_DOMAIN: &str =
    "sealed-lattice/proof/row-code-whir/construction-plan/v1";
const ROW_CODE_WHIR_ORACLE_EQUATION_CATALOG_ENCODING_VERSION: u16 = 2;
const ROW_CODE_WHIR_ORACLE_EQUATION_CATALOG_HASH_DOMAIN: &str =
    "sealed-lattice/proof/row-code-whir/oracle-equation-catalog/v2";
const VERIFIED_VSS_LOW_DEGREE_CERTIFICATE_GEOMETRY_DOMAIN: &str =
    "sealed-lattice/proof/verified-vss-low-degree-certificate-geometry/v1";
const VERIFIED_VSS_LOW_DEGREE_CERTIFICATE_GEOMETRY_VERSION: u16 = 1;
const SELECTED_VSS_LOW_DEGREE_CERTIFICATE_ROOT_COUNT: usize = 8;
const SELECTED_VSS_LOW_DEGREE_CERTIFICATE_SOURCE_DEGREE_BOUND_EXCLUSIVE: u64 = 18_432;

/// Returns the selected construction's trace-mask degree only when the caller
/// has the canonical relation-checking context and trace geometry for the
/// supplied statement schema.
///
/// Relation compilers run before a complete construction plan exists. This is
/// their narrow route to the construction-owned masking parameter; compact
/// fixture contexts deliberately receive no selected-suite value.
pub(in crate::bgv::proof_suite) fn selected_row_code_whir_trace_mask_degree_bound_exclusive(
    application_statement_schema_identifier: u16,
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Option<u64> {
    let selected_context =
        selected_relation_plan_check_context(application_statement_schema_identifier)?;
    let logical_polynomial_coefficient_count =
        ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT as u64;
    let expected_trace_domain_size = match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            logical_polynomial_coefficient_count.checked_div(2)?
        }
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
            logical_polynomial_coefficient_count
        }
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            logical_polynomial_coefficient_count.checked_mul(2)?
        }
        _ => return None,
    };
    (selected_context == *context && trace_domain_size == expected_trace_domain_size)
        .then_some(ROW_CODE_WHIR_TRACE_MASK_DEGREE_BOUND_EXCLUSIVE)
}

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
    pub(in crate::bgv::proof_suite) trace_mask_degree_bound_exclusive: u64,
    pub(in crate::bgv::proof_suite) direct_bound_query_count: usize,
    pub(in crate::bgv::proof_suite) prior_proof_bound_query_count: usize,
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
            trace_mask_degree_bound_exclusive: ROW_CODE_WHIR_TRACE_MASK_DEGREE_BOUND_EXCLUSIVE,
            direct_bound_query_count: ROW_CODE_WHIR_DIRECT_BOUND_QUERY_COUNT,
            prior_proof_bound_query_count: ROW_CODE_WHIR_PRIOR_PROOF_BOUND_QUERY_COUNT,
            maximum_fiat_shamir_candidate_draws_per_output:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        }
    }

    fn for_selected_variant_geometry(
        variant: &RelationPlanVariant,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        let logical_polynomial_coefficient_count =
            ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
        let logical_polynomials_per_physical_row =
            usize::try_from(variant.opening_degree_bound_exclusive())
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?
                .checked_div(logical_polynomial_coefficient_count)
                .filter(|width| {
                    *width > 0
                        && width.is_power_of_two()
                        && *width <= ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
                        && logical_polynomial_coefficient_count
                            .checked_mul(*width)
                            .is_some_and(|capacity| {
                                u64::try_from(capacity).ok()
                                    == Some(variant.opening_degree_bound_exclusive())
                            })
                })
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        let witness_value_count = logical_polynomial_coefficient_count
            .checked_mul(logical_polynomials_per_physical_row)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        let physical_row_witness_variable_count = usize::try_from(witness_value_count.ilog2())
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let table_variable_count = physical_row_witness_variable_count
            .checked_add(1)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        let polynomial_commitment_variable_count =
            usize::try_from(variant.evaluation_domain_size().ilog2())
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let row_code_log_inverse_rate = polynomial_commitment_variable_count
            .checked_sub(table_variable_count)
            .filter(|rate| *rate >= ROW_CODE_WHIR_LOG_INVERSE_RATE)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        let trace_mask_degree_bound_exclusive =
            if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
                ROW_CODE_WHIR_TRACE_MASK_DEGREE_BOUND_EXCLUSIVE
            } else {
                variant_trace_mask_degree_bound(variant)?
            };
        // The row-code rate embeds this candidate's table in the fixed
        // commitment domain. The aggregate PCS then codes that complete
        // domain at its independently selected rate; reusing the embedding
        // rate here would add the redundancy twice.
        Ok(Self {
            logical_polynomial_coefficient_count,
            logical_polynomials_per_physical_row,
            physical_row_witness_variable_count,
            row_code_log_inverse_rate,
            table_variable_count,
            polynomial_commitment_variable_count,
            starting_log_inverse_rate: ROW_CODE_WHIR_LOG_INVERSE_RATE,
            folding_factor: ROW_CODE_WHIR_FOLDING_FACTOR,
            soundness_assumption: RowCodeWhirSoundnessAssumption::UniqueDecoding,
            security_level: ROW_CODE_WHIR_SECURITY_LEVEL,
            proof_of_work_bits: ROW_CODE_WHIR_PROOF_OF_WORK_BITS,
            outer_query_count: ROW_CODE_WHIR_OUTER_QUERY_COUNT,
            trace_mask_degree_bound_exclusive,
            direct_bound_query_count: ROW_CODE_WHIR_DIRECT_BOUND_QUERY_COUNT,
            prior_proof_bound_query_count: ROW_CODE_WHIR_PRIOR_PROOF_BOUND_QUERY_COUNT,
            maximum_fiat_shamir_candidate_draws_per_output:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        })
    }

    #[cfg(test)]
    fn for_checked_fixture(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        let trace_mask_degree_bound_exclusive = variant_trace_mask_degree_bound(variant)?;
        Self::for_checked_fixture_geometry(
            variant.evaluation_domain_size(),
            context.phase_column_query_coordinate_count,
            trace_mask_degree_bound_exclusive,
        )
    }

    #[cfg(test)]
    fn for_checked_fixture_geometry(
        evaluation_domain_size: u64,
        phase_column_query_coordinate_count: u32,
        trace_mask_degree_bound_exclusive: u64,
    ) -> Result<Self, RowCodeWhirConstructionPlanError> {
        let evaluation_domain_size = usize::try_from(evaluation_domain_size)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        const FIXTURE_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize = 8;
        let row_encoding_expansion_factor = FIXTURE_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
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
            .checked_mul(FIXTURE_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
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
        let prior_proof_bound_query_count =
            direct_bound_query_count.min(ROW_CODE_WHIR_PRIOR_PROOF_BOUND_QUERY_COUNT);
        Ok(Self {
            logical_polynomial_coefficient_count,
            logical_polynomials_per_physical_row: FIXTURE_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW,
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
            trace_mask_degree_bound_exclusive,
            direct_bound_query_count,
            prior_proof_bound_query_count,
            maximum_fiat_shamir_candidate_draws_per_output:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        })
    }
}

fn aggregate_table_width_from_parameters(
    parameters: RowCodeWhirSelectedParameters,
) -> Result<usize, RowCodeWhirConstructionPlanError> {
    parameters
        .polynomial_commitment_variable_count
        .checked_sub(parameters.table_variable_count)
        .and_then(|selector_variable_count| {
            u32::try_from(selector_variable_count)
                .ok()
                .and_then(|shift| 1_usize.checked_shl(shift))
        })
        .filter(|width| *width > 0)
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
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
    /// The same setup-polynomial root was already accepted as an output of an
    /// earlier proof in this ceremony. The later proof still authenticates its
    /// claimed opening, but reuses the positive low-degree result bound to that
    /// exact root and statement coordinate.
    PriorSetupPolynomialProofRequired,
    Direct,
}

impl RowCodeWhirBoundLowDegreeMode {
    const fn query_count(self, parameters: RowCodeWhirSelectedParameters) -> usize {
        match self {
            Self::PriorVssProofRequired | Self::PriorSetupPolynomialProofRequired => {
                parameters.prior_proof_bound_query_count
            }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirPhase {
    Base,
    Auxiliary,
    Quotient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirEncodedOraclePlan {
    pub(in crate::bgv::proof_suite) evaluation_count: usize,
    pub(in crate::bgv::proof_suite) leaf_count: usize,
    pub(in crate::bgv::proof_suite) leaf_width: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirQueryEpochPlan {
    pub(in crate::bgv::proof_suite) epoch_ordinal: u32,
    pub(in crate::bgv::proof_suite) bit_length: usize,
    pub(in crate::bgv::proof_suite) domain_size: usize,
    pub(in crate::bgv::proof_suite) query_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirRoundPlan {
    pub(in crate::bgv::proof_suite) round_ordinal: u32,
    pub(in crate::bgv::proof_suite) encoded_oracle: RowCodeWhirEncodedOraclePlan,
    pub(in crate::bgv::proof_suite) out_of_domain_sample_count: usize,
    pub(in crate::bgv::proof_suite) query_epoch: RowCodeWhirQueryEpochPlan,
    pub(in crate::bgv::proof_suite) following_sumcheck_round_count: usize,
    pub(in crate::bgv::proof_suite) commitment_proof_of_work_bits: usize,
    pub(in crate::bgv::proof_suite) folding_proof_of_work_bits: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirFinalRoundPlan {
    pub(in crate::bgv::proof_suite) encoded_oracle: RowCodeWhirEncodedOraclePlan,
    pub(in crate::bgv::proof_suite) query_epoch: RowCodeWhirQueryEpochPlan,
    pub(in crate::bgv::proof_suite) revealed_coefficient_count: usize,
    pub(in crate::bgv::proof_suite) sumcheck_round_count: usize,
    pub(in crate::bgv::proof_suite) proof_of_work_bits: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirWhirPlan {
    pub(in crate::bgv::proof_suite) initial_out_of_domain_sample_count: usize,
    pub(in crate::bgv::proof_suite) initial_sumcheck_round_count: usize,
    pub(in crate::bgv::proof_suite) rounds: Vec<RowCodeWhirRoundPlan>,
    pub(in crate::bgv::proof_suite) final_round: RowCodeWhirFinalRoundPlan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirOpeningBatchPlan {
    pub(in crate::bgv::proof_suite) point_ordinal: u32,
    pub(in crate::bgv::proof_suite) requested_aggregate_column_ordinals: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirCommitmentRole {
    Aggregate,
    AggregateWidePad,
    WhirRound { round_ordinal: u32 },
    BaseFreshSource,
    BaseFreshPad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirQueryRole {
    Outer,
    Bound,
    WhirEpoch { epoch_ordinal: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirExtensionRole {
    Direct(RowCodeWhirChallenge),
    OpeningBatching,
    MaskedSumcheckEpsilon {
        batch_ordinal: u32,
    },
    MaskedSumcheckRound {
        batch_ordinal: u32,
        round_ordinal: u32,
    },
    RoundCheckpoint {
        round_ordinal: u32,
    },
    RoundCombination {
        round_ordinal: u32,
    },
    BaseCaseBlinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirObservationRole {
    OpeningPoint {
        batch_ordinal: u32,
    },
    OpeningEvaluations {
        batch_ordinal: u32,
    },
    MaskedSumcheckClaim {
        batch_ordinal: u32,
    },
    MaskedSumcheckMaskClaim {
        batch_ordinal: u32,
    },
    MaskedSumcheckPolynomial {
        batch_ordinal: u32,
        round_ordinal: u32,
    },
    SwitchMaskDelta {
        round_ordinal: u32,
    },
    BaseMaskedClaim,
    BaseBlindedSourceMessage,
    BaseBlindedSourceRandomness,
    BaseBlindedPadMessage,
    BaseBlindedPadRandomness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirTranscriptOperation {
    ObserveMaskEvaluations {
        value_count: usize,
    },
    ObserveProtocolSchedule {
        canonical_values: Vec<ProofChallengeExtensionElement>,
    },
    SampleExtension {
        role: RowCodeWhirExtensionRole,
        whir_challenge_ordinal: Option<u32>,
    },
    ObserveCommitment {
        role: RowCodeWhirCommitmentRole,
    },
    SampleDistinctIndices {
        role: RowCodeWhirQueryRole,
        upper_bound: usize,
        output_count: usize,
    },
    ObserveExtensionValues {
        observation_ordinal: u32,
        role: RowCodeWhirObservationRole,
        value_count: usize,
    },
    FinishProofStream,
}

/// One logical verifier message in the checked successor transcript. The
/// construction plan derives this closed catalog from the relation prefix and
/// the row-code WHIR operation order; proof bytes cannot supply an operation,
/// tag, sampler layout, or equation range.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RowCodeWhirOracleEquationOperationKind {
    InitialTranscript,
    CommonRound(CommonProofRound),
    CommonProductChallenge(CommonProofApplicationChallengeGroup),
    CommonExtensionChallenge(CommonProofChallenge),
    RowCodeWhir {
        transcript_operation_ordinal: u32,
        operation: RowCodeWhirTranscriptOperation,
    },
}

/// Compact equation grammar for one contiguous maximum-support range. Product
/// and distinct expansion entries are literal linear-chain edges: each hash
/// answer is both the sampled block and the predecessor of the next addressed
/// block. Variable prover responses first derive one fixed-width response root;
/// the separate absorption edge consumes both the current chain state and that
/// root. A fixed-width Merkle commitment is already a response root and does
/// not add the independent root equation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirOracleEquationRangeKind {
    InitialHeaderRoot,
    InitialAbsorption,
    ResponseRoot,
    ResponseBinding,
    ResponseAbsorption,
    AcceptedChallenge,
    ChallengeHandle,
    ExtensionRejectionChain {
        maximum_rejection_count: u32,
    },
    ProductExpansion {
        maximum_candidate_count: u32,
        block_count_per_candidate: u64,
    },
    DistinctExpansion {
        output_count: u32,
        maximum_block_count_per_output: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirOracleEquationPredecessor {
    Independent,
    FixedZeroState,
    PreviousOperationTerminal { operation_ordinal: u32 },
    PriorRangeTerminal { range_ordinal: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RowCodeWhirOracleEquationRangePlan {
    range_ordinal: u16,
    first_equation_offset: u64,
    equation_count: u64,
    kind: RowCodeWhirOracleEquationRangeKind,
    predecessor: RowCodeWhirOracleEquationPredecessor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RowCodeWhirOracleEquationOperationPlan {
    operation_ordinal: u32,
    predecessor_operation_ordinal: Option<u32>,
    first_equation_slot_ordinal: u64,
    oracle_tag: Option<String>,
    kind: RowCodeWhirOracleEquationOperationKind,
    ranges: Vec<RowCodeWhirOracleEquationRangePlan>,
}

impl RowCodeWhirOracleEquationOperationPlan {
    fn maximum_equation_count(&self) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.ranges.iter().try_fold(0_u64, |total, range| {
            total
                .checked_add(range.equation_count)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
        })
    }
}

/// Complete maximum-support oracle-equation catalog for one checked
/// construction plan. Operation zero contains both the canonical typed header
/// root and the first absorption edge from the fixed all-zero predecessor, so
/// the catalog and runtime counter own exactly the same oracle queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirOracleEquationCatalog {
    operations: Vec<RowCodeWhirOracleEquationOperationPlan>,
}

impl RowCodeWhirOracleEquationCatalog {
    fn maximum_equation_count(&self) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.operations.iter().try_fold(0_u64, |total, operation| {
            total
                .checked_add(operation.maximum_equation_count()?)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
        })
    }

    pub(in crate::bgv::proof_suite) fn maximum_transcript_hash_query_count(
        &self,
    ) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.maximum_equation_count()
    }

    pub(in crate::bgv::proof_suite) fn logical_verifier_message_count(
        &self,
    ) -> Result<u64, RowCodeWhirConstructionPlanError> {
        u64::try_from(
            self.operations
                .iter()
                .filter(|operation| {
                    oracle_equation_operation_leaves_pending_challenge(&operation.kind)
                })
                .count(),
        )
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirProofSectionRole {
    RelationCommitment { phase: RowCodeWhirPhase },
    OutOfDomainEvaluations,
    OpeningBatchMaskEvaluations,
    AggregateCommitment,
    AggregateWidePadCommitment,
    PhaseOpenings { phase: RowCodeWhirPhase },
    BoundTreeOpenings { bound_tree_ordinal: u32 },
    AggregateWideOpening,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirProofSectionPlan {
    pub(in crate::bgv::proof_suite) section_ordinal: u32,
    pub(in crate::bgv::proof_suite) role: RowCodeWhirProofSectionRole,
    pub(in crate::bgv::proof_suite) item_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirCheckpointBoundary {
    SourcesAndConstruction,
    PhaseCommitment { phase: RowCodeWhirPhase },
    RelationEvaluationsAndMask,
    AggregateCommitmentsAndQueries,
    WhirRound { round_ordinal: u32 },
    CompletedProofStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirCheckpointPlan {
    pub(in crate::bgv::proof_suite) checkpoint_ordinal: u32,
    pub(in crate::bgv::proof_suite) boundary: RowCodeWhirCheckpointBoundary,
    pub(in crate::bgv::proof_suite) next_transcript_operation_ordinal: u32,
    pub(in crate::bgv::proof_suite) next_proof_section_ordinal: u32,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum RowCodeWhirOpeningFrontierRole {
    Phase { phase: RowCodeWhirPhase },
    BoundTree { bound_tree_ordinal: u32 },
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirOpeningFrontierGeometry {
    pub(in crate::bgv::proof_suite) role: RowCodeWhirOpeningFrontierRole,
    pub(in crate::bgv::proof_suite) leaf_count: usize,
    pub(in crate::bgv::proof_suite) query_count: usize,
    pub(in crate::bgv::proof_suite) opened_value_byte_length: usize,
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
    evaluation_coset_offset: u64,
    pub(super) opening_degree_bound_exclusive: u64,
    pub(super) proof_privacy_mode: ProofPrivacyMode,
    relation_prefix_schedule: CommonProofRelationPrefixSchedule,
    pub(super) requested_source_column_ordinals: Vec<u32>,
    pub(super) base_phase: Option<RowCodeWhirTracePhasePlan>,
    pub(super) auxiliary_phase: Option<RowCodeWhirTracePhasePlan>,
    pub(super) quotient_phase: RowCodeWhirQuotientPhasePlan,
    pub(super) bound_trees: Vec<RowCodeWhirBoundTreePlan>,
    pub(super) bound_reduction_blocks: Vec<RowCodeWhirBoundReductionBlockPlan>,
    pub(super) aggregate_column_roles: Vec<RowCodeWhirAggregateColumnRole>,
    pub(super) phase_order: Vec<RowCodeWhirPhase>,
    pub(super) bound_opening_column_ordinals: Vec<u32>,
    pub(super) whir: RowCodeWhirWhirPlan,
    pub(super) opening_batches: Vec<RowCodeWhirOpeningBatchPlan>,
    pub(super) transcript_operations: Vec<RowCodeWhirTranscriptOperation>,
    pub(super) proof_sections: Vec<RowCodeWhirProofSectionPlan>,
    pub(super) checkpoints: Vec<RowCodeWhirCheckpointPlan>,
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
        let variant = artifact
            .compiled_plan()
            .select_variant(schedule_position, top_count)?;
        let parameters = RowCodeWhirSelectedParameters::for_selected_variant_geometry(variant)?;
        Self::for_context_variant(
            artifact,
            &context,
            schedule_position,
            top_count,
            parameters,
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
        let relation_prefix_schedule = variant.common_proof_relation_prefix_schedule(context)?;

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
        if aggregate_column_roles.is_empty()
            || aggregate_column_roles.len() > aggregate_table_width_from_parameters(parameters)?
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }

        let mut phase_order = Vec::with_capacity(3);
        if base_phase.is_some() {
            phase_order.push(RowCodeWhirPhase::Base);
        }
        if auxiliary_phase.is_some() {
            phase_order.push(RowCodeWhirPhase::Auxiliary);
        }
        phase_order.push(RowCodeWhirPhase::Quotient);
        let bound_opening_column_ordinals = bound_opening_column_ordinals(variant)?;
        let (whir, protocol_schedule) =
            super::aggregate_wide_pcs::derive_aggregate_wide_whir_plan(parameters)
                .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        let opening_batches =
            opening_batch_plans(&aggregate_column_roles, &bound_reduction_blocks, parameters)?;
        let transcript_operations =
            transcript_operation_catalog(RowCodeWhirTranscriptCatalogInput {
                proof_privacy_mode: variant.proof_privacy_mode(),
                base_phase: base_phase.as_ref(),
                auxiliary_phase: auxiliary_phase.as_ref(),
                quotient_phase: &quotient_phase,
                bound_opening_column_ordinals: &bound_opening_column_ordinals,
                bound_trees: &bound_trees,
                bound_reduction_blocks: &bound_reduction_blocks,
                aggregate_column_roles: &aggregate_column_roles,
                opening_batches: &opening_batches,
                whir: &whir,
                protocol_schedule,
                parameters,
            })?;
        let proof_sections = proof_section_plans(
            &phase_order,
            variant.ordered_opening_claims().len(),
            &bound_trees,
            &bound_reduction_blocks,
            variant.proof_privacy_mode(),
            &quotient_phase,
            parameters,
        )?;
        let checkpoints =
            checkpoint_plans(&phase_order, &transcript_operations, &proof_sections, &whir)?;

        Ok(Self {
            application_statement_schema_identifier,
            schedule_position,
            top_count,
            relation_plan_hash: artifact.canonical_plan_hash(),
            relation_plan_variant_hash: variant.canonical_hash()?,
            trace_domain_size: variant.trace_domain_size(),
            evaluation_domain_size: variant.evaluation_domain_size(),
            evaluation_coset_offset: context.evaluation_coset_offset,
            opening_degree_bound_exclusive: variant.opening_degree_bound_exclusive(),
            proof_privacy_mode: variant.proof_privacy_mode(),
            relation_prefix_schedule,
            requested_source_column_ordinals: requested_pre_challenge_source_column_ordinals(
                variant,
            )?,
            base_phase,
            auxiliary_phase,
            quotient_phase,
            bound_trees,
            bound_reduction_blocks,
            aggregate_column_roles,
            phase_order,
            bound_opening_column_ordinals,
            whir,
            opening_batches,
            transcript_operations,
            proof_sections,
            checkpoints,
            parameters,
        })
    }

    pub(in crate::bgv::proof_suite) fn oracle_equation_catalog(
        &self,
    ) -> Result<RowCodeWhirOracleEquationCatalog, RowCodeWhirConstructionPlanError> {
        oracle_equation_catalog_for_plan(self)
    }

    #[cfg(test)]
    fn linear_bcs_transcript_plan(
        &self,
    ) -> Result<linear_bcs_transcript::LinearBcsTranscriptPlan, RowCodeWhirConstructionPlanError>
    {
        linear_bcs_transcript::derive_linear_bcs_transcript_plan(self)
    }

    #[cfg(test)]
    fn linear_bcs_transcript_plan_hash(
        &self,
    ) -> Result<[u8; 64], RowCodeWhirConstructionPlanError> {
        self.linear_bcs_transcript_plan()?.canonical_hash()
    }

    #[cfg(test)]
    fn linear_bcs_hash_query_accounting(
        &self,
    ) -> Result<linear_bcs_transcript::LinearBcsHashQueryAccounting, RowCodeWhirConstructionPlanError>
    {
        self.linear_bcs_transcript_plan()?.hash_query_accounting()
    }

    pub(in crate::bgv::proof_suite) fn quotient_computation_evaluation_domain(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<ProofEvaluationDomain, RowCodeWhirConstructionPlanError> {
        if context.quotient_component_count != self.quotient_phase.quotient_component_count
            || context.quotient_component_degree_bound_exclusive
                != self
                    .quotient_phase
                    .quotient_component_degree_bound_exclusive
            || context.evaluation_coset_offset != self.evaluation_coset_offset
            || context.base_field_modulus != PROOF_BASE_FIELD_MODULUS
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }

        let row_code_domain_size = usize::try_from(self.evaluation_domain_size)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let row_code_domain =
            ProofEvaluationDomain::new(row_code_domain_size, self.evaluation_coset_offset)
                .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        if row_code_domain.generator().canonical() != context.evaluation_domain_generator
            || self.trace_domain_size == 0
            || !self.trace_domain_size.is_power_of_two()
            || !self
                .evaluation_domain_size
                .is_multiple_of(self.trace_domain_size)
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }

        let minimum_quotient_domain_size = self.trace_domain_size.max(
            self.quotient_phase
                .quotient_component_degree_bound_exclusive,
        );
        let quotient_domain_size = minimum_quotient_domain_size
            .checked_next_power_of_two()
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        if quotient_domain_size > self.evaluation_domain_size
            || !quotient_domain_size.is_multiple_of(self.trace_domain_size)
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        ProofEvaluationDomain::new(
            usize::try_from(quotient_domain_size)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            self.evaluation_coset_offset,
        )
        .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
    }

    fn canonical_oracle_equation_catalog_bytes(
        &self,
    ) -> Result<Vec<u8>, RowCodeWhirConstructionPlanError> {
        encode_oracle_equation_catalog(&self.oracle_equation_catalog()?)
    }

    pub(in crate::bgv::proof_suite) fn oracle_equation_catalog_hash(
        &self,
    ) -> Result<[u8; 64], RowCodeWhirConstructionPlanError> {
        let canonical_bytes = self.canonical_oracle_equation_catalog_bytes()?;
        Ok(hash_framed_parts_512(
            ROW_CODE_WHIR_ORACLE_EQUATION_CATALOG_HASH_DOMAIN,
            &[&canonical_bytes],
        ))
    }

    pub(in crate::bgv::proof_suite) fn canonical_identity_bytes(
        &self,
    ) -> Result<Vec<u8>, RowCodeWhirConstructionPlanError> {
        let mut encoder = RowCodeWhirConstructionPlanIdentityEncoder::default();
        encoder.push_u16(ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_ENCODING_VERSION);
        encoder.push_u16(ROW_CODE_WHIR_AGGREGATE_LEAF_STATE_BYTE_LENGTH);
        encoder.push_u16(ROW_CODE_WHIR_MERKLE_DIGEST_BYTE_LENGTH);
        encoder.push_u16(self.application_statement_schema_identifier);
        encoder.push_optional_u32(self.schedule_position);
        encoder.push_optional_u16(self.top_count);
        encoder.push_bytes(&self.relation_plan_hash)?;
        encoder.push_bytes(&self.relation_plan_variant_hash)?;
        encoder.push_u64(self.trace_domain_size);
        encoder.push_u64(self.evaluation_domain_size);
        encoder.push_u64(self.evaluation_coset_offset);
        encoder.push_u64(self.opening_degree_bound_exclusive);
        encoder.push_u16(self.proof_privacy_mode as u16);
        encoder.push_bytes(
            &self
                .relation_prefix_schedule
                .canonical_identity_bytes()
                .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?,
        )?;

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

        encoder.push_length(self.phase_order.len())?;
        for phase in &self.phase_order {
            encoder.push_u16(row_code_whir_phase_tag(*phase));
        }
        encoder.push_length(self.bound_opening_column_ordinals.len())?;
        for column_ordinal in &self.bound_opening_column_ordinals {
            encoder.push_u32(*column_ordinal);
        }
        encode_whir_plan(&mut encoder, &self.whir)?;
        encoder.push_length(self.opening_batches.len())?;
        for batch in &self.opening_batches {
            encoder.push_u32(batch.point_ordinal);
            encoder.push_length(batch.requested_aggregate_column_ordinals.len())?;
            for column_ordinal in &batch.requested_aggregate_column_ordinals {
                encoder.push_u32(*column_ordinal);
            }
        }
        encoder.push_bytes(&self.canonical_oracle_equation_catalog_bytes()?)?;
        encoder.push_length(self.proof_sections.len())?;
        for section in &self.proof_sections {
            encode_proof_section(&mut encoder, *section)?;
        }
        encode_selected_parameters(&mut encoder, self.parameters)?;
        Ok(encoder.finish())
    }

    pub(in crate::bgv::proof_suite) fn canonical_checkpoint_schedule_bytes(
        &self,
    ) -> Result<Vec<u8>, RowCodeWhirConstructionPlanError> {
        let mut encoder = RowCodeWhirConstructionPlanIdentityEncoder::default();
        encoder.push_length(self.checkpoints.len())?;
        for checkpoint in &self.checkpoints {
            encode_checkpoint(&mut encoder, *checkpoint)?;
        }
        Ok(encoder.finish())
    }

    pub(in crate::bgv::proof_suite) const fn relation_plan_hash(&self) -> [u8; 64] {
        self.relation_plan_hash
    }

    pub(in crate::bgv::proof_suite) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(in crate::bgv::proof_suite) const fn relation_prefix_schedule(
        &self,
    ) -> &CommonProofRelationPrefixSchedule {
        &self.relation_prefix_schedule
    }

    pub(in crate::bgv::proof_suite) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(in crate::bgv::proof_suite) const fn selected_parameters(
        &self,
    ) -> RowCodeWhirSelectedParameters {
        self.parameters
    }

    pub(in crate::bgv::proof_suite) const fn outer_query_count(&self) -> usize {
        self.parameters.outer_query_count
    }

    pub(in crate::bgv::proof_suite) fn phase_row_count(
        &self,
        phase: RowCodeWhirPhase,
    ) -> Option<usize> {
        match phase {
            RowCodeWhirPhase::Base => self.base_phase.as_ref().map(|plan| plan.rows.len()),
            RowCodeWhirPhase::Auxiliary => {
                self.auxiliary_phase.as_ref().map(|plan| plan.rows.len())
            }
            RowCodeWhirPhase::Quotient => Some(self.quotient_phase.rows.len()),
        }
    }

    pub(in crate::bgv::proof_suite) fn phase_encoded_column_count(
        &self,
        phase: RowCodeWhirPhase,
    ) -> Option<usize> {
        match phase {
            RowCodeWhirPhase::Base => self
                .base_phase
                .as_ref()
                .map(|plan| plan.geometry.encoded_column_count),
            RowCodeWhirPhase::Auxiliary => self
                .auxiliary_phase
                .as_ref()
                .map(|plan| plan.geometry.encoded_column_count),
            RowCodeWhirPhase::Quotient => Some(self.quotient_phase.geometry.encoded_column_count),
        }
    }

    /// Whether this construction borrows a positively verified VSS
    /// low-degree result instead of proving every bound tree directly.
    ///
    /// The authenticated transcript-prefix handoff is required exactly for
    /// this construction property. Other proof families build their prefix
    /// directly from the canonical proof header and checked construction plan.
    pub(in crate::bgv::proof_suite) fn requires_verified_vss_bound_prerequisite(&self) -> bool {
        self.bound_trees.iter().any(|tree| {
            tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired
        })
    }

    /// Whether this construction reuses an earlier positive low-degree result
    /// for exact setup-polynomial input roots.
    pub(in crate::bgv::proof_suite) fn requires_verified_setup_polynomial_bound_prerequisite(
        &self,
    ) -> bool {
        self.bound_trees.iter().any(|tree| {
            tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired
        })
    }

    /// Rechecks and binds the exact eight direct VSS certificates borrowed by
    /// the selected same-secret relation. This digest is deliberately narrower
    /// than the complete construction identity: it records the certificate
    /// trees and their owning direct-reduction block so an evidence token cannot
    /// be minted from a plan with merely compatible headline dimensions.
    pub(in crate::bgv::proof_suite) fn selected_vss_low_degree_certificate_geometry_digest(
        &self,
    ) -> Result<[u8; 64], RowCodeWhirConstructionPlanError> {
        if self.application_statement_schema_identifier
            != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            || self.schedule_position.is_some()
            || self.top_count.is_some()
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }

        let relation_input = selected_committed_material_relation_plan_input()?;
        let sharing_limb_count = relation_input.sharing_data_modulus_indices.len();
        let reconstruction_threshold = usize::from(relation_input.threshold);
        let participant_count = usize::from(relation_input.participant_count);
        let roots_per_limb = reconstruction_threshold
            .checked_add(participant_count)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        let material_trace_packing_factor =
            usize::try_from(COMMITTED_MATERIAL_TRACE_PACKING_FACTOR)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        if sharing_limb_count != SELECTED_VSS_LOW_DEGREE_CERTIFICATE_ROOT_COUNT
            || relation_input.material_column_degree_bound_exclusive
                != SELECTED_VSS_LOW_DEGREE_CERTIFICATE_SOURCE_DEGREE_BOUND_EXCLUSIVE
            || reconstruction_threshold == 0
            || participant_count == 0
            || self.parameters.direct_bound_query_count == 0
            || self.bound_trees.is_empty()
            || self.bound_trees.iter().any(|tree| {
                tree.construction_kind != BoundTreeConstructionKind::CommittedMaterial
                    || tree.root_use != BoundTreeRootUse::Output
                    || tree.low_degree_mode != RowCodeWhirBoundLowDegreeMode::Direct
                    || tree.query_count != self.parameters.direct_bound_query_count
                    || tree.ordered_columns.len() != material_trace_packing_factor
                    || tree.ordered_columns.iter().any(|column| {
                        column.source_degree_bound_exclusive
                            != relation_input.material_column_degree_bound_exclusive
                    })
            })
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }

        let selected_root_source_ordinals = (0..sharing_limb_count)
            .map(|sharing_limb_ordinal| {
                sharing_limb_ordinal
                    .checked_mul(roots_per_limb)
                    .and_then(|ordinal| u32::try_from(ordinal).ok())
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut selected_trees = Vec::with_capacity(selected_root_source_ordinals.len());
        for expected_root_source_ordinal in &selected_root_source_ordinals {
            let mut matching_trees = self
                .bound_trees
                .iter()
                .filter(|tree| tree.expected_root_source_ordinal == *expected_root_source_ordinal);
            let tree = matching_trees
                .next()
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
            if matching_trees.next().is_some() {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
            selected_trees.push(tree);
        }

        let mut matching_blocks = self.bound_reduction_blocks.iter().filter(|block| {
            block.low_degree_mode == RowCodeWhirBoundLowDegreeMode::Direct
                && block.maximum_source_degree_bound_exclusive
                    == relation_input.material_column_degree_bound_exclusive
                && block.query_count == self.parameters.direct_bound_query_count
                && selected_trees.iter().all(|tree| {
                    block
                        .ordered_bound_tree_ordinals
                        .contains(&tree.bound_tree_ordinal)
                })
        });
        let direct_certificate_block = matching_blocks
            .next()
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        if matching_blocks.next().is_some()
            || direct_certificate_block.ordered_bound_tree_ordinals.len() != self.bound_trees.len()
            || direct_certificate_block.quotient_degree_bound_exclusive
                != relation_input
                    .material_column_degree_bound_exclusive
                    .checked_sub(1)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }

        let mut encoder = RowCodeWhirConstructionPlanIdentityEncoder::default();
        encoder.push_u16(VERIFIED_VSS_LOW_DEGREE_CERTIFICATE_GEOMETRY_VERSION);
        encoder.push_u16(self.application_statement_schema_identifier);
        encoder.push_u64(relation_input.material_column_degree_bound_exclusive);
        encoder.push_usize(self.parameters.direct_bound_query_count)?;
        encode_u32_sequence(&mut encoder, &selected_root_source_ordinals)?;
        encoder.push_length(selected_trees.len())?;
        for tree in selected_trees {
            encode_bound_tree(&mut encoder, tree)?;
        }
        encode_bound_reduction_block(&mut encoder, direct_certificate_block)?;
        Ok(hash_framed_parts_512(
            VERIFIED_VSS_LOW_DEGREE_CERTIFICATE_GEOMETRY_DOMAIN,
            &[&encoder.finish()],
        ))
    }

    #[cfg(test)]
    pub(in crate::bgv::proof_suite) fn bound_tree_query_count(
        &self,
        construction_kind: BoundTreeConstructionKind,
        root_use: BoundTreeRootUse,
        expected_root_source_ordinal: u32,
    ) -> Result<usize, RowCodeWhirConstructionPlanError> {
        let mut matching_query_counts = self.bound_trees.iter().filter_map(|tree| {
            (tree.construction_kind == construction_kind
                && tree.root_use == root_use
                && tree.expected_root_source_ordinal == expected_root_source_ordinal)
                .then_some(tree.query_count)
        });
        let query_count = matching_query_counts
            .next()
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        if matching_query_counts.next().is_some() {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        Ok(query_count)
    }

    pub(in crate::bgv::proof_suite) const fn whir_plan(&self) -> &RowCodeWhirWhirPlan {
        &self.whir
    }

    pub(in crate::bgv::proof_suite) const fn aggregate_logical_column_count(&self) -> usize {
        self.aggregate_column_roles.len()
    }

    /// Physical interleaved table width consumed by the selected PCS. Logical
    /// aggregate roles occupy the leading columns and every remaining column
    /// is canonically zero. Accounting must use this width, not the number of
    /// candidate-specific logical roles.
    pub(in crate::bgv::proof_suite) fn aggregate_table_width(&self) -> usize {
        aggregate_table_width_from_parameters(self.parameters).unwrap_or(0)
    }

    pub(in crate::bgv::proof_suite) fn opening_batches(&self) -> &[RowCodeWhirOpeningBatchPlan] {
        &self.opening_batches
    }

    pub(in crate::bgv::proof_suite) fn transcript_operations(
        &self,
    ) -> &[RowCodeWhirTranscriptOperation] {
        &self.transcript_operations
    }

    pub(in crate::bgv::proof_suite) fn opening_batch_mask_chunk_evaluation_count(
        &self,
    ) -> Result<usize, RowCodeWhirConstructionPlanError> {
        opening_batch_mask_chunk_evaluation_count(self.proof_privacy_mode, &self.quotient_phase)
    }

    pub(in crate::bgv::proof_suite) fn proof_sections(&self) -> &[RowCodeWhirProofSectionPlan] {
        &self.proof_sections
    }

    pub(in crate::bgv::proof_suite) fn checkpoints(&self) -> &[RowCodeWhirCheckpointPlan] {
        &self.checkpoints
    }

    #[cfg(test)]
    pub(in crate::bgv::proof_suite) fn opening_frontier_geometries(
        &self,
    ) -> Result<Vec<RowCodeWhirOpeningFrontierGeometry>, RowCodeWhirConstructionPlanError> {
        let mut geometries = Vec::new();
        geometries
            .try_reserve_exact(self.phase_order.len() + self.bound_trees.len())
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        for phase in &self.phase_order {
            let row_count = self
                .phase_row_count(*phase)
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
            let leaf_count = self
                .phase_encoded_column_count(*phase)
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
            let opened_value_byte_length = self
                .outer_query_count()
                .checked_mul(row_count)
                .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
            geometries.push(RowCodeWhirOpeningFrontierGeometry {
                role: RowCodeWhirOpeningFrontierRole::Phase { phase: *phase },
                leaf_count,
                query_count: self.outer_query_count(),
                opened_value_byte_length,
            });
        }
        for tree in &self.bound_trees {
            let salt_byte_length = match tree.construction_kind {
                BoundTreeConstructionKind::CommittedMaterial => {
                    crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                }
                BoundTreeConstructionKind::SetupPolynomial => 0,
            };
            let opened_leaf_byte_length = tree
                .ordered_columns
                .len()
                .checked_mul(2)
                .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
                .and_then(|length| length.checked_add(salt_byte_length))
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
            geometries.push(RowCodeWhirOpeningFrontierGeometry {
                role: RowCodeWhirOpeningFrontierRole::BoundTree {
                    bound_tree_ordinal: tree.bound_tree_ordinal,
                },
                leaf_count: tree.leaf_count,
                query_count: tree.query_count,
                opened_value_byte_length: tree
                    .query_count
                    .checked_mul(opened_leaf_byte_length)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?,
            });
        }
        Ok(geometries)
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

fn bound_opening_column_ordinals(
    variant: &RelationPlanVariant,
) -> Result<Vec<u32>, RowCodeWhirConstructionPlanError> {
    let mut column_ordinals = Vec::new();
    for claim in variant.ordered_opening_claims() {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_ordinal = claim
            .column_ordinal()
            .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
        let descriptor = variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            )
            .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
        if matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. }) {
            column_ordinals.push(column_ordinal);
        }
    }
    Ok(column_ordinals)
}

fn opening_batch_plans(
    aggregate_column_roles: &[RowCodeWhirAggregateColumnRole],
    bound_reduction_blocks: &[RowCodeWhirBoundReductionBlockPlan],
    parameters: RowCodeWhirSelectedParameters,
) -> Result<Vec<RowCodeWhirOpeningBatchPlan>, RowCodeWhirConstructionPlanError> {
    let opening_point_column_ordinals = aggregate_column_roles
        .iter()
        .enumerate()
        .filter_map(|(column_index, role)| {
            matches!(role, RowCodeWhirAggregateColumnRole::OpeningPoint { .. })
                .then_some(u32::try_from(column_index))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    if opening_point_column_ordinals.is_empty() {
        return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
    }
    let bound_reduction_column_ordinal = aggregate_column_roles
        .iter()
        .position(|role| matches!(role, RowCodeWhirAggregateColumnRole::BoundReduction))
        .map(u32::try_from)
        .transpose()
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;

    let bound_batch_count = bound_reduction_blocks
        .iter()
        .try_fold(0_usize, |total, block| {
            block
                .query_count
                .checked_mul(2)
                .and_then(|query_count| {
                    query_count.checked_add(1 + block.degree_suffix_prefixes.len())
                })
                .and_then(|block_count| total.checked_add(block_count))
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
        })?;
    let capacity = opening_point_column_ordinals
        .len()
        .checked_add(parameters.outer_query_count)
        .and_then(|count| count.checked_add(bound_batch_count))
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    let mut batches = Vec::with_capacity(capacity);
    let mut push_batch = |requested_aggregate_column_ordinals: Vec<u32>|
     -> Result<(), RowCodeWhirConstructionPlanError> {
        let point_ordinal = u32::try_from(batches.len())
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        batches.push(RowCodeWhirOpeningBatchPlan {
            point_ordinal,
            requested_aggregate_column_ordinals,
        });
        Ok(())
    };
    for column_ordinal in &opening_point_column_ordinals {
        push_batch(vec![*column_ordinal])?;
    }
    for _ in 0..parameters.outer_query_count {
        push_batch(opening_point_column_ordinals.clone())?;
    }
    if !bound_reduction_blocks.is_empty() {
        let bound_reduction_column_ordinal = bound_reduction_column_ordinal
            .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
        for block in bound_reduction_blocks {
            for _ in 0..block
                .query_count
                .checked_mul(2)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?
            {
                push_batch(vec![bound_reduction_column_ordinal])?;
            }
            for _ in 0..=block.degree_suffix_prefixes.len() {
                push_batch(vec![bound_reduction_column_ordinal])?;
            }
        }
    }
    if batches.len() != capacity {
        return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
    }
    Ok(batches)
}

struct RowCodeWhirTranscriptCatalogInput<'a> {
    proof_privacy_mode: ProofPrivacyMode,
    base_phase: Option<&'a RowCodeWhirTracePhasePlan>,
    auxiliary_phase: Option<&'a RowCodeWhirTracePhasePlan>,
    quotient_phase: &'a RowCodeWhirQuotientPhasePlan,
    bound_opening_column_ordinals: &'a [u32],
    bound_trees: &'a [RowCodeWhirBoundTreePlan],
    bound_reduction_blocks: &'a [RowCodeWhirBoundReductionBlockPlan],
    aggregate_column_roles: &'a [RowCodeWhirAggregateColumnRole],
    opening_batches: &'a [RowCodeWhirOpeningBatchPlan],
    whir: &'a RowCodeWhirWhirPlan,
    protocol_schedule: Vec<ProofChallengeExtensionElement>,
    parameters: RowCodeWhirSelectedParameters,
}

#[derive(Default)]
struct RowCodeWhirTranscriptCatalogBuilder {
    operations: Vec<RowCodeWhirTranscriptOperation>,
    next_observation_ordinal: u32,
    next_whir_challenge_ordinal: u32,
}

impl RowCodeWhirTranscriptCatalogBuilder {
    fn push(&mut self, operation: RowCodeWhirTranscriptOperation) {
        self.operations.push(operation);
    }

    fn push_observation(
        &mut self,
        role: RowCodeWhirObservationRole,
        value_count: usize,
    ) -> Result<(), RowCodeWhirConstructionPlanError> {
        self.push(RowCodeWhirTranscriptOperation::ObserveExtensionValues {
            observation_ordinal: self.next_observation_ordinal,
            role,
            value_count,
        });
        self.next_observation_ordinal = self
            .next_observation_ordinal
            .checked_add(1)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        Ok(())
    }

    fn push_whir_extension(
        &mut self,
        role: RowCodeWhirExtensionRole,
    ) -> Result<(), RowCodeWhirConstructionPlanError> {
        self.push(RowCodeWhirTranscriptOperation::SampleExtension {
            role,
            whir_challenge_ordinal: Some(self.next_whir_challenge_ordinal),
        });
        self.next_whir_challenge_ordinal = self
            .next_whir_challenge_ordinal
            .checked_add(1)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        Ok(())
    }
}

fn transcript_operation_catalog(
    input: RowCodeWhirTranscriptCatalogInput<'_>,
) -> Result<Vec<RowCodeWhirTranscriptOperation>, RowCodeWhirConstructionPlanError> {
    let RowCodeWhirTranscriptCatalogInput {
        proof_privacy_mode,
        base_phase,
        auxiliary_phase,
        quotient_phase,
        bound_opening_column_ordinals,
        bound_trees,
        bound_reduction_blocks,
        aggregate_column_roles,
        opening_batches,
        whir,
        protocol_schedule,
        parameters,
    } = input;
    let mut builder = RowCodeWhirTranscriptCatalogBuilder::default();
    if proof_privacy_mode == ProofPrivacyMode::SecretBearing {
        builder.push(RowCodeWhirTranscriptOperation::ObserveMaskEvaluations {
            value_count: opening_batch_mask_chunk_evaluation_count(
                proof_privacy_mode,
                quotient_phase,
            )?,
        });
    }
    builder.push(RowCodeWhirTranscriptOperation::ObserveProtocolSchedule {
        canonical_values: protocol_schedule,
    });
    append_opening_point_transcript_operations(
        &mut builder,
        base_phase,
        auxiliary_phase,
        quotient_phase,
        aggregate_column_roles,
        parameters,
    )?;
    append_bound_opening_weight_transcript_operations(&mut builder, bound_opening_column_ordinals);
    builder.push(RowCodeWhirTranscriptOperation::ObserveCommitment {
        role: RowCodeWhirCommitmentRole::Aggregate,
    });
    builder.push(RowCodeWhirTranscriptOperation::ObserveCommitment {
        role: RowCodeWhirCommitmentRole::AggregateWidePad,
    });
    append_bound_degree_transcript_operations(&mut builder, bound_reduction_blocks, parameters)?;
    builder.push(RowCodeWhirTranscriptOperation::SampleDistinctIndices {
        role: RowCodeWhirQueryRole::Outer,
        upper_bound: quotient_phase.geometry.encoded_column_count,
        output_count: parameters.outer_query_count,
    });
    append_bound_query_transcript_operation(&mut builder, bound_trees, bound_reduction_blocks)?;
    let hiding_configuration = super::hiding_whir::selected_hiding_whir_config(parameters)
        .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    let pad_layout =
        super::aggregate_wide_hiding::AggregateWidePadLayout::derive(&hiding_configuration)
            .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    append_aggregate_wide_initial_transcript_operations(
        &mut builder,
        opening_batches,
        whir,
        &hiding_configuration,
        parameters,
    )?;
    append_aggregate_wide_round_transcript_operations(&mut builder, whir, &hiding_configuration)?;
    append_aggregate_wide_base_transcript_operations(
        &mut builder,
        whir,
        &hiding_configuration,
        pad_layout.message_length(),
    )?;
    builder.push(RowCodeWhirTranscriptOperation::FinishProofStream);
    Ok(builder.operations)
}

struct RowCodeWhirOracleEquationCatalogBuilder {
    operations: Vec<RowCodeWhirOracleEquationOperationPlan>,
    next_equation_slot_ordinal: u64,
    pending_challenge: bool,
}

impl RowCodeWhirOracleEquationCatalogBuilder {
    fn new() -> Result<Self, RowCodeWhirConstructionPlanError> {
        let initial_header_root_range = RowCodeWhirOracleEquationRangePlan {
            range_ordinal: 0,
            first_equation_offset: 0,
            equation_count: 1,
            kind: RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot,
            predecessor: RowCodeWhirOracleEquationPredecessor::Independent,
        };
        let initial_absorption_range = RowCodeWhirOracleEquationRangePlan {
            range_ordinal: 1,
            first_equation_offset: 1,
            equation_count: 1,
            kind: RowCodeWhirOracleEquationRangeKind::InitialAbsorption,
            predecessor: RowCodeWhirOracleEquationPredecessor::FixedZeroState,
        };
        Ok(Self {
            operations: vec![RowCodeWhirOracleEquationOperationPlan {
                operation_ordinal: 0,
                predecessor_operation_ordinal: None,
                first_equation_slot_ordinal: 0,
                oracle_tag: None,
                kind: RowCodeWhirOracleEquationOperationKind::InitialTranscript,
                ranges: vec![initial_header_root_range, initial_absorption_range],
            }],
            next_equation_slot_ordinal: 2,
            pending_challenge: false,
        })
    }

    fn push_response(
        &mut self,
        kind: RowCodeWhirOracleEquationOperationKind,
        oracle_tag: String,
        response_root_is_recomputed: bool,
    ) -> Result<(), RowCodeWhirConstructionPlanError> {
        let previous_operation_ordinal = self.previous_operation_ordinal()?;
        let mut ranges = Vec::new();
        let mut next_offset = 0_u64;
        let chain_predecessor_range_kind = if self.pending_challenge {
            RowCodeWhirOracleEquationRangeKind::AcceptedChallenge
        } else {
            RowCodeWhirOracleEquationRangeKind::ResponseBinding
        };
        push_oracle_equation_range(
            &mut ranges,
            &mut next_offset,
            chain_predecessor_range_kind,
            1,
            RowCodeWhirOracleEquationPredecessor::PreviousOperationTerminal {
                operation_ordinal: previous_operation_ordinal,
            },
        )?;
        if response_root_is_recomputed {
            push_oracle_equation_range(
                &mut ranges,
                &mut next_offset,
                RowCodeWhirOracleEquationRangeKind::ResponseRoot,
                1,
                RowCodeWhirOracleEquationPredecessor::Independent,
            )?;
        }
        push_oracle_equation_range(
            &mut ranges,
            &mut next_offset,
            RowCodeWhirOracleEquationRangeKind::ResponseAbsorption,
            1,
            RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal { range_ordinal: 0 },
        )?;
        self.push_operation(kind, Some(oracle_tag), ranges)?;
        self.pending_challenge = false;
        Ok(())
    }

    fn push_extension_challenge(
        &mut self,
        kind: RowCodeWhirOracleEquationOperationKind,
        oracle_tag: String,
        maximum_candidate_draws: u32,
    ) -> Result<(), RowCodeWhirConstructionPlanError> {
        if maximum_candidate_draws == 0 {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let mut ranges = Vec::new();
        let mut next_offset = 0_u64;
        let handle_predecessor =
            self.push_pending_close_if_needed(&mut ranges, &mut next_offset)?;
        push_oracle_equation_range(
            &mut ranges,
            &mut next_offset,
            RowCodeWhirOracleEquationRangeKind::ChallengeHandle,
            1,
            handle_predecessor,
        )?;
        let maximum_rejection_count = maximum_candidate_draws - 1;
        if maximum_rejection_count > 0 {
            let handle_range_ordinal = u16::try_from(ranges.len() - 1)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            push_oracle_equation_range(
                &mut ranges,
                &mut next_offset,
                RowCodeWhirOracleEquationRangeKind::ExtensionRejectionChain {
                    maximum_rejection_count,
                },
                u64::from(maximum_rejection_count)
                    .checked_mul(2)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?,
                RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal {
                    range_ordinal: handle_range_ordinal,
                },
            )?;
        }
        self.push_operation(kind, Some(oracle_tag), ranges)?;
        self.pending_challenge = true;
        Ok(())
    }

    fn push_product_challenge(
        &mut self,
        group: CommonProofApplicationChallengeGroup,
        oracle_tag: String,
        maximum_candidate_draws: u32,
    ) -> Result<(), RowCodeWhirConstructionPlanError> {
        let candidate_byte_length = group.candidate_byte_length();
        let block_byte_length = u64::try_from(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let block_count_per_candidate = candidate_byte_length
            .checked_div(block_byte_length)
            .filter(|count| *count > 0 && candidate_byte_length.is_multiple_of(block_byte_length))
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        if maximum_candidate_draws == 0 {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let mut ranges = Vec::new();
        let mut next_offset = 0_u64;
        let handle_predecessor =
            self.push_pending_close_if_needed(&mut ranges, &mut next_offset)?;
        push_oracle_equation_range(
            &mut ranges,
            &mut next_offset,
            RowCodeWhirOracleEquationRangeKind::ChallengeHandle,
            1,
            handle_predecessor,
        )?;
        let handle_range_ordinal = u16::try_from(ranges.len() - 1)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let expansion_equation_count = u64::from(maximum_candidate_draws)
            .checked_mul(block_count_per_candidate)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        push_oracle_equation_range(
            &mut ranges,
            &mut next_offset,
            RowCodeWhirOracleEquationRangeKind::ProductExpansion {
                maximum_candidate_count: maximum_candidate_draws,
                block_count_per_candidate,
            },
            expansion_equation_count,
            RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal {
                range_ordinal: handle_range_ordinal,
            },
        )?;
        self.push_operation(
            RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(group),
            Some(oracle_tag),
            ranges,
        )?;
        self.pending_challenge = true;
        Ok(())
    }

    fn push_distinct_challenge(
        &mut self,
        transcript_operation_ordinal: u32,
        operation: RowCodeWhirTranscriptOperation,
        oracle_tag: String,
        output_count: u32,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<(), RowCodeWhirConstructionPlanError> {
        if output_count == 0 || maximum_candidate_draws_per_output == 0 {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let candidates_per_block = FIXED_CHALLENGE_BLOCK_BYTE_LENGTH
            .checked_div(std::mem::size_of::<u64>())
            .filter(|count| *count > 0)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        let maximum_block_count_per_output = usize::try_from(maximum_candidate_draws_per_output)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?
            .div_ceil(candidates_per_block);
        let maximum_block_count_per_output = u64::try_from(maximum_block_count_per_output)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let mut ranges = Vec::new();
        let mut next_offset = 0_u64;
        let handle_predecessor =
            self.push_pending_close_if_needed(&mut ranges, &mut next_offset)?;
        push_oracle_equation_range(
            &mut ranges,
            &mut next_offset,
            RowCodeWhirOracleEquationRangeKind::ChallengeHandle,
            1,
            handle_predecessor,
        )?;
        let handle_range_ordinal = u16::try_from(ranges.len() - 1)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let expansion_equation_count = u64::from(output_count)
            .checked_mul(maximum_block_count_per_output)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        push_oracle_equation_range(
            &mut ranges,
            &mut next_offset,
            RowCodeWhirOracleEquationRangeKind::DistinctExpansion {
                output_count,
                maximum_block_count_per_output,
            },
            expansion_equation_count,
            RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal {
                range_ordinal: handle_range_ordinal,
            },
        )?;
        self.push_operation(
            RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
                transcript_operation_ordinal,
                operation,
            },
            Some(oracle_tag),
            ranges,
        )?;
        self.pending_challenge = true;
        Ok(())
    }

    fn push_pending_close_if_needed(
        &self,
        ranges: &mut Vec<RowCodeWhirOracleEquationRangePlan>,
        next_offset: &mut u64,
    ) -> Result<RowCodeWhirOracleEquationPredecessor, RowCodeWhirConstructionPlanError> {
        let previous_operation_ordinal = self.previous_operation_ordinal()?;
        if !self.pending_challenge {
            return Ok(
                RowCodeWhirOracleEquationPredecessor::PreviousOperationTerminal {
                    operation_ordinal: previous_operation_ordinal,
                },
            );
        }
        push_oracle_equation_range(
            ranges,
            next_offset,
            RowCodeWhirOracleEquationRangeKind::AcceptedChallenge,
            1,
            RowCodeWhirOracleEquationPredecessor::PreviousOperationTerminal {
                operation_ordinal: previous_operation_ordinal,
            },
        )?;
        Ok(RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal { range_ordinal: 0 })
    }

    fn push_operation(
        &mut self,
        kind: RowCodeWhirOracleEquationOperationKind,
        oracle_tag: Option<String>,
        ranges: Vec<RowCodeWhirOracleEquationRangePlan>,
    ) -> Result<(), RowCodeWhirConstructionPlanError> {
        if ranges.is_empty() {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let operation_ordinal = u32::try_from(self.operations.len())
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let predecessor_operation_ordinal = operation_ordinal.checked_sub(1);
        let operation_equation_count = ranges.iter().try_fold(0_u64, |total, range| {
            total
                .checked_add(range.equation_count)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
        })?;
        self.operations
            .push(RowCodeWhirOracleEquationOperationPlan {
                operation_ordinal,
                predecessor_operation_ordinal,
                first_equation_slot_ordinal: self.next_equation_slot_ordinal,
                oracle_tag,
                kind,
                ranges,
            });
        self.next_equation_slot_ordinal = self
            .next_equation_slot_ordinal
            .checked_add(operation_equation_count)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        Ok(())
    }

    fn previous_operation_ordinal(&self) -> Result<u32, RowCodeWhirConstructionPlanError> {
        self.operations
            .len()
            .checked_sub(1)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
    }

    fn finish(self) -> Result<RowCodeWhirOracleEquationCatalog, RowCodeWhirConstructionPlanError> {
        if self.pending_challenge {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let catalog = RowCodeWhirOracleEquationCatalog {
            operations: self.operations,
        };
        validate_oracle_equation_catalog(&catalog)?;
        Ok(catalog)
    }
}

fn push_oracle_equation_range(
    ranges: &mut Vec<RowCodeWhirOracleEquationRangePlan>,
    next_offset: &mut u64,
    kind: RowCodeWhirOracleEquationRangeKind,
    equation_count: u64,
    predecessor: RowCodeWhirOracleEquationPredecessor,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if equation_count == 0 {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let range_ordinal =
        u16::try_from(ranges.len()).map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    ranges.push(RowCodeWhirOracleEquationRangePlan {
        range_ordinal,
        first_equation_offset: *next_offset,
        equation_count,
        kind,
        predecessor,
    });
    *next_offset = next_offset
        .checked_add(equation_count)
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    Ok(())
}

fn oracle_equation_catalog_for_plan(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<RowCodeWhirOracleEquationCatalog, RowCodeWhirConstructionPlanError> {
    let mut builder = RowCodeWhirOracleEquationCatalogBuilder::new()?;
    let relation_schedule = &plan.relation_prefix_schedule;
    let application_schema_identifier = plan.application_statement_schema_identifier;
    let maximum_candidate_draws = relation_schedule.maximum_candidate_draws_per_output();
    if maximum_candidate_draws
        != plan
            .parameters
            .maximum_fiat_shamir_candidate_draws_per_output
        || maximum_candidate_draws != PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }

    for tree_ordinal in relation_schedule.ordered_base_tree_ordinals() {
        let round = CommonProofRound::BaseRoot {
            tree_ordinal: *tree_ordinal,
        };
        builder.push_response(
            RowCodeWhirOracleEquationOperationKind::CommonRound(round),
            round.tag(application_schema_identifier),
            false,
        )?;
    }
    for group in relation_schedule.ordered_application_challenge_groups() {
        builder.push_product_challenge(
            *group,
            group.challenge().tag(application_schema_identifier),
            maximum_candidate_draws,
        )?;
    }
    for tree_ordinal in relation_schedule.ordered_auxiliary_tree_ordinals() {
        let round = CommonProofRound::AuxiliaryRoot {
            tree_ordinal: *tree_ordinal,
        };
        builder.push_response(
            RowCodeWhirOracleEquationOperationKind::CommonRound(round),
            round.tag(application_schema_identifier),
            false,
        )?;
    }
    for constraint_ordinal in 0..relation_schedule.composition_challenge_count() {
        let challenge = CommonProofChallenge::Composition { constraint_ordinal };
        builder.push_extension_challenge(
            RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(challenge),
            challenge.tag(application_schema_identifier),
            maximum_candidate_draws,
        )?;
    }
    let quotient_round = CommonProofRound::RowCodeWhirQuotientPhaseRoot;
    builder.push_response(
        RowCodeWhirOracleEquationOperationKind::CommonRound(quotient_round),
        quotient_round.tag(application_schema_identifier),
        false,
    )?;
    for point_ordinal in 0..relation_schedule.out_of_domain_point_count() {
        let challenge = CommonProofChallenge::OutOfDomainPoint { point_ordinal };
        builder.push_extension_challenge(
            RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(challenge),
            challenge.tag(application_schema_identifier),
            maximum_candidate_draws,
        )?;
    }
    let out_of_domain_round = CommonProofRound::OutOfDomainEvaluations;
    builder.push_response(
        RowCodeWhirOracleEquationOperationKind::CommonRound(out_of_domain_round),
        out_of_domain_round.tag(application_schema_identifier),
        true,
    )?;
    for (operation_index, operation) in plan.transcript_operations.iter().enumerate() {
        let transcript_operation_ordinal = u32::try_from(operation_index)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let operation_kind = RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            transcript_operation_ordinal,
            operation: operation.clone(),
        };
        match operation {
            RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. }
            | RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. }
            | RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
            | RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. }
            | RowCodeWhirTranscriptOperation::FinishProofStream => builder.push_response(
                operation_kind,
                row_code_whir_operation_oracle_tag(operation)?,
                !matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
                ),
            )?,
            RowCodeWhirTranscriptOperation::SampleExtension { .. } => builder
                .push_extension_challenge(
                    operation_kind,
                    row_code_whir_operation_oracle_tag(operation)?,
                    maximum_candidate_draws,
                )?,
            RowCodeWhirTranscriptOperation::SampleDistinctIndices { output_count, .. } => builder
                .push_distinct_challenge(
                transcript_operation_ordinal,
                operation.clone(),
                row_code_whir_operation_oracle_tag(operation)?,
                u32::try_from(*output_count)
                    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                maximum_candidate_draws,
            )?,
        }
    }
    builder.finish()
}

fn row_code_whir_operation_oracle_tag(
    operation: &RowCodeWhirTranscriptOperation,
) -> Result<String, RowCodeWhirConstructionPlanError> {
    match operation {
        RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. } => {
            Ok("row-code-whir/opening-batch-mask-evaluations".to_owned())
        }
        RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. } => {
            Ok("row-code-whir/protocol-schedule".to_owned())
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(challenge),
            whir_challenge_ordinal: None,
        } => Ok(challenge.tag()),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role,
            whir_challenge_ordinal: Some(challenge_ordinal),
        } if !matches!(role, RowCodeWhirExtensionRole::Direct(_)) => Ok(format!(
            "row-code-whir/whir-challenge/{challenge_ordinal:08x}"
        )),
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::Aggregate,
        } => Ok("row-code-whir/aggregate-commitment".to_owned()),
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::AggregateWidePad,
        } => Ok("row-code-whir/aggregate-wide-pad-commitment".to_owned()),
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::WhirRound { round_ordinal },
        } => Ok(format!("row-code-whir/whir-commitment/{round_ordinal:08x}")),
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::BaseFreshSource,
        } => Ok("row-code-whir/base-fresh-source-commitment".to_owned()),
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::BaseFreshPad,
        } => Ok("row-code-whir/base-fresh-pad-commitment".to_owned()),
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role,
            upper_bound,
            output_count,
        } => {
            let upper_bound_u64 = u64::try_from(*upper_bound)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            let output_count_u64 = u64::try_from(*output_count)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            match role {
                RowCodeWhirQueryRole::Outer => Ok(format!(
                    "{}/{upper_bound_u64:016x}/{output_count_u64:016x}",
                    RowCodeWhirChallenge::OuterQueryVector.tag(),
                )),
                RowCodeWhirQueryRole::Bound => Ok(format!(
                    "{}/{upper_bound_u64:016x}/{output_count_u64:016x}",
                    RowCodeWhirChallenge::BoundQueryVector.tag(),
                )),
                RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal }
                    if *upper_bound > 0 && upper_bound.is_power_of_two() =>
                {
                    let bit_length = upper_bound.ilog2();
                    Ok(format!(
                        "row-code-whir/whir-query-vector/{epoch_ordinal:08x}/{bit_length:04x}/{output_count_u64:016x}"
                    ))
                }
                RowCodeWhirQueryRole::WhirEpoch { .. } => {
                    Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
                }
            }
        }
        RowCodeWhirTranscriptOperation::ObserveExtensionValues {
            observation_ordinal,
            ..
        } => Ok(format!(
            "row-code-whir/whir-values/{observation_ordinal:08x}"
        )),
        RowCodeWhirTranscriptOperation::FinishProofStream => {
            Ok("row-code-whir/final-proof-openings".to_owned())
        }
        RowCodeWhirTranscriptOperation::SampleExtension { .. } => {
            Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
        }
    }
}

fn oracle_equation_operation_leaves_pending_challenge(
    kind: &RowCodeWhirOracleEquationOperationKind,
) -> bool {
    match kind {
        RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(_)
        | RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(_) => true,
        RowCodeWhirOracleEquationOperationKind::RowCodeWhir { operation, .. } => matches!(
            operation,
            RowCodeWhirTranscriptOperation::SampleExtension { .. }
                | RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. }
        ),
        RowCodeWhirOracleEquationOperationKind::InitialTranscript
        | RowCodeWhirOracleEquationOperationKind::CommonRound(_) => false,
    }
}

fn validate_oracle_equation_operation_shape(
    operation: &RowCodeWhirOracleEquationOperationPlan,
    previous_operation_left_pending_challenge: bool,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    match &operation.kind {
        RowCodeWhirOracleEquationOperationKind::InitialTranscript => {
            if operation.ranges.len() != 2
                || operation.ranges[0].kind != RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot
                || operation.ranges[1].kind != RowCodeWhirOracleEquationRangeKind::InitialAbsorption
            {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
        }
        RowCodeWhirOracleEquationOperationKind::CommonRound(round) => {
            validate_response_equation_ranges(
                &operation.ranges,
                previous_operation_left_pending_challenge,
                common_round_response_root_is_recomputed(*round),
            )?;
        }
        RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(group) => {
            let expansion_range_index = validate_challenge_equation_range_prefix(
                &operation.ranges,
                previous_operation_left_pending_challenge,
            )?;
            let block_byte_length = u64::try_from(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            let block_count_per_candidate = group
                .candidate_byte_length()
                .checked_div(block_byte_length)
                .filter(|block_count| {
                    *block_count > 0
                        && group
                            .candidate_byte_length()
                            .is_multiple_of(block_byte_length)
                })
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
            if operation.ranges.len() != expansion_range_index + 1
                || operation.ranges[expansion_range_index].kind
                    != (RowCodeWhirOracleEquationRangeKind::ProductExpansion {
                        maximum_candidate_count:
                            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
                        block_count_per_candidate,
                    })
            {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
        }
        RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(_) => {
            validate_extension_challenge_equation_ranges(
                &operation.ranges,
                previous_operation_left_pending_challenge,
            )?;
        }
        RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            operation: transcript_operation,
            ..
        } => match transcript_operation {
            RowCodeWhirTranscriptOperation::SampleExtension { .. } => {
                validate_extension_challenge_equation_ranges(
                    &operation.ranges,
                    previous_operation_left_pending_challenge,
                )?;
            }
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                upper_bound,
                output_count,
                ..
            } => {
                let expansion_range_index = validate_challenge_equation_range_prefix(
                    &operation.ranges,
                    previous_operation_left_pending_challenge,
                )?;
                if *upper_bound == 0
                    || !upper_bound.is_power_of_two()
                    || *output_count == 0
                    || *output_count > *upper_bound
                {
                    return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
                }
                let candidates_per_block = FIXED_CHALLENGE_BLOCK_BYTE_LENGTH
                    .checked_div(std::mem::size_of::<u64>())
                    .filter(|candidate_count| *candidate_count > 0)
                    .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
                let maximum_block_count_per_output =
                    usize::try_from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT)
                        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?
                        .div_ceil(candidates_per_block);
                if operation.ranges.len() != expansion_range_index + 1
                    || operation.ranges[expansion_range_index].kind
                        != (RowCodeWhirOracleEquationRangeKind::DistinctExpansion {
                            output_count: u32::try_from(*output_count)
                                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                            maximum_block_count_per_output: u64::try_from(
                                maximum_block_count_per_output,
                            )
                            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                        })
                {
                    return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
                }
            }
            RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. }
            | RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. }
            | RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. }
            | RowCodeWhirTranscriptOperation::FinishProofStream => {
                validate_response_equation_ranges(
                    &operation.ranges,
                    previous_operation_left_pending_challenge,
                    true,
                )?;
            }
            RowCodeWhirTranscriptOperation::ObserveCommitment { .. } => {
                validate_response_equation_ranges(
                    &operation.ranges,
                    previous_operation_left_pending_challenge,
                    false,
                )?;
            }
        },
    }
    Ok(())
}

fn common_round_response_root_is_recomputed(round: CommonProofRound) -> bool {
    !matches!(
        round,
        CommonProofRound::BaseRoot { .. }
            | CommonProofRound::AuxiliaryRoot { .. }
            | CommonProofRound::RowCodeWhirQuotientPhaseRoot
    )
}

fn validate_response_equation_ranges(
    ranges: &[RowCodeWhirOracleEquationRangePlan],
    previous_operation_left_pending_challenge: bool,
    response_root_is_recomputed: bool,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let expected_chain_predecessor_kind = if previous_operation_left_pending_challenge {
        RowCodeWhirOracleEquationRangeKind::AcceptedChallenge
    } else {
        RowCodeWhirOracleEquationRangeKind::ResponseBinding
    };
    let response_absorption_range_index = usize::from(response_root_is_recomputed) + 1;
    let has_exact_shape = ranges.len() == response_absorption_range_index + 1
        && ranges[0].kind == expected_chain_predecessor_kind
        && (!response_root_is_recomputed
            || ranges[1].kind == RowCodeWhirOracleEquationRangeKind::ResponseRoot)
        && ranges[response_absorption_range_index].kind
            == RowCodeWhirOracleEquationRangeKind::ResponseAbsorption
        && ranges[response_absorption_range_index].predecessor
            == RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal { range_ordinal: 0 };
    if !has_exact_shape {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(())
}

fn validate_challenge_equation_range_prefix(
    ranges: &[RowCodeWhirOracleEquationRangePlan],
    previous_operation_left_pending_challenge: bool,
) -> Result<usize, RowCodeWhirConstructionPlanError> {
    let handle_range_index = usize::from(previous_operation_left_pending_challenge);
    if ranges.len() <= handle_range_index
        || (previous_operation_left_pending_challenge
            && ranges[0].kind != RowCodeWhirOracleEquationRangeKind::AcceptedChallenge)
        || ranges[handle_range_index].kind != RowCodeWhirOracleEquationRangeKind::ChallengeHandle
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(handle_range_index + 1)
}

fn validate_extension_challenge_equation_ranges(
    ranges: &[RowCodeWhirOracleEquationRangePlan],
    previous_operation_left_pending_challenge: bool,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let rejection_range_index = validate_challenge_equation_range_prefix(
        ranges,
        previous_operation_left_pending_challenge,
    )?;
    let maximum_rejection_count = PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
        .checked_sub(1)
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    if ranges.len() != rejection_range_index + 1
        || ranges[rejection_range_index].kind
            != (RowCodeWhirOracleEquationRangeKind::ExtensionRejectionChain {
                maximum_rejection_count,
            })
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(())
}

fn validate_oracle_equation_catalog(
    catalog: &RowCodeWhirOracleEquationCatalog,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if catalog.operations.is_empty() {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let mut next_equation_slot_ordinal = 0_u64;
    let mut previous_operation_left_pending_challenge = false;
    for (operation_index, operation) in catalog.operations.iter().enumerate() {
        let expected_operation_ordinal = u32::try_from(operation_index)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        let expected_predecessor = expected_operation_ordinal.checked_sub(1);
        if operation.operation_ordinal != expected_operation_ordinal
            || operation.predecessor_operation_ordinal != expected_predecessor
            || operation.first_equation_slot_ordinal != next_equation_slot_ordinal
            || operation.ranges.is_empty()
            || (operation_index == 0)
                != matches!(
                    &operation.kind,
                    RowCodeWhirOracleEquationOperationKind::InitialTranscript
                )
            || (operation_index == 0) != operation.oracle_tag.is_none()
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let mut next_range_offset = 0_u64;
        for (range_index, range) in operation.ranges.iter().enumerate() {
            let expected_range_ordinal = u16::try_from(range_index)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
            if range.range_ordinal != expected_range_ordinal
                || range.first_equation_offset != next_range_offset
                || range.equation_count == 0
            {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
            match range.predecessor {
                RowCodeWhirOracleEquationPredecessor::Independent
                    if matches!(
                        range.kind,
                        RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot
                            | RowCodeWhirOracleEquationRangeKind::ResponseRoot
                    ) => {}
                RowCodeWhirOracleEquationPredecessor::FixedZeroState
                    if operation_index == 0
                        && range_index == 1
                        && range.kind == RowCodeWhirOracleEquationRangeKind::InitialAbsorption => {}
                RowCodeWhirOracleEquationPredecessor::PreviousOperationTerminal {
                    operation_ordinal,
                } if range_index == 0 && Some(operation_ordinal) == expected_predecessor => {}
                RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal { range_ordinal }
                    if range_index > 0
                        && (range_ordinal.checked_add(1) == Some(expected_range_ordinal)
                            || (range.kind
                                == RowCodeWhirOracleEquationRangeKind::ResponseAbsorption
                                && range_ordinal == 0)) => {}
                _ => return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry),
            }
            let expected_equation_count = match range.kind {
                RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot
                | RowCodeWhirOracleEquationRangeKind::InitialAbsorption
                | RowCodeWhirOracleEquationRangeKind::ResponseRoot
                | RowCodeWhirOracleEquationRangeKind::ResponseBinding
                | RowCodeWhirOracleEquationRangeKind::ResponseAbsorption
                | RowCodeWhirOracleEquationRangeKind::AcceptedChallenge
                | RowCodeWhirOracleEquationRangeKind::ChallengeHandle => 1,
                RowCodeWhirOracleEquationRangeKind::ExtensionRejectionChain {
                    maximum_rejection_count,
                } => u64::from(maximum_rejection_count)
                    .checked_mul(2)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?,
                RowCodeWhirOracleEquationRangeKind::ProductExpansion {
                    maximum_candidate_count,
                    block_count_per_candidate,
                } => u64::from(maximum_candidate_count)
                    .checked_mul(block_count_per_candidate)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?,
                RowCodeWhirOracleEquationRangeKind::DistinctExpansion {
                    output_count,
                    maximum_block_count_per_output,
                } => u64::from(output_count)
                    .checked_mul(maximum_block_count_per_output)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?,
            };
            if range.equation_count != expected_equation_count {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
            next_range_offset = next_range_offset
                .checked_add(range.equation_count)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
        }
        validate_oracle_equation_operation_shape(
            operation,
            previous_operation_left_pending_challenge,
        )?;
        previous_operation_left_pending_challenge =
            oracle_equation_operation_leaves_pending_challenge(&operation.kind);
        next_equation_slot_ordinal = next_equation_slot_ordinal
            .checked_add(next_range_offset)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    }
    if !matches!(
        catalog.operations.last().map(|operation| &operation.kind),
        Some(RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            operation: RowCodeWhirTranscriptOperation::FinishProofStream,
            ..
        })
    ) {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    if previous_operation_left_pending_challenge {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(())
}

fn append_opening_point_transcript_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    base_phase: Option<&RowCodeWhirTracePhasePlan>,
    auxiliary_phase: Option<&RowCodeWhirTracePhasePlan>,
    quotient_phase: &RowCodeWhirQuotientPhasePlan,
    aggregate_column_roles: &[RowCodeWhirAggregateColumnRole],
    parameters: RowCodeWhirSelectedParameters,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let opening_point_count = aggregate_column_roles
        .iter()
        .filter(|role| matches!(role, RowCodeWhirAggregateColumnRole::OpeningPoint { .. }))
        .count();
    if !parameters
        .logical_polynomials_per_physical_row
        .is_power_of_two()
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let selector_count = usize::try_from(parameters.logical_polynomials_per_physical_row.ilog2())
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    for opening_point_index in 0..opening_point_count {
        let opening_point_ordinal = u16::try_from(opening_point_index)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        for selector_index in 0..selector_count {
            builder.push(RowCodeWhirTranscriptOperation::SampleExtension {
                role: RowCodeWhirExtensionRole::Direct(RowCodeWhirChallenge::PointSelectorWeight {
                    opening_point_ordinal,
                    selector_ordinal: u16::try_from(selector_index)
                        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                }),
                whir_challenge_ordinal: None,
            });
        }
        append_trace_group_weight_operations(
            builder,
            opening_point_ordinal,
            base_phase,
            auxiliary_phase,
        )?;
        append_quotient_group_weight_operations(builder, opening_point_ordinal, quotient_phase);
    }
    Ok(())
}

fn append_trace_group_weight_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    opening_point_ordinal: u16,
    base_phase: Option<&RowCodeWhirTracePhasePlan>,
    auxiliary_phase: Option<&RowCodeWhirTracePhasePlan>,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    for (phase, phase_plan) in [
        (RowCodeWhirTracePhase::Base, base_phase),
        (RowCodeWhirTracePhase::Auxiliary, auxiliary_phase),
    ] {
        if let Some(phase_plan) = phase_plan {
            let mut sampled_column_groups = BTreeSet::new();
            for row in &phase_plan.rows {
                if row
                    .opening_point_ordinals
                    .contains(&u32::from(opening_point_ordinal))
                    && sampled_column_groups.insert(row.column_group_ordinal)
                {
                    builder.push(RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::Direct(
                            RowCodeWhirChallenge::TraceColumnGroupWeight {
                                opening_point_ordinal,
                                phase,
                                column_group_ordinal: row.column_group_ordinal,
                            },
                        ),
                        whir_challenge_ordinal: None,
                    });
                }
            }
        }
    }
    Ok(())
}

fn append_quotient_group_weight_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    opening_point_ordinal: u16,
    quotient_phase: &RowCodeWhirQuotientPhasePlan,
) {
    let mut quotient_source_groups = BTreeSet::new();
    for row in &quotient_phase.rows {
        if row
            .opening_point_ordinals
            .contains(&u32::from(opening_point_ordinal))
            && quotient_source_groups.insert(row.source_group_ordinal)
        {
            builder.push(RowCodeWhirTranscriptOperation::SampleExtension {
                role: RowCodeWhirExtensionRole::Direct(RowCodeWhirChallenge::QuotientGroupWeight {
                    opening_point_ordinal,
                    source_group_ordinal: row.source_group_ordinal,
                }),
                whir_challenge_ordinal: None,
            });
        }
    }
    if quotient_phase
        .opening_batch_mask_degree_bound_exclusive
        .is_some()
        && !quotient_source_groups.is_empty()
    {
        builder.push(RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(RowCodeWhirChallenge::OpeningBatchMaskWeight {
                opening_point_ordinal,
            }),
            whir_challenge_ordinal: None,
        });
    }
}

fn append_bound_opening_weight_transcript_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    bound_opening_column_ordinals: &[u32],
) {
    for column_ordinal in bound_opening_column_ordinals {
        builder.push(RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(RowCodeWhirChallenge::BoundOpeningWeight {
                column_ordinal: *column_ordinal,
            }),
            whir_challenge_ordinal: None,
        });
    }
}

fn append_bound_query_transcript_operation(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    bound_trees: &[RowCodeWhirBoundTreePlan],
    bound_reduction_blocks: &[RowCodeWhirBoundReductionBlockPlan],
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if !bound_reduction_blocks.is_empty() {
        let bound_leaf_count = bound_trees
            .first()
            .map(|tree| tree.leaf_count)
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        if bound_trees
            .iter()
            .any(|tree| tree.leaf_count != bound_leaf_count)
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let bound_query_count = bound_reduction_blocks
            .iter()
            .map(|block| block.query_count)
            .max()
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        builder.push(RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role: RowCodeWhirQueryRole::Bound,
            upper_bound: bound_leaf_count,
            output_count: bound_query_count,
        });
    }
    Ok(())
}

fn append_bound_degree_transcript_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    bound_reduction_blocks: &[RowCodeWhirBoundReductionBlockPlan],
    parameters: RowCodeWhirSelectedParameters,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    for (block_index, block) in bound_reduction_blocks.iter().enumerate() {
        for (suffix_index, suffix_prefix) in block.degree_suffix_prefixes.iter().enumerate() {
            let fixed_coordinate_count = block
                .selector_prefix
                .len()
                .checked_add(suffix_prefix.len())
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
            if fixed_coordinate_count > parameters.table_variable_count {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
            for coordinate_index in fixed_coordinate_count..parameters.table_variable_count {
                builder.push(RowCodeWhirTranscriptOperation::SampleExtension {
                    role: RowCodeWhirExtensionRole::Direct(
                        RowCodeWhirChallenge::BoundDegreeCoordinate {
                            block_ordinal: u16::try_from(block_index)
                                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                            degree_test_ordinal: u16::try_from(suffix_index + 1)
                                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                            coordinate_ordinal: u16::try_from(coordinate_index)
                                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                        },
                    ),
                    whir_challenge_ordinal: None,
                });
            }
        }
    }
    Ok(())
}

fn append_aggregate_wide_initial_transcript_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    opening_batches: &[RowCodeWhirOpeningBatchPlan],
    whir: &RowCodeWhirWhirPlan,
    hiding_configuration: &super::hiding_whir::SelectedHidingWhirConfig,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if whir.initial_out_of_domain_sample_count != 0
        || hiding_configuration.commitment_ood_samples != 0
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    for batch in opening_batches {
        builder.push_observation(
            RowCodeWhirObservationRole::OpeningPoint {
                batch_ordinal: batch.point_ordinal,
            },
            parameters.table_variable_count,
        )?;
        builder.push_observation(
            RowCodeWhirObservationRole::OpeningEvaluations {
                batch_ordinal: batch.point_ordinal,
            },
            batch.requested_aggregate_column_ordinals.len(),
        )?;
    }
    builder.push_whir_extension(RowCodeWhirExtensionRole::OpeningBatching)?;
    append_masked_sumcheck_transcript_operations(
        builder,
        0,
        hiding_configuration.round_folding_factor(0),
        false,
    )
}

fn append_masked_sumcheck_transcript_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    batch_ordinal: usize,
    folding_factor: usize,
    observe_scalar_claim: bool,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let batch_ordinal = u32::try_from(batch_ordinal)
        .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
    if observe_scalar_claim {
        builder.push_observation(
            RowCodeWhirObservationRole::MaskedSumcheckClaim { batch_ordinal },
            1,
        )?;
    }
    builder.push_observation(
        RowCodeWhirObservationRole::MaskedSumcheckMaskClaim { batch_ordinal },
        1,
    )?;
    builder
        .push_whir_extension(RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal })?;
    for round_index in 0..folding_factor {
        let round_ordinal = u32::try_from(round_index)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?;
        builder.push_observation(
            RowCodeWhirObservationRole::MaskedSumcheckPolynomial {
                batch_ordinal,
                round_ordinal,
            },
            2,
        )?;
        builder.push_whir_extension(RowCodeWhirExtensionRole::MaskedSumcheckRound {
            batch_ordinal,
            round_ordinal,
        })?;
    }
    Ok(())
}

fn append_aggregate_wide_round_transcript_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    whir: &RowCodeWhirWhirPlan,
    hiding_configuration: &super::hiding_whir::SelectedHidingWhirConfig,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if whir.rounds.len() != hiding_configuration.n_rounds() {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    for (round_index, round) in whir.rounds.iter().enumerate() {
        builder.push(RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::WhirRound {
                round_ordinal: round.round_ordinal,
            },
        });
        if round.out_of_domain_sample_count != 0
            || hiding_configuration.round_parameters[round_index].ood_samples != 0
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        builder.push_observation(
            RowCodeWhirObservationRole::SwitchMaskDelta {
                round_ordinal: round.round_ordinal,
            },
            hiding_configuration.switch_masks[round_index].message_len,
        )?;
        builder.push_whir_extension(RowCodeWhirExtensionRole::RoundCheckpoint {
            round_ordinal: round.round_ordinal,
        })?;
        builder.push(RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role: RowCodeWhirQueryRole::WhirEpoch {
                epoch_ordinal: round.query_epoch.epoch_ordinal,
            },
            upper_bound: round.query_epoch.domain_size,
            output_count: round.query_epoch.query_count,
        });
        builder.push_whir_extension(RowCodeWhirExtensionRole::RoundCombination {
            round_ordinal: round.round_ordinal,
        })?;
        append_masked_sumcheck_transcript_operations(
            builder,
            round_index + 1,
            hiding_configuration.round_folding_factor(round_index + 1),
            true,
        )?;
    }
    Ok(())
}

fn append_aggregate_wide_base_transcript_operations(
    builder: &mut RowCodeWhirTranscriptCatalogBuilder,
    whir: &RowCodeWhirWhirPlan,
    hiding_configuration: &super::hiding_whir::SelectedHidingWhirConfig,
    pad_message_length: usize,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    builder.push(RowCodeWhirTranscriptOperation::ObserveCommitment {
        role: RowCodeWhirCommitmentRole::BaseFreshSource,
    });
    builder.push(RowCodeWhirTranscriptOperation::ObserveCommitment {
        role: RowCodeWhirCommitmentRole::BaseFreshPad,
    });
    builder.push_observation(RowCodeWhirObservationRole::BaseMaskedClaim, 1)?;
    builder.push_whir_extension(RowCodeWhirExtensionRole::BaseCaseBlinding)?;
    builder.push_observation(
        RowCodeWhirObservationRole::BaseBlindedSourceMessage,
        whir.final_round.revealed_coefficient_count,
    )?;
    builder.push_observation(
        RowCodeWhirObservationRole::BaseBlindedSourceRandomness,
        hiding_configuration.oracle_randomness[hiding_configuration.n_rounds()],
    )?;
    builder.push_observation(
        RowCodeWhirObservationRole::BaseBlindedPadMessage,
        pad_message_length,
    )?;
    builder.push_observation(
        RowCodeWhirObservationRole::BaseBlindedPadRandomness,
        hiding_configuration.sumcheck_mask.randomness_len,
    )?;
    builder.push(RowCodeWhirTranscriptOperation::SampleDistinctIndices {
        role: RowCodeWhirQueryRole::WhirEpoch {
            epoch_ordinal: whir.final_round.query_epoch.epoch_ordinal,
        },
        upper_bound: whir.final_round.query_epoch.domain_size,
        output_count: whir.final_round.query_epoch.query_count,
    });
    let pad_shape = p3_whir::MaskCodeShape::new(
        pad_message_length,
        hiding_configuration.sumcheck_mask.randomness_len,
        super::aggregate_wide_hiding::AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
    );
    builder.push(RowCodeWhirTranscriptOperation::SampleDistinctIndices {
        role: RowCodeWhirQueryRole::WhirEpoch {
            epoch_ordinal: whir
                .final_round
                .query_epoch
                .epoch_ordinal
                .checked_add(1)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?,
        },
        upper_bound: pad_shape.domain_size,
        output_count: hiding_configuration.mask_queries,
    });
    Ok(())
}

fn proof_section_plans(
    phase_order: &[RowCodeWhirPhase],
    out_of_domain_evaluation_count: usize,
    bound_trees: &[RowCodeWhirBoundTreePlan],
    _bound_reduction_blocks: &[RowCodeWhirBoundReductionBlockPlan],
    proof_privacy_mode: ProofPrivacyMode,
    quotient_phase: &RowCodeWhirQuotientPhasePlan,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<Vec<RowCodeWhirProofSectionPlan>, RowCodeWhirConstructionPlanError> {
    let mut sections = Vec::new();
    let mut push_section = |role: RowCodeWhirProofSectionRole,
                            item_count: usize|
     -> Result<(), RowCodeWhirConstructionPlanError> {
        sections.push(RowCodeWhirProofSectionPlan {
            section_ordinal: u32::try_from(sections.len())
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            role,
            item_count,
        });
        Ok(())
    };
    for phase in phase_order {
        push_section(
            RowCodeWhirProofSectionRole::RelationCommitment { phase: *phase },
            1,
        )?;
    }
    push_section(
        RowCodeWhirProofSectionRole::OutOfDomainEvaluations,
        out_of_domain_evaluation_count,
    )?;
    if proof_privacy_mode == ProofPrivacyMode::SecretBearing {
        push_section(
            RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations,
            opening_batch_mask_chunk_evaluation_count(proof_privacy_mode, quotient_phase)?,
        )?;
    }
    push_section(RowCodeWhirProofSectionRole::AggregateCommitment, 1)?;
    push_section(RowCodeWhirProofSectionRole::AggregateWidePadCommitment, 1)?;
    for phase in phase_order {
        push_section(
            RowCodeWhirProofSectionRole::PhaseOpenings { phase: *phase },
            parameters.outer_query_count,
        )?;
    }
    for tree in bound_trees {
        push_section(
            RowCodeWhirProofSectionRole::BoundTreeOpenings {
                bound_tree_ordinal: tree.bound_tree_ordinal,
            },
            tree.query_count,
        )?;
    }
    push_section(RowCodeWhirProofSectionRole::AggregateWideOpening, 1)?;
    Ok(sections)
}

fn operation_belongs_to_whir_round(
    operation: &RowCodeWhirTranscriptOperation,
    round_ordinal: u32,
) -> bool {
    let following_batch_ordinal = round_ordinal.checked_add(1);
    match operation {
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role:
                RowCodeWhirCommitmentRole::WhirRound {
                    round_ordinal: observed,
                },
        }
        | RowCodeWhirTranscriptOperation::SampleExtension {
            role:
                RowCodeWhirExtensionRole::RoundCheckpoint {
                    round_ordinal: observed,
                }
                | RowCodeWhirExtensionRole::RoundCombination {
                    round_ordinal: observed,
                },
            ..
        }
        | RowCodeWhirTranscriptOperation::ObserveExtensionValues {
            role:
                RowCodeWhirObservationRole::SwitchMaskDelta {
                    round_ordinal: observed,
                },
            ..
        } => *observed == round_ordinal,
        RowCodeWhirTranscriptOperation::SampleExtension {
            role:
                RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal }
                | RowCodeWhirExtensionRole::MaskedSumcheckRound { batch_ordinal, .. },
            ..
        }
        | RowCodeWhirTranscriptOperation::ObserveExtensionValues {
            role:
                RowCodeWhirObservationRole::MaskedSumcheckClaim { batch_ordinal }
                | RowCodeWhirObservationRole::MaskedSumcheckMaskClaim { batch_ordinal }
                | RowCodeWhirObservationRole::MaskedSumcheckPolynomial { batch_ordinal, .. },
            ..
        } => Some(*batch_ordinal) == following_batch_ordinal,
        _ => false,
    }
}

fn checkpoint_plans(
    phase_order: &[RowCodeWhirPhase],
    operations: &[RowCodeWhirTranscriptOperation],
    proof_sections: &[RowCodeWhirProofSectionPlan],
    whir: &RowCodeWhirWhirPlan,
) -> Result<Vec<RowCodeWhirCheckpointPlan>, RowCodeWhirConstructionPlanError> {
    let mut checkpoints = Vec::new();
    let mut push_checkpoint = |boundary: RowCodeWhirCheckpointBoundary,
                               next_transcript_operation_index: usize,
                               next_proof_section_index: usize|
     -> Result<(), RowCodeWhirConstructionPlanError> {
        checkpoints.push(RowCodeWhirCheckpointPlan {
            checkpoint_ordinal: u32::try_from(checkpoints.len())
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            boundary,
            next_transcript_operation_ordinal: u32::try_from(next_transcript_operation_index)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            next_proof_section_ordinal: u32::try_from(next_proof_section_index)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        });
        Ok(())
    };
    push_checkpoint(RowCodeWhirCheckpointBoundary::SourcesAndConstruction, 0, 0)?;
    for phase in phase_order {
        let phase_section_index = proof_sections
            .iter()
            .position(|section| {
                section.role == (RowCodeWhirProofSectionRole::RelationCommitment { phase: *phase })
            })
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        push_checkpoint(
            RowCodeWhirCheckpointBoundary::PhaseCommitment { phase: *phase },
            0,
            phase_section_index + 1,
        )?;
    }
    let direct_tail_end = operations
        .iter()
        .position(|operation| {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. }
                    | RowCodeWhirTranscriptOperation::SampleExtension {
                        whir_challenge_ordinal: Some(_),
                        ..
                    }
            )
        })
        .unwrap_or(operations.len());
    let aggregate_commitment_section_index = proof_sections
        .iter()
        .position(|section| section.role == RowCodeWhirProofSectionRole::AggregateCommitment)
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    push_checkpoint(
        RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask,
        usize::from(matches!(
            operations.first(),
            Some(RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. })
        )),
        aggregate_commitment_section_index,
    )?;
    push_checkpoint(
        RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries,
        direct_tail_end,
        proof_sections.len().saturating_sub(1),
    )?;
    for round in &whir.rounds {
        let next_operation_index = operations
            .iter()
            .enumerate()
            .filter(|(_, operation)| {
                operation_belongs_to_whir_round(operation, round.round_ordinal)
            })
            .map(|(operation_index, _)| operation_index + 1)
            .max()
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
        push_checkpoint(
            RowCodeWhirCheckpointBoundary::WhirRound {
                round_ordinal: round.round_ordinal,
            },
            next_operation_index,
            proof_sections.len().saturating_sub(1),
        )?;
    }
    push_checkpoint(
        RowCodeWhirCheckpointBoundary::CompletedProofStream,
        operations.len(),
        proof_sections.len(),
    )?;
    Ok(checkpoints)
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

fn encode_oracle_equation_catalog(
    catalog: &RowCodeWhirOracleEquationCatalog,
) -> Result<Vec<u8>, RowCodeWhirConstructionPlanError> {
    validate_oracle_equation_catalog(catalog)?;
    let mut encoder = RowCodeWhirConstructionPlanIdentityEncoder::default();
    encoder.push_u16(ROW_CODE_WHIR_ORACLE_EQUATION_CATALOG_ENCODING_VERSION);
    for domain in [
        TRANSCRIPT_INITIAL_DOMAIN,
        TRANSCRIPT_ABSORB_DOMAIN,
        TRANSCRIPT_RESPONSE_ROOT_DOMAIN,
        TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
        TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN,
        TRANSCRIPT_RESPONSE_BINDING_DOMAIN,
        TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN,
        PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE,
        DISTINCT_QUERY_VECTOR_SAMPLER_TYPE,
    ] {
        encoder.push_bytes(domain.as_bytes())?;
    }
    encoder.push_usize(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH)?;
    encoder.push_length(catalog.operations.len())?;
    for operation in &catalog.operations {
        encoder.push_u32(operation.operation_ordinal);
        encoder.push_optional_u32(operation.predecessor_operation_ordinal);
        encoder.push_u64(operation.first_equation_slot_ordinal);
        match &operation.oracle_tag {
            Some(oracle_tag) => {
                encoder.push_u8(1);
                encoder.push_bytes(oracle_tag.as_bytes())?;
            }
            None => encoder.push_u8(0),
        }
        encode_oracle_equation_operation_kind(&mut encoder, &operation.kind)?;
        encoder.push_length(operation.ranges.len())?;
        for range in &operation.ranges {
            encoder.push_u16(range.range_ordinal);
            encoder.push_u64(range.first_equation_offset);
            encoder.push_u64(range.equation_count);
            encode_oracle_equation_range_kind(&mut encoder, range.kind);
            match range.predecessor {
                RowCodeWhirOracleEquationPredecessor::Independent => encoder.push_u16(1),
                RowCodeWhirOracleEquationPredecessor::FixedZeroState => encoder.push_u16(2),
                RowCodeWhirOracleEquationPredecessor::PreviousOperationTerminal {
                    operation_ordinal,
                } => {
                    encoder.push_u16(3);
                    encoder.push_u32(operation_ordinal);
                }
                RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal { range_ordinal } => {
                    encoder.push_u16(4);
                    encoder.push_u16(range_ordinal);
                }
            }
        }
    }
    Ok(encoder.finish())
}

fn encode_oracle_equation_operation_kind(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    kind: &RowCodeWhirOracleEquationOperationKind,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    match kind {
        RowCodeWhirOracleEquationOperationKind::InitialTranscript => encoder.push_u16(1),
        RowCodeWhirOracleEquationOperationKind::CommonRound(round) => {
            encoder.push_u16(2);
            encode_common_proof_round(encoder, *round);
        }
        RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(group) => {
            encoder.push_u16(3);
            encode_common_proof_challenge(encoder, group.challenge());
            encoder.push_u64(group.modulus());
            encoder.push_u16(group.coordinate_count());
            encoder.push_u64(group.candidate_byte_length());
        }
        RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(challenge) => {
            encoder.push_u16(4);
            encode_common_proof_challenge(encoder, *challenge);
        }
        RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            transcript_operation_ordinal,
            operation,
        } => {
            encoder.push_u16(5);
            encoder.push_u32(*transcript_operation_ordinal);
            encode_transcript_operation(encoder, operation)?;
        }
    }
    Ok(())
}

fn encode_common_proof_round(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    round: CommonProofRound,
) {
    match round {
        CommonProofRound::BaseRoot { tree_ordinal } => {
            encoder.push_u16(1);
            encoder.push_u16(tree_ordinal);
        }
        CommonProofRound::AuxiliaryRoot { tree_ordinal } => {
            encoder.push_u16(2);
            encoder.push_u16(tree_ordinal);
        }
        CommonProofRound::RowCodeWhirQuotientPhaseRoot => encoder.push_u16(4),
        CommonProofRound::OutOfDomainEvaluations => encoder.push_u16(5),
    }
}

fn encode_common_proof_challenge(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    challenge: CommonProofChallenge,
) {
    match challenge {
        CommonProofChallenge::Theta { modulus_ordinal } => {
            encoder.push_u16(1);
            encoder.push_u16(modulus_ordinal);
        }
        CommonProofChallenge::Alpha { modulus_ordinal } => {
            encoder.push_u16(2);
            encoder.push_u16(modulus_ordinal);
        }
        CommonProofChallenge::Composition { constraint_ordinal } => {
            encoder.push_u16(3);
            encoder.push_u32(constraint_ordinal);
        }
        CommonProofChallenge::OutOfDomainPoint { point_ordinal } => {
            encoder.push_u16(4);
            encoder.push_u16(point_ordinal);
        }
    }
}

fn encode_oracle_equation_range_kind(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    kind: RowCodeWhirOracleEquationRangeKind,
) {
    match kind {
        RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot => encoder.push_u16(1),
        RowCodeWhirOracleEquationRangeKind::InitialAbsorption => encoder.push_u16(2),
        RowCodeWhirOracleEquationRangeKind::ResponseRoot => encoder.push_u16(3),
        RowCodeWhirOracleEquationRangeKind::ResponseBinding => encoder.push_u16(4),
        RowCodeWhirOracleEquationRangeKind::ResponseAbsorption => encoder.push_u16(5),
        RowCodeWhirOracleEquationRangeKind::AcceptedChallenge => encoder.push_u16(6),
        RowCodeWhirOracleEquationRangeKind::ChallengeHandle => encoder.push_u16(7),
        RowCodeWhirOracleEquationRangeKind::ExtensionRejectionChain {
            maximum_rejection_count,
        } => {
            encoder.push_u16(8);
            encoder.push_u32(maximum_rejection_count);
        }
        RowCodeWhirOracleEquationRangeKind::ProductExpansion {
            maximum_candidate_count,
            block_count_per_candidate,
        } => {
            encoder.push_u16(9);
            encoder.push_u32(maximum_candidate_count);
            encoder.push_u64(block_count_per_candidate);
        }
        RowCodeWhirOracleEquationRangeKind::DistinctExpansion {
            output_count,
            maximum_block_count_per_output,
        } => {
            encoder.push_u16(10);
            encoder.push_u32(output_count);
            encoder.push_u64(maximum_block_count_per_output);
        }
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
        RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired => 3,
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

const fn row_code_whir_phase_tag(phase: RowCodeWhirPhase) -> u16 {
    match phase {
        RowCodeWhirPhase::Base => 1,
        RowCodeWhirPhase::Auxiliary => 2,
        RowCodeWhirPhase::Quotient => 3,
    }
}

fn encode_encoded_oracle_plan(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    oracle: RowCodeWhirEncodedOraclePlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_usize(oracle.evaluation_count)?;
    encoder.push_usize(oracle.leaf_count)?;
    encoder.push_usize(oracle.leaf_width)
}

fn encode_query_epoch_plan(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    epoch: RowCodeWhirQueryEpochPlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_u32(epoch.epoch_ordinal);
    encoder.push_usize(epoch.bit_length)?;
    encoder.push_usize(epoch.domain_size)?;
    encoder.push_usize(epoch.query_count)
}

fn encode_whir_plan(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    whir: &RowCodeWhirWhirPlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_usize(whir.initial_out_of_domain_sample_count)?;
    encoder.push_usize(whir.initial_sumcheck_round_count)?;
    encoder.push_length(whir.rounds.len())?;
    for round in &whir.rounds {
        encoder.push_u32(round.round_ordinal);
        encode_encoded_oracle_plan(encoder, round.encoded_oracle)?;
        encoder.push_usize(round.out_of_domain_sample_count)?;
        encode_query_epoch_plan(encoder, round.query_epoch)?;
        encoder.push_usize(round.following_sumcheck_round_count)?;
        encoder.push_usize(round.commitment_proof_of_work_bits)?;
        encoder.push_usize(round.folding_proof_of_work_bits)?;
    }
    encode_encoded_oracle_plan(encoder, whir.final_round.encoded_oracle)?;
    encode_query_epoch_plan(encoder, whir.final_round.query_epoch)?;
    encoder.push_usize(whir.final_round.revealed_coefficient_count)?;
    encoder.push_usize(whir.final_round.sumcheck_round_count)?;
    encoder.push_usize(whir.final_round.proof_of_work_bits)
}

fn encode_direct_challenge(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    challenge: RowCodeWhirChallenge,
) {
    match challenge {
        RowCodeWhirChallenge::PointSelectorWeight {
            opening_point_ordinal,
            selector_ordinal,
        } => {
            encoder.push_u16(1);
            encoder.push_u16(opening_point_ordinal);
            encoder.push_u16(selector_ordinal);
        }
        RowCodeWhirChallenge::TraceColumnGroupWeight {
            opening_point_ordinal,
            phase,
            column_group_ordinal,
        } => {
            encoder.push_u16(2);
            encoder.push_u16(opening_point_ordinal);
            encoder.push_u16(match phase {
                RowCodeWhirTracePhase::Base => 1,
                RowCodeWhirTracePhase::Auxiliary => 2,
            });
            encoder.push_u32(column_group_ordinal);
        }
        RowCodeWhirChallenge::QuotientGroupWeight {
            opening_point_ordinal,
            source_group_ordinal,
        } => {
            encoder.push_u16(3);
            encoder.push_u16(opening_point_ordinal);
            encoder.push_u32(source_group_ordinal);
        }
        RowCodeWhirChallenge::OpeningBatchMaskWeight {
            opening_point_ordinal,
        } => {
            encoder.push_u16(4);
            encoder.push_u16(opening_point_ordinal);
        }
        RowCodeWhirChallenge::BoundOpeningWeight { column_ordinal } => {
            encoder.push_u16(5);
            encoder.push_u32(column_ordinal);
        }
        RowCodeWhirChallenge::OuterQueryVector => encoder.push_u16(6),
        RowCodeWhirChallenge::BoundQueryVector => encoder.push_u16(7),
        RowCodeWhirChallenge::BoundDegreeCoordinate {
            block_ordinal,
            degree_test_ordinal,
            coordinate_ordinal,
        } => {
            encoder.push_u16(8);
            encoder.push_u16(block_ordinal);
            encoder.push_u16(degree_test_ordinal);
            encoder.push_u16(coordinate_ordinal);
        }
    }
}

fn encode_extension_role(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    role: RowCodeWhirExtensionRole,
) {
    match role {
        RowCodeWhirExtensionRole::Direct(challenge) => {
            encoder.push_u16(1);
            encode_direct_challenge(encoder, challenge);
        }
        RowCodeWhirExtensionRole::OpeningBatching => encoder.push_u16(2),
        RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal } => {
            encoder.push_u16(3);
            encoder.push_u32(batch_ordinal);
        }
        RowCodeWhirExtensionRole::MaskedSumcheckRound {
            batch_ordinal,
            round_ordinal,
        } => {
            encoder.push_u16(4);
            encoder.push_u32(batch_ordinal);
            encoder.push_u32(round_ordinal);
        }
        RowCodeWhirExtensionRole::RoundCheckpoint { round_ordinal } => {
            encoder.push_u16(5);
            encoder.push_u32(round_ordinal);
        }
        RowCodeWhirExtensionRole::RoundCombination { round_ordinal } => {
            encoder.push_u16(6);
            encoder.push_u32(round_ordinal);
        }
        RowCodeWhirExtensionRole::BaseCaseBlinding => encoder.push_u16(7),
    }
}

fn encode_observation_role(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    role: RowCodeWhirObservationRole,
) {
    match role {
        RowCodeWhirObservationRole::OpeningPoint { batch_ordinal } => {
            encoder.push_u16(1);
            encoder.push_u32(batch_ordinal);
        }
        RowCodeWhirObservationRole::OpeningEvaluations { batch_ordinal } => {
            encoder.push_u16(2);
            encoder.push_u32(batch_ordinal);
        }
        RowCodeWhirObservationRole::MaskedSumcheckClaim { batch_ordinal } => {
            encoder.push_u16(3);
            encoder.push_u32(batch_ordinal);
        }
        RowCodeWhirObservationRole::MaskedSumcheckMaskClaim { batch_ordinal } => {
            encoder.push_u16(4);
            encoder.push_u32(batch_ordinal);
        }
        RowCodeWhirObservationRole::MaskedSumcheckPolynomial {
            batch_ordinal,
            round_ordinal,
        } => {
            encoder.push_u16(5);
            encoder.push_u32(batch_ordinal);
            encoder.push_u32(round_ordinal);
        }
        RowCodeWhirObservationRole::SwitchMaskDelta { round_ordinal } => {
            encoder.push_u16(6);
            encoder.push_u32(round_ordinal);
        }
        RowCodeWhirObservationRole::BaseMaskedClaim => encoder.push_u16(7),
        RowCodeWhirObservationRole::BaseBlindedSourceMessage => encoder.push_u16(8),
        RowCodeWhirObservationRole::BaseBlindedSourceRandomness => encoder.push_u16(9),
        RowCodeWhirObservationRole::BaseBlindedPadMessage => encoder.push_u16(10),
        RowCodeWhirObservationRole::BaseBlindedPadRandomness => encoder.push_u16(11),
    }
}

fn encode_transcript_operation(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    operation: &RowCodeWhirTranscriptOperation,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    match operation {
        RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { value_count } => {
            encoder.push_u16(1);
            encoder.push_usize(*value_count)?;
        }
        RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { canonical_values } => {
            encoder.push_u16(2);
            encoder.push_length(canonical_values.len())?;
            for value in canonical_values {
                for coordinate in value.canonical_coordinates() {
                    encoder.push_u64(coordinate);
                }
            }
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role,
            whir_challenge_ordinal,
        } => {
            encoder.push_u16(3);
            encode_extension_role(encoder, *role);
            encoder.push_optional_u32(*whir_challenge_ordinal);
        }
        RowCodeWhirTranscriptOperation::ObserveCommitment { role } => {
            encoder.push_u16(4);
            match role {
                RowCodeWhirCommitmentRole::Aggregate => encoder.push_u16(1),
                RowCodeWhirCommitmentRole::AggregateWidePad => encoder.push_u16(2),
                RowCodeWhirCommitmentRole::WhirRound { round_ordinal } => {
                    encoder.push_u16(3);
                    encoder.push_u32(*round_ordinal);
                }
                RowCodeWhirCommitmentRole::BaseFreshSource => encoder.push_u16(4),
                RowCodeWhirCommitmentRole::BaseFreshPad => encoder.push_u16(5),
            }
        }
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role,
            upper_bound,
            output_count,
        } => {
            encoder.push_u16(5);
            match role {
                RowCodeWhirQueryRole::Outer => encoder.push_u16(1),
                RowCodeWhirQueryRole::Bound => encoder.push_u16(2),
                RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal } => {
                    encoder.push_u16(3);
                    encoder.push_u32(*epoch_ordinal);
                }
            }
            encoder.push_usize(*upper_bound)?;
            encoder.push_usize(*output_count)?;
        }
        RowCodeWhirTranscriptOperation::ObserveExtensionValues {
            observation_ordinal,
            role,
            value_count,
        } => {
            encoder.push_u16(6);
            encoder.push_u32(*observation_ordinal);
            encode_observation_role(encoder, *role);
            encoder.push_usize(*value_count)?;
        }
        RowCodeWhirTranscriptOperation::FinishProofStream => encoder.push_u16(7),
    }
    Ok(())
}

fn encode_proof_section(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    section: RowCodeWhirProofSectionPlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_u32(section.section_ordinal);
    match section.role {
        RowCodeWhirProofSectionRole::RelationCommitment { phase } => {
            encoder.push_u16(1);
            encoder.push_u16(row_code_whir_phase_tag(phase));
        }
        RowCodeWhirProofSectionRole::OutOfDomainEvaluations => encoder.push_u16(2),
        RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => encoder.push_u16(3),
        RowCodeWhirProofSectionRole::AggregateCommitment => encoder.push_u16(4),
        RowCodeWhirProofSectionRole::AggregateWidePadCommitment => encoder.push_u16(5),
        RowCodeWhirProofSectionRole::PhaseOpenings { phase } => {
            encoder.push_u16(6);
            encoder.push_u16(row_code_whir_phase_tag(phase));
        }
        RowCodeWhirProofSectionRole::BoundTreeOpenings { bound_tree_ordinal } => {
            encoder.push_u16(7);
            encoder.push_u32(bound_tree_ordinal);
        }
        RowCodeWhirProofSectionRole::AggregateWideOpening => encoder.push_u16(8),
    }
    encoder.push_usize(section.item_count)
}

fn encode_checkpoint(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    checkpoint: RowCodeWhirCheckpointPlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    encoder.push_u32(checkpoint.checkpoint_ordinal);
    match checkpoint.boundary {
        RowCodeWhirCheckpointBoundary::SourcesAndConstruction => encoder.push_u16(1),
        RowCodeWhirCheckpointBoundary::PhaseCommitment { phase } => {
            encoder.push_u16(2);
            encoder.push_u16(row_code_whir_phase_tag(phase));
        }
        RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => encoder.push_u16(3),
        RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries => encoder.push_u16(4),
        RowCodeWhirCheckpointBoundary::WhirRound { round_ordinal } => {
            encoder.push_u16(5);
            encoder.push_u32(round_ordinal);
        }
        RowCodeWhirCheckpointBoundary::CompletedProofStream => encoder.push_u16(6),
    }
    encoder.push_u32(checkpoint.next_transcript_operation_ordinal);
    encoder.push_u32(checkpoint.next_proof_section_ordinal);
    Ok(())
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
    encoder.push_u64(parameters.trace_mask_degree_bound_exclusive);
    encoder.push_usize(parameters.direct_bound_query_count)?;
    encoder.push_usize(parameters.prior_proof_bound_query_count)?;
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
    validate_trace_mask_geometry(variant, context, parameters)?;
    validate_domain_geometry_values(
        variant.trace_domain_size(),
        variant.evaluation_domain_size(),
        variant.opening_degree_bound_exclusive(),
        context,
        parameters,
    )
}

fn validate_domain_geometry_values(
    trace_domain_size: u64,
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
    let expected_prior_proof_bound_query_count =
        expected_direct_bound_query_count.min(ROW_CODE_WHIR_PRIOR_PROOF_BOUND_QUERY_COUNT);
    let expected_physical_row_witness_variable_count = parameters
        .logical_polynomial_coefficient_count
        .checked_mul(parameters.logical_polynomials_per_physical_row)
        .filter(|value_count| value_count.is_power_of_two())
        .and_then(|value_count| usize::try_from(value_count.ilog2()).ok());
    let expected_table_variable_count = expected_physical_row_witness_variable_count
        .and_then(|variable_count| variable_count.checked_add(1));
    let expected_row_code_log_inverse_rate =
        expected_table_variable_count.and_then(|table_variable_count| {
            parameters
                .polynomial_commitment_variable_count
                .checked_sub(table_variable_count)
        });
    let maximum_distinct_leaf_query_count = evaluation_domain_size
        .checked_div(2)
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    if trace_domain_size == 0
        || parameters.trace_mask_degree_bound_exclusive == 0
        || parameters.trace_mask_degree_bound_exclusive > trace_domain_size
        || context.base_field_modulus != PROOF_BASE_FIELD_MODULUS
        || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
        || !evaluation_domain_size.is_power_of_two()
        || evaluation_domain_size != encoded_column_capacity
        || parameters.logical_polynomial_coefficient_count == 0
        || !parameters
            .logical_polynomial_coefficient_count
            .is_power_of_two()
        || parameters.logical_polynomials_per_physical_row == 0
        || !parameters
            .logical_polynomials_per_physical_row
            .is_power_of_two()
        || parameters.logical_polynomials_per_physical_row
            > ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
        || expected_physical_row_witness_variable_count
            != Some(parameters.physical_row_witness_variable_count)
        || expected_table_variable_count != Some(parameters.table_variable_count)
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
        || parameters.prior_proof_bound_query_count != expected_prior_proof_bound_query_count
        || parameters.direct_bound_query_count > maximum_distinct_leaf_query_count
        || parameters.prior_proof_bound_query_count > parameters.direct_bound_query_count
        || expected_row_code_log_inverse_rate != Some(parameters.row_code_log_inverse_rate)
        || parameters.row_code_log_inverse_rate < ROW_CODE_WHIR_LOG_INVERSE_RATE
        || parameters.starting_log_inverse_rate != ROW_CODE_WHIR_LOG_INVERSE_RATE
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

fn validate_trace_mask_geometry(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if parameters.trace_mask_degree_bound_exclusive == 0
        || parameters.trace_mask_degree_bound_exclusive > variant.trace_domain_size()
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(());
    }

    let mut prover_column_ordinals = BTreeSet::new();
    for (column_index, column) in variant.ordered_columns().iter().enumerate() {
        if matches!(column.origin(), RelationColumnOrigin::Prover) {
            prover_column_ordinals.insert(
                u32::try_from(column_index)
                    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            );
        }
    }
    if prover_column_ordinals.is_empty() {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }

    let mut rotations_by_prover_column = prover_column_ordinals
        .iter()
        .copied()
        .map(|column_ordinal| (column_ordinal, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for opening_claim in variant.ordered_opening_claims() {
        if opening_claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let Some(column_ordinal) = opening_claim.column_ordinal() else {
            return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
        };
        let Some(rotations) = rotations_by_prover_column.get_mut(&column_ordinal) else {
            continue;
        };
        let opening_point = variant
            .ordered_opening_points()
            .get(
                usize::try_from(opening_claim.opening_point_ordinal())
                    .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
            )
            .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
        rotations.insert(opening_point.trace_rotation());
    }
    let maximum_distinct_rotation_count = rotations_by_prover_column
        .values()
        .map(BTreeSet::len)
        .max()
        .filter(|count| *count != 0)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog)?;
    if rotations_by_prover_column.values().any(BTreeSet::is_empty) {
        return Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog);
    }
    let direct_view_rank_ceiling = u64::try_from(parameters.outer_query_count)
        .ok()
        .and_then(|outer_query_count| {
            u64::from(context.challenge_extension_degree)
                .checked_mul(u64::from(context.out_of_domain_point_count))
                .and_then(|count| count.checked_mul(maximum_distinct_rotation_count))
                .and_then(|opening_view_count| outer_query_count.checked_add(opening_view_count))
        })
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    if parameters.trace_mask_degree_bound_exclusive < direct_view_rank_ceiling {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }

    let mut trace_mask_targets = BTreeSet::new();
    for mask in variant.ordered_masks() {
        if mask.mask_kind() != RelationMaskKind::Trace {
            continue;
        }
        if mask.target_class() != RelationMaskTargetClass::Column
            || mask.mask_degree_bound_exclusive() != parameters.trace_mask_degree_bound_exclusive
            || !trace_mask_targets.insert(mask.target_ordinal())
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
    }
    if trace_mask_targets != prover_column_ordinals {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(())
}

/// The trace-mask degree bound the variant's own compiled masks declare.
///
/// This is per-family geometry, not one global constant. Ten selected families
/// need only the row-code construction's direct-view rank capacity, while the
/// committed-material VSS families carry the larger masking-polynomial degree
/// that their own profile requires. Deriving the bound here and binding it into
/// construction identity keeps one authority; requiring equality with a single
/// pinned value would refuse every family whose relation legitimately needs
/// more mask capacity.
fn variant_trace_mask_degree_bound(
    variant: &RelationPlanVariant,
) -> Result<u64, RowCodeWhirConstructionPlanError> {
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(1);
    }
    let mut trace_mask_degree_bound_exclusive = None;
    for mask in variant.ordered_masks() {
        if mask.mask_kind() != RelationMaskKind::Trace {
            continue;
        }
        if mask.target_class() != RelationMaskTargetClass::Column
            || mask.mask_degree_bound_exclusive() == 0
            || trace_mask_degree_bound_exclusive
                .is_some_and(|degree| degree != mask.mask_degree_bound_exclusive())
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        trace_mask_degree_bound_exclusive = Some(mask.mask_degree_bound_exclusive());
    }
    trace_mask_degree_bound_exclusive
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
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

fn opening_batch_mask_chunk_evaluation_count(
    proof_privacy_mode: ProofPrivacyMode,
    quotient_phase: &RowCodeWhirQuotientPhasePlan,
) -> Result<usize, RowCodeWhirConstructionPlanError> {
    match (
        proof_privacy_mode,
        quotient_phase.opening_batch_mask_degree_bound_exclusive,
    ) {
        (ProofPrivacyMode::PublicOnly, None) => Ok(0),
        (ProofPrivacyMode::SecretBearing, Some(degree_bound_exclusive)) => coefficient_chunk_count(
            degree_bound_exclusive,
            ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT,
        ),
        _ => Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry),
    }
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
        for column_group in column_ordinals.chunks(parameters.logical_polynomials_per_physical_row)
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
            .chunks(parameters.logical_polynomials_per_physical_row)
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
                (0..mask_chunk_count).step_by(parameters.logical_polynomials_per_physical_row)
            {
                for extension_coordinate_ordinal in 0..context.challenge_extension_degree {
                    let mut row_chunks = [None; ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW];
                    let chunk_group_end = mask_chunk_count
                        .min(chunk_group_start + parameters.logical_polynomials_per_physical_row);
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
    } else if matches!(
        application_statement_schema_identifier,
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    ) && construction_kind == BoundTreeConstructionKind::SetupPolynomial
        && root_use == BoundTreeRootUse::Input
    {
        RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired
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
pub(in crate::bgv::proof_suite) mod theorem_certificate;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        ValidatedRelationPlanArtifact, compile_aggregate_threshold_share_relation_plan,
        compile_same_secret_relation_plan, compile_vss_share_linkage_relation_plan,
        selected_ballot_validity_relation_compilation,
        selected_profile::{
            SELECTED_QUOTIENT_COMPONENT_COUNT, selected_relation_plans,
            selected_target_release_relation,
        },
        selected_same_secret_relation_plan_input,
    };

    #[test]
    fn trace_mask_degree_lookup_requires_the_exact_selected_context_and_trace_geometry() {
        let same_secret_schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let same_secret_context =
            selected_relation_plan_check_context(same_secret_schema_identifier)
                .expect("same-secret has a selected relation context");
        assert_eq!(
            selected_row_code_whir_trace_mask_degree_bound_exclusive(
                same_secret_schema_identifier,
                (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT / 2) as u64,
                &same_secret_context,
            ),
            Some(ROW_CODE_WHIR_TRACE_MASK_DEGREE_BOUND_EXCLUSIVE),
        );

        let ballot_schema_identifier =
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
        let ballot_context = selected_relation_plan_check_context(ballot_schema_identifier)
            .expect("ballot validity has a selected relation context");
        assert_eq!(
            selected_row_code_whir_trace_mask_degree_bound_exclusive(
                ballot_schema_identifier,
                ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT as u64,
                &ballot_context,
            ),
            Some(ROW_CODE_WHIR_TRACE_MASK_DEGREE_BOUND_EXCLUSIVE),
        );

        let vss_linkage_schema_identifier =
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        let vss_linkage_context =
            selected_relation_plan_check_context(vss_linkage_schema_identifier)
                .expect("VSS linkage has a selected relation context");
        assert_eq!(
            selected_row_code_whir_trace_mask_degree_bound_exclusive(
                vss_linkage_schema_identifier,
                (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * 2) as u64,
                &vss_linkage_context,
            ),
            Some(ROW_CODE_WHIR_TRACE_MASK_DEGREE_BOUND_EXCLUSIVE),
        );

        let mut fixture_context = same_secret_context.clone();
        fixture_context.phase_column_query_coordinate_count -= 1;
        assert_eq!(
            selected_row_code_whir_trace_mask_degree_bound_exclusive(
                same_secret_schema_identifier,
                (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT / 2) as u64,
                &fixture_context,
            ),
            None,
        );
        assert_eq!(
            selected_row_code_whir_trace_mask_degree_bound_exclusive(
                same_secret_schema_identifier,
                ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT as u64,
                &same_secret_context,
            ),
            None,
        );
        assert_eq!(
            selected_row_code_whir_trace_mask_degree_bound_exclusive(
                u16::MAX,
                (ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT / 2) as u64,
                &same_secret_context,
            ),
            None,
        );
    }

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
        let parameters = RowCodeWhirSelectedParameters::for_checked_fixture_geometry(4_096, 16, 26)
            .expect("the reduced fixture geometry derives");
        assert_eq!(parameters.logical_polynomial_coefficient_count, 64);
        assert_eq!(parameters.logical_polynomials_per_physical_row, 8);
        assert_eq!(parameters.physical_row_witness_variable_count, 9);
        assert_eq!(parameters.row_code_log_inverse_rate, 2);
        assert_eq!(parameters.table_variable_count, 10);
        assert_eq!(parameters.polynomial_commitment_variable_count, 12);
        assert_eq!(parameters.outer_query_count, 16);
        assert_eq!(parameters.trace_mask_degree_bound_exclusive, 26);
        assert_eq!(parameters.direct_bound_query_count, 16);
        assert_eq!(parameters.prior_proof_bound_query_count, 16);
        assert_eq!(
            validate_domain_geometry_values(256, 4_096, 258, &checked_context, parameters),
            Ok(()),
        );

        assert!(
            RowCodeWhirSelectedParameters::for_checked_fixture_geometry(3_072, 16, 26).is_err(),
            "a non-power-of-two evaluation domain has no row-code geometry",
        );
        assert!(
            validate_domain_geometry_values(256, 8_192, 258, &checked_context, parameters).is_err(),
            "the derived parameters cannot be relabeled with another domain",
        );
        for malformed_opening_degree_bound in [0, 256, 513] {
            assert!(
                validate_domain_geometry_values(
                    256,
                    4_096,
                    malformed_opening_degree_bound,
                    &checked_context,
                    parameters,
                )
                .is_err(),
                "opening bound {malformed_opening_degree_bound} must not fit the minimal 258-bound geometry",
            );
        }
        let mut mismatched_context = checked_context.clone();
        mismatched_context.phase_column_query_coordinate_count = 15;
        assert!(
            validate_domain_geometry_values(256, 4_096, 258, &mismatched_context, parameters)
                .is_err(),
            "the exact checked context owns the fixture query geometry",
        );
        let mut insufficient_mask_parameters = parameters;
        insufficient_mask_parameters.trace_mask_degree_bound_exclusive = 25;
        assert!(
            validate_domain_geometry_values(
                256,
                4_096,
                258,
                &checked_context,
                insufficient_mask_parameters,
            )
            .is_ok(),
            "value-only geometry cannot infer a relation's rotation rank",
        );
        for invalid_trace_mask_degree_bound in [0, 257] {
            let mut invalid_parameters = parameters;
            invalid_parameters.trace_mask_degree_bound_exclusive = invalid_trace_mask_degree_bound;
            assert!(
                validate_domain_geometry_values(
                    256,
                    4_096,
                    258,
                    &checked_context,
                    invalid_parameters,
                )
                .is_err(),
                "trace-mask degree bound {invalid_trace_mask_degree_bound} must fit the trace domain",
            );
        }
    }

    #[test]
    fn candidate_specific_row_widths_cover_extended_opening_catalogs() {
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
        for (compiled_plan, expected_opening_bound) in [
            (
                ballot_compilation.relation_plan().clone(),
                ROW_CODE_WHIR_BALLOT_OPENING_DEGREE_BOUND_EXCLUSIVE,
            ),
            (
                target_release_compilation.relation_plan().clone(),
                ROW_CODE_WHIR_TARGET_RELEASE_OPENING_DEGREE_BOUND_EXCLUSIVE,
            ),
            (
                vss_share_linkage,
                ROW_CODE_WHIR_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE,
            ),
            (
                aggregate_threshold_share,
                ROW_CODE_WHIR_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE,
            ),
        ] {
            let schema_identifier = compiled_plan.application_statement_schema_identifier();
            let context = selected_relation_plan_check_context(schema_identifier)
                .expect("the selected family has a relation context");
            let artifact =
                ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
                    .expect("the selected family relation validates");
            let plan = RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
                .expect("the candidate-specific row construction derives");
            assert_eq!(plan.opening_degree_bound_exclusive, expected_opening_bound);
            assert_eq!(
                plan.parameters.logical_polynomials_per_physical_row,
                ROW_CODE_WHIR_COMMITTED_MATERIAL_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW,
            );
            assert_eq!(plan.parameters.row_code_log_inverse_rate, 5);
            assert_eq!(plan.parameters.starting_log_inverse_rate, 2);
            assert_eq!(plan.aggregate_table_width(), 32);
            assert!(!plan.aggregate_column_roles.is_empty());
            assert!(plan.aggregate_column_roles.len() <= plan.aggregate_table_width());
        }
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
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 3_302,
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
            | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 5,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 20,
            _ => 15,
        }
    }

    fn expected_opening_degree_bound_exclusive(
        application_statement_schema_identifier: u16,
    ) -> u64 {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
                ROW_CODE_WHIR_BALLOT_OPENING_DEGREE_BOUND_EXCLUSIVE
            }
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                ROW_CODE_WHIR_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE
            }
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
                ROW_CODE_WHIR_TARGET_RELEASE_OPENING_DEGREE_BOUND_EXCLUSIVE
            }
            _ => ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE,
        }
    }

    fn expected_logical_polynomials_per_physical_row(
        application_statement_schema_identifier: u16,
    ) -> usize {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
                ROW_CODE_WHIR_BALLOT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
            }
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                ROW_CODE_WHIR_COMMITTED_MATERIAL_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
            }
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
                ROW_CODE_WHIR_TARGET_RELEASE_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
            }
            _ => ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW,
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
        assert_eq!(
            plan.quotient_phase.geometry.encoded_column_count,
            usize::try_from(plan.evaluation_domain_size).expect("selected domain fits usize"),
        );
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
        let mutated_identity = mutated_plan
            .canonical_identity_hash()
            .unwrap_or_else(|error| panic!("mutated plan identity for {description}: {error:?}"));
        assert_ne!(
            mutated_identity, expected_identity,
            "construction identity omitted {description}",
        );
    }

    /// Some mutations do not merely change the identity: they contradict a
    /// derivation the plan itself owns, so the plan stops having an identity at
    /// all. Refusal is strictly stronger than a changed hash, and asserting a
    /// changed hash would wrongly require the invalid plan to be encodable.
    fn assert_plan_identity_mutation_refuses(
        plan: &RowCodeWhirConstructionPlan,
        description: &str,
        mutate: impl FnOnce(&mut RowCodeWhirConstructionPlan),
    ) {
        let mut mutated_plan = plan.clone();
        mutate(&mut mutated_plan);
        assert_ne!(mutated_plan, *plan, "mutation did not change {description}");
        assert_eq!(
            mutated_plan.canonical_identity_hash(),
            Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry),
            "construction identity accepted an invalid {description}",
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
            "evaluation coset",
            |mutated| mutated.evaluation_coset_offset += 1,
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
            "trace-mask degree bound",
            |mutated| mutated.parameters.trace_mask_degree_bound_exclusive += 1,
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
            |mutated| mutated.parameters.prior_proof_bound_query_count += 1,
        );
        // The derived oracle-equation catalog is part of the identity, and it
        // refuses a draw ceiling that disagrees with the relation schedule and
        // the pinned protocol constant. The mutated plan therefore has no
        // identity instead of a different one.
        assert_plan_identity_mutation_refuses(
            plan,
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
    fn construction_identity_binds_aggregate_leaf_and_merkle_output_widths() {
        let identity = selected_same_secret_construction_plan()
            .canonical_identity_bytes()
            .expect("the selected construction identity encodes");

        assert_eq!(
            &identity[..6],
            &[
                ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_ENCODING_VERSION as u8,
                (ROW_CODE_WHIR_CONSTRUCTION_PLAN_IDENTITY_ENCODING_VERSION >> 8) as u8,
                ROW_CODE_WHIR_AGGREGATE_LEAF_STATE_BYTE_LENGTH as u8,
                (ROW_CODE_WHIR_AGGREGATE_LEAF_STATE_BYTE_LENGTH >> 8) as u8,
                ROW_CODE_WHIR_MERKLE_DIGEST_BYTE_LENGTH as u8,
                (ROW_CODE_WHIR_MERKLE_DIGEST_BYTE_LENGTH >> 8) as u8,
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
                .unwrap_or_else(|error| {
                    panic!(
                        "selected variant schema {:#06x} schedule {:?} top count {:?} has unsupported row-code WHIR geometry: {error:?}",
                        schema_identifier,
                        variant.schedule_position(),
                        variant.top_count(),
                    )
                });
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
                assert_eq!(plan.evaluation_domain_size, 1 << 24);
                assert_eq!(
                    plan.opening_degree_bound_exclusive,
                    expected_opening_degree_bound_exclusive(schema_identifier),
                );
                assert_eq!(
                    plan.parameters.logical_polynomials_per_physical_row,
                    expected_logical_polynomials_per_physical_row(schema_identifier),
                );
                let expected_log_inverse_rate = if matches!(
                    schema_identifier,
                    ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
                ) {
                    5
                } else {
                    2
                };
                assert_eq!(
                    plan.parameters.row_code_log_inverse_rate,
                    expected_log_inverse_rate,
                );
                assert_eq!(plan.aggregate_table_width(), 1 << expected_log_inverse_rate,);
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
        assert_eq!(base_phase.rows.len(), 32);
        assert_eq!(auxiliary_phase.rows.len(), 15);
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
                        (component_ordinal < 8).then(|| {
                            RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                                component_ordinal: u32::try_from(component_ordinal).unwrap(),
                            }
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
            900,
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
                && tree.leaf_count == 1 << 23
                && tree.ordered_columns.iter().all(|column| {
                    column.source_degree_bound_exclusive == 18_432
                        && column.opening_point_ordinals.len() == 1
                })
        }));
        assert!(plan.bound_trees[8..].iter().all(|tree| {
            tree.ordered_columns.len() == 4
                && tree.source_trace_domain_size == 16_384
                && tree.leaf_count == 1 << 23
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
            vec![0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            plan.bound_reduction_blocks[1].selector_prefix,
            vec![0, 0, 0, 0, 0, 0, 1],
        );
        assert_eq!(
            plan.bound_reduction_blocks
                .iter()
                .map(RowCodeWhirBoundReductionBlockPlan::degree_test_count)
                .sum::<usize>(),
            6,
        );
        assert_eq!(plan.parameters.table_variable_count, 22);
        assert_eq!(plan.parameters.polynomial_commitment_variable_count, 24);
        assert_eq!(plan.parameters.logical_polynomial_coefficient_count, 32_768);
        assert_eq!(plan.parameters.logical_polynomials_per_physical_row, 64);
        let logical_row_selector_coordinate_count =
            usize::try_from(plan.parameters.logical_polynomials_per_physical_row.ilog2())
                .expect("the logical-row selector count fits usize");
        let prefix_stacking_selector_variable_count =
            plan.parameters.polynomial_commitment_variable_count
                - plan.parameters.table_variable_count;
        let encoded_merkle_leaf_width = 1_usize << plan.parameters.folding_factor;
        assert_eq!(logical_row_selector_coordinate_count, 6);
        assert_eq!(prefix_stacking_selector_variable_count, 2);
        assert_eq!(encoded_merkle_leaf_width, 8);
        assert_eq!(SELECTED_QUOTIENT_COMPONENT_COUNT, 8);
        assert_ne!(
            logical_row_selector_coordinate_count,
            prefix_stacking_selector_variable_count
        );
        let selected_quotient_component_count = usize::try_from(SELECTED_QUOTIENT_COMPONENT_COUNT)
            .expect("the quotient component count fits usize");
        assert_ne!(
            plan.parameters.logical_polynomials_per_physical_row,
            selected_quotient_component_count,
        );
        assert_eq!(plan.parameters.physical_row_witness_variable_count, 21);
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
        assert_eq!(plan.parameters.trace_mask_degree_bound_exclusive, 682);
        assert_eq!(
            plan.phase_order,
            vec![
                RowCodeWhirPhase::Base,
                RowCodeWhirPhase::Auxiliary,
                RowCodeWhirPhase::Quotient,
            ],
        );
        assert_eq!(plan.bound_opening_column_ordinals.len(), 44);
        assert_eq!(plan.opening_batches.len(), 1_008);
        assert_eq!(plan.whir.rounds.len(), 5);
        assert_eq!(
            plan.whir
                .rounds
                .iter()
                .map(|round| (round.query_epoch.bit_length, round.query_epoch.query_count,))
                .chain(std::iter::once((
                    plan.whir.final_round.query_epoch.bit_length,
                    plan.whir.final_round.query_epoch.query_count,
                )))
                .collect::<Vec<_>>(),
            vec![
                (23, 387),
                (22, 288),
                (21, 268),
                (20, 264),
                (19, 263),
                (18, 263),
            ],
        );
        assert_eq!(plan.transcript_operations.len(), 2_289);
        assert_eq!(
            plan.transcript_operations
                .iter()
                .find_map(|operation| match operation {
                    RowCodeWhirTranscriptOperation::ObserveProtocolSchedule {
                        canonical_values,
                    } => Some(canonical_values.len()),
                    _ => None,
                }),
            Some(111),
        );
        assert_eq!(
            plan.transcript_operations
                .iter()
                .filter(|operation| matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::Direct(_),
                        ..
                    }
                ))
                .count(),
            177,
        );
        assert_eq!(
            plan.transcript_operations
                .iter()
                .filter(|operation| matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension {
                        whir_challenge_ordinal: Some(_),
                        ..
                    }
                ))
                .count(),
            36,
        );
        assert_eq!(
            plan.transcript_operations
                .iter()
                .filter(|operation| matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
                ))
                .count(),
            9,
        );
        assert_eq!(
            plan.transcript_operations
                .iter()
                .filter(|operation| matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. }
                ))
                .count(),
            9,
        );
        assert_eq!(plan.proof_sections.len(), 22);
        assert_eq!(plan.checkpoints.len(), 12);
        assert_eq!(
            plan.proof_sections[..3]
                .iter()
                .map(|section| section.role)
                .collect::<Vec<_>>(),
            plan.phase_order
                .iter()
                .map(|phase| RowCodeWhirProofSectionRole::RelationCommitment { phase: *phase })
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            plan.checkpoints[1..=3]
                .iter()
                .map(|checkpoint| checkpoint.next_proof_section_ordinal)
                .collect::<Vec<_>>(),
            vec![1, 2, 3],
        );
        let out_of_domain_evaluation_count = plan
            .proof_sections
            .iter()
            .find_map(|section| {
                (section.role == RowCodeWhirProofSectionRole::OutOfDomainEvaluations)
                    .then_some(section.item_count)
            })
            .expect("the selected proof layout contains relation evaluations");
        let public_only_sections = proof_section_plans(
            &plan.phase_order,
            out_of_domain_evaluation_count,
            &plan.bound_trees,
            &plan.bound_reduction_blocks,
            ProofPrivacyMode::PublicOnly,
            &RowCodeWhirQuotientPhasePlan {
                opening_batch_mask_degree_bound_exclusive: None,
                ..plan.quotient_phase.clone()
            },
            plan.parameters,
        )
        .expect("the public-only proof layout is canonical");
        assert_eq!(public_only_sections.len() + 1, plan.proof_sections.len());
        assert!(public_only_sections.iter().all(|section| {
            section.role != RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations
        }));

        let construction_identity = plan
            .canonical_identity_hash()
            .expect("the selected construction identity is canonical");
        let relation_prefix_schedule = plan.relation_prefix_schedule();
        let mutated_relation_prefix_schedule = CommonProofRelationPrefixSchedule::new(
            relation_prefix_schedule
                .ordered_base_tree_ordinals()
                .to_vec(),
            relation_prefix_schedule
                .ordered_application_challenge_groups()
                .to_vec(),
            relation_prefix_schedule
                .ordered_auxiliary_tree_ordinals()
                .to_vec(),
            relation_prefix_schedule
                .composition_challenge_count()
                .checked_add(1)
                .expect("the selected composition-challenge count increments"),
            relation_prefix_schedule.quotient_component_count(),
            relation_prefix_schedule.out_of_domain_point_count(),
            relation_prefix_schedule.opening_claim_count(),
            relation_prefix_schedule.maximum_candidate_draws_per_output(),
            relation_prefix_schedule.privacy_mode(),
        )
        .expect("the mutated relation-prefix schedule remains structurally valid");
        let mut relation_rescheduled_plan = plan.clone();
        relation_rescheduled_plan.relation_prefix_schedule = mutated_relation_prefix_schedule;
        assert_ne!(
            relation_rescheduled_plan
                .canonical_identity_hash()
                .expect("the relation-rescheduled plan identity is canonical"),
            construction_identity,
            "every acceptance-determining relation-prefix schedule field is identity-bound",
        );
        let checkpoint_schedule = plan
            .canonical_checkpoint_schedule_bytes()
            .expect("the selected checkpoint schedule is canonical");
        let mut rescheduled_plan = plan.clone();
        rescheduled_plan.checkpoints.reverse();
        assert_eq!(
            rescheduled_plan
                .canonical_identity_hash()
                .expect("checkpoint scheduling is excluded from cryptographic identity"),
            construction_identity,
        );
        assert_ne!(
            rescheduled_plan
                .canonical_checkpoint_schedule_bytes()
                .expect("rescheduled checkpoints remain canonically encoded"),
            checkpoint_schedule,
        );
    }

    fn selected_same_secret_construction_plan() -> RowCodeWhirConstructionPlan {
        let schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected same-secret relation context exists");
        let compiled_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &context,
        )
        .expect("the selected same-secret relation compiles");
        let artifact =
            ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
                .expect("the selected same-secret relation validates");
        let variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the selected same-secret relation plan has one variant");
        RowCodeWhirConstructionPlan::for_selected_variant(
            &artifact,
            variant.schedule_position(),
            variant.top_count(),
        )
        .expect("the selected same-secret construction plan derives")
    }

    #[test]
    fn quotient_computation_domain_is_plan_derived_and_context_bound() {
        let plan = selected_same_secret_construction_plan();
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the selected same-secret context exists");
        let quotient_domain = plan
            .quotient_computation_evaluation_domain(&context)
            .expect("the selected quotient computation domain derives");
        assert_eq!(quotient_domain.size(), 65_536);
        assert_eq!(
            quotient_domain.coset_offset().canonical(),
            context.evaluation_coset_offset
        );
        assert_eq!(plan.evaluation_domain_size, 16_777_216);

        type ContextMutation = (&'static str, fn(&mut RelationPlanCheckContext));
        let context_mutations: &[ContextMutation] = &[
            ("quotient component count", |mutated| {
                mutated.quotient_component_count += 1;
            }),
            ("quotient component degree", |mutated| {
                mutated.quotient_component_degree_bound_exclusive += 1;
            }),
            ("evaluation coset", |mutated| {
                mutated.evaluation_coset_offset += 1;
            }),
        ];
        for (label, mutate) in context_mutations {
            let mut mutated_context = context.clone();
            mutate(&mut mutated_context);
            assert!(
                plan.quotient_computation_evaluation_domain(&mutated_context)
                    .is_err(),
                "{label} drift must be rejected"
            );
        }

        let mut count_drifted_plan = plan.clone();
        count_drifted_plan.quotient_phase.quotient_component_count += 1;
        assert!(
            count_drifted_plan
                .quotient_computation_evaluation_domain(&context)
                .is_err()
        );
        let mut degree_drifted_plan = plan;
        degree_drifted_plan
            .quotient_phase
            .quotient_component_degree_bound_exclusive += 1;
        assert!(
            degree_drifted_plan
                .quotient_computation_evaluation_domain(&context)
                .is_err()
        );
    }

    #[test]
    fn checked_oracle_equation_catalog_is_closed_exact_and_mutation_sensitive() {
        let plan = selected_same_secret_construction_plan();
        let catalog = plan
            .oracle_equation_catalog()
            .expect("the checked same-secret oracle-equation catalog derives");
        validate_oracle_equation_catalog(&catalog)
            .expect("the checked catalog has a closed predecessor chain");
        let maximum_transcript_hash_query_count = catalog
            .maximum_transcript_hash_query_count()
            .expect("the construction-owned transcript ceiling derives");
        let logical_verifier_message_count = catalog
            .logical_verifier_message_count()
            .expect("the construction-owned verifier-message count derives");
        assert_eq!(
            maximum_transcript_hash_query_count,
            catalog
                .maximum_equation_count()
                .expect("the catalog equation ceiling derives"),
        );
        assert_eq!(maximum_transcript_hash_query_count, 1_141_598);
        assert_eq!(
            logical_verifier_message_count,
            u64::try_from(
                catalog
                    .operations
                    .iter()
                    .filter(|operation| {
                        oracle_equation_operation_leaves_pending_challenge(&operation.kind)
                    })
                    .count(),
            )
            .expect("the verifier-message count fits u64"),
        );
        assert_eq!(logical_verifier_message_count, 4_272);

        let mut product_expansion_count = 0_usize;
        let mut distinct_expansion_count = 0_usize;
        let mut linear_expansion_equation_count = 0_u64;
        for range in catalog
            .operations
            .iter()
            .flat_map(|operation| &operation.ranges)
        {
            match range.kind {
                RowCodeWhirOracleEquationRangeKind::ProductExpansion { .. } => {
                    product_expansion_count += 1;
                    linear_expansion_equation_count += range.equation_count;
                }
                RowCodeWhirOracleEquationRangeKind::DistinctExpansion { .. } => {
                    distinct_expansion_count += 1;
                    linear_expansion_equation_count += range.equation_count;
                }
                _ => {}
            }
        }
        assert_eq!(
            product_expansion_count,
            plan.relation_prefix_schedule()
                .ordered_application_challenge_groups()
                .len(),
        );
        assert_eq!(
            distinct_expansion_count,
            plan.transcript_operations
                .iter()
                .filter(|operation| matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. }
                ))
                .count(),
        );
        assert!(linear_expansion_equation_count > 0);

        let canonical_catalog_bytes = encode_oracle_equation_catalog(&catalog)
            .expect("the oracle-equation catalog encodes canonically");
        assert_eq!(
            encode_oracle_equation_catalog(&catalog)
                .expect("the repeated catalog encoding remains canonical"),
            canonical_catalog_bytes,
        );
        let catalog_hash = plan
            .oracle_equation_catalog_hash()
            .expect("the oracle-equation catalog hash derives");

        let construction_identity = plan
            .canonical_identity_hash()
            .expect("the same-secret construction identity derives");
        let mut checkpoint_rescheduled_plan = plan.clone();
        checkpoint_rescheduled_plan.checkpoints.reverse();
        let checkpoint_rescheduled_catalog = checkpoint_rescheduled_plan
            .oracle_equation_catalog()
            .expect("checkpoint rescheduling preserves a checked catalog");
        assert_eq!(
            encode_oracle_equation_catalog(&checkpoint_rescheduled_catalog)
                .expect("checkpoint rescheduling preserves the cryptographic catalog"),
            canonical_catalog_bytes,
        );
        assert_eq!(
            checkpoint_rescheduled_catalog
                .maximum_transcript_hash_query_count()
                .expect("checkpoint rescheduling preserves the transcript ceiling"),
            maximum_transcript_hash_query_count,
        );
        assert_eq!(
            checkpoint_rescheduled_catalog
                .logical_verifier_message_count()
                .expect("checkpoint rescheduling preserves the verifier-message count"),
            logical_verifier_message_count,
        );
        assert_eq!(
            checkpoint_rescheduled_plan
                .oracle_equation_catalog_hash()
                .expect("checkpoint rescheduling preserves the catalog hash"),
            catalog_hash,
        );
        assert_eq!(
            checkpoint_rescheduled_plan
                .canonical_identity_hash()
                .expect("checkpoint rescheduling preserves construction identity"),
            construction_identity,
        );

        let mut cryptographically_rescheduled_plan = plan.clone();
        let distinct_operation = cryptographically_rescheduled_plan
            .transcript_operations
            .iter_mut()
            .find(|operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                        role: RowCodeWhirQueryRole::Outer,
                        ..
                    }
                )
            })
            .expect("the outer-query operation exists");
        let RowCodeWhirTranscriptOperation::SampleDistinctIndices { output_count, .. } =
            distinct_operation
        else {
            unreachable!();
        };
        *output_count -= 1;
        let cryptographically_rescheduled_catalog = cryptographically_rescheduled_plan
            .oracle_equation_catalog()
            .expect("the changed cryptographic catalog remains checked");
        assert_ne!(
            encode_oracle_equation_catalog(&cryptographically_rescheduled_catalog)
                .expect("the changed cryptographic catalog remains canonical"),
            canonical_catalog_bytes,
        );
        assert_ne!(
            cryptographically_rescheduled_catalog
                .maximum_transcript_hash_query_count()
                .expect("the changed transcript ceiling remains defined"),
            maximum_transcript_hash_query_count,
        );
        assert_ne!(
            cryptographically_rescheduled_plan
                .oracle_equation_catalog_hash()
                .expect("the changed catalog hash remains defined"),
            catalog_hash,
        );
        assert_ne!(
            cryptographically_rescheduled_plan
                .canonical_identity_hash()
                .expect("the changed cryptographic identity remains canonical"),
            construction_identity,
        );

        let mut missing_operation = catalog.clone();
        missing_operation.operations.remove(1);
        assert!(validate_oracle_equation_catalog(&missing_operation).is_err());

        let product_operation_index = catalog
            .operations
            .iter()
            .position(|operation| {
                matches!(
                    &operation.kind,
                    RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(_)
                )
            })
            .expect("the product expansion exists");
        let mut missing_range = catalog.clone();
        missing_range.operations[product_operation_index]
            .ranges
            .pop();
        assert!(validate_oracle_equation_catalog(&missing_range).is_err());

        let mut duplicated_range = catalog.clone();
        let duplicated = duplicated_range.operations[product_operation_index].ranges[0];
        duplicated_range.operations[product_operation_index]
            .ranges
            .insert(0, duplicated);
        assert!(validate_oracle_equation_catalog(&duplicated_range).is_err());

        let multi_range_operation_index = catalog
            .operations
            .iter()
            .position(|operation| operation.ranges.len() >= 3)
            .expect("one challenge closes a predecessor before its handle");
        let mut reordered_ranges = catalog.clone();
        reordered_ranges.operations[multi_range_operation_index]
            .ranges
            .swap(1, 2);
        assert!(validate_oracle_equation_catalog(&reordered_ranges).is_err());

        let mut stale_range_predecessor = catalog.clone();
        stale_range_predecessor.operations[multi_range_operation_index].ranges[2].predecessor =
            RowCodeWhirOracleEquationPredecessor::PriorRangeTerminal { range_ordinal: 0 };
        assert!(validate_oracle_equation_catalog(&stale_range_predecessor).is_err());

        let mut forward_operation_predecessor = catalog;
        forward_operation_predecessor.operations[1].predecessor_operation_ordinal = Some(2);
        assert!(validate_oracle_equation_catalog(&forward_operation_predecessor).is_err());
    }

    #[test]
    fn candidate_bcs_catalog_uses_the_live_one_edge_sampler_chain() {
        let plan = selected_same_secret_construction_plan();
        let catalog = plan
            .linear_bcs_transcript_plan()
            .expect("the literal BCS transcript plan derives");
        let round_count = catalog
            .round_count()
            .expect("the literal BCS round count derives");
        let selected_accounting = plan
            .linear_bcs_hash_query_accounting()
            .expect("the selected literal BCS hash-query accounting derives");
        let selected_catalog_hash = plan
            .linear_bcs_transcript_plan_hash()
            .expect("the selected literal BCS catalog hash derives");
        assert_eq!(round_count, 690_142);
        assert_ne!(selected_catalog_hash, [0_u8; 64]);
        assert_eq!(selected_accounting.round_count, round_count);
        assert_eq!(
            selected_accounting.maximum_single_opening_hash_query_count,
            64
        );
        assert_eq!(selected_accounting.supplied_commitment_opening_count, 3_680);
        assert_eq!(
            selected_accounting.supplied_commitment_independent_opening_hash_query_count_ceiling,
            200_297,
        );
        let opening_query_order =
            linear_bcs_transcript::LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder;
        let merkle_traversal_order =
            linear_bcs_transcript::LinearBcsMerkleTraversalOrder::SortedCoordinates;
        assert_eq!(
            catalog.supplied_commitment_openings(),
            &[
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase {
                            phase: RowCodeWhirPhase::Base,
                        },
                    owner: linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector,
                    payload_leaf_count: 2_097_152,
                    query_count: 387,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase {
                            phase: RowCodeWhirPhase::Auxiliary,
                        },
                    owner: linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector,
                    payload_leaf_count: 2_097_152,
                    query_count: 387,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase {
                            phase: RowCodeWhirPhase::Quotient,
                        },
                    owner: linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector,
                    payload_leaf_count: 2_097_152,
                    query_count: 387,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate,
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 0,
                        },
                    payload_leaf_count: 1_048_576,
                    query_count: 387,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad,
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 5,
                        },
                    payload_leaf_count: 8_192,
                    query_count: 393,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                            round_ordinal: 0,
                        },
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 1,
                        },
                    payload_leaf_count: 524_288,
                    query_count: 288,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                            round_ordinal: 1,
                        },
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 2,
                        },
                    payload_leaf_count: 262_144,
                    query_count: 268,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                            round_ordinal: 2,
                        },
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 3,
                        },
                    payload_leaf_count: 131_072,
                    query_count: 264,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                            round_ordinal: 3,
                        },
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 4,
                        },
                    payload_leaf_count: 65_536,
                    query_count: 263,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource,
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 4,
                        },
                    payload_leaf_count: 65_536,
                    query_count: 263,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad,
                    owner:
                        linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                            epoch_ordinal: 5,
                        },
                    payload_leaf_count: 8_192,
                    query_count: 393,
                    query_order: opening_query_order,
                    merkle_traversal_order,
                },
            ],
        );
        let supplied_roots = catalog
            .round_ranges()
            .iter()
            .filter(|range| {
                matches!(
                    range.prover_oracle_root,
                    linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment { .. }
                )
            })
            .count();
        assert_eq!(supplied_roots, catalog.supplied_commitment_openings().len());
        assert_eq!(
            catalog.final_query().verifier_message_ordinal,
            round_count + 1
        );
        let one_edge_sampler_block_count = catalog
            .one_edge_sampler_block_count()
            .expect("the one-edge sampler block count derives");
        let prover_oracle_round_count = round_count - one_edge_sampler_block_count;
        assert_eq!(
            catalog
                .chain_hash_query_count()
                .expect("the typed chain query count derives"),
            one_edge_sampler_block_count + 2 * prover_oracle_round_count,
        );
        assert_eq!(
            catalog.challenge_selection_rule(),
            linear_bcs_transcript::LinearBcsChallengeSelectionRule::FirstAcceptedInCompleteFixedBlockRange,
        );
        assert!(
            catalog
                .one_edge_sampler_block_count()
                .expect("the one-edge sampler count derives")
                > 0,
        );
        assert!(
            catalog
                .canonical_message_root_hash_query_count()
                .expect("the canonical message-root query count derives")
                > 0,
        );
        assert_eq!(
            linear_bcs_transcript::linear_bcs_round_ordinal_encoding(0),
            Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry),
        );
        assert_ne!(
            linear_bcs_transcript::linear_bcs_round_ordinal_encoding(1)
                .expect("the first round has one canonical encoding"),
            linear_bcs_transcript::linear_bcs_round_ordinal_encoding(2)
                .expect("the second round has one canonical encoding"),
        );
        assert_ne!(
            linear_bcs_transcript::linear_bcs_sampler_block_address_encoding(1, 0),
            linear_bcs_transcript::linear_bcs_sampler_block_address_encoding(1, 1),
        );

        let aggregate_commitment_operation_ordinal = plan
            .transcript_operations
            .iter()
            .position(|operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::ObserveCommitment {
                        role: RowCodeWhirCommitmentRole::Aggregate,
                    }
                )
            })
            .expect("the aggregate commitment operation exists");
        let outer_query_operation_ordinal = plan
            .transcript_operations
            .iter()
            .position(|operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                        role: RowCodeWhirQueryRole::Outer,
                        ..
                    }
                )
            })
            .expect("the outer query operation exists");
        let aggregate_wide_pad_commitment_operation_ordinal = plan
            .transcript_operations
            .iter()
            .position(|operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::ObserveCommitment {
                        role: RowCodeWhirCommitmentRole::AggregateWidePad,
                    }
                )
            })
            .expect("the aggregate-wide pad commitment operation exists");
        let bound_query_operation_ordinal = plan
            .transcript_operations
            .iter()
            .position(|operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                        role: RowCodeWhirQueryRole::Bound,
                        ..
                    }
                )
            })
            .expect("the bound query operation exists");
        assert_eq!(
            aggregate_wide_pad_commitment_operation_ordinal,
            aggregate_commitment_operation_ordinal + 1,
        );
        assert_eq!(
            bound_query_operation_ordinal,
            outer_query_operation_ordinal + 1,
        );
        let bound_opening_weight_operation_ordinals = plan
            .transcript_operations
            .iter()
            .enumerate()
            .filter_map(|(operation_ordinal, operation)| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::Direct(
                            RowCodeWhirChallenge::BoundOpeningWeight { .. }
                        ),
                        ..
                    }
                )
                .then_some(operation_ordinal)
            })
            .collect::<Vec<_>>();
        assert!(!bound_opening_weight_operation_ordinals.is_empty());
        assert!(
            bound_opening_weight_operation_ordinals
                .iter()
                .all(
                    |operation_ordinal| *operation_ordinal < aggregate_commitment_operation_ordinal
                ),
        );
        assert!(
            plan.transcript_operations[..aggregate_commitment_operation_ordinal]
                .iter()
                .all(|operation| !matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                        role: RowCodeWhirQueryRole::Bound,
                        ..
                    } | RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::Direct(
                            RowCodeWhirChallenge::BoundDegreeCoordinate { .. }
                        ),
                        ..
                    }
                ))
        );
        let bound_degree_operation_ordinals = plan
            .transcript_operations
            .iter()
            .enumerate()
            .filter_map(|(operation_ordinal, operation)| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::Direct(
                            RowCodeWhirChallenge::BoundDegreeCoordinate { .. }
                        ),
                        ..
                    }
                )
                .then_some(operation_ordinal)
            })
            .collect::<Vec<_>>();
        assert!(!bound_degree_operation_ordinals.is_empty());
        assert!(
            bound_degree_operation_ordinals
                .iter()
                .all(|operation_ordinal| {
                    *operation_ordinal > aggregate_wide_pad_commitment_operation_ordinal
                        && *operation_ordinal < outer_query_operation_ordinal
                }),
        );

        let canonical_bytes = catalog
            .canonical_bytes()
            .expect("the literal BCS transcript plan encodes canonically");
        assert_eq!(
            plan.linear_bcs_transcript_plan()
                .expect("the repeated literal BCS transcript plan derives")
                .canonical_bytes()
                .expect("the repeated literal BCS transcript plan encodes"),
            canonical_bytes,
        );

        let mut checkpoint_rescheduled_plan = plan.clone();
        checkpoint_rescheduled_plan.checkpoints.reverse();
        assert_eq!(
            checkpoint_rescheduled_plan
                .linear_bcs_transcript_plan()
                .expect("checkpoint rescheduling preserves the literal BCS plan")
                .canonical_bytes()
                .expect("checkpoint rescheduling preserves the literal BCS encoding"),
            canonical_bytes,
        );

        let mut changed_aggregate_payload_plan = plan.clone();
        changed_aggregate_payload_plan.whir.rounds[0]
            .encoded_oracle
            .leaf_count /= 2;
        assert!(
            changed_aggregate_payload_plan
                .linear_bcs_transcript_plan()
                .is_err(),
        );

        let mut changed_successor_epoch_plan = plan.clone();
        changed_successor_epoch_plan.whir.rounds[1]
            .query_epoch
            .domain_size /= 2;
        assert!(
            changed_successor_epoch_plan
                .linear_bcs_transcript_plan()
                .is_err(),
        );

        let mut changed_final_epoch_plan = plan.clone();
        changed_final_epoch_plan
            .whir
            .final_round
            .query_epoch
            .epoch_ordinal -= 1;
        assert!(
            changed_final_epoch_plan
                .linear_bcs_transcript_plan()
                .is_err(),
        );

        let mut reordered_epoch_plan = plan.clone();
        let earlier_query_epoch = reordered_epoch_plan.whir.rounds[1].query_epoch;
        reordered_epoch_plan.whir.rounds[1].query_epoch =
            reordered_epoch_plan.whir.rounds[2].query_epoch;
        reordered_epoch_plan.whir.rounds[2].query_epoch = earlier_query_epoch;
        assert!(reordered_epoch_plan.linear_bcs_transcript_plan().is_err());

        let mut missing_aggregate_root_plan = plan.clone();
        missing_aggregate_root_plan
            .transcript_operations
            .retain(|operation| {
                !matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::ObserveCommitment {
                        role: RowCodeWhirCommitmentRole::Aggregate,
                    }
                )
            });
        assert!(
            missing_aggregate_root_plan
                .linear_bcs_transcript_plan()
                .is_err(),
        );

        let mut duplicated_aggregate_root_plan = plan.clone();
        duplicated_aggregate_root_plan.transcript_operations.insert(
            aggregate_commitment_operation_ordinal,
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::Aggregate,
            },
        );
        assert!(
            duplicated_aggregate_root_plan
                .linear_bcs_transcript_plan()
                .is_err(),
        );

        let mut changed_query_plan = plan;
        let RowCodeWhirTranscriptOperation::SampleDistinctIndices { output_count, .. } =
            changed_query_plan
                .transcript_operations
                .iter_mut()
                .find(|operation| {
                    matches!(
                        operation,
                        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                            role: RowCodeWhirQueryRole::Outer,
                            ..
                        }
                    )
                })
                .expect("the outer-query sampler exists")
        else {
            unreachable!();
        };
        *output_count -= 1;
        assert!(changed_query_plan.linear_bcs_transcript_plan().is_err(),);
    }
}
