//! Canonical combined proof for the exact production same-secret relation.
//!
//! The proof binds the three masked production phases to one plain-WHIR
//! opening argument. Public statement trees remain verifier-owned inputs and
//! are never accepted from the proof object.

use std::collections::{BTreeMap, BTreeSet};

use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_symmetric::MerkleCap;
use zeroize::Zeroizing;

use super::super::GOLDILOCKS_MODULUS;
#[cfg(test)]
use super::super::column_commitment::verify_column_frontier;
use super::super::column_commitment::{hash_opened_column, verify_prehashed_column_frontier};
use super::super::construction_plan::{
    RowCodeWhirAggregateColumnRole, RowCodeWhirBoundLowDegreeMode, RowCodeWhirConstructionPlan,
    RowCodeWhirOpenedPolynomialSource, RowCodeWhirPhase, RowCodeWhirProofSectionPlan,
    RowCodeWhirProofSectionRole, RowCodeWhirSoundnessAssumption, RowCodeWhirTracePhasePlan,
};
#[cfg(test)]
use super::super::plain_whir::plain_aggregate_pcs;
#[cfg(all(test, not(target_arch = "wasm32")))]
use super::super::plain_whir::verify_plain_aggregate_batches_at_points_after_commitment;
use super::super::plain_whir_wire::{
    PlainWhirIncrementalDecoder, PlainWhirWireEncodingProgress, PlainWhirWireSinkEncoder,
    PlainWhirWireSinkEncodingError, plain_whir_incremental_decoder_resident_memory_accounting,
};
use super::super::row_encoding::RowEncodingGeometry;
use super::super::{
    AuthenticatedColumn, ChallengeField, ExtensionFieldChallenger,
    RowCodeWhirChallengerProofStreamAbsorber,
    algebra::{coset_point, polynomial_extension_opening_reduction, polynomial_opening_reduction},
    plain_whir::{
        PlainAggregateCommitment, PlainAggregateIncrementalVerificationPreparation,
        PlainAggregateProof, plain_aggregate_challenger_from_transcript,
        plain_aggregate_pcs_for_construction_plan,
    },
};
#[cfg(all(test, not(target_arch = "wasm32")))]
use super::super::{
    plain_whir::{AggregateLayout, plain_aggregate_challenger},
    plain_whir_wire::plain_whir_batch_wire_breakdown,
    protocol::{StreamingCommitment, aggregate_weighted_message, recompute_authenticated_columns},
    streaming_whir_prover::{
        StreamingPlainAggregateOpeningRequest, commit_streaming_plain_aggregate,
        open_streaming_plain_aggregate_batches_at_points, streaming_plain_aggregate_prover_data,
    },
};
use super::*;
use crate::bgv::proof_suite::prover::requested_pre_challenge_source_column_ordinals;
use crate::bgv::proof_suite::relation_plan::{
    ProofPrivacyMode, RelationColumnOrigin, RelationOpeningSourceClass,
};
use crate::bgv::proof_suite::transcript::{
    RowCodeWhirChallenge, RowCodeWhirTracePhase, RowCodeWhirTranscript,
};
use crate::bgv::proof_suite::{
    BoundTreeConstructionKind, BoundTreeRootUse, COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
    CommonProofByteSink, MAXIMUM_COMMON_PROOF_BYTE_LENGTH, OutOfDomainCompositionVerificationInput,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    ProofBaseFieldElement, ProofByteSource, ProofChallengeExtensionElement, ProofEvaluationDomain,
    ProofTreeCatalogEntry, ProofTreeValue, RelationPlanCheckContext, RelationPlanVariant,
    RelationProofTreeInput, StatementOwnedProofTreeInput, VerifiedKeyRelationColumnEvaluator,
    VerifiedRelationColumnEvaluator, build_relation_bound_public_tree_catalog_entries,
};

const EXACT_PROOF_WIRE_MAGIC: &[u8; 8] = b"SLXPRF05";
#[cfg(test)]
use super::super::MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH;
#[cfg(test)]
const EXACT_PROOF_TABLE_WIDTH: usize = 4;
#[cfg(test)]
const EXACT_COLUMN_QUERY_COUNT: usize = 387;
const EXACT_TABLE_VARIABLE_COUNT: usize = 19;
const EXACT_PCS_VARIABLE_COUNT: usize = 21;
const EXACT_QUOTIENT_PHASE_ROW_COUNT: usize = 15;
const EXACT_OPENING_BATCH_MASK_CHUNK_COUNT: usize = 8;
const EXACT_BOUND_TREE_COUNT: usize = 11;
const EXACT_INPUT_BOUND_TREE_COUNT: usize = 8;
const EXACT_OUTPUT_BOUND_TREE_COUNT: usize = 3;
const EXACT_BOUND_COLUMN_COUNT: usize = 44;
const EXACT_INPUT_BOUND_COLUMN_COUNT: usize = 32;
const EXACT_OUTPUT_BOUND_COLUMN_COUNT: usize = 12;
pub(in crate::bgv::proof_suite::row_code_whir) const EXACT_BOUND_TREE_ROW_WIDTH: usize = 4;
#[cfg(test)]
const EXACT_INPUT_BOUND_QUERY_COUNT: usize = 40;
#[cfg(test)]
const EXACT_OUTPUT_BOUND_QUERY_COUNT: usize = 266;
const EXACT_BOUND_LEAF_COUNT: usize = 1 << 20;
const EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT: usize = 15;
#[cfg(test)]
const EXACT_BOUND_REDUCTION_COLUMN_INDEX: usize = 3;
const EXACT_BOUND_REDUCTION_BLOCK_COUNT: usize = 2;
const EXACT_BOUND_REDUCTION_BLOCK_SELECTOR_VARIABLE_COUNT: usize = 1;
const EXACT_INPUT_BOUND_DEGREE_SUFFIX_PREFIXES: &[&[u8]] =
    &[&[1_u8, 1], &[1_u8, 0, 1], &[1_u8, 0, 0, 1]];
const EXACT_OUTPUT_BOUND_DEGREE_SUFFIX_PREFIXES: &[&[u8]] = &[&[1_u8]];
const EXACT_BOUND_DEGREE_TEST_COUNT: usize = EXACT_BOUND_REDUCTION_BLOCK_COUNT
    + EXACT_INPUT_BOUND_DEGREE_SUFFIX_PREFIXES.len()
    + EXACT_OUTPUT_BOUND_DEGREE_SUFFIX_PREFIXES.len();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactBoundReductionBlockSchedule {
    root_use: BoundTreeRootUse,
    source_degree_bound_exclusive: usize,
    quotient_degree_bound_exclusive: usize,
    degree_suffix_prefixes: &'static [&'static [u8]],
}

impl ExactBoundReductionBlockSchedule {
    const fn degree_test_count(self) -> usize {
        1 + self.degree_suffix_prefixes.len()
    }

    #[cfg(test)]
    fn random_degree_coordinate_count(self) -> usize {
        self.degree_suffix_prefixes
            .iter()
            .map(|prefix| EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT - prefix.len())
            .sum()
    }
}

const EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES: [ExactBoundReductionBlockSchedule;
    EXACT_BOUND_REDUCTION_BLOCK_COUNT] = [
    ExactBoundReductionBlockSchedule {
        root_use: BoundTreeRootUse::Input,
        source_degree_bound_exclusive: 18_432,
        quotient_degree_bound_exclusive: 18_431,
        degree_suffix_prefixes: EXACT_INPUT_BOUND_DEGREE_SUFFIX_PREFIXES,
    },
    ExactBoundReductionBlockSchedule {
        root_use: BoundTreeRootUse::Output,
        source_degree_bound_exclusive: 16_384,
        quotient_degree_bound_exclusive: 16_383,
        degree_suffix_prefixes: EXACT_OUTPUT_BOUND_DEGREE_SUFFIX_PREFIXES,
    },
];
#[cfg(test)]
const EXACT_VERIFIER_MERKLE_HASH_QUERY_COUNT: u64 = 61_241;
const EXACT_RELATION_PLAN_HASH_QUERY_COUNT: u64 = 1;
const EXACT_RELATION_PLAN_DISTINCT_EQUATION_COUNT: u64 = 1;
const EXACT_VARIANT_HASH_QUERY_COUNT: u64 = 1;
const EXACT_VARIANT_DISTINCT_EQUATION_COUNT: u64 = 1;
const EXACT_CONSTRUCTION_PLAN_IDENTITY_HASH_QUERY_COUNT: u64 = 1;
const EXACT_CONSTRUCTION_PLAN_IDENTITY_DISTINCT_EQUATION_COUNT: u64 = 1;
const EXACT_TRANSCRIPT_HEADER_HASH_QUERY_COUNT: u64 = 1;
const EXACT_TRANSCRIPT_HEADER_DISTINCT_EQUATION_COUNT: u64 = 1;
const EXACT_APPLICATION_STATEMENT_HASH_QUERY_COUNT: u64 = 1;
const EXACT_APPLICATION_STATEMENT_DISTINCT_EQUATION_COUNT: u64 = 1;
const EXACT_PUBLIC_SETUP_SAMPLING_HASH_QUERY_COUNT: u64 = 18;
const EXACT_PUBLIC_SETUP_SAMPLING_DISTINCT_EQUATION_COUNT: u64 = 9;
const EXACT_VERIFIER_NON_MERKLE_HASH_QUERY_COUNT: u64 = EXACT_RELATION_PLAN_HASH_QUERY_COUNT
    + EXACT_VARIANT_HASH_QUERY_COUNT
    + EXACT_CONSTRUCTION_PLAN_IDENTITY_HASH_QUERY_COUNT
    + EXACT_TRANSCRIPT_HEADER_HASH_QUERY_COUNT
    + EXACT_APPLICATION_STATEMENT_HASH_QUERY_COUNT
    + EXACT_PUBLIC_SETUP_SAMPLING_HASH_QUERY_COUNT;
const EXACT_VERIFIER_NON_MERKLE_DISTINCT_EQUATION_COUNT: u64 =
    EXACT_RELATION_PLAN_DISTINCT_EQUATION_COUNT
        + EXACT_VARIANT_DISTINCT_EQUATION_COUNT
        + EXACT_CONSTRUCTION_PLAN_IDENTITY_DISTINCT_EQUATION_COUNT
        + EXACT_TRANSCRIPT_HEADER_DISTINCT_EQUATION_COUNT
        + EXACT_APPLICATION_STATEMENT_DISTINCT_EQUATION_COUNT
        + EXACT_PUBLIC_SETUP_SAMPLING_DISTINCT_EQUATION_COUNT;
#[cfg(all(test, not(target_arch = "wasm32")))]
const EXACT_PROOF_ARTIFACT_NAME: &str = "same-secret-row-code-whir-proof-v1.bin";
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactBoundLeafOpening {
    persistent_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    first_point_values: [ProofBaseFieldElement; EXACT_BOUND_TREE_ROW_WIDTH],
    opposite_point_values: [ProofBaseFieldElement; EXACT_BOUND_TREE_ROW_WIDTH],
}

impl ExactBoundLeafOpening {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        persistent_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: [ProofBaseFieldElement; EXACT_BOUND_TREE_ROW_WIDTH],
        opposite_point_values: [ProofBaseFieldElement; EXACT_BOUND_TREE_ROW_WIDTH],
    ) -> Self {
        Self {
            persistent_salt,
            first_point_values,
            opposite_point_values,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactBoundTreeAuthentication {
    opened_leaves: Vec<ExactBoundLeafOpening>,
    frontier: Vec<[u8; 64]>,
}

impl ExactBoundTreeAuthentication {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        opened_leaves: Vec<ExactBoundLeafOpening>,
        frontier: Vec<[u8; 64]>,
    ) -> Self {
        Self {
            opened_leaves,
            frontier,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactBoundQueryIndices {
    accepted_input_root_indices: Vec<usize>,
    accepted_output_root_indices: Vec<usize>,
    input_root_traversal_indices: Vec<usize>,
    output_root_traversal_indices: Vec<usize>,
}

impl ExactBoundQueryIndices {
    fn has_exact_shape(&self, shape: ExactProofShape) -> bool {
        if self.accepted_input_root_indices.len() != shape.verified_vss_bound_query_count
            || self.accepted_output_root_indices.len() != shape.direct_bound_query_count
            || self.input_root_traversal_indices.len() != shape.verified_vss_bound_query_count
            || self.output_root_traversal_indices.len() != shape.direct_bound_query_count
            || self
                .accepted_output_root_indices
                .get(..shape.verified_vss_bound_query_count)
                != Some(self.accepted_input_root_indices.as_slice())
        {
            return false;
        }
        let mut expected_input_root_traversal_indices = self.accepted_input_root_indices.clone();
        expected_input_root_traversal_indices.sort_unstable();
        let mut expected_output_root_traversal_indices = self.accepted_output_root_indices.clone();
        expected_output_root_traversal_indices.sort_unstable();
        self.input_root_traversal_indices == expected_input_root_traversal_indices
            && self.output_root_traversal_indices == expected_output_root_traversal_indices
            && self
                .output_root_traversal_indices
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && self
                .output_root_traversal_indices
                .iter()
                .all(|leaf_index| *leaf_index < EXACT_BOUND_LEAF_COUNT)
    }

    #[cfg(test)]
    fn accepted_indices_for_root_use(&self, root_use: BoundTreeRootUse) -> &[usize] {
        match root_use {
            BoundTreeRootUse::Input => &self.accepted_input_root_indices,
            BoundTreeRootUse::Output => &self.accepted_output_root_indices,
        }
    }

    fn traversal_indices_for_tree_ordinal(
        &self,
        shape: ExactProofShape,
        bound_tree_ordinal: usize,
    ) -> Result<&[usize], String> {
        let indices = match bound_tree_ordinal {
            0..EXACT_INPUT_BOUND_TREE_COUNT => Ok(&self.input_root_traversal_indices),
            EXACT_INPUT_BOUND_TREE_COUNT..EXACT_BOUND_TREE_COUNT => {
                Ok(&self.output_root_traversal_indices)
            }
            _ => Err("bound tree ordinal is outside the exact relation".to_owned()),
        }?;
        if indices.len() != shape.bound_tree_query_count(bound_tree_ordinal)? {
            return Err("bound query indices do not match the checked construction".to_owned());
        }
        Ok(indices)
    }

    fn accepted_query_ordinal_for_tree(
        &self,
        bound_tree_ordinal: usize,
        leaf_index: usize,
    ) -> Result<usize, String> {
        let accepted_indices = match bound_tree_ordinal {
            0..EXACT_INPUT_BOUND_TREE_COUNT => &self.accepted_input_root_indices,
            EXACT_INPUT_BOUND_TREE_COUNT..EXACT_BOUND_TREE_COUNT => {
                &self.accepted_output_root_indices
            }
            _ => return Err("bound tree ordinal is outside the exact relation".to_owned()),
        };
        accepted_indices
            .iter()
            .position(|accepted_leaf_index| *accepted_leaf_index == leaf_index)
            .ok_or_else(|| "bound traversal index is absent from accepted query order".to_owned())
    }
}

#[cfg_attr(test, derive(Clone))]
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretProof {
    base_root: ColumnDigest,
    auxiliary_root: ColumnDigest,
    quotient_root: ColumnDigest,
    out_of_domain_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_mask_chunk_evaluations:
        [ProofChallengeExtensionElement; EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
    aggregate_commitment: PlainAggregateCommitment,
    authenticated_phase_columns: [Vec<AuthenticatedColumn>; 3],
    phase_frontiers: [Vec<ColumnDigest>; 3],
    bound_tree_authentications: Vec<ExactBoundTreeAuthentication>,
    aggregate_opening_proof: PlainAggregateProof,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretPhaseOpenings {
    roots: [ColumnDigest; 3],
    authenticated_columns: [Vec<AuthenticatedColumn>; 3],
    frontiers: [Vec<ColumnDigest>; 3],
}

impl ExactSameSecretPhaseOpenings {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        roots: [ColumnDigest; 3],
        authenticated_columns: [Vec<AuthenticatedColumn>; 3],
        frontiers: [Vec<ColumnDigest>; 3],
    ) -> Self {
        Self {
            roots,
            authenticated_columns,
            frontiers,
        }
    }
}

impl ExactSameSecretProof {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        phase_openings: ExactSameSecretPhaseOpenings,
        out_of_domain_evaluations: Vec<ProofChallengeExtensionElement>,
        opening_batch_mask_chunk_evaluations: [ProofChallengeExtensionElement;
            EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
        aggregate_commitment: PlainAggregateCommitment,
        bound_tree_authentications: Vec<ExactBoundTreeAuthentication>,
        aggregate_opening_proof: PlainAggregateProof,
    ) -> Self {
        let [base_root, auxiliary_root, quotient_root] = phase_openings.roots;
        Self {
            base_root,
            auxiliary_root,
            quotient_root,
            out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations,
            aggregate_commitment,
            authenticated_phase_columns: phase_openings.authenticated_columns,
            phase_frontiers: phase_openings.frontiers,
            bound_tree_authentications,
            aggregate_opening_proof,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactProofShape {
    base_row_count: usize,
    auxiliary_row_count: usize,
    quotient_row_count: usize,
    opening_claim_count: usize,
    encoded_column_count: usize,
    outer_query_count: usize,
    verified_vss_bound_query_count: usize,
    direct_bound_query_count: usize,
    aggregate_table_width: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretProofShape {
    shape: ExactProofShape,
    construction_plan_identity_hash: [u8; 64],
}

impl ExactSameSecretProofShape {
    pub(super) const fn construction_plan_identity_hash(self) -> [u8; 64] {
        self.construction_plan_identity_hash
    }
}

/// Move-only authority for the post-commitment opening schedule. The point-row
/// weights are sampled before the aggregate commitment and cross that boundary
/// only through this opaque continuation.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretOpeningScheduleContinuation {
    shape: ExactProofShape,
    construction_plan_identity_hash: [u8; 64],
    evaluation_domain_generator: u64,
    evaluation_coset_offset: u64,
    point_row_weights: [ExactPointRowWeights; 3],
}

pub(super) fn exact_same_secret_opening_schedule_continuation(
    checked_shape: ExactSameSecretProofShape,
    relation_context: &RelationPlanCheckContext,
    point_row_weights: [ExactPointRowWeights; 3],
) -> ExactSameSecretOpeningScheduleContinuation {
    ExactSameSecretOpeningScheduleContinuation {
        shape: checked_shape.shape,
        construction_plan_identity_hash: checked_shape.construction_plan_identity_hash,
        evaluation_domain_generator: relation_context.evaluation_domain_generator,
        evaluation_coset_offset: relation_context.evaluation_coset_offset,
        point_row_weights,
    }
}

/// Complete plan-derived opening schedule sampled after the aggregate
/// commitment has already been observed by the shared challenger.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretOpeningSchedule {
    points: Vec<Point<ChallengeField>>,
    requested_columns_by_point: Vec<Vec<usize>>,
    outer_accepted_query_indices: Vec<usize>,
    outer_traversal_query_indices: Vec<usize>,
    bound_query_indices: ExactBoundQueryIndices,
    bound_evaluation_domain: ProofEvaluationDomain,
    degree_test_points: Vec<Point<ChallengeField>>,
    point_row_weights: [ExactPointRowWeights; 3],
}

impl ExactSameSecretOpeningSchedule {
    pub(in crate::bgv::proof_suite::row_code_whir) fn points(&self) -> &[Point<ChallengeField>] {
        &self.points
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn requested_columns_by_point(
        &self,
    ) -> &[Vec<usize>] {
        &self.requested_columns_by_point
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn outer_accepted_query_indices(
        &self,
    ) -> &[usize] {
        &self.outer_accepted_query_indices
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn outer_traversal_query_indices(
        &self,
    ) -> &[usize] {
        &self.outer_traversal_query_indices
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn accepted_input_bound_query_indices(
        &self,
    ) -> &[usize] {
        &self.bound_query_indices.accepted_input_root_indices
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn accepted_output_bound_query_indices(
        &self,
    ) -> &[usize] {
        &self.bound_query_indices.accepted_output_root_indices
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn input_bound_traversal_query_indices(
        &self,
    ) -> &[usize] {
        &self.bound_query_indices.input_root_traversal_indices
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn output_bound_traversal_query_indices(
        &self,
    ) -> &[usize] {
        &self.bound_query_indices.output_root_traversal_indices
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn bound_evaluation_domain(
        &self,
    ) -> ProofEvaluationDomain {
        self.bound_evaluation_domain
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn degree_test_points(
        &self,
    ) -> &[Point<ChallengeField>] {
        &self.degree_test_points
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn point_row_weights(
        &self,
    ) -> &[ExactPointRowWeights; 3] {
        &self.point_row_weights
    }
}

impl ExactProofShape {
    #[cfg(test)]
    fn from_variant(variant: &RelationPlanVariant) -> Result<Self, String> {
        let base_layout = ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::BaseOracle)?;
        let auxiliary_layout =
            ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::AuxiliaryOracle)?;
        let geometry = base_layout.geometry()?;
        if auxiliary_layout.geometry()?.encoded_column_count != geometry.encoded_column_count {
            return Err("exact phase encodings do not share one column domain".to_owned());
        }
        Ok(Self {
            base_row_count: base_layout.rows.len(),
            auxiliary_row_count: auxiliary_layout.rows.len(),
            quotient_row_count: EXACT_QUOTIENT_PHASE_ROW_COUNT,
            opening_claim_count: variant.ordered_opening_claims().len(),
            encoded_column_count: geometry.encoded_column_count,
            outer_query_count: EXACT_COLUMN_QUERY_COUNT,
            verified_vss_bound_query_count: EXACT_INPUT_BOUND_QUERY_COUNT,
            direct_bound_query_count: EXACT_OUTPUT_BOUND_QUERY_COUNT,
            aggregate_table_width: EXACT_PROOF_TABLE_WIDTH,
        })
    }

    const fn phase_row_counts(self) -> [usize; 3] {
        [
            self.base_row_count,
            self.auxiliary_row_count,
            self.quotient_row_count,
        ]
    }

    fn maximum_frontier_count(self) -> Result<usize, String> {
        self.outer_query_count
            .checked_mul(self.encoded_column_count.ilog2() as usize)
            .ok_or_else(|| "exact frontier bound overflowed".to_owned())
    }

    fn bound_reduction_evaluation_count(self) -> Result<usize, String> {
        self.verified_vss_bound_query_count
            .checked_add(self.direct_bound_query_count)
            .and_then(|query_count| query_count.checked_mul(2))
            .ok_or_else(|| "bound reduction evaluation count overflowed".to_owned())
    }

    fn bound_tree_query_count(self, bound_tree_ordinal: usize) -> Result<usize, String> {
        match bound_tree_ordinal {
            0..EXACT_INPUT_BOUND_TREE_COUNT => Ok(self.verified_vss_bound_query_count),
            EXACT_INPUT_BOUND_TREE_COUNT..EXACT_BOUND_TREE_COUNT => {
                Ok(self.direct_bound_query_count)
            }
            _ => Err("bound tree ordinal is outside the exact relation".to_owned()),
        }
    }
}

fn validate_exact_trace_phase_plan(
    phase: Option<&RowCodeWhirTracePhasePlan>,
    expected_layout: &ExactBasePhaseLayout,
    expected_tree_role: ProofTreeRole,
) -> Result<RowEncodingGeometry, String> {
    let phase = phase
        .ok_or_else(|| format!("exact construction plan omits the {expected_tree_role:?} phase"))?;
    let expected_geometry = expected_layout.geometry()?;
    if phase.tree_role != expected_tree_role
        || phase.geometry != expected_geometry
        || phase.rows.len() != expected_layout.rows.len()
    {
        return Err(format!(
            "exact construction plan has the wrong {expected_tree_role:?} geometry"
        ));
    }
    for (row_index, (planned_row, expected_row)) in
        phase.rows.iter().zip(&expected_layout.rows).enumerate()
    {
        let expected_row_ordinal = u32::try_from(row_index)
            .map_err(|_| "exact trace-phase row ordinal exceeds u32".to_owned())?;
        if planned_row.column_group_ordinal != expected_row_ordinal
            || planned_row.coefficient_chunk_ordinal != 0
            || planned_row.opening_point_ordinals != expected_row.opening_point_ordinals
        {
            return Err(format!(
                "exact construction plan has the wrong {expected_tree_role:?} row metadata"
            ));
        }
        for (planned_chunk, expected_column_ordinal) in planned_row
            .logical_polynomial_chunks
            .iter()
            .zip(expected_row.column_ordinals)
        {
            match (planned_chunk, expected_column_ordinal) {
                (None, None) => {}
                (Some(planned_chunk), Some(expected_column_ordinal))
                    if planned_chunk.column_ordinal == expected_column_ordinal
                        && planned_chunk.coefficient_chunk_ordinal == 0 => {}
                _ => {
                    return Err(format!(
                        "exact construction plan has the wrong {expected_tree_role:?} row encoding"
                    ));
                }
            }
        }
    }
    Ok(expected_geometry)
}

fn validate_exact_quotient_phase_plan(
    plan: &RowCodeWhirConstructionPlan,
    context: &RelationPlanCheckContext,
) -> Result<RowEncodingGeometry, String> {
    let phase = &plan.quotient_phase;
    let expected_mask_degree_bound_exclusive =
        plan.opening_degree_bound_exclusive
            .checked_sub(1)
            .ok_or_else(|| "exact opening-mask degree bound is empty".to_owned())?;
    let expected_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
        EXACT_QUOTIENT_PHASE_ROW_COUNT,
        PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
        EXACT_ROW_CODE_LOG_INVERSE_RATE,
    )?;
    if context.challenge_extension_degree != 5
        || context.quotient_component_count
            != u32::try_from(LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
                .map_err(|_| "exact quotient component count exceeds u32".to_owned())?
        || phase.quotient_component_count != context.quotient_component_count
        || phase.quotient_component_degree_bound_exclusive
            != context.quotient_component_degree_bound_exclusive
        || phase.opening_batch_mask_degree_bound_exclusive
            != Some(expected_mask_degree_bound_exclusive)
        || phase.rows.len() != EXACT_QUOTIENT_PHASE_ROW_COUNT
        || phase.geometry != expected_geometry
    {
        return Err("exact construction plan has the wrong quotient geometry".to_owned());
    }

    let quotient_row_count = 2 * usize::from(context.challenge_extension_degree);
    for (row_index, row) in phase.rows.iter().enumerate() {
        if row.opening_point_ordinals != [0] {
            return Err("exact construction plan has the wrong quotient opening points".to_owned());
        }
        if row_index < quotient_row_count {
            let expected_chunk_ordinal =
                u32::try_from(row_index / usize::from(context.challenge_extension_degree))
                    .map_err(|_| "exact quotient chunk ordinal exceeds u32".to_owned())?;
            let expected_extension_coordinate =
                u16::try_from(row_index % usize::from(context.challenge_extension_degree))
                    .map_err(|_| "exact quotient extension coordinate exceeds u16".to_owned())?;
            if row.source_class != RelationOpeningSourceClass::Quotient
                || row.source_group_ordinal != 0
                || row.coefficient_chunk_group_start_ordinal != expected_chunk_ordinal
                || row.extension_coordinate_ordinal != expected_extension_coordinate
            {
                return Err("exact construction plan has the wrong quotient row".to_owned());
            }
            for (component_ordinal, chunk) in row.logical_polynomial_chunks.iter().enumerate() {
                let expected_component_ordinal = u32::try_from(component_ordinal)
                    .map_err(|_| "exact quotient component ordinal exceeds u32".to_owned())?;
                if !matches!(
                    chunk,
                    Some(planned_chunk)
                        if planned_chunk.source
                            == RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                                component_ordinal: expected_component_ordinal,
                            }
                            && planned_chunk.coefficient_chunk_ordinal
                                == expected_chunk_ordinal
                ) {
                    return Err(
                        "exact construction plan has the wrong quotient row encoding".to_owned(),
                    );
                }
            }
        } else {
            let expected_extension_coordinate = u16::try_from(row_index - quotient_row_count)
                .map_err(|_| "exact mask extension coordinate exceeds u16".to_owned())?;
            if row.source_class != RelationOpeningSourceClass::BatchMask
                || row.source_group_ordinal != 0
                || row.coefficient_chunk_group_start_ordinal != 0
                || row.extension_coordinate_ordinal != expected_extension_coordinate
            {
                return Err("exact construction plan has the wrong batch-mask row".to_owned());
            }
            for (chunk_ordinal, chunk) in row.logical_polynomial_chunks.iter().enumerate() {
                let expected_chunk_ordinal = u32::try_from(chunk_ordinal)
                    .map_err(|_| "exact mask chunk ordinal exceeds u32".to_owned())?;
                if !matches!(
                    chunk,
                    Some(planned_chunk)
                        if planned_chunk.source
                            == RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
                                mask_ordinal: 0,
                            }
                            && planned_chunk.coefficient_chunk_ordinal
                                == expected_chunk_ordinal
                ) {
                    return Err(
                        "exact construction plan has the wrong batch-mask row encoding".to_owned(),
                    );
                }
            }
        }
    }
    Ok(expected_geometry)
}

fn validate_exact_bound_construction_plan(
    plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
) -> Result<(), String> {
    let mut opening_points_by_column = BTreeMap::<u32, Vec<u32>>::new();
    for claim in variant.ordered_opening_claims() {
        if claim.source_class() == RelationOpeningSourceClass::TreeColumn {
            let column_ordinal = claim
                .column_ordinal()
                .ok_or_else(|| "exact tree opening has no column ordinal".to_owned())?;
            opening_points_by_column
                .entry(column_ordinal)
                .or_default()
                .push(claim.opening_point_ordinal());
        }
    }
    for opening_points in opening_points_by_column.values_mut() {
        opening_points.sort_unstable();
        opening_points.dedup();
    }

    let mut bound_tree_ordinal = 0_usize;
    for (relation_tree_ordinal, descriptor) in variant.ordered_trees().iter().enumerate() {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            expected_root_source_ordinal,
            root_use,
            ordered_column_ordinals,
        } = descriptor
        else {
            continue;
        };
        let tree = plan
            .bound_trees
            .get(bound_tree_ordinal)
            .ok_or_else(|| "exact construction plan omits a bound tree".to_owned())?;
        let (expected_construction_kind, expected_low_degree_mode, expected_query_count) =
            match root_use {
                BoundTreeRootUse::Input => (
                    BoundTreeConstructionKind::CommittedMaterial,
                    RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired,
                    plan.parameters.verified_vss_bound_query_count,
                ),
                BoundTreeRootUse::Output => (
                    BoundTreeConstructionKind::SetupPolynomial,
                    RowCodeWhirBoundLowDegreeMode::Direct,
                    plan.parameters.direct_bound_query_count,
                ),
            };
        if *construction_kind != expected_construction_kind
            || tree.relation_tree_ordinal
                != u32::try_from(relation_tree_ordinal)
                    .map_err(|_| "exact relation tree ordinal exceeds u32".to_owned())?
            || tree.bound_tree_ordinal
                != u32::try_from(bound_tree_ordinal)
                    .map_err(|_| "exact bound tree ordinal exceeds u32".to_owned())?
            || tree.construction_kind != *construction_kind
            || tree.expected_root_source_ordinal != *expected_root_source_ordinal
            || tree.root_use != *root_use
            || tree.source_trace_domain_size != 16_384
            || tree.evaluation_domain_size != plan.evaluation_domain_size
            || tree.leaf_count != EXACT_BOUND_LEAF_COUNT
            || tree.low_degree_mode != expected_low_degree_mode
            || tree.query_count != expected_query_count
            || tree.ordered_columns.len() != EXACT_BOUND_TREE_ROW_WIDTH
            || tree.ordered_columns.len() != ordered_column_ordinals.len()
        {
            return Err("exact construction plan has the wrong bound-tree geometry".to_owned());
        }
        for (column, expected_column_ordinal) in
            tree.ordered_columns.iter().zip(ordered_column_ordinals)
        {
            let descriptor = variant
                .ordered_columns()
                .get(
                    usize::try_from(*expected_column_ordinal)
                        .map_err(|_| "exact bound column ordinal exceeds usize".to_owned())?,
                )
                .ok_or_else(|| "exact bound column is outside the relation".to_owned())?;
            let expected_opening_points = opening_points_by_column
                .get(expected_column_ordinal)
                .ok_or_else(|| "exact bound column has no opening point".to_owned())?;
            if column.column_ordinal != *expected_column_ordinal
                || column.value_type != descriptor.value_type()
                || column.source_degree_bound_exclusive
                    != descriptor.source_degree_bound_exclusive()
                || column.opening_point_ordinals != *expected_opening_points
            {
                return Err("exact construction plan has the wrong bound-column mapping".to_owned());
            }
        }
        bound_tree_ordinal += 1;
    }
    if bound_tree_ordinal != EXACT_BOUND_TREE_COUNT
        || plan.bound_trees.len() != EXACT_BOUND_TREE_COUNT
    {
        return Err("exact construction plan has the wrong bound-tree count".to_owned());
    }

    let expected_blocks = [
        (
            RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired,
            (0_u32..8).collect::<Vec<_>>(),
            18_432_u64,
            18_431_u64,
            vec![0, 0, 0, 0],
            EXACT_INPUT_BOUND_DEGREE_SUFFIX_PREFIXES
                .iter()
                .map(|prefix| prefix.to_vec())
                .collect::<Vec<_>>(),
            plan.parameters.verified_vss_bound_query_count,
        ),
        (
            RowCodeWhirBoundLowDegreeMode::Direct,
            (8_u32..11).collect::<Vec<_>>(),
            16_384_u64,
            16_383_u64,
            vec![0, 0, 0, 1],
            EXACT_OUTPUT_BOUND_DEGREE_SUFFIX_PREFIXES
                .iter()
                .map(|prefix| prefix.to_vec())
                .collect::<Vec<_>>(),
            plan.parameters.direct_bound_query_count,
        ),
    ];
    if plan.bound_reduction_blocks.len() != expected_blocks.len() {
        return Err("exact construction plan has the wrong bound-block count".to_owned());
    }
    for (block, expected) in plan.bound_reduction_blocks.iter().zip(expected_blocks) {
        if block.low_degree_mode != expected.0
            || block.ordered_bound_tree_ordinals != expected.1
            || block.maximum_source_degree_bound_exclusive != expected.2
            || block.quotient_degree_bound_exclusive != expected.3
            || block.polynomial_variable_count != EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT
            || block.selector_prefix != expected.4
            || block.degree_suffix_prefixes != expected.5
            || block.query_count != expected.6
        {
            return Err("exact construction plan has the wrong bound-block schedule".to_owned());
        }
    }
    Ok(())
}

fn validate_exact_same_secret_construction_plan(
    plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    expected_relation_plan_hash: [u8; 64],
    expected_relation_plan_variant_hash: [u8; 64],
) -> Result<ExactProofShape, String> {
    let expected_schema_identifier =
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
    let expected_requested_source_column_ordinals =
        requested_pre_challenge_source_column_ordinals(variant)
            .map_err(|error| format!("derive exact source catalog: {error:?}"))?;
    if plan.application_statement_schema_identifier != expected_schema_identifier
        || plan.schedule_position.is_some()
        || plan.top_count.is_some()
        || plan.relation_plan_hash != expected_relation_plan_hash
        || plan.relation_plan_variant_hash != expected_relation_plan_variant_hash
        || plan.trace_domain_size != variant.trace_domain_size()
        || plan.trace_domain_size != 16_384
        || plan.evaluation_domain_size != variant.evaluation_domain_size()
        || plan.evaluation_domain_size != (1_u64 << EXACT_PCS_VARIABLE_COUNT)
        || plan.opening_degree_bound_exclusive != variant.opening_degree_bound_exclusive()
        || plan.opening_degree_bound_exclusive
            != u64::try_from(
                LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW,
            )
            .map_err(|_| "exact opening degree bound exceeds u64".to_owned())?
        || plan.proof_privacy_mode != ProofPrivacyMode::SecretBearing
        || plan.requested_source_column_ordinals != expected_requested_source_column_ordinals
    {
        return Err("exact construction plan does not match the selected relation".to_owned());
    }

    let parameters = plan.parameters;
    if parameters.logical_polynomial_coefficient_count != LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        || parameters.logical_polynomials_per_physical_row != LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
        || parameters.physical_row_witness_variable_count != PHYSICAL_ROW_WITNESS_VARIABLE_COUNT
        || parameters.row_code_log_inverse_rate != EXACT_ROW_CODE_LOG_INVERSE_RATE
        || parameters.table_variable_count != EXACT_TABLE_VARIABLE_COUNT
        || parameters.polynomial_commitment_variable_count != EXACT_PCS_VARIABLE_COUNT
        || parameters.starting_log_inverse_rate != EXACT_ROW_CODE_LOG_INVERSE_RATE
        || parameters.folding_factor != 3
        || parameters.soundness_assumption != RowCodeWhirSoundnessAssumption::UniqueDecoding
        || parameters.security_level != 262
        || parameters.proof_of_work_bits != 0
        || parameters.outer_query_count == 0
        || parameters.direct_bound_query_count == 0
        || parameters.verified_vss_bound_query_count == 0
        || parameters.verified_vss_bound_query_count > parameters.direct_bound_query_count
        || parameters.direct_bound_query_count > parameters.outer_query_count
        || parameters.maximum_fiat_shamir_candidate_draws_per_output
            != PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
        || parameters.maximum_fiat_shamir_candidate_draws_per_output
            != context.maximum_fiat_shamir_candidate_draws_per_output
        || context.phase_column_query_coordinate_count
            != u32::try_from(parameters.outer_query_count)
                .map_err(|_| "exact query count exceeds u32".to_owned())?
    {
        return Err("exact construction plan has the wrong selected parameters".to_owned());
    }

    let base_layout = ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::BaseOracle)?;
    let auxiliary_layout =
        ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::AuxiliaryOracle)?;
    let base_geometry = validate_exact_trace_phase_plan(
        plan.base_phase.as_ref(),
        &base_layout,
        ProofTreeRole::BaseOracle,
    )?;
    let auxiliary_geometry = validate_exact_trace_phase_plan(
        plan.auxiliary_phase.as_ref(),
        &auxiliary_layout,
        ProofTreeRole::AuxiliaryOracle,
    )?;
    let quotient_geometry = validate_exact_quotient_phase_plan(plan, context)?;
    if auxiliary_geometry.encoded_column_count != base_geometry.encoded_column_count
        || quotient_geometry.encoded_column_count != base_geometry.encoded_column_count
    {
        return Err("exact construction phases do not share one encoded domain".to_owned());
    }

    validate_exact_bound_construction_plan(plan, variant)?;
    let expected_aggregate_column_roles = vec![
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
    ];
    if variant.ordered_opening_points().len() != 3
        || plan.aggregate_column_roles != expected_aggregate_column_roles
    {
        return Err("exact construction plan has the wrong aggregate columns".to_owned());
    }

    Ok(ExactProofShape {
        base_row_count: plan
            .base_phase
            .as_ref()
            .expect("validated exact base phase")
            .rows
            .len(),
        auxiliary_row_count: plan
            .auxiliary_phase
            .as_ref()
            .expect("validated exact auxiliary phase")
            .rows
            .len(),
        quotient_row_count: plan.quotient_phase.rows.len(),
        opening_claim_count: variant.ordered_opening_claims().len(),
        encoded_column_count: base_geometry.encoded_column_count,
        outer_query_count: parameters.outer_query_count,
        verified_vss_bound_query_count: parameters.verified_vss_bound_query_count,
        direct_bound_query_count: parameters.direct_bound_query_count,
        aggregate_table_width: plan.aggregate_table_width(),
    })
}

pub(in crate::bgv::proof_suite::row_code_whir) fn checked_exact_same_secret_proof_shape(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    expected_relation_plan_hash: [u8; 64],
    expected_relation_plan_variant_hash: [u8; 64],
) -> Result<ExactSameSecretProofShape, String> {
    let shape = validate_exact_same_secret_construction_plan(
        construction_plan,
        relation_plan_variant,
        relation_context,
        expected_relation_plan_hash,
        expected_relation_plan_variant_hash,
    )?;
    let construction_plan_identity_hash = construction_plan
        .canonical_identity_hash()
        .map_err(|error| format!("derive exact construction-plan identity: {error:?}"))?;
    Ok(ExactSameSecretProofShape {
        shape,
        construction_plan_identity_hash,
    })
}

pub(super) fn validate_exact_same_secret_verification_construction(
    relation_plan: &CommonProofRelationPlanCapability,
) -> Result<(), String> {
    let variant = relation_plan
        .compiled_plan()
        .select_variant(None, None)
        .map_err(|error| format!("select exact relation for verification: {error:?}"))?;
    validate_exact_same_secret_construction_plan(
        relation_plan.row_code_whir_construction_plan(),
        variant,
        relation_plan
            .validated_relation_plan_artifact()
            .checked_context(),
        relation_plan.relation_plan_hash(),
        relation_plan.relation_plan_variant_hash(),
    )?;
    Ok(())
}

fn checked_exact_verifier_resident_memory_add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "exact verifier resident-memory accounting overflowed".to_owned())
}

fn checked_exact_verifier_resident_memory_multiply(
    left: usize,
    right: usize,
) -> Result<u64, String> {
    u64::try_from(left)
        .ok()
        .and_then(|left| {
            u64::try_from(right)
                .ok()
                .and_then(|right| left.checked_mul(right))
        })
        .ok_or_else(|| "exact verifier resident-memory accounting overflowed".to_owned())
}

fn exact_verifier_resident_vector_payload_byte_length<Value>(
    element_count: usize,
) -> Result<u64, String> {
    checked_exact_verifier_resident_memory_multiply(element_count, core::mem::size_of::<Value>())
}

pub(super) fn derive_exact_same_secret_verification_resident_memory_accounting(
    relation_plan: &CommonProofRelationPlanCapability,
    canonical_application_statement_byte_length: usize,
    canonical_proof_object_header_byte_length: usize,
    canonical_proof_byte_length: usize,
) -> Result<ExactSameSecretVerificationResidentMemoryAccounting, String> {
    validate_exact_declared_proof_byte_length(canonical_proof_byte_length)?;
    let family_body_byte_length = canonical_proof_byte_length
        .checked_sub(canonical_proof_object_header_byte_length)
        .filter(|byte_length| *byte_length != 0)
        .ok_or_else(|| "exact proof body is empty or its framing length overflowed".to_owned())?;
    let variant = relation_plan
        .compiled_plan()
        .select_variant(None, None)
        .map_err(|error| format!("select exact relation for memory accounting: {error:?}"))?;
    let relation_context = relation_plan
        .validated_relation_plan_artifact()
        .checked_context();
    let construction_plan = relation_plan.row_code_whir_construction_plan();
    let shape = validate_exact_same_secret_construction_plan(
        construction_plan,
        variant,
        relation_context,
        relation_plan.relation_plan_hash(),
        relation_plan.relation_plan_variant_hash(),
    )?;
    let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
    let opening_widths = expected_opening_widths(construction_plan);
    let plain_whir_accounting = plain_whir_incremental_decoder_resident_memory_accounting(
        &pcs,
        &opening_widths,
        shape.aggregate_table_width,
        family_body_byte_length,
    )?;

    let fixed_verifier_byte_length = [
        core::mem::size_of::<PreparedExactSameSecretVerification>(),
        core::mem::size_of::<ExactSameSecretIncrementalVerification>(),
        core::mem::size_of::<ExactSameSecretIncrementalDecoder>(),
        core::mem::size_of::<ExactSameSecretIncrementalSemanticVerifier>(),
        core::mem::size_of::<PreparedExactSameSecretRelation>(),
        core::mem::size_of::<ExactSameSecretVerificationContext>(),
        core::mem::size_of::<ExactSameSecretFinalProofVerification>(),
    ]
    .into_iter()
    .try_fold(0_u64, |byte_length, value_byte_length| {
        checked_exact_verifier_resident_memory_add(
            byte_length,
            u64::try_from(value_byte_length)
                .map_err(|_| "exact fixed verifier byte length exceeds u64".to_owned())?,
        )
    })?;
    let canonical_binding_payload_byte_length = [
        u64::try_from(canonical_application_statement_byte_length)
            .map_err(|_| "exact application statement length exceeds u64".to_owned())?,
        checked_exact_verifier_resident_memory_multiply(
            canonical_proof_object_header_byte_length,
            2,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_exact_verifier_resident_memory_add)?;

    // The exact verifier owns one checked relation clone and its internal
    // verifier-sequence evaluator owns another. Canonical construction bytes
    // conservatively cover the nested construction vectors cloned beside
    // them; fixed Vec headers are already included in the fixed structures.
    let relation_variant_payload_byte_length = variant
        .resident_owned_payload_byte_length()
        .map_err(|error| format!("account exact relation variant: {error:?}"))?;
    let relation_context_payload_byte_length = relation_context
        .resident_owned_payload_byte_length()
        .map_err(|error| format!("account exact relation context: {error:?}"))?;
    let construction_plan_payload_byte_length = u64::try_from(
        construction_plan
            .canonical_identity_bytes()
            .map_err(|error| format!("encode exact construction for accounting: {error:?}"))?
            .len(),
    )
    .map_err(|_| "exact construction byte length exceeds u64".to_owned())?;
    let checked_relation_payload_byte_length = [
        checked_exact_verifier_resident_memory_add(
            relation_variant_payload_byte_length,
            relation_variant_payload_byte_length,
        )?,
        checked_exact_verifier_resident_memory_add(
            relation_context_payload_byte_length,
            relation_context_payload_byte_length,
        )?,
        construction_plan_payload_byte_length,
        exact_verifier_resident_vector_payload_byte_length::<RelationProofTreeInput>(
            variant.ordered_trees().len(),
        )?,
        exact_verifier_resident_vector_payload_byte_length::<ProofTreeCatalogEntry>(
            EXACT_BOUND_TREE_COUNT,
        )?,
        exact_verifier_resident_vector_payload_byte_length::<VerifiedStatementOwnedTree>(
            EXACT_BOUND_TREE_COUNT,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_exact_verifier_resident_memory_add)?;

    let opening_point_count = variant.ordered_opening_points().len();
    let phase_row_counts = shape.phase_row_counts();
    let phase_row_count =
        phase_row_counts
            .into_iter()
            .try_fold(0_usize, |row_count, phase_row_count| {
                row_count
                    .checked_add(phase_row_count)
                    .ok_or_else(|| "exact phase row count overflowed".to_owned())
            })?;
    let maximum_phase_row_count = phase_row_counts.into_iter().max().unwrap_or(0);
    let base_and_auxiliary_row_count = shape
        .base_row_count
        .checked_add(shape.auxiliary_row_count)
        .ok_or_else(|| "exact layout row count overflowed".to_owned())?;
    let layout_payload_byte_length = [
        exact_verifier_resident_vector_payload_byte_length::<ExactBasePhaseRow>(
            base_and_auxiliary_row_count,
        )?,
        checked_exact_verifier_resident_memory_multiply(
            base_and_auxiliary_row_count
                .checked_mul(opening_point_count)
                .ok_or_else(|| "exact layout opening catalog count overflowed".to_owned())?,
            core::mem::size_of::<u32>(),
        )?,
        exact_verifier_resident_vector_payload_byte_length::<usize>(opening_widths.len())?,
        exact_verifier_resident_vector_payload_byte_length::<bool>(EXACT_BOUND_TREE_COUNT)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_exact_verifier_resident_memory_add)?;

    let bound_reduction_evaluation_count = shape.bound_reduction_evaluation_count()?;
    let whir_point_count = opening_point_count
        .checked_add(shape.outer_query_count)
        .and_then(|count| count.checked_add(bound_reduction_evaluation_count))
        .and_then(|count| count.checked_add(EXACT_BOUND_DEGREE_TEST_COUNT))
        .ok_or_else(|| "exact WHIR point count overflowed".to_owned())?;
    let bound_query_count = shape
        .verified_vss_bound_query_count
        .checked_add(shape.direct_bound_query_count)
        .ok_or_else(|| "exact bound query count overflowed".to_owned())?;
    let semantic_accumulator_payload_byte_length = [
        exact_verifier_resident_vector_payload_byte_length::<ProofChallengeExtensionElement>(
            opening_point_count,
        )?,
        checked_exact_verifier_resident_memory_multiply(
            opening_point_count
                .checked_mul(phase_row_count)
                .ok_or_else(|| "exact point-row weight count overflowed".to_owned())?,
            core::mem::size_of::<ChallengeField>(),
        )?,
        exact_verifier_resident_vector_payload_byte_length::<ExactBoundOpeningClaim>(
            EXACT_BOUND_COLUMN_COUNT,
        )?,
        exact_verifier_resident_vector_payload_byte_length::<usize>(shape.outer_query_count)?,
        exact_verifier_resident_vector_payload_byte_length::<usize>(bound_query_count)?,
        exact_verifier_resident_vector_payload_byte_length::<Point<ChallengeField>>(
            whir_point_count,
        )?,
        checked_exact_verifier_resident_memory_multiply(
            whir_point_count
                .checked_mul(
                    construction_plan
                        .selected_parameters()
                        .polynomial_commitment_variable_count,
                )
                .ok_or_else(|| "exact WHIR coordinate count overflowed".to_owned())?,
            core::mem::size_of::<ChallengeField>(),
        )?,
        checked_exact_verifier_resident_memory_multiply(
            shape
                .outer_query_count
                .checked_mul(4)
                .ok_or_else(|| "exact query accumulator count overflowed".to_owned())?,
            core::mem::size_of::<[ChallengeField; 3]>(),
        )?,
        checked_exact_verifier_resident_memory_multiply(
            shape
                .outer_query_count
                .checked_mul(3)
                .ok_or_else(|| "exact phase digest count overflowed".to_owned())?,
            core::mem::size_of::<(usize, ColumnDigest)>(),
        )?,
        checked_exact_verifier_resident_memory_multiply(
            bound_reduction_evaluation_count
                .checked_mul(2)
                .ok_or_else(|| "exact bound accumulator count overflowed".to_owned())?,
            core::mem::size_of::<ChallengeField>(),
        )?,
        exact_verifier_resident_vector_payload_byte_length::<(u64, [u8; 64])>(
            shape.direct_bound_query_count,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_exact_verifier_resident_memory_add)?;

    let maximum_phase_frontier_count = shape.maximum_frontier_count()?;
    let maximum_bound_frontier_count = shape
        .direct_bound_query_count
        .checked_mul(EXACT_BOUND_LEAF_COUNT.ilog2() as usize)
        .ok_or_else(|| "exact bound frontier count overflowed".to_owned())?;
    let out_of_domain_decode_payload_byte_length =
        exact_verifier_resident_vector_payload_byte_length::<ProofChallengeExtensionElement>(
            shape.opening_claim_count,
        )?;
    let phase_decode_payload_byte_length = [
        exact_verifier_resident_vector_payload_byte_length::<Goldilocks>(maximum_phase_row_count)?,
        exact_verifier_resident_vector_payload_byte_length::<ColumnDigest>(
            maximum_phase_frontier_count,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_exact_verifier_resident_memory_add)?;
    let bound_decode_payload_byte_length = exact_verifier_resident_vector_payload_byte_length::<
        [u8; 64],
    >(maximum_bound_frontier_count)?;
    let maximum_decode_transient_byte_length = out_of_domain_decode_payload_byte_length
        .max(phase_decode_payload_byte_length)
        .max(bound_decode_payload_byte_length)
        .max(plain_whir_accounting.maximum_resident_byte_length());

    let maximum_resident_byte_length = [
        fixed_verifier_byte_length,
        canonical_binding_payload_byte_length,
        checked_relation_payload_byte_length,
        layout_payload_byte_length,
        semantic_accumulator_payload_byte_length,
        maximum_decode_transient_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_exact_verifier_resident_memory_add)?;
    Ok(ExactSameSecretVerificationResidentMemoryAccounting::new(
        maximum_resident_byte_length,
    ))
}

pub(super) fn challenge_from_production(value: ProofChallengeExtensionElement) -> ChallengeField {
    ChallengeField::new(value.canonical_coordinates().map(Goldilocks::new))
}

fn column_digest_bytes(digest: ColumnDigest) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    for (word_index, word) in digest.into_iter().enumerate() {
        let start = word_index * core::mem::size_of::<u64>();
        bytes[start..start + core::mem::size_of::<u64>()].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn expected_opening_widths(construction_plan: &RowCodeWhirConstructionPlan) -> Vec<usize> {
    construction_plan
        .opening_batches()
        .iter()
        .map(|batch| batch.requested_aggregate_column_ordinals.len())
        .collect()
}

fn maximum_parent_hash_count(tree_height: usize, query_count: usize) -> Result<usize, String> {
    (0..tree_height).try_fold(0_usize, |count, depth| {
        let node_count = 1_usize
            .checked_shl(
                u32::try_from(depth).map_err(|_| "Merkle-tree depth exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "Merkle-tree width overflowed".to_owned())?;
        count
            .checked_add(query_count.min(node_count))
            .ok_or_else(|| "Merkle parent hash-query count overflowed".to_owned())
    })
}

fn maximum_verifier_merkle_hash_query_count(
    shape: ExactProofShape,
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<u64, String> {
    let outer_parent_count = maximum_parent_hash_count(
        shape.encoded_column_count.ilog2() as usize,
        shape.outer_query_count,
    )?;
    let outer_hash_query_count = shape
        .outer_query_count
        .checked_add(outer_parent_count)
        .and_then(|count| count.checked_mul(shape.phase_row_counts().len()))
        .ok_or_else(|| "outer Merkle hash-query count overflowed".to_owned())?;
    let bound_hash_query_count =
        construction_plan
            .bound_trees
            .iter()
            .try_fold(0_usize, |count, tree| {
                let parent_count =
                    maximum_parent_hash_count(tree.leaf_count.ilog2() as usize, tree.query_count)?;
                count
                    .checked_add(tree.query_count)
                    .and_then(|count| count.checked_add(parent_count))
                    .ok_or_else(|| "bound Merkle hash-query count overflowed".to_owned())
            })?;
    let whir_plan = construction_plan.whir_plan();
    let whir_hash_query_count = whir_plan
        .rounds
        .iter()
        .map(|round| (round.encoded_oracle, round.query_epoch.query_count))
        .chain(core::iter::once((
            whir_plan.final_round.encoded_oracle,
            whir_plan.final_round.query_epoch.query_count,
        )))
        .try_fold(0_usize, |count, (oracle, query_count)| {
            let hashes_per_query = (oracle.leaf_count.ilog2() as usize)
                .checked_add(1)
                .ok_or_else(|| "WHIR Merkle path length overflowed".to_owned())?;
            count
                .checked_add(
                    query_count
                        .checked_mul(hashes_per_query)
                        .ok_or_else(|| "WHIR Merkle hash-query count overflowed".to_owned())?,
                )
                .ok_or_else(|| "WHIR Merkle hash-query count overflowed".to_owned())
        })?;
    u64::try_from(
        outer_hash_query_count
            .checked_add(bound_hash_query_count)
            .and_then(|count| count.checked_add(whir_hash_query_count))
            .ok_or_else(|| "verifier Merkle hash-query count overflowed".to_owned())?,
    )
    .map_err(|_| "verifier Merkle hash-query count exceeds u64".to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactSameSecretVerifierAccounting {
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    maximum_verifier_hash_query_count: u64,
    maximum_accepting_database_equation_count: u64,
}

fn exact_same_secret_verifier_accounting(
    construction_plan: &RowCodeWhirConstructionPlan,
    shape: ExactProofShape,
) -> Result<ExactSameSecretVerifierAccounting, String> {
    let oracle_equation_catalog = construction_plan
        .oracle_equation_catalog()
        .map_err(|error| format!("derive exact oracle-equation catalog: {error:?}"))?;
    let maximum_transcript_hash_query_count = oracle_equation_catalog
        .maximum_transcript_hash_query_count()
        .map_err(|error| format!("derive exact transcript hash-query ceiling: {error:?}"))?;
    let logical_verifier_message_count =
        oracle_equation_catalog
            .logical_verifier_message_count()
            .map_err(|error| format!("derive exact logical verifier-message count: {error:?}"))?;
    let maximum_verifier_merkle_hash_query_count =
        maximum_verifier_merkle_hash_query_count(shape, construction_plan)?;
    let maximum_verifier_hash_query_count = maximum_transcript_hash_query_count
        .checked_add(maximum_verifier_merkle_hash_query_count)
        .and_then(|count| count.checked_add(EXACT_VERIFIER_NON_MERKLE_HASH_QUERY_COUNT))
        .ok_or_else(|| "exact verifier hash-query accounting overflowed".to_owned())?;
    let maximum_accepting_database_equation_count = maximum_transcript_hash_query_count
        .checked_add(maximum_verifier_merkle_hash_query_count)
        .and_then(|count| count.checked_add(EXACT_VERIFIER_NON_MERKLE_DISTINCT_EQUATION_COUNT))
        .ok_or_else(|| "exact accepting-database accounting overflowed".to_owned())?;
    Ok(ExactSameSecretVerifierAccounting {
        maximum_transcript_hash_query_count,
        logical_verifier_message_count,
        maximum_verifier_hash_query_count,
        maximum_accepting_database_equation_count,
    })
}

#[cfg(test)]
fn selected_expected_opening_widths() -> Vec<usize> {
    let mut widths = vec![1, 1, 1];
    widths.extend(std::iter::repeat_n(3, EXACT_COLUMN_QUERY_COUNT));
    widths.extend(std::iter::repeat_n(
        1,
        (EXACT_INPUT_BOUND_QUERY_COUNT + EXACT_OUTPUT_BOUND_QUERY_COUNT) * 2,
    ));
    widths.extend(std::iter::repeat_n(1, EXACT_BOUND_DEGREE_TEST_COUNT));
    widths
}

struct VerifiedExactRelation {
    variant: RelationPlanVariant,
    context: crate::bgv::proof_suite::RelationPlanCheckContext,
    proof_shape: ExactProofShape,
    row_code_whir_construction_plan: RowCodeWhirConstructionPlan,
    fiat_shamir_binding: ExactSameSecretFiatShamirBinding,
    relation_trees: Vec<RelationProofTreeInput>,
    verifier_sequence_evaluator: VerifiedKeyRelationColumnEvaluator,
}

#[derive(Clone, Copy)]
struct CheckedExactVerificationContextBindings {
    statement_schema_identifier: u16,
    suite_identifier: [u8; 64],
    action_context_hash: [u8; 64],
}

fn checked_verification_context_bindings(
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    verification_context: &ExactSameSecretVerificationContext,
) -> Result<CheckedExactVerificationContextBindings, String> {
    let application_slot = verification_context.application_slot;
    let statement_schema_identifier = application_slot.application_statement_schema_identifier();
    let suite_identifier = application_slot.suite_identifier().into_bytes();
    let action_context_hash = application_slot.action_context_hash().into_bytes();
    if statement_schema_identifier
        != SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier()
    {
        return Err("exact verification context has the wrong statement schema".to_owned());
    }
    if suite_identifier == [0_u8; 64] {
        return Err("exact verification context has an empty suite identifier".to_owned());
    }
    if application_slot.ceremony_context_hash().into_bytes() != prerequisite.ceremony_context_hash()
        || action_context_hash != prerequisite.action_context_hash()
    {
        return Err("exact verification context has the wrong action binding".to_owned());
    }
    if verification_context.protocol_version != prerequisite.protocol_version() {
        return Err("exact verification context has the wrong protocol version".to_owned());
    }
    if suite_identifier != prerequisite.suite_identifier()
        || application_slot.roster_position() != Some(prerequisite.roster_position())
        || application_slot.schedule_position().is_some()
        || application_slot.producer_sequence().is_some()
    {
        return Err("exact verification context has the wrong application slot".to_owned());
    }
    Ok(CheckedExactVerificationContextBindings {
        statement_schema_identifier,
        suite_identifier,
        action_context_hash,
    })
}

pub(super) fn validate_verification_context_bindings(
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    verification_context: &ExactSameSecretVerificationContext,
) -> Result<(), String> {
    checked_verification_context_bindings(prerequisite, verification_context).map(drop)
}

fn validate_verification_context(
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    verification_context: &ExactSameSecretVerificationContext,
) -> Result<VerifiedExactRelation, String> {
    let CheckedExactVerificationContextBindings {
        statement_schema_identifier,
        suite_identifier,
        action_context_hash,
    } = checked_verification_context_bindings(prerequisite, verification_context)?;
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or_else(|| "selected same-secret relation context is unavailable".to_owned())?;
    let compiled_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .map_err(|error| format!("select same-secret relation input: {error:?}"))?,
        &relation_context,
    )
    .map_err(|error| format!("compile exact same-secret relation: {error:?}"))?;
    let variant = compiled_plan
        .select_variant(None, None)
        .map_err(|error| format!("select exact same-secret relation variant: {error:?}"))?
        .clone();
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_plan,
        &relation_context,
        None,
        None,
    )
    .map_err(|error| format!("validate exact same-secret relation: {error:?}"))?;
    let proof_shape = validate_exact_same_secret_construction_plan(
        relation_plan.row_code_whir_construction_plan(),
        &variant,
        &relation_context,
        relation_plan.relation_plan_hash(),
        relation_plan.relation_plan_variant_hash(),
    )?;
    let fiat_shamir_binding = ExactSameSecretFiatShamirBinding::derive(
        verification_context.protocol_version,
        suite_identifier,
        prerequisite.ceremony_context_hash(),
        action_context_hash,
        &verification_context.canonical_application_statement_bytes,
        &relation_plan,
    )?;
    let statement = decode_selected_same_secret_statement(
        &verification_context.canonical_application_statement_bytes,
        SelectedApplicationStatementContext::new(
            verification_context.protocol_version,
            suite_identifier,
            None,
            None,
        ),
    )
    .map_err(|error| format!("decode exact same-secret statement: {error:?}"))?;
    if statement.ordered_degree_zero_commitment_roots().len() != EXACT_INPUT_BOUND_TREE_COUNT {
        return Err("exact statement has the wrong input-root count".to_owned());
    }
    if statement.ordered_degree_zero_commitment_roots() != prerequisite.ordered_input_roots()
        || statement.participant_identity() != prerequisite.participant_identity()
        || statement.roster_position() != prerequisite.roster_position()
    {
        return Err("exact statement does not match the verified VSS prerequisite".to_owned());
    }
    let mut statement_roots = statement.ordered_degree_zero_commitment_roots().to_vec();
    statement_roots.extend(statement.anchor_commitment_roots());
    let canonical_application_statement = decode_application_statement(
        &verification_context.canonical_application_statement_bytes,
        statement_schema_identifier,
        verification_context.protocol_version,
        suite_identifier,
        None,
        None,
        &relation_context,
    )
    .map_err(|error| format!("decode canonical exact statement: {error:?}"))?;
    let relation_trees = derive_relation_tree_inputs(
        &variant,
        &canonical_application_statement,
        &verification_context.statement_owned_trees,
    )
    .map_err(|error| format!("derive exact verifier-owned trees: {error:?}"))?;
    let mut actual_bound_roots = Vec::new();
    let mut actual_bound_root_uses = Vec::new();
    let mut bound_column_root_uses = BTreeMap::new();
    for (descriptor, relation_tree) in variant.ordered_trees().iter().zip(&relation_trees) {
        match (descriptor, relation_tree) {
            (
                RelationTreeDescriptor::ProofCreated { .. },
                RelationProofTreeInput::ProofCreated {
                    leaf_visibility: crate::bgv::proof_suite::ProofLeafVisibility::SecretBearing,
                    ..
                },
            ) => {}
            (
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    root_use,
                    ordered_column_ordinals,
                    ..
                },
                RelationProofTreeInput::BoundPublic(statement_tree),
            ) => {
                let (input_kind, row_width, expected_root) = match statement_tree {
                    StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. } => (
                        BoundTreeConstructionKind::CommittedMaterial,
                        EXACT_BOUND_TREE_ROW_WIDTH,
                        *expected_root,
                    ),
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        row_width,
                        expected_root,
                        ..
                    } => (
                        BoundTreeConstructionKind::SetupPolynomial,
                        usize::try_from(*row_width)
                            .map_err(|_| "bound tree row width exceeds usize".to_owned())?,
                        *expected_root,
                    ),
                };
                if *construction_kind != input_kind
                    || row_width != EXACT_BOUND_TREE_ROW_WIDTH
                    || ordered_column_ordinals.len() != EXACT_BOUND_TREE_ROW_WIDTH
                    || !matches!(
                        (input_kind, *root_use),
                        (
                            BoundTreeConstructionKind::CommittedMaterial,
                            BoundTreeRootUse::Input
                        ) | (
                            BoundTreeConstructionKind::SetupPolynomial,
                            BoundTreeRootUse::Output
                        )
                    )
                {
                    return Err("verifier-owned bound tree has the wrong construction".to_owned());
                }
                actual_bound_roots.push(expected_root);
                actual_bound_root_uses.push(*root_use);
                for column_ordinal in ordered_column_ordinals {
                    if bound_column_root_uses
                        .insert(*column_ordinal, *root_use)
                        .is_some()
                    {
                        return Err("bound relation column occurs in more than one tree".to_owned());
                    }
                }
            }
            _ => return Err("exact relation tree has the wrong authenticated type".to_owned()),
        }
    }
    if actual_bound_roots != statement_roots
        || actual_bound_roots.len() != EXACT_BOUND_TREE_COUNT
        || actual_bound_root_uses
            != [
                vec![BoundTreeRootUse::Input; EXACT_INPUT_BOUND_TREE_COUNT],
                vec![BoundTreeRootUse::Output; EXACT_OUTPUT_BOUND_TREE_COUNT],
            ]
            .concat()
        || bound_column_root_uses.len() != EXACT_BOUND_COLUMN_COUNT
    {
        return Err("verifier-owned bound roots do not match the application statement".to_owned());
    }
    for (column_ordinal, root_use) in bound_column_root_uses {
        let descriptor = variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| "bound column ordinal exceeds usize".to_owned())?,
            )
            .ok_or_else(|| "bound column ordinal is outside the relation".to_owned())?;
        let (_, block_schedule) = bound_reduction_block_schedule_for_root_use(root_use)?;
        if !matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. })
            || descriptor.source_degree_bound_exclusive()
                != block_schedule.source_degree_bound_exclusive as u64
        {
            return Err("bound column violates its relation descriptor".to_owned());
        }
    }

    let verifier_sequence_evaluator =
        VerifiedKeyRelationColumnEvaluator::from_recomputed_public_setup_seed(
            prerequisite.public_setup_seed(),
            relation_plan.validated_relation_plan_artifact(),
            &variant,
        )
        .map_err(|error| format!("construct verifier-sequence evaluator: {error:?}"))?;
    Ok(VerifiedExactRelation {
        variant,
        context: relation_context,
        proof_shape,
        row_code_whir_construction_plan: relation_plan.row_code_whir_construction_plan().clone(),
        fiat_shamir_binding,
        relation_trees,
        verifier_sequence_evaluator,
    })
}

fn exact_bound_tree_catalog_entries(
    verified_relation: &VerifiedExactRelation,
) -> Result<Vec<ProofTreeCatalogEntry>, String> {
    exact_same_secret_bound_tree_catalog_entries(&verified_relation.relation_trees)
}

pub(in crate::bgv::proof_suite::row_code_whir) fn exact_same_secret_bound_tree_catalog_entries(
    relation_trees: &[RelationProofTreeInput],
) -> Result<Vec<ProofTreeCatalogEntry>, String> {
    let entries = build_relation_bound_public_tree_catalog_entries(relation_trees)
        .map_err(|error| format!("build exact bound tree catalog: {error:?}"))?;
    if entries.len() != EXACT_BOUND_TREE_COUNT
        || entries.iter().any(|entry| {
            entry.materialized_row_width().ok() != Some(EXACT_BOUND_TREE_ROW_WIDTH)
                || entry.bound_root().is_none()
        })
    {
        return Err("exact bound tree catalog has the wrong fixed shape".to_owned());
    }
    Ok(entries)
}

struct ExactTranscriptPrefix {
    transcript: Option<CommonProofTranscript>,
    application_challenges: Vec<crate::bgv::proof_suite::RelationApplicationChallengeAssignment>,
    composition_challenges: Vec<ProofChallengeExtensionElement>,
    out_of_domain_points: Vec<ProofChallengeExtensionElement>,
    opening_points: Vec<ProofChallengeExtensionElement>,
}

fn absorb_role_roots(
    transcript: &mut CommonProofTranscript,
    tree_ordinals: &[u16],
    tree_role: ProofTreeRole,
    root: ColumnDigest,
    variant: &RelationPlanVariant,
) -> Result<(), String> {
    let role_tree_count = variant
        .ordered_trees()
        .iter()
        .filter(|tree| {
            matches!(
                tree,
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ..
                } if *proof_tree_role == tree_role as u16
            )
        })
        .count();
    let root_bytes = column_digest_bytes(root);
    for tree_ordinal in tree_ordinals {
        if usize::from(*tree_ordinal) >= role_tree_count {
            return Err(format!(
                "{tree_role:?} tree {tree_ordinal} is outside the production relation"
            ));
        }
        match tree_role {
            ProofTreeRole::BaseOracle => transcript
                .absorb_base_root(*tree_ordinal, root_bytes)
                .map_err(|error| format!("absorb exact base root: {error:?}"))?,
            ProofTreeRole::AuxiliaryOracle => transcript
                .absorb_auxiliary_root(*tree_ordinal, root_bytes)
                .map_err(|error| format!("absorb exact auxiliary root: {error:?}"))?,
            _ => return Err("exact proof requested an unsupported phase role".to_owned()),
        }
    }
    Ok(())
}

fn exact_transcript_prefix(
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    verification_context: &ExactSameSecretVerificationContext,
    verified_relation: &VerifiedExactRelation,
    base_root: ColumnDigest,
    auxiliary_root: ColumnDigest,
    quotient_root: ColumnDigest,
) -> Result<ExactTranscriptPrefix, String> {
    let schedule = verified_relation
        .variant
        .common_proof_relation_prefix_schedule(&verified_relation.context)
        .map_err(|error| format!("derive exact transcript schedule: {error:?}"))?
        .into_row_code_whir_successor()
        .map_err(|error| format!("derive exact successor transcript schedule: {error:?}"))?;
    let header = exact_transcript_header(
        &verified_relation.fiat_shamir_binding,
        prerequisite.binding_digest(),
    );
    let mut transcript = CommonProofTranscript::new_relation_prefix_for_construction_plan(
        verification_context.protocol_version,
        verification_context
            .application_slot
            .suite_identifier()
            .into_bytes(),
        &verified_relation.row_code_whir_construction_plan,
        verification_context
            .application_slot
            .application_statement_schema_identifier(),
        &header,
        schedule.clone(),
    )
    .map_err(|error| format!("construct exact production transcript: {error:?}"))?;
    #[cfg(test)]
    {
        let out_of_domain_point_cardinality_bounds = (0..verified_relation
            .context
            .out_of_domain_point_count)
            .map(|point_ordinal| {
                verified_relation
                    .variant
                    .out_of_domain_point_sampler_cardinality_bound(
                        &verified_relation.context,
                        point_ordinal,
                    )
                    .map_err(|error| {
                        format!("derive live out-of-domain sampler cardinality bound: {error:?}")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        transcript
            .enable_public_sampler_trace(&out_of_domain_point_cardinality_bounds)
            .map_err(|error| format!("enable exact public sampler trace: {error:?}"))?;
    }
    absorb_role_roots(
        &mut transcript,
        schedule.ordered_base_tree_ordinals(),
        ProofTreeRole::BaseOracle,
        base_root,
        &verified_relation.variant,
    )?;
    let application_challenges = sample_relation_application_challenges(&mut transcript, &schedule)
        .map_err(|error| format!("sample exact application challenges: {error:?}"))?;
    absorb_role_roots(
        &mut transcript,
        schedule.ordered_auxiliary_tree_ordinals(),
        ProofTreeRole::AuxiliaryOracle,
        auxiliary_root,
        &verified_relation.variant,
    )?;
    let mut composition_challenges =
        Vec::with_capacity(verified_relation.variant.constraint_count());
    for constraint_ordinal in 0..verified_relation.variant.constraint_count() {
        composition_challenges.push(
            transcript
                .sample_composition_challenge(
                    u32::try_from(constraint_ordinal)
                        .map_err(|_| "constraint ordinal exceeds u32".to_owned())?,
                )
                .map_err(|error| format!("sample composition challenge: {error:?}"))?,
        );
    }
    transcript
        .absorb_row_code_whir_quotient_phase_root(column_digest_bytes(quotient_root))
        .map_err(|error| format!("absorb exact quotient phase root: {error:?}"))?;
    let mut out_of_domain_points = Vec::with_capacity(usize::from(
        verified_relation.context.out_of_domain_point_count,
    ));
    for point_ordinal in 0..verified_relation.context.out_of_domain_point_count {
        let mut relation_error = None;
        let out_of_domain_point = transcript
            .sample_out_of_domain_point(point_ordinal, |candidate| {
                match verified_relation
                    .variant
                    .out_of_domain_point_candidate_is_forbidden(
                        &verified_relation.context,
                        point_ordinal,
                        candidate,
                        &out_of_domain_points,
                    ) {
                    Ok(forbidden) => forbidden,
                    Err(error) => {
                        relation_error = Some(error);
                        true
                    }
                }
            })
            .map_err(|error| format!("sample exact out-of-domain point: {error:?}"))?;
        if let Some(error) = relation_error {
            return Err(format!("validate exact out-of-domain point: {error:?}"));
        }
        out_of_domain_points.push(out_of_domain_point);
    }
    let opening_points = verified_relation
        .variant
        .derive_opening_points(&verified_relation.context, &out_of_domain_points)
        .map_err(|error| format!("derive exact opening points: {error:?}"))?;
    Ok(ExactTranscriptPrefix {
        transcript: Some(transcript),
        application_challenges,
        composition_challenges,
        out_of_domain_points,
        opening_points,
    })
}

fn finish_exact_transcript(
    prefix: &mut ExactTranscriptPrefix,
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement;
         EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
) -> Result<RowCodeWhirTranscript, String> {
    let transcript = prefix
        .transcript
        .as_mut()
        .ok_or_else(|| "exact common transcript was already consumed".to_owned())?;
    transcript
        .absorb_out_of_domain_evaluations(out_of_domain_evaluations)
        .map_err(|error| format!("absorb exact out-of-domain evaluations: {error:?}"))?;
    prefix
        .transcript
        .take()
        .ok_or_else(|| "exact common transcript was already consumed".to_owned())?
        .into_secret_bearing_row_code_whir_transcript(opening_batch_mask_chunk_evaluations)
        .map_err(|error| format!("handoff exact row-code WHIR transcript: {error:?}"))
}

fn verify_production_out_of_domain_composition(
    verified_relation: &mut VerifiedExactRelation,
    transcript_prefix: &ExactTranscriptPrefix,
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
) -> Result<(), String> {
    verified_relation
        .variant
        .verify_out_of_domain_composition(
            OutOfDomainCompositionVerificationInput::new(
                &verified_relation.context,
                &transcript_prefix.application_challenges,
                &transcript_prefix.composition_challenges,
                &transcript_prefix.out_of_domain_points,
                &transcript_prefix.opening_points,
                out_of_domain_evaluations,
            ),
            |column_ordinal, point| {
                verified_relation
                    .verifier_sequence_evaluator
                    .evaluate_at_extension_point(column_ordinal, point)
            },
        )
        .map_err(|error| format!("verify exact production out-of-domain composition: {error:?}"))
}

#[derive(Clone, Copy)]
pub(super) struct ExactBoundOpeningClaim {
    pub(super) column_ordinal: u32,
    pub(super) opening_point: ChallengeField,
    pub(super) claimed_value: ChallengeField,
    pub(super) batching_weight: ChallengeField,
}

pub(super) fn derive_bound_opening_claims(
    variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<ExactBoundOpeningClaim>, String> {
    if variant.ordered_opening_claims().len() != out_of_domain_evaluations.len() {
        return Err("bound opening reduction has the wrong claim count".to_owned());
    }
    let mut claims = Vec::new();
    for (claim, claimed_value) in variant
        .ordered_opening_claims()
        .iter()
        .zip(out_of_domain_evaluations)
    {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_ordinal = claim
            .column_ordinal()
            .ok_or_else(|| "tree opening claim has no column ordinal".to_owned())?;
        let descriptor = variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| "bound column ordinal exceeds usize".to_owned())?,
            )
            .ok_or_else(|| "bound opening claim references an absent column".to_owned())?;
        if !matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. }) {
            continue;
        }
        let opening_point = opening_points
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| "bound opening-point ordinal exceeds usize".to_owned())?,
            )
            .copied()
            .ok_or_else(|| "bound opening claim references an absent point".to_owned())?;
        claims.push(ExactBoundOpeningClaim {
            column_ordinal,
            opening_point: challenge_from_production(opening_point),
            claimed_value: challenge_from_production(*claimed_value),
            batching_weight: challenger.sample_exact_challenge(
                RowCodeWhirChallenge::BoundOpeningWeight { column_ordinal },
            )?,
        });
    }
    if claims.len() != EXACT_BOUND_COLUMN_COUNT {
        return Err(format!(
            "exact relation has {} bound opening claims, expected {EXACT_BOUND_COLUMN_COUNT}",
            claims.len()
        ));
    }
    Ok(claims)
}

fn derive_bound_query_indices(
    challenger: &mut ExtensionFieldChallenger,
    shape: ExactProofShape,
) -> Result<ExactBoundQueryIndices, String> {
    let accepted_output_root_indices = challenger.sample_exact_distinct_indices(
        RowCodeWhirChallenge::BoundQueryVector,
        EXACT_BOUND_LEAF_COUNT,
        shape.direct_bound_query_count,
    )?;
    let accepted_input_root_indices = accepted_output_root_indices
        .get(..shape.verified_vss_bound_query_count)
        .ok_or_else(|| "bound query sampler returned too few indices".to_owned())?
        .to_vec();
    let mut input_root_traversal_indices = accepted_input_root_indices.clone();
    input_root_traversal_indices.sort_unstable();
    let mut output_root_traversal_indices = accepted_output_root_indices.clone();
    output_root_traversal_indices.sort_unstable();
    let query_indices = ExactBoundQueryIndices {
        accepted_input_root_indices,
        accepted_output_root_indices,
        input_root_traversal_indices,
        output_root_traversal_indices,
    };
    if !query_indices.has_exact_shape(shape) {
        return Err("bound query sampler returned the wrong accepted-order geometry".to_owned());
    }
    Ok(query_indices)
}

fn bound_reduction_block_schedule(
    block_ordinal: usize,
) -> Result<ExactBoundReductionBlockSchedule, String> {
    EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES
        .get(block_ordinal)
        .copied()
        .ok_or_else(|| "bound reduction block ordinal is outside the construction".to_owned())
}

fn bound_reduction_block_schedule_for_root_use(
    root_use: BoundTreeRootUse,
) -> Result<(usize, ExactBoundReductionBlockSchedule), String> {
    EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES
        .iter()
        .copied()
        .enumerate()
        .find(|(_, schedule)| schedule.root_use == root_use)
        .ok_or_else(|| "bound root use has no reduction block".to_owned())
}

#[cfg(test)]
fn bound_degree_random_coordinate_count() -> usize {
    EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES
        .iter()
        .copied()
        .map(ExactBoundReductionBlockSchedule::random_degree_coordinate_count)
        .sum()
}

fn bound_reduction_block_coordinates(block_ordinal: usize) -> Result<Vec<ChallengeField>, String> {
    let block_variable_count = EXACT_TABLE_VARIABLE_COUNT
        .checked_sub(EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT)
        .ok_or_else(|| "bound reduction block geometry underflowed".to_owned())?;
    if EXACT_BOUND_REDUCTION_BLOCK_COUNT
        != 1_usize << EXACT_BOUND_REDUCTION_BLOCK_SELECTOR_VARIABLE_COUNT
        || EXACT_BOUND_REDUCTION_BLOCK_SELECTOR_VARIABLE_COUNT > block_variable_count
    {
        return Err("bound reduction block selector has the wrong fixed width".to_owned());
    }
    bound_reduction_block_schedule(block_ordinal)?;
    Ok((0..block_variable_count)
        .map(|bit_ordinal| {
            if block_ordinal & (1 << (block_variable_count - 1 - bit_ordinal)) == 0 {
                ChallengeField::ZERO
            } else {
                ChallengeField::ONE
            }
        })
        .collect())
}

fn bound_degree_test_points(
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<Point<ChallengeField>>, String> {
    let mut points = Vec::with_capacity(EXACT_BOUND_DEGREE_TEST_COUNT);
    for (block_ordinal, schedule) in EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES
        .iter()
        .copied()
        .enumerate()
    {
        let mut boundary_coordinates = bound_reduction_block_coordinates(block_ordinal)?;
        boundary_coordinates.extend((0..EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT).map(
            |bit_ordinal| {
                if schedule.quotient_degree_bound_exclusive
                    & (1 << (EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT - 1 - bit_ordinal))
                    == 0
                {
                    ChallengeField::ZERO
                } else {
                    ChallengeField::ONE
                }
            },
        ));
        points.push(Point::new(boundary_coordinates));

        // The boundary point checks the first forbidden quotient coefficient.
        // The block-specific aligned subcubes partition every later coefficient
        // through the shared 32,768-coefficient ambient polynomial.
        for (suffix_ordinal, fixed_prefix) in
            schedule.degree_suffix_prefixes.iter().copied().enumerate()
        {
            let mut coordinates = bound_reduction_block_coordinates(block_ordinal)?;
            coordinates.extend(fixed_prefix.iter().copied().map(|bit| {
                if bit == 0 {
                    ChallengeField::ZERO
                } else {
                    ChallengeField::ONE
                }
            }));
            while coordinates.len() < EXACT_TABLE_VARIABLE_COUNT {
                coordinates.push(
                    challenger.sample_exact_challenge(
                        RowCodeWhirChallenge::BoundDegreeCoordinate {
                            block_ordinal: u16::try_from(block_ordinal)
                                .map_err(|_| "bound block ordinal exceeds u16".to_owned())?,
                            degree_test_ordinal: u16::try_from(suffix_ordinal + 1)
                                .map_err(|_| "bound degree-test ordinal exceeds u16".to_owned())?,
                            coordinate_ordinal: u16::try_from(coordinates.len())
                                .map_err(|_| "bound coordinate ordinal exceeds u16".to_owned())?,
                        },
                    )?,
                );
            }
            points.push(Point::new(coordinates));
        }
        if points.len()
            != EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[..=block_ordinal]
                .iter()
                .copied()
                .map(ExactBoundReductionBlockSchedule::degree_test_count)
                .sum::<usize>()
        {
            return Err("bound degree-test block has the wrong fixed shape".to_owned());
        }
    }
    if points.len() != EXACT_BOUND_DEGREE_TEST_COUNT {
        return Err("bound degree-test schedule has the wrong fixed shape".to_owned());
    }
    Ok(points)
}

pub(super) fn bound_column_locations(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, (usize, usize, BoundTreeRootUse)>, String> {
    let mut locations = BTreeMap::new();
    let mut bound_tree_ordinal = 0_usize;
    let mut input_column_count = 0_usize;
    let mut output_column_count = 0_usize;
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::BoundPublic {
            root_use,
            ordered_column_ordinals,
            ..
        } = tree
        else {
            continue;
        };
        for (column_position, column_ordinal) in ordered_column_ordinals.iter().copied().enumerate()
        {
            if locations
                .insert(
                    column_ordinal,
                    (bound_tree_ordinal, column_position, *root_use),
                )
                .is_some()
            {
                return Err("bound relation column occurs in more than one tree".to_owned());
            }
        }
        match root_use {
            BoundTreeRootUse::Input => input_column_count += ordered_column_ordinals.len(),
            BoundTreeRootUse::Output => output_column_count += ordered_column_ordinals.len(),
        }
        bound_tree_ordinal += 1;
    }
    if bound_tree_ordinal != EXACT_BOUND_TREE_COUNT
        || locations.len() != EXACT_BOUND_COLUMN_COUNT
        || input_column_count != EXACT_INPUT_BOUND_COLUMN_COUNT
        || output_column_count != EXACT_OUTPUT_BOUND_COLUMN_COUNT
    {
        return Err("bound relation tree layout has the wrong fixed shape".to_owned());
    }
    Ok(locations)
}

#[derive(Clone)]
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactPointRowWeights {
    pub(super) selectors: [ChallengeField; 3],
    pub(super) base: Vec<ChallengeField>,
    pub(super) auxiliary: Vec<ChallengeField>,
    pub(super) quotient: Vec<ChallengeField>,
}

fn challenge_extension_basis(extension_coordinate: usize) -> ChallengeField {
    ChallengeField::new(core::array::from_fn(|coordinate| {
        if coordinate == extension_coordinate {
            Goldilocks::ONE
        } else {
            Goldilocks::ZERO
        }
    }))
}

pub(super) fn divide_polynomial_opening(
    coefficient_count: usize,
    mut coefficient_at: impl FnMut(usize) -> ChallengeField,
    opening_point: ChallengeField,
    claimed_value: ChallengeField,
) -> Result<(Vec<ChallengeField>, ChallengeField), String> {
    if coefficient_count == 0 {
        return Err("synthetic division requires a nonempty polynomial".to_owned());
    }
    let mut quotient = vec![ChallengeField::ZERO; coefficient_count - 1];
    if let Some(last_quotient) = quotient.last_mut() {
        *last_quotient = coefficient_at(coefficient_count - 1);
        for coefficient_ordinal in (1..quotient.len()).rev() {
            quotient[coefficient_ordinal - 1] =
                coefficient_at(coefficient_ordinal) + opening_point * quotient[coefficient_ordinal];
        }
    }
    let remainder = coefficient_at(0) - claimed_value
        + quotient.first().copied().unwrap_or(ChallengeField::ZERO) * opening_point;
    Ok((quotient, remainder))
}

pub(super) fn derive_exact_point_row_weights(
    challenger: &mut ExtensionFieldChallenger,
    base_layout: &ExactBasePhaseLayout,
    auxiliary_layout: &ExactBasePhaseLayout,
    quotient_opening_point: ProofChallengeExtensionElement,
) -> Result<[ExactPointRowWeights; 3], String> {
    let quotient_chunk_power = challenge_from_production(quotient_opening_point).exp_u64(
        u64::try_from(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .map_err(|_| "logical polynomial coefficient count exceeds u64".to_owned())?,
    );
    let mut weights = Vec::with_capacity(3);
    for opening_point_ordinal in 0..3 {
        let selectors = [
            challenger.sample_exact_challenge(RowCodeWhirChallenge::PointSelectorWeight {
                opening_point_ordinal,
                selector_ordinal: 0,
            })?,
            challenger.sample_exact_challenge(RowCodeWhirChallenge::PointSelectorWeight {
                opening_point_ordinal,
                selector_ordinal: 1,
            })?,
            challenger.sample_exact_challenge(RowCodeWhirChallenge::PointSelectorWeight {
                opening_point_ordinal,
                selector_ordinal: 2,
            })?,
        ];
        let mut base = Vec::with_capacity(base_layout.rows.len());
        for (column_group_ordinal, row) in base_layout.rows.iter().enumerate() {
            base.push(
                if row
                    .opening_point_ordinals
                    .contains(&(opening_point_ordinal as u32))
                {
                    challenger.sample_exact_challenge(
                        RowCodeWhirChallenge::TraceColumnGroupWeight {
                            opening_point_ordinal,
                            phase: RowCodeWhirTracePhase::Base,
                            column_group_ordinal: u32::try_from(column_group_ordinal)
                                .map_err(|_| "base column-group ordinal exceeds u32".to_owned())?,
                        },
                    )?
                } else {
                    ChallengeField::ZERO
                },
            );
        }
        let mut auxiliary = Vec::with_capacity(auxiliary_layout.rows.len());
        for (column_group_ordinal, row) in auxiliary_layout.rows.iter().enumerate() {
            auxiliary.push(
                if row
                    .opening_point_ordinals
                    .contains(&(opening_point_ordinal as u32))
                {
                    challenger.sample_exact_challenge(
                        RowCodeWhirChallenge::TraceColumnGroupWeight {
                            opening_point_ordinal,
                            phase: RowCodeWhirTracePhase::Auxiliary,
                            column_group_ordinal: u32::try_from(column_group_ordinal).map_err(
                                |_| "auxiliary column-group ordinal exceeds u32".to_owned(),
                            )?,
                        },
                    )?
                } else {
                    ChallengeField::ZERO
                },
            );
        }
        let mut quotient = vec![ChallengeField::ZERO; EXACT_QUOTIENT_PHASE_ROW_COUNT];
        if opening_point_ordinal == 0 {
            let quotient_component_weight =
                challenger.sample_exact_challenge(RowCodeWhirChallenge::QuotientGroupWeight {
                    opening_point_ordinal,
                    source_group_ordinal: 0,
                })?;
            let opening_batch_mask_weight = challenger.sample_exact_challenge(
                RowCodeWhirChallenge::OpeningBatchMaskWeight {
                    opening_point_ordinal,
                },
            )?;
            for extension_coordinate in 0..5 {
                let basis = challenge_extension_basis(extension_coordinate);
                quotient[extension_coordinate] = quotient_component_weight * basis;
                quotient[5 + extension_coordinate] =
                    quotient_component_weight * quotient_chunk_power * basis;
                quotient[10 + extension_coordinate] = opening_batch_mask_weight * basis;
            }
        }
        weights.push(ExactPointRowWeights {
            selectors,
            base,
            auxiliary,
            quotient,
        });
    }
    let weights: [ExactPointRowWeights; 3] = weights
        .try_into()
        .map_err(|_| "exact point-row weight count changed".to_owned())?;
    let aggregate_pad_rank = aggregate_pad_rank(&weights);
    if aggregate_pad_rank != 15 {
        return Err(format!(
            "exact aggregate row-pad map has base-field rank {aggregate_pad_rank}, expected 15"
        ));
    }
    Ok(weights)
}

/// Computes the joint base-field rank of the three extension-field aggregate
/// pad values at one coefficient position. Every physical row contributes one
/// independent base-field pad scalar. Full rank makes the three aggregate pad
/// polynomials independent even though each phase reuses its row pads across
/// the three opening points.
fn aggregate_pad_rank(point_row_weights: &[ExactPointRowWeights; 3]) -> usize {
    let source_count = point_row_weights[0].base.len()
        + point_row_weights[0].auxiliary.len()
        + point_row_weights[0].quotient.len();
    let mut matrix = (0..15)
        .map(|_| Vec::with_capacity(source_count))
        .collect::<Vec<_>>();
    for phase_ordinal in 0..3 {
        let phase_row_count = match phase_ordinal {
            0 => point_row_weights[0].base.len(),
            1 => point_row_weights[0].auxiliary.len(),
            2 => point_row_weights[0].quotient.len(),
            _ => unreachable!("three exact phases"),
        };
        for row_ordinal in 0..phase_row_count {
            for (opening_point_ordinal, point_weights) in point_row_weights.iter().enumerate() {
                let weights = match phase_ordinal {
                    0 => &point_weights.base,
                    1 => &point_weights.auxiliary,
                    2 => &point_weights.quotient,
                    _ => unreachable!("three exact phases"),
                };
                let coordinates =
                    <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                        &weights[row_ordinal],
                    );
                for (coordinate_ordinal, coordinate) in coordinates.iter().enumerate() {
                    matrix[opening_point_ordinal * 5 + coordinate_ordinal].push(*coordinate);
                }
            }
        }
    }

    let mut pivot_row = 0_usize;
    for source_ordinal in 0..source_count {
        let Some(nonzero_offset) = matrix[pivot_row..]
            .iter()
            .position(|row| row[source_ordinal] != Goldilocks::ZERO)
        else {
            continue;
        };
        matrix.swap(pivot_row, pivot_row + nonzero_offset);
        let inverse = matrix[pivot_row][source_ordinal].inverse();
        for value in &mut matrix[pivot_row][source_ordinal..] {
            *value *= inverse;
        }
        let normalized_pivot = matrix[pivot_row][source_ordinal..].to_vec();
        for (row_ordinal, row) in matrix.iter_mut().enumerate() {
            if row_ordinal == pivot_row {
                continue;
            }
            let scale = row[source_ordinal];
            for (value, pivot_value) in row[source_ordinal..].iter_mut().zip(&normalized_pivot) {
                *value -= scale * *pivot_value;
            }
        }
        pivot_row += 1;
        if pivot_row == matrix.len() {
            break;
        }
    }
    pivot_row
}

fn claim_key(
    source_class: RelationOpeningSourceClass,
    source_ordinal: u32,
    column_ordinal: Option<u32>,
    opening_point_ordinal: u32,
) -> (u16, u32, u32) {
    let source_identifier = match source_class {
        RelationOpeningSourceClass::TreeColumn => {
            column_ordinal.expect("checked tree claim has a column ordinal")
        }
        RelationOpeningSourceClass::Quotient | RelationOpeningSourceClass::BatchMask => {
            source_ordinal
        }
    };
    (
        source_class as u16,
        source_identifier,
        opening_point_ordinal,
    )
}

fn out_of_domain_evaluation_catalog(
    variant: &RelationPlanVariant,
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
) -> Result<BTreeMap<(u16, u32, u32), ProofChallengeExtensionElement>, String> {
    if out_of_domain_evaluations.len() != variant.ordered_opening_claims().len() {
        return Err("out-of-domain evaluation count does not match the relation".to_owned());
    }
    let mut catalog = BTreeMap::new();
    for (claim, value) in variant
        .ordered_opening_claims()
        .iter()
        .zip(out_of_domain_evaluations)
    {
        let key = claim_key(
            claim.source_class(),
            claim.source_ordinal(),
            claim.column_ordinal(),
            claim.opening_point_ordinal(),
        );
        if catalog.insert(key, *value).is_some() {
            return Err("relation contains a duplicate opening claim".to_owned());
        }
    }
    Ok(catalog)
}

fn selector_equality_weights(selectors: [ChallengeField; 3]) -> [ChallengeField; 8] {
    Poly::new_from_point(&selectors, ChallengeField::ONE)
        .as_slice()
        .try_into()
        .expect("three selector variables have eight equality weights")
}

fn verify_opening_batch_mask_chunk_evaluations(
    variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    chunk_evaluations: &[ProofChallengeExtensionElement; EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
) -> Result<(), String> {
    let opening_point = opening_points
        .first()
        .copied()
        .ok_or_else(|| "exact relation has no quotient opening point".to_owned())?;
    let catalog = out_of_domain_evaluation_catalog(variant, out_of_domain_evaluations)?;
    let claimed_mask_evaluation = catalog
        .get(&claim_key(
            RelationOpeningSourceClass::BatchMask,
            0,
            None,
            0,
        ))
        .copied()
        .ok_or_else(|| "exact relation has no opening-batch mask claim".to_owned())?;
    let opening_point = challenge_from_production(opening_point);
    let chunk_power = opening_point.exp_u64(
        u64::try_from(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .map_err(|_| "logical polynomial coefficient count exceeds u64".to_owned())?,
    );
    let mut recombined_evaluation = ChallengeField::ZERO;
    let mut current_chunk_power = ChallengeField::ONE;
    for chunk_evaluation in chunk_evaluations {
        recombined_evaluation += current_chunk_power * challenge_from_production(*chunk_evaluation);
        current_chunk_power *= chunk_power;
    }
    if recombined_evaluation != challenge_from_production(claimed_mask_evaluation) {
        return Err(
            "opening-batch mask chunk evaluations do not recombine to the production claim"
                .to_owned(),
        );
    }
    Ok(())
}

fn expected_base_phase_out_of_domain_value(
    layout: &ExactBasePhaseLayout,
    row_weights: &[ChallengeField],
    selector_weights: [ChallengeField; 8],
    opening_point_ordinal: u32,
    catalog: &BTreeMap<(u16, u32, u32), ProofChallengeExtensionElement>,
) -> Result<ChallengeField, String> {
    if layout.rows.len() != row_weights.len() {
        return Err("exact base-phase row weights do not match the layout".to_owned());
    }
    let mut expected = ChallengeField::ZERO;
    for (row, row_weight) in layout.rows.iter().zip(row_weights) {
        if *row_weight == ChallengeField::ZERO {
            continue;
        }
        for (block_ordinal, column_ordinal) in row.column_ordinals.iter().enumerate() {
            let Some(column_ordinal) = column_ordinal else {
                continue;
            };
            let value = catalog
                .get(&claim_key(
                    RelationOpeningSourceClass::TreeColumn,
                    0,
                    Some(*column_ordinal),
                    opening_point_ordinal,
                ))
                .copied()
                .ok_or_else(|| {
                    format!(
                        "relation column {column_ordinal} has no opening at point {opening_point_ordinal}"
                    )
                })?;
            expected +=
                *row_weight * selector_weights[block_ordinal] * challenge_from_production(value);
        }
    }
    Ok(expected)
}

fn expected_quotient_phase_out_of_domain_value(
    row_weights: &[ChallengeField],
    selector_weights: [ChallengeField; 8],
    catalog: &BTreeMap<(u16, u32, u32), ProofChallengeExtensionElement>,
    opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement;
         EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
) -> Result<ChallengeField, String> {
    if row_weights.len() != EXACT_QUOTIENT_PHASE_ROW_COUNT {
        return Err("exact quotient row weights have the wrong count".to_owned());
    }
    let mut expected = ChallengeField::ZERO;
    let quotient_component_weight = row_weights[0];
    for (component_ordinal, selector_weight) in selector_weights.iter().enumerate() {
        let source_ordinal = u32::try_from(component_ordinal)
            .map_err(|_| "quotient component ordinal exceeds u32".to_owned())?;
        let value = catalog
            .get(&claim_key(
                RelationOpeningSourceClass::Quotient,
                source_ordinal,
                None,
                0,
            ))
            .copied()
            .ok_or_else(|| format!("quotient component {source_ordinal} has no opening"))?;
        expected += quotient_component_weight * *selector_weight * challenge_from_production(value);
    }
    let opening_batch_mask_weight = row_weights[10];
    for (chunk_ordinal, chunk_evaluation) in opening_batch_mask_chunk_evaluations.iter().enumerate()
    {
        expected += opening_batch_mask_weight
            * selector_weights[chunk_ordinal]
            * challenge_from_production(*chunk_evaluation);
    }
    Ok(expected)
}

fn exact_whir_opening_points(
    opening_points: &[ProofChallengeExtensionElement],
    point_row_weights: &[ExactPointRowWeights; 3],
    query_indices: &[usize],
    bound_query_indices: &ExactBoundQueryIndices,
    bound_evaluation_domain: ProofEvaluationDomain,
    degree_test_points: &[Point<ChallengeField>],
    shape: ExactProofShape,
) -> Result<Vec<Point<ChallengeField>>, String> {
    if opening_points.len() < 3
        || query_indices.len() != shape.outer_query_count
        || !bound_query_indices.has_exact_shape(shape)
        || degree_test_points.len() != EXACT_BOUND_DEGREE_TEST_COUNT
        || bound_evaluation_domain.size() != EXACT_BOUND_LEAF_COUNT * 2
    {
        return Err("exact WHIR opening schedule has the wrong shape".to_owned());
    }
    let bound_reduction_evaluation_count = shape.bound_reduction_evaluation_count()?;
    let point_count = 3_usize
        .checked_add(query_indices.len())
        .and_then(|count| count.checked_add(bound_reduction_evaluation_count))
        .and_then(|count| count.checked_add(degree_test_points.len()))
        .ok_or_else(|| "exact WHIR opening-point count overflowed".to_owned())?;
    let mut points = Vec::new();
    points
        .try_reserve_exact(point_count)
        .map_err(|_| "exact WHIR opening-point allocation failed".to_owned())?;
    for opening_point_ordinal in 0..3 {
        let reduction = polynomial_extension_opening_reduction(
            challenge_from_production(opening_points[opening_point_ordinal]),
            15,
        )?;
        let mut coordinates = Vec::with_capacity(EXACT_TABLE_VARIABLE_COUNT);
        coordinates.push(ChallengeField::ZERO);
        coordinates.extend_from_slice(&point_row_weights[opening_point_ordinal].selectors);
        coordinates.extend_from_slice(reduction.multilinear_point.as_slice());
        if coordinates.len() != EXACT_TABLE_VARIABLE_COUNT {
            return Err("exact out-of-domain WHIR point has the wrong variable count".to_owned());
        }
        points.push(Point::new(coordinates));
    }
    let log_encoded_column_count = shape.encoded_column_count.ilog2() as usize;
    for column_index in query_indices {
        points.push(
            polynomial_opening_reduction(
                coset_point(log_encoded_column_count, *column_index)?,
                EXACT_TABLE_VARIABLE_COUNT,
            )?
            .multilinear_point,
        );
    }
    for (block_ordinal, block_query_indices) in [
        (
            0,
            bound_query_indices.accepted_input_root_indices.as_slice(),
        ),
        (
            1,
            bound_query_indices.accepted_output_root_indices.as_slice(),
        ),
    ] {
        for leaf_index in block_query_indices {
            for evaluation_position in [*leaf_index, *leaf_index + EXACT_BOUND_LEAF_COUNT] {
                let evaluation_point = bound_evaluation_domain
                    .point(evaluation_position)
                    .map_err(|error| format!("derive bound evaluation point: {error:?}"))?;
                let reduction = polynomial_opening_reduction(
                    Goldilocks::new(evaluation_point.canonical()),
                    EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT,
                )?;
                let mut coordinates = bound_reduction_block_coordinates(block_ordinal)?;
                coordinates.extend_from_slice(reduction.multilinear_point.as_slice());
                if coordinates.len() != EXACT_TABLE_VARIABLE_COUNT {
                    return Err("bound reduction WHIR point has the wrong width".to_owned());
                }
                points.push(Point::new(coordinates));
            }
        }
    }
    points.extend_from_slice(degree_test_points);
    Ok(points)
}

#[cfg(test)]
fn requested_columns_by_point(shape: ExactProofShape) -> Vec<Vec<usize>> {
    let mut requested = vec![vec![0], vec![1], vec![2]];
    requested.extend(std::iter::repeat_with(|| vec![0, 1, 2]).take(shape.outer_query_count));
    requested.extend(
        std::iter::repeat_with(|| vec![EXACT_BOUND_REDUCTION_COLUMN_INDEX]).take(
            (shape.verified_vss_bound_query_count + shape.direct_bound_query_count) * 2
                + EXACT_BOUND_DEGREE_TEST_COUNT,
        ),
    );
    requested
}

fn expected_out_of_domain_whir_evaluations(
    variant: &RelationPlanVariant,
    base_layout: &ExactBasePhaseLayout,
    auxiliary_layout: &ExactBasePhaseLayout,
    opening_points: &[ProofChallengeExtensionElement],
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement;
         EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
    point_row_weights: &[ExactPointRowWeights; 3],
) -> Result<[ChallengeField; 3], String> {
    let catalog = out_of_domain_evaluation_catalog(variant, out_of_domain_evaluations)?;
    let mut expected = [ChallengeField::ZERO; 3];
    for opening_point_ordinal in 0..3 {
        let selector_weights =
            selector_equality_weights(point_row_weights[opening_point_ordinal].selectors);
        let mut polynomial_value = expected_base_phase_out_of_domain_value(
            base_layout,
            &point_row_weights[opening_point_ordinal].base,
            selector_weights,
            opening_point_ordinal as u32,
            &catalog,
        )?;
        polynomial_value += expected_base_phase_out_of_domain_value(
            auxiliary_layout,
            &point_row_weights[opening_point_ordinal].auxiliary,
            selector_weights,
            opening_point_ordinal as u32,
            &catalog,
        )?;
        if opening_point_ordinal == 0 {
            polynomial_value += expected_quotient_phase_out_of_domain_value(
                &point_row_weights[opening_point_ordinal].quotient,
                selector_weights,
                &catalog,
                opening_batch_mask_chunk_evaluations,
            )?;
        }
        let reduction = polynomial_extension_opening_reduction(
            challenge_from_production(opening_points[opening_point_ordinal]),
            15,
        )?;
        expected[opening_point_ordinal] =
            polynomial_value * reduction.multilinear_to_polynomial_scale.inverse();
    }
    Ok(expected)
}

fn derive_query_indices(
    challenger: &mut ExtensionFieldChallenger,
    shape: ExactProofShape,
) -> Result<Vec<usize>, String> {
    let (_, traversal_query_indices) = derive_outer_query_indices(challenger, shape)?;
    Ok(traversal_query_indices)
}

fn derive_outer_query_indices(
    challenger: &mut ExtensionFieldChallenger,
    shape: ExactProofShape,
) -> Result<(Vec<usize>, Vec<usize>), String> {
    let accepted_query_indices = challenger.sample_exact_distinct_indices(
        RowCodeWhirChallenge::OuterQueryVector,
        shape.encoded_column_count,
        shape.outer_query_count,
    )?;
    let mut traversal_query_indices = accepted_query_indices.clone();
    traversal_query_indices.sort_unstable();
    Ok((accepted_query_indices, traversal_query_indices))
}

pub(super) fn derive_exact_same_secret_opening_schedule_after_observed_commitment(
    continuation: ExactSameSecretOpeningScheduleContinuation,
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_context: &RelationPlanCheckContext,
    opening_points: &[ProofChallengeExtensionElement],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<ExactSameSecretOpeningSchedule, CommonProofProverError> {
    let construction_identity = construction_plan
        .canonical_identity_hash()
        .map_err(|_| CommonProofProverError::InvalidInput)?;
    let shape = continuation.shape;
    let base_encoded_column_count = construction_plan
        .base_phase
        .as_ref()
        .ok_or(CommonProofProverError::InvalidColumn)?
        .geometry
        .encoded_column_count;
    if construction_identity != continuation.construction_plan_identity_hash
        || relation_context.evaluation_domain_generator != continuation.evaluation_domain_generator
        || relation_context.evaluation_coset_offset != continuation.evaluation_coset_offset
        || relation_context.phase_column_query_coordinate_count
            != u32::try_from(shape.outer_query_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?
        || construction_plan.parameters.outer_query_count != shape.outer_query_count
        || construction_plan.parameters.direct_bound_query_count != shape.direct_bound_query_count
        || construction_plan.parameters.verified_vss_bound_query_count
            != shape.verified_vss_bound_query_count
        || construction_plan.aggregate_table_width() != shape.aggregate_table_width
        || base_encoded_column_count != shape.encoded_column_count
        || opening_points.len() != 3
        || continuation.point_row_weights[0].base.len() != shape.base_row_count
        || continuation.point_row_weights[0].auxiliary.len() != shape.auxiliary_row_count
        || continuation.point_row_weights[0].quotient.len() != shape.quotient_row_count
        || continuation.point_row_weights.iter().any(|weights| {
            weights.base.len() != shape.base_row_count
                || weights.auxiliary.len() != shape.auxiliary_row_count
                || weights.quotient.len() != shape.quotient_row_count
        })
    {
        return Err(CommonProofProverError::InvalidInput);
    }

    let (outer_accepted_query_indices, outer_traversal_query_indices) =
        derive_outer_query_indices(challenger, shape)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
    let bound_query_indices = derive_bound_query_indices(challenger, shape)
        .map_err(|_| CommonProofProverError::InvalidInput)?;
    let degree_test_points =
        bound_degree_test_points(challenger).map_err(|_| CommonProofProverError::InvalidInput)?;
    let bound_evaluation_domain = ProofEvaluationDomain::new(
        usize::try_from(construction_plan.evaluation_domain_size)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        relation_context.evaluation_coset_offset,
    )
    .map_err(|_| CommonProofProverError::InvalidInput)?;
    if bound_evaluation_domain.generator().canonical()
        != relation_context.evaluation_domain_generator
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let points = exact_whir_opening_points(
        opening_points,
        &continuation.point_row_weights,
        &outer_traversal_query_indices,
        &bound_query_indices,
        bound_evaluation_domain,
        &degree_test_points,
        shape,
    )
    .map_err(|_| CommonProofProverError::InvalidOpening)?;
    let requested_columns_by_point = construction_plan
        .opening_batches()
        .iter()
        .map(|batch| {
            batch
                .requested_aggregate_column_ordinals
                .iter()
                .copied()
                .map(|column_ordinal| {
                    let column_ordinal = usize::try_from(column_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?;
                    if column_ordinal >= shape.aggregate_table_width {
                        return Err(CommonProofProverError::InvalidColumn);
                    }
                    Ok(column_ordinal)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    if requested_columns_by_point.len() != points.len()
        || requested_columns_by_point
            .iter()
            .any(|requested_columns| requested_columns.is_empty())
    {
        return Err(CommonProofProverError::InvalidOpening);
    }

    Ok(ExactSameSecretOpeningSchedule {
        points,
        requested_columns_by_point,
        outer_accepted_query_indices,
        outer_traversal_query_indices,
        bound_query_indices,
        bound_evaluation_domain,
        degree_test_points,
        point_row_weights: continuation.point_row_weights,
    })
}

#[cfg(test)]
fn verify_phase_openings(
    shape: ExactProofShape,
    proof: &ExactSameSecretProof,
    query_indices: &[usize],
) -> Result<(), String> {
    let roots = [proof.base_root, proof.auxiliary_root, proof.quotient_root];
    for (phase_index, ((phase_columns, frontier), root)) in proof
        .authenticated_phase_columns
        .iter()
        .zip(&proof.phase_frontiers)
        .zip(roots)
        .enumerate()
    {
        verify_phase_opening(
            shape,
            phase_index,
            root,
            phase_columns,
            frontier,
            query_indices,
        )?;
    }
    Ok(())
}

#[cfg(test)]
fn verify_phase_opening(
    shape: ExactProofShape,
    phase_index: usize,
    root: ColumnDigest,
    phase_columns: &[AuthenticatedColumn],
    frontier: &[ColumnDigest],
    query_indices: &[usize],
) -> Result<(), String> {
    let expected_row_count = *shape
        .phase_row_counts()
        .get(phase_index)
        .ok_or_else(|| "exact phase index is outside the fixed shape".to_owned())?;
    if phase_columns.len() != shape.outer_query_count
        || query_indices.len() != shape.outer_query_count
        || phase_columns
            .iter()
            .any(|column| column.values.len() != expected_row_count)
        || frontier.len() > shape.maximum_frontier_count()?
    {
        return Err("exact same-secret phase opening has the wrong fixed shape".to_owned());
    }
    let opened_columns = query_indices
        .iter()
        .copied()
        .zip(phase_columns.iter().map(|column| column.values.as_slice()))
        .collect::<Vec<_>>();
    verify_column_frontier(&root, shape.encoded_column_count, &opened_columns, frontier)
}

fn verify_materialized_frontier(
    entry: &ProofTreeCatalogEntry,
    opened_leaves: &[(u64, [u8; 64])],
    frontier: &[[u8; 64]],
    expected_query_count: usize,
) -> Result<(), String> {
    if opened_leaves.len() != expected_query_count
        || opened_leaves.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || opened_leaves
            .last()
            .is_some_and(|(leaf_index, _)| *leaf_index >= EXACT_BOUND_LEAF_COUNT as u64)
    {
        return Err("bound tree opening indexes are not canonical".to_owned());
    }
    let mut current = opened_leaves.iter().copied().collect::<BTreeMap<_, _>>();
    let mut frontier_offset = 0_usize;
    for level in 0..EXACT_BOUND_LEAF_COUNT.trailing_zeros() {
        let mut next = BTreeMap::new();
        let mut processed = BTreeSet::new();
        for index in current.keys().copied().collect::<Vec<_>>() {
            if !processed.insert(index) {
                continue;
            }
            let sibling_index = index ^ 1;
            let sibling_digest = if let Some(digest) = current.get(&sibling_index).copied() {
                processed.insert(sibling_index);
                digest
            } else {
                let digest = frontier
                    .get(frontier_offset)
                    .copied()
                    .ok_or_else(|| "bound authentication frontier is truncated".to_owned())?;
                frontier_offset += 1;
                digest
            };
            let own_digest = *current
                .get(&index)
                .ok_or_else(|| "bound authentication leaf is absent".to_owned())?;
            let (left, right) = if index & 1 == 0 {
                (own_digest, sibling_digest)
            } else {
                (sibling_digest, own_digest)
            };
            let parent_index = index / 2;
            let parent_digest = entry
                .materialized_parent_digest(level + 1, parent_index, left, right)
                .map_err(|error| format!("hash bound parent: {error:?}"))?;
            if next.insert(parent_index, parent_digest).is_some() {
                return Err("bound authentication frontier is non-canonical".to_owned());
            }
        }
        current = next;
    }
    if frontier_offset != frontier.len()
        || current.len() != 1
        || current.get(&0).copied() != entry.bound_root()
    {
        return Err("bound authentication frontier has the wrong root".to_owned());
    }
    Ok(())
}

#[cfg(test)]
fn verify_bound_tree_authentications(
    entries: &[ProofTreeCatalogEntry],
    proof: &ExactSameSecretProof,
    bound_query_indices: &ExactBoundQueryIndices,
    shape: ExactProofShape,
) -> Result<(), String> {
    if entries.len() != EXACT_BOUND_TREE_COUNT
        || proof.bound_tree_authentications.len() != EXACT_BOUND_TREE_COUNT
        || !bound_query_indices.has_exact_shape(shape)
    {
        return Err("bound authentication catalog has the wrong fixed shape".to_owned());
    }
    for (bound_tree_ordinal, (entry, authentication)) in entries
        .iter()
        .zip(&proof.bound_tree_authentications)
        .enumerate()
    {
        let tree_query_indices =
            bound_query_indices.traversal_indices_for_tree_ordinal(shape, bound_tree_ordinal)?;
        verify_bound_tree_authentication(entry, authentication, tree_query_indices)?;
    }
    Ok(())
}

#[cfg(test)]
fn verify_bound_tree_authentication(
    entry: &ProofTreeCatalogEntry,
    authentication: &ExactBoundTreeAuthentication,
    tree_query_indices: &[usize],
) -> Result<(), String> {
    let query_count = tree_query_indices.len();
    if authentication.opened_leaves.len() != query_count
        || authentication.opened_leaves.iter().any(|opening| {
            opening.persistent_salt.is_some() != entry.requires_persistent_leaf_salt()
        })
    {
        return Err("bound authentication has the wrong leaf shape".to_owned());
    }
    let maximum_frontier_count = query_count
        .checked_mul(EXACT_BOUND_LEAF_COUNT.ilog2() as usize)
        .ok_or_else(|| "bound frontier limit overflowed".to_owned())?;
    if authentication.frontier.len() > maximum_frontier_count {
        return Err("bound authentication frontier exceeds its fixed maximum".to_owned());
    }
    let mut opened_leaf_digests = Vec::with_capacity(query_count);
    for (leaf_index, opening) in tree_query_indices
        .iter()
        .copied()
        .zip(&authentication.opened_leaves)
    {
        let leaf_index =
            u64::try_from(leaf_index).map_err(|_| "bound leaf index exceeds u64".to_owned())?;
        let (_, leaf_digest) = entry
            .encode_materialized_leaf(
                leaf_index,
                opening.persistent_salt,
                Zeroizing::new(
                    opening
                        .first_point_values
                        .iter()
                        .copied()
                        .map(ProofTreeValue::Base)
                        .collect(),
                ),
                Zeroizing::new(
                    opening
                        .opposite_point_values
                        .iter()
                        .copied()
                        .map(ProofTreeValue::Base)
                        .collect(),
                ),
            )
            .map_err(|error| format!("encode bound leaf: {error:?}"))?;
        opened_leaf_digests.push((leaf_index, leaf_digest));
    }
    verify_materialized_frontier(
        entry,
        &opened_leaf_digests,
        &authentication.frontier,
        query_count,
    )
}

#[cfg(test)]
fn expected_bound_reduction_whir_evaluations(
    variant: &RelationPlanVariant,
    proof: &ExactSameSecretProof,
    bound_query_indices: &ExactBoundQueryIndices,
    bound_evaluation_domain: ProofEvaluationDomain,
    bound_claims: &[ExactBoundOpeningClaim],
    shape: ExactProofShape,
) -> Result<Vec<ChallengeField>, String> {
    let locations = bound_column_locations(variant)?;
    if !bound_query_indices.has_exact_shape(shape) {
        return Err("bound reduction query schedule has the wrong count".to_owned());
    }
    let expected_evaluation_count = shape.bound_reduction_evaluation_count()?;
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(expected_evaluation_count)
        .map_err(|_| "bound reduction evaluation allocation failed".to_owned())?;
    for root_use in [BoundTreeRootUse::Input, BoundTreeRootUse::Output] {
        for (query_ordinal, leaf_index) in bound_query_indices
            .accepted_indices_for_root_use(root_use)
            .iter()
            .copied()
            .enumerate()
        {
            for (opposite, evaluation_position) in [
                (false, leaf_index),
                (true, leaf_index + EXACT_BOUND_LEAF_COUNT),
            ] {
                let evaluation_point = bound_evaluation_domain
                    .point(evaluation_position)
                    .map_err(|error| format!("derive bound evaluation point: {error:?}"))?;
                let evaluation_point_challenge =
                    ChallengeField::from(Goldilocks::new(evaluation_point.canonical()));
                let mut polynomial_value = ChallengeField::ZERO;
                for claim in bound_claims {
                    let (tree_ordinal, column_position, claim_root_use) = locations
                        .get(&claim.column_ordinal)
                        .copied()
                        .ok_or_else(|| "bound claim column has no tree location".to_owned())?;
                    if claim_root_use != root_use {
                        continue;
                    }
                    let opening = proof
                        .bound_tree_authentications
                        .get(tree_ordinal)
                        .and_then(|authentication| authentication.opened_leaves.get(query_ordinal))
                        .ok_or_else(|| "bound claim opening is absent".to_owned())?;
                    let value = if opposite {
                        opening.opposite_point_values[column_position]
                    } else {
                        opening.first_point_values[column_position]
                    };
                    let denominator = evaluation_point_challenge - claim.opening_point;
                    if denominator == ChallengeField::ZERO {
                        return Err("bound opening reduction sampled a pole".to_owned());
                    }
                    polynomial_value += claim.batching_weight
                        * (ChallengeField::from(Goldilocks::new(value.canonical()))
                            - claim.claimed_value)
                        * denominator.inverse();
                }
                let reduction = polynomial_opening_reduction(
                    Goldilocks::new(evaluation_point.canonical()),
                    EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT,
                )?;
                expected
                    .push(polynomial_value * reduction.multilinear_to_polynomial_scale.inverse());
            }
        }
    }
    if expected.len() != expected_evaluation_count {
        return Err("bound reduction evaluation schedule is incomplete".to_owned());
    }
    Ok(expected)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn accumulate_bound_tree_reduction_whir_evaluations(
    variant: &RelationPlanVariant,
    authentication: &ExactBoundTreeAuthentication,
    bound_tree_ordinal: usize,
    bound_query_indices: &ExactBoundQueryIndices,
    bound_evaluation_domain: ProofEvaluationDomain,
    bound_claims: &[ExactBoundOpeningClaim],
    shape: ExactProofShape,
    expected: &mut [ChallengeField],
) -> Result<(), String> {
    let tree_query_indices =
        bound_query_indices.traversal_indices_for_tree_ordinal(shape, bound_tree_ordinal)?;
    let locations = bound_column_locations(variant)?;
    let expected_evaluation_count = shape.bound_reduction_evaluation_count()?;
    if expected.len() != expected_evaluation_count
        || authentication.opened_leaves.len() != tree_query_indices.len()
    {
        return Err("bound reduction accumulator has the wrong fixed shape".to_owned());
    }
    let root_use = locations
        .values()
        .find_map(|(tree_index, _, root_use)| {
            (*tree_index == bound_tree_ordinal).then_some(*root_use)
        })
        .ok_or_else(|| "bound tree has no relation column location".to_owned())?;
    if locations
        .values()
        .any(|(tree_index, _, candidate_root_use)| {
            *tree_index == bound_tree_ordinal && *candidate_root_use != root_use
        })
    {
        return Err("bound tree mixes input and output roots".to_owned());
    }
    let root_use_offset = match root_use {
        BoundTreeRootUse::Input => 0,
        BoundTreeRootUse::Output => shape
            .verified_vss_bound_query_count
            .checked_mul(2)
            .ok_or_else(|| "bound reduction input offset overflowed".to_owned())?,
    };
    for (leaf_index, opening) in tree_query_indices
        .iter()
        .copied()
        .zip(&authentication.opened_leaves)
    {
        let accepted_query_ordinal =
            bound_query_indices.accepted_query_ordinal_for_tree(bound_tree_ordinal, leaf_index)?;
        for (opposite_ordinal, (opposite, evaluation_position)) in [
            (false, leaf_index),
            (true, leaf_index + EXACT_BOUND_LEAF_COUNT),
        ]
        .into_iter()
        .enumerate()
        {
            let evaluation_point = bound_evaluation_domain
                .point(evaluation_position)
                .map_err(|error| format!("derive bound evaluation point: {error:?}"))?;
            let evaluation_point_challenge =
                ChallengeField::from(Goldilocks::new(evaluation_point.canonical()));
            let mut polynomial_value = ChallengeField::ZERO;
            for claim in bound_claims {
                let (claim_tree_ordinal, column_position, claim_root_use) = locations
                    .get(&claim.column_ordinal)
                    .copied()
                    .ok_or_else(|| "bound claim column has no tree location".to_owned())?;
                if claim_tree_ordinal != bound_tree_ordinal || claim_root_use != root_use {
                    continue;
                }
                let value = if opposite {
                    opening.opposite_point_values[column_position]
                } else {
                    opening.first_point_values[column_position]
                };
                let denominator = evaluation_point_challenge - claim.opening_point;
                if denominator == ChallengeField::ZERO {
                    return Err("bound opening reduction sampled a pole".to_owned());
                }
                polynomial_value += claim.batching_weight
                    * (ChallengeField::from(Goldilocks::new(value.canonical()))
                        - claim.claimed_value)
                    * denominator.inverse();
            }
            let reduction = polynomial_opening_reduction(
                Goldilocks::new(evaluation_point.canonical()),
                EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT,
            )?;
            let expected_index = root_use_offset
                .checked_add(
                    accepted_query_ordinal
                        .checked_mul(2)
                        .and_then(|offset| offset.checked_add(opposite_ordinal))
                        .ok_or_else(|| "bound reduction query offset overflowed".to_owned())?,
                )
                .ok_or_else(|| "bound reduction evaluation offset overflowed".to_owned())?;
            let expected_evaluation = expected
                .get_mut(expected_index)
                .ok_or_else(|| "bound reduction evaluation offset is outside shape".to_owned())?;
            *expected_evaluation +=
                polynomial_value * reduction.multilinear_to_polynomial_scale.inverse();
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn accumulate_bound_leaf_reduction_whir_evaluations(
    variant: &RelationPlanVariant,
    opening: &ExactBoundLeafOpening,
    bound_tree_ordinal: usize,
    query_ordinal: usize,
    leaf_index: usize,
    bound_evaluation_domain: ProofEvaluationDomain,
    bound_claims: &[ExactBoundOpeningClaim],
    shape: ExactProofShape,
    expected: &mut [ChallengeField],
) -> Result<(), String> {
    let locations = bound_column_locations(variant)?;
    if expected.len() != shape.bound_reduction_evaluation_count()? {
        return Err("bound leaf reduction accumulator has the wrong shape".to_owned());
    }
    let root_use = locations
        .values()
        .find_map(|(tree_index, _, root_use)| {
            (*tree_index == bound_tree_ordinal).then_some(*root_use)
        })
        .ok_or_else(|| "bound tree has no relation column location".to_owned())?;
    let root_use_offset = match root_use {
        BoundTreeRootUse::Input => 0,
        BoundTreeRootUse::Output => shape
            .verified_vss_bound_query_count
            .checked_mul(2)
            .ok_or_else(|| "bound reduction input offset overflowed".to_owned())?,
    };
    for (opposite_ordinal, (opposite, evaluation_position)) in [
        (false, leaf_index),
        (true, leaf_index + EXACT_BOUND_LEAF_COUNT),
    ]
    .into_iter()
    .enumerate()
    {
        let evaluation_point = bound_evaluation_domain
            .point(evaluation_position)
            .map_err(|error| format!("derive bound evaluation point: {error:?}"))?;
        let evaluation_point_challenge =
            ChallengeField::from(Goldilocks::new(evaluation_point.canonical()));
        let mut polynomial_value = ChallengeField::ZERO;
        for claim in bound_claims {
            let (claim_tree_ordinal, column_position, claim_root_use) = locations
                .get(&claim.column_ordinal)
                .copied()
                .ok_or_else(|| "bound claim column has no tree location".to_owned())?;
            if claim_tree_ordinal != bound_tree_ordinal || claim_root_use != root_use {
                continue;
            }
            let value = if opposite {
                opening.opposite_point_values[column_position]
            } else {
                opening.first_point_values[column_position]
            };
            let denominator = evaluation_point_challenge - claim.opening_point;
            if denominator == ChallengeField::ZERO {
                return Err("bound opening reduction sampled a pole".to_owned());
            }
            polynomial_value += claim.batching_weight
                * (ChallengeField::from(Goldilocks::new(value.canonical())) - claim.claimed_value)
                * denominator.inverse();
        }
        let reduction = polynomial_opening_reduction(
            Goldilocks::new(evaluation_point.canonical()),
            EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT,
        )?;
        let expected_index = root_use_offset
            .checked_add(
                query_ordinal
                    .checked_mul(2)
                    .and_then(|offset| offset.checked_add(opposite_ordinal))
                    .ok_or_else(|| "bound reduction query offset overflowed".to_owned())?,
            )
            .ok_or_else(|| "bound reduction evaluation offset overflowed".to_owned())?;
        *expected
            .get_mut(expected_index)
            .ok_or_else(|| "bound reduction evaluation offset is outside shape".to_owned())? +=
            polynomial_value * reduction.multilinear_to_polynomial_scale.inverse();
    }
    Ok(())
}

fn ensure_bound_opening_points_are_outside_evaluation_domain(
    bound_claims: &[ExactBoundOpeningClaim],
    evaluation_domain_size: u64,
    evaluation_coset_offset: u64,
) -> Result<(), String> {
    let domain_constant = ChallengeField::from(Goldilocks::new(evaluation_coset_offset))
        .exp_u64(evaluation_domain_size);
    if bound_claims
        .iter()
        .any(|claim| claim.opening_point.exp_u64(evaluation_domain_size) == domain_constant)
    {
        return Err("bound opening point lies in the authenticated evaluation domain".to_owned());
    }
    Ok(())
}

#[cfg(test)]
fn expected_query_whir_evaluations(
    shape: ExactProofShape,
    proof: &ExactSameSecretProof,
    query_indices: &[usize],
    point_row_weights: &[ExactPointRowWeights; 3],
) -> Result<Vec<[ChallengeField; 3]>, String> {
    let mut expected = Vec::with_capacity(shape.outer_query_count);
    for (query_ordinal, column_index) in query_indices.iter().copied().enumerate() {
        let reduction = polynomial_opening_reduction(
            coset_point(shape.encoded_column_count.ilog2() as usize, column_index)?,
            EXACT_TABLE_VARIABLE_COUNT,
        )?;
        let mut query_evaluations = [ChallengeField::ZERO; 3];
        for (point_ordinal, point_weights) in point_row_weights.iter().enumerate() {
            let phase_weights = [
                point_weights.base.as_slice(),
                point_weights.auxiliary.as_slice(),
                point_weights.quotient.as_slice(),
            ];
            let mut codeword_value = ChallengeField::ZERO;
            for (phase_ordinal, weights) in phase_weights.iter().enumerate() {
                let opened_values =
                    &proof.authenticated_phase_columns[phase_ordinal][query_ordinal].values;
                if opened_values.len() != weights.len() {
                    return Err("exact query opening does not match phase weights".to_owned());
                }
                codeword_value += opened_values
                    .iter()
                    .zip(*weights)
                    .fold(ChallengeField::ZERO, |sum, (value, weight)| {
                        sum + ChallengeField::from(*value) * *weight
                    });
            }
            query_evaluations[point_ordinal] =
                codeword_value * reduction.multilinear_to_polynomial_scale.inverse();
        }
        expected.push(query_evaluations);
    }
    Ok(expected)
}

#[cfg(test)]
fn accumulate_phase_query_whir_evaluations(
    shape: ExactProofShape,
    phase_index: usize,
    phase_columns: &[AuthenticatedColumn],
    query_indices: &[usize],
    point_row_weights: &[ExactPointRowWeights; 3],
    expected: &mut [[ChallengeField; 3]],
) -> Result<(), String> {
    if phase_columns.len() != shape.outer_query_count
        || query_indices.len() != shape.outer_query_count
        || expected.len() != shape.outer_query_count
    {
        return Err("exact query accumulator has the wrong fixed shape".to_owned());
    }
    for (query_ordinal, (column_index, opened_column)) in
        query_indices.iter().copied().zip(phase_columns).enumerate()
    {
        accumulate_phase_query_column_whir_evaluations(
            shape,
            phase_index,
            query_ordinal,
            column_index,
            &opened_column.values,
            point_row_weights,
            expected,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn accumulate_phase_query_column_whir_evaluations(
    shape: ExactProofShape,
    phase_index: usize,
    query_ordinal: usize,
    column_index: usize,
    opened_values: &[Goldilocks],
    point_row_weights: &[ExactPointRowWeights; 3],
    expected: &mut [[ChallengeField; 3]],
) -> Result<(), String> {
    if query_ordinal >= shape.outer_query_count || expected.len() != shape.outer_query_count {
        return Err("exact query accumulator has the wrong column ordinal".to_owned());
    }
    let reduction = polynomial_opening_reduction(
        coset_point(shape.encoded_column_count.ilog2() as usize, column_index)?,
        EXACT_TABLE_VARIABLE_COUNT,
    )?;
    for (point_ordinal, point_weights) in point_row_weights.iter().enumerate() {
        let phase_weights = match phase_index {
            0 => point_weights.base.as_slice(),
            1 => point_weights.auxiliary.as_slice(),
            2 => point_weights.quotient.as_slice(),
            _ => return Err("exact query phase index is outside the fixed shape".to_owned()),
        };
        if opened_values.len() != phase_weights.len() {
            return Err("exact query opening does not match phase weights".to_owned());
        }
        let codeword_value = opened_values
            .iter()
            .zip(phase_weights)
            .fold(ChallengeField::ZERO, |sum, (value, weight)| {
                sum + ChallengeField::from(*value) * *weight
            });
        expected[query_ordinal][point_ordinal] +=
            codeword_value * reduction.multilinear_to_polynomial_scale.inverse();
    }
    Ok(())
}

#[cfg(test)]
fn verify_whir_evaluation_claims(
    aggregate_opening_proof: &PlainAggregateProof,
    expected_out_of_domain: [ChallengeField; 3],
    expected_queries: &[[ChallengeField; 3]],
    expected_bound_reduction: &[ChallengeField],
    shape: ExactProofShape,
) -> Result<(), String> {
    let bound_reduction_evaluation_count = shape.bound_reduction_evaluation_count()?;
    let expected_evaluation_count = 3
        + shape.outer_query_count
        + bound_reduction_evaluation_count
        + EXACT_BOUND_DEGREE_TEST_COUNT;
    if aggregate_opening_proof.evals.len() != expected_evaluation_count
        || expected_queries.len() != shape.outer_query_count
        || expected_bound_reduction.len() != bound_reduction_evaluation_count
    {
        return Err("exact WHIR evaluation schedule has the wrong count".to_owned());
    }
    for (opening_ordinal, expected) in expected_out_of_domain.iter().enumerate() {
        let batch = &aggregate_opening_proof.evals[opening_ordinal];
        if batch.current() != [*expected] || !batch.next().is_empty() {
            return Err(format!(
                "exact WHIR out-of-domain opening {opening_ordinal} does not authenticate the production claims"
            ));
        }
    }
    for (query_ordinal, expected) in expected_queries.iter().enumerate() {
        let batch = &aggregate_opening_proof.evals[3 + query_ordinal];
        if batch.current() != expected || !batch.next().is_empty() {
            return Err(format!(
                "exact WHIR query opening {query_ordinal} does not match the authenticated phase columns"
            ));
        }
    }
    let bound_evaluation_offset = 3 + shape.outer_query_count;
    for (evaluation_ordinal, expected) in expected_bound_reduction.iter().enumerate() {
        let batch = &aggregate_opening_proof.evals[bound_evaluation_offset + evaluation_ordinal];
        if batch.current() != [*expected] || !batch.next().is_empty() {
            return Err(format!(
                "bound reduction opening {evaluation_ordinal} is not root-authenticated"
            ));
        }
    }
    let degree_test_offset = bound_evaluation_offset + bound_reduction_evaluation_count;
    for degree_test_ordinal in 0..EXACT_BOUND_DEGREE_TEST_COUNT {
        let batch = &aggregate_opening_proof.evals[degree_test_offset + degree_test_ordinal];
        if batch.current() != [ChallengeField::ZERO] || !batch.next().is_empty() {
            return Err(format!(
                "bound reduction degree test {degree_test_ordinal} is nonzero"
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactSameSecretVerificationMetrics {
    pub(crate) proof_byte_length: usize,
    #[cfg(test)]
    pub(crate) canonical_application_statement_byte_length: usize,
    #[cfg(test)]
    pub(crate) opening_claim_count: usize,
    pub(crate) query_count: usize,
    #[cfg(test)]
    pub(crate) maximum_resident_decoded_payload_byte_length: usize,
    #[cfg(test)]
    pub(crate) maximum_transcript_hash_query_count: u64,
    #[cfg(test)]
    pub(crate) logical_verifier_message_count: u64,
    #[cfg(test)]
    pub(crate) maximum_verifier_hash_query_count: u64,
    #[cfg(test)]
    pub(crate) maximum_accepting_database_equation_count: u64,
}

struct PreparedExactSameSecretRelation {
    verification_context: ExactSameSecretVerificationContext,
    verified_relation: VerifiedExactRelation,
    bound_tree_entries: Vec<ProofTreeCatalogEntry>,
    base_layout: ExactBasePhaseLayout,
    auxiliary_layout: ExactBasePhaseLayout,
    #[cfg(test)]
    canonical_application_statement_byte_length: usize,
}

fn prepare_exact_same_secret_relation(
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    verification_context: ExactSameSecretVerificationContext,
) -> Result<PreparedExactSameSecretRelation, String> {
    let verified_relation = validate_verification_context(prerequisite, &verification_context)?;
    let bound_tree_entries = exact_bound_tree_catalog_entries(&verified_relation)?;
    let base_layout =
        ExactBasePhaseLayout::for_tree_role(&verified_relation.variant, ProofTreeRole::BaseOracle)?;
    let auxiliary_layout = ExactBasePhaseLayout::for_tree_role(
        &verified_relation.variant,
        ProofTreeRole::AuxiliaryOracle,
    )?;
    #[cfg(test)]
    let canonical_application_statement_byte_length = verification_context
        .canonical_application_statement_bytes
        .len();
    Ok(PreparedExactSameSecretRelation {
        verification_context,
        verified_relation,
        bound_tree_entries,
        base_layout,
        auxiliary_layout,
        #[cfg(test)]
        canonical_application_statement_byte_length,
    })
}

struct ExactSameSecretIncrementalSemanticVerifier {
    prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    prepared_relation: PreparedExactSameSecretRelation,
    canonical_proof_byte_length: usize,
    verifier_accounting: ExactSameSecretVerifierAccounting,
    phase_roots: Option<[ColumnDigest; 3]>,
    opening_points: Vec<ProofChallengeExtensionElement>,
    point_row_weights: Option<[ExactPointRowWeights; 3]>,
    bound_claims: Vec<ExactBoundOpeningClaim>,
    challenger: Option<ExtensionFieldChallenger>,
    aggregate_commitment: Option<PlainAggregateCommitment>,
    query_indices: Vec<usize>,
    bound_query_indices: Option<ExactBoundQueryIndices>,
    bound_evaluation_domain: Option<ProofEvaluationDomain>,
    whir_points: Vec<Point<ChallengeField>>,
    expected_out_of_domain: Option<[ChallengeField; 3]>,
    expected_queries: Vec<[ChallengeField; 3]>,
    pending_phase_column_digests: [Vec<(usize, ColumnDigest)>; 3],
    pending_phase_expected_queries: [Vec<[ChallengeField; 3]>; 3],
    next_phase_column_indices: [usize; 3],
    expected_bound_reduction: Vec<ChallengeField>,
    pending_bound_leaf_digests: Vec<(u64, [u8; 64])>,
    pending_bound_reduction_delta: Vec<ChallengeField>,
    consumed_phase_count: usize,
    consumed_bound_tree_count: usize,
}

impl ExactSameSecretIncrementalSemanticVerifier {
    fn new(
        prerequisite: VerifiedSameSecretLowDegreePrerequisite,
        prepared_relation: PreparedExactSameSecretRelation,
        canonical_proof_byte_length: usize,
    ) -> Result<Self, String> {
        let verifier_accounting = exact_same_secret_verifier_accounting(
            &prepared_relation
                .verified_relation
                .row_code_whir_construction_plan,
            prepared_relation.verified_relation.proof_shape,
        )?;
        Ok(Self {
            prerequisite,
            prepared_relation,
            canonical_proof_byte_length,
            verifier_accounting,
            phase_roots: None,
            opening_points: Vec::new(),
            point_row_weights: None,
            bound_claims: Vec::new(),
            challenger: None,
            aggregate_commitment: None,
            query_indices: Vec::new(),
            bound_query_indices: None,
            bound_evaluation_domain: None,
            whir_points: Vec::new(),
            expected_out_of_domain: None,
            expected_queries: Vec::new(),
            pending_phase_column_digests: std::array::from_fn(|_| Vec::new()),
            pending_phase_expected_queries: std::array::from_fn(|_| Vec::new()),
            next_phase_column_indices: [0; 3],
            expected_bound_reduction: Vec::new(),
            pending_bound_leaf_digests: Vec::new(),
            pending_bound_reduction_delta: Vec::new(),
            consumed_phase_count: 0,
            consumed_bound_tree_count: 0,
        })
    }

    fn resident_accumulator_payload_byte_length(&self) -> usize {
        let mut byte_length = self
            .opening_points
            .capacity()
            .saturating_mul(core::mem::size_of::<ProofChallengeExtensionElement>())
            .saturating_add(
                self.bound_claims
                    .capacity()
                    .saturating_mul(core::mem::size_of::<ExactBoundOpeningClaim>()),
            )
            .saturating_add(
                self.query_indices
                    .capacity()
                    .saturating_mul(core::mem::size_of::<usize>()),
            )
            .saturating_add(
                self.expected_queries
                    .capacity()
                    .saturating_mul(core::mem::size_of::<[ChallengeField; 3]>()),
            )
            .saturating_add(
                self.expected_bound_reduction
                    .capacity()
                    .saturating_mul(core::mem::size_of::<ChallengeField>()),
            )
            .saturating_add(
                self.pending_bound_leaf_digests
                    .capacity()
                    .saturating_mul(core::mem::size_of::<(u64, [u8; 64])>()),
            )
            .saturating_add(
                self.pending_bound_reduction_delta
                    .capacity()
                    .saturating_mul(core::mem::size_of::<ChallengeField>()),
            );
        for digests in &self.pending_phase_column_digests {
            byte_length = byte_length.saturating_add(
                digests
                    .capacity()
                    .saturating_mul(core::mem::size_of::<(usize, ColumnDigest)>()),
            );
        }
        for evaluations in &self.pending_phase_expected_queries {
            byte_length = byte_length.saturating_add(
                evaluations
                    .capacity()
                    .saturating_mul(core::mem::size_of::<[ChallengeField; 3]>()),
            );
        }
        if let Some(bound_query_indices) = &self.bound_query_indices {
            byte_length = byte_length.saturating_add(
                [
                    bound_query_indices.accepted_input_root_indices.capacity(),
                    bound_query_indices.accepted_output_root_indices.capacity(),
                    bound_query_indices.input_root_traversal_indices.capacity(),
                    bound_query_indices.output_root_traversal_indices.capacity(),
                ]
                .into_iter()
                .sum::<usize>()
                .saturating_mul(core::mem::size_of::<usize>()),
            );
        }
        for point in &self.whir_points {
            byte_length = byte_length.saturating_add(
                point
                    .as_slice()
                    .len()
                    .saturating_mul(core::mem::size_of::<ChallengeField>()),
            );
        }
        byte_length
    }

    fn consume_transcript_material(
        &mut self,
        base_root: ColumnDigest,
        auxiliary_root: ColumnDigest,
        quotient_root: ColumnDigest,
        out_of_domain_evaluations: Vec<ProofChallengeExtensionElement>,
        opening_batch_mask_chunk_evaluations: [ProofChallengeExtensionElement;
            EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
    ) -> Result<(), String> {
        if self.phase_roots.is_some()
            || self.challenger.is_some()
            || !self.opening_points.is_empty()
        {
            return Err("exact transcript material was supplied more than once".to_owned());
        }
        let verified_relation = &mut self.prepared_relation.verified_relation;
        let mut transcript_prefix = exact_transcript_prefix(
            &self.prerequisite,
            &self.prepared_relation.verification_context,
            verified_relation,
            base_root,
            auxiliary_root,
            quotient_root,
        )?;
        verify_production_out_of_domain_composition(
            verified_relation,
            &transcript_prefix,
            &out_of_domain_evaluations,
        )?;
        verify_opening_batch_mask_chunk_evaluations(
            &verified_relation.variant,
            &transcript_prefix.opening_points,
            &out_of_domain_evaluations,
            &opening_batch_mask_chunk_evaluations,
        )?;
        let row_code_whir_transcript = finish_exact_transcript(
            &mut transcript_prefix,
            &out_of_domain_evaluations,
            &opening_batch_mask_chunk_evaluations,
        )?;
        let construction_plan = &verified_relation.row_code_whir_construction_plan;
        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
        let mut challenger = plain_aggregate_challenger_from_transcript(
            &pcs,
            construction_plan.whir_plan(),
            row_code_whir_transcript,
        )?;
        let point_row_weights = derive_exact_point_row_weights(
            &mut challenger,
            &self.prepared_relation.base_layout,
            &self.prepared_relation.auxiliary_layout,
            transcript_prefix.opening_points[0],
        )?;
        let bound_claims = derive_bound_opening_claims(
            &verified_relation.variant,
            &transcript_prefix.opening_points,
            &out_of_domain_evaluations,
            &mut challenger,
        )?;
        ensure_bound_opening_points_are_outside_evaluation_domain(
            &bound_claims,
            verified_relation.variant.evaluation_domain_size(),
            verified_relation.context.evaluation_coset_offset,
        )?;
        let expected_out_of_domain = expected_out_of_domain_whir_evaluations(
            &verified_relation.variant,
            &self.prepared_relation.base_layout,
            &self.prepared_relation.auxiliary_layout,
            &transcript_prefix.opening_points,
            &out_of_domain_evaluations,
            &opening_batch_mask_chunk_evaluations,
            &point_row_weights,
        )?;
        self.phase_roots = Some([base_root, auxiliary_root, quotient_root]);
        self.opening_points = transcript_prefix.opening_points;
        self.point_row_weights = Some(point_row_weights);
        self.bound_claims = bound_claims;
        self.challenger = Some(challenger);
        self.expected_out_of_domain = Some(expected_out_of_domain);
        Ok(())
    }

    fn consume_aggregate_commitment(
        &mut self,
        aggregate_commitment: PlainAggregateCommitment,
    ) -> Result<(), String> {
        if self.phase_roots.is_none() || self.aggregate_commitment.is_some() {
            return Err("exact aggregate commitment is out of order".to_owned());
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let challenger = self
            .challenger
            .as_mut()
            .ok_or_else(|| "exact aggregate commitment precedes transcript material".to_owned())?;
        challenger.observe(aggregate_commitment.clone());
        let query_indices = derive_query_indices(challenger, shape)?;
        let bound_query_indices = derive_bound_query_indices(challenger, shape)?;
        let degree_test_points = bound_degree_test_points(challenger)?;
        let bound_evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(
                self.prepared_relation
                    .verified_relation
                    .variant
                    .evaluation_domain_size(),
            )
            .map_err(|_| "bound evaluation domain exceeds usize".to_owned())?,
            self.prepared_relation
                .verified_relation
                .context
                .evaluation_coset_offset,
        )
        .map_err(|error| format!("construct bound evaluation domain: {error:?}"))?;
        if bound_evaluation_domain.generator().canonical()
            != self
                .prepared_relation
                .verified_relation
                .context
                .evaluation_domain_generator
        {
            return Err("bound evaluation domain has the wrong generator".to_owned());
        }
        let whir_points = exact_whir_opening_points(
            &self.opening_points,
            self.point_row_weights
                .as_ref()
                .ok_or_else(|| "exact point-row weights are absent".to_owned())?,
            &query_indices,
            &bound_query_indices,
            bound_evaluation_domain,
            &degree_test_points,
            shape,
        )?;
        let mut expected_queries = Vec::new();
        expected_queries
            .try_reserve_exact(shape.outer_query_count)
            .map_err(|_| "exact query accumulator allocation failed".to_owned())?;
        expected_queries.resize(shape.outer_query_count, [ChallengeField::ZERO; 3]);
        for (phase_column_digests, pending_phase_expected_queries) in self
            .pending_phase_column_digests
            .iter_mut()
            .zip(&mut self.pending_phase_expected_queries)
        {
            phase_column_digests
                .try_reserve_exact(shape.outer_query_count)
                .map_err(|_| "exact phase-digest allocation failed".to_owned())?;
            pending_phase_expected_queries
                .try_reserve_exact(shape.outer_query_count)
                .map_err(|_| "exact pending query accumulator allocation failed".to_owned())?;
            pending_phase_expected_queries
                .resize(shape.outer_query_count, [ChallengeField::ZERO; 3]);
        }
        let bound_reduction_evaluation_count = shape.bound_reduction_evaluation_count()?;
        let mut expected_bound_reduction = Vec::new();
        expected_bound_reduction
            .try_reserve_exact(bound_reduction_evaluation_count)
            .map_err(|_| "bound reduction accumulator allocation failed".to_owned())?;
        expected_bound_reduction.resize(bound_reduction_evaluation_count, ChallengeField::ZERO);
        self.aggregate_commitment = Some(aggregate_commitment);
        self.query_indices = query_indices;
        self.bound_query_indices = Some(bound_query_indices);
        self.bound_evaluation_domain = Some(bound_evaluation_domain);
        self.whir_points = whir_points;
        self.expected_queries = expected_queries;
        self.expected_bound_reduction = expected_bound_reduction;
        Ok(())
    }

    fn consume_phase_column(
        &mut self,
        phase_index: usize,
        column_index: usize,
        values: Vec<Goldilocks>,
    ) -> Result<(), String> {
        if phase_index >= self.next_phase_column_indices.len()
            || column_index != self.next_phase_column_indices[phase_index]
            || self.aggregate_commitment.is_none()
        {
            return Err("exact authenticated phase column is out of order".to_owned());
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let expected_row_count = *shape
            .phase_row_counts()
            .get(phase_index)
            .ok_or_else(|| "exact phase index is outside the fixed shape".to_owned())?;
        if values.len() != expected_row_count || column_index >= shape.outer_query_count {
            return Err("exact authenticated phase column has the wrong shape".to_owned());
        }
        let authenticated_column_index = *self
            .query_indices
            .get(column_index)
            .ok_or_else(|| "exact phase column has no derived query index".to_owned())?;
        let digest = hash_opened_column(&values, shape.encoded_column_count);
        self.pending_phase_column_digests[phase_index].push((authenticated_column_index, digest));
        accumulate_phase_query_column_whir_evaluations(
            shape,
            phase_index,
            column_index,
            authenticated_column_index,
            &values,
            self.point_row_weights
                .as_ref()
                .ok_or_else(|| "exact point-row weights are absent".to_owned())?,
            &mut self.pending_phase_expected_queries[phase_index],
        )?;
        self.next_phase_column_indices[phase_index] += 1;
        Ok(())
    }

    fn consume_phase_frontier(
        &mut self,
        phase_index: usize,
        frontier: Vec<ColumnDigest>,
    ) -> Result<(), String> {
        if phase_index != self.consumed_phase_count
            || self.next_phase_column_indices.get(phase_index).copied()
                != Some(
                    self.prepared_relation
                        .verified_relation
                        .proof_shape
                        .outer_query_count,
                )
        {
            return Err("exact authenticated phase frontier is out of order".to_owned());
        }
        let root = *self
            .phase_roots
            .as_ref()
            .and_then(|roots| roots.get(phase_index))
            .ok_or_else(|| "exact authenticated phase root is absent".to_owned())?;
        let shape = self.prepared_relation.verified_relation.proof_shape;
        verify_prehashed_column_frontier(
            &root,
            shape.encoded_column_count,
            &self.pending_phase_column_digests[phase_index],
            &frontier,
        )?;
        for (accepted, pending) in self
            .expected_queries
            .iter_mut()
            .zip(&self.pending_phase_expected_queries[phase_index])
        {
            for point_ordinal in 0..accepted.len() {
                accepted[point_ordinal] += pending[point_ordinal];
            }
        }
        self.pending_phase_column_digests[phase_index] = Vec::new();
        self.pending_phase_expected_queries[phase_index] = Vec::new();
        self.consumed_phase_count += 1;
        Ok(())
    }

    fn consume_bound_leaf(
        &mut self,
        bound_tree_ordinal: usize,
        query_ordinal: usize,
        opening: ExactBoundLeafOpening,
    ) -> Result<(), String> {
        if self.consumed_phase_count != 3
            || bound_tree_ordinal != self.consumed_bound_tree_count
            || query_ordinal != self.pending_bound_leaf_digests.len()
        {
            return Err("exact bound leaf is out of order".to_owned());
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let tree_query_indices = self
            .bound_query_indices
            .as_ref()
            .ok_or_else(|| "exact bound query schedule is absent".to_owned())?
            .traversal_indices_for_tree_ordinal(shape, bound_tree_ordinal)?;
        let leaf_index = *tree_query_indices
            .get(query_ordinal)
            .ok_or_else(|| "exact bound leaf has no derived query index".to_owned())?;
        let accepted_query_ordinal = self
            .bound_query_indices
            .as_ref()
            .ok_or_else(|| "exact bound query schedule is absent".to_owned())?
            .accepted_query_ordinal_for_tree(bound_tree_ordinal, leaf_index)?;
        let entry = self
            .prepared_relation
            .bound_tree_entries
            .get(bound_tree_ordinal)
            .ok_or_else(|| "exact bound tree entry is absent".to_owned())?;
        if opening.persistent_salt.is_some() != entry.requires_persistent_leaf_salt() {
            return Err("exact bound leaf has the wrong salt shape".to_owned());
        }
        let leaf_index_u64 =
            u64::try_from(leaf_index).map_err(|_| "bound leaf index exceeds u64".to_owned())?;
        let (_, leaf_digest) = entry
            .encode_materialized_leaf(
                leaf_index_u64,
                opening.persistent_salt,
                Zeroizing::new(
                    opening
                        .first_point_values
                        .iter()
                        .copied()
                        .map(ProofTreeValue::Base)
                        .collect(),
                ),
                Zeroizing::new(
                    opening
                        .opposite_point_values
                        .iter()
                        .copied()
                        .map(ProofTreeValue::Base)
                        .collect(),
                ),
            )
            .map_err(|error| format!("encode bound leaf: {error:?}"))?;
        if self.pending_bound_reduction_delta.is_empty() {
            let bound_reduction_evaluation_count = shape.bound_reduction_evaluation_count()?;
            self.pending_bound_reduction_delta
                .try_reserve_exact(bound_reduction_evaluation_count)
                .map_err(|_| "exact bound reduction delta allocation failed".to_owned())?;
            self.pending_bound_reduction_delta
                .resize(bound_reduction_evaluation_count, ChallengeField::ZERO);
        }
        accumulate_bound_leaf_reduction_whir_evaluations(
            &self.prepared_relation.verified_relation.variant,
            &opening,
            bound_tree_ordinal,
            accepted_query_ordinal,
            leaf_index,
            self.bound_evaluation_domain
                .ok_or_else(|| "exact bound evaluation domain is absent".to_owned())?,
            &self.bound_claims,
            shape,
            &mut self.pending_bound_reduction_delta,
        )?;
        self.pending_bound_leaf_digests
            .push((leaf_index_u64, leaf_digest));
        Ok(())
    }

    fn consume_bound_frontier(
        &mut self,
        bound_tree_ordinal: usize,
        frontier: Vec<[u8; 64]>,
    ) -> Result<(), String> {
        if bound_tree_ordinal != self.consumed_bound_tree_count {
            return Err("exact bound frontier is out of order".to_owned());
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let expected_query_count = self
            .bound_query_indices
            .as_ref()
            .ok_or_else(|| "exact bound query schedule is absent".to_owned())?
            .traversal_indices_for_tree_ordinal(shape, bound_tree_ordinal)?
            .len();
        let entry = self
            .prepared_relation
            .bound_tree_entries
            .get(bound_tree_ordinal)
            .ok_or_else(|| "exact bound tree entry is absent".to_owned())?;
        verify_materialized_frontier(
            entry,
            &self.pending_bound_leaf_digests,
            &frontier,
            expected_query_count,
        )?;
        if self.pending_bound_reduction_delta.len() != self.expected_bound_reduction.len() {
            return Err("exact bound reduction delta has the wrong shape".to_owned());
        }
        for (accepted, pending) in self
            .expected_bound_reduction
            .iter_mut()
            .zip(&self.pending_bound_reduction_delta)
        {
            *accepted += *pending;
        }
        self.pending_bound_leaf_digests = Vec::new();
        self.pending_bound_reduction_delta = Vec::new();
        self.consumed_bound_tree_count += 1;
        Ok(())
    }

    fn prepare_plain_whir_verification(
        &mut self,
        pcs: &super::super::plain_whir::PlainAggregatePcs,
    ) -> Result<PlainAggregateIncrementalVerificationPreparation, String> {
        if self.consumed_phase_count != 3
            || self.consumed_bound_tree_count != EXACT_BOUND_TREE_COUNT
        {
            return Err(
                "exact semantic verification reached plain WHIR before all authenticated sections"
                    .to_owned(),
            );
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let expected_out_of_domain = self
            .expected_out_of_domain
            .take()
            .ok_or_else(|| "exact out-of-domain accumulator is absent".to_owned())?;
        let expected_queries = std::mem::take(&mut self.expected_queries);
        let expected_bound_reduction = std::mem::take(&mut self.expected_bound_reduction);
        let bound_reduction_evaluation_count = shape.bound_reduction_evaluation_count()?;
        if expected_queries.len() != shape.outer_query_count
            || expected_bound_reduction.len() != bound_reduction_evaluation_count
        {
            return Err("exact WHIR evaluation schedule has the wrong count".to_owned());
        }
        let expected_evaluation_count = 3_usize
            .checked_add(shape.outer_query_count)
            .and_then(|count| count.checked_add(bound_reduction_evaluation_count))
            .and_then(|count| count.checked_add(EXACT_BOUND_DEGREE_TEST_COUNT))
            .ok_or_else(|| "exact WHIR evaluation count overflowed".to_owned())?;
        let mut expected_opening_evaluations = Vec::new();
        expected_opening_evaluations
            .try_reserve_exact(expected_evaluation_count)
            .map_err(|_| "exact WHIR expected-opening allocation failed".to_owned())?;
        expected_opening_evaluations.extend(
            expected_out_of_domain
                .into_iter()
                .map(|evaluation| vec![evaluation]),
        );
        expected_opening_evaluations.extend(
            expected_queries
                .into_iter()
                .map(|evaluations| evaluations.to_vec()),
        );
        expected_opening_evaluations.extend(
            expected_bound_reduction
                .into_iter()
                .map(|evaluation| vec![evaluation]),
        );
        expected_opening_evaluations
            .extend((0..EXACT_BOUND_DEGREE_TEST_COUNT).map(|_| vec![ChallengeField::ZERO]));
        let commitment = self
            .aggregate_commitment
            .take()
            .ok_or_else(|| "exact aggregate commitment is absent".to_owned())?;
        let points = std::mem::take(&mut self.whir_points);
        let challenger = self
            .challenger
            .take()
            .ok_or_else(|| "exact WHIR challenger is absent".to_owned())?;
        PlainAggregateIncrementalVerificationPreparation::new(
            pcs,
            commitment,
            points,
            &self
                .prepared_relation
                .verified_relation
                .row_code_whir_construction_plan,
            expected_opening_evaluations,
            challenger,
        )
    }

    fn finish_plain_whir(
        self,
        challenger: ExtensionFieldChallenger,
        _maximum_resident_decoded_payload_byte_length: usize,
    ) -> Result<ExactSameSecretFinalProofVerification, String> {
        if self.consumed_phase_count != 3
            || self.consumed_bound_tree_count != EXACT_BOUND_TREE_COUNT
        {
            return Err(
                "exact semantic verification ended before all authenticated sections".to_owned(),
            );
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let absorber = challenger.begin_final_proof_stream(self.canonical_proof_byte_length)?;
        Ok(ExactSameSecretFinalProofVerification {
            absorber,
            absorbed_byte_length: 0,
            proof_byte_length: self.canonical_proof_byte_length,
            #[cfg(test)]
            canonical_application_statement_byte_length: self
                .prepared_relation
                .canonical_application_statement_byte_length,
            #[cfg(test)]
            opening_claim_count: shape.opening_claim_count,
            query_count: shape.outer_query_count,
            #[cfg(test)]
            maximum_resident_decoded_payload_byte_length:
                _maximum_resident_decoded_payload_byte_length,
            verifier_accounting: self.verifier_accounting,
        })
    }
}

pub(crate) struct ExactSameSecretIncrementalVerification {
    header_comparator: IncrementalExpectedProofObjectHeaderComparator,
    decoder: ExactSameSecretIncrementalDecoder,
    declared_complete_proof_byte_length: usize,
}

impl ExactSameSecretIncrementalVerification {
    pub(super) fn new(
        prerequisite: VerifiedSameSecretLowDegreePrerequisite,
        verification_context: ExactSameSecretVerificationContext,
        header_comparator: IncrementalExpectedProofObjectHeaderComparator,
    ) -> Result<Self, String> {
        let declared_complete_proof_byte_length =
            header_comparator.declared_complete_proof_byte_length();
        let family_body_byte_length = header_comparator.family_body_byte_length();
        let prepared_relation =
            prepare_exact_same_secret_relation(&prerequisite, verification_context)?;
        let construction_plan = &prepared_relation
            .verified_relation
            .row_code_whir_construction_plan;
        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
        let mut decoder = ExactSameSecretIncrementalDecoder::new(
            construction_plan,
            prepared_relation.verified_relation.proof_shape,
            &prepared_relation.bound_tree_entries,
            pcs,
            expected_opening_widths(construction_plan),
            family_body_byte_length,
        )?;
        decoder.install_semantic_verifier(ExactSameSecretIncrementalSemanticVerifier::new(
            prerequisite,
            prepared_relation,
            declared_complete_proof_byte_length,
        )?)?;
        Ok(Self {
            header_comparator,
            decoder,
            declared_complete_proof_byte_length,
        })
    }

    pub(crate) fn decoded_byte_length(&self) -> usize {
        if !self.header_comparator.is_complete() {
            return self.header_comparator.compared_header_byte_length();
        }
        self.header_comparator
            .expected_header_byte_length()
            .checked_add(self.decoder.offset)
            .unwrap_or(self.declared_complete_proof_byte_length)
    }

    pub(crate) fn is_decoding_complete(&self) -> bool {
        self.header_comparator.is_complete() && self.decoder.is_complete()
    }

    pub(crate) fn consume_available<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<(), String> {
        self.header_comparator
            .compare_available(source, available_end_offset)
            .map_err(|error| format!("compare canonical proof-object header: {error:?}"))?;
        if !self.header_comparator.is_complete() {
            return Ok(());
        }
        let header_byte_length = self.header_comparator.expected_header_byte_length();
        let body_available_end_offset = available_end_offset
            .checked_sub(header_byte_length)
            .ok_or_else(|| "exact proof body availability precedes its header".to_owned())?;
        let body_source = self
            .header_comparator
            .body_source(source)
            .map_err(|error| format!("construct exact family-body source: {error:?}"))?;
        self.decoder
            .consume_available(&body_source, body_available_end_offset)
    }

    pub(crate) fn finish_decoding(self) -> Result<ExactSameSecretFinalProofVerification, String> {
        let Self {
            header_comparator,
            decoder,
            declared_complete_proof_byte_length,
        } = self;
        if !header_comparator.is_complete() {
            return Err("exact proof-object header is incomplete".to_owned());
        }
        if declared_complete_proof_byte_length
            != header_comparator.declared_complete_proof_byte_length()
        {
            return Err("exact proof-object length changed during verification".to_owned());
        }
        decoder.finish_semantic()
    }
}

pub(crate) struct ExactSameSecretFinalProofVerification {
    absorber: RowCodeWhirChallengerProofStreamAbsorber,
    absorbed_byte_length: usize,
    proof_byte_length: usize,
    #[cfg(test)]
    canonical_application_statement_byte_length: usize,
    #[cfg(test)]
    opening_claim_count: usize,
    query_count: usize,
    #[cfg(test)]
    maximum_resident_decoded_payload_byte_length: usize,
    verifier_accounting: ExactSameSecretVerifierAccounting,
}

impl ExactSameSecretFinalProofVerification {
    pub(crate) const fn absorbed_byte_length(&self) -> usize {
        self.absorbed_byte_length
    }

    pub(crate) fn absorb(&mut self, canonical_proof_byte_chunk: &[u8]) -> Result<(), String> {
        let following_byte_length = self
            .absorbed_byte_length
            .checked_add(canonical_proof_byte_chunk.len())
            .ok_or_else(|| "exact final proof-stream length overflowed".to_owned())?;
        if following_byte_length > self.proof_byte_length {
            return Err("exact final proof stream exceeds its authenticated length".to_owned());
        }
        self.absorber.absorb(canonical_proof_byte_chunk)?;
        self.absorbed_byte_length = following_byte_length;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<ExactSameSecretVerificationMetrics, String> {
        if self.absorbed_byte_length != self.proof_byte_length {
            return Err(
                "exact final proof stream ended before its authenticated length".to_owned(),
            );
        }
        let transcript_summary = self.absorber.finish()?;
        if transcript_summary.maximum_hash_query_count()
            != self.verifier_accounting.maximum_transcript_hash_query_count
            || transcript_summary.logical_verifier_message_count()
                != self.verifier_accounting.logical_verifier_message_count
            || self.verifier_accounting.maximum_verifier_hash_query_count
                < self.verifier_accounting.maximum_transcript_hash_query_count
            || self
                .verifier_accounting
                .maximum_accepting_database_equation_count
                > self.verifier_accounting.maximum_verifier_hash_query_count
        {
            return Err(
                "exact transcript execution diverges from the checked oracle-equation catalog"
                    .to_owned(),
            );
        }
        Ok(ExactSameSecretVerificationMetrics {
            proof_byte_length: self.proof_byte_length,
            #[cfg(test)]
            canonical_application_statement_byte_length: self
                .canonical_application_statement_byte_length,
            #[cfg(test)]
            opening_claim_count: self.opening_claim_count,
            query_count: self.query_count,
            #[cfg(test)]
            maximum_resident_decoded_payload_byte_length: self
                .maximum_resident_decoded_payload_byte_length,
            #[cfg(test)]
            maximum_transcript_hash_query_count: self
                .verifier_accounting
                .maximum_transcript_hash_query_count,
            #[cfg(test)]
            logical_verifier_message_count: self.verifier_accounting.logical_verifier_message_count,
            #[cfg(test)]
            maximum_verifier_hash_query_count: self
                .verifier_accounting
                .maximum_verifier_hash_query_count,
            #[cfg(test)]
            maximum_accepting_database_equation_count: self
                .verifier_accounting
                .maximum_accepting_database_equation_count,
        })
    }
}

#[cfg(test)]
fn verify_exact_same_secret_proof_bytes(
    prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    verification_context: &ExactSameSecretVerificationContext,
    canonical_proof_object: &[u8],
) -> Result<ExactSameSecretVerificationMetrics, String> {
    let mut header_comparator = IncrementalExpectedProofObjectHeaderComparator::new(
        verification_context
            .canonical_proof_object_header_bytes
            .clone(),
        canonical_proof_object.len(),
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    )
    .map_err(|error| format!("validate exact proof-object framing: {error:?}"))?;
    header_comparator
        .compare_available(canonical_proof_object, canonical_proof_object.len())
        .map_err(|error| format!("compare exact proof-object header: {error:?}"))?;
    let body_source = header_comparator
        .body_source(canonical_proof_object)
        .map_err(|error| format!("construct exact family-body source: {error:?}"))?;
    let prepared_relation =
        prepare_exact_same_secret_relation(&prerequisite, verification_context.clone())?;
    let construction_plan = &prepared_relation
        .verified_relation
        .row_code_whir_construction_plan;
    let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
    let mut decoder = ExactSameSecretIncrementalDecoder::new(
        construction_plan,
        prepared_relation.verified_relation.proof_shape,
        &prepared_relation.bound_tree_entries,
        pcs,
        expected_opening_widths(construction_plan),
        header_comparator.family_body_byte_length(),
    )?;
    decoder.install_semantic_verifier(ExactSameSecretIncrementalSemanticVerifier::new(
        prerequisite,
        prepared_relation,
        canonical_proof_object.len(),
    )?)?;
    decoder.consume_available(&body_source, body_source.byte_length())?;
    let mut final_proof_verification = decoder.finish_semantic()?;
    final_proof_verification.absorb(canonical_proof_object)?;
    final_proof_verification.finish()
}

#[cfg(test)]
fn encode_exact_same_secret_proof(
    construction_plan: &RowCodeWhirConstructionPlan,
    shape: ExactProofShape,
    bound_tree_entries: &[ProofTreeCatalogEntry],
    proof: &ExactSameSecretProof,
) -> Result<Vec<u8>, String> {
    use crate::bgv::proof_suite::prover::BoundedCommonProofByteSink;

    let construction_plan_identity_hash = construction_plan
        .canonical_identity_hash()
        .map_err(|error| format!("derive exact construction-plan identity: {error:?}"))?;
    let mut encoder = ExactSameSecretProofSinkEncoder::new(
        construction_plan,
        ExactSameSecretProofShape {
            shape,
            construction_plan_identity_hash,
        },
        bound_tree_entries,
        proof.clone(),
    )?;
    let expected_byte_length = encoder.canonical_byte_length();
    let mut sink = BoundedCommonProofByteSink::new(expected_byte_length)
        .map_err(|error| format!("allocate exact proof test sink: {error:?}"))?;
    match encoder.write_available(&mut sink) {
        Ok(ExactSameSecretProofEncodingProgress::Complete {
            canonical_byte_length,
        }) if canonical_byte_length == expected_byte_length => Ok(sink.finish()),
        Ok(ExactSameSecretProofEncodingProgress::Complete {
            canonical_byte_length,
        }) => Err(format!(
            "exact proof encoder completed at {canonical_byte_length} bytes, expected {expected_byte_length}"
        )),
        Ok(ExactSameSecretProofEncodingProgress::Pending) => {
            Err("exact proof test sink unexpectedly remained pending".to_owned())
        }
        Err(ExactSameSecretProofSinkEncodingError::InvalidProof(error)) => Err(error),
        Err(ExactSameSecretProofSinkEncodingError::Sink(error)) => {
            Err(format!("write exact proof test sink: {error:?}"))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) enum ExactSameSecretProofEncodingProgress {
    Pending,
    Complete { canonical_byte_length: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) enum ExactSameSecretProofSinkEncodingError<SinkError>
{
    InvalidProof(String),
    Sink(SinkError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactSameSecretProofSinkEncodingPhase {
    Magic,
    BaseRoot,
    AuxiliaryRoot,
    QuotientRoot,
    OutOfDomainEvaluationCount,
    OutOfDomainEvaluation {
        evaluation_index: usize,
    },
    OpeningMaskEvaluation {
        evaluation_index: usize,
    },
    AggregateRoot,
    PhaseValue {
        phase_index: usize,
        column_index: usize,
        row_index: usize,
    },
    PhaseFrontierCount {
        phase_index: usize,
    },
    PhaseFrontierNode {
        phase_index: usize,
        node_index: usize,
    },
    BoundLeafSalt {
        tree_index: usize,
        query_index: usize,
    },
    BoundLeafFirstValue {
        tree_index: usize,
        query_index: usize,
        value_index: usize,
    },
    BoundLeafOppositeValue {
        tree_index: usize,
        query_index: usize,
        value_index: usize,
    },
    BoundFrontierCount {
        tree_index: usize,
    },
    BoundFrontierNode {
        tree_index: usize,
        node_index: usize,
    },
    PlainWhir,
    Complete,
}

#[derive(Clone, Debug)]
struct ExactProofSectionCursor {
    sections: Vec<RowCodeWhirProofSectionPlan>,
    next_section_index: usize,
}

impl ExactProofSectionCursor {
    fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        shape: ExactProofShape,
        bound_tree_count: usize,
    ) -> Result<Self, String> {
        let mut cursor = Self {
            sections: construction_plan.proof_sections().to_vec(),
            next_section_index: 0,
        };
        for phase in exact_phase_order() {
            cursor.consume(RowCodeWhirProofSectionRole::RelationCommitment { phase }, 1)?;
        }
        cursor.consume(
            RowCodeWhirProofSectionRole::OutOfDomainEvaluations,
            shape.opening_claim_count,
        )?;
        cursor.consume(
            RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations,
            EXACT_OPENING_BATCH_MASK_CHUNK_COUNT,
        )?;
        cursor.consume(RowCodeWhirProofSectionRole::AggregateCommitment, 1)?;
        for phase in exact_phase_order() {
            cursor.consume(
                RowCodeWhirProofSectionRole::PhaseOpenings { phase },
                shape.outer_query_count,
            )?;
        }
        for bound_tree_index in 0..bound_tree_count {
            cursor.consume(
                RowCodeWhirProofSectionRole::BoundTreeOpenings {
                    bound_tree_ordinal: u32::try_from(bound_tree_index)
                        .map_err(|_| "exact bound-tree ordinal exceeds u32".to_owned())?,
                },
                shape.bound_tree_query_count(bound_tree_index)?,
            )?;
        }
        cursor.consume(RowCodeWhirProofSectionRole::PlainWhir, 1)?;
        cursor.ensure_complete()?;
        cursor.next_section_index = 0;
        Ok(cursor)
    }

    fn consume(
        &mut self,
        expected_role: RowCodeWhirProofSectionRole,
        expected_item_count: usize,
    ) -> Result<(), String> {
        let section = self
            .sections
            .get(self.next_section_index)
            .copied()
            .ok_or_else(|| "exact proof has no remaining construction-plan section".to_owned())?;
        let expected_section_ordinal = u32::try_from(self.next_section_index)
            .map_err(|_| "exact proof section ordinal exceeds u32".to_owned())?;
        if section.section_ordinal != expected_section_ordinal
            || section.role != expected_role
            || section.item_count != expected_item_count
        {
            return Err(format!(
                "exact proof section {} diverges from the checked construction plan",
                self.next_section_index
            ));
        }
        self.next_section_index = self
            .next_section_index
            .checked_add(1)
            .ok_or_else(|| "exact proof section cursor overflowed".to_owned())?;
        Ok(())
    }

    fn ensure_complete(&self) -> Result<(), String> {
        if self.next_section_index != self.sections.len() {
            return Err("exact proof omitted a checked construction-plan section".to_owned());
        }
        Ok(())
    }
}

const fn exact_phase_order() -> [RowCodeWhirPhase; 3] {
    [
        RowCodeWhirPhase::Base,
        RowCodeWhirPhase::Auxiliary,
        RowCodeWhirPhase::Quotient,
    ]
}

fn exact_phase_at(phase_index: usize) -> Result<RowCodeWhirPhase, String> {
    exact_phase_order()
        .get(phase_index)
        .copied()
        .ok_or_else(|| "exact phase index is outside the construction plan".to_owned())
}

/// Stateful canonical encoder for the production exact same-secret proof.
///
/// A sink may accept only a prefix of one write before reporting that durable
/// browser work is required. The encoder therefore owns the immutable proof
/// and advances its cursor only after the sink accepts the complete current
/// write. Retrying after a sink yield reproduces the identical byte slice.
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretProofSinkEncoder {
    proof: ExactSameSecretProof,
    proof_section_cursor: ExactProofSectionCursor,
    phase: ExactSameSecretProofSinkEncodingPhase,
    written_prefix_byte_length: usize,
    canonical_prefix_byte_length: usize,
    canonical_byte_length: usize,
    plain_whir_encoder: PlainWhirWireSinkEncoder,
}

impl ExactSameSecretProofSinkEncoder {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        checked_shape: ExactSameSecretProofShape,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        proof: ExactSameSecretProof,
    ) -> Result<Self, String> {
        let construction_plan_identity_hash = construction_plan
            .canonical_identity_hash()
            .map_err(|error| format!("derive exact construction-plan identity: {error:?}"))?;
        if checked_shape.construction_plan_identity_hash != construction_plan_identity_hash {
            return Err(
                "exact proof shape is bound to a different construction-plan identity".to_owned(),
            );
        }
        validate_exact_proof_shape(checked_shape.shape, bound_tree_entries, &proof)?;
        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
        let plain_whir_encoder = PlainWhirWireSinkEncoder::new(
            &pcs,
            &proof.aggregate_opening_proof,
            &expected_opening_widths(construction_plan),
            checked_shape.shape.aggregate_table_width,
        )?;
        let canonical_prefix_byte_length = checked_exact_proof_prefix_byte_length(
            checked_shape.shape,
            bound_tree_entries,
            &proof,
        )?;
        let canonical_byte_length = canonical_prefix_byte_length
            .checked_add(plain_whir_encoder.canonical_byte_length())
            .ok_or_else(|| "exact proof canonical byte length overflowed".to_owned())?;
        let proof_section_cursor = ExactProofSectionCursor::new(
            construction_plan,
            checked_shape.shape,
            bound_tree_entries.len(),
        )?;
        Ok(Self {
            proof,
            proof_section_cursor,
            phase: ExactSameSecretProofSinkEncodingPhase::Magic,
            written_prefix_byte_length: 0,
            canonical_prefix_byte_length,
            canonical_byte_length,
            plain_whir_encoder,
        })
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn canonical_byte_length(&self) -> usize {
        self.canonical_byte_length
    }

    #[cfg(test)]
    pub(in crate::bgv::proof_suite::row_code_whir) fn write_available<Sink>(
        &mut self,
        sink: &mut Sink,
    ) -> Result<
        ExactSameSecretProofEncodingProgress,
        ExactSameSecretProofSinkEncodingError<Sink::Error>,
    >
    where
        Sink: CommonProofByteSink,
    {
        loop {
            match self.write_next(sink)? {
                ExactSameSecretProofEncodingProgress::Pending => {}
                complete @ ExactSameSecretProofEncodingProgress::Complete { .. } => {
                    return Ok(complete);
                }
            }
        }
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn write_next<Sink>(
        &mut self,
        sink: &mut Sink,
    ) -> Result<
        ExactSameSecretProofEncodingProgress,
        ExactSameSecretProofSinkEncodingError<Sink::Error>,
    >
    where
        Sink: CommonProofByteSink,
    {
        loop {
            match self.phase {
                ExactSameSecretProofSinkEncodingPhase::Magic => {
                    self.write_prefix_bytes(sink, EXACT_PROOF_WIRE_MAGIC)?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::BaseRoot;
                }
                ExactSameSecretProofSinkEncodingPhase::BaseRoot => {
                    let bytes = column_digest_bytes(self.proof.base_root);
                    self.write_prefix_bytes(sink, &bytes)?;
                    self.consume_proof_section(
                        RowCodeWhirProofSectionRole::RelationCommitment {
                            phase: RowCodeWhirPhase::Base,
                        },
                        1,
                    )?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::AuxiliaryRoot;
                }
                ExactSameSecretProofSinkEncodingPhase::AuxiliaryRoot => {
                    let bytes = column_digest_bytes(self.proof.auxiliary_root);
                    self.write_prefix_bytes(sink, &bytes)?;
                    self.consume_proof_section(
                        RowCodeWhirProofSectionRole::RelationCommitment {
                            phase: RowCodeWhirPhase::Auxiliary,
                        },
                        1,
                    )?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::QuotientRoot;
                }
                ExactSameSecretProofSinkEncodingPhase::QuotientRoot => {
                    let bytes = column_digest_bytes(self.proof.quotient_root);
                    self.write_prefix_bytes(sink, &bytes)?;
                    self.consume_proof_section(
                        RowCodeWhirProofSectionRole::RelationCommitment {
                            phase: RowCodeWhirPhase::Quotient,
                        },
                        1,
                    )?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::OutOfDomainEvaluationCount;
                }
                ExactSameSecretProofSinkEncodingPhase::OutOfDomainEvaluationCount => {
                    let count = checked_u32(
                        self.proof.out_of_domain_evaluations.len(),
                        "out-of-domain evaluation count",
                    )
                    .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)?;
                    self.write_prefix_bytes(sink, &count.to_le_bytes())?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::OutOfDomainEvaluation {
                        evaluation_index: 0,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::OutOfDomainEvaluation {
                    evaluation_index,
                } => {
                    let Some(evaluation) = self
                        .proof
                        .out_of_domain_evaluations
                        .get(evaluation_index)
                        .copied()
                    else {
                        let evaluation_count = self.proof.out_of_domain_evaluations.len();
                        self.consume_proof_section(
                            RowCodeWhirProofSectionRole::OutOfDomainEvaluations,
                            evaluation_count,
                        )?;
                        self.phase = ExactSameSecretProofSinkEncodingPhase::OpeningMaskEvaluation {
                            evaluation_index: 0,
                        };
                        continue;
                    };
                    let bytes = production_extension_bytes(evaluation);
                    self.write_prefix_bytes(sink, &bytes)?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::OutOfDomainEvaluation {
                        evaluation_index: evaluation_index + 1,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::OpeningMaskEvaluation {
                    evaluation_index,
                } => {
                    let Some(evaluation) = self
                        .proof
                        .opening_batch_mask_chunk_evaluations
                        .get(evaluation_index)
                        .copied()
                    else {
                        let evaluation_count =
                            self.proof.opening_batch_mask_chunk_evaluations.len();
                        self.consume_proof_section(
                            RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations,
                            evaluation_count,
                        )?;
                        self.phase = ExactSameSecretProofSinkEncodingPhase::AggregateRoot;
                        continue;
                    };
                    let bytes = production_extension_bytes(evaluation);
                    self.write_prefix_bytes(sink, &bytes)?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::OpeningMaskEvaluation {
                        evaluation_index: evaluation_index + 1,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::AggregateRoot => {
                    let root = self
                        .proof
                        .aggregate_commitment
                        .roots()
                        .first()
                        .copied()
                        .ok_or_else(|| {
                            ExactSameSecretProofSinkEncodingError::InvalidProof(
                                "exact aggregate commitment has no root".to_owned(),
                            )
                        })?;
                    let bytes = column_digest_bytes(root);
                    self.write_prefix_bytes(sink, &bytes)?;
                    self.consume_proof_section(
                        RowCodeWhirProofSectionRole::AggregateCommitment,
                        1,
                    )?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::PhaseValue {
                        phase_index: 0,
                        column_index: 0,
                        row_index: 0,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::PhaseValue {
                    phase_index,
                    column_index,
                    row_index,
                } => {
                    let columns = self
                        .proof
                        .authenticated_phase_columns
                        .get(phase_index)
                        .ok_or_else(|| {
                            ExactSameSecretProofSinkEncodingError::InvalidProof(
                                "exact phase columns are absent from the checked section"
                                    .to_owned(),
                            )
                        })?;
                    let Some(column) = columns.get(column_index) else {
                        self.phase = ExactSameSecretProofSinkEncodingPhase::PhaseFrontierCount {
                            phase_index,
                        };
                        continue;
                    };
                    let Some(value) = column.values.get(row_index).copied() else {
                        self.phase = ExactSameSecretProofSinkEncodingPhase::PhaseValue {
                            phase_index,
                            column_index: column_index + 1,
                            row_index: 0,
                        };
                        continue;
                    };
                    self.write_prefix_bytes(sink, &value.as_canonical_u64().to_le_bytes())?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::PhaseValue {
                        phase_index,
                        column_index,
                        row_index: row_index + 1,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::PhaseFrontierCount { phase_index } => {
                    let frontier =
                        self.proof.phase_frontiers.get(phase_index).ok_or_else(|| {
                            ExactSameSecretProofSinkEncodingError::InvalidProof(
                                "exact phase frontier is absent from the checked section"
                                    .to_owned(),
                            )
                        })?;
                    let count = checked_u32(frontier.len(), "phase frontier count")
                        .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)?;
                    self.write_prefix_bytes(sink, &count.to_le_bytes())?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::PhaseFrontierNode {
                        phase_index,
                        node_index: 0,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::PhaseFrontierNode {
                    phase_index,
                    node_index,
                } => {
                    let frontier =
                        self.proof.phase_frontiers.get(phase_index).ok_or_else(|| {
                            ExactSameSecretProofSinkEncodingError::InvalidProof(
                                "exact phase frontier disappeared during encoding".to_owned(),
                            )
                        })?;
                    let Some(node) = frontier.get(node_index).copied() else {
                        let opening_count = self
                            .proof
                            .authenticated_phase_columns
                            .get(phase_index)
                            .ok_or_else(|| {
                                ExactSameSecretProofSinkEncodingError::InvalidProof(
                                    "exact phase columns are absent from the checked section"
                                        .to_owned(),
                                )
                            })?
                            .len();
                        self.consume_proof_section(
                            RowCodeWhirProofSectionRole::PhaseOpenings {
                                phase: exact_phase_at(phase_index)
                                    .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)?,
                            },
                            opening_count,
                        )?;
                        self.phase =
                            if phase_index + 1 == self.proof.authenticated_phase_columns.len() {
                                ExactSameSecretProofSinkEncodingPhase::BoundLeafSalt {
                                    tree_index: 0,
                                    query_index: 0,
                                }
                            } else {
                                ExactSameSecretProofSinkEncodingPhase::PhaseValue {
                                    phase_index: phase_index + 1,
                                    column_index: 0,
                                    row_index: 0,
                                }
                            };
                        continue;
                    };
                    let bytes = column_digest_bytes(node);
                    self.write_prefix_bytes(sink, &bytes)?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::PhaseFrontierNode {
                        phase_index,
                        node_index: node_index + 1,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::BoundLeafSalt {
                    tree_index,
                    query_index,
                } => {
                    let authentication = self
                        .proof
                        .bound_tree_authentications
                        .get(tree_index)
                        .ok_or_else(|| {
                            ExactSameSecretProofSinkEncodingError::InvalidProof(
                                "exact bound authentication is absent from the checked section"
                                    .to_owned(),
                            )
                        })?;
                    let Some(opening) = authentication.opened_leaves.get(query_index) else {
                        self.phase = ExactSameSecretProofSinkEncodingPhase::BoundFrontierCount {
                            tree_index,
                        };
                        continue;
                    };
                    if let Some(salt) = opening.persistent_salt {
                        self.write_prefix_bytes(sink, &salt)?;
                    } else {
                        self.phase = ExactSameSecretProofSinkEncodingPhase::BoundLeafFirstValue {
                            tree_index,
                            query_index,
                            value_index: 0,
                        };
                        continue;
                    }
                    self.phase = ExactSameSecretProofSinkEncodingPhase::BoundLeafFirstValue {
                        tree_index,
                        query_index,
                        value_index: 0,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::BoundLeafFirstValue {
                    tree_index,
                    query_index,
                    value_index,
                } => {
                    let opening = self
                        .bound_leaf_opening(tree_index, query_index)
                        .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)?;
                    let Some(value) = opening.first_point_values.get(value_index).copied() else {
                        self.phase =
                            ExactSameSecretProofSinkEncodingPhase::BoundLeafOppositeValue {
                                tree_index,
                                query_index,
                                value_index: 0,
                            };
                        continue;
                    };
                    self.write_prefix_bytes(sink, &value.canonical().to_le_bytes())?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::BoundLeafFirstValue {
                        tree_index,
                        query_index,
                        value_index: value_index + 1,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::BoundLeafOppositeValue {
                    tree_index,
                    query_index,
                    value_index,
                } => {
                    let opening = self
                        .bound_leaf_opening(tree_index, query_index)
                        .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)?;
                    let Some(value) = opening.opposite_point_values.get(value_index).copied()
                    else {
                        self.phase = ExactSameSecretProofSinkEncodingPhase::BoundLeafSalt {
                            tree_index,
                            query_index: query_index + 1,
                        };
                        continue;
                    };
                    self.write_prefix_bytes(sink, &value.canonical().to_le_bytes())?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::BoundLeafOppositeValue {
                        tree_index,
                        query_index,
                        value_index: value_index + 1,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::BoundFrontierCount { tree_index } => {
                    let authentication = self
                        .proof
                        .bound_tree_authentications
                        .get(tree_index)
                        .ok_or_else(|| {
                            ExactSameSecretProofSinkEncodingError::InvalidProof(
                                "exact bound authentication disappeared during encoding".to_owned(),
                            )
                        })?;
                    let count = checked_u32(authentication.frontier.len(), "bound frontier count")
                        .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)?;
                    self.write_prefix_bytes(sink, &count.to_le_bytes())?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::BoundFrontierNode {
                        tree_index,
                        node_index: 0,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::BoundFrontierNode {
                    tree_index,
                    node_index,
                } => {
                    let authentication = self
                        .proof
                        .bound_tree_authentications
                        .get(tree_index)
                        .ok_or_else(|| {
                            ExactSameSecretProofSinkEncodingError::InvalidProof(
                                "exact bound authentication disappeared during frontier encoding"
                                    .to_owned(),
                            )
                        })?;
                    let Some(node) = authentication.frontier.get(node_index).copied() else {
                        let opening_count = authentication.opened_leaves.len();
                        self.consume_proof_section(
                            RowCodeWhirProofSectionRole::BoundTreeOpenings {
                                bound_tree_ordinal: u32::try_from(tree_index).map_err(|_| {
                                    ExactSameSecretProofSinkEncodingError::InvalidProof(
                                        "exact bound-tree ordinal exceeds u32".to_owned(),
                                    )
                                })?,
                            },
                            opening_count,
                        )?;
                        self.phase =
                            if tree_index + 1 == self.proof.bound_tree_authentications.len() {
                                ExactSameSecretProofSinkEncodingPhase::PlainWhir
                            } else {
                                ExactSameSecretProofSinkEncodingPhase::BoundLeafSalt {
                                    tree_index: tree_index + 1,
                                    query_index: 0,
                                }
                            };
                        continue;
                    };
                    self.write_prefix_bytes(sink, &node)?;
                    self.phase = ExactSameSecretProofSinkEncodingPhase::BoundFrontierNode {
                        tree_index,
                        node_index: node_index + 1,
                    };
                }
                ExactSameSecretProofSinkEncodingPhase::PlainWhir => {
                    match self
                        .plain_whir_encoder
                        .write_next(&self.proof.aggregate_opening_proof, sink)
                    {
                        Ok(PlainWhirWireEncodingProgress::Pending) => {
                            return Ok(ExactSameSecretProofEncodingProgress::Pending);
                        }
                        Ok(PlainWhirWireEncodingProgress::Complete { .. }) => {
                            self.consume_proof_section(RowCodeWhirProofSectionRole::PlainWhir, 1)?;
                            self.phase = ExactSameSecretProofSinkEncodingPhase::Complete;
                            continue;
                        }
                        Err(PlainWhirWireSinkEncodingError::InvalidProof(error)) => {
                            return Err(ExactSameSecretProofSinkEncodingError::InvalidProof(error));
                        }
                        Err(PlainWhirWireSinkEncodingError::Sink(error)) => {
                            return Err(ExactSameSecretProofSinkEncodingError::Sink(error));
                        }
                    }
                }
                ExactSameSecretProofSinkEncodingPhase::Complete => {
                    self.proof_section_cursor
                        .ensure_complete()
                        .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)?;
                    if self.written_prefix_byte_length != self.canonical_prefix_byte_length {
                        return Err(ExactSameSecretProofSinkEncodingError::InvalidProof(
                            format!(
                                "exact proof encoder wrote {} prefix bytes, expected {}",
                                self.written_prefix_byte_length, self.canonical_prefix_byte_length
                            ),
                        ));
                    }
                    return Ok(ExactSameSecretProofEncodingProgress::Complete {
                        canonical_byte_length: self.canonical_byte_length,
                    });
                }
            }
            return Ok(ExactSameSecretProofEncodingProgress::Pending);
        }
    }

    fn consume_proof_section<SinkError>(
        &mut self,
        role: RowCodeWhirProofSectionRole,
        item_count: usize,
    ) -> Result<(), ExactSameSecretProofSinkEncodingError<SinkError>> {
        self.proof_section_cursor
            .consume(role, item_count)
            .map_err(ExactSameSecretProofSinkEncodingError::InvalidProof)
    }

    fn bound_leaf_opening(
        &self,
        tree_index: usize,
        query_index: usize,
    ) -> Result<&ExactBoundLeafOpening, String> {
        self.proof
            .bound_tree_authentications
            .get(tree_index)
            .and_then(|authentication| authentication.opened_leaves.get(query_index))
            .ok_or_else(|| "exact bound leaf disappeared during encoding".to_owned())
    }

    fn write_prefix_bytes<Sink>(
        &mut self,
        sink: &mut Sink,
        bytes: &[u8],
    ) -> Result<(), ExactSameSecretProofSinkEncodingError<Sink::Error>>
    where
        Sink: CommonProofByteSink,
    {
        let following_byte_length = self
            .written_prefix_byte_length
            .checked_add(bytes.len())
            .filter(|byte_length| *byte_length <= self.canonical_prefix_byte_length)
            .ok_or_else(|| {
                ExactSameSecretProofSinkEncodingError::InvalidProof(
                    "exact proof encoder exceeded its checked canonical prefix length".to_owned(),
                )
            })?;
        sink.write_bytes(bytes)
            .map_err(ExactSameSecretProofSinkEncodingError::Sink)?;
        self.written_prefix_byte_length = following_byte_length;
        Ok(())
    }
}

fn checked_exact_proof_prefix_byte_length(
    shape: ExactProofShape,
    bound_tree_entries: &[ProofTreeCatalogEntry],
    proof: &ExactSameSecretProof,
) -> Result<usize, String> {
    let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| "exact extension byte length overflowed".to_owned())?;
    let fixed_header_byte_length = EXACT_PROOF_WIRE_MAGIC
        .len()
        .checked_add(3 * 64)
        .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
        .and_then(|length| {
            proof
                .out_of_domain_evaluations
                .len()
                .checked_add(EXACT_OPENING_BATCH_MASK_CHUNK_COUNT)
                .and_then(|count| count.checked_mul(extension_byte_length))
                .and_then(|extension_bytes| length.checked_add(extension_bytes))
        })
        .and_then(|length| length.checked_add(64))
        .ok_or_else(|| "exact proof fixed header byte length overflowed".to_owned())?;
    let phase_value_count =
        shape
            .phase_row_counts()
            .into_iter()
            .try_fold(0_usize, |count, row_count| {
                row_count
                    .checked_mul(shape.outer_query_count)
                    .and_then(|phase_count| count.checked_add(phase_count))
                    .ok_or_else(|| "exact phase value count overflowed".to_owned())
            })?;
    let phase_byte_length = phase_value_count
        .checked_mul(core::mem::size_of::<u64>())
        .and_then(|length| {
            proof
                .phase_frontiers
                .iter()
                .try_fold(length, |length, frontier| -> Option<usize> {
                    length
                        .checked_add(core::mem::size_of::<u32>())?
                        .checked_add(frontier.len().checked_mul(64)?)
                })
        })
        .ok_or_else(|| "exact phase opening byte length overflowed".to_owned())?;
    let bound_byte_length = bound_tree_entries
        .iter()
        .zip(&proof.bound_tree_authentications)
        .try_fold(0_usize, |length, (entry, authentication)| {
            let leaf_byte_length = 2_usize
                .checked_mul(EXACT_BOUND_TREE_ROW_WIDTH)
                .and_then(|value_count| value_count.checked_mul(core::mem::size_of::<u64>()))
                .and_then(|length| {
                    if entry.requires_persistent_leaf_salt() {
                        length.checked_add(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)
                    } else {
                        Some(length)
                    }
                })
                .ok_or_else(|| "exact bound leaf byte length overflowed".to_owned())?;
            length
                .checked_add(
                    authentication
                        .opened_leaves
                        .len()
                        .checked_mul(leaf_byte_length)
                        .ok_or_else(|| "exact bound opening byte length overflowed".to_owned())?,
                )
                .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
                .and_then(|length| {
                    authentication
                        .frontier
                        .len()
                        .checked_mul(64)
                        .and_then(|frontier_bytes| length.checked_add(frontier_bytes))
                })
                .ok_or_else(|| "exact bound authentication byte length overflowed".to_owned())
        })?;
    fixed_header_byte_length
        .checked_add(phase_byte_length)
        .and_then(|length| length.checked_add(bound_byte_length))
        .ok_or_else(|| "exact proof canonical prefix byte length overflowed".to_owned())
}

fn production_extension_bytes(
    value: ProofChallengeExtensionElement,
) -> [u8; PROOF_CHALLENGE_EXTENSION_DEGREE * core::mem::size_of::<u64>()] {
    let mut bytes = [0_u8; PROOF_CHALLENGE_EXTENSION_DEGREE * core::mem::size_of::<u64>()];
    for (coordinate_index, coordinate) in value.canonical_coordinates().into_iter().enumerate() {
        let start = coordinate_index * core::mem::size_of::<u64>();
        bytes[start..start + core::mem::size_of::<u64>()]
            .copy_from_slice(&coordinate.to_le_bytes());
    }
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactIncrementalDecodePhase {
    Magic,
    BaseRoot,
    AuxiliaryRoot,
    QuotientRoot,
    OutOfDomainEvaluationCount,
    OutOfDomainEvaluations {
        next_evaluation_index: usize,
    },
    OpeningMaskEvaluations {
        next_evaluation_index: usize,
    },
    AggregateRoot,
    PhaseValues {
        phase_index: usize,
        column_index: usize,
        next_row_index: usize,
    },
    PhaseFrontierCount {
        phase_index: usize,
    },
    PhaseFrontierNodes {
        phase_index: usize,
        next_node_index: usize,
        expected_node_count: usize,
    },
    BoundLeafSalt {
        tree_index: usize,
        query_index: usize,
    },
    BoundLeafFirstValues {
        tree_index: usize,
        query_index: usize,
        next_value_index: usize,
    },
    BoundLeafOppositeValues {
        tree_index: usize,
        query_index: usize,
        next_value_index: usize,
    },
    BoundFrontierCount {
        tree_index: usize,
    },
    BoundFrontierNodes {
        tree_index: usize,
        next_node_index: usize,
        expected_node_count: usize,
    },
    PlainWhir,
    Complete,
}

/// Canonical exact-proof decoder that advances over authenticated resident
/// ranges without retaining the raw stream. All proof-controlled counts are
/// checked against verifier-owned geometry and remaining bytes before a
/// proportional reservation is attempted.
struct ExactSameSecretIncrementalDecoder {
    shape: ExactProofShape,
    proof_section_cursor: ExactProofSectionCursor,
    opening_widths: Vec<usize>,
    bound_tree_requires_persistent_salt: Vec<bool>,
    pcs: super::super::plain_whir::PlainAggregatePcs,
    declared_proof_byte_length: usize,
    offset: usize,
    phase: ExactIncrementalDecodePhase,
    base_root: Option<ColumnDigest>,
    auxiliary_root: Option<ColumnDigest>,
    quotient_root: Option<ColumnDigest>,
    out_of_domain_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_mask_chunk_evaluations:
        [ProofChallengeExtensionElement; EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
    aggregate_commitment: Option<PlainAggregateCommitment>,
    authenticated_phase_columns: [Vec<AuthenticatedColumn>; 3],
    pending_phase_values: Vec<Goldilocks>,
    phase_frontiers: [Vec<ColumnDigest>; 3],
    bound_tree_authentications: Vec<ExactBoundTreeAuthentication>,
    pending_bound_opened_leaves: Vec<ExactBoundLeafOpening>,
    pending_bound_frontier: Vec<[u8; 64]>,
    pending_bound_leaf_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    pending_bound_first_point_values: [ProofBaseFieldElement; EXACT_BOUND_TREE_ROW_WIDTH],
    pending_bound_opposite_point_values: [ProofBaseFieldElement; EXACT_BOUND_TREE_ROW_WIDTH],
    plain_whir_decoder: Option<PlainWhirIncrementalDecoder>,
    semantic_verifier: Option<ExactSameSecretIncrementalSemanticVerifier>,
    final_semantic_verification: Option<ExactSameSecretFinalProofVerification>,
    maximum_resident_decoded_payload_byte_length: usize,
}

fn validate_exact_declared_proof_byte_length(
    declared_proof_byte_length: usize,
) -> Result<(), String> {
    if declared_proof_byte_length == 0 {
        return Err("exact same-secret proof is empty".to_owned());
    }
    if declared_proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(format!(
            "exact same-secret proof has {declared_proof_byte_length} bytes, exceeding the {MAXIMUM_COMMON_PROOF_BYTE_LENGTH}-byte common hard limit"
        ));
    }
    Ok(())
}

impl ExactSameSecretIncrementalDecoder {
    fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        shape: ExactProofShape,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        pcs: super::super::plain_whir::PlainAggregatePcs,
        opening_widths: Vec<usize>,
        declared_proof_byte_length: usize,
    ) -> Result<Self, String> {
        validate_exact_declared_proof_byte_length(declared_proof_byte_length)?;
        if bound_tree_entries.len() != EXACT_BOUND_TREE_COUNT {
            return Err("exact bound tree catalog has the wrong fixed shape".to_owned());
        }
        if opening_widths.is_empty() || opening_widths.iter().any(|width| *width == 0) {
            return Err("exact opening catalog has an empty batch".to_owned());
        }
        let proof_section_cursor =
            ExactProofSectionCursor::new(construction_plan, shape, bound_tree_entries.len())?;
        let mut bound_tree_requires_persistent_salt = Vec::new();
        bound_tree_requires_persistent_salt
            .try_reserve_exact(bound_tree_entries.len())
            .map_err(|_| "exact bound-tree shape allocation failed".to_owned())?;
        bound_tree_requires_persistent_salt.extend(
            bound_tree_entries
                .iter()
                .map(ProofTreeCatalogEntry::requires_persistent_leaf_salt),
        );
        Ok(Self {
            shape,
            proof_section_cursor,
            opening_widths,
            bound_tree_requires_persistent_salt,
            pcs,
            declared_proof_byte_length,
            offset: 0,
            phase: ExactIncrementalDecodePhase::Magic,
            base_root: None,
            auxiliary_root: None,
            quotient_root: None,
            out_of_domain_evaluations: Vec::new(),
            opening_batch_mask_chunk_evaluations: [ProofChallengeExtensionElement::ZERO;
                EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
            aggregate_commitment: None,
            authenticated_phase_columns: std::array::from_fn(|_| Vec::new()),
            pending_phase_values: Vec::new(),
            phase_frontiers: std::array::from_fn(|_| Vec::new()),
            bound_tree_authentications: Vec::new(),
            pending_bound_opened_leaves: Vec::new(),
            pending_bound_frontier: Vec::new(),
            pending_bound_leaf_salt: None,
            pending_bound_first_point_values: [ProofBaseFieldElement::ZERO;
                EXACT_BOUND_TREE_ROW_WIDTH],
            pending_bound_opposite_point_values: [ProofBaseFieldElement::ZERO;
                EXACT_BOUND_TREE_ROW_WIDTH],
            plain_whir_decoder: None,
            semantic_verifier: None,
            final_semantic_verification: None,
            maximum_resident_decoded_payload_byte_length: 0,
        })
    }

    fn install_semantic_verifier(
        &mut self,
        semantic_verifier: ExactSameSecretIncrementalSemanticVerifier,
    ) -> Result<(), String> {
        if self.offset != 0
            || !matches!(self.phase, ExactIncrementalDecodePhase::Magic)
            || self.semantic_verifier.is_some()
        {
            return Err("exact semantic verifier must be installed before decoding".to_owned());
        }
        self.semantic_verifier = Some(semantic_verifier);
        Ok(())
    }

    fn resident_decoded_payload_byte_length(&self) -> usize {
        let mut byte_length = self
            .out_of_domain_evaluations
            .capacity()
            .saturating_mul(core::mem::size_of::<ProofChallengeExtensionElement>());
        for phase_columns in &self.authenticated_phase_columns {
            byte_length = byte_length.saturating_add(
                phase_columns
                    .capacity()
                    .saturating_mul(core::mem::size_of::<AuthenticatedColumn>()),
            );
            for column in phase_columns {
                byte_length = byte_length.saturating_add(
                    column
                        .values
                        .capacity()
                        .saturating_mul(core::mem::size_of::<Goldilocks>()),
                );
            }
        }
        byte_length = byte_length.saturating_add(
            self.pending_phase_values
                .capacity()
                .saturating_mul(core::mem::size_of::<Goldilocks>()),
        );
        for frontier in &self.phase_frontiers {
            byte_length = byte_length.saturating_add(
                frontier
                    .capacity()
                    .saturating_mul(core::mem::size_of::<ColumnDigest>()),
            );
        }
        byte_length = byte_length.saturating_add(
            self.bound_tree_authentications
                .capacity()
                .saturating_mul(core::mem::size_of::<ExactBoundTreeAuthentication>()),
        );
        for authentication in &self.bound_tree_authentications {
            byte_length = byte_length
                .saturating_add(
                    authentication
                        .opened_leaves
                        .capacity()
                        .saturating_mul(core::mem::size_of::<ExactBoundLeafOpening>()),
                )
                .saturating_add(
                    authentication
                        .frontier
                        .capacity()
                        .saturating_mul(core::mem::size_of::<ColumnDigest>()),
                );
        }
        byte_length = byte_length.saturating_add(
            self.pending_bound_opened_leaves
                .capacity()
                .saturating_mul(core::mem::size_of::<ExactBoundLeafOpening>()),
        );
        byte_length = byte_length.saturating_add(
            self.pending_bound_frontier
                .capacity()
                .saturating_mul(core::mem::size_of::<[u8; 64]>()),
        );
        if let Some(decoder) = &self.plain_whir_decoder {
            byte_length =
                byte_length.saturating_add(decoder.resident_decoded_payload_byte_length());
        }
        if let Some(semantic_verifier) = &self.semantic_verifier {
            byte_length = byte_length
                .saturating_add(semantic_verifier.resident_accumulator_payload_byte_length());
        }
        byte_length
    }

    fn record_resident_decoded_payload_byte_length(&mut self) {
        self.maximum_resident_decoded_payload_byte_length = self
            .maximum_resident_decoded_payload_byte_length
            .max(self.resident_decoded_payload_byte_length());
    }

    const fn is_complete(&self) -> bool {
        matches!(self.phase, ExactIncrementalDecodePhase::Complete)
    }

    fn consume_available<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<(), String> {
        if source.byte_length() != self.declared_proof_byte_length
            || available_end_offset > self.declared_proof_byte_length
            || available_end_offset < self.offset
        {
            return Err("exact decoder received the wrong authenticated byte range".to_owned());
        }
        loop {
            if self.phase == ExactIncrementalDecodePhase::PlainWhir {
                let plain_whir_is_complete = {
                    let decoder = self
                        .plain_whir_decoder
                        .as_mut()
                        .ok_or_else(|| "exact proof omitted its plain WHIR decoder".to_owned())?;
                    decoder.consume_available(source, available_end_offset)?;
                    self.offset = decoder.offset();
                    decoder.is_complete()
                };
                self.record_resident_decoded_payload_byte_length();
                if plain_whir_is_complete {
                    if self.semantic_verifier.is_some() {
                        let challenger = self
                            .plain_whir_decoder
                            .take()
                            .ok_or_else(|| "exact proof omitted its plain WHIR proof".to_owned())?
                            .finish_semantic()?;
                        let semantic_verifier = self.semantic_verifier.take().ok_or_else(|| {
                            "exact proof omitted its semantic verifier".to_owned()
                        })?;
                        self.final_semantic_verification =
                            Some(semantic_verifier.finish_plain_whir(
                                challenger,
                                self.maximum_resident_decoded_payload_byte_length,
                            )?);
                    }
                    self.proof_section_cursor
                        .consume(RowCodeWhirProofSectionRole::PlainWhir, 1)?;
                    self.phase = ExactIncrementalDecodePhase::Complete;
                    continue;
                }
                return Ok(());
            }
            if self.is_complete() {
                self.proof_section_cursor.ensure_complete()?;
                if self.offset != self.declared_proof_byte_length {
                    return Err("exact wire contains trailing bytes".to_owned());
                }
                return Ok(());
            }
            let next_byte_length = self.next_primitive_byte_length()?;
            let available_byte_length = available_end_offset - self.offset;
            if available_byte_length < next_byte_length {
                if available_end_offset == self.declared_proof_byte_length {
                    return Err(format!(
                        "exact wire is truncated at byte {}, while reading {next_byte_length} bytes",
                        self.offset
                    ));
                }
                return Ok(());
            }
            self.consume_next_primitive(source)?;
            self.record_resident_decoded_payload_byte_length();
        }
    }

    #[cfg(test)]
    fn finish(
        mut self,
        bound_tree_entries: &[ProofTreeCatalogEntry],
    ) -> Result<ExactSameSecretProof, String> {
        if !self.is_complete() || self.offset != self.declared_proof_byte_length {
            return Err("exact proof ended before its canonical terminal shape".to_owned());
        }
        self.proof_section_cursor.ensure_complete()?;
        let aggregate_opening_proof = self
            .plain_whir_decoder
            .take()
            .ok_or_else(|| "exact proof omitted its plain WHIR proof".to_owned())?
            .finish(&self.pcs)?;
        let proof = ExactSameSecretProof {
            base_root: self
                .base_root
                .ok_or_else(|| "exact proof omitted its base root".to_owned())?,
            auxiliary_root: self
                .auxiliary_root
                .ok_or_else(|| "exact proof omitted its auxiliary root".to_owned())?,
            quotient_root: self
                .quotient_root
                .ok_or_else(|| "exact proof omitted its quotient root".to_owned())?,
            out_of_domain_evaluations: self.out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations: self.opening_batch_mask_chunk_evaluations,
            aggregate_commitment: self
                .aggregate_commitment
                .ok_or_else(|| "exact proof omitted its aggregate root".to_owned())?,
            authenticated_phase_columns: self.authenticated_phase_columns,
            phase_frontiers: self.phase_frontiers,
            bound_tree_authentications: self.bound_tree_authentications,
            aggregate_opening_proof,
        };
        validate_exact_proof_shape(self.shape, bound_tree_entries, &proof)?;
        Ok(proof)
    }

    fn finish_semantic(mut self) -> Result<ExactSameSecretFinalProofVerification, String> {
        if !self.is_complete() || self.offset != self.declared_proof_byte_length {
            return Err("exact proof ended before its canonical terminal shape".to_owned());
        }
        self.proof_section_cursor.ensure_complete()?;
        if self.semantic_verifier.is_some() || self.plain_whir_decoder.is_some() {
            return Err("exact semantic verifier retained unfinished proof state".to_owned());
        }
        if !self.out_of_domain_evaluations.is_empty()
            || self
                .authenticated_phase_columns
                .iter()
                .any(|columns| !columns.is_empty())
            || self
                .phase_frontiers
                .iter()
                .any(|frontier| !frontier.is_empty())
            || !self.bound_tree_authentications.is_empty()
            || !self.pending_bound_opened_leaves.is_empty()
            || !self.pending_bound_frontier.is_empty()
        {
            return Err("exact semantic verifier retained a completed outer section".to_owned());
        }
        self.final_semantic_verification
            .take()
            .ok_or_else(|| "exact semantic verification result is absent".to_owned())
    }

    fn next_primitive_byte_length(&self) -> Result<usize, String> {
        match self.phase {
            ExactIncrementalDecodePhase::Magic => Ok(EXACT_PROOF_WIRE_MAGIC.len()),
            ExactIncrementalDecodePhase::BaseRoot
            | ExactIncrementalDecodePhase::AuxiliaryRoot
            | ExactIncrementalDecodePhase::QuotientRoot
            | ExactIncrementalDecodePhase::AggregateRoot
            | ExactIncrementalDecodePhase::PhaseFrontierNodes { .. }
            | ExactIncrementalDecodePhase::BoundFrontierNodes { .. } => Ok(64),
            ExactIncrementalDecodePhase::OutOfDomainEvaluationCount
            | ExactIncrementalDecodePhase::PhaseFrontierCount { .. }
            | ExactIncrementalDecodePhase::BoundFrontierCount { .. } => {
                Ok(core::mem::size_of::<u32>())
            }
            ExactIncrementalDecodePhase::OutOfDomainEvaluations { .. }
            | ExactIncrementalDecodePhase::OpeningMaskEvaluations { .. } => {
                Ok(PROOF_CHALLENGE_EXTENSION_DEGREE * core::mem::size_of::<u64>())
            }
            ExactIncrementalDecodePhase::PhaseValues { .. }
            | ExactIncrementalDecodePhase::BoundLeafFirstValues { .. }
            | ExactIncrementalDecodePhase::BoundLeafOppositeValues { .. } => {
                Ok(core::mem::size_of::<u64>())
            }
            ExactIncrementalDecodePhase::BoundLeafSalt { .. } => {
                Ok(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)
            }
            ExactIncrementalDecodePhase::PlainWhir | ExactIncrementalDecodePhase::Complete => {
                Err("exact decoder has no outer primitive in its current phase".to_owned())
            }
        }
    }

    fn consume_next_primitive<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<(), String> {
        let phase = self.phase;
        match phase {
            ExactIncrementalDecodePhase::Magic => {
                if self.read_array::<_, 8>(source)? != *EXACT_PROOF_WIRE_MAGIC {
                    return Err("exact same-secret proof has the wrong wire magic".to_owned());
                }
                self.phase = ExactIncrementalDecodePhase::BaseRoot;
            }
            ExactIncrementalDecodePhase::BaseRoot => {
                self.base_root = Some(self.read_digest(source)?);
                self.proof_section_cursor.consume(
                    RowCodeWhirProofSectionRole::RelationCommitment {
                        phase: RowCodeWhirPhase::Base,
                    },
                    1,
                )?;
                self.phase = ExactIncrementalDecodePhase::AuxiliaryRoot;
            }
            ExactIncrementalDecodePhase::AuxiliaryRoot => {
                self.auxiliary_root = Some(self.read_digest(source)?);
                self.proof_section_cursor.consume(
                    RowCodeWhirProofSectionRole::RelationCommitment {
                        phase: RowCodeWhirPhase::Auxiliary,
                    },
                    1,
                )?;
                self.phase = ExactIncrementalDecodePhase::QuotientRoot;
            }
            ExactIncrementalDecodePhase::QuotientRoot => {
                self.quotient_root = Some(self.read_digest(source)?);
                self.proof_section_cursor.consume(
                    RowCodeWhirProofSectionRole::RelationCommitment {
                        phase: RowCodeWhirPhase::Quotient,
                    },
                    1,
                )?;
                self.phase = ExactIncrementalDecodePhase::OutOfDomainEvaluationCount;
            }
            ExactIncrementalDecodePhase::OutOfDomainEvaluationCount => {
                let count = self.read_u32(source)? as usize;
                if count != self.shape.opening_claim_count {
                    return Err(format!(
                        "exact same-secret proof has {count} out-of-domain evaluations, expected {}",
                        self.shape.opening_claim_count
                    ));
                }
                self.ensure_declared_remaining_elements(
                    count,
                    PROOF_CHALLENGE_EXTENSION_DEGREE * core::mem::size_of::<u64>(),
                    "out-of-domain evaluations",
                )?;
                self.out_of_domain_evaluations
                    .try_reserve_exact(count)
                    .map_err(|_| "exact out-of-domain allocation failed".to_owned())?;
                self.phase = if count == 0 {
                    self.proof_section_cursor
                        .consume(RowCodeWhirProofSectionRole::OutOfDomainEvaluations, count)?;
                    ExactIncrementalDecodePhase::OpeningMaskEvaluations {
                        next_evaluation_index: 0,
                    }
                } else {
                    ExactIncrementalDecodePhase::OutOfDomainEvaluations {
                        next_evaluation_index: 0,
                    }
                };
            }
            ExactIncrementalDecodePhase::OutOfDomainEvaluations {
                next_evaluation_index,
            } => {
                let evaluation = self.read_production_extension(source)?;
                self.out_of_domain_evaluations.push(evaluation);
                let following_evaluation_index = next_evaluation_index + 1;
                self.phase = if following_evaluation_index == self.shape.opening_claim_count {
                    self.proof_section_cursor.consume(
                        RowCodeWhirProofSectionRole::OutOfDomainEvaluations,
                        following_evaluation_index,
                    )?;
                    ExactIncrementalDecodePhase::OpeningMaskEvaluations {
                        next_evaluation_index: 0,
                    }
                } else {
                    ExactIncrementalDecodePhase::OutOfDomainEvaluations {
                        next_evaluation_index: following_evaluation_index,
                    }
                };
            }
            ExactIncrementalDecodePhase::OpeningMaskEvaluations {
                next_evaluation_index,
            } => {
                self.opening_batch_mask_chunk_evaluations[next_evaluation_index] =
                    self.read_production_extension(source)?;
                let following_evaluation_index = next_evaluation_index + 1;
                self.phase = if following_evaluation_index == EXACT_OPENING_BATCH_MASK_CHUNK_COUNT {
                    self.proof_section_cursor.consume(
                        RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations,
                        following_evaluation_index,
                    )?;
                    self.consume_transcript_material_if_semantic()?;
                    ExactIncrementalDecodePhase::AggregateRoot
                } else {
                    ExactIncrementalDecodePhase::OpeningMaskEvaluations {
                        next_evaluation_index: following_evaluation_index,
                    }
                };
            }
            ExactIncrementalDecodePhase::AggregateRoot => {
                let root = self.read_digest(source)?;
                let aggregate_commitment = MerkleCap::new(vec![root]);
                if let Some(semantic_verifier) = self.semantic_verifier.as_mut() {
                    semantic_verifier.consume_aggregate_commitment(aggregate_commitment)?;
                } else {
                    self.aggregate_commitment = Some(aggregate_commitment);
                }
                self.proof_section_cursor
                    .consume(RowCodeWhirProofSectionRole::AggregateCommitment, 1)?;
                self.phase = self.begin_phase_values(0)?;
            }
            ExactIncrementalDecodePhase::PhaseValues {
                phase_index,
                column_index,
                next_row_index,
            } => {
                let value = self.read_goldilocks(source)?;
                self.pending_phase_values.push(value);
                let row_count = self.shape.phase_row_counts()[phase_index];
                let following_row_index = next_row_index + 1;
                if following_row_index == row_count {
                    let values = core::mem::take(&mut self.pending_phase_values);
                    if let Some(semantic_verifier) = self.semantic_verifier.as_mut() {
                        semantic_verifier.consume_phase_column(
                            phase_index,
                            column_index,
                            values,
                        )?;
                    } else {
                        self.authenticated_phase_columns[phase_index]
                            .push(AuthenticatedColumn { values });
                    }
                    let following_column_index = column_index + 1;
                    if following_column_index == self.shape.outer_query_count {
                        self.phase =
                            ExactIncrementalDecodePhase::PhaseFrontierCount { phase_index };
                    } else {
                        self.prepare_pending_phase_values(row_count)?;
                        self.phase = ExactIncrementalDecodePhase::PhaseValues {
                            phase_index,
                            column_index: following_column_index,
                            next_row_index: 0,
                        };
                    }
                } else {
                    self.phase = ExactIncrementalDecodePhase::PhaseValues {
                        phase_index,
                        column_index,
                        next_row_index: following_row_index,
                    };
                }
            }
            ExactIncrementalDecodePhase::PhaseFrontierCount { phase_index } => {
                let count = self.read_u32(source)? as usize;
                let maximum = self.shape.maximum_frontier_count()?;
                if count > maximum {
                    return Err(format!(
                        "exact phase frontier has {count} nodes, exceeding {maximum}"
                    ));
                }
                self.ensure_declared_remaining_elements(count, 64, "phase frontier nodes")?;
                self.phase_frontiers[phase_index]
                    .try_reserve_exact(count)
                    .map_err(|_| "exact phase-frontier allocation failed".to_owned())?;
                self.phase = if count == 0 {
                    self.complete_phase_frontier(phase_index)?
                } else {
                    ExactIncrementalDecodePhase::PhaseFrontierNodes {
                        phase_index,
                        next_node_index: 0,
                        expected_node_count: count,
                    }
                };
            }
            ExactIncrementalDecodePhase::PhaseFrontierNodes {
                phase_index,
                next_node_index,
                expected_node_count,
            } => {
                let node = self.read_digest(source)?;
                self.phase_frontiers[phase_index].push(node);
                let following_node_index = next_node_index + 1;
                self.phase = if following_node_index == expected_node_count {
                    self.complete_phase_frontier(phase_index)?
                } else {
                    ExactIncrementalDecodePhase::PhaseFrontierNodes {
                        phase_index,
                        next_node_index: following_node_index,
                        expected_node_count,
                    }
                };
            }
            ExactIncrementalDecodePhase::BoundLeafSalt {
                tree_index,
                query_index,
            } => {
                self.pending_bound_leaf_salt = Some(self.read_array(source)?);
                self.phase = ExactIncrementalDecodePhase::BoundLeafFirstValues {
                    tree_index,
                    query_index,
                    next_value_index: 0,
                };
            }
            ExactIncrementalDecodePhase::BoundLeafFirstValues {
                tree_index,
                query_index,
                next_value_index,
            } => {
                self.pending_bound_first_point_values[next_value_index] =
                    self.read_base_field(source)?;
                let following_value_index = next_value_index + 1;
                self.phase = if following_value_index == EXACT_BOUND_TREE_ROW_WIDTH {
                    ExactIncrementalDecodePhase::BoundLeafOppositeValues {
                        tree_index,
                        query_index,
                        next_value_index: 0,
                    }
                } else {
                    ExactIncrementalDecodePhase::BoundLeafFirstValues {
                        tree_index,
                        query_index,
                        next_value_index: following_value_index,
                    }
                };
            }
            ExactIncrementalDecodePhase::BoundLeafOppositeValues {
                tree_index,
                query_index,
                next_value_index,
            } => {
                self.pending_bound_opposite_point_values[next_value_index] =
                    self.read_base_field(source)?;
                let following_value_index = next_value_index + 1;
                if following_value_index == EXACT_BOUND_TREE_ROW_WIDTH {
                    let opening = ExactBoundLeafOpening {
                        persistent_salt: self.pending_bound_leaf_salt.take(),
                        first_point_values: self.pending_bound_first_point_values,
                        opposite_point_values: self.pending_bound_opposite_point_values,
                    };
                    if let Some(semantic_verifier) = self.semantic_verifier.as_mut() {
                        semantic_verifier.consume_bound_leaf(tree_index, query_index, opening)?;
                    } else {
                        self.pending_bound_opened_leaves.push(opening);
                    }
                    self.pending_bound_first_point_values =
                        [ProofBaseFieldElement::ZERO; EXACT_BOUND_TREE_ROW_WIDTH];
                    self.pending_bound_opposite_point_values =
                        [ProofBaseFieldElement::ZERO; EXACT_BOUND_TREE_ROW_WIDTH];
                    let following_query_index = query_index + 1;
                    let query_count = self.shape.bound_tree_query_count(tree_index)?;
                    self.phase = if following_query_index == query_count {
                        ExactIncrementalDecodePhase::BoundFrontierCount { tree_index }
                    } else {
                        self.begin_bound_leaf(tree_index, following_query_index)?
                    };
                } else {
                    self.phase = ExactIncrementalDecodePhase::BoundLeafOppositeValues {
                        tree_index,
                        query_index,
                        next_value_index: following_value_index,
                    };
                }
            }
            ExactIncrementalDecodePhase::BoundFrontierCount { tree_index } => {
                let count = self.read_u32(source)? as usize;
                let maximum = self
                    .shape
                    .bound_tree_query_count(tree_index)?
                    .checked_mul(EXACT_BOUND_LEAF_COUNT.ilog2() as usize)
                    .ok_or_else(|| "bound frontier limit overflowed".to_owned())?;
                if count > maximum {
                    return Err("bound frontier exceeds its fixed maximum".to_owned());
                }
                self.ensure_declared_remaining_elements(count, 64, "bound frontier nodes")?;
                if self.semantic_verifier.is_some() {
                    self.pending_bound_frontier
                        .try_reserve_exact(count)
                        .map_err(|_| "bound frontier allocation failed".to_owned())?;
                } else {
                    let mut frontier = Vec::new();
                    frontier
                        .try_reserve_exact(count)
                        .map_err(|_| "bound frontier allocation failed".to_owned())?;
                    self.bound_tree_authentications
                        .push(ExactBoundTreeAuthentication {
                            opened_leaves: core::mem::take(&mut self.pending_bound_opened_leaves),
                            frontier,
                        });
                }
                self.phase = if count == 0 {
                    self.complete_bound_frontier(tree_index)?
                } else {
                    ExactIncrementalDecodePhase::BoundFrontierNodes {
                        tree_index,
                        next_node_index: 0,
                        expected_node_count: count,
                    }
                };
            }
            ExactIncrementalDecodePhase::BoundFrontierNodes {
                tree_index,
                next_node_index,
                expected_node_count,
            } => {
                let node = self.read_array(source)?;
                if self.semantic_verifier.is_some() {
                    self.pending_bound_frontier.push(node);
                } else {
                    self.bound_tree_authentications
                        .last_mut()
                        .ok_or_else(|| "exact bound authentication is absent".to_owned())?
                        .frontier
                        .push(node);
                }
                let following_node_index = next_node_index + 1;
                self.phase = if following_node_index == expected_node_count {
                    self.complete_bound_frontier(tree_index)?
                } else {
                    ExactIncrementalDecodePhase::BoundFrontierNodes {
                        tree_index,
                        next_node_index: following_node_index,
                        expected_node_count,
                    }
                };
            }
            ExactIncrementalDecodePhase::PlainWhir | ExactIncrementalDecodePhase::Complete => {
                return Err("exact decoder was polled in a non-outer phase".to_owned());
            }
        }
        Ok(())
    }

    fn consume_transcript_material_if_semantic(&mut self) -> Result<(), String> {
        if self.semantic_verifier.is_none() {
            return Ok(());
        }
        let base_root = self
            .base_root
            .take()
            .ok_or_else(|| "exact proof omitted its base root".to_owned())?;
        let auxiliary_root = self
            .auxiliary_root
            .take()
            .ok_or_else(|| "exact proof omitted its auxiliary root".to_owned())?;
        let quotient_root = self
            .quotient_root
            .take()
            .ok_or_else(|| "exact proof omitted its quotient root".to_owned())?;
        let out_of_domain_evaluations = core::mem::take(&mut self.out_of_domain_evaluations);
        let opening_batch_mask_chunk_evaluations = core::mem::replace(
            &mut self.opening_batch_mask_chunk_evaluations,
            [ProofChallengeExtensionElement::ZERO; EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
        );
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "exact semantic verifier is absent".to_owned())?
            .consume_transcript_material(
                base_root,
                auxiliary_root,
                quotient_root,
                out_of_domain_evaluations,
                opening_batch_mask_chunk_evaluations,
            )
    }

    fn complete_phase_frontier(
        &mut self,
        phase_index: usize,
    ) -> Result<ExactIncrementalDecodePhase, String> {
        if self.semantic_verifier.is_some() {
            if !self.authenticated_phase_columns[phase_index].is_empty() {
                return Err("exact semantic verifier retained raw phase columns".to_owned());
            }
            let frontier = core::mem::take(&mut self.phase_frontiers[phase_index]);
            self.semantic_verifier
                .as_mut()
                .ok_or_else(|| "exact semantic verifier is absent".to_owned())?
                .consume_phase_frontier(phase_index, frontier)?;
        }
        self.proof_section_cursor.consume(
            RowCodeWhirProofSectionRole::PhaseOpenings {
                phase: exact_phase_at(phase_index)?,
            },
            self.shape.outer_query_count,
        )?;
        self.phase_after_phase_frontier(phase_index)
    }

    fn complete_bound_frontier(
        &mut self,
        tree_index: usize,
    ) -> Result<ExactIncrementalDecodePhase, String> {
        if self.semantic_verifier.is_some() {
            if !self.bound_tree_authentications.is_empty()
                || !self.pending_bound_opened_leaves.is_empty()
            {
                return Err("exact semantic verifier retained raw bound openings".to_owned());
            }
            let frontier = core::mem::take(&mut self.pending_bound_frontier);
            self.semantic_verifier
                .as_mut()
                .ok_or_else(|| "exact semantic verifier is absent".to_owned())?
                .consume_bound_frontier(tree_index, frontier)?;
        }
        self.proof_section_cursor.consume(
            RowCodeWhirProofSectionRole::BoundTreeOpenings {
                bound_tree_ordinal: u32::try_from(tree_index)
                    .map_err(|_| "exact bound-tree ordinal exceeds u32".to_owned())?,
            },
            self.shape.bound_tree_query_count(tree_index)?,
        )?;
        self.phase_after_bound_frontier(tree_index)
    }

    fn begin_phase_values(
        &mut self,
        phase_index: usize,
    ) -> Result<ExactIncrementalDecodePhase, String> {
        if phase_index == 0 {
            let phase_value_count = self.shape.phase_row_counts().into_iter().try_fold(
                0_usize,
                |value_count, row_count| {
                    row_count
                        .checked_mul(self.shape.outer_query_count)
                        .and_then(|phase_value_count| value_count.checked_add(phase_value_count))
                        .ok_or_else(|| "exact phase-value count overflowed".to_owned())
                },
            )?;
            self.ensure_declared_remaining_elements(
                phase_value_count,
                core::mem::size_of::<u64>(),
                "authenticated phase values",
            )?;
        }
        let row_count = *self
            .shape
            .phase_row_counts()
            .get(phase_index)
            .ok_or_else(|| "exact phase index is outside the fixed shape".to_owned())?;
        if self.semantic_verifier.is_none() {
            self.authenticated_phase_columns[phase_index]
                .try_reserve_exact(self.shape.outer_query_count)
                .map_err(|_| "exact authenticated-column allocation failed".to_owned())?;
        }
        self.prepare_pending_phase_values(row_count)?;
        Ok(ExactIncrementalDecodePhase::PhaseValues {
            phase_index,
            column_index: 0,
            next_row_index: 0,
        })
    }

    fn prepare_pending_phase_values(&mut self, row_count: usize) -> Result<(), String> {
        self.pending_phase_values.clear();
        self.pending_phase_values
            .try_reserve_exact(row_count)
            .map_err(|_| "exact phase-column allocation failed".to_owned())
    }

    fn phase_after_phase_frontier(
        &mut self,
        phase_index: usize,
    ) -> Result<ExactIncrementalDecodePhase, String> {
        let following_phase_index = phase_index + 1;
        if following_phase_index == self.phase_frontiers.len() {
            if self.semantic_verifier.is_none() {
                self.bound_tree_authentications
                    .try_reserve_exact(EXACT_BOUND_TREE_COUNT)
                    .map_err(|_| "exact bound-authentication allocation failed".to_owned())?;
            }
            self.begin_bound_tree(0)
        } else {
            self.begin_phase_values(following_phase_index)
        }
    }

    fn begin_bound_tree(
        &mut self,
        tree_index: usize,
    ) -> Result<ExactIncrementalDecodePhase, String> {
        let query_count = self.shape.bound_tree_query_count(tree_index)?;
        let leaf_byte_length = 2_usize
            .checked_mul(EXACT_BOUND_TREE_ROW_WIDTH)
            .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
            .and_then(|byte_length| {
                byte_length.checked_add(if self.bound_tree_requires_persistent_salt[tree_index] {
                    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                } else {
                    0
                })
            })
            .ok_or_else(|| "bound leaf byte count overflowed".to_owned())?;
        self.ensure_declared_remaining_elements(
            query_count,
            leaf_byte_length,
            "bound leaf openings",
        )?;
        if self.semantic_verifier.is_none() {
            self.pending_bound_opened_leaves
                .try_reserve_exact(query_count)
                .map_err(|_| "bound leaf-opening allocation failed".to_owned())?;
        }
        if query_count == 0 {
            Ok(ExactIncrementalDecodePhase::BoundFrontierCount { tree_index })
        } else {
            self.begin_bound_leaf(tree_index, 0)
        }
    }

    fn begin_bound_leaf(
        &self,
        tree_index: usize,
        query_index: usize,
    ) -> Result<ExactIncrementalDecodePhase, String> {
        if *self
            .bound_tree_requires_persistent_salt
            .get(tree_index)
            .ok_or_else(|| "bound tree index is outside the exact catalog".to_owned())?
        {
            Ok(ExactIncrementalDecodePhase::BoundLeafSalt {
                tree_index,
                query_index,
            })
        } else {
            Ok(ExactIncrementalDecodePhase::BoundLeafFirstValues {
                tree_index,
                query_index,
                next_value_index: 0,
            })
        }
    }

    fn phase_after_bound_frontier(
        &mut self,
        tree_index: usize,
    ) -> Result<ExactIncrementalDecodePhase, String> {
        let following_tree_index = tree_index + 1;
        if following_tree_index == EXACT_BOUND_TREE_COUNT {
            let decoder = if let Some(semantic_verifier) = self.semantic_verifier.as_mut() {
                let preparation = semantic_verifier.prepare_plain_whir_verification(&self.pcs)?;
                PlainWhirIncrementalDecoder::new_semantic(
                    &self.pcs,
                    &self.opening_widths,
                    self.shape.aggregate_table_width,
                    self.offset,
                    self.declared_proof_byte_length,
                    preparation,
                )?
            } else {
                #[cfg(test)]
                {
                    PlainWhirIncrementalDecoder::new(
                        &self.pcs,
                        &self.opening_widths,
                        self.shape.aggregate_table_width,
                        self.offset,
                        self.declared_proof_byte_length,
                    )?
                }
                #[cfg(not(test))]
                {
                    return Err(
                        "exact production decoding requires its semantic verifier".to_owned()
                    );
                }
            };
            self.plain_whir_decoder = Some(decoder);
            Ok(ExactIncrementalDecodePhase::PlainWhir)
        } else {
            self.begin_bound_tree(following_tree_index)
        }
    }

    fn ensure_declared_remaining_elements(
        &self,
        element_count: usize,
        element_byte_length: usize,
        label: &str,
    ) -> Result<(), String> {
        let required_byte_length = element_count
            .checked_mul(element_byte_length)
            .ok_or_else(|| format!("exact {label} byte count overflowed"))?;
        let remaining_byte_length = self
            .declared_proof_byte_length
            .checked_sub(self.offset)
            .ok_or_else(|| "exact wire cursor exceeds its declared length".to_owned())?;
        if required_byte_length > remaining_byte_length {
            return Err(format!(
                "exact wire is truncated before {label} requiring {required_byte_length} bytes"
            ));
        }
        Ok(())
    }

    fn read_array<Source: ProofByteSource + ?Sized, const BYTE_COUNT: usize>(
        &mut self,
        source: &Source,
    ) -> Result<[u8; BYTE_COUNT], String> {
        let mut bytes = [0_u8; BYTE_COUNT];
        if !source.copy_bytes(self.offset, &mut bytes) {
            return Err("exact wire is truncated".to_owned());
        }
        self.offset = self
            .offset
            .checked_add(BYTE_COUNT)
            .ok_or_else(|| "exact wire offset overflowed".to_owned())?;
        Ok(bytes)
    }

    fn read_u32<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.read_array(source)?))
    }

    fn read_u64<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.read_array(source)?))
    }

    fn read_goldilocks<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<Goldilocks, String> {
        let canonical = self.read_u64(source)?;
        if canonical >= GOLDILOCKS_MODULUS {
            return Err("exact proof contains a non-canonical Goldilocks value".to_owned());
        }
        Ok(Goldilocks::new(canonical))
    }

    fn read_base_field<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<ProofBaseFieldElement, String> {
        ProofBaseFieldElement::from_canonical(self.read_u64(source)?)
            .map_err(|_| "bound leaf contains a non-canonical field value".to_owned())
    }

    fn read_digest<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<ColumnDigest, String> {
        let mut digest = [0_u64; 8];
        for word in &mut digest {
            *word = self.read_u64(source)?;
        }
        Ok(digest)
    }

    fn read_production_extension<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<ProofChallengeExtensionElement, String> {
        let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = self.read_u64(source)?;
        }
        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
            .map_err(|_| "exact proof contains a non-canonical extension value".to_owned())
    }
}

#[cfg(test)]
fn decode_exact_same_secret_proof(
    construction_plan: &RowCodeWhirConstructionPlan,
    shape: ExactProofShape,
    bound_tree_entries: &[ProofTreeCatalogEntry],
    canonical: &[u8],
) -> Result<ExactSameSecretProof, String> {
    let pcs = plain_aggregate_pcs(EXACT_PCS_VARIABLE_COUNT)?;
    let mut decoder = ExactSameSecretIncrementalDecoder::new(
        construction_plan,
        shape,
        bound_tree_entries,
        pcs,
        selected_expected_opening_widths(),
        canonical.len(),
    )?;
    decoder.consume_available(canonical, canonical.len())?;
    decoder.finish(bound_tree_entries)
}

fn validate_exact_proof_shape(
    shape: ExactProofShape,
    bound_tree_entries: &[ProofTreeCatalogEntry],
    proof: &ExactSameSecretProof,
) -> Result<(), String> {
    if proof.out_of_domain_evaluations.len() != shape.opening_claim_count
        || proof.aggregate_commitment.num_roots() != 1
    {
        return Err("exact same-secret proof has the wrong fixed shape".to_owned());
    }
    let maximum_frontier_count = shape.maximum_frontier_count()?;
    for ((columns, expected_row_count), frontier) in proof
        .authenticated_phase_columns
        .iter()
        .zip(shape.phase_row_counts())
        .zip(&proof.phase_frontiers)
    {
        if columns.len() != shape.outer_query_count
            || columns
                .iter()
                .any(|column| column.values.len() != expected_row_count)
            || frontier.len() > maximum_frontier_count
        {
            return Err("exact same-secret phase opening has the wrong fixed shape".to_owned());
        }
    }
    if bound_tree_entries.len() != EXACT_BOUND_TREE_COUNT
        || proof.bound_tree_authentications.len() != EXACT_BOUND_TREE_COUNT
        || bound_tree_entries
            .iter()
            .zip(&proof.bound_tree_authentications)
            .enumerate()
            .any(|(bound_tree_ordinal, (entry, authentication))| {
                let Ok(query_count) = shape.bound_tree_query_count(bound_tree_ordinal) else {
                    return true;
                };
                let Some(maximum_bound_frontier_count) =
                    query_count.checked_mul(EXACT_BOUND_LEAF_COUNT.ilog2() as usize)
                else {
                    return true;
                };
                authentication.opened_leaves.len() != query_count
                    || authentication.frontier.len() > maximum_bound_frontier_count
                    || authentication.opened_leaves.iter().any(|opening| {
                        opening.persistent_salt.is_some() != entry.requires_persistent_leaf_salt()
                    })
            })
    {
        return Err("exact bound authentication has the wrong fixed shape".to_owned());
    }
    Ok(())
}

fn checked_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} exceeds canonical u32"))
}

#[cfg(test)]
mod construction_tests {
    use num_bigint::BigUint;
    use p3_field::extension::BinomiallyExtendable;

    use super::*;
    use crate::bgv::proof_suite::row_code_whir::plain_whir::{
        PlainAggregatePcs, extend_plain_aggregate_public_sampler_exhaustion_catalog,
    };
    use crate::bgv::proof_suite::transcript::{
        CommonProofApplicationChallengeGroup, CommonProofChallenge, PublicSamplerExhaustionCatalog,
        PublicSamplerKind,
    };

    const EXACT_AGGREGATE_SOUNDNESS_UPPER_BOUND_BITS: usize = 245;
    const EXACT_SAME_SECRET_APPLICATION_COUNT: u64 = 10;
    const QROM_RANDOM_ORACLE_QUERY_BOUND_EXPONENT: usize = 80;
    const FIAT_SHAMIR_RANDOM_ORACLE_OUTPUT_BIT_LENGTH: usize = 512;
    const INPUT_BOUND_CLEARED_IDENTITY_ROOT_PAIR_BOUND: u64 = 9_217;
    const EXACT_LOGICAL_VERIFIER_MESSAGE_COUNT: u64 = 5_076;

    #[test]
    fn bound_query_selection_preserves_acceptance_order_and_sorts_only_traversal() {
        let shape = ExactProofShape {
            base_row_count: 1,
            auxiliary_row_count: 1,
            quotient_row_count: 1,
            opening_claim_count: 1,
            encoded_column_count: 1 << 21,
            outer_query_count: 387,
            verified_vss_bound_query_count: 40,
            direct_bound_query_count: 266,
            aggregate_table_width: 4,
        };
        let accepted_output_root_indices = (0..shape.direct_bound_query_count)
            .map(|accepted_ordinal| (accepted_ordinal * 9_973 + 41) % EXACT_BOUND_LEAF_COUNT)
            .collect::<Vec<_>>();
        let accepted_input_root_indices =
            accepted_output_root_indices[..shape.verified_vss_bound_query_count].to_vec();
        let mut input_root_traversal_indices = accepted_input_root_indices.clone();
        input_root_traversal_indices.sort_unstable();
        let mut output_root_traversal_indices = accepted_output_root_indices.clone();
        output_root_traversal_indices.sort_unstable();
        let indices = ExactBoundQueryIndices {
            accepted_input_root_indices,
            accepted_output_root_indices,
            input_root_traversal_indices,
            output_root_traversal_indices,
        };

        assert!(indices.has_exact_shape(shape));
        assert_ne!(
            indices.accepted_output_root_indices, indices.output_root_traversal_indices,
            "the transcript acceptance order must remain distinct from Merkle traversal order",
        );
        assert_eq!(
            indices.accepted_input_root_indices,
            indices.accepted_output_root_indices[..shape.verified_vss_bound_query_count],
            "the prior-certificate subset is exactly the first accepted draws",
        );
        for (accepted_ordinal, leaf_index) in indices
            .accepted_input_root_indices
            .iter()
            .copied()
            .enumerate()
        {
            assert_eq!(
                indices
                    .accepted_query_ordinal_for_tree(0, leaf_index)
                    .expect("the input traversal leaf maps back to acceptance order"),
                accepted_ordinal,
            );
        }

        let mut wrong_subset = indices.clone();
        wrong_subset.accepted_input_root_indices.swap(0, 1);
        assert!(!wrong_subset.has_exact_shape(shape));
        let mut wrong_traversal = indices;
        wrong_traversal.output_root_traversal_indices.swap(0, 1);
        assert!(!wrong_traversal.has_exact_shape(shape));
    }

    #[test]
    fn exact_verifier_admission_uses_only_the_absolute_common_proof_bound() {
        validate_exact_declared_proof_byte_length(MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH + 1)
            .expect("the selected proof-size target is not a cryptographic admission ceiling");
        validate_exact_declared_proof_byte_length(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .expect("the exact absolute common-proof bound is admissible");

        let error = validate_exact_declared_proof_byte_length(MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1)
            .expect_err("one byte beyond the absolute common-proof bound must be refused");
        assert!(error.contains("common hard limit"));
    }

    #[test]
    fn exact_verifier_resident_memory_accounting_accepts_selection_target_variance() {
        let (relation_plan, _, _) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        let canonical_proof_byte_length = MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH + 1;
        let accounting = derive_exact_same_secret_verification_resident_memory_accounting(
            &relation_plan,
            4_096,
            512,
            canonical_proof_byte_length,
        )
        .expect("account a proof above the evidence selection target");

        assert!(
            accounting.maximum_resident_byte_length()
                > u64::try_from(canonical_proof_byte_length)
                    .expect("the selected proof byte length fits u64"),
            "resident accounting must include proof decoding and semantic verifier state"
        );
    }

    #[test]
    fn exact_verifier_resident_memory_accounting_refuses_overflow_and_invalid_framing() {
        assert!(checked_exact_verifier_resident_memory_add(u64::MAX, 1).is_err());

        let (relation_plan, _, _) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        assert!(
            derive_exact_same_secret_verification_resident_memory_accounting(
                &relation_plan,
                4_096,
                1_024,
                1_024,
            )
            .is_err(),
            "a proof body must remain after the canonical header"
        );
        assert!(
            derive_exact_same_secret_verification_resident_memory_accounting(
                &relation_plan,
                4_096,
                512,
                MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1,
            )
            .is_err(),
            "the absolute common-proof anti-exhaustion bound remains authoritative"
        );
    }

    #[test]
    fn exact_construction_plan_correspondence_rejects_operational_mutations() {
        type ExactConstructionPlanMutation = (&'static str, fn(&mut RowCodeWhirConstructionPlan));

        let (capability, variant, relation_context) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        let canonical_plan = capability.row_code_whir_construction_plan().clone();
        let relation_plan_hash = capability.relation_plan_hash();
        let relation_plan_variant_hash = capability.relation_plan_variant_hash();
        let validate = |plan: &RowCodeWhirConstructionPlan| {
            validate_exact_same_secret_construction_plan(
                plan,
                &variant,
                &relation_context,
                relation_plan_hash,
                relation_plan_variant_hash,
            )
        };
        validate(&canonical_plan).expect("accept the capability-held exact construction plan");

        let mutations: &[ExactConstructionPlanMutation] = &[
            ("trace row mapping", |plan| {
                plan.base_phase.as_mut().expect("exact base phase").rows[0]
                    .logical_polynomial_chunks[0]
                    .as_mut()
                    .expect("first exact base chunk")
                    .coefficient_chunk_ordinal += 1;
            }),
            ("trace geometry", |plan| {
                plan.auxiliary_phase
                    .as_mut()
                    .expect("exact auxiliary phase")
                    .geometry
                    .encoded_column_count /= 2;
            }),
            ("quotient row mapping", |plan| {
                plan.quotient_phase.rows[0].coefficient_chunk_group_start_ordinal += 1;
            }),
            ("bound tree query schedule", |plan| {
                plan.bound_trees[0].query_count += 1;
            }),
            ("bound reduction schedule", |plan| {
                plan.bound_reduction_blocks[1].selector_prefix[0] ^= 1;
            }),
            ("aggregate role", |plan| {
                plan.aggregate_column_roles.swap(0, 1);
            }),
            ("selected WHIR parameters", |plan| {
                plan.parameters.outer_query_count += 1;
            }),
        ];
        for (label, mutate) in mutations {
            let mut mutated_plan = canonical_plan.clone();
            mutate(&mut mutated_plan);
            assert!(
                validate(&mutated_plan).is_err(),
                "accepted mutated exact construction plan: {label}"
            );
        }
    }

    #[test]
    fn exact_wire_section_cursor_rejects_reordering_counts_ordinals_and_omission() {
        let (capability, variant, relation_context) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        let canonical_plan = capability.row_code_whir_construction_plan().clone();
        let shape = validate_exact_same_secret_construction_plan(
            &canonical_plan,
            &variant,
            &relation_context,
            capability.relation_plan_hash(),
            capability.relation_plan_variant_hash(),
        )
        .expect("derive the exact proof shape");
        ExactProofSectionCursor::new(&canonical_plan, shape, EXACT_BOUND_TREE_COUNT)
            .expect("the checked construction plan owns the canonical exact wire chronology");

        let mut reordered = canonical_plan.clone();
        reordered.proof_sections.swap(0, 1);
        assert!(
            ExactProofSectionCursor::new(&reordered, shape, EXACT_BOUND_TREE_COUNT).is_err(),
            "a reordered proof section must be refused",
        );

        let mut changed_count = canonical_plan.clone();
        changed_count.proof_sections[3].item_count += 1;
        assert!(
            ExactProofSectionCursor::new(&changed_count, shape, EXACT_BOUND_TREE_COUNT).is_err(),
            "a changed proof-section item count must be refused",
        );

        let mut changed_ordinal = canonical_plan.clone();
        changed_ordinal.proof_sections[0].section_ordinal += 1;
        assert!(
            ExactProofSectionCursor::new(&changed_ordinal, shape, EXACT_BOUND_TREE_COUNT).is_err(),
            "a changed proof-section ordinal must be refused",
        );

        let mut omitted = canonical_plan;
        omitted.proof_sections.pop();
        assert!(
            ExactProofSectionCursor::new(&omitted, shape, EXACT_BOUND_TREE_COUNT).is_err(),
            "an omitted terminal proof section must be refused",
        );
    }

    #[test]
    fn exact_challenge_field_reduction_polynomial_is_irreducible() {
        assert_eq!(
            <Goldilocks as BinomiallyExtendable<5>>::W,
            Goldilocks::new(3)
        );
        assert_eq!(GOLDILOCKS_MODULUS % 5, 1);
        assert_ne!(
            Goldilocks::new(3).exp_u64((GOLDILOCKS_MODULUS - 1) / 5),
            Goldilocks::ONE
        );
    }

    fn evaluate_coefficients(
        coefficients: &[ChallengeField],
        point: ChallengeField,
    ) -> ChallengeField {
        coefficients
            .iter()
            .rev()
            .fold(ChallengeField::ZERO, |value, coefficient| {
                value * point + *coefficient
            })
    }

    fn add_binary_failure_term(
        accumulator: &mut BigUint,
        numerator_base: u64,
        numerator_exponent: u32,
        denominator_exponent: usize,
        common_denominator_exponent: usize,
    ) {
        assert!(denominator_exponent <= common_denominator_exponent);
        *accumulator += BigUint::from(numerator_base).pow(numerator_exponent)
            << (common_denominator_exponent - denominator_exponent);
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ExactAlgebraicChallengeFamily {
        CommonThetaProductVectors {
            challenge_groups: Vec<CommonProofApplicationChallengeGroup>,
        },
        CommonComposition,
        CommonOutOfDomainPoint(CommonProofChallenge),
        RowCodeWhirPointSelectorAndPhaseRow,
        RowCodeWhirBoundOpening,
        RowCodeWhirOpeningBatchMask,
        RowCodeWhirBoundDegreeCoordinate,
        WhirFold {
            round_ordinal: usize,
        },
        WhirQueryCombination {
            round_ordinal: usize,
        },
        WhirFinalSumcheck {
            round_count: usize,
        },
        WhirScalarOpeningBatch,
        PhaseOpeningReduction,
        BoundOpeningReduction,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ExactAlgebraicFailureEvent {
        SameSecretIntegerLift,
        WhirFold,
        WhirQueryCombination,
        WhirFinalSumcheck,
        WhirScalarOpeningBatch,
        OutOfDomainPointForbiddenSet,
        RelationCompositionBatch,
        PackedPhaseSelectorAndRows,
        BoundOpeningBatch,
        OpeningBatchMask,
        PhaseOpeningReductionExceptionalSet,
        BoundOpeningReductionExceptionalSet,
        BoundDegreeSuffix,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ExactAlgebraicSampleSpace {
        ChallengeExtensionField,
        IndependentBaseFieldProduct {
            coordinate_modulus: u64,
            independent_repetition_count: u16,
        },
        OutOfDomainAcceptedCandidates {
            field_cardinality: BigUint,
            accepted_candidate_count_floor: BigUint,
            challenge_field_numerator_ceiling: BigUint,
        },
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ExactAlgebraicSoundnessRow {
        challenge: ExactAlgebraicChallengeFamily,
        event: ExactAlgebraicFailureEvent,
        independent_bad_polynomial_degrees: Vec<u64>,
        multiplicity: u64,
        sample_space: ExactAlgebraicSampleSpace,
    }

    impl ExactAlgebraicSoundnessRow {
        fn extension_field(
            challenge: ExactAlgebraicChallengeFamily,
            event: ExactAlgebraicFailureEvent,
            degree: u64,
            multiplicity: u64,
        ) -> Self {
            Self {
                challenge,
                event,
                independent_bad_polynomial_degrees: vec![degree],
                multiplicity,
                sample_space: ExactAlgebraicSampleSpace::ChallengeExtensionField,
            }
        }

        fn raw_numerator(&self) -> BigUint {
            self.independent_bad_polynomial_degrees
                .iter()
                .copied()
                .map(BigUint::from)
                .fold(BigUint::from(1_u8), |product, degree| product * degree)
                * BigUint::from(self.multiplicity)
        }

        fn challenge_field_numerator(&self, challenge_field_order: &BigUint) -> BigUint {
            let raw_numerator = self.raw_numerator();
            match &self.sample_space {
                ExactAlgebraicSampleSpace::ChallengeExtensionField => {
                    assert_eq!(self.independent_bad_polynomial_degrees.len(), 1);
                    raw_numerator
                }
                ExactAlgebraicSampleSpace::IndependentBaseFieldProduct {
                    coordinate_modulus,
                    independent_repetition_count,
                } => {
                    assert_eq!(
                        self.independent_bad_polynomial_degrees.len(),
                        usize::from(*independent_repetition_count)
                    );
                    assert_eq!(
                        BigUint::from(*coordinate_modulus)
                            .pow(u32::from(*independent_repetition_count)),
                        *challenge_field_order,
                        "the theta product sampler must have the common algebraic denominator"
                    );
                    raw_numerator
                }
                ExactAlgebraicSampleSpace::OutOfDomainAcceptedCandidates {
                    field_cardinality,
                    accepted_candidate_count_floor,
                    challenge_field_numerator_ceiling,
                } => {
                    assert_eq!(field_cardinality, challenge_field_order);
                    assert!(accepted_candidate_count_floor > &BigUint::from(0_u8));
                    assert!(
                        &raw_numerator * field_cardinality
                            <= challenge_field_numerator_ceiling * accepted_candidate_count_floor,
                        "the source-derived out-of-domain accepted set must imply its field-denominator ceiling"
                    );
                    challenge_field_numerator_ceiling.clone()
                }
            }
        }

        fn challenge_matches_event(&self) -> bool {
            matches!(
                (&self.challenge, self.event),
                (
                    ExactAlgebraicChallengeFamily::CommonThetaProductVectors { .. },
                    ExactAlgebraicFailureEvent::SameSecretIntegerLift,
                ) | (
                    ExactAlgebraicChallengeFamily::CommonComposition,
                    ExactAlgebraicFailureEvent::RelationCompositionBatch,
                ) | (
                    ExactAlgebraicChallengeFamily::CommonOutOfDomainPoint(
                        CommonProofChallenge::OutOfDomainPoint { point_ordinal: 0 },
                    ),
                    ExactAlgebraicFailureEvent::OutOfDomainPointForbiddenSet,
                ) | (
                    ExactAlgebraicChallengeFamily::RowCodeWhirPointSelectorAndPhaseRow,
                    ExactAlgebraicFailureEvent::PackedPhaseSelectorAndRows,
                ) | (
                    ExactAlgebraicChallengeFamily::RowCodeWhirBoundOpening,
                    ExactAlgebraicFailureEvent::BoundOpeningBatch,
                ) | (
                    ExactAlgebraicChallengeFamily::RowCodeWhirOpeningBatchMask,
                    ExactAlgebraicFailureEvent::OpeningBatchMask,
                ) | (
                    ExactAlgebraicChallengeFamily::RowCodeWhirBoundDegreeCoordinate,
                    ExactAlgebraicFailureEvent::BoundDegreeSuffix,
                ) | (
                    ExactAlgebraicChallengeFamily::WhirFold { .. },
                    ExactAlgebraicFailureEvent::WhirFold,
                ) | (
                    ExactAlgebraicChallengeFamily::WhirQueryCombination { .. },
                    ExactAlgebraicFailureEvent::WhirQueryCombination,
                ) | (
                    ExactAlgebraicChallengeFamily::WhirFinalSumcheck { .. },
                    ExactAlgebraicFailureEvent::WhirFinalSumcheck,
                ) | (
                    ExactAlgebraicChallengeFamily::WhirScalarOpeningBatch,
                    ExactAlgebraicFailureEvent::WhirScalarOpeningBatch,
                ) | (
                    ExactAlgebraicChallengeFamily::PhaseOpeningReduction,
                    ExactAlgebraicFailureEvent::PhaseOpeningReductionExceptionalSet,
                ) | (
                    ExactAlgebraicChallengeFamily::BoundOpeningReduction,
                    ExactAlgebraicFailureEvent::BoundOpeningReductionExceptionalSet,
                )
            )
        }
    }

    fn assert_without_replacement_probability_is_bounded_by_power(
        accepting_population: u64,
        complete_population: u64,
        query_count: u32,
    ) {
        assert!(u64::from(query_count) <= accepting_population);
        assert!(accepting_population <= complete_population);
        let accepting_falling_factorial = (0..u64::from(query_count))
            .fold(BigUint::from(1_u8), |product, query_ordinal| {
                product * (accepting_population - query_ordinal)
            });
        let complete_falling_factorial = (0..u64::from(query_count))
            .fold(BigUint::from(1_u8), |product, query_ordinal| {
                product * (complete_population - query_ordinal)
            });
        assert!(
            accepting_falling_factorial * BigUint::from(complete_population).pow(query_count)
                <= BigUint::from(accepting_population).pow(query_count)
                    * complete_falling_factorial
        );
    }

    const RECOMPUTED_RESPONSE_ROOT: bool = true;
    const SUPPLIED_COMMITMENT_ROOT: bool = false;

    #[derive(Clone, Copy, Debug)]
    struct StaticTranscriptCounter {
        hash_query_count: u64,
        logical_verifier_message_count: u64,
        pending_challenge: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StaticTranscriptAccounting {
        maximum_hash_query_count: u64,
        logical_verifier_message_count: u64,
    }

    impl StaticTranscriptCounter {
        const fn after_common_handoff(
            hash_query_count: u64,
            logical_verifier_message_count: u64,
        ) -> Self {
            Self {
                hash_query_count,
                logical_verifier_message_count,
                pending_challenge: false,
            }
        }

        fn challenge(&mut self, hash_query_count: u64) {
            assert!(hash_query_count > 0);
            if self.pending_challenge {
                self.hash_query_count += 1;
            }
            self.hash_query_count += hash_query_count;
            self.logical_verifier_message_count += 1;
            self.pending_challenge = true;
        }

        /// The catalog charges one chain-predecessor equation, one optional
        /// recomputed-root equation, and one absorption equation for every
        /// typed response. The chain predecessor is an accepted-challenge
        /// equation when a challenge is pending and a response-binding
        /// equation otherwise, so the per-response charge is `2 + root`
        /// regardless of the pending state. A supplied commitment root is not
        /// recomputed and therefore carries no root equation.
        fn response(&mut self, response_root_is_recomputed: bool) {
            self.hash_query_count += 2 + u64::from(response_root_is_recomputed);
            self.pending_challenge = false;
        }

        fn finish(self) -> StaticTranscriptAccounting {
            assert!(!self.pending_challenge);
            StaticTranscriptAccounting {
                maximum_hash_query_count: self.hash_query_count,
                logical_verifier_message_count: self.logical_verifier_message_count,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct NestedParentHashCounts {
        input_query_tree_count: usize,
        output_query_tree_count: usize,
    }

    impl NestedParentHashCounts {
        const fn weighted_count(self) -> usize {
            EXACT_INPUT_BOUND_TREE_COUNT * self.input_query_tree_count
                + EXACT_OUTPUT_BOUND_TREE_COUNT * self.output_query_tree_count
        }
    }

    fn nested_bit_reversed_parent_hash_counts(
        tree_height: usize,
        input_query_count: usize,
        output_query_count: usize,
    ) -> NestedParentHashCounts {
        assert!(input_query_count <= output_query_count);
        assert!(output_query_count <= 1_usize << tree_height);
        let reverse_shift = usize::BITS as usize - tree_height;
        let output_indices = (0..output_query_count)
            .map(|ordinal| ordinal.reverse_bits() >> reverse_shift)
            .collect::<BTreeSet<_>>();
        let input_indices = (0..input_query_count)
            .map(|ordinal| ordinal.reverse_bits() >> reverse_shift)
            .collect::<BTreeSet<_>>();
        assert!(input_indices.is_subset(&output_indices));

        let parent_hash_count = |indices: &BTreeSet<usize>| {
            (1..=tree_height)
                .map(|level| {
                    indices
                        .iter()
                        .map(|index| index >> level)
                        .collect::<BTreeSet<_>>()
                        .len()
                })
                .sum()
        };
        NestedParentHashCounts {
            input_query_tree_count: parent_hash_count(&input_indices),
            output_query_tree_count: parent_hash_count(&output_indices),
        }
    }

    fn maximum_parent_hash_count(tree_height: usize, query_count: usize) -> usize {
        (0..tree_height)
            .map(|depth| query_count.min(1_usize << depth))
            .sum()
    }

    fn exact_transcript_accounting(
        variant: &RelationPlanVariant,
        relation_context: &crate::bgv::proof_suite::RelationPlanCheckContext,
    ) -> StaticTranscriptAccounting {
        let schedule = variant
            .common_proof_relation_prefix_schedule(relation_context)
            .expect("derive exact transcript schedule")
            .into_row_code_whir_successor()
            .expect("derive exact successor transcript schedule");
        let common_handoff_count = schedule
            .maximum_row_code_whir_handoff_hash_query_count()
            .expect("derive exact common-prefix hash-query ceiling");
        assert_eq!(common_handoff_count, 1_128_593);
        let common_logical_verifier_message_count = schedule
            .maximum_row_code_whir_handoff_logical_verifier_message_count()
            .expect("derive exact common-prefix verifier-message count");
        assert_eq!(common_logical_verifier_message_count, 4_410);

        let base_layout = ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::BaseOracle)
            .expect("derive exact base layout");
        let auxiliary_layout =
            ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::AuxiliaryOracle)
                .expect("derive exact auxiliary layout");
        let phase_row_challenge_count = base_layout
            .rows
            .iter()
            .chain(&auxiliary_layout.rows)
            .map(|row| row.opening_point_ordinals.len())
            .sum::<usize>();
        assert_eq!(phase_row_challenge_count, 524);
        let maximum_extension_hash_query_count = 2 * u64::from(
            crate::bgv::proof_suite::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        ) - 1;

        let mut counter = StaticTranscriptCounter::after_common_handoff(
            common_handoff_count,
            common_logical_verifier_message_count,
        );
        // The pinned WHIR domain separator is one typed response whose root the
        // verifier recomputes.
        counter.response(RECOMPUTED_RESPONSE_ROOT);

        let point_row_challenge_count = 9 + phase_row_challenge_count + 2;
        let precommit_challenge_count = point_row_challenge_count + EXACT_BOUND_COLUMN_COUNT;
        for _ in 0..precommit_challenge_count {
            counter.challenge(maximum_extension_hash_query_count);
        }
        // The aggregate commitment supplies its root.
        counter.response(SUPPLIED_COMMITMENT_ROOT);

        // Every distinct output owns 16 directly addressed 512-bit blocks at
        // the pinned D=128 draw ceiling, in addition to one typed chain handle.
        counter.challenge(exact_distinct_query_hash_count(EXACT_COLUMN_QUERY_COUNT));
        counter.challenge(exact_distinct_query_hash_count(
            EXACT_OUTPUT_BOUND_QUERY_COUNT,
        ));
        let bound_degree_random_coordinate_count = bound_degree_random_coordinate_count();
        assert_eq!(bound_degree_random_coordinate_count, 50);
        for _ in 0..bound_degree_random_coordinate_count {
            counter.challenge(maximum_extension_hash_query_count);
        }

        let pcs = plain_aggregate_pcs(EXACT_PCS_VARIABLE_COUNT)
            .expect("construct exact plain WHIR configuration");
        for _ in 0..pcs.commitment_ood_samples {
            counter.challenge(maximum_extension_hash_query_count);
            counter.response(RECOMPUTED_RESPONSE_ROOT);
        }
        let explicit_point_count = selected_expected_opening_widths().len();
        assert_eq!(explicit_point_count, 1_008);
        for _ in 0..explicit_point_count {
            counter.response(RECOMPUTED_RESPONSE_ROOT);
            counter.response(RECOMPUTED_RESPONSE_ROOT);
        }
        counter.challenge(maximum_extension_hash_query_count);

        for _ in 0..pcs.round_folding_factor(0) {
            counter.response(RECOMPUTED_RESPONSE_ROOT);
            counter.challenge(maximum_extension_hash_query_count);
        }
        for round_index in 0..pcs.n_rounds() {
            let round = &pcs.round_parameters[round_index];
            // Each WHIR round commitment supplies its root.
            counter.response(SUPPLIED_COMMITMENT_ROOT);
            for _ in 0..round.ood_samples {
                counter.challenge(maximum_extension_hash_query_count);
                counter.response(RECOMPUTED_RESPONSE_ROOT);
            }
            counter.challenge(maximum_extension_hash_query_count);
            counter.challenge(exact_distinct_query_hash_count(round.num_queries));
            counter.challenge(maximum_extension_hash_query_count);
            for _ in 0..pcs.round_folding_factor(round_index + 1) {
                counter.response(RECOMPUTED_RESPONSE_ROOT);
                counter.challenge(maximum_extension_hash_query_count);
            }
        }
        counter.response(RECOMPUTED_RESPONSE_ROOT);
        counter.challenge(exact_distinct_query_hash_count(pcs.final_queries));
        for _ in 0..pcs.final_sumcheck_rounds {
            counter.response(RECOMPUTED_RESPONSE_ROOT);
            counter.challenge(maximum_extension_hash_query_count);
        }
        counter.response(RECOMPUTED_RESPONSE_ROOT);
        counter.finish()
    }

    fn exact_distinct_query_hash_count(output_count: usize) -> u64 {
        let candidates_per_block = Hash512::BYTE_LENGTH / std::mem::size_of::<u64>();
        let blocks_per_output = usize::try_from(
            crate::bgv::proof_suite::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        )
        .expect("the candidate ceiling fits usize")
        .div_ceil(candidates_per_block);
        1 + u64::try_from(output_count).expect("the exact query count fits u64")
            * u64::try_from(blocks_per_output).expect("the block count fits u64")
    }

    #[test]
    fn exact_distinct_query_block_ledger_is_directly_recomputed() {
        assert_eq!(exact_distinct_query_hash_count(387), 6_193);
        assert_eq!(exact_distinct_query_hash_count(266), 4_257);
        assert_eq!(exact_distinct_query_hash_count(288), 4_609);
        assert_eq!(exact_distinct_query_hash_count(268), 4_289);
        assert_eq!(exact_distinct_query_hash_count(264), 4_225);
        assert_eq!(exact_distinct_query_hash_count(263), 4_209);
        assert_eq!(
            [387_usize, 266, 387, 288, 268, 264, 263]
                .into_iter()
                .map(exact_distinct_query_hash_count)
                .sum::<u64>(),
            33_975
        );
    }

    pub(super) fn exact_public_sampler_exhaustion_catalog(
        pcs: &PlainAggregatePcs,
        variant: &RelationPlanVariant,
        relation_context: &crate::bgv::proof_suite::RelationPlanCheckContext,
        shape: ExactProofShape,
    ) -> PublicSamplerExhaustionCatalog {
        let schedule = variant
            .common_proof_relation_prefix_schedule(relation_context)
            .expect("derive the exact common-proof transcript schedule")
            .into_row_code_whir_successor()
            .expect("derive the exact successor transcript schedule");
        let out_of_domain_point_cardinality_bounds = (0..relation_context
            .out_of_domain_point_count)
            .map(|point_ordinal| {
                variant
                    .out_of_domain_point_sampler_cardinality_bound(relation_context, point_ordinal)
                    .expect("derive an exact out-of-domain sampler cardinality bound")
            })
            .collect::<Vec<_>>();
        let mut catalog = schedule
            .row_code_whir_handoff_public_sampler_exhaustion_catalog(
                SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier(),
                &out_of_domain_point_cardinality_bounds,
            )
            .expect("derive the exact common-prefix public sampler catalog");
        let maximum_candidate_draws_per_output = schedule.maximum_candidate_draws_per_output();

        let base_layout = ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::BaseOracle)
            .expect("derive the exact base phase layout");
        let auxiliary_layout =
            ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::AuxiliaryOracle)
                .expect("derive the exact auxiliary phase layout");
        let opening_point_count = variant.ordered_opening_points().len();
        let point_selector_count = EXACT_TABLE_VARIABLE_COUNT
            .checked_sub(1)
            .and_then(|remaining| {
                remaining.checked_sub(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT.ilog2() as usize)
            })
            .expect("derive the exact point-selector count");
        for opening_point_ordinal in 0..opening_point_count {
            let opening_point_ordinal =
                u16::try_from(opening_point_ordinal).expect("opening-point ordinal fits u16");
            for selector_ordinal in 0..point_selector_count {
                catalog
                    .push_direct_row_code_whir_extension(
                        RowCodeWhirChallenge::PointSelectorWeight {
                            opening_point_ordinal,
                            selector_ordinal: u16::try_from(selector_ordinal)
                                .expect("selector ordinal fits u16"),
                        },
                        maximum_candidate_draws_per_output,
                    )
                    .expect("catalog an exact point-selector sampler");
            }
            for (phase, layout) in [
                (RowCodeWhirTracePhase::Base, &base_layout),
                (RowCodeWhirTracePhase::Auxiliary, &auxiliary_layout),
            ] {
                for (column_group_ordinal, row) in layout.rows.iter().enumerate() {
                    if row
                        .opening_point_ordinals
                        .contains(&u32::from(opening_point_ordinal))
                    {
                        catalog
                            .push_direct_row_code_whir_extension(
                                RowCodeWhirChallenge::TraceColumnGroupWeight {
                                    opening_point_ordinal,
                                    phase,
                                    column_group_ordinal: u32::try_from(column_group_ordinal)
                                        .expect("column-group ordinal fits u32"),
                                },
                                maximum_candidate_draws_per_output,
                            )
                            .expect("catalog an exact phase-row sampler");
                    }
                }
            }
            if opening_point_ordinal == 0 {
                for challenge in [
                    RowCodeWhirChallenge::QuotientGroupWeight {
                        opening_point_ordinal,
                        source_group_ordinal: 0,
                    },
                    RowCodeWhirChallenge::OpeningBatchMaskWeight {
                        opening_point_ordinal,
                    },
                ] {
                    catalog
                        .push_direct_row_code_whir_extension(
                            challenge,
                            maximum_candidate_draws_per_output,
                        )
                        .expect("catalog an exact quotient-phase sampler");
                }
            }
        }

        let mut bound_column_ordinals = BTreeSet::new();
        for claim in variant.ordered_opening_claims() {
            if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
                continue;
            }
            let column_ordinal = claim
                .column_ordinal()
                .expect("an exact tree opening has a column ordinal");
            let column = variant
                .ordered_columns()
                .get(usize::try_from(column_ordinal).expect("column ordinal fits usize"))
                .expect("an exact opening references a relation column");
            if !matches!(column.origin(), RelationColumnOrigin::BoundTree { .. }) {
                continue;
            }
            assert!(
                bound_column_ordinals.insert(column_ordinal),
                "each exact bound column has one opening claim"
            );
            catalog
                .push_direct_row_code_whir_extension(
                    RowCodeWhirChallenge::BoundOpeningWeight { column_ordinal },
                    maximum_candidate_draws_per_output,
                )
                .expect("catalog an exact bound-opening sampler");
        }
        assert_eq!(bound_column_ordinals.len(), EXACT_BOUND_COLUMN_COUNT);

        catalog
            .push_direct_row_code_whir_distinct(
                RowCodeWhirChallenge::OuterQueryVector,
                shape.encoded_column_count,
                EXACT_COLUMN_QUERY_COUNT,
                maximum_candidate_draws_per_output,
            )
            .expect("catalog the exact outer query vector");
        catalog
            .push_direct_row_code_whir_distinct(
                RowCodeWhirChallenge::BoundQueryVector,
                EXACT_BOUND_LEAF_COUNT,
                EXACT_OUTPUT_BOUND_QUERY_COUNT,
                maximum_candidate_draws_per_output,
            )
            .expect("catalog the exact bound query vector");

        let block_selector_variable_count =
            EXACT_TABLE_VARIABLE_COUNT - EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT;
        for (block_ordinal, schedule) in EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES.iter().enumerate() {
            for (suffix_ordinal, fixed_prefix) in schedule.degree_suffix_prefixes.iter().enumerate()
            {
                for coordinate_ordinal in
                    block_selector_variable_count + fixed_prefix.len()..EXACT_TABLE_VARIABLE_COUNT
                {
                    catalog
                        .push_direct_row_code_whir_extension(
                            RowCodeWhirChallenge::BoundDegreeCoordinate {
                                block_ordinal: u16::try_from(block_ordinal)
                                    .expect("bound block ordinal fits u16"),
                                degree_test_ordinal: u16::try_from(suffix_ordinal + 1)
                                    .expect("bound degree-test ordinal fits u16"),
                                coordinate_ordinal: u16::try_from(coordinate_ordinal)
                                    .expect("bound coordinate ordinal fits u16"),
                            },
                            maximum_candidate_draws_per_output,
                        )
                        .expect("catalog an exact bound-degree sampler");
                }
            }
        }

        extend_plain_aggregate_public_sampler_exhaustion_catalog(
            &mut catalog,
            pcs,
            maximum_candidate_draws_per_output,
        )
        .expect("extend the exact public sampler catalog through plain WHIR");
        catalog
    }

    fn exact_algebraic_soundness_catalog(
        pcs: &PlainAggregatePcs,
        variant: &RelationPlanVariant,
        relation_context: &crate::bgv::proof_suite::RelationPlanCheckContext,
        shape: ExactProofShape,
    ) -> Vec<ExactAlgebraicSoundnessRow> {
        let transcript_schedule = variant
            .common_proof_relation_prefix_schedule(relation_context)
            .expect("derive the exact common-proof transcript schedule")
            .into_row_code_whir_successor()
            .expect("derive the exact successor transcript schedule");
        let theta_challenge_groups = transcript_schedule
            .ordered_application_challenge_groups()
            .iter()
            .copied()
            .filter(|group| matches!(group.challenge(), CommonProofChallenge::Theta { .. }))
            .collect::<Vec<_>>();
        assert_eq!(
            theta_challenge_groups
                .iter()
                .map(|group| (group.challenge(), group.modulus(), group.coordinate_count(),))
                .collect::<Vec<_>>(),
            [
                (
                    CommonProofChallenge::Theta { modulus_ordinal: 0 },
                    GOLDILOCKS_MODULUS,
                    5,
                ),
                (
                    CommonProofChallenge::Theta { modulus_ordinal: 1 },
                    GOLDILOCKS_MODULUS,
                    5,
                ),
                (
                    CommonProofChallenge::Theta { modulus_ordinal: 2 },
                    GOLDILOCKS_MODULUS,
                    5,
                ),
            ],
            "the live transcript must sample three five-coordinate base-field theta vectors"
        );

        let theta_challenges = theta_challenge_groups
            .iter()
            .map(|group| group.challenge())
            .collect::<BTreeSet<_>>();
        let mut theta_degrees_by_repetition =
            BTreeMap::<u16, BTreeMap<CommonProofChallenge, u64>>::new();
        for batch in variant.ordered_integer_lift_batches() {
            let challenge = CommonProofChallenge::Theta {
                modulus_ordinal: variant
                    .non_native_modulus_ordinal(batch.modulus_reference())
                    .expect("derive the exact theta modulus ordinal"),
            };
            assert!(theta_challenges.contains(&challenge));
            let degree = batch
                .theta_bad_polynomial_degree(variant.trace_domain_size())
                .expect("derive the exact theta bad-polynomial degree");
            assert!(
                theta_degrees_by_repetition
                    .entry(batch.challenge_ordinal())
                    .or_default()
                    .insert(challenge, degree)
                    .is_none(),
                "a theta modulus row may occur only once in one repetition"
            );
        }
        let theta_repetition_count = theta_challenge_groups
            .first()
            .expect("the exact same-secret relation has a theta group")
            .coordinate_count();
        let theta_coordinate_modulus = theta_challenge_groups
            .first()
            .expect("the exact same-secret relation has a theta group")
            .modulus();
        assert_eq!(
            theta_repetition_count,
            relation_context.non_native_theta_repetition_count
        );
        assert_eq!(
            theta_degrees_by_repetition
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            (0..theta_repetition_count).collect::<Vec<_>>(),
            "the integer-lift relation must consume every sampled theta repetition"
        );
        let theta_epoch_maximum_degrees = theta_degrees_by_repetition
            .values()
            .map(|degrees_by_challenge| {
                assert_eq!(
                    degrees_by_challenge
                        .keys()
                        .copied()
                        .collect::<BTreeSet<_>>(),
                    theta_challenges,
                    "each theta repetition must cover all three exact modulus rows"
                );
                assert_eq!(
                    degrees_by_challenge.values().copied().collect::<Vec<_>>(),
                    [32_766, 32_766, 32_766],
                    "the theta degrees must remain derived from the three live integer-lift rows"
                );
                degrees_by_challenge
                    .values()
                    .copied()
                    .max()
                    .expect("one theta repetition has a modulus row")
            })
            .collect::<Vec<_>>();
        assert_eq!(theta_epoch_maximum_degrees, [32_766; 5]);

        // Conditional same-secret extraction premise: a false prechallenge
        // assignment fixes one nonzero modulus row before each theta epoch.
        // Every epoch therefore pays the maximum of its three row degrees,
        // while acceptance requires all five independent base-field
        // repetitions to vanish. The live product sampler has denominator
        // p^5; the extension degree happens to be five too, but is not the
        // source of this exponent.
        let mut rows = vec![ExactAlgebraicSoundnessRow {
            challenge: ExactAlgebraicChallengeFamily::CommonThetaProductVectors {
                challenge_groups: theta_challenge_groups,
            },
            event: ExactAlgebraicFailureEvent::SameSecretIntegerLift,
            independent_bad_polynomial_degrees: theta_epoch_maximum_degrees,
            multiplicity: 1,
            sample_space: ExactAlgebraicSampleSpace::IndependentBaseFieldProduct {
                coordinate_modulus: theta_coordinate_modulus,
                independent_repetition_count: theta_repetition_count,
            },
        }];

        for (round_ordinal, round) in pcs.round_parameters.iter().enumerate() {
            // WHIR Theorem 5.2 charges d * ell / |K| for one folding
            // challenge, with d = max(d*, 3). The selected construction has
            // ell = 1 and d* <= 3, so the conservative numerator is the
            // round-domain size plus three rather than plus two.
            rows.push(ExactAlgebraicSoundnessRow::extension_field(
                ExactAlgebraicChallengeFamily::WhirFold { round_ordinal },
                ExactAlgebraicFailureEvent::WhirFold,
                u64::try_from(round.domain_size).expect("WHIR fold domain size fits u64") + 3,
                1,
            ));
            rows.push(ExactAlgebraicSoundnessRow::extension_field(
                ExactAlgebraicChallengeFamily::WhirQueryCombination { round_ordinal },
                ExactAlgebraicFailureEvent::WhirQueryCombination,
                2,
                u64::try_from(round.num_queries).expect("WHIR query count fits u64"),
            ));
        }
        let final_round_ordinal = pcs.n_rounds();
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::WhirFold {
                round_ordinal: final_round_ordinal,
            },
            ExactAlgebraicFailureEvent::WhirFold,
            u64::try_from(pcs.final_round_config().domain_size)
                .expect("final WHIR fold domain size fits u64")
                + 3,
            1,
        ));
        // Each final-sumcheck wire message carries h(0) and h(infinity),
        // while the verifier derives h(1) from the claimed sum and performs
        // quadratic interpolation. A false round identity can therefore have
        // two challenge roots. Charge that degree for every compiled round;
        // charging only the round count as one polynomial would miss the
        // quadratic factor.
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::WhirFinalSumcheck {
                round_count: pcs.final_sumcheck_rounds,
            },
            ExactAlgebraicFailureEvent::WhirFinalSumcheck,
            2,
            u64::try_from(pcs.final_sumcheck_rounds)
                .expect("final WHIR sumcheck round count fits u64"),
        ));

        let scalar_opening_count = selected_expected_opening_widths()
            .into_iter()
            .sum::<usize>();
        assert_eq!(scalar_opening_count, 1_782);
        // This is a conservative union over every scalar opening carried by
        // the adapter. No tighter simultaneous-opening extraction is assumed.
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::WhirScalarOpeningBatch,
            ExactAlgebraicFailureEvent::WhirScalarOpeningBatch,
            u64::try_from(scalar_opening_count).expect("scalar opening count fits u64"),
            1,
        ));

        let out_of_domain_point_ordinal = 0_u16;
        let out_of_domain_cardinality_bound = variant
            .out_of_domain_point_sampler_cardinality_bound(
                relation_context,
                out_of_domain_point_ordinal,
            )
            .expect("derive the exact out-of-domain accepted-candidate floor");
        // Derive the degree of the source-owned cross-multiplied common
        // relation identity from the checked numerator and zeroifier grammar
        // plus the quotient-component reconstruction. The 2^21 term below is
        // a conservative field-denominator ceiling proved from the live
        // accepted set; it is not the similarly sized evaluation domain.
        let out_of_domain_identity_degree = variant
            .cross_multiplied_composition_identity_degree_bound(relation_context)
            .expect("derive the exact cross-multiplied composition identity degree");
        let out_of_domain_challenge_field_numerator_ceiling = BigUint::from(1_u8) << 21_usize;
        rows.push(ExactAlgebraicSoundnessRow {
            challenge: ExactAlgebraicChallengeFamily::CommonOutOfDomainPoint(
                CommonProofChallenge::OutOfDomainPoint {
                    point_ordinal: out_of_domain_point_ordinal,
                },
            ),
            event: ExactAlgebraicFailureEvent::OutOfDomainPointForbiddenSet,
            independent_bad_polynomial_degrees: vec![out_of_domain_identity_degree],
            multiplicity: 1,
            sample_space: ExactAlgebraicSampleSpace::OutOfDomainAcceptedCandidates {
                field_cardinality: out_of_domain_cardinality_bound.field_cardinality().clone(),
                accepted_candidate_count_floor: out_of_domain_cardinality_bound
                    .accepted_candidate_count_floor()
                    .clone(),
                challenge_field_numerator_ceiling: out_of_domain_challenge_field_numerator_ceiling,
            },
        });

        assert_eq!(variant.constraint_count(), 4_406);
        // Independent composition weights turn the first false constraint
        // into one nonzero linear equation, not a constraint-count union.
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::CommonComposition,
            ExactAlgebraicFailureEvent::RelationCompositionBatch,
            1,
            1,
        ));

        let phase_opening_point_count = variant.ordered_opening_points().len();
        assert_eq!(phase_opening_point_count, 3);
        let point_selector_count = EXACT_TABLE_VARIABLE_COUNT
            .checked_sub(1)
            .and_then(|remaining| {
                remaining.checked_sub(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT.ilog2() as usize)
            })
            .expect("derive exact point-selector count");
        assert_eq!(point_selector_count, 3);
        // Each of the three point equations is cubic in its selector vector
        // and linear in its independently sampled row weight.
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::RowCodeWhirPointSelectorAndPhaseRow,
            ExactAlgebraicFailureEvent::PackedPhaseSelectorAndRows,
            u64::try_from(point_selector_count + 1).expect("packed selector degree fits u64"),
            u64::try_from(phase_opening_point_count).expect("phase opening-point count fits u64"),
        ));

        let bound_opening_count = variant
            .ordered_opening_claims()
            .iter()
            .filter(|claim| {
                claim
                    .column_ordinal()
                    .and_then(|column_ordinal| {
                        variant
                            .ordered_columns()
                            .get(usize::try_from(column_ordinal).ok()?)
                    })
                    .is_some_and(|column| {
                        matches!(column.origin(), RelationColumnOrigin::BoundTree { .. })
                    })
            })
            .count();
        assert_eq!(bound_opening_count, EXACT_BOUND_COLUMN_COUNT);
        // As with composition, the first false bound claim gives one nonzero
        // linear equation in the independent bound-opening weights.
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::RowCodeWhirBoundOpening,
            ExactAlgebraicFailureEvent::BoundOpeningBatch,
            1,
            1,
        ));
        // The mask chunks are values of an already-bound polynomial. Their
        // deterministic reconstruction adds no challenge-root event.
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::RowCodeWhirOpeningBatchMask,
            ExactAlgebraicFailureEvent::OpeningBatchMask,
            0,
            u64::try_from(EXACT_OPENING_BATCH_MASK_CHUNK_COUNT)
                .expect("opening-batch mask chunk count fits u64"),
        ));

        // Conditional extraction hypothesis: after the three authenticated
        // phase roots are bound and extracted, every false phase opening fixes
        // a nonzero reduction polynomial of degree below the encoded column
        // domain before its opening point is sampled.
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::PhaseOpeningReduction,
            ExactAlgebraicFailureEvent::PhaseOpeningReductionExceptionalSet,
            u64::try_from(shape.encoded_column_count).expect("encoded phase column count fits u64"),
            u64::try_from(phase_opening_point_count).expect("phase opening-point count fits u64"),
        ));

        // The exact 18,431- and 16,383-coefficient quotient blocks each
        // authenticate paired leaves from one complete 2^21-point codeword.
        // BCIKS contributes one exceptional set per block at that complete
        // domain degree, not separate 2^20 events for the point and its
        // opposite.
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES
                .map(|schedule| schedule.quotient_degree_bound_exclusive),
            [18_431, 16_383],
        );
        let bound_encoded_domain_size = EXACT_BOUND_LEAF_COUNT
            .checked_mul(2)
            .expect("bound encoded domain size fits usize");
        assert_eq!(bound_encoded_domain_size, shape.encoded_column_count);
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::BoundOpeningReduction,
            ExactAlgebraicFailureEvent::BoundOpeningReductionExceptionalSet,
            u64::try_from(bound_encoded_domain_size).expect("bound encoded domain size fits u64"),
            u64::try_from(EXACT_BOUND_REDUCTION_BLOCK_COUNT)
                .expect("bound reduction block count fits u64"),
        ));

        // The input block samples 13 + 12 + 11 coordinates for its three
        // suffix subcubes. The output block samples 14 for its single [1]
        // suffix, giving 50 independent degree coordinates in total.
        let bound_degree_random_coordinate_count = bound_degree_random_coordinate_count();
        assert_eq!(bound_degree_random_coordinate_count, 50);
        rows.push(ExactAlgebraicSoundnessRow::extension_field(
            ExactAlgebraicChallengeFamily::RowCodeWhirBoundDegreeCoordinate,
            ExactAlgebraicFailureEvent::BoundDegreeSuffix,
            1,
            u64::try_from(bound_degree_random_coordinate_count)
                .expect("bound degree coordinate count fits u64"),
        ));
        rows
    }

    fn index_has_prefix(index: usize, variable_count: usize, prefix: &[u8]) -> bool {
        assert!(prefix.len() <= variable_count);
        prefix.iter().enumerate().all(|(bit_ordinal, expected)| {
            let shift = variable_count - 1 - bit_ordinal;
            ((index >> shift) & 1) as u8 == *expected
        })
    }

    #[test]
    fn bound_degree_subcubes_partition_the_complete_forbidden_suffix() {
        let block_coefficient_count = 1_usize << EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT;
        assert_eq!(EXACT_BOUND_DEGREE_TEST_COUNT, 6);
        assert_eq!(EXACT_BOUND_REDUCTION_BLOCK_SELECTOR_VARIABLE_COUNT, 1);
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[0].root_use,
            BoundTreeRootUse::Input
        );
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[0].source_degree_bound_exclusive,
            18_432
        );
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[0].quotient_degree_bound_exclusive,
            18_431
        );
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[0].degree_test_count(),
            4
        );
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[1].root_use,
            BoundTreeRootUse::Output
        );
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[1].source_degree_bound_exclusive,
            16_384
        );
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[1].quotient_degree_bound_exclusive,
            16_383
        );
        assert_eq!(
            EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[1].degree_test_count(),
            2
        );
        for (block_ordinal, schedule) in EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES
            .iter()
            .copied()
            .enumerate()
        {
            let mut covered_count = 0_usize;
            for coefficient_ordinal in 0..block_coefficient_count {
                let suffix_prefix_matches = schedule
                    .degree_suffix_prefixes
                    .iter()
                    .filter(|prefix| {
                        index_has_prefix(
                            coefficient_ordinal,
                            EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT,
                            prefix,
                        )
                    })
                    .count();
                let boundary_matches =
                    usize::from(coefficient_ordinal == schedule.quotient_degree_bound_exclusive);
                let cover_count = boundary_matches + suffix_prefix_matches;
                let should_be_covered =
                    coefficient_ordinal >= schedule.quotient_degree_bound_exclusive;
                assert_eq!(
                    cover_count,
                    usize::from(should_be_covered),
                    "wrong degree-test coverage in block {block_ordinal} at coefficient {coefficient_ordinal}"
                );
                covered_count += cover_count;
            }
            assert_eq!(
                covered_count,
                block_coefficient_count - schedule.quotient_degree_bound_exclusive
            );
        }
    }

    #[test]
    fn synthetic_division_enforces_every_bound_opening_identity() {
        let test_polynomials = [
            vec![ChallengeField::from_u64(17)],
            vec![ChallengeField::from_u64(9), ChallengeField::from_u64(23)],
            (0..37)
                .map(|coefficient_ordinal| {
                    if matches!(coefficient_ordinal, 0 | 1 | 7 | 19 | 36) {
                        ChallengeField::from_u64(coefficient_ordinal as u64 * 1_000_003 + 41)
                    } else {
                        ChallengeField::ZERO
                    }
                })
                .collect(),
        ];
        for (polynomial_ordinal, coefficients) in test_polynomials.iter().enumerate() {
            for opening_point in [
                ChallengeField::ZERO,
                ChallengeField::ONE,
                ChallengeField::from_u64(polynomial_ordinal as u64 * 97 + 13),
            ] {
                let claimed_value = evaluate_coefficients(coefficients, opening_point);
                let (quotient, remainder) = divide_polynomial_opening(
                    coefficients.len(),
                    |coefficient_ordinal| coefficients[coefficient_ordinal],
                    opening_point,
                    claimed_value,
                )
                .expect("divide a nonempty opening polynomial");
                assert_eq!(remainder, ChallengeField::ZERO);
                for check_point in [
                    opening_point,
                    ChallengeField::from_u64(5),
                    ChallengeField::from_u64(1_000_033),
                ] {
                    assert_eq!(
                        evaluate_coefficients(coefficients, check_point) - claimed_value,
                        (check_point - opening_point)
                            * evaluate_coefficients(&quotient, check_point)
                    );
                }

                let (_, wrong_remainder) = divide_polynomial_opening(
                    coefficients.len(),
                    |coefficient_ordinal| coefficients[coefficient_ordinal],
                    opening_point,
                    claimed_value + ChallengeField::ONE,
                )
                .expect("divide a nonempty opening polynomial");
                assert_ne!(wrong_remainder, ChallengeField::ZERO);
            }
        }
        assert!(
            divide_polynomial_opening(
                0,
                |_| ChallengeField::ZERO,
                ChallengeField::ONE,
                ChallengeField::ZERO,
            )
            .is_err()
        );
    }

    #[test]
    fn quotient_chunk_layout_reconstructs_component_and_batch_mask_openings() {
        fn evaluate_sparse(
            terms: &[(usize, ChallengeField)],
            point: ChallengeField,
        ) -> ChallengeField {
            terms
                .iter()
                .fold(ChallengeField::ZERO, |evaluation, (degree, coefficient)| {
                    evaluation + *coefficient * point.exp_u64(*degree as u64)
                })
        }

        fn evaluate_chunk(
            terms: &[(usize, ChallengeField)],
            chunk_ordinal: usize,
            point: ChallengeField,
        ) -> ChallengeField {
            let chunk_start = chunk_ordinal * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
            let chunk_end = chunk_start + LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
            terms
                .iter()
                .filter(|(degree, _)| *degree >= chunk_start && *degree < chunk_end)
                .fold(ChallengeField::ZERO, |evaluation, (degree, coefficient)| {
                    evaluation + *coefficient * point.exp_u64((degree - chunk_start) as u64)
                })
        }

        let opening_point = ChallengeField::new([
            Goldilocks::new(17),
            Goldilocks::new(1),
            Goldilocks::new(9),
            Goldilocks::new(0),
            Goldilocks::new(3),
        ]);
        let chunk_power = opening_point.exp_u64(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT as u64);
        let selectors = [
            ChallengeField::from_u64(3),
            ChallengeField::from_u64(7),
            ChallengeField::from_u64(11),
        ];
        let selector_weights = selector_equality_weights(selectors);
        let components = (0..EXACT_OPENING_BATCH_MASK_CHUNK_COUNT)
            .map(|component_ordinal| {
                vec![
                    (
                        component_ordinal,
                        ChallengeField::from_u64((component_ordinal * 13 + 5) as u64),
                    ),
                    (
                        LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT - 1 - component_ordinal,
                        ChallengeField::from_u64((component_ordinal * 17 + 11) as u64),
                    ),
                    (
                        LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT + component_ordinal,
                        ChallengeField::from_u64((component_ordinal * 19 + 23) as u64),
                    ),
                ]
            })
            .collect::<Vec<_>>();
        let packed_low_evaluation = components.iter().enumerate().fold(
            ChallengeField::ZERO,
            |evaluation, (component_ordinal, component)| {
                evaluation
                    + selector_weights[component_ordinal]
                        * evaluate_chunk(component, 0, opening_point)
            },
        );
        let packed_high_evaluation = components.iter().enumerate().fold(
            ChallengeField::ZERO,
            |evaluation, (component_ordinal, component)| {
                evaluation
                    + selector_weights[component_ordinal]
                        * evaluate_chunk(component, 1, opening_point)
            },
        );
        assert_eq!(
            packed_low_evaluation + chunk_power * packed_high_evaluation,
            components.iter().enumerate().fold(
                ChallengeField::ZERO,
                |evaluation, (component_ordinal, component)| {
                    evaluation
                        + selector_weights[component_ordinal]
                            * evaluate_sparse(component, opening_point)
                },
            )
        );

        let batch_mask = (0..EXACT_OPENING_BATCH_MASK_CHUNK_COUNT)
            .flat_map(|chunk_ordinal| {
                let chunk_start = chunk_ordinal * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
                [
                    (
                        chunk_start,
                        ChallengeField::from_u64((chunk_ordinal * 13 + 43) as u64),
                    ),
                    (
                        (chunk_start + LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT - 1).min(262_142),
                        ChallengeField::from_u64((chunk_ordinal * 17 + 47) as u64),
                    ),
                ]
            })
            .collect::<Vec<_>>();
        let mask_chunk_evaluations =
            core::array::from_fn::<_, EXACT_OPENING_BATCH_MASK_CHUNK_COUNT, _>(|chunk_ordinal| {
                evaluate_chunk(&batch_mask, chunk_ordinal, opening_point)
            });
        let packed_mask_evaluation = mask_chunk_evaluations.iter().enumerate().fold(
            ChallengeField::ZERO,
            |evaluation, (chunk_ordinal, chunk_evaluation)| {
                evaluation + selector_weights[chunk_ordinal] * *chunk_evaluation
            },
        );
        assert_eq!(
            packed_mask_evaluation,
            mask_chunk_evaluations.iter().enumerate().fold(
                ChallengeField::ZERO,
                |evaluation, (chunk_ordinal, chunk_evaluation)| {
                    evaluation + selector_weights[chunk_ordinal] * *chunk_evaluation
                },
            )
        );
        assert_eq!(
            mask_chunk_evaluations
                .iter()
                .fold(
                    (ChallengeField::ZERO, ChallengeField::ONE),
                    |(evaluation, power), chunk_evaluation| {
                        (evaluation + power * *chunk_evaluation, power * chunk_power)
                    },
                )
                .0,
            evaluate_sparse(&batch_mask, opening_point)
        );
    }

    #[test]
    fn three_uniform_selectors_bind_all_eight_packed_claims() {
        for selected_block_ordinal in 0..8 {
            let selectors = core::array::from_fn(|selector_ordinal| {
                let selector_bit = (selected_block_ordinal >> (2 - selector_ordinal)) & 1;
                ChallengeField::from_u64(selector_bit as u64)
            });
            let weights = selector_equality_weights(selectors);
            for (block_ordinal, weight) in weights.into_iter().enumerate() {
                assert_eq!(
                    weight,
                    if block_ordinal == selected_block_ordinal {
                        ChallengeField::ONE
                    } else {
                        ChallengeField::ZERO
                    }
                );
            }
        }
    }

    #[test]
    fn exact_transcript_hash_query_ceiling_is_source_derived() {
        let (capability, variant, relation_context) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        let construction_plan = capability.row_code_whir_construction_plan();
        let shape = validate_exact_same_secret_construction_plan(
            construction_plan,
            &variant,
            &relation_context,
            capability.relation_plan_hash(),
            capability.relation_plan_variant_hash(),
        )
        .expect("validate the exact production construction plan");
        let catalog_accounting = exact_same_secret_verifier_accounting(construction_plan, shape)
            .expect("derive exact catalog-owned verifier accounting");
        let independently_recomputed_accounting =
            exact_transcript_accounting(&variant, &relation_context);
        assert_eq!(
            independently_recomputed_accounting.maximum_hash_query_count,
            catalog_accounting.maximum_transcript_hash_query_count
        );
        assert_eq!(
            independently_recomputed_accounting.logical_verifier_message_count,
            catalog_accounting.logical_verifier_message_count
        );
        // Both the plan-derived oracle-equation catalog and the independent
        // response/challenge recomputation above produce this ceiling, so the
        // pin is a regression guard rather than a third authority.
        assert_eq!(
            catalog_accounting.maximum_transcript_hash_query_count,
            1_337_380
        );
        assert_eq!(
            catalog_accounting.logical_verifier_message_count,
            EXACT_LOGICAL_VERIFIER_MESSAGE_COUNT
        );
    }

    #[test]
    fn exact_non_merkle_hash_query_ceiling_is_catalogued() {
        let (_, variant, _) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        let verifier_source_ordinals = variant
            .ordered_columns()
            .iter()
            .filter_map(|column| match column.origin() {
                RelationColumnOrigin::VerifierSequence {
                    verifier_source_ordinal,
                    ..
                } => Some(*verifier_source_ordinal),
                _ => None,
            })
            .collect::<Vec<_>>();
        let distinct_verifier_source_ordinals = verifier_source_ordinals
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            verifier_source_ordinals.len() as u64,
            EXACT_PUBLIC_SETUP_SAMPLING_HASH_QUERY_COUNT
        );
        assert_eq!(
            distinct_verifier_source_ordinals.len() as u64,
            EXACT_PUBLIC_SETUP_SAMPLING_DISTINCT_EQUATION_COUNT
        );

        let hash_query_components = [
            EXACT_RELATION_PLAN_HASH_QUERY_COUNT,
            EXACT_VARIANT_HASH_QUERY_COUNT,
            EXACT_CONSTRUCTION_PLAN_IDENTITY_HASH_QUERY_COUNT,
            EXACT_TRANSCRIPT_HEADER_HASH_QUERY_COUNT,
            EXACT_APPLICATION_STATEMENT_HASH_QUERY_COUNT,
            EXACT_PUBLIC_SETUP_SAMPLING_HASH_QUERY_COUNT,
        ];
        let distinct_equation_components = [
            EXACT_RELATION_PLAN_DISTINCT_EQUATION_COUNT,
            EXACT_VARIANT_DISTINCT_EQUATION_COUNT,
            EXACT_CONSTRUCTION_PLAN_IDENTITY_DISTINCT_EQUATION_COUNT,
            EXACT_TRANSCRIPT_HEADER_DISTINCT_EQUATION_COUNT,
            EXACT_APPLICATION_STATEMENT_DISTINCT_EQUATION_COUNT,
            EXACT_PUBLIC_SETUP_SAMPLING_DISTINCT_EQUATION_COUNT,
        ];
        assert_eq!(hash_query_components.into_iter().sum::<u64>(), 23);
        assert_eq!(distinct_equation_components.into_iter().sum::<u64>(), 14);
        assert_eq!(EXACT_VERIFIER_NON_MERKLE_HASH_QUERY_COUNT, 23);
        assert_eq!(EXACT_VERIFIER_NON_MERKLE_DISTINCT_EQUATION_COUNT, 14);
    }

    #[test]
    fn exact_merkle_hash_query_ceiling_is_source_derived() {
        let (_, variant, _) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        let shape = ExactProofShape::from_variant(&variant).expect("derive exact proof shape");
        let outer_tree_height = shape.encoded_column_count.ilog2() as usize;
        let outer_parent_count =
            maximum_parent_hash_count(outer_tree_height, EXACT_COLUMN_QUERY_COUNT);
        assert_eq!(outer_tree_height, 21);
        assert_eq!(outer_parent_count, 5_155);
        let outer_hash_query_count = 3 * (EXACT_COLUMN_QUERY_COUNT + outer_parent_count);
        assert_eq!(outer_hash_query_count, 16_626);

        let bound_tree_height = EXACT_BOUND_LEAF_COUNT.ilog2() as usize;
        let bound_parent_counts = nested_bit_reversed_parent_hash_counts(
            bound_tree_height,
            EXACT_INPUT_BOUND_QUERY_COUNT,
            EXACT_OUTPUT_BOUND_QUERY_COUNT,
        );
        assert_eq!(
            bound_parent_counts.input_query_tree_count,
            maximum_parent_hash_count(bound_tree_height, EXACT_INPUT_BOUND_QUERY_COUNT)
        );
        assert_eq!(
            bound_parent_counts.output_query_tree_count,
            maximum_parent_hash_count(bound_tree_height, EXACT_OUTPUT_BOUND_QUERY_COUNT)
        );
        assert_eq!(
            bound_parent_counts,
            NestedParentHashCounts {
                input_query_tree_count: 623,
                output_query_tree_count: 3_437,
            }
        );
        assert_eq!(bound_parent_counts.weighted_count(), 15_295);
        let bound_leaf_hash_query_count = EXACT_INPUT_BOUND_TREE_COUNT
            * EXACT_INPUT_BOUND_QUERY_COUNT
            + EXACT_OUTPUT_BOUND_TREE_COUNT * EXACT_OUTPUT_BOUND_QUERY_COUNT;
        assert_eq!(bound_leaf_hash_query_count, 1_118);
        let bound_hash_query_count =
            bound_parent_counts.weighted_count() + bound_leaf_hash_query_count;
        assert_eq!(bound_hash_query_count, 16_413);

        let pcs = plain_aggregate_pcs(EXACT_PCS_VARIABLE_COUNT)
            .expect("construct exact plain WHIR configuration");
        let mut whir_hash_query_count = 0_usize;
        for round_index in 0..pcs.n_rounds() {
            let round = &pcs.round_parameters[round_index];
            let folded_domain_size = round.domain_size >> pcs.round_folding_factor(round_index);
            whir_hash_query_count += round.num_queries * (folded_domain_size.ilog2() as usize + 1);
        }
        let final_round = pcs.final_round_config();
        let final_folded_domain_size =
            final_round.domain_size >> pcs.round_folding_factor(pcs.n_rounds());
        whir_hash_query_count +=
            pcs.final_queries * (final_folded_domain_size.ilog2() as usize + 1);
        assert_eq!(whir_hash_query_count, 28_202);

        assert_eq!(
            u64::try_from(outer_hash_query_count + bound_hash_query_count + whir_hash_query_count)
                .expect("exact Merkle hash-query count fits u64"),
            EXACT_VERIFIER_MERKLE_HASH_QUERY_COUNT
        );
    }

    #[test]
    fn exact_construction_has_a_conditional_machine_checked_qrom_ledger() {
        let pcs = plain_aggregate_pcs(EXACT_PCS_VARIABLE_COUNT)
            .expect("construct the exact plain WHIR configuration");
        let (capability, variant, relation_context) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        let construction_plan = capability.row_code_whir_construction_plan();
        let shape = validate_exact_same_secret_construction_plan(
            construction_plan,
            &variant,
            &relation_context,
            capability.relation_plan_hash(),
            capability.relation_plan_variant_hash(),
        )
        .expect("validate the exact production construction plan");
        let verifier_accounting = exact_same_secret_verifier_accounting(construction_plan, shape)
            .expect("derive exact catalog-owned verifier accounting");
        let mut query_branches = Vec::new();
        let mut current_log_inverse_rate = pcs.params.starting_log_inv_rate;
        for (round_index, round) in pcs.round_parameters.iter().enumerate() {
            let folded_domain_size = round.domain_size >> pcs.round_folding_factor(round_index);
            query_branches.push((
                current_log_inverse_rate,
                round.num_queries,
                folded_domain_size,
            ));
            current_log_inverse_rate = round.log_inv_rate;
        }
        let final_round = pcs.final_round_config();
        let final_folded_domain_size =
            final_round.domain_size >> pcs.round_folding_factor(pcs.n_rounds());
        query_branches.push((
            current_log_inverse_rate,
            pcs.final_queries,
            final_folded_domain_size,
        ));
        assert_eq!(
            query_branches,
            [
                (2, 387, 1 << 20),
                (4, 288, 1 << 19),
                (6, 268, 1 << 18),
                (8, 264, 1 << 17),
                (10, 263, 1 << 16),
            ]
        );

        let common_binary_denominator_exponent = query_branches
            .iter()
            .map(|(log_inverse_rate, query_count, _)| (log_inverse_rate + 1) * query_count)
            .chain([
                3 * EXACT_COLUMN_QUERY_COUNT,
                EXACT_BOUND_LEAF_COUNT.ilog2() as usize * EXACT_INPUT_BOUND_QUERY_COUNT,
                7 * EXACT_OUTPUT_BOUND_QUERY_COUNT,
            ])
            .max()
            .expect("the exact WHIR configuration has query branches");
        assert_eq!(common_binary_denominator_exponent, 2_893);
        let mut binary_numerator = BigUint::from(0_u8);
        let mut binary_event_terms = Vec::new();
        for &(log_inverse_rate, query_count, complete_population) in &query_branches {
            let ratio_denominator = 1_u64 << (log_inverse_rate + 1);
            let ratio_numerator = (1_u64 << log_inverse_rate) + 1;
            let accepting_population = u64::try_from(complete_population)
                .expect("WHIR query population fits u64")
                / ratio_denominator
                * ratio_numerator;
            assert_without_replacement_probability_is_bounded_by_power(
                accepting_population,
                u64::try_from(complete_population).expect("WHIR query population fits u64"),
                u32::try_from(query_count).expect("query count fits u32"),
            );
            add_binary_failure_term(
                &mut binary_numerator,
                ratio_numerator,
                u32::try_from(query_count).expect("query count fits u32"),
                (log_inverse_rate + 1) * query_count,
                common_binary_denominator_exponent,
            );
            binary_event_terms.push((
                BigUint::from(ratio_numerator)
                    .pow(u32::try_from(query_count).expect("query count fits u32")),
                BigUint::from(1_u8) << ((log_inverse_rate + 1) * query_count),
            ));
        }

        // A rate-one-quarter row word outside its 3/8 unique-decoding
        // radius agrees at no more than a 5/8 fraction of coordinates.
        add_binary_failure_term(
            &mut binary_numerator,
            5,
            EXACT_COLUMN_QUERY_COUNT as u32,
            3 * EXACT_COLUMN_QUERY_COUNT,
            common_binary_denominator_exponent,
        );
        assert_without_replacement_probability_is_bounded_by_power(
            u64::try_from(shape.encoded_column_count).expect("encoded column count fits u64") / 8
                * 5,
            u64::try_from(shape.encoded_column_count).expect("encoded column count fits u64"),
            EXACT_COLUMN_QUERY_COUNT as u32,
        );
        let outer_query_term = BigUint::from(5_u8).pow(EXACT_COLUMN_QUERY_COUNT as u32);
        binary_event_terms.push((
            outer_query_term.clone(),
            BigUint::from(1_u8) << (3 * EXACT_COLUMN_QUERY_COUNT),
        ));
        assert!(
            (&outer_query_term << 262) < (BigUint::from(1_u8) << (3 * EXACT_COLUMN_QUERY_COUNT))
        );

        let input_bound_schedule = EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[0];
        let output_bound_schedule = EXACT_BOUND_REDUCTION_BLOCK_SCHEDULES[1];
        // The VSS-borrowed input columns have source degree below 18,432.
        // Clearing the at most three distinct opening denominators gives a
        // nonzero polynomial of degree at most 18,433. A paired leaf can hide
        // at most two roots, hence at most 9,217 accepting leaves.
        assert_eq!(
            (input_bound_schedule.source_degree_bound_exclusive + 2) / 2,
            INPUT_BOUND_CLEARED_IDENTITY_ROOT_PAIR_BOUND as usize
        );
        add_binary_failure_term(
            &mut binary_numerator,
            INPUT_BOUND_CLEARED_IDENTITY_ROOT_PAIR_BOUND,
            EXACT_INPUT_BOUND_QUERY_COUNT as u32,
            EXACT_BOUND_LEAF_COUNT.ilog2() as usize * EXACT_INPUT_BOUND_QUERY_COUNT,
            common_binary_denominator_exponent,
        );
        // The sampler binds all 266 accepted draws in order. The first 40
        // draws select a uniform subset without replacement; sorting that
        // subset afterward only canonicalizes Merkle traversal and does not
        // change the sampled event.
        assert_without_replacement_probability_is_bounded_by_power(
            INPUT_BOUND_CLEARED_IDENTITY_ROOT_PAIR_BOUND,
            EXACT_BOUND_LEAF_COUNT as u64,
            EXACT_INPUT_BOUND_QUERY_COUNT as u32,
        );
        let bound_query_term = BigUint::from(INPUT_BOUND_CLEARED_IDENTITY_ROOT_PAIR_BOUND)
            .pow(EXACT_INPUT_BOUND_QUERY_COUNT as u32);
        binary_event_terms.push((
            bound_query_term.clone(),
            BigUint::from(1_u8)
                << (EXACT_BOUND_LEAF_COUNT.ilog2() as usize * EXACT_INPUT_BOUND_QUERY_COUNT),
        ));
        assert!(
            (&bound_query_term << 273)
                < (BigUint::from(1_u8)
                    << (EXACT_BOUND_LEAF_COUNT.ilog2() as usize * EXACT_INPUT_BOUND_QUERY_COUNT))
        );
        // The direct output columns have source degree below 16,384, exactly
        // rate 1/128 in the 2^21-point domain. A received word outside the
        // unique-decoding radius therefore agrees on less than 129/256 of
        // coordinates; 65/128 is the conservative dyadic ceiling used here.
        assert_eq!(output_bound_schedule.source_degree_bound_exclusive, 16_384);
        assert_eq!(EXACT_BOUND_LEAF_COUNT * 2 / 128, 16_384);
        add_binary_failure_term(
            &mut binary_numerator,
            65,
            EXACT_OUTPUT_BOUND_QUERY_COUNT as u32,
            7 * EXACT_OUTPUT_BOUND_QUERY_COUNT,
            common_binary_denominator_exponent,
        );
        assert_without_replacement_probability_is_bounded_by_power(
            EXACT_BOUND_LEAF_COUNT as u64 / 128 * 65,
            EXACT_BOUND_LEAF_COUNT as u64,
            EXACT_OUTPUT_BOUND_QUERY_COUNT as u32,
        );
        let output_query_term = BigUint::from(65_u8).pow(EXACT_OUTPUT_BOUND_QUERY_COUNT as u32);
        let output_query_denominator = BigUint::from(1_u8) << (7 * EXACT_OUTPUT_BOUND_QUERY_COUNT);
        binary_event_terms.push((output_query_term.clone(), output_query_denominator.clone()));
        assert!(
            (&output_query_term << 260)
                < (BigUint::from(1_u8) << (7 * EXACT_OUTPUT_BOUND_QUERY_COUNT))
        );

        assert_eq!(shape.opening_claim_count, 4_217);
        assert_eq!(shape.phase_row_counts(), [247, 136, 15]);
        let public_sampler_catalog =
            exact_public_sampler_exhaustion_catalog(&pcs, &variant, &relation_context, shape);
        assert_eq!(
            public_sampler_catalog.sampler_kind_row_count(PublicSamplerKind::Product),
            3
        );
        assert_eq!(
            public_sampler_catalog.sampler_kind_row_count(PublicSamplerKind::Extension),
            5_065
        );
        assert_eq!(
            public_sampler_catalog.sampler_kind_row_count(PublicSamplerKind::OutOfDomain),
            1
        );
        assert_eq!(
            public_sampler_catalog.sampler_kind_row_count(PublicSamplerKind::Distinct),
            7
        );
        assert_eq!(
            public_sampler_catalog.sampler_kind_row_count(PublicSamplerKind::Extension)
                + public_sampler_catalog.sampler_kind_row_count(PublicSamplerKind::OutOfDomain),
            5_066
        );
        assert_eq!(
            public_sampler_catalog.extension_scalar_output_count_including_out_of_domain(),
            5_066
        );
        assert_eq!(
            public_sampler_catalog.logical_verifier_message_count(),
            EXACT_LOGICAL_VERIFIER_MESSAGE_COUNT
        );
        assert_eq!(public_sampler_catalog.bit_output_count(), 0);
        assert_eq!(public_sampler_catalog.grinding_output_count(), 0);
        assert_eq!(
            crate::bgv::proof_suite::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            128
        );
        for row in public_sampler_catalog.rows() {
            assert_eq!(
                row.maximum_candidate_draws_per_output(),
                128,
                "every exact public sampler row must use D=128"
            );
            let expected_candidate_bit_length = match row.sampler_kind() {
                PublicSamplerKind::Product => 512,
                PublicSamplerKind::Extension | PublicSamplerKind::OutOfDomain => 512,
                PublicSamplerKind::Distinct => 64,
            };
            assert_eq!(
                row.candidate_bit_length(),
                expected_candidate_bit_length,
                "exact public sampler candidate width changed for {}",
                row.challenge_tag()
            );
        }
        // This availability bound is exact in the ideal typed random-oracle model for
        // candidates within each row. The union does not assume independence
        // between rows or repeated proofs.
        assert!(
            public_sampler_catalog
                .multiplied_exhaustion_union_bound_is_at_most_inverse_power_of_two(
                    EXACT_SAME_SECRET_APPLICATION_COUNT,
                    128,
                )
                .expect("compare the exact public sampler exhaustion union"),
            "ten same-secret proofs must retain at least 128 public-sampler availability bits"
        );

        assert_eq!(relation_context.base_field_modulus, GOLDILOCKS_MODULUS);
        let challenge_field_order = BigUint::from(relation_context.base_field_modulus)
            .pow(u32::from(relation_context.challenge_extension_degree));
        assert_eq!(
            challenge_field_order,
            BigUint::parse_bytes(
                b"2135987033434293902082969833143585405490115481162544232032811052120416417467265840012020259225601",
                10,
            )
            .expect("parse the exact challenge-field order")
        );
        let algebraic_catalog =
            exact_algebraic_soundness_catalog(&pcs, &variant, &relation_context, shape);
        assert!(
            algebraic_catalog
                .iter()
                .all(ExactAlgebraicSoundnessRow::challenge_matches_event),
            "every algebraic event must remain attached to its typed challenge family"
        );
        let theta_challenge_groups = algebraic_catalog
            .iter()
            .find_map(|row| match &row.challenge {
                ExactAlgebraicChallengeFamily::CommonThetaProductVectors { challenge_groups } => {
                    Some(challenge_groups)
                }
                _ => None,
            })
            .expect("the exact algebraic catalog has theta product vectors");
        assert_eq!(theta_challenge_groups.len(), 3);
        assert!(
            theta_challenge_groups
                .iter()
                .all(|group| group.coordinate_count() == 5)
        );
        assert_eq!(
            algebraic_catalog
                .iter()
                .filter_map(|row| match &row.challenge {
                    ExactAlgebraicChallengeFamily::WhirFold { round_ordinal } => {
                        Some(*round_ordinal)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            (0..=pcs.n_rounds()).collect::<Vec<_>>()
        );
        assert_eq!(
            algebraic_catalog
                .iter()
                .filter_map(|row| match &row.challenge {
                    ExactAlgebraicChallengeFamily::WhirQueryCombination { round_ordinal } => {
                        Some(*round_ordinal)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            (0..pcs.n_rounds()).collect::<Vec<_>>()
        );
        assert_eq!(
            algebraic_catalog
                .iter()
                .filter_map(|row| match &row.challenge {
                    ExactAlgebraicChallengeFamily::WhirFinalSumcheck { round_count } => {
                        Some(*round_count)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            [pcs.final_sumcheck_rounds]
        );
        assert_eq!(
            pcs.final_sumcheck_rounds, 6,
            "the frozen exact WHIR profile has six quadratic final-sumcheck rounds"
        );
        let numerator_for_event = |event| {
            algebraic_catalog
                .iter()
                .filter(|row| row.event == event)
                .map(|row| row.challenge_field_numerator(&challenge_field_order))
                .fold(BigUint::from(0_u8), |sum, numerator| sum + numerator)
        };
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::WhirFold),
            BigUint::from(16_252_943_u64)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::WhirQueryCombination),
            BigUint::from(2_414_u64)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::WhirFinalSumcheck),
            BigUint::from(12_u8)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::WhirScalarOpeningBatch),
            BigUint::from(1_782_u64)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::OutOfDomainPointForbiddenSet),
            BigUint::from(1_u64 << 21)
        );
        assert_eq!(
            algebraic_catalog
                .iter()
                .find(|row| {
                    row.event == ExactAlgebraicFailureEvent::OutOfDomainPointForbiddenSet
                })
                .expect("the exact algebraic catalog has one out-of-domain row")
                .raw_numerator(),
            BigUint::from(171_295_u64),
            "the out-of-domain identity degree remains distinct from its accepted-set field ceiling"
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::RelationCompositionBatch),
            BigUint::from(1_u8)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::PackedPhaseSelectorAndRows),
            BigUint::from(12_u8)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::BoundOpeningBatch),
            BigUint::from(1_u8)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::OpeningBatchMask),
            BigUint::from(0_u8)
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::PhaseOpeningReductionExceptionalSet,),
            BigUint::from(3_u64 * (1_u64 << 21))
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::BoundOpeningReductionExceptionalSet,),
            BigUint::from(4_u64 * (1_u64 << 20))
        );
        assert_eq!(
            numerator_for_event(ExactAlgebraicFailureEvent::BoundDegreeSuffix),
            BigUint::from(50_u8)
        );

        let theta_failure_numerator =
            numerator_for_event(ExactAlgebraicFailureEvent::SameSecretIntegerLift);
        assert_eq!(theta_failure_numerator, BigUint::from(32_766_u64).pow(5));
        assert_eq!(
            theta_failure_numerator,
            BigUint::parse_bytes(b"37767404055200080068576", 10)
                .expect("parse the exact theta numerator")
        );
        let non_theta_algebraic_failure_numerator = algebraic_catalog
            .iter()
            .filter(|row| row.event != ExactAlgebraicFailureEvent::SameSecretIntegerLift)
            .map(|row| row.challenge_field_numerator(&challenge_field_order))
            .fold(BigUint::from(0_u8), |sum, numerator| sum + numerator);
        assert_eq!(
            non_theta_algebraic_failure_numerator,
            BigUint::from(28_840_127_u64)
        );
        let algebraic_failure_numerator =
            &theta_failure_numerator + &non_theta_algebraic_failure_numerator;
        assert_eq!(
            algebraic_failure_numerator,
            BigUint::parse_bytes(b"37767404055200108908703", 10)
                .expect("parse the exact algebraic numerator")
        );
        let aggregate_numerator = &challenge_field_order * binary_numerator
            + (&algebraic_failure_numerator << common_binary_denominator_exponent);
        let aggregate_denominator = &challenge_field_order << common_binary_denominator_exponent;
        assert!(
            (&aggregate_numerator << EXACT_AGGREGATE_SOUNDNESS_UPPER_BOUND_BITS)
                < aggregate_denominator
        );
        assert!(
            (&aggregate_numerator << (EXACT_AGGREGATE_SOUNDNESS_UPPER_BOUND_BITS + 1))
                >= aggregate_denominator
        );
        for (event_numerator, event_denominator) in &binary_event_terms {
            assert!(
                event_numerator * &output_query_denominator
                    <= &output_query_term * event_denominator
            );
        }
        assert!(
            &non_theta_algebraic_failure_numerator * &output_query_denominator
                <= &output_query_term * &challenge_field_order
        );

        // Conditional multi-round QROM arithmetic. The common-construction
        // state function, RBR extractor, row-code list decoder, typed ideal-RO
        // correspondence, same-secret nonzero-theta-row extraction, phase
        // opening-reduction extraction, and checked out-of-domain forbidden-set bound
        // remain named theorem obligations. The `2k/2^512` term is the
        // simulated oracle/database penalty from CMS19 Lemma 4.9. The
        // transcript counter is reconciled with the accepted verifier in the
        // persisted-proof gate; all other verifier-owned SHAKE calls are
        // enumerated by the Merkle and fixed-hash ledgers above.
        let verifier_hash_query_count = verifier_accounting.maximum_verifier_hash_query_count;
        let accepting_database_equation_count_ceiling =
            verifier_accounting.maximum_accepting_database_equation_count;
        assert_eq!(verifier_hash_query_count, 1_430_921);
        assert_eq!(accepting_database_equation_count_ceiling, 1_430_912);

        let adversary_hash_query_bound =
            (BigUint::from(1_u8) << QROM_RANDOM_ORACLE_QUERY_BOUND_EXPONENT) - BigUint::from(1_u8);
        let compiler_query_bound =
            &adversary_hash_query_bound + BigUint::from(verifier_hash_query_count);
        assert_eq!(
            compiler_query_bound,
            BigUint::parse_bytes(b"1208925819614629176137096", 10)
                .expect("the exact compiler query ceiling is a decimal integer")
        );
        let compiler_numerator = BigUint::from(12_u8)
            * &compiler_query_bound
            * &compiler_query_bound
            * &aggregate_numerator
            * (BigUint::from(1_u8) << FIAT_SHAMIR_RANDOM_ORACLE_OUTPUT_BIT_LENGTH)
            + (BigUint::from(48_u8)
                * &compiler_query_bound
                * &compiler_query_bound
                * &compiler_query_bound
                + BigUint::from(2_u8) * BigUint::from(accepting_database_equation_count_ceiling))
                * &aggregate_denominator;
        let compiler_denominator =
            &aggregate_denominator << FIAT_SHAMIR_RANDOM_ORACLE_OUTPUT_BIT_LENGTH;

        let relinearization_position_count = u32::try_from(
            crate::bgv::proof_suite::selected_evaluator_relinearization_entry_positions()
                .expect("derive selected relinearization positions")
                .len(),
        )
        .expect("selected relinearization position count fits u32");
        let galois_batch_count = u32::try_from(
            crate::bgv::proof_suite::selected_galois_key_share_batch_schedule().len(),
        )
        .expect("selected Galois batch count fits u32");
        let application_slot_ceilings = crate::foundation::ProofApplicationSlotCeilings::derive(
            crate::foundation::FOUNDATION_PROFILE.participant_count,
            relinearization_position_count,
            galois_batch_count,
            crate::foundation::SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        )
        .expect("derive selected proof-application ceilings");
        let same_secret_application_ceiling = application_slot_ceilings
            .family_ceiling(
                crate::foundation::ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            )
            .expect("same-secret family has an application ceiling");
        assert_eq!(
            same_secret_application_ceiling,
            u32::from(crate::foundation::FOUNDATION_PROFILE.participant_count)
        );
        assert_eq!(
            u64::from(same_secret_application_ceiling),
            EXACT_SAME_SECRET_APPLICATION_COUNT
        );
        let same_secret_application_count = BigUint::from(EXACT_SAME_SECRET_APPLICATION_COUNT);
        assert_eq!(
            verifier_accounting.logical_verifier_message_count,
            EXACT_LOGICAL_VERIFIER_MESSAGE_COUNT
        );
        // The ordinary family union uses the already-summed per-proof
        // aggregate. Individual event bounds above are diagnostics only: one
        // typed verifier message can drive more than one bad event, so they
        // are not multiplied by the logical message count.
        assert!(
            &same_secret_application_count * &aggregate_numerator * (BigUint::from(1_u8) << 80)
                <= aggregate_denominator
        );
        assert!(
            BigUint::from(4_u8) * &same_secret_application_count * &compiler_numerator
                <= compiler_denominator
        );

        // Since Q_H + h < 2^81, this stronger integer check also rules out
        // an initial-search term consuming the family budget.
        assert!(
            &same_secret_application_count
                * BigUint::from(12_u8)
                * &aggregate_numerator
                * (BigUint::from(1_u8) << 176)
                <= aggregate_denominator
        );
        let transcript_schedule = variant
            .common_proof_relation_prefix_schedule(&relation_context)
            .expect("derive exact transcript schedule")
            .into_row_code_whir_successor()
            .expect("derive exact successor transcript schedule");
        let common_prefix_oracle_answer_byte_length = transcript_schedule
            .ordered_application_challenge_sampler_accounting()
            .expect("derive exact application samplers")
            .into_iter()
            .map(|sampler| {
                usize::try_from(sampler.maximum_oracle_answer_byte_length())
                    .expect("application sampler answer length fits usize")
            })
            .max()
            .unwrap_or(Hash512::BYTE_LENGTH)
            .max(Hash512::BYTE_LENGTH);
        let maximum_typed_oracle_answer_byte_length =
            common_prefix_oracle_answer_byte_length.max(Hash512::BYTE_LENGTH);
        assert_eq!(maximum_typed_oracle_answer_byte_length, 64);
        assert_eq!(maximum_typed_oracle_answer_byte_length * 8, 512);
    }

    #[test]
    fn exact_masking_budget_covers_the_complete_first_oracle_view() {
        let (_, variant, relation_context) = production_same_secret_relation()
            .expect("compile the exact production same-secret relation");
        crate::bgv::proof_suite::zero_knowledge::validate_zero_knowledge_mask_image(
            &variant,
            &relation_context,
        )
        .expect("production trace, quotient, and opening-batch masks cover their views");
        let base_layout = ExactBasePhaseLayout::for_tree_role(&variant, ProofTreeRole::BaseOracle)
            .expect("derive base layout");
        let auxiliary_layout =
            ExactBasePhaseLayout::for_tree_role(&variant, ProofTreeRole::AuxiliaryOracle)
                .expect("derive auxiliary layout");
        let pcs = plain_aggregate_pcs(EXACT_PCS_VARIABLE_COUNT)
            .expect("construct the exact plain WHIR configuration");
        let mut challenger = plain_aggregate_challenger(&pcs, b"exact masking view certificate");
        let point_row_weights = derive_exact_point_row_weights(
            &mut challenger,
            &base_layout,
            &auxiliary_layout,
            ProofChallengeExtensionElement::from_canonical_coordinates([17, 1, 0, 0, 0])
                .expect("construct fixed full-extension quotient opening point"),
        )
        .expect("derive full-rank exact aggregate weights");
        assert_eq!(aggregate_pad_rank(&point_row_weights), 15);

        let row_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
            base_layout.rows.len(),
            PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
            EXACT_ROW_CODE_LOG_INVERSE_RATE,
        )
        .expect("derive exact row-code geometry");
        assert_eq!(row_geometry.pad_value_count(), 1 << 18);
        assert_eq!(row_geometry.encoded_column_count, 1 << 21);
        assert!(EXACT_COLUMN_QUERY_COUNT < row_geometry.pad_value_count());

        let first_oracle_opening_count = pcs.round_parameters[0]
            .num_queries
            .checked_mul(1_usize << pcs.round_folding_factor(0))
            .expect("first-oracle opening count fits usize");
        assert_eq!(first_oracle_opening_count, 3_096);
        assert!(
            EXACT_COLUMN_QUERY_COUNT + first_oracle_opening_count < row_geometry.pad_value_count(),
            "the phase and first-WHIR views together must leave pad entropy"
        );

        // The first prefix fold pairs every low witness entry with one
        // independent high-half pad entry. A zero first folding challenge is
        // the only exceptional event; it is below 2^-319 in Goldilocks^5.
        let challenge_field_order = BigUint::from(GOLDILOCKS_MODULUS).pow(5);
        assert!((BigUint::from(1_u8) << 319) < challenge_field_order);
    }

    #[test]
    fn reduced_round_two_relation_exercises_the_scaling_geometry() {
        use std::collections::BTreeMap;

        use crate::bgv::proof_suite::{
            RelinearizationRoundTwoRelationPlanInput,
            compile_relinearization_round_two_relation_with_source_layout,
            selected_relation_plan_check_context, selected_relinearization_relation_plan_inputs,
        };
        use crate::foundation::ProofApplicationSlotCeilings;

        let (_, selected_input) = selected_relinearization_relation_plan_inputs()
            .expect("select the production round-two relation input");
        assert!(selected_input.geometry.data_moduli.len() >= 3);
        assert!(!selected_input.geometry.special_moduli.is_empty());
        let first_decomposition_block = selected_input
            .geometry
            .decomposition_blocks
            .first()
            .cloned()
            .expect("the selected relation has a first decomposition block");
        assert_eq!(first_decomposition_block.data_modulus_indices, [0, 1, 2]);

        // Preserve the production ring, evaluation domain, commitment basis,
        // and exact first catalog block while removing later modulus blocks.
        // This is the smallest canonical round-two fragment that still owns
        // the complete product, non-native reduction, and anchor topology.
        let fragment_input = RelinearizationRoundTwoRelationPlanInput {
            schedule_position: selected_input.schedule_position,
            geometry: crate::bgv::proof_suite::TrusteeEvaluationKeyRelationGeometry {
                ring_degree: selected_input.geometry.ring_degree,
                evaluation_domain_size: selected_input.geometry.evaluation_domain_size,
                opening_degree_bound_exclusive: selected_input
                    .geometry
                    .opening_degree_bound_exclusive,
                public_polynomial_column_degree_bound_exclusive: selected_input
                    .geometry
                    .public_polynomial_column_degree_bound_exclusive,
                data_moduli: selected_input.geometry.data_moduli[..3].to_vec(),
                special_moduli: vec![selected_input.geometry.special_moduli[0]],
                plaintext_modulus: selected_input.geometry.plaintext_modulus,
                decomposition_blocks: vec![first_decomposition_block],
                commitment_data_modulus_indices: selected_input
                    .geometry
                    .commitment_data_modulus_indices
                    .clone(),
                commitment_module_rank: selected_input.geometry.commitment_module_rank,
            },
        };
        let relation_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("select the production round-two relation context");
        let compiled = compile_relinearization_round_two_relation_with_source_layout(
            &fragment_input,
            &relation_context,
        )
        .expect("compile the reduced production-geometry round-two relation");
        let variant = compiled
            .relation_plan
            .select_variant(Some(fragment_input.schedule_position), None)
            .expect("select the reduced round-two variant");

        assert_eq!(variant.trace_domain_size(), 1 << 14);
        assert_eq!(variant.evaluation_domain_size(), 1 << 21);
        crate::bgv::proof_suite::zero_knowledge::validate_zero_knowledge_mask_image(
            variant,
            &relation_context,
        )
        .expect("the reduced round-two masks cover the complete secret-bearing view");

        let full_ring_products = variant
            .ordered_integer_lift_batches()
            .iter()
            .flat_map(|batch| &batch.ordered_components)
            .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            .collect::<Vec<_>>();
        assert!(!full_ring_products.is_empty());
        assert!(full_ring_products.iter().any(|product| {
            product.multiplier_low_offset != 0 || product.multiplier_high_offset != 0
        }));

        let (radix_digit_column_count, carry_column_count) =
            variant.radix_digit_and_carry_column_counts();
        assert!(radix_digit_column_count > 0);
        assert!(carry_column_count > 0);

        let bound_root_uses = variant
            .ordered_trees()
            .iter()
            .filter_map(|tree| match tree {
                RelationTreeDescriptor::BoundPublic { root_use, .. } => Some(*root_use),
                RelationTreeDescriptor::ProofCreated { .. } => None,
            })
            .collect::<Vec<_>>();
        assert!(bound_root_uses.contains(&BoundTreeRootUse::Input));
        assert!(bound_root_uses.contains(&BoundTreeRootUse::Output));

        let mut product_uses_by_column = BTreeMap::<u32, usize>::new();
        for product in &full_ring_products {
            for column_ordinal in [
                product.multiplicand_low_column_ordinal,
                product.multiplicand_high_column_ordinal,
                product.multiplier_low_column_ordinal,
                product.multiplier_high_column_ordinal,
            ] {
                *product_uses_by_column.entry(column_ordinal).or_default() += 1;
            }
        }
        assert!(
            product_uses_by_column
                .values()
                .any(|use_count| *use_count > 1),
            "one witness column must participate in multiple product constraints"
        );

        let base_layout = ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::BaseOracle)
            .expect("derive the reduced round-two base layout");
        let auxiliary_layout =
            ExactBasePhaseLayout::for_tree_role(variant, ProofTreeRole::AuxiliaryOracle)
                .expect("derive the reduced round-two auxiliary layout");
        let base_geometry = base_layout
            .geometry()
            .expect("derive base row-code geometry");
        let auxiliary_geometry = auxiliary_layout
            .geometry()
            .expect("derive auxiliary row-code geometry");
        assert_eq!(base_geometry.encoded_column_count, 1 << 21);
        assert_eq!(auxiliary_geometry.encoded_column_count, 1 << 21);

        let phase_row_count = base_layout
            .rows
            .len()
            .checked_add(auxiliary_layout.rows.len())
            .and_then(|count| count.checked_add(EXACT_QUOTIENT_PHASE_ROW_COUNT))
            .expect("phase row count fits usize");
        let opened_phase_value_byte_length = EXACT_COLUMN_QUERY_COUNT
            .checked_mul(phase_row_count)
            .and_then(|count| count.checked_mul(core::mem::size_of::<Goldilocks>()))
            .expect("opened phase-value byte length fits usize");
        assert!(
            opened_phase_value_byte_length < 8 * 1_024 * 1_024,
            "the representative fragment must not produce an enormous opened-column payload"
        );

        eprintln!(
            "reduced round-two scaling geometry: columns={} constraints={} claims={} products={} radix_digit_columns={} carry_columns={} base_rows={} auxiliary_rows={} quotient_rows={} opened_phase_value_bytes={}",
            variant.ordered_columns().len(),
            variant.ordered_constraint_count(),
            variant.ordered_opening_claims().len(),
            full_ring_products.len(),
            radix_digit_column_count,
            carry_column_count,
            base_layout.rows.len(),
            auxiliary_layout.rows.len(),
            EXACT_QUOTIENT_PHASE_ROW_COUNT,
            opened_phase_value_byte_length,
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_prover {
    use std::{
        collections::HashMap,
        fs::{self, OpenOptions},
        io::Write,
        path::Path,
        time::Instant,
    };

    use super::super::native_checkpoint::{
        CheckpointBasePhaseSource, CheckpointQuotientPhaseSource, ExactPolynomialStore,
    };
    use super::*;
    use crate::bgv::proof_suite::{
        AuthenticatedCompactCommittedMaterialSource, CommonProofSourcePolynomial,
        PROOF_CHALLENGE_EXTENSION_DEGREE,
    };
    use p3_sumcheck::layout::{Layout, Table, Witness};

    fn fixed_hash(bytes: &[u8], label: &str) -> Result<[u8; 64], String> {
        bytes
            .try_into()
            .map_err(|_| format!("{label} must contain exactly 64 bytes"))
    }

    fn digest_from_words(words: &[u64], label: &str) -> Result<ColumnDigest, String> {
        words
            .try_into()
            .map_err(|_| format!("{label} must contain exactly eight words"))
    }

    pub(super) fn exact_verification_context_from_production_source(
        sources: &PreparedExactSameSecretGenerationSources,
    ) -> Result<ExactSameSecretVerificationContext, String> {
        let request_context = sources
            .source_polynomials
            .exact_same_secret_evidence_request_context();
        let statement = decode_selected_same_secret_statement(
            &sources.canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                request_context.protocol_version(),
                request_context.suite_identifier(),
                None,
                None,
            ),
        )
        .map_err(|error| format!("decode exact evidence statement: {error:?}"))?;
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(request_context.suite_identifier()),
            Hash512::from_bytes(sources.authorization.ceremony_context_hash()),
            Hash512::from_bytes(sources.action_context_hash),
            request_context.application_statement_schema_identifier(),
            Some(statement.roster_position()),
            None,
            None,
        )
        .map_err(|error| format!("construct exact evidence application slot: {error:?}"))?;
        let statement_owned_trees = sources
            .relation_trees
            .iter()
            .enumerate()
            .map(|(ordered_tree_ordinal, relation_tree)| {
                VerifiedStatementOwnedTree::from_authenticated_generation_relation_tree(
                    &sources.relation_plan_variant,
                    ordered_tree_ordinal,
                    relation_tree,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("derive exact evidence statement trees: {error:?}"))?
            .into_iter()
            .flatten()
            .collect();
        let verification_context = ExactSameSecretVerificationContext::new(
            request_context.protocol_version(),
            application_slot,
            sources.canonical_application_statement_bytes.clone(),
            statement_owned_trees,
        )?;
        let prerequisite = production_same_secret_prerequisite(sources)?;
        let _ = validate_verification_context(&prerequisite, &verification_context)?;
        Ok(verification_context)
    }

    fn evaluate_extension_coefficients(
        coefficients: &[ProofChallengeExtensionElement],
        point: ProofChallengeExtensionElement,
    ) -> ProofChallengeExtensionElement {
        coefficients.iter().rev().fold(
            ProofChallengeExtensionElement::ZERO,
            |accumulated, coefficient| accumulated.multiply(point).add(*coefficient),
        )
    }

    fn evaluate_exact_out_of_domain_claims(
        variant: &RelationPlanVariant,
        opening_points: &[ProofChallengeExtensionElement],
        store: &ExactPolynomialStore,
    ) -> Result<Vec<ProofChallengeExtensionElement>, String> {
        variant
            .ordered_opening_claims()
            .iter()
            .map(|claim| {
                let point = opening_points
                    .get(
                        usize::try_from(claim.opening_point_ordinal())
                            .map_err(|_| "opening-point ordinal exceeds usize".to_owned())?,
                    )
                    .copied()
                    .ok_or_else(|| "opening claim references an absent point".to_owned())?;
                match claim.source_class() {
                    RelationOpeningSourceClass::TreeColumn => {
                        let column_ordinal = claim.column_ordinal().ok_or_else(|| {
                            "tree opening claim has no relation column".to_owned()
                        })?;
                        Ok(store.read(column_ordinal)?.evaluate_at(point))
                    }
                    RelationOpeningSourceClass::Quotient => {
                        let coefficients = store.read_quotient_component(
                            u16::try_from(claim.source_ordinal())
                                .map_err(|_| "quotient component ordinal exceeds u16".to_owned())?,
                        )?;
                        Ok(evaluate_extension_coefficients(&coefficients, point))
                    }
                    RelationOpeningSourceClass::BatchMask => {
                        if claim.source_ordinal() != 0 {
                            return Err(
                                "opening-batch mask has a nonzero source ordinal".to_owned()
                            );
                        }
                        let coefficients = store.read_opening_batch_mask()?;
                        Ok(evaluate_extension_coefficients(&coefficients, point))
                    }
                }
            })
            .collect()
    }

    fn evaluate_opening_batch_mask_chunks(
        store: &ExactPolynomialStore,
        opening_point: ProofChallengeExtensionElement,
    ) -> Result<[ProofChallengeExtensionElement; EXACT_OPENING_BATCH_MASK_CHUNK_COUNT], String>
    {
        let coefficients = store.read_opening_batch_mask()?;
        let maximum_coefficient_count = LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
            .checked_mul(EXACT_OPENING_BATCH_MASK_CHUNK_COUNT)
            .ok_or_else(|| "opening-batch mask coefficient limit overflowed".to_owned())?;
        if coefficients.len() > maximum_coefficient_count {
            return Err(format!(
                "opening-batch mask has {} coefficients, exceeding {maximum_coefficient_count}",
                coefficients.len()
            ));
        }
        let mut evaluations =
            [ProofChallengeExtensionElement::ZERO; EXACT_OPENING_BATCH_MASK_CHUNK_COUNT];
        for (chunk_ordinal, evaluation) in evaluations.iter_mut().enumerate() {
            let chunk_start = chunk_ordinal * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
            if chunk_start >= coefficients.len() {
                continue;
            }
            let chunk_end = chunk_start
                .checked_add(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
                .expect("opening-batch mask chunk end fits usize")
                .min(coefficients.len());
            *evaluation = evaluate_extension_coefficients(
                &coefficients[chunk_start..chunk_end],
                opening_point,
            );
        }
        Ok(evaluations)
    }

    fn construct_bound_reduction_polynomial(
        store: &ExactPolynomialStore,
        variant: &RelationPlanVariant,
        bound_claims: &[ExactBoundOpeningClaim],
    ) -> Result<Poly<ChallengeField>, String> {
        let coefficient_count = 1_usize << EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT;
        let locations = bound_column_locations(variant)?;
        let mut aggregate_coefficients =
            std::array::from_fn::<_, EXACT_BOUND_REDUCTION_BLOCK_COUNT, _>(|_| {
                vec![ChallengeField::ZERO; coefficient_count]
            });
        for claim in bound_claims {
            let (_, _, root_use) = locations
                .get(&claim.column_ordinal)
                .copied()
                .ok_or_else(|| "bound claim column has no tree location".to_owned())?;
            let (block_ordinal, block_schedule) =
                bound_reduction_block_schedule_for_root_use(root_use)?;
            let CommonProofSourcePolynomial::Base(source_coefficients) =
                store.read(claim.column_ordinal)?
            else {
                return Err(format!(
                    "bound relation column {} is not base-field valued",
                    claim.column_ordinal
                ));
            };
            if source_coefficients.is_empty()
                || source_coefficients.len() > block_schedule.source_degree_bound_exclusive
            {
                return Err(format!(
                    "bound relation column {} has the wrong degree bound",
                    claim.column_ordinal
                ));
            }
            let (quotient, remainder) = divide_polynomial_opening(
                source_coefficients.len(),
                |coefficient_ordinal| {
                    ChallengeField::from(Goldilocks::new(
                        source_coefficients[coefficient_ordinal].canonical(),
                    ))
                },
                claim.opening_point,
                claim.claimed_value,
            )?;
            if remainder != ChallengeField::ZERO {
                return Err(format!(
                    "bound relation column {} does not match its claimed out-of-domain evaluation",
                    claim.column_ordinal
                ));
            }
            if quotient.len() > block_schedule.quotient_degree_bound_exclusive {
                return Err(format!(
                    "bound relation column {} produced an oversized quotient",
                    claim.column_ordinal
                ));
            }
            for (aggregate, coefficient) in aggregate_coefficients[block_ordinal]
                .iter_mut()
                .zip(quotient)
            {
                *aggregate += claim.batching_weight * coefficient;
            }
        }
        let mut packed_coefficients =
            vec![ChallengeField::ZERO; 1_usize << EXACT_TABLE_VARIABLE_COUNT];
        for (block_ordinal, block_coefficients) in aggregate_coefficients.into_iter().enumerate() {
            let block_start = block_ordinal * coefficient_count;
            packed_coefficients[block_start..block_start + coefficient_count]
                .copy_from_slice(&block_coefficients);
        }
        Ok(Poly::new(packed_coefficients))
    }

    fn capture_frontier_digest(
        frontier_positions: &HashMap<(u32, u64), usize>,
        frontier: &mut [Option<[u8; 64]>],
        level: u32,
        node_index: u64,
        digest: [u8; 64],
    ) -> Result<(), String> {
        let Some(frontier_position) = frontier_positions.get(&(level, node_index)).copied() else {
            return Ok(());
        };
        let slot = frontier
            .get_mut(frontier_position)
            .ok_or_else(|| "bound frontier position is outside its allocation".to_owned())?;
        if slot.replace(digest).is_some() {
            return Err("bound frontier node was produced more than once".to_owned());
        }
        Ok(())
    }

    struct ExactBoundTreeProverSource {
        ordered_column_ordinals: Box<[u32]>,
        persistent_material_source: Option<AuthenticatedCompactCommittedMaterialSource>,
    }

    fn resolve_bound_tree_prover_sources(
        sources: &PreparedExactSameSecretGenerationSources,
        entries: &[ProofTreeCatalogEntry],
    ) -> Result<Vec<ExactBoundTreeProverSource>, String> {
        if entries.len() != EXACT_BOUND_TREE_COUNT {
            return Err("bound authentication source has the wrong fixed shape".to_owned());
        }
        entries
            .iter()
            .map(|entry| {
                let descriptor = sources
                    .relation_plan_variant
                    .ordered_trees()
                    .get(usize::from(entry.tree_catalog_index()))
                    .ok_or_else(|| "bound catalog entry has no relation tree".to_owned())?;
                let RelationTreeDescriptor::BoundPublic {
                    ordered_column_ordinals,
                    ..
                } = descriptor
                else {
                    return Err("bound catalog entry refers to a proof-created tree".to_owned());
                };
                if ordered_column_ordinals.len() != EXACT_BOUND_TREE_ROW_WIDTH {
                    return Err("bound tree has the wrong row width".to_owned());
                }
                let persistent_material_source = if entry.requires_persistent_leaf_salt() {
                    Some(
                        sources
                            .source_polynomials
                            .exact_same_secret_evidence_bound_material_source(
                                entry.tree_catalog_index(),
                                entry
                                    .bound_root()
                                    .ok_or_else(|| "bound tree has no root".to_owned())?,
                            )
                            .map_err(|error| {
                                format!("resolve production bound material source: {error:?}")
                            })?,
                    )
                } else {
                    None
                };
                Ok(ExactBoundTreeProverSource {
                    ordered_column_ordinals: ordered_column_ordinals.to_vec().into_boxed_slice(),
                    persistent_material_source,
                })
            })
            .collect()
    }

    fn build_bound_tree_authentications(
        prover_sources: &[ExactBoundTreeProverSource],
        store: &ExactPolynomialStore,
        entries: &[ProofTreeCatalogEntry],
        bound_query_indices: &ExactBoundQueryIndices,
        evaluation_domain: ProofEvaluationDomain,
        shape: ExactProofShape,
    ) -> Result<Vec<ExactBoundTreeAuthentication>, String> {
        if entries.len() != EXACT_BOUND_TREE_COUNT
            || prover_sources.len() != EXACT_BOUND_TREE_COUNT
            || !bound_query_indices.has_exact_shape(shape)
            || evaluation_domain.size() != EXACT_BOUND_LEAF_COUNT * 2
        {
            return Err("bound authentication prover has the wrong fixed shape".to_owned());
        }
        let mut authentications = Vec::with_capacity(EXACT_BOUND_TREE_COUNT);
        for (bound_tree_ordinal, entry) in entries.iter().enumerate() {
            let prover_source = &prover_sources[bound_tree_ordinal];
            if entry.requires_persistent_leaf_salt()
                != prover_source.persistent_material_source.is_some()
            {
                return Err("bound tree has the wrong persistent material source".to_owned());
            }
            let tree_query_indices = bound_query_indices
                .traversal_indices_for_tree_ordinal(shape, bound_tree_ordinal)?;
            let query_count = tree_query_indices.len();
            let query_positions = tree_query_indices
                .iter()
                .copied()
                .enumerate()
                .map(|(query_ordinal, leaf_index)| (leaf_index, query_ordinal))
                .collect::<HashMap<_, _>>();
            let frontier_coordinates =
                crate::bgv::proof_suite::merkle::minimal_frontier_coordinates(
                    &tree_query_indices
                        .iter()
                        .copied()
                        .map(|leaf_index| {
                            u64::try_from(leaf_index)
                                .map_err(|_| "bound leaf index exceeds u64".to_owned())
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    EXACT_BOUND_LEAF_COUNT,
                )
                .map_err(|error| format!("derive bound frontier coordinates: {error:?}"))?;
            let frontier_positions = frontier_coordinates
                .iter()
                .copied()
                .enumerate()
                .map(|(frontier_position, coordinate)| (coordinate, frontier_position))
                .collect::<HashMap<_, _>>();
            let mut evaluated_columns = Vec::with_capacity(EXACT_BOUND_TREE_ROW_WIDTH);
            for column_ordinal in &prover_source.ordered_column_ordinals {
                let CommonProofSourcePolynomial::Base(coefficients) =
                    store.read(*column_ordinal)?
                else {
                    return Err(format!(
                        "bound column {column_ordinal} is not base-field valued"
                    ));
                };
                evaluated_columns.push(
                    evaluation_domain
                        .evaluate_base_polynomial(&coefficients)
                        .map_err(|error| format!("evaluate bound column: {error:?}"))?,
                );
            }
            let mut opened_leaves = vec![None; query_count];
            let mut frontier = vec![None; frontier_coordinates.len()];
            let mut merkle_stack =
                vec![None::<[u8; 64]>; EXACT_BOUND_LEAF_COUNT.ilog2() as usize + 1];
            for leaf_index in 0..EXACT_BOUND_LEAF_COUNT {
                let first_point_values = std::array::from_fn(|column_position| {
                    evaluated_columns[column_position][leaf_index]
                });
                let opposite_point_values = std::array::from_fn(|column_position| {
                    evaluated_columns[column_position][leaf_index + EXACT_BOUND_LEAF_COUNT]
                });
                let persistent_salt = prover_source
                    .persistent_material_source
                    .as_ref()
                    .map(|source| {
                        source
                            .compact_source()
                            .persistent_leaf_salt(leaf_index)
                            .map_err(|error| format!("derive bound leaf salt: {error:?}"))
                    })
                    .transpose()?;
                let (_, mut digest) = entry
                    .encode_materialized_leaf(
                        u64::try_from(leaf_index)
                            .map_err(|_| "bound leaf index exceeds u64".to_owned())?,
                        persistent_salt,
                        Zeroizing::new(
                            first_point_values
                                .iter()
                                .copied()
                                .map(ProofTreeValue::Base)
                                .collect(),
                        ),
                        Zeroizing::new(
                            opposite_point_values
                                .iter()
                                .copied()
                                .map(ProofTreeValue::Base)
                                .collect(),
                        ),
                    )
                    .map_err(|error| format!("encode production bound leaf: {error:?}"))?;
                if let Some(query_ordinal) = query_positions.get(&leaf_index).copied() {
                    opened_leaves[query_ordinal] = Some(ExactBoundLeafOpening {
                        persistent_salt,
                        first_point_values,
                        opposite_point_values,
                    });
                }
                let mut level = 0_u32;
                let mut node_index = u64::try_from(leaf_index)
                    .map_err(|_| "bound leaf index exceeds u64".to_owned())?;
                capture_frontier_digest(
                    &frontier_positions,
                    &mut frontier,
                    level,
                    node_index,
                    digest,
                )?;
                loop {
                    let stack_position = usize::try_from(level)
                        .map_err(|_| "bound Merkle level exceeds usize".to_owned())?;
                    let Some(left_digest) = merkle_stack[stack_position].take() else {
                        merkle_stack[stack_position] = Some(digest);
                        break;
                    };
                    level += 1;
                    node_index /= 2;
                    digest = entry
                        .materialized_parent_digest(level, node_index, left_digest, digest)
                        .map_err(|error| format!("hash production bound parent: {error:?}"))?;
                    capture_frontier_digest(
                        &frontier_positions,
                        &mut frontier,
                        level,
                        node_index,
                        digest,
                    )?;
                }
            }
            let root = merkle_stack
                .last()
                .and_then(|root| *root)
                .ok_or_else(|| "bound Merkle builder did not produce a root".to_owned())?;
            if Some(root) != entry.bound_root()
                || merkle_stack[..merkle_stack.len() - 1]
                    .iter()
                    .any(Option::is_some)
            {
                return Err("recomputed bound tree has the wrong root".to_owned());
            }
            authentications.push(ExactBoundTreeAuthentication {
                opened_leaves: opened_leaves
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| "a requested bound leaf was not materialized".to_owned())?,
                frontier: frontier
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| "a bound frontier node was not materialized".to_owned())?,
            });
        }
        Ok(authentications)
    }

    fn add_poly(destination: &mut Poly<ChallengeField>, source: &Poly<ChallengeField>) {
        assert_eq!(destination.num_evals(), source.num_evals());
        for (destination, source) in destination.as_mut_slice().iter_mut().zip(source.as_slice()) {
            *destination += *source;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn exact_aggregate_messages(
        store: &ExactPolynomialStore,
        base_layout: &ExactBasePhaseLayout,
        auxiliary_layout: &ExactBasePhaseLayout,
        quotient_component_count: usize,
        row_pad_seeds: [[u8; 32]; 3],
        point_row_weights: &[ExactPointRowWeights; 3],
    ) -> Result<Vec<Poly<ChallengeField>>, String> {
        let base_source = CheckpointBasePhaseSource::new(store, base_layout);
        let auxiliary_source = CheckpointBasePhaseSource::new(store, auxiliary_layout);
        let quotient_source = CheckpointQuotientPhaseSource::new(store, quotient_component_count)?;
        let base_geometry = base_layout.geometry()?;
        let auxiliary_geometry = auxiliary_layout.geometry()?;
        let quotient_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
            quotient_source.row_count(),
            PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
            EXACT_ROW_CODE_LOG_INVERSE_RATE,
        )?;
        let mut messages = Vec::with_capacity(3);
        for weights in point_row_weights {
            let mut aggregate = aggregate_weighted_message(
                &base_source,
                base_geometry,
                &row_pad_seeds[0],
                &weights.base,
            )?;
            let auxiliary = aggregate_weighted_message(
                &auxiliary_source,
                auxiliary_geometry,
                &row_pad_seeds[1],
                &weights.auxiliary,
            )?;
            add_poly(&mut aggregate, &auxiliary);
            let quotient = aggregate_weighted_message(
                &quotient_source,
                quotient_geometry,
                &row_pad_seeds[2],
                &weights.quotient,
            )?;
            add_poly(&mut aggregate, &quotient);
            messages.push(aggregate);
        }
        Ok(messages)
    }

    #[allow(clippy::too_many_arguments)]
    fn exact_aggregate_witness(
        store: &ExactPolynomialStore,
        base_layout: &ExactBasePhaseLayout,
        auxiliary_layout: &ExactBasePhaseLayout,
        quotient_component_count: usize,
        row_pad_seeds: [[u8; 32]; 3],
        point_row_weights: &[ExactPointRowWeights; 3],
        relation_variant: &RelationPlanVariant,
        bound_claims: &[ExactBoundOpeningClaim],
        folding_factor: usize,
    ) -> Result<Witness<ChallengeField>, String> {
        let mut messages = exact_aggregate_messages(
            store,
            base_layout,
            auxiliary_layout,
            quotient_component_count,
            row_pad_seeds,
            point_row_weights,
        )?;
        messages.push(construct_bound_reduction_polynomial(
            store,
            relation_variant,
            bound_claims,
        )?);
        Ok(AggregateLayout::new_witness(
            vec![Table::new(messages)],
            folding_factor,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn recompute_exact_aggregate_polynomial(
        store: &ExactPolynomialStore,
        base_layout: &ExactBasePhaseLayout,
        auxiliary_layout: &ExactBasePhaseLayout,
        quotient_component_count: usize,
        row_pad_seeds: [[u8; 32]; 3],
        point_row_weights: &[ExactPointRowWeights; 3],
        relation_variant: &RelationPlanVariant,
        bound_claims: &[ExactBoundOpeningClaim],
        _folding_factor: usize,
    ) -> Result<Poly<ChallengeField>, String> {
        let base_source = CheckpointBasePhaseSource::new(store, base_layout);
        let auxiliary_source = CheckpointBasePhaseSource::new(store, auxiliary_layout);
        let quotient_source = CheckpointQuotientPhaseSource::new(store, quotient_component_count)?;
        let base_geometry = base_layout.geometry()?;
        let auxiliary_geometry = auxiliary_layout.geometry()?;
        let quotient_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
            quotient_source.row_count(),
            PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
            EXACT_ROW_CODE_LOG_INVERSE_RATE,
        )?;
        let mut stacked = Poly::<ChallengeField>::zero(EXACT_PCS_VARIABLE_COUNT);
        for (column_index, weights) in point_row_weights.iter().enumerate() {
            let mut aggregate = aggregate_weighted_message(
                &base_source,
                base_geometry,
                &row_pad_seeds[0],
                &weights.base,
            )?;
            let auxiliary = aggregate_weighted_message(
                &auxiliary_source,
                auxiliary_geometry,
                &row_pad_seeds[1],
                &weights.auxiliary,
            )?;
            add_poly(&mut aggregate, &auxiliary);
            let quotient = aggregate_weighted_message(
                &quotient_source,
                quotient_geometry,
                &row_pad_seeds[2],
                &weights.quotient,
            )?;
            add_poly(&mut aggregate, &quotient);
            place_exact_aggregate_column(&mut stacked, aggregate, column_index)?;
        }
        let bound_reduction =
            construct_bound_reduction_polynomial(store, relation_variant, bound_claims)?;
        place_exact_aggregate_column(
            &mut stacked,
            bound_reduction,
            EXACT_BOUND_REDUCTION_COLUMN_INDEX,
        )?;
        Ok(stacked)
    }

    fn place_exact_aggregate_column(
        stacked: &mut Poly<ChallengeField>,
        column: Poly<ChallengeField>,
        column_index: usize,
    ) -> Result<(), String> {
        if stacked.num_variables() != EXACT_PCS_VARIABLE_COUNT
            || column.num_variables() != EXACT_TABLE_VARIABLE_COUNT
            || column_index >= EXACT_PROOF_TABLE_WIDTH
        {
            return Err("exact aggregate column has invalid stacking geometry".to_owned());
        }
        let selector_variable_count = EXACT_PCS_VARIABLE_COUNT - EXACT_TABLE_VARIABLE_COUNT;
        let selector_index =
            column_index.reverse_bits() >> (usize::BITS as usize - selector_variable_count);
        for (local_index, value) in column.into_evals().into_iter().enumerate() {
            let destination_index = (local_index << selector_variable_count) | selector_index;
            stacked.as_mut_slice()[destination_index] = value;
        }
        Ok(())
    }

    fn write_artifact(path: &Path, bytes: &[u8]) -> Result<(), String> {
        if path.is_file() {
            let existing =
                fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
            if existing == bytes {
                return Ok(());
            }
            return Err(format!(
                "existing exact artifact {} differs from the current construction",
                path.display()
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("write {}: {error}", path.display()))
    }

    fn generate_exact_same_secret_artifacts() -> Result<
        (
            VerifiedSameSecretLowDegreePrerequisite,
            ExactSameSecretVerificationContext,
            Vec<u8>,
        ),
        String,
    > {
        let started_at = Instant::now();
        let ProductionSameSecretEvidenceSources {
            mut sources,
            authority_handle,
        } = production_same_secret_sources()?;
        let prerequisite = production_same_secret_prerequisite(&sources)?;
        let verification_prerequisite = production_same_secret_prerequisite(&sources)?;
        let store = ExactPolynomialStore::open()?;
        let source_manifest = store
            .read_manifest()?
            .ok_or_else(|| "production source gate must run first".to_owned())?;
        let phase_manifest = store
            .read_phase_manifest()?
            .ok_or_else(|| "phase commitment gate must run first".to_owned())?;
        let quotient_manifest = store
            .read_quotient_manifest()?
            .ok_or_else(|| "quotient commitment gate must run first".to_owned())?;
        if fixed_hash(
            &source_manifest.relation_plan_hash,
            "source relation-plan hash",
        )? != sources.relation_plan.relation_plan_hash()
            || fixed_hash(
                &source_manifest.relation_plan_variant_hash,
                "source relation-plan variant hash",
            )? != sources.relation_plan.relation_plan_variant_hash()
            || source_manifest.canonical_application_statement_bytes
                != sources.canonical_application_statement_bytes
            || fixed_hash(
                &source_manifest.generation_binding_hash,
                "source generation-binding hash",
            )? != sources.generation_binding_hash
            || phase_manifest.relation_plan_hash != source_manifest.relation_plan_hash
            || phase_manifest.relation_plan_variant_hash
                != source_manifest.relation_plan_variant_hash
            || phase_manifest.source_catalog_digest != source_manifest.source_catalog_digest
            || quotient_manifest.relation_plan_hash != source_manifest.relation_plan_hash
            || quotient_manifest.relation_plan_variant_hash
                != source_manifest.relation_plan_variant_hash
            || quotient_manifest.source_catalog_digest != source_manifest.source_catalog_digest
        {
            return Err("exact checkpoints do not share one production relation".to_owned());
        }
        let verification_context = exact_verification_context_from_production_source(&sources)?;
        let mut verified_relation =
            validate_verification_context(&prerequisite, &verification_context)?;
        let bound_tree_entries = exact_bound_tree_catalog_entries(&verified_relation)?;
        let bound_tree_prover_sources =
            resolve_bound_tree_prover_sources(&sources, &bound_tree_entries)?;
        let row_pad_seeds = derive_exact_row_pad_seeds(&mut sources)?;
        release_production_same_secret_authority(authority_handle)?;
        drop(sources);
        let shape = verified_relation.proof_shape;
        if phase_manifest.base_row_count != shape.base_row_count
            || phase_manifest.auxiliary_row_count != shape.auxiliary_row_count
            || quotient_manifest.quotient_phase_row_count != EXACT_QUOTIENT_PHASE_ROW_COUNT
            || phase_manifest.encoded_column_count != shape.encoded_column_count
            || quotient_manifest.encoded_column_count != shape.encoded_column_count
        {
            return Err("exact checkpoint row geometry does not match the relation".to_owned());
        }
        let base_root = digest_from_words(&phase_manifest.base_root_words, "base root")?;
        let auxiliary_root =
            digest_from_words(&phase_manifest.auxiliary_root_words, "auxiliary root")?;
        let quotient_root =
            digest_from_words(&quotient_manifest.quotient_root_words, "quotient root")?;
        let base_layout = ExactBasePhaseLayout::for_tree_role(
            &verified_relation.variant,
            ProofTreeRole::BaseOracle,
        )?;
        let auxiliary_layout = ExactBasePhaseLayout::for_tree_role(
            &verified_relation.variant,
            ProofTreeRole::AuxiliaryOracle,
        )?;
        let mut transcript_prefix = exact_transcript_prefix(
            &prerequisite,
            &verification_context,
            &verified_relation,
            base_root,
            auxiliary_root,
            quotient_root,
        )?;
        let out_of_domain_evaluations = evaluate_exact_out_of_domain_claims(
            &verified_relation.variant,
            &transcript_prefix.opening_points,
            &store,
        )?;
        let opening_batch_mask_chunk_evaluations =
            evaluate_opening_batch_mask_chunks(&store, transcript_prefix.opening_points[0])?;
        verify_production_out_of_domain_composition(
            &mut verified_relation,
            &transcript_prefix,
            &out_of_domain_evaluations,
        )?;
        verify_opening_batch_mask_chunk_evaluations(
            &verified_relation.variant,
            &transcript_prefix.opening_points,
            &out_of_domain_evaluations,
            &opening_batch_mask_chunk_evaluations,
        )?;
        let row_code_whir_transcript = finish_exact_transcript(
            &mut transcript_prefix,
            &out_of_domain_evaluations,
            &opening_batch_mask_chunk_evaluations,
        )?;
        let construction_plan = &verified_relation.row_code_whir_construction_plan;
        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
        let mut prover_challenger = plain_aggregate_challenger_from_transcript(
            &pcs,
            construction_plan.whir_plan(),
            row_code_whir_transcript,
        )?;
        let point_row_weights = derive_exact_point_row_weights(
            &mut prover_challenger,
            &base_layout,
            &auxiliary_layout,
            transcript_prefix.opening_points[0],
        )?;
        let bound_claims = derive_bound_opening_claims(
            &verified_relation.variant,
            &transcript_prefix.opening_points,
            &out_of_domain_evaluations,
            &mut prover_challenger,
        )?;
        ensure_bound_opening_points_are_outside_evaluation_domain(
            &bound_claims,
            verified_relation.variant.evaluation_domain_size(),
            verified_relation.context.evaluation_coset_offset,
        )?;
        let quotient_component_count =
            usize::try_from(verified_relation.context.quotient_component_count)
                .map_err(|_| "quotient component count exceeds usize".to_owned())?;
        let witness = exact_aggregate_witness(
            &store,
            &base_layout,
            &auxiliary_layout,
            quotient_component_count,
            row_pad_seeds,
            &point_row_weights,
            &verified_relation.variant,
            &bound_claims,
            pcs.round_folding_factor(0),
        )?;
        let (aggregate_commitment, committed_prover_data) =
            commit_streaming_plain_aggregate(&pcs, witness, &mut prover_challenger)?;
        drop(committed_prover_data);
        let query_indices = derive_query_indices(&mut prover_challenger, shape)?;
        let bound_query_indices = derive_bound_query_indices(&mut prover_challenger, shape)?;
        let degree_test_points = bound_degree_test_points(&mut prover_challenger)?;
        let bound_evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(verified_relation.variant.evaluation_domain_size())
                .map_err(|_| "bound evaluation domain exceeds usize".to_owned())?,
            verified_relation.context.evaluation_coset_offset,
        )
        .map_err(|error| format!("construct bound evaluation domain: {error:?}"))?;
        if bound_evaluation_domain.generator().canonical()
            != verified_relation.context.evaluation_domain_generator
        {
            return Err("bound evaluation domain has the wrong generator".to_owned());
        }
        let base_source = CheckpointBasePhaseSource::new(&store, &base_layout);
        let auxiliary_source = CheckpointBasePhaseSource::new(&store, &auxiliary_layout);
        let quotient_source = CheckpointQuotientPhaseSource::new(
            &store,
            usize::try_from(verified_relation.context.quotient_component_count)
                .map_err(|_| "quotient component count exceeds usize".to_owned())?,
        )?;
        let (base_columns, base_frontier) = recompute_authenticated_columns(
            &base_source,
            base_layout.geometry()?,
            &row_pad_seeds[0],
            &StreamingCommitment {
                column_root: base_root,
            },
            &query_indices,
        )?;
        let (auxiliary_columns, auxiliary_frontier) = recompute_authenticated_columns(
            &auxiliary_source,
            auxiliary_layout.geometry()?,
            &row_pad_seeds[1],
            &StreamingCommitment {
                column_root: auxiliary_root,
            },
            &query_indices,
        )?;
        let quotient_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
            quotient_source.row_count(),
            PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
            EXACT_ROW_CODE_LOG_INVERSE_RATE,
        )?;
        let (quotient_columns, quotient_frontier) = recompute_authenticated_columns(
            &quotient_source,
            quotient_geometry,
            &row_pad_seeds[2],
            &StreamingCommitment {
                column_root: quotient_root,
            },
            &query_indices,
        )?;
        let bound_tree_authentications = build_bound_tree_authentications(
            &bound_tree_prover_sources,
            &store,
            &bound_tree_entries,
            &bound_query_indices,
            bound_evaluation_domain,
            shape,
        )?;
        let whir_points = exact_whir_opening_points(
            &transcript_prefix.opening_points,
            &point_row_weights,
            &query_indices,
            &bound_query_indices,
            bound_evaluation_domain,
            &degree_test_points,
            shape,
        )?;
        let prover_data = streaming_plain_aggregate_prover_data(
            &pcs,
            exact_aggregate_witness(
                &store,
                &base_layout,
                &auxiliary_layout,
                quotient_component_count,
                row_pad_seeds,
                &point_row_weights,
                &verified_relation.variant,
                &bound_claims,
                pcs.round_folding_factor(0),
            )?,
        )?;
        let requested_columns = requested_columns_by_point(shape);
        let aggregate_opening_proof = open_streaming_plain_aggregate_batches_at_points(
            StreamingPlainAggregateOpeningRequest::new(
                &pcs,
                &aggregate_commitment,
                &whir_points,
                &requested_columns,
            ),
            prover_data,
            &mut prover_challenger,
            || {
                recompute_exact_aggregate_polynomial(
                    &store,
                    &base_layout,
                    &auxiliary_layout,
                    quotient_component_count,
                    row_pad_seeds,
                    &point_row_weights,
                    &verified_relation.variant,
                    &bound_claims,
                    pcs.round_folding_factor(0),
                )
            },
        )?;
        let mut proof = ExactSameSecretProof {
            base_root,
            auxiliary_root,
            quotient_root,
            out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations,
            aggregate_commitment,
            authenticated_phase_columns: [base_columns, auxiliary_columns, quotient_columns],
            phase_frontiers: [base_frontier, auxiliary_frontier, quotient_frontier],
            bound_tree_authentications,
            aggregate_opening_proof,
        };
        verify_phase_openings(shape, &mut proof, &query_indices)?;
        verify_bound_tree_authentications(
            &bound_tree_entries,
            &proof,
            &bound_query_indices,
            shape,
        )?;
        let expected_out_of_domain = expected_out_of_domain_whir_evaluations(
            &verified_relation.variant,
            &base_layout,
            &auxiliary_layout,
            &transcript_prefix.opening_points,
            &proof.out_of_domain_evaluations,
            &proof.opening_batch_mask_chunk_evaluations,
            &point_row_weights,
        )?;
        let expected_queries =
            expected_query_whir_evaluations(shape, &proof, &query_indices, &point_row_weights)?;
        let mut incrementally_accumulated_queries =
            vec![[ChallengeField::ZERO; 3]; shape.outer_query_count];
        for (phase_index, phase_columns) in proof.authenticated_phase_columns.iter().enumerate() {
            accumulate_phase_query_whir_evaluations(
                shape,
                phase_index,
                phase_columns,
                &query_indices,
                &point_row_weights,
                &mut incrementally_accumulated_queries,
            )?;
        }
        if incrementally_accumulated_queries != expected_queries {
            return Err("incremental phase-query accumulation diverged".to_owned());
        }
        let expected_bound_reduction = expected_bound_reduction_whir_evaluations(
            &verified_relation.variant,
            &proof,
            &bound_query_indices,
            bound_evaluation_domain,
            &bound_claims,
            shape,
        )?;
        let mut incrementally_accumulated_bound_reduction =
            vec![ChallengeField::ZERO; shape.bound_reduction_evaluation_count()?];
        for (bound_tree_ordinal, authentication) in
            proof.bound_tree_authentications.iter().enumerate()
        {
            accumulate_bound_tree_reduction_whir_evaluations(
                &verified_relation.variant,
                authentication,
                bound_tree_ordinal,
                &bound_query_indices,
                bound_evaluation_domain,
                &bound_claims,
                shape,
                &mut incrementally_accumulated_bound_reduction,
            )?;
        }
        if incrementally_accumulated_bound_reduction != expected_bound_reduction {
            return Err("incremental bound reduction accumulation diverged".to_owned());
        }
        verify_whir_evaluation_claims(
            &proof.aggregate_opening_proof,
            expected_out_of_domain,
            &expected_queries,
            &expected_bound_reduction,
            shape,
        )?;
        let whir_breakdown = plain_whir_batch_wire_breakdown(
            &pcs,
            &proof.aggregate_opening_proof,
            &expected_opening_widths(construction_plan),
            EXACT_PROOF_TABLE_WIDTH,
        )?;
        let fixed_relation_byte_length = EXACT_PROOF_WIRE_MAGIC.len()
            + 3 * 64
            + 4
            + shape.opening_claim_count * PROOF_CHALLENGE_EXTENSION_DEGREE * 8
            + EXACT_OPENING_BATCH_MASK_CHUNK_COUNT * PROOF_CHALLENGE_EXTENSION_DEGREE * 8
            + 64;
        let phase_value_byte_length =
            shape.outer_query_count * shape.phase_row_counts().into_iter().sum::<usize>() * 8;
        let phase_frontier_byte_length = proof
            .phase_frontiers
            .iter()
            .map(|frontier| 4 + frontier.len() * 64)
            .sum::<usize>();
        let bound_leaf_byte_length = bound_tree_entries
            .iter()
            .zip(&proof.bound_tree_authentications)
            .map(|(entry, authentication)| {
                authentication.opened_leaves.len()
                    * (EXACT_BOUND_TREE_ROW_WIDTH * 2 * 8
                        + if entry.requires_persistent_leaf_salt() {
                            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                        } else {
                            0
                        })
            })
            .sum::<usize>();
        let bound_frontier_byte_length = proof
            .bound_tree_authentications
            .iter()
            .map(|authentication| 4 + authentication.frontier.len() * 64)
            .sum::<usize>();
        let predicted_family_body_byte_length = fixed_relation_byte_length
            + phase_value_byte_length
            + phase_frontier_byte_length
            + bound_leaf_byte_length
            + bound_frontier_byte_length
            + whir_breakdown.complete_byte_length;
        let predicted_complete_proof_byte_length = verification_context
            .canonical_proof_object_header_bytes
            .len()
            .checked_add(predicted_family_body_byte_length)
            .ok_or_else(|| "exact complete proof-size ledger overflowed".to_owned())?;
        if predicted_complete_proof_byte_length > MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH {
            return Err(format!(
                "exact combined proof object predicts {predicted_complete_proof_byte_length} bytes, exceeding the {}-byte selected proof-size target",
                MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH
            ));
        }
        let family_body =
            encode_exact_same_secret_proof(construction_plan, shape, &bound_tree_entries, &proof)?;
        if family_body.len() != predicted_family_body_byte_length {
            return Err(format!(
                "exact family-body size ledger predicts {predicted_family_body_byte_length} bytes but encoded {} bytes",
                family_body.len()
            ));
        }
        let mut proof_object = Vec::new();
        proof_object
            .try_reserve_exact(predicted_complete_proof_byte_length)
            .map_err(|_| "allocate exact complete proof object".to_owned())?;
        proof_object.extend_from_slice(&verification_context.canonical_proof_object_header_bytes);
        proof_object.extend_from_slice(&family_body);
        if proof_object.len() != predicted_complete_proof_byte_length {
            return Err("exact complete proof-size ledger diverged after framing".to_owned());
        }
        let transcript_summary = prover_challenger.finish(&proof_object)?;
        let expected_public_sampler_catalog =
            construction_tests::exact_public_sampler_exhaustion_catalog(
                &pcs,
                &verified_relation.variant,
                &verified_relation.context,
                shape,
            );
        let observed_public_sampler_rows = transcript_summary
            .observed_public_sampler_rows()
            .ok_or_else(|| {
                "exact production transcript did not record public samplers".to_owned()
            })?;
        if observed_public_sampler_rows != expected_public_sampler_catalog.rows() {
            let expected_rows = expected_public_sampler_catalog.rows();
            let mismatch_ordinal = observed_public_sampler_rows
                .iter()
                .zip(expected_rows)
                .position(|(observed, expected)| observed != expected)
                .unwrap_or_else(|| observed_public_sampler_rows.len().min(expected_rows.len()));
            return Err(format!(
                "exact production public sampler trace diverged at row {mismatch_ordinal}: observed {:?}, expected {:?}",
                observed_public_sampler_rows.get(mismatch_ordinal),
                expected_rows.get(mismatch_ordinal),
            ));
        }
        verify_exact_same_secret_proof_bytes(
            verification_prerequisite,
            &verification_context,
            &proof_object,
        )?;
        write_artifact(&store.root().join(EXACT_PROOF_ARTIFACT_NAME), &proof_object)?;
        println!(
            "exact proof wire breakdown: fixed relation {}, phase values {}, phase frontiers {}, bound leaves {}, bound frontiers {}, WHIR {}, WHIR query values {}, WHIR dictionary {}, WHIR references {}",
            fixed_relation_byte_length,
            phase_value_byte_length,
            phase_frontier_byte_length,
            bound_leaf_byte_length,
            bound_frontier_byte_length,
            whir_breakdown.complete_byte_length,
            whir_breakdown.query_value_byte_length,
            whir_breakdown.merkle_dictionary_byte_length,
            whir_breakdown.merkle_reference_byte_length,
        );
        println!(
            "exact same-secret proof object: complete bytes {}, header bytes {}, family-body bytes {}, application statement bytes {}, claims {}, queries {}, complete time {:?}",
            proof_object.len(),
            verification_context
                .canonical_proof_object_header_bytes
                .len(),
            family_body.len(),
            verification_context
                .canonical_application_statement_bytes
                .len(),
            shape.opening_claim_count,
            EXACT_COLUMN_QUERY_COUNT,
            started_at.elapsed(),
        );
        Ok((prerequisite, verification_context, proof_object))
    }

    #[test]
    #[ignore = "manual exact combined same-secret proof gate"]
    fn heavy_rust_kernel_exact_combined_same_secret_proof() {
        let (prerequisite, context, proof) = generate_exact_same_secret_artifacts()
            .expect("generate exact combined same-secret proof");
        let metrics = verify_exact_same_secret_proof_bytes(prerequisite, &context, &proof)
            .expect("fresh native verifier accepts exact same-secret proof");
        assert!(metrics.proof_byte_length <= MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH);
        assert_eq!(metrics.opening_claim_count, 4_217);
        assert_eq!(metrics.query_count, EXACT_COLUMN_QUERY_COUNT);
        assert_eq!(metrics.maximum_transcript_hash_query_count, 1_337_380);
        assert_eq!(metrics.logical_verifier_message_count, 5_076);
        assert_eq!(metrics.maximum_verifier_hash_query_count, 1_430_921);
        assert_eq!(metrics.maximum_accepting_database_equation_count, 1_430_912);
        assert!(metrics.maximum_resident_decoded_payload_byte_length > 0);
        assert!(
            metrics.maximum_resident_decoded_payload_byte_length
                <= MAXIMUM_COMMON_PROOF_BYTE_LENGTH
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod persisted_verifier_tests {
    use std::{fs, path::PathBuf};

    use p3_sumcheck::OpeningBatch;
    use p3_whir::QueryOpening;

    use super::super::native_checkpoint::ExactPolynomialStore;
    use super::*;

    fn artifact_path(file_name: &str) -> PathBuf {
        ExactPolynomialStore::open()
            .expect("open exact polynomial checkpoint")
            .root()
            .join(file_name)
    }

    fn persisted_artifacts() -> (
        VerifiedSameSecretLowDegreePrerequisite,
        ExactSameSecretVerificationContext,
        Vec<u8>,
    ) {
        let ProductionSameSecretEvidenceSources {
            sources,
            authority_handle,
        } = production_same_secret_sources()
            .expect("reconstruct persisted exact authenticated source context");
        let prerequisite = production_same_secret_prerequisite(&sources)
            .expect("reconstruct persisted verified VSS prerequisite");
        let verification_context =
            native_prover::exact_verification_context_from_production_source(&sources)
                .expect("reconstruct persisted typed verification context");
        release_production_same_secret_authority(authority_handle)
            .expect("release persisted exact source authority");
        let proof =
            fs::read(artifact_path(EXACT_PROOF_ARTIFACT_NAME)).expect("read persisted exact proof");
        (prerequisite, verification_context, proof)
    }

    fn prerequisite_from_verification_context(
        verification_context: &ExactSameSecretVerificationContext,
    ) -> Result<VerifiedSameSecretLowDegreePrerequisite, String> {
        prerequisite_with_bindings(
            verification_context,
            verification_context
                .application_slot
                .action_context_hash()
                .into_bytes(),
            [0x25; Hash512::BYTE_LENGTH],
            None,
            TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST,
        )
    }

    fn prerequisite_with_bindings(
        verification_context: &ExactSameSecretVerificationContext,
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        public_setup_seed: [u8; Hash512::BYTE_LENGTH],
        input_roots: Option<[[u8; Hash512::BYTE_LENGTH]; EXACT_INPUT_BOUND_TREE_COUNT]>,
        prior_proof_result_digest: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<VerifiedSameSecretLowDegreePrerequisite, String> {
        let application_slot = verification_context.application_slot;
        let suite_identifier = application_slot.suite_identifier().into_bytes();
        let statement = decode_selected_same_secret_statement(
            &verification_context.canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                verification_context.protocol_version,
                suite_identifier,
                None,
                None,
            ),
        )
        .map_err(|error| format!("decode prerequisite statement: {error:?}"))?;
        let ordered_input_roots = input_roots
            .map_or_else(
                || statement.ordered_degree_zero_commitment_roots().try_into(),
                Ok,
            )
            .map_err(|_| "prerequisite has the wrong input-root count".to_owned())?;
        VerifiedSameSecretLowDegreePrerequisite::for_test(
            verification_context.protocol_version,
            suite_identifier,
            application_slot.ceremony_context_hash().into_bytes(),
            action_context_hash,
            public_setup_seed,
            statement.setup_proof_context_hash(),
            statement.participant_identity(),
            statement.roster_position(),
            ordered_input_roots,
            prior_proof_result_digest,
        )
        .map_err(|error| format!("construct prerequisite: {error:?}"))
    }

    fn default_prerequisite_bindings() -> ([u8; Hash512::BYTE_LENGTH], [u8; Hash512::BYTE_LENGTH]) {
        let mut action_context_hash = [0x23; Hash512::BYTE_LENGTH];
        action_context_hash[Hash512::BYTE_LENGTH - 1] = EXACT_SAME_SECRET_EVIDENCE_REVISION;
        (action_context_hash, [0x25; Hash512::BYTE_LENGTH])
    }

    fn mutate_verification_context(
        verification_context: &ExactSameSecretVerificationContext,
        mutate: impl FnOnce(&mut ExactSameSecretVerificationContext),
    ) -> ExactSameSecretVerificationContext {
        let mut mutated_context = verification_context.clone();
        mutate(&mut mutated_context);
        if let Ok(canonical_header) = canonical_proof_object_header_bytes(
            &mutated_context.canonical_application_statement_bytes,
        ) {
            mutated_context.canonical_proof_object_header_bytes = canonical_header;
        }
        mutated_context
    }

    fn rebind_application_slot(
        verification_context: &mut ExactSameSecretVerificationContext,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        statement_schema_identifier: u16,
    ) {
        let application_slot = verification_context.application_slot;
        verification_context.application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(suite_identifier),
            application_slot.ceremony_context_hash(),
            application_slot.action_context_hash(),
            statement_schema_identifier,
            application_slot.roster_position(),
            application_slot.schedule_position(),
            application_slot.producer_sequence(),
        )
        .expect("rebind exact test application slot");
    }

    fn encode_exact_same_secret_proof_object(
        verification_context: &ExactSameSecretVerificationContext,
        verified_relation: &VerifiedExactRelation,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        proof: &ExactSameSecretProof,
    ) -> Vec<u8> {
        let family_body = encode_exact_same_secret_proof(
            &verified_relation.row_code_whir_construction_plan,
            verified_relation.proof_shape,
            bound_tree_entries,
            proof,
        )
        .expect("encode structurally valid exact family body");
        [
            verification_context
                .canonical_proof_object_header_bytes
                .as_slice(),
            family_body.as_slice(),
        ]
        .concat()
    }

    fn decode_exact_same_secret_proof_object(
        verification_context: &ExactSameSecretVerificationContext,
        verified_relation: &VerifiedExactRelation,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        canonical_proof_object: &[u8],
    ) -> ExactSameSecretProof {
        let mut header_comparator = IncrementalExpectedProofObjectHeaderComparator::new(
            verification_context
                .canonical_proof_object_header_bytes
                .clone(),
            canonical_proof_object.len(),
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        )
        .expect("construct exact proof-object header comparator");
        header_comparator
            .compare_available(canonical_proof_object, canonical_proof_object.len())
            .expect("compare exact proof-object header");
        let body_source = header_comparator
            .body_source(canonical_proof_object)
            .expect("construct exact family-body source");
        let mut family_body = vec![0_u8; body_source.byte_length()];
        assert!(body_source.copy_bytes(0, &mut family_body));
        decode_exact_same_secret_proof(
            &verified_relation.row_code_whir_construction_plan,
            verified_relation.proof_shape,
            bound_tree_entries,
            &family_body,
        )
        .expect("decode exact family body")
    }

    /// Models the historical verifier prefix that authenticated the Boolean
    /// oracle positions and all sumcheck messages but never related a declared
    /// non-Boolean evaluation to that authenticated computation.
    ///
    /// The forged declaration is deliberately not read. The accepted opening
    /// batches are supplied only to reconstruct the unchanged WHIR constraint,
    /// so success means every Merkle path and sumcheck byte outside the omitted
    /// explicit-point equality remains valid.
    fn verify_boolean_authentication_and_sumcheck_without_declared_explicit_evaluation(
        verification_context: &ExactSameSecretVerificationContext,
        forged_proof: &ExactSameSecretProof,
        accepted_opening_batches: &[OpeningBatch<ChallengeField>],
    ) -> Result<(), String> {
        let prerequisite = prerequisite_from_verification_context(verification_context)?;
        let mut verified_relation =
            validate_verification_context(&prerequisite, verification_context)?;
        let shape = verified_relation.proof_shape;
        let bound_tree_entries = exact_bound_tree_catalog_entries(&verified_relation)?;
        let base_layout = ExactBasePhaseLayout::for_tree_role(
            &verified_relation.variant,
            ProofTreeRole::BaseOracle,
        )?;
        let auxiliary_layout = ExactBasePhaseLayout::for_tree_role(
            &verified_relation.variant,
            ProofTreeRole::AuxiliaryOracle,
        )?;
        let mut transcript_prefix = exact_transcript_prefix(
            &prerequisite,
            verification_context,
            &verified_relation,
            forged_proof.base_root,
            forged_proof.auxiliary_root,
            forged_proof.quotient_root,
        )?;
        verify_production_out_of_domain_composition(
            &mut verified_relation,
            &transcript_prefix,
            &forged_proof.out_of_domain_evaluations,
        )?;
        verify_opening_batch_mask_chunk_evaluations(
            &verified_relation.variant,
            &transcript_prefix.opening_points,
            &forged_proof.out_of_domain_evaluations,
            &forged_proof.opening_batch_mask_chunk_evaluations,
        )?;
        let row_code_whir_transcript = finish_exact_transcript(
            &mut transcript_prefix,
            &forged_proof.out_of_domain_evaluations,
            &forged_proof.opening_batch_mask_chunk_evaluations,
        )?;
        let construction_plan = &verified_relation.row_code_whir_construction_plan;
        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
        let mut challenger = plain_aggregate_challenger_from_transcript(
            &pcs,
            construction_plan.whir_plan(),
            row_code_whir_transcript,
        )?;
        let point_row_weights = derive_exact_point_row_weights(
            &mut challenger,
            &base_layout,
            &auxiliary_layout,
            transcript_prefix.opening_points[0],
        )?;
        let bound_claims = derive_bound_opening_claims(
            &verified_relation.variant,
            &transcript_prefix.opening_points,
            &forged_proof.out_of_domain_evaluations,
            &mut challenger,
        )?;
        ensure_bound_opening_points_are_outside_evaluation_domain(
            &bound_claims,
            verified_relation.variant.evaluation_domain_size(),
            verified_relation.context.evaluation_coset_offset,
        )?;
        challenger.observe(forged_proof.aggregate_commitment.clone());
        let query_indices = derive_query_indices(&mut challenger, shape)?;
        let bound_query_indices = derive_bound_query_indices(&mut challenger, shape)?;
        let degree_test_points = bound_degree_test_points(&mut challenger)?;
        let bound_evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(verified_relation.variant.evaluation_domain_size())
                .map_err(|_| "bound evaluation domain exceeds usize".to_owned())?,
            verified_relation.context.evaluation_coset_offset,
        )
        .map_err(|error| format!("construct bound evaluation domain: {error:?}"))?;
        verify_phase_openings(shape, forged_proof, &query_indices)?;
        verify_bound_tree_authentications(
            &bound_tree_entries,
            forged_proof,
            &bound_query_indices,
            shape,
        )?;
        let whir_points = exact_whir_opening_points(
            &transcript_prefix.opening_points,
            &point_row_weights,
            &query_indices,
            &bound_query_indices,
            bound_evaluation_domain,
            &degree_test_points,
            shape,
        )?;
        let weak_prefix_proof = PlainAggregateProof {
            whir: forged_proof.aggregate_opening_proof.whir.clone(),
            evals: accepted_opening_batches.to_vec(),
        };
        verify_plain_aggregate_batches_at_points_after_commitment(
            &pcs,
            &forged_proof.aggregate_commitment,
            &weak_prefix_proof,
            &whir_points,
            construction_plan,
            &mut challenger,
        )
    }

    fn mutate_proof(
        verification_context: &ExactSameSecretVerificationContext,
        canonical_proof_object: &[u8],
        mutate: impl FnOnce(&mut ExactSameSecretProof),
    ) -> Vec<u8> {
        let prerequisite = prerequisite_from_verification_context(verification_context)
            .expect("construct verified VSS prerequisite for mutation");
        let verified_relation = validate_verification_context(&prerequisite, verification_context)
            .expect("validate exact typed context for mutation");
        let bound_tree_entries = exact_bound_tree_catalog_entries(&verified_relation)
            .expect("derive exact bound tree entries for mutation");
        let mut proof = decode_exact_same_secret_proof_object(
            verification_context,
            &verified_relation,
            &bound_tree_entries,
            canonical_proof_object,
        );
        mutate(&mut proof);
        encode_exact_same_secret_proof_object(
            verification_context,
            &verified_relation,
            &bound_tree_entries,
            &proof,
        )
    }

    fn decode_with_available_end_offsets(
        verification_context: &ExactSameSecretVerificationContext,
        verified_relation: &VerifiedExactRelation,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        canonical_proof_object: &[u8],
        available_end_offsets: impl IntoIterator<Item = usize>,
    ) -> ExactSameSecretProof {
        let construction_plan = &verified_relation.row_code_whir_construction_plan;
        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)
            .expect("construct the persisted exact WHIR verifier");
        let mut decoder = ExactSameSecretIncrementalDecoder::new(
            construction_plan,
            verified_relation.proof_shape,
            bound_tree_entries,
            pcs,
            expected_opening_widths(construction_plan),
            canonical_proof_object
                .len()
                .checked_sub(
                    verification_context
                        .canonical_proof_object_header_bytes
                        .len(),
                )
                .expect("exact proof object contains its header"),
        )
        .expect("construct the persisted exact incremental decoder");
        let mut header_comparator = IncrementalExpectedProofObjectHeaderComparator::new(
            verification_context
                .canonical_proof_object_header_bytes
                .clone(),
            canonical_proof_object.len(),
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        )
        .expect("construct persisted proof-object header comparator");
        let mut previous_available_end_offset = 0_usize;
        for available_end_offset in available_end_offsets {
            assert!(
                available_end_offset >= previous_available_end_offset
                    && available_end_offset <= canonical_proof_object.len(),
                "incremental availability ends must be canonical and monotonic"
            );
            header_comparator
                .compare_available(canonical_proof_object, available_end_offset)
                .expect("compare incrementally available exact header bytes");
            if header_comparator.is_complete() {
                let body_source = header_comparator
                    .body_source(canonical_proof_object)
                    .expect("construct incrementally available family-body source");
                let body_available_end_offset =
                    available_end_offset - header_comparator.expected_header_byte_length();
                decoder
                    .consume_available(&body_source, body_available_end_offset)
                    .unwrap_or_else(|error| {
                        panic!(
                            "exact incremental decode failed with bytes available through {available_end_offset}: {error}"
                        )
                    });
                assert!(
                    header_comparator.expected_header_byte_length() + decoder.offset
                        <= available_end_offset
                );
            }
            previous_available_end_offset = available_end_offset;
        }
        assert_eq!(previous_available_end_offset, canonical_proof_object.len());
        decoder
            .finish(bound_tree_entries)
            .expect("finish the persisted exact incremental decode")
    }

    fn adversarial_available_end_offsets(complete_byte_length: usize) -> Vec<usize> {
        let fragment_byte_lengths = [7_usize, 1, 63, 4_097, 3, 65_537, 2, 1_048_576];
        let mut available_end_offsets = vec![0_usize];
        let mut available_end_offset = 0_usize;
        let mut fragment_ordinal = 0_usize;
        while available_end_offset < complete_byte_length {
            available_end_offset = available_end_offset
                .checked_add(fragment_byte_lengths[fragment_ordinal % fragment_byte_lengths.len()])
                .expect("the persisted proof fragment schedule fits usize")
                .min(complete_byte_length);
            available_end_offsets.push(available_end_offset);
            fragment_ordinal += 1;
        }
        available_end_offsets
    }

    fn exact_outer_section_end_offsets(
        verification_context: &ExactSameSecretVerificationContext,
        shape: ExactProofShape,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        proof: &ExactSameSecretProof,
        complete_proof_byte_length: usize,
    ) -> Vec<usize> {
        let mut offsets = vec![
            0,
            verification_context
                .canonical_proof_object_header_bytes
                .len(),
        ];
        let mut offset = verification_context
            .canonical_proof_object_header_bytes
            .len();
        let mut advance = |byte_length: usize| {
            offset = offset
                .checked_add(byte_length)
                .expect("exact section boundary fits usize");
            offsets.push(offset);
        };
        advance(EXACT_PROOF_WIRE_MAGIC.len());
        advance(3 * core::mem::size_of::<ColumnDigest>());
        advance(
            core::mem::size_of::<u32>()
                + proof.out_of_domain_evaluations.len()
                    * PROOF_CHALLENGE_EXTENSION_DEGREE
                    * core::mem::size_of::<u64>(),
        );
        advance(
            EXACT_OPENING_BATCH_MASK_CHUNK_COUNT
                * PROOF_CHALLENGE_EXTENSION_DEGREE
                * core::mem::size_of::<u64>(),
        );
        advance(core::mem::size_of::<ColumnDigest>());
        for row_count in shape.phase_row_counts() {
            advance(shape.outer_query_count * row_count * core::mem::size_of::<Goldilocks>());
        }
        for frontier in &proof.phase_frontiers {
            advance(core::mem::size_of::<u32>() + frontier.len() * 64);
        }
        for (entry, authentication) in bound_tree_entries
            .iter()
            .zip(&proof.bound_tree_authentications)
        {
            let leaf_byte_length = 2 * EXACT_BOUND_TREE_ROW_WIDTH * core::mem::size_of::<u64>()
                + usize::from(entry.requires_persistent_leaf_salt())
                    * COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
            advance(authentication.opened_leaves.len() * leaf_byte_length);
            advance(core::mem::size_of::<u32>() + authentication.frontier.len() * 64);
        }
        assert_eq!(
            offset,
            verification_context
                .canonical_proof_object_header_bytes
                .len()
                + checked_exact_proof_prefix_byte_length(shape, bound_tree_entries, proof)
                    .expect("exact canonical prefix length"),
        );
        offsets.push(complete_proof_byte_length);
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    fn assert_refuses(
        verification_context: &ExactSameSecretVerificationContext,
        proof: &[u8],
        mutation_label: &str,
    ) {
        let Ok(prerequisite) = prerequisite_from_verification_context(verification_context) else {
            return;
        };
        if let Ok(metrics) =
            verify_exact_same_secret_proof_bytes(prerequisite, verification_context, proof)
        {
            panic!(
                "exact verifier accepted {mutation_label}: {} proof bytes, {} claims",
                metrics.proof_byte_length, metrics.opening_claim_count
            );
        }
    }

    fn increment_base_field(value: &mut ProofBaseFieldElement) {
        let canonical = value.canonical();
        let incremented = if canonical == GOLDILOCKS_MODULUS - 1 {
            0
        } else {
            canonical + 1
        };
        *value = ProofBaseFieldElement::from_canonical(incremented)
            .expect("incremented Goldilocks value is canonical");
    }

    fn increment_opening_batch(batch: &mut OpeningBatch<ChallengeField>) {
        let mut current = batch.current().to_vec();
        assert!(!current.is_empty());
        current[0] += ChallengeField::ONE;
        *batch = OpeningBatch::new(current, batch.next().to_vec());
    }

    fn increment_whir_query_value(
        query: &mut QueryOpening<ChallengeField, ChallengeField, Vec<ColumnDigest>>,
    ) {
        match query {
            QueryOpening::Base { values, .. } => {
                values[0] += ChallengeField::ONE;
            }
            QueryOpening::Extension { values, .. } => {
                values[0] += ChallengeField::ONE;
            }
        }
    }

    fn change_whir_query_path(
        query: &mut QueryOpening<ChallengeField, ChallengeField, Vec<ColumnDigest>>,
    ) {
        let path = match query {
            QueryOpening::Base { proof, .. } | QueryOpening::Extension { proof, .. } => proof,
        };
        path[0][0] ^= 1;
    }

    fn swap_distinct_values(values: &mut [Goldilocks]) {
        let different_position = values
            .iter()
            .position(|value| *value != values[0])
            .expect("authenticated production column contains distinct values");
        values.swap(0, different_position);
    }

    fn swap_distinct_eight_byte_chunks(bytes: &mut [u8], first_chunk_offset: usize) {
        let first: [u8; 8] = bytes[first_chunk_offset..first_chunk_offset + 8]
            .try_into()
            .expect("read first extension coordinate");
        let different_chunk_offset = (1..5)
            .map(|coordinate| first_chunk_offset + coordinate * 8)
            .find(|offset| bytes[*offset..*offset + 8] != first)
            .expect("production extension opening contains distinct coordinate limbs");
        let second: [u8; 8] = bytes[different_chunk_offset..different_chunk_offset + 8]
            .try_into()
            .expect("read second extension coordinate");
        bytes[first_chunk_offset..first_chunk_offset + 8].copy_from_slice(&second);
        bytes[different_chunk_offset..different_chunk_offset + 8].copy_from_slice(&first);
    }

    #[test]
    #[ignore = "manual persisted exact verifier gate"]
    fn heavy_rust_kernel_exact_same_secret_persisted_verifier() {
        let (prerequisite, verification_context, proof) = persisted_artifacts();
        let verified_relation = validate_verification_context(&prerequisite, &verification_context)
            .expect("validate persisted typed context for incremental verification");
        let metrics =
            verify_exact_same_secret_proof_bytes(prerequisite, &verification_context, &proof)
                .expect("fresh verifier accepts the persisted canonical proof object");
        assert!(metrics.proof_byte_length <= MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH);
        assert_eq!(
            metrics.canonical_application_statement_byte_length,
            verification_context
                .canonical_application_statement_bytes
                .len()
        );
        assert_eq!(metrics.opening_claim_count, 4_217);
        assert_eq!(metrics.query_count, EXACT_COLUMN_QUERY_COUNT);
        assert_eq!(metrics.maximum_transcript_hash_query_count, 1_337_380);
        assert_eq!(metrics.logical_verifier_message_count, 5_076);
        assert_eq!(metrics.maximum_verifier_hash_query_count, 1_430_921);
        assert_eq!(metrics.maximum_accepting_database_equation_count, 1_430_912);
        assert!(metrics.maximum_resident_decoded_payload_byte_length > 0);
        assert!(
            metrics.maximum_resident_decoded_payload_byte_length
                <= MAXIMUM_COMMON_PROOF_BYTE_LENGTH
        );
        let bound_tree_entries = exact_bound_tree_catalog_entries(&verified_relation)
            .expect("derive persisted bound-tree catalog");

        let one_byte_fragment_decoded = decode_with_available_end_offsets(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &proof,
            0..=proof.len(),
        );
        let one_byte_fragment_reencoded = encode_exact_same_secret_proof_object(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &one_byte_fragment_decoded,
        );
        assert_eq!(one_byte_fragment_reencoded, proof);

        let long_final_fragment_decoded = decode_with_available_end_offsets(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &proof,
            [0, 7, proof.len()],
        );
        let long_final_fragment_reencoded = encode_exact_same_secret_proof_object(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &long_final_fragment_decoded,
        );
        assert_eq!(long_final_fragment_reencoded, proof);

        let adversarial_fragment_decoded = decode_with_available_end_offsets(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &proof,
            adversarial_available_end_offsets(proof.len()),
        );
        let adversarial_fragment_reencoded = encode_exact_same_secret_proof_object(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &adversarial_fragment_decoded,
        );
        assert_eq!(adversarial_fragment_reencoded, proof);

        let retained_proof = decode_exact_same_secret_proof_object(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &proof,
        );
        let boundary_fragment_decoded = decode_with_available_end_offsets(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &proof,
            exact_outer_section_end_offsets(
                &verification_context,
                verified_relation.proof_shape,
                &bound_tree_entries,
                &retained_proof,
                proof.len(),
            ),
        );
        assert_eq!(
            encode_exact_same_secret_proof_object(
                &verification_context,
                &verified_relation,
                &bound_tree_entries,
                &boundary_fragment_decoded,
            ),
            proof,
        );
        println!(
            "persisted exact verifier: complete proof bytes {}, application statement bytes {}, claims {}, queries {}",
            metrics.proof_byte_length,
            metrics.canonical_application_statement_byte_length,
            metrics.opening_claim_count,
            metrics.query_count,
        );
    }

    #[test]
    #[ignore = "manual exact adversarial verifier gate"]
    fn heavy_rust_kernel_exact_same_secret_adversarial_verifier() {
        let (prerequisite, verification_context, proof) = persisted_artifacts();
        let public_input = verification_context.clone();
        let verified_relation = validate_verification_context(&prerequisite, &verification_context)
            .expect("validate persisted typed context for shape derivation");
        let exact_shape = verified_relation.proof_shape;
        let bound_tree_entries = exact_bound_tree_catalog_entries(&verified_relation)
            .expect("derive exact bound-tree catalog for the explicit-point forgery");
        let decoded_proof = decode_exact_same_secret_proof_object(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &proof,
        );
        let transcript_prefix = exact_transcript_prefix(
            &prerequisite,
            &verification_context,
            &verified_relation,
            decoded_proof.base_root,
            decoded_proof.auxiliary_root,
            decoded_proof.quotient_root,
        )
        .expect("derive the accepted proof's explicit opening points");
        verify_exact_same_secret_proof_bytes(prerequisite, &verification_context, &proof)
            .expect("baseline exact proof verifies before adversarial mutations");
        let first_opening_reduction = polynomial_extension_opening_reduction(
            challenge_from_production(transcript_prefix.opening_points[0]),
            LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT.ilog2() as usize,
        )
        .expect("derive the first terminal multilinear point");
        assert!(
            first_opening_reduction
                .multilinear_point
                .as_slice()
                .iter()
                .any(|coordinate| {
                    *coordinate != ChallengeField::ZERO && *coordinate != ChallengeField::ONE
                }),
            "the explicit opening regression requires a non-Boolean terminal point",
        );
        let accepted_terminal_evaluation = decoded_proof.aggregate_opening_proof.evals[0].clone();
        let false_terminal_evaluation = mutate_proof(&verification_context, &proof, |decoded| {
            increment_opening_batch(&mut decoded.aggregate_opening_proof.evals[0]);
        });
        let mut decoded_forgery = decode_exact_same_secret_proof_object(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &false_terminal_evaluation,
        );
        verify_boolean_authentication_and_sumcheck_without_declared_explicit_evaluation(
            &verification_context,
            &decoded_forgery,
            &decoded_proof.aggregate_opening_proof.evals,
        )
        .expect(
            "the Merkle-plus-sumcheck-only prefix must accept when it omits the forged explicit-point declaration",
        );
        let forgery_prerequisite = prerequisite_from_verification_context(&verification_context)
            .expect("construct forgery verified VSS prerequisite");
        let forgery_error = verify_exact_same_secret_proof_bytes(
            forgery_prerequisite,
            &verification_context,
            &false_terminal_evaluation,
        )
        .expect_err("the explicit-point verifier accepted a false terminal evaluation");
        assert!(
            forgery_error.contains(
                "exact WHIR out-of-domain opening 0 does not authenticate the production claims"
            ),
            "the false terminal evaluation reached an unexpected refusal: {forgery_error}",
        );
        let accepted_first_opening_batch = &decoded_proof.aggregate_opening_proof.evals[0];
        let forged_first_opening_batch = &decoded_forgery.aggregate_opening_proof.evals[0];
        assert_ne!(
            forged_first_opening_batch.current()[0],
            accepted_first_opening_batch.current()[0],
            "the forgery must change the sampled non-Boolean terminal evaluation",
        );
        assert_eq!(
            &forged_first_opening_batch.current()[1..],
            &accepted_first_opening_batch.current()[1..],
            "the forgery changed another current-point opening evaluation",
        );
        assert_eq!(
            forged_first_opening_batch.next(),
            accepted_first_opening_batch.next(),
            "the forgery changed a successor-view opening evaluation",
        );
        assert_eq!(
            &decoded_forgery.aggregate_opening_proof.evals[1..],
            &decoded_proof.aggregate_opening_proof.evals[1..],
            "the forgery changed another explicit opening batch",
        );
        decoded_forgery.aggregate_opening_proof.evals[0] = accepted_terminal_evaluation;
        let restored_accepted_proof = encode_exact_same_secret_proof_object(
            &verification_context,
            &verified_relation,
            &bound_tree_entries,
            &decoded_forgery,
        );
        assert_eq!(
            restored_accepted_proof, proof,
            "restoring only the false terminal evaluation must recover every Boolean Merkle opening, commitment, query, and sumcheck byte",
        );

        let changed_protocol = mutate_verification_context(&verification_context, |context| {
            context.protocol_version ^= 1;
        });
        assert_refuses(&changed_protocol, &proof, "changed protocol version");

        let changed_suite = mutate_verification_context(&verification_context, |context| {
            let mut suite_identifier = context.application_slot.suite_identifier().into_bytes();
            suite_identifier[0] ^= 1;
            let schema_identifier = context
                .application_slot
                .application_statement_schema_identifier();
            rebind_application_slot(context, suite_identifier, schema_identifier);
        });
        assert_refuses(&changed_suite, &proof, "changed suite identifier");

        let changed_schema = mutate_verification_context(&verification_context, |context| {
            rebind_application_slot(
                context,
                context.application_slot.suite_identifier().into_bytes(),
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            );
        });
        assert_refuses(&changed_schema, &proof, "changed statement schema");

        let (action_context_hash, public_setup_seed) = default_prerequisite_bindings();
        let mut wrong_action_context_hash = action_context_hash;
        wrong_action_context_hash[0] ^= 1;
        let wrong_action_prerequisite = prerequisite_with_bindings(
            &verification_context,
            wrong_action_context_hash,
            public_setup_seed,
            None,
            TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST,
        )
        .expect("construct wrong-action prerequisite");
        assert!(
            verify_exact_same_secret_proof_bytes(
                wrong_action_prerequisite,
                &verification_context,
                &proof,
            )
            .is_err(),
            "exact verifier accepted a prerequisite for another action",
        );

        let mut wrong_public_setup_seed = public_setup_seed;
        wrong_public_setup_seed[0] ^= 1;
        let wrong_seed_prerequisite = prerequisite_with_bindings(
            &verification_context,
            action_context_hash,
            wrong_public_setup_seed,
            None,
            TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST,
        )
        .expect("construct wrong-seed prerequisite");
        assert!(
            verify_exact_same_secret_proof_bytes(
                wrong_seed_prerequisite,
                &verification_context,
                &proof,
            )
            .is_err(),
            "exact verifier accepted a prerequisite for another setup seed",
        );

        let statement = decode_selected_same_secret_statement(
            &verification_context.canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                verification_context.protocol_version,
                verification_context
                    .application_slot
                    .suite_identifier()
                    .into_bytes(),
                None,
                None,
            ),
        )
        .expect("decode persisted statement for prerequisite mutations");
        let mut wrong_input_roots: [[u8; Hash512::BYTE_LENGTH]; EXACT_INPUT_BOUND_TREE_COUNT] =
            statement
                .ordered_degree_zero_commitment_roots()
                .try_into()
                .expect("persisted statement has eight input roots");
        wrong_input_roots[0][0] ^= 1;
        let wrong_root_prerequisite = prerequisite_with_bindings(
            &verification_context,
            action_context_hash,
            public_setup_seed,
            Some(wrong_input_roots),
            TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST,
        )
        .expect("construct wrong-root prerequisite");
        assert!(
            verify_exact_same_secret_proof_bytes(
                wrong_root_prerequisite,
                &verification_context,
                &proof,
            )
            .is_err(),
            "exact verifier accepted a prerequisite for other input roots",
        );

        let mut wrong_prior_proof_result = TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST;
        wrong_prior_proof_result[0] ^= 1;
        let wrong_prior_proof_prerequisite = prerequisite_with_bindings(
            &verification_context,
            action_context_hash,
            public_setup_seed,
            None,
            wrong_prior_proof_result,
        )
        .expect("construct wrong-prior-proof prerequisite");
        assert!(
            verify_exact_same_secret_proof_bytes(
                wrong_prior_proof_prerequisite,
                &verification_context,
                &proof,
            )
            .is_err(),
            "exact verifier accepted a prerequisite for another VSS proof result",
        );

        let changed_statement = mutate_verification_context(&verification_context, |context| {
            context.canonical_application_statement_bytes[0] ^= 1;
        });
        assert_refuses(&changed_statement, &proof, "changed application statement");

        let changed_public_root = mutate_verification_context(&verification_context, |context| {
            let mut expected_root = context.statement_owned_trees[0].expected_root();
            expected_root[0] ^= 1;
            context.statement_owned_trees[0] =
                context.statement_owned_trees[0].with_test_expected_root(expected_root);
        });
        assert_refuses(&changed_public_root, &proof, "changed public relation root");

        let changed_public_tree_context =
            mutate_verification_context(&verification_context, |context| {
                let mut tree = context.statement_owned_trees[0]
                    .statement_owned_tree_input()
                    .clone();
                match &mut tree {
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash,
                        ..
                    } => material_context_hash[0] ^= 1,
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash,
                        ..
                    } => public_polynomial_context_hash[0] ^= 1,
                }
                context.statement_owned_trees[0] =
                    context.statement_owned_trees[0].with_test_statement_owned_tree_input(tree);
            });
        assert_refuses(
            &changed_public_tree_context,
            &proof,
            "changed public relation-tree context",
        );

        let changed_public_tree_kind =
            mutate_verification_context(&verification_context, |context| {
                let replacement = match context.statement_owned_trees[0]
                    .statement_owned_tree_input()
                    .clone()
                {
                    StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. } => {
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: [0_u8; 64],
                            row_width: EXACT_BOUND_TREE_ROW_WIDTH as u32,
                            expected_root,
                        }
                    }
                    StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. } => {
                        StatementOwnedProofTreeInput::CommittedMaterial {
                            material_context_hash: [0_u8; 64],
                            expected_root,
                        }
                    }
                };
                context.statement_owned_trees[0] = context.statement_owned_trees[0]
                    .with_test_statement_owned_tree_input(replacement);
            });
        assert_refuses(
            &changed_public_tree_kind,
            &proof,
            "changed public relation-tree kind",
        );

        let changed_public_tree_row_width =
            mutate_verification_context(&verification_context, |context| {
                let (tree_index, mut tree) = context
                    .statement_owned_trees
                    .iter()
                    .enumerate()
                    .find_map(|(tree_index, verified_tree)| {
                        match verified_tree.statement_owned_tree_input() {
                            StatementOwnedProofTreeInput::SetupPolynomial { .. } => Some((
                                tree_index,
                                verified_tree.statement_owned_tree_input().clone(),
                            )),
                            StatementOwnedProofTreeInput::CommittedMaterial { .. } => None,
                        }
                    })
                    .expect("the production public tree catalog contains a setup polynomial");
                let StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. } = &mut tree
                else {
                    unreachable!("selected tree is a setup polynomial")
                };
                *row_width = row_width
                    .checked_add(1)
                    .expect("production public tree row width can be incremented");
                context.statement_owned_trees[tree_index] = context.statement_owned_trees
                    [tree_index]
                    .with_test_statement_owned_tree_input(tree);
            });
        assert_refuses(
            &changed_public_tree_row_width,
            &proof,
            "changed public relation-tree row width",
        );

        for (root_ordinal, root_label) in ["base", "auxiliary", "quotient"].into_iter().enumerate()
        {
            let changed_root = mutate_proof(&public_input, &proof, |decoded| {
                let root = match root_ordinal {
                    0 => &mut decoded.base_root,
                    1 => &mut decoded.auxiliary_root,
                    _ => &mut decoded.quotient_root,
                };
                root[0] ^= 1;
            });
            assert_refuses(
                &public_input,
                &changed_root,
                &format!("changed {root_label} phase root"),
            );
        }

        let changed_out_of_domain_evaluation = mutate_proof(&public_input, &proof, |decoded| {
            decoded.out_of_domain_evaluations[0] =
                decoded.out_of_domain_evaluations[0].add(ProofChallengeExtensionElement::ONE);
        });
        assert_refuses(
            &public_input,
            &changed_out_of_domain_evaluation,
            "changed production out-of-domain evaluation",
        );

        let changed_mask_chunk_evaluation = mutate_proof(&public_input, &proof, |decoded| {
            decoded.opening_batch_mask_chunk_evaluations[0] = decoded
                .opening_batch_mask_chunk_evaluations[0]
                .add(ProofChallengeExtensionElement::ONE);
        });
        assert_refuses(
            &public_input,
            &changed_mask_chunk_evaluation,
            "changed opening-batch mask chunk evaluation",
        );

        let changed_aggregate_root = mutate_proof(&public_input, &proof, |decoded| {
            let mut roots = decoded.aggregate_commitment.roots().to_vec();
            roots[0][0] ^= 1;
            decoded.aggregate_commitment = MerkleCap::new(roots);
        });
        assert_refuses(
            &public_input,
            &changed_aggregate_root,
            "changed aggregate commitment root",
        );

        for (phase_ordinal, phase_label) in
            ["base", "auxiliary", "quotient"].into_iter().enumerate()
        {
            let changed_column = mutate_proof(&public_input, &proof, |decoded| {
                decoded.authenticated_phase_columns[phase_ordinal][0].values[0] += Goldilocks::ONE;
            });
            assert_refuses(
                &public_input,
                &changed_column,
                &format!("changed {phase_label} authenticated column value"),
            );

            let changed_frontier = mutate_proof(&public_input, &proof, |decoded| {
                decoded.phase_frontiers[phase_ordinal][0][0] ^= 1;
            });
            assert_refuses(
                &public_input,
                &changed_frontier,
                &format!("changed {phase_label} Merkle frontier"),
            );
        }

        let reordered_phase_values = mutate_proof(&public_input, &proof, |decoded| {
            swap_distinct_values(&mut decoded.authenticated_phase_columns[0][0].values);
        });
        assert_refuses(
            &public_input,
            &reordered_phase_values,
            "reordered packed phase values",
        );

        let changed_bound_salt = mutate_proof(&public_input, &proof, |decoded| {
            let salt = decoded
                .bound_tree_authentications
                .iter_mut()
                .flat_map(|authentication| authentication.opened_leaves.iter_mut())
                .find_map(|opening| opening.persistent_salt.as_mut())
                .expect("production bound authentication includes a persistent salt");
            salt[0] ^= 1;
        });
        assert_refuses(
            &public_input,
            &changed_bound_salt,
            "changed persistent bound leaf salt",
        );

        let changed_bound_value = mutate_proof(&public_input, &proof, |decoded| {
            increment_base_field(
                &mut decoded.bound_tree_authentications[0].opened_leaves[0].first_point_values[0],
            );
        });
        assert_refuses(
            &public_input,
            &changed_bound_value,
            "changed bound first-point value",
        );

        let changed_opposite_bound_value = mutate_proof(&public_input, &proof, |decoded| {
            increment_base_field(
                &mut decoded.bound_tree_authentications[0].opened_leaves[0].opposite_point_values
                    [0],
            );
        });
        assert_refuses(
            &public_input,
            &changed_opposite_bound_value,
            "changed bound opposite-point value",
        );

        let changed_bound_frontier = mutate_proof(&public_input, &proof, |decoded| {
            decoded.bound_tree_authentications[0].frontier[0][0] ^= 1;
        });
        assert_refuses(
            &public_input,
            &changed_bound_frontier,
            "changed bound Merkle frontier",
        );

        let changed_output_bound_value = mutate_proof(&public_input, &proof, |decoded| {
            increment_base_field(
                &mut decoded.bound_tree_authentications[EXACT_INPUT_BOUND_TREE_COUNT].opened_leaves
                    [0]
                .first_point_values[0],
            );
        });
        assert_refuses(
            &public_input,
            &changed_output_bound_value,
            "changed output-bound first-point value",
        );

        let changed_output_bound_frontier = mutate_proof(&public_input, &proof, |decoded| {
            decoded.bound_tree_authentications[EXACT_INPUT_BOUND_TREE_COUNT].frontier[0][0] ^= 1;
        });
        assert_refuses(
            &public_input,
            &changed_output_bound_frontier,
            "changed output-bound Merkle frontier",
        );

        for (evaluation_ordinal, evaluation_label) in [
            (3, "phase-query"),
            (3 + EXACT_COLUMN_QUERY_COUNT, "bound-reduction"),
            (
                3 + EXACT_COLUMN_QUERY_COUNT
                    + (EXACT_INPUT_BOUND_QUERY_COUNT + EXACT_OUTPUT_BOUND_QUERY_COUNT) * 2,
                "bound-degree",
            ),
        ] {
            let changed_evaluation = mutate_proof(&public_input, &proof, |decoded| {
                increment_opening_batch(
                    &mut decoded.aggregate_opening_proof.evals[evaluation_ordinal],
                );
            });
            assert_refuses(
                &public_input,
                &changed_evaluation,
                &format!("changed WHIR {evaluation_label} evaluation"),
            );
        }

        let changed_sumcheck_message = mutate_proof(&public_input, &proof, |decoded| {
            decoded
                .aggregate_opening_proof
                .whir
                .initial_sumcheck
                .polynomial_evaluations[0][0] += ChallengeField::ONE;
        });
        assert_refuses(
            &public_input,
            &changed_sumcheck_message,
            "changed WHIR sumcheck message",
        );

        let whir_round_count = plain_aggregate_pcs(EXACT_PCS_VARIABLE_COUNT)
            .expect("construct exact WHIR configuration for adversarial coverage")
            .n_rounds();
        assert_eq!(whir_round_count, 4);
        for round_ordinal in 0..whir_round_count {
            let changed_round_root = mutate_proof(&public_input, &proof, |decoded| {
                let commitment = decoded.aggregate_opening_proof.whir.rounds[round_ordinal]
                    .commitment
                    .as_mut()
                    .expect("exact WHIR round carries its commitment");
                let mut roots = commitment.roots().to_vec();
                roots[0][0] ^= 1;
                *commitment = MerkleCap::new(roots);
            });
            assert_refuses(
                &public_input,
                &changed_round_root,
                &format!("changed WHIR round {round_ordinal} root"),
            );

            let changed_round_sumcheck = mutate_proof(&public_input, &proof, |decoded| {
                decoded.aggregate_opening_proof.whir.rounds[round_ordinal]
                    .sumcheck
                    .polynomial_evaluations[0][0] += ChallengeField::ONE;
            });
            assert_refuses(
                &public_input,
                &changed_round_sumcheck,
                &format!("changed WHIR round {round_ordinal} sumcheck"),
            );

            let changed_round_query_value = mutate_proof(&public_input, &proof, |decoded| {
                increment_whir_query_value(
                    &mut decoded.aggregate_opening_proof.whir.rounds[round_ordinal].queries[0],
                );
            });
            assert_refuses(
                &public_input,
                &changed_round_query_value,
                &format!("changed WHIR round {round_ordinal} query value"),
            );

            let changed_round_query_path = mutate_proof(&public_input, &proof, |decoded| {
                change_whir_query_path(
                    &mut decoded.aggregate_opening_proof.whir.rounds[round_ordinal].queries[0],
                );
            });
            assert_refuses(
                &public_input,
                &changed_round_query_path,
                &format!("changed WHIR round {round_ordinal} query path"),
            );
        }

        let changed_final_polynomial = mutate_proof(&public_input, &proof, |decoded| {
            let final_polynomial = decoded
                .aggregate_opening_proof
                .whir
                .final_poly
                .as_ref()
                .expect("exact WHIR proof carries a final polynomial");
            let mut evaluations = final_polynomial.as_slice().to_vec();
            evaluations[0] += ChallengeField::ONE;
            decoded.aggregate_opening_proof.whir.final_poly = Some(Poly::new(evaluations));
        });
        assert_refuses(
            &public_input,
            &changed_final_polynomial,
            "changed WHIR final polynomial",
        );

        let changed_final_query_value = mutate_proof(&public_input, &proof, |decoded| {
            increment_whir_query_value(&mut decoded.aggregate_opening_proof.whir.final_queries[0]);
        });
        assert_refuses(
            &public_input,
            &changed_final_query_value,
            "changed WHIR final query value",
        );

        let changed_final_query_path = mutate_proof(&public_input, &proof, |decoded| {
            change_whir_query_path(&mut decoded.aggregate_opening_proof.whir.final_queries[0]);
        });
        assert_refuses(
            &public_input,
            &changed_final_query_path,
            "changed WHIR final query path",
        );

        let changed_final_sumcheck = mutate_proof(&public_input, &proof, |decoded| {
            decoded
                .aggregate_opening_proof
                .whir
                .final_sumcheck
                .as_mut()
                .expect("exact WHIR proof carries a final sumcheck")
                .polynomial_evaluations[0][0] += ChallengeField::ONE;
        });
        assert_refuses(
            &public_input,
            &changed_final_sumcheck,
            "changed WHIR final sumcheck",
        );

        let family_body_offset = verification_context
            .canonical_proof_object_header_bytes
            .len();
        let mut wrong_header = proof.clone();
        wrong_header[0] ^= 1;
        assert_refuses(
            &public_input,
            &wrong_header,
            "wrong canonical proof-object header",
        );

        let mut wrong_magic = proof.clone();
        wrong_magic[family_body_offset] ^= 1;
        assert_refuses(&public_input, &wrong_magic, "wrong proof wire magic");

        let out_of_domain_evaluation_count_offset =
            family_body_offset + EXACT_PROOF_WIRE_MAGIC.len() + 3 * 64;
        assert_eq!(
            out_of_domain_evaluation_count_offset - family_body_offset,
            200
        );
        let mut wrong_out_of_domain_count = proof.clone();
        wrong_out_of_domain_count
            [out_of_domain_evaluation_count_offset..out_of_domain_evaluation_count_offset + 4]
            .copy_from_slice(&0_u32.to_le_bytes());
        assert_refuses(
            &public_input,
            &wrong_out_of_domain_count,
            "wrong out-of-domain-evaluation count",
        );

        let first_out_of_domain_evaluation_offset = out_of_domain_evaluation_count_offset + 4;
        let mut noncanonical_extension = proof.clone();
        noncanonical_extension
            [first_out_of_domain_evaluation_offset..first_out_of_domain_evaluation_offset + 8]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert_refuses(
            &public_input,
            &noncanonical_extension,
            "noncanonical extension coordinate",
        );

        let aggregate_root_offset = first_out_of_domain_evaluation_offset
            + (4_217 + EXACT_OPENING_BATCH_MASK_CHUNK_COUNT) * 40;
        let first_phase_value_offset = aggregate_root_offset + 64;
        let mut noncanonical_phase_value = proof.clone();
        noncanonical_phase_value[first_phase_value_offset..first_phase_value_offset + 8]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert_refuses(
            &public_input,
            &noncanonical_phase_value,
            "noncanonical phase value",
        );

        let mut swapped_extension_limbs = proof.clone();
        swap_distinct_eight_byte_chunks(
            &mut swapped_extension_limbs,
            first_out_of_domain_evaluation_offset,
        );
        assert_refuses(
            &public_input,
            &swapped_extension_limbs,
            "swapped extension-coordinate limbs",
        );

        let first_phase_frontier_offset = first_phase_value_offset
            + EXACT_COLUMN_QUERY_COUNT
                * exact_shape.phase_row_counts().into_iter().sum::<usize>()
                * 8;
        let mut oversized_phase_frontier = proof.clone();
        oversized_phase_frontier[first_phase_frontier_offset..first_phase_frontier_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_refuses(
            &public_input,
            &oversized_phase_frontier,
            "oversized phase frontier count",
        );

        let mut changed_whir_tail = proof.clone();
        *changed_whir_tail.last_mut().expect("proof is nonempty") ^= 1;
        assert_refuses(&public_input, &changed_whir_tail, "changed WHIR tail");

        for truncation_length in [
            0,
            7,
            family_body_offset - 1,
            family_body_offset,
            proof.len() - 1,
        ] {
            assert_refuses(
                &public_input,
                &proof[..truncation_length],
                &format!("proof truncated at byte {truncation_length}"),
            );
        }

        let mut trailing_proof = proof.clone();
        trailing_proof.push(0);
        assert_refuses(&public_input, &trailing_proof, "trailing proof byte");

        for retry_ordinal in 0..3 {
            let retry_prerequisite = prerequisite_from_verification_context(&public_input)
                .expect("construct reset-safe retry prerequisite");
            verify_exact_same_secret_proof_bytes(retry_prerequisite, &public_input, &proof)
                .unwrap_or_else(|error| {
                    panic!(
                        "baseline exact proof fails after adversarial retry {retry_ordinal}: {error}"
                    )
                });
        }
        println!(
            "exact adversarial verifier: all mutations refused and three reset-safe retries accepted"
        );
    }
}
