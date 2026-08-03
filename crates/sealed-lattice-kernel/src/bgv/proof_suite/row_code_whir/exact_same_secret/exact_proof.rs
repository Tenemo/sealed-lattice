//! Canonical combined proof for the exact production same-secret relation.
//!
//! The proof binds the three masked production phases to one aggregate-wide WHIR
//! opening argument. Public statement trees remain verifier-owned inputs and
//! are never accepted from the proof object.

use std::collections::BTreeMap;

#[cfg(test)]
use std::ops::Range;

use p3_challenger::CanObserve;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::OpeningBatch;
use p3_symmetric::MerkleCap;
use zeroize::Zeroizing;

use super::super::GOLDILOCKS_MODULUS;
use super::super::column_commitment::{
    hash_opened_column_with_salt, verify_prehashed_column_frontier,
};
use super::super::compact_merkle_frontier::verify_materialized_bound_frontier;
use super::super::construction_plan::{
    RowCodeWhirAggregateColumnRole, RowCodeWhirBoundLowDegreeMode, RowCodeWhirConstructionPlan,
    RowCodeWhirOpenedPolynomialSource, RowCodeWhirPhase, RowCodeWhirProofSectionPlan,
    RowCodeWhirProofSectionRole, RowCodeWhirSoundnessAssumption, RowCodeWhirTracePhasePlan,
};
use super::super::opening_schedule::phase_index;
use super::super::private_leaf_salt::{
    AcceptedPrivateLeafSaltSet, PRIVATE_LEAF_SALT_BYTE_LENGTH, PrivateLeafSalt,
};
use super::super::row_encoding::RowEncodingGeometry;
#[cfg(test)]
use super::super::verifier_oracle_accounting::derive_deployed_verifier_oracle_accounting;
use super::super::{
    AuthenticatedColumn, ChallengeField, ExtensionFieldChallenger,
    RowCodeWhirChallengerProofStreamAbsorber,
    aggregate_wide_pcs::{
        AggregateWideCommitment, aggregate_wide_challenger_from_transcript,
        aggregate_wide_pcs_for_construction_plan,
    },
    algebra::{coset_point, polynomial_extension_opening_reduction, polynomial_opening_reduction},
};
use super::*;
#[cfg(all(test, feature = "theorem-evidence"))]
use crate::bgv::proof_suite::ValidatedRelationPlanArtifact;
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

const EXACT_PROOF_WIRE_MAGIC: &[u8; 8] = b"SLXPRF08";
const EXACT_ROW_SELECTOR_VARIABLE_COUNT: usize =
    LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW.ilog2() as usize;
const EXACT_TABLE_VARIABLE_COUNT: usize = PHYSICAL_ROW_WITNESS_VARIABLE_COUNT + 1;
const EXACT_PCS_VARIABLE_COUNT: usize =
    EXACT_TABLE_VARIABLE_COUNT + EXACT_ROW_CODE_LOG_INVERSE_RATE;
const EXACT_QUOTIENT_COMPONENT_CHUNK_COUNT: usize = 2;
const EXACT_OPENING_BATCH_MASK_CHUNK_COUNT: usize = LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
const EXACT_QUOTIENT_COMPONENT_ROW_COUNT: usize =
    EXACT_QUOTIENT_COMPONENT_CHUNK_COUNT * PROOF_CHALLENGE_EXTENSION_DEGREE;
const EXACT_QUOTIENT_PHASE_ROW_COUNT: usize =
    (EXACT_QUOTIENT_COMPONENT_CHUNK_COUNT + 1) * PROOF_CHALLENGE_EXTENSION_DEGREE;
const EXACT_BOUND_TREE_COUNT: usize = 11;
const EXACT_INPUT_BOUND_TREE_COUNT: usize = 8;
const EXACT_OUTPUT_BOUND_TREE_COUNT: usize = 3;
const EXACT_BOUND_COLUMN_COUNT: usize = 44;
const EXACT_INPUT_BOUND_COLUMN_COUNT: usize = 32;
const EXACT_OUTPUT_BOUND_COLUMN_COUNT: usize = 12;
pub(in crate::bgv::proof_suite::row_code_whir) const EXACT_BOUND_TREE_ROW_WIDTH: usize = 4;
const EXACT_BOUND_LEAF_COUNT: usize = 1 << (EXACT_PCS_VARIABLE_COUNT - 1);
const EXACT_BOUND_POLYNOMIAL_VARIABLE_COUNT: usize = 15;
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) struct ExactBoundLeafOpening {
    persistent_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    first_point_values: Vec<ProofBaseFieldElement>,
    opposite_point_values: Vec<ProofBaseFieldElement>,
}

impl ExactBoundLeafOpening {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        persistent_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        first_point_values: Vec<ProofBaseFieldElement>,
        opposite_point_values: Vec<ProofBaseFieldElement>,
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
        if self.accepted_input_root_indices.len() != shape.prior_proof_bound_query_count
            || self.accepted_output_root_indices.len() != shape.direct_bound_query_count
            || self.input_root_traversal_indices.len() != shape.prior_proof_bound_query_count
            || self.output_root_traversal_indices.len() != shape.direct_bound_query_count
            || self
                .accepted_output_root_indices
                .get(..shape.prior_proof_bound_query_count)
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
    phase_roots: [Option<ColumnDigest>; 3],
    out_of_domain_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_mask_chunk_evaluations: Vec<ProofChallengeExtensionElement>,
    aggregate_commitment: AggregateWideCommitment,
    aggregate_wide_pad_commitment: AggregateWideCommitment,
    authenticated_phase_columns: [Option<Vec<AuthenticatedColumn>>; 3],
    phase_frontiers: [Option<Vec<ColumnDigest>>; 3],
    bound_tree_authentications: Vec<ExactBoundTreeAuthentication>,
    aggregate_wide_opening_proof: super::super::aggregate_wide_hiding::AggregateWideOpeningProof,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretPhaseOpenings {
    roots: [Option<ColumnDigest>; 3],
    authenticated_columns: [Option<Vec<AuthenticatedColumn>>; 3],
    frontiers: [Option<Vec<ColumnDigest>>; 3],
}

impl ExactSameSecretPhaseOpenings {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        roots: [Option<ColumnDigest>; 3],
        authenticated_columns: [Option<Vec<AuthenticatedColumn>>; 3],
        frontiers: [Option<Vec<ColumnDigest>>; 3],
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
        opening_batch_mask_chunk_evaluations: Vec<ProofChallengeExtensionElement>,
        aggregate_commitment: AggregateWideCommitment,
        aggregate_wide_pad_commitment: AggregateWideCommitment,
        bound_tree_authentications: Vec<ExactBoundTreeAuthentication>,
        aggregate_wide_opening_proof:
            super::super::aggregate_wide_hiding::AggregateWideOpeningProof,
    ) -> Self {
        Self {
            phase_roots: phase_openings.roots,
            out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations,
            aggregate_commitment,
            aggregate_wide_pad_commitment,
            authenticated_phase_columns: phase_openings.authenticated_columns,
            phase_frontiers: phase_openings.frontiers,
            bound_tree_authentications,
            aggregate_wide_opening_proof,
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
    prior_proof_bound_query_count: usize,
    direct_bound_query_count: usize,
    aggregate_table_width: usize,
    phase_leaf_salt_byte_length: usize,
}

impl ExactProofShape {
    const fn phase_row_counts(self) -> [usize; 3] {
        [
            self.base_row_count,
            self.auxiliary_row_count,
            self.quotient_row_count,
        ]
    }

    fn maximum_frontier_count(self) -> Result<usize, String> {
        crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
            self.encoded_column_count,
            self.outer_query_count,
        )
        .map_err(|error| format!("derive exact phase frontier bound: {error:?}"))
    }

    fn maximum_bound_frontier_count(query_count: usize) -> Result<usize, String> {
        crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
            EXACT_BOUND_LEAF_COUNT,
            query_count,
        )
        .map_err(|error| format!("derive exact bound frontier bound: {error:?}"))
    }

    fn bound_reduction_evaluation_count(self) -> Result<usize, String> {
        self.prior_proof_bound_query_count
            .checked_add(self.direct_bound_query_count)
            .and_then(|query_count| query_count.checked_mul(2))
            .ok_or_else(|| "bound reduction evaluation count overflowed".to_owned())
    }

    fn bound_tree_query_count(self, bound_tree_ordinal: usize) -> Result<usize, String> {
        match bound_tree_ordinal {
            0..EXACT_INPUT_BOUND_TREE_COUNT => Ok(self.prior_proof_bound_query_count),
            EXACT_INPUT_BOUND_TREE_COUNT..EXACT_BOUND_TREE_COUNT => {
                Ok(self.direct_bound_query_count)
            }
            _ => Err("bound tree ordinal is outside the exact relation".to_owned()),
        }
    }
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ExactSameSecretTransportDecoderOwner {
    TranscriptMaterial,
    PhaseColumnsAndCompactFrontier { phase: RowCodeWhirPhase },
    BoundLeavesAndCompactFrontier { bound_tree_ordinal: u32 },
    CanonicalAggregateWideTerminal,
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ExactSameSecretTransportSemanticOwner {
    RelationCommitment { phase: RowCodeWhirPhase },
    OutOfDomainCompositionAndRegisteredClaims,
    OpeningBatchMaskConsistency,
    AggregateConstrainedPolynomialCommitment,
    AggregateWidePadCommitmentBinding,
    PhaseOpeningAuthenticationAndReduction { phase: RowCodeWhirPhase },
    BoundAuthenticationAndReduction { bound_tree_ordinal: u32 },
    ExplicitPointAggregateWideOpening,
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ExactSameSecretTransportCountSource {
    ConstructionPlanFixed,
    TransportedU32EqualToConstructionPlan,
    ConstructionPlanFixedWithTransportedCoordinateFrontierCount,
    DeclaredRemainingLengthWithCanonicalInnerDecoder,
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ExactSameSecretTransportLengthRule {
    Digest,
    CountedExtensionValues {
        value_count: usize,
    },
    FixedExtensionValues {
        value_count: usize,
    },
    PhaseCompactOpening {
        query_count: usize,
        row_count: usize,
        leaf_salt_byte_length: usize,
        encoded_column_count: usize,
    },
    BoundCompactOpening {
        query_count: usize,
        row_width: usize,
        leaf_salt_byte_length: usize,
        leaf_count: usize,
    },
    CanonicalAggregateWideOpening {
        byte_length: usize,
    },
}

#[cfg(all(test, feature = "theorem-evidence"))]
impl ExactSameSecretTransportLengthRule {
    fn canonical_byte_length_ceiling(self) -> Result<usize, String> {
        let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| "exact transport extension width overflowed".to_owned())?;
        match self {
            Self::Digest => Ok(64),
            Self::CountedExtensionValues { value_count } => value_count
                .checked_mul(extension_byte_length)
                .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
                .ok_or_else(|| "exact transported extension section overflowed".to_owned()),
            Self::FixedExtensionValues { value_count } => value_count
                .checked_mul(extension_byte_length)
                .ok_or_else(|| "exact transported extension section overflowed".to_owned()),
            Self::PhaseCompactOpening {
                query_count,
                row_count,
                leaf_salt_byte_length,
                encoded_column_count,
            } => {
                let opened_leaf_byte_length = row_count
                    .checked_mul(core::mem::size_of::<u64>())
                    .and_then(|length| length.checked_add(leaf_salt_byte_length))
                    .ok_or_else(|| "exact transported phase leaf width overflowed".to_owned())?;
                let maximum_frontier_node_count =
                    crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
                        encoded_column_count,
                        query_count,
                    )
                    .map_err(|error| {
                        format!("derive exact transported phase frontier: {error:?}")
                    })?;
                query_count
                    .checked_mul(opened_leaf_byte_length)
                    .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
                    .and_then(|length| {
                        maximum_frontier_node_count
                            .checked_mul(64)
                            .and_then(|frontier_length| length.checked_add(frontier_length))
                    })
                    .ok_or_else(|| "exact transported phase section overflowed".to_owned())
            }
            Self::BoundCompactOpening {
                query_count,
                row_width,
                leaf_salt_byte_length,
                leaf_count,
            } => {
                let opened_leaf_byte_length = row_width
                    .checked_mul(2)
                    .and_then(|value_count| value_count.checked_mul(core::mem::size_of::<u64>()))
                    .and_then(|length| length.checked_add(leaf_salt_byte_length))
                    .ok_or_else(|| "exact transported bound leaf width overflowed".to_owned())?;
                let maximum_frontier_node_count =
                    crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
                        leaf_count,
                        query_count,
                    )
                    .map_err(|error| {
                        format!("derive exact transported bound frontier: {error:?}")
                    })?;
                query_count
                    .checked_mul(opened_leaf_byte_length)
                    .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
                    .and_then(|length| {
                        maximum_frontier_node_count
                            .checked_mul(64)
                            .and_then(|frontier_length| length.checked_add(frontier_length))
                    })
                    .ok_or_else(|| "exact transported bound section overflowed".to_owned())
            }
            Self::CanonicalAggregateWideOpening { byte_length } if byte_length > 0 => {
                Ok(byte_length)
            }
            Self::CanonicalAggregateWideOpening { .. } => {
                Err("exact transported aggregate-wide section is empty".to_owned())
            }
        }
    }
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ExactSameSecretTransportSectionRow {
    pub(in crate::bgv::proof_suite) section: RowCodeWhirProofSectionPlan,
    pub(in crate::bgv::proof_suite) decoder_owner: ExactSameSecretTransportDecoderOwner,
    pub(in crate::bgv::proof_suite) semantic_owner: ExactSameSecretTransportSemanticOwner,
    pub(in crate::bgv::proof_suite) count_source: ExactSameSecretTransportCountSource,
    pub(in crate::bgv::proof_suite) length_rule: ExactSameSecretTransportLengthRule,
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ExactSameSecretTransportBinding {
    CanonicalApplicationStatement,
    ProtocolVersion,
    SuiteIdentifier,
    CeremonyContext,
    ActionContext,
    ApplicationSlot,
    RelationPlanIdentity,
    RelationPlanVariantIdentity,
    ConstructionPlanIdentity,
    DeclaredCompleteProofLength,
    FinalCanonicalProofStreamDigest,
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ExactSameSecretTransportRefusal {
    WrongCanonicalProofObjectHeader,
    WrongDeclaredProofLength,
    OversizedDeclaredProofLength,
    WrongFamilyWireMagic,
    TruncatedSection,
    TrailingBytes,
    OmittedOrReorderedConstructionSection,
    WrongFixedItemCount,
    OversizedCoordinateFrontierCount,
    ReusedPrivateLeafSalt,
    NonCanonicalBaseFieldEncoding,
    NonCanonicalExtensionFieldEncoding,
    NonCanonicalAggregateWideSuffix,
}

/// Production-code correspondence from the checked construction sections to
/// the transported row-code WHIR decoder and its semantic verifier.
///
/// The certificate is structural: it proves that the canonical parser has one
/// plan-owned interpretation and that its byte ceiling is the sum of those
/// exact section rules. Acceptance of a concrete emitted proof remains runtime
/// evidence and is not inferred from this catalog.
#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ExactSameSecretTransportCorrespondenceCertificate {
    pub(in crate::bgv::proof_suite) construction_plan_identity_hash: [u8; 64],
    pub(in crate::bgv::proof_suite) relation_plan_hash: [u8; 64],
    pub(in crate::bgv::proof_suite) relation_plan_variant_hash: [u8; 64],
    pub(in crate::bgv::proof_suite) family_wire_magic: [u8; 8],
    pub(in crate::bgv::proof_suite) section_rows: Vec<ExactSameSecretTransportSectionRow>,
    pub(in crate::bgv::proof_suite) bindings: Vec<ExactSameSecretTransportBinding>,
    pub(in crate::bgv::proof_suite) refusals: Vec<ExactSameSecretTransportRefusal>,
    pub(in crate::bgv::proof_suite) aggregate_opening_section_ledger: Vec<(&'static str, usize)>,
    pub(in crate::bgv::proof_suite) family_body_byte_length_ceiling: usize,
}

#[cfg(all(test, feature = "theorem-evidence"))]
const EXACT_SAME_SECRET_TRANSPORT_BINDINGS: [ExactSameSecretTransportBinding; 11] = [
    ExactSameSecretTransportBinding::CanonicalApplicationStatement,
    ExactSameSecretTransportBinding::ProtocolVersion,
    ExactSameSecretTransportBinding::SuiteIdentifier,
    ExactSameSecretTransportBinding::CeremonyContext,
    ExactSameSecretTransportBinding::ActionContext,
    ExactSameSecretTransportBinding::ApplicationSlot,
    ExactSameSecretTransportBinding::RelationPlanIdentity,
    ExactSameSecretTransportBinding::RelationPlanVariantIdentity,
    ExactSameSecretTransportBinding::ConstructionPlanIdentity,
    ExactSameSecretTransportBinding::DeclaredCompleteProofLength,
    ExactSameSecretTransportBinding::FinalCanonicalProofStreamDigest,
];

#[cfg(all(test, feature = "theorem-evidence"))]
const EXACT_SAME_SECRET_TRANSPORT_REFUSALS: [ExactSameSecretTransportRefusal; 13] = [
    ExactSameSecretTransportRefusal::WrongCanonicalProofObjectHeader,
    ExactSameSecretTransportRefusal::WrongDeclaredProofLength,
    ExactSameSecretTransportRefusal::OversizedDeclaredProofLength,
    ExactSameSecretTransportRefusal::WrongFamilyWireMagic,
    ExactSameSecretTransportRefusal::TruncatedSection,
    ExactSameSecretTransportRefusal::TrailingBytes,
    ExactSameSecretTransportRefusal::OmittedOrReorderedConstructionSection,
    ExactSameSecretTransportRefusal::WrongFixedItemCount,
    ExactSameSecretTransportRefusal::OversizedCoordinateFrontierCount,
    ExactSameSecretTransportRefusal::ReusedPrivateLeafSalt,
    ExactSameSecretTransportRefusal::NonCanonicalBaseFieldEncoding,
    ExactSameSecretTransportRefusal::NonCanonicalExtensionFieldEncoding,
    ExactSameSecretTransportRefusal::NonCanonicalAggregateWideSuffix,
];

#[cfg(all(test, feature = "theorem-evidence"))]
fn exact_same_secret_transport_section_rows(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<Vec<ExactSameSecretTransportSectionRow>, String> {
    let aggregate_opening_byte_length =
        canonical_row_code_whir_aggregate_opening_section_byte_ledger(construction_plan)?
            .iter()
            .try_fold(0_usize, |total, (_, byte_length)| {
                total
                    .checked_add(*byte_length)
                    .ok_or_else(|| "exact aggregate opening byte length overflowed".to_owned())
            })?;
    construction_plan
        .proof_sections()
        .iter()
        .copied()
        .map(|section| {
            let (decoder_owner, semantic_owner, count_source, length_rule) = match section.role {
                RowCodeWhirProofSectionRole::RelationCommitment { phase } => (
                    ExactSameSecretTransportDecoderOwner::TranscriptMaterial,
                    ExactSameSecretTransportSemanticOwner::RelationCommitment { phase },
                    ExactSameSecretTransportCountSource::ConstructionPlanFixed,
                    ExactSameSecretTransportLengthRule::Digest,
                ),
                RowCodeWhirProofSectionRole::OutOfDomainEvaluations => (
                    ExactSameSecretTransportDecoderOwner::TranscriptMaterial,
                    ExactSameSecretTransportSemanticOwner::OutOfDomainCompositionAndRegisteredClaims,
                    ExactSameSecretTransportCountSource::TransportedU32EqualToConstructionPlan,
                    ExactSameSecretTransportLengthRule::CountedExtensionValues {
                        value_count: section.item_count,
                    },
                ),
                RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => (
                    ExactSameSecretTransportDecoderOwner::TranscriptMaterial,
                    ExactSameSecretTransportSemanticOwner::OpeningBatchMaskConsistency,
                    ExactSameSecretTransportCountSource::ConstructionPlanFixed,
                    ExactSameSecretTransportLengthRule::FixedExtensionValues {
                        value_count: section.item_count,
                    },
                ),
                RowCodeWhirProofSectionRole::AggregateCommitment => (
                    ExactSameSecretTransportDecoderOwner::TranscriptMaterial,
                    ExactSameSecretTransportSemanticOwner::AggregateConstrainedPolynomialCommitment,
                    ExactSameSecretTransportCountSource::ConstructionPlanFixed,
                    ExactSameSecretTransportLengthRule::Digest,
                ),
                RowCodeWhirProofSectionRole::AggregateWidePadCommitment => (
                    ExactSameSecretTransportDecoderOwner::TranscriptMaterial,
                    ExactSameSecretTransportSemanticOwner::AggregateWidePadCommitmentBinding,
                    ExactSameSecretTransportCountSource::ConstructionPlanFixed,
                    ExactSameSecretTransportLengthRule::Digest,
                ),
                RowCodeWhirProofSectionRole::PhaseOpenings { phase } => {
                    let row_count = construction_plan
                        .phase_row_count(phase)
                        .ok_or_else(|| "exact transported phase has no row geometry".to_owned())?;
                    let encoded_column_count = construction_plan
                        .phase_encoded_column_count(phase)
                        .ok_or_else(|| {
                            "exact transported phase has no encoded domain".to_owned()
                        })?;
                    (
                        ExactSameSecretTransportDecoderOwner::PhaseColumnsAndCompactFrontier {
                            phase,
                        },
                        ExactSameSecretTransportSemanticOwner::PhaseOpeningAuthenticationAndReduction {
                            phase,
                        },
                        ExactSameSecretTransportCountSource::ConstructionPlanFixedWithTransportedCoordinateFrontierCount,
                        ExactSameSecretTransportLengthRule::PhaseCompactOpening {
                            query_count: section.item_count,
                            row_count,
                            leaf_salt_byte_length: if construction_plan.proof_privacy_mode
                                == ProofPrivacyMode::SecretBearing
                            {
                                PRIVATE_LEAF_SALT_BYTE_LENGTH
                            } else {
                                0
                            },
                            encoded_column_count,
                        },
                    )
                }
                RowCodeWhirProofSectionRole::BoundTreeOpenings {
                    bound_tree_ordinal,
                } => {
                    let bound_tree_index = usize::try_from(bound_tree_ordinal)
                        .map_err(|_| "exact transported bound-tree ordinal exceeds usize".to_owned())?;
                    let bound_tree = construction_plan
                        .bound_trees
                        .get(bound_tree_index)
                        .ok_or_else(|| "exact transported bound tree is absent".to_owned())?;
                    if bound_tree.bound_tree_ordinal != bound_tree_ordinal
                        || bound_tree.query_count != section.item_count
                    {
                        return Err("exact transported bound-tree section diverges from the plan".to_owned());
                    }
                    (
                        ExactSameSecretTransportDecoderOwner::BoundLeavesAndCompactFrontier {
                            bound_tree_ordinal,
                        },
                        ExactSameSecretTransportSemanticOwner::BoundAuthenticationAndReduction {
                            bound_tree_ordinal,
                        },
                        ExactSameSecretTransportCountSource::ConstructionPlanFixedWithTransportedCoordinateFrontierCount,
                        ExactSameSecretTransportLengthRule::BoundCompactOpening {
                            query_count: section.item_count,
                            row_width: bound_tree.ordered_columns.len(),
                            leaf_salt_byte_length: if bound_tree.construction_kind
                                == BoundTreeConstructionKind::CommittedMaterial
                            {
                                COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                            } else {
                                0
                            },
                            leaf_count: bound_tree.leaf_count,
                        },
                    )
                }
                RowCodeWhirProofSectionRole::AggregateWideOpening => (
                    ExactSameSecretTransportDecoderOwner::CanonicalAggregateWideTerminal,
                    ExactSameSecretTransportSemanticOwner::ExplicitPointAggregateWideOpening,
                    ExactSameSecretTransportCountSource::DeclaredRemainingLengthWithCanonicalInnerDecoder,
                    ExactSameSecretTransportLengthRule::CanonicalAggregateWideOpening {
                        byte_length: aggregate_opening_byte_length,
                    },
                ),
            };
            Ok(ExactSameSecretTransportSectionRow {
                section,
                decoder_owner,
                semantic_owner,
                count_source,
                length_rule,
            })
        })
        .collect()
}

#[cfg(all(test, feature = "theorem-evidence"))]
impl ExactSameSecretTransportCorrespondenceCertificate {
    pub(in crate::bgv::proof_suite) fn is_bound_to_construction_plan(
        &self,
        construction_plan: &RowCodeWhirConstructionPlan,
    ) -> bool {
        let Ok(construction_plan_identity_hash) = construction_plan.canonical_identity_hash()
        else {
            return false;
        };
        let Ok(expected_rows) = exact_same_secret_transport_section_rows(construction_plan) else {
            return false;
        };
        let Ok(expected_family_body_byte_length_ceiling) =
            expected_rows
                .iter()
                .try_fold(EXACT_PROOF_WIRE_MAGIC.len(), |total, row| {
                    row.length_rule
                        .canonical_byte_length_ceiling()
                        .and_then(|byte_length| {
                            total.checked_add(byte_length).ok_or_else(|| {
                                "exact transported family-body length overflowed".to_owned()
                            })
                        })
                })
        else {
            return false;
        };
        self.construction_plan_identity_hash == construction_plan_identity_hash
            && self.relation_plan_hash == construction_plan.relation_plan_hash
            && self.relation_plan_variant_hash == construction_plan.relation_plan_variant_hash
            && self.family_wire_magic == *EXACT_PROOF_WIRE_MAGIC
            && self.section_rows == expected_rows
            && self
                .section_rows
                .iter()
                .map(|row| row.section)
                .eq(construction_plan.proof_sections().iter().copied())
            && self.bindings == EXACT_SAME_SECRET_TRANSPORT_BINDINGS
            && self.refusals == EXACT_SAME_SECRET_TRANSPORT_REFUSALS
            && self.aggregate_opening_section_ledger
                == canonical_row_code_whir_aggregate_opening_section_byte_ledger(construction_plan)
                    .unwrap_or_default()
            && self.family_body_byte_length_ceiling == expected_family_body_byte_length_ceiling
            && self.family_body_byte_length_ceiling > 0
            && self.family_body_byte_length_ceiling <= MAXIMUM_COMMON_PROOF_BYTE_LENGTH
    }

    pub(in crate::bgv::proof_suite) fn is_complete_for(
        &self,
        construction_plan: &RowCodeWhirConstructionPlan,
        relation_plan: &ValidatedRelationPlanArtifact,
        relation_variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
    ) -> bool {
        let Ok(relation_plan_variant_hash) = relation_variant.canonical_hash() else {
            return false;
        };
        if validate_row_code_whir_transport_construction_plan(
            construction_plan,
            relation_plan,
            relation_variant,
            relation_context,
        )
        .is_err()
        {
            return false;
        }
        self.relation_plan_variant_hash == relation_plan_variant_hash
            && self.is_bound_to_construction_plan(construction_plan)
    }
}

#[cfg(all(test, feature = "theorem-evidence"))]
fn validate_row_code_whir_transport_construction_plan(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_plan: &ValidatedRelationPlanArtifact,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<(), String> {
    let relation_plan_variant_hash = relation_variant
        .canonical_hash()
        .map_err(|error| format!("hash row-code WHIR relation variant for transport: {error:?}"))?;
    let selected_variant = relation_plan
        .compiled_plan()
        .select_variant(
            construction_plan.schedule_position,
            construction_plan.top_count,
        )
        .map_err(|error| {
            format!("select row-code WHIR relation variant for transport: {error:?}")
        })?;
    let selected_variant_hash = selected_variant
        .canonical_hash()
        .map_err(|error| format!("hash selected row-code WHIR relation variant: {error:?}"))?;
    let expected_construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        relation_plan,
        construction_plan.schedule_position,
        construction_plan.top_count,
    )
    .map_err(|error| format!("derive row-code WHIR construction for transport: {error:?}"))?;
    if relation_plan.application_statement_schema_identifier()
        != construction_plan.application_statement_schema_identifier
        || relation_plan.checked_context() != relation_context
        || relation_plan.canonical_plan_hash() != construction_plan.relation_plan_hash
        || relation_plan_variant_hash != selected_variant_hash
        || construction_plan.relation_plan_variant_hash != relation_plan_variant_hash
        || expected_construction_plan != *construction_plan
    {
        return Err(
            "transported row-code WHIR proof diverges from the selected construction".to_owned(),
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "theorem-evidence"))]
pub(in crate::bgv::proof_suite) fn checked_row_code_whir_transport_correspondence(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_plan: &ValidatedRelationPlanArtifact,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<ExactSameSecretTransportCorrespondenceCertificate, String> {
    let relation_plan_variant_hash = relation_variant
        .canonical_hash()
        .map_err(|error| format!("hash row-code WHIR relation variant for transport: {error:?}"))?;
    validate_row_code_whir_transport_construction_plan(
        construction_plan,
        relation_plan,
        relation_variant,
        relation_context,
    )?;
    let section_rows = exact_same_secret_transport_section_rows(construction_plan)?;
    let family_body_byte_length_ceiling =
        section_rows
            .iter()
            .try_fold(EXACT_PROOF_WIRE_MAGIC.len(), |total, row| {
                row.length_rule
                    .canonical_byte_length_ceiling()
                    .and_then(|byte_length| {
                        total.checked_add(byte_length).ok_or_else(|| {
                            "exact transported family-body length overflowed".to_owned()
                        })
                    })
            })?;
    let certificate = ExactSameSecretTransportCorrespondenceCertificate {
        construction_plan_identity_hash: construction_plan
            .canonical_identity_hash()
            .map_err(|error| format!("hash row-code WHIR construction for transport: {error:?}"))?,
        relation_plan_hash: relation_plan.canonical_plan_hash(),
        relation_plan_variant_hash,
        family_wire_magic: *EXACT_PROOF_WIRE_MAGIC,
        section_rows,
        bindings: EXACT_SAME_SECRET_TRANSPORT_BINDINGS.to_vec(),
        refusals: EXACT_SAME_SECRET_TRANSPORT_REFUSALS.to_vec(),
        aggregate_opening_section_ledger:
            canonical_row_code_whir_aggregate_opening_section_byte_ledger(construction_plan)?,
        family_body_byte_length_ceiling,
    };
    if !certificate.is_complete_for(
        construction_plan,
        relation_plan,
        relation_variant,
        relation_context,
    ) {
        return Err("transported row-code WHIR proof correspondence is incomplete".to_owned());
    }
    Ok(certificate)
}

#[cfg(all(test, feature = "theorem-evidence"))]
pub(in crate::bgv::proof_suite) fn checked_exact_same_secret_transport_correspondence(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_plan: &ValidatedRelationPlanArtifact,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<ExactSameSecretTransportCorrespondenceCertificate, String> {
    if construction_plan.application_statement_schema_identifier
        != crate::foundation::ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
    {
        return Err("exact same-secret transport requires the same-secret schema".to_owned());
    }
    checked_row_code_whir_transport_correspondence(
        construction_plan,
        relation_plan,
        relation_variant,
        relation_context,
    )
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
            != u32::try_from(EXACT_QUOTIENT_COMPONENT_COUNT)
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

    let quotient_row_count = EXACT_QUOTIENT_COMPONENT_ROW_COUNT;
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
            for (row_position, chunk) in row.logical_polynomial_chunks.iter().enumerate() {
                if row_position >= EXACT_QUOTIENT_COMPONENT_COUNT {
                    if chunk.is_some() {
                        return Err("exact quotient row populates a non-component lane".to_owned());
                    }
                    continue;
                }
                let component_ordinal = row_position;
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
                    plan.parameters.prior_proof_bound_query_count,
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
            vec![0, 0, 0, 0, 0, 0, 0],
            EXACT_INPUT_BOUND_DEGREE_SUFFIX_PREFIXES
                .iter()
                .map(|prefix| prefix.to_vec())
                .collect::<Vec<_>>(),
            plan.parameters.prior_proof_bound_query_count,
        ),
        (
            RowCodeWhirBoundLowDegreeMode::Direct,
            (8_u32..11).collect::<Vec<_>>(),
            16_384_u64,
            16_383_u64,
            vec![0, 0, 0, 0, 0, 0, 1],
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
        || parameters.prior_proof_bound_query_count == 0
        || parameters.prior_proof_bound_query_count > parameters.direct_bound_query_count
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
        prior_proof_bound_query_count: parameters.prior_proof_bound_query_count,
        direct_bound_query_count: parameters.direct_bound_query_count,
        aggregate_table_width: plan.aggregate_table_width(),
        phase_leaf_salt_byte_length: if plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing {
            PRIVATE_LEAF_SALT_BYTE_LENGTH
        } else {
            0
        },
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
    let opening_widths = expected_opening_widths(construction_plan);
    // Production decoding retains the authenticated family body while the
    // coordinate-free aggregate-wide terminal is materialized. Every owned
    // terminal value has a canonical wire representation of at least its
    // in-memory payload width, so twice the body length covers the source
    // buffer and decoded payload together. Fixed Vec headers are included in
    // the fixed verifier structures below.
    let aggregate_wide_decode_payload_byte_length =
        checked_exact_verifier_resident_memory_multiply(family_body_byte_length, 2)?;

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
        .prior_proof_bound_query_count
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
    let maximum_bound_frontier_count =
        ExactProofShape::maximum_bound_frontier_count(shape.direct_bound_query_count)?;
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
        .max(aggregate_wide_decode_payload_byte_length);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactSameSecretVerifierAccounting {
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    #[cfg(test)]
    maximum_verifier_hash_query_count: u64,
    #[cfg(test)]
    maximum_accepting_database_equation_count: u64,
}

fn exact_same_secret_verifier_accounting(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
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
    #[cfg(test)]
    let deployed_accounting =
        derive_deployed_verifier_oracle_accounting(construction_plan, relation_variant)?;
    #[cfg(not(test))]
    let _ = relation_variant;
    Ok(ExactSameSecretVerifierAccounting {
        maximum_transcript_hash_query_count,
        logical_verifier_message_count,
        #[cfg(test)]
        maximum_verifier_hash_query_count: deployed_accounting.maximum_verifier_hash_query_count(),
        #[cfg(test)]
        maximum_accepting_database_equation_count: deployed_accounting
            .maximum_accepting_database_equation_count(),
    })
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
        .map_err(|error| format!("derive exact transcript schedule: {error:?}"))?;
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
        .get(..shape.prior_proof_bound_query_count)
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
    pub(super) selectors: [ChallengeField; EXACT_ROW_SELECTOR_VARIABLE_COUNT],
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
        let selectors = (0..EXACT_ROW_SELECTOR_VARIABLE_COUNT)
            .map(|selector_ordinal| {
                challenger.sample_exact_challenge(RowCodeWhirChallenge::PointSelectorWeight {
                    opening_point_ordinal,
                    selector_ordinal: u16::try_from(selector_ordinal)
                        .map_err(|_| "row selector ordinal exceeds u16".to_owned())?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "exact row selector count changed".to_owned())?;
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
            for extension_coordinate in 0..PROOF_CHALLENGE_EXTENSION_DEGREE {
                let basis = challenge_extension_basis(extension_coordinate);
                quotient[extension_coordinate] = quotient_component_weight * basis;
                quotient[PROOF_CHALLENGE_EXTENSION_DEGREE + extension_coordinate] =
                    quotient_component_weight * quotient_chunk_power * basis;
                quotient[EXACT_QUOTIENT_COMPONENT_ROW_COUNT + extension_coordinate] =
                    opening_batch_mask_weight * basis;
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
    Ok(weights)
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

fn selector_equality_weights(
    selectors: [ChallengeField; EXACT_ROW_SELECTOR_VARIABLE_COUNT],
) -> [ChallengeField; LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW] {
    Poly::new_from_point(&selectors, ChallengeField::ONE)
        .as_slice()
        .try_into()
        .expect("the selected row selectors have the selected equality-weight count")
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
    selector_weights: [ChallengeField; LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW],
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
    selector_weights: [ChallengeField; LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW],
    catalog: &BTreeMap<(u16, u32, u32), ProofChallengeExtensionElement>,
    opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement;
         EXACT_OPENING_BATCH_MASK_CHUNK_COUNT],
) -> Result<ChallengeField, String> {
    if row_weights.len() != EXACT_QUOTIENT_PHASE_ROW_COUNT {
        return Err("exact quotient row weights have the wrong count".to_owned());
    }
    let mut expected = ChallengeField::ZERO;
    let quotient_component_weight = row_weights[0];
    for (component_ordinal, selector_weight) in selector_weights
        .iter()
        .take(EXACT_QUOTIENT_COMPONENT_COUNT)
        .enumerate()
    {
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
    let opening_batch_mask_weight = row_weights[EXACT_QUOTIENT_COMPONENT_ROW_COUNT];
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
            .prior_proof_bound_query_count
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
    aggregate_commitment: Option<AggregateWideCommitment>,
    aggregate_wide_pad_commitment: Option<AggregateWideCommitment>,
    query_indices: Vec<usize>,
    bound_query_indices: Option<ExactBoundQueryIndices>,
    bound_evaluation_domain: Option<ProofEvaluationDomain>,
    degree_test_points: Vec<Point<ChallengeField>>,
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
            &prepared_relation.verified_relation.variant,
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
            aggregate_wide_pad_commitment: None,
            query_indices: Vec::new(),
            bound_query_indices: None,
            bound_evaluation_domain: None,
            degree_test_points: Vec::new(),
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
        for point in self.degree_test_points.iter().chain(&self.whir_points) {
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
        let pcs = aggregate_wide_pcs_for_construction_plan(construction_plan)?;
        let mut challenger = aggregate_wide_challenger_from_transcript(
            &pcs,
            construction_plan,
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

    fn consume_aggregate_commitments(
        &mut self,
        aggregate_commitment: AggregateWideCommitment,
        aggregate_wide_pad_commitment: AggregateWideCommitment,
    ) -> Result<(), String> {
        if self.phase_roots.is_none()
            || self.aggregate_commitment.is_some()
            || self.aggregate_wide_pad_commitment.is_some()
        {
            return Err("exact aggregate commitments are out of order".to_owned());
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let challenger = self
            .challenger
            .as_mut()
            .ok_or_else(|| "exact aggregate commitments precede transcript material".to_owned())?;
        challenger.observe(aggregate_commitment.clone());
        challenger.observe(aggregate_wide_pad_commitment.clone());
        let degree_test_points = bound_degree_test_points(challenger)?;
        let query_indices = derive_query_indices(challenger, shape)?;
        let bound_query_indices = derive_bound_query_indices(challenger, shape)?;
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
        self.aggregate_wide_pad_commitment = Some(aggregate_wide_pad_commitment);
        self.query_indices = query_indices;
        self.bound_query_indices = Some(bound_query_indices);
        self.bound_evaluation_domain = Some(bound_evaluation_domain);
        self.degree_test_points = degree_test_points;
        self.whir_points = whir_points;
        self.expected_queries = expected_queries;
        self.expected_bound_reduction = expected_bound_reduction;
        Ok(())
    }

    fn consume_phase_column(
        &mut self,
        phase_index: usize,
        column_index: usize,
        persistent_salt: Option<PrivateLeafSalt>,
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
        if persistent_salt.is_some()
            != (shape.phase_leaf_salt_byte_length == PRIVATE_LEAF_SALT_BYTE_LENGTH)
        {
            return Err("exact authenticated phase column has the wrong salt shape".to_owned());
        }
        let digest = hash_opened_column_with_salt(
            &values,
            shape.encoded_column_count,
            persistent_salt.as_ref(),
        );
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
        verify_materialized_bound_frontier(
            entry,
            self.prepared_relation
                .verified_relation
                .row_code_whir_construction_plan
                .bound_trees
                .get(bound_tree_ordinal)
                .ok_or_else(|| "exact bound-tree plan is absent".to_owned())?
                .leaf_count,
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

    fn finish_aggregate_wide(
        mut self,
        proof: super::super::aggregate_wide_wire::CompactAggregateWideOpeningProof,
        _maximum_resident_decoded_payload_byte_length: usize,
    ) -> Result<ExactSameSecretFinalProofVerification, String> {
        if self.consumed_phase_count != 3
            || self.consumed_bound_tree_count != EXACT_BOUND_TREE_COUNT
        {
            return Err(
                "exact semantic verification reached the aggregate-wide opening before all authenticated sections"
                    .to_owned(),
            );
        }
        let shape = self.prepared_relation.verified_relation.proof_shape;
        let expected_out_of_domain = self
            .expected_out_of_domain
            .take()
            .ok_or_else(|| "exact out-of-domain accumulator is absent".to_owned())?;
        let expected_queries = core::mem::take(&mut self.expected_queries);
        let expected_bound_reduction = core::mem::take(&mut self.expected_bound_reduction);
        if expected_queries.len() != shape.outer_query_count
            || expected_bound_reduction.len() != shape.bound_reduction_evaluation_count()?
            || self.degree_test_points.len() != EXACT_BOUND_DEGREE_TEST_COUNT
        {
            return Err("exact aggregate-wide evaluation schedule has the wrong count".to_owned());
        }
        let expected_evaluation_count = 3_usize
            .checked_add(expected_queries.len())
            .and_then(|count| count.checked_add(expected_bound_reduction.len()))
            .and_then(|count| count.checked_add(EXACT_BOUND_DEGREE_TEST_COUNT))
            .ok_or_else(|| "exact aggregate-wide evaluation count overflowed".to_owned())?;
        let mut expected_evaluations = Vec::new();
        expected_evaluations
            .try_reserve_exact(expected_evaluation_count)
            .map_err(|_| "exact aggregate-wide expected-evaluation allocation failed".to_owned())?;
        expected_evaluations.extend(
            expected_out_of_domain
                .into_iter()
                .map(|evaluation| OpeningBatch::new(vec![evaluation], Vec::new())),
        );
        expected_evaluations.extend(
            expected_queries
                .into_iter()
                .map(|evaluations| OpeningBatch::new(evaluations.to_vec(), Vec::new())),
        );
        expected_evaluations.extend(
            expected_bound_reduction
                .into_iter()
                .map(|evaluation| OpeningBatch::new(vec![evaluation], Vec::new())),
        );
        expected_evaluations.extend(
            (0..EXACT_BOUND_DEGREE_TEST_COUNT)
                .map(|_| OpeningBatch::new(vec![ChallengeField::ZERO], Vec::new())),
        );
        if expected_evaluations.len() != self.whir_points.len() {
            return Err("exact aggregate-wide points and evaluations diverged".to_owned());
        }
        let construction_plan = &self
            .prepared_relation
            .verified_relation
            .row_code_whir_construction_plan;
        let requested_columns_by_point = construction_plan
            .opening_batches()
            .iter()
            .map(|batch| {
                batch
                    .requested_aggregate_column_ordinals
                    .iter()
                    .copied()
                    .map(|column| {
                        usize::try_from(column)
                            .map_err(|_| "exact aggregate column ordinal exceeds usize".to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        if requested_columns_by_point.len() != self.whir_points.len() {
            return Err("exact aggregate-wide opening catalog changed".to_owned());
        }
        let pcs = aggregate_wide_pcs_for_construction_plan(construction_plan)?;
        let configuration = super::super::hiding_whir::selected_hiding_whir_config(
            construction_plan.selected_parameters(),
        )
        .map_err(|error| format!("derive aggregate-wide configuration: {error:?}"))?;
        let source_commitment = self
            .aggregate_commitment
            .take()
            .ok_or_else(|| "exact aggregate source commitment is absent".to_owned())?;
        let pad_commitment = self
            .aggregate_wide_pad_commitment
            .take()
            .ok_or_else(|| "exact aggregate-wide pad commitment is absent".to_owned())?;
        let mut challenger = self
            .challenger
            .take()
            .ok_or_else(|| "exact aggregate-wide challenger is absent".to_owned())?;
        super::super::aggregate_wide_verifier::
            verify_compact_aggregate_wide_opening_after_observed_commitments(
                &pcs,
                &configuration,
                &proof,
                &source_commitment,
                &pad_commitment,
                shape.aggregate_table_width,
                &self.whir_points,
                &requested_columns_by_point,
                &expected_evaluations,
                &mut challenger,
            )?;
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
        let pcs = aggregate_wide_pcs_for_construction_plan(construction_plan)?;
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
        #[cfg(test)]
        if transcript_summary
            .observed_public_sampler_rows()
            .is_none_or(<[_]>::is_empty)
        {
            return Err("exact transcript public-sampler trace is empty".to_owned());
        }
        if transcript_summary.maximum_hash_query_count()
            != self.verifier_accounting.maximum_transcript_hash_query_count
            || transcript_summary.logical_verifier_message_count()
                != self.verifier_accounting.logical_verifier_message_count
        {
            return Err(
                "exact transcript execution diverges from the checked oracle-equation catalog"
                    .to_owned(),
            );
        }
        #[cfg(test)]
        if self.verifier_accounting.maximum_verifier_hash_query_count
            < self.verifier_accounting.maximum_transcript_hash_query_count
            || self
                .verifier_accounting
                .maximum_accepting_database_equation_count
                > self.verifier_accounting.maximum_verifier_hash_query_count
        {
            return Err(
                "exact verifier evidence diverges from the checked oracle-equation catalog"
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) enum ExactSameSecretProofEncodingProgress {
    Pending,
    Complete { canonical_byte_length: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) enum ExactSameSecretProofSinkEncodingError<SinkError>
{
    Sink(SinkError),
}

#[derive(Clone, Debug)]
struct ExactProofSectionCursor {
    sections: Vec<RowCodeWhirProofSectionPlan>,
    next_section_index: usize,
}

impl ExactProofSectionCursor {
    fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        opening_claim_count: usize,
        proof_privacy_mode: ProofPrivacyMode,
    ) -> Result<Self, String> {
        if construction_plan.proof_privacy_mode != proof_privacy_mode {
            return Err("exact proof privacy mode diverges from the construction".to_owned());
        }
        let mut cursor = Self {
            sections: construction_plan.proof_sections().to_vec(),
            next_section_index: 0,
        };
        for phase in &construction_plan.phase_order {
            cursor.consume(
                RowCodeWhirProofSectionRole::RelationCommitment { phase: *phase },
                1,
            )?;
        }
        cursor.consume(
            RowCodeWhirProofSectionRole::OutOfDomainEvaluations,
            opening_claim_count,
        )?;
        cursor.consume(
            RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations,
            construction_plan
                .opening_batch_mask_chunk_evaluation_count()
                .map_err(|_| "exact mask geometry is invalid".to_owned())?,
        )?;
        cursor.consume(RowCodeWhirProofSectionRole::AggregateCommitment, 1)?;
        cursor.consume(RowCodeWhirProofSectionRole::AggregateWidePadCommitment, 1)?;
        for phase in &construction_plan.phase_order {
            cursor.consume(
                RowCodeWhirProofSectionRole::PhaseOpenings { phase: *phase },
                construction_plan.outer_query_count(),
            )?;
        }
        for (bound_tree_index, bound_tree) in construction_plan.bound_trees.iter().enumerate() {
            cursor.consume(
                RowCodeWhirProofSectionRole::BoundTreeOpenings {
                    bound_tree_ordinal: u32::try_from(bound_tree_index)
                        .map_err(|_| "exact bound-tree ordinal exceeds u32".to_owned())?,
                },
                bound_tree.query_count,
            )?;
        }
        cursor.consume(RowCodeWhirProofSectionRole::AggregateWideOpening, 1)?;
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

/// Retry-safe canonical encoder for the production exact same-secret proof.
/// The bounded aggregate-wide encoder owns the terminal proof stream.
const EXACT_ENCODER_CHUNK_BYTE_LENGTH: usize = 4_096;

pub(in crate::bgv::proof_suite::row_code_whir) struct ExactSameSecretProofSinkEncoder {
    canonical_prefix: Vec<u8>,
    next_prefix_byte_offset: usize,
    aggregate_wide_encoder: super::super::aggregate_wide_wire::AggregateWideWireSinkEncoder,
    canonical_byte_length: usize,
}

impl ExactSameSecretProofSinkEncoder {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        relation_variant: &RelationPlanVariant,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        proof: ExactSameSecretProof,
    ) -> Result<Self, String> {
        validate_row_code_whir_proof_shape(
            construction_plan,
            relation_variant,
            bound_tree_entries,
            &proof,
        )?;
        ExactProofSectionCursor::new(
            construction_plan,
            relation_variant.ordered_opening_claims().len(),
            relation_variant.proof_privacy_mode(),
        )?;
        let configuration = super::super::hiding_whir::selected_hiding_whir_config(
            construction_plan.selected_parameters(),
        )
        .map_err(|error| format!("derive aggregate-wide configuration: {error:?}"))?;
        let (canonical_prefix, prior_private_leaf_salts) =
            encode_exact_same_secret_prefix(construction_plan, &proof)?;
        let aggregate_wide_encoder =
            super::super::aggregate_wide_wire::AggregateWideWireSinkEncoder::new(
                &configuration,
                &proof.aggregate_wide_opening_proof,
                &expected_opening_widths(construction_plan),
                construction_plan.aggregate_table_width(),
                prior_private_leaf_salts,
            )?;
        let canonical_byte_length = canonical_prefix
            .len()
            .checked_add(aggregate_wide_encoder.canonical_byte_length())
            .ok_or_else(|| "exact proof canonical byte length overflowed".to_owned())?;
        if canonical_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
            return Err(format!(
                "exact proof has {canonical_byte_length} bytes, exceeding the {MAXIMUM_COMMON_PROOF_BYTE_LENGTH}-byte common hard limit"
            ));
        }
        Ok(Self {
            canonical_prefix,
            next_prefix_byte_offset: 0,
            aggregate_wide_encoder,
            canonical_byte_length,
        })
    }

    pub(in crate::bgv::proof_suite::row_code_whir) const fn canonical_byte_length(&self) -> usize {
        self.canonical_byte_length
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
        if self.next_prefix_byte_offset < self.canonical_prefix.len() {
            let following_offset = self
                .next_prefix_byte_offset
                .saturating_add(EXACT_ENCODER_CHUNK_BYTE_LENGTH)
                .min(self.canonical_prefix.len());
            sink.write_bytes(
                &self.canonical_prefix[self.next_prefix_byte_offset..following_offset],
            )
            .map_err(ExactSameSecretProofSinkEncodingError::Sink)?;
            self.next_prefix_byte_offset = following_offset;
            return Ok(ExactSameSecretProofEncodingProgress::Pending);
        }
        match self.aggregate_wide_encoder.write_next(sink) {
            Ok(super::super::aggregate_wide_wire::AggregateWideWireEncodingProgress::Pending) => {
                Ok(ExactSameSecretProofEncodingProgress::Pending)
            }
            Ok(
                super::super::aggregate_wide_wire::AggregateWideWireEncodingProgress::Complete {
                    ..
                },
            ) => Ok(ExactSameSecretProofEncodingProgress::Complete {
                canonical_byte_length: self.canonical_byte_length,
            }),
            Err(super::super::aggregate_wide_wire::AggregateWideWireSinkEncodingError::Sink(
                error,
            )) => Err(ExactSameSecretProofSinkEncodingError::Sink(error)),
        }
    }
}

fn encode_exact_same_secret_prefix(
    construction_plan: &RowCodeWhirConstructionPlan,
    proof: &ExactSameSecretProof,
) -> Result<(Vec<u8>, AcceptedPrivateLeafSaltSet), String> {
    let mut canonical = Vec::new();
    let mut private_leaf_salts = AcceptedPrivateLeafSaltSet::default();
    canonical
        .try_reserve_exact(checked_exact_proof_prefix_byte_length(
            construction_plan,
            proof,
        )?)
        .map_err(|_| "exact proof prefix allocation failed".to_owned())?;
    canonical.extend_from_slice(EXACT_PROOF_WIRE_MAGIC);
    for phase in &construction_plan.phase_order {
        let root = proof.phase_roots[phase_index(*phase)]
            .ok_or_else(|| "scheduled proof phase has no commitment root".to_owned())?;
        canonical.extend_from_slice(&column_digest_bytes(root));
    }
    canonical.extend_from_slice(
        &checked_u32(
            proof.out_of_domain_evaluations.len(),
            "out-of-domain evaluation count",
        )?
        .to_le_bytes(),
    );
    for evaluation in &proof.out_of_domain_evaluations {
        canonical.extend_from_slice(&production_extension_bytes(*evaluation));
    }
    for evaluation in &proof.opening_batch_mask_chunk_evaluations {
        canonical.extend_from_slice(&production_extension_bytes(*evaluation));
    }
    let aggregate_root = proof
        .aggregate_commitment
        .roots()
        .first()
        .copied()
        .ok_or_else(|| "exact aggregate source commitment has no root".to_owned())?;
    let pad_root = proof
        .aggregate_wide_pad_commitment
        .roots()
        .first()
        .copied()
        .ok_or_else(|| "exact aggregate-wide pad commitment has no root".to_owned())?;
    canonical.extend_from_slice(&column_digest_bytes(aggregate_root));
    canonical.extend_from_slice(&column_digest_bytes(pad_root));
    for phase in &construction_plan.phase_order {
        let phase_index = phase_index(*phase);
        let columns = proof.authenticated_phase_columns[phase_index]
            .as_ref()
            .ok_or_else(|| "scheduled proof phase has no authenticated columns".to_owned())?;
        let frontier = proof.phase_frontiers[phase_index]
            .as_ref()
            .ok_or_else(|| "scheduled proof phase has no compact frontier".to_owned())?;
        for column in columns {
            if column.persistent_salt.is_some()
                != (construction_plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing)
            {
                return Err("scheduled proof phase has the wrong leaf-salt shape".to_owned());
            }
            if let Some(salt) = column.persistent_salt {
                append_accepted_private_leaf_salt(&mut canonical, &mut private_leaf_salts, salt)?;
            }
            for value in &column.values {
                canonical.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
            }
        }
        canonical
            .extend_from_slice(&checked_u32(frontier.len(), "phase frontier count")?.to_le_bytes());
        for node in frontier {
            canonical.extend_from_slice(&column_digest_bytes(*node));
        }
    }
    for authentication in &proof.bound_tree_authentications {
        for opening in &authentication.opened_leaves {
            if let Some(salt) = opening.persistent_salt {
                append_accepted_private_leaf_salt(&mut canonical, &mut private_leaf_salts, salt)?;
            }
            for value in opening
                .first_point_values
                .iter()
                .chain(&opening.opposite_point_values)
            {
                canonical.extend_from_slice(&value.canonical().to_le_bytes());
            }
        }
        canonical.extend_from_slice(
            &checked_u32(authentication.frontier.len(), "bound frontier count")?.to_le_bytes(),
        );
        for node in &authentication.frontier {
            canonical.extend_from_slice(node);
        }
    }
    Ok((canonical, private_leaf_salts))
}

fn append_accepted_private_leaf_salt(
    canonical: &mut Vec<u8>,
    accepted_salts: &mut AcceptedPrivateLeafSaltSet,
    salt: PrivateLeafSalt,
) -> Result<(), String> {
    accepted_salts.insert(salt)?;
    canonical.extend_from_slice(&salt);
    Ok(())
}

fn checked_exact_proof_prefix_byte_length(
    construction_plan: &RowCodeWhirConstructionPlan,
    proof: &ExactSameSecretProof,
) -> Result<usize, String> {
    let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| "exact extension byte length overflowed".to_owned())?;
    let extension_count = proof
        .out_of_domain_evaluations
        .len()
        .checked_add(proof.opening_batch_mask_chunk_evaluations.len())
        .ok_or_else(|| "exact extension count overflowed".to_owned())?;
    let mut byte_length = EXACT_PROOF_WIRE_MAGIC
        .len()
        .checked_add(
            construction_plan
                .phase_order
                .len()
                .checked_mul(64)
                .ok_or_else(|| "phase root byte length overflowed".to_owned())?,
        )
        .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
        .and_then(|length| {
            extension_count
                .checked_mul(extension_byte_length)
                .and_then(|bytes| length.checked_add(bytes))
        })
        .and_then(|length| length.checked_add(2 * 64))
        .ok_or_else(|| "exact proof fixed prefix length overflowed".to_owned())?;
    for phase in &construction_plan.phase_order {
        let phase_index = phase_index(*phase);
        let columns = proof.authenticated_phase_columns[phase_index]
            .as_ref()
            .ok_or_else(|| "scheduled proof phase has no authenticated columns".to_owned())?;
        let frontier = proof.phase_frontiers[phase_index]
            .as_ref()
            .ok_or_else(|| "scheduled proof phase has no compact frontier".to_owned())?;
        let value_count = columns.iter().try_fold(0_usize, |count, column| {
            count
                .checked_add(column.values.len())
                .ok_or_else(|| "exact phase value count overflowed".to_owned())
        })?;
        byte_length = byte_length
            .checked_add(
                columns
                    .len()
                    .checked_mul(
                        if construction_plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing {
                            PRIVATE_LEAF_SALT_BYTE_LENGTH
                        } else {
                            0
                        },
                    )
                    .ok_or_else(|| "exact phase salt byte length overflowed".to_owned())?,
            )
            .ok_or_else(|| "exact phase prefix length overflowed".to_owned())?
            .checked_add(
                value_count
                    .checked_mul(core::mem::size_of::<u64>())
                    .ok_or_else(|| "exact phase value byte length overflowed".to_owned())?,
            )
            .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
            .and_then(|length| {
                frontier
                    .len()
                    .checked_mul(64)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .ok_or_else(|| "exact phase prefix length overflowed".to_owned())?;
    }
    for authentication in &proof.bound_tree_authentications {
        for opening in &authentication.opened_leaves {
            let leaf_byte_length = opening
                .first_point_values
                .len()
                .checked_add(opening.opposite_point_values.len())
                .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
                .and_then(|length| {
                    length.checked_add(if opening.persistent_salt.is_some() {
                        COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                    } else {
                        0
                    })
                })
                .ok_or_else(|| "exact bound leaf byte length overflowed".to_owned())?;
            byte_length = byte_length
                .checked_add(leaf_byte_length)
                .ok_or_else(|| "exact bound prefix length overflowed".to_owned())?;
        }
        byte_length = byte_length
            .checked_add(core::mem::size_of::<u32>())
            .and_then(|length| {
                authentication
                    .frontier
                    .len()
                    .checked_mul(64)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .ok_or_else(|| "exact bound frontier byte length overflowed".to_owned())?;
    }
    Ok(byte_length)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExactProofHostileMutationTargetKind {
    Count,
    Field,
    Frontier,
    Header,
    Root,
    Salt,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExactProofHostileMutationTarget {
    pub(super) label: String,
    pub(super) byte_range: Range<usize>,
    pub(super) kind: ExactProofHostileMutationTargetKind,
}

#[cfg(test)]
struct ExactProofMutationScanner<'a> {
    canonical_proof: &'a [u8],
    offset: usize,
    targets: Vec<ExactProofHostileMutationTarget>,
}

#[cfg(test)]
impl<'a> ExactProofMutationScanner<'a> {
    fn new(canonical_proof: &'a [u8], header_byte_length: usize) -> Result<Self, String> {
        if header_byte_length == 0 || header_byte_length >= canonical_proof.len() {
            return Err("exact mutation scan has an invalid proof-object header length".to_owned());
        }
        Ok(Self {
            canonical_proof,
            offset: header_byte_length,
            targets: vec![ExactProofHostileMutationTarget {
                label: "proof-object header".to_owned(),
                byte_range: 0..header_byte_length,
                kind: ExactProofHostileMutationTargetKind::Header,
            }],
        })
    }

    fn take_bytes(&mut self, byte_length: usize, label: &str) -> Result<Range<usize>, String> {
        let following_offset = self
            .offset
            .checked_add(byte_length)
            .filter(|following_offset| *following_offset <= self.canonical_proof.len())
            .ok_or_else(|| format!("exact mutation scan truncated at {label}"))?;
        let byte_range = self.offset..following_offset;
        self.offset = following_offset;
        Ok(byte_range)
    }

    fn record_bytes(
        &mut self,
        byte_length: usize,
        label: impl Into<String>,
        kind: ExactProofHostileMutationTargetKind,
    ) -> Result<Range<usize>, String> {
        let label = label.into();
        let byte_range = self.take_bytes(byte_length, &label)?;
        if byte_range.is_empty() {
            return Err(format!("exact mutation target {label} is empty"));
        }
        self.targets.push(ExactProofHostileMutationTarget {
            label,
            byte_range: byte_range.clone(),
            kind,
        });
        Ok(byte_range)
    }

    fn read_count(&mut self, label: impl Into<String>) -> Result<usize, String> {
        let label = label.into();
        let byte_range = self.record_bytes(
            core::mem::size_of::<u32>(),
            label,
            ExactProofHostileMutationTargetKind::Count,
        )?;
        Ok(u32::from_le_bytes(
            self.canonical_proof[byte_range]
                .try_into()
                .map_err(|_| "exact mutation count has the wrong width".to_owned())?,
        ) as usize)
    }

    fn record_field_bytes(
        &mut self,
        byte_length: usize,
        label: impl Into<String>,
    ) -> Result<Range<usize>, String> {
        self.record_bytes(
            byte_length,
            label,
            ExactProofHostileMutationTargetKind::Field,
        )
    }

    fn finish(self) -> Result<Vec<ExactProofHostileMutationTarget>, String> {
        if self.offset != self.canonical_proof.len() {
            return Err(format!(
                "exact mutation scan left {} trailing proof bytes",
                self.canonical_proof.len() - self.offset
            ));
        }
        Ok(self.targets)
    }
}

#[cfg(test)]
fn exact_phase_label(phase: RowCodeWhirPhase) -> &'static str {
    match phase {
        RowCodeWhirPhase::Base => "base",
        RowCodeWhirPhase::Auxiliary => "auxiliary",
        RowCodeWhirPhase::Quotient => "quotient",
    }
}

/// Replays the production construction and the transported counts to locate
/// hostile-test mutations. No producer-supplied coordinate or width determines
/// the layout.
#[cfg(test)]
pub(super) fn exact_same_secret_hostile_mutation_targets(
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    verification_context: ExactSameSecretVerificationContext,
    canonical_proof: &[u8],
) -> Result<Vec<ExactProofHostileMutationTarget>, String> {
    let canonical_header = verification_context
        .canonical_proof_object_header_bytes
        .clone();
    if !canonical_proof.starts_with(&canonical_header) {
        return Err("exact mutation scan proof has the wrong canonical header".to_owned());
    }
    let prepared_relation = prepare_exact_same_secret_relation(prerequisite, verification_context)?;
    let construction_plan = &prepared_relation
        .verified_relation
        .row_code_whir_construction_plan;
    let shape = prepared_relation.verified_relation.proof_shape;
    let mut scanner = ExactProofMutationScanner::new(canonical_proof, canonical_header.len())?;

    let wire_magic = scanner.record_bytes(
        EXACT_PROOF_WIRE_MAGIC.len(),
        "exact family wire magic",
        ExactProofHostileMutationTargetKind::Header,
    )?;
    if canonical_proof[wire_magic] != *EXACT_PROOF_WIRE_MAGIC {
        return Err("exact mutation scan found the wrong family wire magic".to_owned());
    }
    for phase in &construction_plan.phase_order {
        scanner.record_bytes(
            64,
            format!("{} phase root", exact_phase_label(*phase)),
            ExactProofHostileMutationTargetKind::Root,
        )?;
    }

    let out_of_domain_count = scanner.read_count("out-of-domain evaluation count")?;
    if out_of_domain_count != shape.opening_claim_count {
        return Err("exact mutation scan found the wrong opening-claim count".to_owned());
    }
    let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| "exact mutation extension width overflowed".to_owned())?;
    for opening_ordinal in 0..out_of_domain_count {
        if opening_ordinal == 0 || opening_ordinal + 1 == out_of_domain_count {
            scanner.record_field_bytes(
                extension_byte_length,
                if opening_ordinal + 1 == out_of_domain_count {
                    "terminal relation evaluation".to_owned()
                } else {
                    format!("relation evaluation {opening_ordinal}")
                },
            )?;
        } else {
            scanner.take_bytes(extension_byte_length, "relation evaluation")?;
        }
    }
    for mask_chunk_ordinal in 0..EXACT_OPENING_BATCH_MASK_CHUNK_COUNT {
        if mask_chunk_ordinal == 0 || mask_chunk_ordinal + 1 == EXACT_OPENING_BATCH_MASK_CHUNK_COUNT
        {
            scanner.record_field_bytes(
                extension_byte_length,
                format!("opening-batch mask evaluation {mask_chunk_ordinal}"),
            )?;
        } else {
            scanner.take_bytes(extension_byte_length, "opening-batch mask evaluation")?;
        }
    }
    scanner.record_bytes(
        64,
        "aggregate source root",
        ExactProofHostileMutationTargetKind::Root,
    )?;
    scanner.record_bytes(
        64,
        "aggregate-wide pad root",
        ExactProofHostileMutationTargetKind::Root,
    )?;

    for phase in &construction_plan.phase_order {
        let phase_label = exact_phase_label(*phase);
        let row_count = match phase {
            RowCodeWhirPhase::Base => shape.base_row_count,
            RowCodeWhirPhase::Auxiliary => shape.auxiliary_row_count,
            RowCodeWhirPhase::Quotient => shape.quotient_row_count,
        };
        let per_column_byte_length = row_count
            .checked_mul(core::mem::size_of::<u64>())
            .and_then(|length| length.checked_add(shape.phase_leaf_salt_byte_length))
            .ok_or_else(|| format!("exact {phase_label} opening length overflowed"))?;
        let opening_byte_length = shape
            .outer_query_count
            .checked_mul(per_column_byte_length)
            .ok_or_else(|| format!("exact {phase_label} opening length overflowed"))?;
        scanner.record_field_bytes(
            opening_byte_length,
            format!("{phase_label} phase opening values"),
        )?;
        let frontier_count = scanner.read_count(format!("{phase_label} phase frontier count"))?;
        if frontier_count == 0 || frontier_count > shape.maximum_frontier_count()? {
            return Err(format!(
                "exact {phase_label} mutation frontier has the wrong count"
            ));
        }
        scanner.record_bytes(
            frontier_count
                .checked_mul(64)
                .ok_or_else(|| format!("exact {phase_label} frontier length overflowed"))?,
            format!("{phase_label} phase compact frontier"),
            ExactProofHostileMutationTargetKind::Frontier,
        )?;
    }

    for (bound_tree_ordinal, entry) in prepared_relation.bound_tree_entries.iter().enumerate() {
        let query_count = shape.bound_tree_query_count(bound_tree_ordinal)?;
        let row_width = entry
            .materialized_row_width()
            .map_err(|error| format!("derive exact bound row width: {error:?}"))?;
        let salt_byte_length = if entry.requires_persistent_leaf_salt() {
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
        } else {
            0
        };
        let leaf_byte_length = row_width
            .checked_mul(2)
            .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
            .and_then(|length| length.checked_add(salt_byte_length))
            .ok_or_else(|| "exact bound mutation leaf length overflowed".to_owned())?;
        scanner.record_field_bytes(
            query_count
                .checked_mul(leaf_byte_length)
                .ok_or_else(|| "exact bound mutation opening length overflowed".to_owned())?,
            format!("bound tree {bound_tree_ordinal} opening values"),
        )?;
        let frontier_count =
            scanner.read_count(format!("bound tree {bound_tree_ordinal} frontier count"))?;
        if frontier_count == 0
            || frontier_count > ExactProofShape::maximum_bound_frontier_count(query_count)?
        {
            return Err(format!(
                "exact bound tree {bound_tree_ordinal} mutation frontier has the wrong count"
            ));
        }
        scanner.record_bytes(
            frontier_count
                .checked_mul(64)
                .ok_or_else(|| "exact bound mutation frontier length overflowed".to_owned())?,
            format!("bound tree {bound_tree_ordinal} compact frontier"),
            ExactProofHostileMutationTargetKind::Frontier,
        )?;
    }

    let aggregate_wide_start = scanner.offset;
    let configuration = super::super::hiding_whir::selected_hiding_whir_config(
        construction_plan.selected_parameters(),
    )
    .map_err(|error| format!("derive aggregate-wide mutation configuration: {error:?}"))?;
    let aggregate_wide_targets =
        super::super::aggregate_wide_wire::aggregate_wide_hostile_mutation_targets(
            &configuration,
            &canonical_proof[aggregate_wide_start..],
            &expected_opening_widths(construction_plan),
            shape.aggregate_table_width,
        )?;
    for target in aggregate_wide_targets {
        let kind = match target.kind {
            super::super::aggregate_wide_wire::AggregateWideHostileMutationTargetKind::Count => {
                ExactProofHostileMutationTargetKind::Count
            }
            super::super::aggregate_wide_wire::AggregateWideHostileMutationTargetKind::Field => {
                ExactProofHostileMutationTargetKind::Field
            }
            super::super::aggregate_wide_wire::AggregateWideHostileMutationTargetKind::Frontier => {
                ExactProofHostileMutationTargetKind::Frontier
            }
            super::super::aggregate_wide_wire::AggregateWideHostileMutationTargetKind::Root => {
                ExactProofHostileMutationTargetKind::Root
            }
            super::super::aggregate_wide_wire::AggregateWideHostileMutationTargetKind::Salt => {
                ExactProofHostileMutationTargetKind::Salt
            }
        };
        scanner.targets.push(ExactProofHostileMutationTarget {
            label: target.label,
            byte_range: aggregate_wide_start + target.byte_range.start
                ..aggregate_wide_start + target.byte_range.end,
            kind,
        });
    }
    scanner.offset = canonical_proof.len();
    scanner.finish()
}

/// Exact worst-case family-body length for the construction-driven encoder.
///
/// The ceiling follows the same section order and widths as
/// `encode_exact_same_secret_prefix`. Every Merkle contribution uses the
/// maximum coordinate-derived compact frontier for the checked query count;
/// the aggregate-wide suffix comes from the selected masking wire ledger.
pub(in crate::bgv::proof_suite) fn canonical_row_code_whir_family_body_byte_length_ceiling(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    bound_tree_entries: &[ProofTreeCatalogEntry],
) -> Result<usize, String> {
    if relation_variant.proof_privacy_mode() != construction_plan.proof_privacy_mode
        || bound_tree_entries.len() != construction_plan.bound_trees.len()
    {
        return Err("row-code WHIR accounting inputs diverge from the construction".to_owned());
    }

    let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| "row-code WHIR extension byte length overflowed".to_owned())?;
    let opening_batch_mask_evaluation_count = construction_plan
        .opening_batch_mask_chunk_evaluation_count()
        .map_err(|_| "row-code WHIR mask geometry is invalid".to_owned())?;
    let extension_count = relation_variant
        .ordered_opening_claims()
        .len()
        .checked_add(opening_batch_mask_evaluation_count)
        .ok_or_else(|| "row-code WHIR extension count overflowed".to_owned())?;
    let mut family_body_byte_length = EXACT_PROOF_WIRE_MAGIC
        .len()
        .checked_add(
            construction_plan
                .phase_order
                .len()
                .checked_mul(64)
                .ok_or_else(|| "row-code WHIR phase-root byte length overflowed".to_owned())?,
        )
        .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
        .and_then(|length| {
            extension_count
                .checked_mul(extension_byte_length)
                .and_then(|bytes| length.checked_add(bytes))
        })
        .and_then(|length| length.checked_add(2 * 64))
        .ok_or_else(|| "row-code WHIR fixed prefix length overflowed".to_owned())?;

    for phase in &construction_plan.phase_order {
        let (row_count, encoded_column_count) = match phase {
            RowCodeWhirPhase::Base => construction_plan
                .base_phase
                .as_ref()
                .map(|plan| (plan.rows.len(), plan.geometry.encoded_column_count)),
            RowCodeWhirPhase::Auxiliary => construction_plan
                .auxiliary_phase
                .as_ref()
                .map(|plan| (plan.rows.len(), plan.geometry.encoded_column_count)),
            RowCodeWhirPhase::Quotient => Some((
                construction_plan.quotient_phase.rows.len(),
                construction_plan
                    .quotient_phase
                    .geometry
                    .encoded_column_count,
            )),
        }
        .ok_or_else(|| "scheduled row-code WHIR phase has no geometry".to_owned())?;
        let value_byte_length = construction_plan
            .outer_query_count()
            .checked_mul(row_count)
            .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
            .ok_or_else(|| "row-code WHIR phase opening byte length overflowed".to_owned())?;
        let salt_byte_length = construction_plan
            .outer_query_count()
            .checked_mul(
                if construction_plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing {
                    PRIVATE_LEAF_SALT_BYTE_LENGTH
                } else {
                    0
                },
            )
            .ok_or_else(|| "row-code WHIR phase salt byte length overflowed".to_owned())?;
        let frontier_node_count =
            crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
                encoded_column_count,
                construction_plan.outer_query_count(),
            )
            .map_err(|error| format!("derive row-code WHIR phase frontier ceiling: {error:?}"))?;
        family_body_byte_length = family_body_byte_length
            .checked_add(value_byte_length)
            .and_then(|length| length.checked_add(salt_byte_length))
            .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
            .and_then(|length| {
                frontier_node_count
                    .checked_mul(64)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .ok_or_else(|| "row-code WHIR phase prefix length overflowed".to_owned())?;
    }

    for (entry, planned_tree) in bound_tree_entries
        .iter()
        .zip(&construction_plan.bound_trees)
    {
        if u32::from(entry.tree_catalog_index()) != planned_tree.relation_tree_ordinal
            || entry.bound_root().is_none()
        {
            return Err("row-code WHIR bound tree diverges from the catalog".to_owned());
        }
        let row_width = entry
            .materialized_row_width()
            .map_err(|error| format!("derive row-code WHIR bound row width: {error:?}"))?;
        if row_width == 0 || row_width != planned_tree.ordered_columns.len() {
            return Err("row-code WHIR bound tree has the wrong row width".to_owned());
        }
        let opened_leaf_byte_length = row_width
            .checked_mul(2)
            .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
            .and_then(|length| {
                length.checked_add(if entry.requires_persistent_leaf_salt() {
                    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                } else {
                    0
                })
            })
            .ok_or_else(|| "row-code WHIR bound leaf byte length overflowed".to_owned())?;
        let frontier_node_count =
            crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
                planned_tree.leaf_count,
                planned_tree.query_count,
            )
            .map_err(|error| format!("derive row-code WHIR bound frontier ceiling: {error:?}"))?;
        family_body_byte_length = family_body_byte_length
            .checked_add(
                planned_tree
                    .query_count
                    .checked_mul(opened_leaf_byte_length)
                    .ok_or_else(|| {
                        "row-code WHIR bound opening byte length overflowed".to_owned()
                    })?,
            )
            .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
            .and_then(|length| {
                frontier_node_count
                    .checked_mul(64)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .ok_or_else(|| "row-code WHIR bound prefix length overflowed".to_owned())?;
    }

    let aggregate_opening_byte_length =
        canonical_row_code_whir_aggregate_opening_section_byte_ledger(construction_plan)?
            .iter()
            .try_fold(0_usize, |total, (_, byte_length)| {
                total
                    .checked_add(*byte_length)
                    .ok_or_else(|| "aggregate opening byte length overflowed".to_owned())
            })?;
    family_body_byte_length
        .checked_add(aggregate_opening_byte_length)
        .ok_or_else(|| "row-code WHIR complete family-body length overflowed".to_owned())
}

pub(in crate::bgv::proof_suite) fn canonical_row_code_whir_aggregate_opening_section_byte_ledger(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<Vec<(&'static str, usize)>, String> {
    let opening_evaluation_count =
        construction_plan
            .opening_batches()
            .iter()
            .try_fold(0_usize, |count, batch| {
                count
                    .checked_add(batch.requested_aggregate_column_ordinals.len())
                    .ok_or_else(|| "aggregate opening evaluation count overflowed".to_owned())
            })?;
    let configuration = super::super::hiding_whir::selected_hiding_whir_config(
        construction_plan.selected_parameters(),
    )
    .map_err(|error| format!("derive selected aggregate-wide configuration: {error:?}"))?;
    Ok(
        super::super::hiding_whir::static_accounting::aggregate_wide_pad_opening_byte_ledger(
            &configuration,
            opening_evaluation_count,
        )?
        .sections
        .into_iter()
        .map(|(section, byte_length)| (section.identifier(), byte_length))
        .collect(),
    )
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactSameSecretDecoderPhase {
    TranscriptMaterial,
    PhaseColumns {
        phase_index: usize,
        next_column_index: usize,
    },
    PhaseFrontierCount {
        phase_index: usize,
    },
    PhaseFrontier {
        phase_index: usize,
        frontier_count: usize,
    },
    BoundLeaves {
        tree_index: usize,
        next_query_index: usize,
    },
    BoundFrontierCount {
        tree_index: usize,
    },
    BoundFrontier {
        tree_index: usize,
        frontier_count: usize,
    },
    AggregateWide,
    Complete,
}

struct ExactSameSecretIncrementalDecoder {
    construction_plan: RowCodeWhirConstructionPlan,
    shape: ExactProofShape,
    opening_widths: Vec<usize>,
    bound_tree_requires_persistent_salt: Vec<bool>,
    bound_tree_row_widths: Vec<usize>,
    declared_proof_byte_length: usize,
    offset: usize,
    phase: ExactSameSecretDecoderPhase,
    maximum_resident_section_byte_length: usize,
    private_leaf_salts: AcceptedPrivateLeafSaltSet,
    semantic_verifier: Option<ExactSameSecretIncrementalSemanticVerifier>,
    final_semantic_verification: Option<ExactSameSecretFinalProofVerification>,
    complete: bool,
}

impl ExactSameSecretIncrementalDecoder {
    fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        shape: ExactProofShape,
        bound_tree_entries: &[ProofTreeCatalogEntry],
        _pcs: super::super::aggregate_wide_pcs::AggregateWidePcs,
        opening_widths: Vec<usize>,
        declared_proof_byte_length: usize,
    ) -> Result<Self, String> {
        validate_exact_declared_proof_byte_length(declared_proof_byte_length)?;
        if bound_tree_entries.len() != EXACT_BOUND_TREE_COUNT
            || opening_widths.is_empty()
            || opening_widths.contains(&0)
            || bound_tree_entries.iter().any(|entry| {
                entry
                    .materialized_row_width()
                    .ok()
                    .is_none_or(|width| width == 0)
            })
        {
            return Err("exact decoder geometry has the wrong fixed shape".to_owned());
        }
        ExactProofSectionCursor::new(
            construction_plan,
            shape.opening_claim_count,
            ProofPrivacyMode::SecretBearing,
        )?;
        Ok(Self {
            construction_plan: construction_plan.clone(),
            shape,
            opening_widths,
            bound_tree_requires_persistent_salt: bound_tree_entries
                .iter()
                .map(ProofTreeCatalogEntry::requires_persistent_leaf_salt)
                .collect(),
            bound_tree_row_widths: bound_tree_entries
                .iter()
                .map(|entry| {
                    entry
                        .materialized_row_width()
                        .expect("the decoder validated every bound-tree row width")
                })
                .collect(),
            declared_proof_byte_length,
            offset: 0,
            phase: ExactSameSecretDecoderPhase::TranscriptMaterial,
            maximum_resident_section_byte_length: 0,
            private_leaf_salts: AcceptedPrivateLeafSaltSet::default(),
            semantic_verifier: None,
            final_semantic_verification: None,
            complete: false,
        })
    }

    fn install_semantic_verifier(
        &mut self,
        semantic_verifier: ExactSameSecretIncrementalSemanticVerifier,
    ) -> Result<(), String> {
        if self.offset != 0 || self.complete || self.semantic_verifier.is_some() {
            return Err("exact semantic verifier must be installed before decoding".to_owned());
        }
        self.semantic_verifier = Some(semantic_verifier);
        Ok(())
    }

    const fn is_complete(&self) -> bool {
        self.complete
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
        if self.complete {
            return Ok(());
        }
        loop {
            let progressed = match self.phase {
                ExactSameSecretDecoderPhase::TranscriptMaterial => {
                    self.consume_transcript_material(source, available_end_offset)?
                }
                ExactSameSecretDecoderPhase::PhaseColumns {
                    phase_index,
                    next_column_index,
                } => self.consume_phase_column(
                    source,
                    available_end_offset,
                    phase_index,
                    next_column_index,
                )?,
                ExactSameSecretDecoderPhase::PhaseFrontierCount { phase_index } => {
                    self.consume_phase_frontier_count(source, available_end_offset, phase_index)?
                }
                ExactSameSecretDecoderPhase::PhaseFrontier {
                    phase_index,
                    frontier_count,
                } => self.consume_phase_frontier(
                    source,
                    available_end_offset,
                    phase_index,
                    frontier_count,
                )?,
                ExactSameSecretDecoderPhase::BoundLeaves {
                    tree_index,
                    next_query_index,
                } => self.consume_bound_leaf(
                    source,
                    available_end_offset,
                    tree_index,
                    next_query_index,
                )?,
                ExactSameSecretDecoderPhase::BoundFrontierCount { tree_index } => {
                    self.consume_bound_frontier_count(source, available_end_offset, tree_index)?
                }
                ExactSameSecretDecoderPhase::BoundFrontier {
                    tree_index,
                    frontier_count,
                } => self.consume_bound_frontier(
                    source,
                    available_end_offset,
                    tree_index,
                    frontier_count,
                )?,
                ExactSameSecretDecoderPhase::AggregateWide => {
                    self.consume_aggregate_wide(source, available_end_offset)?
                }
                ExactSameSecretDecoderPhase::Complete => {
                    self.complete = true;
                    false
                }
            };
            if !progressed {
                break;
            }
        }
        if available_end_offset == self.declared_proof_byte_length
            && !matches!(self.phase, ExactSameSecretDecoderPhase::Complete)
        {
            return Err("exact proof ended before its canonical terminal shape".to_owned());
        }
        self.complete = matches!(self.phase, ExactSameSecretDecoderPhase::Complete);
        Ok(())
    }

    fn consume_transcript_material<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<bool, String> {
        let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| "exact transcript extension width overflowed".to_owned())?;
        let extension_count = self
            .shape
            .opening_claim_count
            .checked_add(EXACT_OPENING_BATCH_MASK_CHUNK_COUNT)
            .ok_or_else(|| "exact transcript extension count overflowed".to_owned())?;
        let section_byte_length = EXACT_PROOF_WIRE_MAGIC
            .len()
            .checked_add(3 * 64)
            .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
            .and_then(|length| {
                extension_count
                    .checked_mul(extension_byte_length)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .and_then(|length| length.checked_add(2 * 64))
            .ok_or_else(|| "exact transcript section length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "transcript material",
        )?
        else {
            return Ok(false);
        };
        let mut reader = ExactCanonicalReader::new(&canonical);
        if reader.read_array::<8>()? != *EXACT_PROOF_WIRE_MAGIC {
            return Err("exact same-secret proof has the wrong wire magic".to_owned());
        }
        let base_root = reader.read_digest()?;
        let auxiliary_root = reader.read_digest()?;
        let quotient_root = reader.read_digest()?;
        let out_of_domain_count = reader.read_u32()? as usize;
        if out_of_domain_count != self.shape.opening_claim_count {
            return Err(format!(
                "exact proof has {out_of_domain_count} out-of-domain evaluations, expected {}",
                self.shape.opening_claim_count
            ));
        }
        let out_of_domain_evaluations = (0..out_of_domain_count)
            .map(|_| reader.read_production_extension())
            .collect::<Result<Vec<_>, _>>()?;
        let mut opening_batch_mask_chunk_evaluations =
            [ProofChallengeExtensionElement::ZERO; EXACT_OPENING_BATCH_MASK_CHUNK_COUNT];
        for evaluation in &mut opening_batch_mask_chunk_evaluations {
            *evaluation = reader.read_production_extension()?;
        }
        let aggregate_commitment = MerkleCap::new(vec![reader.read_digest()?]);
        let pad_commitment = MerkleCap::new(vec![reader.read_digest()?]);
        if !reader.remaining().is_empty() {
            return Err("exact transcript section has trailing bytes".to_owned());
        }
        let semantic_verifier = self
            .semantic_verifier
            .as_mut()
            .ok_or_else(|| "exact production decoding requires its semantic verifier".to_owned())?;
        semantic_verifier.consume_transcript_material(
            base_root,
            auxiliary_root,
            quotient_root,
            out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations,
        )?;
        semantic_verifier.consume_aggregate_commitments(aggregate_commitment, pad_commitment)?;
        self.phase = ExactSameSecretDecoderPhase::PhaseColumns {
            phase_index: 0,
            next_column_index: 0,
        };
        Ok(true)
    }

    fn consume_phase_column<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        phase_index: usize,
        next_column_index: usize,
    ) -> Result<bool, String> {
        if next_column_index == self.shape.outer_query_count {
            self.phase = ExactSameSecretDecoderPhase::PhaseFrontierCount { phase_index };
            return Ok(true);
        }
        let row_count = *self
            .shape
            .phase_row_counts()
            .get(phase_index)
            .ok_or_else(|| "exact phase index is outside the fixed shape".to_owned())?;
        let value_byte_length = row_count
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| "exact phase column length overflowed".to_owned())?;
        let section_byte_length = value_byte_length
            .checked_add(self.shape.phase_leaf_salt_byte_length)
            .ok_or_else(|| "exact phase column length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "phase column",
        )?
        else {
            return Ok(false);
        };
        let mut reader = ExactCanonicalReader::new(&canonical);
        let persistent_salt = if self.shape.phase_leaf_salt_byte_length == 0 {
            None
        } else if self.shape.phase_leaf_salt_byte_length == PRIVATE_LEAF_SALT_BYTE_LENGTH {
            Some(read_accepted_private_leaf_salt(
                &mut reader,
                &mut self.private_leaf_salts,
            )?)
        } else {
            return Err("exact phase leaf-salt length is invalid".to_owned());
        };
        let values = (0..row_count)
            .map(|_| reader.read_goldilocks())
            .collect::<Result<Vec<_>, _>>()?;
        if !reader.remaining().is_empty() {
            return Err("exact phase column has trailing bytes".to_owned());
        }
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "exact semantic verifier is absent".to_owned())?
            .consume_phase_column(phase_index, next_column_index, persistent_salt, values)?;
        self.phase = ExactSameSecretDecoderPhase::PhaseColumns {
            phase_index,
            next_column_index: next_column_index + 1,
        };
        Ok(true)
    }

    fn consume_phase_frontier_count<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        phase_index: usize,
    ) -> Result<bool, String> {
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            core::mem::size_of::<u32>(),
            "phase frontier count",
        )?
        else {
            return Ok(false);
        };
        let frontier_count = u32::from_le_bytes(
            canonical
                .as_slice()
                .try_into()
                .map_err(|_| "exact phase frontier count has the wrong width".to_owned())?,
        ) as usize;
        if frontier_count > self.shape.maximum_frontier_count()? {
            return Err("exact phase frontier exceeds its fixed maximum".to_owned());
        }
        self.phase = ExactSameSecretDecoderPhase::PhaseFrontier {
            phase_index,
            frontier_count,
        };
        Ok(true)
    }

    fn consume_phase_frontier<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        phase_index: usize,
        frontier_count: usize,
    ) -> Result<bool, String> {
        let section_byte_length = frontier_count
            .checked_mul(64)
            .ok_or_else(|| "exact phase frontier length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "phase frontier",
        )?
        else {
            return Ok(false);
        };
        let mut reader = ExactCanonicalReader::new(&canonical);
        let frontier = (0..frontier_count)
            .map(|_| reader.read_digest())
            .collect::<Result<Vec<_>, _>>()?;
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "exact semantic verifier is absent".to_owned())?
            .consume_phase_frontier(phase_index, frontier)?;
        if phase_index + 1 < self.shape.phase_row_counts().len() {
            self.phase = ExactSameSecretDecoderPhase::PhaseColumns {
                phase_index: phase_index + 1,
                next_column_index: 0,
            };
        } else {
            self.phase = ExactSameSecretDecoderPhase::BoundLeaves {
                tree_index: 0,
                next_query_index: 0,
            };
        }
        Ok(true)
    }

    fn consume_bound_leaf<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        tree_index: usize,
        next_query_index: usize,
    ) -> Result<bool, String> {
        let query_count = self.shape.bound_tree_query_count(tree_index)?;
        if next_query_index == query_count {
            self.phase = ExactSameSecretDecoderPhase::BoundFrontierCount { tree_index };
            return Ok(true);
        }
        let salt_byte_length = if self.bound_tree_requires_persistent_salt[tree_index] {
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
        } else {
            0
        };
        let row_width = self
            .bound_tree_row_widths
            .get(tree_index)
            .copied()
            .ok_or_else(|| "exact bound-tree row width is absent".to_owned())?;
        let section_byte_length = 2_usize
            .checked_mul(row_width)
            .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
            .and_then(|length| length.checked_add(salt_byte_length))
            .ok_or_else(|| "exact bound leaf length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "bound leaf",
        )?
        else {
            return Ok(false);
        };
        let mut reader = ExactCanonicalReader::new(&canonical);
        let persistent_salt = if salt_byte_length == 0 {
            None
        } else {
            Some(read_accepted_private_leaf_salt(
                &mut reader,
                &mut self.private_leaf_salts,
            )?)
        };
        let mut first_point_values = vec![ProofBaseFieldElement::ZERO; row_width];
        let mut opposite_point_values = vec![ProofBaseFieldElement::ZERO; row_width];
        for value in &mut first_point_values {
            *value = reader.read_base_field()?;
        }
        for value in &mut opposite_point_values {
            *value = reader.read_base_field()?;
        }
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "exact semantic verifier is absent".to_owned())?
            .consume_bound_leaf(
                tree_index,
                next_query_index,
                ExactBoundLeafOpening {
                    persistent_salt,
                    first_point_values,
                    opposite_point_values,
                },
            )?;
        self.phase = ExactSameSecretDecoderPhase::BoundLeaves {
            tree_index,
            next_query_index: next_query_index + 1,
        };
        Ok(true)
    }

    fn consume_bound_frontier_count<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        tree_index: usize,
    ) -> Result<bool, String> {
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            core::mem::size_of::<u32>(),
            "bound frontier count",
        )?
        else {
            return Ok(false);
        };
        let frontier_count = u32::from_le_bytes(
            canonical
                .as_slice()
                .try_into()
                .map_err(|_| "exact bound frontier count has the wrong width".to_owned())?,
        ) as usize;
        let maximum_frontier_count = ExactProofShape::maximum_bound_frontier_count(
            self.shape.bound_tree_query_count(tree_index)?,
        )?;
        if frontier_count > maximum_frontier_count {
            return Err("exact bound frontier exceeds its fixed maximum".to_owned());
        }
        self.phase = ExactSameSecretDecoderPhase::BoundFrontier {
            tree_index,
            frontier_count,
        };
        Ok(true)
    }

    fn consume_bound_frontier<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        tree_index: usize,
        frontier_count: usize,
    ) -> Result<bool, String> {
        let section_byte_length = frontier_count
            .checked_mul(64)
            .ok_or_else(|| "exact bound frontier length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "bound frontier",
        )?
        else {
            return Ok(false);
        };
        let mut reader = ExactCanonicalReader::new(&canonical);
        let frontier = (0..frontier_count)
            .map(|_| reader.read_array())
            .collect::<Result<Vec<_>, _>>()?;
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "exact semantic verifier is absent".to_owned())?
            .consume_bound_frontier(tree_index, frontier)?;
        if tree_index + 1 < EXACT_BOUND_TREE_COUNT {
            self.phase = ExactSameSecretDecoderPhase::BoundLeaves {
                tree_index: tree_index + 1,
                next_query_index: 0,
            };
        } else {
            self.phase = ExactSameSecretDecoderPhase::AggregateWide;
        }
        Ok(true)
    }

    fn consume_aggregate_wide<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<bool, String> {
        let section_byte_length = self
            .declared_proof_byte_length
            .checked_sub(self.offset)
            .ok_or_else(|| "exact aggregate-wide section offset overflowed".to_owned())?;
        if section_byte_length == 0 {
            return Err("exact proof omitted its aggregate-wide opening".to_owned());
        }
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "aggregate-wide opening",
        )?
        else {
            return Ok(false);
        };
        let configuration = super::super::hiding_whir::selected_hiding_whir_config(
            self.construction_plan.selected_parameters(),
        )
        .map_err(|error| format!("derive aggregate-wide configuration: {error:?}"))?;
        let compact_proof = super::super::aggregate_wide_wire::decode_compact_aggregate_wide_opening_with_prior_private_leaf_salts(
                &configuration,
                &canonical,
                &self.opening_widths,
                self.shape.aggregate_table_width,
                core::mem::take(&mut self.private_leaf_salts),
            )?;
        let semantic_verifier = self
            .semantic_verifier
            .take()
            .ok_or_else(|| "exact semantic verifier disappeared before completion".to_owned())?;
        let maximum_resident_decoded_payload_byte_length =
            self.maximum_resident_section_byte_length.max(
                canonical
                    .len()
                    .saturating_add(compact_proof.resident_byte_length())
                    .saturating_add(semantic_verifier.resident_accumulator_payload_byte_length()),
            );
        self.final_semantic_verification =
            Some(semantic_verifier.finish_aggregate_wide(
                compact_proof,
                maximum_resident_decoded_payload_byte_length,
            )?);
        self.phase = ExactSameSecretDecoderPhase::Complete;
        Ok(true)
    }

    fn copy_available_section<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        section_byte_length: usize,
        section_label: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let section_end_offset = self
            .offset
            .checked_add(section_byte_length)
            .filter(|end_offset| *end_offset <= self.declared_proof_byte_length)
            .ok_or_else(|| format!("exact {section_label} exceeds the declared proof length"))?;
        if section_end_offset > available_end_offset {
            return Ok(None);
        }
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(section_byte_length)
            .map_err(|_| format!("exact {section_label} allocation failed"))?;
        canonical.resize(section_byte_length, 0);
        if !source.copy_bytes(self.offset, &mut canonical) {
            return Err(format!(
                "exact proof source did not expose the authenticated {section_label} range"
            ));
        }
        self.offset = section_end_offset;
        self.maximum_resident_section_byte_length = self
            .maximum_resident_section_byte_length
            .max(section_byte_length);
        Ok(Some(canonical))
    }

    fn finish_semantic(mut self) -> Result<ExactSameSecretFinalProofVerification, String> {
        if !self.complete || self.offset != self.declared_proof_byte_length {
            return Err("exact proof ended before its canonical terminal shape".to_owned());
        }
        if self.semantic_verifier.is_some() {
            return Err("exact semantic verifier retained unfinished state".to_owned());
        }
        self.final_semantic_verification
            .take()
            .ok_or_else(|| "exact semantic verification result is absent".to_owned())
    }
}

fn read_accepted_private_leaf_salt(
    reader: &mut ExactCanonicalReader<'_>,
    accepted_salts: &mut AcceptedPrivateLeafSaltSet,
) -> Result<PrivateLeafSalt, String> {
    let salt = reader.read_array::<PRIVATE_LEAF_SALT_BYTE_LENGTH>()?;
    accepted_salts.insert(salt)?;
    Ok(salt)
}

struct ExactCanonicalReader<'a> {
    canonical: &'a [u8],
    offset: usize,
}

impl<'a> ExactCanonicalReader<'a> {
    const fn new(canonical: &'a [u8]) -> Self {
        Self {
            canonical,
            offset: 0,
        }
    }

    fn read_array<const BYTE_COUNT: usize>(&mut self) -> Result<[u8; BYTE_COUNT], String> {
        let following_offset = self
            .offset
            .checked_add(BYTE_COUNT)
            .filter(|offset| *offset <= self.canonical.len())
            .ok_or_else(|| "exact wire is truncated".to_owned())?;
        let bytes = self.canonical[self.offset..following_offset]
            .try_into()
            .map_err(|_| "exact wire primitive has the wrong length".to_owned())?;
        self.offset = following_offset;
        Ok(bytes)
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_digest(&mut self) -> Result<ColumnDigest, String> {
        let mut digest = [0_u64; 8];
        for word in &mut digest {
            *word = self.read_u64()?;
        }
        Ok(digest)
    }

    fn read_goldilocks(&mut self) -> Result<Goldilocks, String> {
        let canonical = self.read_u64()?;
        if canonical >= GOLDILOCKS_MODULUS {
            return Err("exact proof contains a non-canonical Goldilocks value".to_owned());
        }
        Ok(Goldilocks::new(canonical))
    }

    fn read_base_field(&mut self) -> Result<ProofBaseFieldElement, String> {
        ProofBaseFieldElement::from_canonical(self.read_u64()?)
            .map_err(|_| "bound leaf contains a non-canonical field value".to_owned())
    }

    fn read_production_extension(&mut self) -> Result<ProofChallengeExtensionElement, String> {
        let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = self.read_u64()?;
        }
        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
            .map_err(|_| "exact proof contains a non-canonical extension value".to_owned())
    }

    fn remaining(&self) -> &'a [u8] {
        &self.canonical[self.offset..]
    }
}

fn validate_row_code_whir_proof_shape(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    bound_tree_entries: &[ProofTreeCatalogEntry],
    proof: &ExactSameSecretProof,
) -> Result<(), String> {
    let expected_mask_evaluation_count = construction_plan
        .opening_batch_mask_chunk_evaluation_count()
        .map_err(|_| "row-code/WHIR mask geometry is invalid".to_owned())?;
    if relation_variant.proof_privacy_mode() != construction_plan.proof_privacy_mode
        || proof.out_of_domain_evaluations.len() != relation_variant.ordered_opening_claims().len()
        || proof.opening_batch_mask_chunk_evaluations.len() != expected_mask_evaluation_count
        || proof.aggregate_commitment.num_roots() != 1
        || proof.aggregate_wide_pad_commitment.num_roots() != 1
        || proof.aggregate_wide_opening_proof.pad_commitment != proof.aggregate_wide_pad_commitment
        || construction_plan.aggregate_table_width() == 0
    {
        return Err("row-code/WHIR proof has the wrong construction shape".to_owned());
    }
    for phase in [
        RowCodeWhirPhase::Base,
        RowCodeWhirPhase::Auxiliary,
        RowCodeWhirPhase::Quotient,
    ] {
        let phase_index = phase_index(phase);
        let is_scheduled = construction_plan.phase_order.contains(&phase);
        if proof.phase_roots[phase_index].is_some() != is_scheduled
            || proof.authenticated_phase_columns[phase_index].is_some() != is_scheduled
            || proof.phase_frontiers[phase_index].is_some() != is_scheduled
        {
            return Err("row-code/WHIR phase presence diverges from the plan".to_owned());
        }
        if !is_scheduled {
            continue;
        }
        let (expected_row_count, encoded_column_count) = match phase {
            RowCodeWhirPhase::Base => construction_plan
                .base_phase
                .as_ref()
                .map(|phase| (phase.rows.len(), phase.geometry.encoded_column_count)),
            RowCodeWhirPhase::Auxiliary => construction_plan
                .auxiliary_phase
                .as_ref()
                .map(|phase| (phase.rows.len(), phase.geometry.encoded_column_count)),
            RowCodeWhirPhase::Quotient => Some((
                construction_plan.quotient_phase.rows.len(),
                construction_plan
                    .quotient_phase
                    .geometry
                    .encoded_column_count,
            )),
        }
        .ok_or_else(|| "scheduled row-code/WHIR phase has no plan".to_owned())?;
        let columns = proof.authenticated_phase_columns[phase_index]
            .as_ref()
            .ok_or_else(|| "scheduled row-code/WHIR phase opening is absent".to_owned())?;
        let frontier = proof.phase_frontiers[phase_index]
            .as_ref()
            .ok_or_else(|| "scheduled row-code/WHIR phase frontier is absent".to_owned())?;
        let maximum_frontier_count =
            crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
                encoded_column_count,
                construction_plan.outer_query_count(),
            )
            .map_err(|error| format!("derive phase frontier bound: {error:?}"))?;
        if expected_row_count == 0
            || columns.len() != construction_plan.outer_query_count()
            || columns.iter().any(|column| {
                column.values.len() != expected_row_count
                    || column.persistent_salt.is_some()
                        != (construction_plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing)
            })
            || frontier.len() > maximum_frontier_count
        {
            return Err("row-code/WHIR phase opening has the wrong shape".to_owned());
        }
    }
    if bound_tree_entries.len() != construction_plan.bound_trees.len()
        || proof.bound_tree_authentications.len() != construction_plan.bound_trees.len()
        || bound_tree_entries
            .iter()
            .zip(&construction_plan.bound_trees)
            .zip(&proof.bound_tree_authentications)
            .enumerate()
            .any(
                |(bound_tree_ordinal, ((entry, planned_tree), authentication))| {
                    let Ok(maximum_bound_frontier_count) =
                        crate::bgv::proof_suite::merkle::maximum_minimal_frontier_node_count(
                            planned_tree.leaf_count,
                            planned_tree.query_count,
                        )
                    else {
                        return true;
                    };
                    usize::try_from(planned_tree.bound_tree_ordinal).ok()
                        != Some(bound_tree_ordinal)
                        || u16::try_from(planned_tree.relation_tree_ordinal).ok()
                            != Some(entry.tree_catalog_index())
                        || entry.bound_root().is_none()
                        || authentication.opened_leaves.len() != planned_tree.query_count
                        || authentication.frontier.len() > maximum_bound_frontier_count
                        || authentication.opened_leaves.iter().any(|opening| {
                            opening.persistent_salt.is_some()
                                != entry.requires_persistent_leaf_salt()
                                || entry.materialized_row_width().ok()
                                    != Some(opening.first_point_values.len())
                                || opening.opposite_point_values.len()
                                    != opening.first_point_values.len()
                        })
                },
            )
    {
        return Err("row-code/WHIR bound authentication has the wrong shape".to_owned());
    }
    Ok(())
}

fn checked_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} exceeds canonical u32"))
}

#[cfg(test)]
mod aggregate_wide_tests {
    use super::*;

    #[test]
    fn exact_prefix_codec_refuses_private_leaf_salt_reuse_across_commitment_classes() {
        let repeated_salt = [0x8d_u8; PRIVATE_LEAF_SALT_BYTE_LENGTH];
        let distinct_salt = [0x3a_u8; PRIVATE_LEAF_SALT_BYTE_LENGTH];
        let mut canonical = Vec::new();
        let mut encoder_salts = AcceptedPrivateLeafSaltSet::default();
        append_accepted_private_leaf_salt(&mut canonical, &mut encoder_salts, repeated_salt)
            .expect("the phase salt is accepted");
        assert_eq!(
            append_accepted_private_leaf_salt(&mut canonical, &mut encoder_salts, repeated_salt,),
            Err("common proof reuses a private leaf salt".to_owned()),
        );
        append_accepted_private_leaf_salt(&mut canonical, &mut encoder_salts, distinct_salt)
            .expect("a distinct bound-tree salt is accepted");

        let mut reader = ExactCanonicalReader::new(&canonical);
        let mut decoder_salts = AcceptedPrivateLeafSaltSet::default();
        assert_eq!(
            read_accepted_private_leaf_salt(&mut reader, &mut decoder_salts),
            Ok(repeated_salt),
        );
        decoder_salts
            .insert(distinct_salt)
            .expect("the prior bound-tree salt is accepted");
        assert_eq!(
            read_accepted_private_leaf_salt(&mut reader, &mut decoder_salts),
            Err("common proof reuses a private leaf salt".to_owned()),
        );
    }

    #[test]
    fn exact_declared_proof_length_enforces_both_allocation_boundaries() {
        assert!(validate_exact_declared_proof_byte_length(1).is_ok());
        assert!(
            validate_exact_declared_proof_byte_length(MAXIMUM_COMMON_PROOF_BYTE_LENGTH).is_ok()
        );
        assert!(validate_exact_declared_proof_byte_length(0).is_err());
        assert!(
            validate_exact_declared_proof_byte_length(MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1)
                .is_err()
        );
    }
}
