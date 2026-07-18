//! Production prover primitives for the suite-bound common transparent proof.
//!
//! This module contains no native-only path.  Large oracle, Merkle, quotient,
//! and FRI material can be persisted through `external_memory`; proof bytes are
//! emitted to a bounded sink and never need to exist as one allocation.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    ActionPrivateRandomness, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, FoundationSchemaError, Hash512, PRIVATE_PROOF_SALT_PURPOSE,
    PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    PrivateRandomnessKmacInputClassAccounting, PrivateRandomnessStream, ProofObjectHeader,
    hash_foundation_tuple_512, private_randomness_stream_block_count_for_byte_length,
    private_randomness_stream_block_count_for_modulo_outputs,
    proof_attempt_identifier_derivation_count,
};
use crate::hashing::StreamingHash512;

use super::body::{
    PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER, PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER,
    canonical_leaf_byte_length, entry_leaf_count, maximum_minimal_frontier_node_count,
};
use super::external_memory;
use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
};
use super::external_polynomial::{
    ExternalPolynomialError, ExternalPolynomialValue, ExternalPolynomialVector,
    ExternalStockhamTransform, ExternalStockhamTransformDirection, ExternalStockhamTransformError,
    ExternalStockhamTransformPlan, ExternalStockhamTransformProgress,
    external_polynomial_extension_read_resident_memory_requirement,
    external_stockham_resident_memory_requirement, external_value_byte_length,
    map_external_polynomial_plan_error, read_external_polynomial_extension_values,
    read_external_polynomial_value,
};
use super::merkle::{PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER, minimal_frontier_coordinates};
use super::relation_plan::{
    BoundTreeConstructionKind, CheckedRelationApplicationChallenges, ProofPrivacyMode,
    RelationColumnDescriptor, RelationColumnOrigin, RelationColumnValueType,
    RelationConstraintColumnQuery, RelationIntegerLiftCoefficient,
    RelationIntegerLiftComponentDescriptor, RelationIntegerLiftConvolutionKind,
    RelationIntegerLiftConvolutionProductDescriptor, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor,
    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor, RelationMaskCoordinate,
    RelationMaskDescriptor, RelationMaskKind, RelationMaskTargetClass,
    RelationOpeningClaimDescriptor, RelationOpeningSourceClass, RelationTreeDescriptor,
};
use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofChallenge, CommonProofPrivacyMode,
    CommonProofQueryOpeningAbsorber, CommonProofTranscript, CommonProofTranscriptSchedule,
    CompiledRelationPlan, CompleteProofTreeCatalog, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    ProofBaseFieldElement, ProofBodyError, ProofChallengeExtensionElement, ProofEvaluationDomain,
    ProofFieldError, ProofLeafVisibility, ProofMerkleError, ProofMerkleTreeContext,
    ProofOraclePhasePairLeaf, ProofPolynomialError, ProofProfileError, ProofTreeCatalogEntry,
    ProofTreeCatalogInput, ProofTreeCatalogSource, ProofTreeRole, ProofTreeValue,
    RelationApplicationChallengeAssignment, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, RelationProofTreeInput, StatementOwnedProofTreeInput,
    SuiteModulusReference, TranscriptError, ValidatedRelationPlanArtifact,
    build_complete_proof_tree_catalog, divide_extension_polynomial_by_linear_in_place,
    evaluate_extension_at, extension_polynomial_degree, fold_extension_evaluations,
    fold_extension_evaluations_in_place,
};

const SCHEMA_VERSION: u16 = 1;
const PROOF_MERKLE_NODE_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/node/v1";
const HASH_BYTE_LENGTH: usize = 64;
const AUTHENTICATION_DIGEST_BYTE_LENGTH: usize = 64;
const CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/checkpoint-committed-state/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofProverError {
    CanonicalEncoding,
    InvalidInput,
    InvalidColumn,
    InvalidMask,
    InvalidQuotient,
    InvalidOpening,
    InvalidFriLayer,
    InvalidTree,
    CountOverflow,
    AllocationLimitExceeded,
    ResidentMemoryLimitExceeded,
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
    Merkle(ProofMerkleError),
    Relation(RelationPlanError),
}

impl From<ProofFieldError> for CommonProofProverError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for CommonProofProverError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<ProofMerkleError> for CommonProofProverError {
    fn from(error: ProofMerkleError) -> Self {
        Self::Merkle(error)
    }
}

impl From<RelationPlanError> for CommonProofProverError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

mod encoding;
mod fri;
mod generation_state;
mod generation_storage;
mod merkle_storage;
mod private_coins;
mod quotient;
mod relation_columns;

pub(crate) use encoding::{
    BoundedCommonProofByteSink, BoundedCommonProofByteSinkError, CommonProofByteSink,
    CommonProofEncodingError, CommonProofOpeningGeometry, CommonProofTranscriptQuerySink,
    CommonProofTranscriptQuerySinkError, canonical_common_proof_query_section_header,
    canonical_proof_object_header_bytes, common_proof_query_section_byte_length,
    encode_common_proof_query_tree_fragment, write_common_proof_prefix,
};
pub(crate) use fri::{
    construct_fri_terminal_coefficients, construct_initial_fri_polynomial,
    construct_next_fri_layer, construct_opening_batch_mask, evaluate_ordered_deep_openings,
};
#[cfg(test)]
pub(crate) use generation_state::generate_common_proof;
pub(crate) use generation_state::{
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationPoll, CommonProofGenerationStage,
    CommonProofGenerationStateMachine, common_proof_source_provider_is_live_during_phase,
};
pub(crate) use generation_storage::{
    CommonProofExternalMemoryRequirement, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofResidentInfrastructurePayloadAccounting, CommonProofResidentMemoryPhase,
    CommonProofResidentMemoryPhasePlan, CommonProofResidentMemoryPlan,
    GeneratedCommonProofStoragePlanError,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, common_proof_external_memory_requirement,
    common_proof_resident_memory_plan, common_proof_resident_memory_requirement,
};
pub(crate) use merkle_storage::{
    CommonProofMerkleMaterializer, CommonProofMerkleMaterializerProgress,
    CommonProofMerkleStoragePlan, CommonProofOpeningPrefetchProgress, CommonProofOpeningPrefetcher,
    CommonProofTreeStorageError, PrefetchedCommonProofOpeningArtifact, StoredCommonProofMerkleTree,
    common_proof_merkle_storage_plan,
};
pub(crate) use private_coins::{
    CheckpointableCommonProofPrivateCoinSource, CommonProofCheckpointCursorManifestError,
    CommonProofCheckpointCursorManifestRequirement, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinCoordinateCapacity, CommonProofPrivateCoinSource,
    CommonProofPrivateRandomnessAccountingError,
    MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_RUN_COUNT,
    PrivateRandomnessCommonProofCoinError, PrivateRandomnessCommonProofCoinSource,
    common_proof_checkpoint_cursor_manifest_requirement,
    common_proof_checkpoint_cursor_manifest_requirement_for_variant,
    common_proof_private_coin_coordinate_derivation_context_hash,
    common_proof_private_randomness_kmac_input_accounting,
    encode_common_proof_checkpoint_cursor_manifest,
};
#[cfg(test)]
pub(crate) use quotient::{
    construct_composed_quotient_polynomial,
    construct_constraint_stream_composed_quotient_polynomial, construct_quotient_components,
    decompose_composed_quotient,
};
#[cfg(test)]
pub(crate) use relation_columns::ResidentCommonProofSourcePolynomialProvider;
pub(crate) use relation_columns::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofAuxiliaryColumnSynthesisCursor,
    CommonProofBoundTreeLeafSaltRequest, CommonProofColumnEvaluations,
    CommonProofPreChallengeRelationColumns, CommonProofPreChallengeSourceCursor,
    CommonProofPreChallengeSourcePoll, CommonProofPrivateCoinError, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, ProvidedCommonProofSourcePolynomial,
    apply_trace_mask, base_trace_rows, construct_post_challenge_relation_columns,
    construct_pre_challenge_relation_columns, construct_reversed_relation_column,
    evaluate_common_proof_tree_columns, evaluate_pre_challenge_common_proof_tree_columns,
    integer_lift_derived_columns, maximum_auxiliary_synthesis_trace_vector_count,
    proof_created_tree_roles_by_column, relation_column_replay_requirements,
    sample_private_base_polynomial, sample_private_extension_polynomial,
};

use encoding::opened_leaf_indexes;
use fri::{
    add_replay_polynomial_to_initial_fri, add_shifted_extension_polynomial,
    evaluate_replay_polynomial_opening, replay_polynomial_key_for_claim,
    subtract_extension_polynomial, trim_base_polynomial, trim_extension_polynomial,
};
#[cfg(test)]
use generation_storage::CompletedCommonProofGenerationResult;
#[cfg(test)]
use generation_storage::common_tree_materialization_write_transaction_count;
use generation_storage::{
    CommonProofGenerationPollResult, CommonProofReplayPolynomialKey,
    CommonProofReplayPolynomialPlan, CommonProofReplayPolynomialReader,
    CommonProofReplayPolynomialRef, CommonProofReplayPolynomialWriter,
    GeneratedCommonProofStoragePlan, generated_common_proof_storage_plan, insert_materialized_tree,
    map_private_coin_generation_error, statement_owned_tree_root, unique_catalog_entry,
    validate_generation_relation_trees,
};
use merkle_storage::{canonical_common_proof_leaf_byte_length, common_proof_tree_value_type};
use quotient::{
    COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH, CommonProofConstraintStreamQuotientBuilder,
    CommonProofQuotientComponentCursor, CommonProofQuotientConstraintTransformKey,
    CommonProofQuotientEvaluationProgress, rotated_relation_evaluation_position,
    validate_column_polynomials,
};
#[cfg(test)]
use relation_columns::{
    convolution_transpose_rows, full_ring_transpose_rows, prefix_evaluation_rows,
    product_accumulator_rows, suffix_evaluation_rows,
};

#[cfg(test)]
mod tests;
