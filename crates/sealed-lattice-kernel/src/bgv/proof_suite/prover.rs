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
    PrivateRandomnessStream, ProofObjectHeader, hash_foundation_tuple_512,
};
use crate::hashing::StreamingHash512;

use super::external_memory;
use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
};
use super::external_polynomial::{
    ExternalPolynomialValue, ExternalPolynomialVector, ExternalStockhamTransform,
    ExternalStockhamTransformDirection, ExternalStockhamTransformError,
    ExternalStockhamTransformPlan, ExternalStockhamTransformProgress,
    map_external_polynomial_plan_error, read_external_polynomial_value,
};
use super::relation_plan::{
    BoundTreeConstructionKind, ProofPrivacyMode, RelationColumnDescriptor, RelationColumnOrigin,
    RelationColumnValueType, RelationIntegerLiftCoefficient,
    RelationIntegerLiftComponentDescriptor, RelationIntegerLiftConvolutionKind,
    RelationIntegerLiftConvolutionProductDescriptor, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor,
    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor, RelationMaskDescriptor,
    RelationMaskKind, RelationMaskTargetClass, RelationOpeningClaimDescriptor,
    RelationOpeningSourceClass, RelationTreeDescriptor,
};
use super::{
    CommonProofChallenge, CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber,
    CommonProofTranscript, CommonProofTranscriptSchedule, CompiledRelationPlan,
    CompleteProofTreeCatalog, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, PROOF_CHALLENGE_EXTENSION_DEGREE,
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

const PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0107;
const PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER: u16 = 0x0108;
const PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER: u16 = 0x0106;
const SCHEMA_VERSION: u16 = 1;
const PROOF_SECRET_LEAF_SALT_BYTE_LENGTH: usize = 48;
const PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER: u16 = 0x0105;
const PROOF_MERKLE_NODE_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/node/v1";
const HASH_BYTE_LENGTH: usize = 64;
const AUTHENTICATION_NODE_CANONICAL_BYTE_LENGTH: usize = 102;
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
    CommonProofGenerationStateMachine,
};
pub(crate) use generation_storage::{
    CommonProofBoundOpeningProvider, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofResidentMemoryPhase, CommonProofResidentMemoryPhasePlan,
    CommonProofResidentMemoryPlan, MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    common_proof_resident_memory_plan,
};
pub(crate) use merkle_storage::{
    CommonProofMerkleMaterializer, CommonProofMerkleMaterializerProgress,
    CommonProofMerkleStoragePlan, CommonProofOpeningArtifact, CommonProofOpeningPrefetchProgress,
    CommonProofOpeningPrefetcher, CommonProofTreeStorageError,
    PrefetchedCommonProofOpeningArtifact, StoredCommonProofMerkleTree,
    StoredCommonProofOpeningArtifact, common_proof_merkle_storage_plan,
};
pub(crate) use private_coins::{
    CheckpointableCommonProofPrivateCoinSource, CommonProofPrivateCoinSource,
    PrivateRandomnessCommonProofCoinError, PrivateRandomnessCommonProofCoinSource,
};
#[cfg(test)]
pub(crate) use quotient::{
    construct_composed_quotient_polynomial, construct_quotient_components,
    decompose_composed_quotient,
};
pub(crate) use relation_columns::{
    CommonProofColumnEvaluations, CommonProofPreChallengeRelationColumns,
    CommonProofPrivateCoinError, CommonProofSourcePolynomial, apply_trace_mask,
    construct_post_challenge_relation_columns, construct_pre_challenge_relation_columns,
    evaluate_common_proof_tree_columns, evaluate_pre_challenge_common_proof_tree_columns,
    sample_private_base_polynomial, sample_private_extension_polynomial,
};

use encoding::{minimal_frontier_coordinates, opened_leaf_indexes};
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
    GeneratedCommonProofStoragePlan, GeneratedCommonProofStoragePlanError,
    generated_common_proof_storage_plan, insert_materialized_tree,
    map_private_coin_generation_error, statement_owned_tree_root, unique_catalog_entry,
    validate_generation_relation_trees,
};
use merkle_storage::{canonical_common_proof_leaf_byte_length, common_proof_tree_value_type};
use quotient::{
    COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH, CommonProofQuotientComponentCursor,
    CommonProofReplayQuotientBuilder, required_relation_rotations_by_column,
    validate_column_polynomials,
};
#[cfg(test)]
use relation_columns::{
    convolution_transpose_rows, full_ring_transpose_rows, prefix_evaluation_rows,
    product_accumulator_rows, suffix_evaluation_rows,
};

#[cfg(test)]
mod tests;
