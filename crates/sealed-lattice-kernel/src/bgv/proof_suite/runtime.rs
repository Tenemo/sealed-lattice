//! Browser-worker runtime boundaries for the common proof engine.
//!
//! This module owns the non-serializable plan, operation, and verification
//! capabilities used around the generic common prover and verifier. Large
//! proof bytes cross the worker boundary one canonical stream chunk at a time;
//! a chunk is retained until the browser transaction acknowledges it and is
//! then dropped before the next chunk is assembled. External-memory requests
//! use the recorder/replay adapter from `external_memory`, so an asynchronous
//! browser transaction can be replayed byte-for-byte before cryptographic
//! state advances.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::foundation::{
    AuthenticatedCheckpointContinuationSource, BrowserWorkerAuthenticatedStorageHeadSource,
    BrowserWorkerAuthenticatedStorageTransitionSource, CanonicalStreamDomain,
    CanonicalStreamReadbackVerifier, CanonicalStreamVerifier, CanonicalStreamWriter,
    FOUNDATION_PROFILE, Hash512, LocalStorageBinding, PreparedActionProofAttemptSource,
    PrivateRandomCursor, ProofApplicationBinding, ProofApplicationSlotCeilings, RefusalReason,
    SelectedSuiteCapability, StreamDescriptor, VerifiedBoardApplicationSource,
    VerifiedCanonicalStreamSummary,
};
use crate::hashing::hash_framed_parts_512;

use super::relation_plan::RelationColumnOrigin;

use super::{
    BoundedCommonProofByteSinkError, CheckpointableCommonProofPrivateCoinSource,
    CommonProofBoundOpeningProvider, CommonProofByteSink, CommonProofEncodingError,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofGenerationStateMachine,
    CommonProofOpeningGeometry, CommonProofPrivateCoinSource, CommonProofRequiredByteRange,
    CommonProofSourcePolynomial, CommonProofVerificationPoll, CommonProofVerificationStateMachine,
    CommonProofVerifierError, CompiledRelationPlan, CompleteProofTreeCatalog,
    PollableCommonProofVerificationInput, ProofExternalMemory, ProofExternalMemoryExecutorError,
    ProofExternalMemoryProtection, ProofExternalMemoryTransactionAdapterError,
    ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
    ProofExternalMemoryTransactionRequest, ProofProfileError, RelationPlanCheckContext,
    RelationPlanError, RelationProofTreeInput, ValidatedRelationPlanArtifact, VerifiedCommonProof,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree,
    verified_application_statement_hash,
};

const HASH_BYTE_LENGTH: usize = 64;
const VERIFICATION_BINDING_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/verification-binding/v1";
const GENERATION_BINDING_HASH_DOMAIN: &str = "sealed-lattice/common-proof/generation-binding/v1";
const CHECKPOINT_GENESIS_HASH_DOMAIN: &str = "sealed-lattice/common-proof/checkpoint-genesis/v1";
const CHECKPOINT_CURSOR_LIST_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/checkpoint-cursor-list/v1";
const CHECKPOINT_EVENT_HASH_DOMAIN: &str = "sealed-lattice/common-proof/checkpoint-event/v1";
const CHECKPOINT_CUMULATIVE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/checkpoint-cumulative/v1";
const PROOF_APPLICATION_BINDING_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/application-binding/v1";
const CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/canonical-application-binding/v1";
const RELATION_PLAN_HASH_DOMAIN: &str = "sealed-lattice/common-proof/relation-plan/v1";
const OUTPUT_WRITE_HASH_DOMAIN: &str = "sealed-lattice/common-proof/output-write/v1";
const DURABLE_AUTHORIZATION_FRAME_MAGIC: [u8; 8] = *b"SLCPA001";
const DURABLE_AUTHORIZATION_FRAME_VERSION: u16 = 1;
pub(crate) const DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH: usize = 746;
const DURABLE_AUTHORIZATION_RECORD_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/durable-authorization-record/v1";
const COMMON_PROOF_CHECKPOINT_STATE_MAGIC: [u8; 8] = *b"SLCPCK01";
const COMMON_PROOF_CHECKPOINT_STATE_VERSION: u16 = 1;
// Checkpoint state is a build-bound custom binary format, not a canonical
// tuple schema. Its distinct identifier avoids ambiguity with the canonical
// proof-application-slot schema while the authenticated checkpoint manifest
// binds resumption to the exact runtime build.
pub(crate) const COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER: u16 = 0x010b;
pub(crate) const COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH: usize = 400;

/// Absolute anti-exhaustion bound for one canonical streamed proof artifact.
/// Exact proof-family geometry remains cryptographically binding, while phone
/// qualification targets are measured separately and never affect validity.
pub(crate) const MAXIMUM_COMMON_PROOF_BYTE_LENGTH: usize = 268_435_456;

/// A common-proof runtime never retains more than one canonical transport
/// chunk awaiting acknowledgement.
pub(crate) const MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH: usize = 1_048_576;

/// Fixed format capacity of one external-memory record.
/// Every non-final object append has this exact byte length and the final
/// append has the smaller remaining object extent. This is independent of the
/// larger canonical proof transport chunk because IndexedDB custody accounts
/// and authenticates each append as one durable record.
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH: u32 = 49_152;

/// At most two authenticated input chunks may be resident around an
/// incremental decoder call.
pub(crate) const MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS: usize = 2;
const MAXIMUM_COMMON_PROOF_REGISTRY_ENTRY_COUNT: usize = 64;
const MAXIMUM_COMMON_PROOF_HEAVY_OPERATION_COUNT: usize = 1;

pub(crate) fn common_proof_registry_entry_count(
    entry_counts: &[usize],
) -> Result<usize, CommonProofRuntimeError> {
    entry_counts
        .iter()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
}

pub(crate) fn require_common_proof_registry_entry_capacity(
    entry_counts: &[usize],
) -> Result<(), CommonProofRuntimeError> {
    if common_proof_registry_entry_count(entry_counts)? >= MAXIMUM_COMMON_PROOF_REGISTRY_ENTRY_COUNT
    {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    Ok(())
}

pub(crate) fn require_common_proof_worker_process_admission_capacity(
    entry_counts: &[usize],
    heavy_operation_counts: &[usize],
    admits_heavy_operation: bool,
) -> Result<(), CommonProofRuntimeError> {
    let admitted_entry_count = common_proof_registry_entry_count(entry_counts)?
        .checked_add(1)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let admitted_heavy_operation_count = common_proof_registry_entry_count(heavy_operation_counts)?
        .checked_add(usize::from(admits_heavy_operation))
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    require_common_proof_worker_process_ownership_limits(
        &[admitted_entry_count],
        &[admitted_heavy_operation_count],
    )
}

pub(crate) fn require_common_proof_worker_process_ownership_limits(
    entry_counts: &[usize],
    heavy_operation_counts: &[usize],
) -> Result<(), CommonProofRuntimeError> {
    if common_proof_registry_entry_count(entry_counts)? > MAXIMUM_COMMON_PROOF_REGISTRY_ENTRY_COUNT
        || common_proof_registry_entry_count(heavy_operation_counts)?
            > MAXIMUM_COMMON_PROOF_HEAVY_OPERATION_COUNT
    {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRuntimeError {
    InvalidLimits,
    InvalidPlanCapability,
    WrongVerificationBinding,
    UnknownOrStaleHandle,
    CancellationRequested,
    TransactionPending,
    TransactionResponseMissing,
    TransactionReplayIncomplete,
    OutputByteLengthExceeded,
    OutputChunkAwaitingCommit,
    OutputChunkAwaitingReadback,
    OutputChunkNotReady,
    OutputWriteReplayMismatch,
    AllocationLimitExceeded,
    AuthenticatedStorageHeadMismatch,
    WrongOperationPhase,
}

/// Runtime parameters applied before any large proof allocation or browser
/// storage request. The declared proof and prefetched-query byte lengths may
/// reduce their absolute safety bounds. The external-memory record length
/// must equal its fixed format parameter, as must the foundation proof
/// transport chunk checked by [`CommonProofRuntimeLimits::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofRuntimeLimits {
    proof_byte_length: usize,
    external_memory_chunk_byte_length: u32,
    prefetched_query_byte_length: u64,
}

impl CommonProofRuntimeLimits {
    pub(crate) fn new(
        proof_byte_length: usize,
        external_memory_chunk_byte_length: u32,
        prefetched_query_byte_length: u64,
    ) -> Result<Self, CommonProofRuntimeError> {
        let canonical_chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        if proof_byte_length == 0
            || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || canonical_chunk_byte_length != MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
            || external_memory_chunk_byte_length
                != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || prefetched_query_byte_length == 0
            || prefetched_query_byte_length
                > u64::try_from(proof_byte_length)
                    .map_err(|_| CommonProofRuntimeError::InvalidLimits)?
        {
            return Err(CommonProofRuntimeError::InvalidLimits);
        }
        Ok(Self {
            proof_byte_length,
            external_memory_chunk_byte_length,
            prefetched_query_byte_length,
        })
    }

    pub(crate) const fn proof_byte_length(self) -> usize {
        self.proof_byte_length
    }

    pub(crate) const fn external_memory_chunk_byte_length(self) -> u32 {
        self.external_memory_chunk_byte_length
    }

    pub(crate) const fn prefetched_query_byte_length(self) -> u64 {
        self.prefetched_query_byte_length
    }
}

/// Opaque checked relation-plan capability. It can only be minted from a
/// compiled plan that passes the profile and relation checks for its exact
/// context and selected variant.
pub(crate) struct CommonProofRelationPlanCapability {
    relation_plan: CompiledRelationPlan,
    relation_context: RelationPlanCheckContext,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    relation_plan_hash: [u8; HASH_BYTE_LENGTH],
    relation_plan_variant_hash: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofRelationPlanCapability {
    pub(crate) fn from_compiled_plan(
        relation_plan: &CompiledRelationPlan,
        relation_context: &RelationPlanCheckContext,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Result<Self, CommonProofRelationPlanCapabilityError> {
        let _validated =
            ValidatedRelationPlanArtifact::from_compiled_plan(relation_plan, relation_context)
                .map_err(CommonProofRelationPlanCapabilityError::Profile)?;
        let variant = relation_plan
            .select_variant(schedule_position, top_count)
            .map_err(CommonProofRelationPlanCapabilityError::Relation)?;
        let relation_plan_variant_hash = variant
            .canonical_hash()
            .map_err(CommonProofRelationPlanCapabilityError::Relation)?;
        let canonical_plan_bytes = relation_plan
            .canonical_bytes()
            .map_err(CommonProofRelationPlanCapabilityError::Relation)?;
        let relation_plan_hash =
            hash_framed_parts_512(RELATION_PLAN_HASH_DOMAIN, &[&canonical_plan_bytes]);
        Ok(Self {
            relation_plan: relation_plan.clone(),
            relation_context: relation_context.clone(),
            schedule_position,
            top_count,
            relation_plan_hash,
            relation_plan_variant_hash,
        })
    }

    pub(crate) const fn relation_plan_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.relation_plan_hash
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.relation_plan_variant_hash
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generation_input<'input>(
        &'input self,
        protocol_version: u16,
        suite_identifier: [u8; HASH_BYTE_LENGTH],
        canonical_application_statement_bytes: &'input [u8],
        relation_trees: Vec<RelationProofTreeInput>,
        provided_pre_challenge_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
        limits: CommonProofRuntimeLimits,
    ) -> CommonProofGenerationInput<'input> {
        CommonProofGenerationInput {
            protocol_version,
            suite_identifier,
            canonical_application_statement_bytes,
            relation_plan: &self.relation_plan,
            relation_context: &self.relation_context,
            schedule_position: self.schedule_position,
            top_count: self.top_count,
            relation_trees,
            provided_pre_challenge_columns,
            maximum_external_memory_chunk_byte_length: limits.external_memory_chunk_byte_length(),
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: limits.prefetched_query_byte_length(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRelationPlanCapabilityError {
    Profile(ProofProfileError),
    Relation(RelationPlanError),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofSelectedSuiteCapabilityHandle(u32);

impl CommonProofSelectedSuiteCapabilityHandle {
    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofApplicationInputCapabilityHandle(u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofPreverificationApplicationSourceHandle(u32);

/// Family-owned, board-bound statement input for the generic verifier. Exact
/// family modules will mint this only after deriving their canonical statement
/// and proof application binding from the retained verified board carrier.
/// There is deliberately no production constructor from caller bytes.
pub(crate) struct VerifiedCommonProofStatementSource {
    board_object_hash: Hash512,
    application_statement_hash: Hash512,
    canonical_application_statement_bytes: Vec<u8>,
    proof_application_binding: ProofApplicationBinding,
}

impl VerifiedCommonProofStatementSource {
    pub(crate) const fn board_object_hash(&self) -> Hash512 {
        self.board_object_hash
    }

    pub(crate) const fn application_statement_hash(&self) -> Hash512 {
        self.application_statement_hash
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn proof_application_binding(&self) -> &ProofApplicationBinding {
        &self.proof_application_binding
    }

    #[cfg(test)]
    pub(crate) fn from_test_fixture(
        protocol_version: u16,
        suite_identifier: [u8; HASH_BYTE_LENGTH],
        board_object_hash: Hash512,
        canonical_application_statement_bytes: Vec<u8>,
        proof_application_binding: ProofApplicationBinding,
    ) -> Self {
        let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
            protocol_version,
            suite_identifier,
            proof_application_binding
                .application_slot()
                .application_statement_schema_identifier(),
            &canonical_application_statement_bytes,
        ));
        Self {
            board_object_hash,
            application_statement_hash,
            canonical_application_statement_bytes,
            proof_application_binding,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofStatementTreeCapabilityHandle(u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofEvaluatorAuxiliaryRootCapabilityHandle(u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofVerifiedColumnEvaluatorCapabilityHandle(u32);

struct CommonProofSelectedSuiteEntry {
    capability: SelectedSuiteCapability,
}

struct CommonProofApplicationInputEntry {
    verification_binding: CommonProofVerificationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    protocol_version: u16,
    canonical_application_statement_bytes: Vec<u8>,
    proof_stream_descriptor: StreamDescriptor,
    limits: CommonProofRuntimeLimits,
}

struct CommonProofPreverificationApplicationSourceEntry {
    board_source: VerifiedBoardApplicationSource,
    canonical_application_statement_bytes: Vec<u8>,
    limits: CommonProofRuntimeLimits,
    protocol_version: u16,
    proof_application_binding: ProofApplicationBinding,
    relation_plan: CommonProofRelationPlanCapability,
}

struct CommonProofStatementTreeEntry {
    application_handle: u32,
    tree: VerifiedStatementOwnedTree,
}

struct CommonProofEvaluatorAuxiliaryRootEntry {
    application_handle: u32,
    root: VerifiedEvaluatorAuxiliaryRoot,
}

struct CommonProofVerifiedColumnEvaluatorEntry {
    application_handle: u32,
    evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
}

struct RefusingVerifiedColumnEvaluator;

impl VerifiedRelationColumnEvaluator for RefusingVerifiedColumnEvaluator {
    fn evaluate_at_extension_point(
        &mut self,
        _column_ordinal: u32,
        _point: super::ProofChallengeExtensionElement,
    ) -> Option<super::ProofChallengeExtensionElement> {
        None
    }
}

mod authorization_registry;
mod generation_worker;
mod storage_transport;
mod upstream_registry;
mod verification_worker;

pub(crate) use authorization_registry::{
    CommonProofApplicationBinding, CommonProofAuthenticatedLedgerHeadCapabilityHandle,
    CommonProofAuthenticatedLedgerTransitionCapabilityHandle, CommonProofGenerationOperationHandle,
    CommonProofRuntimeRegistry, CommonProofVerificationBinding,
    CommonProofVerificationOperationHandle, ConsumedVerifiedCommonProofCapability,
    GeneratedCommonProofCapabilityHandle, PendingCommonProofAuthorizationHandle,
    PreparedCommonProofAuthorization, VerifiedCommonProofCapabilityHandle,
    durable_authorization_frame_digest,
};
pub(crate) use generation_worker::{
    AuthenticatedCommonProofGenerationCheckpoint, CommonProofGenerationPreparationError,
    CommonProofGenerationSourceError, CommonProofGenerationSources,
    CommonProofGenerationWorkerError, CommonProofGenerationWorkerPoll,
    PreparedCommonProofGeneration,
};
pub(crate) use storage_transport::{
    CommonProofRuntimeCancellation, CommonProofStorageTransactionRuntime,
    PollableCommonProofByteSink, PollableCommonProofByteSinkError, ResidentCommonProofByteSource,
    ResidentCommonProofInputChunk,
};
pub(crate) use upstream_registry::CommonProofUpstreamInputRegistry;
pub(crate) use verification_worker::{
    CommonProofVerificationWorkerError, CommonProofVerificationWorkerPoll,
    ConsumedCommonProofVerificationInputs, PreparedCommonProofVerification,
};

#[cfg(test)]
use authorization_registry::take_replacement_handle_before_consuming_source;
use authorization_registry::{common_proof_stream_domain, take_nonrepeating_handle};
use generation_worker::{
    CommonProofGenerationCheckpointState, CommonProofGenerationWorker, GeneratedCommonProof,
    PendingCommonProofGenerationCheckpoint, required_chunk_indices,
};
use verification_worker::CommonProofVerificationWorker;

#[cfg(test)]
mod tests;
