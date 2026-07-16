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
    BrowserWorkerAuthenticatedStorageHeadSource, BrowserWorkerAuthenticatedStorageTransitionSource,
    CanonicalStreamDomain, CanonicalStreamReadbackVerifier, CanonicalStreamVerifier,
    CanonicalStreamWriter, FOUNDATION_PROFILE, Hash512, LocalStorageBinding,
    PreparedActionProofAttemptSource, PrivateRandomCursor, ProofApplicationBinding,
    ProofApplicationSlotCeilings, RefusalReason, SelectedSuiteCapability, StreamDescriptor,
    VerifiedBoardApplicationSource, VerifiedCanonicalStreamSummary,
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
pub(crate) const COMMON_PROOF_CHECKPOINT_STATE_SCHEMA_IDENTIFIER: u16 = 0x0109;
pub(crate) const COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH: usize = 400;

/// Maximum canonical bytes in one streamed proof artifact under the selected
/// browser profile. This limits the worker's authenticated stream, not its
/// resident WASM memory, and is not a proof field or verifier claim.
pub(crate) const MAXIMUM_COMMON_PROOF_BYTE_LENGTH: usize = 5_242_880;

/// A common-proof runtime never retains more than one canonical transport
/// chunk awaiting acknowledgement.
pub(crate) const MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH: usize = 1_048_576;

/// Fixed capacity of one external-memory record under the browser profile.
/// Every non-final object append has this exact byte length and the final
/// append has the smaller remaining object extent. This is independent of the
/// larger canonical proof transport chunk because IndexedDB custody accounts
/// and authenticates each append as one durable record.
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH: u32 = 49_152;

/// At most two authenticated input chunks may be resident around an
/// incremental decoder call.
pub(crate) const MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS: usize = 2;

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
/// reduce their fixed resource ceilings. The external-memory record length
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

/// One consumed set of positively verified inputs. This value is process local
/// and non-serializable. It can construct the persistent verifier, but it has
/// no constructor from statement roots, relation-plan bytes, or decoded proof
/// binding bytes.
pub(crate) struct ConsumedCommonProofVerificationInputs {
    verification_binding: CommonProofVerificationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    protocol_version: u16,
    canonical_application_statement_bytes: Vec<u8>,
    proof_stream_descriptor: StreamDescriptor,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    evaluator_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    limits: CommonProofRuntimeLimits,
}

impl ConsumedCommonProofVerificationInputs {
    pub(crate) const fn verification_binding(&self) -> CommonProofVerificationBinding {
        self.verification_binding
    }

    pub(crate) const fn relation_plan(&self) -> &CommonProofRelationPlanCapability {
        &self.relation_plan
    }

    pub(crate) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(crate) fn pollable_verification_input(&self) -> PollableCommonProofVerificationInput<'_> {
        PollableCommonProofVerificationInput {
            protocol_version: self.protocol_version,
            suite_identifier: self.verification_binding.suite_identifier,
            canonical_application_statement_bytes: &self.canonical_application_statement_bytes,
            relation_plan: &self.relation_plan.relation_plan,
            relation_context: &self.relation_plan.relation_context,
            schedule_position: self.relation_plan.schedule_position,
            top_count: self.relation_plan.top_count,
            statement_owned_trees: &self.statement_owned_trees,
            evaluator_auxiliary_roots: &self.evaluator_auxiliary_roots,
            declared_proof_byte_length: self.limits.proof_byte_length(),
            proof_byte_ceiling: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            maximum_resident_window_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
                .checked_mul(MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS)
                .unwrap_or(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH),
        }
    }

    pub(crate) fn prepare(
        self,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        let verifier = CommonProofVerificationStateMachine::new(self.pollable_verification_input())
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        Ok(PreparedCommonProofVerification {
            verification_binding: self.verification_binding,
            relation_plan: self.relation_plan,
            proof_stream_descriptor: self.proof_stream_descriptor,
            verifier,
            verified_column_evaluator: self.verified_column_evaluator,
            limits: self.limits,
        })
    }
}

/// Fully owned verifier input assembled only from upstream capabilities. The
/// generated-WASM boundary can retain this value behind an opaque handle, but
/// cannot construct one from proof bytes, roots, or a relation-plan record.
pub(crate) struct PreparedCommonProofVerification {
    verification_binding: CommonProofVerificationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    proof_stream_descriptor: StreamDescriptor,
    verifier: CommonProofVerificationStateMachine,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    limits: CommonProofRuntimeLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofVerificationWorkerPoll {
    NeedsReadback {
        first_chunk_index: u32,
        second_chunk_index: Option<u32>,
    },
    PrefixAccepted,
    QueryHeaderAccepted,
    QueryTreeAccepted {
        catalog_index: u16,
    },
    Complete,
}

#[derive(Debug)]
pub(crate) enum CommonProofVerificationWorkerError {
    Runtime(CommonProofRuntimeError),
    Stream(RefusalReason),
    Verifier(CommonProofVerifierError),
}

impl From<CommonProofRuntimeError> for CommonProofVerificationWorkerError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

enum CommonProofVerificationWorkerPhase {
    Ingesting {
        canonical_stream_verifier: Box<CanonicalStreamVerifier>,
        verifier: Box<CommonProofVerificationStateMachine>,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    },
    Verifying {
        readback_verifier: Box<CanonicalStreamReadbackVerifier>,
        verifier: Box<CommonProofVerificationStateMachine>,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
        resident_chunks: BTreeMap<usize, Vec<u8>>,
    },
    Cancelled,
}

/// One owned, bounded verification operation. Proof bytes are first checked
/// as one canonical sequential stream, then reread from browser storage only
/// through descriptor-authenticated full chunks. The cryptographic decoder
/// sees at most two resident chunks and never receives a caller verdict.
struct CommonProofVerificationWorker {
    verification_binding: CommonProofVerificationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    proof_stream_descriptor: StreamDescriptor,
    limits: CommonProofRuntimeLimits,
    phase: CommonProofVerificationWorkerPhase,
}

impl CommonProofVerificationWorker {
    fn new(
        prepared: PreparedCommonProofVerification,
    ) -> Result<Self, CommonProofVerificationWorkerError> {
        let stream_domain = prepared
            .verification_binding
            .proof_application
            .proof_stream_domain;
        let canonical_stream_verifier =
            CanonicalStreamVerifier::new(stream_domain, prepared.proof_stream_descriptor.clone())
                .map_err(CommonProofVerificationWorkerError::Stream)?;
        Ok(Self {
            verification_binding: prepared.verification_binding,
            relation_plan: prepared.relation_plan,
            proof_stream_descriptor: prepared.proof_stream_descriptor,
            limits: prepared.limits,
            phase: CommonProofVerificationWorkerPhase::Ingesting {
                canonical_stream_verifier: Box::new(canonical_stream_verifier),
                verifier: Box::new(prepared.verifier),
                verified_column_evaluator: prepared.verified_column_evaluator,
            },
        })
    }

    fn absorb_input_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let CommonProofVerificationWorkerPhase::Ingesting {
            canonical_stream_verifier,
            ..
        } = &mut self.phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        canonical_stream_verifier
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .map_err(CommonProofVerificationWorkerError::Stream)
    }

    fn finish_input(&mut self) -> Result<(), CommonProofVerificationWorkerError> {
        let phase = core::mem::replace(
            &mut self.phase,
            CommonProofVerificationWorkerPhase::Cancelled,
        );
        let CommonProofVerificationWorkerPhase::Ingesting {
            canonical_stream_verifier,
            verifier,
            verified_column_evaluator,
        } = phase
        else {
            self.phase = phase;
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        let verified_summary = canonical_stream_verifier
            .finish_with_summary()
            .into_result()
            .map_err(CommonProofVerificationWorkerError::Stream)?;
        let readback_verifier = CanonicalStreamReadbackVerifier::new(
            self.verification_binding
                .proof_application
                .proof_stream_domain,
            self.proof_stream_descriptor.clone(),
            verified_summary,
        )
        .map_err(CommonProofVerificationWorkerError::Stream)?;
        self.phase = CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier: Box::new(readback_verifier),
            verifier,
            verified_column_evaluator,
            resident_chunks: BTreeMap::new(),
        };
        Ok(())
    }

    fn required_readback_chunks(
        verifier: &CommonProofVerificationStateMachine,
    ) -> Result<(usize, Option<usize>), CommonProofRuntimeError> {
        let required_range = verifier
            .required_byte_range()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        required_chunk_indices(required_range)
    }

    fn supply_readback_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier,
            verifier,
            resident_chunks,
            ..
        } = &mut self.phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        let (first_chunk_index, second_chunk_index) = Self::required_readback_chunks(verifier)?;
        if chunk_index != first_chunk_index && Some(chunk_index) != second_chunk_index {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        readback_verifier
            .authenticate_chunk(chunk_index, chunk_bytes)
            .map_err(CommonProofVerificationWorkerError::Stream)?;
        if let Some(existing) = resident_chunks.get(&chunk_index) {
            if existing != chunk_bytes {
                return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
            }
            return Ok(());
        }
        if resident_chunks.len() >= MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded.into());
        }
        let mut owned_chunk = Vec::new();
        owned_chunk
            .try_reserve_exact(chunk_bytes.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        owned_chunk.extend_from_slice(chunk_bytes);
        resident_chunks.insert(chunk_index, owned_chunk);
        Ok(())
    }

    fn poll(
        &mut self,
    ) -> Result<CommonProofVerificationWorkerPoll, CommonProofVerificationWorkerError> {
        let CommonProofVerificationWorkerPhase::Verifying {
            verifier,
            verified_column_evaluator,
            resident_chunks,
            ..
        } = &mut self.phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        if verifier.required_byte_range().is_none() {
            return Ok(CommonProofVerificationWorkerPoll::Complete);
        }
        let (first_chunk_index, second_chunk_index) = Self::required_readback_chunks(verifier)?;
        if !resident_chunks.contains_key(&first_chunk_index)
            || second_chunk_index.is_some_and(|index| !resident_chunks.contains_key(&index))
        {
            return Ok(CommonProofVerificationWorkerPoll::NeedsReadback {
                first_chunk_index: u32::try_from(first_chunk_index)
                    .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
                second_chunk_index: second_chunk_index
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
            });
        }
        let resident_input_chunks = resident_chunks
            .iter()
            .map(|(chunk_index, bytes)| {
                chunk_index
                    .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                    .map(|offset| ResidentCommonProofInputChunk::new(offset, bytes))
                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source = ResidentCommonProofByteSource::new(
            self.limits.proof_byte_length(),
            resident_input_chunks,
        )?;
        let result = verifier.poll(&source, verified_column_evaluator.as_mut());
        resident_chunks.clear();
        match result.map_err(CommonProofVerificationWorkerError::Verifier)? {
            CommonProofVerificationPoll::PrefixAccepted => {
                Ok(CommonProofVerificationWorkerPoll::PrefixAccepted)
            }
            CommonProofVerificationPoll::QueryHeaderAccepted => {
                Ok(CommonProofVerificationWorkerPoll::QueryHeaderAccepted)
            }
            CommonProofVerificationPoll::QueryTreeAccepted { catalog_index } => {
                Ok(CommonProofVerificationWorkerPoll::QueryTreeAccepted { catalog_index })
            }
            CommonProofVerificationPoll::Complete => {
                Ok(CommonProofVerificationWorkerPoll::Complete)
            }
        }
    }

    fn finish(
        mut self,
    ) -> Result<
        (
            CommonProofVerificationBinding,
            CommonProofRelationPlanCapability,
            VerifiedCommonProof,
            VerifiedCanonicalStreamSummary,
        ),
        CommonProofVerificationWorkerError,
    > {
        let phase = core::mem::replace(
            &mut self.phase,
            CommonProofVerificationWorkerPhase::Cancelled,
        );
        let CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier,
            mut verifier,
            resident_chunks,
            ..
        } = phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        if !resident_chunks.is_empty() {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        }
        let proof = verifier
            .take_verified_common_proof()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let verified_stream = readback_verifier
            .finish()
            .into_result()
            .map_err(CommonProofVerificationWorkerError::Stream)?;
        Ok((
            self.verification_binding,
            self.relation_plan,
            proof,
            verified_stream,
        ))
    }

    fn cancel(&mut self) {
        match &mut self.phase {
            CommonProofVerificationWorkerPhase::Ingesting { verifier, .. }
            | CommonProofVerificationWorkerPhase::Verifying { verifier, .. } => verifier.cancel(),
            CommonProofVerificationWorkerPhase::Cancelled => {}
        }
        self.phase = CommonProofVerificationWorkerPhase::Cancelled;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationSourceError {
    PrivateCoinSource,
    BoundOpeningSource,
}

trait ErasedCommonProofPrivateCoinSource {
    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, CommonProofGenerationSourceError>;

    fn fill_raw_bytes(
        &mut self,
        purpose: u16,
        destination: &mut [u8],
    ) -> Result<(), CommonProofGenerationSourceError>;

    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor>;
}

struct ErasedCommonProofPrivateCoinSourceAdapter<Source>(Source);

impl<Source> ErasedCommonProofPrivateCoinSource
    for ErasedCommonProofPrivateCoinSourceAdapter<Source>
where
    Source: CheckpointableCommonProofPrivateCoinSource,
{
    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, CommonProofGenerationSourceError> {
        self.0
            .sample_modulo(purpose, modulus, maximum_candidate_draws_per_output)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn fill_raw_bytes(
        &mut self,
        purpose: u16,
        destination: &mut [u8],
    ) -> Result<(), CommonProofGenerationSourceError> {
        self.0
            .fill_raw_bytes(purpose, destination)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor> {
        self.0.checkpoint_cursors()
    }
}

struct CommonProofWorkerPrivateCoinSource(Box<dyn ErasedCommonProofPrivateCoinSource>);

impl CommonProofWorkerPrivateCoinSource {
    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor> {
        self.0.checkpoint_cursors()
    }
}

impl CommonProofPrivateCoinSource for CommonProofWorkerPrivateCoinSource {
    type Error = CommonProofGenerationSourceError;

    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        self.0
            .sample_modulo(purpose, modulus, maximum_candidate_draws_per_output)
    }

    fn fill_raw_bytes(&mut self, purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_raw_bytes(purpose, destination)
    }
}

trait ErasedCommonProofBoundOpeningProvider {
    fn opening_geometry(
        &self,
        catalog_entry: &super::ProofTreeCatalogEntry,
    ) -> Result<CommonProofOpeningGeometry, CommonProofGenerationSourceError>;

    fn encode_bound_opening_fragment(
        &mut self,
        catalog: &CompleteProofTreeCatalog,
        catalog_index: usize,
        geometry: CommonProofOpeningGeometry,
        sorted_query_representatives: &[u64],
        maximum_fragment_byte_length: usize,
    ) -> Result<
        Vec<u8>,
        CommonProofEncodingError<BoundedCommonProofByteSinkError, CommonProofGenerationSourceError>,
    >;
}

struct ErasedCommonProofBoundOpeningProviderAdapter<Source>(Source);

impl<Source> ErasedCommonProofBoundOpeningProvider
    for ErasedCommonProofBoundOpeningProviderAdapter<Source>
where
    Source: CommonProofBoundOpeningProvider,
{
    fn opening_geometry(
        &self,
        catalog_entry: &super::ProofTreeCatalogEntry,
    ) -> Result<CommonProofOpeningGeometry, CommonProofGenerationSourceError> {
        self.0
            .opening_geometry(catalog_entry)
            .map_err(|_| CommonProofGenerationSourceError::BoundOpeningSource)
    }

    fn encode_bound_opening_fragment(
        &mut self,
        catalog: &CompleteProofTreeCatalog,
        catalog_index: usize,
        geometry: CommonProofOpeningGeometry,
        sorted_query_representatives: &[u64],
        maximum_fragment_byte_length: usize,
    ) -> Result<
        Vec<u8>,
        CommonProofEncodingError<BoundedCommonProofByteSinkError, CommonProofGenerationSourceError>,
    > {
        self.0
            .encode_bound_opening_fragment(
                catalog,
                catalog_index,
                geometry,
                sorted_query_representatives,
                maximum_fragment_byte_length,
            )
            .map_err(|error| match error {
                CommonProofEncodingError::Prover(error) => CommonProofEncodingError::Prover(error),
                CommonProofEncodingError::Sink(error) => CommonProofEncodingError::Sink(error),
                CommonProofEncodingError::Artifact(_) => CommonProofEncodingError::Artifact(
                    CommonProofGenerationSourceError::BoundOpeningSource,
                ),
            })
    }
}

struct CommonProofWorkerBoundOpeningProvider(Box<dyn ErasedCommonProofBoundOpeningProvider>);

impl CommonProofBoundOpeningProvider for CommonProofWorkerBoundOpeningProvider {
    type Error = CommonProofGenerationSourceError;

    fn opening_geometry(
        &self,
        catalog_entry: &super::ProofTreeCatalogEntry,
    ) -> Result<CommonProofOpeningGeometry, Self::Error> {
        self.0.opening_geometry(catalog_entry)
    }

    fn encode_bound_opening_fragment(
        &mut self,
        catalog: &CompleteProofTreeCatalog,
        catalog_index: usize,
        geometry: CommonProofOpeningGeometry,
        sorted_query_representatives: &[u64],
        maximum_fragment_byte_length: usize,
    ) -> Result<Vec<u8>, CommonProofEncodingError<BoundedCommonProofByteSinkError, Self::Error>>
    {
        self.0.encode_bound_opening_fragment(
            catalog,
            catalog_index,
            geometry,
            sorted_query_representatives,
            maximum_fragment_byte_length,
        )
    }
}

/// Owned exact-family sources used by one generated proof. Source errors are
/// collapsed only to their authority boundary: private randomness or a
/// family-owned bound tree. The host cannot install either source through FFI.
pub(crate) struct CommonProofGenerationSources {
    private_coins: CommonProofWorkerPrivateCoinSource,
    bound_openings: CommonProofWorkerBoundOpeningProvider,
}

impl CommonProofGenerationSources {
    pub(crate) fn new<Coins, BoundOpenings>(
        private_coins: Coins,
        bound_openings: BoundOpenings,
    ) -> Self
    where
        Coins: CheckpointableCommonProofPrivateCoinSource + 'static,
        BoundOpenings: CommonProofBoundOpeningProvider + 'static,
    {
        Self {
            private_coins: CommonProofWorkerPrivateCoinSource(Box::new(
                ErasedCommonProofPrivateCoinSourceAdapter(private_coins),
            )),
            bound_openings: CommonProofWorkerBoundOpeningProvider(Box::new(
                ErasedCommonProofBoundOpeningProviderAdapter(bound_openings),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommonProofGenerationBinding {
    verification_binding: CommonProofVerificationBinding,
    attempt_identifier: [u8; 32],
    checkpoint_lineage_identifier: [u8; 32],
    checkpoint_schedule_digest: Hash512,
    checkpoint_next_event_index: u64,
    checkpoint_cumulative_event_digest: Hash512,
}

impl CommonProofGenerationBinding {
    fn from_authenticated_attempt(
        verification_binding: CommonProofVerificationBinding,
        attempt_source: PreparedActionProofAttemptSource,
    ) -> Result<Self, CommonProofRuntimeError> {
        let application_slot = attempt_source.application_slot();
        let proof_application = verification_binding.proof_application;
        if application_slot
            .hash()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
            .into_bytes()
            != proof_application.proof_application_slot_hash
            || application_slot.suite_identifier().into_bytes()
                != verification_binding.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes()
                != verification_binding.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes()
                != verification_binding.action_context_hash
            || attempt_source.application_slot_hash().into_bytes()
                != proof_application.proof_application_slot_hash
            || attempt_source.application_statement_schema_identifier()
                != proof_application.application_statement_schema_identifier
            || attempt_source.board_object_hash().into_bytes()
                != verification_binding.board_object_hash
            || attempt_source.expected_proof_byte_length() != proof_application.proof_byte_length
            || attempt_source.expected_query_count() != proof_application.proof_query_count
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let checkpoint = *attempt_source.checkpoint_continuation();
        Ok(Self {
            verification_binding,
            attempt_identifier: attempt_source.attempt_identifier(),
            checkpoint_lineage_identifier: checkpoint.checkpoint_lineage_identifier(),
            checkpoint_schedule_digest: checkpoint.checkpoint_schedule_digest(),
            checkpoint_next_event_index: checkpoint.next_event_index(),
            checkpoint_cumulative_event_digest: checkpoint.cumulative_event_digest(),
        })
    }

    #[cfg(test)]
    fn for_genuine_test_application(verification_binding: CommonProofVerificationBinding) -> Self {
        let mut binding = Self {
            verification_binding,
            attempt_identifier: [0x91; 32],
            checkpoint_lineage_identifier: [0x92; 32],
            checkpoint_schedule_digest: Hash512::from_bytes([0x93; HASH_BYTE_LENGTH]),
            checkpoint_next_event_index: 0,
            checkpoint_cumulative_event_digest: Hash512::from_bytes([0_u8; HASH_BYTE_LENGTH]),
        };
        binding.checkpoint_cumulative_event_digest =
            Hash512::from_bytes(binding.checkpoint_genesis_digest());
        binding
    }

    /// Stable same-attempt binding for scratch objects and checkpoint replay.
    /// The mutable checkpoint position is deliberately excluded so a resumed
    /// operation addresses the same deterministic transaction namespace.
    fn binding_hash(self) -> [u8; HASH_BYTE_LENGTH] {
        hash_framed_parts_512(
            GENERATION_BINDING_HASH_DOMAIN,
            &[
                &self.verification_binding.binding_hash(),
                &self.attempt_identifier,
                &self.checkpoint_lineage_identifier,
                &self.checkpoint_schedule_digest.into_bytes(),
            ],
        )
    }

    fn checkpoint_genesis_digest(self) -> [u8; HASH_BYTE_LENGTH] {
        hash_framed_parts_512(
            CHECKPOINT_GENESIS_HASH_DOMAIN,
            &[
                &self.binding_hash(),
                &self.checkpoint_lineage_identifier,
                &self.checkpoint_schedule_digest.into_bytes(),
            ],
        )
    }

    fn starts_at_checkpoint_genesis(self) -> bool {
        self.checkpoint_next_event_index == 0
            && self.checkpoint_cumulative_event_digest.into_bytes()
                == self.checkpoint_genesis_digest()
    }
}

#[derive(Debug)]
pub(crate) enum CommonProofGenerationPreparationError {
    Runtime(CommonProofRuntimeError),
    Generation(CommonProofGenerationInitializationError),
}

impl From<CommonProofRuntimeError> for CommonProofGenerationPreparationError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

/// Fully owned generation input. It can be retained behind an opaque worker
/// handle only after an authenticated action attempt agrees with the exact
/// board/application coordinates and the family supplies its real columns and
/// bound-tree opening source.
pub(crate) struct PreparedCommonProofGeneration {
    binding: CommonProofGenerationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    state: CommonProofGenerationStateMachine,
    sources: CommonProofGenerationSources,
    limits: CommonProofRuntimeLimits,
}

impl PreparedCommonProofGeneration {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_exact_family_sources(
        attempt_source: PreparedActionProofAttemptSource,
        verification_binding: CommonProofVerificationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: Vec<u8>,
        relation_trees: Vec<RelationProofTreeInput>,
        provided_pre_challenge_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
        limits: CommonProofRuntimeLimits,
        sources: CommonProofGenerationSources,
    ) -> Result<Self, CommonProofGenerationPreparationError> {
        let binding = CommonProofGenerationBinding::from_authenticated_attempt(
            verification_binding,
            attempt_source,
        )?;
        if relation_plan.relation_plan_hash() != verification_binding.relation_plan_hash
            || limits.proof_byte_length() as u64
                != verification_binding.proof_application.proof_byte_length
            || verified_application_statement_hash(
                protocol_version,
                verification_binding.suite_identifier,
                verification_binding
                    .proof_application
                    .application_statement_schema_identifier,
                &canonical_application_statement_bytes,
            ) != attempt_source.application_statement_hash().into_bytes()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        let state = CommonProofGenerationStateMachine::new(relation_plan.generation_input(
            protocol_version,
            verification_binding.suite_identifier,
            &canonical_application_statement_bytes,
            relation_trees,
            provided_pre_challenge_columns,
            limits,
        ))
        .map_err(CommonProofGenerationPreparationError::Generation)?;
        Ok(Self {
            binding,
            relation_plan,
            state,
            sources,
            limits,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_genuine_test_sources(
        verification_binding: CommonProofVerificationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        state: CommonProofGenerationStateMachine,
        sources: CommonProofGenerationSources,
        limits: CommonProofRuntimeLimits,
    ) -> Self {
        Self {
            binding: CommonProofGenerationBinding::for_genuine_test_application(
                verification_binding,
            ),
            relation_plan,
            state,
            sources,
            limits,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_genuine_test_sources_for_authenticated_checkpoint(
        verification_binding: CommonProofVerificationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        state: CommonProofGenerationStateMachine,
        sources: CommonProofGenerationSources,
        limits: CommonProofRuntimeLimits,
        authenticated_checkpoint_state: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        let checkpoint =
            CommonProofGenerationCheckpointState::decode(authenticated_checkpoint_state)?;
        let mut binding =
            CommonProofGenerationBinding::for_genuine_test_application(verification_binding);
        if checkpoint.stable_attempt_binding_hash != binding.binding_hash()
            || checkpoint.checkpoint_lineage_identifier != binding.checkpoint_lineage_identifier
            || checkpoint.checkpoint_schedule_digest
                != binding.checkpoint_schedule_digest.into_bytes()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        binding.checkpoint_next_event_index = checkpoint.next_event_index;
        binding.checkpoint_cumulative_event_digest =
            Hash512::from_bytes(checkpoint.cumulative_event_digest);
        Ok(Self {
            binding,
            relation_plan,
            state,
            sources,
            limits,
        })
    }
}

type OwnedCommonProofGenerationError = CommonProofGenerationError<
    ProofExternalMemoryTransactionAdapterError,
    CommonProofGenerationSourceError,
    PollableCommonProofByteSinkError,
    CommonProofGenerationSourceError,
>;

#[derive(Debug)]
pub(crate) enum CommonProofGenerationWorkerError {
    Runtime(CommonProofRuntimeError),
    Generation {
        stage: CommonProofGenerationStage,
        error: Box<OwnedCommonProofGenerationError>,
    },
    Cleanup(ProofExternalMemoryExecutorError<ProofExternalMemoryTransactionAdapterError>),
}

impl From<CommonProofRuntimeError> for CommonProofGenerationWorkerError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationWorkerPoll {
    Progress {
        stage: CommonProofGenerationStage,
        checkpoint_ready: bool,
    },
    ResumeComplete {
        stage: CommonProofGenerationStage,
    },
    StorageRequestReady {
        encoded_request_byte_length: u32,
    },
    OutputChunkReady {
        chunk_index: u32,
        chunk_byte_length: u32,
    },
    OutputReadbackRequired {
        chunk_index: u32,
    },
    Complete,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommonProofGenerationCheckpointState {
    stable_attempt_binding_hash: [u8; HASH_BYTE_LENGTH],
    checkpoint_lineage_identifier: [u8; 32],
    checkpoint_schedule_digest: [u8; HASH_BYTE_LENGTH],
    next_event_index: u64,
    cumulative_event_digest: [u8; HASH_BYTE_LENGTH],
    safe_boundary_ordinal: u32,
    position: [u8; 16],
    committed_state_digest: [u8; HASH_BYTE_LENGTH],
    cursor_list_digest: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofGenerationCheckpointState {
    fn encode(&self) -> [u8; COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH] {
        let mut output = [0_u8; COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH];
        let mut cursor = 0_usize;
        append_checkpoint_state_bytes(
            &mut output,
            &mut cursor,
            &COMMON_PROOF_CHECKPOINT_STATE_MAGIC,
        );
        append_checkpoint_state_bytes(
            &mut output,
            &mut cursor,
            &COMMON_PROOF_CHECKPOINT_STATE_VERSION.to_le_bytes(),
        );
        append_checkpoint_state_bytes(
            &mut output,
            &mut cursor,
            &COMMON_PROOF_CHECKPOINT_STATE_SCHEMA_IDENTIFIER.to_le_bytes(),
        );
        append_checkpoint_state_bytes(&mut output, &mut cursor, &self.stable_attempt_binding_hash);
        append_checkpoint_state_bytes(
            &mut output,
            &mut cursor,
            &self.checkpoint_lineage_identifier,
        );
        append_checkpoint_state_bytes(&mut output, &mut cursor, &self.checkpoint_schedule_digest);
        append_checkpoint_state_bytes(
            &mut output,
            &mut cursor,
            &self.next_event_index.to_le_bytes(),
        );
        append_checkpoint_state_bytes(&mut output, &mut cursor, &self.cumulative_event_digest);
        append_checkpoint_state_bytes(
            &mut output,
            &mut cursor,
            &self.safe_boundary_ordinal.to_le_bytes(),
        );
        append_checkpoint_state_bytes(&mut output, &mut cursor, &self.position);
        append_checkpoint_state_bytes(&mut output, &mut cursor, &self.committed_state_digest);
        append_checkpoint_state_bytes(&mut output, &mut cursor, &self.cursor_list_digest);
        append_checkpoint_state_bytes(&mut output, &mut cursor, &0_u64.to_le_bytes());
        debug_assert_eq!(cursor, COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH);
        output
    }

    fn decode(bytes: &[u8]) -> Result<Self, CommonProofRuntimeError> {
        if bytes.len() != COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let mut cursor = 0_usize;
        let magic = read_checkpoint_state_array::<8>(bytes, &mut cursor)?;
        let version = u16::from_le_bytes(read_checkpoint_state_array(bytes, &mut cursor)?);
        let schema_identifier =
            u16::from_le_bytes(read_checkpoint_state_array(bytes, &mut cursor)?);
        if magic != COMMON_PROOF_CHECKPOINT_STATE_MAGIC
            || version != COMMON_PROOF_CHECKPOINT_STATE_VERSION
            || schema_identifier != COMMON_PROOF_CHECKPOINT_STATE_SCHEMA_IDENTIFIER
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let state = Self {
            stable_attempt_binding_hash: read_checkpoint_state_array(bytes, &mut cursor)?,
            checkpoint_lineage_identifier: read_checkpoint_state_array(bytes, &mut cursor)?,
            checkpoint_schedule_digest: read_checkpoint_state_array(bytes, &mut cursor)?,
            next_event_index: u64::from_le_bytes(read_checkpoint_state_array(bytes, &mut cursor)?),
            cumulative_event_digest: read_checkpoint_state_array(bytes, &mut cursor)?,
            safe_boundary_ordinal: u32::from_le_bytes(read_checkpoint_state_array(
                bytes,
                &mut cursor,
            )?),
            position: read_checkpoint_state_array(bytes, &mut cursor)?,
            committed_state_digest: read_checkpoint_state_array(bytes, &mut cursor)?,
            cursor_list_digest: read_checkpoint_state_array(bytes, &mut cursor)?,
        };
        let output_byte_length =
            u64::from_le_bytes(read_checkpoint_state_array(bytes, &mut cursor)?);
        if cursor != bytes.len()
            || output_byte_length != 0
            || state.next_event_index == 0
            || u64::from(state.safe_boundary_ordinal) != state.next_event_index
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(state)
    }

    fn matches_binding(&self, binding: CommonProofGenerationBinding) -> bool {
        self.stable_attempt_binding_hash == binding.binding_hash()
            && self.checkpoint_lineage_identifier == binding.checkpoint_lineage_identifier
            && self.checkpoint_schedule_digest == binding.checkpoint_schedule_digest.into_bytes()
            && self.next_event_index == binding.checkpoint_next_event_index
            && self.cumulative_event_digest
                == binding.checkpoint_cumulative_event_digest.into_bytes()
    }
}

fn append_checkpoint_state_bytes<const LENGTH: usize>(
    output: &mut [u8; COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH],
    cursor: &mut usize,
    bytes: &[u8; LENGTH],
) {
    let end = cursor.saturating_add(LENGTH);
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn read_checkpoint_state_array<const LENGTH: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; LENGTH], CommonProofRuntimeError> {
    let end = cursor
        .checked_add(LENGTH)
        .filter(|end| *end <= bytes.len())
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
    let output = bytes[*cursor..end]
        .try_into()
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    *cursor = end;
    Ok(output)
}

struct PendingCommonProofGenerationCheckpoint {
    state: CommonProofGenerationCheckpointState,
    encoded_state: [u8; COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH],
    ordered_cursor_bytes: Vec<Vec<u8>>,
}

impl PendingCommonProofGenerationCheckpoint {
    fn encoded_state(&self) -> &[u8] {
        &self.encoded_state
    }

    fn safe_boundary_ordinal(&self) -> u32 {
        self.state.safe_boundary_ordinal
    }

    fn ordered_cursor_bytes(&self) -> &[Vec<u8>] {
        &self.ordered_cursor_bytes
    }
}

fn build_generation_checkpoint(
    binding: CommonProofGenerationBinding,
    previous_next_event_index: u64,
    previous_cumulative_event_digest: [u8; HASH_BYTE_LENGTH],
    boundary: CommonProofGenerationCheckpointBoundary,
    private_coins: &CommonProofWorkerPrivateCoinSource,
) -> Result<PendingCommonProofGenerationCheckpoint, CommonProofRuntimeError> {
    let next_event_index = previous_next_event_index
        .checked_add(1)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    if u64::from(boundary.safe_boundary_ordinal()) != next_event_index {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }

    let cursors = private_coins.checkpoint_cursors();
    if cursors.windows(2).any(|pair| {
        let left = pair[0];
        let right = pair[1];
        (left.family(), left.purpose()) >= (right.family(), right.purpose())
    }) {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let mut ordered_cursor_bytes = Vec::new();
    ordered_cursor_bytes
        .try_reserve_exact(cursors.len())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    for cursor in cursors {
        ordered_cursor_bytes.push(
            cursor
                .encode()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
        );
    }
    let cursor_parts = ordered_cursor_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let cursor_list_digest =
        hash_framed_parts_512(CHECKPOINT_CURSOR_LIST_HASH_DOMAIN, &cursor_parts);
    let safe_boundary_ordinal = boundary.safe_boundary_ordinal();
    let position = boundary.position();
    let committed_state_digest = boundary.committed_state_digest();
    let event_digest = hash_framed_parts_512(
        CHECKPOINT_EVENT_HASH_DOMAIN,
        &[
            &binding.binding_hash(),
            &binding.checkpoint_schedule_digest.into_bytes(),
            &previous_next_event_index.to_le_bytes(),
            &safe_boundary_ordinal.to_le_bytes(),
            &position,
            &committed_state_digest,
            &cursor_list_digest,
            &0_u64.to_le_bytes(),
        ],
    );
    let cumulative_event_digest = hash_framed_parts_512(
        CHECKPOINT_CUMULATIVE_HASH_DOMAIN,
        &[&previous_cumulative_event_digest, &event_digest],
    );
    let state = CommonProofGenerationCheckpointState {
        stable_attempt_binding_hash: binding.binding_hash(),
        checkpoint_lineage_identifier: binding.checkpoint_lineage_identifier,
        checkpoint_schedule_digest: binding.checkpoint_schedule_digest.into_bytes(),
        next_event_index,
        cumulative_event_digest,
        safe_boundary_ordinal,
        position,
        committed_state_digest,
        cursor_list_digest,
    };
    Ok(PendingCommonProofGenerationCheckpoint {
        encoded_state: state.encode(),
        state,
        ordered_cursor_bytes,
    })
}

struct GeneratedCommonProof {
    binding: CommonProofGenerationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    stream_descriptor: StreamDescriptor,
}

/// One browser-owned generated proof operation. The cryptographic state,
/// private coin cursors, bound-tree source, external-memory replay, and output
/// digest all stay in this worker. Host input can only satisfy the exact
/// pending storage request or acknowledge and reread the exact staged chunk.
struct CommonProofGenerationWorker {
    binding: CommonProofGenerationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    state: CommonProofGenerationStateMachine,
    private_coins: CommonProofWorkerPrivateCoinSource,
    bound_openings: CommonProofWorkerBoundOpeningProvider,
    storage: CommonProofStorageTransactionRuntime,
    output: Option<PollableCommonProofByteSink>,
    encoded_storage_request: Option<Vec<u8>>,
    terminal_stream_descriptor: Option<StreamDescriptor>,
    checkpoint_next_event_index: u64,
    checkpoint_cumulative_event_digest: [u8; HASH_BYTE_LENGTH],
    last_checkpoint_position: Option<[u8; 16]>,
    pending_checkpoint: Option<PendingCommonProofGenerationCheckpoint>,
    resume_target: Option<CommonProofGenerationCheckpointState>,
    generation_complete: bool,
    cancellation_requested: bool,
    generation_transaction_must_replay_before_cancellation: bool,
    cancellation_complete: bool,
}

impl CommonProofGenerationWorker {
    fn new(prepared: PreparedCommonProofGeneration) -> Result<Self, CommonProofRuntimeError> {
        if !prepared.binding.starts_at_checkpoint_genesis() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Self::new_with_resume_target(prepared, None)
    }

    fn resume(
        prepared: PreparedCommonProofGeneration,
        authenticated_checkpoint_state: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        let target = CommonProofGenerationCheckpointState::decode(authenticated_checkpoint_state)?;
        if !target.matches_binding(prepared.binding) {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Self::new_with_resume_target(prepared, Some(target))
    }

    fn new_with_resume_target(
        prepared: PreparedCommonProofGeneration,
        resume_target: Option<CommonProofGenerationCheckpointState>,
    ) -> Result<Self, CommonProofRuntimeError> {
        let stream_domain = prepared
            .binding
            .verification_binding
            .proof_application
            .proof_stream_domain;
        let output = PollableCommonProofByteSink::new(
            stream_domain,
            prepared.limits.proof_byte_length(),
            prepared.limits,
        )?;
        Ok(Self {
            binding: prepared.binding,
            relation_plan: prepared.relation_plan,
            state: prepared.state,
            private_coins: prepared.sources.private_coins,
            bound_openings: prepared.sources.bound_openings,
            storage: CommonProofStorageTransactionRuntime::for_runtime_binding(
                prepared.binding.binding_hash(),
            ),
            output: Some(output),
            encoded_storage_request: None,
            terminal_stream_descriptor: None,
            checkpoint_next_event_index: 0,
            checkpoint_cumulative_event_digest: prepared.binding.checkpoint_genesis_digest(),
            last_checkpoint_position: None,
            pending_checkpoint: None,
            resume_target,
            generation_complete: false,
            cancellation_requested: false,
            generation_transaction_must_replay_before_cancellation: false,
            cancellation_complete: false,
        })
    }

    fn pending_checkpoint(&self) -> Option<&PendingCommonProofGenerationCheckpoint> {
        self.pending_checkpoint.as_ref()
    }

    fn advance_pending_checkpoint(&mut self) -> Result<(), CommonProofRuntimeError> {
        let pending = self
            .pending_checkpoint
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        self.checkpoint_next_event_index = pending.state.next_event_index;
        self.checkpoint_cumulative_event_digest = pending.state.cumulative_event_digest;
        self.last_checkpoint_position = Some(pending.state.position);
        Ok(())
    }

    fn pending_storage_request(&self) -> Option<&[u8]> {
        self.encoded_storage_request.as_deref()
    }

    #[cfg(test)]
    fn pending_storage_transaction_request(
        &self,
    ) -> Option<&ProofExternalMemoryTransactionRequest> {
        self.storage.pending_request()
    }

    fn supply_storage_response(
        &mut self,
        encoded_response: &[u8],
    ) -> Result<(), CommonProofGenerationWorkerError> {
        if self.encoded_storage_request.is_none() {
            return Err(CommonProofRuntimeError::TransactionResponseMissing.into());
        }
        self.storage.supply_worker_response(encoded_response)?;
        self.encoded_storage_request = None;
        Ok(())
    }

    fn pending_output_chunk(&self) -> Option<(usize, &[u8])> {
        self.output
            .as_ref()
            .and_then(|output| output.pending_chunk())
    }

    fn acknowledge_output_chunk(&mut self) -> Result<(), CommonProofGenerationWorkerError> {
        self.output
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .acknowledge_pending_chunk()?;
        Ok(())
    }

    fn confirm_output_readback(
        &mut self,
        chunk_index: usize,
        readback_bytes: &[u8],
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.output
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .confirm_pending_chunk_readback(chunk_index, readback_bytes)?;
        Ok(())
    }

    fn request_cancellation(&mut self) {
        if self.cancellation_requested {
            return;
        }
        self.cancellation_requested = true;
        self.generation_transaction_must_replay_before_cancellation =
            self.encoded_storage_request.is_some() || self.storage.replay_is_active();
    }

    fn poll(
        &mut self,
    ) -> Result<CommonProofGenerationWorkerPoll, CommonProofGenerationWorkerError> {
        if self.cancellation_complete {
            return Ok(CommonProofGenerationWorkerPoll::Cancelled);
        }
        if self.cancellation_requested {
            return self.poll_cancellation();
        }
        if self.pending_checkpoint.is_some() {
            return Ok(CommonProofGenerationWorkerPoll::Progress {
                stage: self.state.stage(),
                checkpoint_ready: true,
            });
        }
        if let Some(request) = self.pending_storage_request() {
            return Ok(CommonProofGenerationWorkerPoll::StorageRequestReady {
                encoded_request_byte_length: u32::try_from(request.len())
                    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
            });
        }
        if let Some((chunk_index, chunk_bytes)) = self.pending_output_chunk() {
            return Ok(CommonProofGenerationWorkerPoll::OutputChunkReady {
                chunk_index: u32::try_from(chunk_index)
                    .map_err(|_| CommonProofRuntimeError::OutputByteLengthExceeded)?,
                chunk_byte_length: u32::try_from(chunk_bytes.len())
                    .map_err(|_| CommonProofRuntimeError::OutputByteLengthExceeded)?,
            });
        }
        if let Some(chunk_index) = self
            .output
            .as_ref()
            .and_then(PollableCommonProofByteSink::pending_readback_chunk_index)
        {
            return Ok(CommonProofGenerationWorkerPoll::OutputReadbackRequired {
                chunk_index: u32::try_from(chunk_index)
                    .map_err(|_| CommonProofRuntimeError::OutputByteLengthExceeded)?,
            });
        }
        if self.generation_complete {
            return self.finalize_output();
        }

        let result = self.state.poll(
            &mut self.storage,
            &mut self.private_coins,
            self.output
                .as_mut()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
            &mut self.bound_openings,
        );
        if result.is_ok() && self.storage.replay_is_active() {
            self.storage.transaction_completed()?;
        }
        match result {
            Err(error) if generation_error_is_storage_yield(&error) => {
                self.capture_storage_request()?;
                self.poll()
            }
            Err(CommonProofGenerationError::Sink(
                PollableCommonProofByteSinkError::ChunkReady
                | PollableCommonProofByteSinkError::ChunkAwaitingCommit
                | PollableCommonProofByteSinkError::ChunkAwaitingReadback,
            )) => self.poll(),
            Err(error) => Err(CommonProofGenerationWorkerError::Generation {
                stage: self.state.stage(),
                error: Box::new(error),
            }),
            Ok(CommonProofGenerationPoll::StorageTransactionCompleted) => self.progress_poll(),
            Ok(CommonProofGenerationPoll::Complete) => {
                self.generation_complete = true;
                self.finalize_output()
            }
            Ok(
                CommonProofGenerationPoll::ArithmeticStepCompleted
                | CommonProofGenerationPoll::OutputFragmentAccepted,
            ) => self.progress_poll(),
        }
    }

    fn progress_poll(
        &mut self,
    ) -> Result<CommonProofGenerationWorkerPoll, CommonProofGenerationWorkerError> {
        let stage = self.state.stage();
        let Some(boundary) = self.state.checkpoint_boundary() else {
            if self.resume_target.is_some()
                && matches!(
                    stage,
                    CommonProofGenerationStage::EmittingPrefix
                        | CommonProofGenerationStage::EmittingQueries
                        | CommonProofGenerationStage::Finalizing
                        | CommonProofGenerationStage::Complete
                )
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
            }
            return Ok(CommonProofGenerationWorkerPoll::Progress {
                stage,
                checkpoint_ready: false,
            });
        };
        if self.last_checkpoint_position == Some(boundary.position()) {
            return Ok(CommonProofGenerationWorkerPoll::Progress {
                stage,
                checkpoint_ready: false,
            });
        }
        let checkpoint = build_generation_checkpoint(
            self.binding,
            self.checkpoint_next_event_index,
            self.checkpoint_cumulative_event_digest,
            boundary,
            &self.private_coins,
        )?;
        if let Some(target) = &self.resume_target {
            if checkpoint.state.next_event_index > target.next_event_index {
                return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
            }
            self.checkpoint_next_event_index = checkpoint.state.next_event_index;
            self.checkpoint_cumulative_event_digest = checkpoint.state.cumulative_event_digest;
            self.last_checkpoint_position = Some(checkpoint.state.position);
            if checkpoint.state.next_event_index == target.next_event_index {
                if &checkpoint.state != target {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
                }
                self.resume_target = None;
                return Ok(CommonProofGenerationWorkerPoll::ResumeComplete { stage });
            }
            return Ok(CommonProofGenerationWorkerPoll::Progress {
                stage,
                checkpoint_ready: false,
            });
        }
        self.pending_checkpoint = Some(checkpoint);
        Ok(CommonProofGenerationWorkerPoll::Progress {
            stage,
            checkpoint_ready: true,
        })
    }

    fn capture_storage_request(&mut self) -> Result<(), CommonProofGenerationWorkerError> {
        self.storage.capture_yielded_request()?;
        self.encoded_storage_request = Some(self.storage.encode_pending_worker_request()?);
        Ok(())
    }

    fn finalize_output(
        &mut self,
    ) -> Result<CommonProofGenerationWorkerPoll, CommonProofGenerationWorkerError> {
        let output = self
            .output
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if output.final_partial_chunk_is_ready() {
            output.seal_final_chunk()?;
            return self.poll();
        }
        if !output.complete_output_is_authenticated() {
            return Err(CommonProofRuntimeError::OutputChunkNotReady.into());
        }
        let descriptor = self
            .output
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .finish()?;
        let expected = self.binding.verification_binding.proof_application;
        if descriptor.total_byte_length != expected.proof_byte_length
            || descriptor.full_object_digest.into_bytes()
                != expected.proof_stream_full_object_digest
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        self.terminal_stream_descriptor = Some(descriptor);
        Ok(CommonProofGenerationWorkerPoll::Complete)
    }

    fn poll_cancellation(
        &mut self,
    ) -> Result<CommonProofGenerationWorkerPoll, CommonProofGenerationWorkerError> {
        if let Some(request) = self.pending_storage_request() {
            return Ok(CommonProofGenerationWorkerPoll::StorageRequestReady {
                encoded_request_byte_length: u32::try_from(request.len())
                    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
            });
        }
        if self.generation_transaction_must_replay_before_cancellation {
            if !self.storage.replay_is_active() {
                return Err(CommonProofRuntimeError::TransactionResponseMissing.into());
            }
            let result = self.state.poll(
                &mut self.storage,
                &mut self.private_coins,
                self.output
                    .as_mut()
                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
                &mut self.bound_openings,
            );
            match result {
                Ok(_) => self.storage.transaction_completed()?,
                Err(error) => {
                    return Err(CommonProofGenerationWorkerError::Generation {
                        stage: self.state.stage(),
                        error: Box::new(error),
                    });
                }
            }
            self.generation_transaction_must_replay_before_cancellation = false;
        }
        if let Some(output) = self.output.as_mut() {
            output.cancel();
        }
        match self.state.cancel(&mut self.storage) {
            Ok(()) => {
                if self.storage.replay_is_active() {
                    self.storage.transaction_completed()?;
                }
                self.storage.cancel();
                self.output = None;
                self.cancellation_complete = true;
                Ok(CommonProofGenerationWorkerPoll::Cancelled)
            }
            Err(error) if executor_error_is_storage_yield(&error) => {
                self.capture_storage_request()?;
                self.poll_cancellation()
            }
            Err(error) => Err(CommonProofGenerationWorkerError::Cleanup(error)),
        }
    }

    fn finish(self) -> Result<GeneratedCommonProof, CommonProofRuntimeError> {
        if self.cancellation_requested || !self.generation_complete {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        Ok(GeneratedCommonProof {
            binding: self.binding,
            relation_plan: self.relation_plan,
            stream_descriptor: self
                .terminal_stream_descriptor
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
        })
    }
}

fn generation_error_is_storage_yield(error: &OwnedCommonProofGenerationError) -> bool {
    matches!(
        error,
        CommonProofGenerationError::Storage(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded
        ))
    )
}

fn executor_error_is_storage_yield(
    error: &ProofExternalMemoryExecutorError<ProofExternalMemoryTransactionAdapterError>,
) -> bool {
    matches!(
        error,
        ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded
        )
    )
}

fn required_chunk_indices(
    required_range: CommonProofRequiredByteRange,
) -> Result<(usize, Option<usize>), CommonProofRuntimeError> {
    if required_range.byte_length() == 0 {
        return Err(CommonProofRuntimeError::InvalidLimits);
    }
    let first_chunk_index = required_range.offset() / MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH;
    let final_offset = required_range
        .offset()
        .checked_add(required_range.byte_length() - 1)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let final_chunk_index = final_offset / MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH;
    if final_chunk_index > first_chunk_index.saturating_add(1) {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    Ok((
        first_chunk_index,
        (final_chunk_index != first_chunk_index).then_some(final_chunk_index),
    ))
}

/// Process-local ownership registry between accepted suite/setup/board inputs
/// and the common verifier. Upstream owners mint tree and evaluator handles
/// from their non-constructible verified values. Verification consumes the
/// exact application and all supplied handles atomically after a complete
/// coordinate check; a mismatch leaves every capability live for its owner.
pub(crate) struct CommonProofUpstreamInputRegistry {
    next_suite_handle: u32,
    next_application_handle: u32,
    next_preverification_application_source_handle: u32,
    next_statement_tree_handle: u32,
    next_evaluator_root_handle: u32,
    next_verified_column_evaluator_handle: u32,
    suites: BTreeMap<u32, CommonProofSelectedSuiteEntry>,
    applications: BTreeMap<u32, CommonProofApplicationInputEntry>,
    preverification_application_sources:
        BTreeMap<u32, CommonProofPreverificationApplicationSourceEntry>,
    statement_trees: BTreeMap<u32, CommonProofStatementTreeEntry>,
    evaluator_roots: BTreeMap<u32, CommonProofEvaluatorAuxiliaryRootEntry>,
    verified_column_evaluators: BTreeMap<u32, CommonProofVerifiedColumnEvaluatorEntry>,
}

impl Default for CommonProofUpstreamInputRegistry {
    fn default() -> Self {
        Self {
            next_suite_handle: 1,
            next_application_handle: 1,
            next_preverification_application_source_handle: 1,
            next_statement_tree_handle: 1,
            next_evaluator_root_handle: 1,
            next_verified_column_evaluator_handle: 1,
            suites: BTreeMap::new(),
            applications: BTreeMap::new(),
            preverification_application_sources: BTreeMap::new(),
            statement_trees: BTreeMap::new(),
            evaluator_roots: BTreeMap::new(),
            verified_column_evaluators: BTreeMap::new(),
        }
    }
}

impl CommonProofUpstreamInputRegistry {
    pub(crate) fn install_suite(
        &mut self,
        capability: SelectedSuiteCapability,
    ) -> Result<CommonProofSelectedSuiteCapabilityHandle, CommonProofRuntimeError> {
        let handle = take_nonrepeating_handle(&mut self.next_suite_handle)?;
        self.suites
            .insert(handle, CommonProofSelectedSuiteEntry { capability });
        Ok(CommonProofSelectedSuiteCapabilityHandle(handle))
    }

    pub(crate) fn release_suite(&mut self, handle: u32) -> Result<(), CommonProofRuntimeError> {
        self.suites
            .remove(&handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn install_preverification_application_source(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        board_source: &VerifiedBoardApplicationSource,
        statement_source: &VerifiedCommonProofStatementSource,
    ) -> Result<CommonProofPreverificationApplicationSourceHandle, CommonProofRuntimeError> {
        let suite = self
            .suites
            .get(&suite_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let proof_application_binding = statement_source.proof_application_binding();
        let application_slot = proof_application_binding.application_slot();
        let statement_schema_identifier =
            application_slot.application_statement_schema_identifier();
        let canonical_application_statement_bytes =
            statement_source.canonical_application_statement_bytes();
        let expected_statement_hash = verified_application_statement_hash(
            suite.capability.protocol_version(),
            suite.capability.suite_identifier(),
            statement_schema_identifier,
            canonical_application_statement_bytes,
        );
        let proof_stream_descriptor = proof_application_binding.proof_stream_descriptor();
        let proof_byte_length = usize::try_from(proof_stream_descriptor.total_byte_length)
            .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
        let producer_coordinates_match = application_slot.roster_position()
            == board_source.producer_roster_position()
            && application_slot
                .producer_sequence()
                .is_none_or(|sequence| sequence == board_source.producer_sequence());
        if canonical_application_statement_bytes.is_empty()
            || canonical_application_statement_bytes.len()
                > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || proof_byte_length == 0
            || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || application_slot.suite_identifier().into_bytes()
                != suite.capability.suite_identifier()
            || board_source.suite_identifier().into_bytes() != suite.capability.suite_identifier()
            || application_slot.ceremony_context_hash() != board_source.ceremony_context_hash()
            || application_slot.action_context_hash() != board_source.action_context_hash()
            || !producer_coordinates_match
            || board_source.object_hash() != statement_source.board_object_hash()
            || expected_statement_hash != statement_source.application_statement_hash().into_bytes()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        // The fixed candidate's exact-family plans currently exceed the hard
        // per-proof and per-action browser limits. Structural suite binding is
        // therefore not promoted into an exact-family application capability.
        // The generic runtime remains available to separately installed,
        // checked relation-plan capabilities in tests and later integration.
        Err(CommonProofRuntimeError::InvalidPlanCapability)
    }

    /// Consumes one board-bound source and promotes it into the sole
    /// application capability that exact-family tree/root adapters may use.
    /// No caller-provided binding, plan, descriptor, or digest enters this
    /// transition.
    pub(crate) fn promote_preverification_application_source(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        application_source_handle: &CommonProofPreverificationApplicationSourceHandle,
    ) -> Result<CommonProofApplicationInputCapabilityHandle, CommonProofRuntimeError> {
        let suite = self
            .suites
            .get(&suite_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let source = self
            .preverification_application_sources
            .get(&application_source_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let proof_application_binding = &source.proof_application_binding;
        let application_slot = proof_application_binding.application_slot();
        if source.board_source.suite_identifier().into_bytes()
            != suite.capability.suite_identifier()
            || application_slot.suite_identifier().into_bytes()
                != suite.capability.suite_identifier()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let canonical_binding_bytes = proof_application_binding
            .encode()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let canonical_binding_hash = hash_framed_parts_512(
            CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
            &[&canonical_binding_bytes],
        );
        let statement_schema_identifier =
            application_slot.application_statement_schema_identifier();
        let proof_stream_domain = common_proof_stream_domain(statement_schema_identifier)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let selected_variant = source
            .relation_plan
            .relation_plan
            .select_variant(
                source.relation_plan.schedule_position,
                source.relation_plan.top_count,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        let proof_query_count = selected_variant
            .common_proof_transcript_schedule(&source.relation_plan.relation_context)
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?
            .unique_query_count();
        let proof_stream_descriptor = proof_application_binding.proof_stream_descriptor();
        let application_binding = CommonProofApplicationBinding::new(
            application_slot
                .hash()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
                .into_bytes(),
            canonical_binding_hash,
            statement_schema_identifier,
            proof_application_binding.proof_header_hash().into_bytes(),
            proof_stream_domain,
            proof_stream_descriptor.full_object_digest.into_bytes(),
            proof_stream_descriptor.total_byte_length,
            proof_query_count,
        )?;
        let verification_binding = CommonProofVerificationBinding::new(
            suite.capability.suite_identifier(),
            source.board_source.ceremony_context_hash().into_bytes(),
            source.board_source.action_context_hash().into_bytes(),
            source.board_source.object_hash().into_bytes(),
            application_binding,
            source.relation_plan.relation_plan_hash(),
        );

        let handle = take_nonrepeating_handle(&mut self.next_application_handle)?;
        let source = self
            .preverification_application_sources
            .remove(&application_source_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.applications.insert(
            handle,
            CommonProofApplicationInputEntry {
                verification_binding,
                relation_plan: source.relation_plan,
                protocol_version: source.protocol_version,
                canonical_application_statement_bytes: source.canonical_application_statement_bytes,
                proof_stream_descriptor: source
                    .proof_application_binding
                    .proof_stream_descriptor()
                    .clone(),
                limits: source.limits,
            },
        );
        Ok(CommonProofApplicationInputCapabilityHandle(handle))
    }

    pub(crate) fn release_preverification_application_source(
        &mut self,
        application_source_handle: &CommonProofPreverificationApplicationSourceHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.preverification_application_sources
            .remove(&application_source_handle.0)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn mint_statement_tree(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        tree: VerifiedStatementOwnedTree,
    ) -> Result<CommonProofStatementTreeCapabilityHandle, CommonProofRuntimeError> {
        self.applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let handle = take_nonrepeating_handle(&mut self.next_statement_tree_handle)?;
        self.statement_trees.insert(
            handle,
            CommonProofStatementTreeEntry {
                application_handle: application_handle.0,
                tree,
            },
        );
        Ok(CommonProofStatementTreeCapabilityHandle(handle))
    }

    pub(crate) fn mint_evaluator_auxiliary_root(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        root: VerifiedEvaluatorAuxiliaryRoot,
    ) -> Result<CommonProofEvaluatorAuxiliaryRootCapabilityHandle, CommonProofRuntimeError> {
        self.applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let handle = take_nonrepeating_handle(&mut self.next_evaluator_root_handle)?;
        self.evaluator_roots.insert(
            handle,
            CommonProofEvaluatorAuxiliaryRootEntry {
                application_handle: application_handle.0,
                root,
            },
        );
        Ok(CommonProofEvaluatorAuxiliaryRootCapabilityHandle(handle))
    }

    /// Retains the exact-family evaluator for plan-owned verifier-sequence
    /// columns. Families with no such columns must not install one.
    pub(crate) fn mint_verified_column_evaluator(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    ) -> Result<CommonProofVerifiedColumnEvaluatorCapabilityHandle, CommonProofRuntimeError> {
        self.applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if self
            .verified_column_evaluators
            .values()
            .any(|entry| entry.application_handle == application_handle.0)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let handle = take_nonrepeating_handle(&mut self.next_verified_column_evaluator_handle)?;
        self.verified_column_evaluators.insert(
            handle,
            CommonProofVerifiedColumnEvaluatorEntry {
                application_handle: application_handle.0,
                evaluator,
            },
        );
        Ok(CommonProofVerifiedColumnEvaluatorCapabilityHandle(handle))
    }

    pub(crate) fn consume_verification_inputs(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        statement_tree_handles: &[&CommonProofStatementTreeCapabilityHandle],
        evaluator_root_handles: &[&CommonProofEvaluatorAuxiliaryRootCapabilityHandle],
        verified_column_evaluator_handle: Option<
            &CommonProofVerifiedColumnEvaluatorCapabilityHandle,
        >,
    ) -> Result<ConsumedCommonProofVerificationInputs, CommonProofRuntimeError> {
        let application = self
            .applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let mut unique_statement_tree_handles = BTreeSet::new();
        for handle in statement_tree_handles {
            if !unique_statement_tree_handles.insert(handle.0) {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let entry = self
                .statement_trees
                .get(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
            if entry.application_handle != application_handle.0 {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
        }
        let mut unique_evaluator_root_handles = BTreeSet::new();
        for handle in evaluator_root_handles {
            if !unique_evaluator_root_handles.insert(handle.0) {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let entry = self
                .evaluator_roots
                .get(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
            if entry.application_handle != application_handle.0 {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
        }
        let selected_variant = application
            .relation_plan
            .relation_plan
            .select_variant(
                application.relation_plan.schedule_position,
                application.relation_plan.top_count,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        let requires_verified_column_evaluator =
            selected_variant.ordered_columns().iter().any(|column| {
                matches!(
                    column.origin(),
                    RelationColumnOrigin::VerifierSequence { .. }
                )
            });
        if requires_verified_column_evaluator != verified_column_evaluator_handle.is_some() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        if let Some(handle) = verified_column_evaluator_handle {
            let entry = self
                .verified_column_evaluators
                .get(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
            if entry.application_handle != application_handle.0 {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
        }

        let statement_owned_trees = statement_tree_handles
            .iter()
            .map(|handle| {
                self.statement_trees
                    .get(&handle.0)
                    .map(|entry| entry.tree.clone())
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let evaluator_auxiliary_roots = evaluator_root_handles
            .iter()
            .map(|handle| {
                self.evaluator_roots
                    .get(&handle.0)
                    .map(|entry| entry.root)
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let validation_state =
            CommonProofVerificationStateMachine::new(PollableCommonProofVerificationInput {
                protocol_version: application.protocol_version,
                suite_identifier: application.verification_binding.suite_identifier,
                canonical_application_statement_bytes: &application
                    .canonical_application_statement_bytes,
                relation_plan: &application.relation_plan.relation_plan,
                relation_context: &application.relation_plan.relation_context,
                schedule_position: application.relation_plan.schedule_position,
                top_count: application.relation_plan.top_count,
                statement_owned_trees: &statement_owned_trees,
                evaluator_auxiliary_roots: &evaluator_auxiliary_roots,
                declared_proof_byte_length: application.limits.proof_byte_length(),
                proof_byte_ceiling: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
                maximum_resident_window_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
                    .checked_mul(MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS)
                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?,
            })
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        drop(validation_state);

        let application = self
            .applications
            .remove(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        for handle in statement_tree_handles {
            self.statement_trees
                .remove(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        }
        for handle in evaluator_root_handles {
            self.evaluator_roots
                .remove(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        }
        let verified_column_evaluator = match verified_column_evaluator_handle {
            Some(handle) => {
                self.verified_column_evaluators
                    .remove(&handle.0)
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
                    .evaluator
            }
            None => Box::new(RefusingVerifiedColumnEvaluator),
        };
        Ok(ConsumedCommonProofVerificationInputs {
            verification_binding: application.verification_binding,
            relation_plan: application.relation_plan,
            protocol_version: application.protocol_version,
            canonical_application_statement_bytes: application
                .canonical_application_statement_bytes,
            proof_stream_descriptor: application.proof_stream_descriptor,
            statement_owned_trees,
            evaluator_auxiliary_roots,
            verified_column_evaluator,
            limits: application.limits,
        })
    }

    pub(crate) fn cancel_application(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.applications
            .remove(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.statement_trees
            .retain(|_, entry| entry.application_handle != application_handle.0);
        self.evaluator_roots
            .retain(|_, entry| entry.application_handle != application_handle.0);
        self.verified_column_evaluators
            .retain(|_, entry| entry.application_handle != application_handle.0);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn install_test_application_fixture(
        &mut self,
        verification_binding: CommonProofVerificationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
        proof_stream_descriptor: StreamDescriptor,
        limits: CommonProofRuntimeLimits,
    ) -> Result<CommonProofApplicationInputCapabilityHandle, CommonProofRuntimeError> {
        if verification_binding.relation_plan_hash != relation_plan.relation_plan_hash()
            || canonical_application_statement_bytes.is_empty()
            || proof_stream_descriptor.total_byte_length
                != verification_binding.proof_application.proof_byte_length
            || proof_stream_descriptor.full_object_digest.into_bytes()
                != verification_binding
                    .proof_application
                    .proof_stream_full_object_digest
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let mut statement_bytes = Vec::new();
        statement_bytes
            .try_reserve_exact(canonical_application_statement_bytes.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        statement_bytes.extend_from_slice(canonical_application_statement_bytes);
        let handle = take_nonrepeating_handle(&mut self.next_application_handle)?;
        self.applications.insert(
            handle,
            CommonProofApplicationInputEntry {
                verification_binding,
                relation_plan,
                protocol_version,
                canonical_application_statement_bytes: statement_bytes,
                proof_stream_descriptor,
                limits,
            },
        );
        Ok(CommonProofApplicationInputCapabilityHandle(handle))
    }
}

/// Exact durable application reservation consumed by one proof attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofApplicationBinding {
    proof_application_slot_hash: [u8; HASH_BYTE_LENGTH],
    canonical_proof_application_binding_hash: [u8; HASH_BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    proof_header_hash: [u8; HASH_BYTE_LENGTH],
    proof_stream_domain: CanonicalStreamDomain,
    proof_stream_full_object_digest: [u8; HASH_BYTE_LENGTH],
    proof_byte_length: u64,
    proof_query_count: u32,
}

impl CommonProofApplicationBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_application_slot_hash: [u8; HASH_BYTE_LENGTH],
        canonical_proof_application_binding_hash: [u8; HASH_BYTE_LENGTH],
        application_statement_schema_identifier: u16,
        proof_header_hash: [u8; HASH_BYTE_LENGTH],
        proof_stream_domain: CanonicalStreamDomain,
        proof_stream_full_object_digest: [u8; HASH_BYTE_LENGTH],
        proof_byte_length: u64,
        proof_query_count: u32,
    ) -> Result<Self, CommonProofRuntimeError> {
        if application_statement_schema_identifier == 0
            || proof_byte_length == 0
            || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64
            || proof_query_count == 0
        {
            return Err(CommonProofRuntimeError::InvalidLimits);
        }
        Ok(Self {
            proof_application_slot_hash,
            canonical_proof_application_binding_hash,
            application_statement_schema_identifier,
            proof_header_hash,
            proof_stream_domain,
            proof_stream_full_object_digest,
            proof_byte_length,
            proof_query_count,
        })
    }

    fn binding_hash(self) -> [u8; HASH_BYTE_LENGTH] {
        hash_framed_parts_512(
            PROOF_APPLICATION_BINDING_HASH_DOMAIN,
            &[
                &self.proof_application_slot_hash,
                &self.canonical_proof_application_binding_hash,
                &self.application_statement_schema_identifier.to_le_bytes(),
                &self.proof_header_hash,
                &self.proof_stream_domain.canonical_code().to_le_bytes(),
                &self.proof_stream_full_object_digest,
                &self.proof_byte_length.to_le_bytes(),
                &self.proof_query_count.to_le_bytes(),
            ],
        )
    }
}

/// Verifier-owned context for one public proof application. Generation-only
/// randomness, attempt identifiers, and checkpoint continuation are
/// deliberately absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofVerificationBinding {
    suite_identifier: [u8; HASH_BYTE_LENGTH],
    ceremony_context_hash: [u8; HASH_BYTE_LENGTH],
    action_context_hash: [u8; HASH_BYTE_LENGTH],
    board_object_hash: [u8; HASH_BYTE_LENGTH],
    proof_application: CommonProofApplicationBinding,
    relation_plan_hash: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofVerificationBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        suite_identifier: [u8; HASH_BYTE_LENGTH],
        ceremony_context_hash: [u8; HASH_BYTE_LENGTH],
        action_context_hash: [u8; HASH_BYTE_LENGTH],
        board_object_hash: [u8; HASH_BYTE_LENGTH],
        proof_application: CommonProofApplicationBinding,
        relation_plan_hash: [u8; HASH_BYTE_LENGTH],
    ) -> Self {
        Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            board_object_hash,
            proof_application,
            relation_plan_hash,
        }
    }

    pub(crate) fn binding_hash(self) -> [u8; HASH_BYTE_LENGTH] {
        let proof_application_binding_hash = self.proof_application.binding_hash();
        hash_framed_parts_512(
            VERIFICATION_BINDING_HASH_DOMAIN,
            &[
                &self.suite_identifier,
                &self.ceremony_context_hash,
                &self.action_context_hash,
                &self.board_object_hash,
                &proof_application_binding_hash,
                &self.relation_plan_hash,
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofVerificationOperationHandle(u32);

impl CommonProofVerificationOperationHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofGenerationOperationHandle(u32);

impl CommonProofGenerationOperationHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GeneratedCommonProofCapabilityHandle(u32);

impl GeneratedCommonProofCapabilityHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VerifiedCommonProofCapabilityHandle(u32);

impl VerifiedCommonProofCapabilityHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PendingCommonProofAuthorizationHandle(u32);

impl PendingCommonProofAuthorizationHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofAuthenticatedLedgerHeadCapabilityHandle(u32);

impl CommonProofAuthenticatedLedgerHeadCapabilityHandle {
    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofAuthenticatedLedgerTransitionCapabilityHandle(u32);

impl CommonProofAuthenticatedLedgerTransitionCapabilityHandle {
    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

struct CommonProofOperationEntry {
    binding: CommonProofVerificationBinding,
    limits: CommonProofRuntimeLimits,
    cancellation_requested: bool,
    worker: Option<CommonProofVerificationWorker>,
}

struct CommonProofGenerationOperationEntry {
    worker: CommonProofGenerationWorker,
}

struct GeneratedCommonProofCapabilityEntry {
    proof: GeneratedCommonProof,
}

struct VerifiedCommonProofCapabilityEntry {
    binding: CommonProofVerificationBinding,
    proof: VerifiedCommonProof,
    verified_stream: VerifiedCanonicalStreamSummary,
}

/// One terminal verifier capability consumed for an exact protocol-family
/// adapter. The token is process local, cannot be cloned or constructed from
/// decoded proof bytes, and contains no caller-supplied family verdict.
///
/// A family adapter may inspect the verifier-derived binding facts below and
/// then move this token into its own one-shot authority registry. Merely
/// copying any returned hash or scalar cannot recreate the consumed authority.
pub(crate) struct ConsumedVerifiedCommonProofCapability {
    entry: VerifiedCommonProofCapabilityEntry,
}

impl ConsumedVerifiedCommonProofCapability {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.entry.proof.protocol_version()
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.proof.suite_identifier()
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.binding.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.binding.action_context_hash
    }

    pub(crate) const fn board_object_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.binding.board_object_hash
    }

    pub(crate) fn verification_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.binding.binding_hash()
    }

    pub(crate) const fn proof_application_slot_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry
            .binding
            .proof_application
            .proof_application_slot_hash
    }

    pub(crate) const fn canonical_proof_application_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry
            .binding
            .proof_application
            .canonical_proof_application_binding_hash
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.entry.proof.application_statement_schema_identifier()
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.proof.application_statement_hash()
    }

    pub(crate) const fn proof_header_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.proof.proof_header_hash()
    }

    pub(crate) const fn proof_stream_domain(&self) -> CanonicalStreamDomain {
        self.entry.verified_stream.stream_domain()
    }

    pub(crate) const fn proof_stream_full_object_digest(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.verified_stream.full_object_digest().into_bytes()
    }

    pub(crate) const fn proof_byte_length(&self) -> u64 {
        self.entry.proof.proof_byte_length()
    }

    pub(crate) const fn verified_query_count(&self) -> u32 {
        self.entry.proof.verified_query_count()
    }

    pub(crate) const fn relation_plan_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.binding.relation_plan_hash
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.entry.proof.relation_plan_variant_hash()
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.entry.proof.schedule_position()
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.entry.proof.top_count()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommonProofAuthenticatedLedgerHead {
    local_storage_binding: LocalStorageBinding,
    storage_root_commitment: Hash512,
    namespace_sequence: u64,
    authenticated_head_digest: Hash512,
    storage_instance_identity: Hash512,
}

impl CommonProofAuthenticatedLedgerHead {
    const fn from_browser_worker_source(
        source: &BrowserWorkerAuthenticatedStorageHeadSource,
    ) -> Self {
        Self {
            local_storage_binding: source.local_storage_binding(),
            storage_root_commitment: source.storage_root_commitment(),
            namespace_sequence: source.namespace_sequence(),
            authenticated_head_digest: source.authenticated_head_digest(),
            storage_instance_identity: source.storage_instance_identity(),
        }
    }
}

struct CommonProofAuthenticatedLedgerHeadCapabilityEntry {
    terminal_capability_handle: u32,
    authenticated_head: CommonProofAuthenticatedLedgerHead,
}

struct CommonProofAuthenticatedLedgerTransitionCapabilityEntry {
    pending_authorization_handle: u32,
}

struct PendingCommonProofAuthorizationEntry {
    predecessor_authenticated_storage_head: CommonProofAuthenticatedLedgerHead,
    durable_authorization_frame_digest: [u8; HASH_BYTE_LENGTH],
    original_capability_handle: VerifiedCommonProofCapabilityHandle,
    verified_capability: VerifiedCommonProofCapabilityEntry,
}

/// Output-only durable verified facts for one pending ledger application.
///
/// The frame may be persisted and compared byte-for-byte for exact recovery,
/// but it is never decoded as proof authority. The corresponding terminal
/// verifier capability remains exclusively in the registry behind the pending
/// handle until confirmation or abort.
pub(crate) struct PreparedCommonProofAuthorization {
    pending_handle: PendingCommonProofAuthorizationHandle,
    durable_authorization_frame: Box<[u8; DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH]>,
    durable_authorization_frame_digest: [u8; HASH_BYTE_LENGTH],
    proof_application_slot_hash: [u8; HASH_BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    proof_byte_length: u64,
    verified_query_count: u32,
}

impl PreparedCommonProofAuthorization {
    pub(crate) const fn pending_handle(&self) -> &PendingCommonProofAuthorizationHandle {
        &self.pending_handle
    }

    pub(crate) fn durable_authorization_frame(&self) -> &[u8] {
        self.durable_authorization_frame.as_slice()
    }

    pub(crate) const fn durable_authorization_frame_digest(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.durable_authorization_frame_digest
    }

    pub(crate) const fn proof_application_slot_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.proof_application_slot_hash
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn proof_byte_length(&self) -> u64 {
        self.proof_byte_length
    }

    pub(crate) const fn verified_query_count(&self) -> u32 {
        self.verified_query_count
    }

    pub(crate) fn into_pending_handle(self) -> PendingCommonProofAuthorizationHandle {
        self.pending_handle
    }
}

/// Process-local operation and verified-proof registry. Numeric handles are
/// never serialized into checkpoints, and monotonically increasing allocation
/// makes every removed handle permanently stale for this worker instance.
pub(crate) struct CommonProofRuntimeRegistry {
    next_operation_handle: u32,
    next_generation_operation_handle: u32,
    next_verified_capability_handle: u32,
    next_generated_capability_handle: u32,
    next_authenticated_ledger_head_handle: u32,
    next_authenticated_ledger_transition_handle: u32,
    next_pending_authorization_handle: u32,
    operations: BTreeMap<CommonProofVerificationOperationHandle, CommonProofOperationEntry>,
    generation_operations:
        BTreeMap<CommonProofGenerationOperationHandle, CommonProofGenerationOperationEntry>,
    verified_capabilities:
        BTreeMap<VerifiedCommonProofCapabilityHandle, VerifiedCommonProofCapabilityEntry>,
    generated_capabilities:
        BTreeMap<GeneratedCommonProofCapabilityHandle, GeneratedCommonProofCapabilityEntry>,
    authenticated_ledger_heads: BTreeMap<
        CommonProofAuthenticatedLedgerHeadCapabilityHandle,
        CommonProofAuthenticatedLedgerHeadCapabilityEntry,
    >,
    authenticated_ledger_transitions: BTreeMap<
        CommonProofAuthenticatedLedgerTransitionCapabilityHandle,
        CommonProofAuthenticatedLedgerTransitionCapabilityEntry,
    >,
    pending_authorizations:
        BTreeMap<PendingCommonProofAuthorizationHandle, PendingCommonProofAuthorizationEntry>,
}

impl Default for CommonProofRuntimeRegistry {
    fn default() -> Self {
        Self {
            next_operation_handle: 1,
            next_generation_operation_handle: 1,
            next_verified_capability_handle: 1,
            next_generated_capability_handle: 1,
            next_authenticated_ledger_head_handle: 1,
            next_authenticated_ledger_transition_handle: 1,
            next_pending_authorization_handle: 1,
            operations: BTreeMap::new(),
            generation_operations: BTreeMap::new(),
            verified_capabilities: BTreeMap::new(),
            generated_capabilities: BTreeMap::new(),
            authenticated_ledger_heads: BTreeMap::new(),
            authenticated_ledger_transitions: BTreeMap::new(),
            pending_authorizations: BTreeMap::new(),
        }
    }
}

impl CommonProofRuntimeRegistry {
    pub(crate) fn begin_owned_generation(
        &mut self,
        prepared: PreparedCommonProofGeneration,
    ) -> Result<CommonProofGenerationOperationHandle, CommonProofGenerationWorkerError> {
        let worker = CommonProofGenerationWorker::new(prepared)?;
        let handle = CommonProofGenerationOperationHandle(take_nonrepeating_handle(
            &mut self.next_generation_operation_handle,
        )?);
        self.generation_operations
            .insert(handle, CommonProofGenerationOperationEntry { worker });
        Ok(handle)
    }

    pub(crate) fn resume_owned_generation(
        &mut self,
        prepared: PreparedCommonProofGeneration,
        authenticated_checkpoint_state: &[u8],
    ) -> Result<CommonProofGenerationOperationHandle, CommonProofGenerationWorkerError> {
        let worker = CommonProofGenerationWorker::resume(prepared, authenticated_checkpoint_state)?;
        let handle = CommonProofGenerationOperationHandle(take_nonrepeating_handle(
            &mut self.next_generation_operation_handle,
        )?);
        self.generation_operations
            .insert(handle, CommonProofGenerationOperationEntry { worker });
        Ok(handle)
    }

    pub(crate) fn poll_owned_generation(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<CommonProofGenerationWorkerPoll, CommonProofGenerationWorkerError> {
        self.generation_operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .poll()
    }

    pub(crate) fn generation_storage_request(
        &self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<&[u8], CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_storage_request()
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)
    }

    pub(crate) fn generation_checkpoint_state(
        &self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<&[u8], CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_checkpoint()
            .map(PendingCommonProofGenerationCheckpoint::encoded_state)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    pub(crate) fn generation_checkpoint_safe_boundary_ordinal(
        &self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<u32, CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_checkpoint()
            .map(PendingCommonProofGenerationCheckpoint::safe_boundary_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    pub(crate) fn generation_checkpoint_cursor_count(
        &self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<usize, CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_checkpoint()
            .map(|checkpoint| checkpoint.ordered_cursor_bytes().len())
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    pub(crate) fn generation_checkpoint_cursor(
        &self,
        handle: CommonProofGenerationOperationHandle,
        cursor_index: usize,
    ) -> Result<&[u8], CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_checkpoint()
            .and_then(|checkpoint| checkpoint.ordered_cursor_bytes().get(cursor_index))
            .map(Vec::as_slice)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    pub(crate) fn generation_checkpoint_stable_attempt_binding_hash(
        &self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<[u8; HASH_BYTE_LENGTH], CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_checkpoint()
            .map(|checkpoint| checkpoint.state.stable_attempt_binding_hash)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    pub(crate) fn acknowledge_generation_checkpoint(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.generation_operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .advance_pending_checkpoint()
    }

    pub(crate) fn discard_generation_checkpoint(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.acknowledge_generation_checkpoint(handle)
    }

    #[cfg(test)]
    pub(crate) fn generation_storage_transaction_request(
        &self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<&ProofExternalMemoryTransactionRequest, CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_storage_transaction_request()
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)
    }

    pub(crate) fn supply_generation_storage_response(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
        encoded_response: &[u8],
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.generation_operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .supply_storage_response(encoded_response)
    }

    pub(crate) fn generation_output_chunk(
        &self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<(usize, &[u8]), CommonProofRuntimeError> {
        self.generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .pending_output_chunk()
            .ok_or(CommonProofRuntimeError::OutputChunkNotReady)
    }

    pub(crate) fn acknowledge_generation_output_chunk(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.generation_operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .acknowledge_output_chunk()
    }

    pub(crate) fn confirm_generation_output_readback(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
        chunk_index: usize,
        readback_bytes: &[u8],
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.generation_operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .confirm_output_readback(chunk_index, readback_bytes)
    }

    pub(crate) fn request_generation_cancellation(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.generation_operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .worker
            .request_cancellation();
        Ok(())
    }

    pub(crate) fn release_cancelled_generation(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        let operation = self
            .generation_operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if !operation.worker.cancellation_complete {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.generation_operations.remove(&handle);
        Ok(())
    }

    /// Permanently retires local generation authority after the browser owner
    /// can no longer continue the exact storage or output transaction.
    ///
    /// This deliberately does not claim that externally committed scratch or
    /// output bytes were cleaned up. Their authenticated browser owner must
    /// retire that failed attempt as a separate durable operation.
    pub(crate) fn retire_failed_generation(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.generation_operations
            .remove(&handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn finish_owned_generation(
        &mut self,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<GeneratedCommonProofCapabilityHandle, CommonProofGenerationWorkerError> {
        let operation = self
            .generation_operations
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let proof = operation.worker.finish()?;
        let capability_identifier =
            take_nonrepeating_handle(&mut self.next_generated_capability_handle)?;
        self.generated_capabilities.insert(
            GeneratedCommonProofCapabilityHandle(capability_identifier),
            GeneratedCommonProofCapabilityEntry { proof },
        );
        Ok(GeneratedCommonProofCapabilityHandle(capability_identifier))
    }

    pub(crate) fn release_generated_proof(
        &mut self,
        handle: GeneratedCommonProofCapabilityHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.generated_capabilities
            .remove(&handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn begin_owned_verification(
        &mut self,
        prepared: PreparedCommonProofVerification,
    ) -> Result<CommonProofVerificationOperationHandle, CommonProofVerificationWorkerError> {
        let worker = CommonProofVerificationWorker::new(prepared)?;
        let handle = CommonProofVerificationOperationHandle(take_nonrepeating_handle(
            &mut self.next_operation_handle,
        )?);
        self.operations.insert(
            handle,
            CommonProofOperationEntry {
                binding: worker.verification_binding,
                limits: worker.limits,
                cancellation_requested: false,
                worker: Some(worker),
            },
        );
        Ok(handle)
    }

    #[cfg(test)]
    pub(crate) fn begin_verification(
        &mut self,
        binding: CommonProofVerificationBinding,
        relation_plan: &CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<CommonProofVerificationOperationHandle, CommonProofRuntimeError> {
        if binding.relation_plan_hash != relation_plan.relation_plan_hash() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let handle = CommonProofVerificationOperationHandle(take_nonrepeating_handle(
            &mut self.next_operation_handle,
        )?);
        self.operations.insert(
            handle,
            CommonProofOperationEntry {
                binding,
                limits,
                cancellation_requested: false,
                worker: None,
            },
        );
        Ok(handle)
    }

    pub(crate) fn absorb_verification_input_chunk(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let operation = self
            .operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if operation.cancellation_requested {
            return Err(CommonProofRuntimeError::CancellationRequested.into());
        }
        operation
            .worker
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .absorb_input_chunk(chunk_index, chunk_bytes)
    }

    pub(crate) fn finish_verification_input(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let operation = self
            .operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if operation.cancellation_requested {
            return Err(CommonProofRuntimeError::CancellationRequested.into());
        }
        operation
            .worker
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .finish_input()
    }

    pub(crate) fn poll_owned_verification(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<CommonProofVerificationWorkerPoll, CommonProofVerificationWorkerError> {
        let operation = self
            .operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if operation.cancellation_requested {
            if let Some(worker) = operation.worker.as_mut() {
                worker.cancel();
            }
            return Err(CommonProofRuntimeError::CancellationRequested.into());
        }
        operation
            .worker
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .poll()
    }

    pub(crate) fn supply_verification_readback_chunk(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let operation = self
            .operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if operation.cancellation_requested {
            return Err(CommonProofRuntimeError::CancellationRequested.into());
        }
        operation
            .worker
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .supply_readback_chunk(chunk_index, chunk_bytes)
    }

    pub(crate) fn finish_owned_verification(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<VerifiedCommonProofCapabilityHandle, CommonProofVerificationWorkerError> {
        let worker = {
            let operation = self
                .operations
                .get_mut(&handle)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
            if operation.cancellation_requested {
                return Err(CommonProofRuntimeError::CancellationRequested.into());
            }
            operation
                .worker
                .take()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
        };
        let (_binding, relation_plan, proof, verified_stream) = match worker.finish() {
            Ok(terminal) => terminal,
            Err(error) => {
                self.operations.remove(&handle);
                return Err(error);
            }
        };
        match self.register_verified_proof(handle, &relation_plan, proof, verified_stream) {
            Ok(capability_handle) => Ok(capability_handle),
            Err(error) => {
                self.operations.remove(&handle);
                Err(CommonProofVerificationWorkerError::Runtime(error))
            }
        }
    }

    pub(crate) fn request_cancellation(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        let operation = self
            .operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        operation.cancellation_requested = true;
        if let Some(worker) = operation.worker.as_mut() {
            worker.cancel();
        }
        Ok(())
    }

    pub(crate) fn cancellation(
        &self,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<CommonProofRuntimeCancellation, CommonProofRuntimeError> {
        let operation = self
            .operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        Ok(CommonProofRuntimeCancellation {
            cancellation_requested: operation.cancellation_requested,
        })
    }

    pub(crate) fn cancel_operation(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        let mut operation = self
            .operations
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if let Some(worker) = operation.worker.as_mut() {
            worker.cancel();
        }
        Ok(())
    }

    /// Converts the verifier's terminal, non-constructible token into a
    /// process-local capability. Decoded bytes, hashes, and caller-supplied
    /// verdicts cannot enter this registry.
    pub(crate) fn register_verified_proof(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
        relation_plan: &CommonProofRelationPlanCapability,
        proof: VerifiedCommonProof,
        verified_stream: VerifiedCanonicalStreamSummary,
    ) -> Result<VerifiedCommonProofCapabilityHandle, CommonProofRuntimeError> {
        let operation = self.active_operation(handle)?;
        let proof_application = operation.binding.proof_application;
        if operation.cancellation_requested {
            return Err(CommonProofRuntimeError::CancellationRequested);
        }
        if operation.binding.relation_plan_hash != relation_plan.relation_plan_hash()
            || operation.binding.suite_identifier != proof.suite_identifier()
            || proof_application.application_statement_schema_identifier
                != proof.application_statement_schema_identifier()
            || proof_application.proof_header_hash != proof.proof_header_hash()
            || proof_application.proof_stream_domain != verified_stream.stream_domain()
            || proof_application.proof_stream_full_object_digest
                != verified_stream.full_object_digest().into_bytes()
            || proof_application.proof_byte_length != verified_stream.total_byte_length()
            || proof_application.proof_byte_length != proof.proof_byte_length()
            || usize::try_from(proof_application.proof_byte_length).ok()
                != Some(operation.limits.proof_byte_length())
            || proof_application.proof_query_count != proof.verified_query_count()
            || proof.relation_plan_variant_hash() != relation_plan.relation_plan_variant_hash()
            || proof.schedule_position() != relation_plan.schedule_position
            || proof.top_count() != relation_plan.top_count
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let binding = operation.binding;
        let capability_identifier =
            take_nonrepeating_handle(&mut self.next_verified_capability_handle)?;
        self.operations.remove(&handle);
        self.verified_capabilities.insert(
            VerifiedCommonProofCapabilityHandle(capability_identifier),
            VerifiedCommonProofCapabilityEntry {
                binding,
                proof,
                verified_stream,
            },
        );
        Ok(VerifiedCommonProofCapabilityHandle(capability_identifier))
    }

    /// Permanently retires one terminal verifier handle and transfers its
    /// non-serializable authority to an exact protocol-family adapter.
    /// Decoded bytes, hashes, family labels, and caller verdicts cannot enter
    /// this transfer.
    pub(crate) fn consume_verified_proof_for_protocol(
        &mut self,
        handle: &VerifiedCommonProofCapabilityHandle,
    ) -> Result<ConsumedVerifiedCommonProofCapability, CommonProofRuntimeError> {
        let entry = self
            .verified_capabilities
            .remove(handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.authenticated_ledger_heads
            .retain(|_, head| head.terminal_capability_handle != handle.0);
        Ok(ConsumedVerifiedCommonProofCapability { entry })
    }

    /// Retains one authenticated browser-worker ledger head for the exact
    /// terminal verifier capability. The participant identity remains the
    /// local browser identity; it is deliberately not compared with the proof
    /// producer's identity.
    pub(crate) fn retain_authenticated_ledger_head(
        &mut self,
        terminal_capability_handle: &VerifiedCommonProofCapabilityHandle,
        source: &BrowserWorkerAuthenticatedStorageHeadSource,
    ) -> Result<CommonProofAuthenticatedLedgerHeadCapabilityHandle, CommonProofRuntimeError> {
        let verified_capability = self
            .verified_capabilities
            .get(terminal_capability_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let authenticated_head =
            CommonProofAuthenticatedLedgerHead::from_browser_worker_source(source);
        if !authenticated_head_matches_binding(authenticated_head, verified_capability.binding)
            || self
                .authenticated_ledger_heads
                .values()
                .any(|entry| entry.terminal_capability_handle == terminal_capability_handle.0)
        {
            return Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch);
        }
        let handle = CommonProofAuthenticatedLedgerHeadCapabilityHandle(take_nonrepeating_handle(
            &mut self.next_authenticated_ledger_head_handle,
        )?);
        self.authenticated_ledger_heads.insert(
            CommonProofAuthenticatedLedgerHeadCapabilityHandle(handle.0),
            CommonProofAuthenticatedLedgerHeadCapabilityEntry {
                terminal_capability_handle: terminal_capability_handle.0,
                authenticated_head,
            },
        );
        Ok(handle)
    }

    /// Joins a browser-worker authenticated head and prepares one durable
    /// application without leaving an orphaned head capability when the
    /// second step refuses.
    pub(crate) fn prepare_verified_proof_application_from_authenticated_head(
        &mut self,
        terminal_capability_handle: &VerifiedCommonProofCapabilityHandle,
        source: &BrowserWorkerAuthenticatedStorageHeadSource,
    ) -> Result<PreparedCommonProofAuthorization, CommonProofRuntimeError> {
        let predecessor_head_handle =
            self.retain_authenticated_ledger_head(terminal_capability_handle, source)?;
        match self.prepare_verified_proof_application(
            terminal_capability_handle,
            &predecessor_head_handle,
        ) {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                self.authenticated_ledger_heads
                    .remove(&predecessor_head_handle);
                Err(error)
            }
        }
    }

    /// Moves one terminal verifier capability and its authenticated predecessor
    /// head into a retained pending state. The returned frame contains only
    /// verifier-derived facts and is never decoded as proof authority.
    pub(crate) fn prepare_verified_proof_application(
        &mut self,
        handle: &VerifiedCommonProofCapabilityHandle,
        predecessor_head_handle: &CommonProofAuthenticatedLedgerHeadCapabilityHandle,
    ) -> Result<PreparedCommonProofAuthorization, CommonProofRuntimeError> {
        let predecessor_head = self
            .authenticated_ledger_heads
            .get(predecessor_head_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if predecessor_head.terminal_capability_handle != handle.0
            || !self.verified_capabilities.contains_key(handle)
        {
            return Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch);
        }
        let pending_identifier =
            take_nonrepeating_handle(&mut self.next_pending_authorization_handle)?;
        let original_capability_handle = VerifiedCommonProofCapabilityHandle(handle.0);
        let entry = self
            .verified_capabilities
            .remove(handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let predecessor_authenticated_storage_head = self
            .authenticated_ledger_heads
            .remove(predecessor_head_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .authenticated_head;
        let durable_authorization_frame = durable_authorization_frame(&entry);
        let durable_authorization_frame_digest =
            durable_authorization_frame_digest(durable_authorization_frame.as_slice());
        let prepared = PreparedCommonProofAuthorization {
            pending_handle: PendingCommonProofAuthorizationHandle(pending_identifier),
            durable_authorization_frame,
            durable_authorization_frame_digest,
            proof_application_slot_hash: entry
                .binding
                .proof_application
                .proof_application_slot_hash,
            application_statement_schema_identifier: entry
                .proof
                .application_statement_schema_identifier(),
            proof_byte_length: entry.proof.proof_byte_length(),
            verified_query_count: entry.proof.verified_query_count(),
        };
        self.pending_authorizations.insert(
            PendingCommonProofAuthorizationHandle(pending_identifier),
            PendingCommonProofAuthorizationEntry {
                predecessor_authenticated_storage_head,
                durable_authorization_frame_digest,
                original_capability_handle,
                verified_capability: entry,
            },
        );
        Ok(prepared)
    }

    /// Mints one exact transition capability from a freshly authenticated
    /// browser-worker head. A mismatch leaves the pending proof authority live.
    pub(crate) fn retain_authenticated_ledger_transition(
        &mut self,
        pending_handle: &PendingCommonProofAuthorizationHandle,
        source: &BrowserWorkerAuthenticatedStorageTransitionSource,
    ) -> Result<CommonProofAuthenticatedLedgerTransitionCapabilityHandle, CommonProofRuntimeError>
    {
        let pending = self
            .pending_authorizations
            .get(pending_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if !authenticated_transition_source_is_valid(
            pending.predecessor_authenticated_storage_head,
            pending.durable_authorization_frame_digest,
            source,
        ) || self
            .authenticated_ledger_transitions
            .values()
            .any(|entry| entry.pending_authorization_handle == pending_handle.0)
        {
            return Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch);
        }
        let handle = CommonProofAuthenticatedLedgerTransitionCapabilityHandle(
            take_nonrepeating_handle(&mut self.next_authenticated_ledger_transition_handle)?,
        );
        self.authenticated_ledger_transitions.insert(
            CommonProofAuthenticatedLedgerTransitionCapabilityHandle(handle.0),
            CommonProofAuthenticatedLedgerTransitionCapabilityEntry {
                pending_authorization_handle: pending_handle.0,
            },
        );
        Ok(handle)
    }

    /// Joins a browser-worker authenticated transition and confirms one
    /// pending application without retaining an orphaned transition handle if
    /// confirmation refuses.
    pub(crate) fn confirm_verified_proof_application_from_authenticated_transition(
        &mut self,
        pending_handle: &PendingCommonProofAuthorizationHandle,
        source: &BrowserWorkerAuthenticatedStorageTransitionSource,
    ) -> Result<(), CommonProofRuntimeError> {
        let transition_handle =
            self.retain_authenticated_ledger_transition(pending_handle, source)?;
        match self.confirm_verified_proof_application(pending_handle, &transition_handle) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.authenticated_ledger_transitions
                    .remove(&transition_handle);
                Err(error)
            }
        }
    }

    /// Consumes retained proof authority only after an exact transition
    /// capability was minted from the browser-owned authenticated store.
    pub(crate) fn confirm_verified_proof_application(
        &mut self,
        pending_handle: &PendingCommonProofAuthorizationHandle,
        transition_handle: &CommonProofAuthenticatedLedgerTransitionCapabilityHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.pending_authorizations
            .get(pending_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let transition = self
            .authenticated_ledger_transitions
            .get(transition_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if transition.pending_authorization_handle != pending_handle.0 {
            return Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch);
        }
        self.authenticated_ledger_transitions
            .remove(transition_handle);
        self.pending_authorizations.remove(pending_handle);
        Ok(())
    }

    /// Restores the exact terminal verifier capability after a failed or
    /// cancelled ledger transition. The pending handle is permanently stale.
    pub(crate) fn abort_verified_proof_application(
        &mut self,
        pending_handle: &PendingCommonProofAuthorizationHandle,
    ) -> Result<VerifiedCommonProofCapabilityHandle, CommonProofRuntimeError> {
        let original_capability_handle = &self
            .pending_authorizations
            .get(pending_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .original_capability_handle;
        if self
            .verified_capabilities
            .contains_key(original_capability_handle)
        {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        let pending = self
            .pending_authorizations
            .remove(pending_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.authenticated_ledger_transitions
            .retain(|_, transition| transition.pending_authorization_handle != pending_handle.0);
        let restored_identifier = pending.original_capability_handle.0;
        self.verified_capabilities.insert(
            pending.original_capability_handle,
            pending.verified_capability,
        );
        Ok(VerifiedCommonProofCapabilityHandle(restored_identifier))
    }

    fn active_operation(
        &self,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<&CommonProofOperationEntry, CommonProofRuntimeError> {
        let operation = self
            .operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        Ok(operation)
    }
}

fn authenticated_transition_source_is_valid(
    predecessor: CommonProofAuthenticatedLedgerHead,
    expected_record_digest: [u8; HASH_BYTE_LENGTH],
    source: &BrowserWorkerAuthenticatedStorageTransitionSource,
) -> bool {
    source.local_storage_binding() == predecessor.local_storage_binding
        && source.storage_root_commitment() == predecessor.storage_root_commitment
        && source.storage_instance_identity() == predecessor.storage_instance_identity
        && source.predecessor_namespace_sequence() == predecessor.namespace_sequence
        && source.predecessor_authenticated_head_digest() == predecessor.authenticated_head_digest
        && predecessor
            .namespace_sequence
            .checked_add(1)
            .is_some_and(|successor_sequence| {
                successor_sequence == source.successor_namespace_sequence()
            })
        && source.successor_authenticated_head_digest() != predecessor.authenticated_head_digest
        && source.authenticated_record_digest().into_bytes() == expected_record_digest
}

fn authenticated_head_matches_binding(
    authenticated_head: CommonProofAuthenticatedLedgerHead,
    proof_binding: CommonProofVerificationBinding,
) -> bool {
    let storage_binding = authenticated_head.local_storage_binding;
    storage_binding.suite_id().into_bytes() == proof_binding.suite_identifier
        && storage_binding.ceremony_context_hash().into_bytes()
            == proof_binding.ceremony_context_hash
        && storage_binding.action_context_hash().into_bytes() == proof_binding.action_context_hash
}

fn durable_authorization_frame(
    entry: &VerifiedCommonProofCapabilityEntry,
) -> Box<[u8; DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH]> {
    let mut frame = [0_u8; DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH];
    let mut cursor = 0_usize;
    append_authorization_frame_bytes(&mut frame, &mut cursor, &DURABLE_AUTHORIZATION_FRAME_MAGIC);
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &DURABLE_AUTHORIZATION_FRAME_VERSION.to_le_bytes(),
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &(DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH as u32).to_le_bytes(),
    );
    append_authorization_frame_bytes(&mut frame, &mut cursor, &entry.binding.suite_identifier);
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.binding.ceremony_context_hash,
    );
    append_authorization_frame_bytes(&mut frame, &mut cursor, &entry.binding.action_context_hash);
    append_authorization_frame_bytes(&mut frame, &mut cursor, &entry.binding.board_object_hash);
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.binding.proof_application.proof_application_slot_hash,
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry
            .binding
            .proof_application
            .canonical_proof_application_binding_hash,
    );
    append_authorization_frame_bytes(&mut frame, &mut cursor, &entry.binding.relation_plan_hash);
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.proof.protocol_version().to_le_bytes(),
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry
            .proof
            .application_statement_schema_identifier()
            .to_le_bytes(),
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.proof.application_statement_hash(),
    );
    append_authorization_frame_bytes(&mut frame, &mut cursor, &entry.proof.proof_header_hash());
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry
            .verified_stream
            .stream_domain()
            .canonical_code()
            .to_le_bytes(),
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.verified_stream.full_object_digest().into_bytes(),
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.proof.proof_byte_length().to_le_bytes(),
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.proof.verified_query_count().to_le_bytes(),
    );
    append_authorization_frame_bytes(
        &mut frame,
        &mut cursor,
        &entry.proof.relation_plan_variant_hash(),
    );
    let (schedule_position_tag, schedule_position) = entry
        .proof
        .schedule_position()
        .map_or((0_u8, 0_u32), |position| (1, position));
    append_authorization_frame_bytes(&mut frame, &mut cursor, &[schedule_position_tag]);
    append_authorization_frame_bytes(&mut frame, &mut cursor, &schedule_position.to_le_bytes());
    let (top_count_tag, top_count) = entry
        .proof
        .top_count()
        .map_or((0_u8, 0_u16), |count| (1, count));
    append_authorization_frame_bytes(&mut frame, &mut cursor, &[top_count_tag]);
    append_authorization_frame_bytes(&mut frame, &mut cursor, &top_count.to_le_bytes());
    assert_eq!(
        cursor, DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH,
        "the fixed common-proof durable authorization frame length changed",
    );
    Box::new(frame)
}

pub(crate) fn durable_authorization_frame_digest(
    durable_authorization_frame: &[u8],
) -> [u8; HASH_BYTE_LENGTH] {
    hash_framed_parts_512(
        DURABLE_AUTHORIZATION_RECORD_HASH_DOMAIN,
        &[durable_authorization_frame],
    )
}

fn append_authorization_frame_bytes(
    frame: &mut [u8; DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH],
    cursor: &mut usize,
    bytes: &[u8],
) {
    let end = *cursor + bytes.len();
    frame[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

const fn common_proof_stream_domain(
    application_statement_schema_identifier: u16,
) -> Option<CanonicalStreamDomain> {
    match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::DealerVssShareLinkageProof)
        }
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::RecipientAggregateThresholdShareProof)
        }
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::SameSecretProof)
        }
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::PublicKeyShareProof)
        }
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::CollectivePublicKeyAggregateProof)
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::RkgRoundOneProof)
        }
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::RkgRoundOneAggregateProof)
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::RkgRoundTwoProof)
        }
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::GaloisShareProof)
        }
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::EvaluatorKeyAggregateProof)
        }
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::BallotValidityProof)
        }
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(CanonicalStreamDomain::MaliciousTargetShareProof)
        }
        _ => None,
    }
}

fn take_nonrepeating_handle(next_handle: &mut u32) -> Result<u32, CommonProofRuntimeError> {
    if *next_handle == 0 {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    let handle = *next_handle;
    *next_handle = next_handle.checked_add(1).unwrap_or(0);
    Ok(handle)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofRuntimeCancellation {
    cancellation_requested: bool,
}

impl super::ProofCancellation for CommonProofRuntimeCancellation {
    fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }
}

/// One transaction pass of a pollable external-memory operation. Recording
/// yields an owned request. Supplying the browser's read results changes the
/// same object into an exact replay pass; the caller resets it only after the
/// cryptographic component reports that the transaction completed.
pub(crate) struct CommonProofStorageTransactionRuntime {
    pass: CommonProofStorageTransactionPass,
    runtime_binding_hash: [u8; HASH_BYTE_LENGTH],
    next_request_sequence: u64,
}

enum CommonProofStorageTransactionPass {
    Recording(ProofExternalMemoryTransactionRecorder),
    RequestReady(ProofExternalMemoryTransactionRequest),
    Replaying(ProofExternalMemoryTransactionReplay),
    Cancelled,
}

impl Default for CommonProofStorageTransactionRuntime {
    fn default() -> Self {
        Self::for_runtime_binding([0; HASH_BYTE_LENGTH])
    }
}

impl CommonProofStorageTransactionRuntime {
    pub(crate) fn for_runtime_binding(runtime_binding_hash: [u8; HASH_BYTE_LENGTH]) -> Self {
        Self {
            pass: CommonProofStorageTransactionPass::Recording(
                ProofExternalMemoryTransactionRecorder::for_runtime_binding(
                    runtime_binding_hash,
                    1,
                ),
            ),
            runtime_binding_hash,
            next_request_sequence: 1,
        }
    }

    pub(crate) fn storage(&mut self) -> &mut Self {
        self
    }

    /// Moves a recorder-yielded request into the host-visible pending state.
    /// Call this only after the component reports `StorageCommit(Yielded)`.
    pub(crate) fn capture_yielded_request(
        &mut self,
    ) -> Result<&ProofExternalMemoryTransactionRequest, CommonProofRuntimeError> {
        let CommonProofStorageTransactionPass::Recording(recorder) = &mut self.pass else {
            return Err(CommonProofRuntimeError::TransactionPending);
        };
        let request = recorder
            .take_yielded_request()
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)?;
        if request.request_sequence() != self.next_request_sequence {
            return Err(CommonProofRuntimeError::TransactionReplayIncomplete);
        }
        self.next_request_sequence = self
            .next_request_sequence
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.pass = CommonProofStorageTransactionPass::RequestReady(request);
        let CommonProofStorageTransactionPass::RequestReady(request) = &self.pass else {
            unreachable!("the request-ready state was just installed")
        };
        Ok(request)
    }

    pub(crate) fn pending_request(&self) -> Option<&ProofExternalMemoryTransactionRequest> {
        match &self.pass {
            CommonProofStorageTransactionPass::RequestReady(request) => Some(request),
            _ => None,
        }
    }

    pub(crate) fn replay_is_active(&self) -> bool {
        matches!(self.pass, CommonProofStorageTransactionPass::Replaying(_))
    }

    pub(crate) fn encode_pending_worker_request(&self) -> Result<Vec<u8>, CommonProofRuntimeError> {
        self.pending_request()
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)?
            .encode_worker_request()
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
    }

    pub(crate) fn supply_worker_response(
        &mut self,
        encoded_response: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let read_results = self
            .pending_request()
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)?
            .decode_worker_response(encoded_response)
            .map_err(|_| CommonProofRuntimeError::TransactionReplayIncomplete)?;
        self.supply_read_results(read_results)
    }

    pub(crate) fn supply_read_results(
        &mut self,
        read_results: Vec<Vec<u8>>,
    ) -> Result<(), CommonProofRuntimeError> {
        let previous = core::mem::replace(
            &mut self.pass,
            CommonProofStorageTransactionPass::Recording(
                ProofExternalMemoryTransactionRecorder::for_runtime_binding(
                    self.runtime_binding_hash,
                    self.next_request_sequence,
                ),
            ),
        );
        let CommonProofStorageTransactionPass::RequestReady(request) = previous else {
            self.pass = previous;
            return Err(CommonProofRuntimeError::TransactionResponseMissing);
        };
        match ProofExternalMemoryTransactionReplay::new(request, read_results) {
            Ok(replay) => {
                self.pass = CommonProofStorageTransactionPass::Replaying(replay);
                Ok(())
            }
            Err(_) => Err(CommonProofRuntimeError::TransactionReplayIncomplete),
        }
    }

    /// Releases replay bytes only after the resumed component advanced its own
    /// state. Calling this while a request is merely pending fails closed.
    pub(crate) fn transaction_completed(&mut self) -> Result<(), CommonProofRuntimeError> {
        if !matches!(
            &self.pass,
            CommonProofStorageTransactionPass::Replaying(replay)
                if replay.transaction_is_complete()
        ) {
            return Err(CommonProofRuntimeError::TransactionReplayIncomplete);
        }
        self.pass = CommonProofStorageTransactionPass::Recording(
            ProofExternalMemoryTransactionRecorder::for_runtime_binding(
                self.runtime_binding_hash,
                self.next_request_sequence,
            ),
        );
        Ok(())
    }

    pub(crate) fn cancel(&mut self) {
        self.pass = CommonProofStorageTransactionPass::Cancelled;
        self.next_request_sequence = 0;
    }
}

impl ProofExternalMemory for CommonProofStorageTransactionRuntime {
    type Error = ProofExternalMemoryTransactionAdapterError;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.begin_transaction(maximum_payload_byte_length, maximum_operation_count)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.begin_transaction(maximum_payload_byte_length, maximum_operation_count)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn create_object(
        &mut self,
        object: super::ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.create_object(object, protection, exact_byte_length)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.create_object(object, protection, exact_byte_length)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn append_object_bytes(
        &mut self,
        object: super::ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.append_object_bytes(object, expected_offset, bytes)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.append_object_bytes(object, expected_offset, bytes)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn seal_object(&mut self, object: super::ProofExternalMemoryObject) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.seal_object(object),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.seal_object(object),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn read_object_bytes(
        &mut self,
        object: super::ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.read_object_bytes(object, offset, destination)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.read_object_bytes(object, offset, destination)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn delete_object(
        &mut self,
        object: super::ProofExternalMemoryObject,
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.delete_object(object),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.delete_object(object),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.commit_transaction(),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.commit_transaction(),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.abort_transaction(),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.abort_transaction(),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PollableCommonProofByteSinkError {
    ChunkReady,
    ChunkAwaitingCommit,
    ChunkAwaitingReadback,
    ByteLengthExceeded,
    ReplayMismatch,
    AllocationLimitExceeded,
    CanonicalStream,
}

struct PendingOutputWrite {
    byte_length: usize,
    digest: [u8; HASH_BYTE_LENGTH],
    consumed_byte_length: usize,
}

/// Canonical proof output sink with one-chunk working memory. A write that
/// reaches a chunk boundary yields `ChunkReady`; after the browser transaction
/// acknowledges that exact chunk, retrying the exact same write continues at
/// the first unconsumed byte.
pub(crate) struct PollableCommonProofByteSink {
    declared_byte_length: usize,
    observed_byte_length: usize,
    next_chunk_index: usize,
    stream_writer: Option<CanonicalStreamWriter>,
    current_chunk: Zeroizing<Vec<u8>>,
    chunk_awaiting_commit: bool,
    chunk_awaiting_readback: bool,
    pending_write: Option<PendingOutputWrite>,
    terminal: bool,
}

impl PollableCommonProofByteSink {
    pub(crate) fn new(
        stream_domain: CanonicalStreamDomain,
        declared_byte_length: usize,
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        if declared_byte_length == 0 || declared_byte_length > limits.proof_byte_length() {
            return Err(CommonProofRuntimeError::OutputByteLengthExceeded);
        }
        let stream_writer = CanonicalStreamWriter::new(
            stream_domain,
            u64::try_from(declared_byte_length)
                .map_err(|_| CommonProofRuntimeError::OutputByteLengthExceeded)?,
        )
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
        Ok(Self {
            declared_byte_length,
            observed_byte_length: 0,
            next_chunk_index: 0,
            stream_writer: Some(stream_writer),
            current_chunk: Zeroizing::new(Vec::new()),
            chunk_awaiting_commit: false,
            chunk_awaiting_readback: false,
            pending_write: None,
            terminal: false,
        })
    }

    pub(crate) fn pending_chunk(&self) -> Option<(usize, &[u8])> {
        self.chunk_awaiting_commit
            .then_some((self.next_chunk_index, self.current_chunk.as_slice()))
    }

    pub(crate) const fn pending_readback_chunk_index(&self) -> Option<usize> {
        if self.chunk_awaiting_readback {
            Some(self.next_chunk_index)
        } else {
            None
        }
    }

    pub(crate) fn complete_output_is_authenticated(&self) -> bool {
        !self.chunk_awaiting_commit
            && !self.chunk_awaiting_readback
            && self.pending_write.is_none()
            && self.observed_byte_length == self.declared_byte_length
            && self.current_chunk.is_empty()
            && !self.terminal
    }

    pub(crate) fn final_partial_chunk_is_ready(&self) -> bool {
        !self.chunk_awaiting_commit
            && !self.chunk_awaiting_readback
            && self.pending_write.is_none()
            && self.observed_byte_length == self.declared_byte_length
            && !self.current_chunk.is_empty()
            && !self.terminal
    }

    pub(crate) fn acknowledge_pending_chunk(&mut self) -> Result<(), CommonProofRuntimeError> {
        if !self.chunk_awaiting_commit || self.current_chunk.is_empty() {
            return Err(CommonProofRuntimeError::OutputChunkNotReady);
        }
        self.chunk_awaiting_commit = false;
        self.chunk_awaiting_readback = true;
        Ok(())
    }

    /// Accepts only a complete reread of the exact staged chunk. The stream
    /// descriptor advances from these reread bytes, never from the producer's
    /// pre-commit buffer or a host acknowledgement alone.
    pub(crate) fn confirm_pending_chunk_readback(
        &mut self,
        chunk_index: usize,
        readback_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        if !self.chunk_awaiting_readback
            || chunk_index != self.next_chunk_index
            || readback_bytes != self.current_chunk.as_slice()
        {
            return Err(CommonProofRuntimeError::OutputWriteReplayMismatch);
        }
        self.stream_writer
            .as_mut()
            .ok_or(CommonProofRuntimeError::OutputChunkNotReady)?
            .absorb_chunk(self.next_chunk_index, readback_bytes)
            .map_err(|_| CommonProofRuntimeError::OutputWriteReplayMismatch)?;
        self.current_chunk.clear();
        self.chunk_awaiting_readback = false;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::OutputByteLengthExceeded)?;
        Ok(())
    }

    /// Makes a non-full final chunk visible for acknowledgement after the
    /// producer has supplied exactly the declared number of bytes.
    pub(crate) fn seal_final_chunk(&mut self) -> Result<(), CommonProofRuntimeError> {
        if self.chunk_awaiting_commit {
            return Err(CommonProofRuntimeError::OutputChunkAwaitingCommit);
        }
        if self.chunk_awaiting_readback {
            return Err(CommonProofRuntimeError::OutputChunkAwaitingReadback);
        }
        if self.observed_byte_length != self.declared_byte_length
            || self.current_chunk.is_empty()
            || self.pending_write.is_some()
        {
            return Err(CommonProofRuntimeError::OutputChunkNotReady);
        }
        self.chunk_awaiting_commit = true;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        if self.chunk_awaiting_commit
            || self.chunk_awaiting_readback
            || !self.current_chunk.is_empty()
            || self.pending_write.is_some()
            || self.observed_byte_length != self.declared_byte_length
            || self.terminal
        {
            return Err(CommonProofRuntimeError::OutputChunkNotReady);
        }
        self.terminal = true;
        self.stream_writer
            .take()
            .ok_or(CommonProofRuntimeError::OutputChunkNotReady)?
            .finish()
            .map_err(|_| CommonProofRuntimeError::OutputWriteReplayMismatch)
    }

    pub(crate) fn cancel(&mut self) {
        self.stream_writer = None;
        self.current_chunk = Zeroizing::new(Vec::new());
        self.chunk_awaiting_commit = false;
        self.chunk_awaiting_readback = false;
        self.pending_write = None;
        self.terminal = true;
    }

    fn expected_current_chunk_byte_length(
        &self,
    ) -> Result<usize, PollableCommonProofByteSinkError> {
        let remaining = self
            .declared_byte_length
            .checked_sub(
                self.next_chunk_index
                    .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                    .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?,
            )
            .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?;
        Ok(remaining.min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH))
    }
}

impl CommonProofByteSink for PollableCommonProofByteSink {
    type Error = PollableCommonProofByteSinkError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        if self.terminal {
            return Err(PollableCommonProofByteSinkError::ByteLengthExceeded);
        }
        if self.chunk_awaiting_commit {
            return Err(PollableCommonProofByteSinkError::ChunkAwaitingCommit);
        }
        if self.chunk_awaiting_readback {
            return Err(PollableCommonProofByteSinkError::ChunkAwaitingReadback);
        }
        if bytes.is_empty() {
            return self
                .pending_write
                .is_none()
                .then_some(())
                .ok_or(PollableCommonProofByteSinkError::ReplayMismatch);
        }
        if self.pending_write.is_none()
            && self
                .observed_byte_length
                .checked_add(bytes.len())
                .filter(|length| *length <= self.declared_byte_length)
                .is_none()
        {
            return Err(PollableCommonProofByteSinkError::ByteLengthExceeded);
        }
        let digest = hash_framed_parts_512(OUTPUT_WRITE_HASH_DOMAIN, &[bytes]);
        let mut consumed_byte_length = match &self.pending_write {
            Some(pending) if pending.byte_length == bytes.len() && pending.digest == digest => {
                pending.consumed_byte_length
            }
            Some(_) => return Err(PollableCommonProofByteSinkError::ReplayMismatch),
            None => 0,
        };
        if self.pending_write.is_none() {
            self.pending_write = Some(PendingOutputWrite {
                byte_length: bytes.len(),
                digest,
                consumed_byte_length: 0,
            });
        }
        while consumed_byte_length < bytes.len() {
            let expected_chunk_byte_length = self.expected_current_chunk_byte_length()?;
            let available = expected_chunk_byte_length
                .checked_sub(self.current_chunk.len())
                .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?;
            if available == 0 {
                self.chunk_awaiting_commit = true;
                return Err(PollableCommonProofByteSinkError::ChunkReady);
            }
            let copied_byte_length = available.min(bytes.len() - consumed_byte_length);
            let next_observed_byte_length = self
                .observed_byte_length
                .checked_add(copied_byte_length)
                .filter(|length| *length <= self.declared_byte_length)
                .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?;
            self.current_chunk
                .try_reserve_exact(copied_byte_length)
                .map_err(|_| PollableCommonProofByteSinkError::AllocationLimitExceeded)?;
            self.current_chunk.extend_from_slice(
                bytes
                    .get(consumed_byte_length..consumed_byte_length + copied_byte_length)
                    .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?,
            );
            consumed_byte_length += copied_byte_length;
            self.observed_byte_length = next_observed_byte_length;
            self.pending_write
                .as_mut()
                .ok_or(PollableCommonProofByteSinkError::ReplayMismatch)?
                .consumed_byte_length = consumed_byte_length;
            if self.current_chunk.len() == expected_chunk_byte_length {
                self.chunk_awaiting_commit = true;
                return Err(PollableCommonProofByteSinkError::ChunkReady);
            }
        }
        self.pending_write = None;
        Ok(())
    }
}

/// One already-authenticated canonical input chunk. The caller owns the
/// canonical-stream verifier and supplies at most two adjacent chunks around
/// the decoder's current position.
pub(crate) struct ResidentCommonProofInputChunk<'chunk> {
    offset: usize,
    bytes: &'chunk [u8],
}

impl<'chunk> ResidentCommonProofInputChunk<'chunk> {
    pub(crate) const fn new(offset: usize, bytes: &'chunk [u8]) -> Self {
        Self { offset, bytes }
    }
}

/// Read-only window used by `BoundedProofDecoder` and `verify_common_proof`.
/// Missing bytes report truncation; they are never replaced with zeroes or a
/// caller-supplied success marker.
pub(crate) struct ResidentCommonProofByteSource<'chunk> {
    declared_byte_length: usize,
    chunks: Vec<ResidentCommonProofInputChunk<'chunk>>,
}

impl<'chunk> ResidentCommonProofByteSource<'chunk> {
    pub(crate) fn new(
        declared_byte_length: usize,
        chunks: Vec<ResidentCommonProofInputChunk<'chunk>>,
    ) -> Result<Self, CommonProofRuntimeError> {
        if declared_byte_length == 0
            || declared_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || chunks.is_empty()
            || chunks.len() > MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS
        {
            return Err(CommonProofRuntimeError::InvalidLimits);
        }
        let mut previous_end = None;
        for chunk in &chunks {
            let end = chunk
                .offset
                .checked_add(chunk.bytes.len())
                .filter(|end| *end <= declared_byte_length)
                .ok_or(CommonProofRuntimeError::InvalidLimits)?;
            if chunk.bytes.is_empty()
                || chunk.bytes.len() > MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
                || previous_end.is_some_and(|previous| chunk.offset < previous)
            {
                return Err(CommonProofRuntimeError::InvalidLimits);
            }
            previous_end = Some(end);
        }
        Ok(Self {
            declared_byte_length,
            chunks,
        })
    }
}

impl super::ProofByteSource for ResidentCommonProofByteSource<'_> {
    fn byte_length(&self) -> usize {
        self.declared_byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if end > self.declared_byte_length {
            return false;
        }
        let mut destination_offset = 0_usize;
        let mut source_offset = offset;
        while destination_offset < destination.len() {
            let Some(chunk) = self.chunks.iter().find(|chunk| {
                source_offset >= chunk.offset
                    && source_offset < chunk.offset.saturating_add(chunk.bytes.len())
            }) else {
                return false;
            };
            let within_chunk_offset = source_offset - chunk.offset;
            let copied_byte_length = (chunk.bytes.len() - within_chunk_offset)
                .min(destination.len() - destination_offset);
            destination[destination_offset..destination_offset + copied_byte_length]
                .copy_from_slice(
                    &chunk.bytes[within_chunk_offset..within_chunk_offset + copied_byte_length],
                );
            destination_offset += copied_byte_length;
            source_offset += copied_byte_length;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        ProofByteSource, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
        ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
        ProofExternalMemoryTransactionOperation,
    };
    fn limits() -> CommonProofRuntimeLimits {
        CommonProofRuntimeLimits::new(
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        )
        .expect("the fixed worker limits are valid")
    }

    #[test]
    fn output_sink_yields_exact_chunks_and_retries_only_the_same_write() {
        let declared_byte_length = MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH + 17;
        let mut sink = PollableCommonProofByteSink::new(
            CanonicalStreamDomain::BallotValidityProof,
            declared_byte_length,
            limits(),
        )
        .expect("the bounded stream sink starts");
        let bytes = vec![0x5a; declared_byte_length];
        assert_eq!(
            sink.write_bytes(&bytes),
            Err(PollableCommonProofByteSinkError::ChunkReady)
        );
        let (chunk_index, first_chunk) = sink.pending_chunk().expect("the first chunk is ready");
        assert_eq!(chunk_index, 0);
        assert_eq!(first_chunk.len(), MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
        let first_chunk_readback = first_chunk.to_vec();
        assert_eq!(
            sink.write_bytes(&bytes),
            Err(PollableCommonProofByteSinkError::ChunkAwaitingCommit)
        );
        sink.acknowledge_pending_chunk()
            .expect("the first browser transaction commits");
        assert_eq!(
            sink.write_bytes(&bytes),
            Err(PollableCommonProofByteSinkError::ChunkAwaitingReadback)
        );
        let mut substituted_readback = first_chunk_readback.clone();
        substituted_readback[0] ^= 1;
        assert_eq!(
            sink.confirm_pending_chunk_readback(0, &substituted_readback),
            Err(CommonProofRuntimeError::OutputWriteReplayMismatch)
        );
        sink.confirm_pending_chunk_readback(0, &first_chunk_readback)
            .expect("the exact first staged chunk rereads");

        let changed = vec![0x6b; declared_byte_length];
        assert_eq!(
            sink.write_bytes(&changed),
            Err(PollableCommonProofByteSinkError::ReplayMismatch)
        );
        assert_eq!(
            sink.write_bytes(&bytes),
            Err(PollableCommonProofByteSinkError::ChunkReady)
        );
        let (chunk_index, final_chunk) = sink.pending_chunk().expect("the final chunk is ready");
        assert_eq!(chunk_index, 1);
        assert_eq!(
            final_chunk,
            &bytes[MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH..]
        );
        let final_chunk_readback = final_chunk.to_vec();
        sink.acknowledge_pending_chunk()
            .expect("the final browser transaction commits");
        assert_eq!(
            sink.confirm_pending_chunk_readback(0, &final_chunk_readback),
            Err(CommonProofRuntimeError::OutputWriteReplayMismatch)
        );
        sink.confirm_pending_chunk_readback(1, &final_chunk_readback)
            .expect("the exact final staged chunk rereads");
        assert_eq!(sink.write_bytes(&bytes), Ok(()));
        let descriptor = sink.finish().expect("the exact stream seals");
        assert_eq!(descriptor.total_byte_length, declared_byte_length as u64);
        assert_eq!(descriptor.ordered_chunk_digests.len(), 2);
    }

    #[test]
    fn output_sink_refuses_overrun_and_uncommitted_completion() {
        let mut sink = PollableCommonProofByteSink::new(
            CanonicalStreamDomain::PublicKeyShareProof,
            4,
            limits(),
        )
        .expect("small stream starts");
        assert_eq!(
            sink.write_bytes(&[1, 2, 3, 4, 5]),
            Err(PollableCommonProofByteSinkError::ByteLengthExceeded)
        );

        let mut exact = PollableCommonProofByteSink::new(
            CanonicalStreamDomain::PublicKeyShareProof,
            4,
            limits(),
        )
        .expect("exact stream starts");
        assert_eq!(
            exact.write_bytes(&[1, 2, 3, 4]),
            Err(PollableCommonProofByteSinkError::ChunkReady)
        );
        assert_eq!(
            exact.finish(),
            Err(CommonProofRuntimeError::OutputChunkNotReady)
        );

        let mut cancelled = PollableCommonProofByteSink::new(
            CanonicalStreamDomain::PublicKeyShareProof,
            4,
            limits(),
        )
        .expect("cancelled stream starts");
        assert_eq!(
            cancelled.write_bytes(&[1, 2, 3, 4]),
            Err(PollableCommonProofByteSinkError::ChunkReady)
        );
        cancelled.cancel();
        assert!(cancelled.pending_chunk().is_none());
        assert_eq!(
            cancelled.write_bytes(&[1, 2, 3, 4]),
            Err(PollableCommonProofByteSinkError::ByteLengthExceeded)
        );
    }

    #[test]
    fn resident_source_spans_two_chunks_and_fails_closed_on_a_gap() {
        let first = [1_u8, 2, 3, 4];
        let second = [5_u8, 6, 7, 8];
        let source = ResidentCommonProofByteSource::new(
            8,
            vec![
                ResidentCommonProofInputChunk::new(0, &first),
                ResidentCommonProofInputChunk::new(4, &second),
            ],
        )
        .expect("two adjacent chunks form one window");
        let mut destination = [0_u8; 6];
        assert!(source.copy_bytes(1, &mut destination));
        assert_eq!(destination, [2, 3, 4, 5, 6, 7]);

        let gapped = ResidentCommonProofByteSource::new(
            9,
            vec![
                ResidentCommonProofInputChunk::new(0, &first),
                ResidentCommonProofInputChunk::new(5, &second),
            ],
        )
        .expect("a sparse window is representable");
        let mut through_gap = [0xff; 3];
        assert!(!gapped.copy_bytes(3, &mut through_gap));
        assert_eq!(through_gap[0], 4);
    }

    #[test]
    fn storage_transaction_requires_exact_replay_before_state_advances() {
        let object = ProofExternalMemoryObject::new(0);
        let plan = ProofExternalMemoryPlan::new(
            1,
            4,
            4,
            1,
            4,
            4,
            4,
            8,
            vec![ProofExternalMemoryObjectPlan::new(
                object,
                ProofExternalMemoryProtection::PublicIntegrity,
                4,
                0,
                0,
                0,
            )],
        )
        .expect("the one-object test plan is valid");
        let mut executor = ProofExternalMemoryExecutor::new(plan).expect("executor starts");
        let mut runtime = CommonProofStorageTransactionRuntime::default();
        assert_eq!(
            executor.begin_object(runtime.storage(), object),
            Err(ProofExternalMemoryExecutorError::StorageCommit(
                ProofExternalMemoryTransactionAdapterError::Yielded
            ))
        );
        assert_eq!(executor.usage().transaction_count, 0);
        let request = runtime
            .capture_yielded_request()
            .expect("the create request is captured");
        assert!(matches!(
            request.operations(),
            [ProofExternalMemoryTransactionOperation::Create { .. }]
        ));
        let request_sequence = request.request_sequence();
        let encoded_request = runtime
            .encode_pending_worker_request()
            .expect("the pending request has a bounded binary encoding");
        let request_digest = encoded_request
            .get(92..156)
            .expect("the request digest occupies its fixed header field");
        let mut encoded_response = Vec::new();
        encoded_response.extend_from_slice(&1_u16.to_le_bytes());
        encoded_response.extend_from_slice(&2_u16.to_le_bytes());
        encoded_response.extend_from_slice(&request_sequence.to_le_bytes());
        encoded_response.extend_from_slice(request_digest);
        encoded_response.extend_from_slice(&0_u32.to_le_bytes());
        runtime
            .supply_worker_response(&encoded_response)
            .expect("create has no read response");

        runtime
            .begin_transaction(4, 1)
            .expect("the replay transaction header matches");
        assert_eq!(
            runtime.create_object(
                ProofExternalMemoryObject::new(1),
                ProofExternalMemoryProtection::PublicIntegrity,
                4,
            ),
            Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay),
            "a different retried request must be refused"
        );
        assert_eq!(executor.usage().transaction_count, 0);
    }

    #[test]
    fn storage_transaction_cancellation_invalidates_an_inflight_request() {
        let object = ProofExternalMemoryObject::new(0);
        let mut runtime = CommonProofStorageTransactionRuntime::for_runtime_binding([0x55; 64]);
        runtime
            .begin_transaction(4, 1)
            .expect("the bounded transaction begins");
        runtime
            .append_object_bytes(object, 0, &[1, 2, 3, 4])
            .expect("the inflight payload records");
        assert_eq!(
            runtime.commit_transaction(),
            Err(ProofExternalMemoryTransactionAdapterError::Yielded),
        );
        runtime
            .capture_yielded_request()
            .expect("the inflight request is captured");
        let encoded_request = runtime
            .encode_pending_worker_request()
            .expect("the inflight request is visible before cancellation");
        runtime.cancel();
        assert_eq!(
            runtime.encode_pending_worker_request(),
            Err(CommonProofRuntimeError::TransactionResponseMissing),
        );
        assert_eq!(
            runtime.supply_worker_response(&encoded_request),
            Err(CommonProofRuntimeError::TransactionResponseMissing),
        );
        assert_eq!(
            runtime.begin_transaction(4, 1),
            Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle),
        );
    }

    #[test]
    fn runtime_limits_bind_the_fixed_external_memory_chunk_profile_and_reject_overruns() {
        assert_eq!(MAXIMUM_COMMON_PROOF_BYTE_LENGTH, 5_242_880);
        assert_eq!(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, 1_048_576);
        assert_eq!(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            49_152
        );
        let exact_limits = CommonProofRuntimeLimits::new(
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        )
        .expect("the exact fixed worker ceilings are accepted");
        assert_eq!(
            exact_limits.proof_byte_length(),
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH
        );
        assert_eq!(
            exact_limits.external_memory_chunk_byte_length(),
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
        );
        assert_eq!(
            exact_limits.prefetched_query_byte_length(),
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(
                MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                1,
            ),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(
                1,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH - 1,
                1,
            ),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(
                1,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH + 1,
                1,
            ),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(
                1,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                2,
            ),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(
                0,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                1,
            ),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(1, 0, 1),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(
                1,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                0,
            ),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
    }
}
