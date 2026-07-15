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

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::foundation::{
    CanonicalStreamDomain, CanonicalStreamWriter, FOUNDATION_PROFILE, StreamDescriptor,
};
use crate::hashing::hash_framed_parts_512;

use super::{
    CommonProofByteSink, CommonProofGenerationInput, CommonProofSourcePolynomial,
    CommonProofVerificationInput, CommonProofVerifierError, CompiledRelationPlan, ProofByteSource,
    ProofExternalMemory, ProofExternalMemoryProtection, ProofExternalMemoryTransactionAdapterError,
    ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
    ProofExternalMemoryTransactionRequest, ProofProfileError, RelationPlanCheckContext,
    RelationPlanError, RelationProofTreeInput, ValidatedRelationPlanArtifact, VerifiedCommonProof,
    VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree, verify_common_proof,
};

const HASH_BYTE_LENGTH: usize = 64;
const ATTEMPT_BINDING_HASH_DOMAIN: &str = "sealed-lattice/common-proof/attempt-binding/v1";
const RELATION_PLAN_HASH_DOMAIN: &str = "sealed-lattice/common-proof/relation-plan/v1";
const OUTPUT_WRITE_HASH_DOMAIN: &str = "sealed-lattice/common-proof/output-write/v1";

/// The selected browser profile's hard proof-object ceiling. This is a worker
/// allocation control, not a proof field and not a verifier claim.
pub(crate) const MAXIMUM_COMMON_PROOF_BYTE_LENGTH: usize = 5_242_880;

/// A common-proof runtime never retains more than one canonical transport
/// chunk awaiting acknowledgement.
pub(crate) const MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH: usize = 1_048_576;

/// At most two authenticated input chunks may be resident around an
/// incremental decoder call.
pub(crate) const MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRuntimeError {
    InvalidLimits,
    InvalidPlanCapability,
    WrongAttemptBinding,
    UnknownOrStaleHandle,
    WrongOperationKind,
    CancellationRequested,
    TransactionPending,
    TransactionResponseMissing,
    TransactionReplayIncomplete,
    OutputByteLengthExceeded,
    OutputChunkAwaitingCommit,
    OutputChunkNotReady,
    OutputWriteReplayMismatch,
    AllocationLimitExceeded,
}

/// Runtime-only limits applied before any large proof allocation or browser
/// storage request. Caller-selected values may reduce, never raise, the fixed
/// browser profile ceilings.
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
            || external_memory_chunk_byte_length == 0
            || usize::try_from(external_memory_chunk_byte_length)
                .ok()
                .is_none_or(|length| length > canonical_chunk_byte_length)
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
            maximum_prefetched_query_byte_length: limits.prefetched_query_byte_length(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verification_input<'input, Source: ProofByteSource + ?Sized>(
        &'input self,
        protocol_version: u16,
        suite_identifier: [u8; HASH_BYTE_LENGTH],
        canonical_application_statement_bytes: &'input [u8],
        statement_owned_trees: &'input [VerifiedStatementOwnedTree],
        proof_source: &'input Source,
        declared_proof_byte_length: usize,
        limits: CommonProofRuntimeLimits,
    ) -> CommonProofVerificationInput<'input, Source> {
        CommonProofVerificationInput {
            protocol_version,
            suite_identifier,
            canonical_application_statement_bytes,
            relation_plan: &self.relation_plan,
            relation_context: &self.relation_context,
            schedule_position: self.schedule_position,
            top_count: self.top_count,
            statement_owned_trees,
            proof_source,
            declared_proof_byte_length,
            proof_byte_ceiling: limits.proof_byte_length(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRelationPlanCapabilityError {
    Profile(ProofProfileError),
    Relation(RelationPlanError),
}

/// Every resumable operation is bound to one build, suite, action, application
/// slot, proof attempt, relation plan, and fresh checkpoint lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofAttemptBinding {
    runtime_build_manifest_hash: [u8; HASH_BYTE_LENGTH],
    suite_identifier: [u8; HASH_BYTE_LENGTH],
    action_context_hash: [u8; HASH_BYTE_LENGTH],
    proof_application_slot_hash: [u8; HASH_BYTE_LENGTH],
    attempt_identifier: [u8; 32],
    checkpoint_lineage_identifier: [u8; 32],
    relation_plan_hash: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofAttemptBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        runtime_build_manifest_hash: [u8; HASH_BYTE_LENGTH],
        suite_identifier: [u8; HASH_BYTE_LENGTH],
        action_context_hash: [u8; HASH_BYTE_LENGTH],
        proof_application_slot_hash: [u8; HASH_BYTE_LENGTH],
        attempt_identifier: [u8; 32],
        checkpoint_lineage_identifier: [u8; 32],
        relation_plan_hash: [u8; HASH_BYTE_LENGTH],
    ) -> Self {
        Self {
            runtime_build_manifest_hash,
            suite_identifier,
            action_context_hash,
            proof_application_slot_hash,
            attempt_identifier,
            checkpoint_lineage_identifier,
            relation_plan_hash,
        }
    }

    pub(crate) fn binding_hash(self) -> [u8; HASH_BYTE_LENGTH] {
        hash_framed_parts_512(
            ATTEMPT_BINDING_HASH_DOMAIN,
            &[
                &self.runtime_build_manifest_hash,
                &self.suite_identifier,
                &self.action_context_hash,
                &self.proof_application_slot_hash,
                &self.attempt_identifier,
                &self.checkpoint_lineage_identifier,
                &self.relation_plan_hash,
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum CommonProofOperationKind {
    Generation = 1,
    Verification = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofOperationHandle(u32);

impl CommonProofOperationHandle {
    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VerifiedCommonProofCapabilityHandle(u32);

impl VerifiedCommonProofCapabilityHandle {
    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

struct CommonProofOperationEntry {
    binding: CommonProofAttemptBinding,
    operation_kind: CommonProofOperationKind,
    limits: CommonProofRuntimeLimits,
    cancellation_requested: bool,
}

struct VerifiedCommonProofCapabilityEntry {
    binding_hash: [u8; HASH_BYTE_LENGTH],
    proof: VerifiedCommonProof,
}

/// Process-local operation and verified-proof registry. Numeric handles are
/// never serialized into checkpoints, and monotonically increasing allocation
/// makes every removed handle permanently stale for this worker instance.
pub(crate) struct CommonProofRuntimeRegistry {
    next_operation_handle: u32,
    next_verified_capability_handle: u32,
    operations: BTreeMap<CommonProofOperationHandle, CommonProofOperationEntry>,
    verified_capabilities:
        BTreeMap<VerifiedCommonProofCapabilityHandle, VerifiedCommonProofCapabilityEntry>,
}

impl Default for CommonProofRuntimeRegistry {
    fn default() -> Self {
        Self {
            next_operation_handle: 1,
            next_verified_capability_handle: 1,
            operations: BTreeMap::new(),
            verified_capabilities: BTreeMap::new(),
        }
    }
}

impl CommonProofRuntimeRegistry {
    pub(crate) fn begin_operation(
        &mut self,
        operation_kind: CommonProofOperationKind,
        binding: CommonProofAttemptBinding,
        relation_plan: &CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<CommonProofOperationHandle, CommonProofRuntimeError> {
        if binding.relation_plan_hash != relation_plan.relation_plan_hash() {
            return Err(CommonProofRuntimeError::WrongAttemptBinding);
        }
        let handle =
            CommonProofOperationHandle(take_nonrepeating_handle(&mut self.next_operation_handle)?);
        self.operations.insert(
            handle,
            CommonProofOperationEntry {
                binding,
                operation_kind,
                limits,
                cancellation_requested: false,
            },
        );
        Ok(handle)
    }

    pub(crate) fn request_cancellation(
        &mut self,
        handle: CommonProofOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        let operation = self
            .operations
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        operation.cancellation_requested = true;
        Ok(())
    }

    pub(crate) fn cancellation(
        &self,
        handle: CommonProofOperationHandle,
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
        handle: CommonProofOperationHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.operations
            .remove(&handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    /// Executes the actual common verifier and mints an opaque capability only
    /// after every canonical, transcript, opening, FRI, and relation check
    /// succeeds. A decoded proof or a caller-supplied digest cannot enter the
    /// capability registry through any other method.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_and_register<Source, ColumnEvaluator>(
        &mut self,
        handle: CommonProofOperationHandle,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        suite_identifier: [u8; HASH_BYTE_LENGTH],
        canonical_application_statement_bytes: &[u8],
        statement_owned_trees: &[VerifiedStatementOwnedTree],
        proof_source: &Source,
        declared_proof_byte_length: usize,
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<VerifiedCommonProofCapabilityHandle, CommonProofRuntimeVerificationError>
    where
        Source: ProofByteSource + ?Sized,
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        let operation = self
            .active_operation(handle, Some(CommonProofOperationKind::Verification))
            .map_err(CommonProofRuntimeVerificationError::Runtime)?;
        if operation.cancellation_requested {
            return Err(CommonProofRuntimeVerificationError::Runtime(
                CommonProofRuntimeError::CancellationRequested,
            ));
        }
        if operation.binding.relation_plan_hash != relation_plan.relation_plan_hash()
            || operation.binding.suite_identifier != suite_identifier
            || declared_proof_byte_length > operation.limits.proof_byte_length()
        {
            return Err(CommonProofRuntimeVerificationError::Runtime(
                CommonProofRuntimeError::WrongAttemptBinding,
            ));
        }
        let binding_hash = operation.binding.binding_hash();
        let verification_input = relation_plan.verification_input(
            protocol_version,
            suite_identifier,
            canonical_application_statement_bytes,
            statement_owned_trees,
            proof_source,
            declared_proof_byte_length,
            operation.limits,
        );
        let proof = verify_common_proof(verification_input, evaluate_verified_column)
            .map_err(CommonProofRuntimeVerificationError::Verifier)?;
        self.operations.remove(&handle);
        let capability_handle = VerifiedCommonProofCapabilityHandle(
            take_nonrepeating_handle(&mut self.next_verified_capability_handle)
                .map_err(CommonProofRuntimeVerificationError::Runtime)?,
        );
        self.verified_capabilities.insert(
            capability_handle,
            VerifiedCommonProofCapabilityEntry {
                binding_hash,
                proof,
            },
        );
        Ok(capability_handle)
    }

    pub(crate) fn with_verified_proof<ResultValue>(
        &self,
        handle: VerifiedCommonProofCapabilityHandle,
        operation: impl FnOnce(&VerifiedCommonProof) -> ResultValue,
    ) -> Result<ResultValue, CommonProofRuntimeError> {
        let capability = self
            .verified_capabilities
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        Ok(operation(&capability.proof))
    }

    pub(crate) fn verified_binding_hash(
        &self,
        handle: VerifiedCommonProofCapabilityHandle,
    ) -> Result<[u8; HASH_BYTE_LENGTH], CommonProofRuntimeError> {
        self.verified_capabilities
            .get(&handle)
            .map(|capability| capability.binding_hash)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn release_verified_proof(
        &mut self,
        handle: VerifiedCommonProofCapabilityHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.verified_capabilities
            .remove(&handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn active_operation(
        &self,
        handle: CommonProofOperationHandle,
        expected_kind: Option<CommonProofOperationKind>,
    ) -> Result<&CommonProofOperationEntry, CommonProofRuntimeError> {
        let operation = self
            .operations
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if expected_kind.is_some_and(|kind| kind != operation.operation_kind) {
            return Err(CommonProofRuntimeError::WrongOperationKind);
        }
        Ok(operation)
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRuntimeVerificationError {
    Runtime(CommonProofRuntimeError),
    Verifier(CommonProofVerifierError),
}

/// One transaction pass of a pollable external-memory operation. Recording
/// yields an owned request. Supplying the browser's read results changes the
/// same object into an exact replay pass; the caller resets it only after the
/// cryptographic component reports that the transaction completed.
pub(crate) struct CommonProofStorageTransactionRuntime {
    pass: CommonProofStorageTransactionPass,
}

enum CommonProofStorageTransactionPass {
    Recording(ProofExternalMemoryTransactionRecorder),
    RequestReady(ProofExternalMemoryTransactionRequest),
    Replaying(ProofExternalMemoryTransactionReplay),
}

impl Default for CommonProofStorageTransactionRuntime {
    fn default() -> Self {
        Self {
            pass: CommonProofStorageTransactionPass::Recording(
                ProofExternalMemoryTransactionRecorder::new(),
            ),
        }
    }
}

impl CommonProofStorageTransactionRuntime {
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

    pub(crate) fn supply_read_results(
        &mut self,
        read_results: Vec<Vec<u8>>,
    ) -> Result<(), CommonProofRuntimeError> {
        let previous = core::mem::replace(
            &mut self.pass,
            CommonProofStorageTransactionPass::Recording(
                ProofExternalMemoryTransactionRecorder::new(),
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
        if !matches!(self.pass, CommonProofStorageTransactionPass::Replaying(_)) {
            return Err(CommonProofRuntimeError::TransactionReplayIncomplete);
        }
        self.pass = CommonProofStorageTransactionPass::Recording(
            ProofExternalMemoryTransactionRecorder::new(),
        );
        Ok(())
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
            CommonProofStorageTransactionPass::RequestReady(_) => {
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
            CommonProofStorageTransactionPass::RequestReady(_) => {
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
            CommonProofStorageTransactionPass::RequestReady(_) => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn seal_object(&mut self, object: super::ProofExternalMemoryObject) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.seal_object(object),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.seal_object(object),
            CommonProofStorageTransactionPass::RequestReady(_) => {
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
            CommonProofStorageTransactionPass::RequestReady(_) => {
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
            CommonProofStorageTransactionPass::RequestReady(_) => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.commit_transaction(),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.commit_transaction(),
            CommonProofStorageTransactionPass::RequestReady(_) => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.abort_transaction(),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.abort_transaction(),
            CommonProofStorageTransactionPass::RequestReady(_) => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PollableCommonProofByteSinkError {
    ChunkReady,
    ChunkAwaitingCommit,
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
            pending_write: None,
            terminal: false,
        })
    }

    pub(crate) fn pending_chunk(&self) -> Option<(usize, &[u8])> {
        self.chunk_awaiting_commit
            .then_some((self.next_chunk_index, self.current_chunk.as_slice()))
    }

    pub(crate) fn acknowledge_pending_chunk(&mut self) -> Result<(), CommonProofRuntimeError> {
        if !self.chunk_awaiting_commit || self.current_chunk.is_empty() {
            return Err(CommonProofRuntimeError::OutputChunkNotReady);
        }
        self.stream_writer
            .as_mut()
            .ok_or(CommonProofRuntimeError::OutputChunkNotReady)?
            .absorb_chunk(self.next_chunk_index, &self.current_chunk)
            .map_err(|_| CommonProofRuntimeError::OutputWriteReplayMismatch)?;
        self.current_chunk.clear();
        self.chunk_awaiting_commit = false;
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

impl ProofByteSource for ResidentCommonProofByteSource<'_> {
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
        ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError, ProofExternalMemoryObject,
        ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
        ProofExternalMemoryTransactionOperation,
    };
    use crate::foundation::RefusalReason;

    fn limits() -> CommonProofRuntimeLimits {
        CommonProofRuntimeLimits::new(
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH as u32,
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
        assert_eq!(
            sink.write_bytes(&bytes),
            Err(PollableCommonProofByteSinkError::ChunkAwaitingCommit)
        );
        sink.acknowledge_pending_chunk()
            .expect("the first browser transaction commits");

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
        sink.acknowledge_pending_chunk()
            .expect("the final browser transaction commits");
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
        runtime
            .supply_read_results(Vec::new())
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
    fn runtime_limits_reject_every_one_step_overrun() {
        assert_eq!(
            CommonProofRuntimeLimits::new(MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1, 1, 1),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(
                1,
                (MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH + 1) as u32,
                1,
            ),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        assert_eq!(
            CommonProofRuntimeLimits::new(1, 1, 2),
            Err(CommonProofRuntimeError::InvalidLimits)
        );
        let _ = RefusalReason::WrongTypeOrLength;
    }
}
