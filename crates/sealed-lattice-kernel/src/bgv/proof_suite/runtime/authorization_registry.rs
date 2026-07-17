#[cfg(test)]
use super::ProofExternalMemoryTransactionRequest;
use super::{
    BTreeMap, BrowserWorkerAuthenticatedStorageHeadSource,
    BrowserWorkerAuthenticatedStorageTransitionSource, CanonicalStreamDomain,
    CommonProofGenerationWorker, CommonProofGenerationWorkerError, CommonProofGenerationWorkerPoll,
    CommonProofRelationPlanCapability, CommonProofRuntimeCancellation, CommonProofRuntimeError,
    CommonProofRuntimeLimits, CommonProofVerificationWorker, CommonProofVerificationWorkerError,
    CommonProofVerificationWorkerPoll, DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH,
    DURABLE_AUTHORIZATION_FRAME_MAGIC, DURABLE_AUTHORIZATION_FRAME_VERSION,
    DURABLE_AUTHORIZATION_RECORD_HASH_DOMAIN, GeneratedCommonProof, HASH_BYTE_LENGTH, Hash512,
    LocalStorageBinding, MAXIMUM_COMMON_PROOF_BYTE_LENGTH, PROOF_APPLICATION_BINDING_HASH_DOMAIN,
    PendingCommonProofGenerationCheckpoint, PreparedCommonProofGeneration,
    PreparedCommonProofVerification, ProofApplicationSlotCeilings,
    VERIFICATION_BINDING_HASH_DOMAIN, VerifiedCanonicalStreamSummary, VerifiedCommonProof,
    common_proof_registry_entry_count, hash_framed_parts_512,
    require_common_proof_registry_entry_capacity,
};

/// Exact durable application reservation consumed by one proof attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofApplicationBinding {
    pub(super) proof_application_slot_hash: [u8; HASH_BYTE_LENGTH],
    pub(super) canonical_proof_application_binding_hash: [u8; HASH_BYTE_LENGTH],
    pub(super) application_statement_schema_identifier: u16,
    pub(super) proof_header_hash: [u8; HASH_BYTE_LENGTH],
    pub(super) proof_stream_domain: CanonicalStreamDomain,
    pub(super) proof_stream_full_object_digest: [u8; HASH_BYTE_LENGTH],
    pub(super) proof_byte_length: u64,
    pub(super) proof_query_count: u32,
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
    pub(super) suite_identifier: [u8; HASH_BYTE_LENGTH],
    pub(super) ceremony_context_hash: [u8; HASH_BYTE_LENGTH],
    pub(super) action_context_hash: [u8; HASH_BYTE_LENGTH],
    pub(super) board_object_hash: [u8; HASH_BYTE_LENGTH],
    pub(super) proof_application: CommonProofApplicationBinding,
    pub(super) relation_plan_hash: [u8; HASH_BYTE_LENGTH],
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
    pub(crate) fn entry_count(&self) -> Result<usize, CommonProofRuntimeError> {
        common_proof_registry_entry_count(&[
            self.operations.len(),
            self.generation_operations.len(),
            self.verified_capabilities.len(),
            self.generated_capabilities.len(),
            self.authenticated_ledger_heads.len(),
            self.authenticated_ledger_transitions.len(),
            self.pending_authorizations.len(),
        ])
    }

    pub(crate) fn heavy_operation_count(&self) -> Result<usize, CommonProofRuntimeError> {
        common_proof_registry_entry_count(&[
            self.operations.len(),
            self.generation_operations.len(),
        ])
    }

    pub(crate) fn require_entry_capacity(&self) -> Result<(), CommonProofRuntimeError> {
        require_common_proof_registry_entry_capacity(&[
            self.operations.len(),
            self.generation_operations.len(),
            self.verified_capabilities.len(),
            self.generated_capabilities.len(),
            self.authenticated_ledger_heads.len(),
            self.authenticated_ledger_transitions.len(),
            self.pending_authorizations.len(),
        ])
    }

    #[cfg(test)]
    pub(super) fn insert_test_verification_operation(
        &mut self,
        identifier: u32,
        binding: CommonProofVerificationBinding,
        limits: CommonProofRuntimeLimits,
    ) {
        self.operations.insert(
            CommonProofVerificationOperationHandle::from_identifier(identifier),
            CommonProofOperationEntry {
                binding,
                limits,
                cancellation_requested: false,
                worker: None,
            },
        );
    }

    #[cfg(test)]
    pub(super) fn insert_test_authenticated_ledger_transition(&mut self, identifier: u32) {
        self.authenticated_ledger_transitions.insert(
            CommonProofAuthenticatedLedgerTransitionCapabilityHandle(identifier),
            CommonProofAuthenticatedLedgerTransitionCapabilityEntry {
                pending_authorization_handle: identifier,
            },
        );
    }

    #[cfg(test)]
    pub(super) fn remove_test_authenticated_ledger_transition(&mut self, identifier: u32) {
        self.authenticated_ledger_transitions.remove(
            &CommonProofAuthenticatedLedgerTransitionCapabilityHandle(identifier),
        );
    }

    pub(crate) fn begin_owned_generation(
        &mut self,
        prepared: PreparedCommonProofGeneration,
    ) -> Result<CommonProofGenerationOperationHandle, CommonProofGenerationWorkerError> {
        let handle = self.preissue_generation_operation_handle()?;
        self.begin_owned_generation_with_handle(prepared, handle)
    }

    pub(crate) fn preissue_generation_operation_handle(
        &mut self,
    ) -> Result<CommonProofGenerationOperationHandle, CommonProofRuntimeError> {
        self.require_entry_capacity()?;
        Ok(CommonProofGenerationOperationHandle(
            take_nonrepeating_handle(&mut self.next_generation_operation_handle)?,
        ))
    }

    pub(crate) fn begin_owned_generation_with_handle(
        &mut self,
        prepared: PreparedCommonProofGeneration,
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<CommonProofGenerationOperationHandle, CommonProofGenerationWorkerError> {
        let worker = CommonProofGenerationWorker::new(prepared)?;
        self.generation_operations
            .insert(handle, CommonProofGenerationOperationEntry { worker });
        Ok(handle)
    }

    pub(crate) fn resume_owned_generation(
        &mut self,
        prepared: PreparedCommonProofGeneration,
        authenticated_checkpoint_state: &[u8],
    ) -> Result<CommonProofGenerationOperationHandle, CommonProofGenerationWorkerError> {
        let handle = self.preissue_generation_operation_handle()?;
        self.resume_owned_generation_with_handle(prepared, authenticated_checkpoint_state, handle)
    }

    pub(crate) fn resume_owned_generation_with_handle(
        &mut self,
        prepared: PreparedCommonProofGeneration,
        authenticated_checkpoint_state: &[u8],
        handle: CommonProofGenerationOperationHandle,
    ) -> Result<CommonProofGenerationOperationHandle, CommonProofGenerationWorkerError> {
        let worker = CommonProofGenerationWorker::resume(prepared, authenticated_checkpoint_state)?;
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
        let capability_identifier = take_replacement_handle_before_consuming_source(
            &self.generation_operations,
            &handle,
            &mut self.next_generated_capability_handle,
        )?;
        let operation = self
            .generation_operations
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let proof = operation.worker.finish()?;
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
        let handle = self.preissue_verification_operation_handle()?;
        self.begin_owned_verification_with_handle(prepared, handle)
    }

    pub(crate) fn preissue_verification_operation_handle(
        &mut self,
    ) -> Result<CommonProofVerificationOperationHandle, CommonProofRuntimeError> {
        self.require_entry_capacity()?;
        Ok(CommonProofVerificationOperationHandle(
            take_nonrepeating_handle(&mut self.next_operation_handle)?,
        ))
    }

    pub(crate) fn begin_owned_verification_with_handle(
        &mut self,
        prepared: PreparedCommonProofVerification,
        handle: CommonProofVerificationOperationHandle,
    ) -> Result<CommonProofVerificationOperationHandle, CommonProofVerificationWorkerError> {
        let worker = CommonProofVerificationWorker::new(prepared)?;
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
        self.require_entry_capacity()?;
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
        let capability_identifier = take_replacement_handle_before_consuming_source(
            &self.operations,
            &handle,
            &mut self.next_verified_capability_handle,
        )?;
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
        match self.register_verified_proof_with_identifier(
            handle,
            &relation_plan,
            proof,
            verified_stream,
            capability_identifier,
        ) {
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
        let capability_identifier = take_replacement_handle_before_consuming_source(
            &self.operations,
            &handle,
            &mut self.next_verified_capability_handle,
        )?;
        self.register_verified_proof_with_identifier(
            handle,
            relation_plan,
            proof,
            verified_stream,
            capability_identifier,
        )
    }

    fn register_verified_proof_with_identifier(
        &mut self,
        handle: CommonProofVerificationOperationHandle,
        relation_plan: &CommonProofRelationPlanCapability,
        proof: VerifiedCommonProof,
        verified_stream: VerifiedCanonicalStreamSummary,
        capability_identifier: u32,
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
        self.require_entry_capacity()?;
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
        let verified_capability = self
            .verified_capabilities
            .get(terminal_capability_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let predecessor_authenticated_storage_head =
            CommonProofAuthenticatedLedgerHead::from_browser_worker_source(source);
        if !authenticated_head_matches_binding(
            predecessor_authenticated_storage_head,
            verified_capability.binding,
        ) || self
            .authenticated_ledger_heads
            .values()
            .any(|entry| entry.terminal_capability_handle == terminal_capability_handle.0)
        {
            return Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch);
        }
        let pending_identifier =
            take_nonrepeating_handle(&mut self.next_pending_authorization_handle)?;
        let entry = self
            .verified_capabilities
            .remove(terminal_capability_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        Ok(self.retain_pending_authorization(
            pending_identifier,
            VerifiedCommonProofCapabilityHandle(terminal_capability_handle.0),
            entry,
            predecessor_authenticated_storage_head,
        ))
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
        Ok(self.retain_pending_authorization(
            pending_identifier,
            original_capability_handle,
            entry,
            predecessor_authenticated_storage_head,
        ))
    }

    fn retain_pending_authorization(
        &mut self,
        pending_identifier: u32,
        original_capability_handle: VerifiedCommonProofCapabilityHandle,
        entry: VerifiedCommonProofCapabilityEntry,
        predecessor_authenticated_storage_head: CommonProofAuthenticatedLedgerHead,
    ) -> PreparedCommonProofAuthorization {
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
        prepared
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
        self.require_entry_capacity()?;
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
        self.pending_authorizations.remove(pending_handle);
        Ok(())
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

pub(super) const fn common_proof_stream_domain(
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

pub(super) fn take_nonrepeating_handle(
    next_handle: &mut u32,
) -> Result<u32, CommonProofRuntimeError> {
    if *next_handle == 0 {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    let handle = *next_handle;
    *next_handle = next_handle.checked_add(1).unwrap_or(0);
    Ok(handle)
}

pub(super) fn take_replacement_handle_before_consuming_source<SourceHandle: Ord, SourceEntry>(
    source_entries: &BTreeMap<SourceHandle, SourceEntry>,
    source_handle: &SourceHandle,
    next_destination_handle: &mut u32,
) -> Result<u32, CommonProofRuntimeError> {
    if !source_entries.contains_key(source_handle) {
        return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
    }
    take_nonrepeating_handle(next_destination_handle)
}
