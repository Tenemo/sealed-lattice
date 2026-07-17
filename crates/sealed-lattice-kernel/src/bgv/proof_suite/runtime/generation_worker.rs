#[cfg(test)]
use super::ProofExternalMemoryTransactionRequest;
use super::{
    AuthenticatedCheckpointContinuationSource, BTreeMap, BoundedCommonProofByteSinkError,
    CHECKPOINT_CUMULATIVE_HASH_DOMAIN, CHECKPOINT_CURSOR_LIST_HASH_DOMAIN,
    CHECKPOINT_EVENT_HASH_DOMAIN, CHECKPOINT_GENESIS_HASH_DOMAIN,
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER,
    COMMON_PROOF_CHECKPOINT_STATE_MAGIC, COMMON_PROOF_CHECKPOINT_STATE_VERSION,
    CheckpointableCommonProofPrivateCoinSource, CommonProofBoundOpeningProvider,
    CommonProofEncodingError, CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationPoll,
    CommonProofGenerationStage, CommonProofGenerationStateMachine, CommonProofOpeningGeometry,
    CommonProofPrivateCoinSource, CommonProofRelationPlanCapability, CommonProofRequiredByteRange,
    CommonProofRuntimeError, CommonProofRuntimeLimits, CommonProofSourcePolynomial,
    CommonProofStorageTransactionRuntime, CommonProofVerificationBinding, CompleteProofTreeCatalog,
    GENERATION_BINDING_HASH_DOMAIN, HASH_BYTE_LENGTH, Hash512,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, PollableCommonProofByteSink,
    PollableCommonProofByteSinkError, PreparedActionProofAttemptSource, PrivateRandomCursor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryTransactionAdapterError,
    RelationProofTreeInput, StreamDescriptor, hash_framed_parts_512,
    verified_application_statement_hash,
};

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
        catalog_entry: &super::super::ProofTreeCatalogEntry,
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
        catalog_entry: &super::super::ProofTreeCatalogEntry,
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
        catalog_entry: &super::super::ProofTreeCatalogEntry,
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
    pub(crate) fn runtime_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.binding.binding_hash()
    }

    pub(crate) fn verification_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.binding.verification_binding.binding_hash()
    }

    pub(crate) const fn proof_attempt_lineage_identifier(&self) -> [u8; 32] {
        self.binding.attempt_identifier
    }

    pub(crate) const fn checkpoint_lineage_identifier(&self) -> [u8; 32] {
        self.binding.checkpoint_lineage_identifier
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        self.binding.checkpoint_schedule_digest
    }

    pub(crate) fn matches_authenticated_checkpoint(
        &self,
        checkpoint: &AuthenticatedCommonProofGenerationCheckpoint,
    ) -> bool {
        checkpoint.state.matches_binding(self.binding)
    }

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
pub(super) struct CommonProofGenerationCheckpointState {
    pub(super) stable_attempt_binding_hash: [u8; HASH_BYTE_LENGTH],
    pub(super) checkpoint_lineage_identifier: [u8; 32],
    pub(super) checkpoint_schedule_digest: [u8; HASH_BYTE_LENGTH],
    pub(super) next_event_index: u64,
    pub(super) cumulative_event_digest: [u8; HASH_BYTE_LENGTH],
    pub(super) safe_boundary_ordinal: u32,
    pub(super) position: [u8; 16],
    pub(super) committed_state_digest: [u8; HASH_BYTE_LENGTH],
    pub(super) cursor_list_digest: [u8; HASH_BYTE_LENGTH],
}

/// Canonically decoded continuation state received only after browser-owned
/// checkpoint custody has authenticated the encrypted record and its exact
/// boundary. It remains process-local and cannot be serialized as authority.
pub(crate) struct AuthenticatedCommonProofGenerationCheckpoint {
    state: CommonProofGenerationCheckpointState,
}

impl AuthenticatedCommonProofGenerationCheckpoint {
    pub(crate) fn decode(
        authenticated_checkpoint_state: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        Ok(Self {
            state: CommonProofGenerationCheckpointState::decode(authenticated_checkpoint_state)?,
        })
    }

    pub(crate) const fn stable_attempt_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.state.stable_attempt_binding_hash
    }

    pub(crate) const fn checkpoint_lineage_identifier(&self) -> [u8; 32] {
        self.state.checkpoint_lineage_identifier
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        Hash512::from_bytes(self.state.checkpoint_schedule_digest)
    }

    pub(crate) const fn continuation_source(&self) -> AuthenticatedCheckpointContinuationSource {
        AuthenticatedCheckpointContinuationSource::from_authenticated_common_proof_checkpoint(
            self.state.checkpoint_lineage_identifier,
            Hash512::from_bytes(self.state.checkpoint_schedule_digest),
            self.state.next_event_index,
            Hash512::from_bytes(self.state.cumulative_event_digest),
        )
    }
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
            &COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER.to_le_bytes(),
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
        let format_identifier =
            u16::from_le_bytes(read_checkpoint_state_array(bytes, &mut cursor)?);
        if magic != COMMON_PROOF_CHECKPOINT_STATE_MAGIC
            || version != COMMON_PROOF_CHECKPOINT_STATE_VERSION
            || format_identifier != COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER
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

pub(super) struct PendingCommonProofGenerationCheckpoint {
    pub(super) state: CommonProofGenerationCheckpointState,
    encoded_state: [u8; COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH],
    ordered_cursor_bytes: Vec<Vec<u8>>,
}

impl PendingCommonProofGenerationCheckpoint {
    pub(super) fn encoded_state(&self) -> &[u8] {
        &self.encoded_state
    }

    pub(super) fn safe_boundary_ordinal(&self) -> u32 {
        self.state.safe_boundary_ordinal
    }

    pub(super) fn ordered_cursor_bytes(&self) -> &[Vec<u8>] {
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

pub(super) struct GeneratedCommonProof {
    binding: CommonProofGenerationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    stream_descriptor: StreamDescriptor,
}

/// One browser-owned generated proof operation. The cryptographic state,
/// private coin cursors, bound-tree source, external-memory replay, and output
/// digest all stay in this worker. Host input can only satisfy the exact
/// pending storage request or acknowledge and reread the exact staged chunk.
pub(super) struct CommonProofGenerationWorker {
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
    pub(super) cancellation_complete: bool,
}

impl CommonProofGenerationWorker {
    pub(super) fn new(
        prepared: PreparedCommonProofGeneration,
    ) -> Result<Self, CommonProofRuntimeError> {
        if !prepared.binding.starts_at_checkpoint_genesis() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Self::new_with_resume_target(prepared, None)
    }

    pub(super) fn resume(
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

    pub(super) fn pending_checkpoint(&self) -> Option<&PendingCommonProofGenerationCheckpoint> {
        self.pending_checkpoint.as_ref()
    }

    pub(super) fn advance_pending_checkpoint(&mut self) -> Result<(), CommonProofRuntimeError> {
        let pending = self
            .pending_checkpoint
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        self.checkpoint_next_event_index = pending.state.next_event_index;
        self.checkpoint_cumulative_event_digest = pending.state.cumulative_event_digest;
        self.last_checkpoint_position = Some(pending.state.position);
        Ok(())
    }

    pub(super) fn pending_storage_request(&self) -> Option<&[u8]> {
        self.encoded_storage_request.as_deref()
    }

    #[cfg(test)]
    pub(super) fn pending_storage_transaction_request(
        &self,
    ) -> Option<&ProofExternalMemoryTransactionRequest> {
        self.storage.pending_request()
    }

    pub(super) fn supply_storage_response(
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

    pub(super) fn pending_output_chunk(&self) -> Option<(usize, &[u8])> {
        self.output
            .as_ref()
            .and_then(|output| output.pending_chunk())
    }

    pub(super) fn acknowledge_output_chunk(
        &mut self,
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.output
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .acknowledge_pending_chunk()?;
        Ok(())
    }

    pub(super) fn confirm_output_readback(
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

    pub(super) fn request_cancellation(&mut self) {
        if self.cancellation_requested {
            return;
        }
        self.cancellation_requested = true;
        self.generation_transaction_must_replay_before_cancellation =
            self.encoded_storage_request.is_some() || self.storage.replay_is_active();
    }

    pub(super) fn poll(
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

    pub(super) fn finish(self) -> Result<GeneratedCommonProof, CommonProofRuntimeError> {
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

pub(super) fn required_chunk_indices(
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
