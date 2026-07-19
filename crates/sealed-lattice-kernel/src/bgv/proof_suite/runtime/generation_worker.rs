use super::super::prover::{
    CommonProofExternalMemoryRequirement, CommonProofPrivateCoinReplayCursor,
    CommonProofPrivateCoinReplaySpan, CommonProofPrivateCoinReplaySpanStart,
    PublicOnlyCommonProofCoinSource, ReplayableCommonProofPrivateCoinCatalogSource,
    ReplayableCommonProofPrivateCoinSource,
};
use super::super::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofCheckpointCursorManifestError,
    CommonProofCheckpointCursorManifestRequirement, CommonProofProverError,
    ProofExternalMemoryUsage, RelationPlanVariant,
    common_proof_checkpoint_cursor_manifest_requirement_for_variant,
};
#[cfg(test)]
use super::ProofExternalMemoryTransactionRequest;
use super::{
    AuthenticatedCheckpointContinuationSource, CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
    CHECKPOINT_CUMULATIVE_HASH_DOMAIN, CHECKPOINT_CURSOR_MANIFEST_HASH_DOMAIN,
    CHECKPOINT_EVENT_HASH_DOMAIN, CHECKPOINT_GENESIS_HASH_DOMAIN,
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER,
    COMMON_PROOF_CHECKPOINT_STATE_MAGIC, COMMON_PROOF_CHECKPOINT_STATE_VERSION,
    CanonicalDecodeLimits, CheckpointableCommonProofPrivateCoinSource,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationPoll,
    CommonProofGenerationStage, CommonProofGenerationStateMachine,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource,
    CommonProofRelationPlanCapability, CommonProofRequiredByteRange, CommonProofRuntimeError,
    CommonProofRuntimeLimits, CommonProofSourcePolynomialProvider,
    CommonProofStorageTransactionRuntime, CommonProofVerificationBinding,
    GENERATION_BINDING_HASH_DOMAIN, HASH_BYTE_LENGTH, Hash512,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, PollableCommonProofByteSink,
    PollableCommonProofByteSinkError, PreparedActionProofAttemptSource, ProofApplicationBinding,
    ProofApplicationSlot, ProofApplicationSlotCeilings, ProofExternalMemoryExecutorError,
    ProofExternalMemoryTransactionAdapterError, ProofObjectHeader, RelationProofTreeInput,
    StreamDescriptor, VerifiedBoardApplicationSource, Zeroizing, common_proof_stream_domain,
    hash_framed_parts_512, verified_application_statement_hash,
};
use crate::foundation::{
    PreparedPublicOnlyProofAttemptSource, WitnessBoundPreparedActionProofAttemptSource,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationSourceError {
    PrivateCoinSource,
}

trait ErasedCommonProofPrivateCoinSource {
    fn sample_modulo(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, CommonProofGenerationSourceError>;

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), CommonProofGenerationSourceError>;

    fn checkpoint_cursor_manifest(&self) -> Result<Vec<u8>, CommonProofGenerationSourceError>;

    fn capture_proof_salt_replay_cursor(
        &self,
    ) -> Result<CommonProofPrivateCoinReplayCursor, CommonProofGenerationSourceError>;

    fn restore_proof_salt_replay_cursor(
        &mut self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<(), CommonProofGenerationSourceError>;

    fn proof_salt_replay_cursor_matches(
        &self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<bool, CommonProofGenerationSourceError>;

    fn begin_all_coordinate_replay_span(
        &mut self,
    ) -> Result<CommonProofPrivateCoinReplaySpanStart, CommonProofGenerationSourceError>;

    fn finish_all_coordinate_replay_span(
        &mut self,
        start: CommonProofPrivateCoinReplaySpanStart,
    ) -> Result<CommonProofPrivateCoinReplaySpan, CommonProofGenerationSourceError>;

    fn restore_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), CommonProofGenerationSourceError>;

    fn complete_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), CommonProofGenerationSourceError>;

    fn invalidate_all_coordinate_replay_state(&mut self);
}

struct ErasedCommonProofPrivateCoinSourceAdapter<Source>(Source);

impl<Source> ErasedCommonProofPrivateCoinSource
    for ErasedCommonProofPrivateCoinSourceAdapter<Source>
where
    Source: CheckpointableCommonProofPrivateCoinSource
        + ReplayableCommonProofPrivateCoinCatalogSource
        + ReplayableCommonProofPrivateCoinSource,
{
    fn sample_modulo(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, CommonProofGenerationSourceError> {
        self.0
            .sample_modulo(coordinate, modulus, maximum_candidate_draws_per_output)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), CommonProofGenerationSourceError> {
        self.0
            .fill_raw_bytes(coordinate, destination)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn checkpoint_cursor_manifest(&self) -> Result<Vec<u8>, CommonProofGenerationSourceError> {
        self.0
            .checkpoint_cursor_manifest()
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn capture_proof_salt_replay_cursor(
        &self,
    ) -> Result<CommonProofPrivateCoinReplayCursor, CommonProofGenerationSourceError> {
        self.0
            .capture_proof_salt_replay_cursor()
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn restore_proof_salt_replay_cursor(
        &mut self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<(), CommonProofGenerationSourceError> {
        self.0
            .restore_proof_salt_replay_cursor(replay_cursor)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn proof_salt_replay_cursor_matches(
        &self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<bool, CommonProofGenerationSourceError> {
        self.0
            .proof_salt_replay_cursor_matches(replay_cursor)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn begin_all_coordinate_replay_span(
        &mut self,
    ) -> Result<CommonProofPrivateCoinReplaySpanStart, CommonProofGenerationSourceError> {
        self.0
            .begin_all_coordinate_replay_span()
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn finish_all_coordinate_replay_span(
        &mut self,
        start: CommonProofPrivateCoinReplaySpanStart,
    ) -> Result<CommonProofPrivateCoinReplaySpan, CommonProofGenerationSourceError> {
        self.0
            .finish_all_coordinate_replay_span(start)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn restore_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), CommonProofGenerationSourceError> {
        self.0
            .restore_all_coordinate_replay_span(span)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn complete_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), CommonProofGenerationSourceError> {
        self.0
            .complete_all_coordinate_replay_span(span)
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn invalidate_all_coordinate_replay_state(&mut self) {
        self.0.invalidate_all_coordinate_replay_state();
    }
}

struct CommonProofWorkerPrivateCoinSource(Box<dyn ErasedCommonProofPrivateCoinSource>);

impl CommonProofWorkerPrivateCoinSource {
    fn checkpoint_cursor_manifest(&self) -> Result<Vec<u8>, CommonProofGenerationSourceError> {
        self.0.checkpoint_cursor_manifest()
    }
}

impl CommonProofPrivateCoinSource for CommonProofWorkerPrivateCoinSource {
    type Error = CommonProofGenerationSourceError;

    fn sample_modulo(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        self.0
            .sample_modulo(coordinate, modulus, maximum_candidate_draws_per_output)
    }

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.0.fill_raw_bytes(coordinate, destination)
    }
}

impl ReplayableCommonProofPrivateCoinSource for CommonProofWorkerPrivateCoinSource {
    fn capture_proof_salt_replay_cursor(
        &self,
    ) -> Result<CommonProofPrivateCoinReplayCursor, Self::Error> {
        self.0.capture_proof_salt_replay_cursor()
    }

    fn restore_proof_salt_replay_cursor(
        &mut self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<(), Self::Error> {
        self.0.restore_proof_salt_replay_cursor(replay_cursor)
    }

    fn proof_salt_replay_cursor_matches(
        &self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<bool, Self::Error> {
        self.0.proof_salt_replay_cursor_matches(replay_cursor)
    }
}

impl ReplayableCommonProofPrivateCoinCatalogSource for CommonProofWorkerPrivateCoinSource {
    fn begin_all_coordinate_replay_span(
        &mut self,
    ) -> Result<CommonProofPrivateCoinReplaySpanStart, Self::Error> {
        self.0.begin_all_coordinate_replay_span()
    }

    fn finish_all_coordinate_replay_span(
        &mut self,
        start: CommonProofPrivateCoinReplaySpanStart,
    ) -> Result<CommonProofPrivateCoinReplaySpan, Self::Error> {
        self.0.finish_all_coordinate_replay_span(start)
    }

    fn restore_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        self.0.restore_all_coordinate_replay_span(span)
    }

    fn complete_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        self.0.complete_all_coordinate_replay_span(span)
    }

    fn invalidate_all_coordinate_replay_state(&mut self) {
        self.0.invalidate_all_coordinate_replay_state();
    }
}

/// Owned exact-family sources used by one generated proof. Source errors are
/// collapsed only to the private-randomness authority boundary. The host
/// cannot install the source through FFI.
pub(crate) struct CommonProofGenerationSources {
    private_coins: CommonProofWorkerPrivateCoinSource,
    source_polynomial_provider: Option<Box<dyn CommonProofSourcePolynomialProvider>>,
}

impl CommonProofGenerationSources {
    pub(crate) fn new<Coins, SourcePolynomials>(
        private_coins: Coins,
        source_polynomial_provider: SourcePolynomials,
    ) -> Self
    where
        Coins: CheckpointableCommonProofPrivateCoinSource
            + ReplayableCommonProofPrivateCoinCatalogSource
            + ReplayableCommonProofPrivateCoinSource
            + 'static,
        SourcePolynomials: CommonProofSourcePolynomialProvider + 'static,
    {
        Self {
            private_coins: CommonProofWorkerPrivateCoinSource(Box::new(
                ErasedCommonProofPrivateCoinSourceAdapter(private_coins),
            )),
            source_polynomial_provider: Some(Box::new(source_polynomial_provider)),
        }
    }

    pub(crate) fn public_only<SourcePolynomials>(
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_lineage: [u8; 32],
        source_polynomial_provider: SourcePolynomials,
    ) -> Result<Self, CommonProofGenerationSourceError>
    where
        SourcePolynomials: CommonProofSourcePolynomialProvider + 'static,
    {
        if !ProofApplicationSlotCeilings::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS
            .contains(&family_schema_identifier)
        {
            return Err(CommonProofGenerationSourceError::PrivateCoinSource);
        }
        let public_only_coins = PublicOnlyCommonProofCoinSource::new(
            family_schema_identifier,
            derivation_binding_hash,
            attempt_lineage,
        )
        .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)?;
        Ok(Self::new(public_only_coins, source_polynomial_provider))
    }

    fn take_source_polynomial_provider(
        &mut self,
    ) -> Result<Box<dyn CommonProofSourcePolynomialProvider>, CommonProofRuntimeError> {
        self.source_polynomial_provider
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }
}

/// Nonforgeable authorization for one exact generation attempt before any
/// proof bytes exist. Terminal stream coordinates are deliberately absent:
/// the generated proof's descriptor is derived only after authenticated
/// output readback completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofGenerationAuthorization {
    protocol_version: u16,
    suite_identifier: [u8; HASH_BYTE_LENGTH],
    ceremony_context_hash: [u8; HASH_BYTE_LENGTH],
    action_context_hash: [u8; HASH_BYTE_LENGTH],
    application_slot: ProofApplicationSlot,
    proof_application_slot_hash: [u8; HASH_BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; HASH_BYTE_LENGTH],
    proof_header_hash: [u8; HASH_BYTE_LENGTH],
    relation_plan_hash: [u8; HASH_BYTE_LENGTH],
    attempt_identifier: [u8; 32],
    checkpoint_lineage_identifier: [u8; 32],
    checkpoint_schedule_digest: Hash512,
    checkpoint_next_event_index: u64,
    checkpoint_cumulative_event_digest: Hash512,
}

impl CommonProofGenerationAuthorization {
    pub(crate) fn from_witness_bound_authenticated_attempt(
        attempt_source: WitnessBoundPreparedActionProofAttemptSource,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        Self::from_attempt_fields(
            CommonProofGenerationAttemptFields::from_witness_bound(attempt_source),
            relation_plan,
            protocol_version,
            canonical_application_statement_bytes,
            limits,
        )
    }

    pub(crate) fn from_ordinary_authenticated_attempt(
        attempt_source: PreparedActionProofAttemptSource,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        if attempt_source.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Self::from_attempt_fields(
            CommonProofGenerationAttemptFields::from_ordinary(attempt_source),
            relation_plan,
            protocol_version,
            canonical_application_statement_bytes,
            limits,
        )
    }

    pub(crate) fn from_public_only_authenticated_attempt(
        attempt_source: PreparedPublicOnlyProofAttemptSource,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        if !ProofApplicationSlotCeilings::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS
            .contains(&attempt_source.application_statement_schema_identifier())
            || relation_plan.application_statement_schema_identifier()
                != attempt_source.application_statement_schema_identifier()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Self::from_attempt_fields(
            CommonProofGenerationAttemptFields::from_public_only(attempt_source),
            relation_plan,
            protocol_version,
            canonical_application_statement_bytes,
            limits,
        )
    }

    fn from_attempt_fields(
        attempt_source: CommonProofGenerationAttemptFields,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        let application_slot = attempt_source.application_slot;
        let proof_application_slot_hash = application_slot
            .hash()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
            .into_bytes();
        let application_statement_schema_identifier =
            application_slot.application_statement_schema_identifier();
        let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
            canonical_application_statement_bytes.to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .and_then(|header| header.proof_header_hash())
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
        .into_bytes();
        let application_statement_hash = verified_application_statement_hash(
            protocol_version,
            application_slot.suite_identifier().into_bytes(),
            application_statement_schema_identifier,
            canonical_application_statement_bytes,
        );
        let proof_query_count = relation_plan.proof_query_count()?;
        if protocol_version == 0
            || common_proof_stream_domain(application_statement_schema_identifier).is_none()
            || proof_application_slot_hash != attempt_source.application_slot_hash.into_bytes()
            || application_statement_schema_identifier
                != attempt_source.application_statement_schema_identifier
            || application_statement_hash != attempt_source.application_statement_hash.into_bytes()
            || limits.proof_byte_length() as u64 != attempt_source.expected_proof_byte_length
            || proof_query_count != attempt_source.expected_query_count
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let checkpoint = attempt_source.checkpoint_continuation;
        Ok(Self {
            protocol_version,
            suite_identifier: application_slot.suite_identifier().into_bytes(),
            ceremony_context_hash: application_slot.ceremony_context_hash().into_bytes(),
            action_context_hash: application_slot.action_context_hash().into_bytes(),
            application_slot,
            proof_application_slot_hash,
            application_statement_schema_identifier,
            application_statement_hash,
            proof_header_hash,
            relation_plan_hash: relation_plan.relation_plan_hash(),
            attempt_identifier: attempt_source.attempt_identifier,
            checkpoint_lineage_identifier: checkpoint.checkpoint_lineage_identifier(),
            checkpoint_schedule_digest: checkpoint.checkpoint_schedule_digest(),
            checkpoint_next_event_index: checkpoint.next_event_index(),
            checkpoint_cumulative_event_digest: checkpoint.cumulative_event_digest(),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_genuine_test_application(
        protocol_version: u16,
        application_slot: ProofApplicationSlot,
        application_statement_hash: [u8; HASH_BYTE_LENGTH],
        proof_header_hash: [u8; HASH_BYTE_LENGTH],
        relation_plan_hash: [u8; HASH_BYTE_LENGTH],
    ) -> Result<Self, CommonProofRuntimeError> {
        if protocol_version == 0
            || common_proof_stream_domain(
                application_slot.application_statement_schema_identifier(),
            )
            .is_none()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(Self {
            protocol_version,
            suite_identifier: application_slot.suite_identifier().into_bytes(),
            ceremony_context_hash: application_slot.ceremony_context_hash().into_bytes(),
            action_context_hash: application_slot.action_context_hash().into_bytes(),
            application_slot,
            proof_application_slot_hash: application_slot
                .hash()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
                .into_bytes(),
            application_statement_schema_identifier: application_slot
                .application_statement_schema_identifier(),
            application_statement_hash,
            proof_header_hash,
            relation_plan_hash,
            attempt_identifier: [0x91; 32],
            checkpoint_lineage_identifier: [0x92; 32],
            checkpoint_schedule_digest: Hash512::from_bytes([0x93; HASH_BYTE_LENGTH]),
            checkpoint_next_event_index: 0,
            checkpoint_cumulative_event_digest: Hash512::from_bytes([0_u8; HASH_BYTE_LENGTH]),
        })
    }

    pub(crate) fn binding_hash(self) -> [u8; HASH_BYTE_LENGTH] {
        hash_framed_parts_512(
            GENERATION_BINDING_HASH_DOMAIN,
            &[
                &self.protocol_version.to_le_bytes(),
                &self.suite_identifier,
                &self.ceremony_context_hash,
                &self.action_context_hash,
                &self.proof_application_slot_hash,
                &self.application_statement_schema_identifier.to_le_bytes(),
                &self.application_statement_hash,
                &self.proof_header_hash,
                &self.relation_plan_hash,
                &self.attempt_identifier,
                &self.checkpoint_lineage_identifier,
                &self.checkpoint_schedule_digest.into_bytes(),
            ],
        )
    }

    fn derive_post_output_binding(
        self,
        relation_plan: &CommonProofRelationPlanCapability,
        stream_descriptor: &StreamDescriptor,
    ) -> Result<CommonProofPostOutputApplicationBinding, CommonProofRuntimeError> {
        if relation_plan.relation_plan_hash() != self.relation_plan_hash
            || stream_descriptor.total_byte_length == 0
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let proof_stream_domain =
            common_proof_stream_domain(self.application_statement_schema_identifier)
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let canonical_binding = ProofApplicationBinding::new(
            self.application_slot,
            Hash512::from_bytes(self.proof_header_hash),
            stream_descriptor.clone(),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let canonical_binding_bytes = canonical_binding
            .encode()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let canonical_binding_hash = hash_framed_parts_512(
            CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
            &[&canonical_binding_bytes],
        );
        let proof_application = super::CommonProofApplicationBinding::new(
            self.proof_application_slot_hash,
            canonical_binding_hash,
            self.application_statement_schema_identifier,
            self.proof_header_hash,
            proof_stream_domain,
            stream_descriptor.full_object_digest.into_bytes(),
            stream_descriptor.total_byte_length,
            relation_plan.proof_query_count()?,
        )?;
        Ok(CommonProofPostOutputApplicationBinding {
            authorization: self,
            proof_application,
        })
    }
}

#[derive(Clone, Copy)]
struct CommonProofGenerationAttemptFields {
    application_slot: ProofApplicationSlot,
    application_slot_hash: Hash512,
    application_statement_schema_identifier: u16,
    application_statement_hash: Hash512,
    expected_proof_byte_length: u64,
    expected_query_count: u32,
    attempt_identifier: [u8; 32],
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
}

impl CommonProofGenerationAttemptFields {
    const fn from_witness_bound(source: WitnessBoundPreparedActionProofAttemptSource) -> Self {
        Self {
            application_slot: source.application_slot(),
            application_slot_hash: source.application_slot_hash(),
            application_statement_schema_identifier: source
                .application_statement_schema_identifier(),
            application_statement_hash: source.application_statement_hash(),
            expected_proof_byte_length: source.expected_proof_byte_length(),
            expected_query_count: source.expected_query_count(),
            attempt_identifier: source.attempt_identifier(),
            checkpoint_continuation: *source.checkpoint_continuation(),
        }
    }

    const fn from_ordinary(source: PreparedActionProofAttemptSource) -> Self {
        Self {
            application_slot: source.application_slot(),
            application_slot_hash: source.application_slot_hash(),
            application_statement_schema_identifier: source
                .application_statement_schema_identifier(),
            application_statement_hash: source.application_statement_hash(),
            expected_proof_byte_length: source.expected_proof_byte_length(),
            expected_query_count: source.expected_query_count(),
            attempt_identifier: source.attempt_identifier(),
            checkpoint_continuation: *source.checkpoint_continuation(),
        }
    }

    const fn from_public_only(source: PreparedPublicOnlyProofAttemptSource) -> Self {
        Self {
            application_slot: source.application_slot(),
            application_slot_hash: source.application_slot_hash(),
            application_statement_schema_identifier: source
                .application_statement_schema_identifier(),
            application_statement_hash: source.application_statement_hash(),
            expected_proof_byte_length: source.expected_proof_byte_length(),
            expected_query_count: source.expected_query_count(),
            attempt_identifier: source.attempt_lineage_identifier(),
            checkpoint_continuation: *source.checkpoint_continuation(),
        }
    }
}

/// Authenticated terminal application coordinates derived only from the
/// generated stream descriptor. The final object hash joins the binding only
/// after board ingestion positively verifies the exact application slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofPostOutputApplicationBinding {
    authorization: CommonProofGenerationAuthorization,
    proof_application: super::CommonProofApplicationBinding,
}

impl CommonProofPostOutputApplicationBinding {
    pub(crate) fn bind_verified_board_source(
        self,
        board_source: &VerifiedBoardApplicationSource,
    ) -> Result<CommonProofVerificationBinding, CommonProofRuntimeError> {
        let application_slot = self.authorization.application_slot;
        if board_source.suite_identifier().into_bytes() != self.authorization.suite_identifier
            || board_source.ceremony_context_hash().into_bytes()
                != self.authorization.ceremony_context_hash
            || board_source.action_context_hash().into_bytes()
                != self.authorization.action_context_hash
            || board_source.producer_roster_position() != application_slot.roster_position()
            || application_slot
                .producer_sequence()
                .is_some_and(|sequence| sequence != board_source.producer_sequence())
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(CommonProofVerificationBinding::new(
            self.authorization.suite_identifier,
            self.authorization.ceremony_context_hash,
            self.authorization.action_context_hash,
            board_source.object_hash().into_bytes(),
            self.proof_application,
            self.authorization.relation_plan_hash,
        ))
    }

    fn bind_verified_application_source_authority(
        self,
        application_source_authority: &super::VerifiedCommonProofApplicationSourceAuthority,
    ) -> Result<CommonProofVerificationBinding, CommonProofRuntimeError> {
        let application_slot = self.authorization.application_slot;
        if application_source_authority.suite_identifier().into_bytes()
            != self.authorization.suite_identifier
            || application_source_authority
                .ceremony_context_hash()
                .into_bytes()
                != self.authorization.ceremony_context_hash
            || application_source_authority
                .action_context_hash()
                .into_bytes()
                != self.authorization.action_context_hash
            || application_source_authority.application_statement_schema_identifier()
                != self.authorization.application_statement_schema_identifier
            || application_source_authority.producer_roster_position()
                != application_slot.roster_position()
            || application_source_authority.schedule_position()
                != application_slot.schedule_position()
            || application_source_authority.producer_sequence()
                != application_slot.producer_sequence()
            || application_source_authority
                .proof_stream_descriptor()
                .full_object_digest
                .into_bytes()
                != self.proof_application.proof_stream_full_object_digest
            || application_source_authority
                .proof_stream_descriptor()
                .total_byte_length
                != self.proof_application.proof_byte_length
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(CommonProofVerificationBinding::new(
            self.authorization.suite_identifier,
            self.authorization.ceremony_context_hash,
            self.authorization.action_context_hash,
            application_source_authority
                .application_source_object_hash()
                .into_bytes(),
            self.proof_application,
            self.authorization.relation_plan_hash,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommonProofGenerationBinding {
    authorization: CommonProofGenerationAuthorization,
    checkpoint_next_event_index: u64,
    checkpoint_cumulative_event_digest: Hash512,
}

impl CommonProofGenerationBinding {
    fn from_authorization(authorization: CommonProofGenerationAuthorization) -> Self {
        let mut binding = Self {
            authorization,
            checkpoint_next_event_index: authorization.checkpoint_next_event_index,
            checkpoint_cumulative_event_digest: authorization.checkpoint_cumulative_event_digest,
        };
        if binding.checkpoint_next_event_index == 0
            && binding.checkpoint_cumulative_event_digest.into_bytes() == [0_u8; HASH_BYTE_LENGTH]
        {
            binding.checkpoint_cumulative_event_digest =
                Hash512::from_bytes(binding.checkpoint_genesis_digest());
        }
        binding
    }

    /// Stable same-attempt binding for scratch objects and checkpoint replay.
    /// The mutable checkpoint position is deliberately excluded so a resumed
    /// operation addresses the same deterministic transaction namespace.
    fn binding_hash(self) -> [u8; HASH_BYTE_LENGTH] {
        self.authorization.binding_hash()
    }

    fn checkpoint_genesis_digest(self) -> [u8; HASH_BYTE_LENGTH] {
        hash_framed_parts_512(
            CHECKPOINT_GENESIS_HASH_DOMAIN,
            &[
                &self.binding_hash(),
                &self.authorization.checkpoint_lineage_identifier,
                &self.authorization.checkpoint_schedule_digest.into_bytes(),
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

    pub(crate) fn generation_authorization_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.binding.authorization.binding_hash()
    }

    pub(crate) const fn proof_attempt_lineage_identifier(&self) -> [u8; 32] {
        self.binding.authorization.attempt_identifier
    }

    pub(crate) const fn checkpoint_lineage_identifier(&self) -> [u8; 32] {
        self.binding.authorization.checkpoint_lineage_identifier
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        self.binding.authorization.checkpoint_schedule_digest
    }

    pub(crate) fn matches_authenticated_checkpoint(
        &self,
        checkpoint: &AuthenticatedCommonProofGenerationCheckpoint,
    ) -> bool {
        checkpoint.state.matches_binding(self.binding)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_exact_family_sources(
        authorization: CommonProofGenerationAuthorization,
        relation_plan: CommonProofRelationPlanCapability,
        canonical_application_statement_bytes: Vec<u8>,
        relation_trees: Vec<RelationProofTreeInput>,
        limits: CommonProofRuntimeLimits,
        mut sources: CommonProofGenerationSources,
    ) -> Result<Self, CommonProofGenerationPreparationError> {
        let binding = CommonProofGenerationBinding::from_authorization(authorization);
        if relation_plan.relation_plan_hash() != authorization.relation_plan_hash
            || verified_application_statement_hash(
                authorization.protocol_version,
                authorization.suite_identifier,
                authorization.application_statement_schema_identifier,
                &canonical_application_statement_bytes,
            ) != authorization.application_statement_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        let state = CommonProofGenerationStateMachine::new(relation_plan.generation_input(
            authorization.protocol_version,
            authorization.suite_identifier,
            &canonical_application_statement_bytes,
            relation_trees,
            sources.take_source_polynomial_provider()?,
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
        authorization: CommonProofGenerationAuthorization,
        relation_plan: CommonProofRelationPlanCapability,
        state: CommonProofGenerationStateMachine,
        sources: CommonProofGenerationSources,
        limits: CommonProofRuntimeLimits,
    ) -> Self {
        Self {
            binding: CommonProofGenerationBinding::from_authorization(authorization),
            relation_plan,
            state,
            sources,
            limits,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_genuine_test_sources_for_authenticated_checkpoint(
        authorization: CommonProofGenerationAuthorization,
        relation_plan: CommonProofRelationPlanCapability,
        state: CommonProofGenerationStateMachine,
        sources: CommonProofGenerationSources,
        limits: CommonProofRuntimeLimits,
        authenticated_checkpoint_state: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        let checkpoint =
            CommonProofGenerationCheckpointState::decode(authenticated_checkpoint_state)?;
        let mut binding = CommonProofGenerationBinding::from_authorization(authorization);
        if checkpoint.stable_attempt_binding_hash != binding.binding_hash()
            || checkpoint.checkpoint_lineage_identifier
                != binding.authorization.checkpoint_lineage_identifier
            || checkpoint.checkpoint_schedule_digest
                != binding
                    .authorization
                    .checkpoint_schedule_digest
                    .into_bytes()
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
>;

#[derive(Debug)]
pub(crate) enum CommonProofGenerationWorkerError {
    Runtime(CommonProofRuntimeError),
    AuthenticatedSource(CommonProofProverError),
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
    AuthenticatedSourceReadReady {
        source_byte_length: u32,
        authentication_chunk_index: u32,
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
    pub(super) cursor_manifest_digest: [u8; HASH_BYTE_LENGTH],
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
        append_checkpoint_state_bytes(&mut output, &mut cursor, &self.cursor_manifest_digest);
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
            cursor_manifest_digest: read_checkpoint_state_array(bytes, &mut cursor)?,
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
            && self.checkpoint_lineage_identifier
                == binding.authorization.checkpoint_lineage_identifier
            && self.checkpoint_schedule_digest
                == binding
                    .authorization
                    .checkpoint_schedule_digest
                    .into_bytes()
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
    cursor_manifest_bytes: Vec<u8>,
}

impl PendingCommonProofGenerationCheckpoint {
    pub(super) fn encoded_state(&self) -> &[u8] {
        &self.encoded_state
    }

    pub(super) fn safe_boundary_ordinal(&self) -> u32 {
        self.state.safe_boundary_ordinal
    }

    pub(super) fn cursor_manifest_bytes(&self) -> &[u8] {
        &self.cursor_manifest_bytes
    }
}

/// Exact checkpoint custody live set layered on the plan-derived private-coin
/// manifest requirement. It keeps the fixed encoded state, decoded state
/// owner, and `Vec` owner in the runtime module that actually owns them, so
/// selected accounting cannot silently omit or duplicate these bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofGenerationCheckpointCustodyRequirement {
    cursor_manifest_requirement: CommonProofCheckpointCursorManifestRequirement,
    encoded_state_byte_length: u32,
    decoded_state_owner_byte_length: u32,
    pending_checkpoint_fixed_owner_byte_length: u32,
    transient_construction_resident_byte_ceiling: u64,
    pending_checkpoint_resident_byte_ceiling: u64,
    boundary_peak_additional_resident_byte_ceiling: u64,
    restore_workspace_byte_ceiling: u64,
    peak_copied_buffer_byte_length: u32,
}

impl CommonProofGenerationCheckpointCustodyRequirement {
    pub(crate) const fn cursor_manifest_requirement(
        self,
    ) -> CommonProofCheckpointCursorManifestRequirement {
        self.cursor_manifest_requirement
    }

    pub(crate) const fn encoded_state_byte_length(self) -> u32 {
        self.encoded_state_byte_length
    }

    pub(crate) const fn decoded_state_owner_byte_length(self) -> u32 {
        self.decoded_state_owner_byte_length
    }

    pub(crate) const fn pending_checkpoint_fixed_owner_byte_length(self) -> u32 {
        self.pending_checkpoint_fixed_owner_byte_length
    }

    pub(crate) const fn transient_construction_resident_byte_ceiling(self) -> u64 {
        self.transient_construction_resident_byte_ceiling
    }

    pub(crate) const fn pending_checkpoint_resident_byte_ceiling(self) -> u64 {
        self.pending_checkpoint_resident_byte_ceiling
    }

    pub(crate) const fn boundary_peak_additional_resident_byte_ceiling(self) -> u64 {
        self.boundary_peak_additional_resident_byte_ceiling
    }

    pub(crate) const fn restore_workspace_byte_ceiling(self) -> u64 {
        self.restore_workspace_byte_ceiling
    }

    pub(crate) const fn peak_copied_buffer_byte_length(self) -> u32 {
        self.peak_copied_buffer_byte_length
    }

    pub(crate) const fn fits_absolute_bounds(self) -> bool {
        self.cursor_manifest_requirement.fits_absolute_bounds()
            && self.boundary_peak_additional_resident_byte_ceiling
                <= super::super::MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
            && self.peak_copied_buffer_byte_length
                <= super::MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH as u32
    }
}

pub(crate) fn common_proof_generation_checkpoint_custody_requirement_for_variant(
    variant: &RelationPlanVariant,
) -> Result<
    CommonProofGenerationCheckpointCustodyRequirement,
    CommonProofCheckpointCursorManifestError,
> {
    let cursor_manifest_requirement =
        common_proof_checkpoint_cursor_manifest_requirement_for_variant(variant)?;
    let encoded_state_byte_length = u32::try_from(COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH)
        .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let decoded_state_owner_byte_length =
        u32::try_from(core::mem::size_of::<CommonProofGenerationCheckpointState>())
            .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let pending_checkpoint_fixed_owner_byte_length =
        u32::try_from(core::mem::size_of::<PendingCommonProofGenerationCheckpoint>())
            .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let manifest_vector_owner_byte_length = u64::try_from(core::mem::size_of::<Vec<u8>>())
        .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let transient_construction_resident_byte_ceiling = cursor_manifest_requirement
        .peak_additional_resident_byte_ceiling()
        .checked_add(u64::from(decoded_state_owner_byte_length))
        .and_then(|bytes| bytes.checked_add(u64::from(encoded_state_byte_length)))
        .and_then(|bytes| bytes.checked_add(manifest_vector_owner_byte_length))
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let pending_checkpoint_resident_byte_ceiling = cursor_manifest_requirement
        .retained_cursor_state_byte_ceiling()
        .checked_add(u64::from(
            cursor_manifest_requirement.pending_manifest_resident_byte_ceiling(),
        ))
        .and_then(|bytes| bytes.checked_add(u64::from(pending_checkpoint_fixed_owner_byte_length)))
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let boundary_peak_additional_resident_byte_ceiling =
        transient_construction_resident_byte_ceiling.max(pending_checkpoint_resident_byte_ceiling);
    let restore_workspace_byte_ceiling = cursor_manifest_requirement
        .restore_workspace_byte_ceiling()
        .checked_add(u64::from(decoded_state_owner_byte_length))
        .and_then(|bytes| bytes.checked_add(manifest_vector_owner_byte_length))
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let peak_copied_buffer_byte_length = cursor_manifest_requirement
        .peak_copied_buffer_byte_length()
        .max(encoded_state_byte_length);
    Ok(CommonProofGenerationCheckpointCustodyRequirement {
        cursor_manifest_requirement,
        encoded_state_byte_length,
        decoded_state_owner_byte_length,
        pending_checkpoint_fixed_owner_byte_length,
        transient_construction_resident_byte_ceiling,
        pending_checkpoint_resident_byte_ceiling,
        boundary_peak_additional_resident_byte_ceiling,
        restore_workspace_byte_ceiling,
        peak_copied_buffer_byte_length,
    })
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

    let cursor_manifest_bytes = private_coins
        .checkpoint_cursor_manifest()
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let cursor_manifest_digest = hash_framed_parts_512(
        CHECKPOINT_CURSOR_MANIFEST_HASH_DOMAIN,
        &[&cursor_manifest_bytes],
    );
    let safe_boundary_ordinal = boundary.safe_boundary_ordinal();
    let position = boundary.position();
    let committed_state_digest = boundary.committed_state_digest();
    let event_digest = hash_framed_parts_512(
        CHECKPOINT_EVENT_HASH_DOMAIN,
        &[
            &binding.binding_hash(),
            &binding
                .authorization
                .checkpoint_schedule_digest
                .into_bytes(),
            &previous_next_event_index.to_le_bytes(),
            &safe_boundary_ordinal.to_le_bytes(),
            &position,
            &committed_state_digest,
            &cursor_manifest_digest,
            &0_u64.to_le_bytes(),
        ],
    );
    let cumulative_event_digest = hash_framed_parts_512(
        CHECKPOINT_CUMULATIVE_HASH_DOMAIN,
        &[&previous_cumulative_event_digest, &event_digest],
    );
    let state = CommonProofGenerationCheckpointState {
        stable_attempt_binding_hash: binding.binding_hash(),
        checkpoint_lineage_identifier: binding.authorization.checkpoint_lineage_identifier,
        checkpoint_schedule_digest: binding
            .authorization
            .checkpoint_schedule_digest
            .into_bytes(),
        next_event_index,
        cumulative_event_digest,
        safe_boundary_ordinal,
        position,
        committed_state_digest,
        cursor_manifest_digest,
    };
    Ok(PendingCommonProofGenerationCheckpoint {
        encoded_state: state.encode(),
        state,
        cursor_manifest_bytes,
    })
}

pub(super) struct GeneratedCommonProof {
    binding: CommonProofGenerationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    stream_descriptor: StreamDescriptor,
    post_output_binding: CommonProofPostOutputApplicationBinding,
}

/// Process-local production scratch accounting retained until the generation
/// operation is consumed. It is available only to manual runtime evidence and
/// is never serialized or bound into a proof, capability, or package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofGenerationExternalMemoryAccounting {
    compiled_requirement: CommonProofExternalMemoryRequirement,
    actual_usage: ProofExternalMemoryUsage,
    deterministic_prefix_replay_usage: Option<ProofExternalMemoryUsage>,
}

impl CommonProofGenerationExternalMemoryAccounting {
    pub(crate) const fn compiled_requirement(self) -> CommonProofExternalMemoryRequirement {
        self.compiled_requirement
    }

    pub(crate) const fn actual_usage(self) -> ProofExternalMemoryUsage {
        self.actual_usage
    }

    pub(crate) const fn deterministic_prefix_replay_usage(
        self,
    ) -> Option<ProofExternalMemoryUsage> {
        self.deterministic_prefix_replay_usage
    }
}

impl GeneratedCommonProof {
    /// Checks the exact family statement and application coordinates retained
    /// beside a prepackage proof without joining a package source or consuming
    /// the generated capability. The returned descriptor was derived from the
    /// authenticated output readback, never from host accounting.
    pub(super) fn preflight_pending_statement(
        &self,
        expected_application_statement_schema_identifier: u16,
        expected_roster_position: Option<u16>,
        expected_schedule_position: Option<u32>,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        let authorization = self.binding.authorization;
        let application_slot = authorization.application_slot;
        let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
            canonical_application_statement_bytes.to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .and_then(|header| header.proof_header_hash())
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
        .into_bytes();
        if authorization.application_statement_schema_identifier
            != expected_application_statement_schema_identifier
            || application_slot.roster_position() != expected_roster_position
            || application_slot.schedule_position() != expected_schedule_position
            || application_slot.producer_sequence().is_some()
            || verified_application_statement_hash(
                authorization.protocol_version,
                authorization.suite_identifier,
                authorization.application_statement_schema_identifier,
                canonical_application_statement_bytes,
            ) != authorization.application_statement_hash
            || proof_header_hash != authorization.proof_header_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(self.stream_descriptor.clone())
    }

    /// Extends the pending-statement check with the ceremony bindings owned
    /// by a canonical package builder. Selected setup statements intentionally
    /// omit these outer transcript coordinates, so the builder must compare
    /// them against the prover authorization separately.
    pub(super) fn preflight_pending_package(
        &self,
        expected_suite_identifier: [u8; HASH_BYTE_LENGTH],
        expected_ceremony_context_hash: [u8; HASH_BYTE_LENGTH],
        expected_action_context_hash: [u8; HASH_BYTE_LENGTH],
        expected_application_statement_schema_identifier: u16,
        expected_roster_position: Option<u16>,
        expected_schedule_position: Option<u32>,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        let descriptor = self.preflight_pending_statement(
            expected_application_statement_schema_identifier,
            expected_roster_position,
            expected_schedule_position,
            canonical_application_statement_bytes,
        )?;
        let authorization = self.binding.authorization;
        let application_slot = authorization.application_slot;
        if authorization.suite_identifier != expected_suite_identifier
            || application_slot.ceremony_context_hash().into_bytes()
                != expected_ceremony_context_hash
            || application_slot.action_context_hash().into_bytes() != expected_action_context_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(descriptor)
    }

    pub(super) fn bind_verified_board_source(
        &self,
        board_source: &VerifiedBoardApplicationSource,
        board_proof_descriptor: &StreamDescriptor,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<CommonProofVerificationBinding, CommonProofRuntimeError> {
        let authorization = self.binding.authorization;
        let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
            canonical_application_statement_bytes.to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .and_then(|header| header.proof_header_hash())
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
        .into_bytes();
        if &self.stream_descriptor != board_proof_descriptor
            || verified_application_statement_hash(
                authorization.protocol_version,
                authorization.suite_identifier,
                authorization.application_statement_schema_identifier,
                canonical_application_statement_bytes,
            ) != authorization.application_statement_hash
            || proof_header_hash != authorization.proof_header_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.post_output_binding
            .bind_verified_board_source(board_source)
    }

    /// Retires a generated setup proof only after the exact canonical package
    /// descriptor has minted the verifier statement source. This path cannot
    /// fabricate a board carrier for the collective evaluator application.
    pub(super) fn bind_verified_statement_source(
        &self,
        statement_source: &super::VerifiedCommonProofStatementSource,
    ) -> Result<CommonProofVerificationBinding, CommonProofRuntimeError> {
        let authorization = self.binding.authorization;
        let canonical_application_statement_bytes =
            statement_source.canonical_application_statement_bytes();
        let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
            canonical_application_statement_bytes.to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .and_then(|header| header.proof_header_hash())
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
        .into_bytes();
        if self.stream_descriptor
            != *statement_source
                .application_source_authority()
                .proof_stream_descriptor()
            || verified_application_statement_hash(
                authorization.protocol_version,
                authorization.suite_identifier,
                authorization.application_statement_schema_identifier,
                canonical_application_statement_bytes,
            ) != authorization.application_statement_hash
            || proof_header_hash != authorization.proof_header_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let binding = self
            .post_output_binding
            .bind_verified_application_source_authority(
                statement_source.application_source_authority(),
            )?;
        if binding != statement_source.verification_binding() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(binding)
    }
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
    storage: CommonProofStorageTransactionRuntime,
    output: Option<PollableCommonProofByteSink>,
    encoded_storage_request: Option<Zeroizing<Vec<u8>>>,
    terminal_stream_descriptor: Option<StreamDescriptor>,
    checkpoint_next_event_index: u64,
    checkpoint_cumulative_event_digest: [u8; HASH_BYTE_LENGTH],
    last_checkpoint_position: Option<[u8; 16]>,
    pending_checkpoint: Option<PendingCommonProofGenerationCheckpoint>,
    resume_target: Option<CommonProofGenerationCheckpointState>,
    deterministic_prefix_replay_external_memory_usage: Option<ProofExternalMemoryUsage>,
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
        let stream_domain = common_proof_stream_domain(
            prepared
                .binding
                .authorization
                .application_statement_schema_identifier,
        )
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
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
            deterministic_prefix_replay_external_memory_usage: None,
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
        self.encoded_storage_request
            .as_ref()
            .map(|request| request.as_slice())
    }

    pub(super) const fn pending_authenticated_source_read(
        &self,
    ) -> Option<CommonProofAuthenticatedSourceReadRequest> {
        self.state.pending_authenticated_source_read()
    }

    pub(super) fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.state
            .supply_authenticated_source_range(request, authenticated_bytes)
            .map_err(CommonProofGenerationWorkerError::AuthenticatedSource)
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
        if let Some(request) = self.pending_authenticated_source_read() {
            return Ok(
                CommonProofGenerationWorkerPoll::AuthenticatedSourceReadReady {
                    source_byte_length: request.source_byte_length(),
                    authentication_chunk_index: request.authentication_chunk_index(),
                },
            );
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
                self.deterministic_prefix_replay_external_memory_usage = Some(
                    self.state
                        .external_memory_usage()
                        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
                );
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

    pub(super) fn external_memory_accounting(
        &self,
    ) -> Result<CommonProofGenerationExternalMemoryAccounting, CommonProofRuntimeError> {
        if self.cancellation_requested
            || !self.generation_complete
            || self.terminal_stream_descriptor.is_none()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let actual_usage = self
            .state
            .terminal_external_memory_usage()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        Ok(CommonProofGenerationExternalMemoryAccounting {
            compiled_requirement: self.state.external_memory_requirement(),
            actual_usage,
            deterministic_prefix_replay_usage: self
                .deterministic_prefix_replay_external_memory_usage,
        })
    }

    pub(super) fn finish(self) -> Result<GeneratedCommonProof, CommonProofRuntimeError> {
        if self.cancellation_requested || !self.generation_complete {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let stream_descriptor = self
            .terminal_stream_descriptor
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let post_output_binding = self
            .binding
            .authorization
            .derive_post_output_binding(&self.relation_plan, &stream_descriptor)?;
        Ok(GeneratedCommonProof {
            binding: self.binding,
            relation_plan: self.relation_plan,
            stream_descriptor,
            post_output_binding,
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
