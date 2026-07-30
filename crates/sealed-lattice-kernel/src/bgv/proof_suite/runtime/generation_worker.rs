use super::super::prover::{
    COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC, CommonProofExternalMemoryRequirement,
};
use super::super::row_code_whir::{
    ExactSameSecretAuthenticatedTranscriptPrefixRequest, ExactSameSecretFiatShamirBinding,
    ExactSameSecretTranscriptPrefixAuthorityBinding, PreparedExactSameSecretTranscriptPrefix,
    RowCodeWhirGenerationStateMachine, RowCodeWhirTranscriptPrefixAuthority,
};
use super::super::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofProverError, ProofExternalMemoryUsage,
};
#[cfg(test)]
use super::ProofExternalMemoryTransactionRequest;
use super::{
    AuthenticatedCheckpointContinuationSource, CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
    CHECKPOINT_CUMULATIVE_HASH_DOMAIN, CHECKPOINT_CURSOR_MANIFEST_HASH_DOMAIN,
    CHECKPOINT_EVENT_HASH_DOMAIN, CHECKPOINT_GENESIS_HASH_DOMAIN,
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER,
    COMMON_PROOF_CHECKPOINT_STATE_MAGIC, COMMON_PROOF_CHECKPOINT_STATE_VERSION,
    CanonicalDecodeLimits, CheckpointableCommonProofPrivateCoinSource, CommonProofByteSink,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationPoll,
    CommonProofGenerationStage, CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource,
    CommonProofRelationPlanCapability, CommonProofRequiredByteRange, CommonProofRuntimeError,
    CommonProofRuntimeLimits, CommonProofSourcePolynomialProvider,
    CommonProofStorageTransactionRuntime, CommonProofVerificationBinding,
    ExpectedCommonProofPackageBindings, GENERATION_BINDING_HASH_DOMAIN, HASH_BYTE_LENGTH, Hash512,
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

const COMMON_PROOF_GENERATION_CURSOR_MANIFEST_MAGIC: [u8; 8] = *b"SLCGCM01";
const COMMON_PROOF_GENERATION_CURSOR_MANIFEST_VERSION: u16 = 1;
const COMMON_PROOF_GENERATION_CURSOR_MANIFEST_TRANSCRIPT_PRESENT_FLAG: u16 = 1;
const COMMON_PROOF_GENERATION_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH: usize =
    8 + 2 + 2 + 4 + 4 + 4 + HASH_BYTE_LENGTH;
const MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH: usize = 1_048_576;
const MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH: usize = 16 * 1_024;

struct DecodedCommonProofGenerationCursorManifest<'bytes> {
    private_coin_cursor_manifest_bytes: &'bytes [u8],
    transcript_cursor_bytes: &'bytes [u8],
    transcript_cursor_digest: Option<[u8; HASH_BYTE_LENGTH]>,
}

fn encode_common_proof_generation_cursor_manifest(
    private_coin_cursor_manifest_bytes: Vec<u8>,
    transcript_cursor_bytes: &[u8],
    transcript_cursor_digest: Option<[u8; HASH_BYTE_LENGTH]>,
) -> Result<Vec<u8>, CommonProofRuntimeError> {
    let transcript_is_present = !transcript_cursor_bytes.is_empty();
    if private_coin_cursor_manifest_bytes.is_empty()
        || transcript_is_present != transcript_cursor_digest.is_some()
        || transcript_cursor_bytes.len()
            > MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let private_coin_cursor_manifest_byte_length =
        u32::try_from(private_coin_cursor_manifest_bytes.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let transcript_cursor_byte_length = u32::try_from(transcript_cursor_bytes.len())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let total_byte_length = COMMON_PROOF_GENERATION_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
        .checked_add(private_coin_cursor_manifest_bytes.len())
        .and_then(|byte_length| byte_length.checked_add(transcript_cursor_bytes.len()))
        .filter(|byte_length| {
            *byte_length <= MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH
        })
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let total_byte_length_u32 = u32::try_from(total_byte_length)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total_byte_length)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    output.extend_from_slice(&COMMON_PROOF_GENERATION_CURSOR_MANIFEST_MAGIC);
    output.extend_from_slice(&COMMON_PROOF_GENERATION_CURSOR_MANIFEST_VERSION.to_le_bytes());
    output.extend_from_slice(
        &if transcript_is_present {
            COMMON_PROOF_GENERATION_CURSOR_MANIFEST_TRANSCRIPT_PRESENT_FLAG
        } else {
            0
        }
        .to_le_bytes(),
    );
    output.extend_from_slice(&total_byte_length_u32.to_le_bytes());
    output.extend_from_slice(&private_coin_cursor_manifest_byte_length.to_le_bytes());
    output.extend_from_slice(&transcript_cursor_byte_length.to_le_bytes());
    output.extend_from_slice(&transcript_cursor_digest.unwrap_or([0_u8; HASH_BYTE_LENGTH]));
    output.extend_from_slice(&private_coin_cursor_manifest_bytes);
    output.extend_from_slice(transcript_cursor_bytes);
    if output.len() != total_byte_length {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(output)
}

fn decode_common_proof_generation_cursor_manifest(
    manifest_bytes: &[u8],
) -> Result<DecodedCommonProofGenerationCursorManifest<'_>, CommonProofRuntimeError> {
    if manifest_bytes.len() < COMMON_PROOF_GENERATION_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
        || manifest_bytes.len() > MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH
        || manifest_bytes[..8] != COMMON_PROOF_GENERATION_CURSOR_MANIFEST_MAGIC
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let version = u16::from_le_bytes(
        manifest_bytes[8..10]
            .try_into()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
    );
    let flags = u16::from_le_bytes(
        manifest_bytes[10..12]
            .try_into()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
    );
    let total_byte_length = usize::try_from(u32::from_le_bytes(
        manifest_bytes[12..16]
            .try_into()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
    ))
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let private_coin_cursor_manifest_byte_length = usize::try_from(u32::from_le_bytes(
        manifest_bytes[16..20]
            .try_into()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
    ))
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let transcript_cursor_byte_length = usize::try_from(u32::from_le_bytes(
        manifest_bytes[20..24]
            .try_into()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
    ))
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let transcript_cursor_digest: [u8; HASH_BYTE_LENGTH] = manifest_bytes
        [24..24 + HASH_BYTE_LENGTH]
        .try_into()
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let private_coin_cursor_manifest_start =
        COMMON_PROOF_GENERATION_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH;
    let transcript_cursor_start = private_coin_cursor_manifest_start
        .checked_add(private_coin_cursor_manifest_byte_length)
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
    let computed_total_byte_length = transcript_cursor_start
        .checked_add(transcript_cursor_byte_length)
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
    let transcript_is_present =
        flags == COMMON_PROOF_GENERATION_CURSOR_MANIFEST_TRANSCRIPT_PRESENT_FLAG;
    if version != COMMON_PROOF_GENERATION_CURSOR_MANIFEST_VERSION
        || flags & !COMMON_PROOF_GENERATION_CURSOR_MANIFEST_TRANSCRIPT_PRESENT_FLAG != 0
        || total_byte_length != manifest_bytes.len()
        || computed_total_byte_length != total_byte_length
        || private_coin_cursor_manifest_byte_length == 0
        || transcript_cursor_byte_length
            > MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
        || transcript_is_present != (transcript_cursor_byte_length != 0)
        || (!transcript_is_present && transcript_cursor_digest != [0_u8; HASH_BYTE_LENGTH])
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let decoded = DecodedCommonProofGenerationCursorManifest {
        private_coin_cursor_manifest_bytes: &manifest_bytes
            [private_coin_cursor_manifest_start..transcript_cursor_start],
        transcript_cursor_bytes: &manifest_bytes[transcript_cursor_start..],
        transcript_cursor_digest: transcript_is_present.then_some(transcript_cursor_digest),
    };
    if decoded.private_coin_cursor_manifest_bytes.len()
        < COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC.len()
        || decoded.private_coin_cursor_manifest_bytes
            [..COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC.len()]
            != COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(decoded)
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

    fn replay_modulo_samples(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        destination: &mut [u64],
    ) -> Result<(), CommonProofGenerationSourceError>;

    fn checkpoint_cursor_manifest(&self) -> Result<Vec<u8>, CommonProofGenerationSourceError>;
}

struct ErasedCommonProofPrivateCoinSourceAdapter<Source>(Source);

impl<Source> ErasedCommonProofPrivateCoinSource
    for ErasedCommonProofPrivateCoinSourceAdapter<Source>
where
    Source: CheckpointableCommonProofPrivateCoinSource,
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

    fn replay_modulo_samples(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        destination: &mut [u64],
    ) -> Result<(), CommonProofGenerationSourceError> {
        self.0
            .replay_modulo_samples(
                coordinate,
                modulus,
                maximum_candidate_draws_per_output,
                destination,
            )
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
    }

    fn checkpoint_cursor_manifest(&self) -> Result<Vec<u8>, CommonProofGenerationSourceError> {
        self.0
            .checkpoint_cursor_manifest()
            .map_err(|_| CommonProofGenerationSourceError::PrivateCoinSource)
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

    fn replay_modulo_samples(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        destination: &mut [u64],
    ) -> Result<(), Self::Error> {
        self.0.replay_modulo_samples(
            coordinate,
            modulus,
            maximum_candidate_draws_per_output,
            destination,
        )
    }
}

/// Owned exact-family sources used by one generated proof. Source errors are
/// collapsed only to the proof-source authority boundary. The host
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
        Coins: CheckpointableCommonProofPrivateCoinSource + 'static,
        SourcePolynomials: CommonProofSourcePolynomialProvider + 'static,
    {
        Self {
            private_coins: CommonProofWorkerPrivateCoinSource(Box::new(
                ErasedCommonProofPrivateCoinSourceAdapter(private_coins),
            )),
            source_polynomial_provider: Some(Box::new(source_polynomial_provider)),
        }
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
    row_code_whir_construction_plan_identity_hash: [u8; HASH_BYTE_LENGTH],
    attempt_identifier: [u8; 32],
    checkpoint_lineage_identifier: [u8; 32],
    checkpoint_schedule_digest: Hash512,
    checkpoint_next_event_index: u64,
    checkpoint_cumulative_event_digest: Hash512,
}

impl CommonProofGenerationAuthorization {
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) const fn ceremony_context_hash(self) -> [u8; HASH_BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) fn from_witness_bound_authenticated_attempt(
        attempt_source: WitnessBoundPreparedActionProofAttemptSource,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        Self::from_attempt_fields(
            CommonProofGenerationAttemptFields::from_witness_bound(attempt_source),
            relation_plan,
            protocol_version,
            canonical_application_statement_bytes,
        )
    }

    pub(crate) fn from_ordinary_authenticated_attempt(
        attempt_source: PreparedActionProofAttemptSource,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
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
        )
    }

    pub(crate) fn from_public_only_authenticated_attempt(
        attempt_source: PreparedPublicOnlyProofAttemptSource,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
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
        )
    }

    fn from_attempt_fields(
        attempt_source: CommonProofGenerationAttemptFields,
        relation_plan: &CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
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
        if protocol_version == 0
            || common_proof_stream_domain(application_statement_schema_identifier).is_none()
            || proof_application_slot_hash != attempt_source.application_slot_hash.into_bytes()
            || application_statement_schema_identifier
                != attempt_source.application_statement_schema_identifier
            || application_statement_hash != attempt_source.application_statement_hash.into_bytes()
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
            row_code_whir_construction_plan_identity_hash: relation_plan
                .row_code_whir_construction_plan_identity_hash(),
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
        row_code_whir_construction_plan_identity_hash: [u8; HASH_BYTE_LENGTH],
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
            row_code_whir_construction_plan_identity_hash,
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
                &self.row_code_whir_construction_plan_identity_hash,
                &self.attempt_identifier,
                &self.checkpoint_lineage_identifier,
                &self.checkpoint_schedule_digest.into_bytes(),
            ],
        )
    }

    pub(in crate::bgv::proof_suite) fn exact_same_secret_transcript_prefix_authority_binding(
        self,
        canonical_application_statement_bytes: &[u8],
        relation_plan: &CommonProofRelationPlanCapability,
    ) -> Result<ExactSameSecretTranscriptPrefixAuthorityBinding, CommonProofRuntimeError> {
        let fiat_shamir_binding = ExactSameSecretFiatShamirBinding::derive(
            self.protocol_version,
            self.suite_identifier,
            self.ceremony_context_hash,
            self.action_context_hash,
            canonical_application_statement_bytes,
            relation_plan,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if fiat_shamir_binding.proof_application_slot_hash() != self.proof_application_slot_hash
            || fiat_shamir_binding.application_statement_schema_identifier()
                != self.application_statement_schema_identifier
            || fiat_shamir_binding.application_statement_hash() != self.application_statement_hash
            || fiat_shamir_binding.proof_header_hash() != self.proof_header_hash
            || fiat_shamir_binding.relation_plan_hash() != self.relation_plan_hash
            || fiat_shamir_binding.construction_plan_identity_hash()
                != self.row_code_whir_construction_plan_identity_hash
            || self.application_slot.roster_position()
                != Some(fiat_shamir_binding.roster_position())
            || self.application_slot.schedule_position().is_some()
            || self.application_slot.producer_sequence().is_some()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        ExactSameSecretTranscriptPrefixAuthorityBinding::new(
            fiat_shamir_binding,
            self.binding_hash(),
            self.attempt_identifier,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    }

    fn derive_post_output_binding(
        self,
        relation_plan: &CommonProofRelationPlanCapability,
        stream_descriptor: &StreamDescriptor,
    ) -> Result<CommonProofPostOutputApplicationBinding, CommonProofRuntimeError> {
        if relation_plan.relation_plan_hash() != self.relation_plan_hash
            || relation_plan.row_code_whir_construction_plan_identity_hash()
                != self.row_code_whir_construction_plan_identity_hash
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
            relation_plan.row_code_whir_construction_plan_identity_hash(),
            self.application_statement_schema_identifier,
            self.proof_header_hash,
            proof_stream_domain,
            stream_descriptor.full_object_digest.into_bytes(),
            stream_descriptor.total_byte_length,
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
    state: CommonProofGenerationExecutionState,
    sources: CommonProofGenerationSources,
    limits: CommonProofRuntimeLimits,
}

struct CommonProofGenerationExecutionState(RowCodeWhirGenerationStateMachine);

impl CommonProofGenerationExecutionState {
    fn stage(&self) -> CommonProofGenerationStage {
        self.0.stage()
    }

    const fn pending_authenticated_source_read(
        &self,
    ) -> Option<CommonProofAuthenticatedSourceReadRequest> {
        self.0.pending_authenticated_source_read()
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        self.0
            .supply_authenticated_source_range(request, authenticated_bytes)
    }

    fn authenticated_transcript_prefix_request(
        &self,
    ) -> Result<ExactSameSecretAuthenticatedTranscriptPrefixRequest, CommonProofRuntimeError> {
        self.0
            .authenticated_transcript_prefix_request()
            .map_err(|_| CommonProofRuntimeError::WrongOperationPhase)
    }

    fn supply_authenticated_transcript_prefix(
        &mut self,
        prepared: PreparedExactSameSecretTranscriptPrefix,
    ) -> Result<(), CommonProofRuntimeError> {
        self.0
            .supply_authenticated_transcript_prefix(prepared)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    }

    fn external_memory_usage(&self) -> Option<ProofExternalMemoryUsage> {
        self.0.external_memory_usage()
    }

    fn terminal_external_memory_usage(&self) -> Option<ProofExternalMemoryUsage> {
        self.0.terminal_external_memory_usage()
    }

    fn external_memory_requirement(&self) -> Option<CommonProofExternalMemoryRequirement> {
        Some(self.0.external_memory_requirement())
    }

    const fn canonical_output_byte_length(&self) -> Option<usize> {
        self.0.canonical_output_byte_length()
    }

    fn checkpoint_boundary(&self) -> Option<CommonProofGenerationCheckpointBoundary> {
        self.0.checkpoint_boundary()
    }

    fn restore_authenticated_checkpoint_transcript_cursor(
        &mut self,
        canonical_cursor_bytes: &[u8],
        expected_cursor_digest: Option<[u8; HASH_BYTE_LENGTH]>,
    ) -> Result<(), CommonProofRuntimeError> {
        self.0
            .restore_authenticated_checkpoint_transcript_cursor(
                canonical_cursor_bytes,
                expected_cursor_digest,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    }

    fn poll(
        &mut self,
        storage: &mut CommonProofStorageTransactionRuntime,
        coins: &mut CommonProofWorkerPrivateCoinSource,
        sink: &mut RuntimeCommonProofByteSink,
    ) -> Result<CommonProofGenerationPoll, OwnedCommonProofGenerationError> {
        self.0.poll(storage, coins, sink)
    }

    fn cancel(
        &mut self,
        storage: &mut CommonProofStorageTransactionRuntime,
    ) -> Result<(), ProofExternalMemoryExecutorError<ProofExternalMemoryTransactionAdapterError>>
    {
        self.0.cancel(storage)
    }
}

enum RuntimeCommonProofByteSink {
    Pending {
        stream_domain: super::CanonicalStreamDomain,
        limits: CommonProofRuntimeLimits,
    },
    Active(Box<PollableCommonProofByteSink>),
    Cancelled,
}

impl RuntimeCommonProofByteSink {
    fn activate(&mut self, declared_byte_length: usize) -> Result<(), CommonProofRuntimeError> {
        match self {
            Self::Pending {
                stream_domain,
                limits,
            } => {
                let sink = PollableCommonProofByteSink::new(
                    *stream_domain,
                    declared_byte_length,
                    *limits,
                )?;
                *self = Self::Active(Box::new(sink));
                Ok(())
            }
            Self::Active(_) => Ok(()),
            Self::Cancelled => Err(CommonProofRuntimeError::WrongOperationPhase),
        }
    }

    fn pending_chunk(&self) -> Option<(usize, &[u8])> {
        match self {
            Self::Active(sink) => sink.pending_chunk(),
            Self::Pending { .. } | Self::Cancelled => None,
        }
    }

    const fn pending_readback_chunk_index(&self) -> Option<usize> {
        match self {
            Self::Active(sink) => sink.pending_readback_chunk_index(),
            Self::Pending { .. } | Self::Cancelled => None,
        }
    }

    fn acknowledge_pending_chunk(&mut self) -> Result<(), CommonProofRuntimeError> {
        match self {
            Self::Active(sink) => sink.acknowledge_pending_chunk(),
            Self::Pending { .. } | Self::Cancelled => {
                Err(CommonProofRuntimeError::WrongOperationPhase)
            }
        }
    }

    fn confirm_pending_chunk_readback(
        &mut self,
        chunk_index: usize,
        readback_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        match self {
            Self::Active(sink) => sink.confirm_pending_chunk_readback(chunk_index, readback_bytes),
            Self::Pending { .. } | Self::Cancelled => {
                Err(CommonProofRuntimeError::WrongOperationPhase)
            }
        }
    }

    fn final_partial_chunk_is_ready(&self) -> bool {
        matches!(self, Self::Active(sink) if sink.final_partial_chunk_is_ready())
    }

    fn complete_output_is_authenticated(&self) -> bool {
        matches!(self, Self::Active(sink) if sink.complete_output_is_authenticated())
    }

    fn seal_final_chunk(&mut self) -> Result<(), CommonProofRuntimeError> {
        match self {
            Self::Active(sink) => sink.seal_final_chunk(),
            Self::Pending { .. } | Self::Cancelled => {
                Err(CommonProofRuntimeError::WrongOperationPhase)
            }
        }
    }

    fn finish(&mut self) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        let active = match core::mem::replace(self, Self::Cancelled) {
            Self::Active(sink) => sink,
            Self::Pending { .. } | Self::Cancelled => {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
        };
        active.finish()
    }

    fn cancel(&mut self) {
        if let Self::Active(sink) = self {
            sink.cancel();
        }
        *self = Self::Cancelled;
    }
}

impl CommonProofByteSink for RuntimeCommonProofByteSink {
    type Error = PollableCommonProofByteSinkError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Active(sink) => sink.write_bytes(bytes),
            Self::Pending { .. } | Self::Cancelled => {
                Err(PollableCommonProofByteSinkError::ByteLengthExceeded)
            }
        }
    }
}

impl PreparedCommonProofGeneration {
    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.binding
            .authorization
            .application_statement_schema_identifier
    }

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

    pub(crate) fn matches_authenticated_checkpoint(
        &self,
        checkpoint: &AuthenticatedCommonProofGenerationCheckpoint,
    ) -> bool {
        checkpoint.state.matches_binding(self.binding)
    }

    pub(crate) fn from_row_code_whir_sources(
        authorization: CommonProofGenerationAuthorization,
        relation_plan: CommonProofRelationPlanCapability,
        canonical_application_statement_bytes: Vec<u8>,
        relation_trees: Vec<RelationProofTreeInput>,
        limits: CommonProofRuntimeLimits,
        mut sources: CommonProofGenerationSources,
    ) -> Result<Self, CommonProofGenerationPreparationError> {
        let binding = CommonProofGenerationBinding::from_authorization(authorization);
        if relation_plan.relation_plan_hash() != authorization.relation_plan_hash
            || relation_plan.row_code_whir_construction_plan_identity_hash()
                != authorization.row_code_whir_construction_plan_identity_hash
            || verified_application_statement_hash(
                authorization.protocol_version,
                authorization.suite_identifier,
                authorization.application_statement_schema_identifier,
                &canonical_application_statement_bytes,
            ) != authorization.application_statement_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        let transcript_prefix_authority = if relation_plan
            .row_code_whir_construction_plan()
            .requires_verified_vss_bound_prerequisite()
        {
            RowCodeWhirTranscriptPrefixAuthority::VerifiedVss(Box::new(
                authorization.exact_same_secret_transcript_prefix_authority_binding(
                    &canonical_application_statement_bytes,
                    &relation_plan,
                )?,
            ))
        } else {
            RowCodeWhirTranscriptPrefixAuthority::Direct
        };
        let source_polynomial_provider = sources.take_source_polynomial_provider()?;
        let state = RowCodeWhirGenerationStateMachine::new(
            relation_plan.generation_input(
                authorization.protocol_version,
                authorization.suite_identifier,
                &canonical_application_statement_bytes,
                relation_trees,
                source_polynomial_provider,
                limits,
            ),
            relation_plan.row_code_whir_construction_plan(),
            transcript_prefix_authority,
        )
        .map_err(CommonProofGenerationPreparationError::Generation)?;
        Ok(Self {
            binding,
            relation_plan,
            state: CommonProofGenerationExecutionState(state),
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

pub(crate) enum CommonProofGenerationWorkerError {
    Runtime(CommonProofRuntimeError),
    AuthenticatedSource,
    Generation(OwnedCommonProofGenerationError),
    Cleanup,
}

impl core::fmt::Debug for CommonProofGenerationWorkerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Runtime(error) => formatter.debug_tuple("Runtime").field(error).finish(),
            Self::AuthenticatedSource => formatter.write_str("AuthenticatedSource"),
            Self::Generation(error) => formatter.debug_tuple("Generation").field(error).finish(),
            Self::Cleanup => formatter.write_str("Cleanup"),
        }
    }
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
    AuthenticatedTranscriptPrefixRequired,
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
        authenticated_generation_cursor_manifest: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        let state = CommonProofGenerationCheckpointState::decode(authenticated_checkpoint_state)?;
        decode_common_proof_generation_cursor_manifest(authenticated_generation_cursor_manifest)?;
        let cursor_manifest_digest = hash_framed_parts_512(
            CHECKPOINT_CURSOR_MANIFEST_HASH_DOMAIN,
            &[authenticated_generation_cursor_manifest],
        );
        if state.cursor_manifest_digest != cursor_manifest_digest {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(Self { state })
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

struct CommonProofGenerationResumeTarget {
    state: CommonProofGenerationCheckpointState,
    cursor_manifest_bytes: Vec<u8>,
}

impl CommonProofGenerationResumeTarget {
    fn decode(
        authenticated_checkpoint_state: &[u8],
        authenticated_generation_cursor_manifest: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        let authenticated_checkpoint = AuthenticatedCommonProofGenerationCheckpoint::decode(
            authenticated_checkpoint_state,
            authenticated_generation_cursor_manifest,
        )?;
        let mut cursor_manifest_bytes = Vec::new();
        cursor_manifest_bytes
            .try_reserve_exact(authenticated_generation_cursor_manifest.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        cursor_manifest_bytes.extend_from_slice(authenticated_generation_cursor_manifest);
        Ok(Self {
            state: authenticated_checkpoint.state,
            cursor_manifest_bytes,
        })
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
            || u64::from(state.safe_boundary_ordinal).checked_add(1) != Some(state.next_event_index)
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
    if u64::from(boundary.safe_boundary_ordinal()).checked_add(1) != Some(next_event_index) {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }

    let private_coin_cursor_manifest_bytes = private_coins
        .checkpoint_cursor_manifest()
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let cursor_manifest_bytes = encode_common_proof_generation_cursor_manifest(
        private_coin_cursor_manifest_bytes,
        boundary.canonical_transcript_cursor_bytes(),
        boundary.canonical_transcript_cursor_digest(),
    )?;
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
    #[cfg(test)]
    pub(super) fn from_genuine_test_authorization(
        authorization: CommonProofGenerationAuthorization,
    ) -> Result<Self, CommonProofRuntimeError> {
        let stream_descriptor = StreamDescriptor {
            total_byte_length: 1,
            ordered_chunk_digests: vec![Hash512::from_bytes([0xa1; HASH_BYTE_LENGTH])].into(),
            full_object_digest: Hash512::from_bytes([0xa2; HASH_BYTE_LENGTH]),
        };
        let proof_stream_domain =
            common_proof_stream_domain(authorization.application_statement_schema_identifier)
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let proof_application = super::CommonProofApplicationBinding::new(
            authorization.proof_application_slot_hash,
            [0xa3; HASH_BYTE_LENGTH],
            authorization.row_code_whir_construction_plan_identity_hash,
            authorization.application_statement_schema_identifier,
            authorization.proof_header_hash,
            proof_stream_domain,
            stream_descriptor.full_object_digest.into_bytes(),
            stream_descriptor.total_byte_length,
        )?;
        Ok(Self {
            binding: CommonProofGenerationBinding::from_authorization(authorization),
            stream_descriptor,
            post_output_binding: CommonProofPostOutputApplicationBinding {
                authorization,
                proof_application,
            },
        })
    }

    pub(super) fn preflight_attempt_binding(
        &self,
        expected_generation_binding_hash: [u8; HASH_BYTE_LENGTH],
        expected_attempt_identifier: [u8; 32],
    ) -> Result<(), CommonProofRuntimeError> {
        if self.binding.binding_hash() != expected_generation_binding_hash
            || self.binding.authorization.attempt_identifier != expected_attempt_identifier
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(())
    }

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
        expected_bindings: ExpectedCommonProofPackageBindings<'_>,
    ) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        let descriptor = self.preflight_pending_statement(
            expected_bindings.application_statement_schema_identifier,
            expected_bindings.roster_position,
            expected_bindings.schedule_position,
            expected_bindings.canonical_application_statement_bytes,
        )?;
        let authorization = self.binding.authorization;
        let application_slot = authorization.application_slot;
        if authorization.suite_identifier != expected_bindings.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes()
                != expected_bindings.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes()
                != expected_bindings.action_context_hash
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
    state: CommonProofGenerationExecutionState,
    private_coins: CommonProofWorkerPrivateCoinSource,
    storage: CommonProofStorageTransactionRuntime,
    output: RuntimeCommonProofByteSink,
    terminal_stream_descriptor: Option<StreamDescriptor>,
    checkpoint_next_event_index: u64,
    checkpoint_cumulative_event_digest: [u8; HASH_BYTE_LENGTH],
    last_checkpoint_position: Option<[u8; 16]>,
    pending_checkpoint: Option<PendingCommonProofGenerationCheckpoint>,
    resume_target: Option<CommonProofGenerationResumeTarget>,
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
        authenticated_generation_cursor_manifest: &[u8],
    ) -> Result<Self, CommonProofRuntimeError> {
        let target = CommonProofGenerationResumeTarget::decode(
            authenticated_checkpoint_state,
            authenticated_generation_cursor_manifest,
        )?;
        if !target.state.matches_binding(prepared.binding) {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Self::new_with_resume_target(prepared, Some(target))
    }

    fn new_with_resume_target(
        prepared: PreparedCommonProofGeneration,
        resume_target: Option<CommonProofGenerationResumeTarget>,
    ) -> Result<Self, CommonProofRuntimeError> {
        let stream_domain = common_proof_stream_domain(
            prepared
                .binding
                .authorization
                .application_statement_schema_identifier,
        )
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let output = RuntimeCommonProofByteSink::Pending {
            stream_domain,
            limits: prepared.limits,
        };
        Ok(Self {
            binding: prepared.binding,
            relation_plan: prepared.relation_plan,
            state: prepared.state,
            private_coins: prepared.sources.private_coins,
            storage: CommonProofStorageTransactionRuntime::for_runtime_binding(
                prepared.binding.binding_hash(),
            ),
            output,
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

    pub(super) fn pending_storage_request_byte_length(
        &self,
    ) -> Result<usize, CommonProofRuntimeError> {
        self.storage.pending_request_encoded_byte_length()
    }

    pub(super) fn encode_pending_storage_request_into(
        &mut self,
        output: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        self.storage.encode_pending_worker_request_into(output)
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
            .map_err(|_| CommonProofGenerationWorkerError::AuthenticatedSource)
    }

    pub(super) fn authenticated_transcript_prefix_request(
        &self,
    ) -> Result<ExactSameSecretAuthenticatedTranscriptPrefixRequest, CommonProofRuntimeError> {
        self.state.authenticated_transcript_prefix_request()
    }

    pub(super) fn supply_authenticated_transcript_prefix(
        &mut self,
        prepared: PreparedExactSameSecretTranscriptPrefix,
    ) -> Result<(), CommonProofRuntimeError> {
        self.state.supply_authenticated_transcript_prefix(prepared)
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
        self.storage.supply_worker_response(encoded_response)?;
        Ok(())
    }

    pub(super) fn pending_output_chunk(&self) -> Option<(usize, &[u8])> {
        self.output.pending_chunk()
    }

    pub(super) fn acknowledge_output_chunk(
        &mut self,
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.output.acknowledge_pending_chunk()?;
        Ok(())
    }

    pub(super) fn confirm_output_readback(
        &mut self,
        chunk_index: usize,
        readback_bytes: &[u8],
    ) -> Result<(), CommonProofGenerationWorkerError> {
        self.output
            .confirm_pending_chunk_readback(chunk_index, readback_bytes)?;
        Ok(())
    }

    pub(super) fn request_cancellation(&mut self) {
        if self.cancellation_requested {
            return;
        }
        self.cancellation_requested = true;
        self.generation_transaction_must_replay_before_cancellation =
            self.storage.request_is_pending() || self.storage.replay_is_active();
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
        if self.storage.request_is_pending() {
            return Ok(CommonProofGenerationWorkerPoll::StorageRequestReady {
                encoded_request_byte_length: u32::try_from(
                    self.pending_storage_request_byte_length()?,
                )
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
        if let Some(chunk_index) = self.output.pending_readback_chunk_index() {
            return Ok(CommonProofGenerationWorkerPoll::OutputReadbackRequired {
                chunk_index: u32::try_from(chunk_index)
                    .map_err(|_| CommonProofRuntimeError::OutputByteLengthExceeded)?,
            });
        }
        if self.generation_complete {
            return self.finalize_output();
        }

        if let Some(canonical_output_byte_length) = self.state.canonical_output_byte_length() {
            self.output.activate(canonical_output_byte_length)?;
        }

        let result = self
            .state
            .poll(&mut self.storage, &mut self.private_coins, &mut self.output);
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
            Err(error) => Err(CommonProofGenerationWorkerError::Generation(error)),
            Ok(CommonProofGenerationPoll::StorageTransactionCompleted) => self.progress_poll(),
            Ok(CommonProofGenerationPoll::AuthenticatedTranscriptPrefixRequired) => {
                Ok(CommonProofGenerationWorkerPoll::AuthenticatedTranscriptPrefixRequired)
            }
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
                && matches!(stage, CommonProofGenerationStage::Finalizing)
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
            if checkpoint.state.next_event_index > target.state.next_event_index {
                return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
            }
            self.checkpoint_next_event_index = checkpoint.state.next_event_index;
            self.checkpoint_cumulative_event_digest = checkpoint.state.cumulative_event_digest;
            self.last_checkpoint_position = Some(checkpoint.state.position);
            if checkpoint.state.next_event_index == target.state.next_event_index {
                let target = self
                    .resume_target
                    .take()
                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                if checkpoint.state != target.state
                    || checkpoint.cursor_manifest_bytes != target.cursor_manifest_bytes
                {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
                }
                let decoded_cursor_manifest =
                    decode_common_proof_generation_cursor_manifest(&target.cursor_manifest_bytes)?;
                self.state
                    .restore_authenticated_checkpoint_transcript_cursor(
                        decoded_cursor_manifest.transcript_cursor_bytes,
                        decoded_cursor_manifest.transcript_cursor_digest,
                    )?;
                self.deterministic_prefix_replay_external_memory_usage = Some(
                    self.state
                        .external_memory_usage()
                        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
                );
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
        Ok(())
    }

    fn finalize_output(
        &mut self,
    ) -> Result<CommonProofGenerationWorkerPoll, CommonProofGenerationWorkerError> {
        let output = &mut self.output;
        if output.final_partial_chunk_is_ready() {
            output.seal_final_chunk()?;
            return self.poll();
        }
        if !output.complete_output_is_authenticated() {
            return Err(CommonProofRuntimeError::OutputChunkNotReady.into());
        }
        let descriptor = self.output.finish()?;
        self.terminal_stream_descriptor = Some(descriptor);
        Ok(CommonProofGenerationWorkerPoll::Complete)
    }

    fn poll_cancellation(
        &mut self,
    ) -> Result<CommonProofGenerationWorkerPoll, CommonProofGenerationWorkerError> {
        if self.storage.request_is_pending() {
            return Ok(CommonProofGenerationWorkerPoll::StorageRequestReady {
                encoded_request_byte_length: u32::try_from(
                    self.pending_storage_request_byte_length()?,
                )
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
            });
        }
        if self.generation_transaction_must_replay_before_cancellation {
            if !self.storage.replay_is_active() {
                return Err(CommonProofRuntimeError::TransactionResponseMissing.into());
            }
            let result =
                self.state
                    .poll(&mut self.storage, &mut self.private_coins, &mut self.output);
            match result {
                Ok(_) => self.storage.transaction_completed()?,
                Err(error) => {
                    return Err(CommonProofGenerationWorkerError::Generation(error));
                }
            }
            self.generation_transaction_must_replay_before_cancellation = false;
        }
        self.output.cancel();
        match self.state.cancel(&mut self.storage) {
            Ok(()) => {
                if self.storage.replay_is_active() {
                    self.storage.transaction_completed()?;
                }
                self.storage.cancel();
                self.cancellation_complete = true;
                Ok(CommonProofGenerationWorkerPoll::Cancelled)
            }
            Err(error) if executor_error_is_storage_yield(&error) => {
                self.capture_storage_request()?;
                self.poll_cancellation()
            }
            Err(_) => Err(CommonProofGenerationWorkerError::Cleanup),
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
            compiled_requirement: self
                .state
                .external_memory_requirement()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
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

#[cfg(test)]
mod generation_cursor_manifest_tests {
    use super::*;

    #[test]
    fn generation_worker_error_retains_the_structured_generation_failure() {
        let error = CommonProofGenerationWorkerError::Generation(
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
        );

        assert_eq!(format!("{error:?}"), "Generation(Prover(InvalidColumn))");
    }

    fn private_coin_cursor_manifest() -> Vec<u8> {
        let mut manifest = COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC.to_vec();
        manifest.extend_from_slice(&[5, 0, 1, 0, 0, 0, 0]);
        manifest
    }

    fn checkpoint_state_for_manifest(
        manifest: &[u8],
    ) -> [u8; COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH] {
        CommonProofGenerationCheckpointState {
            stable_attempt_binding_hash: [1_u8; HASH_BYTE_LENGTH],
            checkpoint_lineage_identifier: [2_u8; 32],
            checkpoint_schedule_digest: [3_u8; HASH_BYTE_LENGTH],
            next_event_index: 1,
            cumulative_event_digest: [4_u8; HASH_BYTE_LENGTH],
            safe_boundary_ordinal: 0,
            position: [5_u8; 16],
            committed_state_digest: [6_u8; HASH_BYTE_LENGTH],
            cursor_manifest_digest: hash_framed_parts_512(
                CHECKPOINT_CURSOR_MANIFEST_HASH_DOMAIN,
                &[manifest],
            ),
        }
        .encode()
    }

    #[test]
    fn composite_generation_cursor_manifest_round_trips_private_and_transcript_state() {
        let private_manifest = private_coin_cursor_manifest();
        let private_only =
            encode_common_proof_generation_cursor_manifest(private_manifest.clone(), &[], None)
                .expect("a private-only checkpoint cursor manifest is canonical");
        let decoded_private_only = decode_common_proof_generation_cursor_manifest(&private_only)
            .expect("the private-only manifest decodes");
        assert_eq!(
            decoded_private_only.private_coin_cursor_manifest_bytes,
            private_manifest
        );
        assert!(decoded_private_only.transcript_cursor_bytes.is_empty());
        assert_eq!(decoded_private_only.transcript_cursor_digest, None);

        let transcript_cursor = (0_u8..31).collect::<Vec<_>>();
        let transcript_digest = [0xa5_u8; HASH_BYTE_LENGTH];
        let composite = encode_common_proof_generation_cursor_manifest(
            private_manifest.clone(),
            &transcript_cursor,
            Some(transcript_digest),
        )
        .expect("the composite checkpoint cursor manifest is canonical");
        let decoded = decode_common_proof_generation_cursor_manifest(&composite)
            .expect("the composite manifest decodes");
        assert_eq!(decoded.private_coin_cursor_manifest_bytes, private_manifest);
        assert_eq!(decoded.transcript_cursor_bytes, transcript_cursor);
        assert_eq!(decoded.transcript_cursor_digest, Some(transcript_digest));

        let state = checkpoint_state_for_manifest(&composite);
        AuthenticatedCommonProofGenerationCheckpoint::decode(&state, &composite)
            .expect("the exact authenticated state and composite manifest agree");
        let mut changed_composite = composite;
        let final_index = changed_composite.len() - 1;
        changed_composite[final_index] ^= 1;
        assert!(matches!(
            AuthenticatedCommonProofGenerationCheckpoint::decode(&state, &changed_composite),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
    }

    #[test]
    fn composite_generation_cursor_manifest_refuses_malformed_framing_and_limits() {
        let canonical = encode_common_proof_generation_cursor_manifest(
            private_coin_cursor_manifest(),
            &[],
            None,
        )
        .expect("the fixture manifest is canonical");
        let mut malformed_manifests = Vec::new();

        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 1;
        malformed_manifests.push(wrong_magic);
        let mut wrong_version = canonical.clone();
        wrong_version[8] ^= 1;
        malformed_manifests.push(wrong_version);
        let mut reserved_flag = canonical.clone();
        reserved_flag[10] = 2;
        malformed_manifests.push(reserved_flag);
        let mut wrong_total = canonical.clone();
        wrong_total[12..16].copy_from_slice(&1_u32.to_le_bytes());
        malformed_manifests.push(wrong_total);
        let mut empty_private_manifest = canonical.clone();
        empty_private_manifest[16..20].copy_from_slice(&0_u32.to_le_bytes());
        malformed_manifests.push(empty_private_manifest);
        let mut wrong_private_manifest_magic = canonical.clone();
        wrong_private_manifest_magic[COMMON_PROOF_GENERATION_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH] ^=
            1;
        malformed_manifests.push(wrong_private_manifest_magic);
        let mut present_transcript_flag_without_cursor = canonical.clone();
        present_transcript_flag_without_cursor[10..12].copy_from_slice(
            &COMMON_PROOF_GENERATION_CURSOR_MANIFEST_TRANSCRIPT_PRESENT_FLAG.to_le_bytes(),
        );
        malformed_manifests.push(present_transcript_flag_without_cursor);
        let mut absent_transcript_with_digest = canonical.clone();
        absent_transcript_with_digest[24] = 1;
        malformed_manifests.push(absent_transcript_with_digest);
        let mut trailing_byte = canonical.clone();
        trailing_byte.push(0);
        malformed_manifests.push(trailing_byte);
        malformed_manifests.push(
            canonical[..COMMON_PROOF_GENERATION_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH - 1].to_vec(),
        );

        for malformed in malformed_manifests {
            assert!(matches!(
                decode_common_proof_generation_cursor_manifest(&malformed),
                Err(CommonProofRuntimeError::WrongVerificationBinding)
            ));
        }

        let overlong_transcript =
            vec![0_u8; MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH + 1];
        assert!(matches!(
            encode_common_proof_generation_cursor_manifest(
                private_coin_cursor_manifest(),
                &overlong_transcript,
                Some([7_u8; HASH_BYTE_LENGTH]),
            ),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
    }
}
