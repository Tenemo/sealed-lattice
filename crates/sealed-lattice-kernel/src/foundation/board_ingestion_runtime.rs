use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::board_ingestion::{
    CanonicalBoardLimits, CanonicalBoardVerifier, MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT,
    VerifiedTranscriptObject,
};
use super::runtime_input::{RuntimeInputReader as InputReader, refusal_status};
use super::{
    ActionContext, ActionDefinition, BoardPolicy, CanonicalDecodeLimits, CeremonyContext,
    FOUNDATION_PROFILE, FoundationObjectType, Hash512, Manifest, ParticipantIdentity,
    RefusalReason, Roster, SuiteRecord,
};

pub(crate) const BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const VERIFIED_TRANSCRIPT_OBJECT_DESCRIPTION_BYTE_LENGTH: usize =
    2 + 2 + Hash512::BYTE_LENGTH;

type RuntimeResult<Value> = Result<Value, u32>;

pub(crate) struct BoardVerifierCanonicalContextInput<'input> {
    pub(crate) canonical_suite_record_bytes: &'input [u8],
    pub(crate) canonical_manifest_bytes: &'input [u8],
    pub(crate) canonical_roster_bytes: &'input [u8],
    pub(crate) canonical_action_definition_bytes: &'input [u8],
    pub(crate) canonical_board_policy_bytes: &'input [u8],
    pub(crate) ceremony_identifier_bytes: &'input [u8],
    pub(crate) action_identifier_bytes: &'input [u8],
    pub(crate) expected_suite_identifier_bytes: &'input [u8],
    pub(crate) expected_ceremony_context_hash_bytes: &'input [u8],
    pub(crate) expected_action_context_hash_bytes: &'input [u8],
}

/// Process-local board authority for one proof application source. The value
/// owns the verified transcript object and its verifier-derived context; it has
/// no constructor from copied descriptions or canonical carrier bytes.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedBoardApplicationSource {
    verified_object: VerifiedTranscriptObject,
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    producer_roster_position: Option<u16>,
}

impl VerifiedBoardApplicationSource {
    fn from_verifier(
        verifier: &CanonicalBoardVerifier,
        verified_object: VerifiedTranscriptObject,
    ) -> Self {
        let producer_roster_position = verified_object
            .producer_participant_id()
            .and_then(|participant_identity| verifier.roster_position(participant_identity).ok());
        Self {
            verified_object,
            suite_identifier: verifier.suite_id(),
            ceremony_context_hash: verifier.ceremony_context_hash(),
            action_context_hash: verifier.action_context_hash(),
            roster_hash: verifier.roster_hash(),
            producer_roster_position,
        }
    }

    pub(crate) const fn suite_identifier(&self) -> Hash512 {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> Hash512 {
        self.roster_hash
    }

    pub(crate) fn object_hash(&self) -> Hash512 {
        self.verified_object.object_hash()
    }

    pub(crate) fn object_type(&self) -> FoundationObjectType {
        self.verified_object.object_type()
    }

    pub(crate) fn producer_participant_identity(&self) -> Option<ParticipantIdentity> {
        self.verified_object.producer_participant_id()
    }

    pub(crate) const fn producer_roster_position(&self) -> Option<u16> {
        self.producer_roster_position
    }

    pub(crate) fn producer_sequence(&self) -> u64 {
        self.verified_object.producer_sequence()
    }

    pub(crate) fn canonical_carrier_bytes(&self) -> &[u8] {
        self.verified_object.canonical_carrier_bytes()
    }
}

struct BoardVerifierRuntimeSession {
    capability: Zeroizing<[u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    verifier: CanonicalBoardVerifier,
    verified_objects: HashMap<u32, VerifiedTranscriptObject>,
    object_handles_by_hash: HashMap<Hash512, u32>,
}

struct BoardVerifierRuntimeRegistry {
    active_session: Option<BoardVerifierRuntimeSession>,
    next_session_handle: u32,
    next_verified_object_handle: u32,
}

impl Default for BoardVerifierRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_session_handle: 1,
            next_verified_object_handle: 1,
        }
    }
}

impl BoardVerifierRuntimeRegistry {
    fn begin(
        &mut self,
        context_input: BoardVerifierCanonicalContextInput<'_>,
        capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    ) -> RuntimeResult<u32> {
        let capability = Zeroizing::new(capability);
        if self.active_session.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        let configuration = derive_configuration(context_input)?;
        let verifier = CanonicalBoardVerifier::new(
            configuration.suite_id,
            configuration.ceremony_context_hash,
            configuration.action_context_hash,
            &configuration.roster,
            configuration.limits,
            CanonicalDecodeLimits::default(),
        )
        .map_err(|error| refusal_status(error.refusal_reason))?;
        let handle = take_nonrepeating_handle(&mut self.next_session_handle)?;
        self.active_session = Some(BoardVerifierRuntimeSession {
            capability,
            handle,
            verifier,
            verified_objects: HashMap::new(),
            object_handles_by_hash: HashMap::new(),
        });
        Ok(handle)
    }

    fn verify_unordered(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        canonical_carriers: &[Vec<u8>],
    ) -> RuntimeResult<Vec<u8>> {
        preflight_handle_range(self.next_verified_object_handle, canonical_carriers.len())?;
        let session =
            require_active_session_mut(&mut self.active_session, session_handle, capability)?;
        let batch = session
            .verifier
            .verify_unordered_carriers(canonical_carriers)
            .into_result()
            .map_err(refusal_status)?;
        let mut handles = Vec::with_capacity(batch.objects().len());
        for object in batch.objects() {
            if let Some(handle) = session.object_handles_by_hash.get(&object.object_hash()) {
                handles.push(*handle);
                continue;
            }
            let handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
            session
                .object_handles_by_hash
                .insert(object.object_hash(), handle);
            session.verified_objects.insert(handle, object.clone());
            handles.push(handle);
        }
        encode_verified_object_handles(&handles)
    }

    fn describe(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .get(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        let mut output = Vec::with_capacity(VERIFIED_TRANSCRIPT_OBJECT_DESCRIPTION_BYTE_LENGTH);
        output.extend_from_slice(&1_u16.to_le_bytes());
        output.extend_from_slice(&object.object_type().canonical_code().to_le_bytes());
        output.extend_from_slice(object.object_hash().as_bytes());
        Ok(output)
    }

    fn copy_cached_carrier(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .get(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        Ok(object.canonical_carrier_bytes().to_vec())
    }

    fn cached_carrier_byte_length(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<usize> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .get(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        Ok(object.canonical_carrier_bytes().len())
    }

    fn release(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<()> {
        let session =
            require_active_session_mut(&mut self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .remove(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        session.object_handles_by_hash.remove(&object.object_hash());
        Ok(())
    }

    fn cancel(&mut self, session_handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        require_active_session(&self.active_session, session_handle, capability)?;
        self.active_session = None;
        Ok(())
    }
}

struct BoardVerifierRuntimeConfiguration {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    limits: CanonicalBoardLimits,
    roster: Roster,
}

pub(crate) fn begin_board_verifier_session(
    context_input: BoardVerifierCanonicalContextInput<'_>,
    capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
) -> RuntimeResult<u32> {
    with_runtime_registry(|registry| registry.begin(context_input, capability))
}

pub(crate) fn verify_unordered_board_carriers(
    session_handle: u32,
    capability: &[u8],
    framed_canonical_carriers: &[u8],
) -> RuntimeResult<Vec<u8>> {
    let canonical_carriers = decode_framed_carriers(framed_canonical_carriers)?;
    with_runtime_registry(|registry| {
        registry.verify_unordered(session_handle, capability, &canonical_carriers)
    })
}

pub(crate) fn describe_verified_transcript_object(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<Vec<u8>> {
    with_runtime_registry(|registry| {
        registry.describe(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn copy_cached_board_carrier(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<Vec<u8>> {
    with_runtime_registry(|registry| {
        registry.copy_cached_carrier(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn cached_board_carrier_byte_length(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<usize> {
    with_runtime_registry(|registry| {
        registry.cached_carrier_byte_length(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn release_verified_transcript_object(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<()> {
    with_runtime_registry(|registry| {
        registry.release(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn cancel_board_verifier_session(
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    with_runtime_registry(|registry| registry.cancel(session_handle, capability))
}

/// Resolves live board capabilities for another verifier inside this WASM
/// instance. Callers receive verifier-owned values, never caller-provided
/// carrier bytes promoted into capabilities.
pub(crate) fn resolve_verified_transcript_objects(
    session_handle: u32,
    capability: &[u8],
    verified_object_handles: &[u32],
) -> RuntimeResult<Vec<VerifiedTranscriptObject>> {
    with_runtime_registry(|registry| {
        let session = require_active_session(&registry.active_session, session_handle, capability)?;
        verified_object_handles
            .iter()
            .map(|verified_object_handle| {
                session
                    .verified_objects
                    .get(verified_object_handle)
                    .cloned()
                    .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
            })
            .collect()
    })
}

/// Resolves verifier-owned application sources for a consumer in this WASM
/// instance. Descriptions and copied carrier bytes cannot enter this path.
pub(crate) fn resolve_verified_board_application_sources(
    session_handle: u32,
    capability: &[u8],
    verified_object_handles: &[u32],
) -> RuntimeResult<Vec<VerifiedBoardApplicationSource>> {
    with_runtime_registry(|registry| {
        let session = require_active_session(&registry.active_session, session_handle, capability)?;
        verified_object_handles
            .iter()
            .map(|verified_object_handle| {
                let verified_object = session
                    .verified_objects
                    .get(verified_object_handle)
                    .cloned()
                    .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
                Ok(VerifiedBoardApplicationSource::from_verifier(
                    &session.verifier,
                    verified_object,
                ))
            })
            .collect()
    })
}

fn derive_configuration(
    input: BoardVerifierCanonicalContextInput<'_>,
) -> RuntimeResult<BoardVerifierRuntimeConfiguration> {
    let decode_limits = CanonicalDecodeLimits::default();
    require_individually_bounded_input(input.canonical_suite_record_bytes)?;
    require_individually_bounded_input(input.canonical_manifest_bytes)?;
    require_individually_bounded_input(input.canonical_roster_bytes)?;
    require_individually_bounded_input(input.canonical_action_definition_bytes)?;
    require_individually_bounded_input(input.canonical_board_policy_bytes)?;

    let suite = SuiteRecord::decode(input.canonical_suite_record_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_suite_record_bytes,
        suite
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let manifest = Manifest::decode(input.canonical_manifest_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_manifest_bytes,
        manifest
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let roster = Roster::decode(input.canonical_roster_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_roster_bytes,
        roster
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let action_definition =
        ActionDefinition::decode(input.canonical_action_definition_bytes, &decode_limits)
            .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_action_definition_bytes,
        action_definition
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let board_policy = BoardPolicy::decode(input.canonical_board_policy_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_board_policy_bytes,
        board_policy
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;

    let ceremony_identifier = decode_external_identifier(input.ceremony_identifier_bytes)?;
    let action_identifier = decode_external_identifier(input.action_identifier_bytes)?;
    let ceremony_context = CeremonyContext::new(&suite, &manifest, &roster, ceremony_identifier)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    let action_context = ActionContext::new(
        &ceremony_context,
        action_identifier,
        action_definition,
        &board_policy,
    )
    .map_err(|error| refusal_status(error.refusal_reason))?;

    let expected_suite_identifier = decode_expected_hash(input.expected_suite_identifier_bytes)?;
    let expected_ceremony_context_hash =
        decode_expected_hash(input.expected_ceremony_context_hash_bytes)?;
    let expected_action_context_hash =
        decode_expected_hash(input.expected_action_context_hash_bytes)?;
    if action_context.suite_id() != expected_suite_identifier
        || action_context.ceremony_context_hash() != expected_ceremony_context_hash
        || action_context.context_hash() != expected_action_context_hash
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }

    let count_limits = suite.count_limits();
    let limits = CanonicalBoardLimits {
        maximum_ballot_attempts_per_participant: u64::from(
            count_limits.maximum_ballot_attempts_per_participant(),
        ),
        maximum_retained_canonical_carrier_byte_length: super::MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
        maximum_unordered_carriers_per_batch: MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT,
        maximum_retained_transcript_objects: MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT,
    };
    Ok(BoardVerifierRuntimeConfiguration {
        suite_id: action_context.suite_id(),
        ceremony_context_hash: action_context.ceremony_context_hash(),
        action_context_hash: action_context.context_hash(),
        limits,
        roster,
    })
}

fn require_individually_bounded_input(bytes: &[u8]) -> RuntimeResult<()> {
    if bytes.is_empty() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    if bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    Ok(())
}

fn require_exact_reencoding(input: &[u8], canonical_bytes: Vec<u8>) -> RuntimeResult<()> {
    if input != canonical_bytes {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    Ok(())
}

fn decode_external_identifier(bytes: &[u8]) -> RuntimeResult<String> {
    require_individually_bounded_input(bytes)?;
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
}

fn decode_expected_hash(bytes: &[u8]) -> RuntimeResult<Hash512> {
    let hash_bytes = <[u8; Hash512::BYTE_LENGTH]>::try_from(bytes)
        .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
    Ok(Hash512::from_bytes(hash_bytes))
}

fn decode_framed_carriers(bytes: &[u8]) -> RuntimeResult<Vec<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(refusal_status(if bytes.is_empty() {
            RefusalReason::WrongTypeOrLength
        } else {
            RefusalReason::OutsideSupportedProfile
        }));
    }
    let mut reader = InputReader::new(bytes);
    let count = usize::try_from(reader.read_u32()?)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if count == 0
        || count
            > usize::try_from(MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT)
                .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?
    {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let mut carriers = Vec::with_capacity(count);
    for _ in 0..count {
        let byte_length = usize::try_from(reader.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        if byte_length == 0 {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        carriers.push(reader.read_bytes(byte_length)?.to_vec());
    }
    reader.finish()?;
    Ok(carriers)
}

fn encode_verified_object_handles(handles: &[u32]) -> RuntimeResult<Vec<u8>> {
    let count = u32::try_from(handles.len())
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    let capacity = handles
        .len()
        .checked_mul(4)
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&count.to_le_bytes());
    for handle in handles {
        output.extend_from_slice(&handle.to_le_bytes());
    }
    Ok(output)
}

fn require_active_session<'a>(
    active_session: &'a Option<BoardVerifierRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'a BoardVerifierRuntimeSession> {
    let session = active_session
        .as_ref()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_active_session_mut<'a>(
    active_session: &'a mut Option<BoardVerifierRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'a mut BoardVerifierRuntimeSession> {
    let session = active_session
        .as_mut()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_session_binding(
    session: &BoardVerifierRuntimeSession,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    if session.handle != session_handle {
        return Err(refusal_status(RefusalReason::ConsumedState));
    }
    if capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
        || !bool::from(session.capability.as_ref().ct_eq(capability))
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
    Ok(())
}

fn preflight_handle_range(next_handle: u32, additional_count: usize) -> RuntimeResult<()> {
    if next_handle == 0 {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let additional_count = u32::try_from(additional_count)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    next_handle
        .checked_add(additional_count)
        .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    Ok(())
}

fn take_nonrepeating_handle(next_handle: &mut u32) -> RuntimeResult<u32> {
    if *next_handle == 0 {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let handle = *next_handle;
    *next_handle = next_handle.checked_add(1).unwrap_or(0);
    Ok(handle)
}

fn with_runtime_registry<Value>(
    operation: impl FnOnce(&mut BoardVerifierRuntimeRegistry) -> RuntimeResult<Value>,
) -> RuntimeResult<Value> {
    static REGISTRY: OnceLock<Mutex<BoardVerifierRuntimeRegistry>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(BoardVerifierRuntimeRegistry::default()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().active_session = None;
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
    };
    operation(&mut registry)
}
