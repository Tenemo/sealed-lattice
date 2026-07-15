use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::board_ingestion::{
    CanonicalBoardLimits, CanonicalBoardVerifier,
    MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT, VerifiedTranscriptObject,
};
use super::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, RefusalReason, Roster,
};

pub(crate) const BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const VERIFIED_TRANSCRIPT_OBJECT_DESCRIPTION_BYTE_LENGTH: usize =
    2 + 2 + Hash512::BYTE_LENGTH;

const BOARD_VERIFIER_CONFIGURATION_VERSION: u16 = 1;
const FIXED_CONFIGURATION_BYTE_LENGTH: usize =
    2 + 3 * Hash512::BYTE_LENGTH + 8 + 8 + 8 + 4 + 4 + 4;

type RuntimeResult<Value> = Result<Value, u32>;

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
        configuration_bytes: &[u8],
        capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    ) -> RuntimeResult<u32> {
        let capability = Zeroizing::new(capability);
        if self.active_session.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        let configuration = decode_configuration(configuration_bytes)?;
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
        preflight_handle_range(
            self.next_verified_object_handle,
            canonical_carriers.len(),
        )?;
        let session = require_active_session_mut(&mut self.active_session, session_handle, capability)?;
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
        let session = require_active_session_mut(&mut self.active_session, session_handle, capability)?;
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
    configuration_bytes: &[u8],
    capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
) -> RuntimeResult<u32> {
    with_runtime_registry(|registry| registry.begin(configuration_bytes, capability))
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
        registry.cached_carrier_byte_length(
            session_handle,
            capability,
            verified_object_handle,
        )
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

fn decode_configuration(bytes: &[u8]) -> RuntimeResult<BoardVerifierRuntimeConfiguration> {
    if bytes.len() < FIXED_CONFIGURATION_BYTE_LENGTH
        || bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let mut reader = InputReader::new(bytes);
    if reader.read_u16()? != BOARD_VERIFIER_CONFIGURATION_VERSION {
        return Err(refusal_status(RefusalReason::UnsupportedVersionOrSuite));
    }
    let suite_id = Hash512::from_bytes(reader.read_array()?);
    let ceremony_context_hash = Hash512::from_bytes(reader.read_array()?);
    let action_context_hash = Hash512::from_bytes(reader.read_array()?);
    let limits = CanonicalBoardLimits {
        maximum_ballot_attempts_per_participant: reader.read_u64()?,
        maximum_recovery_transitions_per_state_key: reader.read_u64()?,
        maximum_retained_canonical_carrier_byte_length: reader.read_u64()?,
        maximum_unordered_carriers_per_batch: reader.read_u32()?,
        maximum_retained_transcript_objects: reader.read_u32()?,
    };
    if usize::try_from(limits.maximum_unordered_carriers_per_batch)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?
        > usize::try_from(MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?
    {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let roster_byte_length = usize::try_from(reader.read_u32()?)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if roster_byte_length == 0 {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let roster = Roster::decode(
        reader.read_bytes(roster_byte_length)?,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|error| refusal_status(error.refusal_reason))?;
    reader.finish()?;
    Ok(BoardVerifierRuntimeConfiguration {
        suite_id,
        ceremony_context_hash,
        action_context_hash,
        limits,
        roster,
    })
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

struct InputReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> InputReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> RuntimeResult<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> RuntimeResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> RuntimeResult<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_array<const LENGTH: usize>(&mut self) -> RuntimeResult<[u8; LENGTH]> {
        self.read_bytes(LENGTH)?
            .try_into()
            .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
    }

    fn read_bytes(&mut self, byte_length: usize) -> RuntimeResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> RuntimeResult<()> {
        if self.offset != self.bytes.len() {
            return Err(refusal_status(RefusalReason::MalformedEncoding));
        }
        Ok(())
    }
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

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}
