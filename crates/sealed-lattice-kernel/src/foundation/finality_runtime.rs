use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, FinalityCertificate, FinalityStatement,
    FinalityVerificationInput, FinalityVerifier, Hash512, RefusalReason, Roster,
    VerifiedEvaluatorReplay, VerifiedFinality, board_ingestion_runtime,
};

pub(crate) const FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const VERIFIED_FINALITY_DESCRIPTION_BYTE_LENGTH: usize =
    2 + Hash512::BYTE_LENGTH + Hash512::BYTE_LENGTH + 4;

const FINALITY_VERIFIER_CONFIGURATION_VERSION: u16 = 1;
const FIXED_CONFIGURATION_BYTE_LENGTH: usize = 2 + 3 * Hash512::BYTE_LENGTH + 4;
const MAXIMUM_RETAINED_FINALITY_CAPABILITY_COUNT: usize = 64;
const MAXIMUM_RETAINED_EVALUATOR_REPLAY_CAPABILITY_COUNT: usize = 64;

type RuntimeResult<Value> = Result<Value, u32>;

struct FinalityVerifierRuntimeSession {
    capability: Zeroizing<[u8; FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    verifier: FinalityVerifier,
    verified_finalities: HashMap<u32, VerifiedFinality>,
}

struct FinalityVerifierRuntimeRegistry {
    active_session: Option<FinalityVerifierRuntimeSession>,
    next_session_handle: u32,
    next_verified_finality_handle: u32,
}

impl Default for FinalityVerifierRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_session_handle: 1,
            next_verified_finality_handle: 1,
        }
    }
}

impl FinalityVerifierRuntimeRegistry {
    fn begin(
        &mut self,
        configuration_bytes: &[u8],
        capability: [u8; FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    ) -> RuntimeResult<u32> {
        if self.active_session.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        let configuration = decode_configuration(configuration_bytes)?;
        let verifier = FinalityVerifier::new(
            configuration.suite_identifier,
            configuration.ceremony_context_hash,
            configuration.action_context_hash,
            &configuration.roster,
            CanonicalDecodeLimits::default(),
        )
        .map_err(|error| refusal_status(error.refusal_reason))?;
        let handle = take_nonrepeating_handle(&mut self.next_session_handle)?;
        self.active_session = Some(FinalityVerifierRuntimeSession {
            capability: Zeroizing::new(capability),
            handle,
            verifier,
            verified_finalities: HashMap::new(),
        });
        Ok(handle)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_evaluator_replay: &VerifiedEvaluatorReplay,
        board_session_handle: u32,
        board_capability: &[u8],
        verified_finality_object_handles: &[u32],
        canonical_statement: &[u8],
        canonical_certificate: &[u8],
    ) -> RuntimeResult<u32> {
        let statement =
            FinalityStatement::decode(canonical_statement, &CanonicalDecodeLimits::default())
                .map_err(|error| refusal_status(error.refusal_reason))?;
        let certificate =
            FinalityCertificate::decode(canonical_certificate, &CanonicalDecodeLimits::default())
                .map_err(|error| refusal_status(error.refusal_reason))?;
        if verified_finality_object_handles.len() != certificate.ordered_signer_inputs().len() {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        let verified_finality_objects = board_ingestion_runtime::clone_verified_transcript_objects(
            board_session_handle,
            board_capability,
            verified_finality_object_handles,
        )?;
        let verified_finality_object_references =
            verified_finality_objects.iter().collect::<Vec<_>>();
        let verified_finality = {
            let session = require_active_session(&self.active_session, session_handle, capability)?;
            if session.verified_finalities.len() >= MAXIMUM_RETAINED_FINALITY_CAPABILITY_COUNT {
                return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
            }
            session
                .verifier
                .verify(FinalityVerificationInput {
                    statement,
                    certificate: &certificate,
                    verified_evaluator_replay,
                    verified_finality_objects: &verified_finality_object_references,
                })
                .into_result()
                .map_err(refusal_status)?
        };
        let verified_finality_handle =
            take_nonrepeating_handle(&mut self.next_verified_finality_handle)?;
        require_active_session_mut(&mut self.active_session, session_handle, capability)?
            .verified_finalities
            .insert(verified_finality_handle, verified_finality);
        Ok(verified_finality_handle)
    }

    fn describe(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_finality_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let verified_finality = session
            .verified_finalities
            .get(&verified_finality_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        let accepted_signer_count =
            u32::try_from(verified_finality.accepted_finality_object_hashes().len())
                .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        let mut output = Vec::with_capacity(VERIFIED_FINALITY_DESCRIPTION_BYTE_LENGTH);
        output.extend_from_slice(&1_u16.to_le_bytes());
        output.extend_from_slice(verified_finality.finality_hash().as_bytes());
        output.extend_from_slice(
            verified_finality
                .verified_evaluator_replay_object_hash()
                .as_bytes(),
        );
        output.extend_from_slice(&accepted_signer_count.to_le_bytes());
        Ok(output)
    }

    fn release(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_finality_handle: u32,
    ) -> RuntimeResult<()> {
        require_active_session_mut(&mut self.active_session, session_handle, capability)?
            .verified_finalities
            .remove(&verified_finality_handle)
            .map(|_| ())
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    }

    fn cancel(&mut self, session_handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        require_active_session(&self.active_session, session_handle, capability)?;
        self.active_session = None;
        Ok(())
    }
}

struct EvaluatorReplayRuntimeRegistry {
    next_handle: u32,
    verified_replays: HashMap<u32, VerifiedEvaluatorReplay>,
}

impl Default for EvaluatorReplayRuntimeRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            verified_replays: HashMap::new(),
        }
    }
}

struct FinalityVerifierRuntimeConfiguration {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
}

pub(crate) fn begin_finality_verifier_session(
    configuration_bytes: &[u8],
    capability: [u8; FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
) -> RuntimeResult<u32> {
    with_finality_registry(|registry| registry.begin(configuration_bytes, capability))
}

/// Transfers verifier-owned evaluator replay evidence into the process-local
/// replay registry. Only the evaluator verifier may call this function; there
/// is deliberately no byte or FFI registration surface.
pub(crate) fn retain_verified_evaluator_replay(
    verified_evaluator_replay: VerifiedEvaluatorReplay,
) -> RuntimeResult<u32> {
    with_evaluator_replay_registry(|registry| {
        if registry.verified_replays.len() >= MAXIMUM_RETAINED_EVALUATOR_REPLAY_CAPABILITY_COUNT {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let handle = take_nonrepeating_handle(&mut registry.next_handle)?;
        registry
            .verified_replays
            .insert(handle, verified_evaluator_replay);
        Ok(handle)
    })
}

pub(crate) fn release_verified_evaluator_replay(handle: u32) -> RuntimeResult<()> {
    with_evaluator_replay_registry(|registry| {
        registry
            .verified_replays
            .remove(&handle)
            .map(|_| ())
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_finality(
    session_handle: u32,
    capability: &[u8],
    verified_evaluator_replay_handle: u32,
    board_session_handle: u32,
    board_capability: &[u8],
    verified_finality_object_handles: &[u32],
    canonical_statement: &[u8],
    canonical_certificate: &[u8],
) -> RuntimeResult<u32> {
    with_evaluator_replay_registry(|replay_registry| {
        let verified_evaluator_replay = replay_registry
            .verified_replays
            .get(&verified_evaluator_replay_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        with_finality_registry(|finality_registry| {
            finality_registry.verify(
                session_handle,
                capability,
                verified_evaluator_replay,
                board_session_handle,
                board_capability,
                verified_finality_object_handles,
                canonical_statement,
                canonical_certificate,
            )
        })
    })
}

pub(crate) fn describe_verified_finality(
    session_handle: u32,
    capability: &[u8],
    verified_finality_handle: u32,
) -> RuntimeResult<Vec<u8>> {
    with_finality_registry(|registry| {
        registry.describe(session_handle, capability, verified_finality_handle)
    })
}

pub(crate) fn release_verified_finality(
    session_handle: u32,
    capability: &[u8],
    verified_finality_handle: u32,
) -> RuntimeResult<()> {
    with_finality_registry(|registry| {
        registry.release(session_handle, capability, verified_finality_handle)
    })
}

pub(crate) fn cancel_finality_verifier_session(
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    with_finality_registry(|registry| registry.cancel(session_handle, capability))
}

pub(crate) fn with_verified_finality<Value>(
    session_handle: u32,
    capability: &[u8],
    verified_finality_handle: u32,
    operation: impl FnOnce(&VerifiedFinality) -> RuntimeResult<Value>,
) -> RuntimeResult<Value> {
    with_finality_registry(|registry| {
        let session = require_active_session(&registry.active_session, session_handle, capability)?;
        let verified_finality = session
            .verified_finalities
            .get(&verified_finality_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        operation(verified_finality)
    })
}

fn decode_configuration(bytes: &[u8]) -> RuntimeResult<FinalityVerifierRuntimeConfiguration> {
    if bytes.len() < FIXED_CONFIGURATION_BYTE_LENGTH
        || bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let mut reader = InputReader::new(bytes);
    if reader.read_u16()? != FINALITY_VERIFIER_CONFIGURATION_VERSION {
        return Err(refusal_status(RefusalReason::UnsupportedVersionOrSuite));
    }
    let suite_identifier = Hash512::from_bytes(reader.read_array()?);
    let ceremony_context_hash = Hash512::from_bytes(reader.read_array()?);
    let action_context_hash = Hash512::from_bytes(reader.read_array()?);
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
    Ok(FinalityVerifierRuntimeConfiguration {
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        roster,
    })
}

fn require_active_session<'session>(
    active_session: &'session Option<FinalityVerifierRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'session FinalityVerifierRuntimeSession> {
    let session = active_session
        .as_ref()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_active_session_mut<'session>(
    active_session: &'session mut Option<FinalityVerifierRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'session mut FinalityVerifierRuntimeSession> {
    let session = active_session
        .as_mut()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_session_binding(
    session: &FinalityVerifierRuntimeSession,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    if session.handle != session_handle {
        return Err(refusal_status(RefusalReason::ConsumedState));
    }
    if capability.len() != FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
        || !bool::from(session.capability.as_ref().ct_eq(capability))
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
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

struct InputReader<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> InputReader<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> RuntimeResult<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> RuntimeResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_array<const LENGTH: usize>(&mut self) -> RuntimeResult<[u8; LENGTH]> {
        self.read_bytes(LENGTH)?
            .try_into()
            .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
    }

    fn read_bytes(&mut self, byte_length: usize) -> RuntimeResult<&'input [u8]> {
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

fn with_finality_registry<Value>(
    operation: impl FnOnce(&mut FinalityVerifierRuntimeRegistry) -> RuntimeResult<Value>,
) -> RuntimeResult<Value> {
    static REGISTRY: OnceLock<Mutex<FinalityVerifierRuntimeRegistry>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(FinalityVerifierRuntimeRegistry::default()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().active_session = None;
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
    };
    operation(&mut registry)
}

fn with_evaluator_replay_registry<Value>(
    operation: impl FnOnce(&mut EvaluatorReplayRuntimeRegistry) -> RuntimeResult<Value>,
) -> RuntimeResult<Value> {
    static REGISTRY: OnceLock<Mutex<EvaluatorReplayRuntimeRegistry>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(EvaluatorReplayRuntimeRegistry::default()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().verified_replays.clear();
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
    };
    operation(&mut registry)
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}
