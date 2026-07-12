use std::{collections::HashMap, sync::{Mutex, OnceLock}};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ParticipantIdentity, PreservedStateIntent,
    RefusalReason, Roster, StateCapabilityKind, StateOutputVerificationInput,
    StateRecoveryVerificationInput, StateReservationVerificationInput, StateVerifier,
    VerifiedStateOutput, VerifiedStateRecovery, VerifiedStateReservation,
};

pub(crate) const STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const STATE_VERIFIER_IDENTITY_BYTE_LENGTH: usize = 64;
pub(crate) const STATE_VERIFIER_HASH_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;

const STATE_VERIFIER_CONFIGURATION_VERSION: u16 = 1;
const FIXED_CONFIGURATION_BYTE_LENGTH: usize = 2 + 3 * Hash512::BYTE_LENGTH + 2 + 4;
const MAXIMUM_RETAINED_VERIFIED_STATE_OBJECT_COUNT: usize = 512;

enum RuntimeVerifiedStateObject {
    Reservation(VerifiedStateReservation),
    Output(VerifiedStateOutput),
    Recovery(VerifiedStateRecovery),
}

struct StateVerifierRuntimeSession {
    capability: Zeroizing<[u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    verifier: StateVerifier,
    verified_objects: HashMap<u32, RuntimeVerifiedStateObject>,
}

impl StateVerifierRuntimeSession {
    fn require_object_capacity(&self) -> RuntimeResult<()> {
        if self.verified_objects.len() >= MAXIMUM_RETAINED_VERIFIED_STATE_OBJECT_COUNT {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        Ok(())
    }

    fn predecessor_recovery(
        &self,
        handle: u32,
    ) -> RuntimeResult<Option<&VerifiedStateRecovery>> {
        if handle == 0 {
            return Ok(None);
        }
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::Recovery(recovery)) => Ok(Some(recovery)),
            Some(_) => Err(refusal_status(RefusalReason::WrongTypeOrLength)),
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }

    fn reservation(&self, handle: u32) -> RuntimeResult<&VerifiedStateReservation> {
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::Reservation(reservation)) => Ok(reservation),
            Some(_) => Err(refusal_status(RefusalReason::WrongTypeOrLength)),
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }

    fn preserved_intent(&self, handle: u32) -> RuntimeResult<Option<PreservedStateIntent<'_>>> {
        if handle == 0 {
            return Ok(None);
        }
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::Reservation(reservation)) => {
                Ok(Some(PreservedStateIntent::Reservation(reservation)))
            }
            Some(RuntimeVerifiedStateObject::Output(output)) => {
                Ok(Some(PreservedStateIntent::Output(output)))
            }
            Some(RuntimeVerifiedStateObject::Recovery(_)) => {
                Err(refusal_status(RefusalReason::WrongTypeOrLength))
            }
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }
}

struct StateVerifierRuntimeRegistry {
    active_session: Option<StateVerifierRuntimeSession>,
    next_session_handle: u32,
    next_verified_object_handle: u32,
}

impl Default for StateVerifierRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_session_handle: 1,
            next_verified_object_handle: 1,
        }
    }
}

impl StateVerifierRuntimeRegistry {
    fn begin(
        &mut self,
        configuration_bytes: &[u8],
        capability: [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    ) -> RuntimeResult<u32> {
        if self.active_session.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        let configuration = decode_configuration(configuration_bytes)?;
        let verifier = StateVerifier::new(
            configuration.suite_id,
            configuration.ceremony_context_hash,
            configuration.action_context_hash,
            &configuration.roster,
            configuration.maximum_recovery_transitions_per_state_key,
            CanonicalDecodeLimits::default(),
        )
        .map_err(|error| refusal_status(error.refusal_reason))?;
        let handle = take_nonrepeating_handle(&mut self.next_session_handle)?;
        self.active_session = Some(StateVerifierRuntimeSession {
            capability: Zeroizing::new(capability),
            handle,
            verifier,
            verified_objects: HashMap::new(),
        });
        Ok(handle)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_reservation(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        subject_participant_id: ParticipantIdentity,
        capability_kind: StateCapabilityKind,
        predecessor_recovery_handle: u32,
        expected_authorization_hash: Hash512,
        canonical_reservation_intent_carrier: &[u8],
        canonical_state_certificate: &[u8],
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_reservation_intent_carrier, false)?;
        require_verification_input(canonical_state_certificate, false)?;
        let verified_reservation = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            let predecessor_recovery =
                session.predecessor_recovery(predecessor_recovery_handle)?;
            session
                .verifier
                .verify_reservation(StateReservationVerificationInput {
                    subject_participant_id,
                    capability_kind,
                    verified_predecessor_recovery: predecessor_recovery,
                    expected_authorization_hash,
                    canonical_reservation_intent_carrier,
                    canonical_state_certificate,
                })
                .into_result()
                .map_err(refusal_status)?
        };
        let object_handle =
            take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                object_handle,
                RuntimeVerifiedStateObject::Reservation(verified_reservation),
            );
        Ok(object_handle)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_output(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_reservation_handle: u32,
        canonical_output_intent_carrier: &[u8],
        canonical_state_certificate: &[u8],
        exact_output_bytes: &[u8],
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_output_intent_carrier, false)?;
        require_verification_input(canonical_state_certificate, false)?;
        require_verification_input(exact_output_bytes, true)?;
        let verified_output = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            let reservation = session.reservation(verified_reservation_handle)?;
            session
                .verifier
                .verify_output(StateOutputVerificationInput {
                    verified_reservation: reservation,
                    canonical_output_intent_carrier,
                    canonical_state_certificate,
                    exact_output_bytes,
                })
                .into_result()
                .map_err(refusal_status)?
        };
        let object_handle =
            take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                object_handle,
                RuntimeVerifiedStateObject::Output(verified_output),
            );
        Ok(object_handle)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_recovery(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        subject_participant_id: ParticipantIdentity,
        capability_kind: StateCapabilityKind,
        predecessor_recovery_handle: u32,
        preserved_intent_handle: u32,
        canonical_recovery_transition_carrier: &[u8],
        canonical_state_certificate: &[u8],
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_recovery_transition_carrier, false)?;
        require_verification_input(canonical_state_certificate, false)?;
        let verified_recovery = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            let predecessor_recovery =
                session.predecessor_recovery(predecessor_recovery_handle)?;
            let preserved_state_intent = session.preserved_intent(preserved_intent_handle)?;
            session
                .verifier
                .verify_recovery(StateRecoveryVerificationInput {
                    subject_participant_id,
                    capability_kind,
                    verified_predecessor_recovery: predecessor_recovery,
                    preserved_state_intent,
                    canonical_recovery_transition_carrier,
                    canonical_state_certificate,
                })
                .into_result()
                .map_err(refusal_status)?
        };
        let object_handle =
            take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                object_handle,
                RuntimeVerifiedStateObject::Recovery(verified_recovery),
            );
        Ok(object_handle)
    }

    fn release_verified_object(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<()> {
        if verified_object_handle == 0 {
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
        let session = self.require_active_session_mut(session_handle, capability)?;
        session
            .verified_objects
            .remove(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        Ok(())
    }

    fn cancel(&mut self, session_handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        let Some(session) = self.active_session.as_ref() else {
            return Ok(());
        };
        require_session_binding(session, session_handle, capability)?;
        self.active_session = None;
        Ok(())
    }

    fn require_active_session(
        &self,
        handle: u32,
        capability: &[u8],
    ) -> RuntimeResult<&StateVerifierRuntimeSession> {
        let session = self
            .active_session
            .as_ref()
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        require_session_binding(session, handle, capability)?;
        Ok(session)
    }

    fn require_active_session_mut(
        &mut self,
        handle: u32,
        capability: &[u8],
    ) -> RuntimeResult<&mut StateVerifierRuntimeSession> {
        let session = self
            .active_session
            .as_mut()
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        require_session_binding(session, handle, capability)?;
        Ok(session)
    }
}

struct StateVerifierRuntimeConfiguration {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    maximum_recovery_transitions_per_state_key: u16,
    roster: Roster,
}

struct InputReader<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> InputReader<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const BYTE_LENGTH: usize>(&mut self) -> RuntimeResult<[u8; BYTE_LENGTH]> {
        self.read_bytes(BYTE_LENGTH)?
            .try_into()
            .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
    }

    fn read_u16(&mut self) -> RuntimeResult<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> RuntimeResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_bytes(&mut self, byte_length: usize) -> RuntimeResult<&'input [u8]> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> RuntimeResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(refusal_status(RefusalReason::MalformedEncoding))
        }
    }
}

type RuntimeResult<Value> = Result<Value, u32>;

static STATE_VERIFIER_RUNTIME_REGISTRY: OnceLock<Mutex<StateVerifierRuntimeRegistry>> =
    OnceLock::new();

fn runtime_registry() -> &'static Mutex<StateVerifierRuntimeRegistry> {
    STATE_VERIFIER_RUNTIME_REGISTRY
        .get_or_init(|| Mutex::new(StateVerifierRuntimeRegistry::default()))
}

fn with_runtime_registry<ResultValue>(
    operation: impl FnOnce(&mut StateVerifierRuntimeRegistry) -> RuntimeResult<ResultValue>,
) -> RuntimeResult<ResultValue> {
    let mut registry = match runtime_registry().lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().active_session = None;
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
    };
    operation(&mut registry)
}

pub(crate) fn begin_state_verifier_session(
    configuration_bytes: &[u8],
    capability: [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
) -> RuntimeResult<u32> {
    with_runtime_registry(|registry| registry.begin(configuration_bytes, capability))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_state_reservation(
    session_handle: u32,
    capability: &[u8],
    subject_participant_id: &[u8],
    capability_kind_code: u32,
    predecessor_recovery_handle: u32,
    expected_authorization_hash: &[u8],
    canonical_reservation_intent_carrier: &[u8],
    canonical_state_certificate: &[u8],
) -> RuntimeResult<u32> {
    let subject_participant_id = decode_participant_identity(subject_participant_id)?;
    let capability_kind = decode_capability_kind(capability_kind_code)?;
    let expected_authorization_hash = decode_hash(expected_authorization_hash)?;
    with_runtime_registry(|registry| {
        registry.verify_reservation(
            session_handle,
            capability,
            subject_participant_id,
            capability_kind,
            predecessor_recovery_handle,
            expected_authorization_hash,
            canonical_reservation_intent_carrier,
            canonical_state_certificate,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_state_output(
    session_handle: u32,
    capability: &[u8],
    verified_reservation_handle: u32,
    canonical_output_intent_carrier: &[u8],
    canonical_state_certificate: &[u8],
    exact_output_bytes: &[u8],
) -> RuntimeResult<u32> {
    with_runtime_registry(|registry| {
        registry.verify_output(
            session_handle,
            capability,
            verified_reservation_handle,
            canonical_output_intent_carrier,
            canonical_state_certificate,
            exact_output_bytes,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_state_recovery(
    session_handle: u32,
    capability: &[u8],
    subject_participant_id: &[u8],
    capability_kind_code: u32,
    predecessor_recovery_handle: u32,
    preserved_intent_handle: u32,
    canonical_recovery_transition_carrier: &[u8],
    canonical_state_certificate: &[u8],
) -> RuntimeResult<u32> {
    let subject_participant_id = decode_participant_identity(subject_participant_id)?;
    let capability_kind = decode_capability_kind(capability_kind_code)?;
    with_runtime_registry(|registry| {
        registry.verify_recovery(
            session_handle,
            capability,
            subject_participant_id,
            capability_kind,
            predecessor_recovery_handle,
            preserved_intent_handle,
            canonical_recovery_transition_carrier,
            canonical_state_certificate,
        )
    })
}

pub(crate) fn release_verified_state_object(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<()> {
    with_runtime_registry(|registry| {
        registry.release_verified_object(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn cancel_state_verifier_session(
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    with_runtime_registry(|registry| registry.cancel(session_handle, capability))
}

fn decode_configuration(
    configuration_bytes: &[u8],
) -> RuntimeResult<StateVerifierRuntimeConfiguration> {
    if configuration_bytes.len() < FIXED_CONFIGURATION_BYTE_LENGTH
        || configuration_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let mut reader = InputReader::new(configuration_bytes);
    if reader.read_u16()? != STATE_VERIFIER_CONFIGURATION_VERSION {
        return Err(refusal_status(RefusalReason::UnsupportedVersionOrSuite));
    }
    let suite_id = Hash512::from_bytes(reader.read_array()?);
    let ceremony_context_hash = Hash512::from_bytes(reader.read_array()?);
    let action_context_hash = Hash512::from_bytes(reader.read_array()?);
    let maximum_recovery_transitions_per_state_key = reader.read_u16()?;
    let roster_byte_length = usize::try_from(reader.read_u32()?)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if roster_byte_length == 0 {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let roster_bytes = reader.read_bytes(roster_byte_length)?;
    reader.finish()?;
    let roster = Roster::decode(roster_bytes, &CanonicalDecodeLimits::default())
        .map_err(|error| refusal_status(error.refusal_reason))?;
    Ok(StateVerifierRuntimeConfiguration {
        suite_id,
        ceremony_context_hash,
        action_context_hash,
        maximum_recovery_transitions_per_state_key,
        roster,
    })
}

fn decode_participant_identity(bytes: &[u8]) -> RuntimeResult<ParticipantIdentity> {
    let bytes: [u8; STATE_VERIFIER_IDENTITY_BYTE_LENGTH] = bytes
        .try_into()
        .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
    Ok(ParticipantIdentity::from_bytes(bytes))
}

fn decode_hash(bytes: &[u8]) -> RuntimeResult<Hash512> {
    let bytes: [u8; STATE_VERIFIER_HASH_BYTE_LENGTH] = bytes
        .try_into()
        .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
    Ok(Hash512::from_bytes(bytes))
}

fn decode_capability_kind(code: u32) -> RuntimeResult<StateCapabilityKind> {
    let code = u16::try_from(code)
        .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
    StateCapabilityKind::from_canonical_code(code)
        .ok_or_else(|| refusal_status(RefusalReason::WrongTypeOrLength))
}

fn require_verification_input(bytes: &[u8], allow_empty: bool) -> RuntimeResult<()> {
    if (!allow_empty && bytes.is_empty())
        || bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(refusal_status(if bytes.is_empty() {
            RefusalReason::WrongTypeOrLength
        } else {
            RefusalReason::OutsideSupportedProfile
        }));
    }
    Ok(())
}

fn require_session_binding(
    session: &StateVerifierRuntimeSession,
    handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    if session.handle != handle {
        return Err(refusal_status(RefusalReason::ConsumedState));
    }
    if capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
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

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}
