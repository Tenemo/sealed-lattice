use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ParticipantIdentity, RefusalReason, Roster,
    StateCapabilityKind, StateDurableBinding, StateReservationIntentVerificationInput,
    StateReservationVerificationInput, StateVerifier, VerifiedStateOutput,
    VerifiedStateOutputIntent, VerifiedStateReservation, VerifiedStateReservationIntent,
    canonical_stream::VerifiedCanonicalStreamSummary,
    finish_canonical_stream_verifier_with_summary,
};

pub(crate) const STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
const STATE_VERIFIER_IDENTITY_BYTE_LENGTH: usize = 64;
const STATE_VERIFIER_HASH_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
pub(crate) const STATE_DURABLE_BINDING_BYTE_LENGTH: usize = 601;

const STATE_VERIFIER_CONFIGURATION_VERSION: u16 = 1;
const FIXED_CONFIGURATION_BYTE_LENGTH: usize = 2 + 3 * Hash512::BYTE_LENGTH + 4;
const MAXIMUM_RETAINED_VERIFIED_STATE_OBJECT_COUNT: usize = 512;

#[derive(Clone, Copy)]
pub(crate) struct VerifiedStateReservationRuntimeBinding {
    pub(crate) authorization_hash: Hash512,
    pub(crate) durable_binding: StateDurableBinding,
}

enum RuntimeVerifiedStateObject {
    ReservationIntent(VerifiedStateReservationIntent),
    OutputIntent(VerifiedStateOutputIntent),
    Reservation(VerifiedStateReservation),
    Output(VerifiedStateOutput),
}

enum CertifiedRuntimeStateObject {
    Reservation(VerifiedStateReservation),
    Output(VerifiedStateOutput),
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

    fn reservation(&self, handle: u32) -> RuntimeResult<&VerifiedStateReservation> {
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::Reservation(reservation)) => Ok(reservation),
            Some(_) => Err(refusal_status(RefusalReason::WrongTypeOrLength)),
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }

    fn durable_binding(&self, handle: u32) -> RuntimeResult<StateDurableBinding> {
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::ReservationIntent(intent)) => {
                Ok(intent.durable_binding())
            }
            Some(RuntimeVerifiedStateObject::OutputIntent(intent)) => Ok(intent.durable_binding()),
            Some(RuntimeVerifiedStateObject::Reservation(reservation)) => {
                Ok(reservation.durable_binding())
            }
            Some(RuntimeVerifiedStateObject::Output(output)) => Ok(output.durable_binding()),
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
        expected_authorization_hash: Hash512,
        canonical_reservation_intent_carrier: &[u8],
        canonical_state_certificate: &[u8],
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_reservation_intent_carrier, false)?;
        require_verification_input(canonical_state_certificate, false)?;
        let verified_reservation = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            session
                .verifier
                .verify_reservation(StateReservationVerificationInput {
                    subject_participant_id,
                    capability_kind,
                    expected_authorization_hash,
                    canonical_reservation_intent_carrier,
                    canonical_state_certificate,
                })
                .into_result()
                .map_err(refusal_status)?
        };
        let object_handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                object_handle,
                RuntimeVerifiedStateObject::Reservation(verified_reservation),
            );
        Ok(object_handle)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_reservation_intent(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        subject_participant_id: ParticipantIdentity,
        capability_kind: StateCapabilityKind,
        expected_authorization_hash: Hash512,
        canonical_reservation_intent_carrier: &[u8],
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_reservation_intent_carrier, false)?;
        let verified_intent = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            session
                .verifier
                .verify_reservation_intent(StateReservationIntentVerificationInput {
                    subject_participant_id,
                    capability_kind,
                    expected_authorization_hash,
                    canonical_reservation_intent_carrier,
                })
                .into_result()
                .map_err(refusal_status)?
        };
        let object_handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                object_handle,
                RuntimeVerifiedStateObject::ReservationIntent(verified_intent),
            );
        Ok(object_handle)
    }

    fn verify_output(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_reservation_handle: u32,
        canonical_output_intent_carrier: &[u8],
        canonical_state_certificate: &[u8],
        verified_stream: VerifiedCanonicalStreamSummary,
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_output_intent_carrier, false)?;
        require_verification_input(canonical_state_certificate, false)?;
        let verified_output = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            let reservation = session.reservation(verified_reservation_handle)?;
            session
                .verifier
                .verify_output_from_verified_stream(
                    reservation,
                    canonical_output_intent_carrier,
                    canonical_state_certificate,
                    verified_stream,
                )
                .into_result()
                .map_err(refusal_status)?
        };
        let object_handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                object_handle,
                RuntimeVerifiedStateObject::Output(verified_output),
            );
        Ok(object_handle)
    }

    fn verify_output_intent(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_reservation_handle: u32,
        canonical_output_intent_carrier: &[u8],
        verified_stream: VerifiedCanonicalStreamSummary,
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_output_intent_carrier, false)?;
        let verified_intent = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            let reservation = session.reservation(verified_reservation_handle)?;
            session
                .verifier
                .verify_output_intent_from_verified_stream(
                    reservation,
                    canonical_output_intent_carrier,
                    verified_stream,
                )
                .into_result()
                .map_err(refusal_status)?
        };
        let object_handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                object_handle,
                RuntimeVerifiedStateObject::OutputIntent(verified_intent),
            );
        Ok(object_handle)
    }

    #[allow(clippy::too_many_arguments)]
    fn certify_intent(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_intent_handle: u32,
        canonical_state_certificate: &[u8],
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_state_certificate, false)?;
        let certified_object = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            match session.verified_objects.get(&verified_intent_handle) {
                Some(RuntimeVerifiedStateObject::ReservationIntent(intent)) => session
                    .verifier
                    .certify_reservation_intent(intent, canonical_state_certificate)
                    .into_result()
                    .map(CertifiedRuntimeStateObject::Reservation)
                    .map_err(refusal_status)?,
                Some(RuntimeVerifiedStateObject::OutputIntent(intent)) => session
                    .verifier
                    .certify_output_intent(intent, canonical_state_certificate)
                    .into_result()
                    .map(CertifiedRuntimeStateObject::Output)
                    .map_err(refusal_status)?,
                Some(_) => return Err(refusal_status(RefusalReason::WrongTypeOrLength)),
                None => return Err(refusal_status(RefusalReason::ConsumedState)),
            }
        };
        let object_handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        let runtime_object = match certified_object {
            CertifiedRuntimeStateObject::Reservation(value) => {
                RuntimeVerifiedStateObject::Reservation(value)
            }
            CertifiedRuntimeStateObject::Output(value) => RuntimeVerifiedStateObject::Output(value),
        };
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(object_handle, runtime_object);
        Ok(object_handle)
    }

    fn certify_intent_from_unordered_vote_carriers(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_intent_handle: u32,
        canonical_vote_carriers: &[Vec<u8>],
    ) -> RuntimeResult<u32> {
        let certified_object = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            match session.verified_objects.get(&verified_intent_handle) {
                Some(RuntimeVerifiedStateObject::ReservationIntent(intent)) => session
                    .verifier
                    .certify_reservation_intent_from_unordered_vote_carriers(
                        intent,
                        canonical_vote_carriers,
                    )
                    .into_result()
                    .map(CertifiedRuntimeStateObject::Reservation)
                    .map_err(refusal_status)?,
                Some(RuntimeVerifiedStateObject::OutputIntent(intent)) => session
                    .verifier
                    .certify_output_intent_from_unordered_vote_carriers(
                        intent,
                        canonical_vote_carriers,
                    )
                    .into_result()
                    .map(CertifiedRuntimeStateObject::Output)
                    .map_err(refusal_status)?,
                Some(_) => return Err(refusal_status(RefusalReason::WrongTypeOrLength)),
                None => return Err(refusal_status(RefusalReason::ConsumedState)),
            }
        };
        let object_handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        let runtime_object = match certified_object {
            CertifiedRuntimeStateObject::Reservation(value) => {
                RuntimeVerifiedStateObject::Reservation(value)
            }
            CertifiedRuntimeStateObject::Output(value) => RuntimeVerifiedStateObject::Output(value),
        };
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(object_handle, runtime_object);
        Ok(object_handle)
    }

    fn describe(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = self.require_active_session(session_handle, capability)?;
        encode_durable_binding(session.durable_binding(verified_object_handle)?)
    }

    fn reservation_binding(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_reservation_handle: u32,
    ) -> RuntimeResult<VerifiedStateReservationRuntimeBinding> {
        let session = self.require_active_session(session_handle, capability)?;
        match session.verified_objects.get(&verified_reservation_handle) {
            Some(RuntimeVerifiedStateObject::Reservation(reservation)) => {
                Ok(VerifiedStateReservationRuntimeBinding {
                    authorization_hash: reservation.authorization_hash(),
                    durable_binding: reservation.durable_binding(),
                })
            }
            Some(_) => Err(refusal_status(RefusalReason::WrongTypeOrLength)),
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
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
        if session
            .verified_objects
            .remove(&verified_object_handle)
            .is_none()
        {
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
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
            expected_authorization_hash,
            canonical_reservation_intent_carrier,
            canonical_state_certificate,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_state_reservation_intent(
    session_handle: u32,
    capability: &[u8],
    subject_participant_id: &[u8],
    capability_kind_code: u32,
    expected_authorization_hash: &[u8],
    canonical_reservation_intent_carrier: &[u8],
) -> RuntimeResult<u32> {
    let subject_participant_id = decode_participant_identity(subject_participant_id)?;
    let capability_kind = decode_capability_kind(capability_kind_code)?;
    let expected_authorization_hash = decode_hash(expected_authorization_hash)?;
    with_runtime_registry(|registry| {
        registry.verify_reservation_intent(
            session_handle,
            capability,
            subject_participant_id,
            capability_kind,
            expected_authorization_hash,
            canonical_reservation_intent_carrier,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_state_output_verification(
    session_handle: u32,
    capability: &[u8],
    stream_handle: u32,
    verified_reservation_handle: u32,
    canonical_output_intent_carrier: &[u8],
    canonical_state_certificate: &[u8],
) -> RuntimeResult<u32> {
    // An atomic finish attempt owns the stream's terminal transition. Consume
    // it before any state-side refusal so JavaScript can never release the
    // stream authority while the kernel still retains the active session.
    let verified_stream = finish_canonical_stream_verifier_with_summary(stream_handle)?;
    with_runtime_registry(|registry| {
        registry.verify_output(
            session_handle,
            capability,
            verified_reservation_handle,
            canonical_output_intent_carrier,
            canonical_state_certificate,
            verified_stream,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_state_output_intent_verification(
    session_handle: u32,
    capability: &[u8],
    stream_handle: u32,
    verified_reservation_handle: u32,
    canonical_output_intent_carrier: &[u8],
) -> RuntimeResult<u32> {
    // Keep the stream and state lease terminal boundaries identical to
    // `finish_state_output_verification` above.
    let verified_stream = finish_canonical_stream_verifier_with_summary(stream_handle)?;
    with_runtime_registry(|registry| {
        registry.verify_output_intent(
            session_handle,
            capability,
            verified_reservation_handle,
            canonical_output_intent_carrier,
            verified_stream,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn certify_verified_state_intent(
    session_handle: u32,
    capability: &[u8],
    verified_intent_handle: u32,
    canonical_state_certificate: &[u8],
) -> RuntimeResult<u32> {
    with_runtime_registry(|registry| {
        registry.certify_intent(
            session_handle,
            capability,
            verified_intent_handle,
            canonical_state_certificate,
        )
    })
}

pub(crate) fn certify_verified_state_intent_from_unordered_vote_carriers(
    session_handle: u32,
    capability: &[u8],
    verified_intent_handle: u32,
    framed_canonical_vote_carriers: &[u8],
) -> RuntimeResult<u32> {
    let canonical_vote_carriers = decode_unordered_vote_carriers(framed_canonical_vote_carriers)?;
    with_runtime_registry(|registry| {
        registry.certify_intent_from_unordered_vote_carriers(
            session_handle,
            capability,
            verified_intent_handle,
            &canonical_vote_carriers,
        )
    })
}

pub(crate) fn describe_verified_state_object(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<Vec<u8>> {
    with_runtime_registry(|registry| {
        registry.describe(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn verified_state_reservation_binding(
    session_handle: u32,
    capability: &[u8],
    verified_reservation_handle: u32,
) -> RuntimeResult<VerifiedStateReservationRuntimeBinding> {
    with_runtime_registry(|registry| {
        registry.reservation_binding(session_handle, capability, verified_reservation_handle)
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
        roster,
    })
}

fn encode_durable_binding(binding: StateDurableBinding) -> RuntimeResult<Vec<u8>> {
    const DURABLE_BINDING_VERSION: u16 = 1;
    let witness_vote_sequence = binding.witness_vote_sequence();
    let mut output = Vec::with_capacity(STATE_DURABLE_BINDING_BYTE_LENGTH);
    output.extend_from_slice(&DURABLE_BINDING_VERSION.to_le_bytes());
    output.extend_from_slice(&binding.vote_kind().canonical_code().to_le_bytes());
    output.extend_from_slice(&binding.capability_kind().canonical_code().to_le_bytes());
    output.extend_from_slice(binding.suite_id().as_bytes());
    output.extend_from_slice(binding.ceremony_context_hash().as_bytes());
    output.extend_from_slice(binding.action_context_hash().as_bytes());
    output.extend_from_slice(binding.subject_participant_id().as_bytes());
    output.extend_from_slice(binding.state_key().as_bytes());
    output.extend_from_slice(binding.intent_object_hash().as_bytes());
    output.extend_from_slice(&witness_vote_sequence.to_le_bytes());
    encode_optional_hash(&mut output, binding.reservation_intent_object_hash());
    encode_optional_hash(&mut output, binding.output_intent_object_hash());
    encode_optional_hash(&mut output, binding.exact_output_hash());
    output.extend_from_slice(
        &binding
            .exact_output_byte_length()
            .unwrap_or(0)
            .to_le_bytes(),
    );
    if output.len() != STATE_DURABLE_BINDING_BYTE_LENGTH {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    Ok(output)
}

fn encode_optional_hash(output: &mut Vec<u8>, value: Option<Hash512>) {
    match value {
        Some(hash) => {
            output.push(1);
            output.extend_from_slice(hash.as_bytes());
        }
        None => {
            output.push(0);
            output.extend_from_slice(&[0_u8; Hash512::BYTE_LENGTH]);
        }
    }
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
    let code = u16::try_from(code).map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
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

fn decode_unordered_vote_carriers(bytes: &[u8]) -> RuntimeResult<Vec<Vec<u8>>> {
    const MAXIMUM_UNTRUSTED_STATE_VOTE_CARRIER_COUNT: usize =
        FOUNDATION_PROFILE.participant_count as usize * 2;
    require_verification_input(bytes, false)?;
    let mut reader = InputReader::new(bytes);
    let count = usize::try_from(reader.read_u32()?)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if count == 0 || count > MAXIMUM_UNTRUSTED_STATE_VOTE_CARRIER_COUNT {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let mut carriers = Vec::with_capacity(count);
    for _ in 0..count {
        let byte_length = usize::try_from(reader.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        let carrier = reader.read_bytes(byte_length)?;
        require_verification_input(carrier, false)?;
        carriers.push(carrier.to_vec());
    }
    reader.finish()?;
    Ok(carriers)
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

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes},
    };

    use super::*;
    use crate::foundation::{FOUNDATION_PROFILE, RosterEntry};

    fn configuration_bytes() -> Vec<u8> {
        let roster_entries = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                let mut signing_seed = [0_u8; 32];
                signing_seed[0] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                signing_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("test reverse roster position fits u8");
                let (verification_key, _) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_seed = [0x41_u8; 32];
                mailbox_seed[0] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                let mut mailbox_fallback_seed = [0x92_u8; 32];
                mailbox_fallback_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("test reverse roster position fits u8");
                let (mailbox_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
                RosterEntry {
                    roster_position,
                    signing_verification_key: verification_key.into_bytes(),
                    mailbox_encapsulation_key: mailbox_key.into_bytes(),
                }
            })
            .collect();
        let roster_bytes = Roster::new(roster_entries)
            .expect("test roster is valid")
            .encode()
            .expect("test roster encodes");
        let mut configuration = Vec::new();
        configuration.extend_from_slice(&STATE_VERIFIER_CONFIGURATION_VERSION.to_le_bytes());
        configuration.extend_from_slice(&[0x11; Hash512::BYTE_LENGTH]);
        configuration.extend_from_slice(&[0x22; Hash512::BYTE_LENGTH]);
        configuration.extend_from_slice(&[0x33; Hash512::BYTE_LENGTH]);
        configuration.extend_from_slice(
            &u32::try_from(roster_bytes.len())
                .expect("test roster length fits u32")
                .to_le_bytes(),
        );
        configuration.extend_from_slice(&roster_bytes);
        configuration
    }

    #[test]
    fn forged_stale_and_overlapping_requests_preserve_the_active_state_session() {
        let configuration = configuration_bytes();
        let owner = [0x61; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH];
        let mut registry = StateVerifierRuntimeRegistry::default();
        let handle = registry
            .begin(&configuration, owner)
            .expect("state session begins");

        assert_eq!(
            registry.cancel(handle.wrapping_add(1), &owner),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        assert!(registry.active_session.is_some());
        assert_eq!(
            registry.cancel(
                handle,
                &[0x62; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
            ),
            Err(refusal_status(RefusalReason::WrongContext))
        );
        assert!(registry.active_session.is_some());
        assert_eq!(
            registry.begin(
                &configuration,
                [0x63; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
            ),
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        );
        assert!(registry.active_session.is_some());
        assert_eq!(
            registry.release_verified_object(handle, &owner, 1),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        assert!(registry.active_session.is_some());
        assert_eq!(registry.cancel(handle, &owner), Ok(()));
    }
}
