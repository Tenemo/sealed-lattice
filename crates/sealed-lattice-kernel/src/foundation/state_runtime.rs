use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, OnceLock},
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::runtime_input::{RuntimeInputReader as InputReader, refusal_status};
use super::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    ParticipantIdentity, PreparedStateReservationIntent, RefusalReason, Roster,
    StateCapabilityKind, StateDurableBinding, StateReservationIntentVerificationInput,
    StateReservationVerificationInput, StateVerifier, VerifiedStateOutput,
    VerifiedStateOutputIntent, VerifiedStateReservation, VerifiedStateReservationIntent,
    canonical_stream::VerifiedCanonicalStreamSummary,
    finish_canonical_stream_verifier_with_summary,
    resolve_setup_action_randomness_reservation_source,
};

pub(crate) const STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
const STATE_VERIFIER_IDENTITY_BYTE_LENGTH: usize = 64;
const STATE_VERIFIER_HASH_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
pub(crate) const STATE_DURABLE_BINDING_BYTE_LENGTH: usize = 601;

const STATE_VERIFIER_CONFIGURATION_VERSION: u16 = 1;
const FIXED_CONFIGURATION_BYTE_LENGTH: usize = 2 + 3 * Hash512::BYTE_LENGTH + 4;
const MAXIMUM_RETAINED_VERIFIED_STATE_OBJECT_COUNT: usize = 512;
const STATE_PRODUCER_COMMAND_PREPARE_SETUP_ACTION_RANDOMNESS_INTENT: u32 = 1;
const STATE_PRODUCER_COMMAND_CONSTRUCT_RESERVATION_INTENT: u32 = 2;
const STATE_PRODUCER_COMMAND_VERIFY_RESERVATION_INTENT_FOR_WITNESS: u32 = 3;
const STATE_PRODUCER_COMMAND_DERIVE_WITNESS_VOTE_SIGNATURE_MESSAGE: u32 = 4;
const STATE_PRODUCER_COMMAND_CONSTRUCT_WITNESS_VOTE_CARRIER: u32 = 5;
const STATE_PRODUCER_COMMAND_CERTIFY_RESERVATION: u32 = 6;

#[derive(Clone, Copy)]
pub(crate) struct VerifiedStateReservationRuntimeBinding {
    pub(crate) authorization_hash: Hash512,
    pub(crate) durable_binding: StateDurableBinding,
}

enum RuntimeVerifiedStateObject {
    ReservationIntentCandidate(PreparedStateReservationIntent),
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

    fn output(&self, handle: u32) -> RuntimeResult<&VerifiedStateOutput> {
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::Output(output)) => Ok(output),
            Some(_) => Err(refusal_status(RefusalReason::WrongTypeOrLength)),
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }

    fn reservation_intent_candidate(
        &self,
        handle: u32,
    ) -> RuntimeResult<&PreparedStateReservationIntent> {
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::ReservationIntentCandidate(candidate)) => {
                Ok(candidate)
            }
            Some(_) => Err(refusal_status(RefusalReason::WrongTypeOrLength)),
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }

    fn reservation_intent(&self, handle: u32) -> RuntimeResult<&VerifiedStateReservationIntent> {
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::ReservationIntent(intent)) => Ok(intent),
            Some(_) => Err(refusal_status(RefusalReason::WrongTypeOrLength)),
            None => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }

    fn durable_binding(&self, handle: u32) -> RuntimeResult<StateDurableBinding> {
        match self.verified_objects.get(&handle) {
            Some(RuntimeVerifiedStateObject::ReservationIntentCandidate(_)) => {
                Err(refusal_status(RefusalReason::WrongTypeOrLength))
            }
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

    fn prepare_setup_action_randomness_reservation_intent(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        action_randomness_handle: u32,
    ) -> RuntimeResult<(u32, Hash512)> {
        let (prepared_intent, signature_message) = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            let source = resolve_setup_action_randomness_reservation_source(
                action_randomness_handle,
                session
                    .verifier
                    .roster_hash()
                    .map_err(|error| refusal_status(error.refusal_reason))?,
            )?;
            let prepared_intent = session
                .verifier
                .prepare_setup_action_randomness_reservation_intent(
                    source.derivation_input(),
                    source.authorization_hash(),
                )
                .into_result()
                .map_err(refusal_status)?;
            let signature_message = session
                .verifier
                .reservation_intent_signature_message(&prepared_intent)
                .into_result()
                .map_err(refusal_status)?;
            (prepared_intent, signature_message)
        };
        let candidate_handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                candidate_handle,
                RuntimeVerifiedStateObject::ReservationIntentCandidate(prepared_intent),
            );
        Ok((candidate_handle, signature_message))
    }

    fn construct_reservation_intent(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        candidate_handle: u32,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> RuntimeResult<(u32, Vec<u8>)> {
        let produced = {
            let session = self.require_active_session(session_handle, capability)?;
            let candidate = session
                .reservation_intent_candidate(candidate_handle)?
                .clone();
            session
                .verifier
                .construct_and_verify_reservation_intent_carrier(&candidate, signature)
                .into_result()
                .map_err(refusal_status)?
        };
        let (canonical_carrier, verified_intent) = produced.into_parts();
        let verified_intent_handle =
            take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        let session = self.require_active_session_mut(session_handle, capability)?;
        if session.verified_objects.remove(&candidate_handle).is_none() {
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
        session.verified_objects.insert(
            verified_intent_handle,
            RuntimeVerifiedStateObject::ReservationIntent(verified_intent),
        );
        Ok((verified_intent_handle, canonical_carrier))
    }

    fn verify_reservation_intent_for_witness(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        subject_participant_id: ParticipantIdentity,
        canonical_reservation_intent_carrier: &[u8],
    ) -> RuntimeResult<u32> {
        require_verification_input(canonical_reservation_intent_carrier, false)?;
        let verified_intent = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            session
                .verifier
                .verify_setup_action_randomness_intent_for_witness(
                    subject_participant_id,
                    canonical_reservation_intent_carrier,
                )
                .into_result()
                .map_err(refusal_status)?
        };
        let verified_intent_handle =
            take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        self.require_active_session_mut(session_handle, capability)?
            .verified_objects
            .insert(
                verified_intent_handle,
                RuntimeVerifiedStateObject::ReservationIntent(verified_intent),
            );
        Ok(verified_intent_handle)
    }

    fn derive_witness_vote_signature_message(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_intent_handle: u32,
        witness_participant_id: ParticipantIdentity,
    ) -> RuntimeResult<Hash512> {
        let session = self.require_active_session(session_handle, capability)?;
        session
            .verifier
            .derive_state_witness_vote_signature_message(
                session.reservation_intent(verified_intent_handle)?,
                witness_participant_id,
            )
            .into_result()
            .map_err(refusal_status)
    }

    fn construct_witness_vote_carrier(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_intent_handle: u32,
        witness_participant_id: ParticipantIdentity,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> RuntimeResult<Vec<u8>> {
        let session = self.require_active_session(session_handle, capability)?;
        session
            .verifier
            .construct_and_verify_state_witness_vote_carrier(
                session.reservation_intent(verified_intent_handle)?,
                witness_participant_id,
                signature,
            )
            .into_result()
            .map_err(refusal_status)
    }

    fn certify_reservation_and_encode_certificate(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_intent_handle: u32,
        canonical_vote_carriers: &[Vec<u8>],
    ) -> RuntimeResult<(u32, Vec<u8>)> {
        let produced = {
            let session = self.require_active_session(session_handle, capability)?;
            session.require_object_capacity()?;
            session
                .verifier
                .certify_reservation_intent_and_encode_certificate(
                    session.reservation_intent(verified_intent_handle)?,
                    canonical_vote_carriers,
                )
                .into_result()
                .map_err(refusal_status)?
        };
        let (canonical_certificate, verified_reservation) = produced.into_parts();
        let verified_reservation_handle =
            take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
        let session = self.require_active_session_mut(session_handle, capability)?;
        if session
            .verified_objects
            .remove(&verified_intent_handle)
            .is_none()
        {
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
        session.verified_objects.insert(
            verified_reservation_handle,
            RuntimeVerifiedStateObject::Reservation(verified_reservation),
        );
        Ok((verified_reservation_handle, canonical_certificate))
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

    #[allow(clippy::too_many_arguments)]
    fn commit_accepted_setup_reservations<PreparedCommit, Output>(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        ordered_commitment_reservation_handles: &[u32],
        terminal_package_reservation_handles: &[u32],
        expected_terminal_package_authorization_hash: Hash512,
        preflight: impl FnOnce(
            &StateVerifier,
            &[&VerifiedStateReservation],
            &[&VerifiedStateReservation],
        ) -> RuntimeResult<PreparedCommit>,
        commit: impl FnOnce(PreparedCommit) -> Output,
    ) -> RuntimeResult<Output> {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if ordered_commitment_reservation_handles.len() != participant_count
            || terminal_package_reservation_handles.len()
                < usize::from(FOUNDATION_PROFILE.finality_quorum)
            || terminal_package_reservation_handles.len() > participant_count
        {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }

        let prepared_commit = {
            let session = self.require_active_session(session_handle, capability)?;
            let total_handle_count = ordered_commitment_reservation_handles
                .len()
                .checked_add(terminal_package_reservation_handles.len())
                .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
            let mut distinct_handles = HashSet::with_capacity(total_handle_count);
            let mut ordered_commitment_reservations =
                Vec::with_capacity(ordered_commitment_reservation_handles.len());
            for (roster_position, handle) in ordered_commitment_reservation_handles
                .iter()
                .copied()
                .enumerate()
            {
                if handle == 0 || !distinct_handles.insert(handle) {
                    return Err(refusal_status(RefusalReason::WrongTypeOrLength));
                }
                let reservation = session.reservation(handle)?;
                if reservation.capability_kind() != StateCapabilityKind::SetupActionRandomnessRoot {
                    return Err(refusal_status(RefusalReason::WrongTypeOrLength));
                }
                let expected_participant_identity = session
                    .verifier
                    .roster()
                    .entries
                    .get(roster_position)
                    .ok_or_else(|| refusal_status(RefusalReason::WrongTypeOrLength))?
                    .participant_identity()
                    .map_err(|error| refusal_status(error.refusal_reason))?;
                if reservation.subject_participant_id() != expected_participant_identity {
                    return Err(refusal_status(RefusalReason::WrongContext));
                }
                ordered_commitment_reservations.push(reservation);
            }

            let mut terminal_participant_identities =
                HashSet::with_capacity(terminal_package_reservation_handles.len());
            let mut terminal_package_reservations =
                Vec::with_capacity(terminal_package_reservation_handles.len());
            for handle in terminal_package_reservation_handles.iter().copied() {
                if handle == 0 || !distinct_handles.insert(handle) {
                    return Err(refusal_status(RefusalReason::WrongTypeOrLength));
                }
                let reservation = session.reservation(handle)?;
                if reservation.capability_kind() != StateCapabilityKind::SetupTerminalPackage {
                    return Err(refusal_status(RefusalReason::WrongTypeOrLength));
                }
                if reservation.authorization_hash() != expected_terminal_package_authorization_hash
                {
                    return Err(refusal_status(RefusalReason::WrongHashOrRoot));
                }
                if !terminal_participant_identities.insert(reservation.subject_participant_id()) {
                    return Err(refusal_status(RefusalReason::DuplicateIdentity));
                }
                terminal_package_reservations.push(reservation);
            }

            preflight(
                &session.verifier,
                &ordered_commitment_reservations,
                &terminal_package_reservations,
            )?
        };

        // The caller's preflight must reserve the destination handle and make
        // this insertion infallible. Only a completed insertion authorizes
        // destructive removal from the state collector.
        let output = commit(prepared_commit);
        let session = self.require_active_session_mut(session_handle, capability)?;
        for handle in ordered_commitment_reservation_handles
            .iter()
            .chain(terminal_package_reservation_handles)
        {
            let Some(RuntimeVerifiedStateObject::Reservation(_)) =
                session.verified_objects.remove(handle)
            else {
                unreachable!("the preflight borrow established every committed reservation")
            };
        }
        Ok(output)
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

pub(crate) fn run_state_producer_command(command: u32, input: &[u8]) -> RuntimeResult<Vec<u8>> {
    if input.is_empty() || input.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let mut reader = InputReader::new(input);
    let (session_handle, capability) = read_state_session_binding(&mut reader)?;
    let output = match command {
        STATE_PRODUCER_COMMAND_PREPARE_SETUP_ACTION_RANDOMNESS_INTENT => {
            let action_randomness_handle = reader.read_u32()?;
            reader.finish()?;
            let (candidate_handle, signature_message) = with_runtime_registry(|registry| {
                registry.prepare_setup_action_randomness_reservation_intent(
                    session_handle,
                    &capability,
                    action_randomness_handle,
                )
            })?;
            let mut output = Vec::with_capacity(size_of::<u32>() + Hash512::BYTE_LENGTH);
            output.extend_from_slice(&candidate_handle.to_le_bytes());
            output.extend_from_slice(signature_message.as_bytes());
            output
        }
        STATE_PRODUCER_COMMAND_CONSTRUCT_RESERVATION_INTENT => {
            let candidate_handle = reader.read_u32()?;
            let signature = reader.read_array::<ML_DSA_65_SIGNATURE_BYTE_LENGTH>()?;
            reader.finish()?;
            let (verified_intent_handle, canonical_carrier) = with_runtime_registry(|registry| {
                registry.construct_reservation_intent(
                    session_handle,
                    &capability,
                    candidate_handle,
                    signature,
                )
            })?;
            encode_handle_and_bytes(verified_intent_handle, &canonical_carrier)?
        }
        STATE_PRODUCER_COMMAND_VERIFY_RESERVATION_INTENT_FOR_WITNESS => {
            let subject_participant_id = ParticipantIdentity::from_bytes(reader.read_array()?);
            let canonical_carrier = reader.read_length_prefixed_bytes()?;
            reader.finish()?;
            let verified_intent_handle = with_runtime_registry(|registry| {
                registry.verify_reservation_intent_for_witness(
                    session_handle,
                    &capability,
                    subject_participant_id,
                    canonical_carrier,
                )
            })?;
            verified_intent_handle.to_le_bytes().to_vec()
        }
        STATE_PRODUCER_COMMAND_DERIVE_WITNESS_VOTE_SIGNATURE_MESSAGE => {
            let verified_intent_handle = reader.read_u32()?;
            let witness_participant_id = ParticipantIdentity::from_bytes(reader.read_array()?);
            reader.finish()?;
            with_runtime_registry(|registry| {
                registry.derive_witness_vote_signature_message(
                    session_handle,
                    &capability,
                    verified_intent_handle,
                    witness_participant_id,
                )
            })?
            .as_bytes()
            .to_vec()
        }
        STATE_PRODUCER_COMMAND_CONSTRUCT_WITNESS_VOTE_CARRIER => {
            let verified_intent_handle = reader.read_u32()?;
            let witness_participant_id = ParticipantIdentity::from_bytes(reader.read_array()?);
            let signature = reader.read_array::<ML_DSA_65_SIGNATURE_BYTE_LENGTH>()?;
            reader.finish()?;
            with_runtime_registry(|registry| {
                registry.construct_witness_vote_carrier(
                    session_handle,
                    &capability,
                    verified_intent_handle,
                    witness_participant_id,
                    signature,
                )
            })?
        }
        STATE_PRODUCER_COMMAND_CERTIFY_RESERVATION => {
            let verified_intent_handle = reader.read_u32()?;
            let canonical_vote_carriers = decode_unordered_vote_carriers(reader.read_remaining())?;
            let (verified_reservation_handle, canonical_certificate) =
                with_runtime_registry(|registry| {
                    registry.certify_reservation_and_encode_certificate(
                        session_handle,
                        &capability,
                        verified_intent_handle,
                        &canonical_vote_carriers,
                    )
                })?;
            encode_handle_and_bytes(verified_reservation_handle, &canonical_certificate)?
        }
        _ => return Err(refusal_status(RefusalReason::UnsupportedVersionOrSuite)),
    };
    if output.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    Ok(output)
}

fn read_state_session_binding(
    reader: &mut InputReader<'_>,
) -> RuntimeResult<(u32, [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH])> {
    Ok((reader.read_u32()?, reader.read_array()?))
}

fn encode_handle_and_bytes(handle: u32, bytes: &[u8]) -> RuntimeResult<Vec<u8>> {
    let byte_length = u32::try_from(bytes.len())
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    let mut output = Vec::with_capacity(2 * size_of::<u32>() + bytes.len());
    output.extend_from_slice(&handle.to_le_bytes());
    output.extend_from_slice(&byte_length.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(output)
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

/// Borrows one genuine reservation together with the anchored state verifier.
/// This is the generation-side counterpart of the reservation-and-output
/// terminal seam below: it exposes no serialized authority and never consumes
/// the reservation during a retryable proof attempt.
pub(crate) fn with_verified_state_reservation<Value>(
    session_handle: u32,
    capability: &[u8],
    verified_reservation_handle: u32,
    operation: impl FnOnce(&StateVerifier, &VerifiedStateReservation) -> RuntimeResult<Value>,
) -> RuntimeResult<Value> {
    with_runtime_registry(|registry| {
        let session = registry.require_active_session(session_handle, capability)?;
        operation(
            &session.verifier,
            session.reservation(verified_reservation_handle)?,
        )
    })
}

/// Commits one accepted setup against its complete state authority atomically.
///
/// The first handle set must contain exactly the fixed ten kind-four
/// commitments in roster order. The second must contain seven through ten
/// distinct kind-eight reservations authorized by the exact package hash. The
/// fallible preflight borrows every genuine source without consuming it and
/// must reserve an authority destination. The following callback is infallible
/// by type; reservations are removed only after that callback has inserted the
/// authority. Any validation or preflight error leaves the collector intact.
/// Both callbacks run while the state collector is exclusively held and must
/// not re-enter the state runtime.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_accepted_setup_state_reservations<PreparedCommit, Output>(
    session_handle: u32,
    capability: &[u8],
    ordered_commitment_reservation_handles: &[u32],
    terminal_package_reservation_handles: &[u32],
    expected_terminal_package_authorization_hash: Hash512,
    preflight: impl FnOnce(
        &StateVerifier,
        &[&VerifiedStateReservation],
        &[&VerifiedStateReservation],
    ) -> RuntimeResult<PreparedCommit>,
    commit: impl FnOnce(PreparedCommit) -> Output,
) -> RuntimeResult<Output> {
    with_runtime_registry(|registry| {
        registry.commit_accepted_setup_reservations(
            session_handle,
            capability,
            ordered_commitment_reservation_handles,
            terminal_package_reservation_handles,
            expected_terminal_package_authorization_hash,
            preflight,
            commit,
        )
    })
}

/// Borrows the genuine reservation, its exact certified output, and the
/// anchored state-verifier roster for one family terminal. Neither transport
/// hashes nor durable descriptions can recreate these process-local sources.
pub(crate) fn with_verified_state_reservation_and_output<Value>(
    session_handle: u32,
    capability: &[u8],
    verified_reservation_handle: u32,
    verified_output_handle: u32,
    operation: impl FnOnce(
        &StateVerifier,
        &VerifiedStateReservation,
        &VerifiedStateOutput,
    ) -> RuntimeResult<Value>,
) -> RuntimeResult<Value> {
    with_runtime_registry(|registry| {
        let session = registry.require_active_session(session_handle, capability)?;
        operation(
            &session.verifier,
            session.reservation(verified_reservation_handle)?,
            session.output(verified_output_handle)?,
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

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap};

    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
    };

    use super::*;
    use crate::foundation::{
        AuthenticatedCheckpointContinuationSource, FOUNDATION_PROFILE, FoundationObjectType,
        ObjectEnvelope, ProofApplicationSlot, ProofApplicationSlotCeilings, RosterEntry,
        SignedCarrier, StateCertificate, StateReservationIntentPayload, StateWitnessVoteKind,
        StateWitnessVotePayload, derive_state_witness_vote_sequence,
        resolve_prepared_public_only_proof_attempt_source, run_action_randomness_command,
        signature_message,
    };

    const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";

    struct StateProducerRuntimeFixture {
        capability: [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
        configuration: Vec<u8>,
        participant_identities: Vec<ParticipantIdentity>,
        roster_hash: Hash512,
        signing_keys: Vec<ml_dsa_65::PrivateKey>,
    }

    impl StateProducerRuntimeFixture {
        fn new() -> Self {
            let mut roster_entries =
                Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            let mut signing_keys =
                Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                let mut signing_seed = [0_u8; 32];
                signing_seed[0] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                signing_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("test reverse roster position fits u8");
                let (verification_key, signing_key) =
                    ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_seed = [0x41_u8; 32];
                mailbox_seed[0] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                let mut mailbox_fallback_seed = [0x92_u8; 32];
                mailbox_fallback_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("test reverse roster position fits u8");
                let (mailbox_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
                roster_entries.push(RosterEntry {
                    roster_position,
                    signing_verification_key: verification_key.into_bytes(),
                    mailbox_encapsulation_key: mailbox_key.into_bytes(),
                });
                signing_keys.push(signing_key);
            }
            let roster = Roster::new(roster_entries).expect("test roster is valid");
            let participant_identities = roster
                .entries
                .iter()
                .map(|entry| {
                    entry
                        .participant_identity()
                        .expect("participant identity derives")
                })
                .collect();
            let roster_hash = roster.roster_hash().expect("test roster hash derives");
            let roster_bytes = roster.encode().expect("test roster encodes");
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
            Self {
                capability: [0xa5; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
                configuration,
                participant_identities,
                roster_hash,
                signing_keys,
            }
        }

        fn session_input(&self, session_handle: u32) -> Vec<u8> {
            let mut input = Vec::with_capacity(size_of::<u32>() + self.capability.len());
            input.extend_from_slice(&session_handle.to_le_bytes());
            input.extend_from_slice(&self.capability);
            input
        }

        fn action_randomness_open_input(&self) -> Vec<u8> {
            let mut input = vec![0x5a; 64];
            input.extend_from_slice(&[0x11; Hash512::BYTE_LENGTH]);
            input.extend_from_slice(&[0x22; Hash512::BYTE_LENGTH]);
            input.extend_from_slice(&[0x33; Hash512::BYTE_LENGTH]);
            input.extend_from_slice(self.participant_identities[0].as_bytes());
            input
        }

        fn sign_envelope(
            &self,
            producer_roster_position: usize,
            envelope: ObjectEnvelope,
            signature_seed_byte: u8,
        ) -> Vec<u8> {
            let message = signature_message(&envelope, self.roster_hash)
                .expect("test signature message derives");
            let signature = self.signing_keys[producer_roster_position]
                .try_sign_with_seed(
                    &[signature_seed_byte; 32],
                    message.as_bytes(),
                    OBJECT_SIGNATURE_CONTEXT,
                )
                .expect("test signature generates");
            SignedCarrier {
                envelope,
                signature,
            }
            .encode()
            .expect("test signed carrier encodes")
        }

        fn reservation_material(
            &self,
            subject_roster_position: usize,
            capability_kind: StateCapabilityKind,
            authorization_hash: Hash512,
        ) -> (Vec<u8>, Vec<u8>) {
            let intent_envelope = ObjectEnvelope {
                suite_id: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
                object_type: FoundationObjectType::StateReservation,
                ceremony_context_hash: Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
                action_context_hash: Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
                producer_participant_id: Some(self.participant_identities[subject_roster_position]),
                producer_sequence: 0,
                ordered_prerequisite_hashes: Vec::new(),
                payload_bytes: StateReservationIntentPayload {
                    capability_kind,
                    authorization_hash,
                }
                .encode()
                .expect("test reservation payload encodes"),
            };
            let intent_object_hash = intent_envelope
                .object_hash()
                .expect("test reservation object hash derives");
            let subject_roster_byte =
                u8::try_from(subject_roster_position).expect("test roster position fits u8");
            let capability_kind_byte = u8::try_from(capability_kind.canonical_code())
                .expect("test capability-kind code fits u8");
            let canonical_intent_carrier = self.sign_envelope(
                subject_roster_position,
                intent_envelope,
                0x40_u8
                    .wrapping_add(subject_roster_byte)
                    .wrapping_add(capability_kind_byte),
            );
            let vote_sequence =
                derive_state_witness_vote_sequence(StateWitnessVoteKind::Reservation);
            let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
            let canonical_vote_carriers =
                (1..=usize::from(FOUNDATION_PROFILE.state_witness_quorum))
                    .map(|witness_offset| {
                        let witness_roster_position =
                            (subject_roster_position + witness_offset) % participant_count;
                        let witness_roster_byte = u8::try_from(witness_roster_position)
                            .expect("test witness roster position fits u8");
                        let vote_envelope = ObjectEnvelope {
                            suite_id: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
                            object_type: FoundationObjectType::StateWitnessVote,
                            ceremony_context_hash: Hash512::from_bytes(
                                [0x22; Hash512::BYTE_LENGTH],
                            ),
                            action_context_hash: Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
                            producer_participant_id: Some(
                                self.participant_identities[witness_roster_position],
                            ),
                            producer_sequence: vote_sequence,
                            ordered_prerequisite_hashes: Vec::new(),
                            payload_bytes: StateWitnessVotePayload { intent_object_hash }
                                .encode()
                                .expect("test witness-vote payload encodes"),
                        };
                        self.sign_envelope(
                            witness_roster_position,
                            vote_envelope,
                            0x80_u8
                                .wrapping_add(subject_roster_byte)
                                .wrapping_add(witness_roster_byte),
                        )
                    })
                    .collect();
            let canonical_certificate = StateCertificate::new(canonical_vote_carriers)
                .expect("test state certificate has a distinct quorum")
                .encode()
                .expect("test state certificate encodes");
            (canonical_intent_carrier, canonical_certificate)
        }
    }

    fn read_runtime_handle(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[..size_of::<u32>()].try_into().expect("handle bytes"))
    }

    fn frame_vote_carriers(carriers: &[Vec<u8>]) -> Vec<u8> {
        let mut framed = Vec::new();
        framed.extend_from_slice(
            &u32::try_from(carriers.len())
                .expect("test carrier count fits u32")
                .to_le_bytes(),
        );
        for carrier in carriers {
            framed.extend_from_slice(
                &u32::try_from(carrier.len())
                    .expect("test carrier length fits u32")
                    .to_le_bytes(),
            );
            framed.extend_from_slice(carrier);
        }
        framed
    }

    fn retain_test_reservation(
        registry: &mut StateVerifierRuntimeRegistry,
        fixture: &StateProducerRuntimeFixture,
        session_handle: u32,
        subject_roster_position: usize,
        capability_kind: StateCapabilityKind,
        authorization_hash: Hash512,
    ) -> u32 {
        let (canonical_intent_carrier, canonical_certificate) = fixture.reservation_material(
            subject_roster_position,
            capability_kind,
            authorization_hash,
        );
        registry
            .verify_reservation(
                session_handle,
                &fixture.capability,
                fixture.participant_identities[subject_roster_position],
                capability_kind,
                authorization_hash,
                &canonical_intent_carrier,
                &canonical_certificate,
            )
            .expect("test reservation positively verifies")
    }

    struct StateProducerRuntimeCleanup {
        action_randomness_handle: Option<u32>,
        capability: [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
        session_handle: Option<u32>,
    }

    impl Drop for StateProducerRuntimeCleanup {
        fn drop(&mut self) {
            if let Some(session_handle) = self.session_handle.take() {
                let _ = cancel_state_verifier_session(session_handle, &self.capability);
            }
            if let Some(action_randomness_handle) = self.action_randomness_handle.take() {
                let _ = run_action_randomness_command(2, &action_randomness_handle.to_le_bytes());
            }
        }
    }

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
    fn public_only_attempts_require_the_exact_setup_reservation_and_resume_same_lineage() {
        let fixture = StateProducerRuntimeFixture::new();
        let mut registry = StateVerifierRuntimeRegistry::default();
        let session_handle = registry
            .begin(&fixture.configuration, fixture.capability)
            .expect("state verifier session begins");
        let action_randomness_output =
            run_action_randomness_command(1, &fixture.action_randomness_open_input())
                .expect("action randomness opens");
        let action_randomness_handle = read_runtime_handle(&action_randomness_output);
        let mut cleanup = StateProducerRuntimeCleanup {
            action_randomness_handle: Some(action_randomness_handle),
            capability: fixture.capability,
            session_handle: None,
        };
        let setup_reservation_source = resolve_setup_action_randomness_reservation_source(
            action_randomness_handle,
            fixture.roster_hash,
        )
        .expect("the retained action key derives its exact setup reservation");
        let exact_reservation_handle = retain_test_reservation(
            &mut registry,
            &fixture,
            session_handle,
            0,
            StateCapabilityKind::SetupActionRandomnessRoot,
            setup_reservation_source.authorization_hash(),
        );
        let different_reservation_handle = retain_test_reservation(
            &mut registry,
            &fixture,
            session_handle,
            0,
            StateCapabilityKind::SetupActionRandomnessRoot,
            Hash512::from_bytes([0xd4; Hash512::BYTE_LENGTH]),
        );
        let wrong_capability_reservation_handle = retain_test_reservation(
            &mut registry,
            &fixture,
            session_handle,
            0,
            StateCapabilityKind::SetupTerminalPackage,
            setup_reservation_source.authorization_hash(),
        );
        let wrong_subject_reservation_handle = retain_test_reservation(
            &mut registry,
            &fixture,
            session_handle,
            1,
            StateCapabilityKind::SetupActionRandomnessRoot,
            setup_reservation_source.authorization_hash(),
        );
        let exact_reservation_binding = registry
            .reservation_binding(
                session_handle,
                &fixture.capability,
                exact_reservation_handle,
            )
            .expect("the exact setup reservation retains its verifier-derived binding");
        let different_reservation_binding = registry
            .reservation_binding(
                session_handle,
                &fixture.capability,
                different_reservation_handle,
            )
            .expect("the different setup reservation is independently verified");
        let wrong_capability_reservation_binding = registry
            .reservation_binding(
                session_handle,
                &fixture.capability,
                wrong_capability_reservation_handle,
            )
            .expect("the wrong capability reservation is independently verified");
        let wrong_subject_reservation_binding = registry
            .reservation_binding(
                session_handle,
                &fixture.capability,
                wrong_subject_reservation_handle,
            )
            .expect("the wrong subject reservation is independently verified");
        let checkpoint_schedule_digest = Hash512::from_bytes([0x81; Hash512::BYTE_LENGTH]);
        let checkpoint_lineage_identifier = [0x82; 32];
        let mut public_family_lineages = Vec::new();

        for (family_schema_identifier, schedule_position) in [
            (
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
            ),
            (
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
            ),
            (
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
            ),
        ] {
            let application_slot = ProofApplicationSlot::new(
                Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
                family_schema_identifier,
                None,
                schedule_position,
                None,
            )
            .expect("the public-only family has one canonical application slot");
            let application_statement_hash =
                Hash512::from_bytes([0x70; Hash512::BYTE_LENGTH]);
            let fresh_attempt = resolve_prepared_public_only_proof_attempt_source(
                action_randomness_handle,
                exact_reservation_binding,
                fixture.roster_hash,
                application_slot,
                application_statement_hash,
                1,
                1,
                AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                    checkpoint_lineage_identifier,
                    checkpoint_schedule_digest,
                ),
            )
            .expect("the exact public-only attempt is authorized without private coins");
            let resumed_attempt = resolve_prepared_public_only_proof_attempt_source(
                action_randomness_handle,
                exact_reservation_binding,
                fixture.roster_hash,
                application_slot,
                application_statement_hash,
                1,
                1,
                AuthenticatedCheckpointContinuationSource::from_authenticated_common_proof_checkpoint(
                    checkpoint_lineage_identifier,
                    checkpoint_schedule_digest,
                    1,
                    Hash512::from_bytes([0x83; Hash512::BYTE_LENGTH]),
                ),
            )
            .expect("the authenticated continuation resolves the same public-only attempt");

            assert_eq!(
                fresh_attempt.attempt_lineage_identifier(),
                resumed_attempt.attempt_lineage_identifier(),
            );
            assert_eq!(fresh_attempt.application_slot(), application_slot);
            assert_eq!(fresh_attempt.application_statement_hash(), application_statement_hash);
            assert_eq!(fresh_attempt.expected_proof_byte_length(), 1);
            assert_eq!(fresh_attempt.expected_query_count(), 1);
            assert_eq!(fresh_attempt.checkpoint_continuation().next_event_index(), 0);
            assert_eq!(resumed_attempt.checkpoint_continuation().next_event_index(), 1);
            public_family_lineages.push((
                family_schema_identifier,
                fresh_attempt.attempt_lineage_identifier(),
            ));

            assert_eq!(
                resolve_prepared_public_only_proof_attempt_source(
                    action_randomness_handle,
                    different_reservation_binding,
                    fixture.roster_hash,
                    application_slot,
                    application_statement_hash,
                    1,
                    1,
                    AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                        checkpoint_lineage_identifier,
                        checkpoint_schedule_digest,
                    ),
                ),
                Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32),
            );
        }

        for left_index in 0..public_family_lineages.len() {
            for right_index in (left_index + 1)..public_family_lineages.len() {
                assert_ne!(
                    public_family_lineages[left_index].1, public_family_lineages[right_index].1,
                    "distinct public family slots must derive distinct attempt lineages",
                );
            }
        }

        let collective_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            None,
            None,
        )
        .expect("the collective aggregate slot is canonical");
        let changed_statement_attempt = resolve_prepared_public_only_proof_attempt_source(
            action_randomness_handle,
            exact_reservation_binding,
            fixture.roster_hash,
            collective_application_slot,
            Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]),
            1,
            1,
            AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
            ),
        )
        .expect("a different canonical statement derives its own authorized attempt");
        let collective_lineage_identifier = public_family_lineages
            .iter()
            .find_map(|(family_schema_identifier, lineage_identifier)| {
                (*family_schema_identifier
                    == ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER)
                    .then_some(*lineage_identifier)
            })
            .expect("the collective public family lineage was recorded");
        assert_ne!(
            changed_statement_attempt.attempt_lineage_identifier(),
            collective_lineage_identifier,
        );

        for (reservation_binding, refusal_reason) in [
            (
                wrong_capability_reservation_binding,
                RefusalReason::WrongTypeOrLength,
            ),
            (
                wrong_subject_reservation_binding,
                RefusalReason::WrongContext,
            ),
        ] {
            assert_eq!(
                resolve_prepared_public_only_proof_attempt_source(
                    action_randomness_handle,
                    reservation_binding,
                    fixture.roster_hash,
                    collective_application_slot,
                    Hash512::from_bytes([0x70; Hash512::BYTE_LENGTH]),
                    1,
                    1,
                    AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                        checkpoint_lineage_identifier,
                        checkpoint_schedule_digest,
                    ),
                ),
                Err(refusal_reason.canonical_code() as u32),
            );
        }

        let secret_bearing_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            Some(0),
            None,
            None,
        )
        .expect("the secret-bearing family has a canonical slot of its own");
        assert_eq!(
            resolve_prepared_public_only_proof_attempt_source(
                action_randomness_handle,
                exact_reservation_binding,
                fixture.roster_hash,
                secret_bearing_application_slot,
                Hash512::from_bytes([0x70; Hash512::BYTE_LENGTH]),
                1,
                1,
                AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                    checkpoint_lineage_identifier,
                    checkpoint_schedule_digest,
                ),
            ),
            Err(RefusalReason::OutsideSupportedProfile.canonical_code() as u32),
        );

        let wrong_context_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([0x44; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            None,
            None,
        )
        .expect("the public family slot is canonical under its supplied context");
        assert_eq!(
            resolve_prepared_public_only_proof_attempt_source(
                action_randomness_handle,
                exact_reservation_binding,
                fixture.roster_hash,
                wrong_context_application_slot,
                Hash512::from_bytes([0x70; Hash512::BYTE_LENGTH]),
                1,
                1,
                AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                    checkpoint_lineage_identifier,
                    checkpoint_schedule_digest,
                ),
            ),
            Err(RefusalReason::WrongContext.canonical_code() as u32),
        );

        assert_eq!(
            resolve_prepared_public_only_proof_attempt_source(
                action_randomness_handle,
                exact_reservation_binding,
                Hash512::from_bytes([0x99; Hash512::BYTE_LENGTH]),
                collective_application_slot,
                Hash512::from_bytes([0x70; Hash512::BYTE_LENGTH]),
                1,
                1,
                AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                    checkpoint_lineage_identifier,
                    checkpoint_schedule_digest,
                ),
            ),
            Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32),
        );

        run_action_randomness_command(2, &action_randomness_handle.to_le_bytes())
            .expect("action randomness closes");
        cleanup.action_randomness_handle = None;
    }

    #[test]
    fn state_producer_transitions_once_through_signed_intent_distinct_witnesses_and_certificate() {
        let fixture = StateProducerRuntimeFixture::new();
        let session_handle =
            begin_state_verifier_session(&fixture.configuration, fixture.capability)
                .expect("state verifier session begins");
        let action_randomness_output =
            run_action_randomness_command(1, &fixture.action_randomness_open_input())
                .expect("action randomness opens");
        let action_randomness_handle = read_runtime_handle(&action_randomness_output);
        let mut cleanup = StateProducerRuntimeCleanup {
            action_randomness_handle: Some(action_randomness_handle),
            capability: fixture.capability,
            session_handle: Some(session_handle),
        };

        let mut prepare_input = fixture.session_input(session_handle);
        prepare_input.extend_from_slice(&action_randomness_handle.to_le_bytes());
        let prepared = run_state_producer_command(
            STATE_PRODUCER_COMMAND_PREPARE_SETUP_ACTION_RANDOMNESS_INTENT,
            &prepare_input,
        )
        .expect("reservation intent prepares from retained action randomness");
        assert_eq!(prepared.len(), size_of::<u32>() + Hash512::BYTE_LENGTH);
        let candidate_handle = read_runtime_handle(&prepared);
        let signature_message = &prepared[size_of::<u32>()..];

        let mut invalid_construct_input = fixture.session_input(session_handle);
        invalid_construct_input.extend_from_slice(&candidate_handle.to_le_bytes());
        invalid_construct_input.extend_from_slice(&[0_u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH]);
        assert_eq!(
            run_state_producer_command(
                STATE_PRODUCER_COMMAND_CONSTRUCT_RESERVATION_INTENT,
                &invalid_construct_input,
            ),
            Err(refusal_status(RefusalReason::InvalidSignature))
        );

        let subject_signature = fixture.signing_keys[0]
            .try_sign_with_seed(&[0x51; 32], signature_message, OBJECT_SIGNATURE_CONTEXT)
            .expect("subject signs the exact kernel message");
        let mut construct_input = fixture.session_input(session_handle);
        construct_input.extend_from_slice(&candidate_handle.to_le_bytes());
        construct_input.extend_from_slice(&subject_signature);
        let constructed = run_state_producer_command(
            STATE_PRODUCER_COMMAND_CONSTRUCT_RESERVATION_INTENT,
            &construct_input,
        )
        .expect("signed reservation intent self-verifies");
        let verified_intent_handle = read_runtime_handle(&constructed);
        let carrier_byte_length = u32::from_le_bytes(
            constructed[size_of::<u32>()..2 * size_of::<u32>()]
                .try_into()
                .expect("carrier byte length"),
        ) as usize;
        let canonical_intent_carrier = &constructed[2 * size_of::<u32>()..];
        assert_eq!(canonical_intent_carrier.len(), carrier_byte_length);
        assert_eq!(
            run_state_producer_command(
                STATE_PRODUCER_COMMAND_CONSTRUCT_RESERVATION_INTENT,
                &construct_input,
            ),
            Err(refusal_status(RefusalReason::ConsumedState))
        );

        let mut subject_vote_input = fixture.session_input(session_handle);
        subject_vote_input.extend_from_slice(&verified_intent_handle.to_le_bytes());
        subject_vote_input.extend_from_slice(fixture.participant_identities[0].as_bytes());
        assert_eq!(
            run_state_producer_command(
                STATE_PRODUCER_COMMAND_DERIVE_WITNESS_VOTE_SIGNATURE_MESSAGE,
                &subject_vote_input,
            ),
            Err(refusal_status(RefusalReason::WrongContext))
        );

        let mut vote_carriers = Vec::new();
        for roster_position in 1..=usize::from(FOUNDATION_PROFILE.state_witness_quorum) {
            let witness_participant_id = fixture.participant_identities[roster_position];
            let mut vote_message_input = fixture.session_input(session_handle);
            vote_message_input.extend_from_slice(&verified_intent_handle.to_le_bytes());
            vote_message_input.extend_from_slice(witness_participant_id.as_bytes());
            let vote_message = run_state_producer_command(
                STATE_PRODUCER_COMMAND_DERIVE_WITNESS_VOTE_SIGNATURE_MESSAGE,
                &vote_message_input,
            )
            .expect("witness vote message derives");
            let signature = fixture.signing_keys[roster_position]
                .try_sign_with_seed(
                    &[u8::try_from(0x60 + roster_position).expect("hedge byte fits"); 32],
                    &vote_message,
                    OBJECT_SIGNATURE_CONTEXT,
                )
                .expect("witness signs exact kernel message");
            let mut vote_carrier_input = vote_message_input;
            vote_carrier_input.extend_from_slice(&signature);
            vote_carriers.push(
                run_state_producer_command(
                    STATE_PRODUCER_COMMAND_CONSTRUCT_WITNESS_VOTE_CARRIER,
                    &vote_carrier_input,
                )
                .expect("witness vote carrier self-verifies"),
            );
        }

        let duplicate_only =
            vec![vote_carriers[0].clone(); usize::from(FOUNDATION_PROFILE.state_witness_quorum)];
        let mut insufficient_certificate_input = fixture.session_input(session_handle);
        insufficient_certificate_input.extend_from_slice(&verified_intent_handle.to_le_bytes());
        insufficient_certificate_input.extend_from_slice(&frame_vote_carriers(&duplicate_only));
        assert_eq!(
            run_state_producer_command(
                STATE_PRODUCER_COMMAND_CERTIFY_RESERVATION,
                &insufficient_certificate_input,
            ),
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        );

        let mut adversarially_ordered_votes = vote_carriers.clone();
        adversarially_ordered_votes.reverse();
        adversarially_ordered_votes.push(vote_carriers[0].clone());
        let mut certify_input = fixture.session_input(session_handle);
        certify_input.extend_from_slice(&verified_intent_handle.to_le_bytes());
        certify_input.extend_from_slice(&frame_vote_carriers(&adversarially_ordered_votes));
        let certified =
            run_state_producer_command(STATE_PRODUCER_COMMAND_CERTIFY_RESERVATION, &certify_input)
                .expect("distinct fixed-roster quorum certifies the reservation");
        let verified_reservation_handle = read_runtime_handle(&certified);
        let certificate_byte_length = u32::from_le_bytes(
            certified[size_of::<u32>()..2 * size_of::<u32>()]
                .try_into()
                .expect("certificate byte length"),
        ) as usize;
        let canonical_certificate = &certified[2 * size_of::<u32>()..];
        assert_eq!(canonical_certificate.len(), certificate_byte_length);
        let decoded_certificate =
            StateCertificate::decode(canonical_certificate, &CanonicalDecodeLimits::default())
                .expect("produced certificate is canonical");
        assert_eq!(
            decoded_certificate
                .canonical_signed_state_witness_vote_carriers()
                .len(),
            usize::from(FOUNDATION_PROFILE.state_witness_quorum)
        );
        assert_eq!(
            run_state_producer_command(STATE_PRODUCER_COMMAND_CERTIFY_RESERVATION, &certify_input),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        assert!(
            verified_state_reservation_binding(
                session_handle,
                &fixture.capability,
                verified_reservation_handle,
            )
            .is_ok()
        );

        release_verified_state_object(
            session_handle,
            &fixture.capability,
            verified_reservation_handle,
        )
        .expect("reservation releases");
        cancel_state_verifier_session(session_handle, &fixture.capability)
            .expect("state verifier cancels");
        cleanup.session_handle = None;
        run_action_randomness_command(2, &action_randomness_handle.to_le_bytes())
            .expect("action randomness closes");
        cleanup.action_randomness_handle = None;
    }

    #[test]
    fn accepted_setup_commit_preserves_every_reservation_until_infallible_insertion() {
        let fixture = StateProducerRuntimeFixture::new();
        let mut registry = StateVerifierRuntimeRegistry::default();
        let session_handle = registry
            .begin(&fixture.configuration, fixture.capability)
            .expect("state session begins");
        let ordered_commitment_handles = (0..usize::from(FOUNDATION_PROFILE.participant_count))
            .map(|roster_position| {
                retain_test_reservation(
                    &mut registry,
                    &fixture,
                    session_handle,
                    roster_position,
                    StateCapabilityKind::SetupActionRandomnessRoot,
                    Hash512::from_bytes(
                        [0x40_u8.wrapping_add(
                            u8::try_from(roster_position).expect("test roster position fits u8"),
                        ); Hash512::BYTE_LENGTH],
                    ),
                )
            })
            .collect::<Vec<_>>();
        let terminal_package_authorization_hash = Hash512::from_bytes([0xd1; Hash512::BYTE_LENGTH]);
        let terminal_package_handles = (0..usize::from(FOUNDATION_PROFILE.finality_quorum))
            .map(|roster_position| {
                retain_test_reservation(
                    &mut registry,
                    &fixture,
                    session_handle,
                    roster_position,
                    StateCapabilityKind::SetupTerminalPackage,
                    terminal_package_authorization_hash,
                )
            })
            .collect::<Vec<_>>();
        let retained_object_count = registry
            .active_session
            .as_ref()
            .expect("state session remains active")
            .verified_objects
            .len();
        assert_eq!(
            retained_object_count,
            ordered_commitment_handles.len() + terminal_package_handles.len()
        );

        let preflight_called = Cell::new(false);
        assert_eq!(
            registry.commit_accepted_setup_reservations(
                session_handle,
                &fixture.capability,
                &ordered_commitment_handles,
                &terminal_package_handles,
                Hash512::from_bytes([0xd2; Hash512::BYTE_LENGTH]),
                |_, _, _| {
                    preflight_called.set(true);
                    Ok(())
                },
                |()| (),
            ),
            Err(refusal_status(RefusalReason::WrongHashOrRoot))
        );
        assert!(!preflight_called.get());
        assert_eq!(
            registry
                .active_session
                .as_ref()
                .expect("state session remains active")
                .verified_objects
                .len(),
            retained_object_count
        );

        let mut wrong_commitment_order = ordered_commitment_handles.clone();
        wrong_commitment_order.swap(0, 1);
        assert_eq!(
            registry.commit_accepted_setup_reservations(
                session_handle,
                &fixture.capability,
                &wrong_commitment_order,
                &terminal_package_handles,
                terminal_package_authorization_hash,
                |_, _, _| Ok(()),
                |()| (),
            ),
            Err(refusal_status(RefusalReason::WrongContext))
        );
        assert_eq!(
            registry
                .active_session
                .as_ref()
                .expect("state session remains active")
                .verified_objects
                .len(),
            retained_object_count
        );

        let mut duplicate_terminal_handle = terminal_package_handles.clone();
        duplicate_terminal_handle[1] = duplicate_terminal_handle[0];
        assert_eq!(
            registry.commit_accepted_setup_reservations(
                session_handle,
                &fixture.capability,
                &ordered_commitment_handles,
                &duplicate_terminal_handle,
                terminal_package_authorization_hash,
                |_, _, _| Ok(()),
                |()| (),
            ),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );
        assert_eq!(
            registry
                .active_session
                .as_ref()
                .expect("state session remains active")
                .verified_objects
                .len(),
            retained_object_count
        );

        let preflight_refusal = refusal_status(RefusalReason::OutsideSupportedProfile);
        assert_eq!(
            registry.commit_accepted_setup_reservations(
                session_handle,
                &fixture.capability,
                &ordered_commitment_handles,
                &terminal_package_handles,
                terminal_package_authorization_hash,
                |_, _, _| Err(preflight_refusal),
                |()| (),
            ),
            Err(preflight_refusal)
        );
        assert_eq!(
            registry
                .active_session
                .as_ref()
                .expect("state session remains active")
                .verified_objects
                .len(),
            retained_object_count
        );

        let mut authority_collector = BTreeMap::new();
        let authority_handle = registry
            .commit_accepted_setup_reservations(
                session_handle,
                &fixture.capability,
                &ordered_commitment_handles,
                &terminal_package_handles,
                terminal_package_authorization_hash,
                |state_verifier, ordered_commitments, terminal_reservations| {
                    assert_eq!(
                        state_verifier
                            .roster_hash()
                            .expect("state verifier roster hash derives"),
                        fixture.roster_hash
                    );
                    assert_eq!(
                        ordered_commitments.len(),
                        usize::from(FOUNDATION_PROFILE.participant_count)
                    );
                    assert_eq!(
                        terminal_reservations.len(),
                        usize::from(FOUNDATION_PROFILE.finality_quorum)
                    );
                    assert!(ordered_commitments.iter().enumerate().all(
                        |(roster_position, reservation)| {
                            reservation.capability_kind()
                                == StateCapabilityKind::SetupActionRandomnessRoot
                                && reservation.subject_participant_id()
                                    == fixture.participant_identities[roster_position]
                        }
                    ));
                    assert!(terminal_reservations.iter().all(|reservation| {
                        reservation.capability_kind() == StateCapabilityKind::SetupTerminalPackage
                            && reservation.authorization_hash()
                                == terminal_package_authorization_hash
                    }));
                    Ok((fixture.roster_hash, terminal_package_authorization_hash))
                },
                |prepared_authority| {
                    let authority_handle = 1_u32;
                    assert!(
                        authority_collector
                            .insert(authority_handle, prepared_authority)
                            .is_none()
                    );
                    authority_handle
                },
            )
            .expect("preflighted authority insertion commits");
        assert_eq!(authority_handle, 1);
        assert_eq!(authority_collector.len(), 1);
        assert!(
            registry
                .active_session
                .as_ref()
                .expect("state session remains active")
                .verified_objects
                .is_empty()
        );
        for consumed_handle in ordered_commitment_handles
            .iter()
            .chain(&terminal_package_handles)
        {
            assert!(matches!(
                registry.reservation_binding(
                    session_handle,
                    &fixture.capability,
                    *consumed_handle,
                ),
                Err(status) if status == refusal_status(RefusalReason::ConsumedState)
            ));
        }
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
