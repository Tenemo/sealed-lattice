use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer},
};

use super::*;
use crate::foundation::{RosterEntry, signature_message};

const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";
const SUBJECT_ROSTER_POSITION: usize = 0;
const EXACT_OUTPUT_BYTES: &[u8] = b"complete canonical output bytes";

struct TestFixture {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    roster_hash: Hash512,
    private_keys: Vec<ml_dsa_65::PrivateKey>,
    participant_identities: Vec<ParticipantIdentity>,
}

impl TestFixture {
    fn new() -> Self {
        let mut roster_entries =
            Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        let mut private_keys =
            Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let mut key_seed = [0u8; 32];
            key_seed[0] = u8::try_from(roster_position + 1).expect("test roster position fits u8");
            key_seed[31] = u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                .expect("test reverse roster position fits u8");
            let (public_key, private_key) = ml_dsa_65::KG::keygen_from_seed(&key_seed);
            let mut mailbox_encapsulation_key = [0u8; 1_184];
            mailbox_encapsulation_key[1_152] =
                u8::try_from(roster_position + 1).expect("test roster position fits u8");
            roster_entries.push(RosterEntry {
                roster_position,
                signing_verification_key: public_key.into_bytes(),
                mailbox_encapsulation_key,
            });
            private_keys.push(private_key);
        }
        let roster = Roster::new(roster_entries).expect("test roster is canonical");
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
        Self {
            suite_id: Hash512::from_bytes([0x11; 64]),
            ceremony_context_hash: Hash512::from_bytes([0x22; 64]),
            action_context_hash: Hash512::from_bytes([0x33; 64]),
            roster,
            roster_hash,
            private_keys,
            participant_identities,
        }
    }

    fn verifier(&self) -> StateVerifier {
        StateVerifier::new(
            self.suite_id,
            self.ceremony_context_hash,
            self.action_context_hash,
            &self.roster,
            4,
            CanonicalDecodeLimits::default(),
        )
        .expect("test state verifier constructs")
    }

    fn subject_participant_id(&self) -> ParticipantIdentity {
        self.participant_identities[SUBJECT_ROSTER_POSITION]
    }

    fn sign_envelope(
        &self,
        producer_roster_position: usize,
        envelope: ObjectEnvelope,
        signature_seed_byte: u8,
    ) -> Vec<u8> {
        let message =
            signature_message(&envelope, self.roster_hash).expect("test signature message derives");
        let signature = self.private_keys[producer_roster_position]
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

    fn subject_envelope(
        &self,
        object_type: FoundationObjectType,
        recovery_epoch: u64,
        predecessor_transition_hash: Option<Hash512>,
        producer_sequence: u64,
        payload_bytes: Vec<u8>,
    ) -> ObjectEnvelope {
        ObjectEnvelope {
            suite_id: self.suite_id,
            object_type,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            recovery_epoch,
            recovery_transition_hash: predecessor_transition_hash,
            producer_participant_id: Some(self.subject_participant_id()),
            producer_sequence,
            ordered_prerequisite_hashes: Vec::new(),
            payload_bytes,
        }
    }

    fn signed_subject_intent(
        &self,
        object_type: FoundationObjectType,
        recovery_epoch: u64,
        predecessor_transition_hash: Option<Hash512>,
        producer_sequence: u64,
        payload_bytes: Vec<u8>,
    ) -> Vec<u8> {
        self.sign_envelope(
            SUBJECT_ROSTER_POSITION,
            self.subject_envelope(
                object_type,
                recovery_epoch,
                predecessor_transition_hash,
                producer_sequence,
                payload_bytes,
            ),
            0x41_u8.wrapping_add(object_type.canonical_code() as u8),
        )
    }

    fn vote_carrier(
        &self,
        witness_roster_position: usize,
        intent_object_hash: Hash512,
        producer_sequence: u64,
    ) -> Vec<u8> {
        let payload_bytes = StateWitnessVotePayload { intent_object_hash }
            .encode()
            .expect("test vote payload encodes");
        self.sign_envelope(
            witness_roster_position,
            ObjectEnvelope {
                suite_id: self.suite_id,
                object_type: FoundationObjectType::StateWitnessVote,
                ceremony_context_hash: self.ceremony_context_hash,
                action_context_hash: self.action_context_hash,
                recovery_epoch: 0,
                recovery_transition_hash: None,
                producer_participant_id: Some(self.participant_identities[witness_roster_position]),
                producer_sequence,
                ordered_prerequisite_hashes: Vec::new(),
                payload_bytes,
            },
            0x80_u8.wrapping_add(
                u8::try_from(witness_roster_position)
                    .expect("test witness roster position fits u8"),
            ),
        )
    }

    fn certificate_for_positions(
        &self,
        intent_object_hash: Hash512,
        producer_sequence: u64,
        witness_roster_positions: &[usize],
    ) -> Vec<u8> {
        let vote_carriers = witness_roster_positions
            .iter()
            .map(|witness_roster_position| {
                self.vote_carrier(
                    *witness_roster_position,
                    intent_object_hash,
                    producer_sequence,
                )
            })
            .collect();
        StateCertificate::new(vote_carriers)
            .expect("test certificate count is supported")
            .encode()
            .expect("test certificate encodes")
    }
}

fn object_hash(canonical_signed_carrier: &[u8]) -> Hash512 {
    SignedCarrier::decode(canonical_signed_carrier, &CanonicalDecodeLimits::default())
        .expect("test carrier decodes")
        .envelope
        .object_hash()
        .expect("test object hash derives")
}

fn verified_exact_output_stream(
    capability_kind: StateCapabilityKind,
    exact_output_bytes: &[u8],
) -> VerifiedCanonicalStreamSummary {
    let stream_domain = match capability_kind {
        StateCapabilityKind::BallotCandidateList => {
            crate::foundation::CanonicalStreamDomain::StateBallotCandidateListExactOutput
        }
        StateCapabilityKind::FinalitySignature => {
            crate::foundation::CanonicalStreamDomain::StateFinalitySignatureExactOutput
        }
        StateCapabilityKind::TargetRelease => {
            crate::foundation::CanonicalStreamDomain::StateTargetReleaseExactOutput
        }
    };
    let descriptor =
        crate::foundation::derive_canonical_stream_descriptor(stream_domain, exact_output_bytes)
            .expect("exact-output stream descriptor derives");
    let mut verifier = crate::foundation::CanonicalStreamVerifier::new(stream_domain, descriptor)
        .expect("exact-output stream verifier begins");
    for (chunk_index, chunk) in exact_output_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        assert_eq!(
            verifier.absorb_chunk(chunk_index, chunk),
            VerificationResult::valid(())
        );
    }
    verifier
        .finish_with_summary()
        .into_result()
        .expect("exact-output stream verifies")
}

fn expect_refusal<Value>(
    result: VerificationResult<Value>,
    expected_refusal_reason: RefusalReason,
) {
    match result {
        VerificationResult::Valid { .. } => panic!("verification unexpectedly accepted"),
        VerificationResult::Refused { refusal_reason } => {
            assert_eq!(refusal_reason, expected_refusal_reason)
        }
    }
}

#[test]
fn state_payload_and_certificate_codecs_are_exact_and_bounded() {
    let limits = CanonicalDecodeLimits::default();
    let reservation = StateReservationIntentPayload {
        capability_kind: StateCapabilityKind::FinalitySignature,
        authorization_hash: Hash512::from_bytes([0x11; 64]),
    };
    let output = StateOutputIntentPayload {
        reservation_intent_object_hash: Hash512::from_bytes([0x22; 64]),
        exact_output_hash: Hash512::from_bytes([0x33; 64]),
    };
    let vote = StateWitnessVotePayload {
        intent_object_hash: Hash512::from_bytes([0x44; 64]),
    };
    let recovery = StateRecoveryTransitionPayload {
        capability_kind: StateCapabilityKind::TargetRelease,
        preserved_latest_intent_object_hash: Some(Hash512::from_bytes([0x55; 64])),
    };

    for (encoded, expected_schema_identifier) in [
        (
            reservation.encode().expect("reservation encodes"),
            STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER,
        ),
        (
            output.encode().expect("output encodes"),
            STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
        ),
        (
            vote.encode().expect("vote encodes"),
            STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
        ),
        (
            recovery.encode().expect("recovery encodes"),
            STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER,
        ),
    ] {
        assert_eq!(
            u16::from_le_bytes([encoded[0], encoded[1]]),
            expected_schema_identifier
        );
        assert_eq!(u16::from_le_bytes([encoded[2], encoded[3]]), 1);
        assert_eq!(
            CanonicalTuple::decode(&encoded, &limits)
                .expect("state payload is a canonical tuple")
                .schema_identifier,
            expected_schema_identifier
        );
    }
    assert_eq!(
        StateReservationIntentPayload::decode(
            &reservation.encode().expect("reservation encodes"),
            &limits,
        )
        .expect("reservation decodes"),
        reservation
    );
    assert_eq!(
        StateOutputIntentPayload::decode(&output.encode().expect("output encodes"), &limits)
            .expect("output decodes"),
        output
    );
    assert_eq!(
        StateWitnessVotePayload::decode(&vote.encode().expect("vote encodes"), &limits)
            .expect("vote decodes"),
        vote
    );
    assert_eq!(
        StateRecoveryTransitionPayload::decode(
            &recovery.encode().expect("recovery encodes"),
            &limits,
        )
        .expect("recovery decodes"),
        recovery
    );

    let certificate = StateCertificate::new(
        (0..usize::from(FOUNDATION_PROFILE.state_witness_quorum))
            .map(|index| vec![u8::try_from(index).expect("index fits u8"); index + 1])
            .collect(),
    )
    .expect("certificate constructs");
    let encoded_certificate = certificate.encode().expect("certificate encodes");
    assert_eq!(
        StateCertificate::decode(&encoded_certificate, &limits).expect("certificate decodes"),
        certificate
    );

    for unsupported_count in [0, 1, 6, 10, 4_096] {
        let result = StateCertificate::new(vec![Vec::new(); unsupported_count]);
        assert_eq!(
            result
                .expect_err("unsupported certificate count must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    let mut wrong_version = reservation.encode().expect("reservation encodes");
    wrong_version[2..4].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        StateReservationIntentPayload::decode(&wrong_version, &limits)
            .expect_err("unsupported version refuses")
            .refusal_reason,
        RefusalReason::UnsupportedVersionOrSuite
    );
    let mut trailing_bytes = vote.encode().expect("vote encodes");
    trailing_bytes.push(0);
    assert_eq!(
        StateWitnessVotePayload::decode(&trailing_bytes, &limits)
            .expect_err("trailing bytes refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );
    let mut unassigned_capability = reservation.encode().expect("reservation encodes");
    unassigned_capability[14..16].copy_from_slice(&4_u16.to_le_bytes());
    assert_eq!(
        StateReservationIntentPayload::decode(&unassigned_capability, &limits)
            .expect_err("unassigned capability refuses")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let mut oversized_certificate_count = encoded_certificate;
    oversized_certificate_count[16..20].copy_from_slice(&10_u32.to_le_bytes());
    assert_eq!(
        StateCertificate::decode(&oversized_certificate_count, &limits)
            .expect_err("oversized certificate count refuses before proportional parsing")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );
}

#[test]
fn state_derivations_check_domains_boundaries_and_replay_equivocation() {
    let suite_id = Hash512::from_bytes([1; 64]);
    let ceremony_context_hash = Hash512::from_bytes([2; 64]);
    let action_context_hash = Hash512::from_bytes([3; 64]);
    let participant_id = ParticipantIdentity::from_bytes([4; 64]);
    let other_participant_id = ParticipantIdentity::from_bytes([5; 64]);
    let state_key = derive_state_key(
        suite_id,
        ceremony_context_hash,
        action_context_hash,
        participant_id,
        StateCapabilityKind::BallotCandidateList,
    )
    .expect("state key derives");
    assert_eq!(
        state_key,
        derive_state_key(
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            participant_id,
            StateCapabilityKind::BallotCandidateList,
        )
        .expect("same state key derives")
    );
    assert_ne!(
        state_key,
        derive_state_key(
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            other_participant_id,
            StateCapabilityKind::BallotCandidateList,
        )
        .expect("other participant state key derives")
    );
    assert_ne!(
        state_key,
        derive_state_key(
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            participant_id,
            StateCapabilityKind::FinalitySignature,
        )
        .expect("other capability state key derives")
    );

    let exact_output_hash =
        derive_state_exact_output_hash(StateCapabilityKind::BallotCandidateList, b"abc")
            .expect("exact output hash derives");
    assert_ne!(
        exact_output_hash,
        derive_state_exact_output_hash(StateCapabilityKind::BallotCandidateList, b"ab")
            .expect("shorter exact output hash derives")
    );
    assert_ne!(
        exact_output_hash,
        derive_state_exact_output_hash(StateCapabilityKind::FinalitySignature, b"abc")
            .expect("other capability output hash derives")
    );

    assert_eq!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Reservation, 0)
            .expect("epoch-zero reservation sequence derives"),
        1
    );
    assert_eq!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Output, 0)
            .expect("epoch-zero output sequence derives"),
        2
    );
    assert_eq!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Recovery, 1)
            .expect("first recovery sequence derives"),
        3
    );
    let largest_reservation_epoch = (u64::MAX - 1) / 3;
    let largest_output_epoch = (u64::MAX - 2) / 3;
    let largest_recovery_epoch = u64::MAX / 3;
    assert!(
        derive_state_witness_vote_sequence(
            StateWitnessVoteKind::Reservation,
            largest_reservation_epoch,
        )
        .is_ok()
    );
    assert!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Output, largest_output_epoch)
            .is_ok()
    );
    assert!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Recovery, largest_recovery_epoch,)
            .is_ok()
    );
    for (vote_kind, overflowing_epoch) in [
        (
            StateWitnessVoteKind::Reservation,
            largest_reservation_epoch + 1,
        ),
        (StateWitnessVoteKind::Output, largest_output_epoch + 1),
        (StateWitnessVoteKind::Recovery, largest_recovery_epoch + 1),
    ] {
        assert_eq!(
            derive_state_witness_vote_sequence(vote_kind, overflowing_epoch)
                .expect_err("overflowing witness sequence refuses")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }
    assert_eq!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Recovery, 0)
            .expect_err("epoch-zero recovery refuses")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );
    assert_eq!(
        derive_state_recovery_producer_sequence(u64::MAX)
            .expect_err("recovery epoch overflow refuses")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );

    let replay_key = StateWitnessVoteReplayKey::new(
        action_context_hash,
        other_participant_id,
        participant_id,
        state_key,
        StateWitnessVoteKind::Reservation,
        0,
    )
    .expect("reservation replay key derives");
    let intent_object_hash = Hash512::from_bytes([6; 64]);
    let mut replay_index = EphemeralStateWitnessVoteReplayIndex::new();
    assert_eq!(
        replay_index.observe(replay_key, intent_object_hash),
        VerificationResult::valid(StateWitnessVoteReplayDisposition::FirstObservation)
    );
    assert_eq!(
        replay_index.observe(replay_key, intent_object_hash),
        VerificationResult::valid(StateWitnessVoteReplayDisposition::IdempotentReplay)
    );
    assert_eq!(
        replay_index.observe(replay_key, Hash512::from_bytes([7; 64])),
        VerificationResult::refused(RefusalReason::Equivocation)
    );
    assert_eq!(
        replay_index.observe(
            StateWitnessVoteReplayKey::new(
                action_context_hash,
                other_participant_id,
                participant_id,
                state_key,
                StateWitnessVoteKind::Output,
                0,
            )
            .expect("output replay key derives"),
            Hash512::from_bytes([7; 64]),
        ),
        VerificationResult::valid(StateWitnessVoteReplayDisposition::FirstObservation)
    );
}

#[test]
fn state_verifier_accepts_exact_quorums_and_refuses_every_malformed_extra_or_conflict() {
    let fixture = TestFixture::new();
    let verifier = fixture.verifier();
    match StateVerifier::new(
        fixture.suite_id,
        fixture.ceremony_context_hash,
        fixture.action_context_hash,
        &fixture.roster,
        0,
        CanonicalDecodeLimits::default(),
    ) {
        Err(error) => assert_eq!(error.refusal_reason, RefusalReason::OutsideSupportedProfile),
        Ok(_) => panic!("a zero suite recovery-transition maximum unexpectedly accepted"),
    }
    let subject_participant_id = fixture.subject_participant_id();
    let capability_kind = StateCapabilityKind::TargetRelease;
    let authorization_hash = Hash512::from_bytes([0xa1; 64]);
    let reservation_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateReservation,
        0,
        None,
        0,
        StateReservationIntentPayload {
            capability_kind,
            authorization_hash,
        }
        .encode()
        .expect("reservation payload encodes"),
    );
    let reservation_hash = object_hash(&reservation_carrier);
    let reservation_certificate = fixture.certificate_for_positions(
        reservation_hash,
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Reservation, 0)
            .expect("reservation sequence derives"),
        &[1, 2, 3, 4, 5, 6, 7],
    );
    let verified_reservation = verifier
        .verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &reservation_certificate,
        })
        .into_result()
        .expect("valid reservation quorum verifies");
    assert_eq!(verified_reservation.intent_object_hash(), reservation_hash);
    assert_eq!(
        verified_reservation.subject_participant_id(),
        subject_participant_id
    );
    assert_eq!(verified_reservation.capability_kind(), capability_kind);
    assert_eq!(
        verified_reservation.authorization_hash(),
        authorization_hash
    );
    assert_eq!(verified_reservation.recovery_epoch(), 0);
    assert_eq!(verified_reservation.predecessor_transition_hash(), None);

    let exact_output_hash = derive_state_exact_output_hash(capability_kind, EXACT_OUTPUT_BYTES)
        .expect("exact output hash derives");
    let output_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateOutputIntent,
        0,
        None,
        0,
        StateOutputIntentPayload {
            reservation_intent_object_hash: reservation_hash,
            exact_output_hash,
        }
        .encode()
        .expect("output payload encodes"),
    );
    let output_hash = object_hash(&output_carrier);
    let output_certificate = fixture.certificate_for_positions(
        output_hash,
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Output, 0)
            .expect("output sequence derives"),
        &[1, 2, 3, 4, 5, 6, 7, 8],
    );
    let verified_output = verifier
        .verify_output_from_verified_stream(
            &verified_reservation,
            &output_carrier,
            &output_certificate,
            verified_exact_output_stream(capability_kind, EXACT_OUTPUT_BYTES),
        )
        .into_result()
        .expect("valid output quorum verifies");
    assert_eq!(
        verified_output.reservation_intent_object_hash(),
        reservation_hash
    );
    assert_eq!(verified_output.output_intent_object_hash(), output_hash);
    assert_eq!(verified_output.exact_output_hash(), exact_output_hash);
    assert_eq!(
        verified_output.exact_output_byte_length(),
        u64::try_from(EXACT_OUTPUT_BYTES.len()).expect("output length fits u64")
    );

    let recovery_carrier = fixture.signed_subject_intent(
        FoundationObjectType::RecoveryTransition,
        0,
        None,
        1,
        StateRecoveryTransitionPayload {
            capability_kind,
            preserved_latest_intent_object_hash: Some(output_hash),
        }
        .encode()
        .expect("recovery payload encodes"),
    );
    let recovery_hash = object_hash(&recovery_carrier);
    let recovery_certificate = fixture.certificate_for_positions(
        recovery_hash,
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Recovery, 1)
            .expect("recovery sequence derives"),
        &[1, 2, 3, 4, 5, 6, 7],
    );
    let preserved_output = PreservedStateIntent::Output(&verified_output);
    let verified_recovery = verifier
        .verify_recovery(StateRecoveryVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            preserved_state_intent: Some(preserved_output),
            canonical_recovery_transition_carrier: &recovery_carrier,
            canonical_state_certificate: &recovery_certificate,
        })
        .into_result()
        .expect("valid recovery quorum verifies");
    assert_eq!(verified_recovery.transition_object_hash(), recovery_hash);
    assert_eq!(verified_recovery.old_recovery_epoch(), 0);
    assert_eq!(verified_recovery.new_recovery_epoch(), 1);
    assert_eq!(
        verified_recovery.preserved_latest_intent_object_hash(),
        Some(output_hash)
    );

    let empty_recovery_capability_kind = StateCapabilityKind::BallotCandidateList;
    let empty_recovery_carrier = fixture.signed_subject_intent(
        FoundationObjectType::RecoveryTransition,
        0,
        None,
        1,
        StateRecoveryTransitionPayload {
            capability_kind: empty_recovery_capability_kind,
            preserved_latest_intent_object_hash: None,
        }
        .encode()
        .expect("empty recovery payload encodes"),
    );
    let empty_recovery_hash = object_hash(&empty_recovery_carrier);
    let empty_recovery_certificate = fixture.certificate_for_positions(
        empty_recovery_hash,
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Recovery, 1)
            .expect("empty recovery sequence derives"),
        &[1, 2, 3, 4, 5, 6, 7],
    );
    let verified_empty_recovery = verifier
        .verify_recovery(StateRecoveryVerificationInput {
            subject_participant_id,
            capability_kind: empty_recovery_capability_kind,
            verified_predecessor_recovery: None,
            preserved_state_intent: None,
            canonical_recovery_transition_carrier: &empty_recovery_carrier,
            canonical_state_certificate: &empty_recovery_certificate,
        })
        .into_result()
        .expect("an empty first recovery verifies");
    let post_recovery_authorization_hash = Hash512::from_bytes([0xb2; 64]);
    let post_recovery_reservation_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateReservation,
        1,
        Some(empty_recovery_hash),
        0,
        StateReservationIntentPayload {
            capability_kind: empty_recovery_capability_kind,
            authorization_hash: post_recovery_authorization_hash,
        }
        .encode()
        .expect("post-recovery reservation payload encodes"),
    );
    let post_recovery_reservation_hash = object_hash(&post_recovery_reservation_carrier);
    let post_recovery_reservation_certificate = fixture.certificate_for_positions(
        post_recovery_reservation_hash,
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Reservation, 1)
            .expect("post-recovery reservation sequence derives"),
        &[1, 2, 3, 4, 5, 6, 7],
    );
    let verified_post_recovery_reservation = verifier
        .verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind: empty_recovery_capability_kind,
            verified_predecessor_recovery: Some(&verified_empty_recovery),
            expected_authorization_hash: post_recovery_authorization_hash,
            canonical_reservation_intent_carrier: &post_recovery_reservation_carrier,
            canonical_state_certificate: &post_recovery_reservation_certificate,
        })
        .into_result()
        .expect("a reservation derives its epoch and predecessor from verified recovery");
    assert_eq!(verified_post_recovery_reservation.recovery_epoch(), 1);
    assert_eq!(
        verified_post_recovery_reservation.predecessor_transition_hash(),
        Some(empty_recovery_hash)
    );

    let one_transition_verifier = StateVerifier::new(
        fixture.suite_id,
        fixture.ceremony_context_hash,
        fixture.action_context_hash,
        &fixture.roster,
        1,
        CanonicalDecodeLimits::default(),
    )
    .expect("one-transition verifier constructs");
    expect_refusal(
        one_transition_verifier.verify_recovery(StateRecoveryVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: Some(&verified_recovery),
            preserved_state_intent: None,
            canonical_recovery_transition_carrier: &[],
            canonical_state_certificate: &[],
        }),
        RefusalReason::OutsideSupportedProfile,
    );

    expect_refusal(
        verifier.verify_output_from_verified_stream(
            &verified_reservation,
            &output_carrier,
            &output_certificate,
            verified_exact_output_stream(capability_kind, b"different complete output bytes"),
        ),
        RefusalReason::WrongHashOrRoot,
    );

    let duplicate_certificate =
        fixture.certificate_for_positions(reservation_hash, 1, &[1, 2, 3, 4, 5, 6, 6]);
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &duplicate_certificate,
        }),
        RefusalReason::DuplicateIdentity,
    );

    let unordered_certificate =
        fixture.certificate_for_positions(reservation_hash, 1, &[2, 1, 3, 4, 5, 6, 7]);
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &unordered_certificate,
        }),
        RefusalReason::WrongTypeOrLength,
    );

    let subject_inclusive_certificate =
        fixture.certificate_for_positions(reservation_hash, 1, &[0, 1, 2, 3, 4, 5, 6]);
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &subject_inclusive_certificate,
        }),
        RefusalReason::WrongContext,
    );

    let wrong_intent_certificate = fixture.certificate_for_positions(
        Hash512::from_bytes([0xfe; 64]),
        1,
        &[1, 2, 3, 4, 5, 6, 7],
    );
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &wrong_intent_certificate,
        }),
        RefusalReason::WrongHashOrRoot,
    );

    let wrong_sequence_certificate =
        fixture.certificate_for_positions(reservation_hash, 2, &[1, 2, 3, 4, 5, 6, 7]);
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &wrong_sequence_certificate,
        }),
        RefusalReason::WrongContext,
    );

    let mut invalid_extra_carriers = (1..=8)
        .map(|witness_roster_position| {
            fixture.vote_carrier(witness_roster_position, reservation_hash, 1)
        })
        .collect::<Vec<_>>();
    let last_carrier = invalid_extra_carriers
        .last_mut()
        .expect("invalid-extra certificate has a last carrier");
    let mut decoded_last_carrier =
        SignedCarrier::decode(last_carrier, &CanonicalDecodeLimits::default())
            .expect("last carrier decodes");
    decoded_last_carrier.signature[0] ^= 1;
    *last_carrier = decoded_last_carrier
        .encode()
        .expect("mutated carrier encodes");
    let invalid_extra_certificate = StateCertificate::new(invalid_extra_carriers)
        .expect("eight-carrier certificate constructs")
        .encode()
        .expect("eight-carrier certificate encodes");
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &invalid_extra_certificate,
        }),
        RefusalReason::InvalidSignature,
    );

    expect_refusal(
        verifier.verify_recovery(StateRecoveryVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            preserved_state_intent: None,
            canonical_recovery_transition_carrier: &recovery_carrier,
            canonical_state_certificate: &recovery_certificate,
        }),
        RefusalReason::MissingPrerequisite,
    );

    let arbitrary_predecessor_hash = Hash512::from_bytes([0xc7; 64]);
    let arbitrary_chain_reservation_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateReservation,
        1,
        Some(arbitrary_predecessor_hash),
        0,
        StateReservationIntentPayload {
            capability_kind,
            authorization_hash,
        }
        .encode()
        .expect("arbitrary-chain reservation payload encodes"),
    );
    let arbitrary_chain_reservation_hash = object_hash(&arbitrary_chain_reservation_carrier);
    let arbitrary_chain_certificate = fixture.certificate_for_positions(
        arbitrary_chain_reservation_hash,
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Reservation, 1)
            .expect("epoch-one reservation sequence derives"),
        &[1, 2, 3, 4, 5, 6, 7],
    );
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: None,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &arbitrary_chain_reservation_carrier,
            canonical_state_certificate: &arbitrary_chain_certificate,
        }),
        RefusalReason::WrongContext,
    );

    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: Some(&verified_recovery),
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &reservation_certificate,
        }),
        RefusalReason::ConsumedState,
    );
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind: StateCapabilityKind::FinalitySignature,
            verified_predecessor_recovery: Some(&verified_recovery),
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &reservation_certificate,
        }),
        RefusalReason::WrongContext,
    );
    let other_context_verifier = StateVerifier::new(
        fixture.suite_id,
        fixture.ceremony_context_hash,
        Hash512::from_bytes([0xdd; 64]),
        &fixture.roster,
        4,
        CanonicalDecodeLimits::default(),
    )
    .expect("other-context verifier constructs");
    expect_refusal(
        other_context_verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind,
            verified_predecessor_recovery: Some(&verified_recovery),
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &reservation_certificate,
        }),
        RefusalReason::WrongContext,
    );

    let output_lock = StateWitnessLock::new(
        verified_output.state_key(),
        Some(reservation_hash),
        Some(output_hash),
    )
    .expect("output lock constructs");
    assert_eq!(
        verify_state_witness_lock_preservation(
            &output_lock,
            Some(&PreservedStateIntent::Output(&verified_output)),
        ),
        VerificationResult::valid(())
    );
    assert_eq!(
        verify_state_witness_lock_preservation(
            &output_lock,
            Some(&PreservedStateIntent::Reservation(&verified_reservation)),
        ),
        VerificationResult::refused(RefusalReason::ConsumedState)
    );
    assert_eq!(
        verify_state_witness_lock_preservation(&output_lock, None),
        VerificationResult::refused(RefusalReason::ConsumedState)
    );
    let empty_lock = StateWitnessLock::new(verified_output.state_key(), None, None)
        .expect("empty lock constructs");
    assert_eq!(
        verify_state_witness_lock_preservation(&empty_lock, None),
        VerificationResult::valid(())
    );
    let other_state_empty_lock = StateWitnessLock::new(Hash512::from_bytes([0x7f; 64]), None, None)
        .expect("other-state empty lock constructs");
    assert_eq!(
        verify_state_witness_lock_preservation(
            &other_state_empty_lock,
            Some(&PreservedStateIntent::Output(&verified_output)),
        ),
        VerificationResult::refused(RefusalReason::WrongContext)
    );
    assert_eq!(
        StateWitnessLock::new(verified_output.state_key(), None, Some(output_hash))
            .expect_err("an output-only lock refuses")
            .refusal_reason,
        RefusalReason::MissingPrerequisite
    );
}
