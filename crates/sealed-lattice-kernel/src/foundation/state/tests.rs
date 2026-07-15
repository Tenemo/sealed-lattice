use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use super::*;
use crate::foundation::{CanonicalStreamDomain, RosterEntry, signature_message};

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
            let mut signing_seed = [0_u8; 32];
            signing_seed[0] =
                u8::try_from(roster_position + 1).expect("test roster position fits u8");
            signing_seed[31] = u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                .expect("test reverse roster position fits u8");
            let (public_key, private_key) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);

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
                signing_verification_key: public_key.into_bytes(),
                mailbox_encapsulation_key: mailbox_key.into_bytes(),
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

    fn signed_subject_intent(
        &self,
        object_type: FoundationObjectType,
        payload_bytes: Vec<u8>,
    ) -> Vec<u8> {
        self.sign_envelope(
            SUBJECT_ROSTER_POSITION,
            ObjectEnvelope {
                suite_id: self.suite_id,
                object_type,
                ceremony_context_hash: self.ceremony_context_hash,
                action_context_hash: self.action_context_hash,
                producer_participant_id: Some(self.subject_participant_id()),
                producer_sequence: 0,
                ordered_prerequisite_hashes: Vec::new(),
                payload_bytes,
            },
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
        vote_kind: StateWitnessVoteKind,
        witness_roster_positions: &[usize],
    ) -> Vec<u8> {
        let producer_sequence = derive_state_witness_vote_sequence(vote_kind);
        let vote_carriers = witness_roster_positions
            .iter()
            .map(|position| self.vote_carrier(*position, intent_object_hash, producer_sequence))
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
        StateCapabilityKind::FinalitySignature => {
            CanonicalStreamDomain::StateFinalitySignatureExactOutput
        }
        StateCapabilityKind::TargetRelease => CanonicalStreamDomain::StateTargetReleaseExactOutput,
        StateCapabilityKind::SetupActionRandomnessRoot
        | StateCapabilityKind::SetupTerminalPackage => {
            panic!("reservation-only state capability has no exact-output stream")
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
    ] {
        let tuple = CanonicalTuple::decode(&encoded, &limits).expect("state payload is canonical");
        assert_eq!(tuple.schema_identifier, expected_schema_identifier);
        assert_eq!(tuple.schema_version, 1);
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

    for capability_kind in [
        StateCapabilityKind::FinalitySignature,
        StateCapabilityKind::TargetRelease,
        StateCapabilityKind::SetupActionRandomnessRoot,
        StateCapabilityKind::SetupTerminalPackage,
    ] {
        assert_eq!(
            StateCapabilityKind::from_canonical_code(capability_kind.canonical_code()),
            Some(capability_kind)
        );
    }
    for unassigned_code in [0, 5, 6, 7, 9, u16::MAX] {
        assert_eq!(
            StateCapabilityKind::from_canonical_code(unassigned_code),
            None
        );
    }

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
        assert_eq!(
            StateCertificate::new(vec![Vec::new(); unsupported_count])
                .expect_err("unsupported certificate count refuses")
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

    let mut unassigned_capability =
        CanonicalTuple::decode(&reservation.encode().expect("reservation encodes"), &limits)
            .expect("reservation tuple decodes");
    unassigned_capability.items[0] = CanonicalItem::unsigned16(9);
    assert_eq!(
        StateReservationIntentPayload::decode(
            &unassigned_capability
                .encode()
                .expect("mutated reservation tuple encodes"),
            &limits,
        )
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
fn state_derivations_are_domain_separated_and_exact_output_is_complete() {
    let suite_id = Hash512::from_bytes([1; 64]);
    let ceremony_context_hash = Hash512::from_bytes([2; 64]);
    let action_context_hash = Hash512::from_bytes([3; 64]);
    let participant_id = ParticipantIdentity::from_bytes([4; 64]);
    let state_key = derive_state_key(
        suite_id,
        ceremony_context_hash,
        action_context_hash,
        participant_id,
        StateCapabilityKind::FinalitySignature,
    )
    .expect("state key derives");
    assert_ne!(
        state_key,
        derive_state_key(
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            ParticipantIdentity::from_bytes([5; 64]),
            StateCapabilityKind::FinalitySignature,
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
            StateCapabilityKind::TargetRelease,
        )
        .expect("other capability state key derives")
    );

    let finality_hash =
        derive_state_exact_output_hash(StateCapabilityKind::FinalitySignature, b"abc")
            .expect("finality exact-output hash derives");
    assert_ne!(
        finality_hash,
        derive_state_exact_output_hash(StateCapabilityKind::TargetRelease, b"abc")
            .expect("target exact-output hash derives")
    );
    assert_ne!(
        finality_hash,
        derive_state_exact_output_hash(StateCapabilityKind::FinalitySignature, b"ab")
            .expect("shorter exact-output hash derives")
    );
    assert_eq!(
        derive_state_exact_output_hash(StateCapabilityKind::SetupTerminalPackage, b"abc")
            .expect_err("reservation-only capability refuses exact output")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let mut incomplete = StateExactOutputHasher::new(StateCapabilityKind::FinalitySignature, 3)
        .expect("incremental hasher begins");
    incomplete.absorb(b"ab").expect("prefix absorbs");
    assert_eq!(
        incomplete
            .finish()
            .expect_err("incomplete exact output refuses")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );
    let mut overflowing = StateExactOutputHasher::new(StateCapabilityKind::FinalitySignature, 2)
        .expect("incremental hasher begins");
    assert_eq!(
        overflowing
            .absorb(b"abc")
            .expect_err("oversized exact output refuses")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    assert_eq!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Reservation),
        1
    );
    assert_eq!(
        derive_state_witness_vote_sequence(StateWitnessVoteKind::Output),
        2
    );
}

#[test]
fn state_verifier_binds_reservation_quorum_and_exact_output() {
    let fixture = TestFixture::new();
    let verifier = fixture.verifier();
    let subject_participant_id = fixture.subject_participant_id();
    let authorization_hash = Hash512::from_bytes([0xa1; 64]);
    let reservation_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateReservation,
        StateReservationIntentPayload {
            capability_kind: StateCapabilityKind::FinalitySignature,
            authorization_hash,
        }
        .encode()
        .expect("reservation payload encodes"),
    );
    let reservation_hash = object_hash(&reservation_carrier);
    let reservation_certificate = fixture.certificate_for_positions(
        reservation_hash,
        StateWitnessVoteKind::Reservation,
        &[1, 2, 3, 4, 5, 6, 7],
    );
    let verified_reservation = verifier
        .verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind: StateCapabilityKind::FinalitySignature,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &reservation_certificate,
        })
        .into_result()
        .expect("valid reservation verifies");
    assert_eq!(verified_reservation.intent_object_hash(), reservation_hash);
    assert_eq!(
        verified_reservation.authorization_hash(),
        authorization_hash
    );
    assert_eq!(
        verified_reservation
            .durable_binding()
            .witness_vote_sequence(),
        1
    );

    let exact_output_hash =
        derive_state_exact_output_hash(StateCapabilityKind::FinalitySignature, EXACT_OUTPUT_BYTES)
            .expect("exact-output hash derives");
    let output_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateOutputIntent,
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
        StateWitnessVoteKind::Output,
        &[1, 2, 3, 4, 5, 6, 7],
    );
    let verified_output = verifier
        .verify_output_from_verified_stream(
            &verified_reservation,
            &output_carrier,
            &output_certificate,
            verified_exact_output_stream(
                StateCapabilityKind::FinalitySignature,
                EXACT_OUTPUT_BYTES,
            ),
        )
        .into_result()
        .expect("valid exact output verifies");
    assert_eq!(verified_output.output_intent_object_hash(), output_hash);
    assert_eq!(verified_output.exact_output_hash(), exact_output_hash);
    assert_eq!(
        verified_output.exact_output_byte_length(),
        u64::try_from(EXACT_OUTPUT_BYTES.len()).expect("test length fits u64")
    );
    assert_eq!(verified_output.durable_binding().witness_vote_sequence(), 2);

    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind: StateCapabilityKind::FinalitySignature,
            expected_authorization_hash: Hash512::from_bytes([0xa2; 64]),
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &reservation_certificate,
        }),
        RefusalReason::WrongHashOrRoot,
    );
    expect_refusal(
        verifier.verify_output_from_verified_stream(
            &verified_reservation,
            &output_carrier,
            &output_certificate,
            verified_exact_output_stream(StateCapabilityKind::TargetRelease, EXACT_OUTPUT_BYTES),
        ),
        RefusalReason::WrongContext,
    );

    let wrong_output_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateOutputIntent,
        StateOutputIntentPayload {
            reservation_intent_object_hash: reservation_hash,
            exact_output_hash: Hash512::from_bytes([0xee; 64]),
        }
        .encode()
        .expect("wrong output payload encodes"),
    );
    expect_refusal(
        verifier.verify_output_from_verified_stream(
            &verified_reservation,
            &wrong_output_carrier,
            &output_certificate,
            verified_exact_output_stream(
                StateCapabilityKind::FinalitySignature,
                EXACT_OUTPUT_BYTES,
            ),
        ),
        RefusalReason::WrongHashOrRoot,
    );

    let duplicate_certificate = fixture.certificate_for_positions(
        reservation_hash,
        StateWitnessVoteKind::Reservation,
        &[1, 1, 2, 3, 4, 5, 6],
    );
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind: StateCapabilityKind::FinalitySignature,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &duplicate_certificate,
        }),
        RefusalReason::DuplicateIdentity,
    );
    let reordered_certificate = fixture.certificate_for_positions(
        reservation_hash,
        StateWitnessVoteKind::Reservation,
        &[2, 1, 3, 4, 5, 6, 7],
    );
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind: StateCapabilityKind::FinalitySignature,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &reordered_certificate,
        }),
        RefusalReason::WrongTypeOrLength,
    );
    let self_witnessed_certificate = fixture.certificate_for_positions(
        reservation_hash,
        StateWitnessVoteKind::Reservation,
        &[0, 1, 2, 3, 4, 5, 6],
    );
    expect_refusal(
        verifier.verify_reservation(StateReservationVerificationInput {
            subject_participant_id,
            capability_kind: StateCapabilityKind::FinalitySignature,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
            canonical_state_certificate: &self_witnessed_certificate,
        }),
        RefusalReason::WrongContext,
    );
}

#[test]
fn unordered_state_votes_authenticate_before_duplicate_and_equivocation_resolution() {
    let fixture = TestFixture::new();
    let verifier = fixture.verifier();
    let authorization_hash = Hash512::from_bytes([0xb1; 64]);
    let reservation_carrier = fixture.signed_subject_intent(
        FoundationObjectType::StateReservation,
        StateReservationIntentPayload {
            capability_kind: StateCapabilityKind::TargetRelease,
            authorization_hash,
        }
        .encode()
        .expect("reservation payload encodes"),
    );
    let reservation_hash = object_hash(&reservation_carrier);
    let verified_intent = verifier
        .verify_reservation_intent(StateReservationIntentVerificationInput {
            subject_participant_id: fixture.subject_participant_id(),
            capability_kind: StateCapabilityKind::TargetRelease,
            expected_authorization_hash: authorization_hash,
            canonical_reservation_intent_carrier: &reservation_carrier,
        })
        .into_result()
        .expect("reservation intent verifies");
    let sequence = derive_state_witness_vote_sequence(StateWitnessVoteKind::Reservation);
    let mut unordered_votes = (1..=7)
        .rev()
        .map(|position| fixture.vote_carrier(position, reservation_hash, sequence))
        .collect::<Vec<_>>();
    unordered_votes.push(unordered_votes[0].clone());
    verifier
        .certify_reservation_intent_from_unordered_vote_carriers(&verified_intent, &unordered_votes)
        .into_result()
        .expect("unordered votes and semantic replay verify");

    let mut insufficient_votes = unordered_votes[..6].to_vec();
    insufficient_votes.dedup();
    expect_refusal(
        verifier.certify_reservation_intent_from_unordered_vote_carriers(
            &verified_intent,
            &insufficient_votes,
        ),
        RefusalReason::OutsideSupportedProfile,
    );

    let mut equivocation_votes = (1..=7)
        .map(|position| fixture.vote_carrier(position, reservation_hash, sequence))
        .collect::<Vec<_>>();
    equivocation_votes.push(fixture.vote_carrier(1, Hash512::from_bytes([0xef; 64]), sequence));
    expect_refusal(
        verifier.certify_reservation_intent_from_unordered_vote_carriers(
            &verified_intent,
            &equivocation_votes,
        ),
        RefusalReason::Equivocation,
    );

    let mut forged_vote = fixture.vote_carrier(1, Hash512::from_bytes([0xee; 64]), sequence);
    let last_byte = forged_vote.last_mut().expect("signed vote is nonempty");
    *last_byte ^= 1;
    let mut forged_conflict_votes = (1..=7)
        .map(|position| fixture.vote_carrier(position, reservation_hash, sequence))
        .collect::<Vec<_>>();
    forged_conflict_votes.push(forged_vote);
    expect_refusal(
        verifier.certify_reservation_intent_from_unordered_vote_carriers(
            &verified_intent,
            &forged_conflict_votes,
        ),
        RefusalReason::InvalidSignature,
    );
}

#[test]
fn setup_state_capabilities_are_reservation_only() {
    for capability_kind in [
        StateCapabilityKind::SetupActionRandomnessRoot,
        StateCapabilityKind::SetupTerminalPackage,
    ] {
        let fixture = TestFixture::new();
        let verifier = fixture.verifier();
        let authorization_hash = Hash512::from_bytes(
            [u8::try_from(capability_kind.canonical_code()).expect("capability code fits u8"); 64],
        );
        let reservation_carrier = fixture.signed_subject_intent(
            FoundationObjectType::StateReservation,
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
            StateWitnessVoteKind::Reservation,
            &[1, 2, 3, 4, 5, 6, 7],
        );
        let verified_reservation = verifier
            .verify_reservation(StateReservationVerificationInput {
                subject_participant_id: fixture.subject_participant_id(),
                capability_kind,
                expected_authorization_hash: authorization_hash,
                canonical_reservation_intent_carrier: &reservation_carrier,
                canonical_state_certificate: &reservation_certificate,
            })
            .into_result()
            .expect("reservation-only setup capability verifies");
        expect_refusal(
            verifier.verify_output_from_verified_stream(
                &verified_reservation,
                b"not an output intent",
                b"not a certificate",
                verified_exact_output_stream(
                    StateCapabilityKind::TargetRelease,
                    EXACT_OUTPUT_BYTES,
                ),
            ),
            RefusalReason::WrongTypeOrLength,
        );
    }
}
