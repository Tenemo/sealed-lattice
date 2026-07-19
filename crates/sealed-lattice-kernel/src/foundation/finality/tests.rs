use super::*;
use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use crate::foundation::{
    CanonicalBoardLimits, CanonicalBoardVerifier, RosterEntry, StateOutputIntentPayload,
    StateReservationIntentPayload, StateWitnessVoteKind, StateWitnessVotePayload,
    derive_state_exact_output_hash, derive_state_witness_vote_sequence, signature_message,
};

const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";
fn hash(byte: u8) -> Hash512 {
    Hash512::from_bytes([byte; 64])
}

fn canonical_placeholder_carrier(producer_byte: u8) -> Vec<u8> {
    SignedCarrier {
        envelope: ObjectEnvelope {
            suite_id: hash(1),
            object_type: FoundationObjectType::FinalitySignature,
            ceremony_context_hash: hash(2),
            action_context_hash: hash(3),
            producer_participant_id: Some(ParticipantIdentity::from_bytes([producer_byte; 64])),
            producer_sequence: 0,
            ordered_prerequisite_hashes: vec![hash(5)],
            payload_bytes: FinalitySignaturePayload::new(hash(6))
                .encode()
                .expect("placeholder finality payload"),
        },
        signature: [0; crate::foundation::ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    }
    .encode()
    .expect("placeholder signed carrier")
}

fn placeholder_state_certificate() -> StateCertificate {
    StateCertificate::new(
        (0..usize::from(FOUNDATION_PROFILE.state_witness_quorum))
            .map(|index| vec![u8::try_from(index + 1).expect("index fits u8")])
            .collect(),
    )
    .expect("placeholder certificate")
}

struct FinalityTestFixture {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    roster_hash: Hash512,
    participant_identities: Vec<ParticipantIdentity>,
    signing_keys: Vec<ml_dsa_65::PrivateKey>,
}

impl FinalityTestFixture {
    fn new() -> Self {
        let mut roster_entries =
            Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        let mut signing_keys =
            Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let mut signing_seed = [0_u8; 32];
            signing_seed[0] = u8::try_from(roster_position + 1).expect("roster position fits u8");
            signing_seed[31] = u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                .expect("reverse roster position fits u8");
            let (verification_key, signing_key) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            let mut mailbox_seed = [0x41_u8; 32];
            mailbox_seed[0] = u8::try_from(roster_position + 1).expect("roster position fits u8");
            let mut mailbox_fallback_seed = [0x92_u8; 32];
            mailbox_fallback_seed[31] =
                u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                    .expect("reverse roster position fits u8");
            let (mailbox_key, _) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            roster_entries.push(RosterEntry {
                roster_position,
                signing_verification_key: verification_key.into_bytes(),
                mailbox_encapsulation_key: mailbox_key.into_bytes(),
            });
            signing_keys.push(signing_key);
        }
        let roster = Roster::new(roster_entries).expect("test roster");
        let roster_hash = roster.roster_hash().expect("test roster hash");
        let participant_identities = roster
            .entries
            .iter()
            .map(|entry| entry.participant_identity().expect("participant identity"))
            .collect();
        Self {
            suite_identifier: hash(0x11),
            ceremony_context_hash: hash(0x22),
            action_context_hash: hash(0x33),
            roster,
            roster_hash,
            participant_identities,
            signing_keys,
        }
    }

    fn board_verifier(&self) -> CanonicalBoardVerifier {
        CanonicalBoardVerifier::new(
            self.suite_identifier,
            self.ceremony_context_hash,
            self.action_context_hash,
            &self.roster,
            CanonicalBoardLimits {
                maximum_ballot_attempts_per_participant: 4,
                maximum_retained_canonical_carrier_byte_length: 8 * 1024 * 1024,
                maximum_unordered_carriers_per_batch: 128,
                maximum_retained_transcript_objects: 512,
            },
            CanonicalDecodeLimits::default(),
        )
        .expect("test board verifier")
    }

    fn envelope(
        &self,
        producer_roster_position: Option<usize>,
        object_type: FoundationObjectType,
        ordered_prerequisite_hashes: Vec<Hash512>,
        payload_bytes: Vec<u8>,
    ) -> ObjectEnvelope {
        ObjectEnvelope {
            suite_id: self.suite_identifier,
            object_type,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            producer_participant_id: producer_roster_position
                .map(|position| self.participant_identities[position]),
            producer_sequence: 0,
            ordered_prerequisite_hashes,
            payload_bytes,
        }
    }

    fn sign_envelope(
        &self,
        producer_roster_position: usize,
        envelope: ObjectEnvelope,
        signature_seed: [u8; 32],
    ) -> Vec<u8> {
        let message = signature_message(&envelope, self.roster_hash).expect("signature message");
        let signature = self.signing_keys[producer_roster_position]
            .try_sign_with_seed(
                &signature_seed,
                message.as_bytes(),
                OBJECT_SIGNATURE_CONTEXT,
            )
            .expect("test signature");
        SignedCarrier {
            envelope,
            signature,
        }
        .encode()
        .expect("signed carrier")
    }

    fn signed_subject_carrier(
        &self,
        subject_roster_position: usize,
        object_type: FoundationObjectType,
        ordered_prerequisite_hashes: Vec<Hash512>,
        payload_bytes: Vec<u8>,
        operation_ordinal: u8,
    ) -> Vec<u8> {
        let mut signature_seed = [operation_ordinal; 32];
        signature_seed[0] =
            u8::try_from(subject_roster_position + 1).expect("subject roster position fits u8");
        self.sign_envelope(
            subject_roster_position,
            self.envelope(
                Some(subject_roster_position),
                object_type,
                ordered_prerequisite_hashes,
                payload_bytes,
            ),
            signature_seed,
        )
    }

    fn stream_descriptor(
        &self,
        stream_domain: CanonicalStreamDomain,
        content_byte: u8,
    ) -> StreamDescriptor {
        derive_canonical_stream_descriptor(stream_domain, &[content_byte])
            .expect("test stream descriptor")
    }

    fn stream_descriptor_item(
        &self,
        stream_domain: CanonicalStreamDomain,
        content_byte: u8,
    ) -> CanonicalItem {
        let descriptor = self.stream_descriptor(stream_domain, content_byte);
        let tuple = CanonicalTuple::decode(
            &descriptor.encode().expect("descriptor bytes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("descriptor tuple");
        CanonicalItem::nested_tuple(&tuple).expect("nested descriptor")
    }

    fn verified_stream(
        &self,
        stream_domain: CanonicalStreamDomain,
        content_byte: u8,
    ) -> VerifiedCanonicalStreamSummary {
        let descriptor = self.stream_descriptor(stream_domain, content_byte);
        let mut verifier =
            CanonicalStreamVerifier::new(stream_domain, descriptor).expect("test stream verifier");
        verifier
            .absorb_chunk(0, &[content_byte])
            .into_result()
            .expect("test stream chunk");
        verifier
            .finish_with_summary()
            .into_result()
            .expect("test stream summary")
    }

    fn ingest_replay(
        &self,
        board_verifier: &mut CanonicalBoardVerifier,
    ) -> VerifiedEvaluatorReplay {
        let verified_setup_source_hash = hash(0x51);
        let ballots = (0..usize::from(FOUNDATION_PROFILE.participant_count))
            .map(|roster_position| {
                let payload = CanonicalTuple::new(
                    0x1301,
                    1,
                    vec![
                        self.stream_descriptor_item(CanonicalStreamDomain::BallotCiphertext, 0xc1),
                        self.stream_descriptor_item(
                            CanonicalStreamDomain::BallotValidityProof,
                            0xc2,
                        ),
                    ],
                )
                .encode()
                .expect("ballot payload");
                self.signed_subject_carrier(
                    roster_position,
                    FoundationObjectType::BallotPackage,
                    vec![verified_setup_source_hash],
                    payload,
                    0x60,
                )
            })
            .collect::<Vec<_>>();
        let ballot_hashes = ballots
            .iter()
            .map(|carrier| canonical_signed_carrier_object_hash(carrier))
            .collect::<Vec<_>>();
        let selected_ballot_items = ballot_hashes
            .iter()
            .map(|object_hash| CanonicalItem::hash512(object_hash.into_bytes()))
            .collect::<Vec<_>>();
        let aggregate_payload = CanonicalTuple::new(
            0x1404,
            1,
            vec![
                CanonicalItem::hash512(verified_setup_source_hash.into_bytes()),
                CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &selected_ballot_items)
                    .expect("selected ballot list"),
                self.stream_descriptor_item(CanonicalStreamDomain::AggregateCiphertext, 0xc3),
            ],
        )
        .encode()
        .expect("aggregate payload");
        let aggregate_envelope = self.envelope(
            None,
            FoundationObjectType::Aggregate,
            Vec::new(),
            aggregate_payload,
        );
        let aggregate_hash = aggregate_envelope.object_hash().expect("aggregate hash");
        let aggregate = aggregate_envelope.encode().expect("aggregate envelope");
        let replay_payload = super::super::schemas::EvaluatorReplayPayload::new(
            verified_setup_source_hash,
            aggregate_hash,
            self.stream_descriptor(
                CanonicalStreamDomain::ReplayTargetIdentifierCiphertext,
                0xc4,
            ),
            self.stream_descriptor(CanonicalStreamDomain::ReplayTargetOrderCiphertext, 0xc5),
        )
        .encode()
        .expect("replay payload");
        let replay_envelope = self.envelope(
            None,
            FoundationObjectType::EvaluatorReplay,
            Vec::new(),
            replay_payload,
        );
        let replay_hash = replay_envelope.object_hash().expect("replay hash");
        let replay = replay_envelope.encode().expect("replay envelope");
        let mut unordered = vec![replay, aggregate];
        unordered.extend(ballots.into_iter().rev());
        let batch = board_verifier
            .verify_unordered_carriers(&unordered)
            .into_result()
            .expect("replay dependency graph");
        let replay_object = batch
            .objects()
            .iter()
            .find(|object| object.object_hash() == replay_hash)
            .expect("replay capability");
        VerifiedEvaluatorReplay::from_verified_relation(
            replay_object,
            self.roster_hash,
            4,
            1,
            1,
            self.verified_stream(
                CanonicalStreamDomain::ReplayTargetIdentifierCiphertext,
                0xc4,
            ),
            self.verified_stream(CanonicalStreamDomain::ReplayTargetOrderCiphertext, 0xc5),
            &CanonicalDecodeLimits::default(),
        )
        .expect("verified replay relation fixture")
    }

    fn state_certificate(
        &self,
        subject_roster_position: usize,
        intent_object_hash: Hash512,
        vote_kind: StateWitnessVoteKind,
    ) -> StateCertificate {
        let producer_sequence = derive_state_witness_vote_sequence(vote_kind);
        let witness_positions = (0..usize::from(FOUNDATION_PROFILE.participant_count))
            .filter(|position| *position != subject_roster_position)
            .take(usize::from(FOUNDATION_PROFILE.state_witness_quorum));
        let vote_carriers = witness_positions
            .map(|witness_roster_position| {
                let payload = StateWitnessVotePayload { intent_object_hash }
                    .encode()
                    .expect("state vote payload");
                let mut envelope = self.envelope(
                    Some(witness_roster_position),
                    FoundationObjectType::StateWitnessVote,
                    Vec::new(),
                    payload,
                );
                envelope.producer_sequence = producer_sequence;
                let mut seed = [vote_kind.canonical_code() as u8; 32];
                seed[0] =
                    u8::try_from(subject_roster_position + 1).expect("subject position fits u8");
                seed[1] =
                    u8::try_from(witness_roster_position + 1).expect("witness position fits u8");
                self.sign_envelope(witness_roster_position, envelope, seed)
            })
            .collect();
        StateCertificate::new(vote_carriers).expect("state certificate")
    }

    fn finality_signer_input(
        &self,
        subject_roster_position: usize,
        statement_hash: Hash512,
        evaluator_replay_object_hash: Hash512,
    ) -> FinalitySignerInput {
        let reservation_payload = StateReservationIntentPayload {
            capability_kind: StateCapabilityKind::FinalitySignature,
            authorization_hash: statement_hash,
        }
        .encode()
        .expect("reservation payload");
        let reservation_carrier = self.signed_subject_carrier(
            subject_roster_position,
            FoundationObjectType::StateReservation,
            Vec::new(),
            reservation_payload,
            0x71,
        );
        let reservation_object_hash = canonical_signed_carrier_object_hash(&reservation_carrier);
        let reservation_certificate = self.state_certificate(
            subject_roster_position,
            reservation_object_hash,
            StateWitnessVoteKind::Reservation,
        );

        let finality_carrier = self.signed_subject_carrier(
            subject_roster_position,
            FoundationObjectType::FinalitySignature,
            vec![evaluator_replay_object_hash],
            FinalitySignaturePayload::new(statement_hash)
                .encode()
                .expect("finality payload"),
            0x72,
        );
        let exact_output_hash = derive_state_exact_output_hash(
            StateCapabilityKind::FinalitySignature,
            &finality_carrier,
        )
        .expect("finality exact output hash");
        let output_payload = StateOutputIntentPayload {
            reservation_intent_object_hash: reservation_object_hash,
            exact_output_hash,
        }
        .encode()
        .expect("output payload");
        let output_carrier = self.signed_subject_carrier(
            subject_roster_position,
            FoundationObjectType::StateOutputIntent,
            Vec::new(),
            output_payload,
            0x73,
        );
        let output_object_hash = canonical_signed_carrier_object_hash(&output_carrier);
        let output_certificate = self.state_certificate(
            subject_roster_position,
            output_object_hash,
            StateWitnessVoteKind::Output,
        );
        FinalitySignerInput::new(
            finality_carrier,
            reservation_carrier,
            reservation_certificate,
            output_carrier,
            output_certificate,
            &CanonicalDecodeLimits::default(),
        )
        .expect("finality signer input")
    }
}

fn canonical_signed_carrier_object_hash(canonical_carrier: &[u8]) -> Hash512 {
    SignedCarrier::decode(canonical_carrier, &CanonicalDecodeLimits::default())
        .expect("signed carrier")
        .envelope
        .object_hash()
        .expect("signed carrier object hash")
}

#[test]
fn finality_statement_round_trips_and_binds_every_field() {
    let statement = FinalityStatement::new(hash(1), hash(2), hash(3), hash(4), hash(5));
    let bytes = statement.encode().expect("finality statement");
    assert_eq!(
        FinalityStatement::decode(&bytes, &CanonicalDecodeLimits::default())
            .expect("canonical finality statement"),
        statement,
    );

    let original_hash = statement.finality_hash().expect("finality hash");
    let replacements = [
        FinalityStatement::new(hash(9), hash(2), hash(3), hash(4), hash(5)),
        FinalityStatement::new(hash(1), hash(9), hash(3), hash(4), hash(5)),
        FinalityStatement::new(hash(1), hash(2), hash(9), hash(4), hash(5)),
        FinalityStatement::new(hash(1), hash(2), hash(3), hash(9), hash(5)),
        FinalityStatement::new(hash(1), hash(2), hash(3), hash(4), hash(9)),
    ];
    for replacement in replacements {
        assert_ne!(
            replacement.finality_hash().expect("replacement hash"),
            original_hash,
        );
    }
}

#[test]
fn finality_statement_refuses_a_changed_protocol_version() {
    let statement = FinalityStatement::new(hash(1), hash(2), hash(3), hash(4), hash(5));
    let mut tuple = CanonicalTuple::decode(
        &statement.encode().expect("finality statement"),
        &CanonicalDecodeLimits::default(),
    )
    .expect("finality tuple");
    tuple.items[0] = CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version + 1);
    let error = FinalityStatement::decode(
        &tuple.encode().expect("changed statement"),
        &CanonicalDecodeLimits::default(),
    )
    .expect_err("changed protocol version must refuse");
    assert_eq!(
        error.refusal_reason,
        RefusalReason::UnsupportedVersionOrSuite
    );
}

#[test]
fn finality_certificate_refuses_counts_outside_the_quorum_profile() {
    let error = FinalityCertificate::new(Vec::new())
        .expect_err("an empty finality certificate must refuse");
    assert_eq!(error.refusal_reason, RefusalReason::OutsideSupportedProfile);
}

#[test]
fn finality_transport_round_trips_one_canonical_representation() {
    let limits = CanonicalDecodeLimits::default();
    let signer_inputs = (0..FOUNDATION_PROFILE.finality_quorum)
        .map(|position| {
            let carrier = canonical_placeholder_carrier(
                u8::try_from(position + 1).expect("position fits u8"),
            );
            FinalitySignerInput::new(
                carrier.clone(),
                carrier.clone(),
                placeholder_state_certificate(),
                carrier,
                placeholder_state_certificate(),
                &limits,
            )
            .expect("placeholder signer input")
        })
        .collect::<Vec<_>>();
    let certificate = FinalityCertificate::new(signer_inputs).expect("finality certificate");
    let encoded = certificate.encode().expect("finality certificate bytes");
    let decoded = FinalityCertificate::decode(&encoded, &limits)
        .expect("canonical finality certificate decodes");
    assert_eq!(decoded, certificate);
    assert_eq!(
        decoded.ordered_signer_inputs().len(),
        usize::from(FOUNDATION_PROFILE.finality_quorum)
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        FinalityCertificate::decode(&trailing, &limits)
            .expect_err("trailing transport bytes must refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );
}

#[test]
fn finality_verifier_composes_board_signatures_and_exact_state_outputs() {
    let fixture = FinalityTestFixture::new();
    let mut board_verifier = fixture.board_verifier();
    let verified_replay = fixture.ingest_replay(&mut board_verifier);
    let statement = FinalityStatement::new(
        fixture.suite_identifier,
        fixture.ceremony_context_hash,
        fixture.action_context_hash,
        fixture.roster_hash,
        verified_replay.object_hash(),
    );
    let finality_hash = statement.finality_hash().expect("finality hash");
    let signer_inputs = (0..usize::from(FOUNDATION_PROFILE.finality_quorum))
        .map(|subject_roster_position| {
            fixture.finality_signer_input(
                subject_roster_position,
                finality_hash,
                verified_replay.object_hash(),
            )
        })
        .collect::<Vec<_>>();
    let finality_carriers = signer_inputs
        .iter()
        .map(|input| input.canonical_signed_finality_carrier().to_vec())
        .collect::<Vec<_>>();
    let finality_batch = board_verifier
        .verify_unordered_carriers(&finality_carriers)
        .into_result()
        .expect("board-authenticated finality carriers");
    let verified_finality_objects = signer_inputs
        .iter()
        .map(|input| {
            let object_hash =
                canonical_signed_carrier_object_hash(input.canonical_signed_finality_carrier());
            finality_batch
                .objects()
                .iter()
                .find(|object| object.object_hash() == object_hash)
                .expect("finality board capability")
        })
        .collect::<Vec<_>>();
    let certificate =
        FinalityCertificate::new(signer_inputs.clone()).expect("finality certificate");
    let verifier = FinalityVerifier::new(
        fixture.suite_identifier,
        fixture.ceremony_context_hash,
        fixture.action_context_hash,
        &fixture.roster,
        CanonicalDecodeLimits::default(),
    )
    .expect("finality verifier");
    let verified_finality = verifier
        .verify(FinalityVerificationInput {
            statement,
            certificate: &certificate,
            verified_evaluator_replay: &verified_replay,
            verified_finality_objects: &verified_finality_objects,
        })
        .into_result()
        .expect("finality certificate verifies");
    assert_eq!(verified_finality.finality_hash(), finality_hash);
    assert_eq!(
        verified_finality.verified_evaluator_replay_object_hash(),
        verified_replay.object_hash()
    );
    assert_eq!(verified_finality.verified_setup_source_hash(), hash(0x51));
    assert_eq!(
        verified_finality.verified_aggregate_source_hash(),
        verified_replay.verified_aggregate_source_hash()
    );
    assert_eq!(verified_finality.top_count(), 4);
    assert_eq!(
        verified_finality.target_identifier_descriptor(),
        &fixture.stream_descriptor(
            CanonicalStreamDomain::ReplayTargetIdentifierCiphertext,
            0xc4,
        )
    );
    assert_eq!(
        verified_finality.target_order_descriptor(),
        &fixture.stream_descriptor(CanonicalStreamDomain::ReplayTargetOrderCiphertext, 0xc5)
    );
    assert_eq!(
        verified_finality.target_identifier_full_object_digest(),
        verified_finality
            .target_identifier_descriptor()
            .full_object_digest
    );
    assert_eq!(
        verified_finality.target_order_full_object_digest(),
        verified_finality
            .target_order_descriptor()
            .full_object_digest
    );
    assert_eq!(
        verified_finality.accepted_finality_object_hashes().len(),
        usize::from(FOUNDATION_PROFILE.finality_quorum)
    );
    assert_eq!(
        verified_finality.state_outputs().len(),
        usize::from(FOUNDATION_PROFILE.finality_quorum)
    );

    let wrong_replay_statement = FinalityStatement::new(
        fixture.suite_identifier,
        fixture.ceremony_context_hash,
        fixture.action_context_hash,
        fixture.roster_hash,
        hash(0xee),
    );
    assert_eq!(
        verifier
            .verify(FinalityVerificationInput {
                statement: wrong_replay_statement,
                certificate: &certificate,
                verified_evaluator_replay: &verified_replay,
                verified_finality_objects: &verified_finality_objects,
            })
            .into_result()
            .err()
            .expect("a statement naming another replay object must refuse"),
        RefusalReason::MissingPrerequisite
    );

    let mut mismatched_objects = verified_finality_objects.clone();
    mismatched_objects.swap(0, 1);
    assert_eq!(
        verifier
            .verify(FinalityVerificationInput {
                statement,
                certificate: &certificate,
                verified_evaluator_replay: &verified_replay,
                verified_finality_objects: &mismatched_objects,
            })
            .into_result()
            .err()
            .expect("a finality carrier paired with another board capability must refuse"),
        RefusalReason::WrongHashOrRoot
    );

    let mut duplicated_signer_inputs = signer_inputs.clone();
    duplicated_signer_inputs[1] = duplicated_signer_inputs[0].clone();
    let duplicated_certificate = FinalityCertificate::new(duplicated_signer_inputs)
        .expect("duplicate signers remain canonical transport");
    let mut duplicated_objects = verified_finality_objects.clone();
    duplicated_objects[1] = duplicated_objects[0];
    assert_eq!(
        verifier
            .verify(FinalityVerificationInput {
                statement,
                certificate: &duplicated_certificate,
                verified_evaluator_replay: &verified_replay,
                verified_finality_objects: &duplicated_objects,
            })
            .into_result()
            .err()
            .expect("a duplicated finality signer must refuse"),
        RefusalReason::Equivocation
    );

    let mut reordered_signer_inputs = signer_inputs;
    reordered_signer_inputs.swap(0, 1);
    let reordered_certificate = FinalityCertificate::new(reordered_signer_inputs)
        .expect("reordered certificate remains canonical transport");
    let mut reordered_objects = verified_finality_objects;
    reordered_objects.swap(0, 1);
    assert_eq!(
        verifier
            .verify(FinalityVerificationInput {
                statement,
                certificate: &reordered_certificate,
                verified_evaluator_replay: &verified_replay,
                verified_finality_objects: &reordered_objects,
            })
            .into_result()
            .err()
            .expect("reordered finality signers must refuse"),
        RefusalReason::Equivocation
    );
}
