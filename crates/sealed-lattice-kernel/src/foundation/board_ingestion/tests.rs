use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

use super::*;
use crate::bgv::parameters::DATA_PRIMES;
use crate::foundation::{RosterEntry, VerifiedBoardApplicationSource, signature_message};

const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";

struct BoardFixture {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    roster_hash: Hash512,
    participant_identities: Vec<ParticipantIdentity>,
    signing_keys: Vec<ml_dsa_65::PrivateKey>,
}

impl BoardFixture {
    fn new() -> Self {
        let mut entries = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        let mut signing_keys =
            Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let mut signing_seed = [0_u8; 32];
            signing_seed[0] =
                u8::try_from(roster_position + 1).expect("test roster position fits u8");
            signing_seed[31] = u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                .expect("test reverse roster position fits u8");
            let (verification_key, signing_key) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            let mut mailbox_seed = [0x41_u8; 32];
            mailbox_seed[0] =
                u8::try_from(roster_position + 1).expect("test roster position fits u8");
            let mut mailbox_fallback_seed = [0x92_u8; 32];
            mailbox_fallback_seed[31] =
                u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                    .expect("test reverse roster position fits u8");
            let (mailbox_key, _) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            entries.push(RosterEntry {
                roster_position,
                signing_verification_key: verification_key.into_bytes(),
                mailbox_encapsulation_key: mailbox_key.into_bytes(),
            });
            signing_keys.push(signing_key);
        }
        let roster = Roster::new(entries).expect("test roster is valid");
        let roster_hash = roster.roster_hash().expect("test roster hash derives");
        let participant_identities = roster
            .entries
            .iter()
            .map(|entry| entry.participant_identity().expect("identity derives"))
            .collect();
        Self {
            suite_id: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            ceremony_context_hash: Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            action_context_hash: Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            roster,
            roster_hash,
            participant_identities,
            signing_keys,
        }
    }

    fn verifier(&self) -> CanonicalBoardVerifier {
        self.verifier_with_retained_carrier_limit(8 * 1024 * 1024)
    }

    fn verifier_with_retained_carrier_limit(
        &self,
        maximum_retained_canonical_carrier_byte_length: u64,
    ) -> CanonicalBoardVerifier {
        CanonicalBoardVerifier::new(
            self.suite_id,
            self.ceremony_context_hash,
            self.action_context_hash,
            &self.roster,
            CanonicalBoardLimits {
                maximum_ballot_attempts_per_participant: 4,
                maximum_retained_canonical_carrier_byte_length,
                maximum_unordered_carriers_per_batch: 128,
                maximum_retained_transcript_objects: 512,
            },
            CanonicalDecodeLimits::default(),
        )
        .expect("test board verifier constructs")
    }

    fn envelope(
        &self,
        producer_roster_position: usize,
        object_type: FoundationObjectType,
        producer_sequence: u64,
        ordered_prerequisite_hashes: Vec<Hash512>,
        payload_bytes: Vec<u8>,
    ) -> ObjectEnvelope {
        ObjectEnvelope {
            suite_id: self.suite_id,
            object_type,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            producer_participant_id: Some(self.participant_identities[producer_roster_position]),
            producer_sequence,
            ordered_prerequisite_hashes,
            payload_bytes,
        }
    }

    fn sign_envelope(
        &self,
        producer_roster_position: usize,
        envelope: ObjectEnvelope,
        signature_seed_byte: u8,
    ) -> Vec<u8> {
        let message =
            signature_message(&envelope, self.roster_hash).expect("signature message derives");
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

    fn setup_intent(&self, roster_position: usize, commitment_byte: u8) -> Vec<u8> {
        let payload = CanonicalTuple::new(
            SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::hash512(
                [commitment_byte; Hash512::BYTE_LENGTH],
            )],
        )
        .encode()
        .expect("setup-intent payload encodes");
        self.sign_envelope(
            roster_position,
            self.envelope(
                roster_position,
                FoundationObjectType::SetupIntent,
                0,
                Vec::new(),
                payload,
            ),
            0x20_u8
                .wrapping_add(u8::try_from(roster_position).expect("test roster position fits u8")),
        )
    }

    fn public_randomness_commitment(
        &self,
        producer_roster_position: usize,
        setup_intent_hashes: Vec<Hash512>,
    ) -> Vec<u8> {
        let payload = CanonicalTuple::new(
            PUBLIC_RANDOMNESS_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::hash512([0x91; Hash512::BYTE_LENGTH])],
        )
        .encode()
        .expect("public-randomness commitment payload encodes");
        self.sign_envelope(
            producer_roster_position,
            self.envelope(
                producer_roster_position,
                FoundationObjectType::PublicRandomnessCommitment,
                0,
                setup_intent_hashes,
                payload,
            ),
            0x51,
        )
    }

    fn public_randomness_reveal(
        &self,
        producer_roster_position: usize,
        contribution_commitment_object_hash: Hash512,
        reveal_byte: u8,
    ) -> Vec<u8> {
        let payload = CanonicalTuple::new(
            PUBLIC_RANDOMNESS_REVEAL_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(contribution_commitment_object_hash.into_bytes()),
                CanonicalItem::fixed_bytes([reveal_byte; Hash512::BYTE_LENGTH])
                    .expect("public-randomness reveal bytes encode"),
            ],
        )
        .encode()
        .expect("public-randomness reveal payload encodes");
        self.sign_envelope(
            producer_roster_position,
            self.envelope(
                producer_roster_position,
                FoundationObjectType::PublicRandomnessReveal,
                0,
                Vec::new(),
                payload,
            ),
            0x52,
        )
    }

    fn ballot_package(
        &self,
        producer_roster_position: usize,
        verified_setup_source_hash: Hash512,
    ) -> Vec<u8> {
        let payload = CanonicalTuple::new(
            BALLOT_PACKAGE_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                test_stream_descriptor_item(0xc1),
                test_stream_descriptor_item(0xc2),
            ],
        )
        .encode()
        .expect("ballot-package payload encodes");
        self.sign_envelope(
            producer_roster_position,
            self.envelope(
                producer_roster_position,
                FoundationObjectType::BallotPackage,
                0,
                vec![verified_setup_source_hash],
                payload,
            ),
            0x60_u8.wrapping_add(
                u8::try_from(producer_roster_position).expect("test roster position fits u8"),
            ),
        )
    }

    fn dealer_public_record(
        &self,
        producer_roster_position: usize,
        public_setup_seed: Hash512,
    ) -> Vec<u8> {
        let coefficient_root_count =
            DATA_PRIMES.len() * usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
        let recipient_root_count =
            DATA_PRIMES.len() * usize::from(FOUNDATION_PROFILE.participant_count);
        let payload = CanonicalTuple::new(
            DEALER_PUBLIC_RECORD_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(u16::try_from(producer_roster_position).unwrap()),
                test_hash_list_item(coefficient_root_count, 0xd1),
                test_hash_list_item(recipient_root_count, 0xd2),
                test_hash_list_item(usize::from(FOUNDATION_PROFILE.participant_count), 0xd3),
                test_stream_descriptor_item(0xd4),
            ],
        )
        .encode()
        .expect("dealer public record payload encodes");
        self.sign_envelope(
            producer_roster_position,
            self.envelope(
                producer_roster_position,
                FoundationObjectType::PublicSetupRecord,
                0,
                vec![public_setup_seed],
                payload,
            ),
            0x71,
        )
    }

    fn private_share_acceptance(&self, producer_roster_position: usize) -> Vec<u8> {
        let payload = CanonicalTuple::new(
            PRIVATE_SHARE_ACCEPTANCE_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512([0xe1; Hash512::BYTE_LENGTH]),
                test_hash_list_item(DATA_PRIMES.len(), 0xe2),
                test_stream_descriptor_item(0xe3),
            ],
        )
        .encode()
        .expect("private-share acceptance payload encodes");
        self.sign_envelope(
            producer_roster_position,
            self.envelope(
                producer_roster_position,
                FoundationObjectType::PrivateShareAcceptance,
                0,
                Vec::new(),
                payload,
            ),
            0x72,
        )
    }

    fn aggregate(
        &self,
        verified_setup_source_hash: Hash512,
        selected_ballot_object_hashes: &[Hash512],
    ) -> (Vec<u8>, Hash512) {
        let selected_ballots = selected_ballot_object_hashes
            .iter()
            .map(|hash| CanonicalItem::hash512(hash.into_bytes()))
            .collect::<Vec<_>>();
        let payload = CanonicalTuple::new(
            AGGREGATE_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(verified_setup_source_hash.into_bytes()),
                CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &selected_ballots)
                    .expect("selected-ballot hash list encodes"),
                test_stream_descriptor_item(0xc3),
            ],
        )
        .encode()
        .expect("aggregate payload encodes");
        let envelope = ObjectEnvelope {
            suite_id: self.suite_id,
            object_type: FoundationObjectType::Aggregate,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            producer_participant_id: None,
            producer_sequence: 0,
            ordered_prerequisite_hashes: Vec::new(),
            payload_bytes: payload,
        };
        let object_hash = envelope
            .object_hash()
            .expect("aggregate object hash derives");
        (
            envelope
                .encode()
                .expect("unsigned aggregate envelope encodes"),
            object_hash,
        )
    }
}

fn test_stream_descriptor_item(digest_byte: u8) -> CanonicalItem {
    let descriptor = test_stream_descriptor(digest_byte);
    let tuple = CanonicalTuple::decode(
        &descriptor.encode().expect("test stream descriptor encodes"),
        &CanonicalDecodeLimits::default(),
    )
    .expect("test stream descriptor tuple decodes");
    CanonicalItem::nested_tuple(&tuple).expect("nested stream descriptor encodes")
}

fn test_stream_descriptor(digest_byte: u8) -> StreamDescriptor {
    StreamDescriptor::new(
        1,
        vec![Hash512::from_bytes([digest_byte; Hash512::BYTE_LENGTH])],
        Hash512::from_bytes([digest_byte.wrapping_add(1); Hash512::BYTE_LENGTH]),
    )
    .expect("test stream descriptor is valid")
}

fn test_hash_list(count: usize, family: u8) -> Vec<Hash512> {
    (0..count)
        .map(|ordinal| {
            let mut bytes = [family; Hash512::BYTE_LENGTH];
            bytes[..4].copy_from_slice(&u32::try_from(ordinal).unwrap().to_le_bytes());
            Hash512::from_bytes(bytes)
        })
        .collect()
}

fn test_hash_list_item(count: usize, family: u8) -> CanonicalItem {
    let hashes = test_hash_list(count, family);
    let items = hashes
        .iter()
        .map(|hash| CanonicalItem::hash512(hash.into_bytes()))
        .collect::<Vec<_>>();
    CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &items)
        .expect("test hash list encodes")
}

fn carrier_object_hash(carrier_bytes: &[u8]) -> Hash512 {
    SignedCarrier::decode(carrier_bytes, &CanonicalDecodeLimits::default())
        .expect("test signed carrier decodes")
        .envelope
        .object_hash()
        .expect("test object hash derives")
}

#[test]
fn board_authority_rejects_a_nonselected_structural_roster() {
    let fixture = BoardFixture::new();
    let roster = Roster::new(fixture.roster.entries.iter().take(3).cloned().collect())
        .expect("three-participant roster is structural");
    let error = match CanonicalBoardVerifier::new(
        fixture.suite_id,
        fixture.ceremony_context_hash,
        fixture.action_context_hash,
        &roster,
        CanonicalBoardLimits {
            maximum_ballot_attempts_per_participant: 4,
            maximum_retained_canonical_carrier_byte_length: 8 * 1024 * 1024,
            maximum_unordered_carriers_per_batch: 128,
            maximum_retained_transcript_objects: 512,
        },
        CanonicalDecodeLimits::default(),
    ) {
        Ok(_) => panic!("nonselected roster cannot open board authority"),
        Err(error) => error,
    };
    assert_eq!(error.refusal_reason, RefusalReason::OutsideSupportedProfile);
}

#[test]
fn verified_application_sources_retain_exact_setup_payloads_and_manifest() {
    let fixture = BoardFixture::new();
    let manifest_hash = Hash512::from_bytes([0x18; Hash512::BYTE_LENGTH]);
    let public_setup_seed = Hash512::from_bytes([0xa5; Hash512::BYTE_LENGTH]);
    let dealer_roster_position = 3;
    let recipient_roster_position = 6;
    let carriers = [
        fixture.dealer_public_record(dealer_roster_position, public_setup_seed),
        fixture.private_share_acceptance(recipient_roster_position),
    ];
    let mut verifier = fixture.verifier();
    let batch = verifier
        .verify_unordered_carriers(&carriers)
        .into_result()
        .expect("the exact setup carriers verify");
    let mut sources = batch
        .objects()
        .iter()
        .cloned()
        .map(|object| {
            VerifiedBoardApplicationSource::from_verifier(&verifier, manifest_hash, object)
        })
        .collect::<Vec<_>>();
    let acceptance_source_position = sources
        .iter()
        .position(|source| source.object_type() == FoundationObjectType::PrivateShareAcceptance)
        .expect("the acceptance source is retained");
    let acceptance_source = sources.swap_remove(acceptance_source_position);
    let dealer_source = sources.pop().expect("the dealer source is retained");

    assert_eq!(dealer_source.manifest_hash(), manifest_hash);
    assert_eq!(dealer_source.producer_roster_position(), Some(3));
    let dealer_payload = dealer_source
        .dealer_public_record_payload()
        .expect("the exact dealer payload decodes");
    assert_eq!(dealer_payload.dealer_roster_position(), 3);
    assert_eq!(
        dealer_payload.coefficient_material_roots(),
        test_hash_list(
            DATA_PRIMES.len() * usize::from(FOUNDATION_PROFILE.reconstruction_threshold),
            0xd1,
        )
    );
    assert_eq!(
        dealer_payload.recipient_share_material_roots(),
        test_hash_list(
            DATA_PRIMES.len() * usize::from(FOUNDATION_PROFILE.participant_count),
            0xd2,
        )
    );
    assert_eq!(
        dealer_payload.ordered_recipient_envelope_hashes(),
        test_hash_list(usize::from(FOUNDATION_PROFILE.participant_count), 0xd3)
    );
    assert_eq!(
        dealer_payload.share_linkage_proof(),
        &test_stream_descriptor(0xd4)
    );
    assert_eq!(
        dealer_payload.public_setup_seed_prerequisite(),
        public_setup_seed
    );
    assert_eq!(
        dealer_source.private_share_acceptance_payload(),
        Err(RefusalReason::WrongContext)
    );

    assert_eq!(acceptance_source.manifest_hash(), manifest_hash);
    assert_eq!(acceptance_source.producer_roster_position(), Some(6));
    let acceptance_payload = acceptance_source
        .private_share_acceptance_payload()
        .expect("the exact acceptance payload decodes");
    assert_eq!(
        acceptance_payload.recipient_input_root(),
        Hash512::from_bytes([0xe1; Hash512::BYTE_LENGTH])
    );
    assert_eq!(
        acceptance_payload.aggregate_threshold_share_material_roots(),
        test_hash_list(DATA_PRIMES.len(), 0xe2)
    );
    assert_eq!(
        acceptance_payload.aggregate_threshold_share_proof(),
        &test_stream_descriptor(0xe3)
    );
    assert_eq!(
        acceptance_source.dealer_public_record_payload(),
        Err(RefusalReason::WrongContext)
    );
}

#[test]
fn unordered_dependencies_and_semantic_replay_mint_one_cached_capability() {
    let fixture = BoardFixture::new();
    let mut verifier = fixture.verifier();
    let setup_intents = (0..usize::from(FOUNDATION_PROFILE.participant_count))
        .map(|roster_position| {
            fixture.setup_intent(
                roster_position,
                u8::try_from(roster_position + 1).expect("test position fits u8"),
            )
        })
        .collect::<Vec<_>>();
    let setup_intent_hashes = setup_intents
        .iter()
        .map(|carrier| carrier_object_hash(carrier))
        .collect::<Vec<_>>();
    let commitment = fixture.public_randomness_commitment(0, setup_intent_hashes);

    let mut unordered = vec![commitment.clone()];
    unordered.extend(setup_intents.into_iter().rev());
    let batch = verifier
        .verify_unordered_carriers(&unordered)
        .into_result()
        .expect("unordered dependency batch verifies");
    assert_eq!(batch.objects().len(), 11);
    let retained_commitment = batch
        .objects()
        .iter()
        .find(|object| object.object_type() == FoundationObjectType::PublicRandomnessCommitment)
        .expect("commitment capability is present");
    assert_eq!(retained_commitment.canonical_carrier_bytes(), commitment);

    let commitment_envelope = SignedCarrier::decode(&commitment, &CanonicalDecodeLimits::default())
        .expect("commitment decodes")
        .envelope;
    let alternate_signature = fixture.sign_envelope(0, commitment_envelope, 0xd4);
    assert_ne!(alternate_signature, commitment);
    let replay = verifier
        .verify_unordered_carriers(&[alternate_signature])
        .into_result()
        .expect("same semantic object with another valid signature is idempotent");
    assert_eq!(replay.objects().len(), 1);
    assert_eq!(replay.objects()[0].canonical_carrier_bytes(), commitment);
}

#[test]
fn authenticated_slot_conflicts_are_equivocation_but_forged_conflicts_are_not() {
    let fixture = BoardFixture::new();
    let mut verifier = fixture.verifier();
    let accepted = fixture.setup_intent(0, 0x11);
    verifier
        .verify_unordered_carriers(&[accepted])
        .into_result()
        .expect("first producer slot verifies");

    let conflicting = fixture.setup_intent(0, 0x12);
    assert_eq!(
        verifier
            .verify_unordered_carriers(std::slice::from_ref(&conflicting))
            .into_result()
            .expect_err("conflicting authenticated producer slot refuses"),
        RefusalReason::Equivocation
    );

    let mut forged = SignedCarrier::decode(&conflicting, &CanonicalDecodeLimits::default())
        .expect("conflicting carrier decodes");
    forged.signature[0] ^= 1;
    let forged = forged.encode().expect("forged carrier remains canonical");
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[forged])
            .into_result()
            .expect_err("forged conflict remains an invalid signature"),
        RefusalReason::InvalidSignature
    );
}

#[test]
fn frozen_context_and_roster_key_bind_every_signed_carrier() {
    let fixture = BoardFixture::new();
    let mut verifier = fixture.verifier();
    let canonical = fixture.setup_intent(0, 0x21);
    let envelope = SignedCarrier::decode(&canonical, &CanonicalDecodeLimits::default())
        .expect("canonical setup intent decodes")
        .envelope;

    let mut wrong_suite = envelope.clone();
    wrong_suite.suite_id = Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]);
    let mut wrong_ceremony = envelope.clone();
    wrong_ceremony.ceremony_context_hash = Hash512::from_bytes([0x72; Hash512::BYTE_LENGTH]);
    let mut wrong_action = envelope.clone();
    wrong_action.action_context_hash = Hash512::from_bytes([0x73; Hash512::BYTE_LENGTH]);
    for (context_index, context_envelope) in [wrong_suite, wrong_ceremony, wrong_action]
        .into_iter()
        .enumerate()
    {
        let context_carrier = fixture.sign_envelope(
            0,
            context_envelope,
            0xa0_u8.wrapping_add(u8::try_from(context_index).expect("test context index fits u8")),
        );
        assert_eq!(
            verifier
                .verify_unordered_carriers(&[context_carrier])
                .into_result()
                .expect_err("a signed carrier from another context refuses"),
            RefusalReason::WrongContext
        );
    }

    let wrong_roster_key = fixture.sign_envelope(1, envelope, 0xb1);
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[wrong_roster_key])
            .into_result()
            .expect_err("the claimed producer selects the frozen roster key"),
        RefusalReason::InvalidSignature
    );
}

#[test]
fn typed_prerequisite_order_is_roster_derived_and_failure_is_atomic() {
    let fixture = BoardFixture::new();
    let mut verifier = fixture.verifier();
    let setup_intents = (0..usize::from(FOUNDATION_PROFILE.participant_count))
        .map(|roster_position| {
            fixture.setup_intent(
                roster_position,
                u8::try_from(roster_position + 1).expect("test position fits u8"),
            )
        })
        .collect::<Vec<_>>();
    let setup_intent_hashes = setup_intents
        .iter()
        .map(|carrier| carrier_object_hash(carrier))
        .collect::<Vec<_>>();
    let mut wrong_order = setup_intent_hashes.clone();
    wrong_order.swap(0, 1);
    let wrong_commitment = fixture.public_randomness_commitment(0, wrong_order);
    let mut wrong_batch = vec![wrong_commitment];
    wrong_batch.extend(setup_intents.iter().cloned());
    assert_eq!(
        verifier
            .verify_unordered_carriers(&wrong_batch)
            .into_result()
            .expect_err("wrong prerequisite order refuses"),
        RefusalReason::WrongContext
    );

    let correct_commitment = fixture.public_randomness_commitment(0, setup_intent_hashes);
    let mut correct_batch = vec![correct_commitment];
    correct_batch.extend(setup_intents);
    assert_eq!(
        verifier
            .verify_unordered_carriers(&correct_batch)
            .into_result()
            .expect("failed batch did not partially commit state")
            .objects()
            .len(),
        11
    );
}

#[test]
fn public_randomness_reveal_is_bound_to_its_authenticated_source_commitment() {
    let fixture = BoardFixture::new();
    let setup_intents = (0..usize::from(FOUNDATION_PROFILE.participant_count))
        .map(|roster_position| {
            fixture.setup_intent(
                roster_position,
                u8::try_from(roster_position + 1).expect("test position fits u8"),
            )
        })
        .collect::<Vec<_>>();
    let setup_intent_hashes = setup_intents
        .iter()
        .map(|carrier| carrier_object_hash(carrier))
        .collect::<Vec<_>>();
    let commitment = fixture.public_randomness_commitment(2, setup_intent_hashes);
    let commitment_hash = carrier_object_hash(&commitment);
    let reveal = fixture.public_randomness_reveal(2, commitment_hash, 0xa7);

    let mut accepted_batch = vec![reveal, commitment.clone()];
    accepted_batch.extend(setup_intents.clone().into_iter().rev());
    fixture
        .verifier()
        .verify_unordered_carriers(&accepted_batch)
        .into_result()
        .expect("a source reveal matching its commitment verifies");

    let wrong_source_reveal = fixture.public_randomness_reveal(3, commitment_hash, 0xa7);
    let mut wrong_source_batch = vec![wrong_source_reveal, commitment];
    wrong_source_batch.extend(setup_intents.into_iter().rev());
    assert_eq!(
        fixture
            .verifier()
            .verify_unordered_carriers(&wrong_source_batch)
            .into_result()
            .expect_err("another participant cannot reveal a source commitment"),
        RefusalReason::WrongContext
    );
}

#[test]
fn deterministic_unsigned_objects_resolve_typed_dependencies() {
    let fixture = BoardFixture::new();
    let verified_setup_source_hash = Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]);
    let selected_roster_positions = [
        0_usize,
        3,
        usize::from(FOUNDATION_PROFILE.participant_count - 1),
    ];
    let ballots = selected_roster_positions
        .iter()
        .map(|roster_position| fixture.ballot_package(*roster_position, verified_setup_source_hash))
        .collect::<Vec<_>>();
    let ballot_hashes = ballots
        .iter()
        .map(|carrier| carrier_object_hash(carrier))
        .collect::<Vec<_>>();
    let (aggregate, aggregate_hash) = fixture.aggregate(verified_setup_source_hash, &ballot_hashes);
    let replay_payload = CanonicalTuple::new(
        super::super::schemas::EVALUATOR_REPLAY_PAYLOAD_SCHEMA_IDENTIFIER,
        FOUNDATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(verified_setup_source_hash.into_bytes()),
            CanonicalItem::hash512(aggregate_hash.into_bytes()),
            test_stream_descriptor_item(0xc4),
            test_stream_descriptor_item(0xc5),
        ],
    )
    .encode()
    .expect("evaluator-replay payload encodes");
    let replay = ObjectEnvelope {
        suite_id: fixture.suite_id,
        object_type: FoundationObjectType::EvaluatorReplay,
        ceremony_context_hash: fixture.ceremony_context_hash,
        action_context_hash: fixture.action_context_hash,
        producer_participant_id: None,
        producer_sequence: 0,
        ordered_prerequisite_hashes: Vec::new(),
        payload_bytes: replay_payload,
    }
    .encode()
    .expect("unsigned evaluator-replay envelope encodes");

    let mut unordered = vec![replay, aggregate];
    unordered.extend(ballots.into_iter().rev());
    let batch = fixture
        .verifier()
        .verify_unordered_carriers(&unordered)
        .into_result()
        .expect("deterministic objects resolve through later signed ballots");
    assert_eq!(batch.objects().len(), selected_roster_positions.len() + 2);
    assert_eq!(
        batch
            .objects()
            .iter()
            .filter(|object| object.object_type() == FoundationObjectType::BallotPackage)
            .count(),
        selected_roster_positions.len()
    );
    assert!(
        batch
            .objects()
            .iter()
            .any(|object| { object.object_type() == FoundationObjectType::Aggregate })
    );
    assert!(
        batch
            .objects()
            .iter()
            .any(|object| { object.object_type() == FoundationObjectType::EvaluatorReplay })
    );

    let unsigned_setup_intent = SignedCarrier::decode(
        &fixture.setup_intent(0, 0xd1),
        &CanonicalDecodeLimits::default(),
    )
    .expect("setup intent decodes")
    .envelope
    .encode()
    .expect("unsigned setup-intent envelope encodes");
    assert_eq!(
        fixture
            .verifier()
            .verify_unordered_carriers(&[unsigned_setup_intent])
            .into_result()
            .expect_err("a signed family cannot use unsigned transport"),
        RefusalReason::WrongTypeOrLength
    );
}

#[test]
fn aggregate_selected_ballot_subset_must_be_nonempty_unique_and_roster_ordered() {
    let fixture = BoardFixture::new();
    let verified_setup_source_hash = Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]);
    let ballots = [
        fixture.ballot_package(1, verified_setup_source_hash),
        fixture.ballot_package(4, verified_setup_source_hash),
    ];
    let ballot_hashes = ballots
        .iter()
        .map(|carrier| carrier_object_hash(carrier))
        .collect::<Vec<_>>();

    let (empty_aggregate, _) = fixture.aggregate(verified_setup_source_hash, &[]);
    assert_eq!(
        fixture
            .verifier()
            .verify_unordered_carriers(&[empty_aggregate])
            .into_result()
            .expect_err("an empty selected-ballot subset refuses"),
        RefusalReason::WrongTypeOrLength
    );

    for (selected_ballot_hashes, refusal_description) in [
        (
            vec![ballot_hashes[0], ballot_hashes[0]],
            "a repeated selected ballot refuses",
        ),
        (
            vec![ballot_hashes[1], ballot_hashes[0]],
            "selected ballots outside roster order refuse",
        ),
    ] {
        let (aggregate, _) = fixture.aggregate(verified_setup_source_hash, &selected_ballot_hashes);
        let carriers = vec![aggregate, ballots[0].clone(), ballots[1].clone()];
        assert_eq!(
            fixture
                .verifier()
                .verify_unordered_carriers(&carriers)
                .into_result()
                .expect_err(refusal_description),
            RefusalReason::WrongContext
        );
    }
}

#[test]
fn unsupported_family_and_payload_versions_refuse_before_acceptance() {
    let fixture = BoardFixture::new();
    let mut verifier = fixture.verifier();
    let valid = fixture.setup_intent(0, 0x31);
    let carrier_tuple = CanonicalTuple::decode(&valid, &CanonicalDecodeLimits::default())
        .expect("test carrier tuple decodes");
    let mut future_carrier_tuple = carrier_tuple.clone();
    future_carrier_tuple.schema_version = FOUNDATION_SCHEMA_VERSION + 1;
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[future_carrier_tuple
                .encode()
                .expect("future carrier version encodes"),])
            .into_result()
            .expect_err("unsupported carrier version refuses"),
        RefusalReason::UnsupportedVersionOrSuite
    );
    let envelope_bytes = carrier_tuple.items[0]
        .variable_value_bytes()
        .expect("carrier contains variable envelope bytes");
    let envelope_tuple = CanonicalTuple::decode(envelope_bytes, &CanonicalDecodeLimits::default())
        .expect("test envelope tuple decodes");
    let mut future_envelope_tuple = envelope_tuple.clone();
    future_envelope_tuple.schema_version = FOUNDATION_SCHEMA_VERSION + 1;
    let future_envelope_carrier = CanonicalTuple::new(
        super::super::SIGNED_CARRIER_SCHEMA_IDENTIFIER,
        FOUNDATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::variable_bytes(
                future_envelope_tuple
                    .encode()
                    .expect("future envelope version encodes"),
            )
            .expect("future envelope bytes encode"),
            CanonicalItem::fixed_bytes([0_u8; super::super::ML_DSA_65_SIGNATURE_BYTE_LENGTH])
                .expect("placeholder signature encodes"),
        ],
    )
    .encode()
    .expect("future envelope carrier encodes");
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[future_envelope_carrier])
            .into_result()
            .expect_err("unsupported envelope version refuses"),
        RefusalReason::UnsupportedVersionOrSuite
    );
    let mut envelope_tuple = envelope_tuple;
    envelope_tuple.items[3] = CanonicalItem::unsigned16(0x7fff);
    let unsupported_envelope = envelope_tuple.encode().expect("future envelope encodes");
    let unsupported_carrier = CanonicalTuple::new(
        super::super::SIGNED_CARRIER_SCHEMA_IDENTIFIER,
        FOUNDATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::variable_bytes(unsupported_envelope)
                .expect("future envelope bytes encode"),
            CanonicalItem::fixed_bytes([0_u8; super::super::ML_DSA_65_SIGNATURE_BYTE_LENGTH])
                .expect("placeholder signature encodes"),
        ],
    )
    .encode()
    .expect("unsupported family carrier is canonical");
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[unsupported_carrier])
            .into_result()
            .expect_err("unknown canonical family refuses"),
        RefusalReason::UnsupportedVersionOrSuite
    );

    let future_payload = CanonicalTuple::new(
        SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER,
        FOUNDATION_SCHEMA_VERSION + 1,
        vec![CanonicalItem::hash512([0x61; Hash512::BYTE_LENGTH])],
    )
    .encode()
    .expect("future payload encodes canonically");
    let future_carrier = fixture.sign_envelope(
        0,
        fixture.envelope(
            0,
            FoundationObjectType::SetupIntent,
            0,
            Vec::new(),
            future_payload,
        ),
        0x72,
    );
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[future_carrier])
            .into_result()
            .expect_err("unsupported payload version refuses"),
        RefusalReason::UnsupportedVersionOrSuite
    );
}

#[test]
fn witness_slots_resolve_from_typed_intents_independent_of_arrival_order() {
    let fixture = BoardFixture::new();
    let mut verifier = fixture.verifier();
    let reservation_payload = StateReservationIntentPayload {
        capability_kind: StateCapabilityKind::FinalitySignature,
        authorization_hash: Hash512::from_bytes([0xa1; Hash512::BYTE_LENGTH]),
    }
    .encode()
    .expect("reservation payload encodes");
    let reservation = fixture.sign_envelope(
        0,
        fixture.envelope(
            0,
            FoundationObjectType::StateReservation,
            0,
            Vec::new(),
            reservation_payload,
        ),
        0x81,
    );
    let reservation_hash = carrier_object_hash(&reservation);
    let vote_payload = StateWitnessVotePayload {
        intent_object_hash: reservation_hash,
    }
    .encode()
    .expect("vote payload encodes");
    let vote = fixture.sign_envelope(
        1,
        fixture.envelope(
            1,
            FoundationObjectType::StateWitnessVote,
            1,
            Vec::new(),
            vote_payload,
        ),
        0x82,
    );
    let batch = verifier
        .verify_unordered_carriers(&[vote, reservation])
        .into_result()
        .expect("vote resolves through a later typed intent");
    assert_eq!(batch.objects().len(), 2);

    let missing_output_payload = StateOutputIntentPayload {
        reservation_intent_object_hash: Hash512::from_bytes([0xf1; Hash512::BYTE_LENGTH]),
        exact_output_hash: Hash512::from_bytes([0xf2; Hash512::BYTE_LENGTH]),
    }
    .encode()
    .expect("output payload encodes");
    let missing_output = fixture.sign_envelope(
        2,
        fixture.envelope(
            2,
            FoundationObjectType::StateOutputIntent,
            0,
            Vec::new(),
            missing_output_payload,
        ),
        0x83,
    );
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[missing_output])
            .into_result()
            .expect_err("terminal missing typed prerequisite refuses"),
        RefusalReason::MissingPrerequisite
    );
}

#[test]
fn retained_carrier_limit_is_exact_and_semantic_replay_costs_no_extra_bytes() {
    let fixture = BoardFixture::new();
    let first = fixture.setup_intent(0, 0x41);
    let second = fixture.setup_intent(1, 0x42);
    let maximum_retained_canonical_carrier_byte_length =
        u64::try_from(first.len()).expect("test carrier length fits u64");
    let mut verifier = fixture
        .verifier_with_retained_carrier_limit(maximum_retained_canonical_carrier_byte_length);

    verifier
        .verify_unordered_carriers(std::slice::from_ref(&first))
        .into_result()
        .expect("one carrier exactly at the retained-byte limit verifies");
    assert_eq!(
        verifier
            .verify_unordered_carriers(&[second])
            .into_result()
            .expect_err("another semantic object exceeds the retained-byte limit"),
        RefusalReason::OutsideSupportedProfile
    );

    let first_envelope = SignedCarrier::decode(&first, &CanonicalDecodeLimits::default())
        .expect("first carrier decodes")
        .envelope;
    let alternate_signature = fixture.sign_envelope(0, first_envelope, 0xc1);
    let replay = verifier
        .verify_unordered_carriers(&[alternate_signature])
        .into_result()
        .expect("semantic replay does not consume retained-byte capacity");
    assert_eq!(replay.objects()[0].canonical_carrier_bytes(), first);
}
