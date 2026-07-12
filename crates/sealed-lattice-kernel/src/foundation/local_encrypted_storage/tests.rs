use std::collections::VecDeque;

use zeroize::Zeroizing;

use super::*;
use crate::foundation::{EntropySourceError, StreamDescriptor};

struct DeterministicEntropy {
    bytes: VecDeque<u8>,
    call_count: usize,
}

impl DeterministicEntropy {
    fn new(bytes: impl IntoIterator<Item = u8>) -> Self {
        Self {
            bytes: bytes.into_iter().collect(),
            call_count: 0,
        }
    }
}

impl FallibleEntropySource for DeterministicEntropy {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceError> {
        self.call_count += 1;
        if self.bytes.len() < destination.len() {
            return Err(EntropySourceError::Unavailable);
        }
        for destination_byte in destination {
            *destination_byte = self
                .bytes
                .pop_front()
                .expect("the entropy preflight established enough deterministic bytes");
        }
        Ok(())
    }
}

struct PartiallyFailingEntropy;

impl FallibleEntropySource for PartiallyFailingEntropy {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceError> {
        let written_prefix_byte_length = destination.len().min(7);
        destination[..written_prefix_byte_length].fill(0xa5);
        Err(EntropySourceError::Unavailable)
    }
}

fn test_hash(byte: u8) -> Hash512 {
    Hash512::from_bytes([byte; Hash512::BYTE_LENGTH])
}

fn test_binding() -> LocalStorageBinding {
    LocalStorageBinding::new(
        test_hash(0x11),
        test_hash(0x22),
        test_hash(0x33),
        ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
    )
}

fn alternate_binding() -> LocalStorageBinding {
    LocalStorageBinding::new(
        test_hash(0x11),
        test_hash(0x22),
        test_hash(0x34),
        ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
    )
}

fn test_storage_root() -> ActionStorageRoot {
    ActionStorageRoot::from_verified_root(
        test_binding(),
        Zeroizing::new([0xab; ACTION_STORAGE_ROOT_BYTE_LENGTH]),
    )
    .expect("the fixed test storage root is canonical")
}

fn expect_valid<Value>(result: VerificationResult<Value>) -> Value {
    match result {
        VerificationResult::Valid { value } => value,
        VerificationResult::Refused { refusal_reason } => {
            panic!("verification unexpectedly refused with {refusal_reason:?}")
        }
    }
}

fn assert_refused<Value>(result: VerificationResult<Value>, expected: RefusalReason) {
    match result {
        VerificationResult::Valid { .. } => panic!("verification unexpectedly accepted"),
        VerificationResult::Refused { refusal_reason } => {
            assert_eq!(refusal_reason, expected)
        }
    }
}

fn assert_schema_refused<Value>(
    result: Result<Value, FoundationSchemaError>,
    expected: RefusalReason,
) {
    match result {
        Ok(_) => panic!("schema validation unexpectedly accepted"),
        Err(error) => assert_eq!(error.refusal_reason, expected),
    }
}

fn expected_identifier(
    binding: LocalStorageBinding,
    domain: &'static str,
    additional_items: &[CanonicalItem],
) -> Hash512 {
    let mut items = binding.canonical_items().to_vec();
    items.extend_from_slice(additional_items);
    hash512(domain, &items).expect("the test identifier input is canonical")
}

fn replace_tuple_item(bytes: &[u8], index: usize, item: CanonicalItem) -> Vec<u8> {
    let mut tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
        .expect("the source tuple is canonical");
    tuple.items[index] = item;
    tuple.encode().expect("the mutated tuple remains canonical")
}

fn test_checkpoint_manifest(binding: LocalStorageBinding) -> CheckpointManifest {
    CheckpointManifest::new(
        test_hash(0x51),
        binding.suite_id,
        binding.ceremony_context_hash,
        binding.action_context_hash,
        binding.participant_id,
        [0x52; 32],
        1,
        2,
        vec![test_hash(0x53)],
        Vec::new(),
        StreamDescriptor::new(3, vec![test_hash(0x54)], test_hash(0x55))
            .expect("the one-chunk descriptor is valid"),
    )
    .expect("the checkpoint manifest is valid")
}

#[test]
fn storage_root_generation_requires_complete_entropy_and_redacts_secret_material() {
    let expected_root_bytes = (0u8..ACTION_STORAGE_ROOT_BYTE_LENGTH as u8).collect::<Vec<_>>();
    let mut entropy = DeterministicEntropy::new(expected_root_bytes);
    let root = ActionStorageRoot::try_generate(test_binding(), &mut entropy)
        .expect("complete deterministic entropy generates a storage root");
    assert_eq!(entropy.call_count, 1);
    assert_eq!(root.binding(), test_binding());
    assert_eq!(
        root.storage_root_commitment(),
        derive_storage_root_commitment(test_binding(), &root.root).expect("commitment")
    );

    let debug = format!("{root:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("0, 1, 2, 3"));

    assert_eq!(
        ActionStorageRoot::try_generate(test_binding(), &mut PartiallyFailingEntropy)
            .expect_err("partial entropy must fail closed"),
        LocalStorageOperationError::EntropyUnavailable
    );
}

#[test]
fn recovery_value_round_trips_through_canonical_uppercase_base32() {
    let root = test_storage_root();
    let recovery = root.recovery_value().expect("recovery value");
    let encoded = recovery.encode().expect("recovery value encodes");
    assert_eq!(encoded.len(), RECOVERY_VALUE_CANONICAL_BYTE_LENGTH);

    let decoded = LocalStorageRecoveryValue::decode(&encoded, &CanonicalDecodeLimits::default())
        .expect("recovery value decodes");
    assert_eq!(decoded.binding(), test_binding());
    assert_eq!(
        decoded.storage_root_commitment(),
        root.storage_root_commitment()
    );

    let canonical = recovery
        .to_canonical_base32()
        .expect("recovery value has canonical base32");
    assert_eq!(canonical.len(), RECOVERY_VALUE_BASE32_CHARACTER_LENGTH);
    assert!(
        canonical
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    );
    assert!(!canonical.contains('='));

    let lowercase = canonical.to_ascii_lowercase();
    let ingress =
        CanonicalLocalStorageRecoveryIngress::decode(&lowercase, &CanonicalDecodeLimits::default())
            .expect("case-insensitive ingress accepts lowercase");
    assert_eq!(ingress.canonical_base32(), canonical.as_str());
    let recovered = expect_valid(
        ingress
            .into_recovery_value()
            .recover(test_binding(), root.storage_root_commitment_payload()),
    );
    assert_eq!(recovered.binding(), test_binding());
    assert_eq!(
        recovered.storage_root_commitment(),
        root.storage_root_commitment()
    );
}

#[test]
fn recovery_ingress_rejects_noncanonical_text_and_mutated_bound_fields() {
    let root = test_storage_root();
    let recovery = root.recovery_value().expect("recovery value");
    let canonical = recovery
        .to_canonical_base32()
        .expect("recovery value has canonical base32");

    for invalid in [
        canonical[..canonical.len() - 1].to_owned(),
        format!("{}=", &canonical[..canonical.len() - 1]),
        format!(" {}", &canonical[..canonical.len() - 1]),
    ] {
        assert!(
            CanonicalLocalStorageRecoveryIngress::decode(
                &invalid,
                &CanonicalDecodeLimits::default()
            )
            .is_err()
        );
    }

    let mut noncanonical_tail = canonical.as_bytes().to_vec();
    let last = noncanonical_tail
        .last_mut()
        .expect("the recovery encoding is nonempty");
    *last = match *last {
        b'A' => b'B',
        b'Q' => b'R',
        _ => panic!("a 442-byte value has exactly one significant final base32 bit"),
    };
    let noncanonical_tail =
        String::from_utf8(noncanonical_tail).expect("the mutation remains ASCII");
    assert_schema_refused(
        CanonicalLocalStorageRecoveryIngress::decode(
            &noncanonical_tail,
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::MalformedEncoding,
    );

    let encoded = recovery.encode().expect("recovery value encodes");
    let mutations = [
        (5, CanonicalItem::hash512(test_hash(0x61).into_bytes())),
        (
            6,
            CanonicalItem::fixed_bytes([0x62; ACTION_STORAGE_ROOT_BYTE_LENGTH])
                .expect("fixed root item"),
        ),
        (
            7,
            CanonicalItem::fixed_bytes([0x63; RECOVERY_CHECKSUM_BYTE_LENGTH])
                .expect("fixed checksum item"),
        ),
    ];
    for (index, item) in mutations {
        let mutated = replace_tuple_item(&encoded, index, item);
        assert_schema_refused(
            LocalStorageRecoveryValue::decode(&mutated, &CanonicalDecodeLimits::default()),
            RefusalReason::WrongHashOrRoot,
        );
    }
}

#[test]
fn recovery_requires_the_expected_binding_and_externally_verified_commitment() {
    let root = test_storage_root();
    let canonical = root
        .recovery_value()
        .expect("recovery value")
        .to_canonical_base32()
        .expect("base32 recovery value");

    let decode = || {
        CanonicalLocalStorageRecoveryIngress::decode(
            canonical.as_str(),
            &CanonicalDecodeLimits::default(),
        )
        .expect("recovery ingress")
        .into_recovery_value()
    };
    assert_refused(
        decode().recover(alternate_binding(), root.storage_root_commitment_payload()),
        RefusalReason::WrongContext,
    );
    assert_refused(
        decode().recover(
            test_binding(),
            StorageRootCommitmentPayload::new(test_hash(0x77)),
        ),
        RefusalReason::WrongHashOrRoot,
    );
}

#[test]
fn device_wrapping_values_are_canonical_and_opened_roots_are_recomputed() {
    let root = test_storage_root();
    let associated_data = root.device_wrapping_associated_data();
    let associated_data_bytes = associated_data.encode().expect("associated data encodes");
    assert_eq!(
        associated_data_bytes.len(),
        DEVICE_WRAPPING_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH
    );
    assert_eq!(
        DeviceWrappingAssociatedData::decode(
            &associated_data_bytes,
            &CanonicalDecodeLimits::default()
        )
        .expect("associated data decodes"),
        associated_data
    );

    let wrapped = DeviceWrappedStorageRoot::new(
        associated_data,
        [0x71; LOCAL_RECORD_NONCE_BYTE_LENGTH],
        [0x72; ACTION_STORAGE_ROOT_BYTE_LENGTH],
        [0x73; LOCAL_RECORD_TAG_BYTE_LENGTH],
    );
    let wrapped_bytes = wrapped.encode().expect("wrapped root encodes");
    assert_eq!(
        wrapped_bytes.len(),
        DEVICE_WRAPPED_STORAGE_ROOT_MAXIMUM_BYTE_LENGTH
    );
    assert_eq!(
        DeviceWrappedStorageRoot::decode(&wrapped_bytes, &CanonicalDecodeLimits::default())
            .expect("wrapped root decodes"),
        wrapped
    );

    let opened = expect_valid(associated_data.verify_opened_storage_root(
        Zeroizing::new(*root.root),
        test_binding(),
        root.storage_root_commitment_payload(),
    ));
    assert_eq!(
        opened.storage_root_commitment(),
        root.storage_root_commitment()
    );
    assert_refused(
        associated_data.verify_opened_storage_root(
            Zeroizing::new([0x74; ACTION_STORAGE_ROOT_BYTE_LENGTH]),
            test_binding(),
            root.storage_root_commitment_payload(),
        ),
        RefusalReason::WrongHashOrRoot,
    );
    assert_refused(
        associated_data.verify_opened_storage_root(
            Zeroizing::new(*root.root),
            alternate_binding(),
            root.storage_root_commitment_payload(),
        ),
        RefusalReason::WrongContext,
    );
}

#[test]
fn commitment_and_local_record_schema_codecs_round_trip_exactly() {
    let root = test_storage_root();
    let payload = root.storage_root_commitment_payload();
    let payload_bytes = payload.encode().expect("commitment payload encodes");
    assert_eq!(
        payload_bytes.len(),
        STORAGE_ROOT_COMMITMENT_PAYLOAD_MAXIMUM_BYTE_LENGTH
    );
    assert_eq!(
        StorageRootCommitmentPayload::decode(&payload_bytes, &CanonicalDecodeLimits::default())
            .expect("commitment payload decodes"),
        payload
    );

    let identifier = LocalRecordIdentifier::action_randomness(test_binding())
        .expect("action-randomness identifier");
    let associated_data =
        LocalRecordAssociatedData::initial(identifier, 9, 17).expect("initial associated data");
    let associated_data_bytes = associated_data.encode().expect("associated data encodes");
    assert_eq!(associated_data_bytes.len(), 425);
    assert_eq!(
        LocalRecordAssociatedData::decode(
            &associated_data_bytes,
            &CanonicalDecodeLimits::default()
        )
        .expect("associated data decodes"),
        associated_data
    );

    let key_input = LocalRecordKeyInput::from_associated_data(&associated_data);
    let key_input_bytes = key_input.encode().expect("key input encodes");
    assert_eq!(
        key_input_bytes.len(),
        LOCAL_RECORD_KEY_INPUT_MAXIMUM_BYTE_LENGTH
    );
    assert_eq!(
        LocalRecordKeyInput::decode(&key_input_bytes, &CanonicalDecodeLimits::default())
            .expect("key input decodes"),
        key_input
    );
}

#[test]
fn fixed_local_storage_schemas_apply_intrinsic_limits_before_decoding() {
    let limits = CanonicalDecodeLimits::default();
    assert_schema_refused(
        StorageRootCommitmentPayload::decode(
            &[0; STORAGE_ROOT_COMMITMENT_PAYLOAD_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        ),
        RefusalReason::OutsideSupportedProfile,
    );
    assert_schema_refused(
        LocalStorageRecoveryValue::decode(
            &vec![0; RECOVERY_VALUE_CANONICAL_BYTE_LENGTH + 1],
            &limits,
        ),
        RefusalReason::OutsideSupportedProfile,
    );
    assert_schema_refused(
        DeviceWrappingAssociatedData::decode(
            &vec![0; DEVICE_WRAPPING_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        ),
        RefusalReason::OutsideSupportedProfile,
    );
    assert_schema_refused(
        DeviceWrappedStorageRoot::decode(
            &vec![0; DEVICE_WRAPPED_STORAGE_ROOT_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        ),
        RefusalReason::OutsideSupportedProfile,
    );
    assert_schema_refused(
        LocalRecordKeyInput::decode(
            &vec![0; LOCAL_RECORD_KEY_INPUT_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        ),
        RefusalReason::OutsideSupportedProfile,
    );
    assert_schema_refused(
        LocalRecordAssociatedData::decode(
            &vec![0; LOCAL_RECORD_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        ),
        RefusalReason::OutsideSupportedProfile,
    );
}

#[test]
fn record_types_are_closed_and_stable() {
    assert_eq!(LocalRecordType::ALL.len(), 11);
    for (index, record_type) in LocalRecordType::ALL.into_iter().enumerate() {
        let expected_code = u16::try_from(index + 1).expect("eleven codes fit u16");
        assert_eq!(record_type.canonical_code(), expected_code);
        assert_eq!(
            LocalRecordType::from_canonical_code(expected_code),
            Some(record_type)
        );
    }
    for unassigned in [0, 12, u16::MAX] {
        assert_eq!(LocalRecordType::from_canonical_code(unassigned), None);
    }
}

#[test]
fn every_record_identifier_uses_its_exact_domain_and_inputs() {
    let binding = test_binding();
    let action_randomness =
        LocalRecordIdentifier::action_randomness(binding).expect("action identifier");
    assert_eq!(
        action_randomness.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/action-randomness/v1",
            &[]
        )
    );

    let public_coin = LocalRecordIdentifier::public_coin_private_material(binding)
        .expect("public-coin identifier");
    assert_eq!(
        public_coin.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/public-coin/v1",
            &[]
        )
    );

    let material_context_hash = test_hash(0x61);
    let source_material = LocalRecordIdentifier::source_verifiable_secret_sharing_material(
        binding,
        material_context_hash,
    )
    .expect("source-material identifier");
    assert_eq!(
        source_material.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/source-vss-material/v1",
            &[CanonicalItem::hash512(material_context_hash.into_bytes())],
        )
    );

    let recipient_input_root = test_hash(0x62);
    let aggregate_share =
        LocalRecordIdentifier::aggregate_threshold_share(binding, recipient_input_root)
            .expect("aggregate-share identifier");
    assert_eq!(
        aggregate_share.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/aggregate-threshold-share/v1",
            &[CanonicalItem::hash512(recipient_input_root.into_bytes())],
        )
    );

    let statement = CanonicalTuple::new(
        ProofFamily::BallotValidity.statement_schema_identifier(),
        FOUNDATION_PROTOCOL_VERSION,
        vec![CanonicalItem::unsigned16(7)],
    );
    let statement_bytes = statement.encode().expect("statement encodes");
    let proof_header = ProofObjectHeader {
        canonical_application_statement: statement_bytes.clone(),
    };
    let proof_attempt = LocalRecordIdentifier::proof_attempt(
        binding,
        &proof_header,
        [0x63; 32],
        &CanonicalDecodeLimits::default(),
    )
    .expect("proof-attempt identifier");
    assert_eq!(
        proof_attempt.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/proof-attempt/v1",
            &[
                CanonicalItem::variable_bytes(&statement_bytes).expect("statement item"),
                CanonicalItem::fixed_bytes([0x63; 32]).expect("attempt item"),
            ],
        )
    );

    let ballot_attempt = LocalRecordIdentifier::ballot_attempt(binding, &statement, [0x64; 32])
        .expect("ballot-attempt identifier");
    assert_eq!(
        ballot_attempt.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/ballot-attempt/v1",
            &[
                CanonicalItem::variable_bytes(&statement_bytes).expect("statement item"),
                CanonicalItem::fixed_bytes([0x64; 32]).expect("attempt item"),
            ],
        )
    );

    let output_hash = test_hash(0x65);
    let output_chunk = LocalRecordIdentifier::exact_output_chunk(
        binding,
        StateCapabilityKind::FinalitySignature,
        output_hash,
        19,
    )
    .expect("output-chunk identifier");
    assert_eq!(
        output_chunk.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/exact-output-chunk/v1",
            &[
                CanonicalItem::unsigned16(StateCapabilityKind::FinalitySignature.canonical_code()),
                CanonicalItem::hash512(output_hash.into_bytes()),
                CanonicalItem::unsigned64(19),
            ],
        )
    );

    let subject_state =
        LocalRecordIdentifier::subject_state(binding, StateCapabilityKind::TargetRelease)
            .expect("subject-state identifier");
    let subject_state_key = derive_state_key(
        binding.suite_id,
        binding.ceremony_context_hash,
        binding.action_context_hash,
        binding.participant_id,
        StateCapabilityKind::TargetRelease,
    )
    .expect("state key");
    assert_eq!(
        subject_state.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/state-subject/v1",
            &[CanonicalItem::hash512(subject_state_key.into_bytes())],
        )
    );

    let witness_subject = ParticipantIdentity::from_bytes([0x66; ParticipantIdentity::BYTE_LENGTH]);
    let witness_state = LocalRecordIdentifier::witness_state(
        binding,
        witness_subject,
        StateCapabilityKind::BallotCandidateList,
    )
    .expect("witness-state identifier");
    let witness_state_key = derive_state_key(
        binding.suite_id,
        binding.ceremony_context_hash,
        binding.action_context_hash,
        witness_subject,
        StateCapabilityKind::BallotCandidateList,
    )
    .expect("state key");
    assert_eq!(
        witness_state.identifier(),
        expected_identifier(
            binding,
            "sealed-lattice/local-record-id/state-witness/v1",
            &[CanonicalItem::hash512(witness_state_key.into_bytes())],
        )
    );

    let identifiers = [
        action_randomness.identifier(),
        public_coin.identifier(),
        source_material.identifier(),
        aggregate_share.identifier(),
        proof_attempt.identifier(),
        ballot_attempt.identifier(),
        output_chunk.identifier(),
        subject_state.identifier(),
        witness_state.identifier(),
    ];
    for left in 0..identifiers.len() {
        for right in left + 1..identifiers.len() {
            assert_ne!(identifiers[left], identifiers[right]);
        }
    }
}

#[test]
fn proof_ballot_and_checkpoint_identifier_inputs_are_validated() {
    let binding = test_binding();
    let unassigned_statement = CanonicalTuple::new(0x7fff, 1, Vec::new());
    let unassigned_header = ProofObjectHeader {
        canonical_application_statement: unassigned_statement
            .encode()
            .expect("unassigned statement still encodes canonically"),
    };
    assert_schema_refused(
        LocalRecordIdentifier::proof_attempt(
            binding,
            &unassigned_header,
            [1; 32],
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::WrongTypeOrLength,
    );
    assert_schema_refused(
        LocalRecordIdentifier::ballot_attempt(binding, &unassigned_statement, [1; 32]),
        RefusalReason::WrongTypeOrLength,
    );
    let wrong_version_ballot = CanonicalTuple::new(
        ProofFamily::BallotValidity.statement_schema_identifier(),
        2,
        Vec::new(),
    );
    let wrong_version_header = ProofObjectHeader {
        canonical_application_statement: wrong_version_ballot
            .encode()
            .expect("the wrong-version statement remains canonical"),
    };
    assert_schema_refused(
        LocalRecordIdentifier::proof_attempt(
            binding,
            &wrong_version_header,
            [1; 32],
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::WrongTypeOrLength,
    );
    assert_schema_refused(
        LocalRecordIdentifier::ballot_attempt(binding, &wrong_version_ballot, [1; 32]),
        RefusalReason::WrongTypeOrLength,
    );

    let checkpoint = test_checkpoint_manifest(binding);
    let manifest_identifier = LocalRecordIdentifier::checkpoint_manifest(binding, &checkpoint)
        .expect("checkpoint identifier");
    assert_eq!(
        manifest_identifier.identifier(),
        checkpoint
            .checkpoint_identifier()
            .expect("checkpoint identifier")
    );
    let chunk_identifier =
        LocalRecordIdentifier::checkpoint_state_chunk(binding, &checkpoint, 3, test_hash(0x67))
            .expect("checkpoint chunk identifier");
    assert_eq!(
        chunk_identifier.identifier(),
        checkpoint
            .checkpoint_chunk_identifier(3, test_hash(0x67))
            .expect("checkpoint chunk identifier")
    );
    assert_schema_refused(
        LocalRecordIdentifier::checkpoint_manifest(alternate_binding(), &checkpoint),
        RefusalReason::WrongContext,
    );
}

#[test]
fn record_key_derivation_matches_an_independent_kmac256_vector() {
    let root = test_storage_root();
    let key_input = LocalRecordKeyInput {
        binding: test_binding(),
        record_type: LocalRecordType::ActionRandomness,
        record_identifier: test_hash(0x55),
        record_version: 7,
    };
    assert_eq!(key_input.encode().expect("key input encodes").len(), 388);
    let derived_key = root
        .derive_record_key(&key_input)
        .expect("record key derives");
    assert_eq!(
        derived_key.as_ref(),
        &[
            0x6a, 0xfc, 0xa0, 0xa3, 0x11, 0x78, 0x66, 0x2c, 0x52, 0x23, 0xfa, 0xed, 0x0b, 0xbc,
            0xc5, 0x91, 0xe2, 0x3a, 0xd3, 0xc1, 0x38, 0x92, 0x0a, 0x52, 0xe5, 0x5d, 0xf0, 0x52,
            0xb6, 0x73, 0x34, 0x8b,
        ]
    );
    let wrong_binding_input = LocalRecordKeyInput {
        binding: alternate_binding(),
        ..key_input
    };
    assert_eq!(
        root.derive_record_key(&wrong_binding_input)
            .expect_err("cross-context key derivation must fail"),
        LocalStorageOperationError::WrongRecordContext
    );
}

#[test]
fn aes_256_gcm_siv_matches_the_rfc_8452_c2_vector() {
    let mut key = [0u8; 32];
    key[0] = 1;
    let mut nonce = [0u8; LOCAL_RECORD_NONCE_BYTE_LENGTH];
    nonce[0] = 3;
    let mut ciphertext = vec![1, 0, 0, 0, 0, 0, 0, 0];
    let cipher = Aes256GcmSiv::new_from_slice(&key).expect("the key has the exact length");
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut ciphertext)
        .expect("the RFC vector encrypts");
    assert_eq!(ciphertext, [0xc2, 0xef, 0x32, 0x8e, 0x5c, 0x71, 0xc8, 0x3b]);
    assert_eq!(
        tag.as_slice(),
        [
            0x84, 0x31, 0x22, 0x13, 0x0f, 0x73, 0x64, 0xb7, 0x61, 0xe0, 0xb9, 0x74, 0x27, 0xe3,
            0xdf, 0x28,
        ]
    );
}

#[test]
fn initial_and_successor_records_round_trip_with_exact_chain_bindings() {
    let root = test_storage_root();
    let identifier =
        LocalRecordIdentifier::action_randomness(test_binding()).expect("record identifier");
    let plaintext = (0u16..=511)
        .map(|value| (value % 251) as u8)
        .collect::<Vec<_>>();
    let mut initial_entropy = DeterministicEntropy::new([0x31; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    let initial = root
        .try_seal_initial_record(identifier, 4, &plaintext, &mut initial_entropy)
        .expect("initial record seals");
    assert_eq!(initial.associated_data().record_version(), 0);
    assert_eq!(initial.associated_data().creation_recovery_epoch(), 4);
    assert_eq!(initial.associated_data().predecessor_record_hash(), None);
    assert_eq!(
        initial.associated_data().plaintext_byte_length(),
        plaintext.len() as u64
    );
    assert_eq!(initial.nonce(), &[0x31; LOCAL_RECORD_NONCE_BYTE_LENGTH]);

    let initial_bytes = initial.encode().expect("initial envelope encodes");
    let decoded_initial =
        LocalRecordEnvelope::decode(&initial_bytes, &CanonicalDecodeLimits::default())
            .expect("initial envelope decodes");
    assert_eq!(decoded_initial, initial);

    let authenticated_initial = expect_valid(root.authenticate_envelope(
        &decoded_initial,
        &LocalRecordExpectation::initial(identifier),
    ));
    let successor_expectation = authenticated_initial
        .successor_expectation()
        .expect("version zero has a successor");
    assert_eq!(successor_expectation.record_version(), 1);
    assert_eq!(
        successor_expectation.predecessor_record_hash(),
        Some(
            decoded_initial
                .envelope_hash()
                .expect("initial envelope hash")
        )
    );

    let successor_plaintext = b"durable successor state with binary suffix\0\xff";
    let mut successor_entropy = DeterministicEntropy::new([0x32; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    let successor = root
        .try_seal_successor_record(
            &authenticated_initial,
            5,
            successor_plaintext,
            &mut successor_entropy,
        )
        .expect("successor record seals");
    let opened_initial = expect_valid(authenticated_initial.open());
    assert_eq!(opened_initial.as_bytes(), plaintext);

    assert_eq!(successor.associated_data().record_version(), 1);
    assert_eq!(successor.associated_data().creation_recovery_epoch(), 5);
    assert_eq!(
        successor.associated_data().predecessor_record_hash(),
        successor_expectation.predecessor_record_hash()
    );
    let authenticated_successor =
        expect_valid(root.authenticate_envelope(&successor, &successor_expectation));
    let opened_successor = expect_valid(authenticated_successor.open());
    assert_eq!(opened_successor.as_bytes(), successor_plaintext);
}

#[test]
fn an_equivalent_recovered_root_can_continue_an_authenticated_chain() {
    let root = test_storage_root();
    let identifier =
        LocalRecordIdentifier::action_randomness(test_binding()).expect("record identifier");
    let mut entropy = DeterministicEntropy::new([0x41; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    let initial = root
        .try_seal_initial_record(identifier, 1, b"before recovery", &mut entropy)
        .expect("initial record seals");
    let authenticated = expect_valid(
        root.authenticate_envelope(&initial, &LocalRecordExpectation::initial(identifier)),
    );

    let recovered_root = expect_valid(
        root.recovery_value()
            .expect("recovery value")
            .recover(test_binding(), root.storage_root_commitment_payload()),
    );
    let expectation = authenticated
        .successor_expectation()
        .expect("successor expectation");
    let mut successor_entropy = DeterministicEntropy::new([0x42; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    let successor = recovered_root
        .try_seal_successor_record(&authenticated, 2, b"after recovery", &mut successor_entropy)
        .expect("the equivalent recovered root continues the chain");
    let opened = expect_valid(
        recovered_root
            .authenticate_envelope(&successor, &expectation)
            .into_result()
            .expect("successor authenticates")
            .open(),
    );
    assert_eq!(opened.as_bytes(), b"after recovery");
}

#[test]
fn authentication_refuses_wrong_context_version_predecessor_and_root() {
    let root = test_storage_root();
    let identifier =
        LocalRecordIdentifier::action_randomness(test_binding()).expect("record identifier");
    let mut entropy = DeterministicEntropy::new([0x51; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    let envelope = root
        .try_seal_initial_record(identifier, 1, b"record", &mut entropy)
        .expect("record seals");

    assert_refused(
        root.authenticate_envelope(
            &envelope,
            &LocalRecordExpectation {
                identifier,
                record_version: 1,
                predecessor_record_hash: None,
            },
        ),
        RefusalReason::ConsumedState,
    );
    assert_refused(
        root.authenticate_envelope(
            &envelope,
            &LocalRecordExpectation {
                identifier,
                record_version: 0,
                predecessor_record_hash: Some(test_hash(0x52)),
            },
        ),
        RefusalReason::ConsumedState,
    );
    let other_identifier = LocalRecordIdentifier::public_coin_private_material(test_binding())
        .expect("other identifier");
    assert_refused(
        root.authenticate_envelope(
            &envelope,
            &LocalRecordExpectation::initial(other_identifier),
        ),
        RefusalReason::WrongContext,
    );
    let cross_context_identifier = LocalRecordIdentifier::action_randomness(alternate_binding())
        .expect("cross-context identifier");
    assert_refused(
        root.authenticate_envelope(
            &envelope,
            &LocalRecordExpectation::initial(cross_context_identifier),
        ),
        RefusalReason::WrongContext,
    );

    let other_root = ActionStorageRoot::from_verified_root(
        test_binding(),
        Zeroizing::new([0x53; ACTION_STORAGE_ROOT_BYTE_LENGTH]),
    )
    .expect("other root");
    assert_refused(
        other_root.authenticate_envelope(&envelope, &LocalRecordExpectation::initial(identifier)),
        RefusalReason::WrongHashOrRoot,
    );

    let mut unused_entropy = DeterministicEntropy::new([0x54; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    assert_eq!(
        root.try_seal_initial_record(
            cross_context_identifier,
            1,
            b"wrong context",
            &mut unused_entropy,
        )
        .expect_err("cross-context sealing must fail"),
        LocalStorageOperationError::WrongRecordContext
    );
    assert_eq!(unused_entropy.call_count, 0);
}

#[test]
fn every_authenticated_envelope_field_is_bound_before_decryption() {
    let root = test_storage_root();
    let identifier =
        LocalRecordIdentifier::action_randomness(test_binding()).expect("record identifier");
    let expectation = LocalRecordExpectation::initial(identifier);
    let mut entropy = DeterministicEntropy::new([0x61; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    let envelope = root
        .try_seal_initial_record(identifier, 7, b"authenticated plaintext", &mut entropy)
        .expect("record seals");

    let mut mutations = Vec::new();
    let mut changed_associated_data = envelope.clone();
    changed_associated_data
        .associated_data
        .creation_recovery_epoch ^= 1;
    mutations.push(changed_associated_data);
    let mut changed_nonce = envelope.clone();
    changed_nonce.nonce[0] ^= 1;
    mutations.push(changed_nonce);
    let mut changed_ciphertext = envelope.clone();
    changed_ciphertext.ciphertext[0] ^= 1;
    mutations.push(changed_ciphertext);
    let mut changed_tag = envelope.clone();
    changed_tag.tag[0] ^= 1;
    mutations.push(changed_tag);
    let mut changed_authenticator = envelope.clone();
    changed_authenticator.record_authenticator[0] ^= 1;
    mutations.push(changed_authenticator);

    for mutation in &mutations {
        assert_refused(
            root.authenticate_envelope(mutation, &expectation),
            RefusalReason::WrongHashOrRoot,
        );
    }

    let mut valid_authenticator_but_invalid_tag = envelope.clone();
    valid_authenticator_but_invalid_tag.tag[0] ^= 1;
    valid_authenticator_but_invalid_tag.record_authenticator = root
        .record_authenticator(&valid_authenticator_but_invalid_tag)
        .expect("the outer authenticator recomputes in this white-box test");
    let authenticated = expect_valid(
        root.authenticate_envelope(&valid_authenticator_but_invalid_tag, &expectation),
    );
    assert_refused(authenticated.open(), RefusalReason::WrongHashOrRoot);

    let mut wrong_length = envelope.clone();
    wrong_length.ciphertext.pop();
    assert_refused(
        root.authenticate_envelope(&wrong_length, &expectation),
        RefusalReason::WrongTypeOrLength,
    );
}

#[test]
fn local_record_schema_rejects_unassigned_types_bad_versions_and_bad_chain_shapes() {
    let identifier =
        LocalRecordIdentifier::action_randomness(test_binding()).expect("record identifier");
    let associated_data =
        LocalRecordAssociatedData::initial(identifier, 3, 4).expect("associated data");
    let encoded = associated_data.encode().expect("associated data encodes");

    assert_schema_refused(
        LocalRecordAssociatedData::decode(
            &replace_tuple_item(&encoded, 5, CanonicalItem::unsigned16(12)),
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::WrongTypeOrLength,
    );
    assert_schema_refused(
        LocalRecordAssociatedData::decode(
            &replace_tuple_item(&encoded, 0, CanonicalItem::unsigned16(2)),
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::UnsupportedVersionOrSuite,
    );
    assert_schema_refused(
        LocalRecordAssociatedData::decode(
            &replace_tuple_item(&encoded, 7, CanonicalItem::unsigned64(1)),
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::ConsumedState,
    );

    let predecessor = CanonicalItem::hash512(test_hash(0x71).into_bytes());
    let predecessor = CanonicalItem::optional(CanonicalItemType::Hash512, Some(&predecessor))
        .expect("optional predecessor");
    assert_schema_refused(
        LocalRecordAssociatedData::decode(
            &replace_tuple_item(&encoded, 9, predecessor),
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::ConsumedState,
    );

    let mut wrong_schema_version =
        CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("associated data tuple");
    wrong_schema_version.schema_version = 2;
    assert_schema_refused(
        LocalRecordAssociatedData::decode(
            &wrong_schema_version
                .encode()
                .expect("wrong-version tuple encodes"),
            &CanonicalDecodeLimits::default(),
        ),
        RefusalReason::UnsupportedVersionOrSuite,
    );

    let mut trailing_bytes = encoded;
    trailing_bytes.push(0);
    assert_schema_refused(
        LocalRecordAssociatedData::decode(&trailing_bytes, &CanonicalDecodeLimits::default()),
        RefusalReason::MalformedEncoding,
    );
}

#[test]
fn browser_plaintext_limit_is_exact_and_failure_does_not_consume_entropy() {
    let root = test_storage_root();
    let identifier =
        LocalRecordIdentifier::action_randomness(test_binding()).expect("record identifier");
    let maximum_plaintext = vec![0x81; MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH];
    let mut entropy = DeterministicEntropy::new([0x82; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    let envelope = root
        .try_seal_initial_record(identifier, 0, &maximum_plaintext, &mut entropy)
        .expect("the exact browser limit seals");
    let envelope_bytes = envelope.encode().expect("the boundary envelope encodes");
    let envelope = LocalRecordEnvelope::decode(&envelope_bytes, &CanonicalDecodeLimits::default())
        .expect("the boundary envelope decodes within its intrinsic limits");
    let authenticated = expect_valid(
        root.authenticate_envelope(&envelope, &LocalRecordExpectation::initial(identifier)),
    );
    assert_eq!(
        expect_valid(authenticated.open()).as_bytes(),
        maximum_plaintext.as_slice()
    );

    let over_limit = vec![0x83; MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH + 1];
    let mut unused_entropy = DeterministicEntropy::new([0x84; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
    assert_eq!(
        root.try_seal_initial_record(identifier, 0, &over_limit, &mut unused_entropy)
            .expect_err("an over-limit plaintext must fail"),
        LocalStorageOperationError::PlaintextTooLarge
    );
    assert_eq!(unused_entropy.call_count, 0);
}

#[test]
fn sealing_fails_closed_when_nonce_entropy_is_unavailable() {
    let root = test_storage_root();
    let identifier =
        LocalRecordIdentifier::action_randomness(test_binding()).expect("record identifier");
    assert_eq!(
        root.try_seal_initial_record(identifier, 0, b"plaintext", &mut PartiallyFailingEntropy,)
            .expect_err("partial nonce entropy must fail closed"),
        LocalStorageOperationError::EntropyUnavailable
    );
}

#[test]
fn secret_bearing_debug_output_is_redacted() {
    let root = test_storage_root();
    let recovery = root.recovery_value().expect("recovery value");
    let plaintext = LocalRecordPlaintext(Zeroizing::new(b"never print this secret".to_vec()));
    let recovery_debug = format!("{recovery:?}");
    let plaintext_debug = format!("{plaintext:?}");
    assert!(recovery_debug.contains("[REDACTED]"));
    assert!(!recovery_debug.contains("171, 171"));
    assert!(plaintext_debug.contains("[REDACTED]"));
    assert!(!plaintext_debug.contains("never print this secret"));
}
