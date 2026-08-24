use zeroize::Zeroizing;

use super::*;

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
        VerificationResult::Refused { refusal_reason } => assert_eq!(refusal_reason, expected),
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

fn fixed_lowercase_hex<const BYTE_LENGTH: usize>(value: &str) -> [u8; BYTE_LENGTH] {
    assert_eq!(value.len(), BYTE_LENGTH * 2);
    let mut bytes = [0_u8; BYTE_LENGTH];
    for (byte_index, byte) in bytes.iter_mut().enumerate() {
        let hexadecimal_pair = &value[byte_index * 2..byte_index * 2 + 2];
        *byte = u8::from_str_radix(hexadecimal_pair, 16).expect("test hexadecimal byte");
    }
    bytes
}

#[test]
fn storage_kmac256_wrapper_matches_nist_sp_800_185_sample_four() {
    // NIST SP 800-185 supplemental KMAC examples, Sample #4.
    let key: [u8; 32] =
        fixed_lowercase_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let expected: [u8; 64] = fixed_lowercase_hex(concat!(
        "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7",
        "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
    ));

    assert_eq!(
        kmac256::<64>(&key, &[0x00, 0x01, 0x02, 0x03], b"My Tagged Application"),
        expected
    );
}

#[test]
fn storage_root_commitment_binds_the_root_and_every_context_field() {
    let expected_root_bytes = (0u8..ACTION_STORAGE_ROOT_BYTE_LENGTH as u8).collect::<Vec<_>>();
    let root = ActionStorageRoot::from_verified_root(
        test_binding(),
        Zeroizing::new(expected_root_bytes.clone().try_into().expect("root length")),
    )
    .expect("the fixed root is canonical");

    let canonical_derivation_input = ActionStorageDerivationInput::new(test_binding())
        .encode()
        .expect("the action-storage derivation input is canonical");
    let key_material = kmac256::<ACTION_STORAGE_KEY_MATERIAL_BYTE_LENGTH>(
        &expected_root_bytes,
        &canonical_derivation_input,
        ACTION_STORAGE_KEY_HIERARCHY_CUSTOMIZATION,
    );
    assert_eq!(
        root.storage_root_commitment(),
        hash512(
            "sealed-lattice/local-storage-root/v1",
            &[
                CanonicalItem::variable_bytes(&canonical_derivation_input)
                    .expect("derivation bytes are canonical"),
                CanonicalItem::fixed_bytes(
                    &key_material[..STORAGE_ROOT_COMMITMENT_PREIMAGE_BYTE_LENGTH],
                )
                .expect("commitment preimage is canonical"),
            ],
        )
        .expect("the commitment input is canonical")
    );

    let changed_bindings = [
        LocalStorageBinding::new(
            test_hash(0x12),
            test_binding().ceremony_context_hash(),
            test_binding().action_context_hash(),
            test_binding().participant_id(),
        ),
        LocalStorageBinding::new(
            test_binding().suite_id(),
            test_hash(0x23),
            test_binding().action_context_hash(),
            test_binding().participant_id(),
        ),
        alternate_binding(),
        LocalStorageBinding::new(
            test_binding().suite_id(),
            test_binding().ceremony_context_hash(),
            test_binding().action_context_hash(),
            ParticipantIdentity::from_bytes([0x45; ParticipantIdentity::BYTE_LENGTH]),
        ),
    ];
    for changed_binding in changed_bindings {
        let changed_root = ActionStorageRoot::from_verified_root(
            changed_binding,
            Zeroizing::new(expected_root_bytes.clone().try_into().expect("root length")),
        )
        .expect("changed binding is canonical");
        assert_ne!(
            changed_root.storage_root_commitment(),
            root.storage_root_commitment()
        );
    }
    let changed_root = ActionStorageRoot::from_verified_root(
        test_binding(),
        Zeroizing::new([0xac; ACTION_STORAGE_ROOT_BYTE_LENGTH]),
    )
    .expect("changed root is canonical");
    assert_ne!(
        changed_root.storage_root_commitment(),
        root.storage_root_commitment()
    );

    let debug = format!("{root:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("0, 1, 2, 3"));
}

#[test]
fn device_wrapping_schemas_round_trip_and_recompute_opened_roots() {
    let root = test_storage_root();
    let associated_data = root.device_wrapping_associated_data();
    let associated_data_bytes = associated_data.encode().expect("associated data encodes");
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
        [0x71; DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH],
        [0x72; ACTION_STORAGE_ROOT_BYTE_LENGTH],
        [0x73; DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH],
    );
    let wrapped_bytes = wrapped.encode().expect("wrapped root encodes");
    assert_eq!(
        DeviceWrappedStorageRoot::decode(&wrapped_bytes, &CanonicalDecodeLimits::default())
            .expect("wrapped root decodes"),
        wrapped
    );

    let opened = expect_valid(associated_data.verify_opened_storage_root(
        Zeroizing::new(*root.root_bytes()),
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
            Zeroizing::new(*root.root_bytes()),
            alternate_binding(),
            root.storage_root_commitment_payload(),
        ),
        RefusalReason::WrongContext,
    );
}

#[test]
fn local_storage_schemas_apply_their_own_decode_limits() {
    let root = test_storage_root();
    let payload = root.storage_root_commitment_payload();
    let payload_bytes = payload.encode().expect("commitment payload encodes");
    assert_eq!(
        StorageRootCommitmentPayload::decode(&payload_bytes, &CanonicalDecodeLimits::default())
            .expect("commitment payload decodes"),
        payload
    );

    let limits = CanonicalDecodeLimits::default();
    for result in [
        StorageRootCommitmentPayload::decode(
            &[0; STORAGE_ROOT_COMMITMENT_PAYLOAD_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        )
        .map(|_| ()),
        DeviceWrappingAssociatedData::decode(
            &vec![0; DEVICE_WRAPPING_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        )
        .map(|_| ()),
        DeviceWrappedStorageRoot::decode(
            &vec![0; DEVICE_WRAPPED_STORAGE_ROOT_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        )
        .map(|_| ()),
    ] {
        assert_schema_refused(result, RefusalReason::OutsideSupportedProfile);
    }
}

const TEST_CHECKPOINT_LINEAGE_IDENTIFIER: [u8; 32] = [0x91; 32];

fn test_checkpoint_identifier_input(
    ordered_source_digests: &[Hash512],
) -> LocalRecordIdentifierInput<'_> {
    LocalRecordIdentifierInput::CheckpointManifest {
        runtime_build_manifest_hash: test_hash(0x81),
        checkpoint_lineage_identifier: &TEST_CHECKPOINT_LINEAGE_IDENTIFIER,
        operation_kind: 3,
        safe_boundary_ordinal: 7,
        ordered_source_digests,
    }
}

#[test]
fn action_storage_and_local_record_inputs_round_trip_canonically() {
    let derivation_input = ActionStorageDerivationInput::new(test_binding());
    let derivation_bytes = derivation_input.encode().expect("derivation input encodes");
    assert_eq!(
        ActionStorageDerivationInput::decode(&derivation_bytes, &CanonicalDecodeLimits::default(),)
            .expect("derivation input decodes"),
        derivation_input,
    );

    let key_input = LocalRecordKeyInput::new(
        test_binding(),
        test_hash(0xa1),
        LocalRecordType::CheckpointChunk,
        test_hash(0xa2),
        4,
    );
    let key_input_bytes = key_input.encode().expect("record key input encodes");
    assert_eq!(
        LocalRecordKeyInput::decode(&key_input_bytes, &CanonicalDecodeLimits::default())
            .expect("record key input decodes"),
        key_input,
    );

    let associated_data = LocalRecordAssociatedData::new(
        test_binding(),
        test_hash(0xa1),
        LocalRecordType::CheckpointChunk,
        test_hash(0xa2),
        4,
        Some(test_hash(0xa3)),
        19,
    )
    .expect("record associated data is valid");
    let associated_data_bytes = associated_data
        .encode()
        .expect("record associated data encodes");
    assert_eq!(
        LocalRecordAssociatedData::decode(
            &associated_data_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .expect("record associated data decodes"),
        associated_data,
    );

    for (version, predecessor) in [(0, Some(test_hash(0xb1))), (1, None), (u64::MAX, None)] {
        assert_schema_refused(
            LocalRecordAssociatedData::new(
                test_binding(),
                test_hash(0xa1),
                LocalRecordType::CheckpointChunk,
                test_hash(0xa2),
                version,
                predecessor,
                19,
            ),
            RefusalReason::WrongContext,
        );
    }
}

#[test]
fn all_record_identifier_assignments_are_closed_and_context_bound() {
    let source_digests = [test_hash(0xc1), test_hash(0xc2)];
    let identifiers = [
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::ActionRandomness,
        )
        .expect("action-randomness identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::SourceVssMaterial {
                material_context_hash: test_hash(0xc3),
            },
        )
        .expect("source VSS identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::AggregateThresholdShare {
                recipient_input_root: test_hash(0xc4),
            },
        )
        .expect("threshold-share identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::ProofAttempt {
                application_slot_hash: test_hash(0xc5),
            },
        )
        .expect("proof-attempt identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::BallotAttempt {
                canonical_ballot_statement_bytes: b"canonical ballot statement",
                ballot_encryption_attempt_identifier: &[0xc6; 32],
            },
        )
        .expect("ballot-attempt identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::ExactOutputChunk {
                capability_kind: 6,
                exact_output_hash: test_hash(0xc7),
                output_chunk_index: 8,
            },
        )
        .expect("exact-output identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::SubjectState {
                state_key: test_hash(0xc8),
            },
        )
        .expect("subject-state identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::WitnessState {
                state_key: test_hash(0xc9),
            },
        )
        .expect("witness-state identifier"),
        derive_local_record_identifier(
            test_binding(),
            test_checkpoint_identifier_input(&source_digests),
        )
        .expect("checkpoint identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::CheckpointChunk {
                checkpoint_identifier: test_hash(0xca),
                chunk_index: 9,
                chunk_digest: test_hash(0xcb),
            },
        )
        .expect("checkpoint-chunk identifier"),
        derive_local_record_identifier(
            test_binding(),
            LocalRecordIdentifierInput::CommonProofExternalMemory {
                common_proof_environment_identifier: [0xcc; 32],
                common_proof_runtime_binding_hash: test_hash(0xcd),
                proof_attempt_lineage_identifier: [0xce; 32],
                record_kind: CommonProofExternalMemoryRecordKind::DataChunk,
                object_ordinal: 10,
                chunk_ordinal: 11,
                byte_offset: 12,
            },
        )
        .expect("common-proof external-memory identifier"),
    ];
    let unique_identifiers = identifiers.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(unique_identifiers.len(), identifiers.len());

    for record_type_code in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
        assert_eq!(
            LocalRecordType::from_canonical_code(record_type_code)
                .expect("assigned record type")
                .canonical_code(),
            record_type_code,
        );
    }
    assert_eq!(LocalRecordType::from_canonical_code(0), None);
    assert_eq!(LocalRecordType::from_canonical_code(2), None);
    assert_eq!(LocalRecordType::from_canonical_code(13), None);

    let digest_items = source_digests
        .iter()
        .map(|digest| CanonicalItem::hash512(digest.into_bytes()))
        .collect::<Vec<_>>();
    let expected_checkpoint_identifier = hash512(
        "sealed-lattice/runtime/checkpoint/v1",
        &[
            CanonicalItem::hash512(test_hash(0x81).into_bytes()),
            CanonicalItem::hash512(test_binding().suite_id().into_bytes()),
            CanonicalItem::hash512(test_binding().ceremony_context_hash().into_bytes()),
            CanonicalItem::hash512(test_binding().action_context_hash().into_bytes()),
            CanonicalItem::participant_identity(test_binding().participant_id().into_bytes()),
            CanonicalItem::fixed_bytes(TEST_CHECKPOINT_LINEAGE_IDENTIFIER)
                .expect("lineage identifier"),
            CanonicalItem::unsigned16(3),
            CanonicalItem::unsigned32(7),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &digest_items)
                .expect("source digest list"),
        ],
    )
    .expect("checkpoint identifier hashes");
    assert_eq!(identifiers[8], expected_checkpoint_identifier);
}

#[test]
fn common_proof_external_memory_identifier_binds_every_coordinate() {
    let input = |environment_byte,
                 runtime_byte,
                 lineage_byte,
                 record_kind,
                 object_ordinal,
                 chunk_ordinal,
                 byte_offset| {
        LocalRecordIdentifierInput::CommonProofExternalMemory {
            common_proof_environment_identifier: [environment_byte; 32],
            common_proof_runtime_binding_hash: test_hash(runtime_byte),
            proof_attempt_lineage_identifier: [lineage_byte; 32],
            record_kind,
            object_ordinal,
            chunk_ordinal,
            byte_offset,
        }
    };
    let baseline = input(
        0xd1,
        0xd2,
        0xd3,
        CommonProofExternalMemoryRecordKind::DataChunk,
        4,
        5,
        6,
    );
    let baseline_identifier =
        derive_local_record_identifier(test_binding(), baseline).expect("baseline identifier");
    let changed_inputs = [
        input(
            0xe1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::DataChunk,
            4,
            5,
            6,
        ),
        input(
            0xd1,
            0xe2,
            0xd3,
            CommonProofExternalMemoryRecordKind::DataChunk,
            4,
            5,
            6,
        ),
        input(
            0xd1,
            0xd2,
            0xe3,
            CommonProofExternalMemoryRecordKind::DataChunk,
            4,
            5,
            6,
        ),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::SealMarker,
            4,
            5,
            6,
        ),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::DataChunk,
            7,
            5,
            6,
        ),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::DataChunk,
            4,
            8,
            6,
        ),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::DataChunk,
            4,
            5,
            9,
        ),
    ];
    for changed_input in changed_inputs {
        assert_ne!(
            derive_local_record_identifier(test_binding(), changed_input)
                .expect("changed identifier"),
            baseline_identifier,
        );
    }

    derive_local_record_identifier(
        test_binding(),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::ObjectHeader,
            4,
            0,
            0,
        ),
    )
    .expect("the canonical object-header coordinates derive");
    for invalid_input in [
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::ObjectHeader,
            4,
            1,
            0,
        ),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::ObjectHeader,
            4,
            0,
            1,
        ),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::DataChunk,
            4,
            0,
            0,
        ),
        input(
            0xd1,
            0xd2,
            0xd3,
            CommonProofExternalMemoryRecordKind::SealMarker,
            4,
            0,
            0,
        ),
    ] {
        assert_schema_refused(
            derive_local_record_identifier(test_binding(), invalid_input),
            RefusalReason::WrongContext,
        );
    }

    assert_eq!(
        CommonProofExternalMemoryRecordKind::from_canonical_code(1),
        Some(CommonProofExternalMemoryRecordKind::ObjectHeader),
    );
    assert_eq!(
        CommonProofExternalMemoryRecordKind::from_canonical_code(2),
        Some(CommonProofExternalMemoryRecordKind::DataChunk),
    );
    assert_eq!(
        CommonProofExternalMemoryRecordKind::from_canonical_code(3),
        Some(CommonProofExternalMemoryRecordKind::SealMarker),
    );
    assert_eq!(
        CommonProofExternalMemoryRecordKind::from_canonical_code(0),
        None,
    );
    assert_eq!(
        CommonProofExternalMemoryRecordKind::from_canonical_code(4),
        None,
    );
}

#[test]
fn common_proof_external_memory_records_authenticate_their_type_and_coordinates() {
    let root = test_storage_root();
    let action_randomness_commitment = test_hash(0xf1);
    let identifier_input = LocalRecordIdentifierInput::CommonProofExternalMemory {
        common_proof_environment_identifier: [0xf2; 32],
        common_proof_runtime_binding_hash: test_hash(0xf3),
        proof_attempt_lineage_identifier: [0xf4; 32],
        record_kind: CommonProofExternalMemoryRecordKind::DataChunk,
        object_ordinal: 17,
        chunk_ordinal: 19,
        byte_offset: 23,
    };
    let plaintext = b"secret external-memory data chunk";
    let nonce = [0xf5; LOCAL_RECORD_NONCE_BYTE_LENGTH];
    let envelope = root
        .seal_local_record(LocalRecordSealInput {
            action_randomness_commitment,
            identifier_input,
            record_version: 0,
            predecessor_record_hash: None,
            nonce,
            plaintext,
        })
        .expect("the common-proof external-memory record seals");
    assert_eq!(
        expect_valid(root.open_local_record(
            action_randomness_commitment,
            identifier_input,
            0,
            None,
            &envelope,
        ))
        .as_slice(),
        plaintext,
    );

    let changed_identifier_inputs = [
        LocalRecordIdentifierInput::CommonProofExternalMemory {
            common_proof_environment_identifier: [0xf2; 32],
            common_proof_runtime_binding_hash: test_hash(0xf3),
            proof_attempt_lineage_identifier: [0xf4; 32],
            record_kind: CommonProofExternalMemoryRecordKind::SealMarker,
            object_ordinal: 17,
            chunk_ordinal: 19,
            byte_offset: 23,
        },
        LocalRecordIdentifierInput::CommonProofExternalMemory {
            common_proof_environment_identifier: [0xf2; 32],
            common_proof_runtime_binding_hash: test_hash(0xf3),
            proof_attempt_lineage_identifier: [0xf4; 32],
            record_kind: CommonProofExternalMemoryRecordKind::DataChunk,
            object_ordinal: 18,
            chunk_ordinal: 19,
            byte_offset: 23,
        },
        LocalRecordIdentifierInput::CommonProofExternalMemory {
            common_proof_environment_identifier: [0xf2; 32],
            common_proof_runtime_binding_hash: test_hash(0xf3),
            proof_attempt_lineage_identifier: [0xf4; 32],
            record_kind: CommonProofExternalMemoryRecordKind::DataChunk,
            object_ordinal: 17,
            chunk_ordinal: 20,
            byte_offset: 23,
        },
        LocalRecordIdentifierInput::CommonProofExternalMemory {
            common_proof_environment_identifier: [0xf2; 32],
            common_proof_runtime_binding_hash: test_hash(0xf3),
            proof_attempt_lineage_identifier: [0xf4; 32],
            record_kind: CommonProofExternalMemoryRecordKind::DataChunk,
            object_ordinal: 17,
            chunk_ordinal: 19,
            byte_offset: 24,
        },
    ];
    for changed_identifier_input in changed_identifier_inputs {
        assert_refused(
            root.open_local_record(
                action_randomness_commitment,
                changed_identifier_input,
                0,
                None,
                &envelope,
            ),
            RefusalReason::WrongContext,
        );
    }
    assert_refused(
        root.open_local_record(
            action_randomness_commitment,
            LocalRecordIdentifierInput::CheckpointChunk {
                checkpoint_identifier: test_hash(0xf6),
                chunk_index: 19,
                chunk_digest: test_hash(0xf7),
            },
            0,
            None,
            &envelope,
        ),
        RefusalReason::WrongContext,
    );

    let alternate_coordinate_envelope = root
        .seal_local_record(LocalRecordSealInput {
            action_randomness_commitment,
            identifier_input: LocalRecordIdentifierInput::CommonProofExternalMemory {
                common_proof_environment_identifier: [0xf2; 32],
                common_proof_runtime_binding_hash: test_hash(0xf3),
                proof_attempt_lineage_identifier: [0xf4; 32],
                record_kind: CommonProofExternalMemoryRecordKind::DataChunk,
                object_ordinal: 17,
                chunk_ordinal: 20,
                byte_offset: 23,
            },
            record_version: 0,
            predecessor_record_hash: None,
            nonce,
            plaintext,
        })
        .expect("the alternate coordinate record seals");
    assert_ne!(
        envelope.ciphertext(),
        alternate_coordinate_envelope.ciphertext()
    );
    assert_ne!(envelope.tag(), alternate_coordinate_envelope.tag());

    let mut tampered_envelope = envelope;
    tampered_envelope.tag[0] ^= 1;
    assert_refused(
        root.open_local_record(
            action_randomness_commitment,
            identifier_input,
            0,
            None,
            &tampered_envelope,
        ),
        RefusalReason::WrongHashOrRoot,
    );
}

#[test]
fn local_record_sealing_round_trips_and_rejects_bound_mutations() {
    let root = test_storage_root();
    let source_digests = [test_hash(0xd1), test_hash(0xd2)];
    let plaintext = b"authenticated checkpoint manifest with live cursor state";
    let action_randomness_commitment = test_hash(0xd3);
    let envelope = root
        .seal_local_record(LocalRecordSealInput {
            action_randomness_commitment,
            identifier_input: test_checkpoint_identifier_input(&source_digests),
            record_version: 0,
            predecessor_record_hash: None,
            nonce: [0xd4; LOCAL_RECORD_NONCE_BYTE_LENGTH],
            plaintext,
        })
        .expect("record seals");
    assert_ne!(envelope.ciphertext(), plaintext);
    assert_eq!(
        expect_valid(root.open_local_record(
            action_randomness_commitment,
            test_checkpoint_identifier_input(&source_digests),
            0,
            None,
            &envelope,
        ))
        .as_slice(),
        plaintext,
    );

    let encoded = envelope.encode().expect("envelope encodes");
    let decoded = LocalRecordEnvelope::decode(&encoded, &CanonicalDecodeLimits::default())
        .expect("envelope decodes");
    assert_eq!(decoded, envelope);
    assert_eq!(
        envelope.envelope_hash().expect("envelope hash"),
        derive_local_record_envelope_hash(&encoded).expect("canonical envelope hash"),
    );

    assert_refused(
        root.open_local_record(
            test_hash(0xd5),
            test_checkpoint_identifier_input(&source_digests),
            0,
            None,
            &envelope,
        ),
        RefusalReason::WrongContext,
    );
    let alternate_source_digests = [test_hash(0xd1), test_hash(0xd6)];
    assert_refused(
        root.open_local_record(
            action_randomness_commitment,
            test_checkpoint_identifier_input(&alternate_source_digests),
            0,
            None,
            &envelope,
        ),
        RefusalReason::WrongContext,
    );

    let mut mutated_ciphertext = envelope.clone();
    mutated_ciphertext.ciphertext[3] ^= 1;
    assert_refused(
        root.open_local_record(
            action_randomness_commitment,
            test_checkpoint_identifier_input(&source_digests),
            0,
            None,
            &mutated_ciphertext,
        ),
        RefusalReason::WrongHashOrRoot,
    );
    let mut mutated_tag = envelope.clone();
    mutated_tag.tag[7] ^= 1;
    assert_refused(
        root.open_local_record(
            action_randomness_commitment,
            test_checkpoint_identifier_input(&source_digests),
            0,
            None,
            &mutated_tag,
        ),
        RefusalReason::WrongHashOrRoot,
    );
}

fn borrowed_local_record_decode_refusal(encoded: &[u8]) -> RefusalReason {
    match BorrowedLocalRecordEnvelope::decode(encoded, &CanonicalDecodeLimits::default()) {
        Ok(_) => panic!("the malformed borrowed local-record envelope must be refused"),
        Err(error) => error.refusal_reason,
    }
}

#[test]
fn canonical_local_record_path_matches_the_owned_envelope_at_payload_boundaries() {
    let root = test_storage_root();
    let source_digests = [test_hash(0x91), test_hash(0x92)];
    let identifier_input = test_checkpoint_identifier_input(&source_digests);
    let record_identifier = derive_local_record_identifier(root.binding(), identifier_input)
        .expect("the fixed record identifier derives");
    let action_randomness_commitment = test_hash(0x93);
    let nonce = [0x94; LOCAL_RECORD_NONCE_BYTE_LENGTH];

    for plaintext in [
        Vec::new(),
        vec![0xa5],
        (0_u8..=255).collect::<Vec<_>>(),
        vec![0x5a; MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH],
    ] {
        let seal_input = LocalRecordSealWithIdentifierInput {
            action_randomness_commitment,
            record_type: identifier_input.record_type(),
            record_identifier,
            record_version: 0,
            predecessor_record_hash: None,
            nonce,
            plaintext: &plaintext,
        };
        let owned_envelope = root
            .seal_local_record_with_identifier(seal_input)
            .expect("the owned local-record path seals");
        let canonical_envelope = root
            .seal_local_record_with_identifier_canonical(seal_input)
            .expect("the direct canonical local-record path seals");
        assert_eq!(
            canonical_envelope,
            owned_envelope
                .encode()
                .expect("the owned local-record envelope encodes"),
            "the direct path must preserve the established canonical bytes"
        );
        assert_eq!(
            expect_valid(
                root.open_borrowed_local_record_with_identifier(
                    LocalRecordOpenWithIdentifierInput {
                        action_randomness_commitment,
                        record_type: identifier_input.record_type(),
                        expected_identifier: record_identifier,
                        record_version: 0,
                        predecessor_record_hash: None,
                    },
                    &BorrowedLocalRecordEnvelope::decode(
                        &canonical_envelope,
                        &CanonicalDecodeLimits::default(),
                    )
                    .expect(
                        "the canonical local-record envelope decodes without copying ciphertext"
                    ),
                )
            )
            .as_slice(),
            plaintext.as_slice(),
            "the borrowed decoder must authenticate every supported boundary payload"
        );
    }
}

#[test]
fn canonical_local_record_path_rejects_malformed_outer_framing_before_decryption() {
    let root = test_storage_root();
    let source_digests = [test_hash(0x95)];
    let identifier_input = test_checkpoint_identifier_input(&source_digests);
    let record_identifier = derive_local_record_identifier(root.binding(), identifier_input)
        .expect("the fixed record identifier derives");
    let action_randomness_commitment = test_hash(0x96);
    let canonical_envelope = root
        .seal_local_record_with_identifier_canonical(LocalRecordSealWithIdentifierInput {
            action_randomness_commitment,
            record_type: identifier_input.record_type(),
            record_identifier,
            record_version: 0,
            predecessor_record_hash: None,
            nonce: [0x97; LOCAL_RECORD_NONCE_BYTE_LENGTH],
            plaintext: b"borrowed canonical ciphertext",
        })
        .expect("the direct canonical local-record path seals");

    let mut wrong_item_type = canonical_envelope.clone();
    wrong_item_type[8..10]
        .copy_from_slice(&CanonicalItemType::Unsigned16.canonical_code().to_le_bytes());
    let established_wrong_item_type_refusal =
        LocalRecordEnvelope::decode(&wrong_item_type, &CanonicalDecodeLimits::default())
            .expect_err("the established decoder rejects an assigned type with invalid bytes")
            .refusal_reason;
    assert_eq!(
        established_wrong_item_type_refusal,
        RefusalReason::MalformedEncoding,
    );
    assert_eq!(
        borrowed_local_record_decode_refusal(&wrong_item_type),
        established_wrong_item_type_refusal,
        "the borrowed decoder must validate assigned item types before schema types",
    );

    let first_item_byte_length = usize::try_from(u32::from_le_bytes(
        wrong_item_type[10..14]
            .try_into()
            .expect("the first item length is four bytes"),
    ))
    .expect("the first item length fits usize");
    let second_item_header_offset = 14 + first_item_byte_length;
    let mut compound_wrong_item_types = wrong_item_type;
    compound_wrong_item_types[second_item_header_offset..second_item_header_offset + 2]
        .copy_from_slice(&CanonicalItemType::Unsigned16.canonical_code().to_le_bytes());
    assert_eq!(
        borrowed_local_record_decode_refusal(&compound_wrong_item_types),
        LocalRecordEnvelope::decode(
            &compound_wrong_item_types,
            &CanonicalDecodeLimits::default(),
        )
        .expect_err("the established decoder rejects the first malformed assigned item")
        .refusal_reason,
        "a later malformed item must not reorder the first item refusal",
    );

    let malformed_associated_data_before_wrong_nonce_type = CanonicalTuple::new(
        LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER,
        FOUNDATION_PROTOCOL_VERSION,
        vec![
            CanonicalItem::variable_bytes([0x71, 0x72, 0x73])
                .expect("the short associated-data item is canonical"),
            CanonicalItem::ascii("wrong nonce type")
                .expect("the wrong nonce type remains canonically encoded"),
            CanonicalItem::variable_bytes([]).expect("the empty ciphertext item is canonical"),
            CanonicalItem::fixed_bytes([0_u8; LOCAL_RECORD_TAG_BYTE_LENGTH])
                .expect("the fixed tag item is canonical"),
        ],
    )
    .encode()
    .expect("the compound malformed envelope encodes canonically");
    let established_compound_refusal = LocalRecordEnvelope::decode(
        &malformed_associated_data_before_wrong_nonce_type,
        &CanonicalDecodeLimits::default(),
    )
    .expect_err("the established decoder rejects the malformed associated data first")
    .refusal_reason;
    assert_eq!(
        established_compound_refusal,
        RefusalReason::MalformedEncoding
    );
    let borrowed_compound_refusal =
        borrowed_local_record_decode_refusal(&malformed_associated_data_before_wrong_nonce_type);
    assert_eq!(
        borrowed_compound_refusal, established_compound_refusal,
        "the borrowed decoder must decode each schema field before checking the next field",
    );

    let mut inconsistent_item_length = canonical_envelope.clone();
    inconsistent_item_length[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        borrowed_local_record_decode_refusal(&inconsistent_item_length),
        RefusalReason::OutsideSupportedProfile,
    );

    let mut trailing_bytes = canonical_envelope.clone();
    trailing_bytes.push(0);
    assert_eq!(
        borrowed_local_record_decode_refusal(&trailing_bytes),
        RefusalReason::MalformedEncoding,
    );

    let mut truncated_declared_item_list = canonical_envelope[..8].to_vec();
    truncated_declared_item_list[4..8].copy_from_slice(&3_u32.to_le_bytes());
    let established_truncated_refusal = LocalRecordEnvelope::decode(
        &truncated_declared_item_list,
        &CanonicalDecodeLimits::default(),
    )
    .expect_err("the established decoder must reject missing declared item headers")
    .refusal_reason;
    assert_eq!(
        established_truncated_refusal,
        RefusalReason::MalformedEncoding
    );
    assert_eq!(
        borrowed_local_record_decode_refusal(&truncated_declared_item_list),
        established_truncated_refusal,
        "the borrowed decoder must preserve truncated-list refusal semantics",
    );

    let mut unassigned_item_type = canonical_envelope;
    unassigned_item_type[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    let established_unassigned_type_refusal =
        LocalRecordEnvelope::decode(&unassigned_item_type, &CanonicalDecodeLimits::default())
            .expect_err("the established decoder must reject an unassigned item type")
            .refusal_reason;
    assert_eq!(
        established_unassigned_type_refusal,
        RefusalReason::MalformedEncoding,
    );
    assert_eq!(
        borrowed_local_record_decode_refusal(&unassigned_item_type),
        established_unassigned_type_refusal,
        "the borrowed decoder must preserve unassigned-type refusal semantics",
    );
}

#[test]
fn record_versions_derive_distinct_keys_and_enforce_predecessors_and_size_caps() {
    let root = test_storage_root();
    let source_digests = [test_hash(0xe1)];
    let version_zero = root
        .seal_local_record(LocalRecordSealInput {
            action_randomness_commitment: test_hash(0xe2),
            identifier_input: test_checkpoint_identifier_input(&source_digests),
            record_version: 0,
            predecessor_record_hash: None,
            nonce: [0xe3; LOCAL_RECORD_NONCE_BYTE_LENGTH],
            plaintext: b"same plaintext",
        })
        .expect("version zero seals");
    let predecessor_hash = version_zero.envelope_hash().expect("predecessor hash");
    let version_one = root
        .seal_local_record(LocalRecordSealInput {
            action_randomness_commitment: test_hash(0xe2),
            identifier_input: test_checkpoint_identifier_input(&source_digests),
            record_version: 1,
            predecessor_record_hash: Some(predecessor_hash),
            nonce: [0xe3; LOCAL_RECORD_NONCE_BYTE_LENGTH],
            plaintext: b"same plaintext",
        })
        .expect("version one seals");
    assert_ne!(version_zero.ciphertext(), version_one.ciphertext());
    assert_ne!(version_zero.tag(), version_one.tag());

    let oversized_plaintext = vec![0u8; MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH + 1];
    assert_schema_refused(
        root.seal_local_record(LocalRecordSealInput {
            action_randomness_commitment: test_hash(0xe2),
            identifier_input: test_checkpoint_identifier_input(&source_digests),
            record_version: 2,
            predecessor_record_hash: Some(version_one.envelope_hash().expect("predecessor hash")),
            nonce: [0xe4; LOCAL_RECORD_NONCE_BYTE_LENGTH],
            plaintext: &oversized_plaintext,
        }),
        RefusalReason::OutsideSupportedProfile,
    );
}

#[test]
fn aes_256_gcm_siv_matches_rfc_8452_appendix_c2() {
    let mut key = [0u8; 32];
    key[0] = 1;
    let mut nonce = [0u8; 12];
    nonce[0] = 3;
    let mut plaintext = vec![1, 0, 0, 0, 0, 0, 0, 0];
    let cipher = Aes256GcmSiv::new_from_slice(&key).expect("RFC key length");
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut plaintext)
        .expect("RFC vector encrypts");
    assert_eq!(plaintext, [0xc2, 0xef, 0x32, 0x8e, 0x5c, 0x71, 0xc8, 0x3b]);
    assert_eq!(
        tag.as_slice(),
        [
            0x84, 0x31, 0x22, 0x13, 0x0f, 0x73, 0x64, 0xb7, 0x61, 0xe0, 0xb9, 0x74, 0x27, 0xe3,
            0xdf, 0x28,
        ],
    );
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut plaintext, &tag)
        .expect("RFC vector decrypts");
    assert_eq!(plaintext, [1, 0, 0, 0, 0, 0, 0, 0]);
}
