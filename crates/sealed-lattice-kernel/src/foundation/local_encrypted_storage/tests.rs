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

fn replace_tuple_item(bytes: &[u8], index: usize, item: CanonicalItem) -> Vec<u8> {
    let mut tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
        .expect("the source tuple is canonical");
    tuple.items[index] = item;
    tuple.encode().expect("the mutated tuple remains canonical")
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
        2,
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
                2,
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
            LocalRecordIdentifierInput::PublicCoinPrivateMaterial,
        )
        .expect("public-coin identifier"),
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
    ];
    let unique_identifiers = identifiers.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(unique_identifiers.len(), identifiers.len());

    for record_type_code in 1..=11 {
        assert_eq!(
            LocalRecordType::from_canonical_code(record_type_code)
                .expect("assigned record type")
                .canonical_code(),
            record_type_code,
        );
    }
    assert_eq!(LocalRecordType::from_canonical_code(0), None);
    assert_eq!(LocalRecordType::from_canonical_code(12), None);

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
    assert_eq!(identifiers[9], expected_checkpoint_identifier);
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
