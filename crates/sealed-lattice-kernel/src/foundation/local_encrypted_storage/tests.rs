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

    let mut expected_items = Vec::from(test_binding().canonical_items());
    expected_items.push(
        CanonicalItem::fixed_bytes(&expected_root_bytes).expect("the root length is canonical"),
    );
    assert_eq!(
        root.storage_root_commitment(),
        hash512("sealed-lattice/local-storage-root/v2", &expected_items)
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
fn recovery_round_trips_canonical_base32_and_rejects_mutated_bound_values() {
    let root = test_storage_root();
    let recovery = root.recovery_value().expect("recovery value");
    let encoded = recovery.encode().expect("recovery value encodes");
    assert_eq!(encoded.len(), RECOVERY_VALUE_CANONICAL_BYTE_LENGTH);

    let canonical = recovery
        .to_canonical_base32()
        .expect("recovery value has canonical base32");
    assert_eq!(canonical.len(), RECOVERY_VALUE_BASE32_CHARACTER_LENGTH);
    assert!(!canonical.contains('='));
    let ingress = CanonicalLocalStorageRecoveryIngress::decode(
        &canonical.to_ascii_lowercase(),
        &CanonicalDecodeLimits::default(),
    )
    .expect("case-insensitive ingress accepts lowercase");
    assert_eq!(ingress.canonical_base32(), canonical.as_str());
    let recovered = expect_valid(
        ingress
            .into_recovery_value()
            .recover(test_binding(), root.storage_root_commitment_payload()),
    );
    assert_eq!(
        recovered.storage_root_commitment(),
        root.storage_root_commitment()
    );

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

    for (index, item) in [
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
    ] {
        assert_schema_refused(
            LocalStorageRecoveryValue::decode(
                &replace_tuple_item(&encoded, index, item),
                &CanonicalDecodeLimits::default(),
            ),
            RefusalReason::WrongHashOrRoot,
        );
    }
}

#[test]
fn recovery_requires_the_expected_context_and_verified_commitment() {
    let root = test_storage_root();
    let encoded = root
        .recovery_value()
        .expect("recovery value")
        .encode()
        .expect("recovery value encodes");
    let decode = || {
        LocalStorageRecoveryValue::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("recovery value decodes")
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
        LocalStorageRecoveryValue::decode(
            &vec![0; RECOVERY_VALUE_CANONICAL_BYTE_LENGTH + 1],
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
