use super::*;
use crate::foundation::{
    ACTION_STORAGE_ROOT_BYTE_LENGTH, DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH,
    DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH,
};

fn test_binding(offset: u8) -> [u8; BINDING_BYTE_LENGTH] {
    let mut binding = [0_u8; BINDING_BYTE_LENGTH];
    for (index, byte) in binding.iter_mut().enumerate() {
        *byte = offset.wrapping_add(index as u8);
    }
    binding
}

fn test_root(offset: u8) -> [u8; ACTION_STORAGE_ROOT_BYTE_LENGTH] {
    let mut root = [0_u8; ACTION_STORAGE_ROOT_BYTE_LENGTH];
    for (index, byte) in root.iter_mut().enumerate() {
        *byte = offset.wrapping_add(index as u8);
    }
    root
}

fn test_capability(offset: u8) -> [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] {
    let mut capability = [0_u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH];
    for (index, byte) in capability.iter_mut().enumerate() {
        *byte = offset.wrapping_add(index as u8);
    }
    capability
}

fn stage_new_input(
    capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    binding: &[u8; BINDING_BYTE_LENGTH],
    root: &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
) -> Vec<u8> {
    [capability.as_slice(), binding.as_slice(), root.as_slice()].concat()
}

fn lease_input(
    handle: u32,
    capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
) -> Vec<u8> {
    [handle.to_le_bytes().as_slice(), capability.as_slice()].concat()
}

fn stage_output(output: &[u8]) -> (u32, [u8; HASH_BYTE_LENGTH]) {
    assert_eq!(output.len(), HANDLE_BYTE_LENGTH + HASH_BYTE_LENGTH);
    let handle = u32::from_le_bytes(output[..4].try_into().expect("handle"));
    let commitment = output[4..].try_into().expect("commitment");
    (handle, commitment)
}

fn reset_registry() {
    run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_RESET, &[]).expect("reset");
}

fn checkpoint_manifest_identifier_context() -> Vec<u8> {
    [
        [0xa1; HASH_BYTE_LENGTH].as_slice(),
        [0xa2; 32].as_slice(),
        3_u16.to_le_bytes().as_slice(),
        7_u32.to_le_bytes().as_slice(),
        2_u32.to_le_bytes().as_slice(),
        [0xa3; HASH_BYTE_LENGTH].as_slice(),
        [0xa4; HASH_BYTE_LENGTH].as_slice(),
    ]
    .concat()
}

fn record_request_input(
    handle: u32,
    capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    action_randomness_commitment: &[u8; HASH_BYTE_LENGTH],
    record_type: LocalRecordType,
    identifier_context: &[u8],
    record_version: u64,
    predecessor_record_hash: Option<&[u8; HASH_BYTE_LENGTH]>,
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&handle.to_le_bytes());
    input.extend_from_slice(capability);
    input.extend_from_slice(action_randomness_commitment);
    input.extend_from_slice(&record_type.canonical_code().to_le_bytes());
    input.extend_from_slice(
        &u32::try_from(identifier_context.len())
            .expect("identifier context length")
            .to_le_bytes(),
    );
    input.extend_from_slice(identifier_context);
    input.extend_from_slice(&record_version.to_le_bytes());
    match predecessor_record_hash {
        None => input.push(0),
        Some(predecessor) => {
            input.push(1);
            input.extend_from_slice(predecessor);
        }
    }
    input
}

#[test]
fn root_registry_runs_device_wrapping_and_cleanup_without_exporting_root_bytes() {
    reset_registry();
    let capability = test_capability(3);
    let binding = test_binding(17);
    let root = test_root(71);
    let stage_output_bytes = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &binding, &root),
    )
    .expect("stage root");
    let (handle, commitment) = stage_output(&stage_output_bytes);
    assert_ne!(handle, 0);
    assert_ne!(commitment, [0_u8; HASH_BYTE_LENGTH]);

    let associated_data = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA,
        &lease_input(handle, &capability),
    )
    .expect("associated data");
    assert!(associated_data.len() <= 380);
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_COPY_FOR_DEVICE_WRAP,
            &lease_input(handle, &capability),
        )
        .expect("copy for device wrap"),
        root
    );

    let nonce = [0x31_u8; DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH];
    let ciphertext = [0x52_u8; ACTION_STORAGE_ROOT_BYTE_LENGTH];
    let tag = [0x73_u8; DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH];
    let envelope_input = [
        handle.to_le_bytes().as_slice(),
        capability.as_slice(),
        nonce.as_slice(),
        ciphertext.as_slice(),
        tag.as_slice(),
    ]
    .concat();
    let envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_ENCODE_DEVICE_ENVELOPE,
        &envelope_input,
    )
    .expect("encode envelope");
    assert!(envelope.len() <= 492);
    let decoded = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DECODE_DEVICE_ENVELOPE,
        &[
            binding.as_slice(),
            commitment.as_slice(),
            envelope.as_slice(),
        ]
        .concat(),
    )
    .expect("decode envelope");
    let decoded_associated_data_length =
        u32::from_le_bytes(decoded[..4].try_into().expect("associated-data length")) as usize;
    assert_eq!(
        &decoded[4..4 + decoded_associated_data_length],
        associated_data
    );
    assert_eq!(
        &decoded[4 + decoded_associated_data_length..],
        [nonce.as_slice(), ciphertext.as_slice(), tag.as_slice()].concat()
    );

    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &lease_input(handle, &capability),
    )
    .expect("commit");
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DESTROY,
        &lease_input(handle, &capability),
    )
    .expect("destroy");
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA,
            &lease_input(handle, &capability),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)
    );
    reset_registry();
}

#[test]
fn root_registry_refuses_wrong_binding_commitment_capability_and_resource_exhaustion() {
    reset_registry();
    let capability = test_capability(5);
    let binding = test_binding(23);
    let root = test_root(89);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &binding, &root),
    )
    .expect("stage");
    let (handle, commitment) = stage_output(&staged);

    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
            &stage_new_input(&test_capability(91), &binding, &root),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_RESOURCE_LIMIT)
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA,
            &lease_input(handle, &test_capability(93)),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH)
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DISCARD,
        &lease_input(handle, &capability),
    )
    .expect("discard");
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA,
            &lease_input(handle, &capability),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)
    );

    let mut wrong_commitment = commitment;
    wrong_commitment[0] ^= 0x80;
    let opened_input = [
        test_capability(97).as_slice(),
        binding.as_slice(),
        wrong_commitment.as_slice(),
        root.as_slice(),
    ]
    .concat();
    assert_eq!(
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_STAGE_OPENED, &opened_input,),
        Err(refusal_status(RefusalReason::WrongHashOrRoot))
    );

    let valid_open_input = [
        test_capability(101).as_slice(),
        binding.as_slice(),
        commitment.as_slice(),
        root.as_slice(),
    ]
    .concat();
    let opened =
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_STAGE_OPENED, &valid_open_input)
            .expect("stage opened");
    let (opened_handle, _) = stage_output(&opened);
    let nonce = [0_u8; DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH];
    let ciphertext = [0_u8; ACTION_STORAGE_ROOT_BYTE_LENGTH];
    let tag = [0_u8; DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH];
    let envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_ENCODE_DEVICE_ENVELOPE,
        &[
            opened_handle.to_le_bytes().as_slice(),
            test_capability(101).as_slice(),
            nonce.as_slice(),
            ciphertext.as_slice(),
            tag.as_slice(),
        ]
        .concat(),
    )
    .expect("envelope");
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DECODE_DEVICE_ENVELOPE,
            &[
                test_binding(199).as_slice(),
                commitment.as_slice(),
                envelope.as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::WrongContext))
    );
    reset_registry();
}

#[test]
fn forged_or_stale_mutations_cannot_clear_legitimate_root_leases() {
    reset_registry();
    let capability = test_capability(67);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(71), &test_root(73)),
    )
    .expect("legitimate root stages");
    let (handle, _) = stage_output(&staged);
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
            &lease_input(handle, &test_capability(83)),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH)
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DISCARD,
            &lease_input(handle.wrapping_sub(1), &capability),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA,
        &lease_input(handle, &capability),
    )
    .expect("failed forged mutations retain the legitimate staged root");

    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &lease_input(handle, &capability),
    )
    .expect("legitimate root commits");
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DESTROY,
            &lease_input(handle, &test_capability(89)),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH)
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA,
        &lease_input(handle, &capability),
    )
    .expect("failed forged destruction retains the legitimate active root");
    reset_registry();
}

#[test]
fn active_root_commands_derive_seal_open_hash_and_enforce_one_seal_per_record_version() {
    reset_registry();
    let capability = test_capability(103);
    let binding = test_binding(107);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &binding, &test_root(109)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &lease_input(handle, &capability),
    )
    .expect("root commits");

    let identifier_context = checkpoint_manifest_identifier_context();
    let identifier = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
        &[
            lease_input(handle, &capability).as_slice(),
            LocalRecordType::CheckpointManifest
                .canonical_code()
                .to_le_bytes()
                .as_slice(),
            identifier_context.as_slice(),
        ]
        .concat(),
    )
    .expect("record identifier derives");
    assert_eq!(identifier.len(), HASH_BYTE_LENGTH);

    let action_randomness_commitment = [0xb2; HASH_BYTE_LENGTH];
    let request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::CheckpointManifest,
        &identifier_context,
        0,
        None,
    );
    let nonce = [0xb3; 12];
    let plaintext = b"checkpoint manifest with authenticated cursor and boundary";
    let envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[request.as_slice(), nonce.as_slice(), plaintext.as_slice()].concat(),
    )
    .expect("record seals");
    assert_ne!(envelope, plaintext);
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                request.as_slice(),
                [0xb4; 12].as_slice(),
                plaintext.as_slice()
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::ConsumedState)),
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_OPEN_RECORD,
            &[request.as_slice(), envelope.as_slice()].concat(),
        )
        .expect("record opens"),
        plaintext,
    );

    let envelope_hash = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_HASH_RECORD_ENVELOPE,
        &[
            lease_input(handle, &capability).as_slice(),
            envelope.as_slice(),
        ]
        .concat(),
    )
    .expect("envelope hash derives");
    assert_eq!(envelope_hash.len(), HASH_BYTE_LENGTH);

    let mut tampered_envelope = envelope.clone();
    let last_byte = tampered_envelope
        .last_mut()
        .expect("encoded envelope is nonempty");
    *last_byte ^= 1;
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_OPEN_RECORD,
            &[request.as_slice(), tampered_envelope.as_slice()].concat(),
        ),
        Err(refusal_status(RefusalReason::WrongHashOrRoot)),
    );

    let wrong_capability_request = record_request_input(
        handle,
        &test_capability(127),
        &action_randomness_commitment,
        LocalRecordType::CheckpointManifest,
        &identifier_context,
        0,
        None,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_OPEN_RECORD,
            &[wrong_capability_request.as_slice(), envelope.as_slice()].concat(),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH),
    );
    reset_registry();
}

#[test]
fn record_commands_refuse_invalid_types_contexts_and_version_predecessor_pairs() {
    reset_registry();
    let capability = test_capability(131);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(137), &test_root(139)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &lease_input(handle, &capability),
    )
    .expect("root commits");

    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
            &[
                lease_input(handle, &capability).as_slice(),
                12_u16.to_le_bytes().as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
            &[
                lease_input(handle, &capability).as_slice(),
                LocalRecordType::CheckpointChunk
                    .canonical_code()
                    .to_le_bytes()
                    .as_slice(),
                [0; 7].as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::MalformedEncoding)),
    );

    let invalid_version_request = record_request_input(
        handle,
        &capability,
        &[0xc2; HASH_BYTE_LENGTH],
        LocalRecordType::CheckpointManifest,
        &checkpoint_manifest_identifier_context(),
        1,
        None,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                invalid_version_request.as_slice(),
                [0xc3; 12].as_slice(),
                b"manifest".as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::WrongContext)),
    );
    reset_registry();
}

#[test]
fn active_root_seal_budgets_refuse_the_first_invocation_or_byte_beyond_the_ceiling() {
    reset_registry();
    let capability = test_capability(149);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(151), &test_root(157)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &lease_input(handle, &capability),
    )
    .expect("root commits");
    ROOT_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let lease = registry.active.as_mut().expect("active root lease");
        lease.local_record_seal_invocation_count =
            MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT - 1;
    });

    let action_randomness_commitment = [0xd2; HASH_BYTE_LENGTH];
    let first_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::ProofAttempt,
        &[0xd3; HASH_BYTE_LENGTH],
        0,
        None,
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[
            first_request.as_slice(),
            [0xd4; 12].as_slice(),
            b"last allowed invocation".as_slice(),
        ]
        .concat(),
    )
    .expect("last allowed invocation seals");
    let beyond_invocation_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::ProofAttempt,
        &[0xd5; HASH_BYTE_LENGTH],
        0,
        None,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                beyond_invocation_request.as_slice(),
                [0xd6; 12].as_slice(),
                b"refused".as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::OutsideSupportedProfile)),
    );

    ROOT_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let lease = registry.active.as_mut().expect("active root lease");
        lease.local_record_seal_invocation_count = 0;
        lease.local_record_sealed_plaintext_byte_length =
            MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT - 3;
    });
    let exact_byte_ceiling_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::ProofAttempt,
        &[0xd7; HASH_BYTE_LENGTH],
        0,
        None,
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[
            exact_byte_ceiling_request.as_slice(),
            [0xd8; 12].as_slice(),
            b"abc".as_slice(),
        ]
        .concat(),
    )
    .expect("plaintext at the exact byte ceiling seals");
    let beyond_byte_ceiling_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::ProofAttempt,
        &[0xd9; HASH_BYTE_LENGTH],
        0,
        None,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                beyond_byte_ceiling_request.as_slice(),
                [0xda; 12].as_slice(),
                b"d".as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::OutsideSupportedProfile)),
    );
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert_eq!(
            lease.local_record_sealed_plaintext_byte_length,
            MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
        );
    });
    reset_registry();
}
