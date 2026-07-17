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

fn commit_input(
    handle: u32,
    capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
) -> Vec<u8> {
    lease_input(handle, capability)
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

fn common_proof_external_memory_identifier_context() -> Vec<u8> {
    [
        [0xb1; 32].as_slice(),
        [0xb2; HASH_BYTE_LENGTH].as_slice(),
        [0xb3; 32].as_slice(),
        CommonProofExternalMemoryRecordKind::DataChunk
            .canonical_code()
            .to_le_bytes()
            .as_slice(),
        17_u32.to_le_bytes().as_slice(),
        19_u32.to_le_bytes().as_slice(),
        23_u64.to_le_bytes().as_slice(),
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

fn record_identifier_input(
    handle: u32,
    capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    record_type: LocalRecordType,
    identifier_context: &[u8],
) -> Vec<u8> {
    [
        lease_input(handle, capability).as_slice(),
        record_type.canonical_code().to_le_bytes().as_slice(),
        identifier_context,
    ]
    .concat()
}

fn authenticated_repair_request_input(
    handle: u32,
    capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    runtime_build_manifest_hash: &[u8; HASH_BYTE_LENGTH],
    namespace: &[u8],
) -> Vec<u8> {
    [
        lease_input(handle, capability).as_slice(),
        runtime_build_manifest_hash.as_slice(),
        u32::try_from(namespace.len())
            .expect("namespace length")
            .to_le_bytes()
            .as_slice(),
        namespace,
    ]
    .concat()
}

#[test]
fn authenticated_repair_commands_bind_root_build_namespace_and_exact_envelope() {
    reset_registry();
    let capability = test_capability(201);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(203), &test_root(205)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("root commits");

    let runtime_build_manifest_hash = [0xd1; HASH_BYTE_LENGTH];
    let request = authenticated_repair_request_input(
        handle,
        &capability,
        &runtime_build_manifest_hash,
        b"foundation-0",
    );
    let repair_identity =
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY, &request)
            .expect("repair identity derives");
    assert_eq!(repair_identity.len(), HASH_BYTE_LENGTH);
    assert_ne!(repair_identity, vec![0; HASH_BYTE_LENGTH]);

    let different_namespace_request = authenticated_repair_request_input(
        handle,
        &capability,
        &runtime_build_manifest_hash,
        b"foundation-1",
    );
    assert_ne!(
        repair_identity,
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY,
            &different_namespace_request,
        )
        .expect("different namespace identity derives"),
    );
    let different_build_request = authenticated_repair_request_input(
        handle,
        &capability,
        &[0xd2; HASH_BYTE_LENGTH],
        b"foundation-0",
    );
    assert_ne!(
        repair_identity,
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY,
            &different_build_request,
        )
        .expect("different build identity derives"),
    );

    let plaintext = b"exact authenticated repair head";
    let envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_REPAIR_HEAD,
        &[request.as_slice(), [0xd3; 12].as_slice(), plaintext].concat(),
    )
    .expect("repair head seals");
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_OPEN_REPAIR_HEAD,
            &[request.as_slice(), envelope.as_slice()].concat(),
        )
        .expect("repair head opens"),
        plaintext,
    );
    let digest = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DIGEST_REPAIR_HEAD,
        &[request.as_slice(), envelope.as_slice()].concat(),
    )
    .expect("repair head digest derives");
    assert_eq!(digest.len(), HASH_BYTE_LENGTH);
    assert_eq!(
        digest,
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DIGEST_REPAIR_HEAD,
            &[request.as_slice(), envelope.as_slice()].concat(),
        )
        .expect("repair head digest is deterministic"),
    );

    for wrong_context_request in [&different_namespace_request, &different_build_request] {
        assert_eq!(
            run_local_storage_root_command(
                LOCAL_STORAGE_ROOT_COMMAND_OPEN_REPAIR_HEAD,
                &[wrong_context_request.as_slice(), envelope.as_slice()].concat(),
            ),
            Err(refusal_status(RefusalReason::WrongHashOrRoot)),
        );
    }
    let mut tampered_envelope = envelope.clone();
    *tampered_envelope.last_mut().expect("envelope is nonempty") ^= 1;
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_OPEN_REPAIR_HEAD,
            &[request.as_slice(), tampered_envelope.as_slice()].concat(),
        ),
        Err(refusal_status(RefusalReason::WrongHashOrRoot)),
    );
    let wrong_capability_request = authenticated_repair_request_input(
        handle,
        &test_capability(211),
        &runtime_build_manifest_hash,
        b"foundation-0",
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY,
            &wrong_capability_request,
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH),
    );
    reset_registry();
}

#[test]
fn authenticated_repair_commands_reject_noncanonical_namespaces_without_panicking() {
    reset_registry();
    let capability = test_capability(213);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(215), &test_root(217)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("root commits");
    for namespace in [
        b"".as_slice(),
        b"-leading".as_slice(),
        b"trailing-".as_slice(),
        b"double--hyphen".as_slice(),
        b"Uppercase".as_slice(),
        [b'a'; 65].as_slice(),
    ] {
        assert_eq!(
            run_local_storage_root_command(
                LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY,
                &authenticated_repair_request_input(
                    handle,
                    &capability,
                    &[0xe1; HASH_BYTE_LENGTH],
                    namespace,
                ),
            ),
            Err(refusal_status(RefusalReason::WrongTypeOrLength)),
        );
    }
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY,
        &authenticated_repair_request_input(
            handle,
            &capability,
            &[0xe2; HASH_BYTE_LENGTH],
            b"0-valid-numeric-prefix",
        ),
    )
    .expect("numeric namespace prefix is canonical");
    reset_registry();
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
        &commit_input(handle, &capability),
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
fn authenticated_storage_head_source_requires_the_live_worker_root_capability() {
    reset_registry();
    let capability = test_capability(4);
    let binding_bytes = test_binding(18);
    let root = test_root(72);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &binding_bytes, &root),
    )
    .expect("stage root");
    let (handle, commitment_bytes) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("commit root");

    let mut binding_reader = InputReader::new(&binding_bytes);
    let expected_binding = read_binding(&mut binding_reader).expect("decode binding");
    binding_reader.finish().expect("finish binding");
    let authenticated_head_digest = Hash512::from_bytes([0xa5; HASH_BYTE_LENGTH]);
    let storage_instance_identity = Hash512::from_bytes([0xb6; HASH_BYTE_LENGTH]);
    let source = resolve_browser_worker_authenticated_storage_head_source(
        handle,
        &capability,
        17,
        authenticated_head_digest,
        storage_instance_identity,
    )
    .expect("resolve authenticated head source");
    assert_eq!(source.local_storage_binding(), expected_binding);
    assert_eq!(
        source.storage_root_commitment(),
        Hash512::from_bytes(commitment_bytes)
    );
    assert_eq!(source.namespace_sequence(), 17);
    assert_eq!(
        source.authenticated_head_digest(),
        authenticated_head_digest
    );
    assert_eq!(
        source.storage_instance_identity(),
        storage_instance_identity
    );

    assert_eq!(
        resolve_browser_worker_authenticated_storage_head_source(
            handle,
            &test_capability(5),
            17,
            authenticated_head_digest,
            storage_instance_identity,
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH)
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DESTROY,
        &lease_input(handle, &capability),
    )
    .expect("destroy root");
    assert_eq!(
        resolve_browser_worker_authenticated_storage_head_source(
            handle,
            &capability,
            17,
            authenticated_head_digest,
            storage_instance_identity,
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)
    );
    reset_registry();
}

#[test]
fn authenticated_storage_transition_source_requires_the_live_worker_root_capability() {
    reset_registry();
    let capability = test_capability(6);
    let binding_bytes = test_binding(28);
    let root = test_root(92);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &binding_bytes, &root),
    )
    .expect("stage root");
    let (handle, commitment_bytes) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("commit root");

    let mut binding_reader = InputReader::new(&binding_bytes);
    let expected_binding = read_binding(&mut binding_reader).expect("decode binding");
    binding_reader.finish().expect("finish binding");
    let predecessor_head_digest = Hash512::from_bytes([0xa7; HASH_BYTE_LENGTH]);
    let successor_head_digest = Hash512::from_bytes([0xb8; HASH_BYTE_LENGTH]);
    let storage_instance_identity = Hash512::from_bytes([0xc9; HASH_BYTE_LENGTH]);
    let authenticated_record_digest = Hash512::from_bytes([0xda; HASH_BYTE_LENGTH]);
    let source = resolve_browser_worker_authenticated_storage_transition_source(
        handle,
        &capability,
        41,
        predecessor_head_digest,
        42,
        successor_head_digest,
        storage_instance_identity,
        authenticated_record_digest,
    )
    .expect("resolve authenticated transition source");
    assert_eq!(source.local_storage_binding(), expected_binding);
    assert_eq!(
        source.storage_root_commitment(),
        Hash512::from_bytes(commitment_bytes)
    );
    assert_eq!(source.predecessor_namespace_sequence(), 41);
    assert_eq!(
        source.predecessor_authenticated_head_digest(),
        predecessor_head_digest
    );
    assert_eq!(source.successor_namespace_sequence(), 42);
    assert_eq!(
        source.successor_authenticated_head_digest(),
        successor_head_digest
    );
    assert_eq!(
        source.storage_instance_identity(),
        storage_instance_identity
    );
    assert_eq!(
        source.authenticated_record_digest(),
        authenticated_record_digest
    );

    assert_eq!(
        resolve_browser_worker_authenticated_storage_transition_source(
            handle,
            &test_capability(7),
            41,
            predecessor_head_digest,
            42,
            successor_head_digest,
            storage_instance_identity,
            authenticated_record_digest,
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH)
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DESTROY,
        &lease_input(handle, &capability),
    )
    .expect("destroy root");
    assert_eq!(
        resolve_browser_worker_authenticated_storage_transition_source(
            handle,
            &capability,
            41,
            predecessor_head_digest,
            42,
            successor_head_digest,
            storage_instance_identity,
            authenticated_record_digest,
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)
    );
    reset_registry();
}

#[test]
fn authenticated_storage_transition_source_rejects_nonconsecutive_sequences() {
    reset_registry();
    let capability = test_capability(8);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(38), &test_root(102)),
    )
    .expect("stage root");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("commit root");
    let digest = Hash512::from_bytes([0xeb; HASH_BYTE_LENGTH]);

    for (predecessor_sequence, successor_sequence) in
        [(9, 9), (9, 11), (u64::MAX, 0), (u64::MAX, u64::MAX)]
    {
        assert_eq!(
            resolve_browser_worker_authenticated_storage_transition_source(
                handle,
                &capability,
                predecessor_sequence,
                digest,
                successor_sequence,
                digest,
                digest,
                digest,
            ),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );
    }

    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DESTROY,
        &lease_input(handle, &capability),
    )
    .expect("destroy root");
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
fn forged_or_stale_capabilities_cannot_clear_legitimate_root_leases() {
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
            &commit_input(handle, &test_capability(83)),
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
    .expect("failed forged operations retain the legitimate staged root");

    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
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
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
        &[
            lease_input(handle, &capability).as_slice(),
            LocalRecordType::CheckpointManifest
                .canonical_code()
                .to_le_bytes()
                .as_slice(),
            checkpoint_manifest_identifier_context().as_slice(),
        ]
        .concat(),
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
        &commit_input(handle, &capability),
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
fn active_root_record_version_ledger_retains_only_the_highest_successful_version() {
    reset_registry();
    let capability = test_capability(181);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(183), &test_root(185)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("root commits");

    let action_randomness_commitment = [0xe1; HASH_BYTE_LENGTH];
    let state_key = [0xe2; HASH_BYTE_LENGTH];
    let initial_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &state_key,
        0,
        None,
    );
    let initial_envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[
            initial_request.as_slice(),
            [0xe3; 12].as_slice(),
            b"initial witness state".as_slice(),
        ]
        .concat(),
    )
    .expect("initial record seals");
    let record_identifier: [u8; HASH_BYTE_LENGTH] = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
        &record_identifier_input(
            handle,
            &capability,
            LocalRecordType::WitnessState,
            &state_key,
        ),
    )
    .expect("record identifier derives")
    .try_into()
    .expect("record identifier length");
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert_eq!(lease.sealed_record_highest_versions.len(), 1);
        assert_eq!(
            lease.sealed_record_highest_versions.get(&record_identifier),
            Some(&0),
        );
    });

    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                initial_request.as_slice(),
                [0xe4; 12].as_slice(),
                b"reused version".as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::ConsumedState)),
    );

    let initial_envelope_hash: [u8; HASH_BYTE_LENGTH] = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_HASH_RECORD_ENVELOPE,
        &[
            lease_input(handle, &capability).as_slice(),
            initial_envelope.as_slice(),
        ]
        .concat(),
    )
    .expect("initial envelope hash derives")
    .try_into()
    .expect("initial envelope hash length");
    let later_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &state_key,
        7,
        Some(&initial_envelope_hash),
    );
    let later_envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[
            later_request.as_slice(),
            [0xe5; 12].as_slice(),
            b"later witness state".as_slice(),
        ]
        .concat(),
    )
    .expect("higher record version seals without another ledger entry");
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert_eq!(lease.sealed_record_highest_versions.len(), 1);
        assert_eq!(
            lease.sealed_record_highest_versions.get(&record_identifier),
            Some(&7),
        );
    });

    let stale_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &state_key,
        3,
        Some(&initial_envelope_hash),
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                stale_request.as_slice(),
                [0xe6; 12].as_slice(),
                b"stale witness state".as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::ConsumedState)),
    );

    let invalid_next_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &state_key,
        8,
        None,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                invalid_next_request.as_slice(),
                [0xe7; 12].as_slice(),
                b"invalid successor".as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::WrongContext)),
    );
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert_eq!(
            lease.sealed_record_highest_versions.get(&record_identifier),
            Some(&7),
        );
    });

    let later_envelope_hash: [u8; HASH_BYTE_LENGTH] = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_HASH_RECORD_ENVELOPE,
        &[
            lease_input(handle, &capability).as_slice(),
            later_envelope.as_slice(),
        ]
        .concat(),
    )
    .expect("later envelope hash derives")
    .try_into()
    .expect("later envelope hash length");
    let valid_next_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &state_key,
        8,
        Some(&later_envelope_hash),
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[
            valid_next_request.as_slice(),
            [0xe8; 12].as_slice(),
            b"valid successor".as_slice(),
        ]
        .concat(),
    )
    .expect("a failed seal does not consume its higher version");
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert_eq!(lease.sealed_record_highest_versions.len(), 1);
        assert_eq!(
            lease.sealed_record_highest_versions.get(&record_identifier),
            Some(&8),
        );
        assert_eq!(lease.local_record_seal_invocation_count, 3);
    });
    reset_registry();
}

#[test]
fn common_proof_scratch_records_require_dedicated_zero_version_commands() {
    reset_registry();
    let capability = test_capability(187);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(189), &test_root(191)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("root commits");

    let identifier_context = common_proof_external_memory_identifier_context();
    let identifier_input = record_identifier_input(
        handle,
        &capability,
        LocalRecordType::CommonProofExternalMemory,
        &identifier_context,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
            &identifier_input,
        ),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );
    let identifier = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_COMMON_PROOF_EXTERNAL_MEMORY_RECORD_IDENTIFIER,
        &identifier_input,
    )
    .expect("worker-internal scratch identifier derives");
    assert_eq!(identifier.len(), HASH_BYTE_LENGTH);
    let non_scratch_context = [0xe8; HASH_BYTE_LENGTH];
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_COMMON_PROOF_EXTERNAL_MEMORY_RECORD_IDENTIFIER,
            &record_identifier_input(
                handle,
                &capability,
                LocalRecordType::WitnessState,
                &non_scratch_context,
            ),
        ),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );

    let action_randomness_commitment = [0xe9; HASH_BYTE_LENGTH];
    let request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::CommonProofExternalMemory,
        &identifier_context,
        0,
        None,
    );
    let plaintext = b"bounded common-proof scratch";
    let seal_input = [
        request.as_slice(),
        [0xea; 12].as_slice(),
        plaintext.as_slice(),
    ]
    .concat();
    assert_eq!(
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD, &seal_input),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );
    let envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_COMMON_PROOF_EXTERNAL_MEMORY_RECORD,
        &seal_input,
    )
    .expect("worker-internal scratch record seals");
    let non_scratch_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &non_scratch_context,
        0,
        None,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_COMMON_PROOF_EXTERNAL_MEMORY_RECORD,
            &[
                non_scratch_request.as_slice(),
                [0xeb; 12].as_slice(),
                plaintext.as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert!(lease.sealed_record_highest_versions.is_empty());
        assert_eq!(lease.local_record_seal_invocation_count, 1);
        assert_eq!(
            lease.local_record_sealed_plaintext_byte_length,
            u64::try_from(plaintext.len()).expect("plaintext length"),
        );
    });

    let open_input = [request.as_slice(), envelope.as_slice()].concat();
    assert_eq!(
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_OPEN_RECORD, &open_input),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_OPEN_COMMON_PROOF_EXTERNAL_MEMORY_RECORD,
            &open_input,
        )
        .expect("worker-internal scratch record opens"),
        plaintext,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_OPEN_COMMON_PROOF_EXTERNAL_MEMORY_RECORD,
            &[non_scratch_request.as_slice(), envelope.as_slice()].concat(),
        ),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );

    let versioned_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::CommonProofExternalMemory,
        &identifier_context,
        1,
        Some(&[0xec; HASH_BYTE_LENGTH]),
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_COMMON_PROOF_EXTERNAL_MEMORY_RECORD,
            &[
                versioned_request.as_slice(),
                [0xed; 12].as_slice(),
                plaintext.as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::WrongContext)),
    );
    reset_registry();
}

#[test]
fn active_root_identifier_cap_refuses_new_records_but_allows_replacements_and_scratch() {
    reset_registry();
    let capability = test_capability(193);
    let binding = test_binding(195);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &binding, &test_root(197)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("root commits");

    let action_randomness_commitment = [0xed; HASH_BYTE_LENGTH];
    let state_key = [0xee; HASH_BYTE_LENGTH];
    let initial_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &state_key,
        0,
        None,
    );
    let initial_envelope = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[
            initial_request.as_slice(),
            [0xef; 12].as_slice(),
            b"retained witness state".as_slice(),
        ]
        .concat(),
    )
    .expect("initial record seals");
    let initial_envelope_hash: [u8; HASH_BYTE_LENGTH] = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_HASH_RECORD_ENVELOPE,
        &[
            lease_input(handle, &capability).as_slice(),
            initial_envelope.as_slice(),
        ]
        .concat(),
    )
    .expect("initial envelope hash derives")
    .try_into()
    .expect("initial envelope hash length");

    let new_identifier_context = [0xf0; HASH_BYTE_LENGTH];
    let refused_new_identifier: [u8; HASH_BYTE_LENGTH] = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
        &record_identifier_input(
            handle,
            &capability,
            LocalRecordType::ProofAttempt,
            &new_identifier_context,
        ),
    )
    .expect("prospective identifier derives")
    .try_into()
    .expect("prospective identifier length");
    ROOT_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let lease = registry.active.as_mut().expect("active root lease");
        let mut candidate_ordinal = 0_u64;
        while lease.sealed_record_highest_versions.len()
            < maximum_tracked_local_record_identifier_count_per_active_root()
        {
            let mut candidate_identifier = [0_u8; HASH_BYTE_LENGTH];
            candidate_identifier[..8].copy_from_slice(&candidate_ordinal.to_le_bytes());
            candidate_identifier[HASH_BYTE_LENGTH - 1] = 0xff;
            candidate_ordinal = candidate_ordinal
                .checked_add(1)
                .expect("candidate ordinal remains bounded");
            if candidate_identifier != refused_new_identifier {
                lease
                    .sealed_record_highest_versions
                    .entry(candidate_identifier)
                    .or_insert(0);
            }
        }
        assert!(
            !lease
                .sealed_record_highest_versions
                .contains_key(&refused_new_identifier)
        );
    });

    let new_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::ProofAttempt,
        &new_identifier_context,
        0,
        None,
    );
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
            &[
                new_request.as_slice(),
                [0xf1; 12].as_slice(),
                b"new record beyond cap".as_slice(),
            ]
            .concat(),
        ),
        Err(refusal_status(RefusalReason::OutsideSupportedProfile)),
    );
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert_eq!(lease.local_record_seal_invocation_count, 1);
        assert_eq!(
            lease.sealed_record_highest_versions.len(),
            maximum_tracked_local_record_identifier_count_per_active_root(),
        );
    });

    let replacement_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::WitnessState,
        &state_key,
        1,
        Some(&initial_envelope_hash),
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD,
        &[
            replacement_request.as_slice(),
            [0xf2; 12].as_slice(),
            b"replacement at cap".as_slice(),
        ]
        .concat(),
    )
    .expect("replacement at the identifier cap seals");

    let scratch_context = common_proof_external_memory_identifier_context();
    let scratch_request = record_request_input(
        handle,
        &capability,
        &action_randomness_commitment,
        LocalRecordType::CommonProofExternalMemory,
        &scratch_context,
        0,
        None,
    );
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_COMMON_PROOF_EXTERNAL_MEMORY_RECORD,
        &[
            scratch_request.as_slice(),
            [0xf3; 12].as_slice(),
            b"scratch outside the retained ledger".as_slice(),
        ]
        .concat(),
    )
    .expect("worker-internal scratch remains available at the identifier cap");
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active.as_ref().expect("active root lease");
        assert_eq!(
            lease.sealed_record_highest_versions.len(),
            maximum_tracked_local_record_identifier_count_per_active_root(),
        );
        assert_eq!(lease.local_record_seal_invocation_count, 3);
    });
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
        &commit_input(handle, &capability),
    )
    .expect("root commits");

    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER,
            &[
                lease_input(handle, &capability).as_slice(),
                13_u16.to_le_bytes().as_slice(),
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
fn active_root_derives_common_proof_external_memory_identifiers_from_closed_contexts() {
    reset_registry();
    let capability = test_capability(141);
    let staged = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
        &stage_new_input(&capability, &test_binding(143), &test_root(145)),
    )
    .expect("root stages");
    let (handle, _) = stage_output(&staged);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &commit_input(handle, &capability),
    )
    .expect("root commits");

    let context = common_proof_external_memory_identifier_context();
    assert_eq!(
        context.len(),
        COMMON_PROOF_EXTERNAL_MEMORY_IDENTIFIER_CONTEXT_BYTE_LENGTH,
    );
    let derive_identifier = |record_type: LocalRecordType, identifier_context: &[u8]| {
        let command = if record_type == LocalRecordType::CommonProofExternalMemory {
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_COMMON_PROOF_EXTERNAL_MEMORY_RECORD_IDENTIFIER
        } else {
            LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER
        };
        run_local_storage_root_command(
            command,
            &[
                lease_input(handle, &capability).as_slice(),
                record_type.canonical_code().to_le_bytes().as_slice(),
                identifier_context,
            ]
            .concat(),
        )
    };
    let identifier = derive_identifier(LocalRecordType::CommonProofExternalMemory, &context)
        .expect("common-proof external-memory identifier derives");
    assert_eq!(identifier.len(), HASH_BYTE_LENGTH);

    const RUNTIME_BINDING_HASH_OFFSET: usize = 32;
    const PROOF_ATTEMPT_LINEAGE_IDENTIFIER_OFFSET: usize =
        RUNTIME_BINDING_HASH_OFFSET + HASH_BYTE_LENGTH;
    const RECORD_KIND_OFFSET: usize = PROOF_ATTEMPT_LINEAGE_IDENTIFIER_OFFSET + 32;
    const OBJECT_ORDINAL_OFFSET: usize = RECORD_KIND_OFFSET + core::mem::size_of::<u16>();
    const CHUNK_ORDINAL_OFFSET: usize = OBJECT_ORDINAL_OFFSET + core::mem::size_of::<u32>();
    const BYTE_OFFSET_OFFSET: usize = CHUNK_ORDINAL_OFFSET + core::mem::size_of::<u32>();
    assert_eq!(
        BYTE_OFFSET_OFFSET + core::mem::size_of::<u64>(),
        COMMON_PROOF_EXTERNAL_MEMORY_IDENTIFIER_CONTEXT_BYTE_LENGTH,
    );
    for (coordinate_name, coordinate_offset) in [
        ("environment identifier", 0),
        ("runtime-binding hash", RUNTIME_BINDING_HASH_OFFSET),
        (
            "proof-attempt lineage identifier",
            PROOF_ATTEMPT_LINEAGE_IDENTIFIER_OFFSET,
        ),
        ("record kind", RECORD_KIND_OFFSET),
        ("object ordinal", OBJECT_ORDINAL_OFFSET),
        ("chunk ordinal", CHUNK_ORDINAL_OFFSET),
        ("byte offset", BYTE_OFFSET_OFFSET),
    ] {
        let mut changed_context = context.clone();
        changed_context[coordinate_offset] ^= 1;
        let changed_identifier =
            derive_identifier(LocalRecordType::CommonProofExternalMemory, &changed_context)
                .expect(coordinate_name);
        assert_ne!(identifier, changed_identifier, "{coordinate_name}");
    }

    let mut invalid_kind_context = context.clone();
    invalid_kind_context[RECORD_KIND_OFFSET..OBJECT_ORDINAL_OFFSET]
        .copy_from_slice(&4_u16.to_le_bytes());
    assert_eq!(
        derive_identifier(
            LocalRecordType::CommonProofExternalMemory,
            &invalid_kind_context,
        ),
        Err(refusal_status(RefusalReason::WrongTypeOrLength)),
    );

    let mut canonical_header_context = context.clone();
    canonical_header_context[RECORD_KIND_OFFSET..OBJECT_ORDINAL_OFFSET].copy_from_slice(
        &CommonProofExternalMemoryRecordKind::ObjectHeader
            .canonical_code()
            .to_le_bytes(),
    );
    canonical_header_context[CHUNK_ORDINAL_OFFSET..BYTE_OFFSET_OFFSET]
        .copy_from_slice(&0_u32.to_le_bytes());
    canonical_header_context[BYTE_OFFSET_OFFSET..].copy_from_slice(&0_u64.to_le_bytes());
    derive_identifier(
        LocalRecordType::CommonProofExternalMemory,
        &canonical_header_context,
    )
    .expect("canonical object-header coordinates derive");
    let mut invalid_header_chunk_context = canonical_header_context.clone();
    invalid_header_chunk_context[CHUNK_ORDINAL_OFFSET..BYTE_OFFSET_OFFSET]
        .copy_from_slice(&1_u32.to_le_bytes());
    let mut invalid_header_offset_context = canonical_header_context.clone();
    invalid_header_offset_context[BYTE_OFFSET_OFFSET..].copy_from_slice(&1_u64.to_le_bytes());
    let mut invalid_data_chunk_context = context.clone();
    invalid_data_chunk_context[CHUNK_ORDINAL_OFFSET..BYTE_OFFSET_OFFSET]
        .copy_from_slice(&0_u32.to_le_bytes());
    let mut invalid_seal_marker_context = invalid_data_chunk_context.clone();
    invalid_seal_marker_context[RECORD_KIND_OFFSET..OBJECT_ORDINAL_OFFSET].copy_from_slice(
        &CommonProofExternalMemoryRecordKind::SealMarker
            .canonical_code()
            .to_le_bytes(),
    );
    for invalid_coordinate_context in [
        invalid_header_chunk_context,
        invalid_header_offset_context,
        invalid_data_chunk_context,
        invalid_seal_marker_context,
    ] {
        assert_eq!(
            derive_identifier(
                LocalRecordType::CommonProofExternalMemory,
                &invalid_coordinate_context,
            ),
            Err(refusal_status(RefusalReason::WrongContext)),
        );
    }

    assert_eq!(
        derive_identifier(
            LocalRecordType::CommonProofExternalMemory,
            &context[..context.len() - 1],
        ),
        Err(refusal_status(RefusalReason::MalformedEncoding)),
    );
    let mut extended_context = context.clone();
    extended_context.push(0);
    assert_eq!(
        derive_identifier(
            LocalRecordType::CommonProofExternalMemory,
            &extended_context,
        ),
        Err(refusal_status(RefusalReason::MalformedEncoding)),
    );
    assert_eq!(
        derive_identifier(LocalRecordType::CheckpointChunk, &context),
        Err(refusal_status(RefusalReason::MalformedEncoding)),
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
        &commit_input(handle, &capability),
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
