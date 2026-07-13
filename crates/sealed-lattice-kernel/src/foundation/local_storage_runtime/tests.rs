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

#[test]
fn root_registry_runs_wrapping_recovery_and_cleanup_without_exporting_an_unbounded_surface() {
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

    let mutation_identifier = [0x94_u8; MUTATION_IDENTIFIER_BYTE_LENGTH];
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
        &[
            handle.to_le_bytes().as_slice(),
            capability.as_slice(),
            mutation_identifier.as_slice(),
        ]
        .concat(),
    )
    .expect("commit");
    let recovery_export = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_PREPARE_RECOVERY,
        &[
            handle.to_le_bytes().as_slice(),
            capability.as_slice(),
            mutation_identifier.as_slice(),
        ]
        .concat(),
    )
    .expect("prepare recovery");
    assert_eq!(
        recovery_export.len(),
        RECOVERY_CHECKSUM_BYTE_LENGTH + RECOVERY_TEXT_BYTE_LENGTH
    );
    let (checksum, recovery_text) = recovery_export.split_at(RECOVERY_CHECKSUM_BYTE_LENGTH);
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_CONFIRM_RECOVERY,
        &[
            handle.to_le_bytes().as_slice(),
            capability.as_slice(),
            recovery_text,
            checksum,
        ]
        .concat(),
    )
    .expect("confirm recovery");
    run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_DESTROY,
        &lease_input(handle, &capability),
    )
    .expect("destroy");
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_PREPARE_RECOVERY,
            &[
                handle.to_le_bytes().as_slice(),
                capability.as_slice(),
                mutation_identifier.as_slice(),
            ]
            .concat(),
        ),
        Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)
    );

    let recovery_capability = test_capability(139);
    let recovered = run_local_storage_root_command(
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_RECOVERY,
        &[
            recovery_capability.as_slice(),
            binding.as_slice(),
            commitment.as_slice(),
            recovery_text,
        ]
        .concat(),
    )
    .expect("stage recovery");
    let (recovered_handle, recovered_commitment) = stage_output(&recovered[..68]);
    assert_eq!(recovered_commitment, commitment);
    assert_eq!(&recovered[68..], recovery_text);
    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_COPY_FOR_DEVICE_WRAP,
            &lease_input(recovered_handle, &recovery_capability),
        )
        .expect("copy recovered root"),
        root
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
    let mutation_identifier = [0x79; MUTATION_IDENTIFIER_BYTE_LENGTH];

    assert_eq!(
        run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_COMMIT,
            &[
                handle.to_le_bytes().as_slice(),
                test_capability(83).as_slice(),
                mutation_identifier.as_slice(),
            ]
            .concat(),
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
        &[
            handle.to_le_bytes().as_slice(),
            capability.as_slice(),
            mutation_identifier.as_slice(),
        ]
        .concat(),
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
        LOCAL_STORAGE_ROOT_COMMAND_PREPARE_RECOVERY,
        &[
            handle.to_le_bytes().as_slice(),
            capability.as_slice(),
            mutation_identifier.as_slice(),
        ]
        .concat(),
    )
    .expect("failed forged destruction retains the legitimate active root");
    reset_registry();
}
