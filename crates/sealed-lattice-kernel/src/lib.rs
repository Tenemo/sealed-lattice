//! WebAssembly command surface for the sealed-lattice prototype kernel.
//!
//! The maintained Rust API is the byte-oriented command runner and the FFI
//! allocation functions below. Proof internals are crate-private and should be
//! reached through transcript-core commands so trust boundaries stay centralized.

#![recursion_limit = "256"]

pub(crate) mod bgv;
mod encoding;
pub mod foundation;
pub(crate) mod hashing;
pub(crate) mod transcript_core;

use core::{ptr, slice};
use std::vec::Vec;

use bgv::proof_suite::{
    AggregateThresholdShareGenerationMode, AggregateThresholdShareRuntimeError,
    absorb_authenticated_recipient_vss_payload, aggregate_threshold_share_runtime_error_status,
    begin_aggregate_threshold_share_recipient_authority,
    bind_generated_aggregate_threshold_share_proof_to_board,
    discard_aggregate_threshold_share_generation_board_binding_source,
    discard_aggregate_threshold_share_recipient_authority,
    discard_aggregate_threshold_share_verification_terminal_source,
    finish_aggregate_threshold_share_verification, prepare_aggregate_threshold_share_generation,
    prepare_aggregate_threshold_share_verification,
};
use bgv::proof_suite::{
    begin_setup_generation_authority, cancel_setup_generation_public_key_share_body_by_identifier,
    cancel_setup_generation_recipient_payload,
    open_setup_generation_public_key_share_body_by_identifier,
    open_setup_generation_recipient_payload,
    read_setup_generation_public_key_share_body_by_identifier,
    read_setup_generation_recipient_payload, release_setup_generation_authority_by_identifier,
    setup_generation_public_key_share_body_byte_length_by_identifier,
    setup_generation_public_key_share_source_byte_length_by_identifier,
    setup_generation_recipient_payload_byte_length,
    setup_generation_recipient_payload_source_byte_length,
    setup_generation_recipient_payload_source_recipient_roster_position,
};
use foundation::{
    CanonicalStreamRuntimeBegin, FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
    STATE_DURABLE_BINDING_BYTE_LENGTH, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
    VERIFIED_FINALITY_DESCRIPTION_BYTE_LENGTH, absorb_canonical_stream_chunk,
    authenticate_mailbox_gcm_chunk, begin_canonical_stream_verifier, begin_canonical_stream_writer,
    begin_finality_verifier_session, begin_mailbox_gcm_encryptor, begin_mailbox_gcm_verifier,
    begin_state_verifier_session, cancel_canonical_stream, cancel_finality_verifier_session,
    cancel_mailbox_gcm, cancel_state_verifier_session, certify_verified_state_intent,
    certify_verified_state_intent_from_unordered_vote_carriers, decrypt_mailbox_gcm_chunk,
    describe_verified_finality, describe_verified_state_object, encrypt_mailbox_gcm_chunk,
    finish_canonical_stream_verifier, finish_canonical_stream_writer,
    finish_mailbox_gcm_authentication, finish_mailbox_gcm_decryptor, finish_mailbox_gcm_encryptor,
    finish_state_output_intent_verification, finish_state_output_verification,
    release_verified_finality, release_verified_state_object, run_action_randomness_command,
    run_local_storage_root_command, run_state_producer_command, verify_finality,
    verify_state_reservation, verify_state_reservation_intent,
};

pub use encoding::run_transcript_core_command;

fn leak_bytes(bytes: Vec<u8>) -> *mut u8 {
    Box::into_raw(bytes.into_boxed_slice()) as *mut u8
}

unsafe fn transcript_core_command_output(pointer: *const u8, length: usize) -> Vec<u8> {
    if length == 0 || pointer.is_null() {
        return run_transcript_core_command(b"{}");
    }

    let input = unsafe { slice::from_raw_parts(pointer, length) };

    run_transcript_core_command(input)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_allocate(length: usize) -> *mut u8 {
    if length == 0 {
        return ptr::null_mut();
    }

    leak_bytes(vec![0_u8; length])
}

/// # Safety
///
/// `pointer` must either be null with `length == 0` or point to an allocation
/// previously returned by a sealed-lattice allocation or byte-output export
/// with the same `length`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_deallocate(pointer: *mut u8, length: usize) {
    if length == 0 || pointer.is_null() {
        return;
    }

    unsafe {
        ptr::write_bytes(pointer, 0, length);
        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
            pointer, length,
        )));
    }
}

/// # Safety
///
/// `pointer` must either be null with `length == 0` or point to readable bytes
/// for `length` elements in the WebAssembly module's linear memory.
/// `output_length_pointer` must be null or point to writable memory for one
/// `usize` value in the WebAssembly module's linear memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_transcript_core_command_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let output = unsafe { transcript_core_command_output(pointer, length) };
    let output_length = output.len();
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output_length);
        }
    }

    leak_bytes(output)
}

unsafe fn fixed_bytes<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    length: usize,
) -> [u8; BYTE_LENGTH] {
    if pointer.is_null() || length != BYTE_LENGTH {
        return [0_u8; BYTE_LENGTH];
    }
    let mut bytes = [0_u8; BYTE_LENGTH];
    bytes.copy_from_slice(unsafe { slice::from_raw_parts(pointer, length) });
    bytes
}

unsafe fn state_verifier_capability(
    pointer: *const u8,
    length: usize,
) -> [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH] {
    unsafe { fixed_bytes(pointer, length) }
}

unsafe fn canonical_stream_input<'input>(pointer: *const u8, length: usize) -> &'input [u8] {
    if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    }
}

unsafe fn canonical_stream_input_mut<'input>(pointer: *mut u8, length: usize) -> &'input mut [u8] {
    if length == 0 || pointer.is_null() {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(pointer, length) }
    }
}

fn decode_u32_list(bytes: &[u8]) -> Option<Vec<u32>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(size_of::<u32>()) {
        return None;
    }
    bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| <[u8; 4]>::try_from(chunk).ok().map(u32::from_le_bytes))
        .collect()
}

unsafe fn write_u32_if_present(pointer: *mut u32, value: u32) {
    if !pointer.is_null() {
        unsafe {
            pointer.write(value);
        }
    }
}

unsafe fn write_usize_if_present(pointer: *mut usize, value: usize) {
    if !pointer.is_null() {
        unsafe {
            pointer.write(value);
        }
    }
}

/// Begins the single browser-owned aggregate-threshold-share recipient
/// authority from the authenticated public-randomness transcript and the
/// exact roster-ordered VSS terminal catalog. No roots, rows, seeds, or
/// aggregate coefficients cross this boundary.
///
/// The public-randomness catalog contains all setup-intent handles in roster
/// order, then all commitment handles, then all reveal handles, encoded as
/// little-endian `u32` values. The dealer-terminal catalog contains exactly one
/// little-endian `u32` verified VSS terminal handle per participant in roster
/// order. A successful call consumes every dealer terminal.
///
/// # Safety
///
/// Each non-null input pointer must name its declared readable range. A
/// non-null status pointer must name one writable `u32`.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_aggregate_threshold_share_begin_recipient_authority(
    action_randomness_handle: u32,
    local_recipient_roster_position: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    ordered_public_randomness_handle_bytes_pointer: *const u8,
    ordered_public_randomness_handle_bytes_byte_length: usize,
    ordered_dealer_terminal_handle_bytes_pointer: *const u8,
    ordered_dealer_terminal_handle_bytes_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result: Result<u32, AggregateThresholdShareRuntimeError> = (|| {
        let local_recipient_roster_position = u16::try_from(local_recipient_roster_position)
            .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?;
        let board_verifier_session_capability = unsafe {
            canonical_stream_input(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        };
        let ordered_public_randomness_handle_bytes = unsafe {
            canonical_stream_input(
                ordered_public_randomness_handle_bytes_pointer,
                ordered_public_randomness_handle_bytes_byte_length,
            )
        };
        let ordered_dealer_terminal_handle_bytes = unsafe {
            canonical_stream_input(
                ordered_dealer_terminal_handle_bytes_pointer,
                ordered_dealer_terminal_handle_bytes_byte_length,
            )
        };
        let ordered_public_randomness_object_handles =
            decode_u32_list(ordered_public_randomness_handle_bytes)
                .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
        let ordered_dealer_terminal_handles = decode_u32_list(ordered_dealer_terminal_handle_bytes)
            .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
        begin_aggregate_threshold_share_recipient_authority(
            action_randomness_handle,
            local_recipient_roster_position,
            board_verifier_session_handle,
            board_verifier_session_capability,
            &ordered_public_randomness_object_handles,
            &ordered_dealer_terminal_handles,
        )
    })();
    match result {
        Ok(authority_handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            authority_handle
        }
        Err(error) => {
            unsafe {
                write_u32_if_present(
                    status_pointer,
                    aggregate_threshold_share_runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// One-shot consumes an authenticated mailbox-plaintext capability into the
/// exact recipient authority. The envelope and plaintext are accepted
/// only when their canonical bytes reproduce the dealer's verified terminal
/// bindings.
///
/// # Safety
///
/// Each input pointer must be non-null and name its non-empty declared
/// readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_aggregate_threshold_share_absorb_authenticated_recipient_payload(
    recipient_authority_handle: u32,
    authenticated_plaintext_capability_handle: u32,
    canonical_signed_envelope_pointer: *const u8,
    canonical_signed_envelope_length: usize,
    canonical_plaintext_pointer: *const u8,
    canonical_plaintext_length: usize,
) -> u32 {
    if canonical_signed_envelope_pointer.is_null()
        || canonical_signed_envelope_length == 0
        || canonical_plaintext_pointer.is_null()
        || canonical_plaintext_length == 0
    {
        return aggregate_threshold_share_runtime_error_status(
            AggregateThresholdShareRuntimeError::InvalidInput,
        );
    }
    let canonical_signed_envelope_bytes = unsafe {
        slice::from_raw_parts(
            canonical_signed_envelope_pointer,
            canonical_signed_envelope_length,
        )
    };
    let canonical_plaintext_bytes =
        unsafe { slice::from_raw_parts(canonical_plaintext_pointer, canonical_plaintext_length) };
    absorb_authenticated_recipient_vss_payload(
        recipient_authority_handle,
        authenticated_plaintext_capability_handle,
        canonical_signed_envelope_bytes,
        canonical_plaintext_bytes,
    )
    .map_or_else(aggregate_threshold_share_runtime_error_status, |()| 0)
}

const AGGREGATE_THRESHOLD_SHARE_CHECKPOINT_LINEAGE_BYTE_LENGTH: usize = 32;

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_aggregate_threshold_share_generation_from_ffi_inputs(
    selected_suite_handle: u32,
    recipient_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    board_binding_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: AggregateThresholdShareGenerationMode,
) -> u32 {
    let result: Result<(u32, u32), AggregateThresholdShareRuntimeError> = (|| {
        if board_binding_source_handle_output_pointer.is_null()
            || checkpoint_lineage_identifier_pointer.is_null()
            || checkpoint_lineage_identifier_byte_length
                != AGGREGATE_THRESHOLD_SHARE_CHECKPOINT_LINEAGE_BYTE_LENGTH
        {
            return Err(AggregateThresholdShareRuntimeError::InvalidInput);
        }
        let state_verifier_session_capability = unsafe {
            canonical_stream_input(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        };
        let board_verifier_session_capability = unsafe {
            canonical_stream_input(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        };
        let checkpoint_lineage_identifier: [u8;
            AGGREGATE_THRESHOLD_SHARE_CHECKPOINT_LINEAGE_BYTE_LENGTH] = unsafe {
            slice::from_raw_parts(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }
        .try_into()
        .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?;
        prepare_aggregate_threshold_share_generation(
            selected_suite_handle,
            recipient_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability,
            verified_reservation_handle,
            board_verifier_session_handle,
            board_verifier_session_capability,
            setup_intent_object_handle,
            checkpoint_lineage_identifier,
            generation_mode,
        )
    })();
    match result {
        Ok((adapter_handle, board_binding_source_handle)) => {
            unsafe {
                board_binding_source_handle_output_pointer.write(board_binding_source_handle);
                write_u32_if_present(status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe {
                write_u32_if_present(
                    status_pointer,
                    aggregate_threshold_share_runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// Retains a fresh aggregate-threshold-share common-proof generation adapter
/// from the browser-owned recipient authority. The exact statement, all 260
/// source roots, all 26 aggregate roots, trace rows, and proof coins remain in
/// Rust and are bound to the authenticated action attempt.
///
/// # Safety
///
/// Each capability pointer must name its declared readable range. The
/// checkpoint pointer must name exactly 32 readable bytes. The board-binding
/// output pointer must name one writable `u32`; a non-null status pointer must
/// do the same.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_aggregate_threshold_share_prepare_generation(
    selected_suite_handle: u32,
    recipient_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    board_binding_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_aggregate_threshold_share_generation_from_ffi_inputs(
            selected_suite_handle,
            recipient_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            setup_intent_object_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            board_binding_source_handle_output_pointer,
            status_pointer,
            AggregateThresholdShareGenerationMode::Fresh,
        )
    }
}

/// Retains a resumable aggregate-threshold-share generation adapter. The
/// generic proof runtime can activate it only after authenticating checkpoint
/// bytes against the exact fresh attempt and compiled checkpoint schedule.
///
/// # Safety
///
/// Each capability pointer must name its declared readable range. The
/// checkpoint pointer must name exactly 32 readable bytes. The board-binding
/// output pointer must name one writable `u32`; a non-null status pointer must
/// do the same.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_aggregate_threshold_share_prepare_resumed_generation(
    selected_suite_handle: u32,
    recipient_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    board_binding_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_aggregate_threshold_share_generation_from_ffi_inputs(
            selected_suite_handle,
            recipient_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            setup_intent_object_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            board_binding_source_handle_output_pointer,
            status_pointer,
            AggregateThresholdShareGenerationMode::Resume,
        )
    }
}

/// Consumes a generated aggregate-threshold-share proof only after the exact
/// verified private-share-acceptance board carrier reproduces the generated
/// canonical statement, roots, proof descriptor, and application binding.
///
/// # Safety
///
/// The board capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_aggregate_threshold_share_bind_generated_proof_to_board(
    generated_common_proof_handle: u32,
    board_binding_source_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    private_share_acceptance_object_handle: u32,
) -> u32 {
    let board_verifier_session_capability = unsafe {
        canonical_stream_input(
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
        )
    };
    bind_generated_aggregate_threshold_share_proof_to_board(
        generated_common_proof_handle,
        board_binding_source_handle,
        board_verifier_session_handle,
        board_verifier_session_capability,
        private_share_acceptance_object_handle,
    )
    .map_or_else(aggregate_threshold_share_runtime_error_status, |()| 0)
}

/// Permanently discards a generation board-binding source after its common
/// prover adapter is cancelled or its result can no longer be trusted.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_aggregate_threshold_share_discard_generation_board_binding_source(
    board_binding_source_handle: u32,
) -> u32 {
    discard_aggregate_threshold_share_generation_board_binding_source(board_binding_source_handle)
        .map_or_else(aggregate_threshold_share_runtime_error_status, |()| 0)
}

/// Opens verification for one roster participant's exact aggregate-threshold
/// board carrier and retains a one-shot terminal source. The returned generic
/// adapter can verify only the board-bound statement and proof descriptor.
///
/// # Safety
///
/// The board capability pointer must name its declared readable range. The
/// terminal-source output pointer must name one writable `u32`; a non-null
/// status pointer must do the same.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_aggregate_threshold_share_prepare_verification(
    selected_suite_handle: u32,
    recipient_authority_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    private_share_acceptance_object_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result: Result<(u32, u32), AggregateThresholdShareRuntimeError> = (|| {
        if terminal_source_handle_output_pointer.is_null() {
            return Err(AggregateThresholdShareRuntimeError::InvalidInput);
        }
        let board_verifier_session_capability = unsafe {
            canonical_stream_input(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        };
        prepare_aggregate_threshold_share_verification(
            selected_suite_handle,
            recipient_authority_handle,
            board_verifier_session_handle,
            board_verifier_session_capability,
            private_share_acceptance_object_handle,
        )
    })();
    match result {
        Ok((adapter_handle, terminal_source_handle)) => {
            unsafe {
                terminal_source_handle_output_pointer.write(terminal_source_handle);
                write_u32_if_present(status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe {
                write_u32_if_present(
                    status_pointer,
                    aggregate_threshold_share_runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// Consumes one positive generic proof capability into the exact participant
/// terminal slot. It returns one only when this was the tenth distinct roster
/// terminal and the recipient authority transitioned to its completed
/// accepted-setup handoff; otherwise it returns zero with status zero.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_aggregate_threshold_share_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match finish_aggregate_threshold_share_verification(
        verified_common_proof_handle,
        terminal_source_handle,
    ) {
        Ok(qualification_complete) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            u32::from(qualification_complete)
        }
        Err(error) => {
            unsafe {
                write_u32_if_present(
                    status_pointer,
                    aggregate_threshold_share_runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// Permanently discards an aggregate-threshold verification terminal source
/// after its generic verifier is cancelled or reset.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_aggregate_threshold_share_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    discard_aggregate_threshold_share_verification_terminal_source(terminal_source_handle)
        .map_or_else(aggregate_threshold_share_runtime_error_status, |()| 0)
}

/// Permanently discards an active or completed aggregate-threshold-share
/// recipient authority. Its handle is stale after this call.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_aggregate_threshold_share_discard_recipient_authority(
    recipient_authority_handle: u32,
) -> u32 {
    discard_aggregate_threshold_share_recipient_authority(recipient_authority_handle)
        .map_or_else(aggregate_threshold_share_runtime_error_status, |()| 0)
}

unsafe fn write_canonical_stream_begin(
    result: Result<CanonicalStreamRuntimeBegin, u32>,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
) -> u32 {
    match result {
        Ok(begin) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
                write_u32_if_present(total_byte_length_pointer, begin.total_byte_length);
            }
            begin.handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
                write_u32_if_present(total_byte_length_pointer, 0);
            }
            0
        }
    }
}

/// Builds one browser-owned setup-generation authority from live selected-suite,
/// canonical-board, action-randomness, and state-verifier capabilities. The
/// ordered board handles must contain setup intents, commitments, and reveals,
/// each in roster order. No setup witness bytes enter this boundary.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. The ordered
/// object-handle range contains little-endian `u32` handles. A non-null status
/// pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_authority_begin(
    selected_suite_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    ordered_public_randomness_object_handles_pointer: *const u8,
    ordered_public_randomness_object_handles_byte_length: usize,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let board_verifier_session_capability = unsafe {
        canonical_stream_input(
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
        )
    };
    let ordered_public_randomness_object_handle_bytes = unsafe {
        canonical_stream_input(
            ordered_public_randomness_object_handles_pointer,
            ordered_public_randomness_object_handles_byte_length,
        )
    };
    let Some(ordered_public_randomness_object_handles) =
        decode_u32_list(ordered_public_randomness_object_handle_bytes)
    else {
        unsafe {
            write_u32_if_present(
                status_pointer,
                u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code()),
            )
        };
        return 0;
    };
    let state_verifier_session_capability = unsafe {
        canonical_stream_input(
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
        )
    };
    match begin_setup_generation_authority(
        selected_suite_handle,
        board_verifier_session_handle,
        board_verifier_session_capability,
        &ordered_public_randomness_object_handles,
        action_randomness_handle,
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    ) {
        Ok(handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            handle.identifier()
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Returns the exact raw full-Q public-key-share body length before its source
/// is opened. The body is the limb-major, coefficient-major little-endian
/// `u64` payload consumed by the selected collective-key corpus.
///
/// # Safety
///
/// A non-null status pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_public_key_share_body_byte_length(
    authority_handle: u32,
    status_pointer: *mut u32,
) -> u64 {
    match setup_generation_public_key_share_body_byte_length_by_identifier(authority_handle) {
        Ok(byte_length) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Opens the authority-owned raw public-key-share body exactly once without
/// copying its retained coefficient matrix.
///
/// # Safety
///
/// A non-null status pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_public_key_share_body_open(
    authority_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match open_setup_generation_public_key_share_body_by_identifier(authority_handle) {
        Ok(source_handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            source_handle
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Returns the exact body length bound to an opened public-key-share source.
///
/// # Safety
///
/// A non-null status pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_public_key_share_source_byte_length(
    source_handle: u32,
    status_pointer: *mut u32,
) -> u64 {
    match setup_generation_public_key_share_source_byte_length_by_identifier(source_handle) {
        Ok(byte_length) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Writes the next exact sequential public-key-share body range directly into
/// caller-owned WASM memory. The source removes itself after its final byte.
///
/// # Safety
///
/// The output pointer must name its declared writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_public_key_share_body_read(
    source_handle: u32,
    expected_offset: u64,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    if output_pointer.is_null()
        || output_byte_length == 0
        || output_byte_length > foundation::FOUNDATION_PROFILE.stream_chunk_byte_length
    {
        let _ = cancel_setup_generation_public_key_share_body_by_identifier(source_handle);
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
    read_setup_generation_public_key_share_body_by_identifier(
        source_handle,
        expected_offset,
        output,
    )
    .map_or_else(|status| status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_setup_generation_public_key_share_body_cancel(
    source_handle: u32,
) -> u32 {
    cancel_setup_generation_public_key_share_body_by_identifier(source_handle)
        .map_or_else(|status| status, |()| 0)
}

/// Returns the exact canonical 0x2107 byte length before the recipient slot is
/// opened and consumed.
///
/// # Safety
///
/// A non-null status pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_recipient_vss_payload_byte_length(
    authority_handle: u32,
    recipient_roster_position: u16,
    status_pointer: *mut u32,
) -> u64 {
    match setup_generation_recipient_payload_byte_length(
        authority_handle,
        recipient_roster_position,
    ) {
        Ok(byte_length) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Transfers one recipient payload out of its authority exactly once and into
/// an opaque sequential source.
///
/// # Safety
///
/// A non-null status pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_recipient_vss_payload_open(
    authority_handle: u32,
    recipient_roster_position: u16,
    status_pointer: *mut u32,
) -> u32 {
    match open_setup_generation_recipient_payload(authority_handle, recipient_roster_position) {
        Ok(source_handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            source_handle
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Returns the exact byte length retained by one opened recipient source.
///
/// # Safety
///
/// A non-null status pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_recipient_vss_payload_source_byte_length(
    source_handle: u32,
    status_pointer: *mut u32,
) -> u64 {
    match setup_generation_recipient_payload_source_byte_length(source_handle) {
        Ok(byte_length) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Returns the roster position bound to one opened recipient source.
///
/// # Safety
///
/// A non-null status pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_recipient_vss_payload_source_recipient_roster_position(
    source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match setup_generation_recipient_payload_source_recipient_roster_position(source_handle) {
        Ok(recipient_roster_position) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            u32::from(recipient_roster_position)
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Copies the next exact sequential recipient-payload range into caller-owned
/// WASM memory. The source automatically removes itself after its final byte.
///
/// # Safety
///
/// The output pointer must name its declared writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_setup_generation_recipient_vss_payload_read(
    source_handle: u32,
    expected_offset: u64,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    if output_pointer.is_null() || output_byte_length == 0 {
        let _ = cancel_setup_generation_recipient_payload(source_handle);
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
    read_setup_generation_recipient_payload(source_handle, expected_offset, output)
        .map_or_else(|status| status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_setup_generation_recipient_vss_payload_cancel(
    source_handle: u32,
) -> u32 {
    cancel_setup_generation_recipient_payload(source_handle).map_or_else(|status| status, |()| 0)
}

/// Releases an authority and zeroizes every unopened payload and any source
/// opened from it.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_setup_generation_authority_release(authority_handle: u32) -> u32 {
    release_setup_generation_authority_by_identifier(authority_handle)
        .map_or_else(|status| status, |()| 0)
}

/// Begins the sole active canonical-stream writer in this WASM instance.
///
/// # Safety
///
/// Every non-null output pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_begin_writer(
    stream_domain_code: u32,
    total_byte_length: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = begin_canonical_stream_writer(stream_domain_code, total_byte_length);
    unsafe { write_canonical_stream_begin(result, status_pointer, ptr::null_mut()) }
}

/// Begins the sole active canonical-stream verifier in this WASM instance.
///
/// # Safety
///
/// Input pointers must name their declared readable byte ranges. Every
/// non-null output pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_begin_verifier(
    stream_domain_code: u32,
    descriptor_pointer: *const u8,
    descriptor_length: usize,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
) -> u32 {
    let descriptor = unsafe { canonical_stream_input(descriptor_pointer, descriptor_length) };
    let result = begin_canonical_stream_verifier(stream_domain_code, descriptor);
    unsafe { write_canonical_stream_begin(result, status_pointer, total_byte_length_pointer) }
}

/// Absorbs one exact canonical-stream chunk directly from WASM memory.
///
/// # Safety
///
/// Input pointers must name their declared readable byte ranges.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_absorb_chunk(
    handle: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_length: usize,
) -> u32 {
    let chunk = unsafe { canonical_stream_input(chunk_pointer, chunk_length) };
    absorb_canonical_stream_chunk(handle, chunk_index, chunk).map_or_else(|status| status, |()| 0)
}

/// Finishes a writer and returns its bounded canonical descriptor bytes.
///
/// # Safety
///
/// Every non-null output pointer must point to the corresponding writable value in WASM
/// memory. The returned allocation must be released with
/// `sealed_lattice_deallocate` and the reported length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_finish_writer(
    handle: u32,
    status_pointer: *mut u32,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    match finish_canonical_stream_writer(handle) {
        Ok(descriptor_bytes) => {
            let descriptor_byte_length = descriptor_bytes.len();
            unsafe {
                write_u32_if_present(status_pointer, 0);
                write_usize_if_present(output_length_pointer, descriptor_byte_length);
            }
            leak_bytes(descriptor_bytes)
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
                write_usize_if_present(output_length_pointer, 0);
            }
            ptr::null_mut()
        }
    }
}

/// Finishes and removes the active canonical-stream verifier.
///
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_canonical_stream_finish_verifier(handle: u32) -> u32 {
    finish_canonical_stream_verifier(handle).map_or_else(|status| status, |()| 0)
}

/// Removes the active canonical-stream session. Repeated cancellation after a
/// successful removal is a no-op.
///
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_canonical_stream_cancel(handle: u32) -> u32 {
    cancel_canonical_stream(handle).map_or_else(|status| status, |()| 0)
}

/// Begins incremental AES-256-GCM encryption for one authenticated mailbox.
///
/// # Safety
///
/// Input pointers must name their declared readable ranges. `status_pointer`
/// must be null or point to one writable `u32`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_mailbox_gcm_begin_encryptor(
    key_pointer: *const u8,
    key_length: usize,
    nonce_pointer: *const u8,
    nonce_length: usize,
    associated_data_pointer: *const u8,
    associated_data_length: usize,
    total_byte_length: u32,
    status_pointer: *mut u32,
) -> u32 {
    if key_length != foundation::MAILBOX_GCM_KEY_BYTE_LENGTH
        || nonce_length != foundation::MAILBOX_GCM_NONCE_BYTE_LENGTH
        || key_pointer.is_null()
        || nonce_pointer.is_null()
    {
        unsafe {
            write_u32_if_present(
                status_pointer,
                u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code()),
            )
        };
        return 0;
    }
    let key = unsafe { fixed_bytes(key_pointer, key_length) };
    let nonce = unsafe { fixed_bytes(nonce_pointer, nonce_length) };
    let associated_data =
        unsafe { canonical_stream_input(associated_data_pointer, associated_data_length) };
    match begin_mailbox_gcm_encryptor(key, nonce, associated_data, total_byte_length) {
        Ok(handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            handle
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Begins incremental authentication for one mailbox ciphertext. Successful
/// completion changes this same opaque handle into a decryptor.
///
/// # Safety
///
/// Input pointers must name their declared readable ranges. `status_pointer`
/// must be null or point to one writable `u32`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_mailbox_gcm_begin_verifier(
    key_pointer: *const u8,
    key_length: usize,
    nonce_pointer: *const u8,
    nonce_length: usize,
    associated_data_pointer: *const u8,
    associated_data_length: usize,
    total_byte_length: u32,
    status_pointer: *mut u32,
) -> u32 {
    if key_length != foundation::MAILBOX_GCM_KEY_BYTE_LENGTH
        || nonce_length != foundation::MAILBOX_GCM_NONCE_BYTE_LENGTH
        || key_pointer.is_null()
        || nonce_pointer.is_null()
    {
        unsafe {
            write_u32_if_present(
                status_pointer,
                u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code()),
            )
        };
        return 0;
    }
    let key = unsafe { fixed_bytes(key_pointer, key_length) };
    let nonce = unsafe { fixed_bytes(nonce_pointer, nonce_length) };
    let associated_data =
        unsafe { canonical_stream_input(associated_data_pointer, associated_data_length) };
    match begin_mailbox_gcm_verifier(key, nonce, associated_data, total_byte_length) {
        Ok(handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            handle
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Encrypts one mailbox plaintext fragment in place.
///
/// # Safety
///
/// `chunk_pointer` must name its declared writable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_mailbox_gcm_encrypt_chunk(
    handle: u32,
    chunk_pointer: *mut u8,
    chunk_length: usize,
) -> u32 {
    if chunk_pointer.is_null() || chunk_length == 0 {
        let _ = cancel_mailbox_gcm(handle);
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let chunk = unsafe { canonical_stream_input_mut(chunk_pointer, chunk_length) };
    encrypt_mailbox_gcm_chunk(handle, chunk).map_or_else(|status| status, |()| 0)
}

/// Authenticates one staged mailbox ciphertext fragment without decrypting it.
///
/// # Safety
///
/// `chunk_pointer` must name its declared readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_mailbox_gcm_authenticate_chunk(
    handle: u32,
    chunk_pointer: *const u8,
    chunk_length: usize,
) -> u32 {
    if chunk_pointer.is_null() || chunk_length == 0 {
        let _ = cancel_mailbox_gcm(handle);
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let chunk = unsafe { canonical_stream_input(chunk_pointer, chunk_length) };
    authenticate_mailbox_gcm_chunk(handle, chunk).map_or_else(|status| status, |()| 0)
}

/// Finishes mailbox encryption and copies the exact 16-byte GCM tag.
///
/// # Safety
///
/// `tag_pointer` must name a writable range of exactly `tag_length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_mailbox_gcm_finish_encryptor(
    handle: u32,
    tag_pointer: *mut u8,
    tag_length: usize,
) -> u32 {
    if tag_pointer.is_null() || tag_length != foundation::MAILBOX_GCM_TAG_BYTE_LENGTH {
        let _ = cancel_mailbox_gcm(handle);
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    match finish_mailbox_gcm_encryptor(handle) {
        Ok(mut tag) => {
            unsafe {
                slice::from_raw_parts_mut(tag_pointer, tag_length).copy_from_slice(&tag);
            }
            tag.fill(0);
            0
        }
        Err(status) => status,
    }
}

/// Verifies the complete ciphertext tag before changing the handle into a
/// decryptor. No plaintext operation is available before this succeeds.
///
/// # Safety
///
/// `tag_pointer` must name a readable range of exactly `tag_length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_mailbox_gcm_finish_authentication(
    handle: u32,
    tag_pointer: *const u8,
    tag_length: usize,
) -> u32 {
    if tag_pointer.is_null() || tag_length != foundation::MAILBOX_GCM_TAG_BYTE_LENGTH {
        let _ = cancel_mailbox_gcm(handle);
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let tag = unsafe { fixed_bytes(tag_pointer, tag_length) };
    finish_mailbox_gcm_authentication(handle, &tag).map_or_else(|status| status, |()| 0)
}

/// Decrypts one already-authenticated staged ciphertext fragment in place.
///
/// # Safety
///
/// `chunk_pointer` must name its declared writable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_mailbox_gcm_decrypt_chunk(
    handle: u32,
    chunk_pointer: *mut u8,
    chunk_length: usize,
) -> u32 {
    if chunk_pointer.is_null() || chunk_length == 0 {
        let _ = cancel_mailbox_gcm(handle);
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let chunk = unsafe { canonical_stream_input_mut(chunk_pointer, chunk_length) };
    decrypt_mailbox_gcm_chunk(handle, chunk).map_or_else(|status| status, |()| 0)
}

/// Finishes and removes an authenticated mailbox decryptor.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_mailbox_gcm_finish_decryptor(handle: u32) -> u32 {
    finish_mailbox_gcm_decryptor(handle).map_or_else(|status| status, |()| 0)
}

/// Removes the active mailbox GCM session and zeroizes its secret state.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_mailbox_gcm_cancel(handle: u32) -> u32 {
    cancel_mailbox_gcm(handle).map_or_else(|status| status, |()| 0)
}

/// Opens the sole finality-verifier session in this WASM instance. The session
/// can consume only an evaluator replay handle retained by the evaluator
/// verifier; there is no raw replay registration export.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_finality_verifier_begin(
    configuration_pointer: *const u8,
    configuration_length: usize,
    capability_pointer: *const u8,
    capability_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let configuration =
        unsafe { canonical_stream_input(configuration_pointer, configuration_length) };
    let capability = unsafe {
        fixed_bytes::<FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
            capability_pointer,
            capability_length,
        )
    };
    match begin_finality_verifier_session(configuration, capability) {
        Ok(handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            handle
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Verifies finality from live evaluator and canonical-board capabilities.
/// Carrier and certificate bytes are decoded as untrusted input;
/// their claimed provenance is accepted only when the supplied live handles
/// resolve to the exact verifier-owned values.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_finality_verifier_verify(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_evaluator_replay_handle: u32,
    board_session_handle: u32,
    board_capability_pointer: *const u8,
    board_capability_length: usize,
    verified_finality_object_handles_pointer: *const u8,
    verified_finality_object_handles_length: usize,
    canonical_statement_pointer: *const u8,
    canonical_statement_length: usize,
    canonical_certificate_pointer: *const u8,
    canonical_certificate_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let board_capability =
        unsafe { canonical_stream_input(board_capability_pointer, board_capability_length) };
    let verified_finality_object_handle_bytes = unsafe {
        canonical_stream_input(
            verified_finality_object_handles_pointer,
            verified_finality_object_handles_length,
        )
    };
    let canonical_statement =
        unsafe { canonical_stream_input(canonical_statement_pointer, canonical_statement_length) };
    let canonical_certificate = unsafe {
        canonical_stream_input(canonical_certificate_pointer, canonical_certificate_length)
    };
    let Some(verified_finality_object_handles) =
        decode_u32_list(verified_finality_object_handle_bytes)
    else {
        unsafe {
            write_u32_if_present(
                status_pointer,
                foundation::RefusalReason::WrongTypeOrLength.canonical_code() as u32,
            )
        };
        return 0;
    };
    match verify_finality(
        session_handle,
        capability,
        verified_evaluator_replay_handle,
        board_session_handle,
        board_capability,
        &verified_finality_object_handles,
        canonical_statement,
        canonical_certificate,
    ) {
        Ok(handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            handle
        }
        Err(status) => {
            unsafe { write_u32_if_present(status_pointer, status) };
            0
        }
    }
}

/// Copies verifier-derived public finality metadata for a live capability.
///
/// # Safety
///
/// Every pointer must name its declared readable or writable range.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_finality_verifier_describe(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_finality_handle: u32,
    output_pointer: *mut u8,
    output_length: usize,
) -> u32 {
    if output_pointer.is_null() || output_length != VERIFIED_FINALITY_DESCRIPTION_BYTE_LENGTH {
        return foundation::RefusalReason::WrongTypeOrLength.canonical_code() as u32;
    }
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    match describe_verified_finality(session_handle, capability, verified_finality_handle) {
        Ok(description) if description.len() == output_length => {
            unsafe {
                ptr::copy_nonoverlapping(description.as_ptr(), output_pointer, output_length)
            };
            0
        }
        Ok(_) => foundation::RefusalReason::WrongTypeOrLength.canonical_code() as u32,
        Err(status) => status,
    }
}

/// Releases one finality capability. Released handles are permanently stale.
///
/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_finality_verifier_release(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_finality_handle: u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    release_verified_finality(session_handle, capability, verified_finality_handle)
        .map_or_else(|status| status, |()| 0)
}

/// Cancels the finality-verifier session and drops every retained capability.
///
/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_finality_verifier_cancel(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    cancel_finality_verifier_session(session_handle, capability)
        .map_or_else(|status| status, |()| 0)
}

/// # Safety
///
/// Every input pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_begin(
    configuration_pointer: *const u8,
    configuration_length: usize,
    capability_pointer: *const u8,
    capability_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let configuration =
        unsafe { canonical_stream_input(configuration_pointer, configuration_length) };
    let capability = unsafe { state_verifier_capability(capability_pointer, capability_length) };
    match begin_state_verifier_session(configuration, capability) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Verifies one reservation intent before witness certification and returns an
/// opaque lock-candidate handle. The handle contains only verifier-recomputed
/// state binding material and cannot authorize an operation output.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_prepare_reservation(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    subject_participant_id_pointer: *const u8,
    subject_participant_id_length: usize,
    capability_kind_code: u32,
    expected_authorization_hash_pointer: *const u8,
    expected_authorization_hash_length: usize,
    canonical_reservation_intent_carrier_pointer: *const u8,
    canonical_reservation_intent_carrier_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let subject_participant_id = unsafe {
        canonical_stream_input(
            subject_participant_id_pointer,
            subject_participant_id_length,
        )
    };
    let expected_authorization_hash = unsafe {
        canonical_stream_input(
            expected_authorization_hash_pointer,
            expected_authorization_hash_length,
        )
    };
    let canonical_reservation_intent_carrier = unsafe {
        canonical_stream_input(
            canonical_reservation_intent_carrier_pointer,
            canonical_reservation_intent_carrier_length,
        )
    };
    match verify_state_reservation_intent(
        session_handle,
        capability,
        subject_participant_id,
        capability_kind_code,
        expected_authorization_hash,
        canonical_reservation_intent_carrier,
    ) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Verifies a state reservation and returns only an opaque runtime handle.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_verify_reservation(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    subject_participant_id_pointer: *const u8,
    subject_participant_id_length: usize,
    capability_kind_code: u32,
    expected_authorization_hash_pointer: *const u8,
    expected_authorization_hash_length: usize,
    canonical_reservation_intent_carrier_pointer: *const u8,
    canonical_reservation_intent_carrier_length: usize,
    canonical_state_certificate_pointer: *const u8,
    canonical_state_certificate_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let subject_participant_id = unsafe {
        canonical_stream_input(
            subject_participant_id_pointer,
            subject_participant_id_length,
        )
    };
    let expected_authorization_hash = unsafe {
        canonical_stream_input(
            expected_authorization_hash_pointer,
            expected_authorization_hash_length,
        )
    };
    let canonical_reservation_intent_carrier = unsafe {
        canonical_stream_input(
            canonical_reservation_intent_carrier_pointer,
            canonical_reservation_intent_carrier_length,
        )
    };
    let canonical_state_certificate = unsafe {
        canonical_stream_input(
            canonical_state_certificate_pointer,
            canonical_state_certificate_length,
        )
    };
    match verify_state_reservation(
        session_handle,
        capability,
        subject_participant_id,
        capability_kind_code,
        expected_authorization_hash,
        canonical_reservation_intent_carrier,
        canonical_state_certificate,
    ) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Atomically consumes a completed generic canonical-stream verifier and verifies
/// the state output against its reservation. Exact-output bytes cross the WASM
/// boundary only through bounded stream chunks and are never returned.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_finish_output(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    stream_handle: u32,
    verified_reservation_handle: u32,
    canonical_output_intent_carrier_pointer: *const u8,
    canonical_output_intent_carrier_length: usize,
    canonical_state_certificate_pointer: *const u8,
    canonical_state_certificate_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let canonical_output_intent_carrier = unsafe {
        canonical_stream_input(
            canonical_output_intent_carrier_pointer,
            canonical_output_intent_carrier_length,
        )
    };
    let canonical_state_certificate = unsafe {
        canonical_stream_input(
            canonical_state_certificate_pointer,
            canonical_state_certificate_length,
        )
    };
    match finish_state_output_verification(
        session_handle,
        capability,
        stream_handle,
        verified_reservation_handle,
        canonical_output_intent_carrier,
        canonical_state_certificate,
    ) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Atomically consumes a complete exact-output stream and verifies its output
/// intent before witness certification. The returned handle remains a
/// lock-candidate and does not carry a certified output authorization.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_prepare_output(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    stream_handle: u32,
    verified_reservation_handle: u32,
    canonical_output_intent_carrier_pointer: *const u8,
    canonical_output_intent_carrier_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let canonical_output_intent_carrier = unsafe {
        canonical_stream_input(
            canonical_output_intent_carrier_pointer,
            canonical_output_intent_carrier_length,
        )
    };
    match finish_state_output_intent_verification(
        session_handle,
        capability,
        stream_handle,
        verified_reservation_handle,
        canonical_output_intent_carrier,
    ) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Verifies a witness certificate for one prepared state intent and returns
/// the corresponding opaque certified capability handle.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_certify_intent(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_intent_handle: u32,
    canonical_state_certificate_pointer: *const u8,
    canonical_state_certificate_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let canonical_state_certificate = unsafe {
        canonical_stream_input(
            canonical_state_certificate_pointer,
            canonical_state_certificate_length,
        )
    };
    match certify_verified_state_intent(
        session_handle,
        capability,
        verified_intent_handle,
        canonical_state_certificate,
    ) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Verifies adversarially ordered canonical witness-vote carriers for one
/// prepared intent. Transport metadata is not part of this byte boundary.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_certify_unordered_votes(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_intent_handle: u32,
    framed_canonical_vote_carriers_pointer: *const u8,
    framed_canonical_vote_carriers_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let framed_canonical_vote_carriers = unsafe {
        canonical_stream_input(
            framed_canonical_vote_carriers_pointer,
            framed_canonical_vote_carriers_length,
        )
    };
    match certify_verified_state_intent_from_unordered_vote_carriers(
        session_handle,
        capability,
        verified_intent_handle,
        framed_canonical_vote_carriers,
    ) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Copies the verifier-derived durable state binding for an opaque prepared or
/// certified state handle. The output is runtime metadata, not a protocol
/// artifact or producer-provided verdict.
///
/// # Safety
///
/// The capability pointer must name its readable range. The output pointer
/// must name exactly `STATE_DURABLE_BINDING_BYTE_LENGTH` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_describe(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_object_handle: u32,
    output_pointer: *mut u8,
    output_length: usize,
) -> u32 {
    if output_pointer.is_null() || output_length != STATE_DURABLE_BINDING_BYTE_LENGTH {
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    match describe_verified_state_object(session_handle, capability, verified_object_handle) {
        Ok(binding) => {
            unsafe {
                ptr::copy_nonoverlapping(binding.as_ptr(), output_pointer, binding.len());
            }
            0
        }
        Err(status) => {
            unsafe {
                ptr::write_bytes(output_pointer, 0, STATE_DURABLE_BINDING_BYTE_LENGTH);
            }
            status
        }
    }
}

/// Releases one verified-object handle. Released handles are permanently stale.
///
/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_release(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_object_handle: u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    release_verified_state_object(session_handle, capability, verified_object_handle)
        .map_or_else(|status| status, |()| 0)
}

/// Cancels the state-verifier session and drops every retained verified object.
///
/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_cancel(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    cancel_state_verifier_session(session_handle, capability).map_or_else(|status| status, |()| 0)
}

/// Runs one bounded state-intent producer operation against the active state
/// verifier and action-randomness registries.
///
/// Candidate, verified-intent, and reservation handles remain meaningful only
/// in this WASM instance. Returned bytes contain only fixed signature messages
/// or canonical public carriers and certificates. The returned allocation must
/// be released with `sealed_lattice_deallocate` and the reported length.
///
/// # Safety
///
/// `input_pointer` must name its declared readable byte range. Every non-null
/// output pointer must point to the corresponding writable value in WASM
/// memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_state_producer_command(
    command: u32,
    input_pointer: *const u8,
    input_length: usize,
    status_pointer: *mut u32,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = unsafe { canonical_stream_input(input_pointer, input_length) };
    match run_state_producer_command(command, input) {
        Ok(output) => {
            let output_length = output.len();
            unsafe {
                write_u32_if_present(status_pointer, 0);
                write_usize_if_present(output_length_pointer, output_length);
            }
            if output.is_empty() {
                ptr::null_mut()
            } else {
                leak_bytes(output)
            }
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
                write_usize_if_present(output_length_pointer, 0);
            }
            ptr::null_mut()
        }
    }
}

/// Runs one bounded command against the opaque local-storage-root registry.
///
/// Root handles and their capabilities are meaningful only inside this WASM
/// instance. The returned allocation contains command output, never an active
/// capability, and must be released with `sealed_lattice_deallocate` and the
/// reported length.
///
/// # Safety
///
/// `input_pointer` must name its declared readable byte range. Every non-null
/// output pointer must point to the corresponding writable value in WASM
/// memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_local_storage_root_command(
    command: u32,
    input_pointer: *const u8,
    input_length: usize,
    status_pointer: *mut u32,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = unsafe { canonical_stream_input(input_pointer, input_length) };
    match run_local_storage_root_command(command, input) {
        Ok(output) => {
            let output_length = output.len();
            unsafe {
                write_u32_if_present(status_pointer, 0);
                write_usize_if_present(output_length_pointer, output_length);
            }
            if output.is_empty() {
                ptr::null_mut()
            } else {
                leak_bytes(output)
            }
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
                write_usize_if_present(output_length_pointer, 0);
            }
            ptr::null_mut()
        }
    }
}

/// Runs one closed operation against the opaque action-randomness registry.
///
/// Action roots and derived keys remain owned by the WASM instance. Command
/// output contains only the public commitment or the exact purpose-bound bytes
/// consumed by a closed browser-local cryptographic operation.
///
/// # Safety
///
/// `input_pointer` must name its declared readable byte range. Every non-null
/// output pointer must point to the corresponding writable value in WASM
/// memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_action_randomness_command(
    command: u32,
    input_pointer: *const u8,
    input_length: usize,
    status_pointer: *mut u32,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = unsafe { canonical_stream_input(input_pointer, input_length) };
    match run_action_randomness_command(command, input) {
        Ok(output) => {
            let output_length = output.len();
            unsafe {
                write_u32_if_present(status_pointer, 0);
                write_usize_if_present(output_length_pointer, output_length);
            }
            if output.is_empty() {
                ptr::null_mut()
            } else {
                leak_bytes(output)
            }
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
                write_usize_if_present(output_length_pointer, 0);
            }
            ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        sealed_lattice_allocate, sealed_lattice_deallocate,
        sealed_lattice_setup_generation_authority_begin,
        sealed_lattice_setup_generation_recipient_vss_payload_read,
        sealed_lattice_transcript_core_command_with_length,
    };
    use core::ptr;

    #[test]
    fn exported_allocations_deallocate_with_matching_layout() {
        let allocated = sealed_lattice_allocate(4);
        assert!(!allocated.is_null());
        unsafe {
            ptr::write_bytes(allocated, 0xaa, 4);
            sealed_lattice_deallocate(allocated, 4);
        }

        let mut response_length = 0_usize;
        let command = br#"{}"#;
        let response = unsafe {
            sealed_lattice_transcript_core_command_with_length(
                command.as_ptr(),
                command.len(),
                &mut response_length,
            )
        };
        assert!(!response.is_null());
        assert!(response_length > 0);
        unsafe {
            sealed_lattice_deallocate(response, response_length);
        }
    }

    #[test]
    fn setup_generation_authority_boundary_rejects_misaligned_handle_bytes() {
        let malformed_handle_bytes = [1_u8, 2, 3];
        let board_capability = [0_u8; 32];
        let state_capability = [0_u8; 32];
        let mut status = 0_u32;

        let authority_handle = unsafe {
            sealed_lattice_setup_generation_authority_begin(
                1,
                1,
                board_capability.as_ptr(),
                board_capability.len(),
                malformed_handle_bytes.as_ptr(),
                malformed_handle_bytes.len(),
                1,
                1,
                state_capability.as_ptr(),
                state_capability.len(),
                1,
                &mut status,
            )
        };

        assert_eq!(authority_handle, 0);
        assert_eq!(
            status,
            u32::from(crate::foundation::RefusalReason::WrongTypeOrLength.canonical_code())
        );
    }

    #[test]
    fn setup_generation_recipient_read_rejects_empty_output_and_cancels() {
        let status = unsafe {
            sealed_lattice_setup_generation_recipient_vss_payload_read(1, 0, ptr::null_mut(), 0)
        };

        assert_eq!(
            status,
            u32::from(crate::foundation::RefusalReason::WrongTypeOrLength.canonical_code())
        );
    }
}
