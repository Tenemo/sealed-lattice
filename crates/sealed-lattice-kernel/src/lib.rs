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
pub(crate) mod protocol_signatures;
pub(crate) mod transcript_core;

use core::{ptr, slice};
use std::vec::Vec;

use bgv::{
    absorb_bgv_canonical_stream_chunk, active_accepted_setup_proof_binding_session,
    begin_accepted_setup_canonical_stream, begin_accepted_setup_proof_binding_session,
    begin_bgv_canonical_material_reader, begin_bgv_canonical_stream,
    cancel_accepted_setup_proof_binding_session, cancel_bgv_canonical_material_reader,
    cancel_bgv_canonical_stream, finish_bgv_canonical_material_reader, finish_bgv_canonical_stream,
    read_bgv_canonical_material_chunk,
};
use foundation::{
    CanonicalStreamRuntimeBegin, STATE_DURABLE_BINDING_BYTE_LENGTH,
    STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, STATE_WITNESS_VOTE_CARRIER_BYTE_LENGTH,
    absorb_canonical_stream_chunk, authenticate_mailbox_gcm_chunk, begin_canonical_stream_verifier,
    begin_canonical_stream_writer, begin_mailbox_gcm_encryptor, begin_mailbox_gcm_verifier,
    begin_state_verifier_session, cancel_canonical_stream, cancel_mailbox_gcm,
    cancel_state_verifier_session, certify_verified_state_intent,
    certify_verified_state_intent_from_unordered_vote_carriers, decrypt_mailbox_gcm_chunk,
    describe_verified_state_object, encrypt_mailbox_gcm_chunk, finish_canonical_stream_verifier,
    finish_canonical_stream_writer, finish_mailbox_gcm_authentication,
    finish_mailbox_gcm_decryptor, finish_mailbox_gcm_encryptor,
    finish_state_output_intent_verification, finish_state_output_verification,
    finish_state_witness_vote, prepare_state_witness_vote, release_verified_state_object,
    run_local_storage_root_command, verify_state_recovery, verify_state_recovery_intent,
    verify_state_reservation, verify_state_reservation_intent,
};

use encoding::run_accepted_setup_command;
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

unsafe fn write_canonical_stream_begin(
    result: Result<CanonicalStreamRuntimeBegin, u32>,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
    chunk_count_pointer: *mut u32,
) -> u32 {
    match result {
        Ok(begin) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
                write_u32_if_present(total_byte_length_pointer, begin.total_byte_length);
                write_u32_if_present(chunk_count_pointer, begin.chunk_count);
            }
            begin.handle
        }
        Err(status) => {
            unsafe {
                write_u32_if_present(status_pointer, status);
                write_u32_if_present(total_byte_length_pointer, 0);
                write_u32_if_present(chunk_count_pointer, 0);
            }
            0
        }
    }
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
    chunk_count_pointer: *mut u32,
) -> u32 {
    let result = begin_canonical_stream_writer(stream_domain_code, total_byte_length);
    unsafe {
        write_canonical_stream_begin(result, status_pointer, ptr::null_mut(), chunk_count_pointer)
    }
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
    chunk_count_pointer: *mut u32,
) -> u32 {
    let descriptor = unsafe { canonical_stream_input(descriptor_pointer, descriptor_length) };
    let result = begin_canonical_stream_verifier(stream_domain_code, descriptor);
    unsafe {
        write_canonical_stream_begin(
            result,
            status_pointer,
            total_byte_length_pointer,
            chunk_count_pointer,
        )
    }
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

/// Begins a BGV large-object sink whose framing and integrity are owned by the
/// canonical stream verifier.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. Every non-null
/// output pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_bgv_canonical_stream_begin(
    family_code: u32,
    material_root_pointer: *const u8,
    material_root_length: usize,
    descriptor_pointer: *const u8,
    descriptor_length: usize,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
    chunk_count_pointer: *mut u32,
) -> u32 {
    let material_root =
        unsafe { canonical_stream_input(material_root_pointer, material_root_length) };
    let descriptor = unsafe { canonical_stream_input(descriptor_pointer, descriptor_length) };
    let result = begin_bgv_canonical_stream(family_code, material_root, descriptor);
    unsafe {
        write_canonical_stream_begin(
            result,
            status_pointer,
            total_byte_length_pointer,
            chunk_count_pointer,
        )
    }
}

/// Opens an opaque accepted-setup material-ownership session before any setup
/// source is streamed.
///
/// # Safety
///
/// `status_pointer` must be null or point to one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_session_begin(
    status_pointer: *mut u32,
) -> u32 {
    match begin_accepted_setup_proof_binding_session() {
        Ok(session_handle) => {
            unsafe { write_u32_if_present(status_pointer, 0) };
            session_handle
        }
        Err(_) => {
            unsafe {
                write_u32_if_present(
                    status_pointer,
                    foundation::CANONICAL_STREAM_RUNTIME_INVALID_SESSION,
                )
            };
            0
        }
    }
}

/// Begins an accepted-setup stream whose finished material remains owned by
/// the owning setup session until terminal verification or cancellation.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. Every non-null
/// output pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_canonical_stream_begin(
    setup_session_handle: u32,
    family_code: u32,
    material_root_pointer: *const u8,
    material_root_length: usize,
    descriptor_pointer: *const u8,
    descriptor_length: usize,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
    chunk_count_pointer: *mut u32,
) -> u32 {
    let accepted_setup_session =
        match active_accepted_setup_proof_binding_session(setup_session_handle) {
            Ok(session) => session,
            Err(_) => {
                unsafe {
                    write_canonical_stream_begin(
                        Err(foundation::CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
                        status_pointer,
                        total_byte_length_pointer,
                        chunk_count_pointer,
                    )
                };
                return 0;
            }
        };
    let material_root =
        unsafe { canonical_stream_input(material_root_pointer, material_root_length) };
    let descriptor = unsafe { canonical_stream_input(descriptor_pointer, descriptor_length) };
    let result = begin_accepted_setup_canonical_stream(
        family_code,
        material_root,
        descriptor,
        accepted_setup_session,
    );
    unsafe {
        write_canonical_stream_begin(
            result,
            status_pointer,
            total_byte_length_pointer,
            chunk_count_pointer,
        )
    }
}

/// Cancels an accepted-setup session and drains every material root it owns.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_session_cancel(session_handle: u32) -> u32 {
    cancel_accepted_setup_proof_binding_session(session_handle).map_or_else(
        |_| foundation::CANONICAL_STREAM_RUNTIME_INVALID_SESSION,
        |()| 0,
    )
}

/// Executes terminal accepted-setup verification under the already-open opaque
/// material session. The session handle is a direct ABI value, not a field of
/// the protocol request.
///
/// # Safety
///
/// Input pointers must name their declared readable ranges.
/// `output_length_pointer` must be null or point to one writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_command_with_length(
    pointer: *const u8,
    length: usize,
    session_handle: u32,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = unsafe { canonical_stream_input(pointer, length) };
    let output = run_accepted_setup_command(input, session_handle);
    // Terminal verification consumes the session on every ordinary outcome. If
    // parsing or command selection failed before dispatch, cancel the still-live
    // session so its reserved and finished roots are drained.
    let _ = cancel_accepted_setup_proof_binding_session(session_handle);
    let output_length = output.len();
    if !output_length_pointer.is_null() {
        unsafe { output_length_pointer.write(output_length) };
    }
    leak_bytes(output)
}

/// # Safety
///
/// Every input pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_bgv_canonical_stream_absorb_chunk(
    handle: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_length: usize,
) -> u32 {
    let chunk = unsafe { canonical_stream_input(chunk_pointer, chunk_length) };
    absorb_bgv_canonical_stream_chunk(handle, chunk_index, chunk)
        .map_or_else(|status| status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_bgv_canonical_stream_finish(handle: u32) -> u32 {
    finish_bgv_canonical_stream(handle).map_or_else(|status| status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_bgv_canonical_stream_cancel(handle: u32) -> u32 {
    cancel_bgv_canonical_stream(handle).map_or_else(|status| status, |()| 0)
}

/// # Safety
///
/// Every input pointer must name its declared readable range. Non-null output
/// pointers must each point to one writable value of the declared type.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_bgv_canonical_material_reader_begin(
    family_code: u32,
    material_root_pointer: *const u8,
    material_root_length: usize,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
    chunk_count_pointer: *mut u32,
) -> u32 {
    let material_root =
        unsafe { canonical_stream_input(material_root_pointer, material_root_length) };
    let result = begin_bgv_canonical_material_reader(family_code, material_root);
    unsafe {
        write_canonical_stream_begin(
            result,
            status_pointer,
            total_byte_length_pointer,
            chunk_count_pointer,
        )
    }
}

/// # Safety
///
/// The output pointer must name its declared writable range.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_bgv_canonical_material_reader_read_chunk(
    handle: u32,
    chunk_index: u32,
    output_pointer: *mut u8,
    output_length: usize,
) -> u32 {
    if output_pointer.is_null() {
        return foundation::RefusalReason::WrongTypeOrLength.canonical_code() as u32;
    }
    let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_length) };
    read_bgv_canonical_material_chunk(handle, chunk_index, output)
        .map_or_else(|status| status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_bgv_canonical_material_reader_finish(handle: u32) -> u32 {
    finish_bgv_canonical_material_reader(handle).map_or_else(|status| status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_bgv_canonical_material_reader_cancel(handle: u32) -> u32 {
    cancel_bgv_canonical_material_reader(handle).map_or_else(|status| status, |()| 0)
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
    predecessor_recovery_handle: u32,
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
        predecessor_recovery_handle,
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
    predecessor_recovery_handle: u32,
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
        predecessor_recovery_handle,
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

/// Verifies one recovery transition against optional verified predecessor and
/// preserved-intent handles and returns only an opaque recovery handle.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_verify_recovery(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    subject_participant_id_pointer: *const u8,
    subject_participant_id_length: usize,
    capability_kind_code: u32,
    predecessor_recovery_handle: u32,
    preserved_intent_handle: u32,
    canonical_recovery_transition_carrier_pointer: *const u8,
    canonical_recovery_transition_carrier_length: usize,
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
    let canonical_recovery_transition_carrier = unsafe {
        canonical_stream_input(
            canonical_recovery_transition_carrier_pointer,
            canonical_recovery_transition_carrier_length,
        )
    };
    let canonical_state_certificate = unsafe {
        canonical_stream_input(
            canonical_state_certificate_pointer,
            canonical_state_certificate_length,
        )
    };
    match verify_state_recovery(
        session_handle,
        capability,
        subject_participant_id,
        capability_kind_code,
        predecessor_recovery_handle,
        preserved_intent_handle,
        canonical_recovery_transition_carrier,
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

/// Verifies one recovery transition and its resolved preservation relation
/// before witness certification, returning an opaque lock-candidate handle.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_prepare_recovery(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    subject_participant_id_pointer: *const u8,
    subject_participant_id_length: usize,
    capability_kind_code: u32,
    predecessor_recovery_handle: u32,
    preserved_intent_handle: u32,
    canonical_recovery_transition_carrier_pointer: *const u8,
    canonical_recovery_transition_carrier_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let subject_participant_id = unsafe {
        canonical_stream_input(
            subject_participant_id_pointer,
            subject_participant_id_length,
        )
    };
    let canonical_recovery_transition_carrier = unsafe {
        canonical_stream_input(
            canonical_recovery_transition_carrier_pointer,
            canonical_recovery_transition_carrier_length,
        )
    };
    match verify_state_recovery_intent(
        session_handle,
        capability,
        subject_participant_id,
        capability_kind_code,
        predecessor_recovery_handle,
        preserved_intent_handle,
        canonical_recovery_transition_carrier,
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

/// Prepares the exact state-witness envelope and copies its 64-byte signature
/// message. The returned handle can be finished once with an ML-DSA-65
/// signature from the named roster witness.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. The message
/// output must name exactly 64 writable bytes. A non-null status pointer must
/// point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_prepare_witness_vote(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_intent_handle: u32,
    witness_participant_id_pointer: *const u8,
    witness_participant_id_length: usize,
    signature_message_output_pointer: *mut u8,
    signature_message_output_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    if signature_message_output_pointer.is_null()
        || signature_message_output_length != foundation::Hash512::BYTE_LENGTH
    {
        unsafe {
            write_u32_if_present(
                status_pointer,
                u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code()),
            );
        }
        return 0;
    }
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let witness_participant_id = unsafe {
        canonical_stream_input(
            witness_participant_id_pointer,
            witness_participant_id_length,
        )
    };
    let signature_message_output = unsafe {
        slice::from_raw_parts_mut(
            signature_message_output_pointer,
            signature_message_output_length,
        )
    };
    match prepare_state_witness_vote(
        session_handle,
        capability,
        verified_intent_handle,
        witness_participant_id,
        signature_message_output,
    ) {
        Ok(handle) => {
            unsafe {
                write_u32_if_present(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            signature_message_output.fill(0);
            unsafe {
                write_u32_if_present(status_pointer, status);
            }
            0
        }
    }
}

/// Finishes one prepared state-witness vote, verifies its signature, and
/// copies the exact canonical signed carrier.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. The carrier
/// output must name exactly `STATE_WITNESS_VOTE_CARRIER_BYTE_LENGTH` writable
/// bytes. A non-null status pointer must point to one writable `u32` in WASM
/// memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_finish_witness_vote(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    prepared_handle: u32,
    signature_pointer: *const u8,
    signature_length: usize,
    carrier_output_pointer: *mut u8,
    carrier_output_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    if carrier_output_pointer.is_null()
        || carrier_output_length != STATE_WITNESS_VOTE_CARRIER_BYTE_LENGTH
    {
        unsafe {
            write_u32_if_present(
                status_pointer,
                u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code()),
            );
        }
        return 0;
    }
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let signature = unsafe { canonical_stream_input(signature_pointer, signature_length) };
    match finish_state_witness_vote(session_handle, capability, prepared_handle, signature) {
        Ok(canonical_carrier) => {
            unsafe {
                ptr::copy_nonoverlapping(
                    canonical_carrier.as_ptr(),
                    carrier_output_pointer,
                    canonical_carrier.len(),
                );
                write_u32_if_present(status_pointer, 0);
            }
            1
        }
        Err(status) => {
            unsafe {
                ptr::write_bytes(
                    carrier_output_pointer,
                    0,
                    STATE_WITNESS_VOTE_CARRIER_BYTE_LENGTH,
                );
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

#[cfg(test)]
mod tests {
    use super::{
        sealed_lattice_allocate, sealed_lattice_deallocate,
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
}
