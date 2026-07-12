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
pub(crate) mod ring;
pub(crate) mod transcript_core;

use core::{ptr, slice};
use std::vec::Vec;

use bgv::{
    absorb_bgv_canonical_stream_chunk, begin_bgv_canonical_stream, cancel_bgv_canonical_stream,
    finish_bgv_canonical_stream,
};
use foundation::{
    CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH, CanonicalStreamRuntimeBegin,
    FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH, FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH,
    absorb_canonical_stream_chunk, begin_canonical_stream_verifier, begin_canonical_stream_writer,
    begin_foundation_board_session, cancel_canonical_stream, cancel_foundation_board_session,
    finish_canonical_stream_verifier, finish_canonical_stream_writer,
    ingest_foundation_board_carrier, require_complete_foundation_board_carrier_graph,
    run_local_storage_root_command, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
    begin_state_verifier_session, cancel_state_verifier_session, release_verified_state_object,
    verify_state_output, verify_state_recovery, verify_state_reservation,
};

pub use encoding::{roundtrip_bytes, run_transcript_core_command};

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
/// previously returned by `sealed_lattice_allocate` or
/// `sealed_lattice_roundtrip` or `sealed_lattice_transcript_core_command_with_length`
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_roundtrip(pointer: *const u8, length: usize) -> *mut u8 {
    if length == 0 {
        return ptr::null_mut();
    }
    if pointer.is_null() {
        return ptr::null_mut();
    }

    let input = unsafe { slice::from_raw_parts(pointer, length) };

    leak_bytes(roundtrip_bytes(input))
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

unsafe fn canonical_stream_capability(
    pointer: *const u8,
    length: usize,
) -> [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH] {
    if pointer.is_null() || length != CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH {
        return [0_u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
    }
    let mut capability = [0_u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
    capability.copy_from_slice(unsafe { slice::from_raw_parts(pointer, length) });
    capability
}

unsafe fn foundation_board_capability(
    pointer: *const u8,
    length: usize,
) -> [u8; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH] {
    if pointer.is_null() || length != FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH {
        return [0_u8; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH];
    }
    let mut capability = [0_u8; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH];
    capability.copy_from_slice(unsafe { slice::from_raw_parts(pointer, length) });
    capability
}

unsafe fn state_verifier_capability(
    pointer: *const u8,
    length: usize,
) -> [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH] {
    if pointer.is_null() || length != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return [0_u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH];
    }
    let mut capability = [0_u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH];
    capability.copy_from_slice(unsafe { slice::from_raw_parts(pointer, length) });
    capability
}

unsafe fn canonical_stream_input<'input>(pointer: *const u8, length: usize) -> &'input [u8] {
    if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
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
/// `capability_pointer` must point to `capability_length` readable bytes. Every
/// non-null output pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_begin_writer(
    stream_domain_code: u32,
    total_byte_length: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    status_pointer: *mut u32,
    chunk_count_pointer: *mut u32,
) -> u32 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    let result = begin_canonical_stream_writer(stream_domain_code, total_byte_length, capability);
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
    capability_pointer: *const u8,
    capability_length: usize,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
    chunk_count_pointer: *mut u32,
) -> u32 {
    let descriptor = unsafe { canonical_stream_input(descriptor_pointer, descriptor_length) };
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    let result = begin_canonical_stream_verifier(stream_domain_code, descriptor, capability);
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
    capability_pointer: *const u8,
    capability_length: usize,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    let chunk = unsafe { canonical_stream_input(chunk_pointer, chunk_length) };
    absorb_canonical_stream_chunk(handle, &capability, chunk_index, chunk)
        .map_or_else(|status| status, |()| 0)
}

/// Finishes a writer and returns its bounded canonical descriptor bytes.
///
/// # Safety
///
/// `capability_pointer` must name its declared readable range. Every non-null
/// output pointer must point to the corresponding writable value in WASM
/// memory. The returned allocation must be released with
/// `sealed_lattice_deallocate` and the reported length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_finish_writer(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    status_pointer: *mut u32,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    match finish_canonical_stream_writer(handle, &capability) {
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
/// # Safety
///
/// `capability_pointer` must name its declared readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_finish_verifier(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    finish_canonical_stream_verifier(handle, &capability).map_or_else(|status| status, |()| 0)
}

/// Removes the active canonical-stream session. Repeated cancellation after a
/// successful removal is a no-op.
///
/// # Safety
///
/// `capability_pointer` must name its declared readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_canonical_stream_cancel(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    cancel_canonical_stream(handle, &capability).map_or_else(|status| status, |()| 0)
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
    capability_pointer: *const u8,
    capability_length: usize,
    status_pointer: *mut u32,
    total_byte_length_pointer: *mut u32,
    chunk_count_pointer: *mut u32,
) -> u32 {
    let material_root =
        unsafe { canonical_stream_input(material_root_pointer, material_root_length) };
    let descriptor = unsafe { canonical_stream_input(descriptor_pointer, descriptor_length) };
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    let result = begin_bgv_canonical_stream(family_code, material_root, descriptor, capability);
    unsafe {
        write_canonical_stream_begin(
            result,
            status_pointer,
            total_byte_length_pointer,
            chunk_count_pointer,
        )
    }
}

/// Authenticates one exact canonical chunk before staging it in the selected
/// BGV semantic sink.
///
/// # Safety
///
/// Every input pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_bgv_canonical_stream_absorb_chunk(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    let chunk = unsafe { canonical_stream_input(chunk_pointer, chunk_length) };
    absorb_bgv_canonical_stream_chunk(handle, &capability, chunk_index, chunk)
        .map_or_else(|status| status, |()| 0)
}

/// Finishes canonical authentication before promoting the BGV semantic sink.
///
/// # Safety
///
/// `capability_pointer` must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_bgv_canonical_stream_finish(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    finish_bgv_canonical_stream(handle, &capability).map_or_else(|status| status, |()| 0)
}

/// Cancels both the canonical verifier and its operation-owned BGV sink.
/// Repeated cancellation after removal is a no-op.
///
/// # Safety
///
/// `capability_pointer` must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_bgv_canonical_stream_cancel(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_capability(capability_pointer, capability_length) };
    cancel_bgv_canonical_stream(handle, &capability).map_or_else(|status| status, |()| 0)
}

/// Begins the sole active bounded foundation-board session in this WASM
/// instance. The binary configuration contains the version, suite and context
/// hashes, limits, immutable external anchors, and one canonical roster.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_foundation_board_begin(
    configuration_pointer: *const u8,
    configuration_length: usize,
    capability_pointer: *const u8,
    capability_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let configuration =
        unsafe { canonical_stream_input(configuration_pointer, configuration_length) };
    let capability = unsafe { foundation_board_capability(capability_pointer, capability_length) };
    match begin_foundation_board_session(configuration, capability) {
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

/// Ingests one exact canonical carrier and routes it through the fixed verifier
/// requirement assigned to its decoded object family. Success writes only the
/// candidate object hash; no caller-selected verifier or relay metadata enters
/// the boundary.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. The candidate
/// output pointer must name exactly 64 writable bytes in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_foundation_board_ingest(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    canonical_carrier_pointer: *const u8,
    canonical_carrier_length: usize,
    candidate_hash_pointer: *mut u8,
    candidate_hash_length: usize,
) -> u32 {
    if candidate_hash_pointer.is_null()
        || candidate_hash_length != FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH
    {
        return u32::from(foundation::RefusalReason::WrongTypeOrLength.canonical_code());
    }
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    let canonical_carrier =
        unsafe { canonical_stream_input(canonical_carrier_pointer, canonical_carrier_length) };
    match ingest_foundation_board_carrier(handle, capability, canonical_carrier) {
        Ok(candidate_hash) => {
            unsafe {
                ptr::copy_nonoverlapping(
                    candidate_hash.as_ptr(),
                    candidate_hash_pointer,
                    FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH,
                );
            }
            0
        }
        Err(status) => {
            unsafe {
                ptr::write_bytes(
                    candidate_hash_pointer,
                    0,
                    FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH,
                );
            }
            status
        }
    }
}

/// Requires every stored carrier prerequisite edge to have resolved. This does
/// not replace any family-specific proof, relation, state, or storage verifier.
///
/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_foundation_board_require_complete_carrier_graph(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    require_complete_foundation_board_carrier_graph(handle, capability)
        .map_or_else(|status| status, |()| 0)
}

/// Cancels and removes the capability-bound board session. Repeated
/// cancellation after successful removal is a no-op.
///
/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_foundation_board_cancel(
    handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
) -> u32 {
    let capability = unsafe { canonical_stream_input(capability_pointer, capability_length) };
    cancel_foundation_board_session(handle, capability).map_or_else(|status| status, |()| 0)
}

/// Opens the sole capability-bound state-verifier session in this WASM instance.
/// The canonical configuration binds the external roster, suite, ceremony,
/// action, and accepted suite recovery-transition maximum.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
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

/// Verifies a state output against its reservation and the complete exact-output
/// bytes. The bytes are consumed only for recomputation and never returned.
///
/// # Safety
///
/// Every pointer must name its declared readable range. A non-null status
/// pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_state_verifier_verify_output(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_length: usize,
    verified_reservation_handle: u32,
    canonical_output_intent_carrier_pointer: *const u8,
    canonical_output_intent_carrier_length: usize,
    canonical_state_certificate_pointer: *const u8,
    canonical_state_certificate_length: usize,
    exact_output_pointer: *const u8,
    exact_output_length: usize,
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
    let exact_output = unsafe { canonical_stream_input(exact_output_pointer, exact_output_length) };
    match verify_state_output(
        session_handle,
        capability,
        verified_reservation_handle,
        canonical_output_intent_carrier,
        canonical_state_certificate,
        exact_output,
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
    release_verified_state_object(
        session_handle,
        capability,
        verified_object_handle,
    )
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
    cancel_state_verifier_session(session_handle, capability)
        .map_or_else(|status| status, |()| 0)
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
        sealed_lattice_allocate, sealed_lattice_deallocate, sealed_lattice_roundtrip,
        sealed_lattice_transcript_core_command_with_length,
    };
    use core::{ptr, slice};

    #[test]
    fn exported_allocations_deallocate_with_matching_layout() {
        let allocated = sealed_lattice_allocate(4);
        assert!(!allocated.is_null());
        unsafe {
            ptr::write_bytes(allocated, 0xaa, 4);
            sealed_lattice_deallocate(allocated, 4);
        }

        let input = [1_u8, 2, 3, 4, 5];
        let roundtrip = unsafe { sealed_lattice_roundtrip(input.as_ptr(), input.len()) };
        assert!(!roundtrip.is_null());
        let roundtrip_bytes = unsafe { slice::from_raw_parts(roundtrip, input.len()) };
        assert_eq!(roundtrip_bytes, input);
        unsafe {
            sealed_lattice_deallocate(roundtrip, input.len());
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
