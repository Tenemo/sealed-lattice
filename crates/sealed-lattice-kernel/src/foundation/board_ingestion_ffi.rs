use core::{ptr, slice};

use super::RefusalReason;
use super::board_ingestion_runtime::{
    BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, begin_board_verifier_session,
    cached_board_carrier_byte_length, cancel_board_verifier_session, copy_cached_board_carrier,
    describe_verified_transcript_object, release_verified_transcript_object,
    verify_unordered_board_carriers,
};

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if byte_length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, byte_length) }
    }
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe {
            status_pointer.write(status);
        }
    }
}

unsafe fn write_bounded_output(
    result: Result<Vec<u8>, u32>,
    output_pointer: *mut u8,
    output_capacity: usize,
    status_pointer: *mut u32,
) -> usize {
    match result {
        Ok(output) => {
            if output.is_empty()
                || output.len() > output_capacity
                || (output_capacity > 0 && output_pointer.is_null())
            {
                unsafe {
                    write_status(
                        status_pointer,
                        refusal_status(RefusalReason::WrongTypeOrLength),
                    );
                }
                return 0;
            }
            unsafe {
                ptr::copy(output.as_ptr(), output_pointer, output.len());
                write_status(status_pointer, 0);
            }
            output.len()
        }
        Err(status) => {
            unsafe {
                write_status(status_pointer, status);
            }
            0
        }
    }
}

unsafe fn write_exact_output(
    result: Result<Vec<u8>, u32>,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    match result {
        Ok(output) => {
            if output.is_empty() || output.len() != output_byte_length || output_pointer.is_null() {
                return refusal_status(RefusalReason::WrongTypeOrLength);
            }
            unsafe {
                ptr::copy(output.as_ptr(), output_pointer, output.len());
            }
            0
        }
        Err(status) => status,
    }
}

/// # Safety
///
/// Every input pointer must name its declared readable range. A non-null status
/// pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_board_verifier_begin(
    configuration_pointer: *const u8,
    configuration_byte_length: usize,
    capability_pointer: *const u8,
    capability_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let configuration = unsafe { input_bytes(configuration_pointer, configuration_byte_length) };
    let capability = unsafe { input_bytes(capability_pointer, capability_byte_length) };
    let Ok(capability): Result<[u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH], _> =
        capability.try_into()
    else {
        unsafe {
            write_status(
                status_pointer,
                refusal_status(RefusalReason::WrongTypeOrLength),
            );
        }
        return 0;
    };
    match begin_board_verifier_session(configuration, capability) {
        Ok(handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_status(status_pointer, status);
            }
            0
        }
    }
}

/// # Safety
///
/// Every input pointer must name its declared readable range. The output
/// pointer must name its declared writable capacity. A non-null status pointer
/// must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_board_verifier_verify_unordered(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_byte_length: usize,
    framed_carriers_pointer: *const u8,
    framed_carriers_byte_length: usize,
    output_pointer: *mut u8,
    output_capacity: usize,
    status_pointer: *mut u32,
) -> usize {
    let capability = unsafe { input_bytes(capability_pointer, capability_byte_length) };
    let framed_carriers =
        unsafe { input_bytes(framed_carriers_pointer, framed_carriers_byte_length) };
    let required_output_capacity = framed_carriers
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .and_then(|bytes| usize::try_from(u32::from_le_bytes(bytes)).ok())
        .and_then(|count| count.checked_mul(4))
        .and_then(|byte_length| byte_length.checked_add(4));
    if required_output_capacity
        .is_none_or(|required| required > output_capacity || output_pointer.is_null())
    {
        unsafe {
            write_status(
                status_pointer,
                refusal_status(RefusalReason::WrongTypeOrLength),
            );
        }
        return 0;
    }
    unsafe {
        write_bounded_output(
            verify_unordered_board_carriers(session_handle, capability, framed_carriers),
            output_pointer,
            output_capacity,
            status_pointer,
        )
    }
}

/// # Safety
///
/// The capability pointer must name its declared readable range and the output
/// pointer must name its complete writable range.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_board_verifier_describe(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_byte_length: usize,
    verified_object_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let capability = unsafe { input_bytes(capability_pointer, capability_byte_length) };
    unsafe {
        write_exact_output(
            describe_verified_transcript_object(session_handle, capability, verified_object_handle),
            output_pointer,
            output_byte_length,
        )
    }
}

/// # Safety
///
/// The capability pointer must name its declared readable range. A non-null
/// status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_board_verifier_cached_carrier_length(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_byte_length: usize,
    verified_object_handle: u32,
    status_pointer: *mut u32,
) -> usize {
    let capability = unsafe { input_bytes(capability_pointer, capability_byte_length) };
    match cached_board_carrier_byte_length(session_handle, capability, verified_object_handle) {
        Ok(byte_length) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            byte_length
        }
        Err(status) => {
            unsafe {
                write_status(status_pointer, status);
            }
            0
        }
    }
}

/// # Safety
///
/// The capability pointer must name its declared readable range and the output
/// pointer must name its complete writable range.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_board_verifier_copy_cached_carrier(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_byte_length: usize,
    verified_object_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let capability = unsafe { input_bytes(capability_pointer, capability_byte_length) };
    unsafe {
        write_exact_output(
            copy_cached_board_carrier(session_handle, capability, verified_object_handle),
            output_pointer,
            output_byte_length,
        )
    }
}

/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_board_verifier_release(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_byte_length: usize,
    verified_object_handle: u32,
) -> u32 {
    let capability = unsafe { input_bytes(capability_pointer, capability_byte_length) };
    release_verified_transcript_object(session_handle, capability, verified_object_handle)
        .map_or_else(|status| status, |()| 0)
}

/// # Safety
///
/// The capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_board_verifier_cancel(
    session_handle: u32,
    capability_pointer: *const u8,
    capability_byte_length: usize,
) -> u32 {
    let capability = unsafe { input_bytes(capability_pointer, capability_byte_length) };
    cancel_board_verifier_session(session_handle, capability).map_or_else(|status| status, |()| 0)
}
