//! WebAssembly command surface for the sealed-lattice prototype kernel.
//!
//! The maintained Rust API is the byte-oriented command runner and the FFI
//! allocation functions below. Proof internals are crate-private and should be
//! reached through transcript-core commands so claim boundaries stay centralized.

#![recursion_limit = "256"]

pub(crate) mod bgv;
mod encoding;
pub mod fixtures;
pub(crate) mod hashing;
pub(crate) mod ring;
pub(crate) mod transcript_core;

use core::{ptr, slice};
use std::vec::Vec;

pub use encoding::{
    TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION, roundtrip_bytes, run_transcript_core_command,
};

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

#[cfg(test)]
mod tests {
    use super::{
        TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION, bgv, encoding, fixtures, hashing, ring,
        sealed_lattice_allocate, sealed_lattice_deallocate, sealed_lattice_roundtrip,
        sealed_lattice_transcript_core_command_with_length, transcript_core,
    };
    use core::{ptr, slice};

    #[test]
    fn exposes_stable_transcript_core_markers() {
        assert_eq!(
            TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION,
            "sealed-lattice-transcript-core-command-v1"
        );
        assert_eq!(encoding::MODULE_MARKER, "encoding");
        assert_eq!(bgv::MODULE_MARKER, "bgv");
        assert_eq!(hashing::MODULE_MARKER, "hashing");
        assert_eq!(transcript_core::MODULE_MARKER, "transcript-core");
        assert_eq!(fixtures::MODULE_MARKER, "fixtures");
        assert_eq!(ring::MODULE_MARKER, "ring");
    }

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
