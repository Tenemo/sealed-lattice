//! WebAssembly command surface for the sealed-lattice prototype kernel.
//!
//! The active package exposes only the canonical foundation command boundary.
//! Candidate tally-circuit and preparation code remains crate-private until an
//! exact suite has passed its cryptographic and scalar-browser admission gates.

#![recursion_limit = "256"]

mod encoding;
pub mod foundation;
pub(crate) mod hashing;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the unactivated tally circuit is not connected to the package surface"
    )
)]
pub(crate) mod tally_circuit;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the unactivated tally preparation candidate is not connected to the package surface"
    )
)]
pub(crate) mod tally_preparation;
pub(crate) mod transcript_core;

use core::{ptr, slice};
use std::vec::Vec;

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
/// `pointer` must be null or originate from [`sealed_lattice_allocate`] with
/// the same `length`, and must not already have been deallocated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_deallocate(pointer: *mut u8, length: usize) {
    if pointer.is_null() || length == 0 {
        return;
    }

    drop(unsafe { Box::from_raw(slice::from_raw_parts_mut(pointer, length)) });
}

/// Runs one bounded canonical foundation command.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_transcript_core_command_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let output = unsafe { transcript_core_command_output(pointer, length) };
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_bytes(output)
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::{
        sealed_lattice_allocate, sealed_lattice_deallocate,
        sealed_lattice_transcript_core_command_with_length,
    };

    #[test]
    fn allocation_and_command_boundaries_round_trip() {
        let allocated = sealed_lattice_allocate(4);
        assert!(!allocated.is_null());
        unsafe {
            sealed_lattice_deallocate(allocated, 4);
        }

        let command = br#"{"command":"DeriveCanonicalObjectHash","value":{"objectType":"KernelBoundary","value":"test"}}"#;
        let mut response_length = 0_usize;
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

        let mut empty_response_length = 0_usize;
        let empty_response = unsafe {
            sealed_lattice_transcript_core_command_with_length(
                ptr::null(),
                0,
                &mut empty_response_length,
            )
        };
        assert!(!empty_response.is_null());
        unsafe {
            sealed_lattice_deallocate(empty_response, empty_response_length);
        }
    }
}
