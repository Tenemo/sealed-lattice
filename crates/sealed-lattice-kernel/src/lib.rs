//! WebAssembly command surface for the sealed-lattice prototype kernel.
//!
//! The package exposes canonical foundation commands and an unactivated joined
//! seed-custody byte boundary. The latter creates no preparation-continuation
//! authority and production dispatch remains fail-closed.

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
use zeroize::{Zeroize, Zeroizing};

pub use encoding::run_transcript_core_command;

fn leak_bytes(bytes: Vec<u8>) -> *mut u8 {
    Box::into_raw(bytes.into_boxed_slice()) as *mut u8
}

fn leak_secret_bytes(mut bytes: Zeroizing<Vec<u8>>) -> *mut u8 {
    let owned_bytes = std::mem::take(&mut *bytes);
    Box::into_raw(owned_bytes.into_boxed_slice()) as *mut u8
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

/// Erases and releases one secret-bearing Wasm allocation.
///
/// # Safety
///
/// `pointer` must be null or originate from this module with the same `length`,
/// and must not already have been deallocated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_deallocate_secret(pointer: *mut u8, length: usize) {
    if pointer.is_null() || length == 0 {
        return;
    }

    let mut bytes = unsafe { Box::from_raw(slice::from_raw_parts_mut(pointer, length)) };
    bytes.as_mut().zeroize();
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

/// Positively verifies exact retained source, receipt, and public-terminal
/// bytes before encoding inert joined seed-master custody.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_join_seed_masters_320_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = tally_preparation::pseudorandom_zero_sharing_seed_master_custody_320::run_pseudorandom_zero_sharing_seed_master_join_custody_320(input);
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_secret_bytes(output)
}

/// Revalidates one exact authenticated joined-custody plaintext without
/// constructing a seed-master or preparation-continuation handle.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_validate_joined_seed_masters_320_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = tally_preparation::pseudorandom_zero_sharing_seed_master_custody_320::run_pseudorandom_zero_sharing_joined_seed_master_validation_320(input);
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_secret_bytes(output)
}

/// Generates or positively revalidates one exact retained seed-catalog source
/// object through the scalar kernel. Returned bytes are inert local custody and
/// create no publication, receipt, burn, coin-opening, or continuation power.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_seed_catalog_source_320_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = tally_preparation::pseudorandom_zero_sharing_seed_catalog_source_kernel_320::run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(input);
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_secret_bytes(output)
}

/// Runs an exact number of scalar candidate-field multiplications.
///
/// This diagnostic-only export is absent from the production WebAssembly
/// package and exists solely in the feature-gated focused measurement build.
#[cfg(feature = "preparation-field-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_measure_binary_field_320_multiplications(
    multiplication_count: u32,
    seed: u64,
) -> u64 {
    tally_preparation::measure_binary_field_320_multiplications(multiplication_count, seed)
}

#[cfg(test)]
mod tests {
    use core::{ptr, slice};

    use super::{
        sealed_lattice_allocate, sealed_lattice_deallocate, sealed_lattice_deallocate_secret,
        sealed_lattice_join_seed_masters_320_with_length,
        sealed_lattice_seed_catalog_source_320_with_length,
        sealed_lattice_transcript_core_command_with_length,
        sealed_lattice_validate_joined_seed_masters_320_with_length,
    };

    #[test]
    fn allocation_and_command_boundaries_round_trip() {
        let allocated = sealed_lattice_allocate(4);
        assert!(!allocated.is_null());
        unsafe {
            sealed_lattice_deallocate(allocated, 4);
        }

        let secret_allocation = sealed_lattice_allocate(4);
        assert!(!secret_allocation.is_null());
        unsafe {
            secret_allocation.write_bytes(0xa5, 4);
            sealed_lattice_deallocate_secret(secret_allocation, 4);
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

        for (operation, expected_header) in [
            (
                sealed_lattice_join_seed_masters_320_with_length
                    as unsafe extern "C" fn(*const u8, usize, *mut usize) -> *mut u8,
                &b"SLJR\x01\x00\x00"[..],
            ),
            (
                sealed_lattice_seed_catalog_source_320_with_length,
                &b"SLSR\x01\x00\x00"[..],
            ),
            (
                sealed_lattice_validate_joined_seed_masters_320_with_length,
                &b"SLJR\x01\x00\x00"[..],
            ),
        ] {
            let mut refusal_length = 0_usize;
            let refusal = unsafe { operation(ptr::null(), 0, &mut refusal_length) };
            assert!(!refusal.is_null());
            assert_eq!(
                unsafe { slice::from_raw_parts(refusal, refusal_length) }.get(..7),
                Some(expected_header)
            );
            unsafe {
                sealed_lattice_deallocate_secret(refusal, refusal_length);
            }
        }
    }
}
