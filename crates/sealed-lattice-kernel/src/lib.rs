#![recursion_limit = "256"]

mod encoding;
mod foundation;

use core::{ptr, slice};
use std::vec::Vec;
use zeroize::Zeroize;

fn leak_bytes(bytes: Vec<u8>) -> *mut u8 {
    Box::into_raw(bytes.into_boxed_slice()) as *mut u8
}

unsafe fn command_output(pointer: *const u8, length: usize) -> Vec<u8> {
    if length == 0 || pointer.is_null() {
        return encoding::run_foundation_command(&[]);
    }

    let input = unsafe { slice::from_raw_parts(pointer, length) };
    encoding::run_foundation_command(input)
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

    let mut bytes = unsafe { Box::from_raw(slice::from_raw_parts_mut(pointer, length)) };
    bytes.zeroize();
}

/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this module's linear memory. `output_length_pointer` must be null
/// or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_foundation_command_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let output = unsafe { command_output(pointer, length) };
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_bytes(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_allocation_is_null() {
        assert!(sealed_lattice_allocate(0).is_null());
    }

    #[test]
    fn command_abi_returns_owned_output() {
        let input = [0xff];
        let mut output_length = 0_usize;
        let output_pointer = unsafe {
            sealed_lattice_foundation_command_with_length(
                input.as_ptr(),
                input.len(),
                &raw mut output_length,
            )
        };

        assert!(!output_pointer.is_null());
        assert!(output_length > 0);
        unsafe {
            sealed_lattice_deallocate(output_pointer, output_length);
        }
    }
}
