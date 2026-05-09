pub mod bgv;
pub mod close;
pub mod encoding;
pub mod fixtures;
pub mod hashing;
pub mod proofs;
pub mod ring;
pub mod setup;
pub mod transcript_core;
pub mod verifier;

use core::{
    ptr, slice,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::vec::Vec;

pub use encoding::{
    TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION, roundtrip_bytes, run_transcript_core_command,
};

static LAST_OUTPUT_LENGTH: AtomicUsize = AtomicUsize::new(0);

fn leak_bytes(bytes: Vec<u8>) -> *mut u8 {
    Box::into_raw(bytes.into_boxed_slice()) as *mut u8
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
/// `sealed_lattice_roundtrip` or `sealed_lattice_transcript_core_command` with the same
/// `length`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_deallocate(pointer: *mut u8, length: usize) {
    if length == 0 || pointer.is_null() {
        return;
    }

    unsafe {
        drop(Vec::from_raw_parts(pointer, length, length));
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

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_last_output_length() -> usize {
    LAST_OUTPUT_LENGTH.load(Ordering::SeqCst)
}

/// # Safety
///
/// `pointer` must either be null with `length == 0` or point to readable bytes
/// for `length` elements in the WebAssembly module's linear memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_transcript_core_command(
    pointer: *const u8,
    length: usize,
) -> *mut u8 {
    if length == 0 || pointer.is_null() {
        let output = run_transcript_core_command(b"{}");
        LAST_OUTPUT_LENGTH.store(output.len(), Ordering::SeqCst);
        return leak_bytes(output);
    }

    let input = unsafe { slice::from_raw_parts(pointer, length) };
    let output = run_transcript_core_command(input);
    LAST_OUTPUT_LENGTH.store(output.len(), Ordering::SeqCst);

    leak_bytes(output)
}

#[cfg(test)]
mod tests {
    use super::{
        TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION, bgv, close, encoding, fixtures, hashing, proofs,
        ring, setup, transcript_core, verifier,
    };

    #[test]
    fn exposes_stable_transcript_core_markers() {
        assert_eq!(
            TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION,
            "sealed-lattice-transcript-core-command-v1"
        );
        assert_eq!(encoding::MODULE_MARKER, "encoding");
        assert_eq!(hashing::MODULE_MARKER, "hashing");
        assert_eq!(transcript_core::MODULE_MARKER, "transcript-core");
        assert_eq!(fixtures::MODULE_MARKER, "fixtures");
        assert_eq!(ring::MODULE_MARKER, "ring");
        assert_eq!(bgv::MODULE_MARKER, "bgv");
        assert_eq!(proofs::MODULE_MARKER, "proofs");
        assert_eq!(setup::MODULE_MARKER, "setup");
        assert_eq!(close::MODULE_MARKER, "close");
        assert_eq!(
            verifier::future_implementation_summary(),
            "verifier future implementation pending"
        );
    }
}
