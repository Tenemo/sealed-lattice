pub mod bgv;
pub mod close;
pub mod encoding;
pub mod proofs;
pub mod ring;
pub mod setup;
pub mod verifier;

use core::{ptr, slice};
use std::vec::Vec;

pub use encoding::{BYTE_BUFFER_CONTRACT_VERSION, roundtrip_bytes};

fn leak_bytes(mut bytes: Vec<u8>) -> *mut u8 {
    let pointer = bytes.as_mut_ptr();
    std::mem::forget(bytes);

    pointer
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
/// `sealed_lattice_roundtrip` with the same `length`.
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

#[cfg(test)]
mod tests {
    use super::{
        BYTE_BUFFER_CONTRACT_VERSION, bgv, close, encoding, proofs, ring, roundtrip_bytes, setup,
        verifier,
    };

    #[test]
    fn preserves_byte_buffers() {
        assert_eq!(
            roundtrip_bytes(&[0, 1, 2, 127, 128, 255]),
            vec![0, 1, 2, 127, 128, 255],
        );
    }

    #[test]
    fn exposes_stable_foundation_markers() {
        assert_eq!(
            BYTE_BUFFER_CONTRACT_VERSION,
            "sealed-lattice-m01-byte-buffer-roundtrip-v1",
        );
        assert_eq!(encoding::MODULE_MARKER, "encoding");
        assert_eq!(ring::MODULE_MARKER, "ring");
        assert_eq!(bgv::MODULE_MARKER, "bgv");
        assert_eq!(proofs::MODULE_MARKER, "proofs");
        assert_eq!(setup::MODULE_MARKER, "setup");
        assert_eq!(close::MODULE_MARKER, "close");
        assert_eq!(
            verifier::placeholder_summary(),
            "verifier placeholder ready"
        );
    }
}
