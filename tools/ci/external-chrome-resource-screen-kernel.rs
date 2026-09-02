use core::slice;
use std::cell::RefCell;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

use crate::protocol::padded_continuation::padded_kmac256;

const PADDED_KMAC_KEY_BYTE_LENGTH: usize = 40;
const SHAKE256_OUTPUT_BYTE_LENGTH: usize = 64;
const LOCAL_ROW_FAMILY: u32 = 1;
const JOINT_ROW_FAMILY: u32 = 2;
const CONTINUATION_ROW_FAMILY: u32 = 3;

std::thread_local! {
    static SHAKE256_STATE: RefCell<Option<Shake256>> = const { RefCell::new(None) };
}

fn run_padded_kmac<const MESSAGE_BYTE_LENGTH: usize, const OUTPUT_BYTE_LENGTH: usize>(
    family: u32,
    invocation_count: u32,
) -> u32 {
    let mut key = [0x5a_u8; PADDED_KMAC_KEY_BYTE_LENGTH];
    let mut message = [0xa5_u8; MESSAGE_BYTE_LENGTH];
    let mut checksum = family;
    for invocation_ordinal in 0..invocation_count {
        message[0] = family as u8;
        message[MESSAGE_BYTE_LENGTH - size_of::<u32>()..]
            .copy_from_slice(&invocation_ordinal.to_le_bytes());
        let mut output = padded_kmac256::<OUTPUT_BYTE_LENGTH>(&key, &message);
        for byte in output.iter().copied() {
            checksum = checksum.rotate_left(5) ^ u32::from(byte);
        }
        key.copy_from_slice(&output[..PADDED_KMAC_KEY_BYTE_LENGTH]);
        output.zeroize();
    }
    key.zeroize();
    message.zeroize();
    checksum
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_resource_screen_padded_kmac(
    family: u32,
    invocation_count: u32,
) -> u32 {
    match family {
        LOCAL_ROW_FAMILY => run_padded_kmac::<223, 41>(family, invocation_count),
        JOINT_ROW_FAMILY => run_padded_kmac::<223, 40>(family, invocation_count),
        CONTINUATION_ROW_FAMILY => run_padded_kmac::<230, 81>(family, invocation_count),
        _ => u32::MAX,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_resource_screen_shake256_initialize() -> u32 {
    SHAKE256_STATE.with(|state| {
        *state.borrow_mut() = Some(Shake256::default());
    });
    1
}

/// # Safety
///
/// `pointer` must identify `length` readable bytes in this module's linear
/// memory for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_resource_screen_shake256_update(
    pointer: *const u8,
    length: usize,
) -> u32 {
    if length > 0 && pointer.is_null() {
        return 0;
    }
    let input = if length == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    SHAKE256_STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(hasher) = state.as_mut() else {
            return 0;
        };
        hasher.update(input);
        1
    })
}

/// # Safety
///
/// `pointer` must identify exactly 64 writable bytes in this module's linear
/// memory for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_resource_screen_shake256_finalize(
    pointer: *mut u8,
    length: usize,
) -> u32 {
    if pointer.is_null() || length != SHAKE256_OUTPUT_BYTE_LENGTH {
        return 0;
    }
    SHAKE256_STATE.with(|state| {
        let Some(hasher) = state.borrow_mut().take() else {
            return 0;
        };
        let output = unsafe { slice::from_raw_parts_mut(pointer, length) };
        hasher.finalize_xof().read(output);
        1
    })
}
