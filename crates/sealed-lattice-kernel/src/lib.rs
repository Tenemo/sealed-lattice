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
        reason = "the unactivated pre-evaluation-finality verifier is not connected to the package surface"
    )
)]
mod pre_evaluation_finality;
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

/// Positively verifies one complete or partial direct-MPC one-AND transcript.
///
/// This feature-gated evidence boundary emits only a canonical verifier
/// response. It does not activate a suite or authorize production dispatch.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[cfg(feature = "direct-mpc-one-and-verifier")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_verify_direct_mpc_one_and_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = pre_evaluation_finality::run_direct_mpc_one_and_verification_bundle(input);
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

/// Revalidates exact authenticated joined custody and reconstructs its typed
/// local masters before an external state owner issues a one-shot handoff.
/// The restored masters are dropped before this call returns.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_validate_joined_seed_master_restoration_320_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = tally_preparation::pseudorandom_zero_sharing_seed_master_custody_320::run_pseudorandom_zero_sharing_joined_seed_master_restoration_validation_320(input);
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_secret_bytes(output)
}

/// Re-verifies one exact preprocessing-source predecessor and constructs or
/// validates its state-witnessed success-or-burn terminal. The command surface
/// remains internal and does not activate a suite or public SDK capability.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_direct_mpc_preprocessing_source_state_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = pre_evaluation_finality::direct_mpc_preprocessing_source_state_kernel::run_direct_mpc_preprocessing_source_state_kernel(input);
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

/// Opens, uses, or closes one positively verified sender-mailbox context and
/// produces or verifies its exact scalar carrier bytes.
///
/// The context handle remains owned by this WebAssembly instance. Returned
/// bytes create no recipient delivery, receipt, burn, coin-opening, or
/// preparation-continuation authority.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_seed_mailbox_sender_320_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = tally_preparation::pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320::run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(input);
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_secret_bytes(output)
}

/// Opens one positively verified recipient-mailbox inventory, completes its
/// browser-local decapsulation results, and produces or verifies the exact
/// recipient receipt carrier through the scalar kernel.
///
/// Every sender signature and encrypted chunk digest is checked before the
/// adapter returns the ML-KEM ciphertexts to the browser-local key owner. The
/// returned prepared bytes are inert local custody and create no receipt
/// terminal, burn, seed-combination, coin-opening, or preparation-continuation
/// authority.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_seed_recipient_receipt_320_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = tally_preparation::pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320::run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(input);
    if !output_length_pointer.is_null() {
        unsafe {
            output_length_pointer.write(output.len());
        }
    }
    leak_secret_bytes(output)
}

/// Opens, uses, or closes one positively verified receipt-terminal
/// endorsement context and produces or verifies its exact scalar carrier.
///
/// The context handle remains owned by this WebAssembly instance. Returned
/// bytes create only one participant's common-view endorsement carrier. They
/// create no all-roster terminal, burn, seed-combination, coin-opening, or
/// preparation-continuation authority.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory. `output_length_pointer`
/// must be null or identify one writable `usize` value in the same memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_seed_receipt_terminal_endorsement_320_with_length(
    pointer: *const u8,
    length: usize,
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    let output = tally_preparation::pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320::run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(input);
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

/// Opens the deterministic completion-scale zero-sharing diagnostic cursor.
///
/// This export and its raw diagnostic source fixture are absent from the
/// production WebAssembly package.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_open_zero_sharing_measurement_320() -> u32 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::open_completion_zero_sharing_measurement_320()
}

/// Opens one completion-scale diagnostic source cursor for the requested
/// roster position. Every holder of one subset receives the same deterministic
/// measurement master. The raw source fixture is absent from production.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_open_zero_sharing_codeword_source_measurement_320(
    participant_position: u32,
) -> u32 {
    let Ok(participant_position) = u16::try_from(participant_position) else {
        return tally_preparation::pseudorandom_zero_sharing_measurement_320::MEASUREMENT_ERROR;
    };
    tally_preparation::pseudorandom_zero_sharing_measurement_320::open_completion_zero_sharing_codeword_source_measurement_320(participant_position)
}

/// Checks a nonempty field-major block of all-roster zero-codeword openings.
/// Returns zero for a valid block, one for an algebraically invalid block, and
/// `u32::MAX` for malformed or oversized input. This diagnostic-only export
/// authenticates no source and cannot mint a protocol capability.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_verify_zero_sharing_codeword_block_320(
    pointer: *const u8,
    length: usize,
) -> u32 {
    let input = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    tally_preparation::pseudorandom_zero_sharing_measurement_320::verify_completion_zero_sharing_codeword_block_320(input)
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_codeword_byte_length_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_codeword_byte_length_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_codeword_maximum_block_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_codeword_maximum_block_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_codeword_multiplication_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_codeword_multiplication_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_codeword_addition_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_codeword_addition_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_codeword_comparison_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_codeword_comparison_count_320()
}

/// Restores the deterministic diagnostic cursor from one authenticated inner
/// checkpoint while no measurement cursor is open.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_restore_zero_sharing_measurement_320(
    pointer: *const u8,
    length: usize,
) -> u32 {
    let checkpoint = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    tally_preparation::pseudorandom_zero_sharing_measurement_320::restore_completion_zero_sharing_measurement_320(checkpoint)
}

/// Restores one all-roster source diagnostic cursor from its authenticated
/// inner checkpoint while no measurement cursor is open.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_restore_zero_sharing_codeword_source_measurement_320(
    participant_position: u32,
    pointer: *const u8,
    length: usize,
) -> u32 {
    let Ok(participant_position) = u16::try_from(participant_position) else {
        return tally_preparation::pseudorandom_zero_sharing_measurement_320::MEASUREMENT_ERROR;
    };
    let checkpoint = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    tally_preparation::pseudorandom_zero_sharing_measurement_320::restore_completion_zero_sharing_codeword_source_measurement_320(
        participant_position,
        checkpoint,
    )
}

/// Performs exactly one canonical subset-and-basis stream chunk.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_step_zero_sharing_measurement_320() -> u32 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::step_completion_zero_sharing_measurement_320()
}

/// Copies the current authenticated secret checkpoint out of the diagnostic
/// cursor. The caller must erase the returned allocation.
///
/// # Safety
///
/// `output_length_pointer` must be null or identify one writable `usize`
/// value in this WebAssembly module's linear memory.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_zero_sharing_measurement_checkpoint_320_with_length(
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let Some(output) = tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_checkpoint_320() else {
        if !output_length_pointer.is_null() {
            unsafe { output_length_pointer.write(0) };
        }
        return ptr::null_mut();
    };
    if !output_length_pointer.is_null() {
        unsafe { output_length_pointer.write(output.len()) };
    }
    leak_secret_bytes(output)
}

/// Copies the current completed secret output chunk out of the diagnostic
/// cursor. The caller must erase the returned allocation.
///
/// # Safety
///
/// `output_length_pointer` must be null or identify one writable `usize`
/// value in this WebAssembly module's linear memory.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_zero_sharing_measurement_completed_chunk_320_with_length(
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let Some(output) = tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_completed_chunk_320() else {
        if !output_length_pointer.is_null() {
            unsafe { output_length_pointer.write(0) };
        }
        return ptr::null_mut();
    };
    if !output_length_pointer.is_null() {
        unsafe { output_length_pointer.write(output.len()) };
    }
    leak_secret_bytes(output)
}

/// Acknowledges that the current output chunk has been copied by the
/// diagnostic worker. This is not a durable production acknowledgement.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_acknowledge_zero_sharing_measurement_chunk_320() -> u32 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::acknowledge_completion_zero_sharing_measurement_chunk_320()
}

/// Drops the diagnostic cursor and zeroizes its retained Rust-owned buffers.
#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_close_zero_sharing_measurement_320() -> u32 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::close_completion_zero_sharing_measurement_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_state_320() -> u32 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_state_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_zero_sharing_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_zero_sharing_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_basis_stream_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_basis_stream_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_output_chunk_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_output_chunk_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_work_checkpoint_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_work_checkpoint_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_field_output_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_field_output_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_basis_precomputation_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_basis_precomputation_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_combination_multiplication_count_320()
-> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_combination_multiplication_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_combination_addition_count_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_combination_addition_count_320()
}

#[cfg(feature = "preparation-zero-sharing-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_zero_sharing_measurement_expected_checkpoint_traffic_320() -> u64 {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::completion_zero_sharing_measurement_expected_checkpoint_traffic_320()
}

/// Runs the same deterministic typed zero-sharing cursor under the native
/// development target and returns its source-derived counts and output
/// digests. This diagnostic surface is absent from the production package.
#[cfg(feature = "preparation-zero-sharing-measurement")]
pub fn run_completion_zero_sharing_native_measurement_json() -> Result<String, String> {
    tally_preparation::pseudorandom_zero_sharing_measurement_320::run_completion_zero_sharing_native_measurement_json()
}

/// Opens the exact completion-profile direct-MPC PRSS scalar diagnostic.
///
/// This surface is absent from the production WebAssembly package and cannot
/// mint a preparation or continuation capability.
#[cfg(feature = "direct-mpc-scalar-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_open_direct_mpc_prss_measurement() -> u32 {
    tally_preparation::direct_mpc_scalar_measurement::open_completion_direct_mpc_scalar_measurement(
    )
}

/// Restores the direct-MPC PRSS diagnostic from one authenticated safe-boundary checkpoint.
///
/// # Safety
///
/// `pointer` must be null when `length` is zero or identify `length` readable
/// bytes in this WebAssembly module's linear memory.
#[cfg(feature = "direct-mpc-scalar-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_restore_direct_mpc_prss_measurement(
    pointer: *const u8,
    length: usize,
) -> u32 {
    let checkpoint = if length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, length) }
    };
    tally_preparation::direct_mpc_scalar_measurement::restore_completion_direct_mpc_scalar_measurement(
        checkpoint,
    )
}

/// Performs exactly one canonical direct-MPC subset stream and stops at its safe boundary.
#[cfg(feature = "direct-mpc-scalar-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_step_direct_mpc_prss_measurement() -> u32 {
    tally_preparation::direct_mpc_scalar_measurement::step_completion_direct_mpc_scalar_measurement(
    )
}

#[cfg(feature = "direct-mpc-scalar-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_direct_mpc_prss_measurement_state() -> u32 {
    tally_preparation::direct_mpc_scalar_measurement::completion_direct_mpc_scalar_measurement_state(
    )
}

/// Copies the authenticated direct-MPC PRSS checkpoint out of the diagnostic cursor.
///
/// # Safety
///
/// `output_length_pointer` must be null or identify one writable `usize` value
/// in this WebAssembly module's linear memory.
#[cfg(feature = "direct-mpc-scalar-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_direct_mpc_prss_measurement_checkpoint_with_length(
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let Some(output) = tally_preparation::direct_mpc_scalar_measurement::completion_direct_mpc_scalar_measurement_checkpoint() else {
        if !output_length_pointer.is_null() {
            unsafe { output_length_pointer.write(0) };
        }
        return ptr::null_mut();
    };
    if !output_length_pointer.is_null() {
        unsafe { output_length_pointer.write(output.len()) };
    }
    leak_secret_bytes(output)
}

/// Copies the completed canonical direct-MPC PRSS output out of the diagnostic cursor.
///
/// # Safety
///
/// `output_length_pointer` must be null or identify one writable `usize` value
/// in this WebAssembly module's linear memory.
#[cfg(feature = "direct-mpc-scalar-measurement")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_direct_mpc_prss_measurement_result_with_length(
    output_length_pointer: *mut usize,
) -> *mut u8 {
    let Some(output) = tally_preparation::direct_mpc_scalar_measurement::completion_direct_mpc_scalar_measurement_result() else {
        if !output_length_pointer.is_null() {
            unsafe { output_length_pointer.write(0) };
        }
        return ptr::null_mut();
    };
    if !output_length_pointer.is_null() {
        unsafe { output_length_pointer.write(output.len()) };
    }
    leak_secret_bytes(output)
}

#[cfg(feature = "direct-mpc-scalar-measurement")]
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_close_direct_mpc_prss_measurement() -> u32 {
    tally_preparation::direct_mpc_scalar_measurement::close_completion_direct_mpc_scalar_measurement(
    )
}

macro_rules! direct_mpc_measurement_resource_export {
    ($export_name:ident, $resource_function:ident) => {
        #[cfg(feature = "direct-mpc-scalar-measurement")]
        #[unsafe(no_mangle)]
        pub extern "C" fn $export_name() -> u64 {
            tally_preparation::direct_mpc_scalar_measurement::$resource_function()
        }
    };
}

direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_authorized_subset_count,
    completion_direct_mpc_authorized_subset_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_ordinary_stream_count,
    completion_direct_mpc_ordinary_stream_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_zero_basis_stream_count,
    completion_direct_mpc_zero_basis_stream_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_total_stream_count,
    completion_direct_mpc_total_stream_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_ordinary_field_count,
    completion_direct_mpc_ordinary_field_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_zero_field_count,
    completion_direct_mpc_zero_field_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_field_output_count,
    completion_direct_mpc_field_output_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_source_byte_length,
    completion_direct_mpc_source_byte_length
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_basis_multiplication_count,
    completion_direct_mpc_basis_multiplication_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_basis_inverse_count,
    completion_direct_mpc_basis_inverse_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_weight_multiplication_count,
    completion_direct_mpc_weight_multiplication_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_accumulation_addition_count,
    completion_direct_mpc_accumulation_addition_count
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_maximum_xof_allocation_byte_length,
    completion_direct_mpc_maximum_xof_allocation_byte_length
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_canonical_accumulator_byte_length,
    completion_direct_mpc_canonical_accumulator_byte_length
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_internal_accumulator_byte_length,
    completion_direct_mpc_internal_accumulator_byte_length
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_checkpoint_byte_length,
    completion_direct_mpc_checkpoint_byte_length
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_cumulative_checkpoint_byte_length,
    completion_direct_mpc_cumulative_checkpoint_byte_length
);
direct_mpc_measurement_resource_export!(
    sealed_lattice_direct_mpc_prss_result_byte_length,
    completion_direct_mpc_result_byte_length
);

/// Runs the exact typed direct-MPC PRSS cursor under the native development target.
#[cfg(feature = "direct-mpc-scalar-measurement")]
pub fn run_completion_direct_mpc_native_measurement_json() -> Result<String, String> {
    tally_preparation::direct_mpc_scalar_measurement::run_completion_direct_mpc_native_measurement_json()
}

#[cfg(test)]
mod tests {
    use core::{ptr, slice};

    use super::{
        sealed_lattice_allocate, sealed_lattice_deallocate, sealed_lattice_deallocate_secret,
        sealed_lattice_join_seed_masters_320_with_length,
        sealed_lattice_seed_catalog_source_320_with_length,
        sealed_lattice_seed_mailbox_sender_320_with_length,
        sealed_lattice_seed_receipt_terminal_endorsement_320_with_length,
        sealed_lattice_seed_recipient_receipt_320_with_length,
        sealed_lattice_transcript_core_command_with_length,
        sealed_lattice_validate_joined_seed_master_restoration_320_with_length,
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
                sealed_lattice_seed_mailbox_sender_320_with_length,
                &b"SLMR\x01\x00\x00"[..],
            ),
            (
                sealed_lattice_seed_recipient_receipt_320_with_length,
                &b"SLRR\x01\x00\x00"[..],
            ),
            (
                sealed_lattice_seed_receipt_terminal_endorsement_320_with_length,
                &b"SLTP\x01\x00\x00"[..],
            ),
            (
                sealed_lattice_validate_joined_seed_master_restoration_320_with_length,
                &b"SLJR\x01\x00\x00"[..],
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
