//! WebAssembly probes for bounded proof-backend research.
//!
//! The arithmetic export compares raw-witness hashing and affine sumcheck
//! arithmetic between native Rust and `wasm32-unknown-unknown`. The streaming
//! export separately generates, canonically transports, and verifies the
//! complete hiding polynomial-commitment prototype.

use core::{arch::wasm32::memory_size, slice};

static mut LAST_DIAGNOSTIC_DIGEST: [u8; 64] = [0_u8; 64];
static mut LAST_STREAMING_PROTOCOL_DIGEST: [u8; 64] = [0_u8; 64];
static mut LAST_STREAMING_PROTOCOL_METRICS: [u32; 15] = [0_u32; 15];
static mut LAST_EXACT_SAME_SECRET_VERIFIER_METRICS: [u32; 6] = [0_u32; 6];

#[unsafe(no_mangle)]
pub extern "C" fn backend_research_wasm_run(relation_instance_variable_count: u32) -> u32 {
    let digest = super::diagnostic_run_digest(relation_instance_variable_count);
    // SAFETY: the research harness invokes this single-threaded and reads the
    // digest only after this function returns.
    unsafe {
        LAST_DIAGNOSTIC_DIGEST = digest;
    }
    memory_size(0) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn backend_research_wasm_digest_address() -> u32 {
    core::ptr::addr_of!(LAST_DIAGNOSTIC_DIGEST) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn backend_research_streaming_protocol_wasm_run(
    row_count: u32,
    witness_variable_count_per_row: u32,
) -> u32 {
    let result = super::streaming_polynomial_commitment::run_streaming_protocol_probe(
        row_count as usize,
        witness_variable_count_per_row as usize,
    )
    .expect("the deterministic streaming protocol Wasm probe must complete");
    // SAFETY: the research harness invokes this single-threaded and reads the
    // digest only after this function returns.
    unsafe {
        LAST_STREAMING_PROTOCOL_DIGEST = result.digest;
        LAST_STREAMING_PROTOCOL_METRICS = [
            result.canonical_proof_byte_length,
            result.aggregate_proof_byte_length,
            result.aggregate_query_value_byte_length,
            result.aggregate_round_query_value_byte_length,
            result.aggregate_source_query_value_byte_length,
            result.aggregate_fresh_main_query_value_byte_length,
            result.aggregate_mask_query_value_byte_length,
            result.aggregate_merkle_dictionary_byte_length,
            result.aggregate_merkle_reference_byte_length,
            result.aggregate_merkle_unique_node_count,
            result.aggregate_merkle_reference_count,
            result.aggregate_query_count,
            result.outer_column_value_byte_length,
            result.outer_merkle_frontier_byte_length,
            result.outer_merkle_frontier_node_count,
        ]
        .map(|value| u32::try_from(value).expect("the streaming probe metric must fit u32"));
    }
    memory_size(0) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn backend_research_streaming_protocol_wasm_digest_address() -> u32 {
    core::ptr::addr_of!(LAST_STREAMING_PROTOCOL_DIGEST) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn backend_research_streaming_protocol_wasm_metrics_address() -> u32 {
    // SAFETY: the research harness reads this single-threaded after the run.
    core::ptr::addr_of!(LAST_STREAMING_PROTOCOL_METRICS) as u32
}

/// Verifies one persisted exact same-secret proof from caller-owned bytes.
///
/// Returns one on acceptance and zero on refusal. The verifier reconstructs
/// the fixed relation from the canonical public input; it has no source-store,
/// witness, checkpoint, or prover-state input.
///
/// # Safety
///
/// Each pointer must reference the stated number of readable bytes in this
/// WebAssembly instance for the complete duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn backend_research_exact_same_secret_verify(
    public_input_pointer: *const u8,
    public_input_length: usize,
    proof_pointer: *const u8,
    proof_length: usize,
) -> u32 {
    let starting_memory_pages = memory_size(0) as u32;
    if public_input_pointer.is_null()
        || proof_pointer.is_null()
        || public_input_length == 0
        || proof_length == 0
    {
        // SAFETY: the research harness invokes this single-threaded and reads
        // the metrics only after this function returns.
        unsafe {
            LAST_EXACT_SAME_SECRET_VERIFIER_METRICS =
                [0, 0, 0, 0, starting_memory_pages, memory_size(0) as u32];
        }
        return 0;
    }
    // SAFETY: upheld by the caller contract above.
    let public_input = unsafe { slice::from_raw_parts(public_input_pointer, public_input_length) };
    // SAFETY: upheld by the caller contract above.
    let proof = unsafe { slice::from_raw_parts(proof_pointer, proof_length) };
    let result = super::streaming_polynomial_commitment::verify_exact_same_secret_proof_bytes(
        public_input,
        proof,
    );
    let accepted = result.is_ok();
    let ending_memory_pages = memory_size(0) as u32;
    // SAFETY: the research harness invokes this single-threaded and reads the
    // metrics only after this function returns.
    unsafe {
        LAST_EXACT_SAME_SECRET_VERIFIER_METRICS = match result {
            Ok([public_input_bytes, proof_bytes, opening_claims, queries]) => [
                u32::try_from(public_input_bytes)
                    .expect("exact public-input byte length must fit u32"),
                u32::try_from(proof_bytes).expect("exact proof byte length must fit u32"),
                u32::try_from(opening_claims).expect("exact opening count must fit u32"),
                u32::try_from(queries).expect("exact query count must fit u32"),
                starting_memory_pages,
                ending_memory_pages,
            ],
            Err(_) => [0, 0, 0, 0, starting_memory_pages, ending_memory_pages],
        };
    }
    u32::from(accepted)
}

#[unsafe(no_mangle)]
pub extern "C" fn backend_research_exact_same_secret_metrics_address() -> u32 {
    // SAFETY: the research harness reads this single-threaded after the call.
    core::ptr::addr_of!(LAST_EXACT_SAME_SECRET_VERIFIER_METRICS) as u32
}
