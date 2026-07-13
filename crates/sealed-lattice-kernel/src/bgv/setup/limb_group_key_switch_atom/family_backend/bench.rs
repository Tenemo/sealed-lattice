//! Ignored benchmark for per-key round-one prove/verify time, peak memory, and
//! canonical proof size. All measured degrees fit their `8N` coset below the
//! `2^20` domain ceiling without splitting columns.
//!
//! Run through the guarded focused Rust runner:
//! `pnpm run test:rust:kernel:accepted-setup -- round_one_key_prover_cost`
//!
//! This is native development measurement only. It is not browser or WASM
//! evidence, and not supported-phone evidence.

use super::super::proof_field::sixteen_limb_group_field_parameters;
use super::key_proof::{
    KeyFriProofParameters, KeySource, prove_round_one_key_fri, verify_round_one_key_fri,
};
use super::proof_codec::encode_key_proof;
use super::test_support::build_synthetic_key_fixture;

// The process's peak working set (Windows) or high-water RSS (Linux), as a
// development-only prover peak-memory indicator. Process-wide, so the benchmark
// must run as the only test in its invocation for the number to mean anything.
fn peak_memory_bytes() -> Option<u64> {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct ProcessMemoryCounters {
            structure_size: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            quota_peak_paged_pool_usage: usize,
            quota_paged_pool_usage: usize,
            quota_peak_non_paged_pool_usage: usize,
            quota_non_paged_pool_usage: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }
        unsafe extern "system" {
            unsafe fn GetCurrentProcess() -> isize;
            unsafe fn K32GetProcessMemoryInfo(
                process: isize,
                counters: *mut ProcessMemoryCounters,
                counters_size: u32,
            ) -> i32;
        }
        let mut counters = ProcessMemoryCounters {
            structure_size: std::mem::size_of::<ProcessMemoryCounters>() as u32,
            page_fault_count: 0,
            peak_working_set_size: 0,
            working_set_size: 0,
            quota_peak_paged_pool_usage: 0,
            quota_paged_pool_usage: 0,
            quota_peak_non_paged_pool_usage: 0,
            quota_non_paged_pool_usage: 0,
            pagefile_usage: 0,
            peak_pagefile_usage: 0,
        };
        let succeeded = unsafe {
            K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.structure_size)
        };
        if succeeded != 0 {
            return Some(counters.peak_working_set_size as u64);
        }
        None
    }
    #[cfg(all(unix, target_os = "linux"))]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kibibytes: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
                return Some(kibibytes * 1024);
            }
        }
        None
    }
    #[cfg(not(any(windows, all(unix, target_os = "linux"))))]
    {
        None
    }
}

#[test]
#[ignore = "prover-cost benchmark; run via the guarded accepted-setup runner"]
fn round_one_key_prover_cost() {
    use std::time::Instant;
    let parameters = sixteen_limb_group_field_parameters();
    // A level-15 key has 16 digits. For each ring degree m, mask degree m/4
    // covers two openings per query and stays below m/2, so masked quotients fit
    // the degree bound 2m. Every measured 8m coset fits below the 2^20 ceiling.
    let digit_count = 16;
    let query_count = 80;
    println!("round-one key ({digit_count} digits, {query_count} queries, mask degree N/4):");
    for ring_degree in [4096_usize, 8192, 32768] {
        let proof_parameters = KeyFriProofParameters {
            query_count,
            mask_degree: ring_degree / 4,
        };
        let (secret, digits, public) =
            build_synthetic_key_fixture(ring_degree, digit_count, &KeySource::RoundOne);
        let mut salt_seed = 0x1234;
        let prove_start = Instant::now();
        let proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
        let verify_start = Instant::now();
        let accepted =
            verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify");
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
        assert!(accepted, "benchmark proof must verify");
        let proof_bytes = encode_key_proof(&proof).expect("encode").len();
        let proof_kib = proof_bytes as f64 / 1024.0;
        let proof_mib = proof_bytes as f64 / (1024.0 * 1024.0);
        let peak = peak_memory_bytes()
            .map(|bytes| format!("{:.0} MiB", bytes as f64 / (1024.0 * 1024.0)))
            .unwrap_or_else(|| "unavailable".to_string());
        println!(
            "  N = {ring_degree:5}: prove {prove_ms:9.1} ms, verify {verify_ms:8.1} ms, proof {proof_kib:8.1} KiB ({proof_mib:.2} MiB), peak memory {peak}"
        );
    }
}
