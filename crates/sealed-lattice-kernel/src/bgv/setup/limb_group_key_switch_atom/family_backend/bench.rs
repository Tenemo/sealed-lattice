//! Ignored benchmark for a largest-group atom proxy and the complete shipped
//! round-one key schedule. It reports prove/verify time, process-lifetime
//! high-water memory, canonical container size, and test-only prover phase
//! timings. Both statements include the production same-secret linkage and
//! statement/schedule-position bindings. Their `8N` cosets fit below the
//! `2^20` domain ceiling without splitting columns.
//!
//! Run through the guarded focused Rust runner:
//! `pnpm run test:rust:kernel:measurements -- round_one_key_prover_cost`
//!
//! The guarded runner deliberately uses one Rayon thread for memory
//! containment, so these timings measure the algorithmic and allocation path,
//! not the optional native parallel-transform path.
//!
//! This is native development measurement only. It is not browser or WASM
//! evidence, and not supported-phone evidence.

use super::key_proof::{begin_key_prover_phase_timing, finish_key_prover_phase_timing};
use super::schedule::{
    LIMB_GROUP_CAPACITY, SCHEDULE_QUERY_COUNT, prove_key_bearing_trustee_evaluation_keys,
    verify_key_bearing_trustee_evaluation_keys,
};
use crate::bgv::evaluator::top_k::SELECTED_EVALUATOR_WORKING_LEVEL;
use crate::bgv::parameters::POLYNOMIAL_DEGREE;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, generate_development_trustee_instance,
};

const PROOF_RANDOMNESS_SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

// The process's lifetime peak working set (Windows) or high-water RSS (Linux).
// It includes fixture generation and all preceding cases, so it is a ceiling
// observed through each case rather than an isolated per-case prover peak.
fn process_lifetime_high_water_memory_bytes() -> Option<u64> {
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
#[ignore = "prover-cost benchmark; run via the guarded measurements runner"]
fn round_one_key_prover_cost() {
    use std::time::Instant;

    // One capacity-sized atom is the stable per-atom comparison. The complete
    // working-level key has 26 digit columns and splits into 14- and 12-limb
    // atoms.
    let benchmark_cases = [
        ("largest-group atom proxy", LIMB_GROUP_CAPACITY - 1, 1_usize),
        (
            "complete shipped round-one key schedule",
            SELECTED_EVALUATOR_WORKING_LEVEL,
            2_usize,
        ),
    ];
    for (label, level, scheduled_atom_count) in benchmark_cases {
        let fixture_seed = format!("round-one-key-prover-cost-{label}-{POLYNOMIAL_DEGREE}");
        let (statement, witness) = generate_development_trustee_instance(
            &fixture_seed,
            &[(EvaluationKeyShareKind::RelinearizationRoundOne, level)],
            POLYNOMIAL_DEGREE,
        )
        .expect("build production-shaped development statement");
        println!(
            "{label} (N = {POLYNOMIAL_DEGREE}, level {level}, {} digits, {scheduled_atom_count} scheduled atom{}, {SCHEDULE_QUERY_COUNT} queries, mask degree N/4, same-secret linkage):",
            level + 1,
            if scheduled_atom_count == 1 { "" } else { "s" }
        );
        begin_key_prover_phase_timing();
        let prove_start = Instant::now();
        let proof_bytes =
            prove_key_bearing_trustee_evaluation_keys(&statement, &witness, PROOF_RANDOMNESS_SEED)
                .expect("prove shipped schedule");
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
        let phase_timings = finish_key_prover_phase_timing();
        let attributed_prover_ms = phase_timings
            .iter()
            .map(|(_, milliseconds)| milliseconds)
            .sum::<f64>();
        let schedule_and_bridge_ms = (prove_ms - attributed_prover_ms).max(0.0);
        let verify_start = Instant::now();
        verify_key_bearing_trustee_evaluation_keys(&statement, &proof_bytes)
            .expect("verify shipped schedule");
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
        let proof_kib = proof_bytes.len() as f64 / 1024.0;
        let proof_mib = proof_bytes.len() as f64 / (1024.0 * 1024.0);
        let high_water_memory = process_lifetime_high_water_memory_bytes()
            .map(|bytes| format!("{:.0} MiB", bytes as f64 / (1024.0 * 1024.0)))
            .unwrap_or_else(|| "unavailable".to_string());
        println!(
            "  prove {prove_ms:9.1} ms, verify {verify_ms:8.1} ms, proof {proof_kib:8.1} KiB ({proof_mib:.2} MiB), process-lifetime high-water memory through this case {high_water_memory}"
        );
        println!(
            "    phases: {}, schedule/bridge/shared-domain/container overhead {schedule_and_bridge_ms:.1} ms",
            phase_timings
                .iter()
                .map(|(label, milliseconds)| format!("{label} {milliseconds:.1} ms"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}
