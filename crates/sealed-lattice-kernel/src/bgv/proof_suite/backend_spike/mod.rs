//! Isolated backend feasibility research.
//!
//! The module keeps three questions separate:
//!
//! - `raw_merkle_diagnostic` and `bounded_relation_sumcheck` measure the
//!   arithmetic and leaf-hashing memory floors over a genuine affine
//!   cross-column relation. The raw tree is not a PCS, so this is not a proof.
//! - `hiding_whir_memory` models simultaneous allocations required by the
//!   pinned, genuinely verified HidingWhir implementation. That model is the
//!   full-width feasibility gate for the current backend API.
//! - `streaming_polynomial_commitment` prototypes a bounded-witness-storage,
//!   hiding PCS. It commits before the affine sumcheck derives its terminal
//!   point, then authenticates the four terminal evaluations against that
//!   same commitment with a row code, random column checks, and HidingWhir.
//!
//! Measurement witnesses and seeds are deterministic and non-secret. Nothing
//! in this module is on a production protocol path.

pub(crate) mod arena;
pub(crate) mod bounded_relation_sumcheck;
pub(crate) mod field;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod hiding_whir_memory;
pub(crate) mod raw_merkle_diagnostic;
pub(crate) mod streaming_polynomial_commitment;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod peak_alloc;

#[cfg(target_arch = "wasm32")]
pub(crate) mod wasm_probe;

#[cfg(not(target_arch = "wasm32"))]
#[global_allocator]
static PEAK_TRACKING_ALLOCATOR: peak_alloc::PeakTrackingAllocator =
    peak_alloc::PeakTrackingAllocator;

use arena::ArenaGeometry;
use bounded_relation_sumcheck::{
    RelationSumcheckContext, canonical_proof_bytes, evaluate_witness_columns_at, prove_bounded,
    verify_with_authenticated_terminal_evaluations,
};

const ROW_VARIABLE_COUNT: u32 = 14;
const HELD_TRAILING_VARIABLE_COUNT: u32 = 20;
const DIAGNOSTIC_STATEMENT: &[u8] = b"sealed-lattice non-secret affine backend memory diagnostic";

/// Digest shared by native and WebAssembly arithmetic diagnostics.
///
/// It binds the raw witness root, canonical sumcheck messages, and derived
/// terminal point. It does not claim that the terminal point is authenticated
/// by the raw tree.
pub(crate) fn diagnostic_run_digest(relation_instance_variable_count: u32) -> [u8; 64] {
    let geometry = ArenaGeometry::new(relation_instance_variable_count, ROW_VARIABLE_COUNT);
    let raw_root = raw_merkle_diagnostic::streaming_raw_merkle_root(geometry);
    let context = RelationSumcheckContext {
        geometry,
        canonical_statement: DIAGNOSTIC_STATEMENT,
        witness_commitment_root: &raw_root,
    };
    let proof = prove_bounded(context, HELD_TRAILING_VARIABLE_COUNT);
    let proof_bytes = canonical_proof_bytes(&proof);
    let terminal = bounded_relation_sumcheck::terminal_point(context, &proof)
        .expect("an honestly generated diagnostic has the expected round count");
    let terminal_evaluations = evaluate_witness_columns_at(geometry, &terminal);
    let verified =
        verify_with_authenticated_terminal_evaluations(context, &proof, terminal_evaluations)
            .expect("the regenerated terminal evaluations satisfy the affine diagnostic");
    debug_assert_eq!(verified.terminal_point, terminal);
    let terminal_claim_bytes = verified.terminal_claim.to_canonical_bytes();
    let terminal_bytes: Vec<[u8; 40]> = terminal
        .iter()
        .copied()
        .map(|value| value.to_canonical_bytes())
        .collect();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + terminal_bytes.len());
    parts.push(raw_root.as_slice());
    parts.push(proof_bytes.as_slice());
    parts.push(terminal_claim_bytes.as_slice());
    parts.extend(terminal_bytes.iter().map(|bytes| bytes.as_slice()));
    crate::hashing::hash_framed_parts_512(
        "sealed-lattice/backend-research/diagnostic-run/v1",
        &parts,
    )
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct DiagnosticSweepRow {
    pub(crate) relation_instance_variable_count: u32,
    pub(crate) witness_column_count: usize,
    pub(crate) witness_variable_count: u32,
    pub(crate) analytical_resident_raw_tree_peak_bytes: u64,
    pub(crate) measured_streaming_raw_tree_peak_bytes: u64,
    pub(crate) analytical_resident_sumcheck_peak_bytes: u64,
    pub(crate) measured_bounded_sumcheck_peak_bytes: u64,
    pub(crate) sumcheck_messages_agree: Option<bool>,
    pub(crate) raw_roots_agree: Option<bool>,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn run_diagnostic_sweep(
    minimum_relation_instance_variable_count: u32,
    maximum_relation_instance_variable_count: u32,
    resident_baseline_variable_count_cap: u32,
) -> Vec<DiagnosticSweepRow> {
    let mut rows = Vec::new();
    for relation_instance_variable_count in
        minimum_relation_instance_variable_count..=maximum_relation_instance_variable_count
    {
        let geometry = ArenaGeometry::new(relation_instance_variable_count, ROW_VARIABLE_COUNT);
        let raw_root = raw_merkle_diagnostic::streaming_raw_merkle_root(geometry);
        let context = RelationSumcheckContext {
            geometry,
            canonical_statement: DIAGNOSTIC_STATEMENT,
            witness_commitment_root: &raw_root,
        };
        let (_, measured_streaming_raw_tree_peak_bytes) = peak_alloc::measure_peak_delta(|| {
            raw_merkle_diagnostic::streaming_raw_merkle_root(geometry)
        });
        let (bounded_proof, measured_bounded_sumcheck_peak_bytes) =
            peak_alloc::measure_peak_delta(|| prove_bounded(context, HELD_TRAILING_VARIABLE_COUNT));

        let (sumcheck_messages_agree, raw_roots_agree) = if relation_instance_variable_count
            <= resident_baseline_variable_count_cap
        {
            let resident_root = raw_merkle_diagnostic::resident_raw_merkle_root(geometry);
            let resident_proof = prove_bounded(context, geometry.relation_variable_count());
            (
                Some(
                    canonical_proof_bytes(&resident_proof) == canonical_proof_bytes(&bounded_proof),
                ),
                Some(resident_root == raw_root),
            )
        } else {
            (None, None)
        };

        let stacked_evaluation_count = geometry.stacked_evaluation_count() as u64;
        let relation_evaluation_count = geometry.relation_evaluation_count() as u64;
        rows.push(DiagnosticSweepRow {
            relation_instance_variable_count,
            witness_column_count: geometry.witness_column_count(),
            witness_variable_count: geometry.witness_variable_count(),
            analytical_resident_raw_tree_peak_bytes: stacked_evaluation_count * 96,
            measured_streaming_raw_tree_peak_bytes: measured_streaming_raw_tree_peak_bytes as u64,
            analytical_resident_sumcheck_peak_bytes: relation_evaluation_count * 40,
            measured_bounded_sumcheck_peak_bytes: measured_bounded_sumcheck_peak_bytes as u64,
            sumcheck_messages_agree,
            raw_roots_agree,
        });
    }
    rows
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::backend_spike::hiding_whir_memory::pinned_hiding_whir_allocation_lower_bound;

    #[test]
    fn affine_arena_is_consistent_at_small_width() {
        assert!(arena::arena_is_internally_consistent(ArenaGeometry::new(
            3, 6
        )));
    }

    #[test]
    fn measured_diagnostics_match_resident_references_where_run() {
        let rows = run_diagnostic_sweep(0, 2, 2);
        for (relation_instance_variable_count, row) in rows.iter().enumerate() {
            assert_eq!(
                row.relation_instance_variable_count,
                relation_instance_variable_count as u32
            );
            assert_eq!(
                row.witness_column_count,
                4 * (1usize << relation_instance_variable_count)
            );
            assert_eq!(
                row.witness_variable_count,
                ROW_VARIABLE_COUNT + relation_instance_variable_count as u32 + 2
            );
            assert!(row.analytical_resident_raw_tree_peak_bytes > 0);
            assert!(row.measured_streaming_raw_tree_peak_bytes > 0);
            assert!(row.analytical_resident_sumcheck_peak_bytes > 0);
            assert!(row.measured_bounded_sumcheck_peak_bytes > 0);
            assert_eq!(row.sumcheck_messages_agree, Some(true));
            assert_eq!(row.raw_roots_agree, Some(true));
        }
    }

    #[test]
    fn an_unrun_resident_baseline_is_not_reported_as_agreement() {
        let rows = run_diagnostic_sweep(0, 2, 0);
        assert_eq!(rows[0].sumcheck_messages_agree, Some(true));
        assert_eq!(rows[0].raw_roots_agree, Some(true));
        assert_eq!(rows[1].sumcheck_messages_agree, None);
        assert_eq!(rows[1].raw_roots_agree, None);
        assert_eq!(rows[2].sumcheck_messages_agree, None);
        assert_eq!(rows[2].raw_roots_agree, None);
    }

    #[test]
    fn full_width_geometry_exceeds_the_pinned_pcs_memory_limits() {
        let geometry = ArenaGeometry::new(10, ROW_VARIABLE_COUNT);
        assert_eq!(geometry.witness_column_count(), 4_096);
        assert_eq!(geometry.witness_variable_count(), 26);

        let real_pcs_lower_bound = pinned_hiding_whir_allocation_lower_bound(26)
            .expect("the full-width PCS shape is representable");
        assert!(real_pcs_lower_bound.exceeds(256 * 1_048_576));
        assert!(real_pcs_lower_bound.exceeds(640 * 1_048_576));
    }

    #[test]
    fn native_diagnostic_digest_is_stable_for_wasm_parity() {
        let relation_instance_variable_count = 6_u32;
        let digest = diagnostic_run_digest(relation_instance_variable_count);
        assert_eq!(
            crate::hashing::to_hex(&digest),
            "cc1dcd1151a837eb18f0b52acf86ff992adecf9f2a9a2181b9f4ee3a4ee18765139d1440b9a5a1d60325d02ea2c6a6bda8d472411a9eafd4c5d68db41d267814"
        );
    }
}
