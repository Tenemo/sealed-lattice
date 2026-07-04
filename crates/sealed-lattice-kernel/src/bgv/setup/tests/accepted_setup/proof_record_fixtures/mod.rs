use super::*;

// Public key-switch component material for one evaluation-key share, along with
// its canonical component-vector entries and root, as the deterministic fixture
// builders assemble it before it is embedded into a share record.
pub(super) struct EvaluationKeyShareFixtureMaterial {
    pub(super) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(super) component_vector_entries: Vec<serde_json::Value>,
    pub(super) component_vector_root: String,
}

// The relinearization key-share rounds object and the per-level public
// round-one aggregate diagonals recomputed while building it.
pub(super) struct RelinearizationKeyShareRoundsFixture {
    pub(super) rounds: serde_json::Value,
    pub(super) round_one_aggregate_diagonals_by_level: BTreeMap<u64, Vec<Vec<u64>>>,
}

/// Roster size declared by the package the proof fixtures bind. The proof
/// records, proof sets, and per-trustee enumeration all follow the package's
/// own participantCount so the fixtures build the right number of proofs for
/// any supported roster size.
pub(super) fn participant_count_from_package(package: &serde_json::Value) -> u64 {
    package["setupContext"]["participantCount"]
        .as_u64()
        .expect("participant count")
}

// The proof-bearing fixtures are split by proof family. Sub-modules use
// `super::*` to reach the shared work-item types here and sibling fixture
// builders, and only import the accepted_setup test glob when they need it.
// The pub(super) re-exports keep every builder reachable through the
// accepted_setup glob so package_fixtures / material_transport_fixtures and the
// consuming tests import them unchanged.
mod compact_vss_public_material;
mod evaluation_key_share_component_material;
mod galois_key_share_batches;
mod proof_checkpointing;
mod public_evaluation_key_assembly;
mod public_key_share_proofs;
mod relinearization_key_share_rounds;
mod same_secret_anchor_proofs;
mod trustee_evaluation_key_proofs;

pub(super) use compact_vss_public_material::compactify_collective_setup_package;
pub(super) use evaluation_key_share_component_material::*;
pub(super) use galois_key_share_batches::*;
pub(super) use proof_checkpointing::*;
pub(super) use public_evaluation_key_assembly::*;
pub(super) use public_key_share_proofs::*;
pub(super) use relinearization_key_share_rounds::*;
pub(super) use same_secret_anchor_proofs::*;
pub(super) use trustee_evaluation_key_proofs::*;
