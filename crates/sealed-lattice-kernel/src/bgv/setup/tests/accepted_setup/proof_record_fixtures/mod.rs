use super::*;

/// Roster size declared by the package the proof fixtures bind. The proof
/// records, proof sets, and per-trustee enumeration all follow the package's
/// own participantCount so the fixtures build the right number of proofs for
/// any supported roster size.
pub(super) fn participant_count_from_package(package: &serde_json::Value) -> u64 {
    package["setupContext"]["participantCount"]
        .as_u64()
        .expect("participant count")
}

// The proof-bearing fixtures are split by proof family. Each sub-module begins
// with `use super::super::*;` (to reach the accepted_setup test glob) and
// `use super::*;` (to reach the shared work-item types here and the sibling
// fixture builders). The pub(super) re-exports keep every builder reachable
// through the accepted_setup glob so package_fixtures / material_transport_fixtures
// and the consuming tests import them unchanged.
mod compact_vss_public_material;
mod proof_checkpointing;
mod public_key_share_proofs;
mod same_secret_anchor_proofs;

pub(super) use compact_vss_public_material::compactify_collective_setup_package;
pub(super) use proof_checkpointing::*;
pub(super) use public_key_share_proofs::*;
pub(super) use same_secret_anchor_proofs::*;
