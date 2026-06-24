use super::*;

pub(super) struct EvaluationKeyShareFixtureMaterial {
    pub(super) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(super) component_vector_entries: Vec<serde_json::Value>,
    pub(super) component_vector_root: String,
}

pub(super) struct RelinearizationKeyShareRoundsFixture {
    pub(super) rounds: serde_json::Value,
    pub(super) round_one_aggregate_diagonals_by_level: BTreeMap<u64, Vec<Vec<u64>>>,
}

pub(super) struct TrusteeEvaluationKeyProofWorkItem {
    pub(super) trustee_roster_position: u64,
    pub(super) statement:
        crate::bgv::setup::trustee_evaluation_key_proof::TrusteeEvaluationKeyStatement,
    pub(super) record: serde_json::Value,
}

#[derive(Clone)]
pub(super) struct BuiltTrusteeEvaluationKeyProofRecord {
    pub(super) record: serde_json::Value,
    pub(super) transported_proof_material: Option<serde_json::Value>,
}

// Maximum number of trustee evaluation-key provers that run concurrently while
// assembling the first-profile package fixture. Each first-profile prover holds
// its statement, witness, and proof working set, which is several gigabytes, so
// proving all ten trustees at once needs far more than physical memory and
// forces heavy paging. Generating the proofs in batches of this size keeps
// per-trustee proving parallel (each batch member still uses the shared work
// pool for its internal parallelism) while capping concurrent prover memory.
// Three fits a workstation-class machine; a memory-constrained host such as a
// 16 GiB CI runner exports SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE through the
// memory-aware heavy test runner so the build stays within available memory
// instead of being killed mid-proving.
const DEFAULT_TRUSTEE_EVALUATION_KEY_PROOF_GENERATION_BATCH_SIZE: usize = 3;

/// Roster size declared by the package the proof fixtures bind. The proof
/// records, proof sets, and per-trustee enumeration all follow the package's
/// own participantCount so the fixtures build the right number of proofs for
/// any supported roster size.
pub(super) fn participant_count_from_package(package: &serde_json::Value) -> u64 {
    package["setupContext"]["participantCount"]
        .as_u64()
        .expect("participant count")
}

/// An explicit `SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE` override when the
/// memory-aware heavy test runner (or an operator) set one. When present it is
/// authoritative for terminal proving concurrency, so a memory-constrained
/// runner serializes provers regardless of how many cores it reports; absent,
/// the terminal proving path derives concurrency from the core count instead.
pub(super) fn explicit_trustee_proof_batch_size_override() -> Option<usize> {
    std::env::var("SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE")
        .ok()
        .and_then(|configured_batch_size| configured_batch_size.parse::<usize>().ok())
        .filter(|configured_batch_size| *configured_batch_size >= 1)
}

pub(super) fn trustee_evaluation_key_proof_generation_batch_size() -> usize {
    explicit_trustee_proof_batch_size_override()
        .unwrap_or(DEFAULT_TRUSTEE_EVALUATION_KEY_PROOF_GENERATION_BATCH_SIZE)
}

// The proof-bearing fixtures are split by proof family. Each sub-module begins
// with `use super::super::*;` (to reach the accepted_setup test glob) and
// `use super::*;` (to reach the shared work-item types here and the sibling
// fixture builders). The pub(super) re-exports keep every builder reachable
// through the accepted_setup glob so package_fixtures / material_transport_fixtures
// and the consuming tests import them unchanged.
mod evaluation_key_share_component_material;
mod galois_key_share_batches;
mod proof_checkpointing;
mod public_evaluation_key_assembly;
mod public_key_share_proofs;
mod relinearization_key_share_rounds;
mod same_secret_anchor_proofs;
mod trustee_evaluation_key_proofs;

pub(super) use evaluation_key_share_component_material::*;
pub(super) use galois_key_share_batches::*;
pub(super) use proof_checkpointing::*;
pub(super) use public_evaluation_key_assembly::*;
pub(super) use public_key_share_proofs::*;
pub(super) use relinearization_key_share_rounds::*;
pub(super) use same_secret_anchor_proofs::*;
pub(super) use trustee_evaluation_key_proofs::*;
