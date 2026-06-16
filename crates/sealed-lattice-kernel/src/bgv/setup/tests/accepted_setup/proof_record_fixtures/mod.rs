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
// pool for its internal parallelism) while capping concurrent prover memory to
// fit a workstation-class machine.
pub(super) const TRUSTEE_EVALUATION_KEY_PROOF_GENERATION_BATCH_SIZE: usize = 3;

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
