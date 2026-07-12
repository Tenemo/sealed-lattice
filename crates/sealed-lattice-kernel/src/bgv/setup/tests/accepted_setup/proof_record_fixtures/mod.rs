use super::*;

// Public key-switch component material for one evaluation-key share and its
// canonical component-vector root, as the deterministic fixture builders
// assemble it before moving the vectors into authenticated transport.
pub(super) struct EvaluationKeyShareFixtureMaterial {
    pub(super) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(super) component_vector_root: String,
}

// The relinearization key-share rounds object and the per-level public
// round-one aggregate diagonals recomputed while building it.
pub(super) struct RelinearizationKeyShareRoundsFixture {
    pub(super) rounds: serde_json::Value,
    pub(super) round_one_aggregate_diagonals_by_level: BTreeMap<u64, Vec<Vec<u64>>>,
    pub(super) transported_component_materials: Vec<serde_json::Value>,
}

// The Galois key-share batches and their authenticated component-material
// descriptors. Keeping the two together prevents a package record from being
// assembled without the request-side material that production verification
// resolves by root.
pub(super) struct GaloisKeyShareBatchesFixture {
    pub(super) batches: serde_json::Value,
    pub(super) transported_component_materials: Vec<serde_json::Value>,
}

pub(in super::super) fn source_constant_commitments_from_fixture_package(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> Vec<crate::bgv::setup::commitment::SetupCommitmentValue> {
    let trustee_identity = format!("trustee-{trustee_roster_position}");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let ring_degree = package["vssCoefficientCommitmentMaterial"]["ringDegree"]
        .as_u64()
        .expect("VSS coefficient commitment material ring degree") as usize;
    crate::bgv::setup::source_constant_commitments::canonical_source_constant_commitments_from_vss_material(
        &package["vssCoefficientCommitments"],
        &package["vssCoefficientCommitmentMaterial"],
        &trustee_identity,
        trustee_roster_position,
        public_matrix_seed_hash,
        ring_degree,
    )
    .expect("canonical source constant commitments")
    .commitments
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

pub(in super::super) fn public_coefficient_commitment_ring_degree_from_fixture_package(
    package: &serde_json::Value,
) -> usize {
    usize::try_from(
        package["vssPublicCoefficientCommitmentSet"]["ringDegree"]
            .as_u64()
            .expect("public VSS coefficient commitment ring degree"),
    )
    .expect("public VSS coefficient commitment ring degree fits usize")
}

// The proof-bearing fixtures are split by proof family. Sub-modules use
// `super::*` to reach the shared work-item types here and sibling fixture
// builders, and only import the accepted_setup test glob when they need it.
// The pub(super) re-exports keep every builder reachable through the
// accepted_setup glob so package_fixtures / material_transport_fixtures and the
// consuming tests import them unchanged.
mod evaluation_key_share_component_material;
mod galois_key_share_batches;
mod proof_checkpointing;
mod public_evaluation_key_assembly;
mod public_key_share_proofs;
mod relinearization_key_share_rounds;
mod trustee_evaluation_key_proofs;
mod vss_public_material;

pub(super) use evaluation_key_share_component_material::*;
pub(super) use galois_key_share_batches::*;
pub(super) use proof_checkpointing::*;
pub(super) use public_evaluation_key_assembly::*;
pub(super) use public_key_share_proofs::*;
pub(super) use relinearization_key_share_rounds::*;
pub(super) use trustee_evaluation_key_proofs::*;
pub(super) use vss_public_material::{
    DescriptorBackedVssProofMaterialFixture, compact_aggregate_threshold_proof_fixture,
    descriptor_backed_vss_proof_material_fixture, finalize_collective_setup_package,
};
