use super::*;

// Public key-switch component material for one evaluation-key share and its
// canonical component-vector root, as the deterministic fixture builders
// assemble it before moving the vectors into authenticated transport.
pub(super) struct EvaluationKeyShareFixtureMaterial {
    pub(super) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(super) component_vector_root: String,
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
/// any configurable roster size.
pub(super) fn participant_count_from_package(package: &serde_json::Value) -> u64 {
    package["setupContext"]["participantCount"]
        .as_u64()
        .expect("participant count")
}

pub(in super::super) fn vss_commitment_ring_degree_from_fixture_package(
    package: &serde_json::Value,
) -> usize {
    let ring_degree = package["vssShareLinkageStatement"]["ringDegree"]
        .as_u64()
        .or_else(|| package["vssCoefficientCommitmentMaterial"]["ringDegree"].as_u64())
        .expect("VSS coefficient commitment ring degree");
    usize::try_from(ring_degree).expect("VSS coefficient commitment ring degree fits usize")
}

mod evaluation_key_share_component_material;
mod vss_public_material;

pub(super) use vss_public_material::{
    FinalizedCollectiveSetupPackageFixture, finalize_collective_setup_package,
    vss_public_coefficient_commitment_record,
};
