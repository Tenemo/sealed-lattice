use super::*;

use crate::bgv::setup::same_secret_bridge::SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    generate_same_secret_bridge_proof_from_request, generate_vss_share_linkage_proof_from_request,
    verify_same_secret_bridge_proof_source_from_request,
    verify_vss_share_linkage_proof_source_from_request,
};
use crate::bgv::setup::vss_commitment::VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN;
use crate::hashing::{derive_canonical_object_hash, hash512_hex};

const VSS_MATERIAL_SEED_DOMAIN: &str = "sealed-lattice/accepted-setup/vss-material-seed";

struct VssProofRecordFixture {
    record: serde_json::Value,
    proof_binding_lease: crate::bgv::setup::CanonicalSetupProofBindingLease,
}

struct VssProofRecordSetFixture {
    records: Vec<serde_json::Value>,
    proof_binding_leases: Vec<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

struct VssProofMaterialSetFixture {
    value: serde_json::Value,
    proof_binding_leases: Vec<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

pub(super) fn vss_fixture_threshold_degree(package: &serde_json::Value) -> u64 {
    participant_count_from_package(package) / 3 + 1
}

// The canonical committed-material commitment-context hash for a role and
// context, identical to the hash `compute_vss_committed_material_commitment`
// derives internally, so a record builder can compute it before committing.
pub(super) fn accepted_committed_material_context_hash(
    commitment_role: &str,
    commitment_context: &serde_json::Value,
) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssCommittedMaterialCommitmentContext",
        "commitmentRole": commitment_role,
        "commitmentContext": commitment_context,
    }))
    .expect("committed-material commitment context hash")
}

// The holder's private deterministic material seed, derived from the public
// commitment-context hash. Both the record builder (which computes the context
// hash before committing) and the proof-request builder (which reads
// commitmentContextHash off the published commitment) reproduce the same seed,
// so the prover regenerates byte-identical trees without the seed appearing in
// the package.
pub(super) fn accepted_vss_material_seed(commitment_context_hash: &str) -> String {
    hash512_hex(
        VSS_MATERIAL_SEED_DOMAIN,
        &[commitment_context_hash.as_bytes()],
    )
}

pub(super) struct SameSecretBridgeCommittedMaterialRegenerationInputs {
    pub(super) seeds_by_bound_message: Vec<String>,
    pub(super) context_hashes_by_bound_message: Vec<String>,
}

pub(super) fn same_secret_bridge_target_constant_records_from_fixture_package(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> Vec<&serde_json::Value> {
    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let threshold_degree = vss_fixture_threshold_degree(package) as usize;
    let q_share_rns_limb_count = DATA_PRIMES.len();
    let source_record = &coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("target coefficient source records")[trustee_roster_position as usize];
    let coefficient_records = source_record["coefficientCommitments"]
        .as_array()
        .expect("target coefficient records");

    (0..q_share_rns_limb_count)
        .map(|rns_limb_index| &coefficient_records[rns_limb_index * threshold_degree])
        .collect()
}

pub(super) fn same_secret_bridge_committed_material_regeneration_inputs_from_fixture_package(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> SameSecretBridgeCommittedMaterialRegenerationInputs {
    let context_hashes_by_bound_message =
        same_secret_bridge_target_constant_records_from_fixture_package(
            package,
            trustee_roster_position,
        )
        .iter()
        .map(|coefficient_record| {
            coefficient_record["commitment"]["commitmentContextHash"]
                .as_str()
                .expect("bridge target commitment context hash")
                .to_string()
        })
        .collect::<Vec<_>>();
    let seeds_by_bound_message = context_hashes_by_bound_message
        .iter()
        .map(|context_hash| accepted_vss_material_seed(context_hash))
        .collect::<Vec<_>>();

    SameSecretBridgeCommittedMaterialRegenerationInputs {
        seeds_by_bound_message,
        context_hashes_by_bound_message,
    }
}

const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "vss-share-linkage";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
pub(in super::super) const VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "vss-share-linkage-proof-material";

mod aggregate_threshold;
mod commitment_sets;
mod finalized_package;
mod same_secret_bridge;
mod share_linkage;
mod transport;

// Builds only the two aggregate coordinates needed by the direct-verifier
// mutation test. The aggregate proofs still use the content-addressed proof
// checkpoint store; unrelated accepted-setup proof families are not generated.
pub(in super::super) struct CompactAggregateThresholdProofFixture {
    pub(in super::super) package: serde_json::Value,
    pub(in super::super) proof_binding_leases:
        Vec<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

pub(in super::super) fn compact_aggregate_threshold_proof_fixture()
-> CompactAggregateThresholdProofFixture {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(&package);
    package["vssPublicCoefficientCommitmentSet"] =
        commitment_sets::vss_public_coefficient_commitment_set_object(&package, ring_degree);
    package["vssPublicRecipientShareCommitmentSet"] =
        commitment_sets::vss_public_recipient_share_commitment_set_object(&package);
    let mut aggregate_threshold_commitment_set =
        commitment_sets::vss_public_aggregate_threshold_commitment_set_without_proofs_for_coordinates(
            &package,
            &[(0, 0), (1, 0)],
        );
    let aggregate_threshold_proofs = aggregate_threshold::vss_aggregate_threshold_proofs(
        &package,
        &aggregate_threshold_commitment_set,
        &[(0, 0), (1, 0)],
    );
    aggregate_threshold_commitment_set["aggregateThresholdProofs"] =
        serde_json::json!(aggregate_threshold_proofs.records);
    package["vssPublicAggregateThresholdCommitmentSet"] = aggregate_threshold_commitment_set;

    CompactAggregateThresholdProofFixture {
        package,
        proof_binding_leases: aggregate_threshold_proofs.proof_binding_leases,
    }
}

pub(in super::super) use finalized_package::{
    FinalizedCollectiveSetupPackageFixture, finalize_collective_setup_package,
};
pub(in super::super) use transport::descriptor_backed_vss_proof_material_fixture;
