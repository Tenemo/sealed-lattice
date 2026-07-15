use super::*;

use crate::bgv::setup::same_secret_bridge::SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN;
use crate::bgv::setup::vss_commitment::VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN;
use crate::hashing::{derive_canonical_object_hash, hash512_hex};

const VSS_MATERIAL_SEED_DOMAIN: &str = "sealed-lattice/accepted-setup/vss-material-seed";

struct VssProofRecordFixture {
    record: serde_json::Value,
}

struct VssProofRecordSetFixture {
    proof_bytes_hashes: Vec<String>,
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

// These bytes are deliberately not a proof. They give structural fixtures a
// correctly bound, deterministic proof reference so tests can authenticate the
// transport and prove that the common-proof verifier gate still refuses it.
pub(super) fn invalid_common_proof_fixture_bytes(
    proof_family: &str,
    verification_input: &serde_json::Value,
) -> Vec<u8> {
    let verification_input_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "InvalidCommonProofFixtureVerificationInput",
        "proofFamily": proof_family,
        "verificationInput": verification_input,
    }))
    .expect("invalid common-proof fixture verification-input hash");
    format!(
        "sealed-lattice/test-only/invalid-common-proof/v1/{proof_family}/{verification_input_hash}"
    )
    .into_bytes()
}

pub(super) fn invalid_common_proof_fixture_hash(
    proof_family: &str,
    proof_bytes_hash_domain: &str,
    verification_input: &serde_json::Value,
) -> String {
    let proof_bytes = invalid_common_proof_fixture_bytes(proof_family, verification_input);
    hash512_hex(proof_bytes_hash_domain, &[&proof_bytes])
}

const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "vss-share-linkage";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";

// Builds the smallest package needed to exercise the public VSS and
// same-secret structural verifiers. The broader accepted-setup package fixture
// still starts from the legacy coefficient-root view before finalization, so
// using it here would fail while constructing unrelated private-share
// acceptances. This fixture starts with the canonical source material needed
// by the bridge, then lets the ordinary finalizer attach the public views.
fn structural_vss_public_material_fixture() -> FinalizedCollectiveSetupPackageFixture {
    const PARTICIPANT_COUNT: u64 = 3;
    const RING_DEGREE: usize = 128;

    let ceremony_id = "structural-vss-public-material";
    let manifest_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "ElectionManifestHash",
        "fixture": "structural-vss-public-material",
    }))
    .expect("structural VSS manifest hash");
    let roster_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "CollectiveBgvSetupRosterHash",
        "participantCount": PARTICIPANT_COUNT,
    }))
    .expect("structural VSS roster hash");
    let setup_parameters_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "CollectiveBgvSetupParametersHash",
        "participantCount": PARTICIPANT_COUNT,
        "ringDegree": RING_DEGREE,
    }))
    .expect("structural VSS setup parameters hash");
    let setup_epoch = "structural-vss-setup-epoch";
    let public_matrix_seed_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "CollectiveBgvPublicMatrixSeedHash",
        "ceremonyId": ceremony_id,
    }))
    .expect("structural VSS public matrix seed hash");
    let (vss_coefficient_commitments, vss_coefficient_commitment_material) =
        structural_same_secret_source_commitments(
            ceremony_id,
            &manifest_hash,
            &roster_hash,
            &setup_parameters_hash,
            setup_epoch,
            &public_matrix_seed_hash,
            RING_DEGREE,
            PARTICIPANT_COUNT,
        );
    let package = serde_json::json!({
        "objectType": "SetupPackage",
        "setupContext": {
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "participantCount": PARTICIPANT_COUNT,
        },
        "commonRandomness": {
            "publicMatrixSeedHash": public_matrix_seed_hash,
        },
        "vssCoefficientCommitments": vss_coefficient_commitments,
        "vssCoefficientCommitmentMaterial": vss_coefficient_commitment_material,
    });

    finalized_package::finalize_collective_setup_package(package)
}

#[allow(clippy::too_many_arguments)]
fn structural_same_secret_source_commitments(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    participant_count: u64,
) -> (serde_json::Value, serde_json::Value) {
    let setup_context_hash =
        crate::bgv::setup::accepted_setup::setup_context_hash(&serde_json::json!({
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "participantCount": participant_count,
        }))
        .expect("structural VSS setup context hash");
    let threshold_degree = participant_count / 3 + 1;
    let mut source_trustee_records = Vec::new();
    let mut coefficient_commitments = Vec::new();

    for source_trustee_roster_position in 0..participant_count {
        let mut coefficient_commitment_roots = Vec::new();
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..threshold_degree {
                let coefficient_message = accepted_vss_coefficient_message_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    rns_prime,
                    ring_degree,
                )
                .into_iter()
                .map(u128::from)
                .collect::<Vec<_>>();
                let randomness_by_column = accepted_vss_randomness_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    ring_degree,
                );
                let commitment = compute_setup_commitment_for_tests(
                    public_matrix_seed_hash,
                    rns_limb_index,
                    shamir_coefficient_index,
                    &coefficient_message,
                    &randomness_by_column,
                    ring_degree,
                )
                .expect("structural same-secret source commitment");
                coefficient_commitment_roots.push(
                    setup_commitment_root(&commitment)
                        .expect("structural same-secret source commitment root"),
                );
                coefficient_commitments.push(setup_commitment_full_value(&commitment));
            }
        }
        source_trustee_records.push(serde_json::json!({
            "objectType": "VssSourceTrusteeCoefficientCommitments",
            "sourceTrusteeIdentity": format!("trustee-{source_trustee_roster_position}"),
            "coefficientCommitmentRoots": coefficient_commitment_roots,
        }));
    }

    (
        serde_json::json!({
            "objectType": "VssCoefficientCommitmentSet",
            "setupContextHash": setup_context_hash,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "sourceTrusteeRecords": source_trustee_records,
        }),
        serde_json::json!({
            "objectType": "VssCoefficientCommitmentMaterialSet",
            "setupContextHash": setup_context_hash,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "participantCount": participant_count,
            "thresholdDegree": threshold_degree,
            "rnsLimbCount": DATA_PRIMES.len(),
            "ringDegree": ring_degree,
            "coefficientCommitments": coefficient_commitments,
        }),
    )
}

mod aggregate_threshold;
mod commitment_sets;
mod finalized_package;
mod same_secret_bridge;
mod share_linkage;
mod transport;

// Builds only the two aggregate coordinates needed by the direct-verifier
// mutation test. Its proof references are deliberately invalid common-proof
// fixtures; unrelated accepted-setup proof families are not generated.
pub(in super::super) struct CompactAggregateThresholdProofFixture {
    pub(in super::super) package: serde_json::Value,
    pub(in super::super) proof_binding_leases:
        Vec<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

pub(in super::super) fn compact_aggregate_threshold_proof_fixture(
) -> CompactAggregateThresholdProofFixture {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(&package);
    package["vssPublicCoefficientCommitmentSet"] =
        commitment_sets::vss_public_coefficient_commitment_set_object(&package, ring_degree);
    package["vssPublicRecipientShareCommitmentSet"] =
        commitment_sets::vss_public_recipient_share_commitment_set_object(&package);
    let mut aggregate_threshold_commitment_set =
        commitment_sets::vss_public_aggregate_threshold_commitment_set_without_proofs_for_coordinates(
            &package,
            &[(0, 0), (0, 1)],
        );
    let aggregate_threshold_proofs = aggregate_threshold::vss_aggregate_threshold_proofs(
        &package,
        &aggregate_threshold_commitment_set,
        &[(0, 0), (0, 1)],
    );
    aggregate_threshold_commitment_set["aggregateThresholdProofBytesHashes"] =
        serde_json::json!(aggregate_threshold_proofs.proof_bytes_hashes);
    package["vssPublicAggregateThresholdCommitmentSet"] = aggregate_threshold_commitment_set;

    CompactAggregateThresholdProofFixture {
        package,
        proof_binding_leases: aggregate_threshold_proofs.proof_binding_leases,
    }
}

pub(in super::super) use finalized_package::{
    finalize_collective_setup_package, FinalizedCollectiveSetupPackageFixture,
};
pub(in super::super) use transport::descriptor_backed_vss_proof_material_fixture;
