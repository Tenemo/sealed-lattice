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

fn same_secret_bridge_committed_material_regeneration_inputs_from_statement_record(
    statement_record: &serde_json::Value,
) -> SameSecretBridgeCommittedMaterialRegenerationInputs {
    let context_hashes_by_bound_message = statement_record["targetConstantCoefficientCommitments"]
        .as_array()
        .expect("bridge target commitments")
        .iter()
        .map(|commitment_record| {
            commitment_record["commitment"]["commitmentContextHash"]
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

pub(super) fn same_secret_bridge_committed_material_regeneration_inputs_from_fixture_package(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> SameSecretBridgeCommittedMaterialRegenerationInputs {
    let matching_statement_records = package["sameSecretBridgeStatementSet"]["statementRecords"]
        .as_array()
        .expect("same-secret bridge statement records")
        .iter()
        .filter(|statement_record| {
            statement_record["trusteeRosterPosition"].as_u64() == Some(trustee_roster_position)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching_statement_records.len(),
        1,
        "one same-secret bridge statement must bind each trustee"
    );

    same_secret_bridge_committed_material_regeneration_inputs_from_statement_record(
        matching_statement_records[0],
    )
}

const VSS_PUBLIC_COMMITMENT_BINARY_FORMAT: &str = "sealed-lattice-vss-public-commitment-binary";
const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "vss-share-linkage";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const SAME_SECRET_BRIDGE_RELATION: &str = "public constant coefficient commitments bind to the same signed ternary trustee secret as the source VSS constant commitments across Q_share";
const SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound source and public commitment over Q_share";
const SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each Q_share RNS prime";
const SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER: &str = "target constant roots are ordered by contiguous Q_share rnsLimbIndex values starting at zero and bind the listed Q_share prime";
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
pub(in super::super) fn compact_aggregate_threshold_proof_fixture() -> serde_json::Value {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    let ring_degree = usize::try_from(
        package["vssCoefficientCommitmentMaterial"]["ringDegree"]
            .as_u64()
            .expect("VSS coefficient commitment material ring degree"),
    )
    .expect("VSS coefficient commitment material ring degree fits usize");
    package["vssPublicCoefficientCommitmentSet"] =
        commitment_sets::vss_public_coefficient_commitment_set_object(&package, ring_degree);
    package["vssPublicRecipientShareCommitmentSet"] =
        commitment_sets::vss_public_recipient_share_commitment_set_object(&package);
    let mut aggregate_threshold_commitment_set =
        commitment_sets::vss_public_aggregate_threshold_commitment_set_without_proofs_for_coordinates(
            &package,
            &[(0, 0), (1, 0)],
        );
    aggregate_threshold_commitment_set["aggregateThresholdProofs"] =
        serde_json::json!(aggregate_threshold::vss_aggregate_threshold_proofs(
            &package,
            &aggregate_threshold_commitment_set,
        ));
    package["vssPublicAggregateThresholdCommitmentSet"] = aggregate_threshold_commitment_set;
    aggregate_threshold::append_vss_aggregate_threshold_proof_material_transport(&mut package);

    package
}

pub(in super::super) use finalized_package::finalize_collective_setup_package;
pub(in super::super) use transport::descriptor_backed_vss_proof_material_fixture;
