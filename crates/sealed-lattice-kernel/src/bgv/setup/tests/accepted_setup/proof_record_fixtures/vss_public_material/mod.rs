use super::*;

use crate::bgv::setup::setup_proof::SetupProofMaterialTransportHashes;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    generate_same_secret_bridge_proof_from_request, generate_vss_share_linkage_proof_from_request,
};
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

const VSS_PUBLIC_COMMITMENT_BINARY_FORMAT: &str = "sealed-lattice-vss-public-commitment-binary";
const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "vss-share-linkage";
const VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/proof-bytes";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const SAME_SECRET_BRIDGE_RELATION: &str = "target-basis constant coefficient commitments bind to the same signed ternary trustee secret as the source data-basis VSS constant commitments";
const SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb";
const SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime";
const SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER: &str = "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime";
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

    package
}

pub(in super::super) use finalized_package::finalize_collective_setup_package;
