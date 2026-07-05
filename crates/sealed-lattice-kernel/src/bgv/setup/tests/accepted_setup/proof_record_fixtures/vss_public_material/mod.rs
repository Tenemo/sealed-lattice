use super::*;

use crate::bgv::setup::setup_proof::SetupProofMaterialTransportHashes;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    generate_same_secret_bridge_proof_from_request, generate_vss_share_linkage_proof_from_request,
};
use crate::hashing::derive_canonical_object_hash;

const VSS_PUBLIC_COMMITMENT_BINARY_FORMAT: &str = "sealed-lattice-vss-public-commitment-binary-v1";
const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "vss-share-linkage";
const VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/proof-bytes-v1";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes-v1";
const SAME_SECRET_PROOF_FAMILY: &str = "same-secret-linkage-anchor";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const SAME_SECRET_BRIDGE_RELATION: &str = "target-basis constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof";
const SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb";
const SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime";
const SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER: &str = "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime";
pub(in super::super) const SAME_SECRET_BRIDGE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "same-secret-bridge-proof-material";
pub(in super::super) const VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "vss-share-linkage-proof-material";

mod commitment_sets;
mod finalized_package;
mod same_secret_bridge;
mod share_linkage;
mod transport;

pub(in super::super) use finalized_package::finalize_collective_setup_package;
pub(in super::super) use same_secret_bridge::vss_public_coefficient_randomness_i64_fixture;
