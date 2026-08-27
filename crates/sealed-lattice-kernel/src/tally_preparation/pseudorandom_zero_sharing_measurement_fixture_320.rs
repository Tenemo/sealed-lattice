use sha3::{Digest, Sha3_512};

use crate::foundation::Hash512;

use super::pseudorandom_zero_sharing_subset_seed_320::PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH;

const ALL_ROSTER_ZERO_SHARING_MEASUREMENT_MASTER_DOMAIN: &[u8] =
    b"sealed-lattice/v1/diagnostic/all-roster-zero-sharing-master";

/// Derives one deterministic measurement-only master shared by every holder
/// of the same subset. This helper is absent from production builds.
pub(super) fn derive_all_roster_zero_sharing_measurement_master_320(
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    zero_sharing_catalog_identity: Hash512,
    excluded_position_mask: u32,
) -> [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH] {
    let mut derivation = Sha3_512::new();
    derivation.update(ALL_ROSTER_ZERO_SHARING_MEASUREMENT_MASTER_DOMAIN);
    derivation.update(parameter_identity.as_bytes());
    derivation.update(preparation_context_identity.as_bytes());
    derivation.update(zero_sharing_catalog_identity.as_bytes());
    derivation.update(excluded_position_mask.to_le_bytes());
    let digest = derivation.finalize();
    core::array::from_fn(|byte_position| digest[byte_position])
}
