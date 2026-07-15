use super::*;

use crate::bgv::setup::setup_proof::take_verified_setup_proof_material_bytes;
use crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY;

pub(super) fn public_key_share_succinct_proof_bytes_from_hash(
    proof_bytes_hash: &str,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<SetupProofMaterialBytes> {
    validate_hash_string(
        proof_bytes_hash,
        "publicKeyShareSuccinctProof.proofBytesHash",
    )?;
    take_verified_setup_proof_material_bytes(
        PUBLIC_KEY_SHARE_PROOF_FAMILY,
        proof_bytes_hash,
        "publicKeyShareSuccinctProof.proofBytesHash",
        Some(proof_binding_session),
    )
}
