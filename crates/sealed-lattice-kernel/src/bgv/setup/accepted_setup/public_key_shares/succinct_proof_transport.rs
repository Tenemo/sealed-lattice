use super::*;

use crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY;

pub(super) fn public_key_share_succinct_proof_bytes_from_record(
    proof_record: &Value,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(
        proof_material_root,
        "publicKeyShareSuccinctProof.proofMaterialRoot",
    )?;
    let proof_bytes = take_verified_setup_proof_material_bytes(
        PUBLIC_KEY_SHARE_PROOF_FAMILY,
        proof_material_root,
        "publicKeyShareSuccinctProof.proofMaterialRoot",
        Some(proof_binding_session),
    )?;
    let expected_material_root = public_key_share_succinct_proof_material_root(proof_record)?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proofMaterialRoot must match the canonical proof material reference",
        ));
    }

    Ok(proof_bytes)
}

// Semantic identity for one public-key share proof material. Transport
// framing and digests belong exclusively to the canonical stream descriptor.
pub(in crate::bgv::setup) fn public_key_share_succinct_proof_material_root(
    proof_record: &Value,
) -> CanonicalResult<String> {
    crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        PUBLIC_KEY_SHARE_PROOF_FAMILY,
        value_string(proof_record, "proofBytesHash")?,
    )
}
