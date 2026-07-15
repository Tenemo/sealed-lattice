use super::material_records::decode_public_key_share_material_bindings;
use super::*;

pub(super) fn verify_stored_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    let material_root = value_string(material_set, "publicKeyShareMaterialSetRoot")?;
    validate_hash_string(
        material_root,
        "publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
    )?;
    let verified_material = crate::bgv::setup::accepted_setup_public_key_share_material(
        proof_binding_session.session_handle,
        material_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material was not accepted by the canonical stream verifier",
        )
    })?;
    let (bindings, material_roots) = decode_public_key_share_material_bindings(
        setup_context,
        common_binding,
        ring_degree,
        share_records,
        &verified_material,
    )?;

    Ok((bindings, material_roots))
}
