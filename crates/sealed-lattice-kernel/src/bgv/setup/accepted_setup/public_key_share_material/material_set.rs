use super::material_records::decode_public_key_share_material_bindings;
use super::*;

pub(super) fn verify_transport_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    request: &Value,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    let Some(transported_material) = request.get("transportedPublicKeyShareMaterial") else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial is required for binary-chunked public-key share material",
        ));
    };
    if !transported_material.is_object()
        || transported_material
            .get("objectType")
            .and_then(Value::as_str)
            != Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial must be a SetupTransportedPublicKeyShareMaterial object",
        ));
    }
    let transported_material_root =
        value_string(transported_material, "publicKeyShareMaterialSetRoot")?;
    validate_hash_string(
        transported_material_root,
        "transportedPublicKeyShareMaterial.publicKeyShareMaterialSetRoot",
    )?;
    if material_set
        .get("publicKeyShareMaterialSetRoot")
        .and_then(Value::as_str)
        != Some(transported_material_root)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transported public-key share material root must match the public-key share material set",
        ));
    }
    let verified_material = crate::bgv::setup::accepted_setup_public_key_share_material(
        proof_binding_session.session_handle,
        transported_material_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share material was not accepted by the canonical stream verifier",
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

pub(super) fn public_key_share_material_root_reference(
    binding: &PublicKeyShareMaterialBinding,
) -> Value {
    json!({
        "trusteeIdentity": binding.trustee_identity,
        "trusteeRosterPosition": binding.trustee_roster_position,
        "publicKeyShareMaterialRoot": binding.public_key_share_material_root,
    })
}
