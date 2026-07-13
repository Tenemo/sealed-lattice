use super::material_records::*;
use super::transport::verified_canonical_public_key_share_material;
use super::*;

pub(in super::super) fn public_key_share_material_uses_transport(material_set: &Value) -> bool {
    // Presence is sufficient for transport preflight. Full verification also
    // checks the materialEncoding discriminator and the selected structure.
    material_set.get("shareMaterialRecords").is_none()
}

pub(super) fn verify_embedded_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    if material_set.get("transport").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "embedded public-key share material must not declare binary transport fields",
        ));
    }
    let material_records = material_set
        .get("shareMaterialRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.shareMaterialRecords are required",
            )
        })?;
    let roster = super::accepted_roster_from_setup_context(setup_context);
    if material_records.len() != roster.participant_count as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "publicKeyShareMaterial.shareMaterialRecords must contain one record per trustee",
        ));
    }
    let mut bindings = BTreeMap::new();
    let mut material_roots = Vec::new();
    for material_record in material_records {
        let binding = verify_public_key_share_material_record(
            material_record,
            setup_context,
            common_binding,
            ring_degree,
            share_records,
        )?;
        if bindings
            .insert(binding.trustee_roster_position, binding.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.shareMaterialRecords contain duplicate roster positions",
            ));
        }
        material_roots.push(public_key_share_material_root_reference(&binding));
    }

    Ok((bindings, material_roots))
}

pub(super) fn verify_transport_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    request: &Value,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    if material_set.get("shareMaterialRecords").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary-chunked public-key share material must not embed shareMaterialRecords",
        ));
    }
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
    let verified_material = verified_canonical_public_key_share_material(
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
