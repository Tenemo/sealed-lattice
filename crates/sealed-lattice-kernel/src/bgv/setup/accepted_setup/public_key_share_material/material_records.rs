use super::material_set::*;
use super::transport::*;
use super::*;

pub(super) fn decode_public_key_share_material_bindings(
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    material: &VerifiedCanonicalPublicKeyShareMaterial,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    let roster = super::accepted_roster_from_setup_context(setup_context)?;
    if material.records.len() != roster.participant_count as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transported public-key share material participant count does not match the accepted roster",
        ));
    }
    if material.ring_degree != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transported public-key share material ring degree must match the material set",
        ));
    }

    let mut bindings = BTreeMap::new();
    let mut material_roots = Vec::new();
    for expected_roster_position in 0..roster.participant_count {
        let transported_record = material
            .records
            .get(expected_roster_position as usize)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "transported public-key share material is missing a trustee record",
                )
            })?;
        if transported_record.trustee_roster_position != expected_roster_position {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material trustee order is not canonical",
            ));
        }
        let share_record = share_records
            .get(&expected_roster_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported public-key share material must reference an accepted share record",
                )
            })?;
        let trustee_identity = value_string(share_record, "trusteeIdentity")?.to_string();
        let public_key_share_root = value_string(share_record, "publicKeyShareRoot")?.to_string();
        let share_hashes = share_record
            .get("shareCoefficientVectorHash512ByLimb")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public-key share hashes are required",
                )
            })?;
        let mut coefficients_by_limb = Vec::with_capacity(DATA_PRIMES.len());
        let mut limb_records = Vec::with_capacity(DATA_PRIMES.len());
        if transported_record.limbs.len() != DATA_PRIMES.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "transported public-key share material must contain one coefficient vector per Q_share limb",
            ));
        }
        for rns_limb_index in 0..DATA_PRIMES.len() {
            let transported_limb = &transported_record.limbs[rns_limb_index];
            if transported_limb.coefficients.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "transported public-key share coefficient vector width does not match the material ring degree",
                ));
            }
            let coefficient_hash =
                public_key_share_coefficient_vector_hash(&transported_limb.coefficients);
            if share_hashes
                .get(rns_limb_index)
                .and_then(|share_hash| share_hash.get("coefficientVectorHash512"))
                .and_then(Value::as_str)
                != Some(coefficient_hash.as_str())
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "transported public-key share coefficient hash must match the accepted share record",
                ));
            }
            limb_records.push(json!({
                "coefficientsLeHex": coefficient_vector_le_hex(&transported_limb.coefficients),
            }));
            coefficients_by_limb.push(transported_limb.coefficients.clone());
        }
        let material_record = json!({
            "objectType": PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE,
            "ceremonyId": value_string(setup_context, "ceremonyId")?,
            "manifestHash": value_string(setup_context, "manifestHash")?,
            "rosterHash": value_string(setup_context, "rosterHash")?,
            "setupParametersHash": value_string(setup_context, "setupParametersHash")?,
            "setupEpoch": value_string(setup_context, "setupEpoch")?,
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": expected_roster_position,
            "publicMatrixSeedHash": common_binding.public_matrix_seed_hash,
            "publicKeyShareRoot": public_key_share_root,
            "shareCoefficientVectorsByLimb": limb_records,
        });
        let public_key_share_material_root = derive_canonical_object_hash(&material_record)?;
        let binding = PublicKeyShareMaterialBinding {
            trustee_identity: value_string(&material_record, "trusteeIdentity")?.to_string(),
            trustee_roster_position: expected_roster_position,
            public_key_share_root: value_string(&material_record, "publicKeyShareRoot")?
                .to_string(),
            public_key_share_material_root,
            coefficients_by_limb,
        };
        material_roots.push(public_key_share_material_root_reference(&binding));
        if bindings
            .insert(binding.trustee_roster_position, binding)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material contains duplicate trustee records",
            ));
        }
    }
    Ok((bindings, material_roots))
}

pub(in super::super) fn verify_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    public_key_share_set_root: &str,
    share_records: &BTreeMap<u64, Value>,
    request: &Value,
) -> CanonicalResult<BTreeMap<u64, PublicKeyShareMaterialBinding>> {
    if !material_set.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial must be a root-bound object",
        ));
    }
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.objectType must be PublicKeyShareMaterialSet",
        ));
    }
    verify_context_fields_match(material_set, setup_context, "publicKeyShareMaterial")?;
    let ring_degree = usize::try_from(value_u64(material_set, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "publicKeyShareMaterial.ringDegree does not fit usize",
        )
    })?;
    if ring_degree != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "publicKeyShareMaterial.ringDegree must match the accepted setup parameters",
        ));
    }
    if material_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
        || material_set
            .get("publicKeyShareSetRoot")
            .and_then(Value::as_str)
            != Some(public_key_share_set_root)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "publicKeyShareMaterial must bind accepted public randomness and public-key share set root",
        ));
    }
    let (bindings, material_roots) = verify_transport_public_key_share_material_set(
        material_set,
        setup_context,
        common_binding,
        ring_degree,
        share_records,
        request,
    )?;
    if material_set.get("publicKeyShareMaterialRoots") != Some(&Value::Array(material_roots)) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "publicKeyShareMaterial.publicKeyShareMaterialRoots must match the ordered material records",
        ));
    }
    let material_set_root = value_string(material_set, "publicKeyShareMaterialSetRoot")?;
    validate_hash_string(
        material_set_root,
        "publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
    )?;
    let mut root_input = material_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share material set object was checked")
        .remove("publicKeyShareMaterialSetRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if material_set_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterialSetRoot does not match the canonical public-key share material set",
        ));
    }

    Ok(bindings)
}

pub(super) fn verify_public_key_share_material_record(
    material_record: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
) -> CanonicalResult<PublicKeyShareMaterialBinding> {
    if !material_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material records must be objects",
        ));
    }
    if material_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material objectType must be PublicKeyShareMaterial",
        ));
    }
    verify_context_fields_match(
        material_record,
        setup_context,
        "publicKeyShareMaterial.materialRecords",
    )?;
    if material_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public-key share material must bind accepted public randomness",
        ));
    }
    let trustee_roster_position = value_u64(material_record, "trusteeRosterPosition")?;
    let trustee_identity = value_string(material_record, "trusteeIdentity")?.to_string();
    let share_record = share_records.get(&trustee_roster_position).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material must reference an accepted share record",
        )
    })?;
    if share_record.get("trusteeIdentity").and_then(Value::as_str)
        != Some(trustee_identity.as_str())
        || material_record
            .get("publicKeyShareRoot")
            .and_then(Value::as_str)
            != share_record
                .get("publicKeyShareRoot")
                .and_then(Value::as_str)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public-key share material trustee and share root must match the accepted share record",
        ));
    }
    let limbs = material_record
        .get("shareCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share material coefficients are required",
            )
        })?;
    if limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material must contain one coefficient vector per Q_share limb",
        ));
    }
    let share_hashes = share_record
        .get("shareCoefficientVectorHash512ByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public-key share hashes are required",
            )
        })?;
    let mut coefficients_by_limb = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, limb) in limbs.iter().enumerate() {
        let coefficients = coefficient_vector_from_le_hex(
            value_string(limb, "coefficientsLeHex")?,
            ring_degree,
            "public-key share coefficient vector width does not match the material ring degree",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public-key share coefficient vector contains a non-canonical residue",
            ));
        }
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if share_hashes
            .get(rns_limb_index)
            .and_then(|share_hash| share_hash.get("coefficientVectorHash512"))
            .and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public-key share material coefficient hash must match the accepted share record",
            ));
        }
        coefficients_by_limb.push(coefficients);
    }
    let public_key_share_material_root =
        value_string(material_record, "publicKeyShareMaterialRoot")?.to_string();
    validate_hash_string(
        &public_key_share_material_root,
        "publicKeyShareMaterial.shareMaterialRecords.publicKeyShareMaterialRoot",
    )?;
    let mut root_input = material_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share material record object was checked")
        .remove("publicKeyShareMaterialRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if public_key_share_material_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterialRoot does not match the canonical public-key share material",
        ));
    }

    Ok(PublicKeyShareMaterialBinding {
        trustee_identity,
        trustee_roster_position,
        public_key_share_root: value_string(material_record, "publicKeyShareRoot")?.to_string(),
        public_key_share_material_root,
        coefficients_by_limb,
    })
}
