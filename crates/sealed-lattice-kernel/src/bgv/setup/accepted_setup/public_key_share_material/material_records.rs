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
            "public-key share material participant count does not match the accepted roster",
        ));
    }
    if material.ring_degree != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public-key share material ring degree must match the material set",
        ));
    }

    let mut bindings = BTreeMap::new();
    let mut material_root_references = Vec::new();
    for expected_roster_position in 0..roster.participant_count {
        let material_record = material
            .records
            .get(expected_roster_position as usize)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material is missing a trustee record",
                )
            })?;
        if material_record.trustee_roster_position != expected_roster_position {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share material trustee order is not canonical",
            ));
        }
        let share_record = share_records
            .get(&expected_roster_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public-key share material must reference an accepted share record",
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
        if material_record.limbs.len() != DATA_PRIMES.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material must contain one coefficient vector per Q_share limb",
            ));
        }
        for rns_limb_index in 0..DATA_PRIMES.len() {
            let material_limb = &material_record.limbs[rns_limb_index];
            if material_limb.coefficients.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share coefficient vector width does not match the material ring degree",
                ));
            }
            let coefficient_hash =
                public_key_share_coefficient_vector_hash(&material_limb.coefficients);
            if share_hashes
                .get(rns_limb_index)
                .and_then(|share_hash| share_hash.get("coefficientVectorHash512"))
                .and_then(Value::as_str)
                != Some(coefficient_hash.as_str())
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "public-key share coefficient hash must match the accepted share record",
                ));
            }
            limb_records.push(json!({
                "coefficientsLeHex": coefficient_vector_le_hex(&material_limb.coefficients),
            }));
            coefficients_by_limb.push(material_limb.coefficients.clone());
        }
        let material_root_input = json!({
            "objectType": PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE,
            "setupContextHash": setup_context_hash(setup_context)?,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": expected_roster_position,
            "publicMatrixSeedHash": common_binding.public_matrix_seed_hash.as_str(),
            "publicKeyShareRoot": public_key_share_root.as_str(),
            "shareCoefficientVectorsByLimb": limb_records,
        });
        let public_key_share_material_root = derive_canonical_object_hash(&material_root_input)?;
        let binding = PublicKeyShareMaterialBinding {
            trustee_identity,
            trustee_roster_position: expected_roster_position,
            public_key_share_root,
            public_key_share_material_root,
            coefficients_by_limb,
        };
        material_root_references.push(public_key_share_material_root_reference(&binding));
        if bindings
            .insert(binding.trustee_roster_position, binding)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share material contains duplicate trustee records",
            ));
        }
    }
    Ok((bindings, material_root_references))
}

pub(in super::super) fn verify_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    public_key_share_set_root: &str,
    share_records: &BTreeMap<u64, Value>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
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
    let ring_degree = POLYNOMIAL_DEGREE;
    let (bindings, material_root_references) = verify_stored_public_key_share_material_set(
        material_set,
        setup_context,
        common_binding,
        ring_degree,
        share_records,
        proof_binding_session,
    )?;
    let serialized_material_roots = material_set
        .get("publicKeyShareMaterialRoots")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.publicKeyShareMaterialRoots must be an ordered array",
            )
        })?;
    if serialized_material_roots.len() != material_root_references.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "publicKeyShareMaterial.publicKeyShareMaterialRoots must match the ordered material records",
        ));
    }
    for (serialized_material_root, material_root_reference) in serialized_material_roots
        .iter()
        .zip(&material_root_references)
    {
        let serialized_material_root = serialized_material_root.as_str().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.publicKeyShareMaterialRoots entries must be protocol hashes",
            )
        })?;
        validate_hash_string(
            serialized_material_root,
            "publicKeyShareMaterial.publicKeyShareMaterialRoots",
        )?;
        if serialized_material_root
            != value_string(material_root_reference, "publicKeyShareMaterialRoot")?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "publicKeyShareMaterial.publicKeyShareMaterialRoots must match the ordered material records",
            ));
        }
    }
    let material_set_root = value_string(material_set, "publicKeyShareMaterialSetRoot")?;
    validate_hash_string(
        material_set_root,
        "publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
    )?;
    let root_input = json!({
        "objectType": PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE,
        "setupContextHash": setup_context_hash(setup_context)?,
        "ringDegree": ring_degree,
        "publicMatrixSeedHash": common_binding.public_matrix_seed_hash.as_str(),
        "publicKeyShareSetRoot": public_key_share_set_root,
        "publicKeyShareMaterialRoots": material_root_references,
    });
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if material_set_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterialSetRoot does not match the canonical public-key share material set",
        ));
    }

    Ok(bindings)
}
