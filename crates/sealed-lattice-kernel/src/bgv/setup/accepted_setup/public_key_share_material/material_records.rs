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
    let decoded_material = decode_verified_canonical_public_key_share_material(
        material,
        roster.participant_count,
        ring_degree,
    )?;

    let mut bindings = BTreeMap::new();
    let mut material_root_references = Vec::new();
    for expected_roster_position in 0..roster.participant_count {
        let material_record = decoded_material
            .records
            .get(expected_roster_position as usize)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material is missing a trustee record",
                )
            })?;
        let share_record = share_records
            .get(&expected_roster_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "public-key share material must reference an accepted share record",
                )
            })?;
        let public_key_share_root = derive_public_key_share_root(
            setup_context,
            common_binding.public_matrix_seed_hash.as_str(),
            expected_roster_position,
            share_record,
        )?;
        let share_hashes = share_record
            .get("shareCoefficientVectorHashesByLimb")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "accepted public-key share hashes are required",
                )
            })?;
        let mut coefficients_by_limb = Vec::with_capacity(DATA_PRIMES.len());
        let mut limb_records = Vec::with_capacity(DATA_PRIMES.len());
        for rns_limb_index in 0..DATA_PRIMES.len() {
            let material_limb = &material_record.limbs[rns_limb_index];
            let coefficient_hash =
                public_key_share_coefficient_vector_hash(&material_limb.coefficients);
            if share_hashes.get(rns_limb_index).and_then(Value::as_str)
                != Some(coefficient_hash.as_str())
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "public-key share coefficient hash must match the accepted share record",
                ));
            }
            limb_records.push(coefficient_vector_le_hex(&material_limb.coefficients));
            coefficients_by_limb.push(material_limb.coefficients.clone());
        }
        let material_root_input = json!({
            "objectType": PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE,
            "setupContextHash": setup_context_hash(setup_context)?,
            "trusteeRosterPosition": expected_roster_position,
            "publicMatrixSeedHash": common_binding.public_matrix_seed_hash.as_str(),
            "publicKeyShareRoot": public_key_share_root.as_str(),
            "shareCoefficientVectorsLittleEndianHexByLimb": limb_records,
        });
        let public_key_share_material_root = derive_canonical_object_hash(&material_root_input)?;
        let binding = PublicKeyShareMaterialBinding {
            coefficients_by_limb,
        };
        material_root_references.push(json!({
            "trusteeRosterPosition": expected_roster_position,
            "publicKeyShareMaterialRoot": public_key_share_material_root,
        }));
        bindings.insert(expected_roster_position, binding);
    }
    Ok((bindings, material_root_references))
}

pub(in super::super) fn verify_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    public_key_share_set_root: &str,
    share_records: &BTreeMap<u64, Value>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<BTreeMap<u64, PublicKeyShareMaterialBinding>> {
    if !material_set.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "publicKeyShareMaterial must be a root-bound object",
        ));
    }
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "publicKeyShareMaterial.objectType must be PublicKeyShareMaterialSet",
        ));
    }
    let (bindings, material_root_references) = verify_stored_public_key_share_material_set(
        material_set,
        setup_context,
        common_binding,
        ring_degree,
        share_records,
        proof_binding_session,
    )?;
    let material_set_root = value_string(material_set, "publicKeyShareMaterialSetRoot")?;
    validate_hash_string(
        material_set_root,
        "publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
    )?;
    let root_input = json!({
        "objectType": PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE,
        "setupContextHash": setup_context_hash(setup_context)?,
        "publicMatrixSeedHash": common_binding.public_matrix_seed_hash.as_str(),
        "publicKeyShareSetRoot": public_key_share_set_root,
        "publicKeyShareMaterialRoots": material_root_references,
    });
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if material_set_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "publicKeyShareMaterialSetRoot does not match the canonical public-key share material set",
        ));
    }

    Ok(bindings)
}
