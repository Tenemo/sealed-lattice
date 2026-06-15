use super::*;

pub(super) const DIRECT_BALLOT_ACCEPTED_PUBLIC_KEY_MATERIAL_OBJECT_TYPE: &str =
    "DirectBallotAcceptedPublicKeyMaterial";
const ACCEPTED_SETUP_HANDOFF_OBJECT_TYPE: &str = "CollectiveBgvAcceptedSetupHandoff";
const ACCEPTED_DIRECT_BALLOT_HANDOFF_STATUS: &str =
    "accepted-collective-public-key-root-bound-for-direct-ballot-encryption";

pub(super) fn validate_direct_ballot_setup_handoff(
    accepted_public_key_material: &Value,
    accepted_setup_handoff: &Value,
) -> CanonicalResult<String> {
    reject_setup_handoff_secret_fields(accepted_public_key_material, "acceptedPublicKeyMaterial")?;
    reject_setup_handoff_secret_fields(accepted_setup_handoff, "acceptedSetupHandoff")?;
    verify_handoff_type_and_profile(accepted_setup_handoff)?;
    let accepted_setup_handoff_root = verify_accepted_setup_handoff_root(accepted_setup_handoff)?;
    verify_accepted_public_key_material_shape(
        accepted_public_key_material,
        accepted_setup_handoff,
        &accepted_setup_handoff_root,
    )?;
    verify_handoff_setup_binding(accepted_public_key_material, accepted_setup_handoff)?;
    verify_handoff_direct_ballot_binding(accepted_public_key_material, accepted_setup_handoff)?;

    Ok(accepted_setup_handoff_root)
}

fn verify_handoff_type_and_profile(accepted_setup_handoff: &Value) -> CanonicalResult<()> {
    if required_string_field(accepted_setup_handoff, "objectType")?
        != ACCEPTED_SETUP_HANDOFF_OBJECT_TYPE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectType,
            "acceptedSetupHandoff.objectType must be CollectiveBgvAcceptedSetupHandoff",
        ));
    }
    if required_u64_field(accepted_setup_handoff, "objectVersion")? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "acceptedSetupHandoff.objectVersion must be 1",
        ));
    }
    if required_string_field(accepted_setup_handoff, "setupProfileId")?
        != COLLECTIVE_BGV_SETUP_PROFILE_ID
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "acceptedSetupHandoff.setupProfileId must match the collective BGV setup profile",
        ));
    }

    Ok(())
}

fn verify_accepted_setup_handoff_root(accepted_setup_handoff: &Value) -> CanonicalResult<String> {
    let accepted_setup_handoff_root =
        required_string_field(accepted_setup_handoff, "acceptedSetupHandoffRoot")?;
    validate_direct_ballot_hash_hex(
        accepted_setup_handoff_root,
        "acceptedSetupHandoff.acceptedSetupHandoffRoot",
    )?;
    let mut hash_input = accepted_setup_handoff.clone();
    hash_input
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "acceptedSetupHandoff must be an object",
            )
        })?
        .remove("acceptedSetupHandoffRoot");
    let recomputed_handoff_root = derive_protocol_hash("AcceptedSetupHandoffRoot", &hash_input)?;
    if recomputed_handoff_root != accepted_setup_handoff_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "acceptedSetupHandoffRoot does not match the handoff payload",
        ));
    }

    Ok(accepted_setup_handoff_root.to_string())
}

fn verify_handoff_setup_binding(
    accepted_public_key_material: &Value,
    accepted_setup_handoff: &Value,
) -> CanonicalResult<()> {
    let setup_context = direct_ballot_setup_context(accepted_public_key_material)?;
    compare_handoff_hash(
        accepted_setup_handoff,
        "setupPackageHash",
        &setup_context.setup_package_root,
        "acceptedSetupHandoff.setupPackageHash",
    )?;
    compare_handoff_hash(
        accepted_setup_handoff,
        "manifestHash",
        &setup_context.manifest_hash,
        "acceptedSetupHandoff.manifestHash",
    )?;
    compare_handoff_hash(
        accepted_setup_handoff,
        "rosterHash",
        &setup_context.roster_hash,
        "acceptedSetupHandoff.rosterHash",
    )?;
    compare_handoff_hash(
        accepted_setup_handoff,
        "thresholdProfileHash",
        &setup_context.threshold_profile_hash,
        "acceptedSetupHandoff.thresholdProfileHash",
    )?;
    if required_string_field(accepted_setup_handoff, "ceremonyId")? != setup_context.ceremony_id {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "acceptedSetupHandoff.ceremonyId does not match acceptedPublicKeyMaterial",
        ));
    }

    Ok(())
}

fn verify_handoff_direct_ballot_binding(
    accepted_public_key_material: &Value,
    accepted_setup_handoff: &Value,
) -> CanonicalResult<()> {
    let direct_ballot_handoff =
        required_object_field(accepted_setup_handoff, "directBallotEncryptionHandoff")?;
    if required_string_field(direct_ballot_handoff, "status")?
        != ACCEPTED_DIRECT_BALLOT_HANDOFF_STATUS
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            "directBallotEncryptionHandoff.status is not accepted for direct ballot encryption",
        ));
    }
    let setup_context = direct_ballot_setup_context(accepted_public_key_material)?;
    let profile_binding = direct_ballot_profile_binding(accepted_public_key_material)?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "collectivePublicKeyRoot",
        &setup_context.collective_public_key_root,
        "directBallotEncryptionHandoff.collectivePublicKeyRoot",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "bgvPublicKeyRoot",
        &setup_context.bgv_public_key_root,
        "directBallotEncryptionHandoff.bgvPublicKeyRoot",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "bgvProfileHash",
        &profile_binding.bgv_profile_hash,
        "directBallotEncryptionHandoff.bgvProfileHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "canonicalCiphertextConventionHash",
        &canonical_ciphertext_convention_hash()?,
        "directBallotEncryptionHandoff.canonicalCiphertextConventionHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "batchEncoderHash",
        &profile_binding.batch_encoder_hash,
        "directBallotEncryptionHandoff.batchEncoderHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "batchLayoutBindingHash",
        &batch_layout_binding_hash()?,
        "directBallotEncryptionHandoff.batchLayoutBindingHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "ballotScoreEncodingProfileHash",
        &ballot_score_encoding_profile_hash()?,
        "directBallotEncryptionHandoff.ballotScoreEncodingProfileHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "encryptedBallotLayoutHash",
        &profile_binding.encrypted_ballot_layout_hash,
        "directBallotEncryptionHandoff.encryptedBallotLayoutHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "directBallotReservedSlotRuleHash",
        &profile_binding.direct_ballot_reserved_slot_rule_hash,
        "directBallotEncryptionHandoff.directBallotReservedSlotRuleHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "directBallotEncoderMatrixRoot",
        &profile_binding.direct_ballot_encoder_matrix_root,
        "directBallotEncryptionHandoff.directBallotEncoderMatrixRoot",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "witnessPartitionProfileHash",
        &direct_ballot_witness_partition_profile_hash()?,
        "directBallotEncryptionHandoff.witnessPartitionProfileHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "arithmeticCertificateHash",
        &direct_ballot_arithmetic_certificate_hash()?,
        "directBallotEncryptionHandoff.arithmeticCertificateHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "ballotValidityProofProfileHash",
        &direct_ballot_relation_proof_profile_hash()?,
        "directBallotEncryptionHandoff.ballotValidityProofProfileHash",
    )?;
    compare_handoff_hash(
        direct_ballot_handoff,
        "supportedBallotCreationPolicyHash",
        &direct_ballot_creation_policy_hash()?,
        "directBallotEncryptionHandoff.supportedBallotCreationPolicyHash",
    )?;
    if direct_ballot_handoff.get("supportedBallotCreationPolicy")
        != Some(&direct_ballot_creation_policy_value()?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "directBallotEncryptionHandoff.supportedBallotCreationPolicy does not match the selected direct ballot policy",
        ));
    }
    verify_handoff_public_key_material_summary(direct_ballot_handoff)?;

    Ok(())
}

fn verify_handoff_public_key_material_summary(
    direct_ballot_handoff: &Value,
) -> CanonicalResult<()> {
    let accepted_public_key_material =
        required_object_field(direct_ballot_handoff, "acceptedPublicKeyMaterial")?;
    for field_name in [
        "collectivePublicKeyRoot",
        "bgvPublicKeyRoot",
        "publicKeyShareMaterialSetRoot",
        "publicKeyShareSuccinctProofSetRoot",
    ] {
        if accepted_public_key_material.get(field_name) != direct_ballot_handoff.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "acceptedPublicKeyMaterial.{field_name} does not match directBallotEncryptionHandoff"
                ),
            ));
        }
    }

    Ok(())
}

fn verify_accepted_public_key_material_shape(
    accepted_public_key_material: &Value,
    accepted_setup_handoff: &Value,
    accepted_setup_handoff_root: &str,
) -> CanonicalResult<()> {
    if required_string_field(accepted_public_key_material, "objectType")?
        != DIRECT_BALLOT_ACCEPTED_PUBLIC_KEY_MATERIAL_OBJECT_TYPE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectType,
            "acceptedPublicKeyMaterial.objectType must be DirectBallotAcceptedPublicKeyMaterial",
        ));
    }
    if required_u64_field(accepted_public_key_material, "objectVersion")? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "acceptedPublicKeyMaterial.objectVersion must be 1",
        ));
    }
    if required_string_field(accepted_public_key_material, "setupProfileId")?
        != COLLECTIVE_BGV_SETUP_PROFILE_ID
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "acceptedPublicKeyMaterial.setupProfileId must match the collective BGV setup profile",
        ));
    }
    compare_material_hash(
        accepted_public_key_material,
        "acceptedSetupHandoffRoot",
        accepted_setup_handoff_root,
        "acceptedPublicKeyMaterial.acceptedSetupHandoffRoot",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "setupPackageHash",
        required_string_field(accepted_setup_handoff, "setupPackageHash")?,
        "acceptedPublicKeyMaterial.setupPackageHash",
    )?;
    compare_material_string(
        accepted_public_key_material,
        "ceremonyId",
        required_string_field(accepted_setup_handoff, "ceremonyId")?,
        "acceptedPublicKeyMaterial.ceremonyId",
    )?;
    for field_name in [
        "manifestHash",
        "rosterHash",
        "thresholdProfileHash",
        "setupProfileHash",
        "qShareHash",
        "commitmentProfileHash",
    ] {
        compare_material_hash(
            accepted_public_key_material,
            field_name,
            required_string_field(accepted_setup_handoff, field_name)?,
            &format!("acceptedPublicKeyMaterial.{field_name}"),
        )?;
    }
    compare_material_string(
        accepted_public_key_material,
        "setupEpoch",
        required_string_field(accepted_setup_handoff, "setupEpoch")?,
        "acceptedPublicKeyMaterial.setupEpoch",
    )?;

    let direct_ballot_handoff =
        required_object_field(accepted_setup_handoff, "directBallotEncryptionHandoff")?;
    let collective_public_key =
        required_object_field(accepted_public_key_material, "collectivePublicKey")?;
    verify_accepted_collective_public_key_root(collective_public_key)?;
    for field_name in [
        "collectivePublicKeyRoot",
        "publicKeyShareMaterialSetRoot",
        "publicKeyShareSuccinctProofSetRoot",
    ] {
        compare_material_hash(
            accepted_public_key_material,
            field_name,
            required_string_field(direct_ballot_handoff, field_name)?,
            &format!("acceptedPublicKeyMaterial.{field_name}"),
        )?;
        compare_material_hash(
            collective_public_key,
            field_name,
            required_string_field(direct_ballot_handoff, field_name)?,
            &format!("acceptedPublicKeyMaterial.collectivePublicKey.{field_name}"),
        )?;
    }
    let expected_bgv_public_key_root =
        accepted_direct_ballot_bgv_public_key_root(accepted_public_key_material)?;
    compare_material_hash(
        accepted_public_key_material,
        "bgvPublicKeyRoot",
        &expected_bgv_public_key_root,
        "acceptedPublicKeyMaterial.bgvPublicKeyRoot",
    )?;
    compare_material_hash(
        direct_ballot_handoff,
        "bgvPublicKeyRoot",
        &expected_bgv_public_key_root,
        "directBallotEncryptionHandoff.bgvPublicKeyRoot",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "bgvProfileHash",
        &profile_hash()?,
        "acceptedPublicKeyMaterial.bgvProfileHash",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "batchEncoderHash",
        &batch_encoder_hash()?,
        "acceptedPublicKeyMaterial.batchEncoderHash",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "batchLayoutBindingHash",
        &batch_layout_binding_hash()?,
        "acceptedPublicKeyMaterial.batchLayoutBindingHash",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "ballotScoreEncodingProfileHash",
        &ballot_score_encoding_profile_hash()?,
        "acceptedPublicKeyMaterial.ballotScoreEncodingProfileHash",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "encryptedBallotLayoutHash",
        &encrypted_ballot_layout_hash()?,
        "acceptedPublicKeyMaterial.encryptedBallotLayoutHash",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "directBallotReservedSlotRuleHash",
        &direct_ballot_reserved_slot_rule_hash()?,
        "acceptedPublicKeyMaterial.directBallotReservedSlotRuleHash",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "directBallotEncoderMatrixRoot",
        &direct_ballot_encoder_matrix_root()?,
        "acceptedPublicKeyMaterial.directBallotEncoderMatrixRoot",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "arithmeticCertificateHash",
        &direct_ballot_arithmetic_certificate_hash()?,
        "acceptedPublicKeyMaterial.arithmeticCertificateHash",
    )?;
    compare_material_hash(
        accepted_public_key_material,
        "ballotValidityProofProfileHash",
        required_string_field(direct_ballot_handoff, "ballotValidityProofProfileHash")?,
        "acceptedPublicKeyMaterial.ballotValidityProofProfileHash",
    )?;

    Ok(())
}

fn verify_accepted_collective_public_key_root(
    collective_public_key: &Value,
) -> CanonicalResult<()> {
    if required_string_field(collective_public_key, "objectType")? != "CollectivePublicKey" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectType,
            "acceptedPublicKeyMaterial.collectivePublicKey.objectType must be CollectivePublicKey",
        ));
    }
    if required_u64_field(collective_public_key, "objectVersion")? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "acceptedPublicKeyMaterial.collectivePublicKey.objectVersion must be 1",
        ));
    }
    let collective_public_key_root =
        required_string_field(collective_public_key, "collectivePublicKeyRoot")?;
    validate_direct_ballot_hash_hex(
        collective_public_key_root,
        "acceptedPublicKeyMaterial.collectivePublicKey.collectivePublicKeyRoot",
    )?;
    let mut root_input = collective_public_key.clone();
    root_input
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "acceptedPublicKeyMaterial.collectivePublicKey must be an object",
            )
        })?
        .remove("collectivePublicKeyRoot");
    let expected_collective_public_key_root =
        derive_protocol_hash("CollectivePublicKeyRoot", &root_input)?;
    if collective_public_key_root != expected_collective_public_key_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "acceptedPublicKeyMaterial.collectivePublicKeyRoot does not match the canonical collective public key",
        ));
    }

    Ok(())
}

pub(super) fn accepted_direct_ballot_bgv_public_key_root(
    accepted_public_key_material: &Value,
) -> CanonicalResult<String> {
    let common_randomness =
        required_object_field(accepted_public_key_material, "commonRandomness")?;
    let collective_public_key =
        required_object_field(accepted_public_key_material, "collectivePublicKey")?;
    let aggregate_limbs = collective_public_key
        .get("aggregateCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "acceptedPublicKeyMaterial.collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            )
        })?;
    let aggregate_limb_hashes = aggregate_limbs
    .iter()
    .map(|aggregate_limb| {
        Ok(json!({
            "rnsLimbIndex": required_u64_field(aggregate_limb, "rnsLimbIndex")?,
            "rnsPrime": required_u64_field(aggregate_limb, "rnsPrime")?,
            "component": required_string_field(aggregate_limb, "component")?,
            "coefficientByteLength": required_u64_field(aggregate_limb, "coefficientByteLength")?,
            "coefficientVectorHash512": required_string_field(
                aggregate_limb,
                "coefficientVectorHash512",
            )?,
        }))
    })
    .collect::<CanonicalResult<Vec<_>>>()?;

    derive_protocol_hash(
        "BGVPublicKeyRoot",
        &json!({
            "objectType": "AcceptedBgvPublicKeyRootBinding",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "bgvProfileHash": profile_hash()?,
            "collectivePublicKeyRoot": required_string_field(
                collective_public_key,
                "collectivePublicKeyRoot",
            )?,
            "publicMatrixSeedHash": required_string_field(
                common_randomness,
                "publicMatrixSeedHash",
            )?,
            "publicAPolynomialRoot": required_string_field(
                collective_public_key,
                "publicAPolynomialRoot",
            )?,
            "publicKeyShareMaterialSetRoot": required_string_field(
                collective_public_key,
                "publicKeyShareMaterialSetRoot",
            )?,
            "publicKeyShareSuccinctProofSetRoot": required_string_field(
                collective_public_key,
                "publicKeyShareSuccinctProofSetRoot",
            )?,
            "aggregateCoefficientVectorHashesByLimb": aggregate_limb_hashes,
        }),
    )
}

fn compare_material_hash(
    value: &Value,
    field_name: &str,
    expected_hash: &str,
    label: &str,
) -> CanonicalResult<()> {
    validate_direct_ballot_hash_hex(expected_hash, label)?;
    let actual_hash = required_string_field(value, field_name)?;
    validate_direct_ballot_hash_hex(actual_hash, label)?;
    if actual_hash != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match the accepted setup handoff"),
        ));
    }

    Ok(())
}

fn compare_material_string(
    value: &Value,
    field_name: &str,
    expected_value: &str,
    label: &str,
) -> CanonicalResult<()> {
    let actual_value = required_string_field(value, field_name)?;
    if actual_value != expected_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match the accepted setup handoff"),
        ));
    }

    Ok(())
}

fn compare_handoff_hash(
    value: &Value,
    field_name: &str,
    expected_hash: &str,
    label: &str,
) -> CanonicalResult<()> {
    validate_direct_ballot_hash_hex(expected_hash, label)?;
    let actual_hash = required_string_field(value, field_name)?;
    validate_direct_ballot_hash_hex(actual_hash, label)?;
    if actual_hash != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match acceptedPublicKeyMaterial"),
        ));
    }

    Ok(())
}

fn reject_setup_handoff_secret_fields(value: &Value, object_path: &str) -> CanonicalResult<()> {
    for field_name in [
        "setupPrivateWitness",
        "setupSeed",
        "privateSetupSeed",
        "privateSetupSeedHex",
        "ballotEncryptionRandomness",
        "proofMaskRandomness",
        "proofWitness",
        "proofRandomnessSeed",
        "proofRandomnessSeedHex",
        "developmentPlaintext",
        "oracleResult",
    ] {
        if value_contains_object_field(value, field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path} must not contain {field_name}"),
            ));
        }
    }

    Ok(())
}

fn value_contains_object_field(value: &Value, field_name: &str) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, child)| {
            key == field_name || value_contains_object_field(child, field_name)
        }),
        Value::Array(array) => array
            .iter()
            .any(|child| value_contains_object_field(child, field_name)),
        _ => false,
    }
}
