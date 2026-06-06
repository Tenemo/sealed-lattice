use super::*;
use crate::bgv::setup::key_material::collective_public_key_coefficient_root;

pub(super) fn validate_collective_public_key(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    profile_hash: &str,
    backend_profile_hash: &str,
) -> CanonicalResult<()> {
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let collective_public_key_record = value_at_path(collective_public_key, &["record"])?;
    compare_string_at_path(
        collective_public_key_record,
        &["objectType"],
        "BgvCollectivePublicKey",
        "collective public key object type",
    )?;
    compare_hash_at_path(
        collective_public_key_record,
        &["profileHash"],
        profile_hash,
        "collective public key profile hash",
    )?;
    compare_hash_at_path(
        collective_public_key_record,
        &["backendProfileHash"],
        backend_profile_hash,
        "collective public key backend profile hash",
    )?;
    if usize_at_path(collective_public_key_record, &["participantCount"])?
        != participant_bindings.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key participant count does not match participant records",
        ));
    }
    let expected_public_key_share_roots = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.public_key_share_root.clone()))
        .collect::<Vec<_>>();
    if array_at_path(collective_public_key_record, &["publicKeyShareRoots"])?
        != &expected_public_key_share_roots
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key share roots do not match participant records",
        ));
    }
    let coefficient_material = value_at_path(collective_public_key, &["coefficientMaterial"])?;
    validate_collective_public_key_coefficient_material(
        coefficient_material,
        collective_public_key_record,
        participant_bindings,
    )?;
    let expected_coefficient_root = collective_public_key_coefficient_root(coefficient_material)?;
    compare_hash_at_path(
        collective_public_key,
        &["collectivePublicKeyCoefficientRoot"],
        &expected_coefficient_root,
        "collective public key coefficient root",
    )?;
    compare_hash_at_path(
        collective_public_key_record,
        &["collectivePublicKeyCoefficientRoot"],
        &expected_coefficient_root,
        "collective public key record coefficient root",
    )?;

    let collective_public_key_root =
        hash_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    compare_derived_hash(
        "CollectivePublicKeyRoot",
        collective_public_key_record,
        collective_public_key_root,
        "collective public key root",
    )?;
    let expected_bgv_public_key_root = derive_protocol_hash(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "collectivePublicKeyCoefficientRoot": expected_coefficient_root,
            "profileHash": profile_hash,
            "backendProfileHash": backend_profile_hash,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;
    compare_hash_at_path(
        collective_public_key,
        &["bgvPublicKeyRoot"],
        &expected_bgv_public_key_root,
        "BGV public key root",
    )
}

fn validate_collective_public_key_coefficient_material(
    coefficient_material: &Value,
    collective_public_key_record: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
) -> CanonicalResult<()> {
    compare_string_at_path(
        coefficient_material,
        &["objectType"],
        "BgvCollectivePublicKeyCoefficientMaterial",
        "collective public key coefficient material object type",
    )?;
    if usize_at_path(coefficient_material, &["objectVersion"])? != 1
        || usize_at_path(coefficient_material, &["level"])? != DATA_PRIMES.len() - 1
        || usize_at_path(coefficient_material, &["coefficientCount"])? != POLYNOMIAL_DEGREE
        || usize_at_path(coefficient_material, &["participantCount"])? != participant_bindings.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key coefficient material shape does not match the selected setup profile",
        ));
    }
    compare_string_at_path(
        coefficient_material,
        &["basisId"],
        BgvBasisKind::Data.basis_id(),
        "collective public key coefficient basis",
    )?;
    compare_string_at_path(
        coefficient_material,
        &["fullCoefficientExpansionOwner"],
        "passive setup package public key material",
        "collective public key coefficient material owner",
    )?;
    if !bool_at_path(
        coefficient_material,
        &["fullCoefficientVectorHashesComputed"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key coefficient material must bind full coefficient vector hashes",
        ));
    }
    let expected_public_key_share_roots = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.public_key_share_root.clone()))
        .collect::<Vec<_>>();
    if array_at_path(coefficient_material, &["publicKeyShareRoots"])?
        != &expected_public_key_share_roots
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key coefficient material share roots do not match participant records",
        ));
    }
    compare_hash_at_path(
        coefficient_material,
        &["publicCommonRandomPolynomialRoot"],
        string_at_path(
            collective_public_key_record,
            &["publicCommonRandomPolynomialRoot"],
        )?,
        "collective public key coefficient material CRP root",
    )?;
    let expected_participants = participant_bindings
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity,
                "rosterPosition": participant.roster_position,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    if array_at_path(coefficient_material, &["participants"])? != &expected_participants {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key coefficient material participants do not match participant records",
        ));
    }

    let coefficient_tables = array_at_path(coefficient_material, &["coefficientTables"])?;
    let modulus_summaries = array_at_path(coefficient_material, &["modulusSummaries"])?;
    if coefficient_tables.len() != DATA_PRIMES.len() || modulus_summaries.len() != DATA_PRIMES.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key coefficient material must include one table and summary per data prime",
        ));
    }
    for (modulus_index, modulus) in DATA_PRIMES.iter().enumerate() {
        validate_coefficient_table(&coefficient_tables[modulus_index], *modulus)?;
        let summary = &modulus_summaries[modulus_index];
        if unsigned_at_path(summary, &["modulus"])? != *modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public key coefficient summary modulus does not match the selected data basis",
            ));
        }
        for field_name in [
            "componentZeroCoefficientHash512",
            "componentOneCoefficientHash512",
        ] {
            compare_hash_at_path(
                summary,
                &[field_name],
                string_at_path(&coefficient_tables[modulus_index], &[field_name])?,
                "collective public key coefficient summary hash",
            )?;
        }
        compare_string_at_path(
            summary,
            &["fullCoefficientVectorHashStatus"],
            "bound-in-setup-package",
            "collective public key coefficient vector hash status",
        )?;
    }

    Ok(())
}

fn validate_coefficient_table(table: &Value, expected_modulus: u64) -> CanonicalResult<()> {
    if unsigned_at_path(table, &["modulus"])? != expected_modulus
        || usize_at_path(table, &["coefficientByteLength"])? != POLYNOMIAL_DEGREE * 8
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key coefficient table shape does not match the selected data basis",
        ));
    }
    for (hex_field_name, hash_field_name) in [
        (
            "componentZeroCoefficientsLeHex",
            "componentZeroCoefficientHash512",
        ),
        (
            "componentOneCoefficientsLeHex",
            "componentOneCoefficientHash512",
        ),
    ] {
        let bytes = crate::transcript_core::decode_hex(string_at_path(table, &[hex_field_name])?)?;
        if bytes.len() != POLYNOMIAL_DEGREE * 8 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "collective public key coefficient table byte length is invalid",
            ));
        }
        let expected_hash = hash512_hex(
            "sealed-lattice-bgv-rns/public-key-coefficient-vector-v1",
            &[&bytes],
        );
        compare_hash_at_path(
            table,
            &[hash_field_name],
            &expected_hash,
            "collective public key coefficient table hash",
        )?;
    }

    Ok(())
}

pub(super) fn validate_threshold_verification_material(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    threshold_decryption_profile_hash: &str,
    kllps_target_decryption_profile_hash: &str,
) -> CanonicalResult<()> {
    let threshold_material = value_at_path(setup_package, &["thresholdVerificationMaterial"])?;
    let verification_key_set = value_at_path(threshold_material, &["verificationKeySet"])?;
    let expected_participant_setup_record_hashes = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.participant_setup_record_hash.clone()))
        .collect::<Vec<_>>();
    let expected_trustee_threshold_verification_key_hashes = participant_bindings
        .iter()
        .map(|participant| {
            Value::String(participant.trustee_threshold_verification_key_hash.clone())
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantSetupRecordHashes"])?
        != &expected_participant_setup_record_hashes
        || array_at_path(
            verification_key_set,
            &["trusteeThresholdVerificationKeyHashes"],
        )? != &expected_trustee_threshold_verification_key_hashes
        || array_at_path(
            threshold_material,
            &["trusteeThresholdVerificationKeyHashes"],
        )? != &expected_trustee_threshold_verification_key_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "threshold verification material does not match participant setup records",
        ));
    }

    let expected_interpolation_universe = participant_bindings
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity,
                "rosterPosition": participant.roster_position,
                "interpolationPoint": participant.roster_position + 1,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantInterpolationUniverse"])?
        != &expected_interpolation_universe
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "threshold interpolation universe does not match participant setup records",
        ));
    }
    validate_algebraic_share_verification_key_set(
        setup_package,
        threshold_material,
        verification_key_set,
        participant_bindings,
        threshold_decryption_profile_hash,
        kllps_target_decryption_profile_hash,
    )?;

    let threshold_share_verification_key_root =
        hash_at_path(threshold_material, &["thresholdShareVerificationKeyRoot"])?;
    compare_derived_hash(
        "ThresholdShareVerificationKeyRoot",
        verification_key_set,
        threshold_share_verification_key_root,
        "threshold share verification key root",
    )?;
    let expected_threshold_share_verification_key_hash = derive_protocol_hash(
        "ThresholdShareVerificationKeyHash",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
            "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        }),
    )?;
    compare_hash_at_path(
        threshold_material,
        &["thresholdShareVerificationKeyHash"],
        &expected_threshold_share_verification_key_hash,
        "threshold share verification key hash",
    )
}

fn validate_algebraic_share_verification_key_set(
    setup_package: &Value,
    threshold_material: &Value,
    verification_key_set: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    threshold_decryption_profile_hash: &str,
    kllps_target_decryption_profile_hash: &str,
) -> CanonicalResult<()> {
    let algebraic_key_set =
        value_at_path(verification_key_set, &["algebraicShareVerificationKeySet"])?;
    compare_string_at_path(
        algebraic_key_set,
        &["objectType"],
        "BgvThresholdLsssShareVerificationKeySet",
        "algebraic threshold share verification key set object type",
    )?;
    compare_string_at_path(
        algebraic_key_set,
        &["profileId"],
        THRESHOLD_LSSS_SHARE_VERIFICATION_PROFILE_ID,
        "algebraic threshold share verification profile id",
    )?;
    compare_string_at_path(
        algebraic_key_set,
        &["thresholdDecryptionProfileId"],
        THRESHOLD_DECRYPTION_PROFILE_ID,
        "algebraic threshold share verification decryption profile id",
    )?;
    compare_hash_at_path(
        algebraic_key_set,
        &["thresholdDecryptionProfileHash"],
        threshold_decryption_profile_hash,
        "algebraic threshold share verification decryption profile hash",
    )?;
    compare_hash_at_path(
        algebraic_key_set,
        &["kllpsTargetDecryptionProfileHash"],
        kllps_target_decryption_profile_hash,
        "algebraic threshold share verification KLLPS profile hash",
    )?;
    compare_hash_at_path(
        algebraic_key_set,
        &["thresholdProfileHash"],
        string_at_path(setup_package, &["setupInputs", "thresholdProfileHash"])?,
        "algebraic threshold share verification threshold profile hash",
    )?;
    if usize_at_path(algebraic_key_set, &["participantCount"])? != participant_bindings.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "algebraic threshold share verification participant count does not match setup",
        ));
    }
    let expected_decryption_threshold = ((participant_bindings.len().saturating_sub(1)) / 3) + 1;
    if usize_at_path(algebraic_key_set, &["decryptionThreshold"])? != expected_decryption_threshold
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "algebraic threshold share verification decryption threshold does not match the selected setup profile",
        ));
    }
    compare_string_at_path(
        algebraic_key_set,
        &["basisId"],
        BgvBasisKind::Data.basis_id(),
        "algebraic threshold share verification basis id",
    )?;
    if usize_at_path(algebraic_key_set, &["dataPrimeCount"])? != DATA_PRIMES.len()
        || usize_at_path(algebraic_key_set, &["polynomialDegree"])? != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "algebraic threshold share verification profile dimensions do not match BGV setup",
        ));
    }
    compare_string_at_path(
        algebraic_key_set,
        &["algebraicPartDecProofStatus"],
        "ZeroKnowledgeShareEquationProofPending",
        "algebraic PartDec proof status",
    )?;
    compare_string_at_path(
        algebraic_key_set,
        &["finDecShareCombinationStatus"],
        "FinDecCorrectnessAndSmudgingBoundsPending",
        "FinDec share-combination status",
    )?;
    compare_string_at_path(
        algebraic_key_set,
        &["maskReEncryptionProofStatus"],
        "MaskReEncryptionProofPending",
        "mask re-encryption proof status",
    )?;
    compare_string_at_path(
        algebraic_key_set,
        &["publicKeyShareCoefficientMaterialStatus"],
        "root-bound-public-sidecar-required",
        "public key-share coefficient material status",
    )?;
    if bool_at_path(algebraic_key_set, &["lsssSecretSharesExported"])? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "algebraic threshold share verification key set must not export LSSS secret shares",
        ));
    }

    let algebraic_key_root =
        hash_at_path(threshold_material, &["algebraicShareVerificationKeyRoot"])?;
    compare_derived_hash(
        "AlgebraicThresholdShareVerificationKeyRoot",
        algebraic_key_set,
        algebraic_key_root,
        "algebraic threshold share verification key root",
    )?;
    compare_hash_at_path(
        verification_key_set,
        &["algebraicShareVerificationKeyRoot"],
        algebraic_key_root,
        "threshold verification key-set algebraic key root",
    )?;
    let expected_algebraic_key_hash = derive_protocol_hash(
        "AlgebraicThresholdShareVerificationKeyHash",
        &json!({
            "algebraicShareVerificationKeyRoot": algebraic_key_root,
            "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
            "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        }),
    )?;
    compare_hash_at_path(
        threshold_material,
        &["algebraicShareVerificationKeyHash"],
        &expected_algebraic_key_hash,
        "algebraic threshold share verification key hash",
    )?;
    compare_hash_at_path(
        verification_key_set,
        &["algebraicShareVerificationKeyHash"],
        &expected_algebraic_key_hash,
        "threshold verification key-set algebraic key hash",
    )?;

    let trustee_keys = array_at_path(algebraic_key_set, &["trusteeVerificationKeys"])?;
    let participant_records = array_at_path(setup_package, &["participants"])?;
    if trustee_keys.len() != participant_bindings.len()
        || participant_records.len() != participant_bindings.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "algebraic threshold share verification trustee keys must match setup participants",
        ));
    }
    let expected_public_key_share_coefficient_material_roots = trustee_keys
        .iter()
        .map(|trustee_key| {
            hash_at_path(trustee_key, &["publicKeyShareCoefficientMaterialRoot"])
                .map(|hash| Value::String(hash.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let expected_public_key_share_coefficient_material_hashes = trustee_keys
        .iter()
        .map(|trustee_key| {
            hash_at_path(trustee_key, &["publicKeyShareCoefficientMaterialHash"])
                .map(|hash| Value::String(hash.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if array_at_path(
        algebraic_key_set,
        &["publicKeyShareCoefficientMaterialRoots"],
    )? != &expected_public_key_share_coefficient_material_roots
        || array_at_path(
            algebraic_key_set,
            &["publicKeyShareCoefficientMaterialHashes"],
        )? != &expected_public_key_share_coefficient_material_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public key-share coefficient material roots do not match trustee keys",
        ));
    }
    for ((trustee_key, participant_binding), participant_record) in trustee_keys
        .iter()
        .zip(participant_bindings.iter())
        .zip(participant_records.iter())
    {
        validate_trustee_algebraic_share_verification_key(
            trustee_key,
            participant_binding,
            participant_record,
            threshold_decryption_profile_hash,
            kllps_target_decryption_profile_hash,
        )?;
    }

    Ok(())
}

fn validate_trustee_algebraic_share_verification_key(
    trustee_key: &Value,
    participant_binding: &VerifiedParticipantSetupBinding,
    participant_record: &Value,
    threshold_decryption_profile_hash: &str,
    kllps_target_decryption_profile_hash: &str,
) -> CanonicalResult<()> {
    compare_string_at_path(
        trustee_key,
        &["objectType"],
        "BgvTrusteeAlgebraicThresholdShareVerificationKey",
        "trustee algebraic share verification key object type",
    )?;
    compare_string_at_path(
        trustee_key,
        &["profileId"],
        THRESHOLD_LSSS_SHARE_VERIFICATION_PROFILE_ID,
        "trustee algebraic share verification profile id",
    )?;
    compare_hash_at_path(
        trustee_key,
        &["thresholdDecryptionProfileHash"],
        threshold_decryption_profile_hash,
        "trustee algebraic share verification decryption profile hash",
    )?;
    compare_hash_at_path(
        trustee_key,
        &["kllpsTargetDecryptionProfileHash"],
        kllps_target_decryption_profile_hash,
        "trustee algebraic share verification KLLPS profile hash",
    )?;
    compare_string_at_path(
        trustee_key,
        &["trusteeIdentity"],
        &participant_binding.trustee_identity,
        "trustee algebraic share verification identity",
    )?;
    if usize_at_path(trustee_key, &["rosterPosition"])? != participant_binding.roster_position
        || usize_at_path(trustee_key, &["interpolationPoint"])?
            != participant_binding.roster_position + 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "trustee algebraic share verification interpolation point does not match setup",
        ));
    }
    compare_hash_at_path(
        trustee_key,
        &["participantSetupRecordHash"],
        &participant_binding.participant_setup_record_hash,
        "trustee algebraic share verification participant record hash",
    )?;
    compare_hash_at_path(
        trustee_key,
        &["publicKeyShareRoot"],
        &participant_binding.public_key_share_root,
        "trustee algebraic share verification public key-share root",
    )?;
    let public_key_share_coefficient_material_root =
        hash_at_path(trustee_key, &["publicKeyShareCoefficientMaterialRoot"])?;
    let expected_public_key_share_coefficient_material_hash = derive_protocol_hash(
        "TrusteePublicKeyShareCoefficientMaterialHash",
        &json!({
            "publicKeyShareCoefficientMaterialRoot": public_key_share_coefficient_material_root,
            "publicKeyShareRoot": participant_binding.public_key_share_root,
            "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
            "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        }),
    )?;
    compare_hash_at_path(
        trustee_key,
        &["publicKeyShareCoefficientMaterialHash"],
        &expected_public_key_share_coefficient_material_hash,
        "trustee public key-share coefficient material hash",
    )?;
    compare_string_at_path(
        trustee_key,
        &["publicKeyShareCoefficientMaterialTransport"],
        "root-bound-public-sidecar-required-for-claim-bearing-PartDec-verification",
        "trustee public key-share coefficient material transport",
    )?;
    if bool_at_path(trustee_key, &["publicKeyShareCoefficientMaterialIncluded"])? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "trustee public key-share coefficient material must stay as a root-bound sidecar",
        ));
    }
    compare_hash_at_path(
        trustee_key,
        &["trusteeThresholdVerificationKeyHash"],
        &participant_binding.trustee_threshold_verification_key_hash,
        "trustee algebraic share verification trustee key hash",
    )?;
    compare_hash_at_path(
        trustee_key,
        &["localSecretShareCommitmentHash"],
        hash_at_path(participant_record, &["localSecretShareCommitmentHash"])?,
        "trustee algebraic share verification local secret commitment hash",
    )?;
    compare_hash_at_path(
        trustee_key,
        &["localErrorCommitmentHash"],
        hash_at_path(participant_record, &["localErrorCommitmentHash"])?,
        "trustee algebraic share verification local error commitment hash",
    )?;
    hash_at_path(trustee_key, &["thresholdLsssWitnessCommitmentHash"])?;
    compare_string_at_path(
        trustee_key,
        &["proofSystemStatus"],
        "ZeroKnowledgeShareEquationProofPending",
        "trustee algebraic share proof status",
    )?;
    if !bool_at_path(trustee_key, &["shareEquationProofRequired"])?
        || bool_at_path(trustee_key, &["rawSecretShareExported"])?
        || bool_at_path(trustee_key, &["thresholdSecretShareExported"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "trustee algebraic share verification key has invalid proof/export flags",
        ));
    }

    Ok(())
}
