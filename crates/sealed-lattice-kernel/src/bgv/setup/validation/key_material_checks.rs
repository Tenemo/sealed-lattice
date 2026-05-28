use super::*;

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
