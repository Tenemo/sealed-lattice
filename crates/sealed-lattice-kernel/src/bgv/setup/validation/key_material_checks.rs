use super::*;

pub(super) fn validate_collective_public_key(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    profile_digest: &str,
    backend_profile_digest: &str,
) -> CanonicalResult<()> {
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let collective_public_key_record = value_at_path(collective_public_key, &["record"])?;
    compare_string_at_path(
        collective_public_key_record,
        &["objectType"],
        "BgvCollectivePublicKey",
        "collective public key object type",
    )?;
    compare_digest_at_path(
        collective_public_key_record,
        &["profileDigest"],
        profile_digest,
        "collective public key profile digest",
    )?;
    compare_digest_at_path(
        collective_public_key_record,
        &["backendProfileDigest"],
        backend_profile_digest,
        "collective public key backend profile digest",
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
        digest_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    compare_derived_digest(
        "CollectivePublicKeyRoot",
        collective_public_key_record,
        collective_public_key_root,
        "collective public key root",
    )?;
    let expected_bgv_public_key_root = derive_protocol_digest(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;
    compare_digest_at_path(
        collective_public_key,
        &["bgvPublicKeyRoot"],
        &expected_bgv_public_key_root,
        "BGV public key root",
    )
}

pub(super) fn validate_threshold_verification_material(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<()> {
    let threshold_material = value_at_path(setup_package, &["thresholdVerificationMaterial"])?;
    let verification_key_set = value_at_path(threshold_material, &["verificationKeySet"])?;
    let expected_participant_setup_record_digests = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.participant_setup_record_digest.clone()))
        .collect::<Vec<_>>();
    let expected_trustee_threshold_verification_key_digests = participant_bindings
        .iter()
        .map(|participant| {
            Value::String(
                participant
                    .trustee_threshold_verification_key_digest
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantSetupRecordDigests"])?
        != &expected_participant_setup_record_digests
        || array_at_path(
            verification_key_set,
            &["trusteeThresholdVerificationKeyDigests"],
        )? != &expected_trustee_threshold_verification_key_digests
        || array_at_path(
            threshold_material,
            &["trusteeThresholdVerificationKeyDigests"],
        )? != &expected_trustee_threshold_verification_key_digests
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
        digest_at_path(threshold_material, &["thresholdShareVerificationKeyRoot"])?;
    compare_derived_digest(
        "ThresholdShareVerificationKeyRoot",
        verification_key_set,
        threshold_share_verification_key_root,
        "threshold share verification key root",
    )?;
    let expected_threshold_share_verification_key_digest = derive_protocol_digest(
        "ThresholdShareVerificationKeyDigest",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        }),
    )?;
    compare_digest_at_path(
        threshold_material,
        &["thresholdShareVerificationKeyDigest"],
        &expected_threshold_share_verification_key_digest,
        "threshold share verification key digest",
    )
}
