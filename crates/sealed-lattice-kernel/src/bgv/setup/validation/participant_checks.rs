use super::*;

pub(super) fn validate_participant_setup_records(
    setup_package: &Value,
    bgv_parameters_hash: &str,
    target_decryption_parameters_hash: &str,
) -> CanonicalResult<Vec<VerifiedParticipantSetupBinding>> {
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?;
    let manifest_hash = hash_at_path(setup_package, &["setupInputs", "manifestHash"])?;
    let roster_hash = hash_at_path(setup_package, &["setupInputs", "rosterHash"])?;
    let threshold_parameters_hash =
        hash_at_path(setup_package, &["setupInputs", "thresholdParametersHash"])?;
    let participants = array_at_path(setup_package, &["participants"])?;

    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    let mut verified_participants = Vec::with_capacity(participants.len());
    for participant_record in participants {
        compare_string_at_path(
            participant_record,
            &["objectType"],
            "ParticipantBgvSetupRecord",
            "participant record object type",
        )?;
        compare_string_at_path(
            participant_record,
            &["ceremonyId"],
            ceremony_id,
            "participant ceremony id",
        )?;
        compare_hash_at_path(
            participant_record,
            &["manifestHash"],
            manifest_hash,
            "participant manifest hash",
        )?;
        compare_hash_at_path(
            participant_record,
            &["rosterHash"],
            roster_hash,
            "participant roster hash",
        )?;
        compare_hash_at_path(
            participant_record,
            &["thresholdParametersHash"],
            threshold_parameters_hash,
            "participant threshold parameters hash",
        )?;
        compare_hash_at_path(
            participant_record,
            &["bgvParametersHash"],
            bgv_parameters_hash,
            "participant BGV parameters hash",
        )?;
        let trustee_identity = string_at_path(participant_record, &["trusteeIdentity"])?;
        ensure_nfc_identity(trustee_identity, "participant trusteeIdentity")?;
        let roster_position = usize_at_path(participant_record, &["rosterPosition"])?;
        if roster_position >= participants.len() || !roster_positions.insert(roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage participant roster positions must be unique and cover the frozen roster",
            ));
        }
        if !identities.insert(trustee_identity.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage participant identities must be unique",
            ));
        }
        let recovery_epoch = unsigned_at_path(participant_record, &["recoveryEpoch"])?;
        let device_epoch = unsigned_at_path(participant_record, &["deviceEpoch"])?;
        let public_key_share_root = hash_at_path(participant_record, &["publicKeyShareRoot"])?;
        let participant_setup_record_hash =
            hash_at_path(participant_record, &["participantSetupRecordHash"])?;
        let trustee_threshold_verification_key_hash =
            hash_at_path(participant_record, &["trusteeThresholdVerificationKeyHash"])?;
        hash_at_path(participant_record, &["localSecretShareCommitmentHash"])?;
        hash_at_path(participant_record, &["localErrorCommitmentHash"])?;

        let mut participant_record_without_hash = participant_record.clone();
        participant_record_without_hash
            .as_object_mut()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "participant setup record must be an object",
                )
            })?
            .remove("participantSetupRecordHash");
        compare_derived_hash(
            &participant_record_without_hash,
            participant_setup_record_hash,
            "participant setup record hash",
        )?;

        let trustee_threshold_verification_key = json!({
            "objectType": "TrusteeThresholdVerificationKey",
            "targetDecryptionParametersHash": target_decryption_parameters_hash,
            "ceremonyId": ceremony_id,
            "rosterHash": roster_hash,
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "recoveryEpoch": recovery_epoch,
            "deviceEpoch": device_epoch,
            "publicKeyShareRoot": public_key_share_root,
        });
        compare_derived_hash(
            &trustee_threshold_verification_key,
            trustee_threshold_verification_key_hash,
            "trustee threshold verification key hash",
        )?;

        verified_participants.push(VerifiedParticipantSetupBinding {
            trustee_identity: trustee_identity.to_string(),
            roster_position,
            recovery_epoch,
            device_epoch,
            public_key_share_root: public_key_share_root.to_string(),
            participant_setup_record_hash: participant_setup_record_hash.to_string(),
            trustee_threshold_verification_key_hash: trustee_threshold_verification_key_hash
                .to_string(),
        });
    }

    Ok(verified_participants)
}
