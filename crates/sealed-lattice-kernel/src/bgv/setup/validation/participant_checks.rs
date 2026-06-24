use super::*;

pub(super) fn validate_participant_setup_records(
    setup_package: &Value,
    profile_hash: &str,
    backend_profile_hash: &str,
    target_decryption_profile_hash: &str,
    target_decryption_profile_binding_hash: &str,
) -> CanonicalResult<Vec<VerifiedParticipantSetupBinding>> {
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?;
    let manifest_hash = hash_at_path(setup_package, &["setupInputs", "manifestHash"])?;
    let roster_hash = hash_at_path(setup_package, &["setupInputs", "rosterHash"])?;
    let threshold_profile_hash =
        hash_at_path(setup_package, &["setupInputs", "thresholdProfileHash"])?;
    let participants = array_at_path(setup_package, &["participants"])?;
    let participant_identities =
        array_at_path(setup_package, &["setupInputs", "participantIdentities"])?;
    if participant_identities.len() != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setupPackage participant identities do not match participant records",
        ));
    }

    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    let mut verified_participants = Vec::with_capacity(participants.len());
    for (participant_index, participant_record) in participants.iter().enumerate() {
        compare_string_at_path(
            participant_record,
            &["objectType"],
            "ParticipantBgvSetupRecord",
            "participant record object type",
        )?;
        if unsigned_at_path(participant_record, &["objectVersion"])? != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participant setup record object version must be 1",
            ));
        }
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
            &["thresholdProfileHash"],
            threshold_profile_hash,
            "participant threshold profile hash",
        )?;
        compare_hash_at_path(
            participant_record,
            &["profileHash"],
            profile_hash,
            "participant profile hash",
        )?;
        compare_hash_at_path(
            participant_record,
            &["backendProfileHash"],
            backend_profile_hash,
            "participant backend profile hash",
        )?;
        let trustee_identity = string_at_path(participant_record, &["trusteeIdentity"])?;
        ensure_nfc_identity(trustee_identity, "participant trusteeIdentity")?;
        let listed_identity = participant_identities[participant_index]
            .as_str()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupPackage participant identities must be strings",
                )
            })?;
        ensure_nfc_identity(listed_identity, "setupPackage participant identity")?;
        if listed_identity != trustee_identity {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setupPackage participant identity order does not match participant records",
            ));
        }
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
            "ParticipantBgvSetupRecordHash",
            &participant_record_without_hash,
            participant_setup_record_hash,
            "participant setup record hash",
        )?;

        let trustee_threshold_verification_key = json!({
            "objectType": "TrusteeThresholdVerificationKey",
            "objectVersion": 1,
            "targetDecryptionProfileHash": target_decryption_profile_hash,
            "targetDecryptionProfileBindingHash": target_decryption_profile_binding_hash,
            "ceremonyId": ceremony_id,
            "rosterHash": roster_hash,
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "recoveryEpoch": recovery_epoch,
            "deviceEpoch": device_epoch,
            "publicKeyShareRoot": public_key_share_root,
        });
        compare_derived_hash(
            "TrusteeThresholdVerificationKeyHash",
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
