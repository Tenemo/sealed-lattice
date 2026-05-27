use super::*;

pub(super) fn validate_participant_setup_records(
    setup_package: &Value,
    profile_digest: &str,
    backend_profile_digest: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<Vec<VerifiedParticipantSetupBinding>> {
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?;
    let manifest_digest = digest_at_path(setup_package, &["setupInputs", "manifestDigest"])?;
    let roster_digest = digest_at_path(setup_package, &["setupInputs", "rosterDigest"])?;
    let threshold_profile_digest =
        digest_at_path(setup_package, &["setupInputs", "thresholdProfileDigest"])?;
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
            &["setupProfileId"],
            PASSIVE_SETUP_PROFILE_ID,
            "participant setup profile id",
        )?;
        compare_string_at_path(
            participant_record,
            &["ceremonyId"],
            ceremony_id,
            "participant ceremony id",
        )?;
        compare_digest_at_path(
            participant_record,
            &["manifestDigest"],
            manifest_digest,
            "participant manifest digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["rosterDigest"],
            roster_digest,
            "participant roster digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["thresholdProfileDigest"],
            threshold_profile_digest,
            "participant threshold profile digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["profileDigest"],
            profile_digest,
            "participant profile digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["backendProfileDigest"],
            backend_profile_digest,
            "participant backend profile digest",
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
        let public_key_share_root = digest_at_path(participant_record, &["publicKeyShareRoot"])?;
        let participant_setup_record_digest =
            digest_at_path(participant_record, &["participantSetupRecordDigest"])?;
        let trustee_threshold_verification_key_digest = digest_at_path(
            participant_record,
            &["trusteeThresholdVerificationKeyDigest"],
        )?;
        digest_at_path(participant_record, &["localSecretShareCommitmentDigest"])?;
        digest_at_path(participant_record, &["localErrorCommitmentDigest"])?;

        let mut participant_record_without_digest = participant_record.clone();
        participant_record_without_digest
            .as_object_mut()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "participant setup record must be an object",
                )
            })?
            .remove("participantSetupRecordDigest");
        compare_derived_digest(
            "ParticipantBgvSetupRecordDigest",
            &participant_record_without_digest,
            participant_setup_record_digest,
            "participant setup record digest",
        )?;

        let trustee_threshold_verification_key = json!({
            "objectType": "TrusteeThresholdVerificationKey",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
            "ceremonyId": ceremony_id,
            "rosterDigest": roster_digest,
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "recoveryEpoch": recovery_epoch,
            "deviceEpoch": device_epoch,
            "publicKeyShareRoot": public_key_share_root,
            "verificationStatement": "passive-transcript-identity-profile-and-share-domain-binding",
            "maliciousDkgProofIncluded": false,
        });
        compare_derived_digest(
            "TrusteeThresholdVerificationKeyDigest",
            &trustee_threshold_verification_key,
            trustee_threshold_verification_key_digest,
            "trustee threshold verification key digest",
        )?;

        verified_participants.push(VerifiedParticipantSetupBinding {
            trustee_identity: trustee_identity.to_string(),
            roster_position,
            recovery_epoch,
            device_epoch,
            public_key_share_root: public_key_share_root.to_string(),
            participant_setup_record_digest: participant_setup_record_digest.to_string(),
            trustee_threshold_verification_key_digest: trustee_threshold_verification_key_digest
                .to_string(),
        });
    }

    Ok(verified_participants)
}
