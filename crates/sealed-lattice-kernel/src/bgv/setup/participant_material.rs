use super::*;

pub(super) fn participant_setup_material(
    input: &PassiveSetupInput,
    participant: &SetupParticipant,
    profile_digest: &str,
    backend_profile_digest: &str,
    public_common_random_polynomial_root: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<ParticipantSetupMaterial> {
    let local_secret_share_commitment_digest = hash512_hex(
        "sealed-lattice-bgv-rns/local-secret-share-commitment-v1",
        &[
            input.setup_seed_digest.as_bytes(),
            participant.trustee_identity.as_bytes(),
            participant.roster_position.to_string().as_bytes(),
            profile_digest.as_bytes(),
        ],
    );
    let local_error_commitment_digest = hash512_hex(
        "sealed-lattice-bgv-rns/local-error-commitment-v1",
        &[
            input.setup_seed_digest.as_bytes(),
            participant.trustee_identity.as_bytes(),
            participant.roster_position.to_string().as_bytes(),
            public_common_random_polynomial_root.as_bytes(),
        ],
    );
    let public_key_share_record = json!({
        "objectType": "BgvPublicKeyShare",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "localSecretShareCommitmentDigest": local_secret_share_commitment_digest,
        "localErrorCommitmentDigest": local_error_commitment_digest,
        "publicShareConstruction": "b_i=-a*s_i+e_i-over-selected-BGV-RNS-profile",
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "sampledLocalSecretCoefficients": sample_small_distribution(
            &input.setup_seed_digest,
            &participant.trustee_identity,
            "local-secret-share",
            -1,
            1,
        ),
        "sampledLocalErrorCoefficients": sample_centered_binomial_eta2(
            &input.setup_seed_digest,
            &participant.trustee_identity,
            "local-error",
        ),
    });
    let public_key_share_root =
        derive_protocol_digest("PublicKeyShareRoot", &public_key_share_record)?;
    let trustee_threshold_verification_key = json!({
        "objectType": "TrusteeThresholdVerificationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "publicKeyShareRoot": public_key_share_root,
        "verificationStatement": "passive-transcript-identity-profile-and-share-domain-binding",
        "maliciousDkgProofIncluded": false,
    });
    let trustee_threshold_verification_key_digest = derive_protocol_digest(
        "TrusteeThresholdVerificationKeyDigest",
        &trustee_threshold_verification_key,
    )?;
    let participant_record_without_digest = json!({
        "objectType": "ParticipantBgvSetupRecord",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "thresholdProfileDigest": input.threshold_profile_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicKeyShareRoot": public_key_share_root,
        "trusteeThresholdVerificationKeyDigest": trustee_threshold_verification_key_digest,
        "localSecretShareCommitmentDigest": local_secret_share_commitment_digest,
        "localErrorCommitmentDigest": local_error_commitment_digest,
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "sampleDisclosure": "commitment-digests-and-roots-only",
        "sampledLocalSecretCoefficientsIncluded": false,
        "sampledLocalErrorCoefficientsIncluded": false,
        "setupProofProfileForM19": "passive-record-only-active-proof-pending-M19",
    });
    let participant_setup_record_digest = derive_protocol_digest(
        "ParticipantBgvSetupRecordDigest",
        &participant_record_without_digest,
    )?;
    let mut participant_record = participant_record_without_digest;
    participant_record["participantSetupRecordDigest"] =
        Value::String(participant_setup_record_digest.clone());

    Ok(ParticipantSetupMaterial {
        participant_record,
        public_key_share_root,
        participant_setup_record_digest,
        trustee_threshold_verification_key_digest,
    })
}
