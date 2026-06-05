use super::*;

pub(super) fn participant_setup_material(
    input: &PassiveSetupInput,
    participant: &SetupParticipant,
    profile_hash: &str,
    backend_profile_hash: &str,
    public_common_random_polynomial_root: &str,
    target_decryption_profile_hash: &str,
    target_decryption_profile_binding_hash: &str,
) -> CanonicalResult<ParticipantSetupMaterial> {
    let participant_identities = input
        .participants
        .iter()
        .map(|setup_participant| setup_participant.trustee_identity.clone())
        .collect::<Vec<_>>();
    let local_secret_share_commitment_hash = hash512_hex(
        "sealed-lattice-bgv-rns/local-secret-share-commitment-v1",
        &[
            input.private_setup_seed_hash.as_bytes(),
            participant.trustee_identity.as_bytes(),
            participant.roster_position.to_string().as_bytes(),
            profile_hash.as_bytes(),
        ],
    );
    let local_error_commitment_hash = hash512_hex(
        "sealed-lattice-bgv-rns/local-error-commitment-v1",
        &[
            input.private_setup_seed_hash.as_bytes(),
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
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileHash": profile_hash,
        "backendProfileHash": backend_profile_hash,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "localSecretShareCommitmentHash": local_secret_share_commitment_hash,
        "localErrorCommitmentHash": local_error_commitment_hash,
        "publicShareConstruction": "owner-routed-standard-ternary-share-b_i=p*e_i-a*s_i-over-selected-BGV-RNS-profile",
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "sampledLocalSecretCoefficients": sample_bounded_collective_secret_share_distribution(
            &input.private_setup_seed_hash,
            &participant_identities,
            &participant.trustee_identity,
        )?,
        "sampledLocalErrorCoefficients": sample_bounded_collective_error_share_distribution(
            &input.private_setup_seed_hash,
            &participant_identities,
            &participant.trustee_identity,
        )?,
    });
    let public_key_share_root =
        derive_protocol_hash("PublicKeyShareRoot", &public_key_share_record)?;
    let trustee_threshold_verification_key = json!({
        "objectType": "TrusteeThresholdVerificationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetDecryptionProfileHash": target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": target_decryption_profile_binding_hash,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "publicKeyShareRoot": public_key_share_root,
        "verificationStatement": "passive-transcript-identity-profile-and-share-domain-binding",
        "maliciousDkgProofIncluded": false,
    });
    let trustee_threshold_verification_key_hash = derive_protocol_hash(
        "TrusteeThresholdVerificationKeyHash",
        &trustee_threshold_verification_key,
    )?;
    let participant_record_without_hash = json!({
        "objectType": "ParticipantBgvSetupRecord",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "thresholdProfileHash": input.threshold_profile_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileHash": profile_hash,
        "backendProfileHash": backend_profile_hash,
        "publicKeyShareRoot": public_key_share_root,
        "trusteeThresholdVerificationKeyHash": trustee_threshold_verification_key_hash,
        "localSecretShareCommitmentHash": local_secret_share_commitment_hash,
        "localErrorCommitmentHash": local_error_commitment_hash,
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "sampleDisclosure": "commitment-hashes-and-roots-only",
        "sampledLocalSecretCoefficientsIncluded": false,
        "sampledLocalErrorCoefficientsIncluded": false,
        "setupProofProfileForActiveSetupProof": "passive-record-only-active-proof-pending",
    });
    let participant_setup_record_hash = derive_protocol_hash(
        "ParticipantBgvSetupRecordHash",
        &participant_record_without_hash,
    )?;
    let mut participant_record = participant_record_without_hash;
    participant_record["participantSetupRecordHash"] =
        Value::String(participant_setup_record_hash.clone());

    Ok(ParticipantSetupMaterial {
        participant_record,
        public_key_share_root,
        participant_setup_record_hash,
        trustee_threshold_verification_key_hash,
    })
}
