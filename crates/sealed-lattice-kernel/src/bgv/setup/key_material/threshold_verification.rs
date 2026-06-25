use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::setup) fn threshold_verification_material(
    input: &PassiveSetupInput,
    target_decryption_parameters_hash: &str,
    target_decryption_parameters_binding_hash: &str,
    participant_setup_record_hashes: &[String],
    trustee_threshold_verification_key_hashes: &[String],
) -> CanonicalResult<Value> {
    let participant_points = input
        .participants
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity.clone(),
                "rosterPosition": participant.roster_position,
                "interpolationPoint": participant.roster_position + 1,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    let verification_key_set = json!({
        "objectType": "ThresholdShareVerificationKeySet",
        "objectVersion": 1,
        "targetDecryptionParametersHash": target_decryption_parameters_hash,
        "targetDecryptionParametersBindingHash": target_decryption_parameters_binding_hash,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "participantSetupRecordHashes": participant_setup_record_hashes,
        "trusteeThresholdVerificationKeyHashes": trustee_threshold_verification_key_hashes,
        "participantInterpolationUniverse": participant_points,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "passiveSetupVerificationScope": [
            "transcript-binding",
            "identity-binding",
            "roster-binding",
            "parameters-binding",
            "recovery-device-epoch-binding"
        ],
    });
    let threshold_share_verification_key_root =
        derive_canonical_object_hash(&verification_key_set)?;
    let threshold_share_verification_key_hash = derive_canonical_object_hash(&json!({
        "objectType": "ThresholdShareVerificationKeyBinding",
        "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
        "targetDecryptionParametersHash": target_decryption_parameters_hash,
        "targetDecryptionParametersBindingHash": target_decryption_parameters_binding_hash,
    }))?;

    Ok(json!({
        "verificationKeySet": verification_key_set,
        "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHashes": trustee_threshold_verification_key_hashes,
    }))
}
