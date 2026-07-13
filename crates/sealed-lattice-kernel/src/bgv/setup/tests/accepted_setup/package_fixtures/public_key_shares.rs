use super::*;

use crate::hashing::derive_canonical_object_hash;

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn public_key_shares_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let mut share_records = Vec::new();
    for trustee_roster_position in 0..participant_count {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let share_coefficient_hashes = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, _rns_prime)| {
                serde_json::json!({
                    "coefficientVectorHash512": derive_canonical_object_hash(&serde_json::json!({
                        "objectType": "PublicKeyShareRoot",
                        "fixture": "public-key-share-coefficient-vector",
                        "trusteeRosterPosition": trustee_roster_position,
                        "rnsLimbIndex": rns_limb_index,
                    }))
                    .expect("public-key share coefficient hash"),
                })
            })
            .collect::<Vec<_>>();
        let mut share_record = serde_json::json!({
            "objectType": "PublicKeyShare",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "shareCoefficientVectorHash512ByLimb": share_coefficient_hashes,
        });
        share_record["publicKeyShareRoot"] = serde_json::json!(
            derive_canonical_object_hash(&share_record).expect("public-key share root")
        );
        share_records.push(share_record);
    }
    let mut share_set = serde_json::json!({
        "objectType": "PublicKeyShareSet",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "shareRecords": share_records,
    });
    share_set["publicKeyShareSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&share_set).expect("public-key share set root")
    );

    share_set
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn evaluator_key_schedule_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    parameters: &serde_json::Value,
    common_randomness: &serde_json::Value,
    public_key_shares: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let schedule_parameters = &parameters["evaluatorKeySchedule"];
    let mut schedule = serde_json::json!({
        "objectType": "EvaluatorKeySchedule",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "publicMatrixSeedHash": common_randomness["publicMatrixSeedHash"],
        "publicKeyShareSetRoot": public_key_shares["publicKeyShareSetRoot"],
        "relinearizationLevelSchedule": schedule_parameters["relinearizationLevelSchedule"],
        "requiredGaloisKeySchedule": schedule_parameters["requiredGaloisKeySchedule"],
    });
    schedule["evaluatorKeyScheduleRoot"] = serde_json::json!(
        derive_canonical_object_hash(&schedule).expect("evaluator-key schedule root")
    );

    schedule
}
