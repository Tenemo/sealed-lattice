use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn public_key_shares_object(participant_count: u64) -> serde_json::Value {
    let mut share_records = Vec::new();
    for trustee_roster_position in 0..participant_count {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let share_coefficient_hashes = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, _rns_prime)| {
                serde_json::json!({
                    "coefficientVectorHash512": derive_canonical_object_hash(&serde_json::json!({
                        "objectType": "PublicKeyShareCoefficientVectorFixture",
                        "fixture": "public-key-share-coefficient-vector",
                        "trusteeRosterPosition": trustee_roster_position,
                        "rnsLimbIndex": rns_limb_index,
                    }))
                    .expect("public-key share coefficient hash"),
                })
            })
            .collect::<Vec<_>>();
        let share_record = serde_json::json!({
            "objectType": "PublicKeyShare",
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "shareCoefficientVectorHash512ByLimb": share_coefficient_hashes,
        });
        share_records.push(share_record);
    }

    serde_json::json!({
        "objectType": "PublicKeyShareSet",
        "shareRecords": share_records,
    })
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
    let setup_context_hash =
        crate::bgv::setup::accepted_setup::setup_context_hash(&serde_json::json!({
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "participantCount": participant_count,
        }))
        .expect("setup context hash");
    let public_key_share_set_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PublicKeyShareSet",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": common_randomness["publicMatrixSeedHash"],
        "shareRecords": public_key_shares["shareRecords"],
    }))
    .expect("public-key share set root");
    let schedule_parameters = &parameters["evaluatorKeySchedule"];
    serde_json::json!({
        "objectType": "EvaluatorKeySchedule",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": common_randomness["publicMatrixSeedHash"],
        "publicKeyShareSetRoot": public_key_share_set_root,
        "relinearizationLevelSchedule": schedule_parameters["relinearizationLevelSchedule"],
        "requiredGaloisKeySchedule": schedule_parameters["requiredGaloisKeySchedule"],
    })
}
