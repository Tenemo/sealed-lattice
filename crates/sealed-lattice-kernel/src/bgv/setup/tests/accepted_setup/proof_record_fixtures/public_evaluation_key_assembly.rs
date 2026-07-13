use super::*;

use crate::hashing::derive_canonical_object_hash;

// Assembles the public evaluation-key set the accepted-setup verifier's
// `verify_public_evaluation_key_set` recomputes: one relinearization key root per
// scheduled level (derived from the verified round-one/round-two aggregate roots)
// and one Galois key root per scheduled rotation (derived from the verified batch
// share roots). The key-root preimages are byte-identical to the verifier's
// `expected_relinearization_key_roots_for_evaluation_keys` and
// `expected_galois_key_roots_for_evaluation_keys`, and the set carries no
// streamed material reference, so the package embeds the whole set and no
// transported public evaluation-key material is required.
pub(in super::super) fn public_evaluation_key_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let relinearization_rounds = &package["relinearizationKeyShareRounds"];
    let relinearization_rounds_root = relinearization_rounds["relinearizationKeyShareRoundsRoot"]
        .as_str()
        .expect("relinearization rounds root");
    let relinearization_key_roots = schedule["relinearizationLevelSchedule"]
        .as_array()
        .expect("relinearization schedule")
        .iter()
        .map(|level_entry| {
            let level = level_entry["level"].as_u64().expect("relinearization level");
            let round_one_aggregate_root = relinearization_rounds["roundOneAggregateRoots"]
                .as_array()
                .expect("round-one aggregate roots")
                .iter()
                .find(|entry| entry["level"].as_u64() == Some(level))
                .and_then(|entry| entry["roundOneAggregateRoot"].as_str())
                .expect("round-one aggregate root");
            let round_two_aggregate_root = relinearization_rounds["roundTwoAggregateRoots"]
                .as_array()
                .expect("round-two aggregate roots")
                .iter()
                .find(|entry| entry["level"].as_u64() == Some(level))
                .and_then(|entry| entry["roundTwoAggregateRoot"].as_str())
                .expect("round-two aggregate root");
            let relinearization_key_root = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "RelinearizationKeyAggregate",
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
                "level": level,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
            }))
            .expect("relinearization key root");
            serde_json::json!({
                "level": level,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
                "relinearizationKeyRoot": relinearization_key_root,
            })
        })
        .collect::<Vec<_>>();

    let mut galois_batches = package["galoisKeyShareBatches"]
        .as_array()
        .expect("Galois key share batches")
        .iter()
        .collect::<Vec<_>>();
    galois_batches.sort_by_key(|batch| {
        batch["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position")
    });
    let galois_key_share_batch_roots = galois_batches
        .iter()
        .map(|batch| {
            serde_json::json!({
                "trusteeIdentity": batch["trusteeIdentity"],
                "trusteeRosterPosition": batch["trusteeRosterPosition"],
                "galoisKeyShareBatchRoot": batch["galoisKeyShareBatchRoot"],
            })
        })
        .collect::<Vec<_>>();
    let galois_key_roots = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("required Galois key schedule")
        .iter()
        .map(|schedule_entry| {
            let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
            let level = schedule_entry["level"].as_u64().expect("level");
            let contributing_share_roots = galois_batches
                .iter()
                .map(|batch| {
                    let material_record = batch["galoisKeyShareMaterialRecords"]
                        .as_array()
                        .expect("Galois key share material records")
                        .iter()
                        .find(|material_record| {
                            material_record["rotation"].as_u64() == Some(rotation)
                                && material_record["level"].as_u64() == Some(level)
                        })
                        .expect("scheduled Galois material record");
                    serde_json::json!({
                        "trusteeIdentity": batch["trusteeIdentity"],
                        "trusteeRosterPosition": batch["trusteeRosterPosition"],
                        "galoisKeyShareRoot": material_record["galoisKeyShareRoot"],
                    })
                })
                .collect::<Vec<_>>();
            let galois_key_root = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "GaloisKeyAggregate",
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                "rotation": rotation,
                "level": level,
                "contributingShareRoots": contributing_share_roots,
            }))
            .expect("Galois key root");
            serde_json::json!({
                "rotation": rotation,
                "level": level,
                "galoisKeyRoot": galois_key_root,
                "contributingShareRoots": contributing_share_roots,
            })
        })
        .collect::<Vec<_>>();

    let mut evaluation_keys = serde_json::json!({
        "objectType": "PublicEvaluationKeySet",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": participant_count_from_package(package),
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
        "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
        "relinearizationLevelSchedule": schedule["relinearizationLevelSchedule"],
        "relinearizationKeyRoots": relinearization_key_roots,
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
        "galoisKeyShareBatchRoots": galois_key_share_batch_roots,
        "galoisKeyRoots": galois_key_roots,
        "genericKeySwitchKeyRoots": [],
    });
    evaluation_keys["evaluationKeySetHash"] = serde_json::json!(
        derive_canonical_object_hash(&evaluation_keys).expect("evaluation key set hash")
    );

    evaluation_keys
}
