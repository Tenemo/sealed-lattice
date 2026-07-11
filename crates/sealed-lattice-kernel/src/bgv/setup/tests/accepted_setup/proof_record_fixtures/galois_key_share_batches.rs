use super::*;
use rayon::prelude::*;

use crate::bgv::setup::evaluation_key_share_material::EvaluationKeyShareProofFamily;
use crate::hashing::derive_canonical_object_hash;

// Builds one Galois key-share batch per trustee, covering every scheduled
// rotation and level, as `verify_galois_key_share_batches` recomputes it. Each
// material record embeds its key-switch component vectors and the batch root is a
// canonical object hash with no profile-identifier fields.
pub(in super::super) fn galois_key_share_batches_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let participant_count = participant_count_from_package(package);
    let required_schedule = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("Galois key schedule");
    let ring_degree = source_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    // Generate each trustee's Galois key-switch component material across the
    // scheduled rotations in parallel, then consume that trustee's material in
    // schedule order before moving to the next trustee, so peak memory stays
    // bounded to one trustee's rotation materials instead of the full
    // trustee-by-rotation matrix. The per-trustee outer order and per-rotation
    // inner order are preserved, so the emitted batches and roots stay
    // byte-identical to sequential generation.
    let batches = (0..participant_count)
        .map(|trustee_roster_position| {
            let trustee_identity = format!("trustee-{trustee_roster_position}");
            let trustee_materials: Vec<EvaluationKeyShareFixtureMaterial> = required_schedule
                .par_iter()
                .map(|schedule_entry| {
                    let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                    let level = schedule_entry["level"].as_u64().expect("level");
                    let key_switch_seed_hex =
                        galois_key_switch_seed_for_test(schedule, rotation, level);
                    evaluation_key_share_fixture_material(
                        EvaluationKeyShareProofFamily::Galois,
                        trustee_roster_position,
                        level,
                        Some(rotation),
                        ring_degree,
                        &key_switch_seed_hex,
                        None,
                    )
                })
                .collect();
            let mut galois_key_share_material_records = Vec::new();
            let galois_key_share_roots = required_schedule
                .iter()
                .zip(trustee_materials)
                .map(|(schedule_entry, fixture_material)| {
                    let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                    let level = schedule_entry["level"].as_u64().expect("level");
                    let key_switch_seed_hex =
                        galois_key_switch_seed_for_test(schedule, rotation, level);
                    let root = fixture_material.component_vector_root.clone();
                    let material_record = serde_json::json!({
                        "objectType": "GaloisKeyShareMaterial",
                        "proofFamily": "galois-key-share",
                        "trusteeIdentity": trustee_identity.as_str(),
                        "trusteeRosterPosition": trustee_roster_position,
                        "rotation": rotation,
                        "level": level,
                        "galoisKeyShareRoot": root.clone(),
                        "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                        "keySwitchDomain": format!("galois-{rotation}"),
                        "keySwitchSeedHex": key_switch_seed_hex,
                        "ringDegree": ring_degree,
                        "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                        "keySwitchComponentVectors": serde_json::Value::Array(
                            fixture_material.component_vector_entries.clone(),
                        ),
                    });
                    galois_key_share_material_records.push(material_record);
                    serde_json::json!({
                        "rotation": schedule_entry["rotation"],
                        "level": schedule_entry["level"],
                        "galoisKeyShareRoot": root,
                    })
                })
                .collect::<Vec<_>>();
            let mut batch = serde_json::json!({
                "objectType": "GaloisKeyShareBatch",
                "proofFamily": "galois-key-share",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity.as_str(),
                "trusteeRosterPosition": trustee_roster_position,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
                "galoisKeyShareRoots": galois_key_share_roots,
                "galoisKeyShareMaterialRecords": galois_key_share_material_records,
            });
            batch["galoisKeyShareBatchRoot"] = serde_json::json!(
                derive_canonical_object_hash(&batch).expect("Galois key share batch root")
            );
            batch
        })
        .collect::<Vec<_>>();

    serde_json::Value::Array(batches)
}
