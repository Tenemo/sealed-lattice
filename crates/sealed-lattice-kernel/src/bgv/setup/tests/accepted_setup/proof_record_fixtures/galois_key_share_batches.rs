use super::*;
use rayon::prelude::*;

use crate::bgv::setup::evaluation_key_share_material::{
    EvaluationKeyShareDerivedMaterialBinding, EvaluationKeyShareProofFamily,
};

// Builds one Galois key-share batch per trustee, covering every scheduled
// rotation and level. Each material record references component vectors
// authenticated by the canonical stream.
pub(in super::super) fn galois_key_share_batches_object(
    package: &serde_json::Value,
    accepted_setup_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> GaloisKeyShareBatchesFixture {
    let schedule = &package["evaluatorKeySchedule"];
    let participant_count = participant_count_from_package(package);
    let required_schedule = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("Galois key schedule");
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    // Generate each trustee's Galois key-switch component material across the
    // scheduled rotations in parallel, then consume that trustee's material in
    // schedule order before moving to the next trustee, so peak memory stays
    // bounded to one trustee's rotation materials instead of the full
    // trustee-by-rotation matrix. The per-trustee outer order and per-rotation
    // inner order are preserved, so the emitted batches stay byte-identical
    // to sequential generation.
    let mut transported_component_materials = Vec::new();
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
            for (schedule_entry, fixture_material) in
                required_schedule.iter().zip(trustee_materials)
            {
                let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                let level = schedule_entry["level"].as_u64().expect("level");
                let key_switch_seed_hex =
                    galois_key_switch_seed_for_test(schedule, rotation, level);
                let key_switch_domain = format!("galois-{rotation}");
                let mut material_record = serde_json::json!({
                    "objectType": "GaloisKeyShareMaterial",
                    "rotation": rotation,
                    "level": level,
                    "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                });
                let authenticated_material =
                    authenticate_evaluation_key_share_component_material_fixture(
                        EvaluationKeyShareProofFamily::Galois,
                        &material_record,
                        EvaluationKeyShareDerivedMaterialBinding {
                            trustee_identity: &trustee_identity,
                            trustee_roster_position,
                            key_switch_domain: &key_switch_domain,
                            key_switch_seed_hex: &key_switch_seed_hex,
                        },
                        ring_degree,
                        &fixture_material,
                        accepted_setup_session,
                    );
                material_record["keySwitchComponentMaterialRoot"] =
                    serde_json::json!(authenticated_material.material_root);
                transported_component_materials.push(authenticated_material.transported_material);
                galois_key_share_material_records.push(material_record);
            }
            serde_json::json!({
                "objectType": "GaloisKeyShareBatch",
                "trusteeIdentity": trustee_identity.as_str(),
                "trusteeRosterPosition": trustee_roster_position,
                "galoisKeyShareMaterialRecords": galois_key_share_material_records,
            })
        })
        .collect::<Vec<_>>();

    GaloisKeyShareBatchesFixture {
        batches: serde_json::Value::Array(batches),
        transported_component_materials,
    }
}
