use super::*;
use rayon::prelude::*;

use crate::bgv::setup::accepted_setup::{
    evaluation_key_proof_common_binding, expected_galois_key_switch_seed,
    expected_required_galois_key_schedule,
};
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
    let evaluation_key_binding =
        evaluation_key_proof_common_binding(package).expect("evaluation-key proof binding");
    let participant_count = participant_count_from_package(package);
    let required_schedule =
        expected_required_galois_key_schedule().expect("required Galois key schedule");
    let required_schedule = required_schedule.as_array().expect("Galois key schedule");
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    // Generate each trustee's Galois key-switch component material across the
    // scheduled rotations in parallel, then consume that trustee's material in
    // schedule order before moving to the next trustee, so peak memory stays
    // bounded to one trustee's rotation materials instead of the full
    // trustee-by-rotation matrix. The per-trustee outer order and per-rotation
    // inner order are preserved, so the emitted batches stay byte-identical
    // to sequential generation.
    let batches = (0..participant_count)
        .map(|trustee_roster_position| {
            let trustee_identity = format!("trustee-{trustee_roster_position}");
            let trustee_materials: Vec<EvaluationKeyShareFixtureMaterial> = required_schedule
                .par_iter()
                .map(|schedule_entry| {
                    let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                    let level = schedule_entry["level"].as_u64().expect("level");
                    let key_switch_seed_hex =
                        expected_galois_key_switch_seed(&evaluation_key_binding, rotation, level)
                            .expect("Galois key-switch seed");
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
            let mut key_switch_component_material_roots = Vec::new();
            for (schedule_entry, fixture_material) in
                required_schedule.iter().zip(trustee_materials)
            {
                let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                let level = schedule_entry["level"].as_u64().expect("level");
                let key_switch_seed_hex =
                    expected_galois_key_switch_seed(&evaluation_key_binding, rotation, level)
                        .expect("Galois key-switch seed");
                let key_switch_domain = format!("galois-{rotation}");
                let authenticated_material_root =
                    authenticate_evaluation_key_share_component_material_fixture(
                        EvaluationKeyShareProofFamily::Galois,
                        level,
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
                key_switch_component_material_roots.push(authenticated_material_root);
            }
            serde_json::json!({
                "objectType": "GaloisKeyShareBatch",
                "keySwitchComponentMaterialRoots": key_switch_component_material_roots,
            })
        })
        .collect::<Vec<_>>();

    GaloisKeyShareBatchesFixture {
        batches: serde_json::Value::Array(batches),
    }
}
