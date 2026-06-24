use super::*;
use rayon::prelude::*;

pub(in super::super) fn galois_key_share_batches_object_with_terminal_transport(
    package: &serde_json::Value,
    terminal_transport: &mut TerminalEvaluationKeyTransportSinks,
) -> serde_json::Value {
    galois_key_share_batches_object_inner(package, Some(terminal_transport))
}

fn galois_key_share_batches_object_inner(
    package: &serde_json::Value,
    mut terminal_transport: Option<&mut TerminalEvaluationKeyTransportSinks>,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let required_schedule = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("Galois key schedule");
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    // Generate each trustee's Galois key-switch component material across the
    // scheduled rotations in parallel, then consume that trustee's material in
    // schedule order before moving to the next trustee, so peak memory stays
    // bounded to one trustee's rotation materials instead of the full
    // trustee-by-rotation matrix. The per-trustee outer order and per-rotation
    // inner order are preserved, so the emitted batches, roots, and transported
    // component-material order stay byte-identical to sequential generation.
    let batches = same_secret_proofs
        .iter()
        .map(|proof_record| {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
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
                    let mut material_record = serde_json::json!({
                        "objectType": "GaloisKeyShareMaterial",
                        "objectVersion": 1,
                        "proofFamily": "galois-key-share",
                        "trusteeIdentity": trustee_identity,
                        "trusteeRosterPosition": trustee_roster_position,
                        "rotation": rotation,
                        "level": level,
                        "galoisKeyShareRoot": root.clone(),
                        "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                        "keySwitchDomain": format!("galois-{rotation}"),
                        "keySwitchSeedHex": key_switch_seed_hex,
                        "ringDegree": ring_degree,
                        "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                    });
                    if terminal_transport.is_none() {
                        material_record["keySwitchComponentVectors"] =
                            serde_json::Value::Array(fixture_material.component_vector_entries.clone());
                    }
                    if let Some(sinks) = terminal_transport.as_deref_mut() {
                        let transported_component_material_set =
                            move_evaluation_key_share_component_vectors_to_compact_transport(
                                &mut material_record,
                                EvaluationKeyShareProofFamily::Galois,
                                &fixture_material,
                            );
                        sinks.component_materials.extend(
                            transported_component_material_set["componentMaterials"]
                                .as_array()
                                .expect("component materials")
                                .iter()
                                .cloned(),
                        );
                    }
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
                "objectVersion": 1,
                "proofFamily": "galois-key-share",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
                "galoisKeyShareRoots": galois_key_share_roots,
                "galoisKeyShareMaterialRecords": galois_key_share_material_records,
            });
            batch["galoisKeyShareBatchRoot"] = serde_json::json!(
                derive_protocol_hash("GaloisKeyShareBatchRoot", &batch)
                    .expect("Galois key share batch root")
            );
            batch
        })
        .collect::<Vec<_>>();

    serde_json::Value::Array(batches)
}
