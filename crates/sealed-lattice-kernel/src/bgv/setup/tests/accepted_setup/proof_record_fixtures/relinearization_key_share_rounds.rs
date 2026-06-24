use super::*;
use rayon::prelude::*;

pub(in super::super) fn relinearization_key_share_rounds_fixture_with_terminal_transport(
    package: &serde_json::Value,
    terminal_transport: &mut TerminalEvaluationKeyTransportSinks,
) -> RelinearizationKeyShareRoundsFixture {
    relinearization_key_share_rounds_object_inner(package, Some(terminal_transport))
}

fn relinearization_key_share_rounds_object_inner(
    package: &serde_json::Value,
    mut terminal_transport: Option<&mut TerminalEvaluationKeyTransportSinks>,
) -> RelinearizationKeyShareRoundsFixture {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let level_schedule = schedule["relinearizationLevelSchedule"]
        .as_array()
        .expect("relinearization level schedule");
    let scheduled_levels = level_schedule
        .iter()
        .map(|level_entry| level_entry["level"].as_u64().expect("level"))
        .collect::<Vec<_>>();

    let mut round_one_records = Vec::new();
    let mut round_one_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    let mut round_one_share_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_record_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_aggregate_diagonals_by_level = BTreeMap::<u64, Vec<Vec<u64>>>::new();
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex =
            relinearization_key_switch_seed_for_test(schedule, "round-one", level);
        // Generate every trustee's key-switch component material for this level
        // in parallel; the deterministic material is then consumed in roster
        // order by the sequential aggregate-accumulation and record-building
        // pass below, so the emitted records and roots are byte-identical.
        let level_materials: Vec<EvaluationKeyShareFixtureMaterial> = same_secret_proofs
            .par_iter()
            .map(|proof_record| {
                let trustee_roster_position = proof_record["trusteeRosterPosition"]
                    .as_u64()
                    .expect("trustee roster position");
                let relinearization_source = relinearization_round_one_source_by_digit_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    usize::try_from(level).expect("level fits usize") + 1,
                );
                evaluation_key_share_fixture_material(
                    EvaluationKeyShareProofFamily::Relinearization,
                    trustee_roster_position,
                    level,
                    None,
                    ring_degree,
                    &key_switch_seed_hex,
                    Some(&relinearization_source),
                )
            })
            .collect();
        for (proof_record, fixture_material) in same_secret_proofs.iter().zip(level_materials) {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let aggregate_diagonals = round_one_aggregate_diagonals_by_level
                .entry(level)
                .or_insert_with(|| {
                    vec![
                        vec![0_u64; ring_degree];
                        usize::try_from(level).expect("level fits usize") + 1
                    ]
                });
            for (digit_index, aggregate) in aggregate_diagonals.iter_mut().enumerate() {
                for (accumulated, value) in aggregate
                    .iter_mut()
                    .zip(fixture_material.component_b_by_digit[digit_index][digit_index].iter())
                {
                    *accumulated = add_mod(*accumulated, *value, DATA_PRIMES[digit_index])
                        .expect("round-one aggregate accumulation");
                }
            }
            let round_one_share_root = fixture_material.component_vector_root.clone();
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundOne",
                "objectVersion": 1,
                "proofFamily": "relinearization-key-share",
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
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
                "roundOneShareRoot": round_one_share_root,
                "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                "keySwitchDomain": "relinearization",
                "keySwitchSeedHex": key_switch_seed_hex,
                "ringDegree": ring_degree,
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
            });
            if terminal_transport.is_none() {
                record["keySwitchComponentVectors"] =
                    serde_json::Value::Array(fixture_material.component_vector_entries.clone());
            }
            if let Some(sinks) = terminal_transport.as_deref_mut() {
                let transported_component_material_set =
                    move_evaluation_key_share_component_vectors_to_compact_transport(
                        &mut record,
                        EvaluationKeyShareProofFamily::Relinearization,
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
            record["roundOneRecordRoot"] = serde_json::json!(
                derive_protocol_hash("RelinearizationRoundOneRecordRoot", &record)
                    .expect("round-one record root")
            );
            let record_root = record["roundOneRecordRoot"]
                .as_str()
                .expect("round-one record root")
                .to_string();
            round_one_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundOneRecordRoot": record_root,
                }));
            round_one_share_roots.insert((level, trustee_roster_position), round_one_share_root);
            round_one_record_roots.insert((level, trustee_roster_position), record_root);
            round_one_records.push(record);
        }
    }
    let mut round_one_aggregate_roots = Vec::new();
    let mut round_one_aggregate_root_by_level = BTreeMap::new();
    for level in &scheduled_levels {
        let level = *level;
        let aggregate_root = derive_protocol_hash(
            "RelinearizationRoundOneAggregateRoot",
            &serde_json::json!({
                "objectType": "RelinearizationRoundOneAggregate",
                "objectVersion": 1,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "level": level,
                "roundOneRecordRoots": round_one_roots_by_level
                    .get(&level)
                    .expect("round-one roots by level"),
            }),
        )
        .expect("round-one aggregate root");
        round_one_aggregate_roots.push(serde_json::json!({
            "level": level,
            "roundOneAggregateRoot": aggregate_root,
        }));
        round_one_aggregate_root_by_level.insert(level, aggregate_root);
    }

    let mut round_two_records = Vec::new();
    let mut round_two_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex =
            relinearization_key_switch_seed_for_test(schedule, "round-two", level);
        let round_one_aggregate_diagonals = round_one_aggregate_diagonals_by_level
            .get(&level)
            .expect("round-one aggregate diagonals");
        let level_materials: Vec<EvaluationKeyShareFixtureMaterial> = same_secret_proofs
            .par_iter()
            .map(|proof_record| {
                let trustee_roster_position = proof_record["trusteeRosterPosition"]
                    .as_u64()
                    .expect("trustee roster position");
                let relinearization_source = relinearization_round_two_source_by_digit_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    round_one_aggregate_diagonals,
                );
                evaluation_key_share_fixture_material(
                    EvaluationKeyShareProofFamily::Relinearization,
                    trustee_roster_position,
                    level,
                    None,
                    ring_degree,
                    &key_switch_seed_hex,
                    Some(&relinearization_source),
                )
            })
            .collect();
        for (proof_record, fixture_material) in same_secret_proofs.iter().zip(level_materials) {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let round_two_share_root = fixture_material.component_vector_root.clone();
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundTwo",
                "objectVersion": 1,
                "proofFamily": "relinearization-key-share",
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
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
                "roundOneShareRoot": round_one_share_roots
                    .get(&(level, trustee_roster_position))
                    .expect("round-one share root"),
                "roundOneRecordRoot": round_one_record_roots
                    .get(&(level, trustee_roster_position))
                    .expect("round-one record root"),
                "roundOneAggregateRoot": round_one_aggregate_root_by_level
                    .get(&level)
                    .expect("round-one aggregate root"),
                "roundTwoShareRoot": round_two_share_root,
                "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                "keySwitchDomain": "relinearization",
                "keySwitchSeedHex": key_switch_seed_hex,
                "ringDegree": ring_degree,
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
            });
            if terminal_transport.is_none() {
                record["keySwitchComponentVectors"] =
                    serde_json::Value::Array(fixture_material.component_vector_entries.clone());
            }
            if let Some(sinks) = terminal_transport.as_deref_mut() {
                let transported_component_material_set =
                    move_evaluation_key_share_component_vectors_to_compact_transport(
                        &mut record,
                        EvaluationKeyShareProofFamily::Relinearization,
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
            record["roundTwoRecordRoot"] = serde_json::json!(
                derive_protocol_hash("RelinearizationRoundTwoRecordRoot", &record)
                    .expect("round-two record root")
            );
            let record_root = record["roundTwoRecordRoot"]
                .as_str()
                .expect("round-two record root")
                .to_string();
            round_two_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundTwoRecordRoot": record_root,
                }));
            round_two_records.push(record);
        }
    }
    let round_two_aggregate_roots = scheduled_levels
        .iter()
        .map(|level| {
            let aggregate_root = derive_protocol_hash(
                "RelinearizationRoundTwoAggregateRoot",
                &serde_json::json!({
                    "objectType": "RelinearizationRoundTwoAggregate",
                    "objectVersion": 1,
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "level": level,
                    "roundOneAggregateRoot": round_one_aggregate_root_by_level
                        .get(level)
                        .expect("round-one aggregate root"),
                    "roundTwoRecordRoots": round_two_roots_by_level
                        .get(level)
                        .expect("round-two roots by level"),
                }),
            )
            .expect("round-two aggregate root");
            serde_json::json!({
                "level": level,
                "roundTwoAggregateRoot": aggregate_root,
            })
        })
        .collect::<Vec<_>>();

    let mut rounds = serde_json::json!({
        "objectType": "RelinearizationKeyShareRounds",
        "objectVersion": 1,
        "proofFamily": "relinearization-key-share",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": participant_count_from_package(package),
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
        "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
        "relinearizationLevelSchedule": schedule["relinearizationLevelSchedule"],
        "roundOneAggregateRoots": round_one_aggregate_roots,
        "roundOneRecords": round_one_records,
        "roundTwoAggregateRoots": round_two_aggregate_roots,
        "roundTwoRecords": round_two_records,
    });
    rounds["relinearizationKeyShareRoundsRoot"] = serde_json::json!(
        derive_protocol_hash("RelinearizationKeyShareRoundsRoot", &rounds)
            .expect("relinearization rounds root")
    );

    RelinearizationKeyShareRoundsFixture {
        rounds,
        round_one_aggregate_diagonals_by_level,
    }
}
