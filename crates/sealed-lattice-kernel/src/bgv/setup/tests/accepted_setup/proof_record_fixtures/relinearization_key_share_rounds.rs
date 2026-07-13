use super::*;
use rayon::prelude::*;

use crate::bgv::setup::evaluation_key_share_material::{
    EvaluationKeyShareDerivedMaterialBinding, EvaluationKeyShareProofFamily,
};
use crate::hashing::derive_canonical_object_hash;

// Builds the relinearization key-share rounds container the accepted-setup
// verifier's `verify_relinearization_key_share_rounds` recomputes: two-round
// collective relinearization with round-one shares of the trustee secret, the
// public round-one aggregate diagonals, and round-two shares against that
// aggregate. Component vectors cross the canonical authenticated stream and the
// records retain only their material roots. Every record and aggregate root is a
// canonical object hash with no profile-identifier fields, matching the
// verifier's recompute exactly.
pub(in super::super) fn relinearization_key_share_rounds_fixture(
    package: &serde_json::Value,
    accepted_setup_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> RelinearizationKeyShareRoundsFixture {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let participant_count = participant_count_from_package(package);
    let trustee_roster_positions = (0..participant_count).collect::<Vec<_>>();
    let level_schedule = schedule["relinearizationLevelSchedule"]
        .as_array()
        .expect("relinearization level schedule");
    let scheduled_levels = level_schedule
        .iter()
        .map(|level_entry| level_entry["level"].as_u64().expect("level"))
        .collect::<Vec<_>>();

    let mut round_one_records = Vec::new();
    let mut round_one_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    let mut round_one_aggregate_diagonals_by_level = BTreeMap::<u64, Vec<Vec<u64>>>::new();
    let mut transported_component_materials = Vec::new();
    let ring_degree = public_coefficient_commitment_ring_degree_from_fixture_package(package);
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex =
            relinearization_key_switch_seed_for_test(schedule, "round-one", level);
        // Generate every trustee's key-switch component material for this level
        // in parallel; the deterministic material is then consumed in roster
        // order by the sequential aggregate-accumulation and record-building
        // pass below, so the emitted records and roots are byte-identical.
        let level_materials: Vec<EvaluationKeyShareFixtureMaterial> = trustee_roster_positions
            .par_iter()
            .map(|trustee_roster_position| {
                let trustee_roster_position = *trustee_roster_position;
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
        for (trustee_roster_position, fixture_material) in trustee_roster_positions
            .iter()
            .copied()
            .zip(level_materials)
        {
            let trustee_identity = format!("trustee-{trustee_roster_position}");
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
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundOne",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity.as_str(),
                "trusteeRosterPosition": trustee_roster_position,
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
            });
            let authenticated_material =
                authenticate_evaluation_key_share_component_material_fixture(
                    EvaluationKeyShareProofFamily::Relinearization,
                    &record,
                    EvaluationKeyShareDerivedMaterialBinding {
                        trustee_identity: &trustee_identity,
                        trustee_roster_position,
                        key_switch_domain: "relinearization",
                        key_switch_seed_hex: &key_switch_seed_hex,
                    },
                    ring_degree,
                    &fixture_material,
                    accepted_setup_session,
                );
            record["keySwitchComponentMaterialRoot"] =
                serde_json::json!(authenticated_material.material_root);
            transported_component_materials.push(authenticated_material.transported_material);
            record["roundOneRecordRoot"] = serde_json::json!(
                derive_canonical_object_hash(&record).expect("round-one record root")
            );
            let record_root = record["roundOneRecordRoot"]
                .as_str()
                .expect("round-one record root")
                .to_string();
            round_one_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity.as_str(),
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundOneRecordRoot": record_root,
                }));
            round_one_records.push(record);
        }
    }
    let mut round_one_aggregate_roots = Vec::new();
    let mut round_one_aggregate_root_by_level = BTreeMap::new();
    for level in &scheduled_levels {
        let level = *level;
        let aggregate_root = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "RelinearizationRoundOneAggregate",
            "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
            "level": level,
            "roundOneRecordRoots": round_one_roots_by_level
                .get(&level)
                .expect("round-one roots by level"),
        }))
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
        let level_materials: Vec<EvaluationKeyShareFixtureMaterial> = trustee_roster_positions
            .par_iter()
            .map(|trustee_roster_position| {
                let trustee_roster_position = *trustee_roster_position;
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
        for (trustee_roster_position, fixture_material) in trustee_roster_positions
            .iter()
            .copied()
            .zip(level_materials)
        {
            let trustee_identity = format!("trustee-{trustee_roster_position}");
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundTwo",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity.as_str(),
                "trusteeRosterPosition": trustee_roster_position,
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
            });
            let authenticated_material =
                authenticate_evaluation_key_share_component_material_fixture(
                    EvaluationKeyShareProofFamily::Relinearization,
                    &record,
                    EvaluationKeyShareDerivedMaterialBinding {
                        trustee_identity: &trustee_identity,
                        trustee_roster_position,
                        key_switch_domain: "relinearization",
                        key_switch_seed_hex: &key_switch_seed_hex,
                    },
                    ring_degree,
                    &fixture_material,
                    accepted_setup_session,
                );
            record["keySwitchComponentMaterialRoot"] =
                serde_json::json!(authenticated_material.material_root);
            transported_component_materials.push(authenticated_material.transported_material);
            record["roundTwoRecordRoot"] = serde_json::json!(
                derive_canonical_object_hash(&record).expect("round-two record root")
            );
            let record_root = record["roundTwoRecordRoot"]
                .as_str()
                .expect("round-two record root")
                .to_string();
            round_two_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity.as_str(),
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundTwoRecordRoot": record_root,
                }));
            round_two_records.push(record);
        }
    }
    let round_two_aggregate_roots = scheduled_levels
        .iter()
        .map(|level| {
            let aggregate_root = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "RelinearizationRoundTwoAggregate",
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "level": level,
                "roundOneAggregateRoot": round_one_aggregate_root_by_level
                    .get(level)
                    .expect("round-one aggregate root"),
                "roundTwoRecordRoots": round_two_roots_by_level
                    .get(level)
                    .expect("round-two roots by level"),
            }))
            .expect("round-two aggregate root");
            serde_json::json!({
                "level": level,
                "roundTwoAggregateRoot": aggregate_root,
            })
        })
        .collect::<Vec<_>>();

    let mut rounds = serde_json::json!({
        "objectType": "RelinearizationKeyShareRounds",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
        "roundOneAggregateRoots": round_one_aggregate_roots,
        "roundOneRecords": round_one_records,
        "roundTwoAggregateRoots": round_two_aggregate_roots,
        "roundTwoRecords": round_two_records,
    });
    rounds["relinearizationKeyShareRoundsRoot"] = serde_json::json!(
        derive_canonical_object_hash(&rounds).expect("relinearization rounds root")
    );

    RelinearizationKeyShareRoundsFixture {
        rounds,
        round_one_aggregate_diagonals_by_level,
        transported_component_materials,
    }
}
