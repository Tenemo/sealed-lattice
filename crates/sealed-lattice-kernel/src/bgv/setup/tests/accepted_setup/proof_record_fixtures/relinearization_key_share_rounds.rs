use super::*;
use rayon::prelude::*;

use crate::bgv::setup::evaluation_key_share_material::{
    EvaluationKeyShareDerivedMaterialBinding, EvaluationKeyShareProofFamily,
};

// Builds the relinearization key-share rounds container the accepted-setup
// verifier consumes: two-round collective relinearization with round-one
// shares of the trustee secret, the public round-one aggregate diagonals, and
// round-two shares against that aggregate. Component vectors cross the
// canonical authenticated stream and the records retain only their material
// roots.
pub(in super::super) fn relinearization_key_share_rounds_fixture(
    package: &serde_json::Value,
    accepted_setup_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> RelinearizationKeyShareRoundsFixture {
    let schedule = &package["evaluatorKeySchedule"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
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
    let mut round_one_aggregate_diagonals_by_level = BTreeMap::<u64, Vec<Vec<u64>>>::new();
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex = relinearization_key_switch_seed_for_test(
            schedule,
            public_matrix_seed_hash,
            "round-one",
            level,
        );
        // Generate every trustee's key-switch component material for this level
        // in parallel; the deterministic material is then consumed in roster
        // order by the sequential aggregate-accumulation and record-building
        // pass below, so the emitted records are byte-identical.
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
            });
            let authenticated_material_root =
                authenticate_evaluation_key_share_component_material_fixture(
                    EvaluationKeyShareProofFamily::Relinearization,
                    level,
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
                serde_json::json!(authenticated_material_root);
            round_one_records.push(record);
        }
    }

    let mut round_two_records = Vec::new();
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex = relinearization_key_switch_seed_for_test(
            schedule,
            public_matrix_seed_hash,
            "round-two",
            level,
        );
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
            });
            let authenticated_material_root =
                authenticate_evaluation_key_share_component_material_fixture(
                    EvaluationKeyShareProofFamily::Relinearization,
                    level,
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
                serde_json::json!(authenticated_material_root);
            round_two_records.push(record);
        }
    }

    let rounds = serde_json::json!({
        "objectType": "RelinearizationKeyShareRounds",
        "roundOneRecords": round_one_records,
        "roundTwoRecords": round_two_records,
    });

    RelinearizationKeyShareRoundsFixture {
        rounds,
        round_one_aggregate_diagonals_by_level,
    }
}
