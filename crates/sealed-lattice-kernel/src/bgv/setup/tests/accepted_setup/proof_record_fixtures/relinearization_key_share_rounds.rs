use super::*;
use rayon::prelude::*;

use crate::bgv::setup::accepted_setup::{
    evaluation_key_proof_common_binding, expected_relinearization_key_switch_seed,
    scheduled_relinearization_levels,
};
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
    let evaluation_key_binding =
        evaluation_key_proof_common_binding(package).expect("evaluation-key proof binding");
    let participant_count = participant_count_from_package(package);
    let trustee_roster_positions = (0..participant_count).collect::<Vec<_>>();
    let scheduled_levels =
        scheduled_relinearization_levels().expect("relinearization level schedule");

    let mut round_one_key_switch_component_material_roots = Vec::new();
    let mut round_one_aggregate_diagonals_by_level = BTreeMap::<u64, Vec<Vec<u64>>>::new();
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex =
            expected_relinearization_key_switch_seed(&evaluation_key_binding, "round-one", level)
                .expect("round-one relinearization key-switch seed");
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
            round_one_key_switch_component_material_roots.push(authenticated_material_root);
        }
    }

    let mut round_two_key_switch_component_material_roots = Vec::new();
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex =
            expected_relinearization_key_switch_seed(&evaluation_key_binding, "round-two", level)
                .expect("round-two relinearization key-switch seed");
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
            round_two_key_switch_component_material_roots.push(authenticated_material_root);
        }
    }

    let rounds = serde_json::json!({
        "objectType": "RelinearizationKeyShareRounds",
        "roundOneKeySwitchComponentMaterialRoots": round_one_key_switch_component_material_roots,
        "roundTwoKeySwitchComponentMaterialRoots": round_two_key_switch_component_material_roots,
    });

    RelinearizationKeyShareRoundsFixture {
        rounds,
        round_one_aggregate_diagonals_by_level,
    }
}
