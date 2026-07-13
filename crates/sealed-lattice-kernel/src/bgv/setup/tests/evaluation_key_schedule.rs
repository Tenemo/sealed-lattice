use super::*;
use crate::bgv::evaluator::{
    records::MAXIMUM_OPTION_COUNT,
    top_k::{SELECTED_EVALUATOR_WORKING_LEVEL, selected_evaluator_rotation_key_schedule},
};

#[test]
fn selected_rotation_key_schedule_matches_package_commitment() {
    let package = setup_package();
    let full_schedule = selected_evaluator_rotation_key_schedule(MAXIMUM_OPTION_COUNT)
        .expect("full selected rotation schedule");

    assert_eq!(full_schedule.len(), 23);
    assert!(
        full_schedule
            .iter()
            .any(|(rotation, level)| *rotation == 3 && *level == SELECTED_EVALUATOR_WORKING_LEVEL)
    );
    assert!(
        full_schedule
            .iter()
            .any(|(rotation, level)| *rotation == 2 * POLYNOMIAL_DEGREE - 1
                && *level == SELECTED_EVALUATOR_WORKING_LEVEL)
    );
    assert!(
        full_schedule
            .iter()
            .all(|(_, level)| *level == SELECTED_EVALUATOR_WORKING_LEVEL)
    );

    let committed_rotation_schedule = package["evaluationKeys"]["evaluationKeyMaterialCommitment"]
        ["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots")
        .iter()
        .map(|entry| {
            (
                entry["rotation"]
                    .as_u64()
                    .expect("rotation")
                    .try_into()
                    .expect("rotation fits usize"),
                entry["level"]
                    .as_u64()
                    .expect("level")
                    .try_into()
                    .expect("level fits usize"),
            )
        })
        .collect::<Vec<(usize, usize)>>();
    let committed_relinearization_levels = package["evaluationKeys"]
        ["evaluationKeyMaterialCommitment"]["relinearizationKeyRecord"]["levelSchedule"]
        .as_array()
        .expect("relinearization level schedule")
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .expect("level")
                .try_into()
                .expect("level fits usize")
        })
        .collect::<Vec<usize>>();

    assert_eq!(committed_rotation_schedule, full_schedule);
    assert_eq!(
        committed_relinearization_levels,
        vec![SELECTED_EVALUATOR_WORKING_LEVEL]
    );
}
