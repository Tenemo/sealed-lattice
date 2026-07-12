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

#[test]
fn passive_setup_evaluation_key_stream_drives_key_switch_primitives() {
    let package = setup_package();
    let evaluator_key = setup_derived_evaluator_key();
    let sampled_checks = package["evaluationKeys"]["evaluationKeyMaterialCommitment"]["record"]
        ["sampledRelationChecks"]
        .as_array()
        .expect("sampled relation checks");
    let relinearization_seed = sampled_checks
        .iter()
        .find(|check| {
            check["keyKind"] == "relinearization"
                && check["level"] == SELECTED_EVALUATOR_WORKING_LEVEL
        })
        .and_then(|check| check["keyStreamSeed"].as_str())
        .expect("working-level relinearization stream seed");
    let rotation_check = sampled_checks
        .iter()
        .find(|check| {
            check["keyKind"] == "rotation"
                && check["level"] == SELECTED_EVALUATOR_WORKING_LEVEL
                && check["purpose"] == "generator-ordered-packed-rank-return-basis"
        })
        .expect("packed-rank return rotation stream check");
    let rotation = rotation_check["rotation"]
        .as_u64()
        .expect("rotation")
        .try_into()
        .expect("rotation fits usize");
    let rotation_seed = rotation_check["keyStreamSeed"]
        .as_str()
        .expect("rotation stream seed");

    let left = modulus_switch_to(
        &evaluator_key
            .encrypt_slots(&[2, 3, 4, 5], "setup-material-left")
            .expect("left"),
        DIRECT_COMPARISON_OUTPUT_LEVEL,
    )
    .expect("left level");
    let right = modulus_switch_to(
        &evaluator_key
            .encrypt_slots(&[7, 8, 9, 10], "setup-material-right")
            .expect("right"),
        DIRECT_COMPARISON_OUTPUT_LEVEL,
    )
    .expect("right level");
    let relinearization_key = generate_relinearization_key(
        evaluator_key,
        SELECTED_EVALUATOR_WORKING_LEVEL,
        relinearization_seed,
    )
    .expect("setup stream relinearization key");
    let product = relinearize(
        &ciphertext_tensor(&left, &right).expect("tensor"),
        &relinearization_key,
    )
    .expect("relinearize with setup stream key");
    let product_slots = evaluator_key
        .decrypt_to_slots(&product)
        .expect("product decrypt");
    assert_eq!(&product_slots[..4], &[14, 24, 36, 50]);

    let rotation_key = generate_galois_key(
        evaluator_key,
        rotation,
        SELECTED_EVALUATOR_WORKING_LEVEL,
        rotation_seed,
    )
    .expect("setup stream rotation key");
    let rotated = rotate(&left, rotation, &rotation_key).expect("rotate with setup stream key");
    let plaintext_coefficients =
        encode_slots_to_coefficients(&[2, 3, 4, 5]).expect("encode plaintext");
    let rotated_coefficients =
        automorphism_residues(&plaintext_coefficients, rotation, PLAINTEXT_MODULUS);
    let expected_slots =
        forward_negacyclic_ntt(&rotated_coefficients, PLAINTEXT_MODULUS).expect("decode");
    let rotated_slots = evaluator_key
        .decrypt_to_slots(&rotated)
        .expect("rotated decrypt");
    assert_eq!(rotated_slots, expected_slots);
}
