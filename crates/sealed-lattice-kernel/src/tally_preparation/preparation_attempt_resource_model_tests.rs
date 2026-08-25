use super::{
    TallyPreparationError,
    preparation_attempt_resource_model::{
        PreparationAttemptLimits, PreparationAttemptResourceFloor,
        PreparationAttemptResourceFloorInput,
    },
};

const ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET: u64 = 2_147_483_648;

#[test]
fn ballot_and_preparation_attempt_counts_remain_independent() {
    let one_preparation_attempt = PreparationAttemptLimits::for_current_tally_circuit(1).unwrap();
    let three_preparation_attempts =
        PreparationAttemptLimits::for_current_tally_circuit(3).unwrap();

    assert_eq!(one_preparation_attempt.ballot_attempt_count(), 3);
    assert_eq!(three_preparation_attempts.ballot_attempt_count(), 3);
    assert_eq!(
        one_preparation_attempt.maximum_preparation_attempt_count(),
        1
    );
    assert_eq!(
        three_preparation_attempts.maximum_preparation_attempt_count(),
        3
    );
    assert_ne!(one_preparation_attempt, three_preparation_attempts);
}

#[test]
fn zero_attempt_limits_are_rejected_by_their_own_parameter() {
    assert_eq!(
        PreparationAttemptLimits::new(0, 1),
        Err(TallyPreparationError::BallotAttemptCountZero)
    );
    assert_eq!(
        PreparationAttemptLimits::new(3, 0),
        Err(TallyPreparationError::MaximumPreparationAttemptCountZero)
    );
}

#[test]
fn external_candidate_floor_exposes_the_three_attempt_upload_failure() {
    let resource_input = PreparationAttemptResourceFloorInput {
        private_delivery_byte_length_per_fully_delivered_attempt: 1_620_152_640,
        retained_public_byte_length_per_burned_attempt: 0,
        retained_public_byte_length_per_successful_attempt: 426_163_836,
    };
    let resource_floor = PreparationAttemptResourceFloor::derive(
        PreparationAttemptLimits::for_current_tally_circuit(3).unwrap(),
        resource_input,
    )
    .unwrap();

    assert_eq!(resource_floor.one_success_upload_byte_length, 2_046_316_476);
    assert_eq!(
        resource_floor.maximum_fully_delivered_private_byte_length,
        4_860_457_920
    );
    assert_eq!(
        resource_floor.maximum_fully_delivered_private_byte_length
            - ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET,
        2_712_974_272
    );
    assert_eq!(
        resource_floor.maximum_late_burn_then_success_upload_byte_length,
        5_286_621_756
    );
    assert_eq!(
        resource_floor.maximum_all_burn_upload_byte_length,
        4_860_457_920
    );
    assert_eq!(
        resource_floor.maximum_reachable_upload_byte_length,
        5_286_621_756
    );
    assert_eq!(
        resource_floor.excess_over_upload_target(ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET),
        3_139_138_108
    );
    assert!(
        resource_floor
            .exceeds_architecture_review_boundary(ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET)
            .unwrap()
    );
}

#[test]
fn all_burn_and_final_success_branches_are_compared() {
    let limits = PreparationAttemptLimits::new(5, 3).unwrap();
    let all_burn_is_larger = PreparationAttemptResourceFloor::derive(
        limits,
        PreparationAttemptResourceFloorInput {
            private_delivery_byte_length_per_fully_delivered_attempt: 100,
            retained_public_byte_length_per_burned_attempt: 90,
            retained_public_byte_length_per_successful_attempt: 10,
        },
    )
    .unwrap();
    assert_eq!(
        all_burn_is_larger.maximum_late_burn_then_success_upload_byte_length,
        490
    );
    assert_eq!(all_burn_is_larger.maximum_all_burn_upload_byte_length, 570);
    assert_eq!(all_burn_is_larger.maximum_reachable_upload_byte_length, 570);

    let final_success_is_larger = PreparationAttemptResourceFloor::derive(
        limits,
        PreparationAttemptResourceFloorInput {
            private_delivery_byte_length_per_fully_delivered_attempt: 100,
            retained_public_byte_length_per_burned_attempt: 10,
            retained_public_byte_length_per_successful_attempt: 90,
        },
    )
    .unwrap();
    assert_eq!(
        final_success_is_larger.maximum_late_burn_then_success_upload_byte_length,
        410
    );
    assert_eq!(
        final_success_is_larger.maximum_all_burn_upload_byte_length,
        330
    );
    assert_eq!(
        final_success_is_larger.maximum_reachable_upload_byte_length,
        410
    );
}

#[test]
fn a_single_preparation_attempt_has_no_burned_predecessor() {
    let resource_floor = PreparationAttemptResourceFloor::derive(
        PreparationAttemptLimits::new(7, 1).unwrap(),
        PreparationAttemptResourceFloorInput {
            private_delivery_byte_length_per_fully_delivered_attempt: 120,
            retained_public_byte_length_per_burned_attempt: 70,
            retained_public_byte_length_per_successful_attempt: 30,
        },
    )
    .unwrap();

    assert_eq!(resource_floor.one_success_upload_byte_length, 150);
    assert_eq!(
        resource_floor.maximum_fully_delivered_private_byte_length,
        120
    );
    assert_eq!(
        resource_floor.maximum_late_burn_then_success_upload_byte_length,
        150
    );
    assert_eq!(resource_floor.maximum_all_burn_upload_byte_length, 190);
    assert_eq!(resource_floor.maximum_reachable_upload_byte_length, 190);
}

#[test]
fn resource_arithmetic_refuses_overflow() {
    assert_eq!(
        PreparationAttemptResourceFloor::derive(
            PreparationAttemptLimits::new(3, 2).unwrap(),
            PreparationAttemptResourceFloorInput {
                private_delivery_byte_length_per_fully_delivered_attempt: u64::MAX,
                retained_public_byte_length_per_burned_attempt: 0,
                retained_public_byte_length_per_successful_attempt: 0,
            },
        ),
        Err(TallyPreparationError::ArithmeticOverflow)
    );

    let resource_floor = PreparationAttemptResourceFloor::derive(
        PreparationAttemptLimits::new(3, 1).unwrap(),
        PreparationAttemptResourceFloorInput {
            private_delivery_byte_length_per_fully_delivered_attempt: 1,
            retained_public_byte_length_per_burned_attempt: 0,
            retained_public_byte_length_per_successful_attempt: 0,
        },
    )
    .unwrap();
    assert_eq!(
        resource_floor.exceeds_architecture_review_boundary(u64::MAX),
        Err(TallyPreparationError::ArithmeticOverflow)
    );
}
