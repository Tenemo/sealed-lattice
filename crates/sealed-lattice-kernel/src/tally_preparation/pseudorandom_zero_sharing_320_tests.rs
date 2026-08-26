use crate::foundation::{
    FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
};

use super::{
    TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    preparation_attempt_resource_model::{
        PreparationAttemptLimits, PreparationAttemptResourceFloor,
        PreparationAttemptResourceFloorInput,
    },
    pseudorandom_zero_sharing_320::{
        CanonicalZeroSharingCodewordVerifier320, PseudorandomZeroSharingResourceInput,
        PseudorandomZeroSharingResourceModel, canonical_evaluation_point_320,
        evaluate_pseudorandom_zero_sharing_subset_at_point,
    },
    replicated_random_sharing::{ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset},
};

const COMPLETION_ZERO_SHARING_COUNT: u64 = 33_346;
const ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET: u64 = 2_147_483_648;

#[test]
fn every_completion_subset_basis_is_zero_at_the_origin_and_excluded_points() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let geometry = ReplicatedRandomSharingGeometry::derive(participant_count).unwrap();
    let subsets = ReplicatedRandomSharingSubset::all(participant_count).unwrap();

    assert_eq!(subsets.len(), 120);
    for subset in subsets {
        let component_count = usize::try_from(geometry.active_fault_bound).unwrap();
        for component_position in 0..component_count {
            let mut components = vec![BinaryFieldElement320::ZERO; component_count];
            components[component_position] = BinaryFieldElement320::ONE;
            assert_eq!(
                evaluate_pseudorandom_zero_sharing_subset_at_point(
                    subset,
                    &components,
                    BinaryFieldElement320::ZERO,
                )
                .unwrap(),
                BinaryFieldElement320::ZERO
            );
            for excluded_position in subset.excluded_positions() {
                assert_eq!(
                    evaluate_pseudorandom_zero_sharing_subset_at_point(
                        subset,
                        &components,
                        canonical_evaluation_point_320(participant_count, excluded_position)
                            .unwrap(),
                    )
                    .unwrap(),
                    BinaryFieldElement320::ZERO
                );
            }
        }

        let selected_member_positions = subset.member_positions()[..3].to_vec();
        let basis_matrix = core::array::from_fn::<_, 3, _>(|row_position| {
            core::array::from_fn::<_, 3, _>(|column_position| {
                let mut components = vec![BinaryFieldElement320::ZERO; 3];
                components[column_position] = BinaryFieldElement320::ONE;
                evaluate_pseudorandom_zero_sharing_subset_at_point(
                    subset,
                    &components,
                    canonical_evaluation_point_320(
                        participant_count,
                        selected_member_positions[row_position],
                    )
                    .unwrap(),
                )
                .unwrap()
            })
        });
        assert!(!three_by_three_determinant(basis_matrix).is_zero());
    }
}

#[test]
fn summed_subset_sharing_forms_an_exact_zero_constant_degree_six_codeword() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let subsets = ReplicatedRandomSharingSubset::all(participant_count).unwrap();
    let mut values = vec![BinaryFieldElement320::ZERO; usize::from(participant_count)];
    let mut origin_value = BinaryFieldElement320::ZERO;

    for (subset_position, subset) in subsets.iter().copied().enumerate() {
        let components = (0..usize::from(subset.active_fault_bound()))
            .map(|component_position| {
                BinaryFieldElement320::from_low_polynomial_u16(
                    u16::try_from(1 + subset_position * 3 + component_position).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        origin_value = origin_value.add(
            evaluate_pseudorandom_zero_sharing_subset_at_point(
                subset,
                &components,
                BinaryFieldElement320::ZERO,
            )
            .unwrap(),
        );
        for (roster_position, value) in values.iter_mut().enumerate() {
            *value = value.add(
                evaluate_pseudorandom_zero_sharing_subset_at_point(
                    subset,
                    &components,
                    canonical_evaluation_point_320(
                        participant_count,
                        u16::try_from(roster_position).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
        }
    }

    assert_eq!(origin_value, BinaryFieldElement320::ZERO);
    let verifier = CanonicalZeroSharingCodewordVerifier320::new(participant_count).unwrap();
    assert!(verifier.verify(&values).unwrap());
    for mutated_position in 0..values.len() {
        let mut mutated_values = values.clone();
        mutated_values[mutated_position] =
            mutated_values[mutated_position].add(BinaryFieldElement320::ONE);
        assert!(!verifier.verify(&mutated_values).unwrap());
    }
}

#[test]
fn zero_codeword_verifier_accepts_general_degree_six_polynomials_and_rejects_constants() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let verifier = CanonicalZeroSharingCodewordVerifier320::new(participant_count).unwrap();
    let coefficients = [
        BinaryFieldElement320::ZERO,
        field_element(17),
        field_element(29),
        field_element(43),
        field_element(61),
        field_element(83),
        field_element(107),
    ];
    let values = (0..participant_count)
        .map(|roster_position| {
            evaluate_polynomial(
                &coefficients,
                canonical_evaluation_point_320(participant_count, roster_position).unwrap(),
            )
        })
        .collect::<Vec<_>>();

    assert!(verifier.verify(&values).unwrap());
    assert!(
        !verifier
            .verify(&vec![
                BinaryFieldElement320::ONE;
                usize::from(participant_count)
            ])
            .unwrap()
    );
    assert_eq!(
        verifier.verify(&values[..values.len() - 1]),
        Err(TallyPreparationError::GeometryMismatch)
    );
}

#[test]
fn completion_resource_model_reproduces_setup_stream_and_codeword_work() {
    let model = completion_resource_model();

    assert_eq!(model.participant_count, 10);
    assert_eq!(model.active_fault_bound, 3);
    assert_eq!(model.authorized_subset_size, 7);
    assert_eq!(model.authorized_subset_count, 120);
    assert_eq!(model.authorized_subset_count_per_participant, 84);
    assert_eq!(model.seed_contribution_count, 840);
    assert_eq!(model.remote_seed_opening_delivery_count, 5_040);
    assert_eq!(model.seed_opening_byte_length, 104);
    assert_eq!(model.private_seed_opening_delivery_byte_length, 524_160);
    assert_eq!(model.ordered_mailbox_stream_count, 90);
    assert_eq!(model.private_mailbox_wrapper_byte_length, 460_800);
    assert_eq!(model.private_setup_delivery_byte_length, 984_960);
    assert_eq!(
        model.maximum_private_setup_upload_byte_length_per_participant,
        98_496
    );
    assert_eq!(
        model.maximum_private_setup_download_byte_length_per_participant,
        98_496
    );
    assert_eq!(
        model.combined_seed_custody_byte_length_per_participant,
        3_360
    );
    assert_eq!(model.subset_basis_stream_count_per_participant, 252);
    assert_eq!(model.basis_weight_live_byte_length_per_participant, 10_080);
    assert_eq!(
        model.basis_precomputation_field_multiplication_count_per_participant,
        420
    );
    assert_eq!(model.field_output_count_per_participant, 8_403_192);
    assert_eq!(model.field_output_byte_length_per_participant, 336_127_680);
    assert_eq!(model.full_chunk_field_count, 26_214);
    assert_eq!(model.full_chunk_payload_byte_length, 1_048_560);
    assert_eq!(model.field_output_chunk_count_per_participant, 504);
    assert_eq!(model.final_chunk_field_count, 7_132);
    assert_eq!(model.final_chunk_payload_byte_length, 285_280);
    assert_eq!(
        model.stream_field_multiplication_count_per_participant,
        8_403_192
    );
    assert_eq!(model.stream_field_addition_count_per_participant, 8_369_846);
    assert_eq!(
        model.zero_codeword_check_field_multiplication_count_per_participant,
        933_688
    );
    assert_eq!(
        model.zero_codeword_check_field_addition_count_per_participant,
        800_304
    );
    assert_eq!(
        model.zero_codeword_check_comparison_count_per_participant,
        133_384
    );
    assert_eq!(
        model.total_field_multiplication_floor_per_participant,
        9_337_300
    );
}

#[test]
fn replacement_setup_and_one_attempt_policy_fit_the_formula_only_upload_target() {
    let model = completion_resource_model();
    let superseded_private_delivery_byte_length = 1_620_152_640_u64;
    let superseded_zero_slice_delivery_byte_length = 480_182_400_u64;
    let superseded_zero_check_delivery_byte_length = 36_000_u64;
    let replacement_private_delivery_byte_length = superseded_private_delivery_byte_length
        - superseded_zero_slice_delivery_byte_length
        - superseded_zero_check_delivery_byte_length
        + model.private_setup_delivery_byte_length;
    assert_eq!(replacement_private_delivery_byte_length, 1_140_919_200);

    let floor = PreparationAttemptResourceFloor::derive(
        PreparationAttemptLimits::for_current_tally_circuit(1).unwrap(),
        PreparationAttemptResourceFloorInput {
            private_delivery_byte_length_per_fully_delivered_attempt:
                replacement_private_delivery_byte_length,
            retained_public_byte_length_per_burned_attempt: 0,
            retained_public_byte_length_per_successful_attempt: 426_163_836,
        },
    )
    .unwrap();
    assert_eq!(floor.maximum_reachable_upload_byte_length, 1_567_083_036);
    assert_eq!(
        ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET - floor.maximum_reachable_upload_byte_length,
        580_400_612
    );
    assert!(
        !floor
            .exceeds_architecture_review_boundary(ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET)
            .unwrap()
    );
}

#[test]
fn every_positive_fault_geometry_uses_formula_derived_subset_and_stream_counts() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        if roster_parameters.active_fault_bound == 0 {
            assert_eq!(
                PseudorandomZeroSharingResourceModel::derive(
                    PseudorandomZeroSharingResourceInput {
                        participant_count,
                        zero_sharing_count: 19,
                        seed_contribution_byte_length: 40,
                        commitment_salt_byte_length: 64,
                        field_element_byte_length: 40,
                        mailbox_stream_wrapper_byte_length: 5_120,
                        maximum_transport_payload_byte_length: 1_048_576,
                    },
                ),
                Err(TallyPreparationError::GeometryMismatch)
            );
            continue;
        }
        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count).unwrap();
        let model =
            PseudorandomZeroSharingResourceModel::derive(PseudorandomZeroSharingResourceInput {
                participant_count,
                zero_sharing_count: 19,
                seed_contribution_byte_length: 40,
                commitment_salt_byte_length: 64,
                field_element_byte_length: 40,
                mailbox_stream_wrapper_byte_length: 5_120,
                maximum_transport_payload_byte_length: 1_048_576,
            })
            .unwrap();

        assert_eq!(
            model.seed_contribution_count,
            geometry.authorized_subset_count * geometry.authorized_subset_size
        );
        assert_eq!(
            model.remote_seed_opening_delivery_count,
            model.seed_contribution_count * (geometry.authorized_subset_size - 1)
        );
        assert_eq!(
            model.ordered_mailbox_stream_count,
            u64::from(participant_count) * u64::from(participant_count - 1)
        );
        assert_eq!(
            model.field_output_count_per_participant,
            19 * geometry.authorized_subset_count_per_participant * geometry.active_fault_bound
        );
    }
}

#[test]
fn invalid_or_overflowing_resource_shapes_and_algebra_inputs_are_rejected() {
    let invalid_input = PseudorandomZeroSharingResourceInput {
        participant_count: FOUNDATION_PROFILE.participant_count,
        zero_sharing_count: 0,
        seed_contribution_byte_length: 40,
        commitment_salt_byte_length: 64,
        field_element_byte_length: 40,
        mailbox_stream_wrapper_byte_length: 5_120,
        maximum_transport_payload_byte_length: 1_048_576,
    };
    assert_eq!(
        PseudorandomZeroSharingResourceModel::derive(invalid_input),
        Err(TallyPreparationError::GeometryMismatch)
    );
    assert_eq!(
        PseudorandomZeroSharingResourceModel::derive(PseudorandomZeroSharingResourceInput {
            zero_sharing_count: u64::MAX,
            ..invalid_input
        }),
        Err(TallyPreparationError::ArithmeticOverflow)
    );
    assert_eq!(
        PseudorandomZeroSharingResourceModel::derive(PseudorandomZeroSharingResourceInput {
            zero_sharing_count: 1,
            maximum_transport_payload_byte_length: 39,
            ..invalid_input
        }),
        Err(TallyPreparationError::GeometryMismatch)
    );

    let subset =
        ReplicatedRandomSharingSubset::all(FOUNDATION_PROFILE.participant_count).unwrap()[0];
    assert_eq!(
        evaluate_pseudorandom_zero_sharing_subset_at_point(
            subset,
            &[BinaryFieldElement320::ONE; 2],
            BinaryFieldElement320::ONE,
        ),
        Err(TallyPreparationError::GeometryMismatch)
    );
    assert!(matches!(
        canonical_evaluation_point_320(FOUNDATION_PROFILE.participant_count, u16::MAX),
        Err(TallyPreparationError::RosterPositionOutOfRange { .. })
    ));
}

fn completion_resource_model() -> PseudorandomZeroSharingResourceModel {
    PseudorandomZeroSharingResourceModel::derive(PseudorandomZeroSharingResourceInput {
        participant_count: FOUNDATION_PROFILE.participant_count,
        zero_sharing_count: COMPLETION_ZERO_SHARING_COUNT,
        seed_contribution_byte_length: 40,
        commitment_salt_byte_length: 64,
        field_element_byte_length: 40,
        mailbox_stream_wrapper_byte_length: 5_120,
        maximum_transport_payload_byte_length: 1_048_576,
    })
    .unwrap()
}

fn field_element(value: u16) -> BinaryFieldElement320 {
    BinaryFieldElement320::from_low_polynomial_u16(value)
}

fn evaluate_polynomial(
    coefficients: &[BinaryFieldElement320],
    evaluation_point: BinaryFieldElement320,
) -> BinaryFieldElement320 {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(BinaryFieldElement320::ZERO, |value, coefficient| {
            value.multiply(evaluation_point).add(coefficient)
        })
}

fn three_by_three_determinant(matrix: [[BinaryFieldElement320; 3]; 3]) -> BinaryFieldElement320 {
    [
        matrix[0][0].multiply(matrix[1][1]).multiply(matrix[2][2]),
        matrix[0][0].multiply(matrix[1][2]).multiply(matrix[2][1]),
        matrix[0][1].multiply(matrix[1][0]).multiply(matrix[2][2]),
        matrix[0][1].multiply(matrix[1][2]).multiply(matrix[2][0]),
        matrix[0][2].multiply(matrix[1][0]).multiply(matrix[2][1]),
        matrix[0][2].multiply(matrix[1][1]).multiply(matrix[2][0]),
    ]
    .into_iter()
    .fold(BinaryFieldElement320::ZERO, BinaryFieldElement320::add)
}
