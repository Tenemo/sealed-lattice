use crate::foundation::{
    FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
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
    pseudorandom_zero_sharing_seed_catalog_320::PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN,
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
    assert_eq!(model.subset_seed_contribution_count, 840);
    assert_eq!(model.remote_subset_seed_opening_delivery_count, 5_040);
    assert_eq!(model.subset_seed_opening_object_byte_length, 440);
    assert_eq!(
        model.private_subset_seed_opening_delivery_byte_length,
        2_217_600
    );
    assert_eq!(model.pair_seed_opening_delivery_count, 90);
    assert_eq!(model.pair_seed_opening_object_byte_length, 444);
    assert_eq!(model.private_pair_seed_opening_delivery_byte_length, 39_960);
    assert_eq!(model.seed_catalog_inclusion_proof_delivery_count, 5_130);
    assert_eq!(model.seed_catalog_inclusion_proof_byte_length, 658);
    assert_eq!(
        model.private_seed_catalog_inclusion_proof_delivery_byte_length,
        3_375_540
    );
    assert_eq!(model.seed_delivery_descriptor_count, 90);
    assert_eq!(model.seed_delivery_descriptor_body_byte_length, 328);
    assert_eq!(model.private_seed_delivery_descriptor_byte_length, 29_520);
    assert_eq!(
        model.seed_opening_proof_and_descriptor_delivery_byte_length,
        5_662_620
    );
    assert_eq!(model.root_terminal_body_byte_length, 144);
    assert_eq!(model.root_terminal_endorsement_count, 10);
    assert_eq!(
        model.root_terminal_endorsement_authorization_body_byte_length,
        169
    );
    assert_eq!(model.root_terminal_endorsement_envelope_byte_length, 3_589);
    assert_eq!(model.root_terminal_certificate_byte_length, 36_230);
    assert_eq!(model.root_terminal_signature_verification_count, 10);
    assert_eq!(model.ordered_mailbox_stream_count, 90);
    assert_eq!(
        model.provisional_private_mailbox_wrapper_byte_length,
        460_800
    );
    assert_eq!(
        model.provisional_private_setup_delivery_byte_length,
        6_123_420
    );
    assert_eq!(
        model.seed_opening_proof_and_descriptor_upload_byte_length_per_participant,
        566_262
    );
    assert_eq!(
        model.maximum_provisional_private_setup_upload_byte_length_per_participant,
        612_342
    );
    assert_eq!(
        model.maximum_provisional_private_setup_download_byte_length_per_participant,
        612_342
    );
    assert_eq!(
        model.recipient_inventory_body_byte_length_per_participant,
        306
    );
    assert_eq!(
        model.combined_subset_seed_custody_byte_length_per_participant,
        3_360
    );
    assert_eq!(
        model.combined_pair_seed_custody_byte_length_per_participant,
        360
    );
    assert_eq!(
        model.collective_coin_source_custody_byte_length_per_participant,
        40
    );
    assert_eq!(
        model.retained_seed_custody_byte_length_per_participant,
        3_760
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
fn independent_completion_delivery_ledger_matches_every_production_subtotal() {
    let model = completion_resource_model();
    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let active_fault_bound = u64::from(
        derive_foundation_roster_parameters(FOUNDATION_PROFILE.participant_count)
            .unwrap()
            .active_fault_bound,
    );
    let authorized_subset_size = participant_count - active_fault_bound;
    let authorized_subset_count = choose(participant_count, active_fault_bound);
    let subset_seed_contribution_count = authorized_subset_count * authorized_subset_size;
    let remote_subset_seed_opening_delivery_count =
        subset_seed_contribution_count * (authorized_subset_size - 1);
    let ordered_mailbox_stream_count = participant_count * (participant_count - 1);
    let seed_catalog_inclusion_proof_delivery_count =
        remote_subset_seed_opening_delivery_count + ordered_mailbox_stream_count;
    let catalog_leaf_count =
        choose(participant_count - 1, active_fault_bound) + (participant_count - 1) + 1;
    let tree_height = u64::from(catalog_leaf_count.next_power_of_two().ilog2());
    let inclusion_proof_byte_length = 8
        + (4 + tree_height) * 6
        + 4
        + u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN.len())
            .unwrap()
        + u64::try_from(Hash512::BYTE_LENGTH).unwrap()
        + 8
        + 2
        + tree_height * u64::try_from(Hash512::BYTE_LENGTH).unwrap();
    let subset_opening_byte_length = 440_u64;
    let pair_opening_byte_length = 444_u64;
    let descriptor_byte_length = 328_u64;
    let subset_opening_delivery_byte_length =
        remote_subset_seed_opening_delivery_count * subset_opening_byte_length;
    let pair_opening_delivery_byte_length = ordered_mailbox_stream_count * pair_opening_byte_length;
    let inclusion_proof_delivery_byte_length =
        seed_catalog_inclusion_proof_delivery_count * inclusion_proof_byte_length;
    let descriptor_delivery_byte_length = ordered_mailbox_stream_count * descriptor_byte_length;
    let exact_delivery_byte_length = subset_opening_delivery_byte_length
        + pair_opening_delivery_byte_length
        + inclusion_proof_delivery_byte_length
        + descriptor_delivery_byte_length;
    let root_terminal_body_byte_length = 8 + 2 * 6 + 4 + 56 + 64;
    let root_terminal_endorsement_authorization_body_byte_length = 8 + 3 * 6 + 4 + 73 + 64 + 2;
    let root_terminal_endorsement_envelope_byte_length =
        8 + 3 * 6 + 4 + 77 + 4 + root_terminal_endorsement_authorization_body_byte_length + 3_309;
    let root_terminal_certificate_byte_length = 8
        + (2 + participant_count) * 6
        + 4
        + 68
        + 4
        + root_terminal_body_byte_length
        + participant_count * (4 + root_terminal_endorsement_envelope_byte_length);

    assert_eq!(
        model.subset_seed_contribution_count,
        subset_seed_contribution_count
    );
    assert_eq!(
        model.remote_subset_seed_opening_delivery_count,
        remote_subset_seed_opening_delivery_count
    );
    assert_eq!(
        model.private_subset_seed_opening_delivery_byte_length,
        subset_opening_delivery_byte_length
    );
    assert_eq!(
        model.pair_seed_opening_delivery_count,
        ordered_mailbox_stream_count
    );
    assert_eq!(
        model.private_pair_seed_opening_delivery_byte_length,
        pair_opening_delivery_byte_length
    );
    assert_eq!(
        model.seed_catalog_inclusion_proof_delivery_count,
        seed_catalog_inclusion_proof_delivery_count
    );
    assert_eq!(
        model.seed_catalog_inclusion_proof_byte_length,
        inclusion_proof_byte_length
    );
    assert_eq!(
        model.private_seed_catalog_inclusion_proof_delivery_byte_length,
        inclusion_proof_delivery_byte_length
    );
    assert_eq!(
        model.private_seed_delivery_descriptor_byte_length,
        descriptor_delivery_byte_length
    );
    assert_eq!(
        model.seed_opening_proof_and_descriptor_delivery_byte_length,
        exact_delivery_byte_length
    );
    assert_eq!(
        model.root_terminal_body_byte_length,
        root_terminal_body_byte_length
    );
    assert_eq!(model.root_terminal_endorsement_count, participant_count);
    assert_eq!(
        model.root_terminal_endorsement_authorization_body_byte_length,
        root_terminal_endorsement_authorization_body_byte_length
    );
    assert_eq!(
        model.root_terminal_endorsement_envelope_byte_length,
        root_terminal_endorsement_envelope_byte_length
    );
    assert_eq!(
        model.root_terminal_certificate_byte_length,
        root_terminal_certificate_byte_length
    );
    assert_eq!(
        model.root_terminal_signature_verification_count,
        participant_count
    );
}

#[test]
fn replacement_setup_preserves_one_attempt_headroom_but_three_attempts_fail() {
    let model = completion_resource_model();
    let superseded_private_delivery_byte_length = 1_620_152_640_u64;
    let superseded_zero_slice_delivery_byte_length = 480_182_400_u64;
    let superseded_zero_check_delivery_byte_length = 36_000_u64;
    let replacement_private_delivery_byte_length = superseded_private_delivery_byte_length
        - superseded_zero_slice_delivery_byte_length
        - superseded_zero_check_delivery_byte_length
        + model.provisional_private_setup_delivery_byte_length;
    assert_eq!(replacement_private_delivery_byte_length, 1_146_057_660);
    let retained_public_byte_length_per_successful_attempt =
        426_163_836 + model.root_terminal_certificate_byte_length;
    let retained_public_byte_length_per_burned_attempt =
        model.root_terminal_certificate_byte_length;

    let selected_single_attempt_floor = PreparationAttemptResourceFloor::derive(
        PreparationAttemptLimits::for_current_tally_circuit(1).unwrap(),
        PreparationAttemptResourceFloorInput {
            private_delivery_byte_length_per_fully_delivered_attempt:
                replacement_private_delivery_byte_length,
            retained_public_byte_length_per_burned_attempt,
            retained_public_byte_length_per_successful_attempt,
        },
    )
    .unwrap();
    assert_eq!(
        selected_single_attempt_floor.maximum_reachable_upload_byte_length,
        1_572_257_726
    );
    assert_eq!(
        ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET
            - selected_single_attempt_floor.maximum_reachable_upload_byte_length,
        575_225_922
    );
    assert!(
        !selected_single_attempt_floor
            .exceeds_architecture_review_boundary(ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET)
            .unwrap()
    );

    let three_attempt_hostile_floor = PreparationAttemptResourceFloor::derive(
        PreparationAttemptLimits::for_current_tally_circuit(3).unwrap(),
        PreparationAttemptResourceFloorInput {
            private_delivery_byte_length_per_fully_delivered_attempt:
                replacement_private_delivery_byte_length,
            retained_public_byte_length_per_burned_attempt,
            retained_public_byte_length_per_successful_attempt,
        },
    )
    .unwrap();
    assert_eq!(
        three_attempt_hostile_floor.maximum_fully_delivered_private_byte_length,
        3_438_172_980
    );
    assert_eq!(
        three_attempt_hostile_floor.maximum_reachable_upload_byte_length,
        3_864_445_506
    );
    assert_eq!(
        three_attempt_hostile_floor
            .excess_over_upload_target(ALL_PARTICIPANT_UPLOAD_PLANNING_TARGET),
        1_716_961_858
    );
    assert!(
        three_attempt_hostile_floor
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
                        provisional_mailbox_stream_wrapper_byte_length: 5_120,
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
                provisional_mailbox_stream_wrapper_byte_length: 5_120,
            })
            .unwrap();

        assert_eq!(
            model.subset_seed_contribution_count,
            geometry.authorized_subset_count * geometry.authorized_subset_size
        );
        assert_eq!(
            model.remote_subset_seed_opening_delivery_count,
            model.subset_seed_contribution_count * (geometry.authorized_subset_size - 1)
        );
        assert_eq!(
            model.ordered_mailbox_stream_count,
            u64::from(participant_count) * u64::from(participant_count - 1)
        );
        assert_eq!(
            model.pair_seed_opening_delivery_count,
            model.ordered_mailbox_stream_count
        );
        assert_eq!(
            model.seed_catalog_inclusion_proof_delivery_count,
            model.remote_subset_seed_opening_delivery_count
                + model.pair_seed_opening_delivery_count
        );
        assert_eq!(
            model.seed_delivery_descriptor_count,
            model.ordered_mailbox_stream_count
        );
        assert_eq!(
            model.root_terminal_endorsement_count,
            u64::from(participant_count)
        );
        assert_eq!(
            model.root_terminal_signature_verification_count,
            u64::from(participant_count)
        );
        assert_eq!(
            model.seed_opening_proof_and_descriptor_delivery_byte_length,
            model.seed_opening_proof_and_descriptor_upload_byte_length_per_participant
                * u64::from(participant_count)
        );
        assert_eq!(
            model.retained_seed_custody_byte_length_per_participant,
            model.combined_subset_seed_custody_byte_length_per_participant
                + model.combined_pair_seed_custody_byte_length_per_participant
                + model.collective_coin_source_custody_byte_length_per_participant
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
        provisional_mailbox_stream_wrapper_byte_length: 5_120,
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
            provisional_mailbox_stream_wrapper_byte_length: 0,
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
        provisional_mailbox_stream_wrapper_byte_length: 5_120,
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

fn choose(total: u64, selected: u64) -> u64 {
    let selected = selected.min(total - selected);
    (0..selected).fold(1_u64, |value, offset| {
        value * (total - offset) / (offset + 1)
    })
}
