use std::collections::BTreeSet;

use super::*;
use crate::{
    bgv::{
        encoding::{
            decode_plaintext_coefficients_to_extension_lanes,
            encode_extension_lanes_to_plaintext_coefficients,
        },
        evaluator::top_k::{
            SCATTER_GALOIS_ELEMENTS, SCATTER_ROUTES, TRACE_GALOIS_ELEMENTS, TRACE_GALOIS_PATHS,
            compose_galois_path,
        },
        parameters::{
            PLAINTEXT_LANE_IDEMPOTENT_SCALE, PLAINTEXT_LANE_ORBIT_GENERATOR,
            PLAINTEXT_LANE_ROOT_GENERATOR, plaintext_extension_lane_root,
        },
        proof_suite::apply_negacyclic_automorphism,
    },
    encoding::CanonicalErrorCode,
    foundation::FOUNDATION_PROFILE,
};

const PAIR_COUNT: usize = OPTION_COUNT * (OPTION_COUNT - 1) / 2;
const EXPECTED_SHIFT_PLACEMENTS: [(usize, usize, usize); 19] = [
    (1, 0, 7),
    (1, 0, 35),
    (0, 1, 15),
    (0, 1, 33),
    (1, 1, 12),
    (1, 1, 58),
    (0, 0, 38),
    (0, 0, 57),
    (0, 0, 21),
    (1, 1, 31),
    (0, 1, 49),
    (1, 1, 41),
    (0, 1, 6),
    (1, 0, 29),
    (0, 1, 58),
    (1, 0, 57),
    (1, 1, 52),
    (0, 0, 12),
    (0, 0, 7),
];

fn varied_scores() -> [u64; OPTION_COUNT] {
    [1, 10, 2, 9, 3, 8, 4, 7, 5, 6]
}

#[test]
fn configurable_pair_catalogs_cover_every_option_count_without_collisions() {
    for option_count in usize::from(crate::foundation::MINIMUM_CONFIGURABLE_OPTION_COUNT)
        ..=usize::from(crate::foundation::MAXIMUM_CONFIGURABLE_OPTION_COUNT)
    {
        let assignments = pair_character_lane_assignments(option_count)
            .expect("bounded pair-character catalog derives");
        assert_eq!(assignments.len(), option_count * (option_count - 1) / 2);
        let mut occupied = [BTreeSet::new(), BTreeSet::new()];
        let mut assignment_ordinal = 0_usize;
        for shift in 1..option_count {
            for lower_option_ordinal in 0..option_count - shift {
                let assignment = assignments[assignment_ordinal];
                assert_eq!(
                    usize::from(assignment.lower_option_ordinal()),
                    lower_option_ordinal
                );
                assert_eq!(
                    usize::from(assignment.higher_option_ordinal()),
                    lower_option_ordinal + shift
                );
                assert!(
                    occupied[usize::from(assignment.ciphertext_ordinal())]
                        .insert(usize::from(assignment.lane_ordinal()))
                );
                assignment_ordinal += 1;
            }
        }
        assert_eq!(assignment_ordinal, assignments.len());
    }
    assert!(pair_character_lane_assignments(1).is_err());
    assert!(pair_character_lane_assignments(21).is_err());
}

#[test]
fn selected_pair_catalog_is_ordered_collision_free_and_has_exact_reserved_lanes() {
    let assignments = pair_character_lane_assignments(OPTION_COUNT).expect("selected pair catalog");
    assert_eq!(assignments.len(), PAIR_COUNT);

    let mut assignment_position = 0_usize;
    let mut occupied = [BTreeSet::new(), BTreeSet::new()];
    for shift in 1..OPTION_COUNT {
        let (expected_ciphertext, expected_bank, expected_lane_start) =
            EXPECTED_SHIFT_PLACEMENTS[shift - 1];
        for lower_option_ordinal in 0..OPTION_COUNT - shift {
            let assignment = assignments[assignment_position];
            let expected_lane_within_bank =
                (expected_lane_start + lower_option_ordinal) % (PAIR_CHARACTER_LANE_COUNT / 2);
            let expected_lane =
                expected_bank * (PAIR_CHARACTER_LANE_COUNT / 2) + expected_lane_within_bank;
            assert_eq!(
                usize::from(assignment.lower_option_ordinal()),
                lower_option_ordinal
            );
            assert_eq!(
                usize::from(assignment.higher_option_ordinal()),
                lower_option_ordinal + shift
            );
            assert_eq!(
                usize::from(assignment.ciphertext_ordinal()),
                expected_ciphertext,
                "ciphertext drifted for shift {shift} and lower option {lower_option_ordinal}",
            );
            assert_eq!(
                usize::from(assignment.lane_ordinal()) / (PAIR_CHARACTER_LANE_COUNT / 2),
                expected_bank,
                "bank drifted for shift {shift} and lower option {lower_option_ordinal}",
            );
            assert_eq!(
                usize::from(assignment.lane_ordinal()),
                expected_lane,
                "lane drifted for shift {shift} and lower option {lower_option_ordinal}",
            );
            assert!(
                occupied[usize::from(assignment.ciphertext_ordinal())]
                    .insert(usize::from(assignment.lane_ordinal()))
            );
            assignment_position += 1;
        }
    }
    assert_eq!([occupied[0].len(), occupied[1].len()], [19, 26]);
    assert_eq!(
        occupied[0].iter().copied().collect::<Vec<_>>(),
        vec![
            21, 38, 39, 40, 57, 58, 79, 80, 81, 82, 83, 84, 85, 97, 98, 99, 100, 101, 102
        ]
    );
    assert_eq!(
        occupied[1].iter().copied().collect::<Vec<_>>(),
        vec![
            7, 8, 9, 10, 11, 12, 13, 14, 15, 35, 36, 37, 38, 39, 40, 41, 42, 76, 77, 78, 79, 80,
            122, 123, 124, 125
        ]
    );
}

#[test]
fn pair_character_auxiliaries_multiply_to_the_exact_message_in_every_lane() {
    for scores in [
        varied_scores(),
        [MINIMUM_SCORE; OPTION_COUNT],
        [MAXIMUM_SCORE; OPTION_COUNT],
        core::array::from_fn(|option_ordinal| {
            MINIMUM_SCORE + u64::try_from(option_ordinal % SCORE_BUCKET_COUNT).unwrap()
        }),
    ] {
        let plaintexts = pair_character_plaintexts(
            &scores,
            PAIR_CHARACTER_PLAINTEXT_MODULUS,
            PAIR_CHARACTER_RING_DEGREE,
        )
        .expect("pair-character plaintexts");
        let assignments = pair_character_lane_assignments(OPTION_COUNT).expect("pair catalog");
        let assigned = assignments
            .iter()
            .map(|assignment| {
                (
                    usize::from(assignment.ciphertext_ordinal()),
                    usize::from(assignment.lane_ordinal()),
                    usize::from(assignment.lower_option_ordinal()),
                    usize::from(assignment.higher_option_ordinal()),
                )
            })
            .collect::<Vec<_>>();
        for (ciphertext_ordinal, plaintext) in plaintexts.iter().enumerate() {
            for lane_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
                let left = pair_character_lane_value(
                    plaintext.auxiliary_left_coefficients(),
                    lane_ordinal,
                )
                .expect("left lane value");
                let right = pair_character_lane_value(
                    plaintext.auxiliary_right_coefficients(),
                    lane_ordinal,
                )
                .expect("right lane value");
                let message =
                    pair_character_lane_value(plaintext.message_coefficients(), lane_ordinal)
                        .expect("message lane value");
                if let Some((_, _, lower_option_ordinal, higher_option_ordinal)) = assigned
                    .iter()
                    .find(|(assigned_ciphertext, assigned_lane, _, _)| {
                        *assigned_ciphertext == ciphertext_ordinal && *assigned_lane == lane_ordinal
                    })
                {
                    let left_exponent = usize::try_from(
                        scores[*lower_option_ordinal] + MAXIMUM_SCORE - MINIMUM_SCORE,
                    )
                    .unwrap();
                    let right_exponent = PAIR_CHARACTER_LANE_DEGREE
                        - usize::try_from(scores[*higher_option_ordinal]).unwrap();
                    let message_exponent = usize::try_from(
                        scores[*lower_option_ordinal] + MAXIMUM_SCORE
                            - MINIMUM_SCORE
                            - scores[*higher_option_ordinal],
                    )
                    .unwrap();
                    assert_eq!(left.iter().filter(|value| **value != 0).count(), 1);
                    assert_eq!(left[left_exponent], 1);
                    assert_eq!(right.iter().filter(|value| **value != 0).count(), 1);
                    assert_ne!(right[right_exponent], 0);
                    assert_eq!(message.iter().filter(|value| **value != 0).count(), 1);
                    assert_eq!(message[message_exponent], 1);

                    let product_exponent = left_exponent + right_exponent;
                    assert_eq!(
                        product_exponent - PAIR_CHARACTER_LANE_DEGREE,
                        message_exponent
                    );
                    let reduced_product_coefficient = (u128::from(left[left_exponent])
                        * u128::from(right[right_exponent])
                        * u128::from(pair_character_lane_root_for_test(lane_ordinal)))
                        % u128::from(PAIR_CHARACTER_PLAINTEXT_MODULUS);
                    assert_eq!(reduced_product_coefficient, 1);
                } else {
                    assert!(left.iter().all(|value| *value == 0));
                    assert!(right.iter().all(|value| *value == 0));
                    assert!(message.iter().all(|value| *value == 0));
                }
            }
        }
    }
}

#[test]
fn rotated_encoder_profiles_reconstruct_both_auxiliary_plaintexts() {
    let scores = varied_scores();
    let plaintexts = pair_character_plaintexts(
        &scores,
        PAIR_CHARACTER_PLAINTEXT_MODULUS,
        PAIR_CHARACTER_RING_DEGREE,
    )
    .expect("pair-character plaintexts");
    for (ciphertext_ordinal, plaintext) in plaintexts.iter().enumerate() {
        for (auxiliary_ordinal, expected) in [
            plaintext.auxiliary_left_coefficients(),
            plaintext.auxiliary_right_coefficients(),
        ]
        .into_iter()
        .enumerate()
        {
            let mut reconstructed = vec![0_u64; PAIR_CHARACTER_RING_DEGREE];
            for (option_ordinal, score) in scores.iter().copied().enumerate() {
                let profile = pair_character_encoder_profile_sequence(
                    u16::try_from(ciphertext_ordinal).unwrap(),
                    u16::try_from(auxiliary_ordinal).unwrap(),
                    u16::try_from(option_ordinal).unwrap(),
                )
                .expect("selected encoder profile");
                let weights = rotate_encoder_profile_for_score(&profile, auxiliary_ordinal, score);
                for (coefficient, weight) in reconstructed.iter_mut().zip(weights) {
                    *coefficient = (*coefficient + weight) % PAIR_CHARACTER_PLAINTEXT_MODULUS;
                }
            }
            assert_eq!(reconstructed, expected);
        }
    }
}

#[test]
fn sparse_encoder_profiles_reduce_lane_sums_and_cover_all_score_rotations() {
    let assignments = pair_character_lane_assignments(OPTION_COUNT).expect("selected pair catalog");
    let mut observed_plaintext_modulus_reduction = false;
    for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
        for auxiliary_ordinal in 0..PAIR_CHARACTER_AUXILIARY_COUNT - 1 {
            for option_ordinal in 0..OPTION_COUNT {
                let mut unreduced_coefficient_by_lane_block = [0_u64; PAIR_CHARACTER_LANE_COUNT];
                for assignment in assignments.iter().copied().filter(|assignment| {
                    usize::from(assignment.ciphertext_ordinal()) == ciphertext_ordinal
                        && match auxiliary_ordinal {
                            0 => usize::from(assignment.lower_option_ordinal()) == option_ordinal,
                            1 => usize::from(assignment.higher_option_ordinal()) == option_ordinal,
                            _ => false,
                        }
                }) {
                    let idempotent = pair_character_lane_idempotent_coefficients(usize::from(
                        assignment.lane_ordinal(),
                    ))
                    .expect("lane idempotent");
                    for (accumulated, coefficient) in unreduced_coefficient_by_lane_block
                        .iter_mut()
                        .zip(idempotent)
                    {
                        *accumulated += coefficient;
                    }
                }
                observed_plaintext_modulus_reduction |= unreduced_coefficient_by_lane_block
                    .iter()
                    .any(|coefficient| *coefficient >= PAIR_CHARACTER_PLAINTEXT_MODULUS);
                let terms = pair_character_encoder_profile_terms(
                    u16::try_from(ciphertext_ordinal).unwrap(),
                    u16::try_from(auxiliary_ordinal).unwrap(),
                    u16::try_from(option_ordinal).unwrap(),
                )
                .expect("sparse encoder profile terms");
                assert!(terms.len() <= PAIR_CHARACTER_LANE_COUNT);
                let mut observed_lane_blocks = BTreeSet::new();
                for term in terms.iter().copied() {
                    assert!(observed_lane_blocks.insert(term.lane_block_ordinal()));
                    let mut expected_value = unreduced_coefficient_by_lane_block
                        [term.lane_block_ordinal()]
                        % PAIR_CHARACTER_PLAINTEXT_MODULUS;
                    if auxiliary_ordinal == 1 && term.lane_block_ordinal() == 0 {
                        expected_value = if expected_value == 0 {
                            0
                        } else {
                            PAIR_CHARACTER_PLAINTEXT_MODULUS - expected_value
                        };
                    }
                    assert_ne!(expected_value, 0);
                    assert_eq!(term.value(), expected_value);
                    assert_eq!(
                        term.trace_row_ordinal(),
                        term.lane_block_ordinal() * PAIR_CHARACTER_LANE_DEGREE,
                    );
                }
                for (lane_block_ordinal, unreduced_coefficient) in
                    unreduced_coefficient_by_lane_block
                        .iter()
                        .copied()
                        .enumerate()
                {
                    let mut expected_value =
                        unreduced_coefficient % PAIR_CHARACTER_PLAINTEXT_MODULUS;
                    if auxiliary_ordinal == 1 && lane_block_ordinal == 0 {
                        expected_value = if expected_value == 0 {
                            0
                        } else {
                            PAIR_CHARACTER_PLAINTEXT_MODULUS - expected_value
                        };
                    }
                    assert_eq!(
                        observed_lane_blocks.contains(&lane_block_ordinal),
                        expected_value != 0,
                    );
                }

                let profile = pair_character_encoder_profile_sequence(
                    u16::try_from(ciphertext_ordinal).unwrap(),
                    u16::try_from(auxiliary_ordinal).unwrap(),
                    u16::try_from(option_ordinal).unwrap(),
                )
                .expect("encoder profile sequence");
                for score in MINIMUM_SCORE..=MAXIMUM_SCORE {
                    let rotated =
                        rotate_encoder_profile_for_score(&profile, auxiliary_ordinal, score);
                    let mut independently_placed = vec![0_u64; PAIR_CHARACTER_RING_DEGREE];
                    for term in terms.iter().copied() {
                        let lane_block_start =
                            term.lane_block_ordinal() * PAIR_CHARACTER_LANE_DEGREE;
                        let row = match auxiliary_ordinal {
                            0 => {
                                lane_block_start
                                    + usize::try_from(score + MAXIMUM_SCORE - MINIMUM_SCORE)
                                        .unwrap()
                            }
                            1 if term.lane_block_ordinal() == 0 => {
                                PAIR_CHARACTER_RING_DEGREE - usize::try_from(score).unwrap()
                            }
                            1 => lane_block_start - usize::try_from(score).unwrap(),
                            _ => unreachable!(),
                        };
                        assert_eq!(independently_placed[row], 0);
                        independently_placed[row] = term.value();
                    }
                    assert_eq!(rotated, independently_placed);
                }
            }
        }
    }
    assert!(
        observed_plaintext_modulus_reduction,
        "the test catalog must exercise an actually wrapped lane sum",
    );
}

#[test]
fn lane_idempotents_are_complete_and_orthogonal_across_all_selected_lanes() {
    let roots = (0..PAIR_CHARACTER_LANE_COUNT)
        .map(pair_character_lane_root_for_test)
        .collect::<Vec<_>>();
    let mut coefficientwise_sum = [0_u64; PAIR_CHARACTER_LANE_COUNT];
    for selected_lane in 0..PAIR_CHARACTER_LANE_COUNT {
        let idempotent = pair_character_lane_idempotent_coefficients(selected_lane)
            .expect("selected lane idempotent");
        assert_eq!(idempotent.len(), PAIR_CHARACTER_LANE_COUNT);
        assert_eq!(idempotent[0], PLAINTEXT_LANE_IDEMPOTENT_SCALE);
        for (sum, coefficient) in coefficientwise_sum.iter_mut().zip(&idempotent) {
            *sum = (*sum + *coefficient) % PAIR_CHARACTER_PLAINTEXT_MODULUS;
        }
        for (observed_lane, lane_root) in roots.iter().copied().enumerate() {
            let evaluation = evaluate_lane_idempotent_for_test(&idempotent, lane_root);
            assert_eq!(
                evaluation,
                u64::from(observed_lane == selected_lane),
                "idempotent {selected_lane} drifted at lane {observed_lane}",
            );
        }
    }
    assert_eq!(coefficientwise_sum[0], 1);
    assert!(
        coefficientwise_sum[1..]
            .iter()
            .all(|coefficient| *coefficient == 0)
    );
    assert!(pair_character_lane_idempotent_coefficients(PAIR_CHARACTER_LANE_COUNT).is_err());
}

#[test]
fn selected_extension_lane_roots_form_two_exact_inverse_orbit_banks() {
    let bank_lane_count = PAIR_CHARACTER_LANE_COUNT / 2;
    let mut orbit_exponents = BTreeSet::new();
    let mut lane_roots = BTreeSet::new();
    for lane_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
        let orbit_ordinal = lane_ordinal % bank_lane_count;
        let orbit_exponent = modular_power_for_test(
            u64::try_from(PLAINTEXT_LANE_ORBIT_GENERATOR).unwrap(),
            u64::try_from(orbit_ordinal).unwrap(),
            u64::try_from(PAIR_CHARACTER_LANE_DEGREE).unwrap(),
        );
        if lane_ordinal < bank_lane_count {
            assert!(orbit_exponents.insert(orbit_exponent));
        }
        let independently_derived_root = pair_character_lane_root_for_test(lane_ordinal);
        assert_eq!(
            plaintext_extension_lane_root(lane_ordinal),
            Some(independently_derived_root)
        );
        assert!(lane_roots.insert(independently_derived_root));
        assert_eq!(
            modular_power_for_test(
                independently_derived_root,
                u64::try_from(PAIR_CHARACTER_LANE_COUNT).unwrap(),
                PAIR_CHARACTER_PLAINTEXT_MODULUS,
            ),
            PAIR_CHARACTER_PLAINTEXT_MODULUS - 1,
        );
        assert_eq!(
            modular_power_for_test(
                independently_derived_root,
                u64::try_from(2 * PAIR_CHARACTER_LANE_COUNT).unwrap(),
                PAIR_CHARACTER_PLAINTEXT_MODULUS,
            ),
            1,
        );
    }
    assert_eq!(orbit_exponents.len(), bank_lane_count);
    assert_eq!(lane_roots.len(), PAIR_CHARACTER_LANE_COUNT);
    assert_eq!(
        modular_power_for_test(
            u64::try_from(PLAINTEXT_LANE_ORBIT_GENERATOR).unwrap(),
            u64::try_from(bank_lane_count).unwrap(),
            u64::try_from(PAIR_CHARACTER_LANE_DEGREE).unwrap(),
        ),
        1,
    );
    for lane_ordinal in 0..bank_lane_count {
        assert_eq!(
            modular_product_for_test(
                pair_character_lane_root_for_test(lane_ordinal),
                pair_character_lane_root_for_test(lane_ordinal + bank_lane_count),
            ),
            1,
        );
    }
    assert_eq!(
        plaintext_extension_lane_root(PAIR_CHARACTER_LANE_COUNT),
        None
    );
}

#[test]
fn selected_galois_actions_match_extension_lane_substitution() {
    let source_lanes = nonconstant_extension_lanes_for_test();
    let encoded_coefficients = encode_extension_lanes_to_plaintext_coefficients(&source_lanes)
        .expect("nonconstant extension lanes encode");
    let signed_coefficients = encoded_coefficients
        .iter()
        .copied()
        .map(|coefficient| i64::try_from(coefficient).unwrap())
        .collect::<Vec<_>>();
    let independently_derived_roots = (0..PAIR_CHARACTER_LANE_COUNT)
        .map(pair_character_lane_root_for_test)
        .collect::<Vec<_>>();
    let boundary_lanes = [0, 1, 31, 63, 64, 65, 96, 127];

    let selected_actions =
        TRACE_GALOIS_ELEMENTS
            .into_iter()
            .chain(SCATTER_GALOIS_ELEMENTS)
            .chain(
                TRACE_GALOIS_PATHS
                    .into_iter()
                    .map(|path| compose_galois_path(path).expect("trace path composes")),
            )
            .chain(SCATTER_ROUTES.into_iter().map(|route| {
                compose_galois_path(route.galois_path()).expect("scatter path composes")
            }))
            .chain([2 * PAIR_CHARACTER_RING_DEGREE - 1])
            .collect::<Vec<_>>();

    for galois_element in selected_actions {
        let transformed_coefficients = apply_negacyclic_automorphism(
            &signed_coefficients,
            u64::try_from(galois_element).unwrap(),
        )
        .expect("selected negacyclic automorphism applies")
        .into_iter()
        .map(signed_plaintext_residue_for_test)
        .collect::<Vec<_>>();
        for target_lane_ordinal in boundary_lanes {
            let observed_lane =
                pair_character_lane_value(&transformed_coefficients, target_lane_ordinal)
                    .expect("transformed lane decodes");
            let expected_lane = independently_substitute_extension_lane_for_test(
                &source_lanes,
                &independently_derived_roots,
                target_lane_ordinal,
                galois_element,
            );
            assert_eq!(
                observed_lane, expected_lane,
                "Galois element {galois_element} drifted at target lane {target_lane_ordinal}",
            );
        }
    }

    let conjugation_element = 2 * PAIR_CHARACTER_RING_DEGREE - 1;
    for target_lane_ordinal in boundary_lanes {
        let expected_source_lane = if target_lane_ordinal < PAIR_CHARACTER_LANE_COUNT / 2 {
            target_lane_ordinal + PAIR_CHARACTER_LANE_COUNT / 2
        } else {
            target_lane_ordinal - PAIR_CHARACTER_LANE_COUNT / 2
        };
        assert_eq!(
            source_lane_ordinal_for_action_for_test(
                &independently_derived_roots,
                target_lane_ordinal,
                conjugation_element,
            ),
            expected_source_lane,
        );
    }
    let conjugated_once = apply_negacyclic_automorphism(
        &signed_coefficients,
        u64::try_from(conjugation_element).unwrap(),
    )
    .expect("conjugation applies");
    assert_eq!(
        apply_negacyclic_automorphism(
            &conjugated_once,
            u64::try_from(conjugation_element).unwrap(),
        )
        .expect("conjugation is involutive"),
        signed_coefficients,
    );
}

#[test]
fn selected_trace_paths_compute_the_full_extension_field_trace() {
    let source_lanes = nonconstant_extension_lanes_for_test();
    let mut traced_coefficients = encode_extension_lanes_to_plaintext_coefficients(&source_lanes)
        .expect("nonconstant extension lanes encode");
    for path in TRACE_GALOIS_PATHS {
        let trace_action = compose_galois_path(path).expect("trace path composes");
        let signed_trace = traced_coefficients
            .iter()
            .copied()
            .map(|coefficient| i64::try_from(coefficient).unwrap())
            .collect::<Vec<_>>();
        let rotated_trace =
            apply_negacyclic_automorphism(&signed_trace, u64::try_from(trace_action).unwrap())
                .expect("trace action applies");
        for (coefficient, rotated) in traced_coefficients.iter_mut().zip(rotated_trace) {
            *coefficient =
                modular_sum_for_test(*coefficient, signed_plaintext_residue_for_test(rotated));
        }
    }
    let observed_lanes = decode_plaintext_coefficients_to_extension_lanes(&traced_coefficients)
        .expect("full trace output decodes");
    for (lane_ordinal, (source_lane, observed_lane)) in
        source_lanes.iter().zip(observed_lanes).enumerate()
    {
        let mut expected_lane = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
        expected_lane[0] = modular_product_for_test(
            u64::try_from(PAIR_CHARACTER_LANE_DEGREE).unwrap(),
            source_lane[0],
        );
        assert_eq!(
            observed_lane, expected_lane,
            "full field trace drifted in lane {lane_ordinal}",
        );
    }
}

#[test]
fn aggregate_score_difference_range_fits_the_recomputed_plaintext_order() {
    let participant_count = i64::from(FOUNDATION_PROFILE.participant_count);
    let score_span = i64::try_from(MAXIMUM_SCORE - MINIMUM_SCORE).unwrap();
    let maximum_difference_magnitude = participant_count * score_span;
    let aggregate_difference_range = [-maximum_difference_magnitude, maximum_difference_magnitude];
    let normalization_offset = maximum_difference_magnitude;
    let normalized_range = aggregate_difference_range.map(|value| value + normalization_offset);
    assert_eq!(aggregate_difference_range, [-90, 90]);
    assert_eq!(normalized_range, [0, 180]);

    let cyclotomic_order = u64::try_from(2 * PAIR_CHARACTER_RING_DEGREE).unwrap();
    let plaintext_order = multiplicative_order_for_test(
        PAIR_CHARACTER_PLAINTEXT_MODULUS % cyclotomic_order,
        cyclotomic_order,
    );
    assert_eq!(plaintext_order, 256);
    assert!(u64::try_from(normalized_range[1]).unwrap() < plaintext_order);
}

#[test]
fn pair_character_codec_rejects_malformed_scores_and_wrong_suite_geometry() {
    for scores in [vec![1; OPTION_COUNT - 1], vec![1; OPTION_COUNT + 1]] {
        assert_eq!(
            pair_character_plaintexts(
                &scores,
                PAIR_CHARACTER_PLAINTEXT_MODULUS,
                PAIR_CHARACTER_RING_DEGREE,
            )
            .expect_err("wrong score count")
            .code,
            CanonicalErrorCode::MalformedLength
        );
    }
    for invalid_score in [MINIMUM_SCORE - 1, MAXIMUM_SCORE + 1] {
        let mut scores = varied_scores();
        scores[7] = invalid_score;
        assert_eq!(
            pair_character_plaintexts(
                &scores,
                PAIR_CHARACTER_PLAINTEXT_MODULUS,
                PAIR_CHARACTER_RING_DEGREE,
            )
            .expect_err("score outside selected domain")
            .code,
            CanonicalErrorCode::InvalidProtocolObject
        );
    }
    assert!(
        pair_character_plaintexts(
            &varied_scores(),
            PAIR_CHARACTER_PLAINTEXT_MODULUS + 1,
            PAIR_CHARACTER_RING_DEGREE,
        )
        .is_err()
    );
    assert!(
        pair_character_plaintexts(
            &varied_scores(),
            PAIR_CHARACTER_PLAINTEXT_MODULUS,
            PAIR_CHARACTER_RING_DEGREE * 2,
        )
        .is_err()
    );
    for invalid_coordinates in [(2, 0, 0), (0, 2, 0), (0, 0, OPTION_COUNT)] {
        assert!(
            pair_character_encoder_profile_sequence(
                invalid_coordinates.0,
                invalid_coordinates.1,
                u16::try_from(invalid_coordinates.2).expect("invalid option ordinal fits u16"),
            )
            .is_err()
        );
    }
}

fn rotate_encoder_profile_for_score(
    profile: &[u64],
    auxiliary_ordinal: usize,
    score: u64,
) -> Vec<u64> {
    assert_eq!(profile.len(), PAIR_CHARACTER_RING_DEGREE);
    assert!((MINIMUM_SCORE..=MAXIMUM_SCORE).contains(&score));
    let rotation_magnitude = match auxiliary_ordinal {
        0 => usize::try_from(score + MAXIMUM_SCORE - MINIMUM_SCORE).unwrap(),
        1 => usize::try_from(score).unwrap(),
        _ => panic!("unknown pair-character auxiliary"),
    };
    (0..PAIR_CHARACTER_RING_DEGREE)
        .map(|row_ordinal| {
            let profile_row_ordinal = match auxiliary_ordinal {
                0 => {
                    (row_ordinal + PAIR_CHARACTER_RING_DEGREE - rotation_magnitude)
                        % PAIR_CHARACTER_RING_DEGREE
                }
                1 => (row_ordinal + rotation_magnitude) % PAIR_CHARACTER_RING_DEGREE,
                _ => unreachable!(),
            };
            profile[profile_row_ordinal]
        })
        .collect()
}

fn nonconstant_extension_lanes_for_test() -> Vec<[u64; PAIR_CHARACTER_LANE_DEGREE]> {
    (0..PAIR_CHARACTER_LANE_COUNT)
        .map(|lane_ordinal| {
            let mut lane = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
            for residue_exponent in [0, 1, 17, 127, 255] {
                lane[residue_exponent] = u64::try_from(
                    ((lane_ordinal + 1) * 29 + (residue_exponent + 3) * 43) % 256 + 1,
                )
                .unwrap();
            }
            lane
        })
        .collect()
}

fn evaluate_lane_idempotent_for_test(coefficients: &[u64], lane_root: u64) -> u64 {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(0_u64, |evaluation, coefficient| {
            modular_sum_for_test(modular_product_for_test(evaluation, lane_root), coefficient)
        })
}

fn pair_character_lane_root_for_test(lane_ordinal: usize) -> u64 {
    let orbit_ordinal = lane_ordinal % (PAIR_CHARACTER_LANE_COUNT / 2);
    let positive_exponent = modular_power_for_test(
        u64::try_from(PLAINTEXT_LANE_ORBIT_GENERATOR).unwrap(),
        u64::try_from(orbit_ordinal).unwrap(),
        u64::try_from(PAIR_CHARACTER_LANE_DEGREE).unwrap(),
    );
    let exponent = if lane_ordinal < PAIR_CHARACTER_LANE_COUNT / 2 {
        positive_exponent
    } else {
        u64::try_from(PAIR_CHARACTER_LANE_DEGREE).unwrap() - positive_exponent
    };
    modular_power_for_test(
        PLAINTEXT_LANE_ROOT_GENERATOR,
        exponent,
        PAIR_CHARACTER_PLAINTEXT_MODULUS,
    )
}

fn independently_substitute_extension_lane_for_test(
    source_lanes: &[[u64; PAIR_CHARACTER_LANE_DEGREE]],
    lane_roots: &[u64],
    target_lane_ordinal: usize,
    galois_element: usize,
) -> [u64; PAIR_CHARACTER_LANE_DEGREE] {
    let source_lane_ordinal =
        source_lane_ordinal_for_action_for_test(lane_roots, target_lane_ordinal, galois_element);
    let target_lane_root = lane_roots[target_lane_ordinal];
    let mut substituted = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
    for (source_exponent, source_coefficient) in source_lanes[source_lane_ordinal]
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, coefficient)| *coefficient != 0)
    {
        let mapped_exponent = source_exponent
            .checked_mul(galois_element)
            .expect("selected action exponent fits usize");
        let target_exponent = mapped_exponent % PAIR_CHARACTER_LANE_DEGREE;
        let reduction_power = mapped_exponent / PAIR_CHARACTER_LANE_DEGREE;
        let reduction_factor = modular_power_for_test(
            target_lane_root,
            u64::try_from(reduction_power).unwrap(),
            PAIR_CHARACTER_PLAINTEXT_MODULUS,
        );
        substituted[target_exponent] = modular_sum_for_test(
            substituted[target_exponent],
            modular_product_for_test(source_coefficient, reduction_factor),
        );
    }
    substituted
}

fn source_lane_ordinal_for_action_for_test(
    lane_roots: &[u64],
    target_lane_ordinal: usize,
    galois_element: usize,
) -> usize {
    let source_lane_root = modular_power_for_test(
        lane_roots[target_lane_ordinal],
        u64::try_from(galois_element).unwrap(),
        PAIR_CHARACTER_PLAINTEXT_MODULUS,
    );
    lane_roots
        .iter()
        .position(|lane_root| *lane_root == source_lane_root)
        .expect("selected action permutes the extension lane roots")
}

fn signed_plaintext_residue_for_test(value: i64) -> u64 {
    let modulus = i64::try_from(PAIR_CHARACTER_PLAINTEXT_MODULUS).unwrap();
    u64::try_from(value.rem_euclid(modulus)).unwrap()
}

fn modular_sum_for_test(left: u64, right: u64) -> u64 {
    (left + right) % PAIR_CHARACTER_PLAINTEXT_MODULUS
}

fn modular_product_for_test(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(PAIR_CHARACTER_PLAINTEXT_MODULUS)) as u64
}

fn multiplicative_order_for_test(base: u64, modulus: u64) -> u64 {
    let mut residue = 1_u64;
    for order in 1..=modulus {
        residue = ((u128::from(residue) * u128::from(base)) % u128::from(modulus)) as u64;
        if residue == 1 {
            return order;
        }
    }
    panic!("base has no multiplicative order modulo the selected cyclotomic order")
}

fn modular_power_for_test(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = ((u128::from(result) * u128::from(base)) % u128::from(modulus)) as u64;
        }
        base = ((u128::from(base) * u128::from(base)) % u128::from(modulus)) as u64;
        exponent >>= 1;
    }
    result
}
