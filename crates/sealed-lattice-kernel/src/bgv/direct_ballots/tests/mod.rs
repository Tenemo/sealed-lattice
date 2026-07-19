use std::collections::BTreeSet;

use super::*;
use crate::encoding::CanonicalErrorCode;

const PAIR_COUNT: usize = OPTION_COUNT * (OPTION_COUNT - 1) / 2;

fn varied_scores() -> [u64; OPTION_COUNT] {
    [1, 10, 2, 9, 3, 8, 4, 7, 5, 6, 10, 1, 9, 2, 8, 3, 7, 4, 6, 5]
}

#[test]
fn selected_pair_catalog_is_ordered_collision_free_and_has_exact_reserved_lanes() {
    let assignments = selected_pair_character_lane_assignments().expect("selected pair catalog");
    assert_eq!(assignments.len(), PAIR_COUNT);

    let mut assignment_position = 0_usize;
    let mut occupied = [BTreeSet::new(), BTreeSet::new()];
    for shift in 1..OPTION_COUNT {
        for lower_option_ordinal in 0..OPTION_COUNT - shift {
            let assignment = assignments[assignment_position];
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
            assignment_position += 1;
        }
    }
    assert_eq!([occupied[0].len(), occupied[1].len()], [93, 97]);

    let reserved = occupied.map(|lanes| {
        (0..PAIR_CHARACTER_LANE_COUNT)
            .filter(|lane_ordinal| !lanes.contains(lane_ordinal))
            .collect::<Vec<_>>()
    });
    assert_eq!(
        reserved[0],
        vec![
            5, 6, 8, 9, 10, 11, 14, 15, 16, 17, 18, 19, 20, 32, 33, 34, 35, 36, 37, 51, 52, 53, 54,
            55, 56, 64, 65, 66, 67, 68, 69, 77, 78, 96, 127,
        ]
    );
    assert_eq!(
        reserved[1],
        vec![
            0, 1, 2, 3, 4, 5, 6, 26, 27, 28, 53, 54, 55, 56, 61, 62, 63, 72, 73, 74, 75, 91, 92,
            93, 94, 113, 114, 115, 119, 120, 121,
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
        let assignments = selected_pair_character_lane_assignments().expect("pair catalog");
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
    let assignments = selected_pair_character_lane_assignments().expect("selected pair catalog");
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
fn lane_idempotent_coefficients_select_only_the_declared_lane() {
    for selected_lane in [0_usize, 1, 63, 64, 127] {
        let idempotent = pair_character_lane_idempotent_coefficients(selected_lane)
            .expect("selected lane idempotent");
        assert_eq!(idempotent.len(), PAIR_CHARACTER_LANE_COUNT);
        assert_eq!(idempotent[0], 255);
        let mut full_ring_coefficients = vec![0_u64; PAIR_CHARACTER_RING_DEGREE];
        for (coefficient_ordinal, coefficient) in idempotent.into_iter().enumerate() {
            full_ring_coefficients[coefficient_ordinal * PAIR_CHARACTER_LANE_DEGREE] = coefficient;
        }
        for observed_lane in 0..PAIR_CHARACTER_LANE_COUNT {
            let lane_value = pair_character_lane_value(&full_ring_coefficients, observed_lane)
                .expect("lane evaluation");
            if observed_lane == selected_lane {
                assert_eq!(lane_value[0], 1);
                assert!(lane_value[1..].iter().all(|value| *value == 0));
            } else {
                assert!(lane_value.iter().all(|value| *value == 0));
            }
        }
    }
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
    for invalid_coordinates in [(2, 0, 0), (0, 2, 0), (0, 0, 20)] {
        assert!(
            pair_character_encoder_profile_sequence(
                invalid_coordinates.0,
                invalid_coordinates.1,
                invalid_coordinates.2,
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

fn pair_character_lane_root_for_test(lane_ordinal: usize) -> u64 {
    let orbit_ordinal = lane_ordinal % (PAIR_CHARACTER_LANE_COUNT / 2);
    let positive_exponent = modular_power_for_test(
        3,
        u64::try_from(orbit_ordinal).unwrap(),
        PAIR_CHARACTER_PLAINTEXT_MODULUS - 1,
    );
    let exponent = if lane_ordinal < PAIR_CHARACTER_LANE_COUNT / 2 {
        positive_exponent
    } else {
        PAIR_CHARACTER_PLAINTEXT_MODULUS - 1 - positive_exponent
    };
    modular_power_for_test(3, exponent, PAIR_CHARACTER_PLAINTEXT_MODULUS)
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
