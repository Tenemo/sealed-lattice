use super::*;
use supported_profile::plaintext::{ENCODING_DEGREE, odd_power_values, slot_positions};

fn evaluate(coefficients: &[i32], point: u32) -> u32 {
    coefficients.iter().rev().fold(0, |sum, coefficient| {
        (multiply(sum, point) + coefficient.rem_euclid(PLAINTEXT_MODULUS as i32) as u32)
            % PLAINTEXT_MODULUS
    })
}
fn slots(coefficients: &[i32]) -> Vec<u32> {
    let values = odd_power_values(
        &coefficients
            .iter()
            .map(|value| value.rem_euclid(PLAINTEXT_MODULUS as i32) as u32)
            .collect::<Vec<_>>(),
    );
    let positions: Vec<_> = slot_positions(ENCODING_DEGREE).collect();
    positions
        .iter()
        .map(|position| values[*position])
        .chain(
            positions
                .iter()
                .map(|position| values[ENCODING_DEGREE / 2 - 1 - position]),
        )
        .collect()
}
fn sweep(values: &[u32], length: usize) -> Vec<u32> {
    (0..values.len())
        .map(|slot| {
            (0..length)
                .map(|offset| {
                    values[slot / ACTIVE_SLOTS * ACTIVE_SLOTS + (slot + offset) % ACTIVE_SLOTS]
                })
                .sum::<u32>()
                % PLAINTEXT_MODULUS
        })
        .collect()
}

#[test]
fn every_participant_count_has_the_exact_odd_comparison_polynomial() {
    for participants in Profile::participant_range() {
        let profile = Profile::new(participants, 2).unwrap();
        let (comparison, _, _) = parameters(profile, 2);
        let maximum = profile.comparison_degree() as i32;
        for difference in (-maximum..=maximum).step_by(2) {
            assert_eq!(
                evaluate(
                    &comparison,
                    difference.rem_euclid(PLAINTEXT_MODULUS as i32) as u32
                ),
                u32::from(difference > 0)
            );
        }
    }
}

#[test]
fn every_requested_length_has_exact_periodic_weights_and_subring_support() {
    for options in Profile::option_range() {
        let profile = Profile::new(3, options).unwrap();
        let window = profile.rank_window();
        let mask = slots(&rank_mask(profile));
        let correction = slots(&padding_correction(profile));
        for top_count in 1..=options {
            let (_, ranking, offset) = parameters(profile, top_count);
            let weights: Vec<_> = ranking.iter().map(|value| slots(value)).collect();
            let offsets = slots(&offset);
            for polynomial in ranking.iter().chain([&rank_mask(profile)]) {
                let support = DEGREE / (2 * window);
                assert!(
                    polynomial
                        .iter()
                        .enumerate()
                        .all(|(index, value)| index % support == 0 || *value == 0)
                );
                assert!(
                    polynomial
                        .iter()
                        .map(|value| u64::from(value.unsigned_abs()))
                        .sum::<u64>()
                        <= (2 * window) as u64 * u64::from(PLAINTEXT_MODULUS / 2)
                );
            }
            for slot in 0..2 * ACTIVE_SLOTS {
                let rank = (window - slot % window) % window;
                let selected = slot < ACTIVE_SLOTS && rank < top_count;
                let coefficients: Vec<_> =
                    weights.iter().map(|weight| weight[slot] as i32).collect();
                for value in 0..options {
                    assert_eq!(
                        evaluate(&coefficients, value as u32),
                        u32::from(selected && value == rank)
                    );
                }
                assert_eq!(
                    mask[slot],
                    u32::from(slot < ACTIVE_SLOTS && slot % window == 0)
                );
                assert_eq!(
                    correction[slot],
                    if slot < ACTIVE_SLOTS && slot % window == 0 && slot / window >= options {
                        PLAINTEXT_MODULUS - 1
                    } else {
                        0
                    }
                );
                assert_eq!(
                    offsets[slot],
                    if slot >= ACTIVE_SLOTS {
                        0
                    } else if slot < options * window && slot % window < slot / window {
                        1
                    } else {
                        PLAINTEXT_MODULUS - 1
                    }
                );
            }
        }
    }
}

#[test]
fn all_profiles_turnout_edges_and_result_lengths_release_only_the_sorted_identifiers() {
    for options in Profile::option_range() {
        let sample = Profile::new(3, options).unwrap();
        let window = sample.rank_window();
        let mask = slots(&rank_mask(sample));
        let correction = slots(&padding_correction(sample));
        let (_, ranking, _) = parameters(sample, options);
        let weights: Vec<_> = ranking.iter().map(|value| slots(value)).collect();
        for participants in Profile::participant_range() {
            let profile = Profile::new(participants, options).unwrap();
            let (comparison, _, _) = parameters(profile, options);
            for turnout in [profile.minimum_turnout(), participants] {
                for pattern in 0..3 {
                    let totals: Vec<i32> = (0..options)
                        .map(|option| {
                            (0..turnout)
                                .map(|voter| match pattern {
                                    0 => 1,
                                    1 => {
                                        if (option + voter) % 2 == 0 {
                                            1
                                        } else {
                                            10
                                        }
                                    }
                                    _ => {
                                        1 + ((option * 7 + voter * 3 + option * voter) % 10) as i32
                                    }
                                })
                                .sum()
                        })
                        .collect();
                    let mut compared = vec![
                        comparison[0].rem_euclid(PLAINTEXT_MODULUS as i32)
                            as u32;
                        2 * ACTIVE_SLOTS
                    ];
                    for (slot, value) in compared.iter_mut().enumerate().take(ACTIVE_SLOTS) {
                        let (option, opponent) = (slot / window, slot % window);
                        let difference = if option < options && opponent < options {
                            2 * (totals[opponent] - totals[option])
                        } else {
                            0
                        };
                        let offset = if option < options && opponent < option {
                            1
                        } else {
                            -1
                        };
                        *value = evaluate(
                            &comparison,
                            (difference + offset).rem_euclid(PLAINTEXT_MODULUS as i32) as u32,
                        );
                    }
                    for (slot, score) in totals.iter().enumerate() {
                        compared[ACTIVE_SLOTS + slot] = evaluate(&comparison, *score as u32);
                    }
                    let sums = sweep(&compared, window);
                    let kept: Vec<_> = sums
                        .iter()
                        .zip(&mask)
                        .map(|(value, mask)| multiply(*value, *mask))
                        .collect();
                    let mut order: Vec<_> = (0..options).collect();
                    order.sort_by_key(|option| (-totals[*option], *option));
                    for top_count in 1..=options {
                        let broadcast = sweep(&kept, top_count);
                        let mut expected = vec![0; 2 * ACTIVE_SLOTS];
                        for (rank, option) in order.iter().take(top_count).enumerate() {
                            expected[(option * window + ACTIVE_SLOTS - rank) % ACTIVE_SLOTS] = 1;
                        }
                        for slot in 0..2 * ACTIVE_SLOTS {
                            let requested = (window - slot % window) % window;
                            let result = if requested < top_count {
                                let coefficients: Vec<_> =
                                    weights.iter().map(|weight| weight[slot] as i32).collect();
                                (evaluate(&coefficients, broadcast[slot]) + correction[slot])
                                    % PLAINTEXT_MODULUS
                            } else {
                                correction[slot]
                            };
                            assert_eq!(
                                result, expected[slot],
                                "profile={profile:?} turnout={turnout} top={top_count} slot={slot}"
                            );
                        }
                    }
                }
            }
        }
    }
}
