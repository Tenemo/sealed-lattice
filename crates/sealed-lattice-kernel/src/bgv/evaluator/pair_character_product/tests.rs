use crate::bgv::{
    direct_ballots::{PAIR_CHARACTER_LANE_COUNT, PAIR_CHARACTER_LANE_DEGREE},
    encoding::encode_extension_lanes_to_plaintext_coefficients,
    parameters::PLAINTEXT_MODULUS,
};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedMerge {
    kind: PairCharacterProductMergeKind,
    left_start: usize,
    left_count: usize,
    right_start: usize,
    right_count: usize,
    output_depth: usize,
}

const fn online(
    left_start: usize,
    left_count: usize,
    right_start: usize,
    right_count: usize,
    output_depth: usize,
) -> ExpectedMerge {
    ExpectedMerge {
        kind: PairCharacterProductMergeKind::OnlineEqualDepth,
        left_start,
        left_count,
        right_start,
        right_count,
        output_depth,
    }
}

const fn finalization(
    left_start: usize,
    left_count: usize,
    right_start: usize,
    right_count: usize,
    output_depth: usize,
) -> ExpectedMerge {
    ExpectedMerge {
        kind: PairCharacterProductMergeKind::RightmostFinalization,
        left_start,
        left_count,
        right_start,
        right_count,
        output_depth,
    }
}

const MERGES_BY_BALLOT_COUNT: [&[ExpectedMerge]; 10] = [
    &[],
    &[online(0, 1, 1, 1, 1)],
    &[online(0, 1, 1, 1, 1), finalization(0, 2, 2, 1, 2)],
    &[
        online(0, 1, 1, 1, 1),
        online(2, 1, 3, 1, 1),
        online(0, 2, 2, 2, 2),
    ],
    &[
        online(0, 1, 1, 1, 1),
        online(2, 1, 3, 1, 1),
        online(0, 2, 2, 2, 2),
        finalization(0, 4, 4, 1, 3),
    ],
    &[
        online(0, 1, 1, 1, 1),
        online(2, 1, 3, 1, 1),
        online(0, 2, 2, 2, 2),
        online(4, 1, 5, 1, 1),
        finalization(0, 4, 4, 2, 3),
    ],
    &[
        online(0, 1, 1, 1, 1),
        online(2, 1, 3, 1, 1),
        online(0, 2, 2, 2, 2),
        online(4, 1, 5, 1, 1),
        finalization(4, 2, 6, 1, 2),
        finalization(0, 4, 4, 3, 3),
    ],
    &[
        online(0, 1, 1, 1, 1),
        online(2, 1, 3, 1, 1),
        online(0, 2, 2, 2, 2),
        online(4, 1, 5, 1, 1),
        online(6, 1, 7, 1, 1),
        online(4, 2, 6, 2, 2),
        online(0, 4, 4, 4, 3),
    ],
    &[
        online(0, 1, 1, 1, 1),
        online(2, 1, 3, 1, 1),
        online(0, 2, 2, 2, 2),
        online(4, 1, 5, 1, 1),
        online(6, 1, 7, 1, 1),
        online(4, 2, 6, 2, 2),
        online(0, 4, 4, 4, 3),
        finalization(0, 8, 8, 1, 4),
    ],
    &[
        online(0, 1, 1, 1, 1),
        online(2, 1, 3, 1, 1),
        online(0, 2, 2, 2, 2),
        online(4, 1, 5, 1, 1),
        online(6, 1, 7, 1, 1),
        online(4, 2, 6, 2, 2),
        online(0, 4, 4, 4, 3),
        online(8, 1, 9, 1, 1),
        finalization(0, 8, 8, 2, 4),
    ],
];

#[derive(Clone, Copy, Debug)]
struct ExpectedScheduleAccounting {
    root_depth: usize,
    root_level: usize,
    normalization_exponent: usize,
    alignment_switches: usize,
    alignment_drops: usize,
    depth_switches: usize,
    depth_drops: usize,
    terminal_switches: usize,
    terminal_drops: usize,
    maximum_resident_ciphertexts: usize,
}

const SCHEDULE_ACCOUNTING_BY_BALLOT_COUNT: [ExpectedScheduleAccounting; 10] = [
    ExpectedScheduleAccounting {
        root_depth: 0,
        root_level: 22,
        normalization_exponent: 81,
        alignment_switches: 0,
        alignment_drops: 0,
        depth_switches: 0,
        depth_drops: 0,
        terminal_switches: 1,
        terminal_drops: 3,
        maximum_resident_ciphertexts: 2,
    },
    ExpectedScheduleAccounting {
        root_depth: 1,
        root_level: 21,
        normalization_exponent: 72,
        alignment_switches: 0,
        alignment_drops: 0,
        depth_switches: 1,
        depth_drops: 1,
        terminal_switches: 1,
        terminal_drops: 2,
        maximum_resident_ciphertexts: 3,
    },
    ExpectedScheduleAccounting {
        root_depth: 2,
        root_level: 19,
        normalization_exponent: 63,
        alignment_switches: 1,
        alignment_drops: 1,
        depth_switches: 2,
        depth_drops: 3,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 3,
    },
    ExpectedScheduleAccounting {
        root_depth: 2,
        root_level: 19,
        normalization_exponent: 54,
        alignment_switches: 0,
        alignment_drops: 0,
        depth_switches: 3,
        depth_drops: 4,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 4,
    },
    ExpectedScheduleAccounting {
        root_depth: 3,
        root_level: 19,
        normalization_exponent: 45,
        alignment_switches: 1,
        alignment_drops: 3,
        depth_switches: 3,
        depth_drops: 4,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 4,
    },
    ExpectedScheduleAccounting {
        root_depth: 3,
        root_level: 19,
        normalization_exponent: 36,
        alignment_switches: 1,
        alignment_drops: 2,
        depth_switches: 4,
        depth_drops: 5,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 4,
    },
    ExpectedScheduleAccounting {
        root_depth: 3,
        root_level: 19,
        normalization_exponent: 27,
        alignment_switches: 1,
        alignment_drops: 1,
        depth_switches: 5,
        depth_drops: 7,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 4,
    },
    ExpectedScheduleAccounting {
        root_depth: 3,
        root_level: 19,
        normalization_exponent: 18,
        alignment_switches: 0,
        alignment_drops: 0,
        depth_switches: 6,
        depth_drops: 8,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 5,
    },
    ExpectedScheduleAccounting {
        root_depth: 4,
        root_level: 19,
        normalization_exponent: 9,
        alignment_switches: 1,
        alignment_drops: 3,
        depth_switches: 6,
        depth_drops: 8,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 5,
    },
    ExpectedScheduleAccounting {
        root_depth: 4,
        root_level: 19,
        normalization_exponent: 0,
        alignment_switches: 1,
        alignment_drops: 2,
        depth_switches: 7,
        depth_drops: 9,
        terminal_switches: 0,
        terminal_drops: 0,
        maximum_resident_ciphertexts: 5,
    },
];

#[test]
fn selected_pair_character_schedule_pins_every_span_level_and_operation_count() {
    for (ballot_index, expected_accounting) in
        SCHEDULE_ACCOUNTING_BY_BALLOT_COUNT.iter().enumerate()
    {
        let ballot_count = ballot_index + 1;
        let schedule = canonical_pair_character_product_schedule(ballot_count)
            .expect("selected pair-character schedule");
        let root = schedule.nodes[schedule.root_node_ordinal];

        assert_eq!(schedule.ballot_count, ballot_count);
        assert_eq!(schedule.nodes.len(), 2 * ballot_count - 1);
        assert_eq!(schedule.merges.len(), ballot_count - 1);
        assert_eq!(
            root.ballot_span,
            PairCharacterBallotSpan {
                first_ballot_ordinal: 0,
                ballot_count,
            }
        );
        assert_eq!(root.multiplication_depth, expected_accounting.root_depth);
        assert_eq!(root.level, expected_accounting.root_level);
        assert_eq!(root.message_width, 18 * ballot_count + 1);
        assert_eq!(schedule.terminal_output_level, 19);

        for (node_ordinal, node) in schedule.nodes.iter().enumerate() {
            assert_eq!(node.node_ordinal, node_ordinal);
            assert_eq!(node.message_width, 18 * node.ballot_span.ballot_count + 1);
            assert_eq!(
                node.level,
                match node.multiplication_depth {
                    0 => 22,
                    1 => 21,
                    _ => 19,
                }
            );
        }

        let observed_merges = schedule
            .merges
            .iter()
            .map(|merge| {
                let left = schedule.nodes[merge.left_node_ordinal];
                let right = schedule.nodes[merge.right_node_ordinal];
                let output = schedule.nodes[merge.output_node_ordinal];
                assert!(merge.left_node_ordinal < merge.output_node_ordinal);
                assert!(merge.right_node_ordinal < merge.output_node_ordinal);
                assert_eq!(
                    left.ballot_span.end_ballot_ordinal_exclusive(),
                    right.ballot_span.first_ballot_ordinal
                );
                assert_eq!(merge.alignment_level, left.level.min(right.level));
                assert_eq!(
                    merge.left_alignment_drop_count,
                    left.level - merge.alignment_level
                );
                assert_eq!(
                    merge.right_alignment_drop_count,
                    right.level - merge.alignment_level
                );
                assert_eq!(
                    merge.depth_drop_count,
                    [1, 2, 0, 0][output.multiplication_depth - 1]
                );
                ExpectedMerge {
                    kind: merge.kind,
                    left_start: left.ballot_span.first_ballot_ordinal,
                    left_count: left.ballot_span.ballot_count,
                    right_start: right.ballot_span.first_ballot_ordinal,
                    right_count: right.ballot_span.ballot_count,
                    output_depth: output.multiplication_depth,
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observed_merges, MERGES_BY_BALLOT_COUNT[ballot_index],
            "merge topology drifted for {ballot_count} ballots"
        );
        let first_finalization = schedule
            .merges
            .iter()
            .position(|merge| merge.kind == PairCharacterProductMergeKind::RightmostFinalization);
        if let Some(first_finalization) = first_finalization {
            assert!(schedule.merges[first_finalization..].iter().all(|merge| {
                merge.kind == PairCharacterProductMergeKind::RightmostFinalization
            }));
        }

        let accounting = schedule.accounting;
        assert_eq!(accounting.ballot_ciphertext_count, ballot_count);
        assert_eq!(accounting.ciphertext_multiplication_count, ballot_count - 1);
        assert_eq!(accounting.relinearization_count, ballot_count - 1);
        assert_eq!(
            accounting.normalization_plaintext_multiplication_count,
            usize::from(ballot_count < 10)
        );
        assert_eq!(
            accounting.alignment_modulus_switch_count,
            expected_accounting.alignment_switches
        );
        assert_eq!(
            accounting.alignment_modulus_drop_count,
            expected_accounting.alignment_drops
        );
        assert_eq!(
            accounting.depth_modulus_switch_count,
            expected_accounting.depth_switches
        );
        assert_eq!(
            accounting.depth_modulus_drop_count,
            expected_accounting.depth_drops
        );
        assert_eq!(
            accounting.terminal_modulus_switch_count,
            expected_accounting.terminal_switches
        );
        assert_eq!(
            accounting.terminal_modulus_drop_count,
            expected_accounting.terminal_drops
        );
        assert_eq!(
            accounting.modulus_switch_count(),
            expected_accounting.alignment_switches
                + expected_accounting.depth_switches
                + expected_accounting.terminal_switches
        );
        assert_eq!(
            accounting.modulus_drop_count(),
            expected_accounting.alignment_drops
                + expected_accounting.depth_drops
                + expected_accounting.terminal_drops
        );
        assert_eq!(
            accounting.maximum_resident_ciphertext_count,
            expected_accounting.maximum_resident_ciphertexts
        );
        assert_eq!(
            schedule.normalization.coefficient_ordinal,
            expected_accounting.normalization_exponent
        );
    }
}

#[test]
fn selected_normalization_is_the_same_unit_monomial_in_every_extension_lane() {
    for (ballot_index, expected_accounting) in
        SCHEDULE_ACCOUNTING_BY_BALLOT_COUNT.iter().enumerate()
    {
        let ballot_count = ballot_index + 1;
        let schedule = canonical_pair_character_product_schedule(ballot_count)
            .expect("selected pair-character schedule");
        let coefficients = schedule.normalization.plaintext_coefficients();
        let nonzero_coefficients = coefficients
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, coefficient)| *coefficient != 0)
            .collect::<Vec<_>>();
        assert_eq!(
            nonzero_coefficients,
            vec![(expected_accounting.normalization_exponent, 1)]
        );
        let independently_computed_centered_l1_norm = coefficients
            .iter()
            .copied()
            .map(|coefficient| coefficient.min(PLAINTEXT_MODULUS - coefficient))
            .sum::<u64>();
        assert_eq!(independently_computed_centered_l1_norm, 1);
        assert_eq!(schedule.normalization.centered_coefficient_l1_norm, 1);
        assert_eq!(schedule.normalization.convolution_infinity_operator_norm, 1);
        assert_eq!(
            schedule.normalization.requires_plaintext_multiplication(),
            ballot_count < 10
        );

        let mut lane_monomial = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
        lane_monomial[expected_accounting.normalization_exponent] = 1;
        let encoded_monomial = encode_extension_lanes_to_plaintext_coefficients(&vec![
            lane_monomial;
            PAIR_CHARACTER_LANE_COUNT
        ])
        .expect("normalization monomial encodes");
        assert_eq!(encoded_monomial, coefficients);
    }
}

#[test]
fn selected_schedule_reaches_every_aggregate_difference_and_preserves_inactive_zeros() {
    for ballot_count in 1..=10 {
        let schedule = canonical_pair_character_product_schedule(ballot_count)
            .expect("selected pair-character schedule");
        let maximum_aggregate_difference = i64::try_from(9 * ballot_count).unwrap();
        for aggregate_difference in -maximum_aggregate_difference..=maximum_aggregate_difference {
            let differences = reachable_ballot_differences(ballot_count, aggregate_difference);
            assert_eq!(differences.iter().sum::<i64>(), aggregate_difference);
            assert!(
                differences
                    .iter()
                    .all(|difference| (-9..=9).contains(difference))
            );

            let active_product = execute_lane_schedule(&schedule, &differences, true);
            let expected_exponent = usize::try_from(90 + aggregate_difference).unwrap();
            assert_eq!(
                active_product
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(_, coefficient)| *coefficient != 0)
                    .collect::<Vec<_>>(),
                vec![(expected_exponent, 1)],
                "active lane drifted for {ballot_count} ballots and difference {aggregate_difference}"
            );

            let inactive_product = execute_lane_schedule(&schedule, &differences, false);
            assert!(inactive_product.iter().all(|coefficient| *coefficient == 0));
        }
    }
}

#[test]
fn selected_pair_character_schedule_rejects_out_of_range_ballot_counts() {
    for ballot_count in [0, 11, usize::MAX] {
        assert_eq!(
            canonical_pair_character_product_schedule(ballot_count)
                .expect_err("unsupported ballot count")
                .code,
            CanonicalErrorCode::InvalidProtocolObject
        );
    }
}

#[test]
fn production_forest_accepts_its_first_leaf_without_loading_a_key() {
    let mut forest = PairCharacterProductForest::new();
    forest
        .absorb(selected_zero_ciphertext(), None)
        .expect("first selected leaf");
    let accounting = forest.accounting();
    assert_eq!(accounting.ballot_ciphertext_count, 1);
    assert_eq!(accounting.ciphertext_multiplication_count, 0);
    assert_eq!(accounting.relinearization_count, 0);
    assert_eq!(accounting.maximum_resident_ciphertext_count, 1);
}

#[test]
fn production_forest_fails_closed_when_a_required_merge_has_no_key() {
    let mut forest = PairCharacterProductForest::new();
    forest
        .absorb(selected_zero_ciphertext(), None)
        .expect("first selected leaf");
    assert!(forest.absorb(selected_zero_ciphertext(), None).is_err());
    assert!(forest.poisoned);
    assert!(forest.forest.is_empty());
    assert!(forest.nodes.is_empty());
    assert!(forest.merges.is_empty());
}

#[test]
fn production_forest_rejects_wrong_leaf_geometry_before_residency() {
    let mut forest = PairCharacterProductForest::new();
    let malformed = Ciphertext {
        components: vec![vec![vec![1_u64]]],
        level: SELECTED_EVALUATOR_WORKING_LEVEL,
        decrypt_scaling: 1,
    };
    assert!(forest.absorb(malformed, None).is_err());
    assert!(forest.poisoned);
    assert!(forest.forest.is_empty());
    assert_eq!(forest.accounting().ballot_ciphertext_count, 0);
}

type LanePolynomial = [u64; PAIR_CHARACTER_LANE_DEGREE];

fn selected_zero_ciphertext() -> Ciphertext {
    Ciphertext {
        components: vec![
            vec![vec![0_u64; POLYNOMIAL_DEGREE]; SELECTED_EVALUATOR_WORKING_LEVEL + 1];
            2
        ],
        level: SELECTED_EVALUATOR_WORKING_LEVEL,
        decrypt_scaling: 1,
    }
}

fn reachable_ballot_differences(ballot_count: usize, aggregate_difference: i64) -> Vec<i64> {
    let mut remaining_difference = aggregate_difference;
    let mut differences = Vec::with_capacity(ballot_count);
    for _ in 0..ballot_count {
        let difference = remaining_difference.clamp(-9, 9);
        differences.push(difference);
        remaining_difference -= difference;
    }
    assert_eq!(remaining_difference, 0);
    differences
}

fn execute_lane_schedule(
    schedule: &PairCharacterProductSchedule,
    differences: &[i64],
    active: bool,
) -> LanePolynomial {
    let mut products = vec![None; schedule.nodes.len()];
    for node in schedule
        .nodes
        .iter()
        .filter(|node| node.multiplication_depth == 0)
    {
        let mut leaf = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
        if active {
            let exponent =
                usize::try_from(9 + differences[node.ballot_span.first_ballot_ordinal]).unwrap();
            leaf[exponent] = 1;
        }
        products[node.node_ordinal] = Some(leaf);
    }
    for merge in &schedule.merges {
        let left = products[merge.left_node_ordinal]
            .as_ref()
            .expect("left lane product");
        let right = products[merge.right_node_ordinal]
            .as_ref()
            .expect("right lane product");
        products[merge.output_node_ordinal] = Some(lane_polynomial_product(left, right));
    }
    let mut product = products[schedule.root_node_ordinal]
        .take()
        .expect("root lane product");
    if schedule.normalization.requires_plaintext_multiplication() {
        let mut normalization = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
        normalization[schedule.normalization.coefficient_ordinal] = 1;
        product = lane_polynomial_product(&product, &normalization);
    }
    product
}

fn lane_polynomial_product(left: &LanePolynomial, right: &LanePolynomial) -> LanePolynomial {
    let mut product = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
    for (left_exponent, left_coefficient) in left
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, coefficient)| *coefficient != 0)
    {
        for (right_exponent, right_coefficient) in right
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, coefficient)| *coefficient != 0)
        {
            let exponent = left_exponent + right_exponent;
            assert!(
                exponent < PAIR_CHARACTER_LANE_DEGREE,
                "selected pair-character product wrapped its extension lane"
            );
            product[exponent] = (product[exponent]
                + (u128::from(left_coefficient) * u128::from(right_coefficient)
                    % u128::from(PLAINTEXT_MODULUS)) as u64)
                % PLAINTEXT_MODULUS;
        }
    }
    product
}
