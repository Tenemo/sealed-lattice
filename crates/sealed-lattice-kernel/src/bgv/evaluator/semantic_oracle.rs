//! Independent test-only oracle for the selected pair-character evaluator.
//!
//! This module intentionally does not import the evaluator compiler, its route
//! table, or its instruction constants. It derives the selected test candidate
//! directly from the finite-field lane definitions and the canonical pair
//! placement table.

pub(crate) const ORACLE_OPTION_COUNT: usize =
    crate::foundation::FOUNDATION_PROFILE.option_count as usize;
pub(crate) const ORACLE_LANE_COUNT: usize = 128;
pub(crate) const ORACLE_BANK_LANE_COUNT: usize = 64;
pub(crate) const ORACLE_EXTENSION_DEGREE: usize = 256;
pub(crate) const ORACLE_CIPHERTEXT_COUNT: usize = 2;
pub(crate) const ORACLE_PLAINTEXT_MODULUS: u64 = 257;
pub(crate) const ORACLE_COMPARISON_OFFSET: i64 = 90;
const ORACLE_LANE_ROOT_GENERATOR: u64 = 3;
const ORACLE_LANE_ORBIT_GENERATOR: usize = 3;

pub(crate) type OracleExtensionLane = [u64; ORACLE_EXTENSION_DEGREE];
pub(crate) type OracleRingValue = Vec<OracleExtensionLane>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OraclePairAssignment {
    pub(crate) ciphertext_ordinal: usize,
    pub(crate) lane_ordinal: usize,
    pub(crate) lower_option_ordinal: usize,
    pub(crate) higher_option_ordinal: usize,
}

#[derive(Clone, Copy)]
struct OracleShiftPlacement {
    ciphertext_ordinal: usize,
    bank_ordinal: usize,
    lane_start: usize,
}

const ORACLE_SHIFT_PLACEMENTS: [OracleShiftPlacement; 19] = [
    placement(1, 0, 7),
    placement(1, 0, 35),
    placement(0, 1, 15),
    placement(0, 1, 33),
    placement(1, 1, 12),
    placement(1, 1, 58),
    placement(0, 0, 38),
    placement(0, 0, 57),
    placement(0, 0, 21),
    placement(1, 1, 31),
    placement(0, 1, 49),
    placement(1, 1, 41),
    placement(0, 1, 6),
    placement(1, 0, 29),
    placement(0, 1, 58),
    placement(1, 0, 57),
    placement(1, 1, 52),
    placement(0, 0, 12),
    placement(0, 0, 7),
];

const fn placement(
    ciphertext_ordinal: usize,
    bank_ordinal: usize,
    lane_start: usize,
) -> OracleShiftPlacement {
    OracleShiftPlacement {
        ciphertext_ordinal,
        bank_ordinal,
        lane_start,
    }
}

pub(crate) fn pair_assignments() -> Vec<OraclePairAssignment> {
    let mut assignments = Vec::with_capacity(ORACLE_OPTION_COUNT * (ORACLE_OPTION_COUNT - 1) / 2);
    for (shift_index, placement) in ORACLE_SHIFT_PLACEMENTS
        .iter()
        .copied()
        .take(ORACLE_OPTION_COUNT - 1)
        .enumerate()
    {
        let option_shift = shift_index + 1;
        for lower_option_ordinal in 0..ORACLE_OPTION_COUNT - option_shift {
            assignments.push(OraclePairAssignment {
                ciphertext_ordinal: placement.ciphertext_ordinal,
                lane_ordinal: placement.bank_ordinal * ORACLE_BANK_LANE_COUNT
                    + (placement.lane_start + lower_option_ordinal) % ORACLE_BANK_LANE_COUNT,
                lower_option_ordinal,
                higher_option_ordinal: lower_option_ordinal + option_shift,
            });
        }
    }
    assignments
}

pub(crate) fn aggregate_character_inputs(aggregate_scores: &[u64]) -> [OracleRingValue; 2] {
    assert_eq!(aggregate_scores.len(), ORACLE_OPTION_COUNT);
    let mut inputs = [zero_ring_value(), zero_ring_value()];
    for assignment in pair_assignments() {
        let lower_score = i64::try_from(aggregate_scores[assignment.lower_option_ordinal])
            .expect("oracle aggregate score fits i64");
        let higher_score = i64::try_from(aggregate_scores[assignment.higher_option_ordinal])
            .expect("oracle aggregate score fits i64");
        let exponent = ORACLE_COMPARISON_OFFSET + lower_score - higher_score;
        assert!((0..=2 * ORACLE_COMPARISON_OFFSET).contains(&exponent));
        inputs[assignment.ciphertext_ordinal][assignment.lane_ordinal]
            [usize::try_from(exponent).expect("oracle exponent is nonnegative")] = 1;
    }
    inputs
}

pub(crate) fn stable_ranks(aggregate_scores: &[u64]) -> Vec<u64> {
    assert_eq!(aggregate_scores.len(), ORACLE_OPTION_COUNT);
    (0..ORACLE_OPTION_COUNT)
        .map(|option_ordinal| {
            let earlier_not_lower = (0..option_ordinal)
                .filter(|earlier_ordinal| {
                    aggregate_scores[*earlier_ordinal] >= aggregate_scores[option_ordinal]
                })
                .count();
            let later_strictly_higher = (option_ordinal + 1..ORACLE_OPTION_COUNT)
                .filter(|later_ordinal| {
                    aggregate_scores[*later_ordinal] > aggregate_scores[option_ordinal]
                })
                .count();
            u64::try_from(earlier_not_lower + later_strictly_higher).expect("oracle rank fits u64")
        })
        .collect()
}

pub(crate) fn target_values(aggregate_scores: &[u64], top_count: usize) -> [Vec<u64>; 2] {
    assert!((1..=ORACLE_OPTION_COUNT).contains(&top_count));
    let ranks = stable_ranks(aggregate_scores);
    let identifiers = ranks
        .iter()
        .copied()
        .enumerate()
        .map(|(option_ordinal, rank)| {
            if usize::try_from(rank).expect("oracle rank fits usize") < top_count {
                u64::try_from(option_ordinal + 1).expect("oracle identifier fits u64")
            } else {
                0
            }
        })
        .collect();
    let order = ranks
        .into_iter()
        .map(|rank| {
            if usize::try_from(rank).expect("oracle rank fits usize") < top_count {
                rank + 1
            } else {
                0
            }
        })
        .collect();
    [identifiers, order]
}

pub(crate) fn comparison_value(character_exponent: usize) -> u64 {
    assert!(character_exponent <= 2 * usize::try_from(ORACLE_COMPARISON_OFFSET).unwrap());
    u64::from(character_exponent < usize::try_from(ORACLE_COMPARISON_OFFSET).unwrap())
}

pub(crate) fn lane_factor_exponent(lane_ordinal: usize) -> usize {
    assert!(lane_ordinal < ORACLE_LANE_COUNT);
    let orbit_ordinal = lane_ordinal % ORACLE_BANK_LANE_COUNT;
    let positive_exponent = modular_power_usize(
        ORACLE_LANE_ORBIT_GENERATOR,
        orbit_ordinal,
        ORACLE_EXTENSION_DEGREE,
    );
    if lane_ordinal < ORACLE_BANK_LANE_COUNT {
        positive_exponent
    } else {
        ORACLE_EXTENSION_DEGREE - positive_exponent
    }
}

pub(crate) fn lane_root(lane_ordinal: usize) -> u64 {
    modular_power(
        ORACLE_LANE_ROOT_GENERATOR,
        u64::try_from(lane_factor_exponent(lane_ordinal)).expect("factor exponent fits u64"),
        ORACLE_PLAINTEXT_MODULUS,
    )
}

pub(crate) fn source_lane_for_galois_action(
    target_lane_ordinal: usize,
    galois_element: usize,
) -> usize {
    let source_factor_exponent = lane_factor_exponent(target_lane_ordinal)
        * (galois_element % ORACLE_EXTENSION_DEGREE)
        % ORACLE_EXTENSION_DEGREE;
    (0..ORACLE_LANE_COUNT)
        .find(|lane_ordinal| lane_factor_exponent(*lane_ordinal) == source_factor_exponent)
        .expect("odd oracle action maps to one selected lane")
}

pub(crate) fn destination_lane_for_galois_action(
    source_lane_ordinal: usize,
    galois_element: usize,
) -> usize {
    (0..ORACLE_LANE_COUNT)
        .find(|target_lane_ordinal| {
            source_lane_for_galois_action(*target_lane_ordinal, galois_element)
                == source_lane_ordinal
        })
        .expect("odd oracle action has one selected destination lane")
}

pub(crate) fn apply_galois_action(
    source: &OracleRingValue,
    galois_element: usize,
) -> OracleRingValue {
    assert_eq!(source.len(), ORACLE_LANE_COUNT);
    assert_eq!(galois_element % 2, 1);
    let mut output = zero_ring_value();
    for (target_lane_ordinal, target_lane) in output.iter_mut().enumerate() {
        let source_lane_ordinal =
            source_lane_for_galois_action(target_lane_ordinal, galois_element);
        let target_lane_root = lane_root(target_lane_ordinal);
        for (source_exponent, source_coefficient) in source[source_lane_ordinal]
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, coefficient)| *coefficient != 0)
        {
            let mapped_exponent = source_exponent * galois_element;
            let target_exponent = mapped_exponent % ORACLE_EXTENSION_DEGREE;
            let reduction_power = mapped_exponent / ORACLE_EXTENSION_DEGREE;
            let reduction_factor = modular_power(
                target_lane_root,
                u64::try_from(reduction_power).expect("oracle reduction power fits u64"),
                ORACLE_PLAINTEXT_MODULUS,
            );
            target_lane[target_exponent] = add_mod(
                target_lane[target_exponent],
                multiply_mod(source_coefficient, reduction_factor),
            );
        }
    }
    output
}

pub(crate) fn add(left: &OracleRingValue, right: &OracleRingValue) -> OracleRingValue {
    assert_ring_geometry(left);
    assert_ring_geometry(right);
    left.iter()
        .zip(right)
        .map(|(left_lane, right_lane)| {
            core::array::from_fn(|coefficient_ordinal| {
                add_mod(
                    left_lane[coefficient_ordinal],
                    right_lane[coefficient_ordinal],
                )
            })
        })
        .collect()
}

pub(crate) fn multiply(left: &OracleRingValue, right: &OracleRingValue) -> OracleRingValue {
    assert_ring_geometry(left);
    assert_ring_geometry(right);
    left.iter()
        .zip(right)
        .enumerate()
        .map(|(lane_ordinal, (left_lane, right_lane))| {
            extension_lane_product(left_lane, right_lane, lane_root(lane_ordinal))
        })
        .collect()
}

pub(crate) fn zero_ring_value() -> OracleRingValue {
    vec![[0_u64; ORACLE_EXTENSION_DEGREE]; ORACLE_LANE_COUNT]
}

pub(crate) fn extension_trace_monomial(
    lane_ordinal: usize,
    exponent: usize,
) -> OracleExtensionLane {
    assert!(lane_ordinal < ORACLE_LANE_COUNT);
    assert!(exponent < ORACLE_EXTENSION_DEGREE);
    let frobenius_multiplier = modular_power(
        lane_root(lane_ordinal),
        u64::try_from(exponent).expect("oracle trace exponent fits u64"),
        ORACLE_PLAINTEXT_MODULUS,
    );
    let mut coefficient = 1_u64;
    let mut trace_coefficient = 0_u64;
    for _ in 0..ORACLE_EXTENSION_DEGREE {
        trace_coefficient = add_mod(trace_coefficient, coefficient);
        coefficient = multiply_mod(coefficient, frobenius_multiplier);
    }
    let mut trace = [0_u64; ORACLE_EXTENSION_DEGREE];
    trace[exponent] = trace_coefficient;
    trace
}

fn extension_lane_product(
    left: &OracleExtensionLane,
    right: &OracleExtensionLane,
    lane_root: u64,
) -> OracleExtensionLane {
    let mut product = [0_u64; ORACLE_EXTENSION_DEGREE];
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
            let unreduced_exponent = left_exponent + right_exponent;
            let target_exponent = unreduced_exponent % ORACLE_EXTENSION_DEGREE;
            let reduction_factor = if unreduced_exponent < ORACLE_EXTENSION_DEGREE {
                1
            } else {
                lane_root
            };
            product[target_exponent] = add_mod(
                product[target_exponent],
                multiply_mod(
                    multiply_mod(left_coefficient, right_coefficient),
                    reduction_factor,
                ),
            );
        }
    }
    product
}

fn assert_ring_geometry(value: &OracleRingValue) {
    assert_eq!(value.len(), ORACLE_LANE_COUNT);
}

fn add_mod(left: u64, right: u64) -> u64 {
    (left + right) % ORACLE_PLAINTEXT_MODULUS
}

fn multiply_mod(left: u64, right: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(ORACLE_PLAINTEXT_MODULUS)) as u64
}

fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (u128::from(result) * u128::from(base) % u128::from(modulus)) as u64;
        }
        base = (u128::from(base) * u128::from(base) % u128::from(modulus)) as u64;
        exponent >>= 1;
    }
    result
}

fn modular_power_usize(mut base: usize, mut exponent: usize, modulus: usize) -> usize {
    let mut result = 1_usize;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn independent_catalog_covers_every_pair_once_across_both_banks() {
        let assignments = pair_assignments();
        let expected_pair_count = ORACLE_OPTION_COUNT * (ORACLE_OPTION_COUNT - 1) / 2;
        assert_eq!(assignments.len(), expected_pair_count);
        assert_eq!(
            assignments
                .iter()
                .map(|assignment| (
                    assignment.lower_option_ordinal,
                    assignment.higher_option_ordinal
                ))
                .collect::<BTreeSet<_>>()
                .len(),
            expected_pair_count
        );
        assert_eq!(
            assignments
                .iter()
                .map(|assignment| assignment.lane_ordinal / ORACLE_BANK_LANE_COUNT)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1])
        );
        assert_eq!(
            assignments
                .iter()
                .map(|assignment| (assignment.ciphertext_ordinal, assignment.lane_ordinal))
                .collect::<BTreeSet<_>>()
                .len(),
            expected_pair_count
        );
    }

    #[test]
    fn independent_character_and_trace_oracles_cover_every_reachable_difference() {
        for lane_ordinal in [0, ORACLE_BANK_LANE_COUNT] {
            for aggregate_difference in -ORACLE_COMPARISON_OFFSET..=ORACLE_COMPARISON_OFFSET {
                let character_exponent =
                    usize::try_from(ORACLE_COMPARISON_OFFSET + aggregate_difference)
                        .expect("shifted difference is nonnegative");
                assert_eq!(
                    comparison_value(character_exponent),
                    u64::from(aggregate_difference < 0)
                );
                let trace = extension_trace_monomial(lane_ordinal, character_exponent);
                if character_exponent == 0 {
                    assert_eq!(trace[0], ORACLE_PLAINTEXT_MODULUS - 1);
                } else {
                    assert!(trace.iter().all(|coefficient| *coefficient == 0));
                }
            }
        }
    }

    #[test]
    fn direct_stable_rank_and_target_oracles_cover_every_tie_multiplicity_and_top_count() {
        for tie_count in 1..=ORACLE_OPTION_COUNT {
            let mut scores = (0..ORACLE_OPTION_COUNT)
                .map(|option_ordinal| {
                    u64::try_from(ORACLE_OPTION_COUNT - option_ordinal)
                        .expect("oracle score fits u64")
                })
                .collect::<Vec<_>>();
            scores[..tie_count].fill(90);
            let ranks = stable_ranks(&scores);
            assert_eq!(
                ranks.iter().copied().collect::<BTreeSet<_>>().len(),
                ORACLE_OPTION_COUNT
            );
            for top_count in 1..=ORACLE_OPTION_COUNT {
                let [identifiers, order] = target_values(&scores, top_count);
                assert_eq!(
                    identifiers.iter().filter(|value| **value != 0).count(),
                    top_count
                );
                assert_eq!(order.iter().filter(|value| **value != 0).count(), top_count);
                for (option_ordinal, rank) in ranks.iter().copied().enumerate() {
                    let selected = usize::try_from(rank).unwrap() < top_count;
                    assert_eq!(
                        identifiers[option_ordinal],
                        if selected {
                            u64::try_from(option_ordinal + 1).unwrap()
                        } else {
                            0
                        }
                    );
                    assert_eq!(order[option_ordinal], if selected { rank + 1 } else { 0 });
                }
            }
        }
    }
}
