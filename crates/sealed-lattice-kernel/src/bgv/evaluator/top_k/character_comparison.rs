use crate::{
    bgv::{
        encoding::CandidatePlaintextRing,
        modular_arithmetic::{inverse_mod, pow_mod},
        parameters::{CANDIDATE_PLAINTEXT_DEGREE, CANDIDATE_PLAINTEXT_MODULUS},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

use super::pairwise_topology::{
    CHARACTER_ROW_COUNT, CHARACTER_SLOT_COUNT, PairSign, PairTile, PairwiseCharacterTopology,
    RankContribution, SourceAutomorphism, TILE_WIDTH, logical_slot,
};

pub(crate) const CHARACTER_ROOT: u64 = 282;
pub(crate) const BALLOT_COUNT: usize = 10;
pub(crate) const OPTION_COUNT: usize = 20;
pub(crate) const MINIMUM_BALLOT_SCORE: u8 = 1;
pub(crate) const MAXIMUM_BALLOT_SCORE: u8 = 10;
pub(crate) const MAXIMUM_AGGREGATE_DIFFERENCE: i32 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FreeResidueFill {
    Centered,
    Zero,
    NearestConstrainedSide,
}

pub(crate) fn comparison_fourier_coefficients(
    free_residue_fill: FreeResidueFill,
) -> CanonicalResult<[u64; CHARACTER_ROW_COUNT]> {
    let comparison_values = comparison_values(free_residue_fill);
    let inverse_row_count = inverse_mod(CHARACTER_ROW_COUNT as u64, CANDIDATE_PLAINTEXT_MODULUS)?;
    let mut coefficients = [0_u64; CHARACTER_ROW_COUNT];
    for (row, coefficient) in coefficients.iter_mut().enumerate() {
        let row_root = pow_mod(
            CHARACTER_ROOT,
            ((CHARACTER_ROW_COUNT - row) % CHARACTER_ROW_COUNT) as u64,
            CANDIDATE_PLAINTEXT_MODULUS,
        )?;
        let mut row_power = 1_u64;
        let mut accumulated = 0_u64;
        for comparison_value in comparison_values {
            accumulated = add_field(accumulated, multiply_field(comparison_value, row_power));
            row_power = multiply_field(row_power, row_root);
        }
        *coefficient = multiply_field(accumulated, inverse_row_count);
    }
    Ok(coefficients)
}

pub(crate) fn comparison_weight_slots(
    topology: &PairwiseCharacterTopology,
    tile: PairTile,
    free_residue_fill: FreeResidueFill,
) -> CanonicalResult<Vec<u64>> {
    let coefficients = comparison_fourier_coefficients(free_residue_fill)?;
    let mut slots = vec![0_u64; CHARACTER_SLOT_COUNT];
    for bin in topology.bins().iter().filter(|bin| bin.tile == tile) {
        for row in 0..CHARACTER_ROW_COUNT {
            for destination_candidate in
                bin.destination_start..bin.destination_start + bin.pair_count
            {
                slots[logical_slot(bin.sign, destination_candidate, row)?] = coefficients[row];
            }
        }
    }
    Ok(slots)
}

pub(crate) fn ballot_character_slots(scores: &[u8]) -> CanonicalResult<Vec<u64>> {
    if scores.len() != OPTION_COUNT {
        return Err(character_error(
            "character ballot must contain the selected option count",
        ));
    }
    if scores
        .iter()
        .any(|score| !(MINIMUM_BALLOT_SCORE..=MAXIMUM_BALLOT_SCORE).contains(score))
    {
        return Err(character_error(
            "character ballot score is outside the selected range",
        ));
    }

    let mut slots = vec![0_u64; CHARACTER_SLOT_COUNT];
    for (option_index, score) in scores.iter().copied().enumerate() {
        for row in 0..CHARACTER_ROW_COUNT {
            let positive_exponent = row * usize::from(score) % CHARACTER_ROW_COUNT;
            let negative_exponent = (CHARACTER_ROW_COUNT - positive_exponent) % CHARACTER_ROW_COUNT;
            slots[logical_slot(PairSign::Positive, option_index, row)?] = pow_mod(
                CHARACTER_ROOT,
                positive_exponent as u64,
                CANDIDATE_PLAINTEXT_MODULUS,
            )?;
            slots[logical_slot(PairSign::Negative, option_index, row)?] = pow_mod(
                CHARACTER_ROOT,
                negative_exponent as u64,
                CANDIDATE_PLAINTEXT_MODULUS,
            )?;
        }
    }
    Ok(slots)
}

pub(crate) fn evaluate_ranks_from_character_ballots(
    ballots: &[Vec<u8>],
    free_residue_fill: FreeResidueFill,
) -> CanonicalResult<[u64; OPTION_COUNT]> {
    if ballots.len() != BALLOT_COUNT {
        return Err(character_error(
            "character evaluator requires the selected ballot count",
        ));
    }
    let ballot_slots = ballots
        .iter()
        .map(|scores| ballot_character_slots(scores))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let aggregate = balanced_slot_product(&ballot_slots)?;
    let topology = PairwiseCharacterTopology::exact()?;
    let mut pair_tiles = [
        vec![0_u64; CHARACTER_SLOT_COUNT],
        vec![0_u64; CHARACTER_SLOT_COUNT],
    ];
    for bin in topology.bins() {
        let (lower_source, higher_source) = topology.source_automorphisms(*bin)?;
        let lower = apply_source_automorphism(&aggregate, lower_source)?;
        let higher = apply_source_automorphism(&aggregate, higher_source)?;
        let mask = topology.mask_slots(*bin)?;
        let pair_characters = multiply_slots(&multiply_slots(&lower, &higher)?, &mask)?;
        let tile_index = match bin.tile {
            PairTile::First => 0,
            PairTile::Second => 1,
        };
        add_slots_in_place(&mut pair_tiles[tile_index], &pair_characters)?;
    }

    for (tile_index, tile) in [PairTile::First, PairTile::Second].into_iter().enumerate() {
        let weights = comparison_weight_slots(&topology, tile, free_residue_fill)?;
        pair_tiles[tile_index] = multiply_slots(&pair_tiles[tile_index], &weights)?;
    }

    let mut signed_rank_characters = vec![0_u64; CHARACTER_SLOT_COUNT];
    for route in topology.rank_scatter_routes()? {
        let mut route_input = vec![0_u64; CHARACTER_SLOT_COUNT];
        for term in route.terms {
            let tile_index = match term.bin.tile {
                PairTile::First => 0,
                PairTile::Second => 1,
            };
            let mut mask = topology.mask_slots(term.bin)?;
            if term.contribution == RankContribution::Negative {
                for value in &mut mask {
                    *value = multiply_field(*value, term.contribution.residue());
                }
            }
            let contribution = multiply_slots(&pair_tiles[tile_index], &mask)?;
            add_slots_in_place(&mut route_input, &contribution)?;
        }
        let routed = apply_source_automorphism(&route_input, route.automorphism)?;
        add_slots_in_place(&mut signed_rank_characters, &routed)?;
    }

    let mut ranks = [0_u64; OPTION_COUNT];
    for (option_index, rank) in ranks.iter_mut().enumerate() {
        let mut signed_pair_sum = 0_u64;
        for row in 0..CHARACTER_ROW_COUNT {
            signed_pair_sum = add_field(
                signed_pair_sum,
                signed_rank_characters[logical_slot(PairSign::Positive, option_index, row)?],
            );
        }
        *rank = add_field(signed_pair_sum, (OPTION_COUNT - 1 - option_index) as u64);
    }
    Ok(ranks)
}

pub(crate) fn bounded_target_values(
    ranks: &[u64; OPTION_COUNT],
    top_count: usize,
) -> CanonicalResult<([u64; OPTION_COUNT], [u64; OPTION_COUNT])> {
    if !(1..=OPTION_COUNT).contains(&top_count)
        || ranks.iter().any(|rank| *rank >= OPTION_COUNT as u64)
    {
        return Err(character_error(
            "bounded target input is outside the selected rank domain",
        ));
    }
    let mut identifiers = [0_u64; OPTION_COUNT];
    let mut orders = [0_u64; OPTION_COUNT];
    for (option_index, rank) in ranks.iter().copied().enumerate() {
        if rank < top_count as u64 {
            identifiers[option_index] = option_index as u64 + 1;
            orders[option_index] = rank + 1;
        }
    }
    Ok((identifiers, orders))
}

pub(crate) fn rank_lookup_coefficients(top_count: usize) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    if !(1..OPTION_COUNT).contains(&top_count) {
        return Err(character_error(
            "rank lookup is required only for a strict bounded target",
        ));
    }
    let indicator_values = (0..OPTION_COUNT)
        .map(|rank| u64::from(rank < top_count))
        .collect::<Vec<_>>();
    let order_values = (0..OPTION_COUNT)
        .map(|rank| if rank < top_count { rank as u64 + 1 } else { 0 })
        .collect::<Vec<_>>();
    Ok((
        interpolate_field_values(&indicator_values)?,
        interpolate_field_values(&order_values)?,
    ))
}

pub(crate) fn evaluate_field_polynomial(coefficients: &[u64], input: u64) -> u64 {
    coefficients.iter().rev().fold(0_u64, |value, coefficient| {
        add_field(multiply_field(value, input), *coefficient)
    })
}

pub(crate) fn centered_coefficient_norms(coefficients: &[u64]) -> (u128, u64, usize) {
    coefficients.iter().fold(
        (0_u128, 0_u64, 0_usize),
        |(l1_norm, infinity_norm, nonzero_count), coefficient| {
            let magnitude = if *coefficient > CANDIDATE_PLAINTEXT_MODULUS / 2 {
                CANDIDATE_PLAINTEXT_MODULUS - *coefficient
            } else {
                *coefficient
            };
            (
                l1_norm + u128::from(magnitude),
                infinity_norm.max(magnitude),
                nonzero_count + usize::from(*coefficient != 0),
            )
        },
    )
}

fn comparison_values(free_residue_fill: FreeResidueFill) -> [u64; CHARACTER_ROW_COUNT] {
    let inclusive_one_maximum = match free_residue_fill {
        FreeResidueFill::Centered => 127,
        FreeResidueFill::Zero => MAXIMUM_AGGREGATE_DIFFERENCE as usize,
        FreeResidueFill::NearestConstrainedSide => 128,
    };
    let mut values = [0_u64; CHARACTER_ROW_COUNT];
    values[..=inclusive_one_maximum].fill(1);
    values
}

fn balanced_slot_product(inputs: &[Vec<u64>]) -> CanonicalResult<Vec<u64>> {
    if inputs.is_empty() {
        return Err(character_error(
            "balanced character product requires at least one input",
        ));
    }
    let mut frontier = inputs.to_vec();
    while frontier.len() > 1 {
        let mut next_frontier = Vec::with_capacity(frontier.len().div_ceil(2));
        for pair in frontier.chunks(2) {
            next_frontier.push(if pair.len() == 2 {
                multiply_slots(&pair[0], &pair[1])?
            } else {
                pair[0].clone()
            });
        }
        frontier = next_frontier;
    }
    frontier
        .pop()
        .ok_or_else(|| character_error("balanced character product lost its output"))
}

fn apply_source_automorphism(
    slots: &[u64],
    source: SourceAutomorphism,
) -> CanonicalResult<Vec<u64>> {
    if slots.len() != CANDIDATE_PLAINTEXT_DEGREE {
        return Err(character_error(
            "character automorphism received the wrong slot count",
        ));
    }
    let sign_slot_count = CANDIDATE_PLAINTEXT_DEGREE / 2;
    let source_shift = source
        .generator_exponent()
        .rem_euclid(sign_slot_count as i32) as usize;
    let mut output = vec![0_u64; CANDIDATE_PLAINTEXT_DEGREE];
    for (output_index, output_value) in output.iter_mut().enumerate() {
        let output_sign = output_index / sign_slot_count;
        let output_orbit_index = output_index % sign_slot_count;
        let source_sign = output_sign ^ usize::from(source.is_conjugated());
        let source_orbit_index = (output_orbit_index + source_shift) % sign_slot_count;
        *output_value = slots[source_sign * sign_slot_count + source_orbit_index];
    }
    Ok(output)
}

fn multiply_slots(left: &[u64], right: &[u64]) -> CanonicalResult<Vec<u64>> {
    if left.len() != right.len() {
        return Err(character_error(
            "character slot multiplication received mismatched lengths",
        ));
    }
    Ok(left
        .iter()
        .zip(right)
        .map(|(left, right)| multiply_field(*left, *right))
        .collect())
}

fn add_slots_in_place(accumulated: &mut [u64], added: &[u64]) -> CanonicalResult<()> {
    if accumulated.len() != added.len() {
        return Err(character_error(
            "character slot addition received mismatched lengths",
        ));
    }
    for (accumulated, added) in accumulated.iter_mut().zip(added) {
        *accumulated = add_field(*accumulated, *added);
    }
    Ok(())
}

fn interpolate_field_values(values: &[u64]) -> CanonicalResult<Vec<u64>> {
    let mut coefficients = vec![0_u64; values.len()];
    for (point, value) in values.iter().copied().enumerate() {
        let mut numerator = vec![1_u64];
        let mut denominator = 1_u64;
        for other in 0..values.len() {
            if other == point {
                continue;
            }
            numerator = multiply_by_linear_root(&numerator, other as u64);
            denominator = multiply_field(
                denominator,
                (point as i64 - other as i64).rem_euclid(CANDIDATE_PLAINTEXT_MODULUS as i64) as u64,
            );
        }
        let scale = multiply_field(
            value,
            inverse_mod(denominator, CANDIDATE_PLAINTEXT_MODULUS)?,
        );
        for (degree, numerator_coefficient) in numerator.iter().copied().enumerate() {
            coefficients[degree] = add_field(
                coefficients[degree],
                multiply_field(numerator_coefficient, scale),
            );
        }
    }
    Ok(coefficients)
}

fn multiply_by_linear_root(polynomial: &[u64], root: u64) -> Vec<u64> {
    let mut product = vec![0_u64; polynomial.len() + 1];
    for (degree, coefficient) in polynomial.iter().copied().enumerate() {
        product[degree + 1] = add_field(product[degree + 1], coefficient);
        product[degree] = add_field(
            product[degree],
            multiply_field(
                coefficient,
                (CANDIDATE_PLAINTEXT_MODULUS - root) % CANDIDATE_PLAINTEXT_MODULUS,
            ),
        );
    }
    product
}

fn add_field(left: u64, right: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(CANDIDATE_PLAINTEXT_MODULUS)) as u64
}

fn multiply_field(left: u64, right: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(CANDIDATE_PLAINTEXT_MODULUS)) as u64
}

fn character_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn character_root_and_inverse_fourier_transform_are_exact_on_the_full_cycle() {
        assert_eq!(
            pow_mod(3, 256, CANDIDATE_PLAINTEXT_MODULUS).expect("character root"),
            CHARACTER_ROOT,
        );
        assert_eq!(
            pow_mod(
                CHARACTER_ROOT,
                CHARACTER_ROW_COUNT as u64,
                CANDIDATE_PLAINTEXT_MODULUS,
            )
            .expect("root power 256"),
            1,
        );
        assert_eq!(
            pow_mod(
                CHARACTER_ROOT,
                (CHARACTER_ROW_COUNT / 2) as u64,
                CANDIDATE_PLAINTEXT_MODULUS,
            )
            .expect("root power 128"),
            CANDIDATE_PLAINTEXT_MODULUS - 1,
        );

        for fill in [
            FreeResidueFill::Centered,
            FreeResidueFill::Zero,
            FreeResidueFill::NearestConstrainedSide,
        ] {
            let coefficients = comparison_fourier_coefficients(fill).expect("Fourier weights");
            let expected_values = comparison_values(fill);
            for residue in 0..CHARACTER_ROW_COUNT {
                let reconstructed = coefficients.iter().enumerate().fold(
                    0_u64,
                    |accumulated, (row, coefficient)| {
                        add_field(
                            accumulated,
                            multiply_field(
                                *coefficient,
                                pow_mod(
                                    CHARACTER_ROOT,
                                    (row * residue % CHARACTER_ROW_COUNT) as u64,
                                    CANDIDATE_PLAINTEXT_MODULUS,
                                )
                                .expect("character power"),
                            ),
                        )
                    },
                );
                assert_eq!(
                    reconstructed, expected_values[residue],
                    "{fill:?} at {residue}"
                );
            }
        }
    }

    #[test]
    fn all_free_residue_fills_preserve_the_certified_comparison_domain() {
        for fill in [
            FreeResidueFill::Centered,
            FreeResidueFill::Zero,
            FreeResidueFill::NearestConstrainedSide,
        ] {
            let coefficients = comparison_fourier_coefficients(fill).expect("Fourier weights");
            for difference in -MAXIMUM_AGGREGATE_DIFFERENCE..=MAXIMUM_AGGREGATE_DIFFERENCE {
                let residue = difference.rem_euclid(CHARACTER_ROW_COUNT as i32) as usize;
                let comparison = coefficients.iter().enumerate().fold(
                    0_u64,
                    |accumulated, (row, coefficient)| {
                        add_field(
                            accumulated,
                            multiply_field(
                                *coefficient,
                                pow_mod(
                                    CHARACTER_ROOT,
                                    (row * residue % CHARACTER_ROW_COUNT) as u64,
                                    CANDIDATE_PLAINTEXT_MODULUS,
                                )
                                .expect("character power"),
                            ),
                        )
                    },
                );
                assert_eq!(
                    comparison,
                    u64::from(difference >= 0),
                    "{fill:?} at {difference}"
                );
            }
        }
    }

    #[test]
    fn centered_free_fill_has_the_smallest_maximum_tile_weight_norm_of_the_cheap_choices() {
        let topology = PairwiseCharacterTopology::exact().expect("exact pair topology");
        let mut maximum_norms = Vec::new();
        for fill in [
            FreeResidueFill::Centered,
            FreeResidueFill::Zero,
            FreeResidueFill::NearestConstrainedSide,
        ] {
            let first_coefficients = CandidatePlaintextRing::FullySplit
                .encode_logical_slots(
                    &comparison_weight_slots(&topology, PairTile::First, fill)
                        .expect("first-tile weights"),
                )
                .expect("first-tile encoding");
            let second_coefficients = CandidatePlaintextRing::FullySplit
                .encode_logical_slots(
                    &comparison_weight_slots(&topology, PairTile::Second, fill)
                        .expect("second-tile weights"),
                )
                .expect("second-tile encoding");
            maximum_norms.push((
                fill,
                centered_coefficient_norms(&first_coefficients),
                centered_coefficient_norms(&second_coefficients),
            ));
        }
        assert_eq!(
            maximum_norms[0],
            (
                FreeResidueFill::Centered,
                (531_428_620, 32_767, 32_513),
                (528_469_218, 32_767, 32_381),
            ),
        );
        assert_eq!(
            maximum_norms[1],
            (
                FreeResidueFill::Zero,
                (533_359_154, 32_767, 32_640),
                (526_153_695, 32_767, 32_509),
            ),
        );
        let centered_maximum = maximum_norms[0].1.0.max(maximum_norms[0].2.0);
        assert!(
            maximum_norms[1..]
                .iter()
                .all(|(_, first, second)| centered_maximum < first.0.max(second.0))
        );
    }

    #[test]
    fn character_tiles_reproduce_tie_broken_ranks_for_adversarial_ballots() {
        let ballot_sets = [
            vec![vec![1_u8; OPTION_COUNT]; BALLOT_COUNT],
            (0..BALLOT_COUNT)
                .map(|ballot_index| {
                    (0..OPTION_COUNT)
                        .map(|option_index| {
                            MINIMUM_BALLOT_SCORE
                                + ((7 * ballot_index + 3 * option_index) % 10) as u8
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
            (0..BALLOT_COUNT)
                .map(|ballot_index| {
                    (0..OPTION_COUNT)
                        .map(|option_index| {
                            if (ballot_index + option_index).is_multiple_of(2) {
                                MINIMUM_BALLOT_SCORE
                            } else {
                                MAXIMUM_BALLOT_SCORE
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        ];

        for ballots in ballot_sets {
            let expected = reference_ranks(&ballots);
            for fill in [
                FreeResidueFill::Centered,
                FreeResidueFill::Zero,
                FreeResidueFill::NearestConstrainedSide,
            ] {
                assert_eq!(
                    evaluate_ranks_from_character_ballots(&ballots, fill).expect("character ranks"),
                    expected,
                    "{fill:?}",
                );
            }
        }
    }

    #[test]
    fn degree_nineteen_rank_lookups_preserve_bounded_release_for_every_top_count() {
        let ranks = core::array::from_fn(|option_index| (OPTION_COUNT - 1 - option_index) as u64);
        for top_count in 1..OPTION_COUNT {
            let (indicator, order) = rank_lookup_coefficients(top_count).expect("rank lookups");
            assert_eq!(indicator.len(), OPTION_COUNT);
            assert_eq!(order.len(), OPTION_COUNT);
            for rank in 0..OPTION_COUNT {
                assert_eq!(
                    evaluate_field_polynomial(&indicator, rank as u64),
                    u64::from(rank < top_count),
                );
                assert_eq!(
                    evaluate_field_polynomial(&order, rank as u64),
                    if rank < top_count { rank as u64 + 1 } else { 0 },
                );
            }

            let (identifiers, orders) =
                bounded_target_values(&ranks, top_count).expect("bounded target values");
            assert_eq!(
                identifiers
                    .iter()
                    .filter(|identifier| **identifier != 0)
                    .count(),
                top_count,
            );
            assert_eq!(
                orders
                    .iter()
                    .copied()
                    .filter(|order| *order != 0)
                    .collect::<BTreeSet<_>>(),
                (1..=top_count as u64).collect::<BTreeSet<_>>(),
            );
        }
        assert!(rank_lookup_coefficients(OPTION_COUNT).is_err());
    }

    #[test]
    fn malformed_character_inputs_reject_without_truncation() {
        assert!(ballot_character_slots(&vec![1; OPTION_COUNT - 1]).is_err());
        for invalid_score in [0, 11] {
            let mut scores = vec![1; OPTION_COUNT];
            scores[7] = invalid_score;
            assert!(ballot_character_slots(&scores).is_err());
        }
        assert!(
            evaluate_ranks_from_character_ballots(
                &vec![vec![1; OPTION_COUNT]; BALLOT_COUNT - 1],
                FreeResidueFill::Centered,
            )
            .is_err(),
        );
        assert!(bounded_target_values(&[0; OPTION_COUNT], 0).is_err());
        assert!(bounded_target_values(&[OPTION_COUNT as u64; OPTION_COUNT], 1).is_err());
    }

    fn reference_ranks(ballots: &[Vec<u8>]) -> [u64; OPTION_COUNT] {
        let aggregate_scores = core::array::from_fn::<u64, OPTION_COUNT, _>(|option_index| {
            ballots
                .iter()
                .map(|ballot| u64::from(ballot[option_index]))
                .sum()
        });
        core::array::from_fn(|option_index| {
            aggregate_scores
                .iter()
                .enumerate()
                .filter(|(other_option, other_score)| {
                    **other_score > aggregate_scores[option_index]
                        || (**other_score == aggregate_scores[option_index]
                            && *other_option < option_index)
                })
                .count() as u64
        })
    }
}
