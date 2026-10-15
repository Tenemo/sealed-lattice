use super::*;

const FIELD: u64 = 12_289;
const ORBIT: usize = 1_024;

fn residue(value: i64) -> u32 {
    value.rem_euclid(FIELD as i64) as u32
}
fn power(mut value: u64, mut exponent: u64) -> u64 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = result * value % FIELD;
        }
        value = value * value % FIELD;
        exponent >>= 1;
    }
    result
}

// Newton divided differences, converted to ordinary coefficients. This
// test supplies public scalar meanings independently of the native engine.
fn interpolate(points: &[u32], values: &[u32]) -> Vec<u32> {
    let mut differences = values.to_vec();
    for order in 1..points.len() {
        for index in (order..points.len()).rev() {
            let numerator =
                residue(i64::from(differences[index]) - i64::from(differences[index - 1]));
            let denominator = residue(i64::from(points[index]) - i64::from(points[index - order]));
            differences[index] =
                (u64::from(numerator) * power(u64::from(denominator), FIELD - 2) % FIELD) as u32;
        }
    }
    let mut polynomial = vec![*differences.last().unwrap()];
    for index in (0..points.len() - 1).rev() {
        let mut next = vec![0; polynomial.len() + 1];
        for (degree, coefficient) in polynomial.iter().enumerate() {
            next[degree] = residue(
                i64::from(next[degree]) - i64::from(*coefficient) * i64::from(points[index]),
            );
            next[degree + 1] = residue(i64::from(next[degree + 1]) + i64::from(*coefficient));
        }
        next[0] = residue(i64::from(next[0]) + i64::from(differences[index]));
        polynomial = next;
    }
    polynomial
}

fn evaluate(program: &RankingProgram, profile: Profile, ballots: &[Vec<u32>]) -> Vec<u32> {
    let options = profile.options();
    let window = options.next_power_of_two();
    let maximum = 18 * profile.participants() + 1;
    let points: Vec<_> = (0..=maximum)
        .map(|index| residue(2 * index as i64 - maximum as i64))
        .collect();
    let positive: Vec<_> = points
        .iter()
        .map(|value| u32::from(*value > 0 && *value <= FIELD as u32 / 2))
        .collect();
    let comparison = interpolate(&points, &positive);
    let ranks: Vec<_> = (0..options as u32).collect();
    let equality: Vec<_> = (0..options)
        .map(|rank| {
            interpolate(
                &ranks,
                &(0..options)
                    .map(|value| u32::from(value == rank))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let mut values: Vec<Vec<u32>> = Vec::new();
    let word = |bytes: &[u8]| u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
    for instruction in program.bytes()[12..].chunks_exact(16) {
        let operation = word(&instruction[..4]);
        let left = word(&instruction[4..8]);
        let right = word(&instruction[8..12]);
        let parameter = word(&instruction[12..]);
        let output = (0..2 * ORBIT)
            .map(|slot| {
                let input = || values[left][slot];
                let rank_coefficient = |exponent: usize, top_count: usize| {
                    let rank = (window - slot % window) % window;
                    if slot < ORBIT && rank < top_count {
                        equality[rank][exponent]
                    } else {
                        0
                    }
                };
                match operation {
                    0 => {
                        let scores = &ballots[parameter];
                        if slot < options * window && slot % window < options {
                            residue(
                                2 * (i64::from(scores[slot % window])
                                    - i64::from(scores[slot / window])),
                            )
                        } else if slot >= ORBIT && slot < ORBIT + options {
                            scores[slot - ORBIT]
                        } else {
                            0
                        }
                    }
                    1 => residue(i64::from(input()) + i64::from(values[right][slot])),
                    2 => (u64::from(input()) * u64::from(values[right][slot]) % FIELD) as u32,
                    3 => (u64::from(input()) * u64::from(comparison[parameter]) % FIELD) as u32,
                    4 => {
                        let coefficient = if parameter == 0 {
                            u32::from(slot < ORBIT && slot % window == 0)
                        } else {
                            let family = parameter / options;
                            rank_coefficient(
                                parameter % options,
                                if family == 0 { options } else { family },
                            )
                        };
                        (u64::from(input()) * u64::from(coefficient) % FIELD) as u32
                    }
                    5 => {
                        let constant = match parameter {
                            0 => {
                                if slot >= ORBIT {
                                    0
                                } else if slot < options * window && slot % window < slot / window {
                                    1
                                } else {
                                    FIELD as u32 - 1
                                }
                            }
                            1 => comparison[0],
                            value if value == options + 3 => {
                                if slot < ORBIT && slot % window == 0 && slot / window >= options {
                                    FIELD as u32 - 1
                                } else {
                                    0
                                }
                            }
                            2 => rank_coefficient(0, options),
                            value => rank_coefficient(0, value - 2),
                        };
                        residue(i64::from(input()) + i64::from(constant))
                    }
                    6 => values[left][slot / ORBIT * ORBIT + (slot + 1) % ORBIT],
                    _ => panic!("Unknown ranking operation"),
                }
            })
            .collect();
        values.push(output);
    }
    values.pop().unwrap()
}

#[test]
fn emitted_programs_match_clear_sorting_with_ties_extremes_and_missing_ballots() {
    for (participants, options) in [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        for pattern in 0..3 {
            let ballots: Vec<Vec<u32>> = (0..participants)
                .map(|voter| {
                    (0..options)
                        .map(|option| match pattern {
                            0 => 1,
                            1 => {
                                if (voter + option) % 2 == 0 {
                                    10
                                } else {
                                    1
                                }
                            }
                            _ => {
                                if voter % 3 == 0 {
                                    0
                                } else {
                                    ((option * (voter + 3) + voter) % 10 + 1) as u32
                                }
                            }
                        })
                        .collect()
                })
                .collect();
            let totals: Vec<u32> = (0..options)
                .map(|option| ballots.iter().map(|ballot| ballot[option]).sum())
                .collect();
            let mut order: Vec<_> = (0..options).collect();
            order.sort_by_key(|option| (std::cmp::Reverse(totals[*option]), *option));
            for top_count in [1, options / 2, options] {
                let program = RankingProgram::for_profile(profile, top_count).unwrap();
                let mut expected = vec![0; 2 * ORBIT];
                for (rank, option) in order.iter().take(top_count).enumerate() {
                    expected[(option * options.next_power_of_two() + ORBIT - rank) % ORBIT] = 1;
                }
                assert_eq!(
                    evaluate(&program, profile, &ballots),
                    expected,
                    "participants={participants}, options={options}, top_count={top_count}, pattern={pattern}"
                );
            }
        }
    }
}
