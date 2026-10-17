use super::*;
use supported_profile::plaintext::{encoding_degree, power};

// Horner evaluation over signed integers is independent of the transform.
fn evaluate(coefficients: &[i32], point: u32) -> i64 {
    let stride = 2 * coefficients.len() / encoding_degree(coefficients.len());
    coefficients
        .iter()
        .step_by(stride)
        .rev()
        .fold(0i64, |sum, value| {
            (sum * i64::from(point) + i64::from(*value)).rem_euclid(i64::from(PLAINTEXT_MODULUS))
        })
}
fn check(scores: &[u8], degree: usize, sample: &[usize]) {
    let coefficients = encode_with_degree(scores, degree).unwrap();
    let encoding = encoding_degree(degree);
    let stride = 2 * degree / encoding;
    assert_eq!(coefficients.len(), degree);
    assert!(coefficients.iter().enumerate().all(|(index, value)| {
        value.unsigned_abs() <= PLAINTEXT_MODULUS / 2 && (index % stride == 0 || *value == 0)
    }));
    let root = power(11, (PLAINTEXT_MODULUS - 1) / encoding as u32);
    let window = scores.len().next_power_of_two();
    for position in sample {
        let exponent = (0..*position).fold(1usize, |value, _| 5 * value % encoding);
        let option = position / window;
        let opponent = position % window;
        let expected = if option < scores.len() && opponent < scores.len() {
            2 * (i64::from(scores[opponent]) - i64::from(scores[option]))
        } else {
            0
        };
        assert_eq!(
            evaluate(&coefficients, power(root, exponent as u32)),
            expected.rem_euclid(i64::from(PLAINTEXT_MODULUS))
        );
        assert_eq!(
            evaluate(&coefficients, power(root, (encoding - exponent) as u32)),
            scores.get(*position).map_or(0, |score| i64::from(*score))
        );
    }
}

#[test]
fn all_two_option_scores_match_both_small_ring_orbits() {
    for first in 1..=10 {
        for second in 1..=10 {
            check(&[first, second], 32, &(0..8).collect::<Vec<_>>());
        }
    }
}

#[test]
fn every_option_count_preserves_literal_scores_and_zero_padding() {
    for options in Profile::option_range() {
        for scores in [
            vec![1; options],
            vec![10; options],
            (0..options)
                .map(|index| 1 + ((index * 7 + 3) % 10) as u8)
                .collect(),
        ] {
            let window = options.next_power_of_two();
            let mut sample = vec![
                0,
                options - 1,
                options,
                options * window - 1,
                options * window,
                plaintext::ACTIVE_SLOTS - 1,
            ];
            sample.extend(0..options);
            sample.extend((0..options).map(|option| option * window));
            sample.sort_unstable();
            sample.dedup();
            check(&scores, DEGREE, &sample);
        }
    }
}

#[test]
fn refuses_invalid_scores_counts_and_capacity() {
    for scores in [vec![], vec![1], vec![1; 21]] {
        assert_eq!(check_scores(&scores), Err(Refusal::Options));
        assert_eq!(encode(&scores), Err(Refusal::Options));
    }
    for scores in [vec![0, 1], vec![1, 11], vec![10, 10, 10, 0]] {
        assert_eq!(check_scores(&scores), Err(Refusal::Scores));
        assert_eq!(encode(&scores), Err(Refusal::Scores));
    }
    assert_eq!(encode_with_degree(&[1; 20], 2048), Err(Refusal::Capacity));
    assert_eq!(encode_with_degree(&[1, 10], 24), Err(Refusal::Capacity));
    assert!(encode_with_degree(&[1; 20], 4096).is_ok());
}

#[test]
fn integer_lift_matches_each_public_matrix_row_and_literal_score_column() {
    let scores: Vec<u8> = (1..=10).collect();
    let witness = PackingWitness::new(&scores).unwrap();
    let matrix = PackingMatrix::new(scores.len()).unwrap();
    let columns: Vec<_> = (0..scores.len())
        .map(|option| matrix.column(option).unwrap())
        .collect();
    let root = power(
        11,
        (PLAINTEXT_MODULUS - 1) / plaintext::ENCODING_DEGREE as u32,
    );
    for (selected, column) in columns.iter().enumerate() {
        for literal in 0..scores.len() {
            let exponent =
                (0..literal).fold(1usize, |value, _| 5 * value % plaintext::ENCODING_DEGREE);
            assert_eq!(
                evaluate(
                    column,
                    power(root, (plaintext::ENCODING_DEGREE - exponent) as u32)
                ),
                i64::from(selected == literal)
            );
        }
    }
    for position in 0..DEGREE {
        let expected = columns
            .iter()
            .zip(&scores)
            .map(|(column, score)| i64::from(column[position]) * i64::from(*score))
            .sum::<i64>();
        assert_eq!(
            i64::from(witness.message()[position])
                - expected
                - i64::from(PLAINTEXT_MODULUS) * i64::from(witness.quotients()[position]),
            0
        );
    }
    assert!(matrix.column(scores.len()).is_err());
}
