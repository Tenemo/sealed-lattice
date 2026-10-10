use super::*;
use supported_profile::plaintext::power;

// Direct evaluation uses signed integer modular arithmetic, not the FFT.
fn evaluate(coefficients: &[i32], subring_point: u32) -> i64 {
    coefficients
        .iter()
        .step_by(2)
        .rev()
        .fold(0i64, |sum, value| {
            (sum * i64::from(subring_point) + i64::from(*value))
                .rem_euclid(i64::from(PLAINTEXT_MODULUS))
        })
}
fn check(scores: &[u8], degree: usize, sample: &[usize]) {
    let coefficients = encode_with_degree(scores, degree).unwrap();
    assert_eq!(coefficients.len(), degree);
    assert!(
        coefficients
            .iter()
            .all(|value| (-32768..=32768).contains(value))
    );
    assert!(
        coefficients
            .iter()
            .skip(1)
            .step_by(2)
            .all(|value| *value == 0)
    );
    let root = power(3, (PLAINTEXT_MODULUS - 1) / degree as u32);
    let window = scores.len().next_power_of_two();
    let active = scores.len() * scores.len() * window;
    for position in sample {
        let exponent = (0..*position).fold(1usize, |value, _| 5 * value % degree);
        let point = power(root, exponent as u32);
        let expected = if *position < active {
            let option = position / (scores.len() * window);
            let opponent = position % window;
            if opponent < scores.len() {
                2 * (i64::from(scores[opponent]) - i64::from(scores[option]))
            } else {
                0
            }
        } else if *position < active + scores.len() {
            i64::from(scores[position - active])
        } else {
            0
        };
        assert_eq!(
            evaluate(&coefficients, point),
            expected.rem_euclid(i64::from(PLAINTEXT_MODULUS))
        );
        assert_eq!(
            evaluate(&coefficients, power(root, (degree - exponent) as u32)),
            0
        );
    }
}
#[test]
fn all_two_option_scores_match_every_small_ring_slot() {
    for first in 1..=10 {
        for second in 1..=10 {
            check(&[first, second], 64, &(0..16).collect::<Vec<_>>());
        }
    }
}
#[test]
fn full_profile_boundaries_literal_scores_and_padding_match_direct_evaluation() {
    for scores in [
        vec![1; 10],
        vec![10; 10],
        (0..20)
            .map(|index| if index % 2 == 0 { 1 } else { 10 })
            .collect(),
    ] {
        let window = scores.len().next_power_of_two();
        let active = scores.len() * scores.len() * window;
        let mut sample = vec![
            0,
            1,
            scores.len() - 1,
            window - 1,
            active - 1,
            active,
            active + scores.len() - 1,
            active + scores.len(),
            DEGREE / 4 - 1,
        ];
        for option in 0..scores.len() {
            for rank in [0, 1, scores.len() - 1] {
                sample.push((option * scores.len() + rank) * window);
            }
        }
        sample.sort_unstable();
        sample.dedup();
        check(&scores, DEGREE, &sample);
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
    for scores in [vec![1, 10], vec![10; 20]] {
        assert_eq!(check_scores(&scores), Ok(()));
    }
    assert_eq!(encode_with_degree(&[1, 10], 32), Err(Refusal::Capacity));
    assert!(encode_with_degree(&[1, 10], 64).is_ok());
}

#[test]
fn integer_lift_matches_each_public_matrix_row() {
    let scores: Vec<u8> = (1..=10).collect();
    let witness = PackingWitness::new(&scores).unwrap();
    let matrix = PackingMatrix::new(scores.len()).unwrap();
    let columns: Vec<_> = (0..scores.len())
        .map(|option| matrix.column(option).unwrap())
        .collect();
    let active = scores.len() * scores.len() * scores.len().next_power_of_two();
    for (selected, column) in columns.iter().enumerate() {
        assert!(column.iter().all(|value| (-32768..=32768).contains(value)));
        for slot in [0, 1, active + selected] {
            let exponent = (0..slot).fold(1usize, |value, _| 5 * value % DEGREE);
            let expected = if slot >= active {
                1
            } else {
                2 * (i64::from(slot == selected) - i64::from(selected == 0))
            };
            assert_eq!(
                evaluate(column, power(3, exponent as u32)),
                expected.rem_euclid(i64::from(PLAINTEXT_MODULUS))
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
