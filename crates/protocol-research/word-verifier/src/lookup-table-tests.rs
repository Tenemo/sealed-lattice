use super::*;
use supported_profile::relation::EVALUATION_DOMAIN_SIZE;

// Each coefficient is the subgroup's discrete Fourier sum of the indices
// divided by the subgroup's size.
#[test]
fn coefficients_match_direct_fourier_sums() {
    let coefficients = coefficients();
    for index in [0, 1, SYSTEMATIC / 2, SYSTEMATIC - 1] {
        let mut sum = 0;
        let step = power(
            root(SYSTEMATIC),
            ((SYSTEMATIC - index) % SYSTEMATIC) as u128,
        );
        let mut weight = 1;
        for value in 0..SYSTEMATIC {
            sum = add(sum, multiply(value as u128, weight));
            weight = multiply(weight, step);
        }
        assert_eq!(
            coefficients[index],
            multiply(sum, power(SYSTEMATIC as u128, MODULUS - 2))
        );
    }
}

#[test]
fn matches_horner_at_every_small_coset_point() {
    for length in [2, 4, 8, 16, 32, 64] {
        for variant in 0..4 {
            let coefficients: Vec<_> = (0..length)
                .map(|index| match variant {
                    0 => 0,
                    1 => u128::from(index == 0),
                    2 => u128::from(index + 1 == length),
                    _ => power(17, index as u128),
                })
                .collect();
            let transformed = evaluate_on_proof_domain(&coefficients);
            for (index, actual) in transformed.iter().enumerate() {
                let point = multiply(7, power(root(4 * length), index as u128));
                let expected = coefficients.iter().rev().fold(0, |sum, coefficient| {
                    add(multiply(sum, point), *coefficient)
                });
                assert_eq!(*actual, expected);
            }
        }
    }
}

// The verifier's transform equals the prover's on every power-of-two length
// up to the proof domain, including the lengths whose longest stages the
// prover computes beyond its twiddle tables.
#[test]
fn transform_matches_the_prover_transform() {
    let mut state = 1;
    let mut length = 2;
    while length <= EVALUATION_DOMAIN_SIZE {
        let values: Vec<u128> = (0..length)
            .map(|_| {
                state = add(
                    multiply(state, 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834),
                    1,
                );
                state
            })
            .collect();
        let mut expected = values.clone();
        word_proof::field::Transform::new(length.min(SYSTEMATIC)).base(&mut expected, false);
        let mut actual = values;
        transform(&mut actual);
        assert_eq!(actual, expected, "length {length}");
        length *= 2;
    }
}

// The lookup polynomial takes systematic points to their indices, and the
// table holds its values on the proof domain, both by direct evaluation.
#[test]
fn table_holds_the_index_polynomial_on_the_proof_domain() {
    let coefficients = coefficients();
    let evaluate = |point: u128| {
        coefficients.iter().rev().fold(0, |sum, coefficient| {
            add(multiply(sum, point), *coefficient)
        })
    };
    for index in [0, 1, SYSTEMATIC / 2, SYSTEMATIC - 1] {
        assert_eq!(
            evaluate(power(root(SYSTEMATIC), index as u128)),
            index as u128
        );
    }
    let table = on_proof_domain();
    assert_eq!(table.len(), EVALUATION_DOMAIN_SIZE);
    for index in [0, 1, EVALUATION_DOMAIN_SIZE / 2, EVALUATION_DOMAIN_SIZE - 1] {
        assert_eq!(
            table[index],
            evaluate(multiply(
                7,
                power(root(EVALUATION_DOMAIN_SIZE), index as u128)
            ))
        );
    }
}
