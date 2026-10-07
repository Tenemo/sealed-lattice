use super::*;

// Each coefficient is the subgroup's discrete Fourier sum of the indices
// divided by the subgroup's size.
#[test]
fn coefficients_match_direct_fourier_sums() {
    use field::base::add;
    let coefficients = coefficients();
    for index in [0, 1, SYSTEMATIC / 2, SYSTEMATIC - 1] {
        let mut sum = 0;
        let step = power(
            field::root(SYSTEMATIC),
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
    use field::base::{add, multiply, power};
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
                let point = multiply(7, power(field::root(4 * length), index as u128));
                let expected = coefficients.iter().rev().fold(0, |sum, coefficient| {
                    add(multiply(sum, point), *coefficient)
                });
                assert_eq!(*actual, expected);
            }
        }
    }
}
