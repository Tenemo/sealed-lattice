use std::sync::OnceLock;
use supported_profile::relation::SYSTEMATIC;
use word_proof::field::{
    self,
    base::{MODULUS, multiply, power, subtract},
};

// The caller supplies the fixed lookup polynomial coefficients under this
// field. This computes its complete coset evaluation; it creates no proof or
// protocol verification authority.
pub fn evaluate_on_proof_domain(coefficients: &[u128]) -> Vec<u128> {
    assert!(coefficients.len().is_power_of_two());
    assert!((2..=65_536).contains(&coefficients.len()));
    let mut values = vec![0; 4 * coefficients.len()];
    let mut twist = 1;
    for (value, coefficient) in values.iter_mut().zip(coefficients) {
        *value = field::base::multiply(*coefficient, twist);
        twist = field::base::multiply(twist, 7);
    }
    // Tables no longer than the systematic length; the longer stages
    // compute their twiddles as they go.
    field::Transform::new(values.len().min(SYSTEMATIC)).base(&mut values, false);
    values
}

/// The coefficients of the lookup polynomial, which takes the systematic
/// subgroup's element of each index to that index: (H - 1) / 2 at degree
/// zero and 1 / (w^-k - 1) at each degree k, for the subgroup's root w.
pub fn coefficients() -> Vec<u128> {
    let inverse_root = power(field::root(SYSTEMATIC), MODULUS - 2);
    let mut denominators = Vec::with_capacity(SYSTEMATIC - 1);
    let mut value = 1;
    for _ in 1..SYSTEMATIC {
        value = multiply(value, inverse_root);
        denominators.push(subtract(value, 1));
    }
    let mut product = 1;
    let prefixes: Vec<u128> = denominators
        .iter()
        .map(|value| {
            let previous = product;
            product = multiply(product, *value);
            previous
        })
        .collect();
    let mut suffix = power(product, MODULUS - 2);
    let mut values = vec![multiply((SYSTEMATIC - 1) as u128, power(2, MODULUS - 2)); SYSTEMATIC];
    for index in (0..denominators.len()).rev() {
        values[index + 1] = multiply(prefixes[index], suffix);
        suffix = multiply(suffix, denominators[index]);
    }
    values
}

/// The lookup polynomial's values on the proof domain, which every verifier
/// of this instance reads, computed once.
pub fn on_proof_domain() -> &'static [u128] {
    static VALUES: OnceLock<Vec<u128>> = OnceLock::new();
    VALUES.get_or_init(|| evaluate_on_proof_domain(&coefficients()))
}

#[cfg(test)]
mod tests {
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
}
