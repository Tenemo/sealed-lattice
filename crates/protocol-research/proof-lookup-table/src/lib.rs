#[path = "../../word-proof/src/field.rs"]
pub mod field;

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
    field::Transform::new(values.len()).base(&mut values, false);
    values
}

#[cfg(test)]
mod tests {
    use super::*;

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
