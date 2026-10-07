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
#[path = "lib-tests.rs"]
mod tests;
