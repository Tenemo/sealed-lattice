use super::root;
use statement_stream::arithmetic::{MODULUS, add, multiply, power, subtract};
use std::sync::OnceLock;
use supported_profile::relation::SYSTEMATIC;

/// The lookup polynomial's values on the proof domain, which every verifier
/// of this instance reads, computed once.
pub(super) fn on_proof_domain() -> &'static [u128] {
    static VALUES: OnceLock<Vec<u128>> = OnceLock::new();
    VALUES.get_or_init(|| evaluate_on_proof_domain(&coefficients()))
}

/// The coefficients of the lookup polynomial, which takes the systematic
/// subgroup's element of each index to that index: (H - 1) / 2 at degree
/// zero and 1 / (w^-k - 1) at each degree k, for the subgroup's root w.
fn coefficients() -> Vec<u128> {
    let inverse_root = power(root(SYSTEMATIC), MODULUS - 2);
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

// The polynomial's values on the coset of the shift seven by the subgroup
// of four times its length, in the order of the subgroup root's powers.
fn evaluate_on_proof_domain(coefficients: &[u128]) -> Vec<u128> {
    let mut values = vec![0; 4 * coefficients.len()];
    let mut twist = 1;
    for (value, coefficient) in values.iter_mut().zip(coefficients) {
        *value = multiply(*coefficient, twist);
        twist = multiply(twist, 7);
    }
    transform(&mut values);
    values
}

// An in-place radix-2 transform of a power-of-two length: the coefficients
// become the polynomial's values at the powers of the length's root, in
// order. The verifier computes it without the prover's transform.
fn transform(values: &mut [u128]) {
    assert!(values.len().is_power_of_two() && values.len() >= 2);
    let bits = values.len().ilog2();
    for index in 0..values.len() {
        let reversed = index.reverse_bits() >> (usize::BITS - bits);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let mut width = 2;
    while width <= values.len() {
        let step = root(width);
        let mut twiddle = 1;
        let twiddles: Vec<u128> = (0..width / 2)
            .map(|_| {
                let current = twiddle;
                twiddle = multiply(twiddle, step);
                current
            })
            .collect();
        for block in values.chunks_exact_mut(width) {
            let (lower, upper) = block.split_at_mut(width / 2);
            for ((lower, upper), twiddle) in lower.iter_mut().zip(upper).zip(&twiddles) {
                let product = multiply(*upper, *twiddle);
                (*lower, *upper) = (add(*lower, product), subtract(*lower, product));
            }
        }
        width *= 2;
    }
}

#[cfg(test)]
#[path = "lookup-table-tests.rs"]
mod tests;
