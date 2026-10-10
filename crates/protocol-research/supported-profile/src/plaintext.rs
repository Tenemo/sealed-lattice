//! Arithmetic modulo the plaintext modulus and the slot transform of a
//! plaintext whose odd coefficients are zero. Such a plaintext of degree `n`
//! is `g(x^2)` for a polynomial `g` of half the degree. Slot `s` holds
//! `g(r^(5^s))` for the primitive `n`-th root of unity `r`, so the `n / 4`
//! slots are `g`'s values at the orbit of five among the odd powers of `r`.
use crate::PLAINTEXT_MODULUS;

pub fn multiply(left: u32, right: u32) -> u32 {
    (u64::from(left) * u64::from(right) % u64::from(PLAINTEXT_MODULUS)) as u32
}
pub fn power(mut value: u32, mut exponent: u32) -> u32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value);
        }
        value = multiply(value, value);
        exponent >>= 1;
    }
    result
}
/// The representative of a residue in the centered range.
pub fn centered(value: u32) -> i32 {
    if value > PLAINTEXT_MODULUS / 2 {
        value as i32 - PLAINTEXT_MODULUS as i32
    } else {
        value as i32
    }
}
/// The primitive root of unity of a power-of-two order that divides the
/// modulus less one, a power of the generator three.
fn primitive_root(order: usize) -> u32 {
    assert!(order.is_power_of_two() && ((PLAINTEXT_MODULUS - 1) as usize).is_multiple_of(order));
    power(3, (PLAINTEXT_MODULUS - 1) / order as u32)
}
/// Replaces the values with their transform at the root, whose order is
/// their number: each position's new value is the sum of every value times
/// the root raised to the product of both positions.
fn transform(values: &mut [u32], root: u32) {
    let length = values.len();
    let logarithm = length.ilog2();
    for index in 0..length {
        let reversed = index.reverse_bits() >> (usize::BITS - logarithm);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let mut width = 2;
    while width <= length {
        let step = power(root, (length / width) as u32);
        for block in values.chunks_exact_mut(width) {
            let (left, right) = block.split_at_mut(width / 2);
            let mut twiddle = 1;
            for (left, right) in left.iter_mut().zip(right) {
                let first = *left;
                let second = multiply(*right, twiddle);
                *left = (first + second) % PLAINTEXT_MODULUS;
                *right = (first + PLAINTEXT_MODULUS - second) % PLAINTEXT_MODULUS;
                twiddle = multiply(twiddle, step);
            }
        }
        width *= 2;
    }
}
/// The position of each slot, in slot order, among the values at the odd
/// powers of the root: slot `s` is the value at the `5^s`-th power.
pub fn slot_positions(degree: usize) -> impl Iterator<Item = usize> {
    let mut exponent = 1;
    (0..degree / 4).map(move |_| {
        let position = (exponent - 1) / 2;
        exponent = 5 * exponent % degree;
        position
    })
}
/// The centered coefficients of the plaintext of the degree whose slots hold
/// the values and whose other odd-power values and odd coefficients are
/// zero.
pub fn encode_slots(slots: &[u32], degree: usize) -> Vec<i32> {
    assert!(degree >= 16 && slots.len() == degree / 4);
    let mut values = vec![0; degree / 2];
    for (position, value) in slot_positions(degree).zip(slots) {
        values[position] = *value;
    }
    let inverse_root = power(primitive_root(degree), PLAINTEXT_MODULUS - 2);
    transform(&mut values, multiply(inverse_root, inverse_root));
    let mut twist = power((degree / 2) as u32, PLAINTEXT_MODULUS - 2);
    let mut coefficients = vec![0; degree];
    for (position, value) in values.into_iter().enumerate() {
        coefficients[2 * position] = centered(multiply(value, twist));
        twist = multiply(twist, inverse_root);
    }
    coefficients
}
/// The values at the odd powers of the root, in the order of those powers,
/// of the plaintext whose canonical coefficients are given. Its odd
/// coefficients take no part.
pub fn odd_power_values(coefficients: &[u32]) -> Vec<u32> {
    let degree = coefficients.len();
    assert!(degree >= 16);
    let root = primitive_root(degree);
    let mut twist = 1;
    let mut values: Vec<_> = coefficients
        .iter()
        .step_by(2)
        .map(|value| {
            let result = multiply(*value, twist);
            twist = multiply(twist, root);
            result
        })
        .collect();
    transform(&mut values, multiply(root, root));
    values
}

#[cfg(test)]
#[path = "plaintext-tests.rs"]
mod tests;
