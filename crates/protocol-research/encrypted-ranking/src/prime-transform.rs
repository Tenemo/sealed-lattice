//! Arithmetic modulo one transform prime and its negacyclic transform.
//! A transform prime is a Proth prime `odd * 2^32 + 1` below 2^62, so a
//! lazy result below four times the prime fits one word. Its Proth
//! certificate with witness three fixes the transform's root of unity.

use super::word_arithmetic::widening_multiply;
use std::ops::Deref;

/// The high word of the product of two words. On WebAssembly it is formed
/// from four 32-bit partial products, since LLVM would otherwise recognize
/// the high word and call the library routine for a 128-bit product.
#[inline(always)]
fn high_product(left: u64, right: u64) -> u64 {
    if cfg!(target_arch = "wasm32") {
        partial_high_product(left, right)
    } else {
        widening_multiply(left, right).1
    }
}
/// The high word of the product of two words from four 32-bit partial
/// products, with one operand's high half hidden from LLVM so that it keeps
/// them. Every target compiles it so that native tests check the
/// WebAssembly path.
#[inline(always)]
fn partial_high_product(left: u64, right: u64) -> u64 {
    let (left_low, left_high) = (left & 0xffff_ffff, std::hint::black_box(left >> 32));
    let (right_low, right_high) = (right & 0xffff_ffff, right >> 32);
    let low = left_low * right_low;
    let first = left_high.wrapping_mul(right_low);
    let second = left_low * right_high;
    let middle = (low >> 32)
        .wrapping_add(first & 0xffff_ffff)
        .wrapping_add(second & 0xffff_ffff);
    left_high
        .wrapping_mul(right_high)
        .wrapping_add(first >> 32)
        .wrapping_add(second >> 32)
        .wrapping_add(middle >> 32)
}

/// The value below twice the bound reduced below the bound, without a
/// branch.
#[inline(always)]
fn reduce_once(value: u64, bound: u64) -> u64 {
    let reduced = value.wrapping_sub(bound);
    let keep = 0u64.wrapping_sub(u64::from(value < bound));
    reduced ^ ((value ^ reduced) & keep)
}

/// Arithmetic modulo one transform prime. Products reduce with the Barrett
/// reciprocal floor(2^128 / p); a factor used repeatedly multiplies with
/// its Shoup quotient floor(factor 2^64 / p).
#[derive(Clone)]
pub(super) struct PrimeModulus {
    prime: u64,
    reciprocal_low: u64,
    reciprocal_high: u64,
}

impl Deref for PrimeModulus {
    type Target = u64;

    fn deref(&self) -> &u64 {
        &self.prime
    }
}

impl PrimeModulus {
    pub(super) fn new(prime: u64) -> Self {
        assert!(
            prime > 2 && prime % 2 == 1 && prime >> 62 == 0,
            "Transform prime"
        );
        // An odd prime does not divide 2^128, so floor(2^128 / p) equals
        // floor((2^128 - 1) / p).
        let reciprocal = u128::MAX / u128::from(prime);
        Self {
            prime,
            reciprocal_low: reciprocal as u64,
            reciprocal_high: (reciprocal >> 64) as u64,
        }
    }

    /// The product of two residues.
    pub(super) fn multiply(&self, left: u64, right: u64) -> u64 {
        debug_assert!(left < self.prime && right < self.prime);
        let (low, high) = widening_multiply(left, right);
        reduce_once(self.lazy_reduce(low, high), self.prime)
    }

    /// The residue of a double word.
    pub(super) fn reduce_wide(&self, value: u128) -> u64 {
        reduce_once(
            self.lazy_reduce(value as u64, (value >> 64) as u64),
            self.prime,
        )
    }

    /// A value of two words reduced below twice the prime. The quotient
    /// estimate is the high double word of the value times the reciprocal,
    /// whose lowest partial product contributes only its carry; it is at
    /// most one below the exact quotient.
    #[inline(always)]
    fn lazy_reduce(&self, low: u64, high: u64) -> u64 {
        let lowest = high_product(low, self.reciprocal_low);
        let (high_low, high_high) = widening_multiply(high, self.reciprocal_low);
        let (low_high, low_high_carry) = widening_multiply(low, self.reciprocal_high);
        let (sum, first_carry) = low_high.overflowing_add(high_low);
        let (_, second_carry) = sum.overflowing_add(lowest);
        let quotient = low_high_carry
            .wrapping_add(high_high)
            .wrapping_add(u64::from(first_carry))
            .wrapping_add(u64::from(second_carry))
            .wrapping_add(high.wrapping_mul(self.reciprocal_high));
        low.wrapping_sub(quotient.wrapping_mul(self.prime))
    }

    /// The Shoup quotient of a residue, floor(factor 2^64 / p).
    pub(super) fn shoup(&self, factor: u64) -> u64 {
        debug_assert!(factor < self.prime);
        ((u128::from(factor) << 64) / u128::from(self.prime)) as u64
    }

    /// A word times a residue with its Shoup quotient, below twice the
    /// prime.
    #[inline(always)]
    pub(super) fn lazy_multiply_shoup(&self, value: u64, factor: u64, quotient: u64) -> u64 {
        debug_assert!(factor < self.prime && quotient == self.shoup(factor));
        let estimate = high_product(value, quotient);
        value
            .wrapping_mul(factor)
            .wrapping_sub(estimate.wrapping_mul(self.prime))
    }

    /// A word times a residue with its Shoup quotient.
    #[inline(always)]
    pub(super) fn multiply_shoup(&self, value: u64, factor: u64, quotient: u64) -> u64 {
        reduce_once(
            self.lazy_multiply_shoup(value, factor, quotient),
            self.prime,
        )
    }

    /// A residue raised to the exponent.
    pub(super) fn power(&self, mut base: u64, mut exponent: u64) -> u64 {
        let mut result = 1;
        while exponent > 0 {
            if exponent & 1 != 0 {
                result = self.multiply(result, base);
            }
            base = self.multiply(base, base);
            exponent >>= 1;
        }
        result
    }

    /// The inverse of a nonzero residue, by Fermat's little theorem.
    pub(super) fn inverse(&self, value: u64) -> u64 {
        let inverse = self.power(value, self.prime - 2);
        assert_eq!(self.multiply(value, inverse), 1, "Invertible residue");
        inverse
    }
}

/// The negacyclic transform of a power-of-two length n modulo one
/// transform prime. The forward transform evaluates a polynomial at the
/// odd powers of a primitive 2n-th root of unity in bit-reversed order, so
/// that pointwise products of transforms are the transforms of products
/// modulo X^n + 1. The root is three raised to (p - 1) / 2n, which the
/// prime's Proth certificate 3^((p - 1) / 2) = -1 makes primitive.
///
/// Only the forward twiddles and their Shoup quotients are kept: with ψ the
/// root, forward twiddle i is ψ^rev(i), and backward twiddle k is
/// ψ^-(rev(k) + 1), which is -ψ^rev(n - 1 - k) because ψ^n = -1. The Shoup
/// quotient of p - w is the complement of w's, since w 2^64 / p is never an
/// integer.
pub(super) struct Transform {
    prime: PrimeModulus,
    twice_prime: u64,
    twiddles: Box<[u64]>,
    twiddle_quotients: Box<[u64]>,
    inverse_length: u64,
    inverse_length_quotient: u64,
}

impl Transform {
    pub(super) fn new(prime: &PrimeModulus, length: usize) -> Self {
        assert!(length >= 2 && length.is_power_of_two(), "Transform length");
        let doubled = 2 * length as u64;
        assert_eq!(**prime % doubled, 1, "Transform prime");
        let root = prime.power(3, (**prime - 1) / doubled);
        assert_eq!(
            prime.power(root, length as u64),
            **prime - 1,
            "Proth certificate"
        );
        let shift = usize::BITS - length.trailing_zeros();
        let mut twiddles = vec![0; length].into_boxed_slice();
        let mut power = 1;
        for exponent in 0..length {
            twiddles[exponent.reverse_bits() >> shift] = power;
            power = prime.multiply(power, root);
        }
        let twiddle_quotients = twiddles
            .iter()
            .map(|twiddle| prime.shoup(*twiddle))
            .collect();
        let inverse_length = prime.inverse(length as u64);
        Self {
            prime: prime.clone(),
            twice_prime: 2 * **prime,
            twiddles,
            twiddle_quotients,
            inverse_length,
            inverse_length_quotient: prime.shoup(inverse_length),
        }
    }

    /// Transforms residues in place.
    pub(super) fn forward(&self, values: &mut [u64]) {
        assert_eq!(values.len(), self.twiddles.len());
        let mut half = values.len() >> 1;
        let mut twiddle = 1;
        while half > 0 {
            for block in values.chunks_exact_mut(2 * half) {
                let factor = self.twiddles[twiddle];
                let quotient = self.twiddle_quotients[twiddle];
                twiddle += 1;
                let (left, right) = block.split_at_mut(half);
                if half == 1 {
                    // The last level reduces its outputs, which stay below
                    // four times the prime.
                    self.butterfly(&mut left[0], &mut right[0], factor, quotient);
                    left[0] = self.reduce_quadruple(left[0]);
                    right[0] = self.reduce_quadruple(right[0]);
                } else {
                    for (left, right) in left.iter_mut().zip(right) {
                        self.butterfly(left, right, factor, quotient);
                    }
                }
            }
            half >>= 1;
        }
    }

    /// Transforms a transform's values back to residues in place.
    pub(super) fn backward(&self, values: &mut [u64]) {
        let length = self.twiddles.len();
        assert_eq!(values.len(), length);
        let mut half = 1;
        let mut twiddle = 0;
        while half < length {
            for block in values.chunks_exact_mut(2 * half) {
                let factor = *self.prime - self.twiddles[length - 1 - twiddle];
                let quotient = !self.twiddle_quotients[length - 1 - twiddle];
                twiddle += 1;
                let (left, right) = block.split_at_mut(half);
                for (left, right) in left.iter_mut().zip(right) {
                    self.inverse_butterfly(left, right, factor, quotient);
                }
            }
            half <<= 1;
        }
        for value in values {
            *value = self.prime.multiply_shoup(
                *value,
                self.inverse_length,
                self.inverse_length_quotient,
            );
        }
    }

    /// A value below four times the prime reduced below the prime.
    #[inline(always)]
    fn reduce_quadruple(&self, value: u64) -> u64 {
        reduce_once(reduce_once(value, self.twice_prime), *self.prime)
    }

    /// The Cooley-Tukey butterfly on values below four times the prime.
    #[inline(always)]
    fn butterfly(&self, left: &mut u64, right: &mut u64, factor: u64, quotient: u64) {
        *left = reduce_once(*left, self.twice_prime);
        let product = self.prime.lazy_multiply_shoup(*right, factor, quotient);
        *right = *left + self.twice_prime - product;
        *left += product;
    }

    /// The Gentleman-Sande butterfly on values below twice the prime.
    #[inline(always)]
    fn inverse_butterfly(&self, left: &mut u64, right: &mut u64, factor: u64, quotient: u64) {
        let sum = *left + *right;
        let difference = self.twice_prime + *left - *right;
        *left = reduce_once(sum, self.twice_prime);
        *right = self.prime.lazy_multiply_shoup(difference, factor, quotient);
    }
}

#[cfg(test)]
#[path = "prime-transform-tests.rs"]
mod tests;
