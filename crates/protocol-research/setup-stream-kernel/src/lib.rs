#![deny(unsafe_op_in_unsafe_fn)]

mod arithmetic;
mod query;
mod setup;
use arithmetic::{MODULUS, add, multiply, subtract};
pub use setup::{
    ProverFixedTerm, ProverOperatorPlan, SetupStatementOutput, SetupStatementStream,
    prover_operator_plan, setup_polynomial_stream,
};

pub type Element = [u128; 3];
const ZERO: Element = [0, 0, 0];
const ONE: Element = [1, 0, 0];
pub const CHUNK_LIMIT: usize = 1 << 20;
pub fn evaluate_public_values(
    values: Vec<Element>,
    indices: &[u32],
) -> Result<Vec<Element>, Error> {
    query::evaluate(values, indices)
}
fn plus(left: Element, right: Element) -> Element {
    std::array::from_fn(|index| add(left[index], right[index]))
}
fn minus(left: Element, right: Element) -> Element {
    std::array::from_fn(|index| subtract(left[index], right[index]))
}
fn times(left: Element, right: Element) -> Element {
    let mut result = ZERO;
    for (row, first) in left.iter().enumerate() {
        for (column, second) in right.iter().enumerate() {
            let mut product = multiply(*first, *second);
            if row + column >= 3 {
                product = add(product, product);
            }
            let index = (row + column) % 3;
            result[index] = add(result[index], product);
        }
    }
    result
}
// The limb of `radix_bits` bits at `limb` of a little-endian magnitude.
fn limb_value(bytes: &[u8], limb: usize, radix_bits: usize) -> u128 {
    let start = limb * radix_bits;
    let first = start / 8;
    let mut word = [0u8; 16];
    let available = bytes.len().saturating_sub(first).min(13);
    word[..available].copy_from_slice(&bytes[first..first + available]);
    (u128::from_le_bytes(word) >> (start % 8)) & ((1u128 << radix_bits) - 1)
}
// Sum of the limbs of a little-endian magnitude weighted by powers of weight.
fn fingerprint_in(bytes: &[u8], radix_bits: usize, weight: Element) -> Element {
    let mut result = ZERO;
    for limb in (0..(8 * bytes.len()).div_ceil(radix_bits)).rev() {
        result = plus(
            times(result, weight),
            [limb_value(bytes, limb, radix_bits), 0, 0],
        );
    }
    result
}
fn power(mut value: Element, mut exponent: usize) -> Element {
    if value[1] == 0 && value[2] == 0 {
        return [arithmetic::power(value[0], exponent as u128), 0, 0];
    }
    let mut result = ONE;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = times(result, value);
        }
        value = times(value, value);
        exponent >>= 1;
    }
    result
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Parameters,
    Length,
    Encoding,
    Incomplete,
    Arithmetic,
    Binding,
}

// This public-data experiment computes one full-degree affine convolution
// adjoint. It does not verify a setup proof or create voting authority.
// Each canonical coefficient is fingerprinted in limbs of radix_bits bits,
// the limbs of the equations that use it.
pub struct PolynomialStream {
    degree: usize,
    width: usize,
    radix_bits: usize,
    half_modulus: Vec<u8>,
    alpha: Element,
    limb_weight: Element,
    position_weight: Element,
    total: Element,
    coefficients: Vec<Element>,
    record: Vec<u8>,
    record_length: usize,
    consumed: usize,
    failed: bool,
    retain_coefficients: bool,
}

impl PolynomialStream {
    pub fn new(
        modulus: &[u8],
        degree: usize,
        radix_bits: usize,
        alpha: Element,
    ) -> Result<Self, Error> {
        Self::with_retention(modulus, degree, radix_bits, alpha, true)
    }

    pub(crate) fn with_retention(
        modulus: &[u8],
        degree: usize,
        radix_bits: usize,
        alpha: Element,
        retain_coefficients: bool,
    ) -> Result<Self, Error> {
        if !degree.is_power_of_two()
            || !(2..=65_536).contains(&degree)
            || modulus.is_empty()
            || modulus[0] & 1 == 0
            || !(17..=96).contains(&radix_bits)
        {
            return Err(Error::Parameters);
        }
        if alpha.iter().any(|value| *value >= MODULUS) {
            return Err(Error::Parameters);
        }
        let half_modulus = (0..modulus.len())
            .map(|index| {
                (modulus[index] >> 1) | ((modulus.get(index + 1).copied().unwrap_or(0) & 1) << 7)
            })
            .collect();
        Ok(Self {
            degree,
            width: modulus.len() + 1,
            radix_bits,
            half_modulus,
            alpha,
            limb_weight: power(alpha, degree),
            position_weight: ONE,
            total: ZERO,
            coefficients: if retain_coefficients {
                Vec::with_capacity(degree)
            } else {
                Vec::new()
            },
            record: vec![0; modulus.len() + 1],
            record_length: 0,
            consumed: 0,
            failed: false,
            retain_coefficients,
        })
    }

    fn coefficient(&self) -> Result<Element, Error> {
        let negative = self.record[0] == 1;
        let magnitude = &self.record[1..self.width];
        if self.record[0] > 1
            || magnitude
                .iter()
                .rev()
                .cmp(self.half_modulus.iter().rev())
                .is_gt()
            || (negative && magnitude.iter().all(|byte| *byte == 0))
        {
            return Err(Error::Encoding);
        }
        let result = fingerprint_in(magnitude, self.radix_bits, self.limb_weight);
        Ok(if negative {
            minus(ZERO, result)
        } else {
            result
        })
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Encoding);
        }
        if bytes.len() > CHUNK_LIMIT || bytes.len() > self.degree * self.width - self.consumed {
            self.failed = true;
            return Err(Error::Length);
        }
        self.consumed += bytes.len();
        while !bytes.is_empty() {
            let length = bytes.len().min(self.width - self.record_length);
            self.record[self.record_length..self.record_length + length]
                .copy_from_slice(&bytes[..length]);
            self.record_length += length;
            bytes = &bytes[length..];
            if self.record_length == self.width {
                let coefficient = match self.coefficient() {
                    Ok(value) => value,
                    Err(error) => {
                        self.failed = true;
                        return Err(error);
                    }
                };
                self.total = plus(self.total, times(self.position_weight, coefficient));
                self.position_weight = times(self.position_weight, self.alpha);
                if self.retain_coefficients {
                    self.coefficients.push(coefficient);
                }
                self.record_length = 0;
            }
        }
        Ok(())
    }

    pub(crate) fn remaining(&self) -> usize {
        self.degree * self.width - self.consumed
    }

    fn complete(&self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Encoding);
        }
        if self.consumed != self.degree * self.width
            || self.record_length != 0
            || (self.retain_coefficients && self.coefficients.len() != self.degree)
        {
            return Err(Error::Incomplete);
        }
        Ok(())
    }

    pub fn finish_value(self) -> Result<Element, Error> {
        self.complete()?;
        Ok(self.total)
    }

    pub(crate) fn finish_queries_in(
        self,
        indices: &[u32],
        systematic_size: usize,
    ) -> Result<Vec<Element>, Error> {
        query::validate_indices_in(indices, 4 * systematic_size)?;
        query::evaluate_in(self.adjoint()?, indices, systematic_size)
    }

    pub fn adjoint(mut self) -> Result<Vec<Element>, Error> {
        self.complete()?;
        if !self.retain_coefficients {
            return Err(Error::Parameters);
        }
        // Reverse first so each original fingerprint can be overwritten after
        // its only remaining use; a second full-degree vector is unnecessary.
        self.coefficients.reverse();
        let mut value = self.total;
        let wrap = plus(self.limb_weight, ONE);
        for coefficient in &mut self.coefficients {
            let next = minus(times(self.alpha, value), times(wrap, *coefficient));
            *coefficient = value;
            value = next;
        }
        if value != minus(ZERO, self.total) {
            return Err(Error::Arithmetic);
        }
        Ok(self.coefficients)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cubic_field_uses_the_selected_nonresidue() {
        assert_ne!(arithmetic::power(2, (MODULUS - 1) / 3), 1);
    }

    fn auxiliary_stream() -> PolynomialStream {
        PolynomialStream::new(
            supported_profile::auxiliary_modulus(),
            supported_profile::AUXILIARY_DEGREE,
            supported_profile::FHE_LIMB_BITS,
            [17, 37, 91],
        )
        .unwrap()
    }

    #[test]
    fn limb_fingerprints_follow_the_selected_radix() {
        // 2^100 + 2^95 + 5 has 96-bit limbs (2^95 + 5, 2^4) and 95-bit
        // limbs (5, 2^5 + 1).
        let mut bytes = [0u8; 20];
        bytes[0] = 5;
        bytes[11] = 0x80;
        bytes[12] = 0x10;
        let weight = [3, 0, 0];
        assert_eq!(
            fingerprint_in(&bytes, 96, weight),
            [(1 << 95) + 5 + 3 * 16, 0, 0]
        );
        assert_eq!(fingerprint_in(&bytes, 95, weight), [5 + 3 * 33, 0, 0]);
        assert_eq!(limb_value(&[0xff; 20], 1, 95), (1 << 65) - 1);
    }

    #[test]
    fn rejects_partial_records_and_forbidden_lengths_without_output() {
        let mut stream = auxiliary_stream();
        stream.push(&[0; 5]).unwrap();
        assert_eq!(stream.finish_value(), Err(Error::Incomplete));
        let mut stream = auxiliary_stream();
        assert_eq!(stream.push(&vec![0; CHUNK_LIMIT + 1]), Err(Error::Length));
        assert_eq!(stream.push(&[]), Err(Error::Encoding));
        assert_eq!(stream.finish_value(), Err(Error::Encoding));
    }
}
