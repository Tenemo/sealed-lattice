#![deny(unsafe_op_in_unsafe_fn)]

pub mod arithmetic;
mod jobs;
mod query;
mod setup;
use arithmetic::{Columns, MODULUS, add, multiply, subtract};
pub use setup::{
    ProverFixedTerm, ProverOperatorPlan, SetupStatementStream, StatementOutput,
    prover_operator_plan, setup_polynomial_stream,
};

pub use jobs::{JOBS, evaluate_public_columns};
pub type Element = [u128; 3];
const ZERO: Element = [0, 0, 0];
const ONE: Element = [1, 0, 0];
pub const CHUNK_LIMIT: usize = 1 << 20;
// The most products one column sum of the arithmetic holds.
const MAXIMUM_PRODUCTS: usize = 4_096;
fn plus(left: Element, right: Element) -> Element {
    std::array::from_fn(|index| add(left[index], right[index]))
}
fn minus(left: Element, right: Element) -> Element {
    std::array::from_fn(|index| subtract(left[index], right[index]))
}
fn times(left: Element, right: Element) -> Element {
    arithmetic::multiply_extension(left, right)
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
// The powers of a limb weight, one for each limb of a magnitude of the given
// byte length.
fn limb_powers(bytes: usize, radix_bits: usize, weight: Element) -> Vec<Element> {
    let mut power = ONE;
    (0..(8 * bytes).div_ceil(radix_bits))
        .map(|_| {
            let current = power;
            power = times(power, weight);
            current
        })
        .collect()
}
// Sum of the limbs of a little-endian magnitude weighted by the powers of its
// limb weight, each coordinate reduced once.
fn fingerprint_with(bytes: &[u8], radix_bits: usize, powers: &[Element]) -> Element {
    let mut sums = [Columns::ZERO; 3];
    for (limb, power) in powers.iter().enumerate() {
        let value = limb_value(bytes, limb, radix_bits);
        for (sum, coordinate) in sums.iter_mut().zip(power) {
            sum.add_product(value, *coordinate);
        }
    }
    sums.map(Columns::reduce)
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
// The fingerprint of a canonical coefficient record: its magnitude's limbs
// weighted by the powers, negated for a negative sign.
fn record_fingerprint(record: &[u8], radix_bits: usize, powers: &[Element]) -> Element {
    let result = fingerprint_with(&record[1..], radix_bits, powers);
    if record[0] == 1 {
        minus(ZERO, result)
    } else {
        result
    }
}
// Half an odd little-endian modulus, rounded down, in its byte length.
fn half_modulus(modulus: &[u8]) -> Vec<u8> {
    (0..modulus.len())
        .map(|index| {
            (modulus[index] >> 1) | ((modulus.get(index + 1).copied().unwrap_or(0) & 1) << 7)
        })
        .collect()
}
// Whether a coefficient record is canonical: a sign byte of zero or one, a
// magnitude at most half the modulus, and no negative zero.
fn canonical(record: &[u8], half_modulus: &[u8]) -> bool {
    let magnitude = &record[1..];
    record[0] <= 1
        && magnitude
            .iter()
            .rev()
            .cmp(half_modulus.iter().rev())
            .is_le()
        && !(record[0] == 1 && magnitude.iter().all(|byte| *byte == 0))
}
// The refusals of a polynomial's parameters. A coefficient's fingerprint
// sums one product for each limb of the modulus's length, within the
// column sums' bound.
fn check_parameters(
    modulus: &[u8],
    degree: usize,
    radix_bits: usize,
    alpha: Element,
) -> Result<(), Error> {
    if !degree.is_power_of_two()
        || !(2..=65_536).contains(&degree)
        || modulus.is_empty()
        || modulus[0] & 1 == 0
        || !(17..=96).contains(&radix_bits)
        || (8 * modulus.len()).div_ceil(radix_bits) > MAXIMUM_PRODUCTS
        || alpha.iter().any(|value| *value >= MODULUS)
    {
        return Err(Error::Parameters);
    }
    Ok(())
}
// The adjoint of a polynomial from its coefficients' fingerprints and their
// sum weighted by the powers of alpha, whose degree-th power is the limb
// weight.
fn adjoint_of(
    mut coefficients: Vec<Element>,
    total: Element,
    alpha: Element,
    limb_weight: Element,
) -> Result<Vec<Element>, Error> {
    // Reverse first so each original fingerprint can be overwritten after
    // its only remaining use; a second full-degree vector is unnecessary.
    coefficients.reverse();
    let mut value = total;
    let wrap = plus(limb_weight, ONE);
    for coefficient in &mut coefficients {
        let next = minus(times(alpha, value), times(wrap, *coefficient));
        *coefficient = value;
        value = next;
    }
    if value != minus(ZERO, total) {
        return Err(Error::Arithmetic);
    }
    Ok(coefficients)
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
    // The powers of the limb weight, one for each limb of a magnitude.
    limb_powers: Vec<Element>,
    position_weight: Element,
    total: Element,
    coefficients: Vec<Element>,
    record: Vec<u8>,
    record_length: usize,
    consumed: usize,
    failed: bool,
}

impl PolynomialStream {
    pub fn new(
        modulus: &[u8],
        degree: usize,
        radix_bits: usize,
        alpha: Element,
    ) -> Result<Self, Error> {
        check_parameters(modulus, degree, radix_bits, alpha)?;
        let half_modulus = half_modulus(modulus);
        let limb_weight = power(alpha, degree);
        Ok(Self {
            degree,
            width: modulus.len() + 1,
            radix_bits,
            half_modulus,
            alpha,
            limb_weight,
            limb_powers: limb_powers(modulus.len(), radix_bits, limb_weight),
            position_weight: ONE,
            total: ZERO,
            coefficients: Vec::with_capacity(degree),
            record: vec![0; modulus.len() + 1],
            record_length: 0,
            consumed: 0,
            failed: false,
        })
    }

    fn coefficient(&self) -> Result<Element, Error> {
        if !canonical(&self.record, &self.half_modulus) {
            return Err(Error::Encoding);
        }
        Ok(record_fingerprint(
            &self.record,
            self.radix_bits,
            &self.limb_powers,
        ))
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
                self.coefficients.push(coefficient);
                self.record_length = 0;
            }
        }
        Ok(())
    }

    fn complete(&self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Encoding);
        }
        if self.consumed != self.degree * self.width
            || self.record_length != 0
            || self.coefficients.len() != self.degree
        {
            return Err(Error::Incomplete);
        }
        Ok(())
    }

    pub fn finish_value(self) -> Result<Element, Error> {
        self.complete()?;
        Ok(self.total)
    }

    pub fn adjoint(self) -> Result<Vec<Element>, Error> {
        self.complete()?;
        adjoint_of(self.coefficients, self.total, self.alpha, self.limb_weight)
    }
}

/// A polynomial's coefficient records, checked canonical and passed on in
/// runs of whole records that each fit one chunk.
pub(crate) struct PolynomialRecords {
    width: usize,
    half_modulus: Vec<u8>,
    degree: usize,
    // The records of each run but the last.
    run: usize,
    // The records passed on.
    taken: usize,
    buffer: Vec<u8>,
}
impl PolynomialRecords {
    pub(crate) fn new(
        modulus: &[u8],
        degree: usize,
        radix_bits: usize,
        alpha: Element,
    ) -> Result<Self, Error> {
        check_parameters(modulus, degree, radix_bits, alpha)?;
        let width = modulus.len() + 1;
        let run = (CHUNK_LIMIT / width).clamp(1, degree);
        Ok(Self {
            width,
            half_modulus: half_modulus(modulus),
            degree,
            run,
            taken: 0,
            buffer: Vec::with_capacity(run * width),
        })
    }
    pub(crate) fn width(&self) -> usize {
        self.width
    }
    pub(crate) fn remaining(&self) -> usize {
        (self.degree - self.taken) * self.width - self.buffer.len()
    }
    /// Keeps bytes that fit the polynomial and passes on each run they
    /// complete: the position of its first record, its records, and whether
    /// it is the last. A refused run stays whole in the buffer, so every
    /// later push is refused as well.
    pub(crate) fn push(
        &mut self,
        mut bytes: &[u8],
        mut take: impl FnMut(usize, &[u8], bool) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let whole = self.run.min(self.degree - self.taken) * self.width;
        if bytes.len() > self.remaining() || (whole > 0 && self.buffer.len() == whole) {
            return Err(Error::Length);
        }
        while !bytes.is_empty() {
            let records = self.run.min(self.degree - self.taken);
            let length = bytes.len().min(records * self.width - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..length]);
            bytes = &bytes[length..];
            if self.buffer.len() == records * self.width {
                if !self
                    .buffer
                    .chunks_exact(self.width)
                    .all(|record| canonical(record, &self.half_modulus))
                {
                    return Err(Error::Encoding);
                }
                take(
                    self.taken,
                    &self.buffer,
                    self.taken + records == self.degree,
                )?;
                self.taken += records;
                self.buffer.clear();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "lib-tests.rs"]
mod tests;
