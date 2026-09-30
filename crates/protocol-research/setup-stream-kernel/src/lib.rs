#![deny(unsafe_op_in_unsafe_fn)]

mod arithmetic;
mod jobs;
mod query;
mod setup;
use arithmetic::{Columns, MODULUS, add, multiply, subtract};
pub use setup::{
    ProverFixedTerm, ProverOperatorPlan, SetupStatementOutput, SetupStatementStream,
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
        // Precomputed powers give the same fingerprint for an extension
        // weight, including a magnitude with every limb bit set.
        let weight = [17, MODULUS - 5, 1 << 90];
        for (bytes, radix_bits) in [(&bytes[..], 96), (&bytes[..], 17), (&[0xff; 73][..], 64)] {
            assert_eq!(
                fingerprint_with(
                    bytes,
                    radix_bits,
                    &limb_powers(bytes.len(), radix_bits, weight)
                ),
                fingerprint_in(bytes, radix_bits, weight)
            );
        }
        assert_eq!(limb_value(&[0xff; 20], 1, 95), (1 << 65) - 1);
    }

    // A modulus whose limbs reach the column sums' bound of products is
    // accepted at the least and the greatest radix, and one byte more is
    // refused. At that bound, with every limb and power coordinate at its
    // largest, the fingerprint equals the sum of its reduced products.
    #[test]
    fn refuses_moduli_whose_limbs_exceed_the_column_sum_bound() {
        for (radix_bits, bytes) in [(17, 8_704), (96, 49_152)] {
            let mut modulus = vec![0xff; bytes];
            assert_eq!((8 * bytes).div_ceil(radix_bits), MAXIMUM_PRODUCTS);
            assert_eq!(check_parameters(&modulus, 2, radix_bits, ZERO), Ok(()));
            modulus.push(0);
            assert_eq!(
                check_parameters(&modulus, 2, radix_bits, ZERO),
                Err(Error::Parameters)
            );
        }
        let magnitude = vec![0xff; 8_704];
        let powers = vec![[MODULUS - 1; 3]; MAXIMUM_PRODUCTS];
        let mut expected = ZERO;
        for (limb, power) in powers.iter().enumerate() {
            let value = limb_value(&magnitude, limb, 17);
            assert_eq!(value, (1 << 17) - 1);
            for (sum, coordinate) in expected.iter_mut().zip(power) {
                *sum = add(*sum, multiply(value, *coordinate));
            }
        }
        assert_eq!(fingerprint_with(&magnitude, 17, &powers), expected);
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

    #[test]
    fn record_runs_and_their_jobs_match_one_stream() {
        use supported_profile::{DEGREE, FHE_LIMB_BITS, Family, Profile};
        // The widest full-degree records span several runs, and parts of
        // 1,000 bytes split them.
        let modulus = Profile::all()
            .map(|profile| profile.family_modulus(Family::Fhe))
            .max_by_key(Vec::len)
            .unwrap();
        let (width, alpha) = (modulus.len() + 1, [17, 37, 91]);
        let half = half_modulus(&modulus);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut bytes = Vec::with_capacity(DEGREE * width);
        for index in 0..DEGREE {
            let mut record = vec![0; width];
            if index < 2 {
                // The largest magnitude of either sign.
                record[0] = index as u8;
                record[1..].copy_from_slice(&half);
            } else {
                for byte in &mut record[1..width - 2] {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                record[0] = u8::from(state >> 40 & 1 == 1);
            }
            bytes.extend(record);
        }
        let stream = || {
            let mut stream = PolynomialStream::new(&modulus, DEGREE, FHE_LIMB_BITS, alpha).unwrap();
            for part in bytes.chunks(CHUNK_LIMIT) {
                stream.push(part).unwrap();
            }
            stream
        };
        let indices = [0, 5, 70_000, 262_143];
        let expected = query::evaluate_in(stream().adjoint().unwrap(), &indices, DEGREE).unwrap();
        let (mut total, mut value, mut fingerprints, mut runs) = (ZERO, ZERO, Vec::new(), 0);
        let mut records = PolynomialRecords::new(&modulus, DEGREE, FHE_LIMB_BITS, alpha).unwrap();
        for part in bytes.chunks(1_000) {
            records
                .push(part, |position, run, last| {
                    assert_eq!(last, position + run.len() / width == DEGREE);
                    for retain in [true, false] {
                        let output = jobs::fingerprints_job(
                            width,
                            FHE_LIMB_BITS,
                            DEGREE,
                            position,
                            retain,
                            alpha,
                            run,
                        )
                        .wait();
                        let (sum, retained) = jobs::split_fingerprints(&output);
                        if retain {
                            total = plus(total, sum);
                            fingerprints.extend_from_slice(retained);
                        } else {
                            assert!(retained.is_empty());
                            value = plus(value, sum);
                        }
                    }
                    runs += 1;
                    Ok(())
                })
                .unwrap();
        }
        assert!(runs > 1 && records.remaining() == 0);
        assert_eq!(value, stream().finish_value().unwrap());
        assert_eq!(total, value);
        let adjoint = |total| {
            jobs::decode_adjoint(
                &jobs::adjoint_job(&fingerprints, total, alpha, &indices, DEGREE)
                    .unwrap()
                    .wait(),
            )
        };
        assert_eq!(adjoint(total), Ok(expected));
        // Fingerprints whose weighted sum is not the total never close.
        assert_eq!(adjoint(plus(total, ONE)), Err(Error::Arithmetic));
        // A run refuses a magnitude beyond half the modulus, a negative zero
        // and a sign byte beyond one.
        for (offset, value) in [(width - 1, half[half.len() - 1] + 1), (0, 1), (0, 2)] {
            let mut changed = bytes[..CHUNK_LIMIT].to_vec();
            changed[2 * width..3 * width].fill(0);
            changed[2 * width + offset] = value;
            let mut records =
                PolynomialRecords::new(&modulus, DEGREE, FHE_LIMB_BITS, alpha).unwrap();
            assert_eq!(
                records.push(&changed, |_, _, _| Ok(())),
                Err(Error::Encoding)
            );
            assert_eq!(
                records.push(&bytes[..width], |_, _, _| Ok(())),
                Err(Error::Length)
            );
        }
    }
}
