use crate::parameters::*;
use num_bigint::{BigInt, Sign};
use parallel_work::ProtocolHash;
pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
use setup_stream_kernel::{CHUNK_LIMIT, PolynomialStream};
use word_proof::{
    affine::{Operator, PublicColumn, Term},
    field::{self, Element, MODULUS, ONE, ZERO},
};

use supported_profile::{
    Profile, RECIPIENT_SECRET_SUPPORT, RELEASE_DECODING_LIMB_BITS, RELEASE_LIMB_BITS, SHARE_SCALE,
};

/// Signed release variables in the order of `Profile::release_variable_bits`.
pub(crate) const KEY_QUOTIENT: usize = 0;
pub(crate) const KEY_CARRY: usize = 1;
pub(crate) const KEY_ERROR: usize = 2;
pub(crate) const SHARE: usize = 3;
pub(crate) const DECODING_ERROR: usize = 4;
pub(crate) const DECODING_QUOTIENT: usize = 5;
pub(crate) const DECODING_CARRY: usize = 6;
pub(crate) const NOISE: usize = 7;
pub(crate) const RELEASE_QUOTIENT: usize = 8;
pub(crate) const FIRST_RELEASE_CARRY: usize = 9;
/// Share-modulus polynomials fingerprint in decoding limbs and
/// release-modulus polynomials in release limbs.
const DECODING_CHUNK: usize = RELEASE_DECODING_LIMB_BITS / 8;
const RELEASE_CHUNK: usize = RELEASE_LIMB_BITS / 8;
/// The common share polynomial, the recipient key and the aggregate share
/// ciphertext's constant and linear components are share-modulus
/// polynomials; the target's linear component and the partial decryption are
/// release-modulus polynomials.
const SHARE_POLYNOMIALS: usize = 4;
const POLYNOMIALS: usize = 6;
#[derive(Debug)]
pub enum Error {
    Shape,
    Encoding,
    Binding,
    Arithmetic,
}
impl From<setup_stream_kernel::Error> for Error {
    fn from(error: setup_stream_kernel::Error) -> Self {
        use setup_stream_kernel::Error as Stream;
        match error {
            Stream::Parameters | Stream::Length | Stream::Incomplete => Self::Shape,
            Stream::Encoding => Self::Encoding,
            Stream::Binding => Self::Binding,
            Stream::Arithmetic => Self::Arithmetic,
        }
    }
}
pub fn share_modulus() -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, supported_profile::share_modulus())
}
pub fn release_modulus(profile: Profile) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &profile.release_modulus().to_bytes())
}
/// Bytes of one encoded coefficient: a sign byte and the magnitude.
pub fn share_coefficient_bytes() -> usize {
    1 + supported_profile::share_modulus().len()
}
fn coefficient_bytes(profile: Profile, index: usize) -> usize {
    if index < SHARE_POLYNOMIALS {
        share_coefficient_bytes()
    } else {
        release_coefficient_bytes(profile)
    }
}
pub struct PublicStatement {
    pub profile: Profile,
    pub header: Vec<u8>,
    pub polynomials: Vec<Vec<u8>>,
}
pub fn power(mut value: Element, mut exponent: usize) -> Element {
    let mut result = ONE;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = field::multiply(result, value);
        }
        value = field::multiply(value, value);
        exponent >>= 1;
    }
    result
}
fn signed(value: i128) -> u128 {
    if value < 0 {
        MODULUS - value.unsigned_abs()
    } else {
        value as u128
    }
}
fn fingerprint(bytes: &[u8], chunk: usize, weight: Element) -> Element {
    bytes.chunks(chunk).rev().fold(ZERO, |sum, bytes| {
        let mut word = [0; 16];
        word[..bytes.len()].copy_from_slice(bytes);
        field::add(
            field::multiply(sum, weight),
            [u128::from_le_bytes(word), 0, 0],
        )
    })
}
pub fn encode_polynomial(values: &[BigInt], width: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(values.len() * width);
    for value in values {
        let (sign, bytes) = value.to_bytes_le();
        if bytes.len() >= width {
            return Err(Error::Encoding);
        }
        output.push(u8::from(sign == Sign::Minus));
        output.extend(&bytes);
        output.resize(output.len() + width - 1 - bytes.len(), 0);
    }
    Ok(output)
}
/// The stream that fingerprints the statement's polynomial at the index:
/// share-modulus polynomials in decoding limbs and release-modulus
/// polynomials in release limbs.
fn polynomial_stream(
    profile: Profile,
    index: usize,
    alpha: Element,
) -> Result<PolynomialStream, Error> {
    if index >= POLYNOMIALS {
        return Err(Error::Shape);
    }
    let (modulus, limb_bits) = if index < SHARE_POLYNOMIALS {
        (
            supported_profile::share_modulus().to_vec(),
            RELEASE_DECODING_LIMB_BITS,
        )
    } else {
        (profile.release_modulus().to_bytes(), RELEASE_LIMB_BITS)
    };
    Ok(PolynomialStream::new(
        &modulus, SYSTEMATIC, limb_bits, alpha,
    )?)
}
/// The public polynomials whose multiples a release variable's words take:
/// the powers of alpha, or the share polynomial's adjoint.
#[derive(Clone, Copy)]
enum Basis {
    Powers,
    Share,
}
struct Builder {
    profile: Profile,
    bits: Vec<usize>,
    starts: Vec<usize>,
    words: usize,
    alpha: Element,
    omega: Element,
    // The sum of the powers of alpha, each column's weight on them and on
    // the share polynomial's adjoint, that adjoint and its sum, and the
    // weighted adjoints of the recipient key's polynomials, which the
    // positive support column adds and the negative one subtracts.
    powers_sum: Element,
    powers: Vec<Element>,
    share: Vec<Element>,
    share_adjoint: Vec<Element>,
    share_sum: Element,
    recipient: Vec<Element>,
    target: Element,
    consumed: usize,
}
impl Builder {
    fn new(profile: Profile, alpha: Element, header: &[u8]) -> Result<Self, Error> {
        release_header_position(profile, header).ok_or(Error::Shape)?;
        let (starts, words) = release_variable_starts(profile);
        let mut value = ONE;
        let mut powers_sum = ZERO;
        for _ in 0..SYSTEMATIC {
            powers_sum = field::add(powers_sum, value);
            value = field::multiply(value, alpha);
        }
        Ok(Self {
            profile,
            bits: profile.release_variable_bits(),
            starts,
            words,
            alpha,
            omega: power(alpha, SYSTEMATIC),
            powers_sum,
            powers: vec![ZERO; words + 2],
            share: vec![ZERO; words + 2],
            share_adjoint: Vec::new(),
            share_sum: ZERO,
            recipient: vec![ZERO; SYSTEMATIC],
            target: ZERO,
            consumed: 0,
        })
    }
    /// Adds the weighted basis to the words, each word's multiple 65,536
    /// times the one before, and the sum of the words' rows times the bias.
    fn words(
        &mut self,
        first: usize,
        count: usize,
        bias_bits: Option<usize>,
        basis: Basis,
        weight: Element,
    ) {
        assert!(first + count <= self.words);
        let (weights, sum) = match basis {
            Basis::Powers => (&mut self.powers, self.powers_sum),
            Basis::Share => (&mut self.share, self.share_sum),
        };
        let mut scale = 1u128;
        for column in &mut weights[first..first + count] {
            *column = field::add(*column, field::scale(weight, scale));
            scale = field::base::multiply(scale, 65536);
        }
        if let Some(bits) = bias_bits {
            let bias = field::base::power(2, (bits - 1) as u128);
            self.target = field::add(
                self.target,
                field::scale(field::multiply(sum, weight), bias),
            );
        }
    }
    /// Adds the words of bits `first..first + width` of a signed variable at
    /// the weighted basis. A part holding the variable's top bits, or a
    /// centered lower part, is offset by half its range.
    fn part(
        &mut self,
        variable: usize,
        first: usize,
        width: usize,
        centered: bool,
        basis: Basis,
        weight: Element,
    ) {
        assert!(first.is_multiple_of(16) && first + width <= self.bits[variable]);
        self.words(
            self.starts[variable] + first / 16,
            width.div_ceil(16),
            centered.then_some(width),
            basis,
            weight,
        );
    }
    fn variable(&mut self, variable: usize, weight: Element) {
        self.part(
            variable,
            0,
            self.bits[variable],
            true,
            Basis::Powers,
            weight,
        );
    }
    /// Adds each release limb of a signed variable at the basis times its
    /// limb weight. Every limb but the top one is an unsigned digit.
    fn release_limbs(&mut self, variable: usize, basis: Basis, weight: impl Fn(usize) -> Element) {
        let bits = self.bits[variable];
        let limbs = bits.div_ceil(RELEASE_LIMB_BITS);
        for limb in 0..limbs {
            let first = limb * RELEASE_LIMB_BITS;
            let top = limb + 1 == limbs;
            let width = if top { bits - first } else { RELEASE_LIMB_BITS };
            self.part(variable, first, width, top, basis, weight(limb));
        }
    }
    fn polynomial(&mut self, index: usize, polynomial: PolynomialStream) -> Result<(), Error> {
        if index != self.consumed {
            return Err(Error::Shape);
        }
        self.consumed += 1;
        match index {
            0 | 3 => {
                let weight = if index == 0 {
                    ONE
                } else {
                    power(self.alpha, 2 * SYSTEMATIC)
                };
                for (target, value) in self.recipient.iter_mut().zip(polynomial.adjoint()?) {
                    *target = field::add(*target, field::multiply(weight, value));
                }
            }
            1 => self.target = field::subtract(self.target, polynomial.finish_value()?),
            2 => {
                self.target = field::subtract(
                    self.target,
                    field::multiply(
                        power(self.alpha, 2 * SYSTEMATIC),
                        polynomial.finish_value()?,
                    ),
                )
            }
            4 => {
                let adjoint = polynomial.adjoint()?;
                self.share_sum = adjoint.iter().copied().fold(ZERO, field::add);
                self.share_adjoint = adjoint;
                let base = power(self.alpha, 4 * SYSTEMATIC);
                let (omega, clearing) = (self.omega, self.profile.clearing_factor() as u128);
                self.release_limbs(SHARE, Basis::Share, |limb| {
                    field::scale(field::multiply(base, power(omega, limb)), clearing)
                });
            }
            5 => {
                self.target = field::add(
                    self.target,
                    field::multiply(
                        power(self.alpha, 4 * SYSTEMATIC),
                        polynomial.finish_value()?,
                    ),
                )
            }
            _ => return Err(Error::Shape),
        }
        Ok(())
    }
    fn finish(mut self) -> Result<Operator, Error> {
        if self.consumed != POLYNOMIALS {
            return Err(Error::Shape);
        }
        let omega = self.omega;
        let share_modulus = fingerprint(supported_profile::share_modulus(), DECODING_CHUNK, omega);
        let release_modulus = fingerprint(
            &self.profile.release_modulus().to_bytes(),
            RELEASE_CHUNK,
            omega,
        );
        let decoding_carry = field::subtract(omega, [1u128 << RELEASE_DECODING_LIMB_BITS, 0, 0]);
        // The recipient key equation.
        self.variable(KEY_QUOTIENT, field::subtract(ZERO, share_modulus));
        self.variable(KEY_CARRY, decoding_carry);
        self.variable(KEY_ERROR, field::subtract(ZERO, ONE));
        // The aggregate share's decoding equation, with the share scale times
        // the centered lower decoding limb and the signed upper part.
        let decryption = power(self.alpha, 2 * SYSTEMATIC);
        self.variable(DECODING_ERROR, field::subtract(ZERO, decryption));
        self.variable(
            DECODING_QUOTIENT,
            field::subtract(ZERO, field::multiply(decryption, share_modulus)),
        );
        self.variable(DECODING_CARRY, field::multiply(decryption, decoding_carry));
        let share_bits = self.bits[SHARE];
        for (limb, first, width) in [
            (0, 0, RELEASE_DECODING_LIMB_BITS),
            (
                1,
                RELEASE_DECODING_LIMB_BITS,
                share_bits - RELEASE_DECODING_LIMB_BITS,
            ),
        ] {
            let weight = field::scale(
                field::multiply(decryption, power(omega, limb)),
                signed(-i128::from(SHARE_SCALE)),
            );
            self.part(SHARE, first, width, true, Basis::Powers, weight);
        }
        let offset = BigInt::from(SHARE_SCALE) << (RELEASE_DECODING_LIMB_BITS - 1);
        let offset = fingerprint(&offset.to_bytes_le().1, DECODING_CHUNK, omega);
        self.target = field::add(
            self.target,
            field::multiply(field::multiply(decryption, offset), self.powers_sum),
        );
        // The partial decryption equation in release limbs.
        let release = power(self.alpha, 4 * SYSTEMATIC);
        let clearing = self.profile.clearing_factor() as u128;
        self.release_limbs(NOISE, Basis::Powers, |limb| {
            field::scale(field::multiply(release, power(omega, limb)), clearing)
        });
        self.release_limbs(RELEASE_QUOTIENT, Basis::Powers, |limb| {
            field::subtract(
                ZERO,
                field::multiply(
                    field::multiply(release, power(omega, limb)),
                    release_modulus,
                ),
            )
        });
        let release_carry = field::subtract(omega, [1u128 << RELEASE_LIMB_BITS, 0, 0]);
        let output_limbs = self.profile.release_output_limbs();
        for limb in 0..output_limbs - 1 {
            self.variable(
                FIRST_RELEASE_CARRY + limb,
                field::multiply(field::multiply(release, power(omega, limb)), release_carry),
            );
        }
        // Each half of the recipient secret's support follows every limb row.
        let rows = (4 + output_limbs) * SYSTEMATIC;
        let mut support = Vec::with_capacity(2);
        for sign in 0..2 {
            let weight = power(self.alpha, rows + sign);
            support.push((self.words + sign, weight));
            self.target = field::add(
                self.target,
                field::scale(weight, (RECIPIENT_SECRET_SUPPORT / 2) as u128),
            );
        }
        let nonzero = |weights: Vec<Element>| -> Vec<(usize, Element)> {
            weights
                .into_iter()
                .enumerate()
                .filter(|(_, weight)| *weight != ZERO)
                .collect()
        };
        Ok(Operator {
            alpha: self.alpha,
            terms: vec![
                Term {
                    public: PublicColumn::Powers(SYSTEMATIC),
                    weights: nonzero(std::mem::take(&mut self.powers)),
                },
                Term {
                    public: PublicColumn::Values(std::mem::take(&mut self.share_adjoint)),
                    weights: nonzero(std::mem::take(&mut self.share)),
                },
                Term {
                    public: PublicColumn::Values(std::mem::take(&mut self.recipient)),
                    weights: vec![
                        (self.words, ONE),
                        (self.words + 1, field::subtract(ZERO, ONE)),
                    ],
                },
                Term {
                    public: PublicColumn::Ones(SYSTEMATIC),
                    weights: support,
                },
            ],
            target: self.target,
            lookup_weight: power(self.alpha, rows + 2),
        })
    }
}
impl PublicStatement {
    pub fn digest(&self) -> [u8; 64] {
        let mut hash = ProtocolHash::new();
        hash.update(&self.header);
        for polynomial in &self.polynomials {
            hash.update(polynomial);
        }
        hash.finalize()
    }
    pub fn operator(&self, alpha: Element) -> Result<Operator, Error> {
        let mut builder = Builder::new(self.profile, alpha, &self.header)?;
        if self.polynomials.len() != POLYNOMIALS {
            return Err(Error::Shape);
        }
        for (index, bytes) in self.polynomials.iter().enumerate() {
            let mut parser = polynomial_stream(self.profile, index, alpha)?;
            for chunk in bytes.chunks(CHUNK_LIMIT) {
                parser.push(chunk)?;
            }
            builder.polynomial(index, parser)?;
        }
        builder.finish()
    }
}
#[cfg(test)]
#[path = "reference/dense-operator.rs"]
pub(crate) mod dense_operator;
pub struct StatementStream {
    profile: Profile,
    statement_bytes: usize,
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    hash: ProtocolHash,
    header: Vec<u8>,
    builder: Option<Builder>,
    parser: Option<PolynomialStream>,
    index: usize,
    polynomial_bytes: usize,
    consumed: usize,
    failed: bool,
}
impl StatementStream {
    pub fn new(
        profile: Profile,
        expected: [u8; 64],
        alpha: Element,
        queries: &[u32],
    ) -> Result<Self, Error> {
        if alpha.iter().any(|value| *value >= MODULUS)
            || queries.is_empty()
            || queries.len() > 2 * QUERY_COUNT
            || queries.iter().any(|value| *value as usize >= DOMAIN)
            || queries.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            profile,
            statement_bytes: release_relation(profile).statement_bytes(),
            expected,
            alpha,
            queries: queries.to_vec(),
            hash: ProtocolHash::new(),
            header: Vec::new(),
            builder: None,
            parser: None,
            index: 0,
            polynomial_bytes: 0,
            consumed: 0,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Binding);
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > 1048576 || bytes.len() > self.statement_bytes - self.consumed {
            return Err(Error::Shape);
        }
        self.consumed += bytes.len();
        self.hash.update(bytes);
        if self.header.len() < RELEASE_HEADER_BYTES {
            let count = bytes.len().min(RELEASE_HEADER_BYTES - self.header.len());
            self.header.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.header.len() == RELEASE_HEADER_BYTES {
                self.builder = Some(Builder::new(self.profile, self.alpha, &self.header)?);
            }
        }
        while !bytes.is_empty() {
            if self.index >= POLYNOMIALS {
                return Err(Error::Shape);
            }
            let size = SYSTEMATIC * coefficient_bytes(self.profile, self.index);
            if self.parser.is_none() {
                self.parser = Some(polynomial_stream(self.profile, self.index, self.alpha)?);
            }
            let count = bytes.len().min(size - self.polynomial_bytes);
            self.parser.as_mut().unwrap().push(&bytes[..count])?;
            self.polynomial_bytes += count;
            bytes = &bytes[count..];
            if self.polynomial_bytes == size {
                self.builder
                    .as_mut()
                    .ok_or(Error::Shape)?
                    .polynomial(self.index, self.parser.take().unwrap())?;
                self.index += 1;
                self.polynomial_bytes = 0;
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<StatementOutput, Error> {
        if self.failed
            || self.consumed != self.statement_bytes
            || self.index != POLYNOMIALS
            || self.parser.is_some()
            || self.hash.finalize() != self.expected
        {
            return Err(Error::Binding);
        }
        let operator = self.builder.ok_or(Error::Shape)?.finish()?;
        let (target, lookup_weight) = (operator.target, operator.lookup_weight);
        let coefficients = operator
            .at_queries(release_relation(self.profile).columns(), &self.queries)
            .map_err(|_| Error::Arithmetic)?;
        Ok(StatementOutput {
            statement_digest: self.expected,
            target,
            lookup_weight,
            coefficients,
        })
    }
}

#[cfg(test)]
#[path = "statement-tests.rs"]
mod tests;
