use crate::{
    field::{self, Element, MODULUS, ONE, ZERO},
    parameters::*,
};
use num_bigint::{BigInt, Sign};
pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
use sha3::{Digest, Sha3_512};
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
pub(crate) const HEADER_MAGIC: &[u8; 4] = b"LRS1";
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
pub fn release_coefficient_bytes(profile: Profile) -> usize {
    1 + profile.release_modulus().byte_length()
}
fn coefficient_bytes(profile: Profile, index: usize) -> usize {
    if index < SHARE_POLYNOMIALS {
        share_coefficient_bytes()
    } else {
        release_coefficient_bytes(profile)
    }
}
/// The release position a header names, when it has the release magic and
/// names a roster position of the profile.
pub fn header_position(profile: Profile, header: &[u8]) -> Option<usize> {
    if header.len() != RELEASE_HEADER_BYTES || &header[..4] != HEADER_MAGIC {
        return None;
    }
    let position = usize::from(u16::from_le_bytes(
        header[RELEASE_HEADER_BYTES - 2..].try_into().unwrap(),
    ));
    (position < profile.participants()).then_some(position)
}
pub struct PublicStatement {
    pub profile: Profile,
    pub header: Vec<u8>,
    pub polynomials: Vec<Vec<u8>>,
}
pub struct Operator {
    pub coefficients: Vec<Vec<Element>>,
    pub target: Element,
    pub lookup_weight: Element,
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
fn times(values: &[Element], weight: Element) -> Vec<Element> {
    values
        .iter()
        .map(|value| field::multiply(*value, weight))
        .collect()
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
struct Polynomial {
    width: usize,
    chunk: usize,
    half: Vec<u8>,
    alpha: Element,
    weight: Element,
    geometric: Element,
    total: Element,
    values: Vec<Element>,
    buffer: Vec<u8>,
    consumed: usize,
}
impl Polynomial {
    fn new(profile: Profile, index: usize, alpha: Element) -> Result<Self, Error> {
        if index >= POLYNOMIALS || alpha.iter().any(|value| *value >= MODULUS) {
            return Err(Error::Shape);
        }
        let (modulus, chunk) = if index < SHARE_POLYNOMIALS {
            (share_modulus(), DECODING_CHUNK)
        } else {
            (release_modulus(profile), RELEASE_CHUNK)
        };
        let width = coefficient_bytes(profile, index);
        let mut half = (modulus >> 1usize).to_bytes_le().1;
        half.resize(width - 1, 0);
        Ok(Self {
            width,
            chunk,
            half,
            alpha,
            weight: power(alpha, SYSTEMATIC),
            geometric: ONE,
            total: ZERO,
            values: Vec::with_capacity(SYSTEMATIC),
            buffer: Vec::with_capacity(width),
            consumed: 0,
        })
    }
    fn push(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > 1048576 || bytes.len() > SYSTEMATIC * self.width - self.consumed {
            return Err(Error::Shape);
        }
        self.consumed += bytes.len();
        while !bytes.is_empty() {
            let count = bytes.len().min(self.width - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.buffer.len() == self.width {
                let magnitude = &self.buffer[1..];
                if self.buffer[0] > 1
                    || magnitude.iter().rev().cmp(self.half.iter().rev()).is_gt()
                    || (self.buffer[0] == 1 && magnitude.iter().all(|value| *value == 0))
                {
                    return Err(Error::Encoding);
                }
                let value = fingerprint(magnitude, self.chunk, self.weight);
                let value = if self.buffer[0] == 1 {
                    field::subtract(ZERO, value)
                } else {
                    value
                };
                self.total = field::add(self.total, field::multiply(self.geometric, value));
                self.geometric = field::multiply(self.geometric, self.alpha);
                self.values.push(value);
                self.buffer.clear();
            }
        }
        Ok(())
    }
    fn complete(&self) -> Result<(), Error> {
        if self.values.len() != SYSTEMATIC
            || !self.buffer.is_empty()
            || self.consumed != SYSTEMATIC * self.width
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    fn adjoint(mut self) -> Result<Vec<Element>, Error> {
        self.complete()?;
        self.values.reverse();
        let mut current = self.total;
        let wrap = field::add(self.weight, ONE);
        for value in &mut self.values {
            let next = field::subtract(
                field::multiply(self.alpha, current),
                field::multiply(wrap, *value),
            );
            *value = current;
            current = next;
        }
        if current != field::subtract(ZERO, self.total) {
            return Err(Error::Arithmetic);
        }
        Ok(self.values)
    }
}
struct Builder {
    profile: Profile,
    bits: Vec<usize>,
    starts: Vec<usize>,
    words: usize,
    alpha: Element,
    omega: Element,
    geometric: Vec<Element>,
    coefficients: Vec<Vec<Element>>,
    target: Element,
    consumed: usize,
}
impl Builder {
    fn new(profile: Profile, alpha: Element, header: &[u8]) -> Result<Self, Error> {
        header_position(profile, header).ok_or(Error::Shape)?;
        let (starts, words) = release_variable_starts(profile);
        let mut value = ONE;
        let geometric = (0..SYSTEMATIC)
            .map(|_| {
                let previous = value;
                value = field::multiply(value, alpha);
                previous
            })
            .collect();
        Ok(Self {
            profile,
            bits: profile.release_variable_bits(),
            starts,
            words,
            alpha,
            omega: power(alpha, SYSTEMATIC),
            geometric,
            coefficients: vec![vec![ZERO; SYSTEMATIC]; words + 2],
            target: ZERO,
            consumed: 0,
        })
    }
    fn words(
        &mut self,
        first: usize,
        count: usize,
        bias_bits: Option<usize>,
        coefficients: &[Element],
    ) {
        assert!(first + count <= self.words && coefficients.len() == SYSTEMATIC);
        let mut weight = 1u128;
        for column in first..first + count {
            for (target, value) in self.coefficients[column].iter_mut().zip(coefficients) {
                *target = field::add(*target, field::scale(*value, weight));
            }
            weight = field::base::multiply(weight, 65536);
        }
        if let Some(bits) = bias_bits {
            let bias = field::base::power(2, (bits - 1) as u128);
            let sum = coefficients.iter().copied().fold(ZERO, field::add);
            self.target = field::add(self.target, field::scale(sum, bias));
        }
    }
    /// Adds the words of bits `first..first + width` of a signed variable at
    /// the given row coefficients. A part holding the variable's top bits,
    /// or a centered lower part, is offset by half its range.
    fn part(
        &mut self,
        variable: usize,
        first: usize,
        width: usize,
        centered: bool,
        coefficients: &[Element],
    ) {
        assert!(first.is_multiple_of(16) && first + width <= self.bits[variable]);
        self.words(
            self.starts[variable] + first / 16,
            width.div_ceil(16),
            centered.then_some(width),
            coefficients,
        );
    }
    fn variable(&mut self, variable: usize, weight: Element, geometric: &[Element]) {
        self.part(
            variable,
            0,
            self.bits[variable],
            true,
            &times(geometric, weight),
        );
    }
    /// Adds each release limb of a signed variable at the row coefficients
    /// times its limb weight. Every limb but the top one is an unsigned
    /// digit.
    fn release_limbs(
        &mut self,
        variable: usize,
        coefficients: &[Element],
        weight: impl Fn(usize) -> Element,
    ) {
        let bits = self.bits[variable];
        let limbs = bits.div_ceil(RELEASE_LIMB_BITS);
        for limb in 0..limbs {
            let first = limb * RELEASE_LIMB_BITS;
            let top = limb + 1 == limbs;
            let width = if top { bits - first } else { RELEASE_LIMB_BITS };
            self.part(
                variable,
                first,
                width,
                top,
                &times(coefficients, weight(limb)),
            );
        }
    }
    fn polynomial(&mut self, index: usize, polynomial: Polynomial) -> Result<(), Error> {
        if index != self.consumed {
            return Err(Error::Shape);
        }
        polynomial.complete()?;
        self.consumed += 1;
        match index {
            0 | 3 => {
                let weight = if index == 0 {
                    ONE
                } else {
                    power(self.alpha, 2 * SYSTEMATIC)
                };
                for (position, value) in polynomial.adjoint()?.into_iter().enumerate() {
                    let value = field::multiply(weight, value);
                    self.coefficients[self.words][position] =
                        field::add(self.coefficients[self.words][position], value);
                    self.coefficients[self.words + 1][position] =
                        field::subtract(self.coefficients[self.words + 1][position], value);
                }
            }
            1 => self.target = field::subtract(self.target, polynomial.total),
            2 => {
                self.target = field::subtract(
                    self.target,
                    field::multiply(power(self.alpha, 2 * SYSTEMATIC), polynomial.total),
                )
            }
            4 => {
                let adjoint = polynomial.adjoint()?;
                let base = power(self.alpha, 4 * SYSTEMATIC);
                let (omega, clearing) = (self.omega, self.profile.clearing_factor() as u128);
                self.release_limbs(SHARE, &adjoint, |limb| {
                    field::scale(field::multiply(base, power(omega, limb)), clearing)
                });
            }
            5 => {
                self.target = field::add(
                    self.target,
                    field::multiply(power(self.alpha, 4 * SYSTEMATIC), polynomial.total),
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
        let geometric = std::mem::take(&mut self.geometric);
        let omega = self.omega;
        let share_modulus = fingerprint(supported_profile::share_modulus(), DECODING_CHUNK, omega);
        let release_modulus = fingerprint(
            &self.profile.release_modulus().to_bytes(),
            RELEASE_CHUNK,
            omega,
        );
        let decoding_carry = field::subtract(omega, [1u128 << RELEASE_DECODING_LIMB_BITS, 0, 0]);
        // The recipient key equation.
        self.variable(
            KEY_QUOTIENT,
            field::subtract(ZERO, share_modulus),
            &geometric,
        );
        self.variable(KEY_CARRY, decoding_carry, &geometric);
        self.variable(KEY_ERROR, field::subtract(ZERO, ONE), &geometric);
        // The aggregate share's decoding equation, with the share scale times
        // the centered lower decoding limb and the signed upper part.
        let decryption = power(self.alpha, 2 * SYSTEMATIC);
        self.variable(
            DECODING_ERROR,
            field::subtract(ZERO, decryption),
            &geometric,
        );
        self.variable(
            DECODING_QUOTIENT,
            field::subtract(ZERO, field::multiply(decryption, share_modulus)),
            &geometric,
        );
        self.variable(
            DECODING_CARRY,
            field::multiply(decryption, decoding_carry),
            &geometric,
        );
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
            self.part(SHARE, first, width, true, &times(&geometric, weight));
        }
        let offset = BigInt::from(SHARE_SCALE) << (RELEASE_DECODING_LIMB_BITS - 1);
        let offset = fingerprint(&offset.to_bytes_le().1, DECODING_CHUNK, omega);
        let geometric_sum = geometric.iter().copied().fold(ZERO, field::add);
        self.target = field::add(
            self.target,
            field::multiply(field::multiply(decryption, offset), geometric_sum),
        );
        // The partial decryption equation in release limbs.
        let release = power(self.alpha, 4 * SYSTEMATIC);
        let clearing = self.profile.clearing_factor() as u128;
        self.release_limbs(NOISE, &geometric, |limb| {
            field::scale(field::multiply(release, power(omega, limb)), clearing)
        });
        self.release_limbs(RELEASE_QUOTIENT, &geometric, |limb| {
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
                &geometric,
            );
        }
        // Each half of the recipient secret's support follows every limb row.
        let rows = (4 + output_limbs) * SYSTEMATIC;
        for sign in 0..2 {
            let weight = power(self.alpha, rows + sign);
            for value in &mut self.coefficients[self.words + sign] {
                *value = field::add(*value, weight);
            }
            self.target = field::add(
                self.target,
                field::scale(weight, (RECIPIENT_SECRET_SUPPORT / 2) as u128),
            );
        }
        Ok(Operator {
            coefficients: self.coefficients,
            target: self.target,
            lookup_weight: power(self.alpha, rows + 2),
        })
    }
}
impl PublicStatement {
    pub fn digest(&self) -> [u8; 64] {
        let mut hash = Sha3_512::new();
        hash.update(&self.header);
        for polynomial in &self.polynomials {
            hash.update(polynomial);
        }
        hash.finalize().into()
    }
    pub fn operator(&self, alpha: Element) -> Result<Operator, Error> {
        let mut builder = Builder::new(self.profile, alpha, &self.header)?;
        if self.polynomials.len() != POLYNOMIALS {
            return Err(Error::Shape);
        }
        for (index, bytes) in self.polynomials.iter().enumerate() {
            let mut parser = Polynomial::new(self.profile, index, alpha)?;
            for chunk in bytes.chunks(1048576) {
                parser.push(chunk)?;
            }
            builder.polynomial(index, parser)?;
        }
        builder.finish()
    }
}
pub struct StatementStream {
    profile: Profile,
    statement_bytes: usize,
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    hash: Sha3_512,
    header: Vec<u8>,
    builder: Option<Builder>,
    parser: Option<Polynomial>,
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
            hash: Sha3_512::new(),
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
                self.parser = Some(Polynomial::new(self.profile, self.index, self.alpha)?);
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
            || <[u8; 64]>::from(self.hash.finalize()) != self.expected
        {
            return Err(Error::Binding);
        }
        let operator = self.builder.ok_or(Error::Shape)?.finish()?;
        let mut coefficients = Vec::with_capacity(operator.coefficients.len() * self.queries.len());
        for column in operator.coefficients {
            coefficients.extend(
                setup_stream_kernel::evaluate_public_values(column, &self.queries)
                    .map_err(|_| Error::Arithmetic)?,
            );
        }
        Ok(StatementOutput {
            statement_digest: self.expected,
            target: operator.target,
            lookup_weight: operator.lookup_weight,
            coefficients,
        })
    }
}
