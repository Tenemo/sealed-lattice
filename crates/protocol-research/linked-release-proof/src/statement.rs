use crate::{
    field::{self, Element, MODULUS, ONE, ZERO},
    parameters::*,
};
use num_bigint::{BigInt, Sign};
pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
use sha3::{Digest, Sha3_512};

const SETUP_PARAMETERS: &[u8; 137] = include_bytes!("../../setup-proof/parameters.bin");
#[derive(Debug)]
pub enum Error {
    Shape,
    Encoding,
    Binding,
    Arithmetic,
}
pub fn share_modulus() -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &SETUP_PARAMETERS[112..132])
}
pub fn release_modulus() -> BigInt {
    ((BigInt::from(65537u32) * 65445u32) << 160usize) + 1u32
}
pub(crate) fn modulus_parameters() -> Vec<usize> {
    let mut values = vec![SHARE_SCALE as usize];
    for (modulus, width) in [(share_modulus(), 20), (release_modulus(), 24)] {
        let mut bytes = modulus.to_bytes_le().1;
        bytes.resize(width, 0);
        values.push(width);
        values.extend(
            bytes
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as usize),
        );
    }
    values
}
pub const SHARE_SCALE: i128 = 998244353;
pub struct PublicStatement {
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
    buffer: [u8; 25],
    buffered: usize,
    consumed: usize,
}
impl Polynomial {
    fn new(index: usize, alpha: Element) -> Result<Self, Error> {
        if index >= 6 || alpha.iter().any(|value| *value >= MODULUS) {
            return Err(Error::Shape);
        }
        let modulus = if index < 4 {
            share_modulus()
        } else {
            release_modulus()
        };
        let width = if index < 4 { 21 } else { 25 };
        let mut half = (modulus >> 1usize).to_bytes_le().1;
        half.resize(width - 1, 0);
        Ok(Self {
            width,
            chunk: if index < 4 { 12 } else { 6 },
            half,
            alpha,
            weight: power(alpha, SYSTEMATIC),
            geometric: ONE,
            total: ZERO,
            values: Vec::with_capacity(SYSTEMATIC),
            buffer: [0; 25],
            buffered: 0,
            consumed: 0,
        })
    }
    fn push(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > 1048576 || bytes.len() > SYSTEMATIC * self.width - self.consumed {
            return Err(Error::Shape);
        }
        self.consumed += bytes.len();
        while !bytes.is_empty() {
            let count = bytes.len().min(self.width - self.buffered);
            self.buffer[self.buffered..self.buffered + count].copy_from_slice(&bytes[..count]);
            self.buffered += count;
            bytes = &bytes[count..];
            if self.buffered == self.width {
                let magnitude = &self.buffer[1..self.width];
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
                self.buffered = 0;
            }
        }
        Ok(())
    }
    fn complete(&self) -> Result<(), Error> {
        if self.values.len() != SYSTEMATIC
            || self.buffered != 0
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
    alpha: Element,
    omega: Element,
    geometric: Vec<Element>,
    coefficients: Vec<Vec<Element>>,
    target: Element,
    consumed: usize,
}
impl Builder {
    fn new(alpha: Element, header: &[u8]) -> Result<Self, Error> {
        if header.len() != HEADER_BYTES
            || &header[..4] != b"LRS1"
            || u16::from_le_bytes(header[196..198].try_into().unwrap()) >= 10
        {
            return Err(Error::Shape);
        }
        let mut value = ONE;
        let geometric = (0..SYSTEMATIC)
            .map(|_| {
                let previous = value;
                value = field::multiply(value, alpha);
                previous
            })
            .collect();
        Ok(Self {
            alpha,
            omega: power(alpha, SYSTEMATIC),
            geometric,
            coefficients: vec![vec![ZERO; SYSTEMATIC]; COLUMNS],
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
        assert!(first + count <= WORDS && coefficients.len() == SYSTEMATIC);
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
    fn variable(&mut self, index: usize, weight: Element) {
        let values = self
            .geometric
            .iter()
            .map(|value| field::multiply(*value, weight))
            .collect::<Vec<_>>();
        self.words(
            STARTS[index],
            WIDTHS[index].div_ceil(16),
            Some(WIDTHS[index]),
            &values,
        );
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
                    self.coefficients[WORDS][position] =
                        field::add(self.coefficients[WORDS][position], value);
                    self.coefficients[WORDS + 1][position] =
                        field::subtract(self.coefficients[WORDS + 1][position], value);
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
                for limb in 0..3 {
                    let weight = field::scale(field::multiply(base, power(self.omega, limb)), 4);
                    let values = adjoint
                        .iter()
                        .map(|value| field::multiply(*value, weight))
                        .collect::<Vec<_>>();
                    self.words(
                        STARTS[3] + 3 * limb,
                        if limb == 2 { 2 } else { 3 },
                        if limb == 2 { Some(24) } else { None },
                        &values,
                    );
                }
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
        if self.consumed != 6 {
            return Err(Error::Shape);
        }
        let share_modulus = fingerprint(&share_modulus().to_bytes_le().1, 12, self.omega);
        let release_modulus = fingerprint(&release_modulus().to_bytes_le().1, 6, self.omega);
        self.variable(0, field::subtract(ZERO, share_modulus));
        self.variable(1, field::subtract(self.omega, [1u128 << 96, 0, 0]));
        self.variable(2, field::subtract(ZERO, ONE));
        let decryption = power(self.alpha, 2 * SYSTEMATIC);
        self.variable(4, field::subtract(ZERO, decryption));
        self.variable(
            5,
            field::subtract(ZERO, field::multiply(decryption, share_modulus)),
        );
        self.variable(
            6,
            field::multiply(decryption, field::subtract(self.omega, [1u128 << 96, 0, 0])),
        );
        for limb in 0..2 {
            let weight = field::scale(
                field::multiply(decryption, power(self.omega, limb)),
                signed(-SHARE_SCALE),
            );
            let values = self
                .geometric
                .iter()
                .map(|value| field::multiply(*value, weight))
                .collect::<Vec<_>>();
            self.words(
                STARTS[3] + 6 * limb,
                if limb == 0 { 6 } else { 2 },
                Some(if limb == 0 { 96 } else { 24 }),
                &values,
            );
        }
        let offset = BigInt::from(SHARE_SCALE) * (BigInt::from(1) << 95usize);
        let offset = fingerprint(&offset.to_bytes_le().1, 12, self.omega);
        let geometric_sum = self.geometric.iter().copied().fold(ZERO, field::add);
        self.target = field::add(
            self.target,
            field::multiply(field::multiply(decryption, offset), geometric_sum),
        );
        let release = power(self.alpha, 4 * SYSTEMATIC);
        for limb in 0..4 {
            let weight = field::scale(field::multiply(release, power(self.omega, limb)), 4);
            let values = self
                .geometric
                .iter()
                .map(|value| field::multiply(*value, weight))
                .collect::<Vec<_>>();
            self.words(
                STARTS[7] + 3 * limb,
                if limb == 3 { 2 } else { 3 },
                if limb == 3 { Some(24) } else { None },
                &values,
            );
        }
        for limb in 0..3 {
            let weight = field::subtract(
                ZERO,
                field::multiply(
                    field::multiply(release, power(self.omega, limb)),
                    release_modulus,
                ),
            );
            let values = self
                .geometric
                .iter()
                .map(|value| field::multiply(*value, weight))
                .collect::<Vec<_>>();
            self.words(
                STARTS[8] + 3 * limb,
                3,
                if limb == 2 { Some(48) } else { None },
                &values,
            );
        }
        for limb in 0..5 {
            self.variable(
                9 + limb,
                field::multiply(
                    field::multiply(release, power(self.omega, limb)),
                    field::subtract(self.omega, [1u128 << 48, 0, 0]),
                ),
            );
        }
        for sign in 0..2 {
            let weight = power(self.alpha, 10 * SYSTEMATIC + sign);
            for value in &mut self.coefficients[WORDS + sign] {
                *value = field::add(*value, weight);
            }
            self.target = field::add(self.target, field::scale(weight, 128));
        }
        Ok(Operator {
            coefficients: self.coefficients,
            target: self.target,
            lookup_weight: power(self.alpha, 10 * SYSTEMATIC + 2),
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
        let mut builder = Builder::new(alpha, &self.header)?;
        if self.polynomials.len() != 6 {
            return Err(Error::Shape);
        }
        for (index, bytes) in self.polynomials.iter().enumerate() {
            let mut parser = Polynomial::new(index, alpha)?;
            for chunk in bytes.chunks(1048576) {
                parser.push(chunk)?;
            }
            builder.polynomial(index, parser)?;
        }
        builder.finish()
    }
}
pub struct StatementStream {
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
    pub fn new(expected: [u8; 64], alpha: Element, queries: &[u32]) -> Result<Self, Error> {
        if alpha.iter().any(|value| *value >= MODULUS)
            || queries.is_empty()
            || queries.len() > 2 * QUERY_COUNT
            || queries.iter().any(|value| *value as usize >= DOMAIN)
            || queries.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Shape);
        }
        Ok(Self {
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
        if bytes.len() > 1048576 || bytes.len() > STATEMENT_BYTES - self.consumed {
            return Err(Error::Shape);
        }
        self.consumed += bytes.len();
        self.hash.update(bytes);
        if self.header.len() < HEADER_BYTES {
            let count = bytes.len().min(HEADER_BYTES - self.header.len());
            self.header.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.header.len() == HEADER_BYTES {
                self.builder = Some(Builder::new(self.alpha, &self.header)?);
            }
        }
        while !bytes.is_empty() {
            if self.index >= 6 {
                return Err(Error::Shape);
            }
            let size = SYSTEMATIC * if self.index < 4 { 21 } else { 25 };
            if self.parser.is_none() {
                self.parser = Some(Polynomial::new(self.index, self.alpha)?);
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
            || self.consumed != STATEMENT_BYTES
            || self.index != 6
            || self.parser.is_some()
            || <[u8; 64]>::from(self.hash.finalize()) != self.expected
        {
            return Err(Error::Binding);
        }
        let operator = self.builder.ok_or(Error::Shape)?.finish()?;
        let mut coefficients = Vec::with_capacity(COLUMNS * self.queries.len());
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
