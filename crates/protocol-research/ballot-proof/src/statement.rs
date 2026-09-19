use crate::{
    field::{self, Element, MODULUS, ONE, ZERO},
    parameters::*,
};
use ballot_encryption::{encryption::LinkedBallotWitness, packing::PackingMatrix};
use num_bigint::{BigInt, Sign};
use setup_stream_kernel::PolynomialStream;
pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
use sha3::{Digest, Sha3_512};

const PARAMETERS: &[u8; 137] = include_bytes!("../../setup-proof/parameters.bin");
#[derive(Debug)]
pub enum Error {
    Shape,
    Encoding,
    Binding,
    Arithmetic,
}
pub struct PublicStatement {
    pub header: Vec<u8>,
    pub polynomials: Vec<Vec<u8>>,
}
fn signed(value: i64) -> u128 {
    if value < 0 {
        MODULUS - value.unsigned_abs() as u128
    } else {
        value as u128
    }
}
pub(crate) fn encode_polynomial(values: &[BigInt], width: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::with_capacity(values.len() * width);
    for value in values {
        let (sign, magnitude) = value.to_bytes_le();
        if magnitude.len() >= width {
            return Err(Error::Encoding);
        }
        bytes.push(u8::from(sign == Sign::Minus));
        bytes.extend(&magnitude);
        bytes.resize(bytes.len() + width - 1 - magnitude.len(), 0);
    }
    Ok(bytes)
}
impl PublicStatement {
    pub fn from_encryption(witness: &LinkedBallotWitness) -> Result<Self, Error> {
        let mut header = Vec::from(b"LBS1".as_slice());
        header.extend(witness.context.poll().identity());
        header.extend(witness.context.inventory());
        header.extend((witness.context.position() as u16).to_le_bytes());
        header.push(witness.context.poll().manifest().option_count() as u8);
        header.push(u8::try_from(witness.context.poll().top_count()).map_err(|_| Error::Shape)?);
        let mut polynomials = Vec::with_capacity(8);
        for encryption in [&witness.fhe, &witness.auxiliary] {
            let width = if encryption.key.index() == 1 { 109 } else { 6 };
            for values in [
                &encryption.common,
                encryption.key.coefficients(),
                &encryption.components[0].coefficients,
                &encryption.components[1].coefficients,
            ] {
                polynomials.push(encode_polynomial(values, width)?);
            }
        }
        Ok(Self {
            header,
            polynomials,
        })
    }
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
        if self.polynomials.len() != 8 {
            return Err(Error::Shape);
        }
        for (index, bytes) in self.polynomials.iter().enumerate() {
            let mut parser = PolynomialStream::new(if index < 4 { 0 } else { 2 }, alpha)
                .map_err(|_| Error::Arithmetic)?;
            for chunk in bytes.chunks(1 << 20) {
                parser.push(chunk).map_err(|_| Error::Encoding)?;
            }
            builder.polynomial(index, parser)?;
        }
        builder.finish()
    }
}
pub struct Operator {
    pub coefficients: Vec<Vec<Element>>,
    pub target: Element,
    pub lookup_weight: Element,
}
struct Builder {
    alpha: Element,
    options: usize,
    top: usize,
    coefficients: Vec<Vec<Element>>,
    target: Element,
    consumed: usize,
}
fn power(mut value: Element, mut exponent: usize) -> Element {
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
fn powers(alpha: Element, degree: usize) -> Vec<Element> {
    let mut current = ONE;
    (0..degree)
        .map(|_| {
            let previous = current;
            current = field::multiply(current, alpha);
            previous
        })
        .collect()
}
fn public_digits(bytes: &[u8], limb_weight: Element) -> Element {
    bytes.chunks(12).rev().fold(ZERO, |sum, chunk| {
        let mut word = [0; 16];
        word[..chunk.len()].copy_from_slice(chunk);
        field::add(
            field::multiply(sum, limb_weight),
            [u128::from_le_bytes(word), 0, 0],
        )
    })
}
impl Builder {
    fn new(alpha: Element, header: &[u8]) -> Result<Self, Error> {
        if header.len() != HEADER_BYTES
            || &header[..4] != b"LBS1"
            || !(2..=20).contains(&header[134])
            || header[135] == 0
            || header[135] > header[134]
            || u16::from_le_bytes(header[132..134].try_into().unwrap()) >= 20
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            alpha,
            options: header[134] as usize,
            top: header[135] as usize,
            coefficients: vec![vec![ZERO; SYSTEMATIC]; COLUMNS],
            target: ZERO,
            consumed: 0,
        })
    }
    fn add_geometric(&mut self, column: usize, weight: Element, degree: usize) {
        let stride = SYSTEMATIC / degree;
        for (index, value) in powers(self.alpha, degree).into_iter().enumerate() {
            self.coefficients[column][stride * index] = field::add(
                self.coefficients[column][stride * index],
                field::multiply(weight, value),
            );
        }
    }
    fn polynomial(&mut self, index: usize, parser: PolynomialStream) -> Result<(), Error> {
        if self.consumed != index || index >= 8 {
            return Err(Error::Shape);
        }
        self.consumed += 1;
        let auxiliary = index >= 4;
        let local = index % 4;
        let degree = if auxiliary { 4096 } else { SYSTEMATIC };
        let row_base = if auxiliary { 19 * SYSTEMATIC } else { 0 };
        let component = if local == 0 || local == 3 { 1 } else { 0 };
        let weight = power(
            self.alpha,
            row_base + component * degree * if auxiliary { 1 } else { 9 },
        );
        if local < 2 {
            let adjoint = parser.adjoint().map_err(|_| Error::Encoding)?;
            let positive = if auxiliary { 29 } else { 27 };
            for (position, value) in adjoint.into_iter().enumerate() {
                let value = field::multiply(weight, value);
                let position = position * (SYSTEMATIC / degree);
                self.coefficients[positive][position] =
                    field::add(self.coefficients[positive][position], value);
                self.coefficients[positive + 1][position] =
                    field::subtract(self.coefficients[positive + 1][position], value);
            }
        } else {
            self.target = field::add(
                self.target,
                field::multiply(weight, parser.finish_value().map_err(|_| Error::Encoding)?),
            );
        }
        Ok(())
    }
    fn finish(mut self) -> Result<Operator, Error> {
        if self.consumed != 8 {
            return Err(Error::Shape);
        }
        let limb_weight = power(self.alpha, SYSTEMATIC);
        let modulus = public_digits(&PARAMETERS[4..112], limb_weight);
        let raw_modulus = BigInt::from_bytes_le(Sign::Plus, &PARAMETERS[4..112]);
        let scale = public_digits(
            &((&raw_modulus - BigInt::from(1)) / BigInt::from(65537))
                .to_bytes_le()
                .1,
            limb_weight,
        );
        let radix = [1u128 << 96, 0, 0];
        for component in 0..2 {
            let weight = power(self.alpha, component * 9 * SYSTEMATIC);
            self.add_geometric(
                component * 10,
                field::subtract(ZERO, field::multiply(weight, modulus)),
                SYSTEMATIC,
            );
            self.add_geometric(component * 10 + 9, weight, SYSTEMATIC);
            for carry in 0..8 {
                let carry_weight = field::multiply(
                    weight,
                    field::multiply(
                        power(limb_weight, carry),
                        field::subtract(limb_weight, radix),
                    ),
                );
                self.add_geometric(component * 10 + 1 + carry, carry_weight, SYSTEMATIC);
            }
            if component == 0 {
                self.add_geometric(20, scale, SYSTEMATIC);
                self.add_geometric(31, field::scale(scale, 65536), SYSTEMATIC);
            }
        }
        let packing_weight = power(self.alpha, 18 * SYSTEMATIC);
        self.add_geometric(20, packing_weight, SYSTEMATIC);
        self.add_geometric(31, field::scale(packing_weight, 65536), SYSTEMATIC);
        self.add_geometric(21, field::scale(packing_weight, signed(-65537)), SYSTEMATIC);
        let matrix = PackingMatrix::new(self.options, self.top).map_err(|_| Error::Shape)?;
        let geometric = powers(self.alpha, SYSTEMATIC);
        for option in 0..self.options {
            let column = matrix.column(option).map_err(|_| Error::Shape)?;
            let value = column
                .iter()
                .zip(&geometric)
                .fold(ZERO, |sum, (coefficient, weight)| {
                    field::add(sum, field::scale(*weight, signed(i64::from(*coefficient))))
                });
            self.coefficients[22][option] = field::subtract(
                self.coefficients[22][option],
                field::multiply(packing_weight, value),
            );
        }
        let auxiliary_modulus = public_digits(&PARAMETERS[132..137], ONE)[0];
        let auxiliary_scale = (auxiliary_modulus - 1) / 257;
        for component in 0..2 {
            let weight = power(self.alpha, 19 * SYSTEMATIC + component * 4096);
            self.add_geometric(
                23 + 2 * component,
                field::scale(weight, MODULUS - auxiliary_modulus),
                4096,
            );
            self.add_geometric(24 + 2 * component, weight, 4096);
            if component == 0 {
                for (option, point) in geometric.iter().take(self.options).enumerate() {
                    self.coefficients[22][option] = field::add(
                        self.coefficients[22][option],
                        field::scale(field::multiply(weight, *point), auxiliary_scale),
                    );
                }
            }
        }
        let mut row = 19 * SYSTEMATIC + 2 * 4096;
        for (column, degree, count) in [
            (27, SYSTEMATIC, 512),
            (28, SYSTEMATIC, 512),
            (29, 4096, 128),
            (30, 4096, 128),
        ] {
            let weight = power(self.alpha, row);
            row += 1;
            for position in (0..SYSTEMATIC).step_by(SYSTEMATIC / degree) {
                self.coefficients[column][position] =
                    field::add(self.coefficients[column][position], weight);
            }
            self.target = field::add(self.target, field::scale(weight, count));
        }
        for column in 0..WORDS {
            let offset = if column == 22 {
                -1
            } else if [9, 19, 24, 26].contains(&column) {
                64
            } else {
                32768
            };
            let sum = self.coefficients[column]
                .iter()
                .copied()
                .fold(ZERO, field::add);
            self.target = field::add(self.target, field::scale(sum, signed(offset)));
        }
        Ok(Operator {
            coefficients: self.coefficients,
            target: self.target,
            lookup_weight: power(self.alpha, row),
        })
    }
}

pub struct StatementStream {
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    hash: Sha3_512,
    header: Vec<u8>,
    builder: Option<Builder>,
    parser: Option<PolynomialStream>,
    polynomial: usize,
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
            polynomial: 0,
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
        if bytes.len() > 1 << 20 || bytes.len() > STATEMENT_BYTES - self.consumed {
            return Err(Error::Shape);
        }
        self.hash.update(bytes);
        self.consumed += bytes.len();
        if self.header.len() < HEADER_BYTES {
            let count = bytes.len().min(HEADER_BYTES - self.header.len());
            self.header.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.header.len() == HEADER_BYTES {
                self.builder = Some(Builder::new(self.alpha, &self.header)?);
            }
        }
        while !bytes.is_empty() {
            if self.polynomial >= 8 {
                return Err(Error::Shape);
            }
            let size = if self.polynomial < 4 {
                SYSTEMATIC * 109
            } else {
                4096 * 6
            };
            if self.parser.is_none() {
                self.parser = Some(
                    PolynomialStream::new(if self.polynomial < 4 { 0 } else { 2 }, self.alpha)
                        .map_err(|_| Error::Arithmetic)?,
                );
            }
            let count = bytes.len().min(size - self.polynomial_bytes);
            self.parser
                .as_mut()
                .unwrap()
                .push(&bytes[..count])
                .map_err(|_| Error::Encoding)?;
            bytes = &bytes[count..];
            self.polynomial_bytes += count;
            if self.polynomial_bytes == size {
                self.builder
                    .as_mut()
                    .ok_or(Error::Shape)?
                    .polynomial(self.polynomial, self.parser.take().unwrap())?;
                self.polynomial += 1;
                self.polynomial_bytes = 0;
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<StatementOutput, Error> {
        if self.failed
            || self.consumed != STATEMENT_BYTES
            || self.polynomial != 8
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
