#![deny(unsafe_op_in_unsafe_fn)]

use sha3::{Digest, Sha3_512};
#[cfg(feature = "bridge")]
use std::cell::RefCell;

mod arithmetic;
mod query;
mod setup;
use arithmetic::{MODULUS, add, multiply, subtract};
pub use setup::{
    ProverFixedTerm, ProverOperatorPlan, SetupStatementOutput, SetupStatementStream,
    prover_operator_plan,
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
const PARAMETERS: &[u8; 137] = include_bytes!("../../setup-proof/parameters.bin");

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
pub struct PolynomialStream {
    degree: usize,
    width: usize,
    half_modulus: Vec<u8>,
    alpha: Element,
    limb_weight: Element,
    position_weight: Element,
    total: Element,
    coefficients: Vec<Element>,
    record: [u8; 109],
    record_length: usize,
    consumed: usize,
    failed: bool,
    retain_coefficients: bool,
}

impl PolynomialStream {
    pub fn new(family: u32, alpha: Element) -> Result<Self, Error> {
        let degree = match family {
            0 | 1 => 65_536,
            2 => 4_096,
            _ => return Err(Error::Parameters),
        };
        Self::for_degree(family, degree, alpha, true)
    }

    pub(crate) fn for_degree(
        family: u32,
        degree: usize,
        alpha: Element,
        retain_coefficients: bool,
    ) -> Result<Self, Error> {
        if !degree.is_power_of_two() || !(2..=65_536).contains(&degree) {
            return Err(Error::Parameters);
        }
        let modulus: &[u8] = match family {
            0 => &PARAMETERS[4..112],
            1 => &PARAMETERS[112..132],
            2 => &PARAMETERS[132..137],
            _ => return Err(Error::Parameters),
        };
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
            record: [0; 109],
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
        let mut result = ZERO;
        for limb in (0..magnitude.len().div_ceil(12)).rev() {
            let start = limb * 12;
            let mut bytes = [0; 16];
            let length = 12.min(magnitude.len() - start);
            bytes[..length].copy_from_slice(&magnitude[start..start + length]);
            result = plus(
                times(result, self.limb_weight),
                [u128::from_le_bytes(bytes), 0, 0],
            );
        }
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

    pub fn finish(self) -> Result<[u8; 64], Error> {
        let mut hash = Sha3_512::new();
        for coefficient in self.adjoint()? {
            for limb in coefficient {
                hash.update(limb.to_le_bytes());
            }
        }
        Ok(hash.finalize().into())
    }

    pub fn finish_queries(self, indices: &[u32]) -> Result<Vec<Element>, Error> {
        query::validate_indices(indices)?;
        query::evaluate(self.adjoint()?, indices)
    }
}

#[cfg(feature = "bridge")]
struct Session {
    input: Vec<u8>,
    output: [u8; 64],
    query_output: Vec<Element>,
    parser: Option<PolynomialStream>,
    setup: Option<SetupStatementStream>,
    setup_output: Option<SetupStatementOutput>,
}
#[cfg(feature = "bridge")]
thread_local! {
    static SESSION: RefCell<Session> = RefCell::new(Session {
        input: vec![0; CHUNK_LIMIT], output: [0; 64], query_output: Vec::new(), parser: None, setup: None, setup_output: None,
    });
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn output_pointer() -> usize {
    SESSION.with(|session| session.borrow().output.as_ptr() as usize)
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn begin(family: u32) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.setup = None;
        session.setup_output = None;
        let alpha = std::array::from_fn(|index| {
            u128::from_le_bytes(
                session.input[16 * index..16 * (index + 1)]
                    .try_into()
                    .unwrap(),
            )
        });
        session.parser = PolynomialStream::new(family, alpha).ok();
        session.output.fill(0);
        session.query_output.clear();
        u32::from(session.parser.is_none())
    })
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn absorb(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session { input, parser, .. } = &mut *session;
        let result = input
            .get(..length)
            .ok_or(Error::Length)
            .and_then(|bytes| parser.as_mut().ok_or(Error::Incomplete)?.push(bytes));
        if result.is_err() {
            *parser = None;
            1
        } else {
            0
        }
    })
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn finish() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        match session
            .parser
            .take()
            .ok_or(Error::Incomplete)
            .and_then(PolynomialStream::finish)
        {
            Ok(digest) => {
                session.output = digest;
                0
            }
            Err(_) => {
                session.output.fill(0);
                1
            }
        }
    })
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn query_output_pointer() -> usize {
    SESSION.with(|session| session.borrow().query_output.as_ptr() as usize)
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn finish_queries(count: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.query_output.clear();
        let Some(parser) = session.parser.take() else {
            return 1;
        };
        if count == 0 || count > query::QUERY_LIMIT {
            return 1;
        }
        let indices: Vec<u32> = session.input[..count * 4]
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        match parser.finish_queries(&indices) {
            Ok(output) => {
                session.query_output = output;
                0
            }
            Err(_) => 1,
        }
    })
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn begin_setup(count: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.parser = None;
        session.query_output = Vec::new();
        session.setup = None;
        session.setup_output = None;
        if count == 0 || count > query::QUERY_LIMIT {
            return 1;
        }
        let digest = session.input[..64].try_into().unwrap();
        let alpha = std::array::from_fn(|index| {
            u128::from_le_bytes(
                session.input[64 + 16 * index..64 + 16 * (index + 1)]
                    .try_into()
                    .unwrap(),
            )
        });
        let indices: Vec<u32> = session.input[112..112 + 4 * count]
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        session.setup = SetupStatementStream::new(digest, alpha, &indices).ok();
        u32::from(session.setup.is_none())
    })
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn absorb_setup(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session { input, setup, .. } = &mut *session;
        let result = input
            .get(..length)
            .ok_or(Error::Length)
            .and_then(|bytes| setup.as_mut().ok_or(Error::Incomplete)?.push(bytes));
        if result.is_err() {
            *setup = None;
            1
        } else {
            0
        }
    })
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn finish_setup() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.setup_output = session.setup.take().and_then(|stream| stream.finish().ok());
        u32::from(session.setup_output.is_none())
    })
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn setup_output_length() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .setup_output
            .as_ref()
            .map_or(0, SetupStatementOutput::encoded_length)
    })
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn copy_setup_output(offset: usize, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session {
            input,
            setup_output,
            ..
        } = &mut *session;
        let result = input
            .get_mut(..length)
            .ok_or(Error::Length)
            .and_then(|bytes| {
                setup_output
                    .as_ref()
                    .ok_or(Error::Incomplete)?
                    .copy_range(offset, bytes)
            });
        u32::from(result.is_err())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cubic_field_uses_the_selected_nonresidue() {
        assert_ne!(arithmetic::power(2, (MODULUS - 1) / 3), 1);
    }

    #[test]
    fn rejects_partial_records_and_forbidden_lengths_without_output() {
        let mut stream = PolynomialStream::new(2, [17, 37, 91]).unwrap();
        stream.push(&[0; 5]).unwrap();
        assert_eq!(stream.finish(), Err(Error::Incomplete));
        let mut stream = PolynomialStream::new(2, [17, 37, 91]).unwrap();
        assert_eq!(stream.push(&vec![0; CHUNK_LIMIT + 1]), Err(Error::Length));
        assert_eq!(stream.push(&[]), Err(Error::Encoding));
        assert_eq!(stream.finish(), Err(Error::Encoding));
    }
}
