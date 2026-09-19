use crate::{
    field::{self, Element, MODULUS, ONE, ZERO},
    parameters::*,
};
use num_bigint::{BigInt, Sign};
use setup_stream_kernel::{PolynomialStream, SetupStatementOutput, evaluate_public_values};
use sha3::{Digest, Sha3_512};

#[derive(Debug)]
pub enum Error {
    Shape,
    Encoding,
    Context,
    Arithmetic,
}
pub fn header() -> Vec<u8> {
    let setup = setup_witness::contribution::statement_header();
    let mut output = Vec::from(b"RKS1".as_slice());
    output.extend((SYSTEMATIC as u32).to_le_bytes());
    output.extend(&setup[120..140]);
    output
}
pub fn encode_key(values: &[BigInt]) -> Result<Vec<u8>, Error> {
    if values.len() != SYSTEMATIC {
        return Err(Error::Shape);
    }
    let modulus = BigInt::from_bytes_le(Sign::Plus, &header()[8..]);
    let half = modulus >> 1usize;
    let mut output = Vec::with_capacity(SYSTEMATIC * 21);
    for value in values {
        let (sign, magnitude) = value.to_bytes_le();
        if magnitude.len() > 20
            || (sign != Sign::Minus && value > &half)
            || (sign == Sign::Minus && -value > half)
        {
            return Err(Error::Encoding);
        }
        output.push(u8::from(sign == Sign::Minus));
        output.extend(&magnitude);
        output.resize(output.len() + 20 - magnitude.len(), 0);
    }
    Ok(output)
}
pub fn common_bytes() -> Vec<u8> {
    encode_key(&setup_witness::contribution::common_polynomial(42).unwrap()).unwrap()
}
pub fn digest(common: &[u8], public_key: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(header());
    hash.update(common);
    hash.update(public_key);
    hash.finalize().into()
}
pub struct Operator {
    pub coefficients: Vec<Vec<Element>>,
    pub target: Element,
    pub lookup_weight: Element,
}
pub fn operator_from_parts(
    alpha: Element,
    adjoint: Vec<Element>,
    public_value: Element,
) -> Operator {
    assert_eq!(adjoint.len(), SYSTEMATIC);
    let mut powers = Vec::with_capacity(SYSTEMATIC);
    let mut current = ONE;
    let mut sum = ZERO;
    for _ in 0..SYSTEMATIC {
        powers.push(current);
        sum = field::add(sum, current);
        current = field::multiply(current, alpha);
    }
    let z = current;
    let encoded = header();
    let mut lower = [0; 16];
    lower[..12].copy_from_slice(&encoded[8..20]);
    let mut upper = [0; 16];
    upper[..8].copy_from_slice(&encoded[20..28]);
    let modulus = field::add(
        [u128::from_le_bytes(lower), 0, 0],
        field::scale(z, u128::from_le_bytes(upper)),
    );
    let carry = field::subtract(z, [1u128 << 96, 0, 0]);
    let support_positive = field::multiply(z, z);
    let support_negative = field::multiply(support_positive, alpha);
    let offset = field::add(
        field::subtract(field::scale(modulus, 1 << 15), field::scale(carry, 1 << 15)),
        [64, 0, 0],
    );
    let target = field::add(
        field::subtract(
            field::subtract(ZERO, public_value),
            field::multiply(offset, sum),
        ),
        field::scale(field::add(support_positive, support_negative), 128),
    );
    let coefficients = vec![
        powers
            .iter()
            .map(|power| field::subtract(ZERO, field::multiply(*power, modulus)))
            .collect(),
        powers
            .iter()
            .map(|power| field::multiply(*power, carry))
            .collect(),
        powers
            .iter()
            .map(|power| field::subtract(ZERO, *power))
            .collect(),
        adjoint
            .iter()
            .map(|value| field::add(*value, support_positive))
            .collect(),
        adjoint
            .iter()
            .map(|value| field::subtract(support_negative, *value))
            .collect(),
    ];
    Operator {
        coefficients,
        target,
        lookup_weight: field::multiply(support_negative, alpha),
    }
}
pub fn operator(alpha: Element, common: &[u8], public_key: &[u8]) -> Result<Operator, Error> {
    let mut first = PolynomialStream::new(1, alpha).map_err(|_| Error::Arithmetic)?;
    let mut second = PolynomialStream::new(1, alpha).map_err(|_| Error::Arithmetic)?;
    for chunk in common.chunks(1 << 20) {
        first.push(chunk).map_err(|_| Error::Encoding)?;
    }
    for chunk in public_key.chunks(1 << 20) {
        second.push(chunk).map_err(|_| Error::Encoding)?;
    }
    Ok(operator_from_parts(
        alpha,
        first.adjoint().map_err(|_| Error::Encoding)?,
        second.finish_value().map_err(|_| Error::Encoding)?,
    ))
}

pub struct StatementStream {
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    hash: Sha3_512,
    common_hash: Sha3_512,
    expected_common: [u8; 64],
    prefix: Vec<u8>,
    consumed: usize,
    parser: Option<PolynomialStream>,
    adjoint: Option<Vec<Element>>,
    public_value: Option<Element>,
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
            common_hash: Sha3_512::new(),
            expected_common: Sha3_512::digest(common_bytes()).into(),
            prefix: Vec::new(),
            consumed: 0,
            parser: None,
            adjoint: None,
            public_value: None,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Context);
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
        while !bytes.is_empty() {
            if self.prefix.len() < 28 {
                let count = bytes.len().min(28 - self.prefix.len());
                self.prefix.extend(&bytes[..count]);
                self.consumed += count;
                bytes = &bytes[count..];
                if self.prefix.len() == 28 && self.prefix != header() {
                    return Err(Error::Context);
                }
                continue;
            }
            let index = (self.consumed - 28) / (SYSTEMATIC * 21);
            let position = (self.consumed - 28) % (SYSTEMATIC * 21);
            if index >= 2 {
                return Err(Error::Shape);
            }
            if self.parser.is_none() {
                self.parser =
                    Some(PolynomialStream::new(1, self.alpha).map_err(|_| Error::Arithmetic)?);
            }
            let count = bytes.len().min(SYSTEMATIC * 21 - position);
            let chunk = &bytes[..count];
            self.parser
                .as_mut()
                .unwrap()
                .push(chunk)
                .map_err(|_| Error::Encoding)?;
            if index == 0 {
                self.common_hash.update(chunk);
            }
            self.consumed += count;
            bytes = &bytes[count..];
            if position + count == SYSTEMATIC * 21 {
                let parser = self.parser.take().unwrap();
                if index == 0 {
                    if <[u8; 64]>::from(self.common_hash.clone().finalize()) != self.expected_common
                    {
                        return Err(Error::Context);
                    }
                    self.adjoint = Some(parser.adjoint().map_err(|_| Error::Encoding)?);
                } else {
                    self.public_value = Some(parser.finish_value().map_err(|_| Error::Encoding)?);
                }
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<SetupStatementOutput, Error> {
        if self.failed
            || self.consumed != STATEMENT_BYTES
            || self.parser.is_some()
            || <[u8; 64]>::from(self.hash.finalize()) != self.expected
        {
            return Err(Error::Context);
        }
        let operator = operator_from_parts(
            self.alpha,
            self.adjoint.ok_or(Error::Shape)?,
            self.public_value.ok_or(Error::Shape)?,
        );
        let mut coefficients = Vec::with_capacity(COLUMNS * self.queries.len());
        for values in operator.coefficients {
            coefficients.extend(
                evaluate_public_values(values, &self.queries).map_err(|_| Error::Arithmetic)?,
            );
        }
        Ok(SetupStatementOutput {
            statement_digest: self.expected,
            target: operator.target,
            lookup_weight: operator.lookup_weight,
            coefficients,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_prefixes_and_changed_fixed_matrices_never_produce_an_operator() {
        let common = common_bytes();
        let key = vec![0u8; SYSTEMATIC * 21];
        let mut wrong_header = header();
        wrong_header[4] ^= 1;
        let mut hash = Sha3_512::new();
        hash.update(&wrong_header);
        hash.update(&common);
        hash.update(&key);
        let mut decoder = StatementStream::new(hash.finalize().into(), ONE, &[0]).unwrap();
        assert!(decoder.push(&wrong_header).is_err());
        assert!(decoder.push(&common[..128]).is_err());
        assert!(decoder.finish().is_err());
        let mut changed = common;
        changed[1] ^= 1;
        let mut hash = Sha3_512::new();
        hash.update(header());
        hash.update(&changed);
        hash.update(&key);
        let mut decoder = StatementStream::new(hash.finalize().into(), ONE, &[0]).unwrap();
        decoder.push(&header()).unwrap();
        assert!(
            changed
                .chunks(1 << 20)
                .any(|bytes| decoder.push(bytes).is_err())
        );
        assert!(decoder.finish().is_err());
    }
}
