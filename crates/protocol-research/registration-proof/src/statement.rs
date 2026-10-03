use crate::parameters::*;
use num_bigint::{BigInt, Sign};
use parallel_work::{Digest, ProtocolHash};
use setup_stream_kernel::{PolynomialStream, SetupStatementOutput};
use word_proof::{
    affine::{Operator, PublicColumn, Term},
    field::{self, Element, MODULUS, ONE, ZERO},
};

use std::sync::OnceLock;

#[derive(Debug)]
pub enum Error {
    Shape,
    Encoding,
    Context,
    Arithmetic,
}
// Registration precedes the roster, so its statement uses only the share
// modulus, which every profile shares.
pub fn header() -> Vec<u8> {
    let mut output = Vec::from(b"RKS1".as_slice());
    output.extend((SYSTEMATIC as u32).to_le_bytes());
    output.extend(supported_profile::share_modulus());
    output
}
fn key_stream(alpha: Element) -> Result<PolynomialStream, Error> {
    PolynomialStream::new(
        supported_profile::share_modulus(),
        SYSTEMATIC,
        supported_profile::FHE_LIMB_BITS,
        alpha,
    )
    .map_err(|_| Error::Arithmetic)
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
/// The encoded common share polynomial, which every registration statement
/// begins with, computed once per instance.
pub fn common_bytes() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        encode_key(&setup_witness::contribution::common_share_polynomial()).unwrap()
    })
}
pub fn digest(common: &[u8], public_key: &[u8]) -> [u8; 64] {
    let mut hash = ProtocolHash::new();
    hash.update(header());
    hash.update(common);
    hash.update(public_key);
    hash.finalize().into()
}
/// The key equation's operator: the powers of alpha scaled by the modulus,
/// the carry and minus one, and the common polynomial's adjoint with each
/// support weight.
pub fn operator_from_parts(
    alpha: Element,
    adjoint: Vec<Element>,
    public_value: Element,
) -> Operator {
    assert_eq!(adjoint.len(), SYSTEMATIC);
    let mut current = ONE;
    let mut sum = ZERO;
    for _ in 0..SYSTEMATIC {
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
    let minus_one = field::subtract(ZERO, ONE);
    Operator {
        alpha,
        terms: vec![
            Term {
                public: PublicColumn::Powers(SYSTEMATIC),
                weights: vec![
                    (0, field::subtract(ZERO, modulus)),
                    (1, carry),
                    (2, minus_one),
                ],
            },
            Term {
                public: PublicColumn::Values(adjoint),
                weights: vec![(3, ONE), (4, minus_one)],
            },
            Term {
                public: PublicColumn::Ones(SYSTEMATIC),
                weights: vec![(3, support_positive), (4, support_negative)],
            },
        ],
        target,
        lookup_weight: field::multiply(support_negative, alpha),
    }
}
pub fn operator(alpha: Element, common: &[u8], public_key: &[u8]) -> Result<Operator, Error> {
    let mut first = key_stream(alpha)?;
    let mut second = key_stream(alpha)?;
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
    statement_bytes: usize,
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    hash: ProtocolHash,
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
            statement_bytes: registration_relation().statement_bytes(),
            expected,
            alpha,
            queries: queries.to_vec(),
            hash: ProtocolHash::new(),
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
        if bytes.len() > 1 << 20 || bytes.len() > self.statement_bytes - self.consumed {
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
                self.parser = Some(key_stream(self.alpha)?);
            }
            let count = bytes.len().min(SYSTEMATIC * 21 - position);
            let chunk = &bytes[..count];
            self.parser
                .as_mut()
                .unwrap()
                .push(chunk)
                .map_err(|_| Error::Encoding)?;
            if index == 0 && common_bytes().get(position..position + count) != Some(chunk) {
                return Err(Error::Context);
            }
            self.consumed += count;
            bytes = &bytes[count..];
            if position + count == SYSTEMATIC * 21 {
                let parser = self.parser.take().unwrap();
                if index == 0 {
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
            || self.consumed != self.statement_bytes
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
        let (target, lookup_weight) = (operator.target, operator.lookup_weight);
        let coefficients = operator
            .at_queries(registration_relation().columns(), &self.queries)
            .map_err(|_| Error::Arithmetic)?;
        Ok(SetupStatementOutput {
            statement_digest: self.expected,
            target,
            lookup_weight,
            coefficients,
        })
    }
}

#[cfg(test)]
#[path = "reference/dense-operator.rs"]
mod dense_operator;

#[cfg(test)]
mod tests {
    use super::*;

    // The weighted operator places at every row of every column the
    // coefficient the dense reference builds there, with the same target and
    // lookup weight, for any adjoint and public value.
    #[test]
    fn weighted_operators_equal_the_dense_reference_at_every_row() {
        let element = |seed: u128| {
            [
                (seed * 0x9e37_79b9_7f4a_7c15 + 1) % MODULUS,
                (seed * 0x632b_e59b_d9b4_e019 + 2) % MODULUS,
                (seed * 0x1234_5678_9abc_def1 + 3) % MODULUS,
            ]
        };
        let adjoint: Vec<Element> = (0..SYSTEMATIC as u128).map(element).collect();
        let columns = registration_relation().columns();
        for (index, alpha) in [
            [1, 0, 0],
            [13, 17, 19],
            [MODULUS - 2, MODULUS - 3, MODULUS - 5],
        ]
        .into_iter()
        .enumerate()
        {
            let public_value = element((SYSTEMATIC + index) as u128);
            let weighted = operator_from_parts(alpha, adjoint.clone(), public_value);
            let dense =
                super::dense_operator::operator_from_parts(alpha, adjoint.clone(), public_value);
            assert_eq!(weighted.columns(columns), dense.coefficients);
            assert_eq!(
                (weighted.target, weighted.lookup_weight),
                (dense.target, dense.lookup_weight)
            );
        }
    }
    #[test]
    fn rejected_prefixes_and_changed_fixed_matrices_never_produce_an_operator() {
        let common = common_bytes();
        let key = vec![0u8; SYSTEMATIC * 21];
        let mut wrong_header = header();
        wrong_header[4] ^= 1;
        let mut hash = ProtocolHash::new();
        hash.update(&wrong_header);
        hash.update(common);
        hash.update(&key);
        let mut decoder = StatementStream::new(hash.finalize().into(), ONE, &[0]).unwrap();
        assert!(decoder.push(&wrong_header).is_err());
        assert!(decoder.push(&common[..128]).is_err());
        assert!(decoder.finish().is_err());
        let mut changed = common.to_vec();
        changed[1] ^= 1;
        let mut hash = ProtocolHash::new();
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
