use crate::{
    CHUNK_LIMIT, Element, Error, ONE, PolynomialStream, StatementOutput, ZERO,
    evaluate_public_columns, plus, proof_field::MODULUS, query, times,
};
use parallel_work::{HashStream, Sponge};
use supported_profile::{
    Profile,
    relation::{EVALUATION_DOMAIN_SIZE, SYSTEMATIC},
};

/// A public polynomial of an affine operator: its values sit at every
/// (SYSTEMATIC / degree)-th row of a column, with zeros between them.
pub enum PublicColumn {
    /// The first `degree` powers of the operator's challenge.
    Powers(usize),
    /// `degree` ones.
    Ones(usize),
    /// Public values, as many as the degree.
    Values(Vec<Element>),
}
impl PublicColumn {
    /// The sum of the values the column places.
    pub fn sum(&self, alpha: Element) -> Element {
        match self {
            Self::Powers(degree) => powers(alpha, *degree).into_iter().fold(ZERO, plus),
            Self::Ones(degree) => [*degree as u128, 0, 0],
            Self::Values(values) => values.iter().copied().fold(ZERO, plus),
        }
    }
}
/// A public column and the weight with which it enters each relation
/// column it names.
pub struct Term {
    pub public: PublicColumn,
    pub weights: Vec<(usize, Element)>,
}
/// An affine operator at a challenge: each relation column is the weighted
/// sum of the public columns of the terms that name it.
pub struct Operator {
    pub alpha: Element,
    pub terms: Vec<Term>,
    pub target: Element,
    pub lookup_weight: Element,
}
fn powers(alpha: Element, degree: usize) -> Vec<Element> {
    let mut current = ONE;
    (0..degree)
        .map(|_| {
            let previous = current;
            current = times(current, alpha);
            previous
        })
        .collect()
}
impl Operator {
    /// The values of the relation's columns at the queries, column after
    /// column. The query evaluation is linear, so each column's values are
    /// the weighted sums of its public columns' values, and ones on every
    /// row are one at every query.
    pub fn at_queries(self, columns: usize, queries: &[u32]) -> Result<Vec<Element>, Error> {
        let count = queries.len();
        let mut output = vec![ZERO; columns * count];
        let mut evaluated = Vec::new();
        let mut weights = Vec::new();
        for term in self.terms {
            if term.weights.is_empty() {
                continue;
            }
            let values = match term.public {
                PublicColumn::Ones(degree) if degree == SYSTEMATIC => {
                    for (column, weight) in term.weights {
                        for value in &mut output[column * count..(column + 1) * count] {
                            *value = plus(*value, weight);
                        }
                    }
                    continue;
                }
                PublicColumn::Powers(degree) => powers(self.alpha, degree),
                PublicColumn::Ones(degree) => vec![ONE; degree],
                PublicColumn::Values(values) => values,
            };
            evaluated.push(values);
            weights.push(term.weights);
        }
        let values = evaluate_public_columns(evaluated, queries)?;
        for (weights, values) in weights.iter().zip(values.chunks(count)) {
            for (column, weight) in weights {
                for (target, value) in output[column * count..(column + 1) * count]
                    .iter_mut()
                    .zip(values)
                {
                    *target = plus(*target, times(*weight, *value));
                }
            }
        }
        Ok(output)
    }
    /// Every row of the relation's columns.
    #[cfg(any(test, feature = "test-support"))]
    pub fn columns(&self, columns: usize) -> Vec<Vec<Element>> {
        let mut output = vec![vec![ZERO; SYSTEMATIC]; columns];
        for term in &self.terms {
            let values = match &term.public {
                PublicColumn::Powers(degree) => powers(self.alpha, *degree),
                PublicColumn::Ones(degree) => vec![ONE; *degree],
                PublicColumn::Values(values) => values.clone(),
            };
            let stride = SYSTEMATIC / values.len();
            for (column, weight) in &term.weights {
                for (index, value) in values.iter().enumerate() {
                    let target = &mut output[*column][stride * index];
                    *target = plus(*target, times(*weight, *value));
                }
            }
        }
        output
    }
}

/// The builder of a relation's affine operator, whose statement is a header
/// and then a fixed sequence of polynomials. It takes the header, then each
/// polynomial's stream in order.
pub trait OperatorBuilder: Sized {
    type Error: From<Error>;
    const HEADER_BYTES: usize;
    const POLYNOMIALS: usize;
    /// The relation's column count.
    fn columns(profile: Profile) -> usize;
    /// Bytes of the polynomial at the index.
    fn polynomial_bytes(profile: Profile, index: usize) -> usize;
    /// The stream that fingerprints the polynomial at the index.
    fn polynomial_stream(
        profile: Profile,
        index: usize,
        alpha: Element,
    ) -> Result<PolynomialStream, Self::Error>;
    fn begin(profile: Profile, alpha: Element, header: &[u8]) -> Result<Self, Self::Error>;
    fn polynomial(&mut self, index: usize, stream: PolynomialStream) -> Result<(), Self::Error>;
    fn finish(self) -> Result<Operator, Self::Error>;
}

/// The operator at the challenge of a statement's header and polynomials.
pub fn operator<B: OperatorBuilder>(
    profile: Profile,
    alpha: Element,
    header: &[u8],
    polynomials: &[Vec<u8>],
) -> Result<Operator, B::Error> {
    let mut builder = B::begin(profile, alpha, header)?;
    if polynomials.len() != B::POLYNOMIALS {
        return Err(Error::Length.into());
    }
    for (index, bytes) in polynomials.iter().enumerate() {
        let mut stream = B::polynomial_stream(profile, index, alpha)?;
        for chunk in bytes.chunks(CHUNK_LIMIT) {
            stream.push(chunk)?;
        }
        builder.polynomial(index, stream)?;
    }
    builder.finish()
}

/// A statement of a header and then polynomials, as it streams in: its
/// digest, which must be the one the proof declares, and its operator's
/// values at the queries. A refusal stops the stream.
pub struct HeaderThenPolynomials<B: OperatorBuilder> {
    profile: Profile,
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    // The statement's digest, which a helper computes when there are helpers.
    hash: HashStream,
    header: Vec<u8>,
    builder: Option<B>,
    stream: Option<PolynomialStream>,
    index: usize,
    received: usize,
    failed: bool,
}
impl<B: OperatorBuilder> HeaderThenPolynomials<B> {
    pub fn new(
        profile: Profile,
        expected: [u8; 64],
        alpha: Element,
        queries: &[u32],
    ) -> Result<Self, B::Error> {
        if alpha.iter().any(|value| *value >= MODULUS) {
            return Err(Error::Parameters.into());
        }
        query::validate_indices_in(queries, EVALUATION_DOMAIN_SIZE)?;
        Ok(Self {
            profile,
            expected,
            alpha,
            queries: queries.to_vec(),
            hash: HashStream::new(Sponge::ProtocolHash),
            header: Vec::with_capacity(B::HEADER_BYTES),
            builder: None,
            stream: None,
            index: 0,
            received: 0,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), B::Error> {
        if self.failed {
            return Err(Error::Binding.into());
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<(), B::Error> {
        if bytes.len() > CHUNK_LIMIT {
            return Err(Error::Length.into());
        }
        self.hash.update(bytes);
        if self.header.len() < B::HEADER_BYTES {
            let count = bytes.len().min(B::HEADER_BYTES - self.header.len());
            self.header.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.header.len() == B::HEADER_BYTES {
                self.builder = Some(B::begin(self.profile, self.alpha, &self.header)?);
            }
        }
        while !bytes.is_empty() {
            if self.index == B::POLYNOMIALS {
                return Err(Error::Length.into());
            }
            let size = B::polynomial_bytes(self.profile, self.index);
            let stream = match &mut self.stream {
                Some(stream) => stream,
                None => {
                    self.stream
                        .insert(B::polynomial_stream(self.profile, self.index, self.alpha)?)
                }
            };
            let count = bytes.len().min(size - self.received);
            stream.push(&bytes[..count])?;
            bytes = &bytes[count..];
            self.received += count;
            if self.received == size {
                let (Some(builder), Some(stream)) = (self.builder.as_mut(), self.stream.take())
                else {
                    return Err(Error::Incomplete.into());
                };
                builder.polynomial(self.index, stream)?;
                self.index += 1;
                self.received = 0;
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<StatementOutput, B::Error> {
        if self.failed || self.index != B::POLYNOMIALS || self.hash.finish() != self.expected {
            return Err(Error::Binding.into());
        }
        let operator = self.builder.ok_or(Error::Binding)?.finish()?;
        let (target, lookup_weight) = (operator.target, operator.lookup_weight);
        let coefficients = operator
            .at_queries(B::columns(self.profile), &self.queries)
            .map_err(|_| Error::Arithmetic)?;
        Ok(StatementOutput {
            target,
            lookup_weight,
            coefficients,
        })
    }
}

#[cfg(test)]
#[path = "affine-tests.rs"]
mod tests;
