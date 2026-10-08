use ballot_encryption::{
    encryption::{EncryptionWitness, LinkedBallotWitness, fhe_key_polynomial},
    packing::PackingMatrix,
};
use num_bigint::{BigInt, Sign};
use parallel_work::ProtocolHash;
use parallel_work::{HashStream, Sponge};
use setup_stream_kernel::PolynomialStream;
pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
use supported_profile::{
    AUXILIARY_DEGREE, AUXILIARY_PLAINTEXT_MODULUS, FHE_LIMB_BITS, Family, PLAINTEXT_MODULUS,
    Profile, SETUP_ERROR_BITS, WORD_BITS, auxiliary_modulus, relation::*,
};
use word_proof::{
    affine::{Operator, PublicColumn, Term},
    field::{self, Element, MODULUS, ONE, ZERO},
};

use std::collections::BTreeMap;

#[derive(Debug)]
pub enum Error {
    Shape,
    Encoding,
    Binding,
    Arithmetic,
}
/// For the FHE and then the auxiliary encryption: the common polynomial, the
/// key and both ciphertext components.
const POLYNOMIALS: usize = 8;
const HEADER_MAGIC: &[u8; 4] = b"LBS1";
pub struct PublicStatement {
    pub profile: Profile,
    pub header: Vec<u8>,
    pub polynomials: Vec<Vec<u8>>,
}
fn family(index: usize) -> Family {
    if index < POLYNOMIALS / 2 {
        Family::Fhe
    } else {
        Family::Auxiliary
    }
}
/// Bytes of one encoded coefficient of a family: a sign byte and the
/// magnitude.
pub fn coefficient_bytes(profile: Profile, family: Family) -> usize {
    1 + profile.family_magnitude_bytes(family)
}
/// Bytes of one statement polynomial.
pub fn polynomial_bytes(profile: Profile, index: usize) -> usize {
    profile.family_degree(family(index)) * coefficient_bytes(profile, family(index))
}
/// The FHE common and aggregate key indices. The auxiliary pair is derived
/// locally and has no setup-polynomial or host-delivery index.
pub fn setup_input(profile: Profile) -> (Family, usize, usize) {
    (
        Family::Fhe,
        profile.fhe_polynomial(0, 0),
        fhe_key_polynomial(profile),
    )
}
/// The statement header: its magic, the poll and setup identities, the
/// roster position, the option count and the result length.
pub fn header(
    poll: &[u8; 64],
    setup_identity: &[u8; 64],
    position: usize,
    options: usize,
    top_count: usize,
) -> Result<Vec<u8>, Error> {
    let mut header = HEADER_MAGIC.to_vec();
    header.extend(poll);
    header.extend(setup_identity);
    header.extend(
        u16::try_from(position)
            .map_err(|_| Error::Shape)?
            .to_le_bytes(),
    );
    header.push(u8::try_from(options).map_err(|_| Error::Shape)?);
    header.push(u8::try_from(top_count).map_err(|_| Error::Shape)?);
    Ok(header)
}
fn polynomial_stream(
    profile: Profile,
    index: usize,
    alpha: Element,
) -> Result<PolynomialStream, Error> {
    let family = family(index);
    PolynomialStream::new(
        &profile.family_modulus(family),
        profile.family_degree(family),
        FHE_LIMB_BITS,
        alpha,
    )
    .map_err(|_| Error::Arithmetic)
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
        let context = &witness.context;
        let header = header(
            &context.poll().identity(),
            context.setup_identity(),
            context.position(),
            context.poll().manifest().option_count(),
            usize::from(context.poll().top_count()),
        )?;
        Self::from_parts(context.profile(), header, &witness.fhe, &witness.auxiliary)
    }
    pub(crate) fn from_parts(
        profile: Profile,
        header: Vec<u8>,
        fhe: &EncryptionWitness,
        auxiliary: &EncryptionWitness,
    ) -> Result<Self, Error> {
        let mut polynomials = Vec::with_capacity(POLYNOMIALS);
        for (encryption, family) in [(fhe, Family::Fhe), (auxiliary, Family::Auxiliary)] {
            let width = coefficient_bytes(profile, family);
            for values in [
                &encryption.common,
                &encryption.key,
                &encryption.components[0].coefficients,
                &encryption.components[1].coefficients,
            ] {
                polynomials.push(encode_polynomial(values, width)?);
            }
        }
        Ok(Self {
            profile,
            header,
            polynomials,
        })
    }
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
            for chunk in bytes.chunks(1 << 20) {
                parser.push(chunk).map_err(|_| Error::Encoding)?;
            }
            builder.polynomial(index, parser)?;
        }
        builder.finish()
    }
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
/// A public magnitude in FHE limbs, each weighted by a power of the limb
/// weight.
fn public_digits(bytes: &[u8], limb_weight: Element) -> Element {
    bytes
        .chunks(FHE_LIMB_BITS / 8)
        .rev()
        .fold(ZERO, |sum, chunk| {
            let mut word = [0; 16];
            word[..chunk.len()].copy_from_slice(chunk);
            field::add(
                field::multiply(sum, limb_weight),
                [u128::from_le_bytes(word), 0, 0],
            )
        })
}
/// Rows of the ballot equations: each FHE ciphertext component's limbs,
/// one ring degree per limb, then the packing equation, then each auxiliary
/// ciphertext component, then the secrets' supports.
struct Builder {
    profile: Profile,
    columns: BallotColumns,
    alpha: Element,
    column_count: usize,
    // Each column's weight on the powers of alpha and on ones, by degree;
    // each positive support column's weighted adjoints, which its negative
    // column subtracts; and the scores column's rows.
    powers: BTreeMap<usize, Vec<Element>>,
    ones: BTreeMap<usize, Vec<Element>>,
    adjoints: BTreeMap<usize, Vec<Element>>,
    scores: Vec<Element>,
    target: Element,
    consumed: usize,
}
impl Builder {
    fn new(profile: Profile, alpha: Element, header: &[u8]) -> Result<Self, Error> {
        registration_credentials::ballot_body::check_context(profile, header)
            .map_err(|_| Error::Shape)?;
        Ok(Self {
            profile,
            columns: BallotColumns::new(profile),
            alpha,
            column_count: ballot_relation(profile).columns(),
            powers: BTreeMap::new(),
            ones: BTreeMap::new(),
            adjoints: BTreeMap::new(),
            scores: vec![ZERO; profile.options()],
            target: ZERO,
            consumed: 0,
        })
    }
    fn fhe_row(&self, component: usize) -> usize {
        component * self.columns.fhe_limbs() * SYSTEMATIC
    }
    fn packing_row(&self) -> usize {
        self.fhe_row(2)
    }
    fn auxiliary_row(&self, component: usize) -> usize {
        self.packing_row() + SYSTEMATIC + component * AUXILIARY_DEGREE
    }
    /// Adds the weight to the column's weight on the powers of alpha at
    /// every (SYSTEMATIC / degree)-th row.
    fn add_geometric(&mut self, column: usize, weight: Element, degree: usize) {
        let count = self.column_count;
        let weights = self
            .powers
            .entry(degree)
            .or_insert_with(|| vec![ZERO; count]);
        weights[column] = field::add(weights[column], weight);
    }
    fn polynomial(&mut self, index: usize, parser: PolynomialStream) -> Result<(), Error> {
        if self.consumed != index || index >= POLYNOMIALS {
            return Err(Error::Shape);
        }
        self.consumed += 1;
        let auxiliary = family(index) == Family::Auxiliary;
        let local = index % (POLYNOMIALS / 2);
        // The common polynomial and the second ciphertext component enter
        // the second component's equation; the key and the first component
        // enter the first's.
        let component = usize::from(local == 0 || local == 3);
        let weight = power(
            self.alpha,
            if auxiliary {
                self.auxiliary_row(component)
            } else {
                self.fhe_row(component)
            },
        );
        if local < 2 {
            let adjoint = parser.adjoint().map_err(|_| Error::Encoding)?;
            let positive = if auxiliary {
                self.columns.auxiliary_positive()
            } else {
                self.columns.fhe_positive()
            };
            let combined = self
                .adjoints
                .entry(positive)
                .or_insert_with(|| vec![ZERO; adjoint.len()]);
            if combined.len() != adjoint.len() {
                return Err(Error::Shape);
            }
            for (target, value) in combined.iter_mut().zip(adjoint) {
                *target = field::add(*target, field::multiply(weight, value));
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
        if self.consumed != POLYNOMIALS {
            return Err(Error::Shape);
        }
        let columns = self.columns;
        let limb_weight = power(self.alpha, SYSTEMATIC);
        let modulus_bytes = self.profile.ciphertext_modulus().to_bytes();
        let modulus = public_digits(&modulus_bytes, limb_weight);
        let raw_modulus = BigInt::from_bytes_le(Sign::Plus, &modulus_bytes);
        let scale = public_digits(
            &((&raw_modulus - BigInt::from(1)) / BigInt::from(PLAINTEXT_MODULUS))
                .to_bytes_le()
                .1,
            limb_weight,
        );
        let radix = [1u128 << FHE_LIMB_BITS, 0, 0];
        let word = 1u128 << WORD_BITS;
        for component in 0..2 {
            let weight = power(self.alpha, self.fhe_row(component));
            self.add_geometric(
                columns.fhe_quotient(component),
                field::subtract(ZERO, field::multiply(weight, modulus)),
                SYSTEMATIC,
            );
            self.add_geometric(columns.fhe_error(component), weight, SYSTEMATIC);
            for carry in 0..columns.fhe_limbs() - 1 {
                let carry_weight = field::multiply(
                    weight,
                    field::multiply(
                        power(limb_weight, carry),
                        field::subtract(limb_weight, radix),
                    ),
                );
                self.add_geometric(
                    columns.fhe_carry(component, carry),
                    carry_weight,
                    SYSTEMATIC,
                );
            }
            if component == 0 {
                self.add_geometric(columns.plaintext(), scale, SYSTEMATIC);
                self.add_geometric(
                    columns.plaintext_high_bit(),
                    field::scale(scale, word),
                    SYSTEMATIC,
                );
            }
        }
        let packing_weight = power(self.alpha, self.packing_row());
        self.add_geometric(columns.plaintext(), packing_weight, SYSTEMATIC);
        self.add_geometric(
            columns.plaintext_high_bit(),
            field::scale(packing_weight, word),
            SYSTEMATIC,
        );
        self.add_geometric(
            columns.packing_quotient(),
            field::scale(packing_weight, signed(-i64::from(PLAINTEXT_MODULUS))),
            SYSTEMATIC,
        );
        let options = self.profile.options();
        let matrix = PackingMatrix::new(options).map_err(|_| Error::Shape)?;
        let geometric = powers(self.alpha, SYSTEMATIC);
        for option in 0..options {
            let column = matrix.column(option).map_err(|_| Error::Shape)?;
            let value = column
                .iter()
                .zip(&geometric)
                .fold(ZERO, |sum, (coefficient, weight)| {
                    field::add(sum, field::scale(*weight, signed(i64::from(*coefficient))))
                });
            self.scores[option] =
                field::subtract(self.scores[option], field::multiply(packing_weight, value));
        }
        let mut modulus_word = [0; 16];
        modulus_word[..auxiliary_modulus().len()].copy_from_slice(auxiliary_modulus());
        let auxiliary_modulus = u128::from_le_bytes(modulus_word);
        let auxiliary_scale = (auxiliary_modulus - 1) / u128::from(AUXILIARY_PLAINTEXT_MODULUS);
        for component in 0..2 {
            let weight = power(self.alpha, self.auxiliary_row(component));
            self.add_geometric(
                columns.auxiliary_quotient(component),
                field::scale(weight, MODULUS - auxiliary_modulus),
                AUXILIARY_DEGREE,
            );
            self.add_geometric(columns.auxiliary_error(component), weight, AUXILIARY_DEGREE);
            if component == 0 {
                // The auxiliary plaintext carries each score at its option's
                // coefficient.
                for (option, point) in geometric.iter().take(options).enumerate() {
                    self.scores[option] = field::add(
                        self.scores[option],
                        field::scale(field::multiply(weight, *point), auxiliary_scale),
                    );
                }
            }
        }
        // Each support column sums to half of its secret's support.
        let relation = ballot_relation(self.profile);
        let mut row = self.auxiliary_row(2);
        for pair in 0..relation.support_pairs() {
            let (positive, negative) = relation.zero_product_columns(pair);
            let (stride, half) = relation.support(pair);
            for column in [positive, negative] {
                let weight = power(self.alpha, row);
                row += 1;
                let count = self.column_count;
                let weights = self
                    .ones
                    .entry(SYSTEMATIC / stride)
                    .or_insert_with(|| vec![ZERO; count]);
                weights[column] = field::add(weights[column], weight);
                self.target = field::add(self.target, field::scale(weight, u128::from(half)));
            }
        }
        let nonzero = |weights: Vec<Element>| -> Vec<(usize, Element)> {
            weights
                .into_iter()
                .enumerate()
                .filter(|(_, weight)| *weight != ZERO)
                .collect()
        };
        let mut terms = Vec::new();
        for (degree, weights) in std::mem::take(&mut self.powers) {
            terms.push(Term {
                public: PublicColumn::Powers(degree),
                weights: nonzero(weights),
            });
        }
        for (degree, weights) in std::mem::take(&mut self.ones) {
            terms.push(Term {
                public: PublicColumn::Ones(degree),
                weights: nonzero(weights),
            });
        }
        for (positive, adjoint) in std::mem::take(&mut self.adjoints) {
            terms.push(Term {
                public: PublicColumn::Values(adjoint),
                weights: vec![(positive, ONE), (positive + 1, field::subtract(ZERO, ONE))],
            });
        }
        let mut scores = vec![ZERO; SYSTEMATIC];
        scores[..options].copy_from_slice(&self.scores);
        terms.push(Term {
            public: PublicColumn::Values(scores),
            weights: vec![(columns.scores(), ONE)],
        });
        // Each column's rows sum to its weighted public columns' sums.
        let mut sums = vec![ZERO; self.column_count];
        for term in &terms {
            let sum = term.public.sum(self.alpha);
            for (column, weight) in &term.weights {
                sums[*column] = field::add(sums[*column], field::multiply(*weight, sum));
            }
        }
        // Signed words are offset by half their range and scores less one
        // are stored.
        let narrow = [
            columns.fhe_error(0),
            columns.fhe_error(1),
            columns.auxiliary_error(0),
            columns.auxiliary_error(1),
        ];
        for (column, sum) in sums.into_iter().enumerate().take(columns.words()) {
            let offset = if column == columns.scores() {
                -1
            } else if narrow.contains(&column) {
                1 << (SETUP_ERROR_BITS - 1)
            } else {
                1 << (WORD_BITS - 1)
            };
            self.target = field::add(self.target, field::scale(sum, signed(offset)));
        }
        Ok(Operator {
            alpha: self.alpha,
            terms,
            target: self.target,
            lookup_weight: power(self.alpha, row),
        })
    }
}

pub struct StatementStream {
    profile: Profile,
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    statement_bytes: usize,
    // The statement's digest, which a helper computes when there are helpers.
    hash: HashStream,
    header: Vec<u8>,
    builder: Option<Builder>,
    parser: Option<PolynomialStream>,
    polynomial: usize,
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
            expected,
            alpha,
            queries: queries.to_vec(),
            statement_bytes: ballot_relation(profile).statement_bytes(),
            hash: HashStream::new(Sponge::ProtocolHash),
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
        if bytes.len() > 1 << 20 || bytes.len() > self.statement_bytes - self.consumed {
            return Err(Error::Shape);
        }
        self.hash.update(bytes);
        self.consumed += bytes.len();
        if self.header.len() < BALLOT_HEADER_BYTES {
            let count = bytes.len().min(BALLOT_HEADER_BYTES - self.header.len());
            self.header.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.header.len() == BALLOT_HEADER_BYTES {
                self.builder = Some(Builder::new(self.profile, self.alpha, &self.header)?);
            }
        }
        while !bytes.is_empty() {
            if self.polynomial >= POLYNOMIALS {
                return Err(Error::Shape);
            }
            let size = polynomial_bytes(self.profile, self.polynomial);
            if self.parser.is_none() {
                self.parser = Some(polynomial_stream(
                    self.profile,
                    self.polynomial,
                    self.alpha,
                )?);
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
            || self.consumed != self.statement_bytes
            || self.polynomial != POLYNOMIALS
            || self.parser.is_some()
            || self.hash.finish() != self.expected
        {
            return Err(Error::Binding);
        }
        let operator = self.builder.ok_or(Error::Shape)?.finish()?;
        let (target, lookup_weight) = (operator.target, operator.lookup_weight);
        let coefficients = operator
            .at_queries(ballot_relation(self.profile).columns(), &self.queries)
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
#[path = "reference/dense-operator.rs"]
mod dense_operator;

#[cfg(test)]
#[path = "statement-tests.rs"]
pub(crate) mod tests;
