use crate::{
    field::{self, Element, MODULUS, ONE, ZERO},
    parameters::*,
};
use ballot_encryption::{
    encryption::{EncryptionWitness, LinkedBallotWitness, fhe_key_polynomial},
    packing::PackingMatrix,
};
use num_bigint::{BigInt, Sign};
use setup_stream_kernel::PolynomialStream;
pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
use sha3::{Digest, Sha3_512};
use supported_profile::{
    AUXILIARY_DEGREE, AUXILIARY_PLAINTEXT_MODULUS, FHE_LIMB_BITS, Family, PLAINTEXT_MODULUS,
    Profile, SETUP_ERROR_BITS, WORD_BITS, auxiliary_modulus,
};

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
/// Each encryption's family with the setup indices of its common polynomial
/// and its key, which the statement takes as inputs.
pub fn setup_inputs(profile: Profile) -> [(Family, usize, usize); 2] {
    [
        (
            Family::Fhe,
            profile.fhe_polynomial(0, 0),
            fhe_key_polynomial(profile),
        ),
        (
            Family::Auxiliary,
            profile.auxiliary_common_polynomial(),
            profile.auxiliary_key_polynomial(),
        ),
    ]
}
/// The statement header: its magic, the poll and inventory identities, the
/// roster position, the option count and the result length.
pub fn header(
    poll: &[u8; 64],
    inventory: &[u8; 64],
    position: usize,
    options: usize,
    top_count: usize,
) -> Result<Vec<u8>, Error> {
    let mut header = HEADER_MAGIC.to_vec();
    header.extend(poll);
    header.extend(inventory);
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
            context.inventory(),
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
                encryption.key.coefficients(),
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
            let mut parser = polynomial_stream(self.profile, index, alpha)?;
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
    coefficients: Vec<Vec<Element>>,
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
            coefficients: vec![vec![ZERO; SYSTEMATIC]; ballot_relation(profile).columns()],
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
            let degree = self.profile.family_degree(family(index));
            let adjoint = parser.adjoint().map_err(|_| Error::Encoding)?;
            let positive = if auxiliary {
                self.columns.auxiliary_positive()
            } else {
                self.columns.fhe_positive()
            };
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
            self.coefficients[columns.scores()][option] = field::subtract(
                self.coefficients[columns.scores()][option],
                field::multiply(packing_weight, value),
            );
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
                    self.coefficients[columns.scores()][option] = field::add(
                        self.coefficients[columns.scores()][option],
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
                for position in (0..SYSTEMATIC).step_by(stride) {
                    self.coefficients[column][position] =
                        field::add(self.coefficients[column][position], weight);
                }
                self.target = field::add(self.target, field::scale(weight, u128::from(half)));
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
        for column in 0..columns.words() {
            let offset = if column == columns.scores() {
                -1
            } else if narrow.contains(&column) {
                1 << (SETUP_ERROR_BITS - 1)
            } else {
                1 << (WORD_BITS - 1)
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
    profile: Profile,
    expected: [u8; 64],
    alpha: Element,
    queries: Vec<u32>,
    statement_bytes: usize,
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
            || <[u8; 64]>::from(self.hash.finalize()) != self.expected
        {
            return Err(Error::Binding);
        }
        let operator = self.builder.ok_or(Error::Shape)?.finish()?;
        let coefficients =
            setup_stream_kernel::evaluate_public_columns(operator.coefficients, &self.queries)
                .map_err(|_| Error::Arithmetic)?;
        Ok(StatementOutput {
            statement_digest: self.expected,
            target: operator.target,
            lookup_weight: operator.lookup_weight,
            coefficients,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ballot_encryption::packing::PackingWitness;
    use registration_credentials::identity::{PUBLIC_POLYNOMIAL_DOMAIN, identity};
    use setup_aggregate::{RetainedAggregatePolynomial, RetainedSetupInputs};
    use supported_profile::DEGREE;

    /// A uniform public key of the family, retained through the same
    /// digest-checked reader as a setup aggregate's key.
    fn retained_key(profile: Profile, index: usize, seed: u64) -> RetainedAggregatePolynomial {
        let family = profile.setup_family(index).unwrap();
        let modulus = BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(family));
        let half = &modulus >> 1usize;
        let mut state = seed;
        let values: Vec<BigInt> = (0..profile.family_degree(family))
            .map(|_| {
                let mut value = BigInt::from(0);
                for _ in 0..modulus.bits().div_ceil(64) + 1 {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    value = (value << 64usize) + BigInt::from(state);
                }
                let value = value % &modulus;
                if value > half {
                    value - &modulus
                } else {
                    value
                }
            })
            .collect();
        let bytes = encode_polynomial(&values, coefficient_bytes(profile, family)).unwrap();
        let mut record = b"SAV1".to_vec();
        record.extend([7; 64]);
        for body_index in profile.contribution_body_polynomials() {
            record.extend(if body_index == index {
                identity(PUBLIC_POLYNOMIAL_DOMAIN, &bytes).unwrap()
            } else {
                [0; 64]
            });
        }
        let inputs = RetainedSetupInputs::parse(profile, &record, [7; 64]).unwrap();
        let mut reader = inputs.read_polynomial(index).unwrap();
        let chunk = setup_aggregate::CHUNK_BYTES / coefficient_bytes(profile, family)
            * coefficient_bytes(profile, family);
        for (ordinal, part) in bytes.chunks(chunk).enumerate() {
            reader.push(ordinal * chunk, part).unwrap();
        }
        reader.finish().unwrap()
    }

    /// A true ballot of the profile: its statement and witness columns.
    pub(crate) fn synthetic_ballot(profile: Profile) -> (PublicStatement, Vec<Vec<u16>>) {
        let scores: Vec<u8> = (0..profile.options())
            .map(|option| [1, 10, 4, 7][option % 4])
            .collect();
        let packing = PackingWitness::new(&scores).unwrap();
        let [(_, _, fhe_key), (_, _, auxiliary_key)] = setup_inputs(profile);
        let fhe = EncryptionWitness::create(
            profile,
            retained_key(profile, fhe_key, 3),
            packing.message(),
        )
        .unwrap();
        let mut literal = vec![0; AUXILIARY_DEGREE];
        for (target, score) in literal.iter_mut().zip(&scores) {
            *target = i32::from(*score);
        }
        let auxiliary =
            EncryptionWitness::create(profile, retained_key(profile, auxiliary_key, 5), &literal)
                .unwrap();
        let header = header(
            &[1; 64],
            &[7; 64],
            profile.participants() - 1,
            profile.options(),
            profile.options(),
        )
        .unwrap();
        let statement = PublicStatement::from_parts(profile, header, &fhe, &auxiliary).unwrap();
        let columns = crate::columns::from_parts(profile, &packing, &fhe, &auxiliary).unwrap();
        (statement, columns.to_vec())
    }

    fn affine_value(
        statement: &PublicStatement,
        columns: &[Vec<u16>],
        alpha: Element,
    ) -> (Element, Element) {
        let operator = statement.operator(alpha).unwrap();
        let actual =
            operator
                .coefficients
                .iter()
                .zip(columns)
                .fold(ZERO, |sum, (coefficients, column)| {
                    coefficients
                        .iter()
                        .zip(column)
                        .fold(sum, |sum, (coefficient, value)| {
                            field::add(sum, field::scale(*coefficient, u128::from(*value)))
                        })
                });
        (actual, operator.target)
    }

    #[test]
    fn ballots_satisfy_the_affine_relation_at_the_smallest_and_widest_profiles() {
        for (participants, options) in [(3, 2), (16, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            let (statement, mut columns) = synthetic_ballot(profile);
            assert_eq!(columns.len(), ballot_relation(profile).columns());
            assert!(columns.iter().all(|column| column.len() == DEGREE));
            for alpha in [[13, 17, 19], [29, 31, 37]] {
                let (actual, target) = affine_value(&statement, &columns, alpha);
                assert_eq!(actual, target);
            }
            // A changed score, carry or auxiliary quotient breaks it.
            let layout = BallotColumns::new(profile);
            for (column, position) in [
                (layout.scores(), 0),
                (layout.fhe_carry(1, layout.fhe_limbs() - 2), 9),
                (layout.auxiliary_quotient(0), 16),
            ] {
                columns[column][position] ^= 1;
                let (actual, target) = affine_value(&statement, &columns, [13, 17, 19]);
                assert_ne!(actual, target);
                columns[column][position] ^= 1;
            }
        }
    }

    #[test]
    fn statements_of_another_profile_or_position_are_refused() {
        let profile = Profile::new(3, 2).unwrap();
        let (statement, _) = synthetic_ballot(profile);
        let mut other = PublicStatement {
            profile: Profile::new(3, 3).unwrap(),
            header: statement.header.clone(),
            polynomials: statement.polynomials.clone(),
        };
        assert!(other.operator([13, 17, 19]).is_err());
        other.profile = profile;
        other.header[132..134].copy_from_slice(&3u16.to_le_bytes());
        assert!(other.operator([13, 17, 19]).is_err());
        other.header = statement.header.clone();
        other.polynomials.pop();
        assert!(other.operator([13, 17, 19]).is_err());
        // Ciphertext bytes whose top coefficient exceeds half the modulus
        // are not canonical.
        let mut changed = statement.polynomials.clone();
        let width = coefficient_bytes(profile, Family::Fhe);
        changed[2][width - 1] = 0xff;
        let changed = PublicStatement {
            profile,
            header: statement.header.clone(),
            polynomials: changed,
        };
        assert!(changed.operator([13, 17, 19]).is_err());
        assert!(
            statement
                .polynomials
                .iter()
                .enumerate()
                .all(|(index, bytes)| bytes.len() == polynomial_bytes(profile, index))
        );
    }
}
