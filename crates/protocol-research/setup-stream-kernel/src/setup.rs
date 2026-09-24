use super::{
    CHUNK_LIMIT, Element, Error, MODULUS, ONE, PARAMETERS, PolynomialStream, ZERO, arithmetic,
    minus, plus, power, query, times,
};
use sha3::{Digest, Sha3_512};

const WORD_COLUMNS: usize = 333;
const BOOLEAN_COLUMNS: usize = 32;
const COLUMNS: usize = WORD_COLUMNS + BOOLEAN_COLUMNS;
const POLYNOMIALS: usize = 75;
const HEADER_LENGTH: usize = 145;
const RADIX: i128 = 1i128 << 96;
const SHARE_SCALE: i128 = 998_244_353;

fn base(value: i128) -> u128 {
    if value < 0 {
        MODULUS - value.unsigned_abs()
    } else {
        value as u128
    }
}
fn scale(value: Element, scalar: u128) -> Element {
    value.map(|entry| arithmetic::multiply(entry, scalar))
}
fn fingerprint(bytes: &[u8], weight: Element) -> Element {
    let mut result = ZERO;
    for limb in (0..bytes.len().div_ceil(12)).rev() {
        let start = limb * 12;
        let length = 12.min(bytes.len() - start);
        let mut word = [0; 16];
        word[..length].copy_from_slice(&bytes[start..start + length]);
        result = plus(times(result, weight), [u128::from_le_bytes(word), 0, 0]);
    }
    result
}
fn signed_fingerprint(value: i128, weight: Element) -> Element {
    let result = fingerprint(&value.unsigned_abs().to_le_bytes(), weight);
    if value < 0 {
        minus(ZERO, result)
    } else {
        result
    }
}

#[derive(Clone, Copy)]
struct Profile {
    degree: usize,
    auxiliary_degree: usize,
    fhe_half_support: usize,
    share_half_support: usize,
    auxiliary_half_support: usize,
}
impl Profile {
    const FULL: Self = Self {
        degree: 65_536,
        auxiliary_degree: 4_096,
        fhe_half_support: 512,
        share_half_support: 128,
        auxiliary_half_support: 128,
    };
    fn header(self) -> [u8; HEADER_LENGTH] {
        let mut header = [0; HEADER_LENGTH];
        header[..4].copy_from_slice(b"SCO1");
        header[4..8].copy_from_slice(&(self.degree as u32).to_le_bytes());
        header[8..12].copy_from_slice(&(self.auxiliary_degree as u32).to_le_bytes());
        header[12..].copy_from_slice(&PARAMETERS[4..]);
        header
    }
    fn encoded_length(self) -> usize {
        HEADER_LENGTH
            + 42 * self.degree * 109
            + 31 * self.degree * 21
            + 2 * self.auxiliary_degree * 6
    }
    fn polynomial(self, index: usize) -> (u32, usize) {
        if index < 42 {
            (0, self.degree)
        } else if index < 73 {
            (1, self.degree)
        } else {
            (2, self.auxiliary_degree)
        }
    }
}

#[derive(Clone)]
struct Variable {
    terms: Vec<(usize, i128)>,
    offset: i128,
    degree: usize,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct GeometryKey {
    degree: usize,
    automorphism: usize,
    shift: usize,
    constant: bool,
}
impl GeometryKey {
    fn identity(degree: usize) -> Self {
        Self {
            degree,
            automorphism: 1,
            shift: 0,
            constant: false,
        }
    }
    fn shifted(degree: usize, shift: usize) -> Self {
        Self {
            shift: shift % (2 * degree),
            ..Self::identity(degree)
        }
    }
}
struct Geometry {
    sum: Element,
    queries: Vec<Element>,
}
enum PublicUse {
    Common(Variable, Element),
    Value(Element),
}

struct Accumulator {
    profile: Profile,
    alpha: Element,
    indices: Vec<u32>,
    coefficients: Vec<Element>,
    target: Element,
    weight: Element,
    next_word: usize,
    next_boolean: usize,
    supports: Vec<(usize, usize, usize)>,
    geometries: Vec<(GeometryKey, Geometry)>,
    uses: Vec<Vec<PublicUse>>,
    recorded_terms: Option<Vec<ProverFixedTerm>>,
}
impl Accumulator {
    fn new(profile: Profile, alpha: Element, indices: &[u32]) -> Result<Self, Error> {
        query::validate_indices_in(indices, 4 * profile.degree)?;
        Self::build(profile, alpha, indices, false)
    }
    fn build(
        profile: Profile,
        alpha: Element,
        indices: &[u32],
        record_terms: bool,
    ) -> Result<Self, Error> {
        let mut result = Self {
            profile,
            alpha,
            indices: indices.to_vec(),
            coefficients: vec![ZERO; COLUMNS * indices.len()],
            target: ZERO,
            weight: ONE,
            next_word: 0,
            next_boolean: WORD_COLUMNS,
            supports: Vec::new(),
            geometries: Vec::new(),
            uses: (0..POLYNOMIALS).map(|_| Vec::new()).collect(),
            recorded_terms: record_terms.then(Vec::new),
        };
        let secret = result.sparse(profile.degree, profile.fhe_half_support);
        let auxiliary = result.sparse(profile.degree, profile.fhe_half_support);
        let ephemerals: Vec<Variable> = (0..10)
            .map(|_| result.sparse(profile.degree, profile.share_half_support))
            .collect();
        let auxiliary_secret =
            result.sparse(profile.auxiliary_degree, profile.auxiliary_half_support);
        let sharing: Vec<Variable> = (0..3).map(|_| result.signed(114, profile.degree)).collect();
        let limb_weight = power(alpha, profile.degree);
        for gadget in 0..6 {
            let factor = scale(
                power(limb_weight, 144 * gadget / 96),
                1u128 << (144 * gadget % 96),
            );
            let first = 7 * gadget;
            result.key(first, first + 1, &secret, None)?;
            result.key(
                first,
                first + 2,
                &auxiliary,
                Some((&secret, minus(ZERO, factor), 1)),
            )?;
            result.key(first + 3, first + 4, &secret, Some((&auxiliary, factor, 1)))?;
            result.key(
                first + 5,
                first + 6,
                &secret,
                Some((&secret, minus(ZERO, factor), 5)),
            )?;
        }
        for (recipient, ephemeral) in ephemerals.iter().enumerate() {
            let first = 43 + 3 * recipient;
            result.encrypted_share(
                first,
                first + 1,
                ephemeral,
                Some((&secret, &sharing, recipient * profile.degree / 8)),
            )?;
            result.encrypted_share(42, first + 2, ephemeral, None)?;
        }
        result.auxiliary_key(&auxiliary_secret)?;
        for (column, degree, required) in result.supports.clone() {
            let variable = Variable {
                terms: vec![(column, 1)],
                offset: 0,
                degree,
            };
            let key = GeometryKey {
                constant: true,
                ..GeometryKey::identity(degree)
            };
            result.put(&variable, key, result.weight)?;
            result.target = plus(result.target, scale(result.weight, required as u128));
            result.weight = times(result.weight, alpha);
        }
        if result.next_word != WORD_COLUMNS
            || result.next_boolean != COLUMNS
            || result.uses.iter().any(Vec::is_empty)
        {
            return Err(Error::Arithmetic);
        }
        Ok(result)
    }
    fn signed(&mut self, width: usize, degree: usize) -> Variable {
        let mut terms = Vec::new();
        let mut remaining = width;
        let mut shift = 0;
        while remaining >= 16 || shift == 0 {
            let bits = remaining.min(16);
            terms.push((self.next_word, 1i128 << shift));
            self.next_word += 1;
            remaining -= bits;
            shift += bits;
        }
        for bit in 0..remaining {
            terms.push((self.next_boolean, 1i128 << (shift + bit)));
            self.next_boolean += 1;
        }
        Variable {
            terms,
            offset: -(1i128 << (width - 1)),
            degree,
        }
    }
    fn sparse(&mut self, degree: usize, half_support: usize) -> Variable {
        let positive = self.next_boolean;
        self.next_boolean += 2;
        self.supports.extend([
            (positive, degree, half_support),
            (positive + 1, degree, half_support),
        ]);
        Variable {
            terms: vec![(positive, 1), (positive + 1, -1)],
            offset: 0,
            degree,
        }
    }
    fn geometry(&mut self, key: GeometryKey) -> Result<usize, Error> {
        if let Some(index) = self
            .geometries
            .iter()
            .position(|(existing, _)| *existing == key)
        {
            return Ok(index);
        }
        let values = if key.constant {
            vec![ONE; key.degree]
        } else {
            let mut powers = Vec::with_capacity(key.degree);
            let mut value = ONE;
            for _ in 0..key.degree {
                powers.push(value);
                value = times(value, self.alpha);
            }
            (0..key.degree)
                .map(|position| {
                    let exponent = (position * key.automorphism + key.shift) % (2 * key.degree);
                    let value = powers[exponent % key.degree];
                    if exponent < key.degree {
                        value
                    } else {
                        minus(ZERO, value)
                    }
                })
                .collect()
        };
        let sum = values.iter().copied().fold(ZERO, plus);
        let queries = if self.indices.is_empty() {
            Vec::new()
        } else {
            query::evaluate_in(values, &self.indices, self.profile.degree)?
        };
        self.geometries.push((key, Geometry { sum, queries }));
        Ok(self.geometries.len() - 1)
    }
    fn put(&mut self, variable: &Variable, key: GeometryKey, weight: Element) -> Result<(), Error> {
        if variable.degree != key.degree {
            return Err(Error::Arithmetic);
        }
        let index = self.geometry(key)?;
        let geometry = &self.geometries[index].1;
        self.target = minus(
            self.target,
            scale(times(weight, geometry.sum), base(variable.offset)),
        );
        if let Some(terms) = &mut self.recorded_terms {
            terms.push(ProverFixedTerm {
                degree: key.degree,
                automorphism: key.automorphism,
                shift: key.shift,
                constant: key.constant,
                columns: variable
                    .terms
                    .iter()
                    .map(|(column, factor)| (*column, scale(weight, base(*factor))))
                    .collect(),
            });
        }
        for (point, value) in geometry.queries.iter().enumerate() {
            let weighted = times(weight, *value);
            for (column, factor) in &variable.terms {
                let output = column * self.indices.len() + point;
                self.coefficients[output] =
                    plus(self.coefficients[output], scale(weighted, base(*factor)));
            }
        }
        Ok(())
    }
    fn register(
        &mut self,
        common: usize,
        value: usize,
        variable: &Variable,
        value_sign: i128,
    ) -> Result<(), Error> {
        if variable.offset != 0 {
            return Err(Error::Arithmetic);
        }
        self.uses[common].push(PublicUse::Common(variable.clone(), self.weight));
        self.uses[value].push(PublicUse::Value(scale(self.weight, base(value_sign))));
        Ok(())
    }
    fn key(
        &mut self,
        common: usize,
        value: usize,
        secret: &Variable,
        direct: Option<(&Variable, Element, usize)>,
    ) -> Result<(), Error> {
        let degree = self.profile.degree;
        let quotient = self.signed(16, degree);
        let carries: Vec<Variable> = (0..8).map(|_| self.signed(16, degree)).collect();
        let error = self.signed(7, degree);
        let z = power(self.alpha, degree);
        let key = GeometryKey::identity(degree);
        self.register(common, value, secret, 1)?;
        if let Some((variable, factor, automorphism)) = direct {
            self.put(
                variable,
                GeometryKey {
                    automorphism,
                    ..key
                },
                times(self.weight, factor),
            )?;
        }
        self.put(
            &quotient,
            key,
            minus(
                ZERO,
                times(self.weight, fingerprint(&PARAMETERS[4..112], z)),
            ),
        )?;
        self.put(&error, key, minus(ZERO, self.weight))?;
        let mut factor = minus(z, [RADIX as u128, 0, 0]);
        for carry in &carries {
            self.put(carry, key, times(self.weight, factor))?;
            factor = times(factor, z);
        }
        self.weight = times(self.weight, power(z, 9));
        Ok(())
    }
    fn encrypted_share(
        &mut self,
        common: usize,
        value: usize,
        ephemeral: &Variable,
        shared: Option<(&Variable, &[Variable], usize)>,
    ) -> Result<(), Error> {
        let degree = self.profile.degree;
        let quotient = self.signed(16, degree);
        let carry = self.signed(if shared.is_some() { 32 } else { 16 }, degree);
        let error = self.signed(7, degree);
        let z = power(self.alpha, degree);
        let key = GeometryKey::identity(degree);
        self.register(common, value, ephemeral, -1)?;
        if let Some((secret, sharing, point)) = shared {
            self.put(secret, key, scale(self.weight, SHARE_SCALE as u128))?;
            let mut offsets = vec![0i128; degree];
            for (index, coefficient) in sharing.iter().enumerate() {
                let shift = point * (index + 1);
                let key = GeometryKey::shifted(degree, shift);
                let low = Variable {
                    terms: coefficient
                        .terms
                        .iter()
                        .copied()
                        .filter(|(_, factor)| *factor < RADIX)
                        .collect(),
                    offset: -RADIX / 2,
                    degree,
                };
                let high = Variable {
                    terms: coefficient
                        .terms
                        .iter()
                        .copied()
                        .filter(|(_, factor)| *factor >= RADIX)
                        .map(|(column, factor)| (column, factor / RADIX))
                        .collect(),
                    offset: -(1i128 << (114 - 96 - 1)),
                    degree,
                };
                self.put(&low, key, scale(self.weight, SHARE_SCALE as u128))?;
                self.put(
                    &high,
                    key,
                    scale(times(self.weight, z), SHARE_SCALE as u128),
                )?;
                for input in 0..degree {
                    let exponent = (input + shift) % (2 * degree);
                    let offset = SHARE_SCALE * (RADIX / 2);
                    offsets[exponent % degree] += if exponent < degree { offset } else { -offset };
                }
            }
            let mut current = ONE;
            let mut sum = ZERO;
            for offset in offsets {
                sum = plus(sum, times(current, signed_fingerprint(offset, z)));
                current = times(current, self.alpha);
            }
            self.target = minus(self.target, times(self.weight, sum));
        }
        self.put(
            &quotient,
            key,
            minus(
                ZERO,
                times(self.weight, fingerprint(&PARAMETERS[112..132], z)),
            ),
        )?;
        self.put(
            &carry,
            key,
            times(self.weight, minus(z, [RADIX as u128, 0, 0])),
        )?;
        self.put(&error, key, self.weight)?;
        self.weight = times(self.weight, times(z, z));
        Ok(())
    }
    fn auxiliary_key(&mut self, secret: &Variable) -> Result<(), Error> {
        let degree = self.profile.auxiliary_degree;
        let quotient = self.signed(16, degree);
        let error = self.signed(7, degree);
        let key = GeometryKey::identity(degree);
        let z = power(self.alpha, degree);
        self.register(73, 74, secret, 1)?;
        self.put(
            &quotient,
            key,
            minus(
                ZERO,
                times(self.weight, fingerprint(&PARAMETERS[132..137], z)),
            ),
        )?;
        self.put(&error, key, minus(ZERO, self.weight))?;
        self.weight = times(self.weight, z);
        Ok(())
    }
    fn is_common(&self, polynomial: usize) -> bool {
        self.uses[polynomial]
            .iter()
            .any(|usage| matches!(usage, PublicUse::Common(_, _)))
    }
    fn consume(&mut self, polynomial: usize, parser: PolynomialStream) -> Result<(), Error> {
        if self.is_common(polynomial) {
            let values = parser.finish_queries_in(&self.indices, self.profile.degree)?;
            for usage in &self.uses[polynomial] {
                let PublicUse::Common(variable, weight) = usage else {
                    return Err(Error::Arithmetic);
                };
                for (point, value) in values.iter().enumerate() {
                    let weighted = times(*weight, *value);
                    for (column, factor) in &variable.terms {
                        let output = column * self.indices.len() + point;
                        self.coefficients[output] =
                            plus(self.coefficients[output], scale(weighted, base(*factor)));
                    }
                }
            }
        } else {
            let value = parser.finish_value()?;
            for usage in &self.uses[polynomial] {
                let PublicUse::Value(weight) = usage else {
                    return Err(Error::Arithmetic);
                };
                self.target = minus(self.target, times(*weight, value));
            }
        }
        Ok(())
    }
}

pub struct ProverFixedTerm {
    pub degree: usize,
    pub automorphism: usize,
    pub shift: usize,
    pub constant: bool,
    pub columns: Vec<(usize, Element)>,
}
pub struct ProverOperatorPlan {
    pub fixed_terms: Vec<ProverFixedTerm>,
    pub common_columns: Vec<Vec<(usize, Element)>>,
    pub value_weights: Vec<Element>,
    pub target_offset: Element,
    pub lookup_weight: Element,
}
pub fn prover_operator_plan(alpha: Element) -> Result<ProverOperatorPlan, Error> {
    if alpha.iter().any(|value| *value >= MODULUS) {
        return Err(Error::Parameters);
    }
    let mut accumulator = Accumulator::build(Profile::FULL, alpha, &[], true)?;
    let mut common_columns = vec![Vec::new(); POLYNOMIALS];
    let mut value_weights = vec![ZERO; POLYNOMIALS];
    for (index, uses) in accumulator.uses.into_iter().enumerate() {
        for usage in uses {
            match usage {
                PublicUse::Common(variable, weight) => {
                    for (column, factor) in variable.terms {
                        common_columns[index].push((column, scale(weight, base(factor))));
                    }
                }
                PublicUse::Value(weight) => {
                    value_weights[index] = plus(value_weights[index], weight)
                }
            }
        }
    }
    Ok(ProverOperatorPlan {
        fixed_terms: accumulator.recorded_terms.take().ok_or(Error::Arithmetic)?,
        common_columns,
        value_weights,
        target_offset: accumulator.target,
        lookup_weight: accumulator.weight,
    })
}

// Arithmetic output for one fully parsed statement. This is not setup proof
// acceptance and cannot create a voting capability.
pub struct SetupStatementOutput {
    pub statement_digest: [u8; 64],
    pub target: Element,
    pub lookup_weight: Element,
    pub coefficients: Vec<Element>,
}
impl SetupStatementOutput {
    pub fn encoded_length(&self) -> usize {
        64 + 48 * (2 + self.coefficients.len())
    }
    pub fn copy_range(&self, mut offset: usize, mut output: &mut [u8]) -> Result<(), Error> {
        if output.len() > CHUNK_LIMIT
            || offset > self.encoded_length()
            || output.len() > self.encoded_length() - offset
        {
            return Err(Error::Length);
        }
        while !output.is_empty() {
            if offset < 64 {
                let length = output.len().min(64 - offset);
                output[..length].copy_from_slice(&self.statement_digest[offset..offset + length]);
                offset += length;
                output = &mut output[length..];
            } else {
                let element_index = (offset - 64) / 48;
                let element = if element_index == 0 {
                    &self.target
                } else if element_index == 1 {
                    &self.lookup_weight
                } else {
                    &self.coefficients[element_index - 2]
                };
                let word = element[((offset - 64) % 48) / 16].to_le_bytes();
                let start = (offset - 64) % 16;
                let length = output.len().min(16 - start);
                output[..length].copy_from_slice(&word[start..start + length]);
                offset += length;
                output = &mut output[length..];
            }
        }
        Ok(())
    }
}

pub struct SetupStatementStream {
    profile: Profile,
    alpha: Element,
    indices: Vec<u32>,
    expected_digest: [u8; 64],
    hasher: Sha3_512,
    header: [u8; HEADER_LENGTH],
    header_length: usize,
    consumed: usize,
    polynomial: usize,
    parser: Option<PolynomialStream>,
    accumulator: Option<Accumulator>,
    failed: bool,
}
impl SetupStatementStream {
    pub fn new(expected_digest: [u8; 64], alpha: Element, indices: &[u32]) -> Result<Self, Error> {
        Self::with_profile(Profile::FULL, expected_digest, alpha, indices)
    }
    fn with_profile(
        profile: Profile,
        expected_digest: [u8; 64],
        alpha: Element,
        indices: &[u32],
    ) -> Result<Self, Error> {
        query::validate_indices_in(indices, 4 * profile.degree)?;
        if alpha.iter().any(|value| *value >= MODULUS) {
            return Err(Error::Parameters);
        }
        Ok(Self {
            profile,
            alpha,
            indices: indices.to_vec(),
            expected_digest,
            hasher: Sha3_512::new(),
            header: [0; HEADER_LENGTH],
            header_length: 0,
            consumed: 0,
            polynomial: 0,
            parser: None,
            accumulator: None,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Encoding);
        }
        if bytes.len() > CHUNK_LIMIT || bytes.len() > self.profile.encoded_length() - self.consumed
        {
            self.failed = true;
            self.accumulator = None;
            self.parser = None;
            return Err(Error::Length);
        }
        self.hasher.update(bytes);
        self.consumed += bytes.len();
        let result = self.process(bytes);
        if result.is_err() {
            self.failed = true;
            self.accumulator = None;
            self.parser = None;
        }
        result
    }
    fn process(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if self.header_length < HEADER_LENGTH {
            let length = bytes.len().min(HEADER_LENGTH - self.header_length);
            self.header[self.header_length..self.header_length + length]
                .copy_from_slice(&bytes[..length]);
            self.header_length += length;
            bytes = &bytes[length..];
            if self.header_length < HEADER_LENGTH {
                return Ok(());
            }
            if self.header != self.profile.header() {
                return Err(Error::Parameters);
            }
            self.accumulator = Some(Accumulator::new(self.profile, self.alpha, &self.indices)?);
        }
        while !bytes.is_empty() {
            if self.polynomial == POLYNOMIALS {
                return Err(Error::Length);
            }
            let accumulator = self.accumulator.as_mut().ok_or(Error::Incomplete)?;
            if self.parser.is_none() {
                let (family, degree) = self.profile.polynomial(self.polynomial);
                self.parser = Some(PolynomialStream::for_degree(
                    family,
                    degree,
                    self.alpha,
                    accumulator.is_common(self.polynomial),
                )?);
            }
            let parser = self.parser.as_mut().ok_or(Error::Incomplete)?;
            let length = bytes.len().min(parser.remaining());
            parser.push(&bytes[..length])?;
            bytes = &bytes[length..];
            if parser.remaining() == 0 {
                accumulator.consume(
                    self.polynomial,
                    self.parser.take().ok_or(Error::Incomplete)?,
                )?;
                self.polynomial += 1;
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<SetupStatementOutput, Error> {
        if self.failed {
            return Err(Error::Encoding);
        }
        if self.consumed != self.profile.encoded_length()
            || self.polynomial != POLYNOMIALS
            || self.parser.is_some()
        {
            return Err(Error::Incomplete);
        }
        let digest: [u8; 64] = self.hasher.finalize().into();
        if digest != self.expected_digest {
            return Err(Error::Binding);
        }
        let accumulator = self.accumulator.ok_or(Error::Incomplete)?;
        Ok(SetupStatementOutput {
            statement_digest: digest,
            target: accumulator.target,
            lookup_weight: accumulator.weight,
            coefficients: accumulator.coefficients,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            degree: 16,
            auxiliary_degree: 8,
            fhe_half_support: 2,
            share_half_support: 2,
            auxiliary_half_support: 2,
        }
    }
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../setup-stream-fixtures")
                .join(name),
        )
        .unwrap()
    }
    fn encode(output: &SetupStatementOutput) -> Vec<u8> {
        let mut bytes = vec![0; output.encoded_length()];
        for (index, part) in bytes.chunks_mut(107).enumerate() {
            output.copy_range(index * 107, part).unwrap();
        }
        bytes
    }
    #[test]
    fn every_queried_word_coefficient_and_target_match_independent_rows() {
        let statement = fixture("statement.bin");
        let digest: [u8; 64] = Sha3_512::digest(&statement).into();
        let indices = [0, 1, 3, 15, 16, 31, 32, 63];
        for (index, alpha) in [
            [0, 0, 0],
            [1, 0, 0],
            [MODULUS - 1, 0, 0],
            [17, 37, 91],
            [0, 0, 1],
        ]
        .into_iter()
        .enumerate()
        {
            let mut stream =
                SetupStatementStream::with_profile(profile(), digest, alpha, &indices).unwrap();
            for part in statement.chunks(107) {
                stream.push(part).unwrap();
            }
            let output = stream.finish().unwrap();
            assert_eq!(
                encode(&output),
                fixture(&format!("operator-{index}.bin")),
                "challenge {index}"
            );
        }
    }
    #[test]
    fn malformed_or_unbound_statements_never_return_an_operator() {
        let original = fixture("statement.bin");
        let digest: [u8; 64] = Sha3_512::digest(&original).into();
        for kind in 0..5 {
            let mut bytes = original.clone();
            match kind {
                0 => bytes[0] ^= 1,
                1 => bytes[HEADER_LENGTH] = 2,
                2 => {
                    bytes.pop();
                }
                3 => {
                    bytes.push(0);
                }
                _ => bytes[HEADER_LENGTH + 1] ^= 1,
            }
            let mut stream =
                SetupStatementStream::with_profile(profile(), digest, [17, 37, 91], &[0, 1])
                    .unwrap();
            let pushed = stream.push(&bytes);
            if pushed.is_ok() {
                assert!(stream.finish().is_err());
            } else {
                assert!(stream.push(&[]).is_err());
                assert!(stream.finish().is_err());
            }
        }
        let mut stream =
            SetupStatementStream::with_profile(profile(), digest, [17, 37, 91], &[0, 1]).unwrap();
        assert_eq!(stream.push(&vec![0; CHUNK_LIMIT + 1]), Err(Error::Length));
        assert!(stream.finish().is_err());
    }
}
