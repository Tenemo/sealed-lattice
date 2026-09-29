use super::{
    CHUNK_LIMIT, Element, Error, MODULUS, ONE, PolynomialRecords, PolynomialStream, ZERO,
    arithmetic, fingerprint_in, jobs, minus, plus, power, query, times,
};
use parallel_work::{HashStream, Pipeline, Sponge, Ticket};
use std::collections::VecDeque;
use supported_profile::{
    AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT, DEGREE, FHE_LIMB_BITS, FHE_SECRET_SUPPORT, Family,
    Profile, SETUP_ERROR_BITS, SETUP_FHE_CARRY_BITS, SETUP_QUOTIENT_BITS, SHARE_EPHEMERAL_SUPPORT,
    share_modulus,
};

const SHARE_SCALE: i128 = supported_profile::SHARE_SCALE as i128;

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
fn signed_fingerprint(value: i128, radix_bits: usize, weight: Element) -> Element {
    let result = fingerprint_in(&value.unsigned_abs().to_le_bytes(), radix_bits, weight);
    if value < 0 {
        minus(ZERO, result)
    } else {
        result
    }
}
// Share equations use the profile's share limb; every other equation uses
// 96-bit limbs.
fn family_radix(profile: Profile, family: Family) -> usize {
    match family {
        Family::Sharing => profile.share_limb_bits(),
        _ => FHE_LIMB_BITS,
    }
}
fn family_stream(
    profile: Profile,
    family: Family,
    degree: usize,
    alpha: Element,
) -> Result<PolynomialStream, Error> {
    PolynomialStream::new(
        &profile.family_modulus(family),
        degree,
        family_radix(profile, family),
        alpha,
    )
}
/// The parser of one setup polynomial, which fingerprints its coefficients
/// in the limbs of the equations that use it.
pub fn setup_polynomial_stream(
    profile: Profile,
    index: usize,
    alpha: Element,
) -> Result<PolynomialStream, Error> {
    let family = profile.setup_family(index).ok_or(Error::Parameters)?;
    family_stream(profile, family, profile.family_degree(family), alpha)
}

// The setup relation of one supported profile. Tests reduce the ring degrees
// and supports; every other size is the profile's.
#[derive(Clone, Copy)]
struct Layout {
    profile: Profile,
    degree: usize,
    auxiliary_degree: usize,
    fhe_half_support: usize,
    share_half_support: usize,
    auxiliary_half_support: usize,
}
impl Layout {
    fn full(profile: Profile) -> Self {
        Self {
            profile,
            degree: DEGREE,
            auxiliary_degree: AUXILIARY_DEGREE,
            fhe_half_support: FHE_SECRET_SUPPORT / 2,
            share_half_support: SHARE_EPHEMERAL_SUPPORT / 2,
            auxiliary_half_support: AUXILIARY_SECRET_SUPPORT / 2,
        }
    }
    fn header(self) -> Vec<u8> {
        let mut header = Vec::from(b"SCO1".as_slice());
        header.extend((self.degree as u32).to_le_bytes());
        header.extend((self.auxiliary_degree as u32).to_le_bytes());
        header.extend(&self.profile.parameters()[4..]);
        header
    }
    fn polynomial(self, index: usize) -> Option<(Family, usize)> {
        self.profile.setup_family(index).map(|family| {
            (
                family,
                if family == Family::Auxiliary {
                    self.auxiliary_degree
                } else {
                    self.degree
                },
            )
        })
    }
    fn encoded_length(self) -> usize {
        self.header().len()
            + (0..self.profile.setup_polynomials())
                .map(|index| {
                    let (family, degree) = self.polynomial(index).unwrap();
                    degree * (1 + self.profile.family_magnitude_bytes(family))
                })
                .sum::<usize>()
    }
}

#[derive(Clone)]
struct Variable {
    terms: Vec<(usize, i128)>,
    offset: i128,
    degree: usize,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GeometryKey {
    pub(crate) degree: usize,
    pub(crate) automorphism: usize,
    pub(crate) shift: usize,
    pub(crate) constant: bool,
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
/// A geometry's values: ones, or the powers of alpha at the automorphism
/// and shift of each position, negated past the degree.
pub(crate) fn geometry_values(key: GeometryKey, alpha: Element) -> Vec<Element> {
    if key.constant {
        return vec![ONE; key.degree];
    }
    let mut powers = Vec::with_capacity(key.degree);
    let mut value = ONE;
    for _ in 0..key.degree {
        powers.push(value);
        value = times(value, alpha);
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
}
enum PublicUse {
    Common(Variable, Element),
    Value(Element),
}
// The message of a constant share component: the FHE secret plus each
// sharing coefficient's limb parts times Z^(point * (i + 1)).
#[derive(Clone, Copy)]
struct ShareMessage<'a> {
    secret: &'a Variable,
    sharing: &'a [(Variable, Variable)],
    point: usize,
}

struct Accumulator {
    layout: Layout,
    fhe_modulus: Vec<u8>,
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
    // A planning pass only records the geometries its terms use.
    planning: bool,
    // The statement jobs of consumed records, oldest first.
    pending: VecDeque<StatementJob>,
    // The weighted sum of the waited runs of the polynomial whose runs are
    // oldest, and the encoded fingerprints of a common polynomial's records.
    partial: Option<(Element, Vec<u8>)>,
}
// A job of the statement's polynomials, in submission order.
enum StatementJob {
    // The fingerprints of a run of a polynomial's records; the last run
    // completes the polynomial.
    Run {
        polynomial: usize,
        last: bool,
        ticket: Ticket,
    },
    // A common polynomial's adjoint at the query indices.
    Adjoint {
        polynomial: usize,
        ticket: Ticket,
    },
}
impl Accumulator {
    fn new(layout: Layout, alpha: Element, indices: &[u32]) -> Result<Self, Error> {
        query::validate_indices_in(indices, 4 * layout.degree)?;
        // Jobs evaluate every geometry the terms use before the terms.
        let keys: Vec<GeometryKey> =
            Self::build_with(layout, alpha, indices, false, true, Vec::new())?
                .geometries
                .into_iter()
                .map(|(key, _)| key)
                .collect();
        let mut geometries = Vec::with_capacity(keys.len());
        let mut pipeline = Pipeline::new(parallel_work::window());
        let mut add = |index: usize, output: &[u8]| {
            let (sum, queries) = jobs::decode_geometry(output);
            geometries.push((keys[index], Geometry { sum, queries }));
        };
        for (index, key) in keys.iter().enumerate() {
            let ticket = jobs::geometry_job(*key, alpha, indices, layout.degree)?;
            if let Some((index, output)) = pipeline.push(index, ticket) {
                add(index, &output);
            }
        }
        for (index, output) in pipeline.finish() {
            add(index, &output);
        }
        Self::build_with(layout, alpha, indices, false, false, geometries)
    }
    fn build(
        layout: Layout,
        alpha: Element,
        indices: &[u32],
        record_terms: bool,
    ) -> Result<Self, Error> {
        Self::build_with(layout, alpha, indices, record_terms, false, Vec::new())
    }
    fn build_with(
        layout: Layout,
        alpha: Element,
        indices: &[u32],
        record_terms: bool,
        planning: bool,
        geometries: Vec<(GeometryKey, Geometry)>,
    ) -> Result<Self, Error> {
        let profile = layout.profile;
        let shape = profile.setup_shape();
        let columns = shape.word_columns + shape.boolean_columns;
        let mut result = Self {
            layout,
            fhe_modulus: profile.family_modulus(Family::Fhe),
            alpha,
            indices: indices.to_vec(),
            coefficients: if planning {
                Vec::new()
            } else {
                vec![ZERO; columns * indices.len()]
            },
            target: ZERO,
            weight: ONE,
            next_word: 0,
            next_boolean: shape.word_columns,
            supports: Vec::new(),
            geometries,
            uses: (0..profile.setup_polynomials())
                .map(|_| Vec::new())
                .collect(),
            recorded_terms: record_terms.then(Vec::new),
            planning,
            pending: VecDeque::new(),
            partial: None,
        };
        let secret = result.sparse(layout.degree, layout.fhe_half_support);
        let auxiliary = result.sparse(layout.degree, layout.fhe_half_support);
        let ephemerals: Vec<Variable> = (0..profile.participants())
            .map(|_| result.sparse(layout.degree, layout.share_half_support))
            .collect();
        let auxiliary_secret =
            result.sparse(layout.auxiliary_degree, layout.auxiliary_half_support);
        // Each sharing coefficient's low and high limb parts.
        let limb = profile.share_limb_bits();
        let sharing: Vec<(Variable, Variable)> = (0..profile.sharing_degree())
            .map(|_| {
                let low = result.signed(limb, layout.degree);
                let high = result.signed(profile.sharing_coefficient_bits() - limb, layout.degree);
                (low, high)
            })
            .collect();
        let limb_weight = power(alpha, layout.degree);
        let gadget_bits = Profile::gadget_base_bits();
        for gadget in 0..profile.gadget_length() {
            // The gadget digit 2^(144 * gadget) in 96-bit limb fingerprints.
            let factor = scale(
                power(limb_weight, gadget_bits * gadget / FHE_LIMB_BITS),
                1u128 << (gadget_bits * gadget % FHE_LIMB_BITS),
            );
            let first = profile.fhe_polynomial(gadget, 0);
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
        // Roster position a evaluates at Z^a with Z = X^(degree/R).
        let stride = layout.degree / profile.interpolation_degree();
        for (recipient, ephemeral) in ephemerals.iter().enumerate() {
            result.encrypted_share(
                profile.recipient_key_polynomial(recipient),
                profile.share_constant_polynomial(recipient),
                ephemeral,
                Some(ShareMessage {
                    secret: &secret,
                    sharing: &sharing,
                    point: recipient * stride,
                }),
            )?;
            result.encrypted_share(
                profile.share_common_polynomial(),
                profile.share_linear_polynomial(recipient),
                ephemeral,
                None,
            )?;
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
        if result.next_word != shape.word_columns
            || result.next_boolean != columns
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
        let geometry = if self.planning {
            Geometry {
                sum: ZERO,
                queries: Vec::new(),
            }
        } else {
            let values = geometry_values(key, self.alpha);
            let sum = values.iter().copied().fold(ZERO, plus);
            let queries = if self.indices.is_empty() {
                Vec::new()
            } else {
                query::evaluate_in(values, &self.indices, self.layout.degree)?
            };
            Geometry { sum, queries }
        };
        self.geometries.push((key, geometry));
        Ok(self.geometries.len() - 1)
    }
    fn put(&mut self, variable: &Variable, key: GeometryKey, weight: Element) -> Result<(), Error> {
        if variable.degree != key.degree {
            return Err(Error::Arithmetic);
        }
        let index = self.geometry(key)?;
        if self.planning {
            return Ok(());
        }
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
        let degree = self.layout.degree;
        let limbs = self.layout.profile.fhe_limbs();
        let quotient = self.signed(SETUP_QUOTIENT_BITS, degree);
        let carries: Vec<Variable> = (0..limbs - 1)
            .map(|_| self.signed(SETUP_FHE_CARRY_BITS, degree))
            .collect();
        let error = self.signed(SETUP_ERROR_BITS, degree);
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
        let modulus = fingerprint_in(&self.fhe_modulus, FHE_LIMB_BITS, z);
        self.put(&quotient, key, minus(ZERO, times(self.weight, modulus)))?;
        self.put(&error, key, minus(ZERO, self.weight))?;
        let mut factor = minus(z, [1u128 << FHE_LIMB_BITS, 0, 0]);
        for carry in &carries {
            self.put(carry, key, times(self.weight, factor))?;
            factor = times(factor, z);
        }
        self.weight = times(self.weight, power(z, limbs));
        Ok(())
    }
    fn encrypted_share(
        &mut self,
        common: usize,
        value: usize,
        ephemeral: &Variable,
        message: Option<ShareMessage<'_>>,
    ) -> Result<(), Error> {
        let degree = self.layout.degree;
        let profile = self.layout.profile;
        let limb_bits = profile.share_limb_bits();
        let radix = 1i128 << limb_bits;
        let quotient = self.signed(SETUP_QUOTIENT_BITS, degree);
        let carry = self.signed(
            if message.is_some() {
                profile.share_carry_bits()
            } else {
                SETUP_FHE_CARRY_BITS
            },
            degree,
        );
        let error = self.signed(SETUP_ERROR_BITS, degree);
        let z = power(self.alpha, degree);
        let key = GeometryKey::identity(degree);
        self.register(common, value, ephemeral, -1)?;
        if let Some(ShareMessage {
            secret,
            sharing,
            point,
        }) = message
        {
            self.put(secret, key, scale(self.weight, SHARE_SCALE as u128))?;
            let mut offsets = vec![0i128; degree];
            for (index, (low, high)) in sharing.iter().enumerate() {
                let shift = point * (index + 1);
                let key = GeometryKey::shifted(degree, shift);
                self.put(low, key, scale(self.weight, SHARE_SCALE as u128))?;
                self.put(high, key, scale(times(self.weight, z), SHARE_SCALE as u128))?;
                for input in 0..degree {
                    let exponent = (input + shift) % (2 * degree);
                    let offset = SHARE_SCALE * (radix / 2);
                    offsets[exponent % degree] += if exponent < degree { offset } else { -offset };
                }
            }
            let mut current = ONE;
            let mut sum = ZERO;
            for offset in offsets {
                sum = plus(
                    sum,
                    times(current, signed_fingerprint(offset, limb_bits, z)),
                );
                current = times(current, self.alpha);
            }
            self.target = minus(self.target, times(self.weight, sum));
        }
        let modulus = fingerprint_in(share_modulus(), limb_bits, z);
        self.put(&quotient, key, minus(ZERO, times(self.weight, modulus)))?;
        self.put(
            &carry,
            key,
            times(self.weight, minus(z, [radix as u128, 0, 0])),
        )?;
        self.put(&error, key, self.weight)?;
        self.weight = times(self.weight, times(z, z));
        Ok(())
    }
    fn auxiliary_key(&mut self, secret: &Variable) -> Result<(), Error> {
        let degree = self.layout.auxiliary_degree;
        let profile = self.layout.profile;
        let quotient = self.signed(SETUP_QUOTIENT_BITS, degree);
        let error = self.signed(SETUP_ERROR_BITS, degree);
        let key = GeometryKey::identity(degree);
        let z = power(self.alpha, degree);
        self.register(
            profile.auxiliary_common_polynomial(),
            profile.auxiliary_key_polynomial(),
            secret,
            1,
        )?;
        let modulus = fingerprint_in(&profile.family_modulus(Family::Auxiliary), FHE_LIMB_BITS, z);
        self.put(&quotient, key, minus(ZERO, times(self.weight, modulus)))?;
        self.put(&error, key, minus(ZERO, self.weight))?;
        self.weight = times(self.weight, z);
        Ok(())
    }
    fn is_common(&self, polynomial: usize) -> bool {
        self.uses[polynomial]
            .iter()
            .any(|usage| matches!(usage, PublicUse::Common(_, _)))
    }
    // Starts the fingerprints of a run of a polynomial's canonical records
    // of width bytes, from its position.
    fn run(
        &mut self,
        polynomial: usize,
        width: usize,
        position: usize,
        records: &[u8],
        last: bool,
    ) -> Result<(), Error> {
        let (family, degree) = self.layout.polynomial(polynomial).ok_or(Error::Length)?;
        let common = self.is_common(polynomial);
        if self.uses[polynomial]
            .iter()
            .any(|usage| matches!(usage, PublicUse::Common(_, _)) != common)
        {
            return Err(Error::Arithmetic);
        }
        let ticket = jobs::fingerprints_job(
            width,
            family_radix(self.layout.profile, family),
            degree,
            position,
            common,
            self.alpha,
            records,
        );
        self.pending.push_back(StatementJob::Run {
            polynomial,
            last,
            ticket,
        });
        while self.pending.len() > parallel_work::window() {
            self.take_oldest()?;
        }
        Ok(())
    }
}

impl Accumulator {
    // Takes the oldest statement job. A polynomial's last run subtracts its
    // weighted value from the target or starts its adjoint, whose weighted
    // query values are added to the coefficients.
    fn take_oldest(&mut self) -> Result<(), Error> {
        match self.pending.pop_front().unwrap() {
            StatementJob::Run {
                polynomial,
                last,
                ticket,
            } => {
                let output = ticket.wait();
                let (sum, fingerprints) = jobs::split_fingerprints(&output);
                let (total, retained) = self.partial.get_or_insert_with(|| (ZERO, Vec::new()));
                *total = plus(*total, sum);
                retained.extend_from_slice(fingerprints);
                if !last {
                    return Ok(());
                }
                let (total, retained) = self.partial.take().unwrap();
                if self.is_common(polynomial) {
                    let ticket = jobs::adjoint_job(
                        &retained,
                        total,
                        self.alpha,
                        &self.indices,
                        self.layout.degree,
                    )?;
                    self.pending
                        .push_back(StatementJob::Adjoint { polynomial, ticket });
                } else {
                    for usage in &self.uses[polynomial] {
                        let PublicUse::Value(weight) = usage else {
                            unreachable!("A value polynomial has only value uses.");
                        };
                        self.target = minus(self.target, times(*weight, total));
                    }
                }
            }
            StatementJob::Adjoint { polynomial, ticket } => {
                let values = jobs::decode_adjoint(&ticket.wait())?;
                for usage in &self.uses[polynomial] {
                    let PublicUse::Common(variable, weight) = usage else {
                        unreachable!("A common polynomial has only common uses.");
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
            }
        }
        Ok(())
    }
    fn settle(&mut self) -> Result<(), Error> {
        while !self.pending.is_empty() {
            self.take_oldest()?;
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
pub fn prover_operator_plan(profile: Profile, alpha: Element) -> Result<ProverOperatorPlan, Error> {
    if alpha.iter().any(|value| *value >= MODULUS) {
        return Err(Error::Parameters);
    }
    let mut accumulator = Accumulator::build(Layout::full(profile), alpha, &[], true)?;
    let mut common_columns = vec![Vec::new(); profile.setup_polynomials()];
    let mut value_weights = vec![ZERO; profile.setup_polynomials()];
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
pub struct SetupStatementStream {
    layout: Layout,
    expected_header: Vec<u8>,
    encoded_length: usize,
    alpha: Element,
    indices: Vec<u32>,
    expected_digest: [u8; 64],
    // The statement's digest, which a helper computes when there are helpers.
    hasher: HashStream,
    header: Vec<u8>,
    consumed: usize,
    polynomial: usize,
    records: Option<PolynomialRecords>,
    accumulator: Option<Accumulator>,
    failed: bool,
}
impl SetupStatementStream {
    pub fn new(
        profile: Profile,
        expected_digest: [u8; 64],
        alpha: Element,
        indices: &[u32],
    ) -> Result<Self, Error> {
        Self::with_layout(Layout::full(profile), expected_digest, alpha, indices)
    }
    fn with_layout(
        layout: Layout,
        expected_digest: [u8; 64],
        alpha: Element,
        indices: &[u32],
    ) -> Result<Self, Error> {
        query::validate_indices_in(indices, 4 * layout.degree)?;
        if alpha.iter().any(|value| *value >= MODULUS) {
            return Err(Error::Parameters);
        }
        Ok(Self {
            layout,
            expected_header: layout.header(),
            encoded_length: layout.encoded_length(),
            alpha,
            indices: indices.to_vec(),
            expected_digest,
            hasher: HashStream::new(Sponge::ProtocolHash),
            header: Vec::new(),
            consumed: 0,
            polynomial: 0,
            records: None,
            accumulator: None,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Encoding);
        }
        if bytes.len() > CHUNK_LIMIT || bytes.len() > self.encoded_length - self.consumed {
            self.failed = true;
            self.accumulator = None;
            self.records = None;
            return Err(Error::Length);
        }
        self.hasher.update(bytes);
        self.consumed += bytes.len();
        let result = self.process(bytes);
        if result.is_err() {
            self.failed = true;
            self.accumulator = None;
            self.records = None;
        }
        result
    }
    fn process(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        let header_length = self.expected_header.len();
        if self.header.len() < header_length {
            let length = bytes.len().min(header_length - self.header.len());
            self.header.extend_from_slice(&bytes[..length]);
            bytes = &bytes[length..];
            if self.header.len() < header_length {
                return Ok(());
            }
            if self.header != self.expected_header {
                return Err(Error::Parameters);
            }
            self.accumulator = Some(Accumulator::new(self.layout, self.alpha, &self.indices)?);
        }
        while !bytes.is_empty() {
            let (family, degree) = self
                .layout
                .polynomial(self.polynomial)
                .ok_or(Error::Length)?;
            let accumulator = self.accumulator.as_mut().ok_or(Error::Incomplete)?;
            let profile = self.layout.profile;
            if self.records.is_none() {
                self.records = Some(PolynomialRecords::new(
                    &profile.family_modulus(family),
                    degree,
                    family_radix(profile, family),
                    self.alpha,
                )?);
            }
            let records = self.records.as_mut().ok_or(Error::Incomplete)?;
            let (polynomial, width) = (self.polynomial, records.width());
            let length = bytes.len().min(records.remaining());
            records.push(&bytes[..length], |position, run, last| {
                accumulator.run(polynomial, width, position, run, last)
            })?;
            bytes = &bytes[length..];
            if records.remaining() == 0 {
                self.records = None;
                self.polynomial += 1;
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<SetupStatementOutput, Error> {
        if self.failed {
            return Err(Error::Encoding);
        }
        if self.consumed != self.encoded_length
            || self.polynomial != self.layout.profile.setup_polynomials()
            || self.records.is_some()
        {
            return Err(Error::Incomplete);
        }
        let digest = self.hasher.finish();
        if digest != self.expected_digest {
            return Err(Error::Binding);
        }
        let mut accumulator = self.accumulator.ok_or(Error::Incomplete)?;
        accumulator.settle()?;
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
    use num_bigint::{BigInt, BigUint, Sign};
    use num_traits::ToPrimitive;
    use parallel_work::{Digest, ProtocolHash};

    // Every size of the profile over sixteen-coefficient rings.
    fn reduced(profile: Profile) -> Layout {
        Layout {
            profile,
            degree: 16,
            auxiliary_degree: 8,
            fhe_half_support: 2,
            share_half_support: 2,
            auxiliary_half_support: 2,
        }
    }

    struct Random(u64);
    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn signed(&mut self, bits: usize) -> i128 {
            let value =
                ((u128::from(self.next()) << 64) | u128::from(self.next())) & ((1u128 << bits) - 1);
            value as i128 - (1i128 << (bits - 1))
        }
        fn sparse(&mut self, degree: usize, half_support: usize) -> Vec<i8> {
            let mut values = vec![0; degree];
            let mut placed = 0;
            while placed < 2 * half_support {
                let position = self.next() as usize % degree;
                if values[position] == 0 {
                    values[position] = if placed < half_support { 1 } else { -1 };
                    placed += 1;
                }
            }
            values
        }
        // Canonical coefficients of magnitude at most a quarter of the modulus.
        fn polynomial(&mut self, degree: usize, modulus: &BigInt) -> Vec<BigInt> {
            let quarter = (modulus >> 2usize).to_bytes_le().1;
            (0..degree)
                .map(|_| {
                    let bytes: Vec<u8> = quarter
                        .iter()
                        .map(|byte| byte & self.next() as u8)
                        .collect();
                    let magnitude = BigInt::from_bytes_le(Sign::Plus, &bytes);
                    if self.next() & 1 == 1 {
                        -magnitude
                    } else {
                        magnitude
                    }
                })
                .collect()
        }
    }

    fn integer(bytes: &[u8]) -> BigInt {
        BigInt::from_bytes_le(Sign::Plus, bytes)
    }
    fn digit(value: &BigInt, limb: usize, radix_bits: usize) -> BigInt {
        let mask = (BigUint::from(1u8) << radix_bits) - 1u8;
        let magnitude = BigInt::from_biguint(
            Sign::Plus,
            (value.magnitude() >> (radix_bits * limb)) & mask,
        );
        if value.sign() == Sign::Minus {
            -magnitude
        } else {
            magnitude
        }
    }
    // The representative of a residue in (-q/2, q/2) and the multiple of q
    // removed to reach it.
    fn centered(value: &BigInt, modulus: &BigInt) -> (BigInt, BigInt) {
        let mut residue = value % modulus;
        if residue.sign() == Sign::Minus {
            residue += modulus;
        }
        if &residue + &residue > *modulus {
            residue -= modulus;
        }
        let multiple = (value - &residue) / modulus;
        (residue, multiple)
    }
    // Multiplication by X^shift modulo X^degree + 1.
    fn rotate(values: &[BigInt], shift: usize) -> Vec<BigInt> {
        let degree = values.len();
        let mut result = vec![BigInt::from(0); degree];
        for (input, value) in values.iter().enumerate() {
            let exponent = (input + shift) % (2 * degree);
            if exponent < degree {
                result[exponent] += value;
            } else {
                result[exponent - degree] -= value;
            }
        }
        result
    }
    fn product(common: &[BigInt], sparse: &[i8]) -> Vec<BigInt> {
        let mut result = vec![BigInt::from(0); common.len()];
        for (shift, value) in sparse.iter().enumerate() {
            for (position, term) in rotate(common, shift).into_iter().enumerate() {
                result[position] += term * BigInt::from(*value);
            }
        }
        result
    }
    fn automorphism(values: &[i8], power: usize) -> Vec<BigInt> {
        let degree = values.len();
        let mut result = vec![BigInt::from(0); degree];
        for (position, value) in values.iter().enumerate() {
            let exponent = (position * power) % (2 * degree);
            let value = BigInt::from(*value);
            result[exponent % degree] = if exponent < degree { value } else { -value };
        }
        result
    }
    fn signed_integers(values: &[i128]) -> Vec<BigInt> {
        values.iter().map(|value| BigInt::from(*value)).collect()
    }

    #[derive(Clone, Default)]
    struct Witness {
        words: Vec<Vec<i128>>,
        booleans: Vec<Vec<i128>>,
        narrow_words: Vec<(usize, usize)>,
    }
    impl Witness {
        fn sparse(&mut self, values: &[i8]) {
            for sign in [1, -1] {
                self.booleans.push(
                    values
                        .iter()
                        .map(|value| i128::from(*value == sign))
                        .collect(),
                );
            }
        }
        // Words from the low end, then one Boolean per remaining bit.
        fn signed(&mut self, width: usize, values: &[BigInt]) {
            let offset = 1i128 << (width - 1);
            let shifted: Vec<u128> = values
                .iter()
                .map(|value| {
                    let value = value.to_i128().unwrap();
                    assert!(
                        -offset <= value && value < offset,
                        "{value} exceeds {width} bits"
                    );
                    (value + offset) as u128
                })
                .collect();
            let mut remaining = width;
            let mut shift = 0;
            while remaining >= 16 || shift == 0 {
                let bits = remaining.min(16);
                if bits < 16 {
                    self.narrow_words.push((self.words.len(), bits));
                }
                self.words.push(
                    shifted
                        .iter()
                        .map(|value| ((value >> shift) & ((1 << bits) - 1)) as i128)
                        .collect(),
                );
                remaining -= bits;
                shift += bits;
            }
            for bit in 0..remaining {
                self.booleans.push(
                    shifted
                        .iter()
                        .map(|value| ((value >> (shift + bit)) & 1) as i128)
                        .collect(),
                );
            }
        }
        fn columns(&self) -> Vec<Vec<i128>> {
            self.words.iter().chain(&self.booleans).cloned().collect()
        }
    }

    struct KeyEquation<'a> {
        common: &'a [BigInt],
        left: &'a [i8],
        direct: Vec<BigInt>,
        multiplier: BigInt,
        modulus: &'a BigInt,
        limbs: usize,
    }
    // common * left + value - multiplier * direct - error - modulus * quotient
    // = 0 in 96-bit limbs, and the key value it defines.
    fn key_equation(
        witness: &mut Witness,
        random: &mut Random,
        equation: KeyEquation<'_>,
    ) -> Vec<BigInt> {
        let KeyEquation {
            common,
            left,
            direct,
            multiplier,
            modulus,
            limbs,
        } = equation;
        let degree = common.len();
        let exact = product(common, left);
        let digits: Vec<Vec<BigInt>> = (0..limbs)
            .map(|limb| {
                let digits: Vec<BigInt> = common
                    .iter()
                    .map(|value| digit(value, limb, FHE_LIMB_BITS))
                    .collect();
                product(&digits, left)
            })
            .collect();
        let errors: Vec<i128> = (0..degree)
            .map(|_| random.signed(SETUP_ERROR_BITS))
            .collect();
        let mut values = Vec::new();
        let mut quotients = Vec::new();
        let mut carries = vec![Vec::new(); limbs - 1];
        for position in 0..degree {
            let error = BigInt::from(errors[position]);
            let (value, multiple) = centered(
                &(&multiplier * &direct[position] - &exact[position] + &error),
                modulus,
            );
            let quotient = -multiple;
            let mut carry = BigInt::from(0);
            for limb in 0..limbs {
                let mut row = &digits[limb][position] + digit(&value, limb, FHE_LIMB_BITS)
                    - digit(&multiplier, limb, FHE_LIMB_BITS) * &direct[position]
                    - digit(modulus, limb, FHE_LIMB_BITS) * &quotient
                    + &carry;
                if limb == 0 {
                    row -= &error;
                }
                if limb + 1 < limbs {
                    assert_eq!(&row % (BigInt::from(1) << FHE_LIMB_BITS), BigInt::from(0));
                    carry = row >> FHE_LIMB_BITS;
                    carries[limb].push(carry.clone());
                } else {
                    assert_eq!(row, BigInt::from(0));
                }
            }
            quotients.push(quotient);
            values.push(value);
        }
        witness.signed(SETUP_QUOTIENT_BITS, &quotients);
        for carry in &carries {
            witness.signed(SETUP_FHE_CARRY_BITS, carry);
        }
        witness.signed(SETUP_ERROR_BITS, &signed_integers(&errors));
        values
    }

    #[derive(Clone, Copy)]
    struct Message<'a> {
        secret: &'a [i8],
        sharing: &'a [Vec<i128>],
        point: usize,
    }
    // common * ephemeral - value + scale * message + error - modulus * quotient
    // = 0 in share limbs, where the message is the FHE secret plus each
    // sharing coefficient c_i times Z^(a * (i + 1)), and c_i = low + 2^L high
    // + 2^(L - 1).
    fn share_equation(
        witness: &mut Witness,
        random: &mut Random,
        profile: Profile,
        common: &[BigInt],
        ephemeral: &[i8],
        message: Option<Message<'_>>,
    ) -> Vec<BigInt> {
        let degree = common.len();
        let limb = profile.share_limb_bits();
        let modulus = integer(share_modulus());
        let exact = product(common, ephemeral);
        let digits: Vec<Vec<BigInt>> = (0..2)
            .map(|index| {
                let digits: Vec<BigInt> = common
                    .iter()
                    .map(|value| digit(value, index, limb))
                    .collect();
                product(&digits, ephemeral)
            })
            .collect();
        let scale = BigInt::from(SHARE_SCALE);
        let zero = vec![BigInt::from(0); degree];
        let (mut total, mut low, mut high, mut offset) =
            (zero.clone(), zero.clone(), zero.clone(), zero);
        if let Some(Message {
            secret,
            sharing,
            point,
        }) = message
        {
            for (position, value) in secret.iter().enumerate() {
                total[position] += BigInt::from(*value);
                low[position] += BigInt::from(*value);
            }
            for (index, coefficient) in sharing.iter().enumerate() {
                let shift = point * (index + 1);
                let parts = |part: &dyn Fn(i128) -> i128| {
                    rotate(
                        &signed_integers(
                            &coefficient
                                .iter()
                                .map(|value| part(*value))
                                .collect::<Vec<_>>(),
                        ),
                        shift,
                    )
                };
                let rotated = [
                    parts(&|value| value),
                    parts(&|value| value.rem_euclid(1 << limb) - (1 << (limb - 1))),
                    parts(&|value| value.div_euclid(1 << limb)),
                    parts(&|_| 1 << (limb - 1)),
                ];
                for position in 0..degree {
                    total[position] += &rotated[0][position];
                    low[position] += &rotated[1][position];
                    high[position] += &rotated[2][position];
                    offset[position] += &scale * &rotated[3][position];
                }
            }
        }
        let errors: Vec<i128> = (0..degree)
            .map(|_| random.signed(SETUP_ERROR_BITS))
            .collect();
        let radix = BigInt::from(1) << limb;
        let mut values = Vec::new();
        let mut quotients = Vec::new();
        let mut carries = Vec::new();
        for position in 0..degree {
            let error = BigInt::from(errors[position]);
            let (value, quotient) = centered(
                &(&exact[position] + &error + &scale * &total[position]),
                &modulus,
            );
            let row = &digits[0][position] - digit(&value, 0, limb)
                + digit(&offset[position], 0, limb)
                + &scale * &low[position]
                + &error
                - digit(&modulus, 0, limb) * &quotient;
            assert_eq!(&row % &radix, BigInt::from(0));
            let carry = row / &radix;
            let row = &digits[1][position] - digit(&value, 1, limb)
                + digit(&offset[position], 1, limb)
                + &scale * &high[position]
                - digit(&modulus, 1, limb) * &quotient
                + &carry;
            assert_eq!(row, BigInt::from(0));
            carries.push(carry);
            quotients.push(quotient);
            values.push(value);
        }
        witness.signed(SETUP_QUOTIENT_BITS, &quotients);
        witness.signed(
            if message.is_some() {
                profile.share_carry_bits()
            } else {
                SETUP_FHE_CARRY_BITS
            },
            &carries,
        );
        witness.signed(SETUP_ERROR_BITS, &signed_integers(&errors));
        values
    }

    fn encode(values: &[BigInt], width: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in values {
            let (sign, magnitude) = value.to_bytes_le();
            assert!(magnitude.len() <= width);
            bytes.push(u8::from(sign == Sign::Minus));
            bytes.extend(&magnitude);
            bytes.resize(bytes.len() + width - magnitude.len(), 0);
        }
        bytes
    }

    // A satisfying assignment of the integer setup equations, built from the
    // equations rather than from the operator, and the statement it binds.
    fn satisfying_relation(layout: Layout, random: &mut Random) -> (Vec<u8>, Witness) {
        let profile = layout.profile;
        let degree = layout.degree;
        let fhe = integer(&profile.family_modulus(Family::Fhe));
        let auxiliary_modulus = integer(&profile.family_modulus(Family::Auxiliary));
        let share = integer(share_modulus());
        let mut witness = Witness::default();
        let mut polynomials = vec![Vec::new(); profile.setup_polynomials()];
        let secret = random.sparse(degree, layout.fhe_half_support);
        let auxiliary = random.sparse(degree, layout.fhe_half_support);
        let ephemerals: Vec<Vec<i8>> = (0..profile.participants())
            .map(|_| random.sparse(degree, layout.share_half_support))
            .collect();
        let auxiliary_secret =
            random.sparse(layout.auxiliary_degree, layout.auxiliary_half_support);
        for values in [&secret, &auxiliary]
            .into_iter()
            .chain(&ephemerals)
            .chain([&auxiliary_secret])
        {
            witness.sparse(values);
        }
        let limb = profile.share_limb_bits();
        let bits = profile.sharing_coefficient_bits();
        let sharing: Vec<Vec<i128>> = (0..profile.sharing_degree())
            .map(|_| (0..degree).map(|_| random.signed(bits)).collect())
            .collect();
        for coefficient in &sharing {
            let low: Vec<i128> = coefficient
                .iter()
                .map(|value| value.rem_euclid(1 << limb) - (1 << (limb - 1)))
                .collect();
            let high: Vec<i128> = coefficient
                .iter()
                .map(|value| value.div_euclid(1 << limb))
                .collect();
            witness.signed(limb, &signed_integers(&low));
            witness.signed(bits - limb, &signed_integers(&high));
        }
        for gadget in 0..profile.gadget_length() {
            let power = BigInt::from(1) << (Profile::gadget_base_bits() * gadget);
            let first = profile.fhe_polynomial(gadget, 0);
            for component in [0, 3, 5] {
                polynomials[first + component] = random.polynomial(degree, &fhe);
            }
            let keys = [
                (0, &secret, automorphism(&auxiliary, 1), BigInt::from(0)),
                (0, &auxiliary, automorphism(&secret, 1), power.clone()),
                (3, &secret, automorphism(&auxiliary, 1), -power.clone()),
                (5, &secret, automorphism(&secret, 5), power),
            ];
            for (index, (common, left, direct, multiplier)) in keys.into_iter().enumerate() {
                let value = key_equation(
                    &mut witness,
                    random,
                    KeyEquation {
                        common: &polynomials[first + common].clone(),
                        left,
                        direct,
                        multiplier,
                        modulus: &fhe,
                        limbs: profile.fhe_limbs(),
                    },
                );
                polynomials[first + [1, 2, 4, 6][index]] = value;
            }
        }
        let stride = degree / profile.interpolation_degree();
        polynomials[profile.share_common_polynomial()] = random.polynomial(degree, &share);
        for (recipient, ephemeral) in ephemerals.iter().enumerate() {
            let key = random.polynomial(degree, &share);
            polynomials[profile.share_constant_polynomial(recipient)] = share_equation(
                &mut witness,
                random,
                profile,
                &key,
                ephemeral,
                Some(Message {
                    secret: &secret,
                    sharing: &sharing,
                    point: recipient * stride,
                }),
            );
            polynomials[profile.recipient_key_polynomial(recipient)] = key;
            polynomials[profile.share_linear_polynomial(recipient)] = share_equation(
                &mut witness,
                random,
                profile,
                &polynomials[profile.share_common_polynomial()].clone(),
                ephemeral,
                None,
            );
        }
        let common = random.polynomial(layout.auxiliary_degree, &auxiliary_modulus);
        polynomials[profile.auxiliary_key_polynomial()] = key_equation(
            &mut witness,
            random,
            KeyEquation {
                common: &common,
                left: &auxiliary_secret,
                direct: vec![BigInt::from(0); layout.auxiliary_degree],
                multiplier: BigInt::from(0),
                modulus: &auxiliary_modulus,
                limbs: 1,
            },
        );
        polynomials[profile.auxiliary_common_polynomial()] = common;
        let shape = profile.setup_shape();
        assert_eq!(witness.words.len(), shape.word_columns);
        assert_eq!(witness.booleans.len(), shape.boolean_columns);
        assert_eq!(witness.narrow_words, shape.narrow_words);
        let mut statement = layout.header();
        for (index, polynomial) in polynomials.iter().enumerate() {
            let (family, degree) = layout.polynomial(index).unwrap();
            assert_eq!(polynomial.len(), degree);
            statement.extend(encode(polynomial, profile.family_magnitude_bytes(family)));
        }
        assert_eq!(statement.len(), layout.encoded_length());
        (statement, witness)
    }

    fn geometric(alpha: Element, term: &ProverFixedTerm) -> Vec<Element> {
        (0..term.degree)
            .map(|position| {
                if term.constant {
                    return ONE;
                }
                let exponent = (position * term.automorphism + term.shift) % (2 * term.degree);
                let value = power(alpha, exponent % term.degree);
                if exponent < term.degree {
                    value
                } else {
                    minus(ZERO, value)
                }
            })
            .collect()
    }
    fn add_scaled(total: &mut Vec<Element>, values: &[Element], weight: Element) {
        if total.is_empty() {
            *total = vec![ZERO; values.len()];
        }
        assert_eq!(total.len(), values.len());
        for (entry, value) in total.iter_mut().zip(values) {
            *entry = plus(*entry, times(weight, *value));
        }
    }
    // Each witness column's coefficients over the ring positions, and the
    // target, for one statement.
    fn systematic_operator(
        layout: Layout,
        alpha: Element,
        statement: &[u8],
    ) -> (Vec<Vec<Element>>, Element) {
        let profile = layout.profile;
        let shape = profile.setup_shape();
        let mut accumulator = Accumulator::build(layout, alpha, &[], true).unwrap();
        let mut columns = vec![Vec::new(); shape.word_columns + shape.boolean_columns];
        for term in accumulator.recorded_terms.take().unwrap() {
            let geometry = geometric(alpha, &term);
            for (column, weight) in &term.columns {
                add_scaled(&mut columns[*column], &geometry, *weight);
            }
        }
        let mut target = accumulator.target;
        let mut offset = layout.header().len();
        for index in 0..profile.setup_polynomials() {
            let (family, degree) = layout.polynomial(index).unwrap();
            let length = degree * (1 + profile.family_magnitude_bytes(family));
            let mut parser = family_stream(profile, family, degree, alpha).unwrap();
            parser.push(&statement[offset..offset + length]).unwrap();
            offset += length;
            if accumulator.is_common(index) {
                let adjoint = parser.adjoint().unwrap();
                for usage in &accumulator.uses[index] {
                    let PublicUse::Common(variable, weight) = usage else {
                        panic!("mixed public use");
                    };
                    for (column, factor) in &variable.terms {
                        add_scaled(
                            &mut columns[*column],
                            &adjoint,
                            scale(*weight, base(*factor)),
                        );
                    }
                }
            } else {
                let value = parser.finish_value().unwrap();
                for usage in &accumulator.uses[index] {
                    let PublicUse::Value(weight) = usage else {
                        panic!("mixed public use");
                    };
                    target = minus(target, times(*weight, value));
                }
            }
        }
        (columns, target)
    }
    fn apply(columns: &[Vec<Element>], witness: &[Vec<i128>]) -> Element {
        assert_eq!(columns.len(), witness.len());
        let mut total = ZERO;
        for (coefficients, values) in columns.iter().zip(witness) {
            assert_eq!(coefficients.len(), values.len());
            for (coefficient, value) in coefficients.iter().zip(values) {
                total = plus(total, scale(*coefficient, base(*value)));
            }
        }
        total
    }
    fn stream(
        layout: Layout,
        bytes: &[u8],
        digest: [u8; 64],
        indices: &[u32],
    ) -> Result<SetupStatementOutput, Error> {
        let mut stream = SetupStatementStream::with_layout(layout, digest, [17, 37, 91], indices)?;
        for part in bytes.chunks(107) {
            stream.push(part)?;
        }
        stream.finish()
    }
    // Flips the low magnitude bit of a polynomial's first coefficient.
    fn change_polynomial(layout: Layout, statement: &mut [u8], polynomial: usize) {
        let offset = layout.header().len()
            + (0..polynomial)
                .map(|index| {
                    let (family, degree) = layout.polynomial(index).unwrap();
                    degree * (1 + layout.profile.family_magnitude_bytes(family))
                })
                .sum::<usize>();
        statement[offset + 1] ^= 1;
    }

    #[test]
    fn satisfying_integer_witnesses_meet_the_operator_of_every_profile() {
        let mut random = Random(0x9e37_79b9_7f4a_7c15);
        let alpha = [17, 37, 91];
        let indices = [0, 3, 17, 63];
        for profile in Profile::all() {
            let label = format!(
                "{} participants, {} options",
                profile.participants(),
                profile.options()
            );
            let layout = reduced(profile);
            let (statement, witness) = satisfying_relation(layout, &mut random);
            let columns = witness.columns();
            let (operator, target) = systematic_operator(layout, alpha, &statement);
            assert_eq!(apply(&operator, &columns), target, "{label}");
            // The verifier's query coefficients encode the same operator.
            let digest: [u8; 64] = ProtocolHash::digest(&statement).into();
            let output = stream(layout, &statement, digest, &indices).unwrap();
            assert_eq!(output.target, target, "{label}");
            for (column, coefficients) in operator.iter().enumerate() {
                assert_eq!(
                    query::evaluate_in(coefficients.clone(), &indices, layout.degree).unwrap(),
                    output.coefficients[column * indices.len()..(column + 1) * indices.len()],
                    "{label} column {column}"
                );
            }
            // A changed error word or public value no longer meets it.
            let mut changed = columns.clone();
            changed[profile.setup_shape().word_columns - 1][0] ^= 1;
            assert_ne!(apply(&operator, &changed), target, "{label}");
            for polynomial in [
                profile.fhe_polynomial(0, 0),
                profile.auxiliary_key_polynomial(),
            ] {
                let mut changed = statement.clone();
                change_polynomial(layout, &mut changed, polynomial);
                let (operator, target) = systematic_operator(layout, alpha, &changed);
                assert_ne!(apply(&operator, &columns), target, "{label}");
            }
        }
    }

    #[test]
    fn full_layouts_encode_the_profile_statement() {
        for profile in Profile::all() {
            let layout = Layout::full(profile);
            assert_eq!(layout.header(), profile.setup_statement_header());
            assert_eq!(layout.encoded_length(), profile.setup_statement_length());
        }
    }

    #[test]
    fn malformed_or_unbound_statements_never_return_an_operator() {
        let mut random = Random(0x2545_f491_4f6c_dd1d);
        for (participants, options) in [(3, 2), (10, 10), (16, 2)] {
            let layout = reduced(Profile::new(participants, options).unwrap());
            let (original, _) = satisfying_relation(layout, &mut random);
            let digest: [u8; 64] = ProtocolHash::digest(&original).into();
            let header = layout.header().len();
            let share = header
                + (0..layout.profile.share_common_polynomial())
                    .map(|index| {
                        let (family, degree) = layout.polynomial(index).unwrap();
                        degree * (1 + layout.profile.family_magnitude_bytes(family))
                    })
                    .sum::<usize>();
            let expected = [
                Error::Parameters,
                Error::Encoding,
                Error::Incomplete,
                Error::Length,
                Error::Binding,
                Error::Encoding,
            ];
            for (kind, expected) in expected.into_iter().enumerate() {
                let mut bytes = original.clone();
                match kind {
                    0 => bytes[0] ^= 1,
                    1 => bytes[header] = 2,
                    2 => {
                        bytes.pop();
                    }
                    3 => bytes.push(0),
                    4 => bytes[header + 1] ^= 1,
                    // A share coefficient beyond half the modulus.
                    _ => bytes[share + 1..share + 1 + share_modulus().len()].fill(0xff),
                }
                // Each statement but the unbound one is bound, so only its own
                // check can refuse it.
                let bound: [u8; 64] = if kind == 4 {
                    digest
                } else {
                    ProtocolHash::digest(&bytes).into()
                };
                assert_eq!(
                    stream(layout, &bytes, bound, &[0, 1]).err(),
                    Some(expected),
                    "kind {kind}"
                );
            }
        }
        let layout = reduced(Profile::new(3, 2).unwrap());
        let mut stream =
            SetupStatementStream::with_layout(layout, [0; 64], [17, 37, 91], &[0, 1]).unwrap();
        assert_eq!(stream.push(&vec![0; CHUNK_LIMIT + 1]), Err(Error::Length));
        assert_eq!(stream.push(&[]), Err(Error::Encoding));
        assert!(stream.finish().is_err());
    }
}
