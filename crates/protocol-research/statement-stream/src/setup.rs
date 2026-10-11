use super::{
    CHUNK_LIMIT, Element, Error, MODULUS, ONE, PolynomialRecords, PolynomialStream, ZERO,
    arithmetic, fingerprint_in, jobs, minus, plus, power, query, times,
};
use parallel_work::{HashStream, Pipeline, Sponge, Ticket};
use std::collections::VecDeque;
use supported_profile::{
    DEGREE, FHE_LIMB_BITS, FHE_SECRET_SUPPORT, Family, Profile, SETUP_ERROR_BITS,
    SETUP_FHE_CARRY_BITS, SETUP_QUOTIENT_BITS, SHARE_EPHEMERAL_SUPPORT, share_modulus,
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
    fhe_half_support: usize,
    share_half_support: usize,
}
impl Layout {
    fn full(profile: Profile) -> Self {
        Self {
            profile,
            degree: DEGREE,
            fhe_half_support: FHE_SECRET_SUPPORT / 2,
            share_half_support: SHARE_EPHEMERAL_SUPPORT / 2,
        }
    }
    fn header(self) -> Vec<u8> {
        let mut header = self.profile.setup_statement_header();
        header[4..8].copy_from_slice(&(self.degree as u32).to_le_bytes());
        header
    }
    fn polynomial(self, index: usize) -> Option<(Family, usize)> {
        self.profile
            .setup_family(index)
            .map(|family| (family, self.degree))
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
            // Each ring position's offset is a whole number of units between
            // minus and plus the sharing coefficients' count. A planning pass
            // records only the geometries.
            let mut units = (!self.planning).then(|| vec![0i128; degree]);
            for (index, (low, high)) in sharing.iter().enumerate() {
                let shift = point * (index + 1);
                let key = GeometryKey::shifted(degree, shift);
                self.put(low, key, scale(self.weight, SHARE_SCALE as u128))?;
                self.put(high, key, scale(times(self.weight, z), SHARE_SCALE as u128))?;
                if let Some(units) = &mut units {
                    for input in 0..degree {
                        let exponent = (input + shift) % (2 * degree);
                        units[exponent % degree] += if exponent < degree { 1 } else { -1 };
                    }
                }
            }
            if let Some(units) = units {
                // The powers of alpha at the positions of each unit count,
                // weighted once by that offset's fingerprint.
                let bound = sharing.len() as i128;
                let mut powers = vec![ZERO; 2 * sharing.len() + 1];
                let mut current = ONE;
                for count in units {
                    let slot = &mut powers[(count + bound) as usize];
                    *slot = plus(*slot, current);
                    current = times(current, self.alpha);
                }
                let unit = SHARE_SCALE * (radix / 2);
                let mut sum = ZERO;
                for (slot, powers) in powers.into_iter().enumerate() {
                    let offset = (slot as i128 - bound) * unit;
                    sum = plus(sum, times(powers, signed_fingerprint(offset, limb_bits, z)));
                }
                self.target = minus(self.target, times(self.weight, sum));
            }
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
pub struct StatementOutput {
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
    pub fn finish(self) -> Result<StatementOutput, Error> {
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
        Ok(StatementOutput {
            statement_digest: digest,
            target: accumulator.target,
            lookup_weight: accumulator.weight,
            coefficients: accumulator.coefficients,
        })
    }
}

#[cfg(test)]
#[path = "setup-tests.rs"]
mod tests;
