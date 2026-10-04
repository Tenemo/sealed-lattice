//! Public operator resource/parity screen. It constructs no witness, proof,
//! registration, predecessor, selected set, or participant capability.
#![deny(unsafe_op_in_unsafe_fn)]

mod recipe;
mod reference;

use parallel_work::ProtocolHash;
use recipe::{COEFFICIENT_BYTES, Recipe};
use std::collections::BTreeSet;
use word_proof::{
    affine::{Operator, PublicColumn},
    field::{self, Element, ONE, ZERO},
    parameters::{DOMAIN, QUERY_COUNT, SYSTEMATIC},
};

pub const DEGREE: usize = SYSTEMATIC;
pub const SEED_BITS: usize = 512;
pub const ALPHA: Element = [13, 17, 19];
const GEOMETRY: reference::Geometry = reference::Geometry {
    degree: DEGREE,
    seed_bits: SEED_BITS,
    alpha: ALPHA,
};
const QUERY_SAMPLES: usize = 8;
const REPORT_HEADER_BYTES: usize = 4 + 8 * 4 + 3 * 48 + 2 * 64 + 2 * 4;
pub const OUTPUT_BYTES: usize = REPORT_HEADER_BYTES + (18 + QUERY_SAMPLES) * 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Case {
    Seed = 0,
    Opening = 1,
}
impl TryFrom<u32> for Case {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Seed),
            1 => Ok(Self::Opening),
            _ => Err(Error::Computation("Unknown operator case")),
        }
    }
}
impl Case {
    fn polynomials(self) -> usize {
        if self == Self::Seed { 13 } else { 6 }
    }
    pub fn name(self) -> &'static str {
        if self == Self::Seed {
            "seed"
        } else {
            "opening"
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Stage,
    Computation(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stage => formatter.write_str("Operator screen stage"),
            Self::Computation(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for Error {}
impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Self::Computation(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Sample {
    column: usize,
    index: usize,
    value: Element,
}

enum Accumulator {
    Seed(Box<seed_sharing_proof::operator::Accumulator>),
    Opening(Box<opening_share_proof::operator::Accumulator>),
}
impl Accumulator {
    fn new(case: Case) -> Result<Self, Error> {
        Ok(match case {
            Case::Seed => Self::Seed(Box::new(seed_sharing_proof::operator::Accumulator::new(
                DEGREE, SEED_BITS, ALPHA,
            )?)),
            Case::Opening => Self::Opening(Box::new(
                opening_share_proof::operator::Accumulator::new(DEGREE, ALPHA)?,
            )),
        })
    }
    fn push(&mut self, index: usize, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Seed(value) => value.push(index, bytes)?,
            Self::Opening(value) => value.push(index, bytes)?,
        }
        Ok(())
    }
    fn finish_polynomial(&mut self, index: usize) -> Result<(), Error> {
        match self {
            Self::Seed(value) => value.finish_polynomial(index)?,
            Self::Opening(value) => value.finish_polynomial(index)?,
        }
        Ok(())
    }
    fn finish(self) -> Result<Operator, Error> {
        Ok(match self {
            Self::Seed(value) => value.finish()?,
            Self::Opening(value) => value.finish()?,
        })
    }
}

/// Sorted, distinct lower-half positions and their upper-half partners, as
/// consumed by the real verifier. Boundaries coexist with spread positions.
pub fn queries() -> Vec<u32> {
    let half = DOMAIN / 2;
    let mut lower = BTreeSet::from([0, 1, DEGREE - 1, DEGREE, DEGREE + 1, half - 2, half - 1]);
    for index in 0..QUERY_COUNT {
        if lower.len() == QUERY_COUNT {
            break;
        }
        lower.insert(index * (half - 1) / (QUERY_COUNT - 1));
    }
    for index in 0..half {
        if lower.len() == QUERY_COUNT {
            break;
        }
        lower.insert(index);
    }
    lower
        .iter()
        .chain(lower.iter())
        .enumerate()
        .map(|(position, index)| (index + if position < QUERY_COUNT { 0 } else { half }) as u32)
        .collect()
}

fn query_hasher(columns: usize, queries: &[u32]) -> ProtocolHash {
    let mut hash = ProtocolHash::new();
    word_proof::transcript::part(&mut hash, b"public-operator-query-values/v1");
    hash.update((columns as u32).to_le_bytes());
    hash.update((queries.len() as u32).to_le_bytes());
    for index in queries {
        hash.update(index.to_le_bytes());
    }
    hash
}

/// Expands only one mathematical column. This is deliberately a direct
/// scatter of the term definition, not the at_queries factorization.
fn column(operator: &Operator, selected: usize) -> Result<Vec<Element>, Error> {
    let mut output = vec![ZERO; DEGREE];
    for term in &operator.terms {
        let mut weight = ZERO;
        for (candidate, value) in &term.weights {
            if *candidate == selected {
                weight = field::add(weight, *value);
            }
        }
        if weight == ZERO {
            continue;
        }
        let count = match &term.public {
            PublicColumn::Powers(count) | PublicColumn::Ones(count) => *count,
            PublicColumn::Values(values) => values.len(),
        };
        if count != DEGREE {
            return Err(Error::Computation("Operator physical degree"));
        }
        let mut power = ONE;
        for (row, target) in output.iter_mut().enumerate() {
            let value = match &term.public {
                PublicColumn::Powers(_) => {
                    let value = power;
                    power = field::multiply(power, operator.alpha);
                    value
                }
                PublicColumn::Ones(_) => ONE,
                PublicColumn::Values(values) => values[row],
            };
            *target = field::add(*target, field::multiply(weight, value));
        }
    }
    Ok(output)
}
fn physical(
    operator: &Operator,
    degree: usize,
    column: usize,
    row: usize,
) -> Result<Element, Error> {
    let mut result = ZERO;
    for term in &operator.terms {
        let value = match &term.public {
            PublicColumn::Powers(count) if *count == degree => {
                reference::power(operator.alpha, row)
            }
            PublicColumn::Ones(count) if *count == degree => ONE,
            PublicColumn::Values(values) if values.len() == degree => values[row],
            _ => return Err(Error::Computation("Operator physical degree")),
        };
        for (candidate, weight) in &term.weights {
            if *candidate == column {
                result = field::add(result, field::multiply(*weight, value));
            }
        }
    }
    Ok(result)
}

pub struct Screen {
    case: Case,
    phase: u32,
    recipe: Recipe,
    layout: reference::Layout,
    accumulator: Option<Accumulator>,
    polynomial: usize,
    row: usize,
    operator: Option<Operator>,
    target: Element,
    lookup_weight: Element,
    physical_samples: Vec<Sample>,
    sample: usize,
    query_samples: Vec<Sample>,
    queries: Vec<u32>,
    column: usize,
    operator_hash: Option<ProtocolHash>,
    reference_hash: Option<ProtocolHash>,
    operator_digest: [u8; 64],
    reference_digest: [u8; 64],
    query_output: Vec<Element>,
    output: Vec<u8>,
    report: Option<Vec<u8>>,
}
impl Screen {
    pub fn new(case: Case) -> Result<Self, Error> {
        let layout = reference::Layout::new(case);
        let actual = match case {
            Case::Seed => seed_sharing_proof::layout::Layout::new(0)
                .relation
                .columns(),
            Case::Opening => opening_share_proof::layout::Layout::new(0)
                .relation
                .columns(),
        };
        if layout.columns != actual {
            return Err(Error::Computation("Independent column layout"));
        }
        let queries = queries();
        let selections = [
            (0, 0),
            (0, QUERY_COUNT - 1),
            (layout.columns - 1, QUERY_COUNT),
            (layout.columns - 1, 2 * QUERY_COUNT - 1),
            (layout.words, 1),
            (layout.words, QUERY_COUNT / 2),
            (layout.words + 1, QUERY_COUNT + 1),
            (layout.words + 1, QUERY_COUNT + QUERY_COUNT / 2),
        ];
        let query_samples = selections
            .into_iter()
            .map(|(column, position)| Sample {
                column,
                index: queries[position] as usize,
                value: ZERO,
            })
            .collect();
        let reference_hash = Some(query_hasher(layout.columns, &queries));
        let physical_samples = layout.samples(case);
        Ok(Self {
            case,
            phase: 1,
            recipe: Recipe::default(),
            layout,
            accumulator: Some(Accumulator::new(case)?),
            polynomial: 0,
            row: 0,
            operator: None,
            target: ZERO,
            lookup_weight: ZERO,
            physical_samples,
            sample: 0,
            query_samples,
            queries,
            column: 0,
            operator_hash: None,
            reference_hash,
            operator_digest: [0; 64],
            reference_digest: [0; 64],
            query_output: Vec::new(),
            output: Vec::new(),
            report: None,
        })
    }
    pub fn phase(&self) -> u32 {
        self.phase
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn step(&mut self) -> Result<(), Error> {
        match self.phase {
            1 => self.build(),
            2 => self.check_physical(),
            3 => self.reference_column(),
            4 => {
                self.query_output = self
                    .operator
                    .take()
                    .ok_or(Error::Stage)?
                    .at_queries(self.layout.columns, &self.queries)
                    .map_err(|_| Error::Computation("Operator query evaluation"))?;
                self.phase = 5;
                Ok(())
            }
            5 => self.finish_report(),
            _ => Err(Error::Stage),
        }
    }
    fn build(&mut self) -> Result<(), Error> {
        let count = (setup_stream_kernel::CHUNK_LIMIT / COEFFICIENT_BYTES).min(DEGREE - self.row);
        let bytes = self
            .recipe
            .chunk(self.case, self.polynomial, self.row, count);
        let accumulator = self.accumulator.as_mut().ok_or(Error::Stage)?;
        accumulator.push(self.polynomial, &bytes)?;
        self.row += count;
        if self.row == DEGREE {
            accumulator.finish_polynomial(self.polynomial)?;
            self.polynomial += 1;
            self.row = 0;
            if self.polynomial == self.case.polynomials() {
                let operator = self.accumulator.take().ok_or(Error::Stage)?.finish()?;
                self.target = operator.target;
                self.lookup_weight = operator.lookup_weight;
                let mut hash = ProtocolHash::new();
                word_proof::transcript::part(&mut hash, b"public-operator-matrix/v1");
                hash.update((DEGREE as u32).to_le_bytes());
                hash.update((self.layout.columns as u32).to_le_bytes());
                hash.update(field::encode(self.target));
                hash.update(field::encode(self.lookup_weight));
                self.operator_hash = Some(hash);
                self.operator = Some(operator);
                self.phase = 2;
            }
        }
        Ok(())
    }
    fn check_physical(&mut self) -> Result<(), Error> {
        if let Some(sample) = self.physical_samples.get_mut(self.sample) {
            let expected = reference::coefficient(
                &self.recipe,
                self.case,
                &self.layout,
                &GEOMETRY,
                sample.column,
                sample.index,
            );
            let actual = physical(
                self.operator.as_ref().ok_or(Error::Stage)?,
                DEGREE,
                sample.column,
                sample.index,
            )?;
            if actual != expected {
                return Err(Error::Computation(
                    "Independent physical coefficient mismatch",
                ));
            }
            sample.value = actual;
            self.sample += 1;
        } else {
            let (target, lookup) =
                reference::target(&self.recipe, self.case, &self.layout, &GEOMETRY);
            if (target, lookup) != (self.target, self.lookup_weight) {
                return Err(Error::Computation("Independent target or lookup mismatch"));
            }
            self.phase = 3;
        }
        Ok(())
    }
    fn reference_column(&mut self) -> Result<(), Error> {
        let values = column(self.operator.as_ref().ok_or(Error::Stage)?, self.column)?;
        let hash = self.operator_hash.as_mut().ok_or(Error::Stage)?;
        for value in &values {
            hash.update(field::encode(*value));
        }
        // This uses the existing interpolation kernel after a different
        // scatter order. It is plumbing/math parity, not an independent
        // dense-equation verification of every interpolated coefficient.
        let evaluated = setup_stream_kernel::evaluate_public_columns(vec![values], &self.queries)
            .map_err(|_| Error::Computation("Column query reference"))?;
        let hash = self.reference_hash.as_mut().ok_or(Error::Stage)?;
        for value in &evaluated {
            hash.update(field::encode(*value));
        }
        for sample in &mut self.query_samples {
            if sample.column == self.column {
                let position = self
                    .queries
                    .binary_search(&(sample.index as u32))
                    .map_err(|_| Error::Computation("Query sample index"))?;
                sample.value = evaluated[position];
            }
        }
        self.column += 1;
        if self.column == self.layout.columns {
            self.operator_digest = self.operator_hash.take().ok_or(Error::Stage)?.finalize();
            self.reference_digest = self.reference_hash.take().ok_or(Error::Stage)?.finalize();
            self.phase = 4;
        }
        Ok(())
    }
    fn finish_report(&mut self) -> Result<(), Error> {
        if self.query_output.len() != self.layout.columns * self.queries.len() {
            return Err(Error::Computation("Query output shape"));
        }
        let mut hash = query_hasher(self.layout.columns, &self.queries);
        for value in &self.query_output {
            hash.update(field::encode(*value));
        }
        let digest = hash.finalize();
        if digest != self.reference_digest {
            return Err(Error::Computation("Full query output mismatch"));
        }
        for sample in &self.query_samples {
            let position = self
                .queries
                .binary_search(&(sample.index as u32))
                .map_err(|_| Error::Computation("Query sample index"))?;
            if self.query_output[sample.column * self.queries.len() + position] != sample.value {
                return Err(Error::Computation("Query sample mismatch"));
            }
        }
        let mut report = Vec::with_capacity(
            REPORT_HEADER_BYTES + (self.physical_samples.len() + self.query_samples.len()) * 56,
        );
        report.extend(b"OPR1");
        for value in [
            self.case as usize,
            DEGREE,
            4,
            2,
            2,
            SEED_BITS,
            self.layout.columns,
            self.queries.len(),
        ] {
            report.extend((value as u32).to_le_bytes());
        }
        for value in [ALPHA, self.target, self.lookup_weight] {
            report.extend(field::encode(value));
        }
        report.extend(self.operator_digest);
        report.extend(digest);
        for count in [self.physical_samples.len(), self.query_samples.len()] {
            report.extend((count as u32).to_le_bytes());
        }
        for sample in self.physical_samples.iter().chain(&self.query_samples) {
            report.extend((sample.column as u32).to_le_bytes());
            report.extend((sample.index as u32).to_le_bytes());
            report.extend(field::encode(sample.value));
        }
        if report.len() > OUTPUT_BYTES {
            return Err(Error::Computation("Report bound"));
        }
        self.query_output = Vec::new();
        self.report = Some(report);
        self.phase = 12;
        Ok(())
    }
    pub fn next_output(&mut self) -> Result<(), Error> {
        if self.phase != 12 || !self.output.is_empty() {
            return Err(Error::Stage);
        }
        if let Some(report) = self.report.take() {
            self.output = report;
        } else {
            self.phase = 13;
        }
        Ok(())
    }
    pub fn acknowledge_output(&mut self) -> Result<(), Error> {
        if self.phase != 12 || self.output.is_empty() {
            return Err(Error::Stage);
        }
        self.output.clear();
        Ok(())
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Default)]
struct State {
    screen: Option<Screen>,
}
#[cfg(any(test, target_arch = "wasm32"))]
impl State {
    fn begin(&mut self, case: u32) -> u32 {
        if self.screen.is_some() {
            return 6;
        }
        match Case::try_from(case).and_then(Screen::new) {
            Ok(screen) => {
                self.screen = Some(screen);
                0
            }
            Err(_) => 1,
        }
    }
    fn advance(&mut self, operation: fn(&mut Screen) -> Result<(), Error>) -> u32 {
        let Some(screen) = &mut self.screen else {
            return 6;
        };
        match operation(screen) {
            Ok(()) => 0,
            Err(Error::Stage) => 6,
            Err(Error::Computation(_)) => 1,
        }
    }
    fn phase(&self) -> u32 {
        self.screen.as_ref().map_or(0, Screen::phase)
    }
}

#[cfg(target_arch = "wasm32")]
mod browser;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queries_are_complete_distinct_paired_and_include_boundaries() {
        let values = queries();
        assert_eq!(values.len(), 2 * QUERY_COUNT);
        assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
        for (lower, upper) in values[..QUERY_COUNT].iter().zip(&values[QUERY_COUNT..]) {
            assert_eq!(*upper - *lower, (DOMAIN / 2) as u32);
        }
        for value in [
            0,
            1,
            DEGREE - 1,
            DEGREE,
            DEGREE + 1,
            DOMAIN / 2 - 1,
            DOMAIN - 1,
        ] {
            assert!(values.contains(&(value as u32)));
        }
    }
    #[test]
    fn state_refusals_preserve_pending_report_without_running_full_operator() {
        let mut state = State::default();
        assert_eq!(state.begin(2), 1);
        assert_eq!(state.phase(), 0);
        assert_eq!(state.advance(Screen::step), 6);
        // Exercise only output ownership. In particular, do not call the
        // full-ring accumulator constructor from a routine unit test.
        state.screen = Some(Screen {
            case: Case::Seed,
            phase: 1,
            recipe: Recipe::default(),
            layout: reference::Layout::new(Case::Seed),
            accumulator: None,
            polynomial: 0,
            row: 0,
            operator: None,
            target: ZERO,
            lookup_weight: ZERO,
            physical_samples: Vec::new(),
            sample: 0,
            query_samples: Vec::new(),
            queries: Vec::new(),
            column: 0,
            operator_hash: None,
            reference_hash: None,
            operator_digest: [0; 64],
            reference_digest: [0; 64],
            query_output: Vec::new(),
            output: Vec::new(),
            report: None,
        });
        assert_eq!(state.advance(Screen::acknowledge_output), 6);
        assert_eq!(state.advance(Screen::next_output), 6);
        let screen = state.screen.as_mut().unwrap();
        screen.accumulator = None;
        screen.phase = 12;
        screen.report = Some(vec![1, 2, 3]);
        assert_eq!(state.advance(Screen::next_output), 0);
        for operation in [Screen::step, Screen::next_output] {
            assert_eq!(state.advance(operation), 6);
        }
        assert_eq!(state.begin(1), 6);
        assert_eq!(state.screen.as_ref().unwrap().output(), [1, 2, 3]);
        assert_eq!(state.advance(Screen::acknowledge_output), 0);
        assert_eq!(state.advance(Screen::acknowledge_output), 6);
        assert_eq!(state.advance(Screen::next_output), 0);
        assert_eq!(state.phase(), 13);
        assert!(state.screen.as_ref().unwrap().output().is_empty());
        assert_eq!(state.advance(Screen::next_output), 6);
    }
    #[test]
    fn canonical_recipes_cover_signed_limb_and_modulus_edges() {
        let recipe = Recipe::default();
        for case in [Case::Seed, Case::Opening] {
            for polynomial in 0..case.polynomials() {
                let mut stream = setup_stream_kernel::PolynomialStream::new(
                    supported_profile::share_modulus(),
                    256,
                    96,
                    ALPHA,
                )
                .unwrap();
                let bytes = recipe.chunk(case, polynomial, 0, 256);
                stream.push(&bytes).unwrap();
                stream.finish_value().unwrap();
                assert!(bytes.chunks_exact(21).any(|record| record[0] == 1));
                assert!(
                    bytes
                        .chunks_exact(21)
                        .any(|record| record[13..].iter().any(|byte| *byte != 0))
                );
            }
        }
    }
    #[test]
    fn direct_equations_match_streamed_public_operators_on_a_bounded_ring() {
        let recipe = Recipe::default();
        for case in [Case::Seed, Case::Opening] {
            let layout = reference::Layout::new(case);
            for alpha in [ZERO, ONE, ALPHA] {
                let geometry = reference::Geometry {
                    degree: 256,
                    seed_bits: 4,
                    alpha,
                };
                let mut accumulator = match case {
                    Case::Seed => Accumulator::Seed(Box::new(
                        seed_sharing_proof::operator::Accumulator::new(256, 4, alpha).unwrap(),
                    )),
                    Case::Opening => Accumulator::Opening(Box::new(
                        opening_share_proof::operator::Accumulator::new(256, alpha).unwrap(),
                    )),
                };
                for polynomial in 0..case.polynomials() {
                    let bytes = recipe.chunk(case, polynomial, 0, 256);
                    // Coefficient boundaries may span caller chunks.
                    for part in bytes.chunks(127) {
                        accumulator.push(polynomial, part).unwrap();
                    }
                    accumulator.finish_polynomial(polynomial).unwrap();
                }
                let operator = accumulator.finish().unwrap();
                for column in 0..layout.columns {
                    for row in [0, 3, 4, 127, 128, 255] {
                        let expected =
                            reference::coefficient(&recipe, case, &layout, &geometry, column, row);
                        assert_eq!(
                            physical(&operator, 256, column, row).unwrap(),
                            expected,
                            "{case:?} alpha={alpha:?}, column={column}, row={row}"
                        );
                    }
                }
                assert_eq!(
                    (operator.target, operator.lookup_weight),
                    reference::target(&recipe, case, &layout, &geometry)
                );
            }
        }
    }
}
