#[path = "query-domain.rs"]
mod query_domain;
#[path = "proof-transcript.rs"]
mod transcript;
use query_domain::{Coset, Point};
pub(crate) use transcript::context;
use transcript::{Challenges, Header, Reader, Shape, challenges, hash_after, prefix, requested};

use parallel_work::ProtocolHash;
use statement_stream::StatementOutput;
use statement_stream::proof_field::{
    MODULUS, add as add_base, multiply as multiply_base, power as power_base,
    subtract as subtract_base,
};
use std::collections::BTreeMap;
use supported_profile::relation::{EVALUATION_DOMAIN_SIZE, Relation};

#[path = "lookup-table.rs"]
mod lookup_table;

type Element = [u128; 3];
const ZERO: Element = [0, 0, 0];
const ONE: Element = [1, 0, 0];
const FOLDS: usize = (EVALUATION_DOMAIN_SIZE / 2).ilog2() as usize;
pub const HEADER_LENGTH: usize = 4 + 64 + 3 * 64 + 48 + (FOLDS + 3) * 128 + (FOLDS - 1) * 64 + 48;
pub use parallel_work::CHUNK_LIMIT;

/// The public statement parser of one relation. It yields the relation's
/// affine operator at the verifier's queries.
pub trait Statement {
    fn push(&mut self, bytes: &[u8]) -> bool;
    fn finish(self) -> Option<StatementOutput>;
}

fn add(left: Element, right: Element) -> Element {
    std::array::from_fn(|i| add_base(left[i], right[i]))
}
fn subtract(left: Element, right: Element) -> Element {
    std::array::from_fn(|i| subtract_base(left[i], right[i]))
}
fn scale(value: Element, factor: u128) -> Element {
    value.map(|entry| multiply_base(entry, factor))
}
fn multiply(left: Element, right: Element) -> Element {
    statement_stream::proof_field::multiply_extension(left, right)
}
fn encode(value: Element) -> [u8; 48] {
    let mut bytes = [0; 48];
    for (index, entry) in value.iter().enumerate() {
        bytes[16 * index..16 * (index + 1)].copy_from_slice(&entry.to_le_bytes());
    }
    bytes
}
fn root(length: usize) -> u128 {
    power_base(7, (MODULUS - 1) / length as u128)
}
#[derive(Debug)]
pub enum Refusal {
    Encoding,
    Length,
    Context,
    Authentication,
    Relation,
    Phase,
}
struct Row {
    words: Vec<u128>,
    multiplicity: u128,
    linear: Element,
    combined: Element,
    quotient_coefficient: Element,
}

pub struct Verifier<S> {
    shape: Shape,
    role: Vec<u8>,
    header: Header,
    challenges: Challenges,
    statement: Option<S>,
    operator: Option<StatementOutput>,
    statement_done: bool,
    indices: Vec<usize>,
    points: Vec<Point>,
    rows: Vec<Row>,
    values: Vec<Element>,
    expected_fold: Vec<(usize, Element)>,
    stage: usize,
    position: usize,
    reading_count: bool,
    buffer: Vec<u8>,
    authenticated_nodes: BTreeMap<usize, [u8; 64]>,
    // The current stage's leaf and node hashes after their domain, the
    // role and the stage.
    leaf_prefix: ProtocolHash,
    node_prefix: ProtocolHash,
    failed: bool,
    complete: bool,
}
impl<S: Statement> Verifier<S> {
    /// Opens a proof of the relation. The proof's context binds the
    /// statement digest the header declares, so the header fixes the
    /// challenges before the statement parser opens, and the parser must
    /// recompute that digest from the statement.
    pub fn open(
        relation: Relation,
        role: &[u8],
        proof_header: &[u8],
        open_statement: impl FnOnce([u8; 64], Element, &[u32]) -> Option<S>,
    ) -> Result<Self, Refusal> {
        if role.is_empty() || role.len() > 1024 {
            return Err(Refusal::Context);
        }
        let header = Header::parse(proof_header, relation.proof_magic)?;
        let shape = Shape::new(&relation);
        let context = context(&relation, role, &header.statement);
        let challenges = challenges(&shape, role, &context, &header);
        let indices = requested(&challenges.queries, EVALUATION_DOMAIN_SIZE);
        let selected: Vec<u32> = indices.iter().map(|index| *index as u32).collect();
        let statement = open_statement(header.statement, challenges.alpha, &selected)
            .ok_or(Refusal::Context)?;
        Ok(Self {
            shape,
            role: role.to_vec(),
            header,
            challenges,
            statement: Some(statement),
            operator: None,
            statement_done: false,
            indices,
            points: Vec::new(),
            rows: Vec::new(),
            values: Vec::new(),
            expected_fold: Vec::new(),
            stage: 0,
            position: 0,
            reading_count: true,
            buffer: Vec::new(),
            authenticated_nodes: BTreeMap::new(),
            leaf_prefix: prefix(b"bounded-proof/leaf", &[role, &0u32.to_le_bytes()]),
            node_prefix: prefix(b"bounded-proof/node", &[role, &0u32.to_le_bytes()]),
            failed: false,
            complete: false,
        })
    }
    pub fn push_statement(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || self.statement_done {
            return Err(Refusal::Phase);
        }
        if bytes.len() > CHUNK_LIMIT {
            self.failed = true;
            return Err(Refusal::Length);
        }
        if !self.statement.as_mut().ok_or(Refusal::Phase)?.push(bytes) {
            self.failed = true;
            return Err(Refusal::Encoding);
        }
        Ok(())
    }
    pub fn finish_statement(&mut self) -> Result<(), Refusal> {
        if self.failed || self.statement_done {
            return Err(Refusal::Phase);
        }
        self.operator = Some(
            self.statement
                .take()
                .ok_or(Refusal::Phase)?
                .finish()
                .ok_or(Refusal::Encoding)?,
        );
        let table = lookup_table::on_proof_domain();
        self.points = self
            .indices
            .iter()
            .map(|index| Point::new(*index, table[*index]))
            .collect();
        self.statement_done = true;
        Ok(())
    }
    fn stage_shape(&self) -> (usize, usize, [u8; 64]) {
        if self.stage < 3 {
            (
                EVALUATION_DOMAIN_SIZE,
                [self.shape.first_width, self.shape.second_width, 48][self.stage],
                self.header.roots[self.stage],
            )
        } else {
            let round = self.stage - 3;
            (
                EVALUATION_DOMAIN_SIZE >> (round + 1),
                48,
                self.header.fold_roots[round],
            )
        }
    }
    fn missing_siblings(&self, index: usize, length: usize) -> usize {
        let mut node = length + index;
        let mut count = 0;
        while node > 1 && !self.authenticated_nodes.contains_key(&node) {
            count += usize::from(!self.authenticated_nodes.contains_key(&(node ^ 1)));
            node /= 2;
        }
        count
    }
    fn opening(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let (length, width, root) = self.stage_shape();
        let mut reader = Reader::new(bytes);
        let index = reader.word()?;
        if self.indices.get(self.position) != Some(&index) {
            return Err(Refusal::Encoding);
        }
        let data = reader.take(width)?;
        let mut fields = Reader::new(data);
        for _ in 0..width / 16 {
            fields.base()?;
        }
        let salt = reader.take(128)?;
        let mut digest = hash_after(
            &self.leaf_prefix,
            &[&(index as u32).to_le_bytes(), salt, data],
        );
        let mut node = length + index;
        let mut pending = Vec::new();
        let mut level = 1u32;
        while node > 1 && !self.authenticated_nodes.contains_key(&node) {
            pending.push((node, digest));
            let sibling = if let Some(known) = self.authenticated_nodes.get(&(node ^ 1)) {
                *known
            } else {
                let supplied: [u8; 64] = reader.take(64)?.try_into().unwrap();
                pending.push((node ^ 1, supplied));
                supplied
            };
            digest = if node.is_multiple_of(2) {
                hash_after(
                    &self.node_prefix,
                    &[&level.to_le_bytes(), &digest, &sibling],
                )
            } else {
                hash_after(
                    &self.node_prefix,
                    &[&level.to_le_bytes(), &sibling, &digest],
                )
            };
            node /= 2;
            level += 1;
        }
        let expected = self.authenticated_nodes.get(&node).unwrap_or(&root);
        if &digest != expected || reader.position != bytes.len() {
            return Err(Refusal::Authentication);
        }
        self.authenticated_nodes.extend(pending);
        match self.stage {
            0 => self.first(data)?,
            1 => self.second(data)?,
            2 => {
                let value = Reader::new(data).element()?;
                let row = &self.rows[self.position];
                self.values
                    .push(add(row.combined, multiply(row.quotient_coefficient, value)));
            }
            _ => {
                let value = Reader::new(data).element()?;
                if let Ok(expected) = self
                    .expected_fold
                    .binary_search_by_key(&index, |(index, _)| *index)
                    && self.expected_fold[expected].1 != value
                {
                    return Err(Refusal::Relation);
                }
                self.values.push(value);
            }
        }
        Ok(())
    }
    fn first(&mut self, data: &[u8]) -> Result<(), Refusal> {
        let shape = &self.shape;
        let mut reader = Reader::new(data);
        let mut words = Vec::with_capacity(shape.columns);
        for _ in 0..shape.columns {
            words.push(reader.base()?);
        }
        let multiplicity = reader.base()?;
        let mut combined = reader.element()?;
        let point = &self.points[self.position];
        let operator = self.operator.as_ref().ok_or(Refusal::Phase)?;
        let mut linear = ZERO;
        for (column, value) in words.iter().enumerate() {
            linear = add(
                linear,
                scale(
                    operator.coefficients[column * self.indices.len() + self.position],
                    *value,
                ),
            );
            combined = add(
                combined,
                scale(point.weight(shape, &self.challenges, column), *value),
            );
        }
        combined = add(
            combined,
            scale(
                point.weight(shape, &self.challenges, shape.columns),
                multiplicity,
            ),
        );
        for index in 0..shape.booleans {
            let value = words[shape.words + index];
            let residue = multiply_base(
                multiply_base(value, subtract_base(value, 1)),
                point.inverse_vanishing,
            );
            combined = add(
                combined,
                scale(
                    point.weight(shape, &self.challenges, shape.original + index),
                    residue,
                ),
            );
        }
        for (pair, (left, right)) in shape.zero_products.iter().enumerate() {
            let residue = multiply_base(
                multiply_base(words[*left], words[*right]),
                point.inverse_vanishing,
            );
            combined = add(
                combined,
                scale(
                    point.weight(
                        shape,
                        &self.challenges,
                        shape.original + shape.booleans + pair,
                    ),
                    residue,
                ),
            );
        }
        self.rows.push(Row {
            words,
            multiplicity,
            linear,
            combined,
            quotient_coefficient: ZERO,
        });
        Ok(())
    }
    fn second(&mut self, data: &[u8]) -> Result<(), Refusal> {
        let shape = &self.shape;
        let point = &self.points[self.position];
        let row = &mut self.rows[self.position];
        let mut reader = Reader::new(data);
        let mut sum = ZERO;
        let lookups = shape.lookups.len();
        for (index, (column, factor)) in shape.lookups.iter().enumerate() {
            let value = reader.element()?;
            sum = add(sum, value);
            row.combined = add(
                row.combined,
                multiply(
                    point.weight(shape, &self.challenges, shape.columns + 1 + index),
                    value,
                ),
            );
            let denominator = subtract(
                self.challenges.beta,
                [multiply_base(row.words[*column], *factor), 0, 0],
            );
            let residue = scale(
                subtract(multiply(value, denominator), ONE),
                point.inverse_vanishing,
            );
            row.combined = add(
                row.combined,
                multiply(
                    point.weight(
                        shape,
                        &self.challenges,
                        shape.original + shape.booleans + shape.zero_products.len() + index,
                    ),
                    residue,
                ),
            );
        }
        let table_inverse = reader.element()?;
        let mask = reader.element()?;
        row.combined = add(
            row.combined,
            multiply(
                point.weight(shape, &self.challenges, shape.columns + 1 + lookups),
                table_inverse,
            ),
        );
        row.combined = add(
            row.combined,
            multiply(
                point.weight(shape, &self.challenges, shape.columns + 2 + lookups),
                mask,
            ),
        );
        let table_residue = scale(
            subtract(
                multiply(
                    subtract(self.challenges.beta, [point.table, 0, 0]),
                    table_inverse,
                ),
                [row.multiplicity, 0, 0],
            ),
            point.inverse_vanishing,
        );
        row.combined = add(
            row.combined,
            multiply(
                point.weight(shape, &self.challenges, shape.oracles - 2),
                table_residue,
            ),
        );
        let operator = self.operator.as_ref().ok_or(Refusal::Phase)?;
        let linear = add(
            row.linear,
            multiply(operator.lookup_weight, subtract(sum, table_inverse)),
        );
        let claimed = add(
            multiply(self.challenges.mask, operator.target),
            self.header.mask_sum,
        );
        let numerator = subtract(
            add(multiply(self.challenges.mask, linear), mask),
            scale(claimed, Coset::get().inverse_systematic),
        );
        let remainder_weight = point.weight(shape, &self.challenges, shape.oracles - 1);
        row.combined = add(
            row.combined,
            multiply(remainder_weight, scale(numerator, point.inverse)),
        );
        row.quotient_coefficient = subtract(
            point.weight(shape, &self.challenges, shape.original - 1),
            scale(
                remainder_weight,
                multiply_base(point.vanishing, point.inverse),
            ),
        );
        row.words = Vec::new();
        Ok(())
    }
    fn advance(&mut self) -> Result<(), Refusal> {
        self.authenticated_nodes.clear();
        if self.stage == 0
            && let Some(operator) = &mut self.operator
        {
            operator.coefficients = Vec::new();
        }
        if self.stage >= 2 {
            let length = if self.stage == 2 {
                EVALUATION_DOMAIN_SIZE
            } else {
                EVALUATION_DOMAIN_SIZE >> (self.stage - 2)
            };
            let round = if self.stage == 2 { 0 } else { self.stage - 2 };
            let coset = Coset::get();
            let mut expected = Vec::new();
            for index in requested(&self.challenges.queries, length)
                .into_iter()
                .filter(|index| *index < length / 2)
            {
                let left = self.values[self
                    .indices
                    .binary_search(&index)
                    .map_err(|_| Refusal::Encoding)?];
                let right = self.values[self
                    .indices
                    .binary_search(&(index + length / 2))
                    .map_err(|_| Refusal::Encoding)?];
                let folded = add(
                    scale(add(left, right), coset.half),
                    multiply(
                        self.challenges.folds[round],
                        scale(
                            subtract(left, right),
                            multiply_base(coset.half, coset.inverse_fold_point(round, index)),
                        ),
                    ),
                );
                if round == FOLDS - 1 {
                    if folded != self.header.terminal {
                        return Err(Refusal::Relation);
                    }
                } else {
                    expected.push((index, folded));
                }
            }
            if round == FOLDS - 1 {
                self.complete = true;
                self.rows = Vec::new();
                self.values = Vec::new();
                return Ok(());
            }
            self.expected_fold = expected;
            self.values = Vec::new();
            if self.stage == 2 {
                self.rows = Vec::new();
                self.points = Vec::new();
                self.operator = None;
            }
        }
        self.stage += 1;
        let stage = (self.stage as u32).to_le_bytes();
        self.leaf_prefix = prefix(b"bounded-proof/leaf", &[&self.role, &stage]);
        self.node_prefix = prefix(b"bounded-proof/node", &[&self.role, &stage]);
        let length = if self.stage < 3 {
            EVALUATION_DOMAIN_SIZE
        } else {
            EVALUATION_DOMAIN_SIZE >> (self.stage - 2)
        };
        self.indices = requested(&self.challenges.queries, length);
        self.position = 0;
        self.reading_count = true;
        Ok(())
    }
    pub fn push_proof(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || !self.statement_done {
            return Err(Refusal::Phase);
        }
        if bytes.len() > CHUNK_LIMIT {
            self.failed = true;
            return Err(Refusal::Length);
        }
        let result = (|| {
            while !bytes.is_empty() {
                if self.complete {
                    return Err(Refusal::Length);
                }
                let (length, width, _) = self.stage_shape();
                let required = if self.reading_count {
                    4
                } else {
                    4 + width
                        + 128
                        + 64 * self.missing_siblings(self.indices[self.position], length)
                };
                let count = bytes.len().min(required - self.buffer.len());
                self.buffer.extend_from_slice(&bytes[..count]);
                bytes = &bytes[count..];
                if self.buffer.len() == required {
                    let buffered = std::mem::take(&mut self.buffer);
                    if self.reading_count {
                        if u32::from_le_bytes(buffered.as_slice().try_into().unwrap()) as usize
                            != self.indices.len()
                        {
                            return Err(Refusal::Encoding);
                        }
                        self.reading_count = false;
                    } else {
                        self.opening(&buffered)?;
                        self.position += 1;
                        if self.position == self.indices.len() {
                            self.advance()?;
                        }
                    }
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
            self.operator = None;
            self.rows = Vec::new();
            self.values = Vec::new();
        }
        result
    }
    pub fn finish(self) -> bool {
        !self.failed && self.statement_done && self.complete && self.buffer.is_empty()
    }
}

#[cfg(test)]
#[path = "engine-tests.rs"]
mod tests;
