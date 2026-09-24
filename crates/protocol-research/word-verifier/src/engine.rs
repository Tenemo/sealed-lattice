use crate::arithmetic::{
    MODULUS, add as add_base, multiply as multiply_base, power as power_base,
    subtract as subtract_base,
};
use crate::profile::*;
use crate::statement::{
    StatementOutput as SetupStatementOutput, StatementStream as SetupStatementStream,
};
use sha3::{
    Digest, Sha3_512, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::BTreeMap;

type Element = [u128; 3];
const ZERO: Element = [0, 0, 0];
const ONE: Element = [1, 0, 0];
pub const HEADER_LENGTH: usize =
    4 + 64 + 64 + 3 * 64 + 48 + (FOLDS + 3) * 128 + (FOLDS - 1) * 64 + 48;
pub const CHUNK_LIMIT: usize = 1 << 20;

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
    let mut result = ZERO;
    for (first, a) in left.iter().enumerate() {
        for (second, b) in right.iter().enumerate() {
            let mut value = multiply_base(*a, *b);
            if first + second >= 3 {
                value = add_base(value, value);
            }
            let index = (first + second) % 3;
            result[index] = add_base(result[index], value);
        }
    }
    result
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
fn degree(index: usize) -> usize {
    if index < ORIGINAL - 1 {
        WITNESS_DEGREE
    } else if index == ORIGINAL - 1 || index == ORACLES - 2 {
        WITNESS_DEGREE - 1
    } else if index == ORACLES - 1 {
        H - 2
    } else {
        2 * WITNESS_DEGREE - H
    }
}
fn parameter_bytes() -> Vec<u8> {
    let mut bytes: Vec<u8> = relation_parameters()
        .into_iter()
        .chain((0..ORACLES).map(degree))
        .flat_map(|value| (value as u32).to_le_bytes())
        .collect();
    for index in 0..LOOKUPS {
        let (column, scale) = lookup(index);
        bytes.extend((column as u32).to_le_bytes());
        bytes.extend((scale as u32).to_le_bytes());
    }
    bytes
}
fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    part(&mut hash, domain);
    for value in parts {
        part(&mut hash, value);
    }
    hash.finalize().into()
}
fn part(hash: &mut Sha3_512, bytes: &[u8]) {
    Digest::update(hash, (bytes.len() as u32).to_le_bytes());
    Digest::update(hash, bytes);
}
fn wide(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Shake256::default();
    Update::update(&mut hash, &(domain.len() as u32).to_le_bytes());
    Update::update(&mut hash, domain);
    for value in parts {
        Update::update(&mut hash, &(value.len() as u32).to_le_bytes());
        Update::update(&mut hash, value);
    }
    let mut output = vec![0; MESSAGE_BYTES];
    XofReader::read(&mut hash.finalize_xof(), &mut output);
    output
}
fn residue(bytes: &[u8], modulus: u128) -> u128 {
    let mut remainder = 0;
    for byte in bytes.iter().rev() {
        for bit in (0..8).rev() {
            let complement = modulus - remainder;
            remainder = if remainder >= complement {
                remainder - complement
            } else {
                remainder + remainder
            };
            if byte >> bit & 1 != 0 {
                remainder = if remainder == modulus - 1 {
                    0
                } else {
                    remainder + 1
                };
            }
        }
    }
    remainder
}
fn sample(message: &[u8], index: usize, nonbase: bool) -> Element {
    std::array::from_fn(|coordinate| {
        let nonzero = nonbase && coordinate == 2;
        let value = residue(
            &message[96 * index + 32 * coordinate..96 * index + 32 * (coordinate + 1)],
            if nonzero { MODULUS - 1 } else { MODULUS },
        );
        value + u128::from(nonzero)
    })
}

#[derive(Debug)]
pub enum Refusal {
    Encoding,
    Length,
    Context,
    Authentication,
    Relation,
    Stage,
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], Refusal> {
        let end = self.position.checked_add(length).ok_or(Refusal::Length)?;
        let result = self.bytes.get(self.position..end).ok_or(Refusal::Length)?;
        self.position = end;
        Ok(result)
    }
    fn word(&mut self) -> Result<usize, Refusal> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn base(&mut self) -> Result<u128, Refusal> {
        let value = u128::from_le_bytes(self.take(16)?.try_into().unwrap());
        if value >= MODULUS {
            return Err(Refusal::Encoding);
        }
        Ok(value)
    }
    fn element(&mut self) -> Result<Element, Refusal> {
        Ok([self.base()?, self.base()?, self.base()?])
    }
}

struct Header {
    statement: [u8; 64],
    context: [u8; 64],
    roots: [[u8; 64]; 3],
    mask_sum: Element,
    salts: Vec<[u8; 128]>,
    fold_roots: Vec<[u8; 64]>,
    terminal: Element,
}
impl Header {
    fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != HEADER_LENGTH {
            return Err(Refusal::Length);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != PROOF_MAGIC {
            return Err(Refusal::Encoding);
        }
        let statement = reader.take(64)?.try_into().unwrap();
        let context = reader.take(64)?.try_into().unwrap();
        let mut roots = [[0; 64]; 3];
        for root in &mut roots {
            *root = reader.take(64)?.try_into().unwrap();
        }
        let mask_sum = reader.element()?;
        let mut salts = Vec::new();
        for _ in 0..FOLDS + 3 {
            salts.push(reader.take(128)?.try_into().unwrap());
        }
        let mut fold_roots = Vec::new();
        for _ in 0..FOLDS - 1 {
            fold_roots.push(reader.take(64)?.try_into().unwrap());
        }
        let terminal = reader.element()?;
        Ok(Self {
            statement,
            context,
            roots,
            mask_sum,
            salts,
            fold_roots,
            terminal,
        })
    }
}

struct Challenges {
    beta: Element,
    alpha: Element,
    mask: Element,
    combination: Vec<Element>,
    folds: Vec<Element>,
    queries: Vec<usize>,
}
fn challenges(role: &[u8], header: &Header) -> Challenges {
    let mut state = vec![0; MESSAGE_BYTES];
    let mut beta = ZERO;
    let mut alpha = ZERO;
    let mut mask = ZERO;
    let mut combination = Vec::new();
    let mut folds = Vec::new();
    for round in 1..=FOLDS + 3 {
        let message = wide(
            b"bounded-proof/verifier-message",
            &[role, &header.context, &state, &(round as u32).to_le_bytes()],
        );
        if round == 2 {
            beta = sample(&message, 0, true);
        }
        if round == 3 {
            alpha = sample(&message, 0, false);
            mask = sample(&message, 1, false);
        }
        if round == 4 {
            combination = (0..2 * ORACLES)
                .map(|index| sample(&message, index, false))
                .collect();
        }
        if round >= 4 {
            folds.push(sample(
                &message,
                if round == 4 { 2 * ORACLES } else { 0 },
                false,
            ));
        }
        let sum = encode(header.mask_sum);
        let terminal = encode(header.terminal);
        let parts: Vec<&[u8]> = match round {
            1 => vec![&header.roots[0]],
            2 => vec![&header.roots[1], &sum],
            3 => vec![&header.roots[2]],
            _ => {
                if round == FOLDS + 3 {
                    vec![&terminal]
                } else {
                    vec![&header.fold_roots[round - 4]]
                }
            }
        };
        let round_bytes = (round as u32).to_le_bytes();
        let mut input = vec![
            role,
            header.context.as_slice(),
            round_bytes.as_slice(),
            header.salts[round - 1].as_slice(),
        ];
        input.extend(parts);
        let root = hash(b"bounded-proof/message-root", &input);
        let digest = wide(
            b"bounded-proof/chain-state",
            &[role, &header.context, &message, &root],
        );
        state[..64].copy_from_slice(&root);
        state[64..].copy_from_slice(&digest[..MESSAGE_BYTES - 64]);
    }
    let message = wide(
        b"bounded-proof/verifier-message",
        &[
            role,
            &header.context,
            &state,
            &((FOLDS + 4) as u32).to_le_bytes(),
        ],
    );
    let queries = (0..QUERIES)
        .map(|index| {
            u32::from_le_bytes(message[4 * index..4 * (index + 1)].try_into().unwrap()) as usize
                % (D / 2)
        })
        .collect();
    Challenges {
        beta,
        alpha,
        mask,
        combination,
        folds,
        queries,
    }
}
fn requested(queries: &[usize], length: usize) -> Vec<usize> {
    let mut values: Vec<usize> = queries
        .iter()
        .flat_map(|query| {
            let lower = query % (length / 2);
            [lower, lower + length / 2]
        })
        .collect();
    values.sort_unstable();
    values.dedup();
    values
}

struct Point {
    inverse: u128,
    vanishing: u128,
    inverse_vanishing: u128,
    powers: [u128; 4],
    table: u128,
}
impl Point {
    fn new(value: u128, table: u128) -> Self {
        let vanishing = subtract_base(power_base(value, H as u128), 1);
        Self {
            inverse: power_base(value, MODULUS - 2),
            vanishing,
            inverse_vanishing: power_base(vanishing, MODULUS - 2),
            powers: [
                WITNESS_DEGREE,
                WITNESS_DEGREE - 1,
                2 * WITNESS_DEGREE - H,
                H - 2,
            ]
            .map(|degree| power_base(value, (MAX_DEGREE - degree) as u128)),
            table,
        }
    }
    fn weight(&self, challenges: &Challenges, index: usize) -> Element {
        let class = if index < ORIGINAL - 1 {
            0
        } else if index == ORIGINAL - 1 || index == ORACLES - 2 {
            1
        } else if index == ORACLES - 1 {
            3
        } else {
            2
        };
        add(
            challenges.combination[2 * index],
            scale(challenges.combination[2 * index + 1], self.powers[class]),
        )
    }
}
fn table_coefficients() -> Vec<u128> {
    let inverse_root = power_base(root(H), MODULUS - 2);
    let mut denominators = Vec::with_capacity(H - 1);
    let mut power = 1;
    for _ in 1..H {
        power = multiply_base(power, inverse_root);
        denominators.push(subtract_base(power, 1));
    }
    let mut product = 1;
    let prefixes: Vec<u128> = denominators
        .iter()
        .map(|value| {
            let previous = product;
            product = multiply_base(product, *value);
            previous
        })
        .collect();
    let mut suffix = power_base(product, MODULUS - 2);
    let mut values = vec![multiply_base((H - 1) as u128, power_base(2, MODULUS - 2)); H];
    for index in (0..denominators.len()).rev() {
        values[index + 1] = multiply_base(prefixes[index], suffix);
        suffix = multiply_base(suffix, denominators[index]);
    }
    values
}
struct Row {
    words: Vec<u128>,
    multiplicity: u128,
    linear: Element,
    combined: Element,
    quotient_coefficient: Element,
}

pub struct Verifier {
    role: Vec<u8>,
    header: Header,
    challenges: Challenges,
    statement: Option<SetupStatementStream>,
    context_hash: Sha3_512,
    operator: Option<SetupStatementOutput>,
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
    failed: bool,
    complete: bool,
}
impl Verifier {
    pub fn new(
        role: &[u8],
        expected_statement: [u8; 64],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        if role.is_empty() || role.len() > 1024 {
            return Err(Refusal::Context);
        }
        let header = Header::parse(proof_header)?;
        if header.statement != expected_statement {
            return Err(Refusal::Context);
        }
        let challenges = challenges(role, &header);
        let indices = requested(&challenges.queries, D);
        let selected: Vec<u32> = indices.iter().map(|index| *index as u32).collect();
        let statement = SetupStatementStream::new(expected_statement, challenges.alpha, &selected)
            .map_err(|_| Refusal::Context)?;
        let mut context_hash = Sha3_512::new();
        part(&mut context_hash, b"bounded-proof/statement");
        for value in [
            role,
            RELATION_TAG,
            &2u128.to_le_bytes(),
            &root(1 << 20).to_le_bytes(),
            &7u128.to_le_bytes(),
            &parameter_bytes(),
            &(MODULUS - 1).to_le_bytes(),
        ] {
            part(&mut context_hash, value);
        }
        Digest::update(&mut context_hash, (STATEMENT_LENGTH as u32).to_le_bytes());
        Ok(Self {
            role: role.to_vec(),
            header,
            challenges,
            statement: Some(statement),
            context_hash,
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
            failed: false,
            complete: false,
        })
    }
    pub fn push_statement(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || self.statement_done {
            return Err(Refusal::Stage);
        }
        if bytes.len() > CHUNK_LIMIT {
            self.failed = true;
            return Err(Refusal::Length);
        }
        Digest::update(&mut self.context_hash, bytes);
        if self
            .statement
            .as_mut()
            .ok_or(Refusal::Stage)?
            .push(bytes)
            .is_err()
        {
            self.failed = true;
            return Err(Refusal::Encoding);
        }
        Ok(())
    }
    pub fn finish_statement(&mut self) -> Result<(), Refusal> {
        if self.failed || self.statement_done {
            return Err(Refusal::Stage);
        }
        let computed: [u8; 64] = self.context_hash.clone().finalize().into();
        if computed != self.header.context {
            self.failed = true;
            return Err(Refusal::Context);
        }
        self.operator = Some(
            self.statement
                .take()
                .ok_or(Refusal::Stage)?
                .finish()
                .map_err(|_| Refusal::Encoding)?,
        );
        let table = proof_lookup_table::evaluate_on_proof_domain(&table_coefficients());
        self.points = self
            .indices
            .iter()
            .map(|index| {
                Point::new(
                    multiply_base(7, power_base(root(D), *index as u128)),
                    table[*index],
                )
            })
            .collect();
        self.statement_done = true;
        Ok(())
    }
    fn stage_shape(&self) -> (usize, usize, [u8; 64]) {
        if self.stage < 3 {
            (
                D,
                [FIRST_WIDTH, SECOND_WIDTH, 48][self.stage],
                self.header.roots[self.stage],
            )
        } else {
            let round = self.stage - 3;
            (D >> (round + 1), 48, self.header.fold_roots[round])
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
        let mut digest = hash(
            b"bounded-proof/leaf",
            &[
                &self.role,
                &(self.stage as u32).to_le_bytes(),
                &(index as u32).to_le_bytes(),
                salt,
                data,
            ],
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
                hash(
                    b"bounded-proof/node",
                    &[
                        &self.role,
                        &(self.stage as u32).to_le_bytes(),
                        &level.to_le_bytes(),
                        &digest,
                        &sibling,
                    ],
                )
            } else {
                hash(
                    b"bounded-proof/node",
                    &[
                        &self.role,
                        &(self.stage as u32).to_le_bytes(),
                        &level.to_le_bytes(),
                        &sibling,
                        &digest,
                    ],
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
        let mut reader = Reader::new(data);
        let mut words = Vec::with_capacity(COLS);
        for _ in 0..COLS {
            words.push(reader.base()?);
        }
        let multiplicity = reader.base()?;
        let mut combined = reader.element()?;
        let point = &self.points[self.position];
        let operator = self.operator.as_ref().ok_or(Refusal::Stage)?;
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
                scale(point.weight(&self.challenges, column), *value),
            );
        }
        combined = add(
            combined,
            scale(point.weight(&self.challenges, COLS), multiplicity),
        );
        for index in 0..BOOLS {
            let value = words[WORDS + index];
            let residue = multiply_base(
                multiply_base(value, subtract_base(value, 1)),
                point.inverse_vanishing,
            );
            combined = add(
                combined,
                scale(point.weight(&self.challenges, ORIGINAL + index), residue),
            );
        }
        for pair in 0..ZERO_PRODUCTS {
            let (left, right) = zero_product_columns(pair);
            let residue = multiply_base(
                multiply_base(words[left], words[right]),
                point.inverse_vanishing,
            );
            combined = add(
                combined,
                scale(
                    point.weight(&self.challenges, ORIGINAL + BOOLS + pair),
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
        let point = &self.points[self.position];
        let row = &mut self.rows[self.position];
        let mut reader = Reader::new(data);
        let mut sum = ZERO;
        for index in 0..LOOKUPS {
            let value = reader.element()?;
            sum = add(sum, value);
            row.combined = add(
                row.combined,
                multiply(point.weight(&self.challenges, COLS + 1 + index), value),
            );
            let (column, factor) = lookup(index);
            let denominator = subtract(
                self.challenges.beta,
                [multiply_base(row.words[column], factor), 0, 0],
            );
            let residue = scale(
                subtract(multiply(value, denominator), ONE),
                point.inverse_vanishing,
            );
            row.combined = add(
                row.combined,
                multiply(
                    point.weight(&self.challenges, ORIGINAL + BOOLS + ZERO_PRODUCTS + index),
                    residue,
                ),
            );
        }
        let table_inverse = reader.element()?;
        let mask = reader.element()?;
        row.combined = add(
            row.combined,
            multiply(
                point.weight(&self.challenges, COLS + 1 + LOOKUPS),
                table_inverse,
            ),
        );
        row.combined = add(
            row.combined,
            multiply(point.weight(&self.challenges, COLS + 2 + LOOKUPS), mask),
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
            multiply(point.weight(&self.challenges, ORACLES - 2), table_residue),
        );
        let operator = self.operator.as_ref().ok_or(Refusal::Stage)?;
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
            scale(claimed, power_base(H as u128, MODULUS - 2)),
        );
        let remainder_weight = point.weight(&self.challenges, ORACLES - 1);
        row.combined = add(
            row.combined,
            multiply(remainder_weight, scale(numerator, point.inverse)),
        );
        row.quotient_coefficient = subtract(
            point.weight(&self.challenges, ORIGINAL - 1),
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
                D
            } else {
                D >> (self.stage - 2)
            };
            let round = if self.stage == 2 { 0 } else { self.stage - 2 };
            let coset = power_base(7, 1u128 << round);
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
                let point = multiply_base(coset, power_base(root(length), index as u128));
                let folded = add(
                    scale(add(left, right), power_base(2, MODULUS - 2)),
                    multiply(
                        self.challenges.folds[round],
                        scale(
                            subtract(left, right),
                            multiply_base(
                                power_base(2, MODULUS - 2),
                                power_base(point, MODULUS - 2),
                            ),
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
        let length = if self.stage < 3 {
            D
        } else {
            D >> (self.stage - 2)
        };
        self.indices = requested(&self.challenges.queries, length);
        self.position = 0;
        self.reading_count = true;
        Ok(())
    }
    pub fn push_proof(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || !self.statement_done {
            return Err(Refusal::Stage);
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
mod tests {
    use super::*;
    fn header() -> Vec<u8> {
        let mut bytes = vec![0; HEADER_LENGTH];
        bytes[..4].copy_from_slice(PROOF_MAGIC);
        bytes
    }
    #[test]
    fn malformed_headers_and_unfinished_streams_cannot_verify() {
        let bytes = header();
        assert!(Verifier::new(b"role", [0; 64], &bytes).is_ok());
        assert!(!Verifier::new(b"role", [0; 64], &bytes).unwrap().finish());
        assert!(Verifier::new(b"", [0; 64], &bytes).is_err());
        assert!(Verifier::new(b"role", [1; 64], &bytes).is_err());
        assert!(Verifier::new(b"role", [0; 64], &bytes[..HEADER_LENGTH - 1]).is_err());
        for offset in [324, HEADER_LENGTH - 48] {
            let mut changed = bytes.clone();
            changed[offset..offset + 16].copy_from_slice(&MODULUS.to_le_bytes());
            assert!(matches!(
                Verifier::new(b"role", [0; 64], &changed),
                Err(Refusal::Encoding)
            ));
        }
        let mut verifier = Verifier::new(b"role", [0; 64], &bytes).unwrap();
        assert!(matches!(verifier.push_proof(&[0]), Err(Refusal::Stage)));
        assert!(!verifier.finish());
    }
    #[test]
    fn table_coefficients_match_direct_fourier_sums() {
        let coefficients = table_coefficients();
        for index in [0, 1, H / 2, H - 1] {
            let mut sum = 0;
            let step = power_base(root(H), ((H - index) % H) as u128);
            let mut weight = 1;
            for value in 0..H {
                sum = add_base(sum, multiply_base(value as u128, weight));
                weight = multiply_base(weight, step);
            }
            assert_eq!(
                coefficients[index],
                multiply_base(sum, power_base(H as u128, MODULUS - 2))
            );
        }
    }
    #[test]
    fn folded_queries_preserve_required_partners() {
        assert_eq!(requested(&[0, 1, 7, 7, 15], 16), vec![0, 1, 7, 8, 9, 15]);
    }
}
