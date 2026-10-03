use parallel_work::ProtocolHash;
use parallel_work::{HashStream, Sponge};
use setup_stream_kernel::SetupStatementOutput as StatementOutput;
use setup_stream_kernel::arithmetic::{
    MODULUS, add as add_base, multiply as multiply_base, power as power_base,
    subtract as subtract_base,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{collections::BTreeMap, sync::OnceLock};
use supported_profile::relation::{
    DOMAIN as D, MASKS, MAX_DEGREE, QUERY_COUNT as QUERIES, Relation, SYSTEMATIC as H,
    WITNESS_DEGREE,
};

type Element = [u128; 3];
const ZERO: Element = [0, 0, 0];
const ONE: Element = [1, 0, 0];
const FOLDS: usize = (D / 2).ilog2() as usize;
pub const HEADER_LENGTH: usize =
    4 + 64 + 64 + 3 * 64 + 48 + (FOLDS + 3) * 128 + (FOLDS - 1) * 64 + 48;
pub const CHUNK_LIMIT: usize = 1 << 20;

/// The public statement parser of one relation. It yields the relation's
/// affine operator at the verifier's queries.
pub trait Statement {
    fn push(&mut self, bytes: &[u8]) -> bool;
    fn finish(self) -> Option<StatementOutput>;
}

/// The verifier's own reading of a relation's witness, lookup and oracle
/// counts and leaf widths.
struct Shape {
    words: usize,
    booleans: usize,
    columns: usize,
    lookups: Vec<(usize, u128)>,
    zero_products: Vec<(usize, usize)>,
    original: usize,
    oracles: usize,
    first_width: usize,
    second_width: usize,
    message_bytes: usize,
}
impl Shape {
    fn new(relation: &Relation) -> Self {
        let columns = relation.words + relation.booleans;
        let lookups: Vec<_> = (0..relation.words)
            .map(|column| (column, 1))
            .chain(relation.narrow.iter().copied())
            .collect();
        let original = columns + lookups.len() + 4;
        Self {
            words: relation.words,
            booleans: relation.booleans,
            columns,
            oracles: original
                + relation.booleans
                + relation.zero_product_pairs.len()
                + lookups.len()
                + 2,
            original,
            first_width: (columns + 1) * 16 + 48,
            second_width: (lookups.len() + 2) * 48,
            lookups,
            zero_products: relation.zero_product_pairs.clone(),
            message_bytes: relation.message_bytes,
        }
    }
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
    setup_stream_kernel::arithmetic::multiply_extension(left, right)
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
fn degree(shape: &Shape, index: usize) -> usize {
    if index < shape.original - 1 {
        WITNESS_DEGREE
    } else if index == shape.original - 1 || index == shape.oracles - 2 {
        WITNESS_DEGREE - 1
    } else if index == shape.oracles - 1 {
        H - 2
    } else {
        2 * WITNESS_DEGREE - H
    }
}
/// The relation parameters, oracle degrees and lookups that a proof's
/// context binds.
pub(crate) fn context_parameters(relation: &Relation) -> Vec<u8> {
    let shape = &Shape::new(relation);
    let mut bytes: Vec<u8> = [H, QUERIES, MASKS, D, MAX_DEGREE, 2, shape.message_bytes]
        .into_iter()
        .chain(relation.parameters.iter().copied())
        .chain((0..shape.oracles).map(|index| degree(shape, index)))
        .flat_map(|value| (value as u32).to_le_bytes())
        .collect();
    for (column, scale) in &shape.lookups {
        bytes.extend((*column as u32).to_le_bytes());
        bytes.extend((*scale as u32).to_le_bytes());
    }
    bytes
}
fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = ProtocolHash::new();
    part(&mut hash, domain);
    for value in parts {
        part(&mut hash, value);
    }
    hash.finalize()
}
fn part(hash: &mut ProtocolHash, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_le_bytes());
    hash.update(bytes);
}
/// The sponge of a hash that has absorbed its domain and first parts, which
/// every hash with that prefix continues.
fn prefix(domain: &[u8], parts: &[&[u8]]) -> ProtocolHash {
    let mut hash = ProtocolHash::new();
    part(&mut hash, domain);
    for value in parts {
        part(&mut hash, value);
    }
    hash
}
/// The hash of the prefix's domain and parts followed by these parts.
fn hash_after(prefix: &ProtocolHash, parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = prefix.clone();
    for value in parts {
        part(&mut hash, value);
    }
    hash.finalize()
}
fn stream_part(stream: &mut HashStream, bytes: &[u8]) {
    stream.update(&(bytes.len() as u32).to_le_bytes());
    stream.update(bytes);
}
fn wide(domain: &[u8], parts: &[&[u8]], length: usize) -> Vec<u8> {
    let mut hash = Shake256::default();
    Update::update(&mut hash, &(domain.len() as u32).to_le_bytes());
    Update::update(&mut hash, domain);
    for value in parts {
        Update::update(&mut hash, &(value.len() as u32).to_le_bytes());
        Update::update(&mut hash, value);
    }
    let mut output = vec![0; length];
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
    fn parse(bytes: &[u8], magic: &[u8; 4]) -> Result<Self, Refusal> {
        if bytes.len() != HEADER_LENGTH {
            return Err(Refusal::Length);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != magic {
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
fn challenges(shape: &Shape, role: &[u8], header: &Header) -> Challenges {
    let length = shape.message_bytes;
    let mut state = vec![0; length];
    let mut beta = ZERO;
    let mut alpha = ZERO;
    let mut mask = ZERO;
    let mut combination = Vec::new();
    let mut folds = Vec::new();
    for round in 1..=FOLDS + 3 {
        let message = wide(
            b"bounded-proof/verifier-message",
            &[role, &header.context, &state, &(round as u32).to_le_bytes()],
            length,
        );
        if round == 2 {
            beta = sample(&message, 0, true);
        }
        if round == 3 {
            alpha = sample(&message, 0, false);
            mask = sample(&message, 1, false);
        }
        if round == 4 {
            combination = (0..2 * shape.oracles)
                .map(|index| sample(&message, index, false))
                .collect();
        }
        if round >= 4 {
            folds.push(sample(
                &message,
                if round == 4 { 2 * shape.oracles } else { 0 },
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
            length,
        );
        state[..64].copy_from_slice(&root);
        state[64..].copy_from_slice(&digest[..length - 64]);
    }
    let message = wide(
        b"bounded-proof/verifier-message",
        &[
            role,
            &header.context,
            &state,
            &((FOLDS + 4) as u32).to_le_bytes(),
        ],
        length,
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

/// The degrees whose corrections raise an oracle to the largest degree.
const CORRECTED_DEGREES: [usize; 4] = [
    WITNESS_DEGREE,
    WITNESS_DEGREE - 1,
    2 * WITNESS_DEGREE - H,
    H - 2,
];
/// The low bits of an exponent of the domain's root, which index the table
/// of its first powers.
const LOW_BITS: usize = 9;

/// The proof domain is the coset of the shift seven by the subgroup of the
/// domain's root w. Every queried point's values follow from constants this
/// instance computes once: the powers of w as two tables, the shift's
/// inverse, the systematic vanishing polynomial's values on the coset and
/// their inverses, which repeat with the index modulo four because w^H has
/// order four, and the shift's power at each degree correction. Each fold
/// round's points follow from the shift's inverse raised to that round's
/// power of two.
struct Coset {
    low: Vec<u128>,
    high: Vec<u128>,
    inverse_shift: u128,
    vanishing: [u128; 4],
    inverse_vanishing: [u128; 4],
    shifts: [u128; 4],
    inverse_fold_shifts: [u128; FOLDS],
    half: u128,
    inverse_systematic: u128,
}
impl Coset {
    fn get() -> &'static Self {
        static COSET: OnceLock<Coset> = OnceLock::new();
        COSET.get_or_init(|| {
            let root = root(D);
            let powers = |step: u128, count: usize| {
                let mut value = 1;
                (0..count)
                    .map(|_| {
                        let current = value;
                        value = multiply_base(value, step);
                        current
                    })
                    .collect()
            };
            let order_four = power_base(root, H as u128);
            let shifted = power_base(7, H as u128);
            let vanishing: [u128; 4] = std::array::from_fn(|residue| {
                subtract_base(
                    multiply_base(shifted, power_base(order_four, residue as u128)),
                    1,
                )
            });
            let inverse_shift = power_base(7, MODULUS - 2);
            Self {
                low: powers(root, 1 << LOW_BITS),
                high: powers(power_base(root, 1 << LOW_BITS), D >> LOW_BITS),
                inverse_shift,
                inverse_vanishing: vanishing.map(|value| power_base(value, MODULUS - 2)),
                vanishing,
                shifts: CORRECTED_DEGREES
                    .map(|degree| power_base(7, (MAX_DEGREE - degree) as u128)),
                inverse_fold_shifts: std::array::from_fn(|round| {
                    power_base(inverse_shift, 1 << round)
                }),
                half: power_base(2, MODULUS - 2),
                inverse_systematic: power_base(H as u128, MODULUS - 2),
            }
        })
    }
    /// The inverse of a fold round's point 7^(2^round) w^(index 2^round).
    fn inverse_fold_point(&self, round: usize, index: usize) -> u128 {
        multiply_base(
            self.inverse_fold_shifts[round],
            self.root_power(D as u64 - ((index as u64) << round)),
        )
    }
    /// w to the exponent modulo the domain's size.
    fn root_power(&self, exponent: u64) -> u128 {
        let exponent = (exponent % D as u64) as usize;
        multiply_base(
            self.high[exponent >> LOW_BITS],
            self.low[exponent & ((1 << LOW_BITS) - 1)],
        )
    }
}

struct Point {
    inverse: u128,
    vanishing: u128,
    inverse_vanishing: u128,
    powers: [u128; 4],
    table: u128,
}
impl Point {
    /// The values at the point 7 w^index: its inverse 7^-1 w^(D - index),
    /// the vanishing polynomial's value, and 7^e w^(index e) for each
    /// correction exponent e.
    fn new(index: usize, table: u128) -> Self {
        let coset = Coset::get();
        let index = index as u64;
        Self {
            inverse: multiply_base(coset.inverse_shift, coset.root_power(D as u64 - index)),
            vanishing: coset.vanishing[index as usize % 4],
            inverse_vanishing: coset.inverse_vanishing[index as usize % 4],
            powers: std::array::from_fn(|correction| {
                multiply_base(
                    coset.shifts[correction],
                    coset.root_power(index * (MAX_DEGREE - CORRECTED_DEGREES[correction]) as u64),
                )
            }),
            table,
        }
    }
    fn weight(&self, shape: &Shape, challenges: &Challenges, index: usize) -> Element {
        let class = if index < shape.original - 1 {
            0
        } else if index == shape.original - 1 || index == shape.oracles - 2 {
            1
        } else if index == shape.oracles - 1 {
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
    // The statement's context, which a helper hashes when there are helpers.
    context_hash: Option<HashStream>,
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
    /// Opens a proof of the relation against its expected statement. The
    /// statement parser opens only after the proof header fixes its
    /// challenges.
    pub fn open(
        relation: Relation,
        role: &[u8],
        expected_statement: [u8; 64],
        proof_header: &[u8],
        open_statement: impl FnOnce(Element, &[u32]) -> Option<S>,
    ) -> Result<Self, Refusal> {
        if role.is_empty() || role.len() > 1024 {
            return Err(Refusal::Context);
        }
        let header = Header::parse(proof_header, relation.proof_magic)?;
        if header.statement != expected_statement {
            return Err(Refusal::Context);
        }
        let shape = Shape::new(&relation);
        let challenges = challenges(&shape, role, &header);
        let indices = requested(&challenges.queries, D);
        let selected: Vec<u32> = indices.iter().map(|index| *index as u32).collect();
        let statement = open_statement(challenges.alpha, &selected).ok_or(Refusal::Context)?;
        let mut context_hash = HashStream::new(Sponge::ProtocolHash);
        stream_part(&mut context_hash, b"bounded-proof/statement");
        for value in [
            role,
            relation.tag,
            &2u128.to_le_bytes(),
            &root(1 << 20).to_le_bytes(),
            &7u128.to_le_bytes(),
            &context_parameters(&relation),
            &(MODULUS - 1).to_le_bytes(),
        ] {
            stream_part(&mut context_hash, value);
        }
        context_hash.update(&(relation.statement_bytes as u32).to_le_bytes());
        Ok(Self {
            shape,
            role: role.to_vec(),
            header,
            challenges,
            statement: Some(statement),
            context_hash: Some(context_hash),
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
            return Err(Refusal::Stage);
        }
        if bytes.len() > CHUNK_LIMIT {
            self.failed = true;
            return Err(Refusal::Length);
        }
        self.context_hash
            .as_mut()
            .ok_or(Refusal::Stage)?
            .update(bytes);
        if !self.statement.as_mut().ok_or(Refusal::Stage)?.push(bytes) {
            self.failed = true;
            return Err(Refusal::Encoding);
        }
        Ok(())
    }
    pub fn finish_statement(&mut self) -> Result<(), Refusal> {
        if self.failed || self.statement_done {
            return Err(Refusal::Stage);
        }
        let computed = self.context_hash.take().ok_or(Refusal::Stage)?.finish();
        if computed != self.header.context {
            self.failed = true;
            return Err(Refusal::Context);
        }
        self.operator = Some(
            self.statement
                .take()
                .ok_or(Refusal::Stage)?
                .finish()
                .ok_or(Refusal::Encoding)?,
        );
        let table = proof_lookup_table::on_proof_domain();
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
                D,
                [self.shape.first_width, self.shape.second_width, 48][self.stage],
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
                D
            } else {
                D >> (self.stage - 2)
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
    use supported_profile::relation::{PROOF_HEADER_BYTES, registration_relation};

    // A statement that refuses every byte, so no proof it opens completes.
    struct Refused;
    impl Statement for Refused {
        fn push(&mut self, _bytes: &[u8]) -> bool {
            false
        }
        fn finish(self) -> Option<StatementOutput> {
            None
        }
    }
    fn open(role: &[u8], statement: [u8; 64], bytes: &[u8]) -> Result<Verifier<Refused>, Refusal> {
        Verifier::open(registration_relation(), role, statement, bytes, |_, _| {
            Some(Refused)
        })
    }
    fn header() -> Vec<u8> {
        let mut bytes = vec![0; HEADER_LENGTH];
        bytes[..4].copy_from_slice(registration_relation().proof_magic);
        bytes
    }
    #[test]
    fn malformed_headers_and_unfinished_streams_cannot_verify() {
        assert_eq!(HEADER_LENGTH, PROOF_HEADER_BYTES);
        let bytes = header();
        assert!(open(b"role", [0; 64], &bytes).is_ok());
        assert!(!open(b"role", [0; 64], &bytes).unwrap().finish());
        assert!(open(b"", [0; 64], &bytes).is_err());
        assert!(open(b"role", [1; 64], &bytes).is_err());
        assert!(open(b"role", [0; 64], &bytes[..HEADER_LENGTH - 1]).is_err());
        let mut other = bytes.clone();
        other[..4].copy_from_slice(b"SWP2");
        assert!(matches!(
            open(b"role", [0; 64], &other),
            Err(Refusal::Encoding)
        ));
        assert!(matches!(
            Verifier::<Refused>::open(registration_relation(), b"role", [0; 64], &bytes, |_, _| {
                None
            }),
            Err(Refusal::Context)
        ));
        for offset in [324, HEADER_LENGTH - 48] {
            let mut changed = bytes.clone();
            changed[offset..offset + 16].copy_from_slice(&MODULUS.to_le_bytes());
            assert!(matches!(
                open(b"role", [0; 64], &changed),
                Err(Refusal::Encoding)
            ));
        }
        let mut verifier = open(b"role", [0; 64], &bytes).unwrap();
        assert!(matches!(verifier.push_proof(&[0]), Err(Refusal::Stage)));
        assert!(matches!(
            verifier.push_statement(&[0]),
            Err(Refusal::Encoding)
        ));
        assert!(matches!(verifier.finish_statement(), Err(Refusal::Stage)));
        assert!(!verifier.finish());
    }
    // The table-driven values at a point equal direct powers of the point
    // 7 w^index, at both ends of the domain and at every residue modulo four.
    #[test]
    fn points_match_direct_powers() {
        for index in [
            0,
            1,
            2,
            3,
            4,
            511,
            512,
            513,
            H - 1,
            H,
            D / 2 + 5,
            D - 2,
            D - 1,
        ] {
            let value = multiply_base(7, power_base(root(D), index as u128));
            let vanishing = subtract_base(power_base(value, H as u128), 1);
            let point = Point::new(index, 11);
            assert_eq!(point.inverse, power_base(value, MODULUS - 2));
            assert_eq!(multiply_base(point.inverse, value), 1);
            assert_eq!(point.vanishing, vanishing);
            assert_eq!(point.inverse_vanishing, power_base(vanishing, MODULUS - 2));
            for (power, degree) in point.powers.iter().zip(CORRECTED_DEGREES) {
                assert_eq!(*power, power_base(value, (MAX_DEGREE - degree) as u128));
            }
            assert_eq!(point.table, 11);
        }
    }
    // Each fold round's point inverse is the direct inverse of the round's
    // point 7^(2^round) w_length^index, and the halving and systematic
    // constants invert two and the subgroup's size.
    #[test]
    fn fold_points_invert_the_direct_points() {
        let coset = Coset::get();
        assert_eq!(multiply_base(coset.half, 2), 1);
        assert_eq!(multiply_base(coset.inverse_systematic, H as u128), 1);
        for round in [0, 1, 7, FOLDS - 2, FOLDS - 1] {
            let length = D >> round;
            for index in [0, 1, 2, 3, length / 4 + 1, length / 2 - 1] {
                if index >= length / 2 {
                    continue;
                }
                let point = multiply_base(
                    power_base(7, 1 << round),
                    power_base(root(length), index as u128),
                );
                assert_eq!(
                    coset.inverse_fold_point(round, index),
                    power_base(point, MODULUS - 2)
                );
            }
        }
    }
    // A hash that continues a prefix's sponge equals the direct hash of the
    // prefix's domain and parts followed by its own parts.
    #[test]
    fn prefixed_hashes_equal_the_direct_hashes() {
        let role: Vec<u8> = (0..282).map(|index| index as u8).collect();
        for (stage, rest) in [
            (0u32, vec![vec![1, 2, 3, 4], vec![5; 128], vec![6; 144]]),
            (3, vec![vec![9; 4], vec![7; 64], vec![8; 64]]),
            (19, vec![]),
        ] {
            let stage = stage.to_le_bytes();
            let parts: Vec<&[u8]> = rest.iter().map(Vec::as_slice).collect();
            let direct: Vec<&[u8]> = [role.as_slice(), &stage]
                .into_iter()
                .chain(parts.iter().copied())
                .collect();
            assert_eq!(
                hash_after(&prefix(b"bounded-proof/node", &[&role, &stage]), &parts),
                hash(b"bounded-proof/node", &direct)
            );
        }
    }
    #[test]
    fn folded_queries_preserve_required_partners() {
        assert_eq!(requested(&[0, 1, 7, 7, 15], 16), vec![0, 1, 7, 8, 9, 15]);
    }
}
