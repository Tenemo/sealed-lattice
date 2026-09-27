//! An oracle's leaf hashers, split into residue classes of rows. With `P`
//! classes per coset, the shard `s = k + 4 j` holds the rows congruent to `s`
//! modulo `4 P`, which are the positions `j + P q` of the coset `k`. A shard
//! computes those positions' values of each committed polynomial from its
//! coefficients by folding them onto a transform of `SYSTEMATIC / P` points,
//! and absorbs them into its rows, so neither the values nor the row states
//! leave the instance that holds the shard. The folded sums equal the full
//! transform's values exactly.
use crate::{
    field::{self, Element, Transform, ZERO, base},
    oracles::coset,
    parameters::*,
    tree::{self, Tree},
};
use parallel_work::{Job, Part, Ticket, share, submit};
use stateful_sha3::{
    Digest, Sha3_512,
    digest::common::hazmat::{SerializableState, SerializedState},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
};
use zeroize::Zeroizing;

/// Opens a shard's rows from their salts.
pub static OPEN: Job = Job {
    kind: 0x0110,
    run: open,
};
/// Absorbs a base polynomial's values into a shard's rows.
pub static BASE: Job = Job {
    kind: 0x0111,
    run: absorb_base,
};
/// Absorbs an extension polynomial's values into a shard's rows.
pub static EXTENSION: Job = Job {
    kind: 0x0112,
    run: absorb_extension,
};
/// A range of a shard's leaf digests; the last range removes the shard.
pub static CLOSE: Job = Job {
    kind: 0x0113,
    run: close,
};
/// A range of a shard's row states.
pub static EXPORT: Job = Job {
    kind: 0x0114,
    run: export,
};
/// Restores a range of a shard's row states.
pub static IMPORT: Job = Job {
    kind: 0x0115,
    run: import,
};
/// Removes a shard's rows unless they closed.
pub static DISCARD: Job = Job {
    kind: 0x0116,
    run: discard,
};

/// The most rows one job opens, exports or restores.
const ROWS_PER_JOB: usize = 16_384;
/// The polynomials whose shard jobs may run at once.
const POLYNOMIALS_RUNNING: usize = 4;
const HEADER_BYTES: usize = 16;
const STATE_BYTES: usize = 201;
/// The linear memory any one job needs beside the shards' rows: its input
/// and output buffers, its decoded coefficients and values, and the cached
/// transform tables.
const JOB_MEMORY_BYTES: usize = 48 << 20;
const PAGE_BYTES: usize = 65_536;

/// The residue classes per coset for a helper count: the most for which
/// every shard has a helper of its own, and one without enough helpers.
pub fn classes(helpers: usize) -> usize {
    (1 << (helpers / 4).max(1).ilog2()).min(SYSTEMATIC / 2)
}
/// The linear memory a helper instance needs: the rows of the shards it
/// holds beside one job's memory.
pub fn helper_memory_bytes(helpers: usize) -> usize {
    let classes = classes(helpers);
    let shards = (4 * classes).div_ceil(helpers.max(1));
    let rows = shards * (SYSTEMATIC / classes) * size_of::<Sha3_512>();
    (rows + JOB_MEMORY_BYTES).next_multiple_of(PAGE_BYTES)
}

struct Shard {
    hashers: Vec<Sha3_512>,
}
thread_local! {
    static SHARDS: RefCell<BTreeMap<(u64, u32), Shard>> = RefCell::default();
}

// A job's session, shard and classes, and the bytes that follow them.
fn header(input: &[u8]) -> (u64, u32, usize, &[u8]) {
    let session = u64::from_le_bytes(input[..8].try_into().unwrap());
    let shard = u32::from_le_bytes(input[8..12].try_into().unwrap());
    let classes = u32::from_le_bytes(input[12..16].try_into().unwrap()) as usize;
    assert!(classes.is_power_of_two() && classes <= SYSTEMATIC / 2);
    assert!((shard as usize) < 4 * classes);
    (session, shard, classes, &input[HEADER_BYTES..])
}
fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}
fn with_shard<T>(session: u64, shard: u32, action: impl FnOnce(&mut Shard) -> T) -> T {
    SHARDS.with(|shards| action(shards.borrow_mut().get_mut(&(session, shard)).unwrap()))
}

/// A base or extension field element that a shard folds.
trait Folded: Copy + zeroize::Zeroize {
    const ZERO: Self;
    fn add(self, other: Self) -> Self;
    fn scale(self, scalar: u128) -> Self;
}
impl Folded for u128 {
    const ZERO: Self = 0;
    fn add(self, other: Self) -> Self {
        base::add(self, other)
    }
    fn scale(self, scalar: u128) -> Self {
        base::multiply(self, scalar)
    }
}
impl Folded for Element {
    const ZERO: Self = ZERO;
    fn add(self, other: Self) -> Self {
        field::add(self, other)
    }
    fn scale(self, scalar: u128) -> Self {
        field::scale(self, scalar)
    }
}

/// The values at the positions `residue + classes * q` of the coset `k` of
/// a polynomial of the length whose coefficients above the systematic
/// length wrap there, before the transform of `SYSTEMATIC / classes` points.
/// Each coefficient is read as the fold needs it.
fn residue_values<T: Folded>(
    length: usize,
    coefficient: impl Fn(usize) -> T,
    coset_index: usize,
    classes: usize,
    residue: usize,
) -> Zeroizing<Vec<T>> {
    assert!(length <= 2 * SYSTEMATIC + 1);
    let block = SYSTEMATIC / classes;
    let coset = coset(coset_index);
    let high = base::power(coset, SYSTEMATIC as u128);
    let omega = field::root(SYSTEMATIC);
    // The factor between the folded blocks and the twist of the folded sum.
    let step = base::multiply(
        base::power(coset, block as u128),
        base::power(omega, (block * residue) as u128),
    );
    let twist = base::multiply(coset, base::power(omega, residue as u128));
    let wrapped = |index: usize| {
        let mut value = if index < length {
            coefficient(index)
        } else {
            T::ZERO
        };
        if SYSTEMATIC + index < length {
            value = value.add(coefficient(SYSTEMATIC + index).scale(high));
        }
        if index == 0 && length == 2 * SYSTEMATIC + 1 {
            value = value.add(coefficient(2 * SYSTEMATIC).scale(base::multiply(high, high)));
        }
        value
    };
    let mut values = Zeroizing::new(Vec::with_capacity(block));
    let mut power = 1;
    for index in 0..block {
        let mut sum = T::ZERO;
        for fold in (0..classes).rev() {
            sum = sum.scale(step).add(wrapped(index + block * fold));
        }
        values.push(sum.scale(power));
        power = base::multiply(power, twist);
    }
    values
}

/// A polynomial's values at a shard's rows, in row order, from its encoded
/// coefficients.
fn shard_base_values(coefficients: &[u8], shard: u32, classes: usize) -> Zeroizing<Vec<u128>> {
    assert!(coefficients.len().is_multiple_of(16));
    let shard = shard as usize;
    let mut values = residue_values(
        coefficients.len() / 16,
        |index| {
            u128::from_le_bytes(
                coefficients[16 * index..16 * (index + 1)]
                    .try_into()
                    .unwrap(),
            )
        },
        shard % 4,
        classes,
        shard / 4,
    );
    Transform::cached(SYSTEMATIC).base(&mut values, false);
    values
}
/// An extension polynomial's values at a shard's rows, in row order, from
/// its coefficients of the length, each read as the fold needs it.
pub(crate) fn shard_extension_values_of(
    length: usize,
    coefficient: impl Fn(usize) -> Element,
    shard: u32,
    classes: usize,
) -> Zeroizing<Vec<Element>> {
    let shard = shard as usize;
    let mut values = residue_values(length, coefficient, shard % 4, classes, shard / 4);
    Transform::cached(SYSTEMATIC).extension(&mut values, false);
    values
}
/// An extension polynomial's values at a shard's rows, in row order, from
/// its encoded coefficients.
pub(crate) fn shard_extension_values(
    coefficients: &[u8],
    shard: u32,
    classes: usize,
) -> Zeroizing<Vec<Element>> {
    assert!(coefficients.len().is_multiple_of(48));
    shard_extension_values_of(
        coefficients.len() / 48,
        |index| field::decode(&coefficients[48 * index..48 * (index + 1)]),
        shard,
        classes,
    )
}

fn open(input: &[u8]) -> Vec<u8> {
    let (session, shard, classes, rest) = header(input);
    let role_length = usize::from(u16::from_le_bytes(rest[..2].try_into().unwrap()));
    let role = &rest[2..2 + role_length];
    let rest = &rest[2 + role_length..];
    let (stage, width, first, count) = (
        word(rest) as usize,
        word(&rest[4..]) as usize,
        word(&rest[8..]) as usize,
        word(&rest[12..]) as usize,
    );
    let seed: &[u8; tree::SALT_SEED_BYTES] = rest[16..].try_into().unwrap();
    assert!(first + count <= SYSTEMATIC / classes);
    let prefix = tree::leaf_prefix(role, stage);
    let hashers = (first..first + count).map(|q| {
        let row = shard as usize + 4 * classes * q;
        tree::leaf_start(&prefix, row, &tree::salt(seed, row), width)
    });
    extend(session, shard, classes, first, hashers);
    Vec::new()
}
// Appends a range of rows to a shard, which the first range creates.
fn extend(
    session: u64,
    shard: u32,
    classes: usize,
    first: usize,
    hashers: impl Iterator<Item = Sha3_512>,
) {
    SHARDS.with(|shards| {
        let mut shards = shards.borrow_mut();
        let entry = shards.entry((session, shard)).or_insert_with(|| Shard {
            hashers: Vec::with_capacity(SYSTEMATIC / classes),
        });
        assert_eq!(entry.hashers.len(), first);
        entry.hashers.extend(hashers);
    });
}
fn absorb_base(input: &[u8]) -> Vec<u8> {
    let (session, shard, classes, coefficients) = header(input);
    let values = shard_base_values(coefficients, shard, classes);
    with_shard(session, shard, |state| {
        assert_eq!(state.hashers.len(), values.len());
        for (hasher, value) in state.hashers.iter_mut().zip(values.iter()) {
            hasher.update(value.to_le_bytes());
        }
    });
    Vec::new()
}
fn absorb_extension(input: &[u8]) -> Vec<u8> {
    let (session, shard, classes, coefficients) = header(input);
    let values = shard_extension_values(coefficients, shard, classes);
    with_shard(session, shard, |state| {
        assert_eq!(state.hashers.len(), values.len());
        for (hasher, value) in state.hashers.iter_mut().zip(values.iter()) {
            hasher.update(field::encode(*value));
        }
    });
    Vec::new()
}
fn close(input: &[u8]) -> Vec<u8> {
    let (session, shard, classes, rest) = header(input);
    let (first, count) = (word(rest) as usize, word(&rest[4..]) as usize);
    let rows = SYSTEMATIC / classes;
    assert!(first + count <= rows);
    let output = with_shard(session, shard, |state| {
        assert_eq!(state.hashers.len(), rows);
        let mut output = Vec::with_capacity(64 * count);
        for hasher in &mut state.hashers[first..first + count] {
            output.extend(<[u8; 64]>::from(std::mem::take(hasher).finalize()));
        }
        output
    });
    if first + count == rows {
        SHARDS.with(|shards| shards.borrow_mut().remove(&(session, shard)));
    }
    output
}
fn discard(input: &[u8]) -> Vec<u8> {
    let (session, shard, _, _) = header(input);
    SHARDS.with(|shards| shards.borrow_mut().remove(&(session, shard)));
    Vec::new()
}
fn export(input: &[u8]) -> Vec<u8> {
    let (session, shard, _, rest) = header(input);
    let (first, count) = (word(rest) as usize, word(&rest[4..]) as usize);
    with_shard(session, shard, |state| {
        let mut output = Vec::with_capacity(STATE_BYTES * count);
        for hasher in &state.hashers[first..first + count] {
            output.extend(<[u8; STATE_BYTES]>::from(hasher.serialize()));
        }
        output
    })
}
fn import(input: &[u8]) -> Vec<u8> {
    let (session, shard, classes, rest) = header(input);
    let (first, count) = (word(rest) as usize, word(&rest[4..]) as usize);
    let states = &rest[8..];
    assert!(states.len() == STATE_BYTES * count && first + count <= SYSTEMATIC / classes);
    let hashers = states.chunks_exact(STATE_BYTES).map(|bytes| {
        let serialized: &SerializedState<Sha3_512> = bytes.try_into().unwrap();
        Sha3_512::deserialize(serialized).unwrap()
    });
    extend(session, shard, classes, first, hashers);
    Vec::new()
}

/// The row shards of one oracle commitment.
pub struct RowShards {
    session: u64,
    classes: usize,
    // Each started polynomial's shard jobs, oldest first.
    running: VecDeque<Vec<Ticket>>,
    closed: bool,
}

impl RowShards {
    fn new() -> Self {
        Self::with_classes(classes(parallel_work::helpers()))
    }
    fn with_classes(classes: usize) -> Self {
        Self {
            session: parallel_work::session(),
            classes,
            running: VecDeque::new(),
            closed: false,
        }
    }
    fn shards(&self) -> usize {
        4 * self.classes
    }
    fn rows(&self) -> usize {
        SYSTEMATIC / self.classes
    }
    fn header(&self, shard: usize) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(&self.session.to_le_bytes());
        bytes[8..12].copy_from_slice(&(shard as u32).to_le_bytes());
        bytes[12..].copy_from_slice(&(self.classes as u32).to_le_bytes());
        bytes
    }
    // A job on a shard with its header and range before the other bytes.
    fn range_job(
        &self,
        job: &'static Job,
        shard: usize,
        (first, count): (usize, usize),
        bytes: &[&[u8]],
        output: usize,
    ) -> Ticket {
        let mut input = Zeroizing::new(self.header(shard).to_vec());
        input.extend((first as u32).to_le_bytes());
        input.extend((count as u32).to_le_bytes());
        for part in bytes {
            input.extend_from_slice(part);
        }
        submit(job, Some(shard), &[Part::Bytes(&input)], output)
    }
    /// Opens the shards of a tree's rows.
    pub fn open(tree: &Tree) -> Self {
        Self::new().opened(tree)
    }
    fn opened(mut self, tree: &Tree) -> Self {
        let shards = &self;
        let mut prefix = Vec::from((tree.role.len() as u16).to_le_bytes());
        prefix.extend(&tree.role);
        prefix.extend((tree.stage as u32).to_le_bytes());
        prefix.extend((tree.width as u32).to_le_bytes());
        let mut tickets = Vec::new();
        for shard in 0..shards.shards() {
            for first in (0..shards.rows()).step_by(ROWS_PER_JOB) {
                let count = ROWS_PER_JOB.min(shards.rows() - first);
                let mut input = Zeroizing::new(shards.header(shard).to_vec());
                input.extend(&prefix);
                input.extend((first as u32).to_le_bytes());
                input.extend((count as u32).to_le_bytes());
                input.extend(tree.seed());
                tickets.push(submit(&OPEN, Some(shard), &[Part::Bytes(&input)], 0));
            }
        }
        self.running.push_back(tickets);
        self
    }
    // Starts every shard's job on the coefficients, after waiting for the
    // oldest polynomial's jobs once enough run.
    fn absorb(&mut self, job: &'static Job, coefficients: Zeroizing<Vec<u8>>) {
        let coefficients = share(coefficients);
        let tickets = (0..self.shards())
            .map(|shard| {
                submit(
                    job,
                    Some(shard),
                    &[
                        Part::Bytes(&self.header(shard)),
                        Part::Shared(&coefficients),
                    ],
                    0,
                )
            })
            .collect();
        self.running.push_back(tickets);
        while self.running.len() > POLYNOMIALS_RUNNING {
            for ticket in self.running.pop_front().unwrap() {
                ticket.wait();
            }
        }
    }
    /// Absorbs the values of a base polynomial of the coefficients.
    pub fn absorb_base(&mut self, coefficients: &[u128]) {
        let mut bytes = Zeroizing::new(Vec::with_capacity(16 * coefficients.len()));
        for value in coefficients {
            bytes.extend(value.to_le_bytes());
        }
        self.absorb_base_encoded(bytes);
    }
    /// Absorbs the values of a base polynomial of the encoded coefficients.
    pub fn absorb_base_encoded(&mut self, coefficients: Zeroizing<Vec<u8>>) {
        assert!(coefficients.len().is_multiple_of(16));
        self.absorb(&BASE, coefficients);
    }
    /// Absorbs the values of an extension polynomial of the coefficients.
    pub fn absorb_extension(&mut self, coefficients: &[Element]) {
        let mut bytes = Zeroizing::new(Vec::with_capacity(48 * coefficients.len()));
        for value in coefficients {
            bytes.extend(field::encode(*value));
        }
        self.absorb_extension_encoded(bytes);
    }
    /// Absorbs the values of an extension polynomial of the encoded
    /// coefficients.
    pub fn absorb_extension_encoded(&mut self, coefficients: Zeroizing<Vec<u8>>) {
        assert!(coefficients.len().is_multiple_of(48));
        self.absorb(&EXTENSION, coefficients);
    }
    fn settle(&mut self) {
        for tickets in std::mem::take(&mut self.running) {
            for ticket in tickets {
                ticket.wait();
            }
        }
    }
    /// Finishes every row's leaf and the tree above them, a subtree of
    /// leaves at a time: each shard's range of rows holds its residue class
    /// of the subtree's leaves.
    pub fn close(mut self, tree: &mut Tree) {
        self.settle();
        let shards = self.shards();
        let count = tree::SUBTREE_LEAVES.min(DOMAIN) / shards;
        let subtrees = (0..self.rows()).step_by(count).map(|first| {
            let tickets: Vec<_> = (0..shards)
                .map(|shard| self.range_job(&CLOSE, shard, (first, count), &[], 64 * count))
                .collect();
            let mut digests = vec![[0; 64]; shards * count];
            for (shard, ticket) in tickets.into_iter().enumerate() {
                for (q, digest) in ticket.wait().chunks_exact(64).enumerate() {
                    digests[shard + shards * q].copy_from_slice(digest);
                }
            }
            digests
        });
        tree.finish_from(subtrees);
        self.closed = true;
    }
    /// Every row's hash state, in row order.
    pub fn export(&mut self) -> Zeroizing<Vec<[u8; STATE_BYTES]>> {
        self.settle();
        let mut states = Zeroizing::new(vec![[0; STATE_BYTES]; DOMAIN]);
        for shard in 0..self.shards() {
            for first in (0..self.rows()).step_by(ROWS_PER_JOB) {
                let count = ROWS_PER_JOB.min(self.rows() - first);
                let output = self
                    .range_job(&EXPORT, shard, (first, count), &[], STATE_BYTES * count)
                    .wait();
                for (offset, state) in output.chunks_exact(STATE_BYTES).enumerate() {
                    states[shard + self.shards() * (first + offset)].copy_from_slice(state);
                }
            }
        }
        states
    }
    /// Shards holding the rows' hash states, in row order.
    pub fn import(states: &[Sha3_512]) -> Self {
        Self::new().imported(states)
    }
    fn imported(mut self, states: &[Sha3_512]) -> Self {
        assert_eq!(states.len(), DOMAIN);
        let shards = &self;
        let mut tickets = Vec::new();
        for shard in 0..shards.shards() {
            for first in (0..shards.rows()).step_by(ROWS_PER_JOB) {
                let count = ROWS_PER_JOB.min(shards.rows() - first);
                let mut bytes = Zeroizing::new(Vec::with_capacity(STATE_BYTES * count));
                for q in first..first + count {
                    bytes.extend(<[u8; STATE_BYTES]>::from(
                        states[shard + shards.shards() * q].serialize(),
                    ));
                }
                tickets.push(shards.range_job(&IMPORT, shard, (first, count), &[&bytes], 0));
            }
        }
        self.running.push_back(tickets);
        self
    }
}

impl Drop for RowShards {
    // Each shard's jobs run in order, so the rows of abandoned shards leave
    // their instances after their running jobs.
    fn drop(&mut self) {
        if !self.closed {
            for shard in 0..self.shards() {
                submit(
                    &DISCARD,
                    Some(shard),
                    &[Part::Bytes(&self.header(shard))],
                    0,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracles::extension_values;

    // A polynomial of the committed kinds, by its coefficients.
    enum Polynomial {
        Base(Vec<u128>),
        Extension(Vec<Element>),
    }
    fn polynomials(state: &mut u128) -> Vec<Polynomial> {
        let mut extension = |length: usize| -> Vec<Element> {
            (0..length)
                .map(|_| [sample(state), sample(state), sample(state)])
                .collect()
        };
        vec![
            Polynomial::Base(
                extension(SYSTEMATIC + MASKS)
                    .iter()
                    .map(|value| value[0])
                    .collect(),
            ),
            Polynomial::Extension(extension(2 * SYSTEMATIC + 1)),
            Polynomial::Base(extension(SYSTEMATIC).iter().map(|value| value[0]).collect()),
            Polynomial::Extension(extension(SYSTEMATIC + MASKS)),
        ]
    }
    // The tree whose leaves hash each row's values directly.
    fn direct_tree(seed: &[u8; tree::SALT_SEED_BYTES], polynomials: &[Polynomial]) -> Tree {
        let mut tree = Tree::with_seed(
            b"row shards",
            3,
            DOMAIN,
            polynomials.len(),
            Zeroizing::new(*seed),
        );
        let prefix = tree.leaf_hash_prefix();
        let mut hashers: Vec<_> = (0..DOMAIN)
            .map(|row| tree.leaf_hasher(row, &prefix))
            .collect();
        let transform = Transform::cached(SYSTEMATIC);
        for polynomial in polynomials {
            for coset_index in 0..4 {
                match polynomial {
                    Polynomial::Base(coefficients) => {
                        let lifted: Vec<Element> =
                            coefficients.iter().map(|value| [*value, 0, 0]).collect();
                        let values = extension_values(&lifted, coset(coset_index), transform);
                        for (position, value) in values.iter().enumerate() {
                            hashers[coset_index + 4 * position].update(value[0].to_le_bytes());
                        }
                    }
                    Polynomial::Extension(coefficients) => {
                        let values = extension_values(coefficients, coset(coset_index), transform);
                        for (position, value) in values.iter().enumerate() {
                            hashers[coset_index + 4 * position].update(field::encode(*value));
                        }
                    }
                }
            }
        }
        for (row, hasher) in hashers.into_iter().enumerate() {
            tree.leaf(row, hasher);
        }
        tree.finish();
        tree
    }
    // The tree's salt seed without its nodes.
    fn unfinished(tree: &Tree) -> Tree {
        Tree::with_seed(
            &tree.role,
            tree.stage,
            tree.length,
            tree.width,
            Zeroizing::new(*tree.seed()),
        )
    }
    fn absorb(shards: &mut RowShards, polynomial: &Polynomial) {
        match polynomial {
            Polynomial::Base(coefficients) => shards.absorb_base(coefficients),
            Polynomial::Extension(coefficients) => shards.absorb_extension(coefficients),
        }
    }
    fn resident(session: u64) -> bool {
        SHARDS.with(|shards| shards.borrow().keys().any(|key| key.0 == session))
    }

    #[test]
    fn shards_hash_the_rows_of_the_direct_tree() {
        let mut state = 0x9e3779b97f4a7c15f39cc0605cedc834u128;
        let polynomials = polynomials(&mut state);
        let seed = std::array::from_fn(|_| sample(&mut state) as u8);
        let expected = direct_tree(&seed, &polynomials);
        for classes in [1, 2, 16] {
            let mut tree = unfinished(&expected);
            let mut shards = RowShards::with_classes(classes).opened(&tree);
            let session = shards.session;
            for polynomial in &polynomials {
                absorb(&mut shards, polynomial);
            }
            shards.close(&mut tree);
            assert!(!resident(session));
            assert!(tree.root() == expected.root(), "{classes} classes");
        }
        // Rows exported after a polynomial continue where they stopped.
        let mut tree = unfinished(&expected);
        let mut shards = RowShards::with_classes(2).opened(&tree);
        absorb(&mut shards, &polynomials[0]);
        let states = shards.export();
        let abandoned = shards.session;
        drop(shards);
        assert!(!resident(abandoned));
        let states: Vec<Sha3_512> = states
            .iter()
            .map(|bytes| Sha3_512::deserialize(bytes.into()).unwrap())
            .collect();
        let mut shards = RowShards::with_classes(4).imported(&states);
        for polynomial in &polynomials[1..] {
            absorb(&mut shards, polynomial);
        }
        shards.close(&mut tree);
        assert!(tree.root() == expected.root());
    }

    #[test]
    fn helper_memory_holds_each_helpers_shards() {
        for (helpers, classes) in [
            (0, 1),
            (1, 1),
            (7, 1),
            (8, 2),
            (15, 2),
            (16, 4),
            (31, 4),
            (32, 8),
        ] {
            assert_eq!(super::classes(helpers), classes);
            let shards = (4 * classes).div_ceil(helpers.max(1));
            let rows = shards * (SYSTEMATIC / classes) * size_of::<Sha3_512>();
            let bytes = helper_memory_bytes(helpers);
            assert!(bytes.is_multiple_of(PAGE_BYTES) && bytes >= rows + JOB_MEMORY_BYTES);
            assert!(bytes < rows + JOB_MEMORY_BYTES + PAGE_BYTES);
        }
    }

    fn sample(state: &mut u128) -> u128 {
        *state ^= *state << 23;
        *state ^= *state >> 31;
        *state ^= *state << 17;
        *state % field::base::MODULUS
    }

    #[test]
    fn residue_classes_equal_the_full_coset_transform() {
        let mut state = 0x2545f4914f6cdd1du128;
        let transform = Transform::cached(SYSTEMATIC);
        for length in [
            1,
            SYSTEMATIC,
            SYSTEMATIC + MASKS,
            2 * SYSTEMATIC,
            2 * SYSTEMATIC + 1,
        ] {
            let coefficients: Vec<Element> = (0..length)
                .map(|_| [sample(&mut state), sample(&mut state), sample(&mut state)])
                .collect();
            let encoded: Vec<u8> = coefficients
                .iter()
                .flat_map(|value| field::encode(*value))
                .collect();
            let bases: Vec<u8> = coefficients
                .iter()
                .flat_map(|value| value[0].to_le_bytes())
                .collect();
            for coset_index in 0..4 {
                let full = extension_values(&coefficients, coset(coset_index), transform);
                for classes in [1, 2, 8] {
                    for residue in [0, classes - 1] {
                        let shard = (coset_index + 4 * residue) as u32;
                        let values = shard_extension_values(&encoded, shard, classes);
                        let base_values = shard_base_values(&bases, shard, classes);
                        for (q, (value, base_value)) in
                            values.iter().zip(base_values.iter()).enumerate()
                        {
                            let position = residue + classes * q;
                            assert_eq!(*value, full[position]);
                            assert_eq!(*base_value, full[position][0]);
                        }
                    }
                }
            }
        }
    }
}
