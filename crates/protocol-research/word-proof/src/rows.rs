//! An oracle's leaf hashers, split into residue classes of rows. With `P`
//! classes per coset, the shard `s = k + 4 j` holds the rows congruent to `s`
//! modulo `4 P`, which are the positions `j + P q` of the coset `k`. A shard
//! computes those positions' values of each committed polynomial from its
//! coefficients, which its job streams as the folds read them, by folding
//! them onto a transform of `SYSTEMATIC / P` points, and absorbs them into
//! its rows, so neither the values nor the row states leave the instance
//! that holds the shard. The folded sums equal the full transform's values
//! exactly.
use crate::{
    field::{self, Element, Transform, ZERO, base},
    oracles::coset,
    parameters::*,
    tree::{self, Tree},
};
use parallel_work::ProtocolHash;
use parallel_work::{Job, Part, StreamedRecords, Ticket, share, submit};
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
const STATE_BYTES: usize = ProtocolHash::STATE_BYTES;

/// The residue classes per coset for a helper count: the most for which
/// every shard has a helper of its own, and one without enough helpers.
pub fn classes(helpers: usize) -> usize {
    (1 << (helpers / 4).max(1).ilog2()).min(SYSTEMATIC / 2)
}
/// The linear memory the rows of the shards that one of the helpers holds
/// take.
pub fn helper_rows_bytes(helpers: usize) -> usize {
    let classes = classes(helpers);
    let shards = (4 * classes).div_ceil(helpers.max(1));
    shards * (SYSTEMATIC / classes) * size_of::<ProtocolHash>()
}

struct Shard {
    hashers: Vec<ProtocolHash>,
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
    mut coefficient: impl FnMut(usize) -> T,
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
    let mut wrapped = |index: usize| {
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
        // The highest fold starts the sum, which each lower fold scales.
        let mut sum = wrapped(index + block * (classes - 1));
        for fold in (0..classes - 1).rev() {
            sum = sum.scale(step).add(wrapped(index + block * fold));
        }
        values.push(sum.scale(power));
        power = base::multiply(power, twist);
    }
    values
}

/// A base polynomial's values at a shard's rows, in row order, from its
/// coefficients of the length, each read as the fold needs it.
fn shard_base_values_of(
    length: usize,
    coefficient: impl FnMut(usize) -> u128,
    shard: u32,
    classes: usize,
) -> Zeroizing<Vec<u128>> {
    let shard = shard as usize;
    let mut values = residue_values(length, coefficient, shard % 4, classes, shard / 4);
    Transform::cached(SYSTEMATIC).base(&mut values, false);
    values
}
/// An extension polynomial's values at a shard's rows, in row order, from
/// its coefficients of the length, each read as the fold needs it.
pub(crate) fn shard_extension_values_of(
    length: usize,
    coefficient: impl FnMut(usize) -> Element,
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
/// An extension polynomial's values at a shard's rows, in row order, from
/// the encoded coefficients the job streams; each fold reads a region of
/// the classes' span in order.
pub(crate) fn streamed_extension_values(shard: u32, classes: usize) -> Zeroizing<Vec<Element>> {
    let mut coefficients = StreamedRecords::new(48, SYSTEMATIC / classes);
    let length = coefficients.count();
    shard_extension_values_of(
        length,
        |index| field::decode(coefficients.record(index)),
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
    hashers: impl Iterator<Item = ProtocolHash>,
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
    let (session, shard, classes, rest) = header(input);
    assert!(rest.is_empty());
    let mut coefficients = StreamedRecords::new(16, SYSTEMATIC / classes);
    let length = coefficients.count();
    let values = shard_base_values_of(
        length,
        |index| u128::from_le_bytes(coefficients.record(index).try_into().unwrap()),
        shard,
        classes,
    );
    with_shard(session, shard, |state| {
        assert_eq!(state.hashers.len(), values.len());
        for (hasher, value) in state.hashers.iter_mut().zip(values.iter()) {
            hasher.update(value.to_le_bytes());
        }
    });
    Vec::new()
}
fn absorb_extension(input: &[u8]) -> Vec<u8> {
    let (session, shard, classes, rest) = header(input);
    assert!(rest.is_empty());
    let values = streamed_extension_values(shard, classes);
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
            output.extend(std::mem::take(hasher).finalize());
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
            output.extend(hasher.serialize());
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
        let serialized: &[u8; STATE_BYTES] = bytes.try_into().unwrap();
        ProtocolHash::deserialize(serialized).unwrap()
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
    // A job on a shard with its header and range before the other bytes,
    // in an input of their exact length.
    fn range_job(
        &self,
        job: &'static Job,
        shard: usize,
        (first, count): (usize, usize),
        bytes: &[&[u8]],
        output: usize,
    ) -> Ticket {
        let mut input = Zeroizing::new(Vec::with_capacity(
            HEADER_BYTES + 8 + bytes.iter().map(|part| part.len()).sum::<usize>(),
        ));
        input.extend(self.header(shard));
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
    // Records a step's jobs, waiting for the oldest step's once enough run.
    fn started(&mut self, tickets: Vec<Ticket>) {
        self.running.push_back(tickets);
        while self.running.len() > POLYNOMIALS_RUNNING {
            for ticket in self.running.pop_front().unwrap() {
                ticket.wait();
            }
        }
    }
    // Starts every shard's job on the coefficients, which each streams,
    // after waiting for the oldest polynomial's jobs once enough run.
    fn absorb(&mut self, job: &'static Job, coefficients: Zeroizing<Vec<u8>>) {
        let coefficients = share(coefficients);
        let tickets = (0..self.shards())
            .map(|shard| {
                submit(
                    job,
                    Some(shard),
                    &[
                        Part::Bytes(&self.header(shard)),
                        Part::Streamed(&coefficients),
                    ],
                    0,
                )
            })
            .collect();
        self.started(tickets);
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
    // Each shard's jobs over its rows among the rows from the first, one
    // job for at most the job bound of the shard's consecutive rows: the
    // shard, its first row and their count.
    fn ranges(&self, first: usize, count: usize) -> Vec<(usize, usize, usize)> {
        assert!(first + count <= DOMAIN);
        let shards = self.shards();
        let mut ranges = Vec::new();
        for shard in 0..shards {
            let start = first.saturating_sub(shard).div_ceil(shards);
            let end = (first + count).saturating_sub(shard).div_ceil(shards);
            for row in (start..end).step_by(ROWS_PER_JOB) {
                ranges.push((shard, row, ROWS_PER_JOB.min(end - row)));
            }
        }
        ranges
    }
    /// The hash states of the rows from the first, in row order.
    pub fn export(&mut self, first: usize, count: usize) -> Zeroizing<Vec<u8>> {
        self.settle();
        let shards = self.shards();
        let tickets: Vec<_> = self
            .ranges(first, count)
            .into_iter()
            .map(|(shard, row, rows)| {
                let ticket = self.range_job(&EXPORT, shard, (row, rows), &[], STATE_BYTES * rows);
                (shard, row, ticket)
            })
            .collect();
        let mut states = Zeroizing::new(vec![0; STATE_BYTES * count]);
        for (shard, row, ticket) in tickets {
            for (offset, state) in ticket.wait().chunks_exact(STATE_BYTES).enumerate() {
                let index = shard + shards * (row + offset) - first;
                states[STATE_BYTES * index..STATE_BYTES * (index + 1)].copy_from_slice(state);
            }
        }
        states
    }
    /// Shards whose rows' hash states are restored in row order.
    pub fn importing() -> Self {
        Self::new()
    }
    /// Restores the hash states of the rows from the first, in row order,
    /// after those of every earlier row.
    pub fn import(&mut self, first: usize, states: &[u8]) {
        assert!(states.len().is_multiple_of(STATE_BYTES));
        let shards = self.shards();
        let tickets = self
            .ranges(first, states.len() / STATE_BYTES)
            .into_iter()
            .map(|(shard, row, rows)| {
                let mut bytes = Zeroizing::new(Vec::with_capacity(STATE_BYTES * rows));
                for q in row..row + rows {
                    let index = shard + shards * q - first;
                    bytes
                        .extend_from_slice(&states[STATE_BYTES * index..STATE_BYTES * (index + 1)]);
                }
                self.range_job(&IMPORT, shard, (row, rows), &[&bytes], 0)
            })
            .collect();
        self.started(tickets);
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
#[path = "rows-tests.rs"]
mod tests;
