//! Sums of the terms that independent jobs add where they run. Each job
//! adds its terms to its instance's sums of a session's shard. The sums of
//! a computation lie either on every instance that runs its jobs, which the
//! owner adds together once every job ends, or in shards whose jobs all run
//! on the one instance that holds each, which the owner then collects.
//! Field addition is exact, so each total equals the sum the owner computes
//! alone in any order.
use crate::field::{self, Element, ZERO};
use parallel_work::{Job, Part, Pipeline, Ticket, submit};
use std::{cell::RefCell, collections::BTreeMap, collections::VecDeque};
use zeroize::Zeroizing;

/// A range of an instance's sums of a shard, zero where it has none.
pub static COLLECT: Job = Job {
    kind: 0x0120,
    run: collect,
};
/// Removes an instance's sums of a shard.
pub static REMOVE: Job = Job {
    kind: 0x0121,
    run: remove,
};

pub const HEADER_BYTES: usize = 16;
const ELEMENT_BYTES: usize = 48;
/// The sums one collection job copies.
const COLLECTED: usize = 1 << 15;

// This instance's sums of each session's shards.
type Shards = BTreeMap<(u64, u32), Zeroizing<Vec<Element>>>;
thread_local! {
    static SUMS: RefCell<Shards> = RefCell::default();
}

/// A job's session, shard and sum count, and the bytes that follow them.
pub fn header(input: &[u8]) -> (u64, u32, usize, &[u8]) {
    let session = u64::from_le_bytes(input[..8].try_into().unwrap());
    let shard = u32::from_le_bytes(input[8..12].try_into().unwrap());
    let length = u32::from_le_bytes(input[12..16].try_into().unwrap()) as usize;
    (session, shard, length, &input[HEADER_BYTES..])
}
fn encode_header(session: u64, shard: usize, length: usize) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..8].copy_from_slice(&session.to_le_bytes());
    bytes[8..12].copy_from_slice(&(shard as u32).to_le_bytes());
    bytes[12..].copy_from_slice(&(length as u32).to_le_bytes());
    bytes
}
/// Adds a job's terms to this instance's sums of the shard, which its
/// first job creates.
pub fn with<T>(
    session: u64,
    shard: u32,
    length: usize,
    action: impl FnOnce(&mut [Element]) -> T,
) -> T {
    SUMS.with(|sums| {
        let mut sums = sums.borrow_mut();
        let entry = sums
            .entry((session, shard))
            .or_insert_with(|| Zeroizing::new(vec![ZERO; length]));
        assert_eq!(entry.len(), length);
        action(entry)
    })
}
fn word(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
}
fn collect(input: &[u8]) -> Vec<u8> {
    let (session, shard, length, rest) = header(input);
    let (first, count) = (word(rest), word(&rest[4..]));
    assert!(first + count <= length);
    SUMS.with(|sums| match sums.borrow().get(&(session, shard)) {
        Some(values) => {
            let mut output = Vec::with_capacity(ELEMENT_BYTES * count);
            for value in &values[first..first + count] {
                output.extend(field::encode(*value));
            }
            output
        }
        None => vec![0; ELEMENT_BYTES * count],
    })
}
fn remove(input: &[u8]) -> Vec<u8> {
    let (session, shard, _, _) = header(input);
    SUMS.with(|sums| sums.borrow_mut().remove(&(session, shard)));
    Vec::new()
}
// Starts the collection jobs of the ranges of an instance's sums of a
// shard, each named by its first index after the offset, and gives each
// earlier range's encoded sums with its name once a window of them runs.
fn collect_ranges(
    header: &[u8; HEADER_BYTES],
    instance: usize,
    (offset, length): (usize, usize),
    pipeline: &mut Pipeline,
    take: &mut impl FnMut(usize, Zeroizing<Vec<u8>>),
) {
    for first in (0..length).step_by(COLLECTED) {
        let count = COLLECTED.min(length - first);
        let mut range = Vec::from((first as u32).to_le_bytes());
        range.extend((count as u32).to_le_bytes());
        let ticket = submit(
            &COLLECT,
            Some(instance),
            &[Part::Bytes(header), Part::Bytes(&range)],
            ELEMENT_BYTES * count,
        );
        if let Some((name, output)) = pipeline.push(offset + first, ticket) {
            take(name, output);
        }
    }
}
// Keeps a job's ticket, waiting for the oldest once a window of them runs.
// The job returns no output.
fn keep(running: &mut VecDeque<Ticket>, ticket: Ticket) {
    running.push_back(ticket);
    while running.len() > parallel_work::window() {
        assert!(running.pop_front().unwrap().wait().is_empty());
    }
}
fn end(running: &mut VecDeque<Ticket>) {
    for ticket in std::mem::take(running) {
        drop(ticket.wait());
    }
}

/// The sums of one computation's jobs that every instance running them
/// keeps.
pub struct Sums {
    session: u64,
    length: usize,
    running: VecDeque<Ticket>,
    finished: bool,
}
impl Sums {
    pub fn new(length: usize) -> Self {
        assert!(length <= u32::MAX as usize);
        Self {
            session: parallel_work::session(),
            length,
            running: VecDeque::new(),
            finished: false,
        }
    }
    /// The header that starts each job's input.
    pub fn header(&self) -> [u8; HEADER_BYTES] {
        encode_header(self.session, 0, self.length)
    }
    /// Keeps a job's ticket, waiting for the oldest once a window of them
    /// runs. The job returns no output.
    pub fn add(&mut self, ticket: Ticket) {
        keep(&mut self.running, ticket);
    }
    // Each instance that may hold sums: every helper, or this one.
    fn instances() -> usize {
        parallel_work::helpers().max(1)
    }
    /// Gives each instance's sums, each with its index, once every job has
    /// ended; the owner adds them together.
    pub fn finish(mut self, mut add: impl FnMut(usize, Element)) {
        for ticket in std::mem::take(&mut self.running) {
            assert!(ticket.wait().is_empty());
        }
        let header = self.header();
        let mut add = |first: usize, output: Zeroizing<Vec<u8>>| {
            for (offset, bytes) in output.chunks_exact(ELEMENT_BYTES).enumerate() {
                add(first + offset, field::decode(bytes));
            }
        };
        let mut pipeline = Pipeline::new(parallel_work::window());
        for instance in 0..Self::instances() {
            collect_ranges(&header, instance, (0, self.length), &mut pipeline, &mut add);
        }
        for (first, output) in pipeline.finish() {
            add(first, output);
        }
        self.remove();
        self.finished = true;
    }
    fn remove(&self) {
        let header = self.header();
        for instance in 0..Self::instances() {
            submit(&REMOVE, Some(instance), &[Part::Bytes(&header)], 0);
        }
    }
}
impl Drop for Sums {
    // Abandoned sums leave every instance once the jobs that add to them
    // end.
    fn drop(&mut self) {
        if !self.finished {
            end(&mut self.running);
            self.remove();
        }
    }
}

/// The sums of one computation's jobs in shards of equal length, each on
/// the one instance that runs the shard's jobs.
pub struct ShardSums {
    session: u64,
    shards: usize,
    length: usize,
    running: VecDeque<Ticket>,
    finished: bool,
}
impl ShardSums {
    pub fn new(shards: usize, length: usize) -> Self {
        assert!(shards <= u32::MAX as usize && length <= u32::MAX as usize);
        Self {
            session: parallel_work::session(),
            shards,
            length,
            running: VecDeque::new(),
            finished: false,
        }
    }
    fn header(&self, shard: usize) -> [u8; HEADER_BYTES] {
        assert!(shard < self.shards);
        encode_header(self.session, shard, self.length)
    }
    /// Starts a job of the shard, on its parts after the shard's header,
    /// where the shard lies, waiting for the oldest once a window of them
    /// runs. The job returns no output.
    pub fn submit(&mut self, job: &'static Job, shard: usize, parts: &[Part]) {
        let header = self.header(shard);
        let mut joined = vec![Part::Bytes(&header)];
        joined.extend_from_slice(parts);
        keep(&mut self.running, submit(job, Some(shard), &joined, 0));
    }
    /// Gives each range of each shard's encoded sums, with the shard and the
    /// range's first index, once every job has ended.
    pub fn finish(mut self, mut take: impl FnMut(usize, usize, Zeroizing<Vec<u8>>)) {
        for ticket in std::mem::take(&mut self.running) {
            assert!(ticket.wait().is_empty());
        }
        let length = self.length;
        let mut named = |name: usize, output| take(name / length, name % length, output);
        let mut pipeline = Pipeline::new(parallel_work::window());
        for shard in 0..self.shards {
            let header = self.header(shard);
            let range = (shard * length, length);
            collect_ranges(&header, shard, range, &mut pipeline, &mut named);
        }
        for (name, output) in pipeline.finish() {
            named(name, output);
        }
        self.remove();
        self.finished = true;
    }
    fn remove(&self) {
        for shard in 0..self.shards {
            let header = self.header(shard);
            submit(&REMOVE, Some(shard), &[Part::Bytes(&header)], 0);
        }
    }
}
impl Drop for ShardSums {
    // Abandoned shards leave their instances once the jobs that add to them
    // end.
    fn drop(&mut self) {
        if !self.finished {
            end(&mut self.running);
            self.remove();
        }
    }
}
