//! Sums of the terms that independent jobs add where they run. Each job
//! adds its terms to its instance's sums of a session; once every job
//! ends, the owner adds every instance's sums. Field addition is exact, so
//! the total equals the sum the owner computes alone in any order.
use crate::field::{self, Element, ZERO};
use parallel_work::{Job, Part, Pipeline, Ticket, submit};
use std::{cell::RefCell, collections::BTreeMap, collections::VecDeque};
use zeroize::Zeroizing;

/// A range of an instance's sums of a session, zero where it has none.
pub static COLLECT: Job = Job {
    kind: 0x0120,
    run: collect,
};
/// Removes an instance's sums of a session.
pub static REMOVE: Job = Job {
    kind: 0x0121,
    run: remove,
};

pub const HEADER_BYTES: usize = 12;
const ELEMENT_BYTES: usize = 48;
/// The sums one collection job copies.
const COLLECTED: usize = 1 << 15;

thread_local! {
    static SUMS: RefCell<BTreeMap<u64, Zeroizing<Vec<Element>>>> = RefCell::default();
}

/// A job's session and sum count, and the bytes that follow them.
pub fn header(input: &[u8]) -> (u64, usize, &[u8]) {
    let session = u64::from_le_bytes(input[..8].try_into().unwrap());
    let length = u32::from_le_bytes(input[8..12].try_into().unwrap()) as usize;
    (session, length, &input[HEADER_BYTES..])
}
/// Adds a job's terms to this instance's sums of the session, which its
/// first job creates.
pub fn with<T>(session: u64, length: usize, action: impl FnOnce(&mut [Element]) -> T) -> T {
    SUMS.with(|sums| {
        let mut sums = sums.borrow_mut();
        let entry = sums
            .entry(session)
            .or_insert_with(|| Zeroizing::new(vec![ZERO; length]));
        assert_eq!(entry.len(), length);
        action(entry)
    })
}
fn word(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
}
fn collect(input: &[u8]) -> Vec<u8> {
    let (session, length, rest) = header(input);
    let (first, count) = (word(rest), word(&rest[4..]));
    assert!(first + count <= length);
    SUMS.with(|sums| match sums.borrow().get(&session) {
        Some(values) => values[first..first + count]
            .iter()
            .flat_map(|value| field::encode(*value))
            .collect(),
        None => vec![0; ELEMENT_BYTES * count],
    })
}
fn remove(input: &[u8]) -> Vec<u8> {
    let (session, _, _) = header(input);
    SUMS.with(|sums| sums.borrow_mut().remove(&session));
    Vec::new()
}

/// The sums of one computation's jobs.
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
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(&self.session.to_le_bytes());
        bytes[8..].copy_from_slice(&(self.length as u32).to_le_bytes());
        bytes
    }
    /// Keeps a job's ticket, waiting for the oldest once a window of them
    /// runs. The job returns no output.
    pub fn add(&mut self, ticket: Ticket) {
        self.running.push_back(ticket);
        while self.running.len() > parallel_work::window() {
            assert!(self.running.pop_front().unwrap().wait().is_empty());
        }
    }
    // Each instance that may hold sums: every helper, or this one.
    fn instances() -> usize {
        parallel_work::helpers().max(1)
    }
    /// Every instance's sums added together.
    pub fn finish(mut self) -> Zeroizing<Vec<Element>> {
        for ticket in std::mem::take(&mut self.running) {
            assert!(ticket.wait().is_empty());
        }
        let header = self.header();
        let mut total = Zeroizing::new(vec![ZERO; self.length]);
        let mut add = |first: usize, output: Zeroizing<Vec<u8>>| {
            for (sum, bytes) in total[first..]
                .iter_mut()
                .zip(output.chunks_exact(ELEMENT_BYTES))
            {
                *sum = field::add(*sum, field::decode(bytes));
            }
        };
        let mut pipeline = Pipeline::new(parallel_work::window());
        for instance in 0..Self::instances() {
            for first in (0..self.length).step_by(COLLECTED) {
                let count = COLLECTED.min(self.length - first);
                let mut range = Vec::from((first as u32).to_le_bytes());
                range.extend((count as u32).to_le_bytes());
                let ticket = submit(
                    &COLLECT,
                    Some(instance),
                    &[Part::Bytes(&header), Part::Bytes(&range)],
                    ELEMENT_BYTES * count,
                );
                if let Some((first, output)) = pipeline.push(first, ticket) {
                    add(first, output);
                }
            }
        }
        for (first, output) in pipeline.finish() {
            add(first, output);
        }
        self.remove();
        self.finished = true;
        total
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
            for ticket in std::mem::take(&mut self.running) {
                drop(ticket.wait());
            }
            self.remove();
        }
    }
}
