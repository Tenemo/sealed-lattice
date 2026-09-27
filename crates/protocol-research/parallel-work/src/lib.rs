//! Independent jobs that the participant runtime may run on helper instances
//! of the same module. A job is a deterministic function of its input bytes
//! and of the state its shard's earlier jobs left, it draws no randomness,
//! and its caller declares its output length. Without helpers each job runs
//! here when it is submitted; with them a shard's jobs run in submission
//! order on the one helper that holds the shard. Either way every output
//! equals the one this instance computes alone.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_arch = "wasm32"))]
mod simulated;
mod stream;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicU64, Ordering},
};
pub use stream::{HashStream, Sponge};
use zeroize::Zeroizing;

/// The most bytes one job's input or output holds, the bound on one buffer
/// the host copies between instances.
pub const MAXIMUM_JOB_BYTES: usize = 8 << 20;
/// The most parts one job's input joins.
pub const MAXIMUM_JOB_PARTS: usize = 4;

/// A job. A helper instance runs the function its kind names.
pub struct Job {
    pub kind: u32,
    pub run: fn(&[u8]) -> Vec<u8>,
}

static SESSIONS: AtomicU64 = AtomicU64::new(1);

/// A number no other caller in this instance receives, which names the
/// state its jobs keep on their shards. Every crate that includes the same
/// job source draws from this one sequence.
pub fn session() -> u64 {
    SESSIONS.fetch_add(1, Ordering::Relaxed)
}

/// The jobs this crate defines.
pub static JOBS: [&Job; 1] = [&stream::STREAM];

/// The job of a kind among the listed ones.
pub fn find(jobs: &[&'static Job], kind: u32) -> Option<&'static Job> {
    jobs.iter().copied().find(|job| job.kind == kind)
}

#[cfg(target_arch = "wasm32")]
mod host {
    #[link(wasm_import_module = "parallel")]
    unsafe extern "C" {
        /// The helper instances that run jobs, zero when there are none.
        pub fn helpers() -> u32;
        /// Copies bytes that later jobs read and returns their handle.
        pub fn share(pointer: *const u8, length: u32) -> u32;
        /// Drops this instance's reference to shared bytes.
        pub fn release(shared: u32);
        /// Starts a job on its input parts, each a tag and two words: bytes
        /// at a pointer and length, which the host copies now, or shared
        /// bytes. A nonzero pin names the helper that must run the job.
        /// Returns the job's ticket.
        pub fn submit(kind: u32, pin: u32, parts: *const u32, count: u32, output: u32) -> u32;
        /// Waits for the job. The host ends the instance's call when the
        /// job did not return its declared length.
        pub fn wait(ticket: u32);
        /// Copies the waited job's output and clears the host's copy.
        pub fn take(ticket: u32, pointer: *mut u8) -> u32;
        /// Waits for the job and clears its output untaken.
        pub fn discard(ticket: u32);
    }
}

/// The helper instances that run jobs besides this one.
pub fn helpers() -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        unsafe { host::helpers() as usize }
    }
    #[cfg(not(target_arch = "wasm32"))]
    simulated::helpers()
}

/// Bytes that several jobs read; with helpers only the host holds them.
pub struct Shared {
    local: Zeroizing<Vec<u8>>,
    #[cfg(target_arch = "wasm32")]
    length: usize,
    #[cfg(target_arch = "wasm32")]
    remote: u32,
}

/// Holds the bytes for later jobs.
pub fn share(bytes: Zeroizing<Vec<u8>>) -> Shared {
    assert!(bytes.len() <= MAXIMUM_JOB_BYTES, "Job input bound");
    #[cfg(target_arch = "wasm32")]
    if helpers() > 0 {
        let remote = unsafe { host::share(bytes.as_ptr(), bytes.len() as u32) };
        return Shared {
            local: Zeroizing::new(Vec::new()),
            length: bytes.len(),
            remote,
        };
    }
    Shared {
        #[cfg(target_arch = "wasm32")]
        length: bytes.len(),
        local: bytes,
        #[cfg(target_arch = "wasm32")]
        remote: 0,
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        #[cfg(target_arch = "wasm32")]
        if self.remote != 0 {
            unsafe { host::release(self.remote) };
        }
    }
}

/// A part of a job's input: bytes, or shared bytes.
pub enum Part<'a> {
    Bytes(&'a [u8]),
    Shared(&'a Shared),
}

/// A submitted job, whose output its waiter takes.
pub struct Ticket {
    output: Option<Zeroizing<Vec<u8>>>,
    #[cfg(target_arch = "wasm32")]
    remote: u32,
    #[cfg(target_arch = "wasm32")]
    output_length: usize,
    #[cfg(not(target_arch = "wasm32"))]
    simulated: Option<std::sync::Arc<simulated::Slot>>,
}

/// Starts the job on its joined parts. A job with a shard runs where that
/// shard's state lies, after the shard's earlier jobs.
pub fn submit(
    job: &'static Job,
    shard: Option<usize>,
    parts: &[Part],
    output_length: usize,
) -> Ticket {
    assert!(
        parts.len() <= MAXIMUM_JOB_PARTS && output_length <= MAXIMUM_JOB_BYTES,
        "Job bound"
    );
    #[cfg(target_arch = "wasm32")]
    {
        let helpers = helpers();
        if helpers > 0 {
            let mut input_length = 0;
            let words: Vec<u32> = parts
                .iter()
                .flat_map(|part| match part {
                    Part::Bytes(bytes) => {
                        input_length += bytes.len();
                        [0, bytes.as_ptr() as u32, bytes.len() as u32]
                    }
                    Part::Shared(shared) => {
                        input_length += shared.length;
                        [1, shared.remote, 0]
                    }
                })
                .collect();
            assert!(input_length <= MAXIMUM_JOB_BYTES, "Job input bound");
            let pin = shard.map_or(0, |shard| (shard % helpers) as u32 + 1);
            // The host copies every byte part before it returns.
            let remote = unsafe {
                host::submit(
                    job.kind,
                    pin,
                    words.as_ptr(),
                    parts.len() as u32,
                    output_length as u32,
                )
            };
            return Ticket {
                output: None,
                remote,
                output_length,
            };
        }
    }
    let mut input = Zeroizing::new(Vec::new());
    for part in parts {
        input.extend_from_slice(match part {
            Part::Bytes(bytes) => bytes,
            Part::Shared(shared) => &shared.local,
        });
    }
    assert!(input.len() <= MAXIMUM_JOB_BYTES, "Job input bound");
    #[cfg(not(target_arch = "wasm32"))]
    {
        let helpers = helpers();
        if helpers > 0 {
            let pin = shard.map_or(0, |shard| shard % helpers + 1);
            return Ticket {
                output: None,
                simulated: Some(simulated::submit(job, pin, input, output_length)),
            };
        }
    }
    let _ = shard;
    let output = Zeroizing::new((job.run)(&input));
    assert_eq!(output.len(), output_length, "Job output length");
    Ticket {
        output: Some(output),
        #[cfg(target_arch = "wasm32")]
        remote: 0,
        #[cfg(target_arch = "wasm32")]
        output_length,
        #[cfg(not(target_arch = "wasm32"))]
        simulated: None,
    }
}

impl Ticket {
    /// The job's output.
    pub fn wait(mut self) -> Zeroizing<Vec<u8>> {
        #[cfg(target_arch = "wasm32")]
        if self.remote != 0 {
            let remote = std::mem::take(&mut self.remote);
            unsafe { host::wait(remote) };
            let mut output = Zeroizing::new(vec![0; self.output_length]);
            assert_eq!(unsafe { host::take(remote, output.as_mut_ptr()) }, 0);
            return output;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(slot) = self.simulated.take() {
            return slot.wait();
        }
        self.output.take().unwrap()
    }
}

impl Drop for Ticket {
    // An abandoned job still runs; its output is cleared.
    fn drop(&mut self) {
        #[cfg(target_arch = "wasm32")]
        if self.remote != 0 {
            unsafe { host::discard(self.remote) };
        }
    }
}

/// The jobs a caller keeps started ahead of the output it consumes: two for
/// each helper, or one without helpers.
pub fn window() -> usize {
    (2 * helpers()).max(1)
}

/// Tickets in submission order, consumed once more than a window of them
/// run.
pub struct Pipeline {
    running: VecDeque<(usize, Ticket)>,
    window: usize,
}

impl Pipeline {
    pub fn new(window: usize) -> Self {
        Self {
            running: VecDeque::new(),
            window: window.max(1),
        }
    }
    /// Adds a ticket and returns the oldest output once more than the
    /// window run.
    pub fn push(&mut self, index: usize, ticket: Ticket) -> Option<(usize, Zeroizing<Vec<u8>>)> {
        self.running.push_back((index, ticket));
        (self.running.len() > self.window).then(|| {
            let (index, ticket) = self.running.pop_front().unwrap();
            (index, ticket.wait())
        })
    }
    /// The remaining outputs in submission order.
    pub fn finish(self) -> impl Iterator<Item = (usize, Zeroizing<Vec<u8>>)> {
        self.running
            .into_iter()
            .map(|(index, ticket)| (index, ticket.wait()))
    }
}

/// A helper instance's buffers for the one job it runs at a time.
pub mod helper {
    use super::{Job, MAXIMUM_JOB_BYTES, find};
    use std::cell::RefCell;
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct Buffers {
        input: Zeroizing<Vec<u8>>,
        output: Zeroizing<Vec<u8>>,
    }
    thread_local! {static BUFFERS: RefCell<Buffers> = RefCell::default();}

    /// A zeroed input buffer of the length, or a null pointer beyond the
    /// bound.
    pub fn input(length: usize) -> usize {
        if length > MAXIMUM_JOB_BYTES {
            return 0;
        }
        BUFFERS.with(|buffers| {
            let mut buffers = buffers.borrow_mut();
            buffers.input = Zeroizing::new(vec![0; length]);
            buffers.input.as_mut_ptr() as usize
        })
    }
    /// Runs the job of the kind among the registries' jobs on the input,
    /// which it then releases. Returns zero on success and one for a kind
    /// no listed job has; the host checks the output length.
    pub fn run(registries: &[&[&'static Job]], kind: u32) -> u32 {
        let Some(job) = registries.iter().find_map(|jobs| find(jobs, kind)) else {
            return 1;
        };
        BUFFERS.with(|buffers| {
            let mut buffers = buffers.borrow_mut();
            let output = Zeroizing::new((job.run)(&buffers.input));
            buffers.input = Zeroizing::new(Vec::new());
            buffers.output = output;
        });
        0
    }
    pub fn output_pointer() -> usize {
        BUFFERS.with(|buffers| buffers.borrow().output.as_ptr() as usize)
    }
    pub fn output_length() -> usize {
        BUFFERS.with(|buffers| buffers.borrow().output.len())
    }
    /// Clears and releases both buffers.
    pub fn clear() {
        BUFFERS.with(|buffers| *buffers.borrow_mut() = Buffers::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn reverse(input: &[u8]) -> Vec<u8> {
        input.iter().rev().copied().collect()
    }
    static REVERSE: Job = Job {
        kind: 7,
        run: reverse,
    };
    thread_local! {static TOTAL: Cell<u8> = const { Cell::new(0) };}
    // A shard's job that adds its input to the shard's running total.
    fn accumulate(input: &[u8]) -> Vec<u8> {
        TOTAL.with(|total| {
            total.set(
                input
                    .iter()
                    .fold(total.get(), |sum, value| sum.wrapping_add(*value)),
            );
            vec![total.get()]
        })
    }
    static ACCUMULATE: Job = Job {
        kind: 8,
        run: accumulate,
    };
    fn oversized(_: &[u8]) -> Vec<u8> {
        vec![0; MAXIMUM_JOB_BYTES + 1]
    }
    static OVERSIZED: Job = Job {
        kind: 9,
        run: oversized,
    };

    #[test]
    fn outputs_join_parts_and_follow_each_shard() {
        let shared = share(Zeroizing::new(vec![4, 5]));
        let first = submit(&REVERSE, None, &[Part::Bytes(&[1, 2, 3])], 3);
        let second = submit(
            &REVERSE,
            None,
            &[
                Part::Shared(&shared),
                Part::Bytes(&[]),
                Part::Shared(&shared),
            ],
            4,
        );
        assert_eq!(second.wait().to_vec(), [5, 4, 5, 4]);
        assert_eq!(first.wait().to_vec(), [3, 2, 1]);
        let totals: Vec<u8> = [[1, 2], [3, 4]]
            .iter()
            .map(|input| submit(&ACCUMULATE, Some(3), &[Part::Bytes(input)], 1).wait()[0])
            .collect();
        assert_eq!(totals, [3, 10]);
    }

    #[test]
    fn refuses_undeclared_lengths_and_oversized_jobs() {
        // A job with helpers fails when its output is taken.
        for length in [1, 3] {
            assert!(
                std::panic::catch_unwind(|| submit(
                    &REVERSE,
                    None,
                    &[Part::Bytes(&[1, 2])],
                    length
                )
                .wait())
                .is_err()
            );
        }
        let large = vec![0; MAXIMUM_JOB_BYTES / 2 + 1];
        assert!(
            std::panic::catch_unwind(|| submit(
                &REVERSE,
                None,
                &[Part::Bytes(&large), Part::Bytes(&large)],
                0
            ))
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| submit(&REVERSE, None, &[], MAXIMUM_JOB_BYTES + 1))
                .is_err()
        );
        let parts: Vec<Part> = (0..=MAXIMUM_JOB_PARTS).map(|_| Part::Bytes(&[])).collect();
        assert!(std::panic::catch_unwind(|| submit(&REVERSE, None, &parts, 0)).is_err());
        assert!(
            std::panic::catch_unwind(|| share(Zeroizing::new(vec![0; MAXIMUM_JOB_BYTES + 1])))
                .is_err()
        );
    }

    #[test]
    fn pipelines_keep_submission_order() {
        for (count, window) in [(0, 1), (1, 0), (2, 1), (5, 2), (5, 8)] {
            let mut pipeline = Pipeline::new(window);
            let mut seen = Vec::new();
            for index in 0..count {
                let ticket = submit(&REVERSE, None, &[Part::Bytes(&[index as u8, 0])], 2);
                seen.extend(pipeline.push(index, ticket));
            }
            seen.extend(pipeline.finish());
            assert_eq!(
                seen.into_iter()
                    .map(|(index, output)| (index, output.to_vec()))
                    .collect::<Vec<_>>(),
                (0..count)
                    .map(|index| (index, vec![0, index as u8]))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn helpers_run_listed_kinds_within_the_bounds() {
        let jobs: [&'static Job; 2] = [&REVERSE, &OVERSIZED];
        assert_eq!(helper::input(MAXIMUM_JOB_BYTES + 1), 0);
        let pointer = helper::input(3) as *mut u8;
        unsafe { std::slice::from_raw_parts_mut(pointer, 3) }.copy_from_slice(&[4, 5, 6]);
        assert_eq!(helper::run(&[&jobs], 3), 1);
        assert_eq!(helper::run(&[&[], &jobs], 7), 0);
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    helper::output_pointer() as *const u8,
                    helper::output_length(),
                )
            },
            [6, 5, 4]
        );
        helper::clear();
        assert_eq!(helper::output_length(), 0);
        helper::input(0);
        assert_eq!(helper::run(&[&jobs], 9), 0);
        // The host refuses this output, which exceeds any declared length.
        assert_eq!(helper::output_length(), MAXIMUM_JOB_BYTES + 1);
    }
}
