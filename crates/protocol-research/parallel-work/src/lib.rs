//! Independent jobs that the participant runtime may run on helper instances
//! of the same module. A job is a deterministic function of its input bytes
//! and of the state its shard's earlier jobs left, it draws no randomness,
//! and its caller declares its output length. Without helpers each job runs
//! here when it is submitted; with them a shard's jobs run in submission
//! order on the one helper that holds the shard. Either way every output
//! equals the one this instance computes alone.
#![deny(unsafe_op_in_unsafe_fn)]

#[path = "protocol-hash.rs"]
mod protocol_hash;
#[cfg(not(target_arch = "wasm32"))]
mod simulated;
mod stream;
pub use protocol_hash::ProtocolHash;
use std::{
    cell::Cell,
    collections::VecDeque,
    sync::atomic::{AtomicU64, Ordering},
};
pub use stream::{HashStream, PendingDigest, Sponge};
use zeroize::Zeroizing;

/// The most bytes one job's input or output holds, the bound on one buffer
/// the host copies between instances.
pub const MAXIMUM_JOB_BYTES: usize = 8 << 20;
/// The most parts one job's input joins.
pub const MAXIMUM_JOB_PARTS: usize = 4;
/// The linear memory a helper instance keeps for its running job beside the
/// state its jobs share: the job's input and output, each at most one
/// copied buffer, what it computes, and the transform tables jobs cache.
pub const JOB_MEMORY_BYTES: usize = 32 << 20;
/// The most helpers an operation's worker starts.
pub const MAXIMUM_HELPERS: usize = 8;

/// A job. A helper instance runs the function its kind names.
pub struct Job {
    pub kind: u32,
    pub run: fn(&[u8]) -> Vec<u8>,
}

static SESSIONS: AtomicU64 = AtomicU64::new(1);

/// A number no other caller in this instance receives, which names the
/// state its jobs keep on their shards. Every crate that defines jobs draws
/// from this one sequence.
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
        /// Whether the job has ended, without waiting for it.
        pub fn ended(ticket: u32) -> u32;
        /// Copies bytes of the running job's streamed part from a position;
        /// only a helper's host serves it.
        pub fn read(position: u32, pointer: *mut u8, length: u32);
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

/// Holds the words' little-endian bytes for later jobs; with helpers the
/// host copies them without another copy here.
pub fn share_words(words: &[u64]) -> Shared {
    #[cfg(target_arch = "wasm32")]
    if helpers() > 0 {
        let length = 8 * words.len();
        assert!(length <= MAXIMUM_JOB_BYTES, "Job input bound");
        // WebAssembly memory is little-endian, so the words are their bytes.
        let remote = unsafe { host::share(words.as_ptr().cast(), length as u32) };
        return Shared {
            local: Zeroizing::new(Vec::new()),
            length,
            remote,
        };
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(8 * words.len()));
    for word in words {
        bytes.extend(word.to_le_bytes());
    }
    share(bytes)
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

/// Bytes that the host shared itself, such as records it read from
/// storage, by their handle and length, which the host holds; none for a
/// handle or length that no host with helpers gives, as only such a host
/// shares bytes itself.
#[cfg(target_arch = "wasm32")]
pub fn adopt(remote: u32, length: usize) -> Option<Shared> {
    (helpers() > 0 && remote != 0 && length <= MAXIMUM_JOB_BYTES).then(|| Shared {
        local: Zeroizing::new(Vec::new()),
        length,
        remote,
    })
}

impl Shared {
    /// The bytes' length.
    pub fn length(&self) -> usize {
        #[cfg(target_arch = "wasm32")]
        {
            self.length
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.local.len()
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

/// A part of a job's input: bytes, shared bytes, or shared bytes that the
/// job reads in pieces through [`read`] where it runs instead of receiving
/// them with the rest. A job streams at most one part.
#[derive(Clone, Copy)]
pub enum Part<'a> {
    Bytes(&'a [u8]),
    Shared(&'a Shared),
    Streamed(&'a Shared),
}

/// The running job's streamed part: bytes here, or the length of the part
/// that a helper's host holds.
#[derive(Clone, Copy)]
enum Streamed {
    Absent,
    Local(*const u8, usize),
    #[cfg(target_arch = "wasm32")]
    Remote(usize),
}
thread_local! {static STREAMED: Cell<Streamed> = const { Cell::new(Streamed::Absent) };}

/// Runs the job with the streamed bytes as its streamed part, which the
/// job forgets when it returns or panics.
fn run_streaming(job: &Job, input: &[u8], streamed: Option<&[u8]>) -> Vec<u8> {
    struct Restore(Streamed);
    impl Drop for Restore {
        fn drop(&mut self) {
            STREAMED.with(|current| current.set(self.0));
        }
    }
    let part = streamed.map_or(Streamed::Absent, |bytes| {
        Streamed::Local(bytes.as_ptr(), bytes.len())
    });
    let _restore = Restore(STREAMED.with(|current| current.replace(part)));
    (job.run)(input)
}

/// The length of the running job's streamed part.
pub fn streamed_length() -> usize {
    match STREAMED.with(Cell::get) {
        Streamed::Absent => panic!("The job streams no part"),
        Streamed::Local(_, length) => length,
        #[cfg(target_arch = "wasm32")]
        Streamed::Remote(length) => length,
    }
}

/// Reads the running job's streamed part from the position into the output.
pub fn read(position: usize, output: &mut [u8]) {
    let length = streamed_length();
    assert!(
        position <= length && output.len() <= length - position,
        "Streamed part bound"
    );
    match STREAMED.with(Cell::get) {
        Streamed::Absent => unreachable!(),
        // The submitter keeps the part alive until the job returns.
        Streamed::Local(pointer, length) => output.copy_from_slice(
            &unsafe { std::slice::from_raw_parts(pointer, length) }
                [position..position + output.len()],
        ),
        #[cfg(target_arch = "wasm32")]
        Streamed::Remote(_) => unsafe {
            host::read(position as u32, output.as_mut_ptr(), output.len() as u32)
        },
    }
}

/// The bytes one window of a streamed part holds, and one gathered chunk.
const WINDOW_BYTES: usize = 16 << 10;

/// Fixed-width records of the running job's streamed part. Each region of
/// `span` consecutive records keeps a window of its own, which moves to the
/// record a read names when that record lies outside it, so reads that
/// advance through each region read each byte once.
pub struct StreamedRecords {
    width: usize,
    count: usize,
    span: usize,
    windows: Vec<Window>,
}
struct Window {
    first: usize,
    held: usize,
    bytes: Zeroizing<Vec<u8>>,
}

impl StreamedRecords {
    pub fn new(width: usize, span: usize) -> Self {
        let length = streamed_length();
        assert!(
            width > 0 && span > 0 && length.is_multiple_of(width),
            "Streamed record width"
        );
        let count = length / width;
        let capacity = (WINDOW_BYTES / width).max(1).min(span) * width;
        Self {
            width,
            count,
            span,
            windows: (0..count.div_ceil(span))
                .map(|_| Window {
                    first: 0,
                    held: 0,
                    bytes: Zeroizing::new(vec![0; capacity]),
                })
                .collect(),
        }
    }
    /// The records the part holds.
    pub fn count(&self) -> usize {
        self.count
    }
    /// The bytes of the record of the index.
    pub fn record(&mut self, index: usize) -> &[u8] {
        assert!(index < self.count, "Streamed record bound");
        let width = self.width;
        let region = index / self.span;
        let window = &mut self.windows[region];
        if index < window.first || index >= window.first + window.held {
            let end = ((region + 1) * self.span).min(self.count);
            window.held = (window.bytes.len() / width).min(end - index);
            read(index * width, &mut window.bytes[..window.held * width]);
            window.first = index;
        }
        &window.bytes[(index - window.first) * width..][..width]
    }
}

/// Visits the running job's streamed records that the positions name, each
/// with its position: it sorts the positions by the chunk of records their
/// record lies in, then reads the part one chunk at a time, in order.
pub fn gather(
    width: usize,
    positions: usize,
    index: impl Fn(usize) -> usize,
    mut visit: impl FnMut(usize, &[u8]),
) {
    let length = streamed_length();
    assert!(
        width > 0 && length.is_multiple_of(width) && u32::try_from(positions).is_ok(),
        "Streamed record width"
    );
    let count = length / width;
    let per_chunk = (WINDOW_BYTES / width).max(1);
    let chunks = count.div_ceil(per_chunk);
    // Each chunk's first place in the sorted positions.
    let mut starts = vec![0; chunks + 1];
    for position in 0..positions {
        let record = index(position);
        assert!(record < count, "Streamed record bound");
        starts[record / per_chunk + 1] += 1;
    }
    for chunk in 0..chunks {
        starts[chunk + 1] += starts[chunk];
    }
    let mut next = starts.clone();
    let mut sorted = Zeroizing::new(vec![0_u32; positions]);
    for position in 0..positions {
        let chunk = index(position) / per_chunk;
        sorted[next[chunk]] = position as u32;
        next[chunk] += 1;
    }
    let mut bytes = Zeroizing::new(vec![0; per_chunk * width]);
    for chunk in 0..chunks {
        if starts[chunk] == starts[chunk + 1] {
            continue;
        }
        let first = chunk * per_chunk;
        let held = per_chunk.min(count - first);
        read(first * width, &mut bytes[..held * width]);
        for &position in &sorted[starts[chunk]..starts[chunk + 1]] {
            let position = position as usize;
            let record = index(position) - first;
            visit(position, &bytes[record * width..][..width]);
        }
    }
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
        parts.len() <= MAXIMUM_JOB_PARTS
            && output_length <= MAXIMUM_JOB_BYTES
            && parts
                .iter()
                .filter(|part| matches!(part, Part::Streamed(_)))
                .count()
                <= 1,
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
                    Part::Streamed(shared) => {
                        input_length += shared.length;
                        [2, shared.remote, 0]
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
    // The input's exact length, which no growth copies without zeroizing.
    let length = parts
        .iter()
        .map(|part| match part {
            Part::Bytes(bytes) => bytes.len(),
            Part::Shared(shared) => shared.local.len(),
            Part::Streamed(_) => 0,
        })
        .sum();
    let mut input = Zeroizing::new(Vec::with_capacity(length));
    let mut streamed = None;
    for part in parts {
        match part {
            Part::Bytes(bytes) => input.extend_from_slice(bytes),
            Part::Shared(shared) => input.extend_from_slice(&shared.local),
            Part::Streamed(shared) => streamed = Some(&shared.local[..]),
        }
    }
    assert!(
        input.len() + streamed.map_or(0, <[u8]>::len) <= MAXIMUM_JOB_BYTES,
        "Job input bound"
    );
    #[cfg(not(target_arch = "wasm32"))]
    {
        let helpers = helpers();
        if helpers > 0 {
            let pin = shard.map_or(0, |shard| shard % helpers + 1);
            let streamed = streamed.map(|bytes| Zeroizing::new(bytes.to_vec()));
            return Ticket {
                output: None,
                simulated: Some(simulated::submit(job, pin, input, streamed, output_length)),
            };
        }
    }
    let _ = shard;
    let output = Zeroizing::new(run_streaming(job, &input, streamed));
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
    /// The host's number of a job that has not ended, which the host can
    /// await without this instance waiting; none once it has ended, or when
    /// only this instance waits for it.
    pub fn pending(&self) -> Option<u32> {
        #[cfg(target_arch = "wasm32")]
        if self.remote != 0 && unsafe { host::ended(self.remote) } == 0 {
            return Some(self.remote);
        }
        None
    }
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
    #[cfg(target_arch = "wasm32")]
    use super::{STREAMED, Streamed};
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
    /// Names the length of the next job's streamed part, which the host
    /// holds and serves as the job reads it; zero beyond the bound.
    #[cfg(target_arch = "wasm32")]
    pub fn streamed(length: usize) -> u32 {
        if length > MAXIMUM_JOB_BYTES {
            return 0;
        }
        STREAMED.with(|current| current.set(Streamed::Remote(length)));
        1
    }
    /// Runs the job of the kind among the registries' jobs on the input,
    /// which it then releases with any streamed part. Returns zero on
    /// success and one for a kind no listed job has; the host checks the
    /// output length.
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
        #[cfg(target_arch = "wasm32")]
        STREAMED.with(|current| current.set(Streamed::Absent));
        0
    }
    pub fn output_pointer() -> usize {
        BUFFERS.with(|buffers| buffers.borrow().output.as_ptr() as usize)
    }
    pub fn output_length() -> usize {
        BUFFERS.with(|buffers| buffers.borrow().output.len())
    }
    /// Clears and releases both buffers and forgets any streamed part.
    pub fn clear() {
        BUFFERS.with(|buffers| *buffers.borrow_mut() = Buffers::default());
        #[cfg(target_arch = "wasm32")]
        STREAMED.with(|current| current.set(Streamed::Absent));
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
    // Each input byte, then every streamed byte read in pieces of three.
    fn stream_back(input: &[u8]) -> Vec<u8> {
        let mut output = input.to_vec();
        let length = streamed_length();
        for position in (0..length).step_by(3) {
            let mut piece = vec![0; 3.min(length - position)];
            read(position, &mut piece);
            output.extend(piece);
        }
        output
    }
    static STREAM_BACK: Job = Job {
        kind: 10,
        run: stream_back,
    };
    // The streamed part's two-byte records at the indices that the input's
    // two-byte words name, read in order through windows over regions of
    // three records, then gathered in the indices' reverse order.
    fn read_records(input: &[u8]) -> Vec<u8> {
        let indices: Vec<usize> = input
            .chunks_exact(2)
            .map(|pair| usize::from(u16::from_le_bytes([pair[0], pair[1]])))
            .collect();
        let mut records = StreamedRecords::new(2, 3);
        let mut output: Vec<u8> = indices
            .iter()
            .flat_map(|index| records.record(*index).to_vec())
            .collect();
        let mut gathered = vec![[0; 2]; indices.len()];
        gather(
            2,
            indices.len(),
            |position| indices[indices.len() - 1 - position],
            |position, record| gathered[position].copy_from_slice(record),
        );
        output.extend(gathered.into_iter().flatten());
        output
    }
    static READ_RECORDS: Job = Job {
        kind: 12,
        run: read_records,
    };
    // Reads one byte beyond the streamed part.
    fn read_beyond(_: &[u8]) -> Vec<u8> {
        let mut byte = [0];
        read(streamed_length(), &mut byte);
        byte.to_vec()
    }
    static READ_BEYOND: Job = Job {
        kind: 11,
        run: read_beyond,
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
    fn streamed_parts_join_no_input_and_are_read_in_pieces_within_their_bound() {
        let streamed = share_words(&[0x0807_0605_0403_0201, 0x0a09]);
        let shared = share(Zeroizing::new(vec![20, 21]));
        let output = submit(
            &STREAM_BACK,
            Some(2),
            &[
                Part::Bytes(&[30]),
                Part::Streamed(&streamed),
                Part::Shared(&shared),
            ],
            19,
        )
        .wait();
        assert_eq!(
            output.to_vec(),
            [30, 20, 21, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0]
        );
        // A read beyond the part fails the job, and a job streams at most
        // one part.
        assert!(
            std::panic::catch_unwind(
                || submit(&READ_BEYOND, None, &[Part::Streamed(&shared)], 1).wait()
            )
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| submit(
                &STREAM_BACK,
                None,
                &[Part::Streamed(&shared), Part::Streamed(&shared)],
                4
            ))
            .is_err()
        );
        // A job without a streamed part cannot read one.
        assert!(std::panic::catch_unwind(|| submit(&READ_BEYOND, None, &[], 1).wait()).is_err());
    }

    #[test]
    fn streamed_records_read_through_windows_or_gathered_by_chunk_equal_the_part() {
        // Twenty thousand records, each its index's two bytes, which a
        // gather reads in three chunks.
        let part: Vec<u8> = (0..20_000_u16).flat_map(u16::to_le_bytes).collect();
        let streamed = share(Zeroizing::new(part));
        // Forward and backward within and across regions and chunks.
        let indices = [0_u16, 1, 4, 3, 19_999, 2, 2, 8_200, 16_384, 8_191, 0];
        let input: Vec<u8> = indices
            .iter()
            .flat_map(|index| index.to_le_bytes())
            .collect();
        let mut expected = input.clone();
        expected.extend(indices.iter().rev().flat_map(|index| index.to_le_bytes()));
        let output = submit(
            &READ_RECORDS,
            None,
            &[Part::Bytes(&input), Part::Streamed(&streamed)],
            2 * input.len(),
        )
        .wait();
        assert_eq!(output.to_vec(), expected);
        // A record beyond the part fails the job, and the records' width
        // must divide the part.
        assert!(
            std::panic::catch_unwind(|| submit(
                &READ_RECORDS,
                None,
                &[
                    Part::Bytes(&20_000_u16.to_le_bytes()),
                    Part::Streamed(&streamed)
                ],
                4
            )
            .wait())
            .is_err()
        );
        let odd = share(Zeroizing::new(vec![1, 2, 3]));
        assert!(
            std::panic::catch_unwind(|| submit(
                &READ_RECORDS,
                None,
                &[Part::Bytes(&[0, 0]), Part::Streamed(&odd)],
                4
            )
            .wait())
            .is_err()
        );
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
