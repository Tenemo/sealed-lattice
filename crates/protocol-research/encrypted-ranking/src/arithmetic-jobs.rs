//! The arithmetic's transforms, keyed products and per-range lifts as jobs
//! that helper instances of the participant module run on their own. A job
//! names the profile, the ring degree and a set of primes, one prime or a
//! lift, so any instance rebuilds the same arithmetic from public
//! parameters. A set holds every helper-count-th prime from its first, or
//! without helpers consecutive primes, as many as keep its job within the
//! job bound, and its jobs, like those of each of its primes, run on the one
//! helper that holds its transform tables and the transformed polynomials
//! its sessions keep there.
use super::{Arithmetic, Polynomial, shared, word_arithmetic::widening_multiply};
use parallel_work::{
    Job, MAXIMUM_JOB_BYTES, Part, Pipeline, Shared, Ticket, session, share, share_words, submit,
};
use protocol_foundations::{foundation::CanonicalItem, identity::IdentityHasher};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    iter::StepBy,
    ops::Range,
    rc::Rc,
};
use supported_profile::Profile;
use zeroize::Zeroizing;

/// Keeps the centered residues of its streamed polynomial modulo each prime
/// of a set, transformed, as one of its session's sources.
pub static SOURCES: Job = Job {
    kind: 0x0306,
    run: sources,
};
/// The products of two of a session's sources modulo each prime of a set,
/// transformed back; drops the sources whose last product it is.
pub static TENSOR: Job = Job {
    kind: 0x0307,
    run: tensor,
};
/// The centered residues of its streamed key modulo each prime of a set,
/// transformed: each prime's key record after its identity.
pub static RECORDS: Job = Job {
    kind: 0x0308,
    run: records,
};
/// Keeps each gadget digit of its streamed polynomial's canonical
/// coefficients modulo each prime of a set, transformed, for its session's
/// keyed products.
pub static DIGITS: Job = Job {
    kind: 0x0309,
    run: digits,
};
/// The sum of a session's digits modulo a prime times one group's streamed
/// key records, transformed back, after the records' identities; the last
/// group drops the digits.
pub static KEYED: Job = Job {
    kind: 0x030a,
    run: keyed,
};
/// The canonical coefficients of a range of positions from their residues.
pub static LIFT: Job = Job {
    kind: 0x0304,
    run: lift,
};
/// Drops a session's digits modulo a prime, which a keyed product that ends
/// before its last job of that prime leaves kept.
pub static FORGET: Job = Job {
    kind: 0x030b,
    run: forget,
};
pub static JOBS: [&Job; 7] = [&SOURCES, &TENSOR, &RECORDS, &DIGITS, &KEYED, &LIFT, &FORGET];

const HEADER_BYTES: usize = 16;
const SET_BYTES: usize = 8;
/// The positions one lift job reconstructs.
const LIFT_POSITIONS: usize = 2048;
/// The coefficients a job reads of a streamed polynomial at once.
const STREAMED_COEFFICIENTS: usize = 1024;
/// The positions whose key words a keyed product's job reads and multiplies
/// at once, by which the job's bytes are bounded in every build.
const KEYED_POSITIONS: usize = 4096;
/// The positions a keyed product's job takes at once: tests take a few
/// blocks of their small degree, within the bytes the job is bounded by.
#[cfg(not(test))]
const KEYED_BLOCK: usize = KEYED_POSITIONS;
#[cfg(test)]
const KEYED_BLOCK: usize = 4;
const _: () = assert!(KEYED_BLOCK <= KEYED_POSITIONS);
/// The identity of one key record: a key polynomial's transformed residues
/// modulo one prime, which the evaluation's working storage holds.
const EVALUATION_KEY_DOMAIN: &str = "sealed-lattice/evaluation-key-work/v1";
const IDENTITY_BYTES: usize = 64;
/// The key groups one keyed product multiplies.
pub(super) const KEYED_GROUPS: usize = 2;
/// A product's flags that drop its left source, its right source, or a
/// square's one source.
pub(super) const DROP_LEFT: u32 = 1;
pub(super) const DROP_RIGHT: u32 = 2;

thread_local! {
    /// The transformed polynomials each session keeps modulo each prime
    /// whose jobs run here, by position: its sources, or a polynomial's
    /// digits.
    static KEPT: RefCell<HashMap<(u64, usize, usize), Vec<u64>>> = RefCell::default();
}

/// The lift of a product: of a plaintext or secret product, of an external
/// product, or of a ciphertext tensor.
#[derive(Clone, Copy)]
pub(super) enum Lifted {
    Key = 0,
    External = 1,
    Tensor = 2,
}

/// The primes below a count that one set holds: every stride-th from the
/// first.
#[derive(Clone, Copy)]
pub(super) struct PrimeSet {
    first: usize,
    stride: usize,
    count: usize,
}
impl PrimeSet {
    pub(super) fn primes(self) -> StepBy<Range<usize>> {
        (self.first..self.count).step_by(self.stride)
    }
    fn len(self) -> usize {
        self.primes().len()
    }
}
/// The most primes one set holds: a set job's output holds at most a key
/// record and its identity for each prime, within the job bound.
fn set_primes(degree: usize) -> usize {
    MAXIMUM_JOB_BYTES / (IDENTITY_BYTES + 8 * degree)
}
/// The most of the count's first primes that one of their sets holds with
/// the helpers.
fn set_length(count: usize, degree: usize, helpers: usize) -> usize {
    count.div_ceil(helpers.max(1)).min(set_primes(degree))
}
/// The sets that hold the first primes of the count with the helpers: each
/// helper's primes, every helper-count-th from its first, or without
/// helpers every prime, split into as few sets as hold at most a set's
/// primes. A set's jobs run on the helper of its first prime.
fn prime_sets(count: usize, degree: usize, helpers: usize) -> Vec<PrimeSet> {
    let stride = helpers.max(1);
    let span = set_primes(degree) * stride;
    (0..stride.min(count))
        .flat_map(|class| {
            (class..count).step_by(span).map(move |first| PrimeSet {
                first,
                stride,
                count: (first + span).min(count),
            })
        })
        .collect()
}

/// Where a key record belongs: the evaluation's program, its cache and the
/// ordinal of a key or of a group's first key.
#[derive(Clone, Copy)]
pub(super) struct RecordContext {
    pub(super) program: [u8; 64],
    pub(super) cache: u32,
    pub(super) ordinal: usize,
}
impl RecordContext {
    const BYTES: usize = 72;
    fn write(&self, output: &mut Vec<u8>) {
        output.extend(self.program);
        output.extend(self.cache.to_le_bytes());
        output.extend((self.ordinal as u32).to_le_bytes());
    }
    fn read(bytes: &[u8]) -> Self {
        Self {
            program: bytes[..64].try_into().unwrap(),
            cache: u32::from_le_bytes(bytes[64..68].try_into().unwrap()),
            ordinal: number(&bytes[68..]),
        }
    }
}
/// The hasher of a key record's identity: its bytes of the length under
/// the program, the cache, the key's ordinal and the prime.
fn record_hasher(
    context: &RecordContext,
    ordinal: usize,
    prime: usize,
    length: usize,
) -> IdentityHasher {
    IdentityHasher::local(
        EVALUATION_KEY_DOMAIN,
        &[
            CanonicalItem::hash512(context.program),
            CanonicalItem::unsigned64(u64::from(context.cache)),
            CanonicalItem::unsigned64(ordinal as u64),
            CanonicalItem::unsigned64(prime as u64),
        ],
        length,
    )
    .expect("Record identity")
}
/// A key record's identity.
fn record_identity(
    context: &RecordContext,
    ordinal: usize,
    prime: usize,
    record: &[u8],
) -> [u8; 64] {
    let mut hasher = record_hasher(context, ordinal, prime, record.len());
    hasher.absorb(record).expect("Record identity");
    hasher.finish().expect("Record identity")
}

fn number(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
}
fn session_number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}
fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}
fn words(bytes: &[u8]) -> Vec<u64> {
    bytes.chunks_exact(8).map(word).collect()
}
fn extend(output: &mut Vec<u8>, values: &[u64]) {
    let start = output.len();
    output.resize(start + 8 * values.len(), 0);
    for (bytes, value) in output[start..].chunks_exact_mut(8).zip(values) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
}
// A job's arithmetic, its prime or lift, and the bytes that follow them.
fn read(input: &[u8]) -> (Rc<Arithmetic>, usize, &[u8]) {
    let profile = Profile::new(number(input), number(&input[4..])).expect("Job profile");
    (
        shared(profile, number(&input[8..])),
        number(&input[12..]),
        &input[HEADER_BYTES..],
    )
}
// A set job's arithmetic, its prime set, and the bytes that follow them.
fn read_set(input: &[u8]) -> (Rc<Arithmetic>, PrimeSet, &[u8]) {
    let (arithmetic, first, rest) = read(input);
    let set = PrimeSet {
        first,
        stride: number(rest),
        count: number(&rest[4..]),
    };
    assert!(
        set.stride > 0 && set.count <= arithmetic.reductions.len(),
        "Prime set"
    );
    (arithmetic, set, &rest[SET_BYTES..])
}
// The jobs a stage keeps running: one for each helper and one more.
fn window() -> usize {
    parallel_work::helpers() + 1
}

fn sources(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let (session, slot) = (session_number(rest), number(&rest[8..]));
    let residues = arithmetic.set_residues(set);
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for (prime, mut residues) in set.primes().zip(residues) {
            arithmetic.transform(prime).forward(&mut residues);
            assert!(
                kept.insert((session, prime, slot), residues).is_none(),
                "Kept source"
            );
        }
    });
    Vec::new()
}
fn tensor(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let session = session_number(rest);
    let [left, right, drops] = std::array::from_fn(|index| number(&rest[8 + 4 * index..]));
    let drops = drops as u32;
    let mut output = Vec::with_capacity(8 * arithmetic.degree * set.len());
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for prime in set.primes() {
            let reduction = &arithmetic.reductions[prime];
            // A dropped left source becomes the product.
            let mut product = if drops & DROP_LEFT != 0 || (left == right && drops != 0) {
                kept.remove(&(session, prime, left)).expect("Kept source")
            } else {
                kept[&(session, prime, left)].clone()
            };
            if left == right {
                for value in &mut product {
                    *value = reduction.multiply(*value, *value);
                }
            } else {
                for (value, other) in product.iter_mut().zip(&kept[&(session, prime, right)]) {
                    *value = reduction.multiply(*value, *other);
                }
                if drops & DROP_RIGHT != 0 {
                    kept.remove(&(session, prime, right));
                }
            }
            arithmetic.transform(prime).backward(&mut product);
            extend(&mut output, &product);
        }
    });
    output
}
fn records(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let context = RecordContext::read(rest);
    let residues = arithmetic.set_residues(set);
    let record_bytes = 8 * arithmetic.degree;
    let mut output = Vec::with_capacity(set.len() * (IDENTITY_BYTES + record_bytes));
    for (prime, mut residues) in set.primes().zip(residues) {
        arithmetic.transform(prime).forward(&mut residues);
        let start = output.len();
        output.resize(start + IDENTITY_BYTES, 0);
        extend(&mut output, &residues);
        let identity = record_identity(
            &context,
            context.ordinal,
            prime,
            &output[start + IDENTITY_BYTES..],
        );
        output[start..start + IDENTITY_BYTES].copy_from_slice(&identity);
    }
    output
}
fn digits(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let session = session_number(rest);
    let digits = arithmetic.set_digits(set);
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for (prime, digits) in set.primes().zip(digits) {
            let transform = arithmetic.transform(prime);
            for (digit, mut residues) in digits.into_iter().enumerate() {
                transform.forward(&mut residues);
                assert!(
                    kept.insert((session, prime, digit), residues).is_none(),
                    "Kept digits"
                );
            }
        }
    });
    Vec::new()
}
fn keyed(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let (session, last) = (session_number(rest), number(&rest[8..]) != 0);
    let context = RecordContext::read(&rest[12..]);
    let (degree, gadget_length) = (arithmetic.degree, arithmetic.gadget_length);
    let record_bytes = 8 * degree;
    assert_eq!(
        parallel_work::streamed_length(),
        record_bytes * gadget_length
    );
    let reduction = &arithmetic.reductions[prime];
    // Each record's identity absorbs its words as the job reads them.
    let mut hashers: Vec<IdentityHasher> = (0..gadget_length)
        .map(|digit| record_hasher(&context, context.ordinal + digit, prime, record_bytes))
        .collect();
    let mut sum = vec![0u64; degree];
    // A position's products of a digit, below a prime below 2^58, and a
    // key word, below 2^64 even in a changed record, are below 2^122, so at
    // most 64 of them sum below 2^128 and each position reduces once. A
    // changed record then fails only its identity.
    assert!(gadget_length <= 64);
    let mut products = vec![0u128; KEYED_BLOCK.min(degree)];
    let mut words = vec![0u8; 8 * products.len()];
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for first in (0..degree).step_by(products.len()) {
            let count = products.len().min(degree - first);
            products.fill(0);
            for (digit, hasher) in hashers.iter_mut().enumerate() {
                let words = &mut words[..8 * count];
                parallel_work::read(digit * record_bytes + 8 * first, words);
                hasher.absorb(words).expect("Record identity");
                let digits = &kept[&(session, prime, digit)][first..first + count];
                for ((product, digit), key) in
                    products.iter_mut().zip(digits).zip(words.chunks_exact(8))
                {
                    let (low, high) = widening_multiply(*digit, word(key));
                    *product += (u128::from(high) << 64) | u128::from(low);
                }
            }
            for (value, product) in sum[first..first + count].iter_mut().zip(&products) {
                *value = reduction.reduce_wide(*product);
            }
        }
        if last {
            for digit in 0..gadget_length {
                kept.remove(&(session, prime, digit));
            }
        }
    });
    drop((products, words));
    let mut output = Vec::with_capacity(IDENTITY_BYTES * gadget_length + 8 * degree);
    for hasher in hashers {
        output.extend(hasher.finish().expect("Record identity"));
    }
    arithmetic.transform(prime).backward(&mut sum);
    extend(&mut output, &sum);
    output
}
fn forget(input: &[u8]) -> Vec<u8> {
    let (session, prime) = (session_number(input), number(&input[8..]));
    KEPT.with(|kept| {
        kept.borrow_mut()
            .retain(|(kept_session, kept_prime, _), _| {
                (*kept_session, *kept_prime) != (session, prime)
            });
    });
    Vec::new()
}
fn lift(input: &[u8]) -> Vec<u8> {
    let (arithmetic, lifted, rest) = read(input);
    let lift = arithmetic.lift(lifted);
    let positions = number(rest);
    let values = words(&rest[4..]);
    assert_eq!(values.len(), lift.count * positions);
    let residues: Vec<&[u64]> = values.chunks_exact(positions).collect();
    let mut coefficients = vec![0u64; positions * arithmetic.words];
    for (position, coefficient) in coefficients.chunks_exact_mut(arithmetic.words).enumerate() {
        lift.coefficient(
            &residues,
            position,
            &arithmetic.reductions,
            &arithmetic.wide,
            coefficient,
        );
    }
    let mut output = Vec::with_capacity(8 * coefficients.len());
    extend(&mut output, &coefficients);
    output
}

/// Polynomials' transformed residues modulo the first primes of a count,
/// which the instances that run those primes' jobs keep until their last
/// product.
pub(super) struct Sources {
    session: u64,
    count: usize,
    started: Vec<Ticket>,
}

/// The prime and group of a keyed product's job of the index among the
/// jobs of the primes' two groups. The jobs come in batches of as many
/// primes as there are helpers, each batch's first group before its second,
/// so that each helper, which holds one prime of a batch, has a job while
/// the batch runs; without helpers each prime's groups come in turn.
fn keyed_job(index: usize, primes: usize, helpers: usize) -> (usize, usize) {
    let batch = helpers.max(1);
    let first = index / (KEYED_GROUPS * batch) * batch;
    let held = batch.min(primes - first);
    let within = index - KEYED_GROUPS * first;
    (first + within % held, within / held)
}

/// The key records a keyed product needs next: one group's keys from the
/// first ordinal, modulo one prime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordRequest {
    pub first: usize,
    pub count: usize,
    pub prime: usize,
}

/// A keyed product in progress: the sums of a polynomial's gadget digits
/// times each gadget coordinate's key of two groups, one job for each prime
/// and group in the order of [`keyed_job`], each over the records of its
/// group's keys modulo its prime, which the caller delivers. Each prime's
/// digits are kept from just before its first group's job to its last
/// group's.
pub(super) struct KeyedProduct {
    session: u64,
    context: RecordContext,
    // The polynomial until the last prime's digits have started.
    polynomial: Option<Shared>,
    started: Vec<Ticket>,
    requested: usize,
    delivered: Vec<u8>,
    // The pending request's records when the host shared them itself.
    shared: Option<Shared>,
    running: VecDeque<(usize, Ticket)>,
    sums: [Vec<Vec<u64>>; KEYED_GROUPS],
    // The primes whose digits have started and whose last group's job has
    // not.
    kept: Vec<usize>,
}
impl Drop for KeyedProduct {
    // A product that ends before its last group's job of a prime, as after
    // a refusal, drops that prime's digits where they are kept, after its
    // jobs there.
    fn drop(&mut self) {
        for prime in self.kept.drain(..) {
            let mut input = self.session.to_le_bytes().to_vec();
            input.extend((prime as u32).to_le_bytes());
            submit(&FORGET, Some(prime), &[Part::Bytes(&input)], 0);
        }
    }
}
/// A keyed product's next need: the records of a request, the end of a
/// job the host awaits, by the host's number, or both groups' sums modulo
/// each prime, which the caller lifts.
pub(super) enum Keyed {
    Records(RecordRequest),
    Waiting(u32),
    Done([Vec<Vec<u64>>; KEYED_GROUPS]),
}

impl KeyedProduct {
    /// The ordinal of its first group's first key.
    pub(super) fn first_ordinal(&self) -> usize {
        self.context.ordinal
    }
    /// The index of its pending request.
    pub(super) fn requested(&self) -> usize {
        self.requested
    }
}

impl Arithmetic {
    // The start of a job's input: the profile, the degree and a prime or
    // a lift.
    fn header(&self, index: usize) -> Vec<u8> {
        let mut header = Vec::with_capacity(HEADER_BYTES);
        for value in [
            self.profile.participants(),
            self.profile.options(),
            self.degree,
            index,
        ] {
            header.extend((value as u32).to_le_bytes());
        }
        header
    }
    // The start of a prime set's job: its header and the set.
    fn set_header(&self, set: PrimeSet) -> Vec<u8> {
        let mut header = self.header(set.first);
        header.extend((set.stride as u32).to_le_bytes());
        header.extend((set.count as u32).to_le_bytes());
        header
    }
    fn shared_polynomial(&self, polynomial: &[u64]) -> Shared {
        assert_eq!(polynomial.len(), self.polynomial_words());
        share_words(polynomial)
    }
    /// Calls the function with the little-endian words of each coefficient
    /// of the job's streamed polynomial, in order, reading a run of them at
    /// a time.
    pub(super) fn streamed_coefficients(&self, mut use_coefficient: impl FnMut(&[u8])) {
        let coefficient_bytes = 8 * self.words;
        assert_eq!(
            parallel_work::streamed_length(),
            coefficient_bytes * self.degree
        );
        let run = STREAMED_COEFFICIENTS.min(self.degree);
        let mut buffer = Zeroizing::new(vec![0u8; coefficient_bytes * run]);
        for first in (0..self.degree).step_by(run) {
            parallel_work::read(first * coefficient_bytes, &mut buffer);
            for coefficient in buffer.chunks_exact(coefficient_bytes) {
                use_coefficient(coefficient);
            }
        }
    }
    /// The most memory one job holds beside the polynomials it keeps, with
    /// the helpers: a set's products and a product being formed, a set's
    /// residues beside its records, a keyed product's sum and output beside
    /// one block of its key words and their products, or a lift's residues
    /// and coefficients, each beside one run of a streamed polynomial.
    pub(super) fn job_bytes(&self, helpers: usize) -> usize {
        let residue_bytes = 8 * self.degree;
        let held = |count: usize| set_length(count, self.degree, helpers);
        let positions = LIFT_POSITIONS.min(self.degree);
        let jobs = [
            (held(self.tensor_primes()) + 1) * residue_bytes,
            held(self.external_primes) * (2 * residue_bytes + IDENTITY_BYTES),
            2 * residue_bytes
                + self.gadget_length * IDENTITY_BYTES
                + 24 * KEYED_POSITIONS.min(self.degree),
            2 * 8 * positions * (self.tensor_primes() + self.words),
        ];
        HEADER_BYTES
            + SET_BYTES
            + RecordContext::BYTES
            + 8 * self.words * STREAMED_COEFFICIENTS.min(self.degree)
            + jobs.into_iter().max().unwrap()
    }
    /// The most bytes that the instance submitting jobs to the helpers
    /// holds at once to move one job's data beside the products or sums it
    /// keeps: for a product modulo the count's first primes a set's
    /// products, or for a keyed product one job's identities and sum,
    /// copied out of the host, or a lift range's residues modulo the
    /// count's primes, copied in, beside its coefficients, copied out and
    /// decoded.
    pub(super) fn transfer_bytes(&self, count: usize, keyed: bool, helpers: usize) -> usize {
        let residue_bytes = 8 * self.degree;
        let output = if keyed {
            IDENTITY_BYTES * self.gadget_length + residue_bytes
        } else {
            set_length(count, self.degree, helpers) * residue_bytes
        };
        let positions = LIFT_POSITIONS.min(self.degree);
        output.max(HEADER_BYTES + 4 + 8 * positions * (count + 2 * self.words))
    }
    /// The most bytes that the instance submitting a key's record jobs to
    /// the helpers holds at once to copy a set's records and identities out
    /// of the host.
    pub(super) fn records_transfer_bytes(&self, helpers: usize) -> usize {
        set_length(self.external_primes, self.degree, helpers) * (IDENTITY_BYTES + 8 * self.degree)
    }
    /// Sources modulo the first primes of the count.
    pub(super) fn sources(&self, count: usize) -> Sources {
        Sources {
            session: session(),
            count,
            started: Vec::new(),
        }
    }
    /// Keeps the polynomial's transformed residues as the sources' slot.
    pub(super) fn keep_source(&self, sources: &mut Sources, slot: usize, polynomial: &[u64]) {
        let shared = self.shared_polynomial(polynomial);
        for set in prime_sets(sources.count, self.degree, parallel_work::helpers()) {
            let mut input = self.set_header(set);
            input.extend(sources.session.to_le_bytes());
            input.extend((slot as u32).to_le_bytes());
            sources.started.push(submit(
                &SOURCES,
                Some(set.first),
                &[Part::Bytes(&input), Part::Streamed(&shared)],
                0,
            ));
        }
    }
    /// The products of two slots' sources modulo each prime, transformed
    /// back, in prime order. The flags drop the sources whose last product
    /// this is.
    pub(super) fn source_products(
        &self,
        sources: &mut Sources,
        left: usize,
        right: usize,
        drops: u32,
    ) -> Vec<Vec<u64>> {
        for ticket in sources.started.drain(..) {
            assert!(ticket.wait().is_empty());
        }
        let sets = prime_sets(sources.count, self.degree, parallel_work::helpers());
        let tickets: Vec<Ticket> = sets
            .iter()
            .map(|set| {
                let mut input = self.set_header(*set);
                input.extend(sources.session.to_le_bytes());
                for value in [left as u32, right as u32, drops] {
                    input.extend(value.to_le_bytes());
                }
                submit(
                    &TENSOR,
                    Some(set.first),
                    &[Part::Bytes(&input)],
                    8 * self.degree * set.len(),
                )
            })
            .collect();
        let mut products = vec![Vec::new(); sources.count];
        for (set, ticket) in sets.into_iter().zip(tickets) {
            let output = ticket.wait();
            for (prime, bytes) in set.primes().zip(output.chunks_exact(8 * self.degree)) {
                products[prime] = words(bytes);
            }
        }
        products
    }
    /// The product of two polynomials, lifted from the key primes, or from
    /// every prime with the tensor's plaintext rescaling.
    pub(super) fn multiply(&self, left: &[u64], right: &[u64], tensor: bool) -> Polynomial {
        let (count, lifted) = if tensor {
            (self.tensor_primes(), Lifted::Tensor)
        } else {
            (self.key_primes, Lifted::Key)
        };
        let mut sources = self.sources(count);
        self.keep_source(&mut sources, 0, left);
        self.keep_source(&mut sources, 1, right);
        let products = self.source_products(&mut sources, 0, 1, DROP_LEFT | DROP_RIGHT);
        self.lifted(&products, lifted)
    }
    /// The key's record modulo each external-product prime, in prime order,
    /// and each record's identity.
    pub(super) fn key_records(
        &self,
        key: &[u64],
        context: RecordContext,
    ) -> (Vec<[u8; 64]>, Vec<Vec<u8>>) {
        let shared = self.shared_polynomial(key);
        let sets = prime_sets(self.external_primes, self.degree, parallel_work::helpers());
        let record_bytes = 8 * self.degree;
        let tickets: Vec<Ticket> = sets
            .iter()
            .map(|set| {
                let mut input = self.set_header(*set);
                context.write(&mut input);
                submit(
                    &RECORDS,
                    Some(set.first),
                    &[Part::Bytes(&input), Part::Streamed(&shared)],
                    set.len() * (IDENTITY_BYTES + record_bytes),
                )
            })
            .collect();
        drop(shared);
        let mut identities = vec![[0; 64]; self.external_primes];
        let mut records = vec![Vec::new(); self.external_primes];
        for (set, ticket) in sets.into_iter().zip(tickets) {
            let output = ticket.wait();
            for (prime, bytes) in set
                .primes()
                .zip(output.chunks_exact(IDENTITY_BYTES + record_bytes))
            {
                identities[prime] = bytes[..IDENTITY_BYTES].try_into().unwrap();
                records[prime] = bytes[IDENTITY_BYTES..].to_vec();
            }
        }
        (identities, records)
    }
    /// Starts the keyed product of the value with the two groups of keys
    /// from the context's ordinal.
    pub(super) fn keyed_product(&self, value: &[u64], context: RecordContext) -> KeyedProduct {
        KeyedProduct {
            session: session(),
            context,
            polynomial: Some(self.shared_polynomial(value)),
            started: Vec::new(),
            requested: 0,
            delivered: Vec::new(),
            shared: None,
            running: VecDeque::new(),
            sums: std::array::from_fn(|_| vec![Vec::new(); self.external_primes]),
            kept: Vec::new(),
        }
    }
    /// The records a keyed product's next job needs.
    fn keyed_request(&self, product: &KeyedProduct) -> RecordRequest {
        self.keyed_request_at(product.context.ordinal, product.requested)
    }
    /// The records that the job of the index needs in a keyed product whose
    /// first group's first key has the ordinal.
    fn keyed_request_at(&self, ordinal: usize, index: usize) -> RecordRequest {
        let (prime, group) = keyed_job(index, self.external_primes, parallel_work::helpers());
        RecordRequest {
            first: ordinal + group * self.gadget_length,
            count: self.gadget_length,
            prime,
        }
    }
    /// The requests of such a keyed product from the job of the index on.
    pub(super) fn keyed_requests_from(
        &self,
        ordinal: usize,
        index: usize,
    ) -> impl Iterator<Item = RecordRequest> + '_ {
        (index..KEYED_GROUPS * self.external_primes)
            .map(move |index| self.keyed_request_at(ordinal, index))
    }
    /// Takes the next record of the keyed product's pending request; false
    /// when it is not that record.
    pub(super) fn deliver_record(
        &self,
        product: &mut KeyedProduct,
        ordinal: usize,
        prime: usize,
        record: &[u8],
    ) -> bool {
        // Once every job has requested its records, no request is left.
        if product.requested == KEYED_GROUPS * self.external_primes || product.shared.is_some() {
            return false;
        }
        let record_bytes = 8 * self.degree;
        let request = self.keyed_request(product);
        let received = product.delivered.len() / record_bytes;
        if prime != request.prime
            || received == request.count
            || ordinal != request.first + received
            || record.len() != record_bytes
        {
            return false;
        }
        if product.delivered.is_empty() {
            product
                .delivered
                .reserve_exact(request.count * record_bytes);
        }
        product.delivered.extend_from_slice(record);
        true
    }
    /// Takes the pending request's records, which the host shared itself
    /// one after another; false when they are not that whole request's
    /// records or a record of it was delivered.
    pub(super) fn deliver_shared_records(
        &self,
        product: &mut KeyedProduct,
        request: RecordRequest,
        records: Shared,
    ) -> bool {
        if product.requested == KEYED_GROUPS * self.external_primes
            || request != self.keyed_request(product)
            || !product.delivered.is_empty()
            || product.shared.is_some()
            || records.length() != request.count * 8 * self.degree
        {
            return false;
        }
        product.shared = Some(records);
        true
    }
    /// Starts the job of a complete delivery and takes the outputs beyond
    /// the window. Returns the next request, the oldest such job while it
    /// runs when the host can await it, or both groups' sums once every job
    /// has ended. Fails when a job's records are not those whose identities
    /// the caller holds, by ordinal and prime.
    pub(super) fn advance_keyed(
        &self,
        product: &mut KeyedProduct,
        identities: &[Vec<[u8; 64]>],
    ) -> Result<Keyed, ()> {
        let total = KEYED_GROUPS * self.external_primes;
        let record_bytes = 8 * self.degree;
        if product.requested < total
            && (product.shared.is_some()
                || product.delivered.len() == self.gadget_length * record_bytes)
        {
            let request = self.keyed_request(product);
            let (_, group) = keyed_job(
                product.requested,
                self.external_primes,
                parallel_work::helpers(),
            );
            if group == 0
                && let Some(polynomial) = &product.polynomial
            {
                let set = PrimeSet {
                    first: request.prime,
                    stride: 1,
                    count: request.prime + 1,
                };
                let mut input = self.set_header(set);
                input.extend(product.session.to_le_bytes());
                product.started.push(submit(
                    &DIGITS,
                    Some(request.prime),
                    &[Part::Bytes(&input), Part::Streamed(polynomial)],
                    0,
                ));
                product.kept.push(request.prime);
            }
            if group + 1 == KEYED_GROUPS {
                product.kept.retain(|prime| *prime != request.prime);
            }
            let mut input = self.header(request.prime);
            input.extend(product.session.to_le_bytes());
            input.extend(u32::from(group + 1 == KEYED_GROUPS).to_le_bytes());
            RecordContext {
                ordinal: request.first,
                ..product.context
            }
            .write(&mut input);
            let records = product
                .shared
                .take()
                .unwrap_or_else(|| share(Zeroizing::new(std::mem::take(&mut product.delivered))));
            let ticket = submit(
                &KEYED,
                Some(request.prime),
                &[Part::Bytes(&input), Part::Streamed(&records)],
                IDENTITY_BYTES * self.gadget_length + record_bytes,
            );
            drop(records);
            product.running.push_back((product.requested, ticket));
            product.requested += 1;
            if product.requested == total {
                product.polynomial = None;
            }
        }
        let window = if product.requested == total {
            0
        } else {
            window()
        };
        while product.running.len() > window {
            if let Some(number) = product.running[0].1.pending() {
                return Ok(Keyed::Waiting(number));
            }
            let (index, ticket) = product.running.pop_front().unwrap();
            let output = ticket.wait();
            let (prime, group) = keyed_job(index, self.external_primes, parallel_work::helpers());
            let first = product.context.ordinal + group * self.gadget_length;
            let (held, sum) = output.split_at(IDENTITY_BYTES * self.gadget_length);
            for (digit, identity) in held.chunks_exact(IDENTITY_BYTES).enumerate() {
                if identities
                    .get(first + digit)
                    .and_then(|record| record.get(prime))
                    .map(<[u8; 64]>::as_slice)
                    != Some(identity)
                {
                    return Err(());
                }
            }
            product.sums[group][prime] = words(sum);
        }
        if product.requested < total {
            return Ok(Keyed::Records(self.keyed_request(product)));
        }
        for ticket in product.started.drain(..) {
            assert!(ticket.wait().is_empty());
        }
        Ok(Keyed::Done(std::mem::take(&mut product.sums)))
    }
    /// The canonical coefficients that the residues modulo the lift's primes
    /// determine.
    pub(super) fn lifted(&self, residues: &[impl AsRef<[u64]>], lifted: Lifted) -> Polynomial {
        let mut output = self.zero();
        self.lift_ranges(residues, lifted, |start, coefficients| {
            output[start..start + coefficients.len()].copy_from_slice(coefficients);
        });
        output
    }
    /// Adds to the target the canonical coefficients that the residues
    /// modulo the lift's primes determine, one lifted range at a time.
    pub(super) fn add_lifted(
        &self,
        target: &mut Polynomial,
        residues: &[impl AsRef<[u64]>],
        lifted: Lifted,
    ) {
        self.lift_ranges(residues, lifted, |start, coefficients| {
            self.add(&mut target[start..start + coefficients.len()], coefficients);
        });
    }
    // Lifts each range of positions in jobs and hands each range's
    // coefficient words to the function with the offset of its first word.
    fn lift_ranges(
        &self,
        residues: &[impl AsRef<[u64]>],
        lifted: Lifted,
        mut use_range: impl FnMut(usize, &[u64]),
    ) {
        let lift = self.lift(lifted as usize);
        assert_eq!(residues.len(), lift.count);
        let positions = LIFT_POSITIONS.min(self.degree);
        let mut place = |first: usize, bytes: &[u8]| use_range(first * self.words, &words(bytes));
        let mut pipeline = Pipeline::new(parallel_work::window());
        for first in (0..self.degree).step_by(positions) {
            let mut input = self.header(lifted as usize);
            input.reserve_exact(4 + 8 * positions * residues.len());
            input.extend((positions as u32).to_le_bytes());
            for values in residues {
                extend(&mut input, &values.as_ref()[first..first + positions]);
            }
            let ticket = submit(
                &LIFT,
                None,
                &[Part::Bytes(&input)],
                8 * positions * self.words,
            );
            if let Some((first, bytes)) = pipeline.push(first, ticket) {
                place(first, &bytes);
            }
        }
        for (first, bytes) in pipeline.finish() {
            place(first, &bytes);
        }
    }
}

/// Key records by ordinal and prime, and their identities, held by a test.
#[cfg(test)]
pub(super) type HeldRecords = (Vec<Vec<[u8; 64]>>, Vec<Vec<Vec<u8>>>);
#[cfg(test)]
impl Arithmetic {
    /// The keys' records and identities under the context's program and
    /// cache, by ordinal.
    pub(super) fn held_records(&self, keys: &[&Polynomial], context: RecordContext) -> HeldRecords {
        keys.iter()
            .enumerate()
            .map(|(ordinal, key)| self.key_records(key, RecordContext { ordinal, ..context }))
            .unzip()
    }
    /// Delivers each request's held records until the keyed product ends.
    pub(super) fn run_keyed(
        &self,
        mut product: KeyedProduct,
        (identities, records): &HeldRecords,
    ) -> Result<[Polynomial; KEYED_GROUPS], ()> {
        loop {
            match self.advance_keyed(&mut product, identities)? {
                Keyed::Done(sums) => {
                    return Ok(sums.map(|sums| self.lifted(&sums, Lifted::External)));
                }
                // The job has not ended; advancing again looks anew.
                Keyed::Waiting(_) => {}
                Keyed::Records(request) => {
                    for (ordinal, record) in records
                        .iter()
                        .enumerate()
                        .skip(request.first)
                        .take(request.count)
                    {
                        assert!(self.deliver_record(
                            &mut product,
                            ordinal,
                            request.prime,
                            &record[request.prime]
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "arithmetic-jobs-tests.rs"]
mod tests;
