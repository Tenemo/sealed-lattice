//! The arithmetic's transforms, keyed products and per-range lifts as jobs
//! that helper instances of the participant module run on their own. A job
//! names the profile, the ring degree and a set of primes, one prime or a
//! lift, so any instance rebuilds the same arithmetic from public
//! parameters. A set holds every helper-count-th prime from its first, and
//! its jobs, like those of each of its primes, run on the one helper that
//! holds its transform tables and the transformed polynomials its sessions
//! keep there; without helpers one set holds every prime.
use super::{Arithmetic, Polynomial, shared};
use parallel_work::{Job, Part, Pipeline, Shared, Ticket, session, share, share_words, submit};
use registration_credentials::{foundation::CanonicalItem, identity::IdentityHasher};
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
pub static JOBS: [&Job; 6] = [&SOURCES, &TENSOR, &RECORDS, &DIGITS, &KEYED, &LIFT];

const HEADER_BYTES: usize = 16;
const SET_BYTES: usize = 8;
/// The positions one lift job reconstructs.
const LIFT_POSITIONS: usize = 2048;
/// The coefficients a job reads of a streamed polynomial at once.
const STREAMED_COEFFICIENTS: usize = 1024;
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
/// The sets that hold the first primes of the count: one for each helper
/// that holds any of them, or one without helpers.
fn prime_sets(count: usize) -> Vec<PrimeSet> {
    let helpers = parallel_work::helpers();
    if helpers == 0 {
        return vec![PrimeSet {
            first: 0,
            stride: 1,
            count,
        }];
    }
    (0..helpers.min(count))
        .map(|first| PrimeSet {
            first,
            stride: helpers,
            count,
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
/// A key record's identity: its bytes under the program, the cache, the
/// key's ordinal and the prime.
fn record_identity(
    context: &RecordContext,
    ordinal: usize,
    prime: usize,
    record: &[u8],
) -> [u8; 64] {
    let mut hasher = IdentityHasher::local(
        EVALUATION_KEY_DOMAIN,
        &[
            CanonicalItem::hash512(context.program),
            CanonicalItem::unsigned64(u64::from(context.cache)),
            CanonicalItem::unsigned64(ordinal as u64),
            CanonicalItem::unsigned64(prime as u64),
        ],
        record.len(),
    )
    .expect("Record identity");
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
                    *value = reduction.mul(*value, *value);
                }
            } else {
                for (value, other) in product.iter_mut().zip(&kept[&(session, prime, right)]) {
                    *value = reduction.mul(*value, *other);
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
    let mut output = Vec::with_capacity(IDENTITY_BYTES * gadget_length + 8 * degree);
    let mut sum = vec![0u64; degree];
    let mut record = vec![0u8; record_bytes];
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for digit in 0..gadget_length {
            parallel_work::read(digit * record_bytes, &mut record);
            output.extend(record_identity(
                &context,
                context.ordinal + digit,
                prime,
                &record,
            ));
            let digits = &kept[&(session, prime, digit)];
            for ((sum, digit), key) in sum.iter_mut().zip(digits).zip(record.chunks_exact(8)) {
                *sum = reduction.add(*sum, reduction.mul(*digit, word(key)));
            }
        }
        if last {
            for digit in 0..gadget_length {
                kept.remove(&(session, prime, digit));
            }
        }
    });
    arithmetic.transform(prime).backward(&mut sum);
    extend(&mut output, &sum);
    output
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
/// and group in that order, each over the records of its group's keys
/// modulo its prime, which the caller delivers. Each prime's digits are
/// kept from just before its first group's job to its last group's.
pub(super) struct KeyedProduct {
    session: u64,
    context: RecordContext,
    // The polynomial until the last prime's digits have started.
    polynomial: Option<Shared>,
    started: Vec<Ticket>,
    requested: usize,
    delivered: Vec<u8>,
    running: VecDeque<(usize, Ticket)>,
    sums: [Vec<Vec<u64>>; KEYED_GROUPS],
}
/// A keyed product's next need: the records of a request, or both groups'
/// sums modulo each prime, which the caller lifts.
pub(super) enum Keyed {
    Records(RecordRequest),
    Done([Vec<Vec<u64>>; KEYED_GROUPS]),
}

impl KeyedProduct {
    /// The ordinal of its first group's first key.
    pub(super) fn first_ordinal(&self) -> usize {
        self.context.ordinal
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
    /// residues beside its records, a key record with its sum and output,
    /// or a lift's residues and coefficients, each beside one run of a
    /// streamed polynomial.
    pub(super) fn job_bytes(&self, helpers: usize) -> usize {
        let residue_bytes = 8 * self.degree;
        let held = |count: usize| count.div_ceil(helpers.max(1));
        let positions = LIFT_POSITIONS.min(self.degree);
        let jobs = [
            (held(self.tensor_primes()) + 1) * residue_bytes,
            held(self.external_primes) * (2 * residue_bytes + IDENTITY_BYTES),
            3 * residue_bytes + self.gadget_length * IDENTITY_BYTES,
            2 * 8 * positions * (self.tensor_primes() + self.words),
        ];
        HEADER_BYTES
            + SET_BYTES
            + RecordContext::BYTES
            + 8 * self.words * STREAMED_COEFFICIENTS.min(self.degree)
            + jobs.into_iter().max().unwrap()
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
        for set in prime_sets(sources.count) {
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
        let sets = prime_sets(sources.count);
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
        let sets = prime_sets(self.external_primes);
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
            running: VecDeque::new(),
            sums: std::array::from_fn(|_| vec![Vec::new(); self.external_primes]),
        }
    }
    /// The records a keyed product's next job needs.
    fn keyed_request(&self, product: &KeyedProduct) -> RecordRequest {
        let (prime, group) = (
            product.requested / KEYED_GROUPS,
            product.requested % KEYED_GROUPS,
        );
        RecordRequest {
            first: product.context.ordinal + group * self.gadget_length,
            count: self.gadget_length,
            prime,
        }
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
        let record_bytes = 8 * self.degree;
        let request = self.keyed_request(product);
        let received = product.delivered.len() / record_bytes;
        if product.requested == KEYED_GROUPS * self.external_primes
            || prime != request.prime
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
    /// Starts the job of a complete delivery and takes the outputs beyond
    /// the window. Returns the next request, or both groups' lifted sums
    /// once every job has ended. Fails when a job's records are not those
    /// whose identities the caller holds, by ordinal and prime.
    pub(super) fn advance_keyed(
        &self,
        product: &mut KeyedProduct,
        identities: &[Vec<[u8; 64]>],
    ) -> Result<Keyed, ()> {
        let total = KEYED_GROUPS * self.external_primes;
        let record_bytes = 8 * self.degree;
        if product.requested < total && product.delivered.len() == self.gadget_length * record_bytes
        {
            let request = self.keyed_request(product);
            let group = product.requested % KEYED_GROUPS;
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
            }
            let mut input = self.header(request.prime);
            input.extend(product.session.to_le_bytes());
            input.extend(u32::from(group + 1 == KEYED_GROUPS).to_le_bytes());
            RecordContext {
                ordinal: request.first,
                ..product.context
            }
            .write(&mut input);
            let records = share(Zeroizing::new(std::mem::take(&mut product.delivered)));
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
            let (index, ticket) = product.running.pop_front().unwrap();
            let output = ticket.wait();
            let (prime, group) = (index / KEYED_GROUPS, index % KEYED_GROUPS);
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
mod tests {
    use super::*;

    const TEST_DEGREE: usize = 16;

    fn context(ordinal: usize) -> RecordContext {
        RecordContext {
            program: [7; 64],
            cache: 0,
            ordinal,
        }
    }
    // A keyed product takes exactly the records it requests, in order, and
    // refuses records whose identities differ from the held ones: a changed
    // record, and a record of another prime or key. Its digits and a
    // product's sources are dropped after their last use.
    #[test]
    fn keyed_products_take_only_the_held_records_and_keep_nothing() {
        let profile = Profile::new(3, 2).unwrap();
        let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
        let gadget_length = arithmetic.gadget_length;
        let value = arithmetic.uniform(1);
        let keys: Vec<Polynomial> = (0..KEYED_GROUPS * gadget_length)
            .map(|ordinal| arithmetic.uniform(100 + ordinal as u64))
            .collect();
        let held = arithmetic.held_records(&keys.iter().collect::<Vec<_>>(), context(0));
        let run = |held: &HeldRecords| {
            arithmetic.run_keyed(arithmetic.keyed_product(&value, context(0)), held)
        };
        let expected = run(&held).unwrap();
        // The same records in another run give the same sums.
        assert_eq!(run(&held).unwrap(), expected);
        let (identities, records) = &held;
        let mut product = arithmetic.keyed_product(&value, context(0));
        let Keyed::Records(request) = arithmetic.advance_keyed(&mut product, identities).unwrap()
        else {
            panic!("A keyed product needs records first.");
        };
        assert_eq!(
            request,
            RecordRequest {
                first: 0,
                count: gadget_length,
                prime: 0
            }
        );
        // Another key, another prime or a short record is refused.
        assert!(!arithmetic.deliver_record(&mut product, 1, 0, &records[1][0]));
        assert!(!arithmetic.deliver_record(&mut product, 0, 1, &records[0][1]));
        assert!(!arithmetic.deliver_record(&mut product, 0, 0, &records[0][0][8..]));
        // A changed record, another prime's record and swapped keys' records
        // differ from the held identities.
        let mut changed = held.clone();
        changed.1[0][0][5] ^= 1;
        assert!(run(&changed).is_err());
        let mut changed = held.clone();
        changed.1[1][0] = changed.1[1][1].clone();
        assert!(run(&changed).is_err());
        let mut changed = held.clone();
        changed.1.swap(2, 3);
        assert!(run(&changed).is_err());
        KEPT.with(|kept| kept.borrow_mut().clear());
        assert_eq!(run(&held).unwrap(), expected);
        arithmetic.multiply(&value, &arithmetic.uniform(2), true);
        let square = [value.clone(), arithmetic.uniform(3)];
        arithmetic.tensors(&square, &square);
        arithmetic.tensors(&square, &[arithmetic.uniform(4), arithmetic.uniform(5)]);
        KEPT.with(|kept| assert!(kept.borrow().is_empty()));
    }
}
