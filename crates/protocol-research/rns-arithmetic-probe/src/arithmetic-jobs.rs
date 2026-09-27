//! The arithmetic's per-prime transforms and per-range lifts as jobs that
//! helper instances of the participant module run on their own. A job
//! names the profile, the ring degree and a prime or a lift, so any instance
//! rebuilds the same arithmetic from public parameters, and each prime's
//! jobs run on the one helper that holds that prime's transform tables and
//! kept keys.
use super::{Arithmetic, Polynomial, Transformed, shared};
use parallel_work::{Job, Part, Pipeline, Shared, session, share, submit};
use std::{cell::RefCell, collections::HashMap, ops::Range, rc::Rc};
use supported_profile::Profile;
use zeroize::Zeroizing;

/// A polynomial's centered residues modulo a prime, transformed.
pub static FORWARD: Job = Job {
    kind: 0x0300,
    run: forward,
};
/// The product of two transformed residue vectors modulo a prime,
/// transformed back.
pub static PRODUCT: Job = Job {
    kind: 0x0301,
    run: product,
};
/// Keeps a key's centered residues modulo a prime, transformed, as the next
/// key of its session.
pub static KEY: Job = Job {
    kind: 0x0302,
    run: key,
};
/// The sums of a polynomial's transformed gadget digits modulo a prime times
/// each group of a session's kept keys, transformed back.
pub static KEYED: Job = Job {
    kind: 0x0303,
    run: keyed,
};
/// The canonical coefficients of a range of positions from their residues.
pub static LIFT: Job = Job {
    kind: 0x0304,
    run: lift,
};
/// Drops a session's kept keys modulo a prime.
pub static FORGET: Job = Job {
    kind: 0x0305,
    run: forget,
};
pub static JOBS: [&Job; 6] = [&FORWARD, &PRODUCT, &KEY, &KEYED, &LIFT, &FORGET];

const HEADER_BYTES: usize = 16;
/// The positions one lift job reconstructs.
const LIFT_POSITIONS: usize = 2048;

thread_local! {
    /// Each session's kept keys modulo each prime whose jobs run here, in
    /// key order.
    static KEYS: RefCell<HashMap<(u64, usize), Transformed>> = RefCell::default();
}

/// The lift of a product: of a plaintext or secret product, of an external
/// product, or of a ciphertext tensor.
#[derive(Clone, Copy)]
pub(super) enum Lifted {
    Key = 0,
    External = 1,
    Tensor = 2,
}

fn number(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
}
fn session_number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}
fn words(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect()
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
// The jobs a stage keeps running: one for each helper and one more.
fn window() -> usize {
    parallel_work::helpers() + 1
}
// The centered residues modulo the prime of the polynomial the bytes hold,
// transformed.
fn transformed_residues(arithmetic: &Arithmetic, prime: usize, bytes: &[u8]) -> Vec<u64> {
    let polynomial = words(bytes);
    assert_eq!(polynomial.len(), arithmetic.polynomial_words());
    let mut residues = arithmetic
        .projections(&polynomial, prime..prime + 1)
        .remove(0);
    arithmetic.transform(prime).forward(&mut residues);
    residues
}

fn forward(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let residues = transformed_residues(&arithmetic, prime, rest);
    let mut output = Vec::with_capacity(8 * residues.len());
    extend(&mut output, &residues);
    output
}
fn product(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let values = words(rest);
    assert_eq!(values.len(), 2 * arithmetic.degree);
    let (left, right) = values.split_at(arithmetic.degree);
    let reduction = &arithmetic.reductions[prime];
    let mut product: Vec<u64> = left
        .iter()
        .zip(right)
        .map(|(left, right)| reduction.mul(*left, *right))
        .collect();
    arithmetic.transform(prime).backward(&mut product);
    let mut output = Vec::with_capacity(8 * product.len());
    extend(&mut output, &product);
    output
}
fn key(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let (session, ordinal) = (session_number(rest), number(&rest[8..]));
    let residues = transformed_residues(&arithmetic, prime, &rest[12..]);
    KEYS.with(|keys| {
        let mut keys = keys.borrow_mut();
        let kept = keys.entry((session, prime)).or_default();
        assert_eq!(kept.len(), ordinal, "Key order");
        kept.push(residues);
    });
    Vec::new()
}
fn keyed(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let (session, first, groups) = (
        session_number(rest),
        number(&rest[8..]),
        number(&rest[12..]),
    );
    let polynomial = words(&rest[16..]);
    assert_eq!(polynomial.len(), arithmetic.polynomial_words());
    let (degree, gadget_length) = (arithmetic.degree, arithmetic.gadget_length);
    let transform = arithmetic.transform(prime);
    let mut digits = arithmetic.prime_digits(&polynomial, prime);
    drop(polynomial);
    for digit in &mut digits {
        transform.forward(digit);
    }
    let reduction = &arithmetic.reductions[prime];
    let mut output = Vec::with_capacity(8 * groups * degree);
    let mut sum = vec![0u64; degree];
    KEYS.with(|keys| {
        let keys = keys.borrow();
        let kept = &keys[&(session, prime)][first..first + groups * gadget_length];
        for group in kept.chunks_exact(gadget_length) {
            sum.fill(0);
            for (digit, key) in digits.iter().zip(group) {
                for ((sum, digit), key) in sum.iter_mut().zip(digit).zip(key) {
                    *sum = reduction.add(*sum, reduction.mul(*digit, *key));
                }
            }
            transform.backward(&mut sum);
            extend(&mut output, &sum);
        }
    });
    output
}
fn lift(input: &[u8]) -> Vec<u8> {
    let (arithmetic, lifted, rest) = read(input);
    let lift = arithmetic.lift(lifted);
    let positions = number(rest);
    let values = words(&rest[4..]);
    assert_eq!(values.len(), lift.count * positions);
    let residues: Vec<Vec<u64>> = values
        .chunks_exact(positions)
        .map(|residues| residues.to_vec())
        .collect();
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
fn forget(input: &[u8]) -> Vec<u8> {
    let (session, prime) = (session_number(input), number(&input[8..]));
    KEYS.with(|keys| keys.borrow_mut().remove(&(session, prime)));
    Vec::new()
}

// Runs one job for each prime of the range, each on the helper that holds
// that prime, and returns their outputs in prime order.
fn prime_jobs(
    job: &'static Job,
    primes: Range<usize>,
    output_bytes: usize,
    mut input: impl FnMut(usize) -> Vec<u8>,
    shared: Option<&Shared>,
) -> Transformed {
    let first = primes.start;
    let mut outputs = vec![Vec::new(); primes.len()];
    let mut pipeline = Pipeline::new(window());
    for prime in primes {
        let bytes = input(prime);
        let ticket = match shared {
            Some(shared) => submit(
                job,
                Some(prime),
                &[Part::Bytes(&bytes), Part::Shared(shared)],
                output_bytes,
            ),
            None => submit(job, Some(prime), &[Part::Bytes(&bytes)], output_bytes),
        };
        if let Some((prime, output)) = pipeline.push(prime, ticket) {
            outputs[prime - first] = words(&output);
        }
    }
    for (prime, output) in pipeline.finish() {
        outputs[prime - first] = words(&output);
    }
    outputs
}

/// Keys whose transformed residues modulo each external-product prime stay
/// with the instance that runs that prime's jobs: a helper, or this
/// instance without helpers. Dropping the keys drops every kept residue.
pub(super) struct ResidentKeys {
    session: u64,
    primes: usize,
    count: usize,
}

impl ResidentKeys {
    pub(super) fn new(arithmetic: &Arithmetic) -> Self {
        Self {
            session: session(),
            primes: arithmetic.external_primes,
            count: 0,
        }
    }
    pub(super) fn len(&self) -> usize {
        self.count
    }
    /// Drops every kept key.
    pub(super) fn clear(&mut self) {
        if self.count == 0 {
            return;
        }
        prime_jobs(
            &FORGET,
            0..self.primes,
            0,
            |prime| {
                let mut input = self.session.to_le_bytes().to_vec();
                input.extend((prime as u32).to_le_bytes());
                input
            },
            None,
        );
        self.count = 0;
    }
}

impl Drop for ResidentKeys {
    fn drop(&mut self) {
        self.clear();
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
    fn shared_polynomial(&self, polynomial: &[u64]) -> Shared {
        assert_eq!(polynomial.len(), self.polynomial_words());
        let mut bytes = Zeroizing::new(Vec::with_capacity(8 * polynomial.len()));
        extend(&mut bytes, polynomial);
        share(bytes)
    }
    /// The polynomial's centered residues modulo each of the first primes,
    /// transformed.
    pub(super) fn transformed(&self, value: &[u64], count: usize) -> Transformed {
        let shared = self.shared_polynomial(value);
        prime_jobs(
            &FORWARD,
            0..count,
            8 * self.degree,
            |prime| self.header(prime),
            Some(&shared),
        )
    }
    // The products of the transformed residues modulo each prime of the
    // range, transformed back.
    fn prime_products<'a>(
        &self,
        primes: Range<usize>,
        left: impl Fn(usize) -> &'a [u64],
        right: impl Fn(usize) -> &'a [u64],
    ) -> Transformed {
        prime_jobs(
            &PRODUCT,
            primes,
            8 * self.degree,
            |prime| {
                let mut input = self.header(prime);
                extend(&mut input, left(prime));
                extend(&mut input, right(prime));
                input
            },
            None,
        )
    }
    /// The products of the transformed residues modulo each of their
    /// primes, transformed back.
    pub(super) fn products(&self, left: &Transformed, right: &Transformed) -> Transformed {
        assert_eq!(left.len(), right.len());
        self.prime_products(0..left.len(), |prime| &left[prime], |prime| &right[prime])
    }
    /// The product of two polynomials, lifted from the key primes, or from
    /// every prime with the tensor's plaintext rescaling.
    pub(super) fn multiply(&self, left: &[u64], right: &[u64], tensor: bool) -> Polynomial {
        let (count, lifted) = if tensor {
            (self.tensor_primes(), Lifted::Tensor)
        } else {
            (self.key_primes, Lifted::Key)
        };
        let mut products = self.transformed(left, count);
        let right = self.shared_polynomial(right);
        // A window of primes' right residues at a time, each multiplied
        // into the left residues in place.
        for first in (0..count).step_by(window()) {
            let primes = first..count.min(first + window());
            let residues = prime_jobs(
                &FORWARD,
                primes.clone(),
                8 * self.degree,
                |prime| self.header(prime),
                Some(&right),
            );
            let batch = self.prime_products(
                primes.clone(),
                |prime| &products[prime],
                |prime| &residues[prime - first],
            );
            for (prime, product) in primes.zip(batch) {
                products[prime] = product;
            }
        }
        self.lifted(&products, lifted)
    }
    /// Keeps the key's transformed residues modulo every external-product
    /// prime as the next of the keys.
    pub(super) fn keep(&self, keys: &mut ResidentKeys, key: &[u64]) {
        assert_eq!(keys.primes, self.external_primes);
        let shared = self.shared_polynomial(key);
        prime_jobs(
            &KEY,
            0..keys.primes,
            0,
            |prime| {
                let mut input = self.header(prime);
                input.extend(keys.session.to_le_bytes());
                input.extend((keys.count as u32).to_le_bytes());
                input
            },
            Some(&shared),
        );
        keys.count += 1;
    }
    /// The sums of the value's gadget digits times each gadget coordinate's
    /// key, for each of the groups of kept keys from the first group, lifted.
    pub(super) fn keyed<const GROUPS: usize>(
        &self,
        value: &[u64],
        keys: &ResidentKeys,
        first_group: usize,
    ) -> [Polynomial; GROUPS] {
        let first = first_group * self.gadget_length;
        assert!(
            first + GROUPS * self.gadget_length <= keys.count,
            "Kept keys"
        );
        let shared = self.shared_polynomial(value);
        let outputs = prime_jobs(
            &KEYED,
            0..self.external_primes,
            8 * GROUPS * self.degree,
            |prime| {
                let mut input = self.header(prime);
                input.extend(keys.session.to_le_bytes());
                for value in [first, GROUPS] {
                    input.extend((value as u32).to_le_bytes());
                }
                input
            },
            Some(&shared),
        );
        drop(shared);
        std::array::from_fn(|group| {
            let residues: Vec<&[u64]> = outputs
                .iter()
                .map(|output| &output[group * self.degree..(group + 1) * self.degree])
                .collect();
            self.lifted(&residues, Lifted::External)
        })
    }
    /// The canonical coefficients that the residues modulo the lift's primes
    /// determine.
    pub(super) fn lifted(&self, residues: &[impl AsRef<[u64]>], lifted: Lifted) -> Polynomial {
        let lift = self.lift(lifted as usize);
        assert_eq!(residues.len(), lift.count);
        let positions = LIFT_POSITIONS.min(self.degree);
        let mut output = self.zero();
        let mut place = |first: usize, bytes: &[u8]| {
            let start = first * self.words;
            output[start..start + positions * self.words].copy_from_slice(&words(bytes));
        };
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
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEGREE: usize = 16;

    // Keys of interleaved sessions stay apart, a session's cleared keys
    // start again from the first, and dropped keys leave nothing kept.
    #[test]
    fn kept_keys_stay_with_their_session_until_dropped() {
        let profile = Profile::new(3, 2).unwrap();
        let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
        let gadget_length = arithmetic.gadget_length;
        let value = arithmetic.uniform(1);
        let keys = |seed: u64| -> Vec<Polynomial> {
            (0..gadget_length)
                .map(|digit| arithmetic.uniform(seed + digit as u64))
                .collect()
        };
        let (first_keys, second_keys) = (keys(100), keys(200));
        let mut first = ResidentKeys::new(&arithmetic);
        let mut second = ResidentKeys::new(&arithmetic);
        for (left, right) in first_keys.iter().zip(&second_keys) {
            arithmetic.keep(&mut first, left);
            arithmetic.keep(&mut second, right);
        }
        let [first_product] = arithmetic.keyed(&value, &first, 0);
        let [second_product] = arithmetic.keyed(&value, &second, 0);
        assert_ne!(first_product, second_product);
        first.clear();
        assert_eq!(first.len(), 0);
        for key in &second_keys {
            arithmetic.keep(&mut first, key);
        }
        assert_eq!(arithmetic.keyed(&value, &first, 0), [second_product]);
        // A group beyond the kept keys is refused.
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                arithmetic.keyed::<1>(&value, &first, 1)
            }))
            .is_err()
        );
        drop((first, second));
        KEYS.with(|keys| assert!(keys.borrow().is_empty()));
    }
}
