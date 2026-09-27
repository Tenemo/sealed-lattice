//! The arithmetic's per-prime transforms and per-range lifts as jobs that
//! helper instances of the participant module run on their own. A job
//! names the profile, the ring degree and a prime or a lift, so any instance
//! rebuilds the same arithmetic from public parameters, and each prime's
//! jobs run on the one helper that holds that prime's transform tables.
use super::{Arithmetic, Polynomial, Transformed, shared};
use parallel_work::{Job, Part, Pipeline, Shared, share, submit};
use std::{ops::Range, rc::Rc};
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
/// A polynomial's gadget digits modulo a prime, transformed.
pub static DIGITS: Job = Job {
    kind: 0x0302,
    run: digits,
};
/// The sum of transformed digits times transformed keys modulo a prime,
/// transformed back.
pub static EXTERNAL: Job = Job {
    kind: 0x0303,
    run: external,
};
/// The canonical coefficients of a range of positions from their residues.
pub static LIFT: Job = Job {
    kind: 0x0304,
    run: lift,
};
pub static JOBS: [&Job; 5] = [&FORWARD, &PRODUCT, &DIGITS, &EXTERNAL, &LIFT];

const HEADER_BYTES: usize = 16;
/// The positions one lift job reconstructs.
const LIFT_POSITIONS: usize = 2048;

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
fn words(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect()
}
fn extend(output: &mut Vec<u8>, values: &[u64]) {
    for value in values {
        output.extend(value.to_le_bytes());
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

fn forward(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let polynomial = words(rest);
    assert_eq!(polynomial.len(), arithmetic.polynomial_words());
    let mut residues = arithmetic
        .projections(&polynomial, prime..prime + 1)
        .remove(0);
    arithmetic.transform(prime).forward(&mut residues);
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
fn digits(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let polynomial = words(rest);
    assert_eq!(polynomial.len(), arithmetic.polynomial_words());
    let mut output = Vec::with_capacity(8 * arithmetic.gadget_length * arithmetic.degree);
    for mut digit in arithmetic.prime_digits(&polynomial, prime) {
        arithmetic.transform(prime).forward(&mut digit);
        extend(&mut output, &digit);
    }
    output
}
fn external(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let values = words(rest);
    let (degree, gadget_length) = (arithmetic.degree, arithmetic.gadget_length);
    assert_eq!(values.len(), 2 * gadget_length * degree);
    let (digits, keys) = values.split_at(gadget_length * degree);
    let reduction = &arithmetic.reductions[prime];
    let mut sum = vec![0u64; degree];
    for (digit, key) in digits.chunks_exact(degree).zip(keys.chunks_exact(degree)) {
        for ((sum, digit), key) in sum.iter_mut().zip(digit).zip(key) {
            *sum = reduction.add(*sum, reduction.mul(*digit, *key));
        }
    }
    arithmetic.transform(prime).backward(&mut sum);
    let mut output = Vec::with_capacity(8 * degree);
    extend(&mut output, &sum);
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
    // Runs one job for each prime of the range, each on the helper that
    // holds that prime, and returns their outputs in prime order.
    fn prime_jobs(
        &self,
        job: &'static Job,
        primes: Range<usize>,
        output_bytes: usize,
        mut input: impl FnMut(usize) -> Vec<u8>,
        shared: Option<&Shared>,
    ) -> Vec<Vec<u64>> {
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
    /// The polynomial's centered residues modulo each of the first primes,
    /// transformed.
    pub(super) fn transformed(&self, value: &[u64], count: usize) -> Transformed {
        let shared = self.shared_polynomial(value);
        self.prime_jobs(
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
    ) -> Vec<Vec<u64>> {
        self.prime_jobs(
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
            let residues = self.prime_jobs(
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
    /// Each gadget digit of the canonical coefficients, transformed modulo
    /// every external-product prime.
    pub(super) fn digit_transforms(&self, value: &[u64]) -> Vec<Transformed> {
        let shared = self.shared_polynomial(value);
        let outputs = self.prime_jobs(
            &DIGITS,
            0..self.external_primes,
            8 * self.gadget_length * self.degree,
            |prime| self.header(prime),
            Some(&shared),
        );
        (0..self.gadget_length)
            .map(|digit| {
                outputs
                    .iter()
                    .map(|output| output[digit * self.degree..(digit + 1) * self.degree].to_vec())
                    .collect()
            })
            .collect()
    }
    /// The sum of the digits' products with the keys, lifted.
    pub(super) fn external(&self, digits: &[Transformed], keys: &[Transformed]) -> Polynomial {
        assert_eq!(keys.len(), self.gadget_length);
        assert_eq!(digits.len(), self.gadget_length);
        let sums = self.prime_jobs(
            &EXTERNAL,
            0..self.external_primes,
            8 * self.degree,
            |prime| {
                let mut input = self.header(prime);
                for digit in digits {
                    extend(&mut input, &digit[prime]);
                }
                for key in keys {
                    extend(&mut input, &key[prime]);
                }
                input
            },
            None,
        );
        self.lifted(&sums, Lifted::External)
    }
    /// The canonical coefficients that the residues modulo the lift's primes
    /// determine.
    pub(super) fn lifted(&self, residues: &Transformed, lifted: Lifted) -> Polynomial {
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
                extend(&mut input, &values[first..first + positions]);
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
