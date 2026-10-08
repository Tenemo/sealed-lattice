use num_bigint::BigUint;
#[cfg(any(test, feature = "numerical-probes"))]
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use std::{
    cell::{OnceCell, RefCell},
    rc::Rc,
};
use supported_profile::{FHE_SECRET_SUPPORT, PLAINTEXT_MODULUS, Profile};

#[path = "arithmetic-jobs.rs"]
mod jobs;
#[path = "prime-transform.rs"]
mod prime_transform;
#[path = "ranking.rs"]
pub mod ranking;
#[path = "word-arithmetic.rs"]
mod word_arithmetic;

use jobs::{DROP_LEFT, DROP_RIGHT, Keyed, KeyedProduct, PrimeSet, RecordContext};
pub use jobs::{JOBS, RecordRequest};
use prime_transform::{PrimeModulus, Transform};

#[cfg(any(test, feature = "numerical-probes"))]
use word_arithmetic::words_of;
use word_arithmetic::{Lift, MAXIMUM_WORDS, WideModulus, extract, larger};

/// Canonical coefficients below the ciphertext modulus, each in the
/// arithmetic's count of little-endian 64-bit words, in coefficient order.
pub type Polynomial = Vec<u64>;

#[cfg(any(test, feature = "numerical-probes"))]
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn unpack(value: &[u64]) -> BigUint {
    BigUint::from_bytes_le(
        &value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}
/// Reads little-endian words in place.
fn read_words(bytes: &[u8], output: &mut [u64]) {
    for (word, bytes) in output.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().unwrap());
    }
}
/// The least prefix of the primes whose product covers the bound.
fn prefix(primes: &[u64], bound: &BigUint) -> usize {
    let mut product = BigUint::from(1u32);
    for (index, prime) in primes.iter().enumerate() {
        product *= *prime;
        if Lift::covers(&product, index + 1, bound) {
            return index + 1;
        }
    }
    panic!("The tensor primes cover every smaller bound.");
}
/// The residue of little-endian words plus an initial residue: the sum of
/// the words' lazy Shoup products with the prime's word powers, each below
/// twice the prime for any word, reduced by the Shoup quotient of one. At
/// most sixteen products below 2^59 and an initial residue below 2^58 sum
/// below 2^64, so no addition wraps.
fn words_residue(prime: &PrimeModulus, powers: &[(u64, u64)], words: &[u64], initial: u64) -> u64 {
    debug_assert!(words.len() <= MAXIMUM_WORDS && **prime < 1 << 58);
    let mut sum = initial;
    for (word, (power, quotient)) in words.iter().zip(powers) {
        sum = sum.wrapping_add(prime.lazy_multiply_shoup(*word, *power, *quotient));
    }
    prime.multiply_shoup(sum, 1, powers[0].1)
}
/// Bits `start..start + bits` of a canonical coefficient as words, one for
/// every 64 bits of the digit.
fn digit_words(coefficient: &[u64], start: usize, bits: usize, output: &mut [u64]) {
    for (part, word) in output.iter_mut().enumerate() {
        let width = bits - 64 * part;
        *word = extract(coefficient, start + 64 * part);
        if width < 64 {
            *word &= (1 << width) - 1;
        }
    }
}

fn ciphertext_modulus(profile: Profile) -> BigUint {
    let ciphertext = profile.ciphertext_modulus();
    (BigUint::from(ciphertext.odd_factor()) << ciphertext.exponent()) + 1u64
}
/// The primes whose product covers twice a ciphertext tensor's centered
/// bound, and the least prefixes whose products cover twice the centered
/// bounds of plaintext and secret products and of gadget external products.
fn primes(profile: Profile, degree: usize) -> (Vec<u64>, usize, usize) {
    let half_modulus = ciphertext_modulus(profile) >> 1usize;
    let degree_factor = degree as u64;
    // A plaintext coefficient is at most half the plaintext modulus and an
    // aggregate secret's one-norm is at most one support per setup
    // contributor.
    let key_bound = 2u64
        * (degree_factor * u64::from(PLAINTEXT_MODULUS / 2))
            .max((profile.setup_contributors() * FHE_SECRET_SUPPORT) as u64)
        * &half_modulus;
    let external_bound = 2u64
        * profile.gadget_length() as u64
        * degree_factor
        * ((BigUint::from(1u64) << Profile::gadget_base_bits()) - 1u64)
        * &half_modulus;
    let tensor_bound = 2u64 * degree_factor * &half_modulus * &half_modulus;
    let mut primes = Vec::new();
    let mut product = BigUint::from(1u64);
    let mut limit = 1u64 << 58;
    while !Lift::covers(&product, primes.len(), &tensor_bound) {
        limit = super::proth_prime(58, limit);
        primes.push(limit);
        product *= limit;
    }
    let key_primes = prefix(&primes, &key_bound);
    let external_primes = prefix(&primes, &external_bound);
    assert!(key_primes <= external_primes);
    (primes, key_primes, external_primes)
}
/// Upper bounds on the counts of tensor primes and external-product primes,
/// without big integers: every prime has 58 bits, so a product of `k`
/// primes is at least 2^(57 k), and a product at least twice a bound covers
/// it.
fn prime_count_bounds(profile: Profile, degree: usize) -> (usize, usize) {
    // Half the modulus is below 2^(bits - 1) and the degree is a power of
    // two.
    let half_bits = profile.ciphertext_modulus().bits() - 1;
    let degree_bits = degree.ilog2() as usize;
    let gadget_bits = (usize::BITS - profile.gadget_length().leading_zeros()) as usize;
    let tensor_bits = 1 + degree_bits + 2 * half_bits;
    let external_bits = 1 + gadget_bits + degree_bits + Profile::gadget_base_bits() + half_bits;
    let count = |bound_bits: usize| (bound_bits + 1).div_ceil(57);
    (count(tensor_bits), count(external_bits))
}

struct Arithmetic {
    profile: Profile,
    degree: usize,
    words: usize,
    gadget_length: usize,
    modulus: BigUint,
    #[cfg(any(test, feature = "numerical-probes"))]
    signed_modulus: BigInt,
    wide: WideModulus,
    reductions: Vec<PrimeModulus>,
    /// Each prime's residues of 2^(64 j) for the coefficient words j, with
    /// their Shoup quotients. A coefficient's residue sums its words' lazy
    /// products, each below twice the prime, so a sum of at most 16 words'
    /// products and one more prime stays below 2^64.
    word_powers: Vec<Vec<(u64, u64)>>,
    /// Each prime's residue of the negated ciphertext modulus, which a
    /// centered negative coefficient adds.
    negated_modulus: Vec<u64>,
    /// Each prime's transform, built when first used, so an instance that
    /// runs only some primes' jobs holds only their tables.
    transforms: Vec<OnceCell<Transform>>,
    key_primes: usize,
    external_primes: usize,
    key_lift: Lift,
    external_lift: Lift,
    tensor_lift: Lift,
}

impl Arithmetic {
    /// Exact arithmetic modulo the profile's ciphertext modulus. Plaintext
    /// and secret products, gadget external products and ciphertext tensors
    /// each lift from the least prefix of the primes whose product covers
    /// twice their centered bound.
    fn new(profile: Profile, degree: usize) -> Self {
        let modulus = ciphertext_modulus(profile);
        let words = profile.ciphertext_modulus().bits().div_ceil(64);
        assert!(words <= MAXIMUM_WORDS);
        let gadget_length = profile.gadget_length();
        assert!(Profile::gadget_base_bits().div_ceil(64) <= words);
        let (primes, key_primes, external_primes) = primes(profile, degree);
        let reductions: Vec<PrimeModulus> = primes
            .iter()
            .map(|prime| PrimeModulus::new(*prime))
            .collect();
        let transforms = reductions.iter().map(|_| OnceCell::new()).collect();
        let word_powers = reductions
            .iter()
            .map(|prime| {
                let mut power = 1;
                (0..words)
                    .map(|_| {
                        let current = (power, prime.shoup(power));
                        power = prime.multiply(power, ((1u128 << 64) % u128::from(**prime)) as u64);
                        current
                    })
                    .collect()
            })
            .collect();
        let lift = |count: usize, tensor: bool| {
            Lift::new(
                &primes[..count],
                &reductions[..count],
                &modulus,
                PLAINTEXT_MODULUS,
                tensor,
            )
        };
        Self {
            profile,
            degree,
            words,
            gadget_length,
            #[cfg(any(test, feature = "numerical-probes"))]
            signed_modulus: BigInt::from(modulus.clone()),
            wide: WideModulus::new(&modulus),
            negated_modulus: primes
                .iter()
                .map(|prime| {
                    let residue = (&modulus % *prime).to_u64().unwrap();
                    (prime - residue) % prime
                })
                .collect(),
            key_lift: lift(key_primes, false),
            external_lift: lift(external_primes, false),
            tensor_lift: lift(primes.len(), true),
            modulus,
            key_primes,
            external_primes,
            word_powers,
            reductions,
            transforms,
        }
    }
    fn tensor_primes(&self) -> usize {
        self.tensor_lift.count
    }
    fn transform(&self, prime: usize) -> &Transform {
        self.transforms[prime].get_or_init(|| Transform::new(&self.reductions[prime], self.degree))
    }
    /// The lift of a plaintext or secret product, of an external product or
    /// of a ciphertext tensor.
    fn lift(&self, lifted: usize) -> &Lift {
        match lifted {
            0 => &self.key_lift,
            1 => &self.external_lift,
            2 => &self.tensor_lift,
            _ => panic!("Lift"),
        }
    }
    fn polynomial_words(&self) -> usize {
        self.degree * self.words
    }
    fn zero(&self) -> Polynomial {
        vec![0; self.polynomial_words()]
    }
    fn coefficients<'a>(&self, polynomial: &'a [u64]) -> std::slice::ChunksExact<'a, u64> {
        polynomial.chunks_exact(self.words)
    }
    #[cfg(any(test, feature = "numerical-probes"))]
    fn push(&self, output: &mut Polynomial, value: &BigUint) {
        output.extend(words_of(value, self.words));
    }
    #[cfg(any(test, feature = "numerical-probes"))]
    fn push_normalized(&self, output: &mut Polynomial, value: BigInt) {
        let mut value = value % &self.signed_modulus;
        if value.sign() == Sign::Minus {
            value += &self.signed_modulus;
        }
        self.push(output, value.magnitude());
    }
    /// A polynomial of signed coefficients of magnitude below the modulus.
    fn signed(&self, values: &[i32]) -> Polynomial {
        let mut output = self.zero();
        for (coefficient, value) in output.chunks_exact_mut(self.words).zip(values) {
            self.wide.signed(i64::from(*value), coefficient);
        }
        output
    }
    #[cfg(any(test, feature = "numerical-probes"))]
    fn uniform(&self, mut seed: u64) -> Polynomial {
        let sampling_words = self.words + 1;
        let mut output = Vec::with_capacity(self.polynomial_words());
        for _ in 0..self.degree {
            let bytes: Vec<u8> = (0..sampling_words)
                .flat_map(|_| next(&mut seed).to_le_bytes())
                .collect();
            self.push(
                &mut output,
                &(BigUint::from_bytes_le(&bytes) % &self.modulus),
            );
        }
        output
    }
    #[cfg(any(test, feature = "numerical-probes"))]
    fn small(&self, values: &[i16]) -> Polynomial {
        assert_eq!(values.len(), self.degree);
        let mut output = Vec::with_capacity(self.polynomial_words());
        for value in values {
            self.push_normalized(&mut output, BigInt::from(*value));
        }
        output
    }
    /// The residues modulo each prime of the set of the centered
    /// coefficients of the job's streamed polynomial, reading each
    /// coefficient once.
    fn set_residues(&self, set: PrimeSet) -> Vec<Vec<u64>> {
        let mut output: Vec<Vec<u64>> = set
            .primes()
            .map(|_| Vec::with_capacity(self.degree))
            .collect();
        let mut value = [0u64; MAXIMUM_WORDS];
        let value = &mut value[..self.words];
        self.streamed_coefficients(|coefficient| {
            read_words(coefficient, value);
            let negative = larger(value, &self.wide.half);
            for (residues, prime) in output.iter_mut().zip(set.primes()) {
                let initial = if negative {
                    self.negated_modulus[prime]
                } else {
                    0
                };
                residues.push(words_residue(
                    &self.reductions[prime],
                    &self.word_powers[prime],
                    value,
                    initial,
                ));
            }
        });
        output
    }
    /// The tensor products of two ciphertexts' components: the constant
    /// product, the sum of the two cross products and the quadratic product,
    /// each lifted on its own. Each component's residues stay with the
    /// instances that run their primes' jobs from its first product to its
    /// last, so at most three are kept. A square's two cross products are
    /// one product modulo every prime, so its two components' residues and
    /// that product are computed once.
    fn tensors(&self, first: &[Polynomial; 2], second: &[Polynomial; 2]) -> [Polynomial; 3] {
        let mut sources = self.sources(self.tensor_primes());
        let tensor = |sources: &mut jobs::Sources, left, right, drops| {
            let products = self.source_products(sources, left, right, drops);
            self.lifted(&products, jobs::Lifted::Tensor)
        };
        self.keep_source(&mut sources, 0, &first[0]);
        if std::ptr::eq(first, second) {
            self.keep_source(&mut sources, 1, &first[1]);
            let constant = tensor(&mut sources, 0, 0, 0);
            let mut linear = tensor(&mut sources, 0, 1, DROP_LEFT);
            let cross = linear.clone();
            self.add(&mut linear, &cross);
            drop(cross);
            let quadratic = tensor(&mut sources, 1, 1, DROP_LEFT);
            return [constant, linear, quadratic];
        }
        self.keep_source(&mut sources, 2, &second[0]);
        let constant = tensor(&mut sources, 0, 2, 0);
        self.keep_source(&mut sources, 3, &second[1]);
        let mut linear = tensor(&mut sources, 0, 3, DROP_LEFT);
        self.keep_source(&mut sources, 1, &first[1]);
        let products = self.source_products(&mut sources, 1, 2, DROP_RIGHT);
        self.add_lifted(&mut linear, &products, jobs::Lifted::Tensor);
        drop(products);
        let quadratic = tensor(&mut sources, 1, 3, DROP_LEFT | DROP_RIGHT);
        [constant, linear, quadratic]
    }
    /// Each gadget digit of the canonical coefficients' residues modulo each
    /// prime of the set, untransformed, from the job's streamed polynomial,
    /// reading each coefficient once.
    fn set_digits(&self, set: PrimeSet) -> Vec<Vec<Vec<u64>>> {
        let bits = Profile::gadget_base_bits();
        let parts = bits.div_ceil(64);
        let mut output: Vec<Vec<Vec<u64>>> = set
            .primes()
            .map(|_| {
                (0..self.gadget_length)
                    .map(|_| Vec::with_capacity(self.degree))
                    .collect()
            })
            .collect();
        let mut value = [0u64; MAXIMUM_WORDS];
        let value = &mut value[..self.words];
        let mut words = [0u64; MAXIMUM_WORDS];
        let words = &mut words[..parts];
        self.streamed_coefficients(|coefficient| {
            read_words(coefficient, value);
            for digit in 0..self.gadget_length {
                digit_words(value, bits * digit, bits, words);
                for (digits, prime) in output.iter_mut().zip(set.primes()) {
                    digits[digit].push(words_residue(
                        &self.reductions[prime],
                        &self.word_powers[prime],
                        words,
                        0,
                    ));
                }
            }
        });
        output
    }
    /// Starts the product of two ciphertexts, relinearized with each gadget
    /// coordinate's encryption key, first relinearization key, second
    /// relinearization key and second relinearization common polynomial, in
    /// that key order from the context's ordinal.
    fn start_product(
        &self,
        left: &[Polynomial; 2],
        right: &[Polynomial; 2],
        context: RecordContext,
    ) -> KeyedWork {
        let [constant, linear, quadratic] = self.tensors(left, right);
        let keyed = self.keyed_product(&quadratic, context);
        KeyedWork::Product {
            constant,
            linear,
            keyed,
            context,
        }
    }
    /// The automorphism X to X^5, which rotates the plaintext slots.
    fn automorphism(&self, polynomial: &[u64]) -> Polynomial {
        let mut output = self.zero();
        for (index, value) in self.coefficients(polynomial).enumerate() {
            let exponent = index * 5;
            let position = exponent % self.degree;
            let target = &mut output[position * self.words..(position + 1) * self.words];
            if (exponent / self.degree).is_multiple_of(2) {
                target.copy_from_slice(value);
            } else {
                self.wide.negate(value, target);
            }
        }
        output
    }
    /// Starts switching a ciphertext under the automorphism back to the
    /// secret with each gadget coordinate's automorphism key and then its
    /// common polynomial, in that key order from the context's ordinal.
    fn start_rotation(&self, value: &[Polynomial; 2], context: RecordContext) -> KeyedWork {
        let constant = self.automorphism(&value[0]);
        let keyed = self.keyed_product(&self.automorphism(&value[1]), context);
        KeyedWork::Rotation { constant, keyed }
    }
    /// Advances the work's keyed products: the key records they need next,
    /// or the resulting ciphertext. Fails when delivered records are not
    /// those whose identities the caller holds, by ordinal and prime.
    fn advance(&self, work: &mut KeyedWork, identities: &[Vec<[u8; 64]>]) -> Result<Step, ()> {
        loop {
            match work {
                KeyedWork::Product {
                    constant,
                    linear,
                    keyed,
                    context,
                } => match self.advance_keyed(keyed, identities)? {
                    Keyed::Records(request) => return Ok(Step::Records(request)),
                    Keyed::Waiting(number) => return Ok(Step::Waiting(number)),
                    // The first pair of groups' sums: the intermediate
                    // polynomial and the quadratic product's linear term.
                    Keyed::Done([intermediate, quadratic_linear])
                        if context.ordinal == keyed.first_ordinal() =>
                    {
                        self.add_lifted(linear, &quadratic_linear, jobs::Lifted::External);
                        drop(quadratic_linear);
                        let intermediate = self.lifted(&intermediate, jobs::Lifted::External);
                        *keyed = self.keyed_product(
                            &intermediate,
                            RecordContext {
                                ordinal: context.ordinal + jobs::KEYED_GROUPS * self.gadget_length,
                                ..*context
                            },
                        );
                    }
                    Keyed::Done([constant_term, linear_term]) => {
                        self.add_lifted(constant, &constant_term, jobs::Lifted::External);
                        drop(constant_term);
                        self.add_lifted(linear, &linear_term, jobs::Lifted::External);
                        return Ok(Step::Done([
                            std::mem::take(constant),
                            std::mem::take(linear),
                        ]));
                    }
                },
                KeyedWork::Rotation { constant, keyed } => {
                    return match self.advance_keyed(keyed, identities)? {
                        Keyed::Records(request) => Ok(Step::Records(request)),
                        Keyed::Waiting(number) => Ok(Step::Waiting(number)),
                        Keyed::Done([constant_term, linear]) => {
                            self.add_lifted(constant, &constant_term, jobs::Lifted::External);
                            drop(constant_term);
                            Ok(Step::Done([
                                std::mem::take(constant),
                                self.lifted(&linear, jobs::Lifted::External),
                            ]))
                        }
                    };
                }
            }
        }
    }
    /// Up to the count of the requests that follow the work's pending
    /// request, in order: its keyed product's later ones and, in a product's
    /// first keyed product, the second one's.
    fn following(&self, work: &KeyedWork, count: usize) -> Vec<RecordRequest> {
        let (keyed, second) = match work {
            KeyedWork::Product { keyed, context, .. } => (
                keyed,
                (context.ordinal == keyed.first_ordinal())
                    .then(|| context.ordinal + jobs::KEYED_GROUPS * self.gadget_length),
            ),
            KeyedWork::Rotation { keyed, .. } => (keyed, None),
        };
        self.keyed_requests_from(keyed.first_ordinal(), keyed.requested() + 1)
            .chain(
                second
                    .into_iter()
                    .flat_map(|ordinal| self.keyed_requests_from(ordinal, 0)),
            )
            .take(count)
            .collect()
    }
    /// Takes the next record that the work's pending request names; false
    /// when it is not that record.
    fn deliver(&self, work: &mut KeyedWork, ordinal: usize, prime: usize, record: &[u8]) -> bool {
        let (KeyedWork::Product { keyed, .. } | KeyedWork::Rotation { keyed, .. }) = work;
        self.deliver_record(keyed, ordinal, prime, record)
    }
    /// Takes the records of the work's pending request, which the host
    /// shared itself; false when they are not those records.
    fn deliver_shared(
        &self,
        work: &mut KeyedWork,
        request: RecordRequest,
        records: parallel_work::Shared,
    ) -> bool {
        let (KeyedWork::Product { keyed, .. } | KeyedWork::Rotation { keyed, .. }) = work;
        self.deliver_shared_records(keyed, request, records)
    }
    fn add(&self, target: &mut [u64], other: &[u64]) {
        let mut sum = [0u64; MAXIMUM_WORDS];
        let sum = &mut sum[..self.words];
        for (target, other) in target
            .chunks_exact_mut(self.words)
            .zip(self.coefficients(other))
        {
            self.wide.add(target, other, sum);
            target.copy_from_slice(sum);
        }
    }
    #[cfg(any(test, feature = "numerical-probes"))]
    fn affine(
        &self,
        base: &[u64],
        negative: bool,
        small: &[i16],
        multiplier: &BigInt,
        error: i64,
    ) -> Polynomial {
        let mut output = Vec::with_capacity(self.polynomial_words());
        for (base, small) in self.coefficients(base).zip(small) {
            let base = BigInt::from(unpack(base));
            self.push_normalized(
                &mut output,
                if negative { -base } else { base } + multiplier * *small + error,
            );
        }
        output
    }
    #[cfg(any(test, feature = "numerical-probes"))]
    fn decode(&self, ciphertext: &[Polynomial; 2], secret: &[u64]) -> Vec<u64> {
        let mut phase = self.multiply(secret, &ciphertext[1], false);
        self.add(&mut phase, &ciphertext[0]);
        self.coefficients(&phase)
            .map(|value| {
                (((unpack(value) * PLAINTEXT_MODULUS + (&self.modulus >> 1usize)) / &self.modulus)
                    % PLAINTEXT_MODULUS)
                    .to_u64()
                    .unwrap()
            })
            .collect()
    }
}
/// A relinearized product or a rotation whose keyed products run over key
/// records that the caller delivers. A product's context names its first
/// pair of key groups.
enum KeyedWork {
    Product {
        constant: Polynomial,
        linear: Polynomial,
        keyed: KeyedProduct,
        context: RecordContext,
    },
    Rotation {
        constant: Polynomial,
        keyed: KeyedProduct,
    },
}
/// Keyed work's next need: the records of a request, the end of a job the
/// host awaits, or its ciphertext.
enum Step {
    Records(RecordRequest),
    Waiting(u32),
    Done([Polynomial; 2]),
}

thread_local! {
    static SHARED: RefCell<Option<Rc<Arithmetic>>> = const { RefCell::new(None) };
}
/// The profile's arithmetic at the degree, which this instance's engine and
/// jobs share, so that its transform tables exist once.
fn shared(profile: Profile, degree: usize) -> Rc<Arithmetic> {
    SHARED.with(|shared| {
        let mut shared = shared.borrow_mut();
        if let Some(arithmetic) = shared
            .as_ref()
            .filter(|arithmetic| arithmetic.profile == profile && arithmetic.degree == degree)
        {
            return arithmetic.clone();
        }
        let arithmetic = Rc::new(Arithmetic::new(profile, degree));
        *shared = Some(arithmetic.clone());
        arithmetic
    })
}
/// A synthetic aggregate secret of one sparse support per setup contributor.
#[cfg(any(test, feature = "numerical-probes"))]
fn secret(degree: usize, contributors: usize, weight: usize, mut seed: u64) -> Vec<i16> {
    let mut result = vec![0; degree];
    for _ in 0..contributors {
        let mut occupied = vec![false; degree];
        let mut count = 0;
        while count < weight {
            let position = next(&mut seed) as usize & (degree - 1);
            if !occupied[position] {
                occupied[position] = true;
                result[position] += if count < weight / 2 { 1 } else { -1 };
                count += 1;
            }
        }
    }
    result
}

#[cfg(any(test, feature = "numerical-probes"))]
fn ephemeral(degree: usize, weight: usize, mut seed: u64) -> Vec<i16> {
    let mut result = vec![0; degree];
    let mut count = 0;
    while count < weight {
        let position = next(&mut seed) as usize & (degree - 1);
        if result[position] == 0 {
            result[position] = if count < weight / 2 { 1 } else { -1 };
            count += 1;
        }
    }
    result
}

#[cfg(test)]
#[path = "encrypted-tests.rs"]
mod tests;
