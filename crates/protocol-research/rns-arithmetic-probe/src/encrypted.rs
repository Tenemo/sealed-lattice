use fhe_math::{ntt::NttOperator, zq::Modulus};
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
#[path = "ranking.rs"]
pub mod ranking;
#[path = "word-arithmetic.rs"]
mod word_arithmetic;

pub use jobs::JOBS;
use jobs::ResidentKeys;

#[cfg(any(test, feature = "numerical-probes"))]
use word_arithmetic::words_of;
use word_arithmetic::{Lift, MAXIMUM_WORDS, WideModulus, extract, larger};

/// Canonical coefficients below the ciphertext modulus, each in the
/// arithmetic's count of little-endian 64-bit words, in coefficient order.
pub type Polynomial = Vec<u64>;
type Transformed = Vec<Vec<u64>>;

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
/// twice the prime, reduced by the Shoup quotient of one.
fn words_residue(prime: &Modulus, powers: &[(u64, u64)], words: &[u64], initial: u64) -> u64 {
    let mut sum = initial;
    for (word, (power, quotient)) in words.iter().zip(powers) {
        sum += prime.lazy_mul_shoup(*word, *power, *quotient);
    }
    prime.mul_shoup(sum, 1, powers[0].1)
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
    reductions: Vec<Modulus>,
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
    transforms: Vec<OnceCell<NttOperator>>,
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
        let reductions: Vec<Modulus> = primes
            .iter()
            .map(|prime| Modulus::new(*prime).unwrap())
            .collect();
        let transforms = reductions.iter().map(|_| OnceCell::new()).collect();
        let word_powers = reductions
            .iter()
            .map(|prime| {
                let mut power = 1;
                (0..words)
                    .map(|_| {
                        let current = (power, prime.shoup(power));
                        power = prime.mul(power, ((1u128 << 64) % u128::from(**prime)) as u64);
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
    fn transform(&self, prime: usize) -> &NttOperator {
        self.transforms[prime]
            .get_or_init(|| NttOperator::new(&self.reductions[prime], self.degree).unwrap())
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
    /// The residues modulo the prime of the centered coefficients whose
    /// little-endian words the bytes hold.
    fn residues(&self, bytes: &[u8], prime: usize) -> Vec<u64> {
        let (reduction, powers) = (&self.reductions[prime], &self.word_powers[prime]);
        let negated = self.negated_modulus[prime];
        let mut value = [0u64; MAXIMUM_WORDS];
        let value = &mut value[..self.words];
        bytes
            .chunks_exact(8 * self.words)
            .map(|coefficient| {
                read_words(coefficient, value);
                let negative = larger(value, &self.wide.half);
                words_residue(reduction, powers, value, if negative { negated } else { 0 })
            })
            .collect()
    }
    /// The four tensor products of two ciphertexts' components: component
    /// k / 2 of the first times component k % 2 of the second. Each source
    /// is transformed when its first product needs it and dropped after its
    /// last, so at most three are held. A square's two cross products are
    /// one product modulo every prime, so its two sources and that product
    /// are computed once.
    fn tensors(&self, first: &[Polynomial; 2], second: &[Polynomial; 2]) -> [Polynomial; 4] {
        let count = self.tensor_primes();
        let tensor = |left: &Transformed, right: &Transformed| {
            let products = self.products(left, right);
            self.lifted(&products, jobs::Lifted::Tensor)
        };
        let first_constant = self.transformed(&first[0], count);
        if std::ptr::eq(first, second) {
            let first_linear = self.transformed(&first[1], count);
            let constant = tensor(&first_constant, &first_constant);
            let cross = tensor(&first_constant, &first_linear);
            drop(first_constant);
            let quadratic = tensor(&first_linear, &first_linear);
            return [constant, cross.clone(), cross, quadratic];
        }
        let second_constant = self.transformed(&second[0], count);
        let constant = tensor(&first_constant, &second_constant);
        let second_linear = self.transformed(&second[1], count);
        let first_cross = tensor(&first_constant, &second_linear);
        drop(first_constant);
        let first_linear = self.transformed(&first[1], count);
        let quadratic = tensor(&first_linear, &second_linear);
        drop(second_linear);
        let second_cross = tensor(&first_linear, &second_constant);
        [constant, first_cross, second_cross, quadratic]
    }
    /// Each gadget digit of the canonical coefficients' residues modulo the
    /// prime, untransformed, from the coefficients' little-endian words.
    fn prime_digits(&self, bytes: &[u8], prime: usize) -> Vec<Vec<u64>> {
        let bits = Profile::gadget_base_bits();
        let parts = bits.div_ceil(64);
        let mut output: Vec<Vec<u64>> = (0..self.gadget_length)
            .map(|_| Vec::with_capacity(self.degree))
            .collect();
        let mut value = [0u64; MAXIMUM_WORDS];
        let value = &mut value[..self.words];
        let mut words = [0u64; MAXIMUM_WORDS];
        let words = &mut words[..parts];
        let (reduction, powers) = (&self.reductions[prime], &self.word_powers[prime]);
        for coefficient in bytes.chunks_exact(8 * self.words) {
            read_words(coefficient, value);
            for (digit, residues) in output.iter_mut().enumerate() {
                digit_words(value, bits * digit, bits, words);
                residues.push(words_residue(reduction, powers, words, 0));
            }
        }
        output
    }
    /// The product of two ciphertexts, relinearized with each gadget
    /// coordinate's encryption key, first relinearization key, second
    /// relinearization key and second relinearization common polynomial, in
    /// that key order.
    fn relinearized_product(
        &self,
        left: &[Polynomial; 2],
        right: &[Polynomial; 2],
        keys: &ResidentKeys,
    ) -> [Polynomial; 2] {
        let [mut constant, mut linear, other_linear, quadratic] = self.tensors(left, right);
        self.add(&mut linear, &other_linear);
        drop(other_linear);
        let [intermediate, quadratic_linear] = self.keyed(&quadratic, keys, 0);
        drop(quadratic);
        self.add(&mut linear, &quadratic_linear);
        drop(quadratic_linear);
        let [constant_term, linear_term] = self.keyed(&intermediate, keys, 2);
        self.add(&mut constant, &constant_term);
        self.add(&mut linear, &linear_term);
        [constant, linear]
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
    /// A ciphertext under the automorphism, switched back to the secret with
    /// each gadget coordinate's automorphism key and then its common
    /// polynomial.
    fn rotated(&self, value: &[Polynomial; 2], keys: &ResidentKeys) -> [Polynomial; 2] {
        let mut constant = self.automorphism(&value[0]);
        let [constant_term, linear] = self.keyed(&self.automorphism(&value[1]), keys, 0);
        self.add(&mut constant, &constant_term);
        [constant, linear]
    }
    fn add(&self, target: &mut Polynomial, other: &[u64]) {
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
mod tests {
    use super::*;
    use num_traits::Zero;

    // The profile's moduli, gadget and prime prefixes at a small ring degree,
    // checked against exact integer arithmetic.
    const TEST_DEGREE: usize = 16;

    fn profiles() -> Vec<Profile> {
        [(3, 2), (10, 10), (20, 20)]
            .into_iter()
            .map(|(participants, options)| Profile::new(participants, options).unwrap())
            .collect()
    }
    fn convolution(left: &[BigInt], right: &[BigInt]) -> Vec<BigInt> {
        let degree = left.len();
        let mut output = vec![BigInt::zero(); degree];
        for (first, left) in left.iter().enumerate() {
            for (second, right) in right.iter().enumerate() {
                let product = left * right;
                if first + second < degree {
                    output[first + second] += product;
                } else {
                    output[first + second - degree] -= product;
                }
            }
        }
        output
    }
    fn centered(arithmetic: &Arithmetic, polynomial: &[u64]) -> Vec<BigInt> {
        let half = BigInt::from(&arithmetic.modulus >> 1usize);
        arithmetic
            .coefficients(polynomial)
            .map(|value| {
                let value = BigInt::from(unpack(value));
                if value > half {
                    value - &arithmetic.signed_modulus
                } else {
                    value
                }
            })
            .collect()
    }
    fn canonical(arithmetic: &Arithmetic, values: Vec<BigInt>) -> Polynomial {
        let mut output = Vec::new();
        for value in values {
            arithmetic.push_normalized(&mut output, value);
        }
        output
    }
    fn plaintext(values: &[i64]) -> Vec<u64> {
        values
            .iter()
            .map(|value| value.rem_euclid(i64::from(PLAINTEXT_MODULUS)) as u64)
            .collect()
    }
    fn plaintext_product(left: &[i16], right: &[i16]) -> Vec<u64> {
        let integers = |values: &[i16]| {
            values
                .iter()
                .map(|value| BigInt::from(*value))
                .collect::<Vec<_>>()
        };
        plaintext(
            &convolution(&integers(left), &integers(right))
                .into_iter()
                .map(|value| value.to_i64().unwrap())
                .collect::<Vec<_>>(),
        )
    }
    fn plaintext_automorphism(values: &[i16]) -> Vec<u64> {
        let mut output = vec![0i64; values.len()];
        for (index, value) in values.iter().enumerate() {
            let exponent = index * 5;
            let sign = if (exponent / values.len()).is_multiple_of(2) {
                1
            } else {
                -1
            };
            output[exponent % values.len()] = sign * i64::from(*value);
        }
        plaintext(&output)
    }

    #[test]
    fn digit_residues_match_big_integer_digits_at_every_offset() {
        let prime = super::super::proth_prime(58, 1 << 58);
        let reduction = Modulus::new(prime).unwrap();
        let mut power = 1;
        let powers: Vec<(u64, u64)> = (0..16)
            .map(|_| {
                let current = (power, reduction.shoup(power));
                power = reduction.mul(power, ((1u128 << 64) % u128::from(prime)) as u64);
                current
            })
            .collect();
        for words in [9, 14, 16] {
            let mut state = 0x5eed ^ words as u64;
            let mut values: Vec<Vec<u64>> = vec![vec![u64::MAX; words], vec![0; words]];
            values.push((0..words).map(|_| next(&mut state)).collect());
            for value in values {
                let integer = unpack(&value);
                assert_eq!(
                    words_residue(&reduction, &powers, &value, 0),
                    (&integer % prime).to_u64().unwrap()
                );
                assert_eq!(
                    words_residue(&reduction, &powers, &value, prime - 1),
                    ((&integer + prime - 1u32) % prime).to_u64().unwrap()
                );
                for bits in [1, 63, 64, 65, 144] {
                    for start in [
                        0,
                        1,
                        63,
                        64,
                        100,
                        144 * 3,
                        64 * words - bits,
                        64 * words - 1,
                    ] {
                        let digit = (&integer >> start) & ((BigUint::from(1u32) << bits) - 1u32);
                        let mut output = vec![0; bits.div_ceil(64)];
                        digit_words(&value, start, bits, &mut output);
                        assert_eq!(
                            unpack(&output),
                            digit,
                            "words={words}, bits={bits}, start={start}"
                        );
                        assert_eq!(
                            words_residue(&reduction, &powers, &output, 0),
                            (digit % prime).to_u64().unwrap(),
                            "words={words}, bits={bits}, start={start}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn products_match_exact_negacyclic_convolution() {
        for profile in profiles() {
            let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
            assert_eq!(
                arithmetic.words,
                profile.ciphertext_modulus().bits().div_ceil(64)
            );
            let left = arithmetic.uniform(1);
            let right = arithmetic.uniform(2);
            // Plaintext coefficients at both ends of their range.
            let small: Vec<i16> = (0..TEST_DEGREE)
                .map(|index| [i16::MAX, i16::MIN, 0, 5][index % 4])
                .collect();
            let small = arithmetic.small(&small);
            let exact = convolution(
                &centered(&arithmetic, &left),
                &centered(&arithmetic, &small),
            );
            assert_eq!(
                arithmetic.multiply(&left, &small, false),
                canonical(&arithmetic, exact)
            );
            let exact = convolution(
                &centered(&arithmetic, &left),
                &centered(&arithmetic, &right),
            )
            .into_iter()
            .map(|value| {
                let rounded = (value.magnitude() * PLAINTEXT_MODULUS
                    + (&arithmetic.modulus >> 1usize))
                    / &arithmetic.modulus;
                if value.sign() == Sign::Minus {
                    -BigInt::from(rounded)
                } else {
                    BigInt::from(rounded)
                }
            })
            .collect();
            let tensor = arithmetic.multiply(&left, &right, true);
            assert_eq!(tensor, canonical(&arithmetic, exact));
            // Tensor k multiplies component k / 2 of the first ciphertext by
            // component k % 2 of the second.
            let tensors = arithmetic.tensors(
                &[left.clone(), right.clone()],
                &[right.clone(), left.clone()],
            );
            assert_eq!(tensors[0], tensor);
            assert_eq!(tensors[3], tensor);
            // A square's tensors equal those of the value and its copy.
            let value = [left, right];
            assert_eq!(
                arithmetic.tensors(&value, &value),
                arithmetic.tensors(&value, &value.clone())
            );
        }
    }

    // Each group's external product, alone or beside the next group's,
    // equals the exact sum of the gadget digits' products with its keys.
    #[test]
    fn keyed_products_match_exact_gadget_digit_sums() {
        let bits = Profile::gadget_base_bits();
        for profile in profiles() {
            let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
            assert_eq!(
                arithmetic.gadget_length,
                profile.ciphertext_modulus().bits().div_ceil(bits)
            );
            let value = arithmetic.uniform(3);
            let groups: Vec<Vec<Polynomial>> = (0..3)
                .map(|group| {
                    (0..arithmetic.gadget_length)
                        .map(|digit| arithmetic.uniform(10 + (8 * group + digit) as u64))
                        .collect()
                })
                .collect();
            let mut kept = ResidentKeys::new(&arithmetic);
            for key in groups.iter().flatten() {
                arithmetic.keep(&mut kept, key);
            }
            let mask = (BigUint::from(1u32) << bits) - 1u32;
            let exact = |keys: &[Polynomial]| {
                let mut exact = vec![BigInt::zero(); TEST_DEGREE];
                for (digit, key) in keys.iter().enumerate() {
                    let digits: Vec<BigInt> = arithmetic
                        .coefficients(&value)
                        .map(|coefficient| {
                            BigInt::from((unpack(coefficient) >> (bits * digit)) & &mask)
                        })
                        .collect();
                    for (sum, term) in exact
                        .iter_mut()
                        .zip(convolution(&digits, &centered(&arithmetic, key)))
                    {
                        *sum += term;
                    }
                }
                canonical(&arithmetic, exact)
            };
            let [second, third] = arithmetic.keyed(&value, &kept, 1);
            assert_eq!(second, exact(&groups[1]));
            assert_eq!(third, exact(&groups[2]));
            assert_eq!(arithmetic.keyed(&value, &kept, 0), [exact(&groups[0])]);
        }
    }

    #[test]
    fn relinearized_products_and_rotations_decrypt_to_the_plaintext_results() {
        for profile in profiles() {
            let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
            let weight = TEST_DEGREE / 2;
            let contributors = profile.setup_contributors();
            let secret_values = secret(TEST_DEGREE, contributors, weight, 0x1234_5678_9abc_def1);
            let auxiliary_values = secret(TEST_DEGREE, contributors, weight, 0x9876_5432_10ab_cdef);
            let secret = arithmetic.small(&secret_values);
            let auxiliary = arithmetic.small(&auxiliary_values);
            let rotated_secret = arithmetic.automorphism(&secret);
            let zeros = vec![0; TEST_DEGREE];
            let mut encryption = Vec::new();
            let mut first_relinearization = Vec::new();
            let mut second_relinearization = Vec::new();
            let mut rotation = Vec::new();
            let mut second_commons = Vec::new();
            let mut rotation_commons = Vec::new();
            for digit in 0..arithmetic.gadget_length {
                let gadget =
                    BigInt::from(BigUint::from(1u64) << (Profile::gadget_base_bits() * digit));
                let common = arithmetic.uniform(0x6a09_e667_f3bc_c909 ^ digit as u64);
                let second_common = arithmetic.uniform(0xbb67_ae85_84ca_a73b ^ digit as u64);
                let rotation_common = arithmetic.uniform(0x3c6e_f372_fe94_f82b ^ digit as u64);
                encryption.push(arithmetic.affine(
                    &arithmetic.multiply(&secret, &common, false),
                    true,
                    &zeros,
                    &BigInt::zero(),
                    -640,
                ));
                first_relinearization.push(arithmetic.affine(
                    &arithmetic.multiply(&auxiliary, &common, false),
                    true,
                    &secret_values,
                    &gadget,
                    630,
                ));
                second_relinearization.push(arithmetic.affine(
                    &arithmetic.multiply(&secret, &second_common, false),
                    true,
                    &auxiliary_values,
                    &-gadget.clone(),
                    -640,
                ));
                // The automorphism key encrypts the rotated secret times the
                // gadget coordinate.
                let mut key = arithmetic.affine(
                    &arithmetic.multiply(&secret, &rotation_common, false),
                    true,
                    &zeros,
                    &BigInt::zero(),
                    -640,
                );
                let mut shifted = Vec::new();
                for value in arithmetic.coefficients(&rotated_secret) {
                    arithmetic.push_normalized(&mut shifted, BigInt::from(unpack(value)) * &gadget);
                }
                arithmetic.add(&mut key, &shifted);
                rotation.push(key);
                second_commons.push(second_common);
                rotation_commons.push(rotation_common);
            }
            let keep = |groups: &[&[Polynomial]]| {
                let mut kept = ResidentKeys::new(&arithmetic);
                for key in groups.iter().copied().flatten() {
                    arithmetic.keep(&mut kept, key);
                }
                kept
            };
            let multiplication_keys = keep(&[
                &encryption,
                &first_relinearization,
                &second_relinearization,
                &second_commons,
            ]);
            let rotation_keys = keep(&[&rotation, &rotation_commons]);
            let delta =
                BigInt::from((&arithmetic.modulus + PLAINTEXT_MODULUS / 2) / PLAINTEXT_MODULUS);
            let encrypt = |plain: &[i16], seed| {
                let ephemeral = arithmetic.small(&ephemeral(TEST_DEGREE, weight, seed));
                let common = arithmetic.uniform(0x6a09_e667_f3bc_c909);
                [
                    arithmetic.affine(
                        &arithmetic.multiply(&ephemeral, &encryption[0], false),
                        false,
                        plain,
                        &delta,
                        63,
                    ),
                    arithmetic.affine(
                        &arithmetic.multiply(&ephemeral, &common, false),
                        false,
                        &zeros,
                        &BigInt::zero(),
                        -64,
                    ),
                ]
            };
            let first_plain: Vec<i16> = (0..TEST_DEGREE as i16)
                .map(|index| 3 * index - 17)
                .collect();
            let second_plain: Vec<i16> =
                (0..TEST_DEGREE as i16).map(|index| 7 - 2 * index).collect();
            let first = encrypt(&first_plain, 0x12ab_cdef_1234_5679);
            let second = encrypt(&second_plain, 0xfe01_9876_dcba_3211);
            assert_eq!(
                arithmetic.decode(&first, &secret),
                plaintext(
                    &first_plain
                        .iter()
                        .map(|value| i64::from(*value))
                        .collect::<Vec<_>>()
                )
            );
            let product = arithmetic.relinearized_product(&first, &second, &multiplication_keys);
            assert_eq!(
                arithmetic.decode(&product, &secret),
                plaintext_product(&first_plain, &second_plain),
                "profile={profile:?}"
            );
            let square = arithmetic.relinearized_product(&first, &first, &multiplication_keys);
            assert_eq!(
                arithmetic.decode(&square, &secret),
                plaintext_product(&first_plain, &first_plain),
                "profile={profile:?}"
            );
            let rotated = arithmetic.rotated(&first, &rotation_keys);
            assert_eq!(
                arithmetic.decode(&rotated, &secret),
                plaintext_automorphism(&first_plain),
                "profile={profile:?}"
            );
        }
    }
}
