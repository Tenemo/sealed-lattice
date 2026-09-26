use fhe_math::{ntt::NttOperator, rns::RnsContext, zq::Modulus};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{ToPrimitive, Zero};
use supported_profile::{FHE_SECRET_SUPPORT, PLAINTEXT_MODULUS, Profile};

#[path = "ranking.rs"]
pub mod ranking;

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
fn larger(left: &[u64], right: &[u64]) -> bool {
    left.iter().rev().cmp(right.iter().rev()).is_gt()
}
fn residue(value: &[u64], prime: u64) -> u64 {
    let mut result = 0u128;
    for word in value.iter().rev() {
        result = ((result << 64) | *word as u128) % prime as u128;
    }
    result as u64
}
/// Bits `start..start + bits` of a canonical coefficient modulo a prime, by
/// Horner's rule over the digit's 64-bit words from the most significant.
fn digit_residue(value: &[u64], start: usize, bits: usize, prime: u64) -> u64 {
    let mut result = 0u128;
    for word in (0..bits.div_ceil(64)).rev() {
        let bit = start + 64 * word;
        let index = bit / 64;
        let shift = bit % 64;
        let mut part = value.get(index).copied().unwrap_or(0) >> shift;
        if shift > 0 {
            part |= value.get(index + 1).copied().unwrap_or(0) << (64 - shift);
        }
        let width = bits - 64 * word;
        if width < 64 {
            part &= (1 << width) - 1;
        }
        result = ((result << 64) | part as u128) % prime as u128;
    }
    result as u64
}
/// The least prefix of the primes whose product exceeds the bound.
fn prefix(primes: &[u64], bound: &BigUint) -> usize {
    let mut product = BigUint::from(1u32);
    for (index, prime) in primes.iter().enumerate() {
        product *= *prime;
        if &product > bound {
            return index + 1;
        }
    }
    panic!("The tensor primes exceed every smaller bound.");
}

struct Arithmetic {
    degree: usize,
    words: usize,
    gadget_length: usize,
    modulus: BigUint,
    signed_modulus: BigInt,
    half: Vec<u64>,
    primes: Vec<u64>,
    reductions: Vec<Modulus>,
    transforms: Vec<NttOperator>,
    modulus_residues: Vec<u64>,
    key_primes: usize,
    external_primes: usize,
    key_context: RnsContext,
    external_context: RnsContext,
    tensor_context: RnsContext,
}

impl Arithmetic {
    /// Exact arithmetic modulo the profile's ciphertext modulus. Plaintext
    /// and secret products, gadget external products and ciphertext tensors
    /// each lift from the least prefix of the primes whose product exceeds
    /// twice their centered bound.
    fn new(profile: Profile, degree: usize) -> Self {
        let ciphertext = profile.ciphertext_modulus();
        let modulus = (BigUint::from(ciphertext.odd_factor()) << ciphertext.exponent()) + 1u64;
        let words = ciphertext.bits().div_ceil(64);
        let gadget_length = profile.gadget_length();
        let half_modulus = &modulus >> 1usize;
        let degree_factor = degree as u64;
        // A plaintext coefficient is at most half the plaintext modulus and
        // an aggregate secret's one-norm is at most one support per setup
        // contributor.
        let key_bound = 2u64
            * (degree_factor * u64::from(PLAINTEXT_MODULUS / 2))
                .max((profile.setup_contributors() * FHE_SECRET_SUPPORT) as u64)
            * &half_modulus;
        let external_bound = 2u64
            * gadget_length as u64
            * degree_factor
            * ((BigUint::from(1u64) << Profile::gadget_base_bits()) - 1u64)
            * &half_modulus;
        let tensor_bound = 2u64 * degree_factor * &half_modulus * &half_modulus;
        let mut primes = Vec::new();
        let mut product = BigUint::from(1u64);
        let mut limit = 1u64 << 58;
        while product <= tensor_bound {
            limit = super::proth_prime(58, limit);
            primes.push(limit);
            product *= limit;
        }
        let key_primes = prefix(&primes, &key_bound);
        let external_primes = prefix(&primes, &external_bound);
        assert!(key_primes <= external_primes);
        let reductions: Vec<Modulus> = primes
            .iter()
            .map(|prime| Modulus::new(*prime).unwrap())
            .collect();
        let transforms = reductions
            .iter()
            .map(|prime| NttOperator::new(prime, degree).unwrap())
            .collect();
        let mut half = Vec::with_capacity(words);
        push_words(&mut half, &half_modulus, words);
        Self {
            degree,
            words,
            gadget_length,
            signed_modulus: BigInt::from(modulus.clone()),
            half,
            modulus_residues: primes
                .iter()
                .map(|prime| (&modulus % prime).to_u64().unwrap())
                .collect(),
            modulus,
            key_primes,
            external_primes,
            key_context: RnsContext::new(&primes[..key_primes]).unwrap(),
            external_context: RnsContext::new(&primes[..external_primes]).unwrap(),
            tensor_context: RnsContext::new(&primes).unwrap(),
            primes,
            reductions,
            transforms,
        }
    }
    fn tensor_primes(&self) -> usize {
        self.primes.len()
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
    fn push(&self, output: &mut Polynomial, value: &BigUint) {
        push_words(output, value, self.words);
    }
    fn push_normalized(&self, output: &mut Polynomial, value: BigInt) {
        let mut value = value % &self.signed_modulus;
        if value.sign() == Sign::Minus {
            value += &self.signed_modulus;
        }
        self.push(output, value.magnitude());
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
    fn project(&self, polynomial: &[u64], prime: usize) -> Vec<u64> {
        self.coefficients(polynomial)
            .map(|value| {
                let current = residue(value, self.primes[prime]);
                if larger(value, &self.half) {
                    self.reductions[prime].sub(current, self.modulus_residues[prime])
                } else {
                    current
                }
            })
            .collect()
    }
    fn finish(
        &self,
        mut products: Vec<Vec<u64>>,
        context: &RnsContext,
        tensor: bool,
    ) -> Polynomial {
        for (index, values) in products.iter_mut().enumerate() {
            self.transforms[index].backward(values);
        }
        let half_context = context.modulus() >> 1usize;
        let mut residues = vec![0; products.len()];
        let mut output = Vec::with_capacity(self.polynomial_words());
        for position in 0..self.degree {
            for (residue, values) in residues.iter_mut().zip(&products) {
                *residue = values[position];
            }
            let value = context.lift((&residues).into());
            let negative = value > half_context;
            let magnitude = if negative {
                context.modulus() - value
            } else {
                value
            };
            let reduced = if tensor {
                (magnitude * PLAINTEXT_MODULUS + (&self.modulus >> 1usize)) / &self.modulus
                    % &self.modulus
            } else {
                magnitude % &self.modulus
            };
            if negative && !reduced.is_zero() {
                self.push(&mut output, &(&self.modulus - reduced));
            } else {
                self.push(&mut output, &reduced);
            }
        }
        output
    }
    fn multiply(&self, left: &[u64], right: &[u64], tensor: bool) -> Polynomial {
        let count = if tensor {
            self.tensor_primes()
        } else {
            self.key_primes
        };
        let mut products = Vec::with_capacity(count);
        for index in 0..count {
            let mut first = self.project(left, index);
            let mut second = self.project(right, index);
            self.transforms[index].forward(&mut first);
            self.transforms[index].forward(&mut second);
            for (first, second) in first.iter_mut().zip(second) {
                *first = self.reductions[index].mul(*first, second);
            }
            products.push(first);
        }
        self.finish(
            products,
            if tensor {
                &self.tensor_context
            } else {
                &self.key_context
            },
            tensor,
        )
    }
    fn transformed(&self, value: &[u64], count: usize) -> Transformed {
        (0..count)
            .map(|prime| {
                let mut projected = self.project(value, prime);
                self.transforms[prime].forward(&mut projected);
                projected
            })
            .collect()
    }
    fn tensors(&self, first: &[Polynomial; 2], second: &[Polynomial; 2]) -> [Polynomial; 4] {
        let count = self.tensor_primes();
        let sources: Vec<Transformed> = first
            .iter()
            .chain(second)
            .map(|polynomial| self.transformed(polynomial, count))
            .collect();
        std::array::from_fn(|index| {
            let left = index / 2;
            let right = 2 + index % 2;
            let products = (0..count)
                .map(|prime| {
                    sources[left][prime]
                        .iter()
                        .zip(&sources[right][prime])
                        .map(|(left, right)| self.reductions[prime].mul(*left, *right))
                        .collect()
                })
                .collect();
            self.finish(products, &self.tensor_context, true)
        })
    }
    /// Each gadget digit of the canonical coefficients, transformed modulo
    /// every external-product prime.
    fn digit_transforms(&self, value: &[u64]) -> Vec<Transformed> {
        let bits = Profile::gadget_base_bits();
        (0..self.gadget_length)
            .map(|digit| {
                (0..self.external_primes)
                    .map(|prime| {
                        let mut digits: Vec<u64> = self
                            .coefficients(value)
                            .map(|value| {
                                digit_residue(value, bits * digit, bits, self.primes[prime])
                            })
                            .collect();
                        self.transforms[prime].forward(&mut digits);
                        digits
                    })
                    .collect()
            })
            .collect()
    }
    fn external(&self, digits: &[Transformed], keys: &[Transformed]) -> Polynomial {
        assert_eq!(keys.len(), self.gadget_length);
        assert_eq!(digits.len(), self.gadget_length);
        let mut products = vec![vec![0u64; self.degree]; self.external_primes];
        for (digit, key) in digits.iter().zip(keys) {
            for (prime, product) in products.iter_mut().enumerate() {
                for ((sum, digit), key) in product.iter_mut().zip(&digit[prime]).zip(&key[prime]) {
                    *sum =
                        self.reductions[prime].add(*sum, self.reductions[prime].mul(*digit, *key));
                }
            }
        }
        self.finish(products, &self.external_context, false)
    }
    /// The product of two ciphertexts, relinearized with each gadget
    /// coordinate's encryption key, first relinearization key, second
    /// relinearization key and second relinearization common polynomial, in
    /// that key order.
    fn relinearized_product(
        &self,
        left: &[Polynomial; 2],
        right: &[Polynomial; 2],
        keys: &[Transformed],
    ) -> [Polynomial; 2] {
        let group =
            |index: usize| &keys[index * self.gadget_length..(index + 1) * self.gadget_length];
        let [mut constant, mut linear, other_linear, quadratic] = self.tensors(left, right);
        self.add(&mut linear, &other_linear);
        drop(other_linear);
        let digits = self.digit_transforms(&quadratic);
        let intermediate = self.external(&digits, group(0));
        self.add(&mut linear, &self.external(&digits, group(1)));
        drop(digits);
        drop(quadratic);
        let digits = self.digit_transforms(&intermediate);
        self.add(&mut constant, &self.external(&digits, group(2)));
        self.add(&mut linear, &self.external(&digits, group(3)));
        [constant, linear]
    }
    /// The automorphism X to X^5, which rotates the plaintext slots.
    fn automorphism(&self, polynomial: &[u64]) -> Polynomial {
        let mut output = self.zero();
        for (index, value) in self.coefficients(polynomial).enumerate() {
            let exponent = index * 5;
            let position = exponent % self.degree;
            let target = &mut output[position * self.words..(position + 1) * self.words];
            if (exponent / self.degree).is_multiple_of(2) || value.iter().all(|word| *word == 0) {
                target.copy_from_slice(value);
            } else {
                let mut negated = Vec::with_capacity(self.words);
                self.push(&mut negated, &(&self.modulus - unpack(value)));
                target.copy_from_slice(&negated);
            }
        }
        output
    }
    /// A ciphertext under the automorphism, switched back to the secret with
    /// each gadget coordinate's automorphism key and then its common
    /// polynomial.
    fn rotated(&self, value: &[Polynomial; 2], keys: &[Transformed]) -> [Polynomial; 2] {
        let mut constant = self.automorphism(&value[0]);
        let shifted = self.automorphism(&value[1]);
        let digits = self.digit_transforms(&shifted);
        self.add(
            &mut constant,
            &self.external(&digits, &keys[..self.gadget_length]),
        );
        [
            constant,
            self.external(&digits, &keys[self.gadget_length..2 * self.gadget_length]),
        ]
    }
    fn add(&self, target: &mut Polynomial, other: &[u64]) {
        let mut output = Vec::with_capacity(target.len());
        for (target, other) in self.coefficients(target).zip(self.coefficients(other)) {
            self.push(
                &mut output,
                &((unpack(target) + unpack(other)) % &self.modulus),
            );
        }
        *target = output;
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
fn push_words(output: &mut Vec<u64>, value: &BigUint, words: usize) {
    let digits = value.to_u64_digits();
    assert!(digits.len() <= words);
    output.extend(&digits);
    output.resize(output.len() + words - digits.len(), 0);
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
        for words in [9, 14, 16] {
            let mut state = 0x5eed ^ words as u64;
            let value: Vec<u64> = (0..words).map(|_| next(&mut state)).collect();
            let integer = unpack(&value);
            for bits in [1, 63, 64, 65, 144] {
                for start in [0, 1, 63, 64, 100, 144 * 3, 64 * words - bits] {
                    let digit = (&integer >> start) & ((BigUint::from(1u32) << bits) - 1u32);
                    assert_eq!(
                        digit_residue(&value, start, bits, prime),
                        (digit % prime).to_u64().unwrap(),
                        "words={words}, bits={bits}, start={start}"
                    );
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
            let tensors = arithmetic.tensors(&[left.clone(), right.clone()], &[right, left]);
            assert_eq!(tensors[0], tensor);
            assert_eq!(tensors[3], tensor);
        }
    }

    #[test]
    fn external_products_match_exact_gadget_digit_sums() {
        let bits = Profile::gadget_base_bits();
        for profile in profiles() {
            let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
            assert_eq!(
                arithmetic.gadget_length,
                profile.ciphertext_modulus().bits().div_ceil(bits)
            );
            let value = arithmetic.uniform(3);
            let keys: Vec<Polynomial> = (0..arithmetic.gadget_length)
                .map(|digit| arithmetic.uniform(10 + digit as u64))
                .collect();
            let transformed: Vec<Transformed> = keys
                .iter()
                .map(|key| arithmetic.transformed(key, arithmetic.external_primes))
                .collect();
            let mask = (BigUint::from(1u32) << bits) - 1u32;
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
            assert_eq!(
                arithmetic.external(&arithmetic.digit_transforms(&value), &transformed),
                canonical(&arithmetic, exact)
            );
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
            let transform = |values: &[Polynomial]| -> Vec<Transformed> {
                values
                    .iter()
                    .map(|value| arithmetic.transformed(value, arithmetic.external_primes))
                    .collect()
            };
            let multiplication_keys = [
                transform(&encryption),
                transform(&first_relinearization),
                transform(&second_relinearization),
                transform(&second_commons),
            ]
            .concat();
            let rotation_keys = [transform(&rotation), transform(&rotation_commons)].concat();
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
            let rotated = arithmetic.rotated(&first, &rotation_keys);
            assert_eq!(
                arithmetic.decode(&rotated, &secret),
                plaintext_automorphism(&first_plain),
                "profile={profile:?}"
            );
        }
    }
}
