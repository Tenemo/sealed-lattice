use fhe_math::{ntt::NttOperator, rns::RnsContext, zq::Modulus};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{ToPrimitive, Zero};
use sha2::{Digest, Sha512};

#[path = "ranking.rs"]
pub mod ranking;

type Coefficient = [u64; 14];
type Polynomial = Vec<Coefficient>;
type Transformed = Vec<Vec<u64>>;

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn unpack(value: &Coefficient) -> BigUint {
    BigUint::from_bytes_le(
        &value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}
fn pack(value: &BigUint) -> Coefficient {
    let words = value.to_u64_digits();
    assert!(words.len() <= 14);
    std::array::from_fn(|index| words.get(index).copied().unwrap_or(0))
}
fn larger(left: &Coefficient, right: &Coefficient) -> bool {
    left.iter().rev().cmp(right.iter().rev()).is_gt()
}
fn residue(value: &Coefficient, prime: u64) -> u64 {
    let mut result = 0u128;
    for word in value.iter().rev() {
        result = ((result << 64) | *word as u128) % prime as u128;
    }
    result as u64
}

struct Arithmetic {
    degree: usize,
    modulus: BigUint,
    signed_modulus: BigInt,
    half: Coefficient,
    primes: Vec<u64>,
    reductions: Vec<Modulus>,
    transforms: Vec<NttOperator>,
    modulus_residues: Vec<u64>,
    key_context: RnsContext,
    external_context: RnsContext,
    tensor_context: RnsContext,
}

impl Arithmetic {
    fn new(degree: usize) -> Self {
        let modulus = ((BigUint::from(65537u64) * 65319u64) << 832usize) + 1u64;
        let mut limit = 1u64 << 58;
        let primes: Vec<u64> = (0..31)
            .map(|_| {
                limit = super::proth_prime(58, limit);
                limit
            })
            .collect();
        let reductions: Vec<Modulus> = primes
            .iter()
            .map(|prime| Modulus::new(*prime).unwrap())
            .collect();
        let transforms = reductions
            .iter()
            .map(|prime| NttOperator::new(prime, degree).unwrap())
            .collect();
        let key_context = RnsContext::new(&primes[..16]).unwrap();
        let external_context = RnsContext::new(&primes[..18]).unwrap();
        let tensor_context = RnsContext::new(&primes).unwrap();
        let half_modulus = &modulus >> 1usize;
        assert!(key_context.modulus() > &(2u64 * 10u64 * 1024u64 * &half_modulus));
        assert!(key_context.modulus() > &(2u64 * degree as u64 * 32768u64 * &half_modulus));
        assert!(
            external_context.modulus()
                > &(12u64
                    * degree as u64
                    * ((BigUint::from(1u64) << 144usize) - 1u64)
                    * &half_modulus)
        );
        assert!(tensor_context.modulus() > &(2u64 * degree as u64 * &half_modulus * &half_modulus));
        Self {
            degree,
            signed_modulus: BigInt::from(modulus.clone()),
            half: pack(&half_modulus),
            modulus_residues: primes
                .iter()
                .map(|prime| (&modulus % prime).to_u64().unwrap())
                .collect(),
            modulus,
            primes,
            reductions,
            transforms,
            key_context,
            external_context,
            tensor_context,
        }
    }
    fn normalize(&self, value: BigInt) -> Coefficient {
        let mut value = value % &self.signed_modulus;
        if value.sign() == Sign::Minus {
            value += &self.signed_modulus;
        }
        pack(value.magnitude())
    }
    fn uniform(&self, mut seed: u64) -> Polynomial {
        (0..self.degree)
            .map(|_| {
                let bytes: Vec<u8> = (0..15)
                    .flat_map(|_| next(&mut seed).to_le_bytes())
                    .collect();
                pack(&(BigUint::from_bytes_le(&bytes) % &self.modulus))
            })
            .collect()
    }
    fn small(&self, values: &[i16]) -> Polynomial {
        assert_eq!(values.len(), self.degree);
        values
            .iter()
            .map(|value| self.normalize(BigInt::from(*value)))
            .collect()
    }
    fn project(&self, polynomial: &Polynomial, prime: usize) -> Vec<u64> {
        polynomial
            .iter()
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
        let mut output = Vec::with_capacity(self.degree);
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
                (magnitude * 65537u64 + (&self.modulus >> 1usize)) / &self.modulus % &self.modulus
            } else {
                magnitude % &self.modulus
            };
            output.push(if negative && !reduced.is_zero() {
                pack(&(&self.modulus - reduced))
            } else {
                pack(&reduced)
            });
        }
        output
    }
    fn multiply(&self, left: &Polynomial, right: &Polynomial, tensor: bool) -> Polynomial {
        let count = if tensor { 31 } else { 16 };
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
    fn transformed(&self, value: &Polynomial, count: usize) -> Transformed {
        (0..count)
            .map(|prime| {
                let mut projected = self.project(value, prime);
                self.transforms[prime].forward(&mut projected);
                projected
            })
            .collect()
    }
    fn tensors(&self, first: &[Polynomial; 2], second: &[Polynomial; 2]) -> [Polynomial; 4] {
        let sources: Vec<Transformed> = first
            .iter()
            .chain(second)
            .map(|polynomial| self.transformed(polynomial, 31))
            .collect();
        std::array::from_fn(|index| {
            let left = index / 2;
            let right = 2 + index % 2;
            let products = (0..31)
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
    fn digit_transforms(&self, value: &Polynomial) -> Vec<Transformed> {
        let mut all = Vec::with_capacity(6);
        for digit in 0..6 {
            let start = 144 * digit;
            let mut encoded = Vec::with_capacity(18);
            for prime in 0..18 {
                let mut digits: Vec<u64> = value
                    .iter()
                    .map(|value| {
                        let mut result = 0u128;
                        for word in (0..3).rev() {
                            let bit = start + 64 * word;
                            let index = bit / 64;
                            let shift = bit % 64;
                            let mut part = value.get(index).copied().unwrap_or(0) >> shift;
                            if shift > 0 {
                                part |= value.get(index + 1).copied().unwrap_or(0) << (64 - shift);
                            }
                            if word == 2 {
                                part &= 0xffff;
                            }
                            result = ((result << 64) | part as u128) % self.primes[prime] as u128;
                        }
                        result as u64
                    })
                    .collect();
                self.transforms[prime].forward(&mut digits);
                encoded.push(digits);
            }
            all.push(encoded);
        }
        all
    }
    fn external(&self, digits: &[Transformed], keys: &[Transformed]) -> Polynomial {
        assert_eq!(keys.len(), 6);
        assert_eq!(digits.len(), 6);
        let mut products = vec![vec![0u64; self.degree]; 18];
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
    fn add(&self, target: &mut Polynomial, other: &Polynomial) {
        for (target, other) in target.iter_mut().zip(other) {
            *target = pack(&((unpack(target) + unpack(other)) % &self.modulus));
        }
    }
    fn affine(
        &self,
        base: &Polynomial,
        negative: bool,
        small: &[i16],
        multiplier: &BigInt,
        error: i64,
    ) -> Polynomial {
        base.iter()
            .zip(small)
            .map(|(base, small)| {
                let base = BigInt::from(unpack(base));
                self.normalize(if negative { -base } else { base } + multiplier * *small + error)
            })
            .collect()
    }
    fn decode(&self, ciphertext: &[Polynomial; 2], secret: &Polynomial) -> Vec<u64> {
        let mut phase = self.multiply(secret, &ciphertext[1], false);
        self.add(&mut phase, &ciphertext[0]);
        phase
            .iter()
            .map(|value| {
                (((unpack(value) * 65537u64 + (&self.modulus >> 1usize)) / &self.modulus)
                    % 65537u64)
                    .to_u64()
                    .unwrap()
            })
            .collect()
    }
}

fn secret(degree: usize, weight: usize, mut seed: u64) -> Vec<i16> {
    let mut result = vec![0; degree];
    for _ in 0..10 {
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

pub fn probe(log_degree: u32) -> String {
    assert!((3..=16).contains(&log_degree));
    let degree = 1usize << log_degree;
    let support_weight = 1024.min(degree / 2);
    super::benchmark_phase(0);
    let arithmetic = Arithmetic::new(degree);
    let secret_values = secret(degree, support_weight, 0x1234_5678_9abc_def1);
    let auxiliary_values = secret(degree, support_weight, 0x9876_5432_10ab_cdef);
    let secret = arithmetic.small(&secret_values);
    let auxiliary = arithmetic.small(&auxiliary_values);
    let zeros = vec![0; degree];
    let mut public_keys = Vec::new();
    let mut first_relinearization = Vec::new();
    let mut second_relinearization = Vec::new();
    for digit in 0..6 {
        let common = arithmetic.uniform(0x6a09_e667_f3bc_c909 ^ digit as u64);
        let second_common = arithmetic.uniform(0xbb67_ae85_84ca_a73b ^ digit as u64);
        let gadget = BigInt::from(BigUint::from(1u64) << (144 * digit));
        public_keys.push(arithmetic.affine(
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
            &-gadget,
            -640,
        ));
    }
    drop(auxiliary);
    super::benchmark_phase(1);
    let mut first_plain = vec![0i16; degree];
    first_plain[0] = 17;
    first_plain[2] = -29;
    first_plain[degree - 2] = 10;
    let mut second_plain = vec![0i16; degree];
    second_plain[0] = -7;
    second_plain[4] = 3;
    second_plain[degree - 4] += 11;
    let delta = BigInt::from((&arithmetic.modulus + 32768u64) / 65537u64);
    let encrypt = |plain: &[i16], seed| {
        let ephemeral = arithmetic.small(&ephemeral(degree, support_weight, seed));
        let common = arithmetic.uniform(0x6a09_e667_f3bc_c909);
        let first = arithmetic.affine(
            &arithmetic.multiply(&ephemeral, &public_keys[0], false),
            false,
            plain,
            &delta,
            63,
        );
        let second = arithmetic.affine(
            &arithmetic.multiply(&ephemeral, &common, false),
            false,
            &zeros,
            &BigInt::zero(),
            -64,
        );
        [first, second]
    };
    let first = encrypt(&first_plain, 0x12ab_cdef_1234_5679);
    let second = encrypt(&second_plain, 0xfe01_9876_dcba_3211);
    let canonical = |values: &[i16]| {
        values
            .iter()
            .map(|value| (*value as i64).rem_euclid(65537) as u64)
            .collect::<Vec<_>>()
    };
    assert_eq!(arithmetic.decode(&first, &secret), canonical(&first_plain));
    assert_eq!(
        arithmetic.decode(&second, &secret),
        canonical(&second_plain)
    );
    super::benchmark_phase(2);
    let public_keys: Vec<Transformed> = public_keys
        .into_iter()
        .map(|polynomial| arithmetic.transformed(&polynomial, 18))
        .collect();
    let first_relinearization: Vec<Transformed> = first_relinearization
        .into_iter()
        .map(|polynomial| arithmetic.transformed(&polynomial, 18))
        .collect();
    let second_relinearization: Vec<Transformed> = second_relinearization
        .into_iter()
        .map(|polynomial| arithmetic.transformed(&polynomial, 18))
        .collect();
    let common: Vec<Transformed> = (0..6)
        .map(|digit| arithmetic.transformed(&arithmetic.uniform(0xbb67_ae85_84ca_a73b ^ digit), 18))
        .collect();
    super::benchmark_phase(3);
    let [mut constant, mut linear, other_linear, quadratic] = arithmetic.tensors(&first, &second);
    drop(first);
    drop(second);
    arithmetic.add(&mut linear, &other_linear);
    drop(other_linear);
    super::benchmark_phase(4);
    let digits = arithmetic.digit_transforms(&quadratic);
    let intermediate = arithmetic.external(&digits, &public_keys);
    arithmetic.add(
        &mut linear,
        &arithmetic.external(&digits, &first_relinearization),
    );
    drop(digits);
    drop(quadratic);
    let digits = arithmetic.digit_transforms(&intermediate);
    arithmetic.add(
        &mut constant,
        &arithmetic.external(&digits, &second_relinearization),
    );
    arithmetic.add(&mut linear, &arithmetic.external(&digits, &common));
    drop(digits);
    super::benchmark_phase(5);
    let result = [constant, linear];
    let decoded = arithmetic.decode(&result, &secret);
    let mut expected = vec![0i64; degree];
    let first_nonzero: Vec<_> = first_plain
        .iter()
        .enumerate()
        .filter(|(_, value)| **value != 0)
        .collect();
    let second_nonzero: Vec<_> = second_plain
        .iter()
        .enumerate()
        .filter(|(_, value)| **value != 0)
        .collect();
    for (first_index, first_value) in first_nonzero {
        for (second_index, second_value) in &second_nonzero {
            let position = first_index + second_index;
            expected[position % degree] += if position >= degree { -1 } else { 1 }
                * *first_value as i64
                * **second_value as i64;
        }
    }
    assert_eq!(
        decoded,
        expected
            .iter()
            .map(|value| value.rem_euclid(65537) as u64)
            .collect::<Vec<_>>()
    );
    super::benchmark_phase(6);
    let mut digest = Sha512::new();
    for polynomial in &result {
        for coefficient in polynomial {
            for word in coefficient {
                digest.update(word.to_le_bytes());
            }
        }
    }
    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{{\"degree\":{degree},\"participants\":10,\"secretSupportPerContributor\":{support_weight},\"gadgetBits\":144,\"gadgetLength\":6,\"decodedCoefficientsChecked\":{degree},\"digest\":\"{digest}\"}}"
    )
}
