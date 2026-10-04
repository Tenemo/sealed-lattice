use crate::context::BallotComputationContext;
use crate::{
    convolution::{Plan, RADIX, RADIX_BITS, digit},
    gaussian,
    packing::PackingWitness,
    reduction,
};
use num_bigint::{BigInt, Sign};
use registration_credentials::poll::VerifiedPoll;
use setup_aggregate::RetainedAggregatePolynomial;
use supported_profile::{
    AUXILIARY_DEGREE, AUXILIARY_PLAINTEXT_MODULUS, AUXILIARY_SECRET_SUPPORT, FHE_SECRET_SUPPORT,
    Family, PLAINTEXT_MODULUS, Profile,
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Refusal {
    Context,
    Scores,
    Randomness,
    Arithmetic,
}

/// Each encryption reads its own randomness in blocks of this many bytes:
/// a word for each sparse-secret draw, then one sample for each error
/// coefficient.
const READ_BYTES: usize = 65_536;
const DRAW_BYTES: usize = 4;
const SAMPLE_BYTES: usize = 20;

struct Random {
    bytes: Zeroizing<Vec<u8>>,
    cursor: usize,
}
impl Random {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; READ_BYTES]),
            cursor: READ_BYTES,
        }
    }
    fn read<const N: usize>(&mut self) -> Result<Zeroizing<[u8; N]>, Refusal> {
        let mut result = Zeroizing::new([0; N]);
        let mut filled = 0;
        while filled < N {
            if self.cursor == self.bytes.len() {
                #[cfg(not(target_arch = "wasm32"))]
                getrandom::fill(&mut self.bytes).map_err(|_| Refusal::Randomness)?;
                #[cfg(target_arch = "wasm32")]
                {
                    #[link(wasm_import_module = "ballot")]
                    unsafe extern "C" {
                        fn fill_random(pointer: *mut u8, length: usize) -> u32;
                    }
                    // SAFETY: the host receives this live writable buffer and its exact bound.
                    if unsafe { fill_random(self.bytes.as_mut_ptr(), self.bytes.len()) } != 0 {
                        return Err(Refusal::Randomness);
                    }
                }
                self.cursor = 0;
            }
            let count = (N - filled).min(self.bytes.len() - self.cursor);
            result[filled..filled + count]
                .copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
            self.bytes[self.cursor..self.cursor + count].fill(0);
            self.cursor += count;
            filled += count;
        }
        Ok(result)
    }
    fn sparse(&mut self, degree: usize, support: usize) -> Result<Zeroizing<Vec<i8>>, Refusal> {
        let mut values = Zeroizing::new(vec![0; degree]);
        let mut selected = 0;
        while selected < support {
            let position = u32::from_le_bytes(*self.read::<DRAW_BYTES>()?) as usize % degree;
            if values[position] == 0 {
                values[position] = if selected < support / 2 { 1 } else { -1 };
                selected += 1;
            }
        }
        Ok(values)
    }
    fn errors(&mut self, degree: usize) -> Result<Zeroizing<Vec<i8>>, Refusal> {
        (0..degree)
            .map(|_| Ok(gaussian::sample(&*self.read::<SAMPLE_BYTES>()?) as i8))
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
    }
}

pub struct CiphertextComponent {
    pub coefficients: Vec<BigInt>,
    pub quotients: Zeroizing<Vec<i16>>,
    pub carries: Zeroizing<Vec<Vec<i16>>>,
    pub errors: Zeroizing<Vec<i8>>,
}
pub struct EncryptionWitness {
    pub key: Vec<BigInt>,
    pub common: Vec<BigInt>,
    pub ephemeral: Zeroizing<Vec<i8>>,
    pub components: [CiphertextComponent; 2],
}

struct ComponentInput<'a> {
    public: &'a [BigInt],
    modulus: &'a BigInt,
    scale: &'a BigInt,
    message: Option<&'a [i32]>,
    errors: Zeroizing<Vec<i8>>,
}
fn component(
    plan: &Plan,
    ephemeral: &[i8],
    transformed: &[u128],
    input: ComponentInput<'_>,
) -> Result<CiphertextComponent, Refusal> {
    let ComponentInput {
        public,
        modulus,
        scale,
        message,
        errors,
    } = input;
    let degree = public.len();
    let modulus_bytes = modulus.to_bytes_le().1;
    let reducer = reduction::Modulus::new(&modulus_bytes, RADIX_BITS).ok_or(Refusal::Arithmetic)?;
    let limbs = reducer.digits.len();
    if errors.len() != degree || message.is_some_and(|value| value.len() != degree) {
        return Err(Refusal::Arithmetic);
    }
    let products =
        Zeroizing::new(plan.digit_products(public, ephemeral, transformed, limbs, RADIX_BITS));
    let mut coefficients = Vec::with_capacity(degree);
    let mut quotients = Zeroizing::new(Vec::with_capacity(degree));
    for position in 0..degree {
        let mut raw = Zeroizing::new(vec![0i128; limbs]);
        for limb in 0..limbs {
            raw[limb] = products[limb][position]
                + if limb == 0 {
                    i128::from(errors[position])
                } else {
                    0
                }
                + message.map_or(0, |values| {
                    digit(scale, limb) * i128::from(values[position])
                });
        }
        let mut reduced = vec![0u128; limbs];
        let result = reducer
            .reduce(&raw, &mut reduced)
            .ok_or(Refusal::Arithmetic)?;
        let magnitude = reduced.iter().rev().fold(BigInt::from(0), |sum, value| {
            (sum << RADIX_BITS) + BigInt::from(*value)
        });
        coefficients.push(if result.negative {
            -magnitude
        } else {
            magnitude
        });
        quotients.push(i16::try_from(result.quotient).map_err(|_| Refusal::Arithmetic)?);
    }
    let mut carries = Zeroizing::new(vec![vec![0i16; degree]; limbs - 1]);
    for position in 0..degree {
        let mut carry = 0i128;
        for limb in 0..limbs {
            let row = products[limb][position] - digit(&coefficients[position], limb)
                + message.map_or(0, |values| {
                    digit(scale, limb) * i128::from(values[position])
                })
                + if limb == 0 {
                    i128::from(errors[position])
                } else {
                    0
                }
                - digit(modulus, limb) * i128::from(quotients[position])
                + carry;
            if limb + 1 < limbs {
                if row % RADIX != 0 {
                    return Err(Refusal::Arithmetic);
                }
                carry = row / RADIX;
                carries[limb][position] = i16::try_from(carry).map_err(|_| Refusal::Arithmetic)?;
            } else if row != 0 {
                return Err(Refusal::Arithmetic);
            }
        }
    }
    Ok(CiphertextComponent {
        coefficients,
        quotients,
        carries,
        errors,
    })
}

/// A ballot encrypts under the first gadget coordinate's FHE encryption key
/// and under the auxiliary key.
pub fn fhe_key_polynomial(profile: Profile) -> usize {
    profile.fhe_polynomial(0, 1)
}
impl EncryptionWitness {
    /// Encrypts under the digest-checked FHE aggregate key. Auxiliary
    /// encryption has no caller-supplied key or retained setup operand.
    pub fn create(
        profile: Profile,
        key: RetainedAggregatePolynomial,
        message: &[i32],
    ) -> Result<Self, Refusal> {
        if key.index() != fhe_key_polynomial(profile) {
            return Err(Refusal::Context);
        }
        let common =
            setup_witness::contribution::common_polynomial(profile, profile.fhe_polynomial(0, 0))
                .map_err(|_| Refusal::Context)?;
        Self::encrypt(
            key.into_coefficients(),
            common,
            &profile.family_modulus(Family::Fhe),
            PLAINTEXT_MODULUS,
            FHE_SECRET_SUPPORT,
            message,
        )
    }
    /// Encrypts under the two fixed-suite public streams. No participant
    /// has an auxiliary secret or can select either public coordinate.
    pub fn create_auxiliary(message: &[i32]) -> Result<Self, Refusal> {
        Self::encrypt(
            setup_witness::fixed_auxiliary::public_key(),
            setup_witness::fixed_auxiliary::common_polynomial(),
            supported_profile::auxiliary_modulus(),
            AUXILIARY_PLAINTEXT_MODULUS,
            AUXILIARY_SECRET_SUPPORT,
            message,
        )
    }
    fn encrypt(
        key: Vec<BigInt>,
        common: Vec<BigInt>,
        modulus_bytes: &[u8],
        plaintext_modulus: u32,
        support: usize,
        message: &[i32],
    ) -> Result<Self, Refusal> {
        let degree = common.len();
        if key.len() != degree
            || message.len() != degree
            || message
                .iter()
                .any(|value| value.unsigned_abs() > plaintext_modulus / 2)
        {
            return Err(Refusal::Context);
        }
        let modulus = BigInt::from_bytes_le(Sign::Plus, modulus_bytes);
        let scale = (&modulus - BigInt::from(1)) / BigInt::from(plaintext_modulus);
        let random = &mut Random::new();
        let plan = Plan::new(degree);
        let ephemeral = random.sparse(degree, support)?;
        let transformed = Zeroizing::new(plan.sparse_transform(&ephemeral));
        let first = component(
            &plan,
            &ephemeral,
            &transformed,
            ComponentInput {
                public: &key,
                modulus: &modulus,
                scale: &scale,
                message: Some(message),
                errors: random.errors(degree)?,
            },
        )?;
        let second = component(
            &plan,
            &ephemeral,
            &transformed,
            ComponentInput {
                public: &common,
                modulus: &modulus,
                scale: &scale,
                message: None,
                errors: random.errors(degree)?,
            },
        )?;
        Ok(Self {
            key,
            common,
            ephemeral,
            components: [first, second],
        })
    }
}

/// This is an encryption witness, not a signed submission or a verified ballot.
pub struct LinkedBallotWitness {
    pub context: BallotComputationContext,
    pub packing: PackingWitness,
    pub fhe: EncryptionWitness,
    pub auxiliary: EncryptionWitness,
}
/// Refuses scores outside the poll's ballot domain. Callers check them before
/// consuming any one-time ballot authority.
pub fn check_ballot_scores(poll: &VerifiedPoll, scores: &[u8]) -> Result<(), Refusal> {
    if scores.len() != poll.manifest().option_count() {
        return Err(Refusal::Scores);
    }
    crate::packing::check_scores(scores).map_err(|_| Refusal::Scores)
}

impl LinkedBallotWitness {
    pub fn into_context(self) -> BallotComputationContext {
        self.context
    }
    pub fn create_with_context(
        context: BallotComputationContext,
        fhe_key: RetainedAggregatePolynomial,
        scores: &[u8],
    ) -> Result<Self, Refusal> {
        let profile = context.profile();
        if fhe_key.index() != fhe_key_polynomial(profile)
            || fhe_key.inventory() != context.inventory()
        {
            return Err(Refusal::Context);
        }
        check_ballot_scores(context.poll(), scores)?;
        let packing = PackingWitness::new(scores).map_err(|_| Refusal::Scores)?;
        let fhe = EncryptionWitness::create(profile, fhe_key, packing.message())?;
        let mut literal = Zeroizing::new(vec![0i32; AUXILIARY_DEGREE]);
        for (target, score) in literal.iter_mut().zip(scores) {
            *target = i32::from(*score);
        }
        let auxiliary = EncryptionWitness::create_auxiliary(&literal)?;
        Ok(Self {
            context,
            packing,
            fhe,
            auxiliary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Signed;

    fn centered(value: BigInt, modulus: &BigInt) -> BigInt {
        let reduced = (value % modulus + modulus) % modulus;
        if reduced > modulus / 2 {
            reduced - modulus
        } else {
            reduced
        }
    }
    fn ordinary(left: &[BigInt], right: &[i8]) -> Vec<BigInt> {
        let degree = left.len();
        let mut result = vec![BigInt::from(0); degree];
        for (left_index, left) in left.iter().enumerate() {
            for (right_index, right) in right.iter().enumerate() {
                let index = left_index + right_index;
                result[index % degree] +=
                    left * BigInt::from(if index >= degree { -*right } else { *right });
            }
        }
        result
    }
    #[test]
    fn fixed_auxiliary_encryptions_use_the_suite_pair_and_exact_integer_equations() {
        let modulus = BigInt::from_bytes_le(Sign::Plus, supported_profile::auxiliary_modulus());
        let scale = (&modulus - BigInt::from(1)) / AUXILIARY_PLAINTEXT_MODULUS;
        let mut message = vec![0; AUXILIARY_DEGREE];
        message[..4].copy_from_slice(&[1, 10, -128, 128]);
        let witness = EncryptionWitness::create_auxiliary(&message).unwrap();
        assert_eq!(
            witness.common,
            setup_witness::fixed_auxiliary::common_polynomial()
        );
        assert_eq!(witness.key, setup_witness::fixed_auxiliary::public_key());
        assert_ne!(witness.common, witness.key);
        for sign in [-1, 1] {
            assert_eq!(
                witness
                    .ephemeral
                    .iter()
                    .filter(|value| **value == sign)
                    .count(),
                AUXILIARY_SECRET_SUPPORT / 2
            );
        }
        for (component, public) in [&witness.key, &witness.common].into_iter().enumerate() {
            for row in [0, 1, 3, AUXILIARY_DEGREE / 2, AUXILIARY_DEGREE - 1] {
                let mut product = BigInt::from(0);
                for (position, secret) in witness.ephemeral.iter().enumerate() {
                    let index = (row + AUXILIARY_DEGREE - position) % AUXILIARY_DEGREE;
                    product += &public[index]
                        * i32::from(if position <= row { *secret } else { -*secret });
                }
                let value = &witness.components[component];
                let raw = product
                    + i32::from(value.errors[row])
                    + if component == 0 {
                        &scale * message[row]
                    } else {
                        BigInt::from(0)
                    };
                assert_eq!(value.coefficients[row], centered(raw.clone(), &modulus));
                assert_eq!(
                    raw,
                    &value.coefficients[row] + &modulus * i32::from(value.quotients[row])
                );
            }
        }
        assert!(EncryptionWitness::create_auxiliary(&message[..message.len() - 1]).is_err());
        message[0] = 129;
        assert!(EncryptionWitness::create_auxiliary(&message).is_err());
    }
    #[test]
    fn sparse_secret_draws_are_uniform_positions() {
        // A four-byte draw reduced modulo the degree is a uniform position
        // only when the degree divides 2^32.
        let profile = Profile::new(3, 2).unwrap();
        for (family, support) in [
            (Family::Fhe, FHE_SECRET_SUPPORT),
            (Family::Auxiliary, AUXILIARY_SECRET_SUPPORT),
        ] {
            let degree = profile.family_degree(family);
            assert!((1u64 << (8 * DRAW_BYTES)).is_multiple_of(degree as u64));
            assert!(0 < support && support < degree);
        }
    }

    #[test]
    fn both_encryption_moduli_match_independent_integer_convolution_and_decoding() {
        let degree = 32;
        let small = Profile::new(3, 2).unwrap();
        let wide = Profile::new(20, 20).unwrap();
        for (profile, family, plaintext_modulus) in [
            (small, Family::Fhe, 65537i32),
            (wide, Family::Fhe, 65537i32),
            (small, Family::Auxiliary, 257i32),
        ] {
            let bytes = profile.family_modulus(family);
            let modulus = BigInt::from_bytes_le(Sign::Plus, &bytes);
            let scale = (&modulus - BigInt::from(1)) / plaintext_modulus;
            let common: Vec<_> = (0..degree)
                .map(|index| {
                    centered(
                        (&modulus / BigInt::from(2 + index % 7))
                            * BigInt::from(if index % 2 == 0 { 1 } else { -1 })
                            + BigInt::from(index),
                        &modulus,
                    )
                })
                .collect();
            let mut secret = vec![0; degree];
            for (position, sign) in [(1, 1), (3, 1), (17, -1), (31, -1)] {
                secret[position] = sign;
            }
            let mut ephemeral = vec![0; degree];
            for (position, sign) in [(0, 1), (5, 1), (3, -1), (31, -1)] {
                ephemeral[position] = sign;
            }
            let key_error: Vec<_> = (0..degree)
                .map(|index| BigInt::from(if index % 2 == 0 { -640 } else { 630 }))
                .collect();
            let public_key: Vec<_> = ordinary(&common, &secret)
                .into_iter()
                .zip(&key_error)
                .map(|(product, error)| centered(-product + error, &modulus))
                .collect();
            let message: Vec<_> = (0..degree)
                .map(|index| [0, -plaintext_modulus / 2, plaintext_modulus / 2, 1, -1][index % 5])
                .collect();
            let plan = Plan::new(degree);
            let transformed = plan.sparse_transform(&ephemeral);
            let first = component(
                &plan,
                &ephemeral,
                &transformed,
                ComponentInput {
                    public: &public_key,
                    modulus: &modulus,
                    scale: &scale,
                    message: Some(&message),
                    errors: Zeroizing::new(vec![63; degree]),
                },
            )
            .unwrap();
            let second = component(
                &plan,
                &ephemeral,
                &transformed,
                ComponentInput {
                    public: &common,
                    modulus: &modulus,
                    scale: &scale,
                    message: None,
                    errors: Zeroizing::new(vec![-64; degree]),
                },
            )
            .unwrap();
            for (component_index, (public, ciphertext)) in
                [(&public_key, &first), (&common, &second)]
                    .into_iter()
                    .enumerate()
            {
                for (position, product) in ordinary(public, &ephemeral).into_iter().enumerate() {
                    let raw = product
                        + BigInt::from(ciphertext.errors[position])
                        + if component_index == 0 {
                            &scale * message[position]
                        } else {
                            BigInt::from(0)
                        };
                    assert_eq!(
                        ciphertext.coefficients[position],
                        centered(raw.clone(), &modulus)
                    );
                    assert_eq!(
                        raw,
                        &ciphertext.coefficients[position]
                            + &modulus * BigInt::from(ciphertext.quotients[position])
                    );
                }
                assert_eq!(ciphertext.carries.len(), bytes.len().div_ceil(12) - 1);
            }
            let secret_product = ordinary(&second.coefficients, &secret);
            let expected_key_noise = ordinary(&key_error, &ephemeral);
            let error_values: Vec<_> = second
                .errors
                .iter()
                .map(|value| BigInt::from(*value))
                .collect();
            let expected_secret_noise = ordinary(&error_values, &secret);
            for position in 0..degree {
                let phase = centered(
                    &first.coefficients[position] + &secret_product[position],
                    &modulus,
                );
                let noise = &expected_key_noise[position]
                    + &expected_secret_noise[position]
                    + BigInt::from(first.errors[position]);
                assert_eq!(phase, &scale * message[position] + noise);
                let magnitude: BigInt = (phase.abs() + &scale / 2) / &scale;
                let decoded = if phase.is_negative() {
                    -magnitude
                } else {
                    magnitude
                };
                assert_eq!(decoded, BigInt::from(message[position]));
            }
        }
    }
}
