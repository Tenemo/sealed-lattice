use crate::context::BallotComputationContext;
use crate::{
    convolution::{Plan, RADIX, digit},
    gaussian,
    packing::PackingWitness,
    reduction,
};
use num_bigint::{BigInt, Sign};
use registration_credentials::poll::VerifiedPoll;
use setup_aggregate::{
    RetainedAggregatePolynomial, VerifiedAggregatePolynomial, verified::VerifiedSetupAggregate,
};
use std::sync::Arc;
use zeroize::Zeroizing;

const PARAMETERS: &[u8; 137] = include_bytes!("../../setup-proof/parameters.bin");

#[derive(Debug)]
pub enum Refusal {
    Context,
    Scores,
    Randomness,
    Arithmetic,
}

struct Random {
    bytes: Zeroizing<Vec<u8>>,
    cursor: usize,
}
impl Random {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; 65536]),
            cursor: 65536,
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
            let position = u32::from_le_bytes(*self.read::<4>()?) as usize % degree;
            if values[position] == 0 {
                values[position] = if selected < support / 2 { 1 } else { -1 };
                selected += 1;
            }
        }
        Ok(values)
    }
    fn errors(&mut self, degree: usize) -> Result<Zeroizing<Vec<i8>>, Refusal> {
        (0..degree)
            .map(|_| Ok(gaussian::sample(&*self.read::<20>()?) as i8))
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
    pub key: RetainedAggregatePolynomial,
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
    let reducer =
        reduction::Modulus::from_bytes(&modulus_bytes).map_err(|_| Refusal::Arithmetic)?;
    let limbs = reducer.digits.len();
    if errors.len() != degree || message.is_some_and(|value| value.len() != degree) {
        return Err(Refusal::Arithmetic);
    }
    let products = Zeroizing::new(plan.digit_products(public, ephemeral, transformed, limbs));
    let mut coefficients = Vec::with_capacity(degree);
    let mut quotients = Zeroizing::new(Vec::with_capacity(degree));
    for position in 0..degree {
        let mut raw = Zeroizing::new([0i128; 9]);
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
        let mut reduced = [0u128; 9];
        let result = reducer
            .reduce(&raw[..limbs], &mut reduced[..limbs])
            .map_err(|_| Refusal::Arithmetic)?;
        let magnitude = reduced[..limbs]
            .iter()
            .rev()
            .fold(BigInt::from(0), |sum, value| {
                (sum << 96usize) + BigInt::from(*value)
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

impl EncryptionWitness {
    fn create(
        key: RetainedAggregatePolynomial,
        message: &[i32],
        random: &mut Random,
    ) -> Result<Self, Refusal> {
        let (degree, support, common_index, modulus_bytes, plaintext_modulus) = match key.index() {
            1 => (65536, 1024, 0, &PARAMETERS[4..112], 65537),
            74 => (4096, 256, 73, &PARAMETERS[132..137], 257),
            _ => return Err(Refusal::Context),
        };
        if key.coefficients().len() != degree
            || message.len() != degree
            || message
                .iter()
                .any(|value| value.unsigned_abs() > plaintext_modulus / 2)
        {
            return Err(Refusal::Context);
        }
        let modulus = BigInt::from_bytes_le(Sign::Plus, modulus_bytes);
        let scale = (&modulus - BigInt::from(1)) / BigInt::from(plaintext_modulus);
        let common = setup_witness::contribution::common_polynomial(common_index)
            .map_err(|_| Refusal::Context)?;
        let plan = Plan::new(degree);
        let ephemeral = random.sparse(degree, support)?;
        let transformed = Zeroizing::new(plan.sparse_transform(&ephemeral));
        let first = component(
            &plan,
            &ephemeral,
            &transformed,
            ComponentInput {
                public: key.coefficients(),
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
impl LinkedBallotWitness {
    pub fn into_context(self) -> BallotComputationContext {
        self.context
    }
    pub fn create(
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
        fhe_key: VerifiedAggregatePolynomial,
        auxiliary_key: VerifiedAggregatePolynomial,
        position: usize,
        scores: &[u8],
    ) -> Result<Self, Refusal> {
        let context = BallotComputationContext::from_verified(poll, &setup, position)
            .map_err(|_| Refusal::Context)?;
        Self::create_with_context(context, fhe_key.into(), auxiliary_key.into(), scores)
    }
    pub fn create_with_context(
        context: BallotComputationContext,
        fhe_key: RetainedAggregatePolynomial,
        auxiliary_key: RetainedAggregatePolynomial,
        scores: &[u8],
    ) -> Result<Self, Refusal> {
        if fhe_key.index() != 1
            || auxiliary_key.index() != 74
            || fhe_key.inventory() != context.inventory()
            || auxiliary_key.inventory() != context.inventory()
        {
            return Err(Refusal::Context);
        }
        if scores.len() != context.poll().manifest().option_count() {
            return Err(Refusal::Scores);
        }
        let packing = PackingWitness::new(scores).map_err(|_| Refusal::Scores)?;
        let mut random = Random::new();
        let fhe = EncryptionWitness::create(fhe_key, packing.message(), &mut random)?;
        let mut literal = Zeroizing::new(vec![0i32; 4096]);
        for (target, score) in literal.iter_mut().zip(scores) {
            *target = i32::from(*score);
        }
        let auxiliary = EncryptionWitness::create(auxiliary_key, &literal, &mut random)?;
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
    fn both_encryption_moduli_match_independent_integer_convolution_and_decoding() {
        let degree = 32;
        for (bytes, plaintext_modulus) in [
            (&PARAMETERS[4..112], 65537i32),
            (&PARAMETERS[132..137], 257i32),
        ] {
            let modulus = BigInt::from_bytes_le(Sign::Plus, bytes);
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
