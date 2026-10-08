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
    fn read<const N: usize>(&mut self) -> Zeroizing<[u8; N]> {
        let mut result = Zeroizing::new([0; N]);
        let mut filled = 0;
        while filled < N {
            if self.cursor == self.bytes.len() {
                parallel_work::random::ballot(&mut self.bytes);
                self.cursor = 0;
            }
            let count = (N - filled).min(self.bytes.len() - self.cursor);
            result[filled..filled + count]
                .copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
            self.bytes[self.cursor..self.cursor + count].fill(0);
            self.cursor += count;
            filled += count;
        }
        result
    }
    fn sparse(&mut self, degree: usize, support: usize) -> Zeroizing<Vec<i8>> {
        let mut values = Zeroizing::new(vec![0; degree]);
        let mut selected = 0;
        while selected < support {
            let position = u32::from_le_bytes(*self.read::<DRAW_BYTES>()) as usize % degree;
            if values[position] == 0 {
                values[position] = if selected < support / 2 { 1 } else { -1 };
                selected += 1;
            }
        }
        values
    }
    fn errors(&mut self, degree: usize) -> Zeroizing<Vec<i8>> {
        Zeroizing::new(
            (0..degree)
                .map(|_| gaussian::sample(&self.read::<SAMPLE_BYTES>()) as i8)
                .collect(),
        )
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
        let ephemeral = random.sparse(degree, support);
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
                errors: random.errors(degree),
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
                errors: random.errors(degree),
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
#[path = "encryption-tests.rs"]
mod tests;
