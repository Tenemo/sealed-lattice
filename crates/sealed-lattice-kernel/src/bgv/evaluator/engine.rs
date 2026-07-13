use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};

use crate::{
    bgv::{
        evaluator::prg::DeterministicSampler,
        modular_arithmetic::{add_mod, add_mod_fast, inverse_mod, mul_mod, mul_mod_fast, sub_mod},
        ntt::{
            forward_negacyclic_ntt, forward_negacyclic_ntt_in_place, inverse_negacyclic_ntt,
            inverse_negacyclic_ntt_in_place,
        },
        parameters::{
            BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, bgv_parameters_hash,
        },
        rns::RnsPolynomial,
        serialization::{
            BgvObjectKind, canonical_bytes_hex, ciphertext_root, serialize_bgv_object,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

mod ciphertext_records;
mod decryption;
mod operations;

pub(crate) use ciphertext_records::{ciphertext_canonical_bytes_hex, ciphertext_object_root};
pub(crate) use decryption::decryption_accumulator_to_coefficients;
pub(crate) use operations::{
    add_plaintext_coefficients, ciphertext_add, ciphertext_negate, ciphertext_sub,
    ciphertext_tensor, modulus_switch, plaintext_mul, scalar_mul,
};

// Highest modulus-chain level: index of the last data prime, so a fresh
// ciphertext at this level uses all data primes (q = product of all primes).
pub(crate) const EVALUATOR_FULL_LEVEL: usize = DATA_PRIMES.len() - 1;

// Reduce a signed integer coefficient into the canonical residue range
// [0, modulus). Inputs are bounded (secret/error/plaintext coefficients), so the
// i128 widening never overflows.
pub(crate) fn signed_residue(value: i64, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = ((i128::from(value) % modulus_i128) + modulus_i128) % modulus_i128;

    u64::try_from(reduced).expect("residue below a u64 modulus fits u64")
}

// Negacyclic polynomial product modulo a single prime, evaluated through the
// shared forward/inverse NTT so it matches the rest of the BGV-RNS backend.
pub(crate) fn negacyclic_mul(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut left_ntt = left.to_vec();
    let mut right_ntt = right.to_vec();
    forward_negacyclic_ntt_in_place(&mut left_ntt, modulus)?;
    forward_negacyclic_ntt_in_place(&mut right_ntt, modulus)?;
    for (left_value, right_value) in left_ntt.iter_mut().zip(right_ntt.iter()) {
        *left_value = mul_mod_fast(*left_value, *right_value, modulus);
    }
    inverse_negacyclic_ntt_in_place(&mut left_ntt, modulus)?;

    Ok(left_ntt)
}

// A leveled BGV-RNS ciphertext in the coefficient domain. `components` holds the
// polynomial components (two for a normal ciphertext, three immediately after a
// homomorphic multiplication, before relinearization); each component is stored
// as residues per active data prime. `level` selects the active prefix of the
// data-prime chain, `DATA_PRIMES[0..=level]`.
#[derive(Clone, Debug)]
pub(crate) struct Ciphertext {
    pub(crate) components: Vec<Vec<Vec<u64>>>,
    pub(crate) level: usize,
    // The plaintext-field scaling factor f such that raw decryption recovers
    // m * f (mod plaintext modulus). Modulus switching multiplies f by the
    // dropped prime's inverse and multiplication multiplies the two factors, so
    // decryption divides the raw result by this tracked factor.
    pub(crate) decrypt_scaling: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct EncryptionWitness {
    pub(crate) randomizer_coefficients: Vec<i64>,
    pub(crate) error_zero_coefficients: Vec<i64>,
    pub(crate) error_one_coefficients: Vec<i64>,
}

impl Ciphertext {
    pub(crate) fn primes(&self) -> &'static [u64] {
        &DATA_PRIMES[..=self.level]
    }

    pub(crate) fn component_count(&self) -> usize {
        self.components.len()
    }

    fn assert_two_components(&self) -> CanonicalResult<()> {
        if self.components.len() != 2 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "BGV evaluator operation requires a two-component ciphertext",
            ));
        }

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct BgvPublicKey {
    public_b: Vec<Vec<u64>>,
    public_a: Vec<Vec<u64>>,
}

impl BgvPublicKey {
    pub(crate) fn from_components(
        public_b: Vec<Vec<u64>>,
        public_a: Vec<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        validate_public_key_component_shape(&public_b, "component zero")?;
        validate_public_key_component_shape(&public_a, "component one")?;

        Ok(Self { public_b, public_a })
    }

    #[cfg(test)]
    pub(crate) fn encrypt_slots(
        &self,
        slots: &[u64],
        seed_hex: &str,
    ) -> CanonicalResult<Ciphertext> {
        let coefficients = encode_slots_to_coefficients(slots)?;

        self.encrypt_coefficients(&coefficients, seed_hex)
    }

    #[cfg(test)]
    pub(crate) fn encrypt_coefficients(
        &self,
        plaintext_coefficients: &[u64],
        seed_hex: &str,
    ) -> CanonicalResult<Ciphertext> {
        Ok(self
            .encrypt_coefficients_with_witness(plaintext_coefficients, seed_hex)?
            .0)
    }

    #[cfg(test)]
    pub(crate) fn encrypt_coefficients_with_witness(
        &self,
        plaintext_coefficients: &[u64],
        seed_hex: &str,
    ) -> CanonicalResult<(Ciphertext, EncryptionWitness)> {
        encrypt_coefficients_with_public_key_components(
            &self.public_b,
            &self.public_a,
            plaintext_coefficients,
            seed_hex,
        )
    }
}

// The development BGV key set used to drive and check the evaluator. The
// collective public key uses the protocol convention `b = p*e - a*s`, so the
// plaintext lives in the least-significant residue and decryption is exact mod
// the plaintext modulus. The secret is retained only for development decryption
// and correctness certificates; it is never exported through the public surface.
#[derive(Clone)]
pub(crate) struct DevelopmentBgvKey {
    secret: Vec<i64>,
    public_b: Vec<Vec<u64>>,
    public_a: Vec<Vec<u64>>,
}

impl DevelopmentBgvKey {
    pub(crate) fn from_collective_components(
        secret: Vec<i64>,
        public_b: Vec<Vec<u64>>,
        public_a: Vec<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        if secret.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV evaluator collective secret width must match the polynomial degree",
            ));
        }
        let BgvPublicKey { public_b, public_a } =
            BgvPublicKey::from_components(public_b, public_a)?;

        Ok(Self {
            secret,
            public_b,
            public_a,
        })
    }

    #[cfg(test)]
    pub(crate) fn generate(seed_hex: &str) -> CanonicalResult<Self> {
        let secret = DeterministicSampler::new(
            "sealed-lattice-bgv-evaluator/development-secret",
            &[seed_hex.as_bytes()],
        )
        .ternary(POLYNOMIAL_DEGREE);

        // The public-key error is a single small integer polynomial; its RNS
        // limbs are the same polynomial reduced per prime, not independent draws.
        let public_error = DeterministicSampler::new(
            "sealed-lattice-bgv-evaluator/development-public-error",
            &[seed_hex.as_bytes()],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);

        let public_key_components = evaluator_parallel_iterator!(
            DATA_PRIMES.par_iter().copied(),
            DATA_PRIMES.iter().copied()
        )
        .map(|modulus| {
            let modulus_bytes = modulus.to_le_bytes();
            // The public random sample `a` is uniform over the ring, so sampling
            // each RNS limb independently is a valid uniform-mod-q polynomial.
            let public_sample = DeterministicSampler::new(
                "sealed-lattice-bgv-evaluator/development-public-sample",
                &[seed_hex.as_bytes(), &modulus_bytes],
            )
            .uniform_residues(modulus, POLYNOMIAL_DEGREE);

            let secret_residues = secret
                .iter()
                .map(|coefficient| signed_residue(*coefficient, modulus))
                .collect::<Vec<_>>();
            let public_sample_secret_product =
                negacyclic_mul(&public_sample, &secret_residues, modulus)?;
            // b = p*e - a*s, so that c0 + c1*s = m + p*(noise) and decryption
            // recovers m exactly modulo the plaintext modulus.
            let component_b = public_error
                .iter()
                .zip(public_sample_secret_product.iter())
                .map(|(error_coefficient, product)| {
                    let scaled_error = signed_residue(
                        error_coefficient * i64::from(PLAINTEXT_MODULUS_I32),
                        modulus,
                    );
                    sub_mod(scaled_error, *product, modulus)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;

            Ok((component_b, public_sample))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
        let (public_b, public_a) = public_key_components.into_iter().unzip();

        Ok(Self {
            secret,
            public_b,
            public_a,
        })
    }

    pub(crate) fn secret(&self) -> &[i64] {
        &self.secret
    }

    pub(crate) fn public_key_components(&self) -> (&[Vec<u64>], &[Vec<u64>]) {
        (&self.public_b, &self.public_a)
    }

    // Encrypt plaintext slot values into a fresh full-level ciphertext.
    #[cfg(test)]
    pub(crate) fn encrypt_slots(
        &self,
        slots: &[u64],
        seed_hex: &str,
    ) -> CanonicalResult<Ciphertext> {
        let coefficients = encode_slots_to_coefficients(slots)?;

        self.encrypt_coefficients(&coefficients, seed_hex)
    }

    // Encrypt a plaintext polynomial given as coefficients in [0, plaintext
    // modulus): c0 = b*u + p*e0 + m, c1 = a*u + p*e1, at the full data level.
    #[cfg(test)]
    pub(crate) fn encrypt_coefficients(
        &self,
        plaintext_coefficients: &[u64],
        seed_hex: &str,
    ) -> CanonicalResult<Ciphertext> {
        Ok(self
            .encrypt_coefficients_with_witness(plaintext_coefficients, seed_hex)?
            .0)
    }

    pub(crate) fn encrypt_coefficients_with_witness(
        &self,
        plaintext_coefficients: &[u64],
        seed_hex: &str,
    ) -> CanonicalResult<(Ciphertext, EncryptionWitness)> {
        encrypt_coefficients_with_public_key_components(
            &self.public_b,
            &self.public_a,
            plaintext_coefficients,
            seed_hex,
        )
    }

    #[cfg(test)]
    pub(crate) fn decrypt_to_coefficients(
        &self,
        ciphertext: &Ciphertext,
    ) -> CanonicalResult<Vec<u64>> {
        let primes = ciphertext.primes();
        // D = sum_k c_k * s^k, evaluated per prime in the coefficient domain.
        let secret_residues = primes
            .iter()
            .map(|modulus| {
                self.secret
                    .iter()
                    .map(|coefficient| signed_residue(*coefficient, *modulus))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut accumulator: Vec<Vec<u64>> = ciphertext.components[0].clone();
        let mut secret_power = secret_residues.clone();
        for (component_index, component) in ciphertext.components.iter().enumerate().skip(1) {
            if component_index > 1 {
                secret_power = secret_power
                    .iter()
                    .zip(secret_residues.iter())
                    .zip(primes.iter())
                    .map(|((power_limb, secret_limb), modulus)| {
                        negacyclic_mul(power_limb, secret_limb, *modulus)
                    })
                    .collect::<CanonicalResult<Vec<_>>>()?;
            }
            for (limb_index, modulus) in primes.iter().enumerate() {
                let term =
                    negacyclic_mul(&component[limb_index], &secret_power[limb_index], *modulus)?;
                for (accumulated, added) in accumulator[limb_index].iter_mut().zip(term.iter()) {
                    *accumulated = add_mod(*accumulated, *added, *modulus)?;
                }
            }
        }

        decryption_accumulator_to_coefficients(ciphertext, &accumulator)
    }

    #[cfg(test)]
    pub(crate) fn decrypt_to_slots(&self, ciphertext: &Ciphertext) -> CanonicalResult<Vec<u64>> {
        let coefficients = self.decrypt_to_coefficients(ciphertext)?;

        forward_negacyclic_ntt(&coefficients, PLAINTEXT_MODULUS)
    }
}

const PLAINTEXT_MODULUS_I32: i32 = 65_537;

fn encrypt_coefficients_with_public_key_components(
    public_b: &[Vec<u64>],
    public_a: &[Vec<u64>],
    plaintext_coefficients: &[u64],
    seed_hex: &str,
) -> CanonicalResult<(Ciphertext, EncryptionWitness)> {
    validate_public_key_component_shape(public_b, "component zero")?;
    validate_public_key_component_shape(public_a, "component one")?;
    if plaintext_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV evaluator plaintext coefficient vector must match the polynomial degree",
        ));
    }
    let randomizer = DeterministicSampler::new(
        "sealed-lattice-bgv-evaluator/development-encryption-randomizer",
        &[seed_hex.as_bytes()],
    )
    .ternary(POLYNOMIAL_DEGREE);
    let error_zero = DeterministicSampler::new(
        "sealed-lattice-bgv-evaluator/development-encryption-error-zero",
        &[seed_hex.as_bytes()],
    )
    .centered_binomial_eta2(POLYNOMIAL_DEGREE);
    let error_one = DeterministicSampler::new(
        "sealed-lattice-bgv-evaluator/development-encryption-error-one",
        &[seed_hex.as_bytes()],
    )
    .centered_binomial_eta2(POLYNOMIAL_DEGREE);

    let mut component_zero = Vec::with_capacity(DATA_PRIMES.len());
    let mut component_one = Vec::with_capacity(DATA_PRIMES.len());
    for (modulus_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let randomizer_residues = randomizer
            .iter()
            .map(|coefficient| signed_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let public_key_product =
            negacyclic_mul(&public_b[modulus_index], &randomizer_residues, modulus)?;
        let public_sample_product =
            negacyclic_mul(&public_a[modulus_index], &randomizer_residues, modulus)?;

        let limb_zero = (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| {
                let scaled_error = signed_residue(
                    error_zero[coefficient_index] * i64::from(PLAINTEXT_MODULUS_I32),
                    modulus,
                );
                let with_error =
                    add_mod(public_key_product[coefficient_index], scaled_error, modulus)?;
                add_mod(
                    with_error,
                    plaintext_coefficients[coefficient_index],
                    modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let limb_one = (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| {
                let scaled_error = signed_residue(
                    error_one[coefficient_index] * i64::from(PLAINTEXT_MODULUS_I32),
                    modulus,
                );
                add_mod(
                    public_sample_product[coefficient_index],
                    scaled_error,
                    modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;

        component_zero.push(limb_zero);
        component_one.push(limb_one);
    }

    Ok((
        Ciphertext {
            components: vec![component_zero, component_one],
            level: EVALUATOR_FULL_LEVEL,
            decrypt_scaling: 1,
        },
        EncryptionWitness {
            randomizer_coefficients: randomizer,
            error_zero_coefficients: error_zero,
            error_one_coefficients: error_one,
        },
    ))
}

fn validate_public_key_component_shape(component: &[Vec<u64>], label: &str) -> CanonicalResult<()> {
    if component.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("BGV evaluator public key {label} must have one limb per data prime"),
        ));
    }
    for (limb_index, limb) in component.iter().enumerate() {
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("BGV evaluator public key {label} limb has the wrong coefficient count"),
            ));
        }
        let modulus = DATA_PRIMES[limb_index];
        if limb.iter().any(|coefficient| *coefficient >= modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("BGV evaluator public key {label} limb has non-canonical residues"),
            ));
        }
    }

    Ok(())
}

// Encode plaintext slot values (in GF(plaintext modulus)) into the polynomial
// coefficient representation via the inverse batch NTT, matching the BGV batch
// encoder.
pub(crate) fn encode_slots_to_coefficients(slots: &[u64]) -> CanonicalResult<Vec<u64>> {
    if slots.len() > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV evaluator received more slots than the polynomial degree",
        ));
    }
    if slots.iter().any(|slot| *slot >= PLAINTEXT_MODULUS) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV evaluator slot value is outside the plaintext field",
        ));
    }
    let mut padded = vec![0_u64; POLYNOMIAL_DEGREE];
    padded[..slots.len()].copy_from_slice(slots);

    inverse_negacyclic_ntt(&padded, PLAINTEXT_MODULUS)
}

#[cfg(test)]
mod tests {
    use super::{
        BgvPublicKey, Ciphertext, DevelopmentBgvKey, ciphertext_add, ciphertext_negate,
        ciphertext_sub, ciphertext_tensor, modulus_switch, plaintext_mul, scalar_mul,
    };
    use crate::bgv::parameters::PLAINTEXT_MODULUS;

    use std::sync::OnceLock;

    const DEVELOPMENT_SEED: &str = "0011223344556677";

    fn shared_key() -> &'static DevelopmentBgvKey {
        static KEY: OnceLock<DevelopmentBgvKey> = OnceLock::new();
        KEY.get_or_init(|| {
            DevelopmentBgvKey::generate(DEVELOPMENT_SEED).expect("development key generates")
        })
    }

    fn first_slots(values: &[u64]) -> Vec<u64> {
        values.to_vec()
    }

    fn decrypt_prefix(key: &DevelopmentBgvKey, ciphertext: &Ciphertext, count: usize) -> Vec<u64> {
        key.decrypt_to_slots(ciphertext).expect("decrypt")[..count].to_vec()
    }

    #[test]
    fn encrypt_decrypt_round_trips_slot_values() {
        let key = shared_key();
        let slots = first_slots(&[0, 1, 2, 200, 65_536, 7]);
        let ciphertext = key.encrypt_slots(&slots, "aa01").expect("encrypt");
        assert_eq!(decrypt_prefix(key, &ciphertext, slots.len()), slots);
    }

    #[test]
    fn public_key_encryption_matches_development_key_encryption() {
        let key = shared_key();
        let (component_b, component_a) = key.public_key_components();
        let public_key = BgvPublicKey::from_components(component_b.to_vec(), component_a.to_vec())
            .expect("public key");
        let slots = first_slots(&[11, 0, 65_536, 29, 700]);

        let development_ciphertext = key
            .encrypt_slots(&slots, "public-key-parity")
            .expect("development encrypt");
        let public_ciphertext = public_key
            .encrypt_slots(&slots, "public-key-parity")
            .expect("public encrypt");

        assert_eq!(
            public_ciphertext.components,
            development_ciphertext.components
        );
        assert_eq!(public_ciphertext.level, development_ciphertext.level);
        assert_eq!(
            public_ciphertext.decrypt_scaling,
            development_ciphertext.decrypt_scaling
        );
        assert_eq!(decrypt_prefix(key, &public_ciphertext, slots.len()), slots);
    }

    #[test]
    fn homomorphic_addition_and_subtraction_match_slot_arithmetic() {
        let key = shared_key();
        let left = key
            .encrypt_slots(&[3, 100, 65_536], "aa02")
            .expect("encrypt left");
        let right = key
            .encrypt_slots(&[4, 200, 1], "aa03")
            .expect("encrypt right");
        let sum = ciphertext_add(&left, &right).expect("add");
        assert_eq!(decrypt_prefix(key, &sum, 3), vec![7, 300, 0]);

        let left = key.encrypt_slots(&[10, 5], "aa04").expect("encrypt left");
        let right = key.encrypt_slots(&[3, 9], "aa05").expect("encrypt right");
        let difference = ciphertext_sub(&left, &right).expect("sub");
        assert_eq!(decrypt_prefix(key, &difference, 2), vec![7, 65_537 - 4]);
    }

    #[test]
    fn scalar_multiplication_handles_positive_and_centered_negative_scalars() {
        let key = shared_key();
        let ciphertext = key.encrypt_slots(&[2, 3, 4], "aa06").expect("encrypt");
        let scaled = scalar_mul(&ciphertext, 5).expect("scalar mul");
        assert_eq!(decrypt_prefix(key, &scaled, 3), vec![10, 15, 20]);

        let ciphertext = key
            .encrypt_slots(&[2, 3, PLAINTEXT_MODULUS - 1], "aa06-negative")
            .expect("encrypt");
        let negated = ciphertext_negate(&ciphertext).expect("negate");
        let negative_scalar = scalar_mul(&ciphertext, -1).expect("negative scalar");
        let field_residue_scalar = scalar_mul(
            &ciphertext,
            i64::try_from(PLAINTEXT_MODULUS - 1).expect("plaintext modulus fits i64"),
        )
        .expect("field residue scalar");

        assert_eq!(negative_scalar.components, negated.components);
        assert_eq!(field_residue_scalar.components, negated.components);
        assert_eq!(
            decrypt_prefix(key, &negative_scalar, 3),
            vec![PLAINTEXT_MODULUS - 2, PLAINTEXT_MODULUS - 3, 1]
        );
    }

    #[test]
    fn plaintext_and_ciphertext_multiplication_are_slot_wise() {
        let key = shared_key();
        let ciphertext = key.encrypt_slots(&[2, 3, 4, 5], "aa07").expect("encrypt");
        let plaintext = super::encode_slots_to_coefficients(&[10, 0, 7, 1]).expect("encode");
        let product = plaintext_mul(&ciphertext, &plaintext).expect("plaintext mul");
        assert_eq!(decrypt_prefix(key, &product, 4), vec![20, 0, 28, 5]);

        let left = key.encrypt_slots(&[2, 3, 4], "aa08").expect("encrypt left");
        let right = key
            .encrypt_slots(&[5, 6, 7], "aa09")
            .expect("encrypt right");
        let product = ciphertext_tensor(&left, &right).expect("tensor");
        assert_eq!(product.component_count(), 3);
        assert_eq!(decrypt_prefix(key, &product, 3), vec![10, 18, 28]);
    }

    #[test]
    fn modulus_switch_chain_preserves_slots_and_drops_levels() {
        let key = shared_key();
        let ciphertext = key
            .encrypt_slots(&[11, 22, 65_500], "aa10")
            .expect("encrypt");
        let switched = modulus_switch(&ciphertext).expect("modulus switch");
        assert_eq!(switched.level, ciphertext.level - 1);
        assert_eq!(decrypt_prefix(key, &switched, 3), vec![11, 22, 65_500]);

        let mut ciphertext = key.encrypt_slots(&[42, 9, 100], "aa11").expect("encrypt");
        for _ in 0..4 {
            ciphertext = modulus_switch(&ciphertext).expect("modulus switch");
        }
        assert_eq!(ciphertext.level, super::EVALUATOR_FULL_LEVEL - 4);
        assert_eq!(decrypt_prefix(key, &ciphertext, 3), vec![42, 9, 100]);
    }
}
