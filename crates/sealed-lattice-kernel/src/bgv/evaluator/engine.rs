use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};

use crate::{
    bgv::{
        evaluator::prg::DeterministicSampler,
        modular_arithmetic::{add_mod, add_mod_fast, inverse_mod, mul_mod, mul_mod_fast, sub_mod},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        profile::{BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, layout_hash},
        rns::RnsPolynomial,
        serialization::{
            BgvObjectKind, canonical_bytes_hex, ciphertext_root, parse_bgv_object_hex,
            serialize_bgv_object,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

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
    let left_ntt = forward_negacyclic_ntt(left, modulus)?;
    let right_ntt = forward_negacyclic_ntt(right, modulus)?;
    let product = left_ntt
        .iter()
        .zip(right_ntt.iter())
        .map(|(left_value, right_value)| mul_mod_fast(*left_value, *right_value, modulus))
        .collect::<Vec<_>>();

    inverse_negacyclic_ntt(&product, modulus)
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

// The development BGV key set used to drive and check the evaluator. The
// collective public key uses the claim-path convention `b = p*e - a*s`, so the
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
        validate_public_key_component_shape(&public_b, "component zero")?;
        validate_public_key_component_shape(&public_a, "component one")?;

        Ok(Self {
            secret,
            public_b,
            public_a,
        })
    }

    pub(crate) fn generate(seed_hex: &str) -> CanonicalResult<Self> {
        let secret = DeterministicSampler::new(
            "sealed-lattice-bgv-evaluator/development-secret-v1",
            &[seed_hex.as_bytes()],
        )
        .ternary(POLYNOMIAL_DEGREE);

        // The public-key error is a single small integer polynomial; its RNS
        // limbs are the same polynomial reduced per prime, not independent draws.
        let public_error = DeterministicSampler::new(
            "sealed-lattice-bgv-evaluator/development-public-error-v1",
            &[seed_hex.as_bytes()],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);

        #[cfg(not(target_arch = "wasm32"))]
        let public_key_components = DATA_PRIMES
            .par_iter()
            .copied()
            .map(|modulus| {
                let modulus_bytes = modulus.to_le_bytes();
                // The public random sample `a` is uniform over the ring, so sampling
                // each RNS limb independently is a valid uniform-mod-q polynomial.
                let public_sample = DeterministicSampler::new(
                    "sealed-lattice-bgv-evaluator/development-public-sample-v1",
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
        #[cfg(target_arch = "wasm32")]
        let public_key_components = DATA_PRIMES
            .iter()
            .copied()
            .map(|modulus| {
                let modulus_bytes = modulus.to_le_bytes();
                // The public random sample `a` is uniform over the ring, so sampling
                // each RNS limb independently is a valid uniform-mod-q polynomial.
                let public_sample = DeterministicSampler::new(
                    "sealed-lattice-bgv-evaluator/development-public-sample-v1",
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

    // Encrypt plaintext slot values into a fresh full-level ciphertext.
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
    pub(crate) fn encrypt_coefficients(
        &self,
        plaintext_coefficients: &[u64],
        seed_hex: &str,
    ) -> CanonicalResult<Ciphertext> {
        if plaintext_coefficients.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV evaluator plaintext coefficient vector must match the polynomial degree",
            ));
        }
        let randomizer = DeterministicSampler::new(
            "sealed-lattice-bgv-evaluator/development-encryption-randomizer-v1",
            &[seed_hex.as_bytes()],
        )
        .ternary(POLYNOMIAL_DEGREE);
        let error_zero = DeterministicSampler::new(
            "sealed-lattice-bgv-evaluator/development-encryption-error-zero-v1",
            &[seed_hex.as_bytes()],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);
        let error_one = DeterministicSampler::new(
            "sealed-lattice-bgv-evaluator/development-encryption-error-one-v1",
            &[seed_hex.as_bytes()],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);

        let mut component_zero = Vec::with_capacity(DATA_PRIMES.len());
        let mut component_one = Vec::with_capacity(DATA_PRIMES.len());
        for (modulus_index, modulus) in DATA_PRIMES.into_iter().enumerate() {
            let randomizer_residues = randomizer
                .iter()
                .map(|coefficient| signed_residue(*coefficient, modulus))
                .collect::<Vec<_>>();
            let public_key_product =
                negacyclic_mul(&self.public_b[modulus_index], &randomizer_residues, modulus)?;
            let public_sample_product =
                negacyclic_mul(&self.public_a[modulus_index], &randomizer_residues, modulus)?;

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

        Ok(Ciphertext {
            components: vec![component_zero, component_one],
            level: EVALUATOR_FULL_LEVEL,
            decrypt_scaling: 1,
        })
    }

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

        let crt = CrtContext::new(primes);
        let scaling = ciphertext.decrypt_scaling;
        let mut message_coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            let residues = accumulator
                .iter()
                .map(|limb| limb[coefficient_index])
                .collect::<Vec<_>>();
            let centered_mod_plaintext = crt.center_then_reduce_mod_plaintext(&residues);
            message_coefficients.push(mul_mod(centered_mod_plaintext, scaling, PLAINTEXT_MODULUS)?);
        }

        Ok(message_coefficients)
    }

    pub(crate) fn decrypt_to_slots(&self, ciphertext: &Ciphertext) -> CanonicalResult<Vec<u64>> {
        let coefficients = self.decrypt_to_coefficients(ciphertext)?;

        forward_negacyclic_ntt(&coefficients, PLAINTEXT_MODULUS)
    }
}

const PLAINTEXT_MODULUS_I32: i32 = 65_537;

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

pub(crate) fn ciphertext_from_canonical_hex(
    canonical_bytes_hex: &str,
    expected_ciphertext_root: Option<&str>,
) -> CanonicalResult<Ciphertext> {
    let parsed = parse_bgv_object_hex(canonical_bytes_hex)?;
    if parsed.object_kind != BgvObjectKind::Ciphertext {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluator input must be a canonical BGV ciphertext",
        ));
    }
    if parsed.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluator input must be a two-component BGV ciphertext",
        ));
    }
    let level = parsed.components[0].level;
    let data_basis_id = BgvBasisKind::Data.basis_id();
    for component in &parsed.components {
        if component.basis_id != data_basis_id || component.level != level {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate evaluator input must use the selected data basis at one level",
            ));
        }
    }
    let components = parsed
        .components
        .into_iter()
        .map(|component| component.residues_by_modulus)
        .collect::<Vec<_>>();
    let ciphertext = Ciphertext {
        components,
        level,
        decrypt_scaling: 1,
    };
    if let Some(expected_root) = expected_ciphertext_root {
        let actual_root = ciphertext_object_root(&ciphertext)?;
        if actual_root != expected_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate evaluator input ciphertext root does not match its canonical bytes",
            ));
        }
    }

    Ok(ciphertext)
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

// The canonical ciphertext root of an evaluator output: serialize the
// coefficient-domain components as a canonical BGV ciphertext object and root
// the bytes. Used to bind evaluator output ciphertexts into the records.
pub(crate) fn ciphertext_object_root(ciphertext: &Ciphertext) -> CanonicalResult<String> {
    let canonical_bytes = ciphertext_canonical_bytes(ciphertext)?;

    Ok(ciphertext_root(&canonical_bytes))
}

pub(crate) fn ciphertext_canonical_bytes_hex(ciphertext: &Ciphertext) -> CanonicalResult<String> {
    Ok(canonical_bytes_hex(&ciphertext_canonical_bytes(
        ciphertext,
    )?))
}

fn ciphertext_canonical_bytes(ciphertext: &Ciphertext) -> CanonicalResult<Vec<u8>> {
    let canonical_layout = layout_hash()?;
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            RnsPolynomial::coefficient_domain(
                BgvBasisKind::Data,
                ciphertext.level,
                canonical_layout.clone(),
                component.clone(),
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    serialize_bgv_object(BgvObjectKind::Ciphertext, &components)
}

fn require_same_level(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<()> {
    if left.level != right.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV evaluator operation requires ciphertexts at the same modulus level",
        ));
    }

    Ok(())
}

fn require_same_shape(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<()> {
    require_same_level(left, right)?;
    if left.decrypt_scaling != right.decrypt_scaling {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV evaluator addition requires ciphertexts with the same scaling factor",
        ));
    }

    Ok(())
}

pub(crate) fn ciphertext_add(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<Ciphertext> {
    require_same_shape(left, right)?;
    let component_count = left.components.len().max(right.components.len());
    let primes = left.primes();
    let mut components = Vec::with_capacity(component_count);
    for component_index in 0..component_count {
        let mut limbs = Vec::with_capacity(primes.len());
        for (limb_index, modulus) in primes.iter().enumerate() {
            let left_limb = left
                .components
                .get(component_index)
                .map(|component| &component[limb_index]);
            let right_limb = right
                .components
                .get(component_index)
                .map(|component| &component[limb_index]);
            let limb = (0..POLYNOMIAL_DEGREE)
                .map(|coefficient_index| {
                    let left_value = left_limb.map_or(0, |limb| limb[coefficient_index]);
                    let right_value = right_limb.map_or(0, |limb| limb[coefficient_index]);
                    add_mod(left_value, right_value, *modulus)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            limbs.push(limb);
        }
        components.push(limbs);
    }

    Ok(Ciphertext {
        components,
        level: left.level,
        decrypt_scaling: left.decrypt_scaling,
    })
}

pub(crate) fn ciphertext_negate(ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .enumerate()
                .map(|(limb_index, limb)| {
                    let modulus = primes[limb_index];
                    limb.iter()
                        .map(|value| sub_mod(0, *value, modulus))
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

pub(crate) fn ciphertext_sub(left: &Ciphertext, right: &Ciphertext) -> CanonicalResult<Ciphertext> {
    ciphertext_add(left, &ciphertext_negate(right)?)
}

fn centered_plaintext_scalar(scalar: i64) -> i64 {
    let residue = signed_residue(scalar, PLAINTEXT_MODULUS);
    if residue > PLAINTEXT_MODULUS / 2 {
        i64::try_from(i128::from(residue) - i128::from(PLAINTEXT_MODULUS))
            .expect("centered plaintext scalar fits i64")
    } else {
        i64::try_from(residue).expect("centered plaintext scalar fits i64")
    }
}

// Multiply a ciphertext by an integer plaintext scalar (the same value in every
// slot). The message is multiplied modulo the plaintext field, but the RNS lift
// uses the centered representative so negative interpolation coefficients do not
// inflate ciphertext noise by an unnecessary factor of the plaintext modulus.
pub(crate) fn scalar_mul(ciphertext: &Ciphertext, scalar: i64) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let centered_scalar = centered_plaintext_scalar(scalar);
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .enumerate()
                .map(|(limb_index, limb)| {
                    let modulus = primes[limb_index];
                    let scalar_lift = signed_residue(centered_scalar, modulus);
                    limb.iter()
                        .map(|value| mul_mod(*value, scalar_lift, modulus))
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

// Add a plaintext polynomial (coefficients in the plaintext field) into the
// ciphertext's message component, used for constant terms in polynomial
// evaluation.
pub(crate) fn add_plaintext_coefficients(
    ciphertext: &Ciphertext,
    plaintext_coefficients: &[u64],
) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let mut result = ciphertext.clone();
    for (limb_index, modulus) in primes.iter().enumerate() {
        for (target, plaintext) in result.components[0][limb_index]
            .iter_mut()
            .zip(plaintext_coefficients.iter())
        {
            *target = add_mod(*target, plaintext % modulus, *modulus)?;
        }
    }

    Ok(result)
}

// Slot-wise multiply a ciphertext by a plaintext polynomial (negacyclic product
// per limb). The message becomes the slot-wise product with the plaintext.
pub(crate) fn plaintext_mul(
    ciphertext: &Ciphertext,
    plaintext_coefficients: &[u64],
) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    #[cfg(not(target_arch = "wasm32"))]
    let limb_products = primes
        .par_iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            plaintext_mul_limb(ciphertext, plaintext_coefficients, limb_index, *modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let limb_products = primes
        .iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            plaintext_mul_limb(ciphertext, plaintext_coefficients, limb_index, *modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut components = (0..ciphertext.components.len())
        .map(|_| Vec::with_capacity(limb_products.len()))
        .collect::<Vec<_>>();
    for limb_product in limb_products {
        for (component_index, product) in limb_product.into_iter().enumerate() {
            components[component_index].push(product);
        }
    }

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

fn plaintext_mul_limb(
    ciphertext: &Ciphertext,
    plaintext_coefficients: &[u64],
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let lifted_plaintext = plaintext_coefficients
        .iter()
        .map(|coefficient| centered_plaintext_lift(*coefficient, modulus))
        .collect::<Vec<_>>();
    let plaintext_ntt = forward_negacyclic_ntt(&lifted_plaintext, modulus)?;
    ciphertext
        .components
        .iter()
        .map(|component| {
            let component_ntt = forward_negacyclic_ntt(&component[limb_index], modulus)?;
            let product_ntt = component_ntt
                .iter()
                .zip(plaintext_ntt.iter())
                .map(|(component_value, plaintext_value)| {
                    mul_mod_fast(*component_value, *plaintext_value, modulus)
                })
                .collect::<Vec<_>>();

            inverse_negacyclic_ntt(&product_ntt, modulus)
        })
        .collect()
}

fn centered_plaintext_lift(coefficient: u64, modulus: u64) -> u64 {
    let coefficient = coefficient % PLAINTEXT_MODULUS;
    if coefficient > PLAINTEXT_MODULUS / 2 {
        signed_residue(
            i64::try_from(coefficient).expect("plaintext coefficient fits i64")
                - i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
            modulus,
        )
    } else {
        coefficient % modulus
    }
}

// Homomorphic ciphertext multiplication (tensor product) of two two-component
// ciphertexts, producing the three-component ciphertext
// (a0*b0, a0*b1 + a1*b0, a1*b1) before relinearization.
pub(crate) fn ciphertext_tensor(
    left: &Ciphertext,
    right: &Ciphertext,
) -> CanonicalResult<Ciphertext> {
    require_same_level(left, right)?;
    left.assert_two_components()?;
    right.assert_two_components()?;
    let primes = left.primes();

    #[cfg(not(target_arch = "wasm32"))]
    let tensor_limbs = primes
        .par_iter()
        .enumerate()
        .map(|(limb_index, modulus)| ciphertext_tensor_limb(left, right, limb_index, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let tensor_limbs = primes
        .iter()
        .enumerate()
        .map(|(limb_index, modulus)| ciphertext_tensor_limb(left, right, limb_index, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut component_zero = Vec::with_capacity(tensor_limbs.len());
    let mut component_one = Vec::with_capacity(tensor_limbs.len());
    let mut component_two = Vec::with_capacity(tensor_limbs.len());
    for (zero, one, two) in tensor_limbs {
        component_zero.push(zero);
        component_one.push(one);
        component_two.push(two);
    }

    Ok(Ciphertext {
        components: vec![component_zero, component_one, component_two],
        level: left.level,
        decrypt_scaling: mul_mod(
            left.decrypt_scaling,
            right.decrypt_scaling,
            PLAINTEXT_MODULUS,
        )?,
    })
}

fn ciphertext_tensor_limb(
    left: &Ciphertext,
    right: &Ciphertext,
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<(Vec<u64>, Vec<u64>, Vec<u64>)> {
    let left_zero_ntt = forward_negacyclic_ntt(&left.components[0][limb_index], modulus)?;
    let left_one_ntt = forward_negacyclic_ntt(&left.components[1][limb_index], modulus)?;
    let right_zero_ntt = forward_negacyclic_ntt(&right.components[0][limb_index], modulus)?;
    let right_one_ntt = forward_negacyclic_ntt(&right.components[1][limb_index], modulus)?;

    let mut zero_ntt = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut one_ntt = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut two_ntt = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for evaluation_index in 0..POLYNOMIAL_DEGREE {
        let left_zero = left_zero_ntt[evaluation_index];
        let left_one = left_one_ntt[evaluation_index];
        let right_zero = right_zero_ntt[evaluation_index];
        let right_one = right_one_ntt[evaluation_index];
        zero_ntt.push(mul_mod_fast(left_zero, right_zero, modulus));
        let cross = add_mod_fast(
            mul_mod_fast(left_zero, right_one, modulus),
            mul_mod_fast(left_one, right_zero, modulus),
            modulus,
        );
        one_ntt.push(cross);
        two_ntt.push(mul_mod_fast(left_one, right_one, modulus));
    }

    Ok((
        inverse_negacyclic_ntt(&zero_ntt, modulus)?,
        inverse_negacyclic_ntt(&one_ntt, modulus)?,
        inverse_negacyclic_ntt(&two_ntt, modulus)?,
    ))
}

// RNS modulus switch dropping the top prime, reducing noise and moving the
// ciphertext down one level. Per coefficient the dropped limb is centered and
// subtracted, then the remaining limbs are divided by the dropped prime; the
// message is preserved up to the tracked dropped-prime scaling that decryption
// undoes.
pub(crate) fn modulus_switch(ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
    if ciphertext.level == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV evaluator cannot modulus switch below the smallest level",
        ));
    }
    let dropped_modulus = DATA_PRIMES[ciphertext.level];
    let remaining_primes = &DATA_PRIMES[..ciphertext.level];
    let dropped_inverses = remaining_primes
        .iter()
        .map(|modulus| inverse_mod(dropped_modulus % modulus, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    // To preserve the message modulo the plaintext modulus, each component
    // coefficient subtracts a correction delta with delta == c (mod dropped
    // prime) and delta == 0 (mod plaintext modulus), so delta = p * k with
    // k = c * p^{-1} (mod dropped prime), centered. After exact division by the
    // dropped prime the message is scaled by the dropped prime's inverse mod the
    // plaintext modulus, which decryption undoes.
    let plaintext_inverse_mod_dropped =
        inverse_mod(PLAINTEXT_MODULUS % dropped_modulus, dropped_modulus)?;
    let half_dropped_modulus = dropped_modulus / 2;

    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            let dropped_limb = &component[ciphertext.level];
            let corrections = dropped_limb
                .iter()
                .map(|dropped_value| {
                    let scaled = mul_mod(
                        *dropped_value,
                        plaintext_inverse_mod_dropped,
                        dropped_modulus,
                    )?;
                    let centered = if scaled > half_dropped_modulus {
                        i128::from(scaled) - i128::from(dropped_modulus)
                    } else {
                        i128::from(scaled)
                    };
                    Ok(i128::from(PLAINTEXT_MODULUS) * centered)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            remaining_primes
                .iter()
                .enumerate()
                .map(|(limb_index, modulus)| {
                    let dropped_inverse = dropped_inverses[limb_index];
                    (0..POLYNOMIAL_DEGREE)
                        .map(|coefficient_index| {
                            let correction =
                                signed_residue_i128(corrections[coefficient_index], *modulus);
                            let difference = sub_mod(
                                component[limb_index][coefficient_index],
                                correction,
                                *modulus,
                            )?;
                            mul_mod(difference, dropped_inverse, *modulus)
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level - 1,
        decrypt_scaling: mul_mod(
            ciphertext.decrypt_scaling,
            dropped_modulus % PLAINTEXT_MODULUS,
            PLAINTEXT_MODULUS,
        )?,
    })
}

// Reduce a wide signed correction into the canonical residue range of a prime.
fn signed_residue_i128(value: i128, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = ((value % modulus_i128) + modulus_i128) % modulus_i128;

    u64::try_from(reduced).expect("residue below a u64 modulus fits u64")
}

// CRT reconstruction context for a fixed prime set, precomputing the per-prime
// reconstruction factors so decryption only does big-integer additions.
struct CrtContext {
    modulus: BigInt,
    half_modulus: BigInt,
    factors: Vec<BigInt>,
    plaintext_modulus: BigInt,
}

impl CrtContext {
    fn new(primes: &[u64]) -> Self {
        let modulus: BigInt = primes.iter().map(|prime| BigInt::from(*prime)).product();
        let factors = primes
            .iter()
            .map(|prime| {
                let prime_big = BigInt::from(*prime);
                let cofactor = &modulus / &prime_big;
                let cofactor_mod = (&cofactor % &prime_big)
                    .to_u64()
                    .expect("cofactor residue below the prime fits u64");
                let inverse =
                    inverse_mod(cofactor_mod, *prime).expect("cofactor is coprime to its prime");
                (&cofactor * BigInt::from(inverse)) % &modulus
            })
            .collect::<Vec<_>>();
        let half_modulus = &modulus / 2;

        Self {
            modulus,
            half_modulus,
            factors,
            plaintext_modulus: BigInt::from(PLAINTEXT_MODULUS),
        }
    }

    fn center_then_reduce_mod_plaintext(&self, residues: &[u64]) -> u64 {
        let mut accumulator = BigInt::zero();
        for (residue, factor) in residues.iter().zip(self.factors.iter()) {
            accumulator += BigInt::from(*residue) * factor;
        }
        accumulator %= &self.modulus;
        if accumulator > self.half_modulus {
            accumulator -= &self.modulus;
        }
        let reduced = ((accumulator % &self.plaintext_modulus) + &self.plaintext_modulus)
            % &self.plaintext_modulus;

        reduced.to_u64().expect("plaintext residue fits u64")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Ciphertext, DevelopmentBgvKey, ciphertext_add, ciphertext_negate, ciphertext_sub,
        ciphertext_tensor, modulus_switch, plaintext_mul, scalar_mul,
    };
    use crate::bgv::profile::PLAINTEXT_MODULUS;

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
    fn homomorphic_addition_matches_slot_addition() {
        let key = shared_key();
        let left = key
            .encrypt_slots(&[3, 100, 65_536], "aa02")
            .expect("encrypt left");
        let right = key
            .encrypt_slots(&[4, 200, 1], "aa03")
            .expect("encrypt right");
        let sum = ciphertext_add(&left, &right).expect("add");
        assert_eq!(decrypt_prefix(key, &sum, 3), vec![7, 300, 0]);
    }

    #[test]
    fn homomorphic_subtraction_matches_slot_subtraction() {
        let key = shared_key();
        let left = key.encrypt_slots(&[10, 5], "aa04").expect("encrypt left");
        let right = key.encrypt_slots(&[3, 9], "aa05").expect("encrypt right");
        let difference = ciphertext_sub(&left, &right).expect("sub");
        assert_eq!(decrypt_prefix(key, &difference, 2), vec![7, 65_537 - 4]);
    }

    #[test]
    fn scalar_multiplication_scales_each_slot() {
        let key = shared_key();
        let ciphertext = key.encrypt_slots(&[2, 3, 4], "aa06").expect("encrypt");
        let scaled = scalar_mul(&ciphertext, 5).expect("scalar mul");
        assert_eq!(decrypt_prefix(key, &scaled, 3), vec![10, 15, 20]);
    }

    #[test]
    fn scalar_multiplication_uses_centered_lift_for_negative_plaintext_scalars() {
        let key = shared_key();
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
    fn plaintext_multiplication_is_slot_wise() {
        let key = shared_key();
        let ciphertext = key.encrypt_slots(&[2, 3, 4, 5], "aa07").expect("encrypt");
        let plaintext = super::encode_slots_to_coefficients(&[10, 0, 7, 1]).expect("encode");
        let product = plaintext_mul(&ciphertext, &plaintext).expect("plaintext mul");
        assert_eq!(decrypt_prefix(key, &product, 4), vec![20, 0, 28, 5]);
    }

    #[test]
    fn ciphertext_multiplication_yields_slot_products() {
        let key = shared_key();
        let left = key.encrypt_slots(&[2, 3, 4], "aa08").expect("encrypt left");
        let right = key
            .encrypt_slots(&[5, 6, 7], "aa09")
            .expect("encrypt right");
        let product = ciphertext_tensor(&left, &right).expect("tensor");
        assert_eq!(product.component_count(), 3);
        assert_eq!(decrypt_prefix(key, &product, 3), vec![10, 18, 28]);
    }

    #[test]
    fn modulus_switch_preserves_slots_and_drops_a_level() {
        let key = shared_key();
        let ciphertext = key
            .encrypt_slots(&[11, 22, 65_500], "aa10")
            .expect("encrypt");
        let switched = modulus_switch(&ciphertext).expect("modulus switch");
        assert_eq!(switched.level, ciphertext.level - 1);
        assert_eq!(decrypt_prefix(key, &switched, 3), vec![11, 22, 65_500]);
    }

    #[test]
    fn repeated_modulus_switch_chain_preserves_message() {
        let key = shared_key();
        let mut ciphertext = key.encrypt_slots(&[42, 9, 100], "aa11").expect("encrypt");
        for _ in 0..4 {
            ciphertext = modulus_switch(&ciphertext).expect("modulus switch");
        }
        assert_eq!(ciphertext.level, super::EVALUATOR_FULL_LEVEL - 4);
        assert_eq!(decrypt_prefix(key, &ciphertext, 3), vec![42, 9, 100]);
    }
}
