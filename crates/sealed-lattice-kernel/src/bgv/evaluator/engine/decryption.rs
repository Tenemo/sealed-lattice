use super::*;
use crate::bgv::parameters::PLAINTEXT_MODULUS;
use num_bigint::{BigInt, BigUint};
use num_traits::{ToPrimitive, Zero};

const EXACT_ERROR_RECONSTRUCTION_PRIME_LIMIT: usize = 4;

pub(crate) struct ExactDecryptionErrorObserver {
    secret_ntt_by_modulus: Vec<Vec<u64>>,
    secret_square_ntt_by_modulus: Vec<Vec<u64>>,
}

impl ExactDecryptionErrorObserver {
    pub(super) fn new(secret: &[i64]) -> CanonicalResult<Self> {
        if secret.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV exact decryption-error observer requires one secret coefficient per ring coefficient",
            ));
        }

        let mut secret_ntt_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
        let mut secret_square_ntt_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
        for modulus in DATA_PRIMES {
            let mut secret_ntt = secret
                .iter()
                .map(|coefficient| signed_residue(*coefficient, modulus))
                .collect::<Vec<_>>();
            forward_negacyclic_ntt_in_place(&mut secret_ntt, modulus)?;
            let secret_square_ntt = secret_ntt
                .iter()
                .map(|coefficient| mul_mod_fast(*coefficient, *coefficient, modulus))
                .collect::<Vec<_>>();
            secret_ntt_by_modulus.push(secret_ntt);
            secret_square_ntt_by_modulus.push(secret_square_ntt);
        }

        Ok(Self {
            secret_ntt_by_modulus,
            secret_square_ntt_by_modulus,
        })
    }

    pub(crate) fn measure_infinity_norm(
        &self,
        ciphertext: &Ciphertext,
        expected_plaintext_coefficients: &[u64],
    ) -> CanonicalResult<BigUint> {
        if ciphertext.decrypt_scaling == 0 || ciphertext.decrypt_scaling >= PLAINTEXT_MODULUS {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "BGV exact decryption-error observation requires a canonical nonzero decryption multiplier",
            ));
        }
        if expected_plaintext_coefficients.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV exact decryption-error observation requires one expected plaintext coefficient per ring coefficient",
            ));
        }
        if expected_plaintext_coefficients
            .iter()
            .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "BGV exact decryption-error observation received a non-canonical expected plaintext coefficient",
            ));
        }
        let accumulator = self.decryption_accumulator(ciphertext)?;

        exact_decryption_error_infinity_norm(
            ciphertext,
            &accumulator,
            expected_plaintext_coefficients,
        )
    }

    fn decryption_accumulator(&self, ciphertext: &Ciphertext) -> CanonicalResult<Vec<Vec<u64>>> {
        validate_observed_ciphertext(ciphertext)?;
        let primes = ciphertext.primes();
        let mut accumulator = ciphertext.components[0].clone();

        for component_index in 1..ciphertext.components.len() {
            let secret_power_ntt_by_modulus = match component_index {
                1 => &self.secret_ntt_by_modulus,
                2 => &self.secret_square_ntt_by_modulus,
                _ => {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidProtocolObject,
                        "BGV exact decryption-error observer supports at most three ciphertext components",
                    ));
                }
            };
            for (limb_index, modulus) in primes.iter().copied().enumerate() {
                let mut product = ciphertext.components[component_index][limb_index].clone();
                forward_negacyclic_ntt_in_place(&mut product, modulus)?;
                for (coefficient, secret_power) in product
                    .iter_mut()
                    .zip(secret_power_ntt_by_modulus[limb_index].iter())
                {
                    *coefficient = mul_mod_fast(*coefficient, *secret_power, modulus);
                }
                inverse_negacyclic_ntt_in_place(&mut product, modulus)?;
                for (accumulated, added) in accumulator[limb_index].iter_mut().zip(product) {
                    *accumulated = add_mod_fast(*accumulated, added, modulus);
                }
            }
        }

        Ok(accumulator)
    }
}

fn validate_observed_ciphertext(ciphertext: &Ciphertext) -> CanonicalResult<()> {
    if ciphertext.level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV exact decryption-error observer received an unavailable data-prime level",
        ));
    }
    if ciphertext.components.is_empty() || ciphertext.components.len() > 3 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV exact decryption-error observer requires one to three ciphertext components",
        ));
    }
    let primes = ciphertext.primes();
    for (component_index, component) in ciphertext.components.iter().enumerate() {
        if component.len() != primes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!(
                    "BGV exact decryption-error observer component {component_index} must have one limb per active data prime"
                ),
            ));
        }
        for (limb_index, (limb, modulus)) in component.iter().zip(primes.iter()).enumerate() {
            if limb.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!(
                        "BGV exact decryption-error observer component {component_index} limb {limb_index} has the wrong coefficient count"
                    ),
                ));
            }
            if limb.iter().any(|coefficient| *coefficient >= *modulus) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    format!(
                        "BGV exact decryption-error observer component {component_index} limb {limb_index} has non-canonical residues"
                    ),
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn decryption_accumulator_to_coefficients(
    ciphertext: &Ciphertext,
    accumulator: &[Vec<u64>],
) -> CanonicalResult<Vec<u64>> {
    let primes = ciphertext.primes();
    if accumulator.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV decryption accumulator must have one limb per active data prime",
        ));
    }
    for (limb_index, (limb, modulus)) in accumulator.iter().zip(primes.iter()).enumerate() {
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!(
                    "BGV decryption accumulator limb {limb_index} has the wrong coefficient count"
                ),
            ));
        }
        if limb.iter().any(|coefficient| *coefficient >= *modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("BGV decryption accumulator limb {limb_index} has non-canonical residues"),
            ));
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

pub(crate) fn exact_decryption_error_infinity_norm(
    ciphertext: &Ciphertext,
    accumulator: &[Vec<u64>],
    expected_plaintext_coefficients: &[u64],
) -> CanonicalResult<BigUint> {
    if ciphertext.decrypt_scaling == 0 || ciphertext.decrypt_scaling >= PLAINTEXT_MODULUS {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV exact decryption-error observation requires a canonical nonzero decryption multiplier",
        ));
    }
    if expected_plaintext_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV exact decryption-error observation requires one expected plaintext coefficient per ring coefficient",
        ));
    }
    if expected_plaintext_coefficients
        .iter()
        .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV exact decryption-error observation received a non-canonical expected plaintext coefficient",
        ));
    }

    validate_decryption_accumulator(ciphertext, accumulator)?;
    let primes = ciphertext.primes();
    let scaling_inverse = inverse_mod(ciphertext.decrypt_scaling, PLAINTEXT_MODULUS)?;
    let reconstruction_context = ExactErrorReconstructionContext::new(primes)?;
    let mut infinity_norm = BigUint::zero();

    for (coefficient_index, expected_plaintext_coefficient) in
        expected_plaintext_coefficients.iter().copied().enumerate()
    {
        let raw_plaintext_residue = mul_mod(
            expected_plaintext_coefficient,
            scaling_inverse,
            PLAINTEXT_MODULUS,
        )?;
        let centered_raw_plaintext = if raw_plaintext_residue > PLAINTEXT_MODULUS / 2 {
            i128::from(raw_plaintext_residue) - i128::from(PLAINTEXT_MODULUS)
        } else {
            i128::from(raw_plaintext_residue)
        };

        let centered_error = reconstruction_context.reconstruct_centered_error(
            accumulator,
            coefficient_index,
            centered_raw_plaintext,
        )?;
        let centered_accumulator = centered_error
            .checked_mul(i128::from(PLAINTEXT_MODULUS))
            .and_then(|value| value.checked_add(centered_raw_plaintext))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "BGV exact decryption-error observation exceeded its fixed-width error window",
                )
            })?;
        if centered_accumulator.unsigned_abs() > reconstruction_context.modulus() / 2 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!(
                    "BGV exact decryption-error observation exceeded its exact centering window at coefficient {coefficient_index}"
                ),
            ));
        }
        if accumulator
            .iter()
            .zip(primes.iter())
            .any(|(limb, modulus)| {
                signed_i128_residue(centered_accumulator, *modulus) != limb[coefficient_index]
            })
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!(
                    "BGV exact decryption-error observation could not certify coefficient {coefficient_index} inside the fixed-width reconstruction window"
                ),
            ));
        }
        let scaled_error = centered_accumulator - centered_raw_plaintext;
        if scaled_error % i128::from(PLAINTEXT_MODULUS) != 0
            || scaled_error / i128::from(PLAINTEXT_MODULUS) != centered_error
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!(
                    "BGV exact decryption-error observation found a non-divisible coefficient at index {coefficient_index}"
                ),
            ));
        }
        infinity_norm = infinity_norm.max(BigUint::from(centered_error.unsigned_abs()));
    }

    Ok(infinity_norm)
}

fn exact_error_residue(
    accumulator_residue: u64,
    centered_raw_plaintext: i128,
    modulus: u64,
    plaintext_inverse: u64,
) -> CanonicalResult<u64> {
    let raw_plaintext_residue = signed_i128_residue(centered_raw_plaintext, modulus);
    let difference = sub_mod(accumulator_residue, raw_plaintext_residue, modulus)?;

    mul_mod(difference, plaintext_inverse, modulus)
}

struct ExactErrorReconstructionStep {
    modulus: u64,
    plaintext_inverse: u64,
    accumulated_modulus: u128,
    accumulated_modulus_inverse: u64,
}

struct ExactErrorReconstructionContext {
    steps: Vec<ExactErrorReconstructionStep>,
    modulus: u128,
    signed_modulus: i128,
}

impl ExactErrorReconstructionContext {
    fn new(primes: &[u64]) -> CanonicalResult<Self> {
        let mut steps =
            Vec::with_capacity(primes.len().min(EXACT_ERROR_RECONSTRUCTION_PRIME_LIMIT));
        let mut accumulated_modulus = 1_u128;
        for modulus in primes
            .iter()
            .copied()
            .take(EXACT_ERROR_RECONSTRUCTION_PRIME_LIMIT)
        {
            let accumulated_modulus_residue =
                u64::try_from(accumulated_modulus % u128::from(modulus))
                    .expect("residue below a selected data prime fits u64");
            steps.push(ExactErrorReconstructionStep {
                modulus,
                plaintext_inverse: inverse_mod(PLAINTEXT_MODULUS % modulus, modulus)?,
                accumulated_modulus,
                accumulated_modulus_inverse: inverse_mod(accumulated_modulus_residue, modulus)?,
            });
            accumulated_modulus = accumulated_modulus
                .checked_mul(u128::from(modulus))
                .ok_or_else(reconstruction_width_error)?;
        }
        let signed_modulus =
            i128::try_from(accumulated_modulus).map_err(|_| reconstruction_width_error())?;

        Ok(Self {
            steps,
            modulus: accumulated_modulus,
            signed_modulus,
        })
    }

    fn modulus(&self) -> u128 {
        self.modulus
    }

    fn reconstruct_centered_error(
        &self,
        accumulator: &[Vec<u64>],
        coefficient_index: usize,
        centered_raw_plaintext: i128,
    ) -> CanonicalResult<i128> {
        let mut canonical = 0_u128;
        for (limb_index, step) in self.steps.iter().enumerate() {
            let error_residue = exact_error_residue(
                accumulator[limb_index][coefficient_index],
                centered_raw_plaintext,
                step.modulus,
                step.plaintext_inverse,
            )?;
            let canonical_residue = u64::try_from(canonical % u128::from(step.modulus))
                .expect("residue below a selected data prime fits u64");
            let correction = sub_mod(error_residue, canonical_residue, step.modulus)?;
            let correction_multiplier =
                mul_mod(correction, step.accumulated_modulus_inverse, step.modulus)?;
            let correction_value = step
                .accumulated_modulus
                .checked_mul(u128::from(correction_multiplier))
                .ok_or_else(reconstruction_width_error)?;
            canonical = canonical
                .checked_add(correction_value)
                .ok_or_else(reconstruction_width_error)?;
        }
        let canonical = i128::try_from(canonical).map_err(|_| reconstruction_width_error())?;

        Ok(if canonical > self.signed_modulus / 2 {
            canonical - self.signed_modulus
        } else {
            canonical
        })
    }
}

fn reconstruction_width_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "BGV exact decryption-error observation exceeded its fixed-width reconstruction product",
    )
}

fn signed_i128_residue(value: i128, modulus: u64) -> u64 {
    let modulus = i128::from(modulus);
    let residue = ((value % modulus) + modulus) % modulus;

    u64::try_from(residue).expect("residue below a u64 modulus fits u64")
}

fn validate_decryption_accumulator(
    ciphertext: &Ciphertext,
    accumulator: &[Vec<u64>],
) -> CanonicalResult<()> {
    if ciphertext.level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV decryption accumulator has an unavailable data-prime level",
        ));
    }

    let primes = ciphertext.primes();
    if accumulator.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV decryption accumulator must have one limb per active data prime",
        ));
    }
    for (limb_index, (limb, modulus)) in accumulator.iter().zip(primes.iter()).enumerate() {
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!(
                    "BGV decryption accumulator limb {limb_index} has the wrong coefficient count"
                ),
            ));
        }
        if limb.iter().any(|coefficient| *coefficient >= *modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("BGV decryption accumulator limb {limb_index} has non-canonical residues"),
            ));
        }
    }

    Ok(())
}

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
        let accumulator = self.center(residues);
        let reduced = ((accumulator % &self.plaintext_modulus) + &self.plaintext_modulus)
            % &self.plaintext_modulus;

        reduced.to_u64().expect("plaintext residue fits u64")
    }

    fn center(&self, residues: &[u64]) -> BigInt {
        let mut accumulator = BigInt::zero();
        for (residue, factor) in residues.iter().zip(self.factors.iter()) {
            accumulator += BigInt::from(*residue) * factor;
        }
        accumulator %= &self.modulus;
        if accumulator > self.half_modulus {
            accumulator -= &self.modulus;
        }

        accumulator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_error_observer_uses_centered_scaled_plaintext_and_rejects_invalid_inputs() {
        let ciphertext = Ciphertext {
            components: Vec::new(),
            level: 0,
            decrypt_scaling: 3,
        };
        let mut expected_plaintext_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        expected_plaintext_coefficients[..4].copy_from_slice(&[42, 256, 128, 129]);

        // Three has inverse 86 modulo 257. The centered raw plaintext
        // representatives for the four expected coefficients are therefore
        // 14, -86, -43, and 43. Add exact multiples of 257 with both signs.
        let mut accumulator_limb = vec![0_u64; POLYNOMIAL_DEGREE];
        let centered_accumulator_coefficients = [2_841_i64, -3_427, 1_756, -1_242];
        for (coefficient_index, coefficient) in
            centered_accumulator_coefficients.into_iter().enumerate()
        {
            accumulator_limb[coefficient_index] = signed_residue(coefficient, DATA_PRIMES[0]);
        }
        let accumulator = vec![accumulator_limb];

        assert_eq!(
            exact_decryption_error_infinity_norm(
                &ciphertext,
                &accumulator,
                &expected_plaintext_coefficients,
            )
            .expect("exact centered errors are observable"),
            BigUint::from(13_u8),
        );

        let mut wrong_expected_plaintext = expected_plaintext_coefficients.clone();
        wrong_expected_plaintext[0] = 43;
        assert!(
            exact_decryption_error_infinity_norm(
                &ciphertext,
                &accumulator,
                &wrong_expected_plaintext,
            )
            .is_err()
        );

        let mut noncanonical_expected_plaintext = expected_plaintext_coefficients.clone();
        noncanonical_expected_plaintext[0] = PLAINTEXT_MODULUS;
        assert!(
            exact_decryption_error_infinity_norm(
                &ciphertext,
                &accumulator,
                &noncanonical_expected_plaintext,
            )
            .is_err()
        );

        let mut zero_scaling_ciphertext = ciphertext.clone();
        zero_scaling_ciphertext.decrypt_scaling = 0;
        assert!(
            exact_decryption_error_infinity_norm(
                &zero_scaling_ciphertext,
                &accumulator,
                &expected_plaintext_coefficients,
            )
            .is_err()
        );

        let mut noncanonical_accumulator = accumulator;
        noncanonical_accumulator[0][0] = DATA_PRIMES[0];
        assert!(
            exact_decryption_error_infinity_norm(
                &ciphertext,
                &noncanonical_accumulator,
                &expected_plaintext_coefficients,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_error_observer_reconstructs_four_primes_and_verifies_later_active_limbs() {
        let ciphertext = Ciphertext {
            components: Vec::new(),
            level: 4,
            decrypt_scaling: 3,
        };
        let mut expected_plaintext_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        expected_plaintext_coefficients[0] = 42;
        let two_prime_product = i128::from(DATA_PRIMES[0]) * i128::from(DATA_PRIMES[1]);
        let three_prime_product = two_prime_product * i128::from(DATA_PRIMES[2]);
        let expected_error = three_prime_product / 2 + 1;
        assert!(expected_error > two_prime_product / 2);
        assert!(expected_error > three_prime_product / 2);
        let centered_accumulator = 14_i128 + i128::from(PLAINTEXT_MODULUS) * expected_error;
        let mut accumulator = DATA_PRIMES[..=ciphertext.level]
            .iter()
            .map(|_| vec![0_u64; POLYNOMIAL_DEGREE])
            .collect::<Vec<_>>();
        for (limb, modulus) in accumulator.iter_mut().zip(ciphertext.primes()) {
            limb[0] = signed_i128_residue(centered_accumulator, *modulus);
        }

        assert_eq!(
            exact_decryption_error_infinity_norm(
                &ciphertext,
                &accumulator,
                &expected_plaintext_coefficients,
            )
            .expect("wide error is certified by every active limb"),
            BigUint::from(expected_error.unsigned_abs()),
        );

        let mut inconsistent_accumulator = accumulator;
        inconsistent_accumulator[4][0] = (inconsistent_accumulator[4][0] + 1) % DATA_PRIMES[4];
        assert!(
            exact_decryption_error_infinity_norm(
                &ciphertext,
                &inconsistent_accumulator,
                &expected_plaintext_coefficients,
            )
            .is_err()
        );
    }

    #[test]
    fn selected_worst_evaluator_error_fits_the_four_prime_reconstruction_window() {
        const SELECTED_WORST_EVALUATOR_ERROR: u128 = 16_873_484_365_703_521_901_782_467_690_810;
        const SELECTED_FOUR_PRIME_PRODUCT: u128 =
            27_725_714_049_516_016_625_201_161_562_797_375_489;

        let ciphertext = Ciphertext {
            components: Vec::new(),
            level: 3,
            decrypt_scaling: 1,
        };
        let four_prime_product =
            DATA_PRIMES[..=ciphertext.level]
                .iter()
                .fold(1_u128, |product, modulus| {
                    product
                        .checked_mul(u128::from(*modulus))
                        .expect("selected four-prime product fits u128")
                });
        assert_eq!(four_prime_product, SELECTED_FOUR_PRIME_PRODUCT);
        let selected_worst_error = i128::try_from(SELECTED_WORST_EVALUATOR_ERROR)
            .expect("selected worst evaluator error fits i128");
        let centered_accumulator = selected_worst_error
            .checked_mul(i128::from(PLAINTEXT_MODULUS))
            .expect("selected worst evaluator accumulator fits i128");
        assert!(centered_accumulator.unsigned_abs() < four_prime_product / 2);

        let expected_plaintext_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        let mut accumulator = DATA_PRIMES[..=ciphertext.level]
            .iter()
            .map(|_| vec![0_u64; POLYNOMIAL_DEGREE])
            .collect::<Vec<_>>();
        for (limb, modulus) in accumulator.iter_mut().zip(ciphertext.primes()) {
            limb[0] = signed_i128_residue(centered_accumulator, *modulus);
        }

        assert_eq!(
            exact_decryption_error_infinity_norm(
                &ciphertext,
                &accumulator,
                &expected_plaintext_coefficients,
            )
            .expect("selected worst evaluator error is inside the exact reconstruction window"),
            BigUint::from(SELECTED_WORST_EVALUATOR_ERROR),
        );
    }

    #[test]
    fn exact_error_observer_cache_handles_three_component_ciphertext() {
        let mut secret = vec![0_i64; POLYNOMIAL_DEGREE];
        secret[0] = 1;
        let development_key = DevelopmentBgvKey {
            secret,
            public_b: Vec::new(),
            public_a: Vec::new(),
        };
        let observer = development_key
            .exact_decryption_error_observer()
            .expect("test-only exact observer cache is constructed");
        let level = 2;
        let components = [2_i128, -3, 5]
            .into_iter()
            .map(|error| {
                DATA_PRIMES[..=level]
                    .iter()
                    .map(|modulus| {
                        let mut limb = vec![0_u64; POLYNOMIAL_DEGREE];
                        limb[0] =
                            signed_i128_residue(i128::from(PLAINTEXT_MODULUS) * error, *modulus);
                        limb
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let ciphertext = Ciphertext {
            components,
            level,
            decrypt_scaling: 1,
        };
        let expected_plaintext_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];

        assert_eq!(
            observer
                .measure_infinity_norm(&ciphertext, &expected_plaintext_coefficients)
                .expect("three-component exact error is observed"),
            BigUint::from(4_u8),
        );
        assert_eq!(
            development_key
                .exact_decryption_error_infinity_norm(
                    &ciphertext,
                    &expected_plaintext_coefficients,
                )
                .expect("one-shot exact error observation agrees with the reusable cache"),
            BigUint::from(4_u8),
        );
    }
}
