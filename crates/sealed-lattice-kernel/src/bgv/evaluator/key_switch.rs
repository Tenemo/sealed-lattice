use num_bigint::{BigInt, BigUint, Sign};
use num_traits::ToPrimitive;

use crate::{
    bgv::{
        evaluator::{
            engine::{Ciphertext, DevelopmentBgvKey, negacyclic_mul, signed_residue},
            prg::DeterministicSampler,
        },
        modular_arithmetic::{add_mod, add_mod_fast, inverse_mod, mul_mod, mul_mod_fast, sub_mod},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIME},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

mod rotation;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
#[cfg(test)]
use rotation::automorphism_residues;
pub(crate) use rotation::{generate_galois_key, rotate};

pub(crate) const PLAINTEXT_MODULUS_I64: i64 = 65_537;
pub(crate) const KEY_SWITCH_ERROR_DOMAIN: &str = "sealed-lattice-bgv-evaluator/key-switch-error";
pub(crate) const KEY_SWITCH_SAMPLE_DOMAIN: &str = "sealed-lattice-bgv-evaluator/key-switch-sample";
pub(crate) const KEY_SWITCH_DATA_PRIMES_PER_BLOCK: usize = 1;

// A polynomial component held as residue vectors, one per active prime.
type LimbMatrix = Vec<Vec<u64>>;

// A leveled hybrid RNS key-switching key. Each component is one contiguous
// data-prime block in the extended Q*P basis. Its gadget is P times the block
// CRT idempotent, and key application performs exact centered block extension
// followed by the plaintext-preserving BGV correction modulus-down.
#[derive(Clone)]
pub(crate) struct KeySwitchKey {
    pub(crate) level: usize,
    pub(crate) components: Vec<KeySwitchComponent>,
    data_primes_per_block: usize,
}

#[derive(Clone)]
pub(crate) struct KeySwitchComponent {
    component_b_ntt: Vec<Vec<u64>>,
    component_a_ntt: Vec<Vec<u64>>,
    moduli: Vec<u64>,
}

impl KeySwitchComponent {
    #[cfg(test)]
    pub(crate) fn component_b_coefficients(&self) -> CanonicalResult<Vec<Vec<u64>>> {
        self.component_b_ntt
            .iter()
            .zip(self.moduli.iter())
            .map(|(component_b_limb_ntt, modulus)| {
                inverse_negacyclic_ntt(component_b_limb_ntt, *modulus)
            })
            .collect()
    }

    fn from_coefficients(
        component_b: Vec<Vec<u64>>,
        component_a: Vec<Vec<u64>>,
        primes: &[u64],
    ) -> CanonicalResult<Self> {
        let component_b_ntt = ntt_limbs(&component_b, primes)?;
        let component_a_ntt = ntt_limbs(&component_a, primes)?;
        drop(component_b);
        drop(component_a);

        Ok(Self {
            component_b_ntt,
            component_a_ntt,
            moduli: primes.to_vec(),
        })
    }
}

fn ntt_limbs(limbs: &[Vec<u64>], primes: &[u64]) -> CanonicalResult<Vec<Vec<u64>>> {
    if limbs.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component limb count does not match its modulus level",
        ));
    }

    evaluator_parallel_iterator!(
        limbs.par_iter().zip(primes.par_iter()),
        limbs.iter().zip(primes.iter())
    )
    .map(|(limb, modulus)| forward_negacyclic_ntt(limb, *modulus))
    .collect()
}

fn extended_moduli_for_level(level: usize) -> CanonicalResult<Vec<u64>> {
    if level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "hybrid key-switch level is outside the selected data basis",
        ));
    }
    let mut moduli = DATA_PRIMES[..=level].to_vec();
    moduli.push(SPECIAL_PRIME);
    Ok(moduli)
}

fn secret_residues_for_moduli(secret: &[i64], moduli: &[u64]) -> Vec<Vec<u64>> {
    evaluator_parallel_iterator!(moduli.par_iter(), moduli.iter())
        .map(|modulus| {
            secret
                .iter()
                .map(|coefficient| signed_residue(*coefficient, *modulus))
                .collect::<Vec<_>>()
        })
        .collect()
}

// Generate a key-switching key for a source polynomial whose RNS limbs are
// `source_limbs` (one residue vector per active prime), under the development
// secret, at the given modulus level.
fn generate_key_switch_key(
    key: &DevelopmentBgvKey,
    source_limbs: &[Vec<u64>],
    level: usize,
    domain: &str,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchKey> {
    generate_key_switch_key_with_block_size(
        key,
        source_limbs,
        level,
        domain,
        seed_hex,
        KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
    )
}

fn generate_key_switch_key_with_block_size(
    key: &DevelopmentBgvKey,
    source_limbs: &[Vec<u64>],
    level: usize,
    domain: &str,
    seed_hex: &str,
    data_primes_per_block: usize,
) -> CanonicalResult<KeySwitchKey> {
    if data_primes_per_block == 0 || data_primes_per_block > level + 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "hybrid key-switch block size must be between one and the active data-prime count",
        ));
    }
    if source_limbs.len() != level + 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "hybrid key-switch source has the wrong data-limb count",
        ));
    }
    let extended_moduli = extended_moduli_for_level(level)?;
    let secret_residues = secret_residues_for_moduli(key.secret(), &extended_moduli);
    let block_count = (level + 1).div_ceil(data_primes_per_block);
    let components = (0..block_count)
        .map(|block_index| {
            generate_key_switch_component_for_block(
                &extended_moduli,
                &secret_residues,
                source_limbs,
                block_index,
                data_primes_per_block,
                domain,
                seed_hex,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(KeySwitchKey {
        level,
        components,
        data_primes_per_block,
    })
}

fn generate_key_switch_component_for_block(
    extended_moduli: &[u64],
    secret_residues: &[Vec<u64>],
    source_limbs: &[Vec<u64>],
    block_index: usize,
    data_primes_per_block: usize,
    domain: &str,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchComponent> {
    let block_bytes = (block_index as u64).to_le_bytes();
    // One small error polynomial per decomposition block, shared across every
    // Q and P limb so the extended residues encode one bounded integer.
    let error = DeterministicSampler::new(
        KEY_SWITCH_ERROR_DOMAIN,
        &[domain.as_bytes(), seed_hex.as_bytes(), &block_bytes],
    )
    .centered_binomial_eta2(POLYNOMIAL_DEGREE);
    let data_limb_count = source_limbs.len();
    let block_start = block_index * data_primes_per_block;
    let block_end = data_limb_count.min(block_start + data_primes_per_block);
    let limbs = evaluator_parallel_iterator!(extended_moduli.par_iter(), extended_moduli.iter())
        .enumerate()
        .map(|(limb_index, modulus)| {
            let source_limb = (limb_index < data_limb_count
                && (block_start..block_end).contains(&limb_index))
            .then(|| source_limbs[limb_index].as_slice());
            generate_key_switch_component_limb_for_block(KeySwitchComponentLimbInput {
                secret_residue_limb: &secret_residues[limb_index],
                source_limb,
                error: &error,
                modulus: *modulus,
                block_index,
                domain,
                seed_hex,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let (component_b, component_a) = limbs.into_iter().unzip();

    KeySwitchComponent::from_coefficients(component_b, component_a, extended_moduli)
}

struct KeySwitchComponentLimbInput<'a> {
    secret_residue_limb: &'a [u64],
    source_limb: Option<&'a [u64]>,
    error: &'a [i64],
    modulus: u64,
    block_index: usize,
    domain: &'a str,
    seed_hex: &'a str,
}

fn generate_key_switch_component_limb_for_block(
    input: KeySwitchComponentLimbInput<'_>,
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    let public_sample = public_component_a_limb(
        input.domain,
        input.seed_hex,
        input.block_index,
        input.modulus,
    );
    let public_sample_secret_product =
        negacyclic_mul(&public_sample, input.secret_residue_limb, input.modulus)?;
    let component_b_limb = (0..POLYNOMIAL_DEGREE)
        .map(|coefficient_index| {
            // Noise is scaled by the plaintext modulus t so it lies in t*Z and
            // vanishes under the final mod-t reduction.
            let scaled_error = signed_residue(
                input.error[coefficient_index] * PLAINTEXT_MODULUS_I64,
                input.modulus,
            );
            let mut value = sub_mod(
                scaled_error,
                public_sample_secret_product[coefficient_index],
                input.modulus,
            )?;
            if let Some(source_limb) = input.source_limb {
                let gadget_source = mul_mod(
                    source_limb[coefficient_index],
                    SPECIAL_PRIME % input.modulus,
                    input.modulus,
                )?;
                value = add_mod(value, gadget_source, input.modulus)?;
            }
            Ok(value)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok((component_b_limb, public_sample))
}

fn public_component_a_limb(
    domain: &str,
    seed_hex: &str,
    block_index: usize,
    modulus: u64,
) -> Vec<u64> {
    let block_bytes = (block_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    DeterministicSampler::new(
        KEY_SWITCH_SAMPLE_DOMAIN,
        &[
            domain.as_bytes(),
            seed_hex.as_bytes(),
            &block_bytes,
            &modulus_bytes,
        ],
    )
    .uniform_residues(modulus, POLYNOMIAL_DEGREE)
}

// Apply a key-switching key to a single ciphertext component (the term that
// multiplies the source key), producing the two-component RLWE encryption of
// source * term under the secret. The key may be generated at a higher level
// than the term: the CRT-idempotent gadget keys public samples by digit and
// modulus only, so the digits and limbs 0..=term_level of a higher-level key
// are exactly the lower-level key, and the active window is sliced here.
fn key_switch_component(
    term: &[Vec<u64>],
    key_switch_key: &KeySwitchKey,
) -> CanonicalResult<(LimbMatrix, LimbMatrix)> {
    let term_level = term.len().checked_sub(1).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "key-switch term must carry at least one limb",
        )
    })?;
    if key_switch_key.level < term_level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "key-switching key level is below the term level",
        ));
    }
    if term.iter().any(|limb| limb.len() != POLYNOMIAL_DEGREE) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "hybrid key-switch term has the wrong coefficient count",
        ));
    }
    for (limb, modulus) in term.iter().zip(DATA_PRIMES[..=term_level].iter()) {
        if limb.iter().any(|value| *value >= *modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "hybrid key-switch term contains a non-canonical residue",
            ));
        }
    }
    let active_block_count = (term_level + 1).div_ceil(key_switch_key.data_primes_per_block);
    if key_switch_key.components.len() < active_block_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "hybrid key-switch key is missing an active decomposition block",
        ));
    }
    let extended_moduli = extended_moduli_for_level(term_level)?;
    let stored_special_limb_index = key_switch_key.level + 1;
    let mut extended_zero_ntt = vec![vec![0_u64; POLYNOMIAL_DEGREE]; extended_moduli.len()];
    let mut extended_one_ntt = vec![vec![0_u64; POLYNOMIAL_DEGREE]; extended_moduli.len()];

    for (block_index, component) in key_switch_key.components[..active_block_count]
        .iter()
        .enumerate()
    {
        let block_start = block_index * key_switch_key.data_primes_per_block;
        let block_end = (term_level + 1).min(block_start + key_switch_key.data_primes_per_block);
        let digit = centered_block_reconstruction(
            &term[block_start..block_end],
            &DATA_PRIMES[block_start..block_end],
        )?;
        for (extended_limb_index, modulus) in extended_moduli.iter().copied().enumerate() {
            let stored_limb_index = if extended_limb_index <= term_level {
                extended_limb_index
            } else {
                stored_special_limb_index
            };
            if component.moduli.get(stored_limb_index) != Some(&modulus) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "hybrid key-switch component basis does not match its key level",
                ));
            }
            let digit_ntt = forward_negacyclic_ntt(&digit.residues(modulus)?, modulus)?;
            for coefficient_index in 0..POLYNOMIAL_DEGREE {
                extended_zero_ntt[extended_limb_index][coefficient_index] = add_mod_fast(
                    extended_zero_ntt[extended_limb_index][coefficient_index],
                    mul_mod_fast(
                        digit_ntt[coefficient_index],
                        component.component_b_ntt[stored_limb_index][coefficient_index],
                        modulus,
                    ),
                    modulus,
                );
                extended_one_ntt[extended_limb_index][coefficient_index] = add_mod_fast(
                    extended_one_ntt[extended_limb_index][coefficient_index],
                    mul_mod_fast(
                        digit_ntt[coefficient_index],
                        component.component_a_ntt[stored_limb_index][coefficient_index],
                        modulus,
                    ),
                    modulus,
                );
            }
        }
    }

    let extended_zero = extended_zero_ntt
        .iter()
        .zip(extended_moduli.iter())
        .map(|(limb, modulus)| inverse_negacyclic_ntt(limb, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let extended_one = extended_one_ntt
        .iter()
        .zip(extended_moduli.iter())
        .map(|(limb, modulus)| inverse_negacyclic_ntt(limb, *modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok((
        hybrid_modulus_down(&extended_zero, term_level)?,
        hybrid_modulus_down(&extended_one, term_level)?,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CenteredBlockCoefficients {
    Small(Vec<i64>),
    Wide(Vec<BigInt>),
}

impl CenteredBlockCoefficients {
    fn residues(&self, modulus: u64) -> CanonicalResult<Vec<u64>> {
        match self {
            Self::Small(coefficients) => Ok(coefficients
                .iter()
                .map(|coefficient| signed_residue(*coefficient, modulus))
                .collect()),
            Self::Wide(coefficients) => coefficients
                .iter()
                .map(|coefficient| bigint_residue(coefficient, modulus))
                .collect(),
        }
    }
}

fn centered_block_reconstruction(
    residue_limbs: &[Vec<u64>],
    moduli: &[u64],
) -> CanonicalResult<CenteredBlockCoefficients> {
    if residue_limbs.is_empty() || residue_limbs.len() != moduli.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "centered block reconstruction requires one non-empty limb per modulus",
        ));
    }
    for (limb, modulus) in residue_limbs.iter().zip(moduli.iter()) {
        if limb.len() != POLYNOMIAL_DEGREE || limb.iter().any(|value| *value >= *modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "centered block reconstruction received a malformed residue limb",
            ));
        }
    }
    if moduli.len() == 1 {
        let modulus = i64::try_from(moduli[0]).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "single-limb centered reconstruction modulus does not fit i64",
            )
        })?;
        let midpoint = moduli[0] / 2;
        return Ok(CenteredBlockCoefficients::Small(
            residue_limbs[0]
                .iter()
                .map(|residue| {
                    let centered = i64::try_from(*residue).expect("selected modulus fits i64");
                    if *residue > midpoint {
                        centered - modulus
                    } else {
                        centered
                    }
                })
                .collect(),
        ));
    }

    let block_modulus = moduli
        .iter()
        .map(|modulus| BigUint::from(*modulus))
        .product::<BigUint>();
    let half_block_modulus = &block_modulus >> 1_usize;
    let crt_basis = moduli
        .iter()
        .map(|modulus| {
            let partial_modulus = &block_modulus / BigUint::from(*modulus);
            let partial_residue = (&partial_modulus % BigUint::from(*modulus))
                .to_u64()
                .expect("residue fits u64");
            let inverse = inverse_mod(partial_residue, *modulus)?;
            Ok(partial_modulus * BigUint::from(inverse))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let residue = residue_limbs
            .iter()
            .zip(crt_basis.iter())
            .map(|(limb, basis)| basis * BigUint::from(limb[coefficient_index]))
            .sum::<BigUint>()
            % &block_modulus;
        let centered = if residue > half_block_modulus {
            BigInt::from_biguint(Sign::Plus, residue)
                - BigInt::from_biguint(Sign::Plus, block_modulus.clone())
        } else {
            BigInt::from_biguint(Sign::Plus, residue)
        };
        coefficients.push(centered);
    }

    Ok(CenteredBlockCoefficients::Wide(coefficients))
}

fn bigint_residue(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_bigint = BigInt::from(modulus);
    let mut residue = value % &modulus_bigint;
    if residue.sign() == Sign::Minus {
        residue += &modulus_bigint;
    }
    residue.to_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "centered block residue does not fit u64",
        )
    })
}

fn hybrid_modulus_down(extended: &[Vec<u64>], level: usize) -> CanonicalResult<LimbMatrix> {
    let data_limb_count = level + 1;
    if extended.len() != data_limb_count + 1
        || extended.iter().any(|limb| limb.len() != POLYNOMIAL_DEGREE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "hybrid modulus-down input has the wrong extended-basis shape",
        ));
    }
    let special_limb = &extended[data_limb_count];
    if special_limb.iter().any(|value| *value >= SPECIAL_PRIME) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "hybrid modulus-down input contains a non-canonical special-basis residue",
        ));
    }
    let inverse_plaintext_modulus = inverse_mod(PLAINTEXT_MODULUS_I64 as u64, SPECIAL_PRIME)?;
    let mut output = Vec::with_capacity(data_limb_count);
    for (data_limb_index, modulus) in DATA_PRIMES[..=level].iter().copied().enumerate() {
        if extended[data_limb_index]
            .iter()
            .any(|value| *value >= modulus)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "hybrid modulus-down input contains a non-canonical data-basis residue",
            ));
        }
        let inverse_special_modulus = inverse_mod(SPECIAL_PRIME % modulus, modulus)?;
        let limb = extended[data_limb_index]
            .iter()
            .zip(special_limb.iter())
            .map(|(data_residue, special_residue)| {
                let scaled_special_residue =
                    mul_mod(inverse_plaintext_modulus, *special_residue, SPECIAL_PRIME)?;
                let negative_scaled_residue = if scaled_special_residue == 0 {
                    0
                } else {
                    SPECIAL_PRIME - scaled_special_residue
                };
                let centered_correction_quotient =
                    centered_residue_i128(negative_scaled_residue, SPECIAL_PRIME);
                let correction = i128::from(PLAINTEXT_MODULUS_I64) * centered_correction_quotient;
                let correction_residue = signed_i128_residue(correction, modulus);
                let corrected = add_mod(*data_residue, correction_residue, modulus)?;
                mul_mod(corrected, inverse_special_modulus, modulus)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        output.push(limb);
    }

    Ok(output)
}

fn centered_residue_i128(value: u64, modulus: u64) -> i128 {
    if value > modulus / 2 {
        i128::from(value) - i128::from(modulus)
    } else {
        i128::from(value)
    }
}

fn signed_i128_residue(value: i128, modulus: u64) -> u64 {
    let modulus = i128::from(modulus);
    u64::try_from(((value % modulus) + modulus) % modulus).expect("modular i128 residue fits u64")
}

fn add_component_in_place(target: &mut [Vec<u64>], addend: &[Vec<u64>], level: usize) {
    for (limb_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            target[limb_index][coefficient_index] = add_mod_fast(
                target[limb_index][coefficient_index],
                addend[limb_index][coefficient_index],
                *modulus,
            );
        }
    }
}

pub(crate) fn generate_relinearization_key(
    key: &DevelopmentBgvKey,
    level: usize,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchKey> {
    // The relinearization source is the squared secret.
    let secret_residues = secret_residues_for_moduli(key.secret(), &DATA_PRIMES[..=level]);
    let squared = evaluator_parallel_iterator!(secret_residues.par_iter(), secret_residues.iter())
        .enumerate()
        .map(|(limb_index, limb)| negacyclic_mul(limb, limb, DATA_PRIMES[limb_index]))
        .collect::<CanonicalResult<Vec<_>>>()?;

    generate_key_switch_key(key, &squared, level, "relinearization", seed_hex)
}

pub(crate) fn relinearize(
    ciphertext: &Ciphertext,
    relinearization_key: &KeySwitchKey,
) -> CanonicalResult<Ciphertext> {
    if ciphertext.component_count() != 3 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization requires a three-component ciphertext",
        ));
    }
    if relinearization_key.level < ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization key level is below the ciphertext level",
        ));
    }
    let (switched_zero, switched_one) =
        key_switch_component(&ciphertext.components[2], relinearization_key)?;
    let mut component_zero = ciphertext.components[0].clone();
    let mut component_one = ciphertext.components[1].clone();
    add_component_in_place(&mut component_zero, &switched_zero, ciphertext.level);
    add_component_in_place(&mut component_one, &switched_one, ciphertext.level);

    Ok(Ciphertext {
        components: vec![component_zero, component_one],
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::{
        CenteredBlockCoefficients, KEY_SWITCH_ERROR_DOMAIN, PLAINTEXT_MODULUS_I64,
        automorphism_residues, bigint_residue, centered_block_reconstruction,
        centered_residue_i128, generate_galois_key, generate_relinearization_key,
        hybrid_modulus_down, inverse_negacyclic_ntt, relinearize, rotate, signed_i128_residue,
    };
    use crate::bgv::{
        encoding::decode_plaintext_coefficients_to_logical_slots,
        evaluator::engine::{
            Ciphertext, DevelopmentBgvKey, ciphertext_tensor, encode_slots_to_coefficients,
            modulus_switch,
        },
        modular_arithmetic::{add_mod, inverse_mod, mul_mod},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIME},
    };
    use num_bigint::BigInt;

    const DEVELOPMENT_SEED: &str = "0011223344556677";
    const TEST_LEVEL: usize = 3;

    fn shared_key() -> &'static DevelopmentBgvKey {
        static KEY: OnceLock<DevelopmentBgvKey> = OnceLock::new();
        KEY.get_or_init(|| {
            DevelopmentBgvKey::generate(DEVELOPMENT_SEED).expect("development key generates")
        })
    }

    fn at_test_level(ciphertext: &Ciphertext) -> Ciphertext {
        let mut current = ciphertext.clone();
        while current.level > TEST_LEVEL {
            current = modulus_switch(&current).expect("modulus switch");
        }
        current
    }

    #[test]
    fn centered_block_reconstruction_recovers_aggressive_signed_boundaries() {
        let moduli = &DATA_PRIMES[..2];
        let block_modulus = BigInt::from(moduli[0]) * BigInt::from(moduli[1]);
        let half_block_modulus = &block_modulus / BigInt::from(2_u8);
        let expected = vec![
            -half_block_modulus.clone(),
            BigInt::from(-1_i8),
            BigInt::from(0_u8),
            BigInt::from(1_u8),
            half_block_modulus,
        ];
        let residue_limbs = moduli
            .iter()
            .map(|modulus| {
                let mut limb = vec![0_u64; POLYNOMIAL_DEGREE];
                for (coefficient_index, coefficient) in expected.iter().enumerate() {
                    limb[coefficient_index] =
                        bigint_residue(coefficient, *modulus).expect("residue derives");
                }
                limb
            })
            .collect::<Vec<_>>();
        let CenteredBlockCoefficients::Wide(actual) =
            centered_block_reconstruction(&residue_limbs, moduli)
                .expect("two-prime block reconstructs")
        else {
            panic!("two-prime block must use wide centered reconstruction");
        };

        assert_eq!(&actual[..expected.len()], expected.as_slice());

        let mut malformed = residue_limbs;
        malformed[0][0] = moduli[0];
        assert!(centered_block_reconstruction(&malformed, moduli).is_err());
    }

    #[test]
    fn hybrid_modulus_down_matches_the_exact_integer_correction_at_boundaries() {
        let special = i128::from(SPECIAL_PRIME);
        let data = i128::from(DATA_PRIMES[0]);
        let values = [
            -(data * special),
            -special,
            -(special / 2),
            -1,
            0,
            1,
            special / 2,
            special,
            data * special,
        ];
        let mut extended = vec![vec![0_u64; POLYNOMIAL_DEGREE]; 3];
        for (coefficient_index, value) in values.iter().copied().enumerate() {
            extended[0][coefficient_index] = signed_i128_residue(value, DATA_PRIMES[0]);
            extended[1][coefficient_index] = signed_i128_residue(value, DATA_PRIMES[1]);
            extended[2][coefficient_index] = signed_i128_residue(value, SPECIAL_PRIME);
        }
        let actual = hybrid_modulus_down(&extended, 1).expect("hybrid modulus-down derives");
        let inverse_plaintext =
            inverse_mod(PLAINTEXT_MODULUS, SPECIAL_PRIME).expect("plaintext inverse");
        for (coefficient_index, value) in values.iter().copied().enumerate() {
            let special_residue = signed_i128_residue(value, SPECIAL_PRIME);
            let scaled =
                mul_mod(inverse_plaintext, special_residue, SPECIAL_PRIME).expect("scaled");
            let negative_scaled = if scaled == 0 {
                0
            } else {
                SPECIAL_PRIME - scaled
            };
            let correction = i128::from(PLAINTEXT_MODULUS)
                * centered_residue_i128(negative_scaled, SPECIAL_PRIME);
            assert_eq!((value + correction) % special, 0);
            let quotient = (value + correction) / special;
            assert_eq!(
                actual[0][coefficient_index],
                signed_i128_residue(quotient, DATA_PRIMES[0])
            );
            assert_eq!(
                actual[1][coefficient_index],
                signed_i128_residue(quotient, DATA_PRIMES[1])
            );
        }
    }

    #[test]
    fn generated_hybrid_key_material_carries_the_special_basis_relation() {
        let key = shared_key();
        let level = 1;
        let seed = "hybrid-special-basis";
        let generated =
            generate_relinearization_key(key, level, seed).expect("hybrid key generates");
        assert_eq!(generated.components.len(), level + 1);
        let component = &generated.components[0];
        assert_eq!(
            component.moduli,
            vec![DATA_PRIMES[0], DATA_PRIMES[1], SPECIAL_PRIME]
        );
        let special_limb_index = level + 1;
        let component_b = inverse_negacyclic_ntt(
            &component.component_b_ntt[special_limb_index],
            SPECIAL_PRIME,
        )
        .expect("component b inverse NTT");
        let component_a = inverse_negacyclic_ntt(
            &component.component_a_ntt[special_limb_index],
            SPECIAL_PRIME,
        )
        .expect("component a inverse NTT");
        let secret = key
            .secret()
            .iter()
            .map(|coefficient| super::signed_residue(*coefficient, SPECIAL_PRIME))
            .collect::<Vec<_>>();
        let public_sample_secret = super::negacyclic_mul(&component_a, &secret, SPECIAL_PRIME)
            .expect("special-basis public sample product");
        let block_bytes = 0_u64.to_le_bytes();
        let error = super::DeterministicSampler::new(
            KEY_SWITCH_ERROR_DOMAIN,
            &[b"relinearization", seed.as_bytes(), &block_bytes],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            let observed = add_mod(
                component_b[coefficient_index],
                public_sample_secret[coefficient_index],
                SPECIAL_PRIME,
            )
            .expect("special relation sum");
            assert_eq!(
                observed,
                super::signed_residue(
                    error[coefficient_index] * PLAINTEXT_MODULUS_I64,
                    SPECIAL_PRIME,
                )
            );
        }
    }

    #[test]
    fn higher_level_relinearization_key_relinearizes_lower_level_ciphertexts() {
        let key = shared_key();
        let left = at_test_level(&key.encrypt_slots(&[4, 5, 6], "ksk-trunc-a").expect("left"));
        let right = at_test_level(&key.encrypt_slots(&[7, 8, 9], "ksk-trunc-b").expect("right"));
        let product = ciphertext_tensor(&left, &right).expect("tensor");
        // Key generated two levels above the ciphertext level.
        let relinearization_key =
            generate_relinearization_key(key, TEST_LEVEL + 2, "trunc-relin-seed")
                .expect("relin key");
        let relinearized = relinearize(&product, &relinearization_key).expect("relinearize");
        assert_eq!(
            key.decrypt_to_slots(&relinearized).expect("decrypt")[..3].to_vec(),
            vec![28, 40, 54]
        );
    }

    #[test]
    fn higher_level_galois_key_rotates_lower_level_ciphertexts() {
        let key = shared_key();
        let galois_element = 3_usize;
        let slots = [9_u64, 8, 7, 6, 5, 4, 3, 2];
        let ciphertext =
            at_test_level(&key.encrypt_slots(&slots, "ksk-trunc-rot").expect("encrypt"));
        let galois_key =
            generate_galois_key(key, galois_element, TEST_LEVEL + 2, "trunc-galois-seed")
                .expect("galois key");
        let rotated = rotate(&ciphertext, galois_element, &galois_key).expect("rotate");

        let plaintext_coefficients = encode_slots_to_coefficients(&slots).expect("encode");
        let rotated_coefficients =
            automorphism_residues(&plaintext_coefficients, galois_element, PLAINTEXT_MODULUS)
                .expect("plaintext automorphism");
        let expected_slots =
            decode_plaintext_coefficients_to_logical_slots(&rotated_coefficients).expect("decode");

        assert_eq!(
            key.decrypt_to_slots(&rotated).expect("decrypt"),
            expected_slots
        );
    }

    #[test]
    fn relinearization_recovers_two_component_product() {
        let key = shared_key();
        let left = at_test_level(&key.encrypt_slots(&[2, 3, 4], "ksk01").expect("left"));
        let right = at_test_level(&key.encrypt_slots(&[5, 6, 7], "ksk02").expect("right"));
        let product = ciphertext_tensor(&left, &right).expect("tensor");
        let relinearization_key =
            generate_relinearization_key(key, TEST_LEVEL, "relin-seed").expect("relin key");
        let relinearized = relinearize(&product, &relinearization_key).expect("relinearize");
        assert_eq!(relinearized.component_count(), 2);
        assert_eq!(
            key.decrypt_to_slots(&relinearized).expect("decrypt")[..3].to_vec(),
            vec![10, 18, 28]
        );
    }

    #[test]
    fn relinearized_product_supports_a_second_multiplication() {
        let key = shared_key();
        let first_factor = at_test_level(
            &key.encrypt_slots(&[2, 3, 4], "ksk03")
                .expect("first factor"),
        );
        let second_factor = at_test_level(
            &key.encrypt_slots(&[1, 5, 2], "ksk04")
                .expect("second factor"),
        );
        let relinearization_key =
            generate_relinearization_key(key, TEST_LEVEL, "relin-seed").expect("relin key");
        let first = relinearize(
            &ciphertext_tensor(&first_factor, &second_factor).expect("first times second"),
            &relinearization_key,
        )
        .expect("relinearize first times second");
        let third_factor = at_test_level(
            &key.encrypt_slots(&[3, 2, 4], "ksk05")
                .expect("third factor"),
        );
        let second = relinearize(
            &ciphertext_tensor(&first, &third_factor).expect("product with third factor"),
            &relinearization_key,
        )
        .expect("relinearize product with third factor");
        assert_eq!(
            key.decrypt_to_slots(&second).expect("decrypt")[..3].to_vec(),
            vec![6, 30, 32]
        );
    }

    fn assert_rotation_matches_plaintext_automorphism(
        galois_element: usize,
        encryption_seed: &str,
        galois_key_seed: &str,
    ) {
        let key = shared_key();
        let slots = [11_u64, 22, 33, 44, 55, 66, 77, 88];
        let ciphertext =
            at_test_level(&key.encrypt_slots(&slots, encryption_seed).expect("encrypt"));
        let galois_key = generate_galois_key(key, galois_element, TEST_LEVEL, galois_key_seed)
            .expect("galois key");
        let rotated = rotate(&ciphertext, galois_element, &galois_key).expect("rotate");

        let plaintext_coefficients = encode_slots_to_coefficients(&slots).expect("encode");
        let rotated_coefficients =
            automorphism_residues(&plaintext_coefficients, galois_element, PLAINTEXT_MODULUS)
                .expect("plaintext automorphism");
        let expected_slots =
            decode_plaintext_coefficients_to_logical_slots(&rotated_coefficients).expect("decode");

        assert_eq!(
            key.decrypt_to_slots(&rotated).expect("decrypt"),
            expected_slots
        );
    }

    #[test]
    fn forward_and_inverse_rotations_match_the_plaintext_automorphism() {
        assert_rotation_matches_plaintext_automorphism(3, "ksk06", "galois-seed");
        assert_rotation_matches_plaintext_automorphism(43_691, "ksk07", "inverse-galois-seed");
    }

    #[test]
    fn galois_generator_rotates_each_canonical_logical_slot_half() {
        let half_slot_count = POLYNOMIAL_DEGREE / 2;
        let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
        for (slot_index, slot_value) in [
            (0, 11),
            (1, 22),
            (2, 33),
            (17, 44),
            (half_slot_count - 1, 55),
            (half_slot_count, 66),
            (half_slot_count + 1, 77),
            (POLYNOMIAL_DEGREE - 1, 88),
        ] {
            slots[slot_index] = slot_value;
        }
        let plaintext_coefficients = encode_slots_to_coefficients(&slots).expect("encode");
        let rotated_coefficients =
            automorphism_residues(&plaintext_coefficients, 3, PLAINTEXT_MODULUS)
                .expect("apply generator automorphism");
        let rotated_slots =
            decode_plaintext_coefficients_to_logical_slots(&rotated_coefficients).expect("decode");
        let expected_slots = slots[..half_slot_count]
            .iter()
            .cycle()
            .skip(1)
            .take(half_slot_count)
            .chain(
                slots[half_slot_count..]
                    .iter()
                    .cycle()
                    .skip(1)
                    .take(half_slot_count),
            )
            .copied()
            .collect::<Vec<_>>();

        assert_eq!(rotated_slots, expected_slots);
    }
}
