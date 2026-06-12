use super::*;

use crate::bgv::modular_arithmetic::{self, SignedResidueFailure};

pub(super) fn deterministic_key_switch_public_sample(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    digit_index: usize,
    modulus: u64,
    ring_degree: usize,
) -> Vec<u64> {
    let digit_bytes = (digit_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    DeterministicSampler::new(
        KEY_SWITCH_SAMPLE_DOMAIN,
        &[
            key_switch_domain.as_bytes(),
            key_switch_seed_hex.as_bytes(),
            &digit_bytes,
            &modulus_bytes,
        ],
    )
    .uniform_residues(modulus, ring_degree)
}

pub(super) fn negacyclic_public_sample_secret_product_lifted(
    public_sample: &[u64],
    secret_coefficients: &[i128],
) -> CanonicalResult<Vec<i128>> {
    negacyclic_public_sample_secret_product_big_int(public_sample, secret_coefficients)?
        .into_iter()
        .map(|coefficient| {
            coefficient.to_i128().ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key lifted product coefficient does not fit i128",
                )
            })
        })
        .collect()
}

pub(super) fn negacyclic_public_sample_secret_product_big_int(
    public_sample: &[u64],
    secret_coefficients: &[i128],
) -> CanonicalResult<Vec<BigInt>> {
    if public_sample.len() != secret_coefficients.len() {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key lifted big-integer product inputs must have equal width",
        ));
    }
    let ring_degree = public_sample.len();
    if DATA_PRIMES.len() < EVALUATION_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key lifted product CRT basis is too small",
        ));
    }
    let crt_moduli = &DATA_PRIMES[..EVALUATION_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT];
    let product_residues_by_modulus = crt_moduli
        .iter()
        .map(|modulus| {
            let public_sample_residues = public_sample
                .iter()
                .map(|coefficient| coefficient % modulus)
                .collect::<Vec<_>>();
            let secret_residues = secret_coefficients
                .iter()
                .map(|coefficient| signed_i128_residue_u64(*coefficient, *modulus))
                .collect::<CanonicalResult<Vec<_>>>()?;
            negacyclic_product_mod(&public_sample_residues, &secret_residues, *modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut output = Vec::with_capacity(ring_degree);
    for coefficient_index in 0..ring_degree {
        let residues = product_residues_by_modulus
            .iter()
            .map(|residues| residues[coefficient_index])
            .collect::<Vec<_>>();
        output.push(reconstruct_centered_big_int_from_crt_residues(
            &residues, crt_moduli,
        )?);
    }

    Ok(output)
}

fn reconstruct_centered_big_int_from_crt_residues(
    residues: &[u64],
    moduli: &[u64],
) -> CanonicalResult<BigInt> {
    if residues.len() != moduli.len() || residues.is_empty() {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key source product CRT inputs must have matching non-empty length",
        ));
    }
    let mut value = BigInt::from(residues[0]);
    let mut modulus_product = BigInt::from(moduli[0]);
    for (residue, modulus) in residues.iter().copied().zip(moduli.iter().copied()).skip(1) {
        let current_residue = nonnegative_big_int_mod_u64(&value, modulus)?;
        let delta = if residue >= current_residue {
            residue - current_residue
        } else {
            residue
                .checked_add(modulus)
                .and_then(|sum| sum.checked_sub(current_residue))
                .ok_or_else(|| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key source product CRT delta overflowed",
                    )
                })?
        };
        let product_residue = nonnegative_big_int_mod_u64(&modulus_product, modulus)?;
        let product_inverse = inverse_mod(product_residue, modulus)?;
        let correction = mul_mod(delta, product_inverse, modulus)?;
        value += &modulus_product * BigInt::from(correction);
        modulus_product *= BigInt::from(modulus);
    }

    if value > (&modulus_product >> 1_usize) {
        value -= modulus_product;
    }

    Ok(value)
}

fn nonnegative_big_int_mod_u64(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_big = BigInt::from(modulus);
    let residue = ((value % &modulus_big) + &modulus_big) % &modulus_big;
    residue.to_u64().ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "evaluation-key source product CRT residue overflowed",
        )
    })
}

#[cfg(test)]
pub(in crate::bgv::setup) fn automorphism_i128_for_evaluation_key_fixture(
    input: &[i128],
    galois_element: usize,
) -> CanonicalResult<Vec<i128>> {
    automorphism_i128(input, galois_element)
}

pub(super) fn automorphism_i128(
    input: &[i128],
    galois_element: usize,
) -> CanonicalResult<Vec<i128>> {
    let ring_degree = input.len();
    if ring_degree == 0 {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key automorphism input must be non-empty",
        ));
    }
    let two_n = ring_degree.checked_mul(2).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key automorphism ring size overflowed")
    })?;
    let mut output = vec![0_i128; ring_degree];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = coefficient_index
            .checked_mul(galois_element)
            .map(|raw| raw % two_n)
            .ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key automorphism index overflowed",
                )
            })?;
        if exponent < ring_degree {
            output[exponent] = output[exponent].checked_add(*value).ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key automorphism accumulation overflowed",
                )
            })?;
        } else {
            output[exponent - ring_degree] = output[exponent - ring_degree]
                .checked_sub(*value)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key automorphism accumulation overflowed",
                    )
                })?;
        }
    }

    Ok(output)
}

pub(super) fn signed_i128_residue_u64(value: i128, modulus: u64) -> CanonicalResult<u64> {
    modular_arithmetic::signed_i128_residue_u64(value, modulus).map_err(|failure| match failure {
        SignedResidueFailure::Overflowed => {
            invalid_evaluation_key_share_material("evaluation-key signed residue overflowed")
        }
        SignedResidueFailure::DoesNotFitU64 => {
            invalid_evaluation_key_share_material("evaluation-key signed residue does not fit u64")
        }
    })
}
