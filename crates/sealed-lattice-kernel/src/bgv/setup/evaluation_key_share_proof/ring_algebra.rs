use super::*;

use crate::bgv::modular_arithmetic::{self, SignedResidueFailure};

pub(super) fn lifted_secret_message_response_big_int(
    secret_response: i128,
    negative_indicator_response: i128,
    source_message_modulus: u64,
) -> CanonicalResult<BigInt> {
    let lifted = BigInt::from(secret_response)
        + (BigInt::from(source_message_modulus) * BigInt::from(negative_indicator_response));
    if lifted.magnitude().clone() * BigUint::from(2_u8)
        >= super::commitment::setup_commitment_modulus_product()
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key lifted secret response wraps in the centered setup commitment modulus product",
        ));
    }

    Ok(lifted)
}

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
                invalid_evaluation_key_share_proof(
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
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key lifted big-integer product inputs must have equal width",
        ));
    }
    let ring_degree = public_sample.len();
    if DATA_PRIMES.len() < EVALUATION_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT {
        return Err(invalid_evaluation_key_share_proof(
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

pub(super) fn negacyclic_i128_product_lifted(
    left: &[i128],
    right: &[i128],
) -> CanonicalResult<Vec<i128>> {
    if left.len() != right.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key source product inputs must have equal width",
        ));
    }
    let ring_degree = left.len();
    if DATA_PRIMES.len() < EVALUATION_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key source product CRT basis is too small",
        ));
    }
    let crt_moduli = &DATA_PRIMES[..EVALUATION_KEY_SHARE_LIFTED_PRODUCT_CRT_LIMB_COUNT];
    let product_residues_by_modulus = crt_moduli
        .iter()
        .map(|modulus| {
            let left_residues = left
                .iter()
                .map(|coefficient| signed_i128_residue_u64(*coefficient, *modulus))
                .collect::<CanonicalResult<Vec<_>>>()?;
            let right_residues = right
                .iter()
                .map(|coefficient| signed_i128_residue_u64(*coefficient, *modulus))
                .collect::<CanonicalResult<Vec<_>>>()?;
            negacyclic_product_mod(&left_residues, &right_residues, *modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut output = Vec::with_capacity(ring_degree);
    for coefficient_index in 0..ring_degree {
        let residues = product_residues_by_modulus
            .iter()
            .map(|residues| residues[coefficient_index])
            .collect::<Vec<_>>();
        let coefficient = reconstruct_centered_i128_from_crt_residues(&residues, crt_moduli)?;
        output.push(coefficient);
    }

    Ok(output)
}

fn reconstruct_centered_i128_from_crt_residues(
    residues: &[u64],
    moduli: &[u64],
) -> CanonicalResult<i128> {
    let value = reconstruct_centered_big_int_from_crt_residues(residues, moduli)?;
    value.to_i128().ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key source product does not fit i128")
    })
}

fn reconstruct_centered_big_int_from_crt_residues(
    residues: &[u64],
    moduli: &[u64],
) -> CanonicalResult<BigInt> {
    if residues.len() != moduli.len() || residues.is_empty() {
        return Err(invalid_evaluation_key_share_proof(
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
                    invalid_evaluation_key_share_proof(
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
        invalid_evaluation_key_share_proof("evaluation-key source product CRT residue overflowed")
    })
}

#[cfg(test)]
pub(in crate::bgv::setup) fn negacyclic_i128_product_for_evaluation_key_fixture(
    left: &[i128],
    right: &[i128],
) -> CanonicalResult<Vec<i128>> {
    negacyclic_i128_product_lifted(left, right)
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
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key automorphism input must be non-empty",
        ));
    }
    let two_n = ring_degree.checked_mul(2).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key automorphism ring size overflowed")
    })?;
    let mut output = vec![0_i128; ring_degree];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = coefficient_index
            .checked_mul(galois_element)
            .map(|raw| raw % two_n)
            .ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key automorphism index overflowed")
            })?;
        if exponent < ring_degree {
            output[exponent] = output[exponent].checked_add(*value).ok_or_else(|| {
                invalid_evaluation_key_share_proof(
                    "evaluation-key automorphism accumulation overflowed",
                )
            })?;
        } else {
            output[exponent - ring_degree] = output[exponent - ring_degree]
                .checked_sub(*value)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
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
            invalid_evaluation_key_share_proof("evaluation-key signed residue overflowed")
        }
        SignedResidueFailure::DoesNotFitU64 => {
            invalid_evaluation_key_share_proof("evaluation-key signed residue does not fit u64")
        }
    })
}
