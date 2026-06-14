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
