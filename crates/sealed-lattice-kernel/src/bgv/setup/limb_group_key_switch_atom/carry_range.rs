//! Witness-free carry-range proof for the bounded carry column.
//!
//! The limb-group atom carry satisfies `|c_i| <= N+1`. Shifting by the bound,
//! `u_i = c_i + (N+1)` lies in `[0, 2(N+1)]`, which fits in `bit_count` bits.
//! The proof commits `u` and its bit expansion `b` (a length `n * bit_count`
//! column), and proves two relations over one shared commitment:
//!
//! ```text
//! P (bits are binary):   b = b . b        (so every b_k in {0,1})
//! L (reconstruction):    u_i = sum_j 2^j b_{i,j}
//! ```
//!
//! Binary bits plus the reconstruction pin `u_i in [0, 2^bit_count)`, hence
//! `c_i in [-(N+1), 2^bit_count - 1 - (N+1)]`; choosing `bit_count` so
//! `2^bit_count - 1 = 2(N+1)` gives exactly `|c_i| <= N+1`. A carry outside the
//! range needs a set bit beyond `bit_count`, so its reconstruction fails L; a
//! non-binary bit fails P. This is the range leg of the short-witness support,
//! completing the secret (ternary), error (eta-2), and carry columns.
//!
//! Both relations are the batched Fiat-Shamir identities used by `support_proof`
//! and `eta2_support`, sharing one commitment, one mask commitment, and one
//! challenge. The verifier checks the commitment homomorphism and never sees the
//! witness.
//!
//! HONEST SCOPE. This binds the carry range soundly and witness-free. As with the
//! other openings, the full-width challenge means it is not yet zero-knowledge;
//! the bounded structured challenge set and rejection sampling are the remaining
//! zero-knowledge layer. Test-gated; not on any acceptance path.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::linear_opening::{FlatCommitment, LinearOpeningParameters, commit_flat};
use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const GAMMA_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/carry-range-batching-v1";
const CHALLENGE_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/carry-range-challenge-v1";
const MASK_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/carry-range-mask-v1";

pub(crate) struct CarryRangeProof<const LIMB_COUNT: usize> {
    mask_commitment: Vec<[u64; LIMB_COUNT]>,
    response_value: Vec<[u64; LIMB_COUNT]>,
    response_bits: Vec<[u64; LIMB_COUNT]>,
    randomness_response: Vec<[u64; LIMB_COUNT]>,
    binary_garbage_zero: [u64; LIMB_COUNT],
    binary_garbage_one: [u64; LIMB_COUNT],
    binary_mask_batched: [u64; LIMB_COUNT],
    reconstruction_mask_batched: [u64; LIMB_COUNT],
}

fn field_from_digest<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &str,
    parts: &[&[u8]],
) -> [u64; LIMB_COUNT] {
    let digest = hash512(domain, parts);
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
    parameters.unsigned_word_to_element(word)
}

fn seed_bytes<const LIMB_COUNT: usize>(rows: &[[u64; LIMB_COUNT]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in rows {
        for limb in row {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}

fn batching_vector<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment_seed: &[u8],
    family: u8,
    length: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    (0..length)
        .map(|index| {
            field_from_digest(
                parameters,
                GAMMA_DOMAIN,
                &[commitment_seed, &[family], &(index as u64).to_le_bytes()],
            )
        })
        .collect()
}

fn mask_vector<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    seed: u64,
    label: u8,
    length: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    (0..length)
        .map(|index| {
            field_from_digest(
                parameters,
                MASK_DOMAIN,
                &[&seed.to_le_bytes(), &[label], &(index as u64).to_le_bytes()],
            )
        })
        .collect()
}

fn batched_weighted_sum<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    gamma: &[[u64; LIMB_COUNT]],
    values: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut accumulator = parameters.zero();
    for index in 0..gamma.len() {
        accumulator = parameters.add(
            &accumulator,
            &parameters.multiply(&gamma[index], &values[index]),
        );
    }
    accumulator
}

fn batched_product<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    gamma: &[[u64; LIMB_COUNT]],
    left: &[[u64; LIMB_COUNT]],
    right: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut accumulator = parameters.zero();
    for index in 0..gamma.len() {
        let product = parameters.multiply(&left[index], &right[index]);
        accumulator = parameters.add(&accumulator, &parameters.multiply(&gamma[index], &product));
    }
    accumulator
}

fn power_of_two_element<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    exponent: usize,
) -> [u64; LIMB_COUNT] {
    parameters.unsigned_word_to_element(1_u64 << exponent)
}

fn sigma_challenge<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    mask_commitment: &[[u64; LIMB_COUNT]],
    scalars: &[&[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut bytes = seed_bytes(mask_commitment);
    for scalar in scalars {
        for limb in *scalar {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    field_from_digest(parameters, CHALLENGE_DOMAIN, &[&bytes])
}

/// Proves the committed shifted values `value` lie in `[0, 2^bit_count)`, given
/// their bit expansion `bits` (row-major: `bits[i * bit_count + j]` is bit `j`
/// of `value_i`). Commitment message is `value || bits`.
pub(crate) fn prove_carry_range<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    value: &[[u64; LIMB_COUNT]],
    bits: &[[u64; LIMB_COUNT]],
    bit_count: usize,
    randomness: &[[u64; LIMB_COUNT]],
    attempt_seed: u64,
) -> (FlatCommitment<LIMB_COUNT>, CarryRangeProof<LIMB_COUNT>) {
    let value_length = value.len();
    let bits_length = bits.len();
    debug_assert_eq!(bits_length, value_length * bit_count);
    let mut witness = Vec::with_capacity(value_length + bits_length);
    witness.extend_from_slice(value);
    witness.extend_from_slice(bits);
    let commitment = commit_flat(parameters, opening_parameters, &witness, randomness);
    let commitment_seed = seed_bytes(&commitment.rows);
    let gamma_binary = batching_vector(parameters, &commitment_seed, 0x31, bits_length);
    let gamma_reconstruction = batching_vector(parameters, &commitment_seed, 0x32, value_length);

    let mask_value = mask_vector(parameters, attempt_seed, 0x76, value_length);
    let mask_bits = mask_vector(parameters, attempt_seed, 0x62, bits_length);
    let mask_randomness = mask_vector(parameters, attempt_seed, 0x72, randomness.len());
    let mut mask_witness = Vec::with_capacity(value_length + bits_length);
    mask_witness.extend_from_slice(&mask_value);
    mask_witness.extend_from_slice(&mask_bits);
    let mask_commitment = commit_flat(
        parameters,
        opening_parameters,
        &mask_witness,
        &mask_randomness,
    )
    .rows;

    // P (bits binary): b = b . b.
    let binary_garbage_zero = batched_product(parameters, &gamma_binary, &mask_bits, &mask_bits);
    let mut binary_garbage_one = parameters.zero();
    for index in 0..bits_length {
        let cross = parameters.multiply(&mask_bits[index], &bits[index]);
        let doubled = parameters.add(&cross, &cross);
        binary_garbage_one = parameters.add(
            &binary_garbage_one,
            &parameters.multiply(&gamma_binary[index], &doubled),
        );
    }
    let binary_mask_batched = batched_weighted_sum(parameters, &gamma_binary, &mask_bits);

    // L (reconstruction): value_i - sum_j 2^j bits_{i,j} = 0.
    // M_L = sum_i gamma_L_i (mu_value_i - sum_j 2^j mu_bits_{i,j}).
    let mut reconstruction_mask_batched = parameters.zero();
    for i in 0..value_length {
        let mut term = mask_value[i];
        for j in 0..bit_count {
            let weight = power_of_two_element(parameters, j);
            term = parameters.subtract(
                &term,
                &parameters.multiply(&weight, &mask_bits[i * bit_count + j]),
            );
        }
        reconstruction_mask_batched = parameters.add(
            &reconstruction_mask_batched,
            &parameters.multiply(&gamma_reconstruction[i], &term),
        );
    }

    let x = sigma_challenge(
        parameters,
        &mask_commitment,
        &[
            &binary_garbage_zero,
            &binary_garbage_one,
            &binary_mask_batched,
            &reconstruction_mask_batched,
        ],
    );

    let respond = |mask: &[[u64; LIMB_COUNT]], values: &[[u64; LIMB_COUNT]]| {
        mask.iter()
            .zip(values.iter())
            .map(|(mask_value, witness_value)| {
                parameters.add(mask_value, &parameters.multiply(&x, witness_value))
            })
            .collect::<Vec<_>>()
    };
    let response_value = respond(&mask_value, value);
    let response_bits = respond(&mask_bits, bits);
    let randomness_response = respond(&mask_randomness, randomness);

    (
        commitment,
        CarryRangeProof {
            mask_commitment,
            response_value,
            response_bits,
            randomness_response,
            binary_garbage_zero,
            binary_garbage_one,
            binary_mask_batched,
            reconstruction_mask_batched,
        },
    )
}

/// Verifies the carry-range proof without the witness.
pub(crate) fn verify_carry_range<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    commitment: &FlatCommitment<LIMB_COUNT>,
    value_length: usize,
    bit_count: usize,
    proof: &CarryRangeProof<LIMB_COUNT>,
) -> bool {
    let bits_length = value_length * bit_count;
    if proof.response_value.len() != value_length
        || proof.response_bits.len() != bits_length
        || proof.mask_commitment.len() != opening_parameters.commitment_rank
    {
        return false;
    }
    let commitment_seed = seed_bytes(&commitment.rows);
    let gamma_binary = batching_vector(parameters, &commitment_seed, 0x31, bits_length);
    let gamma_reconstruction = batching_vector(parameters, &commitment_seed, 0x32, value_length);
    let x = sigma_challenge(
        parameters,
        &proof.mask_commitment,
        &[
            &proof.binary_garbage_zero,
            &proof.binary_garbage_one,
            &proof.binary_mask_batched,
            &proof.reconstruction_mask_batched,
        ],
    );

    // Commitment homomorphism.
    let mut response_witness = Vec::with_capacity(value_length + bits_length);
    response_witness.extend_from_slice(&proof.response_value);
    response_witness.extend_from_slice(&proof.response_bits);
    let response_commitment = commit_flat(
        parameters,
        opening_parameters,
        &response_witness,
        &proof.randomness_response,
    );
    for row in 0..opening_parameters.commitment_rank {
        let expected = parameters.add(
            &proof.mask_commitment[row],
            &parameters.multiply(&x, &commitment.rows[row]),
        );
        if response_commitment.rows[row] != expected {
            return false;
        }
    }

    // P: sum gamma_b z_b^2 == g0 + x g1 + x (sum gamma_b z_b - m_b).
    let binary_left = batched_product(
        parameters,
        &gamma_binary,
        &proof.response_bits,
        &proof.response_bits,
    );
    let binary_batched_z = batched_weighted_sum(parameters, &gamma_binary, &proof.response_bits);
    let binary_tail = parameters.multiply(
        &x,
        &parameters.subtract(&binary_batched_z, &proof.binary_mask_batched),
    );
    let mut binary_right = parameters.add(
        &proof.binary_garbage_zero,
        &parameters.multiply(&x, &proof.binary_garbage_one),
    );
    binary_right = parameters.add(&binary_right, &binary_tail);
    if binary_left != binary_right {
        return false;
    }

    // L: sum_i gamma_L_i (z_value_i - sum_j 2^j z_bits_{i,j}) == M_L.
    let mut linear_left = parameters.zero();
    for i in 0..value_length {
        let mut term = proof.response_value[i];
        for j in 0..bit_count {
            let weight = power_of_two_element(parameters, j);
            term = parameters.subtract(
                &term,
                &parameters.multiply(&weight, &proof.response_bits[i * bit_count + j]),
            );
        }
        linear_left = parameters.add(
            &linear_left,
            &parameters.multiply(&gamma_reconstruction[i], &term),
        );
    }
    linear_left == proof.reconstruction_mask_batched
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    const BIT_COUNT: usize = 6; // values in [0, 64)

    fn bits_of<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        values: &[u64],
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut bits = Vec::with_capacity(values.len() * BIT_COUNT);
        for value in values {
            for j in 0..BIT_COUNT {
                let bit = (value >> j) & 1;
                bits.push(parameters.unsigned_word_to_element(bit));
            }
        }
        bits
    }

    fn value_elements<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        values: &[u64],
    ) -> Vec<[u64; LIMB_COUNT]> {
        values
            .iter()
            .map(|v| parameters.unsigned_word_to_element(*v))
            .collect()
    }

    fn opening(value_length: usize) -> LinearOpeningParameters {
        LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: value_length + value_length * BIT_COUNT,
            randomness_length: 6,
            matrix_seed: 0xca77,
            mask_bound: 1,
        }
    }

    #[test]
    fn honest_in_range_values_verify() {
        let parameters = sixteen_limb_group_field_parameters();
        let raw = [0_u64, 1, 5, 63, 32, 17, 8, 40];
        let value = value_elements(&parameters, &raw);
        let bits = bits_of(&parameters, &raw);
        let randomness = value_elements(&parameters, &[1, 0, 1, 0, 1, 0]);
        let opening_parameters = opening(value.len());

        let (commitment, proof) = prove_carry_range(
            &parameters,
            &opening_parameters,
            &value,
            &bits,
            BIT_COUNT,
            &randomness,
            0x5eed,
        );
        assert!(verify_carry_range(
            &parameters,
            &opening_parameters,
            &commitment,
            value.len(),
            BIT_COUNT,
            &proof,
        ));
    }

    #[test]
    fn out_of_range_value_with_truncated_bits_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        // value 100 needs a 7th bit; with only BIT_COUNT=6 bits its low bits sum
        // to 100 mod 64 = 36, so the reconstruction fails.
        let raw = [0_u64, 1, 5, 100, 32, 17, 8, 40];
        let value = value_elements(&parameters, &raw);
        let bits = bits_of(&parameters, &raw); // low 6 bits only
        let randomness = value_elements(&parameters, &[1, 0, 1, 0, 1, 0]);
        let opening_parameters = opening(value.len());

        let (commitment, proof) = prove_carry_range(
            &parameters,
            &opening_parameters,
            &value,
            &bits,
            BIT_COUNT,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_carry_range(
                &parameters,
                &opening_parameters,
                &commitment,
                value.len(),
                BIT_COUNT,
                &proof,
            ),
            "a value needing more than BIT_COUNT bits must fail reconstruction"
        );
    }

    #[test]
    fn non_binary_bit_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let raw = [0_u64, 1, 5, 63, 32, 17, 8, 40];
        let mut bits = bits_of(&parameters, &raw);
        // Corrupt bit 0 of value_3 to 2 (non-binary). Its low bits then
        // reconstruct to 2 + 62 = 64, so set value_3 = 64 to keep the linear
        // reconstruction satisfied and isolate the binary check.
        bits[3 * BIT_COUNT] = parameters.unsigned_word_to_element(2);
        let mut adjusted = raw;
        adjusted[3] = 64;
        let value = value_elements(&parameters, &adjusted);
        let randomness = value_elements(&parameters, &[1, 0, 1, 0, 1, 0]);
        let opening_parameters = opening(value.len());

        let (commitment, proof) = prove_carry_range(
            &parameters,
            &opening_parameters,
            &value,
            &bits,
            BIT_COUNT,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_carry_range(
                &parameters,
                &opening_parameters,
                &commitment,
                value.len(),
                BIT_COUNT,
                &proof,
            ),
            "a non-binary bit must fail the binary product relation"
        );
    }

    #[test]
    fn tampered_response_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let raw = [0_u64, 1, 5, 63, 32, 17, 8, 40];
        let value = value_elements(&parameters, &raw);
        let bits = bits_of(&parameters, &raw);
        let randomness = value_elements(&parameters, &[1, 0, 1, 0, 1, 0]);
        let opening_parameters = opening(value.len());

        let (commitment, mut proof) = prove_carry_range(
            &parameters,
            &opening_parameters,
            &value,
            &bits,
            BIT_COUNT,
            &randomness,
            0x5eed,
        );
        proof.response_value[2] = parameters.add(
            &proof.response_value[2],
            &parameters.unsigned_word_to_element(1),
        );
        assert!(!verify_carry_range(
            &parameters,
            &opening_parameters,
            &commitment,
            value.len(),
            BIT_COUNT,
            &proof,
        ));
    }
}
