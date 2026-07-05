//! Witness-free ternary support proof for the secret column.
//!
//! Proves the committed secret `s` is ternary (`s_i in {-1,0,1}`) with a
//! public-coin, witness-free verifier, by two Hadamard product relations over
//! one shared commitment to `(s, q)`:
//!
//! ```text
//! R1:  q = s . s        (so q_i = s_i^2)
//! R2:  q = q . q        (so q_i in {0,1})
//! ```
//!
//! Together `s_i^2 = q_i in {0,1}`, hence `s_i in {-1,0,1}`. A prover with a
//! non-ternary `s_i = 2` must commit `q_i = 4` to satisfy R1, which then fails R2
//! (`4 != 16`); committing `q_i = 1` to satisfy R2 fails R1 (`1 != 4`). Neither
//! escape passes both. This is the short-witness (support) leg for the secret;
//! eta-2 error and carry-range follow the same product-relation pattern
//! (`e(e^2-1)(e^2-4)=0` and a range decomposition), composed the same way.
//!
//! Each relation is the batched degree-two Fiat-Shamir identity of
//! `product_check`, sharing one commitment, one mask commitment, and one sigma
//! challenge `x`. For a batching vector `gamma` and responses `z_s = mu_s + x s`,
//! `z_q = mu_q + x q`:
//!
//! ```text
//! R1:  sum gamma1_i z_s_i^2 == g0_1 + x g1_1 + x (sum gamma1_i z_q_i - m_q1)
//! R2:  sum gamma2_i z_q_i^2 == g0_2 + x g1_2 + x (sum gamma2_i z_q_i - m_q2)
//! ```
//!
//! using `x^2 (sum gamma q) = x (sum gamma z_q - m_q)` to avoid a field inverse.
//! The verifier also checks the commitment homomorphism. It never sees `s` or
//! `q`.
//!
//! HONEST SCOPE. This binds the ternary support soundly and witness-free. As with
//! the other openings, the full-width challenge means it is not yet
//! zero-knowledge (the revealed garbage and responses leak the witness); the
//! bounded structured challenge set and rejection sampling are the remaining
//! zero-knowledge layer. Test-gated; not on any acceptance path.

use super::linear_opening::{FlatCommitment, LinearOpeningParameters, commit_flat};
use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const GAMMA_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/support-batching-v1";
const CHALLENGE_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/support-challenge-v1";
const MASK_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/support-mask-v1";

pub(crate) struct TernarySupportProof<const LIMB_COUNT: usize> {
    pub(crate) mask_commitment: Vec<[u64; LIMB_COUNT]>,
    pub(crate) response_secret: Vec<[u64; LIMB_COUNT]>,
    pub(crate) response_square: Vec<[u64; LIMB_COUNT]>,
    pub(crate) randomness_response: Vec<[u64; LIMB_COUNT]>,
    pub(crate) square_garbage_zero: [u64; LIMB_COUNT],
    pub(crate) square_garbage_one: [u64; LIMB_COUNT],
    pub(crate) square_mask_batched: [u64; LIMB_COUNT],
    pub(crate) binary_garbage_zero: [u64; LIMB_COUNT],
    pub(crate) binary_garbage_one: [u64; LIMB_COUNT],
    pub(crate) binary_mask_batched: [u64; LIMB_COUNT],
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

#[allow(clippy::too_many_arguments)]
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

/// Proves the committed secret `s` (with `q = s . s`) is ternary. The commitment
/// message is `s || q` in that order.
pub(crate) fn prove_ternary_support<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    secret: &[[u64; LIMB_COUNT]],
    square: &[[u64; LIMB_COUNT]],
    randomness: &[[u64; LIMB_COUNT]],
    attempt_seed: u64,
) -> (FlatCommitment<LIMB_COUNT>, TernarySupportProof<LIMB_COUNT>) {
    let length = secret.len();
    let mut witness = Vec::with_capacity(2 * length);
    witness.extend_from_slice(secret);
    witness.extend_from_slice(square);
    let commitment = commit_flat(parameters, opening_parameters, &witness, randomness);
    let commitment_seed = seed_bytes(&commitment.rows);
    let gamma_square = batching_vector(parameters, &commitment_seed, 0x31, length);
    let gamma_binary = batching_vector(parameters, &commitment_seed, 0x32, length);

    let mask_secret = mask_vector(parameters, attempt_seed, 0x73, length);
    let mask_square = mask_vector(parameters, attempt_seed, 0x71, length);
    let mask_randomness = mask_vector(parameters, attempt_seed, 0x72, randomness.len());
    let mut mask_witness = Vec::with_capacity(2 * length);
    mask_witness.extend_from_slice(&mask_secret);
    mask_witness.extend_from_slice(&mask_square);
    let mask_commitment = commit_flat(
        parameters,
        opening_parameters,
        &mask_witness,
        &mask_randomness,
    )
    .rows;

    // R1 (q = s . s): a = b = s, c = q.
    let square_garbage_zero =
        batched_product(parameters, &gamma_square, &mask_secret, &mask_secret);
    let mut square_garbage_one = parameters.zero();
    for index in 0..length {
        // 2 * mu_s_i * s_i
        let cross = parameters.multiply(&mask_secret[index], &secret[index]);
        let doubled = parameters.add(&cross, &cross);
        square_garbage_one = parameters.add(
            &square_garbage_one,
            &parameters.multiply(&gamma_square[index], &doubled),
        );
    }
    let square_mask_batched = batched_weighted_sum(parameters, &gamma_square, &mask_square);

    // R2 (q = q . q): a = b = c = q.
    let binary_garbage_zero =
        batched_product(parameters, &gamma_binary, &mask_square, &mask_square);
    let mut binary_garbage_one = parameters.zero();
    for index in 0..length {
        let cross = parameters.multiply(&mask_square[index], &square[index]);
        let doubled = parameters.add(&cross, &cross);
        binary_garbage_one = parameters.add(
            &binary_garbage_one,
            &parameters.multiply(&gamma_binary[index], &doubled),
        );
    }
    let binary_mask_batched = batched_weighted_sum(parameters, &gamma_binary, &mask_square);

    let x = sigma_challenge(
        parameters,
        &mask_commitment,
        &[
            &square_garbage_zero,
            &square_garbage_one,
            &square_mask_batched,
            &binary_garbage_zero,
            &binary_garbage_one,
            &binary_mask_batched,
        ],
    );

    let respond = |mask: &[[u64; LIMB_COUNT]], value: &[[u64; LIMB_COUNT]]| {
        mask.iter()
            .zip(value.iter())
            .map(|(mask_value, witness_value)| {
                parameters.add(mask_value, &parameters.multiply(&x, witness_value))
            })
            .collect::<Vec<_>>()
    };
    let response_secret = respond(&mask_secret, secret);
    let response_square = respond(&mask_square, square);
    let randomness_response = respond(&mask_randomness, randomness);

    (
        commitment,
        TernarySupportProof {
            mask_commitment,
            response_secret,
            response_square,
            randomness_response,
            square_garbage_zero,
            square_garbage_one,
            square_mask_batched,
            binary_garbage_zero,
            binary_garbage_one,
            binary_mask_batched,
        },
    )
}

/// Verifies the ternary support proof without the witness.
pub(crate) fn verify_ternary_support<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    commitment: &FlatCommitment<LIMB_COUNT>,
    length: usize,
    proof: &TernarySupportProof<LIMB_COUNT>,
) -> bool {
    if proof.response_secret.len() != length
        || proof.response_square.len() != length
        || proof.mask_commitment.len() != opening_parameters.commitment_rank
    {
        return false;
    }
    let commitment_seed = seed_bytes(&commitment.rows);
    let gamma_square = batching_vector(parameters, &commitment_seed, 0x31, length);
    let gamma_binary = batching_vector(parameters, &commitment_seed, 0x32, length);
    let x = sigma_challenge(
        parameters,
        &proof.mask_commitment,
        &[
            &proof.square_garbage_zero,
            &proof.square_garbage_one,
            &proof.square_mask_batched,
            &proof.binary_garbage_zero,
            &proof.binary_garbage_one,
            &proof.binary_mask_batched,
        ],
    );

    // Commitment homomorphism: A (z_s || z_q || z_r) == t_mask + x t.
    let mut response_witness = Vec::with_capacity(2 * length);
    response_witness.extend_from_slice(&proof.response_secret);
    response_witness.extend_from_slice(&proof.response_square);
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

    // R1: sum gamma1 z_s^2 == g0_1 + x g1_1 + x (sum gamma1 z_q - m_q1).
    let square_left = batched_product(
        parameters,
        &gamma_square,
        &proof.response_secret,
        &proof.response_secret,
    );
    let square_batched_z_q =
        batched_weighted_sum(parameters, &gamma_square, &proof.response_square);
    let square_tail = parameters.multiply(
        &x,
        &parameters.subtract(&square_batched_z_q, &proof.square_mask_batched),
    );
    let mut square_right = parameters.add(
        &proof.square_garbage_zero,
        &parameters.multiply(&x, &proof.square_garbage_one),
    );
    square_right = parameters.add(&square_right, &square_tail);
    if square_left != square_right {
        return false;
    }

    // R2: sum gamma2 z_q^2 == g0_2 + x g1_2 + x (sum gamma2 z_q - m_q2).
    let binary_left = batched_product(
        parameters,
        &gamma_binary,
        &proof.response_square,
        &proof.response_square,
    );
    let binary_batched_z_q =
        batched_weighted_sum(parameters, &gamma_binary, &proof.response_square);
    let binary_tail = parameters.multiply(
        &x,
        &parameters.subtract(&binary_batched_z_q, &proof.binary_mask_batched),
    );
    let mut binary_right = parameters.add(
        &proof.binary_garbage_zero,
        &parameters.multiply(&x, &proof.binary_garbage_one),
    );
    binary_right = parameters.add(&binary_right, &binary_tail);
    binary_left == binary_right
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    fn signed<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        values: &[i64],
    ) -> Vec<[u64; LIMB_COUNT]> {
        values
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect()
    }

    fn square_of<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        s: &[[u64; LIMB_COUNT]],
    ) -> Vec<[u64; LIMB_COUNT]> {
        s.iter()
            .map(|value| parameters.multiply(value, value))
            .collect()
    }

    fn opening(length: usize) -> LinearOpeningParameters {
        LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: 2 * length,
            randomness_length: 6,
            matrix_seed: 0x7e57,
            mask_bound: 1,
        }
    }

    #[test]
    fn honest_ternary_secret_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let secret = signed(&parameters, &[1, 0, -1, 1, -1, 0, 1, -1, 0, 1, -1, 0]);
        let square = square_of(&parameters, &secret);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(secret.len());

        let (commitment, proof) = prove_ternary_support(
            &parameters,
            &opening_parameters,
            &secret,
            &square,
            &randomness,
            0x5eed,
        );
        assert!(verify_ternary_support(
            &parameters,
            &opening_parameters,
            &commitment,
            secret.len(),
            &proof,
        ));
    }

    #[test]
    fn non_ternary_secret_with_true_square_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        // s has a coefficient 2 (non-ternary); q = s.s is honest, so R1 holds but
        // R2 (q = q.q) fails because q_i = 4 and 4 != 16.
        let secret = signed(&parameters, &[1, 0, -1, 2, -1, 0, 1, -1]);
        let square = square_of(&parameters, &secret);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(secret.len());

        let (commitment, proof) = prove_ternary_support(
            &parameters,
            &opening_parameters,
            &secret,
            &square,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_ternary_support(
                &parameters,
                &opening_parameters,
                &commitment,
                secret.len(),
                &proof,
            ),
            "a non-ternary secret must be rejected by the binary-square relation"
        );
    }

    #[test]
    fn non_ternary_secret_with_forced_binary_square_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        // s has a 2, but the prover forces q_i = 1 (binary) to try to pass R2;
        // then R1 (q = s.s) fails because s_i^2 = 4 != 1.
        let secret = signed(&parameters, &[1, 0, -1, 2, -1, 0, 1, -1]);
        let mut square = square_of(&parameters, &secret);
        square[3] = parameters.unsigned_word_to_element(1);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(secret.len());

        let (commitment, proof) = prove_ternary_support(
            &parameters,
            &opening_parameters,
            &secret,
            &square,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_ternary_support(
                &parameters,
                &opening_parameters,
                &commitment,
                secret.len(),
                &proof,
            ),
            "forcing a binary square to dodge R2 must fail the square relation R1"
        );
    }

    #[test]
    fn tampered_response_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let secret = signed(&parameters, &[1, 0, -1, 1, -1, 0, 1, -1]);
        let square = square_of(&parameters, &secret);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(secret.len());

        let (commitment, mut proof) = prove_ternary_support(
            &parameters,
            &opening_parameters,
            &secret,
            &square,
            &randomness,
            0x5eed,
        );
        proof.response_secret[2] = parameters.add(
            &proof.response_secret[2],
            &parameters.unsigned_word_to_element(1),
        );
        assert!(!verify_ternary_support(
            &parameters,
            &opening_parameters,
            &commitment,
            secret.len(),
            &proof,
        ));
    }
}
