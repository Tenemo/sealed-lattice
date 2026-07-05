//! Witness-free batched product (Hadamard) check for support proofs.
//!
//! The atom's short-witness support constraints are per-coordinate polynomial
//! identities: `s` ternary is `s_i^2 in {0,1}` with `s_i^2 = s_i * s_i`, eta-2
//! `e` is `e_i(e_i^2-1)(e_i^2-4)=0`, and the bounded carry is a range identity.
//! Every one reduces to Hadamard product identities over committed columns
//! (`q = s . s`, `q = q . q`, and so on). This module proves one such identity
//! `c = a . b` with a public-coin, witness-free verifier, following the LNP22
//! quadratic-relation proof (Fig. 6).
//!
//! Protocol. `a`, `b`, `c` are committed together (flat Ajtai, homomorphic). The
//! prover masks `mu = (mu_a || mu_b || mu_c)`, derives a batching challenge
//! `gamma` and a sigma challenge `x` by Fiat-Shamir, and reveals three scalars
//! plus the responses `z_a = mu_a + x a`, `z_b = mu_b + x b`, `z_c = mu_c + x c`:
//!
//! ```text
//! g0 = sum_i gamma_i mu_a_i mu_b_i
//! g1 = sum_i gamma_i (mu_a_i b_i + a_i mu_b_i)
//! m_c = sum_i gamma_i mu_c_i
//! ```
//!
//! The verifier recovers `sum_i gamma_i c_i = (sum_i gamma_i z_c_i - m_c) / x`
//! and checks the degree-two identity in `x`:
//!
//! ```text
//! sum_i gamma_i z_a_i z_b_i == g0 + x g1 + x^2 * (sum_i gamma_i c_i),
//! ```
//!
//! together with the commitment homomorphism `A (z || z_r) == t_mask + x t`. If
//! `c = a . b` this holds; otherwise the `x^2` coefficient `sum gamma_i a_i b_i`
//! differs from `sum gamma_i c_i` and the identity fails for all but two `x`.
//! Extraction from two transcripts gives `a, b, c` with `sum gamma (a.b - c) = 0`
//! for a random `gamma`, hence `c = a . b`. The verifier never sees the witness.
//!
//! HONEST SCOPE. This binds the product relation soundly and witness-free. As in
//! `linear_opening`, the full-width challenge means it is not yet zero-knowledge
//! (the revealed scalars and responses leak the witness) and the short-witness
//! norm is not enforced here; both need the bounded structured challenge set and
//! rejection sampling of the LNP22 instantiation. Composing this into the ternary
//! and eta-2 support proofs and unifying the commitment are the remaining steps.
//! Test-gated; not on any acceptance path.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::linear_opening::{FlatCommitment, LinearOpeningParameters, commit_flat};
use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const GAMMA_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/product-check-batching-v1";
const CHALLENGE_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/product-check-challenge-v1";
const MASK_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/product-check-mask-v1";

pub(crate) struct ProductCheckProof<const LIMB_COUNT: usize> {
    pub(crate) mask_commitment: Vec<[u64; LIMB_COUNT]>,
    pub(crate) response_a: Vec<[u64; LIMB_COUNT]>,
    pub(crate) response_b: Vec<[u64; LIMB_COUNT]>,
    pub(crate) response_c: Vec<[u64; LIMB_COUNT]>,
    pub(crate) randomness_response: Vec<[u64; LIMB_COUNT]>,
    pub(crate) garbage_zero: [u64; LIMB_COUNT],
    pub(crate) garbage_one: [u64; LIMB_COUNT],
    pub(crate) mask_c_batched: [u64; LIMB_COUNT],
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

fn batching_vector<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment: &FlatCommitment<LIMB_COUNT>,
    length: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut seed = Vec::new();
    for row in &commitment.rows {
        for limb in row {
            seed.extend_from_slice(&limb.to_le_bytes());
        }
    }
    (0..length)
        .map(|index| {
            field_from_digest(
                parameters,
                GAMMA_DOMAIN,
                &[&seed, &(index as u64).to_le_bytes()],
            )
        })
        .collect()
}

fn sigma_challenge<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    mask_commitment: &[[u64; LIMB_COUNT]],
    garbage_zero: &[u64; LIMB_COUNT],
    garbage_one: &[u64; LIMB_COUNT],
    mask_c: &[u64; LIMB_COUNT],
) -> [u64; LIMB_COUNT] {
    let mut seed = Vec::new();
    let push = |element: &[u64; LIMB_COUNT], out: &mut Vec<u8>| {
        for limb in element {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    };
    for row in mask_commitment {
        push(row, &mut seed);
    }
    push(garbage_zero, &mut seed);
    push(garbage_one, &mut seed);
    push(mask_c, &mut seed);
    field_from_digest(parameters, CHALLENGE_DOMAIN, &[&seed])
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

fn batched_inner<const LIMB_COUNT: usize>(
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

/// Proves `c = a . b` for the committed columns. `a`, `b`, `c` are concatenated
/// into the flat commitment message in that order.
pub(crate) fn prove_product<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    a: &[[u64; LIMB_COUNT]],
    b: &[[u64; LIMB_COUNT]],
    c: &[[u64; LIMB_COUNT]],
    randomness: &[[u64; LIMB_COUNT]],
    attempt_seed: u64,
) -> (FlatCommitment<LIMB_COUNT>, ProductCheckProof<LIMB_COUNT>) {
    let length = a.len();
    let mut witness = Vec::with_capacity(3 * length);
    witness.extend_from_slice(a);
    witness.extend_from_slice(b);
    witness.extend_from_slice(c);
    let commitment = commit_flat(parameters, opening_parameters, &witness, randomness);
    let gamma = batching_vector(parameters, &commitment, length);

    let mask_a = mask_vector(parameters, attempt_seed, 0x61, length);
    let mask_b = mask_vector(parameters, attempt_seed, 0x62, length);
    let mask_c = mask_vector(parameters, attempt_seed, 0x63, length);
    let mask_randomness = mask_vector(parameters, attempt_seed, 0x72, randomness.len());
    let mut mask_witness = Vec::with_capacity(3 * length);
    mask_witness.extend_from_slice(&mask_a);
    mask_witness.extend_from_slice(&mask_b);
    mask_witness.extend_from_slice(&mask_c);
    let mask_commitment = commit_flat(
        parameters,
        opening_parameters,
        &mask_witness,
        &mask_randomness,
    )
    .rows;

    // g0 = sum gamma_i mu_a_i mu_b_i
    let garbage_zero = batched_inner(parameters, &gamma, &mask_a, &mask_b);
    // g1 = sum gamma_i (mu_a_i b_i + a_i mu_b_i)
    let mut garbage_one = parameters.zero();
    for index in 0..length {
        let left = parameters.multiply(&mask_a[index], &b[index]);
        let right = parameters.multiply(&a[index], &mask_b[index]);
        let sum = parameters.add(&left, &right);
        garbage_one = parameters.add(&garbage_one, &parameters.multiply(&gamma[index], &sum));
    }
    // m_c = sum gamma_i mu_c_i
    let mut mask_c_batched = parameters.zero();
    for index in 0..length {
        mask_c_batched = parameters.add(
            &mask_c_batched,
            &parameters.multiply(&gamma[index], &mask_c[index]),
        );
    }

    let x = sigma_challenge(
        parameters,
        &mask_commitment,
        &garbage_zero,
        &garbage_one,
        &mask_c_batched,
    );

    let respond = |mask: &[[u64; LIMB_COUNT]], value: &[[u64; LIMB_COUNT]]| {
        mask.iter()
            .zip(value.iter())
            .map(|(mask_value, witness_value)| {
                parameters.add(mask_value, &parameters.multiply(&x, witness_value))
            })
            .collect::<Vec<_>>()
    };
    let response_a = respond(&mask_a, a);
    let response_b = respond(&mask_b, b);
    let response_c = respond(&mask_c, c);
    let randomness_response = respond(&mask_randomness, randomness);

    (
        commitment,
        ProductCheckProof {
            mask_commitment,
            response_a,
            response_b,
            response_c,
            randomness_response,
            garbage_zero,
            garbage_one,
            mask_c_batched,
        },
    )
}

/// Verifies `c = a . b` without the witness.
pub(crate) fn verify_product<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    commitment: &FlatCommitment<LIMB_COUNT>,
    length: usize,
    proof: &ProductCheckProof<LIMB_COUNT>,
) -> bool {
    if proof.response_a.len() != length
        || proof.response_b.len() != length
        || proof.response_c.len() != length
        || proof.mask_commitment.len() != opening_parameters.commitment_rank
    {
        return false;
    }
    let gamma = batching_vector(parameters, commitment, length);
    let x = sigma_challenge(
        parameters,
        &proof.mask_commitment,
        &proof.garbage_zero,
        &proof.garbage_one,
        &proof.mask_c_batched,
    );
    if x == parameters.zero() {
        return false;
    }

    // Commitment homomorphism: A (z || z_r) == t_mask + x t.
    let mut response_witness = Vec::with_capacity(3 * length);
    response_witness.extend_from_slice(&proof.response_a);
    response_witness.extend_from_slice(&proof.response_b);
    response_witness.extend_from_slice(&proof.response_c);
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

    // Recover sum gamma_i c_i = (sum gamma_i z_c_i - m_c) / x.
    let mut batched_z_c = parameters.zero();
    for index in 0..length {
        batched_z_c = parameters.add(
            &batched_z_c,
            &parameters.multiply(&gamma[index], &proof.response_c[index]),
        );
    }
    let numerator = parameters.subtract(&batched_z_c, &proof.mask_c_batched);
    let batched_c = parameters.multiply(&numerator, &parameters.inverse(&x));

    // Product identity: sum gamma_i z_a_i z_b_i == g0 + x g1 + x^2 * batched_c.
    let left = batched_inner(parameters, &gamma, &proof.response_a, &proof.response_b);
    let x_squared = parameters.multiply(&x, &x);
    let mut right = parameters.add(
        &proof.garbage_zero,
        &parameters.multiply(&x, &proof.garbage_one),
    );
    right = parameters.add(&right, &parameters.multiply(&x_squared, &batched_c));
    left == right
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

    fn hadamard<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        a: &[[u64; LIMB_COUNT]],
        b: &[[u64; LIMB_COUNT]],
    ) -> Vec<[u64; LIMB_COUNT]> {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| parameters.multiply(x, y))
            .collect()
    }

    fn opening(length: usize) -> LinearOpeningParameters {
        LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: 3 * length,
            randomness_length: 6,
            matrix_seed: 0x9dc7,
            mask_bound: 1,
        }
    }

    #[test]
    fn honest_product_check_verifies_for_a_ternary_square() {
        let parameters = sixteen_limb_group_field_parameters();
        // s ternary, q = s . s (the ternary-square product identity).
        let s = signed(&parameters, &[1, 0, -1, 1, -1, 0, 1, -1, 0, 1]);
        let q = hadamard(&parameters, &s, &s);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(s.len());

        let (commitment, proof) = prove_product(
            &parameters,
            &opening_parameters,
            &s,
            &s,
            &q,
            &randomness,
            0x5eed,
        );
        assert!(verify_product(
            &parameters,
            &opening_parameters,
            &commitment,
            s.len(),
            &proof,
        ));
    }

    #[test]
    fn honest_product_check_verifies_for_general_vectors() {
        let parameters = sixteen_limb_group_field_parameters();
        let a = signed(&parameters, &[2, -3, 5, 0, 1, -2, 4, -1]);
        let b = signed(&parameters, &[-1, 4, 2, 3, -5, 1, 0, 6]);
        let c = hadamard(&parameters, &a, &b);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(a.len());

        let (commitment, proof) = prove_product(
            &parameters,
            &opening_parameters,
            &a,
            &b,
            &c,
            &randomness,
            0x1234,
        );
        assert!(verify_product(
            &parameters,
            &opening_parameters,
            &commitment,
            a.len(),
            &proof,
        ));
    }

    #[test]
    fn wrong_product_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let a = signed(&parameters, &[2, -3, 5, 0, 1, -2, 4, -1]);
        let b = signed(&parameters, &[-1, 4, 2, 3, -5, 1, 0, 6]);
        let mut c = hadamard(&parameters, &a, &b);
        // Corrupt one product coordinate: c is no longer a . b.
        c[3] = parameters.add(&c[3], &parameters.unsigned_word_to_element(1));
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(a.len());

        let (commitment, proof) = prove_product(
            &parameters,
            &opening_parameters,
            &a,
            &b,
            &c,
            &randomness,
            0x1234,
        );
        assert!(
            !verify_product(
                &parameters,
                &opening_parameters,
                &commitment,
                a.len(),
                &proof
            ),
            "a c that is not the Hadamard product must be rejected"
        );
    }

    #[test]
    fn tampered_response_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let a = signed(&parameters, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let b = signed(&parameters, &[8, 7, 6, 5, 4, 3, 2, 1]);
        let c = hadamard(&parameters, &a, &b);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(a.len());

        let (commitment, mut proof) = prove_product(
            &parameters,
            &opening_parameters,
            &a,
            &b,
            &c,
            &randomness,
            0x77,
        );
        proof.response_a[2] = parameters.add(
            &proof.response_a[2],
            &parameters.unsigned_word_to_element(1),
        );
        assert!(
            !verify_product(
                &parameters,
                &opening_parameters,
                &commitment,
                a.len(),
                &proof
            ),
            "a tampered response must break the commitment or product check"
        );
    }
}
