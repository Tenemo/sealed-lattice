//! Witness-free eta-2 support proof for the error column.
//!
//! Proves the committed error `e` has centered-binomial eta-2 support
//! (`e_i in {-2,-1,0,1,2}`) with a public-coin, witness-free verifier. Writing
//! `w = e^2`, `w2 = w^2 = e^4`, `w3 = w * w2 = e^6`, the support constraint
//! `e_i in {-2..2}` is exactly `w_i in {0,1,4}`, which is the cubic
//!
//! ```text
//! w(w-1)(w-4) = w^3 - 5 w^2 + 4 w = 0   <=>   w3 - 5 w2 + 4 w = 0.
//! ```
//!
//! So the proof composes three Hadamard product relations and one linear
//! relation over one shared commitment to `(e, w, w2, w3)`:
//!
//! ```text
//! P1: w  = e . e      P2: w2 = w . w      P3: w3 = w . w2      L: w3 - 5 w2 + 4 w = 0
//! ```
//!
//! A prover with an out-of-range `e_i = 3` has `w_i = 9`, and honest squares give
//! `w3 - 5 w2 + 4 w = 729 - 405 + 36 = 360 != 0`, so the linear relation rejects
//! it; forging the squares to dodge L instead fails one of the product relations.
//! This demonstrates the product-plus-linear pattern of `support_proof` extends to
//! a degree-six support constraint by composition. The carry-range column follows
//! the same pattern with a range decomposition.
//!
//! Each product relation is the degree-two Fiat-Shamir identity of
//! `product_check`; the linear relation checks `sum gamma_L (z_w3 - 5 z_w2 +
//! 4 z_w) == M_L` for the revealed mask combination `M_L`. All share one
//! commitment, one mask commitment, and one challenge `x`. The verifier also
//! checks the commitment homomorphism and never sees the witness.
//!
//! HONEST SCOPE. This binds the eta-2 support soundly and witness-free. As with
//! the other openings, the full-width challenge means it is not yet
//! zero-knowledge; the bounded structured challenge set and rejection sampling
//! are the remaining zero-knowledge layer. Test-gated; not on any acceptance path.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::linear_opening::{FlatCommitment, LinearOpeningParameters, commit_flat};
use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const GAMMA_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/eta2-batching-v1";
const CHALLENGE_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/eta2-challenge-v1";
const MASK_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/eta2-mask-v1";

/// A single product relation's Fiat-Shamir garbage: `c = a . b` batched.
struct ProductGarbage<const LIMB_COUNT: usize> {
    garbage_zero: [u64; LIMB_COUNT],
    garbage_one: [u64; LIMB_COUNT],
    mask_c_batched: [u64; LIMB_COUNT],
}

pub(crate) struct Eta2SupportProof<const LIMB_COUNT: usize> {
    mask_commitment: Vec<[u64; LIMB_COUNT]>,
    response_error: Vec<[u64; LIMB_COUNT]>,
    response_square: Vec<[u64; LIMB_COUNT]>,
    response_fourth: Vec<[u64; LIMB_COUNT]>,
    response_sixth: Vec<[u64; LIMB_COUNT]>,
    randomness_response: Vec<[u64; LIMB_COUNT]>,
    square_relation: ProductGarbage<LIMB_COUNT>,
    fourth_relation: ProductGarbage<LIMB_COUNT>,
    sixth_relation: ProductGarbage<LIMB_COUNT>,
    linear_mask_batched: [u64; LIMB_COUNT],
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

/// Builds one product relation's garbage for `c = a . b` (with `a`, `b` equal
/// when squaring). `gamma` is that relation's batching vector.
fn product_garbage<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    gamma: &[[u64; LIMB_COUNT]],
    mask_a: &[[u64; LIMB_COUNT]],
    mask_b: &[[u64; LIMB_COUNT]],
    a: &[[u64; LIMB_COUNT]],
    b: &[[u64; LIMB_COUNT]],
    mask_c: &[[u64; LIMB_COUNT]],
) -> ProductGarbage<LIMB_COUNT> {
    let garbage_zero = batched_product(parameters, gamma, mask_a, mask_b);
    let mut garbage_one = parameters.zero();
    for index in 0..gamma.len() {
        let left = parameters.multiply(&mask_a[index], &b[index]);
        let right = parameters.multiply(&a[index], &mask_b[index]);
        let sum = parameters.add(&left, &right);
        garbage_one = parameters.add(&garbage_one, &parameters.multiply(&gamma[index], &sum));
    }
    let mask_c_batched = batched_weighted_sum(parameters, gamma, mask_c);
    ProductGarbage {
        garbage_zero,
        garbage_one,
        mask_c_batched,
    }
}

/// Checks one product identity `sum gamma z_a z_b == g0 + x g1 + x (sum gamma z_c
/// - m_c)`.
fn product_holds<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    gamma: &[[u64; LIMB_COUNT]],
    x: &[u64; LIMB_COUNT],
    response_a: &[[u64; LIMB_COUNT]],
    response_b: &[[u64; LIMB_COUNT]],
    response_c: &[[u64; LIMB_COUNT]],
    garbage: &ProductGarbage<LIMB_COUNT>,
) -> bool {
    let left = batched_product(parameters, gamma, response_a, response_b);
    let batched_z_c = batched_weighted_sum(parameters, gamma, response_c);
    let tail = parameters.multiply(
        x,
        &parameters.subtract(&batched_z_c, &garbage.mask_c_batched),
    );
    let mut right = parameters.add(
        &garbage.garbage_zero,
        &parameters.multiply(x, &garbage.garbage_one),
    );
    right = parameters.add(&right, &tail);
    left == right
}

fn all_challenge_scalars<const LIMB_COUNT: usize>(
    proof: &Eta2SupportProof<LIMB_COUNT>,
) -> Vec<&[u64; LIMB_COUNT]> {
    vec![
        &proof.square_relation.garbage_zero,
        &proof.square_relation.garbage_one,
        &proof.square_relation.mask_c_batched,
        &proof.fourth_relation.garbage_zero,
        &proof.fourth_relation.garbage_one,
        &proof.fourth_relation.mask_c_batched,
        &proof.sixth_relation.garbage_zero,
        &proof.sixth_relation.garbage_one,
        &proof.sixth_relation.mask_c_batched,
        &proof.linear_mask_batched,
    ]
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

/// Proves the committed error `e` is eta-2. The commitment message is
/// `e || w || w2 || w3` with `w = e^2`, `w2 = e^4`, `w3 = e^6`.
pub(crate) fn prove_eta2_support<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    error: &[[u64; LIMB_COUNT]],
    square: &[[u64; LIMB_COUNT]],
    fourth: &[[u64; LIMB_COUNT]],
    sixth: &[[u64; LIMB_COUNT]],
    randomness: &[[u64; LIMB_COUNT]],
    attempt_seed: u64,
) -> (FlatCommitment<LIMB_COUNT>, Eta2SupportProof<LIMB_COUNT>) {
    let length = error.len();
    let mut witness = Vec::with_capacity(4 * length);
    witness.extend_from_slice(error);
    witness.extend_from_slice(square);
    witness.extend_from_slice(fourth);
    witness.extend_from_slice(sixth);
    let commitment = commit_flat(parameters, opening_parameters, &witness, randomness);
    let commitment_seed = seed_bytes(&commitment.rows);
    let gamma_square = batching_vector(parameters, &commitment_seed, 0x31, length);
    let gamma_fourth = batching_vector(parameters, &commitment_seed, 0x32, length);
    let gamma_sixth = batching_vector(parameters, &commitment_seed, 0x33, length);
    let gamma_linear = batching_vector(parameters, &commitment_seed, 0x34, length);

    let mask_error = mask_vector(parameters, attempt_seed, 0x65, length);
    let mask_square = mask_vector(parameters, attempt_seed, 0x77, length);
    let mask_fourth = mask_vector(parameters, attempt_seed, 0x78, length);
    let mask_sixth = mask_vector(parameters, attempt_seed, 0x79, length);
    let mask_randomness = mask_vector(parameters, attempt_seed, 0x72, randomness.len());
    let mut mask_witness = Vec::with_capacity(4 * length);
    mask_witness.extend_from_slice(&mask_error);
    mask_witness.extend_from_slice(&mask_square);
    mask_witness.extend_from_slice(&mask_fourth);
    mask_witness.extend_from_slice(&mask_sixth);
    let mask_commitment = commit_flat(
        parameters,
        opening_parameters,
        &mask_witness,
        &mask_randomness,
    )
    .rows;

    // P1: w = e . e
    let square_relation = product_garbage(
        parameters,
        &gamma_square,
        &mask_error,
        &mask_error,
        error,
        error,
        &mask_square,
    );
    // P2: w2 = w . w
    let fourth_relation = product_garbage(
        parameters,
        &gamma_fourth,
        &mask_square,
        &mask_square,
        square,
        square,
        &mask_fourth,
    );
    // P3: w3 = w . w2
    let sixth_relation = product_garbage(
        parameters,
        &gamma_sixth,
        &mask_square,
        &mask_fourth,
        square,
        fourth,
        &mask_sixth,
    );

    // L: w3 - 5 w2 + 4 w = 0 -> M_L = sum gamma_L (mu_w3 - 5 mu_w2 + 4 mu_w).
    let five = parameters.unsigned_word_to_element(5);
    let four = parameters.unsigned_word_to_element(4);
    let mut linear_mask_batched = parameters.zero();
    for index in 0..length {
        let mut term = mask_sixth[index];
        term = parameters.subtract(&term, &parameters.multiply(&five, &mask_fourth[index]));
        term = parameters.add(&term, &parameters.multiply(&four, &mask_square[index]));
        linear_mask_batched = parameters.add(
            &linear_mask_batched,
            &parameters.multiply(&gamma_linear[index], &term),
        );
    }

    // Challenge scalars in the same order the verifier assembles them.
    let challenge_scalars: [&[u64; LIMB_COUNT]; 10] = [
        &square_relation.garbage_zero,
        &square_relation.garbage_one,
        &square_relation.mask_c_batched,
        &fourth_relation.garbage_zero,
        &fourth_relation.garbage_one,
        &fourth_relation.mask_c_batched,
        &sixth_relation.garbage_zero,
        &sixth_relation.garbage_one,
        &sixth_relation.mask_c_batched,
        &linear_mask_batched,
    ];
    let x = sigma_challenge(parameters, &mask_commitment, &challenge_scalars);

    let respond = |mask: &[[u64; LIMB_COUNT]], value: &[[u64; LIMB_COUNT]]| {
        mask.iter()
            .zip(value.iter())
            .map(|(mask_value, witness_value)| {
                parameters.add(mask_value, &parameters.multiply(&x, witness_value))
            })
            .collect::<Vec<_>>()
    };
    let response_error = respond(&mask_error, error);
    let response_square = respond(&mask_square, square);
    let response_fourth = respond(&mask_fourth, fourth);
    let response_sixth = respond(&mask_sixth, sixth);
    let randomness_response = respond(&mask_randomness, randomness);

    (
        commitment,
        Eta2SupportProof {
            mask_commitment,
            response_error,
            response_square,
            response_fourth,
            response_sixth,
            randomness_response,
            square_relation,
            fourth_relation,
            sixth_relation,
            linear_mask_batched,
        },
    )
}

/// Verifies the eta-2 support proof without the witness.
pub(crate) fn verify_eta2_support<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    commitment: &FlatCommitment<LIMB_COUNT>,
    length: usize,
    proof: &Eta2SupportProof<LIMB_COUNT>,
) -> bool {
    if proof.response_error.len() != length
        || proof.response_square.len() != length
        || proof.response_fourth.len() != length
        || proof.response_sixth.len() != length
        || proof.mask_commitment.len() != opening_parameters.commitment_rank
    {
        return false;
    }
    let commitment_seed = seed_bytes(&commitment.rows);
    let gamma_square = batching_vector(parameters, &commitment_seed, 0x31, length);
    let gamma_fourth = batching_vector(parameters, &commitment_seed, 0x32, length);
    let gamma_sixth = batching_vector(parameters, &commitment_seed, 0x33, length);
    let gamma_linear = batching_vector(parameters, &commitment_seed, 0x34, length);
    let scalars = all_challenge_scalars(proof);
    let x = sigma_challenge(parameters, &proof.mask_commitment, &scalars);

    // Commitment homomorphism.
    let mut response_witness = Vec::with_capacity(4 * length);
    response_witness.extend_from_slice(&proof.response_error);
    response_witness.extend_from_slice(&proof.response_square);
    response_witness.extend_from_slice(&proof.response_fourth);
    response_witness.extend_from_slice(&proof.response_sixth);
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

    // P1: w = e . e
    if !product_holds(
        parameters,
        &gamma_square,
        &x,
        &proof.response_error,
        &proof.response_error,
        &proof.response_square,
        &proof.square_relation,
    ) {
        return false;
    }
    // P2: w2 = w . w
    if !product_holds(
        parameters,
        &gamma_fourth,
        &x,
        &proof.response_square,
        &proof.response_square,
        &proof.response_fourth,
        &proof.fourth_relation,
    ) {
        return false;
    }
    // P3: w3 = w . w2
    if !product_holds(
        parameters,
        &gamma_sixth,
        &x,
        &proof.response_square,
        &proof.response_fourth,
        &proof.response_sixth,
        &proof.sixth_relation,
    ) {
        return false;
    }

    // L: sum gamma_L (z_w3 - 5 z_w2 + 4 z_w) == M_L.
    let five = parameters.unsigned_word_to_element(5);
    let four = parameters.unsigned_word_to_element(4);
    let mut linear_left = parameters.zero();
    for index in 0..length {
        let mut term = proof.response_sixth[index];
        term = parameters.subtract(
            &term,
            &parameters.multiply(&five, &proof.response_fourth[index]),
        );
        term = parameters.add(
            &term,
            &parameters.multiply(&four, &proof.response_square[index]),
        );
        linear_left = parameters.add(
            &linear_left,
            &parameters.multiply(&gamma_linear[index], &term),
        );
    }
    linear_left == proof.linear_mask_batched
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

    fn power_columns<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        e: &[[u64; LIMB_COUNT]],
    ) -> (
        Vec<[u64; LIMB_COUNT]>,
        Vec<[u64; LIMB_COUNT]>,
        Vec<[u64; LIMB_COUNT]>,
    ) {
        let square = e
            .iter()
            .map(|v| parameters.multiply(v, v))
            .collect::<Vec<_>>();
        let fourth = square
            .iter()
            .map(|v| parameters.multiply(v, v))
            .collect::<Vec<_>>();
        let sixth = square
            .iter()
            .zip(fourth.iter())
            .map(|(w, w2)| parameters.multiply(w, w2))
            .collect::<Vec<_>>();
        (square, fourth, sixth)
    }

    fn opening(length: usize) -> LinearOpeningParameters {
        LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: 4 * length,
            randomness_length: 6,
            matrix_seed: 0xe7a2,
            mask_bound: 1,
        }
    }

    #[test]
    fn honest_eta2_error_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let error = signed(&parameters, &[0, 1, -1, 2, -2, 0, 1, -2, 2, -1]);
        let (square, fourth, sixth) = power_columns(&parameters, &error);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(error.len());

        let (commitment, proof) = prove_eta2_support(
            &parameters,
            &opening_parameters,
            &error,
            &square,
            &fourth,
            &sixth,
            &randomness,
            0x5eed,
        );
        assert!(verify_eta2_support(
            &parameters,
            &opening_parameters,
            &commitment,
            error.len(),
            &proof,
        ));
    }

    #[test]
    fn out_of_range_error_with_true_powers_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        // e_i = 3 is out of eta-2 range; honest powers give w3-5w2+4w = 360 != 0,
        // so the linear relation rejects it.
        let error = signed(&parameters, &[0, 1, -1, 3, -2, 0, 1, -2]);
        let (square, fourth, sixth) = power_columns(&parameters, &error);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(error.len());

        let (commitment, proof) = prove_eta2_support(
            &parameters,
            &opening_parameters,
            &error,
            &square,
            &fourth,
            &sixth,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_eta2_support(
                &parameters,
                &opening_parameters,
                &commitment,
                error.len(),
                &proof
            ),
            "an out-of-range error must be rejected by the eta-2 linear relation"
        );
    }

    #[test]
    fn forged_powers_to_dodge_linear_relation_fail_a_product() {
        let parameters = sixteen_limb_group_field_parameters();
        // e_i = 3, but forge w3 so the linear relation w3-5w2+4w=0 holds anyway;
        // then P3 (w3 = w . w2) fails because the forged w3 != w * w2.
        let error = signed(&parameters, &[0, 1, -1, 3, -2, 0, 1, -2]);
        let (square, fourth, mut sixth) = power_columns(&parameters, &error);
        // Force w3_3 = 5 w2_3 - 4 w_3 so L holds at index 3.
        let five = parameters.unsigned_word_to_element(5);
        let four = parameters.unsigned_word_to_element(4);
        let forced = parameters.subtract(
            &parameters.multiply(&five, &fourth[3]),
            &parameters.multiply(&four, &square[3]),
        );
        sixth[3] = forced;
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(error.len());

        let (commitment, proof) = prove_eta2_support(
            &parameters,
            &opening_parameters,
            &error,
            &square,
            &fourth,
            &sixth,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_eta2_support(
                &parameters,
                &opening_parameters,
                &commitment,
                error.len(),
                &proof
            ),
            "forging the sixth power to satisfy L must fail the w3 = w . w2 product"
        );
    }

    #[test]
    fn tampered_response_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let error = signed(&parameters, &[0, 1, -1, 2, -2, 0, 1, -2]);
        let (square, fourth, sixth) = power_columns(&parameters, &error);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let opening_parameters = opening(error.len());

        let (commitment, mut proof) = prove_eta2_support(
            &parameters,
            &opening_parameters,
            &error,
            &square,
            &fourth,
            &sixth,
            &randomness,
            0x5eed,
        );
        proof.response_square[1] = parameters.add(
            &proof.response_square[1],
            &parameters.unsigned_word_to_element(1),
        );
        assert!(!verify_eta2_support(
            &parameters,
            &opening_parameters,
            &commitment,
            error.len(),
            &proof,
        ));
    }
}
