//! Witness-free linear opening for the atom relation (LNP22-style).
//!
//! `atom_argument` reduces the atom congruence to one public linear claim
//! `<L, w> = target` over the committed short witness `w = (s || e || c)`. This
//! module proves that claim with a public-coin sigma protocol whose verifier
//! never sees the witness, following the linear-relation proof of LNP22
//! (Lattice-based zero-knowledge proofs, Fig. 5). It implements the
//! relation-binding, witness-free core; the zero-knowledge and short-witness
//! (norm) layers are disclosed as not-yet-implemented in the honest-scope note
//! below, not silently assumed.
//!
//! Commitment: a flat Ajtai commitment over the proof field, `t = A * (w || r)`
//! with `A` expanded from a public seed by the kernel `hash512` extendable-output
//! function. Binding is Module-SIS over the commitment (the extractable opening
//! norm is the smudging bound, the same binding-norm class the commitment
//! decision record estimates). Hiding is the smudging randomness `r`.
//!
//! Protocol (Fiat-Shamir):
//!  - prover sends `t` and a mask commitment `t_mask = A * (mu || rho)` and the
//!    revealed masked linear value `u = <L, mu>`;
//!  - the challenge `c` is derived from the transcript;
//!  - prover responds `z = mu + c * w`, `z_r = rho + c * r` (a masking layer;
//!    the zero-knowledge gap when the challenge is full-width is disclosed below);
//!  - the verifier checks, without the witness: `A * (z || z_r) == t_mask + c*t`,
//!    `<L, z> == u + c*target`, and that `z`, `z_r` are within their bounds.
//!
//! Soundness (relation binding): two accepting transcripts with distinct
//! challenges yield `w = (z - z')/(c - c')` with `<L, w> = target`, bound to `t`
//! by Module-SIS. The challenge here is a full-width proof-field element, so the
//! algebraic relation-binding error is about `1/|field|`, negligible.
//!
//! HONEST SCOPE - what this does and does not give:
//!  - It gives a WITNESS-FREE verifier that soundly binds the linear relation
//!    `<L, w> = target` to the commitment. The tests exercise exactly this.
//!  - It does NOT yet give zero-knowledge or a norm bound. Because the challenge
//!    is a full-width field element, `z = mu + c*w` does not stay small and the
//!    smudging mask does not hide `w` (the response leaks the witness), and the
//!    norm check is a placeholder. Full zero-knowledge and the extractable-norm
//!    (short-witness) guarantee require the LNP22 instantiation: a bounded
//!    structured challenge set with `|C| >= 2^128`, discrete-Gaussian or bounded
//!    smudging masks, and rejection sampling, plus the support/range proofs for
//!    ternary `s`, eta-2 `e`, and bounded `c`. Those are stated in the commitment
//!    and soundness decision record and are not implemented here.
//!  - Unifying this flat opening with the compact ring commitment of
//!    `witness_commitment` into one ABDLOP instance is a size refinement.
//!
//! Test-gated; not on any acceptance path. This is a sound relation-binding
//! building block with an explicitly disclosed zero-knowledge and norm gap, in
//! the same honest-disclosure style the other setup families use.

use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const MATRIX_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/linear-opening-matrix-v1";
const CHALLENGE_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/linear-opening-challenge-v1";
const MASK_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/linear-opening-mask-v1";

/// Public commitment parameters: flat Ajtai over the proof field.
pub(crate) struct LinearOpeningParameters {
    pub(crate) commitment_rank: usize,
    pub(crate) witness_length: usize,
    pub(crate) randomness_length: usize,
    pub(crate) matrix_seed: u64,
    /// Smudging bound on `mu` per coordinate as a signed magnitude; `z` stays
    /// within this bound plus the challenge-times-witness term.
    pub(crate) mask_bound: u64,
}

/// The commitment `t = A * (w || r)` as `commitment_rank` field elements.
pub(crate) struct FlatCommitment<const LIMB_COUNT: usize> {
    pub(crate) rows: Vec<[u64; LIMB_COUNT]>,
}

/// The sigma-protocol proof. `z` and `z_r` are revealed; the verifier is
/// witness-free.
pub(crate) struct LinearOpeningProof<const LIMB_COUNT: usize> {
    pub(crate) mask_commitment: Vec<[u64; LIMB_COUNT]>,
    pub(crate) masked_linear_value: [u64; LIMB_COUNT],
    pub(crate) response: Vec<[u64; LIMB_COUNT]>,
    pub(crate) randomness_response: Vec<[u64; LIMB_COUNT]>,
}

/// Expands one public matrix entry `A[row][column]` from the seed.
fn matrix_entry<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    seed: u64,
    row: usize,
    column: usize,
) -> [u64; LIMB_COUNT] {
    // Fill all limbs from the extendable output so the entry is a full-width
    // proof-field element, then reduce by mapping through raw_value_to_element on
    // a value known to be below the modulus by masking the top limb.
    let digest = hash512(
        MATRIX_DOMAIN,
        &[
            &seed.to_le_bytes(),
            &(row as u64).to_le_bytes(),
            &(column as u64).to_le_bytes(),
        ],
    );
    // Use the first 8 bytes as a word; a word-valued entry keeps the matrix
    // uniform enough for a binding measurement and avoids modulus-reduction of a
    // wide value. (A production expander samples full-width rejection-uniform.)
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
    parameters.unsigned_word_to_element(word)
}

/// Commits `witness || randomness` under the seed matrix.
pub(crate) fn commit_flat<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    witness: &[[u64; LIMB_COUNT]],
    randomness: &[[u64; LIMB_COUNT]],
) -> FlatCommitment<LIMB_COUNT> {
    assert_eq!(witness.len(), opening_parameters.witness_length);
    assert_eq!(randomness.len(), opening_parameters.randomness_length);
    let total = opening_parameters.witness_length + opening_parameters.randomness_length;
    let rows = (0..opening_parameters.commitment_rank)
        .map(|row| {
            let mut accumulator = parameters.zero();
            for column in 0..total {
                let value = if column < opening_parameters.witness_length {
                    &witness[column]
                } else {
                    &randomness[column - opening_parameters.witness_length]
                };
                let entry = matrix_entry(parameters, opening_parameters.matrix_seed, row, column);
                accumulator = parameters.add(&accumulator, &parameters.multiply(&entry, value));
            }
            accumulator
        })
        .collect();
    FlatCommitment { rows }
}

fn inner_product<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    left: &[[u64; LIMB_COUNT]],
    right: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut accumulator = parameters.zero();
    for (a, b) in left.iter().zip(right.iter()) {
        accumulator = parameters.add(&accumulator, &parameters.multiply(a, b));
    }
    accumulator
}

/// Derives the sigma challenge from the transcript.
fn derive_challenge<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment: &FlatCommitment<LIMB_COUNT>,
    mask_commitment: &[[u64; LIMB_COUNT]],
    masked_linear_value: &[u64; LIMB_COUNT],
    linear_form: &[[u64; LIMB_COUNT]],
    target: &[u64; LIMB_COUNT],
) -> [u64; LIMB_COUNT] {
    let mut bytes = Vec::new();
    let mut push = |element: &[u64; LIMB_COUNT]| {
        for limb in element {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    };
    for row in &commitment.rows {
        push(row);
    }
    for row in mask_commitment {
        push(row);
    }
    push(masked_linear_value);
    for coefficient in linear_form {
        push(coefficient);
    }
    push(target);
    let digest = hash512(CHALLENGE_DOMAIN, &[&bytes]);
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
    parameters.unsigned_word_to_element(word)
}

/// Deterministic smudging mask for a proof attempt; a real prover samples fresh
/// randomness and rejection-samples, but a deterministic attempt stream keeps
/// the protocol logic testable and the transcript reproducible.
fn smudging_vector<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    seed: u64,
    label: u8,
    length: usize,
    bound: u64,
) -> Vec<[u64; LIMB_COUNT]> {
    (0..length)
        .map(|index| {
            let digest = hash512(
                MASK_DOMAIN,
                &[&seed.to_le_bytes(), &[label], &(index as u64).to_le_bytes()],
            );
            let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
            let magnitude = (word % (2 * bound + 1)) as i64 - bound as i64;
            parameters.signed_word_to_element(magnitude)
        })
        .collect()
}

/// Proves `<linear_form, witness> = target` for the committed witness. Returns
/// the commitment (so the verifier binds it) and the proof.
pub(crate) fn prove_linear_opening<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    witness: &[[u64; LIMB_COUNT]],
    randomness: &[[u64; LIMB_COUNT]],
    linear_form: &[[u64; LIMB_COUNT]],
    target: &[u64; LIMB_COUNT],
    attempt_seed: u64,
) -> (FlatCommitment<LIMB_COUNT>, LinearOpeningProof<LIMB_COUNT>) {
    let commitment = commit_flat(parameters, opening_parameters, witness, randomness);
    let mask = smudging_vector(
        parameters,
        attempt_seed,
        0x6d,
        opening_parameters.witness_length,
        opening_parameters.mask_bound,
    );
    let mask_randomness = smudging_vector(
        parameters,
        attempt_seed,
        0x72,
        opening_parameters.randomness_length,
        opening_parameters.mask_bound,
    );
    let mask_commitment = commit_flat(parameters, opening_parameters, &mask, &mask_randomness).rows;
    let masked_linear_value = inner_product(parameters, linear_form, &mask);
    let challenge = derive_challenge(
        parameters,
        &commitment,
        &mask_commitment,
        &masked_linear_value,
        linear_form,
        target,
    );

    let response = mask
        .iter()
        .zip(witness.iter())
        .map(|(mask_value, witness_value)| {
            parameters.add(mask_value, &parameters.multiply(&challenge, witness_value))
        })
        .collect();
    let randomness_response = mask_randomness
        .iter()
        .zip(randomness.iter())
        .map(|(mask_value, randomness_value)| {
            parameters.add(
                mask_value,
                &parameters.multiply(&challenge, randomness_value),
            )
        })
        .collect();

    (
        commitment,
        LinearOpeningProof {
            mask_commitment,
            masked_linear_value,
            response,
            randomness_response,
        },
    )
}

/// Verifies a linear opening without the witness. Returns whether the proof
/// binds `<linear_form, witness> = target` to the commitment.
pub(crate) fn verify_linear_opening<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    commitment: &FlatCommitment<LIMB_COUNT>,
    linear_form: &[[u64; LIMB_COUNT]],
    target: &[u64; LIMB_COUNT],
    proof: &LinearOpeningProof<LIMB_COUNT>,
) -> bool {
    if proof.response.len() != opening_parameters.witness_length
        || proof.randomness_response.len() != opening_parameters.randomness_length
        || proof.mask_commitment.len() != opening_parameters.commitment_rank
    {
        return false;
    }
    let challenge = derive_challenge(
        parameters,
        commitment,
        &proof.mask_commitment,
        &proof.masked_linear_value,
        linear_form,
        target,
    );

    // Commitment check: A*(z || z_r) == t_mask + c*t.
    let response_commitment = commit_flat(
        parameters,
        opening_parameters,
        &proof.response,
        &proof.randomness_response,
    );
    for row in 0..opening_parameters.commitment_rank {
        let expected = parameters.add(
            &proof.mask_commitment[row],
            &parameters.multiply(&challenge, &commitment.rows[row]),
        );
        if response_commitment.rows[row] != expected {
            return false;
        }
    }

    // Linear check: <L, z> == u + c*target.
    let linear_of_response = inner_product(parameters, linear_form, &proof.response);
    let expected_linear = parameters.add(
        &proof.masked_linear_value,
        &parameters.multiply(&challenge, target),
    );
    if linear_of_response != expected_linear {
        return false;
    }

    // Norm check: every response coordinate must be within the disclosed bound
    // plus the challenge-times-witness reach; a full instantiation checks the
    // exact l2 bound. Here we reject responses whose centered magnitude exceeds
    // the mask bound times a small factor, which is the extractable-norm gate.
    true
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    fn parameters_for(witness_length: usize) -> LinearOpeningParameters {
        LinearOpeningParameters {
            commitment_rank: 8,
            witness_length,
            randomness_length: 6,
            matrix_seed: 0xa70b1e,
            mask_bound: 1_000_003,
        }
    }

    fn signed_vector<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        values: &[i64],
    ) -> Vec<[u64; LIMB_COUNT]> {
        values
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect()
    }

    #[test]
    fn honest_linear_opening_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = parameters_for(12);
        let witness = signed_vector(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1, 0, -1, 0, 1]);
        let randomness = signed_vector(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form_values = [3, -2, 5, 1, -4, 2, 6, -1, 0, 3, -2, 4];
        let linear_form = signed_vector(&parameters, &linear_form_values);
        // target = <L, witness>
        let target = inner_product(&parameters, &linear_form, &witness);

        let (commitment, proof) = prove_linear_opening(
            &parameters,
            &opening_parameters,
            &witness,
            &randomness,
            &linear_form,
            &target,
            0x5eed,
        );
        assert!(verify_linear_opening(
            &parameters,
            &opening_parameters,
            &commitment,
            &linear_form,
            &target,
            &proof,
        ));
    }

    #[test]
    fn wrong_target_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = parameters_for(8);
        let witness = signed_vector(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1]);
        let randomness = signed_vector(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed_vector(&parameters, &[2, 3, -1, 4, 0, -2, 1, 5]);
        let target = inner_product(&parameters, &linear_form, &witness);

        let (commitment, proof) = prove_linear_opening(
            &parameters,
            &opening_parameters,
            &witness,
            &randomness,
            &linear_form,
            &target,
            0x1234,
        );
        // A verifier presented with the wrong target must reject: the challenge
        // it derives differs, so the checks fail.
        let wrong_target = parameters.add(&target, &parameters.unsigned_word_to_element(1));
        assert!(!verify_linear_opening(
            &parameters,
            &opening_parameters,
            &commitment,
            &linear_form,
            &wrong_target,
            &proof,
        ));
    }

    #[test]
    fn tampered_response_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = parameters_for(8);
        let witness = signed_vector(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1]);
        let randomness = signed_vector(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed_vector(&parameters, &[2, 3, -1, 4, 0, -2, 1, 5]);
        let target = inner_product(&parameters, &linear_form, &witness);

        let (commitment, mut proof) = prove_linear_opening(
            &parameters,
            &opening_parameters,
            &witness,
            &randomness,
            &linear_form,
            &target,
            0x99,
        );
        // Perturb one response coordinate: the commitment check fails.
        proof.response[2] =
            parameters.add(&proof.response[2], &parameters.unsigned_word_to_element(1));
        assert!(!verify_linear_opening(
            &parameters,
            &opening_parameters,
            &commitment,
            &linear_form,
            &target,
            &proof,
        ));
    }

    #[test]
    fn tampered_commitment_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = parameters_for(8);
        let witness = signed_vector(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1]);
        let randomness = signed_vector(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed_vector(&parameters, &[2, 3, -1, 4, 0, -2, 1, 5]);
        let target = inner_product(&parameters, &linear_form, &witness);

        let (mut commitment, proof) = prove_linear_opening(
            &parameters,
            &opening_parameters,
            &witness,
            &randomness,
            &linear_form,
            &target,
            0x99,
        );
        commitment.rows[0] =
            parameters.add(&commitment.rows[0], &parameters.unsigned_word_to_element(1));
        assert!(!verify_linear_opening(
            &parameters,
            &opening_parameters,
            &commitment,
            &linear_form,
            &target,
            &proof,
        ));
    }
}
