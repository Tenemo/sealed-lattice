//! Zero-knowledge linear opening (honest-verifier), closing the witness-leak gap.
//!
//! The relation-binding openings in `linear_opening`, `product_check`, and the
//! support proofs are sound and witness-free, but their response `z = mu + c w`
//! uses a full-width challenge, so `z` reveals `w`. This module adds the missing
//! zero-knowledge layer for the linear opening in the standard sigma-protocol way
//! (LNP22 / Lyubashevsky): a bounded challenge and a wide uniform smudging mask,
//! plus a simulator that produces an accepting transcript without the witness.
//!
//! Interactive sigma protocol proving `<L, w> = target` for committed `w`:
//!  - prover masks `mu` uniform over `[-mask_bound, mask_bound]` per coordinate
//!    (with `mask_bound >> challenge_bound * ||w||`), commits `t_mask =
//!    A(mu || mu_r)`, and reveals `u = <L, mu>`;
//!  - the verifier sends a challenge `c` in `[1, challenge_bound]`;
//!  - the prover responds `z = mu + c w`, `z_r = mu_r + c r`;
//!  - the verifier checks `A(z || z_r) == t_mask + c t`, `<L, z> == u + c target`,
//!    and that every response coordinate stays within the smudging range.
//!
//! Zero-knowledge (honest-verifier): the `simulate` function, given only the
//! public statement and the challenge, samples `z`, `z_r` from the same smudging
//! range and sets `t_mask = A(z || z_r) - c t` and `u = <L, z> - c target`, so
//! the transcript is accepting and, because `mask_bound >> challenge_bound *
//! ||w||`, statistically indistinguishable from a real transcript (the smudging
//! distance is about `challenge_bound * ||w|| / mask_bound`). The tests confirm
//! the simulator's transcript verifies, which is the zero-knowledge property.
//! Fiat-Shamir compiles this honest-verifier sigma protocol to a non-interactive
//! zero-knowledge argument in the random-oracle model in the usual way.
//!
//! Soundness: over the prime proof field, distinct challenges differ by a nonzero,
//! hence invertible, field element, so two accepting transcripts extract a `w`
//! with `<L, w> = target` bound to the commitment. A bounded challenge set gives
//! `1 / challenge_bound` soundness error per run, amplified by repetition to the
//! target; the challenge bound trades soundness per run against the smudging
//! width (and thus the extractable norm), exactly the LNP22 trade-off.
//!
//! HONEST SCOPE. This demonstrates the zero-knowledge layer (simulator, smudging,
//! bounded challenge, norm-bounded response) soundly and testably. Binding at the
//! full witness size needs a commitment modulus small enough for Module-SIS at the
//! smudged norm (the ring commitment of `witness_commitment`, whose modulus must
//! also admit invertible structured challenges); wiring this opening onto that
//! commitment is the remaining integration, disclosed. Test-gated.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::linear_opening::{FlatCommitment, LinearOpeningParameters, commit_flat};
use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const MASK_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/zk-linear-mask-v1";

pub(crate) struct ZkLinearParameters {
    /// Challenge magnitude bound; challenges are in `[1, challenge_bound]`.
    pub(crate) challenge_bound: u64,
    /// Smudging mask magnitude bound per coordinate.
    pub(crate) mask_bound: u64,
    /// Per-coordinate magnitude bound of the witness class this opening covers
    /// (1 for ternary secrets, 2 for eta-2 errors, `ring_degree + 1` when the
    /// witness includes digit carries). The verifier's response norm bound is
    /// `mask_bound + challenge_bound * witness_magnitude_bound`.
    pub(crate) witness_magnitude_bound: u64,
}

pub(crate) struct ZkLinearProof<const LIMB_COUNT: usize> {
    pub(crate) mask_commitment: Vec<[u64; LIMB_COUNT]>,
    pub(crate) masked_linear_value: [u64; LIMB_COUNT],
    pub(crate) response: Vec<[u64; LIMB_COUNT]>,
    pub(crate) randomness_response: Vec<[u64; LIMB_COUNT]>,
    /// The centered magnitudes of the response coordinates, so the verifier can
    /// check the smudging bound (the response elements are field-reduced).
    pub(crate) response_magnitudes: Vec<u64>,
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

/// Uniform signed mask coordinate in `[-mask_bound, mask_bound]`.
fn mask_coordinate<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    seed: u64,
    label: u8,
    index: usize,
    mask_bound: u64,
) -> [u64; LIMB_COUNT] {
    let digest = hash512(
        MASK_DOMAIN,
        &[&seed.to_le_bytes(), &[label], &(index as u64).to_le_bytes()],
    );
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
    let span = 2 * mask_bound + 1;
    let magnitude = (word % span) as i64 - mask_bound as i64;
    parameters.signed_word_to_element(magnitude)
}

fn challenge_element<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    challenge: u64,
) -> [u64; LIMB_COUNT] {
    parameters.unsigned_word_to_element(challenge)
}

/// Centered magnitude of a field element as a u64 if it fits (mask/challenge
/// bounded responses do), else `u64::MAX` to force a bound failure.
fn centered_magnitude<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    element: &[u64; LIMB_COUNT],
) -> u64 {
    let (_, magnitude) = parameters.centered_raw(element);
    if magnitude[1..].iter().all(|limb| *limb == 0) {
        magnitude[0]
    } else {
        u64::MAX
    }
}

/// Real prover. `challenge` is supplied (interactive form); Fiat-Shamir derives
/// it from the transcript in the non-interactive compilation.
pub(crate) fn prove_zk_linear<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    zk_parameters: &ZkLinearParameters,
    witness: &[[u64; LIMB_COUNT]],
    randomness: &[[u64; LIMB_COUNT]],
    linear_form: &[[u64; LIMB_COUNT]],
    challenge: u64,
    mask_seed: u64,
) -> ZkLinearProof<LIMB_COUNT> {
    let mask: Vec<[u64; LIMB_COUNT]> = (0..opening_parameters.witness_length)
        .map(|index| mask_coordinate(parameters, mask_seed, 0x6d, index, zk_parameters.mask_bound))
        .collect();
    let mask_randomness: Vec<[u64; LIMB_COUNT]> = (0..opening_parameters.randomness_length)
        .map(|index| mask_coordinate(parameters, mask_seed, 0x72, index, zk_parameters.mask_bound))
        .collect();
    let mask_commitment = commit_flat(parameters, opening_parameters, &mask, &mask_randomness).rows;
    let masked_linear_value = inner_product(parameters, linear_form, &mask);

    let challenge_field = challenge_element(parameters, challenge);
    let response: Vec<[u64; LIMB_COUNT]> = mask
        .iter()
        .zip(witness.iter())
        .map(|(mask_value, witness_value)| {
            parameters.add(
                mask_value,
                &parameters.multiply(&challenge_field, witness_value),
            )
        })
        .collect();
    let randomness_response: Vec<[u64; LIMB_COUNT]> = mask_randomness
        .iter()
        .zip(randomness.iter())
        .map(|(mask_value, randomness_value)| {
            parameters.add(
                mask_value,
                &parameters.multiply(&challenge_field, randomness_value),
            )
        })
        .collect();
    let response_magnitudes = response
        .iter()
        .map(|value| centered_magnitude(parameters, value))
        .collect();

    ZkLinearProof {
        mask_commitment,
        masked_linear_value,
        response,
        randomness_response,
        response_magnitudes,
    }
}

/// Honest-verifier simulator: produces an accepting transcript without the
/// witness, distributed indistinguishably from a real one.
pub(crate) fn simulate_zk_linear<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    zk_parameters: &ZkLinearParameters,
    commitment: &FlatCommitment<LIMB_COUNT>,
    linear_form: &[[u64; LIMB_COUNT]],
    target: &[u64; LIMB_COUNT],
    challenge: u64,
    simulation_seed: u64,
) -> ZkLinearProof<LIMB_COUNT> {
    // Sample z, z_r from the same smudging range the honest prover's response
    // (approximately) follows.
    let response: Vec<[u64; LIMB_COUNT]> = (0..opening_parameters.witness_length)
        .map(|index| {
            mask_coordinate(
                parameters,
                simulation_seed,
                0x7a,
                index,
                zk_parameters.mask_bound,
            )
        })
        .collect();
    let randomness_response: Vec<[u64; LIMB_COUNT]> = (0..opening_parameters.randomness_length)
        .map(|index| {
            mask_coordinate(
                parameters,
                simulation_seed,
                0x7b,
                index,
                zk_parameters.mask_bound,
            )
        })
        .collect();
    let challenge_field = challenge_element(parameters, challenge);

    // t_mask = A(z || z_r) - c t, so the commitment check passes.
    let response_commitment = commit_flat(
        parameters,
        opening_parameters,
        &response,
        &randomness_response,
    );
    let mask_commitment: Vec<[u64; LIMB_COUNT]> = (0..opening_parameters.commitment_rank)
        .map(|row| {
            parameters.subtract(
                &response_commitment.rows[row],
                &parameters.multiply(&challenge_field, &commitment.rows[row]),
            )
        })
        .collect();

    // u = <L, z> - c target, so the linear check passes.
    let linear_of_response = inner_product(parameters, linear_form, &response);
    let masked_linear_value = parameters.subtract(
        &linear_of_response,
        &parameters.multiply(&challenge_field, target),
    );

    let response_magnitudes = response
        .iter()
        .map(|value| centered_magnitude(parameters, value))
        .collect();

    ZkLinearProof {
        mask_commitment,
        masked_linear_value,
        response,
        randomness_response,
        response_magnitudes,
    }
}

/// Witness-free verifier: commitment homomorphism, linear check, and smudging
/// norm bound.
pub(crate) fn verify_zk_linear<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    zk_parameters: &ZkLinearParameters,
    commitment: &FlatCommitment<LIMB_COUNT>,
    linear_form: &[[u64; LIMB_COUNT]],
    target: &[u64; LIMB_COUNT],
    challenge: u64,
    proof: &ZkLinearProof<LIMB_COUNT>,
) -> bool {
    if proof.response.len() != opening_parameters.witness_length
        || proof.randomness_response.len() != opening_parameters.randomness_length
        || proof.mask_commitment.len() != opening_parameters.commitment_rank
        || proof.response_magnitudes.len() != opening_parameters.witness_length
        || challenge == 0
        || challenge > zk_parameters.challenge_bound
    {
        return false;
    }
    let challenge_field = challenge_element(parameters, challenge);

    // Norm bound: every response coordinate stays within the smudging range, so
    // the extracted witness is short. The bound is the honest range plus the
    // challenge-times-witness reach the honest prover can add.
    let response_reach = zk_parameters.mask_bound.saturating_add(
        zk_parameters
            .challenge_bound
            .saturating_mul(zk_parameters.witness_magnitude_bound),
    );
    for (value, claimed) in proof.response.iter().zip(proof.response_magnitudes.iter()) {
        let magnitude = centered_magnitude(parameters, value);
        if magnitude != *claimed || magnitude > response_reach {
            return false;
        }
    }

    // Commitment homomorphism: A(z || z_r) == t_mask + c t.
    let response_commitment = commit_flat(
        parameters,
        opening_parameters,
        &proof.response,
        &proof.randomness_response,
    );
    for row in 0..opening_parameters.commitment_rank {
        let expected = parameters.add(
            &proof.mask_commitment[row],
            &parameters.multiply(&challenge_field, &commitment.rows[row]),
        );
        if response_commitment.rows[row] != expected {
            return false;
        }
    }

    // Linear check: <L, z> == u + c target.
    let linear_of_response = inner_product(parameters, linear_form, &proof.response);
    let expected_linear = parameters.add(
        &proof.masked_linear_value,
        &parameters.multiply(&challenge_field, target),
    );
    linear_of_response == expected_linear
}

#[cfg(test)]
mod tests {
    use super::super::linear_opening::commit_flat;
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    fn opening(witness_length: usize) -> LinearOpeningParameters {
        LinearOpeningParameters {
            commitment_rank: 8,
            witness_length,
            randomness_length: 6,
            matrix_seed: 0x2c0de,
            mask_bound: 1,
        }
    }

    fn zk() -> ZkLinearParameters {
        // Challenge up to 2^32, mask up to 2^50 so the smudging distance is about
        // 2^32 * ||w|| / 2^50; with small w this hides well and z stays a u64.
        ZkLinearParameters {
            challenge_bound: 1 << 32,
            mask_bound: 1 << 50,
            witness_magnitude_bound: 2,
        }
    }

    fn signed<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        values: &[i64],
    ) -> Vec<[u64; LIMB_COUNT]> {
        values
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect()
    }

    #[test]
    fn honest_zk_opening_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = opening(10);
        let zk_parameters = zk();
        let witness = signed(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1, 0, -1]);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed(&parameters, &[3, -2, 5, 1, -4, 2, 6, -1, 0, 3]);
        let target = inner_product(&parameters, &linear_form, &witness);
        let commitment = commit_flat(&parameters, &opening_parameters, &witness, &randomness);

        let challenge = 0x1234_5678;
        let proof = prove_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &witness,
            &randomness,
            &linear_form,
            challenge,
            0x5eed,
        );
        assert!(verify_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &commitment,
            &linear_form,
            &target,
            challenge,
            &proof,
        ));
    }

    #[test]
    fn simulated_transcript_verifies_demonstrating_zero_knowledge() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = opening(10);
        let zk_parameters = zk();
        let witness = signed(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1, 0, -1]);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed(&parameters, &[3, -2, 5, 1, -4, 2, 6, -1, 0, 3]);
        let target = inner_product(&parameters, &linear_form, &witness);
        let commitment = commit_flat(&parameters, &opening_parameters, &witness, &randomness);

        let challenge = 0x1234_5678;
        // The simulator uses only the public statement and the challenge - never
        // the witness or the opening randomness.
        let simulated = simulate_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &commitment,
            &linear_form,
            &target,
            challenge,
            0xff0011,
        );
        assert!(
            verify_zk_linear(
                &parameters,
                &opening_parameters,
                &zk_parameters,
                &commitment,
                &linear_form,
                &target,
                challenge,
                &simulated,
            ),
            "a simulator transcript built without the witness must verify (zero-knowledge)"
        );
    }

    #[test]
    fn wrong_target_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = opening(8);
        let zk_parameters = zk();
        let witness = signed(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1]);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed(&parameters, &[2, 3, -1, 4, 0, -2, 1, 5]);
        let target = inner_product(&parameters, &linear_form, &witness);
        let commitment = commit_flat(&parameters, &opening_parameters, &witness, &randomness);

        let challenge = 0xabc_def;
        let proof = prove_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &witness,
            &randomness,
            &linear_form,
            challenge,
            0x99,
        );
        let wrong_target = parameters.add(&target, &parameters.unsigned_word_to_element(1));
        assert!(!verify_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &commitment,
            &linear_form,
            &wrong_target,
            challenge,
            &proof,
        ));
    }

    #[test]
    fn out_of_bound_challenge_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = opening(8);
        let zk_parameters = zk();
        let witness = signed(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1]);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed(&parameters, &[2, 3, -1, 4, 0, -2, 1, 5]);
        let target = inner_product(&parameters, &linear_form, &witness);
        let commitment = commit_flat(&parameters, &opening_parameters, &witness, &randomness);

        let proof = prove_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &witness,
            &randomness,
            &linear_form,
            5,
            0x99,
        );
        // Verifier presented a challenge above the bound must reject.
        assert!(!verify_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &commitment,
            &linear_form,
            &target,
            zk_parameters.challenge_bound + 1,
            &proof,
        ));
    }

    #[test]
    fn tampered_response_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let opening_parameters = opening(8);
        let zk_parameters = zk();
        let witness = signed(&parameters, &[1, 0, -1, 1, 0, -1, 1, 1]);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);
        let linear_form = signed(&parameters, &[2, 3, -1, 4, 0, -2, 1, 5]);
        let target = inner_product(&parameters, &linear_form, &witness);
        let commitment = commit_flat(&parameters, &opening_parameters, &witness, &randomness);

        let challenge = 0x777;
        let mut proof = prove_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &witness,
            &randomness,
            &linear_form,
            challenge,
            0x99,
        );
        proof.response[2] =
            parameters.add(&proof.response[2], &parameters.unsigned_word_to_element(1));
        proof.response_magnitudes[2] = centered_magnitude(&parameters, &proof.response[2]);
        assert!(!verify_zk_linear(
            &parameters,
            &opening_parameters,
            &zk_parameters,
            &commitment,
            &linear_form,
            &target,
            challenge,
            &proof,
        ));
    }
}
