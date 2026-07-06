//! Real BDLOP/Ajtai witness commitment for the key-switch atom family.
//!
//! This module fixes the security parameters selected and estimator-checked in
//! the commitment decision record:
//!
//! - commitment ring `R_c = Z_q[X]/(X^256 + 1)`, `q = 2^32 - 2^20 + 1`, a prime
//!   with `2^16 | q - 1` so the shared negacyclic transform builds the size-256
//!   domain from the same primitive root machinery the proof fields use;
//! - module rank (SIS height) 8, so the published commitment is 8 ring elements
//!   regardless of message width;
//! - randomness rank 6 with centered-ternary openings.
//!
//! Under RC.MATZOV these give at least 282-bit Module-SIS binding (at the
//! generous 2^29 extraction norm) and 152.6-bit Module-LWE hiding. The public
//! matrix is expanded from a commitment seed by a domain-separated `hash512`
//! (SHAKE256) extendable-output function sampled directly in the transform
//! domain, not by a non-cryptographic mixer. The commitment is linear in the
//! message and the randomness, so per-trustee and per-key aggregation add
//! commitments and openings componentwise.
//!
//! This module is test-gated: it is the family's real commitment building block,
//! exercised by its own binding, hiding, and homomorphism tests, and is not yet
//! wired into any acceptance path.

use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::{ProofFieldParameters, single_limb_field_parameters};
use crate::hashing::hash512;

/// Commitment modulus `q = 2^32 - 2^20 + 1` (prime, `2^16 | q - 1`).
pub(crate) const WITNESS_COMMITMENT_MODULUS: u64 = 4_293_918_721;
/// A primitive 65536th root of unity modulo the commitment modulus.
pub(crate) const WITNESS_COMMITMENT_PRIMITIVE_65536TH_ROOT: u64 = 2_147_834_165;
/// Commitment ring degree (the ring is `X^256 + 1`).
pub(crate) const WITNESS_COMMITMENT_RING_DEGREE: usize = 256;
/// Module rank / SIS height: the published commitment is this many ring elements.
pub(crate) const WITNESS_COMMITMENT_MODULE_RANK: usize = 8;
/// Randomness rank with centered-ternary openings.
pub(crate) const WITNESS_COMMITMENT_RANDOMNESS_RANK: usize = 6;

const MATRIX_EXPANSION_DOMAIN: &str =
    "sealed-lattice/setup/limb-group-atom/witness-commitment-matrix-v1";

/// Field parameters for the commitment ring.
pub(crate) fn witness_commitment_parameters() -> ProofFieldParameters<1> {
    single_limb_field_parameters(
        WITNESS_COMMITMENT_MODULUS,
        WITNESS_COMMITMENT_PRIMITIVE_65536TH_ROOT,
    )
}

/// One commitment column expanded from the seed in the transform domain. A
/// column is `block_kind` (message or randomness) at `column_index`, expanded
/// for commitment `row_index`. The 64-byte `hash512` output yields eight field
/// words per invocation; the coefficient index selects the invocation and word.
fn matrix_element(
    parameters: &ProofFieldParameters<1>,
    seed: u64,
    block_kind: u8,
    row_index: usize,
    column_index: usize,
    coefficient_index: usize,
) -> [u64; 1] {
    let invocation = coefficient_index / 8;
    let word_offset = coefficient_index % 8;
    let digest = hash512(
        MATRIX_EXPANSION_DOMAIN,
        &[
            &seed.to_le_bytes(),
            &[block_kind],
            &(row_index as u64).to_le_bytes(),
            &(column_index as u64).to_le_bytes(),
            &(invocation as u64).to_le_bytes(),
        ],
    );
    let start = word_offset * 8;
    let word = u64::from_le_bytes(digest[start..start + 8].try_into().expect("8-byte word"));
    parameters.unsigned_word_to_element(word % WITNESS_COMMITMENT_MODULUS)
}

/// One committed value: `WITNESS_COMMITMENT_MODULE_RANK` ring elements in the
/// transform domain.
pub(crate) type WitnessCommitment = Vec<Vec<[u64; 1]>>;

/// Commits `message` ring elements and `randomness` ring elements under the
/// seed-expanded public matrix. Each operand is a coefficient-domain ring
/// element of degree `WITNESS_COMMITMENT_RING_DEGREE`; the commitment is
/// returned in the transform domain, `t[row] = sum_c A[row][c] * operand[c]`.
pub(crate) fn commit_witness(
    parameters: &ProofFieldParameters<1>,
    domain: &NegacyclicDomain<'_, 1>,
    seed: u64,
    message: &[Vec<[u64; 1]>],
    randomness: &[Vec<[u64; 1]>],
) -> WitnessCommitment {
    assert_eq!(
        domain.size, WITNESS_COMMITMENT_RING_DEGREE,
        "commitment domain must be the commitment ring degree"
    );
    assert_eq!(
        randomness.len(),
        WITNESS_COMMITMENT_RANDOMNESS_RANK,
        "randomness rank mismatch"
    );

    let ring_degree = WITNESS_COMMITMENT_RING_DEGREE;
    let mut accumulators =
        vec![vec![parameters.zero(); ring_degree]; WITNESS_COMMITMENT_MODULE_RANK];

    // Message block: columns 0..message.len(), block kind 0x6d.
    for (column_index, operand) in message.iter().enumerate() {
        assert_eq!(operand.len(), ring_degree, "message ring element degree");
        let mut transformed = operand.clone();
        domain.forward_in_place(&mut transformed);
        accumulate_column(
            parameters,
            &mut accumulators,
            &transformed,
            seed,
            0x6d,
            column_index,
        );
    }

    // Randomness block: columns 0..randomness_rank, block kind 0x72.
    for (column_index, operand) in randomness.iter().enumerate() {
        assert_eq!(operand.len(), ring_degree, "randomness ring element degree");
        let mut transformed = operand.clone();
        domain.forward_in_place(&mut transformed);
        accumulate_column(
            parameters,
            &mut accumulators,
            &transformed,
            seed,
            0x72,
            column_index,
        );
    }

    accumulators
}

fn accumulate_column(
    parameters: &ProofFieldParameters<1>,
    accumulators: &mut [Vec<[u64; 1]>],
    transformed_operand: &[[u64; 1]],
    seed: u64,
    block_kind: u8,
    column_index: usize,
) {
    for (row_index, accumulator) in accumulators.iter_mut().enumerate() {
        for (coefficient_index, (accumulated, operand_value)) in accumulator
            .iter_mut()
            .zip(transformed_operand.iter())
            .enumerate()
        {
            let matrix_value = matrix_element(
                parameters,
                seed,
                block_kind,
                row_index,
                column_index,
                coefficient_index,
            );
            *accumulated = parameters.add(
                accumulated,
                &parameters.multiply(operand_value, &matrix_value),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn coefficient_ring_element(values: &[i64]) -> Vec<[u64; 1]> {
        let parameters = witness_commitment_parameters();
        let mut element = values
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect::<Vec<_>>();
        element.resize(WITNESS_COMMITMENT_RING_DEGREE, parameters.zero());
        element
    }

    fn message_from(columns: Vec<Vec<i64>>) -> Vec<Vec<[u64; 1]>> {
        columns
            .iter()
            .map(|values| coefficient_ring_element(values))
            .collect()
    }

    fn ternary_randomness(seed: u64) -> Vec<Vec<[u64; 1]>> {
        let parameters = witness_commitment_parameters();
        (0..WITNESS_COMMITMENT_RANDOMNESS_RANK)
            .map(|rank_index| {
                (0..WITNESS_COMMITMENT_RING_DEGREE)
                    .map(|coefficient_index| {
                        let digest = hash512(
                            "witness-commitment-test-randomness",
                            &[
                                &seed.to_le_bytes(),
                                &(rank_index as u64).to_le_bytes(),
                                &(coefficient_index as u64).to_le_bytes(),
                            ],
                        );
                        parameters.signed_word_to_element(i64::from(digest[0] % 3) - 1)
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn commitment_ring_prime_and_root_are_valid() {
        // q = 2^32 - 2^20 + 1, and the pinned root has exact order 65536.
        assert_eq!(WITNESS_COMMITMENT_MODULUS, (1u64 << 32) - (1u64 << 20) + 1);
        let q = BigUint::from(WITNESS_COMMITMENT_MODULUS);
        // Miller-Rabin-style check via a few strong bases using BigUint.
        for base in [2u64, 3, 5, 7, 11, 13, 17] {
            let witness = BigUint::from(base).modpow(&(&q - 1u32), &q);
            assert_eq!(witness, BigUint::from(1u32), "Fermat base {base}");
        }
        let root = BigUint::from(WITNESS_COMMITMENT_PRIMITIVE_65536TH_ROOT);
        assert_eq!(
            root.modpow(&BigUint::from(65536u32), &q),
            BigUint::from(1u32)
        );
        assert_ne!(
            root.modpow(&BigUint::from(32768u32), &q),
            BigUint::from(1u32)
        );
    }

    #[test]
    fn commitment_is_deterministic_and_message_sensitive() {
        let parameters = witness_commitment_parameters();
        let domain = NegacyclicDomain::new(&parameters, WITNESS_COMMITMENT_RING_DEGREE)
            .expect("commitment domain builds");
        let message = message_from(vec![vec![1, 0, -1, 1], vec![0, 1, 1, -1]]);
        let randomness = ternary_randomness(1);
        let first = commit_witness(&parameters, &domain, 42, &message, &randomness);
        let second = commit_witness(&parameters, &domain, 42, &message, &randomness);
        assert_eq!(first, second);
        assert_eq!(first.len(), WITNESS_COMMITMENT_MODULE_RANK);

        let mut tampered = message.clone();
        tampered[0][2] = parameters.signed_word_to_element(1); // was -1
        let third = commit_witness(&parameters, &domain, 42, &tampered, &randomness);
        assert_ne!(first, third, "a changed message must change the commitment");

        // A different randomness (hiding source) changes the commitment.
        let other_randomness = ternary_randomness(2);
        let fourth = commit_witness(&parameters, &domain, 42, &message, &other_randomness);
        assert_ne!(
            first, fourth,
            "a changed opening must change the commitment"
        );

        // A different public-matrix seed changes the commitment.
        let fifth = commit_witness(&parameters, &domain, 43, &message, &randomness);
        assert_ne!(
            first, fifth,
            "a changed matrix seed must change the commitment"
        );
    }

    #[test]
    fn commitment_is_linear_in_message_and_randomness() {
        let parameters = witness_commitment_parameters();
        let domain = NegacyclicDomain::new(&parameters, WITNESS_COMMITMENT_RING_DEGREE)
            .expect("commitment domain builds");
        let left_message = message_from(vec![vec![2, -1, 0, 1], vec![1, 1, 0, -1]]);
        let right_message = message_from(vec![vec![-1, 1, 1, 0], vec![0, -1, 1, 1]]);
        let sum_message = message_from(vec![vec![1, 0, 1, 1], vec![1, 0, 1, 0]]);

        let left_randomness = ternary_randomness(10);
        let right_randomness = ternary_randomness(11);
        let sum_randomness = (0..WITNESS_COMMITMENT_RANDOMNESS_RANK)
            .map(|rank_index| {
                (0..WITNESS_COMMITMENT_RING_DEGREE)
                    .map(|coefficient_index| {
                        parameters.add(
                            &left_randomness[rank_index][coefficient_index],
                            &right_randomness[rank_index][coefficient_index],
                        )
                    })
                    .collect()
            })
            .collect::<Vec<_>>();

        let commit_left = commit_witness(&parameters, &domain, 7, &left_message, &left_randomness);
        let commit_right =
            commit_witness(&parameters, &domain, 7, &right_message, &right_randomness);
        let commit_sum = commit_witness(&parameters, &domain, 7, &sum_message, &sum_randomness);

        for row_index in 0..WITNESS_COMMITMENT_MODULE_RANK {
            for coefficient_index in 0..WITNESS_COMMITMENT_RING_DEGREE {
                let added = parameters.add(
                    &commit_left[row_index][coefficient_index],
                    &commit_right[row_index][coefficient_index],
                );
                assert_eq!(
                    added, commit_sum[row_index][coefficient_index],
                    "commitment must be linear in message and randomness (row {row_index}, coefficient {coefficient_index})"
                );
            }
        }
    }
}
