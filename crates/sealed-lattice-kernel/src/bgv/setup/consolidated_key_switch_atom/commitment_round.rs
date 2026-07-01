//! Ajtai commitment round over the spike commitment ring, for prover-cost
//! measurement of the consolidated-atom path.
//!
//! Encoded witness digits are packed into ring elements over
//! Z_q[X]/(X^d + 1) and committed as t[row] = sum_k A[row][k] * m_k +
//! sum_v B[row][v] * r_v in the NTT domain. The module rank, randomness
//! width, and ring dimension here are measurement-scale placeholders for
//! throughput and working-set shape, not a security parameter selection,
//! and the matrix expansion uses a non-cryptographic mixer so the timing
//! reflects arithmetic rather than hash throughput (a production expander
//! would be a seeded XOF).

use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::ProofFieldParameters;

pub(crate) const COMMITMENT_RING_MODULUS: u64 = 2_305_843_009_214_414_849;
pub(crate) const COMMITMENT_RING_PRIMITIVE_65536TH_ROOT: u64 = 1_324_459_744_473_789_483;

pub(crate) struct CommitmentRoundConfiguration {
    pub(crate) module_rank: usize,
    pub(crate) randomness_width: usize,
    pub(crate) ring_dimension: usize,
}

pub(crate) fn measurement_scale_configuration() -> CommitmentRoundConfiguration {
    CommitmentRoundConfiguration {
        module_rank: 8,
        randomness_width: 8,
        ring_dimension: 2048,
    }
}

/// One committed value: module_rank ring elements in the NTT domain.
pub(crate) type CommitmentValue = Vec<Vec<[u64; 1]>>;

/// Commits one digit message under a seeded public matrix. The digits are
/// chunked into ring elements; matrix rows are expanded on demand and never
/// retained, matching a streaming prover.
pub(crate) fn commit_digit_message(
    parameters: &ProofFieldParameters<1>,
    domain: &NegacyclicDomain<'_, 1>,
    configuration: &CommitmentRoundConfiguration,
    matrix_seed: u64,
    polynomial_index: usize,
    digits: &[i32],
) -> CommitmentValue {
    let ring_dimension = configuration.ring_dimension;
    let mut accumulators = vec![vec![parameters.zero(); ring_dimension]; configuration.module_rank];

    for (chunk_index, chunk) in digits.chunks(ring_dimension).enumerate() {
        let mut message = Vec::with_capacity(ring_dimension);
        for digit in chunk {
            message.push(parameters.signed_word_to_element(i64::from(*digit)));
        }
        message.resize(ring_dimension, parameters.zero());
        domain.forward_in_place(&mut message);
        for (row_index, accumulator) in accumulators.iter_mut().enumerate() {
            accumulate_expanded_row_product(
                parameters,
                accumulator,
                &message,
                matrix_seed,
                [
                    0x41,
                    polynomial_index as u64,
                    row_index as u64,
                    chunk_index as u64,
                ],
            );
        }
    }

    for randomness_index in 0..configuration.randomness_width {
        let mut randomness = Vec::with_capacity(ring_dimension);
        for coefficient_index in 0..ring_dimension {
            let mixed = mix(
                matrix_seed ^ 0x72,
                [
                    polynomial_index as u64,
                    randomness_index as u64,
                    coefficient_index as u64,
                ],
            );
            randomness.push(parameters.signed_word_to_element((mixed % 3) as i64 - 1));
        }
        domain.forward_in_place(&mut randomness);
        for (row_index, accumulator) in accumulators.iter_mut().enumerate() {
            accumulate_expanded_row_product(
                parameters,
                accumulator,
                &randomness,
                matrix_seed,
                [
                    0x42,
                    polynomial_index as u64,
                    row_index as u64,
                    randomness_index as u64,
                ],
            );
        }
    }

    accumulators
}

fn accumulate_expanded_row_product(
    parameters: &ProofFieldParameters<1>,
    accumulator: &mut [[u64; 1]],
    operand: &[[u64; 1]],
    matrix_seed: u64,
    labels: [u64; 4],
) {
    for (coefficient_index, (accumulated, operand_value)) in
        accumulator.iter_mut().zip(operand.iter()).enumerate()
    {
        let expanded = mix(
            matrix_seed,
            [
                labels[0] ^ labels[1].rotate_left(17),
                labels[2],
                labels[3] ^ (coefficient_index as u64).rotate_left(31),
            ],
        ) % COMMITMENT_RING_MODULUS;
        // Sampled directly in the NTT domain; the modulo bias is negligible
        // for throughput measurement and irrelevant to security here.
        let row_element = parameters.unsigned_word_to_element(expanded);
        *accumulated = parameters.add(
            accumulated,
            &parameters.multiply(operand_value, &row_element),
        );
    }
}

fn mix(seed: u64, values: [u64; 3]) -> u64 {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    for value in values {
        state ^= value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        state ^= state >> 27;
        state = state.wrapping_mul(0x94d0_49bb_1331_11eb);
        state ^= state >> 31;
    }
    state
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::single_limb_field_parameters;
    use super::*;

    fn test_configuration() -> CommitmentRoundConfiguration {
        CommitmentRoundConfiguration {
            module_rank: 2,
            randomness_width: 0,
            ring_dimension: 64,
        }
    }

    #[test]
    fn commitment_is_deterministic_and_message_sensitive() {
        let parameters = single_limb_field_parameters(
            COMMITMENT_RING_MODULUS,
            COMMITMENT_RING_PRIMITIVE_65536TH_ROOT,
        );
        let domain = NegacyclicDomain::new(&parameters, 64).expect("domain builds");
        let configuration = test_configuration();
        let digits = (0..256)
            .map(|index| ((index * 7) % 11) - 5)
            .collect::<Vec<_>>();
        let first = commit_digit_message(&parameters, &domain, &configuration, 99, 0, &digits);
        let second = commit_digit_message(&parameters, &domain, &configuration, 99, 0, &digits);
        assert_eq!(first, second);
        let mut tampered = digits.clone();
        tampered[100] += 1;
        let third = commit_digit_message(&parameters, &domain, &configuration, 99, 0, &tampered);
        assert_ne!(first, third);
    }

    #[test]
    fn commitment_is_linear_in_the_message_without_randomness() {
        let parameters = single_limb_field_parameters(
            COMMITMENT_RING_MODULUS,
            COMMITMENT_RING_PRIMITIVE_65536TH_ROOT,
        );
        let domain = NegacyclicDomain::new(&parameters, 64).expect("domain builds");
        let configuration = test_configuration();
        let left = (0..256).map(|index| (index % 5) - 2).collect::<Vec<_>>();
        let right = (0..256).map(|index| (index % 3) - 1).collect::<Vec<_>>();
        let sum = left
            .iter()
            .zip(right.iter())
            .map(|(a, b)| a + b)
            .collect::<Vec<_>>();
        let commit_left = commit_digit_message(&parameters, &domain, &configuration, 7, 3, &left);
        let commit_right = commit_digit_message(&parameters, &domain, &configuration, 7, 3, &right);
        let commit_sum = commit_digit_message(&parameters, &domain, &configuration, 7, 3, &sum);
        for row_index in 0..configuration.module_rank {
            for coefficient_index in 0..configuration.ring_dimension {
                let added = parameters.add(
                    &commit_left[row_index][coefficient_index],
                    &commit_right[row_index][coefficient_index],
                );
                assert_eq!(added, commit_sum[row_index][coefficient_index]);
            }
        }
    }
}
