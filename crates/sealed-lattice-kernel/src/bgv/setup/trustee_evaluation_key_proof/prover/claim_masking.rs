#[cfg(test)]
use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::relation::LimbColumnLayout;
#[cfg(test)]
use super::super::relation::TrusteeEvaluationKeyWitness;
#[cfg(test)]
use super::super::{CLAIM_MASK_DIGIT_COUNT, CLAIM_MASK_RADIX, column_mask_degree};
#[cfg(test)]
use super::CLAIM_MASK_DOMAIN;
#[cfg(test)]
use crate::bgv::evaluator::prg::DeterministicSampler;
#[cfg(test)]
use crate::bgv::modular_arithmetic::{add_mod_fast, sub_mod_fast};
#[cfg(test)]
use num_bigint::BigInt;

#[cfg(test)]
pub(in super::super) fn claim_mask_digits(
    proof_randomness_seed_hex: &str,
    global_claim_id: u64,
    mask_digit_count: usize,
) -> Vec<u8> {
    let mut sampler = DeterministicSampler::new(
        CLAIM_MASK_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            &global_claim_id.to_le_bytes(),
        ],
    );
    sampler
        .uniform_residues(CLAIM_MASK_RADIX, mask_digit_count)
        .into_iter()
        .map(|digit| u8::try_from(digit).expect("claim mask digit fits u8"))
        .collect()
}

#[cfg(test)]
pub(super) fn mask_digit_columns(
    layout: &LimbColumnLayout,
    proof_randomness_seed_hex: &str,
) -> Vec<Vec<u64>> {
    let mut columns = vec![vec![0_u64; layout.ring_degree]; layout.mask_column_count];
    for local_claim in 0..layout.claim_count() {
        let digits = claim_mask_digits(
            proof_randomness_seed_hex,
            local_claim as u64,
            layout.claim_mask_digit_count(local_claim),
        );
        for (digit_index, digit) in digits.iter().enumerate() {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            columns[column][half * layout.trace_size + half_position] = u64::from(*digit);
        }
    }
    columns
}

#[cfg(test)]
pub(super) fn masked_half_coefficients(
    plan: &EvaluationDomainPlan,
    half_values: &[u64],
    mask_sampler: &mut DeterministicSampler,
) -> Vec<u64> {
    masked_half_coefficients_with_mask_degree(
        plan,
        half_values,
        column_mask_degree(plan.trace_size),
        mask_sampler,
    )
}

#[cfg(test)]
pub(super) fn masked_half_coefficients_with_mask_degree(
    plan: &EvaluationDomainPlan,
    half_values: &[u64],
    mask_degree: usize,
    mask_sampler: &mut DeterministicSampler,
) -> Vec<u64> {
    let trace_size = plan.trace_size;
    let mut coefficients = plan.coefficients_from_trace_values(half_values);
    coefficients.resize(trace_size + mask_degree, 0);
    let mask = mask_sampler.uniform_residues(plan.modulus, mask_degree);
    for (index, mask_value) in mask.iter().enumerate() {
        coefficients[index] = sub_mod_fast(coefficients[index], *mask_value, plan.modulus);
        coefficients[trace_size + index] =
            add_mod_fast(coefficients[trace_size + index], *mask_value, plan.modulus);
    }
    coefficients
}

#[cfg(test)]
pub(super) fn global_claim_integers(
    witness: &TrusteeEvaluationKeyWitness,
    consistency_vectors: &[Vec<u64>],
    proof_randomness_seed_hex: &str,
) -> Vec<BigInt> {
    // The carry is the only integer witness shared by all commitment fields.
    // Independent commitment-limb opening tapes are proved against their
    // ternary supports under purposes eleven and twelve and bound to their own
    // field relation locally; equating their masked claims across fields would
    // reintroduce the shared-opening construction.
    let signed_vectors = vec![witness.private_vss_carry_witnesses()];
    let mut integers = Vec::with_capacity(signed_vectors.len() * consistency_vectors.len());
    for signed_vector in signed_vectors {
        for consistency_vector in consistency_vectors {
            assert_eq!(
                signed_vector.len(),
                consistency_vector.len(),
                "global claim vector length matches the consistency challenge vector"
            );
            let global_id = integers.len() as u64;
            let clear_sum = signed_vector
                .iter()
                .zip(consistency_vector)
                .map(|(coefficient, combination)| {
                    i128::from(*coefficient) * i128::from(*combination)
                })
                .sum::<i128>();
            let digits =
                claim_mask_digits(proof_randomness_seed_hex, global_id, CLAIM_MASK_DIGIT_COUNT);
            let mut mask_integer = BigInt::from(0_u8);
            let mut digit_weight = BigInt::from(1_u8);
            for digit in digits {
                mask_integer += BigInt::from(digit) * &digit_weight;
                digit_weight *= CLAIM_MASK_RADIX;
            }
            integers.push(BigInt::from(clear_sum) + mask_integer);
        }
    }
    integers
}
