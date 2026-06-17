use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::relation::{
    LimbColumnLayout, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
};
use super::super::*;
use super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;

// Global mask bits for one claim, identical across every limb where the claim
// appears, so the masked claims stay comparable as centered integers.
pub(in super::super) fn claim_mask_bits(
    proof_randomness_seed_hex: &str,
    global_claim_id: u64,
) -> Vec<u8> {
    let mut sampler = DeterministicSampler::new(
        CLAIM_MASK_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            &global_claim_id.to_le_bytes(),
        ],
    );
    let raw = sampler.bytes(CLAIM_MASK_DIGIT_COUNT);

    raw.into_iter().map(|byte| byte & 1).collect()
}

// Global claim identity for the cross-limb comparison and the shared mask:
// the secret claims come first, then every key's error claims in (key, digit)
// order over the whole statement, with repetitions innermost.
pub(in super::super) fn global_claim_id(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    local_claim_index: usize,
) -> u64 {
    let repetition = local_claim_index % CONSISTENCY_REPETITIONS;
    let vector_index = local_claim_index / CONSISTENCY_REPETITIONS;
    if layout.private_vss_active() {
        debug_assert!(statement.private_vss_share.is_some());
        return (vector_index * CONSISTENCY_REPETITIONS + repetition) as u64;
    }
    if vector_index == 0 {
        return repetition as u64;
    }
    // Map the local error position back to (key, digit) and then to the
    // statement-global error position.
    let mut remaining = vector_index - 1;
    for (key_index, digit_count) in &layout.active_keys {
        if remaining < *digit_count {
            let global_error_position: usize = statement.keys[..*key_index]
                .iter()
                .map(|key| key.digit_count())
                .sum::<usize>()
                + remaining;
            return ((1 + global_error_position) * CONSISTENCY_REPETITIONS + repetition) as u64;
        }
        remaining -= digit_count;
    }
    // Linkage vectors: the negative indicator, then the opening-randomness
    // columns, indexed after every statement-global error vector.
    let total_error_vectors: usize = statement
        .keys
        .iter()
        .map(|key| key.digit_count())
        .sum::<usize>();
    let linkage_position = remaining;
    debug_assert!(linkage_position < 1 + layout.linkage_randomness_columns);
    ((1 + total_error_vectors + linkage_position) * CONSISTENCY_REPETITIONS + repetition) as u64
}

// The binary mask digit columns for one limb, as logical length-N vectors.
pub(super) fn mask_digit_columns(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    proof_randomness_seed_hex: &str,
) -> Vec<Vec<u64>> {
    let mut columns = vec![vec![0_u64; layout.ring_degree]; layout.mask_column_count];
    for local_claim in 0..layout.claim_count() {
        let bits = claim_mask_bits(
            proof_randomness_seed_hex,
            global_claim_id(statement, layout, local_claim),
        );
        for (digit_index, bit) in bits.iter().enumerate() {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            columns[column][half * layout.trace_size + half_position] = u64::from(*bit);
        }
    }

    columns
}

// Mask one half-column: interpolate the half over the trace domain, then add
// Z_H times a fresh random polynomial so every off-trace evaluation is
// uniform while the trace values are unchanged.
pub(super) fn masked_half_coefficients(
    plan: &EvaluationDomainPlan,
    half_values: &[u64],
    mask_sampler: &mut DeterministicSampler,
) -> Vec<u64> {
    let trace_size = plan.trace_size;
    let mask_degree = column_mask_degree(trace_size);
    let mut coefficients = plan.coefficients_from_trace_values(half_values);
    coefficients.resize(trace_size + mask_degree, 0);
    let mask = mask_sampler.uniform_residues(plan.modulus, mask_degree);
    // coeffs - r at [0,deg) and + r at [T, T+deg) equals coeffs + (X^T - 1)*r =
    // coeffs + Z_H*r: off-trace evaluations are randomized while trace values
    // are unchanged (the ZK simulator relies on this).
    for (index, mask_value) in mask.iter().enumerate() {
        // Z_H * r = (X^T - 1) * r: subtract at the low positions, add at T+.
        coefficients[index] = sub_mod_fast(coefficients[index], *mask_value, plan.modulus);
        coefficients[trace_size + index] =
            add_mod_fast(coefficients[trace_size + index], *mask_value, plan.modulus);
    }

    coefficients
}

// The shared global claim integers: for every statement-global witness
// vector and consistency repetition, the clear integer combination of the
// signed witness plus the shared smudging mask. Every limb publishes the
// residues of these integers, so the cross-limb binding is integer equality
// recovered by lifting from two limb fields.
pub(super) fn global_claim_integers(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    consistency_vectors: &[Vec<u64>],
    proof_randomness_seed_hex: &str,
) -> Vec<i128> {
    let mut signed_vectors: Vec<&[i64]> = Vec::new();
    if statement.private_vss_share.is_some() {
        // The message (Shamir coefficient) columns carry no consistency claim:
        // they are pinned across the commitment fields by the opening rows plus
        // the opening-randomness consistency, so masking them would only add
        // zero-knowledge leakage with no soundness gain. Only the carry and the
        // opening-randomness columns are claimed. This order must match
        // consistency_vector_count and the consistency loop in relation.rs
        // ([carry, opening-randomness...]).
        signed_vectors.push(&witness.private_vss_carry_witnesses);
        for randomness_columns in &witness.private_vss_opening_randomness_by_shamir_index {
            for column in randomness_columns {
                signed_vectors.push(column);
            }
        }
    } else {
        signed_vectors.push(&witness.secret_coefficients);
        for error_vectors in &witness.error_coefficients_by_key {
            for error_vector in error_vectors {
                signed_vectors.push(error_vector);
            }
        }
        if statement.same_secret_linkage.is_some() {
            signed_vectors.push(&witness.negative_indicator_coefficients);
            for randomness_columns in &witness.opening_randomness_by_limb {
                for column in randomness_columns {
                    signed_vectors.push(column);
                }
            }
        }
    }
    let mut integers = Vec::with_capacity(signed_vectors.len() * CONSISTENCY_REPETITIONS);
    for signed_vector in &signed_vectors {
        for consistency_vector in consistency_vectors {
            let global_id = integers.len() as u64;
            let mut clear_sum = 0_i128;
            for (coefficient, combination) in signed_vector.iter().zip(consistency_vector.iter()) {
                clear_sum += i128::from(*coefficient) * i128::from(*combination);
            }
            let bits = claim_mask_bits(proof_randomness_seed_hex, global_id);
            let mut mask_integer = 0_i128;
            for (digit_index, bit) in bits.iter().enumerate() {
                if *bit == 1 {
                    mask_integer += 1_i128 << digit_index;
                }
            }
            integers.push(clear_sum + mask_integer);
        }
    }

    integers
}
