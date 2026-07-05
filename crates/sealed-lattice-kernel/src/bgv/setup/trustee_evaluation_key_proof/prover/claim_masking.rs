use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::relation::{
    LimbColumnLayout, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
    claim_mask_digit_count_for_global_claim,
};
use super::super::*;
use super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;
use num_bigint::BigInt;

// Global mask digits for one claim, identical across every limb where the claim
// appears, so the masked claims stay comparable as centered integers.
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

// Global claim identity for the cross-limb comparison and the shared mask:
// the secret claims come first, then every key's error claims in (key, digit)
// order over the whole statement, with repetitions innermost.
pub(in super::super) fn global_claim_id(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    local_claim_index: usize,
) -> u64 {
    let repetition = local_claim_index % layout.consistency_repetitions;
    let vector_index = local_claim_index / layout.consistency_repetitions;
    if layout.target_decryption_active() {
        let local_message_digit_vectors = layout.target_decryption_message_columns
            * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
        debug_assert!(vector_index < local_message_digit_vectors);
        let local_message_index =
            vector_index / crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
        let digit_index =
            vector_index % crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
        let global_message_index = statement
            .target_decryption_message_global_index(layout.limb_index, local_message_index)
            .expect("target-decryption message column is in the layout");
        let global_vector_index = global_message_index
            * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT
            + digit_index;

        return (global_vector_index * layout.consistency_repetitions + repetition) as u64;
    }
    if layout.private_vss_active() || layout.vss_public_active() {
        debug_assert!(
            statement.private_vss_share.is_some() || statement.vss_share_linkage.is_some()
        );
        return (vector_index * layout.consistency_repetitions + repetition) as u64;
    }
    if layout.same_secret_bridge_active() {
        return (vector_index * layout.consistency_repetitions + repetition) as u64;
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
            return ((1 + global_error_position) * layout.consistency_repetitions + repetition)
                as u64;
        }
        remaining -= digit_count;
    }
    // Linkage vectors: the negative indicator, optional bridge message
    // digits, then the opening-randomness columns, indexed after every
    // statement-global error vector.
    let total_error_vectors: usize = statement
        .keys
        .iter()
        .map(|key| key.digit_count())
        .sum::<usize>();
    let linkage_position = remaining;
    if let Some(bridge) = &statement.same_secret_bridge {
        let bridge_digit_vector_count = bridge.target_rns_primes.len()
            * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
        debug_assert!(
            linkage_position < 1 + bridge_digit_vector_count + layout.linkage_randomness_columns
        );
    } else {
        debug_assert!(linkage_position < 1 + layout.linkage_randomness_columns);
    }
    ((1 + total_error_vectors + linkage_position) * layout.consistency_repetitions + repetition)
        as u64
}

// The base-3 mask digit columns for one limb, as logical length-N vectors.
pub(super) fn mask_digit_columns(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    proof_randomness_seed_hex: &str,
) -> Vec<Vec<u64>> {
    let mut columns = vec![vec![0_u64; layout.ring_degree]; layout.mask_column_count];
    for local_claim in 0..layout.claim_count() {
        let digits = claim_mask_digits(
            proof_randomness_seed_hex,
            global_claim_id(statement, layout, local_claim),
            layout.claim_mask_digit_count(local_claim),
        );
        for (digit_index, digit) in digits.iter().enumerate() {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            columns[column][half * layout.trace_size + half_position] = u64::from(*digit);
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

fn vss_public_recipient_share_messages_by_item_for_claims(
    witness: &TrusteeEvaluationKeyWitness,
) -> Vec<&[i64]> {
    if witness
        .vss_public_recipient_share_messages_by_item
        .is_empty()
    {
        vec![&witness.vss_public_recipient_share_messages]
    } else {
        witness
            .vss_public_recipient_share_messages_by_item
            .iter()
            .map(Vec::as_slice)
            .collect()
    }
}

fn vss_public_carry_witnesses_by_item_for_claims(
    witness: &TrusteeEvaluationKeyWitness,
) -> Vec<&[i64]> {
    if witness.vss_public_carry_witnesses_by_item.is_empty() {
        vec![&witness.vss_public_carry_witnesses]
    } else {
        witness
            .vss_public_carry_witnesses_by_item
            .iter()
            .map(Vec::as_slice)
            .collect()
    }
}

fn append_vss_public_digit_vectors(digit_vectors: &mut Vec<Vec<i64>>, message_vector: &[i64]) {
    let mut vectors = (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT)
        .map(|_| Vec::with_capacity(message_vector.len()))
        .collect::<Vec<_>>();
    for coefficient in message_vector {
        let unsigned_coefficient = u64::try_from(*coefficient)
            .expect("VSS message coefficient is non-negative after validation");
        let digits =
            crate::bgv::setup::vss_commitment::vss_public_message_digits(unsigned_coefficient)
                .expect("VSS message coefficient fits the digit layout");
        for (digit_index, digit) in digits.iter().enumerate() {
            vectors[digit_index].push(i64::try_from(*digit).expect("VSS message digit fits i64"));
        }
    }
    digit_vectors.extend(vectors);
}

// The shared global claim integers: for every statement-global witness
// vector and consistency repetition, the clear integer combination of the
// signed witness plus the shared smudging mask. Every limb publishes the
// residues of these integers, so the cross-limb binding is integer equality
// recovered by lifting from the statement-selected proof fields.
pub(super) fn global_claim_integers(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    consistency_vectors: &[Vec<u64>],
    proof_randomness_seed_hex: &str,
) -> Vec<BigInt> {
    let mut owned_vss_public_claim_vectors: Vec<Vec<i64>> = Vec::new();
    let mut signed_vectors: Vec<&[i64]> = Vec::new();
    if statement.private_vss_share.is_some() {
        // The message (Shamir coefficient) columns carry no consistency claim:
        // their cross-field consistency is argued globally by carry consistency,
        // the public range-checked share, and enough honest recipient checks.
        // Masking them would only add zero-knowledge leakage with no soundness
        // gain. Only the carry and the opening-randomness columns are claimed.
        // This order must match consistency_vector_count and the consistency
        // loop in relation.rs ([carry, opening-randomness...]).
        signed_vectors.push(&witness.private_vss_carry_witnesses);
        for randomness_columns in &witness.private_vss_opening_randomness_by_shamir_index {
            for column in randomness_columns {
                signed_vectors.push(column);
            }
        }
    } else if let Some(vss_share_linkage) = &statement.vss_share_linkage {
        // Share-linkage claims each lifted-carry vector followed by
        // every message digit vector. Opening randomness stays
        // committed, ternary row-checked, and consumed by the opening lincheck,
        // but it does not carry a separate cross-field integer-equality claim.
        // This order must match consistency_vector_count and the share-linkage
        // branch of batched_sumcheck_value ([carries..., message_digits...]).
        let base_ring_degree = statement.ring_degree;
        let item_count = vss_share_linkage.item_count();
        let coefficient_slot_indices_by_item =
            vss_share_linkage.coefficient_witness_slot_indices_by_item();
        let recipient_messages_by_item =
            vss_public_recipient_share_messages_by_item_for_claims(witness);
        let carry_witnesses_by_item = vss_public_carry_witnesses_by_item_for_claims(witness);
        assert_eq!(
            coefficient_slot_indices_by_item.len(),
            item_count,
            "VSS coefficient slot layout matches the item count"
        );
        assert_eq!(
            recipient_messages_by_item.len(),
            item_count,
            "VSS recipient message witness count matches the item count"
        );
        assert_eq!(
            carry_witnesses_by_item.len(),
            item_count,
            "VSS carry witness count matches the item count"
        );
        let validate_vss_public_vector = |source: &[i64]| {
            assert_eq!(
                source.len(),
                base_ring_degree,
                "VSS witness vector length matches the base ring degree"
            );
        };

        for carry_witnesses in &carry_witnesses_by_item {
            validate_vss_public_vector(carry_witnesses);
            owned_vss_public_claim_vectors.push((*carry_witnesses).to_vec());
        }

        for coefficient_slot_index in 0..vss_share_linkage.unique_coefficient_witness_slot_count() {
            let coefficient_messages =
                &witness.vss_public_coefficient_messages_by_shamir_index[coefficient_slot_index];
            validate_vss_public_vector(coefficient_messages);
            append_vss_public_digit_vectors(
                &mut owned_vss_public_claim_vectors,
                coefficient_messages,
            );
        }

        for recipient_messages in &recipient_messages_by_item {
            validate_vss_public_vector(recipient_messages);
            append_vss_public_digit_vectors(
                &mut owned_vss_public_claim_vectors,
                recipient_messages,
            );
        }

        for claim_vector in &owned_vss_public_claim_vectors {
            signed_vectors.push(claim_vector);
        }
    } else if statement.target_decryption_share.is_some() {
        // Target-decryption masked consistency claims bind direct message
        // digits. Opening randomness stays committed, ternary row-checked, and
        // consumed by the opening equations on setup commitment fields.
        for message_vector in &witness.target_decryption_message_vectors {
            append_vss_public_digit_vectors(&mut owned_vss_public_claim_vectors, message_vector);
        }
        for claim_vector in &owned_vss_public_claim_vectors {
            signed_vectors.push(claim_vector);
        }
    } else {
        signed_vectors.push(&witness.secret_coefficients);
        for error_vectors in &witness.error_coefficients_by_key {
            for error_vector in error_vectors {
                signed_vectors.push(error_vector);
            }
        }
        if statement.same_secret_linkage.is_some() || statement.same_secret_bridge.is_some() {
            signed_vectors.push(&witness.negative_indicator_coefficients);
            if let Some(bridge) = &statement.same_secret_bridge {
                for target_rns_prime in &bridge.target_rns_primes {
                    let target_messages = witness
                        .secret_coefficients
                        .iter()
                        .zip(witness.negative_indicator_coefficients.iter())
                        .map(|(secret_coefficient, negative_indicator)| {
                            let target_message = i128::from(*secret_coefficient)
                                + i128::from(*target_rns_prime) * i128::from(*negative_indicator);
                            let unsigned_target_message = u64::try_from(target_message).expect(
                                "same-secret bridge message is non-negative after validation",
                            );
                            i64::try_from(unsigned_target_message)
                                .expect("same-secret bridge message fits i64")
                        })
                        .collect::<Vec<_>>();
                    append_vss_public_digit_vectors(
                        &mut owned_vss_public_claim_vectors,
                        &target_messages,
                    );
                }
                for digit_vector in &owned_vss_public_claim_vectors {
                    signed_vectors.push(digit_vector);
                }
            }
            for randomness_columns in &witness.opening_randomness_by_limb {
                for column in randomness_columns {
                    signed_vectors.push(column);
                }
            }
        }
    }
    let mut integers = Vec::with_capacity(signed_vectors.len() * consistency_vectors.len());
    for signed_vector in &signed_vectors {
        for consistency_vector in consistency_vectors {
            assert_eq!(
                signed_vector.len(),
                consistency_vector.len(),
                "global claim vector length matches the consistency challenge vector"
            );
            let global_id = integers.len() as u64;
            let mut clear_sum = 0_i128;
            for (coefficient, combination) in signed_vector.iter().zip(consistency_vector.iter()) {
                clear_sum += i128::from(*coefficient) * i128::from(*combination);
            }
            let digits = claim_mask_digits(
                proof_randomness_seed_hex,
                global_id,
                claim_mask_digit_count_for_global_claim(statement, global_id),
            );
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
