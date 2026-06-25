use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(
        DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
        &[proof_bytes],
    )
}

// Binds the operative shape of the internal direct-ballot validity relation proof: statement
// version, encoding, challenge size and domain, proof-bytes domain, relation shape, ring
// degree, and data prime count.
//
// Scope, kept in prose rather than a bound field: this is an internal relation-shape proof.
// Its claim soundness and support zero-knowledge are not established. The weakest checked
// subrelation runs modulo the about 16-bit plaintext modulus 65537, so a single transcript
// yields only about 16 soundness bits against the 192-bit nominal challenge. See the README
// safety boundaries for the full scope statement.
pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_parameters_hash()
-> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "BallotValidityProofParameters",
        "statementVersion": 3,
        "proofEncoding": "binary relation transcript",
        "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
        "proofBytesDomain": DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
        "relation": "BGV all-limb encryption equations, score encoding, one-hot constraints, randomizer support, and error support",
        "sourceRingDegree": POLYNOMIAL_DEGREE,
        "dataPrimeCount": DATA_PRIMES.len(),
    }))
}

// Reports the operative and computed accounting for the internal relation proof. The honest
// weakness figure (weakestRelationEffectiveBitsPerCheck: the about 16 soundness bits per
// transcript on the weakest subrelation, against the 192-bit nominal challenge) is reported
// as a computed value. The scope it implies (claim soundness not established) lives in prose
// docs, not in a bound status field, and no speculative repeated-proof projection is emitted.
pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_accounting()
-> CanonicalResult<Value> {
    let support_check_count = direct_ballot_support_check_count();
    let support_union_loss_bits =
        ceil_log2_usize(support_check_count * direct_ballot_support_maximum_degree());
    let response_union_loss_bits = ceil_log2_usize(direct_ballot_relation_response_scalar_count());
    let zero_knowledge_shift_slack_bits =
        zero_knowledge_shift_slack_bits_after_response_union_bound(
            DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
            response_union_loss_bits,
        )?;
    let weakest_relation_bits_per_check = 16_u32;
    let support_modulus_bits = 64 - direct_ballot_support_modulus().leading_zeros();

    Ok(json!({
        "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "nominalChallengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "challengeCount": 1,
        "weakestCheckedRelation": "score and one-hot linear relation over the plaintext modulus 65537",
        "weakestRelationEffectiveBitsPerCheck": weakest_relation_bits_per_check,
        "supportRelationModulusBits": support_modulus_bits,
        "supportCheckCount": support_check_count,
        "supportMaximumDegree": direct_ballot_support_maximum_degree(),
        "supportUnionLossBits": support_union_loss_bits,
        "targetClassicalSoundnessBits": DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "maskCoefficientBits": DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
        "responseCoefficientBytes": DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
        "witnessBoundBitsForMaskShiftAccounting": DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS,
        "zeroKnowledgeShiftSlackBitsAfterResponseUnionBound": zero_knowledge_shift_slack_bits
    }))
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_bytes() -> usize {
    (DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS * POLYNOMIAL_DEGREE
        + direct_ballot_relation_response_scalar_count())
        * DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_commitment_bytes() -> usize {
    (DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE
        + direct_ballot_score_linear_commitment_scalar_count())
        * size_of::<u64>()
        + direct_ballot_support_commitment_bytes()
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT + DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT
}

pub(super) fn direct_ballot_score_linear_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT * 2
}

pub(super) fn direct_ballot_support_commitment_bytes() -> usize {
    direct_ballot_support_commitment_scalar_count() * size_of::<u64>()
}

pub(super) fn direct_ballot_support_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT
        * DIRECT_BALLOT_SCORE_BUCKET_COUNT
        * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS
        + POLYNOMIAL_DEGREE * DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS
        + 2 * POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS
}

pub(super) fn direct_ballot_support_check_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT + 3 * POLYNOMIAL_DEGREE
}

// Support-check polynomial degrees: 5 is the max degree of the checked support identities; the 2/3/5 expansion counts are the monomials proven per one-hot / randomizer / error witness, feeding the union-bound soundness loss.
pub(super) fn direct_ballot_support_maximum_degree() -> usize {
    5
}

// Statistical masking budget: the response z = mask + challenge*witness hides the witness only if mask bits exceed challenge bits + witness magnitude bits + the per-scalar union-bound loss; the remaining slack is the statistical zero-knowledge margin.
fn zero_knowledge_shift_slack_bits_after_response_union_bound(
    mask_coefficient_bits: usize,
    response_union_loss_bits: u32,
) -> CanonicalResult<u32> {
    u32::try_from(mask_coefficient_bits)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "direct ballot proof mask bit count does not fit proof accounting",
            )
        })?
        .checked_sub(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS)
        .and_then(|slack| slack.checked_sub(DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS))
        .and_then(|slack| slack.checked_sub(response_union_loss_bits))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "direct ballot proof mask bit count is too small for zero-knowledge shift accounting",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::zero_knowledge_shift_slack_bits_after_response_union_bound;
    use crate::encoding::CanonicalErrorCode;

    #[test]
    fn zero_knowledge_shift_slack_rejects_underflowing_parameter_constants() {
        let error = zero_knowledge_shift_slack_bits_after_response_union_bound(1, 1)
            .expect_err("undersized mask bit count should reject");

        assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
        assert!(
            error
                .message
                .contains("too small for zero-knowledge shift accounting")
        );
    }
}
