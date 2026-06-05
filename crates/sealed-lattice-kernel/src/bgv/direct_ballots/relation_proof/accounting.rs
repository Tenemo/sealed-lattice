use super::*;

pub(super) fn direct_ballot_relation_proof_gate(proof_size_bytes: usize) -> &'static str {
    if proof_size_bytes <= DIRECT_BALLOT_RELATION_PROOF_GREEN_BYTES {
        "green: proof bytes are within the target size"
    } else if proof_size_bytes <= DIRECT_BALLOT_RELATION_PROOF_YELLOW_BYTES {
        "yellow: proof bytes are large but below the stop threshold"
    } else {
        "red: proof bytes exceed the stop threshold"
    }
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_challenge_bits() -> u32 {
    DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(
        DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
        &[proof_bytes],
    )
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_profile_hash()
-> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotValidityProofProfileHash",
        &json!({
            "profileId": "direct-encrypted-ballot-validity-relation-v1",
            "statementVersion": 3,
            "proofEncoding": "binary relation transcript",
            "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
            "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
            "proofBytesDomain": DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
            "proofModelStatus": "internal relation proof; claim soundness and support zero-knowledge are not accepted",
            "relation": "BGV all-limb encryption equations, score encoding, one-hot constraints, randomizer support, and error support",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": DATA_PRIMES.len(),
        }),
    )
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_accounting(
    proof_size_bytes: usize,
    total_proof_bytes: usize,
) -> CanonicalResult<Value> {
    let support_check_count = direct_ballot_support_check_count();
    let support_union_loss_bits =
        ceil_log2_usize(support_check_count * direct_ballot_support_maximum_degree());
    let response_union_loss_bits = ceil_log2_usize(direct_ballot_relation_response_scalar_count());
    let zero_knowledge_shift_slack_bits =
        u32::try_from(DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS)
            .expect("mask bit count fits u32")
            - DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS
            - DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS
            - response_union_loss_bits;
    let weakest_relation_bits_per_check = 16_u32;
    let support_modulus_bits = 64 - direct_ballot_support_modulus().leading_zeros();
    let repeated_proof_size_bytes = checked_repeated_byte_count(
        proof_size_bytes,
        DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS
            .div_ceil(weakest_relation_bits_per_check),
        "direct ballot repeated proof size",
    )?;
    let repeated_total_proof_bytes = checked_repeated_byte_count(
        total_proof_bytes,
        DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS
            .div_ceil(weakest_relation_bits_per_check),
        "direct ballot repeated total proof size",
    )?;

    Ok(json!({
        "model": "internal binary transcript with unaccepted claim soundness accounting",
        "proofModelAccepted": false,
        "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "nominalChallengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "challengeCount": 1,
        "weakestCheckedRelation": "score and one-hot linear relation over the plaintext modulus 65537",
        "weakestRelationEffectiveBitsPerCheck": weakest_relation_bits_per_check,
        "supportRelationModulusBits": support_modulus_bits,
        "classicalSoundnessBitsBeforeLosses": Value::Null,
        "supportCheckCount": support_check_count,
        "supportMaximumDegree": direct_ballot_support_maximum_degree(),
        "supportUnionLossBits": support_union_loss_bits,
        "classicalSoundnessBitsAfterSupportUnionBound": Value::Null,
        "targetClassicalSoundnessBits": DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "minimumIndependentRepetitionsForTarget": Value::Null,
        "minimumIndependentRepetitionsStatus": "not accepted from nominal challenge bits; the current weakest checked relation is about 16 bits per check before union losses",
        "estimatedIndependentRepetitionsFromWeakestRelationBeforeUnionLosses": DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS.div_ceil(weakest_relation_bits_per_check),
        "estimatedRepeatedProofSizeBytes": repeated_proof_size_bytes,
        "estimatedRepeatedTotalProofBytes": repeated_total_proof_bytes,
        "maskCoefficientBits": DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
        "responseCoefficientBytes": DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
        "witnessBoundBitsForMaskShiftAccounting": DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS,
        "zeroKnowledgeShiftSlackBitsAfterResponseUnionBound": zero_knowledge_shift_slack_bits,
        "supportAccounting": "The current support checks use one support modulus and witness-dependent support commitments. The support soundness and union-bound model is not accepted.",
        "zeroKnowledgeAccounting": "The current support commitments include witness-dependent expansion coefficients, so zero-knowledge is not accepted even though mask-shift slack is reported for the linear response encoding.",
        "decision": "The internal proof verifies the implemented relation, but claim soundness is not accepted. Nominal challenge bits do not establish 128-bit soundness because subrelations reduce the challenge modulo smaller rings and the support proof must be replaced or formally redesigned."
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

pub(super) fn direct_ballot_support_maximum_degree() -> usize {
    5
}
