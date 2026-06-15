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

pub(crate) fn direct_ballot_witness_partition_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "DirectBallotWitnessPartitionProfileHash",
        &direct_ballot_witness_partition_profile_value(),
    )
}

pub(crate) fn direct_ballot_arithmetic_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotProofArithmeticCertificateHash",
        &direct_ballot_arithmetic_certificate_value()?,
    )
}

pub(crate) fn direct_ballot_witness_partition_profile_value() -> Value {
    json!({
        "objectType": "DirectBallotWitnessPartitionProfile",
        "objectVersion": 1,
        "statementId": "BallotValidityStatement-v1",
        "proofProfileId": "direct-encrypted-ballot-validity-relation-v1",
        "sourceRingDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataPrimeCount": DATA_PRIMES.len(),
        "optionCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreBucketCount": DIRECT_BALLOT_SCORE_BUCKET_COUNT,
        "responseEncodingOrder": [
            "randomizerPolynomial",
            "firstErrorPolynomial",
            "secondErrorPolynomial",
            "encodingCarryPolynomial",
            "scoreScalars",
            "oneHotBucketScalarsByOption",
            "projectedBgvNoWrapCarryScalars"
        ],
        "privateWitnessPartitions": [
            {
                "partitionId": "scoreScalars",
                "valueKind": "bounded integer scalar per option",
                "scalarCount": DIRECT_BALLOT_OPTION_COUNT,
                "minimum": 1,
                "maximum": 10,
                "responseOrder": 4,
                "maskDomain": "sealed-lattice/direct-encrypted-ballot/relation-mask-scalar-v1",
                "maskVectorIndex": 4,
                "packageRetention": "not retained"
            },
            {
                "partitionId": "oneHotBucketScalarsByOption",
                "valueKind": "one-hot score bucket scalar per option and bucket",
                "rowCount": DIRECT_BALLOT_OPTION_COUNT,
                "columnCount": DIRECT_BALLOT_SCORE_BUCKET_COUNT,
                "entrySet": [0, 1],
                "rowSum": 1,
                "responseOrder": 5,
                "maskDomain": "sealed-lattice/direct-encrypted-ballot/relation-mask-scalar-v1",
                "firstMaskVectorIndex": 5,
                "packageRetention": "not retained"
            },
            {
                "partitionId": "encodedPlaintextPolynomial",
                "valueKind": "batch-encoded score polynomial",
                "coefficientCount": POLYNOMIAL_DEGREE,
                "source": "Encode_p(score slots, reserved zero slots, batch encoder profile)",
                "constraint": "linked to scoreScalars through encodingCarryPolynomial",
                "responseOrder": "derived, not separately encoded",
                "packageRetention": "not retained"
            },
            {
                "partitionId": "randomizerPolynomial",
                "valueKind": "signed integer polynomial",
                "coefficientCount": POLYNOMIAL_DEGREE,
                "support": "ternary {-1,0,1}",
                "responseOrder": 0,
                "maskDomain": "sealed-lattice/direct-encrypted-ballot/relation-mask-v1",
                "maskVectorIndex": 0,
                "packageRetention": "not retained"
            },
            {
                "partitionId": "firstErrorPolynomial",
                "valueKind": "signed integer polynomial",
                "coefficientCount": POLYNOMIAL_DEGREE,
                "support": "centered binomial eta-2 range [-2,2]",
                "responseOrder": 1,
                "maskDomain": "sealed-lattice/direct-encrypted-ballot/relation-mask-v1",
                "maskVectorIndex": 1,
                "packageRetention": "not retained"
            },
            {
                "partitionId": "secondErrorPolynomial",
                "valueKind": "signed integer polynomial",
                "coefficientCount": POLYNOMIAL_DEGREE,
                "support": "centered binomial eta-2 range [-2,2]",
                "responseOrder": 2,
                "maskDomain": "sealed-lattice/direct-encrypted-ballot/relation-mask-v1",
                "maskVectorIndex": 2,
                "packageRetention": "not retained"
            },
            {
                "partitionId": "encodingCarryPolynomial",
                "valueKind": "signed integer polynomial",
                "coefficientCount": POLYNOMIAL_DEGREE,
                "relation": "raw encoder linear combination minus encoded plaintext, divided by plaintext modulus",
                "responseOrder": 3,
                "maskDomain": "sealed-lattice/direct-encrypted-ballot/relation-mask-v1",
                "maskVectorIndex": 3,
                "packageRetention": "not retained"
            },
            {
                "partitionId": "projectedBgvNoWrapCarryScalars",
                "valueKind": "signed integer carry scalar per statement-derived projected BGV row",
                "scalarCount": direct_ballot_projected_bgv_no_wrap_carry_scalar_count(),
                "responseOrder": 6,
                "responseCoefficientBytes": DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
                "relation": "integer lift of each projected BGV encryption row, with the existing projected residue commitment used as the no-wrap remainder",
                "currentInternalProofEncoding": "encoded in the binary response after one-hot bucket scalars",
                "packageRetention": "not retained"
            }
        ],
        "privateMaterialPolicy": {
            "packageRetention": "scores, one-hot rows, encoded plaintext, encryption randomness, errors, carries, and masks are not retained in public packages",
            "publicVerificationInputs": "accepted setup handoff, accepted public-key material, package fields, canonical ciphertext bytes, statement hash, and public proof chunks"
        }
    })
}

pub(crate) fn direct_ballot_arithmetic_certificate_value() -> CanonicalResult<Value> {
    let encoder_bounds = direct_ballot_encoder_arithmetic_bounds()?;
    let response_union_loss_bits = ceil_log2_usize(direct_ballot_relation_response_scalar_count());
    let zero_knowledge_shift_slack_bits =
        zero_knowledge_shift_slack_bits_after_response_union_bound(
            DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
            response_union_loss_bits,
        )?;
    let support_check_count = direct_ballot_support_check_count();
    let signed_plaintext_radius = signed_modulus_radius(PLAINTEXT_MODULUS);

    Ok(json!({
        "objectType": "BallotProofArithmeticCertificate",
        "objectVersion": 1,
        "statementId": "BallotValidityStatement-v1",
        "proofProfileId": "direct-encrypted-ballot-validity-relation-v1",
        "certificateStatus": "arithmetic bounds recorded; the proof bytes now include a committed trace proof for support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score rows, projected BGV field rows, and cross-prime no-wrap carry linkage, while accepted proof soundness, Fiat-Shamir/QROM accounting, and zero-knowledge accounting are not complete",
        "sourceRingDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataPrimes": DATA_PRIMES,
        "dataPrimeCount": DATA_PRIMES.len(),
        "limbEquationCount": DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE,
        "projectedBgvRelationRows": DATA_PRIMES.len()
            * 2
            * DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
        "projectedBgvRelationProjectionsPerLimbComponent":
            DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
        "optionCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreBucketCount": DIRECT_BALLOT_SCORE_BUCKET_COUNT,
        "witnessPartitionProfileHash": direct_ballot_witness_partition_profile_hash()?,
        "scoreWitnessBounds": {
            "scoreScalarMinimum": DIRECT_BALLOT_MINIMUM_SCORE,
            "scoreScalarMaximum": DIRECT_BALLOT_MAXIMUM_SCORE,
            "oneHotEntryMinimum": 0,
            "oneHotEntryMaximum": 1,
            "oneHotRowSum": 1,
            "oneHotLemma": "for an integer vector x in Z^10, if each entry is non-negative, ||x||_2 <= 1, and sum_i x_i = 1, then exactly one entry is one and the rest are zero"
        },
        "supportBounds": {
            "supportModuli": direct_ballot_support_moduli(),
            "supportModulusBitSum": direct_ballot_support_moduli_bit_sum(),
            "supportProjectionCountPerPartition": DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION,
            "supportProjectionDomain": "sealed-lattice/direct-encrypted-ballot/support-projection-v1",
            "oneHotEntryMaximumAbs": 1,
            "randomizerCoefficientMaximumAbs": 1,
            "errorCoefficientMaximumAbs": 2,
            "supportCheckCount": support_check_count,
            "supportMaximumPolynomialDegree": direct_ballot_support_maximum_degree(),
            "supportUnionLossBits": ceil_log2_usize(
                support_check_count * direct_ballot_support_maximum_degree()
            ),
            "currentInternalSupportStatus": "statement-derived random-projected support commitments still run in the projected response transcript, and the proof bytes additionally include a salted masked committed trace proof for one-hot Booleanity, ternary randomizer support, centered-binomial error support, helper-square consistency, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score row sums, score linkage, projected BGV field rows, and cross-prime no-wrap carry linkage; accepted simulator and QROM accounting are still open"
        },
        "committedTrace": {
            "status": "public proof bytes include one salted masked committed trace proof per data limb; support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score row sums, score linkage, projected BGV field rows, and cross-prime no-wrap carry linkage are proven from the same committed columns, while accepted soundness, Fiat-Shamir/QROM accounting, and zero-knowledge remain open",
            "logicalColumnCount": DIRECT_BALLOT_COMMITTED_COLUMN_COUNT,
            "witnessPhysicalColumnCount": DIRECT_BALLOT_COMMITTED_COLUMN_COUNT
                * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT,
            "encodingCarryBitColumnCount": DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT,
            "encodingCarrySlackBitColumnCount": DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT,
            "projectedBgvCarryDigitRadix":
                DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX,
            "projectedBgvCarryTernaryDigitColumnCount":
                DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT,
            "projectedBgvCarryMaximumAbs":
                direct_ballot_projected_bgv_no_wrap_committed_carry_maximum_abs()?,
            "linearAccumulatorColumnCount": 1,
            "shiftedLinearAccumulatorColumnCount": 1,
            "traceSplit": DIRECT_BALLOT_COMMITTED_TRACE_SPLIT,
            "traceSize": direct_ballot_committed_trace_size()?,
            "provedRows": [
                "one-hot Booleanity",
                "randomizer ternary support",
                "first error square consistency",
                "first error centered-binomial eta-2 support",
                "second error square consistency",
                "second error centered-binomial eta-2 support",
                "encoding carry bit Booleanity",
                "encoding carry slack bit Booleanity",
                "encoding carry bit decomposition",
                "encoding carry slack range equation",
                "projected no-wrap carry shifted ternary digit support",
                "projected no-wrap carry slack ternary digit support",
                "projected no-wrap carry shifted decomposition",
                "projected no-wrap carry range equation",
                "one-hot row sums",
                "score weighted-sum linkage",
                "projected BGV field rows",
                "cross-prime projected BGV no-wrap carry linkage"
            ]
        },
        "encoderBounds": {
            "encoderId": BATCH_ENCODER_ID,
            "encoderMatrixRoot": direct_ballot_encoder_matrix_root()?,
            "reservedSlotRuleHash": direct_ballot_reserved_slot_rule_hash()?,
            "basisVectorMaximumCoefficient": encoder_bounds.basis_vector_maximum_coefficient,
            "rawScoreLinearCombinationMaximum": encoder_bounds.raw_score_linear_combination_maximum,
            "plaintextCoefficientMaximum": PLAINTEXT_MODULUS - 1,
            "encodingCarryCoefficientMinimum": 0,
            "encodingCarryCoefficientMaximum": encoder_bounds.encoding_carry_coefficient_maximum,
            "encodingCarryRule": "raw encoder linear combination minus plaintext coefficient, divided by plaintext modulus"
        },
        "responseBounds": {
            "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
            "challengeMaximumDecimal": maximum_unsigned_with_bits_decimal(
                DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS as usize
            ),
            "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
            "maskCoefficientBits": DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
            "maskCoefficientMaximumDecimal": maximum_unsigned_with_bits_decimal(
                DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS
            ),
            "witnessBoundBitsForMaskShiftAccounting": DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS,
            "responseCoefficientBytes": DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
            "projectedBgvNoWrapCarryResponseBytes":
                DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
            "projectedBgvNoWrapCarryResponseScalars":
                direct_ballot_projected_bgv_no_wrap_carry_scalar_count(),
            "projectedBgvNoWrapQuotientBounds":
                direct_ballot_projected_bgv_no_wrap_worst_case_bounds()?,
            "responseSignedEncodingBits": DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES * 8,
            "responseMaximumAbsDecimal": direct_ballot_response_maximum_abs_decimal(),
            "responseUnionLossBits": response_union_loss_bits,
            "zeroKnowledgeShiftSlackBitsAfterResponseUnionBound": zero_knowledge_shift_slack_bits
        },
        "integerRows": [
            {
                "rowId": "scoreBucketSum",
                "rowCount": DIRECT_BALLOT_OPTION_COUNT,
                "modulus": PLAINTEXT_MODULUS,
                "signedModulusRadius": signed_plaintext_radius,
                "maximumAbsoluteValueBeforeReduction": DIRECT_BALLOT_SCORE_BUCKET_COUNT,
                "noWrapMargin": signed_plaintext_radius - DIRECT_BALLOT_SCORE_BUCKET_COUNT as u64,
                "status": "arithmetic range is inside the plaintext modulus; accepted soundness still depends on the selected proof backend and one-hot support proof"
            },
            {
                "rowId": "scoreWeightedSum",
                "rowCount": DIRECT_BALLOT_OPTION_COUNT,
                "modulus": PLAINTEXT_MODULUS,
                "signedModulusRadius": signed_plaintext_radius,
                "maximumAbsoluteValueBeforeReduction": DIRECT_BALLOT_MAXIMUM_SCORE
                    + score_bucket_weight_sum(),
                "noWrapMargin": signed_plaintext_radius
                    - (DIRECT_BALLOT_MAXIMUM_SCORE + score_bucket_weight_sum()),
                "status": "arithmetic range is inside the plaintext modulus; accepted soundness still depends on the selected proof backend and one-hot support proof"
            },
            {
                "rowId": "encoderPlaintextCarry",
                "rowCount": POLYNOMIAL_DEGREE,
                "modulus": PLAINTEXT_MODULUS,
                "signedModulusRadius": signed_plaintext_radius,
                "maximumAbsoluteValueBeforeReduction": encoder_bounds.raw_score_linear_combination_maximum
                    + PLAINTEXT_MODULUS - 1,
                "carryCoefficientMaximum": encoder_bounds.encoding_carry_coefficient_maximum,
                "status": "explicit carry bound recorded; accepted proof backend must enforce this carry as a hidden witness"
            }
        ],
        "bgvEncryptionRows": direct_ballot_bgv_arithmetic_rows(),
        "verifierArithmetic": {
            "canonicalResidueChecks": "every ciphertext and public-key limb coefficient must be below its limb modulus before proof verification",
            "statementEncoding": "canonical binary statement hash is length-delimited and root-bound",
            "chunkArithmetic": "chunk count and final chunk length are recomputed from proofByteLength and chunkSizeBytes before proof bytes are reassembled"
        },
        "closureBoundary": "The certificate records concrete arithmetic ranges and the verifier enforces row-specific projected BGV quotient bounds. It does not close accepted soundness, zero-knowledge, or QROM accounting."
    }))
}

pub(crate) fn direct_ballot_relation_proof_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotValidityProofProfileHash",
        &json!({
            "profileId": "direct-encrypted-ballot-validity-relation-v1",
            "statementVersion": 3,
            "witnessPartitionProfileHash": direct_ballot_witness_partition_profile_hash()?,
            "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
            "proofEncoding": "binary relation transcript",
            "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
            "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
            "proofBytesDomain": DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
            "projectedBgvRelationProjectionsPerLimbComponent":
                DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            "proofModelStatus": "internal relation proof with appended committed trace proof; claim soundness and zero-knowledge accounting are not accepted",
        "relation": "statement-derived projected BGV all-limb encryption rows with projected no-wrap carry scalars, score encoding, one-hot constraints, random-projected support checks, and a salted masked committed trace proof for support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score rows, projected BGV field rows, and cross-prime no-wrap carry linkage",
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
        zero_knowledge_shift_slack_bits_after_response_union_bound(
            DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
            response_union_loss_bits,
        )?;
    // The weakest subrelation is checked mod the about 16-bit plaintext modulus 65537, so each check yields only about 16 soundness bits despite the 192-bit nominal challenge; this is why claim soundness is not accepted.
    let weakest_relation_bits_per_check = 16_u32;
    let support_modulus_bits = direct_ballot_support_moduli_bit_sum();
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
        "projectedBgvRelationProjectionsPerLimbComponent":
            DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
        "projectedBgvRelationCommitmentScalars":
            direct_ballot_projected_bgv_commitment_scalar_count(),
        "projectedBgvNoWrapCarryResponseScalars":
            direct_ballot_projected_bgv_no_wrap_carry_scalar_count(),
        "weakestCheckedRelation": "score and one-hot linear relation over the plaintext modulus 65537",
        "weakestRelationEffectiveBitsPerCheck": weakest_relation_bits_per_check,
        "supportRelationModulusBits": support_modulus_bits,
        "supportFieldCount": direct_ballot_support_moduli().len(),
        "supportProjectionCountPerPartition": DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION,
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
        "projectedBgvNoWrapCarryResponseBytes":
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
        "witnessBoundBitsForMaskShiftAccounting": DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS,
        "zeroKnowledgeShiftSlackBitsAfterResponseUnionBound": zero_knowledge_shift_slack_bits,
        "supportAccounting": "The proof still carries statement-derived random support projections over the first three data-prime support fields, and now also carries a salted masked committed trace proof. The committed trace verifies support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score rows, projected BGV field rows, and cross-prime no-wrap carry linkage publicly, but the accepted relation remains open until weakest-relation soundness, zero-knowledge, and Fiat-Shamir/QROM accounting are recorded.",
        "zeroKnowledgeAccounting": "The coefficientwise support expansion commitments have been removed. Zero-knowledge is still not accepted until the committed-trace simulator, mask distribution, opened-row distribution, and abort behavior are recorded.",
        "decision": "The internal proof verifies the implemented relation, but claim soundness is not accepted. Nominal challenge bits do not establish 128-bit soundness because subrelations reduce the challenge modulo smaller rings and the committed trace still needs accepted soundness, Fiat-Shamir/QROM, and zero-knowledge closure."
    }))
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_bytes() -> usize {
    (DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS * POLYNOMIAL_DEGREE
        + direct_ballot_relation_base_response_scalar_count())
        * DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES
        + direct_ballot_projected_bgv_no_wrap_carry_scalar_count()
            * DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_commitment_bytes() -> usize {
    (direct_ballot_projected_bgv_commitment_scalar_count()
        + direct_ballot_score_linear_commitment_scalar_count())
        * size_of::<u64>()
        + direct_ballot_support_commitment_bytes()
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_scalar_count() -> usize {
    direct_ballot_relation_base_response_scalar_count()
        + direct_ballot_projected_bgv_no_wrap_carry_scalar_count()
}

pub(super) fn direct_ballot_relation_base_response_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT + DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT
}

pub(super) fn direct_ballot_score_linear_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT * 2
}

pub(super) fn direct_ballot_projected_bgv_commitment_scalar_count() -> usize {
    DATA_PRIMES.len() * 2 * DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT
}

pub(super) fn direct_ballot_projected_bgv_no_wrap_carry_scalar_count() -> usize {
    direct_ballot_projected_bgv_commitment_scalar_count()
}

pub(super) fn direct_ballot_support_commitment_bytes() -> usize {
    direct_ballot_support_commitment_scalar_count() * size_of::<u64>()
}

pub(super) fn direct_ballot_support_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION
        * direct_ballot_support_moduli().len()
        * (DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS
            + DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS
            + 2 * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS)
}

pub(super) fn direct_ballot_support_check_count() -> usize {
    4 * DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION * direct_ballot_support_moduli().len()
}

// Support-check polynomial degrees: 5 is the max degree of the checked support identities; each support partition is checked through statement-derived random projections over the support modulus.
pub(super) fn direct_ballot_support_maximum_degree() -> usize {
    5
}

fn direct_ballot_support_moduli_bit_sum() -> u32 {
    direct_ballot_support_moduli()
        .iter()
        .map(|modulus| u64::BITS - modulus.leading_zeros())
        .sum()
}

// Statistical masking budget: the response z = mask + challenge*witness hides the witness only if mask bits exceed challenge bits + witness magnitude bits + the per-scalar union-bound loss; the remaining slack is the statistical zero-knowledge margin.
fn zero_knowledge_shift_slack_bits_after_response_union_bound(
    mask_coefficient_bits: usize,
    response_union_loss_bits: u32,
) -> CanonicalResult<u32> {
    u32::try_from(mask_coefficient_bits)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot proof mask bit count does not fit proof accounting",
            )
        })?
        .checked_sub(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS)
        .and_then(|slack| slack.checked_sub(DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS))
        .and_then(|slack| slack.checked_sub(response_union_loss_bits))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot proof mask bit count is too small for zero-knowledge shift accounting",
            )
        })
}

pub(super) struct DirectBallotEncoderArithmeticBounds {
    pub(super) basis_vector_maximum_coefficient: u64,
    pub(super) raw_score_linear_combination_maximum: u64,
    pub(super) encoding_carry_coefficient_maximum: u64,
}

pub(super) fn direct_ballot_encoder_arithmetic_bounds()
-> CanonicalResult<DirectBallotEncoderArithmeticBounds> {
    let score_encoding_basis = direct_ballot_score_encoding_basis()?;
    let mut basis_vector_maximum_coefficient = 0_u64;
    let mut raw_score_linear_combination_maximum = 0_u64;
    let mut encoding_carry_coefficient_maximum = 0_u64;

    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let mut raw_score_linear_combination = 0_u64;
        for basis_polynomial in score_encoding_basis {
            let coefficient = *basis_polynomial.get(coefficient_index).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "direct ballot encoder basis vector does not match the ring degree",
                )
            })?;
            basis_vector_maximum_coefficient = basis_vector_maximum_coefficient.max(coefficient);
            raw_score_linear_combination = raw_score_linear_combination
                .checked_add(
                    coefficient
                        .checked_mul(DIRECT_BALLOT_MAXIMUM_SCORE)
                        .ok_or_else(|| {
                            CanonicalError::new(
                                CanonicalErrorCode::MalformedLength,
                                "direct ballot encoder coefficient bound overflowed",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "direct ballot encoder coefficient bound overflowed",
                    )
                })?;
        }
        raw_score_linear_combination_maximum =
            raw_score_linear_combination_maximum.max(raw_score_linear_combination);
        let conservative_carry_maximum = raw_score_linear_combination
            .checked_add(PLAINTEXT_MODULUS - 1)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "direct ballot encoder coefficient bound overflowed",
                )
            })?
            / PLAINTEXT_MODULUS;
        encoding_carry_coefficient_maximum =
            encoding_carry_coefficient_maximum.max(conservative_carry_maximum);
    }

    Ok(DirectBallotEncoderArithmeticBounds {
        basis_vector_maximum_coefficient,
        raw_score_linear_combination_maximum,
        encoding_carry_coefficient_maximum,
    })
}

fn direct_ballot_bgv_arithmetic_rows() -> Vec<Value> {
    DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(limb_index, modulus)| {
            let profile_bound = bgv_limb_arithmetic_bounds(modulus);
            json!({
                "limbIndex": limb_index,
                "modulus": modulus,
                "signedModulusRadius": profile_bound.signed_modulus_radius,
                "publicKeyCenteredCoefficientMaximumAbs": profile_bound.public_key_centered_coefficient_maximum_abs,
                "ciphertextCenteredCoefficientMaximumAbs": profile_bound.ciphertext_centered_coefficient_maximum_abs,
                "randomizerCoefficientMaximumAbs": 1,
                "errorCoefficientMaximumAbs": 2,
                "componentZero": {
                    "rowCount": POLYNOMIAL_DEGREE,
                    "maximumAbsoluteNumeratorBeforeCarryDecimal":
                        profile_bound.component_zero_numerator_maximum_abs_decimal,
                    "requiredCarryCoefficientMaximumAbs":
                        profile_bound.component_zero_carry_coefficient_maximum_abs,
                    "singleResidueNoWrapMarginDecimal":
                        profile_bound.component_zero_single_residue_margin_decimal,
                    "currentInternalProofStatus": "checked modulo the data prime and through a row-specific projected quotient response bound"
                },
                "componentOne": {
                    "rowCount": POLYNOMIAL_DEGREE,
                    "maximumAbsoluteNumeratorBeforeCarryDecimal":
                        profile_bound.component_one_numerator_maximum_abs_decimal,
                    "requiredCarryCoefficientMaximumAbs":
                        profile_bound.component_one_carry_coefficient_maximum_abs,
                    "singleResidueNoWrapMarginDecimal":
                        profile_bound.component_one_single_residue_margin_decimal,
                    "currentInternalProofStatus": "checked modulo the data prime and through a row-specific projected quotient response bound"
                },
                "acceptedProofRequirement": "complete the soundness, zero-knowledge, and Fiat-Shamir/QROM accounting around the projected quotient rows before the ballot proof can be accepted"
            })
        })
        .collect()
}

fn direct_ballot_projected_bgv_no_wrap_worst_case_bounds() -> CanonicalResult<Value> {
    let encoder_bounds = direct_ballot_encoder_arithmetic_bounds()?;
    let mask_coefficient_maximum_abs =
        maximum_unsigned_bigint_with_bits(DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS);
    let challenge_maximum =
        maximum_unsigned_bigint_with_bits(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS as usize);
    let mut witness_quotient_maximum_abs = BigInt::zero();
    let mut mask_quotient_maximum_abs = BigInt::zero();

    for modulus in DATA_PRIMES {
        let modulus_minus_one = BigInt::from(modulus - 1);
        let polynomial_projection_sum = BigInt::from(POLYNOMIAL_DEGREE) * &modulus_minus_one;
        let score_projection_sum = BigInt::from(DIRECT_BALLOT_OPTION_COUNT) * &modulus_minus_one;
        let component_zero_witness_linear_maximum_abs = &polynomial_projection_sum
            + BigInt::from(PLAINTEXT_MODULUS) * &polynomial_projection_sum * BigInt::from(2_u8)
            + BigInt::from(PLAINTEXT_MODULUS)
                * &polynomial_projection_sum
                * BigInt::from(encoder_bounds.encoding_carry_coefficient_maximum)
            + &score_projection_sum * BigInt::from(DIRECT_BALLOT_MAXIMUM_SCORE);
        let component_one_witness_linear_maximum_abs = &polynomial_projection_sum
            + BigInt::from(PLAINTEXT_MODULUS) * &polynomial_projection_sum * BigInt::from(2_u8);
        let component_zero_mask_linear_maximum_abs = (&polynomial_projection_sum
            + BigInt::from(PLAINTEXT_MODULUS) * &polynomial_projection_sum
            + BigInt::from(PLAINTEXT_MODULUS) * &polynomial_projection_sum
            + &score_projection_sum)
            * &mask_coefficient_maximum_abs;
        let component_one_mask_linear_maximum_abs = (&polynomial_projection_sum
            + BigInt::from(PLAINTEXT_MODULUS) * &polynomial_projection_sum)
            * &mask_coefficient_maximum_abs;

        for witness_linear_maximum_abs in [
            component_zero_witness_linear_maximum_abs,
            component_one_witness_linear_maximum_abs,
        ] {
            let numerator_maximum_abs = witness_linear_maximum_abs + &modulus_minus_one;
            witness_quotient_maximum_abs = witness_quotient_maximum_abs.max(
                ceil_div_nonnegative_bigint_by_u64(&numerator_maximum_abs, modulus)?,
            );
        }
        for mask_linear_maximum_abs in [
            component_zero_mask_linear_maximum_abs,
            component_one_mask_linear_maximum_abs,
        ] {
            mask_quotient_maximum_abs = mask_quotient_maximum_abs.max(
                ceil_div_nonnegative_bigint_by_u64(&mask_linear_maximum_abs, modulus)?,
            );
        }
    }

    let response_quotient_maximum_abs =
        &mask_quotient_maximum_abs + challenge_maximum * &witness_quotient_maximum_abs;

    Ok(json!({
        "boundMode": "verifier enforces row-specific projected quotient response bounds and the committed trace enforces a conservative witness quotient range with ternary digits; these values are conservative worst-case certificate limits",
        "witnessQuotientMaximumAbsDecimal": witness_quotient_maximum_abs.to_string(),
        "maskQuotientMaximumAbsDecimal": mask_quotient_maximum_abs.to_string(),
        "responseQuotientMaximumAbsDecimal": response_quotient_maximum_abs.to_string(),
        "responseQuotientMaximumBitLength":
            positive_bigint_bit_length(&response_quotient_maximum_abs)?,
        "responseEncodingBits":
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES * 8,
        "rowCount": direct_ballot_projected_bgv_no_wrap_carry_scalar_count()
    }))
}

struct DirectBallotBgvLimbArithmeticBounds {
    signed_modulus_radius: u64,
    public_key_centered_coefficient_maximum_abs: u64,
    ciphertext_centered_coefficient_maximum_abs: u64,
    component_zero_numerator_maximum_abs_decimal: String,
    component_one_numerator_maximum_abs_decimal: String,
    component_zero_carry_coefficient_maximum_abs: u64,
    component_one_carry_coefficient_maximum_abs: u64,
    component_zero_single_residue_margin_decimal: String,
    component_one_single_residue_margin_decimal: String,
}

fn bgv_limb_arithmetic_bounds(modulus: u64) -> DirectBallotBgvLimbArithmeticBounds {
    let signed_modulus_radius = signed_modulus_radius(modulus);
    let public_key_centered_coefficient_maximum_abs = signed_modulus_radius;
    let ciphertext_centered_coefficient_maximum_abs = signed_modulus_radius;
    let public_key_product_maximum_abs = u128::from(POLYNOMIAL_DEGREE as u64)
        * u128::from(public_key_centered_coefficient_maximum_abs);
    let scaled_error_maximum_abs = u128::from(PLAINTEXT_MODULUS) * 2;
    let message_maximum_abs = u128::from(PLAINTEXT_MODULUS - 1);
    let component_zero_numerator_maximum_abs =
        u128::from(ciphertext_centered_coefficient_maximum_abs)
            + public_key_product_maximum_abs
            + scaled_error_maximum_abs
            + message_maximum_abs;
    let component_one_numerator_maximum_abs =
        u128::from(ciphertext_centered_coefficient_maximum_abs)
            + public_key_product_maximum_abs
            + scaled_error_maximum_abs;

    DirectBallotBgvLimbArithmeticBounds {
        signed_modulus_radius,
        public_key_centered_coefficient_maximum_abs,
        ciphertext_centered_coefficient_maximum_abs,
        component_zero_numerator_maximum_abs_decimal: component_zero_numerator_maximum_abs
            .to_string(),
        component_one_numerator_maximum_abs_decimal: component_one_numerator_maximum_abs
            .to_string(),
        component_zero_carry_coefficient_maximum_abs: ceil_div_u128(
            component_zero_numerator_maximum_abs,
            u128::from(modulus),
        ) as u64,
        component_one_carry_coefficient_maximum_abs: ceil_div_u128(
            component_one_numerator_maximum_abs,
            u128::from(modulus),
        ) as u64,
        component_zero_single_residue_margin_decimal: signed_decimal_difference(
            u128::from(signed_modulus_radius),
            component_zero_numerator_maximum_abs,
        ),
        component_one_single_residue_margin_decimal: signed_decimal_difference(
            u128::from(signed_modulus_radius),
            component_one_numerator_maximum_abs,
        ),
    }
}

fn signed_modulus_radius(modulus: u64) -> u64 {
    (modulus - 1) / 2
}

fn score_bucket_weight_sum() -> u64 {
    (DIRECT_BALLOT_MINIMUM_SCORE..=DIRECT_BALLOT_MAXIMUM_SCORE).sum()
}

fn maximum_unsigned_with_bits_decimal(bit_count: usize) -> String {
    maximum_unsigned_bigint_with_bits(bit_count).to_string()
}

fn maximum_unsigned_bigint_with_bits(bit_count: usize) -> BigInt {
    (BigInt::from(1_u8) << bit_count) - BigInt::from(1_u8)
}

fn direct_ballot_response_maximum_abs_decimal() -> String {
    let mask_maximum =
        (BigInt::from(1_u8) << DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS) - BigInt::from(1_u8);
    let challenge_maximum =
        (BigInt::from(1_u8) << DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS) - BigInt::from(1_u8);
    let witness_maximum =
        (BigInt::from(1_u8) << DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS) - BigInt::from(1_u8);

    (mask_maximum + challenge_maximum * witness_maximum).to_string()
}

fn ceil_div_u128(numerator: u128, denominator: u128) -> u128 {
    numerator.div_ceil(denominator)
}

fn ceil_div_nonnegative_bigint_by_u64(value: &BigInt, modulus: u64) -> CanonicalResult<BigInt> {
    if value.sign() == Sign::Minus {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot projected BGV quotient bound input must be non-negative",
        ));
    }
    if modulus <= 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot projected BGV quotient bound modulus must be greater than one",
        ));
    }
    let modulus_bigint = BigInt::from(modulus);
    Ok((value + &modulus_bigint - BigInt::from(1_u8)) / modulus_bigint)
}

fn positive_bigint_bit_length(value: &BigInt) -> CanonicalResult<usize> {
    if value.sign() == Sign::Minus {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot projected BGV quotient bit length input must be non-negative",
        ));
    }
    let (_sign, bytes) = value.to_bytes_be();
    let first_byte = match bytes.first() {
        Some(byte) => *byte,
        None => return Ok(0),
    };

    Ok((bytes.len() - 1) * 8 + (u8::BITS - first_byte.leading_zeros()) as usize)
}

fn signed_decimal_difference(left: u128, right: u128) -> String {
    if left >= right {
        (left - right).to_string()
    } else {
        format!("-{}", right - left)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        direct_ballot_arithmetic_certificate_value,
        direct_ballot_projected_bgv_no_wrap_carry_scalar_count,
        zero_knowledge_shift_slack_bits_after_response_union_bound,
    };
    use crate::encoding::CanonicalErrorCode;

    #[test]
    fn zero_knowledge_shift_slack_rejects_underflowing_profile_constants() {
        let error = zero_knowledge_shift_slack_bits_after_response_union_bound(1, 1)
            .expect_err("undersized mask bit count should reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("too small for zero-knowledge shift accounting")
        );
    }

    #[test]
    fn arithmetic_certificate_records_encoder_bounds_and_projected_bgv_carry_rows() {
        let certificate =
            direct_ballot_arithmetic_certificate_value().expect("arithmetic certificate");

        assert_eq!(
            certificate["objectType"],
            "BallotProofArithmeticCertificate"
        );
        assert_eq!(certificate["sourceRingDegree"], 32_768);
        assert_eq!(certificate["plaintextModulus"], 65_537);
        assert_eq!(
            certificate["encoderBounds"]["encodingCarryCoefficientMinimum"],
            0
        );
        assert!(
            certificate["encoderBounds"]["encodingCarryCoefficientMaximum"]
                .as_u64()
                .expect("encoder carry bound")
                > 0
        );

        let first_limb = &certificate["bgvEncryptionRows"][0];
        assert_eq!(first_limb["limbIndex"], 0);
        assert!(
            first_limb["componentZero"]["requiredCarryCoefficientMaximumAbs"]
                .as_u64()
                .expect("component zero carry bound")
                > 0
        );
        assert!(
            first_limb["componentZero"]["singleResidueNoWrapMarginDecimal"]
                .as_str()
                .expect("component zero margin")
                .starts_with('-')
        );
        assert!(
            first_limb["componentZero"]["currentInternalProofStatus"]
                .as_str()
                .expect("component zero status")
                .contains("row-specific projected quotient response bound")
        );
        let quotient_bounds = &certificate["responseBounds"]["projectedBgvNoWrapQuotientBounds"];
        assert_eq!(
            quotient_bounds["rowCount"].as_u64(),
            Some(
                u64::try_from(direct_ballot_projected_bgv_no_wrap_carry_scalar_count())
                    .expect("row count fits u64")
            )
        );
        assert!(
            quotient_bounds["responseQuotientMaximumBitLength"]
                .as_u64()
                .expect("response quotient bit length")
                <= quotient_bounds["responseEncodingBits"]
                    .as_u64()
                    .expect("response encoding bits")
        );
        assert!(
            certificate["closureBoundary"]
                .as_str()
                .expect("closure boundary")
                .contains("does not close accepted soundness")
        );
    }
}
