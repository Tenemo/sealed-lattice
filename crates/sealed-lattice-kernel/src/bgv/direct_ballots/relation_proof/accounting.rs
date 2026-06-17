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

pub(super) fn direct_ballot_relation_proof_dimension_words() -> CanonicalResult<Vec<u64>> {
    Ok(vec![
        usize_to_dimension_word(POLYNOMIAL_DEGREE, "polynomial degree")?,
        PLAINTEXT_MODULUS,
        usize_to_dimension_word(DATA_PRIMES.len(), "data-prime count")?,
        usize_to_dimension_word(DIRECT_BALLOT_OPTION_COUNT, "option count")?,
        usize_to_dimension_word(DIRECT_BALLOT_SCORE_BUCKET_COUNT, "score bucket count")?,
        usize_to_dimension_word(
            DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS,
            "witness polynomial count",
        )?,
        usize_to_dimension_word(
            DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            "projected BGV relation projection count",
        )?,
        usize_to_dimension_word(
            direct_ballot_projected_bgv_commitment_scalar_count(),
            "projected BGV commitment scalar count",
        )?,
        usize_to_dimension_word(
            direct_ballot_score_linear_commitment_scalar_count(),
            "score linear commitment scalar count",
        )?,
        usize_to_dimension_word(
            direct_ballot_score_linear_commitment_bytes(),
            "score linear commitment byte count",
        )?,
        usize_to_dimension_word(
            direct_ballot_relation_commitment_bytes(),
            "relation commitment byte count",
        )?,
        usize_to_dimension_word(
            direct_ballot_relation_response_scalar_count(),
            "relation response scalar count",
        )?,
        usize_to_dimension_word(
            direct_ballot_relation_response_bytes(),
            "relation response byte count",
        )?,
        u64::from(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS),
        usize_to_dimension_word(
            DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
            "relation response coefficient byte count",
        )?,
        usize_to_dimension_word(
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
            "projected BGV no-wrap carry response byte count",
        )?,
        usize_to_dimension_word(
            DIRECT_BALLOT_COMMITTED_COLUMN_COUNT,
            "committed trace logical column count",
        )?,
        usize_to_dimension_word(DIRECT_BALLOT_COMMITTED_TRACE_SPLIT, "committed trace split")?,
    ])
}

fn usize_to_dimension_word(value: usize, label: &str) -> CanonicalResult<u64> {
    u64::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("direct ballot proof {label} does not fit in u64"),
        )
    })
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

pub(crate) fn direct_ballot_soundness_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotProofSoundnessCertificateHash",
        &direct_ballot_soundness_certificate_value()?,
    )
}

pub(crate) fn direct_ballot_zero_knowledge_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotProofZeroKnowledgeCertificateHash",
        &direct_ballot_zero_knowledge_certificate_value()?,
    )
}

pub(crate) fn direct_ballot_verifier_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotProofVerifierCertificateHash",
        &direct_ballot_verifier_certificate_value()?,
    )
}

pub(crate) fn direct_ballot_zero_knowledge_certificate_value() -> CanonicalResult<Value> {
    let outer_response_zero_knowledge = direct_ballot_outer_response_zero_knowledge_accounting()?;
    let committed_trace_zero_knowledge = direct_ballot_committed_trace_zero_knowledge_accounting()?;
    let outer_response_statistical_bits = required_u32_from_value(
        &outer_response_zero_knowledge,
        "statisticalDistanceBitsAfterUnionBound",
    )?;
    let committed_trace_opening_slack = required_u32_from_value(
        &committed_trace_zero_knowledge,
        "minimumUnopenedMaskDimensionPerColumn",
    )?;
    let effective_statistical_zero_knowledge_bits =
        outer_response_statistical_bits.min(committed_trace_opening_slack);

    Ok(json!({
        "objectType": "BallotProofZeroKnowledgeCertificate",
        "objectVersion": 1,
        "statementId": "BallotValidityStatement-v1",
        "proofProfileId": "direct-encrypted-ballot-validity-relation-v1",
        "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
        "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
        "hiddenWitness": [
            "score scalars",
            "one-hot score buckets",
            "encoded plaintext polynomial",
            "encryption randomizer polynomial",
            "encryption error polynomials",
            "encoding carry polynomial",
            "projected BGV no-wrap carry scalars",
            "committed-trace packed support columns",
            "proof mask material"
        ],
        "outerResponseZeroKnowledge": outer_response_zero_knowledge,
        "committedTraceZeroKnowledge": committed_trace_zero_knowledge,
        "simulatorConstruction": {
            "model": "random-oracle Fiat-Shamir simulation with statement-bound public roots",
            "outerResponseSimulator": "sample relation commitments from the mask distribution and sample response scalars from the statistically shifted mask distribution; the recorded union-bound slack limits witness distinguishability",
            "committedTraceSimulator": "sample salted masked extension columns and opened rows subject to the same public row identities; because each committed column has more independent mask coefficients than opened evaluations, opened values are independent of the hidden trace under the recorded degree condition",
            "abortBehavior": "no rejection sampling and no witness-dependent abort in proof generation or verification",
            "packageRetention": "scores, one-hot rows, encoded plaintext, randomizers, errors, carries, masks, and proof randomness seed are not retained in public packages"
        },
        "randomnessSource": {
            "proofMaskRandomness": "fresh platform CSPRNG in accepted package helpers; deterministic fixture seeds are development-only and refused by accepted package creation",
            "committedTraceMasks": "uniform residues derived from proof mask randomness under committed-trace column-mask domains",
            "committedTraceLeafSalts": "fresh proof-mask-derived leaf salts under committed-trace leaf-salt domains",
            "fiatShamirChallenges": "derived from statement hash, proof-profile-bound header material, commitments, and Merkle roots"
        },
        "effectiveStatisticalZeroKnowledgeBits": effective_statistical_zero_knowledge_bits,
        "targetStatisticalZeroKnowledgeBits":
            DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "certificateStatus": "zero-knowledge accounting is closed for the current binary proof profile under the recorded mask-distribution and random-oracle simulation model; accepted package creation requires fresh platform proof-mask randomness"
    }))
}

pub(crate) fn direct_ballot_verifier_certificate_value() -> CanonicalResult<Value> {
    let proof_format_magic =
        std::str::from_utf8(DIRECT_BALLOT_RELATION_PROOF_MAGIC).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot relation proof magic must be ASCII",
            )
        })?;
    let soundness_certificate = direct_ballot_soundness_certificate_value()?;
    let zero_knowledge_certificate = direct_ballot_zero_knowledge_certificate_value()?;
    let effective_soundness_bits =
        required_u32_from_value(&soundness_certificate, "effectiveSoundnessBits")?;
    let effective_zero_knowledge_bits = required_u32_from_value(
        &zero_knowledge_certificate,
        "effectiveStatisticalZeroKnowledgeBits",
    )?;

    Ok(json!({
        "objectType": "BallotProofVerifierCertificate",
        "objectVersion": 1,
        "statementId": "BallotValidityStatement-v1",
        "proofProfileId": "direct-encrypted-ballot-validity-relation-v1",
        "verifierStatus": "accepted-public-verifier-definition",
        "proofFormat": {
            "encoding": "binary relation transcript with explicit profile and dimension header",
            "formatMagic": proof_format_magic,
            "formatVersion": DIRECT_BALLOT_RELATION_PROOF_FORMAT_VERSION,
            "proofBytesDomain": DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
            "relationDimensionWords": direct_ballot_relation_proof_dimension_words()?,
            "rejectUnknownRequiredSections": true,
            "rejectDuplicateSections": true,
            "rejectTrailingBytes": true,
            "rejectMismatchedStatementHash": true,
            "rejectMismatchedProofProfileHash": true,
        },
        "statementBinding": {
            "statementVersion": 3,
            "bindsSetupContext": true,
            "bindsAcceptedPublicKeyMaterial": true,
            "bindsVoterIdentityAndRosterPosition": true,
            "bindsActionContextAndEpochs": true,
            "bindsCiphertextRootAndLimbRoots": true,
            "bindsBatchLayoutAndEncoderMatrix": true,
            "bindsWitnessPartitionProfileHash": direct_ballot_witness_partition_profile_hash()?,
            "bindsArithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
            "bindsSoundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
            "bindsZeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
        },
        "outerVerifier": {
            "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
            "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
            "challengeSource": "statement hash and relation commitment hash",
            "rejectZeroChallenge": true,
            "commitmentHashBindsStatement": true,
            "scoreLinkageUsesFullChallenge": true,
            "projectedBgvRelationProjectionsPerLimbComponent":
                DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            "projectedNoWrapQuotientResponseBounds": "row-specific verifier bounds from the arithmetic certificate",
            "ciphertextRelation": "verifier rebuilds statement-derived projected BGV rows from public key and ciphertext limbs",
        },
        "committedTraceVerifier": {
            "transcriptLabel": "direct-encrypted-ballot-committed-trace",
            "logicalColumnCount": DIRECT_BALLOT_COMMITTED_COLUMN_COUNT,
            "traceSplit": DIRECT_BALLOT_COMMITTED_TRACE_SPLIT,
            "linearBatchCount": DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT,
            "rowCheckBatchCount": DIRECT_BALLOT_COMMITTED_ROW_CHECK_BATCH_COUNT,
            "challengeExtensionDegree": CHALLENGE_EXTENSION_DEGREE,
            "lowDegreeQueryCount": LOW_DEGREE_QUERY_COUNT,
            "deepPointCount": DEEP_POINT_COUNT,
            "domainBlowup": DOMAIN_BLOWUP,
            "finalFoldedCoefficientCount": LOW_DEGREE_FINAL_COEFFICIENT_COUNT,
            "rejectsMalformedMerklePaths": true,
            "rejectsUnsupportedRows": true,
            "verifiesOneHotBooleanity": true,
            "verifiesTernaryRandomizerSupport": true,
            "verifiesCenteredBinomialErrorSupport": true,
            "verifiesHelperSquareConsistency": true,
            "verifiesEncoderCarryBitAndSlackRange": true,
            "verifiesProjectedNoWrapCarryTernaryDigitRange": true,
            "verifiesScoreRowsAndScoreLinkage": true,
            "verifiesProjectedBgvFieldRows": true,
            "verifiesCrossPrimeNoWrapCarryLinkage": true,
            "verifiesPackedColumnShape": true,
        },
        "acceptedInputs": {
            "publicOnly": true,
            "requiresAcceptedSetupHandoff": true,
            "requiresAcceptedPublicKeyMaterial": true,
            "requiresVoterProtocolSignature": true,
            "requiresProofChunkManifest": true,
            "requiresOrderedProofChunks": true,
            "requiresFreshBallotEncryptionRandomnessAtCreation": true,
            "requiresFreshProofMaskRandomnessAtCreation": true,
            "refusesWitness": true,
            "refusesPlaintextScores": true,
            "refusesEncryptionRandomness": true,
            "refusesProofRandomness": true,
            "refusesFixtureRandomnessAtCreation": true,
            "refusesDevelopmentSeeds": true,
        },
        "certificateRoots": {
            "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
            "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
            "zeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
        },
        "effectiveSoundnessBits": effective_soundness_bits,
        "effectiveStatisticalZeroKnowledgeBits": effective_zero_knowledge_bits,
        "targetClassicalSoundnessBits": DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "targetStatisticalZeroKnowledgeBits": DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "acceptanceBoundary": "the public verifier definition is accepted for this proof profile when the proof profile hash, verifier certificate hash, arithmetic certificate hash, soundness certificate hash, zero-knowledge certificate hash, statement, setup handoff, package root, signature, manifest, chunks, proof bytes, and accepted creation randomness boundary all match",
    }))
}

pub(crate) fn direct_ballot_soundness_certificate_value() -> CanonicalResult<Value> {
    let projected_bgv_soundness = direct_ballot_projected_bgv_soundness_accounting()?;
    let committed_trace_soundness = direct_ballot_committed_trace_soundness_accounting()?;
    let projected_bgv_budgeted_bits = required_u32_from_value(
        &projected_bgv_soundness,
        "budgetedClassicalBitsAfterReservedLosses",
    )?;
    let committed_trace_budgeted_bits = required_u32_from_value(
        &committed_trace_soundness,
        "budgetedClassicalBitsAfterReservedLosses",
    )?;
    let effective_soundness_bits = projected_bgv_budgeted_bits.min(committed_trace_budgeted_bits);
    let projected_bgv_raw_round_bits = required_u32_from_value(
        &projected_bgv_soundness,
        "rawProjectionBitsPerLimbComponent",
    )?;
    let committed_trace_raw_round_bits =
        required_u32_from_value(&committed_trace_soundness, "rawCommittedTraceSoundnessBits")?;
    let weakest_round_bits = projected_bgv_raw_round_bits.min(committed_trace_raw_round_bits);
    let minimum_data_prime_bits = minimum_data_prime_floor_log2_bits()?;
    let challenge_extension_degree = u32::try_from(CHALLENGE_EXTENSION_DEGREE).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot challenge extension degree does not fit soundness accounting",
        )
    })?;
    let quantum_soundness_bits = weakest_round_bits / 2;
    let quantum_soundness_after_statement_query_bits = effective_soundness_bits / 2;
    let quantum_collision_resistance_bits = DIRECT_BALLOT_QROM_DIGEST_BITS / 3;

    Ok(json!({
        "objectType": "BallotProofSoundnessCertificate",
        "objectVersion": 1,
        "statementId": "BallotValidityStatement-v1",
        "proofProfileId": "direct-encrypted-ballot-validity-relation-v1",
        "proofBackend": "binary direct ballot relation proof with exact integer score linkage, projected BGV random projections, and DEEP-batched committed trace IOP",
        "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
        "challengeSpaceAndDistribution": {
            "outerRelationChallengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
            "outerRelationChallengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
            "committedTraceTranscript": "direct-encrypted-ballot-committed-trace",
            "linearClaimBatchingField": "base RNS limb field",
            "rowAndLowDegreeChallengeField": "degree-four extension of each RNS limb field",
            "minimumDataPrimeFloorLog2Bits": minimum_data_prime_bits,
            "challengeExtensionDegree": CHALLENGE_EXTENSION_DEGREE,
            "minimumChallengeExtensionFloorLog2Bits":
                minimum_data_prime_bits * challenge_extension_degree
        },
        "roundStructure": [
            "commit witness trace roots for every data limb",
            "sample independent base-field linear claim batches per limb",
            "commit accumulator roots",
            "sample extension-field support and accumulator row checks",
            "commit row-quotient roots",
            "sample DEEP points and lambda batching challenges",
            "prove the batched DEEP quotient codeword with the low-degree IOP",
            "sample low-degree query positions and open witness, accumulator, quotient, and folded-layer Merkle paths"
        ],
        "repetitionCount": 1,
        "projectedBgvProjectionSoundness": projected_bgv_soundness,
        "committedTraceSoundness": committed_trace_soundness,
        "unionBoundAcrossRelationFamilies": {
            "projectedBgvBudgetedClassicalBitsAfterReservedLosses":
                projected_bgv_budgeted_bits,
            "committedTraceBudgetedClassicalBitsAfterReservedLosses":
                committed_trace_budgeted_bits,
            "effectiveSoundnessBits": effective_soundness_bits,
            "targetClassicalSoundnessBits":
                DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
            "status": "the recorded soundness budget clears the target under the verifier-certified proof profile"
        },
        "fiatShamirModel": "random-oracle Fiat-Shamir transcript with explicit domain labels, statement binding, proof-profile binding through the binary header, and Merkle roots absorbed before derived challenges",
        "fiatShamirAccounting": {
            "transform": "multi-round Fiat-Shamir over the direct encrypted ballot transcript",
            "soundnessModel": "classical round-by-round accounting with statement-query loss recorded separately; QROM soundness is computed through the CMS19 state-restoration BCS-in-QROM bound rather than a flat classical loss budget",
            "weakestRoundSoundnessBits": weakest_round_bits,
            "effectiveClassicalSoundnessBitsAfterStatementQueryLoss":
                effective_soundness_bits,
            "qromModel": "CMS19 state-restoration BCS-in-QROM: for a public-coin round-by-round-sound IOP transformed with Fiat-Shamir, QROM soundness is bounded by O(t^2 * eps + t^3 / 2^lambda) for t quantum random-oracle queries, IOP round-by-round soundness eps, and digest length lambda; the t^2 * eps term halves the classical round-by-round soundness by Grover square-root, while the hash term contributes about lambda/3 bits",
            "qromSoundnessTermModel": "t^2 * eps: quantum soundness in bits is about half the weakest classical round",
            "qromHashTermModel": "t^3 / 2^lambda: BHT quantum collision bound on the transcript digest",
            "digestBits": DIRECT_BALLOT_QROM_DIGEST_BITS,
            "digestFunction": "SHAKE256 with a 64-byte output through hash512 for transcript roots, Merkle nodes, proof-profile hashes, and Fiat-Shamir challenges",
            "quantumCollisionResistanceBitsApproximate":
                quantum_collision_resistance_bits,
            "classicalCollisionResistanceBitsApproximate":
                DIRECT_BALLOT_QROM_DIGEST_BITS / 2,
            "achievedQuantumSoundnessBitsApproximate": quantum_soundness_bits,
            "achievedQuantumSoundnessAfterStatementQueryBitsApproximate":
                quantum_soundness_after_statement_query_bits,
            "achievedQuantumSoundnessCalculation": format!(
                "the weakest direct ballot round is the committed-trace row at {weakest_round_bits} classical bits under the named CS25 low-degree row; after data-limb and statement-query losses the effective classical row is {effective_soundness_bits} bits, so CMS19 records about {quantum_soundness_after_statement_query_bits}-bit quantum soundness for the accepted statement scope; the 512-bit digest contributes about {quantum_collision_resistance_bits}-bit quantum collision resistance and is not the bottleneck"
            ),
            "presentTimeThreatScope": "this is a soundness bound for forged ballot validity proofs at proof-generation or proof-substitution time, not a harvest-now-decrypt-later confidentiality surface; the achieved quantum level is recorded below the conventional 128-bit quantum bar",
            "pathTo128BitQuantumSoundness": "128-bit quantum soundness for this Fiat-Shamir proof requires every classical round-by-round row to clear about 256 bits after the relevant union and statement-query losses, or a redesigned proof backend with a stronger proximity test and refreshed QROM analysis",
            "qromReferences": [
                "CMS19, Succinct arguments in the quantum random-oracle model",
                "BCS16, Interactive oracle proofs",
                "DFM20, The measure-and-reprogram technique 2.0: multi-round Fiat-Shamir and more (round-dependent, not the applicable bound at this round count)",
                "DFMS19, Security of the Fiat-Shamir transformation in the quantum random-oracle model",
                "DFMS22, Efficient NIZKs and signatures from commit-and-open protocols in the QROM"
            ],
            "qromReductionLossComputed": true,
            "meetsConventional128BitQuantumBar": false,
            "qromAccepted": false,
            "qromReductionLossStatus": "computed-cms19-state-restoration-achieved-level-recorded"
        },
        "qromReductionLossBudgetBits": DIRECT_BALLOT_RELATION_QROM_LOSS_BUDGET_BITS,
        "qromReductionLossBudgetStatus": "legacy flat budget retained for comparison only; accepted soundness uses fiatShamirAccounting",
        "statementQueryLossBudgetBits": DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS,
        "effectiveSoundnessBits": effective_soundness_bits,
        "certificateStatus": "classical soundness budget recorded under the named CS25 low-degree row for the verifier-certified proof profile; QROM achieved level is computed and recorded below the conventional 128-bit quantum bar; accepted package creation refuses fixture randomness"
    }))
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
    let signed_plaintext_radius = signed_modulus_radius(PLAINTEXT_MODULUS);

    Ok(json!({
        "objectType": "BallotProofArithmeticCertificate",
        "objectVersion": 1,
        "statementId": "BallotValidityStatement-v1",
        "proofProfileId": "direct-encrypted-ballot-validity-relation-v1",
        "certificateStatus": "arithmetic bounds recorded; the proof bytes include a committed trace proof for support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score rows, projected BGV field rows, and cross-prime no-wrap carry linkage, with accepted creation refusing fixture randomness",
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
            "oneHotEntryMaximumAbs": 1,
            "randomizerCoefficientMaximumAbs": 1,
            "errorCoefficientMaximumAbs": 2,
            "currentInternalSupportStatus": "support rows are checked by the salted masked committed trace proof for one-hot Booleanity, ternary randomizer support, centered-binomial error support, helper-square consistency, and packed-column shape; simulator and mask-distribution accounting are recorded in the zero-knowledge certificate"
        },
        "committedTrace": {
            "status": "public proof bytes include one salted masked committed trace proof per data limb; support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score row sums, score linkage, projected BGV field rows, and cross-prime no-wrap carry linkage are proven from the same committed columns, with proof masks supplied through the accepted fresh-randomness boundary",
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
            "linearAccumulatorColumnCount": DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT,
            "shiftedLinearAccumulatorColumnCount":
                DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT,
            "rowCheckBatchCount": DIRECT_BALLOT_COMMITTED_ROW_CHECK_BATCH_COUNT,
            "quotientExtensionColumnPairCount":
                DIRECT_BALLOT_COMMITTED_ROW_CHECK_BATCH_COUNT,
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
            "scoreLinearCommitmentEncoding": "exact signed integer commitments encoded with the fixed response coefficient width",
            "scoreLinearCommitmentScalars": direct_ballot_score_linear_commitment_scalar_count(),
            "scoreLinearCommitmentBytes": direct_ballot_score_linear_commitment_bytes(),
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
                "status": "outer response transcript checks this row as an exact signed integer relation with the full Fiat-Shamir challenge; the proof profile records combined projected-BGV soundness, committed-trace soundness, zero-knowledge accounting, and the accepted verifier certificate"
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
                "status": "outer response transcript checks this row as an exact signed integer relation with the full Fiat-Shamir challenge; the proof profile records combined projected-BGV soundness, committed-trace soundness, zero-knowledge accounting, and the accepted verifier certificate"
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
        "closureBoundary": "The certificate records concrete arithmetic ranges and the verifier enforces row-specific projected BGV quotient bounds. Zero-knowledge accounting, the verifier certificate, accepted creation randomness boundary, and package verification certificates are recorded separately."
    }))
}

pub(crate) fn direct_ballot_relation_proof_profile_hash() -> CanonicalResult<String> {
    let proof_format_magic =
        std::str::from_utf8(DIRECT_BALLOT_RELATION_PROOF_MAGIC).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot relation proof magic must be ASCII",
            )
        })?;

    derive_protocol_hash(
        "BallotValidityProofProfileHash",
        &json!({
            "profileId": "direct-encrypted-ballot-validity-relation-v1",
            "statementVersion": 3,
            "witnessPartitionProfileHash": direct_ballot_witness_partition_profile_hash()?,
            "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
            "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
            "zeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
            "verifierCertificateHash": direct_ballot_verifier_certificate_hash()?,
            "proofEncoding": "binary relation transcript with explicit profile and dimension header",
            "proofFormatMagic": proof_format_magic,
            "proofFormatVersion": DIRECT_BALLOT_RELATION_PROOF_FORMAT_VERSION,
            "relationDimensionWords": direct_ballot_relation_proof_dimension_words()?,
            "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
            "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
            "proofBytesDomain": DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
            "projectedBgvRelationProjectionsPerLimbComponent":
                DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            "scoreLinearCommitmentEncoding": "exact signed integer commitments",
            "proofModelStatus": "accepted public verifier definition with exact score linkage, projected-BGV budget accounting, committed-trace soundness under the named CS25 low-degree row, explicit QROM achieved-level accounting, zero-knowledge accounting, accepted creation randomness boundary, and appended committed trace proof",
            "relation": "statement-derived projected BGV all-limb encryption rows with projected no-wrap carry scalars, exact score encoding and one-hot linkage, and a salted masked committed trace proof for support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score rows, projected BGV field rows, and cross-prime no-wrap carry linkage",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": DATA_PRIMES.len(),
        }),
    )
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_accounting(
    proof_size_bytes: usize,
    total_proof_bytes: usize,
) -> CanonicalResult<Value> {
    let response_union_loss_bits = ceil_log2_usize(direct_ballot_relation_response_scalar_count());
    let zero_knowledge_shift_slack_bits =
        zero_knowledge_shift_slack_bits_after_response_union_bound(
            DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
            response_union_loss_bits,
        )?;
    let soundness_certificate = direct_ballot_soundness_certificate_value()?;
    let projected_bgv_soundness_accounting = soundness_certificate
        .get("projectedBgvProjectionSoundness")
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot soundness certificate is missing projected BGV accounting",
            )
        })?;
    let committed_trace_soundness_accounting = soundness_certificate
        .get("committedTraceSoundness")
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot soundness certificate is missing committed trace accounting",
            )
        })?;
    let effective_soundness_bits =
        required_u32_from_value(&soundness_certificate, "effectiveSoundnessBits")?;
    let zero_knowledge_certificate = direct_ballot_zero_knowledge_certificate_value()?;
    let outer_response_zero_knowledge_accounting = zero_knowledge_certificate
        .get("outerResponseZeroKnowledge")
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot zero-knowledge certificate is missing outer response accounting",
            )
        })?;
    let committed_trace_zero_knowledge_accounting = zero_knowledge_certificate
        .get("committedTraceZeroKnowledge")
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot zero-knowledge certificate is missing committed trace accounting",
            )
        })?;
    let effective_zero_knowledge_bits = required_u32_from_value(
        &zero_knowledge_certificate,
        "effectiveStatisticalZeroKnowledgeBits",
    )?;
    let raw_committed_trace_soundness_bits = committed_trace_soundness_accounting
        .get("rawCommittedTraceSoundnessBits")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace accounting is missing raw soundness bits",
            )
        })?;
    Ok(json!({
        "model": "verifier-certified binary transcript with named CS25 low-degree soundness, computed QROM achieved level, and zero-knowledge accounting",
        "proofModelAccepted": true,
        "singleProofSizeBytes": proof_size_bytes,
        "totalProofBytes": total_proof_bytes,
        "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
        "zeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
        "verifierCertificateHash": direct_ballot_verifier_certificate_hash()?,
        "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "nominalChallengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "challengeCount": 1,
        "projectedBgvRelationProjectionsPerLimbComponent":
            DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
        "projectedBgvRelationCommitmentScalars":
            direct_ballot_projected_bgv_commitment_scalar_count(),
        "projectedBgvNoWrapCarryResponseScalars":
            direct_ballot_projected_bgv_no_wrap_carry_scalar_count(),
        "scoreRelationChallengeUse": "score row sums and score weighted linkage use exact signed integer commitments and the full Fiat-Shamir challenge",
        "projectedBgvProjectionSoundness": projected_bgv_soundness_accounting,
        "committedTraceSoundness": committed_trace_soundness_accounting,
        "fiatShamirAccounting": soundness_certificate["fiatShamirAccounting"].clone(),
        "outerResponseZeroKnowledge": outer_response_zero_knowledge_accounting,
        "committedTraceZeroKnowledge": committed_trace_zero_knowledge_accounting,
        "effectiveStatisticalZeroKnowledgeBits": effective_zero_knowledge_bits,
        "weakestCheckedRelation": "committed trace batching is the recorded weakest relation after data-limb and statement-query losses",
        "weakestRelationEffectiveBitsPerCheck": effective_soundness_bits,
        "classicalSoundnessBitsBeforeLosses": raw_committed_trace_soundness_bits,
        "committedTraceSupportRows": "one-hot Booleanity, ternary randomizer support, centered-binomial error support, helper-square consistency, encoder carry bit/slack range, projected no-wrap carry ternary digits, score linkage, projected BGV field rows, cross-prime no-wrap carry linkage, and packed-column shape",
        "classicalSoundnessBitsAfterCommittedTraceAccounting": effective_soundness_bits,
        "targetClassicalSoundnessBits": DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "minimumIndependentRepetitionsForTarget": 1,
        "minimumIndependentRepetitionsStatus": "one proof clears the recorded classical soundness target under the named CS25 low-degree row; QROM achieved level is computed and remains below the conventional 128-bit quantum bar",
        "estimatedIndependentRepetitionsFromWeakestRelationBeforeUnionLosses": 1,
        "estimatedRepeatedProofSizeBytes": proof_size_bytes,
        "estimatedRepeatedTotalProofBytes": total_proof_bytes,
        "maskCoefficientBits": DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
        "responseCoefficientBytes": DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
        "projectedBgvNoWrapCarryResponseBytes":
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
        "witnessBoundBitsForMaskShiftAccounting": DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS,
        "zeroKnowledgeShiftSlackBitsAfterResponseUnionBound": zero_knowledge_shift_slack_bits,
        "supportAccounting": "Support is carried by the salted masked committed trace, which also verifies encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score rows, projected BGV field rows, and cross-prime no-wrap carry linkage publicly. The recorded classical soundness and zero-knowledge budgets clear their targets under the verifier-certified proof profile, QROM achieved level is recorded separately, and accepted package creation refuses fixture randomness.",
        "zeroKnowledgeAccounting": zero_knowledge_certificate,
        "decision": "The verifier-certified proof verifies the implemented relation, score-linkage checks use exact integer commitments with the full challenge, projected BGV rows record a random-projection budget above the classical target, committed-trace batching records a named CS25 low-degree budget above the classical target, QROM soundness is computed at the achieved level below the conventional 128-bit quantum bar, the mask/opening distribution records a zero-knowledge budget above the target, and accepted package creation refuses fixture randomness. The path remains non-claim-bearing until mobile-compatible runtime evidence and target-decryption gates are closed."
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
    direct_ballot_projected_bgv_commitment_scalar_count() * size_of::<u64>()
        + direct_ballot_score_linear_commitment_bytes()
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

pub(super) fn direct_ballot_score_linear_commitment_bytes() -> usize {
    direct_ballot_score_linear_commitment_scalar_count()
        * DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES
}

pub(super) fn direct_ballot_projected_bgv_commitment_scalar_count() -> usize {
    DATA_PRIMES.len() * 2 * DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT
}

pub(super) fn direct_ballot_projected_bgv_no_wrap_carry_scalar_count() -> usize {
    direct_ballot_projected_bgv_commitment_scalar_count()
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

fn direct_ballot_projected_bgv_soundness_accounting() -> CanonicalResult<Value> {
    let limb_component_count = DATA_PRIMES.len().checked_mul(2).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot projected BGV limb component count overflowed",
        )
    })?;
    let minimum_data_prime_floor_log2_bits = minimum_data_prime_floor_log2_bits()?;
    let projection_count =
        u32::try_from(DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT)
            .map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "direct ballot projected BGV projection count does not fit proof accounting",
                )
            })?;
    let raw_projection_bits = minimum_data_prime_floor_log2_bits
        .checked_mul(projection_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot projected BGV projection bit budget overflowed",
            )
        })?;
    let limb_component_union_loss_bits = ceil_log2_usize(limb_component_count);
    let classical_bits_after_union =
        raw_projection_bits.saturating_sub(limb_component_union_loss_bits);
    let classical_bits_after_statement_query_loss = classical_bits_after_union
        .saturating_sub(DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS);

    Ok(json!({
        "model": "random linear projection of each nonzero BGV residual vector over its RNS data prime",
        "limbComponentCount": limb_component_count,
        "dataPrimeCount": DATA_PRIMES.len(),
        "componentCountPerLimb": 2,
        "minimumDataPrimeFloorLog2Bits": minimum_data_prime_floor_log2_bits,
        "projectionsPerLimbComponent":
            DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
        "rawProjectionBitsPerLimbComponent": raw_projection_bits,
        "limbComponentUnionLossBits": limb_component_union_loss_bits,
        "classicalBitsAfterLimbComponentUnion": classical_bits_after_union,
        "statementQueryLossBudgetBits":
            DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS,
        "qromAccounting": "QROM loss is computed separately in the soundness certificate fiatShamirAccounting row; no flat QROM loss is subtracted from the classical projection row",
        "classicalBitsAfterStatementQueryLoss":
            classical_bits_after_statement_query_loss,
        "budgetedClassicalBitsAfterReservedLosses":
            classical_bits_after_statement_query_loss,
        "targetClassicalSoundnessBits":
            DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "budgetClearsTargetBeforeCommittedTraceReduction":
            classical_bits_after_statement_query_loss
                >= DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "claimBoundary": "records the projected BGV random-projection budget; the combined soundness certificate also accounts for the committed trace and reserved reduction losses"
    }))
}

fn direct_ballot_committed_trace_soundness_accounting() -> CanonicalResult<Value> {
    let trace_size = direct_ballot_committed_trace_size()?;
    let extension_size = trace_size.checked_mul(DOMAIN_BLOWUP).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot committed trace extension size overflowed",
        )
    })?;
    let minimum_data_prime_floor_log2_bits = minimum_data_prime_floor_log2_bits()?;
    let challenge_extension_degree = u32::try_from(CHALLENGE_EXTENSION_DEGREE).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot challenge extension degree does not fit soundness accounting",
        )
    })?;
    let challenge_extension_floor_log2_bits = minimum_data_prime_floor_log2_bits
        .checked_mul(challenge_extension_degree)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot challenge extension bit budget overflowed",
            )
        })?;
    let linear_claims_per_limb = DIRECT_BALLOT_OPTION_COUNT
        .checked_mul(2)
        .and_then(|score_claims| {
            DATA_PRIMES
                .len()
                .checked_mul(2)
                .and_then(|component_count| {
                    component_count.checked_mul(
                        DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
                    )
                })
                .and_then(|projected_claims| score_claims.checked_add(projected_claims))
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace linear claim count overflowed",
            )
        })?;
    let linear_claim_union_loss_bits = ceil_log2_usize(linear_claims_per_limb);
    let linear_batch_bits_per_batch =
        minimum_data_prime_floor_log2_bits.saturating_sub(linear_claim_union_loss_bits);
    let linear_batch_count =
        u32::try_from(DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace linear batch count does not fit soundness accounting",
            )
        })?;
    let independent_linear_batch_bits = linear_batch_bits_per_batch
        .checked_mul(linear_batch_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace linear batch budget overflowed",
            )
        })?;
    let row_combination_terms = DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINT_COUNT
        .checked_add(DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace row-combination term count overflowed",
            )
        })?;
    let row_combination_bits_per_batch =
        challenge_extension_floor_log2_bits.saturating_sub(ceil_log2_usize(row_combination_terms));
    let row_check_batch_count =
        u32::try_from(DIRECT_BALLOT_COMMITTED_ROW_CHECK_BATCH_COUNT).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace row-check batch count does not fit soundness accounting",
            )
        })?;
    let independent_row_combination_bits = row_combination_bits_per_batch
        .checked_mul(row_check_batch_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace row-combination budget overflowed",
            )
        })?;
    let deep_identity_bits_per_point =
        challenge_extension_floor_log2_bits.saturating_sub(ceil_log2_usize(extension_size));
    let deep_identity_bits = deep_identity_bits_per_point
        .checked_mul(u32::try_from(DEEP_POINT_COUNT).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace DEEP point count does not fit soundness accounting",
            )
        })?)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace DEEP identity budget overflowed",
            )
        })?;
    let low_degree_query_count = u32::try_from(LOW_DEGREE_QUERY_COUNT).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot committed trace low-degree query count does not fit soundness accounting",
        )
    })?;
    let low_degree_query_bits = low_degree_query_count
        .checked_mul(DIRECT_BALLOT_FRI_ENTROPY_CAPACITY_QUERY_SOUNDNESS_PERMILLE)
        .and_then(|scaled_bits| scaled_bits.checked_div(1000))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace low-degree query soundness overflowed",
            )
        })?;
    let proven_fallback_query_bits = low_degree_query_count / 2;
    let proven_fallback_classical_bits_after_statement_query_loss = proven_fallback_query_bits
        .saturating_sub(ceil_log2_usize(DATA_PRIMES.len()))
        .saturating_sub(DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS);
    let proven_fallback_query_count_for_target = 2
        * (DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS
            + ceil_log2_usize(DATA_PRIMES.len())
            + DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS);
    let raw_committed_trace_bits = [
        independent_linear_batch_bits,
        independent_row_combination_bits,
        deep_identity_bits,
        low_degree_query_bits,
    ]
    .into_iter()
    .min()
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot committed trace soundness budget is empty",
        )
    })?;
    let limb_union_loss_bits = ceil_log2_usize(DATA_PRIMES.len());
    let classical_bits_after_limb_union =
        raw_committed_trace_bits.saturating_sub(limb_union_loss_bits);
    let classical_bits_after_statement_query_loss = classical_bits_after_limb_union
        .saturating_sub(DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS);

    Ok(json!({
        "model": "committed-column trace with independent base-field linear batching, independent extension-field row-check batching, DEEP out-of-domain checks, and a batched low-degree IOP",
        "dataPrimeCount": DATA_PRIMES.len(),
        "traceSize": trace_size,
        "domainBlowup": DOMAIN_BLOWUP,
        "extensionSize": extension_size,
        "commitmentBoundFactor": COMMITMENT_BOUND_FACTOR,
        "initialDegreeBound": COMMITMENT_BOUND_FACTOR * trace_size,
        "lowDegreeFinalCoefficientCount": LOW_DEGREE_FINAL_COEFFICIENT_COUNT,
        "minimumDataPrimeFloorLog2Bits": minimum_data_prime_floor_log2_bits,
        "challengeExtensionDegree": CHALLENGE_EXTENSION_DEGREE,
        "challengeExtensionFloorLog2Bits": challenge_extension_floor_log2_bits,
        "linearClaimsPerLimb": linear_claims_per_limb,
        "linearClaimUnionLossBits": linear_claim_union_loss_bits,
        "linearBatchCount": DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT,
        "linearBatchBitsPerBatch": linear_batch_bits_per_batch,
        "independentLinearBatchBits": independent_linear_batch_bits,
        "supportConstraintCount": DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINT_COUNT,
        "rowCombinationTermCount": row_combination_terms,
        "rowCheckBatchCount": DIRECT_BALLOT_COMMITTED_ROW_CHECK_BATCH_COUNT,
        "rowCombinationBitsPerBatch": row_combination_bits_per_batch,
        "independentRowCombinationBits": independent_row_combination_bits,
        "deepPointCount": DEEP_POINT_COUNT,
        "deepIdentityBitsPerPoint": deep_identity_bits_per_point,
        "deepIdentityBits": deep_identity_bits,
        "lowDegreeQueryCount": LOW_DEGREE_QUERY_COUNT,
        "lowDegreeQuerySoundnessBits": low_degree_query_bits,
        "lowDegreeSoundness": {
            "queryCount": LOW_DEGREE_QUERY_COUNT,
            "perQueryBoundModel": "claim-bearing under the named CS25 mutual-correlated-agreement FRI conjecture up to the q-ary list-decoding entropy capacity for prime fields, the admissible repair of the disproved up-to-capacity proximity-gap conjecture; at rate one half over the base limb field this records about 0.938 bit per query, floored to 0.930 bit",
            "entropyCapacityQuerySoundnessPermille":
                DIRECT_BALLOT_FRI_ENTROPY_CAPACITY_QUERY_SOUNDNESS_PERMILLE,
            "conjecturedQuerySoundnessBits": low_degree_query_bits,
            "conjectureStatement": "re-based onto CS25 'Our Conjecture 3': the proximity-gap radius this batched DEEP-FRI row relies on is the q-ary list-decoding entropy-capacity mutual-correlated-agreement bound for prime fields, strictly below the 1 - rho up-to-capacity radius that Crites-Stewart and BCHKS26 disproved; this is the same repaired below-capacity assumption family used by the accepted setup proof accounting",
            "namedConjectureReference": "Crites, Stewart, On Reed-Solomon proximity gaps conjectures (CS25), Our Conjecture 3",
            "provenBoundReference": "Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, Proximity gaps for Reed-Solomon codes (BCIKS20)",
            "provenFallbackQuerySoundnessBits": proven_fallback_query_bits,
            "provenFallbackClassicalBitsAfterStatementQueryLoss":
                proven_fallback_classical_bits_after_statement_query_loss,
            "provenFallbackQueryCountFor128BitsAfterStatementQueryLoss":
                proven_fallback_query_count_for_target,
            "acceptedUnderNamedFriConjecture": true,
            "acceptedUnderProvenFallback": false,
            "acceptanceBar": "the named CS25 entropy-capacity low-degree row is not the bottleneck at this query count; the unconditional Johnson fallback does not clear the direct ballot classical target after data-limb and statement-query losses without increasing the query count or changing the backend"
        },
        "rawCommittedTraceSoundnessBits": raw_committed_trace_bits,
        "limbUnionLossBits": limb_union_loss_bits,
        "classicalBitsAfterLimbUnion": classical_bits_after_limb_union,
        "statementQueryLossBudgetBits":
            DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS,
        "qromAccounting": "QROM loss is computed separately in the soundness certificate fiatShamirAccounting row; no flat QROM loss is subtracted from the classical committed-trace row",
        "classicalBitsAfterStatementQueryLoss":
            classical_bits_after_statement_query_loss,
        "budgetedClassicalBitsAfterReservedLosses":
            classical_bits_after_statement_query_loss,
        "targetClassicalSoundnessBits":
            DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS,
        "status": "committed-trace classical soundness clears the target under the named CS25 entropy-capacity low-degree row; QROM achieved level is recorded separately"
    }))
}

fn direct_ballot_outer_response_zero_knowledge_accounting() -> CanonicalResult<Value> {
    let response_union_loss_bits = ceil_log2_usize(direct_ballot_relation_response_scalar_count());
    let shift_slack_bits = zero_knowledge_shift_slack_bits_after_response_union_bound(
        DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
        response_union_loss_bits,
    )?;

    Ok(json!({
        "model": "statistical hiding for integer response scalars z = mask + challenge * witness",
        "maskCoefficientBits": DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS,
        "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "witnessBoundBits": DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS,
        "responseScalarCount": direct_ballot_relation_response_scalar_count(),
        "responseUnionLossBits": response_union_loss_bits,
        "statisticalDistanceBitsAfterUnionBound": shift_slack_bits,
        "responseCoefficientBytes": DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
        "projectedBgvNoWrapCarryResponseBytes":
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
        "status": "outer relation responses have at least 128-bit statistical hiding after the response-scalar union bound"
    }))
}

fn direct_ballot_committed_trace_zero_knowledge_accounting() -> CanonicalResult<Value> {
    let trace_size = direct_ballot_committed_trace_size()?;
    let column_mask_degree = direct_ballot_committed_trace_column_mask_degree(trace_size);
    let opened_evaluations_per_column = LOW_DEGREE_QUERY_COUNT
        .checked_add(DEEP_POINT_COUNT)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace opening count overflowed",
            )
        })?;
    let unopened_mask_dimension = column_mask_degree
        .checked_sub(opened_evaluations_per_column)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot committed trace mask degree is too small for zero-knowledge openings",
            )
        })?;

    Ok(json!({
        "model": "salted masked committed-column IOP with per-column random mask polynomial multiples of X^traceSize - 1",
        "traceSize": trace_size,
        "columnMaskDegree": column_mask_degree,
        "lowDegreeQueryCount": LOW_DEGREE_QUERY_COUNT,
        "deepPointCount": DEEP_POINT_COUNT,
        "openedEvaluationsPerColumn": opened_evaluations_per_column,
        "minimumUnopenedMaskDimensionPerColumn": unopened_mask_dimension,
        "logicalWitnessColumnCount": DIRECT_BALLOT_COMMITTED_COLUMN_COUNT,
        "physicalWitnessColumnCount":
            DIRECT_BALLOT_COMMITTED_COLUMN_COUNT * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT,
        "linearAccumulatorColumnCount": DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT,
        "shiftedLinearAccumulatorColumnCount": DIRECT_BALLOT_COMMITTED_LINEAR_BATCH_COUNT,
        "quotientExtensionColumnPairCount": DIRECT_BALLOT_COMMITTED_ROW_CHECK_BATCH_COUNT,
        "saltedCommitmentModel": "leaf salts and masked extension rows are absorbed only through root-bound Merkle commitments and opened rows",
        "abortBehavior": "no witness-dependent rejection or retry path",
        "status": "opened committed-trace values are simulatable from masked columns because every column retains unopened mask dimension after all low-degree and DEEP openings"
    }))
}

fn minimum_data_prime_floor_log2_bits() -> CanonicalResult<u32> {
    DATA_PRIMES
        .iter()
        .copied()
        .map(floor_log2_u64)
        .min()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "direct ballot BGV profile has no data primes",
            )
        })
}

fn required_u32_from_value(value: &Value, key: &str) -> CanonicalResult<u32> {
    let field = value.get(key).and_then(Value::as_u64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("direct ballot soundness certificate is missing {key}"),
        )
    })?;
    u32::try_from(field).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("direct ballot soundness certificate {key} does not fit in u32"),
        )
    })
}

fn floor_log2_u64(value: u64) -> u32 {
    u64::BITS - 1 - value.leading_zeros()
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
                "acceptedProofRequirement": "accepted package creation must supply fresh platform ballot-encryption and proof-mask randomness; fixture-labelled randomness is refused before encryption or proof generation"
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
        direct_ballot_soundness_certificate_hash, direct_ballot_soundness_certificate_value,
        direct_ballot_verifier_certificate_value, direct_ballot_zero_knowledge_certificate_hash,
        direct_ballot_zero_knowledge_certificate_value,
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
                .contains("accepted creation randomness boundary")
        );
    }

    #[test]
    fn soundness_certificate_records_committed_trace_budget() {
        let certificate =
            direct_ballot_soundness_certificate_value().expect("soundness certificate");

        assert_eq!(certificate["objectType"], "BallotProofSoundnessCertificate");
        assert_eq!(certificate["effectiveSoundnessBits"], 221);
        assert_eq!(
            certificate["projectedBgvProjectionSoundness"]["budgetedClassicalBitsAfterReservedLosses"],
            230
        );
        assert_eq!(
            certificate["fiatShamirAccounting"]["achievedQuantumSoundnessAfterStatementQueryBitsApproximate"],
            110
        );
        assert_eq!(certificate["fiatShamirAccounting"]["qromAccepted"], false);
        assert_eq!(
            certificate["committedTraceSoundness"]["linearBatchCount"],
            7
        );
        assert_eq!(
            certificate["committedTraceSoundness"]["rowCheckBatchCount"],
            2
        );
        assert_eq!(
            certificate["committedTraceSoundness"]["lowDegreeQueryCount"],
            288
        );
        assert_eq!(
            certificate["committedTraceSoundness"]["budgetedClassicalBitsAfterReservedLosses"],
            221
        );
        assert_eq!(
            certificate["committedTraceSoundness"]["lowDegreeSoundness"]["conjecturedQuerySoundnessBits"],
            267
        );
        assert_eq!(
            certificate["committedTraceSoundness"]["lowDegreeSoundness"]["provenFallbackClassicalBitsAfterStatementQueryLoss"],
            99
        );
        assert_eq!(
            certificate["committedTraceSoundness"]["lowDegreeSoundness"]["acceptedUnderNamedFriConjecture"],
            true
        );
        assert_eq!(
            certificate["committedTraceSoundness"]["lowDegreeSoundness"]["acceptedUnderProvenFallback"],
            false
        );
    }

    #[test]
    fn zero_knowledge_certificate_records_mask_and_opening_budget() {
        let certificate =
            direct_ballot_zero_knowledge_certificate_value().expect("zero-knowledge certificate");

        assert_eq!(
            certificate["objectType"],
            "BallotProofZeroKnowledgeCertificate"
        );
        assert_eq!(certificate["effectiveStatisticalZeroKnowledgeBits"], 143);
        assert_eq!(
            certificate["outerResponseZeroKnowledge"]["statisticalDistanceBitsAfterUnionBound"],
            143
        );
        assert_eq!(
            certificate["committedTraceZeroKnowledge"]["columnMaskDegree"],
            512
        );
        assert_eq!(
            certificate["committedTraceZeroKnowledge"]["openedEvaluationsPerColumn"],
            290
        );
        assert_eq!(
            certificate["committedTraceZeroKnowledge"]["minimumUnopenedMaskDimensionPerColumn"],
            222
        );
    }

    #[test]
    fn verifier_certificate_records_public_acceptance_contract() {
        let certificate = direct_ballot_verifier_certificate_value().expect("verifier certificate");

        assert_eq!(certificate["objectType"], "BallotProofVerifierCertificate");
        assert_eq!(
            certificate["verifierStatus"],
            "accepted-public-verifier-definition"
        );
        assert_eq!(
            certificate["certificateRoots"]["soundnessCertificateHash"],
            direct_ballot_soundness_certificate_hash().expect("soundness certificate hash")
        );
        assert_eq!(
            certificate["certificateRoots"]["zeroKnowledgeCertificateHash"],
            direct_ballot_zero_knowledge_certificate_hash()
                .expect("zero-knowledge certificate hash")
        );
        assert_eq!(certificate["acceptedInputs"]["publicOnly"], true);
        assert_eq!(
            certificate["acceptedInputs"]["requiresFreshBallotEncryptionRandomnessAtCreation"],
            true
        );
        assert_eq!(
            certificate["acceptedInputs"]["requiresFreshProofMaskRandomnessAtCreation"],
            true
        );
        assert_eq!(
            certificate["acceptedInputs"]["refusesFixtureRandomnessAtCreation"],
            true
        );
        assert_eq!(certificate["acceptedInputs"]["refusesWitness"], true);
    }
}
