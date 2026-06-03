use super::validation::{
    read_bool_object_field, read_u64_object_field, require_matching_string_field,
};
use super::*;
use super::{plaintext_binding, shared_witness};

pub(super) fn bridge_proof_target_contract_value(
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
    aggregate_derivation_verification_scope: &str,
    claim_status: BridgeClaimStatus,
) -> CanonicalResult<Value> {
    validate_aggregate_derivation_verification_scope(aggregate_derivation_verification_scope)?;
    let polynomial_degree = POLYNOMIAL_DEGREE as u64;
    let data_prime_count = DATA_PRIMES.len() as u64;
    let ciphertext_component_count = BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT;
    let aggregate_reduction_row_count = aggregate_reduced_coordinate_count;
    let shared_witness_layout = shared_witness_layout_value(
        aggregate_reduced_coordinate_count,
        aggregate_quotient_coordinate_count,
    )?;
    let shared_witness_layout_hash = shared_witness_layout_hash(&shared_witness_layout)?;

    let mut target_contract = json!({
        "objectType": "AggregateBridgeProofTargetContract",
        "objectVersion": 1,
        "bridgeProofProfileId": BRIDGE_PROOF_PROFILE_ID,
        "proofBackend": BRIDGE_PROOF_BACKEND,
        "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        "relationScope": "sealed-lattice-aggregate-bridge-relation",
        "aggregateReducedCoordinateCount": aggregate_reduced_coordinate_count,
        "aggregateQuotientCoordinateCount": aggregate_quotient_coordinate_count,
        "commitmentOpeningCoordinateCount": SHARE_COMMITMENT_OPENING_DIMENSION,
        "aggregateReductionRowCount": aggregate_reduction_row_count,
        "fieldReductionModulus": BALLOT_PRIVACY_FIELD_MODULUS,
        "plaintextEncodingRelation": PLAINTEXT_ENCODING_RELATION,
        "plaintextCoefficientCount": polynomial_degree,
        "polynomialDegree": polynomial_degree,
        "dataPrimeCount": data_prime_count,
        "ciphertextComponentCount": ciphertext_component_count,
        "ciphertextCoefficientEquationCount": data_prime_count
            * polynomial_degree
            * ciphertext_component_count,
        "fullRnsCoverageRequired": true,
        "coefficientDomainCanonical": true,
        "sampledDiagnosticsAcceptedForVerification": false,
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_CHECKED_STATUS,
        "sharedWitnessChallengeBitsPerCheck": SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK,
        "sharedWitnessCheckCount": BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64,
        "sharedWitnessZeroKnowledgeStatus": SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        "sameWitnessLinkageModel": SAME_WITNESS_LINKAGE_MODEL,
        "separateSubproofsClosureStatus": SEPARATE_SUBPROOFS_CLOSURE_STATUS,
        "separateSubproofsAcceptedForClosure": false,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS,
        "proofFriendlyPlaintextBindingRequired": true,
        "proofFriendlyPlaintextBindingStatus": PROOF_FRIENDLY_PLAINTEXT_BINDING_STATUS,
        "proofFriendlyPlaintextBindingScheme": PLAINTEXT_COEFFICIENT_BINDING_SCHEME,
        "proofFriendlyPlaintextBindingOpeningCoordinateCount": plaintext_binding::plaintext_binding_opening_scalar_count()? as u64,
        "proofFriendlyPlaintextLiftBindingRequired": true,
        "proofFriendlyPlaintextLiftBindingStatus": PROOF_FRIENDLY_PLAINTEXT_LIFT_BINDING_STATUS,
        "plaintextCanonicalLiftProofStatus": PLAINTEXT_CANONICAL_LIFT_PROOF_CHECKED_STATUS,
        "publicPlaintextRootAcceptedAsClosureEvidence": false,
        "sharedWitnessLayout": shared_witness_layout,
        "sharedWitnessLayoutHash": shared_witness_layout_hash,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_CHECKED_STATUS,
        "bgvRandomnessBoundProofStatus": BGV_RANDOMNESS_BOUND_PROOF_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS,
        "bridgeClaimClosureStatus": claim_status.bridge_claim_verification_status,
        "aggregateDerivationVerificationScope": aggregate_derivation_verification_scope,
        "hwangPiopStatus": HWANG_PIOP_DEFERRED_STATUS,
        "naiveLinearExpansionBackendStatus": NAIVE_LINEAR_EXPANSION_BACKEND_STATUS,
    });
    let target_contract_object = target_contract.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate bridge target contract must be an object",
        )
    })?;
    for (field_name, field_value) in [
        (
            "bgvEncryptionKeyMaterialKind",
            Value::String(BGV_ENCRYPTION_KEY_MATERIAL_KIND.to_string()),
        ),
        ("developmentKeyOnly", Value::Bool(DEVELOPMENT_KEY_ONLY)),
        ("thresholdDecryptable", Value::Bool(THRESHOLD_DECRYPTABLE)),
        (
            "claimBearingBridgeEncryption",
            Value::Bool(claim_status.claim_bearing_bridge_encryption),
        ),
        (
            "sharedWitnessWeakestRelation",
            Value::String(BRIDGE_WEAKEST_ACTIVE_RELATION.to_string()),
        ),
        (
            "sharedWitnessWeakestRelationModel",
            Value::String(BRIDGE_WEAKEST_ACTIVE_RELATION_MODEL.to_string()),
        ),
        (
            "sharedWitnessWeakestRelationEffectiveModulus",
            Value::String(bridge_weakest_active_relation_effective_modulus_decimal()),
        ),
        (
            "sharedWitnessWeakestRelationBitsPerCheck",
            json!(BRIDGE_WEAKEST_ACTIVE_RELATION_BITS_PER_CHECK),
        ),
        (
            "batchIntegerLiftProofModulusProduct",
            Value::String(bridge_batch_integer_lift_proof_modulus_product_decimal()),
        ),
        (
            "batchIntegerLiftProofModuli",
            json!(BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI),
        ),
        (
            "batchIntegerLiftProofModulusProductBitsFloor",
            json!(BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT_BITS_FLOOR),
        ),
        (
            "plaintextEncodingProofModuli",
            json!(BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI),
        ),
        (
            "plaintextEncodingProofModulusProduct",
            Value::String(bridge_batch_integer_lift_proof_modulus_product_decimal()),
        ),
        (
            "plaintextEncodingProofModulusProductBitsFloor",
            json!(BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT_BITS_FLOOR),
        ),
        (
            "sharedWitnessChallengeSamplingModel",
            Value::String(
                shared_witness::BRIDGE_SHARED_WITNESS_CHALLENGE_SAMPLING_MODEL.to_string(),
            ),
        ),
        (
            "sharedWitnessRejectionAttemptLimit",
            json!(BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT as u64),
        ),
        (
            "sharedWitnessRejectionRetryLossBits",
            json!(BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS),
        ),
        (
            "sharedWitnessFullMatrixUnionBoundBits",
            json!(BRIDGE_FULL_MATRIX_UNION_BOUND_BITS),
        ),
        (
            "sharedWitnessRandomOracleQueryBoundBits",
            json!(BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS),
        ),
        (
            "sharedWitnessRandomOracleAccountingModel",
            Value::String(BRIDGE_RANDOM_ORACLE_ACCOUNTING_MODEL.to_string()),
        ),
        (
            "sharedWitnessQromAccountingStatus",
            Value::String(BRIDGE_QROM_ACCOUNTING_STATUS.to_string()),
        ),
        (
            "sharedWitnessProofSystemLossBits",
            json!(BRIDGE_PROOF_SYSTEM_LOSS_BITS),
        ),
        (
            "sharedWitnessChallengeBiasAccountingModel",
            Value::String(BRIDGE_CHALLENGE_BIAS_ACCOUNTING_MODEL.to_string()),
        ),
        (
            "sharedWitnessChallengeBiasBits",
            json!(BRIDGE_CHALLENGE_BIAS_BITS),
        ),
        (
            "sharedWitnessAdditionalRelationLossBits",
            json!(BRIDGE_ADDITIONAL_RELATION_LOSS_BITS),
        ),
        (
            "sharedWitnessBgvSupportRelation",
            Value::String(BRIDGE_BGV_SUPPORT_RELATION.to_string()),
        ),
        (
            "sharedWitnessBgvSupportChallengeDistribution",
            Value::String(BRIDGE_BGV_SUPPORT_CHALLENGE_DISTRIBUTION.to_string()),
        ),
        (
            "sharedWitnessBgvSupportCancellationModel",
            Value::String(BRIDGE_BGV_SUPPORT_CANCELLATION_MODEL.to_string()),
        ),
        (
            "sharedWitnessBgvSupportUnionBoundBits",
            json!(BRIDGE_BGV_SUPPORT_UNION_BOUND_BITS),
        ),
        (
            "sharedWitnessTargetBindingSoundnessBits",
            json!(BRIDGE_TARGET_BINDING_SOUNDNESS_BITS),
        ),
        (
            "sharedWitnessEffectiveBindingBelowTarget",
            json!(BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_BELOW_TARGET),
        ),
        (
            "sharedWitnessGrindingDiscountBitsPerCheck",
            json!(SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK),
        ),
        (
            "sharedWitnessRawWeakestRelationSoundnessBitsFloor",
            json!(BRIDGE_SHARED_WITNESS_RAW_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR),
        ),
        (
            "sharedWitnessEffectiveBindingSoundnessBitsFloor",
            json!(BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_SOUNDNESS_BITS_FLOOR),
        ),
    ] {
        target_contract_object.insert(field_name.to_string(), field_value);
    }

    Ok(target_contract)
}

fn shared_witness_layout_value(
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> CanonicalResult<Value> {
    let polynomial_degree = POLYNOMIAL_DEGREE as u64;
    let data_prime_count = DATA_PRIMES.len() as u64;
    let ciphertext_component_count = BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT;
    let aggregate_integer_share_coordinate_count = aggregate_reduced_coordinate_count;
    let commitment_opening_coordinate_count = SHARE_COMMITMENT_OPENING_DIMENSION as u64;
    let plaintext_coefficient_count = polynomial_degree;
    let plaintext_encoding_quotient_count = polynomial_degree;
    let plaintext_binding_opening_coordinate_count = u64::try_from(
        plaintext_binding::plaintext_binding_opening_scalar_count()?,
    )
    .map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding opening count does not fit u64",
        )
    })?;
    let encryption_randomizer_coefficient_count = polynomial_degree;
    let encryption_error_coefficient_count = ciphertext_component_count * polynomial_degree;
    // Single shared response vector = concatenation of all witness blocks: integer share coords,
    // commitment opening, reduced + quotient aggregate coords, plaintext coefficients (+0 quotient),
    // encryption randomizer, and the two-component encryption error coefficients.
    let shared_response_scalar_count = aggregate_integer_share_coordinate_count
        + commitment_opening_coordinate_count
        + aggregate_reduced_coordinate_count
        + aggregate_quotient_coordinate_count
        + plaintext_coefficient_count
        + plaintext_encoding_quotient_count
        + plaintext_binding_opening_coordinate_count
        + encryption_randomizer_coefficient_count
        + encryption_error_coefficient_count;

    Ok(json!({
        "objectType": "AggregateBridgeSharedWitnessLayout",
        "objectVersion": 1,
        "bridgeProofProfileId": BRIDGE_PROOF_PROFILE_ID,
        "layoutModel": "single-shared-response-vector-v1",
        "aggregateIntegerShareCoordinateCount": aggregate_integer_share_coordinate_count,
        "commitmentOpeningCoordinateCount": commitment_opening_coordinate_count,
        "aggregateReducedCoordinateCount": aggregate_reduced_coordinate_count,
        "aggregateQuotientCoordinateCount": aggregate_quotient_coordinate_count,
        "plaintextCoefficientCount": plaintext_coefficient_count,
        "plaintextEncodingQuotientCount": plaintext_encoding_quotient_count,
        "plaintextBindingOpeningCoordinateCount": plaintext_binding_opening_coordinate_count,
        "encryptionRandomizerCoefficientCount": encryption_randomizer_coefficient_count,
        "encryptionErrorCoefficientCount": encryption_error_coefficient_count,
        // Row counts per sub-relation: commitment rows (module rank) + one per reduced coord;
        // one batch-encoding row per polynomial coefficient; and one BGV ciphertext equation per
        // (data prime, coefficient, ciphertext component).
        "aggregateRelationRowCount": SHARE_COMMITMENT_MODULE_RANK as u64
            + aggregate_reduced_coordinate_count,
        "plaintextEncodingRelationRowCount": polynomial_degree,
        "bgvCiphertextEquationRowCount": data_prime_count
            * polynomial_degree
            * ciphertext_component_count,
        "sharedResponseScalarCount": shared_response_scalar_count,
        "sharedReducedCoordinateColumnRole": "aggregate-reduction-and-bgv-plaintext-slot",
        "plaintextCoefficientColumnRole": "bgv-batch-encoding-and-bgv-encryption-message",
        "sameWitnessLinkageModel": SAME_WITNESS_LINKAGE_MODEL,
        "separateSubproofsAcceptedForClosure": false,
    }))
}

fn shared_witness_layout_hash(layout: &Value) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-shared-witness-layout-v1",
            "layout": layout,
        }),
    )
}

pub(super) fn bridge_proof_target_contract_hash(
    target_contract: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-proof-target-contract-v1",
            "contract": target_contract,
        }),
    )
}

pub(super) fn validate_bridge_proof_target_contract(
    bridge_proof_statement: &Value,
    relation_requirements: &Value,
) -> CanonicalResult<()> {
    let aggregate_reduced_coordinate_count = read_u64_object_field(
        relation_requirements,
        "aggregateReducedCoordinateCount",
        "bridgeProofStatement.relationRequirements",
    )?;
    let aggregate_quotient_coordinate_count = read_u64_object_field(
        relation_requirements,
        "aggregateQuotientCoordinateCount",
        "bridgeProofStatement.relationRequirements",
    )?;
    let aggregate_derivation_verification_scope = required_string_field(
        relation_requirements,
        "aggregateDerivationVerificationScope",
        "bridgeProofStatement.relationRequirements",
    )?;
    let claim_bearing_bridge_encryption = read_bool_object_field(
        relation_requirements,
        "claimBearingBridgeEncryption",
        "bridgeProofStatement.relationRequirements",
    )?;
    let bridge_claim_verification_status = required_string_field(
        relation_requirements,
        "bridgeClaimClosureStatus",
        "bridgeProofStatement.relationRequirements",
    )?;
    if claim_bearing_bridge_encryption {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge target contract cannot claim final bridge closure",
        ));
    }
    let expected_bridge_claim_verification_status = BRIDGE_CLAIM_MISSING_STATUS;
    if bridge_claim_verification_status != expected_bridge_claim_verification_status {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge claim status does not match the relation requirements",
        ));
    }
    let claim_status = BridgeClaimStatus {
        claim_bearing_bridge_encryption,
        scoped_bridge_relation_closure: claim_bearing_bridge_encryption,
        bridge_claim_closure_verified: claim_bearing_bridge_encryption,
        bridge_claim_verification_status: expected_bridge_claim_verification_status,
    };
    let expected_target_contract = bridge_proof_target_contract_value(
        aggregate_reduced_coordinate_count,
        aggregate_quotient_coordinate_count,
        aggregate_derivation_verification_scope,
        claim_status,
    )?;
    let target_contract = required_json_field(
        bridge_proof_statement,
        "bridgeProofTargetContract",
        "bridgeProofStatement",
    )?;
    if target_contract != &expected_target_contract {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge proof target contract does not match the relation requirements",
        ));
    }
    let expected_target_contract_hash =
        bridge_proof_target_contract_hash(&expected_target_contract)?;
    require_matching_string_field(
        bridge_proof_statement,
        "bridgeProofTargetContractHash",
        &expected_target_contract_hash,
        "bridge proof target contract hash",
    )
}
