use super::validation::{read_u64_object_field, require_matching_string_field};
use super::*;

pub(super) fn bridge_proof_target_contract_value(
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> CanonicalResult<Value> {
    let polynomial_degree = POLYNOMIAL_DEGREE as u64;
    let data_prime_count = DATA_PRIMES.len() as u64;
    let ciphertext_component_count = BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT;
    let aggregate_reduction_row_count = aggregate_reduced_coordinate_count;
    let shared_witness_layout = shared_witness_layout_value(
        aggregate_reduced_coordinate_count,
        aggregate_quotient_coordinate_count,
    );
    let shared_witness_layout_hash = shared_witness_layout_hash(&shared_witness_layout)?;

    Ok(json!({
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
        "sharedWitnessSoundnessBits": BRIDGE_SHARED_WITNESS_SOUNDNESS_BITS,
        "sharedWitnessZeroKnowledgeStatus": SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        "sameWitnessLinkageModel": SAME_WITNESS_LINKAGE_MODEL,
        "separateSubproofsClosureStatus": SEPARATE_SUBPROOFS_CLOSURE_STATUS,
        "separateSubproofsAcceptedForClosure": false,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS,
        "proofFriendlyPlaintextBindingRequired": true,
        "plaintextCanonicalLiftProofStatus": PLAINTEXT_CANONICAL_LIFT_PROOF_MISSING_STATUS,
        "publicPlaintextRootAcceptedAsClosureEvidence": false,
        "sharedWitnessLayout": shared_witness_layout,
        "sharedWitnessLayoutHash": shared_witness_layout_hash,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_CHECKED_STATUS,
        "bgvRandomnessBoundProofStatus": BGV_RANDOMNESS_BOUND_PROOF_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS,
        "bridgeClaimClosureStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
        "hwangPiopStatus": HWANG_PIOP_DEFERRED_STATUS,
        "naiveLinearExpansionBackendStatus": NAIVE_LINEAR_EXPANSION_BACKEND_STATUS,
    }))
}

fn shared_witness_layout_value(
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> Value {
    let polynomial_degree = POLYNOMIAL_DEGREE as u64;
    let data_prime_count = DATA_PRIMES.len() as u64;
    let ciphertext_component_count = BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT;
    let aggregate_integer_share_coordinate_count = aggregate_reduced_coordinate_count;
    let commitment_opening_coordinate_count = SHARE_COMMITMENT_OPENING_DIMENSION as u64;
    let plaintext_coefficient_count = polynomial_degree;
    let plaintext_encoding_quotient_count = 0_u64;
    let encryption_randomizer_coefficient_count = polynomial_degree;
    let encryption_error_coefficient_count = ciphertext_component_count * polynomial_degree;
    let shared_response_scalar_count = aggregate_integer_share_coordinate_count
        + commitment_opening_coordinate_count
        + aggregate_reduced_coordinate_count
        + aggregate_quotient_coordinate_count
        + plaintext_coefficient_count
        + plaintext_encoding_quotient_count
        + encryption_randomizer_coefficient_count
        + encryption_error_coefficient_count;

    json!({
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
        "encryptionRandomizerCoefficientCount": encryption_randomizer_coefficient_count,
        "encryptionErrorCoefficientCount": encryption_error_coefficient_count,
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
    })
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
    let expected_target_contract = bridge_proof_target_contract_value(
        aggregate_reduced_coordinate_count,
        aggregate_quotient_coordinate_count,
    )?;
    let target_contract = required_json_field(
        bridge_proof_statement,
        "bridgeProofTargetContract",
        "bridgeProofStatement",
    )?;
    if target_contract != &expected_target_contract {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof target contract does not match the relation requirements",
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
