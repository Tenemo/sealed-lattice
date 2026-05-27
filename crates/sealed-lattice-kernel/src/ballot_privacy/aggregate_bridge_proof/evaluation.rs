use super::*;
use super::{
    dimensions::bridge_variant_dimensions,
    generation::generate_aggregate_bridge_encryption,
    validation::{
        read_i64_array, read_u64_array, read_u64_object_field,
        reject_forbidden_public_bridge_fields, required_protocol_digest_field,
        validate_bridge_encryption_public_shell, validate_prover_randomness_hex,
    },
    verification::verify_aggregate_bridge_encryption,
};

pub(super) fn evaluate_aggregate_bridge_relation(request: &Value) -> CanonicalResult<Value> {
    let component = required_json_field(
        request,
        "aggregateDerivationComponent",
        "evaluateAggregateBridgeRelation",
    )?;
    let setup_package =
        required_json_field(request, "setupPackage", "evaluateAggregateBridgeRelation")?;
    let witness = required_json_field(
        request,
        "aggregateWitness",
        "evaluateAggregateBridgeRelation",
    )?;
    let bridge_encryption = required_json_field(
        request,
        "bridgeEncryption",
        "evaluateAggregateBridgeRelation",
    )?;
    validate_bridge_encryption_public_shell(bridge_encryption)?;
    required_string_field(bridge_encryption, "canonicalBytesHex", "bridgeEncryption")?;

    let prover_randomness_hex = required_string_field(
        request,
        "proverRandomnessHex",
        "evaluateAggregateBridgeRelation",
    )?;
    validate_prover_randomness_hex(prover_randomness_hex)?;
    let aggregate_selection_policy_digest = required_protocol_digest_field(
        request,
        "aggregateSelectionPolicyDigest",
        "evaluateAggregateBridgeRelation",
    )?;
    let bridge_witness_privacy_profile_digest = required_protocol_digest_field(
        request,
        "bridgeWitnessPrivacyProfileDigest",
        "evaluateAggregateBridgeRelation",
    )?;
    let he_param_digest = required_protocol_digest_field(
        request,
        "heParamDigest",
        "evaluateAggregateBridgeRelation",
    )?;

    reject_forbidden_public_bridge_fields(component, "aggregateDerivationComponent")?;
    reject_forbidden_public_bridge_fields(setup_package, "setupPackage")?;

    let statement = required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let dimensions = bridge_variant_dimensions(statement)?;
    let aggregate_integer_share_vector =
        read_u64_array(witness, "aggregateIntegerShareVector", "aggregateWitness")?;
    let aggregate_opening_randomness =
        read_i64_array(witness, "aggregateOpeningRandomness", "aggregateWitness")?;
    if aggregate_integer_share_vector.len() != dimensions.share_vector_width {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge private evaluator aggregate witness width does not match the variant shareVectorWidth",
        ));
    }
    if aggregate_opening_randomness.len() != SHARE_COMMITMENT_OPENING_DIMENSION {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge private evaluator aggregate opening randomness width is invalid",
        ));
    }

    let expected_bridge_encryption = generate_aggregate_bridge_encryption(&json!({
        "aggregateDerivationComponent": component,
        "setupPackage": setup_package,
        "aggregateWitness": witness,
        "proverRandomnessHex": prover_randomness_hex,
        "aggregateSelectionPolicyDigest": aggregate_selection_policy_digest,
        "bridgeWitnessPrivacyProfileDigest": bridge_witness_privacy_profile_digest,
        "heParamDigest": he_param_digest,
        "includeCanonicalBytesHex": true,
    }))?;
    compare_bridge_relation_public_artifacts(
        bridge_encryption,
        &expected_bridge_encryption,
        "bridgeEncryption",
    )?;

    let public_verification = verify_aggregate_bridge_encryption(&json!({
        "aggregateDerivationComponent": component,
        "setupPackage": setup_package,
        "bridgeEncryption": bridge_encryption,
        "aggregateSelectionPolicyDigest": aggregate_selection_policy_digest,
        "bridgeWitnessPrivacyProfileDigest": bridge_witness_privacy_profile_digest,
        "heParamDigest": he_param_digest,
    }))?;
    let proof_bytes_hex =
        required_string_field(bridge_encryption, "bridgeProofBytesHex", "bridgeEncryption")?;
    let proof_byte_length = u64::try_from(proof_bytes_hex.len() / 2).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge proof byte length does not fit u64",
        )
    })?;
    let bridge_proof_statement_digest = required_string_field(
        bridge_encryption,
        "bridgeProofStatementDigest",
        "bridgeEncryption",
    )?;
    let bridge_proof_target_contract_digest = required_string_field(
        bridge_encryption,
        "bridgeProofTargetContractDigest",
        "bridgeEncryption",
    )?;
    let bridge_proof_root =
        required_string_field(bridge_encryption, "bridgeProofRoot", "bridgeEncryption")?;
    let encrypted_aggregate_share_ciphertext_root = required_string_field(
        bridge_encryption,
        "encryptedAggregateShareCiphertextRoot",
        "bridgeEncryption",
    )?;
    let aggregate_reduced_coordinate_count = read_u64_object_field(
        bridge_encryption,
        "aggregateReducedCoordinateCount",
        "bridgeEncryption",
    )?;
    let aggregate_quotient_coordinate_count = read_u64_object_field(
        bridge_encryption,
        "aggregateQuotientCoordinateCount",
        "bridgeEncryption",
    )?;
    let bridge_relation_evaluation_digest = derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "sealed-lattice-private-aggregate-bridge-relation-evaluation-v1",
            "participantCount": dimensions.participant_count,
            "optionCount": dimensions.option_count,
            "shareVectorWidth": dimensions.share_vector_width,
            "aggregateDerivationComponentDigest": required_string_field(
                component,
                "aggregateDerivationComponentDigest",
                "aggregateDerivationComponent",
            )?,
            "bridgeProofStatementDigest": bridge_proof_statement_digest,
            "bridgeProofTargetContractDigest": bridge_proof_target_contract_digest,
            "bridgeProofRoot": bridge_proof_root,
            "encryptedAggregateShareCiphertextRoot": encrypted_aggregate_share_ciphertext_root,
        }),
    )?;
    let public_verifier_checked_relation =
        public_verification["bridgeProofVerificationStatus"] == BRIDGE_PROOF_CHECKED_STATUS;
    let private_relation_status_labels = if public_verifier_checked_relation {
        vec![
            "AggregateBridgePrivateRelationSatisfied",
            "M9PrivateRelationEvaluator",
            "BridgeProofRelationChecked",
            "BridgeProofImplementationEvidenceOnly",
            "SharedWitnessZeroKnowledgeProofMissing",
            "BgvRandomnessBoundProofMissing",
            "BridgeProofClaimClosureMissing",
            "FinalBridgeTheoremPending",
        ]
    } else {
        vec![
            "AggregateBridgePrivateRelationSatisfied",
            "M9PrivateRelationEvaluator",
            "BridgeProofBackendStillRequired",
            "FinalBridgeTheoremPending",
        ]
    };
    let mut private_relation_status_labels = private_relation_status_labels;
    private_relation_status_labels.push(match dimensions.evidence_tier {
        "representative-row-evidence" => "RepresentativeBridgeMatrixRowEvidence",
        _ => "FullBridgeMatrixRowEvidenceMissing",
    });

    Ok(json!({
        "ok": true,
        "operation": "evaluateAggregateBridgeRelation",
        "relationEvaluationStatus": "AggregateBridgePrivateRelationSatisfied",
        "bridgeProofVerificationStatus": public_verification["bridgeProofVerificationStatus"],
        "bridgeEvidenceVerificationStatus": public_verification["bridgeEvidenceVerificationStatus"],
        "publicArtifactWitnessCleanResult": true,
        "bridgeProofBackendStillRequired": !public_verifier_checked_relation,
        "scopedBridgeRelationClosure": false,
        "bridgeClaimClosureVerified": false,
        "bridgeClaimVerificationStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
        "participantCount": dimensions.participant_count,
        "optionCount": dimensions.option_count,
        "claimTier": dimensions.claim_tier,
        "bridgeVariantEvidenceStatus": dimensions.evidence_tier,
        "shareVectorWidth": dimensions.share_vector_width,
        "aggregateReducedCoordinateCount": aggregate_reduced_coordinate_count,
        "aggregateQuotientCoordinateCount": aggregate_quotient_coordinate_count,
        "proofByteLength": proof_byte_length,
        "ciphertextShape": {
            "basisId": required_string_field(bridge_encryption, "basisId", "bridgeEncryption")?,
            "level": read_u64_object_field(bridge_encryption, "level", "bridgeEncryption")?,
            "coefficientCount": read_u64_object_field(
                bridge_encryption,
                "coefficientCount",
                "bridgeEncryption",
            )?,
            "slotCount": read_u64_object_field(bridge_encryption, "slotCount", "bridgeEncryption")?,
            "dataPrimeCount": DATA_PRIMES.len(),
            "ciphertextComponentCount": 2,
            "canonicalByteLength": read_u64_object_field(
                bridge_encryption,
                "canonicalByteLength",
                "bridgeEncryption",
            )?,
        },
        "acceptedDigests": [
            bridge_relation_evaluation_digest,
            bridge_proof_statement_digest,
            bridge_proof_target_contract_digest,
            bridge_proof_root,
            encrypted_aggregate_share_ciphertext_root,
        ],
        "statusLabels": private_relation_status_labels,
    }))
}

pub(super) fn compare_bridge_relation_public_artifacts(
    actual: &Value,
    expected: &Value,
    object_name: &str,
) -> CanonicalResult<()> {
    let actual_object = actual.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("M9 bridge {object_name} must be an object"),
        )
    })?;
    let expected_object = expected.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge expected relation artifact must be an object",
        )
    })?;
    for actual_field_name in actual_object.keys() {
        if !expected_object.contains_key(actual_field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "M9 bridge private evaluator public artifact has unexpected field {object_name}.{actual_field_name}"
                ),
            ));
        }
    }
    for (field_name, expected_value) in expected_object {
        let actual_value = actual_object.get(field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("M9 bridge {object_name}.{field_name} is required"),
            )
        })?;
        if actual_value != expected_value {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "M9 bridge private evaluator public artifact field {object_name}.{field_name} does not match the recomputed shared-witness relation"
                ),
            ));
        }
    }

    Ok(())
}
