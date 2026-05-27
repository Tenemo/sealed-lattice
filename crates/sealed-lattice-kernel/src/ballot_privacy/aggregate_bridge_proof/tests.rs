use super::*;
use super::{
    dimensions::bridge_variant_dimensions,
    evaluation::compare_bridge_relation_public_artifacts,
    target_contract::{
        bridge_proof_target_contract_digest, bridge_proof_target_contract_value,
        validate_bridge_proof_target_contract,
    },
    validation::validate_bridge_proof_public_shell,
};
use num_bigint::BigInt;
use num_traits::One;

fn bridge_relation_gap_status_value() -> Value {
    json!({
        "objectType": "AggregateBridgeRelationGapStatus",
        "objectVersion": 1,
        "scopedBridgeRelationClosure": false,
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_PENDING_STATUS,
        "sharedWitnessZeroKnowledgeStatus": SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_PENDING_STATUS,
        "bgvRandomnessBoundProofStatus": BGV_RANDOMNESS_BOUND_PROOF_MISSING_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS,
        "bridgeClaimClosureStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
        "sampledOnlyBridgeVerificationAccepted": false,
        "hwangPiopStatus": HWANG_PIOP_DEFERRED_STATUS,
    })
}

fn private_material_disclosure() -> Value {
    json!({
        "aggregateOpeningMaterialExported": false,
        "aggregateShareMaterialExported": false,
        "layoutMessageMaterialExported": false,
        "encodedMessageMaterialExported": false,
        "encryptionRandomizerMaterialExported": false,
        "noiseMaterialExported": false,
    })
}

fn minimal_verify_request(bridge_encryption: Value) -> Value {
    json!({
        "aggregateDerivationComponent": {},
        "setupPackage": {},
        "bridgeEncryption": bridge_encryption,
        "aggregateSelectionPolicyDigest": "1".repeat(128),
        "bridgeWitnessPrivacyProfileDigest": "2".repeat(128),
        "heParamDigest": "3".repeat(128),
    })
}

fn sampled_relation_checks() -> Value {
    json!([
        {
            "position": 0,
            "modulus": 140737487306753_u64,
            "componentZeroCoefficient": 7,
            "componentOneCoefficient": 11,
            "relationMatches": true
        }
    ])
}

fn sampled_relation_check_policy() -> Value {
    json!({
        "objectType": "AggregateBridgeSampledRelationCheckPolicy",
        "objectVersion": 1,
        "diagnosticOnly": true,
        "acceptedForBridgeProofVerification": false,
        "fullBridgeProofRequired": true,
        "sampledOnlyBridgeVerificationAccepted": false,
        "relationCheckSource": "first-data-prime-diagnostic",
        "sampledRelationCheckCount": 1
    })
}

fn first_refusal_message(value: &Value) -> &str {
    value["refusedObjects"][0]["message"]
        .as_str()
        .expect("structural rejection should include a refusal message")
}

fn variant_statement(participant_count: u64, option_count: u64, width: u64) -> Value {
    json!({
        "participantCount": participant_count,
        "optionCount": option_count,
        "shareVectorWidth": width,
    })
}

#[test]
fn private_evaluator_variant_dimensions_accept_matrix_edges() {
    let minimum = bridge_variant_dimensions(&variant_statement(3, 2, 22))
        .expect("minimum matrix row should be accepted");
    assert_eq!(minimum.participant_count, 3);
    assert_eq!(minimum.option_count, 2);
    assert_eq!(minimum.share_vector_width, 22);
    assert_eq!(minimum.claim_tier, "micro-roster-outside-claim");

    let maximum = bridge_variant_dimensions(&variant_statement(20, 20, 220))
        .expect("maximum matrix row should be accepted");
    assert_eq!(maximum.participant_count, 20);
    assert_eq!(maximum.option_count, 20);
    assert_eq!(maximum.share_vector_width, 220);
    assert_eq!(maximum.claim_tier, "claim-candidate");
}

#[test]
fn private_evaluator_variant_dimensions_reject_outside_matrix() {
    for statement in [
        variant_statement(2, 2, 22),
        variant_statement(21, 2, 22),
        variant_statement(3, 1, 11),
        variant_statement(3, 21, 231),
        variant_statement(3, 20, 219),
    ] {
        let error = bridge_variant_dimensions(&statement)
            .expect_err("outside-matrix dimensions should reject");
        assert!(
            error.message.contains("M9 bridge"),
            "unexpected error: {error:?}"
        );
    }
}

#[test]
fn private_evaluator_rejects_public_artifact_drift() {
    let expected = json!({
        "ciphertextRoot": "1".repeat(128),
        "bridgeProofRoot": "2".repeat(128),
    });
    let mut actual = expected.clone();
    actual["ciphertextRoot"] = Value::String("3".repeat(128));
    let error = compare_bridge_relation_public_artifacts(&actual, &expected, "bridgeEncryption")
        .expect_err("mutated public artifact should reject");
    assert!(error.message.contains("ciphertextRoot"), "{error:?}");

    let mut with_extra_field = expected.clone();
    with_extra_field["unexpectedField"] = Value::Bool(true);
    let error =
        compare_bridge_relation_public_artifacts(&with_extra_field, &expected, "bridgeEncryption")
            .expect_err("extra public artifact field should reject");
    assert!(error.message.contains("unexpectedField"), "{error:?}");
}

#[test]
fn bridge_proof_target_contract_is_variant_parametric() {
    for width in [22_u64, 55, 220] {
        let target_contract =
            bridge_proof_target_contract_value(width, width).expect("target contract");
        let shared_witness_layout = target_contract["sharedWitnessLayout"]
            .as_object()
            .expect("shared witness layout should be an object");
        assert_eq!(
            target_contract["aggregateReducedCoordinateCount"],
            json!(width)
        );
        assert_eq!(
            target_contract["aggregateQuotientCoordinateCount"],
            json!(width)
        );
        assert_eq!(
            shared_witness_layout["aggregateIntegerShareCoordinateCount"],
            json!(width)
        );
        assert_eq!(
            shared_witness_layout["aggregateRelationRowCount"],
            json!(SHARE_COMMITMENT_MODULE_RANK as u64 + width)
        );
        assert_eq!(
            shared_witness_layout["sharedResponseScalarCount"],
            json!(3 * width + 64 + 4 * 32_768)
        );
        assert_eq!(target_contract["sharedWitnessCheckCount"], json!(2));
        assert_eq!(target_contract["sharedWitnessSoundnessBits"], json!(128));
        assert_eq!(
            target_contract["sharedWitnessZeroKnowledgeStatus"],
            json!(SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS)
        );
        assert_eq!(
            target_contract["bgvRandomnessBoundProofStatus"],
            json!(BGV_RANDOMNESS_BOUND_PROOF_STATUS)
        );
    }
}

#[test]
fn bridge_shared_witness_response_bound_rejects_out_of_range_response() {
    let response_bound = (BigInt::one() << 240_u32) - (BigInt::one() << 112_u32);
    let in_range = &response_bound - BigInt::one();
    shared_witness::validate_response_vector_bounds(
        "test",
        &[BigInt::from(0_u8), in_range.clone(), -&in_range],
    )
    .expect("in-range responses should be accepted");

    for response in [response_bound.clone(), -response_bound] {
        let error = shared_witness::validate_response_vector_bounds("test", &[response])
            .expect_err("out-of-range response should reject");
        assert!(
            error.message.contains("response exceeds"),
            "unexpected error: {error:?}"
        );
    }
}

#[test]
fn bridge_verifier_rejects_forged_checked_status_before_root_checks() {
    let result =
        verify_aggregate_bridge_encryption_from_command_request(&minimal_verify_request(json!({
            "bridgeProofVerificationStatus": "BridgeProofRelationChecked",
            "privateMaterialDisclosure": private_material_disclosure(),
            "sampledPublicRelationChecks": sampled_relation_checks(),
            "sampledPublicRelationCheckPolicy": sampled_relation_check_policy(),
        })));

    assert_eq!(result["ok"], false);
    assert!(
        first_refusal_message(&result).contains("bridgeProofBytesHex"),
        "{result}"
    );
}

#[test]
fn bridge_verifier_rejects_public_witness_fields_before_root_checks() {
    let result =
        verify_aggregate_bridge_encryption_from_command_request(&minimal_verify_request(json!({
            "bgvPlaintext": [1, 2, 3],
            "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
            "privateMaterialDisclosure": private_material_disclosure(),
        })));

    assert_eq!(result["ok"], false);
    assert!(
        first_refusal_message(&result).contains("bgvPlaintext"),
        "{result}"
    );
}

#[test]
fn bridge_verifier_rejects_private_material_disclosure_flags() {
    let mut disclosure = private_material_disclosure();
    disclosure["noiseMaterialExported"] = Value::Bool(true);
    let result =
        verify_aggregate_bridge_encryption_from_command_request(&minimal_verify_request(json!({
            "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
            "privateMaterialDisclosure": disclosure,
        })));

    assert_eq!(result["ok"], false);
    assert!(
        first_refusal_message(&result).contains("noiseMaterialExported"),
        "{result}"
    );
}

#[test]
fn bridge_proof_shell_requires_pending_relation_gap_status() {
    let proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeEncryptionEvidence",
        "privateMaterialDisclosure": private_material_disclosure(),
    });
    let error = validate_bridge_proof_public_shell(&proof_value)
        .expect_err("missing relation gap status should reject");

    assert!(
        error.message.contains("bridgeRelationGapStatus"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_target_contract_rejects_dimension_mutation() {
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
    });
    let target_contract = bridge_proof_target_contract_value(220, 220).expect("target contract");
    let target_contract_digest =
        bridge_proof_target_contract_digest(&target_contract).expect("target digest");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractDigest": target_contract_digest,
    });
    bridge_statement["bridgeProofTargetContract"]["aggregateReductionRowCount"] = json!(219);

    let error = validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect_err("mutated target contract should reject");

    assert!(
        error.message.contains("target contract does not match"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_target_contract_rejects_digest_mutation() {
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
    });
    let target_contract = bridge_proof_target_contract_value(220, 220).expect("target contract");
    let bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractDigest": "0".repeat(128),
    });

    let error = validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect_err("mutated target contract digest should reject");

    assert!(
        error
            .message
            .contains("bridge proof target contract digest"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_target_contract_rejects_separate_subproof_closure() {
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
    });
    let target_contract = bridge_proof_target_contract_value(220, 220).expect("target contract");
    let target_contract_digest =
        bridge_proof_target_contract_digest(&target_contract).expect("target digest");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractDigest": target_contract_digest,
    });
    bridge_statement["bridgeProofTargetContract"]["separateSubproofsAcceptedForClosure"] =
        json!(true);

    let error = validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect_err("separate subproof closure shortcut should reject");

    assert!(
        error.message.contains("target contract does not match"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_target_contract_rejects_shared_witness_layout_mutation() {
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
    });
    let target_contract = bridge_proof_target_contract_value(220, 220).expect("target contract");
    let target_contract_digest =
        bridge_proof_target_contract_digest(&target_contract).expect("target digest");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractDigest": target_contract_digest,
    });
    bridge_statement["bridgeProofTargetContract"]["sharedWitnessLayout"]["sharedResponseScalarCount"] =
        json!(164_563);

    let error = validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect_err("mutated shared-witness layout should reject");

    assert!(
        error.message.contains("target contract does not match"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_target_contract_rejects_shared_witness_layout_digest_mutation() {
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
    });
    let target_contract = bridge_proof_target_contract_value(220, 220).expect("target contract");
    let target_contract_digest =
        bridge_proof_target_contract_digest(&target_contract).expect("target digest");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractDigest": target_contract_digest,
    });
    bridge_statement["bridgeProofTargetContract"]["sharedWitnessLayoutDigest"] =
        json!("0".repeat(128));

    let error = validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect_err("mutated shared-witness layout digest should reject");

    assert!(
        error.message.contains("target contract does not match"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_shell_rejects_claimed_shared_witness_closure() {
    let mut relation_gap_status = bridge_relation_gap_status_value();
    relation_gap_status["sharedWitnessBindingStatus"] =
        Value::String("SharedWitnessBindingRelationChecked".to_string());
    let proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeEncryptionEvidence",
        "bridgeRelationGapStatus": relation_gap_status,
        "privateMaterialDisclosure": private_material_disclosure(),
    });
    let error = validate_bridge_proof_public_shell(&proof_value)
        .expect_err("claimed shared-witness closure should reject");

    assert!(
        error
            .message
            .contains("relation gap status must remain pending"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_shell_rejects_sampled_only_acceptance() {
    let mut relation_gap_status = bridge_relation_gap_status_value();
    relation_gap_status["sampledOnlyBridgeVerificationAccepted"] = Value::Bool(true);
    let proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeEncryptionEvidence",
        "bridgeRelationGapStatus": relation_gap_status,
        "privateMaterialDisclosure": private_material_disclosure(),
    });
    let error = validate_bridge_proof_public_shell(&proof_value)
        .expect_err("sampled-only acceptance should reject");

    assert!(
        error
            .message
            .contains("relation gap status must remain pending"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_shell_rejects_unsupported_bgv_boundedness_proof_bytes() {
    let proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeRelationProof",
        "bridgeSharedWitnessProof": {},
        "bgvRandomnessBoundProofBytesHex": "00",
        "privateMaterialDisclosure": private_material_disclosure(),
    });
    let error = validate_bridge_proof_public_shell(&proof_value).expect_err(
        "unsupported BGV boundedness proof bytes should reject while the proof is missing",
    );

    assert!(
        error.message.contains("bgvRandomnessBoundProofBytesHex"),
        "{error:?}"
    );
}

#[test]
fn bridge_verifier_rejects_sampled_relation_checks_as_acceptance() {
    let mut policy = sampled_relation_check_policy();
    policy["acceptedForBridgeProofVerification"] = Value::Bool(true);
    let result =
        verify_aggregate_bridge_encryption_from_command_request(&minimal_verify_request(json!({
            "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
            "privateMaterialDisclosure": private_material_disclosure(),
            "sampledPublicRelationChecks": sampled_relation_checks(),
            "sampledPublicRelationCheckPolicy": policy,
        })));

    assert_eq!(result["ok"], false);
    assert!(
        first_refusal_message(&result).contains("diagnostic-only"),
        "{result}"
    );
}

#[test]
fn bridge_verifier_rejects_failed_sampled_relation_diagnostic() {
    let mut relation_checks = sampled_relation_checks();
    relation_checks[0]["relationMatches"] = Value::Bool(false);
    let result =
        verify_aggregate_bridge_encryption_from_command_request(&minimal_verify_request(json!({
            "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
            "privateMaterialDisclosure": private_material_disclosure(),
            "sampledPublicRelationChecks": relation_checks,
            "sampledPublicRelationCheckPolicy": sampled_relation_check_policy(),
        })));

    assert_eq!(result["ok"], false);
    assert!(
        first_refusal_message(&result).contains("diagnostic only"),
        "{result}"
    );
}
