use super::*;
use super::{
    dimensions::bridge_variant_dimensions,
    evaluation::compare_bridge_relation_public_artifacts,
    target_contract::{
        bridge_proof_target_contract_hash, bridge_proof_target_contract_value,
        validate_bridge_proof_target_contract,
    },
    validation::{
        validate_bridge_proof_public_shell, validate_bridge_randomness_source,
        validate_bridge_randomness_source_evidence,
        validate_development_randomness_acknowledgement,
    },
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
    let mut bridge_encryption = bridge_encryption;
    if let Some(object) = bridge_encryption.as_object_mut() {
        object.insert(
            "bgvEncryptionKeyMaterialKind".to_string(),
            Value::String(BGV_ENCRYPTION_KEY_MATERIAL_KIND.to_string()),
        );
        object.insert(
            "developmentKeyOnly".to_string(),
            Value::Bool(DEVELOPMENT_KEY_ONLY),
        );
        object.insert(
            "thresholdDecryptable".to_string(),
            Value::Bool(THRESHOLD_DECRYPTABLE),
        );
        object.insert(
            "claimBearingBridgeEncryption".to_string(),
            Value::Bool(CLAIM_BEARING_BRIDGE_ENCRYPTION),
        );
    }
    json!({
        "aggregateDerivationComponent": {},
        "setupPackage": {},
        "bridgeEncryption": bridge_encryption,
        "aggregateSelectionPolicyHash": "1".repeat(128),
        "bridgeWitnessPrivacyProfileHash": "2".repeat(128),
        "heParamHash": "3".repeat(128),
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

fn target_contract_relation_requirements() -> Value {
    json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
        "aggregateDerivationVerificationScope": AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    })
}

fn minimal_checked_relation_proof_value() -> Value {
    json!({
        "objectType": "SealedLatticeAggregateBridgeRelationProof",
        "bridgeSharedWitnessProof": {},
        "scopedBridgeRelationClosure": false,
        "finalBridgeTheoremClosure": false,
        "bridgeClaimClosureVerified": false,
        "bridgeClaimVerificationStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
        "privateMaterialDisclosure": private_material_disclosure(),
    })
}

fn minimal_checked_relation_proof_bytes_hex() -> String {
    let proof_value = minimal_checked_relation_proof_value();

    to_hex(
        canonical_json(&proof_value)
            .expect("minimal proof value should serialize")
            .as_bytes(),
    )
}

fn bridge_proof_bytes_hash(proof_bytes_hex: &str) -> String {
    derive_protocol_hash(
        "ProofBytesHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1",
            "proofBytesHex": proof_bytes_hex,
        }),
    )
    .expect("proof bytes hash should derive")
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
            error.message.contains("encrypted aggregate bridge"),
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
        let target_contract = bridge_proof_target_contract_value(
            width,
            width,
            AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
        )
        .expect("target contract");
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
            json!(3 * width + 64 + 5 * 32_768)
        );
        assert_eq!(target_contract["sharedWitnessCheckCount"], json!(2));
        assert_eq!(
            target_contract["sharedWitnessChallengeEntropyBits"],
            json!(128)
        );
        assert_eq!(
            target_contract["sharedWitnessWeakestRelation"],
            json!(PLAINTEXT_ENCODING_RELATION)
        );
        assert_eq!(
            target_contract["sharedWitnessWeakestRelationModuli"],
            json!(BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI)
        );
        assert_eq!(
            target_contract["sharedWitnessWeakestRelationModulusProduct"],
            json!(bridge_batch_integer_lift_proof_modulus_product_decimal())
        );
        assert_eq!(
            target_contract["plaintextEncodingProofModuli"],
            json!(BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI)
        );
        assert_eq!(
            target_contract["plaintextEncodingProofModulusProductBitsFloor"],
            json!(93)
        );
        assert_eq!(
            target_contract["sharedWitnessEffectiveBindingSoundnessBitsFloor"],
            json!(165)
        );
        assert_eq!(
            target_contract["sharedWitnessRejectionAttemptLimit"],
            json!(64)
        );
        assert_eq!(
            target_contract["sharedWitnessGrindingDiscountBitsPerCheck"],
            json!(6)
        );
        assert_eq!(
            target_contract["sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor"],
            json!(186)
        );
        assert_eq!(
            target_contract["sharedWitnessFullMatrixUnionBoundBits"],
            json!(9)
        );
        assert_eq!(
            target_contract["sharedWitnessEffectiveBindingBelowTarget"],
            json!(false)
        );
        assert_eq!(
            target_contract["bgvEncryptionKeyMaterialKind"],
            json!(BGV_ENCRYPTION_KEY_MATERIAL_KIND)
        );
        assert_eq!(target_contract["developmentKeyOnly"], json!(false));
        assert_eq!(target_contract["thresholdDecryptable"], json!(true));
        assert_eq!(
            target_contract["claimBearingBridgeEncryption"],
            json!(false)
        );
        assert_eq!(
            target_contract["sharedWitnessZeroKnowledgeStatus"],
            json!(SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS)
        );
        assert_eq!(
            target_contract["bgvRandomnessBoundProofStatus"],
            json!(BGV_RANDOMNESS_BOUND_PROOF_STATUS)
        );
        assert_eq!(
            target_contract["plaintextCanonicalLiftProofStatus"],
            json!(PLAINTEXT_CANONICAL_LIFT_PROOF_CHECKED_STATUS)
        );
        assert_eq!(
            target_contract["aggregateDerivationVerificationScope"],
            json!(AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS)
        );
    }
}

#[test]
fn bridge_proof_target_contract_soundness_uses_weakest_relation_modulus() {
    let target_contract = bridge_proof_target_contract_value(
        220,
        220,
        AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    )
    .expect("target contract");
    let relation_modulus_product_bits_floor =
        127_u64 - BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT.leading_zeros() as u64;
    let unadjusted_weakest_relation_soundness =
        relation_modulus_product_bits_floor * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
    let retry_loss = SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK
        * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
    let effective_soundness = unadjusted_weakest_relation_soundness
        - retry_loss
        - BRIDGE_FULL_MATRIX_UNION_BOUND_BITS
        - BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS
        - BRIDGE_PROOF_SYSTEM_LOSS_BITS
        - BRIDGE_CHALLENGE_BIAS_BITS;

    assert_eq!(relation_modulus_product_bits_floor, 93);
    assert_eq!(
        target_contract["plaintextEncodingProofModulusProductBitsFloor"],
        json!(relation_modulus_product_bits_floor)
    );
    assert_eq!(
        target_contract["sharedWitnessChallengeEntropyBits"],
        json!(BRIDGE_SHARED_WITNESS_CHALLENGE_ENTROPY_BITS)
    );
    assert_eq!(
        target_contract["sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor"],
        json!(unadjusted_weakest_relation_soundness)
    );
    assert_eq!(
        target_contract["sharedWitnessRejectionRetryLossBits"],
        json!(retry_loss)
    );
    assert_eq!(
        target_contract["sharedWitnessEffectiveBindingSoundnessBitsFloor"],
        json!(effective_soundness)
    );
    assert!(
        effective_soundness >= BRIDGE_TARGET_BINDING_SOUNDNESS_BITS,
        "effective same-witness binding soundness must meet target"
    );
    assert_ne!(
        effective_soundness,
        BRIDGE_SHARED_WITNESS_CHALLENGE_ENTROPY_BITS
            - BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS
            - BRIDGE_FULL_MATRIX_UNION_BOUND_BITS,
        "bridge soundness must not be derived from challenge entropy alone"
    );
}

#[test]
fn bridge_proof_target_contract_binds_aggregate_derivation_scope() {
    let target_contract = bridge_proof_target_contract_value(
        220,
        220,
        AGGREGATE_DERIVATION_FULL_VERIFICATION_CHECKED_STATUS,
    )
    .expect("target contract with checked aggregate derivation scope");
    let target_contract_hash =
        bridge_proof_target_contract_hash(&target_contract).expect("target hash");
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
        "aggregateDerivationVerificationScope": AGGREGATE_DERIVATION_FULL_VERIFICATION_CHECKED_STATUS,
    });
    let bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractHash": target_contract_hash,
    });

    validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect("checked aggregate-derivation scope should validate");

    let mismatched_relation_requirements = json!({
        "aggregateReducedCoordinateCount": 220,
        "aggregateQuotientCoordinateCount": 220,
        "aggregateDerivationVerificationScope": AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    });
    let error =
        validate_bridge_proof_target_contract(&bridge_statement, &mismatched_relation_requirements)
            .expect_err("aggregate derivation scope mismatch should reject");
    assert!(
        error.message.contains("target contract does not match"),
        "{error:?}"
    );
}

#[test]
fn bridge_randomness_sources_require_explicit_development_acknowledgement() {
    assert!(validate_bridge_randomness_source("fresh-csprng", "proverRandomnessSource").is_ok());
    assert!(
        validate_bridge_randomness_source(
            "development-deterministic-fixture",
            "proverRandomnessSource",
        )
        .is_ok()
    );
    assert!(validate_bridge_randomness_source("seed", "proverRandomnessSource").is_err());
    assert!(
        validate_development_randomness_acknowledgement(
            &json!({}),
            "development-deterministic-fixture",
            "fresh-csprng",
            "bridgeRequest",
        )
        .is_err()
    );
    assert!(
        validate_development_randomness_acknowledgement(
            &json!({
                "developmentRandomnessOverrideAcknowledged": true,
            }),
            "fresh-csprng",
            "development-deterministic-fixture",
            "bridgeRequest",
        )
        .is_ok()
    );
    assert!(
        validate_development_randomness_acknowledgement(
            &json!({}),
            "fresh-csprng",
            "fresh-csprng",
            "bridgeRequest",
        )
        .is_ok()
    );
}

#[test]
fn bridge_randomness_source_evidence_must_match_sources() {
    let fresh_entropy_evidence = json!({
        "objectType": "AggregateBridgeRandomnessSourceEvidence",
        "objectVersion": 1,
        "proverRandomnessSource": "fresh-csprng",
        "encryptionRandomnessSeedSource": "fresh-csprng",
        "callerSuppliedDevelopmentRandomness": false,
        "claimBearingEntropyEvidence": true,
    });
    validate_bridge_randomness_source_evidence(
        &fresh_entropy_evidence,
        "fresh-csprng",
        "fresh-csprng",
        "test.randomnessSourceEvidence",
    )
    .expect("fresh CSPRNG evidence should validate");

    let development_entropy_evidence = json!({
        "objectType": "AggregateBridgeRandomnessSourceEvidence",
        "objectVersion": 1,
        "proverRandomnessSource": "development-deterministic-fixture",
        "encryptionRandomnessSeedSource": "fresh-csprng",
        "callerSuppliedDevelopmentRandomness": true,
        "claimBearingEntropyEvidence": false,
    });
    validate_bridge_randomness_source_evidence(
        &development_entropy_evidence,
        "development-deterministic-fixture",
        "fresh-csprng",
        "test.randomnessSourceEvidence",
    )
    .expect("development evidence should validate only as non-claim-bearing entropy");

    for (mutated_field, mutated_value, expected_message) in [
        (
            "objectType",
            Value::String("WrongRandomnessEvidence".to_string()),
            "aggregate bridge randomness source evidence",
        ),
        (
            "proverRandomnessSource",
            Value::String("development-deterministic-fixture".to_string()),
            "prover source",
        ),
        (
            "callerSuppliedDevelopmentRandomness",
            Value::Bool(true),
            "development flag",
        ),
        (
            "claimBearingEntropyEvidence",
            Value::Bool(false),
            "claim-bearing entropy flag",
        ),
    ] {
        let mut evidence = fresh_entropy_evidence.clone();
        evidence[mutated_field] = mutated_value;
        let error = validate_bridge_randomness_source_evidence(
            &evidence,
            "fresh-csprng",
            "fresh-csprng",
            "test.randomnessSourceEvidence",
        )
        .expect_err("mutated randomness source evidence should reject");

        assert!(
            error.message.contains(expected_message),
            "{mutated_field}: {error:?}"
        );
    }

    let mut evidence_with_extra_field = fresh_entropy_evidence;
    evidence_with_extra_field["entropyOracleClaim"] = Value::Bool(true);
    let error = validate_bridge_randomness_source_evidence(
        &evidence_with_extra_field,
        "fresh-csprng",
        "fresh-csprng",
        "test.randomnessSourceEvidence",
    )
    .expect_err("extra entropy evidence field should reject");
    assert!(error.message.contains("entropyOracleClaim"), "{error:?}");
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
fn bridge_verifier_rejects_proof_bytes_hash_before_setup_checks() {
    let proof_bytes_hex = minimal_checked_relation_proof_bytes_hex();
    let result =
        verify_aggregate_bridge_encryption_from_command_request(&minimal_verify_request(json!({
            "bridgeProofBytesHash": "4".repeat(128),
            "bridgeProofBytesHex": proof_bytes_hex,
            "bridgeProofVerificationStatus": BRIDGE_PROOF_CHECKED_STATUS,
            "canonicalBytesHex": "00",
            "privateMaterialDisclosure": private_material_disclosure(),
            "sampledPublicRelationChecks": sampled_relation_checks(),
            "sampledPublicRelationCheckPolicy": sampled_relation_check_policy(),
        })));

    assert_eq!(result["ok"], false);
    assert!(
        first_refusal_message(&result).contains("bridge proof bytes hash"),
        "{result}"
    );
}

#[test]
fn bridge_verifier_rejects_pending_status_before_setup_checks() {
    let proof_bytes_hex = minimal_checked_relation_proof_bytes_hex();
    let result =
        verify_aggregate_bridge_encryption_from_command_request(&minimal_verify_request(json!({
            "bridgeProofBytesHash": bridge_proof_bytes_hash(&proof_bytes_hex),
            "bridgeProofBytesHex": proof_bytes_hex,
            "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
            "canonicalBytesHex": "00",
            "privateMaterialDisclosure": private_material_disclosure(),
            "sampledPublicRelationChecks": sampled_relation_checks(),
            "sampledPublicRelationCheckPolicy": sampled_relation_check_policy(),
        })));

    assert_eq!(result["ok"], false);
    assert!(
        first_refusal_message(&result).contains("verifier-checked bridge encryption status"),
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
    let relation_requirements = target_contract_relation_requirements();
    let target_contract = bridge_proof_target_contract_value(
        220,
        220,
        AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    )
    .expect("target contract");
    let target_contract_hash =
        bridge_proof_target_contract_hash(&target_contract).expect("target hash");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractHash": target_contract_hash,
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
fn bridge_proof_target_contract_rejects_hash_mutation() {
    let relation_requirements = target_contract_relation_requirements();
    let target_contract = bridge_proof_target_contract_value(
        220,
        220,
        AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    )
    .expect("target contract");
    let bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractHash": "0".repeat(128),
    });

    let error = validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect_err("mutated target contract hash should reject");

    assert!(
        error.message.contains("bridge proof target contract hash"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_target_contract_rejects_separate_subproof_closure() {
    let relation_requirements = target_contract_relation_requirements();
    let target_contract = bridge_proof_target_contract_value(
        220,
        220,
        AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    )
    .expect("target contract");
    let target_contract_hash =
        bridge_proof_target_contract_hash(&target_contract).expect("target hash");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractHash": target_contract_hash,
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
    let relation_requirements = target_contract_relation_requirements();
    let target_contract = bridge_proof_target_contract_value(
        220,
        220,
        AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    )
    .expect("target contract");
    let target_contract_hash =
        bridge_proof_target_contract_hash(&target_contract).expect("target hash");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractHash": target_contract_hash,
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
fn bridge_proof_target_contract_rejects_shared_witness_layout_hash_mutation() {
    let relation_requirements = target_contract_relation_requirements();
    let target_contract = bridge_proof_target_contract_value(
        220,
        220,
        AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
    )
    .expect("target contract");
    let target_contract_hash =
        bridge_proof_target_contract_hash(&target_contract).expect("target hash");
    let mut bridge_statement = json!({
        "bridgeProofTargetContract": target_contract,
        "bridgeProofTargetContractHash": target_contract_hash,
    });
    bridge_statement["bridgeProofTargetContract"]["sharedWitnessLayoutHash"] =
        json!("0".repeat(128));

    let error = validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
        .expect_err("mutated shared-witness layout hash should reject");

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
    let mut proof_value = minimal_checked_relation_proof_value();
    proof_value["bgvRandomnessBoundProofBytesHex"] = Value::String("00".to_string());
    let error = validate_bridge_proof_public_shell(&proof_value).expect_err(
        "unsupported BGV boundedness proof bytes should reject while the proof is missing",
    );

    assert!(
        error.message.contains("bgvRandomnessBoundProofBytesHex"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_shell_rejects_unknown_nested_shared_witness_fields() {
    let mut proof_value = minimal_checked_relation_proof_value();
    proof_value["bridgeSharedWitnessProof"] = json!({
        "objectType": "AggregateBridgeSharedWitnessProof",
        "checks": [
            {
                "checkIndex": 0,
                "novelWitnessLeak": "not accepted"
            }
        ]
    });
    let error = validate_bridge_proof_public_shell(&proof_value)
        .expect_err("unknown nested shared-witness fields should reject");

    assert!(error.message.contains("novelWitnessLeak"), "{error:?}");
}

#[test]
fn bridge_proof_shell_rejects_bgv_side_duplicate_aggregate_response() {
    let mut proof_value = minimal_checked_relation_proof_value();
    proof_value["bridgeSharedWitnessProof"] = json!({
        "objectType": "AggregateBridgeSharedWitnessProof",
        "checks": [
            {
                "checkIndex": 0,
                "bgvAggregateReducedResponseHex": "00"
            }
        ]
    });
    let error = validate_bridge_proof_public_shell(&proof_value)
        .expect_err("duplicate BGV-side aggregate response should reject");

    assert!(
        error.message.contains("bgvAggregateReducedResponseHex"),
        "{error:?}"
    );
}

#[test]
fn bridge_proof_shell_rejects_closure_field_injection() {
    for (field_name, injected_value, expected_message) in [
        (
            "scopedBridgeRelationClosure",
            Value::Bool(true),
            "scoped bridge relation closure flag",
        ),
        (
            "finalBridgeTheoremClosure",
            Value::Bool(true),
            "final bridge theorem closure flag",
        ),
        (
            "bridgeClaimClosureVerified",
            Value::Bool(true),
            "bridge claim closure flag",
        ),
        (
            "bridgeClaimVerificationStatus",
            Value::String("BridgeProofClaimClosureVerified".to_string()),
            "bridge claim verification status",
        ),
    ] {
        let mut proof_value = minimal_checked_relation_proof_value();
        proof_value[field_name] = injected_value;
        let error = validate_bridge_proof_public_shell(&proof_value)
            .expect_err("closure-field injection should reject");

        assert!(
            error.message.contains(expected_message),
            "{field_name}: {error:?}"
        );
    }
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
