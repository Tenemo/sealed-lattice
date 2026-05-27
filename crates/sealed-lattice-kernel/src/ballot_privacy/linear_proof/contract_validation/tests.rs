use super::*;

fn digest(label: &str) -> String {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "label": label,
            "purpose": "linear-proof-contract-validation-test",
        }),
    )
    .expect("test digest should derive")
}

fn full_binding_linear_statement() -> Value {
    json!({
        "ballotProofStatementDigest": digest("ballot-proof-statement"),
        "coefficientModulus": "65537",
        "componentBundleStatementDigest": digest("component-bundle-statement"),
        "objectType": "BallotProofLinearProofStatement",
        "objectVersion": 1,
        "parameterProfileId": FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
        "projectionCoverage": FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "relation": "A*w + t = 0",
        "relationBindingDigest": digest("relation-binding"),
        "relationBindingKind": "component-bundle-and-lowered-relation",
        "ringDegree": 64,
        "statementColumns": 1,
        "statementRows": 1,
        "witnessL2BoundSquared": "65536",
    })
}

fn constant_polynomial(constant: u64) -> Value {
    Value::Array(
        (0..64)
            .map(|coefficient_index| {
                if coefficient_index == 0 {
                    json!(constant)
                } else {
                    json!(0)
                }
            })
            .collect(),
    )
}

fn test_component_statement(component_id: &str, component_digest_label: &str) -> Value {
    json!({
        "coefficientModulus": "65537",
        "componentDigest": digest(component_digest_label),
        "componentId": component_id,
        "proofLoweringStatus": "Lowered",
        "rowBatchNames": ["test rows"],
        "rowCount": 1,
        "rowKinds": ["test-row-kind"],
        "variableColumnCount": 2,
        "variableColumnIndices": [0, 1],
    })
}

fn full_relation_component_bundle_statement() -> Value {
    let mut component_bundle_statement = json!({
        "backendStatementDigest": digest("backend-statement"),
        "ballotProofStatementDigest": digest("ballot-proof-statement"),
        "bundleCoverage": FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "componentStatements": [
            test_component_statement("score-and-shamir-field-component", "score-component"),
            test_component_statement("payload-plaintext-field-component", "payload-component"),
            test_component_statement("share-commitment-component", "share-component"),
            test_component_statement("receiver-encryption-component", "receiver-encryption-component"),
            test_component_statement("receiver-key-binding-component", "receiver-key-binding-component"),
        ],
        "objectType": "BallotProofComponentBundleStatement",
        "objectVersion": 1,
        "relationLabel": "BallotPrivacyPvssRelation",
        "relationStatementDigest": digest("relation-statement"),
        "requiredComponentIds": REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
    });
    let component_bundle_statement_digest =
        derive_ballot_component_bundle_statement_digest(&component_bundle_statement)
            .expect("component bundle statement digest should derive");
    component_bundle_statement
        .as_object_mut()
        .expect("component bundle statement should be an object")
        .insert(
            "componentBundleStatementDigest".to_string(),
            json!(component_bundle_statement_digest),
        );

    component_bundle_statement
}

fn full_relation_bound_linear_statement(component_bundle_statement: &Value) -> Value {
    let mut linear_statement = full_binding_linear_statement();
    let relation_binding_digest = derive_full_relation_binding_digest(component_bundle_statement)
        .expect("full relation binding digest should derive");
    let binding_scalar = binding_scalar_from_digest(&relation_binding_digest)
        .expect("binding scalar should derive from digest");
    let target_constant = FULL_BALLOT_BINDING_COEFFICIENT_MODULUS - binding_scalar;

    let linear_statement_object = linear_statement
        .as_object_mut()
        .expect("linear statement should be an object");
    linear_statement_object.insert(
        "componentBundleStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "componentBundleStatementDigest")
                .expect("component bundle statement should have a digest")
        ),
    );
    linear_statement_object.insert(
        "relationBindingDigest".to_string(),
        json!(relation_binding_digest),
    );
    linear_statement_object.insert(
        "statementMatrixCoefficients".to_string(),
        json!([[constant_polynomial(1)]]),
    );
    linear_statement_object.insert(
        "targetVectorCoefficients".to_string(),
        json!([constant_polynomial(target_constant)]),
    );

    linear_statement
}

fn full_binding_parameter_set(source: &str) -> Value {
    json!({
        "coefficientModulus": "65537",
        "expectedProofSizeBytes": 10,
        "profileId": FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
        "proofSystemRingDegree": 64,
        "relation": "A*w + t = 0",
        "ringDegree": 64,
        "source": source,
        "statementColumns": 1,
        "statementRows": 1,
        "witnessL2BoundSquared": "65536",
    })
}

fn full_binding_encoding(source: &str) -> Value {
    json!({
        "challengeCoefficientBitLength": 5,
        "challengeCoefficientModulus": 17,
        "coefficientModulus": "70368744177829",
        "compressedCoefficientBitLength": 35,
        "compressedCommitmentVectorLength": 18,
        "euclideanResponseLog2StandardDeviation": 14,
        "euclideanResponseVectorLength": 4,
        "expectedProofSizeBytes": 10,
        "fullSizeCoefficientBitLength": 47,
        "hashMaskVectorLength": 2,
        "hintVectorLength": 18,
        "infinityResponseLog2StandardDeviation": 22,
        "infinityResponseVectorLength": 4,
        "profileId": FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
        "randomnessResponseLog2StandardDeviation": 12,
        "randomnessResponseVectorLength": 41,
        "ringDegree": 64,
        "shortResponseLog2StandardDeviation": 18,
        "shortResponseVectorLength": 2,
        "source": source,
        "targetCommitmentVectorLength": 12,
    })
}

fn statement_with_dimensions(option_count: u128, participant_count: usize) -> Value {
    let statement = json!({
        "optionCount": option_count,
        "receiverPayloads": vec![json!({}); participant_count],
        "receiverPublicKeys": vec![json!({}); participant_count],
        "shareCommitments": vec![json!({}); participant_count],
        "shareVectorWidth": option_count * u128::from(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION),
        "thresholdProfileDigest": digest("threshold-profile"),
    });

    statement
}

fn dynamic_roster_profile_evidence(statement: &Value) -> Value {
    let mut evidence = json!({
        "dynamicRosterProfileCertificateDigest": digest("dynamic-roster-certificate"),
        "frozenRosterSize": array_field(statement, "receiverPublicKeys")
            .expect("receiver keys should exist")
            .len(),
        "objectType": "BallotPrivacyRosterProfileEvidence",
        "objectVersion": 1,
        "optionCount": unsigned_integer_field(statement, "optionCount")
            .expect("option count should exist"),
        "profileFamily": "BalancedDefault",
        "proofStatementShape": "EncodedScoreBallotProof-v1",
        "receiverCoverageProfile": "AllFrozenRosterReceivers",
        "thresholdProfileDigest": string_field(statement, "thresholdProfileDigest")
            .expect("threshold profile digest should exist"),
    });
    let evidence_digest = derive_digest("BallotPrivacyRosterProfileEvidenceDigest", &evidence)
        .expect("dynamic roster evidence digest should derive");
    evidence
        .as_object_mut()
        .expect("dynamic roster evidence should be an object")
        .insert(
            "rosterProfileEvidenceDigest".to_string(),
            json!(evidence_digest),
        );

    evidence
}

#[test]
fn binding_scalar_is_a_small_compatibility_coefficient_not_a_soundness_challenge() {
    assert_eq!(
        binding_scalar_from_digest(&format!("{}{}", "0".repeat(16), "1".repeat(112))),
        Some(1)
    );
    assert_eq!(
        binding_scalar_from_digest(&format!("{}{}", "ffffffffffffffff", "1".repeat(112))),
        Some(1 + (u64::MAX % FULL_BALLOT_BINDING_COMPATIBILITY_SCALAR_COUNT))
    );
}

#[test]
fn supported_ballot_privacy_dimensions_accept_mandatory_range() {
    let statement = statement_with_dimensions(2, 20);
    assert!(
        collect_supported_ballot_privacy_dimension_refusals(
            &statement,
            Some(&digest("package")),
            None,
            false,
            false,
        )
        .is_empty()
    );
}

#[test]
fn supported_ballot_privacy_dimensions_require_casual_micro_roster_acknowledgement() {
    for participant_count in 3..10 {
        let statement = statement_with_dimensions(20, participant_count);
        let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
            &statement,
            Some(&digest("package")),
            None,
            false,
            false,
        );

        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("casual micro-roster"))),
            "unacknowledged casual micro roster must be rejected for participant count {participant_count}: {refused_objects:?}"
        );
        assert!(
            collect_supported_ballot_privacy_dimension_refusals(
                &statement,
                Some(&digest("package")),
                None,
                false,
                true,
            )
            .is_empty(),
            "acknowledged non-claim micro roster must be accepted for participant count {participant_count}"
        );

        let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
            &statement,
            Some(&digest("package")),
            None,
            true,
            true,
        );
        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("at least ten frozen participants"))),
            "claim-bearing micro roster must be rejected for participant count {participant_count}: {refused_objects:?}"
        );
    }
}

#[test]
fn supported_ballot_privacy_dimensions_require_dynamic_roster_evidence() {
    let statement = statement_with_dimensions(20, 16);
    let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
        &statement,
        Some(&digest("package")),
        None,
        false,
        false,
    );
    assert!(
        refused_objects
            .iter()
            .any(|refusal| string_field(refusal, "message")
                .is_some_and(|message| message.contains("roster profile parameter certificate"))),
        "dynamic receiver count without evidence must be rejected: {refused_objects:?}"
    );

    let dynamic_roster_evidence = dynamic_roster_profile_evidence(&statement);
    let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
        &statement,
        Some(&digest("package")),
        Some(&dynamic_roster_evidence),
        true,
        false,
    );
    assert!(
        refused_objects
            .iter()
            .any(|refusal| string_field(refusal, "message").is_some_and(
                |message| message.contains("approved roster profile parameter certificate")
            )),
        "self-asserted dynamic roster evidence must be rejected: {refused_objects:?}"
    );
}

#[test]
fn supported_ballot_privacy_dimensions_reject_out_of_range_values() {
    for (mut statement, expected_message) in [
        (statement_with_dimensions(1, 20), "two to twenty options"),
        (statement_with_dimensions(21, 20), "two to twenty options"),
        (
            statement_with_dimensions(20, 2),
            "three to fifty participants",
        ),
        (
            statement_with_dimensions(20, 51),
            "three to fifty participants",
        ),
    ] {
        if expected_message == "two to twenty options" {
            statement["shareVectorWidth"] = json!(220);
        }
        let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
            &statement,
            Some(&digest("package")),
            None,
            false,
            true,
        );

        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains(expected_message))),
            "invalid dimensions must be rejected: {refused_objects:?}"
        );
    }

    let mut statement = statement_with_dimensions(20, 20);
    statement["shareVectorWidth"] = json!(219);
    let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
        &statement,
        Some(&digest("package")),
        None,
        false,
        false,
    );
    assert!(
        refused_objects
            .iter()
            .any(|refusal| string_field(refusal, "message")
                .is_some_and(|message| message.contains("shareVectorWidth"))),
        "wrong share vector width must be rejected: {refused_objects:?}"
    );
}

#[test]
fn full_binding_contract_rejects_mutated_profile_source() {
    let linear_statement = full_binding_linear_statement();
    let parameter_set =
        full_binding_parameter_set("sealed-lattice/linear-proof/unfrozen-parameters-v1");
    let proof_encoding = full_binding_encoding(FULL_BALLOT_BINDING_ENCODING_SOURCE);

    let refused_objects = collect_full_ballot_binding_contract_refusals(
        &linear_statement,
        &parameter_set,
        &proof_encoding,
        Some(10),
        Some(&digest("proof-record")),
    );

    assert!(
        refused_objects
            .iter()
            .any(|refusal| string_field(refusal, "message")
                .is_some_and(|message| message.contains("parameter set does not match"))),
        "mutated parameter source must be rejected: {refused_objects:?}"
    );
}

#[test]
fn full_binding_contract_requires_component_bundle_binding() {
    let mut linear_statement = full_binding_linear_statement();
    let linear_statement_object = linear_statement
        .as_object_mut()
        .expect("linear statement should be an object");
    linear_statement_object.remove("relationBindingKind");
    let parameter_set = full_binding_parameter_set(FULL_BALLOT_BINDING_PARAMETER_SOURCE);
    let proof_encoding = full_binding_encoding(FULL_BALLOT_BINDING_ENCODING_SOURCE);

    let refused_objects = collect_full_ballot_binding_contract_refusals(
        &linear_statement,
        &parameter_set,
        &proof_encoding,
        Some(10),
        Some(&digest("proof-record")),
    );

    assert!(
        refused_objects
            .iter()
            .any(|refusal| string_field(refusal, "message")
                .is_some_and(|message| message.contains("component bundle"))),
        "missing relation binding metadata must be rejected: {refused_objects:?}"
    );
}

#[test]
fn full_relation_binding_accepts_derived_component_bundle_binding() {
    let component_bundle_statement = full_relation_component_bundle_statement();
    let linear_statement = full_relation_bound_linear_statement(&component_bundle_statement);

    assert!(
        collect_full_ballot_relation_binding_refusals(
            &linear_statement,
            Some(&component_bundle_statement),
            Some(&digest("proof-record")),
        )
        .is_empty()
    );
}

#[test]
fn full_relation_binding_rejects_mutated_relation_binding_digest() {
    let component_bundle_statement = full_relation_component_bundle_statement();
    let mut linear_statement = full_relation_bound_linear_statement(&component_bundle_statement);
    linear_statement
        .as_object_mut()
        .expect("linear statement should be an object")
        .insert(
            "relationBindingDigest".to_string(),
            json!(digest("wrong-relation-binding")),
        );

    let refused_objects = collect_full_ballot_relation_binding_refusals(
        &linear_statement,
        Some(&component_bundle_statement),
        Some(&digest("proof-record")),
    );

    assert!(
        refused_objects
            .iter()
            .any(|refusal| string_field(refusal, "message")
                .is_some_and(|message| message.contains("relation binding digest"))),
        "mutated relation binding digest must be rejected: {refused_objects:?}"
    );
}

#[test]
fn full_relation_binding_rejects_mutated_derived_target() {
    let component_bundle_statement = full_relation_component_bundle_statement();
    let mut linear_statement = full_relation_bound_linear_statement(&component_bundle_statement);
    linear_statement["targetVectorCoefficients"][0][0] = json!(0);

    let refused_objects = collect_full_ballot_relation_binding_refusals(
        &linear_statement,
        Some(&component_bundle_statement),
        Some(&digest("proof-record")),
    );

    assert!(
        refused_objects
            .iter()
            .any(|refusal| string_field(refusal, "message")
                .is_some_and(|message| message.contains("matrix and target"))),
        "mutated derived target must be rejected: {refused_objects:?}"
    );
}
