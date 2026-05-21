use super::*;
use crate::ballot_privacy::linear_proof_profile_constants::{
    DEMO_GENERATED_PARAMETER_CONTRACT, DEMO_GENERATED_PROFILE,
};

#[test]
fn proof_byte_bearing_ballot_record_rejects_without_full_relation_coverage() {
    let vectors: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
    )))
    .expect("linear proof vector file should parse");
    let cases = vectors["cases"]
        .as_array()
        .expect("linear proof vector file should contain cases");
    let valid_case = cases
        .iter()
        .find(|vector_case| vector_case["caseName"] == "valid-small-linear-proof")
        .expect("valid linear vector should exist");
    let mutated_target_case = cases
        .iter()
        .find(|vector_case| vector_case["caseName"] == "mutated-target-vector")
        .expect("mutated target vector should exist");
    let proof_bytes_hex = valid_case["proofHex"]
        .as_str()
        .expect("valid vector proofHex should be a string");
    let public_randomness_hex = valid_case["publicRandomnessHex"]
        .as_str()
        .expect("valid vector publicRandomnessHex should be a string");
    let proof_size_bytes = proof_bytes_hex.len() / 2;
    let test_digest = |label: &str| {
        super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "label": label,
                "purpose": "ballot-proof-record-native-test"
            }),
        )
        .expect("test digest should derive")
    };
    let create_statement = || {
        let receiver_public_keys = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPublicKeyDigest": test_digest(&format!("receiver-public-key-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let receiver_payloads = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPayloadCiphertextRoot": test_digest(&format!("receiver-ciphertext-{receiver_roster_position}")),
                    "receiverPayloadDigest": test_digest(&format!("receiver-payload-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let share_commitments = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverRosterPosition": receiver_roster_position,
                    "shareCommitmentDigest": test_digest(&format!("share-commitment-{receiver_roster_position}"))
                })
            })
            .collect::<Vec<_>>();
        let statement_payload = json!({
            "actionContextDigest": test_digest("action-context"),
            "aggregateInputEncodingProfileDigest": test_digest("aggregate-input-encoding-profile"),
            "ballotPackageDigest": test_digest("ballot-package"),
            "ballotProofProfileDigest": test_digest("ballot-proof-profile"),
            "ballotScoreEncodingProfileDigest": test_digest("ballot-score-encoding-profile"),
            "ballotShareLayoutProfileDigest": test_digest("ballot-share-layout-profile"),
            "ceremonyId": "ceremony-ballot-proof-record",
            "challengeDomainDigest": test_digest("challenge-domain"),
            "duplicateBallotPolicyDigest": test_digest("duplicate-policy"),
            "encodedAggregateLayoutDigest": test_digest("encoded-aggregate-layout"),
            "encodedShareVectorLayoutDigest": test_digest("encoded-share-vector-layout"),
            "manifestDigest": test_digest("manifest"),
            "objectType": "BallotProofStatement",
            "objectVersion": 1,
            "optionCount": 20,
            "pollSpecDigest": test_digest("poll-spec"),
            "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
            "receiverKeyProofRoot": test_digest("receiver-key-proof-root"),
            "receiverKeyRoot": test_digest("receiver-key-root"),
            "receiverPayloads": receiver_payloads,
            "receiverPublicKeys": receiver_public_keys,
            "rosterDigest": test_digest("roster"),
            "rosterExternalAcceptanceDigest": test_digest("external-acceptance"),
            "scoreDomainDigest": test_digest("score-domain"),
            "scoreMembershipProfileDigest": test_digest("score-membership-profile"),
            "shareCommitmentMessageBoundCertDigest": test_digest("share-commitment-bound-cert"),
            "shareCommitmentProfileDigest": test_digest("share-commitment-profile"),
            "shareCommitments": share_commitments,
            "shareVectorWidth": 220,
            "thresholdProfileDigest": test_digest("threshold-profile"),
            "tiePolicyDigest": test_digest("tie-policy"),
            "topOptionCount": 3,
            "voterIdentityDigest": test_digest("voter-1"),
            "voterRosterPosition": 1,
            "voterSigningKeyDigest": test_digest("voter-signing-key")
        });
        let statement_digest =
            super::derive_digest("BallotProofStatementDigest", &statement_payload)
                .expect("statement digest should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("statement should be an object")
            .insert(
                "ballotProofStatementDigest".to_string(),
                json!(statement_digest),
            );

        statement
    };
    let create_linear_statement =
        |statement: &Value, parameter_set: &Value, target_vector_coefficients: Value| {
            let backend_statement_digest = test_digest("backend-statement");
            let relation_statement_digest = test_digest("relation-statement");
            let statement_matrix_digest = test_digest("statement-matrix");
            let target_vector_digest = test_digest("target-vector");
            let linear_statement_payload = json!({
                "backendStatementDigest": backend_statement_digest,
                "ballotProofStatementDigest": statement["ballotProofStatementDigest"],
                "coefficientModulus": DEMO_GENERATED_PARAMETER_CONTRACT
                    .source_coefficient_modulus
                    .to_string(),
                "objectType": "BallotProofLinearProofStatement",
                "objectVersion": 1,
                "parameterProfileId": parameter_set["profileId"],
                "relation": "A*w + t = 0",
                "relationStatementDigest": relation_statement_digest,
                "ringDegree": DEMO_GENERATED_PARAMETER_CONTRACT.source_ring_degree,
                "statementColumns": DEMO_GENERATED_PARAMETER_CONTRACT.statement_columns,
                "statementMatrixCoefficients": valid_case["statementMatrixCoefficients"].clone(),
                "statementMatrixDigest": statement_matrix_digest,
                "statementRows": DEMO_GENERATED_PARAMETER_CONTRACT.statement_rows,
                "targetCoefficientRepresentation": "centeredSignedSourceModulus",
                "targetVectorCoefficients": target_vector_coefficients,
                "targetVectorDigest": target_vector_digest,
                "witnessL2BoundSquared": DEMO_GENERATED_PROFILE
                    .exact_norm_bound_squared
                    .to_string()
            });
            let statement_digest = super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "payload": linear_statement_payload,
                    "purpose": "ballot-proof-linear-proof-statement-v1"
                }),
            )
            .expect("linear statement digest should derive");
            let mut linear_statement = linear_statement_payload;
            linear_statement
                .as_object_mut()
                .expect("linear statement should be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));

            linear_statement
        };
    let mut valid_parameter_set = valid_case["parameterSet"].clone();
    valid_parameter_set
        .as_object_mut()
        .expect("parameter set should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes),
        );
    let mut valid_proof_encoding = valid_case["proofEncoding"].clone();
    valid_proof_encoding
        .as_object_mut()
        .expect("proof encoding should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes),
        );
    let create_ballot_proof = |statement: &Value,
                               linear_statement: &Value,
                               parameter_set: &Value,
                               proof_encoding: &Value| {
        let proof_bytes_digest = super::derive_digest(
            "ProofBytesDigest",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_size_bytes
            }),
        )
        .expect("proof bytes digest should derive");
        let proof_encoding_profile_digest =
            super::derive_ballot_proof_encoding_profile_digest(proof_encoding)
                .expect("proof encoding profile digest should derive");
        let proof_parameter_set_digest =
            super::derive_ballot_proof_parameter_set_digest(parameter_set)
                .expect("proof parameter set digest should derive");
        let public_randomness_digest =
            super::derive_ballot_proof_public_randomness_digest(public_randomness_hex)
                .expect("public randomness digest should derive");
        let proof_root = super::derive_digest(
            "BallotProofRecordDigest",
            &json!({
                "linearStatementDigest": linear_statement["statementDigest"],
                "proofBytesDigest": proof_bytes_digest,
                "proofEncodingProfileDigest": proof_encoding_profile_digest,
                "proofParameterSetDigest": proof_parameter_set_digest,
                "publicRandomnessDigest": public_randomness_digest,
                "purpose": "ballot-proof-linear-proof-record-root-v1"
            }),
        )
        .expect("proof root should derive");
        let proof_payload = json!({
            "backendStatementDigest": linear_statement["backendStatementDigest"],
            "ballotProofProfileDigest": statement["ballotProofProfileDigest"],
            "ballotProofStatementDigest": statement["ballotProofStatementDigest"],
            "challengeDigest": "",
            "linearStatementDigest": linear_statement["statementDigest"],
            "objectType": "BallotProofRecord",
            "objectVersion": 1,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofBytesDigest": proof_bytes_digest,
            "proofEncodingProfileDigest": proof_encoding_profile_digest,
            "proofParameterSetDigest": proof_parameter_set_digest,
            "proofRoot": proof_root,
            "proofSizeBytes": proof_size_bytes,
            "publicRandomnessDigest": public_randomness_digest,
            "relationStatementDigest": linear_statement["relationStatementDigest"],
            "statementMatrixDigest": linear_statement["statementMatrixDigest"],
            "targetVectorDigest": linear_statement["targetVectorDigest"]
        });
        let challenge_digest =
            super::derive_ballot_proof_challenge_digest(statement, &proof_payload)
                .expect("challenge digest should derive");
        let mut proof_payload_with_challenge = proof_payload;
        proof_payload_with_challenge
            .as_object_mut()
            .expect("proof payload should be an object")
            .insert("challengeDigest".to_string(), json!(challenge_digest));
        let ballot_proof_record_digest =
            super::derive_digest("BallotProofRecordDigest", &proof_payload_with_challenge)
                .expect("ballot proof record digest should derive");
        let mut ballot_proof = proof_payload_with_challenge;
        ballot_proof
            .as_object_mut()
            .expect("ballot proof should be an object")
            .insert(
                "ballotProofRecordDigest".to_string(),
                json!(ballot_proof_record_digest),
            );

        ballot_proof
    };

    let statement = create_statement();
    let valid_linear_statement = create_linear_statement(
        &statement,
        &valid_parameter_set,
        valid_case["targetVectorCoefficients"].clone(),
    );
    let valid_ballot_proof = create_ballot_proof(
        &statement,
        &valid_linear_statement,
        &valid_parameter_set,
        &valid_proof_encoding,
    );
    let valid_verification = super::verify_ballot_proof(
        &statement,
        &valid_ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts {
            proof_bytes_hex: Some(proof_bytes_hex),
            linear_statement: Some(&valid_linear_statement),
            public_randomness_hex: Some(public_randomness_hex),
            parameter_set: Some(&valid_parameter_set),
            proof_encoding: Some(&valid_proof_encoding),
            ..BallotProofBackendInputParts::default()
        }),
    );

    assert_eq!(valid_verification["ok"], false);
    assert_eq!(
        valid_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        valid_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("full encoded-score ballot relation"),
        "{valid_verification}"
    );
    assert!(
        !valid_verification["statusLabels"]
            .as_array()
            .expect("status labels should be an array")
            .contains(&json!("BallotProofLinearProofVerified"))
    );

    let mut size_unbound_parameter_set = valid_parameter_set.clone();
    size_unbound_parameter_set
        .as_object_mut()
        .expect("parameter set should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes + 1),
        );
    let size_unbound_parameter_ballot_proof = create_ballot_proof(
        &statement,
        &valid_linear_statement,
        &size_unbound_parameter_set,
        &valid_proof_encoding,
    );
    let size_unbound_parameter_verification = super::verify_ballot_proof(
        &statement,
        &size_unbound_parameter_ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts {
            proof_bytes_hex: Some(proof_bytes_hex),
            linear_statement: Some(&valid_linear_statement),
            public_randomness_hex: Some(public_randomness_hex),
            parameter_set: Some(&size_unbound_parameter_set),
            proof_encoding: Some(&valid_proof_encoding),
            ..BallotProofBackendInputParts::default()
        }),
    );

    assert_eq!(size_unbound_parameter_verification["ok"], false);
    assert_eq!(
        size_unbound_parameter_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        size_unbound_parameter_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("byte length")
    );

    let mut size_unbound_proof_encoding = valid_proof_encoding.clone();
    size_unbound_proof_encoding
        .as_object_mut()
        .expect("proof encoding should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes + 1),
        );
    let size_unbound_encoding_ballot_proof = create_ballot_proof(
        &statement,
        &valid_linear_statement,
        &valid_parameter_set,
        &size_unbound_proof_encoding,
    );
    let size_unbound_encoding_verification = super::verify_ballot_proof(
        &statement,
        &size_unbound_encoding_ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts {
            proof_bytes_hex: Some(proof_bytes_hex),
            linear_statement: Some(&valid_linear_statement),
            public_randomness_hex: Some(public_randomness_hex),
            parameter_set: Some(&valid_parameter_set),
            proof_encoding: Some(&size_unbound_proof_encoding),
            ..BallotProofBackendInputParts::default()
        }),
    );

    assert_eq!(size_unbound_encoding_verification["ok"], false);
    assert_eq!(
        size_unbound_encoding_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        size_unbound_encoding_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("byte length")
    );

    let mutated_linear_statement = create_linear_statement(
        &statement,
        &valid_parameter_set,
        mutated_target_case["targetVectorCoefficients"].clone(),
    );
    let mutated_ballot_proof = create_ballot_proof(
        &statement,
        &mutated_linear_statement,
        &valid_parameter_set,
        &valid_proof_encoding,
    );
    let mutated_verification = super::verify_ballot_proof(
        &statement,
        &mutated_ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts {
            proof_bytes_hex: Some(proof_bytes_hex),
            linear_statement: Some(&mutated_linear_statement),
            public_randomness_hex: Some(public_randomness_hex),
            parameter_set: Some(&valid_parameter_set),
            proof_encoding: Some(&valid_proof_encoding),
            ..BallotProofBackendInputParts::default()
        }),
    );

    assert_eq!(mutated_verification["ok"], false);
    assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");
}

#[test]
fn encoded_score_field_ballot_record_rejects_without_full_relation_coverage() {
    let vectors: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
    )))
    .expect("encoded-score field vector file should parse");
    let cases = vectors["cases"]
        .as_array()
        .expect("encoded-score field vector file should contain cases");
    let valid_compact_case = cases
        .iter()
        .find(|vector_case| vector_case["caseName"] == "valid-encoded-score-field-linear-proof")
        .expect("valid encoded-score field vector should exist");
    let mutated_target_compact_case = cases
        .iter()
        .find(|vector_case| vector_case["caseName"] == "mutated-encoded-score-field-target-vector")
        .expect("mutated encoded-score target vector should exist");
    let valid_case = expand_encoded_score_field_vector_case(&vectors, valid_compact_case);
    let mutated_target_case =
        expand_encoded_score_field_vector_case(&vectors, mutated_target_compact_case);
    let proof_bytes_hex = valid_case["proofHex"]
        .as_str()
        .expect("valid vector proofHex should be a string");
    let public_randomness_hex = valid_case["publicRandomnessHex"]
        .as_str()
        .expect("valid vector publicRandomnessHex should be a string");
    let proof_size_bytes = proof_bytes_hex.len() / 2;
    let test_digest = |label: &str| {
        super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "label": label,
                "purpose": "encoded-score-field-ballot-proof-record-native-test"
            }),
        )
        .expect("test digest should derive")
    };
    let create_statement = || {
        let receiver_public_keys = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPublicKeyDigest": test_digest(&format!("receiver-public-key-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let receiver_payloads = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPayloadCiphertextRoot": test_digest(&format!("receiver-ciphertext-{receiver_roster_position}")),
                    "receiverPayloadDigest": test_digest(&format!("receiver-payload-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let share_commitments = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverRosterPosition": receiver_roster_position,
                    "shareCommitmentDigest": test_digest(&format!("share-commitment-{receiver_roster_position}"))
                })
            })
            .collect::<Vec<_>>();
        let statement_payload = json!({
            "actionContextDigest": test_digest("action-context"),
            "aggregateInputEncodingProfileDigest": test_digest("aggregate-input-encoding-profile"),
            "ballotPackageDigest": test_digest("ballot-package"),
            "ballotProofProfileDigest": test_digest("ballot-proof-profile"),
            "ballotScoreEncodingProfileDigest": test_digest("ballot-score-encoding-profile"),
            "ballotShareLayoutProfileDigest": test_digest("ballot-share-layout-profile"),
            "ceremonyId": "ceremony-encoded-score-field-ballot-proof-record",
            "challengeDomainDigest": test_digest("challenge-domain"),
            "duplicateBallotPolicyDigest": test_digest("duplicate-policy"),
            "encodedAggregateLayoutDigest": test_digest("encoded-aggregate-layout"),
            "encodedShareVectorLayoutDigest": test_digest("encoded-share-vector-layout"),
            "manifestDigest": test_digest("manifest"),
            "objectType": "BallotProofStatement",
            "objectVersion": 1,
            "optionCount": 20,
            "pollSpecDigest": test_digest("poll-spec"),
            "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
            "receiverKeyProofRoot": test_digest("receiver-key-proof-root"),
            "receiverKeyRoot": test_digest("receiver-key-root"),
            "receiverPayloads": receiver_payloads,
            "receiverPublicKeys": receiver_public_keys,
            "rosterDigest": test_digest("roster"),
            "rosterExternalAcceptanceDigest": test_digest("external-acceptance"),
            "scoreDomainDigest": test_digest("score-domain"),
            "scoreMembershipProfileDigest": test_digest("score-membership-profile"),
            "shareCommitmentMessageBoundCertDigest": test_digest("share-commitment-bound-cert"),
            "shareCommitmentProfileDigest": test_digest("share-commitment-profile"),
            "shareCommitments": share_commitments,
            "shareVectorWidth": 220,
            "thresholdProfileDigest": test_digest("threshold-profile"),
            "tiePolicyDigest": test_digest("tie-policy"),
            "topOptionCount": 3,
            "voterIdentityDigest": test_digest("voter-1"),
            "voterRosterPosition": 1,
            "voterSigningKeyDigest": test_digest("voter-signing-key")
        });
        let statement_digest =
            super::derive_digest("BallotProofStatementDigest", &statement_payload)
                .expect("statement digest should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("statement should be an object")
            .insert(
                "ballotProofStatementDigest".to_string(),
                json!(statement_digest),
            );

        statement
    };
    let create_linear_statement = |statement: &Value, vector_case: &Value| {
        let mut linear_statement = vectors["linearStatement"].clone();
        let linear_statement_object = linear_statement
            .as_object_mut()
            .expect("linear statement should be an object");
        linear_statement_object.remove("statementDigest");
        linear_statement_object.insert(
            "ballotProofStatementDigest".to_string(),
            statement["ballotProofStatementDigest"].clone(),
        );
        linear_statement_object.insert(
            "statementMatrixCoefficients".to_string(),
            vector_case["statementMatrixCoefficients"].clone(),
        );
        linear_statement_object.insert(
            "targetVectorCoefficients".to_string(),
            vector_case["targetVectorCoefficients"].clone(),
        );
        linear_statement_object.insert(
            "targetCoefficientRepresentation".to_string(),
            vector_case["targetCoefficientRepresentation"].clone(),
        );
        linear_statement_object.insert(
            "statementMatrixDigest".to_string(),
            json!(
                super::derive_digest(
                    "ChallengeDomainDigest",
                    &json!({
                        "purpose": "ballot-proof-linear-statement-matrix-v1",
                        "statementMatrixCoefficients": vector_case["statementMatrixCoefficients"]
                    }),
                )
                .expect("statement matrix digest should derive")
            ),
        );
        linear_statement_object.insert(
            "targetVectorDigest".to_string(),
            json!(
                super::derive_digest(
                    "ChallengeDomainDigest",
                    &json!({
                        "purpose": "ballot-proof-linear-target-vector-v1",
                        "targetVectorCoefficients": vector_case["targetVectorCoefficients"]
                    }),
                )
                .expect("target vector digest should derive")
            ),
        );
        let statement_digest = super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "payload": linear_statement,
                "purpose": "ballot-proof-linear-proof-statement-v1"
            }),
        )
        .expect("linear statement digest should derive");
        linear_statement
            .as_object_mut()
            .expect("linear statement should still be an object")
            .insert("statementDigest".to_string(), json!(statement_digest));

        linear_statement
    };
    let create_ballot_proof = |statement: &Value, linear_statement: &Value| {
        let proof_bytes_digest = super::derive_digest(
            "ProofBytesDigest",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_size_bytes
            }),
        )
        .expect("proof bytes digest should derive");
        let proof_encoding_profile_digest =
            super::derive_ballot_proof_encoding_profile_digest(&valid_case["proofEncoding"])
                .expect("proof encoding profile digest should derive");
        let proof_parameter_set_digest =
            super::derive_ballot_proof_parameter_set_digest(&valid_case["parameterSet"])
                .expect("proof parameter set digest should derive");
        let public_randomness_digest =
            super::derive_ballot_proof_public_randomness_digest(public_randomness_hex)
                .expect("public randomness digest should derive");
        let proof_root = super::derive_digest(
            "BallotProofRecordDigest",
            &json!({
                "linearStatementDigest": linear_statement["statementDigest"],
                "proofBytesDigest": proof_bytes_digest,
                "proofEncodingProfileDigest": proof_encoding_profile_digest,
                "proofParameterSetDigest": proof_parameter_set_digest,
                "publicRandomnessDigest": public_randomness_digest,
                "purpose": "ballot-proof-linear-proof-record-root-v1"
            }),
        )
        .expect("proof root should derive");
        let proof_payload = json!({
            "backendStatementDigest": linear_statement["backendStatementDigest"],
            "ballotProofProfileDigest": statement["ballotProofProfileDigest"],
            "ballotProofStatementDigest": statement["ballotProofStatementDigest"],
            "challengeDigest": "",
            "linearStatementDigest": linear_statement["statementDigest"],
            "objectType": "BallotProofRecord",
            "objectVersion": 1,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofBytesDigest": proof_bytes_digest,
            "proofEncodingProfileDigest": proof_encoding_profile_digest,
            "proofParameterSetDigest": proof_parameter_set_digest,
            "proofRoot": proof_root,
            "proofSizeBytes": proof_size_bytes,
            "publicRandomnessDigest": public_randomness_digest,
            "relationStatementDigest": linear_statement["relationStatementDigest"],
            "statementMatrixDigest": linear_statement["statementMatrixDigest"],
            "targetVectorDigest": linear_statement["targetVectorDigest"]
        });
        let challenge_digest =
            super::derive_ballot_proof_challenge_digest(statement, &proof_payload)
                .expect("challenge digest should derive");
        let mut proof_payload_with_challenge = proof_payload;
        proof_payload_with_challenge
            .as_object_mut()
            .expect("proof payload should be an object")
            .insert("challengeDigest".to_string(), json!(challenge_digest));
        let ballot_proof_record_digest =
            super::derive_digest("BallotProofRecordDigest", &proof_payload_with_challenge)
                .expect("ballot proof record digest should derive");
        let mut ballot_proof = proof_payload_with_challenge;
        ballot_proof
            .as_object_mut()
            .expect("ballot proof should be an object")
            .insert(
                "ballotProofRecordDigest".to_string(),
                json!(ballot_proof_record_digest),
            );

        ballot_proof
    };

    let statement = create_statement();
    let valid_linear_statement = create_linear_statement(&statement, &valid_case);
    let valid_ballot_proof = create_ballot_proof(&statement, &valid_linear_statement);
    let valid_verification = super::verify_ballot_proof(
        &statement,
        &valid_ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts {
            proof_bytes_hex: Some(proof_bytes_hex),
            linear_statement: Some(&valid_linear_statement),
            public_randomness_hex: Some(public_randomness_hex),
            parameter_set: Some(&valid_case["parameterSet"]),
            proof_encoding: Some(&valid_case["proofEncoding"]),
            ..BallotProofBackendInputParts::default()
        }),
    );

    assert_eq!(
        valid_verification["ok"], false,
        "encoded-score field-only ballot proof must not verify as full coverage: {valid_verification}"
    );
    assert_eq!(
        valid_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        valid_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("full encoded-score ballot relation")
    );
    assert!(
        !valid_verification["statusLabels"]
            .as_array()
            .expect("status labels should be an array")
            .contains(&json!("BallotProofLinearProofVerified"))
    );

    let mut relabeled_linear_statement = valid_linear_statement.clone();
    {
        let relabeled_object = relabeled_linear_statement
            .as_object_mut()
            .expect("relabeled statement should be an object");
        relabeled_object.remove("statementDigest");
        relabeled_object.insert(
            "projectionCoverage".to_string(),
            json!(super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE),
        );
    }
    let relabeled_statement_digest = super::derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": relabeled_linear_statement,
            "purpose": "ballot-proof-linear-proof-statement-v1"
        }),
    )
    .expect("relabeled linear statement digest should derive");
    relabeled_linear_statement
        .as_object_mut()
        .expect("relabeled statement should still be an object")
        .insert(
            "statementDigest".to_string(),
            json!(relabeled_statement_digest),
        );
    let relabeled_ballot_proof = create_ballot_proof(&statement, &relabeled_linear_statement);
    let relabeled_verification = super::verify_ballot_proof(
        &statement,
        &relabeled_ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts {
            proof_bytes_hex: Some(proof_bytes_hex),
            linear_statement: Some(&relabeled_linear_statement),
            public_randomness_hex: Some(public_randomness_hex),
            parameter_set: Some(&valid_case["parameterSet"]),
            proof_encoding: Some(&valid_case["proofEncoding"]),
            ..BallotProofBackendInputParts::default()
        }),
    );

    assert_eq!(relabeled_verification["ok"], false);
    assert_eq!(
        relabeled_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        relabeled_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("relabeled refusal message should be a string")
            .contains("dedicated full-relation parameter profile")
    );

    let mutated_linear_statement = create_linear_statement(&statement, &mutated_target_case);
    let mutated_ballot_proof = create_ballot_proof(&statement, &mutated_linear_statement);
    let mutated_verification = super::verify_ballot_proof(
        &statement,
        &mutated_ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts {
            proof_bytes_hex: Some(proof_bytes_hex),
            linear_statement: Some(&mutated_linear_statement),
            public_randomness_hex: Some(public_randomness_hex),
            parameter_set: Some(&valid_case["parameterSet"]),
            proof_encoding: Some(&valid_case["proofEncoding"]),
            ..BallotProofBackendInputParts::default()
        }),
    );

    assert_eq!(mutated_verification["ok"], false);
    assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");
}

pub(super) fn component_proof_record_for_vector(
    component_id: &str,
    proof_bytes_hex: &str,
) -> Value {
    let proof_size_bytes = proof_bytes_hex.len() / 2;
    json!({
        "componentId": component_id,
        "componentProofRecordDigest": test_digest(&format!("{component_id}-component-proof-record")),
        "proofBytesDigest": super::derive_digest(
            "ProofBytesDigest",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_size_bytes
            }),
        )
        .expect("proof bytes digest should derive"),
        "proofSizeBytes": proof_size_bytes
    })
}

pub(super) fn dense_component_proof_input_for_vector(
    component_id: &str,
    vectors: &Value,
    vector_case: &Value,
) -> Value {
    let mut proof_statement = vectors["linearStatement"].clone();
    {
        let proof_statement_object = proof_statement
            .as_object_mut()
            .expect("proof statement should be an object");
        proof_statement_object.insert(
            "statementMatrixCoefficients".to_string(),
            vector_case["statementMatrixCoefficients"].clone(),
        );
        proof_statement_object.insert(
            "targetVectorCoefficients".to_string(),
            vector_case["targetVectorCoefficients"].clone(),
        );
        proof_statement_object.insert(
            "targetCoefficientRepresentation".to_string(),
            vector_case["targetCoefficientRepresentation"].clone(),
        );
    }

    json!({
        "componentId": component_id,
        "proofBytesHex": vector_case["proofHex"],
        "proofEncoding": vectors["proofEncoding"],
        "proofParameterSet": vectors["parameterSet"],
        "proofStatement": proof_statement,
        "proofStatementFormat": "dense-polynomial-matrix-linear-proof-v1",
        "publicRandomnessHex": vector_case["publicRandomnessHex"],
        "statementDigest": vectors["linearStatement"]["statementDigest"]
    })
}
