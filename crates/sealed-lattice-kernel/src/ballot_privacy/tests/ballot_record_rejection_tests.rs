use super::*;
use crate::ballot_privacy::linear_proof::profile_constants::{
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
    let test_hash = |label: &str| {
        super::derive_hash(
            "ChallengeDomainHash",
            &json!({
                "label": label,
                "purpose": "ballot-proof-record-native-test"
            }),
        )
        .expect("test hash should derive")
    };
    let create_statement = || {
        let receiver_public_keys = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPublicKeyHash": test_hash(&format!("receiver-public-key-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let receiver_payloads = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPayloadCiphertextRoot": test_hash(&format!("receiver-ciphertext-{receiver_roster_position}")),
                    "receiverPayloadHash": test_hash(&format!("receiver-payload-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let share_commitments = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverRosterPosition": receiver_roster_position,
                    "shareCommitmentHash": test_hash(&format!("share-commitment-{receiver_roster_position}"))
                })
            })
            .collect::<Vec<_>>();
        let statement_payload = json!({
            "actionContextHash": test_hash("action-context"),
            "aggregateInputEncodingProfileHash": test_hash("aggregate-input-encoding-profile"),
            "ballotPackageHash": test_hash("ballot-package"),
            "ballotProofProfileHash": test_hash("ballot-proof-profile"),
            "ballotScoreEncodingProfileHash": test_hash("ballot-score-encoding-profile"),
            "ballotShareLayoutProfileHash": test_hash("ballot-share-layout-profile"),
            "ceremonyId": "ceremony-ballot-proof-record",
            "challengeDomainHash": test_hash("challenge-domain"),
            "duplicateBallotPolicyHash": test_hash("duplicate-policy"),
            "encodedAggregateLayoutHash": test_hash("encoded-aggregate-layout"),
            "encodedShareVectorLayoutHash": test_hash("encoded-share-vector-layout"),
            "manifestHash": test_hash("manifest"),
            "objectType": "BallotProofStatement",
            "objectVersion": 1,
            "optionCount": 20,
            "pollSpecHash": test_hash("poll-spec"),
            "receiverEncryptionProfileHash": test_hash("receiver-encryption-profile"),
            "receiverKeyProofRoot": test_hash("receiver-key-proof-root"),
            "receiverKeyRoot": test_hash("receiver-key-root"),
            "receiverPayloads": receiver_payloads,
            "receiverPublicKeys": receiver_public_keys,
            "rosterHash": test_hash("roster"),
            "rosterExternalAcceptanceHash": test_hash("external-acceptance"),
            "scoreDomainHash": test_hash("score-domain"),
            "scoreMembershipProfileHash": test_hash("score-membership-profile"),
            "shareCommitmentMessageBoundCertHash": test_hash("share-commitment-bound-cert"),
            "shareCommitmentProfileHash": test_hash("share-commitment-profile"),
            "shareCommitments": share_commitments,
            "shareVectorWidth": 220,
            "thresholdProfileHash": test_hash("threshold-profile"),
            "tiePolicyHash": test_hash("tie-policy"),
            "topOptionCount": 3,
            "voterIdentityHash": test_hash("voter-1"),
            "voterRosterPosition": 1,
            "voterSigningKeyHash": test_hash("voter-signing-key")
        });
        let statement_hash = super::derive_hash("BallotProofStatementHash", &statement_payload)
            .expect("statement hash should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("statement should be an object")
            .insert(
                "ballotProofStatementHash".to_string(),
                json!(statement_hash),
            );

        statement
    };
    let create_linear_statement =
        |statement: &Value, parameter_set: &Value, target_vector_coefficients: Value| {
            let backend_statement_hash = test_hash("backend-statement");
            let relation_statement_hash = test_hash("relation-statement");
            let statement_matrix_hash = test_hash("statement-matrix");
            let target_vector_hash = test_hash("target-vector");
            let linear_statement_payload = json!({
                "backendStatementHash": backend_statement_hash,
                "ballotProofStatementHash": statement["ballotProofStatementHash"],
                "coefficientModulus": DEMO_GENERATED_PARAMETER_CONTRACT
                    .source_coefficient_modulus
                    .to_string(),
                "objectType": "BallotProofLinearProofStatement",
                "objectVersion": 1,
                "parameterProfileId": parameter_set["profileId"],
                "relation": "A*w + t = 0",
                "relationStatementHash": relation_statement_hash,
                "ringDegree": DEMO_GENERATED_PARAMETER_CONTRACT.source_ring_degree,
                "statementColumns": DEMO_GENERATED_PARAMETER_CONTRACT.statement_columns,
                "statementMatrixCoefficients": valid_case["statementMatrixCoefficients"].clone(),
                "statementMatrixHash": statement_matrix_hash,
                "statementRows": DEMO_GENERATED_PARAMETER_CONTRACT.statement_rows,
                "targetCoefficientRepresentation": "centeredSignedSourceModulus",
                "targetVectorCoefficients": target_vector_coefficients,
                "targetVectorHash": target_vector_hash,
                "witnessL2BoundSquared": DEMO_GENERATED_PROFILE
                    .exact_norm_bound_squared
                    .to_string()
            });
            let statement_hash = super::derive_hash(
                "ChallengeDomainHash",
                &json!({
                    "payload": linear_statement_payload,
                    "purpose": "ballot-proof-linear-proof-statement-v1"
                }),
            )
            .expect("linear statement hash should derive");
            let mut linear_statement = linear_statement_payload;
            linear_statement
                .as_object_mut()
                .expect("linear statement should be an object")
                .insert("statementHash".to_string(), json!(statement_hash));

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
        let proof_bytes_hash = super::derive_hash(
            "ProofBytesHash",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_size_bytes
            }),
        )
        .expect("proof bytes hash should derive");
        let proof_encoding_profile_hash =
            super::derive_ballot_proof_encoding_profile_hash(proof_encoding)
                .expect("proof encoding profile hash should derive");
        let proof_parameter_set_hash = super::derive_ballot_proof_parameter_set_hash(parameter_set)
            .expect("proof parameter set hash should derive");
        let public_randomness_hash =
            super::derive_ballot_proof_public_randomness_hash(public_randomness_hex)
                .expect("public randomness hash should derive");
        let proof_root = super::derive_hash(
            "BallotProofRecordHash",
            &json!({
                "linearStatementHash": linear_statement["statementHash"],
                "proofBytesHash": proof_bytes_hash,
                "proofEncodingProfileHash": proof_encoding_profile_hash,
                "proofParameterSetHash": proof_parameter_set_hash,
                "publicRandomnessHash": public_randomness_hash,
                "purpose": "ballot-proof-linear-proof-record-root-v1"
            }),
        )
        .expect("proof root should derive");
        let proof_payload = json!({
            "backendStatementHash": linear_statement["backendStatementHash"],
            "ballotProofProfileHash": statement["ballotProofProfileHash"],
            "ballotProofStatementHash": statement["ballotProofStatementHash"],
            "challengeHash": "",
            "linearStatementHash": linear_statement["statementHash"],
            "objectType": "BallotProofRecord",
            "objectVersion": 1,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofBytesHash": proof_bytes_hash,
            "proofEncodingProfileHash": proof_encoding_profile_hash,
            "proofParameterSetHash": proof_parameter_set_hash,
            "proofRoot": proof_root,
            "proofSizeBytes": proof_size_bytes,
            "publicRandomnessHash": public_randomness_hash,
            "relationStatementHash": linear_statement["relationStatementHash"],
            "statementMatrixHash": linear_statement["statementMatrixHash"],
            "targetVectorHash": linear_statement["targetVectorHash"]
        });
        let challenge_hash = super::derive_ballot_proof_challenge_hash(statement, &proof_payload)
            .expect("challenge hash should derive");
        let mut proof_payload_with_challenge = proof_payload;
        proof_payload_with_challenge
            .as_object_mut()
            .expect("proof payload should be an object")
            .insert("challengeHash".to_string(), json!(challenge_hash));
        let ballot_proof_record_hash =
            super::derive_hash("BallotProofRecordHash", &proof_payload_with_challenge)
                .expect("ballot proof record hash should derive");
        let mut ballot_proof = proof_payload_with_challenge;
        ballot_proof
            .as_object_mut()
            .expect("ballot proof should be an object")
            .insert(
                "ballotProofRecordHash".to_string(),
                json!(ballot_proof_record_hash),
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
    let test_hash = |label: &str| {
        super::derive_hash(
            "ChallengeDomainHash",
            &json!({
                "label": label,
                "purpose": "encoded-score-field-ballot-proof-record-native-test"
            }),
        )
        .expect("test hash should derive")
    };
    let create_statement = || {
        let receiver_public_keys = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPublicKeyHash": test_hash(&format!("receiver-public-key-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let receiver_payloads = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverPayloadCiphertextRoot": test_hash(&format!("receiver-ciphertext-{receiver_roster_position}")),
                    "receiverPayloadHash": test_hash(&format!("receiver-payload-{receiver_roster_position}")),
                    "receiverRosterPosition": receiver_roster_position
                })
            })
            .collect::<Vec<_>>();
        let share_commitments = (1..=20)
            .map(|receiver_roster_position| {
                json!({
                    "receiverIdentity": format!("receiver-{receiver_roster_position}"),
                    "receiverRosterPosition": receiver_roster_position,
                    "shareCommitmentHash": test_hash(&format!("share-commitment-{receiver_roster_position}"))
                })
            })
            .collect::<Vec<_>>();
        let statement_payload = json!({
            "actionContextHash": test_hash("action-context"),
            "aggregateInputEncodingProfileHash": test_hash("aggregate-input-encoding-profile"),
            "ballotPackageHash": test_hash("ballot-package"),
            "ballotProofProfileHash": test_hash("ballot-proof-profile"),
            "ballotScoreEncodingProfileHash": test_hash("ballot-score-encoding-profile"),
            "ballotShareLayoutProfileHash": test_hash("ballot-share-layout-profile"),
            "ceremonyId": "ceremony-encoded-score-field-ballot-proof-record",
            "challengeDomainHash": test_hash("challenge-domain"),
            "duplicateBallotPolicyHash": test_hash("duplicate-policy"),
            "encodedAggregateLayoutHash": test_hash("encoded-aggregate-layout"),
            "encodedShareVectorLayoutHash": test_hash("encoded-share-vector-layout"),
            "manifestHash": test_hash("manifest"),
            "objectType": "BallotProofStatement",
            "objectVersion": 1,
            "optionCount": 20,
            "pollSpecHash": test_hash("poll-spec"),
            "receiverEncryptionProfileHash": test_hash("receiver-encryption-profile"),
            "receiverKeyProofRoot": test_hash("receiver-key-proof-root"),
            "receiverKeyRoot": test_hash("receiver-key-root"),
            "receiverPayloads": receiver_payloads,
            "receiverPublicKeys": receiver_public_keys,
            "rosterHash": test_hash("roster"),
            "rosterExternalAcceptanceHash": test_hash("external-acceptance"),
            "scoreDomainHash": test_hash("score-domain"),
            "scoreMembershipProfileHash": test_hash("score-membership-profile"),
            "shareCommitmentMessageBoundCertHash": test_hash("share-commitment-bound-cert"),
            "shareCommitmentProfileHash": test_hash("share-commitment-profile"),
            "shareCommitments": share_commitments,
            "shareVectorWidth": 220,
            "thresholdProfileHash": test_hash("threshold-profile"),
            "tiePolicyHash": test_hash("tie-policy"),
            "topOptionCount": 3,
            "voterIdentityHash": test_hash("voter-1"),
            "voterRosterPosition": 1,
            "voterSigningKeyHash": test_hash("voter-signing-key")
        });
        let statement_hash = super::derive_hash("BallotProofStatementHash", &statement_payload)
            .expect("statement hash should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("statement should be an object")
            .insert(
                "ballotProofStatementHash".to_string(),
                json!(statement_hash),
            );

        statement
    };
    let create_linear_statement = |statement: &Value, vector_case: &Value| {
        let mut linear_statement = vectors["linearStatement"].clone();
        let linear_statement_object = linear_statement
            .as_object_mut()
            .expect("linear statement should be an object");
        linear_statement_object.remove("statementHash");
        linear_statement_object.insert(
            "ballotProofStatementHash".to_string(),
            statement["ballotProofStatementHash"].clone(),
        );
        linear_statement_object.insert(
            "statementMatrixCoefficients".to_string(),
            vector_case["statementMatrixCoefficients"].clone(),
        );
        linear_statement_object.insert(
            "matrixCoefficientRepresentation".to_string(),
            vector_case
                .get("matrixCoefficientRepresentation")
                .or_else(|| vectors.get("matrixCoefficientRepresentation"))
                .cloned()
                .expect(
                    "encoded-score field vector case or file should define matrixCoefficientRepresentation",
                ),
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
            "statementMatrixHash".to_string(),
            json!(
                super::derive_hash(
                    "ChallengeDomainHash",
                    &json!({
                        "purpose": "ballot-proof-linear-statement-matrix-v1",
                        "statementMatrixCoefficients": vector_case["statementMatrixCoefficients"]
                    }),
                )
                .expect("statement matrix hash should derive")
            ),
        );
        linear_statement_object.insert(
            "targetVectorHash".to_string(),
            json!(
                super::derive_hash(
                    "ChallengeDomainHash",
                    &json!({
                        "purpose": "ballot-proof-linear-target-vector-v1",
                        "targetVectorCoefficients": vector_case["targetVectorCoefficients"]
                    }),
                )
                .expect("target vector hash should derive")
            ),
        );
        let statement_hash = super::derive_hash(
            "ChallengeDomainHash",
            &json!({
                "payload": linear_statement,
                "purpose": "ballot-proof-linear-proof-statement-v1"
            }),
        )
        .expect("linear statement hash should derive");
        linear_statement
            .as_object_mut()
            .expect("linear statement should still be an object")
            .insert("statementHash".to_string(), json!(statement_hash));

        linear_statement
    };
    let create_ballot_proof = |statement: &Value, linear_statement: &Value| {
        let proof_bytes_hash = super::derive_hash(
            "ProofBytesHash",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_size_bytes
            }),
        )
        .expect("proof bytes hash should derive");
        let proof_encoding_profile_hash =
            super::derive_ballot_proof_encoding_profile_hash(&valid_case["proofEncoding"])
                .expect("proof encoding profile hash should derive");
        let proof_parameter_set_hash =
            super::derive_ballot_proof_parameter_set_hash(&valid_case["parameterSet"])
                .expect("proof parameter set hash should derive");
        let public_randomness_hash =
            super::derive_ballot_proof_public_randomness_hash(public_randomness_hex)
                .expect("public randomness hash should derive");
        let proof_root = super::derive_hash(
            "BallotProofRecordHash",
            &json!({
                "linearStatementHash": linear_statement["statementHash"],
                "proofBytesHash": proof_bytes_hash,
                "proofEncodingProfileHash": proof_encoding_profile_hash,
                "proofParameterSetHash": proof_parameter_set_hash,
                "publicRandomnessHash": public_randomness_hash,
                "purpose": "ballot-proof-linear-proof-record-root-v1"
            }),
        )
        .expect("proof root should derive");
        let proof_payload = json!({
            "backendStatementHash": linear_statement["backendStatementHash"],
            "ballotProofProfileHash": statement["ballotProofProfileHash"],
            "ballotProofStatementHash": statement["ballotProofStatementHash"],
            "challengeHash": "",
            "linearStatementHash": linear_statement["statementHash"],
            "objectType": "BallotProofRecord",
            "objectVersion": 1,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofBytesHash": proof_bytes_hash,
            "proofEncodingProfileHash": proof_encoding_profile_hash,
            "proofParameterSetHash": proof_parameter_set_hash,
            "proofRoot": proof_root,
            "proofSizeBytes": proof_size_bytes,
            "publicRandomnessHash": public_randomness_hash,
            "relationStatementHash": linear_statement["relationStatementHash"],
            "statementMatrixHash": linear_statement["statementMatrixHash"],
            "targetVectorHash": linear_statement["targetVectorHash"]
        });
        let challenge_hash = super::derive_ballot_proof_challenge_hash(statement, &proof_payload)
            .expect("challenge hash should derive");
        let mut proof_payload_with_challenge = proof_payload;
        proof_payload_with_challenge
            .as_object_mut()
            .expect("proof payload should be an object")
            .insert("challengeHash".to_string(), json!(challenge_hash));
        let ballot_proof_record_hash =
            super::derive_hash("BallotProofRecordHash", &proof_payload_with_challenge)
                .expect("ballot proof record hash should derive");
        let mut ballot_proof = proof_payload_with_challenge;
        ballot_proof
            .as_object_mut()
            .expect("ballot proof should be an object")
            .insert(
                "ballotProofRecordHash".to_string(),
                json!(ballot_proof_record_hash),
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
        relabeled_object.remove("statementHash");
        relabeled_object.insert(
            "projectionCoverage".to_string(),
            json!(super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE),
        );
    }
    let relabeled_statement_hash = super::derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": relabeled_linear_statement,
            "purpose": "ballot-proof-linear-proof-statement-v1"
        }),
    )
    .expect("relabeled linear statement hash should derive");
    relabeled_linear_statement
        .as_object_mut()
        .expect("relabeled statement should still be an object")
        .insert("statementHash".to_string(), json!(relabeled_statement_hash));
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
        "componentProofRecordHash": test_hash(&format!("{component_id}-component-proof-record")),
        "proofBytesHash": super::derive_hash(
            "ProofBytesHash",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_size_bytes
            }),
        )
        .expect("proof bytes hash should derive"),
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
            "matrixCoefficientRepresentation".to_string(),
            vector_case
                .get("matrixCoefficientRepresentation")
                .or_else(|| vectors.get("matrixCoefficientRepresentation"))
                .cloned()
                .expect(
                    "encoded-score field vector case or file should define matrixCoefficientRepresentation",
                ),
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
        "statementHash": vectors["linearStatement"]["statementHash"]
    })
}
