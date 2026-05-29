use super::*;
use crate::ballot_privacy::{
    linear_proof::parameters::encoded_score_field_linear_proof_encoding_contract,
    linear_proof::profile_constants::{
        GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED,
        GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED,
    },
};

#[test]
fn ballot_proof_record_generation_emits_bound_component_bundle() {
    fn proof_encoding_value(
        profile_id: &str,
        source: &str,
        short_response_vector_length: usize,
    ) -> Value {
        let mut proof_encoding = encoded_score_field_linear_proof_encoding_contract();
        proof_encoding.profile_id = profile_id.to_string();
        proof_encoding.source = source.to_string();
        proof_encoding.short_response_vector_length = short_response_vector_length;
        serde_json::to_value(&proof_encoding).expect("proof encoding should serialize")
    }

    fn parameter_set_value(
        profile_id: &str,
        source: &str,
        ring_degree: usize,
        coefficient_modulus: u64,
        statement_rows: usize,
        statement_columns: usize,
        witness_l2_bound_squared: u128,
    ) -> Value {
        json!({
            "profileId": profile_id,
            "source": source,
            "relation": "A*w + t = 0",
            "ringDegree": ring_degree,
            "proofSystemRingDegree": 64,
            "coefficientModulus": coefficient_modulus.to_string(),
            "statementRows": statement_rows,
            "statementColumns": statement_columns,
            "witnessL2BoundSquared": witness_l2_bound_squared,
        })
    }

    fn hash_for_payload(namespace: &str, value: &Value) -> String {
        super::derive_hash(namespace, value).expect("Hash should derive")
    }

    fn statement_hash_for_payload(purpose: &str, payload: &Value) -> String {
        hash_for_payload(
            "ChallengeDomainHash",
            &json!({
                "payload": payload,
                "purpose": purpose
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn component_statement(
        component_id: &str,
        component_statement_hash_label: &str,
        backend_statement_hash: &str,
        relation_statement_hash: &str,
        ballot_proof_statement_hash: &str,
        coefficient_modulus: &str,
        row_count: usize,
        variable_column_count: usize,
    ) -> Value {
        let variable_column_indices = (0..variable_column_count).collect::<Vec<_>>();
        let component_payload = json!({
            "objectType": "BallotProofComponentStatement",
            "objectVersion": 1,
            "backendStatementHash": backend_statement_hash,
            "ballotProofStatementHash": ballot_proof_statement_hash,
            "coefficientModulus": coefficient_modulus,
            "componentHash": test_hash(&format!("{component_id}-component")),
            "componentId": component_id,
            "matrixHash": test_hash(&format!("{component_id}-matrix")),
            "proofLoweringStatus": "explicitRowsAvailable",
            "relationStatementHash": relation_statement_hash,
            "rowBatchMatrixHashes": [test_hash(&format!("{component_id}-row-matrix"))],
            "rowBatchNames": [format!("{component_id}-rows")],
            "rowBatchTargetVectorHashes": [test_hash(&format!("{component_id}-row-target"))],
            "rowCount": row_count,
            "rowKinds": [format!("{component_id}-rows")],
            "targetVectorHash": test_hash(&format!("{component_id}-target")),
            "variableColumnCount": variable_column_count,
            "variableColumnIndices": variable_column_indices,
        });
        let mut component_statement = component_payload;
        component_statement
            .as_object_mut()
            .expect("component statement should be an object")
            .insert(
                "componentStatementHash".to_string(),
                json!(test_hash(component_statement_hash_label)),
            );
        let canonical_hash = super::derive_ballot_component_statement_hash(&component_statement)
            .expect("component statement hash should derive");
        component_statement
            .as_object_mut()
            .expect("component statement should be an object")
            .insert("componentStatementHash".to_string(), json!(canonical_hash));
        component_statement
    }

    #[allow(clippy::too_many_arguments)]
    fn dense_linear_statement(
        component_id: &str,
        component_statement_hash: &Value,
        parameter_profile_id: &str,
        backend_statement_hash: &str,
        relation_statement_hash: &str,
        ballot_proof_statement_hash: &str,
        statement_matrix_hash: &str,
        target_vector_hash: &str,
        projection_coverage: &str,
        statement_columns: usize,
    ) -> Value {
        let mut unit_polynomial = vec![0_u64; 64];
        unit_polynomial[0] = 1;
        let mut target_polynomial = vec![0_u64; 64];
        target_polynomial[0] = 65_537 - 5;
        let mut statement_matrix_row = vec![vec![0_u64; 64]; statement_columns];
        statement_matrix_row[0] = unit_polynomial;
        let mut statement_payload = json!({
            "objectType": "BallotProofLinearProofStatement",
            "objectVersion": 1,
            "backendStatementHash": backend_statement_hash,
            "ballotProofStatementHash": ballot_proof_statement_hash,
            "coefficientModulus": "65537",
            "componentId": component_id,
            "componentStatementHash": component_statement_hash,
            "parameterProfileId": parameter_profile_id,
            "projectionCoverage": projection_coverage,
            "relation": "A*w + t = 0",
            "relationStatementHash": relation_statement_hash,
            "ringDegree": 64,
            "statementColumns": statement_columns,
            "statementMatrixCoefficients": [statement_matrix_row],
            "statementMatrixHash": statement_matrix_hash,
            "statementRows": 1,
            "targetCoefficientRepresentation": "centeredSignedSourceModulus",
            "targetVectorCoefficients": [target_polynomial],
            "targetVectorHash": target_vector_hash,
            "witnessL2BoundSquared": "65536",
        });
        let statement_hash = statement_hash_for_payload(
            "ballot-proof-linear-proof-statement-v1",
            &statement_payload,
        );
        statement_payload
            .as_object_mut()
            .expect("linear statement should be an object")
            .insert("statementHash".to_string(), json!(statement_hash));
        statement_payload
    }

    #[allow(clippy::too_many_arguments)]
    fn sparse_statement(
        component_id: &str,
        component_statement_hash: &Value,
        parameter_profile_id: &str,
        backend_statement_hash: &str,
        relation_statement_hash: &str,
        ballot_proof_statement_hash: &str,
        coefficient_modulus: &str,
        projection_coverage: &str,
        target_constant_coefficient: Option<&str>,
        witness_l2_bound_squared: &str,
    ) -> Value {
        let matrix_entries = json!([
            {
                "rowIndex": 0,
                "columnIndex": 0,
                "constantCoefficient": 1
            }
        ]);
        let target_entries = target_constant_coefficient.map_or_else(
            || json!([]),
            |constant_coefficient| {
                json!([
                    {
                        "rowIndex": 0,
                        "constantCoefficient": constant_coefficient
                    }
                ])
            },
        );
        let target_entry_count = if target_constant_coefficient.is_some() {
            1
        } else {
            0
        };
        let mut statement_payload = json!({
            "objectType": "BallotProofSparseComponentLinearProofStatement",
            "objectVersion": 1,
            "backendStatementHash": backend_statement_hash,
            "ballotProofStatementHash": ballot_proof_statement_hash,
            "coefficientModulus": coefficient_modulus,
            "componentId": component_id,
            "componentStatementHash": component_statement_hash,
            "parameterProfileId": parameter_profile_id,
            "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
            "projectionCoverage": projection_coverage,
            "relation": "A*w + t = 0",
            "relationStatementHash": relation_statement_hash,
            "sourceBackendColumnIndices": [0],
            "sourceRingDegree": 64,
            "sparseStatementMatrixHash": super::derive_sparse_statement_matrix_hash(&matrix_entries)
                .expect("sparse matrix hash should derive"),
            "sparseStatementMatrixEntries": matrix_entries,
            "sparseStatementTermCount": 1,
            "statementColumns": 1,
            "statementRows": 1,
            "targetCoefficientRepresentation": "centeredSignedSourceModulus",
            "targetVectorHash": super::derive_sparse_target_vector_hash(&target_entries)
                .expect("sparse target hash should derive"),
            "targetVectorEntries": target_entries,
            "targetVectorEntryCount": target_entry_count,
            "witnessL2BoundSquared": witness_l2_bound_squared
        });
        let statement_hash = statement_hash_for_payload(
            "ballot-proof-sparse-linear-proof-statement-v1",
            &statement_payload,
        );
        statement_payload
            .as_object_mut()
            .expect("sparse statement should be an object")
            .insert("statementHash".to_string(), json!(statement_hash));
        statement_payload
    }

    fn structured_statement(
        component_statement_hash: &Value,
        backend_statement_hash: &str,
        relation_statement_hash: &str,
        ballot_proof_statement_hash: &str,
    ) -> Value {
        let module_degree = 256_usize;
        let module_rank = 4_usize;
        let zero_polynomial = vec![0_u64; module_degree];
        let zero_vector = vec![zero_polynomial.clone(); module_rank];
        let mut statement_payload = json!({
            "objectType": "BallotProofStructuredReceiverEncryptionProofStatement",
            "objectVersion": 1,
            "backendStatementHash": backend_statement_hash,
            "ballotProofStatementHash": ballot_proof_statement_hash,
            "coefficientModulus": "12289",
            "componentId": "receiver-encryption-component",
            "componentStatementHash": component_statement_hash,
            "matrixHash": test_hash("receiver-encryption-matrix"),
            "parameterProfileId": "receiver-encryption-test-proof-parameter-v1",
            "proofStatementFormat": "structured-module-lwe-linear-proof-v1",
            "proofSystemRingDegree": 64,
            "receiverEncryptionProfileHash": test_hash("receiver-encryption-profile"),
            "receiverRows": [
                {
                    "ciphertextChunkCount": 1,
                    "ciphertextChunks": [
                        {
                            "chunkIndex": 0,
                            "firstCiphertextVector": zero_vector,
                            "firstNoisePolynomialColumnIndices": [4, 5, 6, 7],
                            "plaintextPolynomialColumnIndex": 9,
                            "randomnessPolynomialColumnIndices": [0, 1, 2, 3],
                            "secondCiphertextPolynomial": zero_polynomial,
                            "secondNoiseColumnIndex": 8
                        }
                    ],
                    "plaintextBitLength": 0,
                    "publicKeyVector": zero_vector,
                    "publicMatrixSeedHash": test_hash("receiver-public-matrix-seed"),
                    "receiverIdentity": "receiver-1",
                    "receiverPayloadHash": test_hash("receiver-payload"),
                    "receiverPublicKeyHash": test_hash("receiver-public-key"),
                    "receiverRosterPosition": 1,
                    "rowCount": 5,
                    "rowOffsetWithinStatement": 0
                }
            ],
            "relation": "A*w + t = 0",
            "relationStatementHash": relation_statement_hash,
            "sourceBackendColumnIndices": [0],
            "sourceRingDegree": 256,
            "statementColumns": 10,
            "statementRows": 5,
            "matrixCoefficientRepresentation": "centeredSignedSourceModulus",
            "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
            "targetVectorHash": test_hash("receiver-encryption-target"),
            "witnessL2BoundSquared": "65536"
        });
        let statement_hash = statement_hash_for_payload(
            "ballot-proof-structured-receiver-encryption-proof-statement-v1",
            &statement_payload,
        );
        statement_payload
            .as_object_mut()
            .expect("structured statement should be an object")
            .insert("statementHash".to_string(), json!(statement_hash));
        statement_payload
    }

    let backend_statement_hash = test_hash("generated-backend-statement");
    let relation_statement_hash = test_hash("generated-relation-statement");
    let statement_matrix_hash = test_hash("generated-statement-matrix");
    let target_vector_hash = test_hash("generated-target-vector");
    let ballot_statement_payload = json!({
        "objectType": "BallotProofStatement",
        "objectVersion": 1,
        "actionContextHash": test_hash("action-context"),
        "aggregateInputEncodingProfileHash": test_hash("aggregate-input-encoding-profile"),
        "ballotPackageHash": test_hash("ballot-package"),
        "ballotProofProfileHash": test_hash("ballot-proof-profile"),
        "ballotScoreEncodingProfileHash": test_hash("ballot-score-encoding-profile"),
        "ballotShareLayoutProfileHash": test_hash("ballot-share-layout-profile"),
        "ceremonyId": "ceremony-generated-ballot-proof-record",
        "challengeDomainHash": test_hash("challenge-domain"),
        "duplicateBallotPolicyHash": test_hash("duplicate-ballot-policy"),
        "encodedAggregateLayoutHash": test_hash("encoded-aggregate-layout"),
        "encodedShareVectorLayoutHash": test_hash("encoded-share-vector-layout"),
        "manifestHash": test_hash("manifest"),
        "optionCount": 2,
        "pollSpecHash": test_hash("poll-spec"),
        "receiverEncryptionProfileHash": test_hash("receiver-encryption-profile"),
        "receiverKeyProofRoot": test_hash("receiver-key-proof-root"),
        "receiverKeyRoot": test_hash("receiver-key-root"),
        "receiverPayloads": [
            {
                "receiverIdentity": "receiver-1",
                "receiverPayloadCiphertextRoot": test_hash("payload-ciphertext-root"),
                "receiverPayloadHash": test_hash("payload"),
                "receiverRosterPosition": 1
            },
            {
                "receiverIdentity": "receiver-2",
                "receiverPayloadCiphertextRoot": test_hash("payload-ciphertext-root-2"),
                "receiverPayloadHash": test_hash("payload-2"),
                "receiverRosterPosition": 2
            },
            {
                "receiverIdentity": "receiver-3",
                "receiverPayloadCiphertextRoot": test_hash("payload-ciphertext-root-3"),
                "receiverPayloadHash": test_hash("payload-3"),
                "receiverRosterPosition": 3
            }
        ],
        "receiverPublicKeys": [
            {
                "receiverIdentity": "receiver-1",
                "receiverPublicKeyHash": test_hash("receiver-public-key"),
                "receiverRosterPosition": 1
            },
            {
                "receiverIdentity": "receiver-2",
                "receiverPublicKeyHash": test_hash("receiver-public-key-2"),
                "receiverRosterPosition": 2
            },
            {
                "receiverIdentity": "receiver-3",
                "receiverPublicKeyHash": test_hash("receiver-public-key-3"),
                "receiverRosterPosition": 3
            }
        ],
        "rosterHash": test_hash("roster"),
        "rosterExternalAcceptanceHash": test_hash("roster-acceptance"),
        "scoreDomainHash": test_hash("score-domain"),
        "scoreMembershipProfileHash": test_hash("score-membership-profile"),
        "shareCommitmentMessageBoundCertHash": test_hash("share-commitment-bound-cert"),
        "shareCommitmentProfileHash": test_hash("share-commitment-profile"),
        "shareCommitments": [
            {
                "receiverIdentity": "receiver-1",
                "receiverRosterPosition": 1,
                "shareCommitmentHash": test_hash("share-commitment")
            },
            {
                "receiverIdentity": "receiver-2",
                "receiverRosterPosition": 2,
                "shareCommitmentHash": test_hash("share-commitment-2")
            },
            {
                "receiverIdentity": "receiver-3",
                "receiverRosterPosition": 3,
                "shareCommitmentHash": test_hash("share-commitment-3")
            }
        ],
        "shareVectorWidth": 22,
        "thresholdProfileHash": test_hash("threshold-profile"),
        "tiePolicyHash": test_hash("tie-policy"),
        "topOptionCount": 1,
        "voterIdentityHash": test_hash("voter-identity"),
        "voterRosterPosition": 1,
        "voterSigningKeyHash": test_hash("voter-signing-key")
    });
    let mut statement = ballot_statement_payload;
    let ballot_proof_statement_hash = hash_for_payload("BallotProofStatementHash", &statement);
    statement
        .as_object_mut()
        .expect("statement should be an object")
        .insert(
            "ballotProofStatementHash".to_string(),
            json!(ballot_proof_statement_hash),
        );
    let ballot_proof_statement_hash = statement["ballotProofStatementHash"]
        .as_str()
        .expect("ballot proof statement hash should be a string")
        .to_string();
    let score_component = component_statement(
        "score-and-shamir-field-component",
        "score-component-statement",
        &backend_statement_hash,
        &relation_statement_hash,
        &ballot_proof_statement_hash,
        "65537",
        1,
        1,
    );
    let payload_component = component_statement(
        "payload-plaintext-field-component",
        "payload-component-statement",
        &backend_statement_hash,
        &relation_statement_hash,
        &ballot_proof_statement_hash,
        "65537",
        1,
        1,
    );
    let share_component = component_statement(
        "share-commitment-component",
        "share-component-statement",
        &backend_statement_hash,
        &relation_statement_hash,
        &ballot_proof_statement_hash,
        "18446744069414584321",
        1,
        1,
    );
    let receiver_encryption_component = component_statement(
        "receiver-encryption-component",
        "receiver-encryption-component-statement",
        &backend_statement_hash,
        &relation_statement_hash,
        &ballot_proof_statement_hash,
        "12289",
        1280,
        1,
    );
    let receiver_key_component = component_statement(
        "receiver-key-binding-component",
        "receiver-key-binding-component-statement",
        &backend_statement_hash,
        &relation_statement_hash,
        &ballot_proof_statement_hash,
        "12289",
        1,
        0,
    );
    let component_statements = vec![
        score_component.clone(),
        payload_component.clone(),
        share_component.clone(),
        receiver_encryption_component.clone(),
        receiver_key_component.clone(),
    ];
    let component_bundle_payload = json!({
        "objectType": "BallotProofComponentBundleStatement",
        "objectVersion": 1,
        "backendStatementHash": backend_statement_hash,
        "ballotProofStatementHash": ballot_proof_statement_hash,
        "bundleCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "componentStatements": component_statements,
        "relationLabel": "BallotPrivacyPvssRelation",
        "relationStatementHash": relation_statement_hash,
        "requiredComponentIds": super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
    });
    let mut component_bundle_statement = component_bundle_payload;
    let component_bundle_statement_hash =
        super::derive_ballot_component_bundle_statement_hash(&component_bundle_statement)
            .expect("component bundle statement hash should derive");
    component_bundle_statement
        .as_object_mut()
        .expect("component bundle statement should be an object")
        .insert(
            "componentBundleStatementHash".to_string(),
            json!(component_bundle_statement_hash),
        );
    let relation_binding_hash =
        super::linear_proof::contract_validation::derive_full_relation_binding_hash(
            &component_bundle_statement,
        )
        .expect("relation binding hash should derive");
    let binding_scalar =
        super::linear_proof::contract_validation::binding_scalar_from_hash(&relation_binding_hash)
            .expect("binding scalar should derive");
    let mut linear_statement = dense_linear_statement(
        "full-ballot-proof",
        &Value::Null,
        super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
        &backend_statement_hash,
        &relation_statement_hash,
        &ballot_proof_statement_hash,
        &statement_matrix_hash,
        &target_vector_hash,
        super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        1,
    );
    linear_statement["targetVectorCoefficients"][0][0] = json!(65_537 - binding_scalar);
    {
        let linear_statement_object = linear_statement
            .as_object_mut()
            .expect("linear statement should be an object");
        linear_statement_object.remove("statementHash");
        linear_statement_object.insert(
            "componentBundleStatementHash".to_string(),
            json!(component_bundle_statement_hash),
        );
        linear_statement_object.insert(
            "relationBindingHash".to_string(),
            json!(relation_binding_hash),
        );
        linear_statement_object.insert(
            "relationBindingKind".to_string(),
            json!("component-bundle-and-lowered-relation"),
        );
    }
    let linear_statement_hash =
        statement_hash_for_payload("ballot-proof-linear-proof-statement-v1", &linear_statement);
    linear_statement
        .as_object_mut()
        .expect("linear statement should still be an object")
        .insert("statementHash".to_string(), json!(linear_statement_hash));
    let full_parameter_set = parameter_set_value(
        super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
        "sealed-lattice/linear-proof/full-ballot-binding-parameters-v1",
        64,
        65_537,
        1,
        1,
        u128::from(GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED),
    );
    let full_proof_encoding = proof_encoding_value(
        super::FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
        "sealed-lattice/linear-proof/full-ballot-binding-encoding-v1",
        2,
    );
    let score_parameter_set = parameter_set_value(
        "encoded-score-field-linear-proof-parameter-v1",
        "sealed-lattice/linear-proof/generated-score-test-parameters-v1",
        64,
        65_537,
        1,
        1,
        u128::from(GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED),
    );
    let payload_parameter_set = parameter_set_value(
        "payload-plaintext-field-linear-proof-parameter-v1",
        "sealed-lattice/linear-proof/generated-payload-test-parameters-v1",
        64,
        65_537,
        1,
        1,
        u128::from(GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED),
    );
    let share_parameter_set = parameter_set_value(
        "share-commitment-linear-proof-parameter-v1",
        "sealed-lattice/linear-proof/generated-share-test-parameters-v1",
        64,
        18_446_744_069_414_584_321,
        1,
        1,
        u128::from(GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED),
    );
    let receiver_encryption_parameter_set = parameter_set_value(
        "receiver-encryption-linear-proof-parameter-v1",
        "sealed-lattice/linear-proof/generated-receiver-encryption-test-parameters-v1",
        256,
        12_289,
        5,
        10,
        u128::from(GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED),
    );
    let component_proof_inputs = json!([
        {
            "componentId": "score-and-shamir-field-component",
            "proofEncoding": proof_encoding_value(
                "encoded-score-field-linear-proof-encoding-v1",
                "sealed-lattice/linear-proof/generated-score-component-test-encoding-v1",
                2
            ),
            "proofParameterSet": score_parameter_set,
            "proofStatement": dense_linear_statement(
                "score-and-shamir-field-component",
                &score_component["componentStatementHash"],
                "encoded-score-field-linear-proof-parameter-v1",
                &backend_statement_hash,
                &relation_statement_hash,
                &ballot_proof_statement_hash,
                &statement_matrix_hash,
                &target_vector_hash,
                "encoded-score-field-rows-only",
                1
            ),
            "proofStatementFormat": "dense-polynomial-matrix-linear-proof-v1",
            "publicRandomnessHex": "11".repeat(32),
            "statementHash": score_component["componentStatementHash"],
        },
        {
            "componentId": "payload-plaintext-field-component",
            "proofEncoding": proof_encoding_value(
                "payload-plaintext-field-linear-proof-encoding-v1",
                "sealed-lattice/linear-proof/generated-payload-component-test-encoding-v1",
                2
            ),
            "proofParameterSet": payload_parameter_set,
            "proofStatement": sparse_statement(
                "payload-plaintext-field-component",
                &payload_component["componentStatementHash"],
                "payload-plaintext-field-linear-proof-parameter-v1",
                &backend_statement_hash,
                &relation_statement_hash,
                &ballot_proof_statement_hash,
                "65537",
                "payload-plaintext-field-rows-only",
                None,
                "65536"
            ),
            "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
            "publicRandomnessHex": "22".repeat(32),
            "statementHash": payload_component["componentStatementHash"],
        },
        {
            "componentId": "share-commitment-component",
            "proofEncoding": proof_encoding_value(
                "share-commitment-linear-proof-encoding-v1",
                "sealed-lattice/linear-proof/generated-share-component-test-encoding-v1",
                2
            ),
            "proofParameterSet": share_parameter_set,
            "proofStatement": sparse_statement(
                "share-commitment-component",
                &share_component["componentStatementHash"],
                "share-commitment-linear-proof-parameter-v1",
                &backend_statement_hash,
                &relation_statement_hash,
                &ballot_proof_statement_hash,
                "18446744069414584321",
                "share-commitment-rows-only",
                Some("18446744069414584316"),
                "1048576"
            ),
            "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
            "publicRandomnessHex": "00".repeat(32),
            "statementHash": share_component["componentStatementHash"],
        },
        {
            "componentId": "receiver-encryption-component",
            "proofEncoding": proof_encoding_value(
                "receiver-encryption-linear-proof-encoding-v1",
                "sealed-lattice/linear-proof/generated-receiver-encryption-component-test-encoding-v1",
                41
            ),
            "proofParameterSet": receiver_encryption_parameter_set,
            "proofStatement": structured_statement(
                &receiver_encryption_component["componentStatementHash"],
                &backend_statement_hash,
                &relation_statement_hash,
                &ballot_proof_statement_hash
            ),
            "proofStatementFormat": "structured-module-lwe-linear-proof-v1",
            "publicRandomnessHex": "44".repeat(32),
            "statementHash": receiver_encryption_component["componentStatementHash"],
        },
        {
            "componentId": "receiver-key-binding-component",
            "proofEncoding": proof_encoding_value(
                "receiver-encryption-linear-proof-encoding-v1",
                "sealed-lattice/linear-proof/generated-receiver-key-binding-component-test-encoding-v1",
                2
            ),
            "proofParameterSet": parameter_set_value(
                "receiver-key-binding-linear-proof-parameter-v1",
                "sealed-lattice/linear-proof/generated-receiver-key-binding-test-parameters-v1",
                64,
                12_289,
                1,
                1,
                u128::from(GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED)
            ),
            "proofStatement": component_proof_statement_for_test(
                "receiver-key-binding-component",
                &receiver_key_component["componentStatementHash"],
                None,
                "public-binding-check-only-v1"
            ),
            "proofStatementFormat": "public-binding-check-only-v1",
            "publicRandomnessHex": "55".repeat(32),
            "statementHash": receiver_key_component["componentStatementHash"],
        }
    ]);
    let mut full_ballot_witness_polynomial = vec![0_i64; 64];
    full_ballot_witness_polynomial[0] =
        i64::try_from(binding_scalar).expect("binding scalar should fit i64");
    let secret_state = json!({
        "sourceWitnessCoefficients": [full_ballot_witness_polynomial]
    });
    let mut dense_component_witness_polynomial = vec![0_i64; 64];
    dense_component_witness_polynomial[0] = 5;
    let dense_component_secret_state = json!({
        "sourceWitnessCoefficients": [dense_component_witness_polynomial]
    });
    let scalar_component_secret_state = json!({
        "sourceWitnessCoefficients": [vec![0_i64; 64]]
    });
    let mut share_witness_polynomial = vec![0_i64; 64];
    share_witness_polynomial[0] = 5;
    let share_component_secret_state = json!({
        "sourceWitnessCoefficients": [share_witness_polynomial]
    });
    let receiver_encryption_component_secret_state = json!({
        "sourceWitnessCoefficients": vec![vec![0_i64; 256]; 10]
    });
    let component_secret_states = json!({
        "score-and-shamir-field-component": dense_component_secret_state,
        "payload-plaintext-field-component": scalar_component_secret_state.clone(),
        "share-commitment-component": share_component_secret_state,
        "receiver-encryption-component": receiver_encryption_component_secret_state,
    });
    let generation = super::generate_ballot_proof_record(super::BallotProofRecordGenerationInput {
        statement: Some(&statement),
        linear_statement: Some(&linear_statement),
        parameter_set: Some(&full_parameter_set),
        proof_encoding: Some(&full_proof_encoding),
        public_randomness_hex: Some(&"00".repeat(32)),
        component_bundle_statement: Some(&component_bundle_statement),
        component_proof_inputs: Some(&component_proof_inputs),
        secret_state: Some(&secret_state),
        prover_randomness_hex: Some(&"07".repeat(32)),
        component_prover_randomness_hexes: Some(&json!({
            "score-and-shamir-field-component": "07".repeat(32),
            "payload-plaintext-field-component": "a2".repeat(32),
            "share-commitment-component": "0c".repeat(32),
            "receiver-encryption-component": "a4".repeat(32)
        })),
        component_secret_states: Some(&component_secret_states),
        casual_micro_roster_acknowledged: true,
    });

    assert_eq!(
        generation["ok"], true,
        "generated ballot proof record should verify: {generation}"
    );
    assert_eq!(generation["verification"]["ok"], true);
    assert_eq!(
        generation["componentProofBundle"]["componentProofs"]
            .as_array()
            .expect("component proofs should be an array")
            .len(),
        super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len()
    );
    assert!(
        generation["componentProofInputs"]
            .as_array()
            .expect("component proof inputs should be an array")
            .iter()
            .all(|component_input| component_input
                .get("proofBytesHex")
                .and_then(Value::as_str)
                .is_some())
    );

    let mut wrong_secret_state = secret_state.clone();
    let wrong_binding_scalar = if binding_scalar == 1 { 2 } else { 1 };
    wrong_secret_state["sourceWitnessCoefficients"][0][0] = json!(wrong_binding_scalar);
    let wrong_generation =
        super::generate_ballot_proof_record(super::BallotProofRecordGenerationInput {
            statement: Some(&statement),
            linear_statement: Some(&linear_statement),
            parameter_set: Some(&full_parameter_set),
            proof_encoding: Some(&full_proof_encoding),
            public_randomness_hex: Some(&"00".repeat(32)),
            component_bundle_statement: Some(&component_bundle_statement),
            component_proof_inputs: Some(&component_proof_inputs),
            secret_state: Some(&wrong_secret_state),
            prover_randomness_hex: Some(&"07".repeat(32)),
            component_prover_randomness_hexes: Some(&json!({
                "score-and-shamir-field-component": "07".repeat(32),
                "payload-plaintext-field-component": "a2".repeat(32),
                "share-commitment-component": "0c".repeat(32),
                "receiver-encryption-component": "a4".repeat(32)
            })),
            component_secret_states: Some(&component_secret_states),
            casual_micro_roster_acknowledged: true,
        });
    assert_eq!(wrong_generation["ok"], false);
    assert_eq!(wrong_generation["unresolvedReason"], "BallotPackageInvalid");
}

#[test]
fn malformed_receiver_key_proof_rejects_before_backend_gate() {
    let verification = super::verify_receiver_key_proof_from_command_request(&json!({
        "receiverKeyProof": {
            "objectType": "ReceiverKeyProof",
            "objectVersion": 1,
            "proofBackend": "LocalLinearLatticeRelation",
            "receiverKeyProofRoot": "00"
        }
    }));

    assert_eq!(verification["ok"], false);
    assert_eq!(verification["backendAvailable"], true);
    assert_eq!(verification["unresolvedReason"], "BallotPackageInvalid");
    assert_eq!(
        verification["refusedObjects"][0]["code"],
        "BallotPackageInvalid"
    );
}

pub(super) fn zero_receiver_key_source_polynomial() -> Vec<u64> {
    vec![0_u64; 256]
}

pub(super) fn zero_receiver_key_witness_polynomial() -> Vec<i64> {
    vec![0_i64; 256]
}

pub(super) fn unit_receiver_key_source_polynomial() -> Vec<u64> {
    let mut polynomial = zero_receiver_key_source_polynomial();
    polynomial[0] = 1;
    polynomial
}

pub(super) fn canonical_receiver_key_witness_polynomial(
    polynomial: &[i64],
    modulus: u64,
) -> Vec<u64> {
    polynomial
        .iter()
        .map(|coefficient| {
            if *coefficient < 0 {
                modulus - coefficient.unsigned_abs()
            } else {
                coefficient.unsigned_abs()
            }
        })
        .collect()
}
