use super::*;

fn sparse_component_proof_statement_from_dense_statement(
    component_id: &str,
    dense_statement: &Value,
) -> Value {
    let statement_rows = integer_property(dense_statement, "statementRows");
    let statement_columns = integer_property(dense_statement, "statementColumns");
    let ring_degree = integer_property(dense_statement, "ringDegree");
    let statement_matrix = dense_statement["statementMatrixCoefficients"]
        .as_array()
        .expect("dense statement matrix should be an array");
    let target_vector = dense_statement["targetVectorCoefficients"]
        .as_array()
        .expect("dense target vector should be an array");
    let matrix_coefficient_representation = dense_statement
        .get("matrixCoefficientRepresentation")
        .and_then(Value::as_str)
        .expect("dense statement should define matrixCoefficientRepresentation");
    assert_eq!(
        statement_matrix.len(),
        statement_rows,
        "dense statement matrix row count should match statementRows"
    );
    assert_eq!(
        target_vector.len(),
        statement_rows,
        "dense target vector row count should match statementRows"
    );
    let mut sparse_matrix_entries = Vec::new();
    for (row_index, matrix_row) in statement_matrix.iter().enumerate().take(statement_rows) {
        let matrix_row_entries = matrix_row
            .as_array()
            .expect("matrix row should be an array");
        assert_eq!(
            matrix_row_entries.len(),
            statement_columns,
            "dense statement matrix column count should match statementColumns"
        );
        for (column_index, matrix_entry) in matrix_row_entries
            .iter()
            .enumerate()
            .take(statement_columns)
        {
            let polynomial_coefficients = matrix_entry
                .as_array()
                .expect("matrix polynomial should be an array");
            assert_eq!(
                polynomial_coefficients.len(),
                ring_degree,
                "matrix polynomial degree should match ring degree"
            );
            assert!(
                polynomial_coefficients
                    .iter()
                    .skip(1)
                    .all(|coefficient| coefficient.as_u64() == Some(0)),
                "test sparse conversion only supports constant source polynomials"
            );
            if polynomial_coefficients[0].as_u64() != Some(0) {
                sparse_matrix_entries.push(json!({
                    "rowIndex": row_index,
                    "columnIndex": column_index,
                    "constantCoefficient": polynomial_coefficients[0]
                }));
            }
        }
    }

    let mut target_entries = Vec::new();
    for (row_index, target_entry) in target_vector.iter().enumerate().take(statement_rows) {
        let polynomial_coefficients = target_entry
            .as_array()
            .expect("target polynomial should be an array");
        assert_eq!(
            polynomial_coefficients.len(),
            ring_degree,
            "target polynomial degree should match ring degree"
        );
        assert!(
            polynomial_coefficients
                .iter()
                .skip(1)
                .all(|coefficient| coefficient.as_u64() == Some(0)),
            "test sparse conversion only supports constant target polynomials"
        );
        if polynomial_coefficients[0].as_u64() != Some(0) {
            target_entries.push(json!({
                "rowIndex": row_index,
                "constantCoefficient": polynomial_coefficients[0]
            }));
        }
    }

    let sparse_matrix_entries_value = json!(sparse_matrix_entries);
    let target_entries_value = json!(target_entries);
    let sparse_matrix_digest =
        super::derive_sparse_statement_matrix_digest(&sparse_matrix_entries_value)
            .expect("sparse matrix digest should derive");
    let target_vector_digest = super::derive_sparse_target_vector_digest(&target_entries_value)
        .expect("sparse target vector digest should derive");
    let source_backend_column_indices = (0..statement_columns).collect::<Vec<_>>();
    let sparse_statement_payload = json!({
        "backendStatementDigest": dense_statement["backendStatementDigest"],
        "ballotProofStatementDigest": dense_statement["ballotProofStatementDigest"],
        "coefficientModulus": dense_statement["coefficientModulus"],
        "componentId": component_id,
        "objectType": "BallotProofSparseComponentLinearProofStatement",
        "objectVersion": 1,
        "parameterProfileId": dense_statement["parameterProfileId"],
        "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
        "projectionCoverage": "payload-plaintext-field-rows-only",
        "relation": dense_statement["relation"],
        "relationStatementDigest": dense_statement["relationStatementDigest"],
        "sourceBackendColumnIndices": source_backend_column_indices,
        "sourceRingDegree": dense_statement["ringDegree"],
        "matrixCoefficientRepresentation": matrix_coefficient_representation,
        "sparseStatementMatrixDigest": sparse_matrix_digest,
        "sparseStatementMatrixEntries": sparse_matrix_entries_value,
        "sparseStatementTermCount": sparse_matrix_entries_value.as_array().expect("sparse matrix entries should be an array").len(),
        "statementColumns": dense_statement["statementColumns"],
        "statementRows": dense_statement["statementRows"],
        "targetCoefficientRepresentation": dense_statement["targetCoefficientRepresentation"],
        "targetVectorDigest": target_vector_digest,
        "targetVectorEntries": target_entries_value,
        "targetVectorEntryCount": target_entries_value.as_array().expect("target entries should be an array").len(),
        "witnessL2BoundSquared": dense_statement["witnessL2BoundSquared"]
    });
    let sparse_statement_digest =
        super::derive_ballot_sparse_linear_statement_digest(&sparse_statement_payload)
            .expect("sparse statement digest should derive");
    let mut sparse_statement = sparse_statement_payload;
    sparse_statement
        .as_object_mut()
        .expect("sparse statement should be an object")
        .insert(
            "statementDigest".to_string(),
            json!(sparse_statement_digest),
        );

    sparse_statement
}

fn sparse_component_proof_input_for_vector(
    component_id: &str,
    vectors: &Value,
    vector_case: &Value,
) -> Value {
    let dense_component_proof_input =
        dense_component_proof_input_for_vector(component_id, vectors, vector_case);
    let sparse_statement = sparse_component_proof_statement_from_dense_statement(
        component_id,
        &dense_component_proof_input["proofStatement"],
    );

    json!({
        "componentId": component_id,
        "proofBytesHex": vector_case["proofHex"],
        "proofEncoding": vectors["proofEncoding"],
        "proofParameterSet": vectors["parameterSet"],
        "proofStatement": sparse_statement,
        "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
        "publicRandomnessHex": vector_case["publicRandomnessHex"],
        "statementDigest": dense_component_proof_input["statementDigest"]
    })
}

fn sparse_statement_for_dense_compatibility_test(
    statement_rows: usize,
    statement_columns: usize,
    source_ring_degree: usize,
    coefficient_modulus: u64,
    matrix_entries_value: Value,
    target_entries_value: Value,
) -> Value {
    let sparse_statement_matrix_digest =
        super::derive_sparse_statement_matrix_digest(&matrix_entries_value)
            .expect("sparse matrix digest should derive");
    let target_vector_digest = super::derive_sparse_target_vector_digest(&target_entries_value)
        .expect("sparse target digest should derive");
    json!({
        "coefficientModulus": coefficient_modulus.to_string(),
        "objectType": "BallotProofSparseComponentLinearProofStatement",
        "objectVersion": 1,
        "sourceRingDegree": source_ring_degree,
        "sparseStatementMatrixDigest": sparse_statement_matrix_digest,
        "sparseStatementMatrixEntries": matrix_entries_value,
        "sparseStatementTermCount": matrix_entries_value
            .as_array()
            .expect("matrix entries should be an array")
            .len(),
        "statementColumns": statement_columns,
        "statementRows": statement_rows,
        "targetVectorDigest": target_vector_digest,
        "targetVectorEntries": target_entries_value,
        "targetVectorEntryCount": target_entries_value
            .as_array()
            .expect("target entries should be an array")
            .len()
    })
}

#[test]
fn sparse_component_statement_parser_supports_polynomial_entries() {
    let sparse_statement = sparse_statement_for_dense_compatibility_test(
        2,
        2,
        4,
        17,
        json!([
            {
                "rowIndex": 0,
                "columnIndex": 1,
                "polynomialCoefficients": [0, 2, 0, 16]
            },
            {
                "rowIndex": 1,
                "columnIndex": 0,
                "constantCoefficient": 5
            }
        ]),
        json!([
            {
                "rowIndex": 0,
                "polynomialCoefficients": [1, 0, 3, 0]
            },
            {
                "rowIndex": 1,
                "constantCoefficient": 7
            }
        ]),
    );
    let (dense_matrix, dense_target) =
        super::dense_matrix_from_sparse_component_statement(&sparse_statement)
            .expect("polynomial sparse statement should densify");

    assert_eq!(
        dense_matrix,
        json!([[[0, 0, 0, 0], [0, 2, 0, 16]], [[5, 0, 0, 0], [0, 0, 0, 0]]])
    );
    assert_eq!(dense_target, json!([[1, 0, 3, 0], [7, 0, 0, 0]]));
}

#[test]
fn sparse_component_statement_parser_rejects_noncanonical_entries() {
    let both_encodings_statement = sparse_statement_for_dense_compatibility_test(
        1,
        1,
        4,
        17,
        json!([
            {
                "rowIndex": 0,
                "columnIndex": 0,
                "constantCoefficient": 1,
                "polynomialCoefficients": [1, 0, 0, 0]
            }
        ]),
        json!([]),
    );
    let both_encodings_error =
        super::dense_matrix_from_sparse_component_statement(&both_encodings_statement)
            .expect_err("sparse entries with both encodings should be rejected");
    assert_eq!(both_encodings_error.code, "BallotPackageInvalid");
    assert!(
        both_encodings_error
            .message
            .contains("either constantCoefficient or polynomialCoefficients")
    );

    let noncanonical_statement = sparse_statement_for_dense_compatibility_test(
        1,
        1,
        4,
        17,
        json!([
            {
                "rowIndex": 0,
                "columnIndex": 0,
                "polynomialCoefficients": [1, 0, 17, 0]
            }
        ]),
        json!([]),
    );
    let noncanonical_error =
        super::dense_matrix_from_sparse_component_statement(&noncanonical_statement)
            .expect_err("noncanonical sparse coefficients should be rejected");
    assert_eq!(noncanonical_error.code, "BallotPackageInvalid");
    assert!(noncanonical_error.message.contains("not canonical"));

    let zero_entry_statement = sparse_statement_for_dense_compatibility_test(
        1,
        1,
        4,
        17,
        json!([
            {
                "rowIndex": 0,
                "columnIndex": 0,
                "polynomialCoefficients": [0, 0, 0, 0]
            }
        ]),
        json!([]),
    );
    let zero_entry_error =
        super::dense_matrix_from_sparse_component_statement(&zero_entry_statement)
            .expect_err("zero sparse entries should be rejected");
    assert_eq!(zero_entry_error.code, "BallotPackageInvalid");
    assert!(zero_entry_error.message.contains("zero polynomials"));
}

#[test]
fn sparse_component_statement_large_shape_parses_without_dense_allocation() {
    let sparse_statement =
        sparse_statement_for_dense_compatibility_test(1024, 1024, 64, 17, json!([]), json!([]));
    let parsed_sparse_statement =
        super::sparse_matrix_from_sparse_component_statement(&sparse_statement)
            .expect("large sparse statement should parse without dense allocation");

    assert_eq!(parsed_sparse_statement.source_statement_matrix.rows(), 1024);
    assert_eq!(
        parsed_sparse_statement.source_statement_matrix.columns(),
        1024
    );

    let component_id = "share-commitment-component";
    let component_proof = component_proof_record_for_vector(component_id, "00");
    let proof_input = json!({
        "componentId": component_id,
        "proofBytesHex": "00",
        "proofEncoding": {
            "profileId": "test-proof-encoding"
        },
        "proofParameterSet": {
            "profileId": "test-proof-parameter-set"
        },
        "proofStatement": sparse_statement,
        "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
        "publicRandomnessHex": "00".repeat(32),
        "statementDigest": test_digest("large-sparse-statement")
    });
    let component_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        component_id,
        &component_proof,
        &proof_input,
    );

    assert_eq!(component_verification["ok"], false);
    assert_eq!(
        component_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert_ne!(
        component_verification["unresolvedReason"],
        "OperationUnavailable"
    );
}

fn structured_receiver_encryption_statement_for_test(first_ciphertext_coefficient: u64) -> Value {
    let module_degree = 256_usize;
    let module_rank = 4_usize;
    let randomness_columns = (0..module_rank)
        .map(|vector_index| {
            (0..module_degree)
                .map(|coefficient_index| vector_index * module_degree + coefficient_index)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let first_noise_columns = (0..module_rank)
        .map(|vector_index| {
            (0..module_degree)
                .map(|coefficient_index| {
                    module_rank * module_degree + vector_index * module_degree + coefficient_index
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let second_noise_columns = (0..module_degree)
        .map(|coefficient_index| 2 * module_rank * module_degree + coefficient_index)
        .collect::<Vec<_>>();
    let zero_polynomial = vec![0_u64; module_degree];
    let mut first_ciphertext_polynomial = zero_polynomial.clone();
    first_ciphertext_polynomial[0] = first_ciphertext_coefficient;
    let first_ciphertext_vector = vec![
        first_ciphertext_polynomial,
        zero_polynomial.clone(),
        zero_polynomial.clone(),
        zero_polynomial.clone(),
    ];
    let zero_vector = vec![
        zero_polynomial.clone(),
        zero_polynomial.clone(),
        zero_polynomial.clone(),
        zero_polynomial.clone(),
    ];
    let mut statement = json!({
        "backendStatementDigest": test_digest("structured-backend-statement"),
        "coefficientModulus": "12289",
        "componentId": "receiver-encryption-component",
        "componentStatementDigest": test_digest("structured-component-statement"),
        "matrixDigest": test_digest("structured-matrix"),
        "objectType": "BallotProofStructuredReceiverEncryptionProofStatement",
        "objectVersion": 1,
        "parameterProfileId": "receiver-encryption-structured-test-v1",
        "proofStatementFormat": "structured-module-lwe-linear-proof-v1",
        "proofSystemRingDegree": 64,
        "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
        "receiverRows": [
            {
                "ciphertextChunkCount": 1,
                "ciphertextChunks": [
                    {
                        "chunkIndex": 0,
                        "firstCiphertextVector": first_ciphertext_vector,
                        "firstNoiseColumnIndices": first_noise_columns,
                        "plaintextBitColumnIndices": [],
                        "randomnessColumnIndices": randomness_columns,
                        "secondCiphertextPolynomial": zero_polynomial,
                        "secondNoiseColumnIndices": second_noise_columns
                    }
                ],
                "plaintextBitLength": 0,
                "publicKeyVector": zero_vector,
                "publicMatrixSeedDigest": test_digest("receiver-public-matrix-seed"),
                "receiverIdentity": "receiver-1",
                "receiverPayloadDigest": test_digest("receiver-payload"),
                "receiverPublicKeyDigest": test_digest("receiver-public-key"),
                "receiverRosterPosition": 1,
                "rowCount": 1280,
                "rowOffsetWithinStatement": 0
            }
        ],
        "relation": "A*w + t = 0",
        "relationStatementDigest": test_digest("structured-relation-statement"),
        "sourceBackendColumnIndices": (0..2304).collect::<Vec<_>>(),
        "sourceRingDegree": 256,
        "statementColumns": 2304,
        "statementRows": 1280,
        "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
        "targetVectorDigest": test_digest("structured-target"),
        "witnessL2BoundSquared": "8192"
    });
    let statement_digest =
        super::derive_ballot_structured_receiver_encryption_statement_digest(&statement)
            .expect("structured statement digest should derive");
    statement
        .as_object_mut()
        .expect("structured statement should be an object")
        .insert("statementDigest".to_string(), json!(statement_digest));

    statement
}

#[test]
fn structured_receiver_encryption_statement_lowers_public_module_lwe_rows() {
    let zero_ciphertext_statement = structured_receiver_encryption_statement_for_test(0);
    let parsed_zero_statement =
        super::structured_receiver_encryption_statement_as_sparse(&zero_ciphertext_statement)
            .expect("structured statement should lower to sparse rows");

    assert_eq!(parsed_zero_statement.source_statement_matrix.rows(), 1280);
    assert_eq!(
        parsed_zero_statement.source_statement_matrix.columns(),
        2304
    );
    assert_eq!(parsed_zero_statement.target_vector_coefficients[0][0], 0);
    assert!(
        parsed_zero_statement
            .source_statement_matrix
            .entries()
            .len()
            > 1024
    );

    let changed_ciphertext_statement = structured_receiver_encryption_statement_for_test(1);
    let parsed_changed_statement =
        super::structured_receiver_encryption_statement_as_sparse(&changed_ciphertext_statement)
            .expect("changed structured statement should lower");

    assert_eq!(
        parsed_changed_statement.target_vector_coefficients[0][0],
        12288
    );
}

#[test]
fn structured_receiver_encryption_statement_rejects_noncanonical_row_offsets() {
    let mut statement = structured_receiver_encryption_statement_for_test(0);
    statement["statementRows"] = json!(1281);
    statement["receiverRows"][0]["rowOffsetWithinStatement"] = json!(1);

    let error = match super::structured_receiver_encryption_statement_as_sparse(&statement) {
        Ok(_) => panic!("receiver row offsets must be canonical and contiguous"),
        Err(error) => error,
    };

    assert!(
        error.message.contains("canonical and contiguous"),
        "unexpected structured receiver row error: {error:?}"
    );
}

#[test]
fn component_linear_proof_bytes_verify_dense_and_sparse_public_statements() {
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
        .expect("valid proof bytes should be a string");
    let dense_component_id = "score-and-shamir-field-component";
    let dense_component_proof =
        component_proof_record_for_vector(dense_component_id, proof_bytes_hex);
    let dense_proof_input =
        dense_component_proof_input_for_vector(dense_component_id, &vectors, &valid_case);
    let dense_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        dense_component_id,
        &dense_component_proof,
        &dense_proof_input,
    );

    assert_eq!(
        dense_verification["ok"], true,
        "dense component statement should verify: {dense_verification}"
    );
    assert!(
        dense_verification["statusLabels"]
            .as_array()
            .expect("dense status labels should be an array")
            .contains(&json!("BallotProofComponentLinearProofVerified"))
    );

    let mutated_dense_proof_input =
        dense_component_proof_input_for_vector(dense_component_id, &vectors, &mutated_target_case);
    let mutated_dense_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        dense_component_id,
        &dense_component_proof,
        &mutated_dense_proof_input,
    );

    assert_eq!(mutated_dense_verification["ok"], false);
    assert_eq!(
        mutated_dense_verification["unresolvedReason"],
        "InvalidFixture"
    );

    let sparse_component_id = "payload-plaintext-field-component";
    let sparse_component_proof =
        component_proof_record_for_vector(sparse_component_id, proof_bytes_hex);
    let sparse_proof_input =
        sparse_component_proof_input_for_vector(sparse_component_id, &vectors, &valid_case);
    let sparse_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        sparse_component_id,
        &sparse_component_proof,
        &sparse_proof_input,
    );

    assert_eq!(
        sparse_verification["ok"], true,
        "sparse statement expansion should verify against the same proof bytes: {sparse_verification}"
    );

    let mut sparse_input_with_stale_target_digest = sparse_proof_input.clone();
    {
        let sparse_statement = sparse_input_with_stale_target_digest["proofStatement"]
            .as_object_mut()
            .expect("sparse proof statement should be an object");
        let target_entries = sparse_statement["targetVectorEntries"]
            .as_array_mut()
            .expect("target entries should be an array");
        let first_target_entry = target_entries
            .iter_mut()
            .find(|target_entry| target_entry["constantCoefficient"].as_u64() != Some(0))
            .expect("target should have a nonzero entry");
        first_target_entry
            .as_object_mut()
            .expect("target entry should be an object")
            .insert("constantCoefficient".to_string(), json!(3));
    }
    let stale_digest_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        sparse_component_id,
        &sparse_component_proof,
        &sparse_input_with_stale_target_digest,
    );

    assert_eq!(stale_digest_verification["ok"], false);
    assert_eq!(
        stale_digest_verification["refusedObjects"][0]["code"],
        "BallotPackageInvalid"
    );
    assert!(
        stale_digest_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("stale digest refusal should be a string")
            .contains("target vector digest")
    );

    let public_zero_component_id = "receiver-key-binding-component";
    let public_zero_component_statement_digest =
        json!(test_digest("receiver-key-binding-component-statement"));
    let public_zero_component_proof =
        component_proof_record_for_vector(public_zero_component_id, "");
    let public_zero_proof_input = component_proof_input_for_test(
        public_zero_component_id,
        &public_zero_component_statement_digest,
    );
    let public_zero_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        public_zero_component_id,
        &public_zero_component_proof,
        &public_zero_proof_input,
    );

    assert_eq!(public_zero_verification["ok"], true);
    assert!(
        public_zero_verification["statusLabels"]
            .as_array()
            .expect("public-zero status labels should be an array")
            .contains(&json!(
                "BallotProofComponentPublicZeroWitnessBindingChecked"
            ))
    );

    let mut public_zero_input_with_proof_bytes = public_zero_proof_input;
    public_zero_input_with_proof_bytes["proofBytesHex"] = json!("00");
    let public_zero_rejection = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        public_zero_component_id,
        &public_zero_component_proof,
        &public_zero_input_with_proof_bytes,
    );

    assert_eq!(public_zero_rejection["ok"], false);
    assert!(
        public_zero_rejection["refusedObjects"][0]["message"]
            .as_str()
            .expect("public-zero refusal message should be a string")
            .contains("must be empty")
    );

    let structured_component_id = "receiver-encryption-component";
    let structured_component_statement_digest =
        json!(test_digest("receiver-encryption-component-statement"));
    let structured_component_proof = component_proof_for_test(
        structured_component_id,
        &structured_component_statement_digest,
    );
    let structured_proof_input = component_proof_input_for_test(
        structured_component_id,
        &structured_component_statement_digest,
    );
    let structured_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        structured_component_id,
        &structured_component_proof,
        &structured_proof_input,
    );

    assert_eq!(structured_verification["ok"], false);
    assert_eq!(
        structured_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        structured_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("structured refusal message should be a string")
            .contains("require a public structured proof statement")
    );

    let mut malformed_structured_input = structured_proof_input;
    malformed_structured_input["proofStatement"]["structuredWitnessTermCount"] = json!("0");
    let malformed_structured_verification = super::verify_component_linear_proof_bytes(
        "verifyBallotProof",
        structured_component_id,
        &structured_component_proof,
        &malformed_structured_input,
    );

    assert_eq!(malformed_structured_verification["ok"], false);
    assert_eq!(
        malformed_structured_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        malformed_structured_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("malformed structured refusal should be a string")
            .contains("require a public structured proof statement")
    );
}

pub(super) fn test_digest(label: &str) -> String {
    super::derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "label": label,
            "purpose": "ballot-component-bundle-test"
        }),
    )
    .expect("test digest should derive")
}

pub(super) fn component_statement_for_test(
    component_id: &str,
    proof_lowering_status: &str,
) -> Value {
    let component_payload = json!({
        "objectType": "BallotProofComponentStatement",
        "objectVersion": 1,
        "backendStatementDigest": test_digest("backend-statement"),
        "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
        "coefficientModulus": "65537",
        "componentDigest": test_digest(&format!("{component_id}-component")),
        "componentId": component_id,
        "matrixDigest": test_digest(&format!("{component_id}-matrix")),
        "proofLoweringStatus": proof_lowering_status,
        "relationStatementDigest": test_digest("relation-statement"),
        "rowBatchMatrixDigests": [test_digest(&format!("{component_id}-row-matrix"))],
        "rowBatchNames": [format!("{component_id}-rows")],
        "rowBatchTargetVectorDigests": [test_digest(&format!("{component_id}-row-target"))],
        "rowCount": 1,
        "rowKinds": ["EncodedScoreFieldRows"],
        "targetVectorDigest": test_digest(&format!("{component_id}-target")),
        "variableColumnCount": 1,
        "variableColumnIndices": [0],
    });
    let component_statement_digest =
        super::derive_ballot_component_statement_digest(&component_payload)
            .expect("component statement digest should derive");
    let mut component_statement = component_payload;
    component_statement
        .as_object_mut()
        .expect("component statement should be an object")
        .insert(
            "componentStatementDigest".to_string(),
            json!(component_statement_digest),
        );

    component_statement
}

pub(super) fn component_bundle_for_test(
    component_statements: Vec<Value>,
    bundle_coverage: &str,
) -> Value {
    let component_bundle_payload = json!({
        "objectType": "BallotProofComponentBundleStatement",
        "objectVersion": 1,
        "backendStatementDigest": test_digest("backend-statement"),
        "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
        "bundleCoverage": bundle_coverage,
        "componentStatements": component_statements,
        "relationLabel": "BallotPrivacyPvssRelation",
        "relationStatementDigest": test_digest("relation-statement"),
        "requiredComponentIds": super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
    });
    let component_bundle_statement_digest =
        super::derive_ballot_component_bundle_statement_digest(&component_bundle_payload)
            .expect("component bundle statement digest should derive");
    let mut component_bundle = component_bundle_payload;
    component_bundle
        .as_object_mut()
        .expect("component bundle should be an object")
        .insert(
            "componentBundleStatementDigest".to_string(),
            json!(component_bundle_statement_digest),
        );

    component_bundle
}

pub(super) fn proof_bytes_digest_for_test(proof_bytes_hex: &str) -> String {
    super::derive_digest(
        "ProofBytesDigest",
        &json!({
            "objectType": "ProofBytes",
            "objectVersion": 1,
            "proofBytesHex": proof_bytes_hex,
            "proofSizeBytes": proof_bytes_hex.len() / 2,
        }),
    )
    .expect("proof bytes digest should derive")
}

pub(super) fn component_proof_input_for_test(
    component_id: &str,
    component_statement_digest: &Value,
) -> Value {
    let component_index = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
        .iter()
        .position(|expected_component_id| *expected_component_id == component_id)
        .expect("component id should be required");
    let public_randomness_byte = format!("{:02x}", component_index + 1);

    let proof_statement_format = if component_id == "receiver-encryption-component" {
        "structured-module-lwe-linear-proof-v1"
    } else if component_id == "receiver-key-binding-component" {
        "public-zero-witness-binding-check-v1"
    } else if component_id == "score-and-shamir-field-component" {
        "dense-polynomial-matrix-linear-proof-v1"
    } else {
        "sparse-polynomial-matrix-linear-proof-v1"
    };
    let proof_statement = component_proof_statement_for_test(
        component_id,
        component_statement_digest,
        if proof_statement_format == "structured-module-lwe-linear-proof-v1"
            || proof_statement_format == "public-zero-witness-binding-check-v1"
        {
            None
        } else {
            Some(test_digest(&format!("{component_id}-proof-statement")))
        },
        proof_statement_format,
    );
    let component_proof_statement_digest =
        super::string_field(&proof_statement, "componentProofStatementDigest")
            .or_else(|| super::string_field(&proof_statement, "statementDigest"))
            .map(ToString::to_string)
            .unwrap_or_else(|| test_digest(&format!("{component_id}-proof-statement")));

    json!({
        "componentId": component_id,
        "componentProofStatementDigest": component_proof_statement_digest,
        "proofBytesHex": if proof_statement_format == "public-zero-witness-binding-check-v1" {
            "".to_string()
        } else {
            test_digest(&format!("{component_id}-proof-bytes-material"))
        },
        "proofEncoding": {
            "profileId": "ballot-proof-component-encoding-v1",
            "componentId": component_id,
        },
        "proofParameterSet": {
            "profileId": "ballot-proof-component-parameter-set-v1",
            "componentId": component_id,
        },
        "proofStatement": proof_statement,
        "proofStatementFormat": proof_statement_format,
        "publicRandomnessHex": public_randomness_byte.repeat(32),
        "statementDigest": component_statement_digest,
    })
}
