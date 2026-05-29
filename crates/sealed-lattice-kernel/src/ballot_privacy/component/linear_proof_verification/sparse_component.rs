use super::*;

pub(super) fn verify_sparse_compatible_component_proof(
    operation: &str,
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Value {
    let component_proof_record_hash = string_field(component_proof, "componentProofRecordHash");
    let proof_statement_format =
        string_field(proof_input, "proofStatementFormat").expect("statement format checked");
    let proof_statement = match object_map(proof_input)
        .and_then(|object| object.get("proofStatement"))
    {
        Some(proof_statement) => proof_statement,
        None => {
            return component_backend_invalid_rejection(
                operation,
                component_id,
                format!(
                    "Ballot proof component proof input for {component_id} must supply its sparse-compatible public proof statement object."
                ),
                component_proof_record_hash,
            );
        }
    };
    let parsed_sparse_statement =
        match if proof_statement_format == STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT {
            parse_structured_share_commitment_statement(proof_statement)
        } else {
            sparse_matrix_from_sparse_component_statement(proof_statement)
        } {
            Ok(parsed_sparse_statement) => parsed_sparse_statement,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": error.code,
                        "message": error.message,
                        "objectHash": string_field(component_proof, "componentProofRecordHash")
                    })],
                    json!(error.code),
                );
            }
        };
    let proof_bytes_hex = match string_field(proof_input, "proofBytesHex") {
        Some(proof_bytes_hex) => proof_bytes_hex,
        None => {
            return component_backend_invalid_rejection(
                operation,
                component_id,
                format!("Ballot proof component {component_id} has no proof bytes."),
                component_proof_record_hash,
            );
        }
    };
    let public_randomness_hex = match string_field(proof_input, "publicRandomnessHex") {
        Some(public_randomness_hex) => public_randomness_hex,
        None => {
            return component_backend_invalid_rejection(
                operation,
                component_id,
                format!("Ballot proof component {component_id} has no public randomness."),
                component_proof_record_hash,
            );
        }
    };
    let parameter_set_value =
        match object_map(proof_input).and_then(|object| object.get("proofParameterSet")) {
            Some(parameter_set_value) => parameter_set_value,
            None => {
                return component_backend_invalid_rejection(
                    operation,
                    component_id,
                    format!("Ballot proof component {component_id} has no parameter set."),
                    component_proof_record_hash,
                );
            }
        };
    let proof_encoding_value =
        match object_map(proof_input).and_then(|object| object.get("proofEncoding")) {
            Some(proof_encoding_value) => proof_encoding_value,
            None => {
                return component_backend_invalid_rejection(
                    operation,
                    component_id,
                    format!("Ballot proof component {component_id} has no proof encoding."),
                    component_proof_record_hash,
                );
            }
        };
    let parameter_set: LinearProofParameterSet =
        match serde_json::from_value(parameter_set_value.clone()) {
            Ok(parameter_set) => parameter_set,
            Err(error) => {
                return component_backend_invalid_rejection(
                    operation,
                    component_id,
                    format!(
                        "Ballot proof component {component_id} parameter set is invalid: {error}."
                    ),
                    component_proof_record_hash,
                );
            }
        };
    let proof_encoding: LinearProofEncoding =
        match serde_json::from_value(proof_encoding_value.clone()) {
            Ok(proof_encoding) => proof_encoding,
            Err(error) => {
                return component_backend_invalid_rejection(
                    operation,
                    component_id,
                    format!(
                        "Ballot proof component {component_id} proof encoding is invalid: {error}."
                    ),
                    component_proof_record_hash,
                );
            }
        };
    let target_coefficient_representation_value = match object_map(proof_statement)
        .and_then(|object| object.get("targetCoefficientRepresentation"))
    {
        Some(target_coefficient_representation_value) => {
            target_coefficient_representation_value.clone()
        }
        None => {
            return component_backend_invalid_rejection(
                operation,
                component_id,
                format!(
                    "Sparse-compatible component proof statement for {component_id} is missing targetCoefficientRepresentation."
                ),
                component_proof_record_hash,
            );
        }
    };
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        match serde_json::from_value(target_coefficient_representation_value) {
            Ok(target_coefficient_representation) => target_coefficient_representation,
            Err(error) => {
                return component_backend_invalid_rejection(
                    operation,
                    component_id,
                    format!(
                        "Sparse-compatible component proof statement for {component_id} has invalid targetCoefficientRepresentation: {error}."
                    ),
                    component_proof_record_hash,
                );
            }
        };
    let matrix_coefficient_representation = match matrix_coefficient_representation_from_statement(
        proof_statement,
        "proofStatement",
    ) {
        Ok(matrix_coefficient_representation) => matrix_coefficient_representation,
        Err(error) => {
            return component_backend_invalid_rejection(
                operation,
                component_id,
                format!(
                    "Sparse-compatible component proof statement for {component_id} has invalid matrixCoefficientRepresentation: {}.",
                    error.message
                ),
                component_proof_record_hash,
            );
        }
    };
    let expected_proof_size_bytes = object_map(component_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size| usize::try_from(proof_size).ok());
    let proof_verification = linear_proof_verifier::verify_sparse_linear_proof_components(
        linear_proof_verifier::SparseLinearProofVerificationInput {
            case_name: &format!("{component_id}-component-proof"),
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            public_randomness_hex,
            source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
            target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
            matrix_coefficient_representation,
            target_coefficient_representation,
            proof_hex: proof_bytes_hex,
            expected_proof_size_bytes,
        },
    );
    if proof_verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return component_proof_backend_rejection(
            operation,
            component_id,
            proof_verification
                .as_object()
                .and_then(|object| object.get("refusedObjects"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| {
                    vec![json!({
                        "code": "InvalidFixture",
                        "message": format!("Ballot proof component {component_id} sparse proof bytes failed without a structured refusal.")
                    })]
                }),
            proof_verification
                .as_object()
                .and_then(|object| object.get("unresolvedReason"))
                .cloned()
                .unwrap_or_else(|| json!("InvalidFixture")),
        );
    }

    let mut status_labels = vec![
        json!("BallotProofComponentProofBytesVerified"),
        json!("BallotProofComponentLinearProofVerified"),
        json!("BallotProofComponentSparseStatementVerifiedWithoutDenseExpansion"),
    ];
    if proof_statement_format == STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT {
        status_labels.push(json!(
            "BallotProofComponentStructuredShareCommitmentStatementVerified"
        ));
    }
    if let Some(proof_status_labels) = proof_verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(proof_status_labels.iter().cloned());
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "componentId": component_id,
        "statusLabels": status_labels,
        "acceptedHashes": [
            string_field(component_proof, "componentProofRecordHash"),
            string_field(component_proof, "proofBytesHash"),
            string_field(proof_input, "componentProofStatementHash"),
            string_field(proof_input, "statementHash")
        ],
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}
