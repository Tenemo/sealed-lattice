use super::*;

pub(super) fn verify_structured_receiver_encryption_component_proof(
    operation: &str,
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Value {
    let mut refused_objects = Vec::new();
    if component_id != "receiver-encryption-component" {
        refused_objects.push(json!({
            "code": "BallotPackageInvalid",
            "message": format!("Structured receiver-encryption proof statements are only valid for receiver-encryption-component, not {component_id}."),
            "objectDigest": string_field(component_proof, "componentProofRecordDigest")
        }));
    }
    if let Some(proof_statement) =
        object_map(proof_input).and_then(|object| object.get("proofStatement"))
    {
        if string_field(proof_statement, "objectType")
            == Some("BallotProofComponentProofStatementPlan")
        {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Structured receiver-encryption proof bytes for {component_id} require a public structured proof statement, not only the proof statement plan."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        } else if derive_ballot_structured_receiver_encryption_statement_digest(proof_statement)
            .as_deref()
            != string_field(proof_statement, "statementDigest")
        {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Ballot proof component proof statement digest for {component_id} does not match its canonical payload."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        }
        if string_field(proof_statement, "statementDigest")
            != string_field(proof_input, "componentProofStatementDigest")
        {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Ballot proof component proof statement for {component_id} is not bound to the supplied proof input."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        }
    } else {
        refused_objects.push(json!({
            "code": "BallotPackageInvalid",
            "message": format!("Ballot proof component proof input for {component_id} must supply its public proof statement object."),
            "objectDigest": string_field(component_proof, "componentProofRecordDigest")
        }));
    }
    if !refused_objects.is_empty() {
        return component_proof_backend_rejection(
            operation,
            component_id,
            refused_objects,
            json!("BallotPackageInvalid"),
        );
    }

    let proof_statement = object_map(proof_input)
        .and_then(|object| object.get("proofStatement"))
        .expect("structured proof statement presence was checked");
    let parsed_structured_statement =
        match parse_structured_receiver_encryption_statement(proof_statement) {
            Ok(parsed_structured_statement) => parsed_structured_statement,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": error.code,
                        "message": error.message,
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!(error.code),
                );
            }
        };
    let proof_bytes_hex = match string_field(proof_input, "proofBytesHex") {
        Some(proof_bytes_hex) => proof_bytes_hex,
        None => {
            return component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component {component_id} has no proof bytes."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            );
        }
    };
    let public_randomness_hex = match string_field(proof_input, "publicRandomnessHex") {
        Some(public_randomness_hex) => public_randomness_hex,
        None => {
            return component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component {component_id} has no public randomness."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            );
        }
    };
    let parameter_set_value = match object_map(proof_input)
        .and_then(|object| object.get("proofParameterSet"))
    {
        Some(parameter_set_value) => parameter_set_value,
        None => {
            return component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component {component_id} has no parameter set."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            );
        }
    };
    let proof_encoding_value = match object_map(proof_input)
        .and_then(|object| object.get("proofEncoding"))
    {
        Some(proof_encoding_value) => proof_encoding_value,
        None => {
            return component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component {component_id} has no proof encoding."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            );
        }
    };
    let parameter_set: LinearProofParameterSet = match serde_json::from_value(
        parameter_set_value.clone(),
    ) {
        Ok(parameter_set) => parameter_set,
        Err(error) => {
            return component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component {component_id} parameter set is invalid: {error}."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            );
        }
    };
    let proof_encoding: LinearProofEncoding = match serde_json::from_value(
        proof_encoding_value.clone(),
    ) {
        Ok(proof_encoding) => proof_encoding,
        Err(error) => {
            return component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component {component_id} proof encoding is invalid: {error}."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            );
        }
    };
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        match serde_json::from_value(
            object_map(proof_statement)
                .and_then(|object| object.get("targetCoefficientRepresentation"))
                .cloned()
                .unwrap_or(Value::Null),
        ) {
            Ok(target_coefficient_representation) => target_coefficient_representation,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Structured receiver-encryption proof statement for {component_id} has invalid targetCoefficientRepresentation: {error}."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
    let matrix_coefficient_representation = match matrix_coefficient_representation_from_statement(
        proof_statement,
        "proofStatement",
    ) {
        Ok(matrix_coefficient_representation) => matrix_coefficient_representation,
        Err(error) => {
            return component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Structured receiver-encryption proof statement for {component_id} has invalid matrixCoefficientRepresentation: {}.", error.message),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            );
        }
    };
    let expected_proof_size_bytes = object_map(component_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size| usize::try_from(proof_size).ok());
    let proof_verification = linear_proof_verifier::verify_streamed_linear_proof_components(
        linear_proof_verifier::StreamedLinearProofVerificationInput {
            case_name: &format!("{component_id}-component-proof"),
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            public_randomness_hex,
            statement: &parsed_structured_statement,
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
                        "message": format!("Ballot proof component {component_id} structured proof bytes failed without a structured refusal.")
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
        json!("BallotProofComponentStructuredReceiverEncryptionStatementVerified"),
    ];
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
        "acceptedDigests": [
            string_field(component_proof, "componentProofRecordDigest"),
            string_field(component_proof, "proofBytesDigest"),
            string_field(proof_input, "componentProofStatementDigest"),
            string_field(proof_input, "statementDigest")
        ],
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}
