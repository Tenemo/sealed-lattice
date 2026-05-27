use super::*;

pub(crate) fn component_linear_proof_vector_case(
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Result<Value, ComponentProofBackendError> {
    let proof_statement = object_map(proof_input)
        .and_then(|object| object.get("proofStatement"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component proof input for {component_id} has no proof statement."
            ))
        })?;
    let proof_statement_format =
        string_field(proof_input, "proofStatementFormat").ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component proof input for {component_id} has no statement format."
            ))
        })?;
    let (statement_matrix_coefficients, target_vector_coefficients) = match proof_statement_format {
        "dense-polynomial-matrix-linear-proof-v1" => (
            object_map(proof_statement)
                .and_then(|object| object.get("statementMatrixCoefficients"))
                .cloned()
                .ok_or_else(|| {
                    ComponentProofBackendError::invalid(format!(
                        "Dense component proof statement for {component_id} has no statement matrix."
                    ))
                })?,
            object_map(proof_statement)
                .and_then(|object| object.get("targetVectorCoefficients"))
                .cloned()
                .ok_or_else(|| {
                    ComponentProofBackendError::invalid(format!(
                        "Dense component proof statement for {component_id} has no target vector."
                    ))
                })?,
        ),
        "sparse-polynomial-matrix-linear-proof-v1" => {
            return Err(ComponentProofBackendError::unavailable(format!(
                "Sparse component proof statement for {component_id} must be verified through the sparse proof-byte backend."
            )));
        }
        "structured-module-sis-share-commitment-v1" => {
            return Err(ComponentProofBackendError::unavailable(format!(
                "Structured share-commitment proof statement for {component_id} must be verified through the sparse proof-byte backend."
            )));
        }
        "structured-module-lwe-linear-proof-v1" => {
            return Err(ComponentProofBackendError::unavailable(format!(
                "Structured receiver-encryption proof bytes for {component_id} are not implemented in this backend slice."
            )));
        }
        "public-zero-witness-binding-check-v1" => {
            return Err(ComponentProofBackendError::unavailable(format!(
                "Public-zero witness binding checks for {component_id} are structural only and are not linear proof bytes."
            )));
        }
        _ => {
            return Err(ComponentProofBackendError::invalid(format!(
                "Ballot proof component proof statement format for {component_id} is not supported."
            )));
        }
    };

    let proof_bytes_hex = string_field(proof_input, "proofBytesHex").ok_or_else(|| {
        ComponentProofBackendError::invalid(format!(
            "Ballot proof component {component_id} has no proof bytes."
        ))
    })?;
    let public_randomness_hex =
        string_field(proof_input, "publicRandomnessHex").ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component {component_id} has no public randomness."
            ))
        })?;
    let parameter_set = object_map(proof_input)
        .and_then(|object| object.get("proofParameterSet"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component {component_id} has no parameter set."
            ))
        })?;
    let proof_encoding = object_map(proof_input)
        .and_then(|object| object.get("proofEncoding"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component {component_id} has no proof encoding."
            ))
        })?;

    Ok(json!({
        "caseName": format!("{component_id}-component-proof"),
        "description": format!("Ballot proof component {component_id} verification through the internal linear proof backend."),
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": statement_matrix_coefficients,
        "targetVectorCoefficients": target_vector_coefficients,
        "matrixCoefficientRepresentation": object_map(proof_statement)
            .and_then(|object| object.get("matrixCoefficientRepresentation"))
            .cloned()
            .unwrap_or_else(|| json!("canonicalUnsignedSourceModulus")),
        "targetCoefficientRepresentation": object_map(proof_statement)
            .and_then(|object| object.get("targetCoefficientRepresentation"))
            .cloned()
            .unwrap_or(Value::Null),
        "proofHex": proof_bytes_hex,
        "expectedProofSizeBytes": object_map(component_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .cloned()
            .unwrap_or(Value::Null)
    }))
}
