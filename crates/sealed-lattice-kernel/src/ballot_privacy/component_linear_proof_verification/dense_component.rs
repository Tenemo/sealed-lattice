use super::*;

pub(super) fn verify_dense_component_proof(
    operation: &str,
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Value {
    let vector_case =
        match component_linear_proof_vector_case(component_id, component_proof, proof_input) {
            Ok(vector_case) => vector_case,
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
    let proof_verification =
        linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
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
                        "message": format!("Ballot proof component {component_id} proof bytes failed without a structured refusal.")
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
