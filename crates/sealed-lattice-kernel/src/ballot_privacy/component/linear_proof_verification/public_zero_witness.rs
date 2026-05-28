use super::*;

pub(super) fn verify_public_zero_witness_component_proof(
    operation: &str,
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Value {
    let mut refused_objects = Vec::new();
    let component_proof_record_hash = string_field(component_proof, "componentProofRecordHash");
    if component_id != "receiver-key-binding-component" {
        refused_objects.push(structural_refusal(
            format!(
                "Public-zero witness binding checks are only valid for receiver-key-binding-component, not {component_id}."
            ),
            component_proof_record_hash,
        ));
    }
    if string_field(proof_input, "proofBytesHex") != Some("")
        || object_map(component_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64)
            != Some(0)
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof bytes for {component_id} must be empty for the public-zero witness binding check."
            ),
            component_proof_record_hash,
        ));
    }
    if let Some(proof_statement) =
        object_map(proof_input).and_then(|object| object.get("proofStatement"))
    {
        refused_objects.extend(collect_component_proof_statement_plan_shape_refusals(
            proof_statement,
            component_id,
            component_proof_record_hash,
        ));
        if derive_ballot_component_proof_statement_plan_hash(proof_statement).as_deref()
            != string_field(proof_statement, "componentProofStatementHash")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement hash for {component_id} does not match its canonical payload."
                ),
                component_proof_record_hash,
            ));
        }
    } else {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof input for {component_id} must supply its public proof statement object."
            ),
            component_proof_record_hash,
        ));
    }
    if !refused_objects.is_empty() {
        return component_proof_backend_rejection(
            operation,
            component_id,
            refused_objects,
            json!("BallotPackageInvalid"),
        );
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "componentId": component_id,
        "statusLabels": [
            "BallotProofComponentProofBytesVerified",
            "BallotProofComponentPublicZeroWitnessBindingChecked"
        ],
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
