use super::*;

pub(crate) fn verify_component_proof_bundle_backend(
    operation: &str,
    _accepted_object_digest: Option<&str>,
    component_proof_bundle: &Value,
    component_proof_inputs: Option<&Value>,
) -> Option<Value> {
    let component_proof_inputs = match component_proof_inputs {
        Some(component_proof_inputs) => component_proof_inputs,
        None => {
            return Some(component_proof_backend_rejection(
                operation,
                "component-proof-bundle",
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": "Ballot proof component backend verification requires component proof inputs.",
                })],
                json!("BallotPackageInvalid"),
            ));
        }
    };
    let component_proof_inputs_array = match component_proof_inputs.as_array() {
        Some(component_proof_inputs_array) => component_proof_inputs_array,
        None => {
            return Some(component_proof_backend_rejection(
                operation,
                "component-proof-bundle",
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": "Ballot proof component backend verification inputs must be an array.",
                })],
                json!("BallotPackageInvalid"),
            ));
        }
    };
    let component_proofs = match array_field(component_proof_bundle, "componentProofs") {
        Some(component_proofs) => component_proofs,
        None => {
            return Some(component_proof_backend_rejection(
                operation,
                "component-proof-bundle",
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": "Ballot proof component proof bundle must contain component proofs.",
                })],
                json!("BallotPackageInvalid"),
            ));
        }
    };
    let mut proof_inputs_by_component = BTreeMap::new();
    for proof_input in component_proof_inputs_array {
        let Some(component_id) = string_field(proof_input, "componentId") else {
            return Some(component_proof_backend_rejection(
                operation,
                "component-proof-bundle",
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": "Ballot proof component backend input is missing componentId.",
                })],
                json!("BallotPackageInvalid"),
            ));
        };
        if proof_inputs_by_component
            .insert(component_id.to_string(), proof_input)
            .is_some()
        {
            return Some(component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component backend inputs contain duplicate componentId {component_id}."),
                })],
                json!("BallotPackageInvalid"),
            ));
        }
    }

    for component_proof in component_proofs {
        let Some(component_id) = string_field(component_proof, "componentId") else {
            return Some(component_proof_backend_rejection(
                operation,
                "component-proof-bundle",
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": "Ballot proof component backend proof record is missing componentId.",
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            ));
        };
        let Some(proof_input) = proof_inputs_by_component.get(component_id) else {
            return Some(component_proof_backend_rejection(
                operation,
                component_id,
                vec![json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component backend proof record for {component_id} has no matching proof input."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                })],
                json!("BallotPackageInvalid"),
            ));
        };
        let component_verification = verify_component_linear_proof_bytes(
            operation,
            component_id,
            component_proof,
            proof_input,
        );
        if component_verification
            .as_object()
            .and_then(|object| object.get("ok"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Some(component_verification);
        }
    }

    None
}
