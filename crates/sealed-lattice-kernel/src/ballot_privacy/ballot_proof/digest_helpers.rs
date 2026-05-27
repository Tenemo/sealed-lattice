use super::*;

pub(crate) fn insert_optional_digest_field(
    payload: &mut Map<String, Value>,
    source: &Value,
    field_name: &str,
) {
    if let Some(digest_value) = string_field(source, field_name) {
        payload.insert(field_name.to_string(), json!(digest_value));
    }
}

pub(crate) fn derive_ballot_proof_challenge_digest(
    statement: &Value,
    ballot_proof: &Value,
) -> Option<String> {
    let mut challenge_payload = Map::new();
    challenge_payload.insert(
        "ballotProofStatementDigest".to_string(),
        json!(string_field(statement, "ballotProofStatementDigest")?),
    );
    challenge_payload.insert(
        "challengeDomainDigest".to_string(),
        json!(string_field(statement, "challengeDomainDigest")?),
    );
    challenge_payload.insert(
        "proofBytesDigest".to_string(),
        json!(string_field(ballot_proof, "proofBytesDigest")?),
    );
    challenge_payload.insert(
        "proofRoot".to_string(),
        json!(string_field(ballot_proof, "proofRoot")?),
    );
    challenge_payload.insert(
        "relationStatementDigest".to_string(),
        json!(string_field(ballot_proof, "relationStatementDigest")?),
    );
    for field_name in [
        "backendStatementDigest",
        "componentBundleStatementDigest",
        "componentProofBundleDigest",
        "linearStatementDigest",
        "proofEncodingProfileDigest",
        "proofParameterSetDigest",
        "publicRandomnessDigest",
        "statementMatrixDigest",
        "targetVectorDigest",
    ] {
        insert_optional_digest_field(&mut challenge_payload, ballot_proof, field_name);
    }

    derive_digest("ChallengeDomainDigest", &Value::Object(challenge_payload))
}

pub(crate) fn derive_ballot_component_statement_digest(
    component_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(component_statement, "componentStatementDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_bundle_statement_digest(
    component_bundle: &Value,
) -> Option<String> {
    let statement_payload =
        value_without_field(component_bundle, "componentBundleStatementDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-bundle-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_proof_record_digest(
    component_proof: &Value,
) -> Option<String> {
    let proof_payload = value_without_field(component_proof, "componentProofRecordDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": proof_payload,
            "purpose": "ballot-proof-component-proof-record-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_proof_bundle_digest(
    component_proof_bundle: &Value,
) -> Option<String> {
    let proof_bundle_payload =
        value_without_field(component_proof_bundle, "componentProofBundleDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": proof_bundle_payload,
            "purpose": "ballot-proof-component-proof-bundle-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_proof_root(
    component_proof: &Value,
    proof_input: &Value,
    expected_component_id: &str,
) -> Option<String> {
    let mut proof_root_payload = Map::new();
    proof_root_payload.insert("componentId".to_string(), json!(expected_component_id));
    if let Some(component_proof_statement_digest) =
        string_field(proof_input, "componentProofStatementDigest")
    {
        proof_root_payload.insert(
            "componentProofStatementDigest".to_string(),
            json!(component_proof_statement_digest),
        );
    }
    proof_root_payload.insert(
        "componentStatementDigest".to_string(),
        json!(string_field(component_proof, "componentStatementDigest")?),
    );
    proof_root_payload.insert(
        "proofBytesDigest".to_string(),
        json!(string_field(component_proof, "proofBytesDigest")?),
    );
    proof_root_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(string_field(component_proof, "proofEncodingProfileDigest")?),
    );
    proof_root_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(string_field(component_proof, "proofParameterSetDigest")?),
    );
    proof_root_payload.insert(
        "proofStatementFormat".to_string(),
        json!(string_field(proof_input, "proofStatementFormat")?),
    );
    proof_root_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(string_field(component_proof, "publicRandomnessDigest")?),
    );
    proof_root_payload.insert(
        "purpose".to_string(),
        json!("ballot-proof-component-proof-root-v1"),
    );
    proof_root_payload.insert(
        "statementDigest".to_string(),
        json!(string_field(proof_input, "statementDigest")?),
    );

    derive_digest("ChallengeDomainDigest", &Value::Object(proof_root_payload))
}
