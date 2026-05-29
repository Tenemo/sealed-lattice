use super::*;

pub(super) fn proof_bytes_size_from_lower_hex(
    proof_bytes_hex: &str,
    allow_empty: bool,
) -> Option<u64> {
    if !proof_bytes_hex.len().is_multiple_of(2)
        || !proof_bytes_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let proof_size_bytes = proof_bytes_hex.len() as u64 / 2;
    if !allow_empty && proof_size_bytes == 0 {
        return None;
    }

    Some(proof_size_bytes)
}

pub(crate) fn insert_optional_hash_field(
    payload: &mut Map<String, Value>,
    source: &Value,
    field_name: &str,
) {
    if let Some(hash_value) = string_field(source, field_name) {
        payload.insert(field_name.to_string(), json!(hash_value));
    }
}

pub(crate) fn derive_ballot_proof_challenge_hash(
    statement: &Value,
    ballot_proof: &Value,
) -> Option<String> {
    let mut challenge_payload = Map::new();
    challenge_payload.insert(
        "ballotProofStatementHash".to_string(),
        json!(string_field(statement, "ballotProofStatementHash")?),
    );
    challenge_payload.insert(
        "challengeDomainHash".to_string(),
        json!(string_field(statement, "challengeDomainHash")?),
    );
    challenge_payload.insert(
        "proofBytesHash".to_string(),
        json!(string_field(ballot_proof, "proofBytesHash")?),
    );
    challenge_payload.insert(
        "proofRoot".to_string(),
        json!(string_field(ballot_proof, "proofRoot")?),
    );
    challenge_payload.insert("purpose".to_string(), json!("ballot-proof-challenge-v1"));
    challenge_payload.insert(
        "relationStatementHash".to_string(),
        json!(string_field(ballot_proof, "relationStatementHash")?),
    );
    for field_name in [
        "backendStatementHash",
        "componentBundleStatementHash",
        "componentProofBundleHash",
        "linearStatementHash",
        "proofEncodingProfileHash",
        "proofParameterSetHash",
        "publicRandomnessHash",
        "statementMatrixHash",
        "targetVectorHash",
    ] {
        insert_optional_hash_field(&mut challenge_payload, ballot_proof, field_name);
    }

    derive_hash("ChallengeDomainHash", &Value::Object(challenge_payload))
}

pub(crate) fn derive_ballot_component_statement_hash(
    component_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(component_statement, "componentStatementHash")?;

    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_bundle_statement_hash(
    component_bundle: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(component_bundle, "componentBundleStatementHash")?;

    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-bundle-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_proof_record_hash(component_proof: &Value) -> Option<String> {
    let proof_payload = value_without_field(component_proof, "componentProofRecordHash")?;

    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": proof_payload,
            "purpose": "ballot-proof-component-proof-record-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_proof_bundle_hash(
    component_proof_bundle: &Value,
) -> Option<String> {
    let proof_bundle_payload =
        value_without_field(component_proof_bundle, "componentProofBundleHash")?;

    derive_hash(
        "ChallengeDomainHash",
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
    if let Some(component_proof_statement_hash) =
        string_field(proof_input, "componentProofStatementHash")
    {
        proof_root_payload.insert(
            "componentProofStatementHash".to_string(),
            json!(component_proof_statement_hash),
        );
    }
    proof_root_payload.insert(
        "componentStatementHash".to_string(),
        json!(string_field(component_proof, "componentStatementHash")?),
    );
    proof_root_payload.insert(
        "proofBytesHash".to_string(),
        json!(string_field(component_proof, "proofBytesHash")?),
    );
    proof_root_payload.insert(
        "proofEncodingProfileHash".to_string(),
        json!(string_field(component_proof, "proofEncodingProfileHash")?),
    );
    proof_root_payload.insert(
        "proofParameterSetHash".to_string(),
        json!(string_field(component_proof, "proofParameterSetHash")?),
    );
    proof_root_payload.insert(
        "proofStatementFormat".to_string(),
        json!(string_field(proof_input, "proofStatementFormat")?),
    );
    proof_root_payload.insert(
        "publicRandomnessHash".to_string(),
        json!(string_field(component_proof, "publicRandomnessHash")?),
    );
    proof_root_payload.insert(
        "purpose".to_string(),
        json!("ballot-proof-component-proof-root-v1"),
    );
    proof_root_payload.insert(
        "statementHash".to_string(),
        json!(string_field(proof_input, "statementHash")?),
    );

    derive_hash("ChallengeDomainHash", &Value::Object(proof_root_payload))
}
