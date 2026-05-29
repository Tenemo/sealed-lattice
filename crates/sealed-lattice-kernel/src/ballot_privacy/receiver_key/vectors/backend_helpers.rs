use super::*;
use serde_json::json;
#[cfg(test)]
pub(super) fn derive_bytes(
    domain: &str,
    payload: &Value,
    byte_length: usize,
) -> Result<Vec<u8>, String> {
    let mut output = vec![0; byte_length];
    let mut output_offset = 0usize;
    let mut block_counter = 0u64;
    while output_offset < byte_length {
        let block_payload = json!({
            "blockCounter": block_counter,
            "payload": payload,
        });
        let canonical = canonical_json(&block_payload)
            .map_err(|error| format!("receiver-key expansion payload is not canonical: {error}"))?;
        let block = hash512(domain, &[canonical.as_bytes()]);
        let bytes_to_copy = block.len().min(byte_length - output_offset);
        output[output_offset..output_offset + bytes_to_copy]
            .copy_from_slice(&block[..bytes_to_copy]);
        output_offset += bytes_to_copy;
        block_counter = block_counter
            .checked_add(1)
            .ok_or_else(|| "receiver-key byte derivation counter overflowed".to_string())?;
    }

    Ok(output)
}

pub(super) fn validate_expected_public_matrix_seed(
    backend_statement: &Map<String, Value>,
) -> Result<(), String> {
    let expected_public_matrix_seed_hash = derive_protocol_hash(
        "ReceiverEncryptionProfileHash",
        &json!({
            "ceremonyId": string_property(backend_statement, "ceremonyId")?,
            "manifestHash": string_property(backend_statement, "manifestHash")?,
            "purpose": "receiver-public-matrix-seed",
            "receiverEncryptionProfileHash": string_property(backend_statement, "receiverEncryptionProfileHash")?,
            "receiverIdentity": string_property(backend_statement, "receiverIdentity")?,
            "receiverRosterPosition": u64_property(backend_statement, "receiverRosterPosition")?,
            "recoveryEpoch": u64_property(backend_statement, "recoveryEpoch")?,
            "rosterHash": string_property(backend_statement, "rosterHash")?,
        }),
    )
    .map_err(|error| format!("receiver-key matrix seed could not be recomputed: {error}"))?;
    if string_property(backend_statement, "publicMatrixSeedHash")?
        != expected_public_matrix_seed_hash
    {
        return Err(
            "receiver-key backend statement public matrix seed is not canonical".to_string(),
        );
    }

    Ok(())
}

pub(super) fn validate_receiver_key_context_hash(
    backend_statement: &Map<String, Value>,
) -> Result<(), String> {
    let expected_context_hash = derive_receiver_key_backend_hash(
        RECEIVER_KEY_PUBLIC_CONTEXT_HASH_PURPOSE,
        &json!({
            "ceremonyId": string_property(backend_statement, "ceremonyId")?,
            "manifestHash": string_property(backend_statement, "manifestHash")?,
            "receiverEncryptionProfileHash": string_property(backend_statement, "receiverEncryptionProfileHash")?,
            "receiverIdentity": string_property(backend_statement, "receiverIdentity")?,
            "receiverPublicKeyHash": string_property(backend_statement, "receiverPublicKeyHash")?,
            "receiverRosterPosition": u64_property(backend_statement, "receiverRosterPosition")?,
            "recoveryEpoch": u64_property(backend_statement, "recoveryEpoch")?,
            "rosterHash": string_property(backend_statement, "rosterHash")?,
        }),
    )?;
    if string_property(backend_statement, "receiverKeyContextHash")? != expected_context_hash {
        return Err("receiver-key backend context hash does not match public inputs".to_string());
    }

    Ok(())
}

pub(super) fn validate_variable_columns(
    backend_statement: &Map<String, Value>,
) -> Result<(), String> {
    let variable_columns = array_property(backend_statement, "variableColumns")?;
    if variable_columns.len() as u64 != RECEIVER_KEY_WITNESS_COLUMN_COUNT {
        return Err("receiver-key backend variable column count is invalid".to_string());
    }
    for (column_index, variable_column) in variable_columns.iter().enumerate() {
        let column_object = object_field(variable_column, "variableColumn")?;
        if u64_property(column_object, "columnIndex")? != column_index as u64 {
            return Err("receiver-key backend variable columns are not canonical".to_string());
        }
        let expected_role = if (column_index as u64) < RECEIVER_KEY_EQUATION_ROW_COUNT {
            "ReceiverSecretCoefficient"
        } else {
            "ReceiverErrorCoefficient"
        };
        let role_offset = if expected_role == "ReceiverSecretCoefficient" {
            column_index as u64
        } else {
            column_index as u64 - RECEIVER_KEY_EQUATION_ROW_COUNT
        };
        let polynomial_index = role_offset / RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let coefficient_index = role_offset % RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let expected_variable_name = if expected_role == "ReceiverSecretCoefficient" {
            format!("receiver_secret_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        } else {
            format!("receiver_error_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        };

        if string_property(column_object, "variableRole")? != expected_role
            || u64_property(column_object, "polynomialIndex")? != polynomial_index
            || u64_property(column_object, "coefficientIndex")? != coefficient_index
            || string_property(column_object, "variableName")? != expected_variable_name
        {
            return Err("receiver-key backend variable column metadata is invalid".to_string());
        }
    }

    Ok(())
}

pub(super) fn validate_row_batch(backend_statement: &Map<String, Value>) -> Result<(), String> {
    let row_batches = array_property(backend_statement, "rowBatches")?;
    if row_batches.len() != 1 {
        return Err("receiver-key backend statement must contain one row batch".to_string());
    }
    let row_batch = object_field(&row_batches[0], "rowBatch")?;
    if string_property(row_batch, "batchKind")? != "HashExpandedRows"
        || string_property(row_batch, "batchName")? != "receiver_key_equation_rows"
        || string_property(row_batch, "coefficientExpansionDomain")?
            != RECEIVER_KEY_EQUATION_COEFFICIENT_EXPANSION_DOMAIN
        || string_property(row_batch, "modulus")? != RECEIVER_ENCRYPTION_MODULUS.to_string()
        || string_property(row_batch, "rowKind")? != "ReceiverKeyEquation"
        || u64_property(row_batch, "rowOffset")? != 0
        || u64_property(row_batch, "rowCount")? != RECEIVER_KEY_EQUATION_ROW_COUNT
        || string_property(row_batch, "sourceAlgebraicRowName")? != "receiver_key_well_formedness"
        || string_property(row_batch, "targetExpansionDomain")?
            != RECEIVER_KEY_EQUATION_TARGET_EXPANSION_DOMAIN
    {
        return Err("receiver-key backend row batch has an invalid canonical shape".to_string());
    }
    validate_decimal_string(&string_property(row_batch, "modulus")?)?;
    if string_property(row_batch, "receiverIdentity")?
        != string_property(backend_statement, "receiverIdentity")?
        || u64_property(row_batch, "receiverRosterPosition")?
            != u64_property(backend_statement, "receiverRosterPosition")?
        || string_property(row_batch, "targetHash")?
            != string_property(backend_statement, "keyMaterialHash")?
    {
        return Err("receiver-key backend row batch is not context-bound".to_string());
    }
    let public_input_hashes = object_property(row_batch, "publicInputHashes")?;
    for (field_name, statement_field_name) in [
        ("keyMaterialHash", "keyMaterialHash"),
        ("publicMatrixSeedHash", "publicMatrixSeedHash"),
        (
            "receiverEncryptionProfileHash",
            "receiverEncryptionProfileHash",
        ),
        ("receiverKeyContextHash", "receiverKeyContextHash"),
        ("receiverPublicKeyHash", "receiverPublicKeyHash"),
    ] {
        if string_property(public_input_hashes, field_name)?
            != string_property(backend_statement, statement_field_name)?
        {
            return Err(
                "receiver-key backend row batch public hash binding is invalid".to_string(),
            );
        }
    }
    validate_column_indices(
        array_property(row_batch, "variableColumnIndices")?,
        0,
        RECEIVER_KEY_WITNESS_COLUMN_COUNT,
    )?;

    let row_batch_payload = json!({
        "coefficientExpansionDomain": string_property(row_batch, "coefficientExpansionDomain")?,
        "modulus": string_property(row_batch, "modulus")?,
        "publicInputHashes": public_input_hashes,
        "receiverIdentity": string_property(row_batch, "receiverIdentity")?,
        "receiverRosterPosition": u64_property(row_batch, "receiverRosterPosition")?,
        "rowCount": u64_property(row_batch, "rowCount")?,
        "rowKind": string_property(row_batch, "rowKind")?,
        "sourceAlgebraicRowName": string_property(row_batch, "sourceAlgebraicRowName")?,
        "targetHash": string_property(row_batch, "targetHash")?,
        "targetExpansionDomain": string_property(row_batch, "targetExpansionDomain")?,
        "variableColumnIndices": array_property(row_batch, "variableColumnIndices")?,
    });
    let matrix_hash = derive_receiver_key_backend_hash(
        RECEIVER_KEY_HASH_EXPANDED_MATRIX_HASH_PURPOSE,
        &row_batch_payload,
    )?;
    let target_vector_hash = derive_receiver_key_backend_hash(
        RECEIVER_KEY_HASH_EXPANDED_TARGET_VECTOR_HASH_PURPOSE,
        &row_batch_payload,
    )?;
    if string_property(row_batch, "matrixHash")? != matrix_hash {
        return Err("receiver-key backend row-batch matrix hash is invalid".to_string());
    }
    if string_property(row_batch, "targetVectorHash")? != target_vector_hash {
        return Err("receiver-key backend row-batch target hash is invalid".to_string());
    }

    Ok(())
}

pub(super) fn validate_bounds(backend_statement: &Map<String, Value>) -> Result<(), String> {
    let bounds = array_property(backend_statement, "bounds")?;
    if bounds.len() != 2 {
        return Err(
            "receiver-key backend statement must contain two short-vector bounds".to_string(),
        );
    }
    validate_bound(&bounds[0], "receiver_secret_coefficients_eta_2", 0)?;
    validate_bound(
        &bounds[1],
        "receiver_error_coefficients_eta_2",
        RECEIVER_KEY_EQUATION_ROW_COUNT,
    )?;

    Ok(())
}

pub(super) fn validate_bound(
    bound: &Value,
    expected_bound_name: &str,
    expected_column_offset: u64,
) -> Result<(), String> {
    let bound_object = object_field(bound, "bound")?;
    if string_property(bound_object, "absoluteMaximum")?
        != RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND.to_string()
        || string_property(bound_object, "boundKind")? != "SignedIntegerAbsoluteBound"
        || string_property(bound_object, "boundName")? != expected_bound_name
    {
        return Err("receiver-key backend bound has an invalid canonical shape".to_string());
    }
    validate_decimal_string(&string_property(bound_object, "absoluteMaximum")?)?;
    validate_column_indices(
        array_property(bound_object, "variableColumnIndices")?,
        expected_column_offset,
        RECEIVER_KEY_EQUATION_ROW_COUNT,
    )?;
    let variable_names = array_property(bound_object, "variableNames")?;
    if variable_names.len() as u64 != RECEIVER_KEY_EQUATION_ROW_COUNT {
        return Err("receiver-key backend bound variable names are invalid".to_string());
    }
    for (index, variable_name) in variable_names.iter().enumerate() {
        let linear_index = index as u64;
        let polynomial_index = linear_index / RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let coefficient_index = linear_index % RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let expected_variable_name = if expected_column_offset == 0 {
            format!("receiver_secret_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        } else {
            format!("receiver_error_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        };
        if variable_name.as_str() != Some(expected_variable_name.as_str()) {
            return Err("receiver-key backend bound variable names are not canonical".to_string());
        }
    }

    Ok(())
}

pub(super) fn validate_hash_change_trace(
    case_object: &Map<String, Value>,
    accepted_hashes: &ReceiverKeyAcceptedHashes,
) -> Result<(), String> {
    let trace = object_property(case_object, "trace")?;
    if let Ok(expected_hash_changed) = bool_property(trace, "expectedHashChanged")
        && expected_hash_changed
    {
        if let Ok(baseline_backend_hash) = string_property(trace, "baselineBackendStatementHash")
            && baseline_backend_hash == accepted_hashes.backend_statement_hash
        {
            return Err("receiver-key hash-change vector did not change backend hash".to_string());
        }
        if let Ok(baseline_linear_hash) = string_property(trace, "baselineLinearStatementHash")
            && baseline_linear_hash == accepted_hashes.linear_statement_hash
        {
            return Err("receiver-key hash-change vector did not change linear hash".to_string());
        }
    }
    if let Ok(trace_hash) = string_property(trace, "backendStatementHash")
        && trace_hash != accepted_hashes.backend_statement_hash
    {
        return Err("receiver-key trace hash does not match backend statement".to_string());
    }
    if let Ok(trace_hash) = string_property(trace, "linearStatementHash")
        && trace_hash != accepted_hashes.linear_statement_hash
    {
        return Err("receiver-key trace hash does not match linear statement".to_string());
    }

    Ok(())
}

pub(super) fn validate_column_indices(
    values: &[Value],
    expected_offset: u64,
    expected_count: u64,
) -> Result<(), String> {
    if values.len() as u64 != expected_count {
        return Err("receiver-key backend column index count is invalid".to_string());
    }
    for (index, value) in values.iter().enumerate() {
        if value.as_u64() != Some(expected_offset + index as u64) {
            return Err("receiver-key backend column indices are not canonical".to_string());
        }
    }

    Ok(())
}

pub(super) fn derive_receiver_key_backend_hash(
    purpose: &str,
    payload: &Value,
) -> Result<String, String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": payload,
            "purpose": purpose
        }),
    )
    .map_err(|error| format!("receiver-key backend hash could not be recomputed: {error}"))
}

pub(super) fn reject_forbidden_witness_keys(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "ciphertextChunks"
                        | "errorVector"
                        | "openingRandomness"
                        | "privateWitness"
                        | "proofRandomness"
                        | "publicKeyVector"
                        | "receiverShareVector"
                        | "secretState"
                        | "secretVector"
                        | "witness"
                ) {
                    return Err(format!(
                        "receiver-key vector exposes forbidden witness key {key}"
                    ));
                }
                reject_forbidden_witness_keys(child)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_forbidden_witness_keys(item)?;
            }
        }
        _ => {}
    }

    Ok(())
}

pub(super) fn is_protocol_hash(value: &str) -> bool {
    value.len() == 128
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_decimal_string(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("receiver-key decimal string is not canonical".to_string());
    }

    Ok(())
}

pub(super) fn object_field<'value>(
    value: &'value Value,
    field_name: &str,
) -> Result<&'value Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{field_name} must be an object"))
}

pub(super) fn object_property<'value>(
    object: &'value Map<String, Value>,
    field_name: &str,
) -> Result<&'value Map<String, Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{field_name} must be an object"))
}

pub(super) fn string_property(
    object: &Map<String, Value>,
    field_name: &str,
) -> Result<String, String> {
    object
        .get(field_name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{field_name} must be a string"))
}

pub(super) fn u64_property(object: &Map<String, Value>, field_name: &str) -> Result<u64, String> {
    object
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field_name} must be an unsigned integer"))
}

pub(super) fn array_property<'value>(
    object: &'value Map<String, Value>,
    field_name: &str,
) -> Result<&'value Vec<Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field_name} must be an array"))
}

pub(super) fn bool_property(object: &Map<String, Value>, field_name: &str) -> Result<bool, String> {
    object
        .get(field_name)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{field_name} must be a boolean"))
}

pub(super) fn value_without_field(value: &Value, field_name: &str) -> Result<Value, String> {
    let object = object_field(value, "object")?;
    let mut copied_object = object.clone();
    copied_object.remove(field_name);

    Ok(Value::Object(copied_object))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::verify_receiver_key_vector_case_value;

    fn generated_case(case_name: &str) -> Value {
        let vectors: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/receiver-key-proof-vectors.json"
        )))
        .expect("receiver-key vector file should parse");

        vectors["cases"]
            .as_array()
            .expect("receiver-key vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == case_name)
            .unwrap_or_else(|| panic!("receiver-key vector case {case_name} should exist"))
            .clone()
    }

    #[test]
    fn verifies_valid_receiver_key_vector() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "valid-receiver-key-proof-backend-statement",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["expectedOutcome"], "accept");
        assert!({
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("ReceiverKeyProofRootRecomputed"))
        });
        assert!({
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("ReceiverKeyLinearStatementChecked"))
        });
    }

    #[test]
    fn verifies_recorded_receiver_key_construction_refusal() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "wrong-public-matrix-seed-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
        assert!({
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("ReceiverKeyConstructionRefusalRecorded"))
        });
    }

    #[test]
    fn verifies_backend_preflight_reject_vector() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "noncanonical-backend-modulus-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
    }

    #[test]
    fn verifies_linear_statement_preflight_reject_vector() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "mutated-linear-statement-target-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
    }

    #[test]
    fn verifies_proof_shell_reject_vector() {
        let verification =
            verify_receiver_key_vector_case_value(&generated_case("mutated-proof-root-rejects"));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
    }
}
