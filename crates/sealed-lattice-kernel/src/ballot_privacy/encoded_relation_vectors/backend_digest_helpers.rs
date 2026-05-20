use super::*;
use serde_json::json;
pub(super) fn validate_explicit_backend_rows(
    rows: &[Value],
    column_count: u64,
    expected_modulus: &str,
    allowed_row_kinds: &[&str],
) -> Result<(), String> {
    for (expected_row_index, row) in rows.iter().enumerate() {
        let row_object = object_field(row, "backend explicit row")?;
        if u64_property(row_object, "rowIndex")? != expected_row_index as u64 {
            return Err(
                "encoded relation backend explicit row indexes are not canonical".to_string(),
            );
        }
        if string_property(row_object, "modulus")? != expected_modulus {
            return Err("encoded relation backend explicit row modulus is invalid".to_string());
        }
        let row_kind = string_property(row_object, "rowKind")?;
        if !allowed_row_kinds
            .iter()
            .any(|allowed_row_kind| row_kind == *allowed_row_kind)
        {
            return Err("encoded relation backend explicit row kind is invalid".to_string());
        }
        validate_signed_decimal_string(&string_property(row_object, "target")?)?;
        let terms = array_property(row_object, "terms")?;
        if terms.is_empty() {
            return Err("encoded relation backend explicit rows must contain terms".to_string());
        }
        for term in terms {
            let term_object = object_field(term, "backend explicit row term")?;
            let column_index = u64_property(term_object, "columnIndex")?;
            if column_index >= column_count {
                return Err(
                    "encoded relation backend explicit term column is out of range".to_string(),
                );
            }
            validate_signed_decimal_string(&string_property(term_object, "coefficient")?)?;
            if string_property(term_object, "variableName")?.is_empty() {
                return Err(
                    "encoded relation backend explicit term variable name is empty".to_string(),
                );
            }
        }
    }

    Ok(())
}

pub(super) fn validate_digest_expanded_backend_row_batch(
    batch_object: &serde_json::Map<String, Value>,
    column_count: u64,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    if string_property(batch_object, "batchKind")? != "DigestExpandedRows"
        || batch_object.contains_key("rows")
    {
        return Err(
            "encoded relation backend digest-expanded row batch is not canonical".to_string(),
        );
    }
    let row_kind = string_property(batch_object, "rowKind")?;
    let expected_row_count = match row_kind.as_str() {
        "ShareCommitmentEquation" => SHARE_COMMITMENT_EQUATION_ROWS,
        "ReceiverPayloadEncryptionEquation" => RECEIVER_ENCRYPTION_EQUATION_ROWS,
        "ReceiverKeyBinding" => RECEIVER_KEY_EQUATION_ROWS,
        _ => {
            return Err("encoded relation backend digest-expanded row kind is invalid".to_string());
        }
    };
    if u64_property(batch_object, "rowCount")? != expected_row_count {
        return Err("encoded relation backend digest-expanded row count is invalid".to_string());
    }
    let receiver_roster_position = u64_property(batch_object, "receiverRosterPosition")?;
    if receiver_roster_position == 0 || receiver_roster_position > dimensions.roster_size {
        return Err(
            "encoded relation backend digest-expanded receiver position is invalid".to_string(),
        );
    }
    if string_property(batch_object, "receiverIdentity")?.is_empty()
        || string_property(batch_object, "sourceAlgebraicRowName")?.is_empty()
        || string_property(batch_object, "coefficientExpansionDomain")?.is_empty()
        || string_property(batch_object, "targetExpansionDomain")?.is_empty()
    {
        return Err("encoded relation backend digest-expanded labels are invalid".to_string());
    }
    validate_digest_string(&string_property(batch_object, "targetDigest")?)?;
    validate_digest_map(object_property(batch_object, "publicInputDigests")?)?;
    validate_column_index_array(
        array_property(batch_object, "variableColumnIndices")?,
        column_count,
    )?;
    validate_batch_digest_pair(
        batch_object,
        DIGEST_EXPANDED_BACKEND_MATRIX_DIGEST_PURPOSE,
        DIGEST_EXPANDED_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE,
        digest_expanded_backend_payload(batch_object)?,
        digest_expanded_backend_payload(batch_object)?,
    )
}

pub(super) fn validate_backend_bounds(
    backend_bounds: &[Value],
    column_count: u64,
    expected_bound_count: u64,
) -> Result<(), String> {
    if backend_bounds.len() as u64 != expected_bound_count {
        return Err("encoded relation backend bound count is invalid".to_string());
    }
    for bound in backend_bounds {
        let bound_object = object_field(bound, "backend bound")?;
        if string_property(bound_object, "boundName")?.is_empty() {
            return Err("encoded relation backend bound name is empty".to_string());
        }
        let bound_kind = string_property(bound_object, "boundKind")?;
        if !matches!(
            bound_kind.as_str(),
            "Boolean" | "CanonicalFieldElement" | "SignedIntegerAbsoluteBound"
        ) {
            return Err("encoded relation backend bound kind is invalid".to_string());
        }
        validate_column_index_array(
            array_property(bound_object, "variableColumnIndices")?,
            column_count,
        )?;
        let variable_names = array_property(bound_object, "variableNames")?;
        if variable_names.len() != array_property(bound_object, "variableColumnIndices")?.len()
            || !variable_names.iter().all(Value::is_string)
        {
            return Err("encoded relation backend bound variables are inconsistent".to_string());
        }
        for field_name in ["absoluteMaximum", "minimum", "maximum"] {
            if let Some(value) = bound_object.get(field_name) {
                validate_signed_decimal_string(
                    value
                        .as_str()
                        .ok_or_else(|| format!("{field_name} must be a decimal string"))?,
                )?;
            }
        }
    }

    Ok(())
}

pub(super) fn validate_backend_proof_components(
    proof_components: &[Value],
    row_batches: &[Value],
    column_count: u64,
) -> Result<(), String> {
    let expected_component_ids = [
        "score-and-shamir-field-component",
        "payload-plaintext-field-component",
        "share-commitment-component",
        "receiver-encryption-component",
        "receiver-key-binding-component",
    ];
    if proof_components.len() != expected_component_ids.len() {
        return Err("encoded relation backend proof-component count is invalid".to_string());
    }

    for (component_index, expected_component_id) in expected_component_ids.iter().enumerate() {
        let component_object = object_field(
            proof_components
                .get(component_index)
                .ok_or_else(|| "encoded relation backend proof component is missing".to_string())?,
            "backend proof component",
        )?;
        let component_id = string_property(component_object, "componentId")?;
        if component_id != *expected_component_id {
            return Err("encoded relation backend proof-component order is invalid".to_string());
        }

        let matching_batches = row_batches
            .iter()
            .map(|batch| object_field(batch, "backend row batch"))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|batch| {
                string_property(batch, "rowKind")
                    .map(|row_kind| component_id_for_row_kind(&row_kind) == component_id)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if matching_batches.is_empty() {
            return Err("encoded relation backend proof component has no row batches".to_string());
        }
        let coefficient_modulus = string_property(component_object, "coefficientModulus")?;
        let expected_row_count = matching_batches
            .iter()
            .try_fold(0_u64, |row_count, batch| {
                if string_property(batch, "modulus")? != coefficient_modulus {
                    return Err(
                        "encoded relation backend proof-component modulus is inconsistent"
                            .to_string(),
                    );
                }
                Ok(row_count + u64_property(batch, "rowCount")?)
            })?;
        if u64_property(component_object, "rowCount")? != expected_row_count {
            return Err(
                "encoded relation backend proof-component row count is invalid".to_string(),
            );
        }

        let expected_lowering_status = if matching_batches
            .iter()
            .all(|batch| string_property(batch, "batchKind").as_deref() == Ok("ExplicitSparseRows"))
        {
            "explicitRowsAvailable"
        } else {
            "digestExpandedRowsPending"
        };
        if string_property(component_object, "proofLoweringStatus")? != expected_lowering_status {
            return Err(
                "encoded relation backend proof-component lowering status is invalid".to_string(),
            );
        }

        let expected_batch_names = matching_batches
            .iter()
            .map(|batch| string_property(batch, "batchName"))
            .collect::<Result<Vec<_>, _>>()?;
        let row_batch_names = array_property(component_object, "rowBatchNames")?;
        if !string_array_equals(row_batch_names, &expected_batch_names) {
            return Err(
                "encoded relation backend proof-component row-batch names are invalid".to_string(),
            );
        }

        let expected_row_kinds =
            matching_batches
                .iter()
                .try_fold(Vec::<String>::new(), |mut row_kinds, batch| {
                    let row_kind = string_property(batch, "rowKind")?;
                    if !row_kinds.contains(&row_kind) {
                        row_kinds.push(row_kind);
                    }
                    Ok::<Vec<String>, String>(row_kinds)
                })?;
        let row_kinds = array_property(component_object, "rowKinds")?;
        if !string_array_equals(row_kinds, &expected_row_kinds) {
            return Err(
                "encoded relation backend proof-component row kinds are invalid".to_string(),
            );
        }

        let expected_column_indices = matching_batches.iter().try_fold(
            std::collections::BTreeSet::<u64>::new(),
            |mut indices, batch| {
                for value in array_property(batch, "variableColumnIndices")? {
                    let column_index = value.as_u64().ok_or_else(|| {
                        "encoded relation backend column index must be an integer".to_string()
                    })?;
                    indices.insert(column_index);
                }
                Ok::<std::collections::BTreeSet<u64>, String>(indices)
            },
        )?;
        let variable_column_indices = array_property(component_object, "variableColumnIndices")?;
        validate_column_index_array(variable_column_indices, column_count)?;
        if variable_column_indices.len() as u64
            != u64_property(component_object, "variableColumnCount")?
            || variable_column_indices
                .iter()
                .map(|value| {
                    value.as_u64().ok_or_else(|| {
                        "encoded relation backend column index must be an integer".to_string()
                    })
                })
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?
                != expected_column_indices
        {
            return Err(
                "encoded relation backend proof-component variable columns are invalid".to_string(),
            );
        }

        let component_digest = string_property(component_object, "componentDigest")?;
        validate_digest_string(&component_digest)?;
        let component_value = Value::Object(component_object.clone());
        let component_payload = value_without_field(&component_value, "componentDigest")?;
        let expected_component_digest =
            derive_backend_digest(BACKEND_PROOF_COMPONENTS_DIGEST_PURPOSE, component_payload)?;
        if component_digest != expected_component_digest {
            return Err("encoded relation backend proof-component digest is invalid".to_string());
        }
    }

    Ok(())
}

pub(super) fn component_id_for_row_kind(row_kind: &str) -> &'static str {
    match row_kind {
        "EncodedScoreFieldRows" => "score-and-shamir-field-component",
        "ReceiverPayloadPlaintextBindingRows" => "payload-plaintext-field-component",
        "ReceiverPayloadPlaintextBitDecompositionRows" => "payload-plaintext-field-component",
        "ShareCommitmentEquationRows" => "share-commitment-component",
        "ShareCommitmentEquation" => "share-commitment-component",
        "ReceiverPayloadEncryptionEquation" => "receiver-encryption-component",
        "ReceiverPayloadEncryptionEquationRows" => "receiver-encryption-component",
        "ReceiverKeyBinding" => "receiver-key-binding-component",
        "ReceiverKeyBindingRows" => "receiver-key-binding-component",
        _ => "",
    }
}

pub(super) fn string_array_equals(values: &[Value], expected: &[String]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(value, expected_value)| value.as_str() == Some(expected_value.as_str()))
}

pub(super) fn validate_batch_digest_pair(
    batch_object: &serde_json::Map<String, Value>,
    matrix_purpose: &str,
    target_purpose: &str,
    matrix_payload: Value,
    target_payload: Value,
) -> Result<(), String> {
    let matrix_digest = string_property(batch_object, "matrixDigest")?;
    let target_vector_digest = string_property(batch_object, "targetVectorDigest")?;
    validate_digest_string(&matrix_digest)?;
    validate_digest_string(&target_vector_digest)?;
    let expected_matrix_digest = derive_backend_digest(matrix_purpose, matrix_payload)?;
    let expected_target_vector_digest = derive_backend_digest(target_purpose, target_payload)?;
    if matrix_digest != expected_matrix_digest {
        return Err("encoded relation backend batch matrix digest is invalid".to_string());
    }
    if target_vector_digest != expected_target_vector_digest {
        return Err("encoded relation backend batch target-vector digest is invalid".to_string());
    }

    Ok(())
}

pub(super) fn explicit_backend_matrix_payload(rows: &[Value]) -> Result<Value, String> {
    let mut matrix_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let row_object = object_field(row, "backend explicit row")?;
        matrix_rows.push(json!({
            "rowIndex": u64_property(row_object, "rowIndex")?,
            "rowKind": string_property(row_object, "rowKind")?,
            "rowName": string_property(row_object, "rowName")?,
            "terms": array_property(row_object, "terms")?,
        }));
    }

    Ok(json!({ "rows": matrix_rows }))
}

pub(super) fn explicit_backend_target_payload(rows: &[Value]) -> Result<Value, String> {
    let mut targets = Vec::with_capacity(rows.len());
    for row in rows {
        let row_object = object_field(row, "backend explicit row")?;
        targets.push(json!({
            "rowIndex": u64_property(row_object, "rowIndex")?,
            "rowKind": string_property(row_object, "rowKind")?,
            "rowName": string_property(row_object, "rowName")?,
            "target": string_property(row_object, "target")?,
        }));
    }

    Ok(json!({ "targets": targets }))
}

pub(super) fn digest_expanded_backend_payload(
    batch_object: &serde_json::Map<String, Value>,
) -> Result<Value, String> {
    Ok(json!({
        "coefficientExpansionDomain": string_property(batch_object, "coefficientExpansionDomain")?,
        "modulus": string_property(batch_object, "modulus")?,
        "publicInputDigests": object_property(batch_object, "publicInputDigests")?,
        "receiverIdentity": string_property(batch_object, "receiverIdentity")?,
        "receiverRosterPosition": u64_property(batch_object, "receiverRosterPosition")?,
        "rowCount": u64_property(batch_object, "rowCount")?,
        "rowKind": string_property(batch_object, "rowKind")?,
        "sourceAlgebraicRowName": string_property(batch_object, "sourceAlgebraicRowName")?,
        "targetDigest": string_property(batch_object, "targetDigest")?,
        "targetExpansionDomain": string_property(batch_object, "targetExpansionDomain")?,
        "variableColumnIndices": array_property(batch_object, "variableColumnIndices")?,
    }))
}

pub(super) fn backend_batch_matrix_summary(batch: &Value) -> Result<Value, String> {
    let batch_object = object_field(batch, "backend row batch")?;
    Ok(json!({
        "batchKind": string_property(batch_object, "batchKind")?,
        "batchName": string_property(batch_object, "batchName")?,
        "matrixDigest": string_property(batch_object, "matrixDigest")?,
        "rowCount": u64_property(batch_object, "rowCount")?,
        "rowKind": string_property(batch_object, "rowKind")?,
        "rowOffset": u64_property(batch_object, "rowOffset")?,
    }))
}

pub(super) fn backend_batch_target_summary(batch: &Value) -> Result<Value, String> {
    let batch_object = object_field(batch, "backend row batch")?;
    Ok(json!({
        "batchKind": string_property(batch_object, "batchKind")?,
        "batchName": string_property(batch_object, "batchName")?,
        "rowCount": u64_property(batch_object, "rowCount")?,
        "rowKind": string_property(batch_object, "rowKind")?,
        "rowOffset": u64_property(batch_object, "rowOffset")?,
        "targetVectorDigest": string_property(batch_object, "targetVectorDigest")?,
    }))
}

pub(super) fn validate_digest_map(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    if object.is_empty() {
        return Err("encoded relation backend digest map must not be empty".to_string());
    }
    for value in object.values() {
        validate_digest_string(value.as_str().ok_or_else(|| {
            "encoded relation backend digest map value must be a string".to_string()
        })?)?;
    }

    Ok(())
}

pub(super) fn validate_column_index_array(
    values: &[Value],
    column_count: u64,
) -> Result<(), String> {
    let mut previous_column_index = None;
    for value in values {
        let column_index = value.as_u64().ok_or_else(|| {
            "encoded relation backend column index must be an integer".to_string()
        })?;
        if column_index >= column_count {
            return Err("encoded relation backend column index is out of range".to_string());
        }
        if let Some(previous) = previous_column_index
            && column_index <= previous
        {
            return Err(
                "encoded relation backend column indices must be strictly increasing".to_string(),
            );
        }
        previous_column_index = Some(column_index);
    }

    Ok(())
}

pub(super) fn reject_forbidden_witness_keys(value: &Value) -> Result<(), String> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "encodedCoordinateShamirCoefficients",
        "errorVector",
        "normalizedScores",
        "privateWitness",
        "ciphertextChunks",
        "encryptionRandomness",
        "openingRandomness",
        "proofRandomness",
        "receiverShareVector",
        "scoreOneHotWitnesses",
        "secretState",
        "secretVector",
        "witness",
    ];

    match value {
        Value::Array(entries) => {
            for entry in entries {
                reject_forbidden_witness_keys(entry)?;
            }
        }
        Value::Object(object) => {
            for (key, entry) in object {
                if FORBIDDEN_KEYS.contains(&key.as_str()) {
                    return Err(format!(
                        "encoded relation vector exposes forbidden witness key {key}"
                    ));
                }
                reject_forbidden_witness_keys(entry)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }

    Ok(())
}

pub(super) fn validate_digest_string(value: &str) -> Result<(), String> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("encoded relation digest must be 64 lowercase bytes".to_string());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("encoded relation digest must be lowercase hex".to_string());
    }

    Ok(())
}

pub(super) fn validate_signed_decimal_string(value: &str) -> Result<(), String> {
    if value.is_empty() || value == "-" || value == "-0" || value.starts_with('+') {
        return Err("encoded relation decimal string is not canonical".to_string());
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("encoded relation decimal string contains non-digits".to_string());
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err("encoded relation decimal string has a leading zero".to_string());
    }

    Ok(())
}

pub(super) fn validate_unsigned_decimal_string(value: &str) -> Result<(), String> {
    validate_signed_decimal_string(value)?;
    if value.starts_with('-') {
        return Err("encoded relation unsigned decimal string is negative".to_string());
    }

    Ok(())
}

pub(super) fn derive_backend_digest(purpose: &str, payload: Value) -> Result<String, String> {
    derive_protocol_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": payload,
            "purpose": purpose,
        }),
    )
    .map_err(|error| format!("encoded relation backend digest could not be recomputed: {error}"))
}

pub(super) fn object_field<'value>(
    value: &'value Value,
    label: &str,
) -> Result<&'value serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

pub(super) fn object_property<'value>(
    object: &'value serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<&'value serde_json::Map<String, Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{field_name} must be a JSON object"))
}

pub(super) fn array_property<'value>(
    object: &'value serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<&'value Vec<Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field_name} must be an array"))
}

pub(super) fn string_property(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<String, String> {
    object
        .get(field_name)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("{field_name} must be a string"))
}

pub(super) fn u64_property(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<u64, String> {
    object
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field_name} must be a non-negative integer"))
}

pub(super) fn bool_property(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<bool, String> {
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
    use serde_json::{Value, json};

    use super::verify_encoded_relation_vector_case_value;

    fn generated_case(case_name: &str) -> Value {
        let vectors: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json"
        )))
        .expect("encoded relation vector file should parse");

        vectors["cases"]
            .as_array()
            .expect("encoded relation vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == case_name)
            .unwrap_or_else(|| panic!("encoded relation vector case {case_name} should exist"))
            .clone()
    }

    fn expect_mini_case_mutation_rejected(mut mutate_case: impl FnMut(&mut Value)) {
        let mut vector_case = generated_case("mini-encoded-ballot-relation");
        mutate_case(&mut vector_case);

        let verification = verify_encoded_relation_vector_case_value(&vector_case);

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["unresolvedReason"], "InvalidFixture");
    }

    fn expect_full_explicit_case_mutation_rejected(mut mutate_case: impl FnMut(&mut Value)) {
        let mut vector_case = generated_case("mini-encoded-ballot-full-explicit-relation");
        mutate_case(&mut vector_case);

        let verification = verify_encoded_relation_vector_case_value(&vector_case);

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["unresolvedReason"], "InvalidFixture");
    }

    #[test]
    fn verifies_mini_encoded_relation_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "mini-encoded-ballot-relation",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["expectedOutcome"], "accept");
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("EncodedRelationDigestRecomputed"))
        );
    }

    #[test]
    fn verifies_mandatory_encoded_relation_summary_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "mandatory-profile-encoded-ballot-relation",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["expectedOutcome"], "accept");
    }

    #[test]
    fn verifies_explicit_share_commitment_relation_summary_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "mini-encoded-ballot-share-commitment-explicit-relation",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["expectedOutcome"], "accept");
    }

    #[test]
    fn verifies_full_explicit_relation_summary_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "mini-encoded-ballot-full-explicit-relation",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["expectedOutcome"], "accept");
    }

    #[test]
    fn verifies_reject_vector_as_recorded_refusal() {
        let verification =
            verify_encoded_relation_vector_case_value(&generated_case("wrong-quotient-rejects"));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("EncodedRelationRejectVectorChecked"))
        );
    }

    #[test]
    fn verifies_backend_preflight_reject_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "noncanonical-backend-coefficient-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!(
                    "EncodedBackendStatementRejectVectorChecked"
                ))
        );
    }

    #[test]
    fn rejects_proof_component_metadata_mutations() {
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][0]["rowCount"] =
                json!(71);
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][0]["proofLoweringStatus"] =
                json!("digestExpandedRowsPending");
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][0]["componentDigest"] =
                json!("0".repeat(128));
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponentsDigest"] =
                json!("0".repeat(128));
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][1]
                ["variableColumnIndices"]
                .as_array_mut()
                .expect("proof component variable columns should be an array")
                .push(json!(0));
        });
    }

    #[test]
    fn rejects_component_proof_readiness_manifest_mutations() {
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["componentProofReadinessManifests"][0]["denseMatrixOracleStatus"] =
                json!("blocked-pending-sparse-proof-statement");
        });
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["componentProofReadinessManifests"][1]["denseCoefficientCount"] =
                json!("95472001");
        });
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["componentProofReadinessManifests"][3]["proofStatementFormat"] =
                json!("dense-polynomial-matrix-linear-proof-v1");
        });
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["proofReadinessSummary"]["fullComponentProofBytesAvailable"] = json!(true);
        });
    }

    #[test]
    fn rejects_component_proof_statement_plan_mutations() {
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["componentProofStatementPlans"][1]["proofBytesAvailability"] =
                json!("available-for-small-dense-oracle");
        });
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["componentProofStatementPlans"][2]["sparseTermCount"] = json!("230401");
        });
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["componentProofStatementPlans"][3]["structuredWitnessTermCount"] =
                json!("15746866");
        });
        expect_full_explicit_case_mutation_rejected(|vector_case| {
            vector_case["componentProofStatementPlans"][3]["componentProofStatementDigest"] =
                json!("0".repeat(128));
        });
    }
}
