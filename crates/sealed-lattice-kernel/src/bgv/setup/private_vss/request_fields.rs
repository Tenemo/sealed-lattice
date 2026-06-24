use super::*;

pub(super) fn compare_context_fields(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> Result<(), PrivateVssRefusal> {
    for field_name in setup_context_field_names() {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(PrivateVssRefusal::new(
                "privateVssContextMismatch",
                format!("{object_path}.{field_name} must match setupContext"),
                format!("{object_path}.{field_name}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn setup_context_field_names() -> [&'static str; 8] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ]
}

pub(super) fn object_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a Value, PrivateVssRefusal> {
    let Some(field) = value.get(field_name) else {
        return Err(PrivateVssRefusal::new(reason_code, message, object_path));
    };
    if !field.is_object() {
        return Err(PrivateVssRefusal::new(
            reason_code,
            format!("{object_path} must be a JSON object"),
            object_path,
        ));
    }

    Ok(field)
}

pub(super) fn array_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a Vec<Value>, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

pub(super) fn string_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a str, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

pub(super) fn hash_string_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a str, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

pub(super) fn u64_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<u64, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

pub(super) fn usize_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<usize, PrivateVssRefusal> {
    let field = u64_field(value, field_name, object_path, reason_code, message)?;
    usize::try_from(field).map_err(|_| {
        PrivateVssRefusal::new(
            reason_code,
            format!("{object_path} does not fit usize"),
            object_path,
        )
    })
}

pub(super) fn u64_vector_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<Vec<u64>, PrivateVssRefusal> {
    let values = array_field(value, field_name, object_path, reason_code, message)?;
    values
        .iter()
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                PrivateVssRefusal::new(
                    reason_code,
                    format!("{object_path} must contain only non-negative integers"),
                    object_path,
                )
            })
        })
        .collect()
}

pub(super) fn hash_vector_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<Vec<String>, PrivateVssRefusal> {
    let values = array_field(value, field_name, object_path, reason_code, message)?;
    values
        .iter()
        .map(|value| {
            let hash = value.as_str().ok_or_else(|| {
                PrivateVssRefusal::new(
                    reason_code,
                    format!("{object_path} must contain protocol hashes"),
                    object_path,
                )
            })?;
            validate_hash_string(hash, object_path)
                .map_err(|error| PrivateVssRefusal::new(reason_code, error.message, object_path))?;
            Ok(hash.to_string())
        })
        .collect()
}

pub(super) fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{field_name} must be a lowercase 512-bit hex protocol hash"),
    ))
}

pub(super) fn validate_exact_randomness_hex(
    value: &str,
    expected_byte_length: usize,
    field_name: &str,
) -> CanonicalResult<()> {
    if value.len() == expected_byte_length * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{field_name} must be {expected_byte_length} bytes of lowercase hex"),
    ))
}
