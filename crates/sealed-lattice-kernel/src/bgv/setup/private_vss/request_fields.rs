use super::*;

pub(super) use crate::bgv::setup_helpers::validate_hash_string;

pub(super) fn compare_context_fields(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> Result<(), PrivateVssRefusal> {
    let expected_setup_context_hash =
        accepted_setup::setup_context_hash(setup_context).map_err(|_| {
            PrivateVssRefusal::new(
                PrivateVssRefusalCode::wrong_context("privateVssContextMismatch"),
                "setupContext must be canonical before comparing private VSS records",
                "setupContext",
            )
        })?;
    if value.get("setupContextHash").and_then(Value::as_str)
        != Some(expected_setup_context_hash.as_str())
    {
        return Err(PrivateVssRefusal::new(
            PrivateVssRefusalCode::wrong_context("privateVssContextMismatch"),
            format!("{object_path}.setupContextHash must match setupContext"),
            format!("{object_path}.setupContextHash"),
        ));
    }

    Ok(())
}

pub(super) fn authoritative_setup_context_field_names() -> [&'static str; 5] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ]
}

pub(super) fn object_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    code: PrivateVssRefusalCode,
    message: impl Into<String>,
) -> Result<&'a Value, PrivateVssRefusal> {
    let Some(field) = value.get(field_name) else {
        return Err(PrivateVssRefusal::new(code, message, object_path));
    };
    if !field.is_object() {
        return Err(PrivateVssRefusal::new(
            code,
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
    code: PrivateVssRefusalCode,
    message: impl Into<String>,
) -> Result<&'a Vec<Value>, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| PrivateVssRefusal::new(code, message, object_path))
}

pub(super) fn string_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    code: PrivateVssRefusalCode,
    message: impl Into<String>,
) -> Result<&'a str, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| PrivateVssRefusal::new(code, message, object_path))
}

pub(super) fn hash_string_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    code: PrivateVssRefusalCode,
    message: impl Into<String>,
) -> Result<&'a str, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| PrivateVssRefusal::new(code, message, object_path))
}

pub(super) fn u64_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    code: PrivateVssRefusalCode,
    message: impl Into<String>,
) -> Result<u64, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| PrivateVssRefusal::new(code, message, object_path))
}

pub(super) fn usize_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    code: PrivateVssRefusalCode,
    message: impl Into<String>,
) -> Result<usize, PrivateVssRefusal> {
    let field = u64_field(value, field_name, object_path, code, message)?;
    usize::try_from(field).map_err(|_| {
        PrivateVssRefusal::new(
            code,
            format!("{object_path} does not fit usize"),
            object_path,
        )
    })
}

pub(super) fn u64_vector_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    code: PrivateVssRefusalCode,
    message: impl Into<String>,
) -> Result<Vec<u64>, PrivateVssRefusal> {
    let values = array_field(value, field_name, object_path, code, message)?;
    values
        .iter()
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                PrivateVssRefusal::new(
                    code,
                    format!("{object_path} must contain only non-negative integers"),
                    object_path,
                )
            })
        })
        .collect()
}
