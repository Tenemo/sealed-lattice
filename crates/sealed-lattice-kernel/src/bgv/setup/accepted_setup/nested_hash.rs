use super::*;

pub(super) fn optional_nested_hash_value(
    setup_package: &Value,
    object_field_name: &str,
    hash_field_name: &str,
) -> CanonicalResult<Value> {
    let Some(object_value) = setup_package.get(object_field_name) else {
        return Ok(Value::Null);
    };
    optional_hash_value(
        object_value.get(hash_field_name),
        &format!("setupPackage.{object_field_name}.{hash_field_name}"),
    )
}

fn optional_hash_value(value: Option<&Value>, field_path: &str) -> CanonicalResult<Value> {
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    let Some(hash_value) = value.as_str() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_path} must be a string when present"),
        ));
    };
    validate_hash_string(hash_value, field_path)?;

    Ok(json!(hash_value))
}

pub(super) fn package_nested_hash(
    setup_package: &Value,
    object_field_name: &str,
    hash_field_name: &str,
) -> CanonicalResult<String> {
    setup_package
        .get(object_field_name)
        .and_then(|object| object.get(hash_field_name))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setupPackage.{object_field_name}.{hash_field_name} is required"),
            )
        })
}
