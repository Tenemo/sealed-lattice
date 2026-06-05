use super::*;

pub(super) fn required_string_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.trim().is_empty())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-empty string"),
            )
        })
}

pub(super) fn usize_field(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let unsigned = value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-negative integer"),
            )
        })?;
    usize::try_from(unsigned).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} does not fit usize"),
        )
    })
}

pub(super) fn compare_hash_field(
    value: &Value,
    field_name: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = hash_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

pub(super) fn compare_string_field(
    value: &Value,
    field_name: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = string_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

pub(super) fn compare_unsigned_field(
    value: &Value,
    field_name: &str,
    expected: u64,
    description: &str,
) -> CanonicalResult<()> {
    let actual = unsigned_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}
