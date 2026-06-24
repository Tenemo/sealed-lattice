use serde_json::Value;

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
};

pub(super) fn read_non_empty_string<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    let field = value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })?;
    if field.trim().is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must not be empty"),
        ));
    }

    Ok(field)
}

pub(super) fn read_hash_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    let hash = read_non_empty_string(value, field_name)?;
    validate_hash_string(hash, field_name)?;

    Ok(hash)
}

pub(super) fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() != 128
        || !hash
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a 128-character lowercase hexadecimal protocol hash"),
        ));
    }

    Ok(())
}

pub(super) fn read_optional_u64(value: &Value, field_name: &str) -> CanonicalResult<Option<u64>> {
    value
        .get(field_name)
        .map(|field| {
            field.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name} must be a non-negative integer"),
                )
            })
        })
        .transpose()
}

pub(super) fn read_optional_usize(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Option<usize>> {
    read_optional_u64(value, field_name)?
        .map(|field| {
            usize::try_from(field).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name} does not fit usize"),
                )
            })
        })
        .transpose()
}

pub(super) fn decimal_i128_value(value: &Value) -> Option<i128> {
    if let Some(value) = value.as_i64() {
        return Some(i128::from(value));
    }
    if let Some(value) = value.as_u64() {
        return Some(i128::from(value));
    }
    value.as_str()?.parse::<i128>().ok()
}

pub(super) fn compare_expected_string(
    request: &Value,
    expected_field_name: &str,
    actual: &str,
    description: &str,
) -> CanonicalResult<()> {
    if let Some(expected) = request.get(expected_field_name).and_then(Value::as_str) {
        validate_hash_string(expected, expected_field_name)?;
        if expected != actual {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("BGV passive setup {description} does not match {expected_field_name}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a str> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing setup package field {}", path.join(".")),
            )
        })?;
    }
    current.as_str().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("setup package field {} must be a string", path.join(".")),
        )
    })
}

pub(super) fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a Value> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing setup package field {}", path.join(".")),
            )
        })?;
    }

    Ok(current)
}

pub(super) fn array_at_path<'a>(
    value: &'a Value,
    path: &[&str],
) -> CanonicalResult<&'a Vec<Value>> {
    value_at_path(value, path)?.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("setup package field {} must be an array", path.join(".")),
        )
    })
}

pub(super) fn unsigned_at_path(value: &Value, path: &[&str]) -> CanonicalResult<u64> {
    value_at_path(value, path)?.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "setup package field {} must be a non-negative integer",
                path.join(".")
            ),
        )
    })
}

pub(super) fn integer_at_path(value: &Value, path: &[&str]) -> CanonicalResult<i64> {
    value_at_path(value, path)?.as_i64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "setup package field {} must be a signed integer",
                path.join(".")
            ),
        )
    })
}

pub(super) fn usize_at_path(value: &Value, path: &[&str]) -> CanonicalResult<usize> {
    let value = unsigned_at_path(value, path)?;
    usize::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("setup package field {} does not fit usize", path.join(".")),
        )
    })
}

pub(super) fn hash_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a str> {
    let hash = string_at_path(value, path)?;
    validate_hash_string(hash, &path.join("."))?;

    Ok(hash)
}

pub(super) fn compare_required_string(
    actual: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("passive BGV setup package {description} does not match its canonical binding"),
        ));
    }

    Ok(())
}

pub(super) fn compare_string_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    compare_required_string(string_at_path(value, path)?, expected, description)
}

pub(super) fn compare_hash_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    compare_required_string(hash_at_path(value, path)?, expected, description)
}

pub(super) fn compare_derived_hash(
    namespace: &str,
    value: &Value,
    actual_hash: &str,
    description: &str,
) -> CanonicalResult<()> {
    let expected_hash = derive_protocol_hash(namespace, value)?;
    if actual_hash != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("passive BGV setup package {description} does not match its canonical payload"),
        ));
    }

    Ok(())
}
