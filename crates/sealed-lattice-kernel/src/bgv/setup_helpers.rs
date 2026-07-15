use serde_json::Value;

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

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

pub(super) fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| invalid_setup_fixture(format!("{field_name} must be a non-empty string")))
}

pub(super) fn u64_field(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_setup_fixture(format!("{field_name} must be a non-negative integer"))
        })
}

pub(super) fn usize_field(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    usize::try_from(u64_field(value, field_name)?)
        .map_err(|_| invalid_setup_fixture(format!("{field_name} does not fit usize")))
}

pub(super) fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if !is_lowercase_protocol_hash(hash) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a 128-character lowercase hexadecimal protocol hash"),
        ));
    }

    Ok(())
}

fn invalid_setup_fixture(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

pub(super) fn is_lowercase_protocol_hash(hash: &str) -> bool {
    hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

pub(super) fn compare_required_u64(
    actual: u64,
    expected: u64,
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

pub(super) fn read_positive_usize_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<usize> {
    let field = usize_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}

pub(super) fn read_positive_u64_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<u64> {
    let field = unsigned_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}
