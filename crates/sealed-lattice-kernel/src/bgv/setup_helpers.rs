use serde_json::Value;

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_digest,
};

const COMMON_FORBIDDEN_SETUP_SECRET_FIELD_NAMES: &[&str] = &[
    "secretShares",
    "rawSecretShares",
    "globalSecret",
    "globalSecretPolynomial",
    "fullSecretPolynomial",
    "trustedDealerSecret",
    "trustedDealerSecretHex",
    "centralizedSecret",
    "rawKeySwitchSecret",
    "rawDecryptionSecret",
];
const REQUEST_ONLY_FORBIDDEN_SETUP_SECRET_FIELD_NAMES: &[&str] =
    &["centralizedSecretReconstruction"];
const PACKAGE_SECRET_FLAG_FIELD_NAMES: &[&str] =
    &["centralizedSecretReconstruction", "rawSecretShareExported"];

pub(super) fn reject_forbidden_setup_fields(request: &Value) -> CanonicalResult<()> {
    for field_name in forbidden_setup_field_names() {
        if request.get(field_name).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{field_name} would centralize BGV secret material and cannot be accepted by M8 setup"
                ),
            ));
        }
    }

    Ok(())
}

pub(super) fn forbidden_setup_field_names() -> Vec<&'static str> {
    COMMON_FORBIDDEN_SETUP_SECRET_FIELD_NAMES
        .iter()
        .chain(REQUEST_ONLY_FORBIDDEN_SETUP_SECRET_FIELD_NAMES)
        .copied()
        .collect()
}

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

pub(super) fn read_digest_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    let digest = read_non_empty_string(value, field_name)?;
    validate_digest_string(digest, field_name)?;

    Ok(digest)
}

pub(super) fn validate_digest_string(digest: &str, field_name: &str) -> CanonicalResult<()> {
    if digest.len() != 128
        || !digest
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a 128-character lowercase hexadecimal protocol digest"),
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

pub(super) fn compare_expected_string(
    request: &Value,
    expected_field_name: &str,
    actual: &str,
    description: &str,
) -> CanonicalResult<()> {
    if let Some(expected) = request.get(expected_field_name).and_then(Value::as_str) {
        validate_digest_string(expected, expected_field_name)?;
        if expected != actual {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
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

pub(super) fn bool_at_path(value: &Value, path: &[&str]) -> CanonicalResult<bool> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing setup package field {}", path.join(".")),
            )
        })?;
    }
    current.as_bool().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("setup package field {} must be a boolean", path.join(".")),
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

pub(super) fn digest_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a str> {
    let digest = string_at_path(value, path)?;
    validate_digest_string(digest, &path.join("."))?;

    Ok(digest)
}

pub(super) fn compare_required_string(
    actual: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M8 setup package {description} does not match its canonical binding"),
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

pub(super) fn compare_digest_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    compare_required_string(digest_at_path(value, path)?, expected, description)
}

pub(super) fn compare_derived_digest(
    namespace: &str,
    value: &Value,
    actual_digest: &str,
    description: &str,
) -> CanonicalResult<()> {
    let expected_digest = derive_protocol_digest(namespace, value)?;
    if actual_digest != expected_digest {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M8 setup package {description} does not match its canonical payload"),
        ));
    }

    Ok(())
}

fn is_forbidden_setup_package_secret_field(field_name: &str) -> bool {
    COMMON_FORBIDDEN_SETUP_SECRET_FIELD_NAMES.contains(&field_name)
}

fn is_setup_package_secret_flag_field(field_name: &str) -> bool {
    PACKAGE_SECRET_FLAG_FIELD_NAMES.contains(&field_name)
}

pub(super) fn reject_forbidden_setup_package_secret_fields(value: &Value) -> CanonicalResult<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                reject_forbidden_setup_package_secret_fields(item)?;
            }
        }
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                if is_forbidden_setup_package_secret_field(field_name) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "{field_name} would expose BGV secret material and cannot be accepted by M8 setup verification"
                        ),
                    ));
                }
                if is_setup_package_secret_flag_field(field_name)
                    && field_value.as_bool() != Some(false)
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        format!("M8 setup package field {field_name} must remain false"),
                    ));
                }
                reject_forbidden_setup_package_secret_fields(field_value)?;
            }
        }
        _ => {}
    }

    Ok(())
}
