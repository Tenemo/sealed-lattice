use serde_json::{Map, Value};

use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::transcript_core::decode_hex;

pub(super) fn required_object<'a>(
    value: &'a Value,
    label: &str,
) -> CanonicalResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_value(format!("{label} must be an object")))
}

pub(super) fn required_value<'a>(
    object: &'a Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<&'a Value> {
    object
        .get(field_name)
        .ok_or_else(|| invalid_value(format!("{field_name} is required")))
}

pub(super) fn required_string<'a>(
    object: &'a Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    required_value(object, field_name)?
        .as_str()
        .ok_or_else(|| invalid_value(format!("{field_name} must be a string")))
}

pub(super) fn required_array<'a>(
    object: &'a Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<&'a [Value]> {
    required_value(object, field_name)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_value(format!("{field_name} must be an array")))
}

pub(super) fn required_u16(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<u16> {
    let value = required_value(object, field_name)?
        .as_u64()
        .ok_or_else(|| invalid_value(format!("{field_name} must be an unsigned integer")))?;
    u16::try_from(value).map_err(|_| invalid_value(format!("{field_name} does not fit u16")))
}

pub(super) fn required_canonical_u64_decimal(
    object: &Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<u64> {
    let value = required_string(object, field_name)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(invalid_value(format!(
            "{field_name} must be a canonical unsigned decimal string"
        )));
    }
    value
        .parse()
        .map_err(|_| invalid_value(format!("{field_name} does not fit u64")))
}

pub(super) fn required_lowercase_hex_bytes(
    object: &Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<Vec<u8>> {
    decode_hex(required_string(object, field_name)?)
}

pub(super) fn invalid_value(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn unsigned_decimal_requires_canonical_syntax() {
        let value = json!({ "number": "00" });
        let object = value.as_object().expect("test input is an object");

        let error = required_canonical_u64_decimal(object, "number")
            .expect_err("canonical decimal syntax must reject a leading zero");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert_eq!(
            error.message,
            "number must be a canonical unsigned decimal string"
        );
    }
}
