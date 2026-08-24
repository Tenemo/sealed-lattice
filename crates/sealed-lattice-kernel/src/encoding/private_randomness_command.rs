use serde_json::{Map, Value, json};

use super::command_fields::{
    invalid_value, required_canonical_u64_decimal, required_exact_lowercase_hex,
    required_lowercase_hex_bytes, required_object, required_u16, required_value,
};
use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{
    CanonicalDecodeLimits, Hash512, PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
    PrivateRandomCursor,
};
use crate::transcript_core::encode_hex;

pub(super) fn encode_private_random_cursor(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let cursor = cursor_from_json(required_value(request, "value")?)?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&cursor.encode().map_err(schema_error)?),
    }))
}

pub(super) fn decode_private_random_cursor(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let canonical_bytes = required_lowercase_hex_bytes(request, "canonicalBytesHex")?;
    let cursor = PrivateRandomCursor::decode(&canonical_bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_error)?;
    Ok(json!({ "value": cursor_to_json(cursor) }))
}

fn cursor_from_json(value: &Value) -> CanonicalResult<PrivateRandomCursor> {
    let object = required_object(value, "private-randomness cursor")?;
    PrivateRandomCursor::new(
        required_u16(object, "family")?,
        required_u16(object, "purpose")?,
        Hash512::from_bytes(required_exact_lowercase_hex::<64>(
            object,
            "derivationContextHash",
        )?),
        required_exact_lowercase_hex::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
            object,
            "streamAttemptIdentifierHex",
        )?,
        required_canonical_u64_decimal(object, "nextCounter")?,
        optional_u16(object, "nextUnreadBitOffsetInBufferedBlock")?,
    )
    .map_err(schema_error)
}

fn cursor_to_json(cursor: PrivateRandomCursor) -> Value {
    let mut value = json!({
        "family": cursor.family(),
        "purpose": cursor.purpose(),
        "derivationContextHash": cursor.derivation_context_hash().to_lowercase_hex(),
        "streamAttemptIdentifierHex": encode_hex(&cursor.stream_attempt_identifier()),
        "nextCounter": cursor.next_counter().to_string(),
    });
    if let Some(offset) = cursor.next_unread_bit_offset_in_buffered_block() {
        value
            .as_object_mut()
            .expect("private-randomness cursor JSON is an object")
            .insert(
                "nextUnreadBitOffsetInBufferedBlock".to_owned(),
                Value::from(offset),
            );
    }
    value
}

fn optional_u16(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<Option<u16>> {
    match object.get(field_name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let value = value.as_u64().ok_or_else(|| {
                invalid_value(format!("{field_name} must be an unsigned integer"))
            })?;
            Ok(Some(u16::try_from(value).map_err(|_| {
                invalid_value(format!("{field_name} does not fit u16"))
            })?))
        }
    }
}

fn schema_error(error: crate::foundation::FoundationSchemaError) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        format!(
            "private-randomness cursor refused: {}",
            error.refusal_reason
        ),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::super::command::run_transcript_core_command_inner;

    fn cursor_value() -> Value {
        json!({
            "family": 0x0200,
            "purpose": 2,
            "derivationContextHash": "11".repeat(64),
            "streamAttemptIdentifierHex": "22".repeat(32),
            "nextCounter": "9",
            "nextUnreadBitOffsetInBufferedBlock": 137,
        })
    }

    #[test]
    fn private_random_cursor_command_round_trips_exactly() {
        let encoded = run_transcript_core_command_inner(
            json!({
                "command": "EncodePrivateRandomCursor",
                "value": cursor_value(),
            })
            .to_string()
            .as_bytes(),
        )
        .expect("cursor encodes");
        let decoded = run_transcript_core_command_inner(
            json!({
                "command": "DecodePrivateRandomCursor",
                "canonicalBytesHex": encoded["canonicalBytesHex"],
            })
            .to_string()
            .as_bytes(),
        )
        .expect("cursor decodes");
        assert_eq!(decoded["value"], cursor_value());
    }

    #[test]
    fn private_random_cursor_command_refuses_unknown_domains_and_misaligned_offsets() {
        let mut unknown_domain = cursor_value();
        unknown_domain["purpose"] = Value::from(4);
        assert!(
            run_transcript_core_command_inner(
                json!({
                    "command": "EncodePrivateRandomCursor",
                    "value": unknown_domain,
                })
                .to_string()
                .as_bytes(),
            )
            .is_err()
        );

        let mut impossible_offset = cursor_value();
        impossible_offset["nextCounter"] = Value::String("0".to_owned());
        assert!(
            run_transcript_core_command_inner(
                json!({
                    "command": "EncodePrivateRandomCursor",
                    "value": impossible_offset,
                })
                .to_string()
                .as_bytes(),
            )
            .is_err()
        );
    }
}
