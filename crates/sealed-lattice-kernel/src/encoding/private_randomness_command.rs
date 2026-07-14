use serde_json::{Map, Value, json};

use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomness, ActionRandomnessDerivationInput,
    CanonicalDecodeLimits, Hash512, PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
    ParticipantIdentity, PrivateRandomBlockInput, PrivateRandomCursor,
};
use crate::transcript_core::{decode_hex, encode_hex};

pub(super) fn encode_action_randomness_derivation_input(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let input = action_randomness_derivation_input_from_json(required_value(request, "value")?)?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&input.encode().map_err(schema_error)?),
    }))
}

pub(super) fn decode_action_randomness_derivation_input(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let canonical_bytes = decode_hex(required_string(request, "canonicalBytesHex")?)?;
    let input = ActionRandomnessDerivationInput::decode(
        &canonical_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(schema_error)?;
    Ok(json!({ "value": action_randomness_derivation_input_to_json(input) }))
}

pub(super) fn derive_action_randomness_commitment(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let input = action_randomness_derivation_input_from_json(required_value(request, "value")?)?;
    let action_randomness = ActionRandomness::derive(
        required_hex_array::<ACTION_RANDOMNESS_ROOT_BYTE_LENGTH>(
            request,
            "actionRandomnessRootHex",
        )?,
        input,
    )
    .map_err(schema_error)?;
    Ok(json!({
        "actionRandomnessCommitment": action_randomness
            .action_randomness_commitment()
            .to_lowercase_hex(),
    }))
}

pub(super) fn encode_private_random_block_input(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let input = private_random_block_input_from_json(required_value(request, "value")?)?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&input.encode().map_err(schema_error)?),
    }))
}

pub(super) fn decode_private_random_block_input(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let canonical_bytes = decode_hex(required_string(request, "canonicalBytesHex")?)?;
    let input =
        PrivateRandomBlockInput::decode(&canonical_bytes, &CanonicalDecodeLimits::default())
            .map_err(schema_error)?;
    Ok(json!({ "value": private_random_block_input_to_json(input) }))
}

pub(super) fn encode_private_random_cursor(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let cursor = cursor_from_json(required_value(request, "value")?)?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&cursor.encode().map_err(schema_error)?),
    }))
}

pub(super) fn decode_private_random_cursor(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let canonical_bytes = decode_hex(required_string(request, "canonicalBytesHex")?)?;
    let cursor = PrivateRandomCursor::decode(&canonical_bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_error)?;
    Ok(json!({ "value": cursor_to_json(cursor) }))
}

fn cursor_from_json(value: &Value) -> CanonicalResult<PrivateRandomCursor> {
    let object = required_object(value, "private-randomness cursor")?;
    PrivateRandomCursor::new(
        required_u16(object, "family")?,
        required_u16(object, "purpose")?,
        Hash512::from_bytes(required_hex_array::<64>(object, "derivationContextHash")?),
        required_hex_array::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
            object,
            "streamAttemptIdentifierHex",
        )?,
        required_u64_decimal(object, "nextCounter")?,
        optional_u16(object, "nextUnreadBitOffsetInBufferedBlock")?,
    )
    .map_err(schema_error)
}

fn action_randomness_derivation_input_from_json(
    value: &Value,
) -> CanonicalResult<ActionRandomnessDerivationInput> {
    let object = required_object(value, "action-randomness derivation input")?;
    Ok(ActionRandomnessDerivationInput::new(
        required_hash(object, "suiteId")?,
        required_hash(object, "ceremonyContextHash")?,
        required_hash(object, "actionContextHash")?,
        ParticipantIdentity::from_bytes(required_hex_array::<64>(object, "participantId")?),
    ))
}

fn action_randomness_derivation_input_to_json(input: ActionRandomnessDerivationInput) -> Value {
    json!({
        "suiteId": input.suite_id().to_lowercase_hex(),
        "ceremonyContextHash": input.ceremony_context_hash().to_lowercase_hex(),
        "actionContextHash": input.action_context_hash().to_lowercase_hex(),
        "participantId": input.participant_id().to_lowercase_hex(),
    })
}

fn private_random_block_input_from_json(value: &Value) -> CanonicalResult<PrivateRandomBlockInput> {
    let object = required_object(value, "private-random block input")?;
    PrivateRandomBlockInput::from_assigned_pair(
        action_randomness_derivation_input_from_json(value)?,
        required_u16(object, "family")?,
        required_u16(object, "purpose")?,
        required_hash(object, "derivationContextHash")?,
        required_hex_array::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
            object,
            "attemptIdentifierHex",
        )?,
        required_u64_decimal(object, "counter")?,
    )
    .map_err(schema_error)
}

fn private_random_block_input_to_json(input: PrivateRandomBlockInput) -> Value {
    let mut value = action_randomness_derivation_input_to_json(input.derivation_input());
    let object = value
        .as_object_mut()
        .expect("action-randomness derivation input JSON is an object");
    object.insert("family".to_owned(), Value::from(input.family()));
    object.insert("purpose".to_owned(), Value::from(input.purpose()));
    object.insert(
        "derivationContextHash".to_owned(),
        Value::String(input.derivation_context_hash().to_lowercase_hex()),
    );
    object.insert(
        "attemptIdentifierHex".to_owned(),
        Value::String(encode_hex(&input.attempt_identifier())),
    );
    object.insert(
        "counter".to_owned(),
        Value::String(input.counter().to_string()),
    );
    value
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

fn required_object<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_value(format!("{field_name} must be an object")))
}

fn required_value<'a>(
    object: &'a Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<&'a Value> {
    object
        .get(field_name)
        .ok_or_else(|| invalid_value(format!("{field_name} is required")))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    required_value(object, field_name)?
        .as_str()
        .ok_or_else(|| invalid_value(format!("{field_name} must be a string")))
}

fn required_u16(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<u16> {
    let value = required_value(object, field_name)?
        .as_u64()
        .ok_or_else(|| invalid_value(format!("{field_name} must be an unsigned integer")))?;
    u16::try_from(value).map_err(|_| invalid_value(format!("{field_name} does not fit u16")))
}

fn required_hash(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<Hash512> {
    Ok(Hash512::from_bytes(required_hex_array::<64>(
        object, field_name,
    )?))
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

fn required_u64_decimal(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<u64> {
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

fn required_hex_array<const BYTE_LENGTH: usize>(
    object: &Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<[u8; BYTE_LENGTH]> {
    let bytes = decode_hex(required_string(object, field_name)?)?;
    bytes.try_into().map_err(|_| {
        invalid_value(format!(
            "{field_name} must contain exactly {BYTE_LENGTH} bytes"
        ))
    })
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

fn invalid_value(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::super::command::run_transcript_core_command_inner;

    fn action_derivation_value() -> Value {
        json!({
            "suiteId": "11".repeat(64),
            "ceremonyContextHash": "22".repeat(64),
            "actionContextHash": "33".repeat(64),
            "participantId": "44".repeat(64),
        })
    }

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
    fn action_and_block_inputs_round_trip_and_commitment_is_context_bound() {
        let action_value = action_derivation_value();
        let encoded_action = run_transcript_core_command_inner(
            json!({
                "command": "EncodeActionRandomnessDerivationInput",
                "value": action_value,
            })
            .to_string()
            .as_bytes(),
        )
        .expect("action derivation input encodes");
        let decoded_action = run_transcript_core_command_inner(
            json!({
                "command": "DecodeActionRandomnessDerivationInput",
                "canonicalBytesHex": encoded_action["canonicalBytesHex"],
            })
            .to_string()
            .as_bytes(),
        )
        .expect("action derivation input decodes");
        assert_eq!(decoded_action["value"], action_derivation_value());

        let commitment = run_transcript_core_command_inner(
            json!({
                "command": "DeriveActionRandomnessCommitment",
                "actionRandomnessRootHex": "5a".repeat(64),
                "value": action_derivation_value(),
            })
            .to_string()
            .as_bytes(),
        )
        .expect("action randomness commitment derives");
        let mut changed_context = action_derivation_value();
        changed_context["actionContextHash"] = Value::String("34".repeat(64));
        let changed_commitment = run_transcript_core_command_inner(
            json!({
                "command": "DeriveActionRandomnessCommitment",
                "actionRandomnessRootHex": "5a".repeat(64),
                "value": changed_context,
            })
            .to_string()
            .as_bytes(),
        )
        .expect("changed commitment derives");
        assert_ne!(
            commitment["actionRandomnessCommitment"],
            changed_commitment["actionRandomnessCommitment"]
        );

        let mut block_value = action_derivation_value();
        let block_object = block_value.as_object_mut().expect("block object");
        block_object.insert("family".to_owned(), Value::from(0x0200));
        block_object.insert("purpose".to_owned(), Value::from(2));
        block_object.insert(
            "derivationContextHash".to_owned(),
            Value::String("55".repeat(64)),
        );
        block_object.insert(
            "attemptIdentifierHex".to_owned(),
            Value::String("66".repeat(32)),
        );
        block_object.insert("counter".to_owned(), Value::String(u64::MAX.to_string()));
        let encoded_block = run_transcript_core_command_inner(
            json!({
                "command": "EncodePrivateRandomBlockInput",
                "value": block_value,
            })
            .to_string()
            .as_bytes(),
        )
        .expect("private-random block input encodes");
        let decoded_block = run_transcript_core_command_inner(
            json!({
                "command": "DecodePrivateRandomBlockInput",
                "canonicalBytesHex": encoded_block["canonicalBytesHex"],
            })
            .to_string()
            .as_bytes(),
        )
        .expect("private-random block input decodes");
        assert_eq!(decoded_block["value"], block_value);
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
