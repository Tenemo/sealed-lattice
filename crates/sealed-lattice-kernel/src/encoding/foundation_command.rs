use serde_json::{Map, Value, json};

use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{CanonicalDecodeLimits, ProofApplicationBinding};
use crate::transcript_core::{decode_hex, encode_hex};

pub(super) fn decode_proof_application_binding(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let canonical_bytes = decode_hex(required_string(request, "canonicalBytesHex")?)?;
    let binding =
        ProofApplicationBinding::decode(&canonical_bytes, &CanonicalDecodeLimits::default())
            .map_err(schema_error)?;
    if binding.encode().map_err(schema_error)? != canonical_bytes {
        return Err(invalid_value(
            "proof application binding did not round-trip to identical canonical bytes",
        ));
    }
    let slot = binding.application_slot();
    let descriptor = binding.proof_stream_descriptor();
    Ok(json!({
        "canonicalBytesHex": encode_hex(&canonical_bytes),
        "applicationSlotCanonicalBytesHex": encode_hex(&slot.encode().map_err(schema_error)?),
        "applicationSlotHash": slot.hash().map_err(schema_error)?.to_lowercase_hex(),
        "suiteIdentifier": slot.suite_identifier().to_lowercase_hex(),
        "ceremonyContextHash": slot.ceremony_context_hash().to_lowercase_hex(),
        "actionContextHash": slot.action_context_hash().to_lowercase_hex(),
        "applicationStatementSchemaIdentifier": slot.application_statement_schema_identifier(),
        "rosterPosition": slot.roster_position(),
        "schedulePosition": slot.schedule_position(),
        "producerSequence": slot.producer_sequence().map(|value| value.to_string()),
        "proofHeaderHash": binding.proof_header_hash().to_lowercase_hex(),
        "proofStreamDescriptorCanonicalBytesHex": encode_hex(
            &descriptor.encode().map_err(schema_error)?
        ),
        "proofByteLength": descriptor.total_byte_length.to_string(),
    }))
}

fn required_object<'a>(value: &'a Value, label: &str) -> CanonicalResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_value(format!("{label} must be an object")))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    object
        .get(field_name)
        .ok_or_else(|| invalid_value(format!("{field_name} is required")))?
        .as_str()
        .ok_or_else(|| invalid_value(format!("{field_name} must be a string")))
}

fn schema_error(error: crate::foundation::FoundationSchemaError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, error.to_string())
}

fn invalid_value(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
