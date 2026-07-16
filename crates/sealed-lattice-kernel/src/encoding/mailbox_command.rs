use serde_json::{Map, Value, json};

use super::command_fields::{
    decode_exact_lowercase_hex, invalid_value, required_array, required_canonical_u64_decimal,
    required_exact_lowercase_hex, required_lowercase_hex_bytes, required_object, required_value,
};
use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{
    CanonicalDecodeLimits, Hash512, MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
    MAILBOX_GCM_TAG_BYTE_LENGTH, MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH,
    MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH, MailboxAssociatedData, MailboxKeyScheduleInput,
    MailboxPayloadType, ParticipantIdentity, SignedMailboxEnvelope, StreamDescriptor,
    derive_setup_mailbox_slot_hash,
};
use crate::transcript_core::encode_hex;

pub(super) fn encode_mailbox_key_schedule_input(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let input = mailbox_key_schedule_input_from_json(required_value(request, "value")?)?;
    let kem_ciphertext = required_exact_lowercase_hex::<MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH>(
        request,
        "kemCiphertextHex",
    )?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&input.encode().map_err(schema_error)?),
        "hkdfExtractSaltHex": encode_hex(
            &input
                .hkdf_extract_salt(&kem_ciphertext)
                .map_err(schema_error)?,
        ),
    }))
}

pub(super) fn decode_mailbox_key_schedule_input(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let bytes = required_lowercase_hex_bytes(request, "canonicalBytesHex")?;
    let input = MailboxKeyScheduleInput::decode(&bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_error)?;
    Ok(json!({
        "value": mailbox_key_schedule_input_to_json(&input),
    }))
}

pub(super) fn encode_mailbox_associated_data(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let associated_data = mailbox_associated_data_from_json(required_value(request, "value")?)?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&associated_data.encode().map_err(schema_error)?),
    }))
}

pub(super) fn decode_mailbox_associated_data(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let bytes = required_lowercase_hex_bytes(request, "canonicalBytesHex")?;
    let associated_data = MailboxAssociatedData::decode(&bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_error)?;
    Ok(json!({
        "value": mailbox_associated_data_to_json(&associated_data),
    }))
}

pub(super) fn encode_stream_descriptor(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let descriptor = stream_descriptor_from_json(required_value(request, "value")?)?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&descriptor.encode().map_err(schema_error)?),
    }))
}

pub(super) fn decode_stream_descriptor(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let bytes = required_lowercase_hex_bytes(request, "canonicalBytesHex")?;
    let descriptor = StreamDescriptor::decode(&bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_error)?;
    Ok(json!({
        "value": stream_descriptor_to_json(&descriptor),
    }))
}

pub(super) fn encode_signed_mailbox_envelope(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let envelope = signed_mailbox_envelope_from_json(required_value(request, "value")?, true)?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&envelope.encode().map_err(schema_error)?),
        "envelopeHash": envelope.envelope_hash().map_err(schema_error)?.to_lowercase_hex(),
    }))
}

pub(super) fn decode_signed_mailbox_envelope(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let bytes = required_lowercase_hex_bytes(request, "canonicalBytesHex")?;
    let envelope = SignedMailboxEnvelope::decode(&bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_error)?;
    Ok(json!({
        "value": signed_mailbox_envelope_to_json(&envelope),
        "envelopeHash": envelope.envelope_hash().map_err(schema_error)?.to_lowercase_hex(),
    }))
}

pub(super) fn derive_mailbox_envelope_hash_command(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let envelope = signed_mailbox_envelope_from_json(required_value(request, "value")?, false)?;
    Ok(json!({
        "envelopeHash": envelope.envelope_hash().map_err(schema_error)?.to_lowercase_hex(),
    }))
}

pub(super) fn derive_setup_mailbox_slot_hash_command(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let object = required_object(required_value(request, "value")?, "setup mailbox slot")?;
    let payload_type =
        MailboxPayloadType::from_canonical_code(required_u16(object, "payloadType")?)
            .ok_or_else(|| invalid_value("payloadType must be an assigned mailbox payload type"))?;
    let ordered_material_roots = required_array(object, "orderedMaterialRoots")?
        .iter()
        .enumerate()
        .map(|(index, root)| hash_from_value(root, &format!("orderedMaterialRoots[{index}]")))
        .collect::<CanonicalResult<Vec<_>>>()?;
    Ok(json!({
        "setupMailboxSlotHash": derive_setup_mailbox_slot_hash(
            required_hash(object, "suiteId")?,
            required_hash(object, "ceremonyContextHash")?,
            required_hash(object, "actionContextHash")?,
            required_hash(object, "rosterHash")?,
            required_participant_identity(object, "sourceParticipantId")?,
            required_participant_identity(object, "recipientParticipantId")?,
            required_canonical_u64_decimal(object, "producerSequence")?,
            payload_type,
            required_hash(object, "statementHash")?,
            &ordered_material_roots,
        )
        .map_err(schema_error)?
        .to_lowercase_hex(),
    }))
}

fn mailbox_key_schedule_input_from_json(value: &Value) -> CanonicalResult<MailboxKeyScheduleInput> {
    let object = required_object(value, "mailbox key-schedule input")?;
    let payload_type_code = required_u16(object, "payloadType")?;
    let payload_type =
        MailboxPayloadType::from_canonical_code(payload_type_code).ok_or_else(|| {
            invalid_value("payloadType must be one of the assigned mailbox payload types")
        })?;
    let material_roots = required_array(object, "orderedMaterialRoots")?
        .iter()
        .enumerate()
        .map(|(index, root)| hash_from_value(root, &format!("orderedMaterialRoots[{index}]")))
        .collect::<CanonicalResult<Vec<_>>>()?;
    MailboxKeyScheduleInput {
        suite_id: required_hash(object, "suiteId")?,
        ceremony_context_hash: required_hash(object, "ceremonyContextHash")?,
        action_context_hash: required_hash(object, "actionContextHash")?,
        roster_hash: required_hash(object, "rosterHash")?,
        source_participant_id: required_participant_identity(object, "sourceParticipantId")?,
        recipient_participant_id: required_participant_identity(object, "recipientParticipantId")?,
        producer_sequence: required_canonical_u64_decimal(object, "producerSequence")?,
        envelope_attempt_identifier: required_exact_lowercase_hex::<
            MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
        >(object, "envelopeAttemptIdentifierHex")?,
        payload_type,
        statement_hash: required_hash(object, "statementHash")?,
        ordered_material_roots: material_roots,
    }
    .checked()
    .map_err(schema_error)
}

fn mailbox_key_schedule_input_to_json(input: &MailboxKeyScheduleInput) -> Value {
    json!({
        "suiteId": input.suite_id.to_lowercase_hex(),
        "ceremonyContextHash": input.ceremony_context_hash.to_lowercase_hex(),
        "actionContextHash": input.action_context_hash.to_lowercase_hex(),
        "rosterHash": input.roster_hash.to_lowercase_hex(),
        "sourceParticipantId": input.source_participant_id.to_lowercase_hex(),
        "recipientParticipantId": input.recipient_participant_id.to_lowercase_hex(),
        "producerSequence": input.producer_sequence.to_string(),
        "envelopeAttemptIdentifierHex": encode_hex(&input.envelope_attempt_identifier),
        "payloadType": input.payload_type.canonical_code(),
        "statementHash": input.statement_hash.to_lowercase_hex(),
        "orderedMaterialRoots": input
            .ordered_material_roots
            .iter()
            .map(|root| root.to_lowercase_hex())
            .collect::<Vec<_>>(),
    })
}

fn mailbox_associated_data_from_json(value: &Value) -> CanonicalResult<MailboxAssociatedData> {
    required_object(value, "mailbox associated data")?;
    MailboxAssociatedData::new(mailbox_key_schedule_input_from_json(value)?).map_err(schema_error)
}

fn mailbox_associated_data_to_json(associated_data: &MailboxAssociatedData) -> Value {
    mailbox_key_schedule_input_to_json(&associated_data.key_schedule_input)
}

fn signed_mailbox_envelope_from_json(
    value: &Value,
    require_source_signature: bool,
) -> CanonicalResult<SignedMailboxEnvelope> {
    let object = required_object(value, "signed mailbox envelope")?;
    let source_signature = if require_source_signature {
        required_exact_lowercase_hex::<MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH>(
            object,
            "sourceSignatureHex",
        )?
    } else {
        [0_u8; MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH]
    };
    SignedMailboxEnvelope::new(
        mailbox_associated_data_from_json(required_value(object, "associatedData")?)?,
        required_exact_lowercase_hex::<MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH>(
            object,
            "kemCiphertextHex",
        )?,
        stream_descriptor_from_json(required_value(object, "ciphertextDescriptor")?)?,
        required_exact_lowercase_hex::<MAILBOX_GCM_TAG_BYTE_LENGTH>(object, "gcmTagHex")?,
        source_signature,
    )
    .map_err(schema_error)
}

fn signed_mailbox_envelope_to_json(envelope: &SignedMailboxEnvelope) -> Value {
    json!({
        "associatedData": mailbox_associated_data_to_json(&envelope.associated_data),
        "kemCiphertextHex": encode_hex(&envelope.kem_ciphertext),
        "ciphertextDescriptor": stream_descriptor_to_json(&envelope.ciphertext_descriptor),
        "gcmTagHex": encode_hex(&envelope.gcm_tag),
        "sourceSignatureHex": encode_hex(&envelope.source_signature),
    })
}

fn stream_descriptor_from_json(value: &Value) -> CanonicalResult<StreamDescriptor> {
    let object = required_object(value, "mailbox ciphertext descriptor")?;
    let ordered_chunk_digests = required_array(object, "orderedChunkDigests")?
        .iter()
        .enumerate()
        .map(|(index, digest)| hash_from_value(digest, &format!("orderedChunkDigests[{index}]")))
        .collect::<CanonicalResult<Vec<_>>>()?;
    StreamDescriptor::new(
        required_canonical_u64_decimal(object, "totalByteLength")?,
        ordered_chunk_digests,
        hash_from_value(
            required_value(object, "fullObjectDigest")?,
            "fullObjectDigest",
        )?,
    )
    .map_err(schema_error)
}

fn stream_descriptor_to_json(descriptor: &StreamDescriptor) -> Value {
    json!({
        "totalByteLength": descriptor.total_byte_length.to_string(),
        "orderedChunkDigests": descriptor
            .ordered_chunk_digests
            .iter()
            .map(|digest| digest.to_lowercase_hex())
            .collect::<Vec<_>>(),
        "fullObjectDigest": descriptor.full_object_digest.to_lowercase_hex(),
    })
}

fn required_u16(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<u16> {
    let value = required_value(object, field_name)?
        .as_u64()
        .ok_or_else(|| invalid_value(format!("{field_name} must be an unsigned integer")))?;
    u16::try_from(value).map_err(|_| invalid_value(format!("{field_name} does not fit u16")))
}

fn required_hash(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<Hash512> {
    hash_from_value(required_value(object, field_name)?, field_name)
}

fn hash_from_value(value: &Value, field_name: &str) -> CanonicalResult<Hash512> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid_value(format!("{field_name} must be a lowercase hex string")))?;
    Ok(Hash512::from_bytes(decode_exact_lowercase_hex::<64>(
        value, field_name,
    )?))
}

fn required_participant_identity(
    object: &Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<ParticipantIdentity> {
    Ok(ParticipantIdentity::from_bytes(
        required_exact_lowercase_hex::<64>(object, field_name)?,
    ))
}

fn schema_error(error: crate::foundation::FoundationSchemaError) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        format!("mailbox value refused: {}", error.refusal_reason),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::super::command::run_transcript_core_command_inner;
    use super::*;
    use crate::foundation::MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH;

    fn run(request: Value) -> Value {
        run_transcript_core_command_inner(request.to_string().as_bytes())
            .expect("mailbox command succeeds")
    }

    fn key_schedule_value() -> Value {
        json!({
            "suiteId": "11".repeat(64),
            "ceremonyContextHash": "22".repeat(64),
            "actionContextHash": "33".repeat(64),
            "rosterHash": "44".repeat(64),
            "sourceParticipantId": "55".repeat(64),
            "recipientParticipantId": "66".repeat(64),
            "producerSequence": "7",
            "envelopeAttemptIdentifierHex": "77".repeat(32),
            "payloadType": 2,
            "statementHash": "88".repeat(64),
            "orderedMaterialRoots": ["91".repeat(64), "92".repeat(64)],
        })
    }

    fn associated_data_value() -> Value {
        key_schedule_value()
    }

    fn setup_mailbox_slot_value() -> Value {
        json!({
            "suiteId": "11".repeat(64),
            "ceremonyContextHash": "22".repeat(64),
            "actionContextHash": "33".repeat(64),
            "rosterHash": "44".repeat(64),
            "sourceParticipantId": "55".repeat(64),
            "recipientParticipantId": "66".repeat(64),
            "producerSequence": "7",
            "payloadType": 2,
            "statementHash": "88".repeat(64),
            "orderedMaterialRoots": ["91".repeat(64), "92".repeat(64)],
        })
    }

    fn unsigned_envelope_value() -> Value {
        json!({
            "associatedData": associated_data_value(),
            "kemCiphertextHex": "5a".repeat(MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH),
            "ciphertextDescriptor": {
                "totalByteLength": "64",
                "orderedChunkDigests": ["a1".repeat(64)],
                "fullObjectDigest": "a2".repeat(64),
            },
            "gcmTagHex": "b1".repeat(MAILBOX_GCM_TAG_BYTE_LENGTH),
        })
    }

    #[test]
    fn mailbox_commands_round_trip_all_three_canonical_schemas() {
        let kem_ciphertext_hex = "5a".repeat(MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH);

        let key_schedule_response = run(json!({
            "command": "EncodeMailboxKeyScheduleInput",
            "value": key_schedule_value(),
            "kemCiphertextHex": kem_ciphertext_hex,
        }));
        assert_eq!(
            key_schedule_response["hkdfExtractSaltHex"]
                .as_str()
                .expect("extract salt is returned")
                .len(),
            MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH * 2
        );
        let decoded_key_schedule = run(json!({
            "command": "DecodeMailboxKeyScheduleInput",
            "canonicalBytesHex": key_schedule_response["canonicalBytesHex"],
        }));
        assert_eq!(decoded_key_schedule["value"]["producerSequence"], "7");
        assert_eq!(decoded_key_schedule["value"]["payloadType"], 2);

        let associated_data_response = run(json!({
            "command": "EncodeMailboxAssociatedData",
            "value": associated_data_value(),
        }));
        let decoded_associated_data = run(json!({
            "command": "DecodeMailboxAssociatedData",
            "canonicalBytesHex": associated_data_response["canonicalBytesHex"],
        }));
        assert_eq!(decoded_associated_data["value"], associated_data_value());

        let descriptor = unsigned_envelope_value()["ciphertextDescriptor"].clone();
        let encoded_descriptor = run(json!({
            "command": "EncodeStreamDescriptor",
            "value": descriptor,
        }));
        let decoded_descriptor = run(json!({
            "command": "DecodeStreamDescriptor",
            "canonicalBytesHex": encoded_descriptor["canonicalBytesHex"],
        }));
        assert_eq!(decoded_descriptor["value"], descriptor);

        let unsigned_envelope = unsigned_envelope_value();
        let envelope_hash_response = run(json!({
            "command": "DeriveMailboxEnvelopeHash",
            "value": unsigned_envelope,
        }));
        assert_eq!(
            envelope_hash_response["envelopeHash"]
                .as_str()
                .expect("envelope hash is returned")
                .len(),
            128
        );

        let mut signed_envelope = unsigned_envelope_value();
        signed_envelope
            .as_object_mut()
            .expect("envelope is an object")
            .insert(
                "sourceSignatureHex".to_owned(),
                Value::String("c1".repeat(MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH)),
            );
        let encoded_envelope = run(json!({
            "command": "EncodeSignedMailboxEnvelope",
            "value": signed_envelope,
        }));
        assert_eq!(
            encoded_envelope["envelopeHash"],
            envelope_hash_response["envelopeHash"]
        );
        let decoded_envelope = run(json!({
            "command": "DecodeSignedMailboxEnvelope",
            "canonicalBytesHex": encoded_envelope["canonicalBytesHex"],
        }));
        assert_eq!(
            decoded_envelope["envelopeHash"],
            encoded_envelope["envelopeHash"]
        );
        assert_eq!(
            decoded_envelope["value"]["associatedData"]["producerSequence"],
            "7"
        );

        let slot_hash = run(json!({
            "command": "DeriveSetupMailboxSlotHash",
            "value": setup_mailbox_slot_value(),
        }));
        assert_eq!(
            slot_hash["setupMailboxSlotHash"]
                .as_str()
                .expect("setup mailbox slot hash is returned")
                .len(),
            128
        );
    }

    #[test]
    fn mailbox_commands_reject_noncanonical_numbers_hex_and_bindings() {
        let kem_ciphertext_hex = "5a".repeat(MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH);

        let mut leading_zero = key_schedule_value();
        leading_zero["producerSequence"] = Value::String("07".to_owned());
        let error = run_transcript_core_command_inner(
            json!({
                "command": "EncodeMailboxKeyScheduleInput",
                "value": leading_zero,
                "kemCiphertextHex": kem_ciphertext_hex,
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("leading-zero decimal refuses");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);

        let error = run_transcript_core_command_inner(
            json!({
                "command": "EncodeMailboxKeyScheduleInput",
                "value": key_schedule_value(),
                "kemCiphertextHex": "AA".repeat(MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH),
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("uppercase hex refuses");
        assert_eq!(error.code, CanonicalErrorCode::InvalidHex);

        let mut unassigned_payload_slot = setup_mailbox_slot_value();
        unassigned_payload_slot["payloadType"] = Value::from(1);
        let error = run_transcript_core_command_inner(
            json!({
                "command": "DeriveSetupMailboxSlotHash",
                "value": unassigned_payload_slot,
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("unassigned mailbox payload type refuses");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
    }
}
