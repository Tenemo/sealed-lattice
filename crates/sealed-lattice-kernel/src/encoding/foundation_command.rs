use serde_json::{Map, Value, json};

use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{
    ACTION_DEFINITION_SCHEMA_IDENTIFIER, ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
    ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER,
    ActionContext, ActionDefinition, ActionRandomnessDerivationInput, ActionStorageDerivationInput,
    BOARD_POLICY_SCHEMA_IDENTIFIER, BoardPolicy, CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER,
    CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER, CanonicalCodecError, CanonicalDecodeLimits,
    CeremonyContext, CheckpointBoundaryProfile, CheckpointRandomUseProfile,
    DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
    DeviceWrappedStorageRoot, DeviceWrappingAssociatedData, DistributionRecord, Hash512,
    IncrementalCanonicalTupleDecoder, LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER, LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER, LocalRecordAssociatedData, LocalRecordEnvelope,
    LocalRecordKeyInput, MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER, MANIFEST_SCHEMA_IDENTIFIER,
    MailboxAssociatedData, MailboxKeyScheduleInput, Manifest, OBJECT_ENVELOPE_SCHEMA_IDENTIFIER,
    OPTION_DEFINITION_SCHEMA_IDENTIFIER, ObjectEnvelope, OptionDefinition,
    PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
    PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER, PersistentProofCoinInput, PrivateRandomBlockInput,
    PrivateRandomCursor, ProofApplicationSlot, RANDOM_CURSOR_SCHEMA_IDENTIFIER,
    ROSTER_ENTRY_SCHEMA_IDENTIFIER, ROSTER_SCHEMA_IDENTIFIER,
    RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER, RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER,
    RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER, Roster, RosterEntry, RuntimeAssetReference,
    RuntimeBuildManifest, RuntimeOperationProfile, SIGNED_CARRIER_SCHEMA_IDENTIFIER,
    SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, STATE_CERTIFICATE_SCHEMA_IDENTIFIER,
    STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER, STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER,
    STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER, STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER, STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
    SUITE_RECORD_SCHEMA_IDENTIFIER, SignedCarrier, SignedMailboxEnvelope, StateCertificate,
    StateOutputIntentPayload, StateRecoveryTransitionPayload, StateReservationIntentPayload,
    StateWitnessVotePayload, StorageRootCommitmentPayload, StreamDescriptor, SuiteRecord,
};
use crate::foundation::{
    LocalStorageRecoveryValue, ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, OrdinaryProofCoinInput,
};
use crate::transcript_core::{decode_hex, encode_hex};

macro_rules! round_trip_schema {
    ($type:path, $bytes:ident, $limits:ident) => {{
        let value = <$type>::decode(&$bytes, &$limits).map_err(schema_error)?;
        (value.encode().map_err(schema_error)?, None)
    }};
}

macro_rules! round_trip_state {
    ($type:path, $bytes:ident, $limits:ident) => {{
        let value = <$type>::decode(&$bytes, &$limits).map_err(state_error)?;
        (value.encode().map_err(state_error)?, None)
    }};
}

pub(super) fn validate_canonical_foundation_value(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let schema_identifier = required_u16(request, "schemaIdentifier")?;
    let limits = CanonicalDecodeLimits::default();
    let canonical_bytes = canonical_foundation_bytes(request, &limits)?;
    if canonical_bytes.len() > CanonicalDecodeLimits::default().maximum_tuple_byte_length {
        return Err(invalid_value(
            "canonical foundation value exceeds the supported byte limit",
        ));
    }

    let (round_tripped_bytes, binding_hash) = match schema_identifier {
        MANIFEST_SCHEMA_IDENTIFIER => {
            let value = Manifest::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.manifest_hash().map_err(schema_error)?),
            )
        }
        OPTION_DEFINITION_SCHEMA_IDENTIFIER => {
            round_trip_schema!(OptionDefinition, canonical_bytes, limits)
        }
        ACTION_DEFINITION_SCHEMA_IDENTIFIER => {
            let value =
                ActionDefinition::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.action_definition_hash().map_err(schema_error)?),
            )
        }
        BOARD_POLICY_SCHEMA_IDENTIFIER => {
            let value = BoardPolicy::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.board_policy_hash().map_err(schema_error)?),
            )
        }
        ROSTER_ENTRY_SCHEMA_IDENTIFIER => round_trip_schema!(RosterEntry, canonical_bytes, limits),
        ROSTER_SCHEMA_IDENTIFIER => {
            let value = Roster::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.roster_hash().map_err(schema_error)?),
            )
        }
        DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER => {
            round_trip_schema!(DistributionRecord, canonical_bytes, limits)
        }
        ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER => round_trip_schema!(
            crate::foundation::ArtifactReference,
            canonical_bytes,
            limits
        ),
        SUITE_RECORD_SCHEMA_IDENTIFIER => {
            let value = SuiteRecord::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.suite_id().map_err(schema_error)?),
            )
        }
        OBJECT_ENVELOPE_SCHEMA_IDENTIFIER => {
            let value = ObjectEnvelope::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.object_hash().map_err(schema_error)?),
            )
        }
        SIGNED_CARRIER_SCHEMA_IDENTIFIER => {
            round_trip_schema!(SignedCarrier, canonical_bytes, limits)
        }
        STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER => {
            round_trip_schema!(StreamDescriptor, canonical_bytes, limits)
        }
        PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER => {
            let value =
                ProofApplicationSlot::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.application_slot_hash().map_err(schema_error)?),
            )
        }
        MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(MailboxKeyScheduleInput, canonical_bytes, limits)
        }
        MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER => {
            round_trip_schema!(MailboxAssociatedData, canonical_bytes, limits)
        }
        SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER => {
            round_trip_schema!(SignedMailboxEnvelope, canonical_bytes, limits)
        }
        DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER => {
            round_trip_schema!(DeviceWrappingAssociatedData, canonical_bytes, limits)
        }
        LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER => {
            round_trip_schema!(LocalRecordAssociatedData, canonical_bytes, limits)
        }
        STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER => {
            round_trip_schema!(LocalStorageRecoveryValue, canonical_bytes, limits)
        }
        STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER => {
            round_trip_schema!(StorageRootCommitmentPayload, canonical_bytes, limits)
        }
        LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(LocalRecordKeyInput, canonical_bytes, limits)
        }
        DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(DeviceWrappedStorageRoot, canonical_bytes, limits)
        }
        LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER => {
            round_trip_schema!(LocalRecordEnvelope, canonical_bytes, limits)
        }
        LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER => (
            crate::foundation::round_trip_local_record_authenticator_input(
                &canonical_bytes,
                &limits,
            )
            .map_err(schema_error)?,
            None,
        ),
        ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(ActionStorageDerivationInput, canonical_bytes, limits)
        }
        PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(PrivateRandomBlockInput, canonical_bytes, limits)
        }
        PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(PersistentProofCoinInput, canonical_bytes, limits)
        }
        ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(ActionRandomnessDerivationInput, canonical_bytes, limits)
        }
        ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER => {
            round_trip_schema!(OrdinaryProofCoinInput, canonical_bytes, limits)
        }
        RANDOM_CURSOR_SCHEMA_IDENTIFIER => {
            round_trip_schema!(PrivateRandomCursor, canonical_bytes, limits)
        }
        RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER => {
            round_trip_schema!(RuntimeAssetReference, canonical_bytes, limits)
        }
        RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER => {
            let value =
                RuntimeBuildManifest::decode(&canonical_bytes, &limits).map_err(schema_error)?;
            (
                value.encode().map_err(schema_error)?,
                Some(value.runtime_build_manifest_hash().map_err(schema_error)?),
            )
        }
        CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER => {
            round_trip_schema!(CheckpointRandomUseProfile, canonical_bytes, limits)
        }
        CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER => {
            round_trip_schema!(CheckpointBoundaryProfile, canonical_bytes, limits)
        }
        RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER => {
            round_trip_schema!(RuntimeOperationProfile, canonical_bytes, limits)
        }
        STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER => {
            round_trip_state!(StateReservationIntentPayload, canonical_bytes, limits)
        }
        STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER => {
            round_trip_state!(StateOutputIntentPayload, canonical_bytes, limits)
        }
        STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER => {
            round_trip_state!(StateWitnessVotePayload, canonical_bytes, limits)
        }
        STATE_CERTIFICATE_SCHEMA_IDENTIFIER => {
            round_trip_state!(StateCertificate, canonical_bytes, limits)
        }
        STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER => {
            round_trip_state!(StateRecoveryTransitionPayload, canonical_bytes, limits)
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::UnsupportedObjectType,
                format!("unsupported foundation schema identifier: {schema_identifier:#06x}"),
            ));
        }
    };

    if round_tripped_bytes != canonical_bytes {
        return Err(invalid_value(
            "foundation value did not round-trip to identical canonical bytes",
        ));
    }

    let mut response = json!({
        "schemaIdentifier": schema_identifier,
        "canonicalBytesHex": encode_hex(&round_tripped_bytes),
    });
    if let Some(binding_hash) = binding_hash {
        response
            .as_object_mut()
            .expect("foundation validation response is an object")
            .insert(
                "bindingHash".to_owned(),
                Value::String(binding_hash.to_lowercase_hex()),
            );
    }
    Ok(response)
}

fn canonical_foundation_bytes(
    request: &Map<String, Value>,
    limits: &CanonicalDecodeLimits,
) -> CanonicalResult<Vec<u8>> {
    let contiguous_bytes = request.get("canonicalBytesHex");
    let fragmented_bytes = request.get("canonicalByteChunksHex");
    match (contiguous_bytes, fragmented_bytes) {
        (Some(_), Some(_)) => Err(invalid_value(
            "canonical foundation input must use exactly one byte representation",
        )),
        (None, None) => Err(invalid_value(
            "canonical foundation input requires canonicalBytesHex or canonicalByteChunksHex",
        )),
        (Some(value), None) => decode_hex(value.as_str().ok_or_else(|| {
            invalid_value("canonicalBytesHex must be a lowercase hexadecimal string")
        })?),
        (None, Some(value)) => {
            let expected_byte_length = required_usize(request, "canonicalByteLength")?;
            let chunks = value.as_array().ok_or_else(|| {
                invalid_value("canonicalByteChunksHex must be an array of hexadecimal strings")
            })?;
            if chunks.is_empty() || chunks.len() > expected_byte_length {
                return Err(invalid_value(
                    "canonicalByteChunksHex must contain bounded nonempty fragments",
                ));
            }
            let mut decoder = IncrementalCanonicalTupleDecoder::new(expected_byte_length, limits)
                .map_err(canonical_codec_error)?;
            for chunk in chunks {
                let chunk = decode_hex(chunk.as_str().ok_or_else(|| {
                    invalid_value("canonicalByteChunksHex entries must be hexadecimal strings")
                })?)?;
                if chunk.is_empty() {
                    return Err(invalid_value(
                        "canonicalByteChunksHex entries must not be empty",
                    ));
                }
                decoder.absorb(&chunk).map_err(canonical_codec_error)?;
            }
            decoder
                .finish()
                .map_err(canonical_codec_error)?
                .encode()
                .map_err(canonical_codec_error)
        }
    }
}

pub(super) fn derive_ceremony_context_hash(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let value = required_object(required_value(request, "value")?, "ceremony context")?;
    let context = CeremonyContext::new(
        required_hash(value, "suiteId")?,
        required_hash(value, "manifestHash")?,
        required_hash(value, "rosterHash")?,
        required_string(value, "ceremonyIdentifier")?.to_owned(),
    )
    .map_err(schema_error)?;
    Ok(json!({
        "ceremonyContextHash": context.context_hash().map_err(schema_error)?.to_lowercase_hex(),
    }))
}

pub(super) fn derive_action_context_hash(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let value = required_object(required_value(request, "value")?, "action context")?;
    let context = ActionContext::new(
        required_hash(value, "ceremonyContextHash")?,
        required_string(value, "actionIdentifier")?.to_owned(),
        required_hash(value, "actionDefinitionHash")?,
        required_hash(value, "boardPolicyHash")?,
    )
    .map_err(schema_error)?;
    Ok(json!({
        "actionContextHash": context.context_hash().map_err(schema_error)?.to_lowercase_hex(),
    }))
}

fn required_object<'a>(value: &'a Value, label: &str) -> CanonicalResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_value(format!("{label} must be an object")))
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

fn required_usize(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<usize> {
    let value = object
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_value(format!("{field_name} must be an unsigned integer")))?;
    usize::try_from(value)
        .map_err(|_| invalid_value(format!("{field_name} exceeds the platform limit")))
}

fn required_hash(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<Hash512> {
    let bytes = decode_hex(required_string(object, field_name)?)?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| invalid_value(format!("{field_name} must contain exactly 64 bytes")))?;
    Ok(Hash512::from_bytes(bytes))
}

fn schema_error(error: crate::foundation::FoundationSchemaError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, error.to_string())
}

fn canonical_codec_error(error: CanonicalCodecError) -> CanonicalError {
    schema_error(error.into())
}

fn state_error(error: crate::foundation::StateError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, error.to_string())
}

fn invalid_value(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER, CanonicalItem, CanonicalTuple,
        DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH,
        DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER, DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH,
        DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, DeviceWrappedStorageRoot,
        DeviceWrappingAssociatedData, FOUNDATION_PROFILE,
        LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH,
        LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
        LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER, LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER,
        LOCAL_RECORD_NONCE_BYTE_LENGTH, LOCAL_RECORD_TAG_BYTE_LENGTH, LocalRecordAssociatedData,
        LocalRecordEnvelope, LocalRecordKeyInput, LocalRecordType, LocalStorageBinding,
        LocalStorageRecoveryValue, ParticipantIdentity,
        STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
        STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER, StabilizedDisplayText,
        StorageRootCommitmentPayload,
    };

    fn manifest() -> Manifest {
        Manifest::new(
            StabilizedDisplayText::from_ingress_utf8(b"Foundation validation")
                .expect("valid display title"),
            (0..FOUNDATION_PROFILE.option_count)
                .map(|option_index| {
                    OptionDefinition::new(
                        option_index,
                        format!("option-{option_index}"),
                        StabilizedDisplayText::from_ingress_utf8(
                            format!("Option {option_index}").as_bytes(),
                        )
                        .expect("valid display label"),
                    )
                    .expect("valid option")
                })
                .collect(),
        )
        .expect("valid manifest")
    }

    #[test]
    fn foundation_validator_round_trips_and_derives_the_manifest_binding() {
        let manifest = manifest();
        let canonical_bytes = manifest.encode().expect("manifest encodes");
        let response = validate_canonical_foundation_value(&json!({
            "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
            "canonicalBytesHex": encode_hex(&canonical_bytes),
        }))
        .expect("canonical manifest validates");
        assert_eq!(
            response["canonicalBytesHex"],
            Value::String(encode_hex(&canonical_bytes))
        );
        assert_eq!(
            response["bindingHash"],
            Value::String(
                manifest
                    .manifest_hash()
                    .expect("manifest hash")
                    .to_lowercase_hex()
            )
        );

        let mut trailing = canonical_bytes;
        trailing.push(0);
        assert!(
            validate_canonical_foundation_value(&json!({
                "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
                "canonicalBytesHex": encode_hex(&trailing),
            }))
            .is_err()
        );
    }

    #[test]
    fn foundation_validator_decodes_fragmented_canonical_bytes_at_every_boundary() {
        let manifest = manifest();
        let canonical_bytes = manifest.encode().expect("manifest encodes");
        let expected_hash = manifest
            .manifest_hash()
            .expect("manifest hash")
            .to_lowercase_hex();

        for split_offset in 1..canonical_bytes.len() {
            let response = validate_canonical_foundation_value(&json!({
                "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
                "canonicalByteLength": canonical_bytes.len(),
                "canonicalByteChunksHex": [
                    encode_hex(&canonical_bytes[..split_offset]),
                    encode_hex(&canonical_bytes[split_offset..]),
                ],
            }))
            .unwrap_or_else(|error| panic!("fragment split {split_offset} must validate: {error}"));
            assert_eq!(
                response["canonicalBytesHex"],
                Value::String(encode_hex(&canonical_bytes)),
                "fragment split {split_offset}"
            );
            assert_eq!(
                response["bindingHash"],
                Value::String(expected_hash.clone()),
                "fragment split {split_offset}"
            );
        }
    }

    #[test]
    fn foundation_validator_refuses_malformed_fragmented_input() {
        let canonical_bytes = manifest().encode().expect("manifest encodes");
        let first_fragment = encode_hex(&canonical_bytes[..8]);
        let remaining_fragment = encode_hex(&canonical_bytes[8..]);

        for request in [
            json!({
                "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
                "canonicalBytesHex": encode_hex(&canonical_bytes),
                "canonicalByteLength": canonical_bytes.len(),
                "canonicalByteChunksHex": [first_fragment.clone(), remaining_fragment.clone()],
            }),
            json!({
                "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
                "canonicalByteLength": canonical_bytes.len() - 1,
                "canonicalByteChunksHex": [first_fragment.clone(), remaining_fragment.clone()],
            }),
            json!({
                "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
                "canonicalByteLength": canonical_bytes.len() + 1,
                "canonicalByteChunksHex": [first_fragment.clone(), remaining_fragment.clone()],
            }),
            json!({
                "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
                "canonicalByteLength": canonical_bytes.len(),
                "canonicalByteChunksHex": [first_fragment.clone(), ""],
            }),
            json!({
                "schemaIdentifier": MANIFEST_SCHEMA_IDENTIFIER,
                "canonicalByteLength": canonical_bytes.len(),
                "canonicalByteChunksHex": [first_fragment, "zz"],
            }),
        ] {
            assert!(
                validate_canonical_foundation_value(&request).is_err(),
                "malformed fragmented input must be refused"
            );
        }
    }

    #[test]
    fn foundation_validator_round_trips_every_local_storage_schema() {
        let binding = LocalStorageBinding::new(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            Hash512::from_bytes([0x33; 64]),
            ParticipantIdentity::from_bytes([0x44; 64]),
        );
        let action_randomness_commitment = Hash512::from_bytes([0x55; 64]);
        let record_identifier = Hash512::from_bytes([0x66; 64]);
        let plaintext = b"authenticated local record".to_vec();
        let associated_data = LocalRecordAssociatedData::new(
            binding,
            action_randomness_commitment,
            LocalRecordType::ProofAttempt,
            record_identifier,
            0,
            3,
            None,
            plaintext.len() as u64,
        )
        .expect("local-record associated data");
        let associated_data_bytes = associated_data.encode().expect("associated data encodes");
        let record_key_input = LocalRecordKeyInput::new(
            binding,
            action_randomness_commitment,
            LocalRecordType::ProofAttempt,
            record_identifier,
            0,
        );
        let local_record_nonce = [0x77; LOCAL_RECORD_NONCE_BYTE_LENGTH];
        let local_record_tag = [0x88; LOCAL_RECORD_TAG_BYTE_LENGTH];
        let authenticator_input = CanonicalTuple::new(
            LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
            1,
            vec![
                CanonicalItem::variable_bytes(&associated_data_bytes)
                    .expect("associated data item"),
                CanonicalItem::fixed_bytes(local_record_nonce).expect("record nonce item"),
                CanonicalItem::variable_bytes(&plaintext).expect("ciphertext item"),
                CanonicalItem::fixed_bytes(local_record_tag).expect("record tag item"),
            ],
        )
        .encode()
        .expect("authenticator input encodes");
        let local_record_envelope = LocalRecordEnvelope::new(
            associated_data,
            local_record_nonce,
            plaintext,
            local_record_tag,
            [0x99; LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH],
        )
        .expect("local-record envelope");
        let recovery_value = LocalStorageRecoveryValue::new(binding, [0xaa; 48])
            .expect("local-storage recovery value");
        let commitment_payload =
            StorageRootCommitmentPayload::new(recovery_value.storage_root_commitment());
        let device_associated_data =
            DeviceWrappingAssociatedData::new(binding, recovery_value.storage_root_commitment());
        let device_envelope = DeviceWrappedStorageRoot::new(
            device_associated_data,
            [0xbb; DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH],
            [0xcc; 48],
            [0xdd; DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH],
        );
        let canonical_values = [
            (
                DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
                device_associated_data.encode().expect("device AAD encodes"),
            ),
            (
                LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
                associated_data_bytes,
            ),
            (
                STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER,
                recovery_value.encode().expect("recovery value encodes"),
            ),
            (
                STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
                commitment_payload.encode().expect("commitment encodes"),
            ),
            (
                LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER,
                record_key_input.encode().expect("record key input encodes"),
            ),
            (
                DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
                device_envelope.encode().expect("device envelope encodes"),
            ),
            (
                LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER,
                local_record_envelope
                    .encode()
                    .expect("record envelope encodes"),
            ),
            (
                LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
                authenticator_input,
            ),
            (
                ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
                ActionStorageDerivationInput::new(binding)
                    .encode()
                    .expect("storage derivation input encodes"),
            ),
        ];

        for (schema_identifier, canonical_bytes) in canonical_values {
            let response = validate_canonical_foundation_value(&json!({
                "schemaIdentifier": schema_identifier,
                "canonicalBytesHex": encode_hex(&canonical_bytes),
            }))
            .expect("local-storage schema validates");
            assert_eq!(
                response["canonicalBytesHex"],
                Value::String(encode_hex(&canonical_bytes))
            );
        }
    }

    #[test]
    fn context_commands_bind_every_external_input() {
        let response = derive_ceremony_context_hash(&json!({
            "value": {
                "suiteId": "11".repeat(64),
                "manifestHash": "22".repeat(64),
                "rosterHash": "33".repeat(64),
                "ceremonyIdentifier": "ceremony-one",
            }
        }))
        .expect("ceremony context derives");
        let first = response["ceremonyContextHash"]
            .as_str()
            .expect("ceremony hash string");
        let changed = derive_ceremony_context_hash(&json!({
            "value": {
                "suiteId": "11".repeat(64),
                "manifestHash": "22".repeat(64),
                "rosterHash": "33".repeat(64),
                "ceremonyIdentifier": "ceremony-two",
            }
        }))
        .expect("changed ceremony context derives");
        assert_ne!(
            first,
            changed["ceremonyContextHash"]
                .as_str()
                .expect("changed ceremony hash string")
        );

        let action = derive_action_context_hash(&json!({
            "value": {
                "ceremonyContextHash": first,
                "actionIdentifier": "action-one",
                "actionDefinitionHash": "44".repeat(64),
                "boardPolicyHash": "55".repeat(64),
            }
        }))
        .expect("action context derives");
        assert_eq!(
            action["actionContextHash"]
                .as_str()
                .expect("action hash string")
                .len(),
            128
        );
    }
}
