use serde_json::{Map, Value, json};

use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{
    ActionContext, ActionDefinition, BoardPolicy, CanonicalDecodeLimits, CeremonyContext,
    FoundationSchemaError, Hash512, Manifest, OptionDefinition, ProofApplicationBinding,
    RefusalReason, Roster, StabilizedDisplayText, SuiteRecord,
};
use crate::transcript_core::{decode_hex, encode_hex};

pub(super) fn encode_foundation_manifest(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let display_title = ingress_display_text(request, "displayTitleUtf8Hex")?;
    let option_definitions = required_array(request, "optionDefinitions")?
        .iter()
        .map(|value| {
            let option = required_object(value, "option definition")?;
            OptionDefinition::new(
                required_u16(option, "optionIndex")?,
                required_string(option, "optionIdentifier")?.to_owned(),
                ingress_display_text(option, "displayLabelUtf8Hex")?,
            )
            .map_err(schema_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let manifest = Manifest::new(display_title, option_definitions).map_err(schema_error)?;
    let canonical_bytes = manifest.encode().map_err(schema_error)?;

    Ok(json!({
        "canonicalBytesHex": encode_hex(&canonical_bytes),
        "manifestHash": manifest.manifest_hash().map_err(schema_error)?.to_lowercase_hex(),
    }))
}

pub(super) fn verify_foundation_manifest(request: &Value) -> CanonicalResult<Value> {
    let canonical_bytes = required_canonical_bytes(request)?;
    let verification = (|| {
        let manifest = decode_manifest(&canonical_bytes)?;
        let manifest_hash = schema_refusal(manifest.manifest_hash())?;
        Ok(json!({ "manifestHash": manifest_hash.to_lowercase_hex() }))
    })();

    Ok(verification_response(verification))
}

pub(super) fn encode_foundation_action_definition(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let action_definition = ActionDefinition::new(
        required_u16(request, "topCount")?,
        required_u64_decimal(request, "submissionCutoffUnixMilliseconds")?,
    )
    .map_err(schema_error)?;
    let canonical_bytes = action_definition.encode().map_err(schema_error)?;

    Ok(json!({
        "canonicalBytesHex": encode_hex(&canonical_bytes),
        "actionDefinitionHash": action_definition
            .action_definition_hash()
            .map_err(schema_error)?
            .to_lowercase_hex(),
    }))
}

pub(super) fn verify_foundation_action_definition(request: &Value) -> CanonicalResult<Value> {
    let canonical_bytes = required_canonical_bytes(request)?;
    let verification = (|| {
        let action_definition = decode_action_definition(&canonical_bytes)?;
        let action_definition_hash = schema_refusal(action_definition.action_definition_hash())?;
        Ok(json!({
            "actionDefinitionHash": action_definition_hash.to_lowercase_hex(),
        }))
    })();

    Ok(verification_response(verification))
}

pub(super) fn encode_foundation_board_policy(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let board_policy =
        BoardPolicy::new(required_string(request, "boardOriginIdentifier")?.to_owned())
            .map_err(schema_error)?;
    let canonical_bytes = board_policy.encode().map_err(schema_error)?;

    Ok(json!({
        "canonicalBytesHex": encode_hex(&canonical_bytes),
        "boardPolicyHash": board_policy.board_policy_hash().map_err(schema_error)?.to_lowercase_hex(),
    }))
}

pub(super) fn verify_foundation_board_policy(request: &Value) -> CanonicalResult<Value> {
    let canonical_bytes = required_canonical_bytes(request)?;
    let verification = (|| {
        let board_policy = decode_board_policy(&canonical_bytes)?;
        let board_policy_hash = schema_refusal(board_policy.board_policy_hash())?;
        Ok(json!({ "boardPolicyHash": board_policy_hash.to_lowercase_hex() }))
    })();

    Ok(verification_response(verification))
}

pub(super) fn verify_foundation_suite_record(request: &Value) -> CanonicalResult<Value> {
    let canonical_bytes = required_canonical_bytes(request)?;
    let verification = (|| {
        let suite = decode_suite_record(&canonical_bytes)?;
        let suite_id = schema_refusal(suite.suite_id())?;
        Ok(json!({ "suiteId": suite_id.to_lowercase_hex() }))
    })();

    Ok(verification_response(verification))
}

pub(super) fn verify_foundation_ceremony_context(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let suite_bytes = decode_hex(required_string(request, "canonicalSuiteRecordBytesHex")?)?;
    let manifest_bytes = decode_hex(required_string(request, "canonicalManifestBytesHex")?)?;
    let roster_bytes = decode_hex(required_string(request, "canonicalRosterBytesHex")?)?;
    let expected_suite_id = required_hash(request, "expectedSuiteId")?;
    let ceremony_identifier = required_string(request, "ceremonyIdentifier")?.to_owned();
    let verification = (|| {
        let suite = decode_suite_record(&suite_bytes)?;
        let suite_id = schema_refusal(suite.suite_id())?;
        if suite_id != expected_suite_id {
            return Err(RefusalReason::WrongContext);
        }
        let manifest = decode_manifest(&manifest_bytes)?;
        let roster = decode_roster(&roster_bytes)?;
        let ceremony_context = schema_refusal(CeremonyContext::new(
            &suite,
            &manifest,
            &roster,
            ceremony_identifier,
        ))?;

        Ok(json!({
            "suiteId": ceremony_context.suite_id().to_lowercase_hex(),
            "manifestHash": ceremony_context.manifest_hash().to_lowercase_hex(),
            "rosterHash": ceremony_context.roster_hash().to_lowercase_hex(),
            "ceremonyContextHash": ceremony_context.context_hash().to_lowercase_hex(),
        }))
    })();

    Ok(verification_response(verification))
}

pub(super) fn verify_foundation_action_context(request: &Value) -> CanonicalResult<Value> {
    let request = required_object(request, "command request")?;
    let suite_bytes = decode_hex(required_string(request, "canonicalSuiteRecordBytesHex")?)?;
    let manifest_bytes = decode_hex(required_string(request, "canonicalManifestBytesHex")?)?;
    let roster_bytes = decode_hex(required_string(request, "canonicalRosterBytesHex")?)?;
    let action_definition_bytes = decode_hex(required_string(
        request,
        "canonicalActionDefinitionBytesHex",
    )?)?;
    let board_policy_bytes = decode_hex(required_string(request, "canonicalBoardPolicyBytesHex")?)?;
    let expected_suite_id = required_hash(request, "expectedSuiteId")?;
    let expected_ceremony_context_hash = required_hash(request, "expectedCeremonyContextHash")?;
    let ceremony_identifier = required_string(request, "ceremonyIdentifier")?.to_owned();
    let action_identifier = required_string(request, "actionIdentifier")?.to_owned();
    let verification = (|| {
        let suite = decode_suite_record(&suite_bytes)?;
        if schema_refusal(suite.suite_id())? != expected_suite_id {
            return Err(RefusalReason::WrongContext);
        }
        let manifest = decode_manifest(&manifest_bytes)?;
        let roster = decode_roster(&roster_bytes)?;
        let ceremony_context = schema_refusal(CeremonyContext::new(
            &suite,
            &manifest,
            &roster,
            ceremony_identifier,
        ))?;
        if ceremony_context.context_hash() != expected_ceremony_context_hash {
            return Err(RefusalReason::WrongContext);
        }
        let action_definition = decode_action_definition(&action_definition_bytes)?;
        let board_policy = decode_board_policy(&board_policy_bytes)?;
        let action_context = schema_refusal(ActionContext::new(
            &ceremony_context,
            action_identifier,
            action_definition,
            &board_policy,
        ))?;

        Ok(json!({
            "suiteId": action_context.suite_id().to_lowercase_hex(),
            "rosterHash": action_context.roster_hash().to_lowercase_hex(),
            "ceremonyContextHash": action_context.ceremony_context_hash().to_lowercase_hex(),
            "actionDefinitionHash": action_context.action_definition_hash().to_lowercase_hex(),
            "boardPolicyHash": action_context.board_policy_hash().to_lowercase_hex(),
            "actionContextHash": action_context.context_hash().to_lowercase_hex(),
            "submissionCutoffHash": action_context.submission_cutoff_hash().to_lowercase_hex(),
        }))
    })();

    Ok(verification_response(verification))
}

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

fn decode_manifest(canonical_bytes: &[u8]) -> Result<Manifest, RefusalReason> {
    let manifest = schema_refusal(Manifest::decode(
        canonical_bytes,
        &CanonicalDecodeLimits::default(),
    ))?;
    require_identical_round_trip(canonical_bytes, schema_refusal(manifest.encode())?)?;
    Ok(manifest)
}

fn decode_action_definition(canonical_bytes: &[u8]) -> Result<ActionDefinition, RefusalReason> {
    let action_definition = schema_refusal(ActionDefinition::decode(
        canonical_bytes,
        &CanonicalDecodeLimits::default(),
    ))?;
    require_identical_round_trip(canonical_bytes, schema_refusal(action_definition.encode())?)?;
    Ok(action_definition)
}

fn decode_board_policy(canonical_bytes: &[u8]) -> Result<BoardPolicy, RefusalReason> {
    let board_policy = schema_refusal(BoardPolicy::decode(
        canonical_bytes,
        &CanonicalDecodeLimits::default(),
    ))?;
    require_identical_round_trip(canonical_bytes, schema_refusal(board_policy.encode())?)?;
    Ok(board_policy)
}

fn decode_suite_record(canonical_bytes: &[u8]) -> Result<SuiteRecord, RefusalReason> {
    let suite = schema_refusal(SuiteRecord::decode(
        canonical_bytes,
        &CanonicalDecodeLimits::default(),
    ))?;
    require_identical_round_trip(canonical_bytes, schema_refusal(suite.encode())?)?;
    Ok(suite)
}

fn decode_roster(canonical_bytes: &[u8]) -> Result<Roster, RefusalReason> {
    let roster = schema_refusal(Roster::decode(
        canonical_bytes,
        &CanonicalDecodeLimits::default(),
    ))?;
    require_identical_round_trip(canonical_bytes, schema_refusal(roster.encode())?)?;
    Ok(roster)
}

fn require_identical_round_trip(
    canonical_bytes: &[u8],
    reencoded_bytes: Vec<u8>,
) -> Result<(), RefusalReason> {
    if canonical_bytes != reencoded_bytes {
        return Err(RefusalReason::MalformedEncoding);
    }
    Ok(())
}

fn verification_response(result: Result<Value, RefusalReason>) -> Value {
    match result {
        Ok(value) => json!({ "isValid": true, "value": value }),
        Err(refusal_reason) => json!({
            "isValid": false,
            "refusalReason": refusal_reason.name(),
        }),
    }
}

fn schema_refusal<Value>(
    result: Result<Value, FoundationSchemaError>,
) -> Result<Value, RefusalReason> {
    result.map_err(|error| error.refusal_reason)
}

fn required_canonical_bytes(request: &Value) -> CanonicalResult<Vec<u8>> {
    let request = required_object(request, "command request")?;
    decode_hex(required_string(request, "canonicalBytesHex")?)
}

fn ingress_display_text(
    object: &Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<StabilizedDisplayText> {
    let bytes = decode_hex(required_string(object, field_name)?)?;
    StabilizedDisplayText::from_ingress_utf8(&bytes).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidUtf8,
            format!("{field_name} is not accepted display text: {error}"),
        )
    })
}

fn required_object<'a>(value: &'a Value, label: &str) -> CanonicalResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_value(format!("{label} must be an object")))
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    field_name: &str,
) -> CanonicalResult<&'a Vec<Value>> {
    object
        .get(field_name)
        .ok_or_else(|| invalid_value(format!("{field_name} is required")))?
        .as_array()
        .ok_or_else(|| invalid_value(format!("{field_name} must be an array")))
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

fn required_u16(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<u16> {
    let value = object
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_value(format!("{field_name} must be an unsigned integer")))?;
    u16::try_from(value).map_err(|_| invalid_value(format!("{field_name} must fit u16")))
}

fn required_u64_decimal(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<u64> {
    required_string(object, field_name)?
        .parse::<u64>()
        .map_err(|_| {
            invalid_value(format!(
                "{field_name} must be a canonical u64 decimal string"
            ))
        })
}

fn required_hash(object: &Map<String, Value>, field_name: &str) -> CanonicalResult<Hash512> {
    let bytes = decode_hex(required_string(object, field_name)?)?;
    let hash_bytes: [u8; Hash512::BYTE_LENGTH] = bytes
        .try_into()
        .map_err(|_| invalid_value(format!("{field_name} must be a 512-bit hash")))?;
    Ok(Hash512::from_bytes(hash_bytes))
}

fn schema_error(error: FoundationSchemaError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, error.to_string())
}

fn invalid_value(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
