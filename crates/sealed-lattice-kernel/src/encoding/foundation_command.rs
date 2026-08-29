use super::{BinaryReader, BinaryWriter, CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{
    ActionContext, ActionDefinition, BoardPolicy, CanonicalDecodeLimits, CeremonyContext,
    FoundationSchemaError, Hash512, Manifest, OptionDefinition, RefusalReason, Roster,
    StabilizedDisplayText,
};

const ENCODE_MANIFEST: u8 = 1;
const VERIFY_MANIFEST: u8 = 2;
const ENCODE_ACTION_DEFINITION: u8 = 3;
const VERIFY_ACTION_DEFINITION: u8 = 4;
const ENCODE_BOARD_POLICY: u8 = 5;
const VERIFY_BOARD_POLICY: u8 = 6;
const VERIFY_CEREMONY_CONTEXT: u8 = 7;
const VERIFY_ACTION_CONTEXT: u8 = 8;

pub(super) fn run(input: &[u8]) -> CanonicalResult<Vec<u8>> {
    let mut reader = BinaryReader::new(input);
    let payload = match reader.read_u8()? {
        ENCODE_MANIFEST => encode_manifest(&mut reader),
        VERIFY_MANIFEST => verify_manifest(&mut reader),
        ENCODE_ACTION_DEFINITION => encode_action_definition(&mut reader),
        VERIFY_ACTION_DEFINITION => verify_action_definition(&mut reader),
        ENCODE_BOARD_POLICY => encode_board_policy(&mut reader),
        VERIFY_BOARD_POLICY => verify_board_policy(&mut reader),
        VERIFY_CEREMONY_CONTEXT => verify_ceremony_context(&mut reader),
        VERIFY_ACTION_CONTEXT => verify_action_context(&mut reader),
        command => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            format!("unsupported foundation command: {command}"),
        )),
    }?;
    reader.finish()?;
    Ok(payload)
}

fn encode_manifest(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let display_title = ingress_display_text(reader.read_bytes()?, "display title")?;
    let option_count = reader.read_u16()?;
    let mut option_definitions = Vec::with_capacity(usize::from(option_count.min(20)));
    for _ in 0..option_count {
        let option_index = reader.read_u16()?;
        let option_identifier = reader.read_string()?.to_owned();
        let display_label = ingress_display_text(reader.read_bytes()?, "display label")?;
        option_definitions.push(
            OptionDefinition::new(option_index, option_identifier, display_label)
                .map_err(schema_error)?,
        );
    }
    let manifest = Manifest::new(display_title, option_definitions).map_err(schema_error)?;
    let canonical_bytes = manifest.encode().map_err(schema_error)?;
    let manifest_hash = manifest.manifest_hash().map_err(schema_error)?;

    let mut response = BinaryWriter::new();
    response.write_bytes(&canonical_bytes)?;
    response.write_fixed(manifest_hash.as_bytes())?;
    Ok(response.into_bytes())
}

fn verify_manifest(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let canonical_bytes = reader.read_bytes()?;
    let verification = (|| {
        let manifest = decode_manifest(canonical_bytes)?;
        schema_refusal(manifest.manifest_hash())
    })();

    verification_response(verification, |manifest_hash, response| {
        response.write_fixed(manifest_hash.as_bytes())
    })
}

fn encode_action_definition(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let top_count = reader.read_u16()?;
    let submission_cutoff_unix_milliseconds = reader.read_u64()?;
    let action_definition = ActionDefinition::new(top_count, submission_cutoff_unix_milliseconds)
        .map_err(schema_error)?;
    let canonical_bytes = action_definition.encode().map_err(schema_error)?;
    let action_definition_hash = action_definition
        .action_definition_hash()
        .map_err(schema_error)?;

    let mut response = BinaryWriter::new();
    response.write_bytes(&canonical_bytes)?;
    response.write_fixed(action_definition_hash.as_bytes())?;
    Ok(response.into_bytes())
}

fn verify_action_definition(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let canonical_bytes = reader.read_bytes()?;
    let verification = (|| {
        let action_definition = decode_action_definition(canonical_bytes)?;
        schema_refusal(action_definition.action_definition_hash())
    })();

    verification_response(verification, |action_definition_hash, response| {
        response.write_fixed(action_definition_hash.as_bytes())
    })
}

fn encode_board_policy(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let board_policy = BoardPolicy::new(reader.read_string()?.to_owned()).map_err(schema_error)?;
    let canonical_bytes = board_policy.encode().map_err(schema_error)?;
    let board_policy_hash = board_policy.board_policy_hash().map_err(schema_error)?;

    let mut response = BinaryWriter::new();
    response.write_bytes(&canonical_bytes)?;
    response.write_fixed(board_policy_hash.as_bytes())?;
    Ok(response.into_bytes())
}

fn verify_board_policy(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let canonical_bytes = reader.read_bytes()?;
    let verification = (|| {
        let board_policy = decode_board_policy(canonical_bytes)?;
        schema_refusal(board_policy.board_policy_hash())
    })();

    verification_response(verification, |board_policy_hash, response| {
        response.write_fixed(board_policy_hash.as_bytes())
    })
}

fn verify_ceremony_context(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let manifest_bytes = reader.read_bytes()?;
    let roster_bytes = reader.read_bytes()?;
    let ceremony_identifier = reader.read_string()?.to_owned();
    let expected_suite_id = read_hash(reader)?;
    let verification = (|| {
        let manifest = decode_manifest(manifest_bytes)?;
        let roster = decode_roster(roster_bytes)?;
        schema_refusal(CeremonyContext::new(
            expected_suite_id,
            &manifest,
            &roster,
            ceremony_identifier,
        ))
    })();

    verification_response(verification, |context, response| {
        response.write_fixed(context.suite_id().as_bytes())?;
        response.write_fixed(context.manifest_hash().as_bytes())?;
        response.write_fixed(context.roster_hash().as_bytes())?;
        response.write_fixed(context.context_hash().as_bytes())
    })
}

fn verify_action_context(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let manifest_bytes = reader.read_bytes()?;
    let roster_bytes = reader.read_bytes()?;
    let action_definition_bytes = reader.read_bytes()?;
    let board_policy_bytes = reader.read_bytes()?;
    let ceremony_identifier = reader.read_string()?.to_owned();
    let action_identifier = reader.read_string()?.to_owned();
    let expected_suite_id = read_hash(reader)?;
    let expected_ceremony_context_hash = read_hash(reader)?;
    let verification = (|| {
        let manifest = decode_manifest(manifest_bytes)?;
        let roster = decode_roster(roster_bytes)?;
        let ceremony_context = schema_refusal(CeremonyContext::new(
            expected_suite_id,
            &manifest,
            &roster,
            ceremony_identifier,
        ))?;
        if ceremony_context.context_hash() != expected_ceremony_context_hash {
            return Err(RefusalReason::WrongContext);
        }
        let action_definition = decode_action_definition(action_definition_bytes)?;
        let board_policy = decode_board_policy(board_policy_bytes)?;
        schema_refusal(ActionContext::new(
            &ceremony_context,
            action_identifier,
            action_definition,
            &board_policy,
        ))
    })();

    verification_response(verification, |context, response| {
        response.write_fixed(context.suite_id().as_bytes())?;
        response.write_fixed(context.roster_hash().as_bytes())?;
        response.write_fixed(context.ceremony_context_hash().as_bytes())?;
        response.write_fixed(context.action_definition_hash().as_bytes())?;
        response.write_fixed(context.board_policy_hash().as_bytes())?;
        response.write_fixed(context.context_hash().as_bytes())?;
        response.write_fixed(context.submission_cutoff_hash().as_bytes())
    })
}

fn verification_response<Value>(
    result: Result<Value, RefusalReason>,
    encode_value: impl FnOnce(Value, &mut BinaryWriter) -> CanonicalResult<()>,
) -> CanonicalResult<Vec<u8>> {
    let mut response = BinaryWriter::new();
    match result {
        Ok(value) => {
            response.write_u8(1)?;
            encode_value(value, &mut response)?;
        }
        Err(refusal_reason) => {
            response.write_u8(0)?;
            response.write_string(refusal_reason.name())?;
        }
    }
    Ok(response.into_bytes())
}

fn read_hash(reader: &mut BinaryReader<'_>) -> CanonicalResult<Hash512> {
    let bytes: [u8; Hash512::BYTE_LENGTH] = reader
        .read_exact(Hash512::BYTE_LENGTH)?
        .try_into()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "hash must contain 64 bytes",
            )
        })?;
    Ok(Hash512::from_bytes(bytes))
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

fn ingress_display_text(bytes: &[u8], field_name: &str) -> CanonicalResult<StabilizedDisplayText> {
    StabilizedDisplayText::from_ingress_utf8(bytes).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidUtf8,
            format!("{field_name} is not accepted display text: {error}"),
        )
    })
}

fn schema_refusal<Value>(
    result: Result<Value, FoundationSchemaError>,
) -> Result<Value, RefusalReason> {
    result.map_err(|error| error.refusal_reason)
}

fn schema_error(error: FoundationSchemaError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, error.to_string())
}
