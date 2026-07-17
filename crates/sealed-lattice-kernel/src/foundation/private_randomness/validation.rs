use super::super::schemas::{SchemaResult, read_item};
use super::super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    ParticipantIdentity, RefusalReason,
};
use super::{PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH, schema_error};

pub(super) fn require_protocol_version(protocol_version: u16) -> SchemaResult<()> {
    if protocol_version != FOUNDATION_PROFILE.protocol_version {
        return Err(schema_error(
            RefusalReason::UnsupportedVersionOrSuite,
            "private-randomness input uses an unsupported protocol version",
        ));
    }
    Ok(())
}

pub(super) fn validate_cursor_offset(next_counter: u64, offset: Option<u16>) -> SchemaResult<()> {
    if let Some(offset) = offset
        && (next_counter == 0 || offset >= PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH)
    {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "private-randomness cursor buffered offset is inconsistent",
        ));
    }
    Ok(())
}

pub(super) fn read_participant_identity(item: &CanonicalItem) -> SchemaResult<ParticipantIdentity> {
    let bytes: [u8; ParticipantIdentity::BYTE_LENGTH] =
        read_item(item, CanonicalItemType::ParticipantIdentity)?
            .try_into()
            .map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "participant identity has the wrong length",
                )
            })?;
    Ok(ParticipantIdentity::from_bytes(bytes))
}

pub(super) fn read_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<CanonicalTuple> {
    Ok(CanonicalTuple::decode(
        read_item(item, CanonicalItemType::NestedTuple)?,
        limits,
    )?)
}

pub(super) fn read_optional_u16(item: &CanonicalItem) -> SchemaResult<Option<u16>> {
    Ok(
        read_optional_unsigned(item, CanonicalItemType::Unsigned16, 2)?
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])),
    )
}

pub(super) fn read_optional_u32(item: &CanonicalItem) -> SchemaResult<Option<u32>> {
    Ok(
        read_optional_unsigned(item, CanonicalItemType::Unsigned32, 4)?
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
    )
}

pub(super) fn read_optional_u64(item: &CanonicalItem) -> SchemaResult<Option<u64>> {
    Ok(
        read_optional_unsigned(item, CanonicalItemType::Unsigned64, 8)?.map(|bytes| {
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        }),
    )
}

fn read_optional_unsigned(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    expected_byte_length: usize,
) -> SchemaResult<Option<&[u8]>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_type.canonical_code()
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "optional private-randomness coordinate has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 3 + expected_byte_length => Ok(Some(&bytes[3..])),
        _ => Err(schema_error(
            RefusalReason::MalformedEncoding,
            "optional private-randomness coordinate is malformed",
        )),
    }
}
