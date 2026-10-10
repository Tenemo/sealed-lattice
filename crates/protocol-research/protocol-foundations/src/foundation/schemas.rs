use core::{fmt, str};

use super::canonical_tuple::CanonicalDecodeBudget;
use super::{
    CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    RefusalReason,
};

pub(super) const FOUNDATION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundationSchemaError {
    pub refusal_reason: RefusalReason,
    pub message: &'static str,
}

impl FoundationSchemaError {
    pub(super) const fn new(refusal_reason: RefusalReason, message: &'static str) -> Self {
        Self {
            refusal_reason,
            message,
        }
    }
}

impl fmt::Display for FoundationSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for FoundationSchemaError {}

impl From<CanonicalCodecError> for FoundationSchemaError {
    fn from(error: CanonicalCodecError) -> Self {
        let refusal_reason = if error.kind == super::CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        };
        Self::new(refusal_reason, "foundation value is not canonical")
    }
}

pub(super) type SchemaResult<Value> = Result<Value, FoundationSchemaError>;

pub(super) fn require_header(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> SchemaResult<()> {
    if tuple.schema_identifier != schema_identifier {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple has the wrong schema",
        ));
    }
    if tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(FoundationSchemaError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "foundation tuple schema version is unsupported",
        ));
    }
    if tuple.items.len() != item_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple has the wrong item count",
        ));
    }
    Ok(())
}

pub(super) fn read_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple item has the wrong semantic type",
        ));
    }
    Ok(item.canonical_bytes())
}

pub(super) fn read_variable_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple item has the wrong semantic type",
        ));
    }
    item.variable_value_bytes().map_err(Into::into)
}

pub(super) fn read_u16(item: &CanonicalItem) -> SchemaResult<u16> {
    let bytes: [u8; 2] = read_item(item, CanonicalItemType::Unsigned16)?
        .try_into()
        .map_err(|_| FoundationSchemaError::new(RefusalReason::MalformedEncoding, "u16 length"))?;
    Ok(u16::from_le_bytes(bytes))
}

pub(super) fn read_ascii(item: &CanonicalItem) -> SchemaResult<&str> {
    str::from_utf8(read_variable_item(item, CanonicalItemType::Ascii)?).map_err(|_| {
        FoundationSchemaError::new(RefusalReason::MalformedEncoding, "ASCII item is invalid")
    })
}

fn read_nested_tuple_list_header(item: &CanonicalItem) -> SchemaResult<(usize, &[u8])> {
    let bytes = read_item(item, CanonicalItemType::HomogeneousList)?;
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]])
            != CanonicalItemType::NestedTuple.canonical_code()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "homogeneous list has the wrong element type",
        ));
    }
    Ok((
        u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize,
        &bytes[6..],
    ))
}

pub(super) fn read_nested_tuple_list_with_budget(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
) -> SchemaResult<Vec<CanonicalTuple>> {
    let (count, bytes) = read_nested_tuple_list_header(item)?;
    if count > limits.maximum_item_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "nested tuple list exceeds the configured count limit",
        ));
    }
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let (tuple, consumed) = CanonicalTuple::decode_prefix(&bytes[offset..], limits, budget, 1)?;
        offset = offset.checked_add(consumed).ok_or_else(|| {
            FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "nested tuple list offset overflows",
            )
        })?;
        tuples.push(tuple);
    }
    if offset != bytes.len() {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "nested tuple list contains trailing bytes",
        ));
    }
    Ok(tuples)
}
