use core::str;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::{
    CanonicalCodecRefusal, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
};

/// A foundation value whose tuple does not have its schema's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationSchemaRefusal;

impl From<CanonicalCodecRefusal> for FoundationSchemaRefusal {
    fn from(_: CanonicalCodecRefusal) -> Self {
        Self
    }
}

pub(super) type SchemaResult<Value> = Result<Value, FoundationSchemaRefusal>;

pub(super) fn require_header(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> SchemaResult<()> {
    if tuple.schema_identifier != schema_identifier {
        return Err(FoundationSchemaRefusal);
    }
    if tuple.items.len() != item_count {
        return Err(FoundationSchemaRefusal);
    }
    Ok(())
}

pub(super) fn read_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaRefusal);
    }
    Ok(item.canonical_bytes())
}

pub(super) fn read_variable_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaRefusal);
    }
    item.variable_value_bytes().map_err(Into::into)
}

pub(super) fn read_u16(item: &CanonicalItem) -> SchemaResult<u16> {
    let bytes: [u8; 2] = read_item(item, CanonicalItemType::Unsigned16)?
        .try_into()
        .map_err(|_| FoundationSchemaRefusal)?;
    Ok(u16::from_le_bytes(bytes))
}

pub(super) fn read_ascii(item: &CanonicalItem) -> SchemaResult<&str> {
    str::from_utf8(read_variable_item(item, CanonicalItemType::Ascii)?)
        .map_err(|_| FoundationSchemaRefusal)
}

fn read_nested_tuple_list_header(item: &CanonicalItem) -> SchemaResult<(usize, &[u8])> {
    let bytes = read_item(item, CanonicalItemType::HomogeneousList)?;
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]])
            != CanonicalItemType::NestedTuple.canonical_code()
    {
        return Err(FoundationSchemaRefusal);
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
        return Err(FoundationSchemaRefusal);
    }
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let (tuple, consumed) = CanonicalTuple::decode_prefix(&bytes[offset..], limits, budget, 1)?;
        offset = offset
            .checked_add(consumed)
            .ok_or(FoundationSchemaRefusal)?;
        tuples.push(tuple);
    }
    if offset != bytes.len() {
        return Err(FoundationSchemaRefusal);
    }
    Ok(tuples)
}
