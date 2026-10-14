use super::super::StabilizedDisplayText;
use super::value::{CanonicalItem, CanonicalItemType, CanonicalTuple, decode_variable_value};
use super::{
    ABSOLUTE_MAXIMUM_NESTING_DEPTH, CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH,
    CanonicalCodecRefusal, CanonicalDecodeBudget, CanonicalDecodeLimits,
};

pub(super) fn decode_tuple_at(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
    nesting_depth: u16,
) -> Result<(CanonicalTuple, usize), CanonicalCodecRefusal> {
    if nesting_depth > limits.maximum_nesting_depth
        || nesting_depth > ABSOLUTE_MAXIMUM_NESTING_DEPTH
        || bytes.len() > limits.maximum_tuple_byte_length
        || bytes.len() < 6
    {
        return Err(CanonicalCodecRefusal);
    }
    let schema_identifier = u16::from_le_bytes([bytes[0], bytes[1]]);
    let item_count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if item_count > limits.maximum_item_count {
        return Err(CanonicalCodecRefusal);
    }
    // The declared item headers must fit before any is read.
    let minimum_length = item_count
        .checked_mul(6)
        .and_then(|value| value.checked_add(6))
        .ok_or(CanonicalCodecRefusal)?;
    if minimum_length > bytes.len() {
        return Err(CanonicalCodecRefusal);
    }
    budget.charge_work(minimum_length)?;
    budget.charge_allocation(
        item_count
            .checked_mul(CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH)
            .ok_or(CanonicalCodecRefusal)?,
    )?;

    let mut items = Vec::with_capacity(item_count);
    let mut offset = 6usize;
    for _ in 0..item_count {
        let header_end = offset.checked_add(6).ok_or(CanonicalCodecRefusal)?;
        if header_end > bytes.len() {
            return Err(CanonicalCodecRefusal);
        }
        let item_type = CanonicalItemType::from_canonical_code(u16::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
        ]))
        .ok_or(CanonicalCodecRefusal)?;
        let byte_length = u32::from_le_bytes([
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        ]) as usize;
        if byte_length > limits.maximum_item_byte_length {
            return Err(CanonicalCodecRefusal);
        }
        let value_end = header_end
            .checked_add(byte_length)
            .ok_or(CanonicalCodecRefusal)?;
        if value_end > bytes.len() {
            return Err(CanonicalCodecRefusal);
        }
        let borrowed_canonical_bytes = &bytes[header_end..value_end];
        validate_item_bytes(
            item_type,
            borrowed_canonical_bytes,
            limits,
            budget,
            nesting_depth,
        )?;
        budget.charge_allocation(borrowed_canonical_bytes.len())?;
        items.push(CanonicalItem {
            item_type,
            canonical_bytes: borrowed_canonical_bytes.to_vec(),
        });
        offset = value_end;
    }
    Ok((
        CanonicalTuple {
            schema_identifier,
            items,
        },
        offset,
    ))
}

pub(in crate::foundation) fn validate_item_bytes(
    item_type: CanonicalItemType,
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
    nesting_depth: u16,
) -> Result<(), CanonicalCodecRefusal> {
    if nesting_depth > limits.maximum_nesting_depth
        || nesting_depth > ABSOLUTE_MAXIMUM_NESTING_DEPTH
    {
        return Err(CanonicalCodecRefusal);
    }
    budget.charge_work(bytes.len())?;
    let expected_length = match item_type {
        CanonicalItemType::Unsigned16 => Some(2),
        CanonicalItemType::Unsigned64 => Some(8),
        CanonicalItemType::Hash512 => Some(64),
        _ => None,
    };
    if let Some(expected_length) = expected_length
        && bytes.len() != expected_length
    {
        return Err(CanonicalCodecRefusal);
    }
    match item_type {
        CanonicalItemType::Ascii => {
            let value = decode_variable_value(bytes)?;
            if value.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
                return Err(CanonicalCodecRefusal);
            }
        }
        CanonicalItemType::DisplayText => {
            let value = decode_variable_value(bytes)?;
            budget.charge_allocation(value.len())?;
            StabilizedDisplayText::from_canonical_utf8(value).map_err(|_| CanonicalCodecRefusal)?;
        }
        CanonicalItemType::NestedTuple => {
            let (_, consumed) = decode_tuple_at(
                bytes,
                limits,
                budget,
                nesting_depth.checked_add(1).ok_or(CanonicalCodecRefusal)?,
            )?;
            if consumed != bytes.len() {
                return Err(CanonicalCodecRefusal);
            }
        }
        CanonicalItemType::HomogeneousList => {
            if bytes.len() < 6 {
                return Err(CanonicalCodecRefusal);
            }
            let element_type =
                CanonicalItemType::from_canonical_code(u16::from_le_bytes([bytes[0], bytes[1]]))
                    .ok_or(CanonicalCodecRefusal)?;
            let count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
            if count > limits.maximum_item_count {
                return Err(CanonicalCodecRefusal);
            }
            validate_list_payload(
                element_type,
                count,
                &bytes[6..],
                limits,
                budget,
                nesting_depth,
            )?;
        }
        _ => {}
    }
    Ok(())
}

/// A homogeneous list holds exactly its count of hashes or of nested tuples.
pub(super) fn validate_list_payload(
    element_type: CanonicalItemType,
    count: usize,
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
    nesting_depth: u16,
) -> Result<(), CanonicalCodecRefusal> {
    if element_type == CanonicalItemType::Hash512 {
        return if count.checked_mul(64) == Some(bytes.len()) {
            Ok(())
        } else {
            Err(CanonicalCodecRefusal)
        };
    }
    if element_type != CanonicalItemType::NestedTuple {
        return Err(CanonicalCodecRefusal);
    }
    let next_depth = nesting_depth.checked_add(1).ok_or(CanonicalCodecRefusal)?;
    let mut offset = 0usize;
    for _ in 0..count {
        let (_, consumed) = decode_tuple_at(&bytes[offset..], limits, budget, next_depth)?;
        offset = offset.checked_add(consumed).ok_or(CanonicalCodecRefusal)?;
    }
    if offset != bytes.len() {
        return Err(CanonicalCodecRefusal);
    }
    Ok(())
}
