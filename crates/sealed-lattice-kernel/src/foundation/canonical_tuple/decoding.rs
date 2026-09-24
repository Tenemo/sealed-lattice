use super::super::StabilizedDisplayText;
use super::value::{CanonicalItem, CanonicalItemType, CanonicalTuple, decode_variable_value};
use super::{
    ABSOLUTE_MAXIMUM_NESTING_DEPTH, CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH,
    CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeBudget, CanonicalDecodeLimits,
};

pub(super) fn decode_tuple_at(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
    nesting_depth: u16,
    base_offset: usize,
) -> Result<(CanonicalTuple, usize), CanonicalCodecError> {
    if nesting_depth > limits.maximum_nesting_depth
        || nesting_depth > ABSOLUTE_MAXIMUM_NESTING_DEPTH
    {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::LimitExceeded,
            base_offset,
            "tuple nesting depth exceeds the configured limit",
        ));
    }
    if bytes.len() > limits.maximum_tuple_byte_length {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::LimitExceeded,
            base_offset,
            "tuple byte length exceeds the configured limit",
        ));
    }
    if bytes.len() < 8 {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::Truncated,
            base_offset + bytes.len(),
            "tuple header is truncated",
        ));
    }
    let schema_identifier = u16::from_le_bytes([bytes[0], bytes[1]]);
    let schema_version = u16::from_le_bytes([bytes[2], bytes[3]]);
    let item_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if item_count > limits.maximum_item_count {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::LimitExceeded,
            base_offset + 4,
            "tuple item count exceeds the configured limit",
        ));
    }
    let minimum_length = item_count
        .checked_mul(6)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                base_offset + 4,
                "tuple item headers overflow the address space",
            )
        })?;
    if minimum_length > bytes.len() {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::Truncated,
            base_offset + bytes.len(),
            "tuple cannot contain its declared item headers",
        ));
    }
    budget.charge_work(minimum_length, base_offset)?;
    let item_allocation_byte_length = item_count
        .checked_mul(CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH)
        .ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                base_offset + 4,
                "tuple item allocation accounting overflows the address space",
            )
        })?;
    budget.charge_allocation(item_allocation_byte_length, base_offset + 4)?;

    let mut items = Vec::with_capacity(item_count);
    let mut offset = 8usize;
    for _ in 0..item_count {
        let header_end = offset.checked_add(6).ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                base_offset + offset,
                "tuple item header offset overflows",
            )
        })?;
        if header_end > bytes.len() {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                base_offset + offset,
                "tuple item header is truncated",
            ));
        }
        let item_type_code = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let item_type =
            CanonicalItemType::from_canonical_code(item_type_code).ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::UnknownItemType,
                    base_offset + offset,
                    "tuple item type is unassigned",
                )
            })?;
        let byte_length = u32::from_le_bytes([
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        ]) as usize;
        if byte_length > limits.maximum_item_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                base_offset + offset + 2,
                "tuple item byte length exceeds the configured limit",
            ));
        }
        let value_start = header_end;
        let value_end = value_start.checked_add(byte_length).ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                base_offset + offset + 2,
                "tuple item end offset overflows",
            )
        })?;
        if value_end > bytes.len() {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                base_offset + value_start,
                "tuple item is truncated",
            ));
        }
        let borrowed_canonical_bytes = &bytes[value_start..value_end];
        validate_item_bytes(
            item_type,
            borrowed_canonical_bytes,
            limits,
            budget,
            nesting_depth,
            base_offset + value_start,
        )?;
        budget.charge_allocation(borrowed_canonical_bytes.len(), base_offset + value_start)?;
        let canonical_bytes = borrowed_canonical_bytes.to_vec();
        items.push(CanonicalItem {
            item_type,
            canonical_bytes,
        });
        offset = value_end;
    }
    Ok((
        CanonicalTuple {
            schema_identifier,
            schema_version,
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
    base_offset: usize,
) -> Result<(), CanonicalCodecError> {
    if nesting_depth > limits.maximum_nesting_depth
        || nesting_depth > ABSOLUTE_MAXIMUM_NESTING_DEPTH
    {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::LimitExceeded,
            base_offset,
            "item nesting depth exceeds the configured limit",
        ));
    }
    budget.charge_work(bytes.len(), base_offset)?;
    let expected_length = match item_type {
        CanonicalItemType::Unsigned16 => Some(2),
        CanonicalItemType::Unsigned64 => Some(8),
        CanonicalItemType::Hash512 => Some(64),
        _ => None,
    };
    if let Some(expected_length) = expected_length
        && bytes.len() != expected_length
    {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::InvalidItem,
            base_offset,
            "tuple item has the wrong fixed byte length",
        ));
    }
    match item_type {
        CanonicalItemType::Ascii => {
            let value = decode_variable_value(bytes, base_offset)?;
            if value.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::InvalidItem,
                    base_offset,
                    "ASCII item contains a non-printable byte",
                ));
            }
        }
        CanonicalItemType::DisplayText => {
            let value = decode_variable_value(bytes, base_offset)?;
            budget.charge_allocation(value.len(), base_offset + 4)?;
            StabilizedDisplayText::from_canonical_utf8(value).map_err(|_| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::InvalidItem,
                    base_offset,
                    "display-text item is not canonical Unicode 17 stabilized NFC",
                )
            })?;
        }
        CanonicalItemType::NestedTuple => {
            let (_, consumed) = decode_tuple_at(
                bytes,
                limits,
                budget,
                nesting_depth.checked_add(1).ok_or_else(|| {
                    CanonicalCodecError::new(
                        CanonicalCodecErrorKind::LengthOverflow,
                        base_offset,
                        "tuple nesting depth overflows",
                    )
                })?,
                base_offset,
            )?;
            if consumed != bytes.len() {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::TrailingBytes,
                    base_offset + consumed,
                    "nested tuple contains trailing bytes",
                ));
            }
        }
        CanonicalItemType::HomogeneousList => {
            if bytes.len() < 6 {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::Truncated,
                    base_offset + bytes.len(),
                    "homogeneous-list header is truncated",
                ));
            }
            let element_type_code = u16::from_le_bytes([bytes[0], bytes[1]]);
            let element_type = CanonicalItemType::from_canonical_code(element_type_code)
                .ok_or_else(|| {
                    CanonicalCodecError::new(
                        CanonicalCodecErrorKind::UnknownItemType,
                        base_offset,
                        "homogeneous-list element type is unassigned",
                    )
                })?;
            let count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
            if count > limits.maximum_item_count {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LimitExceeded,
                    base_offset + 2,
                    "homogeneous-list count exceeds the configured limit",
                ));
            }
            validate_list_payload(
                element_type,
                count,
                &bytes[6..],
                limits,
                budget,
                nesting_depth,
                base_offset + 6,
            )?;
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn validate_list_payload(
    element_type: CanonicalItemType,
    count: usize,
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
    nesting_depth: u16,
    base_offset: usize,
) -> Result<(), CanonicalCodecError> {
    if element_type != CanonicalItemType::NestedTuple {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::InvalidItem,
            base_offset,
            "foundation homogeneous lists contain only nested tuples",
        ));
    }
    let next_depth = nesting_depth.checked_add(1).ok_or_else(|| {
        CanonicalCodecError::new(
            CanonicalCodecErrorKind::LengthOverflow,
            base_offset,
            "tuple nesting depth overflows",
        )
    })?;
    let mut offset = 0usize;
    for _ in 0..count {
        let (_, consumed) = decode_tuple_at(
            &bytes[offset..],
            limits,
            budget,
            next_depth,
            base_offset + offset,
        )?;
        offset = offset.checked_add(consumed).ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                base_offset,
                "homogeneous-list offset overflows",
            )
        })?;
    }
    if offset != bytes.len() {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::TrailingBytes,
            base_offset + offset,
            "homogeneous-list contains trailing bytes",
        ));
    }
    Ok(())
}
