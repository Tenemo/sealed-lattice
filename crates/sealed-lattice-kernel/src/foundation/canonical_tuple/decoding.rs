use super::super::StabilizedDisplayText;
use super::value::{CanonicalItem, CanonicalItemType, CanonicalTuple, decode_variable_value};
use super::{
    ABSOLUTE_MAXIMUM_NESTING_DEPTH, CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH,
    CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeBudget, CanonicalDecodeLimits,
};

#[derive(Debug)]
struct IncrementalCanonicalItem {
    item_type: CanonicalItemType,
    value_start_offset: usize,
    canonical_bytes: Vec<u8>,
    expected_byte_length: usize,
}

/// Decodes one canonical tuple from ordered byte fragments without retaining a
/// second whole-tuple input buffer.
///
/// Item headers and item payloads are validated as soon as they become
/// complete. The enclosing schema can then consume the returned tuple without
/// depending on JavaScript concatenation or a native file-backed reader.
#[derive(Debug)]
pub struct IncrementalCanonicalTupleDecoder {
    limits: CanonicalDecodeLimits,
    budget: CanonicalDecodeBudget,
    expected_byte_length: usize,
    absorbed_byte_length: usize,
    header_bytes: [u8; 8],
    header_byte_length: usize,
    schema_identifier: Option<u16>,
    schema_version: Option<u16>,
    declared_item_count: Option<usize>,
    item_header_bytes: [u8; 6],
    item_header_byte_length: usize,
    current_item: Option<IncrementalCanonicalItem>,
    items: Vec<CanonicalItem>,
    failure: Option<CanonicalCodecError>,
}

impl IncrementalCanonicalTupleDecoder {
    pub fn new(
        expected_byte_length: usize,
        limits: &CanonicalDecodeLimits,
    ) -> Result<Self, CanonicalCodecError> {
        if expected_byte_length > limits.maximum_tuple_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "tuple byte length exceeds the configured limit",
            ));
        }
        if expected_byte_length < 8 {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                expected_byte_length,
                "tuple header is truncated",
            ));
        }
        Ok(Self {
            limits: *limits,
            budget: CanonicalDecodeBudget::new(limits),
            expected_byte_length,
            absorbed_byte_length: 0,
            header_bytes: [0; 8],
            header_byte_length: 0,
            schema_identifier: None,
            schema_version: None,
            declared_item_count: None,
            item_header_bytes: [0; 6],
            item_header_byte_length: 0,
            current_item: None,
            items: Vec::new(),
            failure: None,
        })
    }

    pub fn absorb(&mut self, bytes: &[u8]) -> Result<(), CanonicalCodecError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let result = self.absorb_inner(bytes);
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }

    pub fn finish(self) -> Result<CanonicalTuple, CanonicalCodecError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.absorbed_byte_length != self.expected_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                self.absorbed_byte_length,
                "tuple stream ended before its declared byte length",
            ));
        }
        if self.header_byte_length != self.header_bytes.len() {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                self.absorbed_byte_length,
                "tuple header is truncated",
            ));
        }
        let declared_item_count = self.declared_item_count.ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                self.absorbed_byte_length,
                "tuple header is incomplete",
            )
        })?;
        if self.items.len() != declared_item_count {
            let (byte_offset, message) = if let Some(item) = &self.current_item {
                (item.value_start_offset, "tuple item is truncated")
            } else {
                (
                    self.absorbed_byte_length
                        .saturating_sub(self.item_header_byte_length),
                    "tuple item header is truncated",
                )
            };
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                byte_offset,
                message,
            ));
        }
        Ok(CanonicalTuple {
            schema_identifier: self.schema_identifier.ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::Truncated,
                    0,
                    "tuple schema identifier is missing",
                )
            })?,
            schema_version: self.schema_version.ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::Truncated,
                    2,
                    "tuple schema version is missing",
                )
            })?,
            items: self.items,
        })
    }

    fn absorb_inner(&mut self, bytes: &[u8]) -> Result<(), CanonicalCodecError> {
        let resulting_byte_length = self
            .absorbed_byte_length
            .checked_add(bytes.len())
            .ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    self.absorbed_byte_length,
                    "tuple stream byte length overflows",
                )
            })?;
        if resulting_byte_length > self.expected_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::TrailingBytes,
                self.expected_byte_length,
                "tuple stream contains trailing bytes",
            ));
        }

        let mut chunk_offset = 0usize;
        while chunk_offset < bytes.len() {
            if self.header_byte_length < self.header_bytes.len() {
                let copied_byte_length = (self.header_bytes.len() - self.header_byte_length)
                    .min(bytes.len() - chunk_offset);
                let destination_end = self.header_byte_length + copied_byte_length;
                let source_end = chunk_offset + copied_byte_length;
                self.header_bytes[self.header_byte_length..destination_end]
                    .copy_from_slice(&bytes[chunk_offset..source_end]);
                self.header_byte_length = destination_end;
                chunk_offset = source_end;
                if self.header_byte_length == self.header_bytes.len() {
                    self.initialize_tuple_header()?;
                }
                continue;
            }

            let declared_item_count = self.declared_item_count.ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::InvalidItem,
                    4,
                    "tuple item count was not initialized",
                )
            })?;
            if self.items.len() == declared_item_count && self.current_item.is_none() {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::TrailingBytes,
                    self.absorbed_byte_length + chunk_offset,
                    "tuple contains trailing bytes",
                ));
            }

            if self.current_item.is_none() {
                let copied_byte_length = (self.item_header_bytes.len()
                    - self.item_header_byte_length)
                    .min(bytes.len() - chunk_offset);
                let destination_end = self.item_header_byte_length + copied_byte_length;
                let source_end = chunk_offset + copied_byte_length;
                self.item_header_bytes[self.item_header_byte_length..destination_end]
                    .copy_from_slice(&bytes[chunk_offset..source_end]);
                self.item_header_byte_length = destination_end;
                chunk_offset = source_end;
                if self.item_header_byte_length == self.item_header_bytes.len() {
                    let item_value_start_offset = self.absorbed_byte_length + chunk_offset;
                    self.initialize_item(item_value_start_offset)?;
                    if self
                        .current_item
                        .as_ref()
                        .is_some_and(|item| item.expected_byte_length == 0)
                    {
                        self.finish_current_item()?;
                    }
                }
                continue;
            }

            let current_item = self.current_item.as_mut().ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::InvalidItem,
                    self.absorbed_byte_length + chunk_offset,
                    "tuple item state is missing",
                )
            })?;
            let remaining_item_byte_length = current_item
                .expected_byte_length
                .saturating_sub(current_item.canonical_bytes.len());
            let copied_byte_length = remaining_item_byte_length.min(bytes.len() - chunk_offset);
            let source_end = chunk_offset + copied_byte_length;
            current_item
                .canonical_bytes
                .extend_from_slice(&bytes[chunk_offset..source_end]);
            chunk_offset = source_end;
            if current_item.canonical_bytes.len() == current_item.expected_byte_length {
                self.finish_current_item()?;
            }
        }
        self.absorbed_byte_length = resulting_byte_length;
        Ok(())
    }

    fn initialize_tuple_header(&mut self) -> Result<(), CanonicalCodecError> {
        let schema_identifier = u16::from_le_bytes([self.header_bytes[0], self.header_bytes[1]]);
        let schema_version = u16::from_le_bytes([self.header_bytes[2], self.header_bytes[3]]);
        let item_count = u32::from_le_bytes([
            self.header_bytes[4],
            self.header_bytes[5],
            self.header_bytes[6],
            self.header_bytes[7],
        ]) as usize;
        if item_count > self.limits.maximum_item_count {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                4,
                "tuple item count exceeds the configured limit",
            ));
        }
        let minimum_length = item_count
            .checked_mul(6)
            .and_then(|value| value.checked_add(8))
            .ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    4,
                    "tuple item headers overflow the address space",
                )
            })?;
        if minimum_length > self.expected_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                self.expected_byte_length,
                "tuple cannot contain its declared item headers",
            ));
        }
        self.budget.charge_work(minimum_length, 0)?;
        let item_allocation_byte_length = item_count
            .checked_mul(CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH)
            .ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    4,
                    "tuple item allocation accounting overflows the address space",
                )
            })?;
        self.budget
            .charge_allocation(item_allocation_byte_length, 4)?;
        self.schema_identifier = Some(schema_identifier);
        self.schema_version = Some(schema_version);
        self.declared_item_count = Some(item_count);
        self.items = Vec::with_capacity(item_count);
        Ok(())
    }

    fn initialize_item(&mut self, value_start_offset: usize) -> Result<(), CanonicalCodecError> {
        let item_header_start_offset = value_start_offset.saturating_sub(6);
        let item_type_code =
            u16::from_le_bytes([self.item_header_bytes[0], self.item_header_bytes[1]]);
        let item_type =
            CanonicalItemType::from_canonical_code(item_type_code).ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::UnknownItemType,
                    item_header_start_offset,
                    "tuple item type is unassigned",
                )
            })?;
        let item_byte_length = u32::from_le_bytes([
            self.item_header_bytes[2],
            self.item_header_bytes[3],
            self.item_header_bytes[4],
            self.item_header_bytes[5],
        ]) as usize;
        if item_byte_length > self.limits.maximum_item_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                item_header_start_offset + 2,
                "tuple item byte length exceeds the configured limit",
            ));
        }
        let declared_item_count = self.declared_item_count.ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                4,
                "tuple item count was not initialized",
            )
        })?;
        let remaining_item_count = declared_item_count
            .checked_sub(self.items.len() + 1)
            .ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::TrailingBytes,
                    item_header_start_offset,
                    "tuple contains more items than declared",
                )
            })?;
        let minimum_terminal_offset = value_start_offset
            .checked_add(item_byte_length)
            .and_then(|value| value.checked_add(remaining_item_count.checked_mul(6)?))
            .ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    item_header_start_offset + 2,
                    "tuple item end offset overflows",
                )
            })?;
        if minimum_terminal_offset > self.expected_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::Truncated,
                value_start_offset,
                "tuple item is truncated",
            ));
        }
        self.budget
            .charge_allocation(item_byte_length, value_start_offset)?;
        self.current_item = Some(IncrementalCanonicalItem {
            item_type,
            value_start_offset,
            canonical_bytes: Vec::with_capacity(item_byte_length),
            expected_byte_length: item_byte_length,
        });
        self.item_header_byte_length = 0;
        self.item_header_bytes.fill(0);
        Ok(())
    }

    fn finish_current_item(&mut self) -> Result<(), CanonicalCodecError> {
        let item = self.current_item.take().ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                self.absorbed_byte_length,
                "tuple item state is missing",
            )
        })?;
        validate_item_bytes(
            item.item_type,
            &item.canonical_bytes,
            &self.limits,
            &mut self.budget,
            0,
            item.value_start_offset,
        )?;
        self.items.push(CanonicalItem {
            item_type: item.item_type,
            canonical_bytes: item.canonical_bytes,
        });
        Ok(())
    }
}

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

pub(super) fn validate_item_bytes(
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
        CanonicalItemType::Unsigned8 | CanonicalItemType::Boolean => Some(1),
        CanonicalItemType::Unsigned16 => Some(2),
        CanonicalItemType::Unsigned32 => Some(4),
        CanonicalItemType::Unsigned64 => Some(8),
        CanonicalItemType::Hash512 | CanonicalItemType::ParticipantIdentity => Some(64),
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
        CanonicalItemType::Boolean if !matches!(bytes, [0] | [1]) => {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                base_offset,
                "boolean item is not zero or one",
            ));
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
        CanonicalItemType::Optional => {
            if bytes.len() < 3 {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::Truncated,
                    base_offset + bytes.len(),
                    "optional item is truncated",
                ));
            }
            let contained_type_code = u16::from_le_bytes([bytes[0], bytes[1]]);
            let contained_type = CanonicalItemType::from_canonical_code(contained_type_code)
                .ok_or_else(|| {
                    CanonicalCodecError::new(
                        CanonicalCodecErrorKind::UnknownItemType,
                        base_offset,
                        "optional contained item type is unassigned",
                    )
                })?;
            match bytes[2] {
                0 if bytes.len() == 3 => {}
                0 => {
                    return Err(CanonicalCodecError::new(
                        CanonicalCodecErrorKind::TrailingBytes,
                        base_offset + 3,
                        "absent optional item contains trailing bytes",
                    ));
                }
                1 => {
                    let next_depth = nesting_depth.checked_add(1).ok_or_else(|| {
                        CanonicalCodecError::new(
                            CanonicalCodecErrorKind::LengthOverflow,
                            base_offset + 3,
                            "optional nesting depth overflows",
                        )
                    })?;
                    validate_item_bytes(
                        contained_type,
                        &bytes[3..],
                        limits,
                        budget,
                        next_depth,
                        base_offset + 3,
                    )?
                }
                _ => {
                    return Err(CanonicalCodecError::new(
                        CanonicalCodecErrorKind::InvalidItem,
                        base_offset + 2,
                        "optional tag is not zero or one",
                    ));
                }
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
        CanonicalItemType::FieldElement | CanonicalItemType::ChallengeExtensionElement
            if bytes.is_empty() =>
        {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                base_offset,
                "field item cannot be empty",
            ));
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
    let fixed_length = match element_type {
        CanonicalItemType::Unsigned8 | CanonicalItemType::Boolean => Some(1usize),
        CanonicalItemType::Unsigned16 => Some(2),
        CanonicalItemType::Unsigned32 => Some(4),
        CanonicalItemType::Unsigned64 => Some(8),
        CanonicalItemType::Hash512 | CanonicalItemType::ParticipantIdentity => Some(64),
        _ => None,
    };
    if let Some(element_length) = fixed_length {
        let expected_length = count.checked_mul(element_length).ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                base_offset,
                "homogeneous-list byte length overflows",
            )
        })?;
        if bytes.len() != expected_length {
            return Err(CanonicalCodecError::new(
                if bytes.len() < expected_length {
                    CanonicalCodecErrorKind::Truncated
                } else {
                    CanonicalCodecErrorKind::TrailingBytes
                },
                base_offset + bytes.len().min(expected_length),
                "homogeneous-list payload length is not canonical",
            ));
        }
        for index in 0..count {
            let start = index * element_length;
            validate_item_bytes(
                element_type,
                &bytes[start..start + element_length],
                limits,
                budget,
                nesting_depth,
                base_offset + start,
            )?;
        }
        return Ok(());
    }
    if matches!(
        element_type,
        CanonicalItemType::Ascii | CanonicalItemType::DisplayText
    ) {
        let mut offset = 0usize;
        for _ in 0..count {
            if bytes.len().saturating_sub(offset) < 4 {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::Truncated,
                    base_offset + bytes.len(),
                    "variable-width homogeneous-list element is truncated",
                ));
            }
            let declared_length = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            let element_length = declared_length.checked_add(4).ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    base_offset + offset,
                    "homogeneous-list element length overflows",
                )
            })?;
            let element_end = offset.checked_add(element_length).ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    base_offset + offset,
                    "homogeneous-list element end overflows",
                )
            })?;
            if element_end > bytes.len() {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::Truncated,
                    base_offset + offset,
                    "variable-width homogeneous-list element is truncated",
                ));
            }
            validate_item_bytes(
                element_type,
                &bytes[offset..element_end],
                limits,
                budget,
                nesting_depth,
                base_offset + offset,
            )?;
            offset = element_end;
        }
        if offset != bytes.len() {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::TrailingBytes,
                base_offset + offset,
                "homogeneous-list contains trailing bytes",
            ));
        }
        return Ok(());
    }
    if matches!(
        element_type,
        CanonicalItemType::RawBytes
            | CanonicalItemType::FieldElement
            | CanonicalItemType::ChallengeExtensionElement
    ) {
        // Their element widths and, for raw bytes, fixed-versus-variable
        // framing are selected by the enclosing schema and suite. Preserve
        // the bounded payload here so the profile-aware decoder can enforce
        // exact element boundaries before accepting it.
        return Ok(());
    }
    if element_type != CanonicalItemType::NestedTuple {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::InvalidItem,
            base_offset,
            "homogeneous-list element type has no canonical framing rule",
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
