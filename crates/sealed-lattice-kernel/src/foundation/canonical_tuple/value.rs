use super::super::StabilizedDisplayText;
use super::decoding::{decode_tuple_at, validate_item_bytes};
use super::{
    CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeBudget, CanonicalDecodeLimits,
};
#[cfg(test)]
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CanonicalItemType {
    RawBytes = 0x01,
    Ascii = 0x02,
    Unsigned16 = 0x03,
    Unsigned64 = 0x05,
    Hash512 = 0x06,
    NestedTuple = 0x09,
    DisplayText = 0x0c,
    HomogeneousList = 0x0e,
}

impl CanonicalItemType {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            0x01 => Some(Self::RawBytes),
            0x02 => Some(Self::Ascii),
            0x03 => Some(Self::Unsigned16),
            0x05 => Some(Self::Unsigned64),
            0x06 => Some(Self::Hash512),
            0x09 => Some(Self::NestedTuple),
            0x0c => Some(Self::DisplayText),
            0x0e => Some(Self::HomogeneousList),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalItem {
    pub(super) item_type: CanonicalItemType,
    pub(super) canonical_bytes: Vec<u8>,
}

impl CanonicalItem {
    pub fn fixed_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CanonicalCodecError> {
        let source_bytes = bytes.as_ref();
        ensure_default_fixed_byte_value_limit(source_bytes.len())?;
        Ok(Self {
            item_type: CanonicalItemType::RawBytes,
            canonical_bytes: source_bytes.to_vec(),
        })
    }

    pub fn variable_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CanonicalCodecError> {
        let canonical_bytes =
            encode_variable_value(bytes.as_ref(), "raw-byte item length does not fit u32")?;
        if canonical_bytes.len() > CanonicalDecodeLimits::default().maximum_item_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "variable byte value exceeds the default item limit",
            ));
        }
        Ok(Self {
            item_type: CanonicalItemType::RawBytes,
            canonical_bytes,
        })
    }

    pub fn ascii(value: &str) -> Result<Self, CanonicalCodecError> {
        let bytes = value.as_bytes();
        let (byte_length, capacity) =
            checked_variable_value_layout(bytes.len(), "ASCII item length does not fit u32")?;
        if bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                0,
                "ASCII item contains a non-printable byte",
            ));
        }
        let mut canonical_bytes = Vec::with_capacity(capacity);
        canonical_bytes.extend_from_slice(&byte_length.to_le_bytes());
        canonical_bytes.extend_from_slice(bytes);
        Ok(Self {
            item_type: CanonicalItemType::Ascii,
            canonical_bytes,
        })
    }

    pub fn nonempty_ascii(value: &str) -> Result<Self, CanonicalCodecError> {
        if value.is_empty() {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                0,
                "ASCII item must be nonempty in this schema",
            ));
        }
        Self::ascii(value)
    }

    pub fn unsigned16(value: u16) -> Self {
        Self {
            item_type: CanonicalItemType::Unsigned16,
            canonical_bytes: value.to_le_bytes().to_vec(),
        }
    }

    pub fn unsigned64(value: u64) -> Self {
        Self {
            item_type: CanonicalItemType::Unsigned64,
            canonical_bytes: value.to_le_bytes().to_vec(),
        }
    }

    pub fn hash512(value: [u8; 64]) -> Self {
        Self {
            item_type: CanonicalItemType::Hash512,
            canonical_bytes: value.to_vec(),
        }
    }

    pub fn display_text(value: &StabilizedDisplayText) -> Result<Self, CanonicalCodecError> {
        let canonical_bytes = encode_variable_value(
            value.as_str().as_bytes(),
            "display-text item length does not fit u32",
        )?;
        ensure_default_item_limit(&canonical_bytes)?;
        Ok(Self {
            item_type: CanonicalItemType::DisplayText,
            canonical_bytes,
        })
    }

    pub fn nested_tuple_list(values: &[CanonicalTuple]) -> Result<Self, CanonicalCodecError> {
        let limits = CanonicalDecodeLimits::default();
        if values.len() > limits.maximum_item_count {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "homogeneous-list count exceeds the default item limit",
            ));
        }
        let count = u32::try_from(values.len()).map_err(|_| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                0,
                "homogeneous-list count does not fit u32",
            )
        })?;
        let encoded_values = values
            .iter()
            .map(CanonicalTuple::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let payload_length = encoded_values.iter().try_fold(0usize, |length, bytes| {
            length.checked_add(bytes.len()).ok_or_else(|| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    0,
                    "homogeneous-list byte length overflows",
                )
            })
        })?;
        let canonical_length = 6usize.checked_add(payload_length).ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                0,
                "homogeneous-list byte length overflows",
            )
        })?;
        if canonical_length > limits.maximum_item_byte_length
            || u32::try_from(canonical_length).is_err()
        {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "homogeneous-list payload exceeds the default item limit",
            ));
        }
        let mut canonical_bytes = Vec::with_capacity(canonical_length);
        canonical_bytes.extend_from_slice(
            &CanonicalItemType::NestedTuple
                .canonical_code()
                .to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(&count.to_le_bytes());
        for encoded_value in encoded_values {
            canonical_bytes.extend_from_slice(&encoded_value);
        }
        Ok(Self {
            item_type: CanonicalItemType::HomogeneousList,
            canonical_bytes,
        })
    }

    pub const fn item_type(&self) -> CanonicalItemType {
        self.item_type
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn variable_value_bytes(&self) -> Result<&[u8], CanonicalCodecError> {
        if !matches!(
            self.item_type,
            CanonicalItemType::RawBytes | CanonicalItemType::Ascii | CanonicalItemType::DisplayText
        ) {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                0,
                "item is not a variable-width byte or text value",
            ));
        }
        decode_variable_value(&self.canonical_bytes, 0)
    }

    #[cfg(test)]
    pub(crate) fn zeroize(&mut self) {
        self.canonical_bytes.zeroize();
    }
}

fn encode_variable_value(
    value: &[u8],
    overflow_message: &'static str,
) -> Result<Vec<u8>, CanonicalCodecError> {
    let (byte_length, capacity) = checked_variable_value_layout(value.len(), overflow_message)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&byte_length.to_le_bytes());
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn checked_variable_value_layout(
    value_byte_length: usize,
    overflow_message: &'static str,
) -> Result<(u32, usize), CanonicalCodecError> {
    let byte_length = u32::try_from(value_byte_length).map_err(|_| {
        CanonicalCodecError::new(CanonicalCodecErrorKind::LengthOverflow, 0, overflow_message)
    })?;
    let capacity = value_byte_length.checked_add(4).ok_or_else(|| {
        CanonicalCodecError::new(CanonicalCodecErrorKind::LengthOverflow, 0, overflow_message)
    })?;
    if capacity > CanonicalDecodeLimits::default().maximum_item_byte_length {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::LimitExceeded,
            0,
            "variable-width item exceeds the default item limit",
        ));
    }
    Ok((byte_length, capacity))
}

fn ensure_default_fixed_byte_value_limit(byte_length: usize) -> Result<(), CanonicalCodecError> {
    if byte_length > CanonicalDecodeLimits::default().maximum_item_byte_length {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::LimitExceeded,
            0,
            "fixed byte value exceeds the default item limit",
        ));
    }
    Ok(())
}

fn ensure_default_item_limit(bytes: &[u8]) -> Result<(), CanonicalCodecError> {
    if bytes.len() > CanonicalDecodeLimits::default().maximum_item_byte_length {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::LimitExceeded,
            0,
            "item byte length exceeds the default limit",
        ));
    }
    Ok(())
}

pub(super) fn decode_variable_value(
    bytes: &[u8],
    base_offset: usize,
) -> Result<&[u8], CanonicalCodecError> {
    if bytes.len() < 4 {
        return Err(CanonicalCodecError::new(
            CanonicalCodecErrorKind::Truncated,
            base_offset + bytes.len(),
            "variable-width item length is truncated",
        ));
    }
    let declared_length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let expected_length = declared_length.checked_add(4).ok_or_else(|| {
        CanonicalCodecError::new(
            CanonicalCodecErrorKind::LengthOverflow,
            base_offset,
            "variable-width item length overflows",
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
            "variable-width item length is not canonical",
        ));
    }
    Ok(&bytes[4..])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTuple {
    pub schema_identifier: u16,
    pub schema_version: u16,
    pub items: Vec<CanonicalItem>,
}

impl CanonicalTuple {
    pub fn new(schema_identifier: u16, schema_version: u16, items: Vec<CanonicalItem>) -> Self {
        Self {
            schema_identifier,
            schema_version,
            items,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CanonicalCodecError> {
        let limits = CanonicalDecodeLimits::default();
        let mut budget = CanonicalDecodeBudget::new(&limits);
        if self.items.len() > limits.maximum_item_count {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                4,
                "tuple item count exceeds the default limit",
            ));
        }
        for item in &self.items {
            if item.canonical_bytes.len() > limits.maximum_item_byte_length {
                return Err(CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LimitExceeded,
                    0,
                    "tuple item byte length exceeds the default limit",
                ));
            }
            validate_item_bytes(
                item.item_type,
                &item.canonical_bytes,
                &limits,
                &mut budget,
                0,
                0,
            )?;
        }
        let item_count = u32::try_from(self.items.len()).map_err(|_| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                4,
                "tuple item count does not fit u32",
            )
        })?;
        let total_length = self.items.iter().try_fold(8usize, |length, item| {
            let _ = u32::try_from(item.canonical_bytes.len()).map_err(|_| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    length,
                    "tuple item byte length does not fit u32",
                )
            })?;
            length
                .checked_add(6)
                .and_then(|value| value.checked_add(item.canonical_bytes.len()))
                .ok_or_else(|| {
                    CanonicalCodecError::new(
                        CanonicalCodecErrorKind::LengthOverflow,
                        length,
                        "tuple byte length overflows",
                    )
                })
        })?;
        if total_length > limits.maximum_tuple_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "tuple byte length exceeds the default limit",
            ));
        }
        let mut output = Vec::with_capacity(total_length);
        output.extend_from_slice(&self.schema_identifier.to_le_bytes());
        output.extend_from_slice(&self.schema_version.to_le_bytes());
        output.extend_from_slice(&item_count.to_le_bytes());
        for item in &self.items {
            output.extend_from_slice(&item.item_type.canonical_code().to_le_bytes());
            let byte_length = u32::try_from(item.canonical_bytes.len()).map_err(|_| {
                CanonicalCodecError::new(
                    CanonicalCodecErrorKind::LengthOverflow,
                    output.len(),
                    "tuple item byte length does not fit u32",
                )
            })?;
            output.extend_from_slice(&byte_length.to_le_bytes());
            output.extend_from_slice(&item.canonical_bytes);
        }
        Ok(output)
    }

    pub fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> Result<Self, CanonicalCodecError> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(in crate::foundation) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> Result<Self, CanonicalCodecError> {
        let (tuple, consumed) = decode_tuple_at(bytes, limits, budget, 0, 0)?;
        if consumed != bytes.len() {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::TrailingBytes,
                consumed,
                "tuple contains trailing bytes",
            ));
        }
        Ok(tuple)
    }

    pub(in crate::foundation) fn decode_prefix(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
        nesting_depth: u16,
    ) -> Result<(Self, usize), CanonicalCodecError> {
        decode_tuple_at(bytes, limits, budget, nesting_depth, 0)
    }

    #[cfg(test)]
    pub(crate) fn zeroize(&mut self) {
        for item in &mut self.items {
            item.zeroize();
        }
    }
}
