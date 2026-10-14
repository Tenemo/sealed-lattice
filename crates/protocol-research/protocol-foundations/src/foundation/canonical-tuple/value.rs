use super::super::StabilizedDisplayText;
use super::decoding::{decode_tuple_at, validate_item_bytes};
use super::{CanonicalCodecRefusal, CanonicalDecodeBudget, CanonicalDecodeLimits};

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
    pub fn fixed_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CanonicalCodecRefusal> {
        let source_bytes = bytes.as_ref();
        ensure_default_fixed_byte_value_limit(source_bytes.len())?;
        Ok(Self {
            item_type: CanonicalItemType::RawBytes,
            canonical_bytes: source_bytes.to_vec(),
        })
    }

    pub fn variable_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CanonicalCodecRefusal> {
        let canonical_bytes = encode_variable_value(bytes.as_ref())?;
        if canonical_bytes.len() > CanonicalDecodeLimits::default().maximum_item_byte_length {
            return Err(CanonicalCodecRefusal);
        }
        Ok(Self {
            item_type: CanonicalItemType::RawBytes,
            canonical_bytes,
        })
    }

    pub fn ascii(value: &str) -> Result<Self, CanonicalCodecRefusal> {
        let bytes = value.as_bytes();
        let (byte_length, capacity) = checked_variable_value_layout(bytes.len())?;
        if bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
            return Err(CanonicalCodecRefusal);
        }
        let mut canonical_bytes = Vec::with_capacity(capacity);
        canonical_bytes.extend_from_slice(&byte_length.to_le_bytes());
        canonical_bytes.extend_from_slice(bytes);
        Ok(Self {
            item_type: CanonicalItemType::Ascii,
            canonical_bytes,
        })
    }

    pub fn nonempty_ascii(value: &str) -> Result<Self, CanonicalCodecRefusal> {
        if value.is_empty() {
            return Err(CanonicalCodecRefusal);
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

    pub fn hash512_list(values: &[[u8; 64]]) -> Result<Self, CanonicalCodecRefusal> {
        if values.len() > CanonicalDecodeLimits::default().maximum_item_count {
            return Err(CanonicalCodecRefusal);
        }
        let count = u32::try_from(values.len()).map_err(|_| CanonicalCodecRefusal)?;
        let mut canonical_bytes = Vec::with_capacity(6 + values.len() * 64);
        canonical_bytes
            .extend_from_slice(&CanonicalItemType::Hash512.canonical_code().to_le_bytes());
        canonical_bytes.extend_from_slice(&count.to_le_bytes());
        for value in values {
            canonical_bytes.extend_from_slice(value);
        }
        ensure_default_item_limit(&canonical_bytes)?;
        Ok(Self {
            item_type: CanonicalItemType::HomogeneousList,
            canonical_bytes,
        })
    }

    pub fn display_text(value: &StabilizedDisplayText) -> Result<Self, CanonicalCodecRefusal> {
        let canonical_bytes = encode_variable_value(value.as_str().as_bytes())?;
        ensure_default_item_limit(&canonical_bytes)?;
        Ok(Self {
            item_type: CanonicalItemType::DisplayText,
            canonical_bytes,
        })
    }

    pub fn nested_tuple_list(values: &[CanonicalTuple]) -> Result<Self, CanonicalCodecRefusal> {
        let limits = CanonicalDecodeLimits::default();
        if values.len() > limits.maximum_item_count {
            return Err(CanonicalCodecRefusal);
        }
        let count = u32::try_from(values.len()).map_err(|_| CanonicalCodecRefusal)?;
        let encoded_values = values
            .iter()
            .map(CanonicalTuple::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let payload_length = encoded_values.iter().try_fold(0usize, |length, bytes| {
            length.checked_add(bytes.len()).ok_or(CanonicalCodecRefusal)
        })?;
        let canonical_length = 6usize
            .checked_add(payload_length)
            .ok_or(CanonicalCodecRefusal)?;
        if canonical_length > limits.maximum_item_byte_length
            || u32::try_from(canonical_length).is_err()
        {
            return Err(CanonicalCodecRefusal);
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

    pub fn variable_value_bytes(&self) -> Result<&[u8], CanonicalCodecRefusal> {
        if !matches!(
            self.item_type,
            CanonicalItemType::RawBytes | CanonicalItemType::Ascii | CanonicalItemType::DisplayText
        ) {
            return Err(CanonicalCodecRefusal);
        }
        decode_variable_value(&self.canonical_bytes)
    }
}

fn encode_variable_value(value: &[u8]) -> Result<Vec<u8>, CanonicalCodecRefusal> {
    let (byte_length, capacity) = checked_variable_value_layout(value.len())?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&byte_length.to_le_bytes());
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn checked_variable_value_layout(
    value_byte_length: usize,
) -> Result<(u32, usize), CanonicalCodecRefusal> {
    let byte_length = u32::try_from(value_byte_length).map_err(|_| CanonicalCodecRefusal)?;
    let capacity = value_byte_length
        .checked_add(4)
        .ok_or(CanonicalCodecRefusal)?;
    if capacity > CanonicalDecodeLimits::default().maximum_item_byte_length {
        return Err(CanonicalCodecRefusal);
    }
    Ok((byte_length, capacity))
}

fn ensure_default_fixed_byte_value_limit(byte_length: usize) -> Result<(), CanonicalCodecRefusal> {
    if byte_length > CanonicalDecodeLimits::default().maximum_item_byte_length {
        return Err(CanonicalCodecRefusal);
    }
    Ok(())
}

fn ensure_default_item_limit(bytes: &[u8]) -> Result<(), CanonicalCodecRefusal> {
    if bytes.len() > CanonicalDecodeLimits::default().maximum_item_byte_length {
        return Err(CanonicalCodecRefusal);
    }
    Ok(())
}

pub(super) fn decode_variable_value(bytes: &[u8]) -> Result<&[u8], CanonicalCodecRefusal> {
    if bytes.len() < 4 {
        return Err(CanonicalCodecRefusal);
    }
    let declared_length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let expected_length = declared_length
        .checked_add(4)
        .ok_or(CanonicalCodecRefusal)?;
    if bytes.len() != expected_length {
        return Err(CanonicalCodecRefusal);
    }
    Ok(&bytes[4..])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTuple {
    pub schema_identifier: u16,
    pub items: Vec<CanonicalItem>,
}

impl CanonicalTuple {
    pub fn new(schema_identifier: u16, items: Vec<CanonicalItem>) -> Self {
        Self {
            schema_identifier,
            items,
        }
    }

    /// Whether the tuple has the canonical schema and exactly `item_count`
    /// items.
    pub fn has_header(&self, item_count: usize) -> bool {
        self.schema_identifier == super::CANONICAL_TUPLE_SCHEMA_IDENTIFIER
            && self.items.len() == item_count
    }

    pub fn encode(&self) -> Result<Vec<u8>, CanonicalCodecRefusal> {
        let limits = CanonicalDecodeLimits::default();
        let mut budget = CanonicalDecodeBudget::new(&limits);
        if self.items.len() > limits.maximum_item_count {
            return Err(CanonicalCodecRefusal);
        }
        for item in &self.items {
            if item.canonical_bytes.len() > limits.maximum_item_byte_length {
                return Err(CanonicalCodecRefusal);
            }
            validate_item_bytes(
                item.item_type,
                &item.canonical_bytes,
                &limits,
                &mut budget,
                0,
            )?;
        }
        let item_count = u32::try_from(self.items.len()).map_err(|_| CanonicalCodecRefusal)?;
        let total_length = self.items.iter().try_fold(6usize, |length, item| {
            let _ = u32::try_from(item.canonical_bytes.len()).map_err(|_| CanonicalCodecRefusal)?;
            length
                .checked_add(6)
                .and_then(|value| value.checked_add(item.canonical_bytes.len()))
                .ok_or(CanonicalCodecRefusal)
        })?;
        if total_length > limits.maximum_tuple_byte_length {
            return Err(CanonicalCodecRefusal);
        }
        let mut output = Vec::with_capacity(total_length);
        output.extend_from_slice(&self.schema_identifier.to_le_bytes());
        output.extend_from_slice(&item_count.to_le_bytes());
        for item in &self.items {
            output.extend_from_slice(&item.item_type.canonical_code().to_le_bytes());
            let byte_length =
                u32::try_from(item.canonical_bytes.len()).map_err(|_| CanonicalCodecRefusal)?;
            output.extend_from_slice(&byte_length.to_le_bytes());
            output.extend_from_slice(&item.canonical_bytes);
        }
        Ok(output)
    }

    pub fn decode(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> Result<Self, CanonicalCodecRefusal> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(in crate::foundation) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> Result<Self, CanonicalCodecRefusal> {
        let (tuple, consumed) = decode_tuple_at(bytes, limits, budget, 0)?;
        if consumed != bytes.len() {
            return Err(CanonicalCodecRefusal);
        }
        Ok(tuple)
    }

    pub(in crate::foundation) fn decode_prefix(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
        nesting_depth: u16,
    ) -> Result<(Self, usize), CanonicalCodecRefusal> {
        decode_tuple_at(bytes, limits, budget, nesting_depth)
    }
}
