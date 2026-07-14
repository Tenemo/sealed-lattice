use core::fmt;

use zeroize::Zeroize;

use super::StabilizedDisplayText;

pub const CANONICAL_TUPLE_SCHEMA_IDENTIFIER: u16 = 0x0001;
pub const CANONICAL_TUPLE_VERSION: u16 = 1;
const ABSOLUTE_MAXIMUM_NESTING_DEPTH: u16 = 64;
const DEFAULT_MAXIMUM_CUMULATIVE_WORK_BYTE_LENGTH: usize = 64 * 1024 * 1024;
const DEFAULT_MAXIMUM_CUMULATIVE_ALLOCATION_BYTE_LENGTH: usize = 64 * 1024 * 1024;
// Keep allocation accounting independent of native pointer width so the same
// configured limit accepts and refuses the same canonical bytes under WASM.
const CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalCodecErrorKind {
    Truncated,
    TrailingBytes,
    UnknownItemType,
    InvalidItem,
    LimitExceeded,
    LengthOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCodecError {
    pub kind: CanonicalCodecErrorKind,
    pub byte_offset: usize,
    pub message: &'static str,
}

impl CanonicalCodecError {
    fn new(kind: CanonicalCodecErrorKind, byte_offset: usize, message: &'static str) -> Self {
        Self {
            kind,
            byte_offset,
            message,
        }
    }
}

impl fmt::Display for CanonicalCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at byte {}", self.message, self.byte_offset)
    }
}

impl std::error::Error for CanonicalCodecError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalDecodeLimits {
    pub maximum_tuple_byte_length: usize,
    pub maximum_item_count: usize,
    pub maximum_item_byte_length: usize,
    pub maximum_nesting_depth: u16,
    pub maximum_cumulative_work_byte_length: usize,
    pub maximum_cumulative_allocation_byte_length: usize,
}

impl Default for CanonicalDecodeLimits {
    fn default() -> Self {
        Self {
            maximum_tuple_byte_length: 16 * 1024 * 1024,
            maximum_item_count: 4_096,
            maximum_item_byte_length: 8 * 1024 * 1024,
            maximum_nesting_depth: 32,
            maximum_cumulative_work_byte_length: DEFAULT_MAXIMUM_CUMULATIVE_WORK_BYTE_LENGTH,
            maximum_cumulative_allocation_byte_length:
                DEFAULT_MAXIMUM_CUMULATIVE_ALLOCATION_BYTE_LENGTH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CanonicalDecodeBudget {
    remaining_work_byte_length: usize,
    remaining_allocation_byte_length: usize,
}

impl CanonicalDecodeBudget {
    pub(super) const fn new(limits: &CanonicalDecodeLimits) -> Self {
        Self {
            remaining_work_byte_length: limits.maximum_cumulative_work_byte_length,
            remaining_allocation_byte_length: limits.maximum_cumulative_allocation_byte_length,
        }
    }

    fn charge_work(
        &mut self,
        byte_length: usize,
        byte_offset: usize,
    ) -> Result<(), CanonicalCodecError> {
        if byte_length > self.remaining_work_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                byte_offset,
                "canonical decoding exceeds the configured cumulative work limit",
            ));
        }
        self.remaining_work_byte_length -= byte_length;
        Ok(())
    }

    fn charge_allocation(
        &mut self,
        byte_length: usize,
        byte_offset: usize,
    ) -> Result<(), CanonicalCodecError> {
        if byte_length > self.remaining_allocation_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                byte_offset,
                "canonical decoding exceeds the configured cumulative allocation limit",
            ));
        }
        self.remaining_allocation_byte_length -= byte_length;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CanonicalItemType {
    RawBytes = 0x01,
    Ascii = 0x02,
    Unsigned16 = 0x03,
    Unsigned32 = 0x04,
    Unsigned64 = 0x05,
    Hash512 = 0x06,
    ParticipantIdentity = 0x07,
    FieldElement = 0x08,
    NestedTuple = 0x09,
    Unsigned8 = 0x0a,
    Boolean = 0x0b,
    DisplayText = 0x0c,
    Optional = 0x0d,
    HomogeneousList = 0x0e,
    ChallengeExtensionElement = 0x0f,
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
            0x04 => Some(Self::Unsigned32),
            0x05 => Some(Self::Unsigned64),
            0x06 => Some(Self::Hash512),
            0x07 => Some(Self::ParticipantIdentity),
            0x08 => Some(Self::FieldElement),
            0x09 => Some(Self::NestedTuple),
            0x0a => Some(Self::Unsigned8),
            0x0b => Some(Self::Boolean),
            0x0c => Some(Self::DisplayText),
            0x0d => Some(Self::Optional),
            0x0e => Some(Self::HomogeneousList),
            0x0f => Some(Self::ChallengeExtensionElement),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalItem {
    item_type: CanonicalItemType,
    canonical_bytes: Vec<u8>,
}

impl Zeroize for CanonicalItem {
    fn zeroize(&mut self) {
        self.canonical_bytes.zeroize();
    }
}

impl CanonicalItem {
    pub fn from_canonical_bytes(
        item_type: CanonicalItemType,
        canonical_bytes: Vec<u8>,
        limits: &CanonicalDecodeLimits,
    ) -> Result<Self, CanonicalCodecError> {
        if canonical_bytes.len() > limits.maximum_item_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "item byte length exceeds the configured limit",
            ));
        }
        let mut budget = CanonicalDecodeBudget::new(limits);
        validate_item_bytes(item_type, &canonical_bytes, limits, &mut budget, 0, 0)?;
        Ok(Self {
            item_type,
            canonical_bytes,
        })
    }

    /// Constructs a schema-declared fixed-width raw byte value.
    pub fn fixed_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CanonicalCodecError> {
        let source_bytes = bytes.as_ref();
        ensure_default_fixed_byte_value_limit(source_bytes.len())?;
        Ok(Self {
            item_type: CanonicalItemType::RawBytes,
            canonical_bytes: source_bytes.to_vec(),
        })
    }

    /// Constructs a variable-width raw byte value with its inner u32 length.
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

    pub fn unsigned8(value: u8) -> Self {
        Self {
            item_type: CanonicalItemType::Unsigned8,
            canonical_bytes: vec![value],
        }
    }

    pub fn unsigned16(value: u16) -> Self {
        Self {
            item_type: CanonicalItemType::Unsigned16,
            canonical_bytes: value.to_le_bytes().to_vec(),
        }
    }

    pub fn unsigned32(value: u32) -> Self {
        Self {
            item_type: CanonicalItemType::Unsigned32,
            canonical_bytes: value.to_le_bytes().to_vec(),
        }
    }

    pub fn unsigned64(value: u64) -> Self {
        Self {
            item_type: CanonicalItemType::Unsigned64,
            canonical_bytes: value.to_le_bytes().to_vec(),
        }
    }

    pub fn boolean(value: bool) -> Self {
        Self {
            item_type: CanonicalItemType::Boolean,
            canonical_bytes: vec![u8::from(value)],
        }
    }

    pub fn hash512(value: [u8; 64]) -> Self {
        Self {
            item_type: CanonicalItemType::Hash512,
            canonical_bytes: value.to_vec(),
        }
    }

    pub fn participant_identity(value: [u8; 64]) -> Self {
        Self {
            item_type: CanonicalItemType::ParticipantIdentity,
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

    pub fn nested_tuple(value: &CanonicalTuple) -> Result<Self, CanonicalCodecError> {
        Ok(Self {
            item_type: CanonicalItemType::NestedTuple,
            canonical_bytes: value.encode()?,
        })
    }

    pub fn optional(
        contained_type: CanonicalItemType,
        value: Option<&CanonicalItem>,
    ) -> Result<Self, CanonicalCodecError> {
        if let Some(item) = value
            && item.item_type != contained_type
        {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                0,
                "optional item type does not match its declared contained type",
            ));
        }
        let value_length = value.map_or(0, |item| item.canonical_bytes.len());
        let capacity = 3usize.checked_add(value_length).ok_or_else(|| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                0,
                "optional item length overflows",
            )
        })?;
        if capacity > CanonicalDecodeLimits::default().maximum_item_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "optional item exceeds the default item limit",
            ));
        }
        let mut canonical_bytes = Vec::with_capacity(capacity);
        canonical_bytes.extend_from_slice(&contained_type.canonical_code().to_le_bytes());
        canonical_bytes.push(u8::from(value.is_some()));
        if let Some(item) = value {
            canonical_bytes.extend_from_slice(&item.canonical_bytes);
        }
        ensure_default_item_limit(&canonical_bytes)?;
        let limits = CanonicalDecodeLimits::default();
        let mut budget = CanonicalDecodeBudget::new(&limits);
        validate_item_bytes(
            CanonicalItemType::Optional,
            &canonical_bytes,
            &limits,
            &mut budget,
            0,
            0,
        )?;
        Ok(Self {
            item_type: CanonicalItemType::Optional,
            canonical_bytes,
        })
    }

    pub fn homogeneous_list(
        element_type: CanonicalItemType,
        values: &[CanonicalItem],
    ) -> Result<Self, CanonicalCodecError> {
        let limits = CanonicalDecodeLimits::default();
        if values.len() > limits.maximum_item_count {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "homogeneous-list count exceeds the default item limit",
            ));
        }
        if values.iter().any(|item| item.item_type != element_type) {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::InvalidItem,
                0,
                "homogeneous-list element type mismatch",
            ));
        }
        let count = u32::try_from(values.len()).map_err(|_| {
            CanonicalCodecError::new(
                CanonicalCodecErrorKind::LengthOverflow,
                0,
                "homogeneous-list count does not fit u32",
            )
        })?;
        let payload_length = values.iter().try_fold(0usize, |length, item| {
            length
                .checked_add(item.canonical_bytes.len())
                .ok_or_else(|| {
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
        if canonical_length > limits.maximum_item_byte_length {
            return Err(CanonicalCodecError::new(
                CanonicalCodecErrorKind::LimitExceeded,
                0,
                "homogeneous-list payload exceeds the default item limit",
            ));
        }
        let mut canonical_bytes = Vec::with_capacity(canonical_length);
        canonical_bytes.extend_from_slice(&element_type.canonical_code().to_le_bytes());
        canonical_bytes.extend_from_slice(&count.to_le_bytes());
        for item in values {
            canonical_bytes.extend_from_slice(&item.canonical_bytes);
        }
        ensure_default_item_limit(&canonical_bytes)?;
        let mut budget = CanonicalDecodeBudget::new(&limits);
        validate_list_payload(
            element_type,
            values.len(),
            &canonical_bytes[6..],
            &limits,
            &mut budget,
            0,
            6,
        )?;
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

    /// Returns the payload of a canonical variable-width byte or text value.
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

fn decode_variable_value(bytes: &[u8], base_offset: usize) -> Result<&[u8], CanonicalCodecError> {
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

impl Zeroize for CanonicalTuple {
    fn zeroize(&mut self) {
        self.schema_identifier.zeroize();
        self.schema_version.zeroize();
        self.items.zeroize();
    }
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

    pub fn decode_fragments<Fragment>(
        expected_byte_length: usize,
        fragments: impl IntoIterator<Item = Fragment>,
        limits: &CanonicalDecodeLimits,
    ) -> Result<Self, CanonicalCodecError>
    where
        Fragment: AsRef<[u8]>,
    {
        let mut decoder = IncrementalCanonicalTupleDecoder::new(expected_byte_length, limits)?;
        for fragment in fragments {
            decoder.absorb(fragment.as_ref())?;
        }
        decoder.finish()
    }

    pub(super) fn decode_with_budget(
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

    pub(super) fn decode_prefix(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
        nesting_depth: u16,
    ) -> Result<(Self, usize), CanonicalCodecError> {
        decode_tuple_at(bytes, limits, budget, nesting_depth, 0)
    }
}

fn decode_tuple_at(
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

fn validate_item_bytes(
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

fn validate_list_payload(
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

#[cfg(test)]
mod tests {
    use super::*;

    struct OversizedByteSource {
        bytes: Vec<u8>,
    }

    impl OversizedByteSource {
        fn new(byte_length: usize) -> Self {
            Self {
                bytes: vec![0; byte_length],
            }
        }
    }

    impl AsRef<[u8]> for OversizedByteSource {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    fn unchecked_single_item_tuple(
        item_type: CanonicalItemType,
        canonical_bytes: &[u8],
    ) -> Vec<u8> {
        let mut tuple = Vec::new();
        tuple.extend_from_slice(&1_u16.to_le_bytes());
        tuple.extend_from_slice(&1_u16.to_le_bytes());
        tuple.extend_from_slice(&1_u32.to_le_bytes());
        tuple.extend_from_slice(&item_type.canonical_code().to_le_bytes());
        tuple.extend_from_slice(
            &u32::try_from(canonical_bytes.len())
                .expect("test item length fits u32")
                .to_le_bytes(),
        );
        tuple.extend_from_slice(canonical_bytes);
        tuple
    }

    fn recursively_nested_single_item_tuple(
        nested_tuple_wrapper_count: usize,
        leaf_byte_length: usize,
    ) -> Vec<u8> {
        let leaf_bytes = vec![0x5a; leaf_byte_length];
        let mut encoded = unchecked_single_item_tuple(CanonicalItemType::RawBytes, &leaf_bytes);
        for _ in 0..nested_tuple_wrapper_count {
            encoded = unchecked_single_item_tuple(CanonicalItemType::NestedTuple, &encoded);
        }
        encoded
    }

    fn representative_tuple() -> CanonicalTuple {
        let display = StabilizedDisplayText::from_ingress_utf8("Cafe\u{301}".as_bytes())
            .expect("display text normalizes");
        let nested = CanonicalTuple::new(0x0111, 1, vec![CanonicalItem::unsigned16(3)]);
        CanonicalTuple::new(
            0x0110,
            1,
            vec![
                CanonicalItem::unsigned16(1),
                CanonicalItem::ascii("sealed-lattice").expect("printable ASCII"),
                CanonicalItem::display_text(&display).expect("display text fits u32"),
                CanonicalItem::hash512([0x5a; 64]),
                CanonicalItem::nested_tuple(&nested).expect("nested tuple encodes"),
                CanonicalItem::optional(CanonicalItemType::Hash512, None)
                    .expect("optional encodes"),
            ],
        )
    }

    #[test]
    fn representative_tuples_and_homogeneous_lists_round_trip_byte_identically() {
        let tuple = representative_tuple();
        let encoded = tuple.encode().expect("tuple encodes");
        let decoded = CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("tuple decodes");
        assert_eq!(decoded, tuple);
        assert_eq!(decoded.encode().expect("decoded tuple re-encodes"), encoded);

        let hash_values = [
            CanonicalItem::hash512([1; 64]),
            CanonicalItem::hash512([2; 64]),
        ];
        let nested_values = [
            CanonicalItem::nested_tuple(&CanonicalTuple::new(
                0x0111,
                1,
                vec![CanonicalItem::unsigned16(0)],
            ))
            .expect("nested tuple"),
            CanonicalItem::nested_tuple(&CanonicalTuple::new(
                0x0111,
                1,
                vec![CanonicalItem::unsigned16(1)],
            ))
            .expect("nested tuple"),
        ];
        let list_tuple = CanonicalTuple::new(
            0x0110,
            1,
            vec![
                CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &hash_values)
                    .expect("hash list"),
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &nested_values)
                    .expect("tuple list"),
            ],
        );
        let encoded = list_tuple.encode().expect("encode");
        assert_eq!(
            CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).expect("decode"),
            list_tuple
        );
    }

    #[test]
    fn byte_and_text_constructors_enforce_exact_framed_item_boundaries() {
        let maximum_item_byte_length = CanonicalDecodeLimits::default().maximum_item_byte_length;

        let fixed_item = CanonicalItem::fixed_bytes(vec![0x5a; maximum_item_byte_length])
            .expect("fixed bytes exactly at the item limit must encode");
        assert_eq!(fixed_item.canonical_bytes().len(), maximum_item_byte_length);
        assert_eq!(fixed_item.canonical_bytes().first(), Some(&0x5a));
        assert_eq!(fixed_item.canonical_bytes().last(), Some(&0x5a));
        drop(fixed_item);

        let fixed_error =
            CanonicalItem::fixed_bytes(OversizedByteSource::new(maximum_item_byte_length + 1))
                .expect_err("oversized fixed bytes must refuse before copying");
        assert_eq!(fixed_error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(
            fixed_error.message,
            "fixed byte value exceeds the default item limit"
        );

        let maximum_variable_payload_byte_length = maximum_item_byte_length - 4;
        let variable_item =
            CanonicalItem::variable_bytes(vec![0xa5; maximum_variable_payload_byte_length])
                .expect("variable bytes exactly at the framed item limit must encode");
        assert_eq!(
            variable_item.canonical_bytes().len(),
            maximum_item_byte_length
        );
        assert_eq!(
            &variable_item.canonical_bytes()[..4],
            &u32::try_from(maximum_variable_payload_byte_length)
                .expect("default item limit fits u32")
                .to_le_bytes()
        );
        let variable_payload = variable_item
            .variable_value_bytes()
            .expect("variable payload decodes");
        assert_eq!(variable_payload.first(), Some(&0xa5));
        assert_eq!(variable_payload.last(), Some(&0xa5));
        drop(variable_item);

        let variable_error = CanonicalItem::variable_bytes(OversizedByteSource::new(
            maximum_variable_payload_byte_length + 1,
        ))
        .expect_err("oversized variable bytes must refuse before allocation");
        assert_eq!(variable_error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(
            variable_error.message,
            "variable-width item exceeds the default item limit"
        );

        let maximum_text_byte_length = maximum_item_byte_length - 4;
        let exact_text = "A".repeat(maximum_text_byte_length);

        let ascii_item = CanonicalItem::ascii(&exact_text)
            .expect("ASCII exactly at the framed item limit must encode");
        assert_eq!(ascii_item.canonical_bytes().len(), maximum_item_byte_length);
        assert_eq!(
            ascii_item
                .variable_value_bytes()
                .expect("ASCII payload decodes")
                .len(),
            maximum_text_byte_length
        );
        drop(ascii_item);

        let display_text = StabilizedDisplayText::from_ingress_utf8(exact_text.as_bytes())
            .expect("test text is assigned stabilized NFC");
        drop(exact_text);
        let display_item = CanonicalItem::display_text(&display_text)
            .expect("display text exactly at the framed item limit must encode");
        assert_eq!(
            display_item.canonical_bytes().len(),
            maximum_item_byte_length
        );
        assert_eq!(
            display_item
                .variable_value_bytes()
                .expect("display-text payload decodes")
                .len(),
            maximum_text_byte_length
        );
        drop(display_item);
        drop(display_text);

        let oversized_text = "B".repeat(maximum_text_byte_length + 1);
        let ascii_error = CanonicalItem::ascii(&oversized_text)
            .expect_err("oversized ASCII must refuse before cloning");
        assert_eq!(ascii_error.kind, CanonicalCodecErrorKind::LimitExceeded);

        let oversized_display_text =
            StabilizedDisplayText::from_ingress_utf8(oversized_text.as_bytes())
                .expect("test text is assigned stabilized NFC");
        drop(oversized_text);
        let display_error = CanonicalItem::display_text(&oversized_display_text)
            .expect_err("oversized display text must refuse before cloning");
        assert_eq!(display_error.kind, CanonicalCodecErrorKind::LimitExceeded);
    }

    #[test]
    fn hostile_counts_lengths_types_and_termination_refuse_before_allocation() {
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: 512,
            maximum_item_count: 4,
            maximum_item_byte_length: 128,
            maximum_nesting_depth: 2,
            ..CanonicalDecodeLimits::default()
        };
        let mut oversized_count = vec![0x10, 0x01, 1, 0];
        oversized_count.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            CanonicalTuple::decode(&oversized_count, &limits)
                .expect_err("oversized count must refuse")
                .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );

        let mut unknown_type = CanonicalTuple::new(1, 1, vec![CanonicalItem::unsigned8(1)])
            .encode()
            .expect("encode");
        unknown_type[8..10].copy_from_slice(&0xffff_u16.to_le_bytes());
        assert_eq!(
            CanonicalTuple::decode(&unknown_type, &limits)
                .expect_err("unknown type must refuse")
                .kind,
            CanonicalCodecErrorKind::UnknownItemType
        );

        let mut hostile_length = unknown_type;
        hostile_length[8..10]
            .copy_from_slice(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
        hostile_length[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            CanonicalTuple::decode(&hostile_length, &limits)
                .expect_err("hostile length must refuse")
                .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );

        let mut trailing = representative_tuple().encode().expect("encode");
        trailing.push(0);
        assert_eq!(
            CanonicalTuple::decode(&trailing, &CanonicalDecodeLimits::default())
                .expect_err("trailing byte must refuse")
                .kind,
            CanonicalCodecErrorKind::TrailingBytes
        );
    }

    #[test]
    fn noncanonical_boolean_optional_and_unicode_items_refuse() {
        let decomposed = "Cafe\u{301}".as_bytes();
        let mut noncanonical_display_text = Vec::new();
        noncanonical_display_text.extend_from_slice(
            &u32::try_from(decomposed.len())
                .expect("test text length fits u32")
                .to_le_bytes(),
        );
        noncanonical_display_text.extend_from_slice(decomposed);
        for (item_type, bytes) in [
            (CanonicalItemType::Boolean, vec![2]),
            (CanonicalItemType::Optional, vec![0x06, 0x00, 0, 1]),
            (CanonicalItemType::DisplayText, noncanonical_display_text),
        ] {
            let encoded = unchecked_single_item_tuple(item_type, &bytes);
            assert!(CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).is_err());
        }
    }

    #[test]
    fn deeply_nested_optionals_refuse_at_the_configured_depth() {
        let mut contained_type = CanonicalItemType::Unsigned8;
        let mut nested_value = vec![1];
        for _ in 0..40 {
            let mut optional = Vec::with_capacity(nested_value.len() + 3);
            optional.extend_from_slice(&contained_type.canonical_code().to_le_bytes());
            optional.push(1);
            optional.extend_from_slice(&nested_value);
            nested_value = optional;
            contained_type = CanonicalItemType::Optional;
        }
        let error = CanonicalTuple::decode(
            &unchecked_single_item_tuple(CanonicalItemType::Optional, &nested_value),
            &CanonicalDecodeLimits::default(),
        )
        .expect_err("optional nesting must be bounded");
        assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);

        let mut contained_type = CanonicalItemType::Unsigned8;
        let mut nested_value = vec![1];
        for _ in 0..=ABSOLUTE_MAXIMUM_NESTING_DEPTH {
            let mut optional = Vec::with_capacity(nested_value.len() + 3);
            optional.extend_from_slice(&contained_type.canonical_code().to_le_bytes());
            optional.push(1);
            optional.extend_from_slice(&nested_value);
            nested_value = optional;
            contained_type = CanonicalItemType::Optional;
        }
        let permissive_limits = CanonicalDecodeLimits {
            maximum_nesting_depth: u16::MAX,
            ..CanonicalDecodeLimits::default()
        };
        assert_eq!(
            CanonicalTuple::decode(
                &unchecked_single_item_tuple(CanonicalItemType::Optional, &nested_value),
                &permissive_limits,
            )
            .expect_err("the absolute nesting ceiling cannot be disabled")
            .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );
    }

    #[test]
    fn cumulative_budgets_refuse_recursive_scanning_and_copy_amplification() {
        let encoded = recursively_nested_single_item_tuple(7, 1_024);
        let cumulative_work_byte_length = encoded
            .len()
            .checked_mul(2)
            .expect("test budget multiplication does not overflow");
        let limits = CanonicalDecodeLimits {
            maximum_cumulative_work_byte_length: cumulative_work_byte_length,
            ..CanonicalDecodeLimits::default()
        };

        let error = CanonicalTuple::decode(&encoded, &limits)
            .expect_err("recursive rescanning must consume one shared work budget");
        assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(
            error.message,
            "canonical decoding exceeds the configured cumulative work limit"
        );

        let allocation_encoded = recursively_nested_single_item_tuple(7, 1_024);
        let cumulative_allocation_byte_length = allocation_encoded
            .len()
            .checked_mul(2)
            .expect("test budget multiplication does not overflow");
        let limits = CanonicalDecodeLimits {
            maximum_cumulative_allocation_byte_length: cumulative_allocation_byte_length,
            ..CanonicalDecodeLimits::default()
        };

        let error = CanonicalTuple::decode(&allocation_encoded, &limits)
            .expect_err("recursive copying must consume one shared allocation budget");
        assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(
            error.message,
            "canonical decoding exceeds the configured cumulative allocation limit"
        );
    }

    #[test]
    fn cumulative_budgets_enforce_exact_flat_decode_boundaries() {
        let encoded = unchecked_single_item_tuple(CanonicalItemType::Unsigned8, &[7]);
        let before_item_validation_limit = CanonicalDecodeLimits {
            maximum_cumulative_work_byte_length: encoded.len() - 1,
            ..CanonicalDecodeLimits::default()
        };
        let work_error = CanonicalTuple::decode(&encoded, &before_item_validation_limit)
            .expect_err("item validation work must be precharged");
        assert_eq!(work_error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(work_error.byte_offset, 14);

        let exact_work_limit = CanonicalDecodeLimits {
            maximum_cumulative_work_byte_length: encoded.len(),
            ..CanonicalDecodeLimits::default()
        };
        CanonicalTuple::decode(&encoded, &exact_work_limit)
            .expect("the exact cumulative work boundary must decode");

        let before_item_storage_limit = CanonicalDecodeLimits {
            maximum_cumulative_allocation_byte_length: CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH
                - 1,
            ..CanonicalDecodeLimits::default()
        };
        let storage_error = CanonicalTuple::decode(&encoded, &before_item_storage_limit)
            .expect_err("item storage allocation must be precharged");
        assert_eq!(storage_error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(storage_error.byte_offset, 4);

        let before_item_copy_limit = CanonicalDecodeLimits {
            maximum_cumulative_allocation_byte_length:
                CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH,
            ..CanonicalDecodeLimits::default()
        };
        let copy_error = CanonicalTuple::decode(&encoded, &before_item_copy_limit)
            .expect_err("item byte copying must be precharged");
        assert_eq!(copy_error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(copy_error.byte_offset, 14);

        let exact_limit = CanonicalDecodeLimits {
            maximum_cumulative_allocation_byte_length: CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH
                + 1,
            ..CanonicalDecodeLimits::default()
        };
        CanonicalTuple::decode(&encoded, &exact_limit)
            .expect("the exact logical allocation boundary must decode");
    }

    #[test]
    fn prefix_decodes_share_one_cumulative_budget() {
        let encoded = unchecked_single_item_tuple(CanonicalItemType::Unsigned8, &[7]);
        let limits = CanonicalDecodeLimits {
            maximum_cumulative_work_byte_length: encoded.len(),
            ..CanonicalDecodeLimits::default()
        };
        let mut budget = CanonicalDecodeBudget::new(&limits);

        CanonicalTuple::decode_prefix(&encoded, &limits, &mut budget, 1)
            .expect("the first prefix consumes the exact work budget");
        let error = CanonicalTuple::decode_prefix(&encoded, &limits, &mut budget, 1)
            .expect_err("a second prefix must not receive a fresh work budget");

        assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(error.byte_offset, 0);
        assert_eq!(
            error.message,
            "canonical decoding exceeds the configured cumulative work limit"
        );
    }

    #[test]
    fn constructors_do_not_emit_values_the_default_decoder_refuses() {
        let too_many_values = vec![
            CanonicalItem::unsigned8(0);
            CanonicalDecodeLimits::default().maximum_item_count + 1
        ];
        assert_eq!(
            CanonicalItem::homogeneous_list(CanonicalItemType::Unsigned8, &too_many_values)
                .expect_err("oversized list must refuse")
                .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );

        let too_many_items = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::unsigned8(0);
                CanonicalDecodeLimits::default().maximum_item_count + 1
            ],
        );
        assert_eq!(
            too_many_items
                .encode()
                .expect_err("oversized tuple must refuse")
                .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );

        let maximum_item_byte_length = CanonicalDecodeLimits::default().maximum_item_byte_length;
        assert_eq!(
            CanonicalItem::variable_bytes(vec![0; maximum_item_byte_length])
                .expect_err("inner length framing must be charged before allocation")
                .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );

        let maximum_fixed_item = CanonicalItem::fixed_bytes(vec![0; maximum_item_byte_length])
            .expect("the fixed value itself is exactly at the limit");
        assert_eq!(
            CanonicalItem::optional(CanonicalItemType::RawBytes, Some(&maximum_fixed_item))
                .expect_err("optional framing must be charged before allocation")
                .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );

        let half_limit_item = CanonicalItem::fixed_bytes(vec![0; maximum_item_byte_length / 2])
            .expect("half-limit item");
        assert_eq!(
            CanonicalItem::homogeneous_list(
                CanonicalItemType::RawBytes,
                &[half_limit_item.clone(), half_limit_item],
            )
            .expect_err("list framing must be charged before allocation")
            .kind,
            CanonicalCodecErrorKind::LimitExceeded
        );
    }

    #[test]
    fn incremental_decoder_round_trips_across_every_two_fragment_boundary() {
        let tuple = CanonicalTuple::new(
            0x0110,
            1,
            vec![
                CanonicalItem::nested_tuple(&representative_tuple())
                    .expect("nested representative tuple"),
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::Ascii,
                    &[
                        CanonicalItem::ascii("first").expect("first ASCII item"),
                        CanonicalItem::ascii("second").expect("second ASCII item"),
                        CanonicalItem::ascii("third").expect("third ASCII item"),
                    ],
                )
                .expect("ASCII list"),
                CanonicalItem::boolean(true),
            ],
        );
        let encoded = tuple.encode().expect("tuple encodes");
        let limits = CanonicalDecodeLimits::default();

        for split_offset in 0..=encoded.len() {
            let decoded = CanonicalTuple::decode_fragments(
                encoded.len(),
                [&encoded[..split_offset], &encoded[split_offset..]],
                &limits,
            )
            .unwrap_or_else(|error| panic!("fragment split {split_offset} must decode: {error}"));
            assert_eq!(decoded, tuple, "fragment split {split_offset}");
        }

        let decoded_one_byte_at_a_time =
            CanonicalTuple::decode_fragments(encoded.len(), encoded.chunks(1), &limits)
                .expect("one-byte fragments decode");
        assert_eq!(decoded_one_byte_at_a_time, tuple);
    }

    #[test]
    fn incremental_decoder_refuses_the_same_structural_mutations_as_flat_decode() {
        let limits = CanonicalDecodeLimits::default();
        let canonical = unchecked_single_item_tuple(CanonicalItemType::Boolean, &[1]);
        let mut mutations = Vec::new();

        let mut unknown_item_type = canonical.clone();
        unknown_item_type[8..10].copy_from_slice(&0xffff_u16.to_le_bytes());
        mutations.push(unknown_item_type);

        let mut invalid_boolean = canonical.clone();
        *invalid_boolean.last_mut().expect("boolean byte") = 2;
        mutations.push(invalid_boolean);

        let mut oversized_item = canonical.clone();
        oversized_item[10..14].copy_from_slice(
            &u32::try_from(limits.maximum_item_byte_length + 1)
                .expect("test item bound fits u32")
                .to_le_bytes(),
        );
        mutations.push(oversized_item);

        let mut trailing = canonical;
        trailing.push(0);
        mutations.push(trailing);

        for mutation in mutations {
            let flat_error = CanonicalTuple::decode(&mutation, &limits)
                .expect_err("structural mutation must be refused");
            let mut incremental_decoder =
                IncrementalCanonicalTupleDecoder::new(mutation.len(), &limits)
                    .expect("mutation length is within the tuple limit");
            let incremental_error = mutation
                .chunks(1)
                .find_map(|fragment| incremental_decoder.absorb(fragment).err())
                .unwrap_or_else(|| {
                    incremental_decoder
                        .finish()
                        .expect_err("structural mutation must be refused at finish")
                });
            assert_eq!(incremental_error.kind, flat_error.kind);
            assert_eq!(incremental_error.byte_offset, flat_error.byte_offset);
        }
    }

    #[test]
    fn incremental_decoder_refuses_every_truncated_prefix_without_panicking() {
        let encoded = representative_tuple()
            .encode()
            .expect("representative tuple encodes");
        let limits = CanonicalDecodeLimits::default();

        for prefix_byte_length in 8..encoded.len() {
            let mut decoder = IncrementalCanonicalTupleDecoder::new(encoded.len(), &limits)
                .expect("declared tuple length is valid");
            let absorb_result = decoder.absorb(&encoded[..prefix_byte_length]);
            if absorb_result.is_ok() {
                let error = decoder
                    .finish()
                    .expect_err("a truncated prefix must not finish");
                assert_eq!(error.kind, CanonicalCodecErrorKind::Truncated);
                assert!(error.byte_offset <= prefix_byte_length);
            } else {
                assert_eq!(
                    absorb_result.expect_err("prefix is refused").kind,
                    CanonicalCodecErrorKind::Truncated
                );
            }
        }
    }

    #[test]
    fn incremental_decoder_enforces_declared_length_and_allocation_before_copying() {
        let encoded = unchecked_single_item_tuple(CanonicalItemType::RawBytes, &[0x5a; 32]);
        let limits = CanonicalDecodeLimits {
            maximum_cumulative_allocation_byte_length: CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH
                + 31,
            ..CanonicalDecodeLimits::default()
        };
        let mut decoder = IncrementalCanonicalTupleDecoder::new(encoded.len(), &limits)
            .expect("tuple length is valid");
        let error = decoder
            .absorb(&encoded[..14])
            .expect_err("declared item allocation exceeds the remaining budget");
        assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
        assert_eq!(error.byte_offset, 14);

        let canonical = representative_tuple()
            .encode()
            .expect("representative tuple encodes");
        let mut exact_length_decoder = IncrementalCanonicalTupleDecoder::new(
            canonical.len(),
            &CanonicalDecodeLimits::default(),
        )
        .expect("tuple length is valid");
        let error = exact_length_decoder
            .absorb(&[canonical.as_slice(), &[0]].concat())
            .expect_err("bytes beyond the declared length must be refused");
        assert_eq!(error.kind, CanonicalCodecErrorKind::TrailingBytes);
        assert_eq!(error.byte_offset, canonical.len());
    }

    #[test]
    fn deterministic_hostile_byte_corpus_never_panics_and_successes_are_canonical() {
        fn next_pseudorandom(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }

        let canonical_seed = representative_tuple()
            .encode()
            .expect("representative tuple encodes");
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: 4_096,
            maximum_item_count: 256,
            maximum_item_byte_length: 2_048,
            maximum_cumulative_work_byte_length: 8_192,
            maximum_cumulative_allocation_byte_length: 8_192,
            maximum_nesting_depth: 16,
        };
        let mut pseudorandom_state = 0x7365_616c_6564_4c31_u64;

        for case_index in 0..4_096_usize {
            let mut candidate = if case_index % 2 == 0 {
                canonical_seed.clone()
            } else {
                let byte_length =
                    usize::try_from(next_pseudorandom(&mut pseudorandom_state) % 2_049)
                        .expect("bounded corpus length fits usize");
                (0..byte_length)
                    .map(|_| next_pseudorandom(&mut pseudorandom_state).to_le_bytes()[0])
                    .collect::<Vec<_>>()
            };

            if !candidate.is_empty() {
                let mutation_count =
                    1 + usize::try_from(next_pseudorandom(&mut pseudorandom_state) % 4)
                        .expect("bounded mutation count fits usize");
                for _ in 0..mutation_count {
                    let mutation_index = usize::try_from(
                        next_pseudorandom(&mut pseudorandom_state)
                            % u64::try_from(candidate.len()).expect("candidate length fits u64"),
                    )
                    .expect("bounded mutation index fits usize");
                    candidate[mutation_index] ^=
                        next_pseudorandom(&mut pseudorandom_state).to_le_bytes()[0];
                }
            }

            let decode_outcome =
                std::panic::catch_unwind(|| CanonicalTuple::decode(&candidate, &limits));
            let decoded = decode_outcome.expect("hostile canonical input must never panic");
            if let Ok(tuple) = decoded {
                assert_eq!(
                    tuple.encode().expect("accepted tuple re-encodes"),
                    candidate,
                    "every accepted byte string must already be canonical"
                );
            }
        }
    }
}
