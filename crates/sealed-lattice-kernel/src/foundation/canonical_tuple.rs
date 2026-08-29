use core::fmt;

pub const CANONICAL_TUPLE_SCHEMA_IDENTIFIER: u16 = 0x0001;
pub const CANONICAL_TUPLE_VERSION: u16 = 1;
const ABSOLUTE_MAXIMUM_NESTING_DEPTH: u16 = 64;
const DEFAULT_MAXIMUM_CUMULATIVE_WORK_BYTE_LENGTH: usize = 64 * 1024 * 1024;
const DEFAULT_MAXIMUM_CUMULATIVE_ALLOCATION_BYTE_LENGTH: usize = 64 * 1024 * 1024;
// Keep allocation accounting independent of native pointer width so the same
// configured limit accepts and refuses the same canonical bytes under WASM.
pub(in crate::foundation) const CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH: usize = 32;

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
pub(in crate::foundation) struct CanonicalDecodeBudget {
    remaining_work_byte_length: usize,
    remaining_allocation_byte_length: usize,
}

impl CanonicalDecodeBudget {
    pub(in crate::foundation) const fn new(limits: &CanonicalDecodeLimits) -> Self {
        Self {
            remaining_work_byte_length: limits.maximum_cumulative_work_byte_length,
            remaining_allocation_byte_length: limits.maximum_cumulative_allocation_byte_length,
        }
    }

    pub(in crate::foundation) fn charge_work(
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

    pub(in crate::foundation) fn charge_allocation(
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

mod decoding;
mod value;

pub use value::{CanonicalItem, CanonicalItemType, CanonicalTuple};

#[cfg(test)]
#[path = "canonical_tuple/tests.rs"]
mod tests;
