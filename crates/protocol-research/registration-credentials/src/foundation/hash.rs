use core::fmt;

use super::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalItemType, CanonicalTuple,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash512([u8; 64]);

impl Hash512 {
    pub const BYTE_LENGTH: usize = 64;

    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }

    pub fn to_lowercase_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(128);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl fmt::Debug for Hash512 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Hash512")
            .field(&self.to_lowercase_hex())
            .finish()
    }
}

impl fmt::Display for Hash512 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_lowercase_hex())
    }
}

/// Hashes typed items through the sole foundation SHAKE256 framing.
pub fn hash_foundation_tuple_512(
    domain: &str,
    items: &[CanonicalItem],
) -> Result<Hash512, CanonicalCodecError> {
    let hasher = foundation_tuple_hasher(domain, items)?;
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; Hash512::BYTE_LENGTH];
    reader.read(&mut output);
    Ok(Hash512(output))
}

fn foundation_tuple_hasher(
    domain: &str,
    items: &[CanonicalItem],
) -> Result<Shake256, CanonicalCodecError> {
    let framed_bytes = canonical_foundation_tuple_hash_preimage(domain, items)?;

    let mut hasher = Shake256::default();
    hasher.update(&framed_bytes);
    Ok(hasher)
}

fn canonical_foundation_tuple_hash_preimage(
    domain: &str,
    items: &[CanonicalItem],
) -> Result<Vec<u8>, CanonicalCodecError> {
    let mut framed_items = Vec::with_capacity(items.len().saturating_add(1));
    framed_items.push(CanonicalItem::nonempty_ascii(domain)?);
    framed_items.extend_from_slice(items);
    CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        framed_items,
    )
    .encode()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamingFoundationHashError {
    InvalidDomain,
    ItemCountOverflow,
    ItemLengthOverflow,
    PayloadOverrun,
    PayloadIncomplete,
}

/// Incremental form of `H_512(domain, prefixItems..., bytes(payload))`.
///
/// The tuple and raw-byte item lengths are committed before payload absorption.
/// This matches [`hash_foundation_tuple_512`] without another payload allocation.
pub(crate) struct StreamingFoundationTupleHash512 {
    hasher: Shake256,
    remaining_payload_byte_length: usize,
}

impl StreamingFoundationTupleHash512 {
    pub(crate) fn new_variable_bytes(
        domain: &str,
        prefix_items: &[CanonicalItem],
        payload_byte_length: usize,
    ) -> Result<Self, StreamingFoundationHashError> {
        let domain_item = CanonicalItem::nonempty_ascii(domain)
            .map_err(|_| StreamingFoundationHashError::InvalidDomain)?;
        let item_count = prefix_items
            .len()
            .checked_add(2)
            .ok_or(StreamingFoundationHashError::ItemCountOverflow)?;
        let item_count = u32::try_from(item_count)
            .map_err(|_| StreamingFoundationHashError::ItemCountOverflow)?;
        let payload_byte_length_u32 = u32::try_from(payload_byte_length)
            .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
        let streamed_item_byte_length = payload_byte_length
            .checked_add(4)
            .ok_or(StreamingFoundationHashError::ItemLengthOverflow)?;
        let streamed_item_byte_length_u32 = u32::try_from(streamed_item_byte_length)
            .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;

        let mut hasher = Shake256::default();
        hasher.update(&CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
        hasher.update(&CANONICAL_TUPLE_VERSION.to_le_bytes());
        hasher.update(&item_count.to_le_bytes());
        update_canonical_hash_item(&mut hasher, &domain_item)?;
        for item in prefix_items {
            update_canonical_hash_item(&mut hasher, item)?;
        }
        hasher.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
        hasher.update(&streamed_item_byte_length_u32.to_le_bytes());
        hasher.update(&payload_byte_length_u32.to_le_bytes());
        Ok(Self {
            hasher,
            remaining_payload_byte_length: payload_byte_length,
        })
    }

    pub(crate) fn absorb(
        &mut self,
        payload_fragment: &[u8],
    ) -> Result<(), StreamingFoundationHashError> {
        if payload_fragment.len() > self.remaining_payload_byte_length {
            return Err(StreamingFoundationHashError::PayloadOverrun);
        }
        self.hasher.update(payload_fragment);
        self.remaining_payload_byte_length -= payload_fragment.len();
        Ok(())
    }

    pub(crate) fn finalize(self) -> Result<Hash512, StreamingFoundationHashError> {
        if self.remaining_payload_byte_length != 0 {
            return Err(StreamingFoundationHashError::PayloadIncomplete);
        }
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0_u8; Hash512::BYTE_LENGTH];
        reader.read(&mut output);
        Ok(Hash512(output))
    }
}

fn update_canonical_hash_item(
    hasher: &mut Shake256,
    item: &CanonicalItem,
) -> Result<(), StreamingFoundationHashError> {
    let byte_length = u32::try_from(item.canonical_bytes().len())
        .map_err(|_| StreamingFoundationHashError::ItemLengthOverflow)?;
    hasher.update(&item.item_type().canonical_code().to_le_bytes());
    hasher.update(&byte_length.to_le_bytes());
    hasher.update(item.canonical_bytes());
    Ok(())
}

#[cfg(test)]
#[path = "hash-tests.rs"]
mod tests;
