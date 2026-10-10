use core::fmt;

use super::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalTuple,
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

#[cfg(test)]
#[path = "hash-tests.rs"]
mod tests;
