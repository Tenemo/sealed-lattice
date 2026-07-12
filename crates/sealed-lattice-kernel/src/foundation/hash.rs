use core::fmt;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalTuple,
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
pub fn hash512(domain: &str, items: &[CanonicalItem]) -> Result<Hash512, CanonicalCodecError> {
    let mut framed_items = Vec::with_capacity(items.len().saturating_add(1));
    framed_items.push(CanonicalItem::nonempty_ascii(domain)?);
    framed_items.extend_from_slice(items);
    let framed_bytes = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        framed_items,
    )
    .encode()?;

    let mut hasher = Shake256::default();
    hasher.update(&framed_bytes);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; Hash512::BYTE_LENGTH];
    reader.read(&mut output);
    Ok(Hash512(output))
}

#[cfg(test)]
mod tests {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    #[test]
    fn hash_uses_exact_typed_tuple_framing() {
        let items = [
            CanonicalItem::unsigned16(0x0201),
            CanonicalItem::variable_bytes([7, 8, 9]).expect("raw bytes fit u32"),
        ];
        let actual = hash512("sealed-lattice/test/hash/v1", &items).expect("hash input is valid");

        let mut expected_frame = Vec::new();
        expected_frame.extend_from_slice(&0x0001_u16.to_le_bytes());
        expected_frame.extend_from_slice(&1_u16.to_le_bytes());
        expected_frame.extend_from_slice(&3_u32.to_le_bytes());
        let domain = b"sealed-lattice/test/hash/v1";
        expected_frame.extend_from_slice(&0x02_u16.to_le_bytes());
        expected_frame.extend_from_slice(&((domain.len() + 4) as u32).to_le_bytes());
        expected_frame.extend_from_slice(&(domain.len() as u32).to_le_bytes());
        expected_frame.extend_from_slice(domain);
        expected_frame.extend_from_slice(&0x03_u16.to_le_bytes());
        expected_frame.extend_from_slice(&2_u32.to_le_bytes());
        expected_frame.extend_from_slice(&0x0201_u16.to_le_bytes());
        expected_frame.extend_from_slice(&0x01_u16.to_le_bytes());
        expected_frame.extend_from_slice(&7_u32.to_le_bytes());
        expected_frame.extend_from_slice(&3_u32.to_le_bytes());
        expected_frame.extend_from_slice(&[7, 8, 9]);

        let mut hasher = Shake256::default();
        hasher.update(&expected_frame);
        let mut reader = hasher.finalize_xof();
        let mut expected = [0u8; 64];
        reader.read(&mut expected);
        assert_eq!(actual, Hash512::from_bytes(expected));
        assert_eq!(actual.to_lowercase_hex().len(), 128);
    }

    #[test]
    fn domain_and_item_boundaries_cannot_alias() {
        let first = hash512(
            "sealed-lattice/test/a",
            &[CanonicalItem::variable_bytes(b"bc").expect("raw bytes")],
        )
        .expect("hash");
        let second = hash512(
            "sealed-lattice/test/ab",
            &[CanonicalItem::variable_bytes(b"c").expect("raw bytes")],
        )
        .expect("hash");
        let split = hash512(
            "sealed-lattice/test/a",
            &[
                CanonicalItem::variable_bytes(b"b").expect("raw bytes"),
                CanonicalItem::variable_bytes(b"c").expect("raw bytes"),
            ],
        )
        .expect("hash");
        assert_ne!(first, second);
        assert_ne!(first, split);
        assert_ne!(second, split);
    }

    #[test]
    fn empty_or_non_printable_domains_refuse() {
        assert!(hash512("", &[]).is_err());
        assert!(hash512("sealed-lattice/test\n", &[]).is_err());
    }
}
