//! Purpose-labelled identities through the sole foundation SHAKE256 framing.

use crate::{
    Error,
    foundation::{CanonicalItem, hash::StreamingFoundationTupleHash512},
};

/// The identity of a public polynomial in its canonical coefficient
/// encoding: a setup aggregate, a common polynomial, or a key polynomial read
/// back before use.
pub const PUBLIC_POLYNOMIAL_DOMAIN: &str = "sealed-lattice/public-polynomial/v1";

/// Computes `H_512(domain, prefix..., bytes(payload))` over a payload whose
/// length is committed before absorption.
pub struct IdentityHasher {
    hash: StreamingFoundationTupleHash512,
}
impl IdentityHasher {
    pub fn new(domain: &str, prefix: &[CanonicalItem], length: usize) -> Result<Self, Error> {
        StreamingFoundationTupleHash512::new_variable_bytes(domain, prefix, length)
            .map(|hash| Self { hash })
            .map_err(|_| Error::Shape)
    }
    pub fn absorb(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.hash.absorb(bytes).map_err(|_| Error::Shape)
    }
    pub fn finish(self) -> Result<[u8; 64], Error> {
        self.hash
            .finalize()
            .map(|hash| hash.into_bytes())
            .map_err(|_| Error::Shape)
    }
}

/// The identity of one complete payload without prefix items.
pub fn identity(domain: &str, bytes: &[u8]) -> Result<[u8; 64], Error> {
    let mut hasher = IdentityHasher::new(domain, &[], bytes.len())?;
    hasher.absorb(bytes)?;
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::hash_foundation_tuple_512;

    fn hexadecimal(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn matches_the_foundation_tuple_hash_in_any_fragmentation() {
        let payload: Vec<u8> = (0..1000_u32)
            .map(|index| (index * 37 % 251) as u8)
            .collect();
        let prefix = [
            CanonicalItem::hash512([7; 64]),
            CanonicalItem::unsigned64(9),
        ];
        let mut items = prefix.to_vec();
        items.push(CanonicalItem::variable_bytes(&payload).unwrap());
        let expected = hash_foundation_tuple_512(PUBLIC_POLYNOMIAL_DOMAIN, &items)
            .unwrap()
            .into_bytes();
        for fragment in [1, 17, 999, 1000] {
            let mut hasher =
                IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &prefix, payload.len()).unwrap();
            for part in payload.chunks(fragment) {
                hasher.absorb(part).unwrap();
            }
            assert_eq!(hasher.finish().unwrap(), expected);
        }
    }

    #[test]
    fn matches_independent_shake256_vectors() {
        // SHAKE256 over the canonical tuple, computed outside Rust.
        assert_eq!(
            hexadecimal(&identity(PUBLIC_POLYNOMIAL_DOMAIN, b"").unwrap()),
            "c43f773788c6d66f30eb39ee7230312ad8dda3e5cbb3205075377d824eaa781d54b6dd3661553cb3c64ece7bd15a6df92fdd901b2ba81ae35334879f69fdf8a4"
        );
        assert_eq!(
            hexadecimal(&identity(PUBLIC_POLYNOMIAL_DOMAIN, &[0, 1, 2, 255]).unwrap()),
            "83d5019a3cb3292618bc674220dc584994c5db0e304ca47d144c6d1af27787cfb42ff63a9170c5e3c1761432f27adab775f8d7a047549e66c6b89a79f52c2b11"
        );
    }

    #[test]
    fn refuses_a_short_long_or_empty_domain_payload() {
        let mut hasher = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], 2).unwrap();
        hasher.absorb(&[1]).unwrap();
        assert!(hasher.absorb(&[2, 3]).is_err());
        let mut short = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], 2).unwrap();
        short.absorb(&[1]).unwrap();
        assert!(short.finish().is_err());
        assert!(IdentityHasher::new("", &[], 0).is_err());
    }
}
