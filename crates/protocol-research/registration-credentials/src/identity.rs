//! Purpose-labelled identities through the sole foundation SHAKE256 framing.

use crate::{
    Error,
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    },
};
use parallel_work::{HashStream, PendingDigest, Sponge};

/// The identity of a public polynomial in its canonical coefficient
/// encoding: a setup aggregate, a common polynomial, or a key polynomial read
/// back before use.
pub const PUBLIC_POLYNOMIAL_DOMAIN: &str = "sealed-lattice/public-polynomial/v1";

/// Computes `H_512(domain, prefix..., bytes(payload))` over a payload whose
/// length is committed before absorption.
pub struct IdentityHasher {
    hash: HashStream,
    remaining: usize,
}
impl IdentityHasher {
    /// A hasher whose sponge runs on a helper when there are helpers, for a
    /// caller that does other work between its parts.
    pub fn new(domain: &str, prefix: &[CanonicalItem], length: usize) -> Result<Self, Error> {
        Self::with_stream(HashStream::new(Sponge::Shake256), domain, prefix, length)
    }
    /// A hasher whose sponge runs here, for a caller that waits for the
    /// identity right after its last part.
    pub fn local(domain: &str, prefix: &[CanonicalItem], length: usize) -> Result<Self, Error> {
        Self::with_stream(HashStream::local(Sponge::Shake256), domain, prefix, length)
    }
    fn with_stream(
        mut hash: HashStream,
        domain: &str,
        prefix: &[CanonicalItem],
        length: usize,
    ) -> Result<Self, Error> {
        hash.update(&framing(domain, prefix, length)?);
        Ok(Self {
            hash,
            remaining: length,
        })
    }
    pub fn absorb(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.remaining {
            return Err(Error::Shape);
        }
        self.hash.update(bytes);
        self.remaining -= bytes.len();
        Ok(())
    }
    pub fn finish(self) -> Result<[u8; 64], Error> {
        Ok(self.finish_later()?.wait())
    }
    /// Starts the identity without waiting for it, for a caller whose work
    /// goes on while a helper finishes the sponge.
    pub fn finish_later(self) -> Result<PendingDigest, Error> {
        if self.remaining != 0 {
            return Err(Error::Shape);
        }
        Ok(self.hash.finish_later())
    }
}

/// The canonical tuple framing that precedes a payload of the length: the
/// tuple of the domain, the prefix items and an empty raw-byte item, whose
/// two trailing length words become the payload's.
fn framing(domain: &str, prefix: &[CanonicalItem], length: usize) -> Result<Vec<u8>, Error> {
    let item_length = length
        .checked_add(4)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(Error::Shape)?;
    let payload_length = u32::try_from(length).map_err(|_| Error::Shape)?;
    let mut items = Vec::with_capacity(prefix.len() + 2);
    items.push(CanonicalItem::nonempty_ascii(domain).map_err(|_| Error::Shape)?);
    items.extend_from_slice(prefix);
    items.push(CanonicalItem::variable_bytes([]).map_err(|_| Error::Shape)?);
    let mut framing = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        items,
    )
    .encode()
    .map_err(|_| Error::Shape)?;
    let end = framing.len();
    framing[end - 8..end - 4].copy_from_slice(&item_length.to_le_bytes());
    framing[end - 4..].copy_from_slice(&payload_length.to_le_bytes());
    Ok(framing)
}

/// The identity of one complete payload without prefix items.
pub fn identity(domain: &str, bytes: &[u8]) -> Result<[u8; 64], Error> {
    let mut hasher = IdentityHasher::local(domain, &[], bytes.len())?;
    hasher.absorb(bytes)?;
    hasher.finish()
}

#[cfg(test)]
#[path = "identity-tests.rs"]
mod tests;
