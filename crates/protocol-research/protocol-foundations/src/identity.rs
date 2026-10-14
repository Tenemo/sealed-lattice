//! Purpose-labelled SHAKE256 identities over the foundation's canonical tuple framing.

use crate::{
    Refusal,
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem,
        CanonicalItemType, CanonicalTuple,
    },
};
use parallel_work::{CHUNK_LIMIT, HashStream, PendingDigest, Sponge};

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
    pub fn new(domain: &str, prefix: &[CanonicalItem], length: usize) -> Result<Self, Refusal> {
        Self::with_stream(HashStream::new(Sponge::Shake256), domain, prefix, length)
    }
    /// A hasher whose sponge runs here, for a caller that waits for the
    /// identity right after its last part.
    pub fn local(domain: &str, prefix: &[CanonicalItem], length: usize) -> Result<Self, Refusal> {
        Self::with_stream(HashStream::local(Sponge::Shake256), domain, prefix, length)
    }
    fn with_stream(
        mut hash: HashStream,
        domain: &str,
        prefix: &[CanonicalItem],
        length: usize,
    ) -> Result<Self, Refusal> {
        hash.update(&framing(domain, prefix, Trailing::Variable(length))?);
        Ok(Self {
            hash,
            remaining: length,
        })
    }
    pub fn absorb(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if bytes.len() > self.remaining {
            return Err(Refusal::Shape);
        }
        self.hash.update(bytes);
        self.remaining -= bytes.len();
        Ok(())
    }
    pub fn finish(self) -> Result<[u8; 64], Refusal> {
        Ok(self.finish_later()?.wait())
    }
    /// Starts the identity without waiting for it, for a caller whose work
    /// goes on while a helper finishes the sponge.
    pub fn finish_later(self) -> Result<PendingDigest, Refusal> {
        if self.remaining != 0 {
            return Err(Refusal::Shape);
        }
        Ok(self.hash.finish_later())
    }
}

/// Hashes a body of a committed length, pushed in nonempty parts of at most
/// `CHUNK_LIMIT` bytes, into its exact framed byte identity. A refused part
/// consumes the hasher. The identity supplies no proof or signing authority.
pub struct BodyHasher(Option<IdentityHasher>);
impl BodyHasher {
    pub(crate) fn new(domain: &str, length: usize) -> Result<Self, Refusal> {
        IdentityHasher::local(domain, &[], length).map(|hash| Self(Some(hash)))
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let hash = self.0.as_mut().ok_or(Refusal::Consumed)?;
        if bytes.is_empty() || bytes.len() > CHUNK_LIMIT || hash.absorb(bytes).is_err() {
            self.0 = None;
            return Err(Refusal::Shape);
        }
        Ok(())
    }
    pub fn finish(self) -> Result<[u8; 64], Refusal> {
        self.0.ok_or(Refusal::Consumed)?.finish()
    }
}

/// The raw-byte item a framed payload fills: a fixed item of exactly the
/// payload's length, or a variable one whose value leads with that length.
#[derive(Clone, Copy, Debug)]
pub enum Trailing {
    Fixed(usize),
    Variable(usize),
}

/// The canonical tuple framing that precedes a payload: the tuple of the
/// domain, the prefix items and the trailing raw-byte item, up to the point
/// where the payload's own bytes begin. A caller absorbs the framing and then
/// the payload, so a private payload is never copied.
pub fn framing(
    domain: &str,
    prefix: &[CanonicalItem],
    trailing: Trailing,
) -> Result<Vec<u8>, Refusal> {
    let word = |value: usize| u32::try_from(value).map_err(|_| Refusal::Shape);
    let mut items = Vec::with_capacity(prefix.len() + 1);
    items.push(CanonicalItem::nonempty_ascii(domain).map_err(|_| Refusal::Shape)?);
    items.extend_from_slice(prefix);
    let count = word(items.len() + 1)?;
    let mut framing = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        items,
    )
    .encode()
    .map_err(|_| Refusal::Shape)?;
    framing[4..8].copy_from_slice(&count.to_le_bytes());
    framing.extend_from_slice(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    match trailing {
        Trailing::Fixed(length) => framing.extend_from_slice(&word(length)?.to_le_bytes()),
        Trailing::Variable(length) => {
            let item_length = length.checked_add(4).ok_or(Refusal::Shape)?;
            framing.extend_from_slice(&word(item_length)?.to_le_bytes());
            framing.extend_from_slice(&word(length)?.to_le_bytes());
        }
    }
    Ok(framing)
}

/// The identity of one complete payload without prefix items.
pub fn identity(domain: &str, bytes: &[u8]) -> Result<[u8; 64], Refusal> {
    let mut hasher = IdentityHasher::local(domain, &[], bytes.len())?;
    hasher.absorb(bytes)?;
    hasher.finish()
}

#[cfg(test)]
#[path = "identity-tests.rs"]
mod tests;
