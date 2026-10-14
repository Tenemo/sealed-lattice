//! A signed packet: a body after its four-byte little-endian length, then the
//! body's signature. The framing authenticates nothing; the caller verifies
//! the signature over the body it returns.

use crate::SIGNATURE_BYTES;

pub fn encode(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + body.len() + signature.len());
    packet.extend((body.len() as u32).to_le_bytes());
    packet.extend(body);
    packet.extend(signature);
    packet
}

/// The body, the signature and the bytes after them of the packet that opens
/// the bytes, if its body is at most `maximum` bytes long.
pub fn leading(bytes: &[u8], maximum: usize) -> Option<(&[u8], &[u8], &[u8])> {
    let (length, rest) = bytes.split_first_chunk::<4>()?;
    let length = u32::from_le_bytes(*length) as usize;
    // The bound comes first, so no sum of lengths can overflow on wasm32.
    if length > maximum {
        return None;
    }
    let (body, rest) = rest.split_at_checked(length)?;
    let (signature, rest) = rest.split_at_checked(SIGNATURE_BYTES)?;
    Some((body, signature, rest))
}

/// The body and signature of a packet that fills the bytes exactly.
pub fn split(bytes: &[u8], maximum: usize) -> Option<(&[u8], &[u8])> {
    match leading(bytes, maximum)? {
        (body, signature, []) => Some((body, signature)),
        _ => None,
    }
}

#[cfg(test)]
#[path = "signed-packet-tests.rs"]
mod tests;
