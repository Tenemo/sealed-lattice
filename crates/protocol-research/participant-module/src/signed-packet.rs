//! The signed packets the participant emits and restores: a body after its
//! four-byte length, then its signature.
use protocol_foundations::{
    SIGNATURE_BYTES,
    setup_selection::{ENDORSEMENT_BYTES, MAXIMUM_SELECTION_BYTES},
};

pub(crate) fn encode(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut output = Vec::from((body.len() as u32).to_le_bytes());
    output.extend(body);
    output.extend(signature);
    output
}

/// A signed selection proposal's body and signature.
pub(crate) fn selection(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if length > MAXIMUM_SELECTION_BYTES || bytes.len() != 4 + length + SIGNATURE_BYTES {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
}

/// A signed selection proposal's body and signature, then an endorsement of
/// that selection.
pub(crate) fn endorsed_selection(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let (packet, endorsement) =
        bytes.split_at_checked(bytes.len().checked_sub(ENDORSEMENT_BYTES)?)?;
    let (body, signature) = selection(packet)?;
    Some((body, signature, endorsement))
}

#[cfg(test)]
#[path = "signed-packet-tests.rs"]
mod tests;
