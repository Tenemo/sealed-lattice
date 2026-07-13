use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::to_hex;

pub fn encode_hex(bytes: &[u8]) -> String {
    to_hex(bytes)
}

fn decode_lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn decode_hex(hex: &str) -> CanonicalResult<Vec<u8>> {
    let hex_bytes = hex.as_bytes();
    if !hex_bytes.len().is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "hex string must have an even length",
        ));
    }

    let mut bytes = Vec::with_capacity(hex_bytes.len() / 2);
    for pair in hex_bytes.chunks_exact(2) {
        let high = decode_lower_hex_nibble(pair[0]).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidHex,
                "hex string must use lowercase hexadecimal bytes",
            )
        })?;
        let low = decode_lower_hex_nibble(pair[1]).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidHex,
                "hex string must use lowercase hexadecimal bytes",
            )
        })?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}
