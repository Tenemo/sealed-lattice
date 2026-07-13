use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::to_hex;

pub fn encode_hex(bytes: &[u8]) -> String {
    to_hex(bytes)
}

// Canonical standard-base64 decoder: fixed four-byte chunks, padding only in
// the final chunk, and zeroed padding bits, so exactly one encoding maps to
// each byte string and transported proof bytes stay canonically bound.
#[cfg(test)]
pub fn decode_standard_base64(encoded: &str, field_name: &str) -> CanonicalResult<Vec<u8>> {
    let encoded_bytes = encoded.as_bytes();
    if !encoded_bytes.len().is_multiple_of(4) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} length must be a multiple of four"),
        ));
    }

    let mut decoded = Vec::with_capacity(encoded_bytes.len() / 4 * 3);
    for (chunk_index, chunk) in encoded_bytes.chunks_exact(4).enumerate() {
        let is_final_chunk = (chunk_index + 1) * 4 == encoded_bytes.len();
        let first = decode_standard_base64_digit(chunk[0], field_name)?;
        let second = decode_standard_base64_digit(chunk[1], field_name)?;

        match (chunk[2], chunk[3]) {
            (b'=', b'=') => {
                if !is_final_chunk {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} padding must appear only in the final chunk"),
                    ));
                }
                if second & 0x0f != 0 {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} must use canonical padding bits"),
                    ));
                }
                decoded.push((first << 2) | (second >> 4));
            }
            (_, b'=') => {
                if !is_final_chunk {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} padding must appear only in the final chunk"),
                    ));
                }
                let third = decode_standard_base64_digit(chunk[2], field_name)?;
                if third & 0x03 != 0 {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} must use canonical padding bits"),
                    ));
                }
                decoded.push((first << 2) | (second >> 4));
                decoded.push(((second & 0x0f) << 4) | (third >> 2));
            }
            (b'=', _) => {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name} padding is malformed"),
                ));
            }
            (_, _) => {
                let third = decode_standard_base64_digit(chunk[2], field_name)?;
                let fourth = decode_standard_base64_digit(chunk[3], field_name)?;
                decoded.push((first << 2) | (second >> 4));
                decoded.push(((second & 0x0f) << 4) | (third >> 2));
                decoded.push(((third & 0x03) << 6) | fourth);
            }
        }
    }

    Ok(decoded)
}

#[cfg(test)]
fn decode_standard_base64_digit(byte: u8, field_name: &str) -> CanonicalResult<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must use standard base64"),
        )),
    }
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
