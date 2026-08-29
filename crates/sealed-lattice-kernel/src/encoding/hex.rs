use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub fn encode_hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        output.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    output
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
        let decode_nibble = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high = decode_nibble(pair[0]).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidHex,
                "hex string must use lowercase hexadecimal bytes",
            )
        })?;
        let low = decode_nibble(pair[1]).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidHex,
                "hex string must use lowercase hexadecimal bytes",
            )
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uppercase_hex_is_not_canonical() {
        assert_eq!(
            decode_hex("AB").expect_err("uppercase must refuse").code,
            CanonicalErrorCode::InvalidHex,
        );
    }
}
