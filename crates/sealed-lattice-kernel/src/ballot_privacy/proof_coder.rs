use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    transcript_core::decode_hex,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearProofBytes {
    bytes: Vec<u8>,
}

impl LinearProofBytes {
    pub fn from_hex(proof_hex: &str, expected_length: Option<usize>) -> CanonicalResult<Self> {
        let bytes = decode_hex(proof_hex)?;
        if bytes.is_empty() {
            return Err(invalid_proof("proof bytes must not be empty"));
        }
        if let Some(expected_length) = expected_length {
            match bytes.len().cmp(&expected_length) {
                std::cmp::Ordering::Less => {
                    return Err(invalid_proof("proof bytes are truncated"));
                }
                std::cmp::Ordering::Greater => {
                    return Err(invalid_proof("proof bytes contain trailing data"));
                }
                std::cmp::Ordering::Equal => {}
            }
        }

        Ok(Self { bytes })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub fn decode_little_endian_fixed_width_coefficients(
    bytes: &[u8],
    coefficient_byte_length: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if coefficient_byte_length == 0 || coefficient_byte_length > 8 {
        return Err(invalid_proof(
            "coefficientByteLength must be between one and eight",
        ));
    }
    if !bytes.len().is_multiple_of(coefficient_byte_length) {
        return Err(invalid_proof(
            "coefficient byte stream length is not a multiple of coefficientByteLength",
        ));
    }

    let mut coefficients = Vec::with_capacity(bytes.len() / coefficient_byte_length);
    for chunk in bytes.chunks_exact(coefficient_byte_length) {
        let mut buffer = [0_u8; 8];
        buffer[..coefficient_byte_length].copy_from_slice(chunk);
        let coefficient = u64::from_le_bytes(buffer);
        if coefficient >= modulus {
            return Err(invalid_proof(
                "coefficient encoding is not canonical for the modulus",
            ));
        }
        coefficients.push(coefficient);
    }

    Ok(coefficients)
}

fn invalid_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{LinearProofBytes, decode_little_endian_fixed_width_coefficients};

    #[test]
    fn rejects_truncated_and_extended_proof_bytes() {
        assert!(
            LinearProofBytes::from_hex("00ff", Some(3))
                .expect_err("short proof should fail")
                .message
                .contains("truncated")
        );
        assert!(
            LinearProofBytes::from_hex("00ff", Some(1))
                .expect_err("extended proof should fail")
                .message
                .contains("trailing")
        );
    }

    #[test]
    fn rejects_noncanonical_fixed_width_coefficients() {
        let error = decode_little_endian_fixed_width_coefficients(&[17, 0], 1, 17)
            .expect_err("coefficient equal to modulus should fail");

        assert!(error.message.contains("not canonical"));
    }
}
