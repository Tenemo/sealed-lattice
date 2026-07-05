use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::hash512_hex,
    transcript_core::{decode_hex, encode_hex},
};

pub(in crate::bgv) fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }

    bytes
}

pub(in crate::bgv) fn coefficient_vector_le_hex(coefficients: &[u64]) -> String {
    encode_hex(&coefficient_vector_bytes(coefficients))
}

pub(in crate::bgv) fn coefficient_vector_from_le_hex(
    value: &str,
    expected_coefficient_count: usize,
    length_error_message: &'static str,
) -> CanonicalResult<Vec<u64>> {
    let bytes = decode_hex(value)?;
    if bytes.len() != expected_coefficient_count * 8 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            length_error_message,
        ));
    }

    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut coefficient_bytes = [0_u8; 8];
            coefficient_bytes.copy_from_slice(chunk);
            u64::from_le_bytes(coefficient_bytes)
        })
        .collect())
}

pub(in crate::bgv) fn coefficient_vector_hash512(coefficients: &[u64], domain: &str) -> String {
    hash512_hex(domain, &[&coefficient_vector_bytes(coefficients)])
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(in crate::bgv) fn signed_byte_vector_hex(coefficients: &[i64]) -> CanonicalResult<String> {
    let mut bytes = Vec::with_capacity(coefficients.len());
    for coefficient in coefficients {
        let byte = i8::try_from(*coefficient).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "signed coefficient does not fit a single signed byte",
            )
        })?;
        bytes.push(byte.to_ne_bytes()[0]);
    }

    Ok(encode_hex(&bytes))
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(in crate::bgv) fn signed_byte_vector_from_hex(
    value: &str,
    expected_coefficient_count: usize,
    length_error_message: &'static str,
) -> CanonicalResult<Vec<i64>> {
    let bytes = decode_hex(value)?;
    if bytes.len() != expected_coefficient_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            length_error_message,
        ));
    }

    Ok(bytes
        .into_iter()
        .map(|byte| i64::from(i8::from_ne_bytes([byte])))
        .collect())
}
