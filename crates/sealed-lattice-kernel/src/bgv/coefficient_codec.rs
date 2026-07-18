use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::hash512_hex,
    transcript_core::{decode_hex, encode_hex},
};

/// Returns the unique little-endian byte width used for canonical residues of
/// the supplied modulus. The selected BGV moduli are all greater than one.
pub(in crate::bgv) fn canonical_modulus_byte_length(modulus: u64) -> usize {
    usize::try_from((u64::from(64 - (modulus - 1).leading_zeros()) + 7) / 8)
        .expect("a u64 modulus byte length fits usize")
}

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
