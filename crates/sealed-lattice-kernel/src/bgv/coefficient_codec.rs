#[cfg(test)]
use crate::hashing::hash512_hex;

/// Returns the unique little-endian byte width used for canonical residues of
/// the supplied modulus. The selected BGV moduli are all greater than one.
pub(in crate::bgv) fn canonical_modulus_byte_length(modulus: u64) -> usize {
    usize::try_from(u64::from(64 - (modulus - 1).leading_zeros()).div_ceil(8))
        .expect("a u64 modulus byte length fits usize")
}

#[cfg(test)]
pub(in crate::bgv) fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }

    bytes
}

#[cfg(test)]
pub(in crate::bgv) fn coefficient_vector_hash512(coefficients: &[u64], domain: &str) -> String {
    hash512_hex(domain, &[&coefficient_vector_bytes(coefficients)])
}
