use num_bigint::{BigInt, Sign};

/// Writes the existing fixed-width signed magnitude without allocating a
/// temporary magnitude for each coefficient. The caller checks centering.
pub fn encode_coefficient(value: &BigInt, encoded: &mut [u8]) {
    assert!(encoded.len() > 1);
    let width = encoded.len() - 1;
    assert!(value.magnitude().bits().div_ceil(8) <= width as u64);
    encoded.fill(0);
    encoded[0] = u8::from(value.sign() == Sign::Minus);
    for (chunk, digit) in encoded[1..]
        .chunks_mut(8)
        .zip(value.magnitude().iter_u64_digits())
    {
        chunk.copy_from_slice(&digit.to_le_bytes()[..chunk.len()]);
    }
}

#[cfg(test)]
#[path = "coefficient-encoding-tests.rs"]
mod tests;
