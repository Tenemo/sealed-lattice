//! The canonical record of a centered coefficient of an odd modulus: a sign
//! byte of zero or one before the little-endian magnitude in the modulus's
//! byte length, at most half the modulus rounded down, with zero never
//! negative.

use num_bigint::{BigInt, Sign};

#[derive(Clone, Debug)]
pub struct CenteredCodec {
    // Half the modulus, rounded down, in the modulus's byte length.
    half: Vec<u8>,
}
impl CenteredCodec {
    /// The codec of an odd little-endian modulus.
    pub fn new(modulus: &[u8]) -> Self {
        let half = (0..modulus.len())
            .map(|index| {
                (modulus[index] >> 1) | ((modulus.get(index + 1).copied().unwrap_or(0) & 1) << 7)
            })
            .collect();
        Self { half }
    }
    pub fn record_bytes(&self) -> usize {
        1 + self.half.len()
    }
    pub fn is_canonical(&self, record: &[u8]) -> bool {
        let Some((&sign, magnitude)) = record.split_first() else {
            return false;
        };
        magnitude.len() == self.half.len()
            && sign <= 1
            && magnitude.iter().rev().cmp(self.half.iter().rev()).is_le()
            && !(sign == 1 && magnitude.iter().all(|byte| *byte == 0))
    }
    pub fn decode(&self, record: &[u8]) -> Option<BigInt> {
        self.is_canonical(record).then(|| {
            let magnitude = BigInt::from_bytes_le(Sign::Plus, &record[1..]);
            if record[0] == 1 {
                -magnitude
            } else {
                magnitude
            }
        })
    }
    /// The coefficients of whole records, if every record is canonical.
    pub fn decode_all(&self, bytes: &[u8]) -> Option<Vec<BigInt>> {
        if !bytes.len().is_multiple_of(self.record_bytes()) {
            return None;
        }
        bytes
            .chunks_exact(self.record_bytes())
            .map(|record| self.decode(record))
            .collect()
    }
}

/// Writes a value's sign byte and fixed-width magnitude without allocating
/// a temporary magnitude. The caller checks centering.
pub fn encode(value: &BigInt, record: &mut [u8]) {
    assert!(record.len() > 1);
    let width = record.len() - 1;
    assert!(value.magnitude().bits().div_ceil(8) <= width as u64);
    record.fill(0);
    record[0] = u8::from(value.sign() == Sign::Minus);
    for (chunk, digit) in record[1..]
        .chunks_mut(8)
        .zip(value.magnitude().iter_u64_digits())
    {
        chunk.copy_from_slice(&digit.to_le_bytes()[..chunk.len()]);
    }
}

#[cfg(test)]
#[path = "coefficient-tests.rs"]
mod tests;
