//! Public canonical coefficients, generated independently of any witness.
use num_bigint::{BigInt, Sign};

use crate::Case;

pub const COEFFICIENT_BYTES: usize = 21;
pub const LIMB_BITS: usize = 96;

pub struct Recipe {
    edges: [[u8; COEFFICIENT_BYTES]; 9],
    highest: usize,
    top_limit: u8,
}

fn record(value: BigInt) -> [u8; COEFFICIENT_BYTES] {
    let (sign, bytes) = value.to_bytes_le();
    let mut output = [0; COEFFICIENT_BYTES];
    output[0] = u8::from(sign == Sign::Minus);
    output[1..1 + bytes.len()].copy_from_slice(&bytes);
    output
}

fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

impl Default for Recipe {
    fn default() -> Self {
        let modulus = BigInt::from_bytes_le(Sign::Plus, supported_profile::share_modulus());
        let half = modulus >> 1usize;
        let radix = BigInt::from(1u8) << LIMB_BITS;
        let edges = [
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(-1),
            &radix - 1u8,
            1u8 - &radix,
            radix.clone(),
            -radix,
            half.clone(),
            -&half,
        ]
        .map(record);
        let (_, bytes) = half.to_bytes_le();
        Self {
            edges,
            highest: bytes.len() - 1,
            top_limit: *bytes.last().unwrap(),
        }
    }
}

impl Recipe {
    pub fn coefficient(
        &self,
        case: Case,
        polynomial: usize,
        row: usize,
    ) -> [u8; COEFFICIENT_BYTES] {
        let selector = (row + 3 * polynomial + 5 * case as usize) % 32;
        if selector < self.edges.len() {
            return self.edges[selector];
        }
        let seed = (row as u64)
            .wrapping_add((polynomial as u64 + 1) << 32)
            .wrapping_add((case as u64 + 1) << 56);
        let mut output = [0; COEFFICIENT_BYTES];
        output[0] = (mix(seed) & 1) as u8;
        for block in 0..3 {
            let bytes = mix(seed.wrapping_add((block as u64 + 1) * 0x9e37_79b9)).to_le_bytes();
            let start = 1 + 8 * block;
            let end = (start + 8).min(COEFFICIENT_BYTES);
            output[start..end].copy_from_slice(&bytes[..end - start]);
        }
        // A strictly smaller most significant byte makes every lower byte
        // legal without a modulus reduction or a second polynomial buffer.
        output[1 + self.highest] %= self.top_limit;
        output[2 + self.highest..].fill(0);
        if output[1..].iter().all(|byte| *byte == 0) {
            output[0] = 0;
        }
        output
    }

    pub fn chunk(&self, case: Case, polynomial: usize, start: usize, count: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(count * COEFFICIENT_BYTES);
        for row in start..start + count {
            output.extend(self.coefficient(case, polynomial, row));
        }
        output
    }
}

pub fn digit(record: &[u8; COEFFICIENT_BYTES], limb: usize) -> i128 {
    let (start, length) = if limb == 0 { (1, 12) } else { (13, 8) };
    let mut bytes = [0; 16];
    bytes[..length].copy_from_slice(&record[start..start + length]);
    let value = u128::from_le_bytes(bytes) as i128;
    if record[0] == 0 { value } else { -value }
}

pub fn modulus_digits() -> [i128; 2] {
    let encoded = record(BigInt::from_bytes_le(
        Sign::Plus,
        supported_profile::share_modulus(),
    ));
    [digit(&encoded, 0), digit(&encoded, 1)]
}
