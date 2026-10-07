const THRESHOLDS: &[u8; 127 * 20] = include_bytes!("../gaussian-thresholds.bin");

// Fixed table accesses and loop counts. The implicit last threshold is 2^160.
pub fn sample(bytes: &[u8; 20]) -> i128 {
    let words: [u32; 5] = std::array::from_fn(|index| {
        u32::from_le_bytes(bytes[4 * index..4 * index + 4].try_into().unwrap())
    });
    let mut rank = 0i128;
    for threshold in THRESHOLDS.chunks_exact(20) {
        let mut borrow = 0i64;
        for (index, word) in words.iter().enumerate() {
            let bound = u32::from_le_bytes(threshold[4 * index..4 * index + 4].try_into().unwrap());
            let difference = i64::from(*word) - i64::from(bound) - borrow;
            borrow = (difference >> 63) & 1;
        }
        rank += i128::from(1 - borrow);
    }
    rank - 64
}

#[cfg(test)]
#[path = "gaussian-tests.rs"]
mod tests;
