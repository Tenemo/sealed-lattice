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
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    #[test]
    fn fixed_scan_matches_integer_threshold_search_at_every_boundary() {
        let thresholds: Vec<BigUint> = THRESHOLDS
            .chunks_exact(20)
            .map(BigUint::from_bytes_le)
            .collect();
        let limit = BigUint::one() << 160usize;
        let mut values = vec![BigUint::zero(), &limit - 1u32];
        for threshold in &thresholds {
            for delta in [0u32, 1] {
                if threshold >= &BigUint::from(delta) {
                    values.push(threshold - delta);
                }
                if threshold + delta < limit {
                    values.push(threshold + delta);
                }
            }
        }
        for value in values {
            let mut bytes = [0; 20];
            let encoded = value.to_bytes_le();
            bytes[..encoded.len()].copy_from_slice(&encoded);
            let expected = thresholds
                .iter()
                .filter(|threshold| **threshold <= value)
                .count() as i128
                - 64;
            assert_eq!(sample(&bytes), expected);
            assert!((-64..64).contains(&expected));
        }
    }
}
