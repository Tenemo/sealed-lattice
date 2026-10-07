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
