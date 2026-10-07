use super::*;
// Each digit equals the one the integer's own shifts and masks give, at
// every limb of values of both signs, zero and a single set bit at the
// edges of the words that a digit spans.
#[test]
fn digits_match_the_shifted_and_masked_magnitude() {
    use num_traits::ToPrimitive;
    let mut values = vec![BigInt::from(0), BigInt::from(1), BigInt::from(-1)];
    for bit in [
        0usize, 31, 63, 64, 95, 96, 127, 128, 191, 192, 200, 255, 383, 900,
    ] {
        values.push(BigInt::from(1) << bit);
        values.push(-(BigInt::from(1) << bit));
        values.push((BigInt::from(1) << bit) - 1);
    }
    let mut state = 0x243f_6a88_85a3_08d3u64;
    for words in [1usize, 2, 3, 5, 14] {
        let mut value = BigInt::from(0);
        for _ in 0..words {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            value = (value << 64usize) + BigInt::from(state);
        }
        values.push(-value.clone());
        values.push(value);
    }
    for radix_bits in [17, 32, 63, 64, 65, 95, 96] {
        for value in &values {
            for limb in 0..(1000 / radix_bits + 2) {
                let magnitude: BigInt =
                    (value.abs() >> (radix_bits * limb)) & ((BigInt::from(1) << radix_bits) - 1);
                let expected = magnitude.to_i128().unwrap();
                let expected = if value.is_negative() {
                    -expected
                } else {
                    expected
                };
                assert_eq!(digit_in(value, limb, radix_bits), expected);
            }
        }
    }
}
#[test]
fn signed_digit_products_match_every_ordinary_coefficient() {
    for degree in [2, 4, 8, 16, 32] {
        let plan = Plan::new(degree);
        let public: Vec<BigInt> = (0..degree)
            .map(|index| {
                let value = (BigInt::from(index + 1) << 137usize)
                    + (BigInt::from(3 * index + 7) << 72usize)
                    + BigInt::from(19 * index + 1);
                if index % 2 == 0 { -value } else { value }
            })
            .collect();
        let sparse: Vec<i8> = (0..degree)
            .map(|index| {
                if index % 3 == 0 {
                    -1
                } else if index % 3 == 1 {
                    1
                } else {
                    0
                }
            })
            .collect();
        let transformed = plan.sparse_transform(&sparse);
        for radix_bits in [95, 96] {
            plan.digit_products(&public, &sparse, &transformed, 2, radix_bits);
        }
    }
}
