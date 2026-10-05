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
mod tests {
    use super::encode_coefficient;
    use num_bigint::{BigInt, Sign};
    use supported_profile::{Family, Profile};

    fn check(value: &BigInt, encoded: &mut [u8]) {
        let (sign, magnitude) = value.to_bytes_le();
        let mut expected = vec![0; encoded.len()];
        expected[0] = u8::from(sign == Sign::Minus);
        expected[1..1 + magnitude.len()].copy_from_slice(&magnitude);
        encode_coefficient(value, encoded);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn matches_canonical_bytes_across_limb_and_profile_boundaries() {
        for (participants, options) in [(3, 2), (4, 20), (10, 10), (20, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            for family in [Family::Fhe, Family::Sharing, Family::Auxiliary] {
                let half =
                    BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(family)) >> 1usize;
                let mut encoded = vec![0xa5; 1 + profile.family_magnitude_bytes(family)];
                check(&half, &mut encoded);
                check(&-&half, &mut encoded);
                for bit in [0usize, 7, 8, 31, 32, 63, 64, 65, 95, 96, 127, 128] {
                    let value = BigInt::from(1) << bit;
                    for nearby in [&value - 1, value.clone(), &value + 1] {
                        if nearby > half {
                            continue;
                        }
                        check(&nearby, &mut encoded);
                        check(&-nearby, &mut encoded);
                    }
                }
                // Reusing a buffer after a full-width negative value must
                // clear both its sign and every unused high byte.
                check(&-&half, &mut encoded);
                check(&BigInt::from(0), &mut encoded);
                check(&BigInt::from(1), &mut encoded);
            }
        }
    }

    #[test]
    fn writes_partial_final_limbs_without_truncating() {
        for width in [1usize, 7, 8, 9, 15, 16, 17] {
            let maximum = (BigInt::from(1) << (width * 8)) - 1;
            let mut encoded = vec![0xa5; width + 1];
            check(&maximum, &mut encoded);
            check(&-maximum, &mut encoded);
        }
    }

    #[test]
    #[should_panic]
    fn rejects_an_overwidth_magnitude() {
        encode_coefficient(&(BigInt::from(1) << 72usize), &mut [0; 10]);
    }
}
