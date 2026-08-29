use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::lpsy15_prime_field::{Lpsy15PrimeFieldElement, Lpsy15PrimeFieldError};

#[test]
fn canonical_boundaries_round_trip_and_refuse_the_modulus() {
    let modulus = (BigUint::one() << 320_usize) + BigUint::from(27_u8);
    for value in [BigUint::zero(), BigUint::one(), &modulus - BigUint::one()] {
        let bytes = canonical_bytes(&value);
        let decoded = Lpsy15PrimeFieldElement::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(BigUint::from_bytes_le(&decoded.canonical_bytes()), value);
    }

    assert_eq!(
        Lpsy15PrimeFieldElement::from_canonical_bytes(&canonical_bytes(&modulus)),
        Err(Lpsy15PrimeFieldError::NonCanonicalValue)
    );
    let mut high_bits = [0_u8; 41];
    high_bits[40] = 2;
    assert_eq!(
        Lpsy15PrimeFieldElement::from_canonical_bytes(&high_bits),
        Err(Lpsy15PrimeFieldError::NonCanonicalValue)
    );
    assert_eq!(
        Lpsy15PrimeFieldElement::from_canonical_bytes(&[0_u8; 40]),
        Err(Lpsy15PrimeFieldError::CanonicalByteLength {
            expected: 41,
            actual: 40,
        })
    );
}

#[test]
fn scalar_addition_and_multiplication_match_big_integer_arithmetic() {
    let modulus = (BigUint::one() << 320_usize) + BigUint::from(27_u8);
    let mut random_state = [
        0x243f_6a88_85a3_08d3_u64,
        0x1319_8a2e_0370_7344,
        0xa409_3822_299f_31d0,
        0x082e_fa98_ec4e_6c89,
        0x4528_21e6_38d0_1377,
    ];

    for case_position in 0..256_u64 {
        let left = deterministic_value(&mut random_state, case_position);
        let right = deterministic_value(&mut random_state, case_position ^ u64::MAX);
        let left_field =
            Lpsy15PrimeFieldElement::from_canonical_bytes(&canonical_bytes(&left)).unwrap();
        let right_field =
            Lpsy15PrimeFieldElement::from_canonical_bytes(&canonical_bytes(&right)).unwrap();

        let expected_sum = (&left + &right) % &modulus;
        let expected_product = (&left * &right) % &modulus;
        assert_eq!(
            BigUint::from_bytes_le(&left_field.add(right_field).canonical_bytes()),
            expected_sum,
            "addition case {case_position}"
        );
        assert_eq!(
            BigUint::from_bytes_le(&left_field.multiply(right_field).canonical_bytes()),
            expected_product,
            "multiplication case {case_position}"
        );
    }
}

#[test]
fn unsigned64_construction_is_canonical_and_multiplicative() {
    let left = Lpsy15PrimeFieldElement::from_unsigned64(u64::MAX);
    let right = Lpsy15PrimeFieldElement::from_unsigned64(17);
    let actual = BigUint::from_bytes_le(&left.multiply(right).canonical_bytes());
    assert_eq!(actual, BigUint::from(u64::MAX) * BigUint::from(17_u8));
    assert_eq!(Lpsy15PrimeFieldElement::ZERO.canonical_bytes(), [0_u8; 41]);
    assert_eq!(Lpsy15PrimeFieldElement::ARITHMETIC_BYTE_LENGTH, 48);
}

#[test]
fn modulus_adjacent_arithmetic_reduces_exactly() {
    let modulus = (BigUint::one() << 320_usize) + BigUint::from(27_u8);
    let largest = &modulus - BigUint::one();
    let largest_field =
        Lpsy15PrimeFieldElement::from_canonical_bytes(&canonical_bytes(&largest)).unwrap();
    assert_eq!(
        BigUint::from_bytes_le(&largest_field.add(largest_field).canonical_bytes()),
        &modulus - BigUint::from(2_u8),
    );
    assert_eq!(
        BigUint::from_bytes_le(&largest_field.multiply(largest_field).canonical_bytes()),
        BigUint::one(),
    );
}

fn deterministic_value(random_state: &mut [u64; 5], domain: u64) -> BigUint {
    let mut bytes = [0_u8; 41];
    for (limb_position, limb_state) in random_state.iter_mut().enumerate() {
        *limb_state ^= limb_state.wrapping_shl(13);
        *limb_state ^= limb_state.wrapping_shr(7);
        *limb_state ^= limb_state.wrapping_shl(17);
        let limb = limb_state.wrapping_add(domain.rotate_left((limb_position * 11) as u32));
        bytes[limb_position * 8..(limb_position + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    // Values below 2^320 are always below 2^320 + 27.
    BigUint::from_bytes_le(&bytes)
}

fn canonical_bytes(value: &BigUint) -> [u8; 41] {
    let encoded = value.to_bytes_le();
    assert!(encoded.len() <= 41);
    let mut bytes = [0_u8; 41];
    bytes[..encoded.len()].copy_from_slice(&encoded);
    bytes
}
