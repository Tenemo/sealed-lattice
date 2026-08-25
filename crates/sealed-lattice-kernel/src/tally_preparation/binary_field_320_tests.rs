use num_bigint::BigUint;
use num_traits::{One, Zero};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{
    TallyPreparationError,
    binary_field_320::{BinaryFieldElement320, measure_binary_field_320_multiplications},
};

#[test]
fn candidate_field_polynomial_passes_independent_rabin_irreducibility_test() {
    let modulus = candidate_field_modulus_polynomial();
    let polynomial_x = BigUint::from(2_u8);

    for factor_check_exponent in [160_usize, 64_usize] {
        let frobenius_power =
            independent_frobenius_power(polynomial_x.clone(), factor_check_exponent, &modulus);
        assert_eq!(
            independent_polynomial_greatest_common_divisor(
                frobenius_power ^ polynomial_x.clone(),
                modulus.clone(),
            ),
            BigUint::one(),
            "the degree-320 Rabin factor check at exponent {factor_check_exponent} must have no factor"
        );
    }

    assert_eq!(
        independent_frobenius_power(polynomial_x.clone(), 320, &modulus),
        polynomial_x
    );
}

#[test]
fn candidate_field_reduction_boundary_matches_the_declared_polynomial() {
    let reduced_boundary =
        field_element_with_bit(319).multiply(BinaryFieldElement320::from_low_polynomial_u16(2));
    let expected = field_element_with_bits(&[117, 86, 21, 0]);

    assert_eq!(reduced_boundary, expected);
    assert_eq!(
        reduced_boundary,
        independent_field_product(
            field_element_with_bit(319),
            BinaryFieldElement320::from_low_polynomial_u16(2)
        )
    );
}

#[test]
fn candidate_field_multiplication_matches_independent_polynomial_reduction() {
    let mut deterministic_state = 0x4d59_5df4_d0f3_3173_u64;
    let mut samples = vec![
        BinaryFieldElement320::ZERO,
        BinaryFieldElement320::ONE,
        field_element_with_bit(319),
        BinaryFieldElement320::from_canonical_bytes(&[0xff_u8; 40])
            .expect("all 320-bit strings are canonical"),
    ];
    for _sample_position in 0..76 {
        samples.push(deterministic_field_element(&mut deterministic_state));
    }

    for left_value in &samples {
        for right_value in samples.iter().step_by(7) {
            let expected_product = independent_field_product(*left_value, *right_value);
            assert_eq!(left_value.multiply(*right_value), expected_product);
            assert_eq!(right_value.multiply(*left_value), expected_product);
        }
        assert_eq!(left_value.multiply(BinaryFieldElement320::ONE), *left_value);
        assert_eq!(
            left_value.multiply(BinaryFieldElement320::ZERO),
            BinaryFieldElement320::ZERO
        );
        assert_eq!(
            left_value.square(),
            independent_field_product(*left_value, *left_value)
        );
    }
}

#[test]
fn candidate_field_satisfies_associativity_distributivity_and_inversion() {
    let mut deterministic_state = 0x94d0_49bb_1331_11eb_u64;
    for _sample_position in 0..48 {
        let first = deterministic_field_element(&mut deterministic_state);
        let second = deterministic_field_element(&mut deterministic_state);
        let third = deterministic_field_element(&mut deterministic_state);

        assert_eq!(
            first.multiply(second).multiply(third),
            first.multiply(second.multiply(third))
        );
        assert_eq!(
            first.multiply(second.add(third)),
            first.multiply(second).add(first.multiply(third))
        );
        if first.is_zero() {
            continue;
        }
        let inverse = first
            .multiplicative_inverse()
            .expect("a nonzero field element must be invertible");
        assert_eq!(first.multiply(inverse), BinaryFieldElement320::ONE);
        assert_eq!(second.divide(first).unwrap().multiply(first), second);
    }
    assert_eq!(
        BinaryFieldElement320::ZERO.multiplicative_inverse(),
        Err(TallyPreparationError::ZeroHasNoMultiplicativeInverse)
    );
}

#[test]
fn candidate_field_codec_is_exact_little_endian_and_rejects_wrong_lengths() {
    let every_bit_set = [0xff_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    assert_eq!(
        BinaryFieldElement320::from_canonical_bytes(&every_bit_set)
            .unwrap()
            .canonical_bytes(),
        every_bit_set
    );

    let mut ordered_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    for (byte_position, byte) in ordered_bytes.iter_mut().enumerate() {
        *byte = u8::try_from(byte_position).unwrap();
    }
    assert_eq!(
        BinaryFieldElement320::from_canonical_bytes(&ordered_bytes)
            .unwrap()
            .canonical_bytes(),
        ordered_bytes
    );
    assert!(matches!(
        BinaryFieldElement320::from_canonical_bytes(&ordered_bytes[..39]),
        Err(TallyPreparationError::FieldElementByteLength {
            expected: 40,
            actual: 39
        })
    ));
    assert!(matches!(
        BinaryFieldElement320::from_canonical_bytes(&[0_u8; 41]),
        Err(TallyPreparationError::FieldElementByteLength {
            expected: 40,
            actual: 41
        })
    ));
}

#[test]
fn candidate_field_low_points_are_distinct_nonzero_elements() {
    let points = (1_u16..=10)
        .map(BinaryFieldElement320::from_low_polynomial_u16)
        .collect::<Vec<_>>();

    for (point_position, point) in points.iter().enumerate() {
        assert!(!point.is_zero());
        assert_eq!(
            point.canonical_bytes()[0],
            u8::try_from(point_position + 1).unwrap()
        );
        assert!(point.canonical_bytes()[1..].iter().all(|byte| *byte == 0));
        assert!(points[..point_position].iter().all(|prior| prior != point));
    }
}

#[test]
fn candidate_field_supports_constant_time_equality_and_zeroization() {
    let first = field_element_with_bits(&[319, 117, 63, 0]);
    let same = BinaryFieldElement320::from_canonical_bytes(&first.canonical_bytes()).unwrap();
    let different = first.add(BinaryFieldElement320::ONE);

    assert!(bool::from(first.ct_eq(&same)));
    assert!(!bool::from(first.ct_eq(&different)));

    let mut secret = first;
    secret.zeroize();
    assert_eq!(secret, BinaryFieldElement320::ZERO);
}

#[test]
fn candidate_field_measurement_executes_the_requested_multiplication_count() {
    let multiplication_count = 257_u32;
    let seed = 0xd6e8_feb8_6659_fd93_u64;
    let mut accumulator = independent_measurement_initial_accumulator(seed);
    let mut deterministic_multiplier_limb_states =
        independent_measurement_multiplier_limb_states(seed);

    for _multiplication_position in 0..multiplication_count {
        for limb_state in &mut deterministic_multiplier_limb_states {
            *limb_state ^= *limb_state << 13;
            *limb_state ^= *limb_state >> 7;
            *limb_state ^= *limb_state << 17;
        }
        let mut multiplier_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
        for (limb_state, limb_bytes) in deterministic_multiplier_limb_states
            .iter()
            .zip(multiplier_bytes.chunks_exact_mut(8))
        {
            limb_bytes.copy_from_slice(&limb_state.to_le_bytes());
        }
        accumulator = independent_field_product(
            accumulator,
            BinaryFieldElement320::from_canonical_bytes(&multiplier_bytes).unwrap(),
        );
    }

    assert_eq!(
        measure_binary_field_320_multiplications(multiplication_count, seed),
        field_checksum(accumulator)
    );
    assert_eq!(
        measure_binary_field_320_multiplications(0, seed),
        field_checksum(independent_measurement_initial_accumulator(seed))
    );
    assert_eq!(
        measure_binary_field_320_multiplications(19, 0),
        measure_binary_field_320_multiplications(19, 0x9e37_79b9_7f4a_7c15)
    );
}

fn deterministic_field_element(state: &mut u64) -> BinaryFieldElement320 {
    let mut bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    for chunk in bytes.chunks_exact_mut(8) {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    BinaryFieldElement320::from_canonical_bytes(&bytes).unwrap()
}

fn field_element_with_bit(bit_position: usize) -> BinaryFieldElement320 {
    field_element_with_bits(&[bit_position])
}

fn field_element_with_bits(bit_positions: &[usize]) -> BinaryFieldElement320 {
    let mut bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    for bit_position in bit_positions {
        assert!(*bit_position < 320);
        bytes[*bit_position / 8] |= 1_u8 << (*bit_position % 8);
    }
    BinaryFieldElement320::from_canonical_bytes(&bytes).unwrap()
}

fn candidate_field_modulus_polynomial() -> BigUint {
    (BigUint::one() << 320_usize)
        ^ (BigUint::one() << 117_usize)
        ^ (BigUint::one() << 86_usize)
        ^ (BigUint::one() << 21_usize)
        ^ BigUint::one()
}

fn independent_measurement_initial_accumulator(seed: u64) -> BinaryFieldElement320 {
    let mut bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    for (chunk_position, chunk) in bytes.chunks_exact_mut(8).enumerate() {
        let chunk_value = seed.rotate_left(u32::try_from(chunk_position * 11).unwrap())
            ^ 0xa5a5_a5a5_a5a5_a5a5_u64.wrapping_mul(u64::try_from(chunk_position + 1).unwrap());
        chunk.copy_from_slice(&chunk_value.to_le_bytes());
    }
    BinaryFieldElement320::from_canonical_bytes(&bytes).unwrap()
}

fn independent_measurement_multiplier_limb_states(seed: u64) -> [u64; 5] {
    [
        seed | 1,
        seed.rotate_left(13) ^ 0x243f_6a88_85a3_08d3,
        seed.rotate_left(29) ^ 0x1319_8a2e_0370_7344,
        seed.rotate_left(47) ^ 0xa409_3822_299f_31d0,
        seed.rotate_left(61) ^ 0x082e_fa98_ec4e_6c89,
    ]
}

fn field_checksum(element: BinaryFieldElement320) -> u64 {
    element
        .canonical_bytes()
        .chunks_exact(8)
        .fold(0_u64, |checksum, chunk| {
            checksum ^ u64::from_le_bytes(chunk.try_into().unwrap())
        })
}

fn independent_field_product(
    left: BinaryFieldElement320,
    right: BinaryFieldElement320,
) -> BinaryFieldElement320 {
    let left_polynomial = BigUint::from_bytes_le(&left.canonical_bytes());
    let right_polynomial = BigUint::from_bytes_le(&right.canonical_bytes());
    let mut carryless_product = BigUint::zero();
    for right_bit_position in 0..320_u64 {
        if right_polynomial.bit(right_bit_position) {
            carryless_product ^= &left_polynomial << usize::try_from(right_bit_position).unwrap();
        }
    }
    let reduced =
        independent_polynomial_remainder(carryless_product, &candidate_field_modulus_polynomial());
    let mut canonical_bytes = reduced.to_bytes_le();
    canonical_bytes.resize(BinaryFieldElement320::CANONICAL_BYTE_LENGTH, 0);
    BinaryFieldElement320::from_canonical_bytes(&canonical_bytes).unwrap()
}

fn independent_frobenius_power(mut value: BigUint, exponent: usize, modulus: &BigUint) -> BigUint {
    for _square_position in 0..exponent {
        value = independent_polynomial_square_mod(&value, modulus);
    }
    value
}

fn independent_polynomial_square_mod(value: &BigUint, modulus: &BigUint) -> BigUint {
    let mut squared = BigUint::zero();
    for bit_position in 0..value.bits() {
        if value.bit(bit_position) {
            squared.set_bit(bit_position * 2, true);
        }
    }
    independent_polynomial_remainder(squared, modulus)
}

fn independent_polynomial_greatest_common_divisor(
    mut left: BigUint,
    mut right: BigUint,
) -> BigUint {
    while !right.is_zero() {
        let remainder = independent_polynomial_remainder(left, &right);
        left = right;
        right = remainder;
    }
    left
}

fn independent_polynomial_remainder(mut dividend: BigUint, divisor: &BigUint) -> BigUint {
    assert!(!divisor.is_zero());
    let divisor_degree = divisor.bits() - 1;
    while !dividend.is_zero() && dividend.bits() > divisor_degree {
        let degree_difference = dividend.bits() - 1 - divisor_degree;
        dividend ^= divisor << usize::try_from(degree_difference).unwrap();
    }
    dividend
}
