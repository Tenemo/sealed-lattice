use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::encoding::CanonicalErrorCode;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::{
        DEGREE_THREE_MASK_SHARE_ARTIFACT_MAGIC, DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
        DegreeThreeMaskPolynomial, DegreeThreeMaskShare, canonical_evaluation_point,
        decode_canonical_degree_three_mask_share, reconstruct_degree_three_mask,
    },
};

const COMPLETION_PARTICIPANT_COUNT: u16 = 10;

#[test]
fn field_polynomial_passes_independent_rabin_irreducibility_test() {
    let modulus = binary_field_modulus_polynomial();
    let polynomial_x = BigUint::from(2_u8);

    let mut frobenius_power_128 = polynomial_x.clone();
    for _square_position in 0..128 {
        frobenius_power_128 = independent_polynomial_square_mod(&frobenius_power_128, &modulus);
    }
    assert_eq!(
        independent_polynomial_greatest_common_divisor(
            frobenius_power_128 ^ polynomial_x.clone(),
            modulus.clone(),
        ),
        BigUint::one(),
        "the degree-256 Rabin factor check must have no degree-128 factor"
    );

    let mut frobenius_power_256 = polynomial_x.clone();
    for _square_position in 0..256 {
        frobenius_power_256 = independent_polynomial_square_mod(&frobenius_power_256, &modulus);
    }
    assert_eq!(frobenius_power_256, polynomial_x);
}

#[test]
fn field_multiplication_matches_independent_polynomial_reduction() {
    let mut deterministic_state = 0x7f4a_7c15_9e37_79b9_u64;
    let mut samples = vec![
        BinaryFieldElement256::ZERO,
        BinaryFieldElement256::ONE,
        field_element_with_bit(255),
        BinaryFieldElement256::from_canonical_bytes(&[0xff_u8; 32])
            .expect("all 256-bit strings are canonical"),
    ];
    for _sample_position in 0..68 {
        samples.push(deterministic_field_element(&mut deterministic_state));
    }

    for left_value in &samples {
        for right_value in samples.iter().step_by(7) {
            let expected_product = independent_field_product(*left_value, *right_value);
            assert_eq!(left_value.multiply(*right_value), expected_product);
            assert_eq!(right_value.multiply(*left_value), expected_product);
        }
        assert_eq!(left_value.multiply(BinaryFieldElement256::ONE), *left_value);
        assert_eq!(
            left_value.multiply(BinaryFieldElement256::ZERO),
            BinaryFieldElement256::ZERO
        );
        assert_eq!(
            left_value.square(),
            independent_field_product(*left_value, *left_value)
        );
    }
}

#[test]
fn field_arithmetic_satisfies_associativity_distributivity_and_inversion() {
    let mut deterministic_state = 0xd1b5_4a32_d192_ed03_u64;
    for _sample_position in 0..80 {
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
        assert_eq!(first.multiply(inverse), BinaryFieldElement256::ONE);
        assert_eq!(second.divide(first).unwrap().multiply(first), second);
    }
    assert_eq!(
        BinaryFieldElement256::ZERO.multiplicative_inverse(),
        Err(TallyPreparationError::ZeroHasNoMultiplicativeInverse)
    );
}

#[test]
fn canonical_completion_points_are_little_endian_polynomial_basis_elements() {
    for roster_position in 0..COMPLETION_PARTICIPANT_COUNT {
        let point = canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, roster_position)
            .expect("every completion roster position has a canonical point");
        let bytes = point.canonical_bytes();
        assert_eq!(bytes[0], u8::try_from(roster_position + 1).unwrap());
        assert!(bytes[1..].iter().all(|byte| *byte == 0));
    }
    assert_eq!(
        canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, 9)
            .unwrap()
            .canonical_bytes()[..2],
        [0x0a, 0x00]
    );

    let every_bit_set = [0xff_u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH];
    assert_eq!(
        BinaryFieldElement256::from_canonical_bytes(&every_bit_set)
            .unwrap()
            .canonical_bytes(),
        every_bit_set
    );
    assert!(matches!(
        BinaryFieldElement256::from_canonical_bytes(&every_bit_set[..31]),
        Err(TallyPreparationError::FieldElementByteLength {
            expected: 32,
            actual: 31
        })
    ));
    assert!(matches!(
        BinaryFieldElement256::from_canonical_bytes(&[0_u8; 33]),
        Err(TallyPreparationError::FieldElementByteLength {
            expected: 32,
            actual: 33
        })
    ));
}

#[test]
fn every_four_share_subset_reconstructs_the_completion_secret() {
    let polynomial = sample_polynomial();
    let shares = polynomial
        .shares(COMPLETION_PARTICIPANT_COUNT)
        .expect("completion shares must be generated");
    let expected_secret = polynomial.evaluate(BinaryFieldElement256::ZERO);
    let mut subset_count = 0_usize;

    for first_position in 0..7 {
        for second_position in (first_position + 1)..8 {
            for third_position in (second_position + 1)..9 {
                for fourth_position in (third_position + 1)..10 {
                    let subset = [
                        shares[first_position],
                        shares[second_position],
                        shares[third_position],
                        shares[fourth_position],
                    ];
                    assert_eq!(
                        reconstruct_degree_three_mask(COMPLETION_PARTICIPANT_COUNT, &subset)
                            .expect("four distinct canonical shares must reconstruct"),
                        expected_secret
                    );
                    let reversed_subset = [subset[3], subset[1], subset[0], subset[2]];
                    assert_eq!(
                        reconstruct_degree_three_mask(
                            COMPLETION_PARTICIPANT_COUNT,
                            &reversed_subset,
                        )
                        .unwrap(),
                        expected_secret
                    );
                    subset_count += 1;
                }
            }
        }
    }
    assert_eq!(subset_count, 210);
}

#[test]
fn any_three_shares_are_compatible_with_every_candidate_secret() {
    let polynomial = sample_polynomial();
    let shares = polynomial.shares(COMPLETION_PARTICIPANT_COUNT).unwrap();
    let observed_shares = [shares[1], shares[5], shares[8]];
    let candidate_secrets = [
        BinaryFieldElement256::ZERO,
        BinaryFieldElement256::ONE,
        field_element_from_repeated_byte(0xa5),
        field_element_with_bit(255),
    ];
    let original_secret = polynomial.evaluate(BinaryFieldElement256::ZERO);
    let vanishing_value_at_zero = observed_shares
        .iter()
        .map(|share| share.evaluation_point())
        .fold(BinaryFieldElement256::ONE, |product, point| {
            product.multiply(point)
        });

    for candidate_secret in candidate_secrets {
        let adjustment_scale = candidate_secret
            .add(original_secret)
            .divide(vanishing_value_at_zero)
            .unwrap();
        let alternate_evaluation = |evaluation_point: BinaryFieldElement256| {
            let vanishing_value = observed_shares
                .iter()
                .map(|share| evaluation_point.add(share.evaluation_point()))
                .fold(BinaryFieldElement256::ONE, |product, factor| {
                    product.multiply(factor)
                });
            polynomial
                .evaluate(evaluation_point)
                .add(adjustment_scale.multiply(vanishing_value))
        };

        assert_eq!(
            alternate_evaluation(BinaryFieldElement256::ZERO),
            candidate_secret
        );
        for observed_share in observed_shares {
            assert_eq!(
                alternate_evaluation(observed_share.evaluation_point()),
                observed_share.value()
            );
        }
    }
}

#[test]
fn reconstruction_refuses_malformed_duplicate_and_inconsistent_share_sets() {
    let polynomial = sample_polynomial();
    let shares = polynomial.shares(COMPLETION_PARTICIPANT_COUNT).unwrap();
    assert_eq!(
        reconstruct_degree_three_mask(COMPLETION_PARTICIPANT_COUNT, &shares[..3]),
        Err(TallyPreparationError::InsufficientShares {
            required: DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
            actual: 3,
        })
    );

    let duplicate = [shares[0], shares[1], shares[2], shares[2], shares[4]];
    assert_eq!(
        reconstruct_degree_three_mask(COMPLETION_PARTICIPANT_COUNT, &duplicate),
        Err(TallyPreparationError::DuplicateSharePosition { roster_position: 2 })
    );

    let mut inconsistent = shares.clone();
    inconsistent[4] = DegreeThreeMaskShare::new(
        COMPLETION_PARTICIPANT_COUNT,
        inconsistent[4].roster_position(),
        inconsistent[4].evaluation_point(),
        inconsistent[4].value().add(BinaryFieldElement256::ONE),
    )
    .unwrap();
    assert!(matches!(
        reconstruct_degree_three_mask(COMPLETION_PARTICIPANT_COUNT, &inconsistent),
        Err(TallyPreparationError::InconsistentShare { .. })
    ));

    let wrong_participant_count_share = sample_polynomial().share(9, 3).unwrap();
    let mixed_counts = [
        shares[0],
        shares[1],
        shares[2],
        wrong_participant_count_share,
    ];
    assert_eq!(
        reconstruct_degree_three_mask(COMPLETION_PARTICIPANT_COUNT, &mixed_counts),
        Err(TallyPreparationError::ParticipantCountMismatch)
    );

    let mut excess = shares.clone();
    excess.push(shares[0]);
    assert_eq!(
        reconstruct_degree_three_mask(COMPLETION_PARTICIPANT_COUNT, &excess),
        Err(TallyPreparationError::ExcessShares {
            participant_count: COMPLETION_PARTICIPANT_COUNT,
            actual: 11,
        })
    );
}

#[test]
fn share_construction_refuses_zero_wrong_and_out_of_roster_points() {
    let value = field_element_from_repeated_byte(0x3c);
    assert_eq!(
        DegreeThreeMaskShare::new(
            COMPLETION_PARTICIPANT_COUNT,
            0,
            BinaryFieldElement256::ZERO,
            value,
        ),
        Err(TallyPreparationError::ZeroEvaluationPoint)
    );
    assert_eq!(
        DegreeThreeMaskShare::new(
            COMPLETION_PARTICIPANT_COUNT,
            0,
            BinaryFieldElement256::from_low_polynomial_u16(2),
            value,
        ),
        Err(TallyPreparationError::EvaluationPointMismatch { roster_position: 0 })
    );
    assert_eq!(
        canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, 10),
        Err(TallyPreparationError::RosterPositionOutOfRange {
            roster_position: 10,
            participant_count: COMPLETION_PARTICIPANT_COUNT,
        })
    );
    assert_eq!(
        canonical_evaluation_point(3, 0),
        Err(TallyPreparationError::ParticipantCountOutOfRange {
            participant_count: 3,
        })
    );
}

#[test]
fn share_codec_roundtrips_and_refuses_noncanonical_or_mistyped_bytes() {
    let share = sample_polynomial()
        .share(COMPLETION_PARTICIPANT_COUNT, 6)
        .unwrap();
    assert_eq!(share.participant_count(), COMPLETION_PARTICIPANT_COUNT);
    let canonical_bytes = share.canonical_bytes();
    assert_eq!(
        decode_canonical_degree_three_mask_share(&canonical_bytes).unwrap(),
        share
    );

    let magic_length = DEGREE_THREE_MASK_SHARE_ARTIFACT_MAGIC.len();
    let version_offset = 1 + magic_length;
    let participant_count_offset = version_offset + 1;
    let roster_position_offset = participant_count_offset + 1;
    let evaluation_point_length_offset = roster_position_offset + 1;
    let evaluation_point_offset = evaluation_point_length_offset + 1;
    let value_length_offset =
        evaluation_point_offset + BinaryFieldElement256::CANONICAL_BYTE_LENGTH;

    let mut wrong_magic = canonical_bytes.clone();
    wrong_magic[1] ^= 1;
    assert_eq!(
        decode_canonical_degree_three_mask_share(&wrong_magic),
        Err(TallyPreparationError::ShareArtifactMagicMismatch)
    );

    let mut wrong_version = canonical_bytes.clone();
    wrong_version[version_offset] = 2;
    assert_eq!(
        decode_canonical_degree_three_mask_share(&wrong_version),
        Err(TallyPreparationError::UnsupportedShareArtifactVersion { version: 2 })
    );

    let mut noncanonical_version = canonical_bytes.clone();
    noncanonical_version.splice(version_offset..=version_offset, [0x81, 0x00]);
    assert!(matches!(
        decode_canonical_degree_three_mask_share(&noncanonical_version),
        Err(TallyPreparationError::CanonicalEncoding(error))
            if error.code == CanonicalErrorCode::NonCanonicalVarUint
    ));

    let mut wrong_roster_position = canonical_bytes.clone();
    wrong_roster_position[roster_position_offset] = 10;
    assert!(matches!(
        decode_canonical_degree_three_mask_share(&wrong_roster_position),
        Err(TallyPreparationError::RosterPositionOutOfRange { .. })
    ));

    let mut zero_point = canonical_bytes.clone();
    zero_point[evaluation_point_offset
        ..evaluation_point_offset + BinaryFieldElement256::CANONICAL_BYTE_LENGTH]
        .fill(0);
    assert_eq!(
        decode_canonical_degree_three_mask_share(&zero_point),
        Err(TallyPreparationError::ZeroEvaluationPoint)
    );

    let mut wrong_point = canonical_bytes.clone();
    wrong_point[evaluation_point_offset] ^= 1;
    assert!(matches!(
        decode_canonical_degree_three_mask_share(&wrong_point),
        Err(TallyPreparationError::EvaluationPointMismatch { .. })
    ));

    let mut short_point = canonical_bytes.clone();
    short_point[evaluation_point_length_offset] = 31;
    assert!(matches!(
        decode_canonical_degree_three_mask_share(&short_point),
        Err(TallyPreparationError::FieldElementByteLength {
            expected: 32,
            actual: 31
        })
    ));

    let mut short_value = canonical_bytes.clone();
    short_value[value_length_offset] = 31;
    assert!(matches!(
        decode_canonical_degree_three_mask_share(&short_value),
        Err(TallyPreparationError::FieldElementByteLength {
            expected: 32,
            actual: 31
        })
    ));

    let mut trailing = canonical_bytes.clone();
    trailing.push(0);
    assert_eq!(
        decode_canonical_degree_three_mask_share(&trailing),
        Err(TallyPreparationError::TrailingShareArtifactBytes)
    );
}

fn sample_polynomial() -> DegreeThreeMaskPolynomial {
    DegreeThreeMaskPolynomial::new(
        field_element_from_repeated_byte(0x5a),
        [
            field_element_from_repeated_byte(0x17),
            field_element_from_repeated_byte(0xc3),
            field_element_from_repeated_byte(0x6e),
        ],
    )
}

fn field_element_from_repeated_byte(byte: u8) -> BinaryFieldElement256 {
    BinaryFieldElement256::from_canonical_bytes(&[byte; 32]).unwrap()
}

fn field_element_with_bit(bit_position: usize) -> BinaryFieldElement256 {
    let mut bytes = [0_u8; 32];
    bytes[bit_position / 8] = 1_u8 << (bit_position % 8);
    BinaryFieldElement256::from_canonical_bytes(&bytes).unwrap()
}

fn deterministic_field_element(state: &mut u64) -> BinaryFieldElement256 {
    let mut bytes = [0_u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    BinaryFieldElement256::from_canonical_bytes(&bytes).unwrap()
}

fn binary_field_modulus_polynomial() -> BigUint {
    (BigUint::one() << 256_usize)
        ^ (BigUint::one() << 10_usize)
        ^ (BigUint::one() << 5_usize)
        ^ (BigUint::one() << 2_usize)
        ^ BigUint::one()
}

fn independent_field_product(
    left: BinaryFieldElement256,
    right: BinaryFieldElement256,
) -> BinaryFieldElement256 {
    let left_polynomial = BigUint::from_bytes_le(&left.canonical_bytes());
    let right_polynomial = BigUint::from_bytes_le(&right.canonical_bytes());
    let mut carryless_product = BigUint::zero();
    for right_bit_position in 0..256_u64 {
        if right_polynomial.bit(right_bit_position) {
            carryless_product ^= &left_polynomial << usize::try_from(right_bit_position).unwrap();
        }
    }
    let reduced =
        independent_polynomial_remainder(carryless_product, &binary_field_modulus_polynomial());
    let mut canonical_bytes = reduced.to_bytes_le();
    canonical_bytes.resize(BinaryFieldElement256::CANONICAL_BYTE_LENGTH, 0);
    BinaryFieldElement256::from_canonical_bytes(&canonical_bytes).unwrap()
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
