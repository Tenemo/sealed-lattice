use super::direct_mpc_prime_field::{
    DIRECT_MPC_PRIME_FIELD_MODULUS, DirectMpcPrimeFieldElement, DirectMpcPrimeFieldError,
    evaluate_prime_field_polynomial, interpolate_consecutive_prime_field_values,
};

#[test]
fn prime_field_arithmetic_matches_independent_integer_reduction() {
    let samples = [0_u32, 1, 2, 255, 256, 65_535, 65_536];
    for left in samples {
        for right in samples {
            let left_field = DirectMpcPrimeFieldElement::from_canonical_u32(left).unwrap();
            let right_field = DirectMpcPrimeFieldElement::from_canonical_u32(right).unwrap();
            assert_eq!(
                left_field.add(right_field).canonical_u32(),
                ((u64::from(left) + u64::from(right)) % u64::from(DIRECT_MPC_PRIME_FIELD_MODULUS))
                    as u32
            );
            assert_eq!(
                left_field.subtract(right_field).canonical_u32(),
                ((u64::from(left) + u64::from(DIRECT_MPC_PRIME_FIELD_MODULUS) - u64::from(right))
                    % u64::from(DIRECT_MPC_PRIME_FIELD_MODULUS)) as u32
            );
            assert_eq!(
                left_field.multiply(right_field).canonical_u32(),
                ((u64::from(left) * u64::from(right)) % u64::from(DIRECT_MPC_PRIME_FIELD_MODULUS))
                    as u32
            );
        }
    }

    for value in 1..DIRECT_MPC_PRIME_FIELD_MODULUS {
        let field = DirectMpcPrimeFieldElement::from_canonical_u32(value).unwrap();
        assert_eq!(
            field.multiply(field.multiplicative_inverse().unwrap()),
            DirectMpcPrimeFieldElement::ONE
        );
    }
    assert_eq!(
        DirectMpcPrimeFieldElement::ZERO.multiplicative_inverse(),
        Err(DirectMpcPrimeFieldError::ZeroHasNoMultiplicativeInverse)
    );
}

#[test]
fn canonical_three_byte_encoding_rejects_every_boundary_violation() {
    for value in [0_u32, 1, 255, 256, 65_535, 65_536] {
        let field = DirectMpcPrimeFieldElement::from_canonical_u32(value).unwrap();
        let bytes = field.canonical_bytes();
        assert_eq!(
            DirectMpcPrimeFieldElement::from_canonical_bytes(&bytes).unwrap(),
            field
        );
    }
    assert_eq!(
        DirectMpcPrimeFieldElement::from_canonical_bytes(&[0, 0]),
        Err(DirectMpcPrimeFieldError::CanonicalByteLength {
            expected: 3,
            actual: 2,
        })
    );
    assert_eq!(
        DirectMpcPrimeFieldElement::from_canonical_bytes(&[1, 0, 1]),
        Err(DirectMpcPrimeFieldError::NonCanonicalValue { value: 65_537 })
    );
    assert_eq!(
        DirectMpcPrimeFieldElement::from_canonical_bytes(&[255, 255, 255]),
        Err(DirectMpcPrimeFieldError::NonCanonicalValue { value: 16_777_215 })
    );
}

#[test]
fn consecutive_interpolation_recovers_comparison_and_equality_tables() {
    let comparison_values = (0..=200)
        .map(|value| {
            if value >= 100 {
                DirectMpcPrimeFieldElement::ONE
            } else {
                DirectMpcPrimeFieldElement::ZERO
            }
        })
        .collect::<Vec<_>>();
    let comparison_coefficients =
        interpolate_consecutive_prime_field_values(&comparison_values).unwrap();
    assert_eq!(comparison_coefficients.len(), 201);
    for (point, expected) in comparison_values.iter().copied().enumerate() {
        assert_eq!(
            evaluate_prime_field_polynomial(
                &comparison_coefficients,
                DirectMpcPrimeFieldElement::from_u64_reduced(point as u64),
            ),
            expected,
            "comparison interpolation failed at point {point}"
        );
    }

    for selected_rank in 0..10 {
        let values = (0..10)
            .map(|rank| {
                if rank == selected_rank {
                    DirectMpcPrimeFieldElement::ONE
                } else {
                    DirectMpcPrimeFieldElement::ZERO
                }
            })
            .collect::<Vec<_>>();
        let coefficients = interpolate_consecutive_prime_field_values(&values).unwrap();
        for (rank, expected) in values.iter().copied().enumerate() {
            assert_eq!(
                evaluate_prime_field_polynomial(
                    &coefficients,
                    DirectMpcPrimeFieldElement::from_u64_reduced(rank as u64),
                ),
                expected
            );
        }
    }
}

#[test]
fn interpolation_handles_empty_constant_and_nontrivial_polynomials() {
    assert!(
        interpolate_consecutive_prime_field_values(&[])
            .unwrap()
            .is_empty()
    );
    let constant =
        interpolate_consecutive_prime_field_values(&[DirectMpcPrimeFieldElement::from_u16(42)])
            .unwrap();
    assert_eq!(
        constant.as_ref(),
        &[DirectMpcPrimeFieldElement::from_u16(42)]
    );

    let expected_coefficients = [
        DirectMpcPrimeFieldElement::from_u16(7),
        DirectMpcPrimeFieldElement::from_u16(11),
        DirectMpcPrimeFieldElement::from_u16(13),
        DirectMpcPrimeFieldElement::from_u16(17),
    ];
    let values = (0..4)
        .map(|point| {
            evaluate_prime_field_polynomial(
                &expected_coefficients,
                DirectMpcPrimeFieldElement::from_u16(point),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        interpolate_consecutive_prime_field_values(&values)
            .unwrap()
            .as_ref(),
        expected_coefficients
    );
}
