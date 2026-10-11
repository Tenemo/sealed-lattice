use super::*;
const DOMAIN_SIZE: usize = 4 * SYSTEMATIC_SIZE;

#[test]
fn transforms_match_every_direct_fourier_coefficient() {
    for length in [2, 4, 8, 16, 32] {
        let original: Vec<Element> = (0..length)
            .map(|index| {
                [
                    index as u128,
                    MODULUS - 1 - index as u128,
                    (index * index + 7) as u128,
                ]
            })
            .collect();
        // The inverse transform is unnormalized.
        for inverse in [false, true] {
            let mut root = arithmetic::power(7, (MODULUS - 1) / length as u128);
            if inverse {
                root = arithmetic::power(root, MODULUS - 2);
            }
            let expected: Vec<Element> = (0..length)
                .map(|output| {
                    original
                        .iter()
                        .enumerate()
                        .fold(ZERO, |sum, (input, value)| {
                            plus(
                                sum,
                                scale(*value, arithmetic::power(root, (input * output) as u128)),
                            )
                        })
                })
                .collect();
            let mut actual = original.clone();
            Transform::new(length).apply(&mut actual, inverse);
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn query_values_match_direct_evaluation_of_the_masked_interpolant() {
    let systematic_size = 16;
    let domain_size = 4 * systematic_size;
    let domain_root = arithmetic::power(7, (MODULUS - 1) / domain_size as u128);
    for degree in [2, 16, 4, 8, 2, 16] {
        let values: Vec<Element> = (0..degree)
            .map(|index| {
                [
                    (index * index + 3) as u128,
                    MODULUS - 1 - (index * 5) as u128,
                    1 << (index + 90),
                ]
            })
            .collect();
        // The interpolant's coefficients by the inverse Fourier sum.
        let root = arithmetic::power(7, (MODULUS - 1) / degree as u128);
        let inverse_root = arithmetic::power(root, MODULUS - 2);
        let inverse_degree = arithmetic::power(degree as u128, MODULUS - 2);
        let coefficients: Vec<Element> = (0..degree)
            .map(|power| {
                scale(
                    values.iter().enumerate().fold(ZERO, |sum, (index, value)| {
                        plus(
                            sum,
                            scale(
                                *value,
                                arithmetic::power(inverse_root, (index * power) as u128),
                            ),
                        )
                    }),
                    inverse_degree,
                )
            })
            .collect();
        let stride = systematic_size / degree;
        for indices in [
            vec![0],
            vec![(domain_size - 1) as u32],
            vec![0, (domain_size - 1) as u32],
            (0..domain_size as u32).step_by(3).collect(),
            (1..domain_size as u32).step_by(2).collect(),
            (0..domain_size as u32).collect(),
        ] {
            let actual = evaluate_in(values.clone(), &indices, systematic_size).unwrap();
            for (index, value) in indices.iter().zip(actual) {
                let point = multiply(7, arithmetic::power(domain_root, u128::from(*index)));
                let interpolant = coefficients.iter().rev().fold(ZERO, |sum, coefficient| {
                    plus(scale(sum, point), *coefficient)
                });
                let indicator = (0..stride).fold(0, |sum, power| {
                    arithmetic::add(sum, arithmetic::power(point, (degree * power) as u128))
                });
                let indicator = multiply(indicator, arithmetic::power(stride as u128, MODULUS - 2));
                assert_eq!(value, scale(interpolant, indicator));
            }
        }
    }
}

#[test]
fn refuses_invalid_query_sets_before_transform_work() {
    for indices in [
        vec![],
        vec![0, 0],
        vec![1, 0],
        vec![DOMAIN_SIZE as u32],
        (0..=QUERY_LIMIT as u32).collect(),
    ] {
        assert_eq!(
            validate_indices_in(&indices, DOMAIN_SIZE),
            Err(Error::Parameters)
        );
    }
    assert_eq!(
        validate_indices_in(&[0, (DOMAIN_SIZE - 1) as u32], DOMAIN_SIZE),
        Ok(())
    );
}
