use super::*;
use num_traits::Signed;

fn centered(value: BigInt, modulus: &BigInt) -> BigInt {
    let reduced = (value % modulus + modulus) % modulus;
    if reduced > modulus / 2 {
        reduced - modulus
    } else {
        reduced
    }
}
fn ordinary(left: &[BigInt], right: &[i8]) -> Vec<BigInt> {
    let degree = left.len();
    let mut result = vec![BigInt::from(0); degree];
    for (left_index, left) in left.iter().enumerate() {
        for (right_index, right) in right.iter().enumerate() {
            let index = left_index + right_index;
            result[index % degree] +=
                left * BigInt::from(if index >= degree { -*right } else { *right });
        }
    }
    result
}
#[test]
fn fixed_auxiliary_encryptions_use_the_suite_pair_and_exact_integer_equations() {
    let modulus = BigInt::from_bytes_le(Sign::Plus, supported_profile::auxiliary_modulus());
    let scale = (&modulus - BigInt::from(1)) / AUXILIARY_PLAINTEXT_MODULUS;
    let mut message = vec![0; AUXILIARY_DEGREE];
    message[..4].copy_from_slice(&[1, 10, -128, 128]);
    let witness = EncryptionWitness::create_auxiliary(&message).unwrap();
    assert_eq!(
        witness.common,
        setup_witness::fixed_auxiliary::common_polynomial()
    );
    assert_eq!(witness.key, setup_witness::fixed_auxiliary::public_key());
    assert_ne!(witness.common, witness.key);
    for sign in [-1, 1] {
        assert_eq!(
            witness
                .ephemeral
                .iter()
                .filter(|value| **value == sign)
                .count(),
            AUXILIARY_SECRET_SUPPORT / 2
        );
    }
    for (component, public) in [&witness.key, &witness.common].into_iter().enumerate() {
        for row in [0, 1, 3, AUXILIARY_DEGREE / 2, AUXILIARY_DEGREE - 1] {
            let mut product = BigInt::from(0);
            for (position, secret) in witness.ephemeral.iter().enumerate() {
                let index = (row + AUXILIARY_DEGREE - position) % AUXILIARY_DEGREE;
                product +=
                    &public[index] * i32::from(if position <= row { *secret } else { -*secret });
            }
            let value = &witness.components[component];
            let raw = product
                + i32::from(value.errors[row])
                + if component == 0 {
                    &scale * message[row]
                } else {
                    BigInt::from(0)
                };
            assert_eq!(value.coefficients[row], centered(raw.clone(), &modulus));
            assert_eq!(
                raw,
                &value.coefficients[row] + &modulus * i32::from(value.quotients[row])
            );
        }
    }
    assert!(EncryptionWitness::create_auxiliary(&message[..message.len() - 1]).is_err());
    message[0] = 129;
    assert!(EncryptionWitness::create_auxiliary(&message).is_err());
}
#[test]
fn sparse_secret_draws_are_uniform_positions() {
    // A four-byte draw reduced modulo the degree is a uniform position
    // only when the degree divides 2^32.
    let profile = Profile::new(3, 2).unwrap();
    for (family, support) in [
        (Family::Fhe, FHE_SECRET_SUPPORT),
        (Family::Auxiliary, AUXILIARY_SECRET_SUPPORT),
    ] {
        let degree = profile.family_degree(family);
        assert!((1u64 << (8 * DRAW_BYTES)).is_multiple_of(degree as u64));
        assert!(0 < support && support < degree);
    }
}

#[test]
fn both_encryption_moduli_match_independent_integer_convolution_and_decoding() {
    let degree = 32;
    let small = Profile::new(3, 2).unwrap();
    let wide = Profile::new(20, 20).unwrap();
    for (profile, family, plaintext_modulus) in [
        (small, Family::Fhe, 65537i32),
        (wide, Family::Fhe, 65537i32),
        (small, Family::Auxiliary, 257i32),
    ] {
        let bytes = profile.family_modulus(family);
        let modulus = BigInt::from_bytes_le(Sign::Plus, &bytes);
        let scale = (&modulus - BigInt::from(1)) / plaintext_modulus;
        let common: Vec<_> = (0..degree)
            .map(|index| {
                centered(
                    (&modulus / BigInt::from(2 + index % 7))
                        * BigInt::from(if index % 2 == 0 { 1 } else { -1 })
                        + BigInt::from(index),
                    &modulus,
                )
            })
            .collect();
        let mut secret = vec![0; degree];
        for (position, sign) in [(1, 1), (3, 1), (17, -1), (31, -1)] {
            secret[position] = sign;
        }
        let mut ephemeral = vec![0; degree];
        for (position, sign) in [(0, 1), (5, 1), (3, -1), (31, -1)] {
            ephemeral[position] = sign;
        }
        let key_error: Vec<_> = (0..degree)
            .map(|index| BigInt::from(if index % 2 == 0 { -640 } else { 630 }))
            .collect();
        let public_key: Vec<_> = ordinary(&common, &secret)
            .into_iter()
            .zip(&key_error)
            .map(|(product, error)| centered(-product + error, &modulus))
            .collect();
        let message: Vec<_> = (0..degree)
            .map(|index| [0, -plaintext_modulus / 2, plaintext_modulus / 2, 1, -1][index % 5])
            .collect();
        let plan = Plan::new(degree);
        let transformed = plan.sparse_transform(&ephemeral);
        let first = component(
            &plan,
            &ephemeral,
            &transformed,
            ComponentInput {
                public: &public_key,
                modulus: &modulus,
                scale: &scale,
                message: Some(&message),
                errors: Zeroizing::new(vec![63; degree]),
            },
        )
        .unwrap();
        let second = component(
            &plan,
            &ephemeral,
            &transformed,
            ComponentInput {
                public: &common,
                modulus: &modulus,
                scale: &scale,
                message: None,
                errors: Zeroizing::new(vec![-64; degree]),
            },
        )
        .unwrap();
        for (component_index, (public, ciphertext)) in [(&public_key, &first), (&common, &second)]
            .into_iter()
            .enumerate()
        {
            for (position, product) in ordinary(public, &ephemeral).into_iter().enumerate() {
                let raw = product
                    + BigInt::from(ciphertext.errors[position])
                    + if component_index == 0 {
                        &scale * message[position]
                    } else {
                        BigInt::from(0)
                    };
                assert_eq!(
                    ciphertext.coefficients[position],
                    centered(raw.clone(), &modulus)
                );
                assert_eq!(
                    raw,
                    &ciphertext.coefficients[position]
                        + &modulus * BigInt::from(ciphertext.quotients[position])
                );
            }
            assert_eq!(ciphertext.carries.len(), bytes.len().div_ceil(12) - 1);
        }
        let secret_product = ordinary(&second.coefficients, &secret);
        let expected_key_noise = ordinary(&key_error, &ephemeral);
        let error_values: Vec<_> = second
            .errors
            .iter()
            .map(|value| BigInt::from(*value))
            .collect();
        let expected_secret_noise = ordinary(&error_values, &secret);
        for position in 0..degree {
            let phase = centered(
                &first.coefficients[position] + &secret_product[position],
                &modulus,
            );
            let noise = &expected_key_noise[position]
                + &expected_secret_noise[position]
                + BigInt::from(first.errors[position]);
            assert_eq!(phase, &scale * message[position] + noise);
            let magnitude: BigInt = (phase.abs() + &scale / 2) / &scale;
            let decoded = if phase.is_negative() {
                -magnitude
            } else {
                magnitude
            };
            assert_eq!(decoded, BigInt::from(message[position]));
        }
    }
}
