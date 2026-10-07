use super::*;
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive, Zero};
use supported_profile::{Family, Profile};

// Every supported FHE modulus length at 96-bit limbs, and the share
// modulus at both share limbs.
fn moduli() -> Vec<(Vec<u8>, usize)> {
    let mut moduli: Vec<_> = Profile::all()
        .map(|profile| profile.family_modulus(Family::Fhe))
        .collect();
    moduli.sort_by_key(Vec::len);
    moduli.dedup_by_key(|bytes| bytes.len());
    let mut cases: Vec<_> = moduli.into_iter().map(|bytes| (bytes, 96)).collect();
    for radix in [95, 96] {
        cases.push((supported_profile::share_modulus().to_vec(), radix));
    }
    cases.push((supported_profile::auxiliary_modulus().to_vec(), 96));
    cases
}

#[test]
fn centered_values_and_exact_quotients_match_big_integer_division() {
    for (bytes, radix) in moduli() {
        let modulus = Modulus::new(&bytes, radix).unwrap();
        let mask = BigInt::from((1u128 << radix) - 1);
        let integer_modulus = BigInt::from_bytes_le(Sign::Plus, &bytes);
        let half = &integer_modulus >> 1usize;
        let count = modulus.digits.len();
        assert_eq!(
            modulus
                .digits
                .iter()
                .rev()
                .fold(BigInt::zero(), |sum, value| {
                    (sum << radix) + BigInt::from(*value)
                }),
            integer_modulus
        );
        for factor in [0, 1, 127, 512, 16383, 32767, 65534] {
            for residue in [
                BigInt::zero(),
                BigInt::from(1),
                half.clone(),
                &half + 1,
                &integer_modulus - 1,
            ] {
                for sign in [-1i32, 1] {
                    let raw_integer = (BigInt::from(factor) * &integer_modulus + &residue) * sign;
                    let absolute = raw_integer.abs();
                    let mut raw: Vec<i128> = (0..count)
                        .map(|index| {
                            let value = &absolute >> (radix * index);
                            let digit = if index + 1 == count {
                                value
                            } else {
                                value & &mask
                            };
                            digit.to_i128().unwrap() * i128::from(sign)
                        })
                        .collect();
                    let mut expected =
                        (&raw_integer % &integer_modulus + &integer_modulus) % &integer_modulus;
                    if expected > half {
                        expected -= &integer_modulus;
                    }
                    for transfer in [0i128, 1, -1, 1 << 30, -(1 << 30)] {
                        if count > 1 {
                            raw[0] += transfer << radix;
                            raw[1] -= transfer;
                        }
                        let mut output = vec![0; count];
                        let reduced = modulus.reduce(&raw, &mut output).unwrap();
                        let magnitude = output.iter().rev().fold(BigInt::zero(), |sum, value| {
                            (sum << radix) + BigInt::from(*value)
                        });
                        let actual = if reduced.negative {
                            -magnitude
                        } else {
                            magnitude
                        };
                        assert_eq!(actual, expected);
                        assert_eq!(
                            &actual + BigInt::from(reduced.quotient) * &integer_modulus,
                            raw_integer
                        );
                        assert!(output.iter().all(|digit| *digit < 1u128 << radix));
                        assert!(!actual.is_zero() || !reduced.negative);
                        if count > 1 {
                            raw[0] -= transfer << radix;
                            raw[1] += transfer;
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn refuses_unsupported_estimate_and_shape_before_reduction() {
    let profile = Profile::new(10, 10).unwrap();
    let modulus = Modulus::new(&profile.family_modulus(Family::Fhe), 96).unwrap();
    let mut raw = vec![0; 9];
    raw[8] = (modulus.digits[8] << 16) as i128;
    assert!(modulus.reduce(&raw, &mut [0; 9]).is_none());
    assert!(modulus.reduce(&[0; 8], &mut [0; 9]).is_none());
    assert!(Modulus::new(&[], 96).is_none());
    assert!(Modulus::new(&[2, 1, 0, 0, 1], 96).is_none());
    assert!(Modulus::new(supported_profile::share_modulus(), 16).is_none());
    assert!(Modulus::new(supported_profile::share_modulus(), 97).is_none());
}
