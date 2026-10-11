use super::*;
use crate::common_polynomial::{public_polynomial, public_records};
use supported_profile::Profile;

fn integer(value: &[u64]) -> BigInt {
    let bytes: Vec<u8> = value.iter().flat_map(|word| word.to_le_bytes()).collect();
    BigInt::from_bytes_le(Sign::Plus, &bytes)
}
// The centered residue by division, as public_polynomial computes it.
fn reference(sample: &BigInt, modulus: &BigInt) -> BigInt {
    let value = sample % modulus;
    if value > (modulus >> 1usize) {
        value - modulus
    } else {
        value
    }
}
fn sample_bytes(sample: &BigInt, length: usize) -> Vec<u8> {
    let (_, mut bytes) = sample.to_bytes_le();
    assert!(bytes.len() <= length);
    bytes.resize(length, 0);
    bytes
}
// Every supported ciphertext modulus with its sample width, once.
fn moduli() -> Vec<(ProthModulus, usize)> {
    let mut moduli: Vec<_> = Profile::all()
        .map(|profile| {
            (
                profile.ciphertext_modulus(),
                profile.fhe_common_sample_bits(),
            )
        })
        .collect();
    moduli.sort_by_key(|(modulus, bits)| (modulus.exponent(), modulus.odd_factor(), *bits));
    moduli.dedup();
    moduli
}

// The reduction equals division at the boundaries of each residue class
// and range: zero, the largest sample, multiples of the modulus plus the
// residues around half the modulus and the largest residue, and samples
// whose low part is below the quotient, which take the correction.
#[test]
fn centered_residues_equal_division_at_every_boundary() {
    for (modulus, sample_bits) in moduli() {
        let reduction = ProthReduction::new(modulus, sample_bits);
        let value = integer(&reduction.modulus);
        let half = &value >> 1usize;
        let largest: BigInt = (BigInt::from(1) << sample_bits) - 1;
        let top = &largest / &value;
        let exponent = BigInt::from(1) << modulus.exponent();
        let mut samples = vec![BigInt::from(0), largest.clone()];
        for multiple in [BigInt::from(0), BigInt::from(1), &top - 1, top.clone()] {
            for residue in [
                BigInt::from(0),
                BigInt::from(1),
                &half - 1,
                half.clone(),
                &half + 1,
                &value - 1,
            ] {
                samples.push(&multiple * &value + residue);
            }
        }
        let odd_factor = BigInt::from(modulus.odd_factor());
        let highest = &largest >> modulus.exponent();
        for high in [
            odd_factor.clone(),
            &odd_factor * 3 + 1,
            &highest / &odd_factor * &odd_factor,
            highest,
        ] {
            for low in [BigInt::from(0), BigInt::from(1), &exponent - 1] {
                samples.push(&high * &exponent + low);
            }
        }
        let mut magnitude = vec![0; reduction.words()];
        for sample in samples.into_iter().filter(|sample| *sample <= largest) {
            let negative =
                reduction.centered(&sample_bytes(&sample, sample_bits / 8), &mut magnitude);
            let expected = reference(&sample, &value);
            let sign = if negative { Sign::Minus } else { Sign::Plus };
            assert_eq!(
                BigInt::from_biguint(sign, integer(&magnitude).magnitude().clone()),
                expected
            );
            assert!(!negative || expected.sign() == Sign::Minus);
        }
    }
}

// Every supported profile's common polynomial samples and records equal
// those of division, and the records hold no more memory than their
// length.
#[test]
fn polynomials_and_records_equal_division() {
    let degree = 256;
    for (modulus, sample_bits) in moduli() {
        let bytes = modulus.to_bytes();
        let value = BigInt::from_bytes_le(Sign::Plus, &bytes);
        for label in ["common-fhe-a-0", "common-fhe-k-5"] {
            assert_eq!(
                proth_public_polynomial(label, degree, modulus, sample_bits),
                public_polynomial(label, degree, &value, sample_bits)
            );
            let records = proth_public_records(label, degree, modulus, sample_bits);
            assert_eq!(records.capacity(), records.len());
            assert_eq!(records, public_records(label, degree, &bytes, sample_bits));
        }
    }
}
