use super::*;
use num_bigint::{BigInt, Sign};

fn source(profile: Profile, index: usize) -> (AggregatePolynomial, Vec<u8>, Vec<BigInt>) {
    let family = crate::contribution_family(profile, index).unwrap();
    let width = 1 + profile.family_magnitude_bytes(family);
    let half = BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(family)) >> 1usize;
    let values = vec![
        BigInt::from(0),
        BigInt::from(1),
        BigInt::from(-1),
        half.clone(),
        -half,
    ];
    let mut bytes = vec![0; profile.family_degree(family) * width];
    for (position, coefficient) in bytes.chunks_exact_mut(width).enumerate() {
        let (sign, magnitude) = values[position % values.len()].to_bytes_le();
        coefficient[0] = u8::from(sign == Sign::Minus);
        coefficient[1..1 + magnitude.len()].copy_from_slice(&magnitude);
    }
    let expected = AggregatePolynomial {
        index,
        bytes: bytes.len(),
        digest: registration_credentials::identity::identity(PUBLIC_POLYNOMIAL_DOMAIN, &bytes)
            .unwrap(),
    };
    (expected, bytes, values)
}
#[test]
fn retained_coefficients_match_both_boundaries_in_every_modulus() {
    for (participants, options) in [(3, 2), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        for index in [
            profile.fhe_polynomial(profile.gadget_length() - 1, 6),
            profile.share_linear_polynomial(participants - 1),
        ] {
            let (expected, bytes, values) = source(profile, index);
            let family = profile.setup_family(index).unwrap();
            let width = 1 + profile.family_magnitude_bytes(family);
            let mut reader =
                crate::AggregatePolynomialReader::new(profile, [19; 64], expected).unwrap();
            let chunk = CHUNK_BYTES / width * width;
            for (ordinal, bytes) in bytes.chunks(chunk).enumerate() {
                reader.push(ordinal * chunk, bytes).unwrap();
            }
            let key = reader.finish().unwrap();
            assert_eq!(key.inventory(), &[19; 64]);
            assert_eq!(key.index(), index);
            assert_eq!(key.coefficients().len(), profile.family_degree(family));
            for (position, coefficient) in key.coefficients().iter().enumerate() {
                assert_eq!(coefficient, &values[position % values.len()]);
            }
        }
    }
}
#[test]
fn readers_refuse_a_reference_of_another_profile_or_polynomial() {
    let small = Profile::new(3, 2).unwrap();
    let wide = Profile::new(20, 20).unwrap();
    let index = wide.fhe_polynomial(0, 1);
    let (expected, _, _) = source(wide, index);
    // The same key position has fewer ciphertext bytes in the smaller
    // profile, and a common polynomial is never an aggregate.
    assert!(crate::AggregatePolynomialReader::new(small, [0; 64], expected.clone()).is_err());
    let common = AggregatePolynomial {
        index: wide.fhe_polynomial(0, 0),
        ..expected
    };
    assert!(crate::AggregatePolynomialReader::new(wide, [0; 64], common).is_err());
}
fn share_width(profile: Profile) -> usize {
    1 + profile.family_magnitude_bytes(supported_profile::Family::Sharing)
}
fn push_all(reader: &mut crate::AggregatePolynomialReader, profile: Profile, bytes: &[u8]) {
    let chunk = CHUNK_BYTES / share_width(profile) * share_width(profile);
    for (ordinal, part) in bytes.chunks(chunk).enumerate() {
        reader.push(ordinal * chunk, part).unwrap();
    }
}
#[test]
fn changed_canonical_cache_and_incomplete_reads_supply_no_key() {
    let profile = Profile::new(3, 2).unwrap();
    let (expected, mut bytes, _) = source(profile, profile.share_constant_polynomial(0));
    let mut reader =
        crate::AggregatePolynomialReader::new(profile, [0; 64], expected.clone()).unwrap();
    push_all(
        &mut reader,
        profile,
        &bytes[..bytes.len() - share_width(profile)],
    );
    assert!(matches!(reader.finish(), Err(Refusal::Incomplete)));
    bytes[1] = 1;
    let mut reader = crate::AggregatePolynomialReader::new(profile, [0; 64], expected).unwrap();
    push_all(&mut reader, profile, &bytes);
    assert!(matches!(reader.finish(), Err(Refusal::PreviousAggregate)));
}
#[test]
fn malformed_reads_poison_only_the_pending_key() {
    let profile = Profile::new(3, 2).unwrap();
    let (expected, bytes, _) = source(profile, profile.share_constant_polynomial(0));
    let width = share_width(profile);
    let mut negative_zero = vec![0; width];
    negative_zero[0] = 1;
    let mut unknown_sign = vec![0; width];
    unknown_sign[0] = 2;
    for (offset, invalid) in [
        (width, vec![0; width]),
        (0, vec![]),
        (0, vec![0; width - 1]),
        (0, vec![0; CHUNK_BYTES + 1]),
        (0, negative_zero),
        (0, unknown_sign),
    ] {
        let mut reader =
            crate::AggregatePolynomialReader::new(profile, [0; 64], expected.clone()).unwrap();
        assert!(reader.push(offset, &invalid).is_err());
        assert!(reader.push(0, &bytes[..width]).is_err());
        assert!(reader.finish().is_err());
    }
    let mut reader =
        crate::AggregatePolynomialReader::new(profile, [0; 64], expected.clone()).unwrap();
    reader.push(0, &bytes[..width]).unwrap();
    assert!(reader.push(0, &bytes[..width]).is_err());
    assert!(reader.finish().is_err());
    let mut reader = crate::AggregatePolynomialReader::new(profile, [0; 64], expected).unwrap();
    push_all(&mut reader, profile, &bytes);
    assert!(reader.push(bytes.len(), &bytes[..width]).is_err());
    assert!(reader.finish().is_err());
}
