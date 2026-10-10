use super::*;
use num_bigint::BigUint;
fn encode(value: &BigInt, width: usize) -> Vec<u8> {
    let (sign, magnitude) = value.to_bytes_le();
    let mut bytes = vec![0; width];
    bytes[0] = u8::from(sign == Sign::Minus);
    bytes[1..1 + magnitude.len()].copy_from_slice(&magnitude);
    bytes
}
/// A family's modulus and half of it, rounded down, from the profile.
fn modulus(profile: Profile, family: Family) -> (BigInt, BigInt) {
    let modulus = BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(family));
    let half = &modulus >> 1usize;
    (modulus, half)
}
/// The centered sum of two centered values.
fn centered_sum(left: &BigInt, right: &BigInt, modulus: &BigInt) -> BigInt {
    let positive = ((left + right) % modulus + modulus) % modulus;
    if positive > modulus >> 1usize {
        positive - modulus
    } else {
        positive
    }
}
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
const FAMILIES: [(usize, usize, Family); 5] = [
    (3, 2, Family::Fhe),
    (10, 10, Family::Fhe),
    (20, 20, Family::Fhe),
    (3, 2, Family::Sharing),
    (3, 2, Family::Auxiliary),
];
#[test]
fn centered_wraps_and_cancellation_are_exact() {
    for (participants, options, family) in FAMILIES {
        let profile = Profile::new(participants, options).unwrap();
        let adder = PolynomialAdder::new(profile, family);
        let (modulus, half) = modulus(profile, family);
        let values = [
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(-1),
            half.clone(),
            -&half,
            &half - 1,
            1 - &half,
        ];
        for left in &values {
            for right in &values {
                let incoming = encode(left, adder.width);
                let mut destination = encode(right, adder.width);
                adder.add_into(&incoming, &mut destination).unwrap();
                let expected = centered_sum(left, right, &modulus);
                assert_eq!(destination, encode(&expected, adder.width));
                assert_eq!(adder.decode(&destination).unwrap(), expected);
            }
        }
    }
}
// Chunks of many coefficients, at random and at each side of the wrap
// of a sum past half the modulus, add to the centered sums of their
// values, computed here from the family modulus with big integers.
#[test]
fn chunks_add_to_centered_sums() {
    for (participants, options, family) in FAMILIES {
        let profile = Profile::new(participants, options).unwrap();
        let adder = PolynomialAdder::new(profile, family);
        let (modulus, half) = modulus(profile, family);
        let mut state = 0x5eed ^ adder.width as u64;
        let random = |state: &mut u64| {
            let bytes: Vec<u8> = (0..adder.width + 8)
                .flat_map(|_| next(state).to_le_bytes())
                .collect();
            let value = BigInt::from(BigUint::from_bytes_le(&bytes)) % (&modulus);
            value - &half
        };
        let mut pairs = Vec::new();
        for _ in 0..300 {
            let (left, right) = (random(&mut state), random(&mut state));
            let near = &half - &left;
            pairs.push((left.clone(), right));
            if near <= half {
                pairs.push((left.clone(), near.clone()));
                pairs.push((-&left, -&near));
            }
            if near < half {
                pairs.push((left.clone(), &near + 1));
                pairs.push((-&left, -&near - 1));
            }
        }
        let mut incoming = Vec::new();
        let mut destination = Vec::new();
        let mut expected = Vec::new();
        for (left, right) in &pairs {
            assert!(left.magnitude() <= half.magnitude() && right.magnitude() <= half.magnitude());
            incoming.extend(encode(left, adder.width));
            destination.extend(encode(right, adder.width));
            expected.extend(encode(&centered_sum(left, right, &modulus), adder.width));
        }
        for ((incoming, destination), expected) in incoming
            .chunks(CHUNK_BYTES / adder.width * adder.width)
            .zip(destination.chunks_mut(CHUNK_BYTES / adder.width * adder.width))
            .zip(expected.chunks(CHUNK_BYTES / adder.width * adder.width))
        {
            adder.add_into(incoming, destination).unwrap();
            assert_eq!(destination, expected);
        }
    }
}
#[test]
fn refuses_noncanonical_values_and_shapes() {
    let profile = Profile::new(3, 2).unwrap();
    let adder = PolynomialAdder::new(profile, Family::Auxiliary);
    let (_, half) = modulus(profile, Family::Auxiliary);
    let zero = vec![0; adder.width];
    let mut negative_zero = zero.clone();
    negative_zero[0] = 1;
    assert_eq!(
        adder.add_into(&negative_zero, &mut zero.clone()),
        Err(Refusal::Encoding)
    );
    let mut unknown_sign = zero.clone();
    unknown_sign[0] = 2;
    assert_eq!(
        adder.add_into(&unknown_sign, &mut zero.clone()),
        Err(Refusal::Encoding)
    );
    for excessive in [&half + 1, -&half - 1] {
        let excessive = encode(&excessive, adder.width);
        assert_eq!(
            adder.add_into(&excessive, &mut zero.clone()),
            Err(Refusal::Encoding)
        );
        assert_eq!(
            adder.add_into(&zero, &mut excessive.clone()),
            Err(Refusal::Encoding)
        );
        assert_eq!(adder.decode(&excessive), Err(Refusal::Encoding));
    }
    let mut largest = vec![0xff; adder.width];
    largest[0] = 0;
    assert_eq!(
        adder.add_into(&largest, &mut zero.clone()),
        Err(Refusal::Encoding)
    );
    assert_eq!(adder.decode(&negative_zero), Err(Refusal::Encoding));
    assert_eq!(adder.decode(&zero[1..]), Err(Refusal::Encoding));
    assert_eq!(adder.add_into(&[], &mut []), Err(Refusal::Shape));
    assert_eq!(adder.add_into(&zero, &mut [0]), Err(Refusal::Shape));
    let mut longer = zero.clone();
    longer.push(0);
    assert_eq!(
        adder.add_into(&longer, &mut longer.clone()),
        Err(Refusal::Shape)
    );
    let fhe = PolynomialAdder::new(profile, Family::Fhe);
    let most = CHUNK_BYTES / fhe.width * fhe.width;
    assert_eq!(fhe.add_into(&vec![0; most], &mut vec![0; most]), Ok(()));
    let over = most + fhe.width;
    assert_eq!(
        fhe.add_into(&vec![0; over], &mut vec![0; over]),
        Err(Refusal::Shape)
    );
}
#[test]
fn only_contribution_polynomials_have_an_aggregate_family() {
    for (participants, options) in [(3, 2), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        for index in [
            profile.fhe_polynomial(0, 0),
            profile.fhe_polynomial(profile.gadget_length() - 1, 5),
            profile.share_common_polynomial(),
            profile.recipient_key_polynomial(participants - 1),
            profile.setup_polynomials(),
        ] {
            assert_eq!(contribution_family(profile, index), None);
        }
        for (index, family) in [
            (profile.fhe_polynomial(0, 1), Family::Fhe),
            (
                profile.fhe_polynomial(profile.gadget_length() - 1, 6),
                Family::Fhe,
            ),
            (profile.share_constant_polynomial(0), Family::Sharing),
            (
                profile.share_linear_polynomial(participants - 1),
                Family::Sharing,
            ),
        ] {
            assert_eq!(contribution_family(profile, index), Some(family));
        }
    }
}
