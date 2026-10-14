use super::*;
use supported_profile::{Family, Profile};

// The record of a value, written independently through its byte expansion.
fn record_of(value: &BigInt, width: usize) -> Vec<u8> {
    let (sign, magnitude) = value.to_bytes_le();
    let mut record = vec![0; width];
    record[0] = u8::from(sign == Sign::Minus);
    record[1..1 + magnitude.len()].copy_from_slice(&magnitude);
    record
}

fn moduli() -> Vec<Vec<u8>> {
    let mut moduli: Vec<_> = [(3, 2), (4, 20), (10, 10), (20, 2), (20, 20)]
        .into_iter()
        .flat_map(|(participants, options)| {
            let profile = Profile::new(participants, options).unwrap();
            [Family::Fhe, Family::Sharing, Family::Auxiliary]
                .map(|family| profile.family_modulus(family))
        })
        .collect();
    moduli.push(Profile::new(10, 10).unwrap().release_modulus().to_bytes());
    moduli
}

#[test]
fn accepts_exactly_the_centered_range_and_decodes_it() {
    for modulus in moduli() {
        let codec = CenteredCodec::new(&modulus);
        let width = codec.record_bytes();
        assert_eq!(width, 1 + modulus.len());
        let half = BigInt::from_bytes_le(Sign::Plus, &modulus) >> 1usize;
        for value in [
            half.clone(),
            -&half,
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(-1),
        ] {
            let record = record_of(&value, width);
            assert_eq!(codec.decode(&record), Some(value));
        }
        let beyond = record_of(&(&half + 1), width);
        assert!(!codec.is_canonical(&beyond));
        assert!(!codec.is_canonical(&record_of(&(-&half - 1), width)));
        let mut negative_zero = vec![0; width];
        negative_zero[0] = 1;
        assert!(!codec.is_canonical(&negative_zero));
        let mut sign_two = record_of(&BigInt::from(1), width);
        sign_two[0] = 2;
        assert!(!codec.is_canonical(&sign_two));
        let one = record_of(&BigInt::from(1), width);
        assert!(!codec.is_canonical(&one[..width - 1]));
        assert!(!codec.is_canonical(&[one.as_slice(), &[0]].concat()));
        assert!(!codec.is_canonical(&[]));
        // A polynomial decodes whole canonical records only.
        let polynomial = [one.clone(), record_of(&-&half, width)].concat();
        assert_eq!(
            codec.decode_all(&polynomial),
            Some(vec![BigInt::from(1), -&half])
        );
        assert_eq!(codec.decode_all(&polynomial[1..]), None);
        assert_eq!(codec.decode_all(&[one, beyond].concat()), None);
    }
}

#[test]
fn encodes_canonical_bytes_across_limb_and_modulus_boundaries() {
    for modulus in moduli() {
        let half = BigInt::from_bytes_le(Sign::Plus, &modulus) >> 1usize;
        let mut encoded = vec![0xa5; 1 + modulus.len()];
        let mut check = |value: &BigInt| {
            encode(value, &mut encoded);
            assert_eq!(encoded, record_of(value, encoded.len()));
        };
        check(&half);
        check(&-&half);
        for bit in [0usize, 7, 8, 31, 32, 63, 64, 65, 95, 96, 127, 128] {
            let value = BigInt::from(1) << bit;
            for nearby in [&value - 1, value.clone(), &value + 1] {
                if nearby > half {
                    continue;
                }
                check(&nearby);
                check(&-nearby);
            }
        }
        // Reusing a buffer after a full-width negative value must clear
        // both its sign and every unused high byte.
        check(&-&half);
        check(&BigInt::from(0));
        check(&BigInt::from(1));
    }
}

#[test]
fn encodes_partial_final_limbs_without_truncating() {
    for width in [1usize, 7, 8, 9, 15, 16, 17] {
        let maximum: BigInt = (BigInt::from(1) << (width * 8)) - 1;
        let mut encoded = vec![0xa5; width + 1];
        for value in [maximum.clone(), -maximum] {
            encode(&value, &mut encoded);
            assert_eq!(encoded, record_of(&value, width + 1));
        }
    }
}

#[test]
#[should_panic]
fn refuses_to_encode_an_overwidth_magnitude() {
    encode(&(BigInt::from(1) << 72usize), &mut [0; 10]);
}
