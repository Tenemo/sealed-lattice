use num_bigint::{BigInt, Sign};
use supported_profile::{Family, Profile};

mod retained;
#[cfg(target_arch = "wasm32")]
#[path = "setup-browser.rs"]
pub mod setup_browser;
pub mod verified;
pub use retained::{
    AggregatePolynomialReader, RetainedAggregatePolynomial, RetainedPolynomialReader,
    RetainedSetupInputs, VerifiedAggregatePolynomial,
};

pub const CHUNK_BYTES: usize = 524_288;

/// The provisional aggregate reference and its original participant's tag.
pub fn selection_reference_bytes(profile: Profile) -> usize {
    4 + 64
        + 64 * profile.contribution_body_polynomials().len()
        + registration_credentials::RETAINED_TAG_BYTES
}

/// The family of a setup polynomial that contribution bodies carry, and so
/// the aggregate sums.
pub fn contribution_family(profile: Profile, index: usize) -> Option<Family> {
    profile
        .contribution_body_polynomials()
        .contains(&index)
        .then(|| profile.setup_family(index))
        .flatten()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Shape,
    Encoding,
}

/// Adds centered coefficients of a family: a sign byte of zero or one
/// before a little-endian magnitude of at most half the modulus, rounded
/// down, with zero never negative. It works in little-endian words.
pub struct PolynomialAdder {
    modulus: Vec<u64>,
    half: Vec<u64>,
    width: usize,
}
impl PolynomialAdder {
    pub fn new(profile: Profile, family: Family) -> Self {
        let bytes = profile.family_modulus(family);
        let mut modulus = vec![0; bytes.len().div_ceil(8)];
        read_words(&bytes, &mut modulus);
        let half = (0..modulus.len())
            .map(|index| {
                (modulus[index] >> 1) | modulus.get(index + 1).map_or(0, |next| next << 63)
            })
            .collect();
        Self {
            modulus,
            half,
            width: 1 + profile.family_magnitude_bytes(family),
        }
    }
    /// A canonical coefficient's sign, with its magnitude in the words.
    fn magnitude(&self, bytes: &[u8], words: &mut [u64]) -> Result<bool, Refusal> {
        if bytes.len() != self.width || bytes[0] > 1 {
            return Err(Refusal::Encoding);
        }
        read_words(&bytes[1..], words);
        let negative = bytes[0] == 1;
        if exceeds(words, &self.half) || (negative && words.iter().all(|word| *word == 0)) {
            return Err(Refusal::Encoding);
        }
        Ok(negative)
    }
    pub(crate) fn decode(&self, bytes: &[u8]) -> Result<BigInt, Refusal> {
        let negative = self.magnitude(bytes, &mut vec![0; self.half.len()])?;
        let value = BigInt::from_bytes_le(Sign::Plus, &bytes[1..]);
        Ok(if negative { -value } else { value })
    }
    /// Both inputs are public canonical coefficients. The destination is scratch;
    /// refusal may leave its earlier coefficients changed and grants no capability.
    pub fn add_into(&self, incoming: &[u8], destination: &mut [u8]) -> Result<(), Refusal> {
        if incoming.is_empty()
            || incoming.len() != destination.len()
            || incoming.len() > CHUNK_BYTES
            || !incoming.len().is_multiple_of(self.width)
        {
            return Err(Refusal::Shape);
        }
        let mut left = vec![0; self.half.len()];
        let mut right = vec![0; self.half.len()];
        for (incoming, destination) in incoming
            .chunks_exact(self.width)
            .zip(destination.chunks_exact_mut(self.width))
        {
            let left_negative = self.magnitude(incoming, &mut left)?;
            let right_negative = self.magnitude(destination, &mut right)?;
            // Magnitudes of one sign sum to at most the modulus, and a sum
            // above half wraps to the modulus less it, of the other sign.
            // Magnitudes of opposite signs differ by at most half.
            let negative = if left_negative == right_negative {
                add(&mut right, &left);
                if exceeds(&right, &self.half) {
                    subtract_from(&mut right, &self.modulus);
                    !left_negative
                } else {
                    left_negative
                }
            } else if exceeds(&left, &right) {
                subtract_from(&mut right, &left);
                left_negative
            } else {
                subtract(&mut right, &left);
                right_negative
            };
            destination[0] = u8::from(negative && right.iter().any(|word| *word != 0));
            write_words(&right, &mut destination[1..])?;
        }
        Ok(())
    }
}

/// The little-endian words of little-endian bytes, the last word padded
/// with zeros.
fn read_words(bytes: &[u8], words: &mut [u64]) {
    for (word, bytes) in words.iter_mut().zip(bytes.chunks(8)) {
        let mut padded = [0; 8];
        padded[..bytes.len()].copy_from_slice(bytes);
        *word = u64::from_le_bytes(padded);
    }
}
/// The little-endian bytes of little-endian words, refused when the bytes
/// cannot hold them.
fn write_words(words: &[u64], bytes: &mut [u8]) -> Result<(), Refusal> {
    for (bytes, word) in bytes.chunks_mut(8).zip(words) {
        let word = word.to_le_bytes();
        if word[bytes.len()..].iter().any(|byte| *byte != 0) {
            return Err(Refusal::Encoding);
        }
        bytes.copy_from_slice(&word[..bytes.len()]);
    }
    Ok(())
}
/// Whether the left words, of the right's length, are greater.
fn exceeds(left: &[u64], right: &[u64]) -> bool {
    left.iter().rev().gt(right.iter().rev())
}
/// Adds the words, whose sum fits, to the target.
fn add(target: &mut [u64], words: &[u64]) {
    let mut carry = false;
    for (target, word) in target.iter_mut().zip(words) {
        let (sum, first) = target.overflowing_add(*word);
        let (sum, second) = sum.overflowing_add(u64::from(carry));
        *target = sum;
        carry = first | second;
    }
    debug_assert!(!carry);
}
/// Subtracts the words, at most the target, from the target.
fn subtract(target: &mut [u64], words: &[u64]) {
    let mut borrow = false;
    for (target, word) in target.iter_mut().zip(words) {
        let (difference, first) = target.overflowing_sub(*word);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        *target = difference;
        borrow = first | second;
    }
    debug_assert!(!borrow);
}
/// Replaces the target with the words, at least the target, less it.
fn subtract_from(target: &mut [u64], words: &[u64]) {
    let mut borrow = false;
    for (target, word) in target.iter_mut().zip(words) {
        let (difference, first) = word.overflowing_sub(*target);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        *target = difference;
        borrow = first | second;
    }
    debug_assert!(!borrow);
}

#[cfg(test)]
mod tests {
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
                assert!(
                    left.magnitude() <= half.magnitude() && right.magnitude() <= half.magnitude()
                );
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
}
