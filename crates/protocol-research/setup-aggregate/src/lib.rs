use num_bigint::{BigInt, Sign};
use supported_profile::{Family, Profile};

#[path = "offer-verifier.rs"]
pub mod offer_verifier;
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
        + protocol_foundations::RETAINED_TAG_BYTES
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
#[path = "lib-tests.rs"]
mod tests;
