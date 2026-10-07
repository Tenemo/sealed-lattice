use crate::common_polynomial::public_reader;
use num_bigint::{BigInt, BigUint, Sign};
use sha3::digest::XofReader;
use supported_profile::ProthModulus;

// The centered residues of public_polynomial's samples modulo a Proth prime
// Q = k * 2^e + 1, without dividing by Q. A sample X = H * 2^e + L, with
// H = q * k + r, is congruent to T = r * 2^e + L - q, and since T is below Q
// and above -Q, the least residue is T, or T + Q when T is negative.
pub(crate) struct ProthReduction {
    exponent: usize,
    odd_factor: u64,
    sample_bytes: usize,
    // Words of a sample, of its part from the exponent's bit, and of the
    // modulus.
    sample_words: usize,
    high_words: usize,
    words: usize,
    modulus: Vec<u64>,
    // The largest least residue that stays nonnegative: k * 2^(e - 1).
    half: Vec<u64>,
}

// The little-endian words of k * 2^shift, in the count of words.
fn shifted(odd_factor: u64, shift: usize, words: usize) -> Vec<u64> {
    let mut value = vec![0; words];
    value[shift / 64] = odd_factor << (shift % 64);
    if !shift.is_multiple_of(64) && shift / 64 + 1 < words {
        value[shift / 64 + 1] = odd_factor >> (64 - shift % 64);
    }
    value
}

impl ProthReduction {
    pub(crate) fn new(modulus: ProthModulus, sample_bits: usize) -> Self {
        let exponent = modulus.exponent();
        let words = modulus.bits().div_ceil(64);
        // The quotient q is below 2^(sample_bits - e), which the single
        // correction needs to be below Q; the words fit the fixed buffers.
        assert!(
            sample_bits.is_multiple_of(8)
                && sample_bits > exponent
                && sample_bits - exponent < exponent
                && sample_bits.div_ceil(64).max(words) < 32
                && sample_bits - exponent <= 64 * 8
        );
        let mut value = shifted(u64::from(modulus.odd_factor()), exponent, words);
        value[0] |= 1;
        Self {
            exponent,
            odd_factor: u64::from(modulus.odd_factor()),
            sample_bytes: sample_bits / 8,
            sample_words: sample_bits.div_ceil(64),
            high_words: (sample_bits - exponent).div_ceil(64),
            words,
            modulus: value,
            half: shifted(u64::from(modulus.odd_factor()), exponent - 1, words),
        }
    }

    /// Words of a centered residue's magnitude.
    pub(crate) fn words(&self) -> usize {
        self.words
    }

    /// Writes the magnitude of the little-endian sample's centered residue
    /// and returns whether the residue is negative.
    pub(crate) fn centered(&self, sample: &[u8], magnitude: &mut [u64]) -> bool {
        assert!(sample.len() == self.sample_bytes && magnitude.len() == self.words);
        let mut value = [0u64; 32];
        let value = &mut value[..self.sample_words.max(self.words) + 1];
        for (index, byte) in sample.iter().enumerate() {
            value[index / 8] |= u64::from(*byte) << (8 * (index % 8));
        }
        let (word, bit) = (self.exponent / 64, self.exponent % 64);
        // The quotient and remainder of H by k, one half word at a time
        // from the most significant.
        let mut quotient = [0u64; 8];
        let quotient = &mut quotient[..self.high_words];
        let mut remainder = 0u64;
        for index in (0..self.high_words).rev() {
            let low = value[word + index] >> bit;
            let high = if bit > 0 {
                value[word + index + 1] << (64 - bit)
            } else {
                0
            };
            let high_part = low | high;
            for half in [high_part >> 32, high_part & 0xffff_ffff] {
                let current = (remainder << 32) | half;
                quotient[index] = (quotient[index] << 32) | (current / self.odd_factor);
                remainder = current % self.odd_factor;
            }
        }
        // T = r * 2^e + L, less q.
        magnitude.copy_from_slice(&value[..self.words]);
        magnitude[word] &= (1u64 << bit) - 1;
        magnitude[word] |= remainder << bit;
        for (offset, entry) in magnitude.iter_mut().enumerate().skip(word + 1) {
            *entry = if offset == word + 1 && bit > 0 {
                remainder >> (64 - bit)
            } else {
                0
            };
        }
        let mut borrow = 0u64;
        for (index, entry) in magnitude.iter_mut().enumerate() {
            let subtrahend = quotient.get(index).copied().unwrap_or(0);
            let (difference, first) = entry.overflowing_sub(subtrahend);
            let (difference, second) = difference.overflowing_sub(borrow);
            *entry = difference;
            borrow = u64::from(first || second);
        }
        if borrow != 0 {
            let mut carry = 0u64;
            for (entry, modulus) in magnitude.iter_mut().zip(&self.modulus) {
                let (sum, first) = entry.overflowing_add(*modulus);
                let (sum, second) = sum.overflowing_add(carry);
                *entry = sum;
                carry = u64::from(first || second);
            }
        }
        // Above half the modulus the centered residue is T - Q.
        let above = magnitude
            .iter()
            .rev()
            .zip(self.half.iter().rev())
            .find(|(value, half)| value != half)
            .is_some_and(|(value, half)| value > half);
        if above {
            let mut borrow = 0u64;
            for (entry, modulus) in magnitude.iter_mut().zip(&self.modulus) {
                let (difference, first) = modulus.overflowing_sub(*entry);
                let (difference, second) = difference.overflowing_sub(borrow);
                *entry = difference;
                borrow = u64::from(first || second);
            }
        }
        above
    }

    // Calls the function with each coefficient's sign and magnitude words.
    fn sample(&self, label: &str, degree: usize, mut use_coefficient: impl FnMut(bool, &[u64])) {
        let mut random = public_reader(label);
        let mut sample = vec![0u8; self.sample_bytes];
        let mut magnitude = vec![0u64; self.words];
        for _ in 0..degree {
            random.read(&mut sample);
            let negative = self.centered(&sample, &mut magnitude);
            use_coefficient(negative, &magnitude);
        }
    }
}

/// public_polynomial modulo a Proth prime.
pub(crate) fn proth_public_polynomial(
    label: &str,
    degree: usize,
    modulus: ProthModulus,
    sample_bits: usize,
) -> Vec<BigInt> {
    let reduction = ProthReduction::new(modulus, sample_bits);
    let mut values = Vec::with_capacity(degree);
    let mut digits = Vec::with_capacity(2 * reduction.words());
    reduction.sample(label, degree, |negative, magnitude| {
        digits.clear();
        for word in magnitude {
            digits.extend([*word as u32, (*word >> 32) as u32]);
        }
        let sign = if negative { Sign::Minus } else { Sign::Plus };
        values.push(BigInt::from_biguint(sign, BigUint::from_slice(&digits)));
    });
    values
}

/// public_records modulo a Proth prime.
pub(crate) fn proth_public_records(
    label: &str,
    degree: usize,
    modulus: ProthModulus,
    sample_bits: usize,
) -> Vec<u8> {
    let reduction = ProthReduction::new(modulus, sample_bits);
    let width = modulus.byte_length();
    // Each magnitude's words pass through a buffer, so the records never
    // outgrow their exact length.
    let mut records = Vec::with_capacity(degree * (1 + width));
    let mut bytes = vec![0u8; 8 * reduction.words()];
    reduction.sample(label, degree, |negative, magnitude| {
        for (chunk, word) in bytes.chunks_exact_mut(8).zip(magnitude) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        records.push(u8::from(negative));
        records.extend_from_slice(&bytes[..width]);
    });
    records
}

#[cfg(test)]
#[path = "proth-common-polynomial-tests.rs"]
mod tests;
