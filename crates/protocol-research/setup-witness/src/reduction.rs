use num_bigint::BigUint;
use zeroize::Zeroizing;

// Enough limbs for every supported modulus at the narrowest limb.
pub const MAXIMUM_LIMBS: usize = 16;

pub struct Modulus {
    pub digits: Vec<u128>,
    ceiling_half: Vec<u128>,
    radix_bits: usize,
    mask: u128,
}
pub struct Reduced {
    pub negative: bool,
    // The exact identity is input = centered_output + quotient * modulus.
    pub quotient: i128,
}
impl Modulus {
    /// An odd little-endian modulus split into limbs of `radix_bits` bits.
    pub fn new(bytes: &[u8], radix_bits: usize) -> Option<Self> {
        if bytes.is_empty() || bytes[0] & 1 == 0 || !(17..=96).contains(&radix_bits) {
            return None;
        }
        let mask = (1u128 << radix_bits) - 1;
        let split = |mut value: BigUint| {
            let mut digits = Vec::new();
            while value != BigUint::ZERO {
                let low = &value & BigUint::from(mask);
                digits.push(
                    low.iter_u64_digits()
                        .rev()
                        .fold(0u128, |sum, word| (sum << 64) | u128::from(word)),
                );
                value >>= radix_bits;
            }
            digits
        };
        let value = BigUint::from_bytes_le(bytes);
        let digits = split(value.clone());
        if digits.len() > MAXIMUM_LIMBS || digits.last().copied().unwrap() <= 65536 {
            return None;
        }
        let mut ceiling_half = split((value >> 1usize) + 1u8);
        ceiling_half.resize(digits.len(), 0);
        Some(Self {
            digits,
            ceiling_half,
            radix_bits,
            mask,
        })
    }
    pub fn reduce(&self, raw: &[i128], output: &mut [u128]) -> Option<Reduced> {
        let count = self.digits.len();
        let bits = self.radix_bits;
        let mask = self.mask;
        if raw.len() != count || output.len() != count {
            return None;
        }
        let mut magnitude = Zeroizing::new([0u128; MAXIMUM_LIMBS]);
        let mut remainder = Zeroizing::new([0u128; MAXIMUM_LIMBS]);
        let mut carry = 0i128;
        for index in 0..count {
            let value = raw[index].checked_add(carry)?;
            magnitude[index] = (value as u128) & mask;
            carry = value >> bits;
        }
        let negative = ((carry >> 127) & 1) as u128;
        let sign_mask = 0u128.wrapping_sub(negative);
        let mut inverse_carry = 1u128;
        for digit in magnitude.iter_mut().take(count) {
            let inverted = mask - *digit + inverse_carry;
            inverse_carry = inverted >> bits;
            *digit ^= (*digit ^ (inverted & mask)) & sign_mask;
        }
        let positive_high = carry as u128;
        let negative_high = 0u128
            .wrapping_sub(positive_high)
            .wrapping_sub(1)
            .wrapping_add(inverse_carry);
        let high = positive_high ^ ((positive_high ^ negative_high) & sign_mask);
        let top = high
            .checked_mul(1u128 << bits)
            .and_then(|value| value.checked_add(magnitude[count - 1]))?;
        let modulus_top = self.digits[count - 1];
        if top >= modulus_top << 16 {
            return None;
        }
        let mut quotient = 0u128;
        for bit in (0..16).rev() {
            let candidate = quotient | (1u128 << bit);
            let difference = top as i128 - (candidate * modulus_top) as i128;
            let take = 1 - ((difference >> 127) & 1);
            quotient |= (take as u128) << bit;
        }
        // Ignoring lower modulus limbs gives an upper quotient estimate.
        // Since that estimate is smaller than the leading modulus limb, it
        // exceeds the exact quotient by at most one.
        let mut product_carry = 0u128;
        let mut borrow = 0i128;
        for index in 0..count {
            let product = self.digits[index] * quotient + product_carry;
            product_carry = product >> bits;
            let difference = magnitude[index] as i128 - (product & mask) as i128 - borrow;
            borrow = (difference >> 127) & 1;
            remainder[index] = difference as u128 & mask;
        }
        let mut high_difference = high as i128 - product_carry as i128 - borrow;
        if !matches!(high_difference, 0 | -1) {
            return None;
        }
        let correction = ((high_difference >> 127) & 1) as u128;
        let correction_mask = 0u128.wrapping_sub(correction);
        let mut addition_carry = 0u128;
        for index in 0..count {
            let value = remainder[index] + (self.digits[index] & correction_mask) + addition_carry;
            remainder[index] = value & mask;
            addition_carry = value >> bits;
        }
        high_difference += addition_carry as i128;
        if high_difference != 0 {
            return None;
        }
        quotient -= correction;
        borrow = 0;
        for index in 0..count {
            let difference = remainder[index] as i128 - self.ceiling_half[index] as i128 - borrow;
            borrow = (difference >> 127) & 1;
        }
        let wrap = (1 - borrow) as u128;
        let wrap_mask = 0u128.wrapping_sub(wrap);
        borrow = 0;
        let mut nonzero = 0;
        for index in 0..count {
            let difference = self.digits[index] as i128 - remainder[index] as i128 - borrow;
            borrow = (difference >> 127) & 1;
            let complemented = difference as u128 & mask;
            output[index] = remainder[index] ^ ((remainder[index] ^ complemented) & wrap_mask);
            nonzero |= output[index];
        }
        Some(Reduced {
            negative: (negative ^ wrap) != 0 && nonzero != 0,
            quotient: (quotient + wrap) as i128 * (1 - 2 * negative as i128),
        })
    }
}

#[cfg(test)]
#[path = "reduction-tests.rs"]
mod tests;
