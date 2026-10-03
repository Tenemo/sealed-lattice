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
mod tests {
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
                        let raw_integer =
                            (BigInt::from(factor) * &integer_modulus + &residue) * sign;
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
                            let magnitude =
                                output.iter().rev().fold(BigInt::zero(), |sum, value| {
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
}
