use zeroize::Zeroizing;

pub const RADIX_BITS: usize = 96;
pub const RADIX: u128 = 1u128 << RADIX_BITS;
const MASK: u128 = RADIX - 1;
const MAXIMUM_LIMBS: usize = 9;

pub struct Modulus {
    pub digits: Vec<u128>,
    ceiling_half: Vec<u128>,
}
pub struct Reduced {
    pub negative: bool,
    // The exact identity is input = centered_output + quotient * modulus.
    pub quotient: i128,
}
impl Modulus {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.is_empty() || bytes.len() > 12 * MAXIMUM_LIMBS || bytes[0] & 1 == 0 {
            return Err(());
        }
        let mut digits = Vec::new();
        for chunk in bytes.chunks(12) {
            let mut value = [0; 16];
            value[..chunk.len()].copy_from_slice(chunk);
            digits.push(u128::from_le_bytes(value));
        }
        if digits.last().copied().unwrap() <= 65536 {
            return Err(());
        }
        let mut ceiling_half = digits.clone();
        let mut carried = 0;
        for digit in ceiling_half.iter_mut().rev() {
            let next = *digit & 1;
            *digit = (*digit >> 1) | (carried << 95);
            carried = next;
        }
        let mut carry = 1;
        for digit in &mut ceiling_half {
            let value = *digit + carry;
            *digit = value & MASK;
            carry = value >> 96;
        }
        Ok(Self {
            digits,
            ceiling_half,
        })
    }
    pub fn reduce(&self, raw: &[i128], output: &mut [u128]) -> Result<Reduced, ()> {
        let count = self.digits.len();
        if raw.len() != count || output.len() != count {
            return Err(());
        }
        let mut magnitude = Zeroizing::new([0u128; MAXIMUM_LIMBS]);
        let mut remainder = Zeroizing::new([0u128; MAXIMUM_LIMBS]);
        let mut carry = 0i128;
        for index in 0..count {
            let value = raw[index].checked_add(carry).ok_or(())?;
            magnitude[index] = (value as u128) & MASK;
            carry = value >> 96;
        }
        let negative = ((carry >> 127) & 1) as u128;
        let sign_mask = 0u128.wrapping_sub(negative);
        let mut inverse_carry = 1u128;
        for digit in magnitude.iter_mut().take(count) {
            let inverted = MASK - *digit + inverse_carry;
            inverse_carry = inverted >> 96;
            *digit ^= (*digit ^ (inverted & MASK)) & sign_mask;
        }
        let positive_high = carry as u128;
        let negative_high = 0u128
            .wrapping_sub(positive_high)
            .wrapping_sub(1)
            .wrapping_add(inverse_carry);
        let high = positive_high ^ ((positive_high ^ negative_high) & sign_mask);
        let top = high
            .checked_mul(RADIX)
            .and_then(|value| value.checked_add(magnitude[count - 1]))
            .ok_or(())?;
        let modulus_top = self.digits[count - 1];
        if top >= modulus_top << 16 {
            return Err(());
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
            product_carry = product >> 96;
            let difference = magnitude[index] as i128 - (product & MASK) as i128 - borrow;
            borrow = (difference >> 127) & 1;
            remainder[index] = difference as u128 & MASK;
        }
        let mut high_difference = high as i128 - product_carry as i128 - borrow;
        if !matches!(high_difference, 0 | -1) {
            return Err(());
        }
        let correction = ((high_difference >> 127) & 1) as u128;
        let correction_mask = 0u128.wrapping_sub(correction);
        let mut addition_carry = 0u128;
        for index in 0..count {
            let value = remainder[index] + (self.digits[index] & correction_mask) + addition_carry;
            remainder[index] = value & MASK;
            addition_carry = value >> 96;
        }
        high_difference += addition_carry as i128;
        if high_difference != 0 {
            return Err(());
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
            let complemented = difference as u128 & MASK;
            output[index] = remainder[index] ^ ((remainder[index] ^ complemented) & wrap_mask);
            nonzero |= output[index];
        }
        Ok(Reduced {
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
    const PARAMETERS: &[u8; 137] = include_bytes!("../../setup-proof/parameters.bin");
    #[test]
    fn centered_values_and_exact_quotients_match_big_integer_division() {
        for bytes in [
            &PARAMETERS[4..112],
            &PARAMETERS[112..132],
            &PARAMETERS[132..137],
        ] {
            let modulus = Modulus::from_bytes(bytes).unwrap();
            let integer_modulus = BigInt::from_bytes_le(Sign::Plus, bytes);
            let half = &integer_modulus >> 1usize;
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
                        let count = modulus.digits.len();
                        let mut raw: Vec<i128> = (0..count)
                            .map(|index| {
                                let value = &absolute >> (96 * index);
                                let digit = if index + 1 == count {
                                    value
                                } else {
                                    value & BigInt::from(MASK)
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
                                raw[0] += transfer * RADIX as i128;
                                raw[1] -= transfer;
                            }
                            let mut output = vec![0; count];
                            let reduced = modulus.reduce(&raw, &mut output).unwrap();
                            let magnitude =
                                output.iter().rev().fold(BigInt::zero(), |sum, value| {
                                    (sum << 96usize) + BigInt::from(*value)
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
                            assert!(output.iter().all(|digit| *digit < RADIX));
                            assert!(!actual.is_zero() || !reduced.negative);
                            if count > 1 {
                                raw[0] -= transfer * RADIX as i128;
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
        let modulus = Modulus::from_bytes(&PARAMETERS[4..112]).unwrap();
        let mut raw = vec![0; 9];
        raw[8] = (modulus.digits[8] << 16) as i128;
        assert!(modulus.reduce(&raw, &mut [0; 9]).is_err());
        assert!(modulus.reduce(&[0; 8], &mut [0; 9]).is_err());
        assert!(Modulus::from_bytes(&[]).is_err());
    }
}
