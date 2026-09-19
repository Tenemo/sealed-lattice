const OFFSET: u128 = 133;
pub(crate) const MODULUS: u128 = u128::MAX - (OFFSET << 64) + 2;

#[inline(always)]
pub(crate) fn normalize(value: u128) -> u128 {
    let (reduced, borrowed) = value.overflowing_sub(MODULUS);
    reduced.wrapping_add(MODULUS & 0u128.wrapping_sub(u128::from(borrowed)))
}

#[inline(always)]
pub(crate) fn add(left: u128, right: u128) -> u128 {
    let (sum, carry) = left.overflowing_add(right);
    let correction = ((OFFSET << 64) - 1) & 0u128.wrapping_sub(u128::from(carry));
    normalize(sum.wrapping_add(correction))
}

#[inline(always)]
pub(crate) fn subtract(left: u128, right: u128) -> u128 {
    let (difference, borrowed) = left.overflowing_sub(right);
    difference.wrapping_add(MODULUS & 0u128.wrapping_sub(u128::from(borrowed)))
}

#[inline(always)]
pub(crate) fn multiply(left: u128, right: u128) -> u128 {
    if cfg!(target_arch = "wasm32") {
        multiply_bounded(left, right)
    } else {
        multiply_native(left, right)
    }
}

#[inline(always)]
fn multiply_small_coefficient(value: u64, factor: u16) -> i128 {
    let lower = (value as u32 as u64) * u64::from(factor);
    let upper = (value >> 32) * u64::from(factor) + (lower >> 32);
    (((upper as u128) << 32) | lower as u32 as u128) as i128
}

#[inline(always)]
pub(crate) fn multiply_bounded(left: u128, right: u128) -> u128 {
    let (left_low, left_high) = (left as u64 as u128, left >> 64);
    let (right_low, right_high) = (right as u64 as u128, right >> 64);
    let low = left_low * right_low;
    let middle = left_low * right_high + (low >> 64);
    let other_middle = left_high * right_low + (middle as u64 as u128);
    let high = left_high * right_high + (middle >> 64) + (other_middle >> 64);
    let limbs = [
        low as u64,
        other_middle as u64,
        high as u64,
        (high >> 64) as u64,
    ];
    let constant = limbs[0] as i128 - limbs[2] as i128 - multiply_small_coefficient(limbs[3], 133);
    let linear = limbs[1] as i128
        + multiply_small_coefficient(limbs[2], 133)
        + multiply_small_coefficient(limbs[3], 17_688)
        + (constant >> 64);
    // With B=2^64, the first high limb is in 0..=17821. The next is
    // in 0..=1; if it is one, the final linear limb is below 2370326.
    // These casts are exact, and each small product uses only u64 multiplies.
    debug_assert!((0..=17821).contains(&(linear >> 64)));
    let folded = (linear >> 64) as u16;
    let constant_second = constant as u64 as i128 - i128::from(folded);
    let linear_second =
        linear as u64 as i128 + i128::from(u64::from(folded) * 133) + (constant_second >> 64);
    debug_assert!((0..=1).contains(&(linear_second >> 64)));
    let last = (linear_second >> 64) as u8;
    let constant_third = constant_second as u64 as i128 - i128::from(last);
    let linear_third =
        linear_second as u64 as i128 + i128::from(u64::from(last) * 133) + (constant_third >> 64);
    debug_assert!((0..=(u64::MAX as i128)).contains(&linear_third));
    normalize(((linear_third as u128) << 64) | constant_third as u64 as u128)
}

#[inline(always)]
fn multiply_native(left: u128, right: u128) -> u128 {
    let (left_low, left_high) = (left as u64 as u128, left >> 64);
    let (right_low, right_high) = (right as u64 as u128, right >> 64);
    let low = left_low * right_low;
    let middle = left_low * right_high + (low >> 64);
    let other_middle = left_high * right_low + (middle as u64 as u128);
    let high = left_high * right_high + (middle >> 64) + (other_middle >> 64);
    let limbs = [
        low as u64,
        other_middle as u64,
        high as u64,
        (high >> 64) as u64,
    ];

    // For B=2^64, B^2=133B-1 and B^3=(133^2-1)B-133.
    // The signed accumulators are smaller than 2^80. Two further folds
    // leave a value below B^2, requiring at most one subtraction of p.
    let constant = limbs[0] as i128 - limbs[2] as i128 - 133 * limbs[3] as i128;
    let linear =
        limbs[1] as i128 + 133 * limbs[2] as i128 + 17_688 * limbs[3] as i128 + (constant >> 64);
    let constant_second = constant as u64 as i128 - (linear >> 64);
    let linear_second = linear as u64 as i128 + 133 * (linear >> 64) + (constant_second >> 64);
    let constant_third = constant_second as u64 as i128 - (linear_second >> 64);
    let linear_third =
        linear_second as u64 as i128 + 133 * (linear_second >> 64) + (constant_third >> 64);
    debug_assert!((0..=(u64::MAX as i128)).contains(&linear_third));
    normalize(((linear_third as u128) << 64) | constant_third as u64 as u128)
}

pub(crate) fn power(mut value: u128, mut exponent: u128) -> u128 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value);
        }
        value = multiply(value, value);
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_add(left: u128, right: u128) -> u128 {
        if left >= MODULUS - right {
            left - (MODULUS - right)
        } else {
            left + right
        }
    }
    fn reference_product(mut left: u128, mut right: u128) -> u128 {
        let mut result = 0;
        while right != 0 {
            if right & 1 != 0 {
                result = reference_add(result, left);
            }
            left = reference_add(left, left);
            right >>= 1;
        }
        result
    }
    #[test]
    fn reduction_variants_match_independent_bitwise_modular_products() {
        let edges = [
            0,
            1,
            2,
            (1u128 << 64) - 1,
            1u128 << 64,
            (1u128 << 64) + 1,
            MODULUS - 2,
            MODULUS - 1,
        ];
        for left in edges {
            for right in edges {
                let expected = reference_product(left, right);
                assert_eq!(multiply_bounded(left, right), expected);
                assert_eq!(multiply_native(left, right), expected);
            }
        }
    }
}
