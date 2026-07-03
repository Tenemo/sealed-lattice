//! Fixed-width little-endian unsigned integer helpers for CRT constant
//! derivation and centered lifting. These run on cold paths (setup constants
//! and per-coefficient recombination), so clarity wins over throughput.

/// Returns `left < right` for equal-width little-endian limb arrays.
pub(crate) fn is_less_than<const LIMB_COUNT: usize>(
    left: &[u64; LIMB_COUNT],
    right: &[u64; LIMB_COUNT],
) -> bool {
    for index in (0..LIMB_COUNT).rev() {
        if left[index] != right[index] {
            return left[index] < right[index];
        }
    }
    false
}

/// Subtracts `right` from `left` in place, returning the final borrow.
pub(crate) fn subtract_in_place<const LIMB_COUNT: usize>(
    left: &mut [u64; LIMB_COUNT],
    right: &[u64; LIMB_COUNT],
) -> u64 {
    let mut borrow = 0_u64;
    for index in 0..LIMB_COUNT {
        let (without_borrow, underflow_a) = left[index].overflowing_sub(right[index]);
        let (with_borrow, underflow_b) = without_borrow.overflowing_sub(borrow);
        left[index] = with_borrow;
        borrow = u64::from(underflow_a) + u64::from(underflow_b);
    }
    borrow
}

/// Adds `right` into `left` in place, returning the final carry.
pub(crate) fn add_in_place<const LIMB_COUNT: usize>(
    left: &mut [u64; LIMB_COUNT],
    right: &[u64; LIMB_COUNT],
) -> u64 {
    let mut carry = 0_u64;
    for index in 0..LIMB_COUNT {
        let sum = u128::from(left[index]) + u128::from(right[index]) + u128::from(carry);
        left[index] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    carry
}

/// Accumulates `operand * word` into `accumulator`, returning the final
/// carry. The caller is responsible for leaving enough limb headroom.
pub(crate) fn multiply_word_accumulate<const LIMB_COUNT: usize>(
    accumulator: &mut [u64; LIMB_COUNT],
    operand: &[u64; LIMB_COUNT],
    word: u64,
) -> u64 {
    let mut carry = 0_u64;
    for index in 0..LIMB_COUNT {
        let sum = u128::from(accumulator[index])
            + u128::from(operand[index]) * u128::from(word)
            + u128::from(carry);
        accumulator[index] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    carry
}

/// Multiplies `value` by `word` in place, returning the final carry.
pub(crate) fn multiply_word_in_place<const LIMB_COUNT: usize>(
    value: &mut [u64; LIMB_COUNT],
    word: u64,
) -> u64 {
    let mut carry = 0_u64;
    for value_word in value.iter_mut() {
        let product = u128::from(*value_word) * u128::from(word) + u128::from(carry);
        *value_word = product as u64;
        carry = (product >> 64) as u64;
    }
    carry
}

/// Divides `value` by a single word in place and returns the remainder.
pub(crate) fn divide_word_in_place<const LIMB_COUNT: usize>(
    value: &mut [u64; LIMB_COUNT],
    divisor: u64,
) -> u64 {
    let mut remainder = 0_u64;
    for index in (0..LIMB_COUNT).rev() {
        let dividend = (u128::from(remainder) << 64) | u128::from(value[index]);
        value[index] = (dividend / u128::from(divisor)) as u64;
        remainder = (dividend % u128::from(divisor)) as u64;
    }
    remainder
}

/// Returns `value mod divisor` without modifying `value`.
pub(crate) fn remainder_word<const LIMB_COUNT: usize>(
    value: &[u64; LIMB_COUNT],
    divisor: u64,
) -> u64 {
    let mut remainder = 0_u64;
    for index in (0..LIMB_COUNT).rev() {
        let dividend = (u128::from(remainder) << 64) | u128::from(value[index]);
        remainder = (dividend % u128::from(divisor)) as u64;
    }
    remainder
}

/// Shifts `value` right by one bit in place.
pub(crate) fn shift_right_one_in_place<const LIMB_COUNT: usize>(value: &mut [u64; LIMB_COUNT]) {
    let mut carried_bit = 0_u64;
    for index in (0..LIMB_COUNT).rev() {
        let next_carried_bit = value[index] & 1;
        value[index] = (value[index] >> 1) | (carried_bit << 63);
        carried_bit = next_carried_bit;
    }
}

/// Converts a wide value to u64, or None when it does not fit.
pub(crate) fn to_u64<const LIMB_COUNT: usize>(value: &[u64; LIMB_COUNT]) -> Option<u64> {
    if value[1..].iter().any(|limb| *limb != 0) {
        return None;
    }
    Some(value[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn to_biguint<const LIMB_COUNT: usize>(value: &[u64; LIMB_COUNT]) -> BigUint {
        let mut result = BigUint::from(0_u32);
        for index in (0..LIMB_COUNT).rev() {
            result = (result << 64) | BigUint::from(value[index]);
        }
        result
    }

    #[test]
    fn multiply_divide_and_remainder_agree_with_bigint() {
        let mut value = [0_u64; 4];
        value[0] = 1;
        let mut expected = BigUint::from(1_u32);
        for word in [
            140_737_487_306_753_u64,
            140_737_486_716_929,
            0xffff_ffff_ffff_ffc5,
            3,
            65_537,
        ] {
            let carry = multiply_word_in_place(&mut value, word);
            assert_eq!(carry, 0);
            expected *= BigUint::from(word);
            assert_eq!(to_biguint(&value), expected);
        }
        assert_eq!(
            remainder_word(&value, 1_000_003),
            (expected.clone() % BigUint::from(1_000_003_u64))
                .to_u64_digits()
                .first()
                .copied()
                .unwrap_or(0)
        );
        let mut quotient = value;
        let remainder = divide_word_in_place(&mut quotient, 140_737_487_306_753);
        assert_eq!(remainder, 0);
        assert_eq!(
            to_biguint(&quotient),
            expected / BigUint::from(140_737_487_306_753_u64)
        );
    }

    #[test]
    fn add_subtract_compare_round_trip() {
        let left = [u64::MAX, 7, 0, 1];
        let right = [5, u64::MAX, 2, 0];
        let mut sum = left;
        let carry = add_in_place(&mut sum, &right);
        assert_eq!(carry, 0);
        assert_eq!(to_biguint(&sum), to_biguint(&left) + to_biguint(&right));
        let mut difference = sum;
        let borrow = subtract_in_place(&mut difference, &right);
        assert_eq!(borrow, 0);
        assert_eq!(difference, left);
        assert!(is_less_than(&right, &left));
        assert!(!is_less_than(&left, &right));
        assert!(!is_less_than(&left, &left));
    }

    #[test]
    fn shift_right_halves_the_value() {
        let mut value = [0x8000_0000_0000_0001_u64, 0b1011, 0, 0];
        let expected = (to_biguint(&value)) >> 1;
        shift_right_one_in_place(&mut value);
        assert_eq!(to_biguint(&value), expected);
    }
}
