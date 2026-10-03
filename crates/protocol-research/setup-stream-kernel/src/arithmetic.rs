const OFFSET: u128 = 133;
pub const MODULUS: u128 = u128::MAX - (OFFSET << 64) + 2;

#[inline(always)]
pub fn normalize(value: u128) -> u128 {
    let (reduced, borrowed) = value.overflowing_sub(MODULUS);
    reduced.wrapping_add(MODULUS & 0u128.wrapping_sub(u128::from(borrowed)))
}

#[inline(always)]
pub fn add(left: u128, right: u128) -> u128 {
    let (sum, carry) = left.overflowing_add(right);
    let correction = ((OFFSET << 64) - 1) & 0u128.wrapping_sub(u128::from(carry));
    normalize(sum.wrapping_add(correction))
}

#[inline(always)]
pub fn subtract(left: u128, right: u128) -> u128 {
    let (difference, borrowed) = left.overflowing_sub(right);
    difference.wrapping_add(MODULUS & 0u128.wrapping_sub(u128::from(borrowed)))
}

#[inline(always)]
pub fn multiply(left: u128, right: u128) -> u128 {
    if cfg!(target_arch = "wasm32") {
        multiply_bounded(left, right)
    } else {
        multiply_native(left, right)
    }
}

const LIMB_MASK: u64 = 0xffff_ffff;
/// 2^128 modulo the prime.
const SQUARE_RESIDUE: u128 = (OFFSET << 64) - 1;

/// The four 32-bit limbs of a value, each in its own word.
#[inline(always)]
fn limbs(value: u128) -> [u64; 4] {
    [
        value as u64 & LIMB_MASK,
        (value >> 32) as u64 & LIMB_MASK,
        (value >> 64) as u64 & LIMB_MASK,
        (value >> 96) as u64,
    ]
}

/// A sum of products as eight 32-bit columns without carries. WebAssembly
/// has no widening multiplication, so each product of two limbs is a word
/// whose low half joins column i + j and whose high half column i + j + 1.
/// One product adds at most seven terms below 2^32 to a column, so a sum of
/// at most 4,096 products keeps every column below 2^47.
#[derive(Clone, Copy)]
pub struct Columns([u64; 8]);

impl Columns {
    pub const ZERO: Self = Self([0; 8]);

    #[inline(always)]
    pub fn add_product(&mut self, left: u128, right: u128) {
        let (left, right) = (limbs(left), limbs(right));
        for (i, a) in left.iter().enumerate() {
            for (j, b) in right.iter().enumerate() {
                let product = a * b;
                self.0[i + j] = self.0[i + j].wrapping_add(product & LIMB_MASK);
                self.0[i + j + 1] = self.0[i + j + 1].wrapping_add(product >> 32);
            }
        }
    }

    /// Adds twice the other sum, which counts as twice its products.
    #[inline(always)]
    pub fn add_double(&mut self, other: &Self) {
        for (column, value) in self.0.iter_mut().zip(other.0) {
            *column = column.wrapping_add(value << 1);
        }
    }

    /// The residue of the sum, in constant time. With 2^128 = 133 2^64 - 1
    /// modulo the prime, columns four to seven fold into signed columns
    /// zero to three and columns four and five: t4 = 133 s6, t5 = 133 s7,
    /// t0 = s0 - s4 - t4, t1 = s1 - s5 - t5, t2 = s2 + 133 s4 - s6 + 133
    /// t4 and t3 = s3 + 133 s5 - s7 + 133 t5. Every column is below 2^47,
    /// so every folded one is below 2^62 in magnitude. Their signed carry
    /// chain leaves a 128-bit value and a top word below 2^31 in magnitude,
    /// whose own fold top (133 2^64 - 1) is below 2^102 in magnitude.
    #[inline(always)]
    pub fn reduce(self) -> u128 {
        let s = self.0.map(|value| value as i64);
        let t4 = 133 * s[6];
        let t5 = 133 * s[7];
        let t0 = s[0] - s[4] - t4;
        let t1 = s[1] - s[5] - t5 + (t0 >> 32);
        let t2 = s[2] + 133 * s[4] - s[6] + 133 * t4 + (t1 >> 32);
        let t3 = s[3] + 133 * s[5] - s[7] + 133 * t5 + (t2 >> 32);
        let mask = LIMB_MASK as i64;
        let low = (t0 & mask) as u64 | ((t1 & mask) as u64) << 32;
        let high = (t2 & mask) as u64 | ((t3 & mask) as u64) << 32;
        let top = t3 >> 32;
        let adjustment = (i128::from(top * 133) << 64) - i128::from(top);
        let (sum, overflow) =
            ((u128::from(high) << 64) | u128::from(low)).overflowing_add(adjustment as u128);
        // The exact sum carries 2^128 when a nonnegative adjustment
        // overflows and borrows it when a negative one does not; either
        // correction leaves it below 2^128 and at least zero.
        let negative = adjustment < 0;
        let carry = 0u128.wrapping_sub(u128::from(!negative & overflow));
        let borrow = 0u128.wrapping_sub(u128::from(negative & !overflow));
        normalize(
            sum.wrapping_add(SQUARE_RESIDUE & carry)
                .wrapping_sub(SQUARE_RESIDUE & borrow),
        )
    }
}

#[inline(always)]
pub fn multiply_bounded(left: u128, right: u128) -> u128 {
    let mut columns = Columns::ZERO;
    columns.add_product(left, right);
    columns.reduce()
}

/// The product of two elements of the cubic extension with x^3 = 2. On
/// WebAssembly each coordinate is one reduced sum of its three products.
#[inline(always)]
pub fn multiply_extension(left: [u128; 3], right: [u128; 3]) -> [u128; 3] {
    if cfg!(target_arch = "wasm32") {
        multiply_extension_columns(left, right)
    } else {
        multiply_extension_native(left, right)
    }
}

#[inline(always)]
pub fn multiply_extension_columns(left: [u128; 3], right: [u128; 3]) -> [u128; 3] {
    let [a0, a1, a2] = left;
    let [b0, b1, b2] = right;
    let mut constant = Columns::ZERO;
    constant.add_product(a0, b0);
    let mut wrapped = Columns::ZERO;
    wrapped.add_product(a1, b2);
    wrapped.add_product(a2, b1);
    constant.add_double(&wrapped);
    let mut linear = Columns::ZERO;
    linear.add_product(a0, b1);
    linear.add_product(a1, b0);
    let mut square = Columns::ZERO;
    square.add_product(a2, b2);
    linear.add_double(&square);
    let mut quadratic = Columns::ZERO;
    quadratic.add_product(a0, b2);
    quadratic.add_product(a1, b1);
    quadratic.add_product(a2, b0);
    [constant.reduce(), linear.reduce(), quadratic.reduce()]
}

#[inline(always)]
pub fn multiply_extension_native(left: [u128; 3], right: [u128; 3]) -> [u128; 3] {
    let mut result = [0; 3];
    for (first, a) in left.iter().enumerate() {
        for (second, b) in right.iter().enumerate() {
            let mut value = multiply_native(*a, *b);
            if first + second >= 3 {
                value = add(value, value);
            }
            let index = (first + second) % 3;
            result[index] = add(result[index], value);
        }
    }
    result
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

pub fn power(mut value: u128, mut exponent: u128) -> u128 {
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
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut values = edges.to_vec();
        values.extend((0..48).map(|_| ((u128::from(next()) << 64) | u128::from(next())) % MODULUS));
        // Values below 2^64 and just below the modulus stress the carries.
        values.extend((0..8).map(|_| u128::from(next())));
        values.extend((0..8).map(|_| MODULUS - 1 - u128::from(next() >> 8)));
        for left in &values {
            for right in &values {
                let expected = reference_product(*left, *right);
                assert_eq!(multiply_bounded(*left, *right), expected);
                assert_eq!(multiply_native(*left, *right), expected);
            }
        }
    }
    // The most products one column sum may hold before its reduction.
    const COLUMN_PRODUCTS: usize = 4_096;
    #[test]
    fn column_sums_match_independent_modular_sums_up_to_their_bound() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Operands just below the modulus maximize every limb and column.
        for extreme in [false, true] {
            let mut columns = Columns::ZERO;
            let mut expected = 0;
            for _ in 0..COLUMN_PRODUCTS {
                let (left, right) = if extreme {
                    (MODULUS - 1 - u128::from(next() >> 60), MODULUS - 1)
                } else {
                    (
                        ((u128::from(next()) << 64) | u128::from(next())) % MODULUS,
                        ((u128::from(next()) << 64) | u128::from(next())) % MODULUS,
                    )
                };
                columns.add_product(left, right);
                expected = reference_add(expected, reference_product(left, right));
            }
            assert_eq!(columns.reduce(), expected);
        }
        let mut doubled = Columns::ZERO;
        let mut half = Columns::ZERO;
        for _ in 0..COLUMN_PRODUCTS / 2 {
            half.add_product(MODULUS - 1, MODULUS - 1);
        }
        doubled.add_double(&half);
        let square = reference_product(MODULUS - 1, MODULUS - 1);
        let mut expected = 0;
        for _ in 0..COLUMN_PRODUCTS {
            expected = reference_add(expected, square);
        }
        assert_eq!(doubled.reduce(), expected);
    }
    #[test]
    fn extension_products_match_the_schoolbook_rule() {
        let values = [
            [0, 0, 0],
            [1, 0, 0],
            [0, 1, 0],
            [0, 0, 1],
            [MODULUS - 1, MODULUS - 1, MODULUS - 1],
            [17, MODULUS - 2, 1 << 100],
            [(1 << 64) + 5, (1 << 127) + 9, MODULUS - 133],
        ];
        for left in values {
            for right in values {
                // x^3 = 2 wraps the degree three and four products twice.
                let mut expected = [0; 3];
                for (first, a) in left.iter().enumerate() {
                    for (second, b) in right.iter().enumerate() {
                        let mut value = reference_product(*a, *b);
                        if first + second >= 3 {
                            value = reference_add(value, value);
                        }
                        let index = (first + second) % 3;
                        expected[index] = reference_add(expected[index], value);
                    }
                }
                assert_eq!(multiply_extension_columns(left, right), expected);
                assert_eq!(multiply_extension_native(left, right), expected);
            }
        }
    }
}
