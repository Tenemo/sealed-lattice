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
