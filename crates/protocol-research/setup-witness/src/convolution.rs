#[path = "../../setup-stream-kernel/src/arithmetic.rs"]
mod field;
use field::{MODULUS, add, multiply, power, subtract};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use zeroize::Zeroizing;

pub const RADIX_BITS: usize = 96;
pub const RADIX: i128 = 1i128 << RADIX_BITS;

pub fn digit(value: &BigInt, limb: usize) -> i128 {
    let magnitude = (value.abs() >> (RADIX_BITS * limb)) & BigInt::from(RADIX - 1);
    let result = magnitude.to_i128().unwrap();
    if value.is_negative() { -result } else { result }
}

pub struct Plan {
    degree: usize,
    forward: Vec<u128>,
    inverse: Vec<u128>,
    twist: Vec<u128>,
    inverse_twist: Vec<u128>,
    inverse_degree: u128,
}
impl Plan {
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two() && (2..=65_536).contains(&degree));
        let root = power(7, (MODULUS - 1) / (2 * degree) as u128);
        assert_eq!(power(root, degree as u128), MODULUS - 1);
        assert_eq!(power(root, (2 * degree) as u128), 1);
        let inverse_root = power(root, MODULUS - 2);
        let powers = |root, length| {
            let mut values = vec![1; length];
            for index in 1..length {
                values[index] = multiply(values[index - 1], root);
            }
            values
        };
        Self {
            degree,
            forward: powers(multiply(root, root), degree / 2),
            inverse: powers(multiply(inverse_root, inverse_root), degree / 2),
            twist: powers(root, degree),
            inverse_twist: powers(inverse_root, degree),
            inverse_degree: power(degree as u128, MODULUS - 2),
        }
    }
    fn transform(&self, values: &mut [u128], inverse: bool) {
        assert_eq!(values.len(), self.degree);
        let logarithm = self.degree.ilog2();
        for index in 0..self.degree {
            let reversed = index.reverse_bits() >> (usize::BITS - logarithm);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
        let twiddles = if inverse {
            &self.inverse
        } else {
            &self.forward
        };
        let mut width = 2;
        while width <= self.degree {
            let stride = self.degree / width;
            for block in values.chunks_exact_mut(width) {
                let (left, right) = block.split_at_mut(width / 2);
                for (index, (lower, upper)) in left.iter_mut().zip(right.iter_mut()).enumerate() {
                    let product = multiply(*upper, twiddles[index * stride]);
                    let original = *lower;
                    *lower = add(original, product);
                    *upper = subtract(original, product);
                }
            }
            width *= 2;
        }
        if inverse {
            for value in values {
                *value = multiply(*value, self.inverse_degree);
            }
        }
    }
    pub fn sparse_transform(&self, sparse: &[i8]) -> Vec<u128> {
        assert_eq!(sparse.len(), self.degree);
        let mut values: Vec<u128> = sparse
            .iter()
            .zip(&self.twist)
            .map(|(value, twist)| match value {
                -1 => subtract(0, *twist),
                0 => 0,
                1 => *twist,
                _ => panic!("nonternary coefficient"),
            })
            .collect();
        self.transform(&mut values, false);
        values
    }
    pub fn digit_products(
        &self,
        public: &[BigInt],
        sparse: &[i8],
        transformed: &[u128],
        limbs: usize,
    ) -> Vec<Vec<i128>> {
        assert_eq!(public.len(), self.degree);
        assert_eq!(transformed.len(), self.degree);
        let support = sparse
            .iter()
            .map(|value| value.unsigned_abs() as u128)
            .sum::<u128>();
        assert!(support * (RADIX as u128 - 1) < MODULUS / 2);
        let result: Vec<Vec<i128>> = (0..limbs)
            .map(|limb| {
                let mut values = Zeroizing::new(
                    public
                        .iter()
                        .zip(&self.twist)
                        .map(|(value, twist)| {
                            let value = digit(value, limb);
                            let residue = if value < 0 {
                                MODULUS - value.unsigned_abs()
                            } else {
                                value as u128
                            };
                            multiply(residue, *twist)
                        })
                        .collect::<Vec<u128>>(),
                );
                self.transform(&mut values, false);
                for (value, secret) in values.iter_mut().zip(transformed) {
                    *value = multiply(*value, *secret);
                }
                self.transform(&mut values, true);
                values
                    .iter()
                    .copied()
                    .zip(&self.inverse_twist)
                    .map(|(value, twist)| {
                        let value = multiply(value, *twist);
                        if value > MODULUS / 2 {
                            -((MODULUS - value) as i128)
                        } else {
                            value as i128
                        }
                    })
                    .collect()
            })
            .collect();
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Exact ordinary sparse convolution is an independent full-degree
            // check at fixed boundary and interior positions; small tests check all.
            let positions = if self.degree <= 32 {
                (0..self.degree).collect()
            } else {
                vec![
                    0,
                    1,
                    self.degree / 8 - 1,
                    self.degree / 8,
                    self.degree / 2,
                    self.degree - 2,
                    self.degree - 1,
                ]
            };
            for position in positions {
                let mut expected = BigInt::from(0);
                for (input, secret) in sparse.iter().enumerate().filter(|(_, value)| **value != 0) {
                    let index = (position + self.degree - input) % self.degree;
                    expected += &public[index]
                        * BigInt::from(if position < input { -*secret } else { *secret });
                }
                assert_eq!(
                    reconstruct(&result, position),
                    expected,
                    "ordinary product at {position}"
                );
            }
        }
        result
    }
}

#[cfg(any(test, not(target_arch = "wasm32")))]
pub fn reconstruct(digits: &[Vec<i128>], position: usize) -> BigInt {
    digits.iter().rev().fold(BigInt::from(0), |sum, limb| {
        (sum << RADIX_BITS) + BigInt::from(limb[position])
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_digit_products_match_every_ordinary_coefficient() {
        for degree in [2, 4, 8, 16, 32] {
            let plan = Plan::new(degree);
            let public: Vec<BigInt> = (0..degree)
                .map(|index| {
                    let value = (BigInt::from(index + 1) << 137usize)
                        + (BigInt::from(3 * index + 7) << 72usize)
                        + BigInt::from(19 * index + 1);
                    if index % 2 == 0 { -value } else { value }
                })
                .collect();
            let sparse: Vec<i8> = (0..degree)
                .map(|index| {
                    if index % 3 == 0 {
                        -1
                    } else if index % 3 == 1 {
                        1
                    } else {
                        0
                    }
                })
                .collect();
            let transformed = plan.sparse_transform(&sparse);
            plan.digit_products(&public, &sparse, &transformed, 2);
        }
    }
}
