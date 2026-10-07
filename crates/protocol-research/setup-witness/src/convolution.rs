use num_bigint::BigInt;
use num_traits::Signed;
use setup_stream_kernel::arithmetic::{MODULUS, add, multiply, power, subtract};
use zeroize::Zeroizing;

// FHE, registration and auxiliary equations use 96-bit limbs; share
// equations use the profile's share limb.
pub const RADIX_BITS: usize = supported_profile::FHE_LIMB_BITS;
pub const RADIX: i128 = 1i128 << RADIX_BITS;

pub fn digit(value: &BigInt, limb: usize) -> i128 {
    digit_in(value, limb, RADIX_BITS)
}
/// The limb's digit of the value's magnitude, with the value's sign. It
/// reads the at most three magnitude words that hold the digit.
pub fn digit_in(value: &BigInt, limb: usize, radix_bits: usize) -> i128 {
    assert!(radix_bits <= RADIX_BITS);
    let start = radix_bits * limb;
    let mut words = value.magnitude().iter_u64_digits().skip(start / 64);
    let mut next = || u128::from(words.next().unwrap_or(0));
    let shift = start % 64;
    let mut magnitude = (next() | (next() << 64)) >> shift;
    if shift + radix_bits > 128 {
        magnitude |= next() << (128 - shift);
    }
    let result = (magnitude & ((1u128 << radix_bits) - 1)) as i128;
    if value.is_negative() { -result } else { result }
}

pub struct Plan {
    degree: usize,
    // The powers below the degree of a root of order twice the degree. Its
    // square is the cyclic transform's root, and its power at the degree is
    // minus one.
    powers: Vec<u128>,
    inverse_degree: u128,
}
impl Plan {
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two() && (2..=65_536).contains(&degree));
        let root = power(7, (MODULUS - 1) / (2 * degree) as u128);
        assert_eq!(power(root, degree as u128), MODULUS - 1);
        assert_eq!(power(root, (2 * degree) as u128), 1);
        let mut powers = vec![1; degree];
        for index in 1..degree {
            powers[index] = multiply(powers[index - 1], root);
        }
        Self {
            degree,
            powers,
            inverse_degree: power(degree as u128, MODULUS - 2),
        }
    }
    // The cyclic transform in natural order.
    fn transform(&self, values: &mut [u128]) {
        assert_eq!(values.len(), self.degree);
        let logarithm = self.degree.ilog2();
        for index in 0..self.degree {
            let reversed = index.reverse_bits() >> (usize::BITS - logarithm);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
        let mut width = 2;
        while width <= self.degree {
            // The cyclic root's power of the stride is the root's power of
            // twice the stride.
            let stride = 2 * self.degree / width;
            for block in values.chunks_exact_mut(width) {
                let (left, right) = block.split_at_mut(width / 2);
                for (index, (lower, upper)) in left.iter_mut().zip(right.iter_mut()).enumerate() {
                    let product = multiply(*upper, self.powers[index * stride]);
                    let original = *lower;
                    *lower = add(original, product);
                    *upper = subtract(original, product);
                }
            }
            width *= 2;
        }
    }
    /// The transform of the twisted sparse values divided by the degree,
    /// so that a product's inverse transform divides no further.
    pub fn sparse_transform(&self, sparse: &[i8]) -> Vec<u128> {
        assert_eq!(sparse.len(), self.degree);
        let mut values: Vec<u128> = sparse
            .iter()
            .zip(&self.powers)
            .map(|(value, power)| match value {
                -1 => subtract(0, multiply(*power, self.inverse_degree)),
                0 => 0,
                1 => multiply(*power, self.inverse_degree),
                _ => panic!("nonternary coefficient"),
            })
            .collect();
        self.transform(&mut values);
        values
    }
    /// One limb's centered products with a sparse secret: the limb's
    /// digits, twisted and transformed, times the secret's transform, then
    /// transformed back and untwisted. The inverse transform reads the
    /// forward one at the negated position, whose untwist is minus the
    /// root's power at the degree less the position.
    pub fn limb_products(
        &self,
        digits: impl Iterator<Item = i128>,
        transformed: impl Iterator<Item = u128>,
    ) -> Vec<i128> {
        let mut values = Zeroizing::new(
            digits
                .zip(&self.powers)
                .map(|(value, power)| {
                    let residue = if value < 0 {
                        MODULUS - value.unsigned_abs()
                    } else {
                        value as u128
                    };
                    multiply(residue, *power)
                })
                .collect::<Vec<u128>>(),
        );
        assert_eq!(values.len(), self.degree);
        self.transform(&mut values);
        let mut count = 0;
        for (value, secret) in values.iter_mut().zip(transformed) {
            *value = multiply(*value, secret);
            count += 1;
        }
        assert_eq!(count, self.degree);
        self.transform(&mut values);
        let centered = |position: usize| {
            let value = multiply(values[position], self.powers[position]);
            if value > MODULUS / 2 {
                -((MODULUS - value) as i128)
            } else {
                value as i128
            }
        };
        (0..self.degree)
            .map(|position| match position {
                0 => centered(0),
                _ => -centered(self.degree - position),
            })
            .collect()
    }
    pub fn digit_products(
        &self,
        public: &[BigInt],
        sparse: &[i8],
        transformed: &[u128],
        limbs: usize,
        radix_bits: usize,
    ) -> Vec<Vec<i128>> {
        assert_eq!(public.len(), self.degree);
        assert_eq!(transformed.len(), self.degree);
        check_support(sparse, radix_bits);
        let result: Vec<Vec<i128>> = (0..limbs)
            .map(|limb| {
                self.limb_products(
                    public.iter().map(|value| digit_in(value, limb, radix_bits)),
                    transformed.iter().copied(),
                )
            })
            .collect();
        #[cfg(not(target_arch = "wasm32"))]
        check_products(public, sparse, &result, radix_bits);
        result
    }
}

/// Every centered product of a digit with the sparse secret stays within
/// half the modulus.
pub fn check_support(sparse: &[i8], radix_bits: usize) {
    let support = sparse
        .iter()
        .map(|value| value.unsigned_abs() as u128)
        .sum::<u128>();
    assert!(support * ((1u128 << radix_bits) - 1) < MODULUS / 2);
}

/// Exact ordinary sparse convolution is an independent full-degree check
/// at fixed boundary and interior positions; small tests check all.
#[cfg(not(target_arch = "wasm32"))]
pub fn check_products(public: &[BigInt], sparse: &[i8], result: &[Vec<i128>], radix_bits: usize) {
    let degree = public.len();
    let positions = if degree <= 32 {
        (0..degree).collect()
    } else {
        vec![
            0,
            1,
            degree / 8 - 1,
            degree / 8,
            degree / 2,
            degree - 2,
            degree - 1,
        ]
    };
    for position in positions {
        let mut expected = BigInt::from(0);
        for (input, secret) in sparse.iter().enumerate().filter(|(_, value)| **value != 0) {
            let index = (position + degree - input) % degree;
            expected +=
                &public[index] * BigInt::from(if position < input { -*secret } else { *secret });
        }
        assert_eq!(
            reconstruct_in(result, position, radix_bits),
            expected,
            "ordinary product at {position}"
        );
    }
}

#[cfg(any(test, not(target_arch = "wasm32")))]
pub fn reconstruct_in(digits: &[Vec<i128>], position: usize, radix_bits: usize) -> BigInt {
    digits.iter().rev().fold(BigInt::from(0), |sum, limb| {
        (sum << radix_bits) + BigInt::from(limb[position])
    })
}

#[cfg(test)]
#[path = "convolution-tests.rs"]
mod tests;
