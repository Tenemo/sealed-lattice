use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Scalar Montgomery representation of the LPSY15 field
/// `GF(2^320 + 27)`.
///
/// Canonical values are 41-byte little-endian integers. Only bit zero of the
/// last byte may be set, and the represented integer must be strictly smaller
/// than the prime modulus. The six-limb Montgomery representation is internal
/// and never crosses a protocol boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Lpsy15PrimeFieldElement {
    montgomery_limbs: [u64; Self::LIMB_COUNT],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15PrimeFieldError {
    CanonicalByteLength { expected: usize, actual: usize },
    NonCanonicalValue,
}

impl Lpsy15PrimeFieldElement {
    pub(crate) const CANONICAL_BYTE_LENGTH: usize = 41;
    pub(crate) const ARITHMETIC_BYTE_LENGTH: usize = 48;
    pub(crate) const ZERO: Self = Self {
        montgomery_limbs: [0_u64; Self::LIMB_COUNT],
    };

    const LIMB_COUNT: usize = 6;
    const MODULUS: [u64; Self::LIMB_COUNT] = [27, 0, 0, 0, 0, 1];
    const MONTGOMERY_RADIX_SQUARED: [u64; Self::LIMB_COUNT] = [0, 0, 729, 0, 0, 0];
    // -27^(-1) mod 2^64.
    const MONTGOMERY_NEGATIVE_MODULUS_INVERSE: u64 = 0x7b42_5ed0_97b4_25ed;

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Lpsy15PrimeFieldError> {
        let canonical_bytes: [u8; Self::CANONICAL_BYTE_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| Lpsy15PrimeFieldError::CanonicalByteLength {
                    expected: Self::CANONICAL_BYTE_LENGTH,
                    actual: bytes.len(),
                })?;
        if canonical_bytes[40] > 1 {
            return Err(Lpsy15PrimeFieldError::NonCanonicalValue);
        }

        let mut canonical_limbs = [0_u64; Self::LIMB_COUNT];
        for (limb, limb_bytes) in canonical_limbs[..5]
            .iter_mut()
            .zip(canonical_bytes[..40].chunks_exact(8))
        {
            *limb = u64::from_le_bytes(
                limb_bytes
                    .try_into()
                    .expect("an exact eight-byte chunk must convert to a limb"),
            );
        }
        canonical_limbs[5] = u64::from(canonical_bytes[40]);
        if !limbs_are_less_than(canonical_limbs, Self::MODULUS) {
            return Err(Lpsy15PrimeFieldError::NonCanonicalValue);
        }

        Ok(Self {
            montgomery_limbs: montgomery_multiply_limbs(
                canonical_limbs,
                Self::MONTGOMERY_RADIX_SQUARED,
            ),
        })
    }

    pub(crate) fn from_unsigned64(value: u64) -> Self {
        Self {
            montgomery_limbs: montgomery_multiply_limbs(
                [value, 0, 0, 0, 0, 0],
                Self::MONTGOMERY_RADIX_SQUARED,
            ),
        }
    }

    pub(crate) fn canonical_bytes(self) -> [u8; Self::CANONICAL_BYTE_LENGTH] {
        let canonical_limbs = montgomery_multiply_limbs(self.montgomery_limbs, [1, 0, 0, 0, 0, 0]);
        let mut canonical_bytes = [0_u8; Self::CANONICAL_BYTE_LENGTH];
        for (limb, limb_bytes) in canonical_limbs[..5]
            .iter()
            .zip(canonical_bytes[..40].chunks_exact_mut(8))
        {
            limb_bytes.copy_from_slice(&limb.to_le_bytes());
        }
        canonical_bytes[40] = u8::try_from(canonical_limbs[5])
            .expect("a reduced LPSY15 field element has one high bit");
        canonical_bytes
    }

    pub(crate) fn add(self, other: Self) -> Self {
        let mut sum = [0_u64; Self::LIMB_COUNT];
        let mut carry = 0_u64;
        for ((sum_limb, left_limb), right_limb) in sum
            .iter_mut()
            .zip(self.montgomery_limbs)
            .zip(other.montgomery_limbs)
        {
            let wide_sum = u128::from(left_limb) + u128::from(right_limb) + u128::from(carry);
            *sum_limb = wide_sum as u64;
            carry = (wide_sum >> 64) as u64;
        }
        debug_assert_eq!(carry, 0, "two reduced 321-bit values fit six limbs");
        Self {
            montgomery_limbs: conditionally_subtract_modulus(sum),
        }
    }

    pub(crate) fn multiply(self, other: Self) -> Self {
        Self {
            montgomery_limbs: montgomery_multiply_limbs(
                self.montgomery_limbs,
                other.montgomery_limbs,
            ),
        }
    }
}

impl ConstantTimeEq for Lpsy15PrimeFieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.montgomery_limbs.ct_eq(&other.montgomery_limbs)
    }
}

impl Zeroize for Lpsy15PrimeFieldElement {
    fn zeroize(&mut self) {
        self.montgomery_limbs.zeroize();
    }
}

fn montgomery_multiply_limbs(
    left: [u64; Lpsy15PrimeFieldElement::LIMB_COUNT],
    right: [u64; Lpsy15PrimeFieldElement::LIMB_COUNT],
) -> [u64; Lpsy15PrimeFieldElement::LIMB_COUNT] {
    let mut product = [0_u64; 13];
    for (left_position, left_limb) in left.iter().copied().enumerate() {
        let mut carry = 0_u128;
        for (right_position, right_limb) in right.iter().copied().enumerate() {
            let product_position = left_position + right_position;
            let wide_product = u128::from(left_limb) * u128::from(right_limb)
                + u128::from(product[product_position])
                + carry;
            product[product_position] = wide_product as u64;
            carry = wide_product >> 64;
        }
        propagate_carry(
            &mut product,
            left_position + Lpsy15PrimeFieldElement::LIMB_COUNT,
            carry as u64,
        );
    }

    for reduction_position in 0..Lpsy15PrimeFieldElement::LIMB_COUNT {
        let reduction_factor = product[reduction_position]
            .wrapping_mul(Lpsy15PrimeFieldElement::MONTGOMERY_NEGATIVE_MODULUS_INVERSE);
        let mut carry = 0_u128;
        for modulus_position in 0..Lpsy15PrimeFieldElement::LIMB_COUNT {
            let product_position = reduction_position + modulus_position;
            let wide_sum = u128::from(reduction_factor)
                * u128::from(Lpsy15PrimeFieldElement::MODULUS[modulus_position])
                + u128::from(product[product_position])
                + carry;
            product[product_position] = wide_sum as u64;
            carry = wide_sum >> 64;
        }
        propagate_carry(
            &mut product,
            reduction_position + Lpsy15PrimeFieldElement::LIMB_COUNT,
            carry as u64,
        );
        debug_assert_eq!(product[reduction_position], 0);
    }

    debug_assert_eq!(
        product[12], 0,
        "a Montgomery product is smaller than twice the modulus"
    );
    conditionally_subtract_modulus(
        product[Lpsy15PrimeFieldElement::LIMB_COUNT..12]
            .try_into()
            .expect("six product limbs form one field element"),
    )
}

fn propagate_carry(product: &mut [u64; 13], starting_position: usize, initial_carry: u64) {
    let mut carry = initial_carry;
    for product_limb in &mut product[starting_position..] {
        let wide_sum = u128::from(*product_limb) + u128::from(carry);
        *product_limb = wide_sum as u64;
        carry = (wide_sum >> 64) as u64;
    }
    debug_assert_eq!(
        carry, 0,
        "the thirteen-limb accumulator contains every carry"
    );
}

fn conditionally_subtract_modulus(
    value: [u64; Lpsy15PrimeFieldElement::LIMB_COUNT],
) -> [u64; Lpsy15PrimeFieldElement::LIMB_COUNT] {
    let (difference, borrow) = subtract_limbs(value, Lpsy15PrimeFieldElement::MODULUS);
    let retain_original_mask = 0_u64.wrapping_sub(borrow);
    core::array::from_fn(|limb_position| {
        (value[limb_position] & retain_original_mask)
            | (difference[limb_position] & !retain_original_mask)
    })
}

fn limbs_are_less_than(
    left: [u64; Lpsy15PrimeFieldElement::LIMB_COUNT],
    right: [u64; Lpsy15PrimeFieldElement::LIMB_COUNT],
) -> bool {
    let (_, borrow) = subtract_limbs(left, right);
    borrow == 1
}

fn subtract_limbs(
    left: [u64; Lpsy15PrimeFieldElement::LIMB_COUNT],
    right: [u64; Lpsy15PrimeFieldElement::LIMB_COUNT],
) -> ([u64; Lpsy15PrimeFieldElement::LIMB_COUNT], u64) {
    let mut difference = [0_u64; Lpsy15PrimeFieldElement::LIMB_COUNT];
    let mut borrow = 0_u64;
    for limb_position in 0..Lpsy15PrimeFieldElement::LIMB_COUNT {
        let (without_borrow, first_borrow) =
            left[limb_position].overflowing_sub(right[limb_position]);
        let (with_borrow, second_borrow) = without_borrow.overflowing_sub(borrow);
        difference[limb_position] = with_borrow;
        borrow = u64::from(first_borrow | second_borrow);
    }
    (difference, borrow)
}
