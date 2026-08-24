use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use super::TallyPreparationError;

/// Canonical scalar field used for degree-three output-mask sharing.
///
/// Bytes are the little-endian polynomial-basis coefficients of
/// `GF(2)[X] / (X^256 + X^10 + X^5 + X^2 + 1)`: bit zero of byte zero is the
/// coefficient of `X^0`. Every 32-byte string is a canonical field element.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BinaryFieldElement256 {
    polynomial_limbs: [u64; 4],
}

impl BinaryFieldElement256 {
    pub(crate) const CANONICAL_BYTE_LENGTH: usize = 32;
    pub(crate) const ZERO: Self = Self {
        polynomial_limbs: [0_u64; 4],
    };
    pub(crate) const ONE: Self = Self {
        polynomial_limbs: [1_u64, 0_u64, 0_u64, 0_u64],
    };

    // Reducing X^256 replaces it with X^10 + X^5 + X^2 + 1.
    const REDUCTION_LOW_LIMB: u64 = (1_u64 << 10) | (1_u64 << 5) | (1_u64 << 2) | 1_u64;

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let canonical_bytes: [u8; Self::CANONICAL_BYTE_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| TallyPreparationError::FieldElementByteLength {
                    expected: Self::CANONICAL_BYTE_LENGTH,
                    actual: bytes.len(),
                })?;
        let mut polynomial_limbs = [0_u64; 4];
        for (limb, limb_bytes) in polynomial_limbs
            .iter_mut()
            .zip(canonical_bytes.chunks_exact(8))
        {
            *limb = u64::from_le_bytes(
                limb_bytes
                    .try_into()
                    .expect("an exact eight-byte chunk must convert to a limb"),
            );
        }

        Ok(Self { polynomial_limbs })
    }

    pub(crate) fn from_low_polynomial_u16(value: u16) -> Self {
        Self {
            polynomial_limbs: [u64::from(value), 0_u64, 0_u64, 0_u64],
        }
    }

    pub(crate) fn canonical_bytes(self) -> [u8; Self::CANONICAL_BYTE_LENGTH] {
        let mut canonical_bytes = [0_u8; Self::CANONICAL_BYTE_LENGTH];
        for (limb, limb_bytes) in self
            .polynomial_limbs
            .iter()
            .zip(canonical_bytes.chunks_exact_mut(8))
        {
            limb_bytes.copy_from_slice(&limb.to_le_bytes());
        }
        canonical_bytes
    }

    pub(crate) fn is_zero(self) -> bool {
        self.polynomial_limbs
            .iter()
            .copied()
            .fold(0_u64, |combined, limb| combined | limb)
            == 0
    }

    pub(crate) fn add(self, other: Self) -> Self {
        Self {
            polynomial_limbs: core::array::from_fn(|limb_position| {
                self.polynomial_limbs[limb_position] ^ other.polynomial_limbs[limb_position]
            }),
        }
    }

    /// Scalar carryless multiplication with reduction after every fixed bit.
    ///
    /// The loop count and conditional masks do not depend on either operand.
    pub(crate) fn multiply(self, other: Self) -> Self {
        let mut product = Self::ZERO;
        let mut shifted_multiplicand = self;

        for multiplier_bit_position in 0..256_usize {
            let multiplier_limb_position = multiplier_bit_position / 64;
            let multiplier_bit_within_limb = multiplier_bit_position % 64;
            let multiplier_bit = (other.polynomial_limbs[multiplier_limb_position]
                >> multiplier_bit_within_limb)
                & 1_u64;
            let multiplier_mask = 0_u64.wrapping_sub(multiplier_bit);
            for product_limb_position in 0..4 {
                product.polynomial_limbs[product_limb_position] ^=
                    shifted_multiplicand.polynomial_limbs[product_limb_position] & multiplier_mask;
            }

            let reduction_bit = shifted_multiplicand.polynomial_limbs[3] >> 63;
            shifted_multiplicand.polynomial_limbs = [
                shifted_multiplicand.polynomial_limbs[0] << 1,
                (shifted_multiplicand.polynomial_limbs[1] << 1)
                    | (shifted_multiplicand.polynomial_limbs[0] >> 63),
                (shifted_multiplicand.polynomial_limbs[2] << 1)
                    | (shifted_multiplicand.polynomial_limbs[1] >> 63),
                (shifted_multiplicand.polynomial_limbs[3] << 1)
                    | (shifted_multiplicand.polynomial_limbs[2] >> 63),
            ];
            shifted_multiplicand.polynomial_limbs[0] ^=
                Self::REDUCTION_LOW_LIMB & 0_u64.wrapping_sub(reduction_bit);
        }

        product
    }

    pub(crate) fn square(self) -> Self {
        self.multiply(self)
    }

    /// Computes `self^(2^256 - 2)` with a fixed addition chain.
    pub(crate) fn multiplicative_inverse(self) -> Result<Self, TallyPreparationError> {
        if self.is_zero() {
            return Err(TallyPreparationError::ZeroHasNoMultiplicativeInverse);
        }

        let mut accumulated_power = self;
        for _fixed_power_step in 0..254 {
            accumulated_power = accumulated_power.square().multiply(self);
        }
        Ok(accumulated_power.square())
    }

    pub(crate) fn divide(self, divisor: Self) -> Result<Self, TallyPreparationError> {
        Ok(self.multiply(divisor.multiplicative_inverse()?))
    }
}

impl ConstantTimeEq for BinaryFieldElement256 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.polynomial_limbs.ct_eq(&other.polynomial_limbs)
    }
}

impl Zeroize for BinaryFieldElement256 {
    fn zeroize(&mut self) {
        self.polynomial_limbs.zeroize();
    }
}
