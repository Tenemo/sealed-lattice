use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use super::TallyPreparationError;

/// Unactivated scalar arithmetic for the 40-byte preparation-field candidate.
///
/// Bytes are the little-endian polynomial-basis coefficients of
/// `GF(2)[X] / (X^320 + X^117 + X^86 + X^21 + 1)`: bit zero of byte zero is
/// the coefficient of `X^0`. Every 40-byte string is a canonical element.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BinaryFieldElement320 {
    polynomial_limbs: [u64; 5],
}

impl BinaryFieldElement320 {
    pub(crate) const CANONICAL_BYTE_LENGTH: usize = 40;
    pub(crate) const ZERO: Self = Self {
        polynomial_limbs: [0_u64; 5],
    };
    pub(crate) const ONE: Self = Self {
        polynomial_limbs: [1_u64, 0_u64, 0_u64, 0_u64, 0_u64],
    };

    // Reducing X^320 replaces it with X^117 + X^86 + X^21 + 1.
    const REDUCTION_LOW_LIMBS: [u64; 2] = [
        (1_u64 << 21) | 1_u64,
        (1_u64 << (117 - 64)) | (1_u64 << (86 - 64)),
    ];

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let canonical_bytes: [u8; Self::CANONICAL_BYTE_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| TallyPreparationError::FieldElementByteLength {
                    expected: Self::CANONICAL_BYTE_LENGTH,
                    actual: bytes.len(),
                })?;
        let mut polynomial_limbs = [0_u64; 5];
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
            polynomial_limbs: [u64::from(value), 0_u64, 0_u64, 0_u64, 0_u64],
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

        for multiplier_bit_position in 0..320_usize {
            let multiplier_limb_position = multiplier_bit_position / 64;
            let multiplier_bit_within_limb = multiplier_bit_position % 64;
            let multiplier_bit = (other.polynomial_limbs[multiplier_limb_position]
                >> multiplier_bit_within_limb)
                & 1_u64;
            let multiplier_mask = 0_u64.wrapping_sub(multiplier_bit);
            for product_limb_position in 0..5 {
                product.polynomial_limbs[product_limb_position] ^=
                    shifted_multiplicand.polynomial_limbs[product_limb_position] & multiplier_mask;
            }

            let reduction_bit = shifted_multiplicand.polynomial_limbs[4] >> 63;
            shifted_multiplicand.polynomial_limbs = [
                shifted_multiplicand.polynomial_limbs[0] << 1,
                (shifted_multiplicand.polynomial_limbs[1] << 1)
                    | (shifted_multiplicand.polynomial_limbs[0] >> 63),
                (shifted_multiplicand.polynomial_limbs[2] << 1)
                    | (shifted_multiplicand.polynomial_limbs[1] >> 63),
                (shifted_multiplicand.polynomial_limbs[3] << 1)
                    | (shifted_multiplicand.polynomial_limbs[2] >> 63),
                (shifted_multiplicand.polynomial_limbs[4] << 1)
                    | (shifted_multiplicand.polynomial_limbs[3] >> 63),
            ];
            let reduction_mask = 0_u64.wrapping_sub(reduction_bit);
            shifted_multiplicand.polynomial_limbs[0] ^=
                Self::REDUCTION_LOW_LIMBS[0] & reduction_mask;
            shifted_multiplicand.polynomial_limbs[1] ^=
                Self::REDUCTION_LOW_LIMBS[1] & reduction_mask;
        }

        product
    }

    pub(crate) fn square(self) -> Self {
        self.multiply(self)
    }

    /// Computes `self^(2^320 - 2)` with a fixed addition chain.
    pub(crate) fn multiplicative_inverse(self) -> Result<Self, TallyPreparationError> {
        if self.is_zero() {
            return Err(TallyPreparationError::ZeroHasNoMultiplicativeInverse);
        }

        let mut accumulated_power = self;
        for _fixed_power_step in 0..318 {
            accumulated_power = accumulated_power.square().multiply(self);
        }
        Ok(accumulated_power.square())
    }

    pub(crate) fn divide(self, divisor: Self) -> Result<Self, TallyPreparationError> {
        Ok(self.multiply(divisor.multiplicative_inverse()?))
    }
}

impl ConstantTimeEq for BinaryFieldElement320 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.polynomial_limbs.ct_eq(&other.polynomial_limbs)
    }
}

impl Zeroize for BinaryFieldElement320 {
    fn zeroize(&mut self) {
        self.polynomial_limbs.zeroize();
    }
}

#[cfg(any(test, feature = "preparation-field-measurement"))]
pub(crate) fn measure_binary_field_320_multiplications(
    multiplication_count: u32,
    seed: u64,
) -> u64 {
    let effective_seed = if seed == 0 {
        0x9e37_79b9_7f4a_7c15_u64
    } else {
        seed
    };
    let mut accumulator_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    for (chunk_position, chunk) in accumulator_bytes.chunks_exact_mut(8).enumerate() {
        let chunk_value = effective_seed.rotate_left(
            u32::try_from(chunk_position * 11).expect("five chunk positions fit in u32"),
        ) ^ (0xa5a5_a5a5_a5a5_a5a5_u64
            .wrapping_mul(u64::try_from(chunk_position + 1).expect("five chunks fit in u64")));
        chunk.copy_from_slice(&chunk_value.to_le_bytes());
    }
    let mut accumulator = BinaryFieldElement320::from_canonical_bytes(&accumulator_bytes)
        .expect("the fixed 40-byte accumulator must be canonical");
    let mut deterministic_multiplier_limb_states = [
        effective_seed | 1,
        effective_seed.rotate_left(13) ^ 0x243f_6a88_85a3_08d3,
        effective_seed.rotate_left(29) ^ 0x1319_8a2e_0370_7344,
        effective_seed.rotate_left(47) ^ 0xa409_3822_299f_31d0,
        effective_seed.rotate_left(61) ^ 0x082e_fa98_ec4e_6c89,
    ];

    for _multiplication_position in 0..multiplication_count {
        for limb_state in &mut deterministic_multiplier_limb_states {
            *limb_state ^= *limb_state << 13;
            *limb_state ^= *limb_state >> 7;
            *limb_state ^= *limb_state << 17;
        }
        accumulator = accumulator.multiply(BinaryFieldElement320 {
            polynomial_limbs: deterministic_multiplier_limb_states,
        });
    }

    accumulator
        .canonical_bytes()
        .chunks_exact(8)
        .fold(0_u64, |checksum, chunk| {
            checksum
                ^ u64::from_le_bytes(
                    chunk
                        .try_into()
                        .expect("an exact eight-byte chunk must convert to a checksum limb"),
                )
        })
}
