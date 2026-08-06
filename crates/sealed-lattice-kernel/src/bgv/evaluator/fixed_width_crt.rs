//! Exact bounded-width CRT reconstruction for the wide key-switch candidate.
//!
//! The selected BGV suite reconstructs at most 115-bit centered values and
//! therefore uses the production `i128` path. The compact block-ten candidate
//! owns 305-bit data blocks and a 306-bit special basis. This module exercises
//! the exact five-word algorithm needed before that topology can replace the
//! selected suite; it is compiled only for tests and primitive measurements.

use std::cmp::Ordering;

use crate::{
    bgv::modular_arithmetic::{inverse_mod, mul_mod_fast, sub_mod_fast},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) const FIXED_WIDTH_CRT_WORD_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FixedWidthUnsigned([u64; FIXED_WIDTH_CRT_WORD_COUNT]);

impl FixedWidthUnsigned {
    fn from_u64(value: u64) -> Self {
        let mut words = [0_u64; FIXED_WIDTH_CRT_WORD_COUNT];
        words[0] = value;
        Self(words)
    }

    fn checked_multiply_u64(self, factor: u64) -> Option<Self> {
        let mut product = [0_u64; FIXED_WIDTH_CRT_WORD_COUNT];
        let mut carry = 0_u128;
        for (word_ordinal, word) in self.0.into_iter().enumerate() {
            let full_product = u128::from(word) * u128::from(factor) + carry;
            product[word_ordinal] = full_product as u64;
            carry = full_product >> u64::BITS;
        }
        (carry == 0).then_some(Self(product))
    }

    fn checked_add_product(&mut self, multiplicand: Self, factor: u64) -> Option<()> {
        let mut carry = 0_u128;
        for word_ordinal in 0..FIXED_WIDTH_CRT_WORD_COUNT {
            let full_sum = u128::from(self.0[word_ordinal])
                + u128::from(multiplicand.0[word_ordinal]) * u128::from(factor)
                + carry;
            self.0[word_ordinal] = full_sum as u64;
            carry = full_sum >> u64::BITS;
        }
        (carry == 0).then_some(())
    }

    fn remainder_u64(self, modulus: u64) -> u64 {
        debug_assert!(modulus > 1);
        let modulus_u128 = u128::from(modulus);
        let mut remainder = 0_u128;
        for word in self.0.into_iter().rev() {
            remainder = ((remainder << u64::BITS) | u128::from(word)) % modulus_u128;
        }
        remainder as u64
    }

    fn half(self) -> Self {
        let mut quotient = [0_u64; FIXED_WIDTH_CRT_WORD_COUNT];
        let mut carry = 0_u64;
        for word_ordinal in (0..FIXED_WIDTH_CRT_WORD_COUNT).rev() {
            let word = self.0[word_ordinal];
            quotient[word_ordinal] = (word >> 1) | carry;
            carry = word << (u64::BITS - 1);
        }
        Self(quotient)
    }

    fn compare(self, other: Self) -> Ordering {
        for word_ordinal in (0..FIXED_WIDTH_CRT_WORD_COUNT).rev() {
            match self.0[word_ordinal].cmp(&other.0[word_ordinal]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedWidthCenteredBlockCoefficients {
    canonical_coefficients: Vec<FixedWidthUnsigned>,
    negative_flags: Vec<u8>,
    block_modulus: FixedWidthUnsigned,
}

impl FixedWidthCenteredBlockCoefficients {
    pub(crate) fn reconstruct(
        residue_limbs: &[Vec<u64>],
        moduli: &[u64],
        residue_multipliers: Option<&[u64]>,
    ) -> CanonicalResult<Self> {
        if residue_limbs.is_empty() || residue_limbs.len() != moduli.len() {
            return Err(malformed_length(
                "fixed-width centered reconstruction requires one non-empty limb per modulus",
            ));
        }
        let coefficient_count = residue_limbs[0].len();
        if coefficient_count == 0
            || residue_limbs.iter().zip(moduli).any(|(limb, modulus)| {
                *modulus < 2
                    || limb.len() != coefficient_count
                    || limb.iter().any(|residue| *residue >= *modulus)
            })
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "fixed-width centered reconstruction received a malformed residue limb",
            ));
        }
        if residue_multipliers.is_some_and(|multipliers| {
            multipliers.len() != moduli.len()
                || multipliers
                    .iter()
                    .zip(moduli)
                    .any(|(multiplier, modulus)| *multiplier >= *modulus)
        }) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "fixed-width centered reconstruction multipliers do not match the modulus basis",
            ));
        }

        let mut accumulated_moduli = Vec::with_capacity(moduli.len());
        let mut garner_inverse_by_modulus = Vec::with_capacity(moduli.len());
        let mut accumulated_modulus = FixedWidthUnsigned::from_u64(1);
        for (modulus_ordinal, modulus) in moduli.iter().copied().enumerate() {
            let garner_inverse = if modulus_ordinal == 0 {
                0
            } else {
                inverse_mod(accumulated_modulus.remainder_u64(modulus), modulus)?
            };
            accumulated_modulus = accumulated_modulus
                .checked_multiply_u64(modulus)
                .ok_or_else(fixed_width_overflow)?;
            accumulated_moduli.push(accumulated_modulus);
            garner_inverse_by_modulus.push(garner_inverse);
        }
        let block_modulus = accumulated_modulus;
        let half_block_modulus = block_modulus.half();

        let mut canonical_coefficients = Vec::new();
        canonical_coefficients
            .try_reserve_exact(coefficient_count)
            .map_err(|_| allocation_failure())?;
        let mut negative_flags = Vec::new();
        negative_flags
            .try_reserve_exact(coefficient_count)
            .map_err(|_| allocation_failure())?;
        for coefficient_ordinal in 0..coefficient_count {
            let scaled_residue = |modulus_ordinal: usize| {
                let residue = residue_limbs[modulus_ordinal][coefficient_ordinal];
                residue_multipliers.map_or(residue, |multipliers| {
                    mul_mod_fast(
                        residue,
                        multipliers[modulus_ordinal],
                        moduli[modulus_ordinal],
                    )
                })
            };
            let mut reconstructed = FixedWidthUnsigned::from_u64(scaled_residue(0));
            for modulus_ordinal in 1..moduli.len() {
                let modulus = moduli[modulus_ordinal];
                let reconstructed_residue = reconstructed.remainder_u64(modulus);
                let correction_residue = sub_mod_fast(
                    scaled_residue(modulus_ordinal),
                    reconstructed_residue,
                    modulus,
                );
                let garner_digit = mul_mod_fast(
                    correction_residue,
                    garner_inverse_by_modulus[modulus_ordinal],
                    modulus,
                );
                reconstructed
                    .checked_add_product(accumulated_moduli[modulus_ordinal - 1], garner_digit)
                    .ok_or_else(fixed_width_overflow)?;
                if reconstructed.compare(accumulated_moduli[modulus_ordinal]) != Ordering::Less {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidProtocolObject,
                        "fixed-width Garner reconstruction escaped its canonical modulus",
                    ));
                }
            }
            negative_flags.push(u8::from(
                reconstructed.compare(half_block_modulus) == Ordering::Greater,
            ));
            canonical_coefficients.push(reconstructed);
        }

        Ok(Self {
            canonical_coefficients,
            negative_flags,
            block_modulus,
        })
    }

    pub(crate) fn write_residues(
        &self,
        modulus: u64,
        output: &mut Vec<u64>,
    ) -> CanonicalResult<()> {
        if modulus < 2 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "fixed-width centered residue modulus is too small",
            ));
        }
        output.clear();
        if output.capacity() < self.canonical_coefficients.len() {
            output
                .try_reserve_exact(self.canonical_coefficients.len())
                .map_err(|_| allocation_failure())?;
        }
        let block_modulus_residue = self.block_modulus.remainder_u64(modulus);
        output.extend(
            self.canonical_coefficients
                .iter()
                .copied()
                .zip(self.negative_flags.iter().copied())
                .map(|(coefficient, is_negative)| {
                    let canonical_residue = coefficient.remainder_u64(modulus);
                    if is_negative == 1 {
                        sub_mod_fast(canonical_residue, block_modulus_residue, modulus)
                    } else {
                        canonical_residue
                    }
                }),
        );
        Ok(())
    }

    pub(crate) fn coefficient_count(&self) -> usize {
        self.canonical_coefficients.len()
    }

    #[cfg(feature = "primitive-measurement-evidence")]
    pub(crate) fn retained_byte_length(&self) -> usize {
        self.canonical_coefficients
            .capacity()
            .saturating_mul(std::mem::size_of::<FixedWidthUnsigned>())
            .saturating_add(self.negative_flags.capacity())
            .saturating_add(std::mem::size_of::<FixedWidthUnsigned>())
    }
}

fn malformed_length(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::MalformedLength, message)
}

fn fixed_width_overflow() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "centered CRT reconstruction exceeds its five-word fixed-width bound",
    )
}

fn allocation_failure() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "fixed-width centered CRT allocation failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::parameters::DATA_PRIMES;
    use num_bigint::BigUint;
    use num_traits::{One, ToPrimitive};

    const CANDIDATE_SPECIAL_MODULI: [u64; 6] = [
        2_251_798_701_539_329,
        2_251_798_448_898_049,
        2_251_798_432_055_297,
        2_251_797_893_087_233,
        2_251_797_842_558_977,
        2_251_797_286_748_161,
    ];

    fn residues_for_values(values: &[BigUint], moduli: &[u64]) -> Vec<Vec<u64>> {
        moduli
            .iter()
            .map(|modulus| {
                let modulus = BigUint::from(*modulus);
                values
                    .iter()
                    .map(|value| (value % &modulus).to_u64().expect("residue fits u64"))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn five_word_centered_reconstruction_matches_305_bit_bigint_boundaries() {
        let moduli = &DATA_PRIMES[..10];
        let block_modulus = moduli
            .iter()
            .map(|modulus| BigUint::from(*modulus))
            .product::<BigUint>();
        let half = &block_modulus >> 1_u8;
        let canonical_values = vec![
            BigUint::ZERO,
            BigUint::one(),
            &half - BigUint::one(),
            half.clone(),
            &half + BigUint::one(),
            &block_modulus - BigUint::one(),
        ];
        let reconstruction = FixedWidthCenteredBlockCoefficients::reconstruct(
            &residues_for_values(&canonical_values, moduli),
            moduli,
            None,
        )
        .expect("305-bit block reconstructs");

        assert_eq!(reconstruction.coefficient_count(), canonical_values.len());
        for output_modulus in DATA_PRIMES.into_iter().chain(CANDIDATE_SPECIAL_MODULI) {
            let mut actual = Vec::new();
            reconstruction
                .write_residues(output_modulus, &mut actual)
                .expect("centered residues derive");
            let output_modulus_big = BigUint::from(output_modulus);
            let block_modulus_residue = (&block_modulus % &output_modulus_big)
                .to_u64()
                .expect("block residue fits u64");
            let expected = canonical_values
                .iter()
                .map(|value| {
                    let residue = (value % &output_modulus_big)
                        .to_u64()
                        .expect("value residue fits u64");
                    if value > &half {
                        sub_mod_fast(residue, block_modulus_residue, output_modulus)
                    } else {
                        residue
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn five_word_reconstruction_applies_special_basis_multipliers_exactly() {
        let moduli = CANDIDATE_SPECIAL_MODULI;
        let residue_limbs = moduli
            .iter()
            .enumerate()
            .map(|(limb_ordinal, modulus)| {
                (0..257_u64)
                    .map(|coefficient_ordinal| {
                        coefficient_ordinal
                            .wrapping_mul(65_537)
                            .wrapping_add((limb_ordinal as u64 + 1) * 257)
                            % *modulus
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let multipliers = moduli
            .iter()
            .map(|modulus| inverse_mod(257, *modulus).expect("257 is invertible"))
            .collect::<Vec<_>>();
        let scaled_limbs = residue_limbs
            .iter()
            .zip(&multipliers)
            .zip(moduli)
            .map(|((limb, multiplier), modulus)| {
                limb.iter()
                    .map(|residue| mul_mod_fast(*residue, *multiplier, modulus))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let multiplied = FixedWidthCenteredBlockCoefficients::reconstruct(
            &residue_limbs,
            &moduli,
            Some(&multipliers),
        )
        .expect("multiplied reconstruction derives");
        let explicit =
            FixedWidthCenteredBlockCoefficients::reconstruct(&scaled_limbs, &moduli, None)
                .expect("explicit reconstruction derives");
        assert_eq!(multiplied, explicit);
    }

    #[test]
    fn five_word_reconstruction_refuses_malformed_or_oversized_bases() {
        assert!(FixedWidthCenteredBlockCoefficients::reconstruct(&[], &[], None).is_err());
        assert!(FixedWidthCenteredBlockCoefficients::reconstruct(&[vec![7]], &[7], None).is_err());
        let oversized_moduli = vec![u64::MAX - 58; FIXED_WIDTH_CRT_WORD_COUNT + 1];
        let oversized_limbs = vec![vec![0_u64]; oversized_moduli.len()];
        assert!(
            FixedWidthCenteredBlockCoefficients::reconstruct(
                &oversized_limbs,
                &oversized_moduli,
                None,
            )
            .is_err()
        );
    }
}
