//! Allocation-stable radix-two DFT for browser proof generation.
//!
//! Plonky3's cached DFT implementations retain large twiddle tables. At the
//! selected aggregate domain those tables overlap the encoded column and the
//! streaming leaf frontier beyond the WebAssembly ceiling. This incremental
//! variant derives one layer root and advances its powers in place, so its
//! auxiliary memory is constant and every poll has a bounded arithmetic cost.

use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

use super::ChallengeField;
use crate::bgv::proof_suite::{ProofBaseFieldElement, ProofEvaluationDomain};

const DEFAULT_BUTTERFLIES_PER_POLL: usize = 1 << 16;
const DEFAULT_BIT_REVERSALS_PER_POLL: usize = 1 << 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedDftStage {
    BitReverse,
    Butterflies,
    Complete,
}

/// Incremental in-place DFT with no retained twiddle table.
pub(super) struct BoundedRadix2Dft {
    values: Vec<ChallengeField>,
    logarithmic_length: usize,
    next_bit_reversal_index: usize,
    layer: usize,
    next_butterfly_index: usize,
    stage: BoundedDftStage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedBaseCosetDftStage {
    ApplyCoset,
    BitReverse,
    Butterflies,
    Complete,
}

/// Incremental in-place base-field coset DFT for bound-tree replay.
///
/// The owned coefficient buffer is extended in place, multiplied by the coset
/// powers, and transformed without a twiddle table or second domain-sized
/// allocation. `Zeroizing` clears the active coefficients or evaluations on
/// cancellation and after the caller extracts one bounded stripe.
pub(super) struct BoundedBaseCosetDft {
    values: Zeroizing<Vec<ProofBaseFieldElement>>,
    domain: ProofEvaluationDomain,
    next_coset_index: usize,
    next_coset_power: ProofBaseFieldElement,
    next_bit_reversal_index: usize,
    layer: usize,
    next_butterfly_index: usize,
    stage: BoundedBaseCosetDftStage,
}

impl BoundedBaseCosetDft {
    pub(super) fn new(
        mut coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
        domain: ProofEvaluationDomain,
    ) -> Result<Self, String> {
        if coefficients.is_empty() || coefficients.len() > domain.size() {
            return Err("bounded base DFT coefficient geometry is invalid".to_owned());
        }
        coefficients.resize(domain.size(), ProofBaseFieldElement::ZERO);
        Ok(Self {
            values: coefficients,
            domain,
            next_coset_index: 0,
            next_coset_power: ProofBaseFieldElement::ONE,
            next_bit_reversal_index: 0,
            layer: 0,
            next_butterfly_index: 0,
            stage: BoundedBaseCosetDftStage::ApplyCoset,
        })
    }

    pub(super) fn poll(&mut self) -> Result<bool, String> {
        match self.stage {
            BoundedBaseCosetDftStage::ApplyCoset => {
                self.advance_coset(DEFAULT_BIT_REVERSALS_PER_POLL)?;
                Ok(false)
            }
            BoundedBaseCosetDftStage::BitReverse => {
                self.advance_bit_reversal(DEFAULT_BIT_REVERSALS_PER_POLL)?;
                Ok(false)
            }
            BoundedBaseCosetDftStage::Butterflies => {
                self.advance_butterflies(DEFAULT_BUTTERFLIES_PER_POLL)?;
                Ok(false)
            }
            BoundedBaseCosetDftStage::Complete => Ok(true),
        }
    }

    pub(super) fn into_values(mut self) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, String> {
        if self.stage != BoundedBaseCosetDftStage::Complete {
            return Err("bounded base DFT values were requested before completion".to_owned());
        }
        Ok(core::mem::take(&mut self.values))
    }

    fn advance_coset(&mut self, maximum_indices: usize) -> Result<(), String> {
        if maximum_indices == 0 || self.stage != BoundedBaseCosetDftStage::ApplyCoset {
            return Err("bounded base DFT coset poll has an invalid state".to_owned());
        }
        let end = self
            .next_coset_index
            .saturating_add(maximum_indices)
            .min(self.values.len());
        for value in &mut self.values[self.next_coset_index..end] {
            *value = value.multiply(self.next_coset_power);
            self.next_coset_power = self.next_coset_power.multiply(self.domain.coset_offset());
        }
        self.next_coset_index = end;
        if end == self.values.len() {
            self.stage = BoundedBaseCosetDftStage::BitReverse;
        }
        Ok(())
    }

    fn advance_bit_reversal(&mut self, maximum_indices: usize) -> Result<(), String> {
        if maximum_indices == 0 || self.stage != BoundedBaseCosetDftStage::BitReverse {
            return Err("bounded base DFT bit-reversal poll has an invalid state".to_owned());
        }
        let logarithmic_length = self.values.len().ilog2() as usize;
        let end = self
            .next_bit_reversal_index
            .saturating_add(maximum_indices)
            .min(self.values.len());
        for index in self.next_bit_reversal_index..end {
            let reversed = reverse_low_bits(index, logarithmic_length);
            if index < reversed {
                self.values.swap(index, reversed);
            }
        }
        self.next_bit_reversal_index = end;
        if end == self.values.len() {
            self.stage = BoundedBaseCosetDftStage::Butterflies;
        }
        Ok(())
    }

    fn advance_butterflies(&mut self, maximum_butterflies: usize) -> Result<(), String> {
        let logarithmic_length = self.values.len().ilog2() as usize;
        if maximum_butterflies == 0
            || self.stage != BoundedBaseCosetDftStage::Butterflies
            || self.layer >= logarithmic_length
        {
            return Err("bounded base DFT butterfly poll has an invalid state".to_owned());
        }
        let butterfly_count = self.values.len() / 2;
        let end = self
            .next_butterfly_index
            .saturating_add(maximum_butterflies)
            .min(butterfly_count);
        let block_length = 1_usize
            .checked_shl((self.layer + 1) as u32)
            .ok_or_else(|| "bounded base DFT block length overflowed".to_owned())?;
        let half_block_length = block_length / 2;
        let twiddle_step = self.domain.generator().power(
            u64::try_from(self.values.len() / block_length)
                .map_err(|_| "bounded base DFT twiddle exponent exceeds u64".to_owned())?,
        );
        let mut butterfly_index = self.next_butterfly_index;
        while butterfly_index < end {
            let block_index = butterfly_index / half_block_length;
            let within_block_index = butterfly_index % half_block_length;
            let block_end = end.min(
                block_index
                    .checked_add(1)
                    .and_then(|index| index.checked_mul(half_block_length))
                    .ok_or_else(|| "bounded base DFT block end overflowed".to_owned())?,
            );
            let mut twiddle = twiddle_step.power(
                u64::try_from(within_block_index)
                    .map_err(|_| "bounded base DFT twiddle index exceeds u64".to_owned())?,
            );
            while butterfly_index < block_end {
                let local_index = butterfly_index % half_block_length;
                let left_index = block_index
                    .checked_mul(block_length)
                    .and_then(|offset| offset.checked_add(local_index))
                    .ok_or_else(|| "bounded base DFT left index overflowed".to_owned())?;
                let right_index = left_index
                    .checked_add(half_block_length)
                    .ok_or_else(|| "bounded base DFT right index overflowed".to_owned())?;
                let left = self.values[left_index];
                let right_twiddle = self.values[right_index].multiply(twiddle);
                self.values[left_index] = left.add(right_twiddle);
                self.values[right_index] = left.subtract(right_twiddle);
                twiddle = twiddle.multiply(twiddle_step);
                butterfly_index += 1;
            }
        }
        self.next_butterfly_index = end;
        if end == butterfly_count {
            self.layer += 1;
            self.next_butterfly_index = 0;
            if self.layer == logarithmic_length {
                self.stage = BoundedBaseCosetDftStage::Complete;
            }
        }
        Ok(())
    }
}

impl BoundedRadix2Dft {
    pub(super) fn new(values: Vec<ChallengeField>) -> Result<Self, String> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err("bounded DFT length is not a nonzero power of two".to_owned());
        }
        Ok(Self {
            logarithmic_length: values.len().ilog2() as usize,
            values,
            next_bit_reversal_index: 0,
            layer: 0,
            next_butterfly_index: 0,
            stage: BoundedDftStage::BitReverse,
        })
    }

    pub(super) fn poll(&mut self) -> Result<bool, String> {
        match self.stage {
            BoundedDftStage::BitReverse => {
                self.advance_bit_reversal(DEFAULT_BIT_REVERSALS_PER_POLL)?;
                Ok(false)
            }
            BoundedDftStage::Butterflies => {
                self.advance_butterflies(DEFAULT_BUTTERFLIES_PER_POLL)?;
                Ok(false)
            }
            BoundedDftStage::Complete => Ok(true),
        }
    }

    pub(super) fn into_values(mut self) -> Result<Vec<ChallengeField>, String> {
        if self.stage != BoundedDftStage::Complete {
            return Err("bounded DFT values were requested before completion".to_owned());
        }
        Ok(core::mem::take(&mut self.values))
    }

    fn advance_bit_reversal(&mut self, maximum_indices: usize) -> Result<(), String> {
        if maximum_indices == 0 || self.stage != BoundedDftStage::BitReverse {
            return Err("bounded DFT bit-reversal poll has an invalid state".to_owned());
        }
        let end = self
            .next_bit_reversal_index
            .saturating_add(maximum_indices)
            .min(self.values.len());
        for index in self.next_bit_reversal_index..end {
            let reversed = reverse_low_bits(index, self.logarithmic_length);
            if index < reversed {
                self.values.swap(index, reversed);
            }
        }
        self.next_bit_reversal_index = end;
        if end == self.values.len() {
            self.stage = if self.logarithmic_length == 0 {
                BoundedDftStage::Complete
            } else {
                BoundedDftStage::Butterflies
            };
        }
        Ok(())
    }

    fn advance_butterflies(&mut self, maximum_butterflies: usize) -> Result<(), String> {
        if maximum_butterflies == 0
            || self.stage != BoundedDftStage::Butterflies
            || self.layer >= self.logarithmic_length
        {
            return Err("bounded DFT butterfly poll has an invalid state".to_owned());
        }
        let butterfly_count = self.values.len() / 2;
        let end = self
            .next_butterfly_index
            .saturating_add(maximum_butterflies)
            .min(butterfly_count);
        let block_length = 1_usize
            .checked_shl((self.layer + 1) as u32)
            .ok_or_else(|| "bounded DFT block length overflowed".to_owned())?;
        let half_block_length = block_length / 2;
        let layer_root = Goldilocks::two_adic_generator(self.layer + 1);
        let mut butterfly_index = self.next_butterfly_index;
        while butterfly_index < end {
            let block_index = butterfly_index / half_block_length;
            let within_block_index = butterfly_index % half_block_length;
            let block_end = end.min(
                block_index
                    .checked_add(1)
                    .and_then(|index| index.checked_mul(half_block_length))
                    .ok_or_else(|| "bounded DFT block end overflowed".to_owned())?,
            );
            let mut twiddle = layer_root.exp_u64(within_block_index as u64);
            while butterfly_index < block_end {
                let local_index = butterfly_index % half_block_length;
                let left_index = block_index
                    .checked_mul(block_length)
                    .and_then(|offset| offset.checked_add(local_index))
                    .ok_or_else(|| "bounded DFT left index overflowed".to_owned())?;
                let right_index = left_index
                    .checked_add(half_block_length)
                    .ok_or_else(|| "bounded DFT right index overflowed".to_owned())?;
                let left = self.values[left_index];
                let right_twiddle = self.values[right_index] * twiddle;
                self.values[left_index] = left + right_twiddle;
                self.values[right_index] = left - right_twiddle;
                twiddle *= layer_root;
                butterfly_index += 1;
            }
        }
        self.next_butterfly_index = end;
        if end == butterfly_count {
            self.layer += 1;
            self.next_butterfly_index = 0;
            if self.layer == self.logarithmic_length {
                self.stage = BoundedDftStage::Complete;
            }
        }
        Ok(())
    }
}

impl Drop for BoundedRadix2Dft {
    fn drop(&mut self) {
        self.values.fill(ChallengeField::ZERO);
    }
}

fn reverse_low_bits(value: usize, bit_count: usize) -> usize {
    if bit_count == 0 {
        0
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bit_count)
    }
}

#[cfg(test)]
mod tests {
    use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
    use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};

    use super::*;
    use crate::bgv::proof_suite::row_code_whir::row_encoding::{
        PRIVATE_ROW_PAD_SEED_BYTE_LENGTH, RowCodeHighHalfSource, RowEncodingGeometry, encode_row,
        padded_base_row_coefficients,
    };

    #[test]
    fn bounded_dft_matches_plonky3_across_nontrivial_small_domains() {
        for logarithmic_length in 0..=10 {
            let length = 1_usize << logarithmic_length;
            let input = (0..length)
                .map(|index| {
                    ChallengeField::from_u64(
                        (index as u64)
                            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            .rotate_left((index % 63) as u32),
                    )
                })
                .collect::<Vec<_>>();
            let expected = Radix2Dit::<ChallengeField>::default().dft(input.clone());
            let mut bounded = BoundedRadix2Dft::new(input).expect("the domain is valid");
            while !bounded.poll().expect("the bounded DFT advances") {}
            assert_eq!(
                bounded.into_values().expect("the bounded DFT completed"),
                expected,
                "logarithmic length {logarithmic_length}",
            );
        }
    }

    #[test]
    fn bounded_base_coset_dft_matches_the_production_polynomial_domain() {
        for logarithmic_length in 1..=10 {
            let length = 1_usize << logarithmic_length;
            let domain = ProofEvaluationDomain::new(length, 7).expect("the coset domain is valid");
            let coefficients = (0..(length / 2 + 1))
                .map(|coefficient_index| {
                    ProofBaseFieldElement::from_canonical(
                        u64::try_from(coefficient_index * 37 + 11)
                            .expect("the bounded coefficient fits u64"),
                    )
                    .expect("the bounded coefficient is canonical")
                })
                .collect::<Vec<_>>();
            let expected = domain
                .evaluate_base_polynomial(&coefficients)
                .expect("the reference coset DFT succeeds");
            let mut bounded = BoundedBaseCosetDft::new(Zeroizing::new(coefficients), domain)
                .expect("the bounded coset DFT initializes");
            while !bounded.poll().expect("the bounded coset DFT advances") {}
            assert_eq!(
                bounded
                    .into_values()
                    .expect("the bounded coset DFT completed")
                    .as_slice(),
                expected,
                "logarithmic length {logarithmic_length}",
            );
        }
    }

    #[test]
    fn bounded_phase_row_dft_matches_the_canonical_private_and_public_encodings() {
        let geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(4, 4, 2)
            .expect("the focused row geometry is valid");
        let private_seed = [0x5a_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        for row_index in 0..geometry.row_count {
            let witness = (0..geometry.witness_values_per_row)
                .map(|value_index| {
                    Goldilocks::from_u64(
                        u64::try_from(row_index * 101 + value_index * 17 + 3)
                            .expect("the focused witness value fits u64"),
                    )
                })
                .collect::<Vec<_>>();
            for high_half_source in [
                RowCodeHighHalfSource::CanonicalPublicZeros,
                RowCodeHighHalfSource::PrivateMaskSeed(&private_seed),
            ] {
                let expected = encode_row(geometry, row_index, &witness, high_half_source)
                    .expect("the reference row encoding succeeds");
                let mut base_witness = Vec::new();
                base_witness
                    .try_reserve_exact(geometry.encoded_column_count)
                    .expect("the focused encoded row allocation succeeds");
                base_witness.extend(witness.iter().map(|value| {
                    ProofBaseFieldElement::from_reduced(u128::from(value.as_canonical_u64()))
                }));
                let coefficients = padded_base_row_coefficients(
                    geometry,
                    row_index,
                    Zeroizing::new(base_witness),
                    high_half_source,
                )
                .expect("the bounded row message is canonical");
                let domain = ProofEvaluationDomain::new(
                    geometry.encoded_column_count,
                    Goldilocks::GENERATOR.as_canonical_u64(),
                )
                .expect("the phase coset domain is valid");
                let mut bounded = BoundedBaseCosetDft::new(coefficients, domain)
                    .expect("the bounded phase DFT initializes");
                while !bounded.poll().expect("the bounded phase DFT advances") {}
                let actual = bounded
                    .into_values()
                    .expect("the bounded phase DFT completed");
                assert_eq!(
                    actual
                        .iter()
                        .map(|value| value.canonical())
                        .collect::<Vec<_>>(),
                    expected
                        .iter()
                        .map(|value| value.as_canonical_u64())
                        .collect::<Vec<_>>(),
                    "row {row_index} with {high_half_source:?}",
                );
            }
        }
    }
}
