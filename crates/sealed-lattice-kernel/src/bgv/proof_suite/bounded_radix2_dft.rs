//! Allocation-stable radix-two DFT for browser proof generation.
//!
//! The transform advances in bounded polls, operates in place, and derives one
//! layer root at a time. Compact proof oracles and the temporary row-code
//! differential implementation share this owner so neither path retains a
//! domain-sized twiddle table or a second evaluation buffer.

use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;

use super::compact_cfw::CompactChallengeField;

pub(crate) const DEFAULT_BOUNDED_DFT_BUTTERFLIES_PER_POLL: usize = 1 << 16;
pub(crate) const DEFAULT_BOUNDED_DFT_BIT_REVERSALS_PER_POLL: usize = 1 << 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedRadix2DftStage {
    BitReverse,
    Butterflies,
    Complete,
}

pub(crate) struct BoundedRadix2Dft {
    values: Vec<CompactChallengeField>,
    logarithmic_length: usize,
    next_bit_reversal_index: usize,
    layer: usize,
    next_butterfly_index: usize,
    stage: BoundedRadix2DftStage,
}

impl BoundedRadix2Dft {
    pub(crate) fn new(values: Vec<CompactChallengeField>) -> Result<Self, String> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err("bounded DFT length is not a nonzero power of two".to_owned());
        }
        Ok(Self {
            logarithmic_length: values.len().ilog2() as usize,
            values,
            next_bit_reversal_index: 0,
            layer: 0,
            next_butterfly_index: 0,
            stage: BoundedRadix2DftStage::BitReverse,
        })
    }

    pub(crate) fn poll(&mut self) -> Result<bool, String> {
        match self.stage {
            BoundedRadix2DftStage::BitReverse => {
                self.advance_bit_reversal(DEFAULT_BOUNDED_DFT_BIT_REVERSALS_PER_POLL)?;
                Ok(false)
            }
            BoundedRadix2DftStage::Butterflies => {
                self.advance_butterflies(DEFAULT_BOUNDED_DFT_BUTTERFLIES_PER_POLL)?;
                Ok(false)
            }
            BoundedRadix2DftStage::Complete => Ok(true),
        }
    }

    pub(crate) fn poll_with_maximum_work_unit_count(
        &mut self,
        maximum_work_unit_count: usize,
    ) -> Result<(bool, usize), String> {
        if maximum_work_unit_count == 0 {
            return Err("bounded DFT poll requires positive work".to_owned());
        }
        match self.stage {
            BoundedRadix2DftStage::BitReverse => {
                Ok((false, self.advance_bit_reversal(maximum_work_unit_count)?))
            }
            BoundedRadix2DftStage::Butterflies => {
                Ok((false, self.advance_butterflies(maximum_work_unit_count)?))
            }
            BoundedRadix2DftStage::Complete => Ok((true, 0)),
        }
    }

    pub(crate) fn into_values(mut self) -> Result<Vec<CompactChallengeField>, String> {
        if self.stage != BoundedRadix2DftStage::Complete {
            return Err("bounded DFT values were requested before completion".to_owned());
        }
        Ok(core::mem::take(&mut self.values))
    }

    fn advance_bit_reversal(&mut self, maximum_indices: usize) -> Result<usize, String> {
        if maximum_indices == 0 || self.stage != BoundedRadix2DftStage::BitReverse {
            return Err("bounded DFT bit-reversal poll has an invalid state".to_owned());
        }
        let start = self.next_bit_reversal_index;
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
                BoundedRadix2DftStage::Complete
            } else {
                BoundedRadix2DftStage::Butterflies
            };
        }
        Ok(end - start)
    }

    fn advance_butterflies(&mut self, maximum_butterflies: usize) -> Result<usize, String> {
        if maximum_butterflies == 0
            || self.stage != BoundedRadix2DftStage::Butterflies
            || self.layer >= self.logarithmic_length
        {
            return Err("bounded DFT butterfly poll has an invalid state".to_owned());
        }
        let butterfly_count = self.values.len() / 2;
        let start = self.next_butterfly_index;
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
                self.stage = BoundedRadix2DftStage::Complete;
            }
        }
        Ok(end - start)
    }
}

impl Drop for BoundedRadix2Dft {
    fn drop(&mut self) {
        self.values.fill(CompactChallengeField::ZERO);
    }
}

pub(crate) fn reverse_low_bits(value: usize, bit_count: usize) -> usize {
    if bit_count == 0 {
        0
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bit_count)
    }
}

#[cfg(test)]
mod tests {
    use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn bounded_transform_matches_the_canonical_radix_two_transform() {
        for logarithmic_length in 0..=9 {
            let length = 1_usize << logarithmic_length;
            let input = (0..length)
                .map(|ordinal| {
                    CompactChallengeField::from_u64(
                        u64::try_from(ordinal).expect("small ordinal") * 17 + 3,
                    )
                })
                .collect::<Vec<_>>();
            let expected = Radix2Dit::<CompactChallengeField>::default()
                .dft(input.clone())
                .to_vec();
            let mut bounded = BoundedRadix2Dft::new(input).expect("valid transform geometry");
            while !bounded.poll().expect("bounded transform poll") {}
            assert_eq!(
                bounded.into_values().expect("completed transform values"),
                expected
            );
        }
    }

    #[test]
    fn bounded_transform_rejects_invalid_and_early_extraction() {
        assert!(BoundedRadix2Dft::new(Vec::new()).is_err());
        assert!(BoundedRadix2Dft::new(vec![CompactChallengeField::ONE; 3]).is_err());
        assert!(
            BoundedRadix2Dft::new(vec![CompactChallengeField::ONE; 8])
                .expect("valid transform")
                .into_values()
                .is_err()
        );
    }
}
