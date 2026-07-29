//! Allocation-stable radix-two DFT for browser proof generation.
//!
//! Plonky3's cached DFT implementations retain large twiddle tables. At the
//! selected aggregate domain those tables overlap the encoded column and the
//! streaming leaf frontier beyond the WebAssembly ceiling. This incremental
//! variant derives one layer root and advances its powers in place, so its
//! auxiliary memory is constant and every poll has a bounded arithmetic cost.

use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;

use super::ChallengeField;

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

    use super::*;

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
}
