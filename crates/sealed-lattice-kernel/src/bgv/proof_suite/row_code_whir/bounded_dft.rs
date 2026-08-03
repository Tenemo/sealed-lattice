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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedBaseCosetLaneDftStage {
    FoldCoefficients,
    Transform,
    Complete,
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedButterflyOrdinalRange {
    start: usize,
    end: usize,
}

/// Public-query-derived butterfly ownership for selected outputs of one lane.
///
/// The schedule is computed backwards from the requested output coordinates.
/// A butterfly is retained exactly when one of its outputs is required by a
/// retained butterfly in the next layer. Consequently the forward execution
/// performs every dependency of every selected output and no unrelated
/// butterfly. The ranges are only a compact execution representation; they do
/// not enter the commitment or transcript.
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SelectedBaseCosetLaneDftSchedule {
    lane_column_count: usize,
    selected_output_indices: Vec<usize>,
    butterfly_ranges_by_layer: Vec<Vec<SelectedButterflyOrdinalRange>>,
    butterfly_count: usize,
    maximum_butterfly_count_upper_bound: usize,
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
impl SelectedBaseCosetLaneDftSchedule {
    pub(super) fn new(
        lane_column_count: usize,
        selected_output_indices: &[usize],
    ) -> Result<Self, String> {
        if lane_column_count < 2
            || !lane_column_count.is_power_of_two()
            || selected_output_indices.is_empty()
            || selected_output_indices
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || selected_output_indices
                .last()
                .is_some_and(|index| *index >= lane_column_count)
        {
            return Err("selected lane DFT schedule geometry is invalid".to_owned());
        }

        let logarithmic_length = lane_column_count.ilog2() as usize;
        let butterfly_count_per_layer = lane_column_count / 2;
        let mut required_output_mask = allocate_bit_mask(lane_column_count)?;
        for output_index in selected_output_indices {
            set_mask_bit(&mut required_output_mask, *output_index)?;
        }
        let mut ranges_by_layer = Vec::new();
        ranges_by_layer
            .try_reserve_exact(logarithmic_length)
            .map_err(|_| "selected lane DFT layer allocation failed".to_owned())?;
        ranges_by_layer.resize_with(logarithmic_length, Vec::new);
        let mut exact_butterfly_count = 0_usize;

        for layer in (0..logarithmic_length).rev() {
            let half_block_length = 1_usize
                .checked_shl(layer as u32)
                .ok_or_else(|| "selected lane DFT half-block length overflowed".to_owned())?;
            let block_length = half_block_length
                .checked_mul(2)
                .ok_or_else(|| "selected lane DFT block length overflowed".to_owned())?;
            let mut butterfly_mask = allocate_bit_mask(butterfly_count_per_layer)?;
            visit_mask_indices(&required_output_mask, lane_column_count, |output_index| {
                let block_index = output_index / block_length;
                let within_block_index = output_index % block_length;
                let butterfly_ordinal = block_index
                    .checked_mul(half_block_length)
                    .and_then(|offset| offset.checked_add(within_block_index % half_block_length))
                    .ok_or_else(|| "selected lane DFT butterfly ordinal overflowed".to_owned())?;
                set_mask_bit(&mut butterfly_mask, butterfly_ordinal)
            })?;

            let mut previous_layer_required_mask = allocate_bit_mask(lane_column_count)?;
            let mut layer_ranges = Vec::new();
            let mut active_range: Option<SelectedButterflyOrdinalRange> = None;
            let mut layer_butterfly_count = 0_usize;
            visit_mask_indices(
                &butterfly_mask,
                butterfly_count_per_layer,
                |butterfly_ordinal| {
                    layer_butterfly_count = layer_butterfly_count
                        .checked_add(1)
                        .ok_or_else(|| "selected lane DFT butterfly count overflowed".to_owned())?;
                    match active_range.as_mut() {
                        Some(range) if range.end == butterfly_ordinal => {
                            range.end = range.end.checked_add(1).ok_or_else(|| {
                                "selected lane DFT butterfly range overflowed".to_owned()
                            })?;
                        }
                        Some(range) => {
                            layer_ranges.try_reserve(1).map_err(|_| {
                                "selected lane DFT range allocation failed".to_owned()
                            })?;
                            layer_ranges.push(*range);
                            active_range = Some(SelectedButterflyOrdinalRange {
                                start: butterfly_ordinal,
                                end: butterfly_ordinal + 1,
                            });
                        }
                        None => {
                            active_range = Some(SelectedButterflyOrdinalRange {
                                start: butterfly_ordinal,
                                end: butterfly_ordinal + 1,
                            });
                        }
                    }

                    let block_index = butterfly_ordinal / half_block_length;
                    let within_block_index = butterfly_ordinal % half_block_length;
                    let left_index = block_index
                        .checked_mul(block_length)
                        .and_then(|offset| offset.checked_add(within_block_index))
                        .ok_or_else(|| {
                            "selected lane DFT dependency coordinate overflowed".to_owned()
                        })?;
                    let right_index =
                        left_index.checked_add(half_block_length).ok_or_else(|| {
                            "selected lane DFT dependency coordinate overflowed".to_owned()
                        })?;
                    set_mask_bit(&mut previous_layer_required_mask, left_index)?;
                    set_mask_bit(&mut previous_layer_required_mask, right_index)
                },
            )?;
            if let Some(range) = active_range {
                layer_ranges
                    .try_reserve(1)
                    .map_err(|_| "selected lane DFT range allocation failed".to_owned())?;
                layer_ranges.push(range);
            }
            if layer_ranges.is_empty() || layer_butterfly_count == 0 {
                return Err("selected lane DFT dependency schedule is empty".to_owned());
            }
            exact_butterfly_count = exact_butterfly_count
                .checked_add(layer_butterfly_count)
                .ok_or_else(|| "selected lane DFT butterfly count overflowed".to_owned())?;
            ranges_by_layer[layer] = layer_ranges;
            required_output_mask = previous_layer_required_mask;
        }

        let maximum_butterfly_count_upper_bound = selected_dft_butterfly_count_upper_bound(
            lane_column_count,
            selected_output_indices.len(),
        )?;
        if exact_butterfly_count > maximum_butterfly_count_upper_bound {
            return Err("selected lane DFT exceeds its butterfly upper bound".to_owned());
        }

        let mut selected_indices = Vec::new();
        selected_indices
            .try_reserve_exact(selected_output_indices.len())
            .map_err(|_| "selected lane DFT output-index allocation failed".to_owned())?;
        selected_indices.extend_from_slice(selected_output_indices);
        Ok(Self {
            lane_column_count,
            selected_output_indices: selected_indices,
            butterfly_ranges_by_layer: ranges_by_layer,
            butterfly_count: exact_butterfly_count,
            maximum_butterfly_count_upper_bound,
        })
    }

    pub(super) const fn lane_column_count(&self) -> usize {
        self.lane_column_count
    }

    pub(super) fn selected_output_indices(&self) -> &[usize] {
        &self.selected_output_indices
    }

    pub(super) const fn butterfly_count(&self) -> usize {
        self.butterfly_count
    }

    pub(super) const fn maximum_butterfly_count_upper_bound(&self) -> usize {
        self.maximum_butterfly_count_upper_bound
    }

    pub(super) fn exact_heap_byte_length(&self) -> Result<usize, String> {
        self.selected_output_indices
            .capacity()
            .checked_mul(size_of::<usize>())
            .and_then(|total| {
                self.butterfly_ranges_by_layer
                    .capacity()
                    .checked_mul(size_of::<Vec<SelectedButterflyOrdinalRange>>())
                    .and_then(|layer_catalog| total.checked_add(layer_catalog))
            })
            .and_then(|total| {
                self.butterfly_ranges_by_layer
                    .iter()
                    .try_fold(0_usize, |range_total, ranges| {
                        range_total.checked_add(
                            ranges
                                .capacity()
                                .checked_mul(size_of::<SelectedButterflyOrdinalRange>())?,
                        )
                    })
                    .and_then(|ranges| total.checked_add(ranges))
            })
            .ok_or_else(|| "selected lane DFT schedule liveness overflowed".to_owned())
    }

    pub(super) fn maximum_construction_workspace_byte_length(&self) -> Result<usize, String> {
        bit_mask_byte_length(self.lane_column_count)
            .checked_mul(2)
            .and_then(|total| bit_mask_byte_length(self.lane_column_count / 2).checked_add(total))
            .ok_or_else(|| "selected lane DFT schedule workspace overflowed".to_owned())
    }
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
fn selected_dft_butterfly_count_upper_bound(
    lane_column_count: usize,
    selected_output_count: usize,
) -> Result<usize, String> {
    if lane_column_count < 2
        || !lane_column_count.is_power_of_two()
        || selected_output_count == 0
        || selected_output_count > lane_column_count
    {
        return Err("selected lane DFT upper-bound geometry is invalid".to_owned());
    }
    let maximum_per_layer = lane_column_count / 2;
    (0..lane_column_count.ilog2()).try_fold(0_usize, |total, dependency_depth| {
        let dependency_multiplier = 1_usize
            .checked_shl(dependency_depth)
            .ok_or_else(|| "selected lane DFT dependency multiplier overflowed".to_owned())?;
        let layer_bound = selected_output_count
            .checked_mul(dependency_multiplier)
            .unwrap_or(usize::MAX)
            .min(maximum_per_layer);
        total
            .checked_add(layer_bound)
            .ok_or_else(|| "selected lane DFT upper bound overflowed".to_owned())
    })
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
fn bit_mask_byte_length(bit_count: usize) -> usize {
    bit_count.div_ceil(u64::BITS as usize) * size_of::<u64>()
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
fn allocate_bit_mask(bit_count: usize) -> Result<Vec<u64>, String> {
    if bit_count == 0 {
        return Err("selected lane DFT bit mask is empty".to_owned());
    }
    let word_count = bit_count.div_ceil(u64::BITS as usize);
    let mut mask = Vec::new();
    mask.try_reserve_exact(word_count)
        .map_err(|_| "selected lane DFT bit-mask allocation failed".to_owned())?;
    mask.resize(word_count, 0_u64);
    Ok(mask)
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
fn set_mask_bit(mask: &mut [u64], bit_index: usize) -> Result<(), String> {
    let word = mask
        .get_mut(bit_index / u64::BITS as usize)
        .ok_or_else(|| "selected lane DFT bit coordinate is out of range".to_owned())?;
    *word |= 1_u64 << (bit_index % u64::BITS as usize);
    Ok(())
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
fn visit_mask_indices(
    mask: &[u64],
    bit_count: usize,
    mut visit: impl FnMut(usize) -> Result<(), String>,
) -> Result<(), String> {
    for (word_index, word) in mask.iter().copied().enumerate() {
        let mut remaining = word;
        while remaining != 0 {
            let within_word_index = remaining.trailing_zeros() as usize;
            let bit_index = word_index
                .checked_mul(u64::BITS as usize)
                .and_then(|offset| offset.checked_add(within_word_index))
                .ok_or_else(|| "selected lane DFT bit coordinate overflowed".to_owned())?;
            if bit_index >= bit_count {
                return Err("selected lane DFT bit mask has a noncanonical tail".to_owned());
            }
            visit(bit_index)?;
            remaining &= remaining - 1;
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedSelectedBaseCosetLaneDftStage {
    ApplyCoset,
    BitReverse,
    Butterflies,
    Complete,
}

/// Incremental selected-output DFT for authenticated opening replay.
///
/// Unlike the commitment pass, opening replay does not retain a hasher for
/// every column in a lane. It keeps one coefficient buffer and executes the
/// exact dependency schedule for the public queried coordinates. This leaves
/// the canonical DFT and column order unchanged while bounding work by the
/// selected-output dependency graph.
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(super) struct BoundedSelectedBaseCosetLaneDft {
    values: Zeroizing<Vec<ProofBaseFieldElement>>,
    lane_domain: ProofEvaluationDomain,
    schedule: SelectedBaseCosetLaneDftSchedule,
    next_coset_index: usize,
    next_coset_power: ProofBaseFieldElement,
    next_bit_reversal_index: usize,
    layer: usize,
    next_range_index: usize,
    next_butterfly_ordinal: usize,
    executed_butterfly_count: usize,
    stage: BoundedSelectedBaseCosetLaneDftStage,
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
impl BoundedSelectedBaseCosetLaneDft {
    pub(super) fn new(
        coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
        full_domain: ProofEvaluationDomain,
        lane_ordinal: usize,
        schedule: SelectedBaseCosetLaneDftSchedule,
    ) -> Result<Self, String> {
        let lane_column_count = schedule.lane_column_count();
        if coefficients.len() != lane_column_count
            || lane_column_count > full_domain.size()
            || !full_domain.size().is_multiple_of(lane_column_count)
        {
            return Err("selected base lane DFT geometry is invalid".to_owned());
        }
        let lane_count = full_domain.size() / lane_column_count;
        if !lane_count.is_power_of_two() || lane_ordinal >= lane_count {
            return Err("selected base lane DFT ordinal is invalid".to_owned());
        }
        let lane_offset = full_domain
            .point(lane_ordinal)
            .map_err(|_| "selected base lane DFT offset is invalid".to_owned())?;
        let lane_domain = ProofEvaluationDomain::new(lane_column_count, lane_offset.canonical())
            .map_err(|_| "selected base lane DFT domain is invalid".to_owned())?;
        let expected_lane_generator = full_domain.generator().power(
            u64::try_from(lane_count)
                .map_err(|_| "selected base lane count exceeds u64".to_owned())?,
        );
        if lane_domain.generator() != expected_lane_generator {
            return Err("selected base lane DFT generator is inconsistent".to_owned());
        }
        let first_butterfly_ordinal = schedule
            .butterfly_ranges_by_layer
            .first()
            .and_then(|ranges| ranges.first())
            .map(|range| range.start)
            .ok_or_else(|| "selected base lane DFT schedule is empty".to_owned())?;
        Ok(Self {
            values: coefficients,
            lane_domain,
            schedule,
            next_coset_index: 0,
            next_coset_power: ProofBaseFieldElement::ONE,
            next_bit_reversal_index: 0,
            layer: 0,
            next_range_index: 0,
            next_butterfly_ordinal: first_butterfly_ordinal,
            executed_butterfly_count: 0,
            stage: BoundedSelectedBaseCosetLaneDftStage::ApplyCoset,
        })
    }

    pub(super) fn poll(&mut self) -> Result<bool, String> {
        match self.stage {
            BoundedSelectedBaseCosetLaneDftStage::ApplyCoset => {
                self.advance_coset(DEFAULT_BIT_REVERSALS_PER_POLL)?;
                Ok(false)
            }
            BoundedSelectedBaseCosetLaneDftStage::BitReverse => {
                self.advance_bit_reversal(DEFAULT_BIT_REVERSALS_PER_POLL)?;
                Ok(false)
            }
            BoundedSelectedBaseCosetLaneDftStage::Butterflies => {
                self.advance_butterflies(DEFAULT_BUTTERFLIES_PER_POLL)?;
                Ok(false)
            }
            BoundedSelectedBaseCosetLaneDftStage::Complete => Ok(true),
        }
    }

    pub(super) fn into_selected_values(
        self,
    ) -> Result<Vec<(usize, ProofBaseFieldElement)>, String> {
        if self.stage != BoundedSelectedBaseCosetLaneDftStage::Complete
            || self.executed_butterfly_count != self.schedule.butterfly_count()
        {
            return Err(
                "selected base lane DFT values were requested before completion".to_owned(),
            );
        }
        let mut selected_values = Vec::new();
        selected_values
            .try_reserve_exact(self.schedule.selected_output_indices().len())
            .map_err(|_| "selected base lane DFT output allocation failed".to_owned())?;
        for output_index in self.schedule.selected_output_indices() {
            selected_values.push((
                *output_index,
                *self
                    .values
                    .get(*output_index)
                    .ok_or_else(|| "selected base lane DFT output is absent".to_owned())?,
            ));
        }
        Ok(selected_values)
    }

    fn advance_coset(&mut self, maximum_indices: usize) -> Result<(), String> {
        if maximum_indices == 0 || self.stage != BoundedSelectedBaseCosetLaneDftStage::ApplyCoset {
            return Err("selected base lane DFT coset poll has an invalid state".to_owned());
        }
        let end = self
            .next_coset_index
            .saturating_add(maximum_indices)
            .min(self.values.len());
        for value in &mut self.values[self.next_coset_index..end] {
            *value = value.multiply(self.next_coset_power);
            self.next_coset_power = self
                .next_coset_power
                .multiply(self.lane_domain.coset_offset());
        }
        self.next_coset_index = end;
        if end == self.values.len() {
            self.stage = BoundedSelectedBaseCosetLaneDftStage::BitReverse;
        }
        Ok(())
    }

    fn advance_bit_reversal(&mut self, maximum_indices: usize) -> Result<(), String> {
        if maximum_indices == 0 || self.stage != BoundedSelectedBaseCosetLaneDftStage::BitReverse {
            return Err("selected base lane DFT bit-reversal poll has an invalid state".to_owned());
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
            self.stage = BoundedSelectedBaseCosetLaneDftStage::Butterflies;
        }
        Ok(())
    }

    fn advance_butterflies(&mut self, maximum_butterflies: usize) -> Result<(), String> {
        if maximum_butterflies == 0
            || self.stage != BoundedSelectedBaseCosetLaneDftStage::Butterflies
            || self.layer >= self.schedule.butterfly_ranges_by_layer.len()
        {
            return Err("selected base lane DFT butterfly poll has an invalid state".to_owned());
        }
        let block_length = 1_usize
            .checked_shl((self.layer + 1) as u32)
            .ok_or_else(|| "selected base lane DFT block length overflowed".to_owned())?;
        let half_block_length = block_length / 2;
        let twiddle_step = self.lane_domain.generator().power(
            u64::try_from(self.values.len() / block_length)
                .map_err(|_| "selected base lane DFT twiddle exponent exceeds u64".to_owned())?,
        );
        let layer_ranges = self
            .schedule
            .butterfly_ranges_by_layer
            .get(self.layer)
            .ok_or_else(|| "selected base lane DFT layer is absent".to_owned())?;
        let mut remaining_budget = maximum_butterflies;
        while remaining_budget > 0 && self.next_range_index < layer_ranges.len() {
            let range = layer_ranges[self.next_range_index];
            if self.next_butterfly_ordinal < range.start || self.next_butterfly_ordinal > range.end
            {
                return Err("selected base lane DFT range cursor is invalid".to_owned());
            }
            if self.next_butterfly_ordinal == range.end {
                self.next_range_index += 1;
                if let Some(next_range) = layer_ranges.get(self.next_range_index) {
                    self.next_butterfly_ordinal = next_range.start;
                }
                continue;
            }
            let block_index = self.next_butterfly_ordinal / half_block_length;
            let within_block_index = self.next_butterfly_ordinal % half_block_length;
            let block_end = range.end.min(
                block_index
                    .checked_add(1)
                    .and_then(|index| index.checked_mul(half_block_length))
                    .ok_or_else(|| "selected base lane DFT block end overflowed".to_owned())?,
            );
            let chunk_end = block_end.min(
                self.next_butterfly_ordinal
                    .checked_add(remaining_budget)
                    .ok_or_else(|| "selected base lane DFT poll end overflowed".to_owned())?,
            );
            let mut twiddle =
                if within_block_index == 0 {
                    ProofBaseFieldElement::ONE
                } else {
                    twiddle_step.power(u64::try_from(within_block_index).map_err(|_| {
                        "selected base lane DFT twiddle index exceeds u64".to_owned()
                    })?)
                };
            while self.next_butterfly_ordinal < chunk_end {
                let local_index = self.next_butterfly_ordinal % half_block_length;
                let left_index = block_index
                    .checked_mul(block_length)
                    .and_then(|offset| offset.checked_add(local_index))
                    .ok_or_else(|| "selected base lane DFT left index overflowed".to_owned())?;
                let right_index = left_index
                    .checked_add(half_block_length)
                    .ok_or_else(|| "selected base lane DFT right index overflowed".to_owned())?;
                let left = self.values[left_index];
                let right_twiddle = self.values[right_index].multiply(twiddle);
                self.values[left_index] = left.add(right_twiddle);
                self.values[right_index] = left.subtract(right_twiddle);
                twiddle = twiddle.multiply(twiddle_step);
                self.next_butterfly_ordinal += 1;
                self.executed_butterfly_count = self
                    .executed_butterfly_count
                    .checked_add(1)
                    .ok_or_else(|| {
                        "selected base lane DFT executed-butterfly count overflowed".to_owned()
                    })?;
                remaining_budget -= 1;
            }
        }
        if self.next_range_index == layer_ranges.len() {
            self.layer += 1;
            self.next_range_index = 0;
            if self.layer == self.schedule.butterfly_ranges_by_layer.len() {
                if self.executed_butterfly_count != self.schedule.butterfly_count() {
                    return Err("selected base lane DFT butterfly count is inconsistent".to_owned());
                }
                self.stage = BoundedSelectedBaseCosetLaneDftStage::Complete;
            } else {
                self.next_butterfly_ordinal = self.schedule.butterfly_ranges_by_layer[self.layer]
                    .first()
                    .ok_or_else(|| "selected base lane DFT next layer is empty".to_owned())?
                    .start;
            }
        }
        Ok(())
    }
}

/// Incremental DFT for one interleaved lane of a larger coset domain.
///
/// For a full domain of size `lane_count * lane_column_count`, lane `r`
/// contains the canonical evaluations at indices
/// `r, r + lane_count, r + 2 * lane_count, ...`. The polynomial is reduced
/// modulo `x^lane_column_count - lane_offset^lane_column_count`, then evaluated
/// by one allocation-stable `lane_column_count`-point coset DFT. This keeps the
/// original ascending commitment coordinates available without allocating the
/// complete encoded row.
pub(super) struct BoundedBaseCosetLaneDft {
    coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
    lane_column_count: usize,
    coefficient_fold_constant: ProofBaseFieldElement,
    coefficient_fold_power: ProofBaseFieldElement,
    coefficient_fold_power_ordinal: usize,
    next_fold_coefficient_index: usize,
    lane_domain: ProofEvaluationDomain,
    transform: Option<BoundedBaseCosetDft>,
    stage: BoundedBaseCosetLaneDftStage,
}

impl BoundedBaseCosetLaneDft {
    pub(super) fn new(
        coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
        full_domain: ProofEvaluationDomain,
        lane_column_count: usize,
        lane_ordinal: usize,
    ) -> Result<Self, String> {
        if coefficients.is_empty()
            || coefficients.len() > full_domain.size()
            || lane_column_count < 2
            || !lane_column_count.is_power_of_two()
            || lane_column_count > full_domain.size()
            || !full_domain.size().is_multiple_of(lane_column_count)
        {
            return Err("bounded base lane DFT geometry is invalid".to_owned());
        }
        let lane_count = full_domain.size() / lane_column_count;
        if !lane_count.is_power_of_two() || lane_ordinal >= lane_count {
            return Err("bounded base lane DFT ordinal is invalid".to_owned());
        }
        let lane_offset = full_domain
            .point(lane_ordinal)
            .map_err(|_| "bounded base lane DFT offset is invalid".to_owned())?;
        let lane_domain = ProofEvaluationDomain::new(lane_column_count, lane_offset.canonical())
            .map_err(|_| "bounded base lane DFT domain is invalid".to_owned())?;
        let expected_lane_generator = full_domain.generator().power(
            u64::try_from(lane_count)
                .map_err(|_| "bounded base lane count exceeds u64".to_owned())?,
        );
        if lane_domain.generator() != expected_lane_generator {
            return Err("bounded base lane DFT generator is inconsistent".to_owned());
        }

        let fold_constant = lane_offset.power(
            u64::try_from(lane_column_count)
                .map_err(|_| "bounded base lane width exceeds u64".to_owned())?,
        );
        let next_fold_coefficient_index = coefficients.len().min(lane_column_count);
        Ok(Self {
            coefficients,
            lane_column_count,
            coefficient_fold_constant: fold_constant,
            coefficient_fold_power: ProofBaseFieldElement::ONE,
            coefficient_fold_power_ordinal: 0,
            next_fold_coefficient_index,
            lane_domain,
            transform: None,
            stage: BoundedBaseCosetLaneDftStage::FoldCoefficients,
        })
    }

    pub(super) fn poll(&mut self) -> Result<bool, String> {
        match self.stage {
            BoundedBaseCosetLaneDftStage::FoldCoefficients => {
                self.advance_coefficient_folding(DEFAULT_BIT_REVERSALS_PER_POLL)?;
                Ok(false)
            }
            BoundedBaseCosetLaneDftStage::Transform => {
                let transform = self
                    .transform
                    .as_mut()
                    .ok_or_else(|| "bounded base lane DFT transform is absent".to_owned())?;
                if transform.poll()? {
                    self.stage = BoundedBaseCosetLaneDftStage::Complete;
                }
                Ok(false)
            }
            BoundedBaseCosetLaneDftStage::Complete => Ok(true),
        }
    }

    pub(super) fn into_values(mut self) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, String> {
        if self.stage != BoundedBaseCosetLaneDftStage::Complete {
            return Err("bounded base lane DFT values were requested before completion".to_owned());
        }
        self.transform
            .take()
            .ok_or_else(|| "bounded base lane DFT transform is absent".to_owned())?
            .into_values()
    }

    fn advance_coefficient_folding(&mut self, maximum_coefficients: usize) -> Result<(), String> {
        if maximum_coefficients == 0 || self.stage != BoundedBaseCosetLaneDftStage::FoldCoefficients
        {
            return Err("bounded base lane coefficient-fold poll has an invalid state".to_owned());
        }
        let end = self
            .next_fold_coefficient_index
            .saturating_add(maximum_coefficients)
            .min(self.coefficients.len());
        for source_index in self.next_fold_coefficient_index..end {
            let folded_index = source_index % self.lane_column_count;
            let fold_power_ordinal = source_index / self.lane_column_count;
            while self.coefficient_fold_power_ordinal < fold_power_ordinal {
                self.coefficient_fold_power = self
                    .coefficient_fold_power
                    .multiply(self.coefficient_fold_constant);
                self.coefficient_fold_power_ordinal = self
                    .coefficient_fold_power_ordinal
                    .checked_add(1)
                    .ok_or_else(|| "bounded base lane fold-power ordinal overflowed".to_owned())?;
            }
            if self.coefficient_fold_power_ordinal != fold_power_ordinal {
                return Err("bounded base lane fold-power order is invalid".to_owned());
            }
            let contribution =
                self.coefficients[source_index].multiply(self.coefficient_fold_power);
            self.coefficients[folded_index] = self.coefficients[folded_index].add(contribution);
        }
        self.next_fold_coefficient_index = end;
        if end == self.coefficients.len() {
            self.coefficients.truncate(self.lane_column_count);
            let coefficients =
                core::mem::replace(&mut self.coefficients, Zeroizing::new(Vec::new()));
            self.transform = Some(BoundedBaseCosetDft::new(coefficients, self.lane_domain)?);
            self.stage = BoundedBaseCosetLaneDftStage::Transform;
        }
        Ok(())
    }
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
    use crate::bgv::proof_suite::row_code_whir::{
        column_commitment::{
            InterleavedColumnCommitmentBuilder, PrivateColumnLeafSaltContext, StreamingColumnHasher,
        },
        row_encoding::{
            PRIVATE_ROW_PAD_SEED_BYTE_LENGTH, RowCodeHighHalfSource, RowEncodingGeometry,
            encode_row, padded_base_row_coefficients,
        },
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
    fn bounded_base_coset_lanes_restore_every_canonical_domain_coordinate() {
        for logarithmic_length in 2..=10 {
            let full_length = 1_usize << logarithmic_length;
            let full_domain =
                ProofEvaluationDomain::new(full_length, 7).expect("the full coset domain is valid");
            for logarithmic_lane_count in 0..=logarithmic_length.min(5) {
                let lane_count = 1_usize << logarithmic_lane_count;
                let lane_column_count = full_length / lane_count;
                if lane_column_count < 2 {
                    continue;
                }
                for coefficient_count in [1, lane_column_count, full_length / 2 + 1, full_length] {
                    let coefficients = (0..coefficient_count)
                        .map(|coefficient_index| {
                            ProofBaseFieldElement::from_canonical(
                                u64::try_from(coefficient_index * 53 + 19)
                                    .expect("the focused coefficient fits u64"),
                            )
                            .expect("the focused coefficient is canonical")
                        })
                        .collect::<Vec<_>>();
                    let expected = full_domain
                        .evaluate_base_polynomial(&coefficients)
                        .expect("the reference full-domain DFT succeeds");
                    let mut restored = vec![ProofBaseFieldElement::ZERO; full_length];
                    for lane_ordinal in 0..lane_count {
                        let mut bounded = BoundedBaseCosetLaneDft::new(
                            Zeroizing::new(coefficients.clone()),
                            full_domain,
                            lane_column_count,
                            lane_ordinal,
                        )
                        .expect("the bounded lane DFT initializes");
                        while !bounded.poll().expect("the bounded lane DFT advances") {}
                        let lane = bounded
                            .into_values()
                            .expect("the bounded lane DFT completed");
                        assert_eq!(lane.len(), lane_column_count);
                        for (within_lane_index, value) in lane.iter().copied().enumerate() {
                            restored[within_lane_index * lane_count + lane_ordinal] = value;
                        }
                    }
                    assert_eq!(
                        restored, expected,
                        "log domain {logarithmic_length}, log lane count {logarithmic_lane_count}, coefficient count {coefficient_count}",
                    );
                }
            }
        }
    }

    #[test]
    fn bounded_base_coset_lanes_refuse_malformed_geometry_and_early_extraction() {
        let domain = ProofEvaluationDomain::new(64, 7).expect("the focused domain is valid");
        let coefficients = Zeroizing::new(vec![ProofBaseFieldElement::ONE; 17]);
        assert!(BoundedBaseCosetLaneDft::new(coefficients.clone(), domain, 0, 0).is_err());
        assert!(BoundedBaseCosetLaneDft::new(coefficients.clone(), domain, 24, 0).is_err());
        assert!(BoundedBaseCosetLaneDft::new(coefficients.clone(), domain, 16, 4).is_err());
        let bounded = BoundedBaseCosetLaneDft::new(coefficients, domain, 16, 0)
            .expect("the focused lane geometry is valid");
        assert!(bounded.into_values().is_err());
    }

    #[test]
    fn selected_base_coset_lane_dft_matches_every_requested_canonical_coordinate() {
        for logarithmic_length in 2..=10 {
            let full_length = 1_usize << logarithmic_length;
            let full_domain =
                ProofEvaluationDomain::new(full_length, 7).expect("the full coset domain is valid");
            for logarithmic_lane_count in 0..=logarithmic_length.min(4) {
                let lane_count = 1_usize << logarithmic_lane_count;
                let lane_column_count = full_length / lane_count;
                if lane_column_count < 2 {
                    continue;
                }
                let coefficients = (0..lane_column_count)
                    .map(|coefficient_index| {
                        ProofBaseFieldElement::from_canonical(
                            u64::try_from(coefficient_index * 71 + 23)
                                .expect("the focused coefficient fits u64"),
                        )
                        .expect("the focused coefficient is canonical")
                    })
                    .collect::<Vec<_>>();
                let expected = full_domain
                    .evaluate_base_polynomial(&coefficients)
                    .expect("the reference full-domain DFT succeeds");
                let mut selections = vec![
                    vec![0],
                    vec![lane_column_count - 1],
                    vec![0, lane_column_count - 1],
                ];
                let patterned = (0..lane_column_count)
                    .filter(|index| index % 3 == 0 || index % 7 == 1)
                    .collect::<Vec<_>>();
                if !patterned.is_empty() {
                    selections.push(patterned);
                }
                if lane_column_count <= 64 {
                    selections.push((0..lane_column_count).collect());
                }
                for selected_indices in selections {
                    for lane_ordinal in 0..lane_count {
                        let schedule = SelectedBaseCosetLaneDftSchedule::new(
                            lane_column_count,
                            &selected_indices,
                        )
                        .expect("the selected-output schedule derives");
                        let mut bounded = BoundedSelectedBaseCosetLaneDft::new(
                            Zeroizing::new(coefficients.clone()),
                            full_domain,
                            lane_ordinal,
                            schedule,
                        )
                        .expect("the selected lane DFT initializes");
                        while !bounded.poll().expect("the selected lane DFT advances") {}
                        let selected_values = bounded
                            .into_selected_values()
                            .expect("the selected lane DFT completes");
                        let expected_values = selected_indices
                            .iter()
                            .map(|within_lane_index| {
                                (
                                    *within_lane_index,
                                    expected[within_lane_index * lane_count + lane_ordinal],
                                )
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(
                            selected_values, expected_values,
                            "log domain {logarithmic_length}, log lane count {logarithmic_lane_count}, lane {lane_ordinal}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn selected_lane_dft_schedule_derives_the_conservative_vss_dependency_bound() {
        let lane_column_count = 1_usize << 19;
        let selected_indices = (0..49).collect::<Vec<_>>();
        let schedule = SelectedBaseCosetLaneDftSchedule::new(lane_column_count, &selected_indices)
            .expect("the maximum balanced VSS lane schedule derives");
        let independently_summed_bound = (0..lane_column_count.ilog2())
            .map(|dependency_depth| {
                selected_indices
                    .len()
                    .checked_mul(1_usize << dependency_depth)
                    .expect("the focused dependency count fits usize")
                    .min(lane_column_count / 2)
            })
            .sum::<usize>();
        assert_eq!(schedule.butterfly_count(), independently_summed_bound);
        assert_eq!(
            schedule.maximum_butterfly_count_upper_bound(),
            independently_summed_bound
        );
        assert!(schedule.exact_heap_byte_length().expect("liveness derives") < 1 << 20);
        assert_eq!(
            schedule
                .maximum_construction_workspace_byte_length()
                .expect("schedule workspace derives"),
            163_840
        );
    }

    #[test]
    fn selected_lane_dft_refuses_noncanonical_schedules_and_early_extraction() {
        assert!(SelectedBaseCosetLaneDftSchedule::new(1, &[0]).is_err());
        assert!(SelectedBaseCosetLaneDftSchedule::new(64, &[]).is_err());
        assert!(SelectedBaseCosetLaneDftSchedule::new(64, &[2, 2]).is_err());
        assert!(SelectedBaseCosetLaneDftSchedule::new(64, &[3, 2]).is_err());
        assert!(SelectedBaseCosetLaneDftSchedule::new(64, &[64]).is_err());

        let full_domain =
            ProofEvaluationDomain::new(256, 7).expect("the full coset domain is valid");
        let schedule = SelectedBaseCosetLaneDftSchedule::new(64, &[0, 5, 63])
            .expect("the focused selected schedule derives");
        assert!(
            BoundedSelectedBaseCosetLaneDft::new(
                Zeroizing::new(vec![ProofBaseFieldElement::ONE; 63]),
                full_domain,
                0,
                schedule.clone(),
            )
            .is_err()
        );
        assert!(
            BoundedSelectedBaseCosetLaneDft::new(
                Zeroizing::new(vec![ProofBaseFieldElement::ONE; 64]),
                full_domain,
                4,
                schedule.clone(),
            )
            .is_err()
        );
        let bounded = BoundedSelectedBaseCosetLaneDft::new(
            Zeroizing::new(vec![ProofBaseFieldElement::ONE; 64]),
            full_domain,
            0,
            schedule,
        )
        .expect("the focused selected lane DFT initializes");
        assert!(bounded.into_selected_values().is_err());
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

    #[test]
    fn bounded_phase_row_lanes_match_private_and_public_canonical_encodings() {
        let geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(4, 4, 2)
            .expect("the focused row geometry is valid");
        let private_seed = [0x5a_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let full_domain = ProofEvaluationDomain::new(
            geometry.encoded_column_count,
            Goldilocks::GENERATOR.as_canonical_u64(),
        )
        .expect("the phase coset domain is valid");
        let lane_count = 4;
        let lane_column_count = geometry.encoded_column_count / lane_count;
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
                for lane_ordinal in 0..lane_count {
                    let mut base_witness = Vec::new();
                    base_witness
                        .try_reserve_exact(geometry.padded_coefficient_count)
                        .expect("the focused lane row allocation succeeds");
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
                    let mut bounded = BoundedBaseCosetLaneDft::new(
                        coefficients,
                        full_domain,
                        lane_column_count,
                        lane_ordinal,
                    )
                    .expect("the bounded phase lane DFT initializes");
                    while !bounded.poll().expect("the bounded phase lane DFT advances") {}
                    let actual = bounded
                        .into_values()
                        .expect("the bounded phase lane DFT completed");
                    assert_eq!(
                        actual
                            .iter()
                            .map(|value| value.canonical())
                            .collect::<Vec<_>>(),
                        expected
                            .iter()
                            .skip(lane_ordinal)
                            .step_by(lane_count)
                            .map(Goldilocks::as_canonical_u64)
                            .collect::<Vec<_>>(),
                        "row {row_index}, lane {lane_ordinal}, source {high_half_source:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn interleaved_phase_schedule_preserves_canonical_commitment_bytes() {
        const COMMITMENT_ROLE: &[u8] = b"phase/focused-parity";
        let geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(8, 4, 2)
            .expect("the focused phase geometry is valid");
        let row_pad_seed = [0x35_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let leaf_salt_seed = [0x71_u8; 64];
        let opened_column_indices = [0, 1, 7, 17, 31, 63, 95, 127];
        let witnesses = (0..geometry.row_count)
            .map(|row_index| {
                (0..geometry.witness_values_per_row)
                    .map(|value_index| {
                        Goldilocks::from_u64(
                            u64::try_from(row_index * 149 + value_index * 43 + 11)
                                .expect("the focused witness coordinate fits u64"),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let encoded_rows = witnesses
            .iter()
            .enumerate()
            .map(|(row_index, witness)| {
                encode_row(
                    geometry,
                    row_index,
                    witness,
                    RowCodeHighHalfSource::PrivateMaskSeed(&row_pad_seed),
                )
                .expect("the canonical private row encodes")
            })
            .collect::<Vec<_>>();
        let mut reference_hasher = StreamingColumnHasher::new_with_private_salt(
            geometry.row_count,
            geometry.encoded_column_count,
            &PrivateColumnLeafSaltContext::new(&leaf_salt_seed, COMMITMENT_ROLE),
        )
        .expect("the reference phase commitment initializes");
        for row in &encoded_rows {
            reference_hasher
                .absorb_row(row)
                .expect("the canonical reference row absorbs");
        }
        let expected = reference_hasher
            .finalize_commitment(&opened_column_indices)
            .expect("the reference phase commitment completes");

        let lane_column_count = geometry.encoded_column_count / 32;
        let full_domain = ProofEvaluationDomain::new(
            geometry.encoded_column_count,
            Goldilocks::GENERATOR.as_canonical_u64(),
        )
        .expect("the focused phase domain is valid");
        let mut builder =
            InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
                geometry.row_count,
                geometry.encoded_column_count,
                lane_column_count,
                &opened_column_indices,
                Some(PrivateColumnLeafSaltContext::new(
                    &leaf_salt_seed,
                    COMMITMENT_ROLE,
                )),
            )
            .expect("the interleaved phase commitment initializes");
        while let Some(lane_ordinal) = builder.active_lane_ordinal() {
            for (row_index, witness) in witnesses.iter().enumerate() {
                let mut base_witness = Vec::new();
                base_witness
                    .try_reserve_exact(geometry.padded_coefficient_count.max(lane_column_count))
                    .expect("the focused phase row allocation succeeds");
                base_witness.extend(witness.iter().map(|value| {
                    ProofBaseFieldElement::from_reduced(u128::from(value.as_canonical_u64()))
                }));
                let coefficients = padded_base_row_coefficients(
                    geometry,
                    row_index,
                    Zeroizing::new(base_witness),
                    RowCodeHighHalfSource::PrivateMaskSeed(&row_pad_seed),
                )
                .expect("the bounded phase coefficients derive");
                let mut transform = BoundedBaseCosetLaneDft::new(
                    coefficients,
                    full_domain,
                    lane_column_count,
                    lane_ordinal,
                )
                .expect("the bounded phase lane initializes");
                while !transform.poll().expect("the bounded phase lane advances") {}
                builder
                    .absorb_active_lane_base_row(
                        row_index,
                        &transform
                            .into_values()
                            .expect("the bounded phase lane completes"),
                    )
                    .expect("the bounded phase lane absorbs");
            }
            builder
                .complete_active_lane()
                .expect("the interleaved phase lane completes");
        }
        assert_eq!(
            builder
                .finish_commitment()
                .expect("the interleaved phase commitment completes"),
            expected,
        );
    }
}
