//! Aggregate-wide zero-knowledge masking for the explicit-point row-code opening.
//!
//! One uniformly sampled pad is committed before the first claim-dependent
//! challenge. Sumcheck masks occupy a fixed rank-optimal complement of the
//! accepting-transcript kernel, and every code-switch mask occupies a disjoint
//! slice of the same pad. A challenge-dependent code-switch contributes only
//! the scalar linear image consumed by verification; the pad itself is never
//! published or recomputed from public data.

use core::ops::Range;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_field::{Field, HornerIter, PrimeCharacteristicRing, dot_product};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch,
    constraints::Constraint,
    layout::PrefixInitialSumcheckProver,
    strategy::{SumcheckProver, VariableOrder},
    zk::ZkSumcheckData,
};
use p3_whir::{
    BaseCaseFreshMaskGroup, BaseCaseFreshMaterial, BaseCaseZkProof, MaskCodeShape, MaskProverData,
    QueryOpening,
};

use super::aggregate_wide_pcs::AggregateWideCommitment;
use super::hiding_whir::SelectedHidingWhirConfig;
use super::{ChallengeField, CommitmentScheme, ExtensionFieldChallenger};
use crate::bgv::proof_suite::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    prover::{CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource},
};

/// Selected pad-code expansion for the fixed precommitted masking subspace.
///
/// The message and its query-hiding randomness occupy fewer than half of the
/// 4,096-point code. The resulting relative distance and the unchanged 393
/// spot checks are bound into the complete soundness certificate.
pub(super) const FIXED_SUBSPACE_PAD_LOG_INVERSE_RATE: usize = 1;

/// One logical mask inside a fixed sumcheck-transcript complement.
///
/// Every mask except the final mask omits its constant coefficient. The only
/// kernel of the complete sumcheck transcript consists of constant shifts whose
/// sum is zero, so this fixed complement intersects that kernel only at zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FixedSubspaceSumcheckMaskLayout {
    coefficient_range: Range<usize>,
    includes_constant_coefficient: bool,
}

impl FixedSubspaceSumcheckMaskLayout {
    fn expanded_coefficient_count(&self) -> usize {
        self.coefficient_range.len() + usize::from(!self.includes_constant_coefficient)
    }
}

/// One logical masked-sumcheck batch in the fixed precommitted subspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateWideSumcheckBatchLayout {
    masks: Vec<FixedSubspaceSumcheckMaskLayout>,
}

impl AggregateWideSumcheckBatchLayout {
    #[cfg(test)]
    pub(super) fn masks(&self) -> &[FixedSubspaceSumcheckMaskLayout] {
        &self.masks
    }
}

/// Disjoint chronological partition of the aggregate-wide pad message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateWidePadLayout {
    sumcheck_batches: Vec<AggregateWideSumcheckBatchLayout>,
    switch_mask_ranges: Vec<Range<usize>>,
    message_length: usize,
}

impl AggregateWidePadLayout {
    pub(super) fn derive(configuration: &SelectedHidingWhirConfig) -> Result<Self, String> {
        let round_count = configuration.n_rounds();
        let mut sumcheck_batches = Vec::with_capacity(round_count + 1);
        let mut switch_mask_ranges = Vec::with_capacity(round_count);
        let mut next_offset = 0_usize;

        for batch_ordinal in 0..=round_count {
            let folding_factor = configuration.round_folding_factor(batch_ordinal);
            let mut masks = Vec::with_capacity(folding_factor);
            for mask_ordinal in 0..folding_factor {
                let includes_constant_coefficient = mask_ordinal + 1 == folding_factor;
                let committed_coefficient_count = configuration
                    .sumcheck_mask
                    .message_len
                    .checked_sub(usize::from(!includes_constant_coefficient))
                    .filter(|count| *count > 0)
                    .ok_or_else(|| {
                        "fixed-subspace sumcheck mask has no committed coefficient".to_owned()
                    })?;
                let end = next_offset
                    .checked_add(committed_coefficient_count)
                    .ok_or_else(|| "aggregate-wide sumcheck-mask layout overflowed".to_owned())?;
                masks.push(FixedSubspaceSumcheckMaskLayout {
                    coefficient_range: next_offset..end,
                    includes_constant_coefficient,
                });
                next_offset = end;
            }
            sumcheck_batches.push(AggregateWideSumcheckBatchLayout { masks });

            if batch_ordinal < round_count {
                let end = next_offset
                    .checked_add(configuration.switch_masks[batch_ordinal].message_len)
                    .ok_or_else(|| "aggregate-wide switch-mask layout overflowed".to_owned())?;
                switch_mask_ranges.push(next_offset..end);
                next_offset = end;
            }
        }

        let layout = Self {
            sumcheck_batches,
            switch_mask_ranges,
            message_length: next_offset,
        };
        layout.validate(configuration)?;
        Ok(layout)
    }

    fn validate(&self, configuration: &SelectedHidingWhirConfig) -> Result<(), String> {
        if self.sumcheck_batches.len() != configuration.n_rounds() + 1
            || self.switch_mask_ranges.len() != configuration.n_rounds()
            || self.message_length == 0
        {
            return Err("aggregate-wide pad layout has the wrong group count".to_owned());
        }
        let mut expected_start = 0_usize;
        for batch_ordinal in 0..self.sumcheck_batches.len() {
            let batch = &self.sumcheck_batches[batch_ordinal];
            if batch.masks.len() != configuration.round_folding_factor(batch_ordinal) {
                return Err("aggregate-wide pad layout has the wrong sumcheck width".to_owned());
            }
            for (mask_ordinal, mask) in batch.masks.iter().enumerate() {
                let must_include_constant = mask_ordinal + 1 == batch.masks.len();
                let expected_committed_coefficient_count = configuration
                    .sumcheck_mask
                    .message_len
                    .checked_sub(usize::from(!must_include_constant))
                    .ok_or_else(|| {
                        "fixed-subspace sumcheck mask coefficient count underflowed".to_owned()
                    })?;
                if mask.coefficient_range.start != expected_start
                    || mask.coefficient_range.len() != expected_committed_coefficient_count
                    || mask.includes_constant_coefficient != must_include_constant
                    || mask.expanded_coefficient_count() != configuration.sumcheck_mask.message_len
                {
                    return Err(
                        "fixed-subspace sumcheck slices overlap, leave a gap, or use the wrong complement"
                            .to_owned(),
                    );
                }
                expected_start = mask.coefficient_range.end;
            }
            if let Some(range) = self.switch_mask_ranges.get(batch_ordinal) {
                if range.start != expected_start
                    || range.len() != configuration.switch_masks[batch_ordinal].message_len
                {
                    return Err(
                        "aggregate-wide pad switch slices overlap or leave a gap".to_owned()
                    );
                }
                expected_start = range.end;
            }
        }
        if expected_start != self.message_length {
            return Err("aggregate-wide pad layout does not cover its message".to_owned());
        }
        Ok(())
    }

    pub(super) fn message_length(&self) -> usize {
        self.message_length
    }

    pub(super) fn sumcheck_batch(
        &self,
        batch_ordinal: usize,
    ) -> Result<&AggregateWideSumcheckBatchLayout, String> {
        self.sumcheck_batches
            .get(batch_ordinal)
            .ok_or_else(|| "aggregate-wide sumcheck batch is outside the pad layout".to_owned())
    }

    pub(super) fn switch_mask_range(&self, round_ordinal: usize) -> Result<Range<usize>, String> {
        self.switch_mask_ranges
            .get(round_ordinal)
            .cloned()
            .ok_or_else(|| "aggregate-wide switch mask is outside the pad layout".to_owned())
    }

    #[cfg(test)]
    pub(super) fn switch_delta_count(&self) -> usize {
        self.switch_mask_ranges.iter().map(Range::len).sum()
    }

    pub(super) fn sumcheck_masks(
        &self,
        batch_ordinal: usize,
        pad_message: &[ChallengeField],
    ) -> Result<Vec<Vec<ChallengeField>>, String> {
        if pad_message.len() != self.message_length {
            return Err("aggregate-wide pad message has the wrong length".to_owned());
        }
        Ok(self
            .sumcheck_batch(batch_ordinal)?
            .masks
            .iter()
            .map(|mask| {
                let committed = &pad_message[mask.coefficient_range.clone()];
                if mask.includes_constant_coefficient {
                    committed.to_vec()
                } else {
                    let mut expanded = Vec::with_capacity(committed.len() + 1);
                    expanded.push(ChallengeField::ZERO);
                    expanded.extend_from_slice(committed);
                    expanded
                }
            })
            .collect())
    }
}

/// Exact private-material geometry for the aggregate-wide hiding argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateWideHidingMaterialShape {
    pad_message_length: usize,
    pad_randomness_length: usize,
    oracle_randomness_lengths: Vec<usize>,
    fresh_source_message_length: usize,
    fresh_source_randomness_length: usize,
    total_extension_element_count: usize,
}

impl AggregateWideHidingMaterialShape {
    pub(super) fn derive(configuration: &SelectedHidingWhirConfig) -> Result<Self, String> {
        let pad_layout = AggregateWidePadLayout::derive(configuration)?;
        let pad_message_length = pad_layout.message_length();
        let pad_randomness_length = configuration.sumcheck_mask.randomness_len;
        let oracle_randomness_lengths = (0..=configuration.n_rounds())
            .map(|oracle_ordinal| {
                configuration.oracle_randomness[oracle_ordinal]
                    .checked_shl(
                        u32::try_from(configuration.round_folding_factor(oracle_ordinal)).map_err(
                            |_| "aggregate-wide oracle folding factor exceeds u32".to_owned(),
                        )?,
                    )
                    .ok_or_else(|| "aggregate-wide oracle randomness length overflowed".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let final_round = configuration.final_round_config();
        let fresh_source_message_length = 1_usize
            .checked_shl(
                u32::try_from(final_round.num_variables)
                    .map_err(|_| "aggregate-wide final variable count exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "aggregate-wide final message length overflowed".to_owned())?;
        let fresh_source_randomness_length =
            configuration.oracle_randomness[configuration.n_rounds()];
        let mut total_extension_element_count = pad_message_length
            .checked_add(pad_randomness_length)
            .ok_or_else(|| "aggregate-wide private-material count overflowed".to_owned())?;
        for count in &oracle_randomness_lengths {
            total_extension_element_count = total_extension_element_count
                .checked_add(*count)
                .ok_or_else(|| "aggregate-wide private-material count overflowed".to_owned())?;
        }
        total_extension_element_count = total_extension_element_count
            .checked_add(fresh_source_message_length)
            .and_then(|count| count.checked_add(fresh_source_randomness_length))
            .and_then(|count| count.checked_add(pad_message_length))
            .and_then(|count| count.checked_add(pad_randomness_length))
            .ok_or_else(|| "aggregate-wide private-material count overflowed".to_owned())?;
        Ok(Self {
            pad_message_length,
            pad_randomness_length,
            oracle_randomness_lengths,
            fresh_source_message_length,
            fresh_source_randomness_length,
            total_extension_element_count,
        })
    }

    pub(super) const fn total_extension_element_count(&self) -> usize {
        self.total_extension_element_count
    }

    #[cfg(test)]
    pub(super) fn pad_shape(&self) -> MaskCodeShape {
        MaskCodeShape::new(
            self.pad_message_length,
            self.pad_randomness_length,
            FIXED_SUBSPACE_PAD_LOG_INVERSE_RATE,
        )
    }
}

/// The paper result or exact implementation invariant that discharges one
/// aggregate-wide masking obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
enum AggregateWideMaskingAuthority {
    CfwConstructionSixThreeAndLemmaSixFour,
    CfwConstructionSevenTwoAndLemmaSevenThree,
    CfwPropositionThreeNineteen,
    CfwLemmaThreeTwentySix,
    CheckedDisjointPadLayout,
    CheckedAffineSwitchIdentity,
    CheckedPrivateCoinPartition,
    CheckedPrecommitmentChronology,
}

/// One query-private Reed--Solomon code used by the aggregate-wide argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
struct AggregateWideQueryPrivateCodeRow {
    message_length: usize,
    randomness_length: usize,
    domain_size: usize,
    maximum_distinct_query_count: usize,
    interleaving_width: usize,
}

#[cfg(test)]
impl AggregateWideQueryPrivateCodeRow {
    fn validate(self) -> Result<(), String> {
        if self.message_length == 0
            || self.randomness_length == 0
            || self.domain_size == 0
            || !self.domain_size.is_power_of_two()
            || self.maximum_distinct_query_count == 0
            || self.randomness_length < self.maximum_distinct_query_count
            || self
                .message_length
                .checked_add(self.randomness_length)
                .is_none_or(|coefficient_count| coefficient_count > self.domain_size)
            || self.interleaving_width == 0
            || !self.interleaving_width.is_power_of_two()
        {
            return Err("aggregate-wide query-private code has invalid geometry".to_owned());
        }
        Ok(())
    }
}

/// One disjoint interval in the attempt-private hiding-argument coin stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(test)]
enum AggregateWidePrivateMaterialRole {
    PadMessage,
    PadEncodingRandomness,
    OracleRandomness { epoch_ordinal: u32 },
    FreshSourceMessage,
    FreshSourceEncodingRandomness,
    FreshPadMessage,
    FreshPadEncodingRandomness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
struct AggregateWidePrivateMaterialPartitionRow {
    role: AggregateWidePrivateMaterialRole,
    range: Range<usize>,
}

/// Executable construction-level masking certificate for the selected
/// aggregate-wide opening.
///
/// The certificate is deliberately narrower than a family zero-knowledge
/// theorem. It proves the generic masking step used by the common polynomial
/// commitment argument:
///
/// - Construction 6.3 masks each sumcheck through a unique precommitted slice;
/// - every code switch publishes `logical mask - pad slice`, so the verifier's
///   `pad slice + delta` is exactly the original logical mask;
/// - Construction 7.2 checks the terminal source and the one aggregate pad;
/// - Proposition 3.19 hides every queried Reed--Solomon code because the
///   randomness dimension covers the complete distinct-query vector; and
/// - Lemma 3.26 preserves that randomized encoding under every interleaved
///   fold.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct AggregateWideMaskingCertificate {
    pad_layout: AggregateWidePadLayout,
    sumcheck_batch_count: usize,
    sumcheck_mask_count: usize,
    logical_sumcheck_mask_coefficient_count: usize,
    fixed_subspace_sumcheck_coordinate_count: usize,
    switch_mask_count: usize,
    switch_mask_coefficient_count: usize,
    pad_code: AggregateWideQueryPrivateCodeRow,
    folded_source_codes: Vec<AggregateWideQueryPrivateCodeRow>,
    fresh_source_code: AggregateWideQueryPrivateCodeRow,
    fresh_pad_code: AggregateWideQueryPrivateCodeRow,
    private_material_partition: Vec<AggregateWidePrivateMaterialPartitionRow>,
    private_extension_element_count: usize,
    base_case_mask_group_count: usize,
    switch_delta_logical_coefficient: i8,
    switch_delta_pad_coefficient: i8,
    verifier_pad_coefficient: i8,
    pad_commitment_precedes_claim_dependent_challenges: bool,
    authorities: Vec<AggregateWideMaskingAuthority>,
}

#[cfg(test)]
impl AggregateWideMaskingCertificate {
    pub(super) fn derive(configuration: &SelectedHidingWhirConfig) -> Result<Self, String> {
        if PROOF_BASE_FIELD_MODULUS % 2 == 0 {
            return Err("aggregate-wide masked sumcheck requires odd characteristic".to_owned());
        }

        let pad_layout = AggregateWidePadLayout::derive(configuration)?;
        let material_shape = AggregateWideHidingMaterialShape::derive(configuration)?;
        let pad_shape = material_shape.pad_shape();
        let sumcheck_batch_count = pad_layout.sumcheck_batches.len();
        let sumcheck_mask_count = pad_layout
            .sumcheck_batches
            .iter()
            .map(|batch| batch.masks.len())
            .sum::<usize>();
        let logical_sumcheck_mask_coefficient_count = pad_layout
            .sumcheck_batches
            .iter()
            .flat_map(|batch| &batch.masks)
            .map(FixedSubspaceSumcheckMaskLayout::expanded_coefficient_count)
            .sum::<usize>();
        let fixed_subspace_sumcheck_coordinate_count = pad_layout
            .sumcheck_batches
            .iter()
            .flat_map(|batch| &batch.masks)
            .map(|mask| mask.coefficient_range.len())
            .sum::<usize>();
        let switch_mask_count = pad_layout.switch_mask_ranges.len();
        let switch_mask_coefficient_count = pad_layout.switch_delta_count();

        let pad_code = AggregateWideQueryPrivateCodeRow {
            message_length: pad_shape.message_len,
            randomness_length: pad_shape.randomness_len,
            domain_size: pad_shape.domain_size,
            maximum_distinct_query_count: configuration.mask_queries,
            interleaving_width: 1,
        };

        let mut folded_source_codes = Vec::with_capacity(configuration.n_rounds() + 1);
        let mut remaining_variable_count = configuration.num_variables;
        for epoch_ordinal in 0..=configuration.n_rounds() {
            let folding_factor = configuration.round_folding_factor(epoch_ordinal);
            remaining_variable_count = remaining_variable_count
                .checked_sub(folding_factor)
                .ok_or_else(|| "aggregate-wide fold schedule exceeds its variables".to_owned())?;
            let message_length =
                1_usize
                    .checked_shl(u32::try_from(remaining_variable_count).map_err(|_| {
                        "aggregate-wide folded variable count exceeds u32".to_owned()
                    })?)
                    .ok_or_else(|| "aggregate-wide folded message length overflowed".to_owned())?;
            let (domain_size, query_count) = if epoch_ordinal < configuration.n_rounds() {
                let round = &configuration.round_parameters[epoch_ordinal];
                (
                    round
                        .domain_size
                        .checked_shr(
                            u32::try_from(folding_factor).map_err(|_| {
                                "aggregate-wide folding factor exceeds u32".to_owned()
                            })?,
                        )
                        .filter(|domain_size| *domain_size > 0)
                        .ok_or_else(|| "aggregate-wide folded source domain is empty".to_owned())?,
                    round.num_queries,
                )
            } else {
                let final_round = configuration.final_round_config();
                (
                    final_round
                        .domain_size
                        .checked_shr(u32::try_from(folding_factor).map_err(|_| {
                            "aggregate-wide final folding factor exceeds u32".to_owned()
                        })?)
                        .filter(|domain_size| *domain_size > 0)
                        .ok_or_else(|| {
                            "aggregate-wide final folded source domain is empty".to_owned()
                        })?,
                    configuration.final_queries,
                )
            };
            let randomness_length = configuration.oracle_randomness[epoch_ordinal];
            let expected_raw_randomness_length = randomness_length
                .checked_shl(
                    u32::try_from(folding_factor)
                        .map_err(|_| "aggregate-wide folding factor exceeds u32".to_owned())?,
                )
                .ok_or_else(|| "aggregate-wide raw randomness length overflowed".to_owned())?;
            if material_shape.oracle_randomness_lengths[epoch_ordinal]
                != expected_raw_randomness_length
                || randomness_length != query_count
            {
                return Err(
                    "aggregate-wide folded source randomness does not match its query epoch"
                        .to_owned(),
                );
            }
            folded_source_codes.push(AggregateWideQueryPrivateCodeRow {
                message_length,
                randomness_length,
                domain_size,
                maximum_distinct_query_count: query_count,
                interleaving_width: 1_usize
                    .checked_shl(
                        u32::try_from(folding_factor)
                            .map_err(|_| "aggregate-wide folding factor exceeds u32".to_owned())?,
                    )
                    .ok_or_else(|| "aggregate-wide interleaving width overflowed".to_owned())?,
            });
        }

        let fresh_source_code = *folded_source_codes
            .last()
            .ok_or_else(|| "aggregate-wide source-code schedule is empty".to_owned())?;
        if fresh_source_code.message_length != material_shape.fresh_source_message_length
            || fresh_source_code.randomness_length != material_shape.fresh_source_randomness_length
        {
            return Err("aggregate-wide fresh source material has the wrong shape".to_owned());
        }
        let fresh_pad_code = pad_code;

        let mut private_material_partition = Vec::with_capacity(
            material_shape
                .oracle_randomness_lengths
                .len()
                .checked_add(6)
                .ok_or_else(|| "aggregate-wide private partition count overflowed".to_owned())?,
        );
        let mut next_private_offset = 0_usize;
        let mut push_private_partition =
            |role: AggregateWidePrivateMaterialRole, length: usize| -> Result<(), String> {
                let end = next_private_offset
                    .checked_add(length)
                    .ok_or_else(|| "aggregate-wide private partition overflowed".to_owned())?;
                private_material_partition.push(AggregateWidePrivateMaterialPartitionRow {
                    role,
                    range: next_private_offset..end,
                });
                next_private_offset = end;
                Ok(())
            };
        push_private_partition(
            AggregateWidePrivateMaterialRole::PadMessage,
            material_shape.pad_message_length,
        )?;
        push_private_partition(
            AggregateWidePrivateMaterialRole::PadEncodingRandomness,
            material_shape.pad_randomness_length,
        )?;
        for (epoch_index, randomness_length) in material_shape
            .oracle_randomness_lengths
            .iter()
            .copied()
            .enumerate()
        {
            push_private_partition(
                AggregateWidePrivateMaterialRole::OracleRandomness {
                    epoch_ordinal: u32::try_from(epoch_index)
                        .map_err(|_| "aggregate-wide epoch ordinal exceeds u32".to_owned())?,
                },
                randomness_length,
            )?;
        }
        push_private_partition(
            AggregateWidePrivateMaterialRole::FreshSourceMessage,
            material_shape.fresh_source_message_length,
        )?;
        push_private_partition(
            AggregateWidePrivateMaterialRole::FreshSourceEncodingRandomness,
            material_shape.fresh_source_randomness_length,
        )?;
        push_private_partition(
            AggregateWidePrivateMaterialRole::FreshPadMessage,
            material_shape.pad_message_length,
        )?;
        push_private_partition(
            AggregateWidePrivateMaterialRole::FreshPadEncodingRandomness,
            material_shape.pad_randomness_length,
        )?;

        let certificate = Self {
            pad_layout,
            sumcheck_batch_count,
            sumcheck_mask_count,
            logical_sumcheck_mask_coefficient_count,
            fixed_subspace_sumcheck_coordinate_count,
            switch_mask_count,
            switch_mask_coefficient_count,
            pad_code,
            folded_source_codes,
            fresh_source_code,
            fresh_pad_code,
            private_material_partition,
            private_extension_element_count: next_private_offset,
            base_case_mask_group_count: 1,
            switch_delta_logical_coefficient: 1,
            switch_delta_pad_coefficient: -1,
            verifier_pad_coefficient: 1,
            pad_commitment_precedes_claim_dependent_challenges: true,
            authorities: vec![
                AggregateWideMaskingAuthority::CfwConstructionSixThreeAndLemmaSixFour,
                AggregateWideMaskingAuthority::CfwConstructionSevenTwoAndLemmaSevenThree,
                AggregateWideMaskingAuthority::CfwPropositionThreeNineteen,
                AggregateWideMaskingAuthority::CfwLemmaThreeTwentySix,
                AggregateWideMaskingAuthority::CheckedDisjointPadLayout,
                AggregateWideMaskingAuthority::CheckedAffineSwitchIdentity,
                AggregateWideMaskingAuthority::CheckedPrivateCoinPartition,
                AggregateWideMaskingAuthority::CheckedPrecommitmentChronology,
            ],
        };
        certificate.validate(configuration, &material_shape)?;
        Ok(certificate)
    }

    /// Returns the exact occupied coefficient geometry of one source code
    /// after its interleaved fold batch. Coefficients after the message and
    /// private encoding randomness are fixed to zero, so they are not part of
    /// the Reed--Solomon image dimension used by the soundness theorem.
    pub(super) fn folded_source_code_geometry(
        &self,
        epoch_ordinal: usize,
    ) -> Option<(usize, usize, usize, usize, usize)> {
        self.folded_source_codes.get(epoch_ordinal).map(|code| {
            (
                code.message_length,
                code.randomness_length,
                code.domain_size,
                code.maximum_distinct_query_count,
                code.interleaving_width,
            )
        })
    }

    /// Returns the exact occupied coefficient geometry of the one
    /// aggregate-wide pad code used by the CFW base check.
    pub(super) const fn pad_code_geometry(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.pad_code.message_length,
            self.pad_code.randomness_length,
            self.pad_code.domain_size,
            self.pad_code.maximum_distinct_query_count,
            self.pad_code.interleaving_width,
        )
    }

    fn validate(
        &self,
        configuration: &SelectedHidingWhirConfig,
        material_shape: &AggregateWideHidingMaterialShape,
    ) -> Result<(), String> {
        self.pad_layout.validate(configuration)?;
        self.pad_code.validate()?;
        self.fresh_source_code.validate()?;
        self.fresh_pad_code.validate()?;
        for code in &self.folded_source_codes {
            code.validate()?;
        }

        let expected_sumcheck_mask_count =
            (0..=configuration.n_rounds()).try_fold(0_usize, |count, batch_ordinal| {
                count
                    .checked_add(configuration.round_folding_factor(batch_ordinal))
                    .ok_or_else(|| "aggregate-wide sumcheck-mask count overflowed".to_owned())
            })?;
        if self.sumcheck_batch_count != configuration.n_rounds() + 1
            || self.sumcheck_mask_count != expected_sumcheck_mask_count
            || self.logical_sumcheck_mask_coefficient_count
                != expected_sumcheck_mask_count
                    .checked_mul(configuration.sumcheck_mask.message_len)
                    .ok_or_else(|| {
                        "aggregate-wide sumcheck coefficient count overflowed".to_owned()
                    })?
            || configuration.sumcheck_mask.message_len < 3
            || self.switch_mask_count != configuration.n_rounds()
            || self.switch_mask_coefficient_count
                != configuration
                    .switch_masks
                    .iter()
                    .map(|shape| shape.message_len)
                    .sum::<usize>()
            || self.fixed_subspace_sumcheck_coordinate_count
                != (0..=configuration.n_rounds()).try_fold(0_usize, |count, batch_ordinal| {
                    let folding_factor = configuration.round_folding_factor(batch_ordinal);
                    folding_factor
                        .checked_mul(configuration.sumcheck_mask.message_len)
                        .and_then(|full_count| {
                            full_count.checked_sub(folding_factor.saturating_sub(1))
                        })
                        .and_then(|batch_count| count.checked_add(batch_count))
                        .ok_or_else(|| "fixed-subspace sumcheck dimension overflowed".to_owned())
                })?
            || self
                .fixed_subspace_sumcheck_coordinate_count
                .checked_add(self.switch_mask_coefficient_count)
                != Some(self.pad_layout.message_length())
            || self.pad_code.message_length != self.pad_layout.message_length()
            || self.pad_code.randomness_length != configuration.mask_queries
            || self.pad_code.domain_size != material_shape.pad_shape().domain_size
            || self.fresh_pad_code != self.pad_code
            || self.folded_source_codes.len() != configuration.n_rounds() + 1
            || self.base_case_mask_group_count != 1
            || self.switch_delta_logical_coefficient != 1
            || self.switch_delta_pad_coefficient != -1
            || self.verifier_pad_coefficient != 1
            || self.switch_delta_pad_coefficient + self.verifier_pad_coefficient != 0
            || !self.pad_commitment_precedes_claim_dependent_challenges
            || self.authorities
                != [
                    AggregateWideMaskingAuthority::CfwConstructionSixThreeAndLemmaSixFour,
                    AggregateWideMaskingAuthority::CfwConstructionSevenTwoAndLemmaSevenThree,
                    AggregateWideMaskingAuthority::CfwPropositionThreeNineteen,
                    AggregateWideMaskingAuthority::CfwLemmaThreeTwentySix,
                    AggregateWideMaskingAuthority::CheckedDisjointPadLayout,
                    AggregateWideMaskingAuthority::CheckedAffineSwitchIdentity,
                    AggregateWideMaskingAuthority::CheckedPrivateCoinPartition,
                    AggregateWideMaskingAuthority::CheckedPrecommitmentChronology,
                ]
        {
            return Err("aggregate-wide masking certificate is incomplete".to_owned());
        }

        let mut expected_private_start = 0_usize;
        let mut private_roles = std::collections::BTreeSet::new();
        for row in &self.private_material_partition {
            if row.range.start != expected_private_start
                || row.range.is_empty()
                || !private_roles.insert(row.role)
            {
                return Err(
                    "aggregate-wide private material overlaps, leaves a gap, or reuses a role"
                        .to_owned(),
                );
            }
            expected_private_start = row.range.end;
        }
        if expected_private_start != self.private_extension_element_count
            || self.private_extension_element_count
                != material_shape.total_extension_element_count()
            || self.private_material_partition.len()
                != material_shape.oracle_randomness_lengths.len() + 6
        {
            return Err("aggregate-wide private material partition is incomplete".to_owned());
        }

        for (round_ordinal, switch_range) in self.pad_layout.switch_mask_ranges.iter().enumerate() {
            let expected_length = configuration.oracle_randomness[round_ordinal]
                .checked_add(configuration.round_parameters[round_ordinal].ood_samples)
                .ok_or_else(|| "aggregate-wide switch-mask length overflowed".to_owned())?;
            if switch_range.len() != expected_length {
                return Err("aggregate-wide switch-mask slice has the wrong length".to_owned());
            }
        }
        Ok(())
    }

    pub(super) fn is_complete(&self) -> bool {
        self.authorities.len() == 8
            && self.base_case_mask_group_count == 1
            && self.private_extension_element_count > 0
            && self.sumcheck_mask_count > 0
            && self.switch_mask_count > 0
            && self.pad_commitment_precedes_claim_dependent_challenges
    }

    pub(super) const fn private_extension_element_count(&self) -> usize {
        self.private_extension_element_count
    }

    pub(super) const fn pad_message_length(&self) -> usize {
        self.pad_code.message_length
    }

    pub(super) const fn pad_randomness_length(&self) -> usize {
        self.pad_code.randomness_length
    }

    pub(super) const fn pad_domain_size(&self) -> usize {
        self.pad_code.domain_size
    }
}

/// Secret values used exactly once by one aggregate-wide hiding proof.
pub(super) struct AggregateWideHidingMaterial {
    pub(super) pad_message: Vec<ChallengeField>,
    pub(super) pad_randomness: Vec<ChallengeField>,
    pub(super) oracle_randomness: Vec<Vec<ChallengeField>>,
    pub(super) base_case_fresh_material: BaseCaseFreshMaterial<ChallengeField>,
}

type AggregateWideQueryOpening =
    QueryOpening<ChallengeField, ChallengeField, <CommitmentScheme as Mmcs<ChallengeField>>::Proof>;
type AggregateWideBaseCaseProof = BaseCaseZkProof<ChallengeField, ChallengeField, CommitmentScheme>;
type AggregateWidePadProverData = MaskProverData<ChallengeField, ChallengeField, CommitmentScheme>;

/// One committed aggregate-wide pad retained through the masked base case.
pub(super) struct AggregateWideCommittedPad {
    commitment: AggregateWideCommitment,
    message: Vec<ChallengeField>,
    randomness: Vec<ChallengeField>,
    prover_data: AggregateWidePadProverData,
}

impl AggregateWideCommittedPad {
    pub(super) fn commit(
        extension_mmcs: &ExtensionMmcs<ChallengeField, ChallengeField, CommitmentScheme>,
        shape: MaskCodeShape,
        message: Vec<ChallengeField>,
        randomness: Vec<ChallengeField>,
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<Self, String> {
        if message.len() != shape.message_len || randomness.len() != shape.randomness_len {
            return Err("aggregate-wide pad material has the wrong shape".to_owned());
        }
        let codeword = shape.encode_with_randomness(&message, &randomness);
        let (commitment, prover_data) = extension_mmcs.commit_matrix(codeword);
        challenger.observe(commitment.clone());
        Ok(Self {
            commitment,
            message,
            randomness,
            prover_data,
        })
    }

    pub(super) fn commitment(&self) -> &AggregateWideCommitment {
        &self.commitment
    }

    pub(super) fn message(&self) -> &[ChallengeField] {
        &self.message
    }

    pub(super) fn message_vector(&self) -> &Vec<ChallengeField> {
        &self.message
    }

    pub(super) fn randomness_vector(&self) -> &Vec<ChallengeField> {
        &self.randomness
    }

    pub(super) fn prover_data(&self) -> &AggregateWidePadProverData {
        &self.prover_data
    }
}

/// One code-switch round in the aggregate-wide hiding opening.
#[derive(Clone)]
pub(super) struct AggregateWideRoundProof {
    pub(super) commitment: AggregateWideCommitment,
    pub(super) switch_mask_offset: ChallengeField,
    pub(super) proof_of_work_witness: ChallengeField,
    pub(super) queries: Vec<AggregateWideQueryOpening>,
}

/// Complete theorem-backed aggregate opening before canonical path compaction.
#[derive(Clone)]
pub(super) struct AggregateWideOpeningProof {
    pub(super) pad_commitment: AggregateWideCommitment,
    pub(super) evaluations: Vec<OpeningBatch<ChallengeField>>,
    pub(super) sumchecks: Vec<ZkSumcheckData<ChallengeField, ChallengeField>>,
    pub(super) rounds: Vec<AggregateWideRoundProof>,
    pub(super) base_case: AggregateWideBaseCaseProof,
    query_index_schedule: Vec<Vec<usize>>,
}

impl AggregateWideOpeningProof {
    pub(super) fn new(
        pad_commitment: AggregateWideCommitment,
        evaluations: Vec<OpeningBatch<ChallengeField>>,
        sumchecks: Vec<ZkSumcheckData<ChallengeField, ChallengeField>>,
        rounds: Vec<AggregateWideRoundProof>,
        base_case: AggregateWideBaseCaseProof,
        query_index_schedule: Vec<Vec<usize>>,
    ) -> Self {
        Self {
            pad_commitment,
            evaluations,
            sumchecks,
            rounds,
            base_case,
            query_index_schedule,
        }
    }

    pub(super) fn query_index_schedule(&self) -> &[Vec<usize>] {
        &self.query_index_schedule
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AggregateWideHidingMaterialGenerationError<CoinError> {
    Geometry(String),
    CoinSource(CoinError),
}

pub(super) enum AggregateWideHidingMaterialGenerationPoll {
    ExtensionElementSampled { completed_count: usize },
    Complete(AggregateWideHidingMaterial),
}

/// Incremental sampler for the one dedicated hiding-argument coin stream.
pub(super) struct AggregateWideHidingMaterialGeneration {
    shape: AggregateWideHidingMaterialShape,
    values: Option<Vec<ChallengeField>>,
}

impl AggregateWideHidingMaterialGeneration {
    pub(super) fn new(configuration: &SelectedHidingWhirConfig) -> Result<Self, String> {
        let shape = AggregateWideHidingMaterialShape::derive(configuration)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(shape.total_extension_element_count())
            .map_err(|_| "aggregate-wide private-material allocation failed".to_owned())?;
        Ok(Self {
            shape,
            values: Some(values),
        })
    }

    pub(super) fn poll<Coins: CommonProofPrivateCoinSource>(
        &mut self,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<
        AggregateWideHidingMaterialGenerationPoll,
        AggregateWideHidingMaterialGenerationError<Coins::Error>,
    > {
        let values = self.values.as_mut().ok_or_else(|| {
            AggregateWideHidingMaterialGenerationError::Geometry(
                "aggregate-wide private material was polled after completion".to_owned(),
            )
        })?;
        if values.len() < self.shape.total_extension_element_count() {
            let mut coordinates = [Goldilocks::ZERO; PROOF_CHALLENGE_EXTENSION_DEGREE];
            for coordinate in &mut coordinates {
                *coordinate = Goldilocks::from_u64(
                    coins
                        .sample_modulo(
                            CommonProofPrivateCoinCoordinate::hiding_argument(),
                            PROOF_BASE_FIELD_MODULUS,
                            maximum_candidate_draws_per_output,
                        )
                        .map_err(AggregateWideHidingMaterialGenerationError::CoinSource)?,
                );
            }
            values.push(ChallengeField::new(coordinates));
            return Ok(
                AggregateWideHidingMaterialGenerationPoll::ExtensionElementSampled {
                    completed_count: values.len(),
                },
            );
        }

        let values = self.values.take().ok_or_else(|| {
            AggregateWideHidingMaterialGenerationError::Geometry(
                "aggregate-wide private material is missing".to_owned(),
            )
        })?;
        let mut values = values.into_iter();
        let mut take_values = |count: usize| values.by_ref().take(count).collect::<Vec<_>>();
        let pad_message = take_values(self.shape.pad_message_length);
        let pad_randomness = take_values(self.shape.pad_randomness_length);
        let oracle_randomness = self
            .shape
            .oracle_randomness_lengths
            .iter()
            .map(|count| take_values(*count))
            .collect();
        let source_message = take_values(self.shape.fresh_source_message_length);
        let source_randomness = take_values(self.shape.fresh_source_randomness_length);
        let fresh_pad_message = take_values(self.shape.pad_message_length);
        let fresh_pad_randomness = take_values(self.shape.pad_randomness_length);
        if values.next().is_some() {
            return Err(AggregateWideHidingMaterialGenerationError::Geometry(
                "aggregate-wide private material has trailing values".to_owned(),
            ));
        }
        Ok(AggregateWideHidingMaterialGenerationPoll::Complete(
            AggregateWideHidingMaterial {
                pad_message,
                pad_randomness,
                oracle_randomness,
                base_case_fresh_material: BaseCaseFreshMaterial {
                    source_message,
                    source_randomness,
                    mask_groups: vec![BaseCaseFreshMaskGroup {
                        messages: vec![fresh_pad_message],
                        randomness: vec![fresh_pad_randomness],
                    }],
                },
            },
        ))
    }
}

/// Running affine claim on the one committed aggregate-wide pad.
///
/// The verifier-visible relation is
///
/// `source claim + <pad, covector> + public_offset = target`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateWidePadClaim {
    covector: Vec<ChallengeField>,
    public_offset: ChallengeField,
}

impl AggregateWidePadClaim {
    pub(super) fn new(message_length: usize) -> Self {
        Self {
            covector: ChallengeField::zero_vec(message_length),
            public_offset: ChallengeField::ZERO,
        }
    }

    pub(super) fn covector_vector(&self) -> &Vec<ChallengeField> {
        &self.covector
    }

    pub(super) fn public_offset(&self) -> ChallengeField {
        self.public_offset
    }

    pub(super) fn evaluate(
        &self,
        pad_message: &[ChallengeField],
    ) -> Result<ChallengeField, String> {
        if pad_message.len() != self.covector.len() {
            return Err("aggregate-wide pad claim has the wrong message length".to_owned());
        }
        Ok(dot_product::<ChallengeField, _, _>(
            pad_message.iter().copied(),
            self.covector.iter().copied(),
        ) + self.public_offset)
    }

    pub(super) fn scale(&mut self, factor: ChallengeField) {
        for coefficient in &mut self.covector {
            *coefficient *= factor;
        }
        self.public_offset *= factor;
    }

    pub(super) fn record_sumcheck_batch(
        &mut self,
        batch_layout: &AggregateWideSumcheckBatchLayout,
        eps: ChallengeField,
        randomness: &Point<ChallengeField>,
    ) -> Result<(), String> {
        if batch_layout.masks.len() != randomness.num_variables() {
            return Err(
                "aggregate-wide sumcheck mask count does not match its challenges".to_owned(),
            );
        }
        let two_to_folding = ChallengeField::TWO.exp_u64(randomness.num_variables() as u64);
        self.scale(eps * two_to_folding.inverse());
        for (mask, gamma) in batch_layout.masks.iter().zip(randomness.iter()) {
            let destination = self
                .covector
                .get_mut(mask.coefficient_range.clone())
                .ok_or_else(|| {
                    "aggregate-wide sumcheck mask range is outside the pad".to_owned()
                })?;
            let mut power = if mask.includes_constant_coefficient {
                ChallengeField::ONE
            } else {
                *gamma
            };
            for coefficient in destination {
                *coefficient += power;
                power *= *gamma;
            }
        }
        Ok(())
    }

    pub(super) fn batch_carried_claim(&mut self, multiplier: ChallengeField) {
        self.scale(multiplier);
    }

    pub(super) fn record_switch_mask_offset(
        &mut self,
        range: Range<usize>,
        logical_mask_covector: &[ChallengeField],
        public_offset: ChallengeField,
    ) -> Result<(), String> {
        if range.len() != logical_mask_covector.len() {
            return Err("aggregate-wide switch mask has inconsistent dimensions".to_owned());
        }
        let destination = self
            .covector
            .get_mut(range)
            .ok_or_else(|| "aggregate-wide switch mask range is outside the pad".to_owned())?;
        for (coefficient, increment) in destination.iter_mut().zip(logical_mask_covector) {
            *coefficient += *increment;
        }
        self.public_offset += public_offset;
        Ok(())
    }
}

enum MaskedPlainState {
    Initial(PrefixInitialSumcheckProver<ChallengeField, ChallengeField>),
    Residual(SumcheckProver<ChallengeField, ChallengeField>),
}

/// One-round-at-a-time masked sumcheck over precommitted pad slices.
pub(super) struct PrecommittedMaskedSumcheck {
    plain_state: Option<MaskedPlainState>,
    masks: Vec<Vec<ChallengeField>>,
    future_endpoint_sum: ChallengeField,
    past_mask_evaluations: Vec<ChallengeField>,
    randomness: Vec<ChallengeField>,
    eps: ChallengeField,
    auxiliary_carry: ChallengeField,
    proof: ZkSumcheckData<ChallengeField, ChallengeField>,
    pow_bits: usize,
}

impl PrecommittedMaskedSumcheck {
    pub(super) fn begin_initial<Challenger>(
        plain_state: PrefixInitialSumcheckProver<ChallengeField, ChallengeField>,
        masks: Vec<Vec<ChallengeField>>,
        pow_bits: usize,
        challenger: &mut Challenger,
    ) -> Result<Self, String>
    where
        Challenger: FieldChallenger<ChallengeField> + GrindingChallenger<Witness = ChallengeField>,
    {
        Self::begin(
            MaskedPlainState::Initial(plain_state),
            masks,
            ChallengeField::ZERO,
            false,
            pow_bits,
            challenger,
        )
    }

    pub(super) fn begin_residual<Challenger>(
        plain_state: SumcheckProver<ChallengeField, ChallengeField>,
        masks: Vec<Vec<ChallengeField>>,
        auxiliary_claim: ChallengeField,
        pow_bits: usize,
        challenger: &mut Challenger,
    ) -> Result<Self, String>
    where
        Challenger: FieldChallenger<ChallengeField> + GrindingChallenger<Witness = ChallengeField>,
    {
        Self::begin(
            MaskedPlainState::Residual(plain_state),
            masks,
            auxiliary_claim,
            true,
            pow_bits,
            challenger,
        )
    }

    fn begin<Challenger>(
        plain_state: MaskedPlainState,
        masks: Vec<Vec<ChallengeField>>,
        auxiliary_claim: ChallengeField,
        bind_scalar_claim: bool,
        pow_bits: usize,
        challenger: &mut Challenger,
    ) -> Result<Self, String>
    where
        Challenger: FieldChallenger<ChallengeField> + GrindingChallenger<Witness = ChallengeField>,
    {
        let folding_factor = masks.len();
        if folding_factor == 0 || masks.iter().any(|mask| mask.len() < 3) {
            return Err("precommitted masked sumcheck has an invalid mask shape".to_owned());
        }
        let plain_variable_count = match &plain_state {
            MaskedPlainState::Initial(state) => state.remaining_round_count(),
            MaskedPlainState::Residual(state) => state.num_variables(),
        };
        if folding_factor > plain_variable_count {
            return Err("precommitted masked sumcheck folds too many variables".to_owned());
        }
        if bind_scalar_claim {
            let source_claim = match &plain_state {
                MaskedPlainState::Initial(_) => unreachable!(),
                MaskedPlainState::Residual(state) => state.claimed_sum(),
            };
            challenger.observe_algebra_element(source_claim + auxiliary_claim);
        }

        let future_endpoint_sum: ChallengeField = masks
            .iter()
            .map(|mask| mask[0].double() + mask[1..].iter().copied().sum::<ChallengeField>())
            .sum();
        let mu_tilde =
            ChallengeField::TWO.exp_u64((folding_factor - 1) as u64) * future_endpoint_sum;
        challenger.observe_algebra_element(mu_tilde);
        let eps = challenger.sample_algebra_element();
        Ok(Self {
            plain_state: Some(plain_state),
            masks,
            future_endpoint_sum,
            past_mask_evaluations: Vec::with_capacity(folding_factor),
            randomness: Vec::with_capacity(folding_factor),
            eps,
            auxiliary_carry: auxiliary_claim,
            proof: ZkSumcheckData {
                mu_tilde,
                ell_zk: 3,
                round_coefficients: Vec::with_capacity(folding_factor),
                pow_witnesses: Vec::with_capacity(if pow_bits == 0 { 0 } else { folding_factor }),
            },
            pow_bits,
        })
    }

    pub(super) fn completed_round_count(&self) -> usize {
        self.randomness.len()
    }

    pub(super) fn randomness(&self) -> Point<ChallengeField> {
        Point::new(self.randomness.clone())
    }

    pub(super) fn advance_round<Challenger>(
        &mut self,
        challenger: &mut Challenger,
    ) -> Result<bool, String>
    where
        Challenger: FieldChallenger<ChallengeField> + GrindingChallenger<Witness = ChallengeField>,
    {
        let round_index = self.completed_round_count();
        if round_index == self.masks.len() {
            return Ok(false);
        }
        let plain_state = self
            .plain_state
            .as_mut()
            .ok_or_else(|| "precommitted masked sumcheck plain state is absent".to_owned())?;
        let (plain_constant, plain_leading) = match plain_state {
            MaskedPlainState::Initial(state) => state.round_coefficients().ok_or_else(|| {
                "initial masked sumcheck ended before its mask schedule".to_owned()
            })?,
            MaskedPlainState::Residual(state) => state.round_coefficients(),
        };

        let mask = &self.masks[round_index];
        let mask_endpoints = mask[0].double() + mask[1..].iter().copied().sum::<ChallengeField>();
        self.future_endpoint_sum -= mask_endpoints;
        self.auxiliary_carry *= ChallengeField::TWO.inverse();

        let one_indexed_round = round_index + 1;
        let live_multiplier =
            ChallengeField::TWO.exp_u64((self.masks.len() - one_indexed_round) as u64);
        let mut full_coefficients = ChallengeField::zero_vec(mask.len().max(3));
        for (coefficient, mask_coefficient) in full_coefficients.iter_mut().zip(mask) {
            *coefficient += live_multiplier * *mask_coefficient;
        }
        full_coefficients[0] += self
            .past_mask_evaluations
            .iter()
            .copied()
            .sum::<ChallengeField>()
            * live_multiplier;
        if one_indexed_round < self.masks.len() {
            full_coefficients[0] += ChallengeField::TWO
                .exp_u64((self.masks.len() - one_indexed_round - 1) as u64)
                * self.future_endpoint_sum;
        }
        full_coefficients[0] += self.eps * (plain_constant + self.auxiliary_carry);
        full_coefficients[2] += self.eps * plain_leading;

        let wire = vec![full_coefficients[0], full_coefficients[2]];
        challenger.observe_algebra_slice(&wire);
        self.proof.round_coefficients.push(wire);
        if self.pow_bits > 0 {
            self.proof
                .pow_witnesses
                .push(challenger.grind(self.pow_bits));
        }
        let gamma = challenger.sample_algebra_element();
        self.past_mask_evaluations
            .push(mask.iter().copied().horner(gamma));
        match plain_state {
            MaskedPlainState::Initial(state) => {
                state.fold_round_with_coefficients(plain_constant, plain_leading, gamma);
            }
            MaskedPlainState::Residual(state) => {
                state.fold_round_with_coefficients(plain_constant, plain_leading, gamma);
            }
        }
        self.randomness.push(gamma);
        Ok(true)
    }

    pub(super) fn finish(self) -> Result<PrecommittedMaskedSumcheckOutput, String> {
        self.finish_with_initial_compressed(None)
    }

    pub(super) fn finish_initial_with_compressed(
        self,
        compressed: Poly<ChallengeField>,
    ) -> Result<PrecommittedMaskedSumcheckOutput, String> {
        self.finish_with_initial_compressed(Some(compressed))
    }

    fn finish_with_initial_compressed(
        mut self,
        compressed: Option<Poly<ChallengeField>>,
    ) -> Result<PrecommittedMaskedSumcheckOutput, String> {
        if self.completed_round_count() != self.masks.len() {
            return Err("precommitted masked sumcheck ended before every round".to_owned());
        }
        let mut residual_prover = match self
            .plain_state
            .take()
            .ok_or_else(|| "precommitted masked sumcheck plain state is absent".to_owned())?
        {
            MaskedPlainState::Initial(state) => match compressed {
                Some(compressed) => {
                    state
                        .try_finish_with_compressed(compressed)
                        .map_err(|_| {
                            "initial masked sumcheck rejected its streamed residual".to_owned()
                        })?
                        .0
                }
                None => {
                    state
                        .try_finish()
                        .map_err(|_| {
                            "initial masked sumcheck retained unfinished rounds".to_owned()
                        })?
                        .0
                }
            },
            MaskedPlainState::Residual(state) => {
                if compressed.is_some() {
                    return Err(
                        "residual masked sumcheck received an initial compression".to_owned()
                    );
                }
                state
            }
        };
        residual_prover.scale_weights_and_claim(self.eps);
        Ok(PrecommittedMaskedSumcheckOutput {
            residual_prover,
            randomness: Point::new(self.randomness),
            eps: self.eps,
            proof: self.proof,
        })
    }
}

pub(super) struct PrecommittedMaskedSumcheckOutput {
    pub(super) residual_prover: SumcheckProver<ChallengeField, ChallengeField>,
    pub(super) randomness: Point<ChallengeField>,
    pub(super) eps: ChallengeField,
    pub(super) proof: ZkSumcheckData<ChallengeField, ChallengeField>,
}

/// One source constraint together with the scale accumulated after it entered
/// the reduction and the first folding challenge that applies to it.
struct ScaledSourceConstraint {
    constraint: Constraint<ChallengeField, ChallengeField>,
    scale: ChallengeField,
    first_randomness_index: usize,
}

/// Symbolic source-covector state used by the aggregate-wide verifier.
pub(super) struct AggregateWideSourceConstraints {
    constraints: Vec<ScaledSourceConstraint>,
    folding_randomness: Vec<ChallengeField>,
}

impl AggregateWideSourceConstraints {
    pub(super) fn new(initial: Constraint<ChallengeField, ChallengeField>) -> Self {
        Self {
            constraints: vec![ScaledSourceConstraint {
                constraint: initial,
                scale: ChallengeField::ONE,
                first_randomness_index: 0,
            }],
            folding_randomness: Vec::new(),
        }
    }

    pub(super) fn batch_constraint(
        &mut self,
        constraint: Constraint<ChallengeField, ChallengeField>,
    ) {
        let carried_multiplier = constraint.carried_claim_multiplier();
        for carried in &mut self.constraints {
            carried.scale *= carried_multiplier;
        }
        self.constraints.push(ScaledSourceConstraint {
            constraint,
            scale: ChallengeField::ONE,
            first_randomness_index: self.folding_randomness.len(),
        });
    }

    pub(super) fn record_masked_sumcheck(
        &mut self,
        eps: ChallengeField,
        randomness: &Point<ChallengeField>,
    ) {
        for constraint in &mut self.constraints {
            constraint.scale *= eps;
        }
        self.folding_randomness.extend(randomness.iter());
    }

    pub(super) fn terminal_covector(
        &self,
        terminal_variable_count: usize,
    ) -> Result<Vec<ChallengeField>, String> {
        let terminal_length = 1_usize
            .checked_shl(
                u32::try_from(terminal_variable_count)
                    .map_err(|_| "terminal source variable count exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "terminal source covector length overflowed".to_owned())?;
        let mut terminal = ChallengeField::zero_vec(terminal_length);
        for scaled in &self.constraints {
            if scaled.constraint.num_variables() < terminal_variable_count {
                return Err(
                    "source constraint has fewer variables than the terminal message".to_owned(),
                );
            }
            let fold_count = scaled.constraint.num_variables() - terminal_variable_count;
            let challenges = self
                .folding_randomness
                .get(scaled.first_randomness_index..scaled.first_randomness_index + fold_count)
                .ok_or_else(|| "source constraint is missing folding challenges".to_owned())?;
            let (mut polynomial, _) = scaled.constraint.combine_new();
            for challenge in challenges {
                VariableOrder::Prefix.fix_var(&mut polynomial, *challenge);
            }
            if polynomial.as_slice().len() != terminal.len() {
                return Err("folded source constraint has the wrong terminal length".to_owned());
            }
            for (destination, coefficient) in terminal.iter_mut().zip(polynomial.as_slice()) {
                *destination += scaled.scale * *coefficient;
            }
        }
        Ok(terminal)
    }
}

pub(super) fn fold_limb_randomness(
    raw_randomness: &[ChallengeField],
    folded_length: usize,
    randomness: &Point<ChallengeField>,
) -> Result<Vec<ChallengeField>, String> {
    let limb_count = 1_usize
        .checked_shl(
            u32::try_from(randomness.num_variables())
                .map_err(|_| "folding variable count exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "folding limb count overflowed".to_owned())?;
    if raw_randomness.len() != limb_count * folded_length {
        return Err("interleaved oracle randomness has the wrong length".to_owned());
    }
    let weights =
        p3_multilinear_util::poly::Poly::new_from_point(randomness.as_slice(), ChallengeField::ONE);
    let mut folded = ChallengeField::zero_vec(folded_length);
    for (limb, weight) in raw_randomness
        .chunks_exact(folded_length)
        .zip(weights.as_slice())
    {
        for (destination, source) in folded.iter_mut().zip(limb) {
            *destination += *weight * *source;
        }
    }
    Ok(folded)
}

pub(super) fn switch_mask_offset(
    layout: &AggregateWidePadLayout,
    round_ordinal: usize,
    source_randomness: &[ChallengeField],
    pad_message: &[ChallengeField],
    logical_mask_covector: &[ChallengeField],
) -> Result<ChallengeField, String> {
    let range = layout.switch_mask_range(round_ordinal)?;
    if source_randomness.len() != range.len()
        || logical_mask_covector.len() != range.len()
        || pad_message.len() != layout.message_length()
    {
        return Err("aggregate-wide switch-mask offset has the wrong shape".to_owned());
    }
    Ok(source_randomness
        .iter()
        .zip(&pad_message[range])
        .zip(logical_mask_covector)
        .map(|((source, pad), coefficient)| (*source - *pad) * *coefficient)
        .sum())
}

#[cfg(test)]
mod tests {
    use p3_challenger::{
        CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger,
    };
    use p3_field::{PrimeCharacteristicRing, dot_product};
    use p3_multilinear_util::poly::Poly;
    use p3_sumcheck::{
        product_polynomial::ProductPolynomial,
        strategy::{SumcheckProver, VariableOrder},
        zk::{ZkVerifier, mask_residual},
    };

    use super::*;
    use crate::bgv::proof_suite::row_code_whir::{
        construction_plan::RowCodeWhirSelectedParameters, hiding_whir::selected_hiding_whir_config,
    };

    #[derive(Default)]
    struct CountingPrivateCoins {
        sample_count: usize,
    }

    impl CommonProofPrivateCoinSource for CountingPrivateCoins {
        type Error = &'static str;

        fn sample_modulo(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            if coordinate != CommonProofPrivateCoinCoordinate::hiding_argument()
                || modulus != PROOF_BASE_FIELD_MODULUS
                || maximum_candidate_draws_per_output == 0
            {
                return Err("unexpected aggregate-wide private-coin request");
            }
            let sample = u64::try_from(self.sample_count)
                .map_err(|_| "aggregate-wide sample ordinal exceeded u64")?
                % modulus;
            self.sample_count += 1;
            Ok(sample)
        }

        fn fill_raw_bytes(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            _destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            Err("aggregate-wide material must not request raw bytes")
        }
    }

    fn selected_layout() -> AggregateWidePadLayout {
        let configuration = selected_hiding_whir_config(RowCodeWhirSelectedParameters::selected())
            .expect("selected hiding configuration");
        AggregateWidePadLayout::derive(&configuration).expect("aggregate-wide pad layout")
    }

    #[derive(Clone, Debug)]
    struct TranscriptTestChallenger {
        state: ChallengeField,
        sample_ordinal: u64,
    }

    impl Default for TranscriptTestChallenger {
        fn default() -> Self {
            Self {
                state: ChallengeField::from_u64(17),
                sample_ordinal: 0,
            }
        }
    }

    impl CanObserve<ChallengeField> for TranscriptTestChallenger {
        fn observe(&mut self, value: ChallengeField) {
            self.state =
                self.state * ChallengeField::from_u64(7) + value + ChallengeField::from_u64(3);
        }
    }

    impl CanSample<ChallengeField> for TranscriptTestChallenger {
        fn sample(&mut self) -> ChallengeField {
            self.sample_ordinal += 1;
            let sampled =
                self.state + ChallengeField::from_u64(13_u64.wrapping_mul(self.sample_ordinal) + 5);
            self.state = self.state * ChallengeField::from_u64(11) + sampled;
            sampled
        }
    }

    impl CanSampleBits<usize> for TranscriptTestChallenger {
        fn sample_bits(&mut self, _bits: usize) -> usize {
            0
        }
    }

    impl FieldChallenger<ChallengeField> for TranscriptTestChallenger {}

    impl GrindingChallenger for TranscriptTestChallenger {
        type Witness = ChallengeField;

        fn grind(&mut self, _bits: usize) -> Self::Witness {
            ChallengeField::ZERO
        }
    }

    #[test]
    fn selected_pad_layout_is_disjoint_and_complete() {
        let layout = selected_layout();
        assert_eq!(layout.message_length(), 1_512);
        assert_eq!(layout.switch_delta_count(), 1_470);

        let mut coverage = vec![0_u8; layout.message_length()];
        for batch in &layout.sumcheck_batches {
            for mask in batch.masks() {
                for coordinate in &mut coverage[mask.coefficient_range.clone()] {
                    *coordinate += 1;
                }
            }
        }
        for range in &layout.switch_mask_ranges {
            for coordinate in &mut coverage[range.clone()] {
                *coordinate += 1;
            }
        }
        assert!(coverage.iter().all(|multiplicity| *multiplicity == 1));
    }

    #[test]
    fn selected_private_material_shape_matches_the_complete_hiding_schedule() {
        let configuration = selected_hiding_whir_config(RowCodeWhirSelectedParameters::selected())
            .expect("selected hiding configuration");
        let shape = AggregateWideHidingMaterialShape::derive(&configuration)
            .expect("aggregate-wide private-material shape");

        assert_eq!(shape.pad_message_length, 1_512);
        assert_eq!(shape.pad_randomness_length, 393);
        assert_eq!(
            shape.oracle_randomness_lengths,
            [3_096, 2_304, 2_144, 2_112, 2_104, 2_104]
        );
        assert_eq!(shape.fresh_source_message_length, 64);
        assert_eq!(shape.fresh_source_randomness_length, 263);
        assert_eq!(shape.total_extension_element_count(), 18_001);
        assert_eq!(shape.pad_shape().message_len, 1_512);
        assert_eq!(shape.pad_shape().randomness_len, 393);
        assert_eq!(shape.pad_shape().domain_size, 4_096);
    }

    #[test]
    fn selected_aggregate_wide_masking_certificate_closes_every_generic_obligation() {
        let configuration = selected_hiding_whir_config(RowCodeWhirSelectedParameters::selected())
            .expect("selected hiding configuration");
        let certificate = AggregateWideMaskingCertificate::derive(&configuration)
            .expect("aggregate-wide masking certificate");

        assert!(certificate.is_complete());
        assert_eq!(certificate.sumcheck_batch_count, 6);
        assert_eq!(certificate.sumcheck_mask_count, 18);
        assert_eq!(certificate.logical_sumcheck_mask_coefficient_count, 54);
        assert_eq!(certificate.fixed_subspace_sumcheck_coordinate_count, 42);
        assert_eq!(certificate.switch_mask_count, 5);
        assert_eq!(certificate.switch_mask_coefficient_count, 1_470);
        assert_eq!(certificate.pad_message_length(), 1_512);
        assert_eq!(certificate.pad_randomness_length(), 393);
        assert_eq!(certificate.pad_domain_size(), 4_096);
        assert_eq!(certificate.private_extension_element_count(), 18_001);
        assert_eq!(certificate.private_material_partition.len(), 12);
        assert_eq!(certificate.base_case_mask_group_count, 1);
        assert_eq!(
            certificate
                .folded_source_codes
                .iter()
                .map(|row| {
                    (
                        row.message_length,
                        row.randomness_length,
                        row.domain_size,
                        row.maximum_distinct_query_count,
                        row.interleaving_width,
                    )
                })
                .collect::<Vec<_>>(),
            [
                (2_097_152, 387, 8_388_608, 387, 8),
                (262_144, 288, 4_194_304, 288, 8),
                (32_768, 268, 2_097_152, 268, 8),
                (4_096, 264, 1_048_576, 264, 8),
                (512, 263, 524_288, 263, 8),
                (64, 263, 262_144, 263, 8),
            ],
        );
        assert_eq!(
            certificate.fresh_source_code,
            certificate.folded_source_codes[5]
        );
        assert_eq!(certificate.fresh_pad_code, certificate.pad_code);
    }

    #[test]
    fn aggregate_wide_masking_certificate_refuses_every_load_bearing_mutation() {
        let configuration = selected_hiding_whir_config(RowCodeWhirSelectedParameters::selected())
            .expect("selected hiding configuration");
        let material_shape = AggregateWideHidingMaterialShape::derive(&configuration)
            .expect("aggregate-wide private-material shape");
        let certificate = AggregateWideMaskingCertificate::derive(&configuration)
            .expect("aggregate-wide masking certificate");

        let mut overlapping_slice = certificate.clone();
        overlapping_slice.pad_layout.sumcheck_batches[0].masks[1]
            .coefficient_range
            .start -= 1;
        assert!(
            overlapping_slice
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut short_pad_randomness = certificate.clone();
        short_pad_randomness.pad_code.randomness_length -= 1;
        assert!(
            short_pad_randomness
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut short_source_randomness = certificate.clone();
        short_source_randomness.folded_source_codes[0].randomness_length -= 1;
        assert!(
            short_source_randomness
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut wrong_delta_sign = certificate.clone();
        wrong_delta_sign.switch_delta_pad_coefficient = 1;
        assert!(
            wrong_delta_sign
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut reused_private_role = certificate.clone();
        reused_private_role.private_material_partition[1].role =
            AggregateWidePrivateMaterialRole::PadMessage;
        assert!(
            reused_private_role
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut private_gap = certificate.clone();
        private_gap.private_material_partition[1].range.start += 1;
        assert!(
            private_gap
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut omitted_fresh_group = certificate.clone();
        omitted_fresh_group.base_case_mask_group_count = 0;
        assert!(
            omitted_fresh_group
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut late_pad_commitment = certificate.clone();
        late_pad_commitment.pad_commitment_precedes_claim_dependent_challenges = false;
        assert!(
            late_pad_commitment
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut missing_authority = certificate;
        missing_authority.authorities.pop();
        assert!(
            missing_authority
                .validate(&configuration, &material_shape)
                .is_err()
        );
    }

    #[test]
    fn private_material_sampler_uses_only_the_dedicated_checkpointed_stream() {
        let configuration = selected_hiding_whir_config(RowCodeWhirSelectedParameters::selected())
            .expect("selected hiding configuration");
        let mut generation = AggregateWideHidingMaterialGeneration::new(&configuration)
            .expect("aggregate-wide private-material generation");
        let mut coins = CountingPrivateCoins::default();

        let material = loop {
            match generation
                .poll(&mut coins, 64)
                .expect("sample aggregate-wide private material")
            {
                AggregateWideHidingMaterialGenerationPoll::ExtensionElementSampled {
                    completed_count,
                } => assert_eq!(
                    completed_count * PROOF_CHALLENGE_EXTENSION_DEGREE,
                    coins.sample_count
                ),
                AggregateWideHidingMaterialGenerationPoll::Complete(material) => break material,
            }
        };

        assert_eq!(coins.sample_count, 90_005);
        assert_eq!(material.pad_message.len(), 1_512);
        assert_eq!(material.pad_randomness.len(), 393);
        assert_eq!(
            material
                .oracle_randomness
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            [3_096, 2_304, 2_144, 2_112, 2_104, 2_104],
        );
        assert_eq!(material.base_case_fresh_material.source_message.len(), 64);
        assert_eq!(
            material.base_case_fresh_material.source_randomness.len(),
            263
        );
        assert_eq!(material.base_case_fresh_material.mask_groups.len(), 1);
        assert_eq!(
            material.base_case_fresh_material.mask_groups[0]
                .messages
                .len(),
            1
        );
        assert_eq!(
            material.base_case_fresh_material.mask_groups[0].messages[0].len(),
            1_512
        );
        assert_eq!(
            material.base_case_fresh_material.mask_groups[0].randomness[0].len(),
            393
        );
    }

    #[test]
    fn scalar_switch_offset_preserves_the_private_logical_mask_claim() {
        let layout = selected_layout();
        let pad_message = (0..layout.message_length())
            .map(|index| ChallengeField::from_u64(index as u64 + 11))
            .collect::<Vec<_>>();
        let range = layout.switch_mask_range(2).expect("switch range");
        let logical_mask = (0..range.len())
            .map(|index| ChallengeField::from_u64(10_000 + index as u64))
            .collect::<Vec<_>>();
        let covector = (0..range.len())
            .map(|index| ChallengeField::from_u64(3 * index as u64 + 1))
            .collect::<Vec<_>>();
        let offset = switch_mask_offset(&layout, 2, &logical_mask, &pad_message, &covector)
            .expect("switch-mask offset");
        let mut claim = AggregateWidePadClaim::new(layout.message_length());
        claim
            .record_switch_mask_offset(range, &covector, offset)
            .expect("record switch claim");
        assert_eq!(
            claim.evaluate(&pad_message).expect("evaluate pad claim"),
            dot_product::<ChallengeField, _, _>(
                logical_mask.iter().copied(),
                covector.iter().copied(),
            ),
        );
    }

    #[test]
    fn folded_interleaved_randomness_matches_limb_dot_products() {
        let randomness = Point::new(vec![
            ChallengeField::from_u64(2),
            ChallengeField::from_u64(3),
        ]);
        let raw = (1..=12).map(ChallengeField::from_u64).collect::<Vec<_>>();
        let folded = fold_limb_randomness(&raw, 3, &randomness).expect("fold randomness");
        let weights = p3_multilinear_util::poly::Poly::new_from_point(
            randomness.as_slice(),
            ChallengeField::ONE,
        );
        for coordinate in 0..3 {
            let expected = (0..4)
                .map(|limb| weights.as_slice()[limb] * raw[limb * 3 + coordinate])
                .sum::<ChallengeField>();
            assert_eq!(folded[coordinate], expected);
        }
    }

    #[test]
    fn precommitted_masked_sumcheck_matches_independent_verifier_replay() {
        let evaluations = Poly::new(
            (1..=8)
                .map(|value| ChallengeField::from_u64(2 * value + 1))
                .collect::<Vec<_>>(),
        );
        let weights = Poly::new(
            (1..=8)
                .map(|value| ChallengeField::from_u64(5 * value + 2))
                .collect::<Vec<_>>(),
        );
        let source_claim = dot_product::<ChallengeField, _, _>(
            evaluations.as_slice().iter().copied(),
            weights.as_slice().iter().copied(),
        );
        let product = ProductPolynomial::<ChallengeField, ChallengeField>::new_unpacked(
            VariableOrder::Prefix,
            evaluations,
            weights,
        );
        let source_prover = SumcheckProver::new(product, source_claim);
        let masks = vec![
            vec![
                ChallengeField::from_u64(31),
                ChallengeField::from_u64(37),
                ChallengeField::from_u64(41),
            ],
            vec![
                ChallengeField::from_u64(43),
                ChallengeField::from_u64(47),
                ChallengeField::from_u64(53),
            ],
        ];
        let auxiliary_claim = ChallengeField::from_u64(59);
        let mut prover_challenger = TranscriptTestChallenger::default();
        let mut masked = PrecommittedMaskedSumcheck::begin_residual(
            source_prover,
            masks.clone(),
            auxiliary_claim,
            0,
            &mut prover_challenger,
        )
        .expect("begin masked residual sumcheck");
        while masked
            .advance_round(&mut prover_challenger)
            .expect("advance masked sumcheck")
        {}
        let output = masked.finish().expect("finish masked sumcheck");

        let mut verifier_challenger = TranscriptTestChallenger::default();
        let verifier_handoff =
            ZkVerifier::<ChallengeField, ChallengeField>::verify_precommitted_claim(
                &output.proof,
                3,
                masks.len(),
                0,
                source_claim + auxiliary_claim,
                &mut verifier_challenger,
            )
            .expect("honest precommitted masked sumcheck");

        assert_eq!(verifier_handoff.randomness, output.randomness);
        assert_eq!(verifier_handoff.eps, output.eps);
        let randomness = output.randomness.iter().copied().collect::<Vec<_>>();
        let auxiliary_residual = output.eps
            * auxiliary_claim
            * ChallengeField::TWO.exp_u64(masks.len() as u64).inverse();
        assert_eq!(
            verifier_handoff.claimed_residual,
            output.residual_prover.claimed_sum()
                + mask_residual(&masks, &randomness)
                + auxiliary_residual,
        );

        let mut mutated_proof = output.proof;
        mutated_proof.round_coefficients[0][0] += ChallengeField::ONE;
        let mut mutation_challenger = TranscriptTestChallenger::default();
        let mutated_handoff =
            ZkVerifier::<ChallengeField, ChallengeField>::verify_precommitted_claim(
                &mutated_proof,
                3,
                masks.len(),
                0,
                source_claim + auxiliary_claim,
                &mut mutation_challenger,
            )
            .expect("well-shaped mutation reaches the downstream identity");
        assert!(
            mutated_handoff.randomness != verifier_handoff.randomness
                || mutated_handoff.claimed_residual != verifier_handoff.claimed_residual,
            "a mutated wire must change the soundness-bearing verifier handoff",
        );
    }
}
