//! Aggregate-wide zero-knowledge masking for the explicit-point row-code opening.
//!
//! One uniformly sampled pad is committed before the first claim-dependent
//! challenge. Every logical sumcheck and code-switch mask occupies a disjoint
//! slice of the same pad. Each code switch publishes its complete affine delta
//! before the query vector is sampled, so every later adaptive verifier view
//! is derived from one precommitted full-coordinate mask. The pad itself is
//! never published or recomputed from public data.

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
#[cfg(test)]
use crate::bgv::proof_suite::prover::CommonProofPrivateCoinSamplingCatalog;
use crate::bgv::proof_suite::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    prover::{CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource},
};
#[cfg(test)]
use crate::foundation::{
    DECLARED_ADVERSARIAL_QUERY_BUDGET, MaskGeneratorHonestAbortEvent,
    MaskGeneratorHybridAssumption, MaskGeneratorHybridHop, MaskGeneratorHybridLoss,
    ProofApplicationSlotCeilings, SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
    action_root_expansion_summary, deployed_mask_generator_hybrid, quantum_mask_generator_hybrid,
};

/// Selected pad-code expansion for the full-coordinate aggregate-wide mask.
///
/// The complete 1,524-coordinate message and its query-hiding randomness are
/// encoded in an 8,192-point rate-four domain. The exact distance and the 393
/// without-replacement spot checks are bound into the soundness certificate.
pub(super) const AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE: usize = 2;

/// One complete logical sumcheck mask inside the aggregate-wide pad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateWideSumcheckMaskLayout {
    coefficient_range: Range<usize>,
}

/// One logical masked-sumcheck batch in the full-coordinate pad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateWideSumcheckBatchLayout {
    masks: Vec<AggregateWideSumcheckMaskLayout>,
}

impl AggregateWideSumcheckBatchLayout {
    #[cfg(test)]
    pub(super) fn masks(&self) -> &[AggregateWideSumcheckMaskLayout] {
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
            for _ in 0..folding_factor {
                let committed_coefficient_count = configuration.sumcheck_mask.message_len;
                if committed_coefficient_count == 0 {
                    return Err("aggregate-wide sumcheck mask is empty".to_owned());
                }
                let end = next_offset
                    .checked_add(committed_coefficient_count)
                    .ok_or_else(|| "aggregate-wide sumcheck-mask layout overflowed".to_owned())?;
                masks.push(AggregateWideSumcheckMaskLayout {
                    coefficient_range: next_offset..end,
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
            for mask in &batch.masks {
                if mask.coefficient_range.start != expected_start
                    || mask.coefficient_range.len() != configuration.sumcheck_mask.message_len
                {
                    return Err(
                        "aggregate-wide sumcheck slices overlap, leave a gap, or omit a coordinate"
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
            .map(|mask| pad_message[mask.coefficient_range.clone()].to_vec())
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
            AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
        )
    }
}

/// One query-private Reed--Solomon code used by the aggregate-wide argument.
///
/// For distinct nonzero evaluation points `x_i`, the randomness columns are
/// `x_i^message_length * [1, x_i, ..., x_i^(q-1)]`. Their determinant is the
/// product of the nonzero row scales and the ordinary Vandermonde determinant.
/// Interleaved lanes use the same point vector, but disjoint randomness
/// columns, so their complete query map is block diagonal rather than a claim
/// that the shared queries are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
enum AggregateWideQueryRankVerification {
    DistinctNonzeroTwoAdicGeneralizedVandermonde,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
struct AggregateWideQueryPrivateCodeRow {
    message_length: usize,
    randomness_length: usize,
    domain_size: usize,
    maximum_distinct_query_count: usize,
    interleaving_width: usize,
    rank_verification: AggregateWideQueryRankVerification,
}

#[cfg(test)]
impl AggregateWideQueryPrivateCodeRow {
    fn private_randomness_coordinate_count(self) -> Result<usize, String> {
        self.randomness_length
            .checked_mul(self.interleaving_width)
            .ok_or_else(|| "aggregate-wide query-private randomness count overflowed".to_owned())
    }

    fn transported_query_coordinate_count(self) -> Result<usize, String> {
        self.maximum_distinct_query_count
            .checked_mul(self.interleaving_width)
            .ok_or_else(|| "aggregate-wide transported query count overflowed".to_owned())
    }

    fn validate(self) -> Result<(), String> {
        if self.message_length == 0
            || self.randomness_length == 0
            || self.domain_size == 0
            || !self.domain_size.is_power_of_two()
            || self.maximum_distinct_query_count == 0
            || self.randomness_length != self.maximum_distinct_query_count
            || self
                .message_length
                .checked_add(self.randomness_length)
                .is_none_or(|coefficient_count| coefficient_count > self.domain_size)
            || self.interleaving_width == 0
            || !self.interleaving_width.is_power_of_two()
            || self.rank_verification
                != AggregateWideQueryRankVerification::DistinctNonzeroTwoAdicGeneralizedVandermonde
        {
            return Err("aggregate-wide query-private code has invalid geometry".to_owned());
        }
        Ok(())
    }
}

/// One block of the complete affine verifier view, after conditioning on the
/// already sampled public transcript challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
enum AggregateWideJointAffineViewKind {
    SumcheckTranscript { batch_ordinal: u32 },
    SourceQueriesAndSwitchDelta { epoch_ordinal: u32 },
    TerminalSourceQueries { epoch_ordinal: u32 },
    PadQueries,
    FreshSourceReveal,
    FreshPadReveal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
struct AggregateWideJointAffineViewRow {
    kind: AggregateWideJointAffineViewKind,
    private_coordinate_count: usize,
    joint_view_rank: usize,
    conditional_entropy_dimension: usize,
}

#[cfg(test)]
impl AggregateWideJointAffineViewRow {
    fn validate(self) -> Result<(), String> {
        if self.private_coordinate_count == 0
            || self.joint_view_rank == 0
            || self
                .joint_view_rank
                .checked_add(self.conditional_entropy_dimension)
                != Some(self.private_coordinate_count)
        {
            return Err("aggregate-wide joint affine-view row has invalid rank".to_owned());
        }
        Ok(())
    }
}

/// A verifier-consumed affine image whose rank is already owned by another
/// row. These identities prevent the same query or reveal from being charged
/// twice merely because the wire transports both sides of a linear check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
enum AggregateWideDerivedAffineIdentity {
    SumcheckResidualFromTranscript { batch_ordinal: u32 },
    FoldedRandomnessFromInterleavedLanes { epoch_ordinal: u32 },
    SwitchMaskFromPadAndDelta { round_ordinal: u32 },
    FreshSourceQueriesFromRevealAndCarriedQueries,
    FreshPadQueriesFromRevealAndCarriedQueries,
    MaskedClaimFromRevealsAndPublicTarget,
    TerminalSourceCovectorFromCheckedConstraints,
    TerminalPadCovectorFromCheckedClaims,
}

/// The exact transcript order relevant to masking. Every row after the first
/// has the strict immediate predecessor named by its ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
enum AggregateWideChronologyEvent {
    PrivateMaterialSampled,
    InitialSourceCommitmentObserved,
    PadCommitmentObserved,
    PrecommittedSumcheck { batch_ordinal: u32 },
    FoldedSourceCommitmentObserved { round_ordinal: u32 },
    SwitchDeltaObserved { round_ordinal: u32 },
    SourceQueryVectorSampled { epoch_ordinal: u32 },
    FreshBaseCommitmentsObserved,
    FreshBaseClaimObserved,
    FreshBaseChallengeSampled,
    FreshBaseRevealsObserved,
    PadQueryVectorSampled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
struct AggregateWideChronologyRow {
    ordinal: u32,
    immediate_predecessor: Option<u32>,
    event: AggregateWideChronologyEvent,
}

/// Hash-derived and commitment-derived views are deliberately kept outside the
/// affine rank theorem. This boundary records their exact production census
/// and prevents the component theorem from being reported as Fiat--Shamir or
/// QROM zero knowledge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
struct AggregateWideNonlinearViewBoundary {
    commitment_root_count: usize,
    compact_frontier_count: usize,
    code_switch_image_count: usize,
    fold_image_count: usize,
    hash_output_bit_length: usize,
}

/// Deployment-to-ideal replacement ledger for the private samples consumed by
/// the aggregate-wide mask.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
struct AggregateWideGeneratorHybridCertificate {
    deployed_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 5],
    quantum_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 5],
    action_root_expansion: (usize, usize, usize),
    adversarial_query_budget: u128,
    extension_field_sample_count: usize,
    base_field_sample_count: usize,
    maximum_candidate_draws_per_output: u32,
    ceremony_application_multiplicity: u32,
}

#[cfg(test)]
impl AggregateWideGeneratorHybridCertificate {
    fn derive(private_extension_element_count: usize) -> Result<Self, String> {
        let base_field_sample_count = private_extension_element_count
            .checked_mul(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .ok_or_else(|| "aggregate-wide base-field sample count overflowed".to_owned())?;
        let application_slot_ceilings =
            crate::bgv::proof_suite::selected_profile::selected_proof_application_slot_ceilings()
                .map_err(|_| "selected proof-application ceilings are unavailable".to_owned())?;
        let ceremony_application_multiplicity = application_slot_ceilings
            .family_ceiling(ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER)
            .ok_or_else(|| "same-secret application ceiling is absent".to_owned())?;
        let mut hiding_sampler = CommonProofPrivateCoinSamplingCatalog::default();
        hiding_sampler
            .record_modulo_samples(
                CommonProofPrivateCoinCoordinate::hiding_argument(),
                PROOF_BASE_FIELD_MODULUS,
                SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                base_field_sample_count,
            )
            .map_err(|_| "aggregate-wide hiding sampler is invalid".to_owned())?;
        let hiding_sampler_exhaustion_is_at_most_inverse_power_of_two_128 = hiding_sampler
            .exhaustion_union_bound(ceremony_application_multiplicity)
            .map_err(|_| "aggregate-wide hiding exhaustion bound is invalid".to_owned())?
            .is_at_most_inverse_power_of_two(128);
        if !hiding_sampler_exhaustion_is_at_most_inverse_power_of_two_128 {
            return Err("aggregate-wide hiding exhaustion exceeds 2^-128".to_owned());
        }
        let certificate = Self {
            deployed_hybrid: deployed_mask_generator_hybrid(),
            quantum_hybrid: quantum_mask_generator_hybrid(),
            action_root_expansion: action_root_expansion_summary(),
            adversarial_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            extension_field_sample_count: private_extension_element_count,
            base_field_sample_count,
            maximum_candidate_draws_per_output:
                SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
            ceremony_application_multiplicity,
        };
        certificate.validate()?;
        Ok(certificate)
    }

    fn validate(&self) -> Result<(), String> {
        let expected_application_multiplicity =
            crate::bgv::proof_suite::selected_profile::selected_proof_application_slot_ceilings()
                .map_err(|_| "selected proof-application ceilings are unavailable".to_owned())?
                .family_ceiling(
                    ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                )
                .ok_or_else(|| "same-secret application ceiling is absent".to_owned())?;
        let expected_hops = [
            MaskGeneratorHybridHop::ActionRootEntropy,
            MaskGeneratorHybridHop::ActionKeyHierarchyReplacement,
            MaskGeneratorHybridHop::BlockStreamReplacement,
            MaskGeneratorHybridHop::FramedInputInjectivity,
            MaskGeneratorHybridHop::RejectionSamplerUniformity,
        ];
        let classical_reductions_are_exact = matches!(
            self.deployed_hybrid[1].1,
            MaskGeneratorHybridLoss::ComputationalReduction {
                assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                key_bit_length: 512,
                classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            }
        ) && matches!(
            self.deployed_hybrid[2].1,
            MaskGeneratorHybridLoss::ComputationalReduction {
                assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                key_bit_length: 512,
                classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            }
        );
        let quantum_reductions_are_exact = matches!(
            self.quantum_hybrid[1].1,
            MaskGeneratorHybridLoss::ComputationalReduction {
                assumption: MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction,
                key_bit_length: 512,
                classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            }
        ) && matches!(
            self.quantum_hybrid[2].1,
            MaskGeneratorHybridLoss::ComputationalReduction {
                assumption: MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction,
                key_bit_length: 512,
                classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            }
        );
        if self.deployed_hybrid != deployed_mask_generator_hybrid()
            || self.quantum_hybrid != quantum_mask_generator_hybrid()
            || self.deployed_hybrid.map(|(hop, _)| hop) != expected_hops
            || self.quantum_hybrid.map(|(hop, _)| hop) != expected_hops
            || !matches!(
                self.deployed_hybrid[0].1,
                MaskGeneratorHybridLoss::SecretGuessing {
                    secret_bit_length: 512,
                    query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            || !classical_reductions_are_exact
            || !quantum_reductions_are_exact
            || self.deployed_hybrid[3].1 != MaskGeneratorHybridLoss::Exact
            || self.deployed_hybrid[4].1
                != (MaskGeneratorHybridLoss::ExactGivenHonestAbort {
                    abort_event: MaskGeneratorHonestAbortEvent::RejectionSamplerExhaustion,
                })
            || self.action_root_expansion != action_root_expansion_summary()
            || self.adversarial_query_budget != DECLARED_ADVERSARIAL_QUERY_BUDGET
            || self.extension_field_sample_count == 0
            || self.base_field_sample_count
                != self.extension_field_sample_count * PROOF_CHALLENGE_EXTENSION_DEGREE
            || self.maximum_candidate_draws_per_output
                != SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT
            || self.ceremony_application_multiplicity != expected_application_multiplicity
        {
            return Err("aggregate-wide generator hybrid certificate is incomplete".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
fn aggregate_wide_chronology(
    configuration: &SelectedHidingWhirConfig,
) -> Result<Vec<AggregateWideChronologyRow>, String> {
    let mut events = Vec::new();
    let mut push = |event: AggregateWideChronologyEvent| -> Result<(), String> {
        let ordinal = u32::try_from(events.len())
            .map_err(|_| "aggregate-wide chronology ordinal exceeds u32".to_owned())?;
        events.push(AggregateWideChronologyRow {
            ordinal,
            immediate_predecessor: ordinal.checked_sub(1),
            event,
        });
        Ok(())
    };
    push(AggregateWideChronologyEvent::PrivateMaterialSampled)?;
    push(AggregateWideChronologyEvent::InitialSourceCommitmentObserved)?;
    push(AggregateWideChronologyEvent::PadCommitmentObserved)?;
    push(AggregateWideChronologyEvent::PrecommittedSumcheck { batch_ordinal: 0 })?;
    for round_ordinal in 0..configuration.n_rounds() {
        let round_ordinal = u32::try_from(round_ordinal)
            .map_err(|_| "aggregate-wide round ordinal exceeds u32".to_owned())?;
        push(AggregateWideChronologyEvent::FoldedSourceCommitmentObserved { round_ordinal })?;
        push(AggregateWideChronologyEvent::SwitchDeltaObserved { round_ordinal })?;
        push(AggregateWideChronologyEvent::SourceQueryVectorSampled {
            epoch_ordinal: round_ordinal,
        })?;
        push(AggregateWideChronologyEvent::PrecommittedSumcheck {
            batch_ordinal: round_ordinal + 1,
        })?;
    }
    push(AggregateWideChronologyEvent::FreshBaseCommitmentsObserved)?;
    push(AggregateWideChronologyEvent::FreshBaseClaimObserved)?;
    push(AggregateWideChronologyEvent::FreshBaseChallengeSampled)?;
    push(AggregateWideChronologyEvent::FreshBaseRevealsObserved)?;
    push(AggregateWideChronologyEvent::SourceQueryVectorSampled {
        epoch_ordinal: u32::try_from(configuration.n_rounds())
            .map_err(|_| "aggregate-wide terminal epoch exceeds u32".to_owned())?,
    })?;
    push(AggregateWideChronologyEvent::PadQueryVectorSampled)?;
    Ok(events)
}

#[cfg(test)]
fn aggregate_wide_sumcheck_affine_view(
    masks: &[Vec<ChallengeField>],
    challenges: &[ChallengeField],
) -> Result<Vec<ChallengeField>, String> {
    if masks.len() != 3
        || masks.iter().any(|mask| mask.len() != 3)
        || challenges.len() != masks.len()
    {
        return Err("selected aggregate-wide sumcheck affine map has invalid geometry".to_owned());
    }
    let mut future_endpoint_sum = masks
        .iter()
        .map(|mask| sumcheck_mask_endpoint_sum(mask))
        .sum::<ChallengeField>();
    let mut view = Vec::with_capacity(7);
    view.push(ChallengeField::from_u64(4) * future_endpoint_sum);
    let mut past_mask_evaluations = Vec::with_capacity(masks.len());
    for (round_index, (mask, challenge)) in masks.iter().zip(challenges).enumerate() {
        future_endpoint_sum -= sumcheck_mask_endpoint_sum(mask);
        let mut coefficients = ChallengeField::zero_vec(3);
        apply_precommitted_sumcheck_mask_round(
            &mut coefficients,
            masks,
            round_index,
            future_endpoint_sum,
            &past_mask_evaluations,
        )?;
        view.push(coefficients[0]);
        view.push(coefficients[2]);
        past_mask_evaluations.push(mask.iter().copied().horner(*challenge));
    }
    Ok(view)
}

#[cfg(test)]
fn aggregate_wide_sumcheck_affine_matrix(
    challenges: &[ChallengeField],
) -> Result<Vec<Vec<ChallengeField>>, String> {
    let mut matrix = vec![ChallengeField::zero_vec(9); 7];
    for input_coordinate in 0..9 {
        let mut masks = vec![ChallengeField::zero_vec(3); 3];
        masks[input_coordinate / 3][input_coordinate % 3] = ChallengeField::ONE;
        let view = aggregate_wide_sumcheck_affine_view(&masks, challenges)?;
        for (row, coefficient) in matrix.iter_mut().zip(view) {
            row[input_coordinate] = coefficient;
        }
    }
    Ok(matrix)
}

#[cfg(test)]
fn square_matrix_determinant(matrix: &[Vec<ChallengeField>]) -> Result<ChallengeField, String> {
    if matrix.is_empty() || matrix.iter().any(|row| row.len() != matrix.len()) {
        return Err("aggregate-wide determinant matrix is not square".to_owned());
    }
    let mut reduced = matrix.to_vec();
    let mut determinant = ChallengeField::ONE;
    for column_ordinal in 0..reduced.len() {
        let pivot_offset = reduced[column_ordinal..]
            .iter()
            .position(|row| row[column_ordinal] != ChallengeField::ZERO)
            .ok_or_else(|| "aggregate-wide affine minor is rank deficient".to_owned())?;
        let pivot_ordinal = column_ordinal + pivot_offset;
        if pivot_ordinal != column_ordinal {
            reduced.swap(pivot_ordinal, column_ordinal);
            determinant = -determinant;
        }
        let pivot = reduced[column_ordinal][column_ordinal];
        determinant *= pivot;
        let pivot_inverse = pivot.inverse();
        for value in &mut reduced[column_ordinal][column_ordinal..] {
            *value *= pivot_inverse;
        }
        let normalized_pivot = reduced[column_ordinal][column_ordinal..].to_vec();
        for row in &mut reduced[column_ordinal + 1..] {
            let scale = row[column_ordinal];
            for (value, pivot_value) in row[column_ordinal..].iter_mut().zip(&normalized_pivot) {
                *value -= scale * *pivot_value;
            }
        }
    }
    Ok(determinant)
}

#[cfg(test)]
fn aggregate_wide_sumcheck_minor_determinant(
    selected_columns: &[usize],
    challenges: &[ChallengeField],
) -> Result<ChallengeField, String> {
    if selected_columns.len() != 7
        || selected_columns.iter().any(|column| *column >= 9)
        || selected_columns.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("aggregate-wide sumcheck minor columns are non-canonical".to_owned());
    }
    let complete_matrix = aggregate_wide_sumcheck_affine_matrix(challenges)?;
    let minor = complete_matrix
        .iter()
        .map(|row| {
            selected_columns
                .iter()
                .map(|column| row[*column])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    square_matrix_determinant(&minor)
}

#[cfg(test)]
fn aggregate_wide_joint_affine_view_rows(
    configuration: &SelectedHidingWhirConfig,
    pad_layout: &AggregateWidePadLayout,
    folded_source_codes: &[AggregateWideQueryPrivateCodeRow],
    pad_code: AggregateWideQueryPrivateCodeRow,
    fresh_source_code: AggregateWideQueryPrivateCodeRow,
    fresh_pad_code: AggregateWideQueryPrivateCodeRow,
) -> Result<Vec<AggregateWideJointAffineViewRow>, String> {
    let mut rows = Vec::new();
    for (batch_ordinal, batch) in pad_layout.sumcheck_batches.iter().enumerate() {
        let private_coordinate_count = batch
            .masks
            .iter()
            .map(|mask| mask.coefficient_range.len())
            .sum::<usize>();
        let joint_view_rank = 1_usize
            .checked_add(
                batch
                    .masks
                    .len()
                    .checked_mul(
                        configuration
                            .sumcheck_mask
                            .message_len
                            .checked_sub(1)
                            .ok_or_else(|| {
                                "aggregate-wide sumcheck mask has no wire dimension".to_owned()
                            })?,
                    )
                    .ok_or_else(|| "aggregate-wide sumcheck view rank overflowed".to_owned())?,
            )
            .ok_or_else(|| "aggregate-wide sumcheck view rank overflowed".to_owned())?;
        rows.push(AggregateWideJointAffineViewRow {
            kind: AggregateWideJointAffineViewKind::SumcheckTranscript {
                batch_ordinal: u32::try_from(batch_ordinal)
                    .map_err(|_| "aggregate-wide sumcheck batch exceeds u32".to_owned())?,
            },
            private_coordinate_count,
            joint_view_rank,
            conditional_entropy_dimension: private_coordinate_count
                .checked_sub(joint_view_rank)
                .ok_or_else(|| "aggregate-wide sumcheck rank exceeds its input".to_owned())?,
        });
    }
    for (epoch_ordinal, code) in folded_source_codes.iter().copied().enumerate() {
        let source_randomness_count = code.private_randomness_coordinate_count()?;
        let query_rank = code.transported_query_coordinate_count()?;
        let epoch_ordinal_u32 = u32::try_from(epoch_ordinal)
            .map_err(|_| "aggregate-wide source epoch exceeds u32".to_owned())?;
        if epoch_ordinal < configuration.n_rounds() {
            let switch_coordinate_count = pad_layout.switch_mask_range(epoch_ordinal)?.len();
            rows.push(AggregateWideJointAffineViewRow {
                kind: AggregateWideJointAffineViewKind::SourceQueriesAndSwitchDelta {
                    epoch_ordinal: epoch_ordinal_u32,
                },
                private_coordinate_count: source_randomness_count
                    .checked_add(switch_coordinate_count)
                    .ok_or_else(|| {
                        "aggregate-wide source-and-switch input count overflowed".to_owned()
                    })?,
                joint_view_rank: query_rank
                    .checked_add(switch_coordinate_count)
                    .ok_or_else(|| "aggregate-wide source-and-switch rank overflowed".to_owned())?,
                conditional_entropy_dimension: 0,
            });
        } else {
            rows.push(AggregateWideJointAffineViewRow {
                kind: AggregateWideJointAffineViewKind::TerminalSourceQueries {
                    epoch_ordinal: epoch_ordinal_u32,
                },
                private_coordinate_count: source_randomness_count,
                joint_view_rank: query_rank,
                conditional_entropy_dimension: 0,
            });
        }
    }
    rows.push(AggregateWideJointAffineViewRow {
        kind: AggregateWideJointAffineViewKind::PadQueries,
        private_coordinate_count: pad_code.private_randomness_coordinate_count()?,
        joint_view_rank: pad_code.transported_query_coordinate_count()?,
        conditional_entropy_dimension: 0,
    });
    let fresh_source_coordinate_count = fresh_source_code
        .message_length
        .checked_add(fresh_source_code.randomness_length)
        .ok_or_else(|| "aggregate-wide fresh-source reveal count overflowed".to_owned())?;
    rows.push(AggregateWideJointAffineViewRow {
        kind: AggregateWideJointAffineViewKind::FreshSourceReveal,
        private_coordinate_count: fresh_source_coordinate_count,
        joint_view_rank: fresh_source_coordinate_count,
        conditional_entropy_dimension: 0,
    });
    let fresh_pad_coordinate_count = fresh_pad_code
        .message_length
        .checked_add(fresh_pad_code.randomness_length)
        .ok_or_else(|| "aggregate-wide fresh-pad reveal count overflowed".to_owned())?;
    rows.push(AggregateWideJointAffineViewRow {
        kind: AggregateWideJointAffineViewKind::FreshPadReveal,
        private_coordinate_count: fresh_pad_coordinate_count,
        joint_view_rank: fresh_pad_coordinate_count,
        conditional_entropy_dimension: 0,
    });
    for row in &rows {
        row.validate()?;
    }
    Ok(rows)
}

#[cfg(test)]
fn aggregate_wide_derived_affine_identities(
    configuration: &SelectedHidingWhirConfig,
) -> Result<Vec<AggregateWideDerivedAffineIdentity>, String> {
    let mut identities = Vec::new();
    for batch_ordinal in 0..=configuration.n_rounds() {
        identities.push(
            AggregateWideDerivedAffineIdentity::SumcheckResidualFromTranscript {
                batch_ordinal: u32::try_from(batch_ordinal)
                    .map_err(|_| "aggregate-wide sumcheck batch exceeds u32".to_owned())?,
            },
        );
    }
    for epoch_ordinal in 0..=configuration.n_rounds() {
        identities.push(
            AggregateWideDerivedAffineIdentity::FoldedRandomnessFromInterleavedLanes {
                epoch_ordinal: u32::try_from(epoch_ordinal)
                    .map_err(|_| "aggregate-wide source epoch exceeds u32".to_owned())?,
            },
        );
    }
    for round_ordinal in 0..configuration.n_rounds() {
        identities.push(
            AggregateWideDerivedAffineIdentity::SwitchMaskFromPadAndDelta {
                round_ordinal: u32::try_from(round_ordinal)
                    .map_err(|_| "aggregate-wide switch round exceeds u32".to_owned())?,
            },
        );
    }
    identities.extend([
        AggregateWideDerivedAffineIdentity::FreshSourceQueriesFromRevealAndCarriedQueries,
        AggregateWideDerivedAffineIdentity::FreshPadQueriesFromRevealAndCarriedQueries,
        AggregateWideDerivedAffineIdentity::MaskedClaimFromRevealsAndPublicTarget,
        AggregateWideDerivedAffineIdentity::TerminalSourceCovectorFromCheckedConstraints,
        AggregateWideDerivedAffineIdentity::TerminalPadCovectorFromCheckedClaims,
    ]);
    Ok(identities)
}

#[cfg(test)]
fn aggregate_wide_nonlinear_view_boundary(
    configuration: &SelectedHidingWhirConfig,
) -> AggregateWideNonlinearViewBoundary {
    AggregateWideNonlinearViewBoundary {
        commitment_root_count: configuration.n_rounds() + 4,
        compact_frontier_count: configuration.n_rounds() + 4,
        code_switch_image_count: configuration.n_rounds(),
        fold_image_count: configuration.n_rounds() + 1,
        hash_output_bit_length: 512,
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
/// theorem. It proves the complete construction-level affine masking
/// correspondence used by the common polynomial commitment argument:
///
/// - Construction 6.3 masks each sumcheck through a unique precommitted slice;
/// - every code switch publishes `logical mask - pad slice`, so the verifier's
///   `pad slice + delta` is exactly the original logical mask;
/// - Construction 7.2 checks the terminal source and the one aggregate pad;
/// - Proposition 3.19 hides every transported Reed--Solomon query coordinate;
///   the certificate counts all eight interleaved limbs and jointly ranks each
///   shared query vector with its switch delta;
/// - Lemma 3.26 preserves that randomized encoding under every interleaved
///   fold; and
/// - fresh base reveals, derived query pairs, nonlinear commitment views, the
///   exact transcript chronology, and the deployed KMAC/rejection-sampler
///   hybrid are all catalogued without upgrading the component argument into
///   Fiat--Shamir privacy or QROM zero knowledge.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct AggregateWideMaskingCertificate {
    pad_layout: AggregateWidePadLayout,
    sumcheck_batch_count: usize,
    sumcheck_mask_count: usize,
    logical_sumcheck_mask_coefficient_count: usize,
    full_sumcheck_coordinate_count: usize,
    switch_mask_count: usize,
    switch_mask_coefficient_count: usize,
    pad_code: AggregateWideQueryPrivateCodeRow,
    folded_source_codes: Vec<AggregateWideQueryPrivateCodeRow>,
    fresh_source_code: AggregateWideQueryPrivateCodeRow,
    fresh_pad_code: AggregateWideQueryPrivateCodeRow,
    joint_affine_view_rows: Vec<AggregateWideJointAffineViewRow>,
    total_joint_affine_view_rank: usize,
    total_conditional_entropy_dimension: usize,
    sumcheck_minor_column_ordinals: [usize; 7],
    sumcheck_constant_minor_absolute_determinant: u64,
    derived_affine_identities: Vec<AggregateWideDerivedAffineIdentity>,
    chronology: Vec<AggregateWideChronologyRow>,
    nonlinear_view_boundary: AggregateWideNonlinearViewBoundary,
    generator_hybrid: AggregateWideGeneratorHybridCertificate,
    private_material_partition: Vec<AggregateWidePrivateMaterialPartitionRow>,
    private_extension_element_count: usize,
    base_case_mask_group_count: usize,
    switch_delta_logical_coefficient: i8,
    switch_delta_pad_coefficient: i8,
    verifier_pad_coefficient: i8,
}

#[cfg(test)]
impl AggregateWideMaskingCertificate {
    pub(super) fn derive(configuration: &SelectedHidingWhirConfig) -> Result<Self, String> {
        if PROOF_BASE_FIELD_MODULUS.is_multiple_of(2) {
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
            .map(|mask| mask.coefficient_range.len())
            .sum::<usize>();
        let full_sumcheck_coordinate_count = pad_layout
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
            rank_verification:
                AggregateWideQueryRankVerification::DistinctNonzeroTwoAdicGeneralizedVandermonde,
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
                rank_verification:
                    AggregateWideQueryRankVerification::DistinctNonzeroTwoAdicGeneralizedVandermonde,
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

        let joint_affine_view_rows = aggregate_wide_joint_affine_view_rows(
            configuration,
            &pad_layout,
            &folded_source_codes,
            pad_code,
            fresh_source_code,
            fresh_pad_code,
        )?;
        let total_joint_affine_view_rank =
            joint_affine_view_rows
                .iter()
                .try_fold(0_usize, |rank, row| {
                    rank.checked_add(row.joint_view_rank)
                        .ok_or_else(|| "aggregate-wide joint affine rank overflowed".to_owned())
                })?;
        let total_conditional_entropy_dimension =
            joint_affine_view_rows
                .iter()
                .try_fold(0_usize, |dimension, row| {
                    dimension
                        .checked_add(row.conditional_entropy_dimension)
                        .ok_or_else(|| {
                            "aggregate-wide conditional entropy dimension overflowed".to_owned()
                        })
                })?;
        let sumcheck_minor_column_ordinals = [0, 1, 2, 4, 5, 7, 8];
        let derived_affine_identities = aggregate_wide_derived_affine_identities(configuration)?;
        let chronology = aggregate_wide_chronology(configuration)?;
        let nonlinear_view_boundary = aggregate_wide_nonlinear_view_boundary(configuration);
        let generator_hybrid =
            AggregateWideGeneratorHybridCertificate::derive(next_private_offset)?;

        let certificate = Self {
            pad_layout,
            sumcheck_batch_count,
            sumcheck_mask_count,
            logical_sumcheck_mask_coefficient_count,
            full_sumcheck_coordinate_count,
            switch_mask_count,
            switch_mask_coefficient_count,
            pad_code,
            folded_source_codes,
            fresh_source_code,
            fresh_pad_code,
            joint_affine_view_rows,
            total_joint_affine_view_rank,
            total_conditional_entropy_dimension,
            sumcheck_minor_column_ordinals,
            sumcheck_constant_minor_absolute_determinant: 64,
            derived_affine_identities,
            chronology,
            nonlinear_view_boundary,
            generator_hybrid,
            private_material_partition,
            private_extension_element_count: next_private_offset,
            base_case_mask_group_count: 1,
            switch_delta_logical_coefficient: 1,
            switch_delta_pad_coefficient: -1,
            verifier_pad_coefficient: 1,
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
            || configuration.sumcheck_mask.message_len != 3
            || self.pad_layout.sumcheck_batches.iter().any(|batch| {
                batch.masks.len() != 3
                    || batch
                        .masks
                        .iter()
                        .any(|mask| mask.coefficient_range.len() != 3)
            })
            || self.switch_mask_count != configuration.n_rounds()
            || self.switch_mask_coefficient_count
                != configuration
                    .switch_masks
                    .iter()
                    .map(|shape| shape.message_len)
                    .sum::<usize>()
            || self.full_sumcheck_coordinate_count
                != expected_sumcheck_mask_count
                    .checked_mul(configuration.sumcheck_mask.message_len)
                    .ok_or_else(|| "aggregate-wide sumcheck dimension overflowed".to_owned())?
            || self
                .full_sumcheck_coordinate_count
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
        {
            return Err("aggregate-wide masking certificate is incomplete".to_owned());
        }

        let expected_joint_affine_view_rows = aggregate_wide_joint_affine_view_rows(
            configuration,
            &self.pad_layout,
            &self.folded_source_codes,
            self.pad_code,
            self.fresh_source_code,
            self.fresh_pad_code,
        )?;
        let expected_joint_affine_view_rank =
            expected_joint_affine_view_rows
                .iter()
                .try_fold(0_usize, |rank, row| {
                    rank.checked_add(row.joint_view_rank)
                        .ok_or_else(|| "aggregate-wide joint affine rank overflowed".to_owned())
                })?;
        let expected_conditional_entropy_dimension = expected_joint_affine_view_rows
            .iter()
            .try_fold(0_usize, |dimension, row| {
                dimension
                    .checked_add(row.conditional_entropy_dimension)
                    .ok_or_else(|| {
                        "aggregate-wide conditional entropy dimension overflowed".to_owned()
                    })
            })?;
        let expected_joint_private_coordinate_count = expected_joint_affine_view_rows
            .iter()
            .try_fold(0_usize, |count, row| {
                count
                    .checked_add(row.private_coordinate_count)
                    .ok_or_else(|| "aggregate-wide joint private count overflowed".to_owned())
            })?;
        if self.joint_affine_view_rows != expected_joint_affine_view_rows
            || self.total_joint_affine_view_rank != expected_joint_affine_view_rank
            || self.total_conditional_entropy_dimension != expected_conditional_entropy_dimension
            || expected_joint_private_coordinate_count != self.private_extension_element_count
            || self
                .total_joint_affine_view_rank
                .checked_add(self.total_conditional_entropy_dimension)
                != Some(self.private_extension_element_count)
        {
            return Err("aggregate-wide complete joint affine view is inconsistent".to_owned());
        }

        let expected_minor_determinant =
            -ChallengeField::from_u64(self.sumcheck_constant_minor_absolute_determinant);
        for challenges in [
            [ChallengeField::ZERO; 3],
            [
                ChallengeField::ONE,
                ChallengeField::from_u64(2),
                ChallengeField::from_u64(3),
            ],
            [
                ChallengeField::from_u64(17),
                ChallengeField::from_u64(257),
                ChallengeField::from_u64(65_537),
            ],
        ] {
            if aggregate_wide_sumcheck_minor_determinant(
                &self.sumcheck_minor_column_ordinals,
                &challenges,
            )? != expected_minor_determinant
            {
                return Err(
                    "aggregate-wide adaptive sumcheck map lacks its constant full-rank minor"
                        .to_owned(),
                );
            }
        }
        if self.sumcheck_minor_column_ordinals != [0, 1, 2, 4, 5, 7, 8]
            || self.sumcheck_constant_minor_absolute_determinant != 64
            || self.derived_affine_identities
                != aggregate_wide_derived_affine_identities(configuration)?
            || self.chronology != aggregate_wide_chronology(configuration)?
            || self.nonlinear_view_boundary != aggregate_wide_nonlinear_view_boundary(configuration)
        {
            return Err(
                "aggregate-wide derived or nonlinear view catalog is incomplete".to_owned(),
            );
        }
        self.generator_hybrid.validate()?;
        if self.generator_hybrid.extension_field_sample_count
            != self.private_extension_element_count
        {
            return Err("aggregate-wide generator hybrid has the wrong sample count".to_owned());
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
        self.base_case_mask_group_count == 1
            && self.private_extension_element_count == 18_025
            && self.total_joint_affine_view_rank == 18_013
            && self.total_conditional_entropy_dimension == 12
            && self.joint_affine_view_rows.len() == 15
            && self.derived_affine_identities.len() == 22
            && self.chronology.len() == 30
            && self.nonlinear_view_boundary.commitment_root_count == 9
            && self.nonlinear_view_boundary.compact_frontier_count == 9
            && self.generator_hybrid.validate().is_ok()
            && self.sumcheck_mask_count > 0
            && self.switch_mask_count > 0
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

    pub(super) const fn joint_affine_view_summary(&self) -> (usize, usize, usize) {
        (
            self.private_extension_element_count,
            self.total_joint_affine_view_rank,
            self.total_conditional_entropy_dimension,
        )
    }

    pub(super) const fn nonlinear_view_summary(&self) -> (usize, usize, usize, usize) {
        (
            self.nonlinear_view_boundary.commitment_root_count,
            self.nonlinear_view_boundary.compact_frontier_count,
            self.nonlinear_view_boundary.code_switch_image_count,
            self.nonlinear_view_boundary.fold_image_count,
        )
    }

    pub(super) const fn generator_sample_summary(&self) -> (usize, usize, u32, u32) {
        (
            self.generator_hybrid.extension_field_sample_count,
            self.generator_hybrid.base_field_sample_count,
            self.generator_hybrid.maximum_candidate_draws_per_output,
            self.generator_hybrid.ceremony_application_multiplicity,
        )
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
    pub(super) switch_mask_delta: Vec<ChallengeField>,
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
            let mut power = ChallengeField::ONE;
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

    pub(super) fn record_switch_mask_delta(
        &mut self,
        range: Range<usize>,
        logical_mask_covector: &[ChallengeField],
        switch_mask_delta: &[ChallengeField],
    ) -> Result<(), String> {
        if range.len() != logical_mask_covector.len() || range.len() != switch_mask_delta.len() {
            return Err("aggregate-wide switch mask has inconsistent dimensions".to_owned());
        }
        let destination = self
            .covector
            .get_mut(range)
            .ok_or_else(|| "aggregate-wide switch mask range is outside the pad".to_owned())?;
        for (coefficient, increment) in destination.iter_mut().zip(logical_mask_covector) {
            *coefficient += *increment;
        }
        self.public_offset += dot_product::<ChallengeField, _, _>(
            switch_mask_delta.iter().copied(),
            logical_mask_covector.iter().copied(),
        );
        Ok(())
    }
}

enum MaskedPlainState {
    Initial(Box<PrefixInitialSumcheckProver<ChallengeField, ChallengeField>>),
    Residual(SumcheckProver<ChallengeField, ChallengeField>),
}

fn sumcheck_mask_endpoint_sum(mask: &[ChallengeField]) -> ChallengeField {
    mask[0].double() + mask[1..].iter().copied().sum::<ChallengeField>()
}

fn apply_precommitted_sumcheck_mask_round(
    full_coefficients: &mut [ChallengeField],
    masks: &[Vec<ChallengeField>],
    round_index: usize,
    future_endpoint_sum: ChallengeField,
    past_mask_evaluations: &[ChallengeField],
) -> Result<(), String> {
    let mask = masks
        .get(round_index)
        .ok_or_else(|| "precommitted masked sumcheck round is outside its mask batch".to_owned())?;
    if full_coefficients.len() < mask.len() || past_mask_evaluations.len() != round_index {
        return Err("precommitted masked sumcheck mask view has invalid geometry".to_owned());
    }
    let one_indexed_round = round_index + 1;
    let live_multiplier = ChallengeField::TWO.exp_u64((masks.len() - one_indexed_round) as u64);
    for (coefficient, mask_coefficient) in full_coefficients.iter_mut().zip(mask) {
        *coefficient += live_multiplier * *mask_coefficient;
    }
    full_coefficients[0] += past_mask_evaluations
        .iter()
        .copied()
        .sum::<ChallengeField>()
        * live_multiplier;
    if one_indexed_round < masks.len() {
        full_coefficients[0] += ChallengeField::TWO
            .exp_u64((masks.len() - one_indexed_round - 1) as u64)
            * future_endpoint_sum;
    }
    Ok(())
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
            MaskedPlainState::Initial(Box::new(plain_state)),
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
            .map(|mask| sumcheck_mask_endpoint_sum(mask))
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
        let mask_endpoints = sumcheck_mask_endpoint_sum(mask);
        self.future_endpoint_sum -= mask_endpoints;
        self.auxiliary_carry *= ChallengeField::TWO.inverse();

        let mut full_coefficients = ChallengeField::zero_vec(mask.len().max(3));
        apply_precommitted_sumcheck_mask_round(
            &mut full_coefficients,
            &self.masks,
            round_index,
            self.future_endpoint_sum,
            &self.past_mask_evaluations,
        )?;
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

pub(super) fn switch_mask_delta(
    layout: &AggregateWidePadLayout,
    round_ordinal: usize,
    source_randomness: &[ChallengeField],
    pad_message: &[ChallengeField],
) -> Result<Vec<ChallengeField>, String> {
    let range = layout.switch_mask_range(round_ordinal)?;
    if source_randomness.len() != range.len() || pad_message.len() != layout.message_length() {
        return Err("aggregate-wide switch-mask delta has the wrong shape".to_owned());
    }
    Ok(source_randomness
        .iter()
        .zip(&pad_message[range])
        .map(|(source, pad)| *source - *pad)
        .collect())
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

        fn replay_modulo_samples(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            maximum_candidate_draws_per_output: u32,
            destination: &mut [u64],
        ) -> Result<(), Self::Error> {
            if coordinate != CommonProofPrivateCoinCoordinate::hiding_argument()
                || modulus != PROOF_BASE_FIELD_MODULUS
                || maximum_candidate_draws_per_output == 0
                || destination.len() != self.sample_count
            {
                return Err("unexpected aggregate-wide private-coin replay");
            }
            for (sample_ordinal, sampled) in destination.iter_mut().enumerate() {
                *sampled = u64::try_from(sample_ordinal)
                    .map_err(|_| "aggregate-wide sample ordinal exceeded u64")?
                    % modulus;
            }
            Ok(())
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
        assert_eq!(layout.message_length(), 1_524);
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

        assert_eq!(shape.pad_message_length, 1_524);
        assert_eq!(shape.pad_randomness_length, 393);
        assert_eq!(
            shape.oracle_randomness_lengths,
            [3_096, 2_304, 2_144, 2_112, 2_104, 2_104]
        );
        assert_eq!(shape.fresh_source_message_length, 64);
        assert_eq!(shape.fresh_source_randomness_length, 263);
        assert_eq!(shape.total_extension_element_count(), 18_025);
        assert_eq!(shape.pad_shape().message_len, 1_524);
        assert_eq!(shape.pad_shape().randomness_len, 393);
        assert_eq!(shape.pad_shape().domain_size, 8_192);
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
        assert_eq!(certificate.full_sumcheck_coordinate_count, 54);
        assert_eq!(certificate.switch_mask_count, 5);
        assert_eq!(certificate.switch_mask_coefficient_count, 1_470);
        assert_eq!(certificate.pad_message_length(), 1_524);
        assert_eq!(certificate.pad_randomness_length(), 393);
        assert_eq!(certificate.pad_domain_size(), 8_192);
        assert_eq!(certificate.private_extension_element_count(), 18_025);
        assert_eq!(certificate.total_joint_affine_view_rank, 18_013);
        assert_eq!(certificate.total_conditional_entropy_dimension, 12);
        assert_eq!(certificate.joint_affine_view_rows.len(), 15);
        assert_eq!(
            certificate
                .joint_affine_view_rows
                .iter()
                .map(|row| (
                    row.private_coordinate_count,
                    row.joint_view_rank,
                    row.conditional_entropy_dimension,
                ))
                .collect::<Vec<_>>(),
            [
                (9, 7, 2),
                (9, 7, 2),
                (9, 7, 2),
                (9, 7, 2),
                (9, 7, 2),
                (9, 7, 2),
                (3_483, 3_483, 0),
                (2_592, 2_592, 0),
                (2_412, 2_412, 0),
                (2_376, 2_376, 0),
                (2_367, 2_367, 0),
                (2_104, 2_104, 0),
                (393, 393, 0),
                (327, 327, 0),
                (1_917, 1_917, 0),
            ]
        );
        assert_eq!(
            certificate.sumcheck_minor_column_ordinals,
            [0, 1, 2, 4, 5, 7, 8]
        );
        assert_eq!(certificate.sumcheck_constant_minor_absolute_determinant, 64);
        assert_eq!(certificate.derived_affine_identities.len(), 22);
        assert_eq!(certificate.chronology.len(), 30);
        assert_eq!(certificate.nonlinear_view_boundary.commitment_root_count, 9);
        assert_eq!(
            certificate.nonlinear_view_boundary.compact_frontier_count,
            9
        );
        assert_eq!(certificate.generator_hybrid.base_field_sample_count, 90_125);
        assert_eq!(
            certificate
                .generator_hybrid
                .ceremony_application_multiplicity,
            10
        );
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

        let mut omitted_sumcheck_coordinate = certificate.clone();
        omitted_sumcheck_coordinate.pad_layout.sumcheck_batches[0].masks[0]
            .coefficient_range
            .end -= 1;
        assert!(
            omitted_sumcheck_coordinate
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

        let mut deficient_joint_rank = certificate.clone();
        deficient_joint_rank.joint_affine_view_rows[0].joint_view_rank -= 1;
        assert!(
            deficient_joint_rank
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut altered_sumcheck_map = certificate.clone();
        altered_sumcheck_map.sumcheck_minor_column_ordinals[1] = 3;
        assert!(
            altered_sumcheck_map
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut changed_query_schedule = certificate.clone();
        changed_query_schedule.folded_source_codes[0].maximum_distinct_query_count -= 1;
        assert!(
            changed_query_schedule
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
        late_pad_commitment.chronology[2].event =
            AggregateWideChronologyEvent::PrecommittedSumcheck { batch_ordinal: 0 };
        assert!(
            late_pad_commitment
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut challenge_dependent_mask = certificate.clone();
        challenge_dependent_mask.chronology[0].event =
            AggregateWideChronologyEvent::FreshBaseChallengeSampled;
        assert!(
            challenge_dependent_mask
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut publicly_recomputable_mask = certificate.clone();
        publicly_recomputable_mask.generator_hybrid.deployed_hybrid[0].1 =
            MaskGeneratorHybridLoss::Exact;
        assert!(
            publicly_recomputable_mask
                .validate(&configuration, &material_shape)
                .is_err()
        );

        let mut omitted_nonlinear_view = certificate.clone();
        omitted_nonlinear_view
            .nonlinear_view_boundary
            .compact_frontier_count -= 1;
        assert!(
            omitted_nonlinear_view
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

        assert_eq!(coins.sample_count, 90_125);
        assert_eq!(material.pad_message.len(), 1_524);
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
            1_524
        );
        assert_eq!(
            material.base_case_fresh_material.mask_groups[0].randomness[0].len(),
            393
        );
    }

    #[test]
    fn full_switch_delta_preserves_every_later_linear_mask_view() {
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
        let delta =
            switch_mask_delta(&layout, 2, &logical_mask, &pad_message).expect("switch-mask delta");
        let mut claim = AggregateWidePadClaim::new(layout.message_length());
        claim
            .record_switch_mask_delta(range, &covector, &delta)
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
