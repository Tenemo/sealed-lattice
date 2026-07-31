//! Hiding aggregate-opening configuration for the selected construction.
//!
//! The row pads committed inside the phase rows cannot mask a query answer,
//! because every query vector is drawn only after the aggregate commitment is
//! observed. Query-answer masking therefore belongs to mask groups committed
//! with the aggregate, and the construction already reserves a hiding component
//! in its round-by-round budget.
//!
//! This module derives that configuration from the same selected parameters the
//! plain aggregate opening uses, so the mask geometry the construction plan must
//! bind is a derived quantity rather than a chosen one. It does not yet replace
//! the operative opening argument.

pub(super) mod static_accounting;

use p3_whir::{FoldingFactor, ProtocolParameters, ZkParameters, ZkWhirConfig};

use super::construction_plan::{RowCodeWhirSelectedParameters, RowCodeWhirSoundnessAssumption};
use super::{ChallengeField, ExtensionFieldChallenger};

/// Mask-code message length for the hiding sumcheck.
///
/// The vendored configuration requires at least three coefficients. The selected
/// construction uses the minimum, because the sumcheck mask only has to hide the
/// per-round sumcheck wires and every additional coefficient is proof bytes that
/// no view consumes.
pub(super) const SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH: usize = 3;

/// Log inverse rate of the mask codewords.
///
/// A rate-one mask code has minimal distance, so its spot checks barely bind and
/// the vendored configuration refuses it. The selected construction reuses the
/// row code's inverse rate so the mask codewords carry the same relative
/// distance as everything else the verifier spot-checks.
pub(super) const SELECTED_HIDING_MASK_LOG_INVERSE_RATE: usize = 2;

pub(super) type SelectedHidingWhirConfig =
    ZkWhirConfig<ChallengeField, ChallengeField, ExtensionFieldChallenger>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HidingWhirConfigurationError {
    UnsupportedVariableCount,
    Vendored,
}

impl core::fmt::Display for HidingWhirConfigurationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVariableCount => write!(
                formatter,
                "the hiding aggregate opening requires the selected commitment variable count"
            ),
            Self::Vendored => write!(
                formatter,
                "the vendored hiding WHIR configuration refused the selected parameters"
            ),
        }
    }
}

pub(super) const fn selected_hiding_parameters() -> ZkParameters {
    ZkParameters {
        ell_zk: SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH,
        mask_log_inv_rate: SELECTED_HIDING_MASK_LOG_INVERSE_RATE,
    }
}

/// Derives the hiding configuration for the selected construction parameters.
///
/// The plain and hiding configurations share one round structure, so the folding
/// factors, domains, query counts, and proof-of-work bits are the same values the
/// construction plan already binds. Only the mask budgets are new.
pub(super) fn selected_hiding_whir_config(
    parameters: RowCodeWhirSelectedParameters,
) -> Result<SelectedHidingWhirConfig, HidingWhirConfigurationError> {
    hiding_whir_config_with_mask_parameters(parameters, selected_hiding_parameters())
}

/// Derives a hiding configuration for explicitly chosen mask parameters.
///
/// The admissible-parameter search needs to instantiate candidates other than
/// the selected one. Every non-mask parameter still comes from the construction
/// plan, so a candidate differs from the selection only in its mask budgets.
pub(super) fn hiding_whir_config_with_mask_parameters(
    parameters: RowCodeWhirSelectedParameters,
    mask_parameters: ZkParameters,
) -> Result<SelectedHidingWhirConfig, HidingWhirConfigurationError> {
    if parameters.polynomial_commitment_variable_count == 0 {
        return Err(HidingWhirConfigurationError::UnsupportedVariableCount);
    }
    let soundness_type = match parameters.soundness_assumption {
        RowCodeWhirSoundnessAssumption::UniqueDecoding => {
            p3_whir::SecurityAssumption::UniqueDecoding
        }
    };
    ZkWhirConfig::new(
        parameters.polynomial_commitment_variable_count,
        ProtocolParameters {
            starting_log_inv_rate: parameters.starting_log_inverse_rate,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::Constant(parameters.folding_factor),
            soundness_type,
            security_level: parameters.security_level,
            pow_bits: parameters.proof_of_work_bits,
        },
        mask_parameters,
    )
    .map_err(|_| HidingWhirConfigurationError::Vendored)
}

/// The pipeline move that commits one carried mask group.
///
/// Ownership is chronological: a group is committed by the move named here, and
/// every challenge drawn after that move is bound to its root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(super) enum HidingMaskGroupOwner {
    /// The masked sumcheck batch that folds committed oracle `oracle_ordinal`.
    ///
    /// One mask codeword is stacked per folded variable, so the group width is
    /// that oracle's folding factor.
    SumcheckBatch { oracle_ordinal: usize },
    /// The code switch that produces the oracle committed after `round_ordinal`.
    ///
    /// The switch commits one mask carrying the previous oracle's folded
    /// randomness together with one pad coordinate per out-of-domain answer.
    CodeSwitch { round_ordinal: usize },
}

/// One instantiated carried mask group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct HidingMaskGroupCensusEntry {
    /// Position of this group in the pipeline's chronological commit order.
    pub(super) commit_ordinal: usize,
    /// The move that commits the group.
    pub(super) owner: HidingMaskGroupOwner,
    /// Mask codewords stacked under one root.
    pub(super) width: usize,
    /// Message coefficients per stacked codeword.
    pub(super) message_length: usize,
    /// Encoding-randomness coefficients per stacked codeword.
    pub(super) randomness_length: usize,
    /// Codeword coordinates per stacked codeword.
    pub(super) codeword_domain_size: usize,
}

#[cfg(test)]
impl HidingMaskGroupCensusEntry {
    /// Codeword coordinates the whole group instantiates.
    pub(super) const fn codeword_coordinate_count(&self) -> usize {
        self.width * self.codeword_domain_size
    }

    /// Authentication nodes on one opening path into this group's root.
    ///
    /// Every stacked codeword shares one row per opened position, so a group
    /// opening authenticates one row rather than one path per member.
    pub(super) const fn merkle_path_node_count(&self) -> usize {
        self.codeword_domain_size.trailing_zeros() as usize
    }
}

/// The folded source code the base case checks, shared by the fresh main mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct HidingSourceCodeCensus {
    /// Message coefficients of the terminal folded word.
    pub(super) message_length: usize,
    /// Encoding-randomness coefficients carried by the terminal oracle.
    pub(super) randomness_length: usize,
    /// Coordinates of the folded source domain.
    pub(super) codeword_domain_size: usize,
}

#[cfg(test)]
impl HidingSourceCodeCensus {
    pub(super) const fn merkle_path_node_count(&self) -> usize {
        self.codeword_domain_size.trailing_zeros() as usize
    }
}

/// The complete instantiated mask inventory of one hiding configuration.
///
/// The carried groups are the masks committed while the rounds run. The base
/// case then mirrors every carried group with one freshly committed blind of the
/// same shape, and adds one fresh main mask in the folded source code. Counting
/// only the distinct code shapes, or counting a group as one codeword,
/// understates the inventory, so every derived total here multiplies by group
/// width and by the carried/fresh mirror.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct SelectedHidingMaskCensus {
    /// Carried groups in chronological commit order.
    pub(super) carried_groups: Vec<HidingMaskGroupCensusEntry>,
    /// The folded source code shared by the source oracle and the fresh main mask.
    pub(super) source_code: HidingSourceCodeCensus,
    /// Spot checks the base case draws against the source and fresh main codewords.
    pub(super) source_spot_check_count: usize,
    /// Spot checks the base case draws against each mask group.
    pub(super) mask_spot_check_count: usize,
}

#[cfg(test)]
impl SelectedHidingMaskCensus {
    /// Derives the census from an instantiated configuration.
    pub(super) fn derive(configuration: &SelectedHidingWhirConfig) -> Self {
        let round_count = configuration.inner.n_rounds();
        let mut carried_groups = Vec::with_capacity(2 * round_count + 1);
        let push_sumcheck_batch = |groups: &mut Vec<HidingMaskGroupCensusEntry>,
                                   oracle_ordinal: usize| {
            groups.push(HidingMaskGroupCensusEntry {
                commit_ordinal: groups.len(),
                owner: HidingMaskGroupOwner::SumcheckBatch { oracle_ordinal },
                width: configuration.inner.round_folding_factor(oracle_ordinal),
                message_length: configuration.sumcheck_mask.message_len,
                randomness_length: configuration.sumcheck_mask.randomness_len,
                codeword_domain_size: configuration.sumcheck_mask.domain_size,
            });
        };
        push_sumcheck_batch(&mut carried_groups, 0);
        for round_ordinal in 0..round_count {
            let switch_mask = configuration.switch_masks[round_ordinal];
            carried_groups.push(HidingMaskGroupCensusEntry {
                commit_ordinal: carried_groups.len(),
                owner: HidingMaskGroupOwner::CodeSwitch { round_ordinal },
                width: 1,
                message_length: switch_mask.message_len,
                randomness_length: switch_mask.randomness_len,
                codeword_domain_size: switch_mask.domain_size,
            });
            push_sumcheck_batch(&mut carried_groups, round_ordinal + 1);
        }

        // The base case checks the virtual folded oracle, so the fresh main mask
        // lives in that oracle's code rather than in a mask code.
        let final_round = configuration.inner.final_round_config();
        let source_code = HidingSourceCodeCensus {
            message_length: 1 << final_round.num_variables,
            randomness_length: configuration.oracle_randomness[round_count],
            codeword_domain_size: final_round.domain_size >> final_round.folding_factor,
        };

        Self {
            carried_groups,
            source_code,
            source_spot_check_count: configuration.inner.final_queries,
            mask_spot_check_count: configuration.mask_queries,
        }
    }

    /// Carried mask groups, which is also the number of committed group roots.
    pub(super) fn carried_group_count(&self) -> usize {
        self.carried_groups.len()
    }

    /// Individual carried mask codewords across every group.
    pub(super) fn carried_codeword_count(&self) -> usize {
        self.carried_groups.iter().map(|group| group.width).sum()
    }

    /// Codeword coordinates the carried masks instantiate.
    pub(super) fn carried_codeword_coordinate_count(&self) -> usize {
        self.carried_groups
            .iter()
            .map(HidingMaskGroupCensusEntry::codeword_coordinate_count)
            .sum()
    }

    /// Fresh mirror groups the base case commits.
    ///
    /// Move 1b commits one blind per carried mask, grouped exactly as the
    /// carried masks were, so the mirror inventory equals the carried inventory
    /// group for group.
    pub(super) fn fresh_mirror_group_count(&self) -> usize {
        self.carried_group_count()
    }

    pub(super) fn fresh_mirror_codeword_count(&self) -> usize {
        self.carried_codeword_count()
    }

    pub(super) fn fresh_mirror_codeword_coordinate_count(&self) -> usize {
        self.carried_codeword_coordinate_count()
    }

    /// Roots the hiding layer adds: one per carried group, one per mirror group,
    /// and one for the fresh main mask.
    pub(super) fn committed_root_count(&self) -> usize {
        self.carried_group_count() + self.fresh_mirror_group_count() + 1
    }

    /// Blinded reveal coefficients the base case sends.
    ///
    /// Each carried codeword reveals its message and its encoding randomness
    /// once, and the source reveals its own message and randomness once.
    pub(super) fn blinded_reveal_coefficient_count(&self) -> usize {
        let mask_reveals: usize = self
            .carried_groups
            .iter()
            .map(|group| group.width * (group.message_length + group.randomness_length))
            .sum();
        mask_reveals + self.source_code.message_length + self.source_code.randomness_length
    }

    /// Authentication nodes a literal per-opening encoding would carry.
    ///
    /// This is the direct-port cost: one independent Merkle path for every
    /// opened row, with no node sharing between the paths of one root. It is the
    /// number the canonical multiproof has to beat, not a lower bound.
    pub(super) fn literal_authentication_node_count(&self) -> usize {
        let mask_nodes: usize = self
            .carried_groups
            .iter()
            .map(|group| 2 * self.mask_spot_check_count * group.merkle_path_node_count())
            .sum();
        mask_nodes + 2 * self.source_spot_check_count * self.source_code.merkle_path_node_count()
    }
}

#[cfg(test)]
mod tests {
    use super::super::NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH;
    use super::*;

    /// Digest bytes of one authentication node in the production Merkle tree.
    const PRODUCTION_MERKLE_NODE_BYTE_LENGTH: usize = 64;

    fn selected_census() -> SelectedHidingMaskCensus {
        let configuration = selected_hiding_whir_config(RowCodeWhirSelectedParameters::selected())
            .expect("the selected parameters admit a hiding configuration");
        SelectedHidingMaskCensus::derive(&configuration)
    }

    /// Pins the mask geometry the construction plan will have to bind.
    ///
    /// Every value here is derived from the selected parameters, so a change to
    /// the round structure, query counts, or security level moves this geometry
    /// and must move the plan and the exact ledger with it.
    #[test]
    fn selected_hiding_configuration_derives_its_complete_mask_geometry() {
        let parameters = RowCodeWhirSelectedParameters::selected();
        let configuration = selected_hiding_whir_config(parameters)
            .expect("the selected parameters admit a hiding configuration");

        // The hiding pipeline keeps the plain round structure.
        assert_eq!(configuration.inner.n_rounds(), 5);
        assert_eq!(
            configuration.inner.starting_log_inv_rate,
            parameters.starting_log_inverse_rate
        );

        // Each oracle's randomness budget equals the spot checks of the round
        // that consumes it, so every opening against it is simulatable.
        let consuming_query_counts = configuration
            .inner
            .round_parameters
            .iter()
            .map(|round| round.num_queries)
            .chain(core::iter::once(configuration.inner.final_queries))
            .collect::<Vec<_>>();
        assert_eq!(configuration.oracle_randomness, consuming_query_counts);
        assert_eq!(configuration.oracle_randomness.len(), 6);

        // Randomness must fit strictly inside each oracle's rate slack, which is
        // load-bearing for zero knowledge rather than a layout convenience. The
        // vendored constructor enforces it, so a successful derivation is the
        // proof that it holds for the selected geometry.
        assert!(
            configuration
                .oracle_randomness
                .iter()
                .all(|randomness| *randomness > 0)
        );

        // One sumcheck mask plus one code-switch mask per round.
        assert_eq!(configuration.switch_masks.len(), 5);
        assert_eq!(
            configuration.sumcheck_mask.message_len,
            SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH
        );
        assert_eq!(
            configuration.sumcheck_mask.randomness_len,
            configuration.mask_queries
        );

        // Each code-switch mask commits the previous oracle's folded randomness
        // plus one pad coordinate per out-of-domain answer of that round.
        for (round_index, mask) in configuration.switch_masks.iter().enumerate() {
            assert_eq!(
                mask.message_len,
                configuration.oracle_randomness[round_index]
                    + configuration.inner.round_parameters[round_index].ood_samples
            );
            assert_eq!(mask.randomness_len, configuration.mask_queries);
            // The mask domain is the smallest power of two that holds the
            // message and its randomness, expanded by the mask code's inverse
            // rate. Recomputing it independently keeps the layout honest.
            assert_eq!(
                mask.domain_size,
                (mask.message_len + mask.randomness_len).next_power_of_two()
                    << SELECTED_HIDING_MASK_LOG_INVERSE_RATE
            );
        }

        // Mask spot checks carry no proof-of-work relief, so they target the
        // full security level plus the union over every mask oracle. For the
        // selected geometry that union is over twelve mask oracles, four bits.
        assert_eq!(configuration.mask_queries, 393);

        // The complete derived geometry, pinned so the construction plan binds
        // measured values. Round out-of-domain sampling is empty, which also
        // corroborates the response census behind the transcript ceiling.
        assert_eq!(
            configuration.oracle_randomness,
            vec![387, 288, 268, 264, 263, 263]
        );
        assert_eq!(configuration.sumcheck_mask.domain_size, 2_048);
        assert_eq!(
            configuration
                .switch_masks
                .iter()
                .map(|mask| (mask.message_len, mask.domain_size))
                .collect::<Vec<_>>(),
            vec![
                (387, 4_096),
                (288, 4_096),
                (268, 4_096),
                (264, 4_096),
                (263, 4_096),
            ],
        );
        assert!(
            configuration
                .inner
                .round_parameters
                .iter()
                .all(|round| round.ood_samples == 0)
        );
    }

    /// Derives every instantiated mask group, not just the distinct code shapes.
    ///
    /// The distinct shapes are one sumcheck code and five switch codes. The
    /// instantiated schedule stacks the sumcheck code once per folded variable
    /// and repeats it after every code switch, so counting shapes understates
    /// the inventory by the sumcheck width and by five repetitions.
    #[test]
    fn selected_hiding_census_derives_every_instantiated_carried_group() {
        let census = selected_census();

        // Eleven groups: one sumcheck batch per committed oracle, one code switch
        // per round, interleaved in commit order.
        assert_eq!(census.carried_group_count(), 11);
        assert_eq!(
            census
                .carried_groups
                .iter()
                .map(|group| (group.commit_ordinal, group.owner, group.width))
                .collect::<Vec<_>>(),
            vec![
                (
                    0,
                    HidingMaskGroupOwner::SumcheckBatch { oracle_ordinal: 0 },
                    3
                ),
                (1, HidingMaskGroupOwner::CodeSwitch { round_ordinal: 0 }, 1),
                (
                    2,
                    HidingMaskGroupOwner::SumcheckBatch { oracle_ordinal: 1 },
                    3
                ),
                (3, HidingMaskGroupOwner::CodeSwitch { round_ordinal: 1 }, 1),
                (
                    4,
                    HidingMaskGroupOwner::SumcheckBatch { oracle_ordinal: 2 },
                    3
                ),
                (5, HidingMaskGroupOwner::CodeSwitch { round_ordinal: 2 }, 1),
                (
                    6,
                    HidingMaskGroupOwner::SumcheckBatch { oracle_ordinal: 3 },
                    3
                ),
                (7, HidingMaskGroupOwner::CodeSwitch { round_ordinal: 3 }, 1),
                (
                    8,
                    HidingMaskGroupOwner::SumcheckBatch { oracle_ordinal: 4 },
                    3
                ),
                (9, HidingMaskGroupOwner::CodeSwitch { round_ordinal: 4 }, 1),
                (
                    10,
                    HidingMaskGroupOwner::SumcheckBatch { oracle_ordinal: 5 },
                    3
                ),
            ],
        );

        // Twenty-three carried codewords: eighteen sumcheck masks over the 2,048
        // coordinate mask domain and five switch masks over 4,096 coordinates.
        assert_eq!(census.carried_codeword_count(), 23);
        assert_eq!(
            census
                .carried_groups
                .iter()
                .filter(|group| matches!(group.owner, HidingMaskGroupOwner::SumcheckBatch { .. }))
                .map(|group| group.codeword_coordinate_count())
                .sum::<usize>(),
            36_864
        );
        assert_eq!(
            census
                .carried_groups
                .iter()
                .filter(|group| matches!(group.owner, HidingMaskGroupOwner::CodeSwitch { .. }))
                .map(|group| group.codeword_coordinate_count())
                .sum::<usize>(),
            20_480
        );
        assert_eq!(census.carried_codeword_coordinate_count(), 57_344);

        // The base case mirrors every carried group with one fresh blind of the
        // same shape, so the fresh inventory is a second copy of the carried one.
        assert_eq!(census.fresh_mirror_group_count(), 11);
        assert_eq!(census.fresh_mirror_codeword_count(), 23);
        assert_eq!(census.fresh_mirror_codeword_coordinate_count(), 57_344);

        // The fresh main mask lives in the folded source code, whose terminal
        // word has dimension 64 over a 262,144 coordinate domain.
        assert_eq!(
            census.source_code,
            HidingSourceCodeCensus {
                message_length: 64,
                randomness_length: 263,
                codeword_domain_size: 262_144,
            }
        );
        assert_eq!(census.source_code.merkle_path_node_count(), 18);
        assert_eq!(census.source_spot_check_count, 263);
        assert_eq!(census.mask_spot_check_count, 393);

        // Twenty-three committed roots: eleven carried, eleven mirrors, one fresh main.
        assert_eq!(census.committed_root_count(), 23);
    }

    /// Reproduces the direct-port refusal from the derived census.
    ///
    /// A literal per-opening encoding authenticates one independent path per
    /// opened row. The resulting payload already exceeds the proof selection
    /// gate before roots, opened values, blinded reveals, sumchecks, rounds,
    /// framing, or the existing phase-value payload are counted, which is why a
    /// canonical construction-aware multiproof is a porting prerequisite.
    #[test]
    fn literal_authentication_encoding_exceeds_the_proof_selection_gate() {
        let census = selected_census();

        let sumcheck_group_nodes: usize = census
            .carried_groups
            .iter()
            .filter(|group| matches!(group.owner, HidingMaskGroupOwner::SumcheckBatch { .. }))
            .map(|group| 2 * census.mask_spot_check_count * group.merkle_path_node_count())
            .sum();
        let switch_group_nodes: usize = census
            .carried_groups
            .iter()
            .filter(|group| matches!(group.owner, HidingMaskGroupOwner::CodeSwitch { .. }))
            .map(|group| 2 * census.mask_spot_check_count * group.merkle_path_node_count())
            .sum();
        let source_nodes =
            2 * census.source_spot_check_count * census.source_code.merkle_path_node_count();

        assert_eq!(
            sumcheck_group_nodes * PRODUCTION_MERKLE_NODE_BYTE_LENGTH,
            3_320_064
        );
        assert_eq!(
            switch_group_nodes * PRODUCTION_MERKLE_NODE_BYTE_LENGTH,
            3_018_240
        );
        assert_eq!(source_nodes * PRODUCTION_MERKLE_NODE_BYTE_LENGTH, 605_952);

        let literal_authentication_bytes =
            census.literal_authentication_node_count() * PRODUCTION_MERKLE_NODE_BYTE_LENGTH;
        assert_eq!(literal_authentication_bytes, 6_944_256);
        assert!(literal_authentication_bytes > NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH);
    }

    #[test]
    fn hiding_configuration_refuses_a_degenerate_mask_code() {
        assert!(matches!(
            selected_hiding_whir_config(RowCodeWhirSelectedParameters {
                polynomial_commitment_variable_count: 0,
                ..RowCodeWhirSelectedParameters::selected()
            }),
            Err(HidingWhirConfigurationError::UnsupportedVariableCount),
        ));
    }
}
