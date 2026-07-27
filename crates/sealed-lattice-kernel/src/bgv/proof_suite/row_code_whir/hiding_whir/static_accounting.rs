//! Static canonical-proof accounting for the hiding aggregate-opening candidate.
//!
//! The eligibility question is whether the vendored hiding pipeline can be
//! encoded under the proof selection gate at all. Answering it does not need a
//! generated proof: every section of the canonical stream has a length that the
//! instantiated configuration and the construction plan already determine, and
//! the only position-dependent quantity is the authentication-node count, which
//! has an exact worst-case bound over all position sets.
//!
//! This module derives both ledgers from one configuration: the plain aggregate
//! opening that production currently emits, and the hiding candidate that would
//! replace it. Their difference is the migration's exact proof-size cost.
//!
//! Everything here is a derived static quantity. It is not a generated proof,
//! not a measurement, and not evidence that the candidate is secure.

use crate::bgv::proof_suite::field::PROOF_CHALLENGE_EXTENSION_DEGREE;

use super::super::MERKLE_DIGEST_BYTE_LENGTH;
use super::{HidingMaskGroupOwner, SelectedHidingMaskCensus, SelectedHidingWhirConfig};

/// Canonical wire length of one challenge-field element.
const CHALLENGE_FIELD_WIRE_BYTE_LENGTH: usize = PROOF_CHALLENGE_EXTENSION_DEGREE * size_of::<u64>();

/// Canonical wire length of one base-field element.
const BASE_FIELD_WIRE_BYTE_LENGTH: usize = size_of::<u64>();

/// Canonical wire length of one dictionary reference on an authentication path.
const AUTHENTICATION_REFERENCE_WIRE_BYTE_LENGTH: usize = size_of::<u32>();

/// Canonical wire length of one section element count.
const SECTION_COUNT_WIRE_BYTE_LENGTH: usize = size_of::<u32>();

/// Distinct authentication nodes a canonical dictionary encoding can need.
///
/// One opening contributes one sibling per level. Two openings share a sibling
/// only when they already share the node above it, so the distinct siblings at
/// one level are bounded both by the opening count and by that level's own node
/// count. Summing those minima is exact for the worst-case position set, which
/// is the bound a canonical encoding has to reserve for.
fn saturating_authentication_node_count(leaf_count: usize, opening_count: usize) -> usize {
    let mut node_count = 0;
    let mut level_node_count = leaf_count;
    while level_node_count > 1 {
        node_count += opening_count.min(level_node_count);
        level_node_count >>= 1;
    }
    node_count
}

/// One authenticated opening batch against a single committed root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthenticatedOpeningBatch {
    /// Leaves of the committed tree.
    leaf_count: usize,
    /// Opened positions.
    opening_count: usize,
    /// Challenge-field values one opened row reveals.
    challenge_values_per_opening: usize,
    /// Base-field values one opened row reveals.
    base_values_per_opening: usize,
}

impl AuthenticatedOpeningBatch {
    fn authentication_path_length(&self) -> usize {
        self.leaf_count.trailing_zeros() as usize
    }

    fn dictionary_node_count(&self) -> usize {
        saturating_authentication_node_count(self.leaf_count, self.opening_count)
    }

    fn dictionary_byte_length(&self) -> usize {
        SECTION_COUNT_WIRE_BYTE_LENGTH + self.dictionary_node_count() * MERKLE_DIGEST_BYTE_LENGTH
    }

    fn opened_value_byte_length(&self) -> usize {
        self.opening_count
            * (self.challenge_values_per_opening * CHALLENGE_FIELD_WIRE_BYTE_LENGTH
                + self.base_values_per_opening * BASE_FIELD_WIRE_BYTE_LENGTH)
    }

    fn reference_byte_length(&self) -> usize {
        self.opening_count
            * self.authentication_path_length()
            * AUTHENTICATION_REFERENCE_WIRE_BYTE_LENGTH
    }

    fn byte_length(&self) -> usize {
        self.dictionary_byte_length()
            + self.opened_value_byte_length()
            + self.reference_byte_length()
    }
}

/// A named part of one canonical aggregate-opening stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::bgv::proof_suite::row_code_whir) enum AggregateOpeningSection {
    /// Wire magic and the fixed section counts.
    Framing,
    /// Claimed opening evaluations, one per requested aggregate column.
    OpeningEvaluations,
    /// Out-of-domain answers absorbed with the aggregate commitment.
    CommitmentOutOfDomainAnswers,
    /// Round oracle commitments.
    RoundCommitments,
    /// Out-of-domain answers of the code-switching rounds.
    RoundOutOfDomainAnswers,
    /// Authenticated round query openings.
    RoundQueryOpenings,
    /// Folding sumcheck wires.
    SumcheckWires,
    /// The plain terminal polynomial the verifier folds directly.
    PlainFinalPolynomial,
    /// Authenticated plain terminal query openings.
    PlainFinalQueryOpenings,
    /// Commitments to the interleaved sumcheck masks, one per fold batch.
    SumcheckMaskCommitments,
    /// Commitments to the code-switch masks, one per round.
    CodeSwitchMaskCommitments,
    /// Commitments the base case adds: fresh mirrors and the fresh main mask.
    BaseCaseFreshCommitments,
    /// The fresh-side claim the base case fixes before its blinding challenge.
    BaseCaseMaskedClaim,
    /// One-time-pad reveals of the source message and its encoding randomness.
    BaseCaseBlindedSourceReveals,
    /// One-time-pad reveals of every carried mask and its encoding randomness.
    BaseCaseBlindedMaskReveals,
    /// Authenticated base-case openings of the folded source oracle.
    BaseCaseSourceOpenings,
    /// Authenticated base-case openings of the fresh main mask.
    BaseCaseFreshMainOpenings,
    /// Authenticated paired openings of every carried mask group and its mirror.
    BaseCaseMaskGroupOpenings,
}

impl AggregateOpeningSection {
    pub(in crate::bgv::proof_suite::row_code_whir) const fn identifier(self) -> &'static str {
        match self {
            Self::Framing => "framing",
            Self::OpeningEvaluations => "opening-evaluations",
            Self::CommitmentOutOfDomainAnswers => "commitment-out-of-domain-answers",
            Self::RoundCommitments => "round-commitments",
            Self::RoundOutOfDomainAnswers => "round-out-of-domain-answers",
            Self::RoundQueryOpenings => "round-query-openings",
            Self::SumcheckWires => "sumcheck-wires",
            Self::PlainFinalPolynomial => "plain-final-polynomial",
            Self::PlainFinalQueryOpenings => "plain-final-query-openings",
            Self::SumcheckMaskCommitments => "sumcheck-mask-commitments",
            Self::CodeSwitchMaskCommitments => "code-switch-mask-commitments",
            Self::BaseCaseFreshCommitments => "base-case-fresh-commitments",
            Self::BaseCaseMaskedClaim => "base-case-masked-claim",
            Self::BaseCaseBlindedSourceReveals => "base-case-blinded-source-reveals",
            Self::BaseCaseBlindedMaskReveals => "base-case-blinded-mask-reveals",
            Self::BaseCaseSourceOpenings => "base-case-source-openings",
            Self::BaseCaseFreshMainOpenings => "base-case-fresh-main-openings",
            Self::BaseCaseMaskGroupOpenings => "base-case-mask-group-openings",
        }
    }
}

/// One canonical aggregate-opening byte ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) struct AggregateOpeningByteLedger {
    /// Sections in canonical stream order, each with its exact byte length.
    pub(in crate::bgv::proof_suite::row_code_whir) sections: Vec<(AggregateOpeningSection, usize)>,
}

impl AggregateOpeningByteLedger {
    pub(in crate::bgv::proof_suite::row_code_whir) fn byte_length(&self) -> usize {
        self.sections.iter().map(|(_, bytes)| *bytes).sum()
    }

    fn section_byte_length(&self, section: AggregateOpeningSection) -> usize {
        self.sections
            .iter()
            .filter(|(candidate, _)| *candidate == section)
            .map(|(_, bytes)| *bytes)
            .sum()
    }
}

/// Framing bytes: the wire marker plus the variable, opening, and width counts.
const AGGREGATE_OPENING_FRAMING_BYTE_LENGTH: usize = 8 + 3 * SECTION_COUNT_WIRE_BYTE_LENGTH;

/// Shared round structure of the plain and hiding ledgers.
struct AggregateOpeningRoundGeometry {
    round_count: usize,
    commitment_out_of_domain_answer_count: usize,
    round_out_of_domain_answer_count: usize,
    round_query_batches: Vec<AuthenticatedOpeningBatch>,
    /// Sumcheck rounds per fold batch, in batch order.
    fold_batch_round_counts: Vec<usize>,
    terminal_polynomial_evaluation_count: usize,
    terminal_query_batch: AuthenticatedOpeningBatch,
    plain_terminal_sumcheck_round_count: usize,
}

impl AggregateOpeningRoundGeometry {
    fn derive(configuration: &SelectedHidingWhirConfig) -> Self {
        let inner = &configuration.inner;
        let round_count = inner.n_rounds();
        let round_query_batches = inner
            .round_parameters
            .iter()
            .enumerate()
            .map(|(round_ordinal, parameters)| {
                let folding_factor = inner.round_folding_factor(round_ordinal);
                AuthenticatedOpeningBatch {
                    leaf_count: parameters.domain_size >> folding_factor,
                    opening_count: parameters.num_queries,
                    // Round zero opens the base-field row code; every later
                    // oracle lives in the challenge field.
                    challenge_values_per_opening: if round_ordinal == 0 {
                        0
                    } else {
                        1 << folding_factor
                    },
                    base_values_per_opening: if round_ordinal == 0 {
                        1 << folding_factor
                    } else {
                        0
                    },
                }
            })
            .collect::<Vec<_>>();
        let final_round = inner.final_round_config();
        let terminal_folding_factor = inner.round_folding_factor(round_count);
        Self {
            round_count,
            commitment_out_of_domain_answer_count: inner.commitment_ood_samples,
            round_out_of_domain_answer_count: inner
                .round_parameters
                .iter()
                .map(|parameters| parameters.ood_samples)
                .sum(),
            round_query_batches,
            fold_batch_round_counts: (0..=round_count)
                .map(|batch_ordinal| inner.round_folding_factor(batch_ordinal))
                .collect(),
            terminal_polynomial_evaluation_count: 1 << final_round.num_variables,
            terminal_query_batch: AuthenticatedOpeningBatch {
                leaf_count: final_round.domain_size >> terminal_folding_factor,
                opening_count: inner.final_queries,
                challenge_values_per_opening: 1 << terminal_folding_factor,
                base_values_per_opening: 0,
            },
            plain_terminal_sumcheck_round_count: inner.final_sumcheck_rounds,
        }
    }

    fn round_query_byte_length(&self) -> usize {
        self.round_query_batches
            .iter()
            .map(AuthenticatedOpeningBatch::byte_length)
            .sum()
    }
}

/// Derives the canonical byte ledger of the plain aggregate opening.
///
/// This is the section-by-section length of the argument production currently
/// emits, expressed with the same encoding rules the hiding ledger uses so the
/// two are directly comparable.
pub(in crate::bgv::proof_suite::row_code_whir) fn plain_aggregate_opening_byte_ledger(
    configuration: &SelectedHidingWhirConfig,
    opening_evaluation_count: usize,
) -> AggregateOpeningByteLedger {
    let geometry = AggregateOpeningRoundGeometry::derive(configuration);
    // Every plain sumcheck round sends two challenge-field coefficients, and the
    // terminal phase folds the remaining variables the same way.
    let sumcheck_round_count: usize = geometry.fold_batch_round_counts.iter().sum::<usize>()
        + geometry.plain_terminal_sumcheck_round_count;
    AggregateOpeningByteLedger {
        sections: vec![
            (
                AggregateOpeningSection::Framing,
                AGGREGATE_OPENING_FRAMING_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::OpeningEvaluations,
                opening_evaluation_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::CommitmentOutOfDomainAnswers,
                geometry.commitment_out_of_domain_answer_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::RoundCommitments,
                geometry.round_count * MERKLE_DIGEST_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::RoundOutOfDomainAnswers,
                geometry.round_out_of_domain_answer_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::RoundQueryOpenings,
                geometry.round_query_byte_length(),
            ),
            (
                AggregateOpeningSection::SumcheckWires,
                sumcheck_round_count * 2 * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::PlainFinalPolynomial,
                geometry.terminal_polynomial_evaluation_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::PlainFinalQueryOpenings,
                geometry.terminal_query_batch.byte_length(),
            ),
        ],
    }
}

/// Derives the canonical byte ledger of the hiding aggregate opening.
///
/// The hiding pipeline keeps the plain rounds and replaces the terminal direct
/// send with the masked base case. It adds one committed mask group per fold
/// batch and per code switch, one fresh mirror for each of them, one fresh main
/// mask, the one-time-pad reveals, and the mask spot checks.
pub(in crate::bgv::proof_suite::row_code_whir) fn hiding_aggregate_opening_byte_ledger(
    configuration: &SelectedHidingWhirConfig,
    census: &SelectedHidingMaskCensus,
    opening_evaluation_count: usize,
) -> AggregateOpeningByteLedger {
    let geometry = AggregateOpeningRoundGeometry::derive(configuration);
    // Each masked fold batch sends its mask-sum claim plus two coefficients per
    // sumcheck round, and the terminal variables are settled by the base case
    // rather than by further sumcheck rounds.
    let fold_batch_count = geometry.fold_batch_round_counts.len();
    let masked_sumcheck_element_count: usize =
        fold_batch_count + 2 * geometry.fold_batch_round_counts.iter().sum::<usize>();

    let source_openings = AuthenticatedOpeningBatch {
        leaf_count: census.source_code.codeword_domain_size,
        opening_count: census.source_spot_check_count,
        challenge_values_per_opening: geometry.terminal_query_batch.challenge_values_per_opening,
        base_values_per_opening: 0,
    };
    let fresh_main_openings = AuthenticatedOpeningBatch {
        leaf_count: census.source_code.codeword_domain_size,
        opening_count: census.source_spot_check_count,
        challenge_values_per_opening: 1,
        base_values_per_opening: 0,
    };
    // Each group opens the carried oracle and its fresh mirror at the same
    // positions, so a group contributes two independently rooted batches.
    let mask_group_opening_byte_length: usize = census
        .carried_groups
        .iter()
        .map(|group| {
            let batch = AuthenticatedOpeningBatch {
                leaf_count: group.codeword_domain_size,
                opening_count: census.mask_spot_check_count,
                challenge_values_per_opening: group.width,
                base_values_per_opening: 0,
            };
            2 * batch.byte_length()
        })
        .sum();

    let sumcheck_mask_group_count = census
        .carried_groups
        .iter()
        .filter(|group| matches!(group.owner, HidingMaskGroupOwner::SumcheckBatch { .. }))
        .count();
    let code_switch_mask_group_count = census.carried_group_count() - sumcheck_mask_group_count;

    AggregateOpeningByteLedger {
        sections: vec![
            (
                AggregateOpeningSection::Framing,
                AGGREGATE_OPENING_FRAMING_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::OpeningEvaluations,
                opening_evaluation_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::CommitmentOutOfDomainAnswers,
                geometry.commitment_out_of_domain_answer_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::RoundCommitments,
                geometry.round_count * MERKLE_DIGEST_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::RoundOutOfDomainAnswers,
                geometry.round_out_of_domain_answer_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::RoundQueryOpenings,
                geometry.round_query_byte_length(),
            ),
            (
                AggregateOpeningSection::SumcheckWires,
                masked_sumcheck_element_count * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::SumcheckMaskCommitments,
                sumcheck_mask_group_count * MERKLE_DIGEST_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::CodeSwitchMaskCommitments,
                code_switch_mask_group_count * MERKLE_DIGEST_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::BaseCaseFreshCommitments,
                (census.fresh_mirror_group_count() + 1) * MERKLE_DIGEST_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::BaseCaseMaskedClaim,
                CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::BaseCaseBlindedSourceReveals,
                (census.source_code.message_length + census.source_code.randomness_length)
                    * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::BaseCaseBlindedMaskReveals,
                (census.blinded_reveal_coefficient_count()
                    - census.source_code.message_length
                    - census.source_code.randomness_length)
                    * CHALLENGE_FIELD_WIRE_BYTE_LENGTH,
            ),
            (
                AggregateOpeningSection::BaseCaseSourceOpenings,
                source_openings.byte_length(),
            ),
            (
                AggregateOpeningSection::BaseCaseFreshMainOpenings,
                fresh_main_openings.byte_length(),
            ),
            (
                AggregateOpeningSection::BaseCaseMaskGroupOpenings,
                mask_group_opening_byte_length,
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        RowCodeWhirSelectedParameters, SELECTED_HIDING_MASK_LOG_INVERSE_RATE,
        SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH, SelectedHidingMaskCensus,
        selected_hiding_whir_config,
    };
    use super::*;
    use crate::bgv::proof_suite::row_code_whir::MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH;

    /// Aggregate columns the selected same-secret relation opens.
    ///
    /// The construction plan owns this value; pinning it here keeps the ledger
    /// arithmetic readable and fails loudly if the relation width moves.
    const SELECTED_OPENING_EVALUATION_COUNT: usize = 4_217;

    fn selected_configuration_and_census() -> (
        super::super::SelectedHidingWhirConfig,
        SelectedHidingMaskCensus,
    ) {
        let configuration = selected_hiding_whir_config(RowCodeWhirSelectedParameters::selected())
            .expect("the selected parameters admit a hiding configuration");
        let census = SelectedHidingMaskCensus::derive(&configuration);
        (configuration, census)
    }

    #[test]
    fn saturating_authentication_node_count_is_exact_on_small_trees() {
        // A single opening sends one sibling per level.
        assert_eq!(saturating_authentication_node_count(8, 1), 3);
        // Opening every leaf saturates every level below the root.
        assert_eq!(saturating_authentication_node_count(8, 8), 8 + 4 + 2);
        // Saturation clamps per level rather than per tree.
        assert_eq!(saturating_authentication_node_count(8, 3), 3 + 3 + 2);
        // A degenerate one-leaf tree authenticates nothing.
        assert_eq!(saturating_authentication_node_count(1, 4), 0);
    }

    /// Records the exact static cost of migrating to the hiding candidate.
    ///
    /// The plain ledger is the argument production emits today. The hiding
    /// ledger is the same rounds with the masked base case in place of the
    /// terminal direct send. Both use the canonical dictionary encoding, so the
    /// difference is the migration cost and not an encoding artifact.
    #[test]
    fn hiding_candidate_aggregate_opening_exceeds_the_plain_opening_by_its_mask_layer() {
        let (configuration, census) = selected_configuration_and_census();
        let plain =
            plain_aggregate_opening_byte_ledger(&configuration, SELECTED_OPENING_EVALUATION_COUNT);
        let hiding = hiding_aggregate_opening_byte_ledger(
            &configuration,
            &census,
            SELECTED_OPENING_EVALUATION_COUNT,
        );

        // The rounds are shared, so every round section matches exactly.
        for shared in [
            AggregateOpeningSection::Framing,
            AggregateOpeningSection::OpeningEvaluations,
            AggregateOpeningSection::CommitmentOutOfDomainAnswers,
            AggregateOpeningSection::RoundCommitments,
            AggregateOpeningSection::RoundOutOfDomainAnswers,
            AggregateOpeningSection::RoundQueryOpenings,
        ] {
            assert_eq!(
                plain.section_byte_length(shared),
                hiding.section_byte_length(shared),
                "{} diverged between the two ledgers",
                shared.identifier(),
            );
        }

        // The plain terminal phase is exactly what the base case replaces.
        let replaced_plain_terminal_byte_length = plain
            .section_byte_length(AggregateOpeningSection::PlainFinalPolynomial)
            + plain.section_byte_length(AggregateOpeningSection::PlainFinalQueryOpenings);
        assert!(replaced_plain_terminal_byte_length > 0);
        assert_eq!(
            hiding.section_byte_length(AggregateOpeningSection::PlainFinalPolynomial),
            0
        );
        assert_eq!(
            hiding.section_byte_length(AggregateOpeningSection::PlainFinalQueryOpenings),
            0
        );

        // The mask spot checks dominate the migration cost: nine carried groups
        // and their nine mirrors are each opened at 393 positions.
        let mask_group_opening_byte_length =
            hiding.section_byte_length(AggregateOpeningSection::BaseCaseMaskGroupOpenings);
        assert!(
            mask_group_opening_byte_length
                > hiding.section_byte_length(AggregateOpeningSection::RoundQueryOpenings),
        );

        // The exact ledgers. The rounds are identical, so the difference is the
        // mask layer alone.
        assert_eq!(plain.byte_length(), 1_772_880);
        assert_eq!(hiding.byte_length(), 5_395_996);
        let migration_byte_cost = hiding.byte_length() - plain.byte_length();
        assert_eq!(migration_byte_cost, HIDING_MIGRATION_BYTE_COST);

        // The candidate's own opening argument already exceeds the complete
        // proof selection gate, before any relation, phase, or bound-tree
        // payload is added. This is the decisive eligibility result.
        assert!(
            hiding.byte_length() > MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH,
            "hiding aggregate opening is {} bytes",
            hiding.byte_length(),
        );
        assert!(plain.byte_length() < MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH);

        // The migration budget is at most the margin the plain proof already
        // leaves under the gate, so the cost overruns it by an order of
        // magnitude rather than by a tunable amount.
        assert!(migration_byte_cost > 9 * PLAIN_PROOF_MARGIN_BELOW_SELECTION_GATE);
    }

    /// Bytes the hiding mask layer adds to the plain aggregate opening.
    const HIDING_MIGRATION_BYTE_COST: usize = 3_623_116;

    /// Margin the recorded plain same-secret proof leaves under the gate.
    ///
    /// The plain proof measured `4,842,836` bytes against the `5,242,880`-byte
    /// selection gate. Any masking layer has to fit inside that margin, because
    /// every other section of the stream is unchanged by the masking choice.
    const PLAIN_PROOF_MARGIN_BELOW_SELECTION_GATE: usize = 400_044;

    /// One searched hiding-parameter candidate.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct SearchedHidingCandidate {
        /// Opening bytes the candidate's masking layer adds to its own plain ledger.
        migration_byte_cost: usize,
        /// Complete hiding aggregate-opening bytes.
        hiding_opening_byte_length: usize,
        folding_factor: usize,
        sumcheck_mask_message_length: usize,
        mask_log_inverse_rate: usize,
    }

    /// Searches every admissible masking parameter for one that fits the gate.
    ///
    /// The search covers the sumcheck-mask message length, the mask inverse
    /// rate, and the folding factor, which is the construction-preserving
    /// packing choice that moves the round count and therefore the number of
    /// committed mask groups. Nothing that would weaken the argument is varied:
    /// the security level, the row-code rate, the soundness assumption, and the
    /// commitment variable count stay at their selected values, so every
    /// candidate carries the same query-count derivation the selection uses.
    #[test]
    fn no_admissible_hiding_parameter_fits_the_plain_proof_margin() {
        let selected = RowCodeWhirSelectedParameters::selected();
        let mut candidates = Vec::new();
        for folding_factor in 1..=8 {
            for sumcheck_mask_message_length in 3..=8 {
                for mask_log_inverse_rate in 1..=6 {
                    let parameters = RowCodeWhirSelectedParameters {
                        folding_factor,
                        ..selected
                    };
                    let mask_parameters = p3_whir::ZkParameters {
                        ell_zk: sumcheck_mask_message_length,
                        mask_log_inv_rate: mask_log_inverse_rate,
                    };
                    let Ok(configuration) = super::super::hiding_whir_config_with_mask_parameters(
                        parameters,
                        mask_parameters,
                    ) else {
                        continue;
                    };
                    let census = SelectedHidingMaskCensus::derive(&configuration);
                    let plain = plain_aggregate_opening_byte_ledger(
                        &configuration,
                        SELECTED_OPENING_EVALUATION_COUNT,
                    );
                    let hiding = hiding_aggregate_opening_byte_ledger(
                        &configuration,
                        &census,
                        SELECTED_OPENING_EVALUATION_COUNT,
                    );
                    candidates.push(SearchedHidingCandidate {
                        migration_byte_cost: hiding.byte_length() - plain.byte_length(),
                        hiding_opening_byte_length: hiding.byte_length(),
                        folding_factor,
                        sumcheck_mask_message_length,
                        mask_log_inverse_rate,
                    });
                }
            }
        }

        // The space is genuinely searched rather than degenerate.
        assert!(candidates.len() >= 200, "searched {}", candidates.len());
        candidates.sort_unstable();
        let cheapest = candidates[0];

        // Even the cheapest admissible masking layer costs far more than the
        // whole margin the plain proof leaves under the gate, so no parameter
        // choice inside this family makes the candidate eligible.
        assert!(
            cheapest.migration_byte_cost > 4 * PLAIN_PROOF_MARGIN_BELOW_SELECTION_GATE,
            "cheapest candidate {cheapest:?}",
        );
        assert_eq!(
            (
                cheapest.folding_factor,
                cheapest.sumcheck_mask_message_length,
                cheapest.mask_log_inverse_rate,
            ),
            (8, 3, 3),
        );
        assert_eq!(cheapest.migration_byte_cost, 1_658_836);

        // The selected geometry is not an outlier inside the searched family:
        // its cost is within a small factor of the cheapest one, so the refusal
        // is structural rather than a bad parameter choice.
        let selected_candidate = candidates
            .iter()
            .find(|candidate| {
                (
                    candidate.folding_factor,
                    candidate.sumcheck_mask_message_length,
                    candidate.mask_log_inverse_rate,
                ) == (
                    selected.folding_factor,
                    SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH,
                    SELECTED_HIDING_MASK_LOG_INVERSE_RATE,
                )
            })
            .copied()
            .expect("the selected parameters are inside the searched family");
        assert_eq!(
            selected_candidate.migration_byte_cost,
            HIDING_MIGRATION_BYTE_COST
        );
        assert!(selected_candidate.migration_byte_cost < 3 * cheapest.migration_byte_cost);
    }
}
