//! Exact interactive soundness ledger for the compact public-key slice.
//!
//! The rows below instantiate the unique-decoding round-by-round bounds of the
//! CFW R1CS reduction, masked sumcheck, code switching, and masked base case.
//! Every magnitude is a reduced exact rational. Query errors use integer
//! powers, and every algebraic row is tied to production-derived relation or
//! WHIR geometry. This is an interactive ledger only; hash compilation and its
//! post-quantum composition remain separate gate owners.

use num_bigint::BigUint;
use num_traits::{CheckedSub, One};

use super::cfw_reduction::CfwReductionCatalog;
use super::lifecycle::ExactProbability;
use super::transcript_chronology::{
    PackingTranscriptChronology, TranscriptEpoch, VerifierMoveRole,
};
use super::{
    CROSS_EPOCH_POINT_COORDINATE_COUNT, CompactStaticCatalogError, GOLDILOCKS_BASE_FIELD_MODULUS,
    INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL, MAIN_CODE_LOG_INVERSE_RATE,
    MASK_CODE_LOG_INVERSE_RATE, QUINTIC_EXTENSION_DEGREE, SUMCHECK_MASK_MESSAGE_LENGTH,
    WHIR_FOLD_BATCH_COUNT, WHIR_ROUND_COUNT, WhirStaticLedger,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;

#[derive(Clone, Debug, PartialEq, Eq)]
enum InteractiveFailureEvent {
    LookupMultisetIdentity,
    CrossEpochExplicitPoint,
    CfwInitialConsistency,
    CfwSumcheckRound {
        round_ordinal: u32,
    },
    CfwJointConstraint,
    WhirOpeningBatching {
        epoch: TranscriptEpoch,
    },
    WhirMaskedSumcheckInitial {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    WhirFold {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
        round_ordinal: u8,
        target_domain_size: u64,
    },
    WhirSourceQuery {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
        log_inverse_rate: u32,
        query_count: u64,
    },
    WhirRoundCombination {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
        combined_evaluation_count: u64,
    },
    WhirBaseCombination {
        epoch: TranscriptEpoch,
        source_domain_size: u64,
        mask_domain_size_sum: u64,
    },
    WhirMaskQuery {
        epoch: TranscriptEpoch,
        group_ordinal: u8,
        query_count: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactInteractiveFailureRow {
    event: InteractiveFailureEvent,
    numerator: BigUint,
    denominator: BigUint,
    probability: ExactProbability,
}

impl ExactInteractiveFailureRow {
    fn new(
        event: InteractiveFailureEvent,
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, CompactStaticCatalogError> {
        let probability = ExactProbability::new(numerator.clone(), denominator.clone())?;
        Ok(Self {
            event,
            numerator,
            denominator,
            probability,
        })
    }

    fn check(&self) -> Result<(), CompactStaticCatalogError> {
        if self.probability
            != ExactProbability::new(self.numerator.clone(), self.denominator.clone())?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhirInteractiveSoundness {
    epoch: TranscriptEpoch,
    rows: Vec<ExactInteractiveFailureRow>,
    source_query_branch_count: u64,
    mask_query_branch_count: u64,
    fold_failure_row_count: u64,
    union_bound: ExactProbability,
}

impl WhirInteractiveSoundness {
    fn derive(
        epoch: TranscriptEpoch,
        whir: &WhirStaticLedger,
        extension_field_order: &BigUint,
    ) -> Result<Self, CompactStaticCatalogError> {
        let mut rows = Vec::new();
        rows.push(ExactInteractiveFailureRow::new(
            InteractiveFailureEvent::WhirOpeningBatching { epoch },
            BigUint::from(
                whir.opening_batching_claim_count
                    .checked_sub(1)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
            ),
            extension_field_order.clone(),
        )?);

        let source_rates = [
            MAIN_CODE_LOG_INVERSE_RATE,
            whir.round_log_inverse_rates[0],
            whir.round_log_inverse_rates[1],
            whir.round_log_inverse_rates[2],
        ];
        let mut source_variable_count = whir.polynomial_variable_count;
        let mut fold_failure_row_count = 0_u64;
        for batch_ordinal in 0..WHIR_FOLD_BATCH_COUNT {
            rows.push(ExactInteractiveFailureRow::new(
                InteractiveFailureEvent::WhirMaskedSumcheckInitial {
                    epoch,
                    batch_ordinal: u8::try_from(batch_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                },
                BigUint::one(),
                extension_field_order.clone(),
            )?);

            let source_domain_exponent = source_variable_count
                .checked_add(source_rates[batch_ordinal])
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            let source_domain_size = 1_u64
                .checked_shl(source_domain_exponent)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            let folding_factor = whir.folding_schedule[batch_ordinal];
            for round_ordinal in 0..folding_factor {
                let target_domain_size = source_domain_size
                    .checked_shr(round_ordinal + 1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
                let failure_numerator = target_domain_size
                    .checked_add(SUMCHECK_MASK_MESSAGE_LENGTH)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
                rows.push(ExactInteractiveFailureRow::new(
                    InteractiveFailureEvent::WhirFold {
                        epoch,
                        batch_ordinal: u8::try_from(batch_ordinal)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                        round_ordinal: u8::try_from(round_ordinal)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                        target_domain_size,
                    },
                    BigUint::from(failure_numerator),
                    extension_field_order.clone(),
                )?);
                fold_failure_row_count = fold_failure_row_count
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            }
            let expected_committed_height = source_domain_size
                .checked_shr(folding_factor)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            if expected_committed_height != whir.oracle_heights[batch_ordinal] {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            source_variable_count = source_variable_count
                .checked_sub(folding_factor)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;

            let query_count = whir.query_counts[batch_ordinal];
            rows.push(query_failure_row(
                InteractiveFailureEvent::WhirSourceQuery {
                    epoch,
                    batch_ordinal: u8::try_from(batch_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    log_inverse_rate: source_rates[batch_ordinal],
                    query_count,
                },
                source_rates[batch_ordinal],
                query_count,
            )?);
            if batch_ordinal < WHIR_ROUND_COUNT {
                let combined_evaluation_count = query_count
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
                rows.push(ExactInteractiveFailureRow::new(
                    InteractiveFailureEvent::WhirRoundCombination {
                        epoch,
                        round_ordinal: u8::try_from(batch_ordinal)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                        combined_evaluation_count,
                    },
                    BigUint::from(combined_evaluation_count),
                    extension_field_order.clone(),
                )?);
            }
        }
        if source_variable_count != whir.final_variable_count {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let mask_groups = whir.mask_groups_in_commitment_order().collect::<Vec<_>>();
        let mask_domain_size_sum = mask_groups.iter().try_fold(0_u64, |sum, group| {
            sum.checked_add(group.domain_size)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
        })?;
        let source_domain_size = whir.oracle_heights[WHIR_ROUND_COUNT];
        let base_combination_numerator = source_domain_size
            .checked_add(mask_domain_size_sum)
            .and_then(|value| value.checked_add(1))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        rows.push(ExactInteractiveFailureRow::new(
            InteractiveFailureEvent::WhirBaseCombination {
                epoch,
                source_domain_size,
                mask_domain_size_sum,
            },
            BigUint::from(base_combination_numerator),
            extension_field_order.clone(),
        )?);

        for (group_ordinal, _) in mask_groups.iter().enumerate() {
            rows.push(query_failure_row(
                InteractiveFailureEvent::WhirMaskQuery {
                    epoch,
                    group_ordinal: u8::try_from(group_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    query_count: whir.mask_query_count,
                },
                MASK_CODE_LOG_INVERSE_RATE,
                whir.mask_query_count,
            )?);
        }

        let source_query_branch_count = u64::try_from(WHIR_FOLD_BATCH_COUNT)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let mask_query_branch_count = u64::try_from(mask_groups.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        if mask_query_branch_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?
            != whir.mask_query_union_branch_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let union_bound = sum_probabilities(&rows)?;
        let soundness = Self {
            epoch,
            rows,
            source_query_branch_count,
            mask_query_branch_count,
            fold_failure_row_count,
            union_bound,
        };
        soundness.check()?;
        Ok(soundness)
    }

    fn check(&self) -> Result<(), CompactStaticCatalogError> {
        if self.rows.is_empty()
            || self.rows.iter().any(|row| row.check().is_err())
            || self.union_bound != sum_probabilities(&self.rows)?
            || self.source_query_branch_count
                != u64::try_from(WHIR_FOLD_BATCH_COUNT)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactVerifierMoveFailure {
    ordinal: u32,
    roles: Vec<VerifierMoveRole>,
    contributing_event_count: u64,
    probability: ExactProbability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingInteractiveSoundness {
    outer_rows: Vec<ExactInteractiveFailureRow>,
    pre_challenge: WhirInteractiveSoundness,
    main: WhirInteractiveSoundness,
    interactive_failure_event_count: u64,
    verifier_move_failures: Vec<ExactVerifierMoveFailure>,
    interactive_union_bound: ExactProbability,
    maximum_verifier_move_failure: ExactProbability,
}

impl PackingInteractiveSoundness {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        transcript_chronology: &PackingTranscriptChronology,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let extension_field_order = extension_field_order();
        let outer_rows = outer_failure_rows(relation, cfw_reduction, &extension_field_order)?;
        let pre_challenge = WhirInteractiveSoundness::derive(
            TranscriptEpoch::PreChallenge,
            pre_challenge_whir,
            &extension_field_order,
        )?;
        let main = WhirInteractiveSoundness::derive(
            TranscriptEpoch::Main,
            main_whir,
            &extension_field_order,
        )?;
        let all_rows = outer_rows
            .iter()
            .chain(&pre_challenge.rows)
            .chain(&main.rows)
            .collect::<Vec<_>>();
        let interactive_failure_event_count = u64::try_from(all_rows.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let verifier_move_failures =
            derive_verifier_move_failures(transcript_chronology, &all_rows)?;
        let interactive_union_bound = sum_probability_references(&all_rows)?;
        let maximum_verifier_move_failure = maximum_verifier_move_failure(&verifier_move_failures);
        let soundness = Self {
            outer_rows,
            pre_challenge,
            main,
            interactive_failure_event_count,
            verifier_move_failures,
            interactive_union_bound,
            maximum_verifier_move_failure,
        };
        soundness.check(transcript_chronology)?;
        Ok(soundness)
    }

    pub(super) fn maximum_verifier_move_failure(&self) -> &ExactProbability {
        &self.maximum_verifier_move_failure
    }

    fn check(
        &self,
        transcript_chronology: &PackingTranscriptChronology,
    ) -> Result<(), CompactStaticCatalogError> {
        self.pre_challenge.check()?;
        self.main.check()?;
        if self.outer_rows.iter().any(|row| row.check().is_err()) {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let all_rows = self
            .outer_rows
            .iter()
            .chain(&self.pre_challenge.rows)
            .chain(&self.main.rows)
            .collect::<Vec<_>>();
        let expected_verifier_move_failures =
            derive_verifier_move_failures(transcript_chronology, &all_rows)?;
        let event_count_matches = self.interactive_failure_event_count
            == u64::try_from(all_rows.len())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let move_failures_match = self.verifier_move_failures == expected_verifier_move_failures;
        let move_count_matches =
            self.verifier_move_failures.len() == transcript_chronology.verifier_moves.len();
        let event_union_matches =
            self.interactive_union_bound == sum_probability_references(&all_rows)?;
        let maximum_matches = self.maximum_verifier_move_failure
            == maximum_verifier_move_failure(&self.verifier_move_failures);
        let move_union_matches = self.interactive_union_bound
            == sum_verifier_move_failure_probabilities(&self.verifier_move_failures)?;
        let event_union_meets_target = self
            .interactive_union_bound
            .is_at_most_inverse_power_of_two(256);
        let maximum_meets_target = self
            .maximum_verifier_move_failure
            .is_at_most_inverse_power_of_two(INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL as usize);
        if !(event_count_matches
            && move_failures_match
            && move_count_matches
            && event_union_matches
            && maximum_matches
            && move_union_matches
            && event_union_meets_target
            && maximum_meets_target)
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

fn derive_verifier_move_failures(
    transcript_chronology: &PackingTranscriptChronology,
    failure_rows: &[&ExactInteractiveFailureRow],
) -> Result<Vec<ExactVerifierMoveFailure>, CompactStaticCatalogError> {
    for failure_row in failure_rows {
        let matching_move_count = transcript_chronology
            .verifier_moves
            .iter()
            .filter(|verifier_move| {
                failure_event_belongs_to_verifier_move(&failure_row.event, &verifier_move.roles)
            })
            .count();
        if matching_move_count != 1 {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
    }

    transcript_chronology
        .verifier_moves
        .iter()
        .map(|verifier_move| {
            let contributing_rows = failure_rows
                .iter()
                .copied()
                .filter(|failure_row| {
                    failure_event_belongs_to_verifier_move(&failure_row.event, &verifier_move.roles)
                })
                .collect::<Vec<_>>();
            if contributing_rows.is_empty() {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            Ok(ExactVerifierMoveFailure {
                ordinal: verifier_move.ordinal,
                roles: verifier_move.roles.clone(),
                contributing_event_count: u64::try_from(contributing_rows.len())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                probability: sum_probability_references(&contributing_rows)?,
            })
        })
        .collect()
}

fn failure_event_belongs_to_verifier_move(
    failure_event: &InteractiveFailureEvent,
    verifier_move_roles: &[VerifierMoveRole],
) -> bool {
    verifier_move_roles
        .iter()
        .copied()
        .any(|verifier_move_role| {
            failure_event_belongs_to_verifier_move_role(failure_event, verifier_move_role)
        })
}

fn failure_event_belongs_to_verifier_move_role(
    failure_event: &InteractiveFailureEvent,
    verifier_move_role: VerifierMoveRole,
) -> bool {
    match (failure_event, verifier_move_role) {
        (InteractiveFailureEvent::LookupMultisetIdentity, VerifierMoveRole::LookupChallenge)
        | (InteractiveFailureEvent::CrossEpochExplicitPoint, VerifierMoveRole::CrossEpochPoint)
        | (
            InteractiveFailureEvent::CfwInitialConsistency,
            VerifierMoveRole::CfwInitialRandomness,
        )
        | (InteractiveFailureEvent::CfwJointConstraint, VerifierMoveRole::CfwJointConstraint) => {
            true
        }
        (
            InteractiveFailureEvent::CfwSumcheckRound {
                round_ordinal: event_round_ordinal,
            },
            VerifierMoveRole::CfwSumcheckRound {
                round_ordinal: move_round_ordinal,
            },
        ) => *event_round_ordinal == move_round_ordinal,
        (
            InteractiveFailureEvent::WhirOpeningBatching { epoch: event_epoch },
            VerifierMoveRole::WhirOpeningBatching { epoch: move_epoch },
        )
        | (
            InteractiveFailureEvent::WhirBaseCombination {
                epoch: event_epoch, ..
            },
            VerifierMoveRole::WhirBaseCombination { epoch: move_epoch },
        ) => *event_epoch == move_epoch,
        (
            InteractiveFailureEvent::WhirMaskedSumcheckInitial {
                epoch: event_epoch,
                batch_ordinal: event_batch_ordinal,
            },
            VerifierMoveRole::WhirMaskedSumcheckCombination {
                epoch: move_epoch,
                batch_ordinal: move_batch_ordinal,
            },
        ) => *event_epoch == move_epoch && *event_batch_ordinal == move_batch_ordinal,
        (
            InteractiveFailureEvent::WhirFold {
                epoch: event_epoch,
                batch_ordinal: event_batch_ordinal,
                round_ordinal: event_round_ordinal,
                ..
            },
            VerifierMoveRole::WhirFolding {
                epoch: move_epoch,
                batch_ordinal: move_batch_ordinal,
                round_ordinal: move_round_ordinal,
            },
        ) => {
            *event_epoch == move_epoch
                && *event_batch_ordinal == move_batch_ordinal
                && *event_round_ordinal == move_round_ordinal
        }
        (
            InteractiveFailureEvent::WhirSourceQuery {
                epoch: event_epoch,
                batch_ordinal: event_batch_ordinal,
                ..
            },
            VerifierMoveRole::WhirRoundQueryAndCombination {
                epoch: move_epoch,
                round_ordinal: move_round_ordinal,
            },
        ) => *event_epoch == move_epoch && *event_batch_ordinal == move_round_ordinal,
        (
            InteractiveFailureEvent::WhirRoundCombination {
                epoch: event_epoch,
                round_ordinal: event_round_ordinal,
                ..
            },
            VerifierMoveRole::WhirRoundQueryAndCombination {
                epoch: move_epoch,
                round_ordinal: move_round_ordinal,
            },
        ) => *event_epoch == move_epoch && *event_round_ordinal == move_round_ordinal,
        (
            InteractiveFailureEvent::WhirSourceQuery {
                epoch: event_epoch,
                batch_ordinal,
                ..
            },
            VerifierMoveRole::WhirFinalQueries { epoch: move_epoch },
        ) => *event_epoch == move_epoch && usize::from(*batch_ordinal) == WHIR_ROUND_COUNT,
        (
            InteractiveFailureEvent::WhirMaskQuery {
                epoch: event_epoch, ..
            },
            VerifierMoveRole::WhirFinalQueries { epoch: move_epoch },
        ) => *event_epoch == move_epoch,
        _ => false,
    }
}

fn outer_failure_rows(
    relation: &CompactPublicKeyRelationCatalog,
    cfw_reduction: &CfwReductionCatalog,
    extension_field_order: &BigUint,
) -> Result<Vec<ExactInteractiveFailureRow>, CompactStaticCatalogError> {
    let lookup_challenge_space = extension_field_order
        .checked_sub(&BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS))
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let mut rows = vec![
        ExactInteractiveFailureRow::new(
            InteractiveFailureEvent::LookupMultisetIdentity,
            BigUint::from(relation.lookup_soundness_numerator()),
            lookup_challenge_space,
        )?,
        ExactInteractiveFailureRow::new(
            InteractiveFailureEvent::CrossEpochExplicitPoint,
            BigUint::from(CROSS_EPOCH_POINT_COORDINATE_COUNT),
            extension_field_order.clone(),
        )?,
        ExactInteractiveFailureRow::new(
            InteractiveFailureEvent::CfwInitialConsistency,
            BigUint::from(cfw_reduction.initial_consistency_soundness_numerator()),
            extension_field_order.clone(),
        )?,
    ];
    for round_ordinal in 0..cfw_reduction.sumcheck_round_count() {
        let denominator = if round_ordinal + 1 == cfw_reduction.sumcheck_round_count() {
            extension_field_order
                .checked_sub(&BigUint::from(
                    cfw_reduction.last_round_excluded_element_count(),
                ))
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?
        } else {
            extension_field_order.clone()
        };
        rows.push(ExactInteractiveFailureRow::new(
            InteractiveFailureEvent::CfwSumcheckRound { round_ordinal },
            BigUint::from(cfw_reduction.per_round_soundness_numerator()),
            denominator,
        )?);
    }
    rows.push(ExactInteractiveFailureRow::new(
        InteractiveFailureEvent::CfwJointConstraint,
        BigUint::from(cfw_reduction.joint_constraint_soundness_numerator()),
        extension_field_order.clone(),
    )?);
    Ok(rows)
}

fn query_failure_row(
    event: InteractiveFailureEvent,
    log_inverse_rate: u32,
    query_count: u64,
) -> Result<ExactInteractiveFailureRow, CompactStaticCatalogError> {
    let numerator = BigUint::from(
        (1_u64 << log_inverse_rate)
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
    )
    .pow(u32::try_from(query_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?);
    let denominator = BigUint::from(1_u64 << (log_inverse_rate + 1)).pow(
        u32::try_from(query_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    );
    ExactInteractiveFailureRow::new(event, numerator, denominator)
}

fn query_failure_probability(
    log_inverse_rate: u32,
    query_count: u64,
) -> Result<ExactProbability, CompactStaticCatalogError> {
    let one_query = ExactProbability::new(
        BigUint::from(
            (1_u64 << log_inverse_rate)
                .checked_add(1)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
        ),
        BigUint::from(1_u64 << (log_inverse_rate + 1)),
    )?;
    one_query.power(
        u32::try_from(query_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    )
}

fn sum_probabilities(
    rows: &[ExactInteractiveFailureRow],
) -> Result<ExactProbability, CompactStaticCatalogError> {
    let references = rows.iter().collect::<Vec<_>>();
    sum_probability_references(&references)
}

fn sum_probability_references(
    rows: &[&ExactInteractiveFailureRow],
) -> Result<ExactProbability, CompactStaticCatalogError> {
    rows.iter().try_fold(ExactProbability::zero(), |sum, row| {
        sum.add(&row.probability)
    })
}

fn sum_verifier_move_failure_probabilities(
    verifier_move_failures: &[ExactVerifierMoveFailure],
) -> Result<ExactProbability, CompactStaticCatalogError> {
    verifier_move_failures
        .iter()
        .try_fold(ExactProbability::zero(), |sum, verifier_move_failure| {
            sum.add(&verifier_move_failure.probability)
        })
}

fn maximum_verifier_move_failure(
    verifier_move_failures: &[ExactVerifierMoveFailure],
) -> ExactProbability {
    verifier_move_failures.iter().fold(
        ExactProbability::zero(),
        |maximum, verifier_move_failure| {
            if verifier_move_failure.probability.is_greater_than(&maximum) {
                verifier_move_failure.probability.clone()
            } else {
                maximum
            }
        },
    )
}

fn extension_field_order() -> BigUint {
    BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(QUINTIC_EXTENSION_DEGREE as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[test]
    fn every_packing_has_a_complete_exact_interactive_error_vector() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_event_counts = [106, 104, 102, 100];
        let expected_verifier_move_counts = [82, 80, 78, 76];
        for ((factor, expected_event_count), expected_verifier_move_count) in catalog
            .factor_catalogs
            .iter()
            .zip(expected_event_counts)
            .zip(expected_verifier_move_counts)
        {
            let soundness = &factor.interactive_soundness;
            assert_eq!(
                soundness.interactive_failure_event_count,
                expected_event_count
            );
            assert_eq!(
                soundness.verifier_move_failures.len(),
                expected_verifier_move_count
            );
            assert_eq!(soundness.outer_rows.len(), 27);
            assert_eq!(soundness.pre_challenge.mask_query_branch_count, 7);
            assert_eq!(soundness.main.mask_query_branch_count, 9);
            assert!(
                soundness
                    .interactive_union_bound
                    .is_at_most_inverse_power_of_two(256)
            );
            assert!(
                soundness
                    .maximum_verifier_move_failure
                    .is_at_most_inverse_power_of_two(
                        INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL as usize,
                    )
            );
        }
    }

    #[test]
    fn main_relation_batching_covers_every_cfw_claim_and_explicit_opening() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        for factor in &catalog.factor_catalogs {
            assert_eq!(factor.pre_challenge_whir.opening_batching_claim_count, 1);
            assert_eq!(factor.main_whir.opening_batching_claim_count, 164);

            let pre_challenge_batching = factor
                .interactive_soundness
                .pre_challenge
                .rows
                .iter()
                .find(|row| {
                    row.event
                        == InteractiveFailureEvent::WhirOpeningBatching {
                            epoch: TranscriptEpoch::PreChallenge,
                        }
                })
                .expect("pre-challenge opening-batching row");
            assert_eq!(pre_challenge_batching.numerator, BigUint::from(0_u8));

            let main_batching = factor
                .interactive_soundness
                .main
                .rows
                .iter()
                .find(|row| {
                    row.event
                        == InteractiveFailureEvent::WhirOpeningBatching {
                            epoch: TranscriptEpoch::Main,
                        }
                })
                .expect("main opening-batching row");
            assert_eq!(main_batching.numerator, BigUint::from(163_u16));
            assert_eq!(main_batching.denominator, extension_field_order());
        }
    }

    #[test]
    fn soundness_ledger_rejects_a_changed_failure_magnitude() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor = &catalog.factor_catalogs[3];
        let mut soundness = factor.interactive_soundness.clone();
        soundness.outer_rows[0].numerator += BigUint::one();
        assert_eq!(
            soundness.check(&factor.transcript_chronology),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }

    #[test]
    fn query_failures_are_grouped_by_the_actual_verifier_move() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        for factor in &catalog.factor_catalogs {
            let soundness = &factor.interactive_soundness;
            let combined_round_failures = soundness
                .verifier_move_failures
                .iter()
                .filter(|verifier_move_failure| {
                    matches!(
                        verifier_move_failure.roles.as_slice(),
                        [VerifierMoveRole::WhirRoundQueryAndCombination { .. }]
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(combined_round_failures.len(), 2 * WHIR_ROUND_COUNT);
            assert!(combined_round_failures.iter().all(|verifier_move_failure| {
                verifier_move_failure.contributing_event_count == 2
            }));

            let final_query_failures = soundness
                .verifier_move_failures
                .iter()
                .filter(|verifier_move_failure| {
                    verifier_move_failure
                        .roles
                        .iter()
                        .any(|role| matches!(role, VerifierMoveRole::WhirFinalQueries { .. }))
                })
                .collect::<Vec<_>>();
            assert_eq!(final_query_failures.len(), 2);
            assert!(final_query_failures.iter().any(|verifier_move_failure| {
                verifier_move_failure
                    .roles
                    .contains(&VerifierMoveRole::WhirFinalQueries {
                        epoch: TranscriptEpoch::PreChallenge,
                    })
                    && verifier_move_failure.contributing_event_count == 9
            }));
            assert!(final_query_failures.iter().any(|verifier_move_failure| {
                verifier_move_failure
                    .roles
                    .contains(&VerifierMoveRole::WhirFinalQueries {
                        epoch: TranscriptEpoch::Main,
                    })
                    && verifier_move_failure.contributing_event_count == 10
            }));
        }
    }

    #[test]
    fn main_mask_queries_cover_all_ten_base_query_branches() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        for factor in &catalog.factor_catalogs {
            let main = &factor.main_whir;
            assert_eq!(main.mask_query_union_branch_count, 10);
            assert_eq!(main.mask_query_count, 399);
            let branch_probability =
                query_failure_probability(MASK_CODE_LOG_INVERSE_RATE, main.mask_query_count)
                    .expect("exact mask query probability");
            assert!(
                branch_probability
                    .scale(&BigUint::from(main.mask_query_union_branch_count))
                    .expect("exact union ceiling")
                    .is_at_most_inverse_power_of_two(
                        INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL as usize,
                    )
            );
        }
    }
}
