//! Commitment-before-challenge chronology for the compact public-key ledger.
//!
//! This owner expands the two CFW/WHIR epochs into verifier moves. Consecutive
//! raw samples with no intervening prover response are one verifier move, as
//! required by the interactive reduction rather than being miscounted as
//! independent rounds. Every move records the complete preceding commitment
//! count and its exact ideal challenge space. The catalog is descriptive: the
//! codec and transcript exist, but the compact prover and emitted-proof
//! verifier do not, so this module cannot authorize proof generation.

use num_bigint::BigUint;
use num_traits::{CheckedSub, One};

use super::cfw_reduction::CfwReductionCatalog;
use super::{
    CompactStaticCatalogError, GOLDILOCKS_BASE_FIELD_MODULUS,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, WhirStaticLedger, checked_add,
    checked_product,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TranscriptEpoch {
    PreChallenge,
    Main,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerifierMoveRole {
    LookupChallenge,
    CrossEpochPoint,
    CfwInitialRandomness,
    CfwSumcheckRound {
        round_ordinal: u32,
    },
    CfwJointConstraint,
    WhirOpeningBatching {
        epoch: TranscriptEpoch,
    },
    WhirMaskedSumcheckCombination {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    WhirFolding {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
        round_ordinal: u8,
    },
    WhirRoundQueryAndCombination {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    WhirBaseCombination {
        epoch: TranscriptEpoch,
    },
    WhirFinalQueries {
        epoch: TranscriptEpoch,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ExactChallengeSpace {
    ExtensionVector {
        element_count: u32,
        excluded_element_count: u64,
    },
    BaseElementExtensionVectorAndDistinctQueries {
        extension_element_count: u32,
        groups: Vec<DistinctQueryGeometry>,
    },
    ExtensionVectorAndDistinctQueries {
        extension_element_count: u32,
        groups: Vec<DistinctQueryGeometry>,
    },
    DistinctQueries {
        groups: Vec<DistinctQueryGeometry>,
    },
}

impl ExactChallengeSpace {
    pub(super) fn cardinality(&self) -> Result<BigUint, CompactStaticCatalogError> {
        let extension_field_order = extension_field_order();
        match self {
            Self::ExtensionVector {
                element_count,
                excluded_element_count,
            } => {
                let allowed = extension_field_order
                    .checked_sub(&BigUint::from(*excluded_element_count))
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                if allowed <= BigUint::one() || *element_count == 0 {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                Ok(allowed.pow(*element_count))
            }
            Self::BaseElementExtensionVectorAndDistinctQueries {
                extension_element_count,
                groups,
            } => {
                if *extension_element_count == 0 {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                distinct_query_space_cardinality(groups).map(|cardinality| {
                    cardinality
                        * GOLDILOCKS_BASE_FIELD_MODULUS
                        * extension_field_order.pow(*extension_element_count)
                })
            }
            Self::ExtensionVectorAndDistinctQueries {
                extension_element_count,
                groups,
            } => {
                if *extension_element_count == 0 {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                distinct_query_space_cardinality(groups).map(|cardinality| {
                    cardinality * extension_field_order.pow(*extension_element_count)
                })
            }
            Self::DistinctQueries { groups } => distinct_query_space_cardinality(groups),
        }
    }

    pub(super) fn distinct_query_groups(&self) -> &[DistinctQueryGeometry] {
        match self {
            Self::ExtensionVector { .. } => &[],
            Self::BaseElementExtensionVectorAndDistinctQueries { groups, .. }
            | Self::ExtensionVectorAndDistinctQueries { groups, .. }
            | Self::DistinctQueries { groups } => groups,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DistinctQueryGeometry {
    pub(super) domain_cardinality: u64,
    pub(super) query_count: u64,
}

impl DistinctQueryGeometry {
    pub(super) fn cardinality(self) -> Result<BigUint, CompactStaticCatalogError> {
        if self.domain_cardinality == 0
            || !self.domain_cardinality.is_power_of_two()
            || self.query_count == 0
            || self.query_count >= self.domain_cardinality
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let mut cardinality = BigUint::one();
        for selected_count in 1..=self.query_count {
            cardinality *= self.domain_cardinality - selected_count + 1;
            cardinality /= selected_count;
        }
        Ok(cardinality)
    }

    fn fixed_candidate_slot_count(self) -> Result<u64, CompactStaticCatalogError> {
        checked_product(&[
            self.query_count,
            u64::from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT),
        ])
    }
}

fn distinct_query_space_cardinality(
    groups: &[DistinctQueryGeometry],
) -> Result<BigUint, CompactStaticCatalogError> {
    if groups.is_empty() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    groups
        .iter()
        .try_fold(BigUint::one(), |cardinality, group| {
            group
                .cardinality()
                .map(|group_space| cardinality * group_space)
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifierMove {
    pub(super) ordinal: u32,
    pub(super) roles: Vec<VerifierMoveRole>,
    preceding_prover_response_ordinal: u32,
    preceding_commitment_count: u64,
    pub(super) challenge_space: ExactChallengeSpace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingTranscriptChronology {
    pub(super) verifier_moves: Vec<VerifierMove>,
    pub(super) distinct_query_group_count: u64,
    pub(super) fixed_query_candidate_slot_count: u64,
    commitment_count: u64,
    minimum_verifier_message_bit_length: u64,
    retry_attempt_domain_is_bound: bool,
    retry_uses_fresh_commitment_roots: bool,
}

impl PackingTranscriptChronology {
    pub(super) fn derive(
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let chronology = derive_catalog(pre_challenge_whir, main_whir, cfw_reduction)?;
        chronology.check(pre_challenge_whir, main_whir, cfw_reduction)?;
        Ok(chronology)
    }

    pub(super) fn logical_verifier_move_count(&self) -> Result<u64, CompactStaticCatalogError> {
        u64::try_from(self.verifier_moves.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)
    }

    fn check(
        &self,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected = derive_catalog(pre_challenge_whir, main_whir, cfw_reduction)?;
        if self != &expected
            || self.verifier_moves.is_empty()
            || self.commitment_count != 42
            || self.distinct_query_group_count != 24
            || self.minimum_verifier_message_bit_length != 319
            || self.retry_attempt_domain_is_bound
            || self.retry_uses_fresh_commitment_roots
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        for (ordinal, verifier_move) in self.verifier_moves.iter().enumerate() {
            if usize::try_from(verifier_move.ordinal).ok() != Some(ordinal)
                || verifier_move.roles.is_empty()
                || verifier_move.preceding_prover_response_ordinal == 0
                || verifier_move.preceding_commitment_count == 0
                || verifier_move.challenge_space.cardinality()? <= BigUint::one()
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
        }
        Ok(())
    }
}

fn derive_catalog(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<PackingTranscriptChronology, CompactStaticCatalogError> {
    let mut builder = ChronologyBuilder::new();
    append_outer_chronology(&mut builder, cfw_reduction)?;
    builder.record_combined_verifier_move(
        vec![
            VerifierMoveRole::CfwJointConstraint,
            VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::PreChallenge,
            },
        ],
        ExactChallengeSpace::ExtensionVector {
            element_count: cfw_reduction
                .joint_constraint_randomness_element_count()
                .checked_add(1)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            excluded_element_count: 0,
        },
    )?;
    append_whir_after_opening(
        &mut builder,
        TranscriptEpoch::PreChallenge,
        pre_challenge_whir,
        false,
    )?;
    builder.record_combined_verifier_move(
        vec![
            VerifierMoveRole::WhirFinalQueries {
                epoch: TranscriptEpoch::PreChallenge,
            },
            VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::Main,
            },
        ],
        ExactChallengeSpace::ExtensionVectorAndDistinctQueries {
            extension_element_count: 1,
            groups: final_query_groups(pre_challenge_whir),
        },
    )?;
    append_whir_after_opening(&mut builder, TranscriptEpoch::Main, main_whir, true)?;
    finish_catalog(builder)
}

fn append_outer_chronology(
    builder: &mut ChronologyBuilder,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<(), CompactStaticCatalogError> {
    builder.record_prover_response(0)?;
    builder.record_prover_response(1)?;
    builder.record_verifier_move(
        VerifierMoveRole::LookupChallenge,
        ExactChallengeSpace::ExtensionVector {
            element_count: 1,
            excluded_element_count: GOLDILOCKS_BASE_FIELD_MODULUS,
        },
    )?;
    builder.record_prover_response(1)?;
    builder.record_prover_response(1)?;
    builder.record_prover_response(1)?;
    builder.record_verifier_move(
        VerifierMoveRole::CrossEpochPoint,
        ExactChallengeSpace::ExtensionVector {
            element_count: super::CROSS_EPOCH_POINT_COORDINATE_COUNT,
            excluded_element_count: 0,
        },
    )?;
    builder.record_prover_response(0)?;
    builder.record_verifier_move(
        VerifierMoveRole::CfwInitialRandomness,
        ExactChallengeSpace::ExtensionVector {
            element_count: cfw_reduction.initial_randomness_element_count(),
            excluded_element_count: 0,
        },
    )?;
    for round_ordinal in 0..cfw_reduction.sumcheck_round_count() {
        builder.record_prover_response(0)?;
        builder.record_verifier_move(
            VerifierMoveRole::CfwSumcheckRound { round_ordinal },
            ExactChallengeSpace::ExtensionVector {
                element_count: cfw_reduction.per_round_randomness_element_count(),
                excluded_element_count: if round_ordinal + 1 == cfw_reduction.sumcheck_round_count()
                {
                    cfw_reduction.last_round_excluded_element_count()
                } else {
                    0
                },
            },
        )?;
    }
    builder.record_prover_response(0)
}

fn finish_catalog(
    builder: ChronologyBuilder,
) -> Result<PackingTranscriptChronology, CompactStaticCatalogError> {
    let distinct_query_group_count = builder
        .verifier_moves
        .iter()
        .map(|verifier_move| verifier_move.challenge_space.distinct_query_groups().len())
        .try_fold(0_u64, |count, group_count| {
            checked_add(
                count,
                u64::try_from(group_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
        })?;
    let fixed_query_candidate_slot_count = builder
        .verifier_moves
        .iter()
        .flat_map(|verifier_move| {
            verifier_move
                .challenge_space
                .distinct_query_groups()
                .iter()
                .copied()
        })
        .try_fold(0_u64, |count, group| {
            checked_add(count, group.fixed_candidate_slot_count()?)
        })?;
    let minimum_verifier_message_bit_length = builder
        .verifier_moves
        .iter()
        .map(|verifier_move| {
            verifier_move
                .challenge_space
                .cardinality()
                .map(|cardinality| cardinality.bits().saturating_sub(1))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    Ok(PackingTranscriptChronology {
        verifier_moves: builder.verifier_moves,
        distinct_query_group_count,
        fixed_query_candidate_slot_count,
        commitment_count: builder.commitment_count,
        minimum_verifier_message_bit_length,
        retry_attempt_domain_is_bound: false,
        retry_uses_fresh_commitment_roots: false,
    })
}

fn append_whir_after_opening(
    builder: &mut ChronologyBuilder,
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
    record_final_queries: bool,
) -> Result<(), CompactStaticCatalogError> {
    if whir.folding_schedule.len() != whir.query_counts.len()
        || whir.internal_mask_groups.len() != 7
        || (epoch == TranscriptEpoch::PreChallenge && !whir.external_mask_groups.is_empty())
        || (epoch == TranscriptEpoch::Main && whir.external_mask_groups.len() != 2)
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    builder.record_prover_response(1)?;
    builder.record_verifier_move(
        VerifierMoveRole::WhirMaskedSumcheckCombination {
            epoch,
            batch_ordinal: 0,
        },
        ExactChallengeSpace::ExtensionVector {
            element_count: 1,
            excluded_element_count: 0,
        },
    )?;
    append_folding_moves(builder, epoch, 0, whir.folding_schedule[0])?;

    for round_ordinal in 0..super::WHIR_ROUND_COUNT {
        builder.record_prover_response(2)?;
        builder.record_verifier_move(
            VerifierMoveRole::WhirRoundQueryAndCombination {
                epoch,
                round_ordinal: u8::try_from(round_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            ExactChallengeSpace::BaseElementExtensionVectorAndDistinctQueries {
                extension_element_count: 1,
                groups: vec![DistinctQueryGeometry {
                    domain_cardinality: whir.oracle_heights[round_ordinal],
                    query_count: whir.query_counts[round_ordinal],
                }],
            },
        )?;
        builder.record_prover_response(1)?;
        builder.record_verifier_move(
            VerifierMoveRole::WhirMaskedSumcheckCombination {
                epoch,
                batch_ordinal: u8::try_from(round_ordinal + 1)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            ExactChallengeSpace::ExtensionVector {
                element_count: 1,
                excluded_element_count: 0,
            },
        )?;
        append_folding_moves(
            builder,
            epoch,
            u8::try_from(round_ordinal + 1)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            whir.folding_schedule[round_ordinal + 1],
        )?;
    }

    let mask_groups = whir.mask_groups_in_commitment_order().collect::<Vec<_>>();
    builder.record_prover_response(
        1_u64
            .checked_add(
                u64::try_from(mask_groups.len())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
    )?;
    builder.record_verifier_move(
        VerifierMoveRole::WhirBaseCombination { epoch },
        ExactChallengeSpace::ExtensionVector {
            element_count: 1,
            excluded_element_count: 0,
        },
    )?;
    builder.record_prover_response(0)?;
    if record_final_queries {
        builder.record_verifier_move(
            VerifierMoveRole::WhirFinalQueries { epoch },
            ExactChallengeSpace::DistinctQueries {
                groups: final_query_groups(whir),
            },
        )?;
    }
    Ok(())
}

fn final_query_groups(whir: &WhirStaticLedger) -> Vec<DistinctQueryGeometry> {
    let mut groups = Vec::with_capacity(whir.mask_groups_in_commitment_order().count() + 1);
    groups.push(DistinctQueryGeometry {
        domain_cardinality: whir.oracle_heights[super::WHIR_ROUND_COUNT],
        query_count: whir.query_counts[super::WHIR_ROUND_COUNT],
    });
    groups.extend(
        whir.mask_groups_in_commitment_order()
            .map(|group| DistinctQueryGeometry {
                domain_cardinality: group.domain_size,
                query_count: whir.mask_query_count,
            }),
    );
    groups
}

fn append_folding_moves(
    builder: &mut ChronologyBuilder,
    epoch: TranscriptEpoch,
    batch_ordinal: u8,
    round_count: u32,
) -> Result<(), CompactStaticCatalogError> {
    if round_count == 0 || round_count > u32::from(u8::MAX) {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    for round_ordinal in 0..round_count {
        builder.record_prover_response(0)?;
        builder.record_verifier_move(
            VerifierMoveRole::WhirFolding {
                epoch,
                batch_ordinal,
                round_ordinal: u8::try_from(round_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            ExactChallengeSpace::ExtensionVector {
                element_count: 1,
                excluded_element_count: 0,
            },
        )?;
    }
    Ok(())
}

struct ChronologyBuilder {
    verifier_moves: Vec<VerifierMove>,
    prover_response_count: u32,
    commitment_count: u64,
    verifier_move_since_last_response: bool,
}

impl ChronologyBuilder {
    const fn new() -> Self {
        Self {
            verifier_moves: Vec::new(),
            prover_response_count: 0,
            commitment_count: 0,
            verifier_move_since_last_response: false,
        }
    }

    fn record_prover_response(
        &mut self,
        commitment_count: u64,
    ) -> Result<(), CompactStaticCatalogError> {
        self.prover_response_count = self
            .prover_response_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        self.commitment_count = checked_add(self.commitment_count, commitment_count)?;
        self.verifier_move_since_last_response = false;
        Ok(())
    }

    fn record_verifier_move(
        &mut self,
        role: VerifierMoveRole,
        challenge_space: ExactChallengeSpace,
    ) -> Result<(), CompactStaticCatalogError> {
        self.record_combined_verifier_move(vec![role], challenge_space)
    }

    fn record_combined_verifier_move(
        &mut self,
        roles: Vec<VerifierMoveRole>,
        challenge_space: ExactChallengeSpace,
    ) -> Result<(), CompactStaticCatalogError> {
        if self.prover_response_count == 0 || self.verifier_move_since_last_response {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        if roles.is_empty() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        challenge_space.cardinality()?;
        self.verifier_moves.push(VerifierMove {
            ordinal: u32::try_from(self.verifier_moves.len())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            roles,
            preceding_prover_response_ordinal: self.prover_response_count - 1,
            preceding_commitment_count: self.commitment_count,
            challenge_space,
        });
        self.verifier_move_since_last_response = true;
        Ok(())
    }
}

fn extension_field_order() -> BigUint {
    BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(super::QUINTIC_EXTENSION_DEGREE as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[test]
    fn every_packing_has_a_complete_two_epoch_predecessor_catalog() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_round_counts = [82, 80, 78, 76];
        let expected_candidate_slot_counts = [1_171_456, 1_191_424, 1_194_752, 1_202_176];
        for ((factor, expected_round_count), expected_candidate_slot_count) in catalog
            .factor_catalogs
            .iter()
            .zip(expected_round_counts)
            .zip(expected_candidate_slot_counts)
        {
            let chronology = &factor.transcript_chronology;
            assert_eq!(chronology.verifier_moves.len(), expected_round_count);
            assert_eq!(chronology.commitment_count, 42);
            assert_eq!(chronology.distinct_query_group_count, 24);
            assert_eq!(
                chronology.fixed_query_candidate_slot_count,
                expected_candidate_slot_count
            );
            assert_eq!(chronology.minimum_verifier_message_bit_length, 319);
            assert!(!chronology.retry_attempt_domain_is_bound);
            assert!(!chronology.retry_uses_fresh_commitment_roots);
        }
    }

    #[test]
    fn chronology_rejects_changed_predecessors_and_premature_retry_claims() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor = &catalog.factor_catalogs[3];

        let mut wrong_predecessor = factor.transcript_chronology.clone();
        wrong_predecessor.verifier_moves[1].preceding_commitment_count -= 1;
        assert_eq!(
            wrong_predecessor.check(
                &factor.pre_challenge_whir,
                &factor.main_whir,
                &catalog.cfw_reduction,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut premature_retry_claim = factor.transcript_chronology.clone();
        premature_retry_claim.retry_attempt_domain_is_bound = true;
        premature_retry_claim.retry_uses_fresh_commitment_roots = true;
        assert_eq!(
            premature_retry_claim.check(
                &factor.pre_challenge_whir,
                &factor.main_whir,
                &catalog.cfw_reduction,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }

    #[test]
    fn cfw_mask_roots_precede_every_cfw_challenge() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let chronology = &catalog.factor_catalogs[3].transcript_chronology;
        let cfw_moves = chronology.verifier_moves.iter().filter(|verifier_move| {
            verifier_move.roles.iter().any(|role| {
                matches!(
                    role,
                    VerifierMoveRole::CfwInitialRandomness
                        | VerifierMoveRole::CfwSumcheckRound { .. }
                        | VerifierMoveRole::CfwJointConstraint
                )
            })
        });
        assert_eq!(catalog.cfw_reduction.inner_mask_count(), 69);
        assert_eq!(catalog.cfw_reduction.outer_mask_count(), 23);
        assert!(
            cfw_moves
                .into_iter()
                .all(|verifier_move| { verifier_move.preceding_commitment_count >= 4 })
        );
    }

    #[test]
    fn every_whir_round_samples_queries_and_combination_in_one_verifier_move() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        for factor in &catalog.factor_catalogs {
            for epoch in [TranscriptEpoch::PreChallenge, TranscriptEpoch::Main] {
                let round_moves = factor
                    .transcript_chronology
                    .verifier_moves
                    .iter()
                    .filter(|verifier_move| {
                        verifier_move.roles.iter().any(|role| {
                            matches!(
                                role,
                                VerifierMoveRole::WhirRoundQueryAndCombination {
                                    epoch: move_epoch,
                                    ..
                                } if *move_epoch == epoch
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                assert_eq!(round_moves.len(), super::super::WHIR_ROUND_COUNT);
                for (round_ordinal, verifier_move) in round_moves.into_iter().enumerate() {
                    assert!(verifier_move.roles.iter().any(|role| {
                        matches!(
                            role,
                            VerifierMoveRole::WhirRoundQueryAndCombination {
                                round_ordinal: move_round_ordinal,
                                ..
                            } if usize::from(*move_round_ordinal) == round_ordinal
                        )
                    }));
                    assert!(matches!(
                        verifier_move.challenge_space,
                        ExactChallengeSpace::BaseElementExtensionVectorAndDistinctQueries {
                            extension_element_count: 1,
                            ref groups,
                        } if groups.len() == 1
                    ));
                }
            }
        }
    }

    #[test]
    fn challenges_without_an_intervening_response_share_one_verifier_move() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        for factor in &catalog.factor_catalogs {
            let combined_moves = factor
                .transcript_chronology
                .verifier_moves
                .iter()
                .filter(|verifier_move| verifier_move.roles.len() == 2)
                .collect::<Vec<_>>();
            assert_eq!(combined_moves.len(), 2);
            assert_eq!(
                combined_moves[0].roles,
                vec![
                    VerifierMoveRole::CfwJointConstraint,
                    VerifierMoveRole::WhirOpeningBatching {
                        epoch: TranscriptEpoch::PreChallenge,
                    },
                ]
            );
            assert!(matches!(
                combined_moves[0].challenge_space,
                ExactChallengeSpace::ExtensionVector {
                    element_count: 2,
                    excluded_element_count: 0,
                }
            ));
            assert_eq!(
                combined_moves[1].roles,
                vec![
                    VerifierMoveRole::WhirFinalQueries {
                        epoch: TranscriptEpoch::PreChallenge,
                    },
                    VerifierMoveRole::WhirOpeningBatching {
                        epoch: TranscriptEpoch::Main,
                    },
                ]
            );
            assert!(matches!(
                combined_moves[1].challenge_space,
                ExactChallengeSpace::ExtensionVectorAndDistinctQueries {
                    extension_element_count: 1,
                    ref groups,
                } if groups.len() == 8
            ));
        }
    }
}
