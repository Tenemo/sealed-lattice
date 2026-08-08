//! One executable dispatcher for every verifier move in the factor-one
//! chronology.
//!
//! The chronology catalog supplies only the move ordinal, challenge space, and
//! dependency barrier. This module binds each such entry to a concrete
//! semantic owner and dispatches `KState`, deterministic backward extraction,
//! and bad-transition derivation to the corresponding CFW or WHIR algorithm.
//! A role label by itself never produces an accepting result.

use super::super::{
    CROSS_EPOCH_POINT_COORDINATE_COUNT, CodeRole, ExactChallengeSpace, ExactProbability,
    GOLDILOCKS_BASE_FIELD_MODULUS, RelaxedRoundByRoundCatalog, TranscriptEpoch, UniqueDecodingCode,
    VerifierMoveRole, WHIR_ROUND_COUNT,
};
use super::semantic_composition::{
    SemanticCfwAndPreWhirOpeningBadTransition, SemanticCfwAndPreWhirOpeningPrefix,
    SemanticCfwAndPreWhirOpeningStatement, SemanticCfwAndPreWhirOpeningWitness,
    SemanticCompositionError, SemanticPreWhirFinalAndMainOpeningBadTransition,
    SemanticPreWhirFinalAndMainOpeningPrefix, SemanticPreWhirFinalAndMainOpeningStatement,
    SemanticPreWhirFinalAndMainOpeningWitness, semantic_cfw_and_pre_whir_opening_bad_transition,
    semantic_cfw_and_pre_whir_opening_errbr, semantic_cfw_and_pre_whir_opening_kstate,
    semantic_pre_whir_final_and_main_opening_bad_transition,
    semantic_pre_whir_final_and_main_opening_errbr,
    semantic_pre_whir_final_and_main_opening_kstate,
};
use super::semantic_error_bounds::derive_bad_transition_certificate_events;
use super::semantic_outer::{
    SemanticOuterError, SemanticProductionOuterBadTransition, SemanticProductionOuterPrefix,
    SemanticProductionOuterStatement, SemanticProductionOuterWitness,
    semantic_production_outer_bad_transition, semantic_production_outer_errbr,
    semantic_production_outer_kstate,
};
use super::semantic_whir::{
    SemanticWhirBadTransition, SemanticWhirBaseCombinationBadTransition,
    SemanticWhirBaseKnowledgeWitness, SemanticWhirBasePrefix, SemanticWhirBaseQueryEscape,
    SemanticWhirBaseStatement, SemanticWhirCodeSwitchBadTransition, SemanticWhirCodeSwitchPrefix,
    SemanticWhirCodeSwitchStatement, SemanticWhirError, SemanticWhirMaskedSumcheckPrefix,
    SemanticWhirMaskedSumcheckStatement, SemanticWhirOpeningBatchingPrefix,
    SemanticWhirOpeningBatchingStatement, semantic_whir_base_combination_bad_transition,
    semantic_whir_base_combination_errbr, semantic_whir_base_final_bad_transition,
    semantic_whir_base_final_errbr, semantic_whir_base_kstate,
    semantic_whir_code_switch_bad_transition, semantic_whir_code_switch_errbr,
    semantic_whir_code_switch_kstate, semantic_whir_masked_sumcheck_bad_transition,
    semantic_whir_masked_sumcheck_errbr, semantic_whir_masked_sumcheck_kstate,
};
use super::*;

const FACTOR_ONE_VERIFIER_MOVE_COUNT: usize = 82;
const FACTOR_ONE_CFW_SUMCHECK_ROUND_COUNT: usize = 23;
const FACTOR_ONE_WHIR_FOLDING_MOVE_COUNT: usize = 37;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticVerifierMoveOwner {
    LookupChallenge,
    CrossEpochPoint,
    CfwInitialRandomness,
    CfwSumcheckRound {
        round_ordinal: u32,
    },
    CfwJointAndPreWhirOpening,
    WhirMaskedSumcheckCombination {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    WhirFolding {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
        round_ordinal: u8,
    },
    WhirCodeSwitch {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    WhirBaseCombination {
        epoch: TranscriptEpoch,
    },
    PreWhirFinalAndMainWhirOpening,
    MainWhirFinalQueries,
}

impl SemanticVerifierMoveOwner {
    fn from_roles(roles: &[VerifierMoveRole]) -> Option<Self> {
        match roles {
            [VerifierMoveRole::LookupChallenge] => Some(Self::LookupChallenge),
            [VerifierMoveRole::CrossEpochPoint] => Some(Self::CrossEpochPoint),
            [VerifierMoveRole::CfwInitialRandomness] => Some(Self::CfwInitialRandomness),
            [VerifierMoveRole::CfwSumcheckRound { round_ordinal }] => {
                Some(Self::CfwSumcheckRound {
                    round_ordinal: *round_ordinal,
                })
            }
            [
                VerifierMoveRole::CfwJointConstraint,
                VerifierMoveRole::WhirOpeningBatching {
                    epoch: TranscriptEpoch::PreChallenge,
                },
            ] => Some(Self::CfwJointAndPreWhirOpening),
            [
                VerifierMoveRole::WhirMaskedSumcheckCombination {
                    epoch,
                    batch_ordinal,
                },
            ] => Some(Self::WhirMaskedSumcheckCombination {
                epoch: *epoch,
                batch_ordinal: *batch_ordinal,
            }),
            [
                VerifierMoveRole::WhirFolding {
                    epoch,
                    batch_ordinal,
                    round_ordinal,
                },
            ] => Some(Self::WhirFolding {
                epoch: *epoch,
                batch_ordinal: *batch_ordinal,
                round_ordinal: *round_ordinal,
            }),
            [
                VerifierMoveRole::WhirRoundQueryAndCombination {
                    epoch,
                    round_ordinal,
                },
            ] => Some(Self::WhirCodeSwitch {
                epoch: *epoch,
                round_ordinal: *round_ordinal,
            }),
            [VerifierMoveRole::WhirBaseCombination { epoch }] => {
                Some(Self::WhirBaseCombination { epoch: *epoch })
            }
            [
                VerifierMoveRole::WhirFinalQueries {
                    epoch: TranscriptEpoch::PreChallenge,
                },
                VerifierMoveRole::WhirOpeningBatching {
                    epoch: TranscriptEpoch::Main,
                },
            ] => Some(Self::PreWhirFinalAndMainWhirOpening),
            [
                VerifierMoveRole::WhirFinalQueries {
                    epoch: TranscriptEpoch::Main,
                },
            ] => Some(Self::MainWhirFinalQueries),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticFactorOneMoveDescriptor {
    verifier_move_ordinal: u32,
    owner: SemanticVerifierMoveOwner,
    preceding_prover_response_ordinal: u32,
    preceding_commitment_count: u64,
    challenge_space: ExactChallengeSpace,
    extraction_error: ExactProbability,
    extraction_field_operation_bound: u128,
    extraction_non_field_operation_bound: u128,
    extraction_operation_bound: u128,
}

impl SemanticFactorOneMoveDescriptor {
    pub(super) const fn verifier_move_ordinal(&self) -> u32 {
        self.verifier_move_ordinal
    }

    pub(super) const fn owner(&self) -> SemanticVerifierMoveOwner {
        self.owner
    }

    pub(super) const fn preceding_prover_response_ordinal(&self) -> u32 {
        self.preceding_prover_response_ordinal
    }

    pub(super) const fn preceding_commitment_count(&self) -> u64 {
        self.preceding_commitment_count
    }

    pub(super) const fn challenge_space(&self) -> &ExactChallengeSpace {
        &self.challenge_space
    }

    pub(super) const fn extraction_error(&self) -> &ExactProbability {
        &self.extraction_error
    }

    pub(super) const fn extraction_field_operation_bound(&self) -> u128 {
        self.extraction_field_operation_bound
    }

    pub(super) const fn extraction_non_field_operation_bound(&self) -> u128 {
        self.extraction_non_field_operation_bound
    }

    pub(super) const fn extraction_operation_bound(&self) -> u128 {
        self.extraction_operation_bound
    }

    #[cfg(test)]
    pub(super) fn for_focused_test(owner: SemanticVerifierMoveOwner) -> Self {
        Self {
            verifier_move_ordinal: 0,
            owner,
            preceding_prover_response_ordinal: 1,
            preceding_commitment_count: 1,
            challenge_space: ExactChallengeSpace::ExtensionVector {
                element_count: 1,
                excluded_element_count: 0,
            },
            extraction_error: ExactProbability::new(1_u8.into(), 1_u8.into())
                .expect("one is an exact probability"),
            extraction_field_operation_bound: u128::MAX,
            extraction_non_field_operation_bound: u128::MAX,
            extraction_operation_bound: u128::MAX,
        }
    }

    #[cfg(test)]
    pub(super) fn with_field_operation_bound_for_focused_test(
        mut self,
        extraction_field_operation_bound: u128,
    ) -> Self {
        self.extraction_field_operation_bound = extraction_field_operation_bound;
        self
    }

    #[cfg(test)]
    pub(super) fn with_extraction_error_for_focused_test(
        mut self,
        extraction_error: ExactProbability,
    ) -> Self {
        self.extraction_error = extraction_error;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticFactorOneSchedule {
    moves: Vec<SemanticFactorOneMoveDescriptor>,
}

impl SemanticFactorOneSchedule {
    pub(super) fn from_catalog(
        catalog: &RelaxedRoundByRoundCatalog,
    ) -> Result<Self, SemanticExecutionError> {
        if catalog.transitions.len() != FACTOR_ONE_VERIFIER_MOVE_COUNT
            || usize::try_from(catalog.cfw.sumcheck_round_count).ok()
                != Some(FACTOR_ONE_CFW_SUMCHECK_ROUND_COUNT)
        {
            return Err(SemanticExecutionError::InvalidFactorOneSchedule);
        }
        let mut moves = Vec::with_capacity(catalog.transitions.len());
        for (expected_ordinal, transition) in catalog.transitions.iter().enumerate() {
            let owner = SemanticVerifierMoveOwner::from_roles(&transition.roles)
                .ok_or(SemanticExecutionError::InvalidFactorOneSchedule)?;
            if usize::try_from(transition.verifier_move_ordinal).ok() != Some(expected_ordinal)
                || !challenge_space_matches_owner(owner, &transition.challenge_space, catalog)
                || transition
                    .extraction_field_operation_bound
                    .checked_add(transition.extraction_non_field_operation_bound)
                    != Some(transition.extraction_operation_bound)
            {
                return Err(SemanticExecutionError::InvalidFactorOneSchedule);
            }
            moves.push(SemanticFactorOneMoveDescriptor {
                verifier_move_ordinal: transition.verifier_move_ordinal,
                owner,
                preceding_prover_response_ordinal: transition.preceding_prover_response_ordinal,
                preceding_commitment_count: transition.preceding_commitment_count,
                challenge_space: transition.challenge_space.clone(),
                extraction_error: transition.extraction_error.clone(),
                extraction_field_operation_bound: transition.extraction_field_operation_bound,
                extraction_non_field_operation_bound: transition
                    .extraction_non_field_operation_bound,
                extraction_operation_bound: transition.extraction_operation_bound,
            });
        }
        let schedule = Self { moves };
        schedule.check_owner_chronology(catalog)?;
        Ok(schedule)
    }

    pub(super) fn moves(&self) -> &[SemanticFactorOneMoveDescriptor] {
        &self.moves
    }

    pub(super) fn move_at(
        &self,
        verifier_move_ordinal: u32,
    ) -> Result<&SemanticFactorOneMoveDescriptor, SemanticExecutionError> {
        self.moves
            .get(
                usize::try_from(verifier_move_ordinal)
                    .map_err(|_| SemanticExecutionError::ArithmeticOverflow)?,
            )
            .filter(|descriptor| descriptor.verifier_move_ordinal == verifier_move_ordinal)
            .ok_or(SemanticExecutionError::InvalidFactorOneSchedule)
    }

    fn check_owner_chronology(
        &self,
        catalog: &RelaxedRoundByRoundCatalog,
    ) -> Result<(), SemanticExecutionError> {
        let expected_owners = expected_factor_one_owner_chronology(catalog)?;
        let actual_owners = self
            .moves
            .iter()
            .map(|descriptor| descriptor.owner)
            .collect::<Vec<_>>();
        if actual_owners != expected_owners
            || expected_owners.len() != FACTOR_ONE_VERIFIER_MOVE_COUNT
            || expected_owners
                .iter()
                .filter(|owner| matches!(owner, SemanticVerifierMoveOwner::WhirFolding { .. }))
                .count()
                != FACTOR_ONE_WHIR_FOLDING_MOVE_COUNT
            || self.moves.windows(2).any(|moves| {
                moves[0].preceding_prover_response_ordinal
                    > moves[1].preceding_prover_response_ordinal
                    || moves[0].preceding_commitment_count > moves[1].preceding_commitment_count
            })
        {
            return Err(SemanticExecutionError::InvalidFactorOneSchedule);
        }
        Ok(())
    }
}

fn expected_factor_one_owner_chronology(
    catalog: &RelaxedRoundByRoundCatalog,
) -> Result<Vec<SemanticVerifierMoveOwner>, SemanticExecutionError> {
    let mut owners = Vec::with_capacity(FACTOR_ONE_VERIFIER_MOVE_COUNT);
    owners.push(SemanticVerifierMoveOwner::LookupChallenge);
    owners.push(SemanticVerifierMoveOwner::CrossEpochPoint);
    owners.push(SemanticVerifierMoveOwner::CfwInitialRandomness);
    for round_ordinal in 0..catalog.cfw.sumcheck_round_count {
        owners.push(SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal });
    }
    owners.push(SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening);
    append_expected_whir_owner_chronology(&mut owners, catalog, TranscriptEpoch::PreChallenge)?;
    owners.push(SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening);
    append_expected_whir_owner_chronology(&mut owners, catalog, TranscriptEpoch::Main)?;
    owners.push(SemanticVerifierMoveOwner::MainWhirFinalQueries);
    Ok(owners)
}

fn append_expected_whir_owner_chronology(
    owners: &mut Vec<SemanticVerifierMoveOwner>,
    catalog: &RelaxedRoundByRoundCatalog,
    epoch: TranscriptEpoch,
) -> Result<(), SemanticExecutionError> {
    let mut accounted_folding_moves = 0_usize;
    for batch_ordinal in 0..=WHIR_ROUND_COUNT {
        let batch_ordinal =
            u8::try_from(batch_ordinal).map_err(|_| SemanticExecutionError::ArithmeticOverflow)?;
        owners.push(SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
            epoch,
            batch_ordinal,
        });
        let mut round_ordinals = catalog
            .whir_mca_bounds
            .iter()
            .filter(|bound| bound.epoch == epoch && bound.batch_ordinal == batch_ordinal)
            .map(|bound| bound.round_ordinal)
            .collect::<Vec<_>>();
        round_ordinals.sort_unstable();
        if round_ordinals.is_empty()
            || round_ordinals
                .iter()
                .copied()
                .enumerate()
                .any(|(expected, actual)| usize::from(actual) != expected)
        {
            return Err(SemanticExecutionError::InvalidFactorOneSchedule);
        }
        accounted_folding_moves = accounted_folding_moves
            .checked_add(round_ordinals.len())
            .ok_or(SemanticExecutionError::ArithmeticOverflow)?;
        owners.extend(round_ordinals.into_iter().map(|round_ordinal| {
            SemanticVerifierMoveOwner::WhirFolding {
                epoch,
                batch_ordinal,
                round_ordinal,
            }
        }));
        if usize::from(batch_ordinal) < WHIR_ROUND_COUNT {
            owners.push(SemanticVerifierMoveOwner::WhirCodeSwitch {
                epoch,
                round_ordinal: batch_ordinal,
            });
        }
    }
    let expected_folding_moves = catalog
        .whir_mca_bounds
        .iter()
        .filter(|bound| bound.epoch == epoch)
        .count();
    if accounted_folding_moves != expected_folding_moves {
        return Err(SemanticExecutionError::InvalidFactorOneSchedule);
    }
    owners.push(SemanticVerifierMoveOwner::WhirBaseCombination { epoch });
    Ok(())
}

fn challenge_space_matches_owner(
    owner: SemanticVerifierMoveOwner,
    challenge_space: &ExactChallengeSpace,
    catalog: &RelaxedRoundByRoundCatalog,
) -> bool {
    match (owner, challenge_space) {
        (
            SemanticVerifierMoveOwner::LookupChallenge,
            ExactChallengeSpace::ExtensionVector {
                element_count: 1,
                excluded_element_count,
            },
        ) => *excluded_element_count == GOLDILOCKS_BASE_FIELD_MODULUS,
        (
            SemanticVerifierMoveOwner::CrossEpochPoint,
            ExactChallengeSpace::ExtensionVector {
                element_count,
                excluded_element_count: 0,
            },
        ) => *element_count == CROSS_EPOCH_POINT_COORDINATE_COUNT,
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness,
            ExactChallengeSpace::ExtensionVector {
                element_count,
                excluded_element_count: 0,
            },
        ) => *element_count == catalog.cfw.initial_randomness_element_count,
        (
            SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal },
            ExactChallengeSpace::ExtensionVector {
                element_count,
                excluded_element_count,
            },
        ) => {
            round_ordinal < catalog.cfw.sumcheck_round_count
                && *element_count == catalog.cfw.per_round_randomness_element_count
                && *excluded_element_count
                    == if round_ordinal.saturating_add(1) == catalog.cfw.sumcheck_round_count {
                        catalog.cfw.last_round_excluded_element_count
                    } else {
                        0
                    }
        }
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            ExactChallengeSpace::ExtensionVector {
                element_count,
                excluded_element_count: 0,
            },
        ) => {
            *element_count
                == catalog
                    .cfw
                    .joint_constraint_randomness_element_count
                    .saturating_add(1)
        }
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { .. }
            | SemanticVerifierMoveOwner::WhirFolding { .. }
            | SemanticVerifierMoveOwner::WhirBaseCombination { .. },
            ExactChallengeSpace::ExtensionVector {
                element_count: 1,
                excluded_element_count: 0,
            },
        ) => true,
        (
            SemanticVerifierMoveOwner::WhirCodeSwitch {
                epoch,
                round_ordinal,
            },
            ExactChallengeSpace::BaseElementExtensionVectorAndDistinctQueries {
                extension_element_count: 1,
                groups,
            },
        ) => expected_code_switch_query_group(catalog, epoch, round_ordinal)
            .is_some_and(|expected| groups.as_slice() == [expected]),
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            ExactChallengeSpace::ExtensionVectorAndDistinctQueries {
                extension_element_count: 1,
                groups,
            },
        ) => expected_final_query_groups(catalog, TranscriptEpoch::PreChallenge)
            .is_some_and(|expected| groups == &expected),
        (
            SemanticVerifierMoveOwner::MainWhirFinalQueries,
            ExactChallengeSpace::DistinctQueries { groups },
        ) => expected_final_query_groups(catalog, TranscriptEpoch::Main)
            .is_some_and(|expected| groups == &expected),
        _ => false,
    }
}

fn expected_code_switch_query_group(
    catalog: &RelaxedRoundByRoundCatalog,
    epoch: TranscriptEpoch,
    round_ordinal: u8,
) -> Option<super::super::super::transcript_chronology::DistinctQueryGeometry> {
    let code = unique_code_by_role(
        catalog,
        CodeRole::WhirSource {
            epoch,
            batch_ordinal: round_ordinal,
        },
    )?;
    query_geometry(code)
}

fn expected_final_query_groups(
    catalog: &RelaxedRoundByRoundCatalog,
    epoch: TranscriptEpoch,
) -> Option<Vec<super::super::super::transcript_chronology::DistinctQueryGeometry>> {
    let final_batch_ordinal = u8::try_from(WHIR_ROUND_COUNT).ok()?;
    let source_code = unique_code_by_role(
        catalog,
        CodeRole::WhirSource {
            epoch,
            batch_ordinal: final_batch_ordinal,
        },
    )?;
    let mut groups = vec![query_geometry(source_code)?];
    let mut mask_codes = catalog
        .codes
        .iter()
        .filter_map(|code| match code.role {
            CodeRole::WhirMask {
                epoch: code_epoch,
                group_ordinal,
            } if code_epoch == epoch => Some((group_ordinal, code)),
            _ => None,
        })
        .collect::<Vec<_>>();
    mask_codes.sort_unstable_by_key(|(group_ordinal, _)| *group_ordinal);
    for (expected_group_ordinal, (group_ordinal, code)) in mask_codes.into_iter().enumerate() {
        if usize::from(group_ordinal) != expected_group_ordinal {
            return None;
        }
        groups.push(query_geometry(code)?);
    }
    Some(groups)
}

fn unique_code_by_role(
    catalog: &RelaxedRoundByRoundCatalog,
    role: CodeRole,
) -> Option<&UniqueDecodingCode> {
    let mut matches = catalog.codes.iter().filter(|code| code.role == role);
    let code = matches.next()?;
    matches.next().is_none().then_some(code)
}

fn query_geometry(
    code: &UniqueDecodingCode,
) -> Option<super::super::super::transcript_chronology::DistinctQueryGeometry> {
    let geometry = super::super::super::transcript_chronology::DistinctQueryGeometry {
        domain_cardinality: code.block_length,
        query_count: code.query_count,
    };
    geometry.cardinality().ok().map(|_| geometry)
}

pub(super) enum SemanticVerifierMoveStatement<
    'borrow,
    'cfw_statement,
    Matrices: CompactCfwR1csMatrices,
> {
    ProductionOuter(&'borrow SemanticProductionOuterStatement),
    Cfw(&'borrow SemanticCfwStatement<'cfw_statement, Matrices>),
    CfwAndPreWhirOpening {
        cfw: &'borrow SemanticCfwStatement<'cfw_statement, Matrices>,
        pre_challenge_opening: &'borrow SemanticWhirOpeningBatchingStatement,
    },
    WhirMaskedSumcheck(&'borrow SemanticWhirMaskedSumcheckStatement),
    WhirCodeSwitch(&'borrow SemanticWhirCodeSwitchStatement),
    WhirBase(&'borrow SemanticWhirBaseStatement),
    PreWhirFinalAndMainWhirOpening {
        pre_challenge_base: &'borrow SemanticWhirBaseStatement,
        main_opening: &'borrow SemanticWhirOpeningBatchingStatement,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticVerifierMovePrefix {
    ProductionOuter(SemanticProductionOuterPrefix),
    Cfw(SemanticCfwTranscriptPrefix),
    CfwAndPreWhirOpening(SemanticCfwAndPreWhirOpeningPrefix),
    WhirMaskedSumcheck(SemanticWhirMaskedSumcheckPrefix),
    WhirCodeSwitch(SemanticWhirCodeSwitchPrefix),
    WhirBase(SemanticWhirBasePrefix),
    PreWhirFinalAndMainWhirOpening(SemanticPreWhirFinalAndMainOpeningPrefix),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticKnowledgeWitness {
    ProductionOuter(SemanticProductionOuterWitness),
    Cfw(SemanticCfwExtractedWitness),
    Generalized(SemanticGeneralizedRelationWitness),
    WhirBase(SemanticWhirBaseKnowledgeWitness),
    CfwAndPreWhirOpening(SemanticCfwAndPreWhirOpeningWitness),
    PreWhirFinalAndMainWhirOpening(SemanticPreWhirFinalAndMainOpeningWitness),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticVerifierMoveExtraction {
    pub(super) witness: Option<SemanticKnowledgeWitness>,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticVerifierMoveBadTransition {
    ProductionOuter(SemanticProductionOuterBadTransition),
    Cfw(SemanticCfwBadTransition),
    CfwAndPreWhirOpening(SemanticCfwAndPreWhirOpeningBadTransition),
    WhirMaskedSumcheck(SemanticWhirBadTransition),
    WhirCodeSwitch(SemanticWhirCodeSwitchBadTransition),
    WhirBaseCombination(SemanticWhirBaseCombinationBadTransition),
    PreWhirFinalAndMainWhirOpening(SemanticPreWhirFinalAndMainOpeningBadTransition),
    WhirFinalQueries(Vec<SemanticWhirBaseQueryEscape>),
}

pub(super) fn semantic_factor_one_kstate<Matrices: CompactCfwR1csMatrices>(
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    prefix: &SemanticVerifierMovePrefix,
    witness: &SemanticKnowledgeWitness,
) -> Result<bool, SemanticExecutionError> {
    validate_statement_owner(descriptor.owner, statement)?;
    validate_prefix_stage(descriptor.owner, prefix, false)?;
    match (statement, prefix) {
        (
            SemanticVerifierMoveStatement::ProductionOuter(statement),
            SemanticVerifierMovePrefix::ProductionOuter(prefix),
        ) => match witness {
            SemanticKnowledgeWitness::ProductionOuter(witness) => {
                semantic_production_outer_kstate(statement, prefix, witness).map_err(Into::into)
            }
            _ => Ok(false),
        },
        (
            SemanticVerifierMoveStatement::Cfw(statement),
            SemanticVerifierMovePrefix::Cfw(prefix),
        ) => match witness {
            SemanticKnowledgeWitness::Cfw(witness) => {
                semantic_cfw_kstate(statement, Some(prefix), witness).map_err(Into::into)
            }
            _ => Ok(false),
        },
        (
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw,
                pre_challenge_opening,
            },
            SemanticVerifierMovePrefix::CfwAndPreWhirOpening(prefix),
        ) => match witness {
            SemanticKnowledgeWitness::CfwAndPreWhirOpening(witness) => {
                let statement =
                    SemanticCfwAndPreWhirOpeningStatement::new(cfw, pre_challenge_opening);
                semantic_cfw_and_pre_whir_opening_kstate(&statement, prefix, witness)
                    .map_err(Into::into)
            }
            _ => Ok(false),
        },
        (
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix),
        ) => match witness {
            SemanticKnowledgeWitness::Generalized(witness) => {
                semantic_whir_masked_sumcheck_kstate(statement, Some(prefix), witness)
                    .map_err(Into::into)
            }
            _ => Ok(false),
        },
        (
            SemanticVerifierMoveStatement::WhirCodeSwitch(statement),
            SemanticVerifierMovePrefix::WhirCodeSwitch(prefix),
        ) => match witness {
            SemanticKnowledgeWitness::Generalized(witness) => {
                semantic_whir_code_switch_kstate(statement, Some(prefix), witness)
                    .map_err(Into::into)
            }
            _ => Ok(false),
        },
        (
            SemanticVerifierMoveStatement::WhirBase(statement),
            SemanticVerifierMovePrefix::WhirBase(prefix),
        ) => match witness {
            SemanticKnowledgeWitness::WhirBase(witness) => {
                semantic_whir_base_kstate(statement, Some(prefix), witness).map_err(Into::into)
            }
            _ => Ok(false),
        },
        (
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
                pre_challenge_base,
                main_opening,
            },
            SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix),
        ) => match witness {
            SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(witness) => {
                let statement = SemanticPreWhirFinalAndMainOpeningStatement::new(
                    pre_challenge_base,
                    main_opening,
                );
                semantic_pre_whir_final_and_main_opening_kstate(&statement, prefix, witness)
                    .map_err(Into::into)
            }
            _ => Ok(false),
        },
        _ => Err(SemanticExecutionError::MismatchedMoveData),
    }
}

pub(super) fn semantic_factor_one_errbr<Matrices: CompactCfwR1csMatrices>(
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    extended_prefix: &SemanticVerifierMovePrefix,
    post_challenge_witness: &SemanticKnowledgeWitness,
) -> Result<SemanticVerifierMoveExtraction, SemanticExecutionError> {
    validate_statement_owner(descriptor.owner, statement)?;
    validate_prefix_stage(descriptor.owner, extended_prefix, true)?;
    let extraction = match (statement, extended_prefix, post_challenge_witness) {
        (
            SemanticVerifierMoveStatement::ProductionOuter(statement),
            SemanticVerifierMovePrefix::ProductionOuter(prefix),
            SemanticKnowledgeWitness::ProductionOuter(witness),
        ) => {
            let extraction = semantic_production_outer_errbr(statement, prefix, witness)?;
            SemanticVerifierMoveExtraction {
                witness: extraction
                    .witness
                    .map(SemanticKnowledgeWitness::ProductionOuter),
                field_operation_count: extraction.field_operation_count,
            }
        }
        (
            SemanticVerifierMoveStatement::Cfw(statement),
            SemanticVerifierMovePrefix::Cfw(prefix),
            SemanticKnowledgeWitness::Cfw(witness),
        ) => {
            let extraction = semantic_cfw_errbr_at_verifier_move(statement, prefix, witness)?;
            SemanticVerifierMoveExtraction {
                witness: extraction.witness.map(SemanticKnowledgeWitness::Cfw),
                field_operation_count: extraction.field_operation_count,
            }
        }
        (
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw,
                pre_challenge_opening,
            },
            SemanticVerifierMovePrefix::CfwAndPreWhirOpening(prefix),
            SemanticKnowledgeWitness::CfwAndPreWhirOpening(witness),
        ) => {
            let statement = SemanticCfwAndPreWhirOpeningStatement::new(cfw, pre_challenge_opening);
            let extraction = semantic_cfw_and_pre_whir_opening_errbr(&statement, prefix, witness)?;
            SemanticVerifierMoveExtraction {
                witness: extraction
                    .witness
                    .map(SemanticKnowledgeWitness::CfwAndPreWhirOpening),
                field_operation_count: extraction.field_operation_count,
            }
        }
        (
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix),
            SemanticKnowledgeWitness::Generalized(witness),
        ) => {
            let extraction = semantic_whir_masked_sumcheck_errbr(statement, prefix, witness)?;
            SemanticVerifierMoveExtraction {
                witness: extraction
                    .witness
                    .map(SemanticKnowledgeWitness::Generalized),
                field_operation_count: extraction.field_operation_count,
            }
        }
        (
            SemanticVerifierMoveStatement::WhirCodeSwitch(statement),
            SemanticVerifierMovePrefix::WhirCodeSwitch(prefix),
            SemanticKnowledgeWitness::Generalized(witness),
        ) => {
            let extraction = semantic_whir_code_switch_errbr(statement, prefix, witness)?;
            SemanticVerifierMoveExtraction {
                witness: extraction
                    .witness
                    .map(SemanticKnowledgeWitness::Generalized),
                field_operation_count: extraction.field_operation_count,
            }
        }
        (
            SemanticVerifierMoveStatement::WhirBase(statement),
            SemanticVerifierMovePrefix::WhirBase(prefix),
            SemanticKnowledgeWitness::WhirBase(SemanticWhirBaseKnowledgeWitness::Blinded(witness)),
        ) if matches!(
            descriptor.owner,
            SemanticVerifierMoveOwner::WhirBaseCombination { .. }
        ) =>
        {
            let extraction = semantic_whir_base_combination_errbr(statement, prefix, witness)?;
            SemanticVerifierMoveExtraction {
                witness: extraction.witness.map(|witness| {
                    SemanticKnowledgeWitness::WhirBase(
                        SemanticWhirBaseKnowledgeWitness::PreCombination(witness),
                    )
                }),
                field_operation_count: extraction.field_operation_count,
            }
        }
        (
            SemanticVerifierMoveStatement::WhirBase(statement),
            SemanticVerifierMovePrefix::WhirBase(prefix),
            SemanticKnowledgeWitness::WhirBase(SemanticWhirBaseKnowledgeWitness::Terminal),
        ) if descriptor.owner == SemanticVerifierMoveOwner::MainWhirFinalQueries => {
            let extraction = semantic_whir_base_final_errbr(statement, prefix)?;
            SemanticVerifierMoveExtraction {
                witness: extraction.witness.map(|witness| {
                    SemanticKnowledgeWitness::WhirBase(SemanticWhirBaseKnowledgeWitness::Blinded(
                        witness,
                    ))
                }),
                field_operation_count: extraction.field_operation_count,
            }
        }
        (
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
                pre_challenge_base,
                main_opening,
            },
            SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix),
            SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(witness),
        ) => {
            let statement =
                SemanticPreWhirFinalAndMainOpeningStatement::new(pre_challenge_base, main_opening);
            let extraction =
                semantic_pre_whir_final_and_main_opening_errbr(&statement, prefix, witness)?;
            SemanticVerifierMoveExtraction {
                witness: extraction
                    .witness
                    .map(SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening),
                field_operation_count: extraction.field_operation_count,
            }
        }
        _ => return Err(SemanticExecutionError::MismatchedMoveData),
    };
    if extraction.field_operation_count > descriptor.extraction_field_operation_bound {
        return Err(SemanticExecutionError::ExtractionWorkBoundExceeded);
    }
    Ok(extraction)
}

/// Removes exactly the current verifier message from an extended prefix.
///
/// This is the transcript operation used by the construction-wide relaxed
/// experiment. It preserves every preceding prover message and every earlier
/// verifier challenge; it never rebuilds a prefix from a role label.
pub(super) fn semantic_factor_one_preceding_prefix(
    descriptor: &SemanticFactorOneMoveDescriptor,
    extended_prefix: &SemanticVerifierMovePrefix,
) -> Result<SemanticVerifierMovePrefix, SemanticExecutionError> {
    validate_prefix_stage(descriptor.owner, extended_prefix, true)?;
    let preceding_prefix = match (descriptor.owner, extended_prefix) {
        (
            SemanticVerifierMoveOwner::LookupChallenge,
            SemanticVerifierMovePrefix::ProductionOuter(
                SemanticProductionOuterPrefix::LookupChallengeSampled {
                    pre_challenge_source,
                    ..
                },
            ),
        ) => SemanticVerifierMovePrefix::ProductionOuter(
            SemanticProductionOuterPrefix::PreChallengeSourceCommitted {
                pre_challenge_source: pre_challenge_source.clone(),
            },
        ),
        (
            SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMovePrefix::ProductionOuter(
                SemanticProductionOuterPrefix::CrossEpochPointSampled {
                    commitments,
                    lookup_challenge,
                    ..
                },
            ),
        ) => SemanticVerifierMovePrefix::ProductionOuter(
            SemanticProductionOuterPrefix::PostLookupCommitments {
                commitments: commitments.clone(),
                lookup_challenge: *lookup_challenge,
            },
        ),
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness
            | SemanticVerifierMoveOwner::CfwSumcheckRound { .. },
            SemanticVerifierMovePrefix::Cfw(prefix),
        ) => SemanticVerifierMovePrefix::Cfw(semantic_cfw_preceding_prefix(prefix)?),
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMovePrefix::CfwAndPreWhirOpening(prefix),
        ) => {
            let mut cfw = semantic_cfw_preceding_prefix(&prefix.cfw)?;
            cfw.joint_constraint_challenge = None;
            SemanticVerifierMovePrefix::CfwAndPreWhirOpening(SemanticCfwAndPreWhirOpeningPrefix {
                cfw,
                pre_challenge_opening: SemanticWhirOpeningBatchingPrefix {
                    batching_challenge: None,
                },
            })
        }
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { .. },
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix),
        ) => {
            let mut prefix = prefix.clone();
            prefix.combining_challenge = None;
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix)
        }
        (
            SemanticVerifierMoveOwner::WhirFolding { .. },
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix),
        ) => {
            let mut prefix = prefix.clone();
            prefix
                .round_challenges
                .pop()
                .ok_or(SemanticExecutionError::MalformedPrefix)?;
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix)
        }
        (
            SemanticVerifierMoveOwner::WhirCodeSwitch { .. },
            SemanticVerifierMovePrefix::WhirCodeSwitch(prefix),
        ) => {
            let mut prefix = prefix.clone();
            prefix.query_positions = None;
            prefix.combination_challenge = None;
            SemanticVerifierMovePrefix::WhirCodeSwitch(prefix)
        }
        (
            SemanticVerifierMoveOwner::WhirBaseCombination { .. },
            SemanticVerifierMovePrefix::WhirBase(prefix),
        ) => {
            let mut prefix = prefix.clone();
            prefix.combination_challenge = None;
            SemanticVerifierMovePrefix::WhirBase(prefix)
        }
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix),
        ) => {
            let mut prefix = prefix.clone();
            prefix.pre_challenge_base.query_challenges = None;
            prefix.main_opening.batching_challenge = None;
            SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix)
        }
        (
            SemanticVerifierMoveOwner::MainWhirFinalQueries,
            SemanticVerifierMovePrefix::WhirBase(prefix),
        ) => {
            let mut prefix = prefix.clone();
            prefix.query_challenges = None;
            SemanticVerifierMovePrefix::WhirBase(prefix)
        }
        _ => return Err(SemanticExecutionError::MismatchedMoveData),
    };
    if validate_prefix_stage(descriptor.owner, &preceding_prefix, false)?
        != SemanticPrefixStage::PrecedingProverPrefix
    {
        return Err(SemanticExecutionError::MalformedPrefix);
    }
    Ok(preceding_prefix)
}

pub(super) fn semantic_factor_one_bad_transition<Matrices: CompactCfwR1csMatrices>(
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    extended_prefix: &SemanticVerifierMovePrefix,
    post_challenge_witness: &SemanticKnowledgeWitness,
) -> Result<Option<SemanticVerifierMoveBadTransition>, SemanticExecutionError> {
    validate_statement_owner(descriptor.owner, statement)?;
    validate_prefix_stage(descriptor.owner, extended_prefix, true)?;
    if !semantic_factor_one_kstate(
        descriptor,
        statement,
        extended_prefix,
        post_challenge_witness,
    )? {
        return Ok(None);
    }
    let bad_transition = match (statement, extended_prefix, post_challenge_witness) {
        (
            SemanticVerifierMoveStatement::ProductionOuter(statement),
            SemanticVerifierMovePrefix::ProductionOuter(prefix),
            SemanticKnowledgeWitness::ProductionOuter(witness),
        ) => semantic_production_outer_bad_transition(statement, prefix, witness)?
            .map(SemanticVerifierMoveBadTransition::ProductionOuter),
        (
            SemanticVerifierMoveStatement::Cfw(statement),
            SemanticVerifierMovePrefix::Cfw(prefix),
            SemanticKnowledgeWitness::Cfw(witness),
        ) => semantic_cfw_bad_transition(statement, prefix, witness)?
            .map(SemanticVerifierMoveBadTransition::Cfw),
        (
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw,
                pre_challenge_opening,
            },
            SemanticVerifierMovePrefix::CfwAndPreWhirOpening(prefix),
            SemanticKnowledgeWitness::CfwAndPreWhirOpening(witness),
        ) => {
            let statement = SemanticCfwAndPreWhirOpeningStatement::new(cfw, pre_challenge_opening);
            semantic_cfw_and_pre_whir_opening_bad_transition(&statement, prefix, witness)?
                .map(SemanticVerifierMoveBadTransition::CfwAndPreWhirOpening)
        }
        (
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix),
            SemanticKnowledgeWitness::Generalized(witness),
        ) => semantic_whir_masked_sumcheck_bad_transition(statement, prefix, witness)?
            .map(SemanticVerifierMoveBadTransition::WhirMaskedSumcheck),
        (
            SemanticVerifierMoveStatement::WhirCodeSwitch(statement),
            SemanticVerifierMovePrefix::WhirCodeSwitch(prefix),
            SemanticKnowledgeWitness::Generalized(witness),
        ) => semantic_whir_code_switch_bad_transition(statement, prefix, witness)?
            .map(SemanticVerifierMoveBadTransition::WhirCodeSwitch),
        (
            SemanticVerifierMoveStatement::WhirBase(statement),
            SemanticVerifierMovePrefix::WhirBase(prefix),
            SemanticKnowledgeWitness::WhirBase(SemanticWhirBaseKnowledgeWitness::Blinded(witness)),
        ) if matches!(
            descriptor.owner,
            SemanticVerifierMoveOwner::WhirBaseCombination { .. }
        ) =>
        {
            semantic_whir_base_combination_bad_transition(statement, prefix, witness)?
                .map(SemanticVerifierMoveBadTransition::WhirBaseCombination)
        }
        (
            SemanticVerifierMoveStatement::WhirBase(statement),
            SemanticVerifierMovePrefix::WhirBase(prefix),
            SemanticKnowledgeWitness::WhirBase(SemanticWhirBaseKnowledgeWitness::Terminal),
        ) if descriptor.owner == SemanticVerifierMoveOwner::MainWhirFinalQueries => {
            semantic_whir_base_final_bad_transition(statement, prefix)?
                .map(SemanticVerifierMoveBadTransition::WhirFinalQueries)
        }
        (
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
                pre_challenge_base,
                main_opening,
            },
            SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix),
            SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(witness),
        ) => {
            let statement =
                SemanticPreWhirFinalAndMainOpeningStatement::new(pre_challenge_base, main_opening);
            semantic_pre_whir_final_and_main_opening_bad_transition(&statement, prefix, witness)?
                .map(SemanticVerifierMoveBadTransition::PreWhirFinalAndMainWhirOpening)
        }
        _ => return Err(SemanticExecutionError::MismatchedMoveData),
    };
    if let Some(certificate) = &bad_transition {
        validate_bad_transition_certificate_bound(descriptor, certificate)?;
    }
    Ok(bad_transition)
}

pub(super) fn validate_bad_transition_certificate_bound(
    descriptor: &SemanticFactorOneMoveDescriptor,
    certificate: &SemanticVerifierMoveBadTransition,
) -> Result<(), SemanticExecutionError> {
    let events = derive_bad_transition_certificate_events(descriptor, certificate)
        .map_err(|_| SemanticExecutionError::InvalidBadTransitionCertificate)?;
    let total_probability = events
        .iter()
        .try_fold(
            ExactProbability::zero(),
            |accumulated_probability, event| accumulated_probability.add(&event.probability),
        )
        .map_err(|_| SemanticExecutionError::InvalidBadTransitionCertificate)?;
    if total_probability.is_greater_than(descriptor.extraction_error()) {
        return Err(SemanticExecutionError::BadTransitionProbabilityBoundExceeded);
    }
    Ok(())
}

fn validate_statement_owner<Matrices: CompactCfwR1csMatrices>(
    owner: SemanticVerifierMoveOwner,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
) -> Result<(), SemanticExecutionError> {
    let matches = match (owner, statement) {
        (
            SemanticVerifierMoveOwner::LookupChallenge | SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMoveStatement::ProductionOuter(_),
        )
        | (
            SemanticVerifierMoveOwner::CfwInitialRandomness
            | SemanticVerifierMoveOwner::CfwSumcheckRound { .. },
            SemanticVerifierMoveStatement::Cfw(_),
        )
        | (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening { .. },
        )
        | (
            SemanticVerifierMoveOwner::WhirBaseCombination { .. }
            | SemanticVerifierMoveOwner::MainWhirFinalQueries,
            SemanticVerifierMoveStatement::WhirBase(_),
        )
        | (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening { .. },
        ) => true,
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { batch_ordinal, .. }
            | SemanticVerifierMoveOwner::WhirFolding { batch_ordinal, .. },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(statement),
        ) => statement.batch_ordinal()? == batch_ordinal,
        (
            SemanticVerifierMoveOwner::WhirCodeSwitch { round_ordinal, .. },
            SemanticVerifierMoveStatement::WhirCodeSwitch(statement),
        ) => statement.round_ordinal()? == round_ordinal,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(SemanticExecutionError::MismatchedMoveData)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticPrefixStage {
    PrecedingProverPrefix,
    ExtendedVerifierPrefix,
}

pub(super) fn validate_prefix_stage(
    owner: SemanticVerifierMoveOwner,
    prefix: &SemanticVerifierMovePrefix,
    require_extended: bool,
) -> Result<SemanticPrefixStage, SemanticExecutionError> {
    let stage = match (owner, prefix) {
        (
            SemanticVerifierMoveOwner::LookupChallenge,
            SemanticVerifierMovePrefix::ProductionOuter(
                SemanticProductionOuterPrefix::PreChallengeSourceCommitted { .. },
            ),
        )
        | (
            SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMovePrefix::ProductionOuter(
                SemanticProductionOuterPrefix::PostLookupCommitments { .. },
            ),
        ) => SemanticPrefixStage::PrecedingProverPrefix,
        (
            SemanticVerifierMoveOwner::LookupChallenge,
            SemanticVerifierMovePrefix::ProductionOuter(
                SemanticProductionOuterPrefix::LookupChallengeSampled { .. },
            ),
        )
        | (
            SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMovePrefix::ProductionOuter(
                SemanticProductionOuterPrefix::CrossEpochPointSampled { .. },
            ),
        ) => SemanticPrefixStage::ExtendedVerifierPrefix,
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness,
            SemanticVerifierMovePrefix::Cfw(prefix),
        ) => cfw_initial_prefix_stage(prefix)?,
        (
            SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal },
            SemanticVerifierMovePrefix::Cfw(prefix),
        ) => cfw_round_prefix_stage(prefix, round_ordinal)?,
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMovePrefix::CfwAndPreWhirOpening(prefix),
        ) => match (
            prefix.cfw.joint_constraint_challenge,
            prefix.pre_challenge_opening.batching_challenge,
        ) {
            (None, None) if prefix.cfw.final_message.is_some() => {
                SemanticPrefixStage::PrecedingProverPrefix
            }
            (Some(_), Some(_))
                if semantic_cfw_verifier_transition(&prefix.cfw)?
                    == SemanticCfwVerifierTransition::JointConstraint =>
            {
                SemanticPrefixStage::ExtendedVerifierPrefix
            }
            _ => return Err(SemanticExecutionError::MalformedPrefix),
        },
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { .. },
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix),
        ) if prefix.round_wires.is_empty() && prefix.round_challenges.is_empty() => {
            if prefix.combining_challenge.is_some() {
                SemanticPrefixStage::ExtendedVerifierPrefix
            } else {
                SemanticPrefixStage::PrecedingProverPrefix
            }
        }
        (
            SemanticVerifierMoveOwner::WhirFolding { round_ordinal, .. },
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix),
        ) => whir_folding_prefix_stage(prefix, round_ordinal)?,
        (
            SemanticVerifierMoveOwner::WhirCodeSwitch { .. },
            SemanticVerifierMovePrefix::WhirCodeSwitch(prefix),
        ) => match (&prefix.query_positions, prefix.combination_challenge) {
            (None, None) => SemanticPrefixStage::PrecedingProverPrefix,
            (Some(_), Some(_)) => SemanticPrefixStage::ExtendedVerifierPrefix,
            _ => return Err(SemanticExecutionError::MalformedPrefix),
        },
        (
            SemanticVerifierMoveOwner::WhirBaseCombination { .. },
            SemanticVerifierMovePrefix::WhirBase(prefix),
        ) if prefix.fresh_message.is_some()
            && prefix.revealed_witness.is_none()
            && prefix.query_challenges.is_none() =>
        {
            if prefix.combination_challenge.is_some() {
                SemanticPrefixStage::ExtendedVerifierPrefix
            } else {
                SemanticPrefixStage::PrecedingProverPrefix
            }
        }
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix),
        ) => match (
            prefix.pre_challenge_base.query_challenges.is_some(),
            prefix.main_opening.batching_challenge.is_some(),
        ) {
            (false, false) if prefix.pre_challenge_base.revealed_witness.is_some() => {
                SemanticPrefixStage::PrecedingProverPrefix
            }
            (true, true) => SemanticPrefixStage::ExtendedVerifierPrefix,
            _ => return Err(SemanticExecutionError::MalformedPrefix),
        },
        (
            SemanticVerifierMoveOwner::MainWhirFinalQueries,
            SemanticVerifierMovePrefix::WhirBase(prefix),
        ) if prefix.fresh_message.is_some()
            && prefix.combination_challenge.is_some()
            && prefix.revealed_witness.is_some() =>
        {
            if prefix.query_challenges.is_some() {
                SemanticPrefixStage::ExtendedVerifierPrefix
            } else {
                SemanticPrefixStage::PrecedingProverPrefix
            }
        }
        _ => return Err(SemanticExecutionError::MismatchedMoveData),
    };
    if require_extended && stage != SemanticPrefixStage::ExtendedVerifierPrefix {
        return Err(SemanticExecutionError::MalformedPrefix);
    }
    Ok(stage)
}

fn cfw_initial_prefix_stage(
    prefix: &SemanticCfwTranscriptPrefix,
) -> Result<SemanticPrefixStage, SemanticExecutionError> {
    if prefix.round_polynomials.is_empty()
        && prefix.round_challenges.is_empty()
        && prefix.final_message.is_none()
        && prefix.joint_constraint_challenge.is_none()
    {
        if prefix.constraint_combining_challenge.is_none() && prefix.equality_point.is_empty() {
            return Ok(SemanticPrefixStage::PrecedingProverPrefix);
        }
        if semantic_cfw_verifier_transition(prefix)?
            == SemanticCfwVerifierTransition::InitialRandomness
        {
            return Ok(SemanticPrefixStage::ExtendedVerifierPrefix);
        }
    }
    Err(SemanticExecutionError::MalformedPrefix)
}

fn cfw_round_prefix_stage(
    prefix: &SemanticCfwTranscriptPrefix,
    round_ordinal: u32,
) -> Result<SemanticPrefixStage, SemanticExecutionError> {
    let round_ordinal =
        usize::try_from(round_ordinal).map_err(|_| SemanticExecutionError::ArithmeticOverflow)?;
    if prefix.constraint_combining_challenge.is_none()
        || prefix.final_message.is_some()
        || prefix.joint_constraint_challenge.is_some()
        || prefix.round_polynomials.len() != round_ordinal.saturating_add(1)
    {
        return Err(SemanticExecutionError::MalformedPrefix);
    }
    if prefix.round_challenges.len() == round_ordinal {
        return Ok(SemanticPrefixStage::PrecedingProverPrefix);
    }
    if semantic_cfw_verifier_transition(prefix)?
        == (SemanticCfwVerifierTransition::SumcheckRound { round_ordinal })
    {
        return Ok(SemanticPrefixStage::ExtendedVerifierPrefix);
    }
    Err(SemanticExecutionError::MalformedPrefix)
}

fn whir_folding_prefix_stage(
    prefix: &SemanticWhirMaskedSumcheckPrefix,
    round_ordinal: u8,
) -> Result<SemanticPrefixStage, SemanticExecutionError> {
    let round_ordinal = usize::from(round_ordinal);
    if prefix.combining_challenge.is_none()
        || prefix.round_wires.len() != round_ordinal.saturating_add(1)
    {
        return Err(SemanticExecutionError::MalformedPrefix);
    }
    match prefix.round_challenges.len() {
        count if count == round_ordinal => Ok(SemanticPrefixStage::PrecedingProverPrefix),
        count if count == round_ordinal.saturating_add(1) => {
            Ok(SemanticPrefixStage::ExtendedVerifierPrefix)
        }
        _ => Err(SemanticExecutionError::MalformedPrefix),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticExecutionError {
    ArithmeticOverflow,
    BadTransitionProbabilityBoundExceeded,
    Cfw(SemanticCfwError),
    Composition(SemanticCompositionError),
    ExtractionWorkBoundExceeded,
    InvalidBadTransitionCertificate,
    InvalidFactorOneSchedule,
    MalformedPrefix,
    MismatchedMoveData,
    Outer(SemanticOuterError),
    Whir(SemanticWhirError),
}

impl From<SemanticCfwError> for SemanticExecutionError {
    fn from(error: SemanticCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl From<SemanticCompositionError> for SemanticExecutionError {
    fn from(error: SemanticCompositionError) -> Self {
        Self::Composition(error)
    }
}

impl From<SemanticOuterError> for SemanticExecutionError {
    fn from(error: SemanticOuterError) -> Self {
        Self::Outer(error)
    }
}

impl From<SemanticWhirError> for SemanticExecutionError {
    fn from(error: SemanticWhirError) -> Self {
        Self::Whir(error)
    }
}

#[cfg(test)]
pub(super) struct SemanticUnusedCfwMatrices;

#[cfg(test)]
impl CompactCfwR1csMatrices for SemanticUnusedCfwMatrices {
    fn witness_length(&self) -> usize {
        1
    }

    fn evaluate_assignment_rows(
        &self,
        _matrix_role: CompactCfwMatrixRole,
        _public_input: &[CompactChallengeField],
        _witness: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
        unreachable!("the non-CFW semantic dispatcher test cannot evaluate CFW rows")
    }

    fn public_contribution_at_row_point(
        &self,
        _matrix_role: CompactCfwMatrixRole,
        _row_point: &[CompactChallengeField],
        _public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        unreachable!("the non-CFW semantic dispatcher test cannot evaluate CFW rows")
    }

    fn accumulate_weighted_witness_covector_at_row_point(
        &self,
        _row_point: &[CompactChallengeField],
        _matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        _destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        unreachable!("the non-CFW semantic dispatcher test cannot evaluate CFW rows")
    }
}

#[cfg(test)]
mod tests;
