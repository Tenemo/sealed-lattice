//! One executable dispatcher for every verifier move in the factor-one
//! chronology.
//!
//! The chronology catalog supplies only the move ordinal, challenge space, and
//! dependency barrier. This module binds each such entry to a concrete
//! semantic owner and dispatches `KState`, deterministic backward extraction,
//! and bad-transition derivation to the corresponding CFW or WHIR algorithm.
//! A role label by itself never produces an accepting result.

use super::super::{
    CompactFactorOneContractView, CompactFactorOneSemanticOwner, ExactChallengeSpace,
    ExactProbability, expected_owner_chronology, semantic_owner,
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
use super::semantic_error_bounds::{
    derive_bad_transition_certificate_events, derive_owner_bad_transition_event_ceiling,
};
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

pub(super) type SemanticVerifierMoveOwner = CompactFactorOneSemanticOwner;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticFactorOneMoveDescriptor {
    verifier_move_ordinal: u32,
    owner: SemanticVerifierMoveOwner,
    preceding_prover_response_ordinal: u32,
    preceding_commitment_count: u64,
    challenge_space: ExactChallengeSpace,
    bad_transition_event_ceiling: Vec<super::semantic_error_bounds::SemanticBadEventBound>,
    extraction_error: ExactProbability,
}

impl SemanticFactorOneMoveDescriptor {
    pub(super) const fn verifier_move_ordinal(&self) -> u32 {
        self.verifier_move_ordinal
    }

    pub(super) const fn owner(&self) -> SemanticVerifierMoveOwner {
        self.owner
    }

    pub(super) const fn challenge_space(&self) -> &ExactChallengeSpace {
        &self.challenge_space
    }

    pub(super) const fn extraction_error(&self) -> &ExactProbability {
        &self.extraction_error
    }

    pub(super) fn bad_transition_event_ceiling(
        &self,
    ) -> &[super::semantic_error_bounds::SemanticBadEventBound] {
        &self.bad_transition_event_ceiling
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
            bad_transition_event_ceiling: Vec::new(),
            extraction_error: ExactProbability::new(1_u8.into(), 1_u8.into())
                .expect("one is an exact probability"),
        }
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
    pub(super) fn from_contract(
        contract: CompactFactorOneContractView<'_>,
    ) -> Result<Self, SemanticExecutionError> {
        let expected_owners = expected_owner_chronology(contract)
            .map_err(|_| SemanticExecutionError::InvalidFactorOneSchedule)?;
        if contract.verifier_moves.len() != FACTOR_ONE_VERIFIER_MOVE_COUNT
            || expected_owners.len() != FACTOR_ONE_VERIFIER_MOVE_COUNT
            || contract.cfw_configuration.geometry().sumcheck_round_count()
                != FACTOR_ONE_CFW_SUMCHECK_ROUND_COUNT
        {
            return Err(SemanticExecutionError::InvalidFactorOneSchedule);
        }
        let mut moves = Vec::with_capacity(contract.verifier_moves.len());
        for (expected_ordinal, (move_contract, expected_owner)) in contract
            .verifier_moves
            .iter()
            .zip(expected_owners)
            .enumerate()
        {
            let owner = semantic_owner(move_contract)
                .map_err(|_| SemanticExecutionError::InvalidFactorOneSchedule)?;
            if owner != expected_owner
                || usize::try_from(move_contract.ordinal).ok() != Some(expected_ordinal)
            {
                return Err(SemanticExecutionError::InvalidFactorOneSchedule);
            }
            let events = derive_owner_bad_transition_event_ceiling(contract, owner)
                .map_err(|_| SemanticExecutionError::InvalidFactorOneSchedule)?;
            if events.is_empty() {
                return Err(SemanticExecutionError::InvalidFactorOneSchedule);
            }
            let extraction_error = events
                .iter()
                .try_fold(ExactProbability::zero(), |total, event| {
                    total.add(&event.probability)
                })
                .map_err(|_| SemanticExecutionError::InvalidFactorOneSchedule)?;
            moves.push(SemanticFactorOneMoveDescriptor {
                verifier_move_ordinal: move_contract.ordinal,
                owner,
                preceding_prover_response_ordinal: move_contract.preceding_prover_response_ordinal,
                preceding_commitment_count: u64::from(move_contract.preceding_commitment_count),
                challenge_space: ExactChallengeSpace::from_geometry(
                    &move_contract.message_geometry,
                )
                .map_err(|_| SemanticExecutionError::InvalidFactorOneSchedule)?,
                bad_transition_event_ceiling: events,
                extraction_error,
            });
        }
        if moves.windows(2).any(|moves| {
            moves[0].preceding_prover_response_ordinal > moves[1].preceding_prover_response_ordinal
                || moves[0].preceding_commitment_count > moves[1].preceding_commitment_count
        }) || moves
            .iter()
            .filter(|descriptor| {
                matches!(
                    descriptor.owner,
                    SemanticVerifierMoveOwner::WhirFolding { .. }
                )
            })
            .count()
            != FACTOR_ONE_WHIR_FOLDING_MOVE_COUNT
        {
            return Err(SemanticExecutionError::InvalidFactorOneSchedule);
        }
        Ok(Self { moves })
    }

    pub(super) fn moves(&self) -> &[SemanticFactorOneMoveDescriptor] {
        &self.moves
    }
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
