//! Construction-wide relaxed knowledge state for the compact execution.
//!
//! The local semantic owners prove one verifier move. This module binds them
//! into the actual product chronology: the production outer relation and CFW
//! run first, the pre-challenge WHIR runs while the CFW-derived main input is
//! retained, and the final atomic verifier move transfers knowledge to the
//! main WHIR. Every transition consumes mathematical witnesses and canonical
//! transcript prefixes. No catalog row or producer-supplied completion value
//! can satisfy the predicate.

use super::semantic_composition::{
    SemanticCfwAndPreWhirOpeningPrefix, SemanticCfwAndPreWhirOpeningWitness,
    SemanticPreWhirFinalAndMainOpeningPrefix, SemanticPreWhirFinalAndMainOpeningWitness,
};
use super::semantic_execution::{
    SemanticExecutionError, SemanticFactorOneMoveDescriptor, SemanticKnowledgeWitness,
    SemanticPrefixStage, SemanticVerifierMoveBadTransition, SemanticVerifierMoveOwner,
    SemanticVerifierMovePrefix, SemanticVerifierMoveStatement, semantic_factor_one_bad_transition,
    semantic_factor_one_errbr, semantic_factor_one_kstate, semantic_factor_one_preceding_prefix,
    validate_prefix_stage,
};
use super::semantic_outer::{
    SemanticOuterError, SemanticProductionOuterCommitments, SemanticProductionOuterPrefix,
    SemanticProductionOuterStatement, SemanticProductionOuterWitness,
    semantic_production_outer_kstate,
};
use super::semantic_whir::{
    SemanticWhirBaseKnowledgeWitness, SemanticWhirBasePrefix, SemanticWhirBaseStatement,
    SemanticWhirCodeSwitchPrefix, SemanticWhirCodeSwitchStatement, SemanticWhirError,
    SemanticWhirMaskedSumcheckPrefix, SemanticWhirMaskedSumcheckStatement,
    SemanticWhirOpeningBatchingPrefix, SemanticWhirOpeningBatchingStatement,
    semantic_whir_base_final_errbr, semantic_whir_base_input_pair,
    semantic_whir_base_input_witness, semantic_whir_base_kstate,
    semantic_whir_code_switch_input_pair, semantic_whir_code_switch_output_pair,
    semantic_whir_masked_sumcheck_input_pair, semantic_whir_masked_sumcheck_output_pair,
    semantic_whir_opening_batching_kstate, semantic_whir_opening_input_pair,
    semantic_whir_opening_output_pair,
};
use super::*;
use crate::bgv::proof_suite::compact_public_key_static_catalog::relaxed_round_by_round::{
    MaskGroupRole, TranscriptEpoch, WHIR_ROUND_COUNT,
};

pub(super) struct SemanticConstructionContext<
    'context,
    'cfw_statement,
    Matrices: CompactCfwR1csMatrices,
> {
    outer: &'context SemanticProductionOuterStatement,
    cfw: &'context SemanticCfwStatement<'cfw_statement, Matrices>,
    pre_challenge_opening: &'context SemanticWhirOpeningBatchingStatement,
    main_opening: &'context SemanticWhirOpeningBatchingStatement,
}

impl<'context, 'cfw_statement, Matrices: CompactCfwR1csMatrices>
    SemanticConstructionContext<'context, 'cfw_statement, Matrices>
{
    pub(super) fn new(
        outer: &'context SemanticProductionOuterStatement,
        cfw: &'context SemanticCfwStatement<'cfw_statement, Matrices>,
        pre_challenge_opening: &'context SemanticWhirOpeningBatchingStatement,
        main_opening: &'context SemanticWhirOpeningBatchingStatement,
    ) -> Result<Self, SemanticConstructionError> {
        let context = Self {
            outer,
            cfw,
            pre_challenge_opening,
            main_opening,
        };
        context.validate_production_bindings()?;
        Ok(context)
    }

    fn validate_production_bindings(&self) -> Result<(), SemanticConstructionError> {
        let (pre_relation, pre_instance) =
            semantic_whir_opening_input_pair(self.pre_challenge_opening);
        let (main_relation, main_instance) = semantic_whir_opening_input_pair(self.main_opening);
        let pre_mask_roles = pre_relation
            .mask_codes
            .iter()
            .map(|mask| mask.role)
            .collect::<Vec<_>>();
        let main_mask_roles = main_relation
            .mask_codes
            .iter()
            .map(|mask| mask.role)
            .collect::<Vec<_>>();
        if self.cfw.implicit_tuple_dimensions() != (0, 0)
            || pre_mask_roles != [MaskGroupRole::CrossEpochOpening]
            || main_mask_roles
                != [
                    MaskGroupRole::CfwInner,
                    MaskGroupRole::CfwOuter,
                    MaskGroupRole::CrossEpochOpening,
                ]
            || &pre_relation.source_code != self.outer.pre_challenge_source_relation()
            || &pre_relation.mask_codes[0] != self.outer.shared_mask_relation()
            || &main_relation.source_code != self.outer.main_source_relation()
            || main_relation.source_code != self.cfw.code_relations.source
            || main_relation.mask_codes[0].code != self.cfw.code_relations.inner_masks
            || main_relation.mask_codes[1].code != self.cfw.code_relations.outer_masks
            || main_relation.mask_codes[2] != self.cfw.cross_epoch_handoff.mask_code_relation
            || self.outer.main_source_relation() != &self.cfw.code_relations.source
            || self.outer.shared_mask_relation() != &self.cfw.cross_epoch_handoff.mask_code_relation
            || main_instance.source != self.cfw.committed_instances.source
            || main_instance.masks
                != [
                    self.cfw.committed_instances.inner_masks.clone(),
                    self.cfw.committed_instances.outer_masks.clone(),
                    self.cfw.cross_epoch_handoff.committed_instance.clone(),
                ]
            || pre_instance.masks != [self.cfw.cross_epoch_handoff.committed_instance.clone()]
        {
            return Err(SemanticConstructionError::InvalidProductionBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticConstructionWhirWitness {
    Generalized(SemanticGeneralizedRelationWitness),
    Base(SemanticWhirBaseKnowledgeWitness),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticConstructionWitness {
    OuterAndCfw {
        outer: SemanticProductionOuterWitness,
        cfw: SemanticCfwExtractedWitness,
    },
    PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness,
        main: SemanticGeneralizedRelationWitness,
    },
    MainWhir(SemanticConstructionWhirWitness),
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticWhirCompletedComponent {
    MaskedSumcheck {
        statement: SemanticWhirMaskedSumcheckStatement,
        prefix: SemanticWhirMaskedSumcheckPrefix,
    },
    CodeSwitch {
        statement: SemanticWhirCodeSwitchStatement,
        prefix: SemanticWhirCodeSwitchPrefix,
    },
}

/// Canonical projection of every completed item in one WHIR epoch.
///
/// The opening challenge and every completed prover/verifier component are
/// retained in transcript order. The next component is checked by replaying
/// all prior transformations, so no producer-supplied relation pair or
/// completion flag can bridge adjacent components. Future challenges are not
/// present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticWhirEpochHistory {
    pub(super) opening_prefix: SemanticWhirOpeningBatchingPrefix,
    pub(super) completed_components: Vec<SemanticWhirCompletedComponent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCompletedCfwHandoff {
    pub(super) completed_outer: SemanticProductionOuterPrefix,
    pub(super) cfw_and_pre_challenge_opening: SemanticCfwAndPreWhirOpeningPrefix,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCompletedPreChallengeWhirHandoff {
    pub(super) completed_cfw: SemanticCompletedCfwHandoff,
    pub(super) pre_challenge_history: SemanticWhirEpochHistory,
    pub(super) pre_challenge_base: SemanticWhirBaseStatement,
    pub(super) pre_final_and_main_opening: SemanticPreWhirFinalAndMainOpeningPrefix,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticConstructionPrefix {
    Outer(SemanticProductionOuterPrefix),
    Cfw {
        completed_outer: SemanticProductionOuterPrefix,
        active: SemanticCfwTranscriptPrefix,
    },
    CfwAndPreWhirOpening {
        completed_outer: SemanticProductionOuterPrefix,
        active: SemanticCfwAndPreWhirOpeningPrefix,
    },
    PreChallengeWhir {
        completed_cfw: SemanticCompletedCfwHandoff,
        history: SemanticWhirEpochHistory,
        active: SemanticVerifierMovePrefix,
    },
    PreWhirFinalAndMainOpening {
        completed_cfw: SemanticCompletedCfwHandoff,
        history: SemanticWhirEpochHistory,
        active: SemanticPreWhirFinalAndMainOpeningPrefix,
    },
    MainWhir {
        completed_pre_challenge: SemanticCompletedPreChallengeWhirHandoff,
        history: SemanticWhirEpochHistory,
        active: SemanticVerifierMovePrefix,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticConstructionExtraction {
    pub(super) witness: Option<SemanticConstructionWitness>,
    pub(super) field_operation_count: u128,
}

struct InitialWitness {
    outer: SemanticProductionOuterWitness,
    cfw: SemanticCfwExtractedWitness,
}

pub(super) fn semantic_construction_empty_kstate<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    witness: &SemanticConstructionWitness,
) -> Result<bool, SemanticConstructionError> {
    let Some(initial) = initial_witness(context, witness) else {
        return Ok(false);
    };
    if !initial_witness_bindings_hold(&initial) {
        return Ok(false);
    }
    Ok(semantic_production_outer_kstate(
        context.outer,
        &SemanticProductionOuterPrefix::Empty,
        &initial.outer,
    )? && semantic_cfw_kstate(context.cfw, None, &initial.cfw)?)
}

pub(super) fn semantic_construction_kstate<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    prefix: &SemanticConstructionPrefix,
    witness: &SemanticConstructionWitness,
) -> Result<bool, SemanticConstructionError> {
    validate_statement_and_phase(context, descriptor, statement, prefix)?;
    let local_prefix = local_prefix(descriptor, prefix)?;
    let Some(local_witness) = local_witness(context, descriptor.owner(), prefix, witness) else {
        return Ok(false);
    };
    if !semantic_factor_one_kstate(descriptor, statement, &local_prefix, &local_witness)? {
        return Ok(false);
    }
    match prefix {
        SemanticConstructionPrefix::Outer(prefix) => {
            let Some(initial) = initial_witness(context, witness) else {
                return Ok(false);
            };
            Ok(initial_witness_bindings_hold(&initial)
                && outer_commitment_bindings_hold(context, prefix))
        }
        SemanticConstructionPrefix::Cfw {
            completed_outer, ..
        } => early_product_state_holds(context, completed_outer, witness, true),
        SemanticConstructionPrefix::CfwAndPreWhirOpening {
            completed_outer,
            active,
        } => {
            if !early_product_state_holds(context, completed_outer, witness, false)? {
                return Ok(false);
            }
            let Some(joint_challenge) = active.cfw.joint_constraint_challenge else {
                return Ok(true);
            };
            let cfw_output = semantic_cfw_output_relation_and_instance(context.cfw, &active.cfw)?;
            let main_input = semantic_whir_opening_input_pair(context.main_opening);
            if cfw_output.0 != *main_input.0 || cfw_output.1 != *main_input.1 {
                return Err(SemanticConstructionError::InvalidProductionBinding);
            }
            let Some(main) = main_input_witness(context, witness) else {
                return Ok(false);
            };
            let _ = joint_challenge;
            semantic_whir_opening_batching_kstate(context.main_opening, None, &main)
                .map_err(Into::into)
        }
        SemanticConstructionPrefix::PreChallengeWhir { completed_cfw, .. } => {
            if !completed_cfw_verifier_accepts(context, completed_cfw)? {
                return Ok(false);
            }
            let SemanticConstructionWitness::PreChallengeAndMainInput { main, .. } = witness else {
                return Ok(false);
            };
            semantic_whir_opening_batching_kstate(context.main_opening, None, main)
                .map_err(Into::into)
        }
        SemanticConstructionPrefix::PreWhirFinalAndMainOpening { completed_cfw, .. } => {
            completed_cfw_verifier_accepts(context, completed_cfw)
        }
        SemanticConstructionPrefix::MainWhir {
            completed_pre_challenge,
            ..
        } => completed_pre_challenge_verifier_accepts(context, completed_pre_challenge),
    }
}

fn completed_cfw_verifier_accepts<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    completed: &SemanticCompletedCfwHandoff,
) -> Result<bool, SemanticConstructionError> {
    cfw_transcript_deterministically_accepts(
        context.cfw,
        &completed.cfw_and_pre_challenge_opening.cfw,
    )
    .map_err(Into::into)
}

fn completed_pre_challenge_verifier_accepts<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    completed: &SemanticCompletedPreChallengeWhirHandoff,
) -> Result<bool, SemanticConstructionError> {
    if !completed_cfw_verifier_accepts(context, &completed.completed_cfw)? {
        return Ok(false);
    }
    semantic_whir_base_kstate(
        &completed.pre_challenge_base,
        Some(&completed.pre_final_and_main_opening.pre_challenge_base),
        &SemanticWhirBaseKnowledgeWitness::Terminal,
    )
    .map_err(Into::into)
}

pub(super) fn semantic_construction_errbr<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    extended_prefix: &SemanticConstructionPrefix,
    post_challenge_witness: &SemanticConstructionWitness,
) -> Result<SemanticConstructionExtraction, SemanticConstructionError> {
    validate_extractor_statement_and_phase(context, descriptor, statement, extended_prefix)?;
    let local_prefix = local_prefix(descriptor, extended_prefix)?;
    let local_post_witness = local_witness(
        context,
        descriptor.owner(),
        extended_prefix,
        post_challenge_witness,
    )
    .ok_or(SemanticConstructionError::MismatchedWitnessPhase)?;
    let extraction =
        semantic_factor_one_errbr(descriptor, statement, &local_prefix, &local_post_witness)?;
    let Some(local_predecessor) = extraction.witness else {
        return Ok(SemanticConstructionExtraction {
            witness: None,
            field_operation_count: extraction.field_operation_count,
        });
    };
    let predecessor = construction_predecessor_witness(
        context,
        descriptor.owner(),
        extended_prefix,
        post_challenge_witness,
        local_predecessor,
    )?;
    Ok(SemanticConstructionExtraction {
        witness: Some(predecessor),
        field_operation_count: extraction.field_operation_count,
    })
}

pub(super) fn semantic_construction_bad_transition<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    extended_prefix: &SemanticConstructionPrefix,
    post_challenge_witness: &SemanticConstructionWitness,
) -> Result<Option<SemanticVerifierMoveBadTransition>, SemanticConstructionError> {
    if !semantic_construction_kstate(
        context,
        descriptor,
        statement,
        extended_prefix,
        post_challenge_witness,
    )? {
        return Ok(None);
    }
    let extraction = semantic_construction_errbr(
        context,
        descriptor,
        statement,
        extended_prefix,
        post_challenge_witness,
    )?;
    if let Some(predecessor) = &extraction.witness {
        let preceding_prefix = semantic_construction_preceding_prefix(descriptor, extended_prefix)?;
        if semantic_construction_kstate(
            context,
            descriptor,
            statement,
            &preceding_prefix,
            predecessor,
        )? {
            return Ok(None);
        }
    }
    let local_prefix = local_prefix(descriptor, extended_prefix)?;
    let local_post_witness = local_witness(
        context,
        descriptor.owner(),
        extended_prefix,
        post_challenge_witness,
    )
    .ok_or(SemanticConstructionError::MismatchedWitnessPhase)?;
    semantic_factor_one_bad_transition(descriptor, statement, &local_prefix, &local_post_witness)?
        .map(Some)
        .ok_or(SemanticConstructionError::InconsistentBadTransition)
}

pub(super) fn semantic_construction_preceding_prefix(
    descriptor: &SemanticFactorOneMoveDescriptor,
    extended_prefix: &SemanticConstructionPrefix,
) -> Result<SemanticConstructionPrefix, SemanticConstructionError> {
    let local_extended = local_prefix(descriptor, extended_prefix)?;
    let local_preceding = semantic_factor_one_preceding_prefix(descriptor, &local_extended)?;
    match (extended_prefix, local_preceding) {
        (
            SemanticConstructionPrefix::Outer(_),
            SemanticVerifierMovePrefix::ProductionOuter(prefix),
        ) => Ok(SemanticConstructionPrefix::Outer(prefix)),
        (
            SemanticConstructionPrefix::Cfw {
                completed_outer, ..
            },
            SemanticVerifierMovePrefix::Cfw(active),
        ) => Ok(SemanticConstructionPrefix::Cfw {
            completed_outer: completed_outer.clone(),
            active,
        }),
        (
            SemanticConstructionPrefix::CfwAndPreWhirOpening {
                completed_outer, ..
            },
            SemanticVerifierMovePrefix::CfwAndPreWhirOpening(active),
        ) => Ok(SemanticConstructionPrefix::CfwAndPreWhirOpening {
            completed_outer: completed_outer.clone(),
            active,
        }),
        (
            SemanticConstructionPrefix::PreChallengeWhir {
                completed_cfw,
                history,
                ..
            },
            local_preceding,
        ) => Ok(SemanticConstructionPrefix::PreChallengeWhir {
            completed_cfw: completed_cfw.clone(),
            history: history.clone(),
            active: local_preceding,
        }),
        (
            SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
                completed_cfw,
                history,
                ..
            },
            SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix),
        ) => Ok(SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
            completed_cfw: completed_cfw.clone(),
            history: history.clone(),
            active: prefix,
        }),
        (
            SemanticConstructionPrefix::MainWhir {
                completed_pre_challenge,
                history,
                ..
            },
            local_preceding,
        ) => Ok(SemanticConstructionPrefix::MainWhir {
            completed_pre_challenge: completed_pre_challenge.clone(),
            history: history.clone(),
            active: local_preceding,
        }),
        _ => Err(SemanticConstructionError::MismatchedPrefixPhase),
    }
}

/// Checks Definition 3.5's prover-move implication for the first construction
/// message.
///
/// The first prefix must be the canonical prefix immediately before the lookup
/// challenge. The implication is checked in its contrapositive form: whenever
/// the post-message state holds for a witness, the empty-transcript input
/// relation must already hold for that same witness.
pub(super) fn check_semantic_construction_initial_prover_move<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    prefix: &SemanticConstructionPrefix,
    witness: &SemanticConstructionWitness,
) -> Result<(), SemanticConstructionError> {
    if descriptor.owner() != SemanticVerifierMoveOwner::LookupChallenge
        || !matches!(
            prefix,
            SemanticConstructionPrefix::Outer(
                SemanticProductionOuterPrefix::PreChallengeSourceCommitted { .. }
            )
        )
    {
        return Err(SemanticConstructionError::InvalidProverChronology);
    }
    validate_statement_and_phase(context, descriptor, statement, prefix)?;
    if semantic_construction_kstate(context, descriptor, statement, prefix, witness)?
        && !semantic_construction_empty_kstate(context, witness)?
    {
        return Err(SemanticConstructionError::ProverMoveRepairedKnowledgeState);
    }
    Ok(())
}

/// Checks Definition 3.5's prover-move implication across one adjacent pair of
/// construction verifier moves.
///
/// The prefix comparison rejects any change to prior prover or verifier data;
/// only the next canonical prover message may be appended. The state
/// implication is then checked for the same mathematical witness on both sides.
pub(super) fn check_semantic_construction_prover_move<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    before_descriptor: &SemanticFactorOneMoveDescriptor,
    before_statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    before_prefix: &SemanticConstructionPrefix,
    after_descriptor: &SemanticFactorOneMoveDescriptor,
    after_statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    after_prefix: &SemanticConstructionPrefix,
    witness: &SemanticConstructionWitness,
) -> Result<(), SemanticConstructionError> {
    validate_statement_and_phase(context, before_descriptor, before_statement, before_prefix)?;
    validate_statement_and_phase(context, after_descriptor, after_statement, after_prefix)?;
    let before_local_prefix = local_prefix(before_descriptor, before_prefix)?;
    let after_local_prefix = local_prefix(after_descriptor, after_prefix)?;
    if validate_prefix_stage(before_descriptor.owner(), &before_local_prefix, true)?
        != SemanticPrefixStage::ExtendedVerifierPrefix
        || validate_prefix_stage(after_descriptor.owner(), &after_local_prefix, false)?
            != SemanticPrefixStage::PrecedingProverPrefix
    {
        return Err(SemanticConstructionError::InvalidProverChronology);
    }
    if !prover_prefix_is_exact_successor(
        context,
        before_descriptor.owner(),
        before_statement,
        before_prefix,
        after_descriptor.owner(),
        after_statement,
        after_prefix,
    )? {
        return Err(SemanticConstructionError::InvalidProverChronology);
    }
    if semantic_construction_kstate(
        context,
        after_descriptor,
        after_statement,
        after_prefix,
        witness,
    )? && !semantic_construction_kstate(
        context,
        before_descriptor,
        before_statement,
        before_prefix,
        witness,
    )? {
        return Err(SemanticConstructionError::ProverMoveRepairedKnowledgeState);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prover_prefix_is_exact_successor<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    before_owner: SemanticVerifierMoveOwner,
    before_statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    before_prefix: &SemanticConstructionPrefix,
    after_owner: SemanticVerifierMoveOwner,
    after_statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    after_prefix: &SemanticConstructionPrefix,
) -> Result<bool, SemanticConstructionError> {
    let exact_successor = match (
        before_owner,
        before_statement,
        before_prefix,
        after_owner,
        after_statement,
        after_prefix,
    ) {
        (
            SemanticVerifierMoveOwner::LookupChallenge,
            SemanticVerifierMoveStatement::ProductionOuter(before_statement),
            SemanticConstructionPrefix::Outer(
                SemanticProductionOuterPrefix::LookupChallengeSampled {
                    pre_challenge_source,
                    lookup_challenge,
                },
            ),
            SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMoveStatement::ProductionOuter(after_statement),
            SemanticConstructionPrefix::Outer(
                SemanticProductionOuterPrefix::PostLookupCommitments {
                    commitments,
                    lookup_challenge: after_lookup_challenge,
                },
            ),
        ) => {
            core::ptr::eq(*before_statement, *after_statement)
                && pre_challenge_source == &commitments.pre_challenge_source
                && lookup_challenge == after_lookup_challenge
        }
        (
            SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMoveStatement::ProductionOuter(before_statement),
            SemanticConstructionPrefix::Outer(
                SemanticProductionOuterPrefix::CrossEpochPointSampled {
                    commitments,
                    lookup_challenge,
                    point,
                },
            ),
            SemanticVerifierMoveOwner::CfwInitialRandomness,
            SemanticVerifierMoveStatement::Cfw(after_statement),
            SemanticConstructionPrefix::Cfw {
                completed_outer:
                    SemanticProductionOuterPrefix::CrossEpochDisclosuresSent {
                        commitments: after_commitments,
                        lookup_challenge: after_lookup_challenge,
                        point: after_point,
                        ..
                    },
                ..
            },
        ) => {
            core::ptr::eq(*before_statement, context.outer)
                && core::ptr::eq(*after_statement, context.cfw)
                && commitments == after_commitments
                && lookup_challenge == after_lookup_challenge
                && point == after_point
        }
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness,
            SemanticVerifierMoveStatement::Cfw(before_statement),
            SemanticConstructionPrefix::Cfw {
                completed_outer,
                active: before_active,
            },
            SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal: 0 },
            SemanticVerifierMoveStatement::Cfw(after_statement),
            SemanticConstructionPrefix::Cfw {
                completed_outer: after_completed_outer,
                active: after_active,
            },
        ) => {
            core::ptr::eq(*before_statement, *after_statement)
                && completed_outer == after_completed_outer
                && cfw_prefix_appends_round_polynomial(before_active, after_active)
        }
        (
            SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal },
            SemanticVerifierMoveStatement::Cfw(before_statement),
            SemanticConstructionPrefix::Cfw {
                completed_outer,
                active: before_active,
            },
            SemanticVerifierMoveOwner::CfwSumcheckRound {
                round_ordinal: after_round_ordinal,
            },
            SemanticVerifierMoveStatement::Cfw(after_statement),
            SemanticConstructionPrefix::Cfw {
                completed_outer: after_completed_outer,
                active: after_active,
            },
        ) => {
            round_ordinal.checked_add(1) == Some(after_round_ordinal)
                && core::ptr::eq(*before_statement, *after_statement)
                && completed_outer == after_completed_outer
                && cfw_prefix_appends_round_polynomial(before_active, after_active)
        }
        (
            SemanticVerifierMoveOwner::CfwSumcheckRound { .. },
            SemanticVerifierMoveStatement::Cfw(before_statement),
            SemanticConstructionPrefix::Cfw {
                completed_outer,
                active: before_active,
            },
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw: after_cfw_statement,
                pre_challenge_opening,
            },
            SemanticConstructionPrefix::CfwAndPreWhirOpening {
                completed_outer: after_completed_outer,
                active: after_active,
            },
        ) => {
            core::ptr::eq(*before_statement, *after_cfw_statement)
                && core::ptr::eq(*pre_challenge_opening, context.pre_challenge_opening)
                && completed_outer == after_completed_outer
                && after_active
                    .pre_challenge_opening
                    .batching_challenge
                    .is_none()
                && cfw_prefix_appends_final_message(before_active, &after_active.cfw)
        }
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw,
                pre_challenge_opening,
            },
            SemanticConstructionPrefix::CfwAndPreWhirOpening {
                completed_outer,
                active,
            },
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
                epoch: TranscriptEpoch::PreChallenge,
                batch_ordinal: 0,
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(_),
            SemanticConstructionPrefix::PreChallengeWhir {
                completed_cfw,
                history,
                ..
            },
        ) => {
            core::ptr::eq(*cfw, context.cfw)
                && core::ptr::eq(*pre_challenge_opening, context.pre_challenge_opening)
                && completed_cfw
                    == &SemanticCompletedCfwHandoff {
                        completed_outer: completed_outer.clone(),
                        cfw_and_pre_challenge_opening: active.clone(),
                    }
                && history.opening_prefix == active.pre_challenge_opening
                && history.completed_components.is_empty()
        }
        (
            SemanticVerifierMoveOwner::WhirBaseCombination {
                epoch: TranscriptEpoch::PreChallenge,
            },
            SemanticVerifierMoveStatement::WhirBase(before_base_statement),
            SemanticConstructionPrefix::PreChallengeWhir {
                completed_cfw,
                history,
                active: SemanticVerifierMovePrefix::WhirBase(before_base_prefix),
            },
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
                pre_challenge_base,
                main_opening,
            },
            SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
                completed_cfw: after_completed_cfw,
                history: after_history,
                active: after_active,
            },
        ) => {
            *before_base_statement == *pre_challenge_base
                && core::ptr::eq(*main_opening, context.main_opening)
                && completed_cfw == after_completed_cfw
                && history == after_history
                && after_active.main_opening.batching_challenge.is_none()
                && whir_base_prefix_appends_revealed_witness(
                    before_base_prefix,
                    &after_active.pre_challenge_base,
                )
        }
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
                pre_challenge_base,
                main_opening,
            },
            SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
                completed_cfw,
                history: pre_challenge_history,
                active,
            },
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
                epoch: TranscriptEpoch::Main,
                batch_ordinal: 0,
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(_),
            SemanticConstructionPrefix::MainWhir {
                completed_pre_challenge,
                history: main_history,
                ..
            },
        ) => {
            core::ptr::eq(*main_opening, context.main_opening)
                && completed_pre_challenge
                    == &SemanticCompletedPreChallengeWhirHandoff {
                        completed_cfw: completed_cfw.clone(),
                        pre_challenge_history: pre_challenge_history.clone(),
                        pre_challenge_base: (*pre_challenge_base).clone(),
                        pre_final_and_main_opening: active.clone(),
                    }
                && main_history.opening_prefix == active.main_opening
                && main_history.completed_components.is_empty()
        }
        (
            before_owner,
            before_statement,
            SemanticConstructionPrefix::PreChallengeWhir {
                completed_cfw,
                history: before_history,
                active: before_active,
            },
            after_owner,
            after_statement,
            SemanticConstructionPrefix::PreChallengeWhir {
                completed_cfw: after_completed_cfw,
                history: after_history,
                active: after_active,
            },
        ) => {
            completed_cfw == after_completed_cfw
                && whir_prover_prefix_is_exact_successor(
                    TranscriptEpoch::PreChallenge,
                    before_owner,
                    before_statement,
                    before_history,
                    before_active,
                    after_owner,
                    after_statement,
                    after_history,
                    after_active,
                )?
        }
        (
            before_owner,
            before_statement,
            SemanticConstructionPrefix::MainWhir {
                completed_pre_challenge,
                history: before_history,
                active: before_active,
            },
            after_owner,
            after_statement,
            SemanticConstructionPrefix::MainWhir {
                completed_pre_challenge: after_completed_pre_challenge,
                history: after_history,
                active: after_active,
            },
        ) => {
            completed_pre_challenge == after_completed_pre_challenge
                && whir_prover_prefix_is_exact_successor(
                    TranscriptEpoch::Main,
                    before_owner,
                    before_statement,
                    before_history,
                    before_active,
                    after_owner,
                    after_statement,
                    after_history,
                    after_active,
                )?
        }
        _ => false,
    };
    Ok(exact_successor)
}

fn cfw_prefix_appends_round_polynomial(
    before: &SemanticCfwTranscriptPrefix,
    after: &SemanticCfwTranscriptPrefix,
) -> bool {
    if after.round_polynomials.len() != before.round_polynomials.len().saturating_add(1) {
        return false;
    }
    let Some(next_polynomial) = after.round_polynomials.last() else {
        return false;
    };
    let mut expected = before.clone();
    expected.round_polynomials.push(next_polynomial.clone());
    expected == *after
}

fn cfw_prefix_appends_final_message(
    before: &SemanticCfwTranscriptPrefix,
    after: &SemanticCfwTranscriptPrefix,
) -> bool {
    if before.final_message.is_some()
        || before.joint_constraint_challenge.is_some()
        || after.final_message.is_none()
        || after.joint_constraint_challenge.is_some()
    {
        return false;
    }
    let mut expected = before.clone();
    expected.final_message.clone_from(&after.final_message);
    expected == *after
}

#[allow(clippy::too_many_arguments)]
fn whir_prover_prefix_is_exact_successor<Matrices: CompactCfwR1csMatrices>(
    epoch: TranscriptEpoch,
    before_owner: SemanticVerifierMoveOwner,
    before_statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    before_history: &SemanticWhirEpochHistory,
    before_active: &SemanticVerifierMovePrefix,
    after_owner: SemanticVerifierMoveOwner,
    after_statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    after_history: &SemanticWhirEpochHistory,
    after_active: &SemanticVerifierMovePrefix,
) -> Result<bool, SemanticConstructionError> {
    let exact_successor = match (
        before_owner,
        before_statement,
        before_active,
        after_owner,
        after_statement,
        after_active,
    ) {
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
                epoch: before_epoch,
                batch_ordinal,
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(before_statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(before_prefix),
            SemanticVerifierMoveOwner::WhirFolding {
                epoch: after_epoch,
                batch_ordinal: after_batch_ordinal,
                round_ordinal: 0,
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(after_statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(after_prefix),
        ) => {
            before_epoch == epoch
                && after_epoch == epoch
                && batch_ordinal == after_batch_ordinal
                && *before_statement == *after_statement
                && before_history == after_history
                && whir_masked_prefix_appends_round_wire(before_prefix, after_prefix)
        }
        (
            SemanticVerifierMoveOwner::WhirFolding {
                epoch: before_epoch,
                batch_ordinal,
                round_ordinal,
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(before_statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(before_prefix),
            SemanticVerifierMoveOwner::WhirFolding {
                epoch: after_epoch,
                batch_ordinal: after_batch_ordinal,
                round_ordinal: after_round_ordinal,
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(after_statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(after_prefix),
        ) => {
            before_epoch == epoch
                && after_epoch == epoch
                && batch_ordinal == after_batch_ordinal
                && round_ordinal.checked_add(1) == Some(after_round_ordinal)
                && *before_statement == *after_statement
                && before_history == after_history
                && whir_masked_prefix_appends_round_wire(before_prefix, after_prefix)
        }
        (
            SemanticVerifierMoveOwner::WhirFolding {
                epoch: before_epoch,
                batch_ordinal,
                ..
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(before_statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(before_prefix),
            SemanticVerifierMoveOwner::WhirCodeSwitch {
                epoch: after_epoch,
                round_ordinal,
            },
            SemanticVerifierMoveStatement::WhirCodeSwitch(_),
            SemanticVerifierMovePrefix::WhirCodeSwitch(_),
        ) => {
            before_epoch == epoch
                && after_epoch == epoch
                && batch_ordinal == round_ordinal
                && history_appends_component(
                    before_history,
                    after_history,
                    SemanticWhirCompletedComponent::MaskedSumcheck {
                        statement: (*before_statement).clone(),
                        prefix: before_prefix.clone(),
                    },
                )
        }
        (
            SemanticVerifierMoveOwner::WhirFolding {
                epoch: before_epoch,
                batch_ordinal,
                ..
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(before_statement),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(before_prefix),
            SemanticVerifierMoveOwner::WhirBaseCombination { epoch: after_epoch },
            SemanticVerifierMoveStatement::WhirBase(_),
            SemanticVerifierMovePrefix::WhirBase(_),
        ) => {
            before_epoch == epoch
                && after_epoch == epoch
                && usize::from(batch_ordinal) == WHIR_ROUND_COUNT
                && history_appends_component(
                    before_history,
                    after_history,
                    SemanticWhirCompletedComponent::MaskedSumcheck {
                        statement: (*before_statement).clone(),
                        prefix: before_prefix.clone(),
                    },
                )
        }
        (
            SemanticVerifierMoveOwner::WhirCodeSwitch {
                epoch: before_epoch,
                round_ordinal,
            },
            SemanticVerifierMoveStatement::WhirCodeSwitch(before_statement),
            SemanticVerifierMovePrefix::WhirCodeSwitch(before_prefix),
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
                epoch: after_epoch,
                batch_ordinal,
            },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(_),
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(_),
        ) => {
            before_epoch == epoch
                && after_epoch == epoch
                && round_ordinal.checked_add(1) == Some(batch_ordinal)
                && history_appends_component(
                    before_history,
                    after_history,
                    SemanticWhirCompletedComponent::CodeSwitch {
                        statement: (*before_statement).clone(),
                        prefix: before_prefix.clone(),
                    },
                )
        }
        (
            SemanticVerifierMoveOwner::WhirBaseCombination {
                epoch: TranscriptEpoch::Main,
            },
            SemanticVerifierMoveStatement::WhirBase(before_statement),
            SemanticVerifierMovePrefix::WhirBase(before_prefix),
            SemanticVerifierMoveOwner::MainWhirFinalQueries,
            SemanticVerifierMoveStatement::WhirBase(after_statement),
            SemanticVerifierMovePrefix::WhirBase(after_prefix),
        ) => {
            epoch == TranscriptEpoch::Main
                && *before_statement == *after_statement
                && before_history == after_history
                && whir_base_prefix_appends_revealed_witness(before_prefix, after_prefix)
        }
        _ => false,
    };
    Ok(exact_successor)
}

fn whir_masked_prefix_appends_round_wire(
    before: &SemanticWhirMaskedSumcheckPrefix,
    after: &SemanticWhirMaskedSumcheckPrefix,
) -> bool {
    if after.round_wires.len() != before.round_wires.len().saturating_add(1) {
        return false;
    }
    let Some(next_wire) = after.round_wires.last() else {
        return false;
    };
    let mut expected = before.clone();
    expected.round_wires.push(next_wire.clone());
    expected == *after
}

fn whir_base_prefix_appends_revealed_witness(
    before: &SemanticWhirBasePrefix,
    after: &SemanticWhirBasePrefix,
) -> bool {
    if before.revealed_witness.is_some() || after.revealed_witness.is_none() {
        return false;
    }
    let mut expected = before.clone();
    expected
        .revealed_witness
        .clone_from(&after.revealed_witness);
    expected == *after
}

fn history_appends_component(
    before: &SemanticWhirEpochHistory,
    after: &SemanticWhirEpochHistory,
    expected_component: SemanticWhirCompletedComponent,
) -> bool {
    if before.opening_prefix != after.opening_prefix
        || after.completed_components.len() != before.completed_components.len().saturating_add(1)
    {
        return false;
    }
    let Some((last, preceding)) = after.completed_components.split_last() else {
        return false;
    };
    preceding == before.completed_components.as_slice() && last == &expected_component
}

fn early_product_state_holds<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    completed_outer: &SemanticProductionOuterPrefix,
    witness: &SemanticConstructionWitness,
    require_pre_challenge_input: bool,
) -> Result<bool, SemanticConstructionError> {
    let Some(initial) = initial_witness(context, witness) else {
        return Ok(false);
    };
    if !initial_witness_bindings_hold(&initial)
        || !outer_commitment_bindings_hold(context, completed_outer)
        || !semantic_production_outer_kstate(context.outer, completed_outer, &initial.outer)?
    {
        return Ok(false);
    }
    if !require_pre_challenge_input {
        return Ok(true);
    }
    let pre_challenge = pre_challenge_input_witness(&initial);
    semantic_whir_opening_batching_kstate(context.pre_challenge_opening, None, &pre_challenge)
        .map_err(Into::into)
}

fn initial_witness<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    witness: &SemanticConstructionWitness,
) -> Option<InitialWitness> {
    match witness {
        SemanticConstructionWitness::OuterAndCfw { outer, cfw } => Some(InitialWitness {
            outer: outer.clone(),
            cfw: cfw.clone(),
        }),
        SemanticConstructionWitness::PreChallengeAndMainInput {
            pre_challenge: SemanticConstructionWhirWitness::Generalized(pre_challenge),
            main,
        } => initial_witness_from_handoff(context, pre_challenge, main),
        SemanticConstructionWitness::PreChallengeAndMainInput {
            pre_challenge: SemanticConstructionWhirWitness::Base(_),
            ..
        }
        | SemanticConstructionWitness::MainWhir(_)
        | SemanticConstructionWitness::Terminal => None,
    }
}

fn initial_witness_from_handoff<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    pre_challenge: &SemanticGeneralizedRelationWitness,
    main: &SemanticGeneralizedRelationWitness,
) -> Option<InitialWitness> {
    let [inner_masks, outer_masks, cross_epoch_masks] = main.masks.as_slice() else {
        return None;
    };
    let [pre_challenge_cross_epoch_masks] = pre_challenge.masks.as_slice() else {
        return None;
    };
    if pre_challenge_cross_epoch_masks != cross_epoch_masks {
        return None;
    }
    let geometry = CompactCfwGeometry::derive(context.cfw.matrices.witness_length()).ok()?;
    let cfw = semantic_cfw_witness_from_code_witnesses(
        geometry,
        main.source.clone(),
        inner_masks.clone(),
        outer_masks.clone(),
        cross_epoch_masks.clone(),
    )
    .ok()?;
    let outer = SemanticProductionOuterWitness {
        pre_challenge_source: pre_challenge.source.clone(),
        main_source: cfw.source_code_witness.clone(),
        shared_masks: cfw.cross_epoch_mask_code_witness.clone(),
    };
    Some(InitialWitness { outer, cfw })
}

fn initial_witness_bindings_hold(initial: &InitialWitness) -> bool {
    initial.outer.main_source == initial.cfw.source_code_witness
        && initial.outer.shared_masks == initial.cfw.cross_epoch_mask_code_witness
}

fn pre_challenge_input_witness(initial: &InitialWitness) -> SemanticGeneralizedRelationWitness {
    SemanticGeneralizedRelationWitness {
        source: initial.outer.pre_challenge_source.clone(),
        masks: vec![initial.outer.shared_masks.clone()],
    }
}

fn main_input_witness<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    witness: &SemanticConstructionWitness,
) -> Option<SemanticGeneralizedRelationWitness> {
    match witness {
        SemanticConstructionWitness::OuterAndCfw { cfw, .. } => {
            Some(main_input_witness_from_cfw(cfw))
        }
        SemanticConstructionWitness::PreChallengeAndMainInput { main, .. }
        | SemanticConstructionWitness::MainWhir(SemanticConstructionWhirWitness::Generalized(
            main,
        )) => Some(main.clone()),
        SemanticConstructionWitness::MainWhir(SemanticConstructionWhirWitness::Base(base)) => {
            semantic_whir_base_input_witness(base).cloned()
        }
        SemanticConstructionWitness::Terminal => None,
    }
    .filter(|main| {
        let (relation, _) = semantic_whir_opening_input_pair(context.main_opening);
        main.masks.len() == relation.mask_codes.len()
    })
}

fn main_input_witness_from_cfw(
    cfw: &SemanticCfwExtractedWitness,
) -> SemanticGeneralizedRelationWitness {
    SemanticGeneralizedRelationWitness {
        source: cfw.source_code_witness.clone(),
        masks: vec![
            cfw.inner_mask_code_witness.clone(),
            cfw.outer_mask_code_witness.clone(),
            cfw.cross_epoch_mask_code_witness.clone(),
        ],
    }
}

fn outer_commitment_bindings_hold<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    prefix: &SemanticProductionOuterPrefix,
) -> bool {
    let commitments = match prefix {
        SemanticProductionOuterPrefix::PostLookupCommitments { commitments, .. }
        | SemanticProductionOuterPrefix::CrossEpochPointSampled { commitments, .. }
        | SemanticProductionOuterPrefix::CrossEpochDisclosuresSent { commitments, .. } => {
            Some(commitments)
        }
        SemanticProductionOuterPrefix::Empty
        | SemanticProductionOuterPrefix::PreChallengeSourceCommitted { .. }
        | SemanticProductionOuterPrefix::LookupChallengeSampled { .. } => None,
    };
    let Some(commitments) = commitments else {
        return matches!(
            prefix,
            SemanticProductionOuterPrefix::Empty
                | SemanticProductionOuterPrefix::PreChallengeSourceCommitted { .. }
                | SemanticProductionOuterPrefix::LookupChallengeSampled { .. }
        );
    };
    completed_commitments_match_context(context, commitments)
}

fn completed_commitments_match_context<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    commitments: &SemanticProductionOuterCommitments,
) -> bool {
    let (_, pre_instance) = semantic_whir_opening_input_pair(context.pre_challenge_opening);
    commitments.pre_challenge_source == pre_instance.source
        && commitments.main_source == context.cfw.committed_instances.source
        && commitments.shared_masks == context.cfw.cross_epoch_handoff.committed_instance
}

fn local_prefix(
    descriptor: &SemanticFactorOneMoveDescriptor,
    prefix: &SemanticConstructionPrefix,
) -> Result<SemanticVerifierMovePrefix, SemanticConstructionError> {
    let local = match (descriptor.owner(), prefix) {
        (
            SemanticVerifierMoveOwner::LookupChallenge | SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticConstructionPrefix::Outer(prefix),
        ) => SemanticVerifierMovePrefix::ProductionOuter(prefix.clone()),
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness
            | SemanticVerifierMoveOwner::CfwSumcheckRound { .. },
            SemanticConstructionPrefix::Cfw { active, .. },
        ) => SemanticVerifierMovePrefix::Cfw(active.clone()),
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticConstructionPrefix::CfwAndPreWhirOpening { active, .. },
        ) => SemanticVerifierMovePrefix::CfwAndPreWhirOpening(active.clone()),
        (owner, SemanticConstructionPrefix::PreChallengeWhir { active: prefix, .. })
            if verifier_move_epoch(owner) == Some(TranscriptEpoch::PreChallenge) =>
        {
            prefix.clone()
        }
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticConstructionPrefix::PreWhirFinalAndMainOpening { active: prefix, .. },
        ) => SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(prefix.clone()),
        (owner, SemanticConstructionPrefix::MainWhir { active: prefix, .. })
            if verifier_move_epoch(owner) == Some(TranscriptEpoch::Main) =>
        {
            prefix.clone()
        }
        _ => return Err(SemanticConstructionError::MismatchedPrefixPhase),
    };
    Ok(local)
}

fn local_witness<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    owner: SemanticVerifierMoveOwner,
    prefix: &SemanticConstructionPrefix,
    witness: &SemanticConstructionWitness,
) -> Option<SemanticKnowledgeWitness> {
    match prefix {
        SemanticConstructionPrefix::Outer(_) => initial_witness(context, witness)
            .map(|initial| SemanticKnowledgeWitness::ProductionOuter(initial.outer)),
        SemanticConstructionPrefix::Cfw { .. } => initial_witness(context, witness)
            .map(|initial| SemanticKnowledgeWitness::Cfw(initial.cfw)),
        SemanticConstructionPrefix::CfwAndPreWhirOpening { .. } => {
            initial_witness(context, witness).map(|initial| {
                SemanticKnowledgeWitness::CfwAndPreWhirOpening(
                    SemanticCfwAndPreWhirOpeningWitness {
                        pre_challenge_whir: pre_challenge_input_witness(&initial),
                        cfw: initial.cfw,
                    },
                )
            })
        }
        SemanticConstructionPrefix::PreChallengeWhir { .. } => {
            let SemanticConstructionWitness::PreChallengeAndMainInput { pre_challenge, .. } =
                witness
            else {
                return None;
            };
            whir_local_witness(owner, pre_challenge)
        }
        SemanticConstructionPrefix::PreWhirFinalAndMainOpening { active: prefix, .. } => {
            match witness {
                SemanticConstructionWitness::PreChallengeAndMainInput {
                    pre_challenge:
                        SemanticConstructionWhirWitness::Base(
                            SemanticWhirBaseKnowledgeWitness::Blinded(pre_challenge_whir),
                        ),
                    main,
                } if prefix.pre_challenge_base.query_challenges.is_none() => {
                    Some(SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(
                        SemanticPreWhirFinalAndMainOpeningWitness::BeforeVerifierMove {
                            pre_challenge_whir: pre_challenge_whir.clone(),
                            main_whir: main.clone(),
                        },
                    ))
                }
                SemanticConstructionWitness::MainWhir(
                    SemanticConstructionWhirWitness::Generalized(main_whir),
                ) if prefix.pre_challenge_base.query_challenges.is_some() => {
                    Some(SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(
                        SemanticPreWhirFinalAndMainOpeningWitness::AfterVerifierMove {
                            main_whir: main_whir.clone(),
                        },
                    ))
                }
                _ => None,
            }
        }
        SemanticConstructionPrefix::MainWhir { .. } => match witness {
            SemanticConstructionWitness::MainWhir(main) => whir_local_witness(owner, main),
            SemanticConstructionWitness::Terminal
                if owner == SemanticVerifierMoveOwner::MainWhirFinalQueries =>
            {
                Some(SemanticKnowledgeWitness::WhirBase(
                    SemanticWhirBaseKnowledgeWitness::Terminal,
                ))
            }
            _ => None,
        },
    }
}

fn whir_local_witness(
    owner: SemanticVerifierMoveOwner,
    witness: &SemanticConstructionWhirWitness,
) -> Option<SemanticKnowledgeWitness> {
    match (owner, witness) {
        (
            SemanticVerifierMoveOwner::WhirBaseCombination { .. }
            | SemanticVerifierMoveOwner::MainWhirFinalQueries,
            SemanticConstructionWhirWitness::Base(witness),
        ) => Some(SemanticKnowledgeWitness::WhirBase(witness.clone())),
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { .. }
            | SemanticVerifierMoveOwner::WhirFolding { .. }
            | SemanticVerifierMoveOwner::WhirCodeSwitch { .. },
            SemanticConstructionWhirWitness::Generalized(witness),
        ) => Some(SemanticKnowledgeWitness::Generalized(witness.clone())),
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { .. }
            | SemanticVerifierMoveOwner::WhirFolding { .. }
            | SemanticVerifierMoveOwner::WhirCodeSwitch { .. },
            SemanticConstructionWhirWitness::Base(witness),
        ) => semantic_whir_base_input_witness(witness)
            .cloned()
            .map(SemanticKnowledgeWitness::Generalized),
        _ => None,
    }
}

fn construction_predecessor_witness<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    owner: SemanticVerifierMoveOwner,
    prefix: &SemanticConstructionPrefix,
    post_challenge_witness: &SemanticConstructionWitness,
    local_predecessor: SemanticKnowledgeWitness,
) -> Result<SemanticConstructionWitness, SemanticConstructionError> {
    match (prefix, local_predecessor) {
        (
            SemanticConstructionPrefix::Outer(_),
            SemanticKnowledgeWitness::ProductionOuter(outer),
        ) => {
            let initial = initial_witness(context, post_challenge_witness)
                .ok_or(SemanticConstructionError::MismatchedWitnessPhase)?;
            Ok(SemanticConstructionWitness::OuterAndCfw {
                outer,
                cfw: initial.cfw,
            })
        }
        (SemanticConstructionPrefix::Cfw { .. }, SemanticKnowledgeWitness::Cfw(cfw)) => {
            let initial = initial_witness(context, post_challenge_witness)
                .ok_or(SemanticConstructionError::MismatchedWitnessPhase)?;
            Ok(SemanticConstructionWitness::OuterAndCfw {
                outer: SemanticProductionOuterWitness {
                    pre_challenge_source: initial.outer.pre_challenge_source,
                    main_source: cfw.source_code_witness.clone(),
                    shared_masks: cfw.cross_epoch_mask_code_witness.clone(),
                },
                cfw,
            })
        }
        (
            SemanticConstructionPrefix::CfwAndPreWhirOpening { .. },
            SemanticKnowledgeWitness::CfwAndPreWhirOpening(predecessor),
        ) => Ok(SemanticConstructionWitness::OuterAndCfw {
            outer: SemanticProductionOuterWitness {
                pre_challenge_source: predecessor.pre_challenge_whir.source,
                main_source: predecessor.cfw.source_code_witness.clone(),
                shared_masks: predecessor.cfw.cross_epoch_mask_code_witness.clone(),
            },
            cfw: predecessor.cfw,
        }),
        (
            SemanticConstructionPrefix::PreChallengeWhir { .. },
            SemanticKnowledgeWitness::Generalized(pre_challenge),
        ) => retained_main_witness(post_challenge_witness, |main| {
            SemanticConstructionWitness::PreChallengeAndMainInput {
                pre_challenge: SemanticConstructionWhirWitness::Generalized(pre_challenge),
                main,
            }
        }),
        (
            SemanticConstructionPrefix::PreChallengeWhir { .. },
            SemanticKnowledgeWitness::WhirBase(pre_challenge),
        ) => retained_main_witness(post_challenge_witness, |main| {
            SemanticConstructionWitness::PreChallengeAndMainInput {
                pre_challenge: SemanticConstructionWhirWitness::Base(pre_challenge),
                main,
            }
        }),
        (
            SemanticConstructionPrefix::PreWhirFinalAndMainOpening { .. },
            SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(
                SemanticPreWhirFinalAndMainOpeningWitness::BeforeVerifierMove {
                    pre_challenge_whir,
                    main_whir,
                },
            ),
        ) => Ok(SemanticConstructionWitness::PreChallengeAndMainInput {
            pre_challenge: SemanticConstructionWhirWitness::Base(
                SemanticWhirBaseKnowledgeWitness::Blinded(pre_challenge_whir),
            ),
            main: main_whir,
        }),
        (
            SemanticConstructionPrefix::MainWhir { .. },
            SemanticKnowledgeWitness::Generalized(main),
        ) => Ok(SemanticConstructionWitness::MainWhir(
            SemanticConstructionWhirWitness::Generalized(main),
        )),
        (SemanticConstructionPrefix::MainWhir { .. }, SemanticKnowledgeWitness::WhirBase(main)) => {
            Ok(SemanticConstructionWitness::MainWhir(
                SemanticConstructionWhirWitness::Base(main),
            ))
        }
        _ => {
            let _ = owner;
            Err(SemanticConstructionError::MismatchedWitnessPhase)
        }
    }
}

fn retained_main_witness(
    post_challenge_witness: &SemanticConstructionWitness,
    build: impl FnOnce(SemanticGeneralizedRelationWitness) -> SemanticConstructionWitness,
) -> Result<SemanticConstructionWitness, SemanticConstructionError> {
    let SemanticConstructionWitness::PreChallengeAndMainInput { main, .. } = post_challenge_witness
    else {
        return Err(SemanticConstructionError::MismatchedWitnessPhase);
    };
    Ok(build(main.clone()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SemanticWhirNextComponent {
    MaskedSumcheck { batch_ordinal: u8 },
    CodeSwitch { round_ordinal: u8 },
    Base,
}

fn replay_whir_epoch_history(
    opening: &SemanticWhirOpeningBatchingStatement,
    history: &SemanticWhirEpochHistory,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
        SemanticWhirNextComponent,
    ),
    SemanticConstructionError,
> {
    let (mut relation, mut instance) =
        semantic_whir_opening_output_pair(opening, &history.opening_prefix)?;
    let mut next = SemanticWhirNextComponent::MaskedSumcheck { batch_ordinal: 0 };
    for completed in &history.completed_components {
        match (next, completed) {
            (
                SemanticWhirNextComponent::MaskedSumcheck { batch_ordinal },
                SemanticWhirCompletedComponent::MaskedSumcheck { statement, prefix },
            ) if statement.batch_ordinal()? == batch_ordinal => {
                let input = semantic_whir_masked_sumcheck_input_pair(statement);
                if *input.0 != relation || *input.1 != instance {
                    return Err(SemanticConstructionError::InvalidWhirChronology);
                }
                (relation, instance) =
                    semantic_whir_masked_sumcheck_output_pair(statement, prefix)?;
                next = if usize::from(batch_ordinal) == WHIR_ROUND_COUNT {
                    SemanticWhirNextComponent::Base
                } else {
                    SemanticWhirNextComponent::CodeSwitch {
                        round_ordinal: batch_ordinal,
                    }
                };
            }
            (
                SemanticWhirNextComponent::CodeSwitch { round_ordinal },
                SemanticWhirCompletedComponent::CodeSwitch { statement, prefix },
            ) if statement.round_ordinal()? == round_ordinal => {
                let input = semantic_whir_code_switch_input_pair(statement);
                if *input.0 != relation || *input.1 != instance {
                    return Err(SemanticConstructionError::InvalidWhirChronology);
                }
                (relation, instance) = semantic_whir_code_switch_output_pair(statement, prefix)?;
                next = SemanticWhirNextComponent::MaskedSumcheck {
                    batch_ordinal: round_ordinal
                        .checked_add(1)
                        .ok_or(SemanticConstructionError::InvalidWhirChronology)?,
                };
            }
            _ => return Err(SemanticConstructionError::InvalidWhirChronology),
        }
    }
    Ok((relation, instance, next))
}

fn validate_active_whir_statement<Matrices: CompactCfwR1csMatrices>(
    owner: SemanticVerifierMoveOwner,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    opening: &SemanticWhirOpeningBatchingStatement,
    history: &SemanticWhirEpochHistory,
) -> Result<(), SemanticConstructionError> {
    let (relation, instance, next) = replay_whir_epoch_history(opening, history)?;
    let matches = match (owner, statement, next) {
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { batch_ordinal, .. }
            | SemanticVerifierMoveOwner::WhirFolding { batch_ordinal, .. },
            SemanticVerifierMoveStatement::WhirMaskedSumcheck(statement),
            SemanticWhirNextComponent::MaskedSumcheck {
                batch_ordinal: expected_batch_ordinal,
            },
        ) if batch_ordinal == expected_batch_ordinal => {
            let input = semantic_whir_masked_sumcheck_input_pair(statement);
            *input.0 == relation && *input.1 == instance
        }
        (
            SemanticVerifierMoveOwner::WhirCodeSwitch { round_ordinal, .. },
            SemanticVerifierMoveStatement::WhirCodeSwitch(statement),
            SemanticWhirNextComponent::CodeSwitch {
                round_ordinal: expected_round_ordinal,
            },
        ) if round_ordinal == expected_round_ordinal => {
            let input = semantic_whir_code_switch_input_pair(statement);
            *input.0 == relation && *input.1 == instance
        }
        (
            SemanticVerifierMoveOwner::WhirBaseCombination { .. }
            | SemanticVerifierMoveOwner::MainWhirFinalQueries,
            SemanticVerifierMoveStatement::WhirBase(statement),
            SemanticWhirNextComponent::Base,
        ) => {
            let input = semantic_whir_base_input_pair(statement);
            *input.0 == relation && *input.1 == instance
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(SemanticConstructionError::InvalidWhirChronology)
    }
}

fn validate_completed_cfw_handoff<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    completed: &SemanticCompletedCfwHandoff,
) -> Result<(), SemanticConstructionError> {
    if !matches!(
        completed.completed_outer,
        SemanticProductionOuterPrefix::CrossEpochDisclosuresSent { .. }
    ) || !outer_commitment_bindings_hold(context, &completed.completed_outer)
        || completed
            .cfw_and_pre_challenge_opening
            .cfw
            .joint_constraint_challenge
            .is_none()
        || completed
            .cfw_and_pre_challenge_opening
            .pre_challenge_opening
            .batching_challenge
            .is_none()
    {
        return Err(SemanticConstructionError::InvalidConstructionChronology);
    }
    let cfw_output = semantic_cfw_output_relation_and_instance(
        context.cfw,
        &completed.cfw_and_pre_challenge_opening.cfw,
    )?;
    let main_input = semantic_whir_opening_input_pair(context.main_opening);
    if cfw_output.0 != *main_input.0 || cfw_output.1 != *main_input.1 {
        return Err(SemanticConstructionError::InvalidConstructionChronology);
    }
    Ok(())
}

fn validate_pre_challenge_foundation<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    completed_cfw: &SemanticCompletedCfwHandoff,
    history: &SemanticWhirEpochHistory,
) -> Result<(), SemanticConstructionError> {
    validate_completed_cfw_handoff(context, completed_cfw)?;
    if history.opening_prefix
        != completed_cfw
            .cfw_and_pre_challenge_opening
            .pre_challenge_opening
    {
        return Err(SemanticConstructionError::InvalidConstructionChronology);
    }
    Ok(())
}

fn validate_completed_pre_challenge_handoff<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    completed: &SemanticCompletedPreChallengeWhirHandoff,
) -> Result<(), SemanticConstructionError> {
    validate_pre_challenge_foundation(
        context,
        &completed.completed_cfw,
        &completed.pre_challenge_history,
    )?;
    let (relation, instance, next) = replay_whir_epoch_history(
        context.pre_challenge_opening,
        &completed.pre_challenge_history,
    )?;
    let base_input = semantic_whir_base_input_pair(&completed.pre_challenge_base);
    if next != SemanticWhirNextComponent::Base
        || *base_input.0 != relation
        || *base_input.1 != instance
        || completed
            .pre_final_and_main_opening
            .main_opening
            .batching_challenge
            .is_none()
    {
        return Err(SemanticConstructionError::InvalidConstructionChronology);
    }
    semantic_whir_base_final_errbr(
        &completed.pre_challenge_base,
        &completed.pre_final_and_main_opening.pre_challenge_base,
    )?;
    semantic_whir_opening_output_pair(
        context.main_opening,
        &completed.pre_final_and_main_opening.main_opening,
    )?;
    Ok(())
}

fn validate_statement_and_phase<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    prefix: &SemanticConstructionPrefix,
) -> Result<(), SemanticConstructionError> {
    match (descriptor.owner(), statement, prefix) {
        (
            SemanticVerifierMoveOwner::LookupChallenge | SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMoveStatement::ProductionOuter(statement),
            SemanticConstructionPrefix::Outer(_),
        ) if core::ptr::eq(*statement, context.outer) => Ok(()),
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness
            | SemanticVerifierMoveOwner::CfwSumcheckRound { .. },
            SemanticVerifierMoveStatement::Cfw(statement),
            SemanticConstructionPrefix::Cfw { .. },
        ) if core::ptr::eq(*statement, context.cfw) => Ok(()),
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw,
                pre_challenge_opening,
            },
            SemanticConstructionPrefix::CfwAndPreWhirOpening { .. },
        ) if core::ptr::eq(*cfw, context.cfw)
            && core::ptr::eq(*pre_challenge_opening, context.pre_challenge_opening) =>
        {
            Ok(())
        }
        (
            owner,
            _,
            SemanticConstructionPrefix::PreChallengeWhir {
                completed_cfw,
                history,
                ..
            },
        ) if verifier_move_epoch(owner) == Some(TranscriptEpoch::PreChallenge) => {
            validate_pre_challenge_foundation(context, completed_cfw, history)?;
            validate_active_whir_statement(owner, statement, context.pre_challenge_opening, history)
        }
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
                pre_challenge_base,
                main_opening,
            },
            SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
                completed_cfw,
                history,
                ..
            },
        ) if core::ptr::eq(*main_opening, context.main_opening) => {
            validate_pre_challenge_foundation(context, completed_cfw, history)?;
            let (relation, instance, next) =
                replay_whir_epoch_history(context.pre_challenge_opening, history)?;
            let input = semantic_whir_base_input_pair(pre_challenge_base);
            if next == SemanticWhirNextComponent::Base
                && *input.0 == relation
                && *input.1 == instance
            {
                Ok(())
            } else {
                Err(SemanticConstructionError::InvalidWhirChronology)
            }
        }
        (
            owner,
            _,
            SemanticConstructionPrefix::MainWhir {
                completed_pre_challenge,
                history,
                ..
            },
        ) if verifier_move_epoch(owner) == Some(TranscriptEpoch::Main) => {
            validate_completed_pre_challenge_handoff(context, completed_pre_challenge)?;
            if history.opening_prefix
                != completed_pre_challenge
                    .pre_final_and_main_opening
                    .main_opening
            {
                return Err(SemanticConstructionError::InvalidConstructionChronology);
            }
            validate_active_whir_statement(owner, statement, context.main_opening, history)
        }
        _ => Err(SemanticConstructionError::MismatchedPrefixPhase),
    }
}

/// Checks only the bindings needed to dispatch one deterministic backward
/// extraction step.
///
/// Completed-phase acceptance and WHIR relation replay are `KState`
/// obligations. Repeating them inside `ERRBR` would make the extractor invoke
/// the potentially inefficient state predicate indirectly and would add
/// history-dependent work that is absent from the local extraction algorithm.
/// The local dispatcher still validates the exact move owner, component
/// ordinal, and extended-prefix stage before it runs.
fn validate_extractor_statement_and_phase<Matrices: CompactCfwR1csMatrices>(
    context: &SemanticConstructionContext<'_, '_, Matrices>,
    descriptor: &SemanticFactorOneMoveDescriptor,
    statement: &SemanticVerifierMoveStatement<'_, '_, Matrices>,
    prefix: &SemanticConstructionPrefix,
) -> Result<(), SemanticConstructionError> {
    match (descriptor.owner(), statement, prefix) {
        (
            SemanticVerifierMoveOwner::LookupChallenge | SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMoveStatement::ProductionOuter(statement),
            SemanticConstructionPrefix::Outer(_),
        ) if core::ptr::eq(*statement, context.outer) => Ok(()),
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness
            | SemanticVerifierMoveOwner::CfwSumcheckRound { .. },
            SemanticVerifierMoveStatement::Cfw(statement),
            SemanticConstructionPrefix::Cfw { .. },
        ) if core::ptr::eq(*statement, context.cfw) => Ok(()),
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw,
                pre_challenge_opening,
            },
            SemanticConstructionPrefix::CfwAndPreWhirOpening { .. },
        ) if core::ptr::eq(*cfw, context.cfw)
            && core::ptr::eq(*pre_challenge_opening, context.pre_challenge_opening) =>
        {
            Ok(())
        }
        (owner, _, SemanticConstructionPrefix::PreChallengeWhir { .. })
            if verifier_move_epoch(owner) == Some(TranscriptEpoch::PreChallenge) =>
        {
            Ok(())
        }
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening { main_opening, .. },
            SemanticConstructionPrefix::PreWhirFinalAndMainOpening { .. },
        ) if core::ptr::eq(*main_opening, context.main_opening) => Ok(()),
        (owner, _, SemanticConstructionPrefix::MainWhir { .. })
            if verifier_move_epoch(owner) == Some(TranscriptEpoch::Main) =>
        {
            Ok(())
        }
        _ => Err(SemanticConstructionError::MismatchedPrefixPhase),
    }
}

const fn verifier_move_epoch(owner: SemanticVerifierMoveOwner) -> Option<TranscriptEpoch> {
    match owner {
        SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { epoch, .. }
        | SemanticVerifierMoveOwner::WhirFolding { epoch, .. }
        | SemanticVerifierMoveOwner::WhirCodeSwitch { epoch, .. }
        | SemanticVerifierMoveOwner::WhirBaseCombination { epoch } => Some(epoch),
        SemanticVerifierMoveOwner::MainWhirFinalQueries => Some(TranscriptEpoch::Main),
        SemanticVerifierMoveOwner::LookupChallenge
        | SemanticVerifierMoveOwner::CrossEpochPoint
        | SemanticVerifierMoveOwner::CfwInitialRandomness
        | SemanticVerifierMoveOwner::CfwSumcheckRound { .. }
        | SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening
        | SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticConstructionError {
    Cfw(SemanticCfwError),
    Execution(SemanticExecutionError),
    InconsistentBadTransition,
    InvalidConstructionChronology,
    InvalidProverChronology,
    InvalidProductionBinding,
    InvalidWhirChronology,
    MismatchedPrefixPhase,
    MismatchedWitnessPhase,
    Outer(SemanticOuterError),
    ProverMoveRepairedKnowledgeState,
    Whir(SemanticWhirError),
}

impl From<SemanticCfwError> for SemanticConstructionError {
    fn from(error: SemanticCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl From<SemanticExecutionError> for SemanticConstructionError {
    fn from(error: SemanticExecutionError) -> Self {
        Self::Execution(error)
    }
}

impl From<SemanticOuterError> for SemanticConstructionError {
    fn from(error: SemanticOuterError) -> Self {
        Self::Outer(error)
    }
}

impl From<SemanticWhirError> for SemanticConstructionError {
    fn from(error: SemanticWhirError) -> Self {
        Self::Whir(error)
    }
}

#[cfg(test)]
mod tests;
