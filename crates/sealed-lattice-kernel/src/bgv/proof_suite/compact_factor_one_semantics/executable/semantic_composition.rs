//! Semantic owners for verifier moves shared by adjacent reductions.
//!
//! The production chronology contains two atomic verifier moves with two
//! roles. They cannot be proved by pretending that an extra prover message
//! separates the roles. These owners evaluate both post states under the same
//! extended transcript and run both backward extractors before accepting the
//! reconstructed predecessor.

use super::semantic_whir::{
    SemanticWhirBaseKnowledgeWitness, SemanticWhirBasePrefix, SemanticWhirBaseQueryEscape,
    SemanticWhirBaseStatement, SemanticWhirError, SemanticWhirOpeningBatchingBadTransition,
    SemanticWhirOpeningBatchingPrefix, SemanticWhirOpeningBatchingStatement,
    semantic_whir_base_final_bad_transition, semantic_whir_base_final_errbr,
    semantic_whir_base_kstate, semantic_whir_opening_batching_bad_transition,
    semantic_whir_opening_batching_errbr, semantic_whir_opening_batching_kstate,
};
use super::*;

pub(super) struct SemanticCfwAndPreWhirOpeningStatement<
    'borrow,
    'cfw_statement,
    Matrices: CompactCfwR1csMatrices,
> {
    cfw: &'borrow SemanticCfwStatement<'cfw_statement, Matrices>,
    pre_challenge_opening: &'borrow SemanticWhirOpeningBatchingStatement,
}

impl<'borrow, 'cfw_statement, Matrices: CompactCfwR1csMatrices>
    SemanticCfwAndPreWhirOpeningStatement<'borrow, 'cfw_statement, Matrices>
{
    pub(super) const fn new(
        cfw: &'borrow SemanticCfwStatement<'cfw_statement, Matrices>,
        pre_challenge_opening: &'borrow SemanticWhirOpeningBatchingStatement,
    ) -> Self {
        Self {
            cfw,
            pre_challenge_opening,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwAndPreWhirOpeningPrefix {
    pub(super) cfw: SemanticCfwTranscriptPrefix,
    pub(super) pre_challenge_opening: SemanticWhirOpeningBatchingPrefix,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwAndPreWhirOpeningWitness {
    pub(super) cfw: SemanticCfwExtractedWitness,
    pub(super) pre_challenge_whir: SemanticGeneralizedRelationWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwAndPreWhirOpeningExtraction {
    pub(super) witness: Option<SemanticCfwAndPreWhirOpeningWitness>,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwAndPreWhirOpeningBadTransition {
    pub(super) cfw: Option<SemanticCfwBadTransition>,
    pub(super) pre_challenge_opening: Option<SemanticWhirOpeningBatchingBadTransition>,
}

pub(super) fn semantic_cfw_and_pre_whir_opening_kstate<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwAndPreWhirOpeningStatement<'_, '_, Matrices>,
    prefix: &SemanticCfwAndPreWhirOpeningPrefix,
    witness: &SemanticCfwAndPreWhirOpeningWitness,
) -> Result<bool, SemanticCompositionError> {
    validate_cfw_and_pre_whir_opening_prefix(prefix)?;
    Ok(
        semantic_cfw_kstate(statement.cfw, Some(&prefix.cfw), &witness.cfw)?
            && semantic_whir_opening_batching_kstate(
                statement.pre_challenge_opening,
                Some(&prefix.pre_challenge_opening),
                &witness.pre_challenge_whir,
            )?,
    )
}

pub(super) fn semantic_cfw_and_pre_whir_opening_errbr<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwAndPreWhirOpeningStatement<'_, '_, Matrices>,
    extended_prefix: &SemanticCfwAndPreWhirOpeningPrefix,
    post_challenge_witness: &SemanticCfwAndPreWhirOpeningWitness,
) -> Result<SemanticCfwAndPreWhirOpeningExtraction, SemanticCompositionError> {
    validate_extended_cfw_and_pre_whir_opening_prefix(extended_prefix)?;
    let cfw_extraction = semantic_cfw_errbr_at_verifier_move(
        statement.cfw,
        &extended_prefix.cfw,
        &post_challenge_witness.cfw,
    )?;
    let pre_challenge_extraction = semantic_whir_opening_batching_errbr(
        statement.pre_challenge_opening,
        &extended_prefix.pre_challenge_opening,
        &post_challenge_witness.pre_challenge_whir,
    )?;
    let field_operation_count = cfw_extraction
        .field_operation_count
        .checked_add(pre_challenge_extraction.field_operation_count)
        .ok_or(SemanticCompositionError::ArithmeticOverflow)?;
    let (Some(cfw), Some(pre_challenge_whir)) =
        (cfw_extraction.witness, pre_challenge_extraction.witness)
    else {
        return Ok(SemanticCfwAndPreWhirOpeningExtraction {
            witness: None,
            field_operation_count,
        });
    };
    let preceding_witness = SemanticCfwAndPreWhirOpeningWitness {
        cfw,
        pre_challenge_whir,
    };
    Ok(SemanticCfwAndPreWhirOpeningExtraction {
        witness: Some(preceding_witness),
        field_operation_count,
    })
}

pub(super) fn semantic_cfw_and_pre_whir_opening_bad_transition<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwAndPreWhirOpeningStatement<'_, '_, Matrices>,
    extended_prefix: &SemanticCfwAndPreWhirOpeningPrefix,
    post_challenge_witness: &SemanticCfwAndPreWhirOpeningWitness,
) -> Result<Option<SemanticCfwAndPreWhirOpeningBadTransition>, SemanticCompositionError> {
    validate_extended_cfw_and_pre_whir_opening_prefix(extended_prefix)?;
    if !semantic_cfw_and_pre_whir_opening_kstate(
        statement,
        extended_prefix,
        post_challenge_witness,
    )? {
        return Ok(None);
    }
    let cfw = semantic_cfw_bad_transition(
        statement.cfw,
        &extended_prefix.cfw,
        &post_challenge_witness.cfw,
    )?;
    let pre_challenge_opening = semantic_whir_opening_batching_bad_transition(
        statement.pre_challenge_opening,
        &extended_prefix.pre_challenge_opening,
        &post_challenge_witness.pre_challenge_whir,
    )?;
    if cfw.is_none() && pre_challenge_opening.is_none() {
        return Ok(None);
    }
    Ok(Some(SemanticCfwAndPreWhirOpeningBadTransition {
        cfw,
        pre_challenge_opening,
    }))
}

fn validate_cfw_and_pre_whir_opening_prefix(
    prefix: &SemanticCfwAndPreWhirOpeningPrefix,
) -> Result<(), SemanticCompositionError> {
    match (
        prefix.cfw.joint_constraint_challenge,
        prefix.pre_challenge_opening.batching_challenge,
    ) {
        (None, None) | (Some(_), Some(_)) => Ok(()),
        _ => Err(SemanticCompositionError::MalformedCombinedPrefix),
    }
}

fn validate_extended_cfw_and_pre_whir_opening_prefix(
    prefix: &SemanticCfwAndPreWhirOpeningPrefix,
) -> Result<(), SemanticCompositionError> {
    validate_cfw_and_pre_whir_opening_prefix(prefix)?;
    if prefix.cfw.joint_constraint_challenge.is_none() {
        return Err(SemanticCompositionError::MalformedCombinedPrefix);
    }
    Ok(())
}

pub(super) struct SemanticPreWhirFinalAndMainOpeningStatement<'statement> {
    pre_challenge_base: &'statement SemanticWhirBaseStatement,
    main_opening: &'statement SemanticWhirOpeningBatchingStatement,
}

impl<'statement> SemanticPreWhirFinalAndMainOpeningStatement<'statement> {
    pub(super) const fn new(
        pre_challenge_base: &'statement SemanticWhirBaseStatement,
        main_opening: &'statement SemanticWhirOpeningBatchingStatement,
    ) -> Self {
        Self {
            pre_challenge_base,
            main_opening,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticPreWhirFinalAndMainOpeningPrefix {
    pub(super) pre_challenge_base: SemanticWhirBasePrefix,
    pub(super) main_opening: SemanticWhirOpeningBatchingPrefix,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticPreWhirFinalAndMainOpeningWitness {
    BeforeVerifierMove {
        pre_challenge_whir: SemanticGeneralizedRelationWitness,
        main_whir: SemanticGeneralizedRelationWitness,
    },
    AfterVerifierMove {
        main_whir: SemanticGeneralizedRelationWitness,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticPreWhirFinalAndMainOpeningExtraction {
    pub(super) witness: Option<SemanticPreWhirFinalAndMainOpeningWitness>,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticPreWhirFinalAndMainOpeningBadTransition {
    pub(super) pre_challenge_query_escapes: Option<Vec<SemanticWhirBaseQueryEscape>>,
    pub(super) main_opening: Option<SemanticWhirOpeningBatchingBadTransition>,
}

pub(super) fn semantic_pre_whir_final_and_main_opening_kstate(
    statement: &SemanticPreWhirFinalAndMainOpeningStatement<'_>,
    prefix: &SemanticPreWhirFinalAndMainOpeningPrefix,
    witness: &SemanticPreWhirFinalAndMainOpeningWitness,
) -> Result<bool, SemanticCompositionError> {
    validate_pre_whir_final_and_main_opening_prefix(prefix)?;
    match (
        prefix.pre_challenge_base.query_challenges.is_some(),
        prefix.main_opening.batching_challenge.is_some(),
        witness,
    ) {
        (
            false,
            false,
            SemanticPreWhirFinalAndMainOpeningWitness::BeforeVerifierMove {
                pre_challenge_whir,
                main_whir,
            },
        ) => Ok(semantic_whir_base_kstate(
            statement.pre_challenge_base,
            Some(&prefix.pre_challenge_base),
            &SemanticWhirBaseKnowledgeWitness::Blinded(pre_challenge_whir.clone()),
        )? && semantic_whir_opening_batching_kstate(
            statement.main_opening,
            Some(&prefix.main_opening),
            main_whir,
        )?),
        (
            true,
            true,
            SemanticPreWhirFinalAndMainOpeningWitness::AfterVerifierMove { main_whir },
        ) => Ok(semantic_whir_base_kstate(
            statement.pre_challenge_base,
            Some(&prefix.pre_challenge_base),
            &SemanticWhirBaseKnowledgeWitness::Terminal,
        )? && semantic_whir_opening_batching_kstate(
            statement.main_opening,
            Some(&prefix.main_opening),
            main_whir,
        )?),
        _ => Ok(false),
    }
}

pub(super) fn semantic_pre_whir_final_and_main_opening_errbr(
    statement: &SemanticPreWhirFinalAndMainOpeningStatement<'_>,
    extended_prefix: &SemanticPreWhirFinalAndMainOpeningPrefix,
    post_challenge_witness: &SemanticPreWhirFinalAndMainOpeningWitness,
) -> Result<SemanticPreWhirFinalAndMainOpeningExtraction, SemanticCompositionError> {
    validate_extended_pre_whir_final_and_main_opening_prefix(extended_prefix)?;
    let SemanticPreWhirFinalAndMainOpeningWitness::AfterVerifierMove { main_whir } =
        post_challenge_witness
    else {
        return Err(SemanticCompositionError::MalformedCombinedPrefix);
    };
    let pre_challenge_extraction = semantic_whir_base_final_errbr(
        statement.pre_challenge_base,
        &extended_prefix.pre_challenge_base,
    )?;
    let main_extraction = semantic_whir_opening_batching_errbr(
        statement.main_opening,
        &extended_prefix.main_opening,
        main_whir,
    )?;
    let field_operation_count = pre_challenge_extraction
        .field_operation_count
        .checked_add(main_extraction.field_operation_count)
        .ok_or(SemanticCompositionError::ArithmeticOverflow)?;
    let (Some(pre_challenge_whir), Some(main_whir)) =
        (pre_challenge_extraction.witness, main_extraction.witness)
    else {
        return Ok(SemanticPreWhirFinalAndMainOpeningExtraction {
            witness: None,
            field_operation_count,
        });
    };
    let preceding_witness = SemanticPreWhirFinalAndMainOpeningWitness::BeforeVerifierMove {
        pre_challenge_whir,
        main_whir,
    };
    Ok(SemanticPreWhirFinalAndMainOpeningExtraction {
        witness: Some(preceding_witness),
        field_operation_count,
    })
}

pub(super) fn semantic_pre_whir_final_and_main_opening_bad_transition(
    statement: &SemanticPreWhirFinalAndMainOpeningStatement<'_>,
    extended_prefix: &SemanticPreWhirFinalAndMainOpeningPrefix,
    post_challenge_witness: &SemanticPreWhirFinalAndMainOpeningWitness,
) -> Result<Option<SemanticPreWhirFinalAndMainOpeningBadTransition>, SemanticCompositionError> {
    validate_extended_pre_whir_final_and_main_opening_prefix(extended_prefix)?;
    if !semantic_pre_whir_final_and_main_opening_kstate(
        statement,
        extended_prefix,
        post_challenge_witness,
    )? {
        return Ok(None);
    }
    let SemanticPreWhirFinalAndMainOpeningWitness::AfterVerifierMove { main_whir } =
        post_challenge_witness
    else {
        return Err(SemanticCompositionError::MalformedCombinedPrefix);
    };
    let pre_challenge_query_escapes = semantic_whir_base_final_bad_transition(
        statement.pre_challenge_base,
        &extended_prefix.pre_challenge_base,
    )?;
    let main_opening = semantic_whir_opening_batching_bad_transition(
        statement.main_opening,
        &extended_prefix.main_opening,
        main_whir,
    )?;
    if pre_challenge_query_escapes.is_none() && main_opening.is_none() {
        return Ok(None);
    }
    Ok(Some(SemanticPreWhirFinalAndMainOpeningBadTransition {
        pre_challenge_query_escapes,
        main_opening,
    }))
}

fn validate_pre_whir_final_and_main_opening_prefix(
    prefix: &SemanticPreWhirFinalAndMainOpeningPrefix,
) -> Result<(), SemanticCompositionError> {
    match (
        prefix.pre_challenge_base.query_challenges.is_some(),
        prefix.main_opening.batching_challenge.is_some(),
    ) {
        (false, false) | (true, true) => Ok(()),
        _ => Err(SemanticCompositionError::MalformedCombinedPrefix),
    }
}

fn validate_extended_pre_whir_final_and_main_opening_prefix(
    prefix: &SemanticPreWhirFinalAndMainOpeningPrefix,
) -> Result<(), SemanticCompositionError> {
    validate_pre_whir_final_and_main_opening_prefix(prefix)?;
    if prefix.pre_challenge_base.query_challenges.is_none() {
        return Err(SemanticCompositionError::MalformedCombinedPrefix);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticCompositionError {
    ArithmeticOverflow,
    Cfw(SemanticCfwError),
    MalformedCombinedPrefix,
    Whir(SemanticWhirError),
}

impl From<SemanticCfwError> for SemanticCompositionError {
    fn from(error: SemanticCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl From<SemanticWhirError> for SemanticCompositionError {
    fn from(error: SemanticWhirError) -> Self {
        Self::Whir(error)
    }
}
