//! Executable CDHZ semantics for one production hiding-WHIR masked-sumcheck
//! component.
//!
//! The state after each verifier challenge is the concrete generalized
//! committed relation from Construction 6.3. Source rows and coefficient
//! columns are folded in the production prefix order, carried-mask covectors
//! absorb `epsilon / 2^j`, and the fresh sumcheck masks use the exact
//! past/future recurrence. The backward extractor decodes the preceding
//! source and every mask with the selected canonical decoder. A bad transition
//! is classified only after the post-challenge state holds and the preceding
//! state reconstructed by that extractor does not.

use super::*;
use crate::bgv::proof_suite::compact_public_key_static_catalog::canonical_reed_solomon::{
    canonical_reed_solomon_evaluation_points, correct_canonical_interleaved_reed_solomon_erasures,
    encode_canonical_interleaved_reed_solomon_with_operation_count,
};
use crate::bgv::proof_suite::compact_public_key_static_catalog::relaxed_round_by_round::{
    CommittedMaskCodeRelation, GeneralizedCommittedRelation,
};

mod base_case;
mod opening_batching;

pub(super) use base_case::{
    SemanticWhirBaseCombinationBadTransition, SemanticWhirBaseFreshMessage,
    SemanticWhirBaseKnowledgeWitness, SemanticWhirBaseOracleRole,
    SemanticWhirBasePreCombinationWitness, SemanticWhirBasePrefix, SemanticWhirBaseQueryChallenges,
    SemanticWhirBaseQueryEscape, SemanticWhirBaseStatement,
    semantic_whir_base_combination_bad_transition, semantic_whir_base_combination_errbr,
    semantic_whir_base_final_bad_transition, semantic_whir_base_final_errbr,
    semantic_whir_base_kstate,
};
pub(super) use opening_batching::{
    SemanticWhirOpeningBatchingBadTransition, SemanticWhirOpeningBatchingPrefix,
    SemanticWhirOpeningBatchingStatement, semantic_whir_opening_batching_bad_transition,
    semantic_whir_opening_batching_errbr, semantic_whir_opening_batching_kstate,
};

pub(super) fn semantic_whir_opening_batching_boundaries(
    input_relation: GeneralizedCommittedRelation,
    input_instance: SemanticGeneralizedRelationInstance,
    batching_challenge: ProofChallengeExtensionElement,
) -> Result<
    (
        (
            GeneralizedCommittedRelation,
            SemanticGeneralizedRelationInstance,
        ),
        (
            GeneralizedCommittedRelation,
            SemanticGeneralizedRelationInstance,
        ),
    ),
    SemanticWhirError,
> {
    let statement = opening_batching::SemanticWhirOpeningBatchingStatement::new(
        input_relation,
        input_instance,
    )?;
    let input = (
        statement.input_relation.clone(),
        statement.input_instance.clone(),
    );
    let output = opening_batching::batched_relation_and_instance(&statement, batching_challenge)?;
    Ok((input, output))
}

pub(super) fn semantic_whir_opening_input_pair(
    statement: &SemanticWhirOpeningBatchingStatement,
) -> (
    &GeneralizedCommittedRelation,
    &SemanticGeneralizedRelationInstance,
) {
    (&statement.input_relation, &statement.input_instance)
}

pub(super) fn semantic_whir_opening_output_pair(
    statement: &SemanticWhirOpeningBatchingStatement,
    prefix: &SemanticWhirOpeningBatchingPrefix,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    let challenge = prefix
        .batching_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    opening_batching::batched_relation_and_instance(statement, challenge)
}

pub(super) fn semantic_whir_base_input_witness(
    witness: &SemanticWhirBaseKnowledgeWitness,
) -> Option<&SemanticGeneralizedRelationWitness> {
    match witness {
        SemanticWhirBaseKnowledgeWitness::Input(input)
        | SemanticWhirBaseKnowledgeWitness::PreCombination(
            SemanticWhirBasePreCombinationWitness { input, .. },
        ) => Some(input),
        SemanticWhirBaseKnowledgeWitness::Blinded(_)
        | SemanticWhirBaseKnowledgeWitness::Terminal => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticWhirMaskedSumcheckStatement {
    input_relation: GeneralizedCommittedRelation,
    input_instance: SemanticGeneralizedRelationInstance,
    sumcheck_mask_relation: CommittedMaskCodeRelation,
    sumcheck_mask_instance: SemanticCommittedCodeInstance,
    folding_factor: usize,
    sumcheck_mask_message_length: usize,
}

impl SemanticWhirMaskedSumcheckStatement {
    pub(super) fn new(
        input_relation: GeneralizedCommittedRelation,
        input_instance: SemanticGeneralizedRelationInstance,
        sumcheck_mask_relation: CommittedMaskCodeRelation,
        sumcheck_mask_instance: SemanticCommittedCodeInstance,
    ) -> Result<Self, SemanticWhirError> {
        validate_generalized_relation_descriptor(&input_relation)?;
        let source_width = usize::try_from(input_relation.source_code.interleaving_width)
            .map_err(|_| SemanticWhirError::InvalidGeometry)?;
        if source_width < 2 || !source_width.is_power_of_two() {
            return Err(SemanticWhirError::InvalidGeometry);
        }
        let folding_factor = source_width.ilog2() as usize;
        let expected_source_width = 1_usize
            .checked_shl(
                u32::try_from(folding_factor).map_err(|_| SemanticWhirError::ArithmeticOverflow)?,
            )
            .ok_or(SemanticWhirError::ArithmeticOverflow)?;
        let sumcheck_mask_width = usize::try_from(sumcheck_mask_relation.code.interleaving_width)
            .map_err(|_| SemanticWhirError::InvalidGeometry)?;
        let sumcheck_mask_message_length =
            usize::try_from(sumcheck_mask_relation.code.message_length)
                .map_err(|_| SemanticWhirError::InvalidGeometry)?;
        if expected_source_width != source_width
            || sumcheck_mask_width != folding_factor
            || sumcheck_mask_message_length < 3
            || input_relation.opening_evaluation_claim_count != 0
            || input_relation.carried_reduction_claim_count != 1
            || input_relation.claim_count != 1
            || input_instance.opening_claims.len() != 0
            || input_instance.carried_reduction_claims.len() != 1
            || input_instance.masks.len() != input_relation.mask_codes.len()
        {
            return Err(SemanticWhirError::InvalidGeometry);
        }
        semantic_code_geometry(&sumcheck_mask_relation.code)?;
        validate_committed_instance_shape(&sumcheck_mask_relation.code, &sumcheck_mask_instance)?;
        validate_committed_instance_shape(&input_relation.source_code, &input_instance.source)?;
        for (mask_relation, mask_instance) in
            input_relation.mask_codes.iter().zip(&input_instance.masks)
        {
            validate_committed_instance_shape(&mask_relation.code, mask_instance)?;
        }
        validate_claim_shape(
            &input_relation,
            input_instance
                .carried_reduction_claims
                .first()
                .ok_or(SemanticWhirError::InvalidGeometry)?,
        )?;
        Ok(Self {
            input_relation,
            input_instance,
            sumcheck_mask_relation,
            sumcheck_mask_instance,
            folding_factor,
            sumcheck_mask_message_length,
        })
    }

    pub(super) const fn folding_factor(&self) -> usize {
        self.folding_factor
    }

    pub(super) fn wire_coefficient_count(&self) -> usize {
        self.sumcheck_mask_message_length.max(3) - 1
    }

    pub(super) fn batch_ordinal(&self) -> Result<u8, SemanticWhirError> {
        match self.sumcheck_mask_relation.role {
            super::super::MaskGroupRole::WhirSumcheck { batch_ordinal } => Ok(batch_ordinal),
            _ => Err(SemanticWhirError::InvalidGeometry),
        }
    }
}

pub(super) fn semantic_whir_masked_sumcheck_input_pair(
    statement: &SemanticWhirMaskedSumcheckStatement,
) -> (
    &GeneralizedCommittedRelation,
    &SemanticGeneralizedRelationInstance,
) {
    (&statement.input_relation, &statement.input_instance)
}

pub(super) fn semantic_whir_masked_sumcheck_output_pair(
    statement: &SemanticWhirMaskedSumcheckStatement,
    prefix: &SemanticWhirMaskedSumcheckPrefix,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    validate_prefix(statement, prefix)?;
    let combining_challenge = prefix
        .combining_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    if prefix.round_challenges.len() != statement.folding_factor
        || prefix.round_wires.len() != statement.folding_factor
    {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    relation_after_challenges(
        statement,
        prefix,
        combining_challenge,
        statement.folding_factor,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticWhirMaskedSumcheckPrefix {
    pub(super) mask_hypercube_sum: ProofChallengeExtensionElement,
    pub(super) combining_challenge: Option<ProofChallengeExtensionElement>,
    /// Canonical production wire order `[c_0, c_2, ..., c_d]`.
    pub(super) round_wires: Vec<Vec<ProofChallengeExtensionElement>>,
    pub(super) round_challenges: Vec<ProofChallengeExtensionElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticWhirExtraction {
    pub(super) witness: Option<SemanticGeneralizedRelationWitness>,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticWhirMcaCombination {
    /// `(1 - challenge) * first + challenge * second`.
    AffineFold,
    /// `first + challenge * second`.
    AdditiveCombination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticWhirMcaUncorrectableComponent {
    First,
    Second,
}

/// Concrete witness for the binary-generator mutual-correlated-agreement event.
///
/// The agreement positions are derived from the verifier-consumed combined
/// rows and the canonical codeword carried by the post-challenge witness. On
/// that same set, the selected deterministic erasure corrector has proved that
/// the named component is not the restriction of any codeword. This is the
/// event in Definition 3.14, rather than a producer-supplied completion flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticWhirMcaCertificate {
    pub(super) combination: SemanticWhirMcaCombination,
    pub(super) challenge: ProofChallengeExtensionElement,
    pub(super) agreement_positions: Vec<usize>,
    pub(super) target_domain_size: usize,
    pub(super) selected_decoding_error_count: usize,
    pub(super) uncorrectable_component: SemanticWhirMcaUncorrectableComponent,
}

impl SemanticWhirMcaCertificate {
    pub(super) const fn correlated_function_count(&self) -> usize {
        2
    }

    /// In the strict unique-decoding regime, the binary generator has at most
    /// one bad challenge per target-domain position.
    pub(super) fn exact_error_numerator(&self) -> Result<u64, SemanticWhirError> {
        u64::try_from(self.target_domain_size).map_err(|_| SemanticWhirError::ArithmeticOverflow)
    }
}

enum SemanticWhirBinaryMcaReconstruction {
    Witness {
        first: SemanticCommittedCodeWitness,
        second: SemanticCommittedCodeWitness,
        field_operation_count: u128,
    },
    Certificate(SemanticWhirMcaCertificate),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticWhirVerifierTransition {
    CombiningChallenge,
    SumcheckRound { round_ordinal: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticWhirBadTransition {
    MutualCorrelatedAgreement {
        transition: SemanticWhirVerifierTransition,
        certificate: SemanticWhirMcaCertificate,
    },
    NonzeroPolynomialRoot {
        transition: SemanticWhirVerifierTransition,
        coefficients: Vec<ProofChallengeExtensionElement>,
        challenge: ProofChallengeExtensionElement,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticWhirError {
    ArithmeticOverflow,
    InconsistentBadTransition,
    InvalidGeometry,
    MalformedPrefix,
    Relation(SemanticRelationError),
}

impl From<SemanticRelationError> for SemanticWhirError {
    fn from(error: SemanticRelationError) -> Self {
        Self::Relation(error)
    }
}

impl From<CanonicalReedSolomonError> for SemanticWhirError {
    fn from(error: CanonicalReedSolomonError) -> Self {
        Self::Relation(error.into())
    }
}

/// Concrete knowledge-state predicate for one masked-sumcheck component.
///
/// `None` is the component's input relation. A prover prefix carries the
/// preceding state unchanged. Once `epsilon` is present, every completed
/// verifier challenge selects the exact folded generalized relation.
pub(super) fn semantic_whir_masked_sumcheck_kstate(
    statement: &SemanticWhirMaskedSumcheckStatement,
    prefix: Option<&SemanticWhirMaskedSumcheckPrefix>,
    witness: &SemanticGeneralizedRelationWitness,
) -> Result<bool, SemanticWhirError> {
    let Some(prefix) = prefix else {
        return semantic_generalized_relation_holds(
            &statement.input_relation,
            &statement.input_instance,
            witness,
        )
        .map_err(Into::into);
    };
    validate_prefix(statement, prefix)?;
    let Some(combining_challenge) = prefix.combining_challenge else {
        return semantic_generalized_relation_holds(
            &statement.input_relation,
            &statement.input_instance,
            witness,
        )
        .map_err(Into::into);
    };
    let (relation, instance) = relation_after_challenges(
        statement,
        prefix,
        combining_challenge,
        prefix.round_challenges.len(),
    )?;
    semantic_generalized_relation_holds(&relation, &instance, witness).map_err(Into::into)
}

/// Deterministic polynomial-time CDHZ backward extractor.
///
/// The algorithm executes the selected canonical decoder on every oracle of
/// the immediately preceding relation. It deliberately does not call
/// `KState`, because CDHZ allows that predicate to be inefficient while
/// requiring `ERRBR` to run in polynomial time. Decoder failure returns bottom;
/// the bad-transition experiment separately checks the returned predecessor.
pub(super) fn semantic_whir_masked_sumcheck_errbr(
    statement: &SemanticWhirMaskedSumcheckStatement,
    extended_prefix: &SemanticWhirMaskedSumcheckPrefix,
    _post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<SemanticWhirExtraction, SemanticWhirError> {
    validate_prefix(statement, extended_prefix)?;
    let (preceding_relation, preceding_instance) =
        preceding_relation_and_instance(statement, extended_prefix)?;
    let decoded =
        match decode_generalized_relation_witness(&preceding_relation, &preceding_instance) {
            Ok(decoded) => decoded,
            Err(SemanticRelationError::CodeCorrection(_))
            | Err(SemanticRelationError::RelationNotSatisfied) => {
                return Ok(SemanticWhirExtraction {
                    witness: None,
                    field_operation_count: 0,
                });
            }
            Err(error) => return Err(error.into()),
        };
    Ok(SemanticWhirExtraction {
        witness: Some(decoded.witness),
        field_operation_count: decoded.field_operation_count,
    })
}

/// Executes the bad-transition implication used by the soundness proof.
///
/// This is deliberately not a Boolean supplied by the producer. The function
/// checks the post state, reconstructs the preceding candidate, checks the
/// preceding state, and then derives either the exact binary MCA event or the
/// explicit nonzero polynomial that vanishes at the sampled challenge.
pub(super) fn semantic_whir_masked_sumcheck_bad_transition(
    statement: &SemanticWhirMaskedSumcheckStatement,
    extended_prefix: &SemanticWhirMaskedSumcheckPrefix,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<Option<SemanticWhirBadTransition>, SemanticWhirError> {
    validate_prefix(statement, extended_prefix)?;
    if !semantic_whir_masked_sumcheck_kstate(
        statement,
        Some(extended_prefix),
        post_challenge_witness,
    )? {
        return Ok(None);
    }
    let transition = verifier_transition(extended_prefix)?;
    let (preceding_relation, preceding_instance) =
        preceding_relation_and_instance(statement, extended_prefix)?;
    let (preceding_witness, coefficients, challenge) = match transition {
        SemanticWhirVerifierTransition::CombiningChallenge => {
            let decoded =
                match decode_generalized_relation_witness(&preceding_relation, &preceding_instance)
                {
                    Ok(decoded) => decoded,
                    Err(SemanticRelationError::CodeCorrection(_)) => {
                        return Err(SemanticWhirError::InconsistentBadTransition);
                    }
                    Err(error) => return Err(error.into()),
                };
            if semantic_generalized_relation_holds(
                &preceding_relation,
                &preceding_instance,
                &decoded.witness,
            )? {
                return Ok(None);
            }
            let combining_challenge = extended_prefix
                .combining_challenge
                .ok_or(SemanticWhirError::MalformedPrefix)?;
            let sumcheck_mask_witness = decode_committed_witness(
                &statement.sumcheck_mask_relation.code,
                &statement.sumcheck_mask_instance,
            )?
            .0;
            let mut expected_masks = decoded.witness.masks.clone();
            expected_masks.push(sumcheck_mask_witness.clone());
            let expected_post_witness = SemanticGeneralizedRelationWitness {
                source: decoded.witness.source.clone(),
                masks: expected_masks,
            };
            if expected_post_witness != *post_challenge_witness {
                // Every oracle is unchanged at this transition (apart from
                // appending the separately committed mask). Two different
                // witnesses inside the strict unique radius are impossible.
                return Err(SemanticWhirError::InconsistentBadTransition);
            }
            let input_claim = statement
                .input_instance
                .carried_reduction_claims
                .first()
                .ok_or(SemanticWhirError::InvalidGeometry)?;
            let input_left_hand_side = evaluate_claim(input_claim, &decoded.witness)?;
            let mask_hypercube_sum =
                sumcheck_mask_hypercube_sum(&sumcheck_mask_witness, statement.folding_factor)?;
            (
                decoded.witness,
                vec![
                    mask_hypercube_sum.subtract(extended_prefix.mask_hypercube_sum),
                    input_left_hand_side.subtract(input_claim.target),
                ],
                combining_challenge,
            )
        }
        SemanticWhirVerifierTransition::SumcheckRound { round_ordinal } => {
            let challenge = *extended_prefix
                .round_challenges
                .get(round_ordinal)
                .ok_or(SemanticWhirError::MalformedPrefix)?;
            let (post_relation, post_instance) = relation_after_challenges(
                statement,
                extended_prefix,
                extended_prefix
                    .combining_challenge
                    .ok_or(SemanticWhirError::MalformedPrefix)?,
                round_ordinal + 1,
            )?;
            let (first_rows, second_rows) =
                split_binary_fold_rows(&preceding_instance.source.received_rows)?;
            let source_reconstruction = reconstruct_binary_mca_components(
                &post_relation.source_code,
                &first_rows,
                &second_rows,
                &post_instance.source,
                &post_challenge_witness.source,
                challenge,
                SemanticWhirMcaCombination::AffineFold,
            )?;
            let (first_source, second_source) = match source_reconstruction {
                SemanticWhirBinaryMcaReconstruction::Witness {
                    first,
                    second,
                    field_operation_count: _,
                } => (first, second),
                SemanticWhirBinaryMcaReconstruction::Certificate(certificate) => {
                    return Ok(Some(SemanticWhirBadTransition::MutualCorrelatedAgreement {
                        transition,
                        certificate,
                    }));
                }
            };
            let source = join_binary_fold_witnesses(first_source, second_source)?;
            let masks = decode_unchanged_masks(
                &preceding_relation,
                &preceding_instance,
                &post_challenge_witness.masks,
            )?;
            let preceding_witness = SemanticGeneralizedRelationWitness { source, masks };
            if semantic_generalized_relation_holds(
                &preceding_relation,
                &preceding_instance,
                &preceding_witness,
            )? {
                return Ok(None);
            }
            if fold_generalized_witness_once(&preceding_witness, challenge)?
                != *post_challenge_witness
            {
                return Err(SemanticWhirError::InconsistentBadTransition);
            }
            let actual_polynomial = expected_round_polynomial(
                statement,
                &preceding_relation,
                &preceding_instance,
                &preceding_witness,
                round_ordinal,
            )?;
            let target_before_challenge = replay_target(statement, extended_prefix, round_ordinal)?;
            let transcript_polynomial = reconstruct_round_polynomial(
                target_before_challenge,
                extended_prefix
                    .round_wires
                    .get(round_ordinal)
                    .ok_or(SemanticWhirError::MalformedPrefix)?,
            )?;
            (
                preceding_witness,
                subtract_polynomials(&actual_polynomial, &transcript_polynomial),
                challenge,
            )
        }
    };
    debug_assert!(
        semantic_generalized_relation_holds(
            &preceding_relation,
            &preceding_instance,
            &preceding_witness,
        )? == false
    );
    if coefficients.iter().all(|coefficient| coefficient.is_zero())
        || !evaluate_polynomial(&coefficients, challenge).is_zero()
    {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    Ok(Some(SemanticWhirBadTransition::NonzeroPolynomialRoot {
        transition,
        coefficients,
        challenge,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticWhirCodeSwitchStatement {
    input_relation: GeneralizedCommittedRelation,
    input_instance: SemanticGeneralizedRelationInstance,
    output_source_relation: CommittedCodeRelation,
    output_source_instance: SemanticCommittedCodeInstance,
    switch_mask_relation: CommittedMaskCodeRelation,
    switch_mask_instance: SemanticCommittedCodeInstance,
    query_count: usize,
}

impl SemanticWhirCodeSwitchStatement {
    pub(super) fn new(
        input_relation: GeneralizedCommittedRelation,
        input_instance: SemanticGeneralizedRelationInstance,
        output_source_relation: CommittedCodeRelation,
        output_source_instance: SemanticCommittedCodeInstance,
        switch_mask_relation: CommittedMaskCodeRelation,
        switch_mask_instance: SemanticCommittedCodeInstance,
        query_count: usize,
    ) -> Result<Self, SemanticWhirError> {
        validate_generalized_relation_descriptor(&input_relation)?;
        let input_message_count = input_relation
            .source_code
            .message_length
            .checked_mul(input_relation.source_code.interleaving_width)
            .ok_or(SemanticWhirError::ArithmeticOverflow)?;
        let output_message_count = output_source_relation
            .message_length
            .checked_mul(output_source_relation.interleaving_width)
            .ok_or(SemanticWhirError::ArithmeticOverflow)?;
        if input_relation.source_code.interleaving_width != 1
            || input_relation.opening_evaluation_claim_count != 0
            || input_relation.carried_reduction_claim_count != 1
            || input_relation.claim_count != 1
            || input_instance.opening_claims.len() != 0
            || input_instance.carried_reduction_claims.len() != 1
            || input_instance.masks.len() != input_relation.mask_codes.len()
            || input_message_count != output_message_count
            || switch_mask_relation.code.interleaving_width != 1
            || switch_mask_relation.code.message_length
                != input_relation.source_code.hiding_randomness_length
            || query_count == 0
            || !u64::try_from(query_count)
                .is_ok_and(|query_count| query_count <= input_relation.source_code.block_length)
        {
            return Err(SemanticWhirError::InvalidGeometry);
        }
        semantic_code_geometry(&output_source_relation)?;
        semantic_code_geometry(&switch_mask_relation.code)?;
        validate_committed_instance_shape(&input_relation.source_code, &input_instance.source)?;
        validate_committed_instance_shape(&output_source_relation, &output_source_instance)?;
        validate_committed_instance_shape(&switch_mask_relation.code, &switch_mask_instance)?;
        for (mask_relation, mask_instance) in
            input_relation.mask_codes.iter().zip(&input_instance.masks)
        {
            validate_committed_instance_shape(&mask_relation.code, mask_instance)?;
        }
        validate_claim_shape(
            &input_relation,
            input_instance
                .carried_reduction_claims
                .first()
                .ok_or(SemanticWhirError::InvalidGeometry)?,
        )?;
        Ok(Self {
            input_relation,
            input_instance,
            output_source_relation,
            output_source_instance,
            switch_mask_relation,
            switch_mask_instance,
            query_count,
        })
    }

    pub(super) fn round_ordinal(&self) -> Result<u8, SemanticWhirError> {
        match self.switch_mask_relation.role {
            super::super::MaskGroupRole::WhirCodeSwitch { round_ordinal } => Ok(round_ordinal),
            _ => Err(SemanticWhirError::InvalidGeometry),
        }
    }
}

pub(super) fn semantic_whir_code_switch_input_pair(
    statement: &SemanticWhirCodeSwitchStatement,
) -> (
    &GeneralizedCommittedRelation,
    &SemanticGeneralizedRelationInstance,
) {
    (&statement.input_relation, &statement.input_instance)
}

pub(super) fn semantic_whir_code_switch_output_pair(
    statement: &SemanticWhirCodeSwitchStatement,
    prefix: &SemanticWhirCodeSwitchPrefix,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    validate_code_switch_prefix(statement, prefix)?;
    let query_positions = prefix
        .query_positions
        .as_deref()
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let combination_challenge = prefix
        .combination_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    code_switch_output_relation_and_instance(statement, query_positions, combination_challenge)
}

pub(super) fn semantic_whir_base_input_pair(
    statement: &SemanticWhirBaseStatement,
) -> (
    &GeneralizedCommittedRelation,
    &SemanticGeneralizedRelationInstance,
) {
    (&statement.input_relation, &statement.input_instance)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticWhirCodeSwitchPrefix {
    pub(super) query_positions: Option<Vec<usize>>,
    pub(super) combination_challenge: Option<ProofChallengeExtensionElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticWhirCodeSwitchBadTransition {
    QueryEscape {
        domain_size: usize,
        selected_decoding_error_count: usize,
        differing_row_count: usize,
        query_positions: Vec<usize>,
    },
    NonzeroCombinationPolynomialRoot {
        coefficients: Vec<ProofChallengeExtensionElement>,
        challenge: ProofChallengeExtensionElement,
    },
}

pub(super) fn semantic_whir_code_switch_kstate(
    statement: &SemanticWhirCodeSwitchStatement,
    prefix: Option<&SemanticWhirCodeSwitchPrefix>,
    witness: &SemanticGeneralizedRelationWitness,
) -> Result<bool, SemanticWhirError> {
    let Some(prefix) = prefix else {
        return semantic_generalized_relation_holds(
            &statement.input_relation,
            &statement.input_instance,
            witness,
        )
        .map_err(Into::into);
    };
    validate_code_switch_prefix(statement, prefix)?;
    let (Some(query_positions), Some(combination_challenge)) =
        (&prefix.query_positions, prefix.combination_challenge)
    else {
        return semantic_generalized_relation_holds(
            &statement.input_relation,
            &statement.input_instance,
            witness,
        )
        .map_err(Into::into);
    };
    let (relation, instance) = code_switch_output_relation_and_instance(
        statement,
        query_positions,
        combination_challenge,
    )?;
    semantic_generalized_relation_holds(&relation, &instance, witness).map_err(Into::into)
}

pub(super) fn semantic_whir_code_switch_errbr(
    statement: &SemanticWhirCodeSwitchStatement,
    extended_prefix: &SemanticWhirCodeSwitchPrefix,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<SemanticWhirExtraction, SemanticWhirError> {
    validate_code_switch_prefix(statement, extended_prefix)?;
    if extended_prefix.query_positions.is_none() || extended_prefix.combination_challenge.is_none()
    {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    let preceding_witness =
        reconstruct_code_switch_input_witness(statement, post_challenge_witness)?;
    let encoded_source = encode_canonical_interleaved_reed_solomon_with_operation_count(
        semantic_code_geometry(&statement.input_relation.source_code)?,
        &preceding_witness
            .source
            .coefficient_columns(&statement.input_relation.source_code)?,
    )?;
    let field_operation_count = encoded_source.field_operation_count();
    Ok(SemanticWhirExtraction {
        witness: Some(preceding_witness),
        field_operation_count,
    })
}

pub(super) fn semantic_whir_code_switch_bad_transition(
    statement: &SemanticWhirCodeSwitchStatement,
    extended_prefix: &SemanticWhirCodeSwitchPrefix,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<Option<SemanticWhirCodeSwitchBadTransition>, SemanticWhirError> {
    validate_code_switch_prefix(statement, extended_prefix)?;
    let (Some(query_positions), Some(combination_challenge)) = (
        &extended_prefix.query_positions,
        extended_prefix.combination_challenge,
    ) else {
        return Err(SemanticWhirError::MalformedPrefix);
    };
    if !semantic_whir_code_switch_kstate(statement, Some(extended_prefix), post_challenge_witness)?
    {
        return Ok(None);
    }
    let preceding_witness =
        reconstruct_code_switch_input_witness(statement, post_challenge_witness)?;
    if semantic_generalized_relation_holds(
        &statement.input_relation,
        &statement.input_instance,
        &preceding_witness,
    )? {
        return Ok(None);
    }

    let source_relation = &statement.input_relation.source_code;
    let canonical_rows = encode_canonical_interleaved_reed_solomon(
        semantic_code_geometry(source_relation)?,
        &preceding_witness
            .source
            .coefficient_columns(source_relation)?,
    )?;
    let source_geometry = semantic_code_geometry(source_relation)?;
    let differing_row_count = canonical_rows
        .iter()
        .zip(&statement.input_instance.source.received_rows)
        .filter(|(canonical, received)| canonical != received)
        .count();
    let sampled_rows_all_agree = query_positions.iter().all(|position| {
        canonical_rows[*position] == statement.input_instance.source.received_rows[*position]
    });
    if differing_row_count > source_geometry.selected_decoding_error_count()
        && sampled_rows_all_agree
    {
        return Ok(Some(SemanticWhirCodeSwitchBadTransition::QueryEscape {
            domain_size: source_geometry.block_length(),
            selected_decoding_error_count: source_geometry.selected_decoding_error_count(),
            differing_row_count,
            query_positions: query_positions.clone(),
        }));
    }

    let input_claim = statement
        .input_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    let mut coefficients = Vec::with_capacity(query_positions.len() + 1);
    coefficients
        .push(evaluate_claim(input_claim, &preceding_witness)?.subtract(input_claim.target));
    for &position in query_positions {
        coefficients.push(
            canonical_rows[position][0]
                .subtract(statement.input_instance.source.received_rows[position][0]),
        );
    }
    if coefficients.iter().all(|coefficient| coefficient.is_zero())
        || !evaluate_polynomial(&coefficients, combination_challenge).is_zero()
    {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    Ok(Some(
        SemanticWhirCodeSwitchBadTransition::NonzeroCombinationPolynomialRoot {
            coefficients,
            challenge: combination_challenge,
        },
    ))
}

fn validate_code_switch_prefix(
    statement: &SemanticWhirCodeSwitchStatement,
    prefix: &SemanticWhirCodeSwitchPrefix,
) -> Result<(), SemanticWhirError> {
    match (&prefix.query_positions, prefix.combination_challenge) {
        (None, None) => Ok(()),
        (Some(query_positions), Some(_))
            if query_positions.len() == statement.query_count
                && query_positions.iter().all(|position| {
                    u64::try_from(*position).is_ok_and(|position| {
                        position < statement.input_relation.source_code.block_length
                    })
                })
                && {
                    let mut sorted = query_positions.clone();
                    sorted.sort_unstable();
                    sorted.dedup();
                    sorted.len() == query_positions.len()
                } =>
        {
            Ok(())
        }
        _ => Err(SemanticWhirError::MalformedPrefix),
    }
}

fn code_switch_output_relation_and_instance(
    statement: &SemanticWhirCodeSwitchStatement,
    query_positions: &[usize],
    combination_challenge: ProofChallengeExtensionElement,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    let mut mask_codes = statement.input_relation.mask_codes.clone();
    mask_codes.push(statement.switch_mask_relation.clone());
    let source_message_element_count = statement
        .output_source_relation
        .message_length
        .checked_mul(statement.output_source_relation.interleaving_width)
        .ok_or(SemanticWhirError::ArithmeticOverflow)?;
    let source_hiding_element_count = statement
        .output_source_relation
        .hiding_randomness_length
        .checked_mul(statement.output_source_relation.interleaving_width)
        .ok_or(SemanticWhirError::ArithmeticOverflow)?;
    let mask_message_element_count =
        mask_codes
            .iter()
            .try_fold(0_u64, |count, mask| -> Result<_, SemanticWhirError> {
                count
                    .checked_add(
                        mask.code
                            .message_length
                            .checked_mul(mask.code.interleaving_width)
                            .ok_or(SemanticWhirError::ArithmeticOverflow)?,
                    )
                    .ok_or(SemanticWhirError::ArithmeticOverflow)
            })?;
    let relation = GeneralizedCommittedRelation {
        source_code: statement.output_source_relation.clone(),
        mask_codes,
        source_message_element_count,
        source_hiding_element_count,
        mask_message_element_count,
        covector_extension_element_count: source_message_element_count
            .checked_add(1)
            .and_then(|count| count.checked_add(mask_message_element_count))
            .ok_or(SemanticWhirError::ArithmeticOverflow)?,
        opening_evaluation_claim_count: 0,
        carried_reduction_claim_count: 1,
        claim_count: 1,
    };
    let input_claim = statement
        .input_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    let geometry = semantic_code_geometry(&statement.input_relation.source_code)?;
    let evaluation_points = canonical_reed_solomon_evaluation_points(geometry)?;
    let logical_message_length = usize::try_from(source_message_element_count)
        .map_err(|_| SemanticWhirError::InvalidGeometry)?;
    let switch_message_length = usize::try_from(statement.switch_mask_relation.code.message_length)
        .map_err(|_| SemanticWhirError::InvalidGeometry)?;
    let mut source_covector = input_claim.source_covector.clone();
    let mut switch_mask_covector =
        vec![ProofChallengeExtensionElement::ZERO; switch_message_length];
    let mut target = input_claim.target;
    let mut combination_coefficient = combination_challenge;
    for &position in query_positions {
        let point = *evaluation_points
            .get(position)
            .ok_or(SemanticWhirError::MalformedPrefix)?;
        for (destination, power) in source_covector
            .iter_mut()
            .zip(powers(point, logical_message_length))
        {
            *destination = destination.add(combination_coefficient.multiply(power));
        }
        let mut randomness_power = point.power(
            u64::try_from(logical_message_length)
                .map_err(|_| SemanticWhirError::ArithmeticOverflow)?,
        );
        for destination in &mut switch_mask_covector {
            *destination = destination.add(combination_coefficient.multiply(randomness_power));
            randomness_power = randomness_power.multiply(point);
        }
        target = target.add(
            combination_coefficient.multiply(
                statement
                    .input_instance
                    .source
                    .received_rows
                    .get(position)
                    .and_then(|row| row.first())
                    .copied()
                    .ok_or(SemanticWhirError::MalformedPrefix)?,
            ),
        );
        combination_coefficient = combination_coefficient.multiply(combination_challenge);
    }
    let mut mask_covectors = input_claim.mask_covectors.clone();
    mask_covectors.push(switch_mask_covector);
    let claim = SemanticGeneralizedLinearClaim {
        source_covector,
        mask_covectors,
        target,
    };
    let mut masks = statement.input_instance.masks.clone();
    masks.push(statement.switch_mask_instance.clone());
    let instance = SemanticGeneralizedRelationInstance {
        source: statement.output_source_instance.clone(),
        masks,
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![claim],
    };
    validate_generalized_relation_descriptor(&relation)?;
    Ok((relation, instance))
}

fn reconstruct_code_switch_input_witness(
    statement: &SemanticWhirCodeSwitchStatement,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<SemanticGeneralizedRelationWitness, SemanticWhirError> {
    if post_challenge_witness.masks.len()
        != statement
            .input_relation
            .mask_codes
            .len()
            .checked_add(1)
            .ok_or(SemanticWhirError::ArithmeticOverflow)?
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let logical_message = post_challenge_witness.source.flattened_messages();
    let switch_message = post_challenge_witness
        .masks
        .last()
        .ok_or(SemanticWhirError::InvalidGeometry)?
        .flattened_messages();
    if logical_message.len()
        != usize::try_from(statement.input_relation.source_message_element_count)
            .map_err(|_| SemanticWhirError::InvalidGeometry)?
        || switch_message.len()
            != usize::try_from(
                statement
                    .input_relation
                    .source_code
                    .hiding_randomness_length,
            )
            .map_err(|_| SemanticWhirError::InvalidGeometry)?
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    Ok(SemanticGeneralizedRelationWitness {
        source: SemanticCommittedCodeWitness {
            message_columns: vec![logical_message],
            hiding_randomness_columns: vec![switch_message],
        },
        masks: post_challenge_witness.masks[..statement.input_relation.mask_codes.len()].to_vec(),
    })
}

fn validate_prefix(
    statement: &SemanticWhirMaskedSumcheckStatement,
    prefix: &SemanticWhirMaskedSumcheckPrefix,
) -> Result<(), SemanticWhirError> {
    let challenge_count = prefix.round_challenges.len();
    let wire_count = prefix.round_wires.len();
    if (prefix.combining_challenge.is_none() && (wire_count != 0 || challenge_count != 0))
        || challenge_count > statement.folding_factor
        || wire_count < challenge_count
        || wire_count > challenge_count.saturating_add(1)
        || (challenge_count == statement.folding_factor && wire_count != challenge_count)
        || prefix
            .round_wires
            .iter()
            .any(|wire| wire.len() != statement.wire_coefficient_count())
    {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    Ok(())
}

fn verifier_transition(
    extended_prefix: &SemanticWhirMaskedSumcheckPrefix,
) -> Result<SemanticWhirVerifierTransition, SemanticWhirError> {
    if extended_prefix.combining_challenge.is_none() {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    match extended_prefix.round_challenges.len() {
        0 if extended_prefix.round_wires.is_empty() => {
            Ok(SemanticWhirVerifierTransition::CombiningChallenge)
        }
        completed_round_count
            if completed_round_count > 0
                && extended_prefix.round_wires.len() == completed_round_count =>
        {
            Ok(SemanticWhirVerifierTransition::SumcheckRound {
                round_ordinal: completed_round_count - 1,
            })
        }
        _ => Err(SemanticWhirError::MalformedPrefix),
    }
}

fn preceding_relation_and_instance(
    statement: &SemanticWhirMaskedSumcheckStatement,
    extended_prefix: &SemanticWhirMaskedSumcheckPrefix,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    let combining_challenge = extended_prefix
        .combining_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    if extended_prefix.round_challenges.is_empty() {
        return Ok((
            statement.input_relation.clone(),
            statement.input_instance.clone(),
        ));
    }
    relation_after_challenges(
        statement,
        extended_prefix,
        combining_challenge,
        extended_prefix.round_challenges.len() - 1,
    )
}

fn relation_after_challenges(
    statement: &SemanticWhirMaskedSumcheckStatement,
    prefix: &SemanticWhirMaskedSumcheckPrefix,
    combining_challenge: ProofChallengeExtensionElement,
    completed_round_count: usize,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    if completed_round_count > statement.folding_factor
        || prefix.round_challenges.len() < completed_round_count
    {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    let challenges = &prefix.round_challenges[..completed_round_count];
    let source_code = CommittedCodeRelation {
        interleaving_width: statement
            .input_relation
            .source_code
            .interleaving_width
            .checked_shr(
                u32::try_from(completed_round_count)
                    .map_err(|_| SemanticWhirError::ArithmeticOverflow)?,
            )
            .ok_or(SemanticWhirError::ArithmeticOverflow)?,
        ..statement.input_relation.source_code.clone()
    };
    let mut mask_codes = statement.input_relation.mask_codes.clone();
    mask_codes.push(statement.sumcheck_mask_relation.clone());
    let source_message_element_count = source_code
        .message_length
        .checked_mul(source_code.interleaving_width)
        .ok_or(SemanticWhirError::ArithmeticOverflow)?;
    let source_hiding_element_count = source_code
        .hiding_randomness_length
        .checked_mul(source_code.interleaving_width)
        .ok_or(SemanticWhirError::ArithmeticOverflow)?;
    let mask_message_element_count =
        mask_codes
            .iter()
            .try_fold(0_u64, |count, mask| -> Result<_, SemanticWhirError> {
                count
                    .checked_add(
                        mask.code
                            .message_length
                            .checked_mul(mask.code.interleaving_width)
                            .ok_or(SemanticWhirError::ArithmeticOverflow)?,
                    )
                    .ok_or(SemanticWhirError::ArithmeticOverflow)
            })?;
    let relation = GeneralizedCommittedRelation {
        source_code,
        mask_codes,
        source_message_element_count,
        source_hiding_element_count,
        mask_message_element_count,
        covector_extension_element_count: source_message_element_count
            .checked_add(1)
            .and_then(|count| count.checked_add(mask_message_element_count))
            .ok_or(SemanticWhirError::ArithmeticOverflow)?,
        opening_evaluation_claim_count: 0,
        carried_reduction_claim_count: 1,
        claim_count: 1,
    };
    let input_claim = statement
        .input_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    let source_covector = scale_vector(
        &fold_flattened_columns(
            &input_claim.source_covector,
            usize::try_from(statement.input_relation.source_code.interleaving_width)
                .map_err(|_| SemanticWhirError::InvalidGeometry)?,
            challenges,
        )?,
        combining_challenge,
    );
    let two_to_completed_round_count = power_of_two(completed_round_count);
    let carried_mask_scale = combining_challenge.multiply(
        two_to_completed_round_count
            .inverse()
            .map_err(|_| SemanticWhirError::InvalidGeometry)?,
    );
    let mut mask_covectors = input_claim
        .mask_covectors
        .iter()
        .map(|covector| scale_vector(covector, carried_mask_scale))
        .collect::<Vec<_>>();
    mask_covectors.push(sumcheck_mask_covector(
        statement,
        challenges,
        completed_round_count,
    )?);
    let claim = SemanticGeneralizedLinearClaim {
        source_covector,
        mask_covectors,
        target: replay_target(statement, prefix, completed_round_count)?,
    };
    let mut masks = statement.input_instance.masks.clone();
    masks.push(statement.sumcheck_mask_instance.clone());
    let instance = SemanticGeneralizedRelationInstance {
        source: SemanticCommittedCodeInstance {
            received_rows: fold_received_rows(
                &statement.input_instance.source.received_rows,
                challenges,
            )?,
        },
        masks,
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![claim],
    };
    validate_generalized_relation_descriptor(&relation)?;
    Ok((relation, instance))
}

fn replay_target(
    statement: &SemanticWhirMaskedSumcheckStatement,
    prefix: &SemanticWhirMaskedSumcheckPrefix,
    completed_round_count: usize,
) -> Result<ProofChallengeExtensionElement, SemanticWhirError> {
    let combining_challenge = prefix
        .combining_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let input_target = statement
        .input_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?
        .target;
    let mut target = combining_challenge
        .multiply(input_target)
        .add(prefix.mask_hypercube_sum);
    for round_ordinal in 0..completed_round_count {
        let polynomial = reconstruct_round_polynomial(
            target,
            prefix
                .round_wires
                .get(round_ordinal)
                .ok_or(SemanticWhirError::MalformedPrefix)?,
        )?;
        target = evaluate_polynomial(
            &polynomial,
            *prefix
                .round_challenges
                .get(round_ordinal)
                .ok_or(SemanticWhirError::MalformedPrefix)?,
        );
    }
    Ok(target)
}

fn reconstruct_round_polynomial(
    target: ProofChallengeExtensionElement,
    wire: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, SemanticWhirError> {
    let Some(&constant) = wire.first() else {
        return Err(SemanticWhirError::MalformedPrefix);
    };
    let high_degree_sum = wire[1..].iter().copied().fold(
        ProofChallengeExtensionElement::ZERO,
        ProofChallengeExtensionElement::add,
    );
    let linear = target
        .subtract(constant.add(constant))
        .subtract(high_degree_sum);
    let mut polynomial = Vec::with_capacity(wire.len() + 1);
    polynomial.push(constant);
    polynomial.push(linear);
    polynomial.extend_from_slice(&wire[1..]);
    Ok(polynomial)
}

fn sumcheck_mask_covector(
    statement: &SemanticWhirMaskedSumcheckStatement,
    challenges: &[ProofChallengeExtensionElement],
    completed_round_count: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, SemanticWhirError> {
    let remaining_round_count = statement
        .folding_factor
        .checked_sub(completed_round_count)
        .ok_or(SemanticWhirError::ArithmeticOverflow)?;
    let mut covector = Vec::with_capacity(
        statement
            .folding_factor
            .checked_mul(statement.sumcheck_mask_message_length)
            .ok_or(SemanticWhirError::ArithmeticOverflow)?,
    );
    for mask_ordinal in 0..statement.folding_factor {
        if mask_ordinal < completed_round_count {
            let scale = power_of_two(remaining_round_count);
            covector.extend(scale_vector(
                &powers(
                    *challenges
                        .get(mask_ordinal)
                        .ok_or(SemanticWhirError::MalformedPrefix)?,
                    statement.sumcheck_mask_message_length,
                ),
                scale,
            ));
        } else {
            let future_scale = power_of_two(
                remaining_round_count
                    .checked_sub(1)
                    .ok_or(SemanticWhirError::ArithmeticOverflow)?,
            );
            let mut endpoint_covector =
                vec![ProofChallengeExtensionElement::ONE; statement.sumcheck_mask_message_length];
            endpoint_covector[0] =
                ProofChallengeExtensionElement::ONE.add(ProofChallengeExtensionElement::ONE);
            covector.extend(scale_vector(&endpoint_covector, future_scale));
        }
    }
    Ok(covector)
}

fn expected_round_polynomial(
    statement: &SemanticWhirMaskedSumcheckStatement,
    preceding_relation: &GeneralizedCommittedRelation,
    preceding_instance: &SemanticGeneralizedRelationInstance,
    preceding_witness: &SemanticGeneralizedRelationWitness,
    round_ordinal: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, SemanticWhirError> {
    if round_ordinal >= statement.folding_factor {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    let claim = preceding_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    validate_claim_shape(preceding_relation, claim)?;
    let source_width = usize::try_from(preceding_relation.source_code.interleaving_width)
        .map_err(|_| SemanticWhirError::InvalidGeometry)?;
    if source_width < 2 || source_width % 2 != 0 {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let source_messages = &preceding_witness.source.message_columns;
    let source_covectors = split_flattened_columns(&claim.source_covector, source_width)?;
    if source_messages.len() != source_width {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let polynomial_length = statement.sumcheck_mask_message_length.max(3);
    let mut polynomial = vec![ProofChallengeExtensionElement::ZERO; polynomial_length];
    let half_width = source_width / 2;
    for column_ordinal in 0..half_width {
        let source_zero = source_messages
            .get(column_ordinal)
            .ok_or(SemanticWhirError::InvalidGeometry)?;
        let source_one = source_messages
            .get(half_width + column_ordinal)
            .ok_or(SemanticWhirError::InvalidGeometry)?;
        let covector_zero = source_covectors
            .get(column_ordinal)
            .ok_or(SemanticWhirError::InvalidGeometry)?;
        let covector_one = source_covectors
            .get(half_width + column_ordinal)
            .ok_or(SemanticWhirError::InvalidGeometry)?;
        if source_zero.len() != source_one.len()
            || source_zero.len() != covector_zero.len()
            || source_zero.len() != covector_one.len()
        {
            return Err(SemanticWhirError::InvalidGeometry);
        }
        for (((&source_at_zero, &source_at_one), &covector_at_zero), &covector_at_one) in
            source_zero
                .iter()
                .zip(source_one)
                .zip(covector_zero)
                .zip(covector_one)
        {
            let source_difference = source_at_one.subtract(source_at_zero);
            let covector_difference = covector_at_one.subtract(covector_at_zero);
            polynomial[0] = polynomial[0].add(source_at_zero.multiply(covector_at_zero));
            polynomial[1] = polynomial[1]
                .add(source_at_zero.multiply(covector_difference))
                .add(source_difference.multiply(covector_at_zero));
            polynomial[2] = polynomial[2].add(source_difference.multiply(covector_difference));
        }
    }

    let inverse_two = ProofChallengeExtensionElement::ONE
        .add(ProofChallengeExtensionElement::ONE)
        .inverse()
        .map_err(|_| SemanticWhirError::InvalidGeometry)?;
    let fresh_mask_group_ordinal = preceding_witness
        .masks
        .len()
        .checked_sub(1)
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    for (group_ordinal, (mask_witness, mask_covector)) in preceding_witness
        .masks
        .iter()
        .zip(&claim.mask_covectors)
        .enumerate()
    {
        if group_ordinal != fresh_mask_group_ordinal {
            polynomial[0] = polynomial[0].add(
                dot_product(mask_covector, &mask_witness.flattened_messages())?
                    .multiply(inverse_two),
            );
            continue;
        }
        let member_covectors = split_flattened_columns(mask_covector, statement.folding_factor)?;
        if mask_witness.message_columns.len() != statement.folding_factor
            || member_covectors.len() != statement.folding_factor
        {
            return Err(SemanticWhirError::InvalidGeometry);
        }
        for mask_ordinal in 0..statement.folding_factor {
            let message = &mask_witness.message_columns[mask_ordinal];
            let covector = &member_covectors[mask_ordinal];
            if mask_ordinal == round_ordinal {
                let remaining_round_count = statement
                    .folding_factor
                    .checked_sub(round_ordinal + 1)
                    .ok_or(SemanticWhirError::ArithmeticOverflow)?;
                let scale = power_of_two(remaining_round_count);
                for (coefficient, &mask_coefficient) in polynomial.iter_mut().zip(message) {
                    *coefficient = coefficient.add(scale.multiply(mask_coefficient));
                }
            } else {
                polynomial[0] =
                    polynomial[0].add(dot_product(covector, message)?.multiply(inverse_two));
            }
        }
    }
    Ok(polynomial)
}

fn reconstruct_binary_mca_components(
    relation: &CommittedCodeRelation,
    first_received_rows: &[Vec<ProofChallengeExtensionElement>],
    second_received_rows: &[Vec<ProofChallengeExtensionElement>],
    combined_instance: &SemanticCommittedCodeInstance,
    post_challenge_witness: &SemanticCommittedCodeWitness,
    challenge: ProofChallengeExtensionElement,
    combination: SemanticWhirMcaCombination,
) -> Result<SemanticWhirBinaryMcaReconstruction, SemanticWhirError> {
    let geometry = semantic_code_geometry(relation)?;
    let combined_received_rows = combine_binary_received_rows(
        first_received_rows,
        second_received_rows,
        challenge,
        combination,
    )?;
    if combined_received_rows != combined_instance.received_rows {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    let canonical_post_encoding = encode_canonical_interleaved_reed_solomon_with_operation_count(
        geometry,
        &post_challenge_witness.coefficient_columns(relation)?,
    )?;
    let canonical_post_rows = canonical_post_encoding.rows();
    let agreement_positions = combined_received_rows
        .iter()
        .zip(canonical_post_rows)
        .enumerate()
        .filter_map(|(position, (combined, canonical))| (combined == canonical).then_some(position))
        .collect::<Vec<_>>();
    let selected_decoding_error_count = geometry.selected_decoding_error_count();
    let minimum_agreement_count = geometry
        .block_length()
        .checked_sub(selected_decoding_error_count)
        .ok_or(SemanticWhirError::ArithmeticOverflow)?;
    if agreement_positions.len() < minimum_agreement_count
        || agreement_positions.len() < geometry.dimension()
    {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }

    let (first, first_field_operation_count) =
        match correct_canonical_interleaved_reed_solomon_erasures(
            geometry,
            first_received_rows,
            &agreement_positions,
        ) {
            Ok(decoded) => (
                semantic_witness_from_canonical_decoding(&decoded),
                decoded.field_operation_count(),
            ),
            Err(error) if is_semantic_erasure_correction_failure(error) => {
                return Ok(SemanticWhirBinaryMcaReconstruction::Certificate(
                    SemanticWhirMcaCertificate {
                        combination,
                        challenge,
                        agreement_positions,
                        target_domain_size: geometry.block_length(),
                        selected_decoding_error_count,
                        uncorrectable_component: SemanticWhirMcaUncorrectableComponent::First,
                    },
                ));
            }
            Err(error) => return Err(error.into()),
        };
    let (second, second_field_operation_count) =
        match correct_canonical_interleaved_reed_solomon_erasures(
            geometry,
            second_received_rows,
            &agreement_positions,
        ) {
            Ok(decoded) => (
                semantic_witness_from_canonical_decoding(&decoded),
                decoded.field_operation_count(),
            ),
            Err(error) if is_semantic_erasure_correction_failure(error) => {
                return Ok(SemanticWhirBinaryMcaReconstruction::Certificate(
                    SemanticWhirMcaCertificate {
                        combination,
                        challenge,
                        agreement_positions,
                        target_domain_size: geometry.block_length(),
                        selected_decoding_error_count,
                        uncorrectable_component: SemanticWhirMcaUncorrectableComponent::Second,
                    },
                ));
            }
            Err(error) => return Err(error.into()),
        };
    let expected_post_witness =
        combine_binary_committed_witnesses(&first, &second, challenge, combination)?;
    if expected_post_witness != *post_challenge_witness {
        // Both canonical combinations agree with the same received word on at
        // least the code dimension. Reed-Solomon injectivity makes them equal.
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    Ok(SemanticWhirBinaryMcaReconstruction::Witness {
        first,
        second,
        field_operation_count: canonical_post_encoding
            .field_operation_count()
            .checked_add(first_field_operation_count)
            .and_then(|count| count.checked_add(second_field_operation_count))
            .ok_or(SemanticWhirError::ArithmeticOverflow)?,
    })
}

fn split_binary_fold_rows(
    rows: &[Vec<ProofChallengeExtensionElement>],
) -> Result<
    (
        Vec<Vec<ProofChallengeExtensionElement>>,
        Vec<Vec<ProofChallengeExtensionElement>>,
    ),
    SemanticWhirError,
> {
    let width = rows
        .first()
        .map(Vec::len)
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    if width < 2 || width % 2 != 0 || rows.iter().any(|row| row.len() != width) {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let half_width = width / 2;
    Ok((
        rows.iter().map(|row| row[..half_width].to_vec()).collect(),
        rows.iter().map(|row| row[half_width..].to_vec()).collect(),
    ))
}

fn combine_binary_received_rows(
    first: &[Vec<ProofChallengeExtensionElement>],
    second: &[Vec<ProofChallengeExtensionElement>],
    challenge: ProofChallengeExtensionElement,
    combination: SemanticWhirMcaCombination,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, SemanticWhirError> {
    if first.len() != second.len()
        || first.is_empty()
        || first
            .iter()
            .zip(second)
            .any(|(first, second)| first.is_empty() || first.len() != second.len())
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let first_scale = match combination {
        SemanticWhirMcaCombination::AffineFold => {
            ProofChallengeExtensionElement::ONE.subtract(challenge)
        }
        SemanticWhirMcaCombination::AdditiveCombination => ProofChallengeExtensionElement::ONE,
    };
    Ok(first
        .iter()
        .zip(second)
        .map(|(first, second)| {
            first
                .iter()
                .zip(second)
                .map(|(&first, &second)| {
                    first_scale.multiply(first).add(challenge.multiply(second))
                })
                .collect()
        })
        .collect())
}

fn combine_binary_committed_witnesses(
    first: &SemanticCommittedCodeWitness,
    second: &SemanticCommittedCodeWitness,
    challenge: ProofChallengeExtensionElement,
    combination: SemanticWhirMcaCombination,
) -> Result<SemanticCommittedCodeWitness, SemanticWhirError> {
    Ok(SemanticCommittedCodeWitness {
        message_columns: combine_binary_columns(
            &first.message_columns,
            &second.message_columns,
            challenge,
            combination,
        )?,
        hiding_randomness_columns: combine_binary_columns(
            &first.hiding_randomness_columns,
            &second.hiding_randomness_columns,
            challenge,
            combination,
        )?,
    })
}

fn combine_binary_columns(
    first: &[Vec<ProofChallengeExtensionElement>],
    second: &[Vec<ProofChallengeExtensionElement>],
    challenge: ProofChallengeExtensionElement,
    combination: SemanticWhirMcaCombination,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, SemanticWhirError> {
    if first.len() != second.len()
        || first
            .iter()
            .zip(second)
            .any(|(first, second)| first.len() != second.len())
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let first_scale = match combination {
        SemanticWhirMcaCombination::AffineFold => {
            ProofChallengeExtensionElement::ONE.subtract(challenge)
        }
        SemanticWhirMcaCombination::AdditiveCombination => ProofChallengeExtensionElement::ONE,
    };
    Ok(first
        .iter()
        .zip(second)
        .map(|(first, second)| {
            first
                .iter()
                .zip(second)
                .map(|(&first, &second)| {
                    first_scale.multiply(first).add(challenge.multiply(second))
                })
                .collect()
        })
        .collect())
}

fn join_binary_fold_witnesses(
    first: SemanticCommittedCodeWitness,
    second: SemanticCommittedCodeWitness,
) -> Result<SemanticCommittedCodeWitness, SemanticWhirError> {
    if first.message_columns.len() != second.message_columns.len()
        || first.hiding_randomness_columns.len() != second.hiding_randomness_columns.len()
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let mut message_columns = first.message_columns;
    message_columns.extend(second.message_columns);
    let mut hiding_randomness_columns = first.hiding_randomness_columns;
    hiding_randomness_columns.extend(second.hiding_randomness_columns);
    Ok(SemanticCommittedCodeWitness {
        message_columns,
        hiding_randomness_columns,
    })
}

fn decode_unchanged_masks(
    relation: &GeneralizedCommittedRelation,
    instance: &SemanticGeneralizedRelationInstance,
    post_challenge_masks: &[SemanticCommittedCodeWitness],
) -> Result<Vec<SemanticCommittedCodeWitness>, SemanticWhirError> {
    if relation.mask_codes.len() != instance.masks.len()
        || relation.mask_codes.len() != post_challenge_masks.len()
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    relation
        .mask_codes
        .iter()
        .zip(&instance.masks)
        .zip(post_challenge_masks)
        .map(|((mask_relation, mask_instance), post_challenge_mask)| {
            let decoded = match decode_committed_witness(&mask_relation.code, mask_instance) {
                Ok((decoded, _)) => decoded,
                Err(SemanticRelationError::CodeCorrection(_)) => {
                    return Err(SemanticWhirError::InconsistentBadTransition);
                }
                Err(error) => return Err(error.into()),
            };
            if decoded != *post_challenge_mask {
                return Err(SemanticWhirError::InconsistentBadTransition);
            }
            Ok(decoded)
        })
        .collect()
}

fn semantic_witness_from_canonical_decoding(
    decoded: &crate::bgv::proof_suite::compact_public_key_static_catalog::canonical_reed_solomon::CanonicalReedSolomonDecodedWitness,
) -> SemanticCommittedCodeWitness {
    SemanticCommittedCodeWitness {
        message_columns: decoded.message_columns().to_vec(),
        hiding_randomness_columns: decoded.hiding_randomness_columns().to_vec(),
    }
}

fn is_semantic_erasure_correction_failure(error: CanonicalReedSolomonError) -> bool {
    matches!(
        error,
        CanonicalReedSolomonError::InconsistentLinearSystem
            | CanonicalReedSolomonError::NonCodewordQuotient
            | CanonicalReedSolomonError::OutsideDecodingRadius
    )
}

fn fold_generalized_witness_once(
    witness: &SemanticGeneralizedRelationWitness,
    challenge: ProofChallengeExtensionElement,
) -> Result<SemanticGeneralizedRelationWitness, SemanticWhirError> {
    Ok(SemanticGeneralizedRelationWitness {
        source: fold_committed_witness(&witness.source, &[challenge])?,
        masks: witness.masks.clone(),
    })
}

fn fold_committed_witness(
    witness: &SemanticCommittedCodeWitness,
    challenges: &[ProofChallengeExtensionElement],
) -> Result<SemanticCommittedCodeWitness, SemanticWhirError> {
    Ok(SemanticCommittedCodeWitness {
        message_columns: fold_columns(&witness.message_columns, challenges)?,
        hiding_randomness_columns: fold_columns(&witness.hiding_randomness_columns, challenges)?,
    })
}

fn fold_received_rows(
    rows: &[Vec<ProofChallengeExtensionElement>],
    challenges: &[ProofChallengeExtensionElement],
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, SemanticWhirError> {
    rows.iter()
        .map(|row| {
            fold_columns(
                &row.iter()
                    .copied()
                    .map(|value| vec![value])
                    .collect::<Vec<_>>(),
                challenges,
            )
            .map(|columns| {
                columns
                    .into_iter()
                    .map(|column| column[0])
                    .collect::<Vec<_>>()
            })
        })
        .collect()
}

fn fold_flattened_columns(
    flattened: &[ProofChallengeExtensionElement],
    width: usize,
    challenges: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, SemanticWhirError> {
    Ok(
        fold_columns(&split_flattened_columns(flattened, width)?, challenges)?
            .into_iter()
            .flatten()
            .collect(),
    )
}

fn fold_columns(
    columns: &[Vec<ProofChallengeExtensionElement>],
    challenges: &[ProofChallengeExtensionElement],
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, SemanticWhirError> {
    if columns.is_empty()
        || !columns.len().is_power_of_two()
        || columns
            .iter()
            .any(|column| column.len() != columns[0].len())
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let mut folded = columns.to_vec();
    for &challenge in challenges {
        if folded.len() < 2 || folded.len() % 2 != 0 {
            return Err(SemanticWhirError::InvalidGeometry);
        }
        let half_width = folded.len() / 2;
        let one_minus_challenge = ProofChallengeExtensionElement::ONE.subtract(challenge);
        folded = (0..half_width)
            .map(|column_ordinal| {
                folded[column_ordinal]
                    .iter()
                    .zip(&folded[half_width + column_ordinal])
                    .map(|(&zero, &one)| {
                        one_minus_challenge
                            .multiply(zero)
                            .add(challenge.multiply(one))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
    }
    Ok(folded)
}

fn split_flattened_columns(
    flattened: &[ProofChallengeExtensionElement],
    width: usize,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, SemanticWhirError> {
    if width == 0 || flattened.is_empty() || flattened.len() % width != 0 {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let column_length = flattened.len() / width;
    Ok(flattened
        .chunks_exact(column_length)
        .map(<[ProofChallengeExtensionElement]>::to_vec)
        .collect())
}

fn decode_generalized_relation_witness(
    relation: &GeneralizedCommittedRelation,
    instance: &SemanticGeneralizedRelationInstance,
) -> Result<SemanticGeneralizedRelationExtraction, SemanticRelationError> {
    validate_generalized_relation_descriptor(relation)?;
    if instance.masks.len() != relation.mask_codes.len()
        || instance.opening_claims.len()
            != usize::try_from(relation.opening_evaluation_claim_count)
                .map_err(|_| SemanticRelationError::InvalidGeometry)?
        || instance.carried_reduction_claims.len()
            != usize::try_from(relation.carried_reduction_claim_count)
                .map_err(|_| SemanticRelationError::InvalidGeometry)?
    {
        return Err(SemanticRelationError::MalformedInstance);
    }
    let (source, mut field_operation_count) =
        decode_committed_witness(&relation.source_code, &instance.source)?;
    let mut masks = Vec::with_capacity(relation.mask_codes.len());
    for (mask_relation, mask_instance) in relation.mask_codes.iter().zip(&instance.masks) {
        let (mask, operation_count) = decode_committed_witness(&mask_relation.code, mask_instance)?;
        field_operation_count = field_operation_count
            .checked_add(operation_count)
            .ok_or(SemanticRelationError::ArithmeticOverflow)?;
        masks.push(mask);
    }
    Ok(SemanticGeneralizedRelationExtraction {
        witness: SemanticGeneralizedRelationWitness { source, masks },
        field_operation_count,
    })
}

fn decode_committed_witness(
    relation: &CommittedCodeRelation,
    instance: &SemanticCommittedCodeInstance,
) -> Result<(SemanticCommittedCodeWitness, u128), SemanticRelationError> {
    extract_semantic_committed_code_witness(relation, instance)
}

fn validate_committed_instance_shape(
    relation: &CommittedCodeRelation,
    instance: &SemanticCommittedCodeInstance,
) -> Result<(), SemanticWhirError> {
    let block_length =
        usize::try_from(relation.block_length).map_err(|_| SemanticWhirError::InvalidGeometry)?;
    let width = usize::try_from(relation.interleaving_width)
        .map_err(|_| SemanticWhirError::InvalidGeometry)?;
    if instance.received_rows.len() != block_length
        || instance.received_rows.iter().any(|row| row.len() != width)
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    Ok(())
}

fn validate_claim_shape(
    relation: &GeneralizedCommittedRelation,
    claim: &SemanticGeneralizedLinearClaim,
) -> Result<(), SemanticWhirError> {
    if claim.source_covector.len()
        != usize::try_from(relation.source_message_element_count)
            .map_err(|_| SemanticWhirError::InvalidGeometry)?
        || claim.mask_covectors.len() != relation.mask_codes.len()
        || claim
            .mask_covectors
            .iter()
            .zip(&relation.mask_codes)
            .any(|(covector, mask)| {
                mask.code
                    .message_length
                    .checked_mul(mask.code.interleaving_width)
                    .and_then(|count| usize::try_from(count).ok())
                    != Some(covector.len())
            })
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    Ok(())
}

fn evaluate_claim(
    claim: &SemanticGeneralizedLinearClaim,
    witness: &SemanticGeneralizedRelationWitness,
) -> Result<ProofChallengeExtensionElement, SemanticWhirError> {
    let mut value = dot_product(&claim.source_covector, &witness.source.flattened_messages())?;
    if claim.mask_covectors.len() != witness.masks.len() {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    for (covector, mask) in claim.mask_covectors.iter().zip(&witness.masks) {
        value = value.add(dot_product(covector, &mask.flattened_messages())?);
    }
    Ok(value)
}

fn sumcheck_mask_hypercube_sum(
    witness: &SemanticCommittedCodeWitness,
    folding_factor: usize,
) -> Result<ProofChallengeExtensionElement, SemanticWhirError> {
    if witness.message_columns.len() != folding_factor {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let repetitions = power_of_two(
        folding_factor
            .checked_sub(1)
            .ok_or(SemanticWhirError::InvalidGeometry)?,
    );
    witness
        .message_columns
        .iter()
        .try_fold(ProofChallengeExtensionElement::ZERO, |sum, message| {
            if message.is_empty() {
                return Err(SemanticWhirError::InvalidGeometry);
            }
            let endpoint_sum = message[0].add(message.iter().copied().fold(
                ProofChallengeExtensionElement::ZERO,
                ProofChallengeExtensionElement::add,
            ));
            Ok(sum.add(repetitions.multiply(endpoint_sum)))
        })
}

fn powers(
    value: ProofChallengeExtensionElement,
    count: usize,
) -> Vec<ProofChallengeExtensionElement> {
    let mut power = ProofChallengeExtensionElement::ONE;
    (0..count)
        .map(|_| {
            let current = power;
            power = power.multiply(value);
            current
        })
        .collect()
}

fn power_of_two(exponent: usize) -> ProofChallengeExtensionElement {
    (0..exponent).fold(ProofChallengeExtensionElement::ONE, |power, _| {
        power.add(power)
    })
}

fn scale_vector(
    values: &[ProofChallengeExtensionElement],
    scale: ProofChallengeExtensionElement,
) -> Vec<ProofChallengeExtensionElement> {
    values.iter().map(|value| scale.multiply(*value)).collect()
}

fn subtract_polynomials(
    left: &[ProofChallengeExtensionElement],
    right: &[ProofChallengeExtensionElement],
) -> Vec<ProofChallengeExtensionElement> {
    let length = left.len().max(right.len());
    (0..length)
        .map(|ordinal| {
            left.get(ordinal)
                .copied()
                .unwrap_or(ProofChallengeExtensionElement::ZERO)
                .subtract(
                    right
                        .get(ordinal)
                        .copied()
                        .unwrap_or(ProofChallengeExtensionElement::ZERO),
                )
        })
        .collect()
}

fn evaluate_polynomial(
    coefficients: &[ProofChallengeExtensionElement],
    point: ProofChallengeExtensionElement,
) -> ProofChallengeExtensionElement {
    coefficients.iter().rev().copied().fold(
        ProofChallengeExtensionElement::ZERO,
        |value, coefficient| value.multiply(point).add(coefficient),
    )
}

#[cfg(test)]
mod tests;
