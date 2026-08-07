//! Semantic opening-claim batching at the start of one WHIR epoch.

use super::*;

#[derive(Clone, Debug)]
pub(in super::super) struct SemanticWhirOpeningBatchingStatement {
    pub(super) input_relation: GeneralizedCommittedRelation,
    pub(super) input_instance: SemanticGeneralizedRelationInstance,
}

impl SemanticWhirOpeningBatchingStatement {
    pub(in super::super) fn new(
        input_relation: GeneralizedCommittedRelation,
        input_instance: SemanticGeneralizedRelationInstance,
    ) -> Result<Self, SemanticWhirError> {
        validate_generalized_relation_descriptor(&input_relation)?;
        if input_relation.claim_count == 0
            || input_instance.opening_claims.len()
                != usize::try_from(input_relation.opening_evaluation_claim_count)
                    .map_err(|_| SemanticWhirError::InvalidGeometry)?
            || input_instance.carried_reduction_claims.len()
                != usize::try_from(input_relation.carried_reduction_claim_count)
                    .map_err(|_| SemanticWhirError::InvalidGeometry)?
            || input_instance.masks.len() != input_relation.mask_codes.len()
        {
            return Err(SemanticWhirError::InvalidGeometry);
        }
        validate_committed_instance_shape(&input_relation.source_code, &input_instance.source)?;
        for (mask_relation, mask_instance) in
            input_relation.mask_codes.iter().zip(&input_instance.masks)
        {
            validate_committed_instance_shape(&mask_relation.code, mask_instance)?;
        }
        for claim in input_instance
            .opening_claims
            .iter()
            .chain(&input_instance.carried_reduction_claims)
        {
            validate_claim_shape(&input_relation, claim)?;
        }
        Ok(Self {
            input_relation,
            input_instance,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirOpeningBatchingPrefix {
    pub(in super::super) batching_challenge: Option<ProofChallengeExtensionElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirOpeningBatchingBadTransition {
    pub(super) coefficients: Vec<ProofChallengeExtensionElement>,
    pub(super) challenge: ProofChallengeExtensionElement,
}

pub(in super::super) fn semantic_whir_opening_batching_kstate(
    statement: &SemanticWhirOpeningBatchingStatement,
    prefix: Option<&SemanticWhirOpeningBatchingPrefix>,
    witness: &SemanticGeneralizedRelationWitness,
) -> Result<bool, SemanticWhirError> {
    let Some(challenge) = prefix.and_then(|prefix| prefix.batching_challenge) else {
        return semantic_generalized_relation_holds(
            &statement.input_relation,
            &statement.input_instance,
            witness,
        )
        .map_err(Into::into);
    };
    let (output_relation, output_instance) = batched_relation_and_instance(statement, challenge)?;
    semantic_generalized_relation_holds(&output_relation, &output_instance, witness)
        .map_err(Into::into)
}

/// The witness does not change when public claims are alpha-batched.
pub(in super::super) fn semantic_whir_opening_batching_errbr(
    _statement: &SemanticWhirOpeningBatchingStatement,
    extended_prefix: &SemanticWhirOpeningBatchingPrefix,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<SemanticWhirExtraction, SemanticWhirError> {
    if extended_prefix.batching_challenge.is_none() {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    Ok(SemanticWhirExtraction {
        witness: Some(post_challenge_witness.clone()),
        field_operation_count: 0,
    })
}

pub(in super::super) fn semantic_whir_opening_batching_bad_transition(
    statement: &SemanticWhirOpeningBatchingStatement,
    extended_prefix: &SemanticWhirOpeningBatchingPrefix,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<Option<SemanticWhirOpeningBatchingBadTransition>, SemanticWhirError> {
    let challenge = extended_prefix
        .batching_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    if !semantic_whir_opening_batching_kstate(
        statement,
        Some(extended_prefix),
        post_challenge_witness,
    )? {
        return Ok(None);
    }
    if semantic_generalized_relation_holds(
        &statement.input_relation,
        &statement.input_instance,
        post_challenge_witness,
    )? {
        return Ok(None);
    }
    let coefficients = ordered_claims(statement)
        .map(|claim| {
            evaluate_claim(claim, post_challenge_witness)
                .map(|left_hand_side| left_hand_side.subtract(claim.target))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if coefficients.iter().all(|coefficient| coefficient.is_zero())
        || !evaluate_polynomial(&coefficients, challenge).is_zero()
    {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    Ok(Some(SemanticWhirOpeningBatchingBadTransition {
        coefficients,
        challenge,
    }))
}

pub(super) fn batched_relation_and_instance(
    statement: &SemanticWhirOpeningBatchingStatement,
    challenge: ProofChallengeExtensionElement,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    let source_element_count =
        usize::try_from(statement.input_relation.source_message_element_count)
            .map_err(|_| SemanticWhirError::InvalidGeometry)?;
    let mut source_covector = vec![ProofChallengeExtensionElement::ZERO; source_element_count];
    let mut mask_covectors = statement
        .input_relation
        .mask_codes
        .iter()
        .map(|mask| {
            mask.code
                .message_length
                .checked_mul(mask.code.interleaving_width)
                .and_then(|count| usize::try_from(count).ok())
                .map(|count| vec![ProofChallengeExtensionElement::ZERO; count])
                .ok_or(SemanticWhirError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut target = ProofChallengeExtensionElement::ZERO;
    let mut coefficient = ProofChallengeExtensionElement::ONE;
    for claim in ordered_claims(statement) {
        for (combined, claim_coefficient) in source_covector.iter_mut().zip(&claim.source_covector)
        {
            *combined = combined.add(coefficient.multiply(*claim_coefficient));
        }
        for (combined_mask, claim_mask) in mask_covectors.iter_mut().zip(&claim.mask_covectors) {
            for (combined, claim_coefficient) in combined_mask.iter_mut().zip(claim_mask) {
                *combined = combined.add(coefficient.multiply(*claim_coefficient));
            }
        }
        target = target.add(coefficient.multiply(claim.target));
        coefficient = coefficient.multiply(challenge);
    }
    let output_relation = GeneralizedCommittedRelation {
        opening_evaluation_claim_count: 0,
        carried_reduction_claim_count: 1,
        claim_count: 1,
        ..statement.input_relation.clone()
    };
    let output_instance = SemanticGeneralizedRelationInstance {
        source: statement.input_instance.source.clone(),
        masks: statement.input_instance.masks.clone(),
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![SemanticGeneralizedLinearClaim {
            source_covector,
            mask_covectors,
            target,
        }],
    };
    validate_generalized_relation_descriptor(&output_relation)?;
    Ok((output_relation, output_instance))
}

fn ordered_claims(
    statement: &SemanticWhirOpeningBatchingStatement,
) -> impl Iterator<Item = &SemanticGeneralizedLinearClaim> {
    statement
        .input_instance
        .opening_claims
        .iter()
        .chain(&statement.input_instance.carried_reduction_claims)
}

#[cfg(test)]
mod tests;
