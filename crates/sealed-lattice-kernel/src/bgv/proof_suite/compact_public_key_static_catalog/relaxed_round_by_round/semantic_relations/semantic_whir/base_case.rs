//! Executable Construction 7.2 knowledge states and backward extractors.
//!
//! The combination transition uses the largest agreement set and the selected
//! deterministic Reed-Solomon erasure corrector on both committed sides. The
//! terminal transition re-encodes the revealed coefficients and derives query
//! escape only from verifier-consumed source and mask rows.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirBaseStatement {
    pub(super) input_relation: GeneralizedCommittedRelation,
    pub(super) input_instance: SemanticGeneralizedRelationInstance,
    source_query_count: usize,
    mask_query_count: usize,
}

impl SemanticWhirBaseStatement {
    pub(in super::super) fn new(
        input_relation: GeneralizedCommittedRelation,
        input_instance: SemanticGeneralizedRelationInstance,
        source_query_count: usize,
        mask_query_count: usize,
    ) -> Result<Self, SemanticWhirError> {
        validate_generalized_relation_descriptor(&input_relation)?;
        if input_relation.source_code.interleaving_width != 1
            || input_relation.opening_evaluation_claim_count != 0
            || input_relation.carried_reduction_claim_count != 1
            || input_relation.claim_count != 1
            || input_instance.opening_claims.len() != 0
            || input_instance.carried_reduction_claims.len() != 1
            || input_instance.masks.len() != input_relation.mask_codes.len()
            || source_query_count == 0
            || mask_query_count == 0
            || usize::try_from(input_relation.source_code.block_length)
                .ok()
                .is_none_or(|block_length| source_query_count > block_length)
            || input_relation.mask_codes.iter().any(|mask| {
                usize::try_from(mask.code.block_length)
                    .ok()
                    .is_none_or(|block_length| mask_query_count > block_length)
            })
        {
            return Err(SemanticWhirError::InvalidGeometry);
        }
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
            source_query_count,
            mask_query_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirBaseFreshMessage {
    pub(in super::super) source: SemanticCommittedCodeInstance,
    pub(in super::super) masks: Vec<SemanticCommittedCodeInstance>,
    pub(in super::super) masked_claim: ProofChallengeExtensionElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirBaseQueryChallenges {
    pub(in super::super) source_positions: Vec<usize>,
    pub(in super::super) mask_group_positions: Vec<Vec<usize>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirBasePrefix {
    pub(in super::super) fresh_message: Option<SemanticWhirBaseFreshMessage>,
    pub(in super::super) combination_challenge: Option<ProofChallengeExtensionElement>,
    pub(in super::super) revealed_witness: Option<SemanticGeneralizedRelationWitness>,
    pub(in super::super) query_challenges: Option<SemanticWhirBaseQueryChallenges>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirBasePreCombinationWitness {
    pub(in super::super) input: SemanticGeneralizedRelationWitness,
    pub(in super::super) fresh: SemanticGeneralizedRelationWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) enum SemanticWhirBaseKnowledgeWitness {
    Input(SemanticGeneralizedRelationWitness),
    PreCombination(SemanticWhirBasePreCombinationWitness),
    Blinded(SemanticGeneralizedRelationWitness),
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum SemanticWhirBaseOracleRole {
    Source,
    MaskGroup { group_ordinal: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) enum SemanticWhirBaseCombinationBadTransition {
    MutualCorrelatedAgreement {
        role: SemanticWhirBaseOracleRole,
        certificate: SemanticWhirMcaCertificate,
    },
    NonzeroPolynomialRoot {
        coefficients: Vec<ProofChallengeExtensionElement>,
        challenge: ProofChallengeExtensionElement,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirBaseQueryEscape {
    pub(in super::super) role: SemanticWhirBaseOracleRole,
    pub(in super::super) domain_size: usize,
    pub(in super::super) selected_decoding_error_count: usize,
    pub(in super::super) differing_row_count: usize,
    pub(in super::super) query_positions: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticWhirBaseCombinationExtraction {
    pub(in super::super) witness: Option<SemanticWhirBasePreCombinationWitness>,
    pub(in super::super) field_operation_count: u128,
}

/// Exact prefix-wise Construction 7.2 knowledge-state predicate.
pub(in super::super) fn semantic_whir_base_kstate(
    statement: &SemanticWhirBaseStatement,
    prefix: Option<&SemanticWhirBasePrefix>,
    witness: &SemanticWhirBaseKnowledgeWitness,
) -> Result<bool, SemanticWhirError> {
    let Some(prefix) = prefix else {
        return match witness {
            SemanticWhirBaseKnowledgeWitness::Input(input)
            | SemanticWhirBaseKnowledgeWitness::PreCombination(
                SemanticWhirBasePreCombinationWitness { input, .. },
            ) => semantic_generalized_relation_holds(
                &statement.input_relation,
                &statement.input_instance,
                input,
            )
            .map_err(Into::into),
            SemanticWhirBaseKnowledgeWitness::Blinded(_)
            | SemanticWhirBaseKnowledgeWitness::Terminal => Ok(false),
        };
    };
    validate_base_prefix(statement, prefix)?;
    let Some(fresh_message) = &prefix.fresh_message else {
        return semantic_whir_base_kstate(statement, None, witness);
    };
    let Some(combination_challenge) = prefix.combination_challenge else {
        let SemanticWhirBaseKnowledgeWitness::PreCombination(pre_combination) = witness else {
            return Ok(false);
        };
        return pre_combination_relation_holds(statement, fresh_message, pre_combination);
    };
    let Some(query_challenges) = &prefix.query_challenges else {
        let SemanticWhirBaseKnowledgeWitness::Blinded(blinded) = witness else {
            return Ok(false);
        };
        if prefix
            .revealed_witness
            .as_ref()
            .is_some_and(|revealed| revealed != blinded)
        {
            return Ok(false);
        }
        let (relation, instance) =
            combined_relation_and_instance(statement, fresh_message, combination_challenge)?;
        return semantic_generalized_relation_holds(&relation, &instance, blinded)
            .map_err(Into::into);
    };
    if !matches!(witness, SemanticWhirBaseKnowledgeWitness::Terminal) {
        return Ok(false);
    }
    verifier_accepts_full_base_transcript(
        statement,
        fresh_message,
        combination_challenge,
        prefix
            .revealed_witness
            .as_ref()
            .ok_or(SemanticWhirError::MalformedPrefix)?,
        query_challenges,
    )
}

/// Backward extractor for the combination-randomness move.
pub(in super::super) fn semantic_whir_base_combination_errbr(
    statement: &SemanticWhirBaseStatement,
    extended_prefix: &SemanticWhirBasePrefix,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<SemanticWhirBaseCombinationExtraction, SemanticWhirError> {
    validate_combination_transition_prefix(statement, extended_prefix)?;
    match reconstruct_pre_combination_witness(statement, extended_prefix, post_challenge_witness)? {
        BaseReconstruction::Witness {
            witness,
            field_operation_count,
        } => Ok(SemanticWhirBaseCombinationExtraction {
            witness: Some(witness),
            field_operation_count,
        }),
        BaseReconstruction::MutualCorrelatedAgreement { .. } => {
            Ok(SemanticWhirBaseCombinationExtraction {
                witness: None,
                field_operation_count: 0,
            })
        }
    }
}

pub(in super::super) fn semantic_whir_base_combination_bad_transition(
    statement: &SemanticWhirBaseStatement,
    extended_prefix: &SemanticWhirBasePrefix,
    post_challenge_witness: &SemanticGeneralizedRelationWitness,
) -> Result<Option<SemanticWhirBaseCombinationBadTransition>, SemanticWhirError> {
    validate_combination_transition_prefix(statement, extended_prefix)?;
    if !semantic_whir_base_kstate(
        statement,
        Some(extended_prefix),
        &SemanticWhirBaseKnowledgeWitness::Blinded(post_challenge_witness.clone()),
    )? {
        return Ok(None);
    }
    let reconstruction =
        reconstruct_pre_combination_witness(statement, extended_prefix, post_challenge_witness)?;
    let BaseReconstruction::Witness { witness, .. } = reconstruction else {
        let BaseReconstruction::MutualCorrelatedAgreement { role, certificate } = reconstruction
        else {
            unreachable!("the reconstruction variants are exhaustive")
        };
        return Ok(Some(
            SemanticWhirBaseCombinationBadTransition::MutualCorrelatedAgreement {
                role,
                certificate,
            },
        ));
    };
    let fresh_message = extended_prefix
        .fresh_message
        .as_ref()
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    if pre_combination_relation_holds(statement, fresh_message, &witness)? {
        return Ok(None);
    }
    let combination_challenge = extended_prefix
        .combination_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    if combine_generalized_witnesses(&witness.fresh, &witness.input, combination_challenge)?
        != *post_challenge_witness
    {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    let input_claim = statement
        .input_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    let input_left_hand_side = evaluate_claim(input_claim, &witness.input)?;
    let fresh_left_hand_side = evaluate_claim(input_claim, &witness.fresh)?;
    let coefficients = vec![
        fresh_left_hand_side.subtract(fresh_message.masked_claim),
        input_left_hand_side.subtract(input_claim.target),
    ];
    if coefficients.iter().all(|coefficient| coefficient.is_zero())
        || !evaluate_polynomial(&coefficients, combination_challenge).is_zero()
    {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    Ok(Some(
        SemanticWhirBaseCombinationBadTransition::NonzeroPolynomialRoot {
            coefficients,
            challenge: combination_challenge,
        },
    ))
}

/// Backward extractor for the terminal spot-check randomness.
pub(in super::super) fn semantic_whir_base_final_errbr(
    statement: &SemanticWhirBaseStatement,
    full_prefix: &SemanticWhirBasePrefix,
) -> Result<SemanticWhirExtraction, SemanticWhirError> {
    validate_final_transition_prefix(statement, full_prefix)?;
    let revealed_witness = full_prefix
        .revealed_witness
        .as_ref()
        .ok_or(SemanticWhirError::MalformedPrefix)?
        .clone();
    let (_, field_operation_count) =
        encode_generalized_witness(&statement.input_relation, &revealed_witness)?;
    Ok(SemanticWhirExtraction {
        witness: Some(revealed_witness),
        field_operation_count,
    })
}

pub(in super::super) fn semantic_whir_base_final_bad_transition(
    statement: &SemanticWhirBaseStatement,
    full_prefix: &SemanticWhirBasePrefix,
) -> Result<Option<Vec<SemanticWhirBaseQueryEscape>>, SemanticWhirError> {
    validate_final_transition_prefix(statement, full_prefix)?;
    if !semantic_whir_base_kstate(
        statement,
        Some(full_prefix),
        &SemanticWhirBaseKnowledgeWitness::Terminal,
    )? {
        return Ok(None);
    }
    let revealed_witness = full_prefix
        .revealed_witness
        .as_ref()
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let mut pre_query_prefix = full_prefix.clone();
    pre_query_prefix.query_challenges = None;
    if semantic_whir_base_kstate(
        statement,
        Some(&pre_query_prefix),
        &SemanticWhirBaseKnowledgeWitness::Blinded(revealed_witness.clone()),
    )? {
        return Ok(None);
    }
    let fresh_message = full_prefix
        .fresh_message
        .as_ref()
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let combination_challenge = full_prefix
        .combination_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let (_, combined_instance) =
        combined_relation_and_instance(statement, fresh_message, combination_challenge)?;
    let (canonical_instance, _) =
        encode_generalized_witness(&statement.input_relation, revealed_witness)?;
    let query_challenges = full_prefix
        .query_challenges
        .as_ref()
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let mut escapes = Vec::new();
    append_query_escape(
        &mut escapes,
        SemanticWhirBaseOracleRole::Source,
        &statement.input_relation.source_code,
        &combined_instance.source,
        &canonical_instance.source,
        &query_challenges.source_positions,
    )?;
    for (group_ordinal, (((mask_relation, combined), canonical), query_positions)) in statement
        .input_relation
        .mask_codes
        .iter()
        .zip(&combined_instance.masks)
        .zip(&canonical_instance.masks)
        .zip(&query_challenges.mask_group_positions)
        .enumerate()
    {
        append_query_escape(
            &mut escapes,
            SemanticWhirBaseOracleRole::MaskGroup { group_ordinal },
            &mask_relation.code,
            combined,
            canonical,
            query_positions,
        )?;
    }
    if escapes.is_empty() {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    Ok(Some(escapes))
}

enum BaseReconstruction {
    Witness {
        witness: SemanticWhirBasePreCombinationWitness,
        field_operation_count: u128,
    },
    MutualCorrelatedAgreement {
        role: SemanticWhirBaseOracleRole,
        certificate: SemanticWhirMcaCertificate,
    },
}

fn reconstruct_pre_combination_witness(
    statement: &SemanticWhirBaseStatement,
    prefix: &SemanticWhirBasePrefix,
    blinded_witness: &SemanticGeneralizedRelationWitness,
) -> Result<BaseReconstruction, SemanticWhirError> {
    let fresh_message = prefix
        .fresh_message
        .as_ref()
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let combination_challenge = prefix
        .combination_challenge
        .ok_or(SemanticWhirError::MalformedPrefix)?;
    let (_, mut field_operation_count) =
        encode_generalized_witness(&statement.input_relation, blinded_witness)?;
    let source_reconstruction = correct_oracle_pair(
        &statement.input_relation.source_code,
        &statement.input_instance.source,
        &fresh_message.source,
        &blinded_witness.source,
        combination_challenge,
    )?;
    let (input_source, fresh_source, operation_count) = match source_reconstruction {
        SemanticWhirBinaryMcaReconstruction::Witness {
            first: fresh,
            second: input,
            field_operation_count,
        } => (input, fresh, field_operation_count),
        SemanticWhirBinaryMcaReconstruction::Certificate(certificate) => {
            return Ok(BaseReconstruction::MutualCorrelatedAgreement {
                role: SemanticWhirBaseOracleRole::Source,
                certificate,
            });
        }
    };
    field_operation_count = field_operation_count
        .checked_add(operation_count)
        .ok_or(SemanticWhirError::ArithmeticOverflow)?;
    let mut input_masks = Vec::with_capacity(statement.input_relation.mask_codes.len());
    let mut fresh_masks = Vec::with_capacity(statement.input_relation.mask_codes.len());
    if blinded_witness.masks.len() != statement.input_relation.mask_codes.len() {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    for group_ordinal in 0..statement.input_relation.mask_codes.len() {
        let mask_relation = &statement.input_relation.mask_codes[group_ordinal];
        let input_instance = &statement.input_instance.masks[group_ordinal];
        let fresh_instance = &fresh_message.masks[group_ordinal];
        let blinded_mask_witness = &blinded_witness.masks[group_ordinal];
        let mask_reconstruction = correct_oracle_pair(
            &mask_relation.code,
            input_instance,
            fresh_instance,
            blinded_mask_witness,
            combination_challenge,
        )?;
        let (input_mask, fresh_mask, operation_count) = match mask_reconstruction {
            SemanticWhirBinaryMcaReconstruction::Witness {
                first: fresh,
                second: input,
                field_operation_count,
            } => (input, fresh, field_operation_count),
            SemanticWhirBinaryMcaReconstruction::Certificate(certificate) => {
                return Ok(BaseReconstruction::MutualCorrelatedAgreement {
                    role: SemanticWhirBaseOracleRole::MaskGroup { group_ordinal },
                    certificate,
                });
            }
        };
        field_operation_count = field_operation_count
            .checked_add(operation_count)
            .ok_or(SemanticWhirError::ArithmeticOverflow)?;
        input_masks.push(input_mask);
        fresh_masks.push(fresh_mask);
    }
    Ok(BaseReconstruction::Witness {
        witness: SemanticWhirBasePreCombinationWitness {
            input: SemanticGeneralizedRelationWitness {
                source: input_source,
                masks: input_masks,
            },
            fresh: SemanticGeneralizedRelationWitness {
                source: fresh_source,
                masks: fresh_masks,
            },
        },
        field_operation_count,
    })
}

fn correct_oracle_pair(
    relation: &CommittedCodeRelation,
    input: &SemanticCommittedCodeInstance,
    fresh: &SemanticCommittedCodeInstance,
    blinded_witness: &SemanticCommittedCodeWitness,
    combination_challenge: ProofChallengeExtensionElement,
) -> Result<SemanticWhirBinaryMcaReconstruction, SemanticWhirError> {
    let combined = combine_committed_instances(fresh, input, combination_challenge)?;
    reconstruct_binary_mca_components(
        relation,
        &fresh.received_rows,
        &input.received_rows,
        &combined,
        blinded_witness,
        combination_challenge,
        SemanticWhirMcaCombination::AdditiveCombination,
    )
}

fn pre_combination_relation_holds(
    statement: &SemanticWhirBaseStatement,
    fresh_message: &SemanticWhirBaseFreshMessage,
    witness: &SemanticWhirBasePreCombinationWitness,
) -> Result<bool, SemanticWhirError> {
    if !semantic_generalized_relation_holds(
        &statement.input_relation,
        &statement.input_instance,
        &witness.input,
    )? {
        return Ok(false);
    }
    let input_claim = statement
        .input_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    let fresh_instance = SemanticGeneralizedRelationInstance {
        source: fresh_message.source.clone(),
        masks: fresh_message.masks.clone(),
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![SemanticGeneralizedLinearClaim {
            target: fresh_message.masked_claim,
            ..input_claim.clone()
        }],
    };
    semantic_generalized_relation_holds(&statement.input_relation, &fresh_instance, &witness.fresh)
        .map_err(Into::into)
}

fn combined_relation_and_instance(
    statement: &SemanticWhirBaseStatement,
    fresh_message: &SemanticWhirBaseFreshMessage,
    combination_challenge: ProofChallengeExtensionElement,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticWhirError,
> {
    let input_claim = statement
        .input_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    let source = combine_committed_instances(
        &fresh_message.source,
        &statement.input_instance.source,
        combination_challenge,
    )?;
    let masks = fresh_message
        .masks
        .iter()
        .zip(&statement.input_instance.masks)
        .map(|(fresh, input)| combine_committed_instances(fresh, input, combination_challenge))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        statement.input_relation.clone(),
        SemanticGeneralizedRelationInstance {
            source,
            masks,
            opening_claims: Vec::new(),
            carried_reduction_claims: vec![SemanticGeneralizedLinearClaim {
                target: fresh_message
                    .masked_claim
                    .add(combination_challenge.multiply(input_claim.target)),
                ..input_claim.clone()
            }],
        },
    ))
}

fn combine_committed_instances(
    fresh: &SemanticCommittedCodeInstance,
    input: &SemanticCommittedCodeInstance,
    combination_challenge: ProofChallengeExtensionElement,
) -> Result<SemanticCommittedCodeInstance, SemanticWhirError> {
    if fresh.received_rows.len() != input.received_rows.len()
        || fresh
            .received_rows
            .iter()
            .zip(&input.received_rows)
            .any(|(fresh, input)| fresh.len() != input.len())
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    Ok(SemanticCommittedCodeInstance {
        received_rows: fresh
            .received_rows
            .iter()
            .zip(&input.received_rows)
            .map(|(fresh, input)| {
                fresh
                    .iter()
                    .zip(input)
                    .map(|(&fresh, &input)| fresh.add(combination_challenge.multiply(input)))
                    .collect()
            })
            .collect(),
    })
}

fn combine_generalized_witnesses(
    fresh: &SemanticGeneralizedRelationWitness,
    input: &SemanticGeneralizedRelationWitness,
    combination_challenge: ProofChallengeExtensionElement,
) -> Result<SemanticGeneralizedRelationWitness, SemanticWhirError> {
    if fresh.masks.len() != input.masks.len() {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    Ok(SemanticGeneralizedRelationWitness {
        source: combine_committed_witnesses(&fresh.source, &input.source, combination_challenge)?,
        masks: fresh
            .masks
            .iter()
            .zip(&input.masks)
            .map(|(fresh, input)| combine_committed_witnesses(fresh, input, combination_challenge))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn combine_committed_witnesses(
    fresh: &SemanticCommittedCodeWitness,
    input: &SemanticCommittedCodeWitness,
    combination_challenge: ProofChallengeExtensionElement,
) -> Result<SemanticCommittedCodeWitness, SemanticWhirError> {
    Ok(SemanticCommittedCodeWitness {
        message_columns: combine_columns(
            &fresh.message_columns,
            &input.message_columns,
            combination_challenge,
        )?,
        hiding_randomness_columns: combine_columns(
            &fresh.hiding_randomness_columns,
            &input.hiding_randomness_columns,
            combination_challenge,
        )?,
    })
}

fn combine_columns(
    fresh: &[Vec<ProofChallengeExtensionElement>],
    input: &[Vec<ProofChallengeExtensionElement>],
    combination_challenge: ProofChallengeExtensionElement,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, SemanticWhirError> {
    if fresh.len() != input.len()
        || fresh
            .iter()
            .zip(input)
            .any(|(fresh, input)| fresh.len() != input.len())
    {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    Ok(fresh
        .iter()
        .zip(input)
        .map(|(fresh, input)| {
            fresh
                .iter()
                .zip(input)
                .map(|(&fresh, &input)| fresh.add(combination_challenge.multiply(input)))
                .collect()
        })
        .collect())
}

fn encode_generalized_witness(
    relation: &GeneralizedCommittedRelation,
    witness: &SemanticGeneralizedRelationWitness,
) -> Result<(SemanticGeneralizedRelationInstance, u128), SemanticWhirError> {
    if witness.masks.len() != relation.mask_codes.len() {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let (source, mut field_operation_count) =
        encode_committed_witness(&relation.source_code, &witness.source)?;
    let mut masks = Vec::with_capacity(relation.mask_codes.len());
    for (mask_relation, mask_witness) in relation.mask_codes.iter().zip(&witness.masks) {
        let (mask, operation_count) = encode_committed_witness(&mask_relation.code, mask_witness)?;
        field_operation_count = field_operation_count
            .checked_add(operation_count)
            .ok_or(SemanticWhirError::ArithmeticOverflow)?;
        masks.push(mask);
    }
    Ok((
        SemanticGeneralizedRelationInstance {
            source,
            masks,
            opening_claims: Vec::new(),
            carried_reduction_claims: Vec::new(),
        },
        field_operation_count,
    ))
}

fn encode_committed_witness(
    relation: &CommittedCodeRelation,
    witness: &SemanticCommittedCodeWitness,
) -> Result<(SemanticCommittedCodeInstance, u128), SemanticWhirError> {
    let encoded = encode_canonical_interleaved_reed_solomon_with_operation_count(
        semantic_code_geometry(relation)?,
        &witness.coefficient_columns(relation)?,
    )?;
    Ok((
        SemanticCommittedCodeInstance {
            received_rows: encoded.rows().to_vec(),
        },
        encoded.field_operation_count(),
    ))
}

fn verifier_accepts_full_base_transcript(
    statement: &SemanticWhirBaseStatement,
    fresh_message: &SemanticWhirBaseFreshMessage,
    combination_challenge: ProofChallengeExtensionElement,
    revealed_witness: &SemanticGeneralizedRelationWitness,
    query_challenges: &SemanticWhirBaseQueryChallenges,
) -> Result<bool, SemanticWhirError> {
    let (relation, combined_instance) =
        combined_relation_and_instance(statement, fresh_message, combination_challenge)?;
    let claim = combined_instance
        .carried_reduction_claims
        .first()
        .ok_or(SemanticWhirError::InvalidGeometry)?;
    if evaluate_claim(claim, revealed_witness)? != claim.target {
        return Ok(false);
    }
    let (canonical_instance, _) = encode_generalized_witness(&relation, revealed_witness)?;
    if query_challenges.source_positions.iter().any(|position| {
        canonical_instance.source.received_rows[*position]
            != combined_instance.source.received_rows[*position]
    }) {
        return Ok(false);
    }
    for ((canonical, combined), positions) in canonical_instance
        .masks
        .iter()
        .zip(&combined_instance.masks)
        .zip(&query_challenges.mask_group_positions)
    {
        if positions
            .iter()
            .any(|position| canonical.received_rows[*position] != combined.received_rows[*position])
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn append_query_escape(
    escapes: &mut Vec<SemanticWhirBaseQueryEscape>,
    role: SemanticWhirBaseOracleRole,
    relation: &CommittedCodeRelation,
    combined: &SemanticCommittedCodeInstance,
    canonical: &SemanticCommittedCodeInstance,
    query_positions: &[usize],
) -> Result<(), SemanticWhirError> {
    if combined.received_rows.len() != canonical.received_rows.len() {
        return Err(SemanticWhirError::InvalidGeometry);
    }
    let geometry = semantic_code_geometry(relation)?;
    let differing_row_count = combined
        .received_rows
        .iter()
        .zip(&canonical.received_rows)
        .filter(|(combined, canonical)| combined != canonical)
        .count();
    if differing_row_count <= geometry.selected_decoding_error_count() {
        return Ok(());
    }
    if query_positions
        .iter()
        .any(|position| combined.received_rows[*position] != canonical.received_rows[*position])
    {
        return Err(SemanticWhirError::InconsistentBadTransition);
    }
    escapes.push(SemanticWhirBaseQueryEscape {
        role,
        domain_size: geometry.block_length(),
        selected_decoding_error_count: geometry.selected_decoding_error_count(),
        differing_row_count,
        query_positions: query_positions.to_vec(),
    });
    Ok(())
}

fn validate_base_prefix(
    statement: &SemanticWhirBaseStatement,
    prefix: &SemanticWhirBasePrefix,
) -> Result<(), SemanticWhirError> {
    match (
        &prefix.fresh_message,
        prefix.combination_challenge,
        &prefix.revealed_witness,
        &prefix.query_challenges,
    ) {
        (None, None, None, None) => Ok(()),
        (Some(fresh_message), combination_challenge, revealed_witness, query_challenges) => {
            validate_fresh_message(statement, fresh_message)?;
            if (combination_challenge.is_none()
                && (revealed_witness.is_some() || query_challenges.is_some()))
                || (revealed_witness.is_none() && query_challenges.is_some())
            {
                return Err(SemanticWhirError::MalformedPrefix);
            }
            if let Some(query_challenges) = query_challenges {
                validate_query_challenges(statement, query_challenges)?;
            }
            Ok(())
        }
        _ => Err(SemanticWhirError::MalformedPrefix),
    }
}

fn validate_fresh_message(
    statement: &SemanticWhirBaseStatement,
    fresh_message: &SemanticWhirBaseFreshMessage,
) -> Result<(), SemanticWhirError> {
    if fresh_message.masks.len() != statement.input_relation.mask_codes.len() {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    validate_committed_instance_shape(
        &statement.input_relation.source_code,
        &fresh_message.source,
    )?;
    for (mask_relation, mask_instance) in statement
        .input_relation
        .mask_codes
        .iter()
        .zip(&fresh_message.masks)
    {
        validate_committed_instance_shape(&mask_relation.code, mask_instance)?;
    }
    Ok(())
}

fn validate_query_challenges(
    statement: &SemanticWhirBaseStatement,
    query_challenges: &SemanticWhirBaseQueryChallenges,
) -> Result<(), SemanticWhirError> {
    if !valid_query_positions(
        &query_challenges.source_positions,
        statement.source_query_count,
        usize::try_from(statement.input_relation.source_code.block_length)
            .map_err(|_| SemanticWhirError::InvalidGeometry)?,
    ) || query_challenges.mask_group_positions.len() != statement.input_relation.mask_codes.len()
    {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    for (positions, mask_relation) in query_challenges
        .mask_group_positions
        .iter()
        .zip(&statement.input_relation.mask_codes)
    {
        if !valid_query_positions(
            positions,
            statement.mask_query_count,
            usize::try_from(mask_relation.code.block_length)
                .map_err(|_| SemanticWhirError::InvalidGeometry)?,
        ) {
            return Err(SemanticWhirError::MalformedPrefix);
        }
    }
    Ok(())
}

fn valid_query_positions(positions: &[usize], expected: usize, block_length: usize) -> bool {
    positions.len() == expected
        && positions.iter().all(|position| *position < block_length)
        && positions
            .windows(2)
            .all(|positions| positions[0] < positions[1])
}

fn validate_combination_transition_prefix(
    statement: &SemanticWhirBaseStatement,
    prefix: &SemanticWhirBasePrefix,
) -> Result<(), SemanticWhirError> {
    validate_base_prefix(statement, prefix)?;
    if prefix.fresh_message.is_none()
        || prefix.combination_challenge.is_none()
        || prefix.revealed_witness.is_some()
        || prefix.query_challenges.is_some()
    {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    Ok(())
}

fn validate_final_transition_prefix(
    statement: &SemanticWhirBaseStatement,
    prefix: &SemanticWhirBasePrefix,
) -> Result<(), SemanticWhirError> {
    validate_base_prefix(statement, prefix)?;
    if prefix.fresh_message.is_none()
        || prefix.combination_challenge.is_none()
        || prefix.revealed_witness.is_none()
        || prefix.query_challenges.is_none()
    {
        return Err(SemanticWhirError::MalformedPrefix);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
