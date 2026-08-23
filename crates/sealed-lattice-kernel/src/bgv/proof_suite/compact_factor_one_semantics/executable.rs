//! Executable relaxed relations used by the factor-one proof.
//!
//! These predicates consume actual field values. They do not accept a
//! producer-supplied verdict: input R1CS membership is recomputed from the
//! verifier-owned matrices, while a generalized committed-code relation is
//! checked by re-encoding the supplied message and hiding randomness, measuring
//! its row distance from each oracle, and evaluating every public linear claim.
//! The matching extractor runs the canonical decoder and returns those same
//! mathematical witnesses or a typed failure.

use super::{CommittedCodeRelation, CommittedMaskCodeRelation, GeneralizedCommittedRelation};
use crate::bgv::proof_suite::ProofChallengeExtensionElement;
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT, COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER,
    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_MATRIX_COUNT,
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwError, CompactCfwGeometry,
    CompactCfwMaskMaterial, CompactCfwMatrixRole, CompactCfwR1csMatrices, CompactCfwTranscript,
    CompactChallengeField, PreparedCompactCfwProver, compact_cfw_semantic_final_message,
    compact_cfw_semantic_round_polynomial, compact_cfw_zero_evader_weights,
    compact_challenge_from_production, compact_challenge_to_production,
    verify_compact_cfw_transcript,
};
use crate::bgv::proof_suite::compact_cfw_initial_transition::{
    CompactCfwInitialTransitionBinding, CompactCfwInitialTransitionError,
    CompactCfwInitialVerifierPrefix, verify_compact_cfw_initial_transition_bad_event,
};
use crate::bgv::proof_suite::compact_reed_solomon::{
    CanonicalReedSolomonError, CanonicalReedSolomonGeometry,
    decode_canonical_interleaved_reed_solomon, encode_canonical_interleaved_reed_solomon,
};
use p3_field::PrimeCharacteristicRing;

mod semantic_composition;
mod semantic_construction;
mod semantic_error_bounds;
mod semantic_execution;
mod semantic_outer;
mod semantic_whir;

pub(super) use semantic_error_bounds::derive_factor_one_semantic_error_theorem;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCommittedCodeInstance {
    pub(super) received_rows: Vec<Vec<ProofChallengeExtensionElement>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCommittedCodeWitness {
    pub(super) message_columns: Vec<Vec<ProofChallengeExtensionElement>>,
    pub(super) hiding_randomness_columns: Vec<Vec<ProofChallengeExtensionElement>>,
}

impl SemanticCommittedCodeWitness {
    fn coefficient_columns(
        &self,
        relation: &CommittedCodeRelation,
    ) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, SemanticRelationError> {
        let message_length = usize::try_from(relation.message_length)
            .map_err(|_| SemanticRelationError::InvalidGeometry)?;
        let hiding_randomness_length = usize::try_from(relation.hiding_randomness_length)
            .map_err(|_| SemanticRelationError::InvalidGeometry)?;
        let interleaving_width = usize::try_from(relation.interleaving_width)
            .map_err(|_| SemanticRelationError::InvalidGeometry)?;
        if self.message_columns.len() != interleaving_width
            || self.hiding_randomness_columns.len() != interleaving_width
            || self
                .message_columns
                .iter()
                .any(|column| column.len() != message_length)
            || self
                .hiding_randomness_columns
                .iter()
                .any(|column| column.len() != hiding_randomness_length)
        {
            return Err(SemanticRelationError::MalformedWitness);
        }
        let coefficient_count = message_length
            .checked_add(hiding_randomness_length)
            .ok_or(SemanticRelationError::ArithmeticOverflow)?;
        Ok(self
            .message_columns
            .iter()
            .zip(&self.hiding_randomness_columns)
            .map(|(message, hiding_randomness)| {
                let mut coefficients = Vec::with_capacity(coefficient_count);
                coefficients.extend_from_slice(message);
                coefficients.extend_from_slice(hiding_randomness);
                coefficients
            })
            .collect())
    }

    fn flattened_messages(&self) -> Vec<ProofChallengeExtensionElement> {
        self.message_columns
            .iter()
            .flat_map(|column| column.iter().copied())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticGeneralizedLinearClaim {
    pub(super) source_covector: Vec<ProofChallengeExtensionElement>,
    pub(super) mask_covectors: Vec<Vec<ProofChallengeExtensionElement>>,
    pub(super) target: ProofChallengeExtensionElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticGeneralizedRelationInstance {
    pub(super) source: SemanticCommittedCodeInstance,
    pub(super) masks: Vec<SemanticCommittedCodeInstance>,
    pub(super) opening_claims: Vec<SemanticGeneralizedLinearClaim>,
    pub(super) carried_reduction_claims: Vec<SemanticGeneralizedLinearClaim>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticGeneralizedRelationWitness {
    pub(super) source: SemanticCommittedCodeWitness,
    pub(super) masks: Vec<SemanticCommittedCodeWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticGeneralizedRelationExtraction {
    pub(super) witness: SemanticGeneralizedRelationWitness,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticRelationError {
    ArithmeticOverflow,
    CodeCorrection(CanonicalReedSolomonError),
    InvalidGeometry,
    MalformedInstance,
    MalformedWitness,
    RelationNotSatisfied,
}

impl From<CanonicalReedSolomonError> for SemanticRelationError {
    fn from(error: CanonicalReedSolomonError) -> Self {
        Self::CodeCorrection(error)
    }
}

pub(super) fn semantic_r1cs_relation_holds(
    matrices: &impl CompactCfwR1csMatrices,
    public_input: &[CompactChallengeField],
    witness: &[CompactChallengeField],
) -> Result<bool, CompactCfwError> {
    if public_input.len() != matrices.witness_length() || witness.len() != matrices.witness_length()
    {
        return Ok(false);
    }
    let matrix_rows = [
        CompactCfwMatrixRole::LeftMultiplicand,
        CompactCfwMatrixRole::RightMultiplicand,
        CompactCfwMatrixRole::Product,
    ]
    .map(|matrix_role| matrices.evaluate_assignment_rows(matrix_role, public_input, witness))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let [left_rows, right_rows, product_rows]: [Vec<CompactChallengeField>;
        COMPACT_CFW_MATRIX_COUNT] = matrix_rows
        .try_into()
        .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
    if left_rows.len() != right_rows.len()
        || left_rows.len() != product_rows.len()
        || left_rows.is_empty()
    {
        return Ok(false);
    }
    Ok(left_rows
        .iter()
        .zip(&right_rows)
        .zip(&product_rows)
        .all(|((left, right), product)| *left * *right == *product))
}

pub(super) fn semantic_generalized_relation_holds(
    relation: &GeneralizedCommittedRelation,
    instance: &SemanticGeneralizedRelationInstance,
    witness: &SemanticGeneralizedRelationWitness,
) -> Result<bool, SemanticRelationError> {
    validate_generalized_relation_shape(relation, instance)?;
    if witness.masks.len() != relation.mask_codes.len() {
        return Ok(false);
    }
    let source_relation_holds = match semantic_committed_code_relation_holds(
        &relation.source_code,
        &instance.source,
        &witness.source,
    ) {
        Ok(holds) => holds,
        Err(SemanticRelationError::MalformedWitness) => return Ok(false),
        Err(error) => return Err(error),
    };
    if !source_relation_holds {
        return Ok(false);
    }
    for ((mask_relation, mask_instance), mask_witness) in relation
        .mask_codes
        .iter()
        .zip(&instance.masks)
        .zip(&witness.masks)
    {
        let mask_relation_holds = match semantic_committed_code_relation_holds(
            &mask_relation.code,
            mask_instance,
            mask_witness,
        ) {
            Ok(holds) => holds,
            Err(SemanticRelationError::MalformedWitness) => return Ok(false),
            Err(error) => return Err(error),
        };
        if !mask_relation_holds {
            return Ok(false);
        }
    }

    let source_message = witness.source.flattened_messages();
    let mask_messages = witness
        .masks
        .iter()
        .map(SemanticCommittedCodeWitness::flattened_messages)
        .collect::<Vec<_>>();
    for claim in instance
        .opening_claims
        .iter()
        .chain(&instance.carried_reduction_claims)
    {
        if !semantic_generalized_claim_holds(claim, &source_message, &mask_messages)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn extract_semantic_generalized_relation_witness(
    relation: &GeneralizedCommittedRelation,
    instance: &SemanticGeneralizedRelationInstance,
) -> Result<SemanticGeneralizedRelationExtraction, SemanticRelationError> {
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
        extract_semantic_committed_code_witness(&relation.source_code, &instance.source)?;
    let mut masks = Vec::new();
    masks
        .try_reserve_exact(relation.mask_codes.len())
        .map_err(|_| SemanticRelationError::ArithmeticOverflow)?;
    for (mask_relation, mask_instance) in relation.mask_codes.iter().zip(&instance.masks) {
        let (mask_witness, mask_field_operation_count) =
            extract_semantic_committed_code_witness(&mask_relation.code, mask_instance)?;
        field_operation_count = field_operation_count
            .checked_add(mask_field_operation_count)
            .ok_or(SemanticRelationError::ArithmeticOverflow)?;
        masks.push(mask_witness);
    }
    let extraction = SemanticGeneralizedRelationExtraction {
        witness: SemanticGeneralizedRelationWitness { source, masks },
        field_operation_count,
    };
    if !semantic_generalized_relation_holds(relation, instance, &extraction.witness)? {
        return Err(SemanticRelationError::RelationNotSatisfied);
    }
    Ok(extraction)
}

fn validate_generalized_relation_shape(
    relation: &GeneralizedCommittedRelation,
    instance: &SemanticGeneralizedRelationInstance,
) -> Result<(), SemanticRelationError> {
    validate_generalized_relation_descriptor(relation)?;
    let expected_opening_claim_count = usize::try_from(relation.opening_evaluation_claim_count)
        .map_err(|_| SemanticRelationError::InvalidGeometry)?;
    let expected_carried_claim_count = usize::try_from(relation.carried_reduction_claim_count)
        .map_err(|_| SemanticRelationError::InvalidGeometry)?;
    if instance.masks.len() != relation.mask_codes.len()
        || instance.opening_claims.len() != expected_opening_claim_count
        || instance.carried_reduction_claims.len() != expected_carried_claim_count
        || expected_opening_claim_count
            .checked_add(expected_carried_claim_count)
            .and_then(|count| u64::try_from(count).ok())
            != Some(relation.claim_count)
    {
        return Err(SemanticRelationError::MalformedInstance);
    }
    Ok(())
}

fn validate_generalized_relation_descriptor(
    relation: &GeneralizedCommittedRelation,
) -> Result<(), SemanticRelationError> {
    let source_message_element_count = relation
        .source_code
        .message_length
        .checked_mul(relation.source_code.interleaving_width)
        .ok_or(SemanticRelationError::ArithmeticOverflow)?;
    let source_hiding_element_count = relation
        .source_code
        .hiding_randomness_length
        .checked_mul(relation.source_code.interleaving_width)
        .ok_or(SemanticRelationError::ArithmeticOverflow)?;
    let mask_message_element_count = relation.mask_codes.iter().try_fold(
        0_u64,
        |count, mask_relation| -> Result<_, SemanticRelationError> {
            count
                .checked_add(
                    mask_relation
                        .code
                        .message_length
                        .checked_mul(mask_relation.code.interleaving_width)
                        .ok_or(SemanticRelationError::ArithmeticOverflow)?,
                )
                .ok_or(SemanticRelationError::ArithmeticOverflow)
        },
    )?;
    let covector_extension_element_count = source_message_element_count
        .checked_add(1)
        .and_then(|count| count.checked_add(mask_message_element_count))
        .ok_or(SemanticRelationError::ArithmeticOverflow)?;
    let claim_count = relation
        .opening_evaluation_claim_count
        .checked_add(relation.carried_reduction_claim_count)
        .ok_or(SemanticRelationError::ArithmeticOverflow)?;
    if relation.source_message_element_count != source_message_element_count
        || relation.source_hiding_element_count != source_hiding_element_count
        || relation.mask_message_element_count != mask_message_element_count
        || relation.covector_extension_element_count != covector_extension_element_count
        || relation.claim_count != claim_count
    {
        return Err(SemanticRelationError::InvalidGeometry);
    }
    Ok(())
}

fn semantic_committed_code_relation_holds(
    relation: &CommittedCodeRelation,
    instance: &SemanticCommittedCodeInstance,
    witness: &SemanticCommittedCodeWitness,
) -> Result<bool, SemanticRelationError> {
    let geometry = semantic_code_geometry(relation)?;
    let coefficient_columns = witness.coefficient_columns(relation)?;
    let canonical_rows = encode_canonical_interleaved_reed_solomon(geometry, &coefficient_columns)?;
    if instance.received_rows.len() != geometry.block_length()
        || instance
            .received_rows
            .iter()
            .any(|row| row.len() != geometry.interleaving_width())
    {
        return Err(SemanticRelationError::MalformedInstance);
    }
    let differing_row_count = instance
        .received_rows
        .iter()
        .zip(&canonical_rows)
        .filter(|(received, canonical)| received != canonical)
        .count();
    Ok(differing_row_count <= geometry.selected_decoding_error_count())
}

fn extract_semantic_committed_code_witness(
    relation: &CommittedCodeRelation,
    instance: &SemanticCommittedCodeInstance,
) -> Result<(SemanticCommittedCodeWitness, u128), SemanticRelationError> {
    let decoded = decode_canonical_interleaved_reed_solomon(
        semantic_code_geometry(relation)?,
        &instance.received_rows,
    )?;
    Ok((
        SemanticCommittedCodeWitness {
            message_columns: decoded.message_columns().to_vec(),
            hiding_randomness_columns: decoded.hiding_randomness_columns().to_vec(),
        },
        decoded.field_operation_count(),
    ))
}

fn semantic_code_geometry(
    relation: &CommittedCodeRelation,
) -> Result<CanonicalReedSolomonGeometry, SemanticRelationError> {
    CanonicalReedSolomonGeometry::new(
        usize::try_from(relation.message_length)
            .map_err(|_| SemanticRelationError::InvalidGeometry)?,
        usize::try_from(relation.hiding_randomness_length)
            .map_err(|_| SemanticRelationError::InvalidGeometry)?,
        usize::try_from(relation.block_length)
            .map_err(|_| SemanticRelationError::InvalidGeometry)?,
        usize::try_from(relation.interleaving_width)
            .map_err(|_| SemanticRelationError::InvalidGeometry)?,
    )
    .map_err(Into::into)
}

fn semantic_generalized_claim_holds(
    claim: &SemanticGeneralizedLinearClaim,
    source_message: &[ProofChallengeExtensionElement],
    mask_messages: &[Vec<ProofChallengeExtensionElement>],
) -> Result<bool, SemanticRelationError> {
    if claim.source_covector.len() != source_message.len()
        || claim.mask_covectors.len() != mask_messages.len()
        || claim
            .mask_covectors
            .iter()
            .zip(mask_messages)
            .any(|(covector, message)| covector.len() != message.len())
    {
        return Err(SemanticRelationError::MalformedInstance);
    }
    let source_value = dot_product(&claim.source_covector, source_message)?;
    let combined_value = claim.mask_covectors.iter().zip(mask_messages).try_fold(
        source_value,
        |accumulated, (covector, message)| {
            Ok::<_, SemanticRelationError>(accumulated.add(dot_product(covector, message)?))
        },
    )?;
    Ok(combined_value == claim.target)
}

fn dot_product(
    left: &[ProofChallengeExtensionElement],
    right: &[ProofChallengeExtensionElement],
) -> Result<ProofChallengeExtensionElement, SemanticRelationError> {
    if left.len() != right.len() {
        return Err(SemanticRelationError::MalformedInstance);
    }
    Ok(left.iter().zip(right).fold(
        ProofChallengeExtensionElement::ZERO,
        |sum, (left, right)| sum.add(left.multiply(*right)),
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwCodeRelations {
    pub(super) source: CommittedCodeRelation,
    pub(super) inner_masks: CommittedCodeRelation,
    pub(super) outer_masks: CommittedCodeRelation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwCommittedInstances {
    pub(super) source: SemanticCommittedCodeInstance,
    pub(super) inner_masks: SemanticCommittedCodeInstance,
    pub(super) outer_masks: SemanticCommittedCodeInstance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwCrossEpochHandoff {
    pub(super) mask_code_relation: CommittedMaskCodeRelation,
    pub(super) committed_instance: SemanticCommittedCodeInstance,
    pub(super) point: Vec<CompactChallengeField>,
    pub(super) copied_main_source_element_count: usize,
    pub(super) masked_pre_challenge_evaluation: CompactChallengeField,
    pub(super) masked_main_evaluation: CompactChallengeField,
    pub(super) mask_difference: CompactChallengeField,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwInitialStatementBinding {
    relation_plan_hash: [u8; 64],
    canonical_public_input_binding: [u8; 64],
    initial_verifier_prefix: CompactCfwInitialVerifierPrefix,
}

impl SemanticCfwInitialStatementBinding {
    pub(super) fn new(
        relation_plan_hash: [u8; 64],
        canonical_public_input_binding: [u8; 64],
        initial_verifier_prefix: &CompactCfwInitialVerifierPrefix,
    ) -> Self {
        Self {
            relation_plan_hash,
            canonical_public_input_binding,
            initial_verifier_prefix: initial_verifier_prefix.clone(),
        }
    }
}

pub(super) struct SemanticCfwStatement<'statement, Matrices: CompactCfwR1csMatrices> {
    relation_plan_hash: [u8; 64],
    canonical_public_input_binding: [u8; 64],
    initial_verifier_prefix: CompactCfwInitialVerifierPrefix,
    matrices: &'statement Matrices,
    public_input: &'statement [CompactChallengeField],
    code_relations: &'statement SemanticCfwCodeRelations,
    committed_instances: &'statement SemanticCfwCommittedInstances,
    cross_epoch_handoff: &'statement SemanticCfwCrossEpochHandoff,
    input_implicit_tuple_dimension: usize,
    output_implicit_tuple_dimension: usize,
}

impl<'statement, Matrices: CompactCfwR1csMatrices> SemanticCfwStatement<'statement, Matrices> {
    pub(super) fn new(
        initial_statement_binding: SemanticCfwInitialStatementBinding,
        matrices: &'statement Matrices,
        public_input: &'statement [CompactChallengeField],
        code_relations: &'statement SemanticCfwCodeRelations,
        committed_instances: &'statement SemanticCfwCommittedInstances,
        cross_epoch_handoff: &'statement SemanticCfwCrossEpochHandoff,
    ) -> Result<Self, SemanticCfwError> {
        let SemanticCfwInitialStatementBinding {
            relation_plan_hash,
            canonical_public_input_binding,
            initial_verifier_prefix,
        } = initial_statement_binding;
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())?;
        if public_input.len() != matrices.witness_length()
            || initial_verifier_prefix.equality_point().len() != geometry.sumcheck_round_count()
        {
            return Err(SemanticCfwError::MalformedStatement);
        }
        initial_verifier_prefix.verify_semantic_binding(
            relation_plan_hash,
            canonical_public_input_binding,
            initial_verifier_prefix.auxiliary_target(),
            initial_verifier_prefix.constraint_combining_challenge(),
            initial_verifier_prefix.equality_point(),
        )?;
        validate_semantic_cfw_code_relations(geometry, code_relations)?;
        validate_semantic_cfw_cross_epoch_handoff(geometry, cross_epoch_handoff)?;
        Ok(Self {
            relation_plan_hash,
            canonical_public_input_binding,
            initial_verifier_prefix,
            matrices,
            public_input,
            code_relations,
            committed_instances,
            cross_epoch_handoff,
            input_implicit_tuple_dimension: 0,
            output_implicit_tuple_dimension: 0,
        })
    }

    pub(super) const fn relation_plan_hash(&self) -> [u8; 64] {
        self.relation_plan_hash
    }

    pub(super) const fn implicit_tuple_dimensions(&self) -> (usize, usize) {
        (
            self.input_implicit_tuple_dimension,
            self.output_implicit_tuple_dimension,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwFinalMessage {
    pub(super) outer_evaluations: Vec<CompactChallengeField>,
    pub(super) final_values: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwTranscriptPrefix {
    pub(super) auxiliary_target: CompactChallengeField,
    pub(super) constraint_combining_challenge: Option<CompactChallengeField>,
    pub(super) equality_point: Vec<CompactChallengeField>,
    pub(super) round_polynomials:
        Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
    pub(super) round_challenges: Vec<CompactChallengeField>,
    pub(super) final_message: Option<SemanticCfwFinalMessage>,
    pub(super) joint_constraint_challenge: Option<CompactChallengeField>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwExtractedWitness {
    pub(super) source_code_witness: SemanticCommittedCodeWitness,
    pub(super) inner_mask_code_witness: SemanticCommittedCodeWitness,
    pub(super) outer_mask_code_witness: SemanticCommittedCodeWitness,
    pub(super) cross_epoch_mask_code_witness: SemanticCommittedCodeWitness,
    pub(super) r1cs_witness: Vec<CompactChallengeField>,
    pub(super) mask_material: CompactCfwMaskMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwDecoding {
    pub(super) witness: SemanticCfwExtractedWitness,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwTransitionExtraction {
    pub(super) witness: Option<SemanticCfwExtractedWitness>,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticCfwVerifierTransition {
    InitialRandomness,
    SumcheckRound { round_ordinal: usize },
    JointConstraint,
}

/// Opaque result of deriving and independently checking the initial bad-event
/// polynomial from verifier-owned matrices, an extracted witness, and the
/// source-bound production prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCfwInitialBadTransition {
    initial_verifier_prefix: CompactCfwInitialVerifierPrefix,
    soundness_numerator: u64,
}

impl SemanticCfwInitialBadTransition {
    pub(super) const fn soundness_numerator(&self) -> u64 {
        self.soundness_numerator
    }

    #[cfg(test)]
    fn initial_verifier_prefix(&self) -> &CompactCfwInitialVerifierPrefix {
        &self.initial_verifier_prefix
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticCfwBadTransition {
    InitialConsistency(SemanticCfwInitialBadTransition),
    NonzeroPolynomial {
        transition: SemanticCfwVerifierTransition,
        coefficients: Vec<CompactChallengeField>,
        challenge: CompactChallengeField,
    },
    ZeroEvader {
        residuals: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        challenge: CompactChallengeField,
    },
}

impl SemanticCfwBadTransition {
    /// Uniform polynomial-identity numerator for this certificate family.
    ///
    /// The initial family uses the complete combining-scalar and multilinear
    /// equality-point degree even when a particular auxiliary-target mismatch
    /// would admit the tighter one-root bound.
    pub(super) fn polynomial_identity_numerator(&self) -> Option<u64> {
        match self {
            Self::InitialConsistency(event) => Some(event.soundness_numerator()),
            Self::NonzeroPolynomial { coefficients, .. } => coefficients
                .iter()
                .rposition(|coefficient| *coefficient != CompactChallengeField::ZERO)
                .and_then(|degree| u64::try_from(degree).ok()),
            Self::ZeroEvader { residuals, .. } => residuals
                .iter()
                .rposition(|residual| *residual != CompactChallengeField::ZERO)
                .and_then(|degree| u64::try_from(degree).ok()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticCfwError {
    ArithmeticOverflow,
    CompactCfw(CompactCfwError),
    InconsistentBadTransition,
    InitialSourceBinding(CompactCfwInitialTransitionError),
    MalformedPrefix,
    MalformedStatement,
    Relation(SemanticRelationError),
}

impl From<CompactCfwInitialTransitionError> for SemanticCfwError {
    fn from(error: CompactCfwInitialTransitionError) -> Self {
        Self::InitialSourceBinding(error)
    }
}

impl From<CompactCfwError> for SemanticCfwError {
    fn from(error: CompactCfwError) -> Self {
        Self::CompactCfw(error)
    }
}

impl From<crate::bgv::proof_suite::compact_cfw::CompactCfwGeometryError> for SemanticCfwError {
    fn from(error: crate::bgv::proof_suite::compact_cfw::CompactCfwGeometryError) -> Self {
        Self::CompactCfw(error.into())
    }
}

impl From<SemanticRelationError> for SemanticCfwError {
    fn from(error: SemanticRelationError) -> Self {
        Self::Relation(error)
    }
}

/// Deterministic straight-line extractor for the committed CFW source and
/// locally introduced mask oracles. Every local output is obtained by the
/// canonical unique decoder; the cross-epoch mask witness is carried from the
/// preceding WHIR component and is never re-decoded or charged here. No
/// producer verdict or cached honest assignment enters this algorithm.
pub(super) fn semantic_cfw_errbr<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    carried_cross_epoch_mask_code_witness: SemanticCommittedCodeWitness,
) -> Result<SemanticCfwDecoding, SemanticCfwError> {
    let geometry = CompactCfwGeometry::derive(statement.matrices.witness_length())?;
    let (source_code_witness, source_field_operation_count) =
        extract_semantic_committed_code_witness(
            &statement.code_relations.source,
            &statement.committed_instances.source,
        )?;
    let (inner_mask_code_witness, inner_field_operation_count) =
        extract_semantic_committed_code_witness(
            &statement.code_relations.inner_masks,
            &statement.committed_instances.inner_masks,
        )?;
    let (outer_mask_code_witness, outer_field_operation_count) =
        extract_semantic_committed_code_witness(
            &statement.code_relations.outer_masks,
            &statement.committed_instances.outer_masks,
        )?;

    let witness = semantic_cfw_witness_from_code_witnesses(
        geometry,
        source_code_witness,
        inner_mask_code_witness,
        outer_mask_code_witness,
        carried_cross_epoch_mask_code_witness,
    )?;
    let field_operation_count = source_field_operation_count
        .checked_add(inner_field_operation_count)
        .and_then(|count| count.checked_add(outer_field_operation_count))
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;

    Ok(SemanticCfwDecoding {
        witness,
        field_operation_count,
    })
}

fn semantic_cfw_witness_from_code_witnesses(
    geometry: CompactCfwGeometry,
    source_code_witness: SemanticCommittedCodeWitness,
    inner_mask_code_witness: SemanticCommittedCodeWitness,
    outer_mask_code_witness: SemanticCommittedCodeWitness,
    cross_epoch_mask_code_witness: SemanticCommittedCodeWitness,
) -> Result<SemanticCfwExtractedWitness, SemanticCfwError> {
    let r1cs_witness = source_code_witness
        .flattened_messages()
        .into_iter()
        .map(compact_challenge_from_production)
        .collect::<Vec<_>>();
    if r1cs_witness.len() != geometry.witness_length() {
        return Err(SemanticCfwError::MalformedStatement);
    }
    let inner_masks = compact_mask_messages::<COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH>(
        &inner_mask_code_witness,
        geometry.inner_mask_count(),
    )?;
    let outer_masks = compact_mask_messages::<COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH>(
        &outer_mask_code_witness,
        geometry.outer_mask_count(),
    )?;
    let mask_material =
        CompactCfwMaskMaterial::from_canonical_messages(geometry, inner_masks, outer_masks)?;
    Ok(SemanticCfwExtractedWitness {
        source_code_witness,
        inner_mask_code_witness,
        outer_mask_code_witness,
        cross_epoch_mask_code_witness,
        r1cs_witness,
        mask_material,
    })
}

fn semantic_cfw_decode_for_transition<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    transition: SemanticCfwVerifierTransition,
    post_challenge_witness: &SemanticCfwExtractedWitness,
) -> Result<SemanticCfwDecoding, SemanticCfwError> {
    match transition {
        SemanticCfwVerifierTransition::InitialRandomness => semantic_cfw_errbr(
            statement,
            post_challenge_witness.cross_epoch_mask_code_witness.clone(),
        ),
        SemanticCfwVerifierTransition::SumcheckRound { .. } => {
            let geometry = CompactCfwGeometry::derive(statement.matrices.witness_length())?;
            let (inner_mask_code_witness, inner_field_operation_count) =
                extract_semantic_committed_code_witness(
                    &statement.code_relations.inner_masks,
                    &statement.committed_instances.inner_masks,
                )?;
            let (outer_mask_code_witness, outer_field_operation_count) =
                extract_semantic_committed_code_witness(
                    &statement.code_relations.outer_masks,
                    &statement.committed_instances.outer_masks,
                )?;
            Ok(SemanticCfwDecoding {
                witness: semantic_cfw_witness_from_code_witnesses(
                    geometry,
                    post_challenge_witness.source_code_witness.clone(),
                    inner_mask_code_witness,
                    outer_mask_code_witness,
                    post_challenge_witness.cross_epoch_mask_code_witness.clone(),
                )?,
                field_operation_count: inner_field_operation_count
                    .checked_add(outer_field_operation_count)
                    .ok_or(SemanticCfwError::ArithmeticOverflow)?,
            })
        }
        SemanticCfwVerifierTransition::JointConstraint => Ok(SemanticCfwDecoding {
            witness: post_challenge_witness.clone(),
            field_operation_count: 0,
        }),
    }
}

/// Deterministic extractor at one CFW verifier move.
///
/// The initial move decodes the committed source and both local CFW mask
/// groups, each later sumcheck move decodes the two local mask groups, and the
/// joint move carries the witness unchanged. The extractor does not invoke
/// `KState`: CDHZ permits that predicate to be inefficient, while `ERRBR` must
/// be polynomial-time. Correction failure returns bottom. Whether the returned
/// candidate satisfies the immediately preceding state is evaluated by the
/// bad-transition experiment outside this algorithm.
pub(super) fn semantic_cfw_errbr_at_verifier_move<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    extended_prefix: &SemanticCfwTranscriptPrefix,
    post_challenge_witness: &SemanticCfwExtractedWitness,
) -> Result<SemanticCfwTransitionExtraction, SemanticCfwError> {
    let transition = semantic_cfw_verifier_transition(extended_prefix)?;
    let decoded =
        match semantic_cfw_decode_for_transition(statement, transition, post_challenge_witness) {
            Ok(decoded) => decoded,
            Err(SemanticCfwError::Relation(SemanticRelationError::CodeCorrection(_))) => {
                return Ok(SemanticCfwTransitionExtraction {
                    witness: None,
                    field_operation_count: 0,
                });
            }
            Err(error) => return Err(error),
        };
    Ok(SemanticCfwTransitionExtraction {
        field_operation_count: decoded.field_operation_count,
        witness: Some(decoded.witness),
    })
}

/// Executes the CFW bad-transition implication against the production
/// matrices, decoded commitments, and exact transcript prefix.
pub(super) fn semantic_cfw_bad_transition<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    extended_prefix: &SemanticCfwTranscriptPrefix,
    post_challenge_witness: &SemanticCfwExtractedWitness,
) -> Result<Option<SemanticCfwBadTransition>, SemanticCfwError> {
    let transition = semantic_cfw_verifier_transition(extended_prefix)?;
    if transition == SemanticCfwVerifierTransition::InitialRandomness {
        verify_semantic_cfw_initial_source_binding(statement, extended_prefix)?;
    }
    if !semantic_cfw_kstate(statement, Some(extended_prefix), post_challenge_witness)? {
        return Ok(None);
    }
    let decoded =
        match semantic_cfw_decode_for_transition(statement, transition, post_challenge_witness) {
            Ok(decoded) => decoded,
            Err(SemanticCfwError::Relation(SemanticRelationError::CodeCorrection(_))) => {
                // A true post state already supplies a witness inside the
                // strict radius for these unchanged committed instances.
                return Err(SemanticCfwError::InconsistentBadTransition);
            }
            Err(error) => return Err(error),
        };
    let preceding_prefix = semantic_cfw_preceding_prefix(extended_prefix)?;
    if semantic_cfw_kstate(statement, Some(&preceding_prefix), &decoded.witness)? {
        return Ok(None);
    }
    if decoded.witness != *post_challenge_witness {
        // The post state and decoded predecessor use the same committed code
        // instances at every CFW transition. Strict unique decoding rules out
        // two different witnesses within the selected radius.
        return Err(SemanticCfwError::InconsistentBadTransition);
    }

    match transition {
        SemanticCfwVerifierTransition::InitialRandomness => {
            semantic_cfw_initial_bad_transition(statement, &decoded.witness).map(Some)
        }
        SemanticCfwVerifierTransition::SumcheckRound { round_ordinal } => {
            let actual_polynomial = compact_cfw_semantic_round_polynomial(
                statement.matrices,
                statement.public_input,
                &decoded.witness.r1cs_witness,
                &decoded.witness.mask_material,
                extended_prefix
                    .constraint_combining_challenge
                    .ok_or(SemanticCfwError::MalformedPrefix)?,
                &extended_prefix.equality_point,
                &extended_prefix.round_challenges[..round_ordinal],
                round_ordinal,
            )?;
            let supplied_polynomial = extended_prefix
                .round_polynomials
                .get(round_ordinal)
                .ok_or(SemanticCfwError::MalformedPrefix)?;
            let coefficients = actual_polynomial
                .iter()
                .zip(supplied_polynomial)
                .map(|(&actual, &supplied)| actual - supplied)
                .collect::<Vec<_>>();
            let challenge = *extended_prefix
                .round_challenges
                .get(round_ordinal)
                .ok_or(SemanticCfwError::MalformedPrefix)?;
            if coefficients
                .iter()
                .all(|coefficient| *coefficient == CompactChallengeField::ZERO)
                || compact_polynomial_evaluation(&coefficients, challenge)
                    != CompactChallengeField::ZERO
            {
                return Err(SemanticCfwError::InconsistentBadTransition);
            }
            Ok(Some(SemanticCfwBadTransition::NonzeroPolynomial {
                transition,
                coefficients,
                challenge,
            }))
        }
        SemanticCfwVerifierTransition::JointConstraint => {
            let supplied = extended_prefix
                .final_message
                .as_ref()
                .ok_or(SemanticCfwError::MalformedPrefix)?;
            let actual = compact_cfw_semantic_final_message(
                statement.matrices,
                statement.public_input,
                &decoded.witness.r1cs_witness,
                &decoded.witness.mask_material,
                &extended_prefix.round_challenges,
            )?;
            let residuals = core::array::from_fn(|matrix_ordinal| {
                actual.final_values()[matrix_ordinal] - supplied.final_values[matrix_ordinal]
            });
            let challenge = extended_prefix
                .joint_constraint_challenge
                .ok_or(SemanticCfwError::MalformedPrefix)?;
            let weights = compact_cfw_zero_evader_weights(challenge);
            if residuals
                .iter()
                .all(|residual| *residual == CompactChallengeField::ZERO)
                || residuals
                    .iter()
                    .zip(weights)
                    .map(|(&residual, weight)| residual * weight)
                    .sum::<CompactChallengeField>()
                    != CompactChallengeField::ZERO
            {
                return Err(SemanticCfwError::InconsistentBadTransition);
            }
            Ok(Some(SemanticCfwBadTransition::ZeroEvader {
                residuals,
                weights,
                challenge,
            }))
        }
    }
}

fn semantic_cfw_initial_bad_transition<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    decoded: &SemanticCfwExtractedWitness,
) -> Result<SemanticCfwBadTransition, SemanticCfwError> {
    let actual_auxiliary_target = PreparedCompactCfwProver::prepare(
        statement.matrices,
        statement.public_input,
        &decoded.r1cs_witness,
        decoded.mask_material.clone(),
    )?
    .auxiliary_target();
    let auxiliary_difference =
        actual_auxiliary_target - statement.initial_verifier_prefix.auxiliary_target();
    let residuals = semantic_cfw_masked_constraint_hypercube_residuals(statement, decoded)?;
    let soundness_numerator = verify_compact_cfw_initial_transition_bad_event(
        auxiliary_difference,
        &residuals,
        statement
            .initial_verifier_prefix
            .constraint_combining_challenge(),
        statement.initial_verifier_prefix.equality_point(),
    )
    .map_err(|error| match error {
        CompactCfwInitialTransitionError::IdentityDoesNotVanish
        | CompactCfwInitialTransitionError::ZeroPolynomial => {
            SemanticCfwError::InconsistentBadTransition
        }
        other => SemanticCfwError::InitialSourceBinding(other),
    })?;
    Ok(SemanticCfwBadTransition::InitialConsistency(
        SemanticCfwInitialBadTransition {
            initial_verifier_prefix: statement.initial_verifier_prefix.clone(),
            soundness_numerator,
        },
    ))
}

fn verify_semantic_cfw_initial_source_binding<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    extended_prefix: &SemanticCfwTranscriptPrefix,
) -> Result<(), SemanticCfwError> {
    let constraint_combining_challenge = extended_prefix
        .constraint_combining_challenge
        .ok_or(SemanticCfwError::MalformedPrefix)?;
    statement.initial_verifier_prefix.verify_semantic_binding(
        statement.relation_plan_hash,
        statement.canonical_public_input_binding,
        extended_prefix.auxiliary_target,
        constraint_combining_challenge,
        &extended_prefix.equality_point,
    )?;
    Ok(())
}

fn semantic_cfw_masked_constraint_hypercube_residuals<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    witness: &SemanticCfwExtractedWitness,
) -> Result<Vec<CompactChallengeField>, SemanticCfwError> {
    let geometry = CompactCfwGeometry::derive(statement.matrices.witness_length())?;
    let matrix_rows = CompactCfwMatrixRole::ALL
        .map(|matrix_role| {
            statement.matrices.evaluate_assignment_rows(
                matrix_role,
                statement.public_input,
                &witness.r1cs_witness,
            )
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let row_count = 1_usize
        .checked_shl(
            u32::try_from(geometry.sumcheck_round_count())
                .map_err(|_| SemanticCfwError::ArithmeticOverflow)?,
        )
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    if matrix_rows.iter().any(|rows| rows.len() != row_count) {
        return Err(SemanticCfwError::MalformedStatement);
    }
    let inner_multiplier =
        CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER);
    let mut residuals = Vec::with_capacity(row_count);
    for row_ordinal in 0..row_count {
        let factors = CompactCfwMatrixRole::ALL.map(|matrix_role| {
            let mut factor = matrix_rows[matrix_role.ordinal()][row_ordinal];
            for round_ordinal in 0..geometry.sumcheck_round_count() {
                let mask_ordinal = round_ordinal
                    .checked_mul(COMPACT_CFW_MATRIX_COUNT)
                    .and_then(|ordinal| ordinal.checked_add(matrix_role.ordinal()))
                    .ok_or(SemanticCfwError::ArithmeticOverflow)?;
                let inner_mask = witness
                    .mask_material
                    .inner_masks()
                    .get(mask_ordinal)
                    .ok_or(SemanticCfwError::MalformedStatement)?;
                let endpoint = if (row_ordinal >> round_ordinal) & 1 == 0 {
                    CompactChallengeField::ZERO
                } else {
                    CompactChallengeField::ONE
                };
                factor += inner_multiplier * compact_polynomial_evaluation(inner_mask, endpoint);
            }
            Ok::<_, SemanticCfwError>(factor)
        });
        let factors = factors
            .into_iter()
            .collect::<Result<Vec<_>, SemanticCfwError>>()?;
        residuals.push(
            factors[CompactCfwMatrixRole::LeftMultiplicand.ordinal()]
                * factors[CompactCfwMatrixRole::RightMultiplicand.ordinal()]
                - factors[CompactCfwMatrixRole::Product.ordinal()],
        );
    }
    Ok(residuals)
}

fn semantic_cfw_verifier_transition(
    extended_prefix: &SemanticCfwTranscriptPrefix,
) -> Result<SemanticCfwVerifierTransition, SemanticCfwError> {
    if extended_prefix.joint_constraint_challenge.is_some() {
        if extended_prefix.final_message.is_none()
            || extended_prefix.round_challenges.len() != extended_prefix.round_polynomials.len()
        {
            return Err(SemanticCfwError::MalformedPrefix);
        }
        return Ok(SemanticCfwVerifierTransition::JointConstraint);
    }
    if extended_prefix.final_message.is_some()
        || extended_prefix.constraint_combining_challenge.is_none()
        || extended_prefix.round_challenges.len() != extended_prefix.round_polynomials.len()
    {
        return Err(SemanticCfwError::MalformedPrefix);
    }
    if extended_prefix.round_challenges.is_empty() {
        return Ok(SemanticCfwVerifierTransition::InitialRandomness);
    }
    Ok(SemanticCfwVerifierTransition::SumcheckRound {
        round_ordinal: extended_prefix.round_challenges.len() - 1,
    })
}

fn semantic_cfw_preceding_prefix(
    extended_prefix: &SemanticCfwTranscriptPrefix,
) -> Result<SemanticCfwTranscriptPrefix, SemanticCfwError> {
    let transition = semantic_cfw_verifier_transition(extended_prefix)?;
    let mut preceding = extended_prefix.clone();
    match transition {
        SemanticCfwVerifierTransition::InitialRandomness => {
            preceding.constraint_combining_challenge = None;
            preceding.equality_point.clear();
        }
        SemanticCfwVerifierTransition::SumcheckRound { .. } => {
            let _removed_challenge = preceding
                .round_challenges
                .pop()
                .ok_or(SemanticCfwError::MalformedPrefix)?;
        }
        SemanticCfwVerifierTransition::JointConstraint => {
            preceding.joint_constraint_challenge = None;
        }
    }
    Ok(preceding)
}

/// Executable CDHZ knowledge-state predicate for the CFW transcript prefix.
///
/// The empty and first prover prefixes use the input R1CS relation. Each
/// verifier challenge then selects a new masked-sumcheck state: transcript
/// endpoint checks remain sticky, while the current true reduction value is
/// derived independently from the production matrices, masks, and candidate
/// witness. The full transcript checks the actual generalized committed-code
/// output relation rather than re-requiring the input R1CS witness.
pub(super) fn semantic_cfw_kstate<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    prefix: Option<&SemanticCfwTranscriptPrefix>,
    witness: &SemanticCfwExtractedWitness,
) -> Result<bool, SemanticCfwError> {
    if !semantic_cfw_witness_material_matches(statement, witness)? {
        return Ok(false);
    }
    let Some(prefix) = prefix else {
        return semantic_r1cs_relation_holds(
            statement.matrices,
            statement.public_input,
            &witness.r1cs_witness,
        )
        .map_err(Into::into);
    };
    let geometry = CompactCfwGeometry::derive(statement.matrices.witness_length())?;
    validate_semantic_cfw_prefix_shape(geometry, prefix)?;
    if prefix.constraint_combining_challenge.is_none() {
        return Ok(semantic_cfw_code_relations_hold(statement, witness)?
            && semantic_r1cs_relation_holds(
                statement.matrices,
                statement.public_input,
                &witness.r1cs_witness,
            )?
            && PreparedCompactCfwProver::prepare(
                statement.matrices,
                statement.public_input,
                &witness.r1cs_witness,
                witness.mask_material.clone(),
            )?
            .auxiliary_target()
                == prefix.auxiliary_target);
    }
    if prefix.joint_constraint_challenge.is_some() {
        if !cfw_transcript_deterministically_accepts(statement, prefix)? {
            return Ok(false);
        }
        let output = semantic_cfw_output_relation_and_instance(statement, prefix)?;
        let output_witness = SemanticGeneralizedRelationWitness {
            source: witness.source_code_witness.clone(),
            masks: vec![
                witness.inner_mask_code_witness.clone(),
                witness.outer_mask_code_witness.clone(),
                witness.cross_epoch_mask_code_witness.clone(),
            ],
        };
        return semantic_generalized_relation_holds(&output.0, &output.1, &output_witness)
            .map_err(Into::into);
    }
    if !semantic_cfw_code_relations_hold(statement, witness)? {
        return Ok(false);
    }
    let completed_round_count = prefix.round_challenges.len();
    let supplied_round_count = prefix.round_polynomials.len();
    if supplied_round_count == 0 {
        return semantic_cfw_initial_post_state(statement, prefix, witness);
    }
    if supplied_round_count == completed_round_count.saturating_add(1) {
        let preceding_state = if completed_round_count == 0 {
            semantic_cfw_initial_post_state(statement, prefix, witness)?
        } else {
            semantic_cfw_round_post_state(statement, prefix, witness, completed_round_count)?
        };
        return Ok(preceding_state && cfw_sumcheck_endpoints_are_valid(prefix)?);
    }
    if supplied_round_count != completed_round_count {
        return Err(SemanticCfwError::MalformedPrefix);
    }
    let round_post_state =
        semantic_cfw_round_post_state(statement, prefix, witness, completed_round_count)?;
    if prefix.final_message.is_some() {
        return Ok(round_post_state
            && cfw_transcript_deterministically_accepts(statement, prefix)?
            && semantic_cfw_final_message_matches(statement, prefix, witness)?);
    }
    Ok(round_post_state)
}

fn semantic_cfw_final_message_matches<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    prefix: &SemanticCfwTranscriptPrefix,
    witness: &SemanticCfwExtractedWitness,
) -> Result<bool, SemanticCfwError> {
    let supplied = prefix
        .final_message
        .as_ref()
        .ok_or(SemanticCfwError::MalformedPrefix)?;
    let actual = compact_cfw_semantic_final_message(
        statement.matrices,
        statement.public_input,
        &witness.r1cs_witness,
        &witness.mask_material,
        &prefix.round_challenges,
    )?;
    Ok(supplied.outer_evaluations == actual.outer_evaluations()
        && supplied.final_values == actual.final_values())
}

fn semantic_cfw_witness_material_matches<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    witness: &SemanticCfwExtractedWitness,
) -> Result<bool, SemanticCfwError> {
    if witness
        .cross_epoch_mask_code_witness
        .coefficient_columns(&statement.cross_epoch_handoff.mask_code_relation.code)
        .is_err()
    {
        return Ok(false);
    }
    let geometry = CompactCfwGeometry::derive(statement.matrices.witness_length())?;
    let decoded_r1cs_witness = witness
        .source_code_witness
        .flattened_messages()
        .into_iter()
        .map(compact_challenge_from_production)
        .collect::<Vec<_>>();
    let inner_masks = match compact_mask_messages::<COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH>(
        &witness.inner_mask_code_witness,
        geometry.inner_mask_count(),
    ) {
        Ok(masks) => masks,
        Err(SemanticCfwError::MalformedStatement) => return Ok(false),
        Err(error) => return Err(error),
    };
    let outer_masks = match compact_mask_messages::<COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH>(
        &witness.outer_mask_code_witness,
        geometry.outer_mask_count(),
    ) {
        Ok(masks) => masks,
        Err(SemanticCfwError::MalformedStatement) => return Ok(false),
        Err(error) => return Err(error),
    };
    let decoded_mask_material =
        match CompactCfwMaskMaterial::from_canonical_messages(geometry, inner_masks, outer_masks) {
            Ok(material) => material,
            Err(CompactCfwError::InvalidMaskMaterial) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
    Ok(decoded_r1cs_witness == witness.r1cs_witness
        && decoded_mask_material == witness.mask_material)
}

fn semantic_cfw_code_relations_hold<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    witness: &SemanticCfwExtractedWitness,
) -> Result<bool, SemanticCfwError> {
    for (relation, instance, code_witness) in [
        (
            &statement.code_relations.source,
            &statement.committed_instances.source,
            &witness.source_code_witness,
        ),
        (
            &statement.code_relations.inner_masks,
            &statement.committed_instances.inner_masks,
            &witness.inner_mask_code_witness,
        ),
        (
            &statement.code_relations.outer_masks,
            &statement.committed_instances.outer_masks,
            &witness.outer_mask_code_witness,
        ),
    ] {
        match semantic_committed_code_relation_holds(relation, instance, code_witness) {
            Ok(true) => {}
            Ok(false) | Err(SemanticRelationError::MalformedWitness) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

fn semantic_cfw_initial_post_state<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    prefix: &SemanticCfwTranscriptPrefix,
    witness: &SemanticCfwExtractedWitness,
) -> Result<bool, SemanticCfwError> {
    let challenge = prefix
        .constraint_combining_challenge
        .ok_or(SemanticCfwError::MalformedPrefix)?;
    let actual_polynomial = compact_cfw_semantic_round_polynomial(
        statement.matrices,
        statement.public_input,
        &witness.r1cs_witness,
        &witness.mask_material,
        challenge,
        &prefix.equality_point,
        &[],
        0,
    )?;
    Ok(compact_polynomial_endpoint_sum(&actual_polynomial) == prefix.auxiliary_target)
}

fn semantic_cfw_round_post_state<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    prefix: &SemanticCfwTranscriptPrefix,
    witness: &SemanticCfwExtractedWitness,
    completed_round_count: usize,
) -> Result<bool, SemanticCfwError> {
    if completed_round_count == 0
        || prefix.round_polynomials.len() < completed_round_count
        || prefix.round_challenges.len() < completed_round_count
        || !cfw_sumcheck_endpoints_are_valid(prefix)?
    {
        return Ok(false);
    }
    let round_ordinal = completed_round_count - 1;
    let actual_polynomial = compact_cfw_semantic_round_polynomial(
        statement.matrices,
        statement.public_input,
        &witness.r1cs_witness,
        &witness.mask_material,
        prefix
            .constraint_combining_challenge
            .ok_or(SemanticCfwError::MalformedPrefix)?,
        &prefix.equality_point,
        &prefix.round_challenges[..round_ordinal],
        round_ordinal,
    )?;
    let challenge = prefix.round_challenges[round_ordinal];
    Ok(compact_polynomial_evaluation(&actual_polynomial, challenge)
        == compact_polynomial_evaluation(&prefix.round_polynomials[round_ordinal], challenge))
}

fn cfw_sumcheck_endpoints_are_valid(
    prefix: &SemanticCfwTranscriptPrefix,
) -> Result<bool, SemanticCfwError> {
    for (round_ordinal, polynomial) in prefix.round_polynomials.iter().enumerate() {
        let expected = if round_ordinal == 0 {
            prefix.auxiliary_target
        } else {
            let previous_challenge = *prefix
                .round_challenges
                .get(round_ordinal - 1)
                .ok_or(SemanticCfwError::MalformedPrefix)?;
            compact_polynomial_evaluation(
                prefix
                    .round_polynomials
                    .get(round_ordinal - 1)
                    .ok_or(SemanticCfwError::MalformedPrefix)?,
                previous_challenge,
            )
        };
        if compact_polynomial_endpoint_sum(polynomial) != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn compact_polynomial_endpoint_sum(
    coefficients: &[CompactChallengeField],
) -> CompactChallengeField {
    coefficients
        .first()
        .copied()
        .unwrap_or(CompactChallengeField::ZERO)
        + coefficients.iter().copied().sum::<CompactChallengeField>()
}

fn compact_polynomial_evaluation(
    coefficients: &[CompactChallengeField],
    point: CompactChallengeField,
) -> CompactChallengeField {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(CompactChallengeField::ZERO, |value, coefficient| {
            value * point + coefficient
        })
}

fn cfw_transcript_deterministically_accepts<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    prefix: &SemanticCfwTranscriptPrefix,
) -> Result<bool, SemanticCfwError> {
    let Some(final_message) = &prefix.final_message else {
        return Ok(false);
    };
    let transcript = CompactCfwTranscript::new(
        prefix.auxiliary_target,
        prefix.round_polynomials.clone(),
        final_message.outer_evaluations.clone(),
        final_message.final_values,
    );
    let joint_challenge = prefix
        .joint_constraint_challenge
        .unwrap_or(CompactChallengeField::ZERO);
    match verify_compact_cfw_transcript(
        statement.matrices,
        statement.public_input,
        &transcript,
        prefix
            .constraint_combining_challenge
            .ok_or(SemanticCfwError::MalformedPrefix)?,
        &prefix.equality_point,
        &prefix.round_challenges,
        joint_challenge,
    ) {
        Ok(_) => Ok(true),
        Err(
            CompactCfwError::SumcheckConsistency { .. }
            | CompactCfwError::FinalConsistency
            | CompactCfwError::InvalidFinalChallenge,
        ) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn semantic_cfw_output_relation_and_instance<Matrices: CompactCfwR1csMatrices>(
    statement: &SemanticCfwStatement<'_, Matrices>,
    prefix: &SemanticCfwTranscriptPrefix,
) -> Result<
    (
        GeneralizedCommittedRelation,
        SemanticGeneralizedRelationInstance,
    ),
    SemanticCfwError,
> {
    let geometry = CompactCfwGeometry::derive(statement.matrices.witness_length())?;
    validate_semantic_cfw_prefix_shape(geometry, prefix)?;
    let final_message = prefix
        .final_message
        .as_ref()
        .ok_or(SemanticCfwError::MalformedPrefix)?;
    let joint_challenge = prefix
        .joint_constraint_challenge
        .ok_or(SemanticCfwError::MalformedPrefix)?;

    let joint_weights = compact_cfw_zero_evader_weights(joint_challenge);
    let mut joint_source_covector = vec![CompactChallengeField::ZERO; geometry.witness_length()];
    statement
        .matrices
        .accumulate_weighted_witness_covector_at_row_point(
            &prefix.round_challenges,
            joint_weights,
            &mut joint_source_covector,
        )?;
    let mut joint_target = CompactChallengeField::ZERO;
    for matrix_role in CompactCfwMatrixRole::ALL {
        let public_contribution = statement.matrices.public_contribution_at_row_point(
            matrix_role,
            &prefix.round_challenges,
            statement.public_input,
        )?;
        joint_target += joint_weights[matrix_role.ordinal()]
            * (final_message.final_values[matrix_role.ordinal()] - public_contribution);
    }

    let inner_message_element_count = geometry
        .inner_mask_count()
        .checked_mul(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    let outer_message_element_count = geometry
        .outer_mask_count()
        .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    let cross_epoch_message_element_count = statement
        .cross_epoch_handoff
        .mask_code_relation
        .code
        .message_length
        .checked_mul(
            statement
                .cross_epoch_handoff
                .mask_code_relation
                .code
                .interleaving_width,
        )
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    let cross_epoch_source_covector =
        compact_vector_to_production(semantic_cross_epoch_prefix_covector(
            geometry.witness_length(),
            &statement.cross_epoch_handoff.point,
            statement
                .cross_epoch_handoff
                .copied_main_source_element_count,
        )?)?;
    let zero_source_covector =
        vec![ProofChallengeExtensionElement::ZERO; geometry.witness_length()];
    let zero_inner_covector =
        vec![ProofChallengeExtensionElement::ZERO; inner_message_element_count];
    let zero_outer_covector =
        vec![ProofChallengeExtensionElement::ZERO; outer_message_element_count];
    let mut main_opening_cross_epoch_covector =
        vec![ProofChallengeExtensionElement::ZERO; cross_epoch_message_element_count];
    main_opening_cross_epoch_covector[1] = ProofChallengeExtensionElement::ONE;
    let mut difference_cross_epoch_covector =
        vec![ProofChallengeExtensionElement::ZERO; cross_epoch_message_element_count];
    difference_cross_epoch_covector[0] = ProofChallengeExtensionElement::ONE;
    difference_cross_epoch_covector[1] = ProofChallengeExtensionElement::ONE.negate();
    let opening_claims = vec![
        SemanticGeneralizedLinearClaim {
            source_covector: cross_epoch_source_covector,
            mask_covectors: vec![
                zero_inner_covector.clone(),
                zero_outer_covector.clone(),
                main_opening_cross_epoch_covector,
            ],
            target: compact_challenge_to_production(
                statement.cross_epoch_handoff.masked_main_evaluation,
            )?,
        },
        SemanticGeneralizedLinearClaim {
            source_covector: zero_source_covector.clone(),
            mask_covectors: vec![
                zero_inner_covector.clone(),
                zero_outer_covector.clone(),
                difference_cross_epoch_covector,
            ],
            target: compact_challenge_to_production(statement.cross_epoch_handoff.mask_difference)?,
        },
    ];
    let mut joint_inner_covector = vec![CompactChallengeField::ZERO; inner_message_element_count];
    let inner_multiplier =
        CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER);
    for (round_ordinal, &point) in prefix.round_challenges.iter().enumerate() {
        for matrix_role in CompactCfwMatrixRole::ALL {
            let mask_ordinal = round_ordinal
                .checked_mul(COMPACT_CFW_MATRIX_COUNT)
                .and_then(|ordinal| ordinal.checked_add(matrix_role.ordinal()))
                .ok_or(SemanticCfwError::ArithmeticOverflow)?;
            let start = mask_ordinal
                .checked_mul(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
                .ok_or(SemanticCfwError::ArithmeticOverflow)?;
            let scale = inner_multiplier * joint_weights[matrix_role.ordinal()];
            for (destination, power) in joint_inner_covector
                [start..start + COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH]
                .iter_mut()
                .zip(compact_powers(point, COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH))
            {
                *destination = scale * power;
            }
        }
    }
    let mut claims = Vec::with_capacity(geometry.generalized_committed_relation_claim_count());
    claims.push(SemanticGeneralizedLinearClaim {
        source_covector: compact_vector_to_production(joint_source_covector)?,
        mask_covectors: vec![
            compact_vector_to_production(joint_inner_covector)?,
            zero_outer_covector.clone(),
            vec![ProofChallengeExtensionElement::ZERO; cross_epoch_message_element_count],
        ],
        target: compact_challenge_to_production(joint_target)?,
    });

    for inner_mask_ordinal in 0..geometry.inner_mask_count() {
        let start = inner_mask_ordinal
            .checked_mul(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
            .ok_or(SemanticCfwError::ArithmeticOverflow)?;
        for endpoint_ordinal in 0..COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT {
            let mut inner_covector =
                vec![ProofChallengeExtensionElement::ZERO; inner_message_element_count];
            if endpoint_ordinal == 0 {
                inner_covector[start] = ProofChallengeExtensionElement::ONE;
            } else {
                inner_covector[start..start + COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH]
                    .fill(ProofChallengeExtensionElement::ONE);
            }
            claims.push(SemanticGeneralizedLinearClaim {
                source_covector: vec![
                    ProofChallengeExtensionElement::ZERO;
                    geometry.witness_length()
                ],
                mask_covectors: vec![
                    inner_covector,
                    zero_outer_covector.clone(),
                    vec![ProofChallengeExtensionElement::ZERO; cross_epoch_message_element_count],
                ],
                target: ProofChallengeExtensionElement::ZERO,
            });
        }
    }
    for (outer_mask_ordinal, (&point, &target)) in prefix
        .round_challenges
        .iter()
        .zip(&final_message.outer_evaluations)
        .enumerate()
    {
        let start = outer_mask_ordinal
            .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
            .ok_or(SemanticCfwError::ArithmeticOverflow)?;
        let mut outer_covector =
            vec![ProofChallengeExtensionElement::ZERO; outer_message_element_count];
        outer_covector[start..start + COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH].copy_from_slice(
            &compact_vector_to_production(compact_powers(
                point,
                COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
            ))?,
        );
        claims.push(SemanticGeneralizedLinearClaim {
            source_covector: vec![ProofChallengeExtensionElement::ZERO; geometry.witness_length()],
            mask_covectors: vec![
                zero_inner_covector.clone(),
                outer_covector,
                vec![ProofChallengeExtensionElement::ZERO; cross_epoch_message_element_count],
            ],
            target: compact_challenge_to_production(target)?,
        });
    }
    if claims.len() != geometry.generalized_committed_relation_claim_count() {
        return Err(SemanticCfwError::MalformedStatement);
    }

    let relation = semantic_cfw_output_relation_descriptor(
        geometry,
        statement.code_relations,
        &statement.cross_epoch_handoff.mask_code_relation,
    )?;
    let instance = SemanticGeneralizedRelationInstance {
        source: statement.committed_instances.source.clone(),
        masks: vec![
            statement.committed_instances.inner_masks.clone(),
            statement.committed_instances.outer_masks.clone(),
            statement.cross_epoch_handoff.committed_instance.clone(),
        ],
        opening_claims,
        carried_reduction_claims: claims,
    };
    validate_generalized_relation_descriptor(&relation)?;
    Ok((relation, instance))
}

fn semantic_cfw_output_relation_descriptor(
    geometry: CompactCfwGeometry,
    code_relations: &SemanticCfwCodeRelations,
    cross_epoch_mask_relation: &CommittedMaskCodeRelation,
) -> Result<GeneralizedCommittedRelation, SemanticCfwError> {
    validate_semantic_cfw_code_relations(geometry, code_relations)?;
    if cross_epoch_mask_relation.role != super::MaskGroupRole::CrossEpochOpening
        || cross_epoch_mask_relation.code.message_length != 1
        || cross_epoch_mask_relation.code.interleaving_width != 2
    {
        return Err(SemanticCfwError::MalformedStatement);
    }
    semantic_code_geometry(&cross_epoch_mask_relation.code)?;
    let source_message_element_count = code_relations
        .source
        .message_length
        .checked_mul(code_relations.source.interleaving_width)
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    let source_hiding_element_count = code_relations
        .source
        .hiding_randomness_length
        .checked_mul(code_relations.source.interleaving_width)
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    let mask_codes = vec![
        CommittedMaskCodeRelation {
            role: super::MaskGroupRole::CfwInner,
            code: code_relations.inner_masks.clone(),
        },
        CommittedMaskCodeRelation {
            role: super::MaskGroupRole::CfwOuter,
            code: code_relations.outer_masks.clone(),
        },
        cross_epoch_mask_relation.clone(),
    ];
    let mask_message_element_count =
        mask_codes
            .iter()
            .try_fold(0_u64, |count, mask| -> Result<_, SemanticCfwError> {
                count
                    .checked_add(
                        mask.code
                            .message_length
                            .checked_mul(mask.code.interleaving_width)
                            .ok_or(SemanticCfwError::ArithmeticOverflow)?,
                    )
                    .ok_or(SemanticCfwError::ArithmeticOverflow)
            })?;
    let opening_evaluation_claim_count = 2_u64;
    let carried_reduction_claim_count =
        u64::try_from(geometry.generalized_committed_relation_claim_count())
            .map_err(|_| SemanticCfwError::ArithmeticOverflow)?;
    let relation = GeneralizedCommittedRelation {
        source_code: code_relations.source.clone(),
        mask_codes,
        source_message_element_count,
        source_hiding_element_count,
        mask_message_element_count,
        covector_extension_element_count: source_message_element_count
            .checked_add(1)
            .and_then(|count| count.checked_add(mask_message_element_count))
            .ok_or(SemanticCfwError::ArithmeticOverflow)?,
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
        claim_count: opening_evaluation_claim_count
            .checked_add(carried_reduction_claim_count)
            .ok_or(SemanticCfwError::ArithmeticOverflow)?,
    };
    validate_generalized_relation_descriptor(&relation)?;
    Ok(relation)
}

/// Independently derives the production prefix-opening covector. The
/// cross-epoch point uses the production multilinear convention in which the
/// first coordinate selects the most-significant Boolean branch. Only the
/// authenticated copied prefix is operative; the rest of the main CFW source
/// has zero coefficient.
fn semantic_cross_epoch_prefix_covector(
    source_message_element_count: usize,
    point: &[CompactChallengeField],
    copied_element_count: usize,
) -> Result<Vec<CompactChallengeField>, SemanticCfwError> {
    let point_domain_element_count = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| SemanticCfwError::ArithmeticOverflow)?)
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    if copied_element_count == 0
        || copied_element_count > point_domain_element_count
        || source_message_element_count
            != point_domain_element_count
                .checked_mul(2)
                .ok_or(SemanticCfwError::ArithmeticOverflow)?
    {
        return Err(SemanticCfwError::MalformedStatement);
    }

    let mut equality_covector = vec![CompactChallengeField::ONE];
    for &coordinate in point {
        let mut extended = Vec::with_capacity(
            equality_covector
                .len()
                .checked_mul(2)
                .ok_or(SemanticCfwError::ArithmeticOverflow)?,
        );
        for &partial_weight in &equality_covector {
            extended.push(partial_weight * (CompactChallengeField::ONE - coordinate));
            extended.push(partial_weight * coordinate);
        }
        equality_covector = extended;
    }
    if equality_covector.len() != point_domain_element_count {
        return Err(SemanticCfwError::MalformedStatement);
    }

    let mut source_covector = vec![CompactChallengeField::ZERO; source_message_element_count];
    source_covector[..copied_element_count]
        .copy_from_slice(&equality_covector[..copied_element_count]);
    Ok(source_covector)
}

fn compact_powers(value: CompactChallengeField, count: usize) -> Vec<CompactChallengeField> {
    let mut power = CompactChallengeField::ONE;
    (0..count)
        .map(|_| {
            let current = power;
            power *= value;
            current
        })
        .collect()
}

fn compact_vector_to_production(
    values: Vec<CompactChallengeField>,
) -> Result<Vec<ProofChallengeExtensionElement>, SemanticCfwError> {
    values
        .into_iter()
        .map(compact_challenge_to_production)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn validate_semantic_cfw_code_relations(
    geometry: CompactCfwGeometry,
    relations: &SemanticCfwCodeRelations,
) -> Result<(), SemanticCfwError> {
    let source_message_element_count = relations
        .source
        .message_length
        .checked_mul(relations.source.interleaving_width)
        .ok_or(SemanticCfwError::ArithmeticOverflow)?;
    if usize::try_from(source_message_element_count).ok() != Some(geometry.witness_length())
        || usize::try_from(relations.inner_masks.message_length).ok()
            != Some(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
        || usize::try_from(relations.inner_masks.interleaving_width).ok()
            != Some(geometry.inner_mask_count())
        || usize::try_from(relations.outer_masks.message_length).ok()
            != Some(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
        || usize::try_from(relations.outer_masks.interleaving_width).ok()
            != Some(geometry.outer_mask_count())
    {
        return Err(SemanticCfwError::MalformedStatement);
    }
    semantic_code_geometry(&relations.source)?;
    semantic_code_geometry(&relations.inner_masks)?;
    semantic_code_geometry(&relations.outer_masks)?;
    Ok(())
}

fn validate_semantic_cfw_cross_epoch_handoff(
    geometry: CompactCfwGeometry,
    handoff: &SemanticCfwCrossEpochHandoff,
) -> Result<(), SemanticCfwError> {
    if handoff.mask_code_relation.role != super::MaskGroupRole::CrossEpochOpening
        || handoff.mask_code_relation.code.message_length != 1
        || handoff.mask_code_relation.code.interleaving_width != 2
        || handoff.masked_pre_challenge_evaluation
            - handoff.masked_main_evaluation
            - handoff.mask_difference
            != CompactChallengeField::ZERO
    {
        return Err(SemanticCfwError::MalformedStatement);
    }
    semantic_code_geometry(&handoff.mask_code_relation.code)?;
    let block_length = usize::try_from(handoff.mask_code_relation.code.block_length)
        .map_err(|_| SemanticCfwError::ArithmeticOverflow)?;
    if handoff.committed_instance.received_rows.len() != block_length
        || handoff
            .committed_instance
            .received_rows
            .iter()
            .any(|row| row.len() != 2)
    {
        return Err(SemanticCfwError::MalformedStatement);
    }
    semantic_cross_epoch_prefix_covector(
        geometry.witness_length(),
        &handoff.point,
        handoff.copied_main_source_element_count,
    )?;
    Ok(())
}

fn validate_semantic_cfw_prefix_shape(
    geometry: CompactCfwGeometry,
    prefix: &SemanticCfwTranscriptPrefix,
) -> Result<(), SemanticCfwError> {
    let round_count = geometry.sumcheck_round_count();
    let has_initial_challenge = prefix.constraint_combining_challenge.is_some();
    let final_message_is_present = prefix.final_message.is_some();
    if (!has_initial_challenge
        && (!prefix.equality_point.is_empty()
            || !prefix.round_polynomials.is_empty()
            || !prefix.round_challenges.is_empty()
            || final_message_is_present
            || prefix.joint_constraint_challenge.is_some()))
        || (has_initial_challenge && prefix.equality_point.len() != round_count)
        || prefix.round_polynomials.len() > round_count
        || prefix.round_challenges.len() > prefix.round_polynomials.len()
        || prefix.round_polynomials.len() > prefix.round_challenges.len().saturating_add(1)
        || (final_message_is_present
            && (prefix.round_polynomials.len() != round_count
                || prefix.round_challenges.len() != round_count))
        || (prefix.joint_constraint_challenge.is_some() && !final_message_is_present)
    {
        return Err(SemanticCfwError::MalformedPrefix);
    }
    if let Some(final_message) = &prefix.final_message
        && final_message.outer_evaluations.len() != geometry.outer_mask_count()
    {
        return Err(SemanticCfwError::MalformedPrefix);
    }
    Ok(())
}

fn compact_mask_messages<const MESSAGE_LENGTH: usize>(
    witness: &SemanticCommittedCodeWitness,
    expected_mask_count: usize,
) -> Result<Vec<[CompactChallengeField; MESSAGE_LENGTH]>, SemanticCfwError> {
    if witness.message_columns.len() != expected_mask_count
        || witness
            .message_columns
            .iter()
            .any(|message| message.len() != MESSAGE_LENGTH)
    {
        return Err(SemanticCfwError::MalformedStatement);
    }
    witness
        .message_columns
        .iter()
        .map(|message| {
            message
                .iter()
                .copied()
                .map(compact_challenge_from_production)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| SemanticCfwError::MalformedStatement)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::{CommittedMaskCodeRelation, MaskGroupRole};
    use super::*;
    use crate::bgv::proof_suite::ProofBaseFieldElement;
    use crate::bgv::proof_suite::compact_cfw::compact_challenge_from_production;
    use p3_field::{Field, PrimeCharacteristicRing};

    fn field(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(value).expect("small canonical field element"),
        )
    }

    fn committed_code_relation(
        message_length: u64,
        hiding_randomness_length: u64,
        block_length: u64,
        interleaving_width: u64,
    ) -> CommittedCodeRelation {
        CommittedCodeRelation {
            message_length,
            hiding_randomness_length,
            block_length,
            interleaving_width,
        }
    }

    fn code_fixture(
        relation: &CommittedCodeRelation,
        first_coefficient: u64,
    ) -> (SemanticCommittedCodeInstance, SemanticCommittedCodeWitness) {
        let message_length = usize::try_from(relation.message_length).unwrap();
        let hiding_randomness_length = usize::try_from(relation.hiding_randomness_length).unwrap();
        let interleaving_width = usize::try_from(relation.interleaving_width).unwrap();
        let message_columns = (0..interleaving_width)
            .map(|column_ordinal| {
                (0..message_length)
                    .map(|coefficient_ordinal| {
                        field(
                            first_coefficient
                                + u64::try_from(column_ordinal * 11 + coefficient_ordinal).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let hiding_randomness_columns = (0..interleaving_width)
            .map(|column_ordinal| {
                (0..hiding_randomness_length)
                    .map(|coefficient_ordinal| {
                        field(
                            first_coefficient
                                + 41
                                + u64::try_from(column_ordinal * 7 + coefficient_ordinal).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let witness = SemanticCommittedCodeWitness {
            message_columns,
            hiding_randomness_columns,
        };
        let received_rows = encode_canonical_interleaved_reed_solomon(
            semantic_code_geometry(relation).unwrap(),
            &witness.coefficient_columns(relation).unwrap(),
        )
        .unwrap();
        (SemanticCommittedCodeInstance { received_rows }, witness)
    }

    fn code_fixture_from_messages(
        relation: &CommittedCodeRelation,
        message_columns: Vec<Vec<ProofChallengeExtensionElement>>,
        first_randomness_coefficient: u64,
    ) -> (SemanticCommittedCodeInstance, SemanticCommittedCodeWitness) {
        let hiding_randomness_length = usize::try_from(relation.hiding_randomness_length).unwrap();
        let interleaving_width = usize::try_from(relation.interleaving_width).unwrap();
        assert_eq!(message_columns.len(), interleaving_width);
        let hiding_randomness_columns = (0..interleaving_width)
            .map(|column_ordinal| {
                (0..hiding_randomness_length)
                    .map(|coefficient_ordinal| {
                        field(
                            first_randomness_coefficient
                                + u64::try_from(column_ordinal * 17 + coefficient_ordinal).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let witness = SemanticCommittedCodeWitness {
            message_columns,
            hiding_randomness_columns,
        };
        let received_rows = encode_canonical_interleaved_reed_solomon(
            semantic_code_geometry(relation).unwrap(),
            &witness.coefficient_columns(relation).unwrap(),
        )
        .unwrap();
        (SemanticCommittedCodeInstance { received_rows }, witness)
    }

    fn claim_for_witness(
        witness: &SemanticGeneralizedRelationWitness,
        source_weight: u64,
        mask_weights: &[u64],
    ) -> SemanticGeneralizedLinearClaim {
        let source_message = witness.source.flattened_messages();
        let mask_messages = witness
            .masks
            .iter()
            .map(SemanticCommittedCodeWitness::flattened_messages)
            .collect::<Vec<_>>();
        let source_covector = vec![field(source_weight); source_message.len()];
        let mask_covectors = mask_messages
            .iter()
            .zip(mask_weights)
            .map(|(message, weight)| vec![field(*weight); message.len()])
            .collect::<Vec<_>>();
        let target = source_covector
            .iter()
            .zip(&source_message)
            .map(|(coefficient, value)| coefficient.multiply(*value))
            .chain(
                mask_covectors
                    .iter()
                    .zip(&mask_messages)
                    .flat_map(|(covector, message)| {
                        covector
                            .iter()
                            .zip(message)
                            .map(|(coefficient, value)| coefficient.multiply(*value))
                    }),
            )
            .fold(ProofChallengeExtensionElement::ZERO, |sum, value| {
                sum.add(value)
            });
        SemanticGeneralizedLinearClaim {
            source_covector,
            mask_covectors,
            target,
        }
    }

    #[test]
    fn executable_generalized_relation_extracts_codes_and_recomputes_every_claim() {
        let source_relation = committed_code_relation(2, 1, 8, 2);
        let mask_relation = committed_code_relation(1, 1, 8, 1);
        let relation = GeneralizedCommittedRelation {
            source_code: source_relation.clone(),
            mask_codes: vec![CommittedMaskCodeRelation {
                role: MaskGroupRole::CfwInner,
                code: mask_relation.clone(),
            }],
            source_message_element_count: 4,
            source_hiding_element_count: 2,
            mask_message_element_count: 1,
            covector_extension_element_count: 6,
            opening_evaluation_claim_count: 1,
            carried_reduction_claim_count: 1,
            claim_count: 2,
        };
        let (mut source_instance, source_witness) = code_fixture(&source_relation, 3);
        let (mut mask_instance, mask_witness) = code_fixture(&mask_relation, 71);
        source_instance.received_rows[1][0] = source_instance.received_rows[1][0].add(field(97));
        source_instance.received_rows[6][1] = source_instance.received_rows[6][1].add(field(101));
        mask_instance.received_rows[2][0] = mask_instance.received_rows[2][0].add(field(103));
        let witness = SemanticGeneralizedRelationWitness {
            source: source_witness,
            masks: vec![mask_witness],
        };
        let opening_claim = claim_for_witness(&witness, 2, &[3]);
        let carried_claim = claim_for_witness(&witness, 5, &[7]);
        let instance = SemanticGeneralizedRelationInstance {
            source: source_instance,
            masks: vec![mask_instance],
            opening_claims: vec![opening_claim],
            carried_reduction_claims: vec![carried_claim],
        };

        assert!(semantic_generalized_relation_holds(&relation, &instance, &witness).unwrap());
        let extraction = extract_semantic_generalized_relation_witness(&relation, &instance)
            .expect("the unique decoder extracts the generalized relation witness");
        assert_eq!(extraction.witness, witness);
        assert!(extraction.field_operation_count > 0);

        let mut changed_target = instance.clone();
        changed_target.opening_claims[0].target =
            changed_target.opening_claims[0].target.add(field(1));
        assert!(
            !semantic_generalized_relation_holds(&relation, &changed_target, &witness).unwrap()
        );
        assert_eq!(
            extract_semantic_generalized_relation_witness(&relation, &changed_target),
            Err(SemanticRelationError::RelationNotSatisfied)
        );

        let mut substituted_witness = witness.clone();
        substituted_witness.source.message_columns[0][0] =
            substituted_witness.source.message_columns[0][0].add(field(1));
        assert!(
            !semantic_generalized_relation_holds(&relation, &instance, &substituted_witness)
                .unwrap()
        );

        let mut malformed_witness = witness;
        malformed_witness.source.message_columns[0].pop();
        assert_eq!(
            semantic_generalized_relation_holds(&relation, &instance, &malformed_witness),
            Ok(false)
        );
    }

    struct SmallR1csMatrices;

    impl CompactCfwR1csMatrices for SmallR1csMatrices {
        fn witness_length(&self) -> usize {
            2
        }

        fn evaluate_assignment_rows(
            &self,
            matrix_role: CompactCfwMatrixRole,
            public_input: &[CompactChallengeField],
            witness: &[CompactChallengeField],
        ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
            if public_input.len() != 2 || witness.len() != 2 {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            Ok(match matrix_role {
                CompactCfwMatrixRole::LeftMultiplicand => vec![
                    public_input[0] + witness[0],
                    public_input[1],
                    witness[0],
                    public_input[0],
                ],
                CompactCfwMatrixRole::RightMultiplicand => vec![
                    witness[1],
                    witness[0] + witness[1],
                    public_input[1],
                    witness[1],
                ],
                CompactCfwMatrixRole::Product => vec![
                    CompactChallengeField::from_u64(7) * witness[1],
                    CompactChallengeField::from_u64(3) * (witness[0] + witness[1]),
                    CompactChallengeField::from_u64(3) * witness[0],
                    CompactChallengeField::from_u64(2) * witness[1],
                ],
            })
        }

        fn public_contribution_at_row_point(
            &self,
            matrix_role: CompactCfwMatrixRole,
            row_point: &[CompactChallengeField],
            public_input: &[CompactChallengeField],
        ) -> Result<CompactChallengeField, CompactCfwError> {
            if row_point.len() != 2 || public_input.len() != 2 {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            let rows = self.evaluate_assignment_rows(
                matrix_role,
                public_input,
                &[CompactChallengeField::ZERO; 2],
            )?;
            Ok(rows
                .into_iter()
                .enumerate()
                .map(|(row_ordinal, value)| {
                    let weight = row_point.iter().enumerate().fold(
                        CompactChallengeField::ONE,
                        |weight, (coordinate_ordinal, coordinate)| {
                            if (row_ordinal >> coordinate_ordinal) & 1 == 0 {
                                weight * (CompactChallengeField::ONE - *coordinate)
                            } else {
                                weight * *coordinate
                            }
                        },
                    );
                    weight * value
                })
                .sum())
        }

        fn accumulate_weighted_witness_covector_at_row_point(
            &self,
            row_point: &[CompactChallengeField],
            matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
            destination: &mut [CompactChallengeField],
        ) -> Result<(), CompactCfwError> {
            if row_point.len() != 2 || destination.len() != 2 {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            for matrix_role in CompactCfwMatrixRole::ALL {
                for witness_ordinal in 0..destination.len() {
                    let mut basis_witness = [CompactChallengeField::ZERO; 2];
                    basis_witness[witness_ordinal] = CompactChallengeField::ONE;
                    let rows = self.evaluate_assignment_rows(
                        matrix_role,
                        &[CompactChallengeField::ZERO; 2],
                        &basis_witness,
                    )?;
                    let coefficient = rows
                        .into_iter()
                        .enumerate()
                        .map(|(row_ordinal, value)| {
                            let row_weight = row_point.iter().enumerate().fold(
                                CompactChallengeField::ONE,
                                |weight, (coordinate_ordinal, coordinate)| {
                                    if (row_ordinal >> coordinate_ordinal) & 1 == 0 {
                                        weight * (CompactChallengeField::ONE - *coordinate)
                                    } else {
                                        weight * *coordinate
                                    }
                                },
                            );
                            row_weight * value
                        })
                        .sum::<CompactChallengeField>();
                    destination[witness_ordinal] +=
                        matrix_role_weights[matrix_role.ordinal()] * coefficient;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn executable_input_relation_recomputes_rows_and_refuses_wrong_shapes() {
        let public_input = [
            compact_challenge_from_production(field(2)),
            compact_challenge_from_production(field(3)),
        ];
        let witness = [
            compact_challenge_from_production(field(5)),
            compact_challenge_from_production(field(7)),
        ];
        assert!(semantic_r1cs_relation_holds(&SmallR1csMatrices, &public_input, &witness).unwrap());
        assert!(
            !semantic_r1cs_relation_holds(&SmallR1csMatrices, &public_input[..1], &witness)
                .unwrap()
        );
    }

    #[test]
    fn cfw_kstate_and_errbr_execute_every_canonical_prefix_message() {
        let source_relation = committed_code_relation(2, 1, 8, 1);
        let inner_mask_relation = committed_code_relation(4, 1, 8, 6);
        let outer_mask_relation = committed_code_relation(8, 1, 16, 2);
        let cross_epoch_mask_relation = CommittedMaskCodeRelation {
            role: MaskGroupRole::CrossEpochOpening,
            code: committed_code_relation(1, 1, 8, 2),
        };
        let code_relations = SemanticCfwCodeRelations {
            source: source_relation.clone(),
            inner_masks: inner_mask_relation.clone(),
            outer_masks: outer_mask_relation.clone(),
        };
        let (source_instance, source_code_witness) =
            code_fixture_from_messages(&source_relation, vec![vec![field(5), field(7)]], 31);
        let inner_messages = (0..6_u64)
            .map(|mask_ordinal| {
                let first = field(41 + mask_ordinal * 3);
                let second = field(43 + mask_ordinal * 3);
                vec![
                    ProofChallengeExtensionElement::ZERO,
                    first,
                    second,
                    first.add(second).negate(),
                ]
            })
            .collect::<Vec<_>>();
        let (inner_mask_instance, inner_mask_code_witness) =
            code_fixture_from_messages(&inner_mask_relation, inner_messages, 101);
        let outer_messages = (0..2_u64)
            .map(|mask_ordinal| {
                (0..8_u64)
                    .map(|coefficient_ordinal| field(151 + mask_ordinal * 11 + coefficient_ordinal))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let (outer_mask_instance, outer_mask_code_witness) =
            code_fixture_from_messages(&outer_mask_relation, outer_messages, 211);
        let pre_challenge_mask = compact_challenge_from_production(field(307));
        let main_mask = compact_challenge_from_production(field(311));
        let copied_main_evaluation = compact_challenge_from_production(field(5));
        let (cross_epoch_mask_instance, cross_epoch_mask_code_witness) = code_fixture_from_messages(
            &cross_epoch_mask_relation.code,
            vec![vec![field(307)], vec![field(311)]],
            331,
        );
        let cross_epoch_handoff = SemanticCfwCrossEpochHandoff {
            mask_code_relation: cross_epoch_mask_relation,
            committed_instance: cross_epoch_mask_instance,
            point: Vec::new(),
            copied_main_source_element_count: 1,
            masked_pre_challenge_evaluation: copied_main_evaluation + pre_challenge_mask,
            masked_main_evaluation: copied_main_evaluation + main_mask,
            mask_difference: pre_challenge_mask - main_mask,
        };
        let committed_instances = SemanticCfwCommittedInstances {
            source: source_instance,
            inner_masks: inner_mask_instance,
            outer_masks: outer_mask_instance,
        };
        let public_input = [
            compact_challenge_from_production(field(2)),
            compact_challenge_from_production(field(3)),
        ];
        let matrices = SmallR1csMatrices;
        let expected_extraction = semantic_cfw_witness_from_code_witnesses(
            CompactCfwGeometry::derive(matrices.witness_length()).unwrap(),
            source_code_witness,
            inner_mask_code_witness,
            outer_mask_code_witness,
            cross_epoch_mask_code_witness.clone(),
        )
        .expect("the focused committed witnesses define the CFW witness");
        let constraint_combining_challenge = compact_challenge_from_production(field(13));
        let equality_point = vec![
            compact_challenge_from_production(field(17)),
            compact_challenge_from_production(field(19)),
        ];
        let round_challenges = vec![
            compact_challenge_from_production(field(23)),
            compact_challenge_from_production(field(29)),
        ];
        let prepared = PreparedCompactCfwProver::prepare(
            &matrices,
            &public_input,
            &expected_extraction.r1cs_witness,
            expected_extraction.mask_material.clone(),
        )
        .expect("small CFW witness prepares");
        let auxiliary_target = prepared.auxiliary_target();
        let relation_plan_hash = [0x5a; 64];
        let canonical_public_input_binding = [0x6a; 64];
        let initial_verifier_prefix = CompactCfwInitialVerifierPrefix::for_focused_semantic_test(
            relation_plan_hash,
            canonical_public_input_binding,
            auxiliary_target,
            constraint_combining_challenge,
            equality_point.clone(),
        );
        let statement = SemanticCfwStatement::new(
            SemanticCfwInitialStatementBinding::new(
                relation_plan_hash,
                canonical_public_input_binding,
                &initial_verifier_prefix,
            ),
            &matrices,
            &public_input,
            &code_relations,
            &committed_instances,
            &cross_epoch_handoff,
        )
        .expect("small production-shaped CFW statement derives");
        let decoding = semantic_cfw_errbr(&statement, cross_epoch_mask_code_witness.clone())
            .expect("deterministic CFW extractor decodes every committed oracle");
        assert_eq!(statement.relation_plan_hash(), [0x5a; 64]);
        assert_eq!(statement.implicit_tuple_dimensions(), (0, 0));
        assert!(decoding.field_operation_count > 0);
        let extraction = decoding.witness;
        assert_eq!(extraction, expected_extraction);
        assert!(semantic_cfw_kstate(&statement, None, &extraction).unwrap());

        let mut prover = prepared
            .begin(constraint_combining_challenge, equality_point.clone())
            .expect("small CFW prover begins");
        let mut round_polynomials = Vec::new();
        for round_challenge in &round_challenges {
            round_polynomials.push(
                prover
                    .next_round_polynomial()
                    .expect("small CFW round polynomial derives"),
            );
            prover
                .bind_round_challenge(*round_challenge)
                .expect("small CFW round challenge binds");
        }
        let finish = prover.finish().expect("small CFW prover finishes");

        let initial_prover_prefix = SemanticCfwTranscriptPrefix {
            auxiliary_target,
            constraint_combining_challenge: None,
            equality_point: Vec::new(),
            round_polynomials: Vec::new(),
            round_challenges: Vec::new(),
            final_message: None,
            joint_constraint_challenge: None,
        };
        assert!(
            semantic_cfw_kstate(&statement, Some(&initial_prover_prefix), &extraction).unwrap()
        );

        let initial_verifier_prefix = SemanticCfwTranscriptPrefix {
            auxiliary_target,
            constraint_combining_challenge: Some(constraint_combining_challenge),
            equality_point: equality_point.clone(),
            round_polynomials: Vec::new(),
            round_challenges: Vec::new(),
            final_message: None,
            joint_constraint_challenge: None,
        };
        assert!(
            semantic_cfw_kstate(&statement, Some(&initial_verifier_prefix), &extraction).unwrap()
        );
        let initial_transition_extraction =
            semantic_cfw_errbr_at_verifier_move(&statement, &initial_verifier_prefix, &extraction)
                .expect("the initial verifier-move extractor executes");
        assert_eq!(
            initial_transition_extraction.witness,
            Some(extraction.clone())
        );
        assert!(initial_transition_extraction.field_operation_count > 0);
        assert_eq!(
            semantic_cfw_bad_transition(&statement, &initial_verifier_prefix, &extraction,)
                .expect("the honest initial transition is classified"),
            None
        );

        let dispatcher_cfw_statement =
            semantic_execution::SemanticVerifierMoveStatement::Cfw(&statement);
        let dispatcher_cfw_witness =
            semantic_execution::SemanticKnowledgeWitness::Cfw(extraction.clone());
        let initial_descriptor =
            semantic_execution::SemanticFactorOneMoveDescriptor::for_focused_test(
                semantic_execution::SemanticVerifierMoveOwner::CfwInitialRandomness,
            );
        let dispatcher_initial_predecessor =
            semantic_execution::SemanticVerifierMovePrefix::Cfw(initial_prover_prefix.clone());
        let dispatcher_initial_extended =
            semantic_execution::SemanticVerifierMovePrefix::Cfw(initial_verifier_prefix.clone());
        assert!(
            semantic_execution::semantic_factor_one_kstate(
                &initial_descriptor,
                &dispatcher_cfw_statement,
                &dispatcher_initial_predecessor,
                &dispatcher_cfw_witness,
            )
            .unwrap()
        );
        assert!(
            semantic_execution::semantic_factor_one_kstate(
                &initial_descriptor,
                &dispatcher_cfw_statement,
                &dispatcher_initial_extended,
                &dispatcher_cfw_witness,
            )
            .unwrap()
        );
        let dispatcher_initial_extraction = semantic_execution::semantic_factor_one_errbr(
            &initial_descriptor,
            &dispatcher_cfw_statement,
            &dispatcher_initial_extended,
            &dispatcher_cfw_witness,
        )
        .unwrap();
        assert_eq!(
            dispatcher_initial_extraction.witness,
            Some(dispatcher_cfw_witness.clone())
        );
        assert_eq!(
            dispatcher_initial_extraction.field_operation_count,
            initial_transition_extraction.field_operation_count
        );
        assert_eq!(
            semantic_execution::semantic_factor_one_bad_transition(
                &initial_descriptor,
                &dispatcher_cfw_statement,
                &dispatcher_initial_extended,
                &dispatcher_cfw_witness,
            )
            .unwrap(),
            None
        );

        for completed_round_count in 0..round_polynomials.len() {
            let prover_prefix = SemanticCfwTranscriptPrefix {
                auxiliary_target,
                constraint_combining_challenge: Some(constraint_combining_challenge),
                equality_point: equality_point.clone(),
                round_polynomials: round_polynomials[..=completed_round_count].to_vec(),
                round_challenges: round_challenges[..completed_round_count].to_vec(),
                final_message: None,
                joint_constraint_challenge: None,
            };
            assert!(semantic_cfw_kstate(&statement, Some(&prover_prefix), &extraction).unwrap());

            let verifier_prefix = SemanticCfwTranscriptPrefix {
                round_challenges: round_challenges[..=completed_round_count].to_vec(),
                ..prover_prefix.clone()
            };
            assert!(semantic_cfw_kstate(&statement, Some(&verifier_prefix), &extraction).unwrap());
            let round_descriptor =
                semantic_execution::SemanticFactorOneMoveDescriptor::for_focused_test(
                    semantic_execution::SemanticVerifierMoveOwner::CfwSumcheckRound {
                        round_ordinal: u32::try_from(completed_round_count).unwrap(),
                    },
                );
            let dispatcher_round_predecessor =
                semantic_execution::SemanticVerifierMovePrefix::Cfw(prover_prefix);
            let dispatcher_round_extended =
                semantic_execution::SemanticVerifierMovePrefix::Cfw(verifier_prefix);
            assert!(
                semantic_execution::semantic_factor_one_kstate(
                    &round_descriptor,
                    &dispatcher_cfw_statement,
                    &dispatcher_round_predecessor,
                    &dispatcher_cfw_witness,
                )
                .unwrap()
            );
            assert!(
                semantic_execution::semantic_factor_one_kstate(
                    &round_descriptor,
                    &dispatcher_cfw_statement,
                    &dispatcher_round_extended,
                    &dispatcher_cfw_witness,
                )
                .unwrap()
            );
            assert_eq!(
                semantic_execution::semantic_factor_one_errbr(
                    &round_descriptor,
                    &dispatcher_cfw_statement,
                    &dispatcher_round_extended,
                    &dispatcher_cfw_witness,
                )
                .unwrap()
                .witness,
                Some(dispatcher_cfw_witness.clone())
            );
            assert_eq!(
                semantic_execution::semantic_factor_one_bad_transition(
                    &round_descriptor,
                    &dispatcher_cfw_statement,
                    &dispatcher_round_extended,
                    &dispatcher_cfw_witness,
                )
                .unwrap(),
                None
            );
        }

        let final_message = SemanticCfwFinalMessage {
            outer_evaluations: finish.outer_evaluations().to_vec(),
            final_values: finish.final_values(),
        };
        let final_prover_prefix = SemanticCfwTranscriptPrefix {
            auxiliary_target,
            constraint_combining_challenge: Some(constraint_combining_challenge),
            equality_point: equality_point.clone(),
            round_polynomials: round_polynomials.clone(),
            round_challenges: round_challenges.clone(),
            final_message: Some(final_message.clone()),
            joint_constraint_challenge: None,
        };
        assert!(semantic_cfw_kstate(&statement, Some(&final_prover_prefix), &extraction).unwrap());

        let prefix = SemanticCfwTranscriptPrefix {
            auxiliary_target,
            constraint_combining_challenge: Some(constraint_combining_challenge),
            equality_point,
            round_polynomials,
            round_challenges,
            final_message: Some(final_message),
            joint_constraint_challenge: Some(compact_challenge_from_production(field(37))),
        };
        assert!(semantic_cfw_kstate(&statement, Some(&prefix), &extraction).unwrap());
        let (output_relation, output_instance) =
            semantic_cfw_output_relation_and_instance(&statement, &prefix)
                .expect("the exact unbatched CFW-to-WHIR relation derives");
        assert_eq!(
            output_relation
                .mask_codes
                .iter()
                .map(|mask| mask.role)
                .collect::<Vec<_>>(),
            vec![
                MaskGroupRole::CfwInner,
                MaskGroupRole::CfwOuter,
                MaskGroupRole::CrossEpochOpening,
            ]
        );
        assert_eq!(output_relation.opening_evaluation_claim_count, 2);
        assert_eq!(
            output_relation.carried_reduction_claim_count,
            u64::try_from(
                CompactCfwGeometry::derive(matrices.witness_length())
                    .unwrap()
                    .generalized_committed_relation_claim_count()
            )
            .unwrap()
        );
        assert_eq!(
            output_relation.claim_count,
            output_relation.opening_evaluation_claim_count
                + output_relation.carried_reduction_claim_count
        );
        let output_witness = SemanticGeneralizedRelationWitness {
            source: extraction.source_code_witness.clone(),
            masks: vec![
                extraction.inner_mask_code_witness.clone(),
                extraction.outer_mask_code_witness.clone(),
                extraction.cross_epoch_mask_code_witness.clone(),
            ],
        };
        assert!(
            semantic_generalized_relation_holds(
                &output_relation,
                &output_instance,
                &output_witness,
            )
            .unwrap()
        );
        let pre_challenge_opening_statement =
            semantic_whir::SemanticWhirOpeningBatchingStatement::new(
                output_relation.clone(),
                output_instance.clone(),
            )
            .expect("the independent opening-batching statement derives");
        let combined_statement = semantic_composition::SemanticCfwAndPreWhirOpeningStatement::new(
            &statement,
            &pre_challenge_opening_statement,
        );
        let combined_predecessor_prefix =
            semantic_composition::SemanticCfwAndPreWhirOpeningPrefix {
                cfw: final_prover_prefix.clone(),
                pre_challenge_opening: semantic_whir::SemanticWhirOpeningBatchingPrefix {
                    batching_challenge: None,
                },
            };
        let combined_extended_prefix = semantic_composition::SemanticCfwAndPreWhirOpeningPrefix {
            cfw: prefix.clone(),
            pre_challenge_opening: semantic_whir::SemanticWhirOpeningBatchingPrefix {
                batching_challenge: Some(field(347)),
            },
        };
        let combined_witness = semantic_composition::SemanticCfwAndPreWhirOpeningWitness {
            cfw: extraction.clone(),
            pre_challenge_whir: output_witness.clone(),
        };
        assert!(
            semantic_composition::semantic_cfw_and_pre_whir_opening_kstate(
                &combined_statement,
                &combined_predecessor_prefix,
                &combined_witness,
            )
            .unwrap()
        );
        assert!(
            semantic_composition::semantic_cfw_and_pre_whir_opening_kstate(
                &combined_statement,
                &combined_extended_prefix,
                &combined_witness,
            )
            .unwrap()
        );
        let combined_extraction = semantic_composition::semantic_cfw_and_pre_whir_opening_errbr(
            &combined_statement,
            &combined_extended_prefix,
            &combined_witness,
        )
        .expect("both backward extractors execute for the atomic verifier move");
        assert_eq!(combined_extraction.witness, Some(combined_witness.clone()));
        assert_eq!(combined_extraction.field_operation_count, 0);
        assert_eq!(
            semantic_composition::semantic_cfw_and_pre_whir_opening_bad_transition(
                &combined_statement,
                &combined_extended_prefix,
                &combined_witness,
            )
            .unwrap(),
            None
        );
        let dispatcher_combined_descriptor =
            semantic_execution::SemanticFactorOneMoveDescriptor::for_focused_test(
                semantic_execution::SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            );
        let dispatcher_combined_statement =
            semantic_execution::SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
                cfw: &statement,
                pre_challenge_opening: &pre_challenge_opening_statement,
            };
        let dispatcher_combined_predecessor =
            semantic_execution::SemanticVerifierMovePrefix::CfwAndPreWhirOpening(
                combined_predecessor_prefix.clone(),
            );
        let dispatcher_combined_extended =
            semantic_execution::SemanticVerifierMovePrefix::CfwAndPreWhirOpening(
                combined_extended_prefix.clone(),
            );
        let dispatcher_combined_witness =
            semantic_execution::SemanticKnowledgeWitness::CfwAndPreWhirOpening(
                combined_witness.clone(),
            );
        assert!(
            semantic_execution::semantic_factor_one_kstate(
                &dispatcher_combined_descriptor,
                &dispatcher_combined_statement,
                &dispatcher_combined_predecessor,
                &dispatcher_combined_witness,
            )
            .unwrap()
        );
        assert!(
            semantic_execution::semantic_factor_one_kstate(
                &dispatcher_combined_descriptor,
                &dispatcher_combined_statement,
                &dispatcher_combined_extended,
                &dispatcher_combined_witness,
            )
            .unwrap()
        );
        assert_eq!(
            semantic_execution::semantic_factor_one_errbr(
                &dispatcher_combined_descriptor,
                &dispatcher_combined_statement,
                &dispatcher_combined_extended,
                &dispatcher_combined_witness,
            )
            .unwrap()
            .witness,
            Some(dispatcher_combined_witness.clone())
        );
        assert_eq!(
            semantic_execution::semantic_factor_one_bad_transition(
                &dispatcher_combined_descriptor,
                &dispatcher_combined_statement,
                &dispatcher_combined_extended,
                &dispatcher_combined_witness,
            )
            .unwrap(),
            None
        );
        let mixed_combined_prefix = semantic_composition::SemanticCfwAndPreWhirOpeningPrefix {
            cfw: prefix.clone(),
            pre_challenge_opening: semantic_whir::SemanticWhirOpeningBatchingPrefix {
                batching_challenge: None,
            },
        };
        assert_eq!(
            semantic_composition::semantic_cfw_and_pre_whir_opening_kstate(
                &combined_statement,
                &mixed_combined_prefix,
                &combined_witness,
            ),
            Err(semantic_composition::SemanticCompositionError::MalformedCombinedPrefix)
        );
        let ((whir_input_relation, whir_input_instance), (batched_relation, batched_instance)) =
            semantic_whir::semantic_whir_opening_batching_boundaries(
                output_relation.clone(),
                output_instance.clone(),
                field(347),
            )
            .expect("main WHIR opening batching accepts the exact CFW output pair");
        assert_eq!(whir_input_relation, output_relation);
        assert_eq!(whir_input_instance, output_instance);
        assert_eq!(batched_relation.opening_evaluation_claim_count, 0);
        assert_eq!(batched_relation.carried_reduction_claim_count, 1);
        assert_eq!(batched_relation.claim_count, 1);
        assert!(
            semantic_generalized_relation_holds(
                &batched_relation,
                &batched_instance,
                &output_witness,
            )
            .unwrap()
        );
        let mut changed_cross_epoch_opening = output_instance.clone();
        changed_cross_epoch_opening.opening_claims[0].target = changed_cross_epoch_opening
            .opening_claims[0]
            .target
            .add(field(1));
        assert!(
            !semantic_generalized_relation_holds(
                &output_relation,
                &changed_cross_epoch_opening,
                &output_witness,
            )
            .unwrap()
        );

        let invalid_public_input = [
            compact_challenge_from_production(field(2)),
            compact_challenge_from_production(field(4)),
        ];
        let invalid_relation_plan_hash = [0x5b; 64];
        let invalid_public_input_binding = [0x6b; 64];
        let extraction_prefix = CompactCfwInitialVerifierPrefix::for_focused_semantic_test(
            invalid_relation_plan_hash,
            invalid_public_input_binding,
            auxiliary_target,
            constraint_combining_challenge,
            prefix.equality_point.clone(),
        );
        let invalid_statement_for_extraction = SemanticCfwStatement::new(
            SemanticCfwInitialStatementBinding::new(
                invalid_relation_plan_hash,
                invalid_public_input_binding,
                &extraction_prefix,
            ),
            &matrices,
            &invalid_public_input,
            &code_relations,
            &committed_instances,
            &cross_epoch_handoff,
        )
        .expect("the invalid-relation statement remains structurally canonical");
        let invalid_decoding = semantic_cfw_errbr(
            &invalid_statement_for_extraction,
            cross_epoch_mask_code_witness,
        )
        .expect("the committed witness still decodes canonically");
        assert!(invalid_decoding.field_operation_count > 0);
        let invalid_extraction = invalid_decoding.witness;
        assert!(
            !semantic_cfw_kstate(&invalid_statement_for_extraction, None, &invalid_extraction,)
                .unwrap()
        );
        let invalid_initial_polynomial = compact_cfw_semantic_round_polynomial(
            &matrices,
            &invalid_public_input,
            &invalid_extraction.r1cs_witness,
            &invalid_extraction.mask_material,
            constraint_combining_challenge,
            &prefix.equality_point,
            &[],
            0,
        )
        .expect("the invalid relation still defines the first semantic polynomial");
        let invalid_initial_prefix = SemanticCfwTranscriptPrefix {
            auxiliary_target: compact_polynomial_endpoint_sum(&invalid_initial_polynomial),
            constraint_combining_challenge: Some(constraint_combining_challenge),
            equality_point: prefix.equality_point.clone(),
            round_polynomials: Vec::new(),
            round_challenges: Vec::new(),
            final_message: None,
            joint_constraint_challenge: None,
        };
        let invalid_source_prefix = CompactCfwInitialVerifierPrefix::for_focused_semantic_test(
            invalid_relation_plan_hash,
            invalid_public_input_binding,
            invalid_initial_prefix.auxiliary_target,
            constraint_combining_challenge,
            invalid_initial_prefix.equality_point.clone(),
        );
        let invalid_statement = SemanticCfwStatement::new(
            SemanticCfwInitialStatementBinding::new(
                invalid_relation_plan_hash,
                invalid_public_input_binding,
                &invalid_source_prefix,
            ),
            &matrices,
            &invalid_public_input,
            &code_relations,
            &committed_instances,
            &cross_epoch_handoff,
        )
        .expect("the exact invalid prefix binds the verifier-owned statement");
        let mut wrong_relation_plan_hash = invalid_relation_plan_hash;
        wrong_relation_plan_hash[0] ^= 1;
        assert!(matches!(
            SemanticCfwStatement::new(
                SemanticCfwInitialStatementBinding::new(
                    wrong_relation_plan_hash,
                    invalid_public_input_binding,
                    &invalid_source_prefix,
                ),
                &matrices,
                &invalid_public_input,
                &code_relations,
                &committed_instances,
                &cross_epoch_handoff,
            ),
            Err(SemanticCfwError::InitialSourceBinding(
                CompactCfwInitialTransitionError::BindingMismatch(
                    CompactCfwInitialTransitionBinding::RelationPlanVariant,
                ),
            ))
        ));
        let mut wrong_public_input_binding = invalid_public_input_binding;
        wrong_public_input_binding[0] ^= 1;
        assert!(matches!(
            SemanticCfwStatement::new(
                SemanticCfwInitialStatementBinding::new(
                    invalid_relation_plan_hash,
                    wrong_public_input_binding,
                    &invalid_source_prefix,
                ),
                &matrices,
                &invalid_public_input,
                &code_relations,
                &committed_instances,
                &cross_epoch_handoff,
            ),
            Err(SemanticCfwError::InitialSourceBinding(
                CompactCfwInitialTransitionError::BindingMismatch(
                    CompactCfwInitialTransitionBinding::CanonicalPublicInput,
                ),
            ))
        ));
        for (changed_prefix, expected_binding) in [
            (
                SemanticCfwTranscriptPrefix {
                    auxiliary_target: invalid_initial_prefix.auxiliary_target
                        + CompactChallengeField::ONE,
                    ..invalid_initial_prefix.clone()
                },
                CompactCfwInitialTransitionBinding::AuxiliaryTarget,
            ),
            (
                SemanticCfwTranscriptPrefix {
                    constraint_combining_challenge: Some(
                        constraint_combining_challenge + CompactChallengeField::ONE,
                    ),
                    ..invalid_initial_prefix.clone()
                },
                CompactCfwInitialTransitionBinding::InitialVerifierMessage,
            ),
            (
                SemanticCfwTranscriptPrefix {
                    equality_point: vec![
                        invalid_initial_prefix.equality_point[0] + CompactChallengeField::ONE,
                        invalid_initial_prefix.equality_point[1],
                    ],
                    ..invalid_initial_prefix.clone()
                },
                CompactCfwInitialTransitionBinding::InitialVerifierMessage,
            ),
        ] {
            assert_eq!(
                semantic_cfw_bad_transition(
                    &invalid_statement,
                    &changed_prefix,
                    &invalid_extraction,
                ),
                Err(SemanticCfwError::InitialSourceBinding(
                    CompactCfwInitialTransitionError::BindingMismatch(expected_binding),
                ))
            );
        }
        assert!(
            semantic_cfw_kstate(
                &invalid_statement,
                Some(&invalid_initial_prefix),
                &invalid_extraction,
            )
            .unwrap()
        );
        assert_eq!(
            semantic_cfw_errbr_at_verifier_move(
                &invalid_statement,
                &invalid_initial_prefix,
                &invalid_extraction,
            )
            .expect("the initial bad transition executes")
            .witness,
            Some(invalid_extraction.clone())
        );
        let invalid_initial_event = semantic_cfw_bad_transition(
            &invalid_statement,
            &invalid_initial_prefix,
            &invalid_extraction,
        )
        .expect("the initial bad transition is classified")
        .expect("the invalid input creates a bad transition");
        let mut substituted_extraction = invalid_extraction.clone();
        substituted_extraction.r1cs_witness[0] += CompactChallengeField::ONE;
        assert_eq!(
            semantic_cfw_bad_transition(
                &invalid_statement,
                &invalid_initial_prefix,
                &substituted_extraction,
            ),
            Ok(None)
        );
        assert_eq!(
            invalid_initial_event.polynomial_identity_numerator(),
            Some(3)
        );
        let SemanticCfwBadTransition::InitialConsistency(initial_event) = &invalid_initial_event
        else {
            panic!("unexpected initial transition event: {invalid_initial_event:?}");
        };
        assert_eq!(initial_event.soundness_numerator(), 3);
        assert_eq!(
            initial_event
                .initial_verifier_prefix()
                .constraint_combining_challenge(),
            constraint_combining_challenge
        );
        assert_eq!(
            initial_event.initial_verifier_prefix().equality_point(),
            prefix.equality_point
        );
        let initial_descriptor =
            semantic_execution::SemanticFactorOneMoveDescriptor::for_focused_test(
                semantic_execution::SemanticVerifierMoveOwner::CfwInitialRandomness,
            );
        let initial_events = semantic_error_bounds::derive_bad_transition_certificate_events(
            &initial_descriptor,
            &semantic_execution::SemanticVerifierMoveBadTransition::Cfw(
                invalid_initial_event.clone(),
            ),
        )
        .expect("the opaque initial event enters the semantic probability ledger");
        assert_eq!(
            initial_events
                .iter()
                .map(|event| event.family)
                .collect::<Vec<_>>(),
            [semantic_error_bounds::SemanticBadEventFamily::CfwInitialConsistencyIdentity]
        );

        let first_round_challenge = prefix.round_challenges[0];
        let mut root_adjusted_polynomial = prefix.round_polynomials[0];
        root_adjusted_polynomial[0] -= first_round_challenge;
        root_adjusted_polynomial[1] += CompactChallengeField::ONE;
        let root_adjusted_round_prefix = SemanticCfwTranscriptPrefix {
            auxiliary_target: compact_polynomial_endpoint_sum(&root_adjusted_polynomial),
            constraint_combining_challenge: Some(constraint_combining_challenge),
            equality_point: prefix.equality_point.clone(),
            round_polynomials: vec![root_adjusted_polynomial],
            round_challenges: vec![first_round_challenge],
            final_message: None,
            joint_constraint_challenge: None,
        };
        let mut root_adjusted_prover_prefix = root_adjusted_round_prefix.clone();
        root_adjusted_prover_prefix.round_challenges.clear();
        assert!(
            !semantic_cfw_kstate(&statement, Some(&root_adjusted_prover_prefix), &extraction,)
                .unwrap()
        );
        assert!(
            semantic_cfw_kstate(&statement, Some(&root_adjusted_round_prefix), &extraction,)
                .unwrap()
        );
        let root_adjusted_extraction = semantic_cfw_errbr_at_verifier_move(
            &statement,
            &root_adjusted_round_prefix,
            &extraction,
        )
        .expect("the sumcheck transition extractor executes");
        assert_eq!(root_adjusted_extraction.witness, Some(extraction.clone()));
        assert!(root_adjusted_extraction.field_operation_count > 0);
        let root_adjusted_event =
            semantic_cfw_bad_transition(&statement, &root_adjusted_round_prefix, &extraction)
                .expect("the sumcheck bad transition is classified")
                .expect("the adjusted polynomial creates a bad transition");
        assert_eq!(root_adjusted_event.polynomial_identity_numerator(), Some(1));
        match root_adjusted_event {
            SemanticCfwBadTransition::NonzeroPolynomial {
                transition,
                coefficients,
                challenge,
            } => {
                assert_eq!(
                    transition,
                    SemanticCfwVerifierTransition::SumcheckRound { round_ordinal: 0 }
                );
                assert_eq!(challenge, first_round_challenge);
                assert!(
                    coefficients
                        .iter()
                        .any(|coefficient| *coefficient != CompactChallengeField::ZERO)
                );
                assert_eq!(
                    compact_polynomial_evaluation(&coefficients, challenge),
                    CompactChallengeField::ZERO
                );
            }
            event => panic!("unexpected sumcheck transition event: {event:?}"),
        }

        let actual_final_values = finish.final_values();
        assert_ne!(
            actual_final_values[CompactCfwMatrixRole::LeftMultiplicand.ordinal()],
            CompactChallengeField::ZERO
        );
        let final_value_adjustment = compact_challenge_from_production(field(1));
        let mut equation_preserving_final_values = actual_final_values;
        equation_preserving_final_values[CompactCfwMatrixRole::RightMultiplicand.ordinal()] +=
            final_value_adjustment;
        equation_preserving_final_values[CompactCfwMatrixRole::Product.ordinal()] +=
            actual_final_values[CompactCfwMatrixRole::LeftMultiplicand.ordinal()]
                * final_value_adjustment;
        let equation_preserving_final_message = SemanticCfwFinalMessage {
            outer_evaluations: finish.outer_evaluations().to_vec(),
            final_values: equation_preserving_final_values,
        };
        let equation_preserving_final_prover_prefix = SemanticCfwTranscriptPrefix {
            auxiliary_target,
            constraint_combining_challenge: Some(constraint_combining_challenge),
            equality_point: prefix.equality_point.clone(),
            round_polynomials: prefix.round_polynomials.clone(),
            round_challenges: prefix.round_challenges.clone(),
            final_message: Some(equation_preserving_final_message.clone()),
            joint_constraint_challenge: None,
        };
        assert!(
            cfw_transcript_deterministically_accepts(
                &statement,
                &equation_preserving_final_prover_prefix,
            )
            .unwrap()
        );
        assert!(
            !semantic_cfw_kstate(
                &statement,
                Some(&equation_preserving_final_prover_prefix),
                &extraction,
            )
            .unwrap()
        );

        let left_final_value =
            actual_final_values[CompactCfwMatrixRole::LeftMultiplicand.ordinal()];
        let zero_evader_challenge = -left_final_value.inverse();
        let zero_evader_prefix = SemanticCfwTranscriptPrefix {
            joint_constraint_challenge: Some(zero_evader_challenge),
            ..equation_preserving_final_prover_prefix.clone()
        };
        assert!(semantic_cfw_kstate(&statement, Some(&zero_evader_prefix), &extraction).unwrap());
        let zero_evader_extraction =
            semantic_cfw_errbr_at_verifier_move(&statement, &zero_evader_prefix, &extraction)
                .expect("the zero-evader transition extractor executes");
        assert_eq!(zero_evader_extraction.witness, Some(extraction.clone()));
        assert_eq!(zero_evader_extraction.field_operation_count, 0);
        let zero_evader_event =
            semantic_cfw_bad_transition(&statement, &zero_evader_prefix, &extraction)
                .expect("the joint bad transition is classified")
                .expect("the adjusted final values create a joint bad transition");
        assert_eq!(zero_evader_event.polynomial_identity_numerator(), Some(2));
        match zero_evader_event {
            SemanticCfwBadTransition::ZeroEvader {
                residuals,
                weights,
                challenge,
            } => {
                assert_eq!(challenge, zero_evader_challenge);
                assert!(
                    residuals
                        .iter()
                        .any(|residual| *residual != CompactChallengeField::ZERO)
                );
                assert_eq!(weights, compact_cfw_zero_evader_weights(challenge));
                assert_eq!(
                    residuals
                        .iter()
                        .zip(weights)
                        .map(|(&residual, weight)| residual * weight)
                        .sum::<CompactChallengeField>(),
                    CompactChallengeField::ZERO
                );
            }
            event => panic!("unexpected joint transition event: {event:?}"),
        }

        let mut changed_prefix = prefix.clone();
        changed_prefix.round_polynomials[0][3] += compact_challenge_from_production(field(1));
        assert!(!semantic_cfw_kstate(&statement, Some(&changed_prefix), &extraction).unwrap());

        let mut changed_auxiliary_target = prefix.clone();
        changed_auxiliary_target.auxiliary_target += compact_challenge_from_production(field(1));
        assert!(
            !semantic_cfw_kstate(&statement, Some(&changed_auxiliary_target), &extraction).unwrap()
        );

        let mut changed_final_value = prefix.clone();
        changed_final_value
            .final_message
            .as_mut()
            .expect("complete prefix has a final message")
            .final_values[0] += compact_challenge_from_production(field(1));
        assert!(!semantic_cfw_kstate(&statement, Some(&changed_final_value), &extraction).unwrap());

        let mut substituted_extraction = extraction.clone();
        substituted_extraction.r1cs_witness[0] += compact_challenge_from_production(field(1));
        assert!(!semantic_cfw_kstate(&statement, Some(&prefix), &substituted_extraction).unwrap());

        let mut substituted_inner_mask_extraction = extraction.clone();
        let original_inner_mask_coefficient = substituted_inner_mask_extraction
            .inner_mask_code_witness
            .message_columns[0][1];
        substituted_inner_mask_extraction
            .inner_mask_code_witness
            .message_columns[0][1] = original_inner_mask_coefficient.add(field(1));
        assert_eq!(
            semantic_cfw_kstate(
                &statement,
                Some(&prefix),
                &substituted_inner_mask_extraction,
            ),
            Ok(false)
        );

        let mut malformed_prefix = prefix;
        malformed_prefix
            .round_challenges
            .push(compact_challenge_from_production(field(41)));
        assert_eq!(
            semantic_cfw_kstate(&statement, Some(&malformed_prefix), &extraction),
            Err(SemanticCfwError::MalformedPrefix)
        );
    }
}
