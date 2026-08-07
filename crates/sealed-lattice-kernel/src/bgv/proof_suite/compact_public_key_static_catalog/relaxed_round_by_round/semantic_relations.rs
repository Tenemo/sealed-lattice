//! Executable relaxed relations used by the round-by-round theorem.
//!
//! These predicates consume actual field values. They do not accept a
//! producer-supplied verdict: input R1CS membership is recomputed from the
//! verifier-owned matrices, while a generalized committed-code relation is
//! checked by re-encoding the supplied message and hiding randomness, measuring
//! its row distance from each oracle, and evaluating every public linear claim.
//! The matching extractor runs the canonical decoder and returns those same
//! mathematical witnesses or a typed failure.

use super::{CommittedCodeRelation, GeneralizedCommittedRelation};
use crate::bgv::proof_suite::ProofChallengeExtensionElement;
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_MATRIX_COUNT, CompactCfwError, CompactCfwMatrixRole, CompactCfwR1csMatrices,
    CompactChallengeField,
};
use crate::bgv::proof_suite::compact_public_key_static_catalog::canonical_reed_solomon::{
    CanonicalReedSolomonError, CanonicalReedSolomonGeometry,
    decode_canonical_interleaved_reed_solomon, encode_canonical_interleaved_reed_solomon,
};

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
    validate_generalized_relation_shape(relation, instance, witness)?;
    if !semantic_committed_code_relation_holds(
        &relation.source_code,
        &instance.source,
        &witness.source,
    )? {
        return Ok(false);
    }
    for ((mask_relation, mask_instance), mask_witness) in relation
        .mask_codes
        .iter()
        .zip(&instance.masks)
        .zip(&witness.masks)
    {
        if !semantic_committed_code_relation_holds(
            &mask_relation.code,
            mask_instance,
            mask_witness,
        )? {
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
    witness: &SemanticGeneralizedRelationWitness,
) -> Result<(), SemanticRelationError> {
    validate_generalized_relation_descriptor(relation)?;
    let expected_opening_claim_count = usize::try_from(relation.opening_evaluation_claim_count)
        .map_err(|_| SemanticRelationError::InvalidGeometry)?;
    let expected_carried_claim_count = usize::try_from(relation.carried_reduction_claim_count)
        .map_err(|_| SemanticRelationError::InvalidGeometry)?;
    if instance.masks.len() != relation.mask_codes.len()
        || witness.masks.len() != relation.mask_codes.len()
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

#[cfg(test)]
mod tests {
    use super::super::{CommittedMaskCodeRelation, MaskGroupRole};
    use super::*;
    use crate::bgv::proof_suite::ProofBaseFieldElement;
    use crate::bgv::proof_suite::compact_cfw::compact_challenge_from_production;

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
                CompactCfwMatrixRole::LeftMultiplicand => {
                    vec![public_input[0] + witness[0], public_input[1]]
                }
                CompactCfwMatrixRole::RightMultiplicand => {
                    vec![witness[1], witness[0] + witness[1]]
                }
                CompactCfwMatrixRole::Product => vec![
                    (public_input[0] + witness[0]) * witness[1],
                    public_input[1] * (witness[0] + witness[1]),
                ],
            })
        }

        fn public_contribution_at_row_point(
            &self,
            _matrix_role: CompactCfwMatrixRole,
            _row_point: &[CompactChallengeField],
            _public_input: &[CompactChallengeField],
        ) -> Result<CompactChallengeField, CompactCfwError> {
            Err(CompactCfwError::InvalidMatrixSource)
        }

        fn accumulate_weighted_witness_covector_at_row_point(
            &self,
            _row_point: &[CompactChallengeField],
            _matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
            _destination: &mut [CompactChallengeField],
        ) -> Result<(), CompactCfwError> {
            Err(CompactCfwError::InvalidMatrixSource)
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
}
