use crate::{
    bgv::{
        parameters::POLYNOMIAL_DEGREE,
        setup::{
            SETUP_COMMITMENT_MODULE_RANK, VerifiedPublicRandomness,
            sample_collective_public_key_common_reference_limb,
            sample_galois_common_reference_limb, sample_relinearization_common_reference_limb,
            setup_commitment_matrix_polynomial,
        },
    },
    foundation::{ProofApplicationSlotCeilings, RefusalReason},
    transcript_core::encode_hex,
};

use super::super::{
    OpenedFriLayerPair, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofEvaluationDomain, ValidatedRelationPlanArtifact, VerifiedRelationColumnEvaluator,
    VerifiedRelationColumnEvaluatorMemoryAccounting,
};
use super::{
    ModulusCatalog, RelationColumnOrigin, RelationColumnValueType, RelationPlanCheckContext,
    RelationPlanVariant, RelationVerifierSource, SelectorPathStepKind, SuiteModulusReference,
    negacyclic_automorphism_mapping_values,
};

const SETUP_COMMITMENT_MATRIX_PROTOCOL_SOURCE_KIND: u16 = 5;
const COLLECTIVE_PUBLIC_KEY_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND: u16 = 6;
const RELINEARIZATION_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND: u16 = 7;
const GALOIS_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND: u16 = 8;

struct CachedEvaluationDomainColumn {
    domain: ProofEvaluationDomain,
    evaluations: Vec<ProofBaseFieldElement>,
}

struct CachedVerifierColumn {
    column_ordinal: u32,
    coefficients: Vec<ProofBaseFieldElement>,
    evaluation_domain_column: Option<CachedEvaluationDomainColumn>,
}

/// Rebuilds key-relation verifier columns only from the accepted public
/// randomness terminal and a checked relation plan. No polynomial or alternate
/// public-source representation can enter this adapter.
pub(crate) struct VerifiedKeyRelationColumnEvaluator {
    public_setup_seed: [u8; 64],
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    ring_degree: usize,
    trace_domain: ProofEvaluationDomain,
    cached_column: Option<CachedVerifierColumn>,
}

impl VerifiedKeyRelationColumnEvaluator {
    pub(crate) fn from_verified_public_randomness(
        verified_public_randomness: &VerifiedPublicRandomness,
        validated_relation_plan: &ValidatedRelationPlanArtifact,
        selected_relation_plan_variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
    ) -> Result<Self, RefusalReason> {
        let revalidated_relation_plan = ValidatedRelationPlanArtifact::from_compiled_plan(
            validated_relation_plan.compiled_plan(),
            relation_context,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        if &revalidated_relation_plan != validated_relation_plan {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }

        let application_statement_schema_identifier =
            validated_relation_plan.application_statement_schema_identifier();
        if !is_supported_key_relation_family(application_statement_schema_identifier) {
            return Err(RefusalReason::OutsideSupportedProfile);
        }

        let artifact_variant = validated_relation_plan
            .compiled_plan()
            .select_variant(
                selected_relation_plan_variant.schedule_position(),
                selected_relation_plan_variant.top_count(),
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        if artifact_variant != selected_relation_plan_variant {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }

        let trace_domain_size = selected_relation_plan_variant.trace_domain_size();
        let ring_degree = trace_domain_size
            .checked_mul(2)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value == POLYNOMIAL_DEGREE)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(trace_domain_size)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;

        let mut verifier_column_count = 0_usize;
        for descriptor in selected_relation_plan_variant.ordered_columns() {
            let RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } = descriptor.origin()
            else {
                continue;
            };
            if descriptor.value_type() != RelationColumnValueType::BaseField
                || descriptor.source_degree_bound_exclusive() < trace_domain_size
            {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            let verifier_source = selected_relation_plan_variant
                .verifier_source(*verifier_source_ordinal)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            let sequence_length = validate_verifier_source(
                application_statement_schema_identifier,
                verifier_source,
                u64::try_from(ring_degree).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                relation_context,
            )?;
            let last_sequence_index = trace_domain_size
                .checked_sub(1)
                .and_then(|last_row| last_row.checked_mul(*logical_element_stride))
                .and_then(|offset| first_logical_element_index.checked_add(offset))
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if *logical_element_stride == 0 || last_sequence_index >= sequence_length {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            verifier_column_count = verifier_column_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
        if verifier_column_count == 0 {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }

        Ok(Self {
            public_setup_seed: verified_public_randomness.public_setup_seed().into_bytes(),
            relation_plan_variant: selected_relation_plan_variant.clone(),
            relation_context: relation_context.clone(),
            ring_degree,
            trace_domain,
            cached_column: None,
        })
    }

    fn ensure_cached_column(&mut self, column_ordinal: u32) -> Result<(), RefusalReason> {
        if self
            .cached_column
            .as_ref()
            .map(|cached| cached.column_ordinal)
            == Some(column_ordinal)
        {
            return Ok(());
        }

        let mut trace_rows = self.verifier_sequence_rows(column_ordinal)?;
        self.trace_domain
            .interpolate_base_polynomial_in_place(&mut trace_rows)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        self.cached_column = Some(CachedVerifierColumn {
            column_ordinal,
            coefficients: trace_rows,
            evaluation_domain_column: None,
        });
        Ok(())
    }

    fn verifier_sequence_rows(
        &self,
        column_ordinal: u32,
    ) -> Result<Vec<ProofBaseFieldElement>, RefusalReason> {
        let descriptor = self
            .relation_plan_variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let RelationColumnOrigin::VerifierSequence {
            verifier_source_ordinal,
            first_logical_element_index,
            logical_element_stride,
        } = descriptor.origin()
        else {
            return Err(RefusalReason::WrongTypeOrLength);
        };
        let verifier_source = self
            .relation_plan_variant
            .verifier_source(*verifier_source_ordinal)
            .ok_or(RefusalReason::InvalidArithmeticRelation)?;
        let sequence = self.full_verifier_sequence(verifier_source)?;
        let first_index = usize::try_from(*first_logical_element_index)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let stride = usize::try_from(*logical_element_stride)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut rows = Vec::with_capacity(self.trace_domain.size());
        for row_ordinal in 0..self.trace_domain.size() {
            let sequence_index = row_ordinal
                .checked_mul(stride)
                .and_then(|offset| first_index.checked_add(offset))
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let value = sequence
                .get(sequence_index)
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            rows.push(
                ProofBaseFieldElement::from_canonical(value)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
            );
        }
        Ok(rows)
    }

    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
        match source {
            RelationVerifierSource::Protocol {
                protocol_source_kind: SETUP_COMMITMENT_MATRIX_PROTOCOL_SOURCE_KIND,
                source_coordinates,
                ..
            } => {
                let [data_modulus_index, matrix_part, row, column] = source_coordinates.as_slice()
                else {
                    return Err(RefusalReason::WrongTypeOrLength);
                };
                let data_modulus_index = u16::try_from(*data_modulus_index)
                    .map_err(|_| RefusalReason::WrongTypeOrLength)?;
                let matrix_part =
                    u16::try_from(*matrix_part).map_err(|_| RefusalReason::WrongTypeOrLength)?;
                let matrix_row = match matrix_part {
                    1 => usize::try_from(*row).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    2 if *row == 0 => SETUP_COMMITMENT_MODULE_RANK,
                    _ => return Err(RefusalReason::WrongTypeOrLength),
                };
                let modulus = self
                    .relation_context
                    .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                setup_commitment_matrix_polynomial(
                    &encode_hex(&self.public_setup_seed),
                    usize::from(data_modulus_index),
                    matrix_row,
                    usize::try_from(*column).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    self.ring_degree,
                    modulus,
                )
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)
            }
            RelationVerifierSource::Protocol {
                protocol_source_kind: COLLECTIVE_PUBLIC_KEY_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND,
                source_coordinates,
                ..
            } => {
                let [data_modulus_index] = source_coordinates.as_slice() else {
                    return Err(RefusalReason::WrongTypeOrLength);
                };
                sample_collective_public_key_common_reference_limb(
                    &self.public_setup_seed,
                    u16::try_from(*data_modulus_index)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?,
                    self.ring_degree,
                )
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)
            }
            RelationVerifierSource::Protocol {
                protocol_source_kind: RELINEARIZATION_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND,
                source_coordinates,
                ..
            } => sample_key_switch_common_reference(
                &self.public_setup_seed,
                source_coordinates,
                self.ring_degree,
                sample_relinearization_common_reference_limb,
            ),
            RelationVerifierSource::Protocol {
                protocol_source_kind: GALOIS_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND,
                source_coordinates,
                ..
            } => sample_key_switch_common_reference(
                &self.public_setup_seed,
                source_coordinates,
                self.ring_degree,
                sample_galois_common_reference_limb,
            ),
            RelationVerifierSource::NegacyclicAutomorphismMapping {
                ring_degree,
                galois_element,
            } => negacyclic_automorphism_mapping_values(*ring_degree, *galois_element)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation),
            _ => Err(RefusalReason::WrongTypeOrLength),
        }
    }
}

impl VerifiedRelationColumnEvaluator for VerifiedKeyRelationColumnEvaluator {
    fn memory_accounting(
        &self,
    ) -> Result<
        VerifiedRelationColumnEvaluatorMemoryAccounting,
        super::super::CommonProofVerifierError,
    > {
        let checked_payload = |count: usize, value_byte_length: usize| {
            u64::try_from(count)
                .ok()
                .and_then(|count| {
                    u64::try_from(value_byte_length)
                        .ok()
                        .and_then(|width| count.checked_mul(width))
                })
                .ok_or(super::super::CommonProofVerifierError::InvalidTreeLayout)
        };
        let fixed_and_input_resident_byte_length = u64::try_from(core::mem::size_of::<Self>())
            .ok()
            .and_then(|fixed| {
                self.relation_plan_variant
                    .resident_owned_payload_byte_length()
                    .ok()
                    .and_then(|payload| fixed.checked_add(payload))
            })
            .and_then(|length| {
                self.relation_context
                    .resident_owned_payload_byte_length()
                    .ok()
                    .and_then(|payload| length.checked_add(payload))
            })
            .ok_or(super::super::CommonProofVerifierError::InvalidTreeLayout)?;
        let coefficient_cache_byte_length = checked_payload(
            self.trace_domain.size(),
            core::mem::size_of::<ProofBaseFieldElement>(),
        )?;
        let evaluation_cache_byte_length = checked_payload(
            usize::try_from(self.relation_plan_variant.evaluation_domain_size())
                .map_err(|_| super::super::CommonProofVerifierError::InvalidTreeLayout)?,
            core::mem::size_of::<ProofBaseFieldElement>(),
        )?;
        let maximum_cached_column_resident_byte_length = coefficient_cache_byte_length
            .checked_add(evaluation_cache_byte_length)
            .ok_or(super::super::CommonProofVerifierError::InvalidTreeLayout)?;
        // Changing columns retains the previous cache while the new verifier
        // sequence and its trace-domain projection are derived.
        let maximum_evaluation_transient_byte_length =
            checked_payload(self.ring_degree, core::mem::size_of::<u64>())?
                .checked_add(coefficient_cache_byte_length)
                .ok_or(super::super::CommonProofVerifierError::InvalidTreeLayout)?;
        VerifiedRelationColumnEvaluatorMemoryAccounting::new(
            fixed_and_input_resident_byte_length,
            maximum_cached_column_resident_byte_length,
            maximum_evaluation_transient_byte_length,
        )
    }

    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement> {
        self.ensure_cached_column(column_ordinal).ok()?;
        let coefficients = &self.cached_column.as_ref()?.coefficients;
        Some(coefficients.iter().rev().fold(
            ProofChallengeExtensionElement::ZERO,
            |accumulated, coefficient| {
                accumulated
                    .multiply(point)
                    .add(ProofChallengeExtensionElement::from_base(*coefficient))
            },
        ))
    }

    fn evaluate_at_evaluation_domain_pair(
        &mut self,
        column_ordinal: u32,
        evaluation_domain: ProofEvaluationDomain,
        query_representative: u64,
    ) -> Option<OpenedFriLayerPair> {
        let query_representative = usize::try_from(query_representative).ok()?;
        let half_domain_size = evaluation_domain.size().checked_div(2)?;
        if query_representative >= half_domain_size {
            return None;
        }
        self.ensure_cached_column(column_ordinal).ok()?;
        let needs_evaluation = self
            .cached_column
            .as_ref()?
            .evaluation_domain_column
            .as_ref()
            .is_none_or(|cached| cached.domain != evaluation_domain);
        if needs_evaluation {
            let mut evaluations = self.cached_column.as_ref()?.coefficients.clone();
            evaluation_domain
                .evaluate_base_polynomial_in_place(&mut evaluations)
                .ok()?;
            self.cached_column.as_mut()?.evaluation_domain_column =
                Some(CachedEvaluationDomainColumn {
                    domain: evaluation_domain,
                    evaluations,
                });
        }
        let cached = self
            .cached_column
            .as_ref()?
            .evaluation_domain_column
            .as_ref()?;
        Some(OpenedFriLayerPair::new(
            ProofChallengeExtensionElement::from_base(
                *cached.evaluations.get(query_representative)?,
            ),
            ProofChallengeExtensionElement::from_base(
                *cached
                    .evaluations
                    .get(query_representative.checked_add(half_domain_size)?)?,
            ),
        ))
    }
}

fn is_supported_key_relation_family(application_statement_schema_identifier: u16) -> bool {
    matches!(
        application_statement_schema_identifier,
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
    )
}

fn validate_verifier_source(
    application_statement_schema_identifier: u16,
    source: &RelationVerifierSource,
    ring_degree: u64,
    relation_context: &RelationPlanCheckContext,
) -> Result<u64, RefusalReason> {
    match source {
        RelationVerifierSource::Protocol {
            protocol_source_kind,
            source_coordinates,
            statement_binding_path,
            ..
        } => {
            if !protocol_source_kind_is_supported_by_family(
                application_statement_schema_identifier,
                *protocol_source_kind,
            ) || statement_binding_path.len() != 1
                || statement_binding_path[0].step_kind() != SelectorPathStepKind::TupleField
                || statement_binding_path[0].argument() != 0
            {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            match *protocol_source_kind {
                SETUP_COMMITMENT_MATRIX_PROTOCOL_SOURCE_KIND => {
                    let [data_modulus_index, matrix_part, row, column] =
                        source_coordinates.as_slice()
                    else {
                        return Err(RefusalReason::WrongTypeOrLength);
                    };
                    let data_modulus_index = u16::try_from(*data_modulus_index)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
                    relation_context
                        .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                    match u16::try_from(*matrix_part)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?
                    {
                        1 => {
                            usize::try_from(*row).map_err(|_| RefusalReason::WrongTypeOrLength)?;
                        }
                        2 if *row == 0 => {}
                        _ => return Err(RefusalReason::WrongTypeOrLength),
                    }
                    usize::try_from(*column).map_err(|_| RefusalReason::WrongTypeOrLength)?;
                }
                COLLECTIVE_PUBLIC_KEY_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND => {
                    let [data_modulus_index] = source_coordinates.as_slice() else {
                        return Err(RefusalReason::WrongTypeOrLength);
                    };
                    let data_modulus_index = u16::try_from(*data_modulus_index)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
                    relation_context
                        .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                }
                RELINEARIZATION_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND
                | GALOIS_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND => {
                    let [
                        schedule_position,
                        decomposition_block_index,
                        modulus_catalog_identifier,
                        modulus_index,
                    ] = source_coordinates.as_slice()
                    else {
                        return Err(RefusalReason::WrongTypeOrLength);
                    };
                    u32::try_from(*schedule_position)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
                    u16::try_from(*decomposition_block_index)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
                    let modulus_index = u16::try_from(*modulus_index)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
                    let modulus_reference = match u16::try_from(*modulus_catalog_identifier)
                        .map_err(|_| RefusalReason::WrongTypeOrLength)?
                    {
                        value if value == ModulusCatalog::Data as u16 => {
                            SuiteModulusReference::data(modulus_index)
                        }
                        value if value == ModulusCatalog::Special as u16 => {
                            SuiteModulusReference::special(modulus_index)
                        }
                        _ => return Err(RefusalReason::WrongTypeOrLength),
                    };
                    relation_context
                        .resolved_modulus(modulus_reference)
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                }
                _ => return Err(RefusalReason::InvalidArithmeticRelation),
            }
            Ok(ring_degree)
        }
        RelationVerifierSource::NegacyclicAutomorphismMapping {
            ring_degree: source_ring_degree,
            galois_element,
        } => {
            if application_statement_schema_identifier
                != ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                || *source_ring_degree != ring_degree
            {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            super::model::validate_negacyclic_automorphism(*source_ring_degree, *galois_element)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            ring_degree
                .checked_mul(3)
                .ok_or(RefusalReason::OutsideSupportedProfile)
        }
        _ => Err(RefusalReason::InvalidArithmeticRelation),
    }
}

fn protocol_source_kind_is_supported_by_family(
    application_statement_schema_identifier: u16,
    protocol_source_kind: u16,
) -> bool {
    match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => {
            protocol_source_kind == SETUP_COMMITMENT_MATRIX_PROTOCOL_SOURCE_KIND
        }
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => matches!(
            protocol_source_kind,
            SETUP_COMMITMENT_MATRIX_PROTOCOL_SOURCE_KIND
                | COLLECTIVE_PUBLIC_KEY_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND
        ),
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
            matches!(
                protocol_source_kind,
                SETUP_COMMITMENT_MATRIX_PROTOCOL_SOURCE_KIND
                    | RELINEARIZATION_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND
            )
        }
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => matches!(
            protocol_source_kind,
            SETUP_COMMITMENT_MATRIX_PROTOCOL_SOURCE_KIND
                | GALOIS_COMMON_REFERENCE_PROTOCOL_SOURCE_KIND
        ),
        _ => false,
    }
}

type KeySwitchCommonReferenceSampler =
    fn(&[u8; 64], u32, u16, u16, u16, usize) -> crate::encoding::CanonicalResult<Vec<u64>>;

fn sample_key_switch_common_reference(
    public_setup_seed: &[u8; 64],
    source_coordinates: &[u64],
    ring_degree: usize,
    sampler: KeySwitchCommonReferenceSampler,
) -> Result<Vec<u64>, RefusalReason> {
    let [
        schedule_position,
        block_ordinal,
        modulus_catalog,
        modulus_index,
    ] = source_coordinates
    else {
        return Err(RefusalReason::WrongTypeOrLength);
    };
    sampler(
        public_setup_seed,
        u32::try_from(*schedule_position).map_err(|_| RefusalReason::WrongTypeOrLength)?,
        u16::try_from(*block_ordinal).map_err(|_| RefusalReason::WrongTypeOrLength)?,
        u16::try_from(*modulus_catalog).map_err(|_| RefusalReason::WrongTypeOrLength)?,
        u16::try_from(*modulus_index).map_err(|_| RefusalReason::WrongTypeOrLength)?,
        ring_degree,
    )
    .map_err(|_| RefusalReason::InvalidArithmeticRelation)
}
