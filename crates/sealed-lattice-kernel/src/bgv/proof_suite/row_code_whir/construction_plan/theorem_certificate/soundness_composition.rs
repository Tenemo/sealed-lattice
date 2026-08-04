use super::*;
use crate::{
    bgv::proof_suite::selected_accounting::resource_accounting::derive_selected_proof_family_application_inventory,
    foundation::{FOUNDATION_PROFILE, ProofFamilyApplicationInventory},
    hashing::{hash_framed_parts_512, to_hex},
};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

const MAPPED_SOUNDNESS_EVIDENCE_FORMAT_VERSION: u16 = 5;
const MAPPED_SOUNDNESS_CHRONOLOGY_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/mapped-soundness-chronology/v5";
const MAPPED_SOUNDNESS_CHECKPOINT_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/mapped-soundness-checkpoint/v5";
const MAPPED_SOUNDNESS_REFRESH_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_REFRESH_COMMON_PROOF_SOUNDNESS_EVIDENCE";
const MAPPED_SOUNDNESS_EVIDENCE_FILE_NAME: &str =
    "selected-common-proof-mapped-soundness-evidence.json";
const MAPPED_SOUNDNESS_CHECKPOINT_FILE_STEM: &str = "selected-common-proof-mapped-soundness-v5";
const MAPPED_SOUNDNESS_COMBINED_CHECKPOINT_FILE_NAME: &str =
    "selected-common-proof-mapped-soundness-evidence-v5.json";
const MAPPED_SOUNDNESS_CONDITIONAL_ORACLE_MODEL: &str =
    "single-fixed-512-bit-qro-with-precommitted-auxiliary-restriction-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SequentialSoundnessCompositionRule {
    EarliestInvalidAcceptanceWithStatementFixedBeforeOwnChallenges,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConditionalOracleAssumption {
    SingleFixed512BitQroWithPrecommittedAuxiliaryRestriction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SequentialPriorHistoryTreatment {
    ArbitraryAuxiliaryInputBeforeCurrentStatementBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrossProofIndependenceUse {
    None,
    #[cfg(test)]
    Assumed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionInitialTranscriptBinding {
    ProtocolSuiteConstructionSchemaAndCanonicalProofHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionChallengeChronologyRow {
    operation_ordinal: u32,
    immediate_predecessor_operation_ordinal: u32,
    verifier_message_round_ordinal: u64,
    output_byte_length: u64,
    fixed_hash_query_count: u64,
    failure_event_owner: SelectedPlanFailureEventOwner,
}

/// Finite production-plan proof that the statement-bearing canonical header is
/// absorbed before every verifier message owned by this physical proof.
///
/// This is derived from the same oracle-equation catalog and semantic state
/// transition rows consumed by the mapped CMS transform. It is not a caller-
/// supplied chronology flag.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionStatementChallengeChronologyCertificate {
    construction_plan_identity_hash: [u8; 64],
    initial_binding: ProductionInitialTranscriptBinding,
    initial_operation_ordinal: u32,
    canonical_header_root_equation_slot_ordinal: u64,
    initial_absorption_equation_slot_ordinal: u64,
    challenge_rows: Vec<ProductionChallengeChronologyRow>,
}

impl ProductionStatementChallengeChronologyCertificate {
    fn derive(
        plan: &RowCodeWhirConstructionPlan,
        soundness: &ProductionMappedSoundnessCertificate,
    ) -> Result<Self, WhirTheoremCertificateError> {
        Self::derive_from_parts(
            plan,
            &soundness.selected_plan_state_predicate,
            &soundness.cms19_whole_state_transitions,
            soundness.logical_verifier_message_count,
        )
    }

    fn derive_from_geometry(
        plan: &RowCodeWhirConstructionPlan,
        geometry: &RowCodeWhirProductionGeometryCertificate,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if !geometry.is_complete()
            || geometry.construction_plan_identity_hash
                != plan
                    .canonical_identity_hash()
                    .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        Self::derive_from_parts(
            plan,
            &geometry.selected_plan_state_predicate,
            &geometry.cms19_whole_state_transitions,
            geometry.logical_verifier_message_count,
        )
    }

    fn derive_from_parts(
        plan: &RowCodeWhirConstructionPlan,
        selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
        whole_state_transitions: &Cms19WholeStateTransitionCertificate,
        logical_verifier_message_count: u64,
    ) -> Result<Self, WhirTheoremCertificateError> {
        let catalog = plan
            .oracle_equation_catalog()
            .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
        if !whole_state_transitions.is_complete_for(plan, &catalog, selected_plan_state_predicate) {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let initial_operation = catalog
            .operations
            .first()
            .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
        let initial_state_row = whole_state_transitions
            .rows
            .first()
            .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
        let [header_root_range, initial_absorption_range] = initial_operation.ranges.as_slice()
        else {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        };
        if initial_operation.operation_ordinal != 0
            || initial_operation.predecessor_operation_ordinal.is_some()
            || initial_operation.first_equation_slot_ordinal != 0
            || initial_operation.kind != RowCodeWhirOracleEquationOperationKind::InitialTranscript
            || initial_operation.oracle_tag.is_some()
            || header_root_range.kind != RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot
            || header_root_range.predecessor != RowCodeWhirOracleEquationPredecessor::Independent
            || initial_absorption_range.kind
                != RowCodeWhirOracleEquationRangeKind::InitialAbsorption
            || initial_absorption_range.predecessor
                != RowCodeWhirOracleEquationPredecessor::FixedZeroState
            || initial_state_row.operation_ordinal != 0
            || initial_state_row.predecessor_operation_ordinal.is_some()
            || initial_state_row.transition != Cms19SemanticStateTransition::InitialCanonicalPrefix
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }

        let mut challenge_rows = Vec::new();
        for (operation, state_row) in catalog.operations.iter().zip(&whole_state_transitions.rows) {
            let Cms19SemanticStateTransition::VerifierMessageFill {
                round_ordinal,
                output_byte_length,
                failure_event_owner,
                ..
            } = state_row.transition
            else {
                continue;
            };
            let immediate_predecessor_operation_ordinal = operation
                .operation_ordinal
                .checked_sub(1)
                .filter(|predecessor| operation.predecessor_operation_ordinal == Some(*predecessor))
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
            let mut atomic_challenge_ranges =
                operation
                    .ranges
                    .iter()
                    .filter_map(|range| match range.kind {
                        RowCodeWhirOracleEquationRangeKind::AtomicChallengeSeededHashStream {
                            output_byte_length,
                            fixed_hash_query_count,
                        } => Some((output_byte_length, fixed_hash_query_count)),
                        _ => None,
                    });
            if !oracle_equation_operation_leaves_pending_challenge(&operation.kind)
                || atomic_challenge_ranges.next()
                    != Some((
                        output_byte_length,
                        atomic_challenge_fixed_hash_query_count(output_byte_length).map_err(
                            |_| WhirTheoremCertificateError::IncompleteTranscriptMapping,
                        )?,
                    ))
                || atomic_challenge_ranges.next().is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
            challenge_rows.push(ProductionChallengeChronologyRow {
                operation_ordinal: operation.operation_ordinal,
                immediate_predecessor_operation_ordinal,
                verifier_message_round_ordinal: round_ordinal,
                output_byte_length,
                fixed_hash_query_count: atomic_challenge_fixed_hash_query_count(output_byte_length)
                    .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
                failure_event_owner,
            });
        }
        let certificate = Self {
            construction_plan_identity_hash: plan
                .canonical_identity_hash()
                .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
            initial_binding:
                ProductionInitialTranscriptBinding::ProtocolSuiteConstructionSchemaAndCanonicalProofHeader,
            initial_operation_ordinal: initial_operation.operation_ordinal,
            canonical_header_root_equation_slot_ordinal: initial_operation
                .first_equation_slot_ordinal
                .checked_add(header_root_range.first_equation_offset)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            initial_absorption_equation_slot_ordinal: initial_operation
                .first_equation_slot_ordinal
                .checked_add(initial_absorption_range.first_equation_offset)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            challenge_rows,
        };
        if !certificate.is_self_consistent(logical_verifier_message_count)
            || !plan
                .canonical_identity_hash()
                .is_ok_and(|identity| identity == certificate.construction_plan_identity_hash)
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        Ok(certificate)
    }

    fn is_self_consistent(&self, logical_verifier_message_count: u64) -> bool {
        self.construction_plan_identity_hash != [0_u8; 64]
            && self.initial_binding
                == ProductionInitialTranscriptBinding::ProtocolSuiteConstructionSchemaAndCanonicalProofHeader
            && self.initial_operation_ordinal == 0
            && self.canonical_header_root_equation_slot_ordinal == 0
            && self.initial_absorption_equation_slot_ordinal == 1
            && u64::try_from(self.challenge_rows.len()).ok()
                == Some(logical_verifier_message_count)
            && !self.challenge_rows.is_empty()
            && self.challenge_rows.iter().all(|row| {
                row.operation_ordinal > self.initial_operation_ordinal
                    && row.immediate_predecessor_operation_ordinal
                        == row.operation_ordinal - 1
                    && row.verifier_message_round_ordinal > 0
                    && row.output_byte_length > 0
                    && atomic_challenge_fixed_hash_query_count(row.output_byte_length).ok()
                        == Some(row.fixed_hash_query_count)
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProductionStatementChallengeChronologySummary {
    pub(super) construction_plan_identity_hash: [u8; 64],
    pub(super) logical_challenge_count: u64,
    pub(super) first_challenge_operation_ordinal: u32,
    pub(super) last_challenge_operation_ordinal: u32,
    pub(super) canonical_statement_and_header_are_absorbed_first: bool,
    pub(super) every_challenge_has_immediate_predecessor: bool,
}

pub(super) fn checked_production_statement_challenge_chronology_summary(
    plan: &RowCodeWhirConstructionPlan,
    geometry: &RowCodeWhirProductionGeometryCertificate,
) -> Result<ProductionStatementChallengeChronologySummary, WhirTheoremCertificateError> {
    let certificate =
        ProductionStatementChallengeChronologyCertificate::derive_from_geometry(plan, geometry)?;
    let first_challenge_operation_ordinal = certificate
        .challenge_rows
        .first()
        .map(|row| row.operation_ordinal)
        .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    let last_challenge_operation_ordinal = certificate
        .challenge_rows
        .last()
        .map(|row| row.operation_ordinal)
        .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    Ok(ProductionStatementChallengeChronologySummary {
        construction_plan_identity_hash: certificate.construction_plan_identity_hash,
        logical_challenge_count: u64::try_from(certificate.challenge_rows.len())
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        first_challenge_operation_ordinal,
        last_challenge_operation_ordinal,
        canonical_statement_and_header_are_absorbed_first: certificate.initial_operation_ordinal
            == 0
            && certificate.canonical_header_root_equation_slot_ordinal == 0
            && certificate.initial_absorption_equation_slot_ordinal == 1
            && first_challenge_operation_ordinal > certificate.initial_operation_ordinal,
        every_challenge_has_immediate_predecessor: certificate.challenge_rows.iter().all(|row| {
            row.immediate_predecessor_operation_ordinal.checked_add(1)
                == Some(row.operation_ordinal)
        }),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MappedConstructionSoundnessSummary {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    construction_plan_identity_hash: [u8; 64],
    logical_verifier_message_count: u64,
    family_application_multiplicity: u64,
    adversarial_query_bound: BigUint,
    verifier_hash_query_count: u64,
    accepting_database_equation_count: u64,
    oracle_output_bit_length: usize,
    fixed_output_sampler_reduction: Cms19FixedOutputSeededSamplerReduction,
    fixed_output_oracle_graph_identity_hash: [u8; 64],
    classical_failure_probability_ceiling: ExactBigFraction,
    primary_oracle_qrom_failure_probability_at_declared_budget: ExactBigFraction,
    auxiliary_table_bad_event_probability_ceiling: ExactBigFraction,
    qrom_failure_probability_at_declared_budget: ExactBigFraction,
    every_failure_owner_is_mapped_once: bool,
    exact_query_products_are_bounded: bool,
    statement_challenge_chronology: ProductionStatementChallengeChronologyCertificate,
    requires_verified_vss_bound_prerequisite: bool,
    requires_verified_setup_polynomial_bound_prerequisite: bool,
}

impl MappedConstructionSoundnessSummary {
    fn from_checked_production(
        plan: &RowCodeWhirConstructionPlan,
        prerequisites: &ProductionSoundnessPrerequisites,
        soundness: &ProductionMappedSoundnessCertificate,
    ) -> Result<Self, WhirTheoremCertificateError> {
        let exact_failure = &soundness.exact_failure_magnitude;
        let statement_challenge_chronology =
            ProductionStatementChallengeChronologyCertificate::derive(plan, soundness)?;
        let oracle_output_bit_length = match soundness.cms19_arithmetic.oracle_model_requirement {
            Cms19ArithmeticOracleModelRequirement::FixedOutputRandomOracle {
                output_bit_length,
            } => output_bit_length,
        };
        let fixed_output_oracle_graph_input = Cms19FixedOutputOracleGraphInput {
            plan,
            partition: &soundness
                .cms19_arithmetic
                .separated_oracle_projection
                .concrete_shake256_partition,
            selected_plan_state_predicate: &soundness.selected_plan_state_predicate,
            whole_state_transitions: &soundness.cms19_whole_state_transitions,
            whole_database_support: &soundness.cms19_whole_database_support,
            commitment_subtree_extraction: &soundness.commitment_subtree_extraction,
            nonlinear_commitment_binding: &soundness.nonlinear_commitment_binding,
            atomic_round_semantics: &soundness.cms19_atomic_round_semantics,
            deployed_leaf_oracle: &soundness.deployed_aggregate_leaf_oracle,
            sampler_model: &soundness.cms19_fixed_output_seeded_sampler_model,
            strong_round_semantics: &soundness.cms19_strong_round_by_round_semantics,
            state_predicate: &soundness.cms19_state_predicate,
            exact_failure: &soundness.exact_failure_magnitude,
            arithmetic: &soundness.cms19_arithmetic,
        };
        if !soundness.cms19_state_predicate.is_complete()
            || !soundness
                .cms19_strong_round_by_round_semantics
                .is_complete()
            || !soundness
                .cms19_fixed_output_oracle_graph
                .is_complete_for(fixed_output_oracle_graph_input)
            || !plan.oracle_equation_catalog().is_ok_and(|catalog| {
                soundness
                    .cms19_transcript_oracle_output_inventory
                    .is_complete_for(plan, &catalog)
                    && soundness
                        .cms19_fixed_output_seeded_sampler_model
                        .matches_production_width_inventory(
                            &soundness.cms19_transcript_oracle_output_inventory,
                        )
                    && soundness
                        .cms19_fixed_output_seeded_sampler_model
                        .classical_sampler_distribution
                        .relation_plan_variant_hash
                        == plan.relation_plan_variant_hash
            })
        {
            return Err(WhirTheoremCertificateError::IncompleteFixedOutputOracleGraph);
        }
        let fixed_output_oracle_graph_identity_hash = soundness
            .cms19_fixed_output_oracle_graph
            .canonical_identity_hash()?;
        let summary = Self {
            application_statement_schema_identifier: plan.application_statement_schema_identifier,
            schedule_position: plan.schedule_position,
            top_count: plan.top_count,
            construction_plan_identity_hash: prerequisites.construction_plan_identity_hash,
            logical_verifier_message_count: soundness.logical_verifier_message_count,
            family_application_multiplicity: exact_failure.family_application_multiplicity,
            adversarial_query_bound: soundness.cms19_arithmetic.adversarial_query_bound.clone(),
            verifier_hash_query_count: soundness.cms19_arithmetic.verifier_hash_query_count,
            accepting_database_equation_count: soundness
                .cms19_arithmetic
                .accepting_database_equation_count,
            oracle_output_bit_length,
            fixed_output_sampler_reduction: soundness
                .cms19_fixed_output_seeded_sampler_model
                .reduction,
            fixed_output_oracle_graph_identity_hash,
            classical_failure_probability_ceiling: exact_failure
                .classical_failure_probability_ceiling
                .clone(),
            primary_oracle_qrom_failure_probability_at_declared_budget: exact_failure
                .cms19_primary_oracle_qrom_failure_probability_ceiling
                .clone(),
            auxiliary_table_bad_event_probability_ceiling: exact_failure
                .auxiliary_table_bad_event_probability_ceiling
                .clone(),
            qrom_failure_probability_at_declared_budget: exact_failure
                .qrom_failure_probability_ceiling
                .clone(),
            every_failure_owner_is_mapped_once: exact_failure.all_failure_owners_mapped_once,
            exact_query_products_are_bounded: exact_failure.exact_query_products_bounded,
            statement_challenge_chronology,
            requires_verified_vss_bound_prerequisite: plan
                .requires_verified_vss_bound_prerequisite(),
            requires_verified_setup_polynomial_bound_prerequisite: plan
                .requires_verified_setup_polynomial_bound_prerequisite(),
        };
        if !summary.is_complete() {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        Ok(summary)
    }

    fn is_complete(&self) -> bool {
        self.application_statement_schema_identifier != 0
            && self.construction_plan_identity_hash != [0_u8; 64]
            && self.logical_verifier_message_count > 0
            && self.family_application_multiplicity > 0
            && self.adversarial_query_bound == BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            && self.verifier_hash_query_count > 0
            && self.accepting_database_equation_count > 0
            && self.oracle_output_bit_length == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
            && self.fixed_output_sampler_reduction
                == Cms19FixedOutputSeededSamplerReduction::DomainSeparatedPredecessorLinkedFixedHashSamplerV1
            && self.fixed_output_oracle_graph_identity_hash != [0_u8; 64]
            && !self
                .classical_failure_probability_ceiling
                .numerator
                .is_zero()
            && !self
                .primary_oracle_qrom_failure_probability_at_declared_budget
                .numerator
                .is_zero()
            && !self
                .auxiliary_table_bad_event_probability_ceiling
                .numerator
                .is_zero()
            && !self
                .qrom_failure_probability_at_declared_budget
                .numerator
                .is_zero()
            && self.every_failure_owner_is_mapped_once
            && self.exact_query_products_are_bounded
            && self
                .statement_challenge_chronology
                .is_self_consistent(self.logical_verifier_message_count)
            && self
                .statement_challenge_chronology
                .construction_plan_identity_hash
                == self.construction_plan_identity_hash
            && !(self.requires_verified_vss_bound_prerequisite
                && self.requires_verified_setup_polynomial_bound_prerequisite)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MappedConstructionSoundnessEvidenceRow {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    construction_plan_identity_hash: [u8; 64],
    logical_verifier_message_count: u64,
    family_application_multiplicity: u64,
    adversarial_query_bound: BigUint,
    verifier_hash_query_count: u64,
    accepting_database_equation_count: u64,
    oracle_output_bit_length: usize,
    fixed_output_sampler_reduction: Cms19FixedOutputSeededSamplerReduction,
    fixed_output_oracle_graph_identity_hash: [u8; 64],
    classical_failure_probability_ceiling: ExactBigFraction,
    primary_oracle_qrom_failure_probability_at_declared_budget: ExactBigFraction,
    auxiliary_table_bad_event_probability_ceiling: ExactBigFraction,
    qrom_failure_probability_at_declared_budget: ExactBigFraction,
    chronology_hash: [u8; 64],
    initial_operation_ordinal: u32,
    canonical_header_root_equation_slot_ordinal: u64,
    initial_absorption_equation_slot_ordinal: u64,
    first_challenge_operation_ordinal: u32,
    challenge_operation_count: u64,
    requires_verified_vss_bound_prerequisite: bool,
    requires_verified_setup_polynomial_bound_prerequisite: bool,
}

impl MappedConstructionSoundnessEvidenceRow {
    fn from_checked_summary(
        summary: &MappedConstructionSoundnessSummary,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if !summary.is_complete() {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        let first_challenge_operation_ordinal = summary
            .statement_challenge_chronology
            .challenge_rows
            .first()
            .map(|row| row.operation_ordinal)
            .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
        let row = Self {
            application_statement_schema_identifier: summary
                .application_statement_schema_identifier,
            schedule_position: summary.schedule_position,
            top_count: summary.top_count,
            construction_plan_identity_hash: summary.construction_plan_identity_hash,
            logical_verifier_message_count: summary.logical_verifier_message_count,
            family_application_multiplicity: summary.family_application_multiplicity,
            adversarial_query_bound: summary.adversarial_query_bound.clone(),
            verifier_hash_query_count: summary.verifier_hash_query_count,
            accepting_database_equation_count: summary.accepting_database_equation_count,
            oracle_output_bit_length: summary.oracle_output_bit_length,
            fixed_output_sampler_reduction: summary.fixed_output_sampler_reduction,
            fixed_output_oracle_graph_identity_hash: summary
                .fixed_output_oracle_graph_identity_hash,
            classical_failure_probability_ceiling: summary
                .classical_failure_probability_ceiling
                .clone(),
            primary_oracle_qrom_failure_probability_at_declared_budget: summary
                .primary_oracle_qrom_failure_probability_at_declared_budget
                .clone(),
            auxiliary_table_bad_event_probability_ceiling: summary
                .auxiliary_table_bad_event_probability_ceiling
                .clone(),
            qrom_failure_probability_at_declared_budget: summary
                .qrom_failure_probability_at_declared_budget
                .clone(),
            chronology_hash: mapped_soundness_chronology_hash(
                &summary.statement_challenge_chronology,
            )?,
            initial_operation_ordinal: summary
                .statement_challenge_chronology
                .initial_operation_ordinal,
            canonical_header_root_equation_slot_ordinal: summary
                .statement_challenge_chronology
                .canonical_header_root_equation_slot_ordinal,
            initial_absorption_equation_slot_ordinal: summary
                .statement_challenge_chronology
                .initial_absorption_equation_slot_ordinal,
            first_challenge_operation_ordinal,
            challenge_operation_count: summary.logical_verifier_message_count,
            requires_verified_vss_bound_prerequisite: summary
                .requires_verified_vss_bound_prerequisite,
            requires_verified_setup_polynomial_bound_prerequisite: summary
                .requires_verified_setup_polynomial_bound_prerequisite,
        };
        if !row.is_complete()
            || mapped_primary_oracle_qrom_failure_for_query_bound(
                &row,
                &row.adversarial_query_bound,
            )? != row.primary_oracle_qrom_failure_probability_at_declared_budget
            || mapped_complete_qrom_failure_for_query_bound(&row, &row.adversarial_query_bound)?
                != row.qrom_failure_probability_at_declared_budget
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        Ok(row)
    }

    fn is_complete(&self) -> bool {
        self.application_statement_schema_identifier != 0
            && self.construction_plan_identity_hash != [0_u8; 64]
            && self.logical_verifier_message_count > 0
            && self.family_application_multiplicity > 0
            && self.adversarial_query_bound == BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            && self.verifier_hash_query_count > 0
            && self.accepting_database_equation_count > 0
            && self.oracle_output_bit_length == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
            && self.fixed_output_sampler_reduction
                == Cms19FixedOutputSeededSamplerReduction::DomainSeparatedPredecessorLinkedFixedHashSamplerV1
            && self.fixed_output_oracle_graph_identity_hash != [0_u8; 64]
            && !self
                .classical_failure_probability_ceiling
                .numerator
                .is_zero()
            && !self
                .primary_oracle_qrom_failure_probability_at_declared_budget
                .numerator
                .is_zero()
            && !self
                .auxiliary_table_bad_event_probability_ceiling
                .numerator
                .is_zero()
            && !self
                .qrom_failure_probability_at_declared_budget
                .numerator
                .is_zero()
            && mapped_primary_oracle_qrom_failure_for_query_bound(
                self,
                &self.adversarial_query_bound,
            )
            .is_ok_and(|expected| {
                expected == self.primary_oracle_qrom_failure_probability_at_declared_budget
            })
            && self
                .primary_oracle_qrom_failure_probability_at_declared_budget
                .add(&self.auxiliary_table_bad_event_probability_ceiling)
                .is_ok_and(|expected| {
                    expected == self.qrom_failure_probability_at_declared_budget
                })
            && self.chronology_hash != [0_u8; 64]
            && self.initial_operation_ordinal == 0
            && self.canonical_header_root_equation_slot_ordinal == 0
            && self.initial_absorption_equation_slot_ordinal == 1
            && self.first_challenge_operation_ordinal > self.initial_operation_ordinal
            && self.challenge_operation_count == self.logical_verifier_message_count
            && !(self.requires_verified_vss_bound_prerequisite
                && self.requires_verified_setup_polynomial_bound_prerequisite)
    }
}

fn exact_failure_owner_kind_tag(kind: ExactFailureOwnerKind) -> u16 {
    match kind {
        ExactFailureOwnerKind::NonNativeThetaProduct => 1,
        ExactFailureOwnerKind::NonNativeAlphaProduct => 2,
        ExactFailureOwnerKind::RelationComposition => 3,
        ExactFailureOwnerKind::OutOfDomainPoint => 4,
        ExactFailureOwnerKind::PointSelector => 5,
        ExactFailureOwnerKind::TraceColumnGroup => 6,
        ExactFailureOwnerKind::QuotientGroup => 7,
        ExactFailureOwnerKind::OpeningBatchMask => 8,
        ExactFailureOwnerKind::BoundOpening => 9,
        ExactFailureOwnerKind::BoundDegreeCoordinate => 10,
        ExactFailureOwnerKind::OuterQueryVector => 11,
        ExactFailureOwnerKind::BoundQueryVector => 12,
        ExactFailureOwnerKind::WhirQueryVector => 13,
        ExactFailureOwnerKind::WhirOpeningBatching => 14,
        ExactFailureOwnerKind::MaskedSumcheckEpsilon => 15,
        ExactFailureOwnerKind::MaskedSumcheckFold => 16,
        ExactFailureOwnerKind::RoundCheckpoint => 17,
        ExactFailureOwnerKind::RoundCombination => 18,
        ExactFailureOwnerKind::BaseCaseBlinding => 19,
    }
}

fn mapped_soundness_chronology_hash(
    chronology: &ProductionStatementChallengeChronologyCertificate,
) -> Result<[u8; 64], WhirTheoremCertificateError> {
    let challenge_count = u64::try_from(chronology.challenge_rows.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut canonical_bytes = Vec::with_capacity(
        64_usize
            .checked_add(32)
            .and_then(|length| length.checked_add(chronology.challenge_rows.len().checked_mul(30)?))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    canonical_bytes.extend_from_slice(&MAPPED_SOUNDNESS_EVIDENCE_FORMAT_VERSION.to_le_bytes());
    canonical_bytes.extend_from_slice(&chronology.construction_plan_identity_hash);
    canonical_bytes.extend_from_slice(&chronology.initial_operation_ordinal.to_le_bytes());
    canonical_bytes.extend_from_slice(
        &chronology
            .canonical_header_root_equation_slot_ordinal
            .to_le_bytes(),
    );
    canonical_bytes.extend_from_slice(
        &chronology
            .initial_absorption_equation_slot_ordinal
            .to_le_bytes(),
    );
    canonical_bytes.extend_from_slice(&challenge_count.to_le_bytes());
    for challenge in &chronology.challenge_rows {
        canonical_bytes.extend_from_slice(&challenge.operation_ordinal.to_le_bytes());
        canonical_bytes.extend_from_slice(
            &challenge
                .immediate_predecessor_operation_ordinal
                .to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(&challenge.verifier_message_round_ordinal.to_le_bytes());
        canonical_bytes.extend_from_slice(&challenge.output_byte_length.to_le_bytes());
        canonical_bytes.extend_from_slice(&challenge.fixed_hash_query_count.to_le_bytes());
        canonical_bytes.extend_from_slice(
            &exact_failure_owner_kind_tag(exact_failure_owner_kind(challenge.failure_event_owner)?)
                .to_le_bytes(),
        );
    }
    Ok(hash_framed_parts_512(
        MAPPED_SOUNDNESS_CHRONOLOGY_HASH_DOMAIN,
        &[&canonical_bytes],
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConservativePhysicalProofFailureRow {
    global_physical_proof_ordinal: u32,
    family_physical_proof_ordinal: u32,
    application_statement_schema_identifier: u16,
    logical_relation_instance_count: u32,
    construction_plan_identity_hash: [u8; 64],
    fixed_output_oracle_graph_identity_hash: [u8; 64],
    adversarial_query_bound: BigUint,
    classical_failure_probability_ceiling: ExactBigFraction,
    primary_oracle_qrom_failure_probability_ceiling: ExactBigFraction,
    auxiliary_table_bad_event_probability_ceiling: ExactBigFraction,
    qrom_failure_probability_ceiling: ExactBigFraction,
    statement_binding: ProductionInitialTranscriptBinding,
    first_challenge_operation_ordinal: u32,
    challenge_operation_count: u64,
    prior_history_treatment: SequentialPriorHistoryTreatment,
    cross_proof_independence_use: CrossProofIndependenceUse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConservativeProofFamilyFailureRow {
    application_statement_schema_identifier: u16,
    physical_proof_application_count: u32,
    logical_relation_instance_count: u32,
    construction_plan_identity_hash: [u8; 64],
    fixed_output_oracle_graph_identity_hash: [u8; 64],
    classical_failure_probability_ceiling: ExactBigFraction,
    primary_oracle_qrom_failure_probability_ceiling: ExactBigFraction,
    auxiliary_table_bad_event_probability_ceiling: ExactBigFraction,
    qrom_failure_probability_ceiling: ExactBigFraction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConservativeActionSoundnessCompositionCertificate {
    action_top_count: u16,
    composition_rule: SequentialSoundnessCompositionRule,
    conditional_oracle_assumption: ConditionalOracleAssumption,
    conditional_oracle_assumption_reference_count: u8,
    mapped_transform_count: u32,
    physical_proof_application_count: u32,
    logical_relation_instance_count: u32,
    ordered_physical_proof_rows: Vec<ConservativePhysicalProofFailureRow>,
    ordered_family_rows: Vec<ConservativeProofFamilyFailureRow>,
    classical_failure_probability_ceiling: ExactBigFraction,
    primary_oracle_qrom_failure_probability_at_declared_budget: ExactBigFraction,
    auxiliary_table_bad_event_probability_ceiling: ExactBigFraction,
    qrom_failure_probability_at_declared_budget: ExactBigFraction,
    declared_adversarial_query_bound: BigUint,
    last_query_bound_with_composed_qrom_ceiling_below_one_half: BigUint,
    first_query_bound_with_composed_qrom_ceiling_at_least_one_half: BigUint,
    ordinary_invalid_acceptance_mass_gate_holds: bool,
    transformed_initial_mass_gate_holds: bool,
    mapped_qrom_contribution_is_at_most_one_quarter: bool,
    auxiliary_table_bad_event_charge_count: u32,
    shared_action_root_hybrid_credit_count: u8,
    claims_one_global_transform: bool,
    claims_concrete_sponge_reduction: bool,
}

impl ConservativeActionSoundnessCompositionCertificate {
    fn is_complete_for(
        &self,
        evidence_rows: &[MappedConstructionSoundnessEvidenceRow],
        inventory: &ProofFamilyApplicationInventory,
        action_top_count: u16,
    ) -> bool {
        derive_conservative_action_soundness_composition(evidence_rows, inventory, action_top_count)
            .is_ok_and(|expected| expected == *self)
    }
}

fn mapped_primary_oracle_qrom_failure_for_query_bound(
    evidence_row: &MappedConstructionSoundnessEvidenceRow,
    adversarial_query_bound: &BigUint,
) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
    let compiler_query_bound =
        adversarial_query_bound + BigUint::from(evidence_row.verifier_hash_query_count);
    let oracle_square_relaxation_constant = evidence_row
        .fixed_output_sampler_reduction
        .oracle_square_relaxation_constant();
    let classical_soundness_coefficient = oracle_square_relaxation_constant
        .checked_mul(
            evidence_row
                .fixed_output_sampler_reduction
                .database_lifting_constant(),
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let ideal_oracle_penalty_coefficient = classical_soundness_coefficient
        .checked_mul(
            evidence_row
                .fixed_output_sampler_reduction
                .database_collision_coefficient(),
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let classical_multiplier = BigUint::from(classical_soundness_coefficient)
        * &compiler_query_bound
        * &compiler_query_bound;
    let classical_term = evidence_row
        .classical_failure_probability_ceiling
        .multiply_integer(&classical_multiplier)?;
    let ideal_oracle_penalty_numerator = BigUint::from(ideal_oracle_penalty_coefficient)
        * &compiler_query_bound
        * &compiler_query_bound
        * &compiler_query_bound
        + BigUint::from(oracle_square_relaxation_constant)
            * BigUint::from(evidence_row.accepting_database_equation_count);
    classical_term.add(&ExactBigFraction::new(
        ideal_oracle_penalty_numerator,
        BigUint::one() << evidence_row.oracle_output_bit_length,
    )?)
}

fn mapped_complete_qrom_failure_for_query_bound(
    evidence_row: &MappedConstructionSoundnessEvidenceRow,
    adversarial_query_bound: &BigUint,
) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
    mapped_primary_oracle_qrom_failure_for_query_bound(evidence_row, adversarial_query_bound)?
        .add(&evidence_row.auxiliary_table_bad_event_probability_ceiling)
}

#[cfg(test)]
fn composed_qrom_failure_for_query_bound(
    evidence_rows: &[MappedConstructionSoundnessEvidenceRow],
    inventory: &ProofFamilyApplicationInventory,
    adversarial_query_bound: &BigUint,
) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
    evidence_rows
        .iter()
        .try_fold(ExactBigFraction::zero(), |total, evidence_row| {
            let multiplicity = inventory
                .family_entry(evidence_row.application_statement_schema_identifier)
                .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?
                .physical_proof_application_count();
            total.add(
                &mapped_complete_qrom_failure_for_query_bound(
                    evidence_row,
                    adversarial_query_bound,
                )?
                .multiply_u64(u64::from(multiplicity))?,
            )
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactComposedQromFailurePolynomial {
    /// Coefficients in ascending degree order, over one exact denominator.
    numerator_coefficients: [BigUint; 4],
    denominator: BigUint,
}

impl ExactComposedQromFailurePolynomial {
    fn derive(
        evidence_rows: &[MappedConstructionSoundnessEvidenceRow],
        inventory: &ProofFamilyApplicationInventory,
    ) -> Result<Self, WhirTheoremCertificateError> {
        let mut fractional_coefficients: [ExactBigFraction; 4] =
            core::array::from_fn(|_| ExactBigFraction::zero());
        let fixed_oracle_denominator = BigUint::one() << CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH;
        for evidence_row in evidence_rows {
            let physical_proof_count = inventory
                .family_entry(evidence_row.application_statement_schema_identifier)
                .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?
                .physical_proof_application_count();
            if u64::from(physical_proof_count) != evidence_row.family_application_multiplicity {
                return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
            }
            let physical_proof_count = BigUint::from(physical_proof_count);
            let verifier_hash_query_count = BigUint::from(evidence_row.verifier_hash_query_count);
            let verifier_hash_query_count_squared =
                &verifier_hash_query_count * &verifier_hash_query_count;
            let verifier_hash_query_count_cubed =
                &verifier_hash_query_count_squared * &verifier_hash_query_count;
            let oracle_square_relaxation_constant = evidence_row
                .fixed_output_sampler_reduction
                .oracle_square_relaxation_constant();
            let classical_soundness_coefficient = oracle_square_relaxation_constant
                .checked_mul(
                    evidence_row
                        .fixed_output_sampler_reduction
                        .database_lifting_constant(),
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            let ideal_oracle_penalty_coefficient = classical_soundness_coefficient
                .checked_mul(
                    evidence_row
                        .fixed_output_sampler_reduction
                        .database_collision_coefficient(),
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

            let physical_classical_coefficient = evidence_row
                .classical_failure_probability_ceiling
                .multiply_integer(
                    &(&physical_proof_count * BigUint::from(classical_soundness_coefficient)),
                )?;
            add_exact_fraction(
                &mut fractional_coefficients[2],
                &physical_classical_coefficient,
            )?;
            add_exact_fraction(
                &mut fractional_coefficients[1],
                &physical_classical_coefficient
                    .multiply_integer(&(&verifier_hash_query_count << 1_usize))?,
            )?;
            add_exact_fraction(
                &mut fractional_coefficients[0],
                &physical_classical_coefficient
                    .multiply_integer(&verifier_hash_query_count_squared)?,
            )?;

            let physical_ideal_oracle_coefficient = ExactBigFraction::new(
                &physical_proof_count * BigUint::from(ideal_oracle_penalty_coefficient),
                fixed_oracle_denominator.clone(),
            )?;
            add_exact_fraction(
                &mut fractional_coefficients[3],
                &physical_ideal_oracle_coefficient,
            )?;
            add_exact_fraction(
                &mut fractional_coefficients[2],
                &physical_ideal_oracle_coefficient
                    .multiply_integer(&(BigUint::from(3_u8) * &verifier_hash_query_count))?,
            )?;
            add_exact_fraction(
                &mut fractional_coefficients[1],
                &physical_ideal_oracle_coefficient.multiply_integer(
                    &(BigUint::from(3_u8) * &verifier_hash_query_count_squared),
                )?,
            )?;
            add_exact_fraction(
                &mut fractional_coefficients[0],
                &physical_ideal_oracle_coefficient
                    .multiply_integer(&verifier_hash_query_count_cubed)?,
            )?;

            let accepting_equation_penalty = ExactBigFraction::new(
                &physical_proof_count
                    * BigUint::from(oracle_square_relaxation_constant)
                    * BigUint::from(evidence_row.accepting_database_equation_count),
                fixed_oracle_denominator.clone(),
            )?;
            add_exact_fraction(&mut fractional_coefficients[0], &accepting_equation_penalty)?;
            add_exact_fraction(
                &mut fractional_coefficients[0],
                &evidence_row
                    .auxiliary_table_bad_event_probability_ceiling
                    .multiply_integer(&physical_proof_count)?,
            )?;
        }

        let denominator = fractional_coefficients.iter().fold(
            BigUint::one(),
            |common_denominator, coefficient| {
                let common_divisor = greatest_common_divisor_big(
                    common_denominator.clone(),
                    coefficient.denominator.clone(),
                );
                common_denominator / common_divisor * &coefficient.denominator
            },
        );
        if denominator.is_zero() {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let numerator_coefficients = fractional_coefficients
            .map(|coefficient| coefficient.numerator * (&denominator / coefficient.denominator));
        Ok(Self {
            numerator_coefficients,
            denominator,
        })
    }

    fn numerator_at(&self, adversarial_query_bound: &BigUint) -> BigUint {
        self.numerator_coefficients
            .iter()
            .rev()
            .fold(BigUint::zero(), |accumulated, coefficient| {
                accumulated * adversarial_query_bound + coefficient
            })
    }

    fn failure_fraction_at(
        &self,
        adversarial_query_bound: &BigUint,
    ) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
        ExactBigFraction::new(
            self.numerator_at(adversarial_query_bound),
            self.denominator.clone(),
        )
    }

    fn is_below_one_half_at(&self, adversarial_query_bound: &BigUint) -> bool {
        (self.numerator_at(adversarial_query_bound) << 1_usize) < self.denominator
    }
}

fn add_exact_fraction(
    destination: &mut ExactBigFraction,
    contribution: &ExactBigFraction,
) -> Result<(), WhirTheoremCertificateError> {
    *destination = destination.add(contribution)?;
    Ok(())
}

fn constant_success_query_boundary(
    failure_polynomial: &ExactComposedQromFailurePolynomial,
    declared_adversarial_query_bound: &BigUint,
) -> Result<(BigUint, BigUint), WhirTheoremCertificateError> {
    if !failure_polynomial.is_below_one_half_at(declared_adversarial_query_bound) {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let one = BigUint::one();
    let mut last_below = declared_adversarial_query_bound.clone();
    let mut first_at_least = (&last_below + &one) << 1_usize;
    let mut expansion_count = 0_usize;
    while failure_polynomial.is_below_one_half_at(&first_at_least) {
        last_below = first_at_least;
        first_at_least = (&last_below + &one) << 1_usize;
        expansion_count = expansion_count
            .checked_add(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        if expansion_count > CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
    }
    while &last_below + &one < first_at_least {
        let midpoint = (&last_below + &first_at_least) >> 1_usize;
        if failure_polynomial.is_below_one_half_at(&midpoint) {
            last_below = midpoint;
        } else {
            first_at_least = midpoint;
        }
    }
    Ok((last_below, first_at_least))
}

fn derive_conservative_action_soundness_composition(
    evidence_rows: &[MappedConstructionSoundnessEvidenceRow],
    inventory: &ProofFamilyApplicationInventory,
    action_top_count: u16,
) -> Result<ConservativeActionSoundnessCompositionCertificate, WhirTheoremCertificateError> {
    if action_top_count == 0
        || action_top_count > FOUNDATION_PROFILE.option_count
        || evidence_rows.len() != inventory.ordered_family_entries().len()
        || evidence_rows.iter().any(|row| !row.is_complete())
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let evaluator_schema_identifier =
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let evidence_rows_by_schema = evidence_rows
        .iter()
        .map(|row| (row.application_statement_schema_identifier, row))
        .collect::<BTreeMap<_, _>>();
    if evidence_rows_by_schema.len() != evidence_rows.len()
        || evidence_rows.iter().any(|row| {
            if row.application_statement_schema_identifier == evaluator_schema_identifier {
                row.top_count != Some(action_top_count)
            } else {
                row.top_count.is_some()
            }
        })
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    let mut ordered_physical_proof_rows = Vec::new();
    let mut ordered_family_rows = Vec::new();
    let mut global_physical_proof_ordinal = 0_u32;
    let mut classical_failure_probability_ceiling = ExactBigFraction::zero();
    let mut primary_oracle_qrom_failure_probability_at_declared_budget = ExactBigFraction::zero();
    let mut auxiliary_table_bad_event_probability_ceiling = ExactBigFraction::zero();
    let mut qrom_failure_probability_at_declared_budget = ExactBigFraction::zero();
    for family in inventory.ordered_family_entries() {
        let evidence_row = evidence_rows_by_schema
            .get(&family.application_statement_schema_identifier())
            .copied()
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let physical_count = family.physical_proof_application_count();
        let logical_count = family.logical_relation_instance_count();
        if physical_count == 0
            || logical_count == 0
            || logical_count % physical_count != 0
            || evidence_row.family_application_multiplicity != u64::from(physical_count)
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        let logical_count_per_proof = logical_count / physical_count;
        let family_classical = evidence_row
            .classical_failure_probability_ceiling
            .multiply_u64(u64::from(physical_count))?;
        let family_primary_oracle_qrom = evidence_row
            .primary_oracle_qrom_failure_probability_at_declared_budget
            .multiply_u64(u64::from(physical_count))?;
        let family_auxiliary_table_bad_event = evidence_row
            .auxiliary_table_bad_event_probability_ceiling
            .multiply_u64(u64::from(physical_count))?;
        let family_qrom = evidence_row
            .qrom_failure_probability_at_declared_budget
            .multiply_u64(u64::from(physical_count))?;
        if family_primary_oracle_qrom.add(&family_auxiliary_table_bad_event)? != family_qrom {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        classical_failure_probability_ceiling =
            classical_failure_probability_ceiling.add(&family_classical)?;
        primary_oracle_qrom_failure_probability_at_declared_budget =
            primary_oracle_qrom_failure_probability_at_declared_budget
                .add(&family_primary_oracle_qrom)?;
        auxiliary_table_bad_event_probability_ceiling =
            auxiliary_table_bad_event_probability_ceiling.add(&family_auxiliary_table_bad_event)?;
        qrom_failure_probability_at_declared_budget =
            qrom_failure_probability_at_declared_budget.add(&family_qrom)?;
        ordered_family_rows.push(ConservativeProofFamilyFailureRow {
            application_statement_schema_identifier: family
                .application_statement_schema_identifier(),
            physical_proof_application_count: physical_count,
            logical_relation_instance_count: logical_count,
            construction_plan_identity_hash: evidence_row.construction_plan_identity_hash,
            fixed_output_oracle_graph_identity_hash: evidence_row
                .fixed_output_oracle_graph_identity_hash,
            classical_failure_probability_ceiling: family_classical,
            primary_oracle_qrom_failure_probability_ceiling: family_primary_oracle_qrom,
            auxiliary_table_bad_event_probability_ceiling: family_auxiliary_table_bad_event,
            qrom_failure_probability_ceiling: family_qrom,
        });
        let first_challenge_operation_ordinal = evidence_row.first_challenge_operation_ordinal;
        for family_physical_proof_ordinal in 0..physical_count {
            ordered_physical_proof_rows.push(ConservativePhysicalProofFailureRow {
                global_physical_proof_ordinal,
                family_physical_proof_ordinal,
                application_statement_schema_identifier: family
                    .application_statement_schema_identifier(),
                logical_relation_instance_count: logical_count_per_proof,
                construction_plan_identity_hash: evidence_row.construction_plan_identity_hash,
                fixed_output_oracle_graph_identity_hash: evidence_row
                    .fixed_output_oracle_graph_identity_hash,
                adversarial_query_bound: evidence_row.adversarial_query_bound.clone(),
                classical_failure_probability_ceiling: evidence_row
                    .classical_failure_probability_ceiling
                    .clone(),
                primary_oracle_qrom_failure_probability_ceiling: evidence_row
                    .primary_oracle_qrom_failure_probability_at_declared_budget
                    .clone(),
                auxiliary_table_bad_event_probability_ceiling: evidence_row
                    .auxiliary_table_bad_event_probability_ceiling
                    .clone(),
                qrom_failure_probability_ceiling: evidence_row
                    .qrom_failure_probability_at_declared_budget
                    .clone(),
                statement_binding:
                    ProductionInitialTranscriptBinding::ProtocolSuiteConstructionSchemaAndCanonicalProofHeader,
                first_challenge_operation_ordinal,
                challenge_operation_count: evidence_row.logical_verifier_message_count,
                prior_history_treatment:
                    SequentialPriorHistoryTreatment::ArbitraryAuxiliaryInputBeforeCurrentStatementBinding,
                cross_proof_independence_use: CrossProofIndependenceUse::None,
            });
            global_physical_proof_ordinal = global_physical_proof_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        }
    }
    let expected_physical_count = inventory
        .total_physical_proof_application_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_logical_count = inventory
        .total_logical_relation_instance_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    if global_physical_proof_ordinal != expected_physical_count
        || ordered_physical_proof_rows
            .iter()
            .enumerate()
            .any(|(ordinal, row)| {
                u32::try_from(ordinal).ok() != Some(row.global_physical_proof_ordinal)
                    || row.statement_binding
                        != ProductionInitialTranscriptBinding::ProtocolSuiteConstructionSchemaAndCanonicalProofHeader
                    || row.first_challenge_operation_ordinal == 0
                    || row.challenge_operation_count == 0
                    || row.adversarial_query_bound
                        != BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
                    || row.fixed_output_oracle_graph_identity_hash == [0_u8; 64]
                    || row
                        .primary_oracle_qrom_failure_probability_ceiling
                        .add(&row.auxiliary_table_bad_event_probability_ceiling)
                        .ok()
                        .as_ref()
                        != Some(&row.qrom_failure_probability_ceiling)
                    || row.prior_history_treatment
                        != SequentialPriorHistoryTreatment::ArbitraryAuxiliaryInputBeforeCurrentStatementBinding
                    || row.cross_proof_independence_use != CrossProofIndependenceUse::None
            })
        || ordered_physical_proof_rows
            .iter()
            .map(|row| row.logical_relation_instance_count)
            .try_fold(0_u32, u32::checked_add)
            != Some(expected_logical_count)
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }

    let one = ExactBigFraction::from_u64(1, 1)?;
    let ordinary_invalid_acceptance_mass_gate_holds = classical_failure_probability_ceiling
        .multiply_integer(&(BigUint::one() << CMS19_ADVERSARIAL_QUERY_EXPONENT))?
        .less_than_or_equal(&one);
    let oracle_square_relaxation_constant = evidence_rows[0]
        .fixed_output_sampler_reduction
        .oracle_square_relaxation_constant();
    let classical_soundness_coefficient = oracle_square_relaxation_constant
        .checked_mul(
            evidence_rows[0]
                .fixed_output_sampler_reduction
                .database_lifting_constant(),
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let transformed_initial_mass_gate_holds = classical_failure_probability_ceiling
        .multiply_integer(&(BigUint::from(classical_soundness_coefficient) << 176_usize))?
        .less_than_or_equal(&one);
    let mapped_qrom_contribution_is_at_most_one_quarter =
        qrom_failure_probability_at_declared_budget
            .less_than_or_equal(&ExactBigFraction::from_u64(1, 4)?);
    let declared_adversarial_query_bound = BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET);
    let composed_qrom_failure_polynomial =
        ExactComposedQromFailurePolynomial::derive(evidence_rows, inventory)?;
    if composed_qrom_failure_polynomial.failure_fraction_at(&declared_adversarial_query_bound)?
        != qrom_failure_probability_at_declared_budget
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let (
        last_query_bound_with_composed_qrom_ceiling_below_one_half,
        first_query_bound_with_composed_qrom_ceiling_at_least_one_half,
    ) = constant_success_query_boundary(
        &composed_qrom_failure_polynomial,
        &declared_adversarial_query_bound,
    )?;
    if !ordinary_invalid_acceptance_mass_gate_holds
        || !transformed_initial_mass_gate_holds
        || !mapped_qrom_contribution_is_at_most_one_quarter
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    Ok(ConservativeActionSoundnessCompositionCertificate {
        action_top_count,
        composition_rule:
            SequentialSoundnessCompositionRule::EarliestInvalidAcceptanceWithStatementFixedBeforeOwnChallenges,
        conditional_oracle_assumption:
            ConditionalOracleAssumption::SingleFixed512BitQroWithPrecommittedAuxiliaryRestriction,
        conditional_oracle_assumption_reference_count: 1,
        mapped_transform_count: expected_physical_count,
        physical_proof_application_count: expected_physical_count,
        logical_relation_instance_count: expected_logical_count,
        ordered_physical_proof_rows,
        ordered_family_rows,
        classical_failure_probability_ceiling,
        primary_oracle_qrom_failure_probability_at_declared_budget,
        auxiliary_table_bad_event_probability_ceiling,
        qrom_failure_probability_at_declared_budget,
        declared_adversarial_query_bound,
        last_query_bound_with_composed_qrom_ceiling_below_one_half,
        first_query_bound_with_composed_qrom_ceiling_at_least_one_half,
        ordinary_invalid_acceptance_mass_gate_holds,
        transformed_initial_mass_gate_holds,
        mapped_qrom_contribution_is_at_most_one_quarter,
        auxiliary_table_bad_event_charge_count: expected_physical_count,
        shared_action_root_hybrid_credit_count: 0,
        claims_one_global_transform: false,
        claims_concrete_sponge_reduction: false,
    })
}

fn checked_selected_mapped_soundness_summary(
    artifact: &ValidatedRelationPlanArtifact,
    schema_identifier: u16,
    action_top_count: u16,
    aggregate_wide_masking_certificates: &mut Vec<(
        RowCodeWhirSelectedParameters,
        AggregateWideMaskingCertificate,
    )>,
) -> Result<MappedConstructionSoundnessEvidenceRow, WhirTheoremCertificateError> {
    if artifact.application_statement_schema_identifier() != schema_identifier {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let matching_variants = artifact
        .compiled_plan()
        .variants()
        .iter()
        .filter(|variant| {
            if schema_identifier
                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            {
                variant.top_count() == Some(action_top_count)
            } else {
                variant.top_count().is_none()
            }
        })
        .collect::<Vec<_>>();
    let [relation_variant] = matching_variants.as_slice() else {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    };
    let relation_context = selected_relation_plan_check_context(schema_identifier)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let plan = RowCodeWhirConstructionPlan::for_selected_variant(
        artifact,
        relation_variant.schedule_position(),
        relation_variant.top_count(),
    )
    .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let prerequisites = checked_production_soundness_prerequisites(
        &plan,
        artifact,
        relation_variant,
        &relation_context,
    )?;
    let masking_certificate_index = if let Some(index) = aggregate_wide_masking_certificates
        .iter()
        .position(|(parameters, _)| *parameters == prerequisites.parameters)
    {
        index
    } else {
        let hiding_configuration =
            super::super::super::hiding_whir::selected_hiding_whir_config(prerequisites.parameters)
                .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        let masking_certificate = AggregateWideMaskingCertificate::derive(&hiding_configuration)
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        aggregate_wide_masking_certificates.push((prerequisites.parameters, masking_certificate));
        aggregate_wide_masking_certificates.len() - 1
    };
    let started_at = Instant::now();
    eprintln!(
        "checking mapped soundness schema {schema_identifier:#06x}, schedule {:?}, top count {:?}",
        relation_variant.schedule_position(),
        relation_variant.top_count(),
    );
    let soundness = checked_production_mapped_soundness_certificate(
        &plan,
        relation_variant,
        &relation_context,
        &aggregate_wide_masking_certificates[masking_certificate_index].1,
        &prerequisites,
    )?;
    let summary = MappedConstructionSoundnessSummary::from_checked_production(
        &plan,
        &prerequisites,
        &soundness,
    )?;
    let evidence_row = MappedConstructionSoundnessEvidenceRow::from_checked_summary(&summary)?;
    eprintln!(
        "checked mapped soundness schema {schema_identifier:#06x}, schedule {:?}, top count {:?} in {:?}",
        relation_variant.schedule_position(),
        relation_variant.top_count(),
        started_at.elapsed(),
    );
    Ok(evidence_row)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactFractionEvidenceRecord {
    numerator_decimal: String,
    denominator_decimal: String,
}

impl ExactFractionEvidenceRecord {
    fn from_fraction(fraction: &ExactBigFraction) -> Self {
        Self {
            numerator_decimal: fraction.numerator.to_string(),
            denominator_decimal: fraction.denominator.to_string(),
        }
    }

    fn to_fraction(&self) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
        ExactBigFraction::new(
            parse_canonical_decimal_big_uint(&self.numerator_decimal)?,
            parse_canonical_decimal_big_uint(&self.denominator_decimal)?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappedConstructionSoundnessEvidenceRecord {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    construction_plan_identity_hash_hex: String,
    logical_verifier_message_count: u64,
    family_application_multiplicity: u64,
    adversarial_query_bound_decimal: String,
    verifier_hash_query_count: u64,
    accepting_database_equation_count: u64,
    oracle_output_bit_length: u16,
    fixed_output_sampler_reduction: String,
    fixed_output_oracle_graph_identity_hash_hex: String,
    classical_failure_probability_ceiling: ExactFractionEvidenceRecord,
    primary_oracle_qrom_failure_probability_at_declared_budget: ExactFractionEvidenceRecord,
    auxiliary_table_bad_event_probability_ceiling: ExactFractionEvidenceRecord,
    qrom_failure_probability_at_declared_budget: ExactFractionEvidenceRecord,
    chronology_hash_hex: String,
    initial_operation_ordinal: u32,
    canonical_header_root_equation_slot_ordinal: u64,
    initial_absorption_equation_slot_ordinal: u64,
    first_challenge_operation_ordinal: u32,
    challenge_operation_count: u64,
    requires_verified_vss_bound_prerequisite: bool,
    requires_verified_setup_polynomial_bound_prerequisite: bool,
}

impl MappedConstructionSoundnessEvidenceRecord {
    fn from_evidence_row(
        row: &MappedConstructionSoundnessEvidenceRow,
    ) -> Result<Self, WhirTheoremCertificateError> {
        Ok(Self {
            application_statement_schema_identifier: row.application_statement_schema_identifier,
            schedule_position: row.schedule_position,
            top_count: row.top_count,
            construction_plan_identity_hash_hex: to_hex(&row.construction_plan_identity_hash),
            logical_verifier_message_count: row.logical_verifier_message_count,
            family_application_multiplicity: row.family_application_multiplicity,
            adversarial_query_bound_decimal: row.adversarial_query_bound.to_string(),
            verifier_hash_query_count: row.verifier_hash_query_count,
            accepting_database_equation_count: row.accepting_database_equation_count,
            oracle_output_bit_length: u16::try_from(row.oracle_output_bit_length)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            fixed_output_sampler_reduction: row
                .fixed_output_sampler_reduction
                .evidence_identifier()
                .to_owned(),
            fixed_output_oracle_graph_identity_hash_hex: to_hex(
                &row.fixed_output_oracle_graph_identity_hash,
            ),
            classical_failure_probability_ceiling: ExactFractionEvidenceRecord::from_fraction(
                &row.classical_failure_probability_ceiling,
            ),
            primary_oracle_qrom_failure_probability_at_declared_budget:
                ExactFractionEvidenceRecord::from_fraction(
                    &row.primary_oracle_qrom_failure_probability_at_declared_budget,
                ),
            auxiliary_table_bad_event_probability_ceiling:
                ExactFractionEvidenceRecord::from_fraction(
                    &row.auxiliary_table_bad_event_probability_ceiling,
                ),
            qrom_failure_probability_at_declared_budget: ExactFractionEvidenceRecord::from_fraction(
                &row.qrom_failure_probability_at_declared_budget,
            ),
            chronology_hash_hex: to_hex(&row.chronology_hash),
            initial_operation_ordinal: row.initial_operation_ordinal,
            canonical_header_root_equation_slot_ordinal: row
                .canonical_header_root_equation_slot_ordinal,
            initial_absorption_equation_slot_ordinal: row.initial_absorption_equation_slot_ordinal,
            first_challenge_operation_ordinal: row.first_challenge_operation_ordinal,
            challenge_operation_count: row.challenge_operation_count,
            requires_verified_vss_bound_prerequisite: row.requires_verified_vss_bound_prerequisite,
            requires_verified_setup_polynomial_bound_prerequisite: row
                .requires_verified_setup_polynomial_bound_prerequisite,
        })
    }

    fn to_evidence_row(
        &self,
    ) -> Result<MappedConstructionSoundnessEvidenceRow, WhirTheoremCertificateError> {
        let row = MappedConstructionSoundnessEvidenceRow {
            application_statement_schema_identifier: self.application_statement_schema_identifier,
            schedule_position: self.schedule_position,
            top_count: self.top_count,
            construction_plan_identity_hash: decode_lowercase_hex_hash(
                &self.construction_plan_identity_hash_hex,
            )?,
            logical_verifier_message_count: self.logical_verifier_message_count,
            family_application_multiplicity: self.family_application_multiplicity,
            adversarial_query_bound: parse_canonical_decimal_big_uint(
                &self.adversarial_query_bound_decimal,
            )?,
            verifier_hash_query_count: self.verifier_hash_query_count,
            accepting_database_equation_count: self.accepting_database_equation_count,
            oracle_output_bit_length: usize::from(self.oracle_output_bit_length),
            fixed_output_sampler_reduction:
                Cms19FixedOutputSeededSamplerReduction::from_evidence_identifier(
                    &self.fixed_output_sampler_reduction,
                )
                .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
            fixed_output_oracle_graph_identity_hash: decode_lowercase_hex_hash(
                &self.fixed_output_oracle_graph_identity_hash_hex,
            )?,
            classical_failure_probability_ceiling: self
                .classical_failure_probability_ceiling
                .to_fraction()?,
            primary_oracle_qrom_failure_probability_at_declared_budget: self
                .primary_oracle_qrom_failure_probability_at_declared_budget
                .to_fraction()?,
            auxiliary_table_bad_event_probability_ceiling: self
                .auxiliary_table_bad_event_probability_ceiling
                .to_fraction()?,
            qrom_failure_probability_at_declared_budget: self
                .qrom_failure_probability_at_declared_budget
                .to_fraction()?,
            chronology_hash: decode_lowercase_hex_hash(&self.chronology_hash_hex)?,
            initial_operation_ordinal: self.initial_operation_ordinal,
            canonical_header_root_equation_slot_ordinal: self
                .canonical_header_root_equation_slot_ordinal,
            initial_absorption_equation_slot_ordinal: self.initial_absorption_equation_slot_ordinal,
            first_challenge_operation_ordinal: self.first_challenge_operation_ordinal,
            challenge_operation_count: self.challenge_operation_count,
            requires_verified_vss_bound_prerequisite: self.requires_verified_vss_bound_prerequisite,
            requires_verified_setup_polynomial_bound_prerequisite: self
                .requires_verified_setup_polynomial_bound_prerequisite,
        };
        if !row.is_complete()
            || mapped_primary_oracle_qrom_failure_for_query_bound(
                &row,
                &row.adversarial_query_bound,
            )? != row.primary_oracle_qrom_failure_probability_at_declared_budget
            || mapped_complete_qrom_failure_for_query_bound(&row, &row.adversarial_query_bound)?
                != row.qrom_failure_probability_at_declared_budget
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        Ok(row)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappedSoundnessEvidenceDocument {
    format_version: u16,
    action_top_count: u16,
    conditional_oracle_model: String,
    rows: Vec<MappedConstructionSoundnessEvidenceRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappedSoundnessCheckpointRecord {
    format_version: u16,
    row_digest_hex: String,
    row: MappedConstructionSoundnessEvidenceRecord,
}

fn parse_canonical_decimal_big_uint(decimal: &str) -> Result<BigUint, WhirTheoremCertificateError> {
    if decimal.is_empty()
        || (decimal.len() > 1 && decimal.starts_with('0'))
        || !decimal.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let value = BigUint::parse_bytes(decimal.as_bytes(), 10)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if value.to_string() != decimal {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    Ok(value)
}

fn decode_lowercase_hex_hash(encoded: &str) -> Result<[u8; 64], WhirTheoremCertificateError> {
    if encoded.len() != 128 {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let decode_nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut decoded = [0_u8; 64];
    for (byte_ordinal, encoded_byte) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(encoded_byte[0])
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let low = decode_nibble(encoded_byte[1])
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        decoded[byte_ordinal] = (high << 4) | low;
    }
    Ok(decoded)
}

fn repository_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn mapped_soundness_evidence_path() -> PathBuf {
    repository_root_path()
        .join("test-vectors")
        .join(MAPPED_SOUNDNESS_EVIDENCE_FILE_NAME)
}

fn mapped_soundness_checkpoint_path(schema_identifier: u16) -> PathBuf {
    repository_root_path()
        .join("temp")
        .join("test-checkpoints")
        .join(format!(
            "{MAPPED_SOUNDNESS_CHECKPOINT_FILE_STEM}-schema-{schema_identifier:04x}.json"
        ))
}

fn mapped_soundness_combined_checkpoint_path() -> PathBuf {
    repository_root_path()
        .join("temp")
        .join("test-checkpoints")
        .join(MAPPED_SOUNDNESS_COMBINED_CHECKPOINT_FILE_NAME)
}

fn canonical_record_bytes(
    record: &MappedConstructionSoundnessEvidenceRecord,
) -> Result<Vec<u8>, WhirTheoremCertificateError> {
    serde_json::to_vec(record).map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)
}

fn checkpoint_for_evidence_row(
    row: &MappedConstructionSoundnessEvidenceRow,
) -> Result<MappedSoundnessCheckpointRecord, WhirTheoremCertificateError> {
    let record = MappedConstructionSoundnessEvidenceRecord::from_evidence_row(row)?;
    let canonical_bytes = canonical_record_bytes(&record)?;
    Ok(MappedSoundnessCheckpointRecord {
        format_version: MAPPED_SOUNDNESS_EVIDENCE_FORMAT_VERSION,
        row_digest_hex: to_hex(&hash_framed_parts_512(
            MAPPED_SOUNDNESS_CHECKPOINT_HASH_DOMAIN,
            &[&canonical_bytes],
        )),
        row: record,
    })
}

fn validate_checkpoint(
    checkpoint: &MappedSoundnessCheckpointRecord,
) -> Result<MappedConstructionSoundnessEvidenceRow, WhirTheoremCertificateError> {
    let canonical_bytes = canonical_record_bytes(&checkpoint.row)?;
    if checkpoint.format_version != MAPPED_SOUNDNESS_EVIDENCE_FORMAT_VERSION
        || checkpoint.row_digest_hex
            != to_hex(&hash_framed_parts_512(
                MAPPED_SOUNDNESS_CHECKPOINT_HASH_DOMAIN,
                &[&canonical_bytes],
            ))
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    checkpoint.row.to_evidence_row()
}

fn persist_mapped_soundness_checkpoint(
    row: &MappedConstructionSoundnessEvidenceRow,
) -> Result<(), WhirTheoremCertificateError> {
    let checkpoint = checkpoint_for_evidence_row(row)?;
    let path = mapped_soundness_checkpoint_path(row.application_statement_schema_identifier);
    if let Ok(existing_bytes) = fs::read(&path) {
        let existing: MappedSoundnessCheckpointRecord = serde_json::from_slice(&existing_bytes)
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        if validate_checkpoint(&existing)? != *row || existing != checkpoint {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    fs::create_dir_all(parent).map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let mut encoded = serde_json::to_vec_pretty(&checkpoint)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    encoded.push(b'\n');
    fs::write(path, encoded).map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)
}

fn load_mapped_soundness_checkpoint(
    schema_identifier: u16,
) -> Result<MappedConstructionSoundnessEvidenceRow, WhirTheoremCertificateError> {
    let encoded = fs::read(mapped_soundness_checkpoint_path(schema_identifier))
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let checkpoint: MappedSoundnessCheckpointRecord = serde_json::from_slice(&encoded)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let row = validate_checkpoint(&checkpoint)?;
    if row.application_statement_schema_identifier != schema_identifier {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    Ok(row)
}

fn parse_mapped_soundness_evidence_document(
    encoded: &[u8],
) -> Result<
    (
        MappedSoundnessEvidenceDocument,
        Vec<MappedConstructionSoundnessEvidenceRow>,
    ),
    WhirTheoremCertificateError,
> {
    let document: MappedSoundnessEvidenceDocument = serde_json::from_slice(encoded)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if document.format_version != MAPPED_SOUNDNESS_EVIDENCE_FORMAT_VERSION
        || document.action_top_count != FOUNDATION_PROFILE.option_count
        || document.conditional_oracle_model != MAPPED_SOUNDNESS_CONDITIONAL_ORACLE_MODEL
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let rows = document
        .rows
        .iter()
        .map(MappedConstructionSoundnessEvidenceRecord::to_evidence_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((document, rows))
}

fn load_tracked_mapped_soundness_evidence() -> Result<
    (
        MappedSoundnessEvidenceDocument,
        Vec<MappedConstructionSoundnessEvidenceRow>,
    ),
    WhirTheoremCertificateError,
> {
    let encoded = fs::read(mapped_soundness_evidence_path())
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    parse_mapped_soundness_evidence_document(&encoded)
}

fn checked_selected_action_soundness_composition(
    action_top_count: u16,
) -> Result<
    (
        ConservativeActionSoundnessCompositionCertificate,
        Vec<MappedConstructionSoundnessEvidenceRow>,
        ProofFamilyApplicationInventory,
    ),
    WhirTheoremCertificateError,
> {
    if action_top_count != FOUNDATION_PROFILE.option_count {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let inventory = derive_selected_proof_family_application_inventory()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let (_, evidence_rows) = load_tracked_mapped_soundness_evidence()?;
    validate_mapped_soundness_evidence_rows(&evidence_rows, &inventory, action_top_count)?;
    let certificate = derive_conservative_action_soundness_composition(
        &evidence_rows,
        &inventory,
        action_top_count,
    )?;
    Ok((certificate, evidence_rows, inventory))
}

fn validate_mapped_soundness_evidence_rows(
    evidence_rows: &[MappedConstructionSoundnessEvidenceRow],
    inventory: &ProofFamilyApplicationInventory,
    action_top_count: u16,
) -> Result<(), WhirTheoremCertificateError> {
    // Each isolated schema owner derives its row from the current production
    // plan before either comparing it with tracked evidence or persisting an
    // authenticated checkpoint. Composition owns the imported row bytes,
    // inventory order, multiplicities, and cross-proof arithmetic; rebuilding
    // all production plans here would merge those independent owners into one
    // long-running test without adding a second correspondence argument.
    if action_top_count != FOUNDATION_PROFILE.option_count
        || evidence_rows.len() != inventory.ordered_family_entries().len()
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    for (row, family) in evidence_rows.iter().zip(inventory.ordered_family_entries()) {
        let schema_identifier = family.application_statement_schema_identifier();
        if !row.is_complete()
            || row.application_statement_schema_identifier != schema_identifier
            || row.family_application_multiplicity
                != u64::from(family.physical_proof_application_count())
            || if schema_identifier
                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            {
                row.top_count != Some(action_top_count)
            } else {
                row.top_count.is_some()
            }
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
    }
    Ok(())
}

fn consolidate_mapped_soundness_checkpoints() -> Result<PathBuf, WhirTheoremCertificateError> {
    let action_top_count = FOUNDATION_PROFILE.option_count;
    let inventory = derive_selected_proof_family_application_inventory()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let evidence_rows = inventory
        .ordered_family_entries()
        .iter()
        .map(|family| {
            load_mapped_soundness_checkpoint(family.application_statement_schema_identifier())
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_mapped_soundness_evidence_rows(&evidence_rows, &inventory, action_top_count)?;
    let certificate = derive_conservative_action_soundness_composition(
        &evidence_rows,
        &inventory,
        action_top_count,
    )?;
    if !certificate.is_complete_for(&evidence_rows, &inventory, action_top_count) {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let document = MappedSoundnessEvidenceDocument {
        format_version: MAPPED_SOUNDNESS_EVIDENCE_FORMAT_VERSION,
        action_top_count,
        conditional_oracle_model: MAPPED_SOUNDNESS_CONDITIONAL_ORACLE_MODEL.to_owned(),
        rows: evidence_rows
            .iter()
            .map(MappedConstructionSoundnessEvidenceRecord::from_evidence_row)
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut encoded = serde_json::to_vec_pretty(&document)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    encoded.push(b'\n');
    let path = mapped_soundness_combined_checkpoint_path();
    if let Ok(existing) = fs::read(&path) {
        if existing != encoded {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        return Ok(path);
    }
    let parent = path
        .parent()
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    fs::create_dir_all(parent).map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    fs::write(&path, encoded).map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    Ok(path)
}

#[cfg(test)]
fn synthetic_mapped_soundness_summaries(
    inventory: &ProofFamilyApplicationInventory,
    action_top_count: u16,
) -> Vec<MappedConstructionSoundnessEvidenceRow> {
    inventory
        .ordered_family_entries()
        .iter()
        .enumerate()
        .map(|(family_index, family)| {
            let schema_identifier = family.application_statement_schema_identifier();
            let schedule_position = matches!(schema_identifier, 0x1214..=0x1217)
                .then_some(0);
            let top_count = (schema_identifier
                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER)
                .then_some(action_top_count);
            let mut construction_plan_identity_hash = [0_u8; 64];
            construction_plan_identity_hash[0] = u8::try_from(family_index + 1)
                .expect("the synthetic family index fits one byte");
            let chronology = ProductionStatementChallengeChronologyCertificate {
                construction_plan_identity_hash,
                initial_binding:
                    ProductionInitialTranscriptBinding::ProtocolSuiteConstructionSchemaAndCanonicalProofHeader,
                initial_operation_ordinal: 0,
                canonical_header_root_equation_slot_ordinal: 0,
                initial_absorption_equation_slot_ordinal: 1,
                challenge_rows: vec![ProductionChallengeChronologyRow {
                    operation_ordinal: 1,
                    immediate_predecessor_operation_ordinal: 0,
                    verifier_message_round_ordinal: 1,
                    output_byte_length: 64,
                    fixed_hash_query_count: 2,
                    failure_event_owner: SelectedPlanFailureEventOwner::CommonExtensionChallenge {
                        challenge: CommonProofChallenge::Composition {
                            constraint_ordinal: 0,
                        },
                    },
                }],
            };
            let mut evidence_row = MappedConstructionSoundnessEvidenceRow {
                application_statement_schema_identifier: schema_identifier,
                schedule_position,
                top_count,
                construction_plan_identity_hash,
                logical_verifier_message_count: 1,
                family_application_multiplicity: u64::from(
                    family.physical_proof_application_count(),
                ),
                adversarial_query_bound: BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
                verifier_hash_query_count: u64::try_from(family_index + 100)
                    .expect("the synthetic verifier count fits u64"),
                accepting_database_equation_count: u64::try_from(family_index + 90)
                    .expect("the synthetic equation count fits u64"),
                oracle_output_bit_length: CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
                fixed_output_sampler_reduction:
                    Cms19FixedOutputSeededSamplerReduction::DomainSeparatedPredecessorLinkedFixedHashSamplerV1,
                fixed_output_oracle_graph_identity_hash: hash_framed_parts_512(
                    "sealed-lattice/test/synthetic-fixed-output-oracle-graph",
                    &[&construction_plan_identity_hash],
                ),
                classical_failure_probability_ceiling: ExactBigFraction::new(
                    BigUint::one(),
                    BigUint::one() << 400_usize,
                )
                .expect("the synthetic classical failure derives"),
                primary_oracle_qrom_failure_probability_at_declared_budget:
                    ExactBigFraction::zero(),
                auxiliary_table_bad_event_probability_ceiling: ExactBigFraction::new(
                    BigUint::one(),
                    BigUint::one() << 512_usize,
                )
                .expect("the synthetic auxiliary-table bad event derives"),
                qrom_failure_probability_at_declared_budget: ExactBigFraction::zero(),
                chronology_hash: mapped_soundness_chronology_hash(&chronology)
                    .expect("the synthetic chronology hash derives"),
                initial_operation_ordinal: chronology.initial_operation_ordinal,
                canonical_header_root_equation_slot_ordinal: chronology
                    .canonical_header_root_equation_slot_ordinal,
                initial_absorption_equation_slot_ordinal: chronology
                    .initial_absorption_equation_slot_ordinal,
                first_challenge_operation_ordinal: 1,
                challenge_operation_count: 1,
                requires_verified_vss_bound_prerequisite: schema_identifier
                    == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                requires_verified_setup_polynomial_bound_prerequisite: false,
            };
            evidence_row.primary_oracle_qrom_failure_probability_at_declared_budget =
                mapped_primary_oracle_qrom_failure_for_query_bound(
                    &evidence_row,
                    &evidence_row.adversarial_query_bound,
                )
                .expect("the synthetic primary-oracle QROM failure derives");
            evidence_row.qrom_failure_probability_at_declared_budget =
                mapped_complete_qrom_failure_for_query_bound(
                    &evidence_row,
                    &evidence_row.adversarial_query_bound,
                )
                .expect("the synthetic complete QROM failure derives");
            evidence_row
        })
        .collect()
}

#[cfg(test)]
fn inverse_power_of_two_interval(fraction: &ExactBigFraction) -> (usize, usize) {
    let mut upper_exponent = 0_usize;
    while fraction.is_at_most_inverse_power_of_two(upper_exponent) {
        upper_exponent += 1;
        assert!(
            upper_exponent <= 1_024,
            "failure exponent is unexpectedly large"
        );
    }
    (upper_exponent, upper_exponent - 1)
}

#[test]
#[ignore = "owned by test:rust:kernel:theorem-evidence"]
fn conservative_physical_proof_composition_rejects_accounting_mutations() {
    let inventory = derive_selected_proof_family_application_inventory()
        .expect("the selected proof inventory derives");
    let action_top_count = FOUNDATION_PROFILE.option_count;
    let evidence_rows = synthetic_mapped_soundness_summaries(&inventory, action_top_count);
    let canonical_document = MappedSoundnessEvidenceDocument {
        format_version: MAPPED_SOUNDNESS_EVIDENCE_FORMAT_VERSION,
        action_top_count,
        conditional_oracle_model: MAPPED_SOUNDNESS_CONDITIONAL_ORACLE_MODEL.to_owned(),
        rows: evidence_rows
            .iter()
            .map(MappedConstructionSoundnessEvidenceRecord::from_evidence_row)
            .collect::<Result<Vec<_>, _>>()
            .expect("the synthetic mapped-soundness rows encode"),
    };
    let canonical_document_bytes = serde_json::to_vec(&canonical_document)
        .expect("the canonical mapped-soundness document encodes");
    let (_, decoded_evidence_rows) =
        parse_mapped_soundness_evidence_document(&canonical_document_bytes)
            .expect("the separated-oracle evidence decodes canonically");
    assert_eq!(decoded_evidence_rows, evidence_rows);
    let mut stale_version_four_document =
        serde_json::to_value(&canonical_document).expect("the stale document value encodes");
    let stale_document_object = stale_version_four_document
        .as_object_mut()
        .expect("the evidence document is an object");
    stale_document_object.insert("formatVersion".to_owned(), serde_json::Value::from(4_u16));
    for row in stale_document_object
        .get_mut("rows")
        .and_then(serde_json::Value::as_array_mut)
        .expect("the evidence rows form an array")
    {
        row.as_object_mut()
            .expect("an evidence row is an object")
            .remove("fixedOutputOracleGraphIdentityHashHex");
    }
    let stale_version_four_bytes = serde_json::to_vec(&stale_version_four_document)
        .expect("the stale evidence document encodes");
    assert!(
        parse_mapped_soundness_evidence_document(&stale_version_four_bytes).is_err(),
        "version-four evidence without a derived graph-certificate identity must remain refused",
    );
    let mut wrong_sampler_reduction = canonical_document.clone();
    wrong_sampler_reduction.rows[0].fixed_output_sampler_reduction =
        "forged-fixed-output-sampler-reduction".to_owned();
    let wrong_sampler_reduction_bytes = serde_json::to_vec(&wrong_sampler_reduction)
        .expect("the hostile mapped-soundness document encodes");
    assert!(
        parse_mapped_soundness_evidence_document(&wrong_sampler_reduction_bytes).is_err(),
        "a forged fixed-output sampler reduction identifier must refuse",
    );
    let mut omitted_graph_certificate = canonical_document.clone();
    omitted_graph_certificate.rows[0].fixed_output_oracle_graph_identity_hash_hex =
        to_hex(&[0_u8; 64]);
    let omitted_graph_certificate_bytes = serde_json::to_vec(&omitted_graph_certificate)
        .expect("the hostile graph-certificate document encodes");
    assert!(
        parse_mapped_soundness_evidence_document(&omitted_graph_certificate_bytes).is_err(),
        "composition must refuse a row without an independently derived graph-certificate identity",
    );
    let mut wrong_oracle_model = canonical_document.clone();
    wrong_oracle_model.conditional_oracle_model =
        "domain-separated-shake256-ideal-xof-quantum-random-oracle".to_owned();
    let wrong_oracle_model_bytes =
        serde_json::to_vec(&wrong_oracle_model).expect("the hostile oracle-model document encodes");
    assert!(
        parse_mapped_soundness_evidence_document(&wrong_oracle_model_bytes).is_err(),
        "the obsolete concrete ideal-XOF claim must refuse",
    );
    let refuses_evidence_rows = |candidate: &[MappedConstructionSoundnessEvidenceRow]| {
        assert!(
            derive_conservative_action_soundness_composition(
                candidate,
                &inventory,
                action_top_count,
            )
            .is_err(),
            "altered mapped chronology must refuse before composition",
        );
    };
    let mut omitted_challenge = evidence_rows.clone();
    omitted_challenge[0].challenge_operation_count = 0;
    refuses_evidence_rows(&omitted_challenge);
    let mut challenge_before_header = evidence_rows.clone();
    challenge_before_header[0].first_challenge_operation_ordinal = 0;
    refuses_evidence_rows(&challenge_before_header);
    let mut changed_initial_absorption = evidence_rows.clone();
    changed_initial_absorption[0].initial_absorption_equation_slot_ordinal = 2;
    refuses_evidence_rows(&changed_initial_absorption);
    let mut missing_chronology_binding = evidence_rows.clone();
    missing_chronology_binding[0].chronology_hash = [0_u8; 64];
    refuses_evidence_rows(&missing_chronology_binding);
    let mut missing_graph_certificate = evidence_rows.clone();
    missing_graph_certificate[0].fixed_output_oracle_graph_identity_hash = [0_u8; 64];
    refuses_evidence_rows(&missing_graph_certificate);
    let mut changed_qrom_probability = evidence_rows.clone();
    changed_qrom_probability[0].qrom_failure_probability_at_declared_budget =
        ExactBigFraction::zero();
    refuses_evidence_rows(&changed_qrom_probability);
    let mut omitted_auxiliary_table_bad_event = evidence_rows.clone();
    omitted_auxiliary_table_bad_event[0].auxiliary_table_bad_event_probability_ceiling =
        ExactBigFraction::zero();
    refuses_evidence_rows(&omitted_auxiliary_table_bad_event);
    let mut changed_primary_oracle_probability = evidence_rows.clone();
    changed_primary_oracle_probability[0]
        .primary_oracle_qrom_failure_probability_at_declared_budget =
        ExactBigFraction::new(BigUint::one(), BigUint::one() << 256_usize)
            .expect("the hostile primary-oracle probability derives");
    refuses_evidence_rows(&changed_primary_oracle_probability);
    let exact_failure_polynomial =
        ExactComposedQromFailurePolynomial::derive(&evidence_rows, &inventory)
            .expect("the exact synthetic QROM polynomial derives");
    let declared_query_bound = BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET);
    let comparison_query_bounds = [
        BigUint::zero(),
        BigUint::one(),
        &declared_query_bound - BigUint::one(),
        declared_query_bound.clone(),
        &declared_query_bound + BigUint::one(),
        &declared_query_bound << 1_usize,
    ];
    let one_half = ExactBigFraction::from_u64(1, 2).expect("one half derives");
    for comparison_query_bound in comparison_query_bounds {
        let direct_failure = composed_qrom_failure_for_query_bound(
            &evidence_rows,
            &inventory,
            &comparison_query_bound,
        )
        .expect("the direct synthetic QROM expression derives");
        assert_eq!(
            exact_failure_polynomial
                .failure_fraction_at(&comparison_query_bound)
                .expect("the polynomial synthetic QROM expression derives"),
            direct_failure,
        );
        assert_eq!(
            exact_failure_polynomial.is_below_one_half_at(&comparison_query_bound),
            direct_failure.less_than(&one_half),
        );
    }
    let certificate = derive_conservative_action_soundness_composition(
        &evidence_rows,
        &inventory,
        action_top_count,
    )
    .expect("the conservative synthetic composition derives");
    assert!(certificate.is_complete_for(&evidence_rows, &inventory, action_top_count));
    assert_eq!(certificate.physical_proof_application_count, 103);
    assert_eq!(certificate.logical_relation_instance_count, 159);
    assert_eq!(certificate.mapped_transform_count, 103);
    assert_eq!(certificate.conditional_oracle_assumption_reference_count, 1);
    assert_eq!(certificate.auxiliary_table_bad_event_charge_count, 103);
    assert_eq!(certificate.shared_action_root_hybrid_credit_count, 0);
    assert!(!certificate.claims_one_global_transform);
    assert!(!certificate.claims_concrete_sponge_reduction);

    let rejects = |candidate: ConservativeActionSoundnessCompositionCertificate| {
        assert!(!candidate.is_complete_for(&evidence_rows, &inventory, action_top_count));
    };
    let mut missing_physical_proof = certificate.clone();
    missing_physical_proof.ordered_physical_proof_rows.pop();
    rejects(missing_physical_proof);
    let mut changed_logical_count = certificate.clone();
    changed_logical_count.ordered_physical_proof_rows[0].logical_relation_instance_count += 1;
    rejects(changed_logical_count);
    let mut reused_ordinal = certificate.clone();
    reused_ordinal.ordered_physical_proof_rows[1].global_physical_proof_ordinal = 0;
    rejects(reused_ordinal);
    let mut reduced_query_budget = certificate.clone();
    reduced_query_budget.ordered_physical_proof_rows[0].adversarial_query_bound -= BigUint::one();
    rejects(reduced_query_budget);
    let mut omitted_physical_graph_certificate = certificate.clone();
    omitted_physical_graph_certificate.ordered_physical_proof_rows[0]
        .fixed_output_oracle_graph_identity_hash = [0_u8; 64];
    rejects(omitted_physical_graph_certificate);
    let mut challenge_dependent_statement = certificate.clone();
    challenge_dependent_statement.ordered_physical_proof_rows[0]
        .first_challenge_operation_ordinal = 0;
    rejects(challenge_dependent_statement);
    let mut assumed_independence = certificate.clone();
    assumed_independence.ordered_physical_proof_rows[0].cross_proof_independence_use =
        CrossProofIndependenceUse::Assumed;
    rejects(assumed_independence);
    let mut repeated_assumption_charge = certificate.clone();
    repeated_assumption_charge.conditional_oracle_assumption_reference_count = 103;
    rejects(repeated_assumption_charge);
    let mut shared_hybrid_credit = certificate.clone();
    shared_hybrid_credit.shared_action_root_hybrid_credit_count = 1;
    rejects(shared_hybrid_credit);
    let mut shared_auxiliary_table_credit = certificate.clone();
    shared_auxiliary_table_credit.auxiliary_table_bad_event_charge_count = 1;
    rejects(shared_auxiliary_table_credit);
    let mut omitted_auxiliary_table_total = certificate.clone();
    omitted_auxiliary_table_total.auxiliary_table_bad_event_probability_ceiling =
        ExactBigFraction::zero();
    rejects(omitted_auxiliary_table_total);
    let mut global_transform_claim = certificate.clone();
    global_transform_claim.claims_one_global_transform = true;
    rejects(global_transform_claim);
    let mut wrong_action_geometry = certificate.clone();
    wrong_action_geometry.action_top_count -= 1;
    rejects(wrong_action_geometry);
}

fn assert_mapped_soundness_derives_in_isolation(schema_identifier: u16) {
    let _certificate_test_guard = PRODUCTION_GEOMETRY_CERTIFICATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let artifact = selected_relation_plan_for_schema(schema_identifier)
        .expect("the selected focused relation plan derives");
    let mut masking_certificates = Vec::new();
    let evidence_row = checked_selected_mapped_soundness_summary(
        &artifact,
        schema_identifier,
        FOUNDATION_PROFILE.option_count,
        &mut masking_certificates,
    )
    .expect("the isolated mapped soundness certificate derives");
    assert!(evidence_row.is_complete());
    assert_eq!(
        evidence_row.application_statement_schema_identifier,
        schema_identifier,
    );
    let inventory = derive_selected_proof_family_application_inventory()
        .expect("the selected proof inventory derives");
    let family = inventory
        .family_entry(schema_identifier)
        .expect("the focused schema belongs to the production proof inventory");
    assert_eq!(
        evidence_row.family_application_multiplicity,
        u64::from(family.physical_proof_application_count()),
    );
    assert_eq!(
        mapped_primary_oracle_qrom_failure_for_query_bound(
            &evidence_row,
            &evidence_row.adversarial_query_bound,
        )
        .expect("the mapped primary-oracle QROM expression derives"),
        evidence_row.primary_oracle_qrom_failure_probability_at_declared_budget,
    );
    assert_eq!(
        mapped_complete_qrom_failure_for_query_bound(
            &evidence_row,
            &evidence_row.adversarial_query_bound,
        )
        .expect("the mapped complete QROM expression derives"),
        evidence_row.qrom_failure_probability_at_declared_budget,
    );
    match std::env::var(MAPPED_SOUNDNESS_REFRESH_ENVIRONMENT_VARIABLE) {
        Ok(value) if value == "1" => persist_mapped_soundness_checkpoint(&evidence_row)
            .expect("the construction-bound mapped-soundness checkpoint persists"),
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{MAPPED_SOUNDNESS_REFRESH_ENVIRONMENT_VARIABLE} must be absent or exactly 1");
        }
        Err(std::env::VarError::NotPresent) => {
            let (_, tracked_rows) = load_tracked_mapped_soundness_evidence()
                .expect("the tracked mapped-soundness evidence decodes canonically");
            let matching_rows = tracked_rows
                .iter()
                .filter(|tracked| {
                    tracked.application_statement_schema_identifier == schema_identifier
                })
                .collect::<Vec<_>>();
            let [tracked_row] = matching_rows.as_slice() else {
                panic!("the tracked evidence must contain the focused schema exactly once");
            };
            assert_eq!(
                **tracked_row, evidence_row,
                "the tracked row must equal the independently derived production geometry",
            );
        }
    }
}

macro_rules! mapped_soundness_schema_test {
    ($test_name:ident, $schema_identifier:expr) => {
        #[test]
        #[ignore = "owned by test:rust:kernel:theorem-evidence"]
        fn $test_name() {
            assert_mapped_soundness_derives_in_isolation($schema_identifier);
        }
    };
}

mapped_soundness_schema_test!(
    vss_share_linkage_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    aggregate_threshold_share_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    same_secret_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    public_key_share_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    collective_public_key_aggregate_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    relinearization_round_one_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    rkg_round_one_aggregate_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    relinearization_round_two_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    galois_key_share_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    evaluator_key_aggregate_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    ballot_validity_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
);
mapped_soundness_schema_test!(
    target_share_mapped_soundness_derives_in_isolation,
    ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
);

#[test]
#[ignore = "owned by test:rust:kernel:theorem-evidence"]
fn selected_mapped_soundness_checkpoints_consolidate_canonically() {
    let path = consolidate_mapped_soundness_checkpoints()
        .expect("all focused mapped-soundness checkpoints consolidate canonically");
    eprintln!(
        "consolidated mapped-soundness evidence at {}",
        path.display()
    );
}

#[test]
#[ignore = "owned by test:rust:kernel:theorem-evidence"]
fn selected_complete_action_maps_one_transform_to_each_physical_proof() {
    let action_top_count = FOUNDATION_PROFILE.option_count;
    let (certificate, evidence_rows, inventory) =
        checked_selected_action_soundness_composition(action_top_count)
            .expect("the selected conservative action composition derives");
    assert!(certificate.is_complete_for(&evidence_rows, &inventory, action_top_count));
    assert_eq!(certificate.ordered_family_rows.len(), 12);
    assert_eq!(certificate.physical_proof_application_count, 103);
    assert_eq!(certificate.logical_relation_instance_count, 159);
    assert_eq!(certificate.mapped_transform_count, 103);
    assert_eq!(certificate.conditional_oracle_assumption_reference_count, 1);
    assert_eq!(certificate.auxiliary_table_bad_event_charge_count, 103);
    assert_eq!(certificate.shared_action_root_hybrid_credit_count, 0);
    assert!(!certificate.claims_one_global_transform);
    assert!(!certificate.claims_concrete_sponge_reduction);
    assert!(certificate.ordinary_invalid_acceptance_mass_gate_holds);
    assert!(certificate.transformed_initial_mass_gate_holds);
    assert!(certificate.mapped_qrom_contribution_is_at_most_one_quarter);
    assert_eq!(
        certificate.declared_adversarial_query_bound,
        BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
    );
    assert_eq!(
        &certificate.last_query_bound_with_composed_qrom_ceiling_below_one_half + BigUint::one(),
        certificate.first_query_bound_with_composed_qrom_ceiling_at_least_one_half,
    );
    let classical_interval =
        inverse_power_of_two_interval(&certificate.classical_failure_probability_ceiling);
    let qrom_interval =
        inverse_power_of_two_interval(&certificate.qrom_failure_probability_at_declared_budget);
    assert_eq!(
        certificate
            .primary_oracle_qrom_failure_probability_at_declared_budget
            .add(&certificate.auxiliary_table_bad_event_probability_ceiling)
            .expect("the action QROM components add"),
        certificate.qrom_failure_probability_at_declared_budget,
    );
    eprintln!(
        "selected conservative composition: physical {}, logical {}, classical in (2^-{}, 2^-{}], fixed-budget QROM in (2^-{}, 2^-{}], constant-success boundary bit lengths {}/{}",
        certificate.physical_proof_application_count,
        certificate.logical_relation_instance_count,
        classical_interval.0,
        classical_interval.1,
        qrom_interval.0,
        qrom_interval.1,
        certificate
            .last_query_bound_with_composed_qrom_ceiling_below_one_half
            .bits(),
        certificate
            .first_query_bound_with_composed_qrom_ceiling_at_least_one_half
            .bits(),
    );
}
