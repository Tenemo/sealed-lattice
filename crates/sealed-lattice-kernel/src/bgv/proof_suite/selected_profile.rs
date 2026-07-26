//! Deterministic construction of the fixed proof-profile artifact.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;

use crate::bgv::{
    evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
};
use crate::foundation::{
    ProofApplicationSlotCeilings, SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
    SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION, selected_evaluator_resource_accounting,
    selected_sharing_data_prime_coordinates,
};

use crate::{
    bgv::{
        evaluator::candidate_evidence::EvaluatorCandidateInput,
        setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
        target_decryption::kllps_release::{
            KLLPS_DENOMINATOR_CLEARING_FACTOR, selected_factor_four_flooding_bound,
        },
    },
    foundation::{FOUNDATION_PROFILE, Hash512},
};

use super::profile::FIRST_PROFILE_APPLICATION_FAMILIES;
use super::relation_plan::trustee_evaluation_key_relation_basis_for_catalog_level;
use super::transcript::{CommonProofApplicationChallengeSamplerAccounting, CommonProofChallenge};
use super::{
    BallotValidityRelationPlanInput, CompiledBallotValidityRelation,
    compile_ballot_validity_relation,
};
use super::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_EVALUATION_COSET_OFFSET,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, PROOF_NON_NATIVE_ALPHA_REPETITION_COUNT,
    PROOF_NON_NATIVE_THETA_REPETITION_COUNT, PROOF_OUT_OF_DOMAIN_POINT_COUNT,
    RelationPlanCheckContext, ResolvedSuiteModulus, SuiteModulusReference,
    row_code_whir::{
        ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE, ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE,
        ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT,
    },
};

use super::{
    BoundTreeConstructionKind, CollectivePublicKeyAggregatePlanInput, CommittedMaterialProfile,
    CommittedMaterialRelationPlanInput, CompiledRelationPlan, CompiledTargetReleaseRelation,
    EvaluatorKeyAggregateEntryPlanInput, EvaluatorKeyAggregatePlanInput,
    EvaluatorKeyAggregateVariantInput, GaloisKeyShareRelationEntryInput,
    GaloisKeyShareRelationPlanInput, ProofProfileError, PublicAggregateRelationGeometry,
    PublicKeyShareRelationPlanInput, RelationPlanVariant, RelinearizationRoundOneRelationPlanInput,
    RelinearizationRoundTwoRelationPlanInput, RkgRoundOneAggregatePlanInput,
    RkgRoundOneAggregateVariantInput, SameSecretRelationPlanInput, SelectedEvaluatorEntryKind,
    TargetReleaseRelationPlanInput, TrusteeEvaluationKeyRelationGeometry,
    ValidatedRelationPlanArtifact, compile_aggregate_threshold_share_relation_plan,
    compile_ballot_validity_relation_plan, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_galois_key_share_relation_plan,
    compile_public_key_share_relation_plan, compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_two_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_target_release_relation,
    compile_vss_share_linkage_relation_plan, selected_evaluator_entry_positions,
    selected_galois_key_share_batch_schedule,
};

#[cfg(test)]
use super::ProofProfileSet;
use super::profile::FirstProfileRootTopology;

#[cfg(test)]
use crate::bgv::evaluator::program::selected_evaluator_program_set;

pub(super) const SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 =
    ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE;
pub(super) const SELECTED_EVALUATION_DOMAIN_SIZE: u64 = ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE;
pub(super) const SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE: u64 =
    POLYNOMIAL_DEGREE as u64 / 2;
const SELECTED_QUOTIENT_COMPONENT_COUNT: u32 = 8;
const SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_COUNT: u32 = 9;
const SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE: u64 =
    POLYNOMIAL_DEGREE as u64 / 2;
const SELECTED_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE: u64 = 34_050;
const SELECTED_COMMITTED_MATERIAL_QUOTIENT_COMPONENT_COUNT: u32 = 3;
const RESERVED_BALLOT_SLOT_RULE: u16 = 1;
const NON_NATIVE_IDENTITY_COMPILER_FACTOR: u32 = 12;
// This fail-closed screen is deliberately conservative until a complete
// construction-specific round-by-round and QROM ledger replaces it. It does
// not itself establish a QROM claim.
const NON_NATIVE_THETA_TRANSITION_BATCH_FACTOR: u32 = 24;
const NON_NATIVE_THETA_CONSERVATIVE_SEARCH_FACTOR: u32 = 200;
const NON_NATIVE_THETA_SCREEN_CEILING_BITS: usize = 176;
// Alpha retains its separately derived local allocation.
const NON_NATIVE_ALPHA_ACTION_MARGIN_BITS: usize = 184;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedNonNativeIdentitySoundnessRow {
    application_statement_schema_identifier: u16,
    challenge: CommonProofChallenge,
    arithmetic_modulus_reference: SuiteModulusReference,
    ordered_bad_polynomial_degrees: Vec<u64>,
    bad_set_numerator: BigUint,
    sample_space_denominator: BigUint,
    complete_action_application_multiplicity: u32,
    screen_event_factor: u32,
    screen_ceiling_bits: usize,
    sampler_accounting: CommonProofApplicationChallengeSamplerAccounting,
}

fn expected_product_sampler_total_xof_query_count_ceiling(
    sampler_accounting: CommonProofApplicationChallengeSamplerAccounting,
) -> Result<u64, ProofProfileError> {
    let oracle_answer_byte_length =
        u64::try_from(Hash512::BYTE_LENGTH).map_err(|_| ProofProfileError::CountOverflow)?;
    let candidate_byte_length = sampler_accounting.candidate_byte_length();
    if candidate_byte_length == 0
        || !candidate_byte_length.is_multiple_of(oracle_answer_byte_length)
    {
        return Err(ProofProfileError::InvalidSchedule);
    }
    let candidate_block_count = candidate_byte_length / oracle_answer_byte_length;
    u64::from(sampler_accounting.maximum_candidate_draw_count())
        .checked_mul(candidate_block_count)
        .and_then(|candidate_query_count| candidate_query_count.checked_add(1))
        .ok_or(ProofProfileError::CountOverflow)
}

impl SelectedNonNativeIdentitySoundnessRow {
    fn new(
        application_statement_schema_identifier: u16,
        challenge: CommonProofChallenge,
        arithmetic_modulus_reference: SuiteModulusReference,
        ordered_bad_polynomial_degrees: Vec<u64>,
        complete_action_application_multiplicity: u32,
        sampler_accounting: CommonProofApplicationChallengeSamplerAccounting,
    ) -> Result<Self, ProofProfileError> {
        if sampler_accounting.challenge() != challenge
            || usize::from(sampler_accounting.coordinate_count())
                != ordered_bad_polynomial_degrees.len()
            || sampler_accounting.maximum_candidate_draw_count()
                != PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
            || sampler_accounting.total_xof_query_count_ceiling()
                != expected_product_sampler_total_xof_query_count_ceiling(sampler_accounting)?
        {
            return Err(ProofProfileError::InvalidSchedule);
        }
        let sample_modulus = sampler_accounting.modulus();
        let bad_set_numerator = ordered_bad_polynomial_degrees
            .iter()
            .copied()
            .map(|degree| BigUint::from(degree.min(sample_modulus)))
            .product();
        let sample_space_denominator =
            BigUint::from(sample_modulus).pow(u32::from(sampler_accounting.coordinate_count()));
        let (screen_event_factor, screen_ceiling_bits) = selected_non_native_identity_screen(
            challenge,
            complete_action_application_multiplicity,
        )?;
        Ok(Self {
            application_statement_schema_identifier,
            challenge,
            arithmetic_modulus_reference,
            ordered_bad_polynomial_degrees,
            bad_set_numerator,
            sample_space_denominator,
            complete_action_application_multiplicity,
            screen_event_factor,
            screen_ceiling_bits,
            sampler_accounting,
        })
    }

    fn minimum_repetition_count(&self) -> Result<u16, ProofProfileError> {
        minimum_non_native_identity_repetition_count(
            self.sampler_accounting.modulus(),
            &self.ordered_bad_polynomial_degrees,
            self.screen_event_factor,
            self.screen_ceiling_bits,
        )
    }

    fn key(&self) -> (u16, CommonProofChallenge, SuiteModulusReference) {
        (
            self.application_statement_schema_identifier,
            self.challenge,
            self.arithmetic_modulus_reference,
        )
    }

    fn satisfies_selected_screen(&self) -> Result<bool, ProofProfileError> {
        let action_numerator = (&self.bad_set_numerator * BigUint::from(self.screen_event_factor))
            << self.screen_ceiling_bits;
        Ok(action_numerator <= self.sample_space_denominator)
    }
}

fn selected_non_native_identity_screen(
    challenge: CommonProofChallenge,
    complete_action_application_multiplicity: u32,
) -> Result<(u32, usize), ProofProfileError> {
    if complete_action_application_multiplicity == 0 {
        return Err(ProofProfileError::InvalidSchedule);
    }
    let (event_factor, ceiling_bits) = match challenge {
        CommonProofChallenge::Theta { .. } => (
            complete_action_application_multiplicity
                .checked_mul(NON_NATIVE_THETA_TRANSITION_BATCH_FACTOR)
                .and_then(|factor| factor.checked_mul(NON_NATIVE_IDENTITY_COMPILER_FACTOR))
                .and_then(|factor| factor.checked_mul(NON_NATIVE_THETA_CONSERVATIVE_SEARCH_FACTOR))
                .ok_or(ProofProfileError::CountOverflow)?,
            NON_NATIVE_THETA_SCREEN_CEILING_BITS,
        ),
        CommonProofChallenge::Alpha { .. } => (
            complete_action_application_multiplicity
                .checked_mul(NON_NATIVE_IDENTITY_COMPILER_FACTOR)
                .ok_or(ProofProfileError::CountOverflow)?,
            NON_NATIVE_ALPHA_ACTION_MARGIN_BITS,
        ),
        _ => return Err(ProofProfileError::InvalidSchedule),
    };
    Ok((event_factor, ceiling_bits))
}

fn uses_committed_material_proof_schedule(
    application_statement_schema_identifier: u16,
) -> Option<bool> {
    if matches!(
        application_statement_schema_identifier,
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
    ) {
        Some(true)
    } else if FIRST_PROFILE_APPLICATION_FAMILIES.contains(&application_statement_schema_identifier)
    {
        Some(false)
    } else {
        None
    }
}

fn uses_public_aggregate_quotient_geometry(application_statement_schema_identifier: u16) -> bool {
    matches!(
        application_statement_schema_identifier,
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    )
}

pub(crate) fn selected_proof_application_slot_ceilings()
-> Result<ProofApplicationSlotCeilings, ProofProfileError> {
    let root_topology =
        FirstProfileRootTopology::selected(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)?;
    let evaluator_resource_accounting = selected_evaluator_resource_accounting()
        .map_err(|_| ProofProfileError::InvalidRootTopology)?;
    let selected_galois_batch_count =
        u32::try_from(selected_galois_key_share_batch_schedule().len())
            .map_err(|_| ProofProfileError::CountOverflow)?;

    ProofApplicationSlotCeilings::derive(
        root_topology.roster_size(),
        evaluator_resource_accounting.relinearization_position_count(),
        selected_galois_batch_count,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    )
    .map_err(|_| ProofProfileError::InvalidRootTopology)
}

fn minimum_non_native_identity_repetition_count(
    sample_modulus: u64,
    ordered_bad_polynomial_degrees: &[u64],
    screen_event_factor: u32,
    screen_ceiling_bits: usize,
) -> Result<u16, ProofProfileError> {
    if sample_modulus < 2 || ordered_bad_polynomial_degrees.is_empty() || screen_event_factor == 0 {
        return Err(ProofProfileError::InvalidSchedule);
    }
    let action_factor = BigUint::from(screen_event_factor);
    let mut bad_set_numerator = BigUint::from(1_u8);
    let mut sample_space_denominator = BigUint::from(1_u8);
    for (repetition_index, bad_polynomial_degree) in
        ordered_bad_polynomial_degrees.iter().copied().enumerate()
    {
        bad_set_numerator *= BigUint::from(bad_polynomial_degree.min(sample_modulus));
        sample_space_denominator *= BigUint::from(sample_modulus);
        let action_numerator = (&bad_set_numerator * &action_factor) << screen_ceiling_bits;
        if action_numerator <= sample_space_denominator {
            return u16::try_from(repetition_index + 1)
                .map_err(|_| ProofProfileError::CountOverflow);
        }
    }
    Err(ProofProfileError::InvalidSchedule)
}

fn ordered_bad_polynomial_degrees(
    degrees_by_repetition: BTreeMap<u16, u64>,
    expected_repetition_count: u16,
) -> Result<Vec<u64>, ProofProfileError> {
    if degrees_by_repetition.len() != usize::from(expected_repetition_count)
        || degrees_by_repetition
            .keys()
            .copied()
            .ne(0..expected_repetition_count)
    {
        return Err(ProofProfileError::InvalidSchedule);
    }
    Ok(degrees_by_repetition.into_values().collect())
}

fn required_theta_repetition_count(
    application_statement_schema_identifier: u16,
    variant: &RelationPlanVariant,
    complete_action_application_multiplicity: u32,
    sampler_rows: &[CommonProofApplicationChallengeSamplerAccounting],
    soundness_rows: &mut Vec<SelectedNonNativeIdentitySoundnessRow>,
) -> Result<Option<u16>, ProofProfileError> {
    let mut degrees_by_modulus_and_repetition =
        BTreeMap::<SuiteModulusReference, BTreeMap<u16, u64>>::new();
    for batch in variant.ordered_integer_lift_batches() {
        let degree = batch.theta_bad_polynomial_degree(variant.trace_domain_size())?;
        if degrees_by_modulus_and_repetition
            .entry(batch.modulus_reference())
            .or_default()
            .insert(batch.challenge_ordinal(), degree)
            .is_some()
        {
            return Err(ProofProfileError::InvalidSchedule);
        }
    }
    let mut maximum_required_count = None::<u16>;
    for (modulus_reference, degrees_by_repetition) in degrees_by_modulus_and_repetition {
        let ordered_degrees = ordered_bad_polynomial_degrees(
            degrees_by_repetition,
            PROOF_NON_NATIVE_THETA_REPETITION_COUNT,
        )?;
        let challenge = CommonProofChallenge::Theta {
            modulus_ordinal: variant.non_native_modulus_ordinal(modulus_reference)?,
        };
        let sampler_accounting = sampler_rows
            .iter()
            .copied()
            .find(|row| row.challenge() == challenge)
            .ok_or(ProofProfileError::InvalidSchedule)?;
        let row = SelectedNonNativeIdentitySoundnessRow::new(
            application_statement_schema_identifier,
            challenge,
            modulus_reference,
            ordered_degrees,
            complete_action_application_multiplicity,
            sampler_accounting,
        )?;
        let required_count = row.minimum_repetition_count()?;
        maximum_required_count = Some(
            maximum_required_count.map_or(required_count, |current| current.max(required_count)),
        );
        soundness_rows.push(row);
    }
    Ok(maximum_required_count)
}

fn required_alpha_repetition_count(
    application_statement_schema_identifier: u16,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    complete_action_application_multiplicity: u32,
    sampler_rows: &[CommonProofApplicationChallengeSamplerAccounting],
    soundness_rows: &mut Vec<SelectedNonNativeIdentitySoundnessRow>,
) -> Result<Option<u16>, ProofProfileError> {
    let mut degrees_by_modulus_and_repetition =
        BTreeMap::<SuiteModulusReference, BTreeMap<u16, u64>>::new();
    for batch in variant.ordered_coefficient_local_identity_batches() {
        let degree = batch.alpha_bad_polynomial_degree()?;
        degrees_by_modulus_and_repetition
            .entry(batch.modulus_reference())
            .or_default()
            .entry(batch.challenge_ordinal())
            .and_modify(|current| *current = (*current).max(degree))
            .or_insert(degree);
    }
    let mut maximum_required_count = None::<u16>;
    for (modulus_reference, degrees_by_repetition) in degrees_by_modulus_and_repetition {
        let ordered_degrees = ordered_bad_polynomial_degrees(
            degrees_by_repetition,
            PROOF_NON_NATIVE_ALPHA_REPETITION_COUNT,
        )?;
        let challenge = CommonProofChallenge::Alpha {
            modulus_ordinal: variant.non_native_modulus_ordinal(modulus_reference)?,
        };
        let sampler_accounting = sampler_rows
            .iter()
            .copied()
            .find(|row| row.challenge() == challenge)
            .ok_or(ProofProfileError::InvalidSchedule)?;
        if sampler_accounting.modulus() != context.resolved_modulus(modulus_reference)? {
            return Err(ProofProfileError::InvalidSchedule);
        }
        let row = SelectedNonNativeIdentitySoundnessRow::new(
            application_statement_schema_identifier,
            challenge,
            modulus_reference,
            ordered_degrees,
            complete_action_application_multiplicity,
            sampler_accounting,
        )?;
        let required_count = row.minimum_repetition_count()?;
        maximum_required_count = Some(
            maximum_required_count.map_or(required_count, |current| current.max(required_count)),
        );
        soundness_rows.push(row);
    }
    Ok(maximum_required_count)
}

fn selected_non_native_identity_soundness_ledger(
    compiled_plans: &[CompiledRelationPlan],
) -> Result<Vec<SelectedNonNativeIdentitySoundnessRow>, ProofProfileError> {
    let application_slot_ceilings = selected_proof_application_slot_ceilings()?;
    let mut required_theta_count = None::<u16>;
    let mut required_alpha_count = None::<u16>;
    let mut soundness_rows = Vec::new();
    for plan in compiled_plans {
        let complete_action_application_multiplicity = application_slot_ceilings
            .family_ceiling(plan.application_statement_schema_identifier())
            .ok_or(ProofProfileError::InvalidSchedule)?;
        let context =
            selected_relation_plan_check_context(plan.application_statement_schema_identifier())
                .ok_or(ProofProfileError::InvalidSchedule)?;
        for variant in plan.variants() {
            let sampler_rows = variant
                .common_proof_relation_prefix_schedule(&context)?
                .ordered_application_challenge_sampler_accounting()
                .map_err(|_| ProofProfileError::InvalidSchedule)?;
            let starting_row_count = soundness_rows.len();
            let theta_count = required_theta_repetition_count(
                plan.application_statement_schema_identifier(),
                variant,
                complete_action_application_multiplicity,
                &sampler_rows,
                &mut soundness_rows,
            )?;
            let alpha_count = required_alpha_repetition_count(
                plan.application_statement_schema_identifier(),
                variant,
                &context,
                complete_action_application_multiplicity,
                &sampler_rows,
                &mut soundness_rows,
            )?;
            if soundness_rows.len() - starting_row_count != sampler_rows.len() {
                return Err(ProofProfileError::InvalidSchedule);
            }
            required_theta_count = match (required_theta_count, theta_count) {
                (Some(current), Some(required)) => Some(current.max(required)),
                (None, Some(required)) => Some(required),
                (current, None) => current,
            };
            required_alpha_count = match (required_alpha_count, alpha_count) {
                (Some(current), Some(required)) => Some(current.max(required)),
                (None, Some(required)) => Some(required),
                (current, None) => current,
            };
        }
    }
    if required_theta_count != Some(PROOF_NON_NATIVE_THETA_REPETITION_COUNT)
        || required_alpha_count != Some(PROOF_NON_NATIVE_ALPHA_REPETITION_COUNT)
    {
        return Err(ProofProfileError::InvalidSchedule);
    }
    let mut row_keys = BTreeSet::new();
    for row in &soundness_rows {
        if !row_keys.insert(row.key()) || !row.satisfies_selected_screen()? {
            return Err(ProofProfileError::InvalidSchedule);
        }
    }
    Ok(soundness_rows)
}

pub(crate) fn selected_relation_plan_check_context(
    application_statement_schema_identifier: u16,
) -> Option<RelationPlanCheckContext> {
    let uses_committed_material_schedule =
        uses_committed_material_proof_schedule(application_statement_schema_identifier)?;
    let uses_public_aggregate_quotient_geometry =
        uses_public_aggregate_quotient_geometry(application_statement_schema_identifier);
    let mut resolved_moduli = DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(modulus_index, modulus)| {
            ResolvedSuiteModulus::new(
                SuiteModulusReference::data(
                    u16::try_from(modulus_index).expect("the selected data basis fits u16"),
                ),
                modulus,
            )
        })
        .collect::<Vec<_>>();
    resolved_moduli.extend(SPECIAL_PRIMES.iter().copied().enumerate().map(
        |(modulus_index, modulus)| {
            ResolvedSuiteModulus::new(
                SuiteModulusReference::special(
                    u16::try_from(modulus_index).expect("the selected special basis fits u16"),
                ),
                modulus,
            )
        },
    ));
    resolved_moduli.push(ResolvedSuiteModulus::new(
        SuiteModulusReference::plaintext(),
        PLAINTEXT_MODULUS,
    ));
    resolved_moduli.extend(
        DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
            .iter()
            .copied()
            .enumerate()
            .map(|(modulus_index, modulus)| {
                ResolvedSuiteModulus::new(
                    SuiteModulusReference::target(
                        u16::try_from(modulus_index).expect("the selected target basis fits u16"),
                    ),
                    modulus,
                )
            }),
    );

    Some(RelationPlanCheckContext {
        base_field_modulus: PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: u16::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .expect("the selected challenge extension degree fits u16"),
        evaluation_domain_generator: modular_power(
            PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
            (1_u64 << 32) / SELECTED_EVALUATION_DOMAIN_SIZE,
            PROOF_BASE_FIELD_MODULUS,
        ),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        out_of_domain_point_count: PROOF_OUT_OF_DOMAIN_POINT_COUNT,
        quotient_component_count: if uses_committed_material_schedule {
            SELECTED_COMMITTED_MATERIAL_QUOTIENT_COMPONENT_COUNT
        } else if uses_public_aggregate_quotient_geometry {
            SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_COUNT
        } else {
            SELECTED_QUOTIENT_COMPONENT_COUNT
        },
        quotient_component_degree_bound_exclusive: if uses_committed_material_schedule {
            selected_committed_material_quotient_component_degree_bound_exclusive().ok()?
        } else if uses_public_aggregate_quotient_geometry {
            SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE
        } else {
            SELECTED_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE
        },
        phase_column_query_coordinate_count: ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT,
        non_native_theta_repetition_count: PROOF_NON_NATIVE_THETA_REPETITION_COUNT,
        non_native_alpha_repetition_count: PROOF_NON_NATIVE_ALPHA_REPETITION_COUNT,
        maximum_fiat_shamir_candidate_draws_per_output:
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        resolved_moduli,
    })
}

pub(crate) fn selected_ballot_validity_relation_compilation()
-> Result<CompiledBallotValidityRelation, super::RelationPlanError> {
    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(super::RelationPlanError::InvalidDomain)?;
    compile_ballot_validity_relation(
        &BallotValidityRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            active_data_modulus_indices: selected_data_modulus_indices(),
            plaintext_modulus: PLAINTEXT_MODULUS,
            reserved_slot_rule: RESERVED_BALLOT_SLOT_RULE,
        },
        &relation_context,
    )
}

#[cfg(test)]
pub(crate) fn selected_proof_profile_set(
    maximum_ballot_attempts_per_participant: u16,
) -> Result<ProofProfileSet, ProofProfileError> {
    let relation_plans = selected_relation_plans()?;
    ProofProfileSet::new(
        relation_plans,
        FirstProfileRootTopology::selected(maximum_ballot_attempts_per_participant)?,
    )
}

pub(crate) fn selected_committed_material_profile()
-> Result<CommittedMaterialProfile, ProofProfileError> {
    CommittedMaterialProfile::for_common_proof_evaluation_domain(
        POLYNOMIAL_DEGREE,
        usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
            .map_err(|_| ProofProfileError::CountOverflow)?,
        usize::try_from(SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE)
            .map_err(|_| ProofProfileError::CountOverflow)?,
    )
    .map_err(|_| ProofProfileError::InvalidRelationPlan)
}

pub(crate) fn selected_bound_root_source_trace_domain_size(
    application_statement_schema_identifier: u16,
    construction_kind: BoundTreeConstructionKind,
    relation_trace_domain_size: u64,
    evaluation_domain_size: u64,
) -> Result<u64, ProofProfileError> {
    if relation_trace_domain_size == 0 || evaluation_domain_size != SELECTED_EVALUATION_DOMAIN_SIZE
    {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    if construction_kind == BoundTreeConstructionKind::SetupPolynomial {
        return Ok(relation_trace_domain_size);
    }

    let committed_material_profile = selected_committed_material_profile()?;
    let physical_trace_domain_size = u64::try_from(committed_material_profile.trace_domain_size())
        .map_err(|_| ProofProfileError::CountOverflow)?;
    let committed_material_evaluation_domain_size =
        u64::try_from(committed_material_profile.evaluation_domain_size())
            .map_err(|_| ProofProfileError::CountOverflow)?;
    let expected_relation_trace_domain_size = match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            selected_committed_material_relation_plan_input()?.relation_trace_domain_size()?
        }
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
            physical_trace_domain_size
        }
        _ => return Err(ProofProfileError::InvalidRootTopology),
    };
    if relation_trace_domain_size != expected_relation_trace_domain_size
        || evaluation_domain_size != committed_material_evaluation_domain_size
    {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    Ok(physical_trace_domain_size)
}

pub(crate) fn selected_target_decryption_flooding_bound() -> Result<BigUint, ProofProfileError> {
    selected_factor_four_flooding_bound().map_err(|_| ProofProfileError::InvalidRelationPlan)
}

/// Compiles the sole selected target-release relation from production suite
/// constants. Accounting, generation adapters, and verification all consume
/// this constructor so the eight-prime factor-four geometry cannot drift.
pub(crate) fn selected_target_release_relation()
-> Result<CompiledTargetReleaseRelation, ProofProfileError> {
    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(ProofProfileError::InvalidSchedule)?;
    let material_column_degree_bound_exclusive = u64::try_from(
        selected_committed_material_profile()?.material_column_degree_bound_exclusive(),
    )
    .map_err(|_| ProofProfileError::CountOverflow)?;
    compile_target_release_relation(
        &TargetReleaseRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            material_column_degree_bound_exclusive,
            public_polynomial_column_degree_bound_exclusive: selected_ring_degree(),
            target_modulus_indices: (0..=CANONICAL_TARGET_CIPHERTEXT_LEVEL)
                .map(|index| u16::try_from(index).map_err(|_| ProofProfileError::CountOverflow))
                .collect::<Result<Vec<_>, _>>()?,
            decryption_scale: KLLPS_DENOMINATOR_CLEARING_FACTOR,
            simulation_scale: KLLPS_DENOMINATOR_CLEARING_FACTOR,
            flooding_bound: selected_target_decryption_flooding_bound()?,
        },
        &relation_context,
    )
    .map_err(ProofProfileError::from)
}

pub(crate) fn selected_committed_material_relation_plan_input()
-> Result<CommittedMaterialRelationPlanInput, ProofProfileError> {
    let committed_material_profile = selected_committed_material_profile()?;
    Ok(CommittedMaterialRelationPlanInput {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        material_column_degree_bound_exclusive: u64::try_from(
            committed_material_profile.material_column_degree_bound_exclusive(),
        )
        .map_err(|_| ProofProfileError::CountOverflow)?,
        participant_count: FOUNDATION_PROFILE.participant_count,
        threshold: FOUNDATION_PROFILE.reconstruction_threshold,
        sharing_data_modulus_indices: selected_sharing_data_modulus_indices()?,
        trace_mask_degree_bound_exclusive: u64::try_from(
            committed_material_profile.masking_polynomial_maximum_degree() + 1,
        )
        .map_err(|_| ProofProfileError::CountOverflow)?,
    })
}

fn selected_committed_material_quotient_component_degree_bound_exclusive()
-> Result<u64, ProofProfileError> {
    let relation_input = selected_committed_material_relation_plan_input()?;
    let component_count = u64::from(SELECTED_COMMITTED_MATERIAL_QUOTIENT_COMPONENT_COUNT);
    let rounded_mask_degree = component_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(relation_input.trace_mask_degree_bound_exclusive))
        .and_then(|degree| degree.checked_add(component_count.checked_sub(1)?))
        .and_then(|degree| degree.checked_div(component_count))
        .ok_or(ProofProfileError::CountOverflow)?;
    let quotient_decomposition_stride = relation_input
        .relation_trace_domain_size()?
        .checked_add(rounded_mask_degree)
        .ok_or(ProofProfileError::CountOverflow)?;
    let minimum_telescoping_mask_degree_bound_exclusive =
        u64::from(ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT)
            .checked_add(u64::from(PROOF_OUT_OF_DOMAIN_POINT_COUNT))
            .ok_or(ProofProfileError::CountOverflow)?;
    quotient_decomposition_stride
        .checked_add(minimum_telescoping_mask_degree_bound_exclusive)
        .ok_or(ProofProfileError::CountOverflow)
}

pub(crate) fn selected_relation_plans()
-> Result<Vec<ValidatedRelationPlanArtifact>, ProofProfileError> {
    let ordinary_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(ProofProfileError::InvalidSchedule)?;
    let committed_material_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(ProofProfileError::InvalidSchedule)?;
    let public_aggregate_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(ProofProfileError::InvalidSchedule)?;
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let commitment_data_modulus_indices = selected_commitment_data_modulus_indices()?;
    let same_secret = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()?,
        &ordinary_context,
    )?;
    let public_key_share = compile_public_key_share_relation_plan(
        &selected_public_key_share_relation_plan_input()?,
        &ordinary_context,
    )?;
    let active_data_modulus_indices = selected_data_modulus_indices();

    let aggregate_geometry = PublicAggregateRelationGeometry {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        public_polynomial_column_degree_bound_exclusive:
            SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        participant_count: FOUNDATION_PROFILE.participant_count,
    };
    let collective_public_key = compile_collective_public_key_aggregate_relation_plan(
        &CollectivePublicKeyAggregatePlanInput {
            geometry: aggregate_geometry.clone(),
            ordered_component_moduli: trace_half_modulus_references(
                &active_data_modulus_indices
                    .iter()
                    .copied()
                    .map(SuiteModulusReference::data)
                    .collect::<Vec<_>>(),
            ),
        },
        &public_aggregate_context,
    )?;

    let (relinearization_schedule_position, relinearization_catalog_level) = evaluator_candidate
        .relinearization_levels
        .iter()
        .copied()
        .enumerate()
        .next()
        .filter(|_| evaluator_candidate.relinearization_levels.len() == 1)
        .ok_or(ProofProfileError::InvalidRelationPlan)?;
    let relinearization_schedule_position = u32::try_from(relinearization_schedule_position)
        .map_err(|_| ProofProfileError::CountOverflow)?;
    let relinearization_geometry = selected_trustee_evaluation_key_geometry(
        &evaluator_candidate,
        relinearization_catalog_level,
        commitment_data_modulus_indices.clone(),
    )?;
    let relinearization_round_one = compile_relinearization_round_one_relation_plan(
        &RelinearizationRoundOneRelationPlanInput {
            schedule_position: relinearization_schedule_position,
            geometry: relinearization_geometry.clone(),
        },
        &ordinary_context,
    )?;
    let relinearization_root_component_moduli = trace_half_modulus_references(
        &ordered_trustee_root_row_modulus_references(&relinearization_geometry)?,
    );
    let rkg_round_one_aggregate = compile_rkg_round_one_aggregate_relation_plan(
        &RkgRoundOneAggregatePlanInput {
            geometry: aggregate_geometry.clone(),
            ordered_variants: vec![RkgRoundOneAggregateVariantInput {
                schedule_position: relinearization_schedule_position,
                ordered_left_component_moduli: relinearization_root_component_moduli.clone(),
                ordered_right_component_moduli: relinearization_root_component_moduli.clone(),
            }],
        },
        &public_aggregate_context,
    )?;
    let relinearization_round_two = compile_relinearization_round_two_relation_plan(
        &RelinearizationRoundTwoRelationPlanInput {
            schedule_position: relinearization_schedule_position,
            geometry: relinearization_geometry,
        },
        &ordinary_context,
    )?;

    let galois_catalog_level = evaluator_candidate
        .galois_key_schedule
        .iter()
        .map(|(_, level)| *level)
        .max()
        .ok_or(ProofProfileError::InvalidRelationPlan)?;
    let galois_geometry = selected_trustee_evaluation_key_geometry(
        &evaluator_candidate,
        galois_catalog_level,
        commitment_data_modulus_indices,
    )?;
    let galois_entries = evaluator_candidate
        .galois_key_schedule
        .iter()
        .copied()
        .enumerate()
        .map(|(schedule_position, (galois_element, level))| {
            Ok(GaloisKeyShareRelationEntryInput {
                schedule_position: u32::try_from(schedule_position)
                    .map_err(|_| ProofProfileError::CountOverflow)?,
                galois_element: u64::try_from(galois_element)
                    .map_err(|_| ProofProfileError::CountOverflow)?,
                selected_level: level,
            })
        })
        .collect::<Result<Vec<_>, ProofProfileError>>()?;
    let [galois_batch_schedule_position] = selected_galois_key_share_batch_schedule();
    let galois_key_shares = compile_galois_key_share_relation_plan(
        &GaloisKeyShareRelationPlanInput {
            batch_schedule_position: galois_batch_schedule_position,
            ordered_entries: galois_entries,
            geometry: galois_geometry.clone(),
        },
        &ordinary_context,
    )?;
    let evaluator_variants = selected_evaluator_aggregate_variants(
        &evaluator_candidate,
        &relinearization_root_component_moduli,
    )?;
    let evaluator_key_aggregate = compile_evaluator_key_aggregate_relation_plan(
        &EvaluatorKeyAggregatePlanInput {
            geometry: aggregate_geometry,
            ordered_variants: evaluator_variants,
        },
        &public_aggregate_context,
    )?;

    let ballot_validity = compile_ballot_validity_relation_plan(
        &BallotValidityRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            active_data_modulus_indices: active_data_modulus_indices.clone(),
            plaintext_modulus: PLAINTEXT_MODULUS,
            reserved_slot_rule: RESERVED_BALLOT_SLOT_RULE,
        },
        &ordinary_context,
    )?;

    let target_release = selected_target_release_relation()?.relation_plan().clone();

    let committed_material_input = selected_committed_material_relation_plan_input()?;
    let vss_share_linkage = compile_vss_share_linkage_relation_plan(
        &committed_material_input,
        &committed_material_context,
    )?;
    let aggregate_threshold_share = compile_aggregate_threshold_share_relation_plan(
        &committed_material_input,
        &committed_material_context,
    )?;

    let compiled_plans = vec![
        same_secret,
        public_key_share,
        collective_public_key,
        relinearization_round_one,
        rkg_round_one_aggregate,
        relinearization_round_two,
        galois_key_shares,
        evaluator_key_aggregate,
        ballot_validity,
        target_release,
        vss_share_linkage,
        aggregate_threshold_share,
    ];
    let _non_native_identity_soundness_ledger =
        selected_non_native_identity_soundness_ledger(&compiled_plans)?;
    compiled_plans
        .into_iter()
        .map(|plan| {
            let context = selected_relation_plan_check_context(
                plan.application_statement_schema_identifier(),
            )
            .ok_or(ProofProfileError::InvalidSchedule)?;
            ValidatedRelationPlanArtifact::from_owned_compiled_plan(plan, &context)
        })
        .collect()
}

pub(crate) fn selected_same_secret_relation_plan_input()
-> Result<SameSecretRelationPlanInput, ProofProfileError> {
    let material_column_degree_bound_exclusive = u64::try_from(
        selected_committed_material_profile()?.material_column_degree_bound_exclusive(),
    )
    .map_err(|_| ProofProfileError::CountOverflow)?;
    Ok(SameSecretRelationPlanInput {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        material_column_degree_bound_exclusive,
        public_polynomial_column_degree_bound_exclusive:
            SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        sharing_data_modulus_indices: selected_sharing_data_modulus_indices()?,
        commitment_data_modulus_indices: selected_commitment_data_modulus_indices()?,
        commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
            .map_err(|_| ProofProfileError::CountOverflow)?,
    })
}

pub(crate) fn selected_public_key_share_relation_plan_input()
-> Result<PublicKeyShareRelationPlanInput, ProofProfileError> {
    Ok(PublicKeyShareRelationPlanInput {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        public_polynomial_column_degree_bound_exclusive:
            SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        data_modulus_indices: selected_data_modulus_indices(),
        commitment_data_modulus_indices: selected_commitment_data_modulus_indices()?,
        commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
            .map_err(|_| ProofProfileError::CountOverflow)?,
        plaintext_modulus: PLAINTEXT_MODULUS,
    })
}

fn selected_commitment_data_modulus_indices() -> Result<Vec<u16>, ProofProfileError> {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .copied()
        .map(|modulus_index| {
            u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)
        })
        .collect()
}

fn selected_trustee_evaluation_key_geometry(
    evaluator_candidate: &EvaluatorCandidateInput,
    catalog_level: usize,
    commitment_data_modulus_indices: Vec<u16>,
) -> Result<TrusteeEvaluationKeyRelationGeometry, ProofProfileError> {
    let relation_basis =
        trustee_evaluation_key_relation_basis_for_catalog_level(evaluator_candidate, catalog_level)
            .map_err(|_| ProofProfileError::InvalidRelationPlan)?;

    Ok(TrusteeEvaluationKeyRelationGeometry {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        public_polynomial_column_degree_bound_exclusive:
            SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        data_moduli: relation_basis.data_moduli,
        special_moduli: relation_basis.special_moduli,
        plaintext_modulus: evaluator_candidate.plaintext_modulus,
        decomposition_blocks: relation_basis.decomposition_blocks,
        commitment_data_modulus_indices,
        commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
            .map_err(|_| ProofProfileError::CountOverflow)?,
    })
}

pub(crate) fn selected_relinearization_relation_plan_inputs() -> Result<
    (
        RelinearizationRoundOneRelationPlanInput,
        RelinearizationRoundTwoRelationPlanInput,
    ),
    ProofProfileError,
> {
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let (schedule_position, catalog_level) = evaluator_candidate
        .relinearization_levels
        .iter()
        .copied()
        .enumerate()
        .next()
        .filter(|_| evaluator_candidate.relinearization_levels.len() == 1)
        .ok_or(ProofProfileError::InvalidRelationPlan)?;
    let schedule_position =
        u32::try_from(schedule_position).map_err(|_| ProofProfileError::CountOverflow)?;
    let geometry = selected_trustee_evaluation_key_geometry(
        &evaluator_candidate,
        catalog_level,
        selected_commitment_data_modulus_indices()?,
    )?;
    Ok((
        RelinearizationRoundOneRelationPlanInput {
            schedule_position,
            geometry: geometry.clone(),
        },
        RelinearizationRoundTwoRelationPlanInput {
            schedule_position,
            geometry,
        },
    ))
}

pub(crate) fn selected_galois_key_share_relation_plan_input()
-> Result<GaloisKeyShareRelationPlanInput, ProofProfileError> {
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let catalog_level = evaluator_candidate
        .galois_key_schedule
        .iter()
        .map(|(_, level)| *level)
        .max()
        .ok_or(ProofProfileError::InvalidRelationPlan)?;
    let commitment_data_modulus_indices = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .copied()
        .map(|modulus_index| {
            u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let geometry = selected_trustee_evaluation_key_geometry(
        &evaluator_candidate,
        catalog_level,
        commitment_data_modulus_indices,
    )?;
    let ordered_entries = evaluator_candidate
        .galois_key_schedule
        .iter()
        .copied()
        .enumerate()
        .map(|(schedule_position, (galois_element, selected_level))| {
            Ok(GaloisKeyShareRelationEntryInput {
                schedule_position: u32::try_from(schedule_position)
                    .map_err(|_| ProofProfileError::CountOverflow)?,
                galois_element: u64::try_from(galois_element)
                    .map_err(|_| ProofProfileError::CountOverflow)?,
                selected_level,
            })
        })
        .collect::<Result<Vec<_>, ProofProfileError>>()?;
    let [batch_schedule_position] = selected_galois_key_share_batch_schedule();
    Ok(GaloisKeyShareRelationPlanInput {
        batch_schedule_position,
        ordered_entries,
        geometry,
    })
}

fn selected_evaluator_aggregate_variants(
    evaluator_candidate: &EvaluatorCandidateInput,
    ordered_relinearization_runtime_component_moduli: &[SuiteModulusReference],
) -> Result<Vec<EvaluatorKeyAggregateVariantInput>, ProofProfileError> {
    let commitment_data_modulus_indices = selected_commitment_data_modulus_indices()?;
    (1..=FOUNDATION_PROFILE.option_count)
        .map(|top_count| {
            let ordered_entries = selected_evaluator_entry_positions(top_count)
                .map_err(|_| ProofProfileError::InvalidRelationPlan)?
                .into_iter()
                .map(|position| {
                    let source_schedule_position = usize::try_from(position.schedule_position())
                        .map_err(|_| ProofProfileError::CountOverflow)?;
                    let ordered_runtime_component_moduli = match position.key_kind() {
                        SelectedEvaluatorEntryKind::Relinearization { catalog_level } => {
                            if evaluator_candidate
                                .relinearization_levels
                                .get(source_schedule_position)
                                .copied()
                                != Some(catalog_level)
                            {
                                return Err(ProofProfileError::InvalidRelationPlan);
                            }
                            ordered_relinearization_runtime_component_moduli.to_vec()
                        }
                        SelectedEvaluatorEntryKind::Galois {
                            galois_element,
                            catalog_level,
                        } => {
                            if evaluator_candidate
                                .galois_key_schedule
                                .get(source_schedule_position)
                                .copied()
                                != Some((galois_element, catalog_level))
                            {
                                return Err(ProofProfileError::InvalidRelationPlan);
                            }
                            let geometry = selected_trustee_evaluation_key_geometry(
                                evaluator_candidate,
                                catalog_level,
                                commitment_data_modulus_indices.clone(),
                            )?;
                            trace_half_modulus_references(
                                &ordered_trustee_root_row_modulus_references(&geometry)?,
                            )
                        }
                    };
                    Ok(EvaluatorKeyAggregateEntryPlanInput {
                        schedule_position: position.schedule_position(),
                        ordered_runtime_component_moduli,
                    })
                })
                .collect::<Result<Vec<_>, ProofProfileError>>()?;
            Ok(EvaluatorKeyAggregateVariantInput {
                top_count,
                ordered_entries,
            })
        })
        .collect()
}

fn ordered_trustee_root_row_modulus_references(
    geometry: &TrusteeEvaluationKeyRelationGeometry,
) -> Result<Vec<SuiteModulusReference>, ProofProfileError> {
    let ordered_moduli = (0..geometry.data_moduli.len())
        .map(|modulus_index| {
            Ok(SuiteModulusReference::data(
                u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)?,
            ))
        })
        .chain((0..geometry.special_moduli.len()).map(|modulus_index| {
            Ok(SuiteModulusReference::special(
                u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)?,
            ))
        }))
        .collect::<Result<Vec<_>, ProofProfileError>>()?;
    Ok((0..geometry.decomposition_blocks.len())
        .flat_map(|_| ordered_moduli.iter().copied())
        .collect())
}

fn trace_half_modulus_references(
    ordered_moduli: &[SuiteModulusReference],
) -> Vec<SuiteModulusReference> {
    ordered_moduli
        .iter()
        .copied()
        .flat_map(|modulus_reference| [modulus_reference; 2])
        .collect()
}

fn selected_data_modulus_indices() -> Vec<u16> {
    (0..DATA_PRIMES.len())
        .map(|modulus_index| {
            u16::try_from(modulus_index).expect("the selected data basis fits u16")
        })
        .collect()
}

fn selected_sharing_data_modulus_indices() -> Result<Vec<u16>, ProofProfileError> {
    selected_sharing_data_prime_coordinates()
        .map(|coordinates| {
            coordinates
                .iter()
                .map(|(data_modulus_index, _)| *data_modulus_index)
                .collect()
        })
        .map_err(|_| ProofProfileError::InvalidRelationPlan)
}

fn selected_ring_degree() -> u64 {
    u64::try_from(POLYNOMIAL_DEGREE).expect("the selected ring degree fits u64")
}

fn modular_power(base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let modulus_wide = u128::from(modulus);
    let mut result = 1_u128;
    let mut base_wide = u128::from(base) % modulus_wide;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = (result * base_wide) % modulus_wide;
        }
        base_wide = (base_wide * base_wide) % modulus_wide;
        exponent >>= 1;
    }
    u64::try_from(result).expect("the modular result is less than the u64 modulus")
}

#[cfg(test)]
mod tests {
    use super::super::relation_plan::{
        BoundTreeConstructionKind, RelationColumnOrigin, RelationMaskKind, RelationTreeDescriptor,
    };
    use super::super::transcript::{
        CommonProofApplicationChallengeGroup, CommonProofPrivacyMode,
        CommonProofRelationPrefixSchedule,
    };
    use super::*;

    fn assert_fixed_block_sampler_accounting(
        sampler_accounting: CommonProofApplicationChallengeSamplerAccounting,
        expected_candidate_block_count: u64,
    ) {
        let oracle_answer_byte_length = sampler_accounting.maximum_oracle_answer_byte_length();
        assert_eq!(
            oracle_answer_byte_length,
            u64::try_from(Hash512::BYTE_LENGTH).expect("the oracle answer length fits u64"),
        );
        assert_eq!(
            sampler_accounting.candidate_byte_length(),
            expected_candidate_block_count * oracle_answer_byte_length,
        );
        assert_eq!(
            sampler_accounting.maximum_candidate_draw_count(),
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        );
        assert_eq!(sampler_accounting.chain_handle_xof_query_count(), 1);
        let expected_candidate_xof_query_count =
            u64::from(sampler_accounting.maximum_candidate_draw_count())
                * expected_candidate_block_count;
        assert_eq!(
            sampler_accounting.candidate_xof_query_count_ceiling(),
            expected_candidate_xof_query_count,
        );
        assert_eq!(
            sampler_accounting.total_xof_query_count_ceiling(),
            sampler_accounting.chain_handle_xof_query_count() + expected_candidate_xof_query_count,
        );
        assert_eq!(
            sampler_accounting.total_xof_query_count_ceiling(),
            expected_product_sampler_total_xof_query_count_ceiling(sampler_accounting)
                .expect("the fixed-block sampler query ceiling derives"),
        );
    }

    #[test]
    fn product_sampler_query_ceiling_scales_with_rounded_candidate_blocks() {
        let group = CommonProofApplicationChallengeGroup::new(
            CommonProofChallenge::Alpha { modulus_ordinal: 0 },
            2,
            513,
        )
        .expect("the 513-bit product sampler derives");
        let schedule = CommonProofRelationPrefixSchedule::new(
            Vec::new(),
            vec![group],
            Vec::new(),
            1,
            1,
            1,
            1,
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            CommonProofPrivacyMode::PublicOnly,
        )
        .expect("the two-block sampler schedule is valid");
        let [sampler_accounting] = schedule
            .ordered_application_challenge_sampler_accounting()
            .expect("the two-block sampler accounting derives")
            .try_into()
            .expect("the schedule has exactly one application sampler");

        assert_fixed_block_sampler_accounting(sampler_accounting, 2);
    }

    #[test]
    fn conservative_theta_screen_requires_five_repetitions_independently_of_alpha() {
        let theta_challenge = CommonProofChallenge::Theta { modulus_ordinal: 1 };
        let (theta_event_factor, theta_ceiling_bits) =
            selected_non_native_identity_screen(theta_challenge, 20)
                .expect("the selected theta screen derives");
        assert_eq!(theta_event_factor, 20 * 24 * 12 * 200);
        assert_eq!(theta_ceiling_bits, 176);
        assert_eq!(
            minimum_non_native_identity_repetition_count(
                PROOF_BASE_FIELD_MODULUS,
                &[65_534; 4],
                theta_event_factor,
                theta_ceiling_bits,
            ),
            Err(ProofProfileError::InvalidSchedule),
        );
        assert_eq!(
            minimum_non_native_identity_repetition_count(
                PROOF_BASE_FIELD_MODULUS,
                &[65_534; 5],
                theta_event_factor,
                theta_ceiling_bits,
            ),
            Ok(5),
        );

        let (alpha_event_factor, alpha_ceiling_bits) = selected_non_native_identity_screen(
            CommonProofChallenge::Alpha { modulus_ordinal: 0 },
            10,
        )
        .expect("the independently selected alpha screen derives");
        assert_eq!(alpha_event_factor, 10 * 12);
        assert_eq!(alpha_ceiling_bits, 184);
        assert_eq!(
            minimum_non_native_identity_repetition_count(
                DATA_PRIMES[0],
                &[9; 7],
                alpha_event_factor,
                alpha_ceiling_bits,
            ),
            Ok(7),
        );
        assert_eq!(
            selected_non_native_identity_screen(theta_challenge, u32::MAX),
            Err(ProofProfileError::CountOverflow),
        );
        assert_eq!(
            selected_non_native_identity_screen(
                CommonProofChallenge::Composition {
                    constraint_ordinal: 0,
                },
                1,
            ),
            Err(ProofProfileError::InvalidSchedule),
        );
    }

    #[test]
    fn selected_physical_proof_counts_follow_production_topology() {
        let root_topology =
            FirstProfileRootTopology::selected(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
                .expect("selected root topology");
        let evaluator_resource_accounting =
            selected_evaluator_resource_accounting().expect("selected evaluator accounting");
        let galois_batch_schedule = selected_galois_key_share_batch_schedule();
        let application_slot_ceilings =
            selected_proof_application_slot_ceilings().expect("selected application slots");
        let family_ceiling = |schema_identifier| {
            application_slot_ceilings
                .family_ceiling(schema_identifier)
                .expect("selected family application slots")
        };
        let roster_size = u32::from(root_topology.roster_size());
        let relinearization_position_count =
            evaluator_resource_accounting.relinearization_position_count();
        let galois_batch_count =
            u32::try_from(galois_batch_schedule.len()).expect("Galois batch count fits u32");

        for schema_identifier in [
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        ] {
            assert_eq!(family_ceiling(schema_identifier), roster_size);
        }
        assert_eq!(
            family_ceiling(
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            roster_size * relinearization_position_count,
        );
        assert_eq!(
            family_ceiling(
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            relinearization_position_count,
        );
        assert_eq!(
            family_ceiling(
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            roster_size * relinearization_position_count,
        );
        assert_eq!(
            family_ceiling(
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            roster_size * galois_batch_count,
        );
        assert_eq!(
            family_ceiling(
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            1,
        );
        assert_eq!(
            family_ceiling(
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            1,
        );
        assert_eq!(
            family_ceiling(
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        );

        assert_eq!(
            application_slot_ceilings.total_application_slot_ceiling(),
            crate::foundation::selected_maximum_proof_objects_per_action()
                .expect("selected suite proof-object ceiling"),
        );
    }

    #[test]
    fn selected_non_native_identity_counts_are_independently_minimal() {
        let relation_artifacts = selected_relation_plans().expect("selected relation plans");
        let compiled_plans = relation_artifacts
            .iter()
            .map(|artifact| artifact.compiled_plan().clone())
            .collect::<Vec<_>>();
        let rows = selected_non_native_identity_soundness_ledger(&compiled_plans)
            .expect("selected non-native identity soundness ledger");
        let accepted_coordinate_byte_length =
            u64::try_from(std::mem::size_of::<u64>()).expect("the coordinate width fits u64");

        let ballot_theta_row = rows
            .iter()
            .find(|row| {
                row.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                    && row.arithmetic_modulus_reference == SuiteModulusReference::plaintext()
            })
            .expect("selected ballot plaintext theta row");
        assert!(matches!(
            ballot_theta_row.challenge,
            CommonProofChallenge::Theta { .. }
        ));
        assert_eq!(
            ballot_theta_row.ordered_bad_polynomial_degrees,
            vec![65_534; 5]
        );
        assert_eq!(
            ballot_theta_row.complete_action_application_multiplicity,
            20
        );
        assert_eq!(
            ballot_theta_row.bad_set_numerator,
            BigUint::from(65_534_u64).pow(5)
        );
        assert_eq!(
            ballot_theta_row.sample_space_denominator,
            BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(5),
        );
        assert_eq!(ballot_theta_row.screen_event_factor, 1_152_000);
        assert_eq!(ballot_theta_row.screen_ceiling_bits, 176);
        assert_eq!(ballot_theta_row.minimum_repetition_count(), Ok(5));
        assert!(
            ballot_theta_row
                .satisfies_selected_screen()
                .expect("theta screen")
        );
        assert_eq!(
            ballot_theta_row.sampler_accounting.modulus(),
            PROOF_BASE_FIELD_MODULUS
        );
        assert_eq!(ballot_theta_row.sampler_accounting.coordinate_count(), 5);
        assert_fixed_block_sampler_accounting(ballot_theta_row.sampler_accounting, 1);
        assert_eq!(
            ballot_theta_row
                .sampler_accounting
                .accepted_vector_byte_length(),
            u64::from(ballot_theta_row.sampler_accounting.coordinate_count())
                * accepted_coordinate_byte_length,
        );
        assert_eq!(
            minimum_non_native_identity_repetition_count(
                PROOF_BASE_FIELD_MODULUS,
                &[65_534; 4],
                1_152_000,
                176,
            ),
            Err(ProofProfileError::InvalidSchedule),
        );

        let vss_alpha_row = rows
            .iter()
            .find(|row| {
                row.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                    && row.arithmetic_modulus_reference == SuiteModulusReference::data(0)
            })
            .expect("selected VSS first-data-modulus alpha row");
        assert!(matches!(
            vss_alpha_row.challenge,
            CommonProofChallenge::Alpha { .. }
        ));
        assert_eq!(vss_alpha_row.ordered_bad_polynomial_degrees, vec![9; 7]);
        assert_eq!(vss_alpha_row.complete_action_application_multiplicity, 10);
        assert_eq!(vss_alpha_row.bad_set_numerator, BigUint::from(9_u8).pow(7));
        assert_eq!(
            vss_alpha_row.sample_space_denominator,
            BigUint::from(DATA_PRIMES[0]).pow(7),
        );
        assert_eq!(vss_alpha_row.minimum_repetition_count(), Ok(7));
        assert_eq!(vss_alpha_row.screen_event_factor, 120);
        assert_eq!(vss_alpha_row.screen_ceiling_bits, 184);
        assert!(
            vss_alpha_row
                .satisfies_selected_screen()
                .expect("alpha margin")
        );
        assert_eq!(vss_alpha_row.sampler_accounting.modulus(), DATA_PRIMES[0]);
        assert_eq!(vss_alpha_row.sampler_accounting.coordinate_count(), 7);
        assert_fixed_block_sampler_accounting(vss_alpha_row.sampler_accounting, 1);
        assert_eq!(
            vss_alpha_row
                .sampler_accounting
                .accepted_vector_byte_length(),
            u64::from(vss_alpha_row.sampler_accounting.coordinate_count())
                * accepted_coordinate_byte_length,
        );
        assert_eq!(
            minimum_non_native_identity_repetition_count(DATA_PRIMES[0], &[9; 6], 120, 184),
            Err(ProofProfileError::InvalidSchedule),
        );
    }

    #[test]
    fn selected_contexts_bind_each_family_schedule() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected ordinary proof context");
        assert_eq!(context.out_of_domain_point_count, 1);
        assert_eq!(context.phase_column_query_coordinate_count, 387);
        assert_eq!(
            context.evaluation_domain_generator,
            17_654_865_857_378_133_588
        );
        assert_eq!(context.quotient_component_degree_bound_exclusive, 34_050);
        assert_eq!(
            context.resolved_moduli.len(),
            DATA_PRIMES.len()
                + SPECIAL_PRIMES.len()
                + 1
                + DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL].len()
        );

        let persistent_material_profile =
            CommittedMaterialProfile::for_common_proof_evaluation_domain(
                POLYNOMIAL_DEGREE,
                usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
                    .expect("the selected evaluation domain fits usize"),
                usize::try_from(SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE)
                    .expect("the selected opening bound fits usize"),
            )
            .expect("persistent material profile on the consuming domain");
        assert_eq!(
            persistent_material_profile.material_column_degree_bound_exclusive(),
            18_432
        );
        assert_eq!(
            persistent_material_profile.masking_polynomial_maximum_degree(),
            2_047
        );
        assert_eq!(
            persistent_material_profile.committed_polynomial_degree_bound_exclusive(),
            usize::try_from(SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE)
                .expect("the selected opening bound fits usize")
        );

        let committed_material_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected committed-material proof context");
        assert_eq!(committed_material_context.out_of_domain_point_count, 1);
        assert_eq!(
            committed_material_context.phase_column_query_coordinate_count,
            387
        );
        assert_eq!(committed_material_context.quotient_component_count, 3);
        assert_eq!(
            committed_material_context.quotient_component_degree_bound_exclusive,
            selected_committed_material_quotient_component_degree_bound_exclusive()
                .expect("selected committed-material quotient bound derives")
        );
        assert_eq!(
            committed_material_context.quotient_component_degree_bound_exclusive,
            68_655
        );
        assert_eq!(
            committed_material_context.evaluation_domain_generator,
            context.evaluation_domain_generator
        );
        for family in [
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        ] {
            let public_aggregate_context = selected_relation_plan_check_context(family)
                .expect("selected public-aggregate proof context");
            assert_eq!(public_aggregate_context.out_of_domain_point_count, 1);
            assert_eq!(
                public_aggregate_context.phase_column_query_coordinate_count,
                387
            );
            assert_eq!(public_aggregate_context.quotient_component_count, 9);
            assert_eq!(
                public_aggregate_context.quotient_component_degree_bound_exclusive,
                16_384
            );
            assert_eq!(
                public_aggregate_context.evaluation_domain_generator,
                context.evaluation_domain_generator
            );
        }
        assert!(
            selected_relation_plan_check_context(0xffff).is_none(),
            "an unsupported caller-selected family cannot acquire a selected context",
        );
    }

    #[test]
    fn selected_public_aggregate_quotient_capacity_covers_the_exact_maximum_degree() {
        let trace_domain_size = SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE;
        let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
        let numerator_maximum_degree = participant_count * (trace_domain_size - 1);
        let quotient_maximum_degree = numerator_maximum_degree - trace_domain_size;
        let quotient_coefficient_count = numerator_maximum_degree - trace_domain_size + 1;
        let quotient_capacity = u64::from(SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_COUNT)
            * SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE;
        let one_fewer_component_capacity =
            u64::from(SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_COUNT - 1)
                * SELECTED_PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE;
        assert_eq!(numerator_maximum_degree, 163_830);
        assert_eq!(quotient_maximum_degree, 147_446);
        assert_eq!(quotient_coefficient_count, 147_447);
        assert_eq!(quotient_capacity, 147_456);
        assert_eq!(one_fewer_component_capacity, 131_072);
        assert!(quotient_coefficient_count > one_fewer_component_capacity);
        assert!(quotient_coefficient_count <= quotient_capacity);
    }

    #[test]
    fn selected_secret_relation_masks_match_row_code_phase_geometry() {
        let same_secret_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected same-secret context");
        let same_secret_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &same_secret_context,
        )
        .expect("selected same-secret relation plan");
        let same_secret_variant = same_secret_plan
            .select_variant(None, None)
            .expect("selected same-secret variant");
        assert_eq!(
            same_secret_variant.quotient_decomposition_stride(&same_secret_context),
            Ok(17_266)
        );
        assert!(same_secret_variant.ordered_masks().iter().all(|mask| {
            match mask.mask_kind() {
                RelationMaskKind::Trace => mask.mask_degree_bound_exclusive() == 784,
                RelationMaskKind::Telescoping => mask.mask_degree_bound_exclusive() == 16_784,
                RelationMaskKind::OpeningBatch => mask.mask_degree_bound_exclusive() == 262_143,
            }
        }));

        let ballot_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected ballot context");
        let ballot_compilation = selected_ballot_validity_relation_compilation()
            .expect("selected ballot relation compilation");
        let ballot_variant = ballot_compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("selected ballot variant");
        assert_eq!(
            ballot_variant.quotient_decomposition_stride(&ballot_context),
            Ok(33_662)
        );
        assert!(ballot_variant.ordered_masks().iter().all(|mask| {
            match mask.mask_kind() {
                RelationMaskKind::Trace => mask.mask_degree_bound_exclusive() == 794,
                RelationMaskKind::Telescoping => mask.mask_degree_bound_exclusive() == 388,
                RelationMaskKind::OpeningBatch => mask.mask_degree_bound_exclusive() == 262_143,
            }
        }));
    }

    #[test]
    fn selected_profile_has_the_complete_relation_and_root_inventory() {
        let mut profile = selected_proof_profile_set(3).expect("selected proof profile");
        assert_eq!(
            profile.relation_plans().len(),
            super::super::FIRST_PROFILE_APPLICATION_FAMILIES.len()
        );

        let relation_plan = |schema_identifier| {
            profile
                .relation_plans()
                .iter()
                .find(|artifact| {
                    artifact.application_statement_schema_identifier() == schema_identifier
                })
                .expect("selected relation family")
                .compiled_plan()
        };
        let evaluator_plan = relation_plan(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        );
        let key_positions = selected_evaluator_program_set()
            .and_then(|program| program.key_positions())
            .expect("selected evaluator key positions");
        assert_eq!(
            key_positions
                .galois_catalog_positions()
                .iter()
                .map(|position| (position.galois_element(), position.catalog_level()))
                .collect::<Vec<_>>(),
            vec![
                (15, 14),
                (19, 14),
                (219, 14),
                (257, 18),
                (1_025, 18),
                (8_193, 18),
            ]
        );
        let evaluator_entry_count_by_top_count = key_positions
            .streams()
            .iter()
            .map(|stream| {
                (
                    stream.top_count(),
                    stream.relinearization_catalog_levels().len()
                        + stream.galois_catalog_positions().len(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            evaluator_plan.variants().len(),
            usize::from(FOUNDATION_PROFILE.option_count)
        );
        let trees_per_evaluator_entry = usize::from(FOUNDATION_PROFILE.participant_count) + 1;
        for (variant, (top_count, evaluator_entry_count)) in evaluator_plan
            .variants()
            .iter()
            .zip(&evaluator_entry_count_by_top_count)
        {
            assert_eq!(variant.schedule_position(), None);
            assert_eq!(variant.top_count(), Some(*top_count));
            assert_eq!(
                variant.ordered_trees().len(),
                evaluator_entry_count * trees_per_evaluator_entry
            );
        }

        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let sharing_limb_count = selected_sharing_data_modulus_indices()
            .expect("selected sharing coordinates")
            .len();
        let commitment_anchor_count = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len();
        let round_one_variant_count = relation_plan(
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .variants()
        .len();
        let round_one_aggregate_variant_count = relation_plan(
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .variants()
        .len();
        let round_two_variant_count = relation_plan(
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .variants()
        .len();
        let galois_variant_count = relation_plan(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .variants()
        .len();
        let galois_entry_count = EvaluatorCandidateInput::implemented()
            .expect("selected evaluator candidate")
            .galois_key_schedule
            .len();
        let expected_root_edge_count = participant_count * sharing_limb_count
            + participant_count * participant_count * sharing_limb_count
            + participant_count * 2
            + participant_count * commitment_anchor_count
            + participant_count
                * commitment_anchor_count
                * (round_one_variant_count + round_two_variant_count + galois_variant_count)
            + participant_count
            + round_one_aggregate_variant_count * participant_count * 2
            + round_two_variant_count * participant_count * 4
            + galois_variant_count * participant_count * galois_entry_count
            + evaluator_entry_count_by_top_count
                .iter()
                .map(|(_, evaluator_entry_count)| evaluator_entry_count * participant_count)
                .sum::<usize>();
        assert_eq!(
            profile.root_compatibility_edges().len(),
            expected_root_edge_count
        );
        profile.assert_catalog_mutation_boundaries();
    }

    #[test]
    fn selected_vss_relations_use_the_root_preserving_compact_range_plan() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected VSS proof context");
        let input = selected_committed_material_relation_plan_input()
            .expect("selected committed-material relation input");
        assert_eq!(
            input.sharing_data_modulus_indices.as_slice(),
            &[0, 1, 2, 3, 4, 5, 6, 7]
        );
        let share_linkage_plan = compile_vss_share_linkage_relation_plan(&input, &context)
            .expect("selected VSS share-linkage relation plan");
        let aggregate_threshold_plan =
            compile_aggregate_threshold_share_relation_plan(&input, &context)
                .expect("selected aggregate-threshold-share relation plan");
        let share_linkage = &share_linkage_plan.variants()[0];
        let aggregate_threshold = &aggregate_threshold_plan.variants()[0];

        assert_eq!(
            input
                .message_trace_domain_size()
                .expect("selected committed-material message trace domain"),
            16_384
        );
        assert_eq!(
            input
                .relation_trace_domain_size()
                .expect("selected committed-material packed trace domain"),
            65_536
        );
        assert_eq!(share_linkage.trace_domain_size(), 65_536);
        assert_eq!(share_linkage.opening_degree_bound_exclusive(), 262_144);
        assert_eq!(share_linkage.evaluation_domain_size(), 2_097_152);
        assert_eq!(context.out_of_domain_point_count, 1);
        assert_eq!(context.phase_column_query_coordinate_count, 387);
        assert_eq!(share_linkage.ordered_columns().len(), 3_451);
        assert_eq!(aggregate_threshold.ordered_columns().len(), 2_528);

        let minimum_telescoping_mask_degree_bound_exclusive =
            u64::from(context.phase_column_query_coordinate_count)
                .checked_add(u64::from(context.out_of_domain_point_count))
                .expect("selected telescoping-mask degree derives");
        assert_eq!(minimum_telescoping_mask_degree_bound_exclusive, 388);

        for (
            relation,
            expected_bound_root_count,
            expected_proof_created_column_count,
            expected_constraint_count,
        ) in [
            (share_linkage, 112, 3_003, 3_767),
            (aggregate_threshold, 88, 2_176, 2_672),
        ] {
            let quotient_decomposition_stride = relation
                .quotient_decomposition_stride(&context)
                .expect("selected quotient decomposition stride derives");
            assert_eq!(quotient_decomposition_stride, 68_267);
            assert_eq!(
                context.quotient_component_degree_bound_exclusive,
                quotient_decomposition_stride + minimum_telescoping_mask_degree_bound_exclusive
            );
            let maximum_prover_column_degree_bound_exclusive = relation
                .ordered_columns()
                .iter()
                .filter(|column| matches!(column.origin(), RelationColumnOrigin::Prover))
                .map(|column| column.source_degree_bound_exclusive())
                .max()
                .expect("selected relation has prover columns");
            assert_eq!(maximum_prover_column_degree_bound_exclusive, 67_584);
            assert!(relation.ordered_masks().iter().all(|mask| {
                mask.mask_kind() != RelationMaskKind::Trace
                    || mask.mask_degree_bound_exclusive() == 2_048
            }));
            let maximum_ternary_range_numerator_degree =
                (maximum_prover_column_degree_bound_exclusive - 1) * 3;
            assert_eq!(maximum_ternary_range_numerator_degree, 202_749);
            assert!(
                maximum_ternary_range_numerator_degree < relation.opening_degree_bound_exclusive()
            );
            assert!(
                context.quotient_component_degree_bound_exclusive
                    < relation.opening_degree_bound_exclusive()
            );
            let telescoping_masks = relation
                .ordered_masks()
                .iter()
                .filter(|mask| mask.mask_kind() == RelationMaskKind::Telescoping)
                .collect::<Vec<_>>();
            assert_eq!(telescoping_masks.len(), 2);
            assert!(telescoping_masks.iter().all(|mask| {
                mask.mask_degree_bound_exclusive()
                    == minimum_telescoping_mask_degree_bound_exclusive
            }));
            assert_eq!(
                relation
                    .ordered_columns()
                    .iter()
                    .filter(|column| matches!(column.origin(), RelationColumnOrigin::Prover))
                    .count(),
                expected_proof_created_column_count
            );
            assert_eq!(
                relation.ordered_constraint_count(),
                expected_constraint_count
            );
            let proof_created_trees = relation
                .ordered_trees()
                .iter()
                .filter_map(|tree| match tree {
                    RelationTreeDescriptor::ProofCreated {
                        ordered_column_ordinals,
                        ..
                    } => Some(ordered_column_ordinals),
                    RelationTreeDescriptor::BoundPublic { .. } => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(proof_created_trees.len(), 1);
            assert_eq!(
                proof_created_trees[0].len(),
                expected_proof_created_column_count
            );
            assert_eq!(
                relation
                    .ordered_trees()
                    .iter()
                    .filter(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
                    .count(),
                expected_bound_root_count
            );
            assert!(relation.ordered_trees().iter().all(|tree| match tree {
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    ordered_column_ordinals,
                    ..
                } => {
                    *construction_kind == BoundTreeConstructionKind::CommittedMaterial
                        && ordered_column_ordinals.len() == 4
                }
                RelationTreeDescriptor::ProofCreated { .. } => true,
            }));
        }
    }
}
