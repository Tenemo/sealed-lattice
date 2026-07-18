//! Deterministic construction of the fixed proof-profile artifact.

use num_bigint::BigUint;

use crate::bgv::{
    evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    parameters::{
        DATA_PRIMES, LOGICAL_SLOT_GENERATOR, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES,
        root_parameters_for_modulus,
    },
};
use crate::foundation::{
    ProofApplicationSlotCeilings, SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
    SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION, selected_evaluator_resource_accounting,
};

use crate::{
    bgv::{
        evaluator::{
            candidate_evidence::EvaluatorCandidateInput, program::selected_evaluator_program_set,
        },
        setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
        target_decryption::kllps_release::{
            KLLPS_DENOMINATOR_CLEARING_FACTOR, selected_factor_four_flooding_bound,
        },
    },
    foundation::FOUNDATION_PROFILE,
};

use super::profile::FIRST_PROFILE_APPLICATION_FAMILIES;
use super::relation_plan::trustee_evaluation_key_relation_basis_for_catalog_level;
use super::{
    BallotValidityRelationPlanInput, CompiledBallotValidityRelation,
    compile_ballot_validity_relation,
};
use super::{
    COMMITTED_MATERIAL_PROOF_EVALUATION_BLOWUP_FACTOR, COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT,
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR,
    PROOF_EVALUATION_COSET_OFFSET, PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT,
    RelationApplicationRoundByRoundTransitionCatalog, RelationPlanCheckContext,
    ResolvedSuiteModulus, SuiteModulusReference,
};

use super::{
    CollectivePublicKeyAggregatePlanInput, CommittedMaterialProfile,
    CommittedMaterialRelationPlanInput, CompiledTargetReleaseRelation,
    EvaluatorKeyAggregateEntryPlanInput, EvaluatorKeyAggregatePlanInput,
    EvaluatorKeyAggregateVariantInput, FirstProfileRootTopology, GaloisKeyShareRelationEntryInput,
    GaloisKeyShareRelationPlanInput, ProofProfileError, ProofProfileSet,
    PublicAggregateRelationGeometry, PublicKeyShareRelationPlanInput,
    RelinearizationRoundOneRelationPlanInput, RelinearizationRoundTwoRelationPlanInput,
    RkgRoundOneAggregatePlanInput, RkgRoundOneAggregateVariantInput, SameSecretRelationPlanInput,
    TargetReleaseRelationPlanInput, TrusteeEvaluationKeyRelationGeometry,
    ValidatedRelationPlanArtifact, compile_aggregate_threshold_share_relation_plan,
    compile_ballot_validity_relation_plan, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_galois_key_share_relation_plan,
    compile_public_key_share_relation_plan, compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_two_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_target_release_relation,
    compile_vss_share_linkage_relation_plan, selected_galois_key_share_batch_schedule,
};

pub(super) const SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 262_144;
const SELECTED_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 524_288;
pub(super) const SELECTED_EVALUATION_DOMAIN_SIZE: u64 =
    SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE * PROOF_EVALUATION_BLOWUP_FACTOR as u64;
pub(super) const SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE: u64 =
    POLYNOMIAL_DEGREE as u64 / 2;
const SELECTED_QUOTIENT_COMPONENT_COUNT: u32 = 8;
const SELECTED_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE: u64 = 33_884;
const SELECTED_COMMITTED_MATERIAL_QUOTIENT_COMPONENT_COUNT: u32 = 3;
const RESERVED_BALLOT_SLOT_RULE: u16 = 1;

/// Leading coefficient of the round-by-round error term in the CMS19
/// transformation bound
/// `B_g(Q_H) <= 12 * t_g^2 * epsilon_(rbr,g) + (48 * t_g^3 + 2 * k_g) / 2^512`.
/// This theorem constant is independent of the selected family inventory.
const CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT: u32 = 12;
const POWERS_MCA_NUMERATOR_BASE: u32 = 7;
const POWERS_MCA_NUMERATOR_EXPONENT: u32 = 7;
const ORDINARY_POWERS_MCA_DENOMINATOR_FACTOR: u32 = 12;
const COMMITTED_MATERIAL_POWERS_MCA_DENOMINATOR_FACTOR: u32 = 48;
const ORDINARY_QUERY_AGREEMENT_NUMERATOR: u32 = 3;
const ORDINARY_QUERY_AGREEMENT_DENOMINATOR: u32 = 8;
const COMMITTED_MATERIAL_QUERY_AGREEMENT_NUMERATOR: u32 = 5_001;
const COMMITTED_MATERIAL_QUERY_AGREEMENT_DENOMINATOR: u32 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedPhysicalProofMultiplicities {
    ordinary: u32,
    committed_material: u32,
}

/// One selected, non-serialized row of application round-by-round theorem
/// inputs. Every value is recomputed from the production relation variant and
/// its family-selected proof context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRelationApplicationRoundByRoundTheoremInput {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    transition_catalog: RelationApplicationRoundByRoundTransitionCatalog,
    numerical_bounds: SelectedRelationApplicationRoundByRoundNumericalBounds,
}

impl SelectedRelationApplicationRoundByRoundTheoremInput {
    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn transition_catalog(
        &self,
    ) -> &RelationApplicationRoundByRoundTransitionCatalog {
        &self.transition_catalog
    }

    pub(crate) const fn numerical_bounds(
        &self,
    ) -> &SelectedRelationApplicationRoundByRoundNumericalBounds {
        &self.numerical_bounds
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRoundByRoundProbabilityBound {
    numerator: BigUint,
    denominator: BigUint,
}

impl SelectedRoundByRoundProbabilityBound {
    fn new(numerator: BigUint, denominator: BigUint) -> Result<Self, ProofProfileError> {
        if denominator == BigUint::from(0_u8) || numerator > denominator {
            return Err(ProofProfileError::InvalidSchedule);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    pub(crate) const fn numerator(&self) -> &BigUint {
        &self.numerator
    }

    pub(crate) const fn denominator(&self) -> &BigUint {
        &self.denominator
    }

    pub(crate) fn is_at_most(&self, right: &Self) -> bool {
        &self.numerator * &right.denominator <= &right.numerator * &self.denominator
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRelationApplicationRoundByRoundNumericalBounds {
    ordered_non_native_challenge_bounds: Vec<SelectedRoundByRoundProbabilityBound>,
    composition_batching_bound: SelectedRoundByRoundProbabilityBound,
    deep_identity_bound: SelectedRoundByRoundProbabilityBound,
    opening_batch_mca_bound: SelectedRoundByRoundProbabilityBound,
    ordered_fri_fold_bounds: Vec<SelectedRoundByRoundProbabilityBound>,
    query_vector_bound: SelectedRoundByRoundProbabilityBound,
    round_by_round_error_bound: SelectedRoundByRoundProbabilityBound,
}

impl SelectedRelationApplicationRoundByRoundNumericalBounds {
    pub(crate) fn ordered_non_native_challenge_bounds(
        &self,
    ) -> &[SelectedRoundByRoundProbabilityBound] {
        &self.ordered_non_native_challenge_bounds
    }

    pub(crate) const fn composition_batching_bound(&self) -> &SelectedRoundByRoundProbabilityBound {
        &self.composition_batching_bound
    }

    pub(crate) const fn deep_identity_bound(&self) -> &SelectedRoundByRoundProbabilityBound {
        &self.deep_identity_bound
    }

    pub(crate) const fn opening_batch_mca_bound(&self) -> &SelectedRoundByRoundProbabilityBound {
        &self.opening_batch_mca_bound
    }

    pub(crate) fn ordered_fri_fold_bounds(&self) -> &[SelectedRoundByRoundProbabilityBound] {
        &self.ordered_fri_fold_bounds
    }

    pub(crate) const fn query_vector_bound(&self) -> &SelectedRoundByRoundProbabilityBound {
        &self.query_vector_bound
    }

    pub(crate) const fn round_by_round_error_bound(&self) -> &SelectedRoundByRoundProbabilityBound {
        &self.round_by_round_error_bound
    }
}

impl SelectedPhysicalProofMultiplicities {
    fn total(self) -> Result<u32, ProofProfileError> {
        self.ordinary
            .checked_add(self.committed_material)
            .ok_or(ProofProfileError::CountOverflow)
    }
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

fn selected_physical_proof_multiplicities()
-> Result<SelectedPhysicalProofMultiplicities, ProofProfileError> {
    let application_slot_ceilings = selected_proof_application_slot_ceilings()?;
    let multiplicities = application_slot_ceilings
        .ordered_family_ceilings()
        .iter()
        .try_fold(
            SelectedPhysicalProofMultiplicities {
                ordinary: 0,
                committed_material: 0,
            },
            |mut multiplicities, family| {
                let destination = if uses_committed_material_proof_schedule(
                    family.application_statement_schema_identifier,
                )
                .ok_or(ProofProfileError::UnsupportedFamily)?
                {
                    &mut multiplicities.committed_material
                } else {
                    &mut multiplicities.ordinary
                };
                *destination = destination
                    .checked_add(family.application_slot_ceiling)
                    .ok_or(ProofProfileError::CountOverflow)?;
                Ok::<SelectedPhysicalProofMultiplicities, ProofProfileError>(multiplicities)
            },
        )?;
    if multiplicities.total()? != application_slot_ceilings.total_application_slot_ceiling() {
        return Err(ProofProfileError::InvalidSchedule);
    }
    Ok(multiplicities)
}

fn fri_fold_count_for_degree_bounds(
    opening_degree_bound_exclusive: u64,
    final_degree_bound_exclusive: u32,
) -> Option<u16> {
    let final_degree_bound_exclusive = u64::from(final_degree_bound_exclusive);
    if opening_degree_bound_exclusive <= final_degree_bound_exclusive
        || final_degree_bound_exclusive <= 1
    {
        return None;
    }
    let mut current_degree_bound = opening_degree_bound_exclusive;
    let mut fold_count = 0_u16;
    while current_degree_bound > final_degree_bound_exclusive {
        current_degree_bound = current_degree_bound.checked_add(1)?.checked_div(2)?;
        fold_count = fold_count.checked_add(1)?;
    }
    Some(fold_count)
}

pub(crate) fn selected_relation_plan_check_context(
    application_statement_schema_identifier: u16,
) -> Option<RelationPlanCheckContext> {
    let uses_committed_material_schedule =
        uses_committed_material_proof_schedule(application_statement_schema_identifier)?;
    let evaluation_blowup_factor = if uses_committed_material_schedule {
        COMMITTED_MATERIAL_PROOF_EVALUATION_BLOWUP_FACTOR
    } else {
        PROOF_EVALUATION_BLOWUP_FACTOR
    };
    let opening_degree_bound_exclusive = if uses_committed_material_schedule {
        SELECTED_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE
    } else {
        SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE
    };
    if opening_degree_bound_exclusive.checked_mul(u64::from(evaluation_blowup_factor))?
        != SELECTED_EVALUATION_DOMAIN_SIZE
    {
        return None;
    }
    let fri_fold_count = fri_fold_count_for_degree_bounds(
        opening_degree_bound_exclusive,
        PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    )?;
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
        evaluation_blowup_factor,
        evaluation_domain_generator: modular_power(
            PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
            (1_u64 << 32) / SELECTED_EVALUATION_DOMAIN_SIZE,
            PROOF_BASE_FIELD_MODULUS,
        ),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        deep_point_count: PROOF_DEEP_POINT_COUNT,
        quotient_component_count: if uses_committed_material_schedule {
            SELECTED_COMMITTED_MATERIAL_QUOTIENT_COMPONENT_COUNT
        } else {
            SELECTED_QUOTIENT_COMPONENT_COUNT
        },
        quotient_component_degree_bound_exclusive: if uses_committed_material_schedule {
            selected_committed_material_quotient_component_degree_bound_exclusive().ok()?
        } else {
            SELECTED_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE
        },
        fri_fold_count,
        final_polynomial_degree_bound_exclusive: PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
        unique_query_count: if uses_committed_material_schedule {
            COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT
        } else {
            PROOF_UNIQUE_QUERY_COUNT
        },
        non_native_modular_identity_challenge_count: PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT,
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
    let primitive_two_n_root = root_parameters_for_modulus(PLAINTEXT_MODULUS)
        .ok_or(super::RelationPlanError::InvalidDomain)?
        .negacyclic_root;
    compile_ballot_validity_relation(
        &BallotValidityRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            active_data_modulus_indices: selected_data_modulus_indices(),
            plaintext_modulus: PLAINTEXT_MODULUS,
            primitive_two_n_root,
            slot_generator: u16::try_from(LOGICAL_SLOT_GENERATOR)
                .map_err(|_| super::RelationPlanError::CountOverflow)?,
            reserved_slot_rule: RESERVED_BALLOT_SLOT_RULE,
        },
        &relation_context,
    )
}

pub(crate) fn selected_proof_profile_set(
    maximum_ballot_attempts_per_participant: u16,
) -> Result<ProofProfileSet, ProofProfileError> {
    let relation_plans = selected_relation_plans()?;
    ProofProfileSet::new(
        relation_plans,
        FirstProfileRootTopology::selected(maximum_ballot_attempts_per_participant)?,
    )
}

pub(crate) fn selected_relation_application_round_by_round_theorem_inputs()
-> Result<Vec<SelectedRelationApplicationRoundByRoundTheoremInput>, ProofProfileError> {
    selected_relation_plans()?
        .into_iter()
        .flat_map(|artifact| {
            let application_statement_schema_identifier =
                artifact.application_statement_schema_identifier();
            let context =
                selected_relation_plan_check_context(application_statement_schema_identifier);
            artifact
                .compiled_plan()
                .variants()
                .iter()
                .cloned()
                .map(move |variant| {
                    (
                        application_statement_schema_identifier,
                        context.clone(),
                        variant,
                    )
                })
                .collect::<Vec<_>>()
        })
        .map(
            |(application_statement_schema_identifier, context, variant)| {
                let context = context.ok_or(ProofProfileError::InvalidSchedule)?;
                let transition_catalog = variant
                    .application_round_by_round_transition_catalog(&context)
                    .map_err(ProofProfileError::from)?;
                let numerical_bounds = selected_relation_application_numerical_bounds(
                    &variant,
                    &context,
                    &transition_catalog,
                )?;
                Ok(SelectedRelationApplicationRoundByRoundTheoremInput {
                    application_statement_schema_identifier,
                    schedule_position: variant.schedule_position(),
                    top_count: variant.top_count(),
                    transition_catalog,
                    numerical_bounds,
                })
            },
        )
        .collect()
}

pub(crate) fn selected_multiplicity_weighted_round_by_round_error_bound()
-> Result<SelectedRoundByRoundProbabilityBound, ProofProfileError> {
    let theorem_inputs = selected_relation_application_round_by_round_theorem_inputs()?;
    let application_slot_ceilings = selected_proof_application_slot_ceilings()?;
    let mut accumulated_numerator = BigUint::from(0_u8);
    let mut accumulated_denominator = BigUint::from(1_u8);
    let mut consumed_theorem_input_count = 0_usize;

    for family in application_slot_ceilings.ordered_family_ceilings() {
        let family_inputs = theorem_inputs
            .iter()
            .filter(|input| {
                input.application_statement_schema_identifier()
                    == family.application_statement_schema_identifier
            })
            .collect::<Vec<_>>();
        let family_bound = family_inputs
            .iter()
            .map(|input| input.numerical_bounds().round_by_round_error_bound())
            .reduce(|left, right| if left.is_at_most(right) { right } else { left })
            .ok_or(ProofProfileError::InvalidSchedule)?;
        consumed_theorem_input_count = consumed_theorem_input_count
            .checked_add(family_inputs.len())
            .ok_or(ProofProfileError::CountOverflow)?;
        let weighted_multiplicity = family
            .application_slot_ceiling
            .checked_mul(CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT)
            .ok_or(ProofProfileError::CountOverflow)?;
        accumulated_numerator = &accumulated_numerator * family_bound.denominator()
            + BigUint::from(weighted_multiplicity)
                * family_bound.numerator()
                * &accumulated_denominator;
        accumulated_denominator *= family_bound.denominator();
    }
    if consumed_theorem_input_count != theorem_inputs.len() {
        return Err(ProofProfileError::InvalidSchedule);
    }
    SelectedRoundByRoundProbabilityBound::new(accumulated_numerator, accumulated_denominator)
}

fn selected_relation_application_numerical_bounds(
    variant: &super::RelationPlanVariant,
    context: &RelationPlanCheckContext,
    transition_catalog: &RelationApplicationRoundByRoundTransitionCatalog,
) -> Result<SelectedRelationApplicationRoundByRoundNumericalBounds, ProofProfileError> {
    let (powers_mca_denominator_factor, query_agreement_numerator, query_agreement_denominator) =
        match context.evaluation_blowup_factor {
            PROOF_EVALUATION_BLOWUP_FACTOR => (
                ORDINARY_POWERS_MCA_DENOMINATOR_FACTOR,
                ORDINARY_QUERY_AGREEMENT_NUMERATOR,
                ORDINARY_QUERY_AGREEMENT_DENOMINATOR,
            ),
            COMMITTED_MATERIAL_PROOF_EVALUATION_BLOWUP_FACTOR => (
                COMMITTED_MATERIAL_POWERS_MCA_DENOMINATOR_FACTOR,
                COMMITTED_MATERIAL_QUERY_AGREEMENT_NUMERATOR,
                COMMITTED_MATERIAL_QUERY_AGREEMENT_DENOMINATOR,
            ),
            _ => return Err(ProofProfileError::InvalidSchedule),
        };
    if variant
        .opening_degree_bound_exclusive()
        .checked_mul(u64::from(context.evaluation_blowup_factor))
        != Some(variant.evaluation_domain_size())
    {
        return Err(ProofProfileError::InvalidSchedule);
    }

    let extension_field_cardinality = transition_catalog
        .deep_allowed_set_root_bound()
        .extension_field_cardinality()
        .clone();
    let ordered_non_native_challenge_bounds = transition_catalog
        .ordered_non_native_challenge_bad_sets()
        .iter()
        .map(|group| {
            SelectedRoundByRoundProbabilityBound::new(
                group.product_bad_candidate_count_bound(),
                group.product_space_cardinality(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let composition_batching_bound = SelectedRoundByRoundProbabilityBound::new(
        BigUint::from(1_u8),
        extension_field_cardinality.clone(),
    )?;
    let deep_bound = transition_catalog.deep_allowed_set_root_bound();
    let deep_identity_bound = SelectedRoundByRoundProbabilityBound::new(
        deep_bound.root_count_bound().clone(),
        deep_bound.allowed_candidate_count_lower_bound().clone(),
    )?;

    let initial_powers_mca_bound = selected_powers_mca_bound(
        variant.evaluation_domain_size(),
        powers_mca_denominator_factor,
        &extension_field_cardinality,
    )?;
    let opening_batch_mca_bound = SelectedRoundByRoundProbabilityBound::new(
        initial_powers_mca_bound.numerator()
            * transition_catalog.opening_batch_mca_transition_count(),
        initial_powers_mca_bound.denominator().clone(),
    )?;

    let mut folded_domain_size = variant.evaluation_domain_size();
    let mut ordered_fri_fold_bounds =
        Vec::with_capacity(usize::from(transition_catalog.fri_fold_transition_count()));
    for _ in 0..transition_catalog.fri_fold_transition_count() {
        if folded_domain_size <= 1 || folded_domain_size % 2 != 0 {
            return Err(ProofProfileError::InvalidSchedule);
        }
        folded_domain_size /= 2;
        ordered_fri_fold_bounds.push(selected_powers_mca_bound(
            folded_domain_size,
            powers_mca_denominator_factor,
            &extension_field_cardinality,
        )?);
    }

    let query_vector_bound = SelectedRoundByRoundProbabilityBound::new(
        BigUint::from(query_agreement_numerator)
            .pow(transition_catalog.query_vector_position_count()),
        BigUint::from(query_agreement_denominator)
            .pow(transition_catalog.query_vector_position_count()),
    )?;
    let mut round_by_round_error_bound = query_vector_bound.clone();
    for candidate in ordered_non_native_challenge_bounds
        .iter()
        .chain([&composition_batching_bound, &deep_identity_bound])
        .chain([&opening_batch_mca_bound])
        .chain(ordered_fri_fold_bounds.iter())
    {
        if !candidate.is_at_most(&round_by_round_error_bound) {
            round_by_round_error_bound = candidate.clone();
        }
    }

    Ok(SelectedRelationApplicationRoundByRoundNumericalBounds {
        ordered_non_native_challenge_bounds,
        composition_batching_bound,
        deep_identity_bound,
        opening_batch_mca_bound,
        ordered_fri_fold_bounds,
        query_vector_bound,
        round_by_round_error_bound,
    })
}

/// Instantiates the proved length-two Powers/MCA upper bound used by both the
/// opening-claim batching hybrids and each radix-two FRI fold. The selected
/// rate-specific denominator factors are the fixed rational upper bounds at
/// the two selected Johnson-regime distance endpoints.
fn selected_powers_mca_bound(
    code_domain_size: u64,
    denominator_factor: u32,
    extension_field_cardinality: &BigUint,
) -> Result<SelectedRoundByRoundProbabilityBound, ProofProfileError> {
    if code_domain_size == 0 || denominator_factor == 0 {
        return Err(ProofProfileError::InvalidSchedule);
    }
    SelectedRoundByRoundProbabilityBound::new(
        BigUint::from(POWERS_MCA_NUMERATOR_BASE).pow(POWERS_MCA_NUMERATOR_EXPONENT)
            * BigUint::from(code_domain_size).pow(2),
        BigUint::from(denominator_factor) * extension_field_cardinality,
    )
}

pub(crate) fn selected_committed_material_profile()
-> Result<CommittedMaterialProfile, ProofProfileError> {
    CommittedMaterialProfile::for_common_proof_evaluation_domain(
        POLYNOMIAL_DEGREE,
        usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
            .map_err(|_| ProofProfileError::CountOverflow)?,
    )
    .map_err(|_| ProofProfileError::InvalidRelationPlan)
}

pub(crate) fn selected_target_decryption_flooding_bound() -> Result<BigUint, ProofProfileError> {
    selected_factor_four_flooding_bound().map_err(|_| ProofProfileError::InvalidRelationPlan)
}

/// Compiles the sole selected target-release relation from production suite
/// constants. Accounting, generation adapters, and verification all consume
/// this constructor so the six-prime factor-four geometry cannot drift.
pub(crate) fn selected_target_release_relation()
-> Result<CompiledTargetReleaseRelation, ProofProfileError> {
    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(ProofProfileError::InvalidSchedule)?;
    let commitment_data_modulus_indices = selected_commitment_data_modulus_indices()?;
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
            flooding_bound: selected_target_decryption_flooding_bound()?.into(),
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
        opening_degree_bound_exclusive: SELECTED_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE,
        material_column_degree_bound_exclusive: u64::try_from(
            committed_material_profile.material_column_degree_bound_exclusive(),
        )
        .map_err(|_| ProofProfileError::CountOverflow)?,
        participant_count: FOUNDATION_PROFILE.participant_count,
        threshold: FOUNDATION_PROFILE.reconstruction_threshold,
        sharing_data_modulus_indices: selected_data_modulus_indices(),
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
        u64::from(COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT)
            .checked_mul(2)
            .and_then(|query_coordinate_count| {
                query_coordinate_count.checked_add(u64::from(PROOF_DEEP_POINT_COUNT))
            })
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
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let committed_material_profile = selected_committed_material_profile()?;
    let material_column_degree_bound_exclusive =
        u64::try_from(committed_material_profile.material_column_degree_bound_exclusive())
            .map_err(|_| ProofProfileError::CountOverflow)?;
    let same_secret = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()?,
        &ordinary_context,
    )?;
    let public_key_share = compile_public_key_share_relation_plan(
        &selected_public_key_share_relation_plan_input()?,
        &ordinary_context,
    )?;
    let sharing_data_modulus_indices = selected_data_modulus_indices();

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
            ordered_component_moduli: split_polynomial_modulus_references(
                &sharing_data_modulus_indices
                    .iter()
                    .copied()
                    .map(SuiteModulusReference::data)
                    .collect::<Vec<_>>(),
            ),
        },
        &ordinary_context,
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
    let relinearization_root_component_moduli = split_polynomial_modulus_references(
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
        &ordinary_context,
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
        .first()
        .map(|(_, level)| *level)
        .filter(|level| {
            *level == evaluator_candidate.evaluator_working_level
                && evaluator_candidate
                    .galois_key_schedule
                    .iter()
                    .all(|(_, candidate_level)| candidate_level == level)
        })
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
            if level != galois_catalog_level {
                return Err(ProofProfileError::InvalidRelationPlan);
            }
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
    let galois_root_component_moduli = split_polynomial_modulus_references(
        &ordered_trustee_root_row_modulus_references(&galois_geometry)?,
    );

    let evaluator_variants = selected_evaluator_aggregate_variants(
        &evaluator_candidate,
        &relinearization_root_component_moduli,
        &galois_root_component_moduli,
    )?;
    let evaluator_key_aggregate = compile_evaluator_key_aggregate_relation_plan(
        &EvaluatorKeyAggregatePlanInput {
            geometry: aggregate_geometry,
            ordered_variants: evaluator_variants,
        },
        &ordinary_context,
    )?;

    let ballot_validity = compile_ballot_validity_relation_plan(
        &BallotValidityRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            active_data_modulus_indices: sharing_data_modulus_indices.clone(),
            plaintext_modulus: PLAINTEXT_MODULUS,
            primitive_two_n_root: root_parameters_for_modulus(PLAINTEXT_MODULUS)
                .ok_or(ProofProfileError::InvalidRelationPlan)?
                .negacyclic_root,
            slot_generator: u16::try_from(LOGICAL_SLOT_GENERATOR)
                .map_err(|_| ProofProfileError::CountOverflow)?,
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
        sharing_data_modulus_indices: selected_data_modulus_indices(),
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

pub(crate) fn selected_galois_key_share_relation_plan_input()
-> Result<GaloisKeyShareRelationPlanInput, ProofProfileError> {
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let catalog_level = evaluator_candidate
        .galois_key_schedule
        .first()
        .map(|(_, level)| *level)
        .filter(|level| {
            *level == evaluator_candidate.evaluator_working_level
                && evaluator_candidate
                    .galois_key_schedule
                    .iter()
                    .all(|(_, candidate_level)| candidate_level == level)
        })
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
    ordered_galois_runtime_component_moduli: &[SuiteModulusReference],
) -> Result<Vec<EvaluatorKeyAggregateVariantInput>, ProofProfileError> {
    let key_positions = selected_evaluator_program_set()
        .and_then(|program| program.key_positions())
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    if key_positions.relinearization_catalog_levels() != evaluator_candidate.relinearization_levels
        || key_positions.galois_catalog_positions().len()
            != evaluator_candidate.galois_key_schedule.len()
        || key_positions
            .galois_catalog_positions()
            .iter()
            .zip(&evaluator_candidate.galois_key_schedule)
            .any(|(position, expected)| {
                (position.galois_element(), position.catalog_level()) != *expected
            })
    {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    if key_positions.streams().len() != usize::from(FOUNDATION_PROFILE.option_count) {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    key_positions
        .streams()
        .iter()
        .map(|stream| {
            let mut ordered_entries = stream
                .relinearization_catalog_levels()
                .iter()
                .map(|level| {
                    let schedule_position = key_positions
                        .relinearization_catalog_levels()
                        .binary_search(level)
                        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
                    Ok(EvaluatorKeyAggregateEntryPlanInput {
                        schedule_position: u32::try_from(schedule_position)
                            .map_err(|_| ProofProfileError::CountOverflow)?,
                        ordered_runtime_component_moduli:
                            ordered_relinearization_runtime_component_moduli.to_vec(),
                    })
                })
                .collect::<Result<Vec<_>, ProofProfileError>>()?;
            ordered_entries.extend(
                stream
                    .galois_catalog_positions()
                    .iter()
                    .map(|position| {
                        let schedule_position = key_positions
                            .galois_catalog_positions()
                            .binary_search(position)
                            .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
                        Ok(EvaluatorKeyAggregateEntryPlanInput {
                            schedule_position: u32::try_from(schedule_position)
                                .map_err(|_| ProofProfileError::CountOverflow)?,
                            ordered_runtime_component_moduli:
                                ordered_galois_runtime_component_moduli.to_vec(),
                        })
                    })
                    .collect::<Result<Vec<_>, ProofProfileError>>()?,
            );
            Ok(EvaluatorKeyAggregateVariantInput {
                top_count: stream.top_count(),
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

fn split_polynomial_modulus_references(
    ordered_moduli: &[SuiteModulusReference],
) -> Vec<SuiteModulusReference> {
    ordered_moduli
        .iter()
        .copied()
        .flat_map(|modulus_reference| [modulus_reference, modulus_reference])
        .collect()
}

fn selected_data_modulus_indices() -> Vec<u16> {
    (0..DATA_PRIMES.len())
        .map(|modulus_index| {
            u16::try_from(modulus_index).expect("the selected data basis fits u16")
        })
        .collect()
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
    use std::collections::BTreeSet;

    use super::super::relation_plan::{
        BoundTreeConstructionKind, RelationColumnOrigin, RelationMaskKind, RelationTreeDescriptor,
    };
    use super::*;

    fn fraction_is_at_most(
        left_numerator: &BigUint,
        left_denominator: &BigUint,
        right_numerator: &BigUint,
        right_denominator: &BigUint,
    ) -> bool {
        left_numerator * right_denominator <= right_numerator * left_denominator
    }

    fn homogeneous_non_native_group_bound_for_repetition_count(
        group: &super::super::RelationApplicationChallengeBadSetGroup,
        repetition_count: u16,
    ) -> SelectedRoundByRoundProbabilityBound {
        let first_coordinate = group
            .ordered_coordinate_bounds()
            .first()
            .expect("a selected non-native group contains a coordinate");
        assert!(group.ordered_coordinate_bounds().iter().all(|coordinate| {
            coordinate.bad_polynomial_degree_bound()
                == first_coordinate.bad_polynomial_degree_bound()
                && coordinate.bad_candidate_count_bound()
                    == first_coordinate.bad_candidate_count_bound()
        }));
        SelectedRoundByRoundProbabilityBound::new(
            BigUint::from(first_coordinate.bad_candidate_count_bound())
                .pow(u32::from(repetition_count)),
            BigUint::from(group.coordinate_modulus()).pow(u32::from(repetition_count)),
        )
        .expect("a product-space bad set is a probability")
    }

    fn multiplicity_weighted_query_error_mass(
        multiplicities: SelectedPhysicalProofMultiplicities,
        committed_material_query_count: u32,
    ) -> (BigUint, BigUint) {
        let ordinary_denominator = BigUint::from(8_u32).pow(PROOF_UNIQUE_QUERY_COUNT);
        let ordinary_numerator = BigUint::from(3_u32).pow(PROOF_UNIQUE_QUERY_COUNT);
        let committed_material_denominator =
            BigUint::from(10_000_u32).pow(committed_material_query_count);
        let committed_material_numerator =
            BigUint::from(5_001_u32).pow(committed_material_query_count);
        let common_denominator = &ordinary_denominator * &committed_material_denominator;
        let weighted_numerator = BigUint::from(CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT)
            * (BigUint::from(multiplicities.ordinary)
                * ordinary_numerator
                * &committed_material_denominator
                + BigUint::from(multiplicities.committed_material)
                    * committed_material_numerator
                    * ordinary_denominator);
        (weighted_numerator, common_denominator)
    }

    fn selected_multiplicity_weighted_query_error_mass(
        committed_material_query_count: u32,
    ) -> Result<(BigUint, BigUint), ProofProfileError> {
        Ok(multiplicity_weighted_query_error_mass(
            selected_physical_proof_multiplicities()?,
            committed_material_query_count,
        ))
    }

    #[test]
    fn cms19_coefficient_is_applied_once_per_physical_proof_event() {
        let ordinary_only = SelectedPhysicalProofMultiplicities {
            ordinary: 1,
            committed_material: 0,
        };
        let (ordinary_weighted_numerator, ordinary_common_denominator) =
            multiplicity_weighted_query_error_mass(ordinary_only, 1);
        let ordinary_numerator = BigUint::from(3_u32).pow(PROOF_UNIQUE_QUERY_COUNT);
        let ordinary_denominator = BigUint::from(8_u32).pow(PROOF_UNIQUE_QUERY_COUNT);
        assert_eq!(
            &ordinary_weighted_numerator * &ordinary_denominator,
            BigUint::from(12_u32) * ordinary_numerator * &ordinary_common_denominator,
        );

        let committed_material_only = SelectedPhysicalProofMultiplicities {
            ordinary: 0,
            committed_material: 1,
        };
        let committed_material_query_count = 7;
        let (committed_weighted_numerator, committed_common_denominator) =
            multiplicity_weighted_query_error_mass(
                committed_material_only,
                committed_material_query_count,
            );
        let committed_numerator = BigUint::from(5_001_u32).pow(committed_material_query_count);
        let committed_denominator = BigUint::from(10_000_u32).pow(committed_material_query_count);
        assert_eq!(
            &committed_weighted_numerator * &committed_denominator,
            BigUint::from(12_u32) * committed_numerator * &committed_common_denominator,
        );
    }

    #[test]
    fn selected_physical_proof_multiplicities_follow_production_topology() {
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

        let multiplicities =
            selected_physical_proof_multiplicities().expect("selected proof multiplicities");
        let committed_material_multiplicity = [
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ]
        .into_iter()
        .map(family_ceiling)
        .sum::<u32>();
        assert_eq!(
            multiplicities.committed_material,
            committed_material_multiplicity,
        );
        assert_eq!(
            multiplicities.ordinary,
            application_slot_ceilings.total_application_slot_ceiling()
                - committed_material_multiplicity,
        );
        assert_eq!(
            multiplicities.total().expect("selected multiplicity total"),
            application_slot_ceilings.total_application_slot_ceiling(),
        );
        assert_eq!(
            application_slot_ceilings.total_application_slot_ceiling(),
            crate::foundation::selected_maximum_proof_objects_per_action()
                .expect("selected suite proof-object ceiling"),
        );
    }

    #[test]
    fn selected_contexts_bind_each_family_schedule() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected ordinary proof context");
        assert_eq!(context.deep_point_count, 1);
        assert_eq!(
            context.evaluation_domain_generator,
            17_654_865_857_378_133_588
        );
        assert_eq!(context.fri_fold_count, 10);
        assert_eq!(context.evaluation_blowup_factor, 8);
        assert_eq!(context.unique_query_count, 168);
        assert_eq!(
            context.resolved_moduli.len(),
            DATA_PRIMES.len() + SPECIAL_PRIMES.len() + 3
        );

        let persistent_material_profile =
            CommittedMaterialProfile::for_common_proof_evaluation_domain(
                POLYNOMIAL_DEGREE,
                usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
                    .expect("the selected evaluation domain fits usize"),
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
        assert_eq!(committed_material_context.evaluation_blowup_factor, 4);
        assert_eq!(committed_material_context.unique_query_count, 192);
        assert_eq!(committed_material_context.fri_fold_count, 11);
        assert_eq!(committed_material_context.quotient_component_count, 3);
        assert_eq!(
            committed_material_context.quotient_component_degree_bound_exclusive,
            selected_committed_material_quotient_component_degree_bound_exclusive()
                .expect("selected committed-material quotient bound derives")
        );
        assert_eq!(
            committed_material_context.quotient_component_degree_bound_exclusive,
            265_261
        );
        assert_eq!(
            committed_material_context.evaluation_domain_generator,
            context.evaluation_domain_generator
        );
        assert!(
            selected_relation_plan_check_context(0xffff).is_none(),
            "an unsupported caller-selected family cannot acquire a selected context",
        );
    }

    #[test]
    fn selected_round_by_round_rows_cover_every_variant_and_exact_transition_count() {
        let artifacts = selected_relation_plans().expect("selected relation plans");
        let theorem_inputs = selected_relation_application_round_by_round_theorem_inputs()
            .expect("selected application theorem inputs");
        assert_eq!(
            theorem_inputs
                .iter()
                .map(|input| input.application_statement_schema_identifier())
                .collect::<BTreeSet<_>>(),
            FIRST_PROFILE_APPLICATION_FAMILIES.into_iter().collect(),
        );
        assert_eq!(
            theorem_inputs.len(),
            artifacts
                .iter()
                .map(|artifact| artifact.compiled_plan().variants().len())
                .sum::<usize>(),
        );

        for input in &theorem_inputs {
            let artifact = artifacts
                .iter()
                .find(|artifact| {
                    artifact.application_statement_schema_identifier()
                        == input.application_statement_schema_identifier()
                })
                .expect("theorem input family belongs to the selected inventory");
            let variant = artifact
                .compiled_plan()
                .select_variant(input.schedule_position(), input.top_count())
                .expect("theorem input selector resolves exactly one variant");
            let context = selected_relation_plan_check_context(
                input.application_statement_schema_identifier(),
            )
            .expect("selected theorem input context");
            let catalog = input.transition_catalog();
            assert_eq!(
                catalog.opening_batch_mca_transition_count(),
                u32::try_from(variant.ordered_opening_claims().len())
                    .expect("selected opening-claim count fits u32"),
            );
            assert_eq!(catalog.fri_fold_transition_count(), context.fri_fold_count);
            assert_eq!(catalog.query_vector_transition_count(), 1);
            assert_eq!(
                catalog.query_vector_position_count(),
                context.unique_query_count,
            );
            assert_eq!(catalog.composition_batching_transition_count(), 1);
            assert_eq!(
                catalog.composition_coefficient_count(),
                u32::try_from(variant.constraint_count())
                    .expect("selected constraint count fits u32"),
            );
            assert_eq!(
                catalog.maximum_candidate_draws_per_output(),
                context.maximum_fiat_shamir_candidate_draws_per_output,
            );

            let mut prior_group_key = None;
            for group in catalog.ordered_non_native_challenge_bad_sets() {
                let group_key = (group.challenge_role(), group.modulus_reference());
                assert!(prior_group_key.is_none_or(|prior| prior < group_key));
                prior_group_key = Some(group_key);
                assert_eq!(
                    group.ordered_coordinate_bounds().len(),
                    usize::from(PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT),
                );
                assert_eq!(
                    group
                        .ordered_coordinate_bounds()
                        .iter()
                        .map(|coordinate| coordinate.repetition_ordinal())
                        .collect::<Vec<_>>(),
                    (0..PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT).collect::<Vec<_>>(),
                );
                assert!(group.ordered_coordinate_bounds().iter().all(|coordinate| {
                    coordinate.bad_candidate_count_bound()
                        <= coordinate.bad_polynomial_degree_bound()
                        && coordinate.bad_candidate_count_bound() <= group.coordinate_modulus()
                }));
            }

            let deep = catalog.deep_allowed_set_root_bound();
            assert_eq!(
                catalog.deep_point_transition_count(),
                context.deep_point_count
            );
            assert_eq!(
                deep.allowed_candidate_count_lower_bound() + deep.forbidden_candidate_count_bound(),
                deep.extension_field_cardinality().clone(),
            );
            assert!(deep.root_count_bound() <= &BigUint::from(deep.identity_degree_bound()),);

            let numerical = input.numerical_bounds();
            assert_eq!(
                numerical.ordered_non_native_challenge_bounds().len(),
                catalog.ordered_non_native_challenge_bad_sets().len(),
            );
            for (bound, group) in numerical
                .ordered_non_native_challenge_bounds()
                .iter()
                .zip(catalog.ordered_non_native_challenge_bad_sets())
            {
                assert_eq!(
                    bound.numerator(),
                    &group.product_bad_candidate_count_bound()
                );
                assert_eq!(bound.denominator(), &group.product_space_cardinality());
            }
            assert_eq!(
                numerical.composition_batching_bound().numerator(),
                &BigUint::from(1_u8),
            );
            assert_eq!(
                numerical.composition_batching_bound().denominator(),
                deep.extension_field_cardinality(),
            );
            assert_eq!(
                numerical.deep_identity_bound().numerator(),
                deep.root_count_bound(),
            );
            assert_eq!(
                numerical.deep_identity_bound().denominator(),
                deep.allowed_candidate_count_lower_bound(),
            );
            assert_eq!(
                numerical.ordered_fri_fold_bounds().len(),
                usize::from(catalog.fri_fold_transition_count()),
            );
            for adjacent_bounds in numerical.ordered_fri_fold_bounds().windows(2) {
                assert_eq!(
                    adjacent_bounds[1].numerator() * 4_u8,
                    adjacent_bounds[0].numerator().clone(),
                );
                assert_eq!(
                    adjacent_bounds[1].denominator(),
                    adjacent_bounds[0].denominator(),
                );
            }
            let first_fold = numerical
                .ordered_fri_fold_bounds()
                .first()
                .expect("the selected schedule contains a FRI fold");
            assert_eq!(
                numerical.opening_batch_mca_bound().numerator(),
                &(first_fold.numerator() * 4_u8 * catalog.opening_batch_mca_transition_count()),
            );
            assert_eq!(
                numerical.opening_batch_mca_bound().denominator(),
                first_fold.denominator(),
            );

            let query_bound = numerical.query_vector_bound();
            let (expected_query_numerator_base, expected_query_denominator_base) =
                if context.evaluation_blowup_factor == PROOF_EVALUATION_BLOWUP_FACTOR {
                    (
                        ORDINARY_QUERY_AGREEMENT_NUMERATOR,
                        ORDINARY_QUERY_AGREEMENT_DENOMINATOR,
                    )
                } else {
                    assert_eq!(
                        context.evaluation_blowup_factor,
                        COMMITTED_MATERIAL_PROOF_EVALUATION_BLOWUP_FACTOR,
                    );
                    (
                        COMMITTED_MATERIAL_QUERY_AGREEMENT_NUMERATOR,
                        COMMITTED_MATERIAL_QUERY_AGREEMENT_DENOMINATOR,
                    )
                };
            assert_eq!(
                query_bound.numerator(),
                &BigUint::from(expected_query_numerator_base)
                    .pow(catalog.query_vector_position_count()),
            );
            assert_eq!(
                query_bound.denominator(),
                &BigUint::from(expected_query_denominator_base)
                    .pow(catalog.query_vector_position_count()),
            );
            assert!(
                numerical
                    .ordered_non_native_challenge_bounds()
                    .iter()
                    .chain([
                        numerical.composition_batching_bound(),
                        numerical.deep_identity_bound(),
                        numerical.opening_batch_mca_bound(),
                        query_bound,
                    ])
                    .chain(numerical.ordered_fri_fold_bounds())
                    .all(|bound| bound.is_at_most(numerical.round_by_round_error_bound())),
                "the derived row maximum must cover every exact transition",
            );
        }
    }

    #[test]
    fn committed_material_query_count_has_an_exact_eight_bit_selected_margin() {
        let extension_field_size =
            BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(PROOF_CHALLENGE_EXTENSION_DEGREE as u32);
        let evaluation_domain_size_squared = BigUint::from(SELECTED_EVALUATION_DOMAIN_SIZE).pow(2);
        let common_fold_numerator = BigUint::from(7_u32).pow(7) * evaluation_domain_size_squared;

        // The proved Johnson-regime fold error is exact at rate 1/4:
        // 7^7 * |L0|^2 / (48 * |F|). At rate 1/8, replacing
        // rho^(3/2) by the smaller rational 1/32 gives the conservative
        // upper bound 7^7 * |L0|^2 / (12 * |F|). Both are far below the
        // respective final-query transition and therefore do not determine
        // the per-message maximum.
        let committed_material_fold_denominator = BigUint::from(48_u32) * &extension_field_size;
        let ordinary_fold_upper_denominator = BigUint::from(12_u32) * &extension_field_size;
        assert!(fraction_is_at_most(
            &common_fold_numerator,
            &committed_material_fold_denominator,
            &BigUint::from(5_001_u32).pow(184),
            &BigUint::from(10_000_u32).pow(184),
        ));
        assert!(fraction_is_at_most(
            &common_fold_numerator,
            &ordinary_fold_upper_denominator,
            &BigUint::from(3_u32).pow(168),
            &BigUint::from(8_u32).pow(168),
        ));

        let operative_ceiling_denominator = BigUint::from(2_u32).pow(176);
        let selected_margin_denominator = BigUint::from(2_u32).pow(184);
        let one = BigUint::from(1_u32);

        let (below_minimum_numerator, below_minimum_denominator) =
            selected_multiplicity_weighted_query_error_mass(183)
                .expect("selected physical proof multiplicities");
        assert!(!fraction_is_at_most(
            &below_minimum_numerator,
            &below_minimum_denominator,
            &one,
            &operative_ceiling_denominator,
        ));

        let (minimum_numerator, minimum_denominator) =
            selected_multiplicity_weighted_query_error_mass(184)
                .expect("selected physical proof multiplicities");
        assert!(fraction_is_at_most(
            &minimum_numerator,
            &minimum_denominator,
            &one,
            &operative_ceiling_denominator,
        ));
        assert!(!fraction_is_at_most(
            &minimum_numerator,
            &minimum_denominator,
            &one,
            &selected_margin_denominator,
        ));

        let (below_selected_margin_numerator, below_selected_margin_denominator) =
            selected_multiplicity_weighted_query_error_mass(191)
                .expect("selected physical proof multiplicities");
        assert!(!fraction_is_at_most(
            &below_selected_margin_numerator,
            &below_selected_margin_denominator,
            &one,
            &selected_margin_denominator,
        ));
        let (selected_numerator, selected_denominator) =
            selected_multiplicity_weighted_query_error_mass(
                COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT,
            )
            .expect("selected physical proof multiplicities");
        assert!(fraction_is_at_most(
            &selected_numerator,
            &selected_denominator,
            &one,
            &selected_margin_denominator,
        ));
    }

    #[test]
    fn selected_non_native_repetition_count_is_the_minimum_for_the_action_margin() {
        let selected_bound = selected_multiplicity_weighted_round_by_round_error_bound()
            .expect("selected multiplicity-weighted round-by-round bound");
        let selected_margin = SelectedRoundByRoundProbabilityBound::new(
            BigUint::from(1_u8),
            BigUint::from(2_u8).pow(184),
        )
        .expect("selected action margin");
        assert!(selected_bound.is_at_most(&selected_margin));

        let prior_repetition_count = PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT
            .checked_sub(1)
            .expect("the selected repetition count is positive");
        let ballot_family =
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
        let ballot_theorem_input = selected_relation_application_round_by_round_theorem_inputs()
            .expect("selected application theorem inputs")
            .into_iter()
            .find(|input| input.application_statement_schema_identifier() == ballot_family)
            .expect("selected ballot theorem input");
        let prior_ballot_non_native_bound = ballot_theorem_input
            .transition_catalog()
            .ordered_non_native_challenge_bad_sets()
            .iter()
            .map(|group| {
                homogeneous_non_native_group_bound_for_repetition_count(
                    group,
                    prior_repetition_count,
                )
            })
            .reduce(|left, right| if left.is_at_most(&right) { right } else { left })
            .expect("the ballot relation contains a non-native challenge group");
        let ballot_multiplicity = selected_proof_application_slot_ceilings()
            .expect("selected proof application slots")
            .family_ceiling(ballot_family)
            .expect("selected ballot multiplicity");
        let prior_weighted_ballot_lower_bound = SelectedRoundByRoundProbabilityBound::new(
            BigUint::from(
                ballot_multiplicity
                    .checked_mul(CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT)
                    .expect("weighted ballot multiplicity fits u32"),
            ) * prior_ballot_non_native_bound.numerator(),
            prior_ballot_non_native_bound.denominator().clone(),
        )
        .expect("the prior weighted ballot lower bound is a probability");
        assert!(
            !prior_weighted_ballot_lower_bound.is_at_most(&selected_margin),
            "one fewer non-native repetition already fails on the ballot contribution alone",
        );
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
        let sharing_limb_count = DATA_PRIMES.len();
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
            32_768
        );
        assert_eq!(
            input
                .relation_trace_domain_size()
                .expect("selected committed-material packed trace domain"),
            262_144
        );
        assert_eq!(share_linkage.trace_domain_size(), 262_144);
        assert_eq!(share_linkage.opening_degree_bound_exclusive(), 524_288);
        assert_eq!(share_linkage.evaluation_domain_size(), 2_097_152);
        assert_eq!(share_linkage.ordered_columns().len(), 9_414);
        assert_eq!(aggregate_threshold.ordered_columns().len(), 8_932);

        let minimum_telescoping_mask_degree_bound_exclusive = u64::from(context.unique_query_count)
            .checked_mul(2)
            .and_then(|query_coordinate_count| {
                query_coordinate_count.checked_add(u64::from(context.deep_point_count))
            })
            .expect("selected telescoping-mask degree derives");

        for (relation, expected_bound_root_count, expected_proof_created_column_count) in [
            (share_linkage, 364, 7_958),
            (aggregate_threshold, 286, 7_788),
        ] {
            let quotient_decomposition_stride = relation
                .quotient_decomposition_stride(&context)
                .expect("selected quotient decomposition stride derives");
            assert_eq!(quotient_decomposition_stride, 264_875);
            assert_eq!(
                context.quotient_component_degree_bound_exclusive,
                quotient_decomposition_stride + minimum_telescoping_mask_degree_bound_exclusive
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
