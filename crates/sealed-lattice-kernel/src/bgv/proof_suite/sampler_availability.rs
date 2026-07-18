//! Exact honest-exhaustion accounting for the common-proof public samplers.
//!
//! This module is a source-owned correctness and availability ledger. None of
//! its values is serialized, transcript-bound, accepted from proof bytes, or
//! included in invalid-acceptance soundness. Exhausting a checked draw ceiling
//! remains a loud proof-generation or verification refusal.

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::foundation::FOUNDATION_PROFILE;

use super::{
    RelationApplicationRoundByRoundTransitionCatalog, RelationChallengeRole,
    RelationPlanCheckContext, RelationPlanVariant, SuiteModulusReference,
    selected_profile::{
        selected_proof_application_slot_ceilings, selected_relation_plan_check_context,
        selected_relation_plans,
    },
};

const COMMON_PROOF_EXTENSION_CANDIDATE_BIT_LENGTH: u32 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofSamplerAvailabilityAccountingError {
    CountOverflow,
    InvalidSchedule,
    SelectedProfile,
}

/// Exact dyadic probability or a dyadic union upper bound. The represented
/// fraction is `numerator / 2^denominator_power_of_two_exponent`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofSamplerExhaustionProbabilityBound {
    numerator: BigUint,
    denominator_power_of_two_exponent: u32,
}

impl CommonProofSamplerExhaustionProbabilityBound {
    fn new(
        numerator: BigUint,
        denominator_power_of_two_exponent: u32,
    ) -> Result<Self, CommonProofSamplerAvailabilityAccountingError> {
        if numerator > power_of_two(denominator_power_of_two_exponent)? {
            return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
        }
        Ok(Self {
            numerator,
            denominator_power_of_two_exponent,
        })
    }

    fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator_power_of_two_exponent: 0,
        }
    }

    pub(crate) const fn numerator(&self) -> &BigUint {
        &self.numerator
    }

    pub(crate) const fn denominator_power_of_two_exponent(&self) -> u32 {
        self.denominator_power_of_two_exponent
    }

    pub(crate) fn denominator(
        &self,
    ) -> Result<BigUint, CommonProofSamplerAvailabilityAccountingError> {
        power_of_two(self.denominator_power_of_two_exponent)
    }

    pub(crate) fn is_at_most_inverse_power_of_two(&self, exponent: u32) -> bool {
        if self.numerator.is_zero() {
            return true;
        }
        if self.denominator_power_of_two_exponent < exponent {
            return false;
        }
        let Ok(numerator_ceiling_shift) =
            usize::try_from(self.denominator_power_of_two_exponent - exponent)
        else {
            return false;
        };
        self.numerator <= BigUint::one() << numerator_ceiling_shift
    }

    fn checked_union(
        &self,
        right: &Self,
    ) -> Result<Self, CommonProofSamplerAvailabilityAccountingError> {
        let common_exponent = self
            .denominator_power_of_two_exponent
            .max(right.denominator_power_of_two_exponent);
        let left_shift = usize::try_from(common_exponent - self.denominator_power_of_two_exponent)
            .map_err(|_| CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
        let right_shift =
            usize::try_from(common_exponent - right.denominator_power_of_two_exponent)
                .map_err(|_| CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
        let mut numerator = (&self.numerator << left_shift) + (&right.numerator << right_shift);
        let denominator = power_of_two(common_exponent)?;
        if numerator > denominator {
            numerator = denominator;
        }
        Self::new(numerator, common_exponent)
    }

    fn checked_multiply_union(
        &self,
        multiplicity: u64,
    ) -> Result<Self, CommonProofSamplerAvailabilityAccountingError> {
        let mut numerator = &self.numerator * BigUint::from(multiplicity);
        let denominator = power_of_two(self.denominator_power_of_two_exponent)?;
        if numerator > denominator {
            numerator = denominator;
        }
        Self::new(numerator, self.denominator_power_of_two_exponent)
    }
}

/// Exact ideal-XOF exhaustion fraction for one jointly sampled theta or alpha
/// product vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofProductSamplerAvailabilityAccounting {
    challenge_role: RelationChallengeRole,
    modulus_reference: SuiteModulusReference,
    coordinate_modulus: u64,
    coordinate_count: u16,
    product_space_cardinality: BigUint,
    candidate_byte_length: u64,
    raw_candidate_space_power_of_two_exponent: u32,
    rejected_raw_candidate_count: BigUint,
    maximum_candidate_draw_count: u32,
    exhaustion_probability: CommonProofSamplerExhaustionProbabilityBound,
}

impl CommonProofProductSamplerAvailabilityAccounting {
    pub(crate) const fn challenge_role(&self) -> RelationChallengeRole {
        self.challenge_role
    }

    pub(crate) const fn modulus_reference(&self) -> SuiteModulusReference {
        self.modulus_reference
    }

    pub(crate) const fn coordinate_modulus(&self) -> u64 {
        self.coordinate_modulus
    }

    pub(crate) const fn coordinate_count(&self) -> u16 {
        self.coordinate_count
    }

    pub(crate) const fn product_space_cardinality(&self) -> &BigUint {
        &self.product_space_cardinality
    }

    pub(crate) const fn candidate_byte_length(&self) -> u64 {
        self.candidate_byte_length
    }

    pub(crate) const fn raw_candidate_space_power_of_two_exponent(&self) -> u32 {
        self.raw_candidate_space_power_of_two_exponent
    }

    pub(crate) const fn rejected_raw_candidate_count(&self) -> &BigUint {
        &self.rejected_raw_candidate_count
    }

    pub(crate) const fn maximum_candidate_draw_count(&self) -> u32 {
        self.maximum_candidate_draw_count
    }

    pub(crate) const fn exhaustion_probability(
        &self,
    ) -> &CommonProofSamplerExhaustionProbabilityBound {
        &self.exhaustion_probability
    }
}

/// Exact non-canonical-tail exhaustion fraction for an unrestricted extension
/// challenge. One accepted extension element has `uniform_preimage_count`
/// raw 512-bit preimages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofExtensionSamplerAvailabilityAccounting {
    extension_field_cardinality: BigUint,
    raw_candidate_space_power_of_two_exponent: u32,
    uniform_preimage_count: BigUint,
    noncanonical_raw_candidate_count: BigUint,
    maximum_candidate_draw_count: u32,
    exhaustion_probability: CommonProofSamplerExhaustionProbabilityBound,
}

impl CommonProofExtensionSamplerAvailabilityAccounting {
    pub(crate) const fn extension_field_cardinality(&self) -> &BigUint {
        &self.extension_field_cardinality
    }

    pub(crate) const fn raw_candidate_space_power_of_two_exponent(&self) -> u32 {
        self.raw_candidate_space_power_of_two_exponent
    }

    pub(crate) const fn uniform_preimage_count(&self) -> &BigUint {
        &self.uniform_preimage_count
    }

    pub(crate) const fn noncanonical_raw_candidate_count(&self) -> &BigUint {
        &self.noncanonical_raw_candidate_count
    }

    pub(crate) const fn maximum_candidate_draw_count(&self) -> u32 {
        self.maximum_candidate_draw_count
    }

    pub(crate) const fn exhaustion_probability(
        &self,
    ) -> &CommonProofSamplerExhaustionProbabilityBound {
        &self.exhaustion_probability
    }
}

/// Honest-exhaustion upper bound for a DEEP draw. The forbidden extension
/// element count is generated from the checked relation grammar, while the
/// raw rejection count also includes the non-canonical 512-bit tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofDeepSamplerAvailabilityAccounting {
    extension_field_cardinality: BigUint,
    raw_candidate_space_power_of_two_exponent: u32,
    uniform_preimage_count: BigUint,
    noncanonical_raw_candidate_count: BigUint,
    forbidden_extension_element_count_upper_bound: BigUint,
    rejected_raw_candidate_count_upper_bound: BigUint,
    maximum_candidate_draw_count: u32,
    exhaustion_probability_upper_bound: CommonProofSamplerExhaustionProbabilityBound,
}

impl CommonProofDeepSamplerAvailabilityAccounting {
    pub(crate) const fn extension_field_cardinality(&self) -> &BigUint {
        &self.extension_field_cardinality
    }

    pub(crate) const fn raw_candidate_space_power_of_two_exponent(&self) -> u32 {
        self.raw_candidate_space_power_of_two_exponent
    }

    pub(crate) const fn uniform_preimage_count(&self) -> &BigUint {
        &self.uniform_preimage_count
    }

    pub(crate) const fn noncanonical_raw_candidate_count(&self) -> &BigUint {
        &self.noncanonical_raw_candidate_count
    }

    pub(crate) const fn forbidden_extension_element_count_upper_bound(&self) -> &BigUint {
        &self.forbidden_extension_element_count_upper_bound
    }

    pub(crate) const fn rejected_raw_candidate_count_upper_bound(&self) -> &BigUint {
        &self.rejected_raw_candidate_count_upper_bound
    }

    pub(crate) const fn maximum_candidate_draw_count(&self) -> u32 {
        self.maximum_candidate_draw_count
    }

    pub(crate) const fn exhaustion_probability_upper_bound(
        &self,
    ) -> &CommonProofSamplerExhaustionProbabilityBound {
        &self.exhaustion_probability_upper_bound
    }
}

/// Exact exhaustion probability for the complete duplicate-free query vector,
/// plus its simpler per-output union upper bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofQueryVectorSamplerAvailabilityAccounting {
    query_orbit_count: u64,
    unique_query_count: u32,
    maximum_candidate_draw_count_per_output: u32,
    exact_exhaustion_probability: CommonProofSamplerExhaustionProbabilityBound,
    per_output_union_probability_upper_bound: CommonProofSamplerExhaustionProbabilityBound,
}

impl CommonProofQueryVectorSamplerAvailabilityAccounting {
    pub(crate) const fn query_orbit_count(&self) -> u64 {
        self.query_orbit_count
    }

    pub(crate) const fn unique_query_count(&self) -> u32 {
        self.unique_query_count
    }

    pub(crate) const fn maximum_candidate_draw_count_per_output(&self) -> u32 {
        self.maximum_candidate_draw_count_per_output
    }

    pub(crate) const fn exact_exhaustion_probability(
        &self,
    ) -> &CommonProofSamplerExhaustionProbabilityBound {
        &self.exact_exhaustion_probability
    }

    pub(crate) const fn per_output_union_probability_upper_bound(
        &self,
    ) -> &CommonProofSamplerExhaustionProbabilityBound {
        &self.per_output_union_probability_upper_bound
    }
}

/// Complete public-sampler honest-exhaustion ledger for one physical proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofSamplerAvailabilityAccounting {
    ordered_product_samplers: Vec<CommonProofProductSamplerAvailabilityAccounting>,
    generic_extension_sampler: CommonProofExtensionSamplerAvailabilityAccounting,
    generic_extension_draw_count: u64,
    deep_sampler: CommonProofDeepSamplerAvailabilityAccounting,
    deep_point_draw_count: u16,
    query_vector_sampler: CommonProofQueryVectorSamplerAvailabilityAccounting,
    combined_exhaustion_probability_upper_bound: CommonProofSamplerExhaustionProbabilityBound,
}

impl CommonProofSamplerAvailabilityAccounting {
    pub(crate) fn ordered_product_samplers(
        &self,
    ) -> &[CommonProofProductSamplerAvailabilityAccounting] {
        &self.ordered_product_samplers
    }

    pub(crate) const fn generic_extension_sampler(
        &self,
    ) -> &CommonProofExtensionSamplerAvailabilityAccounting {
        &self.generic_extension_sampler
    }

    pub(crate) const fn generic_extension_draw_count(&self) -> u64 {
        self.generic_extension_draw_count
    }

    pub(crate) const fn deep_sampler(&self) -> &CommonProofDeepSamplerAvailabilityAccounting {
        &self.deep_sampler
    }

    pub(crate) const fn deep_point_draw_count(&self) -> u16 {
        self.deep_point_draw_count
    }

    pub(crate) const fn query_vector_sampler(
        &self,
    ) -> &CommonProofQueryVectorSamplerAvailabilityAccounting {
        &self.query_vector_sampler
    }

    pub(crate) const fn combined_exhaustion_probability_upper_bound(
        &self,
    ) -> &CommonProofSamplerExhaustionProbabilityBound {
        &self.combined_exhaustion_probability_upper_bound
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofSamplerAvailabilityVariantAccounting {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    application_multiplicity: u32,
    per_proof: CommonProofSamplerAvailabilityAccounting,
}

impl SelectedProofSamplerAvailabilityVariantAccounting {
    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn application_multiplicity(&self) -> u32 {
        self.application_multiplicity
    }

    pub(crate) const fn per_proof(&self) -> &CommonProofSamplerAvailabilityAccounting {
        &self.per_proof
    }
}

/// Exact selected `n = 10` physical inventory and its no-independence union
/// upper bound for honest sampler exhaustion across one complete action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedActionSamplerAvailabilityAccounting {
    top_count: u16,
    physical_proof_object_count: u32,
    ordered_variant_accounting: Vec<SelectedProofSamplerAvailabilityVariantAccounting>,
    complete_action_exhaustion_probability_upper_bound:
        CommonProofSamplerExhaustionProbabilityBound,
}

impl SelectedActionSamplerAvailabilityAccounting {
    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) const fn physical_proof_object_count(&self) -> u32 {
        self.physical_proof_object_count
    }

    pub(crate) fn ordered_variant_accounting(
        &self,
    ) -> &[SelectedProofSamplerAvailabilityVariantAccounting] {
        &self.ordered_variant_accounting
    }

    pub(crate) const fn complete_action_exhaustion_probability_upper_bound(
        &self,
    ) -> &CommonProofSamplerExhaustionProbabilityBound {
        &self.complete_action_exhaustion_probability_upper_bound
    }
}

pub(crate) fn selected_complete_action_sampler_availability_accounting() -> Result<
    SelectedActionSamplerAvailabilityAccounting,
    CommonProofSamplerAvailabilityAccountingError,
> {
    let top_count = FOUNDATION_PROFILE.option_count;
    let application_slot_ceilings = selected_proof_application_slot_ceilings()
        .map_err(|_| CommonProofSamplerAvailabilityAccountingError::SelectedProfile)?;
    let relation_plans = selected_relation_plans()
        .map_err(|_| CommonProofSamplerAvailabilityAccountingError::SelectedProfile)?;
    if relation_plans.len() != application_slot_ceilings.ordered_family_ceilings().len() {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }
    let mut ordered_variant_accounting = Vec::new();
    let mut physical_proof_object_count = 0_u32;
    let mut complete_action_exhaustion_probability_upper_bound =
        CommonProofSamplerExhaustionProbabilityBound::zero();

    for relation_plan in relation_plans {
        let application_statement_schema_identifier =
            relation_plan.application_statement_schema_identifier();
        let family_application_ceiling = application_slot_ceilings
            .family_ceiling(application_statement_schema_identifier)
            .ok_or(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule)?;
        let variants = relation_plan.compiled_plan().variants();
        if variants.is_empty() {
            return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
        }
        let relation_context =
            selected_relation_plan_check_context(application_statement_schema_identifier)
                .ok_or(CommonProofSamplerAvailabilityAccountingError::SelectedProfile)?;
        let has_top_count_selector = variants.iter().any(|variant| variant.top_count().is_some());
        if has_top_count_selector {
            if variants.len() != usize::from(FOUNDATION_PROFILE.option_count)
                || variants
                    .iter()
                    .enumerate()
                    .any(|(variant_ordinal, variant)| {
                        variant.schedule_position().is_some()
                            || u16::try_from(variant_ordinal)
                                .ok()
                                .and_then(|ordinal| ordinal.checked_add(1))
                                != variant.top_count()
                    })
            {
                return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
            }
            let mut selected_variants = variants
                .iter()
                .filter(|variant| variant.top_count() == Some(top_count));
            let selected_variant = selected_variants
                .next()
                .ok_or(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule)?;
            if selected_variants.next().is_some() {
                return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
            }
            let selected_per_proof =
                sampler_availability_for_variant(selected_variant, &relation_context)?;
            for variant in variants {
                if sampler_availability_for_variant(variant, &relation_context)?
                    != selected_per_proof
                {
                    return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
                }
            }
            append_selected_sampler_variant_accounting(
                application_statement_schema_identifier,
                selected_variant,
                &relation_context,
                family_application_ceiling,
                &mut physical_proof_object_count,
                &mut ordered_variant_accounting,
                &mut complete_action_exhaustion_probability_upper_bound,
            )?;
        } else {
            if variants.iter().any(|variant| variant.top_count().is_some()) {
                return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
            }
            let variant_count = u32::try_from(variants.len())
                .map_err(|_| CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
            let application_multiplicity = family_application_ceiling
                .checked_div(variant_count)
                .filter(|multiplicity| {
                    *multiplicity != 0
                        && multiplicity
                            .checked_mul(variant_count)
                            .is_some_and(|count| count == family_application_ceiling)
                })
                .ok_or(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule)?;
            for variant in variants {
                append_selected_sampler_variant_accounting(
                    application_statement_schema_identifier,
                    variant,
                    &relation_context,
                    application_multiplicity,
                    &mut physical_proof_object_count,
                    &mut ordered_variant_accounting,
                    &mut complete_action_exhaustion_probability_upper_bound,
                )?;
            }
        }
    }
    if physical_proof_object_count != application_slot_ceilings.total_application_slot_ceiling() {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }

    Ok(SelectedActionSamplerAvailabilityAccounting {
        top_count,
        physical_proof_object_count,
        ordered_variant_accounting,
        complete_action_exhaustion_probability_upper_bound,
    })
}

fn append_selected_sampler_variant_accounting(
    application_statement_schema_identifier: u16,
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    application_multiplicity: u32,
    physical_proof_object_count: &mut u32,
    ordered_variant_accounting: &mut Vec<SelectedProofSamplerAvailabilityVariantAccounting>,
    complete_action_exhaustion_probability_upper_bound: &mut CommonProofSamplerExhaustionProbabilityBound,
) -> Result<(), CommonProofSamplerAvailabilityAccountingError> {
    if application_multiplicity == 0 {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }
    let per_proof = sampler_availability_for_variant(variant, relation_context)?;
    *complete_action_exhaustion_probability_upper_bound =
        complete_action_exhaustion_probability_upper_bound.checked_union(
            &per_proof
                .combined_exhaustion_probability_upper_bound()
                .checked_multiply_union(u64::from(application_multiplicity))?,
        )?;
    *physical_proof_object_count = physical_proof_object_count
        .checked_add(application_multiplicity)
        .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
    ordered_variant_accounting.push(SelectedProofSamplerAvailabilityVariantAccounting {
        application_statement_schema_identifier,
        schedule_position: variant.schedule_position(),
        top_count: variant.top_count(),
        application_multiplicity,
        per_proof,
    });
    Ok(())
}

fn sampler_availability_for_variant(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<CommonProofSamplerAvailabilityAccounting, CommonProofSamplerAvailabilityAccountingError>
{
    let transition_catalog = variant
        .application_round_by_round_transition_catalog(relation_context)
        .map_err(|_| CommonProofSamplerAvailabilityAccountingError::SelectedProfile)?;
    common_proof_sampler_availability_accounting(
        &transition_catalog,
        variant.evaluation_domain_size(),
    )
}

fn common_proof_sampler_availability_accounting(
    transition_catalog: &RelationApplicationRoundByRoundTransitionCatalog,
    evaluation_domain_size: u64,
) -> Result<CommonProofSamplerAvailabilityAccounting, CommonProofSamplerAvailabilityAccountingError>
{
    let maximum_candidate_draw_count = transition_catalog.maximum_candidate_draws_per_output();
    if maximum_candidate_draw_count == 0 || transition_catalog.query_vector_transition_count() != 1
    {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }

    let ordered_product_samplers = transition_catalog
        .ordered_non_native_challenge_bad_sets()
        .iter()
        .map(|group| {
            product_sampler_availability_accounting(
                group.challenge_role(),
                group.modulus_reference(),
                group.coordinate_modulus(),
                u16::try_from(group.ordered_coordinate_bounds().len())
                    .map_err(|_| CommonProofSamplerAvailabilityAccountingError::CountOverflow)?,
                maximum_candidate_draw_count,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let deep_allowed_set = transition_catalog.deep_allowed_set_root_bound();
    let (generic_extension_sampler, deep_sampler) = extension_sampler_availability_accounting(
        deep_allowed_set.extension_field_cardinality(),
        deep_allowed_set.forbidden_candidate_count_bound(),
        COMMON_PROOF_EXTENSION_CANDIDATE_BIT_LENGTH,
        maximum_candidate_draw_count,
    )?;
    let generic_extension_draw_count =
        u64::from(transition_catalog.composition_coefficient_count())
            .checked_add(u64::from(
                transition_catalog.opening_batch_mca_transition_count(),
            ))
            .and_then(|count| {
                count.checked_add(u64::from(transition_catalog.fri_fold_transition_count()))
            })
            .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
    let deep_point_draw_count = transition_catalog.deep_point_transition_count();
    let query_orbit_count = evaluation_domain_size
        .checked_div(2)
        .filter(|count| *count > 0)
        .ok_or(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule)?;
    let query_vector_sampler = query_vector_sampler_availability_accounting(
        query_orbit_count,
        transition_catalog.query_vector_position_count(),
        maximum_candidate_draw_count,
    )?;

    let mut combined_exhaustion_probability_upper_bound =
        CommonProofSamplerExhaustionProbabilityBound::zero();
    for product_sampler in &ordered_product_samplers {
        combined_exhaustion_probability_upper_bound =
            combined_exhaustion_probability_upper_bound
                .checked_union(product_sampler.exhaustion_probability())?;
    }
    combined_exhaustion_probability_upper_bound = combined_exhaustion_probability_upper_bound
        .checked_union(
            &generic_extension_sampler
                .exhaustion_probability()
                .checked_multiply_union(generic_extension_draw_count)?,
        )?;
    combined_exhaustion_probability_upper_bound = combined_exhaustion_probability_upper_bound
        .checked_union(
            &deep_sampler
                .exhaustion_probability_upper_bound()
                .checked_multiply_union(u64::from(deep_point_draw_count))?,
        )?;
    combined_exhaustion_probability_upper_bound = combined_exhaustion_probability_upper_bound
        .checked_union(query_vector_sampler.exact_exhaustion_probability())?;

    Ok(CommonProofSamplerAvailabilityAccounting {
        ordered_product_samplers,
        generic_extension_sampler,
        generic_extension_draw_count,
        deep_sampler,
        deep_point_draw_count,
        query_vector_sampler,
        combined_exhaustion_probability_upper_bound,
    })
}

fn product_sampler_availability_accounting(
    challenge_role: RelationChallengeRole,
    modulus_reference: SuiteModulusReference,
    coordinate_modulus: u64,
    coordinate_count: u16,
    maximum_candidate_draw_count: u32,
) -> Result<
    CommonProofProductSamplerAvailabilityAccounting,
    CommonProofSamplerAvailabilityAccountingError,
> {
    if coordinate_modulus <= 1 || coordinate_count == 0 || maximum_candidate_draw_count == 0 {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }
    let product_space_cardinality =
        BigUint::from(coordinate_modulus).pow(u32::from(coordinate_count));
    let maximum_candidate = &product_space_cardinality - BigUint::one();
    let candidate_bit_length = maximum_candidate.bits().max(1);
    let candidate_byte_length = candidate_bit_length
        .checked_add(7)
        .and_then(|count| count.checked_div(8))
        .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
    let raw_candidate_space_power_of_two_exponent = u32::try_from(
        candidate_byte_length
            .checked_mul(8)
            .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?,
    )
    .map_err(|_| CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
    let raw_candidate_space = power_of_two(raw_candidate_space_power_of_two_exponent)?;
    let rejected_raw_candidate_count = &raw_candidate_space % &product_space_cardinality;
    let exhaustion_probability = CommonProofSamplerExhaustionProbabilityBound::new(
        rejected_raw_candidate_count.pow(maximum_candidate_draw_count),
        raw_candidate_space_power_of_two_exponent
            .checked_mul(maximum_candidate_draw_count)
            .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?,
    )?;

    Ok(CommonProofProductSamplerAvailabilityAccounting {
        challenge_role,
        modulus_reference,
        coordinate_modulus,
        coordinate_count,
        product_space_cardinality,
        candidate_byte_length,
        raw_candidate_space_power_of_two_exponent,
        rejected_raw_candidate_count,
        maximum_candidate_draw_count,
        exhaustion_probability,
    })
}

fn extension_sampler_availability_accounting(
    extension_field_cardinality: &BigUint,
    forbidden_extension_element_count_upper_bound: &BigUint,
    raw_candidate_space_power_of_two_exponent: u32,
    maximum_candidate_draw_count: u32,
) -> Result<
    (
        CommonProofExtensionSamplerAvailabilityAccounting,
        CommonProofDeepSamplerAvailabilityAccounting,
    ),
    CommonProofSamplerAvailabilityAccountingError,
> {
    if extension_field_cardinality <= &BigUint::one()
        || forbidden_extension_element_count_upper_bound >= extension_field_cardinality
        || maximum_candidate_draw_count == 0
    {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }
    let raw_candidate_space = power_of_two(raw_candidate_space_power_of_two_exponent)?;
    if extension_field_cardinality > &raw_candidate_space {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }
    let uniform_preimage_count = &raw_candidate_space / extension_field_cardinality;
    let noncanonical_raw_candidate_count = &raw_candidate_space % extension_field_cardinality;
    let exhaustion_denominator_exponent = raw_candidate_space_power_of_two_exponent
        .checked_mul(maximum_candidate_draw_count)
        .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
    let exhaustion_probability = CommonProofSamplerExhaustionProbabilityBound::new(
        noncanonical_raw_candidate_count.pow(maximum_candidate_draw_count),
        exhaustion_denominator_exponent,
    )?;
    let rejected_raw_candidate_count_upper_bound = &noncanonical_raw_candidate_count
        + &uniform_preimage_count * forbidden_extension_element_count_upper_bound;
    if rejected_raw_candidate_count_upper_bound > raw_candidate_space {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }
    let exhaustion_probability_upper_bound = CommonProofSamplerExhaustionProbabilityBound::new(
        rejected_raw_candidate_count_upper_bound.pow(maximum_candidate_draw_count),
        exhaustion_denominator_exponent,
    )?;

    Ok((
        CommonProofExtensionSamplerAvailabilityAccounting {
            extension_field_cardinality: extension_field_cardinality.clone(),
            raw_candidate_space_power_of_two_exponent,
            uniform_preimage_count: uniform_preimage_count.clone(),
            noncanonical_raw_candidate_count: noncanonical_raw_candidate_count.clone(),
            maximum_candidate_draw_count,
            exhaustion_probability,
        },
        CommonProofDeepSamplerAvailabilityAccounting {
            extension_field_cardinality: extension_field_cardinality.clone(),
            raw_candidate_space_power_of_two_exponent,
            uniform_preimage_count,
            noncanonical_raw_candidate_count,
            forbidden_extension_element_count_upper_bound:
                forbidden_extension_element_count_upper_bound.clone(),
            rejected_raw_candidate_count_upper_bound,
            maximum_candidate_draw_count,
            exhaustion_probability_upper_bound,
        },
    ))
}

fn query_vector_sampler_availability_accounting(
    query_orbit_count: u64,
    unique_query_count: u32,
    maximum_candidate_draw_count_per_output: u32,
) -> Result<
    CommonProofQueryVectorSamplerAvailabilityAccounting,
    CommonProofSamplerAvailabilityAccountingError,
> {
    if !query_orbit_count.is_power_of_two()
        || unique_query_count == 0
        || u64::from(unique_query_count) > query_orbit_count
        || maximum_candidate_draw_count_per_output == 0
    {
        return Err(CommonProofSamplerAvailabilityAccountingError::InvalidSchedule);
    }
    let query_orbit_power_of_two_exponent = query_orbit_count.trailing_zeros();
    let per_output_denominator_exponent = query_orbit_power_of_two_exponent
        .checked_mul(maximum_candidate_draw_count_per_output)
        .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
    let per_output_denominator = power_of_two(per_output_denominator_exponent)?;
    let exact_denominator_exponent = per_output_denominator_exponent
        .checked_mul(unique_query_count)
        .ok_or(CommonProofSamplerAvailabilityAccountingError::CountOverflow)?;
    let exact_denominator = power_of_two(exact_denominator_exponent)?;
    let mut exact_success_numerator = BigUint::one();
    let mut per_output_union_numerator = BigUint::zero();
    for prior_accepted_count in 0..unique_query_count {
        let duplicate_draw_sequence_count =
            BigUint::from(prior_accepted_count).pow(maximum_candidate_draw_count_per_output);
        exact_success_numerator *= &per_output_denominator - &duplicate_draw_sequence_count;
        per_output_union_numerator += duplicate_draw_sequence_count;
    }
    let exact_exhaustion_probability = CommonProofSamplerExhaustionProbabilityBound::new(
        exact_denominator - exact_success_numerator,
        exact_denominator_exponent,
    )?;
    if per_output_union_numerator > per_output_denominator {
        per_output_union_numerator = per_output_denominator;
    }
    let per_output_union_probability_upper_bound =
        CommonProofSamplerExhaustionProbabilityBound::new(
            per_output_union_numerator,
            per_output_denominator_exponent,
        )?;

    Ok(CommonProofQueryVectorSamplerAvailabilityAccounting {
        query_orbit_count,
        unique_query_count,
        maximum_candidate_draw_count_per_output,
        exact_exhaustion_probability,
        per_output_union_probability_upper_bound,
    })
}

fn power_of_two(exponent: u32) -> Result<BigUint, CommonProofSamplerAvailabilityAccountingError> {
    Ok(BigUint::one()
        << usize::try_from(exponent)
            .map_err(|_| CommonProofSamplerAvailabilityAccountingError::CountOverflow)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_sampler_exhaustion_uses_the_complete_product_space() {
        let accounting = product_sampler_availability_accounting(
            RelationChallengeRole::NonNativeTheta,
            SuiteModulusReference::plaintext(),
            3,
            2,
            2,
        )
        .expect("the small product sampler is valid");

        assert_eq!(accounting.product_space_cardinality(), &BigUint::from(9_u8));
        assert_eq!(accounting.candidate_byte_length(), 1);
        assert_eq!(
            accounting.rejected_raw_candidate_count(),
            &BigUint::from(4_u8)
        );
        assert_eq!(
            accounting.exhaustion_probability().numerator(),
            &BigUint::from(16_u8)
        );
        assert_eq!(
            accounting
                .exhaustion_probability()
                .denominator_power_of_two_exponent(),
            16,
        );
    }

    #[test]
    fn extension_sampler_separates_raw_tail_from_forbidden_points() {
        let (generic, deep) = extension_sampler_availability_accounting(
            &BigUint::from(3_u8),
            &BigUint::from(1_u8),
            8,
            2,
        )
        .expect("the small extension sampler is valid");

        assert_eq!(generic.uniform_preimage_count(), &BigUint::from(85_u8));
        assert_eq!(generic.noncanonical_raw_candidate_count(), &BigUint::one());
        assert_eq!(
            generic.exhaustion_probability().numerator(),
            &BigUint::one()
        );
        assert_eq!(
            deep.rejected_raw_candidate_count_upper_bound(),
            &BigUint::from(86_u8),
        );
        assert_eq!(
            deep.exhaustion_probability_upper_bound().numerator(),
            &BigUint::from(7_396_u16),
        );
        assert_eq!(
            deep.exhaustion_probability_upper_bound()
                .denominator_power_of_two_exponent(),
            16,
        );
    }

    #[test]
    fn duplicate_free_query_vector_reports_exact_sequential_exhaustion() {
        let accounting = query_vector_sampler_availability_accounting(8, 3, 2)
            .expect("the small query-vector sampler is valid");

        assert_eq!(
            accounting.exact_exhaustion_probability().numerator(),
            &BigUint::from(20_224_u32),
        );
        assert_eq!(
            accounting
                .exact_exhaustion_probability()
                .denominator_power_of_two_exponent(),
            18,
        );
        assert_eq!(
            accounting
                .per_output_union_probability_upper_bound()
                .numerator(),
            &BigUint::from(5_u8),
        );
        assert_eq!(
            accounting
                .per_output_union_probability_upper_bound()
                .denominator_power_of_two_exponent(),
            6,
        );
        assert!(
            accounting.exact_exhaustion_probability().numerator()
                * accounting
                    .per_output_union_probability_upper_bound()
                    .denominator()
                    .expect("the denominator fits")
                <= accounting
                    .per_output_union_probability_upper_bound()
                    .numerator()
                    * accounting
                        .exact_exhaustion_probability()
                        .denominator()
                        .expect("the denominator fits")
        );
    }

    #[test]
    fn generic_deep_bound_counts_direct_equality_with_each_prior_center() {
        let relation_plan = super::super::selected_profile::selected_relation_plans()
            .expect("selected relation plans")
            .into_iter()
            .next()
            .expect("the selected catalog is nonempty");
        let application_statement_schema_identifier =
            relation_plan.application_statement_schema_identifier();
        let variant = relation_plan
            .compiled_plan()
            .variants()
            .first()
            .expect("a selected relation has one variant");
        let one_center_context =
            super::super::selected_profile::selected_relation_plan_check_context(
                application_statement_schema_identifier,
            )
            .expect("selected relation context");
        let one_center_bound = variant
            .application_deep_forbidden_candidate_count_bound(&one_center_context)
            .expect("one-center DEEP bound");
        let opening_point_count = variant
            .ordered_opening_points()
            .iter()
            .filter(|point| point.deep_point_ordinal() == 0)
            .count();
        assert!(opening_point_count > 0);

        let mut two_center_context = one_center_context.clone();
        two_center_context.deep_point_count = 2;
        let two_center_bound = variant
            .application_deep_forbidden_candidate_count_bound(&two_center_context)
            .expect("two-center DEEP bound");
        let prior_translated_orbit_collision_increment =
            BigUint::from(
                opening_point_count
                    .checked_mul(opening_point_count)
                    .expect("opening-point square fits"),
            ) * BigUint::from(one_center_context.challenge_extension_degree);

        assert_eq!(
            two_center_bound - one_center_bound,
            BigUint::one() + prior_translated_orbit_collision_increment,
        );
    }

    #[test]
    fn selected_complete_action_sampler_exhaustion_is_below_hardening_target() {
        let accounting = selected_complete_action_sampler_availability_accounting()
            .expect("selected sampler availability accounting");
        let observed_physical_proof_count = accounting
            .ordered_variant_accounting()
            .iter()
            .map(|row| row.application_multiplicity())
            .sum::<u32>();
        let product_sampler_count = accounting
            .ordered_variant_accounting()
            .iter()
            .flat_map(|row| row.per_proof().ordered_product_samplers())
            .count();

        assert_eq!(accounting.top_count(), FOUNDATION_PROFILE.option_count);
        assert_eq!(
            observed_physical_proof_count,
            accounting.physical_proof_object_count()
        );
        assert!(product_sampler_count > 0);
        assert!(accounting.ordered_variant_accounting().iter().all(|row| {
            row.per_proof()
                .ordered_product_samplers()
                .iter()
                .all(|sampler| sampler.coordinate_count() == 9)
                && row.per_proof().deep_point_draw_count() == 1
                && row.per_proof().generic_extension_draw_count() > 0
        }));
        assert!(
            !accounting
                .complete_action_exhaustion_probability_upper_bound()
                .numerator()
                .is_zero()
        );
        assert!(
            accounting
                .complete_action_exhaustion_probability_upper_bound()
                .is_at_most_inverse_power_of_two(128)
        );
    }
}
