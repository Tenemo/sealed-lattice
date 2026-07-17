use std::collections::BTreeSet;

use crate::foundation::ProofApplicationSlotCeilings;

use super::{
    compiled_plan::{CompiledRelationPlan, RelationPlanCheckContext},
    expressions::{strictly_sorted_unique_by_key, validate_challenge_catalog},
    layout::RelationPlanVariant,
    model::{ModulusCatalog, ProofPrivacyMode, RelationPlanError},
};

#[derive(Default)]
struct ApplicationExtractorPhaseColumns {
    derived_base_columns: BTreeSet<u32>,
    derived_auxiliary_columns: BTreeSet<u32>,
}

pub(super) struct RelationPlanChecker<'context> {
    context: &'context RelationPlanCheckContext,
}

impl<'context> RelationPlanChecker<'context> {
    pub(super) fn new(context: &'context RelationPlanCheckContext) -> Self {
        Self { context }
    }

    pub(super) fn check(&self, compiled: &CompiledRelationPlan) -> Result<(), RelationPlanError> {
        self.check_context()?;
        let plan = &compiled.plan;
        let expected_privacy_mode =
            ProofPrivacyMode::for_family(plan.application_statement_schema_identifier)
                .ok_or(RelationPlanError::UnsupportedApplicationFamily)?;
        if plan.variants.is_empty() {
            return Err(RelationPlanError::InvalidVariantSelector);
        }
        let mut selectors = BTreeSet::new();
        for variant in &plan.variants {
            self.check_variant_selector(plan.application_statement_schema_identifier, variant)?;
            if !selectors.insert((variant.schedule_position, variant.top_count)) {
                return Err(RelationPlanError::DuplicateVariant);
            }
            if variant.proof_privacy_mode != expected_privacy_mode {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            self.check_variant(plan.application_statement_schema_identifier, variant)?;
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn check_context(
        &self,
    ) -> Result<(), RelationPlanError> {
        if self.context.base_field_modulus < 3
            || self.context.base_field_modulus.is_multiple_of(2)
            || self.context.challenge_extension_degree == 0
            || self.context.evaluation_blowup_factor == 0
            || !self.context.evaluation_blowup_factor.is_power_of_two()
            || self.context.evaluation_domain_generator == 0
            || self.context.evaluation_domain_generator >= self.context.base_field_modulus
            || self.context.evaluation_coset_offset == 0
            || self.context.evaluation_coset_offset >= self.context.base_field_modulus
            || self.context.deep_point_count == 0
            || self.context.quotient_component_count < 2
            || self.context.quotient_component_degree_bound_exclusive == 0
            || self.context.fri_fold_count == 0
            || self.context.final_polynomial_degree_bound_exclusive == 0
            || self.context.unique_query_count == 0
            || self.context.non_native_modular_identity_challenge_count == 0
            || self.context.maximum_fiat_shamir_candidate_draws_per_output == 0
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        if !strictly_sorted_unique_by_key(&self.context.resolved_moduli, |entry| entry.reference) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for resolved in &self.context.resolved_moduli {
            if resolved.reference.catalog == ModulusCatalog::ProofField
                || resolved.modulus < 3
                || resolved.modulus >= self.context.base_field_modulus
            {
                return Err(RelationPlanError::InvalidModulus);
            }
        }
        Ok(())
    }

    fn check_variant_selector(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        let valid = match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
                ..=ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                variant.schedule_position.is_some() && variant.top_count.is_none()
            }
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                variant.schedule_position.is_some() && matches!(variant.top_count, Some(1..=20))
            }
            _ => variant.schedule_position.is_none() && variant.top_count.is_none(),
        };
        if !valid {
            return Err(RelationPlanError::InvalidVariantSelector);
        }
        Ok(())
    }

    fn check_variant(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        self.check_domains(variant)?;
        self.check_moduli(variant)?;
        self.check_sources_and_samplers(variant)?;
        let semantic_bounds = self.check_columns_and_semantic_cells(variant)?;
        self.check_radix_convolutions(variant, &semantic_bounds)?;
        self.check_trees(variant)?;
        self.check_constraints(variant, &semantic_bounds)?;
        self.check_coefficient_local_identity_batches(
            application_statement_schema_identifier,
            variant,
            &semantic_bounds,
        )?;
        let extractor_phase_columns = self.check_integer_lift_batches(
            application_statement_schema_identifier,
            variant,
            &semantic_bounds,
        )?;
        self.check_application_extractor_phase_ownership(variant, &extractor_phase_columns)?;
        self.check_openings(variant)?;
        self.check_masks(variant)?;
        crate::bgv::proof_suite::validate_zero_knowledge_mask_image(variant, self.context)?;
        let challenge_catalog = variant.derived_challenge_catalog(self.context)?;
        validate_challenge_catalog(&challenge_catalog, variant, self.context)?;
        let epoch_catalogs = variant.derived_challenge_epoch_catalogs(self.context)?;
        if epoch_catalogs.is_empty() {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        for epoch_catalog in epoch_catalogs {
            let _ = epoch_catalog.canonical_catalog_bytes()?;
        }
        let _ = variant.common_proof_transcript_schedule(self.context)?;
        Ok(())
    }
}

mod constraints;
mod integer_lift;
mod integer_lift_bounds;
mod model;
mod openings;

pub(super) use constraints::{
    full_trace_zeroifier_expression, zeroifier_roots_are_confined_to_trace_domain,
};
pub(super) use integer_lift_bounds::{
    derive_semantic_cell_interval, integer_lift_maximum_absolute_product,
};
