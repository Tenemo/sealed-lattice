use crate::foundation::{CanonicalItem, CanonicalTuple};

use super::{
    checking::RelationPlanChecker,
    expressions::{
        canonical_nested_list, encode_generated_tuple, hash_generated_variable_bytes,
        resident_vec_storage_byte_length,
    },
    layout::RelationPlanVariant,
    model::{RelationPlanError, SuiteModulusReference},
    schema::{RELATION_PLAN_HASH_DOMAIN, RELATION_PLAN_SCHEMA_IDENTIFIER, SCHEMA_VERSION},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RelationPlan {
    pub(super) application_statement_schema_identifier: u16,
    pub(super) variants: Vec<RelationPlanVariant>,
}

impl RelationPlan {
    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RELATION_PLAN_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                canonical_nested_list(
                    self.variants
                        .iter()
                        .map(RelationPlanVariant::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        encode_generated_tuple(&self.canonical_tuple()?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompiledRelationPlan {
    pub(super) plan: RelationPlan,
}

impl CompiledRelationPlan {
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        self.plan.variants.iter().try_fold(
            resident_vec_storage_byte_length(&self.plan.variants)?,
            |total, variant| {
                total
                    .checked_add(variant.resident_owned_payload_byte_length()?)
                    .ok_or(RelationPlanError::CountOverflow)
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        self.plan.canonical_tuple()
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.plan.canonical_bytes()
    }

    #[cfg(test)]
    pub(crate) fn encode_canonical_tuple(
        &self,
        canonical_tuple: &CanonicalTuple,
    ) -> Result<Vec<u8>, RelationPlanError> {
        encode_generated_tuple(canonical_tuple)
    }

    pub(crate) fn canonical_hash(&self) -> Result<[u8; 64], RelationPlanError> {
        self.canonical_byte_length_and_hash().map(|(_, hash)| hash)
    }

    pub(crate) fn canonical_byte_length_and_hash(
        &self,
    ) -> Result<(u64, [u8; 64]), RelationPlanError> {
        let canonical_bytes = self.canonical_bytes()?;
        let byte_length = u64::try_from(canonical_bytes.len())
            .map_err(|_| RelationPlanError::CanonicalEncoding)?;
        let hash = hash_generated_variable_bytes(RELATION_PLAN_HASH_DOMAIN, &canonical_bytes)?;
        Ok((byte_length, hash))
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.plan.application_statement_schema_identifier
    }

    pub(crate) fn variants(&self) -> &[RelationPlanVariant] {
        &self.plan.variants
    }

    pub(crate) fn select_variant(
        &self,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Result<&RelationPlanVariant, RelationPlanError> {
        let mut matches = self.plan.variants.iter().filter(|variant| {
            variant.schedule_position == schedule_position && variant.top_count == top_count
        });
        let selected = matches
            .next()
            .ok_or(RelationPlanError::InvalidVariantSelector)?;
        if matches.next().is_some() {
            return Err(RelationPlanError::DuplicateVariant);
        }
        Ok(selected)
    }

    pub(crate) fn check(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        RelationPlanChecker::new(context).check(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedSuiteModulus {
    pub(super) reference: SuiteModulusReference,
    pub(super) modulus: u64,
}

impl ResolvedSuiteModulus {
    pub(crate) const fn new(reference: SuiteModulusReference, modulus: u64) -> Self {
        Self { reference, modulus }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanCheckContext {
    pub(crate) base_field_modulus: u64,
    pub(crate) challenge_extension_degree: u16,
    pub(crate) evaluation_blowup_factor: u32,
    pub(crate) evaluation_domain_generator: u64,
    pub(crate) evaluation_coset_offset: u64,
    pub(crate) deep_point_count: u16,
    pub(crate) quotient_component_count: u32,
    pub(crate) quotient_component_degree_bound_exclusive: u64,
    pub(crate) fri_fold_count: u16,
    pub(crate) final_polynomial_degree_bound_exclusive: u32,
    pub(crate) unique_query_count: u32,
    pub(crate) non_native_theta_repetition_count: u16,
    pub(crate) non_native_alpha_repetition_count: u16,
    pub(crate) maximum_fiat_shamir_candidate_draws_per_output: u32,
    pub(crate) resolved_moduli: Vec<ResolvedSuiteModulus>,
}

impl RelationPlanCheckContext {
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        resident_vec_storage_byte_length(&self.resolved_moduli)
    }

    pub(crate) fn resolved_modulus(
        &self,
        reference: SuiteModulusReference,
    ) -> Result<u64, RelationPlanError> {
        self.resolved_moduli
            .binary_search_by_key(&reference, |entry| entry.reference)
            .ok()
            .map(|index| self.resolved_moduli[index].modulus)
            .ok_or(RelationPlanError::MissingModulus)
    }
}
