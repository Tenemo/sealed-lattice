//! Canonical proof-profile artifact generation.
//!
//! The artifact is constructed only from checked field schedules and checked
//! relation plans.  It deliberately has no permissive "unknown profile"
//! representation: a missing family, an unvalidated plan, or an unresolved
//! root edge prevents artifact generation.

use std::collections::BTreeSet;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
};

use super::{
    CompiledRelationPlan, PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    PROOF_CHALLENGE_EXTENSION_POLYNOMIAL_COEFFICIENTS, RelationPlanCheckContext,
    RelationPlanError, validate_proof_field_profile,
};

const PROOF_PROFILE_SET_SCHEMA_IDENTIFIER: u16 = 0x2200;
const PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2201;
const PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2202;
const PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER: u16 = 0x2203;
const RELATION_PLAN_SCHEMA_IDENTIFIER: u16 = 0x2204;
const RELATION_ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER: u16 = 0x222a;
const RELATION_ROOT_ENDPOINT_SCHEMA_IDENTIFIER: u16 = 0x222b;
const SCHEMA_VERSION: u16 = 1;

pub(crate) const FIRST_PROFILE_APPLICATION_FAMILIES: [u16; 12] = [
    0x1211, 0x1212, 0x1213, 0x1214, 0x1215, 0x1216, 0x1217, 0x1218, 0x1302, 0x1621,
    0x2110, 0x2111,
];

pub(crate) const PROOF_EVALUATION_BLOWUP_FACTOR: u32 = 8;
pub(crate) const PROOF_EVALUATION_COSET_OFFSET: u64 = 7;
pub(crate) const PROOF_DEEP_POINT_COUNT: u16 = 2;
pub(crate) const PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE: u32 = 256;
pub(crate) const PROOF_UNIQUE_QUERY_COUNT: u32 = 168;
pub(crate) const PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT: u16 = 7;
pub(crate) const PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofProfileError {
    CanonicalEncoding,
    InvalidField,
    InvalidSchedule,
    UnsupportedFamily,
    MissingFamily,
    DuplicateFamily,
    NonCanonicalOrder,
    InvalidRelationPlan,
    RelationPlan(RelationPlanError),
    InvalidRootEndpoint,
    DuplicateRootEdge,
    CountOverflow,
}

impl From<RelationPlanError> for ProofProfileError {
    fn from(error: RelationPlanError) -> Self {
        Self::RelationPlan(error)
    }
}

fn canonical_encoding_error<T>(_: T) -> ProofProfileError {
    ProofProfileError::CanonicalEncoding
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofFieldProfile {
    base_field_modulus: u64,
    maximum_two_adic_subgroup_generator: u64,
    monic_challenge_extension_polynomial_coefficients: Vec<u64>,
}

impl ProofFieldProfile {
    pub(crate) fn selected() -> Result<Self, ProofProfileError> {
        validate_proof_field_profile().map_err(|_| ProofProfileError::InvalidField)?;
        Ok(Self {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            maximum_two_adic_subgroup_generator:
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
            monic_challenge_extension_polynomial_coefficients:
                PROOF_CHALLENGE_EXTENSION_POLYNOMIAL_COEFFICIENTS.to_vec(),
        })
    }

    fn validate(&self) -> Result<(), ProofProfileError> {
        let selected = Self::selected()?;
        if self != &selected {
            return Err(ProofProfileError::InvalidField);
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, ProofProfileError> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.base_field_modulus),
                CanonicalItem::unsigned64(self.maximum_two_adic_subgroup_generator),
                canonical_u64_list(
                    &self.monic_challenge_extension_polynomial_coefficients,
                )?,
            ],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofFieldSchedule {
    proof_field_index: u16,
    evaluation_blowup_factor: u32,
    evaluation_coset_offset: u64,
    deep_point_count: u16,
    final_polynomial_degree_bound_exclusive: u32,
    unique_query_count: u32,
    non_native_modular_identity_challenge_count: u16,
    maximum_fiat_shamir_candidate_draws_per_output: u32,
}

impl ProofFieldSchedule {
    fn selected() -> Self {
        Self {
            proof_field_index: 0,
            evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
            evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
            deep_point_count: PROOF_DEEP_POINT_COUNT,
            final_polynomial_degree_bound_exclusive:
                PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
            unique_query_count: PROOF_UNIQUE_QUERY_COUNT,
            non_native_modular_identity_challenge_count:
                PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT,
            maximum_fiat_shamir_candidate_draws_per_output:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        }
    }

    fn validate(&self, proof_field_count: usize) -> Result<(), ProofProfileError> {
        if *self != Self::selected()
            || usize::from(self.proof_field_index) >= proof_field_count
            || self.evaluation_blowup_factor == 0
            || !self.evaluation_blowup_factor.is_power_of_two()
            || self.evaluation_coset_offset == 0
            || self.evaluation_coset_offset >= PROOF_BASE_FIELD_MODULUS
            || self.deep_point_count == 0
            || self.final_polynomial_degree_bound_exclusive <= 1
            || self.unique_query_count == 0
            || self.non_native_modular_identity_challenge_count == 0
            || self.maximum_fiat_shamir_candidate_draws_per_output == 0
        {
            return Err(ProofProfileError::InvalidSchedule);
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.proof_field_index),
                CanonicalItem::unsigned32(self.evaluation_blowup_factor),
                CanonicalItem::unsigned64(self.evaluation_coset_offset),
                CanonicalItem::unsigned16(self.deep_point_count),
                CanonicalItem::unsigned32(self.final_polynomial_degree_bound_exclusive),
                CanonicalItem::unsigned32(self.unique_query_count),
                CanonicalItem::unsigned16(
                    self.non_native_modular_identity_challenge_count,
                ),
                CanonicalItem::unsigned32(
                    self.maximum_fiat_shamir_candidate_draws_per_output,
                ),
            ],
        )
    }

    fn matches_relation_context(&self, context: &RelationPlanCheckContext) -> bool {
        context.base_field_modulus == PROOF_BASE_FIELD_MODULUS
            && context.challenge_extension_degree
                == u16::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                    .expect("the fixed extension degree fits u16")
            && context.evaluation_blowup_factor == self.evaluation_blowup_factor
            && context.evaluation_coset_offset == self.evaluation_coset_offset
            && context.deep_point_count == self.deep_point_count
            && context.final_polynomial_degree_bound_exclusive
                == self.final_polynomial_degree_bound_exclusive
            && context.unique_query_count == self.unique_query_count
            && context.non_native_modular_identity_challenge_count
                == self.non_native_modular_identity_challenge_count
            && context.maximum_fiat_shamir_candidate_draws_per_output
                == self.maximum_fiat_shamir_candidate_draws_per_output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofFamilyProfile {
    application_statement_schema_identifier: u16,
    field_schedule: ProofFieldSchedule,
}

impl ProofFamilyProfile {
    pub(crate) fn selected(
        application_statement_schema_identifier: u16,
    ) -> Result<Self, ProofProfileError> {
        if !FIRST_PROFILE_APPLICATION_FAMILIES
            .contains(&application_statement_schema_identifier)
        {
            return Err(ProofProfileError::UnsupportedFamily);
        }
        Ok(Self {
            application_statement_schema_identifier,
            field_schedule: ProofFieldSchedule::selected(),
        })
    }

    fn validate(&self, proof_field_count: usize) -> Result<(), ProofProfileError> {
        if !FIRST_PROFILE_APPLICATION_FAMILIES
            .contains(&self.application_statement_schema_identifier)
        {
            return Err(ProofProfileError::UnsupportedFamily);
        }
        self.field_schedule.validate(proof_field_count)
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, ProofProfileError> {
        self.validate(1)?;
        Ok(CanonicalTuple::new(
            PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::nested_tuple(&self.field_schedule.canonical_tuple())
                    .map_err(canonical_encoding_error)?,
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedRelationPlanArtifact {
    application_statement_schema_identifier: u16,
    canonical_plan_tuple: CanonicalTuple,
    compiled_plan: CompiledRelationPlan,
}

impl ValidatedRelationPlanArtifact {
    pub(crate) fn from_compiled_plan(
        plan: &CompiledRelationPlan,
        context: &RelationPlanCheckContext,
    ) -> Result<Self, ProofProfileError> {
        plan.check(context)?;
        let canonical_plan_tuple = plan.canonical_tuple()?;
        let canonical_bytes = plan.canonical_bytes()?;
        if canonical_plan_tuple.schema_identifier != RELATION_PLAN_SCHEMA_IDENTIFIER
            || canonical_plan_tuple.schema_version != SCHEMA_VERSION
            || canonical_plan_tuple.items.len() != 2
        {
            return Err(ProofProfileError::InvalidRelationPlan);
        }
        let application_statement_schema_identifier =
            read_canonical_u16(&canonical_plan_tuple.items[0])?;
        let family_profile = ProofFamilyProfile::selected(
            application_statement_schema_identifier,
        )?;
        if !family_profile.field_schedule.matches_relation_context(context) {
            return Err(ProofProfileError::InvalidSchedule);
        }
        if plan.encode_canonical_tuple(&canonical_plan_tuple)? != canonical_bytes {
            return Err(ProofProfileError::CanonicalEncoding);
        }
        Ok(Self {
            application_statement_schema_identifier,
            canonical_plan_tuple,
            compiled_plan: plan.clone(),
        })
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    fn canonical_tuple(&self) -> &CanonicalTuple {
        &self.canonical_plan_tuple
    }

    fn compiled_plan(&self) -> &CompiledRelationPlan {
        &self.compiled_plan
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RelationRootConstructionKind {
    CommittedMaterial = 1,
    SetupPolynomial = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationRootEndpoint {
    application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    producer_sequence: Option<u64>,
    verifier_source_ordinal: u32,
}

impl RelationRootEndpoint {
    pub(crate) fn new(
        application_statement_schema_identifier: u16,
        roster_position: Option<u16>,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        producer_sequence: Option<u64>,
        verifier_source_ordinal: u32,
    ) -> Result<Self, ProofProfileError> {
        let endpoint = Self {
            application_statement_schema_identifier,
            roster_position,
            schedule_position,
            top_count,
            producer_sequence,
            verifier_source_ordinal,
        };
        endpoint.validate_presence_pattern()?;
        Ok(endpoint)
    }

    fn validate_presence_pattern(&self) -> Result<(), ProofProfileError> {
        let family = self.application_statement_schema_identifier;
        if !FIRST_PROFILE_APPLICATION_FAMILIES.contains(&family) {
            return Err(ProofProfileError::UnsupportedFamily);
        }

        let roster_expected = matches!(
            family,
            0x2110 | 0x2111 | 0x1211 | 0x1212 | 0x1214 | 0x1216 | 0x1217 | 0x1302 | 0x1621
        );
        let schedule_expected = matches!(family, 0x1214 | 0x1215 | 0x1216 | 0x1217);
        let top_count_expected = family == 0x1218;
        let producer_sequence_expected = family == 0x1302;
        if self.roster_position.is_some() != roster_expected
            || self.schedule_position.is_some() != schedule_expected
            || self.top_count.is_some() != top_count_expected
            || self.producer_sequence.is_some() != producer_sequence_expected
            || self.top_count.is_some_and(|top_count| !(1..=20).contains(&top_count))
        {
            return Err(ProofProfileError::InvalidRootEndpoint);
        }
        Ok(())
    }

    fn canonical_tuple(self) -> Result<CanonicalTuple, ProofProfileError> {
        self.validate_presence_pattern()?;
        let roster_position = self.roster_position.map(CanonicalItem::unsigned16);
        let schedule_position = self.schedule_position.map(CanonicalItem::unsigned32);
        let top_count = self.top_count.map(CanonicalItem::unsigned16);
        let producer_sequence = self.producer_sequence.map(CanonicalItem::unsigned64);
        Ok(CanonicalTuple::new(
            RELATION_ROOT_ENDPOINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned16,
                    roster_position.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned32,
                    schedule_position.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(CanonicalItemType::Unsigned16, top_count.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned64,
                    producer_sequence.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned32(self.verifier_source_ordinal),
            ],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationRootCompatibilityEdge {
    producer_endpoint: RelationRootEndpoint,
    consumer_endpoint: RelationRootEndpoint,
    construction_kind: RelationRootConstructionKind,
}

impl RelationRootCompatibilityEdge {
    pub(crate) fn new(
        producer_endpoint: RelationRootEndpoint,
        consumer_endpoint: RelationRootEndpoint,
        construction_kind: RelationRootConstructionKind,
    ) -> Result<Self, ProofProfileError> {
        producer_endpoint.validate_presence_pattern()?;
        consumer_endpoint.validate_presence_pattern()?;
        if producer_endpoint == consumer_endpoint {
            return Err(ProofProfileError::InvalidRootEndpoint);
        }
        Ok(Self {
            producer_endpoint,
            consumer_endpoint,
            construction_kind,
        })
    }

    fn canonical_tuple(self) -> Result<CanonicalTuple, ProofProfileError> {
        Ok(CanonicalTuple::new(
            RELATION_ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.producer_endpoint.canonical_tuple()?)
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::nested_tuple(&self.consumer_endpoint.canonical_tuple()?)
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.construction_kind as u16),
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofProfileSet {
    proof_fields: Vec<ProofFieldProfile>,
    proof_families: Vec<ProofFamilyProfile>,
    relation_plans: Vec<ValidatedRelationPlanArtifact>,
    root_compatibility_edges: Vec<RelationRootCompatibilityEdge>,
}

impl ProofProfileSet {
    pub(crate) fn new(
        relation_plans: Vec<ValidatedRelationPlanArtifact>,
        root_compatibility_edges: Vec<RelationRootCompatibilityEdge>,
    ) -> Result<Self, ProofProfileError> {
        let proof_fields = vec![ProofFieldProfile::selected()?];
        let proof_families = FIRST_PROFILE_APPLICATION_FAMILIES
            .into_iter()
            .map(ProofFamilyProfile::selected)
            .collect::<Result<Vec<_>, _>>()?;
        let profile = Self {
            proof_fields,
            proof_families,
            relation_plans,
            root_compatibility_edges,
        };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), ProofProfileError> {
        if self.proof_fields.len() != 1 {
            return Err(ProofProfileError::InvalidField);
        }
        self.proof_fields[0].validate()?;

        if self.proof_families.len() != FIRST_PROFILE_APPLICATION_FAMILIES.len()
            || self.relation_plans.len() != FIRST_PROFILE_APPLICATION_FAMILIES.len()
        {
            return Err(ProofProfileError::MissingFamily);
        }
        for (family_index, expected_family) in
            FIRST_PROFILE_APPLICATION_FAMILIES.iter().copied().enumerate()
        {
            let family = &self.proof_families[family_index];
            family.validate(self.proof_fields.len())?;
            if family.application_statement_schema_identifier != expected_family
                || self.relation_plans[family_index]
                    .application_statement_schema_identifier()
                    != expected_family
            {
                return Err(ProofProfileError::NonCanonicalOrder);
            }
        }

        let mut edge_bytes = BTreeSet::new();
        let mut previous_edge_bytes = None;
        for edge in &self.root_compatibility_edges {
            let canonical_bytes = edge
                .canonical_tuple()?
                .encode()
                .map_err(canonical_encoding_error)?;
            if previous_edge_bytes
                .as_ref()
                .is_some_and(|previous| previous >= &canonical_bytes)
            {
                return Err(ProofProfileError::NonCanonicalOrder);
            }
            if !edge_bytes.insert(canonical_bytes.clone()) {
                return Err(ProofProfileError::DuplicateRootEdge);
            }
            previous_edge_bytes = Some(canonical_bytes);
        }
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, ProofProfileError> {
        self.validate()?;
        let tuple = CanonicalTuple::new(
            PROOF_PROFILE_SET_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                canonical_nested_list(
                    self.proof_fields
                        .iter()
                        .map(ProofFieldProfile::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.proof_families
                        .iter()
                        .map(ProofFamilyProfile::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.relation_plans
                        .iter()
                        .map(|plan| plan.canonical_tuple().clone()),
                )?,
                canonical_nested_list(
                    self.root_compatibility_edges
                        .iter()
                        .copied()
                        .map(RelationRootCompatibilityEdge::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        );
        encode_generated_tuple(&tuple)
    }
}

fn read_canonical_u16(item: &CanonicalItem) -> Result<u16, ProofProfileError> {
    if item.item_type() != CanonicalItemType::Unsigned16
        || item.canonical_bytes().len() != 2
    {
        return Err(ProofProfileError::CanonicalEncoding);
    }
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(canonical_encoding_error)?,
    ))
}

fn canonical_u64_list(values: &[u64]) -> Result<CanonicalItem, ProofProfileError> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned64)
        .collect::<Vec<_>>();
    canonical_generated_list(CanonicalItemType::Unsigned64, &items)
}

fn canonical_nested_list(
    tuples: impl IntoIterator<Item = CanonicalTuple>,
) -> Result<CanonicalItem, ProofProfileError> {
    let items = tuples
        .into_iter()
        .map(|tuple| {
            let limits = generated_tuple_encoding_limits(&tuple, true)?;
            CanonicalItem::nested_tuple_with_limits(&tuple, &limits)
                .map_err(canonical_encoding_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical_generated_list(CanonicalItemType::NestedTuple, &items)
}

fn canonical_generated_list(
    element_type: CanonicalItemType,
    items: &[CanonicalItem],
) -> Result<CanonicalItem, ProofProfileError> {
    let canonical_byte_length = items.iter().try_fold(6_usize, |length, item| {
        length
            .checked_add(item.canonical_bytes().len())
            .ok_or(ProofProfileError::CanonicalEncoding)
    })?;
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: canonical_byte_length,
        maximum_item_count: items.len(),
        maximum_item_byte_length: canonical_byte_length,
        ..CanonicalDecodeLimits::default()
    };
    CanonicalItem::homogeneous_list_with_limits(element_type, items, &limits)
        .map_err(canonical_encoding_error)
}

fn generated_tuple_encoding_limits(
    tuple: &CanonicalTuple,
    nested_item: bool,
) -> Result<CanonicalDecodeLimits, ProofProfileError> {
    let tuple_byte_length = tuple.items.iter().try_fold(8_usize, |length, item| {
        u32::try_from(item.canonical_bytes().len())
            .map_err(|_| ProofProfileError::CanonicalEncoding)?;
        length
            .checked_add(6)
            .and_then(|value| value.checked_add(item.canonical_bytes().len()))
            .ok_or(ProofProfileError::CanonicalEncoding)
    })?;
    let maximum_contained_item_byte_length = tuple
        .items
        .iter()
        .map(|item| item.canonical_bytes().len())
        .max()
        .unwrap_or(0);
    Ok(CanonicalDecodeLimits {
        maximum_tuple_byte_length: tuple_byte_length,
        maximum_item_count: tuple.items.len(),
        maximum_item_byte_length: if nested_item {
            maximum_contained_item_byte_length.max(tuple_byte_length)
        } else {
            maximum_contained_item_byte_length
        },
        ..CanonicalDecodeLimits::default()
    })
}

fn encode_generated_tuple(tuple: &CanonicalTuple) -> Result<Vec<u8>, ProofProfileError> {
    tuple
        .encode_with_limits(&generated_tuple_encoding_limits(tuple, false)?)
        .map_err(canonical_encoding_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_field_and_schedule_are_canonical_and_nonnegotiable() {
        let field = ProofFieldProfile::selected().expect("selected field is valid");
        assert_eq!(field.validate(), Ok(()));
        assert_eq!(ProofFieldSchedule::selected().validate(1), Ok(()));

        let mut wrong_field = field.clone();
        wrong_field.maximum_two_adic_subgroup_generator = 1;
        assert_eq!(wrong_field.validate(), Err(ProofProfileError::InvalidField));

        let mut wrong_schedule = ProofFieldSchedule::selected();
        wrong_schedule.unique_query_count -= 1;
        assert_eq!(
            wrong_schedule.validate(1),
            Err(ProofProfileError::InvalidSchedule),
        );
    }

    #[test]
    fn root_endpoint_presence_is_derived_from_the_family() {
        assert!(RelationRootEndpoint::new(0x1216, Some(0), Some(3), None, None, 4).is_ok());
        assert_eq!(
            RelationRootEndpoint::new(0x1216, Some(0), None, None, None, 4),
            Err(ProofProfileError::InvalidRootEndpoint),
        );
        assert!(RelationRootEndpoint::new(0x1218, None, None, Some(20), None, 0).is_ok());
        assert_eq!(
            RelationRootEndpoint::new(0x1218, None, None, Some(21), None, 0),
            Err(ProofProfileError::InvalidRootEndpoint),
        );
        assert!(RelationRootEndpoint::new(0x1302, Some(9), None, None, Some(2), 1).is_ok());
    }

    #[test]
    fn complete_family_catalog_is_strictly_increasing() {
        assert!(FIRST_PROFILE_APPLICATION_FAMILIES
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        for family in FIRST_PROFILE_APPLICATION_FAMILIES {
            assert!(ProofFamilyProfile::selected(family).is_ok());
        }
        assert_eq!(
            ProofFamilyProfile::selected(0x9999),
            Err(ProofProfileError::UnsupportedFamily),
        );
    }
}
