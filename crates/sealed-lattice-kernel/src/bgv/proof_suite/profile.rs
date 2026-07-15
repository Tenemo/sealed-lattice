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

use super::relation_plan::{
    BoundTreeConstructionKind, BoundTreeRootUse, RelationColumnValueType,
    RelationOpeningSourceClass, RelationTreeDescriptor,
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
    InvalidRootTopology,
    MissingRootProducer,
    AmbiguousRootProducer,
    IncompatibleRoot,
    InsufficientRootMaskImage,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvaluatorKeyShareSourceKind {
    Relinearization,
    Galois,
}

impl EvaluatorKeyShareSourceKind {
    const fn application_statement_schema_identifier(self) -> u16 {
        match self {
            Self::Relinearization => 0x1216,
            Self::Galois => 0x1217,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorKeyAggregateEntryTopology {
    pub(crate) source_kind: EvaluatorKeyShareSourceKind,
    pub(crate) schedule_position: u32,
}

/// Instance topology needed to expand relation-plan variants into concrete
/// application slots.  It carries semantic ceremony choices, never raw root
/// endpoints or edges; the profile derives those from the checked plans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FirstProfileRootTopology {
    pub(crate) roster_size: u16,
    pub(crate) ordered_evaluator_key_entries: Vec<EvaluatorKeyAggregateEntryTopology>,
    pub(crate) target_evaluator_key_entry_count: u16,
    pub(crate) ordered_ballot_producer_sequences: Vec<u64>,
}

impl FirstProfileRootTopology {
    fn validate(&self) -> Result<(), ProofProfileError> {
        if !(3..=20).contains(&self.roster_size)
            || self.ordered_evaluator_key_entries.is_empty()
            || self.ordered_evaluator_key_entries.len() != 20
            || self.target_evaluator_key_entry_count == 0
            || usize::from(self.target_evaluator_key_entry_count)
                > self.ordered_evaluator_key_entries.len()
            || !self
                .ordered_ballot_producer_sequences
                .windows(2)
                .all(|window| window[0] < window[1])
        {
            return Err(ProofProfileError::InvalidRootTopology);
        }
        Ok(())
    }
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
        root_topology: FirstProfileRootTopology,
    ) -> Result<Self, ProofProfileError> {
        validate_relation_plan_catalog(&relation_plans)?;
        root_topology.validate()?;
        let root_compatibility_edges =
            derive_root_compatibility_edges(&relation_plans, &root_topology)?;
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
        validate_root_compatibility_edges(
            &self.relation_plans,
            &self.root_compatibility_edges,
        )?;
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct RelationRootColumnShape {
    value_type: RelationColumnValueType,
    source_degree_bound_exclusive: u64,
    canonical_residue_modulus: Option<super::SuiteModulusReference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RelationRootShape {
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    ordered_columns: Vec<RelationRootColumnShape>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundRootSlot {
    endpoint: RelationRootEndpoint,
    construction_kind: RelationRootConstructionKind,
    root_use: BoundTreeRootUse,
    ordered_column_ordinals: Vec<u32>,
    shape: RelationRootShape,
}

fn validate_relation_plan_catalog(
    relation_plans: &[ValidatedRelationPlanArtifact],
) -> Result<(), ProofProfileError> {
    if relation_plans.len() != FIRST_PROFILE_APPLICATION_FAMILIES.len() {
        return Err(ProofProfileError::MissingFamily);
    }
    for (artifact, expected_family) in relation_plans
        .iter()
        .zip(FIRST_PROFILE_APPLICATION_FAMILIES)
    {
        if artifact.application_statement_schema_identifier() != expected_family {
            return Err(ProofProfileError::NonCanonicalOrder);
        }
    }
    Ok(())
}

fn relation_plan_artifact(
    relation_plans: &[ValidatedRelationPlanArtifact],
    application_statement_schema_identifier: u16,
) -> Result<&ValidatedRelationPlanArtifact, ProofProfileError> {
    let index = FIRST_PROFILE_APPLICATION_FAMILIES
        .binary_search(&application_statement_schema_identifier)
        .map_err(|_| ProofProfileError::UnsupportedFamily)?;
    relation_plans
        .get(index)
        .filter(|artifact| {
            artifact.application_statement_schema_identifier()
                == application_statement_schema_identifier
        })
        .ok_or(ProofProfileError::MissingFamily)
}

fn root_shape(
    variant: &super::RelationPlanVariant,
    ordered_column_ordinals: &[u32],
) -> Result<RelationRootShape, ProofProfileError> {
    let ordered_columns = ordered_column_ordinals
        .iter()
        .copied()
        .map(|column_ordinal| {
            let column = variant
                .ordered_columns()
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| ProofProfileError::CountOverflow)?,
                )
                .ok_or(ProofProfileError::IncompatibleRoot)?;
            Ok(RelationRootColumnShape {
                value_type: column.value_type(),
                source_degree_bound_exclusive: column
                    .source_degree_bound_exclusive(),
                canonical_residue_modulus: column.canonical_residue_modulus(),
            })
        })
        .collect::<Result<Vec<_>, ProofProfileError>>()?;
    if ordered_columns.is_empty() {
        return Err(ProofProfileError::IncompatibleRoot);
    }
    Ok(RelationRootShape {
        trace_domain_size: variant.trace_domain_size(),
        evaluation_domain_size: variant.evaluation_domain_size(),
        opening_degree_bound_exclusive: variant
            .opening_degree_bound_exclusive(),
        ordered_columns,
    })
}

fn ordered_bound_root_slots(
    relation_plans: &[ValidatedRelationPlanArtifact],
    application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    producer_sequence: Option<u64>,
    construction_kind: RelationRootConstructionKind,
    root_use: BoundTreeRootUse,
) -> Result<Vec<BoundRootSlot>, ProofProfileError> {
    let artifact = relation_plan_artifact(
        relation_plans,
        application_statement_schema_identifier,
    )?;
    let variant = artifact
        .compiled_plan()
        .select_variant(schedule_position, top_count)?;
    let expected_construction_kind = match construction_kind {
        RelationRootConstructionKind::CommittedMaterial => {
            BoundTreeConstructionKind::CommittedMaterial
        }
        RelationRootConstructionKind::SetupPolynomial => {
            BoundTreeConstructionKind::SetupPolynomial
        }
    };
    variant
        .ordered_trees()
        .iter()
        .filter_map(|tree| {
            let RelationTreeDescriptor::BoundPublic {
                construction_kind: actual_construction_kind,
                expected_root_source_ordinal,
                root_use: actual_root_use,
                ordered_column_ordinals,
            } = tree
            else {
                return None;
            };
            (*actual_construction_kind == expected_construction_kind
                && *actual_root_use == root_use)
                .then_some((*expected_root_source_ordinal, ordered_column_ordinals))
        })
        .map(|(verifier_source_ordinal, ordered_column_ordinals)| {
            Ok(BoundRootSlot {
                endpoint: RelationRootEndpoint::new(
                    application_statement_schema_identifier,
                    roster_position,
                    schedule_position,
                    top_count,
                    producer_sequence,
                    verifier_source_ordinal,
                )?,
                construction_kind,
                root_use,
                ordered_column_ordinals: ordered_column_ordinals.clone(),
                shape: root_shape(variant, ordered_column_ordinals)?,
            })
        })
        .collect()
}

fn bound_root_slot_for_endpoint(
    relation_plans: &[ValidatedRelationPlanArtifact],
    endpoint: RelationRootEndpoint,
    construction_kind: RelationRootConstructionKind,
    root_use: BoundTreeRootUse,
) -> Result<BoundRootSlot, ProofProfileError> {
    let mut roots = ordered_bound_root_slots(
        relation_plans,
        endpoint.application_statement_schema_identifier,
        endpoint.roster_position,
        endpoint.schedule_position,
        endpoint.top_count,
        endpoint.producer_sequence,
        construction_kind,
        root_use,
    )?
    .into_iter()
    .filter(|root| {
        root.endpoint.verifier_source_ordinal
            == endpoint.verifier_source_ordinal
    });
    let root = roots.next().ok_or(match root_use {
        BoundTreeRootUse::Output => ProofProfileError::MissingRootProducer,
        BoundTreeRootUse::Input => ProofProfileError::InvalidRootEndpoint,
    })?;
    if roots.next().is_some() {
        return Err(ProofProfileError::AmbiguousRootProducer);
    }
    Ok(root)
}

fn append_root_edge(
    edges: &mut Vec<RelationRootCompatibilityEdge>,
    assigned_consumers: &mut BTreeSet<RelationRootEndpoint>,
    producer: &BoundRootSlot,
    consumer: &BoundRootSlot,
    construction_kind: RelationRootConstructionKind,
) -> Result<(), ProofProfileError> {
    if producer.root_use != BoundTreeRootUse::Output {
        return Err(ProofProfileError::MissingRootProducer);
    }
    if consumer.root_use != BoundTreeRootUse::Input {
        return Err(ProofProfileError::InvalidRootEndpoint);
    }
    if producer.construction_kind != construction_kind
        || consumer.construction_kind != construction_kind
        || producer.shape != consumer.shape
    {
        return Err(ProofProfileError::IncompatibleRoot);
    }
    if !assigned_consumers.insert(consumer.endpoint) {
        return Err(ProofProfileError::AmbiguousRootProducer);
    }
    edges.push(RelationRootCompatibilityEdge::new(
        producer.endpoint,
        consumer.endpoint,
        construction_kind,
    )?);
    Ok(())
}

fn require_root_count(
    roots: &[BoundRootSlot],
    expected_count: usize,
) -> Result<(), ProofProfileError> {
    if roots.len() != expected_count {
        return Err(ProofProfileError::InvalidRootTopology);
    }
    Ok(())
}

fn checked_product(left: usize, right: usize) -> Result<usize, ProofProfileError> {
    left.checked_mul(right)
        .ok_or(ProofProfileError::CountOverflow)
}

fn checked_sum(left: usize, right: usize) -> Result<usize, ProofProfileError> {
    left.checked_add(right)
        .ok_or(ProofProfileError::CountOverflow)
}

fn derive_root_compatibility_edges(
    relation_plans: &[ValidatedRelationPlanArtifact],
    topology: &FirstProfileRootTopology,
) -> Result<Vec<RelationRootCompatibilityEdge>, ProofProfileError> {
    validate_relation_plan_catalog(relation_plans)?;
    topology.validate()?;
    let roster_size = usize::from(topology.roster_size);
    let mut edges = Vec::new();
    let mut assigned_consumers = BTreeSet::new();

    // Expand the two committed-material relations.  The typed plan inventory
    // fixes the limb-major root order; the topology supplies only the roster
    // cardinality.  Consequently a caller cannot relabel dealers or
    // recipients by presenting a different edge list.
    let vss_output_template = ordered_bound_root_slots(
        relation_plans,
        0x2110,
        Some(0),
        None,
        None,
        None,
        RelationRootConstructionKind::CommittedMaterial,
        BoundTreeRootUse::Output,
    )?;
    let aggregate_input_template = ordered_bound_root_slots(
        relation_plans,
        0x2111,
        Some(0),
        None,
        None,
        None,
        RelationRootConstructionKind::CommittedMaterial,
        BoundTreeRootUse::Input,
    )?;
    let aggregate_output_template = ordered_bound_root_slots(
        relation_plans,
        0x2111,
        Some(0),
        None,
        None,
        None,
        RelationRootConstructionKind::CommittedMaterial,
        BoundTreeRootUse::Output,
    )?;
    if aggregate_input_template.is_empty()
        || !aggregate_input_template.len().is_multiple_of(roster_size)
    {
        return Err(ProofProfileError::InvalidRootTopology);
    }
    let sharing_limb_count = aggregate_input_template.len() / roster_size;
    require_root_count(&aggregate_output_template, sharing_limb_count)?;
    if sharing_limb_count == 0
        || !vss_output_template.len().is_multiple_of(sharing_limb_count)
    {
        return Err(ProofProfileError::InvalidRootTopology);
    }
    let roots_per_vss_limb = vss_output_template.len() / sharing_limb_count;
    let threshold = roots_per_vss_limb
        .checked_sub(roster_size)
        .filter(|threshold| (2..=roster_size).contains(threshold))
        .ok_or(ProofProfileError::InvalidRootTopology)?;

    for dealer_position in 0..topology.roster_size {
        let dealer_outputs = ordered_bound_root_slots(
            relation_plans,
            0x2110,
            Some(dealer_position),
            None,
            None,
            None,
            RelationRootConstructionKind::CommittedMaterial,
            BoundTreeRootUse::Output,
        )?;
        require_root_count(&dealer_outputs, vss_output_template.len())?;

        let same_secret_inputs = ordered_bound_root_slots(
            relation_plans,
            0x1211,
            Some(dealer_position),
            None,
            None,
            None,
            RelationRootConstructionKind::CommittedMaterial,
            BoundTreeRootUse::Input,
        )?;
        require_root_count(&same_secret_inputs, sharing_limb_count)?;
        for sharing_limb_ordinal in 0..sharing_limb_count {
            let coefficient_zero_index = checked_product(
                sharing_limb_ordinal,
                roots_per_vss_limb,
            )?;
            append_root_edge(
                &mut edges,
                &mut assigned_consumers,
                &dealer_outputs[coefficient_zero_index],
                &same_secret_inputs[sharing_limb_ordinal],
                RelationRootConstructionKind::CommittedMaterial,
            )?;
        }

        for recipient_position in 0..topology.roster_size {
            let recipient_inputs = ordered_bound_root_slots(
                relation_plans,
                0x2111,
                Some(recipient_position),
                None,
                None,
                None,
                RelationRootConstructionKind::CommittedMaterial,
                BoundTreeRootUse::Input,
            )?;
            require_root_count(&recipient_inputs, aggregate_input_template.len())?;
            for sharing_limb_ordinal in 0..sharing_limb_count {
                let producer_index = checked_sum(
                    checked_product(sharing_limb_ordinal, roots_per_vss_limb)?,
                    checked_sum(threshold, usize::from(recipient_position))?,
                )?;
                let consumer_index = checked_sum(
                    checked_product(sharing_limb_ordinal, roster_size)?,
                    usize::from(dealer_position),
                )?;
                append_root_edge(
                    &mut edges,
                    &mut assigned_consumers,
                    &dealer_outputs[producer_index],
                    &recipient_inputs[consumer_index],
                    RelationRootConstructionKind::CommittedMaterial,
                )?;
            }
        }
    }

    for recipient_position in 0..topology.roster_size {
        let aggregate_outputs = ordered_bound_root_slots(
            relation_plans,
            0x2111,
            Some(recipient_position),
            None,
            None,
            None,
            RelationRootConstructionKind::CommittedMaterial,
            BoundTreeRootUse::Output,
        )?;
        let target_inputs = ordered_bound_root_slots(
            relation_plans,
            0x1621,
            Some(recipient_position),
            None,
            None,
            None,
            RelationRootConstructionKind::CommittedMaterial,
            BoundTreeRootUse::Input,
        )?;
        require_root_count(&aggregate_outputs, sharing_limb_count)?;
        require_root_count(&target_inputs, sharing_limb_count)?;
        for sharing_limb_ordinal in 0..sharing_limb_count {
            append_root_edge(
                &mut edges,
                &mut assigned_consumers,
                &aggregate_outputs[sharing_limb_ordinal],
                &target_inputs[sharing_limb_ordinal],
                RelationRootConstructionKind::CommittedMaterial,
            )?;
        }
    }

    // Same-secret anchors are produced by 0x1211 and consumed by the
    // public-key-share relation in the same roster slot.  Both sides are
    // ordered by the checked commitment-modulus catalog.
    for roster_position in 0..topology.roster_size {
        let anchor_outputs = ordered_bound_root_slots(
            relation_plans,
            0x1211,
            Some(roster_position),
            None,
            None,
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Output,
        )?;
        let public_key_anchor_inputs = ordered_bound_root_slots(
            relation_plans,
            0x1212,
            Some(roster_position),
            None,
            None,
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Input,
        )?;
        require_root_count(&public_key_anchor_inputs, anchor_outputs.len())?;
        for (producer, consumer) in anchor_outputs
            .iter()
            .zip(public_key_anchor_inputs.iter())
        {
            append_root_edge(
                &mut edges,
                &mut assigned_consumers,
                producer,
                consumer,
                RelationRootConstructionKind::SetupPolynomial,
            )?;
        }
    }

    let collective_public_key_inputs = ordered_bound_root_slots(
        relation_plans,
        0x1213,
        None,
        None,
        None,
        None,
        RelationRootConstructionKind::SetupPolynomial,
        BoundTreeRootUse::Input,
    )?;
    let collective_public_key_outputs = ordered_bound_root_slots(
        relation_plans,
        0x1213,
        None,
        None,
        None,
        None,
        RelationRootConstructionKind::SetupPolynomial,
        BoundTreeRootUse::Output,
    )?;
    require_root_count(&collective_public_key_inputs, roster_size)?;
    require_root_count(&collective_public_key_outputs, 1)?;
    for roster_position in 0..topology.roster_size {
        let public_key_outputs = ordered_bound_root_slots(
            relation_plans,
            0x1212,
            Some(roster_position),
            None,
            None,
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Output,
        )?;
        require_root_count(&public_key_outputs, 1)?;
        append_root_edge(
            &mut edges,
            &mut assigned_consumers,
            &public_key_outputs[0],
            &collective_public_key_inputs[usize::from(roster_position)],
            RelationRootConstructionKind::SetupPolynomial,
        )?;
    }

    derive_rkg_aggregate_edges(
        relation_plans,
        topology,
        &mut edges,
        &mut assigned_consumers,
    )?;
    derive_evaluator_aggregate_edges(
        relation_plans,
        topology,
        &mut edges,
        &mut assigned_consumers,
    )?;
    derive_public_key_to_ballot_edges(
        relation_plans,
        topology,
        &collective_public_key_outputs[0],
        &mut edges,
        &mut assigned_consumers,
    )?;

    // The remaining setup-polynomial inputs are the per-trustee anchor and
    // round-one-aggregate consumers.  Exact root geometry and slot scope make
    // their producer unique; any missing or second compatible producer is a
    // profile-generation failure.
    let all_outputs = all_bound_root_slots(
        relation_plans,
        topology,
        BoundTreeRootUse::Output,
    )?;
    for consumer in all_bound_root_slots(
        relation_plans,
        topology,
        BoundTreeRootUse::Input,
    )? {
        if assigned_consumers.contains(&consumer.endpoint) {
            continue;
        }
        let candidates = all_outputs
            .iter()
            .filter(|producer| {
                allowed_root_transition(
                    producer.endpoint.application_statement_schema_identifier,
                    consumer.endpoint.application_statement_schema_identifier,
                ) && root_scopes_are_compatible(producer.endpoint, consumer.endpoint)
                    && producer.construction_kind == consumer.construction_kind
                    && producer.shape == consumer.shape
            })
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [] => return Err(ProofProfileError::MissingRootProducer),
            [producer] => append_root_edge(
                &mut edges,
                &mut assigned_consumers,
                producer,
                &consumer,
                producer.construction_kind,
            )?,
            _ => return Err(ProofProfileError::AmbiguousRootProducer),
        }
    }

    validate_persistent_committed_material_mask_images(
        relation_plans,
        topology,
        &edges,
    )?;

    let mut encoded_edges = edges
        .into_iter()
        .map(|edge| {
            Ok((
                edge.canonical_tuple()?
                    .encode()
                    .map_err(canonical_encoding_error)?,
                edge,
            ))
        })
        .collect::<Result<Vec<_>, ProofProfileError>>()?;
    encoded_edges.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded_edges
        .windows(2)
        .any(|window| window[0].0 == window[1].0)
    {
        return Err(ProofProfileError::DuplicateRootEdge);
    }
    Ok(encoded_edges.into_iter().map(|(_, edge)| edge).collect())
}

fn committed_material_root_view_coordinate_count(
    relation_plans: &[ValidatedRelationPlanArtifact],
    endpoint: RelationRootEndpoint,
    root_use: BoundTreeRootUse,
) -> Result<u64, ProofProfileError> {
    let root = bound_root_slot_for_endpoint(
        relation_plans,
        endpoint,
        RelationRootConstructionKind::CommittedMaterial,
        root_use,
    )?;
    let variant = relation_plan_artifact(
        relation_plans,
        endpoint.application_statement_schema_identifier,
    )?
    .compiled_plan()
    .select_variant(endpoint.schedule_position, endpoint.top_count)?;
    let extension_degree = u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
        .map_err(|_| ProofProfileError::CountOverflow)?;
    let phase_pair_query_coordinate_count = u64::from(PROOF_UNIQUE_QUERY_COUNT)
        .checked_mul(2)
        .ok_or(ProofProfileError::CountOverflow)?;
    let mut maximum_coordinate_count = 0_u64;
    for column_ordinal in root.ordered_column_ordinals {
        let mut deep_opening_count = 0_u64;
        let mut required_rotations = BTreeSet::from([(false, 0_u64)]);
        for claim in variant.ordered_opening_claims().iter().filter(|claim| {
            claim.source_class() == RelationOpeningSourceClass::TreeColumn
                && claim.column_ordinal() == Some(column_ordinal)
        }) {
            deep_opening_count = deep_opening_count
                .checked_add(1)
                .ok_or(ProofProfileError::CountOverflow)?;
            let opening_point = variant
                .ordered_opening_points()
                .get(
                    usize::try_from(claim.opening_point_ordinal())
                        .map_err(|_| ProofProfileError::CountOverflow)?,
                )
                .ok_or(ProofProfileError::IncompatibleRoot)?;
            required_rotations.insert(opening_point.trace_rotation());
        }
        if deep_opening_count == 0 {
            return Err(ProofProfileError::InsufficientRootMaskImage);
        }
        let query_rotation_count = u64::try_from(required_rotations.len())
            .map_err(|_| ProofProfileError::CountOverflow)?;
        let coordinate_count = deep_opening_count
            .checked_mul(extension_degree)
            .and_then(|count| {
                phase_pair_query_coordinate_count
                    .checked_mul(query_rotation_count)
                    .and_then(|query_count| count.checked_add(query_count))
            })
            .ok_or(ProofProfileError::CountOverflow)?;
        maximum_coordinate_count = maximum_coordinate_count.max(coordinate_count);
    }
    if maximum_coordinate_count == 0 {
        return Err(ProofProfileError::InsufficientRootMaskImage);
    }
    Ok(maximum_coordinate_count)
}

fn committed_material_mask_coefficient_count(
    root: &BoundRootSlot,
) -> Result<u64, ProofProfileError> {
    if root.construction_kind != RelationRootConstructionKind::CommittedMaterial {
        return Err(ProofProfileError::IncompatibleRoot);
    }
    let mut counts = root.shape.ordered_columns.iter().map(|column| {
        column
            .source_degree_bound_exclusive
            .checked_sub(root.shape.trace_domain_size)
            .filter(|count| *count > 0 && *count <= root.shape.trace_domain_size)
            .ok_or(ProofProfileError::InsufficientRootMaskImage)
    });
    let coefficient_count = counts
        .next()
        .ok_or(ProofProfileError::InsufficientRootMaskImage)??;
    for count in counts {
        if count? != coefficient_count {
            return Err(ProofProfileError::InsufficientRootMaskImage);
        }
    }
    Ok(coefficient_count)
}

fn validate_persistent_committed_material_mask_images(
    relation_plans: &[ValidatedRelationPlanArtifact],
    topology: &FirstProfileRootTopology,
    edges: &[RelationRootCompatibilityEdge],
) -> Result<(), ProofProfileError> {
    for producer in all_bound_root_slots(
        relation_plans,
        topology,
        BoundTreeRootUse::Output,
    )?
    .into_iter()
    .filter(|root| {
        root.construction_kind == RelationRootConstructionKind::CommittedMaterial
    }) {
        let mut required_coefficient_count =
            committed_material_root_view_coordinate_count(
                relation_plans,
                producer.endpoint,
                BoundTreeRootUse::Output,
            )?;
        for edge in edges.iter().filter(|edge| {
            edge.construction_kind
                == RelationRootConstructionKind::CommittedMaterial
                && edge.producer_endpoint == producer.endpoint
        }) {
            required_coefficient_count = required_coefficient_count
                .checked_add(committed_material_root_view_coordinate_count(
                    relation_plans,
                    edge.consumer_endpoint,
                    BoundTreeRootUse::Input,
                )?)
                .ok_or(ProofProfileError::CountOverflow)?;
        }
        if committed_material_mask_coefficient_count(&producer)?
            < required_coefficient_count
        {
            return Err(ProofProfileError::InsufficientRootMaskImage);
        }
    }
    Ok(())
}

fn derive_rkg_aggregate_edges(
    relation_plans: &[ValidatedRelationPlanArtifact],
    topology: &FirstProfileRootTopology,
    edges: &mut Vec<RelationRootCompatibilityEdge>,
    assigned_consumers: &mut BTreeSet<RelationRootEndpoint>,
) -> Result<(), ProofProfileError> {
    let aggregate_plan = relation_plan_artifact(relation_plans, 0x1215)?;
    let roster_size = usize::from(topology.roster_size);
    for variant in aggregate_plan.compiled_plan().variants() {
        let schedule_position = variant
            .schedule_position()
            .ok_or(ProofProfileError::InvalidRootTopology)?;
        if variant.top_count().is_some() {
            return Err(ProofProfileError::InvalidRootTopology);
        }
        let aggregate_inputs = ordered_bound_root_slots(
            relation_plans,
            0x1215,
            None,
            Some(schedule_position),
            None,
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Input,
        )?;
        let aggregate_outputs = ordered_bound_root_slots(
            relation_plans,
            0x1215,
            None,
            Some(schedule_position),
            None,
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Output,
        )?;
        require_root_count(&aggregate_inputs, checked_product(2, roster_size)?)?;
        require_root_count(&aggregate_outputs, 2)?;
        for roster_position in 0..topology.roster_size {
            let trustee_outputs = ordered_bound_root_slots(
                relation_plans,
                0x1214,
                Some(roster_position),
                Some(schedule_position),
                None,
                None,
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Output,
            )?;
            require_root_count(&trustee_outputs, 2)?;
            for component_ordinal in 0..2 {
                let consumer_index = checked_sum(
                    checked_product(component_ordinal, roster_size)?,
                    usize::from(roster_position),
                )?;
                append_root_edge(
                    edges,
                    assigned_consumers,
                    &trustee_outputs[component_ordinal],
                    &aggregate_inputs[consumer_index],
                    RelationRootConstructionKind::SetupPolynomial,
                )?;
            }
        }
    }
    Ok(())
}

fn derive_evaluator_aggregate_edges(
    relation_plans: &[ValidatedRelationPlanArtifact],
    topology: &FirstProfileRootTopology,
    edges: &mut Vec<RelationRootCompatibilityEdge>,
    assigned_consumers: &mut BTreeSet<RelationRootEndpoint>,
) -> Result<(), ProofProfileError> {
    let roster_size = usize::from(topology.roster_size);
    for top_count in 1..=20_u16 {
        let evaluator_inputs = ordered_bound_root_slots(
            relation_plans,
            0x1218,
            None,
            None,
            Some(top_count),
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Input,
        )?;
        let evaluator_outputs = ordered_bound_root_slots(
            relation_plans,
            0x1218,
            None,
            None,
            Some(top_count),
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Output,
        )?;
        require_root_count(
            &evaluator_inputs,
            checked_product(usize::from(top_count), roster_size)?,
        )?;
        require_root_count(&evaluator_outputs, usize::from(top_count))?;
        for (entry_ordinal, entry) in topology
            .ordered_evaluator_key_entries
            .iter()
            .take(usize::from(top_count))
            .enumerate()
        {
            let producer_family = entry
                .source_kind
                .application_statement_schema_identifier();
            for roster_position in 0..topology.roster_size {
                let trustee_outputs = ordered_bound_root_slots(
                    relation_plans,
                    producer_family,
                    Some(roster_position),
                    Some(entry.schedule_position),
                    None,
                    None,
                    RelationRootConstructionKind::SetupPolynomial,
                    BoundTreeRootUse::Output,
                )?;
                require_root_count(&trustee_outputs, 1)?;
                let consumer_index = checked_sum(
                    checked_product(entry_ordinal, roster_size)?,
                    usize::from(roster_position),
                )?;
                append_root_edge(
                    edges,
                    assigned_consumers,
                    &trustee_outputs[0],
                    &evaluator_inputs[consumer_index],
                    RelationRootConstructionKind::SetupPolynomial,
                )?;
            }
        }
    }

    let selected_top_count = topology.target_evaluator_key_entry_count;
    let evaluator_outputs = ordered_bound_root_slots(
        relation_plans,
        0x1218,
        None,
        None,
        Some(selected_top_count),
        None,
        RelationRootConstructionKind::SetupPolynomial,
        BoundTreeRootUse::Output,
    )?;
    require_root_count(&evaluator_outputs, usize::from(selected_top_count))?;
    for roster_position in 0..topology.roster_size {
        let target_inputs = ordered_bound_root_slots(
            relation_plans,
            0x1621,
            Some(roster_position),
            None,
            None,
            None,
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Input,
        )?;
        require_root_count(&target_inputs, usize::from(selected_top_count))?;
        for entry_ordinal in 0..usize::from(selected_top_count) {
            append_root_edge(
                edges,
                assigned_consumers,
                &evaluator_outputs[entry_ordinal],
                &target_inputs[entry_ordinal],
                RelationRootConstructionKind::SetupPolynomial,
            )?;
        }
    }
    Ok(())
}

fn derive_public_key_to_ballot_edges(
    relation_plans: &[ValidatedRelationPlanArtifact],
    topology: &FirstProfileRootTopology,
    collective_public_key_output: &BoundRootSlot,
    edges: &mut Vec<RelationRootCompatibilityEdge>,
    assigned_consumers: &mut BTreeSet<RelationRootEndpoint>,
) -> Result<(), ProofProfileError> {
    for producer_sequence in topology
        .ordered_ballot_producer_sequences
        .iter()
        .copied()
    {
        // The roster position is a real 0x1302 endpoint component, not a
        // placeholder.  Expand one ballot application for every roster slot
        // at this producer sequence.
        for roster_position in 0..topology.roster_size {
            let ballot_inputs = ordered_bound_root_slots(
                relation_plans,
                0x1302,
                Some(roster_position),
                None,
                None,
                Some(producer_sequence),
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Input,
            )?;
            require_root_count(&ballot_inputs, 1)?;
            append_root_edge(
                edges,
                assigned_consumers,
                collective_public_key_output,
                &ballot_inputs[0],
                RelationRootConstructionKind::SetupPolynomial,
            )?;
        }
    }
    Ok(())
}

fn all_bound_root_slots(
    relation_plans: &[ValidatedRelationPlanArtifact],
    topology: &FirstProfileRootTopology,
    root_use: BoundTreeRootUse,
) -> Result<Vec<BoundRootSlot>, ProofProfileError> {
    let mut roots = Vec::new();
    for artifact in relation_plans {
        let family = artifact.application_statement_schema_identifier();
        for variant in artifact.compiled_plan().variants() {
            let schedule_position = variant.schedule_position();
            let top_count = variant.top_count();
            let roster_positions = if family == 0x1302 {
                (0..topology.roster_size).map(Some).collect::<Vec<_>>()
            } else if matches!(
                family,
                0x2110 | 0x2111 | 0x1211 | 0x1212 | 0x1214 | 0x1216 | 0x1217 | 0x1621
            ) {
                (0..topology.roster_size).map(Some).collect::<Vec<_>>()
            } else {
                vec![None]
            };
            let producer_sequences = if family == 0x1302 {
                topology
                    .ordered_ballot_producer_sequences
                    .iter()
                    .copied()
                    .map(Some)
                    .collect::<Vec<_>>()
            } else {
                vec![None]
            };
            for roster_position in roster_positions.iter().copied() {
                for producer_sequence in producer_sequences.iter().copied() {
                    for construction_kind in [
                        RelationRootConstructionKind::CommittedMaterial,
                        RelationRootConstructionKind::SetupPolynomial,
                    ] {
                        roots.extend(ordered_bound_root_slots(
                            relation_plans,
                            family,
                            roster_position,
                            schedule_position,
                            top_count,
                            producer_sequence,
                            construction_kind,
                            root_use,
                        )?);
                    }
                }
            }
        }
    }
    Ok(roots)
}

fn allowed_root_transition(producer_family: u16, consumer_family: u16) -> bool {
    matches!(
        (producer_family, consumer_family),
        (0x2110, 0x2111 | 0x1211)
            | (0x2111, 0x1621)
            | (0x1211, 0x1212 | 0x1214 | 0x1216 | 0x1217)
            | (0x1212, 0x1213)
            | (0x1213, 0x1302)
            | (0x1214, 0x1215)
            | (0x1215, 0x1216 | 0x1217)
            | (0x1216 | 0x1217, 0x1218)
            | (0x1218, 0x1621)
    )
}

fn root_scopes_are_compatible(
    producer: RelationRootEndpoint,
    consumer: RelationRootEndpoint,
) -> bool {
    let families = (
        producer.application_statement_schema_identifier,
        consumer.application_statement_schema_identifier,
    );
    let roster_matches = match families {
        (0x2110, 0x2111)
        | (0x1212, 0x1213)
        | (0x1213, 0x1302)
        | (0x1214, 0x1215)
        | (0x1216 | 0x1217, 0x1218)
        | (0x1218, 0x1621) => true,
        _ => producer
            .roster_position
            .zip(consumer.roster_position)
            .is_none_or(|(left, right)| left == right),
    };
    roster_matches
        && producer
            .schedule_position
            .zip(consumer.schedule_position)
            .is_none_or(|(left, right)| left == right)
}

fn validate_root_compatibility_edges(
    relation_plans: &[ValidatedRelationPlanArtifact],
    edges: &[RelationRootCompatibilityEdge],
) -> Result<(), ProofProfileError> {
    let mut assigned_consumers = BTreeSet::new();
    for edge in edges {
        if !allowed_root_transition(
            edge.producer_endpoint
                .application_statement_schema_identifier,
            edge.consumer_endpoint
                .application_statement_schema_identifier,
        ) || !root_scopes_are_compatible(
            edge.producer_endpoint,
            edge.consumer_endpoint,
        ) || !assigned_consumers.insert(edge.consumer_endpoint)
        {
            return Err(ProofProfileError::AmbiguousRootProducer);
        }
        let producer = bound_root_slot_for_endpoint(
            relation_plans,
            edge.producer_endpoint,
            edge.construction_kind,
            BoundTreeRootUse::Output,
        )?;
        let consumer = bound_root_slot_for_endpoint(
            relation_plans,
            edge.consumer_endpoint,
            edge.construction_kind,
            BoundTreeRootUse::Input,
        )?;
        if producer.shape != consumer.shape {
            return Err(ProofProfileError::IncompatibleRoot);
        }
    }
    Ok(())
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

    fn synthetic_anchor_root(
        family: u16,
        source_ordinal: u32,
        root_use: BoundTreeRootUse,
    ) -> BoundRootSlot {
        BoundRootSlot {
            endpoint: RelationRootEndpoint::new(
                family,
                Some(0),
                None,
                None,
                None,
                source_ordinal,
            )
            .expect("the synthetic endpoint follows its family shape"),
            construction_kind: RelationRootConstructionKind::SetupPolynomial,
            root_use,
            ordered_column_ordinals: vec![0],
            shape: RelationRootShape {
                trace_domain_size: 1 << 15,
                evaluation_domain_size: 1 << 19,
                opening_degree_bound_exclusive: 1 << 16,
                ordered_columns: vec![RelationRootColumnShape {
                    value_type: RelationColumnValueType::BaseField,
                    source_degree_bound_exclusive: 1 << 15,
                    canonical_residue_modulus: None,
                }],
            },
        }
    }

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
    fn anchor_edge_rejects_an_input_as_its_producer() {
        let producer = synthetic_anchor_root(0x1211, 3, BoundTreeRootUse::Input);
        let consumer = synthetic_anchor_root(0x1212, 4, BoundTreeRootUse::Input);
        let mut edges = Vec::new();
        let mut assigned_consumers = BTreeSet::new();

        assert_eq!(
            append_root_edge(
                &mut edges,
                &mut assigned_consumers,
                &producer,
                &consumer,
                RelationRootConstructionKind::SetupPolynomial,
            ),
            Err(ProofProfileError::MissingRootProducer),
        );
        assert!(edges.is_empty());
        assert!(assigned_consumers.is_empty());
    }

    #[test]
    fn anchor_edge_rejects_a_second_producer_for_one_consumer() {
        let first_producer =
            synthetic_anchor_root(0x1211, 3, BoundTreeRootUse::Output);
        let second_producer =
            synthetic_anchor_root(0x1211, 5, BoundTreeRootUse::Output);
        let consumer = synthetic_anchor_root(0x1212, 4, BoundTreeRootUse::Input);
        let mut edges = Vec::new();
        let mut assigned_consumers = BTreeSet::new();

        append_root_edge(
            &mut edges,
            &mut assigned_consumers,
            &first_producer,
            &consumer,
            RelationRootConstructionKind::SetupPolynomial,
        )
        .expect("the first unique producer is admissible");
        assert_eq!(
            append_root_edge(
                &mut edges,
                &mut assigned_consumers,
                &second_producer,
                &consumer,
                RelationRootConstructionKind::SetupPolynomial,
            ),
            Err(ProofProfileError::AmbiguousRootProducer),
        );
        assert_eq!(edges.len(), 1);
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
