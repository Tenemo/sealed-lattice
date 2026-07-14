use std::collections::{BTreeMap, BTreeSet};

use crate::{
    bgv::{
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIME},
        proof_suite::{
            COMMON_PROOF_PROFILE,
            field::{GOLDILOCKS_MODULUS, Goldilocks},
            profile::{is_prime_u64, modular_power},
            relation_plan::{
                ProofFamily, ProofPrivacyMode, ProofTreeRole, RelationColumnSource,
                RelationPlanCatalog, RelationPlanVariantSelector, RootConstructionKind, Zeroifier,
            },
        },
    },
    foundation::{
        CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
        CanonicalTuple, SuiteArtifactKind,
    },
};

const PROOF_PROFILE_SET_SCHEMA_IDENTIFIER: u16 = 0x2200;
const PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2201;
const PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2202;
const PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER: u16 = 0x2203;
const RELATION_PLAN_SCHEMA_IDENTIFIER: u16 = 0x2204;
const RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER: u16 = 0x2205;
const RELATION_COLUMN_SCHEMA_IDENTIFIER: u16 = 0x2206;
const PROOF_CREATED_TREE_SCHEMA_IDENTIFIER: u16 = 0x2207;
const BOUND_PUBLIC_TREE_SCHEMA_IDENTIFIER: u16 = 0x2208;
const RELATION_CONSTRAINT_SCHEMA_IDENTIFIER: u16 = 0x2209;
const RELATION_OPENING_POINT_SCHEMA_IDENTIFIER: u16 = 0x220a;
const RELATION_OPENING_CLAIM_SCHEMA_IDENTIFIER: u16 = 0x220b;
const RELATION_MASK_SCHEMA_IDENTIFIER: u16 = 0x220c;
const SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x220e;
const RELATION_PUBLIC_SAMPLER_SCHEMA_IDENTIFIER: u16 = 0x220f;
const CONSTANT_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2210;
const EVALUATION_VARIABLE_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2211;
const COLUMN_VALUE_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2212;
const TRANSCRIPT_CHALLENGE_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2213;
const ADD_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2214;
const MULTIPLY_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2215;
const NEGATE_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2216;
const POWER_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2217;
const FROBENIUS_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x2218;
const APPLICATION_STATEMENT_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2220;
const PROTOCOL_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2221;
const SUITE_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2222;
const APPLICATION_SLOT_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2223;
const SAMPLER_OUTPUT_SOURCE_SCHEMA_IDENTIFIER: u16 = 0x2224;
const SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER: u16 = 0x2225;
const VALUE_LAYOUT_SCHEMA_IDENTIFIER: u16 = 0x2226;
const VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2227;
const BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2228;
const PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2229;
const ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER: u16 = 0x222a;
const ROOT_ENDPOINT_SCHEMA_IDENTIFIER: u16 = 0x222b;
const SCHEMA_VERSION: u16 = 1;

const MAXIMUM_FIELD_COUNT: usize = 8;
const MAXIMUM_FAMILY_COUNT: usize = 32;
const MAXIMUM_VARIANTS_PER_PLAN: usize = 64;
const MAXIMUM_VERIFIER_SOURCE_COUNT: usize = 4_096;
const MAXIMUM_PUBLIC_SAMPLER_COUNT: usize = 4_096;
const MAXIMUM_COLUMN_COUNT: usize = 4_096;
const MAXIMUM_TREE_COUNT: usize = 4_096;
const MAXIMUM_CONSTRAINT_COUNT: usize = 4_096;
const MAXIMUM_PROGRAM_INSTRUCTION_COUNT: usize = 4_096;
const MAXIMUM_OPENING_POINT_COUNT: usize = 4_096;
const MAXIMUM_OPENING_CLAIM_COUNT: usize = 4_096;
const MAXIMUM_MASK_COUNT: usize = 4_096;
const MAXIMUM_ROOT_EDGE_COUNT: usize = 4_096;
const MAXIMUM_SELECTOR_PATH_LENGTH: usize = 64;
const MAXIMUM_VALUE_SHAPE_RANK: usize = 16;
const MAXIMUM_ROLE_COORDINATE_COUNT: usize = 16;
const MAXIMUM_COMPLETE_TREE_COUNT: usize = u16::MAX as usize + 1;
const MAXIMUM_LOGICAL_SOURCE_ELEMENT_COUNT: u64 = 4_194_304;
const MAXIMUM_ZEROIFIER_COEFFICIENT_COUNT: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofProfileArtifactError {
    Canonical(CanonicalCodecError),
    WrongSchema,
    WrongVersion,
    WrongItemCount,
    WrongItemType,
    LimitExceeded,
    ArithmeticOverflow,
    InvalidValue,
    InvalidOrdering,
    DuplicateValue,
    UnresolvedIndex,
    TypeMismatch,
    IncompleteSemanticPlan,
}

impl From<CanonicalCodecError> for ProofProfileArtifactError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

type ArtifactResult<T> = Result<T, ProofProfileArtifactError>;

pub(crate) fn validate_proof_profile_set_bytes(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> ArtifactResult<Vec<u8>> {
    let artifact = ProofProfileSetArtifact::decode(bytes, limits)?;
    artifact.validate()?;
    let round_tripped_bytes = artifact.encode()?;
    if round_tripped_bytes != bytes {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    Ok(round_tripped_bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofProfileSetArtifact {
    pub(crate) proof_fields: Vec<ProofFieldProfileArtifact>,
    pub(crate) proof_families: Vec<ProofFamilyProfileArtifact>,
    pub(crate) relation_plans: Vec<RelationPlanArtifact>,
    pub(crate) root_compatibility_edges: Vec<RelationRootCompatibilityEdgeArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofFieldProfileArtifact {
    pub(crate) base_field_modulus: u64,
    pub(crate) maximum_two_adic_subgroup_generator: u64,
    pub(crate) monic_challenge_extension_polynomial_coefficients: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofFamilyProfileArtifact {
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) field_schedule: ProofFieldScheduleArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofFieldScheduleArtifact {
    pub(crate) proof_field_index: u16,
    pub(crate) evaluation_blowup_factor: u32,
    pub(crate) evaluation_coset_offset: u64,
    pub(crate) deep_point_count: u16,
    pub(crate) final_polynomial_degree_bound_exclusive: u32,
    pub(crate) unique_query_count: u32,
    pub(crate) nonnative_modular_identity_challenge_count: u16,
    pub(crate) maximum_fiat_shamir_candidate_draws_per_output: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanArtifact {
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) variants: Vec<RelationPlanVariantArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanVariantArtifact {
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) proof_privacy_mode: u16,
    pub(crate) trace_domain_size: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) ordered_nonnative_moduli: Vec<SuiteModulusReferenceArtifact>,
    pub(crate) ordered_verifier_sources: Vec<RelationVerifierSourceArtifact>,
    pub(crate) ordered_public_samplers: Vec<RelationPublicSamplerArtifact>,
    pub(crate) ordered_columns: Vec<RelationColumnArtifact>,
    pub(crate) ordered_trees: Vec<RelationTreeArtifact>,
    pub(crate) ordered_constraints: Vec<RelationConstraintArtifact>,
    pub(crate) ordered_opening_points: Vec<RelationOpeningPointArtifact>,
    pub(crate) ordered_opening_claims: Vec<RelationOpeningClaimArtifact>,
    pub(crate) ordered_masks: Vec<RelationMaskArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SuiteModulusReferenceArtifact {
    pub(crate) catalog: u16,
    pub(crate) modulus_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationVerifierSourceArtifact {
    ApplicationStatement {
        value_path: Vec<RelationSelectorPathStepArtifact>,
        value_layout: RelationValueLayoutArtifact,
    },
    Protocol {
        protocol_source_kind: u16,
        source_coordinates: Vec<u64>,
        statement_binding_path: Vec<RelationSelectorPathStepArtifact>,
        value_layout: RelationValueLayoutArtifact,
    },
    Suite {
        value_path: Vec<RelationSelectorPathStepArtifact>,
        value_layout: RelationValueLayoutArtifact,
    },
    ApplicationSlot {
        value_path: Vec<RelationSelectorPathStepArtifact>,
        value_layout: RelationValueLayoutArtifact,
    },
    SamplerOutput {
        public_sampler_ordinal: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationSelectorPathStepArtifact {
    pub(crate) step_kind: u16,
    pub(crate) argument: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationValueLayoutArtifact {
    pub(crate) element_kind: u16,
    pub(crate) residue_modulus: Option<SuiteModulusReferenceArtifact>,
    pub(crate) shape: Vec<u64>,
    pub(crate) embedding_kind: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPublicSamplerArtifact {
    pub(crate) seed_verifier_source_ordinal: u32,
    pub(crate) role_domain: String,
    pub(crate) canonical_role_coordinate_bytes: Vec<u8>,
    pub(crate) output_modulus: SuiteModulusReferenceArtifact,
    pub(crate) output_count: u64,
    pub(crate) output_verifier_source_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationColumnArtifact {
    pub(crate) origin: RelationColumnOriginArtifact,
    pub(crate) value_type: u16,
    pub(crate) source_degree_bound_exclusive: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationColumnOriginArtifact {
    VerifierSequence {
        verifier_source_ordinal: u32,
        first_logical_element_index: u64,
        logical_element_stride: u64,
    },
    BoundTree {
        expected_root_source_ordinal: u32,
    },
    Prover,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationTreeArtifact {
    ProofCreated {
        proof_tree_role: u16,
        ordered_column_ordinals: Vec<u32>,
    },
    BoundPublic {
        construction_kind: u16,
        expected_root_source_ordinal: u32,
        root_use: u16,
        ordered_column_ordinals: Vec<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationConstraintArtifact {
    pub(crate) constraint_role: u16,
    pub(crate) role_coordinates: Vec<u64>,
    pub(crate) numerator_postfix_expression: Vec<RelationExpressionInstructionArtifact>,
    pub(crate) zeroifier_postfix_expression: Vec<RelationExpressionInstructionArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationExpressionInstructionArtifact {
    Constant(u64),
    EvaluationVariable,
    ColumnValue {
        column_ordinal: u32,
        rotation_is_negative: u8,
        rotation_magnitude: u64,
    },
    TranscriptChallenge {
        challenge_role: u16,
        role_coordinates: Vec<u64>,
    },
    Add,
    Multiply,
    Negate,
    Power(u64),
    Frobenius(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationOpeningPointArtifact {
    pub(crate) deep_point_ordinal: u16,
    pub(crate) trace_rotation_is_negative: u8,
    pub(crate) trace_rotation_magnitude: u64,
    pub(crate) conjugate_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationOpeningClaimArtifact {
    pub(crate) source_class: u16,
    pub(crate) source_ordinal: u32,
    pub(crate) column_ordinal: Option<u32>,
    pub(crate) opening_point_ordinal: u32,
    pub(crate) source_degree_bound_exclusive: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationMaskArtifact {
    pub(crate) mask_purpose: u16,
    pub(crate) mask_kind: u16,
    pub(crate) target_class: u16,
    pub(crate) target_ordinal: u32,
    pub(crate) mask_degree_bound_exclusive: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationRootCompatibilityEdgeArtifact {
    pub(crate) producer_endpoint: RelationRootEndpointArtifact,
    pub(crate) consumer_endpoint: RelationRootEndpointArtifact,
    pub(crate) construction_kind: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationRootEndpointArtifact {
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) roster_position: Option<u16>,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) producer_sequence: Option<u64>,
    pub(crate) verifier_source_ordinal: u32,
}

impl ProofProfileSetArtifact {
    pub(crate) fn from_unlowered_relation_plan_catalog(
        catalog: &RelationPlanCatalog,
    ) -> ArtifactResult<Self> {
        let proof_field = ProofFieldProfileArtifact {
            base_field_modulus: COMMON_PROOF_PROFILE.base_field_modulus,
            maximum_two_adic_subgroup_generator: COMMON_PROOF_PROFILE
                .maximum_two_adic_subgroup_generator,
            monic_challenge_extension_polynomial_coefficients: COMMON_PROOF_PROFILE
                .monic_challenge_extension_polynomial_coefficients
                .to_vec(),
        };
        let field_schedule = ProofFieldScheduleArtifact {
            proof_field_index: 0,
            evaluation_blowup_factor: COMMON_PROOF_PROFILE.evaluation_blowup_factor,
            evaluation_coset_offset: COMMON_PROOF_PROFILE.evaluation_coset_offset,
            deep_point_count: COMMON_PROOF_PROFILE.deep_point_count,
            final_polynomial_degree_bound_exclusive: COMMON_PROOF_PROFILE
                .final_polynomial_degree_bound_exclusive,
            unique_query_count: COMMON_PROOF_PROFILE.unique_query_count,
            nonnative_modular_identity_challenge_count: COMMON_PROOF_PROFILE
                .nonnative_modular_identity_challenge_count,
            maximum_fiat_shamir_candidate_draws_per_output: COMMON_PROOF_PROFILE
                .maximum_fiat_shamir_candidate_draws_per_output,
        };
        let proof_families = ProofFamily::ALL
            .into_iter()
            .map(|family| ProofFamilyProfileArtifact {
                application_statement_schema_identifier: family.schema_identifier(),
                field_schedule: field_schedule.clone(),
            })
            .collect();
        let relation_plans = catalog
            .plans
            .iter()
            .map(|plan| {
                Ok(RelationPlanArtifact {
                    application_statement_schema_identifier: plan.family.schema_identifier(),
                    variants: plan
                        .variants
                        .iter()
                        .map(RelationPlanVariantArtifact::from_unlowered_variant)
                        .collect::<ArtifactResult<Vec<_>>>()?,
                })
            })
            .collect::<ArtifactResult<Vec<_>>>()?;
        let root_compatibility_edges = catalog
            .root_compatibility_edges
            .iter()
            .map(|edge| RelationRootCompatibilityEdgeArtifact {
                producer_endpoint: RelationRootEndpointArtifact {
                    application_statement_schema_identifier: edge
                        .producer_family
                        .schema_identifier(),
                    roster_position: None,
                    schedule_position: None,
                    top_count: None,
                    producer_sequence: None,
                    verifier_source_ordinal: u32::from(edge.producer_tree_ordinal),
                },
                consumer_endpoint: RelationRootEndpointArtifact {
                    application_statement_schema_identifier: edge
                        .consumer_family
                        .schema_identifier(),
                    roster_position: None,
                    schedule_position: None,
                    top_count: None,
                    producer_sequence: None,
                    verifier_source_ordinal: u32::from(edge.consumer_tree_ordinal),
                },
                construction_kind: match edge.construction_kind {
                    RootConstructionKind::CommittedMaterial => 1,
                    RootConstructionKind::SetupPolynomial => 2,
                },
            })
            .collect();
        Ok(Self {
            proof_fields: vec![proof_field],
            proof_families,
            relation_plans,
            root_compatibility_edges,
        })
    }

    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_tuple(&tuple, PROOF_PROFILE_SET_SCHEMA_IDENTIFIER, 4)?;
        Ok(Self {
            proof_fields: read_nested_tuple_list(&tuple.items[0], limits, MAXIMUM_FIELD_COUNT)?
                .iter()
                .map(ProofFieldProfileArtifact::from_tuple)
                .collect::<ArtifactResult<Vec<_>>>()?,
            proof_families: read_nested_tuple_list(&tuple.items[1], limits, MAXIMUM_FAMILY_COUNT)?
                .iter()
                .map(|value| ProofFamilyProfileArtifact::from_tuple(value, limits))
                .collect::<ArtifactResult<Vec<_>>>()?,
            relation_plans: read_nested_tuple_list(&tuple.items[2], limits, MAXIMUM_FAMILY_COUNT)?
                .iter()
                .map(|value| RelationPlanArtifact::from_tuple(value, limits))
                .collect::<ArtifactResult<Vec<_>>>()?,
            root_compatibility_edges: read_nested_tuple_list(
                &tuple.items[3],
                limits,
                MAXIMUM_ROOT_EDGE_COUNT,
            )?
            .iter()
            .map(|value| RelationRootCompatibilityEdgeArtifact::from_tuple(value, limits))
            .collect::<ArtifactResult<Vec<_>>>()?,
        })
    }

    pub(crate) fn encode(&self) -> ArtifactResult<Vec<u8>> {
        let fields = self
            .proof_fields
            .iter()
            .map(ProofFieldProfileArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let families = self
            .proof_families
            .iter()
            .map(ProofFamilyProfileArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let plans = self
            .relation_plans
            .iter()
            .map(RelationPlanArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let edges = self
            .root_compatibility_edges
            .iter()
            .map(RelationRootCompatibilityEdgeArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            PROOF_PROFILE_SET_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                nested_tuple_list(&fields)?,
                nested_tuple_list(&families)?,
                nested_tuple_list(&plans)?,
                nested_tuple_list(&edges)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn validate(&self) -> ArtifactResult<()> {
        if self.proof_fields.is_empty() || self.proof_fields.len() > MAXIMUM_FIELD_COUNT {
            return Err(ProofProfileArtifactError::LimitExceeded);
        }
        for field in &self.proof_fields {
            field.validate()?;
        }

        let expected_family_identifiers = ProofFamily::ALL
            .into_iter()
            .map(ProofFamily::schema_identifier)
            .collect::<BTreeSet<_>>();
        let family_identifiers = self
            .proof_families
            .iter()
            .map(|family| family.application_statement_schema_identifier)
            .collect::<Vec<_>>();
        let plan_identifiers = self
            .relation_plans
            .iter()
            .map(|plan| plan.application_statement_schema_identifier)
            .collect::<Vec<_>>();
        require_strictly_increasing(&family_identifiers)?;
        require_strictly_increasing(&plan_identifiers)?;
        if family_identifiers.iter().copied().collect::<BTreeSet<_>>()
            != expected_family_identifiers
            || plan_identifiers != family_identifiers
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }

        let families = self
            .proof_families
            .iter()
            .map(|family| (family.application_statement_schema_identifier, family))
            .collect::<BTreeMap<_, _>>();
        let mut globally_assigned_mask_purposes = BTreeSet::new();
        for plan in &self.relation_plans {
            let family_profile = families
                .get(&plan.application_statement_schema_identifier)
                .ok_or(ProofProfileArtifactError::InvalidValue)?;
            family_profile.validate(&self.proof_fields)?;
            plan.validate(
                family_profile,
                &self.proof_fields,
                &mut globally_assigned_mask_purposes,
            )?;
        }
        self.validate_root_compatibility_edges()?;
        Ok(())
    }

    fn validate_root_compatibility_edges(&self) -> ArtifactResult<()> {
        let encoded_edges = self
            .root_compatibility_edges
            .iter()
            .map(RelationRootCompatibilityEdgeArtifact::to_tuple)
            .map(|result| result.and_then(|tuple| Ok(tuple.encode()?)))
            .collect::<ArtifactResult<Vec<_>>>()?;
        require_strictly_increasing(&encoded_edges)?;
        for edge in &self.root_compatibility_edges {
            if !matches!(edge.construction_kind, 1 | 2) {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            self.validate_root_endpoint(&edge.producer_endpoint, 2, edge.construction_kind)?;
            self.validate_root_endpoint(&edge.consumer_endpoint, 1, edge.construction_kind)?;
        }
        Ok(())
    }

    fn validate_root_endpoint(
        &self,
        endpoint: &RelationRootEndpointArtifact,
        expected_root_use: u16,
        expected_construction_kind: u16,
    ) -> ArtifactResult<()> {
        let family =
            ProofFamily::from_schema_identifier(endpoint.application_statement_schema_identifier)
                .ok_or(ProofProfileArtifactError::InvalidValue)?;
        validate_endpoint_coordinate_presence(family, endpoint)?;
        let plan = self
            .relation_plans
            .iter()
            .find(|plan| {
                plan.application_statement_schema_identifier
                    == endpoint.application_statement_schema_identifier
            })
            .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
        let variant = plan
            .variants
            .iter()
            .find(|variant| {
                variant.schedule_position == endpoint.schedule_position
                    && variant.top_count == endpoint.top_count
            })
            .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
        let source_index = usize::try_from(endpoint.verifier_source_ordinal)
            .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
        let source = variant
            .ordered_verifier_sources
            .get(source_index)
            .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
        let layout = source.layout(&variant.ordered_public_samplers)?;
        if layout.element_kind != 1 || !layout.shape.is_empty() {
            return Err(ProofProfileArtifactError::TypeMismatch);
        }
        let matching_tree_count = variant
            .ordered_trees
            .iter()
            .filter(|tree| {
                matches!(
                    tree,
                    RelationTreeArtifact::BoundPublic {
                        construction_kind,
                        expected_root_source_ordinal,
                        root_use,
                        ..
                    } if *construction_kind == expected_construction_kind
                        && *expected_root_source_ordinal == endpoint.verifier_source_ordinal
                        && *root_use == expected_root_use
                )
            })
            .count();
        if matching_tree_count != 1 {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        Ok(())
    }
}

impl RelationPlanVariantArtifact {
    fn from_unlowered_variant(
        variant: &super::relation_plan::RelationPlanVariant,
    ) -> ArtifactResult<Self> {
        let (schedule_position, top_count) = match variant.selector {
            RelationPlanVariantSelector::Unscheduled => (None, None),
            RelationPlanVariantSelector::SchedulePosition(position) => (Some(position), None),
            RelationPlanVariantSelector::TopCount(count) => (None, Some(count)),
        };
        let mut ordered_nonnative_moduli = variant
            .ordered_nonnative_moduli
            .iter()
            .map(|certificate| suite_modulus_reference(certificate.modulus))
            .collect::<ArtifactResult<Vec<_>>>()?;
        ordered_nonnative_moduli.sort();
        let ordered_columns = variant
            .ordered_columns
            .iter()
            .enumerate()
            .map(|(column_ordinal, column)| {
                Ok(RelationColumnArtifact {
                    origin: match column.source {
                        RelationColumnSource::Verifier => {
                            RelationColumnOriginArtifact::VerifierSequence {
                                verifier_source_ordinal: u32::try_from(column_ordinal)
                                    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
                                first_logical_element_index: 0,
                                logical_element_stride: 1,
                            }
                        }
                        RelationColumnSource::Prover => RelationColumnOriginArtifact::Prover,
                    },
                    value_type: 1,
                    source_degree_bound_exclusive: column.degree_bound_exclusive,
                })
            })
            .collect::<ArtifactResult<Vec<_>>>()?;
        let ordered_trees = variant
            .ordered_trees
            .iter()
            .filter(|tree| {
                matches!(
                    tree.role,
                    ProofTreeRole::BoundPublicInput
                        | ProofTreeRole::BoundPublicOutput
                        | ProofTreeRole::Witness
                )
            })
            .map(|tree| {
                Ok(match tree.role {
                    ProofTreeRole::BoundPublicInput | ProofTreeRole::BoundPublicOutput => {
                        RelationTreeArtifact::BoundPublic {
                            construction_kind: 2,
                            expected_root_source_ordinal: u32::from(tree.ordinal),
                            root_use: if tree.role == ProofTreeRole::BoundPublicInput {
                                1
                            } else {
                                2
                            },
                            ordered_column_ordinals: columns_for_tree(tree.role, variant)?,
                        }
                    }
                    ProofTreeRole::Witness => RelationTreeArtifact::ProofCreated {
                        proof_tree_role: 2,
                        ordered_column_ordinals: columns_for_tree(tree.role, variant)?,
                    },
                    ProofTreeRole::QuotientComponent | ProofTreeRole::OpeningBatchMask => {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                })
            })
            .collect::<ArtifactResult<Vec<_>>>()?;
        let ordered_constraints = variant
            .ordered_constraints
            .iter()
            .map(|constraint| {
                Ok(RelationConstraintArtifact {
                    constraint_role: constraint.kind as u16 + 1,
                    role_coordinates: vec![constraint.normalized_degree_bound_exclusive],
                    // The coarse catalog has not yet lowered the owning semantic
                    // numerator. Keep a typed nonempty program so canonical
                    // parsing is deterministic; semantic validation refuses the
                    // candidate before this can authorize acceptance.
                    numerator_postfix_expression: vec![
                        RelationExpressionInstructionArtifact::EvaluationVariable,
                    ],
                    zeroifier_postfix_expression: unlowered_zeroifier_program(
                        constraint.zeroifier,
                        variant.trace_domain_size,
                    )?,
                })
            })
            .collect::<ArtifactResult<Vec<_>>>()?;
        let ordered_opening_points = (0..COMMON_PROOF_PROFILE.deep_point_count)
            .map(|deep_point_ordinal| RelationOpeningPointArtifact {
                deep_point_ordinal,
                trace_rotation_is_negative: 0,
                trace_rotation_magnitude: 0,
                conjugate_index: 0,
            })
            .collect::<Vec<_>>();
        let ordered_opening_claims = variant
            .ordered_opening_claims
            .iter()
            .enumerate()
            .map(|(claim_ordinal, claim)| {
                let tree = variant
                    .ordered_trees
                    .iter()
                    .find(|tree| tree.ordinal == claim.tree_ordinal)
                    .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                let (source_class, column_ordinal) = match tree.role {
                    ProofTreeRole::BoundPublicInput
                    | ProofTreeRole::BoundPublicOutput
                    | ProofTreeRole::Witness => (1, Some(0)),
                    ProofTreeRole::QuotientComponent => (2, None),
                    ProofTreeRole::OpeningBatchMask => (3, None),
                };
                Ok(RelationOpeningClaimArtifact {
                    source_class,
                    source_ordinal: u32::from(claim.tree_ordinal),
                    column_ordinal,
                    opening_point_ordinal: u32::try_from(
                        claim_ordinal % usize::from(COMMON_PROOF_PROFILE.deep_point_count),
                    )
                    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
                    source_degree_bound_exclusive: claim.source_degree_bound_exclusive,
                })
            })
            .collect::<ArtifactResult<Vec<_>>>()?;
        let ordered_masks = variant
            .ordered_masks
            .iter()
            .enumerate()
            .map(|(mask_ordinal, mask)| RelationMaskArtifact {
                mask_purpose: mask.purpose,
                mask_kind: if mask_ordinal == 0 { 1 } else { 3 },
                target_class: if mask_ordinal == 0 { 1 } else { 3 },
                target_ordinal: 0,
                mask_degree_bound_exclusive: mask.degree_bound_exclusive,
            })
            .collect();
        Ok(Self {
            schedule_position,
            top_count,
            proof_privacy_mode: variant.privacy_mode as u16,
            trace_domain_size: variant.trace_domain_size,
            evaluation_domain_size: variant.evaluation_domain_size,
            opening_degree_bound_exclusive: variant
                .degree_certificate
                .opening_degree_bound_exclusive,
            ordered_nonnative_moduli,
            ordered_verifier_sources: vec![],
            ordered_public_samplers: vec![],
            ordered_columns,
            ordered_trees,
            ordered_constraints,
            ordered_opening_points,
            ordered_opening_claims,
            ordered_masks,
        })
    }
}

fn suite_modulus_reference(modulus: u64) -> ArtifactResult<SuiteModulusReferenceArtifact> {
    if let Some(index) = DATA_PRIMES
        .iter()
        .position(|candidate| *candidate == modulus)
    {
        return Ok(SuiteModulusReferenceArtifact {
            catalog: 1,
            modulus_index: u16::try_from(index)
                .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
        });
    }
    if modulus == SPECIAL_PRIME {
        return Ok(SuiteModulusReferenceArtifact {
            catalog: 2,
            modulus_index: 0,
        });
    }
    if modulus == PLAINTEXT_MODULUS {
        return Ok(SuiteModulusReferenceArtifact {
            catalog: 3,
            modulus_index: 0,
        });
    }
    Err(ProofProfileArtifactError::UnresolvedIndex)
}

fn columns_for_tree(
    role: ProofTreeRole,
    variant: &super::relation_plan::RelationPlanVariant,
) -> ArtifactResult<Vec<u32>> {
    variant
        .ordered_columns
        .iter()
        .enumerate()
        .filter_map(|(column_ordinal, column)| {
            let selected = match role {
                ProofTreeRole::Witness => column.source == RelationColumnSource::Prover,
                ProofTreeRole::BoundPublicInput | ProofTreeRole::BoundPublicOutput => {
                    column.source == RelationColumnSource::Verifier
                }
                _ => false,
            };
            selected.then(|| {
                u32::try_from(column_ordinal)
                    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)
            })
        })
        .collect()
}

fn unlowered_zeroifier_program(
    zeroifier: Zeroifier,
    trace_domain_size: u64,
) -> ArtifactResult<Vec<RelationExpressionInstructionArtifact>> {
    let root = match zeroifier {
        Zeroifier::Trace => 1,
        Zeroifier::BoundaryRow(row) => {
            let maximum_order = 1_u64 << (GOLDILOCKS_MODULUS - 1).trailing_zeros();
            let trace_generator = Goldilocks::from_canonical_u64(
                COMMON_PROOF_PROFILE.maximum_two_adic_subgroup_generator,
            )
            .ok_or(ProofProfileArtifactError::InvalidValue)?
            .pow_u64(maximum_order / trace_domain_size);
            u64::from_le_bytes(trace_generator.pow_u64(u64::from(row)).canonical_bytes())
        }
    };
    let mut program = vec![RelationExpressionInstructionArtifact::EvaluationVariable];
    if zeroifier == Zeroifier::Trace {
        program.push(RelationExpressionInstructionArtifact::Power(
            trace_domain_size,
        ));
    }
    program.extend([
        RelationExpressionInstructionArtifact::Constant(
            GOLDILOCKS_MODULUS
                .checked_sub(root)
                .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?,
        ),
        RelationExpressionInstructionArtifact::Add,
    ]);
    Ok(program)
}

impl ProofFieldProfileArtifact {
    fn validate(&self) -> ArtifactResult<()> {
        if !is_prime_u64(self.base_field_modulus)
            || self.base_field_modulus != GOLDILOCKS_MODULUS
            || self.maximum_two_adic_subgroup_generator
                != COMMON_PROOF_PROFILE.maximum_two_adic_subgroup_generator
            || self.monic_challenge_extension_polynomial_coefficients
                != COMMON_PROOF_PROFILE.monic_challenge_extension_polynomial_coefficients
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        if self
            .monic_challenge_extension_polynomial_coefficients
            .iter()
            .any(|coefficient| *coefficient >= self.base_field_modulus)
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        let two_adic_order_exponent = (self.base_field_modulus - 1).trailing_zeros();
        let exact_order = 1_u64
            .checked_shl(two_adic_order_exponent)
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        if modular_power(
            self.maximum_two_adic_subgroup_generator,
            exact_order,
            self.base_field_modulus,
        ) != 1
            || modular_power(
                self.maximum_two_adic_subgroup_generator,
                exact_order / 2,
                self.base_field_modulus,
            ) == 1
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        Ok(())
    }
}

impl ProofFamilyProfileArtifact {
    fn validate(&self, proof_fields: &[ProofFieldProfileArtifact]) -> ArtifactResult<()> {
        if ProofFamily::from_schema_identifier(self.application_statement_schema_identifier)
            .is_none()
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        let field_index = usize::from(self.field_schedule.proof_field_index);
        let field = proof_fields
            .get(field_index)
            .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
        self.field_schedule.validate(field)
    }
}

impl ProofFieldScheduleArtifact {
    fn validate(&self, field: &ProofFieldProfileArtifact) -> ArtifactResult<()> {
        if self.evaluation_blowup_factor != COMMON_PROOF_PROFILE.evaluation_blowup_factor
            || self.evaluation_coset_offset != COMMON_PROOF_PROFILE.evaluation_coset_offset
            || self.deep_point_count != COMMON_PROOF_PROFILE.deep_point_count
            || self.final_polynomial_degree_bound_exclusive
                != COMMON_PROOF_PROFILE.final_polynomial_degree_bound_exclusive
            || self.unique_query_count != COMMON_PROOF_PROFILE.unique_query_count
            || self.nonnative_modular_identity_challenge_count
                != COMMON_PROOF_PROFILE.nonnative_modular_identity_challenge_count
            || self.maximum_fiat_shamir_candidate_draws_per_output
                != COMMON_PROOF_PROFILE.maximum_fiat_shamir_candidate_draws_per_output
            || !self.evaluation_blowup_factor.is_power_of_two()
            || self.evaluation_coset_offset == 0
            || self.evaluation_coset_offset >= field.base_field_modulus
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        Ok(())
    }
}

impl RelationPlanArtifact {
    fn validate(
        &self,
        family_profile: &ProofFamilyProfileArtifact,
        proof_fields: &[ProofFieldProfileArtifact],
        globally_assigned_mask_purposes: &mut BTreeSet<u16>,
    ) -> ArtifactResult<()> {
        let family =
            ProofFamily::from_schema_identifier(self.application_statement_schema_identifier)
                .ok_or(ProofProfileArtifactError::InvalidValue)?;
        if self.variants.is_empty() || self.variants.len() > MAXIMUM_VARIANTS_PER_PLAN {
            return Err(ProofProfileArtifactError::LimitExceeded);
        }
        validate_variant_catalog(family, &self.variants)?;
        let field = proof_fields
            .get(usize::from(family_profile.field_schedule.proof_field_index))
            .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
        for variant in &self.variants {
            variant.validate(
                family,
                &family_profile.field_schedule,
                field,
                globally_assigned_mask_purposes,
            )?;
        }
        Ok(())
    }
}

fn validate_variant_catalog(
    family: ProofFamily,
    variants: &[RelationPlanVariantArtifact],
) -> ArtifactResult<()> {
    match family {
        ProofFamily::RelinearizationRoundOne
        | ProofFamily::RelinearizationRoundOneAggregate
        | ProofFamily::RelinearizationRoundTwo
        | ProofFamily::GaloisKeyShare => {
            for (expected_position, variant) in variants.iter().enumerate() {
                if variant.schedule_position
                    != Some(
                        u32::try_from(expected_position)
                            .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
                    )
                    || variant.top_count.is_some()
                {
                    return Err(ProofProfileArtifactError::InvalidOrdering);
                }
            }
        }
        ProofFamily::EvaluatorKeyAggregate => {
            if variants.len() != 20 {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            for (variant_index, variant) in variants.iter().enumerate() {
                if variant.schedule_position.is_some()
                    || variant.top_count
                        != Some(
                            u16::try_from(variant_index + 1)
                                .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
                        )
                {
                    return Err(ProofProfileArtifactError::InvalidOrdering);
                }
            }
        }
        _ => {
            if variants.len() != 1
                || variants[0].schedule_position.is_some()
                || variants[0].top_count.is_some()
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
        }
    }
    Ok(())
}

impl RelationPlanVariantArtifact {
    fn validate(
        &self,
        family: ProofFamily,
        schedule: &ProofFieldScheduleArtifact,
        field: &ProofFieldProfileArtifact,
        globally_assigned_mask_purposes: &mut BTreeSet<u16>,
    ) -> ArtifactResult<()> {
        if self.proof_privacy_mode != family.privacy_mode() as u16
            || !self.trace_domain_size.is_power_of_two()
            || !self.evaluation_domain_size.is_power_of_two()
            || self.trace_domain_size == 0
            || self.opening_degree_bound_exclusive <= 1
            || !self
                .evaluation_domain_size
                .is_multiple_of(self.trace_domain_size)
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        let rounded_opening_bound = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        let expected_evaluation_domain_size = rounded_opening_bound
            .checked_mul(u64::from(schedule.evaluation_blowup_factor))
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        if self.evaluation_domain_size != expected_evaluation_domain_size
            || !(field.base_field_modulus - 1).is_multiple_of(self.evaluation_domain_size)
            || modular_power(
                schedule.evaluation_coset_offset,
                self.trace_domain_size,
                field.base_field_modulus,
            ) == 1
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        require_strictly_increasing(&self.ordered_nonnative_moduli)?;
        if self.ordered_verifier_sources.is_empty()
            || self.ordered_columns.is_empty()
            || self.ordered_trees.is_empty()
            || self.ordered_constraints.is_empty()
            || self.ordered_opening_points.is_empty()
            || self.ordered_opening_claims.is_empty()
        {
            return Err(ProofProfileArtifactError::IncompleteSemanticPlan);
        }
        self.validate_verifier_sources(family, field)?;
        self.validate_public_samplers(family, field)?;
        self.validate_columns_and_trees(field)?;
        let quotient_parameters = self.validate_constraints(schedule, field)?;
        self.validate_opening_points(schedule, field)?;
        self.validate_opening_claims(&quotient_parameters)?;
        self.validate_masks(
            family,
            &quotient_parameters,
            globally_assigned_mask_purposes,
        )?;
        self.validate_complete_tree_catalog(&quotient_parameters, schedule)?;
        Ok(())
    }

    fn validate_verifier_sources(
        &self,
        family: ProofFamily,
        field: &ProofFieldProfileArtifact,
    ) -> ArtifactResult<()> {
        let encoded_sources = self
            .ordered_verifier_sources
            .iter()
            .map(RelationVerifierSourceArtifact::to_tuple)
            .map(|result| result.and_then(|tuple| Ok(tuple.encode()?)))
            .collect::<ArtifactResult<Vec<_>>>()?;
        require_strictly_increasing(&encoded_sources)?;
        for source in &self.ordered_verifier_sources {
            match source {
                RelationVerifierSourceArtifact::ApplicationStatement {
                    value_path,
                    value_layout,
                } => {
                    validate_selector_path(value_path, SelectorPathRoot::ApplicationStatement)?;
                    value_layout.validate(field)?;
                }
                RelationVerifierSourceArtifact::Protocol {
                    protocol_source_kind,
                    source_coordinates,
                    statement_binding_path,
                    value_layout,
                } => validate_protocol_source(
                    family,
                    self.schedule_position,
                    *protocol_source_kind,
                    source_coordinates,
                    statement_binding_path,
                    value_layout,
                    field,
                )?,
                RelationVerifierSourceArtifact::Suite {
                    value_path,
                    value_layout,
                } => {
                    validate_selector_path(value_path, SelectorPathRoot::Suite)?;
                    value_layout.validate(field)?;
                }
                RelationVerifierSourceArtifact::ApplicationSlot {
                    value_path,
                    value_layout,
                } => {
                    validate_selector_path(value_path, SelectorPathRoot::ApplicationSlot)?;
                    value_layout.validate(field)?;
                }
                RelationVerifierSourceArtifact::SamplerOutput {
                    public_sampler_ordinal,
                } => {
                    if usize::try_from(*public_sampler_ordinal)
                        .ok()
                        .is_none_or(|index| index >= self.ordered_public_samplers.len())
                    {
                        return Err(ProofProfileArtifactError::UnresolvedIndex);
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_public_samplers(
        &self,
        family: ProofFamily,
        field: &ProofFieldProfileArtifact,
    ) -> ArtifactResult<()> {
        let expected_domain_prefix = format!(
            "sealed-lattice/proof/{:04x}/public-sampler/",
            family.schema_identifier()
        );
        let mut preceding_key: Option<(&str, &[u8])> = None;
        let mut sampler_output_sources = BTreeMap::new();
        for (source_ordinal, source) in self.ordered_verifier_sources.iter().enumerate() {
            if let RelationVerifierSourceArtifact::SamplerOutput {
                public_sampler_ordinal,
            } = source
                && sampler_output_sources
                    .insert(
                        *public_sampler_ordinal,
                        u32::try_from(source_ordinal)
                            .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
                    )
                    .is_some()
            {
                return Err(ProofProfileArtifactError::DuplicateValue);
            }
        }
        for (sampler_ordinal, sampler) in self.ordered_public_samplers.iter().enumerate() {
            let current_key = (
                sampler.role_domain.as_str(),
                sampler.canonical_role_coordinate_bytes.as_slice(),
            );
            if preceding_key.is_some_and(|preceding| preceding >= current_key) {
                return Err(ProofProfileArtifactError::InvalidOrdering);
            }
            preceding_key = Some(current_key);
            if !sampler.role_domain.starts_with(&expected_domain_prefix)
                || !sampler.role_domain.ends_with("/v1")
                || sampler.role_domain.len() <= expected_domain_prefix.len() + 3
                || sampler.output_count == 0
                || sampler.output_count > MAXIMUM_LOGICAL_SOURCE_ELEMENT_COUNT
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            let seed_index = usize::try_from(sampler.seed_verifier_source_ordinal)
                .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
            let seed_source = self
                .ordered_verifier_sources
                .get(seed_index)
                .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
            if matches!(
                seed_source,
                RelationVerifierSourceArtifact::SamplerOutput { .. }
            ) {
                return Err(ProofProfileArtifactError::TypeMismatch);
            }
            let seed_layout = seed_source.layout(&self.ordered_public_samplers)?;
            if seed_layout.element_kind != 1 || !seed_layout.shape.is_empty() {
                return Err(ProofProfileArtifactError::TypeMismatch);
            }
            let expected_source_ordinal = sampler_output_sources
                .get(
                    &u32::try_from(sampler_ordinal)
                        .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
                )
                .copied()
                .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
            if sampler.output_verifier_source_ordinal != expected_source_ordinal {
                return Err(ProofProfileArtifactError::UnresolvedIndex);
            }
            let modulus = resolve_suite_modulus(&sampler.output_modulus, field)?;
            if modulus >= field.base_field_modulus || sampler.output_modulus.catalog == 4 {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
        }
        if sampler_output_sources.len() != self.ordered_public_samplers.len() {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        Ok(())
    }

    fn validate_columns_and_trees(&self, field: &ProofFieldProfileArtifact) -> ArtifactResult<()> {
        let mut consumed_source_elements = self
            .ordered_verifier_sources
            .iter()
            .map(|source| {
                let layout = source.layout(&self.ordered_public_samplers)?;
                let count = layout.logical_element_count()?;
                if count > MAXIMUM_LOGICAL_SOURCE_ELEMENT_COUNT {
                    return Err(ProofProfileArtifactError::LimitExceeded);
                }
                let count = usize::try_from(count)
                    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                Ok(vec![false; count])
            })
            .collect::<ArtifactResult<Vec<_>>>()?;
        let mut source_is_consumed = vec![false; self.ordered_verifier_sources.len()];
        for column in &self.ordered_columns {
            if !matches!(column.value_type, 1 | 2)
                || column.source_degree_bound_exclusive == 0
                || column.source_degree_bound_exclusive > self.opening_degree_bound_exclusive
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            match &column.origin {
                RelationColumnOriginArtifact::VerifierSequence {
                    verifier_source_ordinal,
                    first_logical_element_index,
                    logical_element_stride,
                } => {
                    let source_index = usize::try_from(*verifier_source_ordinal)
                        .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                    let source = self
                        .ordered_verifier_sources
                        .get(source_index)
                        .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                    let layout = source.layout(&self.ordered_public_samplers)?;
                    layout.validate(field)?;
                    if (column.value_type == 1 && !matches!(layout.element_kind, 2 | 4))
                        || (column.value_type == 2 && layout.element_kind != 3)
                    {
                        return Err(ProofProfileArtifactError::TypeMismatch);
                    }
                    let source_consumption = consumed_source_elements
                        .get_mut(source_index)
                        .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                    for row in 0..self.trace_domain_size {
                        let logical_index = first_logical_element_index
                            .checked_add(
                                row.checked_mul(*logical_element_stride)
                                    .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?,
                            )
                            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
                        let logical_index = usize::try_from(logical_index)
                            .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                        let consumed = source_consumption
                            .get_mut(logical_index)
                            .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                        if *consumed {
                            return Err(ProofProfileArtifactError::DuplicateValue);
                        }
                        *consumed = true;
                    }
                    if *logical_element_stride == 0 && source_consumption.len() != 1 {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                    source_is_consumed[source_index] = true;
                }
                RelationColumnOriginArtifact::BoundTree {
                    expected_root_source_ordinal,
                } => {
                    if column.value_type != 1 {
                        return Err(ProofProfileArtifactError::TypeMismatch);
                    }
                    let source_index = usize::try_from(*expected_root_source_ordinal)
                        .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                    let source = self
                        .ordered_verifier_sources
                        .get(source_index)
                        .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                    let layout = source.layout(&self.ordered_public_samplers)?;
                    if layout.element_kind != 1 || !layout.shape.is_empty() {
                        return Err(ProofProfileArtifactError::TypeMismatch);
                    }
                    source_is_consumed[source_index] = true;
                }
                RelationColumnOriginArtifact::Prover => {
                    if self.proof_privacy_mode != ProofPrivacyMode::SecretBearing as u16 {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                }
            }
        }
        for (source_index, source) in self.ordered_verifier_sources.iter().enumerate() {
            if matches!(source, RelationVerifierSourceArtifact::SamplerOutput { .. })
                && consumed_source_elements[source_index]
                    .iter()
                    .any(|consumed| !consumed)
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            if !source_is_consumed[source_index]
                && !self.ordered_public_samplers.iter().any(|sampler| {
                    usize::try_from(sampler.seed_verifier_source_ordinal).ok() == Some(source_index)
                })
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
        }

        let mut column_membership = vec![0_u8; self.ordered_columns.len()];
        for tree in &self.ordered_trees {
            if tree.ordered_column_ordinals().is_empty() {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            let mut preceding_column = None;
            for column_ordinal in tree.ordered_column_ordinals() {
                if preceding_column.is_some_and(|preceding| preceding >= *column_ordinal) {
                    return Err(ProofProfileArtifactError::InvalidOrdering);
                }
                preceding_column = Some(*column_ordinal);
                let column_index = usize::try_from(*column_ordinal)
                    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                let membership = column_membership
                    .get_mut(column_index)
                    .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                *membership = membership
                    .checked_add(1)
                    .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
                let column = &self.ordered_columns[column_index];
                match tree {
                    RelationTreeArtifact::ProofCreated {
                        proof_tree_role, ..
                    } => {
                        if !matches!(proof_tree_role, 1 | 2)
                            || matches!(
                                column.origin,
                                RelationColumnOriginArtifact::BoundTree { .. }
                            )
                        {
                            return Err(ProofProfileArtifactError::TypeMismatch);
                        }
                    }
                    RelationTreeArtifact::BoundPublic {
                        construction_kind,
                        expected_root_source_ordinal,
                        root_use,
                        ..
                    } => {
                        if !matches!(construction_kind, 1 | 2) || !matches!(root_use, 1 | 2) {
                            return Err(ProofProfileArtifactError::InvalidValue);
                        }
                        if !matches!(
                            column.origin,
                            RelationColumnOriginArtifact::BoundTree {
                                expected_root_source_ordinal: source
                            } if source == *expected_root_source_ordinal
                        ) {
                            return Err(ProofProfileArtifactError::TypeMismatch);
                        }
                    }
                }
            }
        }
        if column_membership.iter().any(|membership| *membership != 1) {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        if self.proof_privacy_mode == ProofPrivacyMode::PublicOnly as u16
            && self
                .ordered_columns
                .iter()
                .any(|column| matches!(column.origin, RelationColumnOriginArtifact::Prover))
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        Ok(())
    }

    fn validate_constraints(
        &self,
        schedule: &ProofFieldScheduleArtifact,
        field: &ProofFieldProfileArtifact,
    ) -> ArtifactResult<QuotientParameters> {
        let mut constraint_keys = BTreeSet::new();
        let mut maximum_quotient_degree = 0_u64;
        let mut referenced_columns = BTreeSet::new();
        for constraint in &self.ordered_constraints {
            if !constraint_keys.insert((
                constraint.constraint_role,
                constraint.role_coordinates.clone(),
            )) {
                return Err(ProofProfileArtifactError::DuplicateValue);
            }
            let numerator = validate_numerator_program(
                &constraint.numerator_postfix_expression,
                &self.ordered_columns,
                self.trace_domain_size,
                self.ordered_nonnative_moduli.len(),
                schedule,
                field,
            )?;
            referenced_columns.extend(numerator.referenced_columns);
            let zeroifier = compile_zeroifier_program(
                &constraint.zeroifier_postfix_expression,
                self.evaluation_domain_size,
                schedule,
                field,
            )?;
            let quotient_degree = numerator
                .degree
                .checked_sub(zeroifier.degree)
                .ok_or(ProofProfileArtifactError::InvalidValue)?;
            maximum_quotient_degree = maximum_quotient_degree.max(quotient_degree);
        }
        if referenced_columns.is_empty() {
            return Err(ProofProfileArtifactError::IncompleteSemanticPlan);
        }

        let trace_mask_degree_bound =
            if self.proof_privacy_mode == ProofPrivacyMode::SecretBearing as u16 {
                let trace_mask_bounds = self
                    .ordered_masks
                    .iter()
                    .filter(|mask| mask.mask_kind == 1 && mask.target_class == 1)
                    .map(|mask| mask.mask_degree_bound_exclusive)
                    .collect::<BTreeSet<_>>();
                if trace_mask_bounds.len() != 1 {
                    return Err(ProofProfileArtifactError::InvalidValue);
                }
                *trace_mask_bounds
                    .first()
                    .ok_or(ProofProfileArtifactError::InvalidValue)?
            } else {
                0
            };
        let quotient_component_count = derive_quotient_component_count(
            maximum_quotient_degree,
            self.trace_domain_size,
            trace_mask_degree_bound,
        )?;
        let count = u64::from(quotient_component_count);
        let masking_share = count
            .checked_add(1)
            .and_then(|value| value.checked_mul(trace_mask_degree_bound))
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?
            .div_ceil(count);
        let component_width = self
            .trace_domain_size
            .checked_add(masking_share)
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        // Every radix-two query representative opens the two opposite
        // coordinates of the initial oracle. Later fold collisions cannot
        // increase this per-oracle opened-coordinate set.
        let maximum_initial_oracle_query_coordinate_count = u64::from(schedule.unique_query_count)
            .checked_mul(2)
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        let quotient_mask_degree_bound = u64::from(schedule.deep_point_count)
            .checked_add(maximum_initial_oracle_query_coordinate_count)
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        let quotient_component_degree_bound_exclusive =
            if self.proof_privacy_mode == ProofPrivacyMode::SecretBearing as u16 {
                component_width
                    .checked_add(quotient_mask_degree_bound)
                    .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?
            } else {
                component_width
            };
        let fri_fold_count = derive_fri_fold_count(
            self.opening_degree_bound_exclusive,
            u64::from(schedule.final_polynomial_degree_bound_exclusive),
        )?;
        Ok(QuotientParameters {
            quotient_component_count,
            quotient_component_degree_bound_exclusive,
            quotient_mask_degree_bound,
            trace_mask_degree_bound,
            fri_fold_count,
        })
    }

    fn validate_opening_points(
        &self,
        schedule: &ProofFieldScheduleArtifact,
        field: &ProofFieldProfileArtifact,
    ) -> ArtifactResult<()> {
        let extension_degree = u16::try_from(
            field
                .monic_challenge_extension_polynomial_coefficients
                .len(),
        )
        .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
        let mut points = BTreeSet::new();
        for point in &self.ordered_opening_points {
            if point.deep_point_ordinal >= schedule.deep_point_count
                || point.conjugate_index >= extension_degree
                || point.trace_rotation_is_negative > 1
                || (point.trace_rotation_magnitude == 0 && point.trace_rotation_is_negative != 0)
                || point.trace_rotation_magnitude >= self.trace_domain_size
                || !points.insert(*point)
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
        }
        Ok(())
    }

    fn validate_opening_claims(
        &self,
        quotient_parameters: &QuotientParameters,
    ) -> ArtifactResult<()> {
        let mut claim_keys = BTreeSet::new();
        let mut used_opening_points = BTreeSet::new();
        for claim in &self.ordered_opening_claims {
            let opening_point_index = usize::try_from(claim.opening_point_ordinal)
                .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
            if opening_point_index >= self.ordered_opening_points.len() {
                return Err(ProofProfileArtifactError::UnresolvedIndex);
            }
            used_opening_points.insert(opening_point_index);
            if !claim_keys.insert((
                claim.source_class,
                claim.source_ordinal,
                claim.column_ordinal,
                claim.opening_point_ordinal,
            )) {
                return Err(ProofProfileArtifactError::DuplicateValue);
            }
            match claim.source_class {
                1 => {
                    let tree_index = usize::try_from(claim.source_ordinal)
                        .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                    let tree = self
                        .ordered_trees
                        .get(tree_index)
                        .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                    let column_ordinal = claim
                        .column_ordinal
                        .ok_or(ProofProfileArtifactError::TypeMismatch)?;
                    if !tree.ordered_column_ordinals().contains(&column_ordinal) {
                        return Err(ProofProfileArtifactError::UnresolvedIndex);
                    }
                    let column_index = usize::try_from(column_ordinal)
                        .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                    if claim.source_degree_bound_exclusive
                        != self.ordered_columns[column_index].source_degree_bound_exclusive
                    {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                }
                2 => {
                    if claim.column_ordinal.is_some()
                        || claim.source_ordinal
                            >= u32::from(quotient_parameters.quotient_component_count)
                        || claim.source_degree_bound_exclusive
                            != quotient_parameters.quotient_component_degree_bound_exclusive
                    {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                }
                3 => {
                    if self.proof_privacy_mode != ProofPrivacyMode::SecretBearing as u16
                        || claim.source_ordinal != 0
                        || claim.column_ordinal.is_some()
                        || claim.source_degree_bound_exclusive
                            != self.opening_degree_bound_exclusive - 1
                    {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                }
                _ => return Err(ProofProfileArtifactError::InvalidValue),
            }
        }
        if used_opening_points.len() != self.ordered_opening_points.len() {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        Ok(())
    }

    fn validate_masks(
        &self,
        family: ProofFamily,
        quotient_parameters: &QuotientParameters,
        globally_assigned_mask_purposes: &mut BTreeSet<u16>,
    ) -> ArtifactResult<()> {
        if self.proof_privacy_mode == ProofPrivacyMode::PublicOnly as u16 {
            if !self.ordered_masks.is_empty() {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            return Ok(());
        }
        let prover_column_ordinals = self
            .ordered_columns
            .iter()
            .enumerate()
            .filter_map(|(column_ordinal, column)| {
                matches!(column.origin, RelationColumnOriginArtifact::Prover)
                    .then_some(u32::try_from(column_ordinal).ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        if prover_column_ordinals.is_empty()
            || quotient_parameters.trace_mask_degree_bound == 0
            || quotient_parameters.trace_mask_degree_bound > self.trace_domain_size
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        let mut trace_targets = BTreeSet::new();
        let mut quotient_targets = BTreeSet::new();
        let mut batch_target_count = 0_usize;
        for mask in &self.ordered_masks {
            if mask.mask_purpose >= 0xff00
                || !globally_assigned_mask_purposes.insert(mask.mask_purpose)
                || mask.mask_degree_bound_exclusive == 0
            {
                return Err(ProofProfileArtifactError::DuplicateValue);
            }
            match (mask.mask_kind, mask.target_class) {
                (1, 1) => {
                    if !prover_column_ordinals.contains(&mask.target_ordinal)
                        || mask.mask_degree_bound_exclusive
                            != quotient_parameters.trace_mask_degree_bound
                        || !trace_targets.insert(mask.target_ordinal)
                    {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                }
                (2, 2) => {
                    if mask.target_ordinal
                        >= u32::from(quotient_parameters.quotient_component_count - 1)
                        || mask.mask_degree_bound_exclusive
                            != quotient_parameters.quotient_mask_degree_bound
                        || !quotient_targets.insert(mask.target_ordinal)
                    {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                }
                (3, 3) => {
                    if mask.target_ordinal != 0
                        || mask.mask_degree_bound_exclusive
                            != self.opening_degree_bound_exclusive - 1
                    {
                        return Err(ProofProfileArtifactError::InvalidValue);
                    }
                    batch_target_count += 1;
                }
                _ => return Err(ProofProfileArtifactError::InvalidValue),
            }
        }
        if trace_targets != prover_column_ordinals
            || quotient_targets.len()
                != usize::from(quotient_parameters.quotient_component_count - 1)
            || batch_target_count != 1
        {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        let _ = family;
        Ok(())
    }

    fn validate_complete_tree_catalog(
        &self,
        quotient_parameters: &QuotientParameters,
        _schedule: &ProofFieldScheduleArtifact,
    ) -> ArtifactResult<()> {
        let opening_mask_tree_count =
            usize::from(self.proof_privacy_mode == ProofPrivacyMode::SecretBearing as u16);
        let nonterminal_fri_tree_count = usize::from(quotient_parameters.fri_fold_count - 1);
        let complete_count = self
            .ordered_trees
            .len()
            .checked_add(usize::from(quotient_parameters.quotient_component_count))
            .and_then(|count| count.checked_add(opening_mask_tree_count))
            .and_then(|count| count.checked_add(nonterminal_fri_tree_count))
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        if complete_count > MAXIMUM_COMPLETE_TREE_COUNT {
            return Err(ProofProfileArtifactError::LimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QuotientParameters {
    quotient_component_count: u16,
    quotient_component_degree_bound_exclusive: u64,
    quotient_mask_degree_bound: u64,
    trace_mask_degree_bound: u64,
    fri_fold_count: u16,
}

impl RelationValueLayoutArtifact {
    fn validate(&self, field: &ProofFieldProfileArtifact) -> ArtifactResult<()> {
        if self.shape.len() > MAXIMUM_VALUE_SHAPE_RANK
            || self.logical_element_count()? > MAXIMUM_LOGICAL_SOURCE_ELEMENT_COUNT
        {
            return Err(ProofProfileArtifactError::LimitExceeded);
        }
        match self.element_kind {
            1 => {
                if self.residue_modulus.is_some()
                    || !self.shape.is_empty()
                    || self.embedding_kind != 0
                {
                    return Err(ProofProfileArtifactError::TypeMismatch);
                }
            }
            2 | 3 => {
                if self.residue_modulus.is_some() || self.embedding_kind != 1 {
                    return Err(ProofProfileArtifactError::TypeMismatch);
                }
            }
            4 => {
                let modulus_reference = self
                    .residue_modulus
                    .as_ref()
                    .ok_or(ProofProfileArtifactError::TypeMismatch)?;
                let modulus = resolve_suite_modulus(modulus_reference, field)?;
                if !matches!(self.embedding_kind, 2 | 3)
                    || modulus >= field.base_field_modulus
                    || modulus_reference.catalog == 4
                {
                    return Err(ProofProfileArtifactError::TypeMismatch);
                }
            }
            _ => return Err(ProofProfileArtifactError::InvalidValue),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectorPathRoot {
    ApplicationStatement,
    Suite,
    ApplicationSlot,
}

fn validate_selector_path(
    path: &[RelationSelectorPathStepArtifact],
    root: SelectorPathRoot,
) -> ArtifactResult<()> {
    if path.is_empty() || path.len() > MAXIMUM_SELECTOR_PATH_LENGTH {
        return Err(ProofProfileArtifactError::LimitExceeded);
    }
    for (step_index, step) in path.iter().enumerate() {
        match step.step_kind {
            1 | 2 | 7 => {}
            3..=6 if step.argument == 0 => {}
            8 if root == SelectorPathRoot::Suite
                && SuiteArtifactKind::from_canonical_code(
                    u16::try_from(step.argument)
                        .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
                )
                .is_some() => {}
            _ => return Err(ProofProfileArtifactError::InvalidValue),
        }
        if step_index == 0 {
            match root {
                SelectorPathRoot::ApplicationStatement if step.step_kind != 1 => {
                    return Err(ProofProfileArtifactError::TypeMismatch);
                }
                SelectorPathRoot::ApplicationSlot => {
                    if step.step_kind != 1 || step.argument >= 7 {
                        return Err(ProofProfileArtifactError::TypeMismatch);
                    }
                }
                SelectorPathRoot::Suite if !matches!(step.step_kind, 1 | 8) => {
                    return Err(ProofProfileArtifactError::TypeMismatch);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_protocol_source(
    family: ProofFamily,
    selected_schedule_position: Option<u32>,
    protocol_source_kind: u16,
    coordinates: &[u64],
    binding_path: &[RelationSelectorPathStepArtifact],
    layout: &RelationValueLayoutArtifact,
    field: &ProofFieldProfileArtifact,
) -> ArtifactResult<()> {
    validate_selector_path(binding_path, SelectorPathRoot::ApplicationStatement)?;
    layout.validate(field)?;
    let expected_binding_field = match protocol_source_kind {
        1 if family == ProofFamily::DirectBallot && coordinates.len() == 2 => {
            validate_binary_coordinate(coordinates[0])?;
            validate_data_prime_index(coordinates[1])?;
            7
        }
        2 if family == ProofFamily::DirectBallot && coordinates.len() == 2 => {
            validate_binary_coordinate(coordinates[0])?;
            validate_data_prime_index(coordinates[1])?;
            8
        }
        3 if family == ProofFamily::TargetDecryptionShare && coordinates.len() == 3 => {
            validate_binary_coordinate(coordinates[0])?;
            validate_binary_coordinate(coordinates[1])?;
            validate_target_prime_index(coordinates[2])?;
            6
        }
        4 if family == ProofFamily::TargetDecryptionShare && coordinates.len() == 2 => {
            validate_binary_coordinate(coordinates[0])?;
            validate_target_prime_index(coordinates[1])?;
            13_u64
                .checked_add(coordinates[0])
                .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?
        }
        5 if matches!(
            family,
            ProofFamily::SameSecret
                | ProofFamily::PublicKeyShare
                | ProofFamily::RelinearizationRoundOne
                | ProofFamily::RelinearizationRoundTwo
                | ProofFamily::GaloisKeyShare
        ) && coordinates.len() == 4 =>
        {
            validate_data_prime_index(coordinates[0])?;
            if coordinates[1] > 1 || coordinates[2] >= 2 || coordinates[3] >= 2 {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            0
        }
        6 if family == ProofFamily::PublicKeyShare && coordinates.len() == 1 => {
            validate_data_prime_index(coordinates[0])?;
            0
        }
        7 if matches!(
            family,
            ProofFamily::RelinearizationRoundOne
                | ProofFamily::RelinearizationRoundOneAggregate
                | ProofFamily::RelinearizationRoundTwo
        ) && coordinates.len() == 4 =>
        {
            if Some(
                u32::try_from(coordinates[0])
                    .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
            ) != selected_schedule_position
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            validate_modulus_coordinate(coordinates[2], coordinates[3])?;
            0
        }
        8 if family == ProofFamily::GaloisKeyShare && coordinates.len() == 4 => {
            if Some(
                u32::try_from(coordinates[0])
                    .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
            ) != selected_schedule_position
            {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            validate_modulus_coordinate(coordinates[2], coordinates[3])?;
            0
        }
        9 if coordinates.is_empty() => match family {
            ProofFamily::AggregateThresholdShare => 7,
            ProofFamily::SameSecret
            | ProofFamily::PublicKeyShare
            | ProofFamily::CollectivePublicKey
            | ProofFamily::RelinearizationRoundOne
            | ProofFamily::RelinearizationRoundOneAggregate
            | ProofFamily::RelinearizationRoundTwo
            | ProofFamily::GaloisKeyShare
            | ProofFamily::EvaluatorKeyAggregate => 0,
            ProofFamily::DirectBallot => 7,
            ProofFamily::TargetDecryptionShare => 5,
            _ => return Err(ProofProfileArtifactError::InvalidValue),
        },
        _ => return Err(ProofProfileArtifactError::InvalidValue),
    };
    if binding_path
        != [RelationSelectorPathStepArtifact {
            step_kind: 1,
            argument: expected_binding_field,
        }]
    {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    if protocol_source_kind == 9 {
        if layout.element_kind != 1
            || !layout.shape.is_empty()
            || layout.residue_modulus.is_some()
            || layout.embedding_kind != 0
        {
            return Err(ProofProfileArtifactError::TypeMismatch);
        }
        return Ok(());
    }
    let expected_modulus = match protocol_source_kind {
        1 | 2 => SuiteModulusReferenceArtifact {
            catalog: 1,
            modulus_index: u16::try_from(coordinates[1])
                .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
        },
        3 => SuiteModulusReferenceArtifact {
            catalog: 5,
            modulus_index: u16::try_from(coordinates[2])
                .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
        },
        4 => SuiteModulusReferenceArtifact {
            catalog: 5,
            modulus_index: u16::try_from(coordinates[1])
                .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
        },
        5 | 6 => SuiteModulusReferenceArtifact {
            catalog: 1,
            modulus_index: u16::try_from(coordinates[0])
                .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
        },
        7 | 8 => SuiteModulusReferenceArtifact {
            catalog: u16::try_from(coordinates[2])
                .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
            modulus_index: u16::try_from(coordinates[3])
                .map_err(|_| ProofProfileArtifactError::InvalidValue)?,
        },
        _ => return Err(ProofProfileArtifactError::InvalidValue),
    };
    if layout.element_kind != 4
        || layout.residue_modulus.as_ref() != Some(&expected_modulus)
        || layout.shape != [POLYNOMIAL_DEGREE as u64]
        || layout.embedding_kind != 2
    {
        return Err(ProofProfileArtifactError::TypeMismatch);
    }
    Ok(())
}

fn validate_binary_coordinate(value: u64) -> ArtifactResult<()> {
    if value > 1 {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    Ok(())
}

fn validate_data_prime_index(index: u64) -> ArtifactResult<()> {
    if usize::try_from(index)
        .ok()
        .is_none_or(|index| index >= DATA_PRIMES.len())
    {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    Ok(())
}

fn validate_target_prime_index(index: u64) -> ArtifactResult<()> {
    let target_level = crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL;
    if usize::try_from(index)
        .ok()
        .is_none_or(|index| index > target_level)
    {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    Ok(())
}

fn validate_modulus_coordinate(catalog: u64, index: u64) -> ArtifactResult<()> {
    match catalog {
        1 => validate_data_prime_index(index),
        2 if index == 0 => Ok(()),
        _ => Err(ProofProfileArtifactError::InvalidValue),
    }
}

fn resolve_suite_modulus(
    reference: &SuiteModulusReferenceArtifact,
    field: &ProofFieldProfileArtifact,
) -> ArtifactResult<u64> {
    match reference.catalog {
        1 => DATA_PRIMES
            .get(usize::from(reference.modulus_index))
            .copied()
            .ok_or(ProofProfileArtifactError::UnresolvedIndex),
        2 if reference.modulus_index == 0 => Ok(SPECIAL_PRIME),
        3 if reference.modulus_index == 0 => Ok(PLAINTEXT_MODULUS),
        4 if reference.modulus_index == 0 => Ok(field.base_field_modulus),
        5 => {
            let index = usize::from(reference.modulus_index);
            if index > crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL {
                return Err(ProofProfileArtifactError::UnresolvedIndex);
            }
            DATA_PRIMES
                .get(index)
                .copied()
                .ok_or(ProofProfileArtifactError::UnresolvedIndex)
        }
        _ => Err(ProofProfileArtifactError::UnresolvedIndex),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpressionProgramResult {
    degree: u64,
    referenced_columns: BTreeSet<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpressionStackValue {
    degree: u64,
    is_extension_value: bool,
}

fn validate_numerator_program(
    instructions: &[RelationExpressionInstructionArtifact],
    columns: &[RelationColumnArtifact],
    trace_domain_size: u64,
    nonnative_modulus_count: usize,
    schedule: &ProofFieldScheduleArtifact,
    field: &ProofFieldProfileArtifact,
) -> ArtifactResult<ExpressionProgramResult> {
    if instructions.is_empty() || instructions.len() > MAXIMUM_PROGRAM_INSTRUCTION_COUNT {
        return Err(ProofProfileArtifactError::LimitExceeded);
    }
    let extension_degree = u16::try_from(
        field
            .monic_challenge_extension_polynomial_coefficients
            .len(),
    )
    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
    let mut stack = Vec::new();
    let mut referenced_columns = BTreeSet::new();
    for instruction in instructions {
        match instruction {
            RelationExpressionInstructionArtifact::Constant(value) => {
                if *value >= field.base_field_modulus {
                    return Err(ProofProfileArtifactError::InvalidValue);
                }
                stack.push(ExpressionStackValue {
                    degree: 0,
                    is_extension_value: false,
                });
            }
            RelationExpressionInstructionArtifact::EvaluationVariable => {
                stack.push(ExpressionStackValue {
                    degree: 1,
                    is_extension_value: false,
                });
            }
            RelationExpressionInstructionArtifact::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => {
                validate_canonical_rotation(
                    *rotation_is_negative,
                    *rotation_magnitude,
                    trace_domain_size,
                )?;
                let column_index = usize::try_from(*column_ordinal)
                    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                let column = columns
                    .get(column_index)
                    .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                referenced_columns.insert(*column_ordinal);
                stack.push(ExpressionStackValue {
                    degree: column.source_degree_bound_exclusive - 1,
                    is_extension_value: column.value_type == 2,
                });
            }
            RelationExpressionInstructionArtifact::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } => {
                validate_expression_challenge(
                    *challenge_role,
                    role_coordinates,
                    nonnative_modulus_count,
                    schedule,
                )?;
                stack.push(ExpressionStackValue {
                    degree: 0,
                    is_extension_value: true,
                });
            }
            RelationExpressionInstructionArtifact::Add => {
                let right = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                let left = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                stack.push(ExpressionStackValue {
                    degree: left.degree.max(right.degree),
                    is_extension_value: left.is_extension_value || right.is_extension_value,
                });
            }
            RelationExpressionInstructionArtifact::Multiply => {
                let right = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                let left = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                stack.push(ExpressionStackValue {
                    degree: left
                        .degree
                        .checked_add(right.degree)
                        .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?,
                    is_extension_value: left.is_extension_value || right.is_extension_value,
                });
            }
            RelationExpressionInstructionArtifact::Negate => {
                if stack.is_empty() {
                    return Err(ProofProfileArtifactError::TypeMismatch);
                }
            }
            RelationExpressionInstructionArtifact::Power(exponent) => {
                let value = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                stack.push(ExpressionStackValue {
                    degree: value
                        .degree
                        .checked_mul(*exponent)
                        .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?,
                    is_extension_value: value.is_extension_value,
                });
            }
            RelationExpressionInstructionArtifact::Frobenius(conjugate_index) => {
                if *conjugate_index >= extension_degree || stack.is_empty() {
                    return Err(ProofProfileArtifactError::InvalidValue);
                }
            }
        }
        if stack.len() > MAXIMUM_PROGRAM_INSTRUCTION_COUNT {
            return Err(ProofProfileArtifactError::LimitExceeded);
        }
    }
    if stack.len() != 1 {
        return Err(ProofProfileArtifactError::TypeMismatch);
    }
    Ok(ExpressionProgramResult {
        degree: stack[0].degree,
        referenced_columns,
    })
}

fn validate_expression_challenge(
    challenge_role: u16,
    role_coordinates: &[u64],
    nonnative_modulus_count: usize,
    schedule: &ProofFieldScheduleArtifact,
) -> ArtifactResult<()> {
    let (modulus_ordinal, challenge_ordinal) = match (challenge_role, role_coordinates) {
        (1, [modulus_ordinal, challenge_ordinal]) => (*modulus_ordinal, *challenge_ordinal),
        (2, [modulus_ordinal, challenge_ordinal, _unit_ordinal]) => {
            (*modulus_ordinal, *challenge_ordinal)
        }
        _ => return Err(ProofProfileArtifactError::InvalidValue),
    };
    if usize::try_from(modulus_ordinal)
        .ok()
        .is_none_or(|ordinal| ordinal >= nonnative_modulus_count)
        || challenge_ordinal >= u64::from(schedule.nonnative_modular_identity_challenge_count)
    {
        return Err(ProofProfileArtifactError::UnresolvedIndex);
    }
    Ok(())
}

fn validate_canonical_rotation(
    rotation_is_negative: u8,
    rotation_magnitude: u64,
    trace_domain_size: u64,
) -> ArtifactResult<()> {
    if rotation_is_negative > 1
        || (rotation_magnitude == 0 && rotation_is_negative != 0)
        || rotation_magnitude >= trace_domain_size
    {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompiledZeroifier {
    degree: u64,
}

fn compile_zeroifier_program(
    instructions: &[RelationExpressionInstructionArtifact],
    evaluation_domain_size: u64,
    schedule: &ProofFieldScheduleArtifact,
    field: &ProofFieldProfileArtifact,
) -> ArtifactResult<CompiledZeroifier> {
    if instructions.is_empty() || instructions.len() > MAXIMUM_PROGRAM_INSTRUCTION_COUNT {
        return Err(ProofProfileArtifactError::LimitExceeded);
    }
    if field.base_field_modulus != GOLDILOCKS_MODULUS
        || evaluation_domain_size > MAXIMUM_LOGICAL_SOURCE_ELEMENT_COUNT
    {
        return Err(ProofProfileArtifactError::LimitExceeded);
    }
    let mut stack: Vec<Vec<Goldilocks>> = Vec::new();
    for instruction in instructions {
        match instruction {
            RelationExpressionInstructionArtifact::Constant(value) => {
                stack.push(vec![
                    Goldilocks::from_canonical_u64(*value)
                        .ok_or(ProofProfileArtifactError::InvalidValue)?,
                ]);
            }
            RelationExpressionInstructionArtifact::EvaluationVariable => {
                stack.push(vec![Goldilocks::ZERO, Goldilocks::ONE]);
            }
            RelationExpressionInstructionArtifact::Add => {
                let right = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                let left = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                stack.push(polynomial_add(&left, &right)?);
            }
            RelationExpressionInstructionArtifact::Multiply => {
                let right = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                let left = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                stack.push(polynomial_multiply(&left, &right)?);
            }
            RelationExpressionInstructionArtifact::Negate => {
                let value = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                stack.push(value.into_iter().map(Goldilocks::negate).collect());
            }
            RelationExpressionInstructionArtifact::Power(exponent) => {
                let value = stack.pop().ok_or(ProofProfileArtifactError::TypeMismatch)?;
                stack.push(polynomial_power(&value, *exponent)?);
            }
            _ => return Err(ProofProfileArtifactError::TypeMismatch),
        }
    }
    if stack.len() != 1 {
        return Err(ProofProfileArtifactError::TypeMismatch);
    }
    let polynomial = trim_polynomial(stack.pop().expect("one zeroifier remains"));
    if polynomial.is_empty() {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    let evaluation_domain_size_u64 = evaluation_domain_size;
    let maximum_two_adic_order = 1_u64
        .checked_shl((field.base_field_modulus - 1).trailing_zeros())
        .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
    if !maximum_two_adic_order.is_multiple_of(evaluation_domain_size_u64) {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    let generator = Goldilocks::from_canonical_u64(field.maximum_two_adic_subgroup_generator)
        .ok_or(ProofProfileArtifactError::InvalidValue)?
        .pow_u64(maximum_two_adic_order / evaluation_domain_size_u64);
    let mut evaluation_point = Goldilocks::from_canonical_u64(schedule.evaluation_coset_offset)
        .ok_or(ProofProfileArtifactError::InvalidValue)?;
    for _ in 0..evaluation_domain_size {
        if evaluate_polynomial(&polynomial, evaluation_point) == Goldilocks::ZERO {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
        evaluation_point = evaluation_point.multiply(generator);
    }
    Ok(CompiledZeroifier {
        degree: u64::try_from(polynomial.len() - 1)
            .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?,
    })
}

fn trim_polynomial(mut polynomial: Vec<Goldilocks>) -> Vec<Goldilocks> {
    while polynomial.last() == Some(&Goldilocks::ZERO) {
        polynomial.pop();
    }
    polynomial
}

fn polynomial_add(left: &[Goldilocks], right: &[Goldilocks]) -> ArtifactResult<Vec<Goldilocks>> {
    let length = left.len().max(right.len());
    if length > MAXIMUM_ZEROIFIER_COEFFICIENT_COUNT {
        return Err(ProofProfileArtifactError::LimitExceeded);
    }
    Ok(trim_polynomial(
        (0..length)
            .map(|index| {
                left.get(index)
                    .copied()
                    .unwrap_or(Goldilocks::ZERO)
                    .add(right.get(index).copied().unwrap_or(Goldilocks::ZERO))
            })
            .collect(),
    ))
}

fn polynomial_multiply(
    left: &[Goldilocks],
    right: &[Goldilocks],
) -> ArtifactResult<Vec<Goldilocks>> {
    if left.is_empty() || right.is_empty() {
        return Ok(Vec::new());
    }
    let length = left
        .len()
        .checked_add(right.len())
        .and_then(|value| value.checked_sub(1))
        .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
    if length > MAXIMUM_ZEROIFIER_COEFFICIENT_COUNT {
        return Err(ProofProfileArtifactError::LimitExceeded);
    }
    let mut product = vec![Goldilocks::ZERO; length];
    for (left_index, left_value) in left.iter().enumerate() {
        for (right_index, right_value) in right.iter().enumerate() {
            let product_index = left_index + right_index;
            product[product_index] = product[product_index].add(left_value.multiply(*right_value));
        }
    }
    Ok(trim_polynomial(product))
}

fn polynomial_power(
    polynomial: &[Goldilocks],
    mut exponent: u64,
) -> ArtifactResult<Vec<Goldilocks>> {
    let mut result = vec![Goldilocks::ONE];
    let mut power = polynomial.to_vec();
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = polynomial_multiply(&result, &power)?;
        }
        exponent >>= 1;
        if exponent != 0 {
            power = polynomial_multiply(&power, &power)?;
        }
    }
    Ok(trim_polynomial(result))
}

fn evaluate_polynomial(polynomial: &[Goldilocks], point: Goldilocks) -> Goldilocks {
    polynomial
        .iter()
        .rev()
        .fold(Goldilocks::ZERO, |value, coefficient| {
            value.multiply(point).add(*coefficient)
        })
}

fn derive_quotient_component_count(
    quotient_degree: u64,
    trace_domain_size: u64,
    trace_mask_degree_bound: u64,
) -> ArtifactResult<u16> {
    for component_count in 2_u16..=u16::MAX {
        let count = u64::from(component_count);
        let capacity = count
            .checked_mul(trace_domain_size)
            .and_then(|value| {
                count
                    .checked_add(1)
                    .and_then(|factor| factor.checked_mul(trace_mask_degree_bound))
                    .and_then(|mask_capacity| value.checked_add(mask_capacity))
            })
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        if quotient_degree < capacity {
            return Ok(component_count);
        }
    }
    Err(ProofProfileArtifactError::LimitExceeded)
}

fn derive_fri_fold_count(
    opening_degree_bound_exclusive: u64,
    final_degree_bound_exclusive: u64,
) -> ArtifactResult<u16> {
    if opening_degree_bound_exclusive <= 1
        || final_degree_bound_exclusive == 0
        || final_degree_bound_exclusive >= opening_degree_bound_exclusive - 1
    {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    for fold_count in 1_u16..=63 {
        let denominator = 1_u64
            .checked_shl(u32::from(fold_count))
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        if (opening_degree_bound_exclusive - 1).div_ceil(denominator)
            <= final_degree_bound_exclusive
        {
            return Ok(fold_count);
        }
    }
    Err(ProofProfileArtifactError::LimitExceeded)
}

fn validate_endpoint_coordinate_presence(
    family: ProofFamily,
    endpoint: &RelationRootEndpointArtifact,
) -> ArtifactResult<()> {
    let (expects_roster, expects_schedule, expects_producer) = match family {
        ProofFamily::VssShareLinkage
        | ProofFamily::AggregateThresholdShare
        | ProofFamily::SameSecret
        | ProofFamily::PublicKeyShare
        | ProofFamily::TargetDecryptionShare => (true, false, false),
        ProofFamily::CollectivePublicKey | ProofFamily::EvaluatorKeyAggregate => {
            (false, false, false)
        }
        ProofFamily::RelinearizationRoundOne
        | ProofFamily::RelinearizationRoundTwo
        | ProofFamily::GaloisKeyShare => (true, true, false),
        ProofFamily::RelinearizationRoundOneAggregate => (false, true, false),
        ProofFamily::DirectBallot => (true, false, true),
    };
    if endpoint.roster_position.is_some() != expects_roster
        || endpoint.schedule_position.is_some() != expects_schedule
        || endpoint.producer_sequence.is_some() != expects_producer
        || endpoint.top_count.is_some() != (family == ProofFamily::EvaluatorKeyAggregate)
        || endpoint.roster_position.is_some_and(|position| {
            position >= crate::foundation::FOUNDATION_PROFILE.participant_count
        })
        || endpoint
            .top_count
            .is_some_and(|count| !(1..=20).contains(&count))
    {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    Ok(())
}

fn require_strictly_increasing<T: Ord>(values: &[T]) -> ArtifactResult<()> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(ProofProfileArtifactError::InvalidOrdering);
    }
    Ok(())
}

impl ProofFieldProfileArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER, 3)?;
        Ok(Self {
            base_field_modulus: read_u64(&tuple.items[0])?,
            maximum_two_adic_subgroup_generator: read_u64(&tuple.items[1])?,
            monic_challenge_extension_polynomial_coefficients: read_u64_list(&tuple.items[2], 64)?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.base_field_modulus),
                CanonicalItem::unsigned64(self.maximum_two_adic_subgroup_generator),
                u64_list(&self.monic_challenge_extension_polynomial_coefficients)?,
            ],
        ))
    }
}

impl ProofFamilyProfileArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        require_tuple(tuple, PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER, 2)?;
        Ok(Self {
            application_statement_schema_identifier: read_u16(&tuple.items[0])?,
            field_schedule: ProofFieldScheduleArtifact::from_tuple(&read_nested_tuple(
                &tuple.items[1],
                limits,
            )?)?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                nested_tuple_item(&self.field_schedule.to_tuple())?,
            ],
        ))
    }
}

impl ProofFieldScheduleArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER, 8)?;
        Ok(Self {
            proof_field_index: read_u16(&tuple.items[0])?,
            evaluation_blowup_factor: read_u32(&tuple.items[1])?,
            evaluation_coset_offset: read_u64(&tuple.items[2])?,
            deep_point_count: read_u16(&tuple.items[3])?,
            final_polynomial_degree_bound_exclusive: read_u32(&tuple.items[4])?,
            unique_query_count: read_u32(&tuple.items[5])?,
            nonnative_modular_identity_challenge_count: read_u16(&tuple.items[6])?,
            maximum_fiat_shamir_candidate_draws_per_output: read_u32(&tuple.items[7])?,
        })
    }

    fn to_tuple(&self) -> CanonicalTuple {
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
                CanonicalItem::unsigned16(self.nonnative_modular_identity_challenge_count),
                CanonicalItem::unsigned32(self.maximum_fiat_shamir_candidate_draws_per_output),
            ],
        )
    }
}

impl RelationPlanArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_PLAN_SCHEMA_IDENTIFIER, 2)?;
        Ok(Self {
            application_statement_schema_identifier: read_u16(&tuple.items[0])?,
            variants: read_nested_tuple_list(&tuple.items[1], limits, MAXIMUM_VARIANTS_PER_PLAN)?
                .iter()
                .map(|value| RelationPlanVariantArtifact::from_tuple(value, limits))
                .collect::<ArtifactResult<Vec<_>>>()?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        let variants = self
            .variants
            .iter()
            .map(RelationPlanVariantArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            RELATION_PLAN_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                nested_tuple_list(&variants)?,
            ],
        ))
    }
}

impl RelationPlanVariantArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER, 15)?;
        Ok(Self {
            schedule_position: read_optional_u32(&tuple.items[0])?,
            top_count: read_optional_u16(&tuple.items[1])?,
            proof_privacy_mode: read_u16(&tuple.items[2])?,
            trace_domain_size: read_u64(&tuple.items[3])?,
            evaluation_domain_size: read_u64(&tuple.items[4])?,
            opening_degree_bound_exclusive: read_u64(&tuple.items[5])?,
            ordered_nonnative_moduli: read_nested_tuple_list(
                &tuple.items[6],
                limits,
                MAXIMUM_VERIFIER_SOURCE_COUNT,
            )?
            .iter()
            .map(SuiteModulusReferenceArtifact::from_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_verifier_sources: read_nested_tuple_list(
                &tuple.items[7],
                limits,
                MAXIMUM_VERIFIER_SOURCE_COUNT,
            )?
            .iter()
            .map(|value| RelationVerifierSourceArtifact::from_tuple(value, limits))
            .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_public_samplers: read_nested_tuple_list(
                &tuple.items[8],
                limits,
                MAXIMUM_PUBLIC_SAMPLER_COUNT,
            )?
            .iter()
            .map(|value| RelationPublicSamplerArtifact::from_tuple(value, limits))
            .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_columns: read_nested_tuple_list(&tuple.items[9], limits, MAXIMUM_COLUMN_COUNT)?
                .iter()
                .map(|value| RelationColumnArtifact::from_tuple(value, limits))
                .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_trees: read_nested_tuple_list(&tuple.items[10], limits, MAXIMUM_TREE_COUNT)?
                .iter()
                .map(RelationTreeArtifact::from_tuple)
                .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_constraints: read_nested_tuple_list(
                &tuple.items[11],
                limits,
                MAXIMUM_CONSTRAINT_COUNT,
            )?
            .iter()
            .map(|value| RelationConstraintArtifact::from_tuple(value, limits))
            .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_opening_points: read_nested_tuple_list(
                &tuple.items[12],
                limits,
                MAXIMUM_OPENING_POINT_COUNT,
            )?
            .iter()
            .map(RelationOpeningPointArtifact::from_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_opening_claims: read_nested_tuple_list(
                &tuple.items[13],
                limits,
                MAXIMUM_OPENING_CLAIM_COUNT,
            )?
            .iter()
            .map(RelationOpeningClaimArtifact::from_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?,
            ordered_masks: read_nested_tuple_list(&tuple.items[14], limits, MAXIMUM_MASK_COUNT)?
                .iter()
                .map(RelationMaskArtifact::from_tuple)
                .collect::<ArtifactResult<Vec<_>>>()?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        let nonnative_moduli = self
            .ordered_nonnative_moduli
            .iter()
            .map(SuiteModulusReferenceArtifact::to_tuple)
            .collect::<Vec<_>>();
        let verifier_sources = self
            .ordered_verifier_sources
            .iter()
            .map(RelationVerifierSourceArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let samplers = self
            .ordered_public_samplers
            .iter()
            .map(RelationPublicSamplerArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let columns = self
            .ordered_columns
            .iter()
            .map(RelationColumnArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let trees = self
            .ordered_trees
            .iter()
            .map(RelationTreeArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let constraints = self
            .ordered_constraints
            .iter()
            .map(RelationConstraintArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let opening_points = self
            .ordered_opening_points
            .iter()
            .copied()
            .map(RelationOpeningPointArtifact::to_tuple)
            .collect::<Vec<_>>();
        let opening_claims = self
            .ordered_opening_claims
            .iter()
            .map(RelationOpeningClaimArtifact::to_tuple)
            .collect::<ArtifactResult<Vec<_>>>()?;
        let masks = self
            .ordered_masks
            .iter()
            .map(RelationMaskArtifact::to_tuple)
            .collect::<Vec<_>>();
        Ok(CanonicalTuple::new(
            RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                optional_u32(self.schedule_position)?,
                optional_u16(self.top_count)?,
                CanonicalItem::unsigned16(self.proof_privacy_mode),
                CanonicalItem::unsigned64(self.trace_domain_size),
                CanonicalItem::unsigned64(self.evaluation_domain_size),
                CanonicalItem::unsigned64(self.opening_degree_bound_exclusive),
                nested_tuple_list(&nonnative_moduli)?,
                nested_tuple_list(&verifier_sources)?,
                nested_tuple_list(&samplers)?,
                nested_tuple_list(&columns)?,
                nested_tuple_list(&trees)?,
                nested_tuple_list(&constraints)?,
                nested_tuple_list(&opening_points)?,
                nested_tuple_list(&opening_claims)?,
                nested_tuple_list(&masks)?,
            ],
        ))
    }
}

impl SuiteModulusReferenceArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER, 2)?;
        Ok(Self {
            catalog: read_u16(&tuple.items[0])?,
            modulus_index: read_u16(&tuple.items[1])?,
        })
    }

    fn to_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.catalog),
                CanonicalItem::unsigned16(self.modulus_index),
            ],
        )
    }
}

impl RelationVerifierSourceArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        match tuple.schema_identifier {
            APPLICATION_STATEMENT_SOURCE_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, APPLICATION_STATEMENT_SOURCE_SCHEMA_IDENTIFIER, 2)?;
                Ok(Self::ApplicationStatement {
                    value_path: read_selector_path(&tuple.items[0], limits)?,
                    value_layout: RelationValueLayoutArtifact::from_tuple(&read_nested_tuple(
                        &tuple.items[1],
                        limits,
                    )?)?,
                })
            }
            PROTOCOL_SOURCE_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, PROTOCOL_SOURCE_SCHEMA_IDENTIFIER, 4)?;
                Ok(Self::Protocol {
                    protocol_source_kind: read_u16(&tuple.items[0])?,
                    source_coordinates: read_u64_list(
                        &tuple.items[1],
                        MAXIMUM_ROLE_COORDINATE_COUNT,
                    )?,
                    statement_binding_path: read_selector_path(&tuple.items[2], limits)?,
                    value_layout: RelationValueLayoutArtifact::from_tuple(&read_nested_tuple(
                        &tuple.items[3],
                        limits,
                    )?)?,
                })
            }
            SUITE_SOURCE_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, SUITE_SOURCE_SCHEMA_IDENTIFIER, 2)?;
                Ok(Self::Suite {
                    value_path: read_selector_path(&tuple.items[0], limits)?,
                    value_layout: RelationValueLayoutArtifact::from_tuple(&read_nested_tuple(
                        &tuple.items[1],
                        limits,
                    )?)?,
                })
            }
            APPLICATION_SLOT_SOURCE_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, APPLICATION_SLOT_SOURCE_SCHEMA_IDENTIFIER, 2)?;
                Ok(Self::ApplicationSlot {
                    value_path: read_selector_path(&tuple.items[0], limits)?,
                    value_layout: RelationValueLayoutArtifact::from_tuple(&read_nested_tuple(
                        &tuple.items[1],
                        limits,
                    )?)?,
                })
            }
            SAMPLER_OUTPUT_SOURCE_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, SAMPLER_OUTPUT_SOURCE_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::SamplerOutput {
                    public_sampler_ordinal: read_u32(&tuple.items[0])?,
                })
            }
            _ => Err(ProofProfileArtifactError::WrongSchema),
        }
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        match self {
            Self::ApplicationStatement {
                value_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                APPLICATION_STATEMENT_SOURCE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    selector_path_item(value_path)?,
                    nested_tuple_item(&value_layout.to_tuple()?)?,
                ],
            )),
            Self::Protocol {
                protocol_source_kind,
                source_coordinates,
                statement_binding_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                PROTOCOL_SOURCE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*protocol_source_kind),
                    u64_list(source_coordinates)?,
                    selector_path_item(statement_binding_path)?,
                    nested_tuple_item(&value_layout.to_tuple()?)?,
                ],
            )),
            Self::Suite {
                value_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                SUITE_SOURCE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    selector_path_item(value_path)?,
                    nested_tuple_item(&value_layout.to_tuple()?)?,
                ],
            )),
            Self::ApplicationSlot {
                value_path,
                value_layout,
            } => Ok(CanonicalTuple::new(
                APPLICATION_SLOT_SOURCE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    selector_path_item(value_path)?,
                    nested_tuple_item(&value_layout.to_tuple()?)?,
                ],
            )),
            Self::SamplerOutput {
                public_sampler_ordinal,
            } => Ok(CanonicalTuple::new(
                SAMPLER_OUTPUT_SOURCE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*public_sampler_ordinal)],
            )),
        }
    }

    fn layout<'artifact>(
        &'artifact self,
        samplers: &'artifact [RelationPublicSamplerArtifact],
    ) -> ArtifactResult<RelationValueLayoutArtifact> {
        match self {
            Self::ApplicationStatement { value_layout, .. }
            | Self::Protocol { value_layout, .. }
            | Self::Suite { value_layout, .. }
            | Self::ApplicationSlot { value_layout, .. } => Ok(value_layout.clone()),
            Self::SamplerOutput {
                public_sampler_ordinal,
            } => {
                let sampler_index = usize::try_from(*public_sampler_ordinal)
                    .map_err(|_| ProofProfileArtifactError::ArithmeticOverflow)?;
                let sampler = samplers
                    .get(sampler_index)
                    .ok_or(ProofProfileArtifactError::UnresolvedIndex)?;
                Ok(RelationValueLayoutArtifact {
                    element_kind: 4,
                    residue_modulus: Some(sampler.output_modulus.clone()),
                    shape: vec![sampler.output_count],
                    embedding_kind: 2,
                })
            }
        }
    }
}

impl RelationSelectorPathStepArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER, 2)?;
        Ok(Self {
            step_kind: read_u16(&tuple.items[0])?,
            argument: read_u64(&tuple.items[1])?,
        })
    }

    fn to_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.step_kind),
                CanonicalItem::unsigned64(self.argument),
            ],
        )
    }
}

impl RelationValueLayoutArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, VALUE_LAYOUT_SCHEMA_IDENTIFIER, 4)?;
        Ok(Self {
            element_kind: read_u16(&tuple.items[0])?,
            residue_modulus: read_optional_nested_tuple(&tuple.items[1])?
                .as_ref()
                .map(SuiteModulusReferenceArtifact::from_tuple)
                .transpose()?,
            shape: read_u64_list(&tuple.items[2], MAXIMUM_VALUE_SHAPE_RANK)?,
            embedding_kind: read_u16(&tuple.items[3])?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        let residue_modulus = self.residue_modulus.as_ref().map(|value| value.to_tuple());
        Ok(CanonicalTuple::new(
            VALUE_LAYOUT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.element_kind),
                optional_nested_tuple(residue_modulus.as_ref())?,
                u64_list(&self.shape)?,
                CanonicalItem::unsigned16(self.embedding_kind),
            ],
        ))
    }

    fn logical_element_count(&self) -> ArtifactResult<u64> {
        self.shape.iter().try_fold(1_u64, |count, dimension| {
            if *dimension == 0 {
                return Err(ProofProfileArtifactError::InvalidValue);
            }
            count
                .checked_mul(*dimension)
                .ok_or(ProofProfileArtifactError::ArithmeticOverflow)
        })
    }
}

impl RelationPublicSamplerArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_PUBLIC_SAMPLER_SCHEMA_IDENTIFIER, 6)?;
        Ok(Self {
            seed_verifier_source_ordinal: read_u32(&tuple.items[0])?,
            role_domain: read_ascii(&tuple.items[1])?,
            canonical_role_coordinate_bytes: read_variable_bytes(&tuple.items[2])?,
            output_modulus: SuiteModulusReferenceArtifact::from_tuple(&read_nested_tuple(
                &tuple.items[3],
                limits,
            )?)?,
            output_count: read_u64(&tuple.items[4])?,
            output_verifier_source_ordinal: read_u32(&tuple.items[5])?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_PUBLIC_SAMPLER_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.seed_verifier_source_ordinal),
                CanonicalItem::ascii(&self.role_domain)?,
                CanonicalItem::variable_bytes(&self.canonical_role_coordinate_bytes)?,
                nested_tuple_item(&self.output_modulus.to_tuple())?,
                CanonicalItem::unsigned64(self.output_count),
                CanonicalItem::unsigned32(self.output_verifier_source_ordinal),
            ],
        ))
    }
}

impl RelationColumnArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_COLUMN_SCHEMA_IDENTIFIER, 3)?;
        Ok(Self {
            origin: RelationColumnOriginArtifact::from_tuple(&read_nested_tuple(
                &tuple.items[0],
                limits,
            )?)?,
            value_type: read_u16(&tuple.items[1])?,
            source_degree_bound_exclusive: read_u64(&tuple.items[2])?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_COLUMN_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                nested_tuple_item(&self.origin.to_tuple())?,
                CanonicalItem::unsigned16(self.value_type),
                CanonicalItem::unsigned64(self.source_degree_bound_exclusive),
            ],
        ))
    }
}

impl RelationColumnOriginArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        match tuple.schema_identifier {
            VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER, 3)?;
                Ok(Self::VerifierSequence {
                    verifier_source_ordinal: read_u32(&tuple.items[0])?,
                    first_logical_element_index: read_u64(&tuple.items[1])?,
                    logical_element_stride: read_u64(&tuple.items[2])?,
                })
            }
            BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::BoundTree {
                    expected_root_source_ordinal: read_u32(&tuple.items[0])?,
                })
            }
            PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Prover)
            }
            _ => Err(ProofProfileArtifactError::WrongSchema),
        }
    }

    fn to_tuple(&self) -> CanonicalTuple {
        match self {
            Self::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } => CanonicalTuple::new(
                VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*verifier_source_ordinal),
                    CanonicalItem::unsigned64(*first_logical_element_index),
                    CanonicalItem::unsigned64(*logical_element_stride),
                ],
            ),
            Self::BoundTree {
                expected_root_source_ordinal,
            } => CanonicalTuple::new(
                BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*expected_root_source_ordinal)],
            ),
            Self::Prover => CanonicalTuple::new(
                PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![],
            ),
        }
    }
}

impl RelationTreeArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        match tuple.schema_identifier {
            PROOF_CREATED_TREE_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, PROOF_CREATED_TREE_SCHEMA_IDENTIFIER, 2)?;
                Ok(Self::ProofCreated {
                    proof_tree_role: read_u16(&tuple.items[0])?,
                    ordered_column_ordinals: read_u32_list(&tuple.items[1], MAXIMUM_COLUMN_COUNT)?,
                })
            }
            BOUND_PUBLIC_TREE_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, BOUND_PUBLIC_TREE_SCHEMA_IDENTIFIER, 4)?;
                Ok(Self::BoundPublic {
                    construction_kind: read_u16(&tuple.items[0])?,
                    expected_root_source_ordinal: read_u32(&tuple.items[1])?,
                    root_use: read_u16(&tuple.items[2])?,
                    ordered_column_ordinals: read_u32_list(&tuple.items[3], MAXIMUM_COLUMN_COUNT)?,
                })
            }
            _ => Err(ProofProfileArtifactError::WrongSchema),
        }
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        match self {
            Self::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => Ok(CanonicalTuple::new(
                PROOF_CREATED_TREE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*proof_tree_role),
                    u32_list(ordered_column_ordinals)?,
                ],
            )),
            Self::BoundPublic {
                construction_kind,
                expected_root_source_ordinal,
                root_use,
                ordered_column_ordinals,
            } => Ok(CanonicalTuple::new(
                BOUND_PUBLIC_TREE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*construction_kind),
                    CanonicalItem::unsigned32(*expected_root_source_ordinal),
                    CanonicalItem::unsigned16(*root_use),
                    u32_list(ordered_column_ordinals)?,
                ],
            )),
        }
    }

    fn ordered_column_ordinals(&self) -> &[u32] {
        match self {
            Self::ProofCreated {
                ordered_column_ordinals,
                ..
            }
            | Self::BoundPublic {
                ordered_column_ordinals,
                ..
            } => ordered_column_ordinals,
        }
    }
}

impl RelationConstraintArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_CONSTRAINT_SCHEMA_IDENTIFIER, 4)?;
        Ok(Self {
            constraint_role: read_u16(&tuple.items[0])?,
            role_coordinates: read_u64_list(&tuple.items[1], MAXIMUM_ROLE_COORDINATE_COUNT)?,
            numerator_postfix_expression: read_instruction_list(&tuple.items[2], limits)?,
            zeroifier_postfix_expression: read_instruction_list(&tuple.items[3], limits)?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_CONSTRAINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.constraint_role),
                u64_list(&self.role_coordinates)?,
                instruction_list_item(&self.numerator_postfix_expression)?,
                instruction_list_item(&self.zeroifier_postfix_expression)?,
            ],
        ))
    }
}

impl RelationExpressionInstructionArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        match tuple.schema_identifier {
            CONSTANT_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, CONSTANT_INSTRUCTION_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::Constant(read_field_element(&tuple.items[0])?))
            }
            EVALUATION_VARIABLE_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, EVALUATION_VARIABLE_INSTRUCTION_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::EvaluationVariable)
            }
            COLUMN_VALUE_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, COLUMN_VALUE_INSTRUCTION_SCHEMA_IDENTIFIER, 3)?;
                Ok(Self::ColumnValue {
                    column_ordinal: read_u32(&tuple.items[0])?,
                    rotation_is_negative: read_u8(&tuple.items[1])?,
                    rotation_magnitude: read_u64(&tuple.items[2])?,
                })
            }
            TRANSCRIPT_CHALLENGE_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, TRANSCRIPT_CHALLENGE_INSTRUCTION_SCHEMA_IDENTIFIER, 2)?;
                Ok(Self::TranscriptChallenge {
                    challenge_role: read_u16(&tuple.items[0])?,
                    role_coordinates: read_u64_list(
                        &tuple.items[1],
                        MAXIMUM_ROLE_COORDINATE_COUNT,
                    )?,
                })
            }
            ADD_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, ADD_INSTRUCTION_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Add)
            }
            MULTIPLY_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, MULTIPLY_INSTRUCTION_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Multiply)
            }
            NEGATE_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, NEGATE_INSTRUCTION_SCHEMA_IDENTIFIER, 0)?;
                Ok(Self::Negate)
            }
            POWER_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, POWER_INSTRUCTION_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::Power(read_u64(&tuple.items[0])?))
            }
            FROBENIUS_INSTRUCTION_SCHEMA_IDENTIFIER => {
                require_tuple(tuple, FROBENIUS_INSTRUCTION_SCHEMA_IDENTIFIER, 1)?;
                Ok(Self::Frobenius(read_u16(&tuple.items[0])?))
            }
            _ => Err(ProofProfileArtifactError::WrongSchema),
        }
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        let (schema_identifier, items) = match self {
            Self::Constant(value) => (
                CONSTANT_INSTRUCTION_SCHEMA_IDENTIFIER,
                vec![field_element_item(*value)?],
            ),
            Self::EvaluationVariable => (EVALUATION_VARIABLE_INSTRUCTION_SCHEMA_IDENTIFIER, vec![]),
            Self::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => (
                COLUMN_VALUE_INSTRUCTION_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::unsigned32(*column_ordinal),
                    CanonicalItem::unsigned8(*rotation_is_negative),
                    CanonicalItem::unsigned64(*rotation_magnitude),
                ],
            ),
            Self::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } => (
                TRANSCRIPT_CHALLENGE_INSTRUCTION_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::unsigned16(*challenge_role),
                    u64_list(role_coordinates)?,
                ],
            ),
            Self::Add => (ADD_INSTRUCTION_SCHEMA_IDENTIFIER, vec![]),
            Self::Multiply => (MULTIPLY_INSTRUCTION_SCHEMA_IDENTIFIER, vec![]),
            Self::Negate => (NEGATE_INSTRUCTION_SCHEMA_IDENTIFIER, vec![]),
            Self::Power(exponent) => (
                POWER_INSTRUCTION_SCHEMA_IDENTIFIER,
                vec![CanonicalItem::unsigned64(*exponent)],
            ),
            Self::Frobenius(conjugate_index) => (
                FROBENIUS_INSTRUCTION_SCHEMA_IDENTIFIER,
                vec![CanonicalItem::unsigned16(*conjugate_index)],
            ),
        };
        Ok(CanonicalTuple::new(
            schema_identifier,
            SCHEMA_VERSION,
            items,
        ))
    }
}

impl RelationOpeningPointArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_OPENING_POINT_SCHEMA_IDENTIFIER, 4)?;
        Ok(Self {
            deep_point_ordinal: read_u16(&tuple.items[0])?,
            trace_rotation_is_negative: read_u8(&tuple.items[1])?,
            trace_rotation_magnitude: read_u64(&tuple.items[2])?,
            conjugate_index: read_u16(&tuple.items[3])?,
        })
    }

    fn to_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_OPENING_POINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.deep_point_ordinal),
                CanonicalItem::unsigned8(self.trace_rotation_is_negative),
                CanonicalItem::unsigned64(self.trace_rotation_magnitude),
                CanonicalItem::unsigned16(self.conjugate_index),
            ],
        )
    }
}

impl RelationOpeningClaimArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_OPENING_CLAIM_SCHEMA_IDENTIFIER, 5)?;
        Ok(Self {
            source_class: read_u16(&tuple.items[0])?,
            source_ordinal: read_u32(&tuple.items[1])?,
            column_ordinal: read_optional_u32(&tuple.items[2])?,
            opening_point_ordinal: read_u32(&tuple.items[3])?,
            source_degree_bound_exclusive: read_u64(&tuple.items[4])?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            RELATION_OPENING_CLAIM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.source_class),
                CanonicalItem::unsigned32(self.source_ordinal),
                optional_u32(self.column_ordinal)?,
                CanonicalItem::unsigned32(self.opening_point_ordinal),
                CanonicalItem::unsigned64(self.source_degree_bound_exclusive),
            ],
        ))
    }
}

impl RelationMaskArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, RELATION_MASK_SCHEMA_IDENTIFIER, 5)?;
        Ok(Self {
            mask_purpose: read_u16(&tuple.items[0])?,
            mask_kind: read_u16(&tuple.items[1])?,
            target_class: read_u16(&tuple.items[2])?,
            target_ordinal: read_u32(&tuple.items[3])?,
            mask_degree_bound_exclusive: read_u64(&tuple.items[4])?,
        })
    }

    fn to_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_MASK_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.mask_purpose),
                CanonicalItem::unsigned16(self.mask_kind),
                CanonicalItem::unsigned16(self.target_class),
                CanonicalItem::unsigned32(self.target_ordinal),
                CanonicalItem::unsigned64(self.mask_degree_bound_exclusive),
            ],
        )
    }
}

impl RelationRootCompatibilityEdgeArtifact {
    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> ArtifactResult<Self> {
        require_tuple(tuple, ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER, 3)?;
        Ok(Self {
            producer_endpoint: RelationRootEndpointArtifact::from_tuple(&read_nested_tuple(
                &tuple.items[0],
                limits,
            )?)?,
            consumer_endpoint: RelationRootEndpointArtifact::from_tuple(&read_nested_tuple(
                &tuple.items[1],
                limits,
            )?)?,
            construction_kind: read_u16(&tuple.items[2])?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                nested_tuple_item(&self.producer_endpoint.to_tuple()?)?,
                nested_tuple_item(&self.consumer_endpoint.to_tuple()?)?,
                CanonicalItem::unsigned16(self.construction_kind),
            ],
        ))
    }
}

impl RelationRootEndpointArtifact {
    fn from_tuple(tuple: &CanonicalTuple) -> ArtifactResult<Self> {
        require_tuple(tuple, ROOT_ENDPOINT_SCHEMA_IDENTIFIER, 6)?;
        Ok(Self {
            application_statement_schema_identifier: read_u16(&tuple.items[0])?,
            roster_position: read_optional_u16(&tuple.items[1])?,
            schedule_position: read_optional_u32(&tuple.items[2])?,
            top_count: read_optional_u16(&tuple.items[3])?,
            producer_sequence: read_optional_u64(&tuple.items[4])?,
            verifier_source_ordinal: read_u32(&tuple.items[5])?,
        })
    }

    fn to_tuple(&self) -> ArtifactResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            ROOT_ENDPOINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                optional_u16(self.roster_position)?,
                optional_u32(self.schedule_position)?,
                optional_u16(self.top_count)?,
                optional_u64(self.producer_sequence)?,
                CanonicalItem::unsigned32(self.verifier_source_ordinal),
            ],
        ))
    }
}

fn read_selector_path(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> ArtifactResult<Vec<RelationSelectorPathStepArtifact>> {
    read_nested_tuple_list(item, limits, MAXIMUM_SELECTOR_PATH_LENGTH)?
        .iter()
        .map(RelationSelectorPathStepArtifact::from_tuple)
        .collect()
}

fn selector_path_item(path: &[RelationSelectorPathStepArtifact]) -> ArtifactResult<CanonicalItem> {
    let tuples = path
        .iter()
        .copied()
        .map(RelationSelectorPathStepArtifact::to_tuple)
        .collect::<Vec<_>>();
    nested_tuple_list(&tuples)
}

fn read_instruction_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> ArtifactResult<Vec<RelationExpressionInstructionArtifact>> {
    read_nested_tuple_list(item, limits, MAXIMUM_PROGRAM_INSTRUCTION_COUNT)?
        .iter()
        .map(RelationExpressionInstructionArtifact::from_tuple)
        .collect()
}

fn instruction_list_item(
    instructions: &[RelationExpressionInstructionArtifact],
) -> ArtifactResult<CanonicalItem> {
    let tuples = instructions
        .iter()
        .map(RelationExpressionInstructionArtifact::to_tuple)
        .collect::<ArtifactResult<Vec<_>>>()?;
    nested_tuple_list(&tuples)
}

fn require_tuple(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> ArtifactResult<()> {
    if tuple.schema_identifier != schema_identifier {
        return Err(ProofProfileArtifactError::WrongSchema);
    }
    if tuple.schema_version != SCHEMA_VERSION {
        return Err(ProofProfileArtifactError::WrongVersion);
    }
    if tuple.items.len() != item_count {
        return Err(ProofProfileArtifactError::WrongItemCount);
    }
    Ok(())
}

fn read_fixed<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> ArtifactResult<[u8; BYTE_LENGTH]> {
    if item.item_type() != expected_type || item.canonical_bytes().len() != BYTE_LENGTH {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    let mut bytes = [0_u8; BYTE_LENGTH];
    bytes.copy_from_slice(item.canonical_bytes());
    Ok(bytes)
}

fn read_u8(item: &CanonicalItem) -> ArtifactResult<u8> {
    Ok(read_fixed::<1>(item, CanonicalItemType::Unsigned8)?[0])
}

fn read_u16(item: &CanonicalItem) -> ArtifactResult<u16> {
    Ok(u16::from_le_bytes(read_fixed::<2>(
        item,
        CanonicalItemType::Unsigned16,
    )?))
}

fn read_u32(item: &CanonicalItem) -> ArtifactResult<u32> {
    Ok(u32::from_le_bytes(read_fixed::<4>(
        item,
        CanonicalItemType::Unsigned32,
    )?))
}

fn read_u64(item: &CanonicalItem) -> ArtifactResult<u64> {
    Ok(u64::from_le_bytes(read_fixed::<8>(
        item,
        CanonicalItemType::Unsigned64,
    )?))
}

fn read_field_element(item: &CanonicalItem) -> ArtifactResult<u64> {
    Ok(u64::from_le_bytes(read_fixed::<8>(
        item,
        CanonicalItemType::FieldElement,
    )?))
}

fn read_ascii(item: &CanonicalItem) -> ArtifactResult<String> {
    if item.item_type() != CanonicalItemType::Ascii {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    let bytes = item.variable_value_bytes()?;
    let value = std::str::from_utf8(bytes).map_err(|_| ProofProfileArtifactError::InvalidValue)?;
    Ok(value.to_owned())
}

fn read_variable_bytes(item: &CanonicalItem) -> ArtifactResult<Vec<u8>> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    Ok(item.variable_value_bytes()?.to_vec())
}

fn read_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> ArtifactResult<CanonicalTuple> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    Ok(CanonicalTuple::decode(item.canonical_bytes(), limits)?)
}

fn read_optional_fixed<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    contained_type: CanonicalItemType,
) -> ArtifactResult<Option<[u8; BYTE_LENGTH]>> {
    if item.item_type() != CanonicalItemType::Optional {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 3
        || u16::from_le_bytes([bytes[0], bytes[1]]) != contained_type.canonical_code()
    {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == BYTE_LENGTH + 3 => {
            let mut value = [0_u8; BYTE_LENGTH];
            value.copy_from_slice(&bytes[3..]);
            Ok(Some(value))
        }
        _ => Err(ProofProfileArtifactError::InvalidValue),
    }
}

fn read_optional_u16(item: &CanonicalItem) -> ArtifactResult<Option<u16>> {
    Ok(read_optional_fixed::<2>(item, CanonicalItemType::Unsigned16)?.map(u16::from_le_bytes))
}

fn read_optional_u32(item: &CanonicalItem) -> ArtifactResult<Option<u32>> {
    Ok(read_optional_fixed::<4>(item, CanonicalItemType::Unsigned32)?.map(u32::from_le_bytes))
}

fn read_optional_u64(item: &CanonicalItem) -> ArtifactResult<Option<u64>> {
    Ok(read_optional_fixed::<8>(item, CanonicalItemType::Unsigned64)?.map(u64::from_le_bytes))
}

fn read_optional_nested_tuple(item: &CanonicalItem) -> ArtifactResult<Option<CanonicalTuple>> {
    if item.item_type() != CanonicalItemType::Optional {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 3
        || u16::from_le_bytes([bytes[0], bytes[1]])
            != CanonicalItemType::NestedTuple.canonical_code()
    {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 => Ok(Some(CanonicalTuple::decode(
            &bytes[3..],
            &CanonicalDecodeLimits::default(),
        )?)),
        _ => Err(ProofProfileArtifactError::InvalidValue),
    }
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
    maximum_count: usize,
) -> ArtifactResult<(usize, &[u8])> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(ProofProfileArtifactError::WrongItemType);
    }
    let count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if count > maximum_count {
        return Err(ProofProfileArtifactError::LimitExceeded);
    }
    Ok((count, &bytes[6..]))
}

fn read_fixed_list<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    element_type: CanonicalItemType,
    maximum_count: usize,
) -> ArtifactResult<Vec<[u8; BYTE_LENGTH]>> {
    let (count, payload) = read_list_header(item, element_type, maximum_count)?;
    let expected_length = count
        .checked_mul(BYTE_LENGTH)
        .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
    if payload.len() != expected_length {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    payload
        .chunks_exact(BYTE_LENGTH)
        .map(|chunk| {
            let mut value = [0_u8; BYTE_LENGTH];
            value.copy_from_slice(chunk);
            Ok(value)
        })
        .collect()
}

fn read_u32_list(item: &CanonicalItem, maximum_count: usize) -> ArtifactResult<Vec<u32>> {
    read_fixed_list::<4>(item, CanonicalItemType::Unsigned32, maximum_count)?
        .into_iter()
        .map(|value| Ok(u32::from_le_bytes(value)))
        .collect()
}

fn read_u64_list(item: &CanonicalItem, maximum_count: usize) -> ArtifactResult<Vec<u64>> {
    read_fixed_list::<8>(item, CanonicalItemType::Unsigned64, maximum_count)?
        .into_iter()
        .map(|value| Ok(u64::from_le_bytes(value)))
        .collect()
}

fn read_nested_tuple_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    maximum_count: usize,
) -> ArtifactResult<Vec<CanonicalTuple>> {
    let (count, payload) = read_list_header(item, CanonicalItemType::NestedTuple, maximum_count)?;
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0_usize;
    for _ in 0..count {
        let tuple_length = canonical_tuple_prefix_length(
            payload
                .get(offset..)
                .ok_or(ProofProfileArtifactError::InvalidValue)?,
        )?;
        let end = offset
            .checked_add(tuple_length)
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        let tuple_bytes = payload
            .get(offset..end)
            .ok_or(ProofProfileArtifactError::InvalidValue)?;
        tuples.push(CanonicalTuple::decode(tuple_bytes, limits)?);
        offset = end;
    }
    if offset != payload.len() {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    Ok(tuples)
}

fn canonical_tuple_prefix_length(bytes: &[u8]) -> ArtifactResult<usize> {
    if bytes.len() < 8 {
        return Err(ProofProfileArtifactError::InvalidValue);
    }
    let item_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header_end = offset
            .checked_add(6)
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        let header = bytes
            .get(offset..header_end)
            .ok_or(ProofProfileArtifactError::InvalidValue)?;
        let item_length = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        offset = header_end
            .checked_add(item_length)
            .ok_or(ProofProfileArtifactError::ArithmeticOverflow)?;
        if offset > bytes.len() {
            return Err(ProofProfileArtifactError::InvalidValue);
        }
    }
    Ok(offset)
}

fn nested_tuple_item(tuple: &CanonicalTuple) -> ArtifactResult<CanonicalItem> {
    Ok(CanonicalItem::nested_tuple(tuple)?)
}

fn nested_tuple_list(tuples: &[CanonicalTuple]) -> ArtifactResult<CanonicalItem> {
    let items = tuples
        .iter()
        .map(nested_tuple_item)
        .collect::<ArtifactResult<Vec<_>>>()?;
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::NestedTuple,
        &items,
    )?)
}

fn u32_list(values: &[u32]) -> ArtifactResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned32)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned32,
        &items,
    )?)
}

fn u64_list(values: &[u64]) -> ArtifactResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned64)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned64,
        &items,
    )?)
}

fn optional_u16(value: Option<u16>) -> ArtifactResult<CanonicalItem> {
    let item = value.map(CanonicalItem::unsigned16);
    Ok(CanonicalItem::optional(
        CanonicalItemType::Unsigned16,
        item.as_ref(),
    )?)
}

fn optional_u32(value: Option<u32>) -> ArtifactResult<CanonicalItem> {
    let item = value.map(CanonicalItem::unsigned32);
    Ok(CanonicalItem::optional(
        CanonicalItemType::Unsigned32,
        item.as_ref(),
    )?)
}

fn optional_u64(value: Option<u64>) -> ArtifactResult<CanonicalItem> {
    let item = value.map(CanonicalItem::unsigned64);
    Ok(CanonicalItem::optional(
        CanonicalItemType::Unsigned64,
        item.as_ref(),
    )?)
}

fn optional_nested_tuple(value: Option<&CanonicalTuple>) -> ArtifactResult<CanonicalItem> {
    let item = value.map(nested_tuple_item).transpose()?;
    Ok(CanonicalItem::optional(
        CanonicalItemType::NestedTuple,
        item.as_ref(),
    )?)
}

fn field_element_item(value: u64) -> ArtifactResult<CanonicalItem> {
    Ok(CanonicalItem::from_canonical_bytes(
        CanonicalItemType::FieldElement,
        value.to_le_bytes().to_vec(),
        &CanonicalDecodeLimits::default(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::build_relation_plan_catalog;

    fn unlowered_candidate() -> ProofProfileSetArtifact {
        let catalog = build_relation_plan_catalog(1, 1).expect("relation-plan catalog");
        ProofProfileSetArtifact::from_unlowered_relation_plan_catalog(&catalog)
            .expect("typed candidate")
    }

    fn common_field() -> ProofFieldProfileArtifact {
        unlowered_candidate().proof_fields.remove(0)
    }

    fn common_schedule() -> ProofFieldScheduleArtifact {
        unlowered_candidate()
            .proof_families
            .remove(0)
            .field_schedule
    }

    #[test]
    fn typed_candidate_round_trips_byte_identically_but_remains_fail_closed() {
        let candidate = unlowered_candidate();
        let encoded = candidate.encode().expect("candidate encoding");
        let decoded = ProofProfileSetArtifact::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("candidate decoding");
        assert_eq!(decoded, candidate);
        assert_eq!(decoded.encode().expect("round-trip encoding"), encoded);
        assert_eq!(
            decoded.validate(),
            Err(ProofProfileArtifactError::IncompleteSemanticPlan)
        );
    }

    #[test]
    fn canonical_profile_decoder_rejects_header_truncation_and_trailing_mutations() {
        let encoded = unlowered_candidate().encode().expect("candidate encoding");

        let mut wrong_schema = encoded.clone();
        wrong_schema[..2].copy_from_slice(&0x21ff_u16.to_le_bytes());
        assert_eq!(
            ProofProfileSetArtifact::decode(&wrong_schema, &CanonicalDecodeLimits::default(),),
            Err(ProofProfileArtifactError::WrongSchema)
        );

        let mut wrong_version = encoded.clone();
        wrong_version[2..4].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            ProofProfileSetArtifact::decode(&wrong_version, &CanonicalDecodeLimits::default(),),
            Err(ProofProfileArtifactError::WrongVersion)
        );

        for truncated_length in [0, 1, 7, encoded.len() - 1] {
            assert!(
                ProofProfileSetArtifact::decode(
                    &encoded[..truncated_length],
                    &CanonicalDecodeLimits::default(),
                )
                .is_err()
            );
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(
            ProofProfileSetArtifact::decode(&trailing, &CanonicalDecodeLimits::default()).is_err()
        );
    }

    #[test]
    fn duplicate_family_and_catalog_order_mutations_are_rejected() {
        let mut duplicate_family = unlowered_candidate();
        duplicate_family.proof_families[1].application_statement_schema_identifier =
            duplicate_family.proof_families[0].application_statement_schema_identifier;
        assert_eq!(
            duplicate_family.validate(),
            Err(ProofProfileArtifactError::InvalidOrdering)
        );

        let mut reordered_plan = unlowered_candidate();
        reordered_plan.relation_plans.swap(0, 1);
        assert_eq!(
            reordered_plan.validate(),
            Err(ProofProfileArtifactError::InvalidOrdering)
        );
        assert_eq!(
            require_strictly_increasing(&[1_u16, 1]),
            Err(ProofProfileArtifactError::InvalidOrdering)
        );
    }

    #[test]
    fn layouts_and_selector_paths_reject_overflow_and_ill_typed_steps() {
        let field = common_field();
        let overflowing_layout = RelationValueLayoutArtifact {
            element_kind: 2,
            residue_modulus: None,
            shape: vec![u64::MAX, 2],
            embedding_kind: 1,
        };
        assert_eq!(
            overflowing_layout.validate(&field),
            Err(ProofProfileArtifactError::ArithmeticOverflow)
        );
        let hash_array = RelationValueLayoutArtifact {
            element_kind: 1,
            residue_modulus: None,
            shape: vec![1],
            embedding_kind: 0,
        };
        assert_eq!(
            hash_array.validate(&field),
            Err(ProofProfileArtifactError::TypeMismatch)
        );

        assert_eq!(
            validate_selector_path(&[], SelectorPathRoot::ApplicationStatement),
            Err(ProofProfileArtifactError::LimitExceeded)
        );
        assert_eq!(
            validate_selector_path(
                &[RelationSelectorPathStepArtifact {
                    step_kind: 4,
                    argument: 1,
                }],
                SelectorPathRoot::ApplicationSlot,
            ),
            Err(ProofProfileArtifactError::InvalidValue)
        );
        assert_eq!(
            validate_selector_path(
                &[RelationSelectorPathStepArtifact {
                    step_kind: 8,
                    argument: 99,
                }],
                SelectorPathRoot::Suite,
            ),
            Err(ProofProfileArtifactError::InvalidValue)
        );
    }

    #[test]
    fn numerator_program_rejects_underflow_bad_rotations_and_catalog_indexes() {
        let columns = vec![RelationColumnArtifact {
            origin: RelationColumnOriginArtifact::Prover,
            value_type: 1,
            source_degree_bound_exclusive: 8,
        }];
        let schedule = common_schedule();
        let field = common_field();
        for program in [
            vec![RelationExpressionInstructionArtifact::Add],
            vec![RelationExpressionInstructionArtifact::ColumnValue {
                column_ordinal: 1,
                rotation_is_negative: 0,
                rotation_magnitude: 0,
            }],
            vec![RelationExpressionInstructionArtifact::ColumnValue {
                column_ordinal: 0,
                rotation_is_negative: 2,
                rotation_magnitude: 1,
            }],
            vec![RelationExpressionInstructionArtifact::TranscriptChallenge {
                challenge_role: 1,
                role_coordinates: vec![1, 0],
            }],
        ] {
            assert!(
                validate_numerator_program(&program, &columns, 16, 1, &schedule, &field,).is_err()
            );
        }
    }

    #[test]
    fn zeroifier_program_rejects_forbidden_zero_and_coset_vanishing_programs() {
        let schedule = common_schedule();
        let field = common_field();
        assert_eq!(
            compile_zeroifier_program(&[], 8, &schedule, &field),
            Err(ProofProfileArtifactError::LimitExceeded)
        );
        assert_eq!(
            compile_zeroifier_program(
                &[RelationExpressionInstructionArtifact::ColumnValue {
                    column_ordinal: 0,
                    rotation_is_negative: 0,
                    rotation_magnitude: 0,
                }],
                8,
                &schedule,
                &field,
            ),
            Err(ProofProfileArtifactError::TypeMismatch)
        );
        assert_eq!(
            compile_zeroifier_program(
                &[RelationExpressionInstructionArtifact::Constant(0)],
                8,
                &schedule,
                &field,
            ),
            Err(ProofProfileArtifactError::InvalidValue)
        );
        let vanishes_at_coset_origin = [
            RelationExpressionInstructionArtifact::EvaluationVariable,
            RelationExpressionInstructionArtifact::Constant(
                GOLDILOCKS_MODULUS - schedule.evaluation_coset_offset,
            ),
            RelationExpressionInstructionArtifact::Add,
        ];
        assert_eq!(
            compile_zeroifier_program(&vanishes_at_coset_origin, 8, &schedule, &field),
            Err(ProofProfileArtifactError::InvalidValue)
        );
        let trace_zeroifier = [
            RelationExpressionInstructionArtifact::EvaluationVariable,
            RelationExpressionInstructionArtifact::Power(8),
            RelationExpressionInstructionArtifact::Constant(GOLDILOCKS_MODULUS - 1),
            RelationExpressionInstructionArtifact::Add,
        ];
        assert_eq!(
            compile_zeroifier_program(&trace_zeroifier, 8, &schedule, &field)
                .expect("disjoint coset zeroifier")
                .degree,
            8
        );
    }

    #[test]
    fn opening_claims_reject_out_of_range_tree_and_point_indexes() {
        let mut variant = unlowered_candidate()
            .relation_plans
            .remove(0)
            .variants
            .remove(0);
        variant.ordered_opening_points = vec![RelationOpeningPointArtifact {
            deep_point_ordinal: 0,
            trace_rotation_is_negative: 0,
            trace_rotation_magnitude: 0,
            conjugate_index: 0,
        }];
        variant.ordered_opening_claims = vec![RelationOpeningClaimArtifact {
            source_class: 1,
            source_ordinal: u32::MAX,
            column_ordinal: Some(0),
            opening_point_ordinal: 0,
            source_degree_bound_exclusive: 1,
        }];
        let quotient_parameters = QuotientParameters {
            quotient_component_count: 2,
            quotient_component_degree_bound_exclusive: 8,
            quotient_mask_degree_bound: 4,
            trace_mask_degree_bound: 1,
            fri_fold_count: 1,
        };
        assert_eq!(
            variant.validate_opening_claims(&quotient_parameters),
            Err(ProofProfileArtifactError::UnresolvedIndex)
        );
        variant.ordered_opening_claims[0].source_class = 2;
        variant.ordered_opening_claims[0].source_ordinal = 0;
        variant.ordered_opening_claims[0].column_ordinal = None;
        variant.ordered_opening_claims[0].opening_point_ordinal = u32::MAX;
        assert_eq!(
            variant.validate_opening_claims(&quotient_parameters),
            Err(ProofProfileArtifactError::UnresolvedIndex)
        );
    }
}
