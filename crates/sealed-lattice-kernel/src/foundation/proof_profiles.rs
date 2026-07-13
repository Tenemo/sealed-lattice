use super::schemas::{
    SchemaResult, read_list_header, read_nested_tuple, read_nested_tuple_list, read_u16, read_u32,
    read_u64, require_header,
};
use super::suite_record::{is_prime_u64, modular_power, modular_product};
use super::{
    ArtifactKind, ArtifactReference, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, CollectivePublicKeyAggregationRelationPlan, FoundationSchemaError, ProofFamily,
    RELATION_PLAN_SCHEMA_IDENTIFIER, RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER, RefusalReason,
    SuiteRecord,
};

pub const PROOF_PROFILE_SET_SCHEMA_IDENTIFIER: u16 = 0x2200;
pub const PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2201;
pub const PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2202;
pub const PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER: u16 = 0x2203;
pub const PROOF_PROFILE_SET_MAXIMUM_BYTE_LENGTH: usize = 65_536;
pub const PROOF_PROFILE_MAXIMUM_CHALLENGE_EXTENSION_DEGREE: usize = 64;

const PROOF_PROFILE_SCHEMA_VERSION: u16 = 1;
const REQUIRED_PROOF_FAMILY_COUNT: usize = 12;
const MAXIMUM_PROOF_FIELD_COUNT: usize = REQUIRED_PROOF_FAMILY_COUNT;
const PROOF_FIELD_PROFILE_MAXIMUM_BYTE_LENGTH: usize = 560;
const PROOF_FIELD_SCHEDULE_MAXIMUM_BYTE_LENGTH: usize = 86;
const PROOF_FAMILY_PROFILE_MAXIMUM_BYTE_LENGTH: usize = 108;
const ORDERED_PROOF_PROFILE_FAMILIES: [ProofFamily; REQUIRED_PROOF_FAMILY_COUNT] = [
    ProofFamily::SameSecretLinkage,
    ProofFamily::PublicKeyShare,
    ProofFamily::CollectivePublicKeyAggregate,
    ProofFamily::RelinearizationRoundOne,
    ProofFamily::RelinearizationRoundOneAggregate,
    ProofFamily::RelinearizationRoundTwo,
    ProofFamily::GaloisKeyShare,
    ProofFamily::EvaluatorKeyAggregate,
    ProofFamily::BallotValidity,
    ProofFamily::PairedTargetShare,
    ProofFamily::SourceBatchedVerifiableSecretSharingLinkage,
    ProofFamily::AggregateThresholdShare,
];

/// One base field and its canonical challenge-extension representation.
///
/// Validation establishes primality, exact two-adic generator order, canonical
/// residues, and polynomial irreducibility. It does not establish that the
/// field size or extension degree provides a claimed security level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofFieldProfile {
    pub base_field_modulus: u64,
    pub maximum_two_adic_subgroup_generator: u64,
    pub monic_challenge_extension_polynomial_coefficients: Vec<u64>,
}

impl ProofFieldProfile {
    pub fn new(
        base_field_modulus: u64,
        maximum_two_adic_subgroup_generator: u64,
        monic_challenge_extension_polynomial_coefficients: Vec<u64>,
    ) -> SchemaResult<Self> {
        let profile = Self {
            base_field_modulus,
            maximum_two_adic_subgroup_generator,
            monic_challenge_extension_polynomial_coefficients,
        };
        profile.validate_intrinsic()?;
        Ok(profile)
    }

    pub fn challenge_extension_degree(&self) -> usize {
        self.monic_challenge_extension_polynomial_coefficients.len()
    }

    pub fn maximum_two_adic_subgroup_order(&self) -> u64 {
        1u64 << (self.base_field_modulus - 1).trailing_zeros()
    }

    pub fn validate_intrinsic(&self) -> SchemaResult<()> {
        let modulus = self.base_field_modulus;
        if modulus <= 2 || modulus.is_multiple_of(2) || !is_prime_u64(modulus) {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof base-field modulus must be an odd prime",
            ));
        }
        let extension_degree = self.challenge_extension_degree();
        if extension_degree == 0
            || extension_degree > PROOF_PROFILE_MAXIMUM_CHALLENGE_EXTENSION_DEGREE
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof challenge-extension degree is outside the bounded profile",
            ));
        }
        if self
            .monic_challenge_extension_polynomial_coefficients
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "proof challenge-extension coefficient is not a canonical base-field residue",
            ));
        }

        let generator = self.maximum_two_adic_subgroup_generator;
        if generator == 0 || generator >= modulus {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "proof two-adic generator is not a canonical nonzero base-field residue",
            ));
        }
        let maximum_two_adic_order = self.maximum_two_adic_subgroup_order();
        if modular_power(generator, maximum_two_adic_order, modulus) != 1
            || modular_power(generator, maximum_two_adic_order / 2, modulus) == 1
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof two-adic generator does not have the field's exact maximum two-adic order",
            ));
        }
        if !is_monic_polynomial_irreducible(
            &self.monic_challenge_extension_polynomial_coefficients,
            modulus,
        ) {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof challenge-extension polynomial is reducible over the base field",
            ));
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate_intrinsic()?;
        Ok(CanonicalTuple::new(
            PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER,
            PROOF_PROFILE_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.base_field_modulus),
                CanonicalItem::unsigned64(self.maximum_two_adic_subgroup_generator),
                encode_u64_list(&self.monic_challenge_extension_polynomial_coefficients)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            read_u64(&tuple.items[0])?,
            read_u64(&tuple.items[1])?,
            read_bounded_extension_polynomial(&tuple.items[2])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&decode_bounded_tuple(
            bytes,
            limits,
            PROOF_FIELD_PROFILE_MAXIMUM_BYTE_LENGTH,
            "proof field profile exceeds its bounded canonical length",
        )?)
    }
}

/// The immutable common-proof schedule selected by a suite family profile.
/// It contains no algorithm identifiers or proof-provided relation choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofFieldSchedule {
    pub proof_field_index: u16,
    pub evaluation_blowup_factor: u32,
    pub evaluation_coset_offset: u64,
    pub deep_point_count: u16,
    pub final_polynomial_degree_bound_exclusive: u32,
    pub unique_query_count: u32,
    pub non_native_modular_identity_challenge_count: u16,
    pub maximum_fiat_shamir_candidate_draws_per_output: u32,
}

impl ProofFieldSchedule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_field_index: u16,
        evaluation_blowup_factor: u32,
        evaluation_coset_offset: u64,
        deep_point_count: u16,
        final_polynomial_degree_bound_exclusive: u32,
        unique_query_count: u32,
        non_native_modular_identity_challenge_count: u16,
        maximum_fiat_shamir_candidate_draws_per_output: u32,
    ) -> SchemaResult<Self> {
        if evaluation_blowup_factor == 0 || !evaluation_blowup_factor.is_power_of_two() {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof evaluation blowup factor must be a nonzero power of two",
            ));
        }
        if evaluation_coset_offset <= 1 {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof evaluation coset offset must be nonzero and outside the trivial subgroup",
            ));
        }
        if deep_point_count == 0
            || final_polynomial_degree_bound_exclusive == 0
            || unique_query_count == 0
            || non_native_modular_identity_challenge_count == 0
            || maximum_fiat_shamir_candidate_draws_per_output == 0
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof DEEP, terminal-degree, query, non-native challenge, and Fiat-Shamir candidate-draw counts must be positive",
            ));
        }
        Ok(Self {
            proof_field_index,
            evaluation_blowup_factor,
            evaluation_coset_offset,
            deep_point_count,
            final_polynomial_degree_bound_exclusive,
            unique_query_count,
            non_native_modular_identity_challenge_count,
            maximum_fiat_shamir_candidate_draws_per_output,
        })
    }

    pub fn validate_intrinsic(&self) -> SchemaResult<()> {
        Self::new(
            self.proof_field_index,
            self.evaluation_blowup_factor,
            self.evaluation_coset_offset,
            self.deep_point_count,
            self.final_polynomial_degree_bound_exclusive,
            self.unique_query_count,
            self.non_native_modular_identity_challenge_count,
            self.maximum_fiat_shamir_candidate_draws_per_output,
        )?;
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate_intrinsic()?;
        Ok(CanonicalTuple::new(
            PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER,
            PROOF_PROFILE_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.proof_field_index),
                CanonicalItem::unsigned32(self.evaluation_blowup_factor),
                CanonicalItem::unsigned64(self.evaluation_coset_offset),
                CanonicalItem::unsigned16(self.deep_point_count),
                CanonicalItem::unsigned32(self.final_polynomial_degree_bound_exclusive),
                CanonicalItem::unsigned32(self.unique_query_count),
                CanonicalItem::unsigned16(self.non_native_modular_identity_challenge_count),
                CanonicalItem::unsigned32(self.maximum_fiat_shamir_candidate_draws_per_output),
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER, 8)?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_u32(&tuple.items[1])?,
            read_u64(&tuple.items[2])?,
            read_u16(&tuple.items[3])?,
            read_u32(&tuple.items[4])?,
            read_u32(&tuple.items[5])?,
            read_u16(&tuple.items[6])?,
            read_u32(&tuple.items[7])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&decode_bounded_tuple(
            bytes,
            limits,
            PROOF_FIELD_SCHEDULE_MAXIMUM_BYTE_LENGTH,
            "proof field schedule exceeds its bounded canonical length",
        )?)
    }
}

/// A closed application-statement family and its suite-selected schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofFamilyProfile {
    pub proof_family: ProofFamily,
    pub field_schedule: ProofFieldSchedule,
}

impl ProofFamilyProfile {
    pub fn new(
        proof_family: ProofFamily,
        field_schedule: ProofFieldSchedule,
    ) -> SchemaResult<Self> {
        field_schedule.validate_intrinsic()?;
        Ok(Self {
            proof_family,
            field_schedule,
        })
    }

    pub const fn application_statement_schema_identifier(&self) -> u16 {
        self.proof_family.statement_schema_identifier()
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.field_schedule.validate_intrinsic()?;
        Ok(CanonicalTuple::new(
            PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER,
            PROOF_PROFILE_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier()),
                CanonicalItem::nested_tuple(&self.field_schedule.canonical_tuple()?)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_header(tuple, PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER, 2)?;
        let statement_schema_identifier = read_u16(&tuple.items[0])?;
        let proof_family = ProofFamily::from_statement_schema_identifier(
            statement_schema_identifier,
        )
        .ok_or_else(|| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof family application-statement schema identifier is unassigned",
            )
        })?;
        let schedule_tuple = read_nested_tuple(&tuple.items[1], limits)?;
        Self::new(
            proof_family,
            ProofFieldSchedule::from_tuple(&schedule_tuple)?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(
            &decode_bounded_tuple(
                bytes,
                limits,
                PROOF_FAMILY_PROFILE_MAXIMUM_BYTE_LENGTH,
                "proof family profile exceeds its bounded canonical length",
            )?,
            limits,
        )
    }
}

/// The canonical suite artifact that maps every version-one proof family to an
/// immutable field schedule.
///
/// The current artifact embeds the exact deterministic public-only collective
/// public-key aggregation plan. It deliberately does not claim coverage for
/// the other proof families, common-proof acceptance, witness extraction, a
/// security level, or complete FRI soundness. Those remain separate work from
/// this first relation-plan slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofProfileSet {
    pub proof_fields: Vec<ProofFieldProfile>,
    pub proof_families: Vec<ProofFamilyProfile>,
    relation_plans: Vec<CanonicalTuple>,
    root_compatibility_edges: Vec<CanonicalTuple>,
}

impl ProofProfileSet {
    pub fn new(
        proof_fields: Vec<ProofFieldProfile>,
        proof_families: Vec<ProofFamilyProfile>,
        suite_record: &SuiteRecord,
    ) -> SchemaResult<Self> {
        let mut profile_set = Self {
            proof_fields,
            proof_families,
            relation_plans: Vec::new(),
            root_compatibility_edges: Vec::new(),
        };
        profile_set.validate_profile_catalog()?;
        let relation_plan =
            CollectivePublicKeyAggregationRelationPlan::for_suite(suite_record, &profile_set)?;
        profile_set.relation_plans.push(CanonicalTuple::decode(
            &relation_plan.encode(),
            &CanonicalDecodeLimits::default(),
        )?);
        profile_set.validate_intrinsic()?;
        Ok(profile_set)
    }

    pub fn validate_intrinsic(&self) -> SchemaResult<()> {
        self.validate_profile_catalog()?;
        validate_relation_plan_catalog(&self.relation_plans, &self.root_compatibility_edges)
    }

    fn validate_profile_catalog(&self) -> SchemaResult<()> {
        if self.proof_fields.is_empty() || self.proof_fields.len() > MAXIMUM_PROOF_FIELD_COUNT {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof profile set must contain between one and twelve proof fields",
            ));
        }
        let mut previous_modulus = None;
        for field in &self.proof_fields {
            field.validate_intrinsic()?;
            if previous_modulus.is_some_and(|previous| field.base_field_modulus <= previous) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "proof field moduli must be distinct and strictly increasing",
                ));
            }
            previous_modulus = Some(field.base_field_modulus);
        }

        if self.proof_families.len() != REQUIRED_PROOF_FAMILY_COUNT {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof profile set must contain exactly the twelve version-one proof families",
            ));
        }
        let mut referenced_fields = vec![false; self.proof_fields.len()];
        for (family_index, family_profile) in self.proof_families.iter().enumerate() {
            if family_profile.proof_family != ORDERED_PROOF_PROFILE_FAMILIES[family_index] {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "proof families must appear once each in application-statement identifier order",
                ));
            }
            family_profile.field_schedule.validate_intrinsic()?;
            let field_index = usize::from(family_profile.field_schedule.proof_field_index);
            let field = self.proof_fields.get(field_index).ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof family references a proof-field index outside the field catalog",
                )
            })?;
            validate_schedule_against_field(&family_profile.field_schedule, field)?;
            referenced_fields[field_index] = true;
        }
        if referenced_fields.iter().any(|is_referenced| !is_referenced) {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof profile set contains an unreferenced proof field",
            ));
        }
        Ok(())
    }

    pub fn validate_for_suite(&self, suite_record: &SuiteRecord) -> SchemaResult<()> {
        self.validate_intrinsic()?;
        let expected_relation_plan =
            CollectivePublicKeyAggregationRelationPlan::for_suite(suite_record, self)?.encode();
        if self.relation_plans[0].encode()? != expected_relation_plan {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "collective public-key aggregation relation plan does not match the suite",
            ));
        }
        Ok(())
    }

    pub fn collective_public_key_aggregation_relation_plan_bytes(&self) -> SchemaResult<Vec<u8>> {
        self.validate_intrinsic()?;
        Ok(self.relation_plans[0].encode()?)
    }

    pub fn field_and_schedule_for_family(
        &self,
        proof_family: ProofFamily,
    ) -> SchemaResult<(&ProofFieldProfile, &ProofFieldSchedule)> {
        self.validate_profile_catalog()?;
        let statement_schema_identifier = proof_family.statement_schema_identifier();
        let family_index = self
            .proof_families
            .binary_search_by_key(&statement_schema_identifier, |profile| {
                profile.application_statement_schema_identifier()
            })
            .map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof family is absent from the suite proof profile",
                )
            })?;
        let schedule = &self.proof_families[family_index].field_schedule;
        Ok((
            &self.proof_fields[usize::from(schedule.proof_field_index)],
            schedule,
        ))
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate_intrinsic()?;
        let field_items = self
            .proof_fields
            .iter()
            .map(|field| CanonicalItem::nested_tuple(&field.canonical_tuple()?).map_err(Into::into))
            .collect::<SchemaResult<Vec<_>>>()?;
        let family_items = self
            .proof_families
            .iter()
            .map(|family| {
                CanonicalItem::nested_tuple(&family.canonical_tuple()?).map_err(Into::into)
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let relation_plan_items = self
            .relation_plans
            .iter()
            .map(|relation_plan| CanonicalItem::nested_tuple(relation_plan).map_err(Into::into))
            .collect::<SchemaResult<Vec<_>>>()?;
        let root_compatibility_edge_items = self
            .root_compatibility_edges
            .iter()
            .map(|edge| CanonicalItem::nested_tuple(edge).map_err(Into::into))
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            PROOF_PROFILE_SET_SCHEMA_IDENTIFIER,
            PROOF_PROFILE_SCHEMA_VERSION,
            vec![
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &field_items)?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &family_items)?,
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &relation_plan_items,
                )?,
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &root_compatibility_edge_items,
                )?,
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let encoded = self.canonical_tuple()?.encode()?;
        require_profile_set_byte_bound(encoded.len())?;
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_profile_set_byte_bound(bytes.len())?;
        let mut bounded_limits = *limits;
        bounded_limits.maximum_tuple_byte_length = bounded_limits
            .maximum_tuple_byte_length
            .min(PROOF_PROFILE_SET_MAXIMUM_BYTE_LENGTH);
        bounded_limits.maximum_item_byte_length = bounded_limits
            .maximum_item_byte_length
            .min(PROOF_PROFILE_SET_MAXIMUM_BYTE_LENGTH);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, PROOF_PROFILE_SET_SCHEMA_IDENTIFIER, 4)?;
        require_nested_tuple_count(
            &tuple.items[0],
            1,
            MAXIMUM_PROOF_FIELD_COUNT,
            "proof profile field count is outside the bounded profile",
        )?;
        require_nested_tuple_count(
            &tuple.items[1],
            REQUIRED_PROOF_FAMILY_COUNT,
            REQUIRED_PROOF_FAMILY_COUNT,
            "proof profile family count must be exactly twelve",
        )?;
        require_nested_tuple_count(
            &tuple.items[2],
            1,
            1,
            "proof profile relation-plan count must be exactly one in the implemented slice",
        )?;
        require_nested_tuple_count(
            &tuple.items[3],
            0,
            0,
            "proof profile root compatibility edges require producer relation plans",
        )?;
        let proof_fields = read_nested_tuple_list(&tuple.items[0], &bounded_limits)?
            .iter()
            .map(ProofFieldProfile::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        let proof_families = read_nested_tuple_list(&tuple.items[1], &bounded_limits)?
            .iter()
            .map(|family| ProofFamilyProfile::from_tuple(family, &bounded_limits))
            .collect::<SchemaResult<Vec<_>>>()?;
        let profile_set = Self {
            proof_fields,
            proof_families,
            relation_plans: read_nested_tuple_list(&tuple.items[2], &bounded_limits)?,
            root_compatibility_edges: read_nested_tuple_list(&tuple.items[3], &bounded_limits)?,
        };
        profile_set.validate_intrinsic()?;
        Ok(profile_set)
    }

    pub fn decode_for_suite(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        suite_record: &SuiteRecord,
    ) -> SchemaResult<Self> {
        let profile_set = Self::decode(bytes, limits)?;
        profile_set.validate_for_suite(suite_record)?;
        Ok(profile_set)
    }

    pub fn artifact_reference(&self) -> SchemaResult<ArtifactReference> {
        ArtifactReference::from_artifact_bytes(ArtifactKind::ProofProfileSet, &self.encode()?)
    }

    pub fn decode_verified_artifact(
        reference: &ArtifactReference,
        canonical_artifact_bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        suite_record: &SuiteRecord,
    ) -> SchemaResult<Self> {
        if reference.artifact_kind != ArtifactKind::ProofProfileSet {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "suite artifact reference does not identify a proof-profile set",
            ));
        }
        reference.verify_artifact_bytes(canonical_artifact_bytes)?;
        Self::decode_for_suite(canonical_artifact_bytes, limits, suite_record)
    }
}

fn validate_relation_plan_catalog(
    relation_plans: &[CanonicalTuple],
    root_compatibility_edges: &[CanonicalTuple],
) -> SchemaResult<()> {
    if relation_plans.len() != 1 {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof profile set must contain the collective public-key aggregation relation plan",
        ));
    }
    let relation_plan = &relation_plans[0];
    require_header(relation_plan, RELATION_PLAN_SCHEMA_IDENTIFIER, 2)?;
    if read_u16(&relation_plan.items[0])?
        != ProofFamily::CollectivePublicKeyAggregate.statement_schema_identifier()
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof profile relation plan has the wrong application statement",
        ));
    }
    let variants =
        read_nested_tuple_list(&relation_plan.items[1], &CanonicalDecodeLimits::default())?;
    if variants.len() != 1 {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation relation plan must contain one variant",
        ));
    }
    require_header(&variants[0], RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER, 15)?;
    if !root_compatibility_edges.is_empty() {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "root compatibility edges require their producer relation plans",
        ));
    }
    Ok(())
}

fn validate_schedule_against_field(
    schedule: &ProofFieldSchedule,
    field: &ProofFieldProfile,
) -> SchemaResult<()> {
    let modulus = field.base_field_modulus;
    if schedule.evaluation_coset_offset >= modulus {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "proof evaluation coset offset is not a canonical base-field residue",
        ));
    }
    let maximum_two_adic_order = field.maximum_two_adic_subgroup_order();
    if u64::from(schedule.evaluation_blowup_factor) > maximum_two_adic_order {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof evaluation blowup does not fit the selected field's two-adic subgroup",
        ));
    }
    let terminal_domain_capacity = u64::from(schedule.final_polynomial_degree_bound_exclusive)
        .checked_next_power_of_two()
        .ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof terminal polynomial capacity overflows its canonical power-of-two domain",
            )
        })?;
    if terminal_domain_capacity > maximum_two_adic_order {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof terminal polynomial bound does not fit the selected field's two-adic subgroup",
        ));
    }
    if u64::from(schedule.unique_query_count) > maximum_two_adic_order {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof distinct query count exceeds the selected field's maximum two-adic domain",
        ));
    }
    if !extension_field_has_at_least(
        modulus,
        field.challenge_extension_degree(),
        u64::from(schedule.deep_point_count),
    ) {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof DEEP-point count exceeds the selected extension field",
        ));
    }
    Ok(())
}

fn extension_field_has_at_least(modulus: u64, degree: usize, required_count: u64) -> bool {
    let mut cardinality = 1u128;
    for _ in 0..degree {
        let Some(next_cardinality) = cardinality.checked_mul(u128::from(modulus)) else {
            return true;
        };
        cardinality = next_cardinality;
        if cardinality >= u128::from(required_count) {
            return true;
        }
    }
    cardinality >= u128::from(required_count)
}

fn is_monic_polynomial_irreducible(coefficients: &[u64], modulus: u64) -> bool {
    let degree = coefficients.len();
    if degree == 1 {
        return true;
    }
    if coefficients[0] == 0 {
        return false;
    }

    let mut monic_polynomial = coefficients.to_vec();
    monic_polynomial.push(1);
    let indeterminate = polynomial_remainder(&[0, 1], &monic_polynomial, modulus);
    let required_greatest_common_divisor_iterations = prime_divisors(degree)
        .into_iter()
        .map(|prime_divisor| degree / prime_divisor)
        .collect::<Vec<_>>();
    let mut frobenius_power = indeterminate.clone();
    for iteration in 1..=degree {
        frobenius_power =
            polynomial_power_remainder(&frobenius_power, modulus, &monic_polynomial, modulus);
        if required_greatest_common_divisor_iterations.contains(&iteration) {
            let difference = polynomial_difference(&frobenius_power, &indeterminate, modulus);
            if !polynomial_greatest_common_divisor_is_one(&monic_polynomial, &difference, modulus) {
                return false;
            }
        }
    }
    normalized_polynomial(frobenius_power) == normalized_polynomial(indeterminate)
}

fn prime_divisors(mut value: usize) -> Vec<usize> {
    let mut divisors = Vec::new();
    let mut candidate = 2usize;
    while candidate <= value / candidate {
        if value.is_multiple_of(candidate) {
            divisors.push(candidate);
            while value.is_multiple_of(candidate) {
                value /= candidate;
            }
        }
        candidate += 1;
    }
    if value > 1 {
        divisors.push(value);
    }
    divisors
}

fn polynomial_power_remainder(
    base: &[u64],
    mut exponent: u64,
    divisor: &[u64],
    modulus: u64,
) -> Vec<u64> {
    let mut result = vec![1];
    let mut current_power = polynomial_remainder(base, divisor, modulus);
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = polynomial_remainder(
                &polynomial_product(&result, &current_power, modulus),
                divisor,
                modulus,
            );
        }
        exponent >>= 1;
        if exponent > 0 {
            current_power = polynomial_remainder(
                &polynomial_product(&current_power, &current_power, modulus),
                divisor,
                modulus,
            );
        }
    }
    result
}

fn polynomial_product(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    let mut product = vec![0u64; left.len() + right.len() - 1];
    for (left_index, left_coefficient) in left.iter().copied().enumerate() {
        for (right_index, right_coefficient) in right.iter().copied().enumerate() {
            let product_index = left_index + right_index;
            product[product_index] = modular_sum(
                product[product_index],
                modular_product(left_coefficient, right_coefficient, modulus),
                modulus,
            );
        }
    }
    normalized_polynomial(product)
}

fn polynomial_difference(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    let mut difference = vec![0u64; left.len().max(right.len())];
    for (index, output) in difference.iter_mut().enumerate() {
        *output = modular_difference(
            left.get(index).copied().unwrap_or(0),
            right.get(index).copied().unwrap_or(0),
            modulus,
        );
    }
    normalized_polynomial(difference)
}

fn polynomial_greatest_common_divisor_is_one(left: &[u64], right: &[u64], modulus: u64) -> bool {
    let mut left = normalized_polynomial(left.to_vec());
    let mut right = normalized_polynomial(right.to_vec());
    while !polynomial_is_zero(&right) {
        let remainder = polynomial_remainder(&left, &right, modulus);
        left = right;
        right = remainder;
    }
    left.len() == 1 && left[0] != 0
}

fn polynomial_remainder(numerator: &[u64], denominator: &[u64], modulus: u64) -> Vec<u64> {
    let mut remainder = normalized_polynomial(numerator.to_vec());
    let denominator = normalized_polynomial(denominator.to_vec());
    debug_assert!(!polynomial_is_zero(&denominator));
    let denominator_leading_inverse = modular_power(
        *denominator
            .last()
            .expect("a normalized polynomial is nonempty"),
        modulus - 2,
        modulus,
    );
    while !polynomial_is_zero(&remainder) && remainder.len() >= denominator.len() {
        let shift = remainder.len() - denominator.len();
        let cancellation_factor = modular_product(
            *remainder
                .last()
                .expect("a normalized polynomial is nonempty"),
            denominator_leading_inverse,
            modulus,
        );
        for (denominator_index, denominator_coefficient) in denominator.iter().copied().enumerate()
        {
            let remainder_index = shift + denominator_index;
            remainder[remainder_index] = modular_difference(
                remainder[remainder_index],
                modular_product(cancellation_factor, denominator_coefficient, modulus),
                modulus,
            );
        }
        remainder = normalized_polynomial(remainder);
    }
    remainder
}

fn polynomial_is_zero(polynomial: &[u64]) -> bool {
    polynomial.len() == 1 && polynomial[0] == 0
}

fn normalized_polynomial(mut polynomial: Vec<u64>) -> Vec<u64> {
    while polynomial.len() > 1 && polynomial.last() == Some(&0) {
        polynomial.pop();
    }
    if polynomial.is_empty() {
        polynomial.push(0);
    }
    polynomial
}

fn modular_sum(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

fn modular_difference(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        modulus - (right - left)
    }
}

fn encode_u64_list(values: &[u64]) -> SchemaResult<CanonicalItem> {
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

fn read_bounded_extension_polynomial(item: &CanonicalItem) -> SchemaResult<Vec<u64>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned64)?;
    if count == 0 || count > PROOF_PROFILE_MAXIMUM_CHALLENGE_EXTENSION_DEGREE {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof challenge-extension coefficient count is outside the bounded profile",
        ));
    }
    let expected_byte_length = count.checked_mul(size_of::<u64>()).ok_or_else(|| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "proof challenge-extension coefficient byte length overflows",
        )
    })?;
    if bytes.len() != expected_byte_length {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "proof challenge-extension coefficient list has the wrong byte length",
        ));
    }
    bytes
        .chunks_exact(size_of::<u64>())
        .map(|chunk| {
            let coefficient_bytes: [u8; size_of::<u64>()] = chunk.try_into().map_err(|_| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "proof challenge-extension coefficient has the wrong byte length",
                )
            })?;
            Ok(u64::from_le_bytes(coefficient_bytes))
        })
        .collect()
}

fn require_nested_tuple_count(
    item: &CanonicalItem,
    minimum_count: usize,
    maximum_count: usize,
    message: &'static str,
) -> SchemaResult<()> {
    let (count, _) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if !(minimum_count..=maximum_count).contains(&count) {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            message,
        ));
    }
    Ok(())
}

fn require_profile_set_byte_bound(byte_length: usize) -> SchemaResult<()> {
    if byte_length > PROOF_PROFILE_SET_MAXIMUM_BYTE_LENGTH {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof profile set exceeds the 65,536-byte decode bound",
        ));
    }
    Ok(())
}

fn decode_bounded_tuple(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
    maximum_byte_length: usize,
    bound_message: &'static str,
) -> SchemaResult<CanonicalTuple> {
    if bytes.len() > maximum_byte_length {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            bound_message,
        ));
    }
    let mut bounded_limits = *limits;
    bounded_limits.maximum_tuple_byte_length = bounded_limits
        .maximum_tuple_byte_length
        .min(maximum_byte_length);
    bounded_limits.maximum_item_byte_length = bounded_limits
        .maximum_item_byte_length
        .min(maximum_byte_length);
    Ok(CanonicalTuple::decode(bytes, &bounded_limits)?)
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
mod tests;
