//! Canonical proof-profile artifact generation.
//!
//! The artifact is constructed only from checked field schedules and checked
//! relation plans.  It deliberately has no permissive "unknown profile"
//! representation: a missing family, an unvalidated plan, or an unresolved
//! root edge prevents artifact generation.

#[cfg(test)]
use std::collections::BTreeSet;

use crate::foundation::{FOUNDATION_PROFILE, ProofApplicationSlotCeilings as ProofFamilies};

#[cfg(test)]
use crate::{
    bgv::evaluator::candidate_evidence::EvaluatorCandidateInput,
    bgv::setup::SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
    foundation::{
        ArtifactKind, ArtifactReference, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
        CanonicalTuple,
    },
};

#[cfg(test)]
use super::relation_plan::{
    BoundTreeConstructionKind, BoundTreeRootUse, RelationColumnValueType, RelationTreeDescriptor,
};

#[cfg(test)]
use super::row_code_whir::{
    ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN, ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
    ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN, ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN,
    ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT, ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN,
    RowCodeWhirConstructionPlan, RowCodeWhirSelectedParameters, RowCodeWhirSoundnessAssumption,
};

#[cfg(test)]
use super::transcript::{
    TRANSCRIPT_ABSORB_DOMAIN_BYTES, TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN_BYTES,
    TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN_BYTES, TRANSCRIPT_DISTINCT_QUERY_BLOCK_DOMAIN_BYTES,
    TRANSCRIPT_INITIAL_DOMAIN_BYTES, TRANSCRIPT_PRODUCT_RESIDUE_BLOCK_DOMAIN_BYTES,
    TRANSCRIPT_RESPONSE_BINDING_DOMAIN_BYTES,
};

use super::{
    CompiledRelationPlan, RelationPlanCheckContext, RelationPlanError, SelectedEvaluatorEntryKind,
    selected_evaluator_entry_positions, selected_relation_plan_check_context,
};

#[cfg(test)]
use super::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_CHALLENGE_EXTENSION_POLYNOMIAL_COEFFICIENTS,
    RelationPlanVariant, SuiteModulusReference, validate_proof_field_profile,
    zero_knowledge::{TraceMaskObservationCoordinateCatalog, TraceMaskSurjectivityCertificate},
};

#[cfg(test)]
const PROOF_PROFILE_SET_SCHEMA_IDENTIFIER: u16 = 0x2200;
#[cfg(test)]
const PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2201;
#[cfg(test)]
const PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2202;
#[cfg(test)]
const RELATION_PLAN_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x222c;
#[cfg(test)]
const RELATION_ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER: u16 = 0x222a;
#[cfg(test)]
const RELATION_ROOT_ENDPOINT_SCHEMA_IDENTIFIER: u16 = 0x222b;
#[cfg(test)]
const ROW_CODE_WHIR_CONSTRUCTION_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2254;
#[cfg(test)]
const ROW_CODE_WHIR_CONSTRUCTION_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x2255;
#[cfg(test)]
const ROW_CODE_WHIR_HASH_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x2256;
#[cfg(test)]
const SCHEMA_VERSION: u16 = 1;
#[cfg(test)]
const PROOF_FAMILY_PROFILE_SCHEMA_VERSION: u16 = 2;
#[cfg(test)]
const PROOF_PROFILE_SET_VERSION: u16 = 4;
#[cfg(test)]
const SELECTED_ROW_CODE_WHIR_CONSTRUCTION_REFERENCE_COUNT: usize = 31;
#[cfg(test)]
const ROW_CODE_WHIR_HASH_ALGORITHM_IDENTIFIER: &str = "SHAKE256";
#[cfg(test)]
const ROW_CODE_WHIR_DIGEST_BYTE_LENGTH: u16 = 64;

pub(crate) const FIRST_PROFILE_APPLICATION_FAMILIES: [u16; 12] = [
    ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
];

pub(crate) const PROOF_EVALUATION_COSET_OFFSET: u64 = 7;
// BGKTTZ23's correlated-hIOP composition theorem has one final random
// out-of-domain center and permits every plan-fixed rotation of that center.
// A second independently sampled center is a different protocol and would
// need a separate composition theorem. The degree-five challenge extension
// already gives the one-center application identity ample soundness margin.
pub(crate) const PROOF_OUT_OF_DOMAIN_POINT_COUNT: u16 = 1;
pub(crate) const PROOF_NON_NATIVE_THETA_REPETITION_COUNT: u16 = 5;
pub(crate) const PROOF_NON_NATIVE_ALPHA_REPETITION_COUNT: u16 = 7;
pub(crate) const PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofProfileError {
    CanonicalEncoding,
    #[cfg(test)]
    InvalidField,
    InvalidSchedule,
    UnsupportedFamily,
    #[cfg(test)]
    MissingFamily,
    #[cfg(test)]
    NonCanonicalOrder,
    InvalidRelationPlan,
    #[cfg(test)]
    InvalidConstructionProfile,
    RelationPlan(RelationPlanError),
    #[cfg(test)]
    InvalidRootEndpoint,
    InvalidRootTopology,
    #[cfg(test)]
    MissingRootProducer,
    #[cfg(test)]
    AmbiguousRootProducer,
    #[cfg(test)]
    IncompatibleRoot,
    #[cfg(test)]
    InsufficientRootMaskImage,
    #[cfg(test)]
    DuplicateRootEdge,
    CountOverflow,
}

impl From<RelationPlanError> for ProofProfileError {
    fn from(error: RelationPlanError) -> Self {
        Self::RelationPlan(error)
    }
}

#[cfg(test)]
fn canonical_encoding_error<T>(_: T) -> ProofProfileError {
    ProofProfileError::CanonicalEncoding
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofFieldProfile {
    base_field_modulus: u64,
    maximum_two_adic_subgroup_generator: u64,
    monic_challenge_extension_polynomial_coefficients: Vec<u64>,
}

#[cfg(test)]
impl ProofFieldProfile {
    pub(crate) fn selected() -> Result<Self, ProofProfileError> {
        validate_proof_field_profile().map_err(|_| ProofProfileError::InvalidField)?;
        Ok(Self {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            maximum_two_adic_subgroup_generator: PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
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
                canonical_u64_list(&self.monic_challenge_extension_polynomial_coefficients)?,
            ],
        ))
    }
}

fn matches_selected_relation_context(
    application_statement_schema_identifier: u16,
    context: &RelationPlanCheckContext,
) -> bool {
    selected_relation_plan_check_context(application_statement_schema_identifier)
        .is_some_and(|selected_context| selected_context == *context)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofFamilyProfile {
    application_statement_schema_identifier: u16,
    proof_field_index: u16,
}

impl ProofFamilyProfile {
    pub(crate) fn selected(
        application_statement_schema_identifier: u16,
    ) -> Result<Self, ProofProfileError> {
        if !FIRST_PROFILE_APPLICATION_FAMILIES.contains(&application_statement_schema_identifier) {
            return Err(ProofProfileError::UnsupportedFamily);
        }
        Ok(Self {
            application_statement_schema_identifier,
            proof_field_index: 0,
        })
    }

    #[cfg(test)]
    fn validate(&self, proof_field_count: usize) -> Result<(), ProofProfileError> {
        if !FIRST_PROFILE_APPLICATION_FAMILIES
            .contains(&self.application_statement_schema_identifier)
        {
            return Err(ProofProfileError::UnsupportedFamily);
        }
        if usize::from(self.proof_field_index) >= proof_field_count
            || self != &Self::selected(self.application_statement_schema_identifier)?
        {
            return Err(ProofProfileError::InvalidSchedule);
        }
        Ok(())
    }

    #[cfg(test)]
    fn canonical_tuple(&self) -> Result<CanonicalTuple, ProofProfileError> {
        self.validate(1)?;
        Ok(CanonicalTuple::new(
            PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER,
            PROOF_FAMILY_PROFILE_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::unsigned16(self.proof_field_index),
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedRelationPlanArtifact {
    application_statement_schema_identifier: u16,
    canonical_plan_byte_length: u64,
    canonical_plan_hash: [u8; 64],
    checked_context: RelationPlanCheckContext,
    compiled_plan: CompiledRelationPlan,
}

impl ValidatedRelationPlanArtifact {
    pub(crate) fn from_compiled_plan(
        plan: &CompiledRelationPlan,
        context: &RelationPlanCheckContext,
    ) -> Result<Self, ProofProfileError> {
        Self::from_owned_compiled_plan(plan.clone(), context)
    }

    pub(crate) fn from_owned_compiled_plan(
        plan: CompiledRelationPlan,
        context: &RelationPlanCheckContext,
    ) -> Result<Self, ProofProfileError> {
        let application_statement_schema_identifier = Self::check_plan_for_family(&plan, context)?;
        if !matches_selected_relation_context(application_statement_schema_identifier, context) {
            return Err(ProofProfileError::InvalidSchedule);
        }
        Self::from_checked_plan(plan, context, application_statement_schema_identifier)
    }

    #[cfg(test)]
    pub(crate) fn from_checked_fixture_plan(
        plan: &CompiledRelationPlan,
        context: &RelationPlanCheckContext,
    ) -> Result<Self, ProofProfileError> {
        let application_statement_schema_identifier = Self::check_plan_for_family(plan, context)?;
        Self::from_checked_plan(
            plan.clone(),
            context,
            application_statement_schema_identifier,
        )
    }

    fn check_plan_for_family(
        plan: &CompiledRelationPlan,
        context: &RelationPlanCheckContext,
    ) -> Result<u16, ProofProfileError> {
        plan.check(context)?;
        let application_statement_schema_identifier =
            plan.application_statement_schema_identifier();
        ProofFamilyProfile::selected(application_statement_schema_identifier)?;
        Ok(application_statement_schema_identifier)
    }

    fn from_checked_plan(
        plan: CompiledRelationPlan,
        context: &RelationPlanCheckContext,
        application_statement_schema_identifier: u16,
    ) -> Result<Self, ProofProfileError> {
        let (canonical_plan_byte_length, canonical_plan_hash) =
            plan.canonical_byte_length_and_hash()?;
        if canonical_plan_byte_length == 0 {
            return Err(ProofProfileError::CanonicalEncoding);
        }
        Ok(Self {
            application_statement_schema_identifier,
            canonical_plan_byte_length,
            canonical_plan_hash,
            checked_context: context.clone(),
            compiled_plan: plan,
        })
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn canonical_plan_hash(&self) -> [u8; 64] {
        self.canonical_plan_hash
    }

    pub(in crate::bgv::proof_suite) const fn checked_context(&self) -> &RelationPlanCheckContext {
        &self.checked_context
    }

    #[cfg(test)]
    fn canonical_reference_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_PLAN_REFERENCE_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::unsigned64(self.canonical_plan_byte_length),
                CanonicalItem::hash512(self.canonical_plan_hash),
            ],
        )
    }

    pub(crate) fn compiled_plan(&self) -> &CompiledRelationPlan {
        &self.compiled_plan
    }
}

#[cfg(test)]
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
    #[cfg(test)]
    const fn application_statement_schema_identifier(self) -> u16 {
        match self {
            Self::Relinearization => {
                ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
            }
            Self::Galois => ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorKeyAggregateEntryTopology {
    source_kind: EvaluatorKeyShareSourceKind,
    producer_schedule_position: u32,
    producer_output_ordinal: u32,
}

impl EvaluatorKeyAggregateEntryTopology {
    pub(crate) const fn source_kind(self) -> EvaluatorKeyShareSourceKind {
        self.source_kind
    }

    pub(crate) const fn producer_schedule_position(self) -> u32 {
        self.producer_schedule_position
    }

    pub(crate) const fn producer_output_ordinal(self) -> u32 {
        self.producer_output_ordinal
    }
}

/// Instance topology needed to expand relation-plan variants into concrete
/// application slots.  It carries semantic ceremony choices, never raw root
/// endpoints or edges; the profile derives those from the checked plans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FirstProfileRootTopology {
    roster_size: u16,
    ordered_evaluator_key_entries_by_top_count: Vec<Vec<EvaluatorKeyAggregateEntryTopology>>,
    ordered_ballot_producer_sequences: Vec<u64>,
}

impl FirstProfileRootTopology {
    pub(crate) fn selected(
        maximum_ballot_attempts_per_participant: u16,
    ) -> Result<Self, ProofProfileError> {
        if maximum_ballot_attempts_per_participant == 0 {
            return Err(ProofProfileError::InvalidRootTopology);
        }
        let topology = Self {
            roster_size: FOUNDATION_PROFILE.participant_count,
            ordered_evaluator_key_entries_by_top_count:
                Self::selected_evaluator_key_entries_by_top_count()?,
            ordered_ballot_producer_sequences: (0..u64::from(
                maximum_ballot_attempts_per_participant,
            ))
                .collect(),
        };
        topology.validate()?;
        Ok(topology)
    }

    pub(crate) const fn roster_size(&self) -> u16 {
        self.roster_size
    }

    pub(crate) fn evaluator_key_entries(
        &self,
        top_count: u16,
    ) -> Result<&[EvaluatorKeyAggregateEntryTopology], ProofProfileError> {
        self.ordered_evaluator_key_entries_by_top_count
            .get(usize::from(
                top_count
                    .checked_sub(1)
                    .ok_or(ProofProfileError::InvalidRootTopology)?,
            ))
            .map(Vec::as_slice)
            .ok_or(ProofProfileError::InvalidRootTopology)
    }

    fn validate(&self) -> Result<(), ProofProfileError> {
        if self.roster_size != FOUNDATION_PROFILE.participant_count
            || self.ordered_evaluator_key_entries_by_top_count.len()
                != usize::from(FOUNDATION_PROFILE.option_count)
            || self
                .ordered_evaluator_key_entries_by_top_count
                .iter()
                .any(Vec::is_empty)
            || self.ordered_ballot_producer_sequences.is_empty()
            || self
                .ordered_ballot_producer_sequences
                .iter()
                .copied()
                .enumerate()
                .any(|(ordinal, producer_sequence)| {
                    u64::try_from(ordinal).ok() != Some(producer_sequence)
                })
        {
            return Err(ProofProfileError::InvalidRootTopology);
        }

        let selected = Self::selected_evaluator_key_entries_by_top_count()?;
        if self.ordered_evaluator_key_entries_by_top_count != selected {
            return Err(ProofProfileError::InvalidRootTopology);
        }
        Ok(())
    }

    fn selected_evaluator_key_entries_by_top_count()
    -> Result<Vec<Vec<EvaluatorKeyAggregateEntryTopology>>, ProofProfileError> {
        (1..=FOUNDATION_PROFILE.option_count)
            .map(|top_count| {
                let entries = selected_evaluator_entry_positions(top_count)
                    .map_err(|_| ProofProfileError::InvalidRootTopology)?
                    .into_iter()
                    .map(|position| match position.key_kind() {
                        SelectedEvaluatorEntryKind::Relinearization { .. } => {
                            EvaluatorKeyAggregateEntryTopology {
                                source_kind: EvaluatorKeyShareSourceKind::Relinearization,
                                producer_schedule_position: position.schedule_position(),
                                producer_output_ordinal: 0,
                            }
                        }
                        SelectedEvaluatorEntryKind::Galois { .. } => {
                            EvaluatorKeyAggregateEntryTopology {
                                source_kind: EvaluatorKeyShareSourceKind::Galois,
                                producer_schedule_position: 0,
                                producer_output_ordinal: position.schedule_position(),
                            }
                        }
                    })
                    .collect::<Vec<_>>();
                Ok(entries)
            })
            .collect()
    }
}

#[cfg(test)]
use canonical_profile_artifact::canonical_u64_list;

#[cfg(test)]
pub(crate) use canonical_profile_artifact::ProofProfileSet;

#[cfg(test)]
mod canonical_profile_artifact {
    use super::*;

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
                ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
            );
            let schedule_expected = matches!(
                family,
                ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            );
            let top_count_expected =
                family == ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
            let producer_sequence_expected =
                family == ProofFamilies::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
            if self.roster_position.is_some() != roster_expected
                || self.schedule_position.is_some() != schedule_expected
                || self.top_count.is_some() != top_count_expected
                || self.producer_sequence.is_some() != producer_sequence_expected
                || self
                    .top_count
                    .is_some_and(|top_count| !(1..=20).contains(&top_count))
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RowCodeWhirParameterProfile {
        logical_polynomial_coefficient_count: u64,
        logical_polynomials_per_physical_row: u64,
        physical_row_witness_variable_count: u64,
        row_code_log_inverse_rate: u64,
        table_variable_count: u64,
        polynomial_commitment_variable_count: u64,
        starting_log_inverse_rate: u64,
        folding_factor: u64,
        soundness_assumption: u16,
        security_level: u64,
        proof_of_work_bits: u64,
        outer_query_count: u64,
        direct_bound_query_count: u64,
        verified_vss_bound_query_count: u64,
        maximum_fiat_shamir_candidate_draws_per_output: u32,
        evaluation_coset_offset: u64,
    }

    impl RowCodeWhirParameterProfile {
        fn selected() -> Result<Self, ProofProfileError> {
            Self::from_selected(RowCodeWhirSelectedParameters::selected())
        }

        fn from_selected(
            parameters: RowCodeWhirSelectedParameters,
        ) -> Result<Self, ProofProfileError> {
            let convert_count =
                |count| u64::try_from(count).map_err(|_| ProofProfileError::CountOverflow);
            Ok(Self {
                logical_polynomial_coefficient_count: convert_count(
                    parameters.logical_polynomial_coefficient_count,
                )?,
                logical_polynomials_per_physical_row: convert_count(
                    parameters.logical_polynomials_per_physical_row,
                )?,
                physical_row_witness_variable_count: convert_count(
                    parameters.physical_row_witness_variable_count,
                )?,
                row_code_log_inverse_rate: convert_count(parameters.row_code_log_inverse_rate)?,
                table_variable_count: convert_count(parameters.table_variable_count)?,
                polynomial_commitment_variable_count: convert_count(
                    parameters.polynomial_commitment_variable_count,
                )?,
                starting_log_inverse_rate: convert_count(parameters.starting_log_inverse_rate)?,
                folding_factor: convert_count(parameters.folding_factor)?,
                soundness_assumption: match parameters.soundness_assumption {
                    RowCodeWhirSoundnessAssumption::UniqueDecoding => 1,
                },
                security_level: convert_count(parameters.security_level)?,
                proof_of_work_bits: convert_count(parameters.proof_of_work_bits)?,
                outer_query_count: convert_count(parameters.outer_query_count)?,
                direct_bound_query_count: convert_count(parameters.direct_bound_query_count)?,
                verified_vss_bound_query_count: convert_count(
                    parameters.verified_vss_bound_query_count,
                )?,
                maximum_fiat_shamir_candidate_draws_per_output: parameters
                    .maximum_fiat_shamir_candidate_draws_per_output,
                evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
            })
        }

        fn validate(&self) -> Result<(), ProofProfileError> {
            if self != &Self::selected()? {
                return Err(ProofProfileError::InvalidConstructionProfile);
            }
            Ok(())
        }

        fn canonical_items(self) -> Vec<CanonicalItem> {
            vec![
                CanonicalItem::unsigned64(self.logical_polynomial_coefficient_count),
                CanonicalItem::unsigned64(self.logical_polynomials_per_physical_row),
                CanonicalItem::unsigned64(self.physical_row_witness_variable_count),
                CanonicalItem::unsigned64(self.row_code_log_inverse_rate),
                CanonicalItem::unsigned64(self.table_variable_count),
                CanonicalItem::unsigned64(self.polynomial_commitment_variable_count),
                CanonicalItem::unsigned64(self.starting_log_inverse_rate),
                CanonicalItem::unsigned64(self.folding_factor),
                CanonicalItem::unsigned16(self.soundness_assumption),
                CanonicalItem::unsigned64(self.security_level),
                CanonicalItem::unsigned64(self.proof_of_work_bits),
                CanonicalItem::unsigned64(self.outer_query_count),
                CanonicalItem::unsigned64(self.direct_bound_query_count),
                CanonicalItem::unsigned64(self.verified_vss_bound_query_count),
                CanonicalItem::unsigned32(self.maximum_fiat_shamir_candidate_draws_per_output),
                CanonicalItem::unsigned64(self.evaluation_coset_offset),
            ]
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RowCodeWhirHashProfile {
        hash_algorithm_identifier: String,
        digest_byte_length: u16,
        protocol_hash_domain: Vec<u8>,
        phase_column_leaf_domain: Vec<u8>,
        phase_column_node_domain: Vec<u8>,
        aggregate_leaf_domain: Vec<u8>,
        aggregate_node_domain: Vec<u8>,
        transcript_initial_domain: Vec<u8>,
        transcript_absorb_domain: Vec<u8>,
        transcript_challenge_handle_domain: Vec<u8>,
        transcript_accepted_challenge_domain: Vec<u8>,
        transcript_response_binding_domain: Vec<u8>,
        transcript_product_residue_block_domain: Vec<u8>,
        transcript_distinct_query_block_domain: Vec<u8>,
    }

    impl RowCodeWhirHashProfile {
        fn selected() -> Self {
            Self {
                hash_algorithm_identifier: ROW_CODE_WHIR_HASH_ALGORITHM_IDENTIFIER.to_owned(),
                digest_byte_length: ROW_CODE_WHIR_DIGEST_BYTE_LENGTH,
                protocol_hash_domain: ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN.to_vec(),
                phase_column_leaf_domain: ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN.to_vec(),
                phase_column_node_domain: ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN.to_vec(),
                aggregate_leaf_domain: ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.to_vec(),
                aggregate_node_domain: ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN.to_vec(),
                transcript_initial_domain: TRANSCRIPT_INITIAL_DOMAIN_BYTES.to_vec(),
                transcript_absorb_domain: TRANSCRIPT_ABSORB_DOMAIN_BYTES.to_vec(),
                transcript_challenge_handle_domain: TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN_BYTES
                    .to_vec(),
                transcript_accepted_challenge_domain: TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN_BYTES
                    .to_vec(),
                transcript_response_binding_domain: TRANSCRIPT_RESPONSE_BINDING_DOMAIN_BYTES
                    .to_vec(),
                transcript_product_residue_block_domain:
                    TRANSCRIPT_PRODUCT_RESIDUE_BLOCK_DOMAIN_BYTES.to_vec(),
                transcript_distinct_query_block_domain:
                    TRANSCRIPT_DISTINCT_QUERY_BLOCK_DOMAIN_BYTES.to_vec(),
            }
        }

        fn validate(&self) -> Result<(), ProofProfileError> {
            if self != &Self::selected() {
                return Err(ProofProfileError::InvalidConstructionProfile);
            }
            Ok(())
        }

        fn canonical_tuple(&self) -> Result<CanonicalTuple, ProofProfileError> {
            self.validate()?;
            Ok(CanonicalTuple::new(
                ROW_CODE_WHIR_HASH_PROFILE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::ascii(&self.hash_algorithm_identifier)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned16(self.digest_byte_length),
                    CanonicalItem::fixed_bytes(&self.protocol_hash_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.phase_column_leaf_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.phase_column_node_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.aggregate_leaf_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.aggregate_node_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.transcript_initial_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.transcript_absorb_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.transcript_challenge_handle_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.transcript_accepted_challenge_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.transcript_response_binding_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.transcript_product_residue_block_domain)
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::fixed_bytes(&self.transcript_distinct_query_block_domain)
                        .map_err(canonical_encoding_error)?,
                ],
            ))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RowCodeWhirConstructionReference {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        canonical_identity_byte_length: u64,
        canonical_identity_hash: [u8; 64],
    }

    impl RowCodeWhirConstructionReference {
        fn for_selected_variant(
            artifact: &ValidatedRelationPlanArtifact,
            variant: &RelationPlanVariant,
        ) -> Result<(Self, RowCodeWhirSelectedParameters), ProofProfileError> {
            let schedule_position = variant.schedule_position();
            let top_count = variant.top_count();
            let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
                artifact,
                schedule_position,
                top_count,
            )
            .map_err(|_| ProofProfileError::InvalidConstructionProfile)?;
            let canonical_identity_bytes = construction_plan
                .canonical_identity_bytes()
                .map_err(|_| ProofProfileError::CanonicalEncoding)?;
            let canonical_identity_byte_length = u64::try_from(canonical_identity_bytes.len())
                .map_err(|_| ProofProfileError::CountOverflow)?;
            if canonical_identity_byte_length == 0 {
                return Err(ProofProfileError::CanonicalEncoding);
            }
            let canonical_identity_hash = construction_plan
                .canonical_identity_hash()
                .map_err(|_| ProofProfileError::CanonicalEncoding)?;
            Ok((
                Self {
                    application_statement_schema_identifier: artifact
                        .application_statement_schema_identifier(),
                    schedule_position,
                    top_count,
                    canonical_identity_byte_length,
                    canonical_identity_hash,
                },
                construction_plan.selected_parameters(),
            ))
        }

        fn coordinates(&self) -> (u16, Option<u32>, Option<u16>) {
            (
                self.application_statement_schema_identifier,
                self.schedule_position,
                self.top_count,
            )
        }

        fn canonical_tuple(&self) -> Result<CanonicalTuple, ProofProfileError> {
            let schedule_position = self.schedule_position.map(CanonicalItem::unsigned32);
            let top_count = self.top_count.map(CanonicalItem::unsigned16);
            Ok(CanonicalTuple::new(
                ROW_CODE_WHIR_CONSTRUCTION_REFERENCE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                    CanonicalItem::optional(
                        CanonicalItemType::Unsigned32,
                        schedule_position.as_ref(),
                    )
                    .map_err(canonical_encoding_error)?,
                    CanonicalItem::optional(CanonicalItemType::Unsigned16, top_count.as_ref())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned64(self.canonical_identity_byte_length),
                    CanonicalItem::hash512(self.canonical_identity_hash),
                ],
            ))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RowCodeWhirConstructionProfile {
        parameters: RowCodeWhirParameterProfile,
        hash_profile: RowCodeWhirHashProfile,
        ordered_references: Vec<RowCodeWhirConstructionReference>,
    }

    impl RowCodeWhirConstructionProfile {
        fn selected(
            relation_plans: &[ValidatedRelationPlanArtifact],
        ) -> Result<Self, ProofProfileError> {
            let (parameters, ordered_references) =
                derive_selected_row_code_whir_construction_catalog(relation_plans)?;
            let profile = Self {
                parameters,
                hash_profile: RowCodeWhirHashProfile::selected(),
                ordered_references,
            };
            profile.validate(relation_plans)?;
            Ok(profile)
        }

        fn validate(
            &self,
            relation_plans: &[ValidatedRelationPlanArtifact],
        ) -> Result<(), ProofProfileError> {
            validate_relation_plan_catalog(relation_plans)?;
            self.parameters.validate()?;
            self.hash_profile.validate()?;
            if self.ordered_references.len() != SELECTED_ROW_CODE_WHIR_CONSTRUCTION_REFERENCE_COUNT
            {
                return Err(ProofProfileError::InvalidConstructionProfile);
            }

            let mut coordinates = BTreeSet::new();
            let mut identity_hashes = BTreeSet::new();
            let mut reference_index = 0_usize;
            for artifact in relation_plans {
                for variant in artifact.compiled_plan().variants() {
                    let reference = self
                        .ordered_references
                        .get(reference_index)
                        .ok_or(ProofProfileError::InvalidConstructionProfile)?;
                    reference_index = reference_index
                        .checked_add(1)
                        .ok_or(ProofProfileError::CountOverflow)?;
                    if !coordinates.insert(reference.coordinates())
                        || !identity_hashes.insert(reference.canonical_identity_hash)
                        || reference.canonical_identity_byte_length == 0
                    {
                        return Err(ProofProfileError::InvalidConstructionProfile);
                    }
                    if reference.coordinates()
                        != (
                            artifact.application_statement_schema_identifier(),
                            variant.schedule_position(),
                            variant.top_count(),
                        )
                    {
                        return Err(ProofProfileError::NonCanonicalOrder);
                    }
                }
            }
            if reference_index != self.ordered_references.len() {
                return Err(ProofProfileError::InvalidConstructionProfile);
            }
            Ok(())
        }

        fn canonical_tuple(
            &self,
            relation_plans: &[ValidatedRelationPlanArtifact],
        ) -> Result<CanonicalTuple, ProofProfileError> {
            self.validate(relation_plans)?;
            let mut items = self.parameters.canonical_items();
            items.push(
                CanonicalItem::nested_tuple(&self.hash_profile.canonical_tuple()?)
                    .map_err(canonical_encoding_error)?,
            );
            items.push(canonical_nested_list(
                self.ordered_references
                    .iter()
                    .map(RowCodeWhirConstructionReference::canonical_tuple)
                    .collect::<Result<Vec<_>, _>>()?,
            )?);
            Ok(CanonicalTuple::new(
                ROW_CODE_WHIR_CONSTRUCTION_PROFILE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                items,
            ))
        }
    }

    fn derive_selected_row_code_whir_construction_catalog(
        relation_plans: &[ValidatedRelationPlanArtifact],
    ) -> Result<
        (
            RowCodeWhirParameterProfile,
            Vec<RowCodeWhirConstructionReference>,
        ),
        ProofProfileError,
    > {
        validate_relation_plan_catalog(relation_plans)?;
        let selected_parameters = RowCodeWhirSelectedParameters::selected();
        let mut ordered_references = Vec::new();
        for artifact in relation_plans {
            for variant in artifact.compiled_plan().variants() {
                let (reference, parameters) =
                    RowCodeWhirConstructionReference::for_selected_variant(artifact, variant)?;
                if parameters != selected_parameters {
                    return Err(ProofProfileError::InvalidConstructionProfile);
                }
                ordered_references.push(reference);
            }
        }
        if ordered_references.len() != SELECTED_ROW_CODE_WHIR_CONSTRUCTION_REFERENCE_COUNT {
            return Err(ProofProfileError::InvalidConstructionProfile);
        }
        Ok((
            RowCodeWhirParameterProfile::from_selected(selected_parameters)?,
            ordered_references,
        ))
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct ProofProfileSet {
        proof_fields: Vec<ProofFieldProfile>,
        proof_families: Vec<ProofFamilyProfile>,
        relation_plans: Vec<ValidatedRelationPlanArtifact>,
        root_compatibility_edges: Vec<RelationRootCompatibilityEdge>,
        row_code_whir_construction_profile: RowCodeWhirConstructionProfile,
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
            let row_code_whir_construction_profile =
                RowCodeWhirConstructionProfile::selected(&relation_plans)?;
            let profile = Self {
                proof_fields,
                proof_families,
                relation_plans,
                root_compatibility_edges,
                row_code_whir_construction_profile,
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
            for (family_index, expected_family) in FIRST_PROFILE_APPLICATION_FAMILIES
                .iter()
                .copied()
                .enumerate()
            {
                let family = &self.proof_families[family_index];
                family.validate(self.proof_fields.len())?;
                if family.application_statement_schema_identifier != expected_family
                    || self.relation_plans[family_index].application_statement_schema_identifier()
                        != expected_family
                {
                    return Err(ProofProfileError::NonCanonicalOrder);
                }
                if self
                    .row_code_whir_construction_profile
                    .parameters
                    .evaluation_coset_offset
                    != PROOF_EVALUATION_COSET_OFFSET
                    || self
                        .row_code_whir_construction_profile
                        .parameters
                        .maximum_fiat_shamir_candidate_draws_per_output
                        != PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
                {
                    return Err(ProofProfileError::InvalidSchedule);
                }
            }

            self.row_code_whir_construction_profile
                .validate(&self.relation_plans)?;

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
                PROOF_PROFILE_SET_VERSION,
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
                            .map(ValidatedRelationPlanArtifact::canonical_reference_tuple),
                    )?,
                    canonical_nested_list(
                        self.root_compatibility_edges
                            .iter()
                            .copied()
                            .map(RelationRootCompatibilityEdge::canonical_tuple)
                            .collect::<Result<Vec<_>, _>>()?,
                    )?,
                    CanonicalItem::nested_tuple(
                        &self
                            .row_code_whir_construction_profile
                            .canonical_tuple(&self.relation_plans)?,
                    )
                    .map_err(canonical_encoding_error)?,
                ],
            );
            encode_generated_tuple(&tuple)
        }

        pub(crate) fn relation_plans(&self) -> &[ValidatedRelationPlanArtifact] {
            &self.relation_plans
        }

        pub(crate) fn root_compatibility_edges(&self) -> &[RelationRootCompatibilityEdge] {
            &self.root_compatibility_edges
        }

        #[cfg(test)]
        pub(crate) fn assert_catalog_mutation_boundaries(&mut self) {
            let baseline_bytes = self
                .canonical_bytes()
                .expect("selected proof-profile artifact encodes");
            let baseline_reference = proof_profile_artifact_reference(&baseline_bytes);

            let original_plan_byte_length = self.relation_plans[0].canonical_plan_byte_length;
            self.relation_plans[0].canonical_plan_byte_length = original_plan_byte_length + 1;
            let wrong_plan_length_bytes = self
                .canonical_bytes()
                .expect("a mutated positive plan length remains structurally canonical");
            assert_ne!(wrong_plan_length_bytes, baseline_bytes);
            assert_ne!(
                proof_profile_artifact_reference(&wrong_plan_length_bytes).artifact_hash(),
                baseline_reference.artifact_hash()
            );
            self.relation_plans[0].canonical_plan_byte_length = original_plan_byte_length;

            self.relation_plans[0].canonical_plan_hash[0] ^= 1;
            let wrong_plan_hash_bytes = self
                .canonical_bytes()
                .expect("a mutated plan hash remains structurally canonical");
            assert_ne!(wrong_plan_hash_bytes, baseline_bytes);
            assert_ne!(
                proof_profile_artifact_reference(&wrong_plan_hash_bytes).artifact_hash(),
                baseline_reference.artifact_hash()
            );
            self.relation_plans[0].canonical_plan_hash[0] ^= 1;

            self.relation_plans.swap(0, 1);
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::NonCanonicalOrder)
            );
            self.relation_plans.swap(0, 1);

            self.proof_families[0].proof_field_index = 1;
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidSchedule)
            );
            self.proof_families[0].proof_field_index = 0;

            self.proof_families.swap(0, 1);
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::NonCanonicalOrder)
            );
            self.proof_families.swap(0, 1);

            self.row_code_whir_construction_profile
                .parameters
                .maximum_fiat_shamir_candidate_draws_per_output += 1;
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidSchedule)
            );
            self.row_code_whir_construction_profile
                .parameters
                .maximum_fiat_shamir_candidate_draws_per_output -= 1;

            self.row_code_whir_construction_profile
                .parameters
                .evaluation_coset_offset += 1;
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidSchedule)
            );
            self.row_code_whir_construction_profile
                .parameters
                .evaluation_coset_offset -= 1;

            self.row_code_whir_construction_profile
                .parameters
                .folding_factor += 1;
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidConstructionProfile)
            );
            self.row_code_whir_construction_profile
                .parameters
                .folding_factor -= 1;

            self.row_code_whir_construction_profile
                .hash_profile
                .protocol_hash_domain[0] ^= 1;
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidConstructionProfile)
            );
            self.row_code_whir_construction_profile
                .hash_profile
                .protocol_hash_domain[0] ^= 1;

            self.row_code_whir_construction_profile
                .hash_profile
                .transcript_challenge_handle_domain[0] ^= 1;
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidConstructionProfile)
            );
            self.row_code_whir_construction_profile
                .hash_profile
                .transcript_challenge_handle_domain[0] ^= 1;

            self.row_code_whir_construction_profile.ordered_references[0]
                .canonical_identity_byte_length += 1;
            let wrong_construction_length_bytes = self
                .canonical_bytes()
                .expect("a mutated positive construction length remains structurally canonical");
            assert_ne!(wrong_construction_length_bytes, baseline_bytes);
            assert_ne!(
                proof_profile_artifact_reference(&wrong_construction_length_bytes).artifact_hash(),
                baseline_reference.artifact_hash()
            );
            self.row_code_whir_construction_profile.ordered_references[0]
                .canonical_identity_byte_length -= 1;

            self.row_code_whir_construction_profile.ordered_references[0]
                .canonical_identity_hash[0] ^= 1;
            let wrong_construction_hash_bytes = self
                .canonical_bytes()
                .expect("a mutated construction hash remains structurally canonical");
            assert_ne!(wrong_construction_hash_bytes, baseline_bytes);
            assert_ne!(
                proof_profile_artifact_reference(&wrong_construction_hash_bytes).artifact_hash(),
                baseline_reference.artifact_hash()
            );
            self.row_code_whir_construction_profile.ordered_references[0]
                .canonical_identity_hash[0] ^= 1;

            self.row_code_whir_construction_profile.ordered_references[0].schedule_position =
                Some(0);
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::NonCanonicalOrder)
            );
            self.row_code_whir_construction_profile.ordered_references[0].schedule_position = None;

            self.row_code_whir_construction_profile
                .ordered_references
                .swap(0, 1);
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::NonCanonicalOrder)
            );
            self.row_code_whir_construction_profile
                .ordered_references
                .swap(0, 1);

            let duplicate_reference =
                self.row_code_whir_construction_profile.ordered_references[0].clone();
            let final_reference = self
                .row_code_whir_construction_profile
                .ordered_references
                .last_mut()
                .expect("selected construction references are nonempty");
            let original_final_reference = core::mem::replace(final_reference, duplicate_reference);
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidConstructionProfile)
            );
            *self
                .row_code_whir_construction_profile
                .ordered_references
                .last_mut()
                .expect("selected construction references are nonempty") = original_final_reference;

            let removed_reference = self
                .row_code_whir_construction_profile
                .ordered_references
                .pop()
                .expect("selected construction references are nonempty");
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::InvalidConstructionProfile)
            );
            self.row_code_whir_construction_profile
                .ordered_references
                .push(removed_reference);

            self.root_compatibility_edges.swap(0, 1);
            assert_eq!(
                self.canonical_bytes(),
                Err(ProofProfileError::NonCanonicalOrder)
            );
            self.root_compatibility_edges.swap(0, 1);

            let original_edge = self.root_compatibility_edges[0];
            self.root_compatibility_edges[0].construction_kind =
                match original_edge.construction_kind {
                    RelationRootConstructionKind::CommittedMaterial => {
                        RelationRootConstructionKind::SetupPolynomial
                    }
                    RelationRootConstructionKind::SetupPolynomial => {
                        RelationRootConstructionKind::CommittedMaterial
                    }
                };
            assert!(self.canonical_bytes().is_err());
            self.root_compatibility_edges[0] = original_edge;

            assert_eq!(
                self.canonical_bytes()
                    .expect("restored proof-profile artifact encodes"),
                baseline_bytes
            );
        }
    }

    #[cfg(test)]
    fn proof_profile_artifact_reference(bytes: &[u8]) -> ArtifactReference {
        let cumulative_limit = bytes
            .len()
            .checked_mul(64)
            .expect("generated profile decode limit fits usize");
        ArtifactReference::from_canonical_artifact_bytes(
            ArtifactKind::ProofProfileSet,
            bytes,
            &CanonicalDecodeLimits {
                maximum_tuple_byte_length: bytes.len(),
                maximum_item_count: 100_000,
                maximum_item_byte_length: bytes.len(),
                maximum_nesting_depth: 32,
                maximum_cumulative_work_byte_length: cumulative_limit,
                maximum_cumulative_allocation_byte_length: cumulative_limit,
            },
        )
        .expect("generated proof-profile artifact reference derives")
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

    #[derive(Clone, Copy)]
    struct RelationRootApplicationCoordinates {
        application_statement_schema_identifier: u16,
        roster_position: Option<u16>,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        producer_sequence: Option<u64>,
    }

    impl RelationRootApplicationCoordinates {
        const fn new(
            application_statement_schema_identifier: u16,
            roster_position: Option<u16>,
            schedule_position: Option<u32>,
            top_count: Option<u16>,
            producer_sequence: Option<u64>,
        ) -> Self {
            Self {
                application_statement_schema_identifier,
                roster_position,
                schedule_position,
                top_count,
                producer_sequence,
            }
        }
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
        application_statement_schema_identifier: u16,
        construction_kind: RelationRootConstructionKind,
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
                    source_degree_bound_exclusive: column.source_degree_bound_exclusive(),
                    canonical_residue_modulus: column.canonical_residue_modulus(),
                })
            })
            .collect::<Result<Vec<_>, ProofProfileError>>()?;
        if ordered_columns.is_empty() {
            return Err(ProofProfileError::IncompatibleRoot);
        }
        let selected_construction_kind = match construction_kind {
            RelationRootConstructionKind::CommittedMaterial => {
                BoundTreeConstructionKind::CommittedMaterial
            }
            RelationRootConstructionKind::SetupPolynomial => {
                BoundTreeConstructionKind::SetupPolynomial
            }
        };
        let trace_domain_size =
            super::super::selected_profile::selected_bound_root_source_trace_domain_size(
                application_statement_schema_identifier,
                selected_construction_kind,
                variant.trace_domain_size(),
                variant.evaluation_domain_size(),
            )
            .map_err(|error| match error {
                ProofProfileError::InvalidRootTopology => ProofProfileError::InvalidRootEndpoint,
                ProofProfileError::InvalidRelationPlan => ProofProfileError::IncompatibleRoot,
                error => error,
            })?;
        Ok(RelationRootShape {
            trace_domain_size,
            evaluation_domain_size: variant.evaluation_domain_size(),
            ordered_columns,
        })
    }

    fn ordered_bound_root_slots(
        relation_plans: &[ValidatedRelationPlanArtifact],
        coordinates: RelationRootApplicationCoordinates,
        construction_kind: RelationRootConstructionKind,
        root_use: BoundTreeRootUse,
    ) -> Result<Vec<BoundRootSlot>, ProofProfileError> {
        let RelationRootApplicationCoordinates {
            application_statement_schema_identifier,
            roster_position,
            schedule_position,
            top_count,
            producer_sequence,
        } = coordinates;
        let artifact =
            relation_plan_artifact(relation_plans, application_statement_schema_identifier)?;
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
                    shape: root_shape(
                        variant,
                        application_statement_schema_identifier,
                        construction_kind,
                        ordered_column_ordinals,
                    )?,
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
            RelationRootApplicationCoordinates::new(
                endpoint.application_statement_schema_identifier,
                endpoint.roster_position,
                endpoint.schedule_position,
                endpoint.top_count,
                endpoint.producer_sequence,
            ),
            construction_kind,
            root_use,
        )?
        .into_iter()
        .filter(|root| root.endpoint.verifier_source_ordinal == endpoint.verifier_source_ordinal);
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
            RelationRootApplicationCoordinates::new(
                ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
                None,
                None,
            ),
            RelationRootConstructionKind::CommittedMaterial,
            BoundTreeRootUse::Output,
        )?;
        let aggregate_input_template = ordered_bound_root_slots(
            relation_plans,
            RelationRootApplicationCoordinates::new(
                ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
                None,
                None,
            ),
            RelationRootConstructionKind::CommittedMaterial,
            BoundTreeRootUse::Input,
        )?;
        let aggregate_output_template = ordered_bound_root_slots(
            relation_plans,
            RelationRootApplicationCoordinates::new(
                ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
                None,
                None,
            ),
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
        if sharing_limb_count == 0 || !vss_output_template.len().is_multiple_of(sharing_limb_count)
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
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(dealer_position),
                    None,
                    None,
                    None,
                ),
                RelationRootConstructionKind::CommittedMaterial,
                BoundTreeRootUse::Output,
            )?;
            require_root_count(&dealer_outputs, vss_output_template.len())?;

            let same_secret_inputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(dealer_position),
                    None,
                    None,
                    None,
                ),
                RelationRootConstructionKind::CommittedMaterial,
                BoundTreeRootUse::Input,
            )?;
            require_root_count(&same_secret_inputs, sharing_limb_count)?;
            for (sharing_limb_ordinal, same_secret_input) in same_secret_inputs.iter().enumerate() {
                let coefficient_zero_index =
                    checked_product(sharing_limb_ordinal, roots_per_vss_limb)?;
                append_root_edge(
                    &mut edges,
                    &mut assigned_consumers,
                    &dealer_outputs[coefficient_zero_index],
                    same_secret_input,
                    RelationRootConstructionKind::CommittedMaterial,
                )?;
            }

            for recipient_position in 0..topology.roster_size {
                let recipient_inputs = ordered_bound_root_slots(
                    relation_plans,
                    RelationRootApplicationCoordinates::new(
                        ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                        Some(recipient_position),
                        None,
                        None,
                        None,
                    ),
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
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(recipient_position),
                    None,
                    None,
                    None,
                ),
                RelationRootConstructionKind::CommittedMaterial,
                BoundTreeRootUse::Output,
            )?;
            let target_inputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(recipient_position),
                    None,
                    None,
                    None,
                ),
                RelationRootConstructionKind::CommittedMaterial,
                BoundTreeRootUse::Input,
            )?;
            require_root_count(&aggregate_outputs, sharing_limb_count)?;
            if target_inputs.is_empty() || target_inputs.len() > aggregate_outputs.len() {
                return Err(ProofProfileError::InvalidRootTopology);
            }
            for sharing_limb_ordinal in 0..target_inputs.len() {
                append_root_edge(
                    &mut edges,
                    &mut assigned_consumers,
                    &aggregate_outputs[sharing_limb_ordinal],
                    &target_inputs[sharing_limb_ordinal],
                    RelationRootConstructionKind::CommittedMaterial,
                )?;
            }
        }

        // Same-secret anchors are consumed by the public-key-share relation in
        // the same roster slot. Both sides are
        // ordered by the checked commitment-modulus catalog.
        for roster_position in 0..topology.roster_size {
            let anchor_outputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(roster_position),
                    None,
                    None,
                    None,
                ),
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Output,
            )?;
            let public_key_anchor_inputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(roster_position),
                    None,
                    None,
                    None,
                ),
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Input,
            )?;
            require_root_count(&public_key_anchor_inputs, anchor_outputs.len())?;
            for (producer, consumer) in anchor_outputs.iter().zip(public_key_anchor_inputs.iter()) {
                append_root_edge(
                    &mut edges,
                    &mut assigned_consumers,
                    producer,
                    consumer,
                    RelationRootConstructionKind::SetupPolynomial,
                )?;
            }

            // The trustee evaluation-key relations re-open the same ordered
            // commitment-modulus anchors. Their statement-root ordinals differ
            // because each family precedes the anchors with its own public key
            // material, so bind the compiler-fixed input suffix explicitly.
            let trustee_anchor_outputs = anchor_outputs
                .get(..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
                .ok_or(ProofProfileError::InvalidRootTopology)?;
            for (trustee_family, preceding_input_root_count, first_anchor_source_ordinal) in [
                (
                    ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                    0_usize,
                    2_u32,
                ),
                (
                    ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                    4,
                    5,
                ),
                (
                    ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    0,
                    0,
                ),
            ] {
                let trustee_plan = relation_plan_artifact(relation_plans, trustee_family)?;
                for variant in trustee_plan.compiled_plan().variants() {
                    let schedule_position = variant
                        .schedule_position()
                        .ok_or(ProofProfileError::InvalidRootTopology)?;
                    let trustee_inputs = ordered_bound_root_slots(
                        relation_plans,
                        RelationRootApplicationCoordinates::new(
                            trustee_family,
                            Some(roster_position),
                            Some(schedule_position),
                            None,
                            None,
                        ),
                        RelationRootConstructionKind::SetupPolynomial,
                        BoundTreeRootUse::Input,
                    )?;
                    require_root_count(
                        &trustee_inputs,
                        checked_sum(preceding_input_root_count, trustee_anchor_outputs.len())?,
                    )?;
                    let anchor_inputs = &trustee_inputs[preceding_input_root_count..];
                    for (anchor_ordinal, (producer, consumer)) in trustee_anchor_outputs
                        .iter()
                        .zip(anchor_inputs.iter())
                        .enumerate()
                    {
                        let expected_source_ordinal = first_anchor_source_ordinal
                            .checked_add(
                                u32::try_from(anchor_ordinal)
                                    .map_err(|_| ProofProfileError::CountOverflow)?,
                            )
                            .ok_or(ProofProfileError::CountOverflow)?;
                        if consumer.endpoint.verifier_source_ordinal != expected_source_ordinal {
                            return Err(ProofProfileError::InvalidRootTopology);
                        }
                        append_root_edge(
                            &mut edges,
                            &mut assigned_consumers,
                            producer,
                            consumer,
                            RelationRootConstructionKind::SetupPolynomial,
                        )?;
                    }
                }
            }
        }

        let collective_public_key_inputs = ordered_bound_root_slots(
            relation_plans,
            RelationRootApplicationCoordinates::new(
                ProofFamilies::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
                None,
                None,
            ),
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Input,
        )?;
        let collective_public_key_outputs = ordered_bound_root_slots(
            relation_plans,
            RelationRootApplicationCoordinates::new(
                ProofFamilies::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
                None,
                None,
            ),
            RelationRootConstructionKind::SetupPolynomial,
            BoundTreeRootUse::Output,
        )?;
        require_root_count(&collective_public_key_inputs, roster_size)?;
        require_root_count(&collective_public_key_outputs, 1)?;
        for roster_position in 0..topology.roster_size {
            let public_key_outputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(roster_position),
                    None,
                    None,
                    None,
                ),
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
            SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len(),
            &mut edges,
            &mut assigned_consumers,
        )?;
        derive_evaluator_aggregate_edges(
            relation_plans,
            topology,
            &mut edges,
            &mut assigned_consumers,
        )?;
        // The remaining setup-polynomial inputs are the per-trustee anchor and
        // round-one-aggregate consumers.  Exact root geometry and slot scope make
        // their producer unique; any missing or second compatible producer is a
        // profile-generation failure.
        let all_outputs = all_bound_root_slots(relation_plans, topology, BoundTreeRootUse::Output)?;
        for consumer in all_bound_root_slots(relation_plans, topology, BoundTreeRootUse::Input)? {
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

        validate_persistent_committed_material_mask_images(relation_plans, topology, &edges)?;

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

    fn committed_material_root_view_catalogs(
        relation_plans: &[ValidatedRelationPlanArtifact],
        endpoint: RelationRootEndpoint,
        root_use: BoundTreeRootUse,
    ) -> Result<Vec<TraceMaskObservationCoordinateCatalog>, ProofProfileError> {
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
        let challenge_extension_degree = u16::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| ProofProfileError::CountOverflow)?;
        ProofFamilyProfile::selected(endpoint.application_statement_schema_identifier)?;
        let phase_column_query_coordinate_count = ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT;
        let catalogs = root
            .ordered_column_ordinals
            .into_iter()
            .map(|column_ordinal| {
                TraceMaskObservationCoordinateCatalog::derive(
                    variant,
                    column_ordinal,
                    challenge_extension_degree,
                    phase_column_query_coordinate_count,
                )
                .map_err(ProofProfileError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if catalogs.is_empty() {
            return Err(ProofProfileError::InsufficientRootMaskImage);
        }
        Ok(catalogs)
    }

    fn committed_material_mask_coefficient_counts(
        root: &BoundRootSlot,
    ) -> Result<Vec<u64>, ProofProfileError> {
        if root.construction_kind != RelationRootConstructionKind::CommittedMaterial {
            return Err(ProofProfileError::IncompatibleRoot);
        }
        let counts = root
            .shape
            .ordered_columns
            .iter()
            .map(|column| {
                column
                    .source_degree_bound_exclusive
                    .checked_sub(root.shape.trace_domain_size)
                    .filter(|count| *count > 0 && *count <= root.shape.trace_domain_size)
                    .ok_or(ProofProfileError::InsufficientRootMaskImage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if counts.is_empty() {
            return Err(ProofProfileError::InsufficientRootMaskImage);
        }
        Ok(counts)
    }

    fn validate_persistent_committed_material_mask_images(
        relation_plans: &[ValidatedRelationPlanArtifact],
        topology: &FirstProfileRootTopology,
        edges: &[RelationRootCompatibilityEdge],
    ) -> Result<(), ProofProfileError> {
        for producer in all_bound_root_slots(relation_plans, topology, BoundTreeRootUse::Output)?
            .into_iter()
            .filter(|root| {
                root.construction_kind == RelationRootConstructionKind::CommittedMaterial
            })
        {
            let producer_catalogs = committed_material_root_view_catalogs(
                relation_plans,
                producer.endpoint,
                BoundTreeRootUse::Output,
            )?;
            let mut joint_catalogs_by_physical_column = producer_catalogs
                .into_iter()
                .map(|catalog| vec![catalog])
                .collect::<Vec<_>>();
            for edge in edges.iter().filter(|edge| {
                edge.construction_kind == RelationRootConstructionKind::CommittedMaterial
                    && edge.producer_endpoint == producer.endpoint
            }) {
                let consumer_catalogs = committed_material_root_view_catalogs(
                    relation_plans,
                    edge.consumer_endpoint,
                    BoundTreeRootUse::Input,
                )?;
                if consumer_catalogs.len() != joint_catalogs_by_physical_column.len() {
                    return Err(ProofProfileError::IncompatibleRoot);
                }
                for (joint_catalogs, consumer_catalog) in joint_catalogs_by_physical_column
                    .iter_mut()
                    .zip(consumer_catalogs)
                {
                    joint_catalogs.push(consumer_catalog);
                }
            }
            let mask_coefficient_counts = committed_material_mask_coefficient_counts(&producer)?;
            if mask_coefficient_counts.len() != joint_catalogs_by_physical_column.len() {
                return Err(ProofProfileError::IncompatibleRoot);
            }
            for (mask_coefficient_count, joint_catalogs) in mask_coefficient_counts
                .into_iter()
                .zip(&joint_catalogs_by_physical_column)
            {
                TraceMaskSurjectivityCertificate::derive(mask_coefficient_count, joint_catalogs)
                    .map_err(|error| match error {
                        RelationPlanError::CountOverflow => ProofProfileError::CountOverflow,
                        _ => ProofProfileError::InsufficientRootMaskImage,
                    })?;
            }
        }
        Ok(())
    }

    fn derive_rkg_aggregate_edges(
        relation_plans: &[ValidatedRelationPlanArtifact],
        topology: &FirstProfileRootTopology,
        anchor_root_count: usize,
        edges: &mut Vec<RelationRootCompatibilityEdge>,
        assigned_consumers: &mut BTreeSet<RelationRootEndpoint>,
    ) -> Result<(), ProofProfileError> {
        let aggregate_plan = relation_plan_artifact(
            relation_plans,
            ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        )?;
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
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    None,
                    Some(schedule_position),
                    None,
                    None,
                ),
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Input,
            )?;
            let aggregate_outputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    None,
                    Some(schedule_position),
                    None,
                    None,
                ),
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Output,
            )?;
            require_root_count(&aggregate_inputs, checked_product(2, roster_size)?)?;
            require_root_count(&aggregate_outputs, 2)?;
            for roster_position in 0..topology.roster_size {
                let trustee_outputs = ordered_bound_root_slots(
                    relation_plans,
                    RelationRootApplicationCoordinates::new(
                        ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                        Some(roster_position),
                        Some(schedule_position),
                        None,
                        None,
                    ),
                    RelationRootConstructionKind::SetupPolynomial,
                    BoundTreeRootUse::Output,
                )?;
                require_root_count(&trustee_outputs, 2)?;
                for (component_ordinal, trustee_output) in trustee_outputs.iter().enumerate() {
                    let consumer_index = checked_sum(
                        checked_product(component_ordinal, roster_size)?,
                        usize::from(roster_position),
                    )?;
                    append_root_edge(
                        edges,
                        assigned_consumers,
                        trustee_output,
                        &aggregate_inputs[consumer_index],
                        RelationRootConstructionKind::SetupPolynomial,
                    )?;
                }
                let round_two_inputs = ordered_bound_root_slots(
                    relation_plans,
                    RelationRootApplicationCoordinates::new(
                        ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                        Some(roster_position),
                        Some(schedule_position),
                        None,
                        None,
                    ),
                    RelationRootConstructionKind::SetupPolynomial,
                    BoundTreeRootUse::Input,
                )?;
                require_root_count(&round_two_inputs, checked_sum(4, anchor_root_count)?)?;
                for component_ordinal in 0..2 {
                    append_root_edge(
                        edges,
                        assigned_consumers,
                        &trustee_outputs[component_ordinal],
                        &round_two_inputs[component_ordinal],
                        RelationRootConstructionKind::SetupPolynomial,
                    )?;
                    append_root_edge(
                        edges,
                        assigned_consumers,
                        &aggregate_outputs[component_ordinal],
                        &round_two_inputs[component_ordinal + 2],
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
        let galois_batch_output_count = EvaluatorCandidateInput::implemented()
            .map_err(|_| ProofProfileError::InvalidRootTopology)?
            .galois_key_schedule
            .len();
        for top_count in 1..=20_u16 {
            let selected_entries = topology
                .ordered_evaluator_key_entries_by_top_count
                .get(usize::from(top_count - 1))
                .ok_or(ProofProfileError::InvalidRootTopology)?;
            let evaluator_inputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    None,
                    None,
                    Some(top_count),
                    None,
                ),
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Input,
            )?;
            let evaluator_outputs = ordered_bound_root_slots(
                relation_plans,
                RelationRootApplicationCoordinates::new(
                    ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    None,
                    None,
                    Some(top_count),
                    None,
                ),
                RelationRootConstructionKind::SetupPolynomial,
                BoundTreeRootUse::Output,
            )?;
            require_root_count(
                &evaluator_inputs,
                checked_product(selected_entries.len(), roster_size)?,
            )?;
            require_root_count(&evaluator_outputs, selected_entries.len())?;
            for (entry_ordinal, entry) in selected_entries.iter().enumerate() {
                let evaluator_input_offset = checked_product(entry_ordinal, roster_size)?;
                let producer_family = entry.source_kind.application_statement_schema_identifier();
                for roster_position in 0..topology.roster_size {
                    let trustee_outputs = ordered_bound_root_slots(
                        relation_plans,
                        RelationRootApplicationCoordinates::new(
                            producer_family,
                            Some(roster_position),
                            Some(entry.producer_schedule_position),
                            None,
                            None,
                        ),
                        RelationRootConstructionKind::SetupPolynomial,
                        BoundTreeRootUse::Output,
                    )?;
                    require_root_count(
                        &trustee_outputs,
                        match entry.source_kind {
                            EvaluatorKeyShareSourceKind::Relinearization => 1,
                            EvaluatorKeyShareSourceKind::Galois => galois_batch_output_count,
                        },
                    )?;
                    let producer_output_index = usize::try_from(entry.producer_output_ordinal)
                        .map_err(|_| ProofProfileError::CountOverflow)?;
                    let producer_output = trustee_outputs
                        .get(producer_output_index)
                        .ok_or(ProofProfileError::InvalidRootTopology)?;
                    let evaluator_input_index = evaluator_input_offset
                        .checked_add(usize::from(roster_position))
                        .ok_or(ProofProfileError::CountOverflow)?;
                    append_root_edge(
                        edges,
                        assigned_consumers,
                        producer_output,
                        evaluator_inputs
                            .get(evaluator_input_index)
                            .ok_or(ProofProfileError::InvalidRootTopology)?,
                        RelationRootConstructionKind::SetupPolynomial,
                    )?;
                }
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
                let roster_positions = if matches!(
                    family,
                    ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofFamilies::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
                ) {
                    (0..topology.roster_size).map(Some).collect::<Vec<_>>()
                } else {
                    vec![None]
                };
                let producer_sequences =
                    if family == ProofFamilies::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER {
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
                                RelationRootApplicationCoordinates::new(
                                    family,
                                    roster_position,
                                    schedule_position,
                                    top_count,
                                    producer_sequence,
                                ),
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
            (
                ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            ) | (
                ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
            ) | (
                ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ) | (
                ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ) | (
                ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
            ) | (
                ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ) | (
                ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            )
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
            (
                ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            | (
                ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            | (
                ProofFamilies::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            | (
                ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ) => true,
            _ => producer
                .roster_position
                .zip(consumer.roster_position)
                .is_none_or(|(left, right)| left == right),
        };
        let schedule_matches = matches!(
            families,
            (
                ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofFamilies::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            )
        ) || producer
            .schedule_position
            .zip(consumer.schedule_position)
            .is_none_or(|(left, right)| left == right);
        roster_matches && schedule_matches
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
            ) || !root_scopes_are_compatible(edge.producer_endpoint, edge.consumer_endpoint)
                || !assigned_consumers.insert(edge.consumer_endpoint)
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

    pub(super) fn canonical_u64_list(values: &[u64]) -> Result<CanonicalItem, ProofProfileError> {
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
                    ordered_columns: vec![RelationRootColumnShape {
                        value_type: RelationColumnValueType::BaseField,
                        source_degree_bound_exclusive: 1 << 15,
                        canonical_residue_modulus: None,
                    }],
                },
            }
        }

        #[test]
        fn selected_field_and_family_mapping_are_canonical_and_nonnegotiable() {
            let field = ProofFieldProfile::selected().expect("selected field is valid");
            assert_eq!(field.validate(), Ok(()));
            let ordinary_family = ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
            let ordinary_family_profile =
                ProofFamilyProfile::selected(ordinary_family).expect("selected proof family");
            assert_eq!(
                ordinary_family_profile
                    .canonical_tuple()
                    .expect("selected proof family encodes"),
                CanonicalTuple::new(
                    PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER,
                    PROOF_FAMILY_PROFILE_SCHEMA_VERSION,
                    vec![
                        CanonicalItem::unsigned16(ordinary_family),
                        CanonicalItem::unsigned16(0),
                    ],
                )
            );

            let mut wrong_field = field.clone();
            wrong_field.maximum_two_adic_subgroup_generator = 1;
            assert_eq!(wrong_field.validate(), Err(ProofProfileError::InvalidField));

            let mut wrong_family_profile = ordinary_family_profile;
            wrong_family_profile.proof_field_index = 1;
            assert_eq!(
                wrong_family_profile.validate(1),
                Err(ProofProfileError::InvalidSchedule),
            );
        }

        #[test]
        fn relation_plan_artifacts_require_the_complete_selected_context() {
            let application_statement_schema_identifier =
                ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
            let selected_context =
                selected_relation_plan_check_context(application_statement_schema_identifier)
                    .expect("same-secret has a selected relation context");
            let relation_plan = crate::bgv::proof_suite::compile_same_secret_relation_plan(
                &crate::bgv::proof_suite::selected_same_secret_relation_plan_input()
                    .expect("derive the selected same-secret relation input"),
                &selected_context,
            )
            .expect("compile the selected same-secret relation");
            ValidatedRelationPlanArtifact::from_compiled_plan(&relation_plan, &selected_context)
                .expect("the exact selected context mints a validated artifact");

            let mut alternative_valid_context = selected_context.clone();
            let modulus = u128::from(alternative_valid_context.base_field_modulus);
            let generator = u128::from(alternative_valid_context.evaluation_domain_generator);
            alternative_valid_context.evaluation_domain_generator =
                u64::try_from(((generator * generator) % modulus * generator) % modulus)
                    .expect("the cubed alternative generator fits u64");
            let alternative_relation_plan =
                crate::bgv::proof_suite::compile_same_secret_relation_plan(
                    &crate::bgv::proof_suite::selected_same_secret_relation_plan_input()
                        .expect("derive the alternative same-secret relation input"),
                    &alternative_valid_context,
                )
                .expect("compile under a different generally valid domain generator");
            assert_eq!(
                alternative_relation_plan.check(&alternative_valid_context),
                Ok(())
            );
            assert_eq!(
                ValidatedRelationPlanArtifact::from_compiled_plan(
                    &alternative_relation_plan,
                    &alternative_valid_context,
                ),
                Err(ProofProfileError::InvalidSchedule),
                "a generally valid context must not be relabeled as the selected construction",
            );
            let checked_fixture_artifact =
                ValidatedRelationPlanArtifact::from_checked_fixture_plan(
                    &alternative_relation_plan,
                    &alternative_valid_context,
                )
                .expect("the fully checked fixture context mints a fixture artifact");
            assert_eq!(
                checked_fixture_artifact.checked_context(),
                &alternative_valid_context,
            );
            assert_eq!(
                checked_fixture_artifact.canonical_plan_hash(),
                alternative_relation_plan
                    .canonical_hash()
                    .expect("the checked fixture relation plan hashes canonically"),
            );
            assert!(
                RowCodeWhirConstructionPlan::for_checked_fixture_variant(
                    &checked_fixture_artifact,
                    &alternative_valid_context,
                    None,
                    None,
                )
                .is_err(),
                "fixture construction must reject a domain the proof engine cannot execute",
            );
            assert!(
                matches!(
                    crate::bgv::proof_suite::CommonProofRelationPlanCapability::from_checked_fixture_plan(
                        &alternative_relation_plan,
                        &alternative_valid_context,
                        None,
                        None,
                    ),
                    Err(
                        crate::bgv::proof_suite::CommonProofRelationPlanCapabilityError::RowCodeWhirConstructionPlan,
                    ),
                ),
                "the fixture runtime capability must reject the same unsupported domain",
            );
            assert!(
                RowCodeWhirConstructionPlan::for_checked_fixture_variant(
                    &checked_fixture_artifact,
                    &selected_context,
                    None,
                    None,
                )
                .is_err(),
                "a fixture artifact cannot be reused under a different valid context",
            );
            assert!(
                RowCodeWhirConstructionPlan::for_selected_variant(
                    &checked_fixture_artifact,
                    None,
                    None,
                )
                .is_err(),
                "a fixture artifact cannot mint a selected production construction",
            );
        }

        #[test]
        fn selected_hash_profile_binds_every_executable_domain_in_canonical_order() {
            assert_eq!(
                RowCodeWhirHashProfile::selected()
                    .canonical_tuple()
                    .expect("selected hash profile encodes"),
                CanonicalTuple::new(
                    ROW_CODE_WHIR_HASH_PROFILE_SCHEMA_IDENTIFIER,
                    SCHEMA_VERSION,
                    vec![
                        CanonicalItem::ascii(ROW_CODE_WHIR_HASH_ALGORITHM_IDENTIFIER)
                            .expect("selected hash algorithm identifier is canonical ASCII"),
                        CanonicalItem::unsigned16(ROW_CODE_WHIR_DIGEST_BYTE_LENGTH),
                        CanonicalItem::fixed_bytes(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN)
                            .expect("row-code protocol domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN)
                            .expect("phase-column leaf domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN)
                            .expect("phase-column node domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN)
                            .expect("aggregate leaf domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN)
                            .expect("aggregate node domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(TRANSCRIPT_INITIAL_DOMAIN_BYTES)
                            .expect("transcript initial domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(TRANSCRIPT_ABSORB_DOMAIN_BYTES)
                            .expect("transcript absorb domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN_BYTES)
                            .expect("transcript challenge domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN_BYTES)
                            .expect("accepted-challenge domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(TRANSCRIPT_RESPONSE_BINDING_DOMAIN_BYTES)
                            .expect("response-binding domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(TRANSCRIPT_PRODUCT_RESIDUE_BLOCK_DOMAIN_BYTES)
                            .expect("product-residue block domain fits the canonical byte limit"),
                        CanonicalItem::fixed_bytes(TRANSCRIPT_DISTINCT_QUERY_BLOCK_DOMAIN_BYTES)
                            .expect("distinct-query block domain fits the canonical byte limit"),
                    ],
                ),
            );
        }

        #[test]
        fn root_endpoint_presence_is_derived_from_the_family() {
            assert!(
                RelationRootEndpoint::new(
                    ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(0),
                    Some(3),
                    None,
                    None,
                    4,
                )
                .is_ok()
            );
            assert_eq!(
                RelationRootEndpoint::new(
                    ProofFamilies::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(0),
                    None,
                    None,
                    None,
                    4,
                ),
                Err(ProofProfileError::InvalidRootEndpoint),
            );
            assert!(
                RelationRootEndpoint::new(
                    ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    None,
                    None,
                    Some(20),
                    None,
                    0,
                )
                .is_ok()
            );
            assert_eq!(
                RelationRootEndpoint::new(
                    ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    None,
                    None,
                    Some(21),
                    None,
                    0,
                ),
                Err(ProofProfileError::InvalidRootEndpoint),
            );
            assert_eq!(
                RelationRootEndpoint::new(
                    ProofFamilies::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    None,
                    Some(0),
                    Some(20),
                    None,
                    0,
                ),
                Err(ProofProfileError::InvalidRootEndpoint),
            );
            assert!(
                RelationRootEndpoint::new(
                    ProofFamilies::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                    Some(9),
                    None,
                    None,
                    Some(2),
                    1,
                )
                .is_ok()
            );
        }

        #[test]
        fn anchor_edge_rejects_an_input_as_its_producer() {
            let producer = synthetic_anchor_root(
                ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                3,
                BoundTreeRootUse::Input,
            );
            let consumer = synthetic_anchor_root(
                ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                4,
                BoundTreeRootUse::Input,
            );
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
            let first_producer = synthetic_anchor_root(
                ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                3,
                BoundTreeRootUse::Output,
            );
            let second_producer = synthetic_anchor_root(
                ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                5,
                BoundTreeRootUse::Output,
            );
            let consumer = synthetic_anchor_root(
                ProofFamilies::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                4,
                BoundTreeRootUse::Input,
            );
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
            assert!(
                FIRST_PROFILE_APPLICATION_FAMILIES
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            for family in FIRST_PROFILE_APPLICATION_FAMILIES {
                assert!(ProofFamilyProfile::selected(family).is_ok());
            }
            assert_eq!(
                ProofFamilyProfile::selected(0x9999),
                Err(ProofProfileError::UnsupportedFamily),
            );
        }

        #[test]
        fn committed_material_root_shape_preserves_the_physical_trace_domain() {
            let committed_material_profile =
                super::super::super::selected_profile::selected_committed_material_profile()
                    .expect("selected committed-material profile");
            let physical_trace_domain_size =
                u64::try_from(committed_material_profile.trace_domain_size())
                    .expect("physical trace domain fits u64");
            let evaluation_domain_size =
                u64::try_from(committed_material_profile.evaluation_domain_size())
                    .expect("evaluation domain fits u64");
            let packed_trace_domain_size = physical_trace_domain_size
                * super::super::super::relation_plan::COMMITTED_MATERIAL_TRACE_PACKING_FACTOR;

            for family in [
                ProofFamilies::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            ] {
                assert_eq!(
                    super::super::super::selected_profile::selected_bound_root_source_trace_domain_size(
                        family,
                        BoundTreeConstructionKind::CommittedMaterial,
                        packed_trace_domain_size,
                        evaluation_domain_size,
                    ),
                    Ok(physical_trace_domain_size),
                );
                assert_eq!(
                    super::super::super::selected_profile::selected_bound_root_source_trace_domain_size(
                        family,
                        BoundTreeConstructionKind::CommittedMaterial,
                        physical_trace_domain_size,
                        evaluation_domain_size,
                    ),
                    Err(ProofProfileError::InvalidRelationPlan),
                );
            }
            for family in [
                ProofFamilies::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                ProofFamilies::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
            ] {
                assert_eq!(
                    super::super::super::selected_profile::selected_bound_root_source_trace_domain_size(
                        family,
                        BoundTreeConstructionKind::CommittedMaterial,
                        physical_trace_domain_size,
                        evaluation_domain_size,
                    ),
                    Ok(physical_trace_domain_size),
                );
                assert_eq!(
                    super::super::super::selected_profile::selected_bound_root_source_trace_domain_size(
                        family,
                        BoundTreeConstructionKind::CommittedMaterial,
                        packed_trace_domain_size,
                        evaluation_domain_size,
                    ),
                    Err(ProofProfileError::InvalidRelationPlan),
                );
            }
        }

        #[test]
        fn persistent_root_views_use_the_successor_phase_query_geometry() {
            assert_eq!(ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT, 387);
            for family in FIRST_PROFILE_APPLICATION_FAMILIES {
                assert_eq!(
                    ProofFamilyProfile::selected(family)
                        .map(|_| ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT),
                    Ok(387),
                );
            }
            assert_eq!(
                ProofFamilyProfile::selected(0x9999)
                    .map(|_| ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT),
                Err(ProofProfileError::UnsupportedFamily),
            );
        }
    }
}
