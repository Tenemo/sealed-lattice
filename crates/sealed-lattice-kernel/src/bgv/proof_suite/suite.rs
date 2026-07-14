use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::{
    bgv::{
        evaluator::{
            records::MAXIMUM_OPTION_COUNT,
            top_k::{
                direct_score_packing_basis_galois_elements,
                packed_rank_forward_basis_galois_elements,
                packed_rank_return_basis_galois_elements,
            },
        },
        parameters::{
            DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, ROOT_PARAMETERS, RootParameters,
            SPECIAL_PRIME,
        },
    },
    foundation::{
        ArtifactReference, CanonicalCodecError, CanonicalDecodeLimits, DistributionRecord,
        FOUNDATION_PROFILE, FoundationSchemaError, Hash512,
        MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT, PRIVATE_PROOF_SALT_PURPOSE,
        SuiteArtifactKind, SuiteRecord,
    },
};

use super::{
    COMMON_PROOF_PROFILE, ProofFamily, RelationPlanCatalog, SecurityAccounting,
    build_relation_plan_catalog,
    deterministic_artifacts::{
        DeterministicArtifactError, DeterministicSuiteArtifactSet, SuiteArtifactSemanticBlocker,
    },
    profile::{is_prime_u64, modular_power, security_accounting},
    profile_artifact::{ProofProfileArtifactError, ProofProfileSetArtifact},
    relation_plan::{RelationPlanValidationError, RelationPlanVariantSelector},
};

const COMPLETE_BALLOT_PACKAGE_BYTE_CEILING: u64 = 14_680_064;
const CEREMONY_BYTE_CEILING: u64 = 2_147_483_648;
const MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT: u16 = 1;
const MAXIMUM_RECOVERY_TRANSITIONS_PER_STATE_KEY: u16 = 1;
const MAXIMUM_SETUP_BYTES_PER_PARTICIPANT: u64 = 1_073_741_824;
const KEY_SWITCH_DATA_PRIMES_PER_BLOCK: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActionProofSchedule {
    pub(crate) top_count: u16,
    pub(crate) relinearization_positions: Vec<u32>,
    pub(crate) galois_positions: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GeneratedSuiteArtifact {
    pub(crate) canonical_bytes: Vec<u8>,
    pub(crate) reference: ArtifactReference,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GeneratedProofSuiteCandidate {
    pub(crate) ordered_galois_elements: Vec<usize>,
    pub(crate) action_schedules: Vec<ActionProofSchedule>,
    pub(crate) relation_plan_catalog: RelationPlanCatalog,
    pub(crate) artifacts: Vec<GeneratedSuiteArtifact>,
    pub(crate) suite_record: SuiteRecord,
    pub(crate) canonical_suite_record_bytes: Vec<u8>,
    pub(crate) suite_id: Hash512,
    pub(crate) security_accounting: SecurityAccounting,
}

/// An obligation that must be discharged before candidate bytes can authorize
/// proof acceptance. These values are implementation diagnostics only. They are
/// deliberately absent from every proof, suite artifact, and transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(test)]
pub(crate) enum CommonProofAcceptanceBlocker {
    CanonicalRelationProgramsNotLowered,
    CommonWitnessExtractionTheoremMissing,
    ApplicationToProximityReductionMissing,
    CompleteIntegerRelationCertificatesMissing,
    ConstructionSpecificZeroKnowledgeSimulatorMissing,
    AdaptiveSharedOracleQromReductionMissing,
    CompleteResourceFixedPointMissing,
    LegacyProofFamiliesNotMigrated,
    ScalarWasmBrowserResourceSpikeMissing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CommonProofAcceptanceError {
    pub(crate) blockers: Vec<CommonProofAcceptanceBlocker>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SuiteGenerationError {
    UnsupportedRosterSize,
    RootParameterMismatch,
    RotationSchedule(String),
    RelationPlan(RelationPlanValidationError),
    MissingPlan,
    MissingVariant,
    ArithmeticOverflow,
    ResourceCeilingExceeded,
    ArtifactCatalogMismatch,
    CanonicalEncoding(CanonicalCodecError),
    FoundationSchema(FoundationSchemaError),
    ProofProfileArtifact(ProofProfileArtifactError),
    DeterministicArtifact(DeterministicArtifactError),
    SemanticIncompleteness(Vec<SuiteArtifactSemanticBlocker>),
}

impl SuiteGenerationError {
    pub(crate) fn is_semantically_incomplete(&self) -> bool {
        matches!(self, Self::SemanticIncompleteness(_))
    }
}

impl From<RelationPlanValidationError> for SuiteGenerationError {
    fn from(error: RelationPlanValidationError) -> Self {
        Self::RelationPlan(error)
    }
}

impl From<CanonicalCodecError> for SuiteGenerationError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::CanonicalEncoding(error)
    }
}

impl From<FoundationSchemaError> for SuiteGenerationError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::FoundationSchema(error)
    }
}

impl From<ProofProfileArtifactError> for SuiteGenerationError {
    fn from(error: ProofProfileArtifactError) -> Self {
        Self::ProofProfileArtifact(error)
    }
}

impl From<DeterministicArtifactError> for SuiteGenerationError {
    fn from(error: DeterministicArtifactError) -> Self {
        Self::DeterministicArtifact(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SuiteConstructionMode {
    RequireCompleteArtifacts,
    PreserveIncompleteDevelopmentTranscriptDomain,
}

pub(crate) fn generate_proof_suite_candidate(
    roster_size: u16,
) -> Result<GeneratedProofSuiteCandidate, SuiteGenerationError> {
    generate_proof_suite_candidate_with_mode(
        roster_size,
        SuiteConstructionMode::RequireCompleteArtifacts,
    )
}

fn generate_proof_suite_candidate_with_mode(
    roster_size: u16,
    construction_mode: SuiteConstructionMode,
) -> Result<GeneratedProofSuiteCandidate, SuiteGenerationError> {
    if roster_size != FOUNDATION_PROFILE.participant_count {
        return Err(SuiteGenerationError::UnsupportedRosterSize);
    }
    validate_ring_parameters()?;
    let ordered_galois_elements = selected_galois_catalog()?;
    let relinearization_catalog_length = 1_u32;
    let galois_catalog_length = u32::try_from(ordered_galois_elements.len())
        .map_err(|_| SuiteGenerationError::ArithmeticOverflow)?;
    let action_schedules = (1..=MAXIMUM_OPTION_COUNT)
        .map(|top_count| ActionProofSchedule {
            top_count: top_count as u16,
            relinearization_positions: vec![0],
            galois_positions: (0..galois_catalog_length).collect(),
        })
        .collect::<Vec<_>>();
    let relation_plan_catalog =
        build_relation_plan_catalog(relinearization_catalog_length, galois_catalog_length)?;
    let (proof_profile_artifact, proof_profile_bytes) =
        build_proof_profile_artifact(&relation_plan_catalog)?;
    let deterministic_artifacts = DeterministicSuiteArtifactSet::from_operative_parameters()?;
    deterministic_artifacts
        .validate_available_structure(&proof_profile_artifact, &ordered_galois_elements)?;
    if construction_mode == SuiteConstructionMode::RequireCompleteArtifacts {
        return Err(SuiteGenerationError::SemanticIncompleteness(
            deterministic_artifacts.semantic_blockers(&proof_profile_artifact)?,
        ));
    }

    let maximum_candidate_packages_per_action = u32::from(roster_size);
    let maximum_target_share_submissions = u32::from(roster_size);
    let (maximum_proof_objects_per_action, maximum_proof_bytes_per_action) =
        derive_action_resource_caps(
            roster_size,
            maximum_candidate_packages_per_action,
            maximum_target_share_submissions,
            &action_schedules,
            &relation_plan_catalog,
        )?;

    let maximum_candidate_bytes_per_participant =
        u64::from(MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
            .checked_mul(COMPLETE_BALLOT_PACKAGE_BYTE_CEILING)
            .ok_or(SuiteGenerationError::ArithmeticOverflow)?;
    let maximum_candidate_bytes_per_action = u64::from(maximum_candidate_packages_per_action)
        .checked_mul(COMPLETE_BALLOT_PACKAGE_BYTE_CEILING)
        .ok_or(SuiteGenerationError::ArithmeticOverflow)?;
    let artifact_bodies =
        deterministic_artifacts.encode_incomplete_development_bodies(proof_profile_bytes)?;
    let artifacts = artifact_bodies
        .into_iter()
        .zip(SuiteArtifactKind::ALL)
        .map(|(canonical_bytes, artifact_kind)| {
            let reference =
                ArtifactReference::from_canonical_artifact(artifact_kind, &canonical_bytes)?;
            Ok(GeneratedSuiteArtifact {
                canonical_bytes,
                reference,
            })
        })
        .collect::<Result<Vec<_>, SuiteGenerationError>>()?;
    let artifact_references = artifacts
        .iter()
        .map(|artifact| artifact.reference)
        .collect::<Vec<_>>();
    if artifact_references
        .iter()
        .map(|reference| reference.artifact_kind)
        .ne(SuiteArtifactKind::ALL)
    {
        return Err(SuiteGenerationError::ArtifactCatalogMismatch);
    }
    let artifact_byte_length = artifacts.iter().try_fold(0_u64, |total, artifact| {
        total
            .checked_add(artifact.canonical_bytes.len() as u64)
            .ok_or(SuiteGenerationError::ArithmeticOverflow)
    })?;
    let maximum_public_corpus_bytes = maximum_candidate_bytes_per_action
        .checked_add(maximum_proof_bytes_per_action)
        .and_then(|value| value.checked_add(artifact_byte_length))
        .ok_or(SuiteGenerationError::ArithmeticOverflow)?;
    if maximum_candidate_bytes_per_action > CEREMONY_BYTE_CEILING
        || maximum_proof_bytes_per_action > CEREMONY_BYTE_CEILING
        || maximum_public_corpus_bytes > CEREMONY_BYTE_CEILING
    {
        return Err(SuiteGenerationError::ResourceCeilingExceeded);
    }

    let suite_record = build_suite_record(
        u16::try_from(maximum_target_share_submissions)
            .map_err(|_| SuiteGenerationError::ArithmeticOverflow)?,
        maximum_candidate_packages_per_action,
        maximum_proof_objects_per_action,
        maximum_candidate_bytes_per_participant,
        maximum_candidate_bytes_per_action,
        maximum_proof_bytes_per_action,
        maximum_public_corpus_bytes,
        artifact_references,
    )?;
    let canonical_suite_record_bytes = suite_record.encode()?;
    let suite_id = suite_record.suite_id()?;
    let (maximum_authentication_equations, maximum_iop_round_count) =
        relation_plan_catalog.maximum_security_metrics();
    let security_accounting = security_accounting(
        maximum_proof_objects_per_action,
        relation_plan_catalog.maximum_evaluation_domain_size(),
        maximum_authentication_equations,
        maximum_iop_round_count,
    );

    Ok(GeneratedProofSuiteCandidate {
        ordered_galois_elements,
        action_schedules,
        relation_plan_catalog,
        artifacts,
        suite_record,
        canonical_suite_record_bytes,
        suite_id,
        security_accounting,
    })
}

pub(crate) fn common_proof_suite_id() -> [u8; 64] {
    common_proof_suite_candidate().suite_id.into_bytes()
}

pub(crate) fn common_proof_randomness_purpose_is_assigned(
    family_schema_identifier: u16,
    purpose: u16,
) -> bool {
    let Some(family) = ProofFamily::from_schema_identifier(family_schema_identifier) else {
        return false;
    };
    let candidate = common_proof_suite_candidate();
    let Some(plan) = candidate.relation_plan_catalog.plan(family) else {
        return false;
    };
    if purpose == PRIVATE_PROOF_SALT_PURPOSE {
        return family.privacy_mode() == super::relation_plan::ProofPrivacyMode::SecretBearing;
    }
    plan.variants.iter().any(|variant| {
        candidate
            .relation_plan_catalog
            .validate_mask_purpose(family, variant.selector, purpose)
            .is_ok()
    })
}

fn common_proof_suite_candidate() -> &'static GeneratedProofSuiteCandidate {
    static CANDIDATE: OnceLock<GeneratedProofSuiteCandidate> = OnceLock::new();
    CANDIDATE.get_or_init(|| {
        generate_proof_suite_candidate_with_mode(
            FOUNDATION_PROFILE.participant_count,
            SuiteConstructionMode::PreserveIncompleteDevelopmentTranscriptDomain,
        )
        .expect("the fixed development transcript domain must remain reproducible")
    })
}

#[cfg(test)]
pub(crate) fn generate_incomplete_development_proof_suite_candidate(
    roster_size: u16,
) -> Result<GeneratedProofSuiteCandidate, SuiteGenerationError> {
    generate_proof_suite_candidate_with_mode(
        roster_size,
        SuiteConstructionMode::PreserveIncompleteDevelopmentTranscriptDomain,
    )
}

#[cfg(test)]
pub(crate) fn require_common_proof_acceptance(
    _candidate: &GeneratedProofSuiteCandidate,
) -> Result<(), CommonProofAcceptanceError> {
    // Candidate generation proves the implemented arithmetic and structural
    // gates, but it is intentionally not an acceptance path. Keep this closed
    // list executable so a caller cannot accidentally treat a deterministic
    // candidate identifier as a cryptographic proof-suite authorization.
    Err(CommonProofAcceptanceError {
        blockers: vec![
            CommonProofAcceptanceBlocker::CanonicalRelationProgramsNotLowered,
            CommonProofAcceptanceBlocker::CommonWitnessExtractionTheoremMissing,
            CommonProofAcceptanceBlocker::ApplicationToProximityReductionMissing,
            CommonProofAcceptanceBlocker::CompleteIntegerRelationCertificatesMissing,
            CommonProofAcceptanceBlocker::ConstructionSpecificZeroKnowledgeSimulatorMissing,
            CommonProofAcceptanceBlocker::AdaptiveSharedOracleQromReductionMissing,
            CommonProofAcceptanceBlocker::CompleteResourceFixedPointMissing,
            CommonProofAcceptanceBlocker::LegacyProofFamiliesNotMigrated,
            CommonProofAcceptanceBlocker::ScalarWasmBrowserResourceSpikeMissing,
        ],
    })
}

fn validate_ring_parameters() -> Result<(), SuiteGenerationError> {
    if POLYNOMIAL_DEGREE != 32_768
        || PLAINTEXT_MODULUS != 65_537
        || !is_prime_u64(PLAINTEXT_MODULUS)
    {
        return Err(SuiteGenerationError::RootParameterMismatch);
    }
    validate_root_parameters(&ROOT_PARAMETERS)?;
    validate_slot_layout()?;
    Ok(())
}

fn validate_root_parameters(
    root_parameters: &[RootParameters],
) -> Result<(), SuiteGenerationError> {
    let twice_degree = 2_u64 * POLYNOMIAL_DEGREE as u64;
    for parameters in root_parameters {
        if !is_prime_u64(parameters.modulus)
            || !(parameters.modulus - 1).is_multiple_of(twice_degree)
            || modular_power(parameters.negacyclic_root, twice_degree, parameters.modulus) != 1
            || modular_power(
                parameters.negacyclic_root,
                POLYNOMIAL_DEGREE as u64,
                parameters.modulus,
            ) != parameters.modulus - 1
            || modular_power(
                parameters.cyclic_root,
                POLYNOMIAL_DEGREE as u64,
                parameters.modulus,
            ) != 1
            || modular_power(
                parameters.cyclic_root,
                (POLYNOMIAL_DEGREE / 2) as u64,
                parameters.modulus,
            ) == 1
        {
            return Err(SuiteGenerationError::RootParameterMismatch);
        }
    }
    Ok(())
}

fn validate_slot_layout() -> Result<(), SuiteGenerationError> {
    let automorphism_modulus = 2_u64
        .checked_mul(
            u64::try_from(POLYNOMIAL_DEGREE)
                .map_err(|_| SuiteGenerationError::ArithmeticOverflow)?,
        )
        .ok_or(SuiteGenerationError::ArithmeticOverflow)?;
    let generator_order = u64::try_from(POLYNOMIAL_DEGREE / 2)
        .map_err(|_| SuiteGenerationError::ArithmeticOverflow)?;
    if modular_power(3, generator_order, automorphism_modulus) != 1
        || modular_power(3, generator_order / 2, automorphism_modulus) == 1
    {
        return Err(SuiteGenerationError::RootParameterMismatch);
    }

    let mut exponents = BTreeSet::new();
    let mut exponent = 1_u64;
    for _ in 0..generator_order {
        exponents.insert(exponent);
        exponents.insert(automorphism_modulus - exponent);
        exponent = exponent
            .checked_mul(3)
            .ok_or(SuiteGenerationError::ArithmeticOverflow)?
            % automorphism_modulus;
    }
    if exponents.len() != POLYNOMIAL_DEGREE
        || exponents.iter().any(|exponent| exponent.is_multiple_of(2))
    {
        return Err(SuiteGenerationError::RootParameterMismatch);
    }
    Ok(())
}

fn selected_galois_catalog() -> Result<Vec<usize>, SuiteGenerationError> {
    let mut elements = BTreeSet::new();
    for result in [
        direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT),
        packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT),
        packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT),
    ] {
        elements
            .extend(result.map_err(|error| SuiteGenerationError::RotationSchedule(error.message))?);
    }
    if elements.is_empty() {
        return Err(SuiteGenerationError::RotationSchedule(
            "the selected evaluator schedule contains no Galois positions".to_string(),
        ));
    }
    Ok(elements.into_iter().collect())
}

fn derive_action_resource_caps(
    roster_size: u16,
    candidate_package_count: u32,
    target_share_submission_count: u32,
    action_schedules: &[ActionProofSchedule],
    relation_plan_catalog: &RelationPlanCatalog,
) -> Result<(u32, u64), SuiteGenerationError> {
    let mut maximum_object_count = 0_u32;
    let mut maximum_byte_count = 0_u64;
    for schedule in action_schedules {
        let relinearization_count = schedule.relinearization_positions.len() as u32;
        let galois_count = schedule.galois_positions.len() as u32;
        let mut action_object_count = 0_u32;
        let mut action_byte_count = 0_u64;
        for family in ProofFamily::ALL {
            let slot_count = family
                .slot_ceiling(
                    u32::from(roster_size),
                    relinearization_count,
                    galois_count,
                    candidate_package_count,
                    target_share_submission_count,
                )
                .ok_or(SuiteGenerationError::ArithmeticOverflow)?;
            action_object_count = action_object_count
                .checked_add(slot_count)
                .ok_or(SuiteGenerationError::ArithmeticOverflow)?;
            let plan = relation_plan_catalog
                .plan(family)
                .ok_or(SuiteGenerationError::MissingPlan)?;
            let family_bytes = match family {
                ProofFamily::RelinearizationRoundOne
                | ProofFamily::RelinearizationRoundOneAggregate
                | ProofFamily::RelinearizationRoundTwo => schedule
                    .relinearization_positions
                    .iter()
                    .try_fold(0_u64, |total, position| {
                        let variant = variant_for_selector(
                            plan,
                            RelationPlanVariantSelector::SchedulePosition(*position),
                        )?;
                        let multiplicity =
                            if family == ProofFamily::RelinearizationRoundOneAggregate {
                                1_u64
                            } else {
                                u64::from(roster_size)
                            };
                        total
                            .checked_add(
                                multiplicity
                                    .checked_mul(variant.proof_grammar_metrics.proof_byte_ceiling)
                                    .ok_or(SuiteGenerationError::ArithmeticOverflow)?,
                            )
                            .ok_or(SuiteGenerationError::ArithmeticOverflow)
                    })?,
                ProofFamily::GaloisKeyShare => {
                    schedule
                        .galois_positions
                        .iter()
                        .try_fold(0_u64, |total, position| {
                            let variant = variant_for_selector(
                                plan,
                                RelationPlanVariantSelector::SchedulePosition(*position),
                            )?;
                            total
                                .checked_add(
                                    u64::from(roster_size)
                                        .checked_mul(
                                            variant.proof_grammar_metrics.proof_byte_ceiling,
                                        )
                                        .ok_or(SuiteGenerationError::ArithmeticOverflow)?,
                                )
                                .ok_or(SuiteGenerationError::ArithmeticOverflow)
                        })?
                }
                ProofFamily::EvaluatorKeyAggregate => {
                    let variant = variant_for_selector(
                        plan,
                        RelationPlanVariantSelector::TopCount(schedule.top_count),
                    )?;
                    variant.proof_grammar_metrics.proof_byte_ceiling
                }
                _ => {
                    let variant =
                        variant_for_selector(plan, RelationPlanVariantSelector::Unscheduled)?;
                    u64::from(slot_count)
                        .checked_mul(variant.proof_grammar_metrics.proof_byte_ceiling)
                        .ok_or(SuiteGenerationError::ArithmeticOverflow)?
                }
            };
            action_byte_count = action_byte_count
                .checked_add(family_bytes)
                .ok_or(SuiteGenerationError::ArithmeticOverflow)?;
        }
        maximum_object_count = maximum_object_count.max(action_object_count);
        maximum_byte_count = maximum_byte_count.max(action_byte_count);
    }
    Ok((maximum_object_count, maximum_byte_count))
}

fn variant_for_selector(
    plan: &super::relation_plan::RelationPlan,
    selector: RelationPlanVariantSelector,
) -> Result<&super::relation_plan::RelationPlanVariant, SuiteGenerationError> {
    plan.variants
        .iter()
        .find(|variant| variant.selector == selector)
        .ok_or(SuiteGenerationError::MissingVariant)
}

fn build_proof_profile_artifact(
    relation_plan_catalog: &RelationPlanCatalog,
) -> Result<(ProofProfileSetArtifact, Vec<u8>), SuiteGenerationError> {
    let artifact =
        ProofProfileSetArtifact::from_unlowered_relation_plan_catalog(relation_plan_catalog)?;
    let encoded = artifact.encode()?;
    let decoded = ProofProfileSetArtifact::decode(&encoded, &CanonicalDecodeLimits::default())?;
    if decoded != artifact || decoded.encode()? != encoded {
        return Err(SuiteGenerationError::ArtifactCatalogMismatch);
    }
    match decoded.validate() {
        Ok(()) | Err(ProofProfileArtifactError::IncompleteSemanticPlan) => Ok((artifact, encoded)),
        Err(error) => Err(error.into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_suite_record(
    maximum_target_share_submissions: u16,
    maximum_candidate_packages_per_action: u32,
    maximum_proof_objects_per_action: u32,
    maximum_candidate_bytes_per_participant: u64,
    maximum_candidate_bytes_per_action: u64,
    maximum_proof_bytes_per_action: u64,
    maximum_public_corpus_bytes: u64,
    artifact_references: Vec<ArtifactReference>,
) -> Result<SuiteRecord, SuiteGenerationError> {
    let target_level = crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL;
    let ordered_target_data_prime_indexes = (0..=target_level)
        .map(|index| u16::try_from(index).map_err(|_| SuiteGenerationError::ArithmeticOverflow))
        .collect::<Result<Vec<_>, _>>()?;
    let ordered_sharing_data_prime_indexes = (0..DATA_PRIMES.len())
        .map(|index| u16::try_from(index).map_err(|_| SuiteGenerationError::ArithmeticOverflow))
        .collect::<Result<Vec<_>, _>>()?;
    let maximum_private_sampler_candidate_draws_per_output =
        u32::try_from(MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT)
            .map_err(|_| SuiteGenerationError::ArithmeticOverflow)?;
    Ok(SuiteRecord {
        roster_size: FOUNDATION_PROFILE.participant_count,
        byzantine_bound: FOUNDATION_PROFILE.active_fault_bound,
        reconstruction_threshold: FOUNDATION_PROFILE.reconstruction_threshold,
        finality_quorum: FOUNDATION_PROFILE.finality_quorum,
        polynomial_degree: u32::try_from(POLYNOMIAL_DEGREE)
            .map_err(|_| SuiteGenerationError::ArithmeticOverflow)?,
        plaintext_modulus: PLAINTEXT_MODULUS,
        ordered_data_primes: DATA_PRIMES.to_vec(),
        ordered_special_primes: vec![SPECIAL_PRIME],
        ordered_target_data_prime_indexes,
        ordered_sharing_data_prime_indexes,
        key_switch_data_primes_per_block: KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
        maximum_ballot_attempts_per_participant: MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        maximum_recovery_transitions_per_state_key: MAXIMUM_RECOVERY_TRANSITIONS_PER_STATE_KEY,
        maximum_target_share_submissions,
        maximum_private_sampler_candidate_draws_per_output,
        maximum_public_sampler_candidate_draws_per_output: COMMON_PROOF_PROFILE
            .maximum_fiat_shamir_candidate_draws_per_output,
        maximum_candidate_packages_per_action,
        maximum_proof_objects_per_action,
        maximum_candidate_bytes_per_participant,
        maximum_candidate_bytes_per_action,
        maximum_setup_bytes_per_participant: MAXIMUM_SETUP_BYTES_PER_PARTICIPANT,
        maximum_proof_bytes_per_action,
        maximum_public_corpus_bytes,
        maximum_participant_upload_bytes: MAXIMUM_SETUP_BYTES_PER_PARTICIPANT
            .max(maximum_candidate_bytes_per_participant),
        maximum_ceremony_upload_bytes: CEREMONY_BYTE_CEILING,
        distributions: DistributionRecord::supported_profile_records(),
        artifacts: artifact_references,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn for_each_data_and_special_root_parameter(mut assertion: impl FnMut(usize, u64)) {
        let expected_moduli = DATA_PRIMES
            .into_iter()
            .chain([SPECIAL_PRIME])
            .collect::<Vec<_>>();
        assert_eq!(ROOT_PARAMETERS[0].modulus, PLAINTEXT_MODULUS);
        assert_eq!(ROOT_PARAMETERS.len(), expected_moduli.len() + 1);
        for (ciphertext_parameter_index, expected_modulus) in
            expected_moduli.into_iter().enumerate()
        {
            let root_parameter_index = ciphertext_parameter_index + 1;
            assert_eq!(
                ROOT_PARAMETERS[root_parameter_index].modulus,
                expected_modulus
            );
            assertion(root_parameter_index, expected_modulus);
        }
    }

    #[test]
    fn each_data_and_special_prime_rejects_a_prime_without_two_n_congruence() {
        const PRIME_WITHOUT_TWO_N_CONGRUENCE: u64 = 3;
        assert!(is_prime_u64(PRIME_WITHOUT_TWO_N_CONGRUENCE));
        assert!(
            !(PRIME_WITHOUT_TWO_N_CONGRUENCE - 1).is_multiple_of(2_u64 * POLYNOMIAL_DEGREE as u64)
        );

        for_each_data_and_special_root_parameter(|root_parameter_index, expected_modulus| {
            let mut invalid_parameters = ROOT_PARAMETERS;
            invalid_parameters[root_parameter_index].modulus = PRIME_WITHOUT_TWO_N_CONGRUENCE;
            assert_eq!(
                validate_root_parameters(&invalid_parameters),
                Err(SuiteGenerationError::RootParameterMismatch),
                "modulus {expected_modulus} accepted a replacement prime without 2N congruence"
            );
        });
    }

    #[test]
    fn each_data_and_special_prime_rejects_a_wrong_negacyclic_exact_order_root() {
        for_each_data_and_special_root_parameter(|root_parameter_index, expected_modulus| {
            let mut invalid_parameters = ROOT_PARAMETERS;
            invalid_parameters[root_parameter_index].negacyclic_root =
                invalid_parameters[root_parameter_index].cyclic_root;
            assert_eq!(
                validate_root_parameters(&invalid_parameters),
                Err(SuiteGenerationError::RootParameterMismatch),
                "modulus {expected_modulus} accepted an order-N root as its negacyclic root"
            );
        });
    }

    #[test]
    fn each_data_and_special_prime_rejects_a_wrong_cyclic_exact_order_root() {
        for_each_data_and_special_root_parameter(|root_parameter_index, expected_modulus| {
            let mut invalid_parameters = ROOT_PARAMETERS;
            invalid_parameters[root_parameter_index].cyclic_root =
                invalid_parameters[root_parameter_index].negacyclic_root;
            assert_eq!(
                validate_root_parameters(&invalid_parameters),
                Err(SuiteGenerationError::RootParameterMismatch),
                "modulus {expected_modulus} accepted an order-2N root as its cyclic root"
            );
        });
    }
}
