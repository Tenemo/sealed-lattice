//! Rust-owned authority boundary for the exact selected suite.

use std::collections::BTreeMap;

use crate::bgv::{
    key_switch_topology::{
        KEY_SWITCH_DATA_PRIMES_PER_BLOCK, KEY_SWITCH_SPECIAL_PRIMES, KeySwitchDecompositionTopology,
    },
    parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    proof_suite::{
        MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, SelectedEvaluatorEntryKind,
        selected_evaluator_galois_entry_positions,
        selected_evaluator_relinearization_entry_positions,
    },
};

#[cfg(test)]
use crate::bgv::{
    evaluator::{
        candidate_evidence::EvaluatorCandidateInput,
        noise_recurrence::direct_ballot_target_noise_bounds,
        program::selected_evaluator_program_set,
    },
    parameters::validate_supported_algebraic_parameters,
    proof_suite::{
        selected_complete_proof_resource_accounting, selected_evaluator_aggregate_relation_plan,
        selected_evaluator_entry_positions, selected_galois_key_share_batch_schedule,
        selected_recipient_private_vss_payload_byte_length, selected_relation_plans,
        selected_target_decryption_flooding_bound,
    },
};

#[cfg(test)]
use super::schemas::PROTOTYPE_PARTICIPANT_COUNT;
use super::schemas::SchemaResult;
#[cfg(test)]
use super::suite_artifacts::{
    selected_encoder_and_ballot_layout_artifact_bytes, selected_evaluator_program_artifact_bytes,
    selected_lattice_commitment_profile_artifact_bytes, selected_proof_profile_artifact_bytes,
    selected_target_decryption_profile_artifact_bytes,
    selected_verifiable_secret_sharing_profile_artifact_bytes,
};
use super::{FOUNDATION_PROFILE, FoundationSchemaError, Hash512, RefusalReason, SuiteRecord};

#[cfg(test)]
use super::{
    ArtifactKind, ArtifactReference, CanonicalDecodeLimits, CanonicalItem, CanonicalTuple,
    MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, ProofApplicationSlotCeilings, SuiteCountLimits,
    derive_foundation_roster_parameters,
};
#[cfg(test)]
use crate::bgv::proof_suite::SelectedEvaluatorEntryPosition;

#[cfg(test)]
pub(crate) const SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT: u16 = 3;
pub(crate) const SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 64;
pub(crate) const SELECTED_MAXIMUM_PUBLIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 128;
#[cfg(test)]
pub(crate) const SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION: u32 = 20;

/// Non-serializable authority for the exact selected cryptographic suite.
/// Callers cannot supply an identifier, feasibility measurement, or artifact
/// reference as a substitute for canonical suite selection.
pub(crate) struct SelectedSuiteCapability {
    suite_identifier: [u8; 64],
}

impl SelectedSuiteCapability {
    pub(crate) const fn protocol_version(&self) -> u16 {
        FOUNDATION_PROFILE.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn ordered_data_primes(&self) -> &'static [u64] {
        &DATA_PRIMES
    }

    pub(crate) const fn ordered_special_primes(&self) -> &'static [u64] {
        &KEY_SWITCH_SPECIAL_PRIMES
    }

    pub(crate) const fn key_switch_data_primes_per_block(&self) -> u16 {
        KEY_SWITCH_DATA_PRIMES_PER_BLOCK as u16
    }

    pub(crate) const fn polynomial_degree(&self) -> u32 {
        POLYNOMIAL_DEGREE as u32
    }

    pub(crate) const fn maximum_private_sampler_candidate_draws_per_output(&self) -> u32 {
        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT
    }
}

#[cfg(test)]
pub(crate) fn selected_suite_capability_for_tests() -> SelectedSuiteCapability {
    let structural_record = SuiteRecord::new(
        selected_count_limits().expect("structural test count limits derive"),
        structural_artifact_references_for_tests(),
    )
    .expect("structural test suite is canonical");
    SelectedSuiteCapability {
        suite_identifier: structural_record
            .suite_id()
            .expect("structural test suite identifier derives")
            .into_bytes(),
    }
}

#[cfg(test)]
fn structural_artifact_references_for_tests() -> Vec<ArtifactReference> {
    ArtifactKind::ALL
        .into_iter()
        .map(|artifact_kind| {
            let bytes = CanonicalTuple::new(
                artifact_kind.artifact_schema_identifier(),
                artifact_kind.artifact_schema_version(),
                vec![CanonicalItem::unsigned16(artifact_kind.canonical_code())],
            )
            .encode()
            .expect("structural test artifact encodes");
            ArtifactReference::from_canonical_artifact_bytes(
                artifact_kind,
                &bytes,
                &CanonicalDecodeLimits::default(),
            )
            .expect("structural test artifact reference derives")
        })
        .collect()
}

pub(crate) fn select_suite_record(record: &SuiteRecord) -> SchemaResult<SelectedSuiteCapability> {
    require_selected_suite_record(record)?;
    Ok(SelectedSuiteCapability {
        suite_identifier: record.suite_id()?.into_bytes(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorLevelResourceAccounting {
    catalog_level: usize,
    component_wire_byte_length: u64,
    component_resident_byte_length: u64,
    source_component_count_per_participant: u64,
    final_component_count: u64,
    source_wire_byte_length_per_participant: u64,
    source_resident_byte_length_per_participant: u64,
    final_wire_byte_length: u64,
    final_resident_byte_length: u64,
}

impl SelectedEvaluatorLevelResourceAccounting {
    pub(crate) const fn catalog_level(self) -> usize {
        self.catalog_level
    }

    pub(crate) const fn component_wire_byte_length(self) -> u64 {
        self.component_wire_byte_length
    }

    pub(crate) const fn component_resident_byte_length(self) -> u64 {
        self.component_resident_byte_length
    }

    pub(crate) const fn source_component_count_per_participant(self) -> u64 {
        self.source_component_count_per_participant
    }

    pub(crate) const fn final_component_count(self) -> u64 {
        self.final_component_count
    }

    pub(crate) const fn source_wire_byte_length_per_participant(self) -> u64 {
        self.source_wire_byte_length_per_participant
    }

    pub(crate) const fn source_resident_byte_length_per_participant(self) -> u64 {
        self.source_resident_byte_length_per_participant
    }

    pub(crate) const fn final_wire_byte_length(self) -> u64 {
        self.final_wire_byte_length
    }

    pub(crate) const fn final_resident_byte_length(self) -> u64 {
        self.final_resident_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorResourceAccounting {
    levels: Vec<SelectedEvaluatorLevelResourceAccounting>,
    relinearization_position_count: u32,
    galois_position_count: u32,
    source_component_count_per_participant: u64,
    source_public_polynomial_context_hash_count_per_participant: u64,
    source_public_polynomial_context_hash_resident_byte_length_per_participant: u64,
    final_component_count: u64,
    source_wire_byte_length_per_participant: u64,
    source_resident_byte_length_per_participant: u64,
    final_evaluator_key_store_wire_byte_length: u64,
    final_evaluator_key_store_resident_byte_length: u64,
    ceremony_setup_wire_byte_length: u64,
    ceremony_source_and_final_resident_volume_byte_length: u64,
}

impl SelectedEvaluatorResourceAccounting {
    pub(crate) fn levels(&self) -> &[SelectedEvaluatorLevelResourceAccounting] {
        &self.levels
    }

    pub(crate) const fn source_component_count_per_participant(&self) -> u64 {
        self.source_component_count_per_participant
    }

    pub(crate) const fn relinearization_position_count(&self) -> u32 {
        self.relinearization_position_count
    }

    pub(crate) const fn galois_position_count(&self) -> u32 {
        self.galois_position_count
    }

    pub(crate) const fn source_public_polynomial_context_hash_count_per_participant(&self) -> u64 {
        self.source_public_polynomial_context_hash_count_per_participant
    }

    pub(crate) const fn source_public_polynomial_context_hash_resident_byte_length_per_participant(
        &self,
    ) -> u64 {
        self.source_public_polynomial_context_hash_resident_byte_length_per_participant
    }

    pub(crate) const fn final_component_count(&self) -> u64 {
        self.final_component_count
    }

    pub(crate) const fn source_wire_byte_length_per_participant(&self) -> u64 {
        self.source_wire_byte_length_per_participant
    }

    pub(crate) const fn source_resident_byte_length_per_participant(&self) -> u64 {
        self.source_resident_byte_length_per_participant
    }

    pub(crate) const fn final_evaluator_key_store_wire_byte_length(&self) -> u64 {
        self.final_evaluator_key_store_wire_byte_length
    }

    pub(crate) const fn final_evaluator_key_store_resident_byte_length(&self) -> u64 {
        self.final_evaluator_key_store_resident_byte_length
    }

    pub(crate) const fn ceremony_setup_wire_byte_length(&self) -> u64 {
        self.ceremony_setup_wire_byte_length
    }

    pub(crate) const fn ceremony_source_and_final_resident_volume_byte_length(&self) -> u64 {
        self.ceremony_source_and_final_resident_volume_byte_length
    }
}

pub(crate) fn selected_evaluator_resource_accounting()
-> SchemaResult<SelectedEvaluatorResourceAccounting> {
    let relinearization_positions =
        selected_evaluator_relinearization_entry_positions().map_err(|_| {
            invalid_selected_suite("selected relinearization key positions are invalid")
        })?;
    let galois_positions = selected_evaluator_galois_entry_positions()
        .map_err(|_| invalid_selected_suite("selected Galois key positions are invalid"))?;
    if relinearization_positions.is_empty() || galois_positions.is_empty() {
        return Err(invalid_selected_suite(
            "selected evaluator key position catalog is empty",
        ));
    }
    let mut component_counts_by_level = BTreeMap::<usize, (u64, u64)>::new();
    let mut relinearization_position_count = 0_u32;
    let mut galois_position_count = 0_u32;
    for position in relinearization_positions {
        let SelectedEvaluatorEntryKind::Relinearization { catalog_level } = position.key_kind()
        else {
            return Err(invalid_selected_suite(
                "selected relinearization position has the wrong key kind",
            ));
        };
        relinearization_position_count = relinearization_position_count
            .checked_add(1)
            .ok_or_else(resource_count_overflow)?;
        let counts = component_counts_by_level
            .entry(catalog_level)
            .or_insert((0, 0));
        counts.0 = counts
            .0
            .checked_add(3)
            .ok_or_else(resource_count_overflow)?;
        counts.1 = counts
            .1
            .checked_add(2)
            .ok_or_else(resource_count_overflow)?;
    }
    for position in galois_positions {
        let SelectedEvaluatorEntryKind::Galois { catalog_level, .. } = position.key_kind() else {
            return Err(invalid_selected_suite(
                "selected Galois position has the wrong key kind",
            ));
        };
        galois_position_count = galois_position_count
            .checked_add(1)
            .ok_or_else(resource_count_overflow)?;
        let counts = component_counts_by_level
            .entry(catalog_level)
            .or_insert((0, 0));
        counts.0 = counts
            .0
            .checked_add(1)
            .ok_or_else(resource_count_overflow)?;
        counts.1 = counts
            .1
            .checked_add(1)
            .ok_or_else(resource_count_overflow)?;
    }

    let mut levels = Vec::new();
    levels
        .try_reserve_exact(component_counts_by_level.len())
        .map_err(|_| resource_count_overflow())?;
    for (catalog_level, (source_component_count, final_component_count)) in
        component_counts_by_level
    {
        let decomposition_topology = KeySwitchDecompositionTopology::for_level(catalog_level)
            .map_err(|_| invalid_selected_suite("selected key-switch topology is invalid"))?;
        let component_wire_byte_length = decomposition_topology
            .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
            .map_err(|_| invalid_selected_suite("selected component wire length is invalid"))?;
        let component_resident_byte_length = decomposition_topology
            .resident_component_byte_length(POLYNOMIAL_DEGREE)
            .map_err(|_| invalid_selected_suite("selected component resident length is invalid"))?;
        levels.push(SelectedEvaluatorLevelResourceAccounting {
            catalog_level,
            component_wire_byte_length,
            component_resident_byte_length,
            source_component_count_per_participant: source_component_count,
            final_component_count,
            source_wire_byte_length_per_participant: component_wire_byte_length
                .checked_mul(source_component_count)
                .ok_or_else(resource_count_overflow)?,
            source_resident_byte_length_per_participant: component_resident_byte_length
                .checked_mul(source_component_count)
                .ok_or_else(resource_count_overflow)?,
            final_wire_byte_length: component_wire_byte_length
                .checked_mul(final_component_count)
                .ok_or_else(resource_count_overflow)?,
            final_resident_byte_length: component_resident_byte_length
                .checked_mul(final_component_count)
                .ok_or_else(resource_count_overflow)?,
        });
    }

    let source_component_count_per_participant =
        levels.iter().try_fold(0_u64, |total, level| {
            total
                .checked_add(level.source_component_count_per_participant())
                .ok_or_else(resource_count_overflow)
        })?;
    let final_component_count = levels.iter().try_fold(0_u64, |total, level| {
        total
            .checked_add(level.final_component_count())
            .ok_or_else(resource_count_overflow)
    })?;
    let source_wire_byte_length_per_participant =
        levels.iter().try_fold(0_u64, |total, level| {
            total
                .checked_add(level.source_wire_byte_length_per_participant())
                .ok_or_else(resource_count_overflow)
        })?;
    let source_component_resident_byte_length_per_participant =
        levels.iter().try_fold(0_u64, |total, level| {
            total
                .checked_add(level.source_resident_byte_length_per_participant())
                .ok_or_else(resource_count_overflow)
        })?;
    let source_public_polynomial_context_hash_count_per_participant =
        u64::from(relinearization_position_count)
            .checked_add(u64::from(galois_position_count))
            .ok_or_else(resource_count_overflow)?;
    let source_public_polynomial_context_hash_resident_byte_length_per_participant =
        source_public_polynomial_context_hash_count_per_participant
            .checked_mul(
                u64::try_from(Hash512::BYTE_LENGTH).map_err(|_| resource_count_overflow())?,
            )
            .ok_or_else(resource_count_overflow)?;
    let source_resident_byte_length_per_participant =
        source_component_resident_byte_length_per_participant
            .checked_add(source_public_polynomial_context_hash_resident_byte_length_per_participant)
            .ok_or_else(resource_count_overflow)?;
    let final_evaluator_key_store_wire_byte_length =
        levels.iter().try_fold(0_u64, |total, level| {
            total
                .checked_add(level.final_wire_byte_length())
                .ok_or_else(resource_count_overflow)
        })?;
    let final_evaluator_key_store_resident_byte_length =
        levels.iter().try_fold(0_u64, |total, level| {
            total
                .checked_add(level.final_resident_byte_length())
                .ok_or_else(resource_count_overflow)
        })?;
    let source_wire_byte_length_for_ceremony = source_wire_byte_length_per_participant
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(resource_count_overflow)?;
    let ceremony_setup_wire_byte_length = source_wire_byte_length_for_ceremony
        .checked_add(final_evaluator_key_store_wire_byte_length)
        .ok_or_else(resource_count_overflow)?;
    let ceremony_source_resident_volume_byte_length = source_resident_byte_length_per_participant
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(resource_count_overflow)?;
    let ceremony_source_and_final_resident_volume_byte_length =
        ceremony_source_resident_volume_byte_length
            .checked_add(final_evaluator_key_store_resident_byte_length)
            .ok_or_else(resource_count_overflow)?;
    let accounting = SelectedEvaluatorResourceAccounting {
        levels,
        relinearization_position_count,
        galois_position_count,
        source_component_count_per_participant,
        source_public_polynomial_context_hash_count_per_participant,
        source_public_polynomial_context_hash_resident_byte_length_per_participant,
        final_component_count,
        source_wire_byte_length_per_participant,
        source_resident_byte_length_per_participant,
        final_evaluator_key_store_wire_byte_length,
        final_evaluator_key_store_resident_byte_length,
        ceremony_setup_wire_byte_length,
        ceremony_source_and_final_resident_volume_byte_length,
    };
    require_selected_evaluator_resource_accounting(&accounting)?;
    Ok(accounting)
}

fn require_selected_evaluator_resource_accounting(
    accounting: &SelectedEvaluatorResourceAccounting,
) -> SchemaResult<()> {
    let mut source_component_count_per_participant = 0_u64;
    let mut final_component_count = 0_u64;
    let mut source_wire_byte_length_per_participant = 0_u64;
    let mut source_component_resident_byte_length_per_participant = 0_u64;
    let mut final_evaluator_key_store_wire_byte_length = 0_u64;
    let mut final_evaluator_key_store_resident_byte_length = 0_u64;
    let mut previous_catalog_level = None;
    for level in accounting.levels() {
        if previous_catalog_level
            .is_some_and(|previous_catalog_level| level.catalog_level() <= previous_catalog_level)
            || level.component_wire_byte_length() == 0
            || level.component_resident_byte_length() == 0
            || level.source_component_count_per_participant() == 0
            || level.final_component_count() == 0
            || level.source_wire_byte_length_per_participant()
                != level
                    .component_wire_byte_length()
                    .checked_mul(level.source_component_count_per_participant())
                    .ok_or_else(resource_count_overflow)?
            || level.source_resident_byte_length_per_participant()
                != level
                    .component_resident_byte_length()
                    .checked_mul(level.source_component_count_per_participant())
                    .ok_or_else(resource_count_overflow)?
            || level.final_wire_byte_length()
                != level
                    .component_wire_byte_length()
                    .checked_mul(level.final_component_count())
                    .ok_or_else(resource_count_overflow)?
            || level.final_resident_byte_length()
                != level
                    .component_resident_byte_length()
                    .checked_mul(level.final_component_count())
                    .ok_or_else(resource_count_overflow)?
        {
            return Err(invalid_selected_suite(
                "selected evaluator level accounting is inconsistent",
            ));
        }
        previous_catalog_level = Some(level.catalog_level());
        source_component_count_per_participant = source_component_count_per_participant
            .checked_add(level.source_component_count_per_participant())
            .ok_or_else(resource_count_overflow)?;
        final_component_count = final_component_count
            .checked_add(level.final_component_count())
            .ok_or_else(resource_count_overflow)?;
        source_wire_byte_length_per_participant = source_wire_byte_length_per_participant
            .checked_add(level.source_wire_byte_length_per_participant())
            .ok_or_else(resource_count_overflow)?;
        source_component_resident_byte_length_per_participant =
            source_component_resident_byte_length_per_participant
                .checked_add(level.source_resident_byte_length_per_participant())
                .ok_or_else(resource_count_overflow)?;
        final_evaluator_key_store_wire_byte_length = final_evaluator_key_store_wire_byte_length
            .checked_add(level.final_wire_byte_length())
            .ok_or_else(resource_count_overflow)?;
        final_evaluator_key_store_resident_byte_length =
            final_evaluator_key_store_resident_byte_length
                .checked_add(level.final_resident_byte_length())
                .ok_or_else(resource_count_overflow)?;
    }
    let source_public_polynomial_context_hash_count_per_participant =
        u64::from(accounting.relinearization_position_count())
            .checked_add(u64::from(accounting.galois_position_count()))
            .ok_or_else(resource_count_overflow)?;
    let source_public_polynomial_context_hash_resident_byte_length_per_participant =
        source_public_polynomial_context_hash_count_per_participant
            .checked_mul(
                u64::try_from(Hash512::BYTE_LENGTH).map_err(|_| resource_count_overflow())?,
            )
            .ok_or_else(resource_count_overflow)?;
    let source_resident_byte_length_per_participant =
        source_component_resident_byte_length_per_participant
            .checked_add(source_public_polynomial_context_hash_resident_byte_length_per_participant)
            .ok_or_else(resource_count_overflow)?;
    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let ceremony_setup_wire_byte_length = source_wire_byte_length_per_participant
        .checked_mul(participant_count)
        .and_then(|source_byte_length| {
            source_byte_length.checked_add(final_evaluator_key_store_wire_byte_length)
        })
        .ok_or_else(resource_count_overflow)?;
    let ceremony_source_and_final_resident_volume_byte_length =
        source_resident_byte_length_per_participant
            .checked_mul(participant_count)
            .and_then(|source_byte_length| {
                source_byte_length.checked_add(final_evaluator_key_store_resident_byte_length)
            })
            .ok_or_else(resource_count_overflow)?;
    if accounting.levels().is_empty()
        || accounting.relinearization_position_count() == 0
        || accounting.galois_position_count() == 0
        || accounting.source_component_count_per_participant()
            != source_component_count_per_participant
        || accounting.source_public_polynomial_context_hash_count_per_participant()
            != source_public_polynomial_context_hash_count_per_participant
        || accounting.source_public_polynomial_context_hash_resident_byte_length_per_participant()
            != source_public_polynomial_context_hash_resident_byte_length_per_participant
        || accounting.final_component_count() != final_component_count
        || accounting.source_wire_byte_length_per_participant()
            != source_wire_byte_length_per_participant
        || accounting.source_resident_byte_length_per_participant()
            != source_resident_byte_length_per_participant
        || accounting.final_evaluator_key_store_wire_byte_length()
            != final_evaluator_key_store_wire_byte_length
        || accounting.final_evaluator_key_store_resident_byte_length()
            != final_evaluator_key_store_resident_byte_length
        || accounting.ceremony_setup_wire_byte_length() != ceremony_setup_wire_byte_length
        || accounting.ceremony_source_and_final_resident_volume_byte_length()
            != ceremony_source_and_final_resident_volume_byte_length
        || accounting.ceremony_setup_wire_byte_length()
            > crate::foundation::MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || accounting.source_resident_byte_length_per_participant()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || accounting.final_evaluator_key_store_resident_byte_length()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(invalid_selected_suite(
            "selected evaluator resource accounting exceeds an absolute bound or is inconsistent",
        ));
    }
    Ok(())
}

pub(crate) fn require_selected_suite_record(record: &SuiteRecord) -> SchemaResult<()> {
    let expected_record = selected_suite_record()?;
    if record != &expected_record {
        return Err(invalid_selected_suite(
            "suite record is not the exact selected roster, count, and artifact profile",
        ));
    }
    Ok(())
}

fn selected_suite_record() -> SchemaResult<SuiteRecord> {
    // No runtime record is frozen while the evaluator topology, proof
    // representation, and release bounds remain unsettled. In particular, do
    // not run the research recurrence or relation compilers on a participant's
    // browser path merely to discover that the candidate is unavailable.
    Err(invalid_selected_suite(
        "no canonical selected suite record has been frozen",
    ))
}

#[cfg(test)]
fn derive_selected_suite_candidate_record() -> SchemaResult<SuiteRecord> {
    require_selected_foundation_geometry()?;
    require_selected_evaluator_catalog()?;
    require_selected_release_margins()?;

    // `selected_relation_plans` performs the final relation-plan check. In
    // particular, the committed-material checker owns the VSS numerator,
    // quotient, opening-degree, and evaluation-domain inequalities. An
    // unchecked compiler result can never reach suite identity derivation.
    let relation_plans = selected_relation_plans()
        .map_err(|_| invalid_selected_suite("selected relation geometry is invalid"))?;
    require_selected_complete_list_relation(&relation_plans)?;
    require_selected_absolute_resource_bounds()?;

    let count_limits = selected_count_limits()?;
    let artifact_references = derive_selected_artifact_references()?;
    SuiteRecord::new(count_limits, artifact_references)
}

#[cfg(test)]
fn require_selected_foundation_geometry() -> SchemaResult<()> {
    let roster_parameters = derive_foundation_roster_parameters(PROTOTYPE_PARTICIPANT_COUNT)
        .ok_or_else(|| invalid_selected_suite("selected roster geometry is invalid"))?;
    if FOUNDATION_PROFILE.participant_count != PROTOTYPE_PARTICIPANT_COUNT
        || FOUNDATION_PROFILE.participant_count != roster_parameters.participant_count
        || FOUNDATION_PROFILE.active_fault_bound != roster_parameters.active_fault_bound
        || FOUNDATION_PROFILE.reconstruction_threshold != roster_parameters.reconstruction_threshold
        || FOUNDATION_PROFILE.finality_quorum != roster_parameters.finality_quorum
        || FOUNDATION_PROFILE.state_witness_quorum != roster_parameters.state_witness_quorum
        || FOUNDATION_PROFILE.option_count < 2
        || FOUNDATION_PROFILE.minimum_score > FOUNDATION_PROFILE.maximum_score
    {
        return Err(invalid_selected_suite(
            "selected roster or ballot geometry is inconsistent",
        ));
    }
    validate_supported_algebraic_parameters()
        .map_err(|_| invalid_selected_suite("selected ring or modulus catalog is invalid"))?;
    // This also checks the exact canonical pair ordering against the live
    // ballot-slot codec, rather than trusting a copied layout constant.
    selected_encoder_and_ballot_layout_artifact_bytes()?;
    Ok(())
}

#[cfg(test)]
fn require_selected_evaluator_catalog() -> SchemaResult<()> {
    let candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| invalid_selected_suite("selected evaluator candidate is invalid"))?;
    if candidate.data_primes.as_slice() != DATA_PRIMES
        || candidate.special_primes.as_slice() != KEY_SWITCH_SPECIAL_PRIMES
        || candidate.galois_key_schedule.is_empty()
        || candidate.relinearization_levels.is_empty()
    {
        return Err(invalid_selected_suite(
            "selected evaluator candidate disagrees with the suite algebra",
        ));
    }

    let program_key_positions = selected_evaluator_program_set()
        .and_then(|program| program.key_positions())
        .map_err(|_| invalid_selected_suite("selected evaluator program is invalid"))?;
    if program_key_positions.streams().len() != usize::from(FOUNDATION_PROFILE.option_count)
        || program_key_positions.relinearization_catalog_levels()
            != candidate.relinearization_levels
        || program_key_positions.galois_catalog_positions().len()
            != candidate.galois_key_schedule.len()
        || program_key_positions
            .galois_catalog_positions()
            .iter()
            .zip(&candidate.galois_key_schedule)
            .any(|(position, expected)| {
                (position.galois_element(), position.catalog_level()) != *expected
            })
    {
        return Err(invalid_selected_suite(
            "selected evaluator program and ordered key catalog disagree",
        ));
    }

    let relinearization_positions = selected_evaluator_relinearization_entry_positions()
        .map_err(|_| invalid_selected_suite("selected relinearization catalog is invalid"))?;
    let galois_positions = selected_evaluator_galois_entry_positions()
        .map_err(|_| invalid_selected_suite("selected Galois catalog is invalid"))?;
    if relinearization_positions.len() != candidate.relinearization_levels.len()
        || galois_positions.len() != candidate.galois_key_schedule.len()
        || relinearization_positions
            .iter()
            .enumerate()
            .any(|(schedule_position, position)| {
                position.schedule_position() != u32::try_from(schedule_position).unwrap_or(u32::MAX)
                    || !matches!(
                        position.key_kind(),
                        SelectedEvaluatorEntryKind::Relinearization { catalog_level }
                            if Some(&catalog_level)
                                == candidate.relinearization_levels.get(schedule_position)
                    )
            })
        || galois_positions
            .iter()
            .enumerate()
            .any(|(schedule_position, position)| {
                position.schedule_position() != u32::try_from(schedule_position).unwrap_or(u32::MAX)
                    || !matches!(
                        position.key_kind(),
                        SelectedEvaluatorEntryKind::Galois {
                            galois_element,
                            catalog_level,
                        } if Some(&(galois_element, catalog_level))
                            == candidate.galois_key_schedule.get(schedule_position)
                    )
            })
    {
        return Err(invalid_selected_suite(
            "selected evaluator setup positions and ordered catalog disagree",
        ));
    }

    let selected_relinearization_position_count =
        u32::try_from(relinearization_positions.len()).map_err(|_| resource_count_overflow())?;
    let mut expected_complete_list = relinearization_positions;
    expected_complete_list.extend(galois_positions);
    let ordered_variant_catalogs = (1..=FOUNDATION_PROFILE.option_count)
        .map(|top_count| {
            selected_evaluator_entry_positions(top_count)
                .map(|positions| (top_count, positions))
                .map_err(|_| invalid_selected_suite("selected complete evaluator list is invalid"))
        })
        .collect::<SchemaResult<Vec<_>>>()?;
    require_complete_evaluator_variant_catalogs(
        &expected_complete_list,
        &ordered_variant_catalogs,
    )?;

    let selected_galois_batch_count =
        u32::try_from(selected_galois_key_share_batch_schedule().len())
            .map_err(|_| resource_count_overflow())?;
    let application_slot_ceilings = ProofApplicationSlotCeilings::derive(
        FOUNDATION_PROFILE.participant_count,
        selected_relinearization_position_count,
        selected_galois_batch_count,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    )?;
    if application_slot_ceilings.family_ceiling(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ) != Some(1)
    {
        return Err(invalid_selected_suite(
            "selected complete evaluator list does not own exactly one application slot",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn require_complete_evaluator_variant_catalogs(
    expected_complete_list: &[SelectedEvaluatorEntryPosition],
    ordered_variant_catalogs: &[(u16, Vec<SelectedEvaluatorEntryPosition>)],
) -> SchemaResult<()> {
    if expected_complete_list.is_empty()
        || ordered_variant_catalogs.len() != usize::from(FOUNDATION_PROFILE.option_count)
        || ordered_variant_catalogs.iter().enumerate().any(
            |(variant_index, (top_count, positions))| {
                u16::try_from(variant_index)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    != Some(*top_count)
                    || positions.as_slice() != expected_complete_list
            },
        )
    {
        return Err(invalid_selected_suite(
            "selected complete evaluator list omits, reorders, or substitutes a catalog entry",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn require_selected_release_margins() -> SchemaResult<()> {
    let option_count = usize::from(FOUNDATION_PROFILE.option_count);
    let target_bounds = direct_ballot_target_noise_bounds(
        u64::from(FOUNDATION_PROFILE.participant_count),
        usize::from(FOUNDATION_PROFILE.participant_count),
        option_count,
        u64::from(FOUNDATION_PROFILE.minimum_score),
        u64::from(FOUNDATION_PROFILE.maximum_score),
    )
    .map_err(|_| invalid_selected_suite("selected evaluator recurrence is invalid"))?;
    if target_bounds.len() != option_count
        || target_bounds
            .iter()
            .enumerate()
            .any(|(top_count_index, bound)| {
                bound.top_count != top_count_index + 1
                    || !bound.every_decryption_margin_is_positive()
            })
    {
        return Err(invalid_selected_suite(
            "selected evaluator recurrence has a non-positive decryption margin",
        ));
    }
    if selected_target_decryption_flooding_bound()
        .map_err(|_| invalid_selected_suite("selected factor-four release is invalid"))?
        .bits()
        == 0
    {
        return Err(invalid_selected_suite(
            "selected factor-four flooding bound is empty",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn require_selected_complete_list_relation(
    relation_plans: &[crate::bgv::proof_suite::ValidatedRelationPlanArtifact],
) -> SchemaResult<()> {
    let complete_list_schema_identifier =
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let mut matching_plans = relation_plans.iter().filter(|plan| {
        plan.application_statement_schema_identifier() == complete_list_schema_identifier
    });
    let selected_plan = matching_plans
        .next()
        .ok_or_else(|| invalid_selected_suite("selected complete-list relation is missing"))?;
    if matching_plans.next().is_some() {
        return Err(invalid_selected_suite(
            "selected complete-list relation is not unique",
        ));
    }
    let independently_derived_plan = selected_evaluator_aggregate_relation_plan()
        .map_err(|_| invalid_selected_suite("selected complete-list relation is invalid"))?;
    if selected_plan.compiled_plan() != &independently_derived_plan
        || independently_derived_plan.variants().len()
            != usize::from(FOUNDATION_PROFILE.option_count)
        || independently_derived_plan
            .variants()
            .iter()
            .enumerate()
            .any(|(variant_index, variant)| {
                variant.schedule_position().is_some()
                    || variant.top_count()
                        != u16::try_from(variant_index)
                            .ok()
                            .and_then(|index| index.checked_add(1))
            })
    {
        return Err(invalid_selected_suite(
            "selected complete-list counts or root topology disagree",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn require_selected_absolute_resource_bounds() -> SchemaResult<()> {
    selected_evaluator_resource_accounting()?;
    let vss_payload_byte_length = selected_recipient_private_vss_payload_byte_length()
        .map_err(|_| invalid_selected_suite("selected VSS payload accounting is invalid"))?;
    if vss_payload_byte_length == 0
        || vss_payload_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
    {
        return Err(invalid_selected_suite(
            "selected VSS payload exceeds the absolute stream bound",
        ));
    }

    let proof_resources = selected_complete_proof_resource_accounting()
        .map_err(|_| invalid_selected_suite("selected proof resource accounting is invalid"))?;
    if proof_resources.ordered_families().is_empty()
        || proof_resources.ordered_families().iter().any(|family| {
            family.maximum_proof_byte_length() == 0
                || family.maximum_proof_byte_length() > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        })
        || proof_resources.maximum_one_browser_wasm_resident_byte_length()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(invalid_selected_suite(
            "selected proof resource accounting exceeds an absolute bound or is incomplete",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn derive_selected_artifact_references() -> SchemaResult<Vec<ArtifactReference>> {
    let artifacts = [
        (
            ArtifactKind::EncoderAndBallotLayout,
            selected_encoder_and_ballot_layout_artifact_bytes()?,
        ),
        (
            ArtifactKind::VerifiableSecretSharingProfile,
            selected_verifiable_secret_sharing_profile_artifact_bytes()?,
        ),
        (
            ArtifactKind::LatticeCommitmentProfile,
            selected_lattice_commitment_profile_artifact_bytes()?,
        ),
        (
            ArtifactKind::ProofProfileSet,
            selected_proof_profile_artifact_bytes(
                SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
            )?,
        ),
        (
            ArtifactKind::EvaluatorProgramSet,
            selected_evaluator_program_artifact_bytes()?,
        ),
        (
            ArtifactKind::TargetDecryptionProfile,
            selected_target_decryption_profile_artifact_bytes()?,
        ),
    ];
    artifacts
        .into_iter()
        .map(|(artifact_kind, canonical_bytes)| {
            let byte_length = canonical_bytes.len();
            if byte_length == 0
                || u64::try_from(byte_length).map_err(|_| resource_count_overflow())?
                    > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
            {
                return Err(invalid_selected_suite(
                    "selected artifact exceeds the absolute stream bound",
                ));
            }
            let cumulative_work_byte_length = byte_length
                .checked_mul(64)
                .ok_or_else(resource_count_overflow)?;
            let decode_limits = CanonicalDecodeLimits {
                maximum_tuple_byte_length: byte_length,
                maximum_item_count: 100_000,
                maximum_item_byte_length: byte_length,
                maximum_nesting_depth: 32,
                maximum_cumulative_work_byte_length: cumulative_work_byte_length,
                maximum_cumulative_allocation_byte_length: cumulative_work_byte_length,
            };
            ArtifactReference::from_canonical_artifact_bytes(
                artifact_kind,
                &canonical_bytes,
                &decode_limits,
            )
        })
        .collect()
}

#[cfg(test)]
fn selected_count_limits() -> SchemaResult<SuiteCountLimits> {
    SuiteCountLimits::new(
        SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        FOUNDATION_PROFILE.participant_count,
        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        SELECTED_MAXIMUM_PUBLIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        selected_maximum_proof_objects_per_action()?,
    )
}

#[cfg(test)]
pub(crate) fn selected_maximum_proof_objects_per_action() -> SchemaResult<u32> {
    let evaluator_resource_accounting = selected_evaluator_resource_accounting()?;
    let selected_relinearization_position_count =
        evaluator_resource_accounting.relinearization_position_count();
    let selected_galois_batch_count =
        u32::try_from(selected_galois_key_share_batch_schedule().len())
            .map_err(|_| resource_count_overflow())?;
    Ok(ProofApplicationSlotCeilings::derive(
        FOUNDATION_PROFILE.participant_count,
        selected_relinearization_position_count,
        selected_galois_batch_count,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    )?
    .total_application_slot_ceiling())
}

fn invalid_selected_suite(message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(RefusalReason::UnsupportedVersionOrSuite, message)
}

fn resource_count_overflow() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "selected suite resource accounting overflowed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected_complete_evaluator_catalog_fixture() -> (
        Vec<SelectedEvaluatorEntryPosition>,
        Vec<(u16, Vec<SelectedEvaluatorEntryPosition>)>,
    ) {
        let mut expected_complete_list = selected_evaluator_relinearization_entry_positions()
            .expect("selected relinearization catalog derives");
        expected_complete_list.extend(
            selected_evaluator_galois_entry_positions().expect("selected Galois catalog derives"),
        );
        let ordered_variant_catalogs = (1..=FOUNDATION_PROFILE.option_count)
            .map(|top_count| {
                (
                    top_count,
                    selected_evaluator_entry_positions(top_count)
                        .expect("selected action catalog derives"),
                )
            })
            .collect();
        (expected_complete_list, ordered_variant_catalogs)
    }

    #[test]
    fn every_action_variant_uses_the_exact_four_entry_evaluator_catalog() {
        let (expected_complete_list, ordered_variant_catalogs) =
            selected_complete_evaluator_catalog_fixture();
        assert_eq!(expected_complete_list.len(), 4);
        assert_eq!(
            ordered_variant_catalogs.len(),
            usize::from(FOUNDATION_PROFILE.option_count)
        );
        require_complete_evaluator_variant_catalogs(
            &expected_complete_list,
            &ordered_variant_catalogs,
        )
        .expect("every action variant uses the complete catalog");

        let selected_relinearization_position_count = u32::try_from(
            selected_evaluator_relinearization_entry_positions()
                .expect("selected relinearization catalog derives")
                .len(),
        )
        .expect("selected relinearization count fits u32");
        let selected_galois_batch_count =
            u32::try_from(selected_galois_key_share_batch_schedule().len())
                .expect("selected Galois batch count fits u32");
        let application_slot_ceilings = ProofApplicationSlotCeilings::derive(
            FOUNDATION_PROFILE.participant_count,
            selected_relinearization_position_count,
            selected_galois_batch_count,
            SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        )
        .expect("selected application slots derive");
        assert_eq!(
            application_slot_ceilings.family_ceiling(
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ),
            Some(1)
        );
    }

    #[test]
    fn complete_evaluator_variant_catalog_refuses_an_omitted_entry() {
        let (expected_complete_list, mut ordered_variant_catalogs) =
            selected_complete_evaluator_catalog_fixture();
        ordered_variant_catalogs[0]
            .1
            .pop()
            .expect("complete catalog has an entry to omit");
        assert_eq!(
            require_complete_evaluator_variant_catalogs(
                &expected_complete_list,
                &ordered_variant_catalogs,
            )
            .expect_err("an omitted evaluator entry must refuse")
            .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn complete_evaluator_variant_catalog_refuses_reordered_entries() {
        let (expected_complete_list, mut ordered_variant_catalogs) =
            selected_complete_evaluator_catalog_fixture();
        ordered_variant_catalogs[1].1.swap(0, 1);
        assert_eq!(
            require_complete_evaluator_variant_catalogs(
                &expected_complete_list,
                &ordered_variant_catalogs,
            )
            .expect_err("reordered evaluator entries must refuse")
            .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn complete_evaluator_variant_catalog_refuses_a_substituted_entry() {
        let (expected_complete_list, mut ordered_variant_catalogs) =
            selected_complete_evaluator_catalog_fixture();
        let replacement = ordered_variant_catalogs[2].1[0];
        let final_entry_index = ordered_variant_catalogs[2].1.len() - 1;
        ordered_variant_catalogs[2].1[final_entry_index] = replacement;
        assert_eq!(
            require_complete_evaluator_variant_catalogs(
                &expected_complete_list,
                &ordered_variant_catalogs,
            )
            .expect_err("a substituted evaluator entry must refuse")
            .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn selected_evaluator_accounting_reports_exact_wire_and_resident_measurements() {
        let accounting = selected_evaluator_resource_accounting().expect("resource accounting");
        let candidate = EvaluatorCandidateInput::implemented().expect("candidate derives");
        let expected_source_component_count = u64::try_from(
            candidate
                .relinearization_levels
                .len()
                .checked_mul(3)
                .and_then(|count| count.checked_add(candidate.galois_key_schedule.len()))
                .expect("selected component count fits usize"),
        )
        .expect("selected component count fits u64");
        let expected_final_component_count = u64::try_from(
            candidate
                .relinearization_levels
                .len()
                .checked_mul(2)
                .and_then(|count| count.checked_add(candidate.galois_key_schedule.len()))
                .expect("selected component count fits usize"),
        )
        .expect("selected component count fits u64");
        assert_eq!(
            accounting.relinearization_position_count(),
            u32::try_from(candidate.relinearization_levels.len())
                .expect("selected relinearization count fits u32")
        );
        assert_eq!(
            accounting.galois_position_count(),
            u32::try_from(candidate.galois_key_schedule.len())
                .expect("selected Galois count fits u32")
        );
        assert_eq!(
            accounting.source_component_count_per_participant(),
            expected_source_component_count
        );
        assert_eq!(
            accounting.final_component_count(),
            expected_final_component_count
        );
        assert_eq!(
            accounting.source_public_polynomial_context_hash_count_per_participant(),
            u64::from(accounting.relinearization_position_count())
                + u64::from(accounting.galois_position_count())
        );
        assert_eq!(
            accounting.source_public_polynomial_context_hash_resident_byte_length_per_participant(),
            accounting.source_public_polynomial_context_hash_count_per_participant()
                * u64::try_from(Hash512::BYTE_LENGTH).expect("hash width fits u64")
        );
        assert!(accounting.levels().iter().all(|level| {
            level.component_wire_byte_length() < level.component_resident_byte_length()
                && level.source_wire_byte_length_per_participant()
                    == level.component_wire_byte_length()
                        * level.source_component_count_per_participant()
                && level.source_resident_byte_length_per_participant()
                    == level.component_resident_byte_length()
                        * level.source_component_count_per_participant()
                && level.final_wire_byte_length()
                    == level.component_wire_byte_length() * level.final_component_count()
                && level.final_resident_byte_length()
                    == level.component_resident_byte_length() * level.final_component_count()
        }));
        assert_eq!(
            accounting.source_wire_byte_length_per_participant(),
            accounting
                .levels()
                .iter()
                .map(|level| level.source_wire_byte_length_per_participant())
                .sum::<u64>()
        );
        assert_eq!(
            accounting.source_resident_byte_length_per_participant(),
            accounting
                .levels()
                .iter()
                .map(|level| level.source_resident_byte_length_per_participant())
                .sum::<u64>()
                + accounting
                    .source_public_polynomial_context_hash_resident_byte_length_per_participant()
        );
        assert_eq!(
            accounting.final_evaluator_key_store_wire_byte_length(),
            accounting
                .levels()
                .iter()
                .map(|level| level.final_wire_byte_length())
                .sum::<u64>()
        );
        assert_eq!(
            accounting.ceremony_setup_wire_byte_length(),
            accounting.source_wire_byte_length_per_participant()
                * u64::from(FOUNDATION_PROFILE.participant_count)
                + accounting.final_evaluator_key_store_wire_byte_length()
        );
        assert_eq!(
            accounting.ceremony_source_and_final_resident_volume_byte_length(),
            accounting.source_resident_byte_length_per_participant()
                * u64::from(FOUNDATION_PROFILE.participant_count)
                + accounting.final_evaluator_key_store_resident_byte_length()
        );
        const CEREMONY_CORPUS_PLANNING_TARGET_BYTE_LENGTH: u64 = 2_147_483_648;
        let planning_target_overage = accounting
            .ceremony_setup_wire_byte_length()
            .saturating_sub(CEREMONY_CORPUS_PLANNING_TARGET_BYTE_LENGTH);
        assert!(
            accounting.ceremony_setup_wire_byte_length()
                <= crate::foundation::MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        );
        eprintln!(
            "selected_evaluator_resources levels={:?} relinearization_positions={} galois_positions={} source_components_per_participant={} source_public_polynomial_context_hashes_per_participant={} source_public_polynomial_context_hash_resident_bytes_per_participant={} final_components={} source_wire_per_participant={} source_resident_per_participant={} final_wire={} final_resident={} ceremony_wire={} ceremony_source_and_final_resident_volume={} corpus_planning_target={} corpus_planning_overage={}",
            accounting.levels(),
            accounting.relinearization_position_count(),
            accounting.galois_position_count(),
            accounting.source_component_count_per_participant(),
            accounting.source_public_polynomial_context_hash_count_per_participant(),
            accounting.source_public_polynomial_context_hash_resident_byte_length_per_participant(),
            accounting.final_component_count(),
            accounting.source_wire_byte_length_per_participant(),
            accounting.source_resident_byte_length_per_participant(),
            accounting.final_evaluator_key_store_wire_byte_length(),
            accounting.final_evaluator_key_store_resident_byte_length(),
            accounting.ceremony_setup_wire_byte_length(),
            accounting.ceremony_source_and_final_resident_volume_byte_length(),
            CEREMONY_CORPUS_PLANNING_TARGET_BYTE_LENGTH,
            planning_target_overage,
        );
    }

    #[test]
    fn suite_selection_refuses_before_a_canonical_record_is_frozen() {
        let structural_candidate = SuiteRecord::new(
            selected_count_limits().expect("selected count limits derive"),
            structural_artifact_references_for_tests(),
        )
        .expect("structural candidate is canonical");
        assert_eq!(
            require_selected_suite_record(&structural_candidate)
                .expect_err("an unavailable suite cannot mint authority")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
        assert_eq!(
            select_suite_record(&structural_candidate)
                .err()
                .expect("an unavailable suite cannot mint authority")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    #[ignore = "full candidate selection gate; run only after the evaluator and proof representation settle"]
    fn candidate_suite_gate_derives_one_complete_canonical_record() {
        let candidate = derive_selected_suite_candidate_record()
            .expect("the candidate must satisfy every static selection gate");
        assert_eq!(
            candidate.artifacts(),
            derive_selected_artifact_references()
                .expect("candidate artifacts derive")
                .as_slice()
        );
        assert!(candidate.suite_id().is_ok());
        assert_eq!(
            select_suite_record(&candidate)
                .err()
                .expect("a candidate cannot become runtime authority before it is frozen")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }
}
