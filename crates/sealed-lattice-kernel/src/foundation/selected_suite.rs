//! Exact allowlist checks for the selected fixed suite.

use std::collections::BTreeMap;

use crate::bgv::{
    key_switch_topology::{KEY_SWITCH_DATA_PRIMES_PER_BLOCK, KEY_SWITCH_SPECIAL_PRIMES},
    parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    proof_suite::{
        MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, selected_galois_key_share_batch_schedule,
    },
};

use crate::bgv::{
    key_switch_topology::KeySwitchDecompositionTopology,
    proof_suite::{
        SelectedEvaluatorEntryKind, selected_evaluator_galois_entry_positions,
        selected_evaluator_relinearization_entry_positions,
    },
};

use super::schemas::SchemaResult;
use super::{
    ArtifactKind, ArtifactReference, FOUNDATION_PROFILE, FoundationSchemaError, Hash512,
    ProofApplicationSlotCeilings, RefusalReason, SuiteCountLimits, SuiteRecord,
};

#[cfg(test)]
use super::{
    CanonicalDecodeLimits, selected_encoder_and_ballot_layout_artifact_bytes,
    selected_evaluator_program_artifact_bytes, selected_lattice_commitment_profile_artifact_bytes,
    selected_proof_profile_artifact_bytes, selected_target_decryption_profile_artifact_bytes,
    selected_verifiable_secret_sharing_profile_artifact_bytes,
};

pub(crate) const SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT: u16 = 3;
pub(crate) const SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 64;
pub(crate) const SELECTED_MAXIMUM_PUBLIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 128;
pub(crate) const SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION: u32 = 20;

const SELECTED_CANDIDATE_SUITE_IDENTIFIER: Hash512 = Hash512::from_bytes([
    0xaf, 0xda, 0x52, 0x0b, 0xe6, 0xd3, 0x0c, 0x78, 0x60, 0x7a, 0xc5, 0x6a, 0x5e, 0xf5, 0x10, 0x15,
    0x0f, 0x89, 0x5a, 0x97, 0x34, 0x25, 0xa5, 0x10, 0x8e, 0xd1, 0xee, 0x10, 0x80, 0x00, 0xd2, 0x3c,
    0x78, 0xbf, 0xe8, 0xbb, 0x65, 0xb6, 0x3f, 0xe7, 0x69, 0x61, 0x9a, 0x43, 0xf2, 0x60, 0x9f, 0x1c,
    0x2a, 0xf9, 0xf6, 0x5f, 0x22, 0x5f, 0x99, 0x5e, 0x5b, 0x8e, 0x31, 0x1b, 0x7e, 0xaf, 0xbb, 0xaf,
]);

const SELECTED_ARTIFACT_REFERENCE_INPUTS: [(ArtifactKind, u64, [u8; 64]); 6] = [
    (
        ArtifactKind::EncoderAndBallotLayout,
        38,
        [
            0x23, 0x43, 0xbe, 0xdf, 0x62, 0x8e, 0x86, 0x60, 0xa8, 0x77, 0xb4, 0xd5, 0x41, 0xbf,
            0x1d, 0x79, 0x61, 0x71, 0x36, 0xdc, 0x27, 0x97, 0xd0, 0xd4, 0xf7, 0x9b, 0xad, 0x1b,
            0x06, 0xa8, 0x5a, 0x11, 0x01, 0x92, 0x29, 0xde, 0xac, 0x22, 0xa0, 0xda, 0xf9, 0x5b,
            0xed, 0x71, 0x88, 0xc4, 0x0b, 0xc5, 0x7b, 0xa9, 0xbd, 0x47, 0x58, 0x8e, 0x97, 0x8c,
            0x45, 0x78, 0x95, 0xff, 0x3d, 0x55, 0x6b, 0x73,
        ],
    ),
    (
        ArtifactKind::VerifiableSecretSharingProfile,
        74,
        [
            0x49, 0xd3, 0x33, 0x6d, 0x22, 0x7e, 0x29, 0x7d, 0x65, 0xe3, 0xde, 0x75, 0x8e, 0x1e,
            0xdd, 0xd1, 0x95, 0x6d, 0x18, 0xaa, 0xbc, 0xd0, 0x0e, 0x7e, 0x4f, 0x7d, 0x4f, 0x73,
            0x99, 0x42, 0x72, 0x7e, 0x93, 0x85, 0xb5, 0xba, 0x50, 0x5b, 0xbd, 0xfa, 0x1e, 0x41,
            0x35, 0xf8, 0x48, 0x01, 0x1d, 0x28, 0x03, 0x47, 0x03, 0x1f, 0xe9, 0xc6, 0x25, 0x45,
            0xde, 0x84, 0x22, 0xe6, 0x40, 0x6c, 0x3c, 0xea,
        ],
    ),
    (
        ArtifactKind::LatticeCommitmentProfile,
        34,
        [
            0xfe, 0x40, 0xcd, 0x4a, 0x47, 0x87, 0x7c, 0xcd, 0x0c, 0x93, 0x3a, 0x1e, 0x05, 0x12,
            0x8a, 0x8a, 0x07, 0x40, 0xab, 0x36, 0x87, 0xb7, 0xb9, 0xa6, 0x0f, 0x77, 0xce, 0x46,
            0x3a, 0xc4, 0xb7, 0x11, 0x2e, 0xd7, 0x1a, 0xec, 0xd5, 0x82, 0x5b, 0xcb, 0xae, 0x5f,
            0x46, 0x92, 0x5a, 0xd8, 0xb6, 0xa4, 0x55, 0x86, 0x53, 0xa0, 0x1e, 0xdc, 0x9a, 0x31,
            0xa8, 0xbb, 0x2d, 0x9e, 0x36, 0x2e, 0x44, 0x7a,
        ],
    ),
    (
        ArtifactKind::ProofProfileSet,
        957_460,
        [
            0xb6, 0xbe, 0xd3, 0x13, 0x39, 0xf9, 0xbb, 0x45, 0xa1, 0xd7, 0x96, 0x19, 0x82, 0xb0,
            0x7a, 0x46, 0x92, 0x84, 0x3e, 0x0c, 0x3d, 0x7c, 0x18, 0xe3, 0x89, 0x1b, 0xa5, 0xbc,
            0x23, 0xd9, 0x48, 0xc2, 0x7f, 0xa2, 0x3b, 0x3b, 0x6f, 0x9a, 0x12, 0x6c, 0xe9, 0x9f,
            0x72, 0xd8, 0xde, 0xd9, 0x1f, 0xdb, 0xa4, 0x1c, 0x38, 0x50, 0x20, 0x9f, 0x0e, 0xbf,
            0x8d, 0xa1, 0x0b, 0xae, 0x83, 0xca, 0x63, 0x76,
        ],
    ),
    (
        ArtifactKind::EvaluatorProgramSet,
        20_270_968,
        [
            0xfd, 0x9c, 0x95, 0x8a, 0x65, 0xdc, 0xf9, 0x36, 0x40, 0xa1, 0x8e, 0x7b, 0xcc, 0x1c,
            0x5a, 0x9a, 0x79, 0x2e, 0xd6, 0xce, 0x8d, 0x36, 0x23, 0xa7, 0xb7, 0x07, 0xc4, 0x61,
            0x62, 0x15, 0x17, 0xd1, 0x84, 0xda, 0x4b, 0x5a, 0x75, 0x08, 0x49, 0x93, 0x6a, 0xe0,
            0xd3, 0xba, 0x25, 0x5b, 0xea, 0x4d, 0x0b, 0x8a, 0x6b, 0xff, 0xa5, 0x1a, 0x96, 0x3f,
            0xa6, 0xbf, 0x41, 0x65, 0x5d, 0xd9, 0x9b, 0xb0,
        ],
    ),
    (
        ArtifactKind::TargetDecryptionProfile,
        36,
        [
            0xf3, 0xc8, 0x19, 0x92, 0x71, 0xb3, 0x78, 0xa0, 0xfd, 0xeb, 0x07, 0xf8, 0x2c, 0x69,
            0xf5, 0xe2, 0xff, 0x15, 0x1f, 0x31, 0x5a, 0x24, 0x72, 0x17, 0x4e, 0x55, 0x75, 0xe9,
            0x6e, 0xb7, 0xf0, 0xa7, 0x6d, 0x27, 0xeb, 0xa8, 0x04, 0xbf, 0x89, 0x7d, 0xb9, 0xfe,
            0xad, 0x9e, 0x33, 0x3a, 0x8c, 0x6c, 0xc6, 0xa6, 0x2d, 0x7d, 0x90, 0xb8, 0x5f, 0x7c,
            0x14, 0xe3, 0x7a, 0x7f, 0x98, 0x48, 0x90, 0xe0,
        ],
    ),
];

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
pub(crate) const fn selected_suite_capability_for_tests() -> SelectedSuiteCapability {
    SelectedSuiteCapability {
        suite_identifier: SELECTED_CANDIDATE_SUITE_IDENTIFIER.into_bytes(),
    }
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
    let expected_count_limits = selected_count_limits()?;
    if record.roster_size() != FOUNDATION_PROFILE.participant_count
        || record.byzantine_bound() != FOUNDATION_PROFILE.active_fault_bound
        || record.reconstruction_threshold() != FOUNDATION_PROFILE.reconstruction_threshold
        || record.finality_quorum() != FOUNDATION_PROFILE.finality_quorum
        || record.count_limits() != expected_count_limits
        || record.artifacts() != selected_artifact_references()?.as_slice()
        || record.suite_id()? != SELECTED_CANDIDATE_SUITE_IDENTIFIER
    {
        return Err(invalid_selected_suite(
            "suite record is not the exact selected roster, count, and artifact profile",
        ));
    }
    Ok(())
}

pub(crate) fn selected_artifact_references() -> SchemaResult<Vec<ArtifactReference>> {
    SELECTED_ARTIFACT_REFERENCE_INPUTS
        .into_iter()
        .map(|(artifact_kind, byte_length, artifact_hash)| {
            ArtifactReference::new(
                artifact_kind,
                byte_length,
                Hash512::from_bytes(artifact_hash),
            )
        })
        .collect()
}

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
    use crate::foundation::{CanonicalItem, CanonicalTuple};

    fn selected_candidate_suite_record() -> SuiteRecord {
        SuiteRecord::new(
            selected_count_limits().expect("selected count limits derive"),
            selected_artifact_references().expect("selected artifact references derive"),
        )
        .expect("selected structural candidate is canonical")
    }

    fn structural_artifact_references() -> Vec<ArtifactReference> {
        ArtifactKind::ALL
            .into_iter()
            .map(|artifact_kind| {
                let bytes = CanonicalTuple::new(
                    artifact_kind.artifact_schema_identifier(),
                    artifact_kind.artifact_schema_version(),
                    vec![CanonicalItem::unsigned16(artifact_kind.canonical_code())],
                )
                .encode()
                .expect("test artifact encodes");
                ArtifactReference::from_canonical_artifact_bytes(
                    artifact_kind,
                    &bytes,
                    &CanonicalDecodeLimits::default(),
                )
                .expect("test artifact reference derives")
            })
            .collect()
    }

    #[test]
    fn selected_evaluator_accounting_reports_exact_wire_and_resident_measurements() {
        let accounting = selected_evaluator_resource_accounting().expect("resource accounting");
        assert_eq!(accounting.levels().len(), 2);
        let relinearization_level = accounting
            .levels()
            .iter()
            .find(|level| level.catalog_level() == 23)
            .expect("the selected level-23 relinearization material is accounted");
        let galois_level = accounting
            .levels()
            .iter()
            .find(|level| level.catalog_level() == 25)
            .expect("the selected level-25 Galois material is accounted");
        assert_eq!(
            relinearization_level.source_component_count_per_participant(),
            3
        );
        assert_eq!(relinearization_level.final_component_count(), 2);
        assert_eq!(galois_level.source_component_count_per_participant(), 4);
        assert_eq!(galois_level.final_component_count(), 4);
        assert_eq!(accounting.source_component_count_per_participant(), 7);
        assert_eq!(accounting.final_component_count(), 6);
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
    fn selected_artifact_reference_generator_matches_the_fixed_catalog_and_suite_identifier() {
        let generated_artifact_bytes = vec![
            (
                ArtifactKind::EncoderAndBallotLayout,
                selected_encoder_and_ballot_layout_artifact_bytes()
                    .expect("encoder and ballot artifact derives"),
            ),
            (
                ArtifactKind::VerifiableSecretSharingProfile,
                selected_verifiable_secret_sharing_profile_artifact_bytes()
                    .expect("VSS artifact derives"),
            ),
            (
                ArtifactKind::LatticeCommitmentProfile,
                selected_lattice_commitment_profile_artifact_bytes()
                    .expect("commitment artifact derives"),
            ),
            (
                ArtifactKind::ProofProfileSet,
                selected_proof_profile_artifact_bytes(
                    SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
                )
                .expect("proof-profile artifact derives"),
            ),
            (
                ArtifactKind::EvaluatorProgramSet,
                selected_evaluator_program_artifact_bytes()
                    .expect("evaluator-program artifact derives"),
            ),
            (
                ArtifactKind::TargetDecryptionProfile,
                selected_target_decryption_profile_artifact_bytes()
                    .expect("target-decryption artifact derives"),
            ),
        ];
        let artifacts = generated_artifact_bytes
            .into_iter()
            .map(|(artifact_kind, bytes)| {
                let generated_artifact_work_limit = bytes
                    .len()
                    .checked_mul(64)
                    .expect("generated artifact work limit fits usize");
                let decode_limits = CanonicalDecodeLimits {
                    maximum_tuple_byte_length: bytes.len(),
                    maximum_item_count: 100_000,
                    maximum_item_byte_length: bytes.len(),
                    maximum_nesting_depth: 32,
                    maximum_cumulative_work_byte_length: generated_artifact_work_limit,
                    maximum_cumulative_allocation_byte_length: generated_artifact_work_limit,
                };
                ArtifactReference::from_canonical_artifact_bytes(
                    artifact_kind,
                    &bytes,
                    &decode_limits,
                )
                .expect("generated artifact reference derives")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            artifacts,
            selected_artifact_references().expect("fixed artifact references derive")
        );
        let candidate = SuiteRecord::new(
            selected_count_limits().expect("selected count limits derive"),
            artifacts,
        )
        .expect("candidate suite record");
        assert_eq!(
            candidate.suite_id().expect("suite identifier derives"),
            SELECTED_CANDIDATE_SUITE_IDENTIFIER
        );
        assert_eq!(
            candidate.encode().expect("candidate suite encodes").len(),
            1_590
        );
    }

    #[test]
    fn exact_selected_suite_mints_authority_independently_of_phone_measurements() {
        let candidate = selected_candidate_suite_record();
        require_selected_suite_record(&candidate).expect("selected suite is admitted");
        let capability = select_suite_record(&candidate).expect("selected suite mints authority");
        assert_eq!(
            capability.suite_identifier(),
            candidate
                .suite_id()
                .expect("selected suite identifier derives")
                .into_bytes()
        );
    }

    #[test]
    fn nonselected_roster_candidate_cannot_cross_the_authority_boundary() {
        let mut tuple = CanonicalTuple::decode(
            &selected_candidate_suite_record()
                .encode()
                .expect("selected candidate encodes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("selected candidate tuple decodes");
        let roster_parameters = crate::foundation::derive_foundation_roster_parameters(3)
            .expect("three participants are configurable");
        tuple.items[1] = CanonicalItem::unsigned16(roster_parameters.participant_count);
        tuple.items[2] = CanonicalItem::unsigned16(roster_parameters.active_fault_bound);
        tuple.items[3] = CanonicalItem::unsigned16(roster_parameters.reconstruction_threshold);
        tuple.items[4] = CanonicalItem::unsigned16(roster_parameters.finality_quorum);
        tuple.items[15] = CanonicalItem::unsigned16(roster_parameters.participant_count);
        tuple.items[18] = CanonicalItem::unsigned32(6);
        let candidate = SuiteRecord::decode(
            &tuple.encode().expect("candidate suite encodes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("nonselected candidate remains structural");

        assert_eq!(
            require_selected_suite_record(&candidate)
                .expect_err("nonselected roster cannot mint selected-suite authority")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
        let selection_error = match select_suite_record(&candidate) {
            Ok(_) => panic!("nonselected roster cannot be selected"),
            Err(error) => error,
        };
        assert_eq!(
            selection_error.refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn proof_profile_reference_length_hash_and_order_are_exact() {
        let fixed_artifacts = selected_artifact_references().expect("fixed references derive");
        let proof_profile_index = ArtifactKind::ALL
            .iter()
            .position(|kind| *kind == ArtifactKind::ProofProfileSet)
            .expect("proof profile is in the complete artifact inventory");
        let proof_profile = fixed_artifacts[proof_profile_index];

        let mut wrong_length_artifacts = fixed_artifacts.clone();
        wrong_length_artifacts[proof_profile_index] = ArtifactReference::new(
            ArtifactKind::ProofProfileSet,
            proof_profile.byte_length() + 1,
            proof_profile.artifact_hash(),
        )
        .expect("positive mutated length is structural");
        let wrong_length = SuiteRecord::new(
            selected_count_limits().expect("selected count limits derive"),
            wrong_length_artifacts,
        )
        .expect("mutated reference remains a structural suite");
        assert_eq!(
            require_selected_suite_record(&wrong_length)
                .expect_err("proof-profile length drift must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );

        let mut wrong_hash_bytes = proof_profile.artifact_hash().into_bytes();
        wrong_hash_bytes[0] ^= 1;
        let mut wrong_hash_artifacts = fixed_artifacts.clone();
        wrong_hash_artifacts[proof_profile_index] = ArtifactReference::new(
            ArtifactKind::ProofProfileSet,
            proof_profile.byte_length(),
            Hash512::from_bytes(wrong_hash_bytes),
        )
        .expect("mutated hash reference is structural");
        let wrong_hash = SuiteRecord::new(
            selected_count_limits().expect("selected count limits derive"),
            wrong_hash_artifacts,
        )
        .expect("mutated reference remains a structural suite");
        assert_eq!(
            require_selected_suite_record(&wrong_hash)
                .expect_err("proof-profile hash drift must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );

        let mut reordered_artifacts = fixed_artifacts;
        reordered_artifacts.swap(proof_profile_index - 1, proof_profile_index);
        assert_eq!(
            SuiteRecord::new(
                selected_count_limits().expect("selected count limits derive"),
                reordered_artifacts,
            )
            .expect_err("artifact order drift must refuse")
            .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn invalid_selected_profile_prevents_authority_minting() {
        let counts = selected_count_limits().expect("selected counts");
        let suite =
            SuiteRecord::new(counts, structural_artifact_references()).expect("structural suite");
        assert_eq!(
            require_selected_suite_record(&suite)
                .expect_err("an invalid proof profile cannot cross the operative boundary")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
        assert_eq!(
            select_suite_record(&suite)
                .err()
                .expect("an invalid proof profile cannot mint authority")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }
}
