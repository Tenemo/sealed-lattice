//! Exact allowlist checks for the selected fixed suite.

use crate::bgv::{
    key_switch_topology::{
        KEY_SWITCH_DATA_PRIMES_PER_BLOCK, KEY_SWITCH_SPECIAL_PRIMES, KeySwitchDecompositionTopology,
    },
    parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    proof_suite::{
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH, SelectedEvaluatorEntryKind,
        selected_evaluator_entry_positions,
    },
};

#[cfg(test)]
use crate::bgv::evaluator::program::selected_evaluator_program_set;

use super::schemas::SchemaResult;
use super::{
    ArtifactKind, ArtifactReference, FOUNDATION_PROFILE, FoundationSchemaError, Hash512,
    RefusalReason, SuiteByteLimits, SuiteCountLimits, SuiteRecord,
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
pub(crate) const SELECTED_MAXIMUM_PROOF_OBJECTS_PER_ACTION: u32 = 269;
pub(crate) const MOBILE_CEREMONY_UPLOAD_BYTE_CEILING: u64 = 2_147_483_648;
pub(crate) const SELECTED_MAXIMUM_EXACT_FAMILY_PROOF_BYTE_LENGTH: u64 = 149_419_382;
pub(crate) const SELECTED_EXACT_FAMILY_PROOF_BYTES_PER_ACTION: u64 = 9_150_628_410;

const SELECTED_CANDIDATE_SUITE_IDENTIFIER: Hash512 = Hash512::from_bytes([
    0x02, 0x23, 0xd2, 0x39, 0xfe, 0x4c, 0xf0, 0xb6, 0xa2, 0xc0, 0x9a, 0xc6, 0xa7, 0x6a, 0x6b, 0x92,
    0x3a, 0x37, 0xc5, 0xf9, 0x8e, 0x74, 0x05, 0x05, 0x89, 0xf2, 0x55, 0x9e, 0xef, 0x7a, 0x90, 0xf2,
    0x41, 0x77, 0x0f, 0xa7, 0xda, 0x54, 0x5d, 0x5b, 0x83, 0x4a, 0x9b, 0x3e, 0x73, 0x66, 0xf1, 0x75,
    0x11, 0xaa, 0x02, 0x8c, 0x66, 0xf8, 0x91, 0x48, 0xeb, 0x7d, 0x18, 0x2c, 0xa9, 0x1d, 0x2d, 0xd0,
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

/// Reserved non-serializable authority shape for a future admissible fixed
/// suite. The current structural candidate cannot construct this value because
/// its exact-family proof accounting exceeds the fixed browser ceilings.
/// Callers cannot supply an identifier or artifact reference as a substitute.
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
}

pub(crate) fn select_suite_record(record: &SuiteRecord) -> SchemaResult<SelectedSuiteCapability> {
    require_selected_suite_record(record)?;
    Ok(SelectedSuiteCapability {
        suite_identifier: record.suite_id()?.into_bytes(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorResourceAccounting {
    component_material_wire_byte_length: u64,
    component_material_resident_byte_length: u64,
    source_component_count_per_participant: u64,
    aggregate_component_count: u64,
    final_evaluator_key_store_wire_byte_length: u64,
    final_evaluator_key_store_byte_length: u64,
    setup_upload_lower_bound_per_participant: u64,
    ceremony_setup_upload_lower_bound: u64,
    complete_runtime_material_per_participant: u64,
    complete_runtime_material_for_ceremony: u64,
}

impl SelectedEvaluatorResourceAccounting {
    #[cfg(test)]
    pub(crate) const fn component_material_wire_byte_length(self) -> u64 {
        self.component_material_wire_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn component_material_resident_byte_length(self) -> u64 {
        self.component_material_resident_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn source_component_count_per_participant(self) -> u64 {
        self.source_component_count_per_participant
    }

    #[cfg(test)]
    pub(crate) const fn aggregate_component_count(self) -> u64 {
        self.aggregate_component_count
    }

    #[cfg(test)]
    pub(crate) const fn final_evaluator_key_store_wire_byte_length(self) -> u64 {
        self.final_evaluator_key_store_wire_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn final_evaluator_key_store_byte_length(self) -> u64 {
        self.final_evaluator_key_store_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn setup_upload_lower_bound_per_participant(self) -> u64 {
        self.setup_upload_lower_bound_per_participant
    }

    #[cfg(test)]
    pub(crate) const fn ceremony_setup_upload_lower_bound(self) -> u64 {
        self.ceremony_setup_upload_lower_bound
    }

    #[cfg(test)]
    pub(crate) const fn complete_runtime_material_per_participant(self) -> u64 {
        self.complete_runtime_material_per_participant
    }

    #[cfg(test)]
    pub(crate) const fn complete_runtime_material_for_ceremony(self) -> u64 {
        self.complete_runtime_material_for_ceremony
    }

    fn require_mobile_ceremony_upload_limit(self) -> SchemaResult<()> {
        if self.ceremony_setup_upload_lower_bound > MOBILE_CEREMONY_UPLOAD_BYTE_CEILING {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "selected evaluator setup material exceeds the fixed ceremony upload ceiling",
            ));
        }
        Ok(())
    }
}

pub(crate) fn selected_evaluator_resource_accounting()
-> SchemaResult<SelectedEvaluatorResourceAccounting> {
    let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .map_err(|_| invalid_selected_suite("selected evaluator key positions are invalid"))?;
    let decomposition_topology = KeySwitchDecompositionTopology::for_level(
        DATA_PRIMES
            .len()
            .checked_sub(1)
            .ok_or_else(resource_count_overflow)?,
    )
    .map_err(|_| invalid_selected_suite("selected key-switch topology is invalid"))?;
    let component_material_wire_byte_length = decomposition_topology
        .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
        .map_err(|_| invalid_selected_suite("selected component wire length is invalid"))?;
    let component_material_resident_byte_length = decomposition_topology
        .resident_component_byte_length(POLYNOMIAL_DEGREE)
        .map_err(|_| invalid_selected_suite("selected component resident length is invalid"))?;
    let mut source_component_count_per_participant = 0_u64;
    let mut aggregate_component_count = 0_u64;

    for position in positions {
        let catalog_level = match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level }
            | SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
        };
        let decomposition_digit_count = catalog_level
            .checked_add(1)
            .ok_or_else(resource_count_overflow)?;
        if decomposition_digit_count != DATA_PRIMES.len() {
            return Err(invalid_selected_suite(
                "selected evaluator entry does not use the complete data-prime basis",
            ));
        }
        match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { .. } => {
                // Two round-one source components and one round-two source
                // component produce the two final relinearization components.
                source_component_count_per_participant = source_component_count_per_participant
                    .checked_add(3)
                    .ok_or_else(resource_count_overflow)?;
                aggregate_component_count = aggregate_component_count
                    .checked_add(2)
                    .ok_or_else(resource_count_overflow)?;
            }
            SelectedEvaluatorEntryKind::Galois { .. } => {
                source_component_count_per_participant = source_component_count_per_participant
                    .checked_add(1)
                    .ok_or_else(resource_count_overflow)?;
                aggregate_component_count = aggregate_component_count
                    .checked_add(1)
                    .ok_or_else(resource_count_overflow)?;
            }
        }
    }

    let final_evaluator_key_store_wire_byte_length = component_material_wire_byte_length
        .checked_mul(aggregate_component_count)
        .ok_or_else(resource_count_overflow)?;
    let final_evaluator_key_store_byte_length = component_material_resident_byte_length
        .checked_mul(aggregate_component_count)
        .ok_or_else(resource_count_overflow)?;
    let setup_upload_lower_bound_per_participant = component_material_wire_byte_length
        .checked_mul(source_component_count_per_participant)
        .ok_or_else(resource_count_overflow)?;
    let source_upload_for_ceremony = setup_upload_lower_bound_per_participant
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(resource_count_overflow)?;
    let ceremony_setup_upload_lower_bound = source_upload_for_ceremony
        .checked_add(final_evaluator_key_store_wire_byte_length)
        .ok_or_else(resource_count_overflow)?;
    let complete_runtime_material_per_participant = component_material_resident_byte_length
        .checked_mul(source_component_count_per_participant)
        .ok_or_else(resource_count_overflow)?;
    let source_runtime_material_for_ceremony = complete_runtime_material_per_participant
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(resource_count_overflow)?;
    let complete_runtime_material_for_ceremony = source_runtime_material_for_ceremony
        .checked_add(final_evaluator_key_store_byte_length)
        .ok_or_else(resource_count_overflow)?;
    Ok(SelectedEvaluatorResourceAccounting {
        component_material_wire_byte_length,
        component_material_resident_byte_length,
        source_component_count_per_participant,
        aggregate_component_count,
        final_evaluator_key_store_wire_byte_length,
        final_evaluator_key_store_byte_length,
        setup_upload_lower_bound_per_participant,
        ceremony_setup_upload_lower_bound,
        complete_runtime_material_per_participant,
        complete_runtime_material_for_ceremony,
    })
}

pub(crate) fn require_selected_suite_record(record: &SuiteRecord) -> SchemaResult<()> {
    let expected_count_limits = selected_count_limits()?;
    let expected_byte_limits = selected_byte_limits()?;
    if record.roster_size() != FOUNDATION_PROFILE.participant_count
        || record.byzantine_bound() != FOUNDATION_PROFILE.active_fault_bound
        || record.reconstruction_threshold() != FOUNDATION_PROFILE.reconstruction_threshold
        || record.finality_quorum() != FOUNDATION_PROFILE.finality_quorum
        || record.count_limits() != expected_count_limits
        || record.byte_limits() != expected_byte_limits
        || record.artifacts() != selected_artifact_references()?.as_slice()
        || record.suite_id()? != SELECTED_CANDIDATE_SUITE_IDENTIFIER
    {
        return Err(invalid_selected_suite(
            "suite record is not the exact selected roster, count, byte, and artifact profile",
        ));
    }

    selected_evaluator_resource_accounting()?.require_mobile_ceremony_upload_limit()?;

    // The structural candidate is reproducible, but its exact-family plans do
    // not fit the fixed proof-object or per-action browser ceilings. Keep the
    // authority boundary fail-closed until those relations are redesigned.
    if SELECTED_MAXIMUM_EXACT_FAMILY_PROOF_BYTE_LENGTH > MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64
        || SELECTED_EXACT_FAMILY_PROOF_BYTES_PER_ACTION
            > expected_byte_limits.maximum_proof_bytes_per_action()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "selected exact-family proof accounting exceeds the fixed browser proof ceilings",
        ));
    }
    Err(FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "selected exact-family proof relations are not admitted by the fixed browser profile",
    ))
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
        SELECTED_MAXIMUM_PROOF_OBJECTS_PER_ACTION,
    )
}

fn selected_byte_limits() -> SchemaResult<SuiteByteLimits> {
    SuiteByteLimits::new(
        44_040_192,
        293_601_280,
        1_500_000_000,
        1_500_000_000,
        2_000_000_000,
        1_600_000_000,
        MOBILE_CEREMONY_UPLOAD_BYTE_CEILING,
    )
}

#[cfg(test)]
fn selected_maximum_proof_objects_per_action() -> SchemaResult<u32> {
    let program = selected_evaluator_program_set()
        .map_err(|_| invalid_selected_suite("selected evaluator program is invalid"))?;
    let key_positions = program
        .key_positions()
        .map_err(|_| invalid_selected_suite("selected evaluator key positions are invalid"))?;
    let participant_count = u32::from(FOUNDATION_PROFILE.participant_count);
    key_positions
        .streams()
        .iter()
        .map(|stream| {
            let relinearization_count =
                u32::try_from(stream.relinearization_catalog_levels().len())
                    .map_err(|_| resource_count_overflow())?;
            let galois_count = u32::try_from(stream.galois_catalog_positions().len())
                .map_err(|_| resource_count_overflow())?;
            participant_count
                .checked_mul(4)
                .and_then(|count| {
                    relinearization_count
                        .checked_add(galois_count)
                        .and_then(|evaluator_entry_count| evaluator_entry_count.checked_add(1))
                        .and_then(|aggregate_count| count.checked_add(aggregate_count))
                })
                .and_then(|count| {
                    participant_count
                        .checked_mul(2)
                        .and_then(|trustee_count| trustee_count.checked_add(1))
                        .and_then(|per_position| per_position.checked_mul(relinearization_count))
                        .and_then(|position_count| count.checked_add(position_count))
                })
                .and_then(|count| {
                    participant_count
                        .checked_mul(galois_count)
                        .and_then(|galois_proofs| count.checked_add(galois_proofs))
                })
                .and_then(|count| count.checked_add(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION))
                .and_then(|count| count.checked_add(participant_count))
                .ok_or_else(resource_count_overflow)
        })
        .collect::<SchemaResult<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or_else(|| invalid_selected_suite("selected evaluator program has no streams"))
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
            selected_byte_limits().expect("selected byte limits derive"),
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
    fn selected_evaluator_accounting_fits_the_mobile_ceremony_upload_ceiling() {
        let accounting = selected_evaluator_resource_accounting().expect("resource accounting");
        assert_eq!(accounting.component_material_wire_byte_length(), 6_684_672);
        assert_eq!(
            accounting.component_material_resident_byte_length(),
            8_912_896
        );
        assert_eq!(accounting.source_component_count_per_participant(), 19);
        assert_eq!(accounting.aggregate_component_count(), 18);
        assert_eq!(
            accounting.final_evaluator_key_store_wire_byte_length(),
            120_324_096
        );
        assert_eq!(
            accounting.final_evaluator_key_store_byte_length(),
            160_432_128
        );
        assert_eq!(
            accounting.setup_upload_lower_bound_per_participant(),
            127_008_768
        );
        assert_eq!(
            accounting.ceremony_setup_upload_lower_bound(),
            1_390_411_776
        );
        assert_eq!(
            accounting.complete_runtime_material_per_participant(),
            169_345_024
        );
        assert_eq!(
            accounting.complete_runtime_material_for_ceremony(),
            1_853_882_368
        );
        accounting
            .require_mobile_ceremony_upload_limit()
            .expect("setup upload fits the fixed ceiling");
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
        assert_eq!(
            selected_maximum_proof_objects_per_action()
                .expect("selected proof-object count derives"),
            SELECTED_MAXIMUM_PROOF_OBJECTS_PER_ACTION
        );
        let candidate = SuiteRecord::new(
            selected_count_limits().expect("selected count limits derive"),
            selected_byte_limits().expect("selected byte limits derive"),
            artifacts,
        )
        .expect("candidate suite record");
        assert_eq!(
            candidate.suite_id().expect("suite identifier derives"),
            SELECTED_CANDIDATE_SUITE_IDENTIFIER
        );
        assert_eq!(
            candidate.encode().expect("candidate suite encodes").len(),
            1_688
        );
    }

    #[test]
    fn exact_structural_candidate_remains_below_the_operative_authority_boundary() {
        let candidate = selected_candidate_suite_record();
        assert_eq!(
            require_selected_suite_record(&candidate)
                .expect_err("oversized exact-family plans cannot become operative")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
        assert_eq!(
            select_suite_record(&candidate)
                .err()
                .expect("oversized exact-family plans cannot mint authority")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
        assert!(
            SELECTED_MAXIMUM_EXACT_FAMILY_PROOF_BYTE_LENGTH
                > MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64
        );
        assert!(
            SELECTED_EXACT_FAMILY_PROOF_BYTES_PER_ACTION
                > candidate.byte_limits().maximum_proof_bytes_per_action()
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
        let ballot_package_byte_ceiling = selected_byte_limits()
            .expect("selected byte limits derive")
            .maximum_candidate_bytes_per_participant()
            / u64::from(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT);
        tuple.items[21] = CanonicalItem::unsigned64(6 * ballot_package_byte_ceiling);
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
            selected_byte_limits().expect("selected byte limits derive"),
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
            selected_byte_limits().expect("selected byte limits derive"),
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
                selected_byte_limits().expect("selected byte limits derive"),
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
        let suite = SuiteRecord::new(
            counts,
            selected_byte_limits().expect("selected byte limits derive"),
            structural_artifact_references(),
        )
        .expect("structural suite");
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
