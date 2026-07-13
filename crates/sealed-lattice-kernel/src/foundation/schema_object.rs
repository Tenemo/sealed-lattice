use super::proof_commitments::reencode_canonical_proof_commitment_object;
use super::{
    ACTION_DEFINITION_SCHEMA_IDENTIFIER, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER, ActionDefinition,
    ArtifactReference, BOARD_POLICY_SCHEMA_IDENTIFIER, BoardPolicy,
    CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER, CHECKPOINT_MANIFEST_SCHEMA_IDENTIFIER,
    CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER,
    COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalTuple, CheckpointBoundaryProfile, CheckpointManifest,
    CheckpointRandomUseProfile, CollectivePublicKeyAggregateStatement,
    DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
    DeviceWrappedStorageRoot, DeviceWrappingAssociatedData, DistributionRecord,
    FoundationSchemaError, LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER, LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER,
    LocalRecordAssociatedData, LocalRecordEnvelope, LocalRecordKeyInput,
    MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
    MANIFEST_SCHEMA_IDENTIFIER, MOBILE_RUNTIME_PROFILE_SCHEMA_IDENTIFIER, MailboxAssociatedData,
    MailboxKeyScheduleInput, Manifest, MobileRuntimeProfile, OBJECT_ENVELOPE_SCHEMA_IDENTIFIER,
    OPTION_DEFINITION_SCHEMA_IDENTIFIER, ObjectEnvelope, OptionDefinition,
    PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER, PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER,
    PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER, PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER,
    PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER, PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER,
    PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER, PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
    PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER, PROOF_PROFILE_SET_SCHEMA_IDENTIFIER,
    PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER, ProofFamilyProfile, ProofFieldProfile,
    ProofFieldSchedule, ProofObjectHeader, ProofProfileSet, RANDOM_CURSOR_SCHEMA_IDENTIFIER,
    ROSTER_ENTRY_SCHEMA_IDENTIFIER, ROSTER_SCHEMA_IDENTIFIER,
    RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER, RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER,
    RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER, RandomCursor, RefusalReason, Roster, RosterEntry,
    RuntimeAssetReference, RuntimeBuildManifest, RuntimeOperationProfile,
    SIGNED_CARRIER_SCHEMA_IDENTIFIER, SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER,
    STATE_CERTIFICATE_SCHEMA_IDENTIFIER, STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
    STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER, STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER,
    STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER, STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER, SUITE_RECORD_SCHEMA_IDENTIFIER, SignedCarrier,
    SignedMailboxEnvelope, StateCertificate, StateError, StateOutputIntentPayload,
    StateRecoveryTransitionPayload, StateReservationIntentPayload, StateWitnessVotePayload,
    StorageRootCommitmentPayload, StreamDescriptor, SuiteRecord,
};

const FOUNDATION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FoundationSchemaObjectValidation {
    pub schema_identifier: u16,
    pub schema_version: u16,
    pub canonical_byte_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FoundationSchemaObjectValidationError {
    CanonicalCodec(CanonicalCodecError),
    Schema {
        refusal_reason: RefusalReason,
        message: &'static str,
    },
    UnsupportedSchemaIdentifier(u16),
    UnsupportedSchemaVersion(u16),
    ReencodingMismatch,
}

impl From<CanonicalCodecError> for FoundationSchemaObjectValidationError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::CanonicalCodec(error)
    }
}

impl From<FoundationSchemaError> for FoundationSchemaObjectValidationError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Schema {
            refusal_reason: error.refusal_reason,
            message: error.message,
        }
    }
}

impl From<StateError> for FoundationSchemaObjectValidationError {
    fn from(error: StateError) -> Self {
        Self::Schema {
            refusal_reason: error.refusal_reason,
            message: error.message,
        }
    }
}

pub(crate) fn validate_foundation_schema_object(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> Result<FoundationSchemaObjectValidation, FoundationSchemaObjectValidationError> {
    let (schema_identifier, schema_version) = CanonicalTuple::decode_schema_header(bytes, limits)?;

    macro_rules! reencode_schema {
        ($value_type:ty) => {{
            require_supported_schema_version(schema_version)?;
            <$value_type>::decode(bytes, limits)?.encode()?
        }};
    }

    let reencoded = match schema_identifier {
        OBJECT_ENVELOPE_SCHEMA_IDENTIFIER => reencode_schema!(ObjectEnvelope),
        SIGNED_CARRIER_SCHEMA_IDENTIFIER => reencode_schema!(SignedCarrier),
        PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER => {
            require_supported_schema_version(schema_version)?;
            ProofObjectHeader::decode(bytes, limits)?.encode_prevalidated()?
        }
        PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER
        | PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER
        | PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER
        | PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER
        | PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER
        | PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER => {
            require_supported_schema_version(schema_version)?;
            reencode_canonical_proof_commitment_object(schema_identifier, bytes, limits)?
        }
        MANIFEST_SCHEMA_IDENTIFIER => reencode_schema!(Manifest),
        OPTION_DEFINITION_SCHEMA_IDENTIFIER => reencode_schema!(OptionDefinition),
        ACTION_DEFINITION_SCHEMA_IDENTIFIER => reencode_schema!(ActionDefinition),
        BOARD_POLICY_SCHEMA_IDENTIFIER => reencode_schema!(BoardPolicy),
        ROSTER_ENTRY_SCHEMA_IDENTIFIER => reencode_schema!(RosterEntry),
        ROSTER_SCHEMA_IDENTIFIER => reencode_schema!(Roster),
        DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER => reencode_schema!(DistributionRecord),
        ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER => reencode_schema!(ArtifactReference),
        SUITE_RECORD_SCHEMA_IDENTIFIER => reencode_schema!(SuiteRecord),
        STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER => reencode_schema!(StreamDescriptor),
        MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER => reencode_schema!(MailboxKeyScheduleInput),
        MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER => reencode_schema!(MailboxAssociatedData),
        SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER => reencode_schema!(SignedMailboxEnvelope),
        DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER => {
            reencode_schema!(DeviceWrappingAssociatedData)
        }
        LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER => {
            reencode_schema!(LocalRecordAssociatedData)
        }
        STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER => {
            reencode_schema!(StorageRootCommitmentPayload)
        }
        LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER => reencode_schema!(LocalRecordKeyInput),
        DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER => {
            reencode_schema!(DeviceWrappedStorageRoot)
        }
        LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER => reencode_schema!(LocalRecordEnvelope),
        STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER => {
            reencode_schema!(StateReservationIntentPayload)
        }
        STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER => {
            reencode_schema!(StateOutputIntentPayload)
        }
        STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER => {
            reencode_schema!(StateWitnessVotePayload)
        }
        STATE_CERTIFICATE_SCHEMA_IDENTIFIER => reencode_schema!(StateCertificate),
        STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER => {
            reencode_schema!(StateRecoveryTransitionPayload)
        }
        RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER => reencode_schema!(RuntimeAssetReference),
        RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER => reencode_schema!(RuntimeBuildManifest),
        RANDOM_CURSOR_SCHEMA_IDENTIFIER => reencode_schema!(RandomCursor),
        CHECKPOINT_MANIFEST_SCHEMA_IDENTIFIER => reencode_schema!(CheckpointManifest),
        CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER => {
            reencode_schema!(CheckpointRandomUseProfile)
        }
        CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER => {
            reencode_schema!(CheckpointBoundaryProfile)
        }
        RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER => {
            reencode_schema!(RuntimeOperationProfile)
        }
        MOBILE_RUNTIME_PROFILE_SCHEMA_IDENTIFIER => reencode_schema!(MobileRuntimeProfile),
        PROOF_PROFILE_SET_SCHEMA_IDENTIFIER => reencode_schema!(ProofProfileSet),
        PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER => reencode_schema!(ProofFieldProfile),
        PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER => reencode_schema!(ProofFamilyProfile),
        PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER => reencode_schema!(ProofFieldSchedule),
        COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            reencode_schema!(CollectivePublicKeyAggregateStatement)
        }
        _ => {
            return Err(
                FoundationSchemaObjectValidationError::UnsupportedSchemaIdentifier(
                    schema_identifier,
                ),
            );
        }
    };
    if reencoded != bytes {
        return Err(FoundationSchemaObjectValidationError::ReencodingMismatch);
    }
    Ok(FoundationSchemaObjectValidation {
        schema_identifier,
        schema_version,
        canonical_byte_length: bytes.len(),
    })
}

fn require_supported_schema_version(
    schema_version: u16,
) -> Result<(), FoundationSchemaObjectValidationError> {
    if schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(
            FoundationSchemaObjectValidationError::UnsupportedSchemaVersion(schema_version),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{CanonicalItem, CanonicalItemType, Hash512, ProofAuthenticationNode};

    #[test]
    fn validates_representative_independent_schema_families() {
        let limits = CanonicalDecodeLimits::default();
        let values = [
            StorageRootCommitmentPayload::new(Hash512::from_bytes([1; 64]))
                .encode()
                .expect("storage commitment encodes"),
            StateReservationIntentPayload {
                capability_kind: crate::foundation::StateCapabilityKind::BallotCandidateList,
                authorization_hash: Hash512::from_bytes([2; 64]),
            }
            .encode()
            .expect("state intent encodes"),
            CheckpointRandomUseProfile::new(1, 2)
                .expect("checkpoint random-use profile")
                .encode()
                .expect("checkpoint random-use profile encodes"),
            ProofAuthenticationNode::new(3, 4, Hash512::from_bytes([5; 64]))
                .encode()
                .expect("authentication node encodes"),
            ProofFieldSchedule::new(0, 4, 3, 2, 8, 4, 2, 6)
                .expect("proof field schedule")
                .encode()
                .expect("proof field schedule encodes"),
            CollectivePublicKeyAggregateStatement::new(
                Hash512::from_bytes([6; 64]),
                vec![Hash512::from_bytes([7; 64])],
                Hash512::from_bytes([8; 64]),
                Hash512::from_bytes([9; 64]),
            )
            .expect("collective public-key aggregate statement")
            .encode()
            .expect("collective public-key aggregate statement encodes"),
        ];

        for value in values {
            let tuple = CanonicalTuple::decode(&value, &limits).expect("test tuple decodes");
            assert_eq!(
                validate_foundation_schema_object(&value, &limits),
                Ok(FoundationSchemaObjectValidation {
                    schema_identifier: tuple.schema_identifier,
                    schema_version: tuple.schema_version,
                    canonical_byte_length: value.len(),
                })
            );
        }
    }

    #[test]
    fn refuses_unknown_and_noncanonical_objects() {
        let limits = CanonicalDecodeLimits::default();
        let unknown = CanonicalTuple::new(0xffff, 1, Vec::new())
            .encode()
            .expect("unknown tuple encodes canonically");
        assert_eq!(
            validate_foundation_schema_object(&unknown, &limits),
            Err(FoundationSchemaObjectValidationError::UnsupportedSchemaIdentifier(0xffff))
        );

        let mut unknown_with_unparsed_payload = Vec::new();
        unknown_with_unparsed_payload.extend_from_slice(&0xffff_u16.to_le_bytes());
        unknown_with_unparsed_payload.extend_from_slice(&1_u16.to_le_bytes());
        unknown_with_unparsed_payload.extend_from_slice(&1_u32.to_le_bytes());
        unknown_with_unparsed_payload.extend_from_slice(&0xffff_u16.to_le_bytes());
        unknown_with_unparsed_payload.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            validate_foundation_schema_object(&unknown_with_unparsed_payload, &limits),
            Err(FoundationSchemaObjectValidationError::UnsupportedSchemaIdentifier(0xffff))
        );

        let mut trailing = StorageRootCommitmentPayload::new(Hash512::from_bytes([3; 64]))
            .encode()
            .expect("commitment encodes");
        trailing.push(0);
        let trailing_result = validate_foundation_schema_object(&trailing, &limits);
        assert!(
            matches!(
                &trailing_result,
                Err(FoundationSchemaObjectValidationError::Schema { .. })
            ),
            "{trailing_result:?}"
        );
    }

    #[test]
    fn nested_redecoding_shares_the_cumulative_work_budget() {
        let mut nested_tuple = CanonicalTuple::new(
            0xffff,
            1,
            vec![
                CanonicalItem::fixed_bytes(vec![0x5a; 4_096])
                    .expect("leaf bytes fit the default item limit"),
            ],
        );
        for _ in 0..8 {
            nested_tuple = CanonicalTuple::new(
                0xffff,
                1,
                vec![
                    CanonicalItem::nested_tuple(&nested_tuple).expect("nested test tuple encodes"),
                ],
            );
        }
        let nested_item =
            CanonicalItem::nested_tuple(&nested_tuple).expect("frontier node tuple encodes");
        let encoded = CanonicalTuple::new(
            PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
            1,
            vec![
                CanonicalItem::unsigned16(0),
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &[nested_item])
                    .expect("nested tuple list encodes"),
            ],
        )
        .encode()
        .expect("frontier-shaped test object encodes");

        let limits = CanonicalDecodeLimits {
            maximum_cumulative_work_byte_length: 60_000,
            ..CanonicalDecodeLimits::default()
        };
        CanonicalTuple::decode(&encoded, &limits)
            .expect("one canonical pass stays within the cumulative work budget");
        let validation_result = validate_foundation_schema_object(&encoded, &limits);
        assert!(
            matches!(
                &validation_result,
                Err(FoundationSchemaObjectValidationError::Schema {
                    refusal_reason: RefusalReason::OutsideSupportedProfile,
                    ..
                })
            ),
            "{validation_result:?}"
        );
    }

    #[test]
    fn deterministic_hostile_mutation_corpus_never_panics() {
        let limits = CanonicalDecodeLimits::default();
        let seed_objects = [
            StorageRootCommitmentPayload::new(Hash512::from_bytes([0x11; 64]))
                .encode()
                .expect("storage commitment encodes"),
            StateReservationIntentPayload {
                capability_kind: crate::foundation::StateCapabilityKind::BallotCandidateList,
                authorization_hash: Hash512::from_bytes([0x22; 64]),
            }
            .encode()
            .expect("state reservation intent encodes"),
            CheckpointRandomUseProfile::new(0x0116, 7)
                .expect("checkpoint random-use profile")
                .encode()
                .expect("checkpoint random-use profile encodes"),
            ProofAuthenticationNode::new(3, 4, Hash512::from_bytes([0x33; 64]))
                .encode()
                .expect("authentication node encodes"),
            ProofFieldSchedule::new(0, 4, 3, 2, 8, 4, 2, 6)
                .expect("proof field schedule")
                .encode()
                .expect("proof field schedule encodes"),
            CollectivePublicKeyAggregateStatement::new(
                Hash512::from_bytes([0x44; 64]),
                vec![Hash512::from_bytes([0x45; 64])],
                Hash512::from_bytes([0x46; 64]),
                Hash512::from_bytes([0x47; 64]),
            )
            .expect("collective public-key aggregate statement")
            .encode()
            .expect("collective public-key aggregate statement encodes"),
        ];
        let mut mutation_state = 0x9e37_79b9_7f4a_7c15_u64;

        for mutation_index in 0..4_096_usize {
            mutation_state ^= mutation_state << 13;
            mutation_state ^= mutation_state >> 7;
            mutation_state ^= mutation_state << 17;
            let seed_object = &seed_objects[mutation_index % seed_objects.len()];
            let mut candidate = seed_object.clone();

            match mutation_index % 5 {
                0 => {
                    let retained_byte_length = (mutation_state as usize) % (candidate.len() + 1);
                    candidate.truncate(retained_byte_length);
                }
                1 => {
                    let byte_index = (mutation_state as usize) % candidate.len();
                    let bit_index = ((mutation_state >> 8) & 7) as u8;
                    candidate[byte_index] ^= 1_u8 << bit_index;
                }
                2 => {
                    let byte_index = (mutation_state as usize) % candidate.len();
                    let replacement_byte = (mutation_state >> 24) as u8;
                    candidate[byte_index] = replacement_byte;
                    candidate.extend_from_slice(&[
                        (mutation_state >> 32) as u8,
                        (mutation_state >> 40) as u8,
                    ]);
                }
                3 => {
                    if candidate.len() >= 8 {
                        let header_byte_index = 4 + ((mutation_state as usize) % 4);
                        candidate[header_byte_index] = 0xff;
                    }
                }
                _ => {
                    let candidate_byte_length = (mutation_state as usize) % 1_025;
                    candidate.resize(candidate_byte_length, 0);
                    for (byte_index, byte) in candidate.iter_mut().enumerate() {
                        mutation_state ^= mutation_state << 13;
                        mutation_state ^= mutation_state >> 7;
                        mutation_state ^= mutation_state << 17;
                        *byte = (mutation_state >> (byte_index % 8)) as u8;
                    }
                }
            }

            let validation =
                std::panic::catch_unwind(|| validate_foundation_schema_object(&candidate, &limits));
            assert!(
                validation.is_ok(),
                "foundation schema validation panicked for deterministic mutation {mutation_index}"
            );
            if let Ok(Ok(accepted)) = validation {
                assert_eq!(accepted.canonical_byte_length, candidate.len());
            }
        }
    }
}
