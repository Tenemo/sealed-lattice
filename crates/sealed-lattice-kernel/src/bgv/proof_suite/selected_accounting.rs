//! Exact proof-object accounting for the fixed suite.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

use crate::{
    bgv::{
        evaluator::{
            program::{EvaluatorProgramKeyPositions, selected_evaluator_program_set},
            top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        },
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        serialization::{
            parse_two_component_data_ciphertext_at_level,
            two_component_data_ciphertext_canonical_byte_length_ceiling_at_level,
        },
        setup::{
            CanonicalAcceptedSetupPackage, VerifiedAcceptedSetupConsumedObjectByteLengthCatalog,
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog,
            VerifiedVssQualificationTerminals,
            selected_setup_generation_private_randomness_kmac_input_accounting,
        },
        target_decryption::{
            kllps_release::selected_target_release_private_randomness_kmac_input_accounting,
            selected_target_paired_partial_decryption_residue_byte_length,
            selected_target_paired_partial_decryption_stream_byte_length,
            selected_target_partial_decryption_stream_byte_length,
        },
    },
    foundation::{
        AggregatePayload, CanonicalDecodeLimits, FOUNDATION_PROFILE, FoundationObjectType, Hash512,
        MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, ObjectEnvelope, ParticipantIdentity,
        PrivateRandomnessKmacInputClassAccounting, ProofApplicationSlotCeilings, ProofObjectHeader,
        SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT, StreamDescriptor,
        VerifiedBoardApplicationSource, VerifiedEvaluatorReplay, VerifiedFinality,
        VerifiedStateOutput, selected_action_root_private_randomness_kmac_input_accounting,
        selected_evaluator_resource_accounting, selected_maximum_proof_objects_per_action,
        selected_setup_transport_private_randomness_kmac_input_accounting,
    },
};

use super::body::{
    CommonProofComponentByteLengths, ProofTreeCatalogSource, minimal_frontier_node_count,
};
use super::committed_material::maximum_committed_material_kmac_input_accounting;
use super::external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH;
use super::prover::{
    CommonProofCheckpointCursorManifestRequirement, CommonProofExternalMemoryRequirement,
    CommonProofResidentMemoryPhase, CommonProofResidentMemoryPlan,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, common_proof_external_memory_requirement,
    common_proof_private_randomness_kmac_input_accounting,
    common_proof_resident_memory_requirement, common_proof_source_provider_is_live_during_phase,
};
use super::relation_plan::{
    BoundTreeConstructionKind, BoundTreeRootUse, CommittedMaterialSourceProviderMemoryAccounting,
    ProofPrivacyMode, RelationColumnOrigin, RelationMaskKind, RelationPlanCheckContext,
    RelationPlanVariant, RelationTreeDescriptor,
    aggregate_threshold_share_source_provider_memory_accounting,
    ballot_encryption_private_randomness_kmac_input_accounting,
    vss_share_linkage_source_provider_memory_accounting,
};
use super::{
    BCS_MERKLE_STATISTICAL_PRIVACY_DENOMINATOR_EXPONENT, CommonProofByteLengthCeiling,
    CommonProofGenerationCheckpointCustodyRequirement, CommonProofRuntimeLimits,
    CommonProofTranscriptSchedule, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, ProofBodyLayout, ProofLeafVisibility,
    ProofTreeCatalogInput, ProofTreeRole, RelationProofTreeInput, RelationRootConstructionKind,
    RelationRootEndpoint, SelectedApplicationStatementContext,
    SelectedBallotCiphertextReadbackMemoryAccounting,
    SelectedBallotValidityCarrierBufferAccounting,
    SelectedEvaluatorAggregateSourceProviderMemoryAccounting,
    SelectedRelationApplicationRoundByRoundTheoremInput, StatementOwnedProofTreeInput,
    VerifiedBallotValidityOutput, VerifierHashEquationLedger,
    aggregate_threshold_share_private_randomness_kmac_input_accounting,
    build_complete_proof_tree_catalog, canonical_common_proof_byte_length_ceiling,
    canonical_selected_application_statement_for_ceiling,
    common_proof_generation_checkpoint_custody_requirement_for_variant,
    common_proof_randomness_purpose_is_assigned, decode_selected_application_statement,
    evaluator_aggregate_source_provider_memory_accounting, proof_query_tree_byte_length,
    selected_ballot_ciphertext_readback_memory_accounting,
    selected_ballot_validity_carrier_buffer_accounting, selected_committed_material_profile,
    selected_committed_material_relation_plan_input, selected_evaluator_entry_positions,
    selected_galois_key_share_batch_schedule, selected_galois_key_share_contribution_roots,
    selected_proof_profile_set, selected_relation_application_round_by_round_theorem_inputs,
    selected_relation_plan_check_context, verifier_hash_equation_ledger,
};

use super::selected_profile::selected_proof_application_slot_ceilings;

struct SelectedProofTransportSizing {
    ceiling: CommonProofByteLengthCeiling,
    layout: ProofBodyLayout,
    maximum_prefetched_query_byte_length: u64,
    proof_byte_length: u64,
    transcript_schedule: CommonProofTranscriptSchedule,
    tree_ceilings: Vec<SelectedProofTreeByteCeiling>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedProofAccountingError {
    CanonicalEncoding,
    InvalidProfile,
    ApplicationSoundness,
    InvalidTreeGeometry,
    CountOverflow,
    AllocationLimitExceeded,
    ProofByteLengthExceeded {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        proof_byte_length: usize,
        maximum_proof_byte_length: usize,
    },
    GeneratedProofByteLengthExceeded {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        generated_proof_byte_length: u64,
        proof_byte_ceiling: u64,
    },
    ResourcePlanning,
    DuplicateCompleteActionOwner,
    MissingCompleteActionOwner,
    UnassignedMaskPurposeClass {
        application_statement_schema_identifier: u16,
        purpose_class: u16,
    },
}

/// Exact canonical and decoded stream buffers owned by the selected paired
/// target-release path. This is development accounting only; it is not a
/// protocol field or a verifier verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedTargetReleaseStreamBufferAccounting {
    canonical_role_stream_byte_length: u64,
    canonical_pair_wire_byte_length: u64,
    generation_retained_canonical_byte_length: u64,
    verification_decoded_residue_byte_length: u64,
    full_stream_copy_count: u8,
    full_stream_copy_byte_length: u64,
    maximum_full_stream_copied_buffer_byte_length: u64,
}

impl SelectedTargetReleaseStreamBufferAccounting {
    pub(crate) const fn canonical_role_stream_byte_length(self) -> u64 {
        self.canonical_role_stream_byte_length
    }

    pub(crate) const fn canonical_pair_wire_byte_length(self) -> u64 {
        self.canonical_pair_wire_byte_length
    }

    pub(crate) const fn generation_retained_canonical_byte_length(self) -> u64 {
        self.generation_retained_canonical_byte_length
    }

    pub(crate) const fn verification_decoded_residue_byte_length(self) -> u64 {
        self.verification_decoded_residue_byte_length
    }

    pub(crate) const fn full_stream_copy_count(self) -> u8 {
        self.full_stream_copy_count
    }

    pub(crate) const fn full_stream_copy_byte_length(self) -> u64 {
        self.full_stream_copy_byte_length
    }

    pub(crate) const fn maximum_full_stream_copied_buffer_byte_length(self) -> u64 {
        self.maximum_full_stream_copied_buffer_byte_length
    }
}

/// Exact canonical and decoded residue bytes for the two finalized evaluator
/// target ciphertexts supplied to one generated-object accounting run. Wire
/// lengths remain data-dependent because the production BGV codec uses
/// canonical variable-width integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedGeneratedTargetCiphertextByteAccounting {
    target_identifier_canonical_wire_byte_length: u64,
    target_order_canonical_wire_byte_length: u64,
    canonical_pair_wire_byte_length: u64,
    target_ciphertext_codec_ceiling_wire_byte_length: u64,
    target_pair_codec_ceiling_wire_byte_length: u64,
    target_identifier_decoded_residue_byte_length: u64,
    target_order_decoded_residue_byte_length: u64,
    decoded_pair_residue_byte_length: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
}

impl SelectedGeneratedTargetCiphertextByteAccounting {
    pub(crate) const fn target_identifier_canonical_wire_byte_length(self) -> u64 {
        self.target_identifier_canonical_wire_byte_length
    }

    pub(crate) const fn target_order_canonical_wire_byte_length(self) -> u64 {
        self.target_order_canonical_wire_byte_length
    }

    pub(crate) const fn canonical_pair_wire_byte_length(self) -> u64 {
        self.canonical_pair_wire_byte_length
    }

    pub(crate) const fn target_ciphertext_codec_ceiling_wire_byte_length(self) -> u64 {
        self.target_ciphertext_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn target_pair_codec_ceiling_wire_byte_length(self) -> u64 {
        self.target_pair_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn target_identifier_decoded_residue_byte_length(self) -> u64 {
        self.target_identifier_decoded_residue_byte_length
    }

    pub(crate) const fn target_order_decoded_residue_byte_length(self) -> u64 {
        self.target_order_decoded_residue_byte_length
    }

    pub(crate) const fn decoded_pair_residue_byte_length(self) -> u64 {
        self.decoded_pair_residue_byte_length
    }

    pub(crate) const fn maximum_boundary_copied_buffer_byte_length(self) -> u64 {
        self.maximum_boundary_copied_buffer_byte_length
    }
}

pub(crate) fn selected_generated_target_ciphertext_byte_accounting(
    canonical_target_identifier_ciphertext_bytes: &[u8],
    canonical_target_order_ciphertext_bytes: &[u8],
) -> Result<SelectedGeneratedTargetCiphertextByteAccounting, SelectedProofAccountingError> {
    let copied_buffer_bound = u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let target_identifier_canonical_wire_byte_length =
        u64::try_from(canonical_target_identifier_ciphertext_bytes.len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let target_order_canonical_wire_byte_length =
        u64::try_from(canonical_target_order_ciphertext_bytes.len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    if target_identifier_canonical_wire_byte_length == 0
        || target_order_canonical_wire_byte_length == 0
        || target_identifier_canonical_wire_byte_length > copied_buffer_bound
        || target_order_canonical_wire_byte_length > copied_buffer_bound
    {
        return Err(SelectedProofAccountingError::AllocationLimitExceeded);
    }

    let target_identifier = parse_two_component_data_ciphertext_at_level(
        canonical_target_identifier_ciphertext_bytes,
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let target_order = parse_two_component_data_ciphertext_at_level(
        canonical_target_order_ciphertext_bytes,
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let target_identifier_decoded_residue_byte_length =
        selected_decoded_residue_byte_length(&target_identifier.components)?;
    let target_order_decoded_residue_byte_length =
        selected_decoded_residue_byte_length(&target_order.components)?;
    let canonical_pair_wire_byte_length = target_identifier_canonical_wire_byte_length
        .checked_add(target_order_canonical_wire_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let decoded_pair_residue_byte_length = target_identifier_decoded_residue_byte_length
        .checked_add(target_order_decoded_residue_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let target_ciphertext_codec_ceiling_wire_byte_length =
        two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let target_pair_codec_ceiling_wire_byte_length =
        target_ciphertext_codec_ceiling_wire_byte_length
            .checked_mul(2)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    if canonical_pair_wire_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || target_identifier_canonical_wire_byte_length
            > target_ciphertext_codec_ceiling_wire_byte_length
        || target_order_canonical_wire_byte_length
            > target_ciphertext_codec_ceiling_wire_byte_length
        || decoded_pair_residue_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    Ok(SelectedGeneratedTargetCiphertextByteAccounting {
        target_identifier_canonical_wire_byte_length,
        target_order_canonical_wire_byte_length,
        canonical_pair_wire_byte_length,
        target_ciphertext_codec_ceiling_wire_byte_length,
        target_pair_codec_ceiling_wire_byte_length,
        target_identifier_decoded_residue_byte_length,
        target_order_decoded_residue_byte_length,
        decoded_pair_residue_byte_length,
        maximum_boundary_copied_buffer_byte_length: target_identifier_canonical_wire_byte_length
            .max(target_order_canonical_wire_byte_length),
    })
}

/// Exact generated bytes for the positively verified aggregate input and the
/// evaluator replay output. Descriptor lengths are subdivisions of their
/// carriers and are reported for diagnostics without being added twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedGeneratedEvaluatorCorpusByteAccounting {
    selected_ballot_count: u16,
    aggregate_source_carrier_wire_byte_length: u64,
    aggregate_ciphertext_descriptor_byte_length: u64,
    aggregate_ciphertext_stream_wire_byte_length: u64,
    aggregate_ciphertext_decoded_residue_byte_length: u64,
    evaluator_replay_carrier_wire_byte_length: u64,
    target_identifier_descriptor_byte_length: u64,
    target_order_descriptor_byte_length: u64,
    target_identifier_stream_wire_byte_length: u64,
    target_order_stream_wire_byte_length: u64,
    target_pair_stream_wire_byte_length: u64,
    target_pair_codec_ceiling_wire_byte_length: u64,
    target_pair_decoded_residue_byte_length: u64,
    complete_evaluator_public_corpus_wire_byte_length: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
}

impl SelectedGeneratedEvaluatorCorpusByteAccounting {
    pub(crate) const fn selected_ballot_count(self) -> u16 {
        self.selected_ballot_count
    }

    pub(crate) const fn aggregate_source_carrier_wire_byte_length(self) -> u64 {
        self.aggregate_source_carrier_wire_byte_length
    }

    pub(crate) const fn aggregate_ciphertext_descriptor_byte_length(self) -> u64 {
        self.aggregate_ciphertext_descriptor_byte_length
    }

    pub(crate) const fn aggregate_ciphertext_stream_wire_byte_length(self) -> u64 {
        self.aggregate_ciphertext_stream_wire_byte_length
    }

    pub(crate) const fn aggregate_ciphertext_decoded_residue_byte_length(self) -> u64 {
        self.aggregate_ciphertext_decoded_residue_byte_length
    }

    pub(crate) const fn evaluator_replay_carrier_wire_byte_length(self) -> u64 {
        self.evaluator_replay_carrier_wire_byte_length
    }

    pub(crate) const fn target_identifier_descriptor_byte_length(self) -> u64 {
        self.target_identifier_descriptor_byte_length
    }

    pub(crate) const fn target_order_descriptor_byte_length(self) -> u64 {
        self.target_order_descriptor_byte_length
    }

    pub(crate) const fn target_identifier_stream_wire_byte_length(self) -> u64 {
        self.target_identifier_stream_wire_byte_length
    }

    pub(crate) const fn target_order_stream_wire_byte_length(self) -> u64 {
        self.target_order_stream_wire_byte_length
    }

    pub(crate) const fn target_pair_stream_wire_byte_length(self) -> u64 {
        self.target_pair_stream_wire_byte_length
    }

    pub(crate) const fn target_pair_codec_ceiling_wire_byte_length(self) -> u64 {
        self.target_pair_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn target_pair_decoded_residue_byte_length(self) -> u64 {
        self.target_pair_decoded_residue_byte_length
    }

    pub(crate) const fn complete_evaluator_public_corpus_wire_byte_length(self) -> u64 {
        self.complete_evaluator_public_corpus_wire_byte_length
    }

    pub(crate) const fn maximum_boundary_copied_buffer_byte_length(self) -> u64 {
        self.maximum_boundary_copied_buffer_byte_length
    }
}

pub(crate) fn selected_generated_evaluator_corpus_byte_accounting(
    aggregate_source: &VerifiedBoardApplicationSource,
    verified_evaluator_replay: &VerifiedEvaluatorReplay,
) -> Result<SelectedGeneratedEvaluatorCorpusByteAccounting, SelectedProofAccountingError> {
    if aggregate_source.object_type() != FoundationObjectType::Aggregate
        || aggregate_source.object_hash()
            != verified_evaluator_replay.verified_aggregate_source_hash()
        || aggregate_source.suite_identifier() != verified_evaluator_replay.suite_identifier()
        || aggregate_source.ceremony_context_hash()
            != verified_evaluator_replay.ceremony_context_hash()
        || aggregate_source.action_context_hash() != verified_evaluator_replay.action_context_hash()
        || aggregate_source.roster_hash() != verified_evaluator_replay.roster_hash()
        || verified_evaluator_replay.target_level() as usize != CANONICAL_TARGET_CIPHERTEXT_LEVEL
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let aggregate_source_carrier = ObjectEnvelope::decode(
        aggregate_source.canonical_carrier_bytes(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    if aggregate_source_carrier
        .object_hash()
        .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
        != aggregate_source.object_hash()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let aggregate_payload = AggregatePayload::decode(
        &aggregate_source_carrier.payload_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    if aggregate_payload.verified_setup_source_hash()
        != verified_evaluator_replay.verified_setup_source_hash()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let selected_ballot_count =
        u16::try_from(aggregate_payload.selected_ballot_object_hashes().len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let aggregate_descriptor = aggregate_payload.aggregate_ciphertext_descriptor();
    let aggregate_source_carrier_wire_byte_length =
        u64::try_from(aggregate_source.canonical_carrier_bytes().len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let aggregate_ciphertext_descriptor_byte_length = u64::try_from(
        aggregate_descriptor
            .encode()
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
            .len(),
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let aggregate_ciphertext_stream_wire_byte_length = aggregate_descriptor.total_byte_length;
    let evaluator_replay_carrier_wire_byte_length =
        verified_evaluator_replay.canonical_carrier_byte_length();
    let target_identifier_descriptor_byte_length = u64::try_from(
        verified_evaluator_replay
            .target_identifier_descriptor()
            .encode()
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
            .len(),
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let target_order_descriptor_byte_length = u64::try_from(
        verified_evaluator_replay
            .target_order_descriptor()
            .encode()
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
            .len(),
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let target_identifier_stream_wire_byte_length = verified_evaluator_replay
        .target_identifier_descriptor()
        .total_byte_length;
    let target_order_stream_wire_byte_length = verified_evaluator_replay
        .target_order_descriptor()
        .total_byte_length;
    let target_pair_stream_wire_byte_length = target_identifier_stream_wire_byte_length
        .checked_add(target_order_stream_wire_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let target_pair_codec_ceiling_wire_byte_length =
        two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
        .checked_mul(2)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;

    let residue_byte_length =
        u64::try_from(size_of::<u64>()).map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE)
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let aggregate_ciphertext_decoded_residue_byte_length = u64::try_from(DATA_PRIMES.len())
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?
        .checked_mul(polynomial_degree)
        .and_then(|byte_length| byte_length.checked_mul(2))
        .and_then(|byte_length| byte_length.checked_mul(residue_byte_length))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let target_pair_decoded_residue_byte_length =
        u64::try_from(CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?
            .checked_mul(polynomial_degree)
            .and_then(|byte_length| byte_length.checked_mul(2))
            .and_then(|byte_length| byte_length.checked_mul(2))
            .and_then(|byte_length| byte_length.checked_mul(residue_byte_length))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let complete_evaluator_public_corpus_wire_byte_length =
        aggregate_source_carrier_wire_byte_length
            .checked_add(aggregate_ciphertext_stream_wire_byte_length)
            .and_then(|total| total.checked_add(evaluator_replay_carrier_wire_byte_length))
            .and_then(|total| total.checked_add(target_pair_stream_wire_byte_length))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let copied_buffer_bound = u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let maximum_boundary_copied_buffer_byte_length = target_identifier_stream_wire_byte_length
        .max(target_order_stream_wire_byte_length)
        .max(aggregate_source_carrier_wire_byte_length)
        .max(evaluator_replay_carrier_wire_byte_length);
    if selected_ballot_count == 0
        || aggregate_ciphertext_stream_wire_byte_length == 0
        || target_identifier_stream_wire_byte_length == 0
        || target_order_stream_wire_byte_length == 0
        || target_pair_stream_wire_byte_length > target_pair_codec_ceiling_wire_byte_length
        || aggregate_ciphertext_stream_wire_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || target_pair_stream_wire_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || complete_evaluator_public_corpus_wire_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || maximum_boundary_copied_buffer_byte_length > copied_buffer_bound
        || aggregate_ciphertext_decoded_residue_byte_length
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || target_pair_decoded_residue_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    Ok(SelectedGeneratedEvaluatorCorpusByteAccounting {
        selected_ballot_count,
        aggregate_source_carrier_wire_byte_length,
        aggregate_ciphertext_descriptor_byte_length,
        aggregate_ciphertext_stream_wire_byte_length,
        aggregate_ciphertext_decoded_residue_byte_length,
        evaluator_replay_carrier_wire_byte_length,
        target_identifier_descriptor_byte_length,
        target_order_descriptor_byte_length,
        target_identifier_stream_wire_byte_length,
        target_order_stream_wire_byte_length,
        target_pair_stream_wire_byte_length,
        target_pair_codec_ceiling_wire_byte_length,
        target_pair_decoded_residue_byte_length,
        complete_evaluator_public_corpus_wire_byte_length,
        maximum_boundary_copied_buffer_byte_length,
    })
}

fn selected_decoded_residue_byte_length(
    components: &[crate::bgv::rns::RnsPolynomial],
) -> Result<u64, SelectedProofAccountingError> {
    let residue_byte_length =
        u64::try_from(size_of::<u64>()).map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    components
        .iter()
        .flat_map(|component| component.residues_by_modulus.iter())
        .try_fold(0_u64, |total, residues| {
            total
                .checked_add(
                    u64::try_from(residues.len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?
                        .checked_mul(residue_byte_length)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?,
                )
                .ok_or(SelectedProofAccountingError::CountOverflow)
        })
}

/// Generated byte lengths retained by one decoded accepted setup package and
/// its descriptor-addressed public streams. The five hash-list carrier lengths
/// are subdivisions of the canonical package and therefore are not added to
/// any corpus total a second time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedAcceptedSetupPackageByteAccounting {
    canonical_package_byte_length: u64,
    canonical_package_codec_ceiling_byte_length: u64,
    ordered_hash_list_carrier_byte_lengths: [u64; 5],
    setup_intent_canonical_wire_byte_length: u64,
    public_randomness_commitment_canonical_wire_byte_length: u64,
    public_randomness_reveal_canonical_wire_byte_length: u64,
    dealer_public_record_canonical_wire_byte_length: u64,
    dealer_public_record_codec_ceiling_wire_byte_length: u64,
    private_share_acceptance_canonical_wire_byte_length: u64,
    private_share_acceptance_codec_ceiling_wire_byte_length: u64,
    private_vss_ciphertext_stream_wire_byte_length: u64,
    private_vss_signed_envelope_wire_byte_length: u64,
    private_vss_complete_recipient_wire_byte_length: u64,
    maximum_private_vss_ciphertext_descriptor_byte_length: u64,
    maximum_private_vss_signed_envelope_byte_length: u64,
    consumed_setup_object_canonical_wire_byte_length: u64,
    consumed_setup_object_codec_ceiling_wire_byte_length: u64,
    maximum_consumed_setup_object_canonical_wire_byte_length: u64,
    maximum_consumed_setup_object_codec_ceiling_wire_byte_length: u64,
    collective_public_key_wire_byte_length: u64,
    evaluator_source_material_wire_byte_length: u64,
    evaluator_source_material_resident_byte_length_per_participant: u64,
    final_evaluator_key_store_wire_byte_length: u64,
    final_evaluator_key_store_resident_byte_length: u64,
    package_public_proof_descriptor_count: u32,
    package_public_proof_wire_byte_length: u64,
    maximum_package_public_proof_wire_byte_length: u64,
    vss_share_linkage_proof_wire_byte_length: u64,
    aggregate_threshold_share_proof_wire_byte_length: u64,
    complete_setup_proof_wire_byte_length: u64,
    complete_setup_proof_ceiling_wire_byte_length: u64,
    maximum_complete_setup_proof_wire_byte_length: u64,
    package_referenced_stream_wire_byte_length: u64,
    package_and_referenced_stream_wire_byte_length: u64,
    complete_setup_canonical_wire_byte_length: u64,
    complete_setup_codec_and_proof_ceiling_wire_byte_length: u64,
}

impl SelectedAcceptedSetupPackageByteAccounting {
    pub(crate) const fn canonical_package_byte_length(self) -> u64 {
        self.canonical_package_byte_length
    }

    pub(crate) const fn canonical_package_codec_ceiling_byte_length(self) -> u64 {
        self.canonical_package_codec_ceiling_byte_length
    }

    pub(crate) const fn ordered_hash_list_carrier_byte_lengths(self) -> [u64; 5] {
        self.ordered_hash_list_carrier_byte_lengths
    }

    pub(crate) const fn setup_intent_canonical_wire_byte_length(self) -> u64 {
        self.setup_intent_canonical_wire_byte_length
    }

    pub(crate) const fn public_randomness_commitment_canonical_wire_byte_length(self) -> u64 {
        self.public_randomness_commitment_canonical_wire_byte_length
    }

    pub(crate) const fn public_randomness_reveal_canonical_wire_byte_length(self) -> u64 {
        self.public_randomness_reveal_canonical_wire_byte_length
    }

    pub(crate) const fn dealer_public_record_canonical_wire_byte_length(self) -> u64 {
        self.dealer_public_record_canonical_wire_byte_length
    }

    pub(crate) const fn dealer_public_record_codec_ceiling_wire_byte_length(self) -> u64 {
        self.dealer_public_record_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn private_share_acceptance_canonical_wire_byte_length(self) -> u64 {
        self.private_share_acceptance_canonical_wire_byte_length
    }

    pub(crate) const fn private_share_acceptance_codec_ceiling_wire_byte_length(self) -> u64 {
        self.private_share_acceptance_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn private_vss_ciphertext_stream_wire_byte_length(self) -> u64 {
        self.private_vss_ciphertext_stream_wire_byte_length
    }

    pub(crate) const fn private_vss_signed_envelope_wire_byte_length(self) -> u64 {
        self.private_vss_signed_envelope_wire_byte_length
    }

    pub(crate) const fn private_vss_complete_recipient_wire_byte_length(self) -> u64 {
        self.private_vss_complete_recipient_wire_byte_length
    }

    pub(crate) const fn maximum_private_vss_ciphertext_descriptor_byte_length(self) -> u64 {
        self.maximum_private_vss_ciphertext_descriptor_byte_length
    }

    pub(crate) const fn maximum_private_vss_signed_envelope_byte_length(self) -> u64 {
        self.maximum_private_vss_signed_envelope_byte_length
    }

    pub(crate) const fn consumed_setup_object_canonical_wire_byte_length(self) -> u64 {
        self.consumed_setup_object_canonical_wire_byte_length
    }

    pub(crate) const fn consumed_setup_object_codec_ceiling_wire_byte_length(self) -> u64 {
        self.consumed_setup_object_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn maximum_consumed_setup_object_canonical_wire_byte_length(self) -> u64 {
        self.maximum_consumed_setup_object_canonical_wire_byte_length
    }

    pub(crate) const fn maximum_consumed_setup_object_codec_ceiling_wire_byte_length(self) -> u64 {
        self.maximum_consumed_setup_object_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn collective_public_key_wire_byte_length(self) -> u64 {
        self.collective_public_key_wire_byte_length
    }

    pub(crate) const fn evaluator_source_material_wire_byte_length(self) -> u64 {
        self.evaluator_source_material_wire_byte_length
    }

    pub(crate) const fn evaluator_source_material_resident_byte_length_per_participant(
        self,
    ) -> u64 {
        self.evaluator_source_material_resident_byte_length_per_participant
    }

    pub(crate) const fn final_evaluator_key_store_wire_byte_length(self) -> u64 {
        self.final_evaluator_key_store_wire_byte_length
    }

    pub(crate) const fn final_evaluator_key_store_resident_byte_length(self) -> u64 {
        self.final_evaluator_key_store_resident_byte_length
    }

    pub(crate) const fn package_public_proof_descriptor_count(self) -> u32 {
        self.package_public_proof_descriptor_count
    }

    pub(crate) const fn package_public_proof_wire_byte_length(self) -> u64 {
        self.package_public_proof_wire_byte_length
    }

    pub(crate) const fn maximum_package_public_proof_wire_byte_length(self) -> u64 {
        self.maximum_package_public_proof_wire_byte_length
    }

    pub(crate) const fn vss_share_linkage_proof_wire_byte_length(self) -> u64 {
        self.vss_share_linkage_proof_wire_byte_length
    }

    pub(crate) const fn aggregate_threshold_share_proof_wire_byte_length(self) -> u64 {
        self.aggregate_threshold_share_proof_wire_byte_length
    }

    pub(crate) const fn complete_setup_proof_wire_byte_length(self) -> u64 {
        self.complete_setup_proof_wire_byte_length
    }

    pub(crate) const fn complete_setup_proof_ceiling_wire_byte_length(self) -> u64 {
        self.complete_setup_proof_ceiling_wire_byte_length
    }

    pub(crate) const fn maximum_complete_setup_proof_wire_byte_length(self) -> u64 {
        self.maximum_complete_setup_proof_wire_byte_length
    }

    pub(crate) const fn package_referenced_stream_wire_byte_length(self) -> u64 {
        self.package_referenced_stream_wire_byte_length
    }

    pub(crate) const fn package_and_referenced_stream_wire_byte_length(self) -> u64 {
        self.package_and_referenced_stream_wire_byte_length
    }

    pub(crate) const fn complete_setup_canonical_wire_byte_length(self) -> u64 {
        self.complete_setup_canonical_wire_byte_length
    }

    pub(crate) const fn complete_setup_codec_and_proof_ceiling_wire_byte_length(self) -> u64 {
        self.complete_setup_codec_and_proof_ceiling_wire_byte_length
    }
}

pub(crate) fn selected_accepted_setup_package_byte_accounting(
    package: &CanonicalAcceptedSetupPackage,
    consumed_object_byte_lengths: &VerifiedAcceptedSetupConsumedObjectByteLengthCatalog,
    private_vss_mailbox_byte_lengths: &VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog,
    verified_vss_qualification: &VerifiedVssQualificationTerminals,
    action: &SelectedActionProofAccounting,
) -> Result<SelectedAcceptedSetupPackageByteAccounting, SelectedProofAccountingError> {
    private_vss_mailbox_byte_lengths
        .require_matches_verified_qualification(verified_vss_qualification)
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let public_proof_slots = package
        .selected_public_proof_slots()
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    if public_proof_slots.len() != package.ordered_proof_descriptors().len() {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let mut observed_descriptor_counts = BTreeMap::<(u16, Option<u32>), u32>::new();
    let mut package_public_proof_wire_byte_length = 0_u64;
    let mut maximum_package_public_proof_wire_byte_length = 0_u64;
    let mut package_descriptor_codec_expansion_byte_length = 0_u64;
    for (public_proof_slot, proof_descriptor) in public_proof_slots
        .iter()
        .zip(package.ordered_proof_descriptors())
    {
        let schema_identifier = public_proof_slot.application_statement_schema_identifier();
        if !matches!(
            selected_proof_corpus_category(schema_identifier),
            Some(SelectedProofCorpusCategory::Setup | SelectedProofCorpusCategory::Evaluator)
        ) {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        let mut matching_applications =
            action.variant_applications().iter().filter(|application| {
                application.application_statement_schema_identifier() == schema_identifier
                    && application.schedule_position() == public_proof_slot.schedule_position()
                    && (application.top_count().is_none()
                        || application.top_count() == Some(action.top_count()))
            });
        let application = matching_applications
            .next()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        if matching_applications.next().is_some() || application.application_multiplicity() == 0 {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        let individual_proof_byte_ceiling = application
            .proof_byte_length()
            .checked_div(u64::from(application.application_multiplicity()))
            .filter(|ceiling| {
                ceiling.checked_mul(u64::from(application.application_multiplicity()))
                    == Some(application.proof_byte_length())
            })
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let proof_wire_byte_length = proof_descriptor.total_byte_length;
        if proof_wire_byte_length == 0 || proof_wire_byte_length > individual_proof_byte_ceiling {
            return Err(
                SelectedProofAccountingError::GeneratedProofByteLengthExceeded {
                    application_statement_schema_identifier: schema_identifier,
                    schedule_position: application.schedule_position(),
                    top_count: application.top_count(),
                    generated_proof_byte_length: proof_wire_byte_length,
                    proof_byte_ceiling: individual_proof_byte_ceiling,
                },
            );
        }
        let descriptor_count = observed_descriptor_counts
            .entry((schema_identifier, application.schedule_position()))
            .or_default();
        *descriptor_count = descriptor_count
            .checked_add(1)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        if *descriptor_count > application.application_multiplicity() {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        package_public_proof_wire_byte_length = package_public_proof_wire_byte_length
            .checked_add(proof_wire_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        maximum_package_public_proof_wire_byte_length =
            maximum_package_public_proof_wire_byte_length.max(proof_wire_byte_length);
        package_descriptor_codec_expansion_byte_length =
            package_descriptor_codec_expansion_byte_length
                .checked_add(selected_stream_descriptor_codec_expansion_byte_length(
                    proof_wire_byte_length,
                    individual_proof_byte_ceiling,
                )?)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
    }
    let descriptor_lengths = package
        .ordered_proof_descriptor_total_byte_lengths()
        .collect::<Vec<_>>();
    let descriptor_total_byte_length =
        descriptor_lengths
            .iter()
            .try_fold(0_u64, |total, descriptor_byte_length| {
                total
                    .checked_add(*descriptor_byte_length)
                    .ok_or(SelectedProofAccountingError::CountOverflow)
            })?;
    if descriptor_lengths.len() != public_proof_slots.len()
        || descriptor_total_byte_length != package_public_proof_wire_byte_length
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let vss_share_linkage_proof_accounting = selected_generated_descriptor_corpus_accounting(
        consumed_object_byte_lengths.ordered_vss_share_linkage_proof_descriptors(),
        selected_unique_action_application(
            action,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        )?,
    )?;
    let aggregate_threshold_share_proof_accounting =
        selected_generated_descriptor_corpus_accounting(
            consumed_object_byte_lengths.ordered_aggregate_threshold_share_proof_descriptors(),
            selected_unique_action_application(
                action,
                ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            )?,
        )?;
    let complete_setup_proof_wire_byte_length = package_public_proof_wire_byte_length
        .checked_add(vss_share_linkage_proof_accounting.generated_wire_byte_length)
        .and_then(|total| {
            total.checked_add(aggregate_threshold_share_proof_accounting.generated_wire_byte_length)
        })
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let maximum_complete_setup_proof_wire_byte_length =
        maximum_package_public_proof_wire_byte_length
            .max(vss_share_linkage_proof_accounting.maximum_generated_wire_byte_length)
            .max(aggregate_threshold_share_proof_accounting.maximum_generated_wire_byte_length);
    let setup_category = action
        .category(SelectedProofCorpusCategory::Setup)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let evaluator_category = action
        .category(SelectedProofCorpusCategory::Evaluator)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let complete_setup_proof_ceiling_wire_byte_length = setup_category
        .canonical_proof_byte_length()
        .checked_add(evaluator_category.canonical_proof_byte_length())
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let package_public_proof_descriptor_count = u32::try_from(public_proof_slots.len())
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let observed_complete_setup_proof_count = package_public_proof_descriptor_count
        .checked_add(vss_share_linkage_proof_accounting.proof_count)
        .and_then(|count| count.checked_add(aggregate_threshold_share_proof_accounting.proof_count))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let expected_complete_setup_proof_count = setup_category
        .physical_proof_object_count()
        .checked_add(evaluator_category.physical_proof_object_count())
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    if observed_complete_setup_proof_count != expected_complete_setup_proof_count
        || complete_setup_proof_wire_byte_length > complete_setup_proof_ceiling_wire_byte_length
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let evaluator_resource_accounting = selected_evaluator_resource_accounting()
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let final_evaluator_key_store_wire_byte_length =
        package.evaluator_key_store_descriptor().total_byte_length;
    if final_evaluator_key_store_wire_byte_length
        != evaluator_resource_accounting.final_evaluator_key_store_wire_byte_length()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let evaluator_source_material_wire_byte_length = evaluator_resource_accounting
        .source_wire_byte_length_per_participant()
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let evaluator_source_material_resident_byte_length_per_participant =
        evaluator_resource_accounting.source_resident_byte_length_per_participant();
    let final_evaluator_key_store_resident_byte_length =
        evaluator_resource_accounting.final_evaluator_key_store_resident_byte_length();
    let collective_public_key_wire_byte_length =
        package.collective_public_key_descriptor().total_byte_length;
    let package_referenced_stream_wire_byte_length = collective_public_key_wire_byte_length
        .checked_add(final_evaluator_key_store_wire_byte_length)
        .and_then(|total| total.checked_add(package_public_proof_wire_byte_length))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let canonical_package_byte_length = package.canonical_package_byte_length();
    let canonical_package_codec_ceiling_byte_length = canonical_package_byte_length
        .checked_add(package_descriptor_codec_expansion_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let package_and_referenced_stream_wire_byte_length = canonical_package_byte_length
        .checked_add(package_referenced_stream_wire_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let setup_intent_canonical_wire_byte_length = selected_exact_object_corpus_byte_lengths(
        consumed_object_byte_lengths.ordered_setup_intent_canonical_byte_lengths(),
    )?;
    let public_randomness_commitment_canonical_wire_byte_length =
        selected_exact_object_corpus_byte_lengths(
            consumed_object_byte_lengths
                .ordered_public_randomness_commitment_canonical_byte_lengths(),
        )?;
    let public_randomness_reveal_canonical_wire_byte_length =
        selected_exact_object_corpus_byte_lengths(
            consumed_object_byte_lengths.ordered_public_randomness_reveal_canonical_byte_lengths(),
        )?;
    let dealer_public_record_canonical_wire_byte_length =
        selected_exact_object_corpus_byte_lengths(
            consumed_object_byte_lengths.ordered_dealer_public_record_canonical_byte_lengths(),
        )?;
    let private_share_acceptance_canonical_wire_byte_length =
        selected_exact_object_corpus_byte_lengths(
            consumed_object_byte_lengths.ordered_private_share_acceptance_canonical_byte_lengths(),
        )?;
    let private_vss_ciphertext_stream_wire_byte_length =
        private_vss_mailbox_byte_lengths.ciphertext_stream_byte_length();
    let private_vss_signed_envelope_wire_byte_length =
        private_vss_mailbox_byte_lengths.canonical_signed_envelope_byte_length();
    let private_vss_complete_recipient_wire_byte_length =
        private_vss_mailbox_byte_lengths.complete_recipient_private_wire_byte_length();
    let maximum_private_vss_ciphertext_descriptor_byte_length =
        private_vss_mailbox_byte_lengths.maximum_ciphertext_descriptor_byte_length();
    let maximum_private_vss_signed_envelope_byte_length =
        private_vss_mailbox_byte_lengths.maximum_canonical_signed_envelope_byte_length();
    if private_vss_ciphertext_stream_wire_byte_length == 0
        || private_vss_signed_envelope_wire_byte_length == 0
        || private_vss_complete_recipient_wire_byte_length
            != private_vss_ciphertext_stream_wire_byte_length
                .checked_add(private_vss_signed_envelope_wire_byte_length)
                .ok_or(SelectedProofAccountingError::CountOverflow)?
        || private_vss_mailbox_byte_lengths
            .ordered_dealer_upload_byte_lengths()
            .len()
            != usize::from(FOUNDATION_PROFILE.participant_count)
        || private_vss_mailbox_byte_lengths
            .ordered_recipient_download_byte_lengths()
            .len()
            != usize::from(FOUNDATION_PROFILE.participant_count)
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let (dealer_public_record_codec_ceiling_wire_byte_length, maximum_dealer_record_ceiling) =
        selected_object_corpus_codec_ceiling(
            consumed_object_byte_lengths.ordered_dealer_public_record_canonical_byte_lengths(),
            consumed_object_byte_lengths.ordered_vss_share_linkage_proof_descriptors(),
            selected_unique_action_application(
                action,
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            )?,
        )?;
    let (private_share_acceptance_codec_ceiling_wire_byte_length, maximum_share_acceptance_ceiling) =
        selected_object_corpus_codec_ceiling(
            consumed_object_byte_lengths.ordered_private_share_acceptance_canonical_byte_lengths(),
            consumed_object_byte_lengths.ordered_aggregate_threshold_share_proof_descriptors(),
            selected_unique_action_application(
                action,
                ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            )?,
        )?;
    let consumed_setup_object_canonical_wire_byte_length = [
        setup_intent_canonical_wire_byte_length,
        public_randomness_commitment_canonical_wire_byte_length,
        public_randomness_reveal_canonical_wire_byte_length,
        dealer_public_record_canonical_wire_byte_length,
        private_share_acceptance_canonical_wire_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, |total, corpus_byte_length| {
        total
            .checked_add(corpus_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)
    })?;
    let consumed_setup_object_codec_ceiling_wire_byte_length = [
        setup_intent_canonical_wire_byte_length,
        public_randomness_commitment_canonical_wire_byte_length,
        public_randomness_reveal_canonical_wire_byte_length,
        dealer_public_record_codec_ceiling_wire_byte_length,
        private_share_acceptance_codec_ceiling_wire_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, |total, corpus_byte_length| {
        total
            .checked_add(corpus_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)
    })?;
    let maximum_consumed_setup_object_canonical_wire_byte_length = [
        consumed_object_byte_lengths.ordered_setup_intent_canonical_byte_lengths(),
        consumed_object_byte_lengths.ordered_public_randomness_commitment_canonical_byte_lengths(),
        consumed_object_byte_lengths.ordered_public_randomness_reveal_canonical_byte_lengths(),
        consumed_object_byte_lengths.ordered_dealer_public_record_canonical_byte_lengths(),
        consumed_object_byte_lengths.ordered_private_share_acceptance_canonical_byte_lengths(),
    ]
    .into_iter()
    .flat_map(|byte_lengths| byte_lengths.iter().copied())
    .max()
    .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let maximum_consumed_setup_object_codec_ceiling_wire_byte_length = [
        consumed_object_byte_lengths
            .ordered_setup_intent_canonical_byte_lengths()
            .iter()
            .copied()
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?,
        consumed_object_byte_lengths
            .ordered_public_randomness_commitment_canonical_byte_lengths()
            .iter()
            .copied()
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?,
        consumed_object_byte_lengths
            .ordered_public_randomness_reveal_canonical_byte_lengths()
            .iter()
            .copied()
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?,
        maximum_dealer_record_ceiling,
        maximum_share_acceptance_ceiling,
    ]
    .into_iter()
    .max()
    .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let complete_setup_canonical_wire_byte_length =
        consumed_setup_object_canonical_wire_byte_length
            .checked_add(package_and_referenced_stream_wire_byte_length)
            .and_then(|total| total.checked_add(evaluator_source_material_wire_byte_length))
            .and_then(|total| total.checked_add(private_vss_complete_recipient_wire_byte_length))
            .and_then(|total| {
                total.checked_add(vss_share_linkage_proof_accounting.generated_wire_byte_length)
            })
            .and_then(|total| {
                total.checked_add(
                    aggregate_threshold_share_proof_accounting.generated_wire_byte_length,
                )
            })
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let complete_setup_codec_and_proof_ceiling_wire_byte_length =
        canonical_package_codec_ceiling_byte_length
            .checked_add(consumed_setup_object_codec_ceiling_wire_byte_length)
            .and_then(|total| total.checked_add(collective_public_key_wire_byte_length))
            .and_then(|total| total.checked_add(evaluator_source_material_wire_byte_length))
            .and_then(|total| total.checked_add(final_evaluator_key_store_wire_byte_length))
            .and_then(|total| total.checked_add(private_vss_complete_recipient_wire_byte_length))
            .and_then(|total| total.checked_add(complete_setup_proof_ceiling_wire_byte_length))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    if package_and_referenced_stream_wire_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || complete_setup_canonical_wire_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || complete_setup_codec_and_proof_ceiling_wire_byte_length
            > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || complete_setup_canonical_wire_byte_length
            > complete_setup_codec_and_proof_ceiling_wire_byte_length
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    Ok(SelectedAcceptedSetupPackageByteAccounting {
        canonical_package_byte_length,
        canonical_package_codec_ceiling_byte_length,
        ordered_hash_list_carrier_byte_lengths: package.ordered_hash_list_carrier_byte_lengths(),
        setup_intent_canonical_wire_byte_length,
        public_randomness_commitment_canonical_wire_byte_length,
        public_randomness_reveal_canonical_wire_byte_length,
        dealer_public_record_canonical_wire_byte_length,
        dealer_public_record_codec_ceiling_wire_byte_length,
        private_share_acceptance_canonical_wire_byte_length,
        private_share_acceptance_codec_ceiling_wire_byte_length,
        private_vss_ciphertext_stream_wire_byte_length,
        private_vss_signed_envelope_wire_byte_length,
        private_vss_complete_recipient_wire_byte_length,
        maximum_private_vss_ciphertext_descriptor_byte_length,
        maximum_private_vss_signed_envelope_byte_length,
        consumed_setup_object_canonical_wire_byte_length,
        consumed_setup_object_codec_ceiling_wire_byte_length,
        maximum_consumed_setup_object_canonical_wire_byte_length,
        maximum_consumed_setup_object_codec_ceiling_wire_byte_length,
        collective_public_key_wire_byte_length,
        evaluator_source_material_wire_byte_length,
        evaluator_source_material_resident_byte_length_per_participant,
        final_evaluator_key_store_wire_byte_length,
        final_evaluator_key_store_resident_byte_length,
        package_public_proof_descriptor_count,
        package_public_proof_wire_byte_length,
        maximum_package_public_proof_wire_byte_length,
        vss_share_linkage_proof_wire_byte_length: vss_share_linkage_proof_accounting
            .generated_wire_byte_length,
        aggregate_threshold_share_proof_wire_byte_length:
            aggregate_threshold_share_proof_accounting.generated_wire_byte_length,
        complete_setup_proof_wire_byte_length,
        complete_setup_proof_ceiling_wire_byte_length,
        maximum_complete_setup_proof_wire_byte_length,
        package_referenced_stream_wire_byte_length,
        package_and_referenced_stream_wire_byte_length,
        complete_setup_canonical_wire_byte_length,
        complete_setup_codec_and_proof_ceiling_wire_byte_length,
    })
}

#[derive(Clone, Copy)]
struct SelectedGeneratedDescriptorCorpusAccounting {
    proof_count: u32,
    generated_wire_byte_length: u64,
    maximum_generated_wire_byte_length: u64,
}

fn selected_generated_descriptor_corpus_accounting(
    descriptors: &[StreamDescriptor],
    application: &SelectedActionProofVariantAccounting,
) -> Result<SelectedGeneratedDescriptorCorpusAccounting, SelectedProofAccountingError> {
    if descriptors.len()
        != usize::try_from(application.application_multiplicity())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?
        || application.application_multiplicity() == 0
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let individual_proof_byte_ceiling = application
        .proof_byte_length()
        .checked_div(u64::from(application.application_multiplicity()))
        .filter(|ceiling| {
            ceiling.checked_mul(u64::from(application.application_multiplicity()))
                == Some(application.proof_byte_length())
        })
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let mut generated_wire_byte_length = 0_u64;
    let mut maximum_generated_wire_byte_length = 0_u64;
    for descriptor in descriptors {
        let generated_proof_byte_length = descriptor.total_byte_length;
        if generated_proof_byte_length == 0 {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        if generated_proof_byte_length > individual_proof_byte_ceiling {
            return Err(
                SelectedProofAccountingError::GeneratedProofByteLengthExceeded {
                    application_statement_schema_identifier: application
                        .application_statement_schema_identifier(),
                    schedule_position: application.schedule_position(),
                    top_count: application.top_count(),
                    generated_proof_byte_length,
                    proof_byte_ceiling: individual_proof_byte_ceiling,
                },
            );
        }
        generated_wire_byte_length = generated_wire_byte_length
            .checked_add(generated_proof_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        maximum_generated_wire_byte_length =
            maximum_generated_wire_byte_length.max(generated_proof_byte_length);
    }
    Ok(SelectedGeneratedDescriptorCorpusAccounting {
        proof_count: application.application_multiplicity(),
        generated_wire_byte_length,
        maximum_generated_wire_byte_length,
    })
}

fn selected_exact_object_corpus_byte_lengths(
    ordered_canonical_byte_lengths: &[u64],
) -> Result<u64, SelectedProofAccountingError> {
    if ordered_canonical_byte_lengths.len() != usize::from(FOUNDATION_PROFILE.participant_count)
        || ordered_canonical_byte_lengths.contains(&0)
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    ordered_canonical_byte_lengths
        .iter()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(*byte_length)
                .ok_or(SelectedProofAccountingError::CountOverflow)
        })
}

fn selected_object_corpus_codec_ceiling(
    generated_carrier_byte_lengths: &[u64],
    proof_descriptors: &[StreamDescriptor],
    application: &SelectedActionProofVariantAccounting,
) -> Result<(u64, u64), SelectedProofAccountingError> {
    if generated_carrier_byte_lengths.len() != proof_descriptors.len()
        || proof_descriptors.len()
            != usize::try_from(application.application_multiplicity())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
        || application.application_multiplicity() == 0
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let individual_proof_byte_ceiling = application
        .proof_byte_length()
        .checked_div(u64::from(application.application_multiplicity()))
        .filter(|ceiling| {
            ceiling.checked_mul(u64::from(application.application_multiplicity()))
                == Some(application.proof_byte_length())
        })
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    generated_carrier_byte_lengths
        .iter()
        .copied()
        .zip(proof_descriptors)
        .try_fold((0_u64, 0_u64), |(total, maximum), (carrier, descriptor)| {
            if carrier == 0 {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            let carrier_ceiling = carrier
                .checked_add(selected_stream_descriptor_codec_expansion_byte_length(
                    descriptor.total_byte_length,
                    individual_proof_byte_ceiling,
                )?)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            Ok((
                total
                    .checked_add(carrier_ceiling)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
                maximum.max(carrier_ceiling),
            ))
        })
}

fn selected_stream_descriptor_codec_expansion_byte_length(
    generated_stream_byte_length: u64,
    stream_byte_ceiling: u64,
) -> Result<u64, SelectedProofAccountingError> {
    if generated_stream_byte_length == 0 || stream_byte_ceiling < generated_stream_byte_length {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    selected_stream_descriptor_canonical_byte_length(stream_byte_ceiling)?
        .checked_sub(selected_stream_descriptor_canonical_byte_length(
            generated_stream_byte_length,
        )?)
        .ok_or(SelectedProofAccountingError::InvalidProfile)
}

fn selected_stream_descriptor_canonical_byte_length(
    stream_byte_length: u64,
) -> Result<u64, SelectedProofAccountingError> {
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let chunk_rounding_byte_length = chunk_byte_length
        .checked_sub(1)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let chunk_count = stream_byte_length
        .checked_add(chunk_rounding_byte_length)
        .and_then(|length| length.checked_div(chunk_byte_length))
        .filter(|count| *count != 0)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let descriptor = StreamDescriptor::new(
        stream_byte_length,
        vec![
            Hash512::from_bytes([0; Hash512::BYTE_LENGTH]);
            usize::try_from(chunk_count)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
        ],
        Hash512::from_bytes([0; Hash512::BYTE_LENGTH]),
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    u64::try_from(
        descriptor
            .encode()
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
            .len(),
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)
}

/// Exact generated bytes for the board-authenticated ballot carriers and the
/// ciphertext and proof streams positively joined to their verified outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedGeneratedBallotCorpusByteAccounting {
    accepted_ballot_count: u32,
    ballot_package_carrier_wire_byte_length: u64,
    ballot_package_carrier_codec_ceiling_wire_byte_length: u64,
    ciphertext_wire_byte_length: u64,
    generated_proof_wire_byte_length: u64,
    non_proof_wire_byte_length: u64,
    non_proof_codec_ceiling_wire_byte_length: u64,
    generated_complete_ballot_wire_byte_length: u64,
    proof_ceiling_wire_byte_length: u64,
    complete_ballot_codec_and_proof_ceiling_wire_byte_length: u64,
    retained_decoded_ciphertext_residue_byte_length: u64,
    generation_resident_peak_byte_length: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
}

impl SelectedGeneratedBallotCorpusByteAccounting {
    pub(crate) const fn accepted_ballot_count(self) -> u32 {
        self.accepted_ballot_count
    }

    pub(crate) const fn ballot_package_carrier_wire_byte_length(self) -> u64 {
        self.ballot_package_carrier_wire_byte_length
    }

    pub(crate) const fn ballot_package_carrier_codec_ceiling_wire_byte_length(self) -> u64 {
        self.ballot_package_carrier_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn ciphertext_wire_byte_length(self) -> u64 {
        self.ciphertext_wire_byte_length
    }

    pub(crate) const fn generated_proof_wire_byte_length(self) -> u64 {
        self.generated_proof_wire_byte_length
    }

    pub(crate) const fn non_proof_wire_byte_length(self) -> u64 {
        self.non_proof_wire_byte_length
    }

    pub(crate) const fn non_proof_codec_ceiling_wire_byte_length(self) -> u64 {
        self.non_proof_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn generated_complete_ballot_wire_byte_length(self) -> u64 {
        self.generated_complete_ballot_wire_byte_length
    }

    pub(crate) const fn proof_ceiling_wire_byte_length(self) -> u64 {
        self.proof_ceiling_wire_byte_length
    }

    pub(crate) const fn complete_ballot_codec_and_proof_ceiling_wire_byte_length(self) -> u64 {
        self.complete_ballot_codec_and_proof_ceiling_wire_byte_length
    }

    pub(crate) const fn retained_decoded_ciphertext_residue_byte_length(self) -> u64 {
        self.retained_decoded_ciphertext_residue_byte_length
    }

    pub(crate) const fn generation_resident_peak_byte_length(self) -> u64 {
        self.generation_resident_peak_byte_length
    }

    pub(crate) const fn maximum_boundary_copied_buffer_byte_length(self) -> u64 {
        self.maximum_boundary_copied_buffer_byte_length
    }
}

pub(crate) fn selected_generated_ballot_corpus_byte_accounting(
    verified_ballot_sources: &[VerifiedBoardApplicationSource],
    verified_ballot_outputs: &[VerifiedBallotValidityOutput],
    action: &SelectedActionProofAccounting,
) -> Result<SelectedGeneratedBallotCorpusByteAccounting, SelectedProofAccountingError> {
    let ballot_application = selected_unique_action_application(
        action,
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    )?;
    if ballot_application.application_multiplicity()
        != SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION
        || verified_ballot_sources.len()
            != usize::try_from(ballot_application.application_multiplicity())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
        || verified_ballot_outputs.len() != verified_ballot_sources.len()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let ballot_category = action
        .category(SelectedProofCorpusCategory::Ballot)
        .filter(|category| {
            category.physical_proof_object_count() == ballot_application.application_multiplicity()
        })
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let individual_proof_byte_ceiling = ballot_application
        .proof_byte_length()
        .checked_div(u64::from(ballot_application.application_multiplicity()))
        .filter(|ceiling| {
            ceiling.checked_mul(u64::from(ballot_application.application_multiplicity()))
                == Some(ballot_application.proof_byte_length())
        })
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let carrier_buffers = selected_ballot_validity_carrier_buffer_accounting()
        .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;

    let mut outputs_by_object_hash = BTreeMap::new();
    for output in verified_ballot_outputs {
        if outputs_by_object_hash
            .insert(output.ballot_package_object_hash(), output)
            .is_some()
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
    }

    let mut ballot_package_carrier_wire_byte_length = 0_u64;
    let mut ballot_package_carrier_codec_ceiling_wire_byte_length = 0_u64;
    let mut ciphertext_wire_byte_length = 0_u64;
    let mut generated_proof_wire_byte_length = 0_u64;
    let mut maximum_ballot_package_carrier_byte_length = 0_u64;
    for source in verified_ballot_sources {
        let object_hash = source.object_hash().into_bytes();
        let output = outputs_by_object_hash
            .remove(&object_hash)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let payload = source
            .ballot_package_payload()
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
        if source.object_type() != FoundationObjectType::BallotPackage
            || source.suite_identifier().into_bytes() != output.suite_identifier()
            || source.ceremony_context_hash().into_bytes() != output.ceremony_context_hash()
            || source.action_context_hash().into_bytes() != output.action_context_hash()
            || source.roster_hash().into_bytes() != output.roster_hash()
            || source
                .producer_participant_identity()
                .map(|identity| identity.into_bytes())
                != Some(output.producer_identity())
            || source.producer_roster_position() != Some(output.producer_roster_position())
            || source.producer_sequence() != output.producer_sequence()
            || payload.ciphertext_descriptor() != output.ciphertext_descriptor()
            || payload.ciphertext_descriptor().total_byte_length
                != carrier_buffers.canonical_ciphertext_byte_length()
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        let carrier_byte_length = u64::try_from(source.canonical_carrier_bytes().len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let proof_byte_length = payload.proof_descriptor().total_byte_length;
        if carrier_byte_length == 0 {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        if proof_byte_length > individual_proof_byte_ceiling {
            return Err(
                SelectedProofAccountingError::GeneratedProofByteLengthExceeded {
                    application_statement_schema_identifier:
                        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                    schedule_position: ballot_application.schedule_position(),
                    top_count: ballot_application.top_count(),
                    generated_proof_byte_length: proof_byte_length,
                    proof_byte_ceiling: individual_proof_byte_ceiling,
                },
            );
        }
        ballot_package_carrier_wire_byte_length = ballot_package_carrier_wire_byte_length
            .checked_add(carrier_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let carrier_codec_ceiling_byte_length = carrier_byte_length
            .checked_add(selected_stream_descriptor_codec_expansion_byte_length(
                proof_byte_length,
                individual_proof_byte_ceiling,
            )?)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        ballot_package_carrier_codec_ceiling_wire_byte_length =
            ballot_package_carrier_codec_ceiling_wire_byte_length
                .checked_add(carrier_codec_ceiling_byte_length)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        ciphertext_wire_byte_length = ciphertext_wire_byte_length
            .checked_add(payload.ciphertext_descriptor().total_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        generated_proof_wire_byte_length = generated_proof_wire_byte_length
            .checked_add(proof_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        maximum_ballot_package_carrier_byte_length =
            maximum_ballot_package_carrier_byte_length.max(carrier_codec_ceiling_byte_length);
    }
    if !outputs_by_object_hash.is_empty() {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let non_proof_wire_byte_length = ballot_package_carrier_wire_byte_length
        .checked_add(ciphertext_wire_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let generated_complete_ballot_wire_byte_length = non_proof_wire_byte_length
        .checked_add(generated_proof_wire_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let non_proof_codec_ceiling_wire_byte_length =
        ballot_package_carrier_codec_ceiling_wire_byte_length
            .checked_add(ciphertext_wire_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let proof_ceiling_wire_byte_length = ballot_category.canonical_proof_byte_length();
    let complete_ballot_codec_and_proof_ceiling_wire_byte_length =
        non_proof_codec_ceiling_wire_byte_length
            .checked_add(proof_ceiling_wire_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let retained_decoded_ciphertext_residue_byte_length = carrier_buffers
        .decoded_ciphertext_residue_byte_length()
        .checked_mul(u64::from(ballot_application.application_multiplicity()))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let previously_retained_ciphertext_residue_byte_length = carrier_buffers
        .decoded_ciphertext_residue_byte_length()
        .checked_mul(u64::from(
            ballot_application
                .application_multiplicity()
                .checked_sub(1)
                .ok_or(SelectedProofAccountingError::InvalidProfile)?,
        ))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let generation_resident_peak_byte_length = previously_retained_ciphertext_residue_byte_length
        .checked_add(ballot_category.generation_resident_peak_byte_length())
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let maximum_boundary_copied_buffer_byte_length = maximum_ballot_package_carrier_byte_length
        .max(carrier_buffers.maximum_boundary_copied_buffer_byte_length())
        .max(ballot_category.maximum_copied_buffer_byte_length());
    if generated_proof_wire_byte_length > proof_ceiling_wire_byte_length
        || generated_complete_ballot_wire_byte_length
            > complete_ballot_codec_and_proof_ceiling_wire_byte_length
        || complete_ballot_codec_and_proof_ceiling_wire_byte_length
            > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || generation_resident_peak_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || maximum_boundary_copied_buffer_byte_length
            > u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    Ok(SelectedGeneratedBallotCorpusByteAccounting {
        accepted_ballot_count: ballot_application.application_multiplicity(),
        ballot_package_carrier_wire_byte_length,
        ballot_package_carrier_codec_ceiling_wire_byte_length,
        ciphertext_wire_byte_length,
        generated_proof_wire_byte_length,
        non_proof_wire_byte_length,
        non_proof_codec_ceiling_wire_byte_length,
        generated_complete_ballot_wire_byte_length,
        proof_ceiling_wire_byte_length,
        complete_ballot_codec_and_proof_ceiling_wire_byte_length,
        retained_decoded_ciphertext_residue_byte_length,
        generation_resident_peak_byte_length,
        maximum_boundary_copied_buffer_byte_length,
    })
}

fn selected_unique_action_application(
    action: &SelectedActionProofAccounting,
    application_statement_schema_identifier: u16,
) -> Result<&SelectedActionProofVariantAccounting, SelectedProofAccountingError> {
    let mut matching_applications = action.variant_applications().iter().filter(|application| {
        application.application_statement_schema_identifier()
            == application_statement_schema_identifier
    });
    let application = matching_applications
        .next()
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    if matching_applications.next().is_some() || application.application_multiplicity() == 0 {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    Ok(application)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedParticipantStateCarrierUploadByteAccounting {
    participant_identity: ParticipantIdentity,
    subject_intent_carrier_byte_length: u64,
    witness_vote_carrier_byte_length: u64,
    complete_carrier_upload_byte_length: u64,
}

impl SelectedParticipantStateCarrierUploadByteAccounting {
    pub(crate) const fn participant_identity(self) -> ParticipantIdentity {
        self.participant_identity
    }

    pub(crate) const fn subject_intent_carrier_byte_length(self) -> u64 {
        self.subject_intent_carrier_byte_length
    }

    pub(crate) const fn witness_vote_carrier_byte_length(self) -> u64 {
        self.witness_vote_carrier_byte_length
    }

    pub(crate) const fn complete_carrier_upload_byte_length(self) -> u64 {
        self.complete_carrier_upload_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedStateOutputCarrierCorpusByteAccounting {
    state_output_count: u32,
    subject_intent_carrier_count: u32,
    witness_vote_carrier_count: u32,
    canonical_state_certificate_count: u32,
    subject_intent_carrier_wire_byte_length: u64,
    witness_vote_carrier_wire_byte_length: u64,
    constituent_carrier_wire_byte_length: u64,
    canonical_state_certificate_wire_byte_length: u64,
    state_certificate_framing_wire_byte_length: u64,
    canonical_verifier_transport_wire_byte_length: u64,
    maximum_constituent_carrier_wire_byte_length: u64,
    maximum_canonical_state_certificate_wire_byte_length: u64,
    participant_uploads: Vec<SelectedParticipantStateCarrierUploadByteAccounting>,
}

impl SelectedStateOutputCarrierCorpusByteAccounting {
    pub(crate) const fn state_output_count(&self) -> u32 {
        self.state_output_count
    }

    pub(crate) const fn subject_intent_carrier_count(&self) -> u32 {
        self.subject_intent_carrier_count
    }

    pub(crate) const fn witness_vote_carrier_count(&self) -> u32 {
        self.witness_vote_carrier_count
    }

    pub(crate) const fn canonical_state_certificate_count(&self) -> u32 {
        self.canonical_state_certificate_count
    }

    pub(crate) const fn subject_intent_carrier_wire_byte_length(&self) -> u64 {
        self.subject_intent_carrier_wire_byte_length
    }

    pub(crate) const fn witness_vote_carrier_wire_byte_length(&self) -> u64 {
        self.witness_vote_carrier_wire_byte_length
    }

    pub(crate) const fn constituent_carrier_wire_byte_length(&self) -> u64 {
        self.constituent_carrier_wire_byte_length
    }

    pub(crate) const fn canonical_state_certificate_wire_byte_length(&self) -> u64 {
        self.canonical_state_certificate_wire_byte_length
    }

    pub(crate) const fn state_certificate_framing_wire_byte_length(&self) -> u64 {
        self.state_certificate_framing_wire_byte_length
    }

    pub(crate) const fn canonical_verifier_transport_wire_byte_length(&self) -> u64 {
        self.canonical_verifier_transport_wire_byte_length
    }

    pub(crate) const fn maximum_constituent_carrier_wire_byte_length(&self) -> u64 {
        self.maximum_constituent_carrier_wire_byte_length
    }

    pub(crate) const fn maximum_canonical_state_certificate_wire_byte_length(&self) -> u64 {
        self.maximum_canonical_state_certificate_wire_byte_length
    }

    pub(crate) fn participant_uploads(
        &self,
    ) -> &[SelectedParticipantStateCarrierUploadByteAccounting] {
        &self.participant_uploads
    }
}

#[derive(Default)]
struct StateCarrierCorpusAccumulator {
    state_output_count: u32,
    subject_intent_carrier_count: u32,
    witness_vote_carrier_count: u32,
    canonical_state_certificate_count: u32,
    subject_intent_carrier_wire_byte_length: u64,
    witness_vote_carrier_wire_byte_length: u64,
    canonical_state_certificate_wire_byte_length: u64,
    maximum_constituent_carrier_wire_byte_length: u64,
    maximum_canonical_state_certificate_wire_byte_length: u64,
    participant_uploads: BTreeMap<ParticipantIdentity, (u64, u64)>,
}

pub(crate) fn selected_state_output_carrier_corpus_byte_accounting(
    verified_outputs: &[VerifiedStateOutput],
) -> Result<SelectedStateOutputCarrierCorpusByteAccounting, SelectedProofAccountingError> {
    if verified_outputs.is_empty()
        || verified_outputs.len() > usize::from(FOUNDATION_PROFILE.participant_count)
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let mut accounting = StateCarrierCorpusAccumulator::default();
    for verified_output in verified_outputs {
        accounting.state_output_count = accounting
            .state_output_count
            .checked_add(1)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let subject_participant_id = verified_output.subject_participant_id();
        let carrier_lengths = verified_output.consumed_carrier_byte_lengths();
        let reservation = carrier_lengths.reservation();
        accumulate_state_carrier_flow(
            &mut accounting,
            subject_participant_id,
            reservation.canonical_intent_carrier_byte_length(),
            reservation.canonical_certificate_byte_length(),
            reservation
                .witness_carriers()
                .map(|witness| {
                    (
                        witness.witness_participant_id(),
                        witness.canonical_carrier_byte_length(),
                    )
                })
                .collect::<Vec<_>>(),
        )?;
        accumulate_state_carrier_flow(
            &mut accounting,
            subject_participant_id,
            carrier_lengths.canonical_output_intent_carrier_byte_length(),
            carrier_lengths.canonical_output_certificate_byte_length(),
            carrier_lengths
                .output_witness_carriers()
                .map(|witness| {
                    (
                        witness.witness_participant_id(),
                        witness.canonical_carrier_byte_length(),
                    )
                })
                .collect::<Vec<_>>(),
        )?;
    }
    finish_state_carrier_corpus_accounting(accounting)
}

fn accumulate_state_carrier_flow(
    accounting: &mut StateCarrierCorpusAccumulator,
    subject_participant_id: ParticipantIdentity,
    canonical_intent_carrier_byte_length: u64,
    canonical_state_certificate_byte_length: u64,
    ordered_witness_carriers: Vec<(ParticipantIdentity, u64)>,
) -> Result<(), SelectedProofAccountingError> {
    if canonical_intent_carrier_byte_length == 0
        || canonical_state_certificate_byte_length == 0
        || ordered_witness_carriers.len() != usize::from(FOUNDATION_PROFILE.state_witness_quorum)
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    accounting.subject_intent_carrier_count = accounting
        .subject_intent_carrier_count
        .checked_add(1)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    accounting.canonical_state_certificate_count = accounting
        .canonical_state_certificate_count
        .checked_add(1)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    accounting.subject_intent_carrier_wire_byte_length = accounting
        .subject_intent_carrier_wire_byte_length
        .checked_add(canonical_intent_carrier_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    accounting.canonical_state_certificate_wire_byte_length = accounting
        .canonical_state_certificate_wire_byte_length
        .checked_add(canonical_state_certificate_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    accounting.maximum_constituent_carrier_wire_byte_length = accounting
        .maximum_constituent_carrier_wire_byte_length
        .max(canonical_intent_carrier_byte_length);
    accounting.maximum_canonical_state_certificate_wire_byte_length = accounting
        .maximum_canonical_state_certificate_wire_byte_length
        .max(canonical_state_certificate_byte_length);
    let subject_upload = accounting
        .participant_uploads
        .entry(subject_participant_id)
        .or_default();
    subject_upload.0 = subject_upload
        .0
        .checked_add(canonical_intent_carrier_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;

    for (witness_participant_id, canonical_witness_carrier_byte_length) in ordered_witness_carriers
    {
        if canonical_witness_carrier_byte_length == 0
            || witness_participant_id == subject_participant_id
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        accounting.witness_vote_carrier_count = accounting
            .witness_vote_carrier_count
            .checked_add(1)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        accounting.witness_vote_carrier_wire_byte_length = accounting
            .witness_vote_carrier_wire_byte_length
            .checked_add(canonical_witness_carrier_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        accounting.maximum_constituent_carrier_wire_byte_length = accounting
            .maximum_constituent_carrier_wire_byte_length
            .max(canonical_witness_carrier_byte_length);
        let witness_upload = accounting
            .participant_uploads
            .entry(witness_participant_id)
            .or_default();
        witness_upload.1 = witness_upload
            .1
            .checked_add(canonical_witness_carrier_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    }
    Ok(())
}

fn finish_state_carrier_corpus_accounting(
    accounting: StateCarrierCorpusAccumulator,
) -> Result<SelectedStateOutputCarrierCorpusByteAccounting, SelectedProofAccountingError> {
    let expected_intent_count = accounting
        .state_output_count
        .checked_mul(2)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let expected_witness_count = expected_intent_count
        .checked_mul(u32::from(FOUNDATION_PROFILE.state_witness_quorum))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    if accounting.subject_intent_carrier_count != expected_intent_count
        || accounting.canonical_state_certificate_count != expected_intent_count
        || accounting.witness_vote_carrier_count != expected_witness_count
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let constituent_carrier_wire_byte_length = accounting
        .subject_intent_carrier_wire_byte_length
        .checked_add(accounting.witness_vote_carrier_wire_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let state_certificate_framing_wire_byte_length = accounting
        .canonical_state_certificate_wire_byte_length
        .checked_sub(accounting.witness_vote_carrier_wire_byte_length)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let canonical_verifier_transport_wire_byte_length = accounting
        .subject_intent_carrier_wire_byte_length
        .checked_add(accounting.canonical_state_certificate_wire_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let participant_uploads = accounting
        .participant_uploads
        .into_iter()
        .map(
            |(
                participant_identity,
                (subject_intent_carrier_byte_length, witness_vote_carrier_byte_length),
            )| {
                let complete_carrier_upload_byte_length = subject_intent_carrier_byte_length
                    .checked_add(witness_vote_carrier_byte_length)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?;
                Ok(SelectedParticipantStateCarrierUploadByteAccounting {
                    participant_identity,
                    subject_intent_carrier_byte_length,
                    witness_vote_carrier_byte_length,
                    complete_carrier_upload_byte_length,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SelectedStateOutputCarrierCorpusByteAccounting {
        state_output_count: accounting.state_output_count,
        subject_intent_carrier_count: accounting.subject_intent_carrier_count,
        witness_vote_carrier_count: accounting.witness_vote_carrier_count,
        canonical_state_certificate_count: accounting.canonical_state_certificate_count,
        subject_intent_carrier_wire_byte_length: accounting.subject_intent_carrier_wire_byte_length,
        witness_vote_carrier_wire_byte_length: accounting.witness_vote_carrier_wire_byte_length,
        constituent_carrier_wire_byte_length,
        canonical_state_certificate_wire_byte_length: accounting
            .canonical_state_certificate_wire_byte_length,
        state_certificate_framing_wire_byte_length,
        canonical_verifier_transport_wire_byte_length,
        maximum_constituent_carrier_wire_byte_length: accounting
            .maximum_constituent_carrier_wire_byte_length,
        maximum_canonical_state_certificate_wire_byte_length: accounting
            .maximum_canonical_state_certificate_wire_byte_length,
        participant_uploads,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedParticipantFinalityCarrierUploadByteAccounting {
    participant_identity: ParticipantIdentity,
    finality_carrier_byte_length: u64,
    state_carrier_byte_length: u64,
    complete_carrier_upload_byte_length: u64,
}

impl SelectedParticipantFinalityCarrierUploadByteAccounting {
    pub(crate) const fn participant_identity(self) -> ParticipantIdentity {
        self.participant_identity
    }

    pub(crate) const fn finality_carrier_byte_length(self) -> u64 {
        self.finality_carrier_byte_length
    }

    pub(crate) const fn state_carrier_byte_length(self) -> u64 {
        self.state_carrier_byte_length
    }

    pub(crate) const fn complete_carrier_upload_byte_length(self) -> u64 {
        self.complete_carrier_upload_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedFinalityCarrierCorpusByteAccounting {
    signer_count: u32,
    finality_carrier_wire_byte_length: u64,
    state_carriers: SelectedStateOutputCarrierCorpusByteAccounting,
    constituent_carrier_count: u32,
    constituent_carrier_wire_byte_length: u64,
    canonical_finality_certificate_wire_byte_length: u64,
    finality_certificate_framing_wire_byte_length: u64,
    maximum_constituent_carrier_wire_byte_length: u64,
    participant_uploads: Vec<SelectedParticipantFinalityCarrierUploadByteAccounting>,
}

impl SelectedFinalityCarrierCorpusByteAccounting {
    pub(crate) const fn signer_count(&self) -> u32 {
        self.signer_count
    }

    pub(crate) const fn finality_carrier_wire_byte_length(&self) -> u64 {
        self.finality_carrier_wire_byte_length
    }

    pub(crate) const fn state_carriers(&self) -> &SelectedStateOutputCarrierCorpusByteAccounting {
        &self.state_carriers
    }

    pub(crate) const fn constituent_carrier_count(&self) -> u32 {
        self.constituent_carrier_count
    }

    pub(crate) const fn constituent_carrier_wire_byte_length(&self) -> u64 {
        self.constituent_carrier_wire_byte_length
    }

    pub(crate) const fn canonical_finality_certificate_wire_byte_length(&self) -> u64 {
        self.canonical_finality_certificate_wire_byte_length
    }

    pub(crate) const fn finality_certificate_framing_wire_byte_length(&self) -> u64 {
        self.finality_certificate_framing_wire_byte_length
    }

    pub(crate) const fn maximum_constituent_carrier_wire_byte_length(&self) -> u64 {
        self.maximum_constituent_carrier_wire_byte_length
    }

    pub(crate) fn participant_uploads(
        &self,
    ) -> &[SelectedParticipantFinalityCarrierUploadByteAccounting] {
        &self.participant_uploads
    }
}

pub(crate) fn selected_finality_carrier_corpus_byte_accounting(
    verified_finality: &VerifiedFinality,
) -> Result<SelectedFinalityCarrierCorpusByteAccounting, SelectedProofAccountingError> {
    let state_carriers =
        selected_state_output_carrier_corpus_byte_accounting(verified_finality.state_outputs())?;
    let finality_carriers = verified_finality.consumed_carrier_byte_lengths();
    let signer_count = u32::try_from(finality_carriers.ordered_signers().len())
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    if signer_count != u32::from(FOUNDATION_PROFILE.finality_quorum)
        || state_carriers.state_output_count() != signer_count
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let mut participant_uploads = state_carriers
        .participant_uploads()
        .iter()
        .map(|upload| {
            (
                upload.participant_identity(),
                (0_u64, upload.complete_carrier_upload_byte_length()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut finality_carrier_wire_byte_length = 0_u64;
    let mut maximum_constituent_carrier_wire_byte_length =
        state_carriers.maximum_constituent_carrier_wire_byte_length();
    for signer in finality_carriers.ordered_signers() {
        let canonical_finality_carrier_byte_length =
            signer.canonical_finality_carrier_byte_length();
        finality_carrier_wire_byte_length = finality_carrier_wire_byte_length
            .checked_add(canonical_finality_carrier_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        maximum_constituent_carrier_wire_byte_length = maximum_constituent_carrier_wire_byte_length
            .max(canonical_finality_carrier_byte_length);
        let upload = participant_uploads
            .entry(signer.signer_participant_id())
            .or_default();
        upload.0 = upload
            .0
            .checked_add(canonical_finality_carrier_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    }
    let constituent_carrier_count = signer_count
        .checked_add(state_carriers.subject_intent_carrier_count())
        .and_then(|count| count.checked_add(state_carriers.witness_vote_carrier_count()))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let constituent_carrier_wire_byte_length = finality_carrier_wire_byte_length
        .checked_add(state_carriers.constituent_carrier_wire_byte_length())
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let canonical_finality_certificate_wire_byte_length =
        finality_carriers.canonical_certificate_byte_length();
    let finality_certificate_framing_wire_byte_length =
        canonical_finality_certificate_wire_byte_length
            .checked_sub(constituent_carrier_wire_byte_length)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let participant_uploads = participant_uploads
        .into_iter()
        .map(
            |(participant_identity, (finality_carrier_byte_length, state_carrier_byte_length))| {
                let complete_carrier_upload_byte_length = finality_carrier_byte_length
                    .checked_add(state_carrier_byte_length)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?;
                Ok(SelectedParticipantFinalityCarrierUploadByteAccounting {
                    participant_identity,
                    finality_carrier_byte_length,
                    state_carrier_byte_length,
                    complete_carrier_upload_byte_length,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SelectedFinalityCarrierCorpusByteAccounting {
        signer_count,
        finality_carrier_wire_byte_length,
        state_carriers,
        constituent_carrier_count,
        constituent_carrier_wire_byte_length,
        canonical_finality_certificate_wire_byte_length,
        finality_certificate_framing_wire_byte_length,
        maximum_constituent_carrier_wire_byte_length,
        participant_uploads,
    })
}

/// Exact generated target-release bundle bytes, separated so the proof stream
/// can be reconciled with the proof corpus without counting it twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedGeneratedTargetReleaseByteAccounting {
    release_bundle_count: u32,
    canonical_bundle_wire_byte_length: u64,
    signed_carrier_codec_ceiling_wire_byte_length: u64,
    non_proof_wire_byte_length: u64,
    non_proof_codec_ceiling_wire_byte_length: u64,
    partial_decryption_wire_byte_length: u64,
    proof_wire_byte_length: u64,
    proof_ceiling_wire_byte_length: u64,
    complete_target_codec_and_proof_ceiling_wire_byte_length: u64,
    verification_decoded_residue_byte_length: u64,
    generation_resident_peak_byte_length: u64,
    maximum_non_proof_boundary_copied_buffer_byte_length: u64,
    state_carriers: SelectedStateOutputCarrierCorpusByteAccounting,
    complete_target_with_state_transport_wire_byte_length: u64,
}

impl SelectedGeneratedTargetReleaseByteAccounting {
    pub(crate) const fn release_bundle_count(&self) -> u32 {
        self.release_bundle_count
    }

    pub(crate) const fn canonical_bundle_wire_byte_length(&self) -> u64 {
        self.canonical_bundle_wire_byte_length
    }

    pub(crate) const fn signed_carrier_codec_ceiling_wire_byte_length(&self) -> u64 {
        self.signed_carrier_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn non_proof_wire_byte_length(&self) -> u64 {
        self.non_proof_wire_byte_length
    }

    pub(crate) const fn non_proof_codec_ceiling_wire_byte_length(&self) -> u64 {
        self.non_proof_codec_ceiling_wire_byte_length
    }

    pub(crate) const fn partial_decryption_wire_byte_length(&self) -> u64 {
        self.partial_decryption_wire_byte_length
    }

    pub(crate) const fn proof_wire_byte_length(&self) -> u64 {
        self.proof_wire_byte_length
    }

    pub(crate) const fn proof_ceiling_wire_byte_length(&self) -> u64 {
        self.proof_ceiling_wire_byte_length
    }

    pub(crate) const fn complete_target_codec_and_proof_ceiling_wire_byte_length(&self) -> u64 {
        self.complete_target_codec_and_proof_ceiling_wire_byte_length
    }

    pub(crate) const fn verification_decoded_residue_byte_length(&self) -> u64 {
        self.verification_decoded_residue_byte_length
    }

    pub(crate) const fn generation_resident_peak_byte_length(&self) -> u64 {
        self.generation_resident_peak_byte_length
    }

    pub(crate) const fn maximum_non_proof_boundary_copied_buffer_byte_length(&self) -> u64 {
        self.maximum_non_proof_boundary_copied_buffer_byte_length
    }

    pub(crate) const fn state_carriers(&self) -> &SelectedStateOutputCarrierCorpusByteAccounting {
        &self.state_carriers
    }

    pub(crate) const fn complete_target_with_state_transport_wire_byte_length(&self) -> u64 {
        self.complete_target_with_state_transport_wire_byte_length
    }
}

pub(crate) fn selected_generated_target_release_byte_accounting(
    verified_outputs: &[VerifiedStateOutput],
    action: &SelectedActionProofAccounting,
) -> Result<SelectedGeneratedTargetReleaseByteAccounting, SelectedProofAccountingError> {
    let target_application = selected_unique_action_application(
        action,
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    )?;
    if verified_outputs.len()
        != usize::try_from(target_application.application_multiplicity())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let individual_proof_byte_ceiling = target_application
        .proof_byte_length()
        .checked_div(u64::from(target_application.application_multiplicity()))
        .filter(|ceiling| {
            ceiling.checked_mul(u64::from(target_application.application_multiplicity()))
                == Some(target_application.proof_byte_length())
        })
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let stream_buffers = selected_target_release_stream_buffer_accounting()?;
    let target_category = action
        .category(SelectedProofCorpusCategory::TargetRelease)
        .filter(|category| {
            category.physical_proof_object_count() == target_application.application_multiplicity()
        })
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let state_carriers = selected_state_output_carrier_corpus_byte_accounting(verified_outputs)?;

    let mut canonical_bundle_wire_byte_length = 0_u64;
    let mut signed_carrier_codec_ceiling_wire_byte_length = 0_u64;
    let mut non_proof_wire_byte_length = 0_u64;
    let mut non_proof_codec_ceiling_wire_byte_length = 0_u64;
    let mut partial_decryption_wire_byte_length = 0_u64;
    let mut proof_wire_byte_length = 0_u64;
    let mut maximum_non_proof_boundary_copied_buffer_byte_length = 0_u64;
    for verified_output in verified_outputs {
        if verified_output.capability_kind()
            != crate::foundation::StateCapabilityKind::TargetRelease
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        let bundle = verified_output
            .target_release_output_bundle()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let byte_lengths = bundle
            .byte_lengths()
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
        if byte_lengths.target_identifier() != stream_buffers.canonical_role_stream_byte_length()
            || byte_lengths.target_order() != stream_buffers.canonical_role_stream_byte_length()
            || byte_lengths
                .target_identifier()
                .checked_add(byte_lengths.target_order())
                != Some(stream_buffers.canonical_pair_wire_byte_length())
            || byte_lengths.malicious_share_proof() == 0
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        if byte_lengths.malicious_share_proof() > individual_proof_byte_ceiling {
            return Err(
                SelectedProofAccountingError::GeneratedProofByteLengthExceeded {
                    application_statement_schema_identifier:
                        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
                    schedule_position: target_application.schedule_position(),
                    top_count: target_application.top_count(),
                    generated_proof_byte_length: byte_lengths.malicious_share_proof(),
                    proof_byte_ceiling: individual_proof_byte_ceiling,
                },
            );
        }
        let bundle_non_proof_wire_byte_length = byte_lengths
            .total()
            .checked_sub(byte_lengths.malicious_share_proof())
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let proof_descriptor_codec_expansion_byte_length =
            selected_stream_descriptor_codec_expansion_byte_length(
                byte_lengths.malicious_share_proof(),
                individual_proof_byte_ceiling,
            )?;
        let signed_carrier_codec_ceiling_byte_length = byte_lengths
            .signed_carrier()
            .checked_add(proof_descriptor_codec_expansion_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let bundle_non_proof_codec_ceiling_wire_byte_length = bundle_non_proof_wire_byte_length
            .checked_add(proof_descriptor_codec_expansion_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        canonical_bundle_wire_byte_length = canonical_bundle_wire_byte_length
            .checked_add(byte_lengths.total())
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        non_proof_wire_byte_length = non_proof_wire_byte_length
            .checked_add(bundle_non_proof_wire_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        signed_carrier_codec_ceiling_wire_byte_length =
            signed_carrier_codec_ceiling_wire_byte_length
                .checked_add(signed_carrier_codec_ceiling_byte_length)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        non_proof_codec_ceiling_wire_byte_length = non_proof_codec_ceiling_wire_byte_length
            .checked_add(bundle_non_proof_codec_ceiling_wire_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        partial_decryption_wire_byte_length = partial_decryption_wire_byte_length
            .checked_add(stream_buffers.canonical_pair_wire_byte_length())
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        proof_wire_byte_length = proof_wire_byte_length
            .checked_add(byte_lengths.malicious_share_proof())
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        maximum_non_proof_boundary_copied_buffer_byte_length =
            maximum_non_proof_boundary_copied_buffer_byte_length.max(
                byte_lengths
                    .signed_carrier()
                    .max(signed_carrier_codec_ceiling_byte_length)
                    .max(stream_buffers.canonical_role_stream_byte_length()),
            );
    }
    if canonical_bundle_wire_byte_length
        != non_proof_wire_byte_length
            .checked_add(proof_wire_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let proof_ceiling_wire_byte_length = target_category.canonical_proof_byte_length();
    let complete_target_codec_and_proof_ceiling_wire_byte_length =
        non_proof_codec_ceiling_wire_byte_length
            .checked_add(proof_ceiling_wire_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let verification_decoded_residue_byte_length = stream_buffers
        .verification_decoded_residue_byte_length()
        .checked_mul(u64::from(target_application.application_multiplicity()))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let generation_resident_peak_byte_length = target_category
        .generation_resident_peak_byte_length()
        .checked_add(stream_buffers.generation_retained_canonical_byte_length())
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    maximum_non_proof_boundary_copied_buffer_byte_length =
        maximum_non_proof_boundary_copied_buffer_byte_length
            .max(target_category.maximum_copied_buffer_byte_length())
            .max(state_carriers.maximum_constituent_carrier_wire_byte_length())
            .max(state_carriers.maximum_canonical_state_certificate_wire_byte_length());
    let complete_target_with_state_transport_wire_byte_length = canonical_bundle_wire_byte_length
        .checked_add(state_carriers.canonical_verifier_transport_wire_byte_length())
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    if proof_wire_byte_length > proof_ceiling_wire_byte_length
        || canonical_bundle_wire_byte_length
            > complete_target_codec_and_proof_ceiling_wire_byte_length
        || complete_target_codec_and_proof_ceiling_wire_byte_length
            > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || complete_target_with_state_transport_wire_byte_length
            > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || generation_resident_peak_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || maximum_non_proof_boundary_copied_buffer_byte_length
            > u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    Ok(SelectedGeneratedTargetReleaseByteAccounting {
        release_bundle_count: u32::try_from(verified_outputs.len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        canonical_bundle_wire_byte_length,
        signed_carrier_codec_ceiling_wire_byte_length,
        non_proof_wire_byte_length,
        non_proof_codec_ceiling_wire_byte_length,
        partial_decryption_wire_byte_length,
        proof_wire_byte_length,
        proof_ceiling_wire_byte_length,
        complete_target_codec_and_proof_ceiling_wire_byte_length,
        verification_decoded_residue_byte_length,
        generation_resident_peak_byte_length,
        maximum_non_proof_boundary_copied_buffer_byte_length,
        state_carriers,
        complete_target_with_state_transport_wire_byte_length,
    })
}

/// One non-overlapping owner of generated bytes in the selected complete
/// action. These labels exist only in development accounting and are never
/// encoded into a protocol object or verification result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SelectedCompleteActionCorpusOwner {
    SetupPublicCorpus,
    SetupPrivateMailboxCorpus,
    BallotPublicCorpus,
    EvaluatorPublicCorpus,
    FinalityPublicCorpus,
    TargetReleasePublicCorpus,
}

impl SelectedCompleteActionCorpusOwner {
    pub(crate) const ALL: [Self; 6] = [
        Self::SetupPublicCorpus,
        Self::SetupPrivateMailboxCorpus,
        Self::BallotPublicCorpus,
        Self::EvaluatorPublicCorpus,
        Self::FinalityPublicCorpus,
        Self::TargetReleasePublicCorpus,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedCompleteActionCorpusOwnerByteAccounting {
    owner: SelectedCompleteActionCorpusOwner,
    canonical_wire_byte_length: u64,
    codec_and_proof_ceiling_wire_byte_length: u64,
    producer_upload_byte_length: u64,
    complete_verifier_download_byte_length: u64,
    public_storage_byte_length: u64,
    private_mailbox_storage_byte_length: u64,
}

impl SelectedCompleteActionCorpusOwnerByteAccounting {
    pub(crate) const fn owner(self) -> SelectedCompleteActionCorpusOwner {
        self.owner
    }

    pub(crate) const fn canonical_wire_byte_length(self) -> u64 {
        self.canonical_wire_byte_length
    }

    pub(crate) const fn codec_and_proof_ceiling_wire_byte_length(self) -> u64 {
        self.codec_and_proof_ceiling_wire_byte_length
    }

    pub(crate) const fn producer_upload_byte_length(self) -> u64 {
        self.producer_upload_byte_length
    }

    pub(crate) const fn complete_verifier_download_byte_length(self) -> u64 {
        self.complete_verifier_download_byte_length
    }

    pub(crate) const fn public_storage_byte_length(self) -> u64 {
        self.public_storage_byte_length
    }

    pub(crate) const fn private_mailbox_storage_byte_length(self) -> u64 {
        self.private_mailbox_storage_byte_length
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SelectedCompleteActionCorpusTotals {
    canonical_wire_byte_length: u64,
    codec_and_proof_ceiling_wire_byte_length: u64,
    producer_upload_byte_length: u64,
    complete_verifier_download_byte_length: u64,
    public_storage_byte_length: u64,
    private_mailbox_storage_byte_length: u64,
}

/// Generated production-object accounting for one exact selected action. The
/// modeled proof peaks remain separate from allocator and browser-process
/// observations, which must come from the measurement runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedCompleteActionByteAccounting {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    setup_package_hash: Hash512,
    evaluator_replay_object_hash: Hash512,
    aggregate_source_object_hash: Hash512,
    finality_hash: Hash512,
    proof_accounting: SelectedProofByteAccounting,
    sampler_availability_accounting:
        super::sampler_availability::SelectedActionSamplerAvailabilityAccounting,
    application_soundness_accounting:
        super::qrom_soundness::SelectedActionApplicationSoundnessAccounting,
    top_count: u16,
    owners: Vec<SelectedCompleteActionCorpusOwnerByteAccounting>,
    totals: SelectedCompleteActionCorpusTotals,
    generated_proof_wire_byte_length: u64,
    proof_ceiling_wire_byte_length: u64,
    maximum_private_mailbox_recipient_download_byte_length: u64,
    modeled_proof_generation_resident_peak_byte_length: u64,
    modeled_proof_generation_external_scratch_peak_byte_length: u64,
    maximum_source_derived_boundary_copied_buffer_byte_length: u64,
    evaluator_source_resident_byte_length_per_participant: u64,
    final_evaluator_key_store_resident_byte_length: u64,
    ceremony_private_randomness_kmac_input_accounting:
        PrivateRandomnessKmacInputClassAccounting,
    proof_privacy_private_randomness_kmac_input_accounting:
        PrivateRandomnessKmacInputClassAccounting,
}

impl SelectedCompleteActionByteAccounting {
    pub(crate) const fn suite_identifier(&self) -> Hash512 {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> Hash512 {
        self.roster_hash
    }

    pub(crate) const fn setup_package_hash(&self) -> Hash512 {
        self.setup_package_hash
    }

    pub(crate) const fn evaluator_replay_object_hash(&self) -> Hash512 {
        self.evaluator_replay_object_hash
    }

    pub(crate) const fn aggregate_source_object_hash(&self) -> Hash512 {
        self.aggregate_source_object_hash
    }

    pub(crate) const fn finality_hash(&self) -> Hash512 {
        self.finality_hash
    }

    pub(crate) const fn proof_accounting(&self) -> &SelectedProofByteAccounting {
        &self.proof_accounting
    }

    pub(crate) const fn sampler_availability_accounting(
        &self,
    ) -> &super::sampler_availability::SelectedActionSamplerAvailabilityAccounting {
        &self.sampler_availability_accounting
    }

    pub(crate) const fn application_soundness_accounting(
        &self,
    ) -> &super::qrom_soundness::SelectedActionApplicationSoundnessAccounting {
        &self.application_soundness_accounting
    }

    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) fn owners(&self) -> &[SelectedCompleteActionCorpusOwnerByteAccounting] {
        &self.owners
    }

    pub(crate) const fn canonical_wire_byte_length(&self) -> u64 {
        self.totals.canonical_wire_byte_length
    }

    pub(crate) const fn codec_and_proof_ceiling_wire_byte_length(&self) -> u64 {
        self.totals.codec_and_proof_ceiling_wire_byte_length
    }

    pub(crate) const fn producer_upload_byte_length(&self) -> u64 {
        self.totals.producer_upload_byte_length
    }

    pub(crate) const fn complete_verifier_download_byte_length(&self) -> u64 {
        self.totals.complete_verifier_download_byte_length
    }

    pub(crate) const fn public_storage_byte_length(&self) -> u64 {
        self.totals.public_storage_byte_length
    }

    pub(crate) const fn private_mailbox_storage_byte_length(&self) -> u64 {
        self.totals.private_mailbox_storage_byte_length
    }

    pub(crate) const fn generated_proof_wire_byte_length(&self) -> u64 {
        self.generated_proof_wire_byte_length
    }

    pub(crate) const fn proof_ceiling_wire_byte_length(&self) -> u64 {
        self.proof_ceiling_wire_byte_length
    }

    pub(crate) const fn maximum_private_mailbox_recipient_download_byte_length(&self) -> u64 {
        self.maximum_private_mailbox_recipient_download_byte_length
    }

    pub(crate) const fn modeled_proof_generation_resident_peak_byte_length(&self) -> u64 {
        self.modeled_proof_generation_resident_peak_byte_length
    }

    pub(crate) const fn modeled_proof_generation_external_scratch_peak_byte_length(
        &self,
    ) -> u64 {
        self.modeled_proof_generation_external_scratch_peak_byte_length
    }

    pub(crate) const fn maximum_source_derived_boundary_copied_buffer_byte_length(
        &self,
    ) -> u64 {
        self.maximum_source_derived_boundary_copied_buffer_byte_length
    }

    pub(crate) const fn evaluator_source_resident_byte_length_per_participant(&self) -> u64 {
        self.evaluator_source_resident_byte_length_per_participant
    }

    pub(crate) const fn final_evaluator_key_store_resident_byte_length(&self) -> u64 {
        self.final_evaluator_key_store_resident_byte_length
    }

    pub(crate) const fn ceremony_private_randomness_kmac_input_accounting(
        &self,
    ) -> PrivateRandomnessKmacInputClassAccounting {
        self.ceremony_private_randomness_kmac_input_accounting
    }

    pub(crate) const fn proof_privacy_private_randomness_kmac_input_accounting(
        &self,
    ) -> PrivateRandomnessKmacInputClassAccounting {
        self.proof_privacy_private_randomness_kmac_input_accounting
    }
}

#[cfg(test)]
pub(crate) fn selected_complete_action_byte_accounting_diagnostic_json(
    accounting: &SelectedCompleteActionByteAccounting,
) -> Result<String, serde_json::Error> {
    let hash_hex = |hash: Hash512| {
        hash.as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let owner_name = |owner| match owner {
        SelectedCompleteActionCorpusOwner::SetupPublicCorpus => "setup-public-corpus",
        SelectedCompleteActionCorpusOwner::SetupPrivateMailboxCorpus => {
            "setup-private-mailbox-corpus"
        }
        SelectedCompleteActionCorpusOwner::BallotPublicCorpus => "ballot-public-corpus",
        SelectedCompleteActionCorpusOwner::EvaluatorPublicCorpus => "evaluator-public-corpus",
        SelectedCompleteActionCorpusOwner::FinalityPublicCorpus => "finality-public-corpus",
        SelectedCompleteActionCorpusOwner::TargetReleasePublicCorpus => {
            "target-release-public-corpus"
        }
    };
    let kmac_input_class_json = |ledger: PrivateRandomnessKmacInputClassAccounting| {
        serde_json::json!({
            "actionKeyHierarchyDerivationCount": ledger
                .action_key_hierarchy_derivation_count(),
            "attemptIdentifierDerivationCount": ledger
                .attempt_identifier_derivation_count(),
            "committedMaterialInnerDerivationCount": ledger
                .committed_material_inner_derivation_count(),
            "privateStreamBlockCount": ledger.private_stream_block_count(),
            "totalCount": ledger.total_count(),
        })
    };
    let sampler_probability_json =
        |bound: &super::sampler_availability::CommonProofSamplerExhaustionProbabilityBound| {
            serde_json::json!({
                "denominatorPowerOfTwoExponent": bound
                    .denominator_power_of_two_exponent(),
                "numerator": bound.numerator().to_string(),
            })
        };
    let exact_probability_json =
        |bound: &super::qrom_soundness::SelectedExactProbabilityBound| {
            serde_json::json!({
                "denominator": bound.denominator().to_string(),
                "numerator": bound.numerator().to_string(),
            })
        };
    let round_by_round_probability_json =
        |bound: &super::selected_profile::SelectedRoundByRoundProbabilityBound| {
            serde_json::json!({
                "denominator": bound.denominator().to_string(),
                "numerator": bound.numerator().to_string(),
            })
        };
    let owner_rows = accounting
        .owners()
        .iter()
        .map(|row| {
            serde_json::json!({
                "canonicalWireByteLength": row.canonical_wire_byte_length(),
                "codecAndProofCeilingWireByteLength": row
                    .codec_and_proof_ceiling_wire_byte_length(),
                "completeVerifierDownloadByteLength": row
                    .complete_verifier_download_byte_length(),
                "owner": owner_name(row.owner()),
                "privateMailboxStorageByteLength": row
                    .private_mailbox_storage_byte_length(),
                "producerUploadByteLength": row.producer_upload_byte_length(),
                "publicStorageByteLength": row.public_storage_byte_length(),
            })
        })
        .collect::<Vec<_>>();
    let ceremony_kmac_input_accounting =
        accounting.ceremony_private_randomness_kmac_input_accounting();
    let proof_privacy_kmac_input_accounting =
        accounting.proof_privacy_private_randomness_kmac_input_accounting();
    let complete_kmac_input_accounting = ceremony_kmac_input_accounting
        .checked_add(proof_privacy_kmac_input_accounting)
        .expect("selected complete-action KMAC accounting already passed checked construction");
    let sampler_variant_rows = accounting
        .sampler_availability_accounting()
        .ordered_variant_accounting()
        .iter()
        .map(|variant| {
            let per_proof = variant.per_proof();
            let product_sampler_rows = per_proof
                .ordered_product_samplers()
                .iter()
                .map(|sampler| {
                    serde_json::json!({
                        "candidateByteLength": sampler.candidate_byte_length(),
                        "challengeRoleIdentifier": sampler.challenge_role() as u16,
                        "coordinateCount": sampler.coordinate_count(),
                        "coordinateModulus": sampler.coordinate_modulus(),
                        "exhaustionProbability": sampler_probability_json(
                            sampler.exhaustion_probability(),
                        ),
                        "maximumCandidateDrawCount": sampler.maximum_candidate_draw_count(),
                        "modulusCatalogIdentifier": sampler
                            .modulus_reference()
                            .catalog_identifier(),
                        "modulusIndex": sampler.modulus_reference().modulus_index(),
                        "productSpaceCardinality": sampler
                            .product_space_cardinality()
                            .to_string(),
                        "rawCandidateSpacePowerOfTwoExponent": sampler
                            .raw_candidate_space_power_of_two_exponent(),
                        "rejectedRawCandidateCount": sampler
                            .rejected_raw_candidate_count()
                            .to_string(),
                    })
                })
                .collect::<Vec<_>>();
            let generic_extension_sampler = per_proof.generic_extension_sampler();
            let deep_sampler = per_proof.deep_sampler();
            let query_vector_sampler = per_proof.query_vector_sampler();
            serde_json::json!({
                "applicationMultiplicity": variant.application_multiplicity(),
                "applicationStatementSchemaIdentifier": variant
                    .application_statement_schema_identifier(),
                "combinedExhaustionProbabilityUpperBound": sampler_probability_json(
                    per_proof.combined_exhaustion_probability_upper_bound(),
                ),
                "deepPointDrawCount": per_proof.deep_point_draw_count(),
                "deepSampler": {
                    "exhaustionProbabilityUpperBound": sampler_probability_json(
                        deep_sampler.exhaustion_probability_upper_bound(),
                    ),
                    "extensionFieldCardinality": deep_sampler
                        .extension_field_cardinality()
                        .to_string(),
                    "forbiddenExtensionElementCountUpperBound": deep_sampler
                        .forbidden_extension_element_count_upper_bound()
                        .to_string(),
                    "maximumCandidateDrawCount": deep_sampler
                        .maximum_candidate_draw_count(),
                    "noncanonicalRawCandidateCount": deep_sampler
                        .noncanonical_raw_candidate_count()
                        .to_string(),
                    "rawCandidateSpacePowerOfTwoExponent": deep_sampler
                        .raw_candidate_space_power_of_two_exponent(),
                    "rejectedRawCandidateCountUpperBound": deep_sampler
                        .rejected_raw_candidate_count_upper_bound()
                        .to_string(),
                    "uniformPreimageCount": deep_sampler.uniform_preimage_count().to_string(),
                },
                "genericExtensionDrawCount": per_proof.generic_extension_draw_count(),
                "genericExtensionSampler": {
                    "exhaustionProbability": sampler_probability_json(
                        generic_extension_sampler.exhaustion_probability(),
                    ),
                    "extensionFieldCardinality": generic_extension_sampler
                        .extension_field_cardinality()
                        .to_string(),
                    "maximumCandidateDrawCount": generic_extension_sampler
                        .maximum_candidate_draw_count(),
                    "noncanonicalRawCandidateCount": generic_extension_sampler
                        .noncanonical_raw_candidate_count()
                        .to_string(),
                    "rawCandidateSpacePowerOfTwoExponent": generic_extension_sampler
                        .raw_candidate_space_power_of_two_exponent(),
                    "uniformPreimageCount": generic_extension_sampler
                        .uniform_preimage_count()
                        .to_string(),
                },
                "productSamplers": product_sampler_rows,
                "queryVectorSampler": {
                    "exactExhaustionProbability": sampler_probability_json(
                        query_vector_sampler.exact_exhaustion_probability(),
                    ),
                    "maximumCandidateDrawCountPerOutput": query_vector_sampler
                        .maximum_candidate_draw_count_per_output(),
                    "perOutputUnionProbabilityUpperBound": sampler_probability_json(
                        query_vector_sampler.per_output_union_probability_upper_bound(),
                    ),
                    "queryOrbitCount": query_vector_sampler.query_orbit_count(),
                    "uniqueQueryCount": query_vector_sampler.unique_query_count(),
                },
                "schedulePosition": variant.schedule_position(),
                "topCount": variant.top_count(),
            })
        })
        .collect::<Vec<_>>();
    let application_soundness_variant_rows = accounting
        .application_soundness_accounting()
        .variant_rows()
        .iter()
        .map(|row| {
            let variant = accounting
                .proof_accounting()
                .variant_ceilings()
                .get(row.variant_catalog_index())
                .expect("application-soundness row passed selected variant inventory checking");
            let theorem_input = variant.round_by_round_theorem_input();
            assert_eq!(
                row.application_statement_schema_identifier(),
                theorem_input.application_statement_schema_identifier(),
            );
            assert_eq!(row.schedule_position(), theorem_input.schedule_position());
            assert_eq!(row.top_count(), theorem_input.top_count());
            let transitions = theorem_input.transition_catalog();
            let numerical_bounds = theorem_input.numerical_bounds();
            serde_json::json!({
                "applicationStatementSchemaIdentifier": row
                    .application_statement_schema_identifier(),
                "checkedOracleEquationCount": row.checked_oracle_equation_count(),
                "logicalVerifierMessageCount": row.logical_verifier_message_count(),
                "numericalBounds": {
                    "compositionBatching": round_by_round_probability_json(
                        numerical_bounds.composition_batching_bound(),
                    ),
                    "deepIdentity": round_by_round_probability_json(
                        numerical_bounds.deep_identity_bound(),
                    ),
                    "openingBatchMca": round_by_round_probability_json(
                        numerical_bounds.opening_batch_mca_bound(),
                    ),
                    "orderedFriFolds": numerical_bounds
                        .ordered_fri_fold_bounds()
                        .iter()
                        .map(round_by_round_probability_json)
                        .collect::<Vec<_>>(),
                    "orderedNonNativeChallenges": numerical_bounds
                        .ordered_non_native_challenge_bounds()
                        .iter()
                        .map(round_by_round_probability_json)
                        .collect::<Vec<_>>(),
                    "queryVector": round_by_round_probability_json(
                        numerical_bounds.query_vector_bound(),
                    ),
                    "roundByRoundError": round_by_round_probability_json(
                        numerical_bounds.round_by_round_error_bound(),
                    ),
                },
                "physicalApplicationMultiplicity": row
                    .physical_application_multiplicity(),
                "quantumRandomOracleSingleEventBound": exact_probability_json(
                    row.quantum_random_oracle_single_event_bound(),
                ),
                "roundByRoundErrorBound": exact_probability_json(
                    row.round_by_round_error_bound(),
                ),
                "schedulePosition": row.schedule_position(),
                "theoremTransitionCounts": {
                    "compositionBatchingTransitionCount": transitions
                        .composition_batching_transition_count(),
                    "compositionCoefficientCount": transitions
                        .composition_coefficient_count(),
                    "deepPointTransitionCount": transitions.deep_point_transition_count(),
                    "friFoldTransitionCount": transitions.fri_fold_transition_count(),
                    "maximumCandidateDrawsPerOutput": transitions
                        .maximum_candidate_draws_per_output(),
                    "openingBatchMcaTransitionCount": transitions
                        .opening_batch_mca_transition_count(),
                    "orderedNonNativeChallengeGroupCount": transitions
                        .ordered_non_native_challenge_bad_sets()
                        .len(),
                    "queryVectorPositionCount": transitions.query_vector_position_count(),
                    "queryVectorTransitionCount": transitions
                        .query_vector_transition_count(),
                },
                "topCount": row.top_count(),
                "variantCatalogIndex": row.variant_catalog_index(),
                "verifierIdealXofQueryCount": row.verifier_ideal_xof_query_count(),
            })
        })
        .collect::<Vec<_>>();
    let application_soundness_accounting = accounting.application_soundness_accounting();
    let sampler_availability_accounting = accounting.sampler_availability_accounting();
    serde_json::to_string(&serde_json::json!({
        "applicationSoundnessAccounting": {
            "ordinaryInvalidAcceptanceBound": exact_probability_json(
                application_soundness_accounting.ordinary_invalid_acceptance_bound(),
            ),
            "quantumRandomOracleInvalidAcceptanceBound": exact_probability_json(
                application_soundness_accounting
                    .quantum_random_oracle_invalid_acceptance_bound(),
            ),
            "roundByRoundCompilerInputBound": exact_probability_json(
                application_soundness_accounting.round_by_round_compiler_input_bound(),
            ),
            "variantRows": application_soundness_variant_rows,
        },
        "identity": {
            "actionContextHash": hash_hex(accounting.action_context_hash()),
            "aggregateSourceObjectHash": hash_hex(accounting.aggregate_source_object_hash()),
            "ceremonyContextHash": hash_hex(accounting.ceremony_context_hash()),
            "evaluatorReplayObjectHash": hash_hex(accounting.evaluator_replay_object_hash()),
            "finalityHash": hash_hex(accounting.finality_hash()),
            "rosterHash": hash_hex(accounting.roster_hash()),
            "setupPackageHash": hash_hex(accounting.setup_package_hash()),
            "suiteIdentifier": hash_hex(accounting.suite_identifier()),
            "topCount": accounting.top_count(),
        },
        "ownerRows": owner_rows,
        "privateRandomnessKmacInputAccounting": {
            "ceremony": kmac_input_class_json(ceremony_kmac_input_accounting),
            "completeAction": kmac_input_class_json(complete_kmac_input_accounting),
            "proofPrivacy": kmac_input_class_json(proof_privacy_kmac_input_accounting),
        },
        "recordKind": "selected-complete-action-generated-byte-accounting",
        "recordVersion": 2,
        "samplerAvailabilityAccounting": {
            "completeActionExhaustionProbabilityUpperBound": sampler_probability_json(
                sampler_availability_accounting
                    .complete_action_exhaustion_probability_upper_bound(),
            ),
            "physicalProofObjectCount": sampler_availability_accounting
                .physical_proof_object_count(),
            "variantRows": sampler_variant_rows,
        },
        "sourceModeledResources": {
            "evaluatorSourceResidentByteLengthPerParticipant": accounting
                .evaluator_source_resident_byte_length_per_participant(),
            "finalEvaluatorKeyStoreResidentByteLength": accounting
                .final_evaluator_key_store_resident_byte_length(),
            "maximumBoundaryCopiedBufferByteLength": accounting
                .maximum_source_derived_boundary_copied_buffer_byte_length(),
            "proofGenerationExternalScratchPeakByteLength": accounting
                .modeled_proof_generation_external_scratch_peak_byte_length(),
            "proofGenerationResidentPeakByteLengthExcludingWasmStack": accounting
                .modeled_proof_generation_resident_peak_byte_length(),
        },
        "totals": {
            "canonicalWireByteLength": accounting.canonical_wire_byte_length(),
            "codecAndProofCeilingWireByteLength": accounting
                .codec_and_proof_ceiling_wire_byte_length(),
            "completeVerifierDownloadByteLength": accounting
                .complete_verifier_download_byte_length(),
            "generatedProofWireByteLength": accounting.generated_proof_wire_byte_length(),
            "maximumPrivateMailboxRecipientDownloadByteLength": accounting
                .maximum_private_mailbox_recipient_download_byte_length(),
            "privateMailboxStorageByteLength": accounting
                .private_mailbox_storage_byte_length(),
            "producerUploadByteLength": accounting.producer_upload_byte_length(),
            "proofCeilingWireByteLength": accounting.proof_ceiling_wire_byte_length(),
            "publicStorageByteLength": accounting.public_storage_byte_length(),
        },
    }))
}

pub(crate) struct SelectedCompleteActionByteAccountingInput<'input> {
    pub(crate) accepted_setup_package: &'input CanonicalAcceptedSetupPackage,
    pub(crate) accepted_setup_consumed_object_byte_lengths:
        &'input VerifiedAcceptedSetupConsumedObjectByteLengthCatalog,
    pub(crate) private_vss_mailbox_byte_lengths:
        &'input VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog,
    pub(crate) verified_vss_qualification: &'input VerifiedVssQualificationTerminals,
    pub(crate) aggregate_source: &'input VerifiedBoardApplicationSource,
    pub(crate) verified_ballot_sources: &'input [VerifiedBoardApplicationSource],
    pub(crate) verified_ballot_outputs: &'input [VerifiedBallotValidityOutput],
    pub(crate) verified_finality: &'input VerifiedFinality,
    pub(crate) verified_target_release_outputs: &'input [VerifiedStateOutput],
}

pub(crate) fn selected_complete_action_byte_accounting(
    input: SelectedCompleteActionByteAccountingInput<'_>,
) -> Result<SelectedCompleteActionByteAccounting, SelectedProofAccountingError> {
    let proof_accounting = selected_proof_byte_accounting()?;
    let top_count = FOUNDATION_PROFILE.option_count;
    let action = proof_accounting
        .actions()
        .iter()
        .find(|action| action.top_count() == top_count)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let sampler_availability_accounting =
        super::sampler_availability::selected_complete_action_sampler_availability_accounting()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let application_soundness_accounting =
        super::qrom_soundness::require_selected_application_soundness_bounds(&proof_accounting)
            .map_err(|_| SelectedProofAccountingError::ApplicationSoundness)?
            .actions()
            .iter()
            .find(|accounting| accounting.top_count() == top_count)
            .cloned()
            .ok_or(SelectedProofAccountingError::ApplicationSoundness)?;
    if sampler_availability_accounting.top_count() != top_count
        || sampler_availability_accounting.physical_proof_object_count()
            != action.physical_proof_object_count()
        || application_soundness_accounting.variant_rows().len()
            != action.variant_applications().len()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let verified_evaluator_replay = input.verified_finality.verified_evaluator_replay();
    let finality_statement = input.verified_finality.statement();
    if verified_evaluator_replay.top_count() != top_count
        || input.accepted_setup_package.setup_package_hash()
            != verified_evaluator_replay.verified_setup_source_hash()
        || finality_statement.suite_identifier() != verified_evaluator_replay.suite_identifier()
        || finality_statement.ceremony_context_hash()
            != verified_evaluator_replay.ceremony_context_hash()
        || finality_statement.action_context_hash()
            != verified_evaluator_replay.action_context_hash()
        || finality_statement.roster_hash() != verified_evaluator_replay.roster_hash()
        || finality_statement.evaluator_replay_object_hash()
            != verified_evaluator_replay.object_hash()
        || input.verified_finality.finality_hash()
            != finality_statement
                .finality_hash()
                .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    if input.verified_ballot_outputs.iter().any(|output| {
        output.suite_identifier() != finality_statement.suite_identifier().into_bytes()
            || output.ceremony_context_hash()
                != finality_statement.ceremony_context_hash().into_bytes()
            || output.action_context_hash()
                != finality_statement.action_context_hash().into_bytes()
            || output.roster_hash() != finality_statement.roster_hash().into_bytes()
            || output.verified_setup_source_hash()
                != input.accepted_setup_package.setup_package_hash().into_bytes()
    }) || input.verified_target_release_outputs.iter().any(|output| {
        output.suite_id() != finality_statement.suite_identifier()
            || output.ceremony_context_hash() != finality_statement.ceremony_context_hash()
            || output.action_context_hash() != finality_statement.action_context_hash()
            || output.target_release_output_bundle().is_none_or(|bundle| {
                bundle.finality_hash() != input.verified_finality.finality_hash()
            })
    }) {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let setup = selected_accepted_setup_package_byte_accounting(
        input.accepted_setup_package,
        input.accepted_setup_consumed_object_byte_lengths,
        input.private_vss_mailbox_byte_lengths,
        input.verified_vss_qualification,
        action,
    )?;
    let ballots = selected_generated_ballot_corpus_byte_accounting(
        input.verified_ballot_sources,
        input.verified_ballot_outputs,
        action,
    )?;
    let evaluator = selected_generated_evaluator_corpus_byte_accounting(
        input.aggregate_source,
        verified_evaluator_replay,
    )?;
    let finality = selected_finality_carrier_corpus_byte_accounting(input.verified_finality)?;
    let target_release = selected_generated_target_release_byte_accounting(
        input.verified_target_release_outputs,
        action,
    )?;

    let setup_private_mailbox_wire_byte_length =
        setup.private_vss_complete_recipient_wire_byte_length();
    let setup_public_wire_byte_length = setup
        .complete_setup_canonical_wire_byte_length()
        .checked_sub(setup_private_mailbox_wire_byte_length)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let setup_public_codec_and_proof_ceiling_wire_byte_length = setup
        .complete_setup_codec_and_proof_ceiling_wire_byte_length()
        .checked_sub(setup_private_mailbox_wire_byte_length)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let target_release_public_wire_byte_length =
        target_release.complete_target_with_state_transport_wire_byte_length();
    let target_release_codec_and_proof_ceiling_wire_byte_length = target_release
        .complete_target_codec_and_proof_ceiling_wire_byte_length()
        .checked_add(
            target_release
                .state_carriers()
                .canonical_verifier_transport_wire_byte_length(),
        )
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let owner_rows = vec![
        selected_public_complete_action_owner_row(
            SelectedCompleteActionCorpusOwner::SetupPublicCorpus,
            setup_public_wire_byte_length,
            setup_public_codec_and_proof_ceiling_wire_byte_length,
        ),
        SelectedCompleteActionCorpusOwnerByteAccounting {
            owner: SelectedCompleteActionCorpusOwner::SetupPrivateMailboxCorpus,
            canonical_wire_byte_length: setup_private_mailbox_wire_byte_length,
            codec_and_proof_ceiling_wire_byte_length: setup_private_mailbox_wire_byte_length,
            producer_upload_byte_length: setup_private_mailbox_wire_byte_length,
            complete_verifier_download_byte_length: 0,
            public_storage_byte_length: 0,
            private_mailbox_storage_byte_length: setup_private_mailbox_wire_byte_length,
        },
        selected_public_complete_action_owner_row(
            SelectedCompleteActionCorpusOwner::BallotPublicCorpus,
            ballots.generated_complete_ballot_wire_byte_length(),
            ballots.complete_ballot_codec_and_proof_ceiling_wire_byte_length(),
        ),
        selected_public_complete_action_owner_row(
            SelectedCompleteActionCorpusOwner::EvaluatorPublicCorpus,
            evaluator.complete_evaluator_public_corpus_wire_byte_length(),
            evaluator.complete_evaluator_public_corpus_wire_byte_length(),
        ),
        selected_public_complete_action_owner_row(
            SelectedCompleteActionCorpusOwner::FinalityPublicCorpus,
            finality.canonical_finality_certificate_wire_byte_length(),
            finality.canonical_finality_certificate_wire_byte_length(),
        ),
        selected_public_complete_action_owner_row(
            SelectedCompleteActionCorpusOwner::TargetReleasePublicCorpus,
            target_release_public_wire_byte_length,
            target_release_codec_and_proof_ceiling_wire_byte_length,
        ),
    ];
    let (owners, totals) = selected_complete_action_corpus_totals(owner_rows)?;
    let maximum_private_mailbox_recipient_download_byte_length = input
        .private_vss_mailbox_byte_lengths
        .ordered_recipient_download_byte_lengths()
        .iter()
        .copied()
        .max()
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    if input
        .private_vss_mailbox_byte_lengths
        .ordered_recipient_download_byte_lengths()
        .iter()
        .try_fold(0_u64, |total, byte_length| total.checked_add(*byte_length))
        != Some(setup_private_mailbox_wire_byte_length)
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let generated_proof_wire_byte_length = setup
        .complete_setup_proof_wire_byte_length()
        .checked_add(ballots.generated_proof_wire_byte_length())
        .and_then(|total| total.checked_add(target_release.proof_wire_byte_length()))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let proof_ceiling_wire_byte_length = action.proof_byte_length();
    if generated_proof_wire_byte_length > proof_ceiling_wire_byte_length
        || totals.public_storage_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || totals.complete_verifier_download_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || maximum_private_mailbox_recipient_download_byte_length
            > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    let modeled_proof_generation_resident_peak_byte_length = action
        .categories()
        .iter()
        .map(|category| category.generation_resident_peak_byte_length())
        .max()
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let modeled_proof_generation_external_scratch_peak_byte_length = action
        .categories()
        .iter()
        .map(|category| category.external_scratch_peak_stored_byte_length())
        .max()
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let maximum_source_derived_boundary_copied_buffer_byte_length = [
        setup.canonical_package_codec_ceiling_byte_length(),
        setup.maximum_consumed_setup_object_codec_ceiling_wire_byte_length(),
        setup.maximum_private_vss_signed_envelope_byte_length(),
        ballots.maximum_boundary_copied_buffer_byte_length(),
        evaluator.maximum_boundary_copied_buffer_byte_length(),
        finality.maximum_constituent_carrier_wire_byte_length(),
        target_release.maximum_non_proof_boundary_copied_buffer_byte_length(),
    ]
    .into_iter()
    .max()
    .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let ceremony_private_randomness_kmac_input_accounting =
        action.ceremony_private_randomness_kmac_input_accounting();
    let proof_privacy_private_randomness_kmac_input_accounting =
        action.proof_privacy_private_randomness_kmac_input_accounting();

    Ok(SelectedCompleteActionByteAccounting {
        suite_identifier: finality_statement.suite_identifier(),
        ceremony_context_hash: finality_statement.ceremony_context_hash(),
        action_context_hash: finality_statement.action_context_hash(),
        roster_hash: finality_statement.roster_hash(),
        setup_package_hash: input.accepted_setup_package.setup_package_hash(),
        evaluator_replay_object_hash: verified_evaluator_replay.object_hash(),
        aggregate_source_object_hash: input.aggregate_source.object_hash(),
        finality_hash: input.verified_finality.finality_hash(),
        proof_accounting,
        sampler_availability_accounting,
        application_soundness_accounting,
        top_count,
        owners,
        totals,
        generated_proof_wire_byte_length,
        proof_ceiling_wire_byte_length,
        maximum_private_mailbox_recipient_download_byte_length,
        modeled_proof_generation_resident_peak_byte_length,
        modeled_proof_generation_external_scratch_peak_byte_length,
        maximum_source_derived_boundary_copied_buffer_byte_length,
        evaluator_source_resident_byte_length_per_participant: setup
            .evaluator_source_material_resident_byte_length_per_participant(),
        final_evaluator_key_store_resident_byte_length: setup
            .final_evaluator_key_store_resident_byte_length(),
        ceremony_private_randomness_kmac_input_accounting,
        proof_privacy_private_randomness_kmac_input_accounting,
    })
}

const fn selected_public_complete_action_owner_row(
    owner: SelectedCompleteActionCorpusOwner,
    canonical_wire_byte_length: u64,
    codec_and_proof_ceiling_wire_byte_length: u64,
) -> SelectedCompleteActionCorpusOwnerByteAccounting {
    SelectedCompleteActionCorpusOwnerByteAccounting {
        owner,
        canonical_wire_byte_length,
        codec_and_proof_ceiling_wire_byte_length,
        producer_upload_byte_length: canonical_wire_byte_length,
        complete_verifier_download_byte_length: canonical_wire_byte_length,
        public_storage_byte_length: canonical_wire_byte_length,
        private_mailbox_storage_byte_length: 0,
    }
}

fn selected_complete_action_corpus_totals(
    rows: Vec<SelectedCompleteActionCorpusOwnerByteAccounting>,
) -> Result<
    (
        Vec<SelectedCompleteActionCorpusOwnerByteAccounting>,
        SelectedCompleteActionCorpusTotals,
    ),
    SelectedProofAccountingError,
> {
    let mut rows_by_owner = BTreeMap::new();
    for row in rows {
        if row.canonical_wire_byte_length() == 0
            || row.codec_and_proof_ceiling_wire_byte_length()
                < row.canonical_wire_byte_length()
            || row.producer_upload_byte_length() != row.canonical_wire_byte_length()
            || row.complete_verifier_download_byte_length()
                .checked_add(row.private_mailbox_storage_byte_length())
                != Some(row.canonical_wire_byte_length())
            || row.public_storage_byte_length()
                .checked_add(row.private_mailbox_storage_byte_length())
                != Some(row.canonical_wire_byte_length())
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        if rows_by_owner.insert(row.owner(), row).is_some() {
            return Err(SelectedProofAccountingError::DuplicateCompleteActionOwner);
        }
    }
    if rows_by_owner.len() != SelectedCompleteActionCorpusOwner::ALL.len()
        || SelectedCompleteActionCorpusOwner::ALL
            .iter()
            .any(|owner| !rows_by_owner.contains_key(owner))
    {
        return Err(SelectedProofAccountingError::MissingCompleteActionOwner);
    }

    let ordered_rows = SelectedCompleteActionCorpusOwner::ALL
        .into_iter()
        .map(|owner| {
            rows_by_owner
                .remove(&owner)
                .ok_or(SelectedProofAccountingError::MissingCompleteActionOwner)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let totals = ordered_rows.iter().try_fold(
        SelectedCompleteActionCorpusTotals::default(),
        |total, row| {
            Ok(SelectedCompleteActionCorpusTotals {
                canonical_wire_byte_length: total
                    .canonical_wire_byte_length
                    .checked_add(row.canonical_wire_byte_length())
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
                codec_and_proof_ceiling_wire_byte_length: total
                    .codec_and_proof_ceiling_wire_byte_length
                    .checked_add(row.codec_and_proof_ceiling_wire_byte_length())
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
                producer_upload_byte_length: total
                    .producer_upload_byte_length
                    .checked_add(row.producer_upload_byte_length())
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
                complete_verifier_download_byte_length: total
                    .complete_verifier_download_byte_length
                    .checked_add(row.complete_verifier_download_byte_length())
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
                public_storage_byte_length: total
                    .public_storage_byte_length
                    .checked_add(row.public_storage_byte_length())
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
                private_mailbox_storage_byte_length: total
                    .private_mailbox_storage_byte_length
                    .checked_add(row.private_mailbox_storage_byte_length())
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
            })
        },
    )?;
    Ok((ordered_rows, totals))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedMaskOrdinalConsumption {
    purpose_class: u16,
    first_consumed_mask_ordinal: Option<u32>,
    last_consumed_mask_ordinal: Option<u32>,
    consumed_mask_count: u32,
}

impl SelectedMaskOrdinalConsumption {
    pub(crate) const fn purpose_class(self) -> u16 {
        self.purpose_class
    }

    pub(crate) const fn first_consumed_mask_ordinal(self) -> Option<u32> {
        self.first_consumed_mask_ordinal
    }

    pub(crate) const fn last_consumed_mask_ordinal(self) -> Option<u32> {
        self.last_consumed_mask_ordinal
    }

    pub(crate) const fn consumed_mask_count(self) -> u32 {
        self.consumed_mask_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedMaskCoordinateConsumption {
    trace_masks: SelectedMaskOrdinalConsumption,
    quotient_masks: SelectedMaskOrdinalConsumption,
    opening_masks: SelectedMaskOrdinalConsumption,
    total_mask_count: u32,
}

impl SelectedMaskCoordinateConsumption {
    pub(crate) const fn trace_masks(self) -> SelectedMaskOrdinalConsumption {
        self.trace_masks
    }

    pub(crate) const fn quotient_masks(self) -> SelectedMaskOrdinalConsumption {
        self.quotient_masks
    }

    pub(crate) const fn opening_masks(self) -> SelectedMaskOrdinalConsumption {
        self.opening_masks
    }

    pub(crate) const fn total_mask_count(self) -> u32 {
        self.total_mask_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofTreeByteCeiling {
    tree_catalog_index: u16,
    source: ProofTreeCatalogSource,
    leaf_visibility: ProofLeafVisibility,
    bound_tree_construction_kind: Option<BoundTreeConstructionKind>,
    bound_root_source_ordinal: Option<u32>,
    bound_root_use: Option<BoundTreeRootUse>,
    requires_persistent_leaf_salt: bool,
    row_width: u32,
    tree_height: u32,
    leaf_count: u64,
    opened_row_count: u32,
    authentication_frontier_node_count: u32,
    opened_row_payload_byte_length: u64,
    authentication_frontier_digest_byte_length: u64,
    canonical_framing_byte_length: u64,
    query_record_byte_length: u64,
}

impl SelectedProofTreeByteCeiling {
    pub(crate) const fn tree_catalog_index(self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn source(self) -> ProofTreeCatalogSource {
        self.source
    }

    pub(crate) const fn leaf_visibility(self) -> ProofLeafVisibility {
        self.leaf_visibility
    }

    pub(crate) const fn bound_tree_construction_kind(self) -> Option<BoundTreeConstructionKind> {
        self.bound_tree_construction_kind
    }

    pub(crate) const fn bound_root_source_ordinal(self) -> Option<u32> {
        self.bound_root_source_ordinal
    }

    pub(crate) const fn bound_root_use(self) -> Option<BoundTreeRootUse> {
        self.bound_root_use
    }

    pub(crate) const fn requires_persistent_leaf_salt(self) -> bool {
        self.requires_persistent_leaf_salt
    }

    pub(crate) const fn row_width(self) -> u32 {
        self.row_width
    }

    pub(crate) const fn tree_height(self) -> u32 {
        self.tree_height
    }

    pub(crate) const fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    pub(crate) const fn opened_row_count(self) -> u32 {
        self.opened_row_count
    }

    pub(crate) const fn authentication_frontier_node_count(self) -> u32 {
        self.authentication_frontier_node_count
    }

    pub(crate) const fn opened_row_payload_byte_length(self) -> u64 {
        self.opened_row_payload_byte_length
    }

    pub(crate) const fn authentication_frontier_digest_byte_length(self) -> u64 {
        self.authentication_frontier_digest_byte_length
    }

    pub(crate) const fn canonical_framing_byte_length(self) -> u64 {
        self.canonical_framing_byte_length
    }

    pub(crate) const fn query_record_byte_length(self) -> u64 {
        self.query_record_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedSourcePolynomialProviderMemoryAccounting {
    BallotValidity(SelectedBallotValidityCarrierBufferAccounting),
    EvaluatorAggregate(SelectedEvaluatorAggregateSourceProviderMemoryAccounting),
    CommittedMaterial(CommittedMaterialSourceProviderMemoryAccounting),
}

impl SelectedSourcePolynomialProviderMemoryAccounting {
    pub(crate) const fn loading_persistent_resident_byte_length(self) -> u64 {
        match self {
            Self::BallotValidity(accounting) => {
                accounting.provider_loading_persistent_resident_byte_length()
            }
            Self::EvaluatorAggregate(accounting) => {
                accounting.loading_persistent_resident_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
                accounting.loading_persistent_resident_byte_length()
            }
        }
    }

    pub(crate) const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
        match self {
            Self::BallotValidity(accounting) => {
                accounting.provider_post_source_finish_persistent_resident_byte_length()
            }
            Self::EvaluatorAggregate(accounting) => {
                accounting.post_source_polynomial_finish_persistent_resident_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
                accounting.post_source_polynomial_finish_persistent_resident_byte_length()
            }
        }
    }

    pub(crate) const fn additional_loading_source_polynomials_transient_byte_length(self) -> u64 {
        match self {
            Self::BallotValidity(accounting) => {
                accounting.provider_additional_loading_transient_byte_length()
            }
            Self::EvaluatorAggregate(accounting) => {
                accounting.additional_loading_source_polynomials_transient_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
                accounting.additional_loading_source_polynomials_transient_byte_length()
            }
        }
    }

    pub(crate) const fn maximum_returned_source_polynomial_byte_length(self) -> u64 {
        match self {
            Self::BallotValidity(accounting) => {
                accounting.transferred_source_polynomial_byte_length()
            }
            Self::EvaluatorAggregate(accounting) => {
                accounting.maximum_returned_source_polynomial_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
                accounting.maximum_returned_source_polynomial_byte_length()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofResidentMemoryPhaseCeiling {
    phase: CommonProofResidentMemoryPhase,
    base_prover_byte_length: u64,
    source_polynomial_provider_persistent_resident_byte_length: u64,
    source_polynomial_provider_additional_transient_byte_length: u64,
    application_runtime_persistent_resident_byte_length: u64,
    application_runtime_boundary_overlap_byte_length: u64,
    checkpoint_boundary_count: u16,
    checkpoint_custody_byte_length: u64,
    combined_byte_length: u64,
}

impl SelectedProofResidentMemoryPhaseCeiling {
    pub(crate) const fn phase(self) -> CommonProofResidentMemoryPhase {
        self.phase
    }

    pub(crate) const fn base_prover_byte_length(self) -> u64 {
        self.base_prover_byte_length
    }

    pub(crate) const fn source_polynomial_provider_persistent_resident_byte_length(self) -> u64 {
        self.source_polynomial_provider_persistent_resident_byte_length
    }

    pub(crate) const fn source_polynomial_provider_additional_transient_byte_length(self) -> u64 {
        self.source_polynomial_provider_additional_transient_byte_length
    }

    pub(crate) const fn application_runtime_persistent_resident_byte_length(self) -> u64 {
        self.application_runtime_persistent_resident_byte_length
    }

    pub(crate) const fn application_runtime_boundary_overlap_byte_length(self) -> u64 {
        self.application_runtime_boundary_overlap_byte_length
    }

    pub(crate) const fn checkpoint_boundary_count(self) -> u16 {
        self.checkpoint_boundary_count
    }

    pub(crate) const fn checkpoint_custody_byte_length(self) -> u64 {
        self.checkpoint_custody_byte_length
    }

    pub(crate) const fn combined_byte_length(self) -> u64 {
        self.combined_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofVariantByteCeiling {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    proof_privacy_mode: ProofPrivacyMode,
    canonical_relation_plan_byte_length: u64,
    canonical_relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    canonical_variant_byte_length: u64,
    canonical_variant_hash: [u8; Hash512::BYTE_LENGTH],
    round_by_round_theorem_input: SelectedRelationApplicationRoundByRoundTheoremInput,
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    relation_column_count: u32,
    integer_lift_batch_count: u32,
    integer_lift_component_count: u32,
    coefficient_local_identity_batch_count: u32,
    coefficient_local_residual_count: u32,
    opening_point_count: u32,
    opening_claim_count: u32,
    logical_relation_count: u32,
    bound_tree_count: u32,
    proof_byte_length: u64,
    component_byte_lengths: CommonProofComponentByteLengths,
    mask_coordinate_consumption: SelectedMaskCoordinateConsumption,
    proof_private_randomness_kmac_input_accounting: PrivateRandomnessKmacInputClassAccounting,
    checkpoint_custody_requirement: CommonProofGenerationCheckpointCustodyRequirement,
    tree_ceilings: Vec<SelectedProofTreeByteCeiling>,
    maximum_prefetched_query_byte_length: u64,
    verifier_hash_equation_ledger: VerifierHashEquationLedger,
    source_polynomial_provider_memory_accounting:
        Option<SelectedSourcePolynomialProviderMemoryAccounting>,
    ballot_ciphertext_readback_memory_accounting:
        Option<SelectedBallotCiphertextReadbackMemoryAccounting>,
    resident_memory_requirement: CommonProofResidentMemoryPlan,
    resident_memory_phase_ceilings: Vec<SelectedProofResidentMemoryPhaseCeiling>,
    external_memory_requirement: CommonProofExternalMemoryRequirement,
}

impl SelectedProofVariantByteCeiling {
    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn proof_privacy_mode(&self) -> ProofPrivacyMode {
        self.proof_privacy_mode
    }

    pub(crate) const fn canonical_relation_plan_byte_length(&self) -> u64 {
        self.canonical_relation_plan_byte_length
    }

    pub(crate) const fn canonical_relation_plan_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.canonical_relation_plan_hash
    }

    pub(crate) const fn canonical_variant_byte_length(&self) -> u64 {
        self.canonical_variant_byte_length
    }

    pub(crate) const fn canonical_variant_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.canonical_variant_hash
    }

    pub(crate) const fn round_by_round_theorem_input(
        &self,
    ) -> &SelectedRelationApplicationRoundByRoundTheoremInput {
        &self.round_by_round_theorem_input
    }

    pub(crate) const fn trace_domain_size(&self) -> u64 {
        self.trace_domain_size
    }

    pub(crate) const fn evaluation_domain_size(&self) -> u64 {
        self.evaluation_domain_size
    }

    pub(crate) const fn opening_degree_bound_exclusive(&self) -> u64 {
        self.opening_degree_bound_exclusive
    }

    pub(crate) const fn relation_column_count(&self) -> u32 {
        self.relation_column_count
    }

    pub(crate) const fn integer_lift_batch_count(&self) -> u32 {
        self.integer_lift_batch_count
    }

    pub(crate) const fn integer_lift_component_count(&self) -> u32 {
        self.integer_lift_component_count
    }

    pub(crate) const fn coefficient_local_identity_batch_count(&self) -> u32 {
        self.coefficient_local_identity_batch_count
    }

    pub(crate) const fn coefficient_local_residual_count(&self) -> u32 {
        self.coefficient_local_residual_count
    }

    pub(crate) const fn opening_point_count(&self) -> u32 {
        self.opening_point_count
    }

    pub(crate) const fn opening_claim_count(&self) -> u32 {
        self.opening_claim_count
    }

    pub(crate) const fn logical_relation_count(&self) -> u32 {
        self.logical_relation_count
    }

    pub(crate) const fn bound_tree_count(&self) -> u32 {
        self.bound_tree_count
    }

    pub(crate) const fn proof_byte_length(&self) -> u64 {
        self.proof_byte_length
    }

    pub(crate) const fn component_byte_lengths(&self) -> CommonProofComponentByteLengths {
        self.component_byte_lengths
    }

    pub(crate) const fn mask_coordinate_consumption(&self) -> SelectedMaskCoordinateConsumption {
        self.mask_coordinate_consumption
    }

    pub(crate) const fn proof_private_randomness_kmac_input_accounting(
        &self,
    ) -> PrivateRandomnessKmacInputClassAccounting {
        self.proof_private_randomness_kmac_input_accounting
    }

    pub(crate) const fn checkpoint_cursor_manifest_requirement(
        &self,
    ) -> CommonProofCheckpointCursorManifestRequirement {
        self.checkpoint_custody_requirement
            .cursor_manifest_requirement()
    }

    pub(crate) const fn checkpoint_custody_requirement(
        &self,
    ) -> CommonProofGenerationCheckpointCustodyRequirement {
        self.checkpoint_custody_requirement
    }

    pub(crate) fn tree_ceilings(&self) -> &[SelectedProofTreeByteCeiling] {
        &self.tree_ceilings
    }

    pub(crate) const fn maximum_prefetched_query_byte_length(&self) -> u64 {
        self.maximum_prefetched_query_byte_length
    }

    pub(crate) const fn verifier_hash_equation_ledger(&self) -> &VerifierHashEquationLedger {
        &self.verifier_hash_equation_ledger
    }

    pub(crate) const fn secret_bearing_tree_root_count(&self) -> u64 {
        self.verifier_hash_equation_ledger
            .secret_bearing_tree_root_count()
    }

    pub(crate) const fn full_salted_leaf_count(&self) -> u64 {
        self.verifier_hash_equation_ledger.full_salted_leaf_count()
    }

    pub(crate) const fn opened_salted_leaf_count(&self) -> u64 {
        self.verifier_hash_equation_ledger
            .opened_salted_leaf_count()
    }

    pub(crate) const fn hidden_salted_leaf_count(&self) -> u64 {
        self.verifier_hash_equation_ledger
            .hidden_salted_leaf_count()
    }

    pub(crate) const fn source_polynomial_provider_memory_accounting(
        &self,
    ) -> Option<SelectedSourcePolynomialProviderMemoryAccounting> {
        self.source_polynomial_provider_memory_accounting
    }

    pub(crate) const fn ballot_ciphertext_readback_memory_accounting(
        &self,
    ) -> Option<SelectedBallotCiphertextReadbackMemoryAccounting> {
        self.ballot_ciphertext_readback_memory_accounting
    }

    pub(crate) const fn resident_memory_requirement(&self) -> &CommonProofResidentMemoryPlan {
        &self.resident_memory_requirement
    }

    pub(crate) fn resident_memory_phase_ceilings(
        &self,
    ) -> &[SelectedProofResidentMemoryPhaseCeiling] {
        &self.resident_memory_phase_ceilings
    }

    pub(crate) fn combined_resident_memory_peak_byte_length(&self) -> u64 {
        self.resident_memory_phase_ceilings
            .iter()
            .map(|phase| phase.combined_byte_length())
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn checkpoint_boundary_count(&self) -> u32 {
        self.resident_memory_phase_ceilings
            .iter()
            .map(|phase| u32::from(phase.checkpoint_boundary_count()))
            .sum()
    }

    pub(crate) const fn external_memory_requirement(&self) -> CommonProofExternalMemoryRequirement {
        self.external_memory_requirement
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SelectedProofComponentByteLengths {
    canonical_framing: u64,
    relation_commitments_and_openings: u64,
    quotient_commitments_and_openings: u64,
    transcript_opening_claims: u64,
    fri: u64,
}

impl SelectedProofComponentByteLengths {
    pub(crate) const fn canonical_framing(self) -> u64 {
        self.canonical_framing
    }

    pub(crate) const fn relation_commitments_and_openings(self) -> u64 {
        self.relation_commitments_and_openings
    }

    pub(crate) const fn quotient_commitments_and_openings(self) -> u64 {
        self.quotient_commitments_and_openings
    }

    pub(crate) const fn transcript_opening_claims(self) -> u64 {
        self.transcript_opening_claims
    }

    pub(crate) const fn fri(self) -> u64 {
        self.fri
    }

    pub(crate) fn proof_byte_length(self) -> Option<u64> {
        self.canonical_framing
            .checked_add(self.relation_commitments_and_openings)
            .and_then(|length| length.checked_add(self.quotient_commitments_and_openings))
            .and_then(|length| length.checked_add(self.transcript_opening_claims))
            .and_then(|length| length.checked_add(self.fri))
    }

    fn from_common_proof_components(
        components: CommonProofComponentByteLengths,
    ) -> Result<Self, SelectedProofAccountingError> {
        Ok(Self {
            canonical_framing: u64::try_from(components.canonical_framing())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            relation_commitments_and_openings: u64::try_from(
                components.relation_commitments_and_openings(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            quotient_commitments_and_openings: u64::try_from(
                components.quotient_commitments_and_openings(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            transcript_opening_claims: u64::try_from(components.transcript_opening_claims())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            fri: u64::try_from(components.fri())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        })
    }

    fn checked_multiply(self, multiplicity: u32) -> Result<Self, SelectedProofAccountingError> {
        let multiplicity = u64::from(multiplicity);
        Ok(Self {
            canonical_framing: self
                .canonical_framing
                .checked_mul(multiplicity)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            relation_commitments_and_openings: self
                .relation_commitments_and_openings
                .checked_mul(multiplicity)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            quotient_commitments_and_openings: self
                .quotient_commitments_and_openings
                .checked_mul(multiplicity)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            transcript_opening_claims: self
                .transcript_opening_claims
                .checked_mul(multiplicity)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            fri: self
                .fri
                .checked_mul(multiplicity)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
        })
    }

    fn checked_add(self, right: Self) -> Result<Self, SelectedProofAccountingError> {
        Ok(Self {
            canonical_framing: self
                .canonical_framing
                .checked_add(right.canonical_framing)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            relation_commitments_and_openings: self
                .relation_commitments_and_openings
                .checked_add(right.relation_commitments_and_openings)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            quotient_commitments_and_openings: self
                .quotient_commitments_and_openings
                .checked_add(right.quotient_commitments_and_openings)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            transcript_opening_claims: self
                .transcript_opening_claims
                .checked_add(right.transcript_opening_claims)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            fri: self
                .fri
                .checked_add(right.fri)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedActionProofVariantAccounting {
    variant_catalog_index: usize,
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    application_multiplicity: u32,
    logical_relation_application_count: u32,
    proof_byte_length: u64,
    component_byte_lengths: SelectedProofComponentByteLengths,
}

impl SelectedActionProofVariantAccounting {
    pub(crate) const fn variant_catalog_index(self) -> usize {
        self.variant_catalog_index
    }

    pub(crate) const fn application_statement_schema_identifier(self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn schedule_position(self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn application_multiplicity(self) -> u32 {
        self.application_multiplicity
    }

    pub(crate) const fn physical_proof_object_count(self) -> u32 {
        self.application_multiplicity
    }

    pub(crate) const fn logical_relation_application_count(self) -> u32 {
        self.logical_relation_application_count
    }

    pub(crate) const fn proof_byte_length(self) -> u64 {
        self.proof_byte_length
    }

    pub(crate) const fn component_byte_lengths(self) -> SelectedProofComponentByteLengths {
        self.component_byte_lengths
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SelectedProofCorpusCategory {
    Setup,
    Evaluator,
    Ballot,
    TargetRelease,
}

impl SelectedProofCorpusCategory {
    pub(crate) const ALL: [Self; 4] = [
        Self::Setup,
        Self::Evaluator,
        Self::Ballot,
        Self::TargetRelease,
    ];
}

/// Fixed copy volume incurred by the selected proof transport before the
/// verifier begins transcript-derived random-access readback. The latter has
/// a separate request counter because its exact volume depends on the concrete
/// proof's query representatives and chunk alignment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SelectedProofFixedTransportCopyAccounting {
    generation_pending_chunk_staging_byte_length: u64,
    generation_wasm_to_host_byte_length: u64,
    generation_authenticated_readback_byte_length: u64,
    verification_initial_ingress_byte_length: u64,
}

impl SelectedProofFixedTransportCopyAccounting {
    pub(crate) const fn generation_pending_chunk_staging_byte_length(self) -> u64 {
        self.generation_pending_chunk_staging_byte_length
    }

    pub(crate) const fn generation_wasm_to_host_byte_length(self) -> u64 {
        self.generation_wasm_to_host_byte_length
    }

    pub(crate) const fn generation_authenticated_readback_byte_length(self) -> u64 {
        self.generation_authenticated_readback_byte_length
    }

    pub(crate) const fn verification_initial_ingress_byte_length(self) -> u64 {
        self.verification_initial_ingress_byte_length
    }

    pub(crate) fn generation_total_byte_length(self) -> Option<u64> {
        self.generation_pending_chunk_staging_byte_length
            .checked_add(self.generation_wasm_to_host_byte_length)
            .and_then(|length| {
                length.checked_add(self.generation_authenticated_readback_byte_length)
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofCategoryByteAccounting {
    category: SelectedProofCorpusCategory,
    physical_proof_object_count: u32,
    canonical_proof_byte_length: u64,
    generation_resident_peak_byte_length: u64,
    external_scratch_peak_stored_byte_length: u64,
    external_scratch_total_written_byte_length: u64,
    external_scratch_total_read_byte_length: u64,
    external_scratch_transaction_count: u64,
    maximum_copied_buffer_byte_length: u64,
    fixed_transport_copies: SelectedProofFixedTransportCopyAccounting,
}

impl SelectedProofCategoryByteAccounting {
    pub(crate) const fn category(self) -> SelectedProofCorpusCategory {
        self.category
    }

    pub(crate) const fn physical_proof_object_count(self) -> u32 {
        self.physical_proof_object_count
    }

    pub(crate) const fn canonical_proof_byte_length(self) -> u64 {
        self.canonical_proof_byte_length
    }

    /// Every proof byte is uploaded once by its producer.
    pub(crate) const fn producer_upload_byte_length(self) -> u64 {
        self.canonical_proof_byte_length
    }

    /// One complete verifier downloads every canonical proof byte once before
    /// authenticated random-access verification begins.
    pub(crate) const fn single_verifier_download_byte_length(self) -> u64 {
        self.canonical_proof_byte_length
    }

    /// The untrusted public corpus stores the canonical proof bytes once.
    pub(crate) const fn public_storage_byte_length(self) -> u64 {
        self.canonical_proof_byte_length
    }

    /// The producer's authenticated output store retains the canonical proof
    /// until generation readback and publication complete.
    pub(crate) const fn producer_cached_byte_length(self) -> u64 {
        self.canonical_proof_byte_length
    }

    pub(crate) const fn generation_resident_peak_byte_length(self) -> u64 {
        self.generation_resident_peak_byte_length
    }

    pub(crate) const fn external_scratch_peak_stored_byte_length(self) -> u64 {
        self.external_scratch_peak_stored_byte_length
    }

    pub(crate) const fn external_scratch_total_written_byte_length(self) -> u64 {
        self.external_scratch_total_written_byte_length
    }

    pub(crate) const fn external_scratch_total_read_byte_length(self) -> u64 {
        self.external_scratch_total_read_byte_length
    }

    pub(crate) const fn external_scratch_transaction_count(self) -> u64 {
        self.external_scratch_transaction_count
    }

    pub(crate) const fn maximum_copied_buffer_byte_length(self) -> u64 {
        self.maximum_copied_buffer_byte_length
    }

    pub(crate) const fn fixed_transport_copies(self) -> SelectedProofFixedTransportCopyAccounting {
        self.fixed_transport_copies
    }
}

/// Exact secret-leaf population for one selected complete action. Persistent
/// statement roots are coalesced through the profile's checked root-
/// compatibility graph, while proof-created roots retain physical proof
/// multiplicity. This is derived security analysis and is never serialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedSecretLeafPopulationAccounting {
    proof_local_physical_root_count: u64,
    persistent_physical_root_count: u64,
    physical_root_count: u64,
    proof_local_full_salted_leaf_count: u64,
    persistent_full_salted_leaf_count: u64,
    distinct_full_salted_leaf_count: u64,
    proof_view_full_salted_leaf_occurrence_count: u64,
    opened_salted_leaf_occurrence_count: u64,
    hidden_salted_leaf_occurrence_count: u64,
    distinct_full_secret_tree_hash_equation_count: u64,
}

impl SelectedSecretLeafPopulationAccounting {
    pub(crate) const fn proof_local_physical_root_count(self) -> u64 {
        self.proof_local_physical_root_count
    }

    pub(crate) const fn persistent_physical_root_count(self) -> u64 {
        self.persistent_physical_root_count
    }

    pub(crate) const fn physical_root_count(self) -> u64 {
        self.physical_root_count
    }

    pub(crate) const fn proof_local_full_salted_leaf_count(self) -> u64 {
        self.proof_local_full_salted_leaf_count
    }

    pub(crate) const fn persistent_full_salted_leaf_count(self) -> u64 {
        self.persistent_full_salted_leaf_count
    }

    /// Numerator of the complete-action BCS16 statistical term. The
    /// denominator exponent is supplied by the proof backend constant below.
    pub(crate) const fn distinct_full_salted_leaf_count(self) -> u64 {
        self.distinct_full_salted_leaf_count
    }

    pub(crate) const fn statistical_privacy_denominator_exponent(self) -> u16 {
        BCS_MERKLE_STATISTICAL_PRIVACY_DENOMINATOR_EXPONENT
    }

    pub(crate) const fn proof_view_full_salted_leaf_occurrence_count(self) -> u64 {
        self.proof_view_full_salted_leaf_occurrence_count
    }

    pub(crate) const fn opened_salted_leaf_occurrence_count(self) -> u64 {
        self.opened_salted_leaf_occurrence_count
    }

    pub(crate) const fn hidden_salted_leaf_occurrence_count(self) -> u64 {
        self.hidden_salted_leaf_occurrence_count
    }

    pub(crate) const fn distinct_full_secret_tree_hash_equation_count(self) -> u64 {
        self.distinct_full_secret_tree_hash_equation_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedActionProofAccounting {
    top_count: u16,
    variant_applications: Vec<SelectedActionProofVariantAccounting>,
    categories: Vec<SelectedProofCategoryByteAccounting>,
    physical_proof_object_count: u32,
    logical_relation_application_count: u32,
    proof_byte_length: u64,
    component_byte_lengths: SelectedProofComponentByteLengths,
    secret_leaf_population_accounting: SelectedSecretLeafPopulationAccounting,
    ceremony_private_randomness_kmac_input_accounting: PrivateRandomnessKmacInputClassAccounting,
    proof_privacy_private_randomness_kmac_input_accounting:
        PrivateRandomnessKmacInputClassAccounting,
}

impl SelectedActionProofAccounting {
    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) fn variant_applications(&self) -> &[SelectedActionProofVariantAccounting] {
        &self.variant_applications
    }

    pub(crate) fn categories(&self) -> &[SelectedProofCategoryByteAccounting] {
        &self.categories
    }

    pub(crate) fn category(
        &self,
        category: SelectedProofCorpusCategory,
    ) -> Option<&SelectedProofCategoryByteAccounting> {
        self.categories
            .iter()
            .find(|accounting| accounting.category() == category)
    }

    pub(crate) const fn physical_proof_object_count(&self) -> u32 {
        self.physical_proof_object_count
    }

    pub(crate) const fn logical_relation_application_count(&self) -> u32 {
        self.logical_relation_application_count
    }

    pub(crate) const fn proof_byte_length(&self) -> u64 {
        self.proof_byte_length
    }

    pub(crate) const fn component_byte_lengths(&self) -> SelectedProofComponentByteLengths {
        self.component_byte_lengths
    }

    pub(crate) const fn secret_leaf_population_accounting(
        &self,
    ) -> SelectedSecretLeafPopulationAccounting {
        self.secret_leaf_population_accounting
    }

    pub(crate) const fn ceremony_private_randomness_kmac_input_accounting(
        &self,
    ) -> PrivateRandomnessKmacInputClassAccounting {
        self.ceremony_private_randomness_kmac_input_accounting
    }

    pub(crate) const fn proof_privacy_private_randomness_kmac_input_accounting(
        &self,
    ) -> PrivateRandomnessKmacInputClassAccounting {
        self.proof_privacy_private_randomness_kmac_input_accounting
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofByteAccounting {
    variant_ceilings: Vec<SelectedProofVariantByteCeiling>,
    actions: Vec<SelectedActionProofAccounting>,
    target_release_stream_buffers: SelectedTargetReleaseStreamBufferAccounting,
}

impl SelectedProofByteAccounting {
    pub(crate) fn variant_ceilings(&self) -> &[SelectedProofVariantByteCeiling] {
        &self.variant_ceilings
    }

    pub(crate) fn actions(&self) -> &[SelectedActionProofAccounting] {
        &self.actions
    }

    pub(crate) fn action_ceremony_private_randomness_kmac_input_accounting(
        &self,
        top_count: u16,
    ) -> Option<PrivateRandomnessKmacInputClassAccounting> {
        self.actions
            .iter()
            .find(|action| action.top_count() == top_count)
            .map(SelectedActionProofAccounting::ceremony_private_randomness_kmac_input_accounting)
    }

    pub(crate) fn action_proof_privacy_private_randomness_kmac_input_accounting(
        &self,
        top_count: u16,
    ) -> Option<PrivateRandomnessKmacInputClassAccounting> {
        self.actions
            .iter()
            .find(|action| action.top_count() == top_count)
            .map(
                SelectedActionProofAccounting::proof_privacy_private_randomness_kmac_input_accounting,
            )
    }

    pub(crate) const fn target_release_stream_buffers(
        &self,
    ) -> SelectedTargetReleaseStreamBufferAccounting {
        self.target_release_stream_buffers
    }

    pub(crate) fn maximum_proof_object_count(&self) -> u32 {
        self.actions
            .iter()
            .map(SelectedActionProofAccounting::physical_proof_object_count)
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn maximum_logical_relation_application_count(&self) -> u32 {
        self.actions
            .iter()
            .map(SelectedActionProofAccounting::logical_relation_application_count)
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn maximum_proof_byte_length(&self) -> u64 {
        self.actions
            .iter()
            .map(SelectedActionProofAccounting::proof_byte_length)
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn maximum_variant_proof_byte_length(&self) -> u64 {
        self.variant_ceilings
            .iter()
            .map(SelectedProofVariantByteCeiling::proof_byte_length)
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn ballot_proof_byte_length(&self) -> Option<u64> {
        self.variant_ceilings
            .iter()
            .find(|ceiling| {
                ceiling.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
            })
            .map(SelectedProofVariantByteCeiling::proof_byte_length)
    }
}

pub(crate) fn selected_target_release_stream_buffer_accounting()
-> Result<SelectedTargetReleaseStreamBufferAccounting, SelectedProofAccountingError> {
    let canonical_role_stream_byte_length = u64::try_from(
        selected_target_partial_decryption_stream_byte_length()
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let canonical_pair_wire_byte_length = u64::try_from(
        selected_target_paired_partial_decryption_stream_byte_length()
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let verification_decoded_residue_byte_length = u64::try_from(
        selected_target_paired_partial_decryption_residue_byte_length()
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    if canonical_role_stream_byte_length
        .checked_mul(2)
        .is_none_or(|expected_pair_length| expected_pair_length != canonical_pair_wire_byte_length)
        || canonical_role_stream_byte_length
            > u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
        || canonical_pair_wire_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || verification_decoded_residue_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }
    Ok(SelectedTargetReleaseStreamBufferAccounting {
        canonical_role_stream_byte_length,
        canonical_pair_wire_byte_length,
        generation_retained_canonical_byte_length: canonical_pair_wire_byte_length,
        verification_decoded_residue_byte_length,
        full_stream_copy_count: 0,
        full_stream_copy_byte_length: 0,
        maximum_full_stream_copied_buffer_byte_length: 0,
    })
}

pub(crate) fn selected_proof_byte_accounting()
-> Result<SelectedProofByteAccounting, SelectedProofAccountingError> {
    let target_release_stream_buffers = selected_target_release_stream_buffer_accounting()?;
    let proof_profile =
        selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let key_positions = selected_evaluator_program_set()
        .and_then(|program| program.key_positions())
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    if key_positions.streams().len() != usize::from(FOUNDATION_PROFILE.option_count) {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let mut round_by_round_theorem_inputs_by_selector = BTreeMap::new();
    for theorem_input in selected_relation_application_round_by_round_theorem_inputs()
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
    {
        let selector = (
            theorem_input.application_statement_schema_identifier(),
            theorem_input.schedule_position(),
            theorem_input.top_count(),
        );
        if round_by_round_theorem_inputs_by_selector
            .insert(selector, theorem_input)
            .is_some()
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
    }

    let mut variant_ceilings = Vec::new();
    for relation_plan in proof_profile.relation_plans() {
        let application_statement_schema_identifier =
            relation_plan.application_statement_schema_identifier();
        let (canonical_relation_plan_byte_length, canonical_relation_plan_hash) = relation_plan
            .compiled_plan()
            .canonical_byte_length_and_hash()
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
        let relation_context =
            selected_relation_plan_check_context(application_statement_schema_identifier)
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let committed_material_source_provider_memory_accounting = match
            application_statement_schema_identifier
        {
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                let relation_input = selected_committed_material_relation_plan_input()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let accounting = if application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                {
                    vss_share_linkage_source_provider_memory_accounting(
                        &relation_input,
                        &relation_context,
                        relation_plan.compiled_plan(),
                    )
                } else {
                    aggregate_threshold_share_source_provider_memory_accounting(
                        &relation_input,
                        &relation_context,
                        relation_plan.compiled_plan(),
                    )
                }
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                if accounting.preparation_peak_resident_byte_length()
                    > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                    || accounting.construction_peak_resident_byte_length()
                        > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                {
                    return Err(SelectedProofAccountingError::ResourcePlanning);
                }
                Some(accounting)
            }
            _ => None,
        };
        for variant in relation_plan.compiled_plan().variants() {
            let source_polynomial_provider_memory_accounting = match
                application_statement_schema_identifier
            {
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
                    Some(SelectedSourcePolynomialProviderMemoryAccounting::BallotValidity(
                        selected_ballot_validity_carrier_buffer_accounting()
                            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
                    ))
                }
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                    Some(SelectedSourcePolynomialProviderMemoryAccounting::EvaluatorAggregate(
                        evaluator_aggregate_source_provider_memory_accounting(
                            variant,
                            &relation_context,
                        )
                        .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
                    ))
                }
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                    Some(SelectedSourcePolynomialProviderMemoryAccounting::CommittedMaterial(
                        committed_material_source_provider_memory_accounting
                            .ok_or(SelectedProofAccountingError::ResourcePlanning)?,
                    ))
                }
                _ => None,
            };
            let canonical_variant_bytes = variant
                .canonical_bytes()
                .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
            let canonical_variant_byte_length = u64::try_from(canonical_variant_bytes.len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let canonical_variant_hash = variant
                .canonical_hash()
                .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
            let round_by_round_theorem_input = round_by_round_theorem_inputs_by_selector
                .remove(&(
                    application_statement_schema_identifier,
                    variant.schedule_position(),
                    variant.top_count(),
                ))
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            let statement_context = SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                variant.schedule_position(),
                variant.top_count(),
            );
            let statement_bytes = canonical_selected_application_statement_for_ceiling(
                application_statement_schema_identifier,
                statement_context,
            )
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
            let ballot_ciphertext_readback_memory_accounting =
                if application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                {
                    let SelectedSourcePolynomialProviderMemoryAccounting::BallotValidity(
                        carrier_accounting,
                    ) = source_polynomial_provider_memory_accounting
                        .ok_or(SelectedProofAccountingError::ResourcePlanning)?
                    else {
                        return Err(SelectedProofAccountingError::ResourcePlanning);
                    };
                    Some(selected_ballot_ciphertext_readback_memory_accounting(
                        u64::try_from(statement_bytes.len())
                            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                        carrier_accounting,
                    )?)
                } else {
                    None
                };
            let logical_relation_count = selected_logical_relation_count(
                application_statement_schema_identifier,
                &statement_bytes,
                statement_context,
                variant.top_count(),
            )?;
            let mask_coordinate_consumption = selected_mask_coordinate_consumption(
                application_statement_schema_identifier,
                variant,
            )?;
            let checkpoint_custody_requirement =
                common_proof_generation_checkpoint_custody_requirement_for_variant(variant)
                    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
            let checkpoint_cursor_manifest_requirement =
                checkpoint_custody_requirement.cursor_manifest_requirement();
            let expected_logical_cursor_count = mask_coordinate_consumption
                .total_mask_count()
                .checked_add(u32::from(
                    variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing,
                ))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            if checkpoint_cursor_manifest_requirement.logical_cursor_count()
                != expected_logical_cursor_count
                || !checkpoint_custody_requirement.fits_absolute_bounds()
            {
                return Err(SelectedProofAccountingError::ResourcePlanning);
            }
            let transport_sizing = selected_proof_transport_sizing(
                application_statement_schema_identifier,
                statement_bytes,
                variant,
                &relation_context,
            )?;
            let verifier_hash_equation_ledger = verifier_hash_equation_ledger(
                &transport_sizing.transcript_schedule,
                &transport_sizing.ceiling,
                transport_sizing.layout.catalog(),
            )
            .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
            let resident_memory_requirement = common_proof_resident_memory_requirement(
                variant,
                &relation_context,
                &transport_sizing.transcript_schedule,
                transport_sizing.layout.catalog(),
                application_statement_schema_identifier,
                u64::try_from(transport_sizing.ceiling.canonical_header_byte_length())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                transport_sizing.maximum_prefetched_query_byte_length,
                u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
                u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            )
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
            let resident_memory_phase_ceilings = selected_resident_memory_phase_ceilings(
                &resident_memory_requirement,
                checkpoint_custody_requirement,
                transport_sizing.transcript_schedule.fri_fold_count(),
                source_polynomial_provider_memory_accounting,
                ballot_ciphertext_readback_memory_accounting,
            )?;
            let external_memory_requirement = common_proof_external_memory_requirement(
                variant,
                &relation_context,
                transport_sizing.layout.catalog(),
                &transport_sizing.transcript_schedule,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            )
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
            let bound_tree_count = u32::try_from(
                transport_sizing
                    .layout
                    .catalog()
                    .entries()
                    .iter()
                    .filter(|entry| entry.source() == ProofTreeCatalogSource::RelationBoundPublic)
                    .count(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            if application_statement_schema_identifier
                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                && logical_relation_count != bound_tree_count
            {
                return Err(SelectedProofAccountingError::InvalidTreeGeometry);
            }
            let relation_column_count = u32::try_from(variant.ordered_columns().len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let integer_lift_batch_count =
                u32::try_from(variant.ordered_integer_lift_batches().len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let integer_lift_component_count = variant
                .ordered_integer_lift_batches()
                .iter()
                .try_fold(0_u32, |count, batch| {
                    count
                        .checked_add(
                            u32::try_from(batch.ordered_components.len())
                                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                        )
                        .ok_or(SelectedProofAccountingError::CountOverflow)
                })?;
            let coefficient_local_identity_batch_count =
                u32::try_from(variant.ordered_coefficient_local_identity_batches().len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let coefficient_local_residual_count = variant
                .ordered_coefficient_local_identity_batches()
                .iter()
                .try_fold(0_u32, |count, batch| {
                    count
                        .checked_add(
                            u32::try_from(batch.ordered_residuals.len())
                                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                        )
                        .ok_or(SelectedProofAccountingError::CountOverflow)
                })?;
            let opening_point_count = u32::try_from(variant.ordered_opening_points().len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let opening_claim_count = u32::try_from(variant.ordered_opening_claims().len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let proof_local_full_salted_leaf_count = transport_sizing
                .tree_ceilings
                .iter()
                .filter(|tree| {
                    tree.leaf_visibility() == ProofLeafVisibility::SecretBearing
                        && !tree.requires_persistent_leaf_salt()
                })
                .try_fold(0_u64, |count, tree| {
                    count
                        .checked_add(tree.leaf_count())
                        .ok_or(SelectedProofAccountingError::CountOverflow)
                })?;
            let proof_private_randomness_kmac_input_accounting =
                common_proof_private_randomness_kmac_input_accounting(
                    application_statement_schema_identifier,
                    variant,
                    proof_local_full_salted_leaf_count,
                )
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
            let selected_variant_ceiling = SelectedProofVariantByteCeiling {
                application_statement_schema_identifier,
                schedule_position: variant.schedule_position(),
                top_count: variant.top_count(),
                proof_privacy_mode: variant.proof_privacy_mode(),
                canonical_relation_plan_byte_length,
                canonical_relation_plan_hash,
                canonical_variant_byte_length,
                canonical_variant_hash,
                round_by_round_theorem_input,
                trace_domain_size: variant.trace_domain_size(),
                evaluation_domain_size: variant.evaluation_domain_size(),
                opening_degree_bound_exclusive: variant.opening_degree_bound_exclusive(),
                relation_column_count,
                integer_lift_batch_count,
                integer_lift_component_count,
                coefficient_local_identity_batch_count,
                coefficient_local_residual_count,
                opening_point_count,
                opening_claim_count,
                logical_relation_count,
                bound_tree_count,
                proof_byte_length: transport_sizing.proof_byte_length,
                component_byte_lengths: transport_sizing.ceiling.component_byte_lengths(),
                mask_coordinate_consumption,
                proof_private_randomness_kmac_input_accounting,
                checkpoint_custody_requirement,
                tree_ceilings: transport_sizing.tree_ceilings,
                maximum_prefetched_query_byte_length: transport_sizing
                    .maximum_prefetched_query_byte_length,
                verifier_hash_equation_ledger,
                source_polynomial_provider_memory_accounting,
                ballot_ciphertext_readback_memory_accounting,
                resident_memory_requirement,
                resident_memory_phase_ceilings,
                external_memory_requirement,
            };
            require_selected_variant_absolute_resource_bounds(&selected_variant_ceiling)?;
            variant_ceilings.push(selected_variant_ceiling);
        }
    }

    if !round_by_round_theorem_inputs_by_selector.is_empty() {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    require_selected_variant_selector_inventory(&variant_ceilings, &key_positions)?;
    let application_slot_ceilings = selected_proof_application_slot_ceilings()
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    if application_slot_ceilings.family_ceiling(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ) != Some(1)
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let mut actions = Vec::new();
    let mut observed_top_counts = BTreeSet::new();
    for stream_positions in key_positions.streams() {
        if !observed_top_counts.insert(stream_positions.top_count()) {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        actions.push(selected_action_proof_accounting(
            &variant_ceilings,
            &application_slot_ceilings,
            proof_profile.root_compatibility_edges(),
            stream_positions.top_count(),
        )?);
    }
    if observed_top_counts.len() != usize::from(FOUNDATION_PROFILE.option_count) {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let proof_accounting = SelectedProofByteAccounting {
        variant_ceilings,
        actions,
        target_release_stream_buffers,
    };
    super::qrom_soundness::require_selected_application_soundness_bounds(&proof_accounting)
        .map_err(|_| SelectedProofAccountingError::ApplicationSoundness)?;
    Ok(proof_accounting)
}

fn require_selected_variant_selector_inventory(
    variant_ceilings: &[SelectedProofVariantByteCeiling],
    key_positions: &EvaluatorProgramKeyPositions,
) -> Result<(), SelectedProofAccountingError> {
    let mut observed_selectors = BTreeMap::<u16, BTreeSet<(Option<u32>, Option<u16>)>>::new();
    for variant in variant_ceilings {
        if !observed_selectors
            .entry(variant.application_statement_schema_identifier())
            .or_default()
            .insert((variant.schedule_position(), variant.top_count()))
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
    }

    let unselected = BTreeSet::from([(None, None)]);
    let mut expected_selectors = BTreeMap::new();
    for schema_identifier in [
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    ] {
        expected_selectors.insert(schema_identifier, unselected.clone());
    }

    let relinearization_selectors = (0..key_positions.relinearization_catalog_levels().len())
        .map(|schedule_position| {
            u32::try_from(schedule_position)
                .map(|schedule_position| (Some(schedule_position), None))
                .map_err(|_| SelectedProofAccountingError::CountOverflow)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if relinearization_selectors.is_empty() {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    for schema_identifier in [
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    ] {
        expected_selectors.insert(schema_identifier, relinearization_selectors.clone());
    }

    let galois_selectors = selected_galois_key_share_batch_schedule()
        .into_iter()
        .map(|schedule_position| (Some(schedule_position), None))
        .collect::<BTreeSet<_>>();
    if galois_selectors.is_empty() {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    expected_selectors.insert(
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        galois_selectors,
    );

    let evaluator_selectors = key_positions
        .streams()
        .iter()
        .map(|stream| (None, Some(stream.top_count())))
        .collect::<BTreeSet<_>>();
    if evaluator_selectors.len() != usize::from(FOUNDATION_PROFILE.option_count)
        || evaluator_selectors
            != (1..=FOUNDATION_PROFILE.option_count)
                .map(|top_count| (None, Some(top_count)))
                .collect::<BTreeSet<_>>()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    expected_selectors.insert(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        evaluator_selectors,
    );

    if observed_selectors != expected_selectors {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    Ok(())
}

fn selected_proof_transport_sizing(
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: Vec<u8>,
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<SelectedProofTransportSizing, SelectedProofAccountingError> {
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let proof_header_bytes = proof_header
        .encode()
        .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let transcript_schedule = variant
        .common_proof_transcript_schedule(relation_context)
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let relation_trees = selected_relation_tree_inputs(variant)?;
    let catalog = build_complete_proof_tree_catalog(
        ProofTreeCatalogInput {
            suite_identifier: [0; Hash512::BYTE_LENGTH],
            canonical_proof_object_header_bytes: proof_header_bytes.clone(),
            application_statement_schema_identifier,
            proof_field_index: 0,
            evaluation_domain_size: variant.evaluation_domain_size(),
            relation_trees,
        },
        &transcript_schedule,
    )
    .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
    let layout = ProofBodyLayout::new(
        catalog,
        &transcript_schedule,
        transcript_schedule.terminal_coefficient_count(),
    )
    .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
    let ceiling = canonical_common_proof_byte_length_ceiling(proof_header_bytes.len(), &layout)
        .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
    require_selected_query_ceiling_geometry(
        transcript_schedule.unique_query_count(),
        transcript_schedule.query_orbit_count(),
        &layout,
        &ceiling,
    )?;
    let proof_byte_length = require_selected_proof_byte_length(
        application_statement_schema_identifier,
        variant.schedule_position(),
        variant.top_count(),
        ceiling.proof_byte_length(),
    )?;
    let tree_ceilings = selected_tree_byte_ceilings(variant, &layout, &ceiling)?;
    let maximum_prefetched_query_byte_length =
        tree_ceilings.iter().try_fold(0_u64, |maximum, tree| {
            tree.opened_row_payload_byte_length()
                .checked_add(tree.authentication_frontier_digest_byte_length())
                .map(|length| maximum.max(length))
                .ok_or(SelectedProofAccountingError::CountOverflow)
        })?;
    if maximum_prefetched_query_byte_length == 0 {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    Ok(SelectedProofTransportSizing {
        ceiling,
        layout,
        maximum_prefetched_query_byte_length,
        proof_byte_length,
        transcript_schedule,
        tree_ceilings,
    })
}

pub(crate) fn selected_proof_runtime_limits(
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
    variant: &RelationPlanVariant,
) -> Result<CommonProofRuntimeLimits, SelectedProofAccountingError> {
    let relation_context =
        selected_relation_plan_check_context(application_statement_schema_identifier)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let transport_sizing = selected_proof_transport_sizing(
        application_statement_schema_identifier,
        canonical_application_statement_bytes.to_vec(),
        variant,
        &relation_context,
    )?;
    CommonProofRuntimeLimits::new(
        usize::try_from(transport_sizing.proof_byte_length)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        transport_sizing.maximum_prefetched_query_byte_length,
    )
    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)
}

fn selected_mask_coordinate_consumption(
    application_statement_schema_identifier: u16,
    variant: &RelationPlanVariant,
) -> Result<SelectedMaskCoordinateConsumption, SelectedProofAccountingError> {
    let mask_coordinate_consumption = derive_selected_mask_coordinate_consumption(variant)?;
    for mask in variant.ordered_masks() {
        let purpose_class = mask.mask_coordinate().purpose_class();
        if !common_proof_randomness_purpose_is_assigned(
            application_statement_schema_identifier,
            purpose_class,
        ) {
            return Err(SelectedProofAccountingError::UnassignedMaskPurposeClass {
                application_statement_schema_identifier,
                purpose_class,
            });
        }
    }
    Ok(mask_coordinate_consumption)
}

fn derive_selected_mask_coordinate_consumption(
    variant: &RelationPlanVariant,
) -> Result<SelectedMaskCoordinateConsumption, SelectedProofAccountingError> {
    let mut consumed_mask_coordinates = BTreeSet::new();
    let mut trace_mask_ordinals = BTreeSet::new();
    let mut quotient_mask_ordinals = BTreeSet::new();
    let mut opening_mask_ordinals = BTreeSet::new();
    for mask in variant.ordered_masks() {
        let mask_coordinate = mask.mask_coordinate();
        let purpose_class = mask_coordinate.purpose_class();
        let mask_ordinal = mask_coordinate.mask_ordinal();
        if !consumed_mask_coordinates.insert((purpose_class, mask_ordinal)) {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        let ordinal_class = match mask.mask_kind() {
            RelationMaskKind::Trace => &mut trace_mask_ordinals,
            RelationMaskKind::Telescoping => &mut quotient_mask_ordinals,
            RelationMaskKind::OpeningBatch => &mut opening_mask_ordinals,
        };
        if !ordinal_class.insert(mask_ordinal) {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
    }
    let trace_masks =
        selected_mask_ordinal_consumption(RelationMaskKind::Trace as u16, &trace_mask_ordinals)?;
    let quotient_masks = selected_mask_ordinal_consumption(
        RelationMaskKind::Telescoping as u16,
        &quotient_mask_ordinals,
    )?;
    let opening_masks = selected_mask_ordinal_consumption(
        RelationMaskKind::OpeningBatch as u16,
        &opening_mask_ordinals,
    )?;
    let total_mask_count = trace_masks
        .consumed_mask_count()
        .checked_add(quotient_masks.consumed_mask_count())
        .and_then(|count| count.checked_add(opening_masks.consumed_mask_count()))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    if usize::try_from(total_mask_count)
        .ok()
        .is_none_or(|count| count != consumed_mask_coordinates.len())
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    Ok(SelectedMaskCoordinateConsumption {
        trace_masks,
        quotient_masks,
        opening_masks,
        total_mask_count,
    })
}

fn selected_mask_ordinal_consumption(
    purpose_class: u16,
    consumed_mask_ordinals: &BTreeSet<u32>,
) -> Result<SelectedMaskOrdinalConsumption, SelectedProofAccountingError> {
    let consumption = SelectedMaskOrdinalConsumption {
        purpose_class,
        first_consumed_mask_ordinal: consumed_mask_ordinals.first().copied(),
        last_consumed_mask_ordinal: consumed_mask_ordinals.last().copied(),
        consumed_mask_count: u32::try_from(consumed_mask_ordinals.len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
    };
    match consumption.consumed_mask_count() {
        0 if consumption.first_consumed_mask_ordinal().is_none()
            && consumption.last_consumed_mask_ordinal().is_none() => {}
        consumed_mask_count
            if consumption.first_consumed_mask_ordinal() == Some(0)
                && consumption
                    .last_consumed_mask_ordinal()
                    .and_then(|ordinal| ordinal.checked_add(1))
                    == Some(consumed_mask_count) => {}
        _ => return Err(SelectedProofAccountingError::InvalidProfile),
    }
    Ok(consumption)
}

fn selected_logical_relation_count(
    application_statement_schema_identifier: u16,
    statement_bytes: &[u8],
    statement_context: SelectedApplicationStatementContext,
    top_count: Option<u16>,
) -> Result<u32, SelectedProofAccountingError> {
    let logical_relation_count = match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            let statement = decode_selected_application_statement(
                statement_bytes,
                application_statement_schema_identifier,
                statement_context,
            )
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
            selected_galois_key_share_contribution_roots(&statement)
                .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?
                .len()
        }
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            selected_evaluator_entry_positions(
                top_count.ok_or(SelectedProofAccountingError::InvalidProfile)?,
            )
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
            .len()
            .checked_mul(usize::from(FOUNDATION_PROFILE.participant_count) + 1)
            .ok_or(SelectedProofAccountingError::CountOverflow)?
        }
        _ => 1,
    };
    u32::try_from(logical_relation_count)
        .ok()
        .filter(|count| *count != 0)
        .ok_or(SelectedProofAccountingError::CountOverflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SelectedPersistentSecretRootIdentity {
    RootCompatibilityComponent(RelationRootEndpoint),
    UnconnectedApplicationRoot {
        variant_catalog_index: usize,
        tree_catalog_index: u16,
        application_ordinal: u32,
    },
}

fn selected_committed_material_root_components(
    root_compatibility_edges: &[super::RelationRootCompatibilityEdge],
) -> BTreeMap<RelationRootEndpoint, RelationRootEndpoint> {
    let mut adjacency = BTreeMap::<RelationRootEndpoint, BTreeSet<RelationRootEndpoint>>::new();
    for edge in root_compatibility_edges
        .iter()
        .copied()
        .filter(|edge| edge.construction_kind() == RelationRootConstructionKind::CommittedMaterial)
    {
        let producer = edge.producer_endpoint();
        let consumer = edge.consumer_endpoint();
        adjacency.entry(producer).or_default().insert(consumer);
        adjacency.entry(consumer).or_default().insert(producer);
    }

    let mut unvisited = adjacency.keys().copied().collect::<BTreeSet<_>>();
    let mut components = BTreeMap::new();
    while let Some(component_start) = unvisited.first().copied() {
        let mut stack = vec![component_start];
        let mut component = BTreeSet::new();
        while let Some(endpoint) = stack.pop() {
            if !unvisited.remove(&endpoint) {
                continue;
            }
            component.insert(endpoint);
            if let Some(neighbors) = adjacency.get(&endpoint) {
                stack.extend(neighbors.iter().copied());
            }
        }
        let component_identity = component_start;
        for endpoint in component {
            components.insert(endpoint, component_identity);
        }
    }
    components
}

fn selected_secret_leaf_population_accounting(
    variant_applications: &[SelectedActionProofVariantAccounting],
    variant_ceilings: &[SelectedProofVariantByteCeiling],
    root_compatibility_edges: &[super::RelationRootCompatibilityEdge],
) -> Result<SelectedSecretLeafPopulationAccounting, SelectedProofAccountingError> {
    let committed_material_root_components =
        selected_committed_material_root_components(root_compatibility_edges);
    let mut persistent_root_leaf_counts =
        BTreeMap::<SelectedPersistentSecretRootIdentity, u64>::new();
    let mut proof_local_physical_root_count = 0_u64;
    let mut proof_local_full_salted_leaf_count = 0_u64;
    let mut proof_local_full_secret_tree_hash_equation_count = 0_u64;
    let mut proof_view_full_salted_leaf_occurrence_count = 0_u64;
    let mut opened_salted_leaf_occurrence_count = 0_u64;
    let mut hidden_salted_leaf_occurrence_count = 0_u64;

    for application in variant_applications {
        let variant = variant_ceilings
            .get(application.variant_catalog_index())
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let multiplicity = u64::from(application.application_multiplicity());
        let persistent_trees = variant
            .tree_ceilings()
            .iter()
            .copied()
            .filter(|tree| tree.requires_persistent_leaf_salt())
            .collect::<Vec<_>>();
        let persistent_root_count = u64::try_from(persistent_trees.len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let persistent_full_salted_leaf_count =
            persistent_trees.iter().try_fold(0_u64, |count, tree| {
                count
                    .checked_add(tree.leaf_count())
                    .ok_or(SelectedProofAccountingError::CountOverflow)
            })?;
        let persistent_full_secret_tree_hash_equation_count =
            persistent_trees.iter().try_fold(0_u64, |count, tree| {
                let tree_equation_count = tree
                    .leaf_count()
                    .checked_mul(2)
                    .and_then(|value| value.checked_sub(1))
                    .ok_or(SelectedProofAccountingError::CountOverflow)?;
                count
                    .checked_add(tree_equation_count)
                    .ok_or(SelectedProofAccountingError::CountOverflow)
            })?;
        let ledger = variant.verifier_hash_equation_ledger();
        let proof_local_root_count = ledger
            .secret_bearing_tree_root_count()
            .checked_sub(persistent_root_count)
            .ok_or(SelectedProofAccountingError::InvalidTreeGeometry)?;
        let proof_local_leaf_count = ledger
            .full_salted_leaf_count()
            .checked_sub(persistent_full_salted_leaf_count)
            .ok_or(SelectedProofAccountingError::InvalidTreeGeometry)?;
        let proof_local_tree_equation_count = ledger
            .full_secret_tree_hash_equation_count()
            .checked_sub(persistent_full_secret_tree_hash_equation_count)
            .ok_or(SelectedProofAccountingError::InvalidTreeGeometry)?;
        proof_local_physical_root_count = proof_local_physical_root_count
            .checked_add(
                proof_local_root_count
                    .checked_mul(multiplicity)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
            )
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        proof_local_full_salted_leaf_count = proof_local_full_salted_leaf_count
            .checked_add(
                proof_local_leaf_count
                    .checked_mul(multiplicity)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
            )
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        proof_local_full_secret_tree_hash_equation_count =
            proof_local_full_secret_tree_hash_equation_count
                .checked_add(
                    proof_local_tree_equation_count
                        .checked_mul(multiplicity)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?,
                )
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        proof_view_full_salted_leaf_occurrence_count = proof_view_full_salted_leaf_occurrence_count
            .checked_add(
                ledger
                    .full_salted_leaf_count()
                    .checked_mul(multiplicity)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
            )
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        opened_salted_leaf_occurrence_count = opened_salted_leaf_occurrence_count
            .checked_add(
                ledger
                    .opened_salted_leaf_count()
                    .checked_mul(multiplicity)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
            )
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        hidden_salted_leaf_occurrence_count = hidden_salted_leaf_occurrence_count
            .checked_add(
                ledger
                    .hidden_salted_leaf_count()
                    .checked_mul(multiplicity)
                    .ok_or(SelectedProofAccountingError::CountOverflow)?,
            )
            .ok_or(SelectedProofAccountingError::CountOverflow)?;

        for tree in persistent_trees {
            if tree.leaf_visibility() != ProofLeafVisibility::SecretBearing
                || tree.bound_tree_construction_kind()
                    != Some(BoundTreeConstructionKind::CommittedMaterial)
                || tree.bound_root_use().is_none()
            {
                return Err(SelectedProofAccountingError::InvalidTreeGeometry);
            }
            let root_source_ordinal = tree
                .bound_root_source_ordinal()
                .ok_or(SelectedProofAccountingError::InvalidTreeGeometry)?;
            let matching_endpoints = committed_material_root_components
                .keys()
                .copied()
                .filter(|endpoint| {
                    endpoint.application_statement_schema_identifier()
                        == application.application_statement_schema_identifier()
                        && endpoint.schedule_position() == application.schedule_position()
                        && endpoint.top_count() == application.top_count()
                        && endpoint.verifier_source_ordinal() == root_source_ordinal
                })
                .collect::<Vec<_>>();
            if !matching_endpoints.is_empty()
                && matching_endpoints.len()
                    != usize::try_from(application.application_multiplicity())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?
            {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            if matching_endpoints.is_empty() {
                for application_ordinal in 0..application.application_multiplicity() {
                    let identity =
                        SelectedPersistentSecretRootIdentity::UnconnectedApplicationRoot {
                            variant_catalog_index: application.variant_catalog_index(),
                            tree_catalog_index: tree.tree_catalog_index(),
                            application_ordinal,
                        };
                    if persistent_root_leaf_counts
                        .insert(identity, tree.leaf_count())
                        .is_some()
                    {
                        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
                    }
                }
            } else {
                for endpoint in matching_endpoints {
                    let component_identity = *committed_material_root_components
                        .get(&endpoint)
                        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
                    let identity = SelectedPersistentSecretRootIdentity::RootCompatibilityComponent(
                        component_identity,
                    );
                    if persistent_root_leaf_counts
                        .insert(identity, tree.leaf_count())
                        .is_some_and(|leaf_count| leaf_count != tree.leaf_count())
                    {
                        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
                    }
                }
            }
        }
    }

    if proof_view_full_salted_leaf_occurrence_count
        != opened_salted_leaf_occurrence_count
            .checked_add(hidden_salted_leaf_occurrence_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    let persistent_physical_root_count = u64::try_from(persistent_root_leaf_counts.len())
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let persistent_full_salted_leaf_count =
        persistent_root_leaf_counts
            .values()
            .try_fold(0_u64, |count, leaf_count| {
                count
                    .checked_add(*leaf_count)
                    .ok_or(SelectedProofAccountingError::CountOverflow)
            })?;
    let persistent_full_secret_tree_hash_equation_count = persistent_root_leaf_counts
        .values()
        .try_fold(0_u64, |count, leaf_count| {
            count
                .checked_add(
                    leaf_count
                        .checked_mul(2)
                        .and_then(|value| value.checked_sub(1))
                        .ok_or(SelectedProofAccountingError::CountOverflow)?,
                )
                .ok_or(SelectedProofAccountingError::CountOverflow)
        })?;
    Ok(SelectedSecretLeafPopulationAccounting {
        proof_local_physical_root_count,
        persistent_physical_root_count,
        physical_root_count: proof_local_physical_root_count
            .checked_add(persistent_physical_root_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?,
        proof_local_full_salted_leaf_count,
        persistent_full_salted_leaf_count,
        distinct_full_salted_leaf_count: proof_local_full_salted_leaf_count
            .checked_add(persistent_full_salted_leaf_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?,
        proof_view_full_salted_leaf_occurrence_count,
        opened_salted_leaf_occurrence_count,
        hidden_salted_leaf_occurrence_count,
        distinct_full_secret_tree_hash_equation_count:
            proof_local_full_secret_tree_hash_equation_count
                .checked_add(persistent_full_secret_tree_hash_equation_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
    })
}

fn selected_tree_byte_ceilings(
    variant: &RelationPlanVariant,
    layout: &ProofBodyLayout,
    ceiling: &super::CommonProofByteLengthCeiling,
) -> Result<Vec<SelectedProofTreeByteCeiling>, SelectedProofAccountingError> {
    if layout.catalog().entries().len() != ceiling.query_trees().len() {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    layout
        .catalog()
        .entries()
        .iter()
        .zip(ceiling.query_trees())
        .enumerate()
        .map(|(catalog_index, (entry, tree))| {
            if usize::from(entry.tree_catalog_index()) != catalog_index
                || entry.tree_catalog_index() != tree.tree_catalog_index()
                || entry.source() != tree.source()
            {
                return Err(SelectedProofAccountingError::InvalidTreeGeometry);
            }
            let row_width = u32::try_from(
                entry
                    .materialized_row_width()
                    .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?,
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let leaf_visibility = entry.materialized_leaf_visibility();
            let (bound_tree_construction_kind, bound_root_source_ordinal, bound_root_use) =
                match entry.source() {
                    ProofTreeCatalogSource::RelationBoundPublic => {
                        let Some(RelationTreeDescriptor::BoundPublic {
                            construction_kind,
                            expected_root_source_ordinal,
                            root_use,
                            ..
                        }) = variant.ordered_trees().get(catalog_index)
                        else {
                            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
                        };
                        (
                            Some(*construction_kind),
                            Some(*expected_root_source_ordinal),
                            Some(*root_use),
                        )
                    }
                    ProofTreeCatalogSource::RelationProofCreated { .. } => {
                        if !matches!(
                            variant.ordered_trees().get(catalog_index),
                            Some(RelationTreeDescriptor::ProofCreated { .. })
                        ) {
                            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
                        }
                        (None, None, None)
                    }
                    ProofTreeCatalogSource::QuotientComponent { .. }
                    | ProofTreeCatalogSource::OpeningBatchMask
                    | ProofTreeCatalogSource::NonterminalFriLayer { .. } => (None, None, None),
                };
            let opened_row_payload_byte_length =
                u64::try_from(tree.opened_leaf_payload_byte_length())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let authentication_frontier_digest_byte_length =
                u64::try_from(tree.authentication_frontier_digest_byte_length())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let canonical_framing_byte_length = u64::try_from(tree.canonical_framing_byte_length())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let query_record_byte_length = u64::try_from(tree.byte_length())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            if opened_row_payload_byte_length
                .checked_add(authentication_frontier_digest_byte_length)
                .and_then(|length| length.checked_add(canonical_framing_byte_length))
                != Some(query_record_byte_length)
            {
                return Err(SelectedProofAccountingError::InvalidTreeGeometry);
            }
            Ok(SelectedProofTreeByteCeiling {
                tree_catalog_index: tree.tree_catalog_index(),
                source: tree.source(),
                leaf_visibility,
                bound_tree_construction_kind,
                bound_root_source_ordinal,
                bound_root_use,
                requires_persistent_leaf_salt: entry.requires_persistent_leaf_salt(),
                row_width,
                tree_height: tree.tree_height(),
                leaf_count: u64::try_from(tree.leaf_count())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                opened_row_count: u32::try_from(tree.opened_leaf_count_at_ceiling())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                authentication_frontier_node_count: u32::try_from(
                    tree.authentication_frontier_node_count_at_ceiling(),
                )
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                opened_row_payload_byte_length,
                authentication_frontier_digest_byte_length,
                canonical_framing_byte_length,
                query_record_byte_length,
            })
        })
        .collect()
}

fn selected_action_proof_accounting(
    variant_ceilings: &[SelectedProofVariantByteCeiling],
    application_slot_ceilings: &ProofApplicationSlotCeilings,
    root_compatibility_edges: &[super::RelationRootCompatibilityEdge],
    top_count: u16,
) -> Result<SelectedActionProofAccounting, SelectedProofAccountingError> {
    let mut variant_indices_by_family = BTreeMap::<u16, Vec<usize>>::new();
    for (variant_catalog_index, variant) in variant_ceilings.iter().enumerate() {
        if application_slot_ceilings
            .family_ceiling(variant.application_statement_schema_identifier())
            .is_none()
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        variant_indices_by_family
            .entry(variant.application_statement_schema_identifier())
            .or_default()
            .push(variant_catalog_index);
    }
    if variant_indices_by_family.len() != application_slot_ceilings.ordered_family_ceilings().len()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let mut variant_applications = Vec::new();
    let mut physical_proof_object_count = 0_u32;
    let mut logical_relation_application_count = 0_u32;
    let mut proof_byte_length = 0_u64;
    let mut component_byte_lengths = SelectedProofComponentByteLengths::default();
    for family_ceiling in application_slot_ceilings.ordered_family_ceilings() {
        let family_variant_indices = variant_indices_by_family
            .get(&family_ceiling.application_statement_schema_identifier)
            .filter(|indices| !indices.is_empty())
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let has_top_count_selector = family_variant_indices
            .iter()
            .any(|index| variant_ceilings[*index].top_count().is_some());
        if has_top_count_selector {
            if !family_variant_indices.iter().all(|index| {
                variant_ceilings[*index].schedule_position().is_none()
                    && variant_ceilings[*index].top_count().is_some()
            }) {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            let mut selected_indices = family_variant_indices
                .iter()
                .copied()
                .filter(|index| variant_ceilings[*index].top_count() == Some(top_count));
            let selected_index = selected_indices
                .next()
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            if selected_indices.next().is_some() {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            append_action_variant_accounting(
                &mut variant_applications,
                &mut physical_proof_object_count,
                &mut logical_relation_application_count,
                &mut proof_byte_length,
                &mut component_byte_lengths,
                selected_index,
                family_ceiling.application_slot_ceiling,
                &variant_ceilings[selected_index],
            )?;
        } else {
            if family_variant_indices
                .iter()
                .any(|index| variant_ceilings[*index].top_count().is_some())
            {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            let family_variant_count = u32::try_from(family_variant_indices.len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let application_multiplicity = family_ceiling
                .application_slot_ceiling
                .checked_div(family_variant_count)
                .filter(|multiplicity| {
                    *multiplicity != 0
                        && multiplicity
                            .checked_mul(family_variant_count)
                            .is_some_and(|count| count == family_ceiling.application_slot_ceiling)
                })
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            for variant_catalog_index in family_variant_indices {
                append_action_variant_accounting(
                    &mut variant_applications,
                    &mut physical_proof_object_count,
                    &mut logical_relation_application_count,
                    &mut proof_byte_length,
                    &mut component_byte_lengths,
                    *variant_catalog_index,
                    application_multiplicity,
                    &variant_ceilings[*variant_catalog_index],
                )?;
            }
        }
    }
    if physical_proof_object_count != application_slot_ceilings.total_application_slot_ceiling() {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let categories =
        selected_proof_category_byte_accounting(&variant_applications, variant_ceilings)?;
    let secret_leaf_population_accounting = selected_secret_leaf_population_accounting(
        &variant_applications,
        variant_ceilings,
        root_compatibility_edges,
    )?;
    let (
        ceremony_private_randomness_kmac_input_accounting,
        proof_privacy_private_randomness_kmac_input_accounting,
    ) = selected_action_private_randomness_kmac_input_accounting(
        &variant_applications,
        variant_ceilings,
        secret_leaf_population_accounting,
    )?;
    Ok(SelectedActionProofAccounting {
        top_count,
        variant_applications,
        categories,
        physical_proof_object_count,
        logical_relation_application_count,
        proof_byte_length,
        component_byte_lengths,
        secret_leaf_population_accounting,
        ceremony_private_randomness_kmac_input_accounting,
        proof_privacy_private_randomness_kmac_input_accounting,
    })
}

fn selected_action_private_randomness_kmac_input_accounting(
    variant_applications: &[SelectedActionProofVariantAccounting],
    variant_ceilings: &[SelectedProofVariantByteCeiling],
    secret_leaf_population: SelectedSecretLeafPopulationAccounting,
) -> Result<
    (
        PrivateRandomnessKmacInputClassAccounting,
        PrivateRandomnessKmacInputClassAccounting,
    ),
    SelectedProofAccountingError,
> {
    let proof_application_accounting = variant_applications.iter().try_fold(
        PrivateRandomnessKmacInputClassAccounting::zero(),
        |accounting, application| {
            let variant = variant_ceilings
                .get(application.variant_catalog_index())
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            let application_accounting = variant
                .proof_private_randomness_kmac_input_accounting()
                .checked_multiply(u64::from(application.application_multiplicity()))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            accounting
                .checked_add(application_accounting)
                .ok_or(SelectedProofAccountingError::CountOverflow)
        },
    )?;
    let action_root_accounting = selected_action_root_private_randomness_kmac_input_accounting()
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let persistent_material_accounting = maximum_committed_material_kmac_input_accounting(
        selected_committed_material_profile()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?,
        secret_leaf_population.persistent_physical_root_count(),
        secret_leaf_population.persistent_full_salted_leaf_count(),
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let proof_privacy_accounting = action_root_accounting
        .checked_add(proof_application_accounting)
        .and_then(|accounting| accounting.checked_add(persistent_material_accounting))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;

    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let setup_generation_accounting =
        selected_setup_generation_private_randomness_kmac_input_accounting()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
            .checked_multiply(participant_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let aggregate_threshold_share_accounting =
        aggregate_threshold_share_private_randomness_kmac_input_accounting()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
            .checked_multiply(participant_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let setup_transport_accounting =
        selected_setup_transport_private_randomness_kmac_input_accounting()
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let ballot_application_multiplicity = variant_applications
        .iter()
        .filter(|application| {
            application.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
        })
        .try_fold(0_u64, |count, application| {
            count
                .checked_add(u64::from(application.application_multiplicity()))
                .ok_or(SelectedProofAccountingError::CountOverflow)
        })?;
    let ballot_encryption_accounting = ballot_encryption_private_randomness_kmac_input_accounting(
        u64::try_from(POLYNOMIAL_DEGREE)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
    )
    .and_then(|accounting| accounting.checked_multiply(ballot_application_multiplicity))
    .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let target_application_multiplicity = variant_applications
        .iter()
        .filter(|application| {
            application.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
        })
        .try_fold(0_u64, |count, application| {
            count
                .checked_add(u64::from(application.application_multiplicity()))
                .ok_or(SelectedProofAccountingError::CountOverflow)
        })?;
    let target_release_accounting =
        selected_target_release_private_randomness_kmac_input_accounting()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
            .checked_multiply(target_application_multiplicity)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let ceremony_accounting = action_root_accounting
        .checked_add(proof_application_accounting)
        .and_then(|accounting| accounting.checked_add(setup_generation_accounting))
        .and_then(|accounting| accounting.checked_add(aggregate_threshold_share_accounting))
        .and_then(|accounting| accounting.checked_add(setup_transport_accounting))
        .and_then(|accounting| accounting.checked_add(ballot_encryption_accounting))
        .and_then(|accounting| accounting.checked_add(target_release_accounting))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    Ok((ceremony_accounting, proof_privacy_accounting))
}

fn selected_proof_corpus_category(
    application_statement_schema_identifier: u16,
) -> Option<SelectedProofCorpusCategory> {
    match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SelectedProofCorpusCategory::Setup)
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SelectedProofCorpusCategory::Evaluator)
        }
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SelectedProofCorpusCategory::Ballot)
        }
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SelectedProofCorpusCategory::TargetRelease)
        }
        _ => None,
    }
}

fn selected_proof_category_byte_accounting(
    variant_applications: &[SelectedActionProofVariantAccounting],
    variant_ceilings: &[SelectedProofVariantByteCeiling],
) -> Result<Vec<SelectedProofCategoryByteAccounting>, SelectedProofAccountingError> {
    let mut categories = Vec::with_capacity(SelectedProofCorpusCategory::ALL.len());
    for category in SelectedProofCorpusCategory::ALL {
        let mut physical_proof_object_count = 0_u32;
        let mut canonical_proof_byte_length = 0_u64;
        let mut generation_resident_peak_byte_length = 0_u64;
        let mut external_scratch_peak_stored_byte_length = 0_u64;
        let mut external_scratch_total_written_byte_length = 0_u64;
        let mut external_scratch_total_read_byte_length = 0_u64;
        let mut external_scratch_transaction_count = 0_u64;
        let mut maximum_copied_buffer_byte_length = 0_u64;
        for application in variant_applications.iter().filter(|application| {
            selected_proof_corpus_category(application.application_statement_schema_identifier())
                == Some(category)
        }) {
            let variant = variant_ceilings
                .get(application.variant_catalog_index())
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            let multiplicity = u64::from(application.application_multiplicity());
            let external_memory = variant.external_memory_requirement();
            physical_proof_object_count = physical_proof_object_count
                .checked_add(application.physical_proof_object_count())
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            canonical_proof_byte_length = canonical_proof_byte_length
                .checked_add(application.proof_byte_length())
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            generation_resident_peak_byte_length = generation_resident_peak_byte_length
                .max(variant.combined_resident_memory_peak_byte_length());
            external_scratch_peak_stored_byte_length = external_scratch_peak_stored_byte_length
                .max(external_memory.peak_stored_byte_length());
            external_scratch_total_written_byte_length = external_scratch_total_written_byte_length
                .checked_add(
                    external_memory
                        .total_written_byte_length()
                        .checked_mul(multiplicity)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?,
                )
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            external_scratch_total_read_byte_length = external_scratch_total_read_byte_length
                .checked_add(
                    external_memory
                        .total_read_byte_length()
                        .checked_mul(multiplicity)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?,
                )
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            external_scratch_transaction_count = external_scratch_transaction_count
                .checked_add(
                    external_memory
                        .transaction_count()
                        .checked_mul(multiplicity)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?,
                )
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            maximum_copied_buffer_byte_length = maximum_copied_buffer_byte_length.max(
                selected_variant_copied_buffer_requirements(variant)
                    .into_iter()
                    .map(|(_, byte_length)| byte_length)
                    .max()
                    .ok_or(SelectedProofAccountingError::ResourcePlanning)?,
            );
        }
        if physical_proof_object_count == 0 || canonical_proof_byte_length == 0 {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        categories.push(SelectedProofCategoryByteAccounting {
            category,
            physical_proof_object_count,
            canonical_proof_byte_length,
            generation_resident_peak_byte_length,
            external_scratch_peak_stored_byte_length,
            external_scratch_total_written_byte_length,
            external_scratch_total_read_byte_length,
            external_scratch_transaction_count,
            maximum_copied_buffer_byte_length,
            fixed_transport_copies: SelectedProofFixedTransportCopyAccounting {
                generation_pending_chunk_staging_byte_length: canonical_proof_byte_length,
                generation_wasm_to_host_byte_length: canonical_proof_byte_length,
                generation_authenticated_readback_byte_length: canonical_proof_byte_length,
                verification_initial_ingress_byte_length: canonical_proof_byte_length,
            },
        });
    }
    if variant_applications.iter().any(|application| {
        selected_proof_corpus_category(application.application_statement_schema_identifier())
            .is_none()
    }) {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    Ok(categories)
}

#[allow(clippy::too_many_arguments)]
fn append_action_variant_accounting(
    variant_applications: &mut Vec<SelectedActionProofVariantAccounting>,
    physical_proof_object_count: &mut u32,
    logical_relation_application_count: &mut u32,
    proof_byte_length: &mut u64,
    component_byte_lengths: &mut SelectedProofComponentByteLengths,
    variant_catalog_index: usize,
    application_multiplicity: u32,
    variant: &SelectedProofVariantByteCeiling,
) -> Result<(), SelectedProofAccountingError> {
    let variant_logical_relation_application_count = variant
        .logical_relation_count()
        .checked_mul(application_multiplicity)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let variant_proof_byte_length = variant
        .proof_byte_length()
        .checked_mul(u64::from(application_multiplicity))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let variant_component_byte_lengths =
        SelectedProofComponentByteLengths::from_common_proof_components(
            variant.component_byte_lengths(),
        )?
        .checked_multiply(application_multiplicity)?;
    if variant_component_byte_lengths.proof_byte_length() != Some(variant_proof_byte_length) {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    *physical_proof_object_count = physical_proof_object_count
        .checked_add(application_multiplicity)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    *logical_relation_application_count = logical_relation_application_count
        .checked_add(variant_logical_relation_application_count)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    *proof_byte_length = proof_byte_length
        .checked_add(variant_proof_byte_length)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    *component_byte_lengths = component_byte_lengths.checked_add(variant_component_byte_lengths)?;
    variant_applications.push(SelectedActionProofVariantAccounting {
        variant_catalog_index,
        application_statement_schema_identifier: variant.application_statement_schema_identifier(),
        schedule_position: variant.schedule_position(),
        top_count: variant.top_count(),
        application_multiplicity,
        logical_relation_application_count: variant_logical_relation_application_count,
        proof_byte_length: variant_proof_byte_length,
        component_byte_lengths: variant_component_byte_lengths,
    });
    Ok(())
}

fn require_selected_proof_byte_length(
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    proof_byte_length: usize,
) -> Result<u64, SelectedProofAccountingError> {
    if proof_byte_length == 0 || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(SelectedProofAccountingError::ProofByteLengthExceeded {
            application_statement_schema_identifier,
            schedule_position,
            top_count,
            proof_byte_length,
            maximum_proof_byte_length: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        });
    }
    u64::try_from(proof_byte_length).map_err(|_| SelectedProofAccountingError::CountOverflow)
}

fn selected_relation_tree_inputs(
    variant: &RelationPlanVariant,
) -> Result<Vec<RelationProofTreeInput>, SelectedProofAccountingError> {
    variant
        .ordered_trees()
        .iter()
        .map(|tree| match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|column_index| variant.ordered_columns().get(column_index))
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::Prover)
                        })
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                Ok(RelationProofTreeInput::ProofCreated {
                    tree_role: match proof_tree_role {
                        1 => ProofTreeRole::BaseOracle,
                        2 => ProofTreeRole::AuxiliaryOracle,
                        _ => return Err(SelectedProofAccountingError::InvalidProfile),
                    },
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    leaf_visibility,
                })
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind,
                ordered_column_ordinals,
                ..
            } => Ok(RelationProofTreeInput::BoundPublic(
                match construction_kind {
                    BoundTreeConstructionKind::CommittedMaterial => {
                        StatementOwnedProofTreeInput::CommittedMaterial {
                            material_context_hash: [0; Hash512::BYTE_LENGTH],
                            expected_root: [0; Hash512::BYTE_LENGTH],
                        }
                    }
                    BoundTreeConstructionKind::SetupPolynomial => {
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: [0; Hash512::BYTE_LENGTH],
                            row_width: u32::try_from(ordered_column_ordinals.len())
                                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                            expected_root: [0; Hash512::BYTE_LENGTH],
                        }
                    }
                },
            )),
        })
        .collect()
}

fn require_selected_query_ceiling_geometry(
    unique_query_count: u32,
    query_orbit_count: u64,
    layout: &ProofBodyLayout,
    ceiling: &super::CommonProofByteLengthCeiling,
) -> Result<(), SelectedProofAccountingError> {
    let unique_query_count = usize::try_from(unique_query_count)
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let query_representatives =
        selected_query_ceiling_witness(unique_query_count, query_orbit_count)?;
    if layout.catalog().evaluation_domain_size().checked_div(2) != Some(query_orbit_count)
        || ceiling.query_trees().len() != layout.catalog().entries().len()
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    for (catalog_index, tree) in ceiling.query_trees().iter().enumerate() {
        let leaf_count = tree.leaf_count();
        if !leaf_count.is_power_of_two()
            || leaf_count.trailing_zeros() != tree.tree_height()
            || u64::try_from(leaf_count)
                .ok()
                .is_none_or(|count| count > query_orbit_count)
            || tree.maximum_opened_leaf_count() != unique_query_count.min(leaf_count)
            || proof_query_tree_byte_length(layout, catalog_index, &query_representatives)
                .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?
                != tree.byte_length()
        {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
        let leaf_count_u64 =
            u64::try_from(leaf_count).map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let projected_leaf_indexes = query_representatives
            .iter()
            .map(|representative| representative % leaf_count_u64)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if projected_leaf_indexes.len() != tree.opened_leaf_count_at_ceiling()
            || minimal_frontier_node_count(&projected_leaf_indexes, leaf_count)
                .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?
                != tree.authentication_frontier_node_count_at_ceiling()
        {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
    }
    Ok(())
}

/// Constructs one query vector that attains every folded-tree frontier maximum
/// for the supplied production schedule. The repeated seed width is the
/// smallest power-of-two capacity covering the query count. Retaining every
/// odd-parity seed covers every shorter cyclic bit window; adding the required
/// even-parity seeds makes full-width windows injective. Repeating those seeds
/// through the query-orbit width therefore maximally disperses the same query
/// vector at every power-of-two folded tree geometry.
fn selected_query_ceiling_witness(
    unique_query_count: usize,
    query_orbit_count: u64,
) -> Result<Vec<u64>, SelectedProofAccountingError> {
    if unique_query_count == 0
        || !query_orbit_count.is_power_of_two()
        || u64::try_from(unique_query_count)
            .ok()
            .is_none_or(|count| count > query_orbit_count)
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    let seed_capacity = unique_query_count
        .checked_next_power_of_two()
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let seed_bit_width = seed_capacity.trailing_zeros();
    let query_orbit_bit_width = query_orbit_count.trailing_zeros();
    let mut selected_seeds = Vec::new();
    selected_seeds
        .try_reserve_exact(unique_query_count)
        .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
    if seed_bit_width == 0 {
        selected_seeds.push(0_usize);
    } else {
        selected_seeds.extend((0..seed_capacity).filter(|seed| seed.count_ones() % 2 == 1));
        selected_seeds.extend(
            (0..seed_capacity)
                .filter(|seed| seed.count_ones() % 2 == 0)
                .take(unique_query_count - selected_seeds.len()),
        );
    }
    let mut query_representatives = Vec::new();
    query_representatives
        .try_reserve_exact(unique_query_count)
        .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
    for seed in selected_seeds {
        let seed = u64::try_from(seed).map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let mut representative = 0_u64;
        let mut bit_offset = 0_u32;
        while seed_bit_width != 0 && bit_offset < query_orbit_bit_width {
            let copied_bit_count = seed_bit_width.min(query_orbit_bit_width - bit_offset);
            let copied_bit_mask = 1_u64
                .checked_shl(copied_bit_count)
                .and_then(|value| value.checked_sub(1))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            representative |= (seed & copied_bit_mask) << bit_offset;
            bit_offset = bit_offset
                .checked_add(copied_bit_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        }
        query_representatives.push(representative);
    }
    query_representatives.sort_unstable();
    if query_representatives.len() != unique_query_count
        || !query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || query_representatives
            .last()
            .is_none_or(|representative| *representative >= query_orbit_count)
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    Ok(query_representatives)
}

fn selected_query_frontier_node_count(
    tree_height: u32,
    query_count: usize,
) -> Result<usize, SelectedProofAccountingError> {
    if tree_height == 0 {
        return if query_count == 1 {
            Ok(0)
        } else {
            Err(SelectedProofAccountingError::InvalidTreeGeometry)
        };
    }
    let mut frontier_count = 0_usize;
    for level in 1..tree_height {
        let subtree_count = 1_usize
            .checked_shl(tree_height - level)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        frontier_count = frontier_count
            .checked_add(query_count.min(subtree_count))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    }
    frontier_count
        .checked_add(2)
        .and_then(|count| count.checked_sub(query_count))
        .ok_or(SelectedProofAccountingError::CountOverflow)
}

fn selected_resident_memory_phase_ceilings(
    resident_memory_requirement: &CommonProofResidentMemoryPlan,
    checkpoint_custody_requirement: CommonProofGenerationCheckpointCustodyRequirement,
    fri_fold_count: u16,
    source_polynomial_provider_memory_accounting: Option<
        SelectedSourcePolynomialProviderMemoryAccounting,
    >,
    ballot_ciphertext_readback_memory_accounting: Option<
        SelectedBallotCiphertextReadbackMemoryAccounting,
    >,
) -> Result<Vec<SelectedProofResidentMemoryPhaseCeiling>, SelectedProofAccountingError> {
    let retained_cursor_state_byte_length = checkpoint_custody_requirement
        .cursor_manifest_requirement()
        .retained_cursor_state_byte_ceiling();
    let boundary_checkpoint_custody_byte_length =
        checkpoint_custody_requirement.boundary_peak_additional_resident_byte_ceiling();
    if boundary_checkpoint_custody_byte_length < retained_cursor_state_byte_length
        || !checkpoint_custody_requirement.fits_absolute_bounds()
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }
    if source_polynomial_provider_memory_accounting.is_some_and(|accounting| {
        resident_memory_requirement
            .phases()
            .iter()
            .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials)
            .is_none_or(|phase| {
                phase.relation_polynomial_working_set_byte_length()
                    < accounting.maximum_returned_source_polynomial_byte_length()
            })
    }) {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    let mut observed_deriving_auxiliary_columns = false;
    let mut observed_constructing_quotient = false;
    let mut observed_deriving_openings = false;
    let mut observed_constructing_initial_fri = false;
    let mut observed_folding_fri = false;
    let mut phase_ceilings = Vec::new();
    phase_ceilings
        .try_reserve_exact(resident_memory_requirement.phases().len())
        .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
    for phase_plan in resident_memory_requirement.phases() {
        let checkpoint_boundary_count = match phase_plan.phase() {
            CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns => {
                if observed_deriving_auxiliary_columns {
                    return Err(SelectedProofAccountingError::ResourcePlanning);
                }
                observed_deriving_auxiliary_columns = true;
                1
            }
            CommonProofResidentMemoryPhase::ConstructingQuotient => {
                if observed_constructing_quotient {
                    return Err(SelectedProofAccountingError::ResourcePlanning);
                }
                observed_constructing_quotient = true;
                1
            }
            CommonProofResidentMemoryPhase::DerivingOpenings => {
                if observed_deriving_openings {
                    return Err(SelectedProofAccountingError::ResourcePlanning);
                }
                observed_deriving_openings = true;
                1
            }
            CommonProofResidentMemoryPhase::ConstructingInitialFri => {
                if observed_constructing_initial_fri {
                    return Err(SelectedProofAccountingError::ResourcePlanning);
                }
                observed_constructing_initial_fri = true;
                1
            }
            CommonProofResidentMemoryPhase::FoldingFri => {
                if observed_folding_fri {
                    return Err(SelectedProofAccountingError::ResourcePlanning);
                }
                observed_folding_fri = true;
                fri_fold_count.saturating_sub(1)
            }
            _ => 0,
        };
        let checkpoint_custody_byte_length = if checkpoint_boundary_count == 0 {
            retained_cursor_state_byte_length
        } else {
            boundary_checkpoint_custody_byte_length
        };
        let source_polynomial_provider_persistent_resident_byte_length =
            if common_proof_source_provider_is_live_during_phase(phase_plan.phase()) {
                source_polynomial_provider_memory_accounting.map_or(0, |accounting| {
                    if phase_plan.phase()
                        == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
                    {
                        accounting.loading_persistent_resident_byte_length()
                    } else {
                        accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                    }
                })
            } else {
                0
            };
        let source_polynomial_provider_additional_transient_byte_length =
            if phase_plan.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
                source_polynomial_provider_memory_accounting.map_or(0, |accounting| {
                    accounting.additional_loading_source_polynomials_transient_byte_length()
                })
            } else {
                0
            };
        let application_runtime_persistent_resident_byte_length =
            ballot_ciphertext_readback_memory_accounting
                .map_or(0, |accounting| accounting.persistent_resident_byte_length());
        let application_runtime_boundary_overlap_byte_length =
            ballot_ciphertext_readback_memory_accounting.map_or(0, |accounting| {
                accounting.maximum_boundary_overlap_byte_length()
            });
        let combined_byte_length = phase_plan
            .total_byte_length()
            .checked_add(source_polynomial_provider_persistent_resident_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?
            .checked_add(source_polynomial_provider_additional_transient_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?
            .checked_add(application_runtime_persistent_resident_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?
            .checked_add(application_runtime_boundary_overlap_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?
            .checked_add(checkpoint_custody_byte_length)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        phase_ceilings.push(SelectedProofResidentMemoryPhaseCeiling {
            phase: phase_plan.phase(),
            base_prover_byte_length: phase_plan.total_byte_length(),
            source_polynomial_provider_persistent_resident_byte_length,
            source_polynomial_provider_additional_transient_byte_length,
            application_runtime_persistent_resident_byte_length,
            application_runtime_boundary_overlap_byte_length,
            checkpoint_boundary_count,
            checkpoint_custody_byte_length,
            combined_byte_length,
        });
    }
    if !observed_deriving_auxiliary_columns
        || !observed_constructing_quotient
        || !observed_deriving_openings
        || !observed_constructing_initial_fri
        || !observed_folding_fri
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }
    Ok(phase_ceilings)
}

fn selected_variant_copied_buffer_requirements(
    variant: &SelectedProofVariantByteCeiling,
) -> [(&'static str, u64); 4] {
    [
        (
            "query prefetch",
            variant.maximum_prefetched_query_byte_length(),
        ),
        (
            "external-memory transaction",
            variant
                .external_memory_requirement()
                .maximum_transaction_payload_byte_length(),
        ),
        (
            "proof stream chunk",
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH as u64,
        ),
        (
            "checkpoint custody",
            u64::from(
                variant
                    .checkpoint_custody_requirement()
                    .peak_copied_buffer_byte_length(),
            ),
        ),
    ]
}

fn require_selected_variant_absolute_resource_bounds(
    variant: &SelectedProofVariantByteCeiling,
) -> Result<(), SelectedProofAccountingError> {
    let maximum_copied_buffer_byte_length =
        u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    if selected_variant_copied_buffer_requirements(variant)
        .into_iter()
        .any(|(_, byte_length)| byte_length > maximum_copied_buffer_byte_length)
        || variant
            .resident_memory_phase_ceilings()
            .iter()
            .any(|phase| {
                phase.combined_byte_length() > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
            })
        || variant
            .checkpoint_custody_requirement()
            .restore_workspace_byte_ceiling()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || variant
            .external_memory_requirement()
            .peak_stored_byte_length()
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bgv::{
        evaluator::top_k::selected_evaluator_rotation_key_schedule,
        parameters::{BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE},
        rns::RnsPolynomial,
        serialization::{BgvObjectKind, serialize_bgv_object},
    };

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn canonical_target_ciphertext(residue_offset: u64) -> Vec<u8> {
        let component = |component_offset: u64| {
            RnsPolynomial::coefficient_domain(
                BgvBasisKind::Data,
                CANONICAL_TARGET_CIPHERTEXT_LEVEL,
                DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
                    .iter()
                    .enumerate()
                    .map(|(modulus_index, modulus)| {
                        (0..POLYNOMIAL_DEGREE)
                            .map(|coefficient_index| {
                                residue_offset
                                    .wrapping_add(component_offset)
                                    .wrapping_add(
                                        u64::try_from(modulus_index)
                                            .expect("test modulus index fits u64"),
                                    )
                                    .wrapping_add(
                                        u64::try_from(coefficient_index)
                                            .expect("test coefficient index fits u64"),
                                    )
                                    % modulus
                            })
                            .collect()
                    })
                    .collect(),
            )
            .expect("test target polynomial validates")
        };
        serialize_bgv_object(BgvObjectKind::Ciphertext, &[component(0), component(17)])
            .expect("test target ciphertext serializes")
    }

    fn complete_action_owner_row(
        owner: SelectedCompleteActionCorpusOwner,
        byte_length: u64,
    ) -> SelectedCompleteActionCorpusOwnerByteAccounting {
        match owner {
            SelectedCompleteActionCorpusOwner::SetupPrivateMailboxCorpus => {
                SelectedCompleteActionCorpusOwnerByteAccounting {
                    owner,
                    canonical_wire_byte_length: byte_length,
                    codec_and_proof_ceiling_wire_byte_length: byte_length + 1,
                    producer_upload_byte_length: byte_length,
                    complete_verifier_download_byte_length: 0,
                    public_storage_byte_length: 0,
                    private_mailbox_storage_byte_length: byte_length,
                }
            }
            _ => selected_public_complete_action_owner_row(
                owner,
                byte_length,
                byte_length + 1,
            ),
        }
    }

    #[test]
    fn complete_action_corpus_accounting_rejects_omissions_duplicates_and_overlap() {
        let rows = SelectedCompleteActionCorpusOwner::ALL
            .into_iter()
            .enumerate()
            .map(|(owner_index, owner)| {
                complete_action_owner_row(
                    owner,
                    u64::try_from(owner_index + 1).expect("test owner index fits u64") * 17,
                )
            })
            .collect::<Vec<_>>();
        let (ordered_rows, totals) =
            selected_complete_action_corpus_totals(rows.clone()).expect("complete inventory sums");
        assert_eq!(
            ordered_rows
                .iter()
                .map(|row| row.owner())
                .collect::<Vec<_>>(),
            SelectedCompleteActionCorpusOwner::ALL
        );
        assert_eq!(totals.canonical_wire_byte_length, 357);
        assert_eq!(totals.codec_and_proof_ceiling_wire_byte_length, 363);
        assert_eq!(totals.producer_upload_byte_length, 357);
        assert_eq!(totals.complete_verifier_download_byte_length, 323);
        assert_eq!(totals.public_storage_byte_length, 323);
        assert_eq!(totals.private_mailbox_storage_byte_length, 34);

        let mut missing_owner_rows = rows.clone();
        missing_owner_rows.pop();
        assert_eq!(
            selected_complete_action_corpus_totals(missing_owner_rows),
            Err(SelectedProofAccountingError::MissingCompleteActionOwner)
        );

        let mut duplicate_owner_rows = rows.clone();
        duplicate_owner_rows.push(rows[0]);
        assert_eq!(
            selected_complete_action_corpus_totals(duplicate_owner_rows),
            Err(SelectedProofAccountingError::DuplicateCompleteActionOwner)
        );

        let mut overlapping_row_set = rows;
        overlapping_row_set[0].private_mailbox_storage_byte_length = 1;
        assert_eq!(
            selected_complete_action_corpus_totals(overlapping_row_set),
            Err(SelectedProofAccountingError::InvalidProfile)
        );
    }

    fn assert_selected_mask_ordinal_consumption_is_consecutive(
        ordinal_consumption: SelectedMaskOrdinalConsumption,
        expected_purpose_class: u16,
    ) {
        assert_eq!(ordinal_consumption.purpose_class(), expected_purpose_class);
        match ordinal_consumption.consumed_mask_count() {
            0 => {
                assert_eq!(ordinal_consumption.first_consumed_mask_ordinal(), None);
                assert_eq!(ordinal_consumption.last_consumed_mask_ordinal(), None);
            }
            consumed_mask_count => {
                let first_consumed_mask_ordinal = ordinal_consumption
                    .first_consumed_mask_ordinal()
                    .expect("a non-empty mask-coordinate class has a first ordinal");
                let last_consumed_mask_ordinal = ordinal_consumption
                    .last_consumed_mask_ordinal()
                    .expect("a non-empty mask-coordinate class has a last ordinal");
                assert_eq!(first_consumed_mask_ordinal, 0);
                assert_eq!(
                    last_consumed_mask_ordinal
                        .checked_add(1)
                        .expect("the last mask ordinal increments without overflow"),
                    consumed_mask_count
                );
            }
        }
    }

    fn assert_selected_mask_coordinate_consumption_is_complete(
        mask_coordinate_consumption: SelectedMaskCoordinateConsumption,
    ) {
        assert_selected_mask_ordinal_consumption_is_consecutive(
            mask_coordinate_consumption.trace_masks(),
            RelationMaskKind::Trace as u16,
        );
        assert_selected_mask_ordinal_consumption_is_consecutive(
            mask_coordinate_consumption.quotient_masks(),
            RelationMaskKind::Telescoping as u16,
        );
        assert_selected_mask_ordinal_consumption_is_consecutive(
            mask_coordinate_consumption.opening_masks(),
            RelationMaskKind::OpeningBatch as u16,
        );
        assert_eq!(
            mask_coordinate_consumption
                .trace_masks()
                .consumed_mask_count()
                + mask_coordinate_consumption
                    .quotient_masks()
                    .consumed_mask_count()
                + mask_coordinate_consumption
                    .opening_masks()
                    .consumed_mask_count(),
            mask_coordinate_consumption.total_mask_count()
        );
    }

    fn assert_selected_variant_fits_absolute_resource_bounds(
        variant: &SelectedProofVariantByteCeiling,
    ) {
        let schema_identifier = variant.application_statement_schema_identifier();
        let schedule_position = variant.schedule_position();
        let top_count = variant.top_count();
        let copied_buffer_byte_length_bound =
            u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .expect("the copied-buffer limit fits u64");
        for (copy_phase, copied_buffer_byte_length) in
            selected_variant_copied_buffer_requirements(variant)
        {
            assert!(
                copied_buffer_byte_length <= copied_buffer_byte_length_bound,
                "selected proof schema {schema_identifier:#06x}, schedule {schedule_position:?}, top count {top_count:?}, copied-buffer phase {copy_phase} needs {copied_buffer_byte_length} bytes, exceeding the {copied_buffer_byte_length_bound}-byte absolute copied-buffer bound"
            );
        }

        for phase in variant.resident_memory_phase_ceilings() {
            let phase_byte_length = phase.combined_byte_length();
            assert!(
                phase_byte_length <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
                "selected proof schema {schema_identifier:#06x}, schedule {schedule_position:?}, top count {top_count:?}, resident phase {:?} needs {phase_byte_length} bytes, exceeding the {MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH}-byte absolute WebAssembly resident bound",
                phase.phase(),
            );
        }
        let resident_peak_byte_length = variant
            .resident_memory_phase_ceilings()
            .iter()
            .map(|phase| phase.combined_byte_length())
            .max()
            .expect("the selected resident plan has at least one phase");
        assert!(
            resident_peak_byte_length <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
            "selected proof schema {schema_identifier:#06x}, schedule {schedule_position:?}, top count {top_count:?} needs a {resident_peak_byte_length}-byte resident peak, exceeding the {MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH}-byte absolute WebAssembly resident bound"
        );
        let checkpoint_restore_workspace_byte_length = variant
            .checkpoint_custody_requirement()
            .restore_workspace_byte_ceiling();
        assert!(
            checkpoint_restore_workspace_byte_length
                <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
            "selected proof schema {schema_identifier:#06x}, schedule {schedule_position:?}, top count {top_count:?} needs {checkpoint_restore_workspace_byte_length} bytes to restore checkpoint custody, exceeding the {MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH}-byte absolute WebAssembly resident bound"
        );

        let external_scratch_byte_length = variant
            .external_memory_requirement()
            .peak_stored_byte_length();
        assert!(
            external_scratch_byte_length <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
            "selected proof schema {schema_identifier:#06x}, schedule {schedule_position:?}, top count {top_count:?} needs {external_scratch_byte_length} bytes of external scratch, exceeding the {MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH}-byte absolute scratch bound"
        );
    }

    #[test]
    fn selected_target_release_stream_accounting_measures_move_and_borrow_ownership() {
        let accounting =
            selected_target_release_stream_buffer_accounting().expect("target-release accounting");
        let removed_full_stream_copy_count = accounting
            .canonical_pair_wire_byte_length()
            .checked_div(accounting.canonical_role_stream_byte_length())
            .expect("the canonical role stream is non-empty");
        assert_eq!(
            accounting
                .canonical_pair_wire_byte_length()
                .checked_rem(accounting.canonical_role_stream_byte_length()),
            Some(0)
        );
        assert_eq!(
            accounting.generation_retained_canonical_byte_length(),
            accounting.canonical_pair_wire_byte_length()
        );
        assert!(
            accounting.verification_decoded_residue_byte_length()
                < accounting.canonical_pair_wire_byte_length()
        );
        assert_eq!(accounting.full_stream_copy_count(), 0);
        assert_eq!(accounting.full_stream_copy_byte_length(), 0);
        assert_eq!(
            accounting.maximum_full_stream_copied_buffer_byte_length(),
            0
        );
        assert!(
            accounting.canonical_role_stream_byte_length()
                <= u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                    .expect("the copied-buffer bound fits u64")
        );

        let generation_preparation_copy_byte_length_before_move = accounting
            .full_stream_copy_byte_length()
            .checked_add(accounting.canonical_pair_wire_byte_length())
            .expect("the prior generation copy volume fits u64");
        let verification_copy_byte_length_before_borrow = accounting
            .full_stream_copy_byte_length()
            .checked_add(accounting.canonical_pair_wire_byte_length())
            .expect("the prior verification copy volume fits u64");
        eprintln!(
            "target_release_stream_buffers canonical_role_wire_bytes={} canonical_pair_wire_bytes={} generation_retained_canonical_bytes={} verification_decoded_residue_bytes={} removed_full_stream_copy_count_per_phase={} maximum_removed_full_stream_copy_bytes={} generation_copy_bytes_before_move={} generation_copy_bytes_after_move={} verification_copy_bytes_before_borrow={} verification_copy_bytes_after_borrow={}",
            accounting.canonical_role_stream_byte_length(),
            accounting.canonical_pair_wire_byte_length(),
            accounting.generation_retained_canonical_byte_length(),
            accounting.verification_decoded_residue_byte_length(),
            removed_full_stream_copy_count,
            accounting.canonical_role_stream_byte_length(),
            generation_preparation_copy_byte_length_before_move,
            accounting.full_stream_copy_byte_length(),
            verification_copy_byte_length_before_borrow,
            accounting.full_stream_copy_byte_length(),
        );
    }

    #[test]
    fn generated_target_ciphertext_accounting_uses_exact_production_codec_bytes() {
        let target_identifier_bytes = canonical_target_ciphertext(3);
        let target_order_bytes = canonical_target_ciphertext(30_000);
        let accounting = selected_generated_target_ciphertext_byte_accounting(
            &target_identifier_bytes,
            &target_order_bytes,
        )
        .expect("generated target accounting derives");
        let decoded_single_target_residue_byte_length = u64::try_from(2)
            .expect("component count fits u64")
            .checked_mul(
                u64::try_from(CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1)
                    .expect("target limb count fits u64"),
            )
            .and_then(|count| {
                count.checked_mul(u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64"))
            })
            .and_then(|count| {
                count.checked_mul(u64::try_from(size_of::<u64>()).expect("residue width fits u64"))
            })
            .expect("selected target decoded size fits u64");
        assert_eq!(
            accounting.target_identifier_canonical_wire_byte_length(),
            u64::try_from(target_identifier_bytes.len()).expect("test wire length fits u64")
        );
        assert_eq!(
            accounting.target_order_canonical_wire_byte_length(),
            u64::try_from(target_order_bytes.len()).expect("test wire length fits u64")
        );
        assert_ne!(
            accounting.target_identifier_canonical_wire_byte_length(),
            accounting.target_order_canonical_wire_byte_length(),
            "variable-width residue encodings must be measured from generated bytes"
        );
        assert_eq!(
            accounting.canonical_pair_wire_byte_length(),
            accounting.target_identifier_canonical_wire_byte_length()
                + accounting.target_order_canonical_wire_byte_length()
        );
        assert!(
            accounting.target_identifier_canonical_wire_byte_length()
                <= accounting.target_ciphertext_codec_ceiling_wire_byte_length()
        );
        assert!(
            accounting.target_order_canonical_wire_byte_length()
                <= accounting.target_ciphertext_codec_ceiling_wire_byte_length()
        );
        assert_eq!(
            accounting.target_pair_codec_ceiling_wire_byte_length(),
            accounting.target_ciphertext_codec_ceiling_wire_byte_length() * 2
        );
        assert_eq!(
            accounting.target_identifier_decoded_residue_byte_length(),
            decoded_single_target_residue_byte_length
        );
        assert_eq!(
            accounting.target_order_decoded_residue_byte_length(),
            decoded_single_target_residue_byte_length
        );
        assert_eq!(
            accounting.decoded_pair_residue_byte_length(),
            decoded_single_target_residue_byte_length * 2
        );
        assert_eq!(
            accounting.maximum_boundary_copied_buffer_byte_length(),
            accounting
                .target_identifier_canonical_wire_byte_length()
                .max(accounting.target_order_canonical_wire_byte_length())
        );
    }

    #[test]
    fn generated_target_ciphertext_accounting_rejects_noncanonical_or_wrong_level_bytes() {
        let canonical_target_bytes = canonical_target_ciphertext(9);
        assert_eq!(
            selected_generated_target_ciphertext_byte_accounting(&[], &canonical_target_bytes),
            Err(SelectedProofAccountingError::AllocationLimitExceeded)
        );

        let mut trailing_target_bytes = canonical_target_bytes.clone();
        trailing_target_bytes.push(0);
        assert_eq!(
            selected_generated_target_ciphertext_byte_accounting(
                &trailing_target_bytes,
                &canonical_target_bytes,
            ),
            Err(SelectedProofAccountingError::CanonicalEncoding)
        );

        let wrong_level = CANONICAL_TARGET_CIPHERTEXT_LEVEL - 1;
        let wrong_level_component = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            wrong_level,
            DATA_PRIMES[..=wrong_level]
                .iter()
                .map(|_| vec![0_u64; POLYNOMIAL_DEGREE])
                .collect(),
        )
        .expect("wrong-level test component still validates");
        let wrong_level_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[wrong_level_component.clone(), wrong_level_component],
        )
        .expect("wrong-level ciphertext serializes");
        assert_eq!(
            selected_generated_target_ciphertext_byte_accounting(
                &canonical_target_bytes,
                &wrong_level_bytes,
            ),
            Err(SelectedProofAccountingError::CanonicalEncoding)
        );
    }

    #[test]
    fn stream_descriptor_codec_ceiling_tracks_exact_chunk_boundaries() {
        let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .expect("selected chunk length fits u64");
        let one_chunk_lengths = [1_u64, chunk_byte_length - 1, chunk_byte_length];
        let one_chunk_descriptor_byte_length =
            selected_stream_descriptor_canonical_byte_length(one_chunk_lengths[0])
                .expect("one-chunk descriptor length derives");
        for stream_byte_length in one_chunk_lengths {
            assert_eq!(
                selected_stream_descriptor_canonical_byte_length(stream_byte_length)
                    .expect("one-chunk descriptor length derives"),
                one_chunk_descriptor_byte_length
            );
            assert_eq!(
                selected_stream_descriptor_codec_expansion_byte_length(
                    stream_byte_length,
                    stream_byte_length,
                ),
                Ok(0)
            );
        }

        let two_chunk_stream_byte_length = chunk_byte_length + 1;
        let two_chunk_descriptor_byte_length =
            selected_stream_descriptor_canonical_byte_length(two_chunk_stream_byte_length)
                .expect("two-chunk descriptor length derives");
        assert!(two_chunk_descriptor_byte_length > one_chunk_descriptor_byte_length);
        assert_eq!(
            selected_stream_descriptor_codec_expansion_byte_length(
                chunk_byte_length,
                two_chunk_stream_byte_length,
            ),
            Ok(two_chunk_descriptor_byte_length - one_chunk_descriptor_byte_length)
        );

        let maximum_proof_descriptor_byte_length =
            selected_stream_descriptor_canonical_byte_length(
                u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
                    .expect("proof stream bound fits u64"),
            )
            .expect("maximum proof descriptor length derives");
        assert!(maximum_proof_descriptor_byte_length > two_chunk_descriptor_byte_length);
        assert_eq!(
            selected_stream_descriptor_codec_expansion_byte_length(0, 1),
            Err(SelectedProofAccountingError::InvalidProfile)
        );
        assert_eq!(
            selected_stream_descriptor_codec_expansion_byte_length(2, 1),
            Err(SelectedProofAccountingError::InvalidProfile)
        );
        assert_eq!(
            selected_stream_descriptor_canonical_byte_length(0),
            Err(SelectedProofAccountingError::CountOverflow)
        );
    }

    #[test]
    fn selected_program_positions_drive_proof_multiplicities() {
        let program = selected_evaluator_program_set().expect("selected program set");
        let positions = program.key_positions().expect("selected key positions");
        assert!(!positions.relinearization_catalog_levels().is_empty());
        assert!(!positions.galois_catalog_positions().is_empty());
        assert_eq!(
            positions
                .galois_catalog_positions()
                .iter()
                .map(|position| (position.galois_element(), position.catalog_level()))
                .collect::<Vec<_>>(),
            selected_evaluator_rotation_key_schedule(usize::from(FOUNDATION_PROFILE.option_count))
                .expect("selected rotation schedule")
        );
        let complete_stream = positions
            .streams()
            .iter()
            .find(|stream| stream.top_count() == FOUNDATION_PROFILE.option_count)
            .expect("the selected program contains the complete top-count stream");
        assert_eq!(
            complete_stream.relinearization_catalog_levels(),
            positions.relinearization_catalog_levels()
        );
        assert_eq!(
            complete_stream.galois_catalog_positions(),
            positions.galois_catalog_positions()
        );
        assert!(positions.streams().iter().all(|stream| {
            !stream.relinearization_catalog_levels().is_empty()
                && !stream.galois_catalog_positions().is_empty()
                && stream
                    .relinearization_catalog_levels()
                    .iter()
                    .all(|level| positions.relinearization_catalog_levels().contains(level))
                && stream
                    .galois_catalog_positions()
                    .iter()
                    .all(|position| positions.galois_catalog_positions().contains(position))
        }));
    }

    #[test]
    fn absolute_proof_byte_safety_bound_rejects_one_byte_over_before_accounting() {
        const TEST_SCHEMA_IDENTIFIER: u16 = 0x1211;
        const TEST_SCHEDULE_POSITION: Option<u32> = Some(7);
        const TEST_TOP_COUNT: Option<u16> = None;
        assert_eq!(MAXIMUM_COMMON_PROOF_BYTE_LENGTH, 268_435_456);
        assert_eq!(
            require_selected_proof_byte_length(
                TEST_SCHEMA_IDENTIFIER,
                TEST_SCHEDULE_POSITION,
                TEST_TOP_COUNT,
                MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            ),
            Ok(MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64)
        );
        assert_eq!(
            require_selected_proof_byte_length(
                TEST_SCHEMA_IDENTIFIER,
                TEST_SCHEDULE_POSITION,
                TEST_TOP_COUNT,
                0,
            ),
            Err(SelectedProofAccountingError::ProofByteLengthExceeded {
                application_statement_schema_identifier: TEST_SCHEMA_IDENTIFIER,
                schedule_position: TEST_SCHEDULE_POSITION,
                top_count: TEST_TOP_COUNT,
                proof_byte_length: 0,
                maximum_proof_byte_length: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            })
        );
        assert_eq!(
            require_selected_proof_byte_length(
                TEST_SCHEMA_IDENTIFIER,
                TEST_SCHEDULE_POSITION,
                TEST_TOP_COUNT,
                MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1,
            ),
            Err(SelectedProofAccountingError::ProofByteLengthExceeded {
                application_statement_schema_identifier: TEST_SCHEMA_IDENTIFIER,
                schedule_position: TEST_SCHEDULE_POSITION,
                top_count: TEST_TOP_COUNT,
                proof_byte_length: MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1,
                maximum_proof_byte_length: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            })
        );
    }

    #[test]
    fn query_ceiling_witness_attains_frontier_maxima_for_derived_geometries() {
        for unique_query_count in [1_usize, 7, 65, 191, 257] {
            let query_orbit_bit_width = unique_query_count
                .checked_next_power_of_two()
                .expect("test query count has a power-of-two capacity")
                .trailing_zeros()
                + 4;
            let query_orbit_count = 1_u64 << query_orbit_bit_width;
            let query_representatives =
                selected_query_ceiling_witness(unique_query_count, query_orbit_count)
                    .expect("query ceiling witness derives");
            assert_eq!(query_representatives.len(), unique_query_count);
            assert!(
                query_representatives
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            assert!(
                query_representatives
                    .last()
                    .is_some_and(|representative| *representative < query_orbit_count)
            );

            for tree_height in 0..=query_orbit_bit_width {
                let leaf_count = 1_usize << tree_height;
                let projected_leaf_indexes = query_representatives
                    .iter()
                    .map(|representative| representative % leaf_count as u64)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let opened_leaf_count = unique_query_count.min(leaf_count);
                assert_eq!(projected_leaf_indexes.len(), opened_leaf_count);
                assert_eq!(
                    minimal_frontier_node_count(&projected_leaf_indexes, leaf_count)
                        .expect("projected frontier derives"),
                    selected_query_frontier_node_count(tree_height, opened_leaf_count)
                        .expect("maximum frontier derives")
                );
            }
        }
    }

    #[test]
    fn compiled_selected_schedules_drive_query_frontier_geometry() {
        let proof_profile =
            selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
                .expect("selected proof profile");
        let mut observed_schedule_classes = BTreeSet::new();
        for relation_plan in proof_profile.relation_plans() {
            let application_statement_schema_identifier =
                relation_plan.application_statement_schema_identifier();
            let relation_context =
                selected_relation_plan_check_context(application_statement_schema_identifier)
                    .expect("selected relation context");
            for variant in relation_plan.compiled_plan().variants() {
                let mask_coordinate_consumption =
                    derive_selected_mask_coordinate_consumption(variant)
                        .expect("selected mask-coordinate consumption derives");
                assert_selected_mask_coordinate_consumption_is_complete(
                    mask_coordinate_consumption,
                );
                match variant.proof_privacy_mode() {
                    ProofPrivacyMode::PublicOnly => {
                        assert_eq!(mask_coordinate_consumption.total_mask_count(), 0)
                    }
                    ProofPrivacyMode::SecretBearing => assert!(
                        mask_coordinate_consumption.total_mask_count() > 0,
                        "secret-bearing relation {application_statement_schema_identifier:#06x} has no private mask coordinate"
                    ),
                }
                let transcript_schedule = variant
                    .common_proof_transcript_schedule(&relation_context)
                    .expect("selected transcript schedule");
                let evaluation_domain_size = variant.evaluation_domain_size();
                let trace_domain_size = variant.trace_domain_size();
                assert_eq!(evaluation_domain_size % trace_domain_size, 0);
                observed_schedule_classes.insert((
                    transcript_schedule.unique_query_count(),
                    evaluation_domain_size / trace_domain_size,
                ));

                let unique_query_count = usize::try_from(transcript_schedule.unique_query_count())
                    .expect("selected query count fits usize");
                let query_orbit_count = transcript_schedule.query_orbit_count();
                let query_representatives =
                    selected_query_ceiling_witness(unique_query_count, query_orbit_count)
                        .expect("selected query witness");
                let mut folded_leaf_counts = BTreeSet::from([query_orbit_count]);
                for fold_ordinal in 0..transcript_schedule.fri_fold_count().saturating_sub(1) {
                    folded_leaf_counts.insert(
                        query_orbit_count
                            .checked_shr(u32::from(fold_ordinal) + 1)
                            .filter(|leaf_count| *leaf_count != 0)
                            .expect("selected folded leaf count"),
                    );
                }
                for leaf_count in folded_leaf_counts {
                    let projected_leaf_indexes = query_representatives
                        .iter()
                        .map(|representative| representative % leaf_count)
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    let leaf_count =
                        usize::try_from(leaf_count).expect("selected leaf count fits usize");
                    let opened_leaf_count = unique_query_count.min(leaf_count);
                    assert_eq!(projected_leaf_indexes.len(), opened_leaf_count);
                    assert_eq!(
                        minimal_frontier_node_count(&projected_leaf_indexes, leaf_count)
                            .expect("selected projected frontier"),
                        selected_query_frontier_node_count(
                            leaf_count.trailing_zeros(),
                            opened_leaf_count,
                        )
                        .expect("selected maximum frontier")
                    );
                }
            }
        }
        assert_eq!(
            observed_schedule_classes,
            BTreeSet::from([(168, 8), (192, 4)])
        );
    }

    #[test]
    #[ignore = "long-running exact-family accounting; run via the guarded measurements runner"]
    fn selected_exact_family_and_action_proof_accounting_reports_measurements() {
        let accounting =
            selected_proof_byte_accounting().expect("selected proof accounting derives");
        let mut family_maxima = std::collections::BTreeMap::<u16, u64>::new();
        for ceiling in accounting.variant_ceilings() {
            family_maxima
                .entry(ceiling.application_statement_schema_identifier())
                .and_modify(|maximum| *maximum = (*maximum).max(ceiling.proof_byte_length()))
                .or_insert(ceiling.proof_byte_length());
        }
        let maximum_variant = accounting
            .variant_ceilings()
            .iter()
            .max_by_key(|ceiling| ceiling.proof_byte_length())
            .expect("selected relation catalog is non-empty");
        const PROOF_BYTE_LENGTH_PLANNING_TARGET: u64 = 5_242_880;
        const EXTERNAL_SCRATCH_PLANNING_TARGET: u64 = 268_435_456;
        const WASM_RESIDENT_PLANNING_TARGET: u64 = 402_653_184;
        const COPIED_BUFFER_PLANNING_TARGET: u64 = 1_572_864;
        const COMPLETE_CORPUS_PLANNING_TARGET: u64 = 2_147_483_648;
        let variant_count_above_planning_target = accounting
            .variant_ceilings()
            .iter()
            .filter(|variant| variant.proof_byte_length() > PROOF_BYTE_LENGTH_PLANNING_TARGET)
            .count();
        let maximum_external_scratch_byte_length = accounting
            .variant_ceilings()
            .iter()
            .map(|variant| {
                variant
                    .external_memory_requirement()
                    .peak_stored_byte_length()
            })
            .max()
            .expect("the selected relation catalog is non-empty");
        let external_scratch_count_above_planning_target = accounting
            .variant_ceilings()
            .iter()
            .filter(|variant| {
                variant
                    .external_memory_requirement()
                    .peak_stored_byte_length()
                    > EXTERNAL_SCRATCH_PLANNING_TARGET
            })
            .count();
        let maximum_resident_byte_length = accounting
            .variant_ceilings()
            .iter()
            .map(|variant| variant.combined_resident_memory_peak_byte_length())
            .max()
            .expect("the selected relation catalog is non-empty");
        let resident_count_above_planning_target = accounting
            .variant_ceilings()
            .iter()
            .filter(|variant| {
                variant.combined_resident_memory_peak_byte_length() > WASM_RESIDENT_PLANNING_TARGET
            })
            .count();
        let maximum_copied_buffer_byte_length = accounting
            .variant_ceilings()
            .iter()
            .flat_map(selected_variant_copied_buffer_requirements)
            .map(|(_, byte_length)| byte_length)
            .max()
            .expect("the selected copied-buffer catalog is non-empty");
        let copied_buffer_count_above_planning_target = accounting
            .variant_ceilings()
            .iter()
            .filter(|variant| {
                selected_variant_copied_buffer_requirements(variant)
                    .into_iter()
                    .any(|(_, byte_length)| byte_length > COPIED_BUFFER_PLANNING_TARGET)
            })
            .count();
        let action_count_above_corpus_planning_target = accounting
            .actions()
            .iter()
            .filter(|action| action.proof_byte_length() > COMPLETE_CORPUS_PLANNING_TARGET)
            .count();
        assert!(
            family_maxima
                .values()
                .all(|byte_length| { *byte_length <= MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64 })
        );
        for (variant_catalog_index, variant) in accounting.variant_ceilings().iter().enumerate() {
            let mask_coordinate_consumption = variant.mask_coordinate_consumption();
            assert_selected_mask_coordinate_consumption_is_complete(mask_coordinate_consumption);
            let checkpoint_cursor_manifest_requirement =
                variant.checkpoint_cursor_manifest_requirement();
            let checkpoint_custody_requirement = variant.checkpoint_custody_requirement();
            assert_eq!(
                checkpoint_custody_requirement.cursor_manifest_requirement(),
                checkpoint_cursor_manifest_requirement
            );
            let secret_proof_salt_cursor_count =
                u32::from(variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing);
            let expected_checkpoint_run_count = [
                mask_coordinate_consumption
                    .trace_masks()
                    .consumed_mask_count(),
                mask_coordinate_consumption
                    .quotient_masks()
                    .consumed_mask_count(),
                mask_coordinate_consumption
                    .opening_masks()
                    .consumed_mask_count(),
                secret_proof_salt_cursor_count,
            ]
            .into_iter()
            .map(|count| u32::from(count != 0))
            .sum::<u32>();
            assert_eq!(
                checkpoint_cursor_manifest_requirement.logical_cursor_count(),
                mask_coordinate_consumption.total_mask_count() + secret_proof_salt_cursor_count
            );
            assert_eq!(
                checkpoint_cursor_manifest_requirement.consecutive_coordinate_run_count(),
                expected_checkpoint_run_count
            );
            assert_eq!(
                checkpoint_cursor_manifest_requirement.maximum_override_count(),
                checkpoint_cursor_manifest_requirement.logical_cursor_count()
                    - expected_checkpoint_run_count
            );
            assert_eq!(
                checkpoint_cursor_manifest_requirement.pending_manifest_resident_byte_ceiling(),
                checkpoint_cursor_manifest_requirement.canonical_manifest_byte_ceiling()
            );
            assert_eq!(
                checkpoint_cursor_manifest_requirement.restore_workspace_byte_ceiling(),
                checkpoint_cursor_manifest_requirement.retained_cursor_state_byte_ceiling()
            );
            assert_eq!(
                checkpoint_cursor_manifest_requirement.peak_additional_resident_byte_ceiling(),
                checkpoint_cursor_manifest_requirement.retained_cursor_state_byte_ceiling()
                    + u64::from(
                        checkpoint_cursor_manifest_requirement.canonical_manifest_byte_ceiling()
                    )
                    + u64::from(
                        checkpoint_cursor_manifest_requirement.encoding_workspace_byte_ceiling()
                    )
            );
            assert_eq!(
                checkpoint_cursor_manifest_requirement.peak_copied_buffer_byte_length(),
                checkpoint_cursor_manifest_requirement.canonical_manifest_byte_ceiling()
            );
            assert!(checkpoint_cursor_manifest_requirement.fits_absolute_bounds());
            assert_eq!(
                checkpoint_custody_requirement.boundary_peak_additional_resident_byte_ceiling(),
                checkpoint_custody_requirement
                    .transient_construction_resident_byte_ceiling()
                    .max(checkpoint_custody_requirement.pending_checkpoint_resident_byte_ceiling())
            );
            assert_eq!(
                checkpoint_custody_requirement.peak_copied_buffer_byte_length(),
                checkpoint_cursor_manifest_requirement
                    .peak_copied_buffer_byte_length()
                    .max(checkpoint_custody_requirement.encoded_state_byte_length())
            );
            assert!(checkpoint_custody_requirement.encoded_state_byte_length() > 0);
            assert!(checkpoint_custody_requirement.decoded_state_owner_byte_length() > 0);
            assert!(
                checkpoint_custody_requirement.pending_checkpoint_fixed_owner_byte_length() > 0
            );
            assert!(checkpoint_custody_requirement.fits_absolute_bounds());
            let relation_context = selected_relation_plan_check_context(
                variant.application_statement_schema_identifier(),
            )
            .expect("the selected relation context derives");
            assert_eq!(
                variant.evaluation_domain_size(),
                variant.opening_degree_bound_exclusive()
                    * u64::from(relation_context.evaluation_blowup_factor)
            );
            assert!(variant.trace_domain_size().is_power_of_two());
            assert!(variant.evaluation_domain_size().is_power_of_two());
            assert!(variant.canonical_relation_plan_byte_length() > 0);
            assert!(variant.canonical_variant_byte_length() > 0);
            assert_ne!(
                variant.canonical_relation_plan_hash(),
                [0; Hash512::BYTE_LENGTH]
            );
            assert_ne!(variant.canonical_variant_hash(), [0; Hash512::BYTE_LENGTH]);
            assert!(variant.relation_column_count() > 0);
            assert!(variant.opening_point_count() > 0);
            assert!(variant.opening_claim_count() > 0);
            assert_eq!(
                variant.checkpoint_boundary_count(),
                u32::from(relation_context.fri_fold_count) + 3
            );
            assert_eq!(
                variant.resident_memory_phase_ceilings().len(),
                variant.resident_memory_requirement().phases().len()
            );
            let source_polynomial_provider_memory_accounting =
                variant.source_polynomial_provider_memory_accounting();
            assert_eq!(
                source_polynomial_provider_memory_accounting.is_some(),
                matches!(
                    variant.application_statement_schema_identifier(),
                    ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                        | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                )
            );
            if let Some(accounting) = source_polynomial_provider_memory_accounting {
                match accounting {
                    SelectedSourcePolynomialProviderMemoryAccounting::BallotValidity(
                        accounting,
                    ) => {
                        assert!(accounting.provider_fixed_owner_byte_length() > 0);
                        assert!(accounting.provider_source_plan_catalog_byte_length() > 0);
                        assert!(
                            accounting.provider_ordered_source_column_catalog_byte_length() > 0
                        );
                        assert!(
                            accounting.provider_loading_persistent_resident_byte_length()
                                > accounting
                                    .provider_post_source_finish_persistent_resident_byte_length()
                        );
                    }
                    SelectedSourcePolynomialProviderMemoryAccounting::EvaluatorAggregate(
                        accounting,
                    ) => {
                        assert_eq!(
                            accounting.loading_persistent_resident_byte_length(),
                            accounting
                                .post_source_polynomial_finish_persistent_resident_byte_length()
                                + accounting.readback_chunk_digest_byte_length()
                                + accounting.readback_authentication_flag_byte_length()
                        );
                        assert_eq!(
                            accounting
                                .additional_loading_source_polynomials_transient_byte_length(),
                            accounting.maximum_pending_column_byte_length()
                                + accounting.maximum_cached_authenticated_chunk_byte_length()
                        );
                    }
                    SelectedSourcePolynomialProviderMemoryAccounting::CommittedMaterial(
                        accounting,
                    ) => {
                        assert_eq!(
                            accounting.loading_persistent_resident_byte_length(),
                            accounting.adapter_fixed_byte_length()
                                + accounting.authenticated_coefficient_byte_length()
                                + accounting.compact_source_byte_length()
                                + accounting.adapter_source_wrapper_catalog_byte_length()
                                + accounting.trace_provider_source_wrapper_catalog_byte_length()
                                + accounting.bound_material_column_lookup_catalog_byte_length()
                                + accounting.ordered_column_catalog_byte_length()
                                + accounting.resolved_modulus_catalog_byte_length()
                                + accounting.recipe_catalog_byte_length()
                                + accounting.nested_recipe_catalog_byte_length()
                        );
                        assert_eq!(
                            accounting.preparation_transient_byte_length(),
                            accounting.relation_tree_input_catalog_byte_length()
                                + accounting.canonical_witness_framing_transient_byte_length()
                        );
                        assert_eq!(
                            accounting.canonical_witness_framing_transient_byte_length(),
                            4_096
                        );
                        assert!(
                            accounting.preparation_peak_resident_byte_length()
                                <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                        );
                        assert!(
                            accounting.construction_peak_resident_byte_length()
                                <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                        );
                    }
                }
            }
            let ballot_ciphertext_readback_memory_accounting =
                variant.ballot_ciphertext_readback_memory_accounting();
            assert_eq!(
                ballot_ciphertext_readback_memory_accounting.is_some(),
                variant.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
            );
            if let Some(accounting) = ballot_ciphertext_readback_memory_accounting {
                assert_eq!(
                    accounting.persistent_resident_byte_length(),
                    accounting.fixed_owner_byte_length()
                        + accounting.descriptor_encoded_byte_length()
                        + accounting.descriptor_digest_catalog_byte_length()
                        + accounting.polynomial_catalog_byte_length()
                        + accounting.canonical_application_statement_byte_length()
                );
                assert_eq!(
                    accounting.maximum_boundary_overlap_byte_length(),
                    selected_ballot_validity_carrier_buffer_accounting()
                        .expect("selected ballot carrier accounting derives")
                        .maximum_boundary_copied_buffer_byte_length()
                        * 2
                );
            }
            for (combined_phase, base_phase) in variant
                .resident_memory_phase_ceilings()
                .iter()
                .zip(variant.resident_memory_requirement().phases())
            {
                assert_eq!(combined_phase.phase(), base_phase.phase());
                assert_eq!(
                    combined_phase.base_prover_byte_length(),
                    base_phase.total_byte_length()
                );
                let expected_checkpoint_custody_byte_length =
                    if combined_phase.checkpoint_boundary_count() == 0 {
                        checkpoint_cursor_manifest_requirement.retained_cursor_state_byte_ceiling()
                    } else {
                        checkpoint_custody_requirement
                            .boundary_peak_additional_resident_byte_ceiling()
                    };
                assert_eq!(
                    combined_phase.checkpoint_custody_byte_length(),
                    expected_checkpoint_custody_byte_length
                );
                let source_polynomial_provider_is_live =
                    common_proof_source_provider_is_live_during_phase(combined_phase.phase());
                assert_eq!(
                    combined_phase.source_polynomial_provider_persistent_resident_byte_length(),
                    if source_polynomial_provider_is_live {
                        source_polynomial_provider_memory_accounting.map_or(0, |accounting| {
                            if combined_phase.phase()
                                == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
                            {
                                accounting.loading_persistent_resident_byte_length()
                            } else {
                                accounting
                                    .post_source_polynomial_finish_persistent_resident_byte_length()
                            }
                        })
                    } else {
                        0
                    }
                );
                assert_eq!(
                    combined_phase.source_polynomial_provider_additional_transient_byte_length(),
                    if combined_phase.phase()
                        == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
                    {
                        source_polynomial_provider_memory_accounting.map_or(0, |accounting| {
                            accounting.additional_loading_source_polynomials_transient_byte_length()
                        })
                    } else {
                        0
                    }
                );
                assert_eq!(
                    combined_phase.combined_byte_length(),
                    combined_phase.base_prover_byte_length()
                        + combined_phase
                            .source_polynomial_provider_persistent_resident_byte_length()
                        + combined_phase
                            .source_polynomial_provider_additional_transient_byte_length()
                        + combined_phase.application_runtime_persistent_resident_byte_length()
                        + combined_phase.application_runtime_boundary_overlap_byte_length()
                        + combined_phase.checkpoint_custody_byte_length()
                );
            }
            assert_eq!(
                variant
                    .component_byte_lengths()
                    .proof_byte_length()
                    .and_then(|length| u64::try_from(length).ok()),
                Some(variant.proof_byte_length())
            );
            assert_eq!(
                variant.bound_tree_count(),
                u32::try_from(
                    variant
                        .tree_ceilings()
                        .iter()
                        .filter(|tree| tree.source() == ProofTreeCatalogSource::RelationBoundPublic)
                        .count()
                )
                .expect("the selected bound-tree count fits u32")
            );
            let verifier_hash_equation_ledger = variant.verifier_hash_equation_ledger();
            assert_eq!(
                verifier_hash_equation_ledger.application_statement_hash_query_count(),
                1
            );
            assert_eq!(
                verifier_hash_equation_ledger.proof_header_hash_query_count(),
                2
            );
            assert_eq!(
                verifier_hash_equation_ledger.relation_plan_variant_hash_query_count(),
                1
            );
            assert_eq!(
                verifier_hash_equation_ledger.relation_plan_hash_query_count(),
                1
            );
            assert_eq!(
                verifier_hash_equation_ledger.fixed_checked_oracle_equation_count(),
                4
            );
            assert_eq!(
                verifier_hash_equation_ledger.query_trees().len(),
                variant.tree_ceilings().len()
            );
            assert_eq!(
                variant.secret_bearing_tree_root_count(),
                verifier_hash_equation_ledger.secret_bearing_tree_root_count()
            );
            assert_eq!(
                variant.full_salted_leaf_count(),
                verifier_hash_equation_ledger.full_salted_leaf_count()
            );
            assert_eq!(
                variant.opened_salted_leaf_count(),
                verifier_hash_equation_ledger.opened_salted_leaf_count()
            );
            assert_eq!(
                variant.hidden_salted_leaf_count(),
                verifier_hash_equation_ledger.hidden_salted_leaf_count()
            );
            for (tree_ledger, tree_ceiling) in verifier_hash_equation_ledger
                .query_trees()
                .iter()
                .zip(variant.tree_ceilings())
            {
                assert_eq!(
                    tree_ledger.tree_catalog_index(),
                    tree_ceiling.tree_catalog_index()
                );
                assert_eq!(tree_ledger.source(), tree_ceiling.source());
                assert_eq!(
                    tree_ledger.opened_leaf_hash_query_count(),
                    u64::from(tree_ceiling.opened_row_count())
                );
                assert_eq!(
                    tree_ledger.authentication_parent_hash_query_count(),
                    u64::from(tree_ceiling.opened_row_count())
                        + u64::from(tree_ceiling.authentication_frontier_node_count())
                        - 1
                );
            }
            assert_eq!(
                verifier_hash_equation_ledger.tree_hash_query_count(),
                verifier_hash_equation_ledger
                    .query_trees()
                    .iter()
                    .map(|tree| tree.ideal_xof_query_count())
                    .sum::<u64>()
            );
            assert_eq!(
                verifier_hash_equation_ledger.ideal_xof_query_count(),
                verifier_hash_equation_ledger.transcript_hash_query_count()
                    + verifier_hash_equation_ledger.application_statement_hash_query_count()
                    + verifier_hash_equation_ledger.proof_header_hash_query_count()
                    + verifier_hash_equation_ledger.relation_plan_hash_query_count()
                    + verifier_hash_equation_ledger.relation_plan_variant_hash_query_count()
                    + verifier_hash_equation_ledger.tree_hash_query_count()
            );
            assert_eq!(
                verifier_hash_equation_ledger.checked_oracle_equation_count(),
                verifier_hash_equation_ledger.transcript_hash_query_count()
                    + verifier_hash_equation_ledger.fixed_checked_oracle_equation_count()
                    + verifier_hash_equation_ledger
                        .query_trees()
                        .iter()
                        .map(|tree| tree.checked_oracle_equation_count())
                        .sum::<u64>()
            );
            match variant.proof_privacy_mode() {
                ProofPrivacyMode::PublicOnly => assert!(
                    variant
                        .tree_ceilings()
                        .iter()
                        .all(|tree| tree.leaf_visibility() == ProofLeafVisibility::Public)
                ),
                ProofPrivacyMode::SecretBearing => {
                    assert!(variant.tree_ceilings().iter().any(|tree| {
                        tree.leaf_visibility() == ProofLeafVisibility::SecretBearing
                    }))
                }
            }
            for tree in variant.tree_ceilings() {
                assert_eq!(
                    tree.opened_row_payload_byte_length()
                        + tree.authentication_frontier_digest_byte_length()
                        + tree.canonical_framing_byte_length(),
                    tree.query_record_byte_length()
                );
                assert!(tree.row_width() > 0);
                assert!(tree.opened_row_count() > 0);
                assert!(tree.authentication_frontier_node_count() > 0);
                assert_eq!(tree.leaf_count(), 1_u64 << tree.tree_height());
                if tree.requires_persistent_leaf_salt() {
                    assert_eq!(
                        tree.bound_tree_construction_kind(),
                        Some(BoundTreeConstructionKind::CommittedMaterial)
                    );
                    assert!(tree.bound_root_source_ordinal().is_some());
                    assert!(tree.bound_root_use().is_some());
                    assert_eq!(tree.leaf_visibility(), ProofLeafVisibility::SecretBearing);
                }
            }
            if matches!(
                variant.application_statement_schema_identifier(),
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                    | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            ) {
                for phase in variant.resident_memory_requirement().phases() {
                    assert_eq!(phase.auxiliary_trace_workspace_byte_length(), 0);
                }
            }
            let external_memory = variant.external_memory_requirement();
            assert!(external_memory.step_count() > 0);
            assert_eq!(
                external_memory.maximum_chunk_byte_length(),
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            );
            assert!(
                external_memory.maximum_transaction_payload_byte_length()
                    >= u64::from(external_memory.maximum_chunk_byte_length())
            );
            assert!(external_memory.object_count() > 0);
            assert!(external_memory.peak_stored_byte_length() > 0);
            assert!(external_memory.total_written_byte_length() > 0);
            assert!(external_memory.total_read_byte_length() > 0);
            assert!(external_memory.transaction_count() > 0);
            eprintln!(
                "proof_variant index={variant_catalog_index} schema={:#06x} schedule={:?} top_count={:?} privacy={:?} relation_plan_bytes={} relation_plan_hash={} variant_bytes={} variant_hash={} trace_domain={} evaluation_domain={} opening_degree={} columns={} integer_lift_batches={} integer_lift_components={} coefficient_local_batches={} coefficient_local_residuals={} opening_points={} opening_claims={} logical_relations={} mask_coordinates={:?} checkpoint_cursor_manifest_requirement={:?} checkpoint_custody_requirement={:?} checkpoint_boundaries={} proof_ceiling={} bound_trees={} components={:?} maximum_prefetched_query_bytes={} base_resident_peak={} combined_resident_peak={} base_resident_phases={:?} combined_resident_phases={:?} external_requirement={:?} verifier_hash_equation_ledger={:?} trees={:?}",
                variant.application_statement_schema_identifier(),
                variant.schedule_position(),
                variant.top_count(),
                variant.proof_privacy_mode(),
                variant.canonical_relation_plan_byte_length(),
                bytes_to_hex(&variant.canonical_relation_plan_hash()),
                variant.canonical_variant_byte_length(),
                bytes_to_hex(&variant.canonical_variant_hash()),
                variant.trace_domain_size(),
                variant.evaluation_domain_size(),
                variant.opening_degree_bound_exclusive(),
                variant.relation_column_count(),
                variant.integer_lift_batch_count(),
                variant.integer_lift_component_count(),
                variant.coefficient_local_identity_batch_count(),
                variant.coefficient_local_residual_count(),
                variant.opening_point_count(),
                variant.opening_claim_count(),
                variant.logical_relation_count(),
                variant.mask_coordinate_consumption(),
                variant.checkpoint_cursor_manifest_requirement(),
                variant.checkpoint_custody_requirement(),
                variant.checkpoint_boundary_count(),
                variant.proof_byte_length(),
                variant.bound_tree_count(),
                variant.component_byte_lengths(),
                variant.maximum_prefetched_query_byte_length(),
                variant.resident_memory_requirement().peak_byte_length(),
                variant.combined_resident_memory_peak_byte_length(),
                variant.resident_memory_requirement().phases(),
                variant.resident_memory_phase_ceilings(),
                variant.external_memory_requirement(),
                variant.verifier_hash_equation_ledger(),
                variant.tree_ceilings(),
            );
            assert_selected_variant_fits_absolute_resource_bounds(variant);
        }
        assert_eq!(
            accounting.actions().len(),
            usize::from(FOUNDATION_PROFILE.option_count)
        );
        for (expected_top_count, action) in
            (1..=FOUNDATION_PROFILE.option_count).zip(accounting.actions())
        {
            assert_eq!(action.top_count(), expected_top_count);
            let physical_count = action
                .variant_applications()
                .iter()
                .map(|row| row.physical_proof_object_count())
                .sum::<u32>();
            let logical_count = action
                .variant_applications()
                .iter()
                .map(|row| row.logical_relation_application_count())
                .sum::<u32>();
            let proof_byte_length = action
                .variant_applications()
                .iter()
                .map(|row| row.proof_byte_length())
                .sum::<u64>();
            let component_byte_lengths = action
                .variant_applications()
                .iter()
                .try_fold(
                    SelectedProofComponentByteLengths::default(),
                    |total, row| total.checked_add(row.component_byte_lengths()),
                )
                .expect("selected action component byte lengths sum without overflow");
            assert_eq!(physical_count, action.physical_proof_object_count());
            assert_eq!(logical_count, action.logical_relation_application_count());
            assert_eq!(proof_byte_length, action.proof_byte_length());
            assert_eq!(component_byte_lengths, action.component_byte_lengths());
            assert_eq!(
                action.component_byte_lengths().proof_byte_length(),
                Some(action.proof_byte_length())
            );
            let secret_leaf_population = action.secret_leaf_population_accounting();
            assert_eq!(
                secret_leaf_population.physical_root_count(),
                secret_leaf_population.proof_local_physical_root_count()
                    + secret_leaf_population.persistent_physical_root_count()
            );
            assert_eq!(
                secret_leaf_population.distinct_full_salted_leaf_count(),
                secret_leaf_population.proof_local_full_salted_leaf_count()
                    + secret_leaf_population.persistent_full_salted_leaf_count()
            );
            assert_eq!(
                secret_leaf_population.proof_view_full_salted_leaf_occurrence_count(),
                secret_leaf_population.opened_salted_leaf_occurrence_count()
                    + secret_leaf_population.hidden_salted_leaf_occurrence_count()
            );
            assert!(
                secret_leaf_population.distinct_full_salted_leaf_count()
                    <= secret_leaf_population.proof_view_full_salted_leaf_occurrence_count()
            );
            assert_eq!(
                secret_leaf_population.statistical_privacy_denominator_exponent(),
                BCS_MERKLE_STATISTICAL_PRIVACY_DENOMINATOR_EXPONENT
            );
            assert!(
                secret_leaf_population.distinct_full_secret_tree_hash_equation_count()
                    >= secret_leaf_population.physical_root_count()
            );
            assert_eq!(
                action
                    .categories()
                    .iter()
                    .map(|category| category.physical_proof_object_count())
                    .sum::<u32>(),
                action.physical_proof_object_count()
            );
            assert_eq!(
                action
                    .categories()
                    .iter()
                    .map(|category| category.canonical_proof_byte_length())
                    .sum::<u64>(),
                action.proof_byte_length()
            );
            assert_eq!(
                action
                    .categories()
                    .iter()
                    .map(|category| category.category())
                    .collect::<Vec<_>>(),
                SelectedProofCorpusCategory::ALL
            );
            for category in action.categories() {
                let canonical_proof_byte_length = category.canonical_proof_byte_length();
                assert_eq!(
                    category.producer_upload_byte_length(),
                    canonical_proof_byte_length
                );
                assert_eq!(
                    category.single_verifier_download_byte_length(),
                    canonical_proof_byte_length
                );
                assert_eq!(
                    category.public_storage_byte_length(),
                    canonical_proof_byte_length
                );
                assert_eq!(
                    category.producer_cached_byte_length(),
                    canonical_proof_byte_length
                );
                let fixed_copies = category.fixed_transport_copies();
                assert_eq!(
                    fixed_copies.generation_pending_chunk_staging_byte_length(),
                    canonical_proof_byte_length
                );
                assert_eq!(
                    fixed_copies.generation_wasm_to_host_byte_length(),
                    canonical_proof_byte_length
                );
                assert_eq!(
                    fixed_copies.generation_authenticated_readback_byte_length(),
                    canonical_proof_byte_length
                );
                assert_eq!(
                    fixed_copies.verification_initial_ingress_byte_length(),
                    canonical_proof_byte_length
                );
                assert_eq!(
                    fixed_copies.generation_total_byte_length(),
                    canonical_proof_byte_length.checked_mul(3)
                );
                assert!(category.generation_resident_peak_byte_length() > 0);
                assert!(category.external_scratch_peak_stored_byte_length() > 0);
                assert!(category.external_scratch_total_written_byte_length() > 0);
                assert!(category.external_scratch_total_read_byte_length() > 0);
                assert!(category.external_scratch_transaction_count() > 0);
                assert!(category.maximum_copied_buffer_byte_length() > 0);
            }
            let action_components = action.component_byte_lengths();
            assert!(action_components.canonical_framing() > 0);
            assert!(action_components.relation_commitments_and_openings() > 0);
            assert!(action_components.quotient_commitments_and_openings() > 0);
            assert!(action_components.transcript_opening_claims() > 0);
            assert!(action_components.fri() > 0);
            assert!(action.variant_applications().iter().all(|row| {
                row.application_multiplicity() > 0
                    && row.application_statement_schema_identifier()
                        == accounting.variant_ceilings()[row.variant_catalog_index()]
                            .application_statement_schema_identifier()
                    && row.schedule_position()
                        == accounting.variant_ceilings()[row.variant_catalog_index()]
                            .schedule_position()
                    && row.top_count()
                        == accounting.variant_ceilings()[row.variant_catalog_index()].top_count()
                    && row.component_byte_lengths().proof_byte_length()
                        == Some(row.proof_byte_length())
                    && accounting
                        .variant_ceilings()
                        .get(row.variant_catalog_index())
                        .is_some()
            }));
            let (setup_proof_object_count, setup_proof_byte_length) = action
                .variant_applications()
                .iter()
                .filter(|row| {
                    !matches!(
                        row.application_statement_schema_identifier(),
                        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                            | ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
                    )
                })
                .fold((0_u32, 0_u64), |(count, bytes), row| {
                    (
                        count + row.physical_proof_object_count(),
                        bytes + row.proof_byte_length(),
                    )
                });
            let (ballot_proof_object_count, ballot_proof_byte_length) = action
                .variant_applications()
                .iter()
                .filter(|row| {
                    row.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                })
                .fold((0_u32, 0_u64), |(count, bytes), row| {
                    (
                        count + row.physical_proof_object_count(),
                        bytes + row.proof_byte_length(),
                    )
                });
            let (target_proof_object_count, target_proof_byte_length) = action
                .variant_applications()
                .iter()
                .filter(|row| {
                    row.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
                })
                .fold((0_u32, 0_u64), |(count, bytes), row| {
                    (
                        count + row.physical_proof_object_count(),
                        bytes + row.proof_byte_length(),
                    )
                });
            assert_eq!(
                setup_proof_object_count + ballot_proof_object_count + target_proof_object_count,
                action.physical_proof_object_count()
            );
            assert_eq!(
                setup_proof_byte_length + ballot_proof_byte_length + target_proof_byte_length,
                action.proof_byte_length()
            );
            eprintln!(
                "proof_action top_count={} physical_objects={} logical_relations={} proof_ceiling={} components={:?} secret_leaf_population={:?} rows={:?}",
                action.top_count(),
                action.physical_proof_object_count(),
                action.logical_relation_application_count(),
                action.proof_byte_length(),
                action.component_byte_lengths(),
                action.secret_leaf_population_accounting(),
                action.variant_applications(),
            );
            eprintln!(
                "proof_action_categories top_count={} setup_objects={} setup_bytes={} ballot_objects={} ballot_bytes={} target_objects={} target_bytes={} complete_objects={} complete_bytes={}",
                action.top_count(),
                setup_proof_object_count,
                setup_proof_byte_length,
                ballot_proof_object_count,
                ballot_proof_byte_length,
                target_proof_object_count,
                target_proof_byte_length,
                action.physical_proof_object_count(),
                action.proof_byte_length(),
            );
            assert!(
                action.proof_byte_length() <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                "selected top-count {} action needs {} proof bytes, exceeding the {}-byte absolute canonical transport-stream bound",
                action.top_count(),
                action.proof_byte_length(),
                MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
            );
        }
        eprintln!(
            "proof_totals family_maxima={family_maxima:?} maximum_variant={:?} variants_above_planning_target={} maximum_physical_objects={} maximum_logical_relations={} maximum_action_bytes={} ballot_bytes={:?}",
            (
                maximum_variant.application_statement_schema_identifier(),
                maximum_variant.schedule_position(),
                maximum_variant.top_count(),
                maximum_variant.proof_byte_length(),
            ),
            variant_count_above_planning_target,
            accounting.maximum_proof_object_count(),
            accounting.maximum_logical_relation_application_count(),
            accounting.maximum_proof_byte_length(),
            accounting.ballot_proof_byte_length(),
        );
        eprintln!(
            "proof_soft_planning_variances proof_target={} proof_maximum={} proof_overage={} proof_variants_above={} proof_ratio={:.6} scratch_target={} scratch_maximum={} scratch_overage={} scratch_variants_above={} scratch_ratio={:.6} resident_target={} resident_maximum={} resident_overage={} resident_variants_above={} resident_ratio={:.6} copied_target={} copied_maximum={} copied_overage={} copied_variants_above={} copied_ratio={:.6} corpus_target={} action_maximum={} action_overage={} actions_above={} action_ratio={:.6}",
            PROOF_BYTE_LENGTH_PLANNING_TARGET,
            maximum_variant.proof_byte_length(),
            maximum_variant
                .proof_byte_length()
                .saturating_sub(PROOF_BYTE_LENGTH_PLANNING_TARGET),
            variant_count_above_planning_target,
            maximum_variant.proof_byte_length() as f64 / PROOF_BYTE_LENGTH_PLANNING_TARGET as f64,
            EXTERNAL_SCRATCH_PLANNING_TARGET,
            maximum_external_scratch_byte_length,
            maximum_external_scratch_byte_length.saturating_sub(EXTERNAL_SCRATCH_PLANNING_TARGET),
            external_scratch_count_above_planning_target,
            maximum_external_scratch_byte_length as f64 / EXTERNAL_SCRATCH_PLANNING_TARGET as f64,
            WASM_RESIDENT_PLANNING_TARGET,
            maximum_resident_byte_length,
            maximum_resident_byte_length.saturating_sub(WASM_RESIDENT_PLANNING_TARGET),
            resident_count_above_planning_target,
            maximum_resident_byte_length as f64 / WASM_RESIDENT_PLANNING_TARGET as f64,
            COPIED_BUFFER_PLANNING_TARGET,
            maximum_copied_buffer_byte_length,
            maximum_copied_buffer_byte_length.saturating_sub(COPIED_BUFFER_PLANNING_TARGET),
            copied_buffer_count_above_planning_target,
            maximum_copied_buffer_byte_length as f64 / COPIED_BUFFER_PLANNING_TARGET as f64,
            COMPLETE_CORPUS_PLANNING_TARGET,
            accounting.maximum_proof_byte_length(),
            accounting
                .maximum_proof_byte_length()
                .saturating_sub(COMPLETE_CORPUS_PLANNING_TARGET),
            action_count_above_corpus_planning_target,
            accounting.maximum_proof_byte_length() as f64 / COMPLETE_CORPUS_PLANNING_TARGET as f64,
        );
        assert_eq!(
            accounting.maximum_variant_proof_byte_length(),
            maximum_variant.proof_byte_length()
        );
        assert_eq!(
            accounting.maximum_proof_object_count(),
            accounting
                .actions()
                .iter()
                .map(SelectedActionProofAccounting::physical_proof_object_count)
                .max()
                .expect("the selected action catalog is non-empty")
        );
        assert_eq!(
            accounting.maximum_proof_object_count(),
            selected_maximum_proof_objects_per_action()
                .expect("the production selected proof-slot ceiling derives")
        );
        assert_eq!(
            accounting.maximum_proof_byte_length(),
            accounting
                .actions()
                .iter()
                .map(SelectedActionProofAccounting::proof_byte_length)
                .max()
                .expect("the selected action catalog is non-empty")
        );
        assert!(
            accounting
                .ballot_proof_byte_length()
                .is_some_and(|length| length > 0)
        );
        assert!(accounting.maximum_proof_byte_length() > 0);
    }
}
