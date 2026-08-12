//! Browser-worker runtime boundaries for the common proof engine.
//!
//! This module owns the non-serializable plan, operation, and verification
//! capabilities used around the generic common prover and verifier. Large
//! proof bytes cross the worker boundary one canonical stream chunk at a time;
//! a chunk is retained until the browser transaction acknowledges it and is
//! then dropped before the next chunk is assembled. External-memory requests
//! use the recorder/replay adapter from `external_memory`, so an asynchronous
//! browser transaction can be replayed byte-for-byte before cryptographic
//! state advances.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::bgv::setup::{CanonicalAcceptedSetupPackage, VerifiedPublicRandomness};
use crate::foundation::{
    AuthenticatedCheckpointContinuationSource, BrowserWorkerAuthenticatedStorageHeadSource,
    BrowserWorkerAuthenticatedStorageTransitionSource, CanonicalDecodeLimits,
    CanonicalStreamDomain, CanonicalStreamReadbackVerifier, CanonicalStreamVerifier,
    CanonicalStreamWriter, FOUNDATION_PROFILE, Hash512, LocalStorageBinding,
    PreparedActionProofAttemptSource, ProofApplicationBinding, ProofApplicationSlot,
    ProofApplicationSlotCeilings, ProofObjectHeader, RefusalReason, SelectedSuiteCapability,
    StreamDescriptor, VerifiedBoardApplicationSource, VerifiedCanonicalStreamSummary,
};
use crate::hashing::hash_framed_parts_512;

use super::relation_plan::RelationColumnOrigin;

use super::{
    CheckpointableCommonProofPrivateCoinSource, CommonProofByteSink,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinSource, CommonProofRequiredByteRange,
    CommonProofSourcePolynomialProvider, CommonProofVerifierError, CompiledRelationPlan,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, ProofExternalMemory,
    ProofExternalMemoryExecutorError, ProofExternalMemoryProtection,
    ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionRecorder,
    ProofExternalMemoryTransactionReplay, ProofExternalMemoryTransactionRequest, ProofProfileError,
    RelationPlanCheckContext, RelationProofTreeInput, ValidatedRelationPlanArtifact,
    VerifiedCommonProof, VerifiedEvaluatorAuxiliaryRoot, VerifiedRelationColumnEvaluator,
    VerifiedRelationColumnEvaluatorMemoryAccounting, VerifiedStatementOwnedTree,
    row_code_whir::RowCodeWhirConstructionPlan, verified_application_statement_hash,
};
#[cfg(test)]
use super::{SelectedApplicationStatementContext, decode_selected_vss_share_linkage_statement};

const HASH_BYTE_LENGTH: usize = 64;
const VERIFICATION_BINDING_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/verification-binding/v2";
const GENERATION_BINDING_HASH_DOMAIN: &str = "sealed-lattice/common-proof/generation-binding/v2";
const CHECKPOINT_GENESIS_HASH_DOMAIN: &str = "sealed-lattice/common-proof/checkpoint-genesis/v1";
const CHECKPOINT_CURSOR_MANIFEST_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/checkpoint-cursor-manifest/v3";
const CHECKPOINT_EVENT_HASH_DOMAIN: &str = "sealed-lattice/common-proof/checkpoint-event/v1";
const CHECKPOINT_CUMULATIVE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/checkpoint-cumulative/v1";
const CHECKPOINT_SCHEDULE_HASH_DOMAIN: &str = "sealed-lattice/common-proof/checkpoint-schedule/v1";
const CHECKPOINT_SCHEDULE_VERSION: u16 = 2;
const PROOF_APPLICATION_BINDING_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/application-binding/v2";
pub(super) const CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/canonical-application-binding/v1";
const OUTPUT_WRITE_HASH_DOMAIN: &str = "sealed-lattice/common-proof/output-write/v1";
const DURABLE_AUTHORIZATION_FRAME_MAGIC: [u8; 8] = *b"SLCPA001";
const DURABLE_AUTHORIZATION_FRAME_VERSION: u16 = 2;
pub(crate) const DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH: usize = 742;
const DURABLE_AUTHORIZATION_RECORD_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/durable-authorization-record/v1";
const COMMON_PROOF_CHECKPOINT_STATE_MAGIC: [u8; 8] = *b"SLCPCK02";
const COMMON_PROOF_CHECKPOINT_STATE_VERSION: u16 = 2;
// Checkpoint state is a build-bound custom binary format, not a canonical
// tuple schema. Its distinct identifier avoids ambiguity with the canonical
// proof-application-slot schema while the authenticated checkpoint manifest
// binds resumption to the exact runtime build.
pub(crate) const COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER: u16 = 0x010c;
pub(crate) const COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH: usize = 400;

/// Absolute anti-exhaustion bound for one canonical streamed proof artifact.
/// Exact proof-family geometry remains cryptographically binding, while phone
/// qualification targets are measured separately and never affect validity.
pub(crate) const MAXIMUM_COMMON_PROOF_BYTE_LENGTH: usize = 268_435_456;

/// A common-proof runtime never retains more than one canonical transport
/// chunk awaiting acknowledgement.
pub(crate) const MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH: usize = 1_048_576;

/// Fixed format capacity of one external-memory record.
/// Every non-final object append has this exact byte length and the final
/// append has the smaller remaining object extent. External-memory records use
/// the same canonical chunk size as foundation streams and local-record
/// plaintexts.
const _: () = assert!(FOUNDATION_PROFILE.stream_chunk_byte_length <= u32::MAX as usize);
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH: u32 =
    FOUNDATION_PROFILE.stream_chunk_byte_length as u32;

/// At most two authenticated input chunks may be resident around an
/// incremental decoder call.
pub(crate) const MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS: usize = 2;
const MAXIMUM_COMMON_PROOF_REGISTRY_ENTRY_COUNT: usize = 64;
const MAXIMUM_COMMON_PROOF_HEAVY_OPERATION_COUNT: usize = 1;

pub(crate) fn common_proof_registry_entry_count(
    entry_counts: &[usize],
) -> Result<usize, CommonProofRuntimeError> {
    entry_counts
        .iter()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
}

pub(crate) fn require_common_proof_registry_entry_capacity(
    entry_counts: &[usize],
) -> Result<(), CommonProofRuntimeError> {
    if common_proof_registry_entry_count(entry_counts)? >= MAXIMUM_COMMON_PROOF_REGISTRY_ENTRY_COUNT
    {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    Ok(())
}

pub(crate) fn require_common_proof_worker_process_admission_capacity(
    entry_counts: &[usize],
    heavy_operation_counts: &[usize],
    admits_heavy_operation: bool,
) -> Result<(), CommonProofRuntimeError> {
    let admitted_entry_count = common_proof_registry_entry_count(entry_counts)?
        .checked_add(1)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let admitted_heavy_operation_count = common_proof_registry_entry_count(heavy_operation_counts)?
        .checked_add(usize::from(admits_heavy_operation))
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    require_common_proof_worker_process_ownership_limits(
        &[admitted_entry_count],
        &[admitted_heavy_operation_count],
    )
}

pub(crate) fn require_common_proof_worker_process_ownership_limits(
    entry_counts: &[usize],
    heavy_operation_counts: &[usize],
) -> Result<(), CommonProofRuntimeError> {
    if common_proof_registry_entry_count(entry_counts)? > MAXIMUM_COMMON_PROOF_REGISTRY_ENTRY_COUNT
        || common_proof_registry_entry_count(heavy_operation_counts)?
            > MAXIMUM_COMMON_PROOF_HEAVY_OPERATION_COUNT
    {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRuntimeError {
    InvalidLimits,
    InvalidPlanCapability,
    WrongVerificationBinding,
    UnknownOrStaleHandle,
    CancellationRequested,
    TransactionPending,
    TransactionResponseMissing,
    TransactionReplayIncomplete,
    OutputByteLengthExceeded,
    OutputChunkAwaitingCommit,
    OutputChunkAwaitingReadback,
    OutputChunkNotReady,
    OutputWriteReplayMismatch,
    AllocationLimitExceeded,
    AuthenticatedStorageHeadMismatch,
    WrongOperationPhase,
}

/// Runtime parameters applied before any large proof allocation or browser
/// storage request. The maximum proof and prefetched-query byte lengths may
/// reduce their absolute safety bounds. The generated proof's exact length is
/// authenticated separately by its canonical stream descriptor. The external-memory record length
/// must equal its fixed format parameter, as must the foundation proof
/// transport chunk checked by [`CommonProofRuntimeLimits::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofRuntimeLimits {
    maximum_proof_byte_length: usize,
    external_memory_chunk_byte_length: u32,
    prefetched_query_byte_length: u64,
}

impl CommonProofRuntimeLimits {
    pub(crate) fn new(
        maximum_proof_byte_length: usize,
        external_memory_chunk_byte_length: u32,
        prefetched_query_byte_length: u64,
    ) -> Result<Self, CommonProofRuntimeError> {
        let canonical_chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        if maximum_proof_byte_length == 0
            || maximum_proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || canonical_chunk_byte_length != MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
            || external_memory_chunk_byte_length
                != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || prefetched_query_byte_length == 0
            || prefetched_query_byte_length
                > u64::try_from(maximum_proof_byte_length)
                    .map_err(|_| CommonProofRuntimeError::InvalidLimits)?
        {
            return Err(CommonProofRuntimeError::InvalidLimits);
        }
        Ok(Self {
            maximum_proof_byte_length,
            external_memory_chunk_byte_length,
            prefetched_query_byte_length,
        })
    }

    pub(crate) const fn maximum_proof_byte_length(self) -> usize {
        self.maximum_proof_byte_length
    }

    pub(crate) const fn external_memory_chunk_byte_length(self) -> u32 {
        self.external_memory_chunk_byte_length
    }

    pub(crate) const fn prefetched_query_byte_length(self) -> u64 {
        self.prefetched_query_byte_length
    }
}

/// Opaque checked relation-plan capability. It can only be minted from a
/// compiled plan that passes the profile, relation, and construction checks
/// for its exact context and variant. The production constructor additionally
/// requires the globally selected family context.
pub(crate) struct CommonProofRelationPlanCapability {
    validated_relation_plan: ValidatedRelationPlanArtifact,
    relation_context: RelationPlanCheckContext,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    relation_plan_hash: [u8; HASH_BYTE_LENGTH],
    relation_plan_variant_hash: [u8; HASH_BYTE_LENGTH],
    row_code_whir_construction_plan: RowCodeWhirConstructionPlan,
    row_code_whir_construction_plan_identity_hash: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofRelationPlanCapability {
    pub(crate) fn from_compiled_plan(
        relation_plan: &CompiledRelationPlan,
        relation_context: &RelationPlanCheckContext,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Result<Self, CommonProofRelationPlanCapabilityError> {
        let validated =
            ValidatedRelationPlanArtifact::from_compiled_plan(relation_plan, relation_context)
                .map_err(CommonProofRelationPlanCapabilityError::Profile)?;
        let row_code_whir_construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            &validated,
            schedule_position,
            top_count,
        )
        .map_err(|_| CommonProofRelationPlanCapabilityError::RowCodeWhirConstructionPlan)?;
        Self::from_validated_plan(
            validated,
            schedule_position,
            top_count,
            row_code_whir_construction_plan,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_checked_fixture_plan(
        relation_plan: &CompiledRelationPlan,
        relation_context: &RelationPlanCheckContext,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Result<Self, CommonProofRelationPlanCapabilityError> {
        let validated = ValidatedRelationPlanArtifact::from_checked_fixture_plan(
            relation_plan,
            relation_context,
        )
        .map_err(CommonProofRelationPlanCapabilityError::Profile)?;
        let row_code_whir_construction_plan =
            RowCodeWhirConstructionPlan::for_checked_fixture_variant(
                &validated,
                relation_context,
                schedule_position,
                top_count,
            )
            .map_err(|_| CommonProofRelationPlanCapabilityError::RowCodeWhirConstructionPlan)?;
        Self::from_validated_plan(
            validated,
            schedule_position,
            top_count,
            row_code_whir_construction_plan,
        )
    }

    fn from_validated_plan(
        validated_relation_plan: ValidatedRelationPlanArtifact,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        row_code_whir_construction_plan: RowCodeWhirConstructionPlan,
    ) -> Result<Self, CommonProofRelationPlanCapabilityError> {
        let relation_plan_hash = row_code_whir_construction_plan.relation_plan_hash();
        let relation_plan_variant_hash =
            row_code_whir_construction_plan.relation_plan_variant_hash();
        let row_code_whir_construction_plan_identity_hash = row_code_whir_construction_plan
            .canonical_identity_hash()
            .map_err(|_| CommonProofRelationPlanCapabilityError::RowCodeWhirConstructionPlan)?;
        let relation_context = validated_relation_plan.checked_context().clone();
        Ok(Self {
            validated_relation_plan,
            relation_context,
            schedule_position,
            top_count,
            relation_plan_hash,
            relation_plan_variant_hash,
            row_code_whir_construction_plan,
            row_code_whir_construction_plan_identity_hash,
        })
    }

    pub(crate) const fn relation_plan_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.relation_plan_hash
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.relation_plan_variant_hash
    }

    pub(crate) const fn row_code_whir_construction_plan_identity_hash(
        &self,
    ) -> [u8; HASH_BYTE_LENGTH] {
        self.row_code_whir_construction_plan_identity_hash
    }

    pub(in crate::bgv::proof_suite) const fn row_code_whir_construction_plan(
        &self,
    ) -> &RowCodeWhirConstructionPlan {
        &self.row_code_whir_construction_plan
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.validated_relation_plan
            .application_statement_schema_identifier()
    }

    pub(crate) fn compiled_plan(&self) -> &CompiledRelationPlan {
        self.validated_relation_plan.compiled_plan()
    }

    pub(crate) const fn relation_context(&self) -> &RelationPlanCheckContext {
        &self.relation_context
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) fn proof_query_count(&self) -> Result<u32, CommonProofRuntimeError> {
        u32::try_from(self.row_code_whir_construction_plan.outer_query_count())
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)
    }

    /// Derives the exact durable-boundary schedule from the checked plan.
    /// Transport chunking and prefetch policy are deliberately absent: they
    /// may change how work is resumed but never which construction is proved.
    pub(crate) fn checkpoint_schedule_digest(&self) -> Result<Hash512, CommonProofRuntimeError> {
        let checkpoint_schedule_bytes = self
            .row_code_whir_construction_plan
            .canonical_checkpoint_schedule_bytes()
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        Ok(Hash512::from_bytes(hash_framed_parts_512(
            CHECKPOINT_SCHEDULE_HASH_DOMAIN,
            &[
                &CHECKPOINT_SCHEDULE_VERSION.to_le_bytes(),
                &COMMON_PROOF_CHECKPOINT_STATE_FORMAT_IDENTIFIER.to_le_bytes(),
                &self.row_code_whir_construction_plan_identity_hash,
                &checkpoint_schedule_bytes,
            ],
        )))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generation_input<'input>(
        &'input self,
        protocol_version: u16,
        suite_identifier: [u8; HASH_BYTE_LENGTH],
        canonical_application_statement_bytes: &'input [u8],
        relation_trees: Vec<RelationProofTreeInput>,
        source_polynomial_provider: Box<dyn CommonProofSourcePolynomialProvider>,
        limits: CommonProofRuntimeLimits,
    ) -> CommonProofGenerationInput<'input> {
        CommonProofGenerationInput {
            protocol_version,
            suite_identifier,
            canonical_application_statement_bytes,
            relation_plan: self.validated_relation_plan.compiled_plan(),
            relation_context: &self.relation_context,
            schedule_position: self.schedule_position,
            top_count: self.top_count,
            relation_trees,
            source_polynomial_provider,
            maximum_external_memory_chunk_byte_length: limits.external_memory_chunk_byte_length(),
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: limits.prefetched_query_byte_length(),
        }
    }

    pub(crate) const fn validated_relation_plan_artifact(&self) -> &ValidatedRelationPlanArtifact {
        &self.validated_relation_plan
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRelationPlanCapabilityError {
    Profile(ProofProfileError),
    RowCodeWhirConstructionPlan,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofSelectedSuiteCapabilityHandle(u32);

impl CommonProofSelectedSuiteCapabilityHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofApplicationInputCapabilityHandle(u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofPreverificationApplicationSourceHandle(u32);

/// Verifier-owned authority for the exact source and selected coordinates of
/// one common-proof application. It is minted only from a verified board
/// source or from the positively joined canonical accepted-setup package.
pub(super) struct VerifiedCommonProofApplicationSourceAuthority {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    application_source_object_hash: Hash512,
    application_statement_schema_identifier: u16,
    producer_roster_position: Option<u16>,
    schedule_position: Option<u32>,
    producer_sequence: Option<u64>,
    proof_stream_descriptor: StreamDescriptor,
}

impl VerifiedCommonProofApplicationSourceAuthority {
    fn from_verified_board_source(
        board_source: &VerifiedBoardApplicationSource,
        proof_application_binding: &ProofApplicationBinding,
    ) -> Self {
        let application_slot = proof_application_binding.application_slot();
        Self {
            suite_identifier: board_source.suite_identifier(),
            ceremony_context_hash: board_source.ceremony_context_hash(),
            action_context_hash: board_source.action_context_hash(),
            application_source_object_hash: board_source.object_hash(),
            application_statement_schema_identifier: application_slot
                .application_statement_schema_identifier(),
            producer_roster_position: board_source.producer_roster_position(),
            schedule_position: application_slot.schedule_position(),
            producer_sequence: application_slot
                .producer_sequence()
                .map(|_| board_source.producer_sequence()),
            proof_stream_descriptor: proof_application_binding.proof_stream_descriptor().clone(),
        }
    }

    fn from_verified_accepted_setup_package(
        setup_package: &CanonicalAcceptedSetupPackage,
        verified_public_randomness: &VerifiedPublicRandomness,
        proof_descriptor_index: usize,
    ) -> Result<(Self, u16), CommonProofRuntimeError> {
        if setup_package.setup_intent_object_hashes()
            != verified_public_randomness.ordered_setup_intent_object_hashes()
            || setup_package.public_randomness_commitment_object_hashes()
                != verified_public_randomness.ordered_commitment_object_hashes()
            || setup_package.public_randomness_reveal_object_hashes()
                != verified_public_randomness.ordered_reveal_object_hashes()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let selected_slots = setup_package
            .selected_public_proof_slots()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let selected_slot = selected_slots
            .get(proof_descriptor_index)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let proof_stream_descriptor = setup_package
            .ordered_proof_descriptors()
            .get(proof_descriptor_index)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?
            .clone();
        let verified_context = verified_public_randomness.context();
        let expected_application_slot = ProofApplicationSlot::new(
            verified_context.suite_identifier(),
            verified_context.ceremony_context_hash(),
            verified_context.action_context_hash(),
            selected_slot.application_statement_schema_identifier(),
            selected_slot.roster_position(),
            selected_slot.schedule_position(),
            None,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        Ok((
            Self {
                suite_identifier: expected_application_slot.suite_identifier(),
                ceremony_context_hash: expected_application_slot.ceremony_context_hash(),
                action_context_hash: expected_application_slot.action_context_hash(),
                application_source_object_hash: setup_package.setup_package_hash(),
                application_statement_schema_identifier: expected_application_slot
                    .application_statement_schema_identifier(),
                producer_roster_position: expected_application_slot.roster_position(),
                schedule_position: expected_application_slot.schedule_position(),
                producer_sequence: expected_application_slot.producer_sequence(),
                proof_stream_descriptor,
            },
            verified_context.protocol_version(),
        ))
    }

    pub(super) const fn suite_identifier(&self) -> Hash512 {
        self.suite_identifier
    }

    pub(super) const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(super) const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub(super) const fn application_source_object_hash(&self) -> Hash512 {
        self.application_source_object_hash
    }

    pub(super) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(super) const fn producer_roster_position(&self) -> Option<u16> {
        self.producer_roster_position
    }

    pub(super) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(super) const fn producer_sequence(&self) -> Option<u64> {
        self.producer_sequence
    }

    pub(super) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    fn matches_proof_application_binding(
        &self,
        proof_application_binding: &ProofApplicationBinding,
    ) -> bool {
        let application_slot = proof_application_binding.application_slot();
        application_slot.suite_identifier() == self.suite_identifier
            && application_slot.ceremony_context_hash() == self.ceremony_context_hash
            && application_slot.action_context_hash() == self.action_context_hash
            && application_slot.application_statement_schema_identifier()
                == self.application_statement_schema_identifier
            && application_slot.roster_position() == self.producer_roster_position
            && application_slot.schedule_position() == self.schedule_position
            && application_slot.producer_sequence() == self.producer_sequence
            && proof_application_binding.proof_stream_descriptor() == &self.proof_stream_descriptor
    }
}

/// Family-owned statement input for the generic verifier. Exact family
/// modules mint this only after deriving their canonical statement and proof
/// application binding from retained verifier-owned source authority. There is
/// deliberately no production constructor from caller bytes alone.
pub(crate) struct VerifiedCommonProofStatementSource {
    application_source_authority: VerifiedCommonProofApplicationSourceAuthority,
    application_statement_hash: Hash512,
    canonical_application_statement_bytes: Vec<u8>,
    proof_application_binding: ProofApplicationBinding,
    verification_binding: CommonProofVerificationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
    protocol_version: u16,
}

impl VerifiedCommonProofStatementSource {
    /// Test-only exact VSS source seam. It derives producer coordinates and
    /// every context binding from the canonical statement and the retained
    /// public-randomness terminal; tests cannot supply detached roots or plan
    /// coordinates through this constructor.
    #[cfg(test)]
    pub(in crate::bgv) fn from_test_verified_vss_statement_source(
        verified_public_randomness: &VerifiedPublicRandomness,
        canonical_application_statement_bytes: Vec<u8>,
        proof_stream_descriptor: StreamDescriptor,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        let schema_identifier =
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        if relation_plan.application_statement_schema_identifier() != schema_identifier
            || relation_plan.schedule_position.is_some()
            || relation_plan.top_count.is_some()
        {
            return Err(CommonProofRuntimeError::InvalidPlanCapability);
        }
        let context = verified_public_randomness.context();
        let statement = decode_selected_vss_share_linkage_statement(
            &canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                context.protocol_version(),
                context.suite_identifier().into_bytes(),
                None,
                None,
            ),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let roster_position = statement.roster_position();
        if statement.protocol_version() != context.protocol_version()
            || statement.suite_identifier() != context.suite_identifier().into_bytes()
            || statement.ceremony_context_hash() != context.ceremony_context_hash().into_bytes()
            || statement.action_context_hash() != context.action_context_hash().into_bytes()
            || statement.roster_hash() != context.roster_hash().into_bytes()
            || statement.public_setup_seed()
                != verified_public_randomness.public_setup_seed().into_bytes()
            || verified_public_randomness
                .ordered_participant_identities()
                .get(usize::from(roster_position))
                .map(|identity| identity.into_bytes())
                != Some(statement.participant_identity())
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let application_slot = ProofApplicationSlot::new(
            context.suite_identifier(),
            context.ceremony_context_hash(),
            context.action_context_hash(),
            schema_identifier,
            Some(roster_position),
            None,
            None,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let proof_header = ProofObjectHeader::from_canonical_application_statement(
            canonical_application_statement_bytes.clone(),
            &CanonicalDecodeLimits::default(),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let proof_application_binding = ProofApplicationBinding::new(
            application_slot,
            proof_header
                .proof_header_hash()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
            proof_stream_descriptor.clone(),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let application_source_authority = VerifiedCommonProofApplicationSourceAuthority {
            suite_identifier: context.suite_identifier(),
            ceremony_context_hash: context.ceremony_context_hash(),
            action_context_hash: context.action_context_hash(),
            application_source_object_hash: verified_public_randomness.setup_proof_context_hash(),
            application_statement_schema_identifier: schema_identifier,
            producer_roster_position: Some(roster_position),
            schedule_position: None,
            producer_sequence: None,
            proof_stream_descriptor,
        };
        Self::from_exact_family_application_source_authority(
            application_source_authority,
            context.protocol_version(),
            canonical_application_statement_bytes,
            proof_application_binding,
            relation_plan,
            limits,
        )
    }

    /// Joins one exact-family statement to a positively verified board
    /// carrier. The board object hash is never transported into this
    /// constructor: it is read only from the retained board capability after
    /// the family has recomputed the canonical statement and selected the
    /// checked relation and exact limits.
    pub(super) fn from_exact_family_verified_board_source(
        board_source: VerifiedBoardApplicationSource,
        protocol_version: u16,
        canonical_application_statement_bytes: Vec<u8>,
        proof_application_binding: ProofApplicationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        let application_source_authority =
            VerifiedCommonProofApplicationSourceAuthority::from_verified_board_source(
                &board_source,
                &proof_application_binding,
            );
        Self::from_exact_family_application_source_authority(
            application_source_authority,
            protocol_version,
            canonical_application_statement_bytes,
            proof_application_binding,
            relation_plan,
            limits,
        )
    }

    /// Joins one exact-family statement to the exact selected proof slot and
    /// descriptor committed by a canonical accepted-setup package. The package
    /// inventory must name the same positively verified setup-intent,
    /// commitment, and reveal objects as the retained public-randomness
    /// terminal. The caller-provided binding cannot select a different slot or
    /// descriptor.
    pub(in crate::bgv) fn from_exact_family_verified_accepted_setup_package(
        setup_package: &CanonicalAcceptedSetupPackage,
        verified_public_randomness: &VerifiedPublicRandomness,
        proof_descriptor_index: usize,
        canonical_application_statement_bytes: Vec<u8>,
        proof_application_binding: ProofApplicationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        let (application_source_authority, protocol_version) =
            VerifiedCommonProofApplicationSourceAuthority::from_verified_accepted_setup_package(
                setup_package,
                verified_public_randomness,
                proof_descriptor_index,
            )?;
        Self::from_exact_family_application_source_authority(
            application_source_authority,
            protocol_version,
            canonical_application_statement_bytes,
            proof_application_binding,
            relation_plan,
            limits,
        )
    }

    fn from_exact_family_application_source_authority(
        application_source_authority: VerifiedCommonProofApplicationSourceAuthority,
        protocol_version: u16,
        canonical_application_statement_bytes: Vec<u8>,
        proof_application_binding: ProofApplicationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        let application_slot = proof_application_binding.application_slot();
        let statement_schema_identifier =
            application_slot.application_statement_schema_identifier();
        let proof_header = ProofObjectHeader::from_canonical_application_statement(
            canonical_application_statement_bytes.clone(),
            &CanonicalDecodeLimits::default(),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let expected_proof_header_hash = proof_header
            .proof_header_hash()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let proof_stream_descriptor = proof_application_binding.proof_stream_descriptor();
        let proof_byte_length = usize::try_from(proof_stream_descriptor.total_byte_length)
            .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
        if protocol_version == 0
            || canonical_application_statement_bytes.is_empty()
            || canonical_application_statement_bytes.len()
                > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || proof_byte_length > limits.maximum_proof_byte_length()
            || !application_source_authority
                .matches_proof_application_binding(&proof_application_binding)
            || proof_application_binding.proof_header_hash() != expected_proof_header_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let proof_stream_domain = common_proof_stream_domain(statement_schema_identifier)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let canonical_binding_bytes = proof_application_binding
            .encode()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let canonical_binding_hash = hash_framed_parts_512(
            CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
            &[&canonical_binding_bytes],
        );
        let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
            protocol_version,
            application_slot.suite_identifier().into_bytes(),
            statement_schema_identifier,
            &canonical_application_statement_bytes,
        ));
        let proof_application = CommonProofApplicationBinding::new(
            application_slot
                .hash()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
                .into_bytes(),
            canonical_binding_hash,
            relation_plan.row_code_whir_construction_plan_identity_hash(),
            statement_schema_identifier,
            expected_proof_header_hash.into_bytes(),
            proof_stream_domain,
            proof_stream_descriptor.full_object_digest.into_bytes(),
            proof_stream_descriptor.total_byte_length,
        )?;
        let verification_binding = CommonProofVerificationBinding::new(
            application_slot.suite_identifier().into_bytes(),
            application_slot.ceremony_context_hash().into_bytes(),
            application_slot.action_context_hash().into_bytes(),
            application_source_authority
                .application_source_object_hash()
                .into_bytes(),
            proof_application,
            relation_plan.relation_plan_hash(),
        );
        Ok(Self {
            application_source_authority,
            application_statement_hash,
            canonical_application_statement_bytes,
            proof_application_binding,
            verification_binding,
            relation_plan,
            limits,
            protocol_version,
        })
    }

    pub(super) const fn application_source_authority(
        &self,
    ) -> &VerifiedCommonProofApplicationSourceAuthority {
        &self.application_source_authority
    }

    pub(crate) const fn application_statement_hash(&self) -> Hash512 {
        self.application_statement_hash
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn proof_application_binding(&self) -> &ProofApplicationBinding {
        &self.proof_application_binding
    }

    #[cfg(test)]
    pub(crate) const fn relation_plan_capability(&self) -> &CommonProofRelationPlanCapability {
        &self.relation_plan
    }

    pub(crate) fn selected_relation_variant(
        &self,
    ) -> Result<&super::RelationPlanVariant, CommonProofRuntimeError> {
        if self.relation_plan.application_statement_schema_identifier()
            != self
                .application_source_authority
                .application_statement_schema_identifier()
        {
            return Err(CommonProofRuntimeError::InvalidPlanCapability);
        }
        self.relation_plan
            .compiled_plan()
            .select_variant(
                self.relation_plan.schedule_position,
                self.relation_plan.top_count,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)
    }

    pub(crate) fn verification_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.verification_binding.binding_hash()
    }

    /// Builds the genuine generic verifier for the native exact-proof
    /// evidence path. The source was already derived from a verified public-
    /// randomness terminal, and the production verifier rechecks the complete
    /// selected VSS relation and statement-tree catalog here.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(in crate::bgv::proof_suite) fn prepare_exact_vss_evidence_verification(
        self,
        statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        ConsumedCommonProofVerificationInputs {
            statement_source: CommonProofVerificationStatementSource::from_exact(self),
            statement_owned_trees,
            evaluator_auxiliary_roots: Vec::new(),
            verified_column_evaluator: Box::new(RefusingVerifiedColumnEvaluator),
        }
        .prepare_exact_vss_evidence()
    }

    pub(super) const fn verification_binding(&self) -> CommonProofVerificationBinding {
        self.verification_binding
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofEvaluatorAuxiliaryRootCapabilityHandle(u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofVerifiedColumnEvaluatorCapabilityHandle(u32);

struct CommonProofSelectedSuiteEntry {
    capability: SelectedSuiteCapability,
    canonical_suite_record_bytes: Vec<u8>,
}

/// Linear owner of the exact family-minted statement source used by one
/// common-proof verifier. It cannot be reconstructed from roots, decoded
/// bindings, or test-only fixture values.
pub(super) struct CommonProofVerificationStatementSource(Box<VerifiedCommonProofStatementSource>);

impl CommonProofVerificationStatementSource {
    pub(super) fn from_exact(source: VerifiedCommonProofStatementSource) -> Self {
        Self(Box::new(source))
    }

    pub(super) fn verification_binding(&self) -> CommonProofVerificationBinding {
        self.0.verification_binding
    }

    pub(super) fn relation_plan(&self) -> &CommonProofRelationPlanCapability {
        &self.0.relation_plan
    }

    pub(super) fn protocol_version(&self) -> u16 {
        self.0.protocol_version
    }

    pub(super) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.0.canonical_application_statement_bytes
    }

    pub(super) fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        self.0
            .application_source_authority
            .proof_stream_descriptor()
    }

    pub(super) fn limits(&self) -> CommonProofRuntimeLimits {
        self.0.limits
    }

    pub(super) fn exact_source(
        &self,
    ) -> Result<&VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
        Ok(&self.0)
    }

    #[cfg(test)]
    pub(super) fn into_exact_source(
        self,
    ) -> Result<VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
        Ok(*self.0)
    }
}

/// Package-builder expectations checked against a retained generated or
/// positively verified proof. This is borrowed call context, not serialized
/// proof material or authority.
#[derive(Clone, Copy)]
pub(crate) struct ExpectedCommonProofPackageBindings<'statement> {
    pub(crate) suite_identifier: [u8; HASH_BYTE_LENGTH],
    pub(crate) ceremony_context_hash: [u8; HASH_BYTE_LENGTH],
    pub(crate) action_context_hash: [u8; HASH_BYTE_LENGTH],
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) roster_position: Option<u16>,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) canonical_application_statement_bytes: &'statement [u8],
}

struct CommonProofApplicationInputEntry {
    statement_source: CommonProofVerificationStatementSource,
    statement_owned_tree_batch: Option<Vec<VerifiedStatementOwnedTree>>,
}

struct CommonProofPreverificationApplicationSourceEntry {
    source: VerifiedCommonProofStatementSource,
}

struct CommonProofEvaluatorAuxiliaryRootEntry {
    application_handle: u32,
    root: VerifiedEvaluatorAuxiliaryRoot,
}

struct CommonProofVerifiedColumnEvaluatorEntry {
    application_handle: u32,
    evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
}

struct RefusingVerifiedColumnEvaluator;

impl VerifiedRelationColumnEvaluator for RefusingVerifiedColumnEvaluator {
    fn memory_accounting(
        &self,
    ) -> Result<VerifiedRelationColumnEvaluatorMemoryAccounting, CommonProofVerifierError> {
        VerifiedRelationColumnEvaluatorMemoryAccounting::new(
            u64::try_from(core::mem::size_of::<Self>())
                .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            0,
            0,
        )
    }

    fn evaluate_at_extension_point(
        &mut self,
        _column_ordinal: u32,
        _point: super::ProofChallengeExtensionElement,
    ) -> Option<super::ProofChallengeExtensionElement> {
        None
    }
}

mod authorization_registry;
mod generation_worker;
mod storage_transport;
mod upstream_registry;
mod verification_worker;

pub(crate) use authorization_registry::{
    BorrowedVerifiedCommonProofCapability, CommonProofApplicationBinding,
    CommonProofGenerationOperationHandle, CommonProofRuntimeRegistry,
    CommonProofVerificationBinding, CommonProofVerificationOperationHandle,
    ConsumedVerifiedCommonProofCapability, GeneratedCommonProofCapabilityHandle,
    PendingCommonProofAuthorizationHandle, VerifiedCommonProofCapabilityHandle,
    durable_authorization_frame_digest,
};
pub(crate) use generation_worker::{
    AuthenticatedCommonProofGenerationCheckpoint, CommonProofGenerationAuthorization,
    CommonProofGenerationExternalMemoryAccounting, CommonProofGenerationPreparationError,
    CommonProofGenerationSources, CommonProofGenerationWorkerError,
    CommonProofGenerationWorkerPoll, PreparedCommonProofGeneration,
};
#[cfg(test)]
pub(crate) use generation_worker::{
    CommonProofGenerationCheckpointChain, CommonProofGenerationCheckpointChainAdvance,
    CommonProofGenerationTestCheckpointAuthority,
    MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH,
};
pub(crate) use storage_transport::{
    CommonProofStorageTransactionRuntime, PollableCommonProofByteSink,
    PollableCommonProofByteSinkError, ResidentCommonProofByteSource, ResidentCommonProofInputChunk,
};
pub(crate) use upstream_registry::CommonProofUpstreamInputRegistry;
pub(crate) use verification_worker::{
    CommonProofVerificationReadbackAccounting, CommonProofVerificationWorkerError,
    CommonProofVerificationWorkerPoll, ConsumedCommonProofVerificationInputs,
    PreparedCommonProofVerification,
};

#[cfg(test)]
use authorization_registry::take_replacement_handle_before_consuming_source;
use authorization_registry::{common_proof_stream_domain, take_nonrepeating_handle};
use generation_worker::{
    CommonProofGenerationWorker, GeneratedCommonProof, PendingCommonProofGenerationCheckpoint,
    required_chunk_indices,
};
use verification_worker::CommonProofVerificationWorker;

#[cfg(test)]
mod tests;
