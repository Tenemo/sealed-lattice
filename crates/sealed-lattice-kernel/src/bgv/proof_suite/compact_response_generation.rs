//! Pollable response custody for compact proof generation.
//!
//! The construction owner streams each response leaf into this state, then
//! reconstructs only the verifier-selected leaves at the response tree's
//! exact last-use boundary. Response values are therefore not retained merely
//! because a later verifier move determines their opening. External tree
//! transactions, transcript advancement, canonical proof assembly, and
//! authenticated checkpoint publication share one explicit state machine.

use std::collections::VecDeque;

use super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
use super::compact_generation_checkpoint::{
    CompactGenerationCheckpointError, CompactResponseCheckpointSchedule,
    compact_response_generation_checkpoint_boundary,
};
use super::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireInput,
    CompactProofWireAssembler, CompactProofWireError, CompactProofWireGeometry,
    DecodedCompactPublicInput,
};
use super::compact_response_merkle::{
    CompactResponseLeafValue, CompactResponseLeafValueKind, CompactResponseMerkleError,
    CompactResponseMerkleGeometry, CompactResponseQuerySchedule, compact_response_leaf_digest,
    reconstruct_compact_response_root,
};
use super::compact_response_tree_external::{
    CompactResponseTreeExternalMemoryExecutionError, CompactResponseTreeExternalMemorySetupError,
    CompactResponseTreeLastUseOutput, CompactResponseTreeRetentionDriver,
    CompactResponseTreeRetentionPoll,
};
use super::compact_transcript::{CompactProverTranscript, CompactTranscriptError};
use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryUsage,
};
use super::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};
use super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;
use super::prover::CommonProofGenerationCheckpointBoundary;
use crate::foundation::Hash512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactOwnedResponseLeaf {
    BaseField(Vec<ProofBaseFieldElement>),
    ExtensionField(Vec<ProofChallengeExtensionElement>),
    Padding,
}

impl CompactOwnedResponseLeaf {
    pub(crate) fn base_field(values: Vec<ProofBaseFieldElement>) -> Self {
        Self::BaseField(values)
    }

    pub(crate) fn extension_field(values: Vec<ProofChallengeExtensionElement>) -> Self {
        Self::ExtensionField(values)
    }

    pub(crate) const fn padding() -> Self {
        Self::Padding
    }

    pub(crate) fn borrowed(&self) -> CompactResponseLeafValue<'_> {
        match self {
            Self::BaseField(values) => CompactResponseLeafValue::BaseField(values),
            Self::ExtensionField(values) => CompactResponseLeafValue::ExtensionField(values),
            Self::Padding => CompactResponseLeafValue::Padding,
        }
    }

    pub(crate) const fn value_kind(&self) -> CompactResponseLeafValueKind {
        match self {
            Self::BaseField(_) => CompactResponseLeafValueKind::BaseField,
            Self::ExtensionField(_) => CompactResponseLeafValueKind::ExtensionField,
            Self::Padding => CompactResponseLeafValueKind::Padding,
        }
    }

    pub(crate) fn field_element_count(&self) -> Result<u64, CompactResponseGenerationError> {
        let value_count = match self {
            Self::BaseField(values) => values.len(),
            Self::ExtensionField(values) => values.len(),
            Self::Padding => 0,
        };
        u64::try_from(value_count).map_err(|_| CompactResponseGenerationError::InvalidGeometry)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactResponseGenerationError {
    InvalidGeometry,
    WrongPhase,
    AllocationLimitExceeded,
    RootMismatch,
    ProofWire(CompactProofWireError),
    ResponseMerkle(CompactResponseMerkleError),
    ResponseTreeSetup(CompactResponseTreeExternalMemorySetupError),
    ExternalMemory(ProofExternalMemoryError),
    Transcript(CompactTranscriptError),
    Checkpoint(CompactGenerationCheckpointError),
}

impl From<CompactProofWireError> for CompactResponseGenerationError {
    fn from(error: CompactProofWireError) -> Self {
        Self::ProofWire(error)
    }
}

impl From<CompactResponseMerkleError> for CompactResponseGenerationError {
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::ResponseMerkle(error)
    }
}

impl From<CompactResponseTreeExternalMemorySetupError> for CompactResponseGenerationError {
    fn from(error: CompactResponseTreeExternalMemorySetupError) -> Self {
        Self::ResponseTreeSetup(error)
    }
}

impl From<ProofExternalMemoryError> for CompactResponseGenerationError {
    fn from(error: ProofExternalMemoryError) -> Self {
        Self::ExternalMemory(error)
    }
}

impl From<CompactTranscriptError> for CompactResponseGenerationError {
    fn from(error: CompactTranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<CompactGenerationCheckpointError> for CompactResponseGenerationError {
    fn from(error: CompactGenerationCheckpointError) -> Self {
        Self::Checkpoint(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactResponseGenerationPollError<StorageError> {
    Generation(CompactResponseGenerationError),
    ResponseTree(CompactResponseTreeExternalMemoryExecutionError<StorageError>),
}

impl<StorageError> From<CompactResponseGenerationError>
    for CompactResponseGenerationPollError<StorageError>
{
    fn from(error: CompactResponseGenerationError) -> Self {
        Self::Generation(error)
    }
}

impl<StorageError> From<CompactResponseTreeExternalMemoryExecutionError<StorageError>>
    for CompactResponseGenerationPollError<StorageError>
{
    fn from(error: CompactResponseTreeExternalMemoryExecutionError<StorageError>) -> Self {
        Self::ResponseTree(error)
    }
}

impl<StorageError> From<CompactTranscriptError>
    for CompactResponseGenerationPollError<StorageError>
{
    fn from(error: CompactTranscriptError) -> Self {
        Self::Generation(CompactResponseGenerationError::Transcript(error))
    }
}

impl<StorageError> From<CompactResponseMerkleError>
    for CompactResponseGenerationPollError<StorageError>
{
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::Generation(CompactResponseGenerationError::ResponseMerkle(error))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactResponseGenerationPoll {
    ResponseRequired {
        response_ordinal: u32,
    },
    ResponseLeafRequired {
        response_ordinal: u32,
        leaf_ordinal: u64,
    },
    OpenedLeafRequired {
        response_ordinal: u32,
        leaf_ordinal: u64,
    },
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    CheckpointCursorRequired,
    Complete,
}

struct PendingCompactResponseOpening {
    query_schedule: CompactResponseQuerySchedule,
    output: CompactResponseTreeLastUseOutput,
    next_query_offset: usize,
    opened_leaf_digests: Vec<[u8; Hash512::BYTE_LENGTH]>,
    base_field_values: Vec<ProofBaseFieldElement>,
    extension_field_values: Vec<ProofChallengeExtensionElement>,
    leaf_salts: Vec<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
}

enum CompactResponseGenerationPhase {
    ReadyForResponse,
    StartingResponse {
        response_ordinal: u32,
        fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
    },
    WritingResponse {
        response_ordinal: u32,
        next_leaf_ordinal: u64,
        fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
    },
    AdvancingVerifierMove,
    OpeningResponse(Box<PendingCompactResponseOpening>),
    AwaitingCheckpointCursor,
    Terminal,
    Cancelled,
    Transitioning,
}

pub(crate) struct CompactResponseGenerationState {
    proof_wire_geometry: CompactProofWireGeometry,
    response_merkle_geometries: Vec<CompactResponseMerkleGeometry>,
    checkpoint_schedule: CompactResponseCheckpointSchedule,
    prover_transcript: CompactProverTranscript,
    verifier_messages: Vec<DecodedFixedUniformVerifierMessage>,
    proof_wire_assembler: CompactProofWireAssembler,
    response_tree_retention_driver: CompactResponseTreeRetentionDriver,
    pending_round_salts: Vec<Option<[u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH]>>,
    pending_wire_inputs: Vec<Option<CompactProofResponseWireInput>>,
    completed_openings: VecDeque<CompactResponseGenerationCompletedOpening>,
    latest_checkpoint_boundary: Option<CommonProofGenerationCheckpointBoundary>,
    phase: CompactResponseGenerationPhase,
}

pub(crate) struct CompactResponseGenerationOutput {
    canonical_proof_bytes: Vec<u8>,
    external_memory_usage: ProofExternalMemoryUsage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseGenerationCompletedOpening {
    response_ordinal: u32,
    root: [u8; Hash512::BYTE_LENGTH],
    query_leaf_ordinals: Vec<u64>,
    external_memory_usage: ProofExternalMemoryUsage,
}

impl CompactResponseGenerationCompletedOpening {
    pub(crate) const fn response_ordinal(&self) -> u32 {
        self.response_ordinal
    }

    pub(crate) const fn root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.root
    }

    pub(crate) fn query_leaf_ordinals(&self) -> &[u64] {
        &self.query_leaf_ordinals
    }

    pub(crate) const fn external_memory_usage(&self) -> ProofExternalMemoryUsage {
        self.external_memory_usage
    }
}

impl CompactResponseGenerationOutput {
    pub(crate) fn canonical_proof_bytes(&self) -> &[u8] {
        &self.canonical_proof_bytes
    }

    pub(crate) const fn external_memory_usage(&self) -> ProofExternalMemoryUsage {
        self.external_memory_usage
    }

    pub(crate) fn into_canonical_proof_bytes(self) -> Vec<u8> {
        self.canonical_proof_bytes
    }
}

impl CompactResponseGenerationState {
    pub(crate) fn new(
        proof_wire_geometry: &CompactProofWireGeometry,
        response_merkle_geometries: &[CompactResponseMerkleGeometry],
        decoded_public_input: &DecodedCompactPublicInput,
        canonical_public_input_bytes: &[u8],
    ) -> Result<Self, CompactResponseGenerationError> {
        let checkpoint_schedule = CompactResponseCheckpointSchedule::derive(
            proof_wire_geometry,
            response_merkle_geometries,
        )?;
        let prover_transcript = CompactProverTranscript::new(
            proof_wire_geometry,
            decoded_public_input,
            canonical_public_input_bytes,
        )?;
        let proof_wire_assembler = CompactProofWireAssembler::new(proof_wire_geometry)?;
        let response_tree_retention_driver = CompactResponseTreeRetentionDriver::new(
            response_merkle_geometries,
            proof_wire_geometry.responses(),
        )?;
        let response_count = proof_wire_geometry.responses().len();
        if response_count == 0 || response_count != response_merkle_geometries.len() {
            return Err(CompactResponseGenerationError::InvalidGeometry);
        }
        let mut verifier_messages = Vec::new();
        verifier_messages
            .try_reserve_exact(response_count)
            .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
        let mut pending_round_salts = Vec::new();
        pending_round_salts
            .try_reserve_exact(response_count)
            .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
        pending_round_salts.resize_with(response_count, || None);
        let mut pending_wire_inputs = Vec::new();
        pending_wire_inputs
            .try_reserve_exact(response_count)
            .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
        pending_wire_inputs.resize_with(response_count, || None);
        let mut completed_openings = VecDeque::new();
        completed_openings
            .try_reserve(response_count)
            .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
        Ok(Self {
            proof_wire_geometry: proof_wire_geometry.clone(),
            response_merkle_geometries: response_merkle_geometries.to_vec(),
            checkpoint_schedule,
            prover_transcript,
            verifier_messages,
            proof_wire_assembler,
            response_tree_retention_driver,
            pending_round_salts,
            pending_wire_inputs,
            completed_openings,
            latest_checkpoint_boundary: None,
            phase: CompactResponseGenerationPhase::ReadyForResponse,
        })
    }

    pub(crate) fn verifier_messages(&self) -> &[DecodedFixedUniformVerifierMessage] {
        &self.verifier_messages
    }

    pub(crate) fn canonical_proof_prefix_bytes(&self) -> &[u8] {
        self.proof_wire_assembler.canonical_prefix_bytes()
    }

    pub(crate) const fn checkpoint_boundary(
        &self,
    ) -> Option<&CommonProofGenerationCheckpointBoundary> {
        self.latest_checkpoint_boundary.as_ref()
    }

    pub(crate) fn take_completed_opening(
        &mut self,
    ) -> Option<CompactResponseGenerationCompletedOpening> {
        self.completed_openings.pop_front()
    }

    pub(crate) fn begin_response(
        &mut self,
        fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
    ) -> Result<(), CompactResponseGenerationError> {
        if !matches!(self.phase, CompactResponseGenerationPhase::ReadyForResponse) {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        let response_index = self.prover_transcript.completed_response_count();
        let response_geometry = self
            .response_merkle_geometries
            .get(response_index)
            .ok_or(CompactResponseGenerationError::WrongPhase)?;
        let expected_response_ordinal = u32::try_from(response_index)
            .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
        if response_geometry.response_ordinal() != expected_response_ordinal {
            return Err(CompactResponseGenerationError::InvalidGeometry);
        }
        self.latest_checkpoint_boundary = None;
        self.phase = CompactResponseGenerationPhase::StartingResponse {
            response_ordinal: expected_response_ordinal,
            fiat_shamir_round_salt,
        };
        Ok(())
    }

    pub(crate) fn supply_next_response_leaf(
        &mut self,
        leaf: &CompactOwnedResponseLeaf,
        leaf_salt: &[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
    ) -> Result<(), CompactResponseGenerationError> {
        let (response_ordinal, next_leaf_ordinal) = match self.phase {
            CompactResponseGenerationPhase::WritingResponse {
                response_ordinal,
                next_leaf_ordinal,
                ..
            } if self
                .response_tree_retention_driver
                .pending_tree_chunk()
                .is_none() =>
            {
                (response_ordinal, next_leaf_ordinal)
            }
            _ => return Err(CompactResponseGenerationError::WrongPhase),
        };
        let response_index = usize::try_from(response_ordinal)
            .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
        let leaf_count = self
            .response_merkle_geometries
            .get(response_index)
            .ok_or(CompactResponseGenerationError::InvalidGeometry)?
            .merkle_leaf_count();
        if next_leaf_ordinal >= leaf_count {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        self.response_tree_retention_driver
            .absorb_next_response_leaf(leaf.borrowed(), leaf_salt)?;
        let CompactResponseGenerationPhase::WritingResponse {
            next_leaf_ordinal, ..
        } = &mut self.phase
        else {
            return Err(CompactResponseGenerationError::WrongPhase);
        };
        *next_leaf_ordinal = next_leaf_ordinal
            .checked_add(1)
            .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
        Ok(())
    }

    pub(crate) fn supply_next_opened_leaf(
        &mut self,
        leaf: &CompactOwnedResponseLeaf,
        leaf_salt: [u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
    ) -> Result<(), CompactResponseGenerationError> {
        let CompactResponseGenerationPhase::OpeningResponse(opening) = &mut self.phase else {
            return Err(CompactResponseGenerationError::WrongPhase);
        };
        let leaf_ordinal = *opening
            .query_schedule
            .as_slice()
            .get(opening.next_query_offset)
            .ok_or(CompactResponseGenerationError::WrongPhase)?;
        let response_index = usize::try_from(opening.output.response_ordinal())
            .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
        let merkle_geometry = self
            .response_merkle_geometries
            .get(response_index)
            .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
        let leaf_digest = compact_response_leaf_digest(
            merkle_geometry,
            leaf_ordinal,
            leaf.borrowed(),
            &leaf_salt,
        )?;
        opening
            .opened_leaf_digests
            .try_reserve(1)
            .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
        opening.opened_leaf_digests.push(leaf_digest);
        match leaf {
            CompactOwnedResponseLeaf::BaseField(values) => {
                opening
                    .base_field_values
                    .try_reserve(values.len())
                    .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
                opening.base_field_values.extend_from_slice(values);
            }
            CompactOwnedResponseLeaf::ExtensionField(values) => {
                opening
                    .extension_field_values
                    .try_reserve(values.len())
                    .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
                opening.extension_field_values.extend_from_slice(values);
            }
            CompactOwnedResponseLeaf::Padding => {
                return Err(CompactResponseGenerationError::ResponseMerkle(
                    CompactResponseMerkleError::InvalidOpeningIndices,
                ));
            }
        }
        opening
            .leaf_salts
            .try_reserve(1)
            .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
        opening.leaf_salts.push(leaf_salt);
        opening.next_query_offset = opening
            .next_query_offset
            .checked_add(1)
            .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
        Ok(())
    }

    pub(crate) fn supply_checkpoint_private_randomness_cursor(
        &mut self,
        canonical_private_randomness_cursor_bytes: &[u8],
    ) -> Result<(), CompactResponseGenerationError> {
        if !matches!(
            self.phase,
            CompactResponseGenerationPhase::AwaitingCheckpointCursor
        ) || self.latest_checkpoint_boundary.is_some()
        {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        let boundary = compact_response_generation_checkpoint_boundary(
            &self.checkpoint_schedule,
            &self.prover_transcript,
            &self.proof_wire_assembler,
            canonical_private_randomness_cursor_bytes,
        )?;
        self.latest_checkpoint_boundary = Some(boundary);
        self.phase = if self.prover_transcript.completed_response_count()
            == self.prover_transcript.total_response_count()
        {
            CompactResponseGenerationPhase::Terminal
        } else {
            CompactResponseGenerationPhase::ReadyForResponse
        };
        Ok(())
    }

    pub(crate) fn restore_authenticated_checkpoint_transcript_cursor(
        &mut self,
        canonical_cursor_bytes: &[u8],
        expected_cursor_digest: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<(), CompactResponseGenerationError> {
        if !matches!(
            self.phase,
            CompactResponseGenerationPhase::ReadyForResponse
                | CompactResponseGenerationPhase::Terminal
        ) || self.latest_checkpoint_boundary.is_none()
        {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        self.prover_transcript
            .restore_authenticated_checkpoint_cursor(
                canonical_cursor_bytes,
                expected_cursor_digest,
            )?;
        let completed_proof_response_count = self
            .checkpoint_schedule
            .completed_proof_response_count(self.prover_transcript.completed_response_count())?;
        if self.proof_wire_assembler.completed_response_count() != completed_proof_response_count {
            return Err(CompactResponseGenerationError::Checkpoint(
                CompactGenerationCheckpointError::WrongResponseBoundary,
            ));
        }
        self.prover_transcript
            .validate_canonical_proof_prefix_at_response_count(
                self.proof_wire_assembler.canonical_prefix_bytes(),
                completed_proof_response_count,
            )?;
        Ok(())
    }

    pub(crate) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<CompactResponseGenerationPoll, CompactResponseGenerationPollError<Storage::Error>>
    {
        match self.phase {
            CompactResponseGenerationPhase::ReadyForResponse => {
                let response_ordinal =
                    u32::try_from(self.prover_transcript.completed_response_count())
                        .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                Ok(CompactResponseGenerationPoll::ResponseRequired { response_ordinal })
            }
            CompactResponseGenerationPhase::StartingResponse {
                response_ordinal,
                fiat_shamir_round_salt,
            } => {
                self.response_tree_retention_driver
                    .begin_next_response(storage)?;
                self.phase = CompactResponseGenerationPhase::WritingResponse {
                    response_ordinal,
                    next_leaf_ordinal: 0,
                    fiat_shamir_round_salt,
                };
                Ok(CompactResponseGenerationPoll::StorageTransactionCompleted)
            }
            CompactResponseGenerationPhase::WritingResponse {
                response_ordinal,
                next_leaf_ordinal,
                fiat_shamir_round_salt,
            } => {
                if self
                    .response_tree_retention_driver
                    .pending_tree_chunk()
                    .is_some()
                {
                    self.response_tree_retention_driver
                        .append_pending_tree_chunk(storage)?;
                    return Ok(CompactResponseGenerationPoll::StorageTransactionCompleted);
                }
                let response_index = usize::try_from(response_ordinal)
                    .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                let leaf_count = self
                    .response_merkle_geometries
                    .get(response_index)
                    .ok_or(CompactResponseGenerationError::InvalidGeometry)?
                    .merkle_leaf_count();
                if next_leaf_ordinal < leaf_count {
                    return Ok(CompactResponseGenerationPoll::ResponseLeafRequired {
                        response_ordinal,
                        leaf_ordinal: next_leaf_ordinal,
                    });
                }
                let root = self
                    .response_tree_retention_driver
                    .seal_next_response(storage)?;
                self.prover_transcript
                    .record_response_commitment(root, fiat_shamir_round_salt)?;
                let verifier_message = self.prover_transcript.derive_verifier_message()?;
                self.verifier_messages.push(verifier_message);
                let pending_round_salt = self
                    .pending_round_salts
                    .get_mut(response_index)
                    .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
                if pending_round_salt.replace(fiat_shamir_round_salt).is_some() {
                    return Err(CompactResponseGenerationError::WrongPhase.into());
                }
                self.phase = CompactResponseGenerationPhase::AdvancingVerifierMove;
                Ok(CompactResponseGenerationPoll::ArithmeticStepCompleted)
            }
            CompactResponseGenerationPhase::AdvancingVerifierMove => {
                match self
                    .response_tree_retention_driver
                    .advance_verifier_move(&self.verifier_messages, storage)?
                {
                    CompactResponseTreeRetentionPoll::StorageTransactionCompleted => {
                        Ok(CompactResponseGenerationPoll::StorageTransactionCompleted)
                    }
                    CompactResponseTreeRetentionPoll::OpeningReady(output) => {
                        let response_index = usize::try_from(output.response_ordinal())
                            .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                        let merkle_geometry =
                            self.response_merkle_geometries
                                .get(response_index)
                                .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
                        let query_schedule =
                            CompactResponseQuerySchedule::derive_at_last_query_boundary(
                                merkle_geometry,
                                self.proof_wire_geometry.responses(),
                                &self.verifier_messages,
                            )?;
                        if output.query_leaf_ordinals() != query_schedule.as_slice() {
                            return Err(CompactResponseGenerationError::InvalidGeometry.into());
                        }
                        let first_leaf_ordinal = *query_schedule
                            .as_slice()
                            .first()
                            .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
                        self.phase = CompactResponseGenerationPhase::OpeningResponse(Box::new(
                            PendingCompactResponseOpening {
                                query_schedule,
                                output,
                                next_query_offset: 0,
                                opened_leaf_digests: Vec::new(),
                                base_field_values: Vec::new(),
                                extension_field_values: Vec::new(),
                                leaf_salts: Vec::new(),
                            },
                        ));
                        Ok(CompactResponseGenerationPoll::OpenedLeafRequired {
                            response_ordinal: u32::try_from(response_index)
                                .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?,
                            leaf_ordinal: first_leaf_ordinal,
                        })
                    }
                    CompactResponseTreeRetentionPoll::VerifierMoveComplete => {
                        self.phase = CompactResponseGenerationPhase::AwaitingCheckpointCursor;
                        Ok(CompactResponseGenerationPoll::CheckpointCursorRequired)
                    }
                }
            }
            CompactResponseGenerationPhase::OpeningResponse(ref opening) => {
                if let Some(leaf_ordinal) = opening
                    .query_schedule
                    .as_slice()
                    .get(opening.next_query_offset)
                    .copied()
                {
                    return Ok(CompactResponseGenerationPoll::OpenedLeafRequired {
                        response_ordinal: opening.output.response_ordinal(),
                        leaf_ordinal,
                    });
                }
                self.finalize_opening()?;
                Ok(CompactResponseGenerationPoll::ArithmeticStepCompleted)
            }
            CompactResponseGenerationPhase::AwaitingCheckpointCursor => {
                Ok(CompactResponseGenerationPoll::CheckpointCursorRequired)
            }
            CompactResponseGenerationPhase::Terminal => Ok(CompactResponseGenerationPoll::Complete),
            CompactResponseGenerationPhase::Cancelled
            | CompactResponseGenerationPhase::Transitioning => {
                Err(CompactResponseGenerationError::WrongPhase.into())
            }
        }
    }

    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseGenerationPollError<Storage::Error>> {
        if matches!(self.phase, CompactResponseGenerationPhase::Cancelled) {
            return Ok(());
        }
        self.response_tree_retention_driver.cancel(storage)?;
        self.pending_round_salts.clear();
        self.pending_wire_inputs.clear();
        self.completed_openings.clear();
        self.latest_checkpoint_boundary = None;
        self.phase = CompactResponseGenerationPhase::Cancelled;
        Ok(())
    }

    pub(crate) fn finish(
        self,
    ) -> Result<CompactResponseGenerationOutput, CompactResponseGenerationError> {
        if !matches!(self.phase, CompactResponseGenerationPhase::Terminal)
            || self.latest_checkpoint_boundary.is_none()
            || self.pending_round_salts.iter().any(Option::is_some)
            || self.pending_wire_inputs.iter().any(Option::is_some)
        {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        self.prover_transcript.finish()?;
        let canonical_proof_bytes = self.proof_wire_assembler.finish()?;
        let external_memory_usage = self.response_tree_retention_driver.finish()?;
        Ok(CompactResponseGenerationOutput {
            canonical_proof_bytes,
            external_memory_usage,
        })
    }

    fn finalize_opening(&mut self) -> Result<(), CompactResponseGenerationError> {
        let previous_phase = core::mem::replace(
            &mut self.phase,
            CompactResponseGenerationPhase::Transitioning,
        );
        let CompactResponseGenerationPhase::OpeningResponse(opening) = previous_phase else {
            return Err(CompactResponseGenerationError::WrongPhase);
        };
        let PendingCompactResponseOpening {
            query_schedule,
            output,
            next_query_offset,
            opened_leaf_digests,
            base_field_values,
            extension_field_values,
            leaf_salts,
        } = *opening;
        if next_query_offset != query_schedule.as_slice().len() {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        let response_index = usize::try_from(output.response_ordinal())
            .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
        let merkle_geometry = self
            .response_merkle_geometries
            .get(response_index)
            .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
        let reconstructed_root = reconstruct_compact_response_root(
            merkle_geometry,
            &query_schedule,
            &opened_leaf_digests,
            output.frontier(),
        )?;
        if reconstructed_root != output.root() {
            return Err(CompactResponseGenerationError::RootMismatch);
        }
        let mut query_leaf_ordinals = Vec::new();
        query_leaf_ordinals
            .try_reserve_exact(query_schedule.as_slice().len())
            .map_err(|_| CompactResponseGenerationError::AllocationLimitExceeded)?;
        query_leaf_ordinals.extend_from_slice(query_schedule.as_slice());
        let completed_opening = CompactResponseGenerationCompletedOpening {
            response_ordinal: output.response_ordinal(),
            root: output.root(),
            query_leaf_ordinals,
            external_memory_usage: output.usage(),
        };
        let fiat_shamir_round_salt = self
            .pending_round_salts
            .get_mut(response_index)
            .and_then(Option::take)
            .ok_or(CompactResponseGenerationError::WrongPhase)?;
        let wire_input = CompactProofResponseWireInput::new(
            output.root(),
            fiat_shamir_round_salt,
            base_field_values,
            extension_field_values,
            leaf_salts,
            output.into_frontier(),
        );
        let pending_wire_input = self
            .pending_wire_inputs
            .get_mut(response_index)
            .ok_or(CompactResponseGenerationError::InvalidGeometry)?;
        if pending_wire_input.replace(wire_input).is_some() {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        self.append_contiguous_wire_inputs()?;
        self.completed_openings.push_back(completed_opening);
        self.phase = CompactResponseGenerationPhase::AdvancingVerifierMove;
        Ok(())
    }

    fn append_contiguous_wire_inputs(&mut self) -> Result<(), CompactResponseGenerationError> {
        loop {
            let next_response_index = self.proof_wire_assembler.completed_response_count();
            let Some(pending_wire_input) = self
                .pending_wire_inputs
                .get_mut(next_response_index)
                .and_then(Option::take)
            else {
                return Ok(());
            };
            self.proof_wire_assembler
                .append_response(&pending_wire_input)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::super::compact_proof_wire::{
        CompactProofResponseWireGeometry, CompactPublicInputBindings,
        CompactPublicInputWireGeometry, decode_compact_proof_wire, decode_compact_public_input,
        encode_compact_public_input,
    };
    use super::super::compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValueKind,
        CompactResponseQuerySelection, verify_decoded_compact_response_opening,
    };
    use super::super::compact_response_tree_external::CompactResponseTreeExternalMemoryExecutionError;
    use super::super::compact_transcript::derive_compact_fiat_shamir_verifier_message;
    use super::super::external_memory::tests::TestStorage;
    use super::super::external_memory::{
        ProofExternalMemory, ProofExternalMemoryExecutorError,
        ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionOperation,
        ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
        ProofExternalMemoryTransactionRequest,
    };
    use super::super::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageGeometry,
    };
    use super::*;

    struct ResponseGenerationFixture {
        proof_wire_geometry: CompactProofWireGeometry,
        response_merkle_geometries: Vec<CompactResponseMerkleGeometry>,
        canonical_public_input_bytes: Vec<u8>,
        decoded_public_input: DecodedCompactPublicInput,
        response_leaves: Vec<Vec<CompactOwnedResponseLeaf>>,
        response_leaf_salts: Vec<Vec<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>>,
        fiat_shamir_round_salts: Vec<[u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH]>,
    }

    #[derive(Debug)]
    struct ResponseGenerationRun {
        canonical_proof_bytes: Vec<u8>,
        verifier_messages: Vec<DecodedFixedUniformVerifierMessage>,
        checkpoint_boundaries: Vec<CommonProofGenerationCheckpointBoundary>,
        external_memory_usage: ProofExternalMemoryUsage,
        yielded_storage_transaction_count: u64,
    }

    enum TestStoragePath {
        Direct(TestStorage),
        RecordAndReplay {
            recorder: Box<ProofExternalMemoryTransactionRecorder>,
            backend: TestStorage,
            yielded_storage_transaction_count: u64,
        },
    }

    impl TestStoragePath {
        fn direct() -> Self {
            Self::Direct(TestStorage::default())
        }

        fn record_and_replay() -> Self {
            Self::RecordAndReplay {
                recorder: Box::new(ProofExternalMemoryTransactionRecorder::new()),
                backend: TestStorage::default(),
                yielded_storage_transaction_count: 0,
            }
        }

        fn poll(
            &mut self,
            state: &mut CompactResponseGenerationState,
        ) -> Result<CompactResponseGenerationPoll, CompactResponseGenerationError> {
            match self {
                Self::Direct(storage) => match state.poll(storage) {
                    Ok(poll) => Ok(poll),
                    Err(CompactResponseGenerationPollError::Generation(error)) => Err(error),
                    Err(error) => panic!("direct response storage failed: {error:?}"),
                },
                Self::RecordAndReplay {
                    recorder,
                    backend,
                    yielded_storage_transaction_count,
                } => match state.poll(recorder.as_mut()) {
                    Ok(poll) => Ok(poll),
                    Err(CompactResponseGenerationPollError::Generation(error)) => Err(error),
                    Err(CompactResponseGenerationPollError::ResponseTree(
                        CompactResponseTreeExternalMemoryExecutionError::Storage(
                            ProofExternalMemoryExecutorError::StorageCommit(
                                ProofExternalMemoryTransactionAdapterError::Yielded,
                            ),
                        ),
                    )) => {
                        let request = recorder
                            .take_yielded_request()
                            .expect("one response-tree transaction was yielded");
                        let read_results = execute_recorded_transaction(&request, backend);
                        let mut replay =
                            ProofExternalMemoryTransactionReplay::new(request, read_results)
                                .expect("the backend response matches the exact request");
                        let poll = state
                            .poll(&mut replay)
                            .expect("the exact response-tree transaction replays");
                        assert!(replay.transaction_is_complete());
                        *yielded_storage_transaction_count += 1;
                        Ok(poll)
                    }
                    Err(error) => panic!("recorded response storage failed: {error:?}"),
                },
            }
        }

        const fn yielded_storage_transaction_count(&self) -> u64 {
            match self {
                Self::Direct(_) => 0,
                Self::RecordAndReplay {
                    yielded_storage_transaction_count,
                    ..
                } => *yielded_storage_transaction_count,
            }
        }
    }

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("small canonical base-field value")
    }

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates([
            value,
            value + 1,
            value + 2,
            value + 3,
            value + 4,
        ])
        .expect("small canonical extension-field value")
    }

    fn response_generation_fixture() -> ResponseGenerationFixture {
        let wire_geometries = vec![
            CompactProofResponseWireGeometry::new(
                0,
                1,
                0,
                1,
                1,
                FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
                    .expect("first verifier-message geometry"),
            )
            .expect("first response wire geometry"),
            CompactProofResponseWireGeometry::new(
                1,
                1,
                0,
                1,
                1,
                FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
                    .expect("second verifier-message geometry"),
            )
            .expect("second response wire geometry"),
            CompactProofResponseWireGeometry::new(
                2,
                0,
                1,
                1,
                0,
                FixedUniformVerifierMessageGeometry::new(
                    1,
                    0,
                    0,
                    vec![FixedUniformDistinctQueryGeometry::new(2, 1)],
                )
                .expect("third verifier-message geometry"),
            )
            .expect("third response wire geometry"),
        ];
        let response_merkle_geometries = vec![
            CompactResponseMerkleGeometry::new(
                0,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    2,
                    1,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: 2,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::BaseField,
                    1,
                )],
            )
            .expect("first response Merkle geometry"),
            CompactResponseMerkleGeometry::new(
                1,
                vec![
                    CompactResponseComponentGeometry::new(
                        0,
                        1,
                        1,
                        CompactResponseQuerySelection::EveryLeaf,
                        CompactResponseLeafValueKind::BaseField,
                        1,
                    ),
                    CompactResponseComponentGeometry::new(
                        1,
                        1,
                        0,
                        CompactResponseQuerySelection::Unqueried,
                        CompactResponseLeafValueKind::Padding,
                        0,
                    ),
                ],
            )
            .expect("second response Merkle geometry"),
            CompactResponseMerkleGeometry::new(
                2,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    1,
                    1,
                    CompactResponseQuerySelection::EveryLeaf,
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                )],
            )
            .expect("third response Merkle geometry"),
        ];
        let proof_wire_geometry =
            CompactProofWireGeometry::new(wire_geometries).expect("proof wire geometry");
        let public_input_geometry =
            CompactPublicInputWireGeometry::new(1, 1).expect("public-input geometry");
        let public_input_bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x32; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x34; Hash512::BYTE_LENGTH]),
        );
        let canonical_public_input_bytes =
            encode_compact_public_input(public_input_geometry, public_input_bindings, &[base(7)])
                .expect("canonical public input encodes");
        let decoded_public_input = decode_compact_public_input(
            public_input_geometry,
            public_input_bindings,
            &canonical_public_input_bytes,
        )
        .expect("canonical public input decodes");
        ResponseGenerationFixture {
            proof_wire_geometry,
            response_merkle_geometries,
            canonical_public_input_bytes,
            decoded_public_input,
            response_leaves: vec![
                vec![
                    CompactOwnedResponseLeaf::base_field(vec![base(11)]),
                    CompactOwnedResponseLeaf::base_field(vec![base(13)]),
                ],
                vec![
                    CompactOwnedResponseLeaf::base_field(vec![base(17)]),
                    CompactOwnedResponseLeaf::padding(),
                ],
                vec![CompactOwnedResponseLeaf::extension_field(vec![extension(
                    19,
                )])],
            ],
            response_leaf_salts: vec![
                vec![
                    [0x81; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
                    [0x82; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
                ],
                vec![
                    [0x83; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
                    [0x85; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
                ],
                vec![[0x84; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]],
            ],
            fiat_shamir_round_salts: vec![
                [0x91; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
                [0x92; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
                [0x93; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            ],
        }
    }

    fn execute_recorded_transaction(
        request: &ProofExternalMemoryTransactionRequest,
        storage: &mut TestStorage,
    ) -> Vec<Zeroizing<Vec<u8>>> {
        storage
            .begin_transaction(u64::MAX, u32::MAX)
            .expect("the backend transaction begins");
        let mut read_results = Vec::new();
        for operation in request.operations() {
            match operation {
                ProofExternalMemoryTransactionOperation::Create {
                    object,
                    protection,
                    exact_byte_length,
                } => storage
                    .create_object(*object, *protection, *exact_byte_length)
                    .expect("the backend creates the response tree"),
                ProofExternalMemoryTransactionOperation::Append {
                    object,
                    expected_offset,
                    bytes,
                } => storage
                    .append_object_bytes(*object, *expected_offset, bytes)
                    .expect("the backend appends response-tree bytes"),
                ProofExternalMemoryTransactionOperation::Seal { object } => storage
                    .seal_object(*object)
                    .expect("the backend seals the response tree"),
                ProofExternalMemoryTransactionOperation::Read {
                    object,
                    offset,
                    byte_length,
                } => {
                    let mut result = Zeroizing::new(vec![
                        0_u8;
                        usize::try_from(*byte_length).expect(
                            "the bounded read length fits usize"
                        )
                    ]);
                    storage
                        .read_object_bytes(*object, *offset, &mut result)
                        .expect("the backend reads response-tree bytes");
                    read_results.push(result);
                }
                ProofExternalMemoryTransactionOperation::Delete { object } => storage
                    .delete_object(*object)
                    .expect("the backend deletes the response tree"),
            }
        }
        storage
            .commit_transaction()
            .expect("the backend transaction commits");
        read_results
    }

    fn run_response_generation(
        mut storage_path: TestStoragePath,
        authenticated_replay_boundaries: Option<&[CommonProofGenerationCheckpointBoundary]>,
        corrupt_first_delayed_opening: bool,
    ) -> Result<ResponseGenerationRun, CompactResponseGenerationError> {
        let fixture = response_generation_fixture();
        let mut state = CompactResponseGenerationState::new(
            &fixture.proof_wire_geometry,
            &fixture.response_merkle_geometries,
            &fixture.decoded_public_input,
            &fixture.canonical_public_input_bytes,
        )?;
        let mut checkpoint_boundaries = Vec::new();
        let mut corrupted_opening_was_supplied = false;
        assert!(!state.canonical_proof_prefix_bytes().is_empty());
        loop {
            match storage_path.poll(&mut state)? {
                CompactResponseGenerationPoll::ResponseRequired { response_ordinal } => {
                    let response_index = usize::try_from(response_ordinal)
                        .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                    state.begin_response(fixture.fiat_shamir_round_salts[response_index])?;
                }
                CompactResponseGenerationPoll::ResponseLeafRequired {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    let response_index = usize::try_from(response_ordinal)
                        .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                    let leaf_index = usize::try_from(leaf_ordinal)
                        .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                    state.supply_next_response_leaf(
                        &fixture.response_leaves[response_index][leaf_index],
                        &fixture.response_leaf_salts[response_index][leaf_index],
                    )?;
                }
                CompactResponseGenerationPoll::OpenedLeafRequired {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    let response_index = usize::try_from(response_ordinal)
                        .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                    let leaf_index = usize::try_from(leaf_ordinal)
                        .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?;
                    let corrupt_this_opening = corrupt_first_delayed_opening
                        && response_ordinal == 0
                        && !corrupted_opening_was_supplied;
                    let leaf = if corrupt_this_opening {
                        corrupted_opening_was_supplied = true;
                        CompactOwnedResponseLeaf::base_field(vec![base(99)])
                    } else {
                        fixture.response_leaves[response_index][leaf_index].clone()
                    };
                    state.supply_next_opened_leaf(
                        &leaf,
                        fixture.response_leaf_salts[response_index][leaf_index],
                    )?;
                }
                CompactResponseGenerationPoll::CheckpointCursorRequired => {
                    let response_index = state
                        .verifier_messages()
                        .len()
                        .checked_sub(1)
                        .ok_or(CompactResponseGenerationError::WrongPhase)?;
                    let cursor_bytes = [
                        0xc1,
                        u8::try_from(response_index)
                            .map_err(|_| CompactResponseGenerationError::InvalidGeometry)?,
                    ];
                    state.supply_checkpoint_private_randomness_cursor(&cursor_bytes)?;
                    let boundary = state
                        .checkpoint_boundary()
                        .cloned()
                        .ok_or(CompactResponseGenerationError::WrongPhase)?;
                    if let Some(authenticated_boundaries) = authenticated_replay_boundaries {
                        let authenticated_boundary =
                            authenticated_boundaries
                                .get(response_index)
                                .ok_or(CompactResponseGenerationError::WrongPhase)?;
                        assert_eq!(&boundary, authenticated_boundary);
                        state.restore_authenticated_checkpoint_transcript_cursor(
                            authenticated_boundary.canonical_transcript_cursor_bytes(),
                            authenticated_boundary
                                .canonical_transcript_cursor_digest()
                                .ok_or(CompactResponseGenerationError::WrongPhase)?,
                        )?;
                    }
                    checkpoint_boundaries.push(boundary);
                }
                CompactResponseGenerationPoll::ArithmeticStepCompleted
                | CompactResponseGenerationPoll::StorageTransactionCompleted => {}
                CompactResponseGenerationPoll::Complete => break,
            }
        }
        let verifier_messages = state.verifier_messages().to_vec();
        let yielded_storage_transaction_count = storage_path.yielded_storage_transaction_count();
        let output = state.finish()?;
        assert!(!output.canonical_proof_bytes().is_empty());
        let external_memory_usage = output.external_memory_usage();
        Ok(ResponseGenerationRun {
            canonical_proof_bytes: output.into_canonical_proof_bytes(),
            verifier_messages,
            checkpoint_boundaries,
            external_memory_usage,
            yielded_storage_transaction_count,
        })
    }

    fn independently_verify_run(run: &ResponseGenerationRun) {
        let fixture = response_generation_fixture();
        let decoded_proof =
            decode_compact_proof_wire(&fixture.proof_wire_geometry, &run.canonical_proof_bytes)
                .expect("the independently owned proof decoder accepts canonical bytes");
        let mut independently_derived_messages = Vec::new();
        for response_index in 0..fixture.proof_wire_geometry.responses().len() {
            independently_derived_messages.push(
                derive_compact_fiat_shamir_verifier_message(
                    &fixture.proof_wire_geometry,
                    &decoded_proof,
                    &run.canonical_proof_bytes,
                    &fixture.decoded_public_input,
                    &fixture.canonical_public_input_bytes,
                    u32::try_from(response_index).expect("small response ordinal"),
                )
                .expect("the independent transcript derives the verifier message"),
            );
        }
        assert_eq!(independently_derived_messages, run.verifier_messages);
        for response_index in 0..fixture.proof_wire_geometry.responses().len() {
            let query_schedule = CompactResponseQuerySchedule::derive(
                &fixture.response_merkle_geometries[response_index],
                fixture.proof_wire_geometry.responses(),
                &independently_derived_messages,
            )
            .expect("the independent verifier derives the opening schedule");
            verify_decoded_compact_response_opening(
                &fixture.response_merkle_geometries[response_index],
                &fixture.proof_wire_geometry.responses()[response_index],
                &decoded_proof.responses()[response_index],
                &run.canonical_proof_bytes,
                &query_schedule,
            )
            .expect("the independent verifier accepts the reconstructed response opening");
        }
    }

    #[test]
    fn response_state_replays_storage_and_cold_prefix_without_retaining_delayed_values() {
        let recorded = run_response_generation(TestStoragePath::record_and_replay(), None, false)
            .expect("recorded response generation completes");
        assert_eq!(recorded.checkpoint_boundaries.len(), 3);
        assert_eq!(recorded.yielded_storage_transaction_count, 15);
        assert_eq!(
            recorded.external_memory_usage.total_written_byte_length(),
            448
        );
        assert_eq!(recorded.external_memory_usage.total_read_byte_length(), 448);
        assert_eq!(
            recorded.external_memory_usage.peak_stored_byte_length(),
            384
        );
        assert_eq!(recorded.external_memory_usage.transaction_count(), 15);
        assert_eq!(recorded.external_memory_usage.deleted_object_count(), 3);
        independently_verify_run(&recorded);

        let cold_replay = run_response_generation(
            TestStoragePath::direct(),
            Some(&recorded.checkpoint_boundaries),
            false,
        )
        .expect("cold deterministic prefix replay completes");
        assert_eq!(
            cold_replay.canonical_proof_bytes,
            recorded.canonical_proof_bytes
        );
        assert_eq!(cold_replay.verifier_messages, recorded.verifier_messages);
        assert_eq!(
            cold_replay.checkpoint_boundaries,
            recorded.checkpoint_boundaries
        );
        assert_eq!(
            cold_replay.external_memory_usage,
            recorded.external_memory_usage
        );
        independently_verify_run(&cold_replay);
    }

    #[test]
    fn response_state_refuses_replayed_leaf_that_does_not_match_retained_root() {
        assert_eq!(
            run_response_generation(TestStoragePath::direct(), None, true)
                .expect_err("a changed delayed opening must fail closed"),
            CompactResponseGenerationError::RootMismatch
        );
    }

    #[test]
    fn response_state_cancels_an_incomplete_tree_and_remains_terminal() {
        let fixture = response_generation_fixture();
        let mut state = CompactResponseGenerationState::new(
            &fixture.proof_wire_geometry,
            &fixture.response_merkle_geometries,
            &fixture.decoded_public_input,
            &fixture.canonical_public_input_bytes,
        )
        .expect("response state initializes");
        state
            .begin_response(fixture.fiat_shamir_round_salts[0])
            .expect("the first response begins");
        let mut storage = TestStorage::default();
        assert_eq!(
            state.poll(&mut storage),
            Ok(CompactResponseGenerationPoll::StorageTransactionCompleted)
        );
        assert_eq!(storage.committed_object_count(), 1);
        state
            .cancel(&mut storage)
            .expect("cancellation deletes the incomplete response tree");
        assert_eq!(storage.committed_object_count(), 0);
        state
            .cancel(&mut storage)
            .expect("repeated cancellation is idempotent");
        assert!(matches!(
            state.poll(&mut storage),
            Err(CompactResponseGenerationPollError::Generation(
                CompactResponseGenerationError::WrongPhase
            ))
        ));
    }
}
