//! Browser-compatible prover primitives for construction-driven row-code proofs.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::hashing::StreamingHash512;

use super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
#[cfg(test)]
use super::external_memory::ProofExternalMemoryObject;
use super::external_polynomial::{ExternalPolynomialVector, external_value_byte_length};
use super::field::{ProofBaseFieldElement, ProofChallengeExtensionElement, ProofFieldError};
use super::merkle::{ProofMerkleError, ProofTreeRole};
use super::polynomial::{ProofEvaluationDomain, ProofPolynomialError, evaluate_extension_at};
use super::relation_plan::{
    CheckedRelationApplicationChallenges, ProofPrivacyMode, RelationApplicationChallengeAssignment,
    RelationColumnDescriptor, RelationColumnOrigin, RelationColumnValueType,
    RelationConstraintColumnQuery, RelationIntegerLiftCoefficient,
    RelationIntegerLiftComponentDescriptor, RelationIntegerLiftConvolutionKind,
    RelationIntegerLiftConvolutionProductDescriptor, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor,
    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor, RelationMaskDescriptor,
    RelationMaskKind, RelationMaskTargetClass, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, RelationTreeDescriptor, SuiteModulusReference,
};
use super::transcript::CommonProofChallenge;

const HASH_BYTE_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofProverError {
    CanonicalEncoding,
    InvalidInput,
    InvalidColumn,
    InvalidMask,
    InvalidQuotient,
    InvalidOpening,
    InvalidTree,
    CountOverflow,
    AllocationLimitExceeded,
    ResidentMemoryLimitExceeded,
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
    Merkle(ProofMerkleError),
    Relation(RelationPlanError),
}

impl From<ProofFieldError> for CommonProofProverError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for CommonProofProverError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<ProofMerkleError> for CommonProofProverError {
    fn from(error: ProofMerkleError) -> Self {
        Self::Merkle(error)
    }
}

impl From<RelationPlanError> for CommonProofProverError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CommonProofGenerationStage {
    PreparingInputs = 1,
    MaterializingBaseTrees = 2,
    DerivingApplicationColumns = 3,
    MaterializingAuxiliaryTrees = 4,
    ConstructingQuotient = 5,
    MaterializingQuotientTrees = 6,
    DerivingOutOfDomainOpenings = 7,
    MaterializingOpeningMask = 8,
    ReducingCommittedOracles = 9,
    Finalizing = 12,
    Cancelled = 14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationPoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    AuthenticatedTranscriptPrefixRequired,
    OutputFragmentAccepted,
    Complete,
}

/// One replayable commitment-round boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofGenerationCheckpointBoundary {
    safe_boundary_ordinal: u32,
    position: [u8; 16],
    committed_state_digest: [u8; HASH_BYTE_LENGTH],
    canonical_transcript_cursor_bytes: Vec<u8>,
    canonical_transcript_cursor_digest: Option<[u8; HASH_BYTE_LENGTH]>,
}

impl CommonProofGenerationCheckpointBoundary {
    pub(crate) const fn new(
        safe_boundary_ordinal: u32,
        position: [u8; 16],
        committed_state_digest: [u8; HASH_BYTE_LENGTH],
    ) -> Self {
        Self {
            safe_boundary_ordinal,
            position,
            committed_state_digest,
            canonical_transcript_cursor_bytes: Vec::new(),
            canonical_transcript_cursor_digest: None,
        }
    }

    pub(crate) fn with_canonical_transcript_cursor(
        mut self,
        canonical_transcript_cursor_bytes: Vec<u8>,
        canonical_transcript_cursor_digest: [u8; HASH_BYTE_LENGTH],
    ) -> Self {
        self.canonical_transcript_cursor_bytes = canonical_transcript_cursor_bytes;
        self.canonical_transcript_cursor_digest = Some(canonical_transcript_cursor_digest);
        self
    }

    pub(crate) const fn safe_boundary_ordinal(&self) -> u32 {
        self.safe_boundary_ordinal
    }

    pub(crate) const fn position(&self) -> [u8; 16] {
        self.position
    }

    pub(crate) const fn committed_state_digest(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.committed_state_digest
    }

    pub(crate) fn canonical_transcript_cursor_bytes(&self) -> &[u8] {
        &self.canonical_transcript_cursor_bytes
    }

    pub(crate) const fn canonical_transcript_cursor_digest(
        &self,
    ) -> Option<[u8; HASH_BYTE_LENGTH]> {
        self.canonical_transcript_cursor_digest
    }
}

mod encoding;
mod generation_storage;
mod private_coins;
mod quotient;
mod relation_columns;

pub(crate) use encoding::{CommonProofByteSink, canonical_proof_object_header_bytes};
#[cfg(test)]
pub(crate) use generation_storage::{
    AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
};
pub(crate) use generation_storage::{
    CommonProofExternalMemoryRequirement, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofReplayPolynomialEncoding, CommonProofReplayPolynomialPlan,
    CommonProofReplayPolynomialRangeDestination, CommonProofReplayPolynomialRangeReader,
    CommonProofReplayPolynomialReader, CommonProofReplayPolynomialRef,
    CommonProofReplayPolynomialWriter, MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    validate_generation_relation_trees,
};
pub(crate) use private_coins::{
    COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC, CheckpointableCommonProofPrivateCoinSource,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinCoordinateCapacity,
    CommonProofPrivateCoinSource, PrivateRandomnessCommonProofCoinError,
    PrivateRandomnessCommonProofCoinSource,
};
#[cfg(test)]
pub(crate) use private_coins::{
    CommonProofPrivateCoinSamplingCatalog, CommonProofPrivateCoinSamplingOperation,
    RecordingCommonProofPrivateCoinSource,
    common_proof_checkpoint_cursor_manifest_requirement_for_variant,
    common_proof_private_coin_coordinate_derivation_context_hash,
    encode_common_proof_checkpoint_cursor_manifest,
};
pub(crate) use quotient::{
    CommonProofConstraintStreamQuotientBuilder, CommonProofQuotientComponentCursor,
    CommonProofQuotientConstraintTransformKey, CommonProofQuotientEvaluationProgress,
    CommonProofQuotientEvaluationReadRequest, common_proof_quotient_constraint_catalog,
    common_proof_quotient_evaluation_read_accounting,
    common_proof_quotient_materialization_liveness,
};
#[cfg(test)]
pub(crate) use quotient::{construct_composed_quotient_polynomial, decompose_composed_quotient};
#[cfg(test)]
pub(crate) use relation_columns::construct_pre_challenge_relation_columns;
pub(crate) use relation_columns::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofAuxiliaryColumnReconstructionCatalog,
    CommonProofAuxiliaryColumnReconstructionCursor, CommonProofAuxiliaryColumnSynthesisCursor,
    CommonProofBoundTreeLeafSaltRequest, CommonProofPreChallengeSourceCursor,
    CommonProofPreChallengeSourcePoll, CommonProofPrivateCoinError, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    CommonProofSourceReplayIdentityCatalog, ProvidedCommonProofSourcePolynomial, apply_trace_mask,
    authenticated_pre_challenge_source_coefficient_position_counts, base_trace_rows,
    common_proof_auxiliary_materialization_liveness, construct_opening_batch_mask,
    construct_reversed_relation_column, ordered_integer_lift_auxiliary_column_ordinals,
    persisted_pre_challenge_column_coefficient_position_counts, relation_reversed_column_bindings,
    replay_relation_private_mask_polynomial, requested_pre_challenge_source_column_ordinals,
    sample_private_extension_polynomial, validate_source_column,
};

fn add_shifted_extension_polynomial(
    target: &mut Vec<ProofChallengeExtensionElement>,
    addend: &[ProofChallengeExtensionElement],
    shift: usize,
) -> Result<(), CommonProofProverError> {
    let required = shift
        .checked_add(addend.len())
        .ok_or(CommonProofProverError::CountOverflow)?;
    if target.len() < required {
        target.resize(required, ProofChallengeExtensionElement::ZERO);
    }
    for (ordinal, coefficient) in addend.iter().copied().enumerate() {
        target[shift + ordinal] = target[shift + ordinal].add(coefficient);
    }
    Ok(())
}

fn subtract_extension_polynomial(
    target: &mut Vec<ProofChallengeExtensionElement>,
    subtrahend: &[ProofChallengeExtensionElement],
) -> Result<(), CommonProofProverError> {
    if target.len() < subtrahend.len() {
        target.resize(subtrahend.len(), ProofChallengeExtensionElement::ZERO);
    }
    for (destination, coefficient) in target.iter_mut().zip(subtrahend) {
        *destination = destination.subtract(*coefficient);
    }
    Ok(())
}

fn trim_base_polynomial(coefficients: &mut Vec<ProofBaseFieldElement>) {
    while coefficients.len() > 1 && coefficients.last() == Some(&ProofBaseFieldElement::ZERO) {
        coefficients.pop();
    }
}

fn trim_extension_polynomial(coefficients: &mut Vec<ProofChallengeExtensionElement>) {
    while coefficients.len() > 1
        && coefficients.last() == Some(&ProofChallengeExtensionElement::ZERO)
    {
        coefficients.pop();
    }
}
