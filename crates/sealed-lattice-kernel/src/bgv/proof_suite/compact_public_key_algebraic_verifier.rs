//! Positive algebraic verification for the selected compact public-key proof.
//!
//! This layer consumes only the owning transport terminal. It resolves prover
//! and verifier values through semantic contract roles, derives the structured
//! public matrix contribution without an assignment, and verifies the CFW
//! equations before handing their target and public covectors to WHIR.

use p3_field::PrimeCharacteristicRing;

use crate::foundation::{Hash512, RefusalReason};

use super::compact_cfw::{
    COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwError,
    CompactCfwMaskedCrossEpochClaims, CompactCfwPublicMainCovectorCombination,
    CompactCfwPublicMainCovectorContinuation, CompactCfwPublicMainCovectors, CompactCfwTranscript,
    CompactChallengeField, compact_cfw_zero_evader_weights, compact_challenge_from_production,
    verify_compact_cfw_transcript_with_weighted_public_contribution,
};
use super::compact_cfw_geometry::CompactCfwGeometry;
use super::compact_masking_public_covector::{
    CompactFactorOnePublicCovectorAuthority, CompactFactorOnePublicCovectorError,
    CompactFactorOnePublicTransposeSource,
};
use super::compact_proof_wire::CompactPublicInputBindings;
use super::compact_public_key_verifier::{
    CompactPublicKeyTransportError, VerifiedCompactPublicKeyTransport,
};
use super::compact_reed_solomon_domain::CompactReedSolomonDomainError;
use super::compact_whir::{CompactWhirError, fold_compact_whir_query_major_source_openings};
use super::compact_whir_algebraic_verifier::{
    CompactWhirAlgebraicRelation, CompactWhirAlgebraicVerifierError, CompactWhirBlindedMaskReveal,
    CompactWhirCodeSwitchTranscript, CompactWhirSourceSpotCheck, CompactWhirSumcheckTranscript,
    verify_compact_whir_mask_spot_checks, verify_compact_whir_source_spot_checks,
};
use super::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};
use super::prover::CommonProofProverError;
use super::relation_plan::{
    CompactStructuredWitnessCovectorAccumulator, CompactStructuredWitnessCovectorAccumulatorPoll,
};

const MAIN_WHIR_EPOCH: u8 = 2;
const INITIAL_WHIR_BATCH: u8 = 0;
const PRE_CHALLENGE_WHIR_EPOCH: u8 = 1;
const COMPACT_WHIR_BATCH_COUNT: usize = 4;
const COMPACT_WHIR_CODE_SWITCH_COUNT: usize = 3;
pub(crate) const COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL: u64 =
    65_536;
pub(crate) const COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT: u64 = 19_038_593;
pub(crate) const COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT: u32 =
    (COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT
        / COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL) as u32;
const COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_MAGIC: [u8; 8] = *b"SLCAVC01";
pub(crate) const COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_BYTE_LENGTH: usize =
    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_MAGIC.len()
        + 6 * Hash512::BYTE_LENGTH
        + size_of::<u64>();

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyAlgebraicVerificationError {
    Transport(CompactPublicKeyTransportError),
    Cfw(CompactCfwError),
    PublicCovector(CompactFactorOnePublicCovectorError),
    StructuredTranspose(CommonProofProverError),
    WhirEncoding(CompactWhirError),
    Whir {
        epoch: u8,
        stage: CompactPublicKeyWhirVerificationStage,
        error: CompactWhirAlgebraicVerifierError,
    },
    InvalidTranscript,
    ArithmeticOverflow,
    CheckpointUnavailable,
    MalformedCheckpoint,
    WrongCheckpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyWhirVerificationStage {
    InitialRelation,
    Sumcheck { batch_ordinal: u8 },
    CodeSwitch { round_ordinal: u8 },
    BaseTarget,
    BaseSource,
    BaseMask { group_ordinal: u8 },
}

impl From<CompactPublicKeyTransportError> for CompactPublicKeyAlgebraicVerificationError {
    fn from(error: CompactPublicKeyTransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<CompactCfwError> for CompactPublicKeyAlgebraicVerificationError {
    fn from(error: CompactCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl From<CompactFactorOnePublicCovectorError> for CompactPublicKeyAlgebraicVerificationError {
    fn from(error: CompactFactorOnePublicCovectorError) -> Self {
        Self::PublicCovector(error)
    }
}

impl From<CommonProofProverError> for CompactPublicKeyAlgebraicVerificationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::StructuredTranspose(error)
    }
}

impl From<CompactWhirError> for CompactPublicKeyAlgebraicVerificationError {
    fn from(error: CompactWhirError) -> Self {
        Self::WhirEncoding(error)
    }
}

impl CompactPublicKeyAlgebraicVerificationError {
    pub(crate) const fn refusal_reason(self) -> RefusalReason {
        match self {
            Self::Transport(error) => error.refusal_reason(),
            Self::Cfw(error) => compact_cfw_refusal_reason(error),
            Self::PublicCovector(error) => compact_public_covector_refusal_reason(error),
            Self::StructuredTranspose(error) => compact_transpose_refusal_reason(error),
            Self::WhirEncoding(error) => compact_whir_encoding_refusal_reason(error),
            Self::Whir { error, .. } => compact_whir_algebraic_refusal_reason(error),
            Self::InvalidTranscript => RefusalReason::InvalidProof,
            Self::ArithmeticOverflow => RefusalReason::OutsideSupportedProfile,
            Self::CheckpointUnavailable => RefusalReason::ConsumedState,
            Self::MalformedCheckpoint => RefusalReason::MalformedEncoding,
            Self::WrongCheckpoint => RefusalReason::WrongContext,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactPublicKeyAlgebraicVerificationCheckpoint {
    public_input_bindings: CompactPublicInputBindings,
    canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    completed_work_unit_count: u64,
}

impl CompactPublicKeyAlgebraicVerificationCheckpoint {
    fn encode(self) -> [u8; COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_BYTE_LENGTH] {
        let mut bytes = [0_u8; COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_BYTE_LENGTH];
        let mut cursor = 0_usize;
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_MAGIC,
        );
        for binding in self.public_input_bindings.ordered_hashes() {
            write_checkpoint_bytes(&mut bytes, &mut cursor, binding.as_bytes());
        }
        write_checkpoint_bytes(&mut bytes, &mut cursor, &self.canonical_proof_binding);
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &self.canonical_public_input_binding,
        );
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &self.completed_work_unit_count.to_le_bytes(),
        );
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, CompactPublicKeyAlgebraicVerificationError> {
        if bytes.len() != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_BYTE_LENGTH {
            return Err(CompactPublicKeyAlgebraicVerificationError::MalformedCheckpoint);
        }
        let mut cursor = 0_usize;
        let magic = read_checkpoint_array::<8>(bytes, &mut cursor)?;
        if magic != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_MAGIC {
            return Err(CompactPublicKeyAlgebraicVerificationError::MalformedCheckpoint);
        }
        let public_input_bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
        );
        let canonical_proof_binding = read_checkpoint_array(bytes, &mut cursor)?;
        let canonical_public_input_binding = read_checkpoint_array(bytes, &mut cursor)?;
        let completed_work_unit_count =
            u64::from_le_bytes(read_checkpoint_array(bytes, &mut cursor)?);
        if cursor != bytes.len()
            || completed_work_unit_count == 0
            || !completed_work_unit_count.is_multiple_of(
                COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL,
            )
            || completed_work_unit_count
                > maximum_compact_public_key_algebraic_verification_checkpoint_work_unit_count()
        {
            return Err(CompactPublicKeyAlgebraicVerificationError::MalformedCheckpoint);
        }
        Ok(Self {
            public_input_bindings,
            canonical_proof_binding,
            canonical_public_input_binding,
            completed_work_unit_count,
        })
    }
}

fn write_checkpoint_bytes<const BYTE_LENGTH: usize>(
    output: &mut [u8],
    cursor: &mut usize,
    bytes: &[u8; BYTE_LENGTH],
) {
    let end = cursor
        .checked_add(BYTE_LENGTH)
        .expect("the fixed checkpoint geometry fits usize");
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn read_checkpoint_array<const BYTE_LENGTH: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; BYTE_LENGTH], CompactPublicKeyAlgebraicVerificationError> {
    let end = cursor
        .checked_add(BYTE_LENGTH)
        .ok_or(CompactPublicKeyAlgebraicVerificationError::MalformedCheckpoint)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(CompactPublicKeyAlgebraicVerificationError::MalformedCheckpoint)?
        .try_into()
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::MalformedCheckpoint)?;
    *cursor = end;
    Ok(value)
}

const fn compact_cfw_refusal_reason(error: CompactCfwError) -> RefusalReason {
    match error {
        CompactCfwError::CountOverflow | CompactCfwError::AllocationLimitExceeded => {
            RefusalReason::OutsideSupportedProfile
        }
        CompactCfwError::InvalidGeometry | CompactCfwError::IncompatibleChallengeField => {
            RefusalReason::UnsupportedVersionOrSuite
        }
        CompactCfwError::InvalidMaskMaterial
        | CompactCfwError::InvalidMatrixSource
        | CompactCfwError::WrongProverPhase
        | CompactCfwError::SumcheckConsistency { .. }
        | CompactCfwError::FinalConsistency
        | CompactCfwError::InvalidFinalChallenge
        | CompactCfwError::InvalidClaimInput => RefusalReason::InvalidProof,
    }
}

const fn compact_transpose_refusal_reason(error: CommonProofProverError) -> RefusalReason {
    match error {
        CommonProofProverError::CountOverflow
        | CommonProofProverError::AllocationLimitExceeded
        | CommonProofProverError::ResidentMemoryLimitExceeded => {
            RefusalReason::OutsideSupportedProfile
        }
        CommonProofProverError::CanonicalEncoding
        | CommonProofProverError::InvalidInput
        | CommonProofProverError::InvalidColumn
        | CommonProofProverError::InvalidMask
        | CommonProofProverError::InvalidQuotient
        | CommonProofProverError::InvalidOpening
        | CommonProofProverError::InvalidTree
        | CommonProofProverError::Field(_)
        | CommonProofProverError::Polynomial(_)
        | CommonProofProverError::Merkle(_)
        | CommonProofProverError::Relation(_) => RefusalReason::InvalidProof,
    }
}

const fn compact_public_covector_refusal_reason(
    error: CompactFactorOnePublicCovectorError,
) -> RefusalReason {
    match error {
        CompactFactorOnePublicCovectorError::AllocationLimitExceeded
        | CompactFactorOnePublicCovectorError::ArithmeticOverflow => {
            RefusalReason::OutsideSupportedProfile
        }
        CompactFactorOnePublicCovectorError::InvalidContract => {
            RefusalReason::UnsupportedVersionOrSuite
        }
        CompactFactorOnePublicCovectorError::InvalidPublicInput
        | CompactFactorOnePublicCovectorError::InvalidVerifierPrefix
        | CompactFactorOnePublicCovectorError::InvalidCovector => RefusalReason::InvalidProof,
        CompactFactorOnePublicCovectorError::Cfw(error) => compact_cfw_refusal_reason(error),
        CompactFactorOnePublicCovectorError::Transpose(error) => {
            compact_transpose_refusal_reason(error)
        }
        CompactFactorOnePublicCovectorError::ReedSolomonDomain(error) => match error {
            CompactReedSolomonDomainError::ArithmeticOverflow => {
                RefusalReason::OutsideSupportedProfile
            }
            CompactReedSolomonDomainError::InvalidGeometry => {
                RefusalReason::UnsupportedVersionOrSuite
            }
        },
    }
}

const fn compact_whir_encoding_refusal_reason(error: CompactWhirError) -> RefusalReason {
    match error {
        CompactWhirError::CountOverflow | CompactWhirError::AllocationLimitExceeded => {
            RefusalReason::OutsideSupportedProfile
        }
        CompactWhirError::InvalidConfiguration
        | CompactWhirError::FoldingScheduleMismatch
        | CompactWhirError::RoundRateMismatch
        | CompactWhirError::FinalVariableCountMismatch
        | CompactWhirError::InvalidProofOfWorkGeometry => RefusalReason::UnsupportedVersionOrSuite,
        CompactWhirError::InvalidMessage
        | CompactWhirError::InvalidEncodedMatrix
        | CompactWhirError::InvalidRelation
        | CompactWhirError::InvalidWorkBudget
        | CompactWhirError::WrongProverPhase => RefusalReason::InvalidProof,
    }
}

const fn compact_whir_algebraic_refusal_reason(
    error: CompactWhirAlgebraicVerifierError,
) -> RefusalReason {
    match error {
        CompactWhirAlgebraicVerifierError::ArithmeticOverflow => {
            RefusalReason::OutsideSupportedProfile
        }
        CompactWhirAlgebraicVerifierError::InvalidContract => {
            RefusalReason::UnsupportedVersionOrSuite
        }
        CompactWhirAlgebraicVerifierError::InvalidRelation
        | CompactWhirAlgebraicVerifierError::InvalidSumcheck
        | CompactWhirAlgebraicVerifierError::InvalidCodeSwitch
        | CompactWhirAlgebraicVerifierError::InvalidBaseCase => RefusalReason::InvalidProof,
    }
}

fn compact_whir_verification_error(
    epoch: u8,
    stage: CompactPublicKeyWhirVerificationStage,
    error: CompactWhirAlgebraicVerifierError,
) -> CompactPublicKeyAlgebraicVerificationError {
    CompactPublicKeyAlgebraicVerificationError::Whir {
        epoch,
        stage,
        error,
    }
}

struct ParsedCompactCfwTranscript {
    geometry: CompactCfwGeometry,
    constraint_combining_challenge: CompactChallengeField,
    equality_point: Vec<CompactChallengeField>,
    sumcheck_point: Vec<CompactChallengeField>,
    joint_constraint_challenge: CompactChallengeField,
    opening_batching_challenge: CompactChallengeField,
    cross_epoch_claims: CompactCfwMaskedCrossEpochClaims,
    transcript: CompactCfwTranscript,
    first_main_fold_challenges: Vec<CompactChallengeField>,
}

pub(crate) struct CompactPublicKeyCfwVerification {
    parsed: Option<ParsedCompactCfwTranscript>,
    accumulator: CompactStructuredWitnessCovectorAccumulator<CompactFactorOnePublicTransposeSource>,
    public_covector_continuation: Option<CompactCfwPublicMainCovectorContinuation>,
    complete_handoff: Option<Box<AlgebraicallyVerifiedCompactCfwHandoff>>,
}

pub(crate) enum CompactPublicKeyCfwVerificationPoll {
    WorkCompleted { completed_work_unit_count: u64 },
    Complete(Box<AlgebraicallyVerifiedCompactCfwHandoff>),
}

pub(crate) struct AlgebraicallyVerifiedCompactCfwHandoff {
    main_relation_target: CompactChallengeField,
    public_covectors_after_first_fold: CompactCfwPublicMainCovectors,
    first_main_fold_challenges: Vec<CompactChallengeField>,
    cross_epoch_point: Vec<CompactChallengeField>,
    masked_pre_challenge_target: CompactChallengeField,
}

impl AlgebraicallyVerifiedCompactCfwHandoff {
    pub(crate) fn into_parts(
        self,
    ) -> (
        CompactChallengeField,
        CompactCfwPublicMainCovectors,
        Vec<CompactChallengeField>,
        Vec<CompactChallengeField>,
        CompactChallengeField,
    ) {
        (
            self.main_relation_target,
            self.public_covectors_after_first_fold,
            self.first_main_fold_challenges,
            self.cross_epoch_point,
            self.masked_pre_challenge_target,
        )
    }
}

impl CompactPublicKeyCfwVerification {
    pub(crate) fn begin(
        transport: &VerifiedCompactPublicKeyTransport,
    ) -> Result<Self, CompactPublicKeyAlgebraicVerificationError> {
        let parsed = ParsedCompactCfwTranscript::parse(transport)?;
        let inputs = transport.verifier_inputs();
        let copied_main_source_element_count =
            usize::try_from(inputs.cfw_configuration.cross_epoch().copied_element_count)
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let public_combination =
            CompactCfwPublicMainCovectorCombination::from_public_challenges_after_first_whir_fold(
                parsed.geometry,
                parsed.cross_epoch_claims.point(),
                copied_main_source_element_count,
                &parsed.sumcheck_point,
                parsed.joint_constraint_challenge,
                parsed.opening_batching_challenge,
                &parsed.first_main_fold_challenges,
            )?;
        let (public_covector_continuation, destination) = public_combination.into_parts();
        let lookup_challenge = required_verifier_extension_role(transport, 1, 0, 0, 0, 1)?[0];
        let public_authority = CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
            transport.public_input_owner(),
        )?;
        let transpose_source = public_authority.transpose_source(lookup_challenge)?;
        let accumulator = CompactStructuredWitnessCovectorAccumulator::
            from_projected_public_relation_with_public_contributions(
                transpose_source,
                inputs.relation,
                public_covector_continuation.row_point(),
                public_covector_continuation.matrix_role_weights(),
                destination,
                &parsed.first_main_fold_challenges,
            )?;
        Ok(Self {
            parsed: Some(parsed),
            accumulator,
            public_covector_continuation: Some(public_covector_continuation),
            complete_handoff: None,
        })
    }

    pub(crate) fn advance(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyCfwVerificationPoll, CompactPublicKeyAlgebraicVerificationError>
    {
        if maximum_work_unit_count == 0 {
            return Err(CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint);
        }
        let mut total_completed_work_unit_count = 0_u64;
        loop {
            if let Some(handoff) = self.complete_handoff.take() {
                return Ok(CompactPublicKeyCfwVerificationPoll::Complete(handoff));
            }
            let remaining_work_unit_count = maximum_work_unit_count
                .checked_sub(total_completed_work_unit_count)
                .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
            if remaining_work_unit_count == 0 {
                return Ok(CompactPublicKeyCfwVerificationPoll::WorkCompleted {
                    completed_work_unit_count: total_completed_work_unit_count,
                });
            }
            match self.accumulator.advance(remaining_work_unit_count)? {
                CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                    completed_work_unit_count,
                    ..
                } => {
                    if completed_work_unit_count == 0
                        || completed_work_unit_count > remaining_work_unit_count
                    {
                        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
                    }
                    total_completed_work_unit_count = total_completed_work_unit_count
                        .checked_add(completed_work_unit_count)
                        .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
                }
                CompactStructuredWitnessCovectorAccumulatorPoll::Complete(source_covector) => {
                    let public_contributions = self.accumulator.completed_public_contributions()?;
                    let parsed = self
                        .parsed
                        .take()
                        .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;
                    let public_weights =
                        compact_cfw_zero_evader_weights(parsed.joint_constraint_challenge);
                    let weighted_public_contribution = public_contributions
                        .into_iter()
                        .zip(public_weights)
                        .map(|(contribution, weight)| contribution * weight)
                        .sum::<CompactChallengeField>();
                    let claim_batch =
                        verify_compact_cfw_transcript_with_weighted_public_contribution(
                            parsed.geometry,
                            &parsed.transcript,
                            parsed.constraint_combining_challenge,
                            &parsed.equality_point,
                            &parsed.sumcheck_point,
                            parsed.joint_constraint_challenge,
                            weighted_public_contribution,
                        )?;
                    let main_relation_target = claim_batch
                        .main_relation_target_with_masked_cross_epoch_claims(
                            &parsed.cross_epoch_claims,
                            parsed.opening_batching_challenge,
                        )?;
                    let cross_epoch_point = parsed.cross_epoch_claims.point().to_vec();
                    let masked_pre_challenge_target =
                        parsed.cross_epoch_claims.disclosed_values()[0];
                    let public_covectors_after_first_fold = self
                        .public_covector_continuation
                        .take()
                        .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?
                        .finish_after_matrix_accumulation(source_covector)?;
                    self.complete_handoff =
                        Some(Box::new(AlgebraicallyVerifiedCompactCfwHandoff {
                            main_relation_target,
                            public_covectors_after_first_fold,
                            first_main_fold_challenges: parsed.first_main_fold_challenges,
                            cross_epoch_point,
                            masked_pre_challenge_target,
                        }));
                    if total_completed_work_unit_count != 0 {
                        return Ok(CompactPublicKeyCfwVerificationPoll::WorkCompleted {
                            completed_work_unit_count: total_completed_work_unit_count,
                        });
                    }
                }
            }
        }
    }
}

/// Pollable positive verifier for one selected compact public-key proof. The
/// transport terminal remains owned here until CFW and both WHIR epochs have
/// passed their independent equations.
pub(crate) struct CompactPublicKeyAlgebraicVerification {
    transport: Option<VerifiedCompactPublicKeyTransport>,
    cfw_verification: CompactPublicKeyCfwVerification,
    completed_work_unit_count: u64,
    replay_target_work_unit_count: Option<u64>,
}

pub(crate) enum CompactPublicKeyAlgebraicVerificationPoll {
    WorkCompleted {
        completed_work_unit_count: u64,
        checkpoint_safe_boundary_ordinal: Option<u32>,
    },
    ResumeComplete {
        completed_work_unit_count: u64,
        checkpoint_safe_boundary_ordinal: u32,
    },
    Complete(Box<AlgebraicallyVerifiedCompactPublicKeyProof>),
}

/// Internal positive terminal. This is deliberately not a workflow proof
/// capability: runtime binding and the public verification result own that
/// later transition.
pub(crate) struct AlgebraicallyVerifiedCompactPublicKeyProof {
    transport: VerifiedCompactPublicKeyTransport,
}

impl AlgebraicallyVerifiedCompactPublicKeyProof {
    #[cfg(test)]
    pub(crate) const fn transport(&self) -> &VerifiedCompactPublicKeyTransport {
        &self.transport
    }

    pub(crate) fn into_transport(self) -> VerifiedCompactPublicKeyTransport {
        self.transport
    }
}

impl CompactPublicKeyAlgebraicVerification {
    pub(crate) fn begin(
        transport: VerifiedCompactPublicKeyTransport,
    ) -> Result<Self, CompactPublicKeyAlgebraicVerificationError> {
        let cfw_verification = CompactPublicKeyCfwVerification::begin(&transport)?;
        Ok(Self {
            transport: Some(transport),
            cfw_verification,
            completed_work_unit_count: 0,
            replay_target_work_unit_count: None,
        })
    }

    pub(crate) fn resume(
        transport: VerifiedCompactPublicKeyTransport,
        canonical_checkpoint_bytes: &[u8],
    ) -> Result<Self, CompactPublicKeyAlgebraicVerificationError> {
        let checkpoint =
            CompactPublicKeyAlgebraicVerificationCheckpoint::decode(canonical_checkpoint_bytes)?;
        if checkpoint.public_input_bindings != transport.public_input_bindings()
            || checkpoint.canonical_proof_binding != transport.canonical_proof_binding()
            || checkpoint.canonical_public_input_binding
                != transport.canonical_public_input_binding()
        {
            return Err(CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint);
        }
        let mut verification = Self::begin(transport)?;
        verification.replay_target_work_unit_count = Some(checkpoint.completed_work_unit_count);
        Ok(verification)
    }

    pub(crate) fn canonical_checkpoint_bytes(
        &self,
    ) -> Result<
        [u8; COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_BYTE_LENGTH],
        CompactPublicKeyAlgebraicVerificationError,
    > {
        if checkpoint_safe_boundary_ordinal(self.completed_work_unit_count).is_none()
            || self.replay_target_work_unit_count.is_some()
        {
            return Err(CompactPublicKeyAlgebraicVerificationError::CheckpointUnavailable);
        }
        let transport = self
            .transport
            .as_ref()
            .ok_or(CompactPublicKeyAlgebraicVerificationError::CheckpointUnavailable)?;
        Ok(CompactPublicKeyAlgebraicVerificationCheckpoint {
            public_input_bindings: transport.public_input_bindings(),
            canonical_proof_binding: transport.canonical_proof_binding(),
            canonical_public_input_binding: transport.canonical_public_input_binding(),
            completed_work_unit_count: self.completed_work_unit_count,
        }
        .encode())
    }

    pub(crate) fn advance(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyAlgebraicVerificationPoll, CompactPublicKeyAlgebraicVerificationError>
    {
        if maximum_work_unit_count == 0 {
            return Err(CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint);
        }
        let replay_work_unit_count = self
            .replay_target_work_unit_count
            .map(|target_work_unit_count| {
                target_work_unit_count
                    .checked_sub(self.completed_work_unit_count)
                    .ok_or(CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint)
                    .map(|remaining_work_unit_count| {
                        remaining_work_unit_count.min(maximum_work_unit_count)
                    })
            })
            .transpose()?;
        let next_checkpoint_work_unit_count = self
            .completed_work_unit_count
            .checked_div(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL)
            .and_then(|completed_boundary_count| completed_boundary_count.checked_add(1))
            .and_then(|next_boundary_count| {
                next_boundary_count.checked_mul(
                    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL,
                )
            })
            .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let work_until_next_checkpoint = next_checkpoint_work_unit_count
            .checked_sub(self.completed_work_unit_count)
            .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let bounded_work_unit_count = replay_work_unit_count
            .unwrap_or(maximum_work_unit_count)
            .min(work_until_next_checkpoint);
        if bounded_work_unit_count == 0 {
            return Err(CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint);
        }
        match self.cfw_verification.advance(bounded_work_unit_count)? {
            CompactPublicKeyCfwVerificationPoll::WorkCompleted {
                completed_work_unit_count,
            } => {
                self.completed_work_unit_count = self
                    .completed_work_unit_count
                    .checked_add(completed_work_unit_count)
                    .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
                let checkpoint_safe_boundary_ordinal =
                    checkpoint_safe_boundary_ordinal(self.completed_work_unit_count);
                if let Some(target_work_unit_count) = self.replay_target_work_unit_count {
                    if self.completed_work_unit_count > target_work_unit_count {
                        return Err(CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint);
                    }
                    if self.completed_work_unit_count == target_work_unit_count {
                        self.replay_target_work_unit_count = None;
                        return Ok(CompactPublicKeyAlgebraicVerificationPoll::ResumeComplete {
                            completed_work_unit_count,
                            checkpoint_safe_boundary_ordinal: checkpoint_safe_boundary_ordinal
                                .ok_or(
                                    CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint,
                                )?,
                        });
                    }
                }
                Ok(CompactPublicKeyAlgebraicVerificationPoll::WorkCompleted {
                    completed_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                })
            }
            CompactPublicKeyCfwVerificationPoll::Complete(handoff) => {
                if self.replay_target_work_unit_count.is_some() {
                    return Err(CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint);
                }
                if self.completed_work_unit_count
                    != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT
                {
                    return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
                }
                let transport = self
                    .transport
                    .as_ref()
                    .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;
                verify_compact_whir_epochs(transport, *handoff)?;
                Ok(CompactPublicKeyAlgebraicVerificationPoll::Complete(
                    Box::new(AlgebraicallyVerifiedCompactPublicKeyProof {
                        transport: self
                            .transport
                            .take()
                            .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?,
                    }),
                ))
            }
        }
    }
}

const fn maximum_compact_public_key_algebraic_verification_checkpoint_work_unit_count() -> u64 {
    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT as u64
        * COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL
}

fn checkpoint_safe_boundary_ordinal(completed_work_unit_count: u64) -> Option<u32> {
    if completed_work_unit_count == 0
        || !completed_work_unit_count
            .is_multiple_of(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL)
        || completed_work_unit_count
            > maximum_compact_public_key_algebraic_verification_checkpoint_work_unit_count()
    {
        return None;
    }
    u32::try_from(
        completed_work_unit_count
            / COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL
            - 1,
    )
    .ok()
}

fn verify_compact_whir_epochs(
    transport: &VerifiedCompactPublicKeyTransport,
    handoff: AlgebraicallyVerifiedCompactCfwHandoff,
) -> Result<(), CompactPublicKeyAlgebraicVerificationError> {
    let inputs = transport.verifier_inputs();
    let pre_challenge_epoch = required_whir_epoch(inputs.whir_epochs, PRE_CHALLENGE_WHIR_EPOCH)?;
    let pre_challenge_folds = required_whir_folds(inputs.whir_folds, PRE_CHALLENGE_WHIR_EPOCH)?;
    let main_epoch = required_whir_epoch(inputs.whir_epochs, MAIN_WHIR_EPOCH)?;
    let main_folds = required_whir_folds(inputs.whir_folds, MAIN_WHIR_EPOCH)?;
    let (
        main_relation_target,
        main_public_covectors,
        first_main_fold_challenges,
        cross_epoch_point,
        masked_pre_challenge_target,
    ) = handoff.into_parts();

    let pre_challenge_relation = CompactWhirAlgebraicRelation::pre_challenge(
        pre_challenge_epoch,
        &cross_epoch_point,
        masked_pre_challenge_target,
    )
    .map_err(|error| {
        compact_whir_verification_error(
            PRE_CHALLENGE_WHIR_EPOCH,
            CompactPublicKeyWhirVerificationStage::InitialRelation,
            error,
        )
    })?;
    verify_compact_whir_epoch(
        transport,
        pre_challenge_epoch,
        pre_challenge_folds,
        pre_challenge_relation,
        None,
    )?;

    let main_relation =
        CompactWhirAlgebraicRelation::main(main_epoch, main_public_covectors, main_relation_target)
            .map_err(|error| {
                compact_whir_verification_error(
                    MAIN_WHIR_EPOCH,
                    CompactPublicKeyWhirVerificationStage::InitialRelation,
                    error,
                )
            })?;
    verify_compact_whir_epoch(
        transport,
        main_epoch,
        main_folds,
        main_relation,
        Some(&first_main_fold_challenges),
    )
}

fn verify_compact_whir_epoch(
    transport: &VerifiedCompactPublicKeyTransport,
    epoch: &super::compact_proof_contract::CompactWhirEpochContract,
    folds: [super::compact_proof_contract::CompactWhirFoldContract; COMPACT_WHIR_BATCH_COUNT],
    mut relation: CompactWhirAlgebraicRelation,
    already_applied_first_fold_challenges: Option<&[CompactChallengeField]>,
) -> Result<(), CompactPublicKeyAlgebraicVerificationError> {
    let mut final_folding_challenges = Vec::new();
    for (batch_index, fold) in folds.iter().copied().enumerate() {
        let batch_ordinal = u8::try_from(batch_index)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let auxiliary_target =
            required_complete_response_role(transport, 12, epoch.epoch, batch_ordinal, 0, 1)?[0];
        let combination_challenge = compact_challenge_from_production(
            required_verifier_extension_role(transport, 7, epoch.epoch, batch_ordinal, 0, 1)?[0],
        );
        let folding_factor = usize::try_from(epoch.folding_schedule[batch_index])
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let mut round_wires = Vec::new();
        let mut round_challenges = Vec::new();
        round_wires
            .try_reserve_exact(folding_factor)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        round_challenges
            .try_reserve_exact(folding_factor)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        for round_index in 0..folding_factor {
            let round_ordinal = u32::try_from(round_index)
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
            round_wires.push(
                required_complete_response_role(
                    transport,
                    13,
                    epoch.epoch,
                    batch_ordinal,
                    round_ordinal,
                    2,
                )?
                .try_into()
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?,
            );
            round_challenges.push(compact_challenge_from_production(
                required_verifier_extension_role(
                    transport,
                    8,
                    epoch.epoch,
                    batch_ordinal,
                    round_ordinal,
                    1,
                )?[0],
            ));
        }
        if batch_index == 0
            && already_applied_first_fold_challenges
                .is_some_and(|expected| expected != round_challenges)
        {
            return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
        }
        relation
            .verify_sumcheck_batch(
                epoch,
                fold,
                batch_index,
                batch_index == 0 && already_applied_first_fold_challenges.is_some(),
                CompactWhirSumcheckTranscript {
                    auxiliary_target,
                    combination_challenge,
                    round_wires: &round_wires,
                    round_challenges: &round_challenges,
                },
            )
            .map_err(|error| {
                compact_whir_verification_error(
                    epoch.epoch,
                    CompactPublicKeyWhirVerificationStage::Sumcheck { batch_ordinal },
                    error,
                )
            })?;
        if batch_index == COMPACT_WHIR_BATCH_COUNT - 1 {
            final_folding_challenges = round_challenges;
        } else {
            verify_compact_whir_code_switch(
                transport,
                epoch,
                folds[batch_index],
                folds[batch_index + 1],
                batch_index,
                &round_challenges,
                &mut relation,
            )?;
        }
    }
    verify_compact_whir_base_case(
        transport,
        epoch,
        folds[COMPACT_WHIR_BATCH_COUNT - 1],
        &final_folding_challenges,
        &relation,
    )
}

fn verify_compact_whir_code_switch(
    transport: &VerifiedCompactPublicKeyTransport,
    epoch: &super::compact_proof_contract::CompactWhirEpochContract,
    input_fold: super::compact_proof_contract::CompactWhirFoldContract,
    output_fold: super::compact_proof_contract::CompactWhirFoldContract,
    round_index: usize,
    folding_challenges: &[CompactChallengeField],
    relation: &mut CompactWhirAlgebraicRelation,
) -> Result<(), CompactPublicKeyAlgebraicVerificationError> {
    if round_index >= COMPACT_WHIR_CODE_SWITCH_COUNT {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    let stage_round_ordinal = u8::try_from(round_index)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let round_ordinal = u32::try_from(round_index)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let role = transport.verifier_role(9, epoch.epoch, 0, round_ordinal)?;
    if role.extension_elements().len() != 1
        || role.base_field_elements().len() != 1
        || role.distinct_query_groups().len() != 1
    {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    let combination_challenge = compact_challenge_from_production(role.extension_elements()[0]);
    let query_positions = role.distinct_query_groups()[0].clone();
    let expected_width = usize::try_from(input_fold.oracle_width)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let source_rows = if round_index == 0 && epoch.epoch == PRE_CHALLENGE_WHIR_EPOCH {
        required_opened_base_rows(transport, 1, 0, 0, 0, &query_positions, expected_width)?
    } else {
        let (role_tag, role_epoch, role_round) = if round_index == 0 {
            (3, 0, 0)
        } else {
            (14, epoch.epoch, round_ordinal - 1)
        };
        required_opened_extension_rows(
            transport,
            role_tag,
            role_epoch,
            0,
            role_round,
            &query_positions,
            expected_width,
            true,
        )?
    };
    let flattened_source_rows = source_rows.into_iter().flatten().collect::<Vec<_>>();
    let folded_source_openings = fold_compact_whir_query_major_source_openings(
        &flattened_source_rows,
        query_positions.len(),
        folding_challenges,
    )?;
    relation
        .verify_code_switch(
            epoch,
            input_fold,
            output_fold,
            round_index,
            CompactWhirCodeSwitchTranscript {
                combination_challenge,
                query_positions: &query_positions,
                folded_source_openings: &folded_source_openings,
            },
        )
        .map_err(|error| {
            compact_whir_verification_error(
                epoch.epoch,
                CompactPublicKeyWhirVerificationStage::CodeSwitch {
                    round_ordinal: stage_round_ordinal,
                },
                error,
            )
        })?;
    Ok(())
}

fn verify_compact_whir_base_case(
    transport: &VerifiedCompactPublicKeyTransport,
    epoch: &super::compact_proof_contract::CompactWhirEpochContract,
    final_fold: super::compact_proof_contract::CompactWhirFoldContract,
    final_folding_challenges: &[CompactChallengeField],
    relation: &CompactWhirAlgebraicRelation,
) -> Result<(), CompactPublicKeyAlgebraicVerificationError> {
    let combination_challenge = compact_challenge_from_production(
        required_verifier_extension_role(transport, 10, epoch.epoch, 0, 0, 1)?[0],
    );
    let mask_group_count = epoch
        .external_mask_groups
        .len()
        .checked_add(epoch.internal_mask_groups.len())
        .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let final_query_role = transport.verifier_role(11, epoch.epoch, 0, 0)?;
    if !final_query_role.extension_elements().is_empty()
        || !final_query_role.base_field_elements().is_empty()
        || final_query_role.distinct_query_groups().len() != mask_group_count + 1
    {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    let final_query_groups = final_query_role.distinct_query_groups().to_vec();
    let fresh_claim = required_complete_response_role(transport, 18, epoch.epoch, 0, 0, 1)?[0];
    let source_message_length = 1_usize
        .checked_shl(epoch.final_variable_count)
        .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let blinded_source_message =
        required_complete_response_role(transport, 19, epoch.epoch, 0, 0, source_message_length)?;
    let blinded_source_randomness = required_complete_response_role(
        transport,
        20,
        epoch.epoch,
        0,
        0,
        usize::try_from(final_fold.hiding_randomness_length)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
    )?;
    let mut blinded_masks = Vec::new();
    blinded_masks
        .try_reserve_exact(mask_group_count)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    for (group_index, contract) in epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .copied()
        .enumerate()
    {
        blinded_masks.push(required_blinded_mask_reveal(
            transport,
            epoch.epoch,
            group_index,
            contract,
        )?);
    }
    relation
        .verify_blinded_target(
            epoch,
            fresh_claim,
            combination_challenge,
            &blinded_source_message,
            &blinded_masks,
        )
        .map_err(|error| {
            compact_whir_verification_error(
                epoch.epoch,
                CompactPublicKeyWhirVerificationStage::BaseTarget,
                error,
            )
        })?;

    let source_query_positions = &final_query_groups[0];
    let carried_source_rows = required_opened_extension_rows(
        transport,
        14,
        epoch.epoch,
        0,
        u32::try_from(COMPACT_WHIR_CODE_SWITCH_COUNT - 1)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
        source_query_positions,
        usize::try_from(final_fold.oracle_width)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
        true,
    )?;
    let fresh_source_rows = required_opened_extension_rows(
        transport,
        16,
        epoch.epoch,
        0,
        0,
        source_query_positions,
        1,
        true,
    )?;
    verify_compact_whir_source_spot_checks(CompactWhirSourceSpotCheck {
        final_fold,
        final_folding_challenges,
        query_positions: source_query_positions,
        carried_source_rows: &carried_source_rows,
        fresh_source_rows: &fresh_source_rows,
        blinded_message: &blinded_source_message,
        blinded_randomness: &blinded_source_randomness,
        combination_challenge,
    })
    .map_err(|error| {
        compact_whir_verification_error(
            epoch.epoch,
            CompactPublicKeyWhirVerificationStage::BaseSource,
            error,
        )
    })?;

    for (group_index, (contract, blinded_mask)) in epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .copied()
        .zip(&blinded_masks)
        .enumerate()
    {
        let group_ordinal = u8::try_from(group_index)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let query_positions = &final_query_groups[group_index + 1];
        let (carried_role_tag, carried_epoch, carried_batch, carried_round, exact_positions) =
            carried_mask_response_role(epoch.epoch, contract)?;
        let carried_rows = required_opened_extension_rows(
            transport,
            carried_role_tag,
            carried_epoch,
            carried_batch,
            carried_round,
            query_positions,
            usize::try_from(contract.width)
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
            exact_positions,
        )?;
        let fresh_rows = required_opened_extension_rows(
            transport,
            17,
            epoch.epoch,
            group_ordinal,
            0,
            query_positions,
            usize::try_from(contract.width)
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
            true,
        )?;
        verify_compact_whir_mask_spot_checks(
            contract,
            query_positions,
            &carried_rows,
            &fresh_rows,
            blinded_mask,
            combination_challenge,
        )
        .map_err(|error| {
            compact_whir_verification_error(
                epoch.epoch,
                CompactPublicKeyWhirVerificationStage::BaseMask { group_ordinal },
                error,
            )
        })?;
    }
    Ok(())
}

impl ParsedCompactCfwTranscript {
    fn parse(
        transport: &VerifiedCompactPublicKeyTransport,
    ) -> Result<Self, CompactPublicKeyAlgebraicVerificationError> {
        let inputs = transport.verifier_inputs();
        let geometry = inputs.cfw_configuration.geometry();
        let initial_values = required_verifier_extension_role(
            transport,
            3,
            0,
            0,
            0,
            geometry
                .sumcheck_round_count()
                .checked_add(1)
                .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
        )?;
        let (&constraint_combining_challenge, equality_point) = initial_values
            .split_first()
            .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;

        let mut sumcheck_point = Vec::new();
        sumcheck_point
            .try_reserve_exact(geometry.sumcheck_round_count())
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let mut round_polynomials = Vec::new();
        round_polynomials
            .try_reserve_exact(geometry.sumcheck_round_count())
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        for round_index in 0..geometry.sumcheck_round_count() {
            let round_ordinal = u32::try_from(round_index)
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
            sumcheck_point.push(compact_challenge_from_production(
                required_verifier_extension_role(transport, 4, 0, 0, round_ordinal, 1)?[0],
            ));
            round_polynomials.push(
                required_complete_response_role(
                    transport,
                    8,
                    0,
                    0,
                    round_ordinal,
                    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
                )?
                .try_into()
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?,
            );
        }

        let cross_epoch_point = required_verifier_extension_role(
            transport,
            2,
            0,
            0,
            0,
            usize::try_from(
                inputs
                    .cfw_configuration
                    .cross_epoch()
                    .point_coordinate_count,
            )
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
        )?
        .into_iter()
        .map(compact_challenge_from_production)
        .collect();
        let disclosed_cross_epoch_values =
            required_complete_response_role(transport, 6, 0, 0, 0, 3)?;
        let cross_epoch_claims = CompactCfwMaskedCrossEpochClaims::new(
            cross_epoch_point,
            usize::try_from(inputs.cfw_configuration.cross_epoch().copied_element_count)
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
            disclosed_cross_epoch_values[0],
            disclosed_cross_epoch_values[1],
            disclosed_cross_epoch_values[2],
        );
        let auxiliary_target = required_complete_response_role(transport, 7, 0, 0, 0, 1)?[0];
        let outer_evaluations =
            required_complete_response_role(transport, 9, 0, 0, 0, geometry.outer_mask_count())?;
        let final_values =
            required_complete_response_role(transport, 10, 0, 0, 0, COMPACT_CFW_MATRIX_COUNT)?
                .try_into()
                .map_err(|_| CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;
        let joint_constraint_challenge =
            required_verifier_extension_role(transport, 5, 0, 0, 0, 1)?[0];
        let opening_batching_challenge =
            required_verifier_extension_role(transport, 6, MAIN_WHIR_EPOCH, 0, 0, 1)?[0];
        let main_epoch = inputs
            .whir_epochs
            .iter()
            .find(|epoch| epoch.epoch == MAIN_WHIR_EPOCH)
            .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;
        let first_fold_count = usize::try_from(main_epoch.folding_schedule[0])
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        let mut first_main_fold_challenges = Vec::new();
        first_main_fold_challenges
            .try_reserve_exact(first_fold_count)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
        for round_index in 0..first_fold_count {
            first_main_fold_challenges.push(compact_challenge_from_production(
                required_verifier_extension_role(
                    transport,
                    8,
                    MAIN_WHIR_EPOCH,
                    INITIAL_WHIR_BATCH,
                    u32::try_from(round_index).map_err(|_| {
                        CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow
                    })?,
                    1,
                )?[0],
            ));
        }
        Ok(Self {
            geometry,
            constraint_combining_challenge: compact_challenge_from_production(
                constraint_combining_challenge,
            ),
            equality_point: equality_point
                .iter()
                .copied()
                .map(compact_challenge_from_production)
                .collect(),
            sumcheck_point,
            joint_constraint_challenge: compact_challenge_from_production(
                joint_constraint_challenge,
            ),
            opening_batching_challenge: compact_challenge_from_production(
                opening_batching_challenge,
            ),
            cross_epoch_claims,
            transcript: CompactCfwTranscript::new(
                auxiliary_target,
                round_polynomials,
                outer_evaluations,
                final_values,
            ),
            first_main_fold_challenges,
        })
    }
}

fn required_whir_epoch(
    epochs: &[super::compact_proof_contract::CompactWhirEpochContract],
    epoch_tag: u8,
) -> Result<
    &super::compact_proof_contract::CompactWhirEpochContract,
    CompactPublicKeyAlgebraicVerificationError,
> {
    let mut matching = epochs.iter().filter(|epoch| epoch.epoch == epoch_tag);
    let epoch = matching
        .next()
        .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;
    if matching.next().is_some() {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    Ok(epoch)
}

fn required_whir_folds(
    folds: &[super::compact_proof_contract::CompactWhirFoldContract],
    epoch_tag: u8,
) -> Result<
    [super::compact_proof_contract::CompactWhirFoldContract; COMPACT_WHIR_BATCH_COUNT],
    CompactPublicKeyAlgebraicVerificationError,
> {
    let matching = folds
        .iter()
        .copied()
        .filter(|fold| fold.epoch == epoch_tag)
        .collect::<Vec<_>>();
    let matching: [super::compact_proof_contract::CompactWhirFoldContract;
        COMPACT_WHIR_BATCH_COUNT] = matching
        .try_into()
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;
    if matching
        .iter()
        .enumerate()
        .any(|(batch_index, fold)| usize::from(fold.batch_ordinal) != batch_index)
    {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    Ok(matching)
}

fn required_opened_base_rows(
    transport: &VerifiedCompactPublicKeyTransport,
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
    expected_positions: &[u64],
    expected_width: usize,
) -> Result<Vec<Vec<CompactChallengeField>>, CompactPublicKeyAlgebraicVerificationError> {
    let role = transport.opened_base_role(role_tag, epoch, batch_ordinal, round_ordinal)?;
    if expected_positions.is_empty()
        || role.opened_leaves().len() != expected_positions.len()
        || role
            .opened_leaves()
            .iter()
            .zip(expected_positions)
            .any(|(leaf, position)| {
                leaf.component_leaf_ordinal() != *position || leaf.values().len() != expected_width
            })
    {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    Ok(role
        .opened_leaves()
        .iter()
        .map(|leaf| {
            leaf.values()
                .iter()
                .copied()
                .map(compact_challenge_from_base)
                .collect()
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn required_opened_extension_rows(
    transport: &VerifiedCompactPublicKeyTransport,
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
    expected_positions: &[u64],
    expected_width: usize,
    positions_must_be_exact: bool,
) -> Result<Vec<Vec<CompactChallengeField>>, CompactPublicKeyAlgebraicVerificationError> {
    let role = transport.opened_extension_role(role_tag, epoch, batch_ordinal, round_ordinal)?;
    if expected_positions.is_empty()
        || (positions_must_be_exact && role.opened_leaves().len() != expected_positions.len())
    {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(expected_positions.len())
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    for expected_position in expected_positions {
        let leaf = role
            .opened_leaves()
            .binary_search_by_key(expected_position, |leaf| leaf.component_leaf_ordinal())
            .ok()
            .and_then(|leaf_index| role.opened_leaves().get(leaf_index))
            .filter(|leaf| leaf.values().len() == expected_width)
            .ok_or(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript)?;
        rows.push(
            leaf.values()
                .iter()
                .copied()
                .map(compact_challenge_from_production)
                .collect(),
        );
    }
    Ok(rows)
}

fn required_blinded_mask_reveal(
    transport: &VerifiedCompactPublicKeyTransport,
    epoch: u8,
    group_index: usize,
    contract: super::compact_proof_contract::CompactWhirMaskGroupContract,
) -> Result<CompactWhirBlindedMaskReveal, CompactPublicKeyAlgebraicVerificationError> {
    let width = usize::try_from(contract.width)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let message_length = usize::try_from(contract.message_length)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let randomness_length = usize::try_from(contract.randomness_length)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let lane_length = message_length
        .checked_add(randomness_length)
        .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let value_count = width
        .checked_mul(lane_length)
        .ok_or(CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    let values = required_complete_response_role(
        transport,
        21,
        epoch,
        u8::try_from(group_index)
            .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?,
        0,
        value_count,
    )?;
    let mut messages = Vec::new();
    let mut randomness = Vec::new();
    messages
        .try_reserve_exact(width)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    randomness
        .try_reserve_exact(width)
        .map_err(|_| CompactPublicKeyAlgebraicVerificationError::ArithmeticOverflow)?;
    for lane in values.chunks_exact(lane_length) {
        messages.push(lane[..message_length].to_vec());
        randomness.push(lane[message_length..].to_vec());
    }
    if messages.len() != width || randomness.len() != width {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    Ok(CompactWhirBlindedMaskReveal {
        messages,
        randomness,
    })
}

fn carried_mask_response_role(
    epoch: u8,
    contract: super::compact_proof_contract::CompactWhirMaskGroupContract,
) -> Result<(u8, u8, u8, u32, bool), CompactPublicKeyAlgebraicVerificationError> {
    match (contract.role_tag, contract.coordinate) {
        (1, 0) => Ok((5, 0, 0, 0, false)),
        (2, 0) => Ok((2, 0, 0, 0, true)),
        (3, 0) => Ok((4, 0, 0, 0, true)),
        (4, batch_ordinal) if usize::from(batch_ordinal) < COMPACT_WHIR_BATCH_COUNT => {
            Ok((11, epoch, batch_ordinal, 0, true))
        }
        (5, round_ordinal) if usize::from(round_ordinal) < COMPACT_WHIR_CODE_SWITCH_COUNT => {
            Ok((15, epoch, 0, u32::from(round_ordinal), true))
        }
        _ => Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript),
    }
}

fn compact_challenge_from_base(value: ProofBaseFieldElement) -> CompactChallengeField {
    CompactChallengeField::from_u64(value.canonical())
}

fn required_verifier_extension_role(
    transport: &VerifiedCompactPublicKeyTransport,
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
    expected_value_count: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, CompactPublicKeyAlgebraicVerificationError> {
    let role = transport.verifier_role(role_tag, epoch, batch_ordinal, round_ordinal)?;
    if !role.base_field_elements().is_empty()
        || !role.distinct_query_groups().is_empty()
        || role.extension_elements().len() != expected_value_count
    {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    Ok(role.extension_elements().to_vec())
}

fn required_complete_response_role(
    transport: &VerifiedCompactPublicKeyTransport,
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
    expected_value_count: usize,
) -> Result<Vec<CompactChallengeField>, CompactPublicKeyAlgebraicVerificationError> {
    let values = transport
        .opened_extension_role(role_tag, epoch, batch_ordinal, round_ordinal)?
        .complete_values()?;
    if values.len() != expected_value_count {
        return Err(CompactPublicKeyAlgebraicVerificationError::InvalidTranscript);
    }
    Ok(values
        .into_iter()
        .map(compact_challenge_from_production)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(
        completed_work_unit_count: u64,
    ) -> CompactPublicKeyAlgebraicVerificationCheckpoint {
        CompactPublicKeyAlgebraicVerificationCheckpoint {
            public_input_bindings: CompactPublicInputBindings::new(
                Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x44; Hash512::BYTE_LENGTH]),
            ),
            canonical_proof_binding: [0x55; Hash512::BYTE_LENGTH],
            canonical_public_input_binding: [0x66; Hash512::BYTE_LENGTH],
            completed_work_unit_count,
        }
    }

    #[test]
    fn algebraic_verification_checkpoint_round_trips_exact_sources_and_safe_cursor() {
        let checkpoint =
            checkpoint(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL);
        let canonical_bytes = checkpoint.encode();
        assert_eq!(canonical_bytes.len(), 400);
        assert_eq!(
            CompactPublicKeyAlgebraicVerificationCheckpoint::decode(&canonical_bytes),
            Ok(checkpoint)
        );

        for changed_byte_offset in [8, 72, 136, 200, 264, 328] {
            let mut changed_bytes = canonical_bytes;
            changed_bytes[changed_byte_offset] ^= 1;
            assert_ne!(
                CompactPublicKeyAlgebraicVerificationCheckpoint::decode(&changed_bytes),
                Ok(checkpoint),
                "source coordinate at byte offset {changed_byte_offset} must remain load-bearing"
            );
        }
    }

    #[test]
    fn algebraic_verification_checkpoint_refuses_malformed_framing_and_genesis() {
        let canonical_bytes =
            checkpoint(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL)
                .encode();
        for malformed_bytes in [
            canonical_bytes[..canonical_bytes.len() - 1].to_vec(),
            {
                let mut bytes = canonical_bytes.to_vec();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = canonical_bytes.to_vec();
                bytes[0] ^= 1;
                bytes
            },
            checkpoint(0).encode().to_vec(),
            checkpoint(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL - 1)
                .encode()
                .to_vec(),
            checkpoint(
                maximum_compact_public_key_algebraic_verification_checkpoint_work_unit_count()
                    + COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL,
            )
            .encode()
            .to_vec(),
        ] {
            assert_eq!(
                CompactPublicKeyAlgebraicVerificationCheckpoint::decode(&malformed_bytes),
                Err(CompactPublicKeyAlgebraicVerificationError::MalformedCheckpoint)
            );
        }
    }
}
