//! Canonical WHIR primitives for the compact factor-one proof.
//!
//! The same hash functions, commitment scheme, challenger, and protocol
//! configuration are used by generation and independent verification.
//! Base-source custody retains the exact encoded matrix produced by WHIR. The
//! selected extension source instead recomputes the same canonical rows in
//! bounded stripes from retained source authority and encoding randomness, so
//! it never retains the 640 MiB logical matrix or constructs a redundant inner
//! Merkle tree.

use core::mem::size_of;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::{Matrix, dense::DenseMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::poly::Poly;
#[cfg(test)]
use p3_sumcheck::zk::stack_codewords;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
#[cfg(test)]
use p3_whir::pcs::zk::HidingWhirEncodedExtensionOracle;
use p3_whir::pcs::zk::{
    HidingWhirProver, MaskCodeShape, MaskGroupShape, MaskProverData, ZkWhirConfig, ZkWhirProof,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, ZkParameters};
use rand::{Rng, RngExt};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::{
    bounded_radix2_dft::BoundedRadix2Dft,
    compact_cfw::CompactChallengeField,
    compact_proof_contract::{
        CompactWhirEpochContract, CompactWhirFoldContract, CompactWhirMaskGroupContract,
    },
};

pub(super) const COMPACT_WHIR_FOLD_COUNT: usize = 4;
pub(super) const COMPACT_WHIR_ROUND_COUNT: usize = COMPACT_WHIR_FOLD_COUNT - 1;
pub(super) const COMPACT_WHIR_FINAL_VARIABLE_COUNT: u32 = 3;
pub(super) const COMPACT_WHIR_REPEATED_FOLDING_FACTOR: u32 = 4;
pub(super) const COMPACT_WHIR_STARTING_LOG_INVERSE_RATE: usize = 2;
pub(super) const COMPACT_WHIR_ROUND_LOG_INVERSE_RATES: [u32; COMPACT_WHIR_ROUND_COUNT] = [2, 4, 8];
pub(super) const COMPACT_WHIR_PROTOCOL_SECURITY_LEVEL: usize = 267;
pub(super) const COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH: usize = 3;
pub(super) const COMPACT_WHIR_MASK_LOG_INVERSE_RATE: usize = 2;
pub(crate) const COMPACT_WHIR_EXTENSION_RESPONSE_STRIPE_ROW_COUNT: usize = 1 << 14;

const COMPACT_WHIR_HASH_DOMAIN: &[u8] = b"sealed-lattice/compact-proof/whir/hash/v1";
const COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH: usize = 64;
pub(crate) const COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH: usize =
    COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH / size_of::<u64>();

#[derive(Clone, Copy, Debug)]
pub(crate) struct CompactWhirByteHasher;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CompactWhirGoldilocksLeafHasher;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CompactWhirWordHasher;

pub(crate) type CompactWhirInnerChallenger =
    HashChallenger<u8, CompactWhirByteHasher, COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH>;
pub(crate) type CompactWhirChallenger =
    SerializingChallenger64<Goldilocks, CompactWhirInnerChallenger>;
pub(crate) type CompactWhirNodeCompressor =
    CompressionFunctionFromHasher<CompactWhirWordHasher, 2, COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH>;
pub(crate) type CompactWhirCommitmentScheme = MerkleTreeMmcs<
    Goldilocks,
    u64,
    CompactWhirGoldilocksLeafHasher,
    CompactWhirNodeCompressor,
    2,
    COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH,
>;
pub(crate) type CompactWhirExtensionCommitmentScheme =
    ExtensionMmcs<Goldilocks, CompactChallengeField, CompactWhirCommitmentScheme>;
pub(crate) type CompactWhirCommitment =
    <CompactWhirCommitmentScheme as Mmcs<Goldilocks>>::Commitment;
pub(crate) type CompactWhirMaskProverData =
    MaskProverData<Goldilocks, CompactChallengeField, CompactWhirCommitmentScheme>;
pub(crate) type CompactWhirProof =
    ZkWhirProof<Goldilocks, CompactChallengeField, CompactWhirCommitmentScheme>;
pub(crate) type CompactWhirConfiguration =
    ZkWhirConfig<CompactChallengeField, Goldilocks, CompactWhirChallenger>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirError {
    CountOverflow,
    AllocationLimitExceeded,
    InvalidConfiguration,
    FoldingScheduleMismatch,
    RoundRateMismatch,
    FinalVariableCountMismatch,
    InvalidProofOfWorkGeometry,
    InvalidMessage,
    InvalidEncodedMatrix,
    InvalidRelation,
    InvalidWorkBudget,
    WrongProverPhase,
}

pub(crate) struct CompactWhirEncodedInitialOracle {
    source_message: Option<Vec<Goldilocks>>,
    encoding_randomness: Vec<Goldilocks>,
    encoded_matrix: DenseMatrix<Goldilocks>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirPreChallengeRelationPreparationStep {
    ConvertSource,
    BuildEqualityCovector,
    VerifyRelation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirPreChallengeRelationPreparationPoll {
    StepCompleted {
        step: CompactWhirPreChallengeRelationPreparationStep,
        processed_work_unit_count: u64,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactWhirPreChallengeRelationPreparationPhase {
    ConvertSource,
    BuildEqualityCovector,
    VerifyRelation,
    Complete,
}

/// Pollable construction of the exact base-source relation entering the first
/// WHIR epoch. The constructor owns the committed source message after its
/// initial response has been retained, expands the verifier-derived equality
/// covector in bounded chunks, and checks the masked cross-epoch claim before
/// the relation can enter the sumcheck.
pub(crate) struct CompactWhirPreChallengeRelationPreparation {
    base_source: Option<Vec<Goldilocks>>,
    source_evaluations: Vec<CompactChallengeField>,
    equality_point: Vec<CompactChallengeField>,
    source_covector: Vec<CompactChallengeField>,
    next_source_element: usize,
    completed_equality_coordinate_count: usize,
    next_equality_parent_ordinal: usize,
    next_relation_element: usize,
    accumulated_source_claim: CompactChallengeField,
    masked_pre_challenge_evaluation: CompactChallengeField,
    masked_main_evaluation: CompactChallengeField,
    mask_difference: CompactChallengeField,
    pre_challenge_mask: CompactChallengeField,
    main_mask: CompactChallengeField,
    opening_batching_challenge: CompactChallengeField,
    phase: CompactWhirPreChallengeRelationPreparationPhase,
}

/// Opaque, checked relation handed to the first masked WHIR sumcheck.
pub(crate) struct CompactWhirPreChallengeRelation {
    source_evaluations: Vec<CompactChallengeField>,
    source_covector: Vec<CompactChallengeField>,
    source_claim: CompactChallengeField,
    masked_target: CompactChallengeField,
    pre_challenge_mask: CompactChallengeField,
    opening_batching_challenge: CompactChallengeField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactWhirInitialSumcheckPhase {
    AwaitingCombinationChallenge,
    ComputingRoundPolynomial {
        next_pair_ordinal: usize,
        constant_coefficient: CompactChallengeField,
        leading_coefficient: CompactChallengeField,
    },
    RoundPolynomialReady {
        constant_coefficient: CompactChallengeField,
        leading_coefficient: CompactChallengeField,
    },
    FoldingRound {
        challenge: CompactChallengeField,
        next_pair_ordinal: usize,
        constant_coefficient: CompactChallengeField,
        leading_coefficient: CompactChallengeField,
    },
    ScalingWeights {
        next_element_ordinal: usize,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirInitialSumcheckPoll {
    RoundPolynomialStepCompleted {
        round_ordinal: u32,
        processed_work_unit_count: u64,
        polynomial_ready: bool,
    },
    BoundRoundStepCompleted {
        round_ordinal: u32,
        processed_work_unit_count: u64,
        round_complete: bool,
    },
    WeightScalingStepCompleted {
        processed_work_unit_count: u64,
        scaling_complete: bool,
    },
}

/// Scalar, pollable Construction 6.3 sumcheck batch for the live compact
/// prover. It emits the same auxiliary target and dropped-linear-coefficient
/// round wire as the WHIR implementation while making every source scan and
/// fold interruptible at an explicit work budget.
pub(crate) struct CompactWhirInitialSumcheckState {
    source_evaluations: Vec<CompactChallengeField>,
    source_covector: Vec<CompactChallengeField>,
    source_claim: CompactChallengeField,
    masked_target: CompactChallengeField,
    opening_batching_challenge: CompactChallengeField,
    sumcheck_mask_messages: Vec<Vec<CompactChallengeField>>,
    sumcheck_mask_encoding_randomness: Vec<Vec<CompactChallengeField>>,
    sumcheck_mask_oracle: CompactWhirEncodedMaskGroup,
    auxiliary_target: CompactChallengeField,
    remaining_mask_endpoint_sum: CompactChallengeField,
    preceding_mask_carry: CompactChallengeField,
    combination_challenge: Option<CompactChallengeField>,
    round_challenges: Vec<CompactChallengeField>,
    past_mask_evaluations: Vec<CompactChallengeField>,
    pending_round_wire: Option<Vec<CompactChallengeField>>,
    round_wires: Vec<Vec<CompactChallengeField>>,
    phase: CompactWhirInitialSumcheckPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactWhirCodeSwitchPhase {
    FoldingPreviousRandomness,
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirCodeSwitchPreparationPoll {
    RandomnessFoldStepCompleted {
        processed_work_unit_count: u64,
        fold_complete: bool,
    },
    Complete,
}

/// Pollable preparation and bounded source encoding for one WHIR code-switch
/// response. The switch-mask message is the exact affine fold of the prior
/// source oracle's hiding randomness; only its encoding randomness is fresh.
pub(crate) struct CompactWhirCodeSwitchState {
    source_evaluations: Vec<CompactChallengeField>,
    source_oracle: CompactWhirRecomputableExtensionInitialOracle,
    previous_encoding_randomness: Vec<Goldilocks>,
    folding_weights: Vec<CompactChallengeField>,
    folded_previous_randomness: Vec<CompactChallengeField>,
    next_randomness_element_ordinal: usize,
    switch_mask_encoding_randomness: Vec<CompactChallengeField>,
    switch_mask_oracle: Option<CompactWhirEncodedMaskGroup>,
    switch_mask_shape: MaskGroupShape,
    previous_source_height: usize,
    expected_query_count: usize,
    query_positions: Option<Vec<usize>>,
    combination_challenge: Option<CompactChallengeField>,
    phase: CompactWhirCodeSwitchPhase,
}

#[cfg(test)]
pub(crate) struct CompactWhirEncodedExtensionInitialOracle {
    encoded_oracle: HidingWhirEncodedExtensionOracle<Goldilocks, CompactChallengeField>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactWhirRecomputableExtensionStage {
    PrepareStripe,
    PrepareColumn,
    LoadSource,
    Transform,
    CaptureStripe,
    StripeReady,
    Complete,
    OpeningReplayComplete,
}

pub(crate) struct CompactWhirRecomputableExtensionInitialOracle {
    source_element_count: usize,
    source_height: usize,
    encoded_height: usize,
    width: usize,
    randomness_rows: usize,
    randomness: Vec<CompactChallengeField>,
    maximum_stripe_row_count: usize,
    stripe_first_row: usize,
    stripe_end_row: usize,
    next_response_row: usize,
    stripe_values: Vec<CompactChallengeField>,
    current_column_ordinal: usize,
    next_source_row: usize,
    active_transform: Option<BoundedRadix2Dft>,
    encoded_column_values: Option<Vec<CompactChallengeField>>,
    next_capture_row: usize,
    opening_row_ordinals: Vec<usize>,
    next_opening_row_offset: usize,
    stage: CompactWhirRecomputableExtensionStage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirRecomputableExtensionPoll {
    ArithmeticStepCompleted { processed_work_unit_count: u64 },
    StripeReady { first_row: u64, row_count: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirRecomputableExtensionError<SourceError> {
    Whir(CompactWhirError),
    Source(SourceError),
}

impl<SourceError> From<CompactWhirError> for CompactWhirRecomputableExtensionError<SourceError> {
    fn from(error: CompactWhirError) -> Self {
        Self::Whir(error)
    }
}

pub(crate) struct CompactWhirEncodedMaskGroup {
    encoded_matrix: DenseMatrix<CompactChallengeField>,
}

impl CompactWhirEncodedInitialOracle {
    pub(crate) fn encode<R: Rng>(
        configuration: &CompactWhirConfiguration,
        message: Vec<Goldilocks>,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let expected_message_length = 1_usize
            .checked_shl(
                u32::try_from(configuration.num_variables)
                    .map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .ok_or(CompactWhirError::CountOverflow)?;
        if message.len() != expected_message_length {
            return Err(CompactWhirError::InvalidMessage);
        }
        let commitment_scheme = compact_whir_commitment_scheme();
        let transform = Radix2DFTSmallBatch::<Goldilocks>::default();
        let prover = HidingWhirProver::new(configuration, &transform, &commitment_scheme);
        let encoded_oracle = prover.encode_base_initial_oracle(Poly::new(message), random_source);
        let encoded = Self {
            source_message: Some(encoded_oracle.message.into_evals()),
            encoding_randomness: encoded_oracle.randomness,
            encoded_matrix: encoded_oracle.encoded,
        };
        let (expected_width, expected_height) = initial_oracle_dimensions(configuration)?;
        let matrix = encoded.encoded_matrix();
        if matrix.width() != expected_width || matrix.height() != expected_height {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        Ok(encoded)
    }

    pub(crate) const fn encoded_matrix(&self) -> &DenseMatrix<Goldilocks> {
        &self.encoded_matrix
    }

    pub(crate) fn encoded_row(&self, row_ordinal: usize) -> Option<&[Goldilocks]> {
        self.encoded_matrix().row_slices().nth(row_ordinal)
    }

    pub(crate) fn take_source_message(&mut self) -> Result<Vec<Goldilocks>, CompactWhirError> {
        self.source_message
            .take()
            .ok_or(CompactWhirError::WrongProverPhase)
    }

    pub(crate) fn encoding_randomness(&self) -> &[Goldilocks] {
        &self.encoding_randomness
    }

    pub(crate) fn take_encoding_randomness(&mut self) -> Result<Vec<Goldilocks>, CompactWhirError> {
        if self.encoding_randomness.is_empty() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(core::mem::take(&mut self.encoding_randomness))
    }
}

impl Drop for CompactWhirEncodedInitialOracle {
    fn drop(&mut self) {
        if let Some(source_message) = self.source_message.as_mut() {
            source_message.fill(Goldilocks::ZERO);
        }
        self.encoding_randomness.fill(Goldilocks::ZERO);
    }
}

impl CompactWhirPreChallengeRelationPreparation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        base_source: Vec<Goldilocks>,
        equality_point: Vec<CompactChallengeField>,
        masked_pre_challenge_evaluation: CompactChallengeField,
        masked_main_evaluation: CompactChallengeField,
        mask_difference: CompactChallengeField,
        pre_challenge_mask: CompactChallengeField,
        main_mask: CompactChallengeField,
        opening_batching_challenge: CompactChallengeField,
    ) -> Result<Self, CompactWhirError> {
        if base_source.is_empty()
            || !base_source.len().is_power_of_two()
            || equality_point.len() != base_source.len().ilog2() as usize
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        let mut source_evaluations = Vec::new();
        source_evaluations
            .try_reserve_exact(base_source.len())
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        let mut source_covector = allocate_zero_extension_values(base_source.len())?;
        source_covector[0] = CompactChallengeField::ONE;
        Ok(Self {
            base_source: Some(base_source),
            source_evaluations,
            equality_point,
            source_covector,
            next_source_element: 0,
            completed_equality_coordinate_count: 0,
            next_equality_parent_ordinal: 0,
            next_relation_element: 0,
            accumulated_source_claim: CompactChallengeField::ZERO,
            masked_pre_challenge_evaluation,
            masked_main_evaluation,
            mask_difference,
            pre_challenge_mask,
            main_mask,
            opening_batching_challenge,
            phase: CompactWhirPreChallengeRelationPreparationPhase::ConvertSource,
        })
    }

    pub(crate) fn poll(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirPreChallengeRelationPreparationPoll, CompactWhirError> {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirError::InvalidWorkBudget);
        }
        match self.phase {
            CompactWhirPreChallengeRelationPreparationPhase::ConvertSource => {
                let base_source = self
                    .base_source
                    .as_ref()
                    .ok_or(CompactWhirError::WrongProverPhase)?;
                let end = self
                    .next_source_element
                    .saturating_add(maximum_work_unit_count)
                    .min(base_source.len());
                self.source_evaluations.extend(
                    base_source[self.next_source_element..end]
                        .iter()
                        .copied()
                        .map(CompactChallengeField::from),
                );
                let processed_work_unit_count = u64::try_from(end - self.next_source_element)
                    .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_source_element = end;
                if end == base_source.len() {
                    let mut base_source = self
                        .base_source
                        .take()
                        .ok_or(CompactWhirError::WrongProverPhase)?;
                    base_source.fill(Goldilocks::ZERO);
                    self.phase =
                        CompactWhirPreChallengeRelationPreparationPhase::BuildEqualityCovector;
                }
                Ok(
                    CompactWhirPreChallengeRelationPreparationPoll::StepCompleted {
                        step: CompactWhirPreChallengeRelationPreparationStep::ConvertSource,
                        processed_work_unit_count,
                    },
                )
            }
            CompactWhirPreChallengeRelationPreparationPhase::BuildEqualityCovector => {
                let coordinate_count = self.equality_point.len();
                if self.completed_equality_coordinate_count >= coordinate_count {
                    return Err(CompactWhirError::WrongProverPhase);
                }
                let parent_count = 1_usize
                    .checked_shl(
                        u32::try_from(self.completed_equality_coordinate_count)
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    )
                    .ok_or(CompactWhirError::CountOverflow)?;
                let end = self
                    .next_equality_parent_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(parent_count);
                let coordinate = self.equality_point
                    [coordinate_count - 1 - self.completed_equality_coordinate_count];
                for parent_ordinal in self.next_equality_parent_ordinal..end {
                    let parent = self.source_covector[parent_ordinal];
                    let high = parent * coordinate;
                    self.source_covector[parent_ordinal] = parent - high;
                    self.source_covector[parent_count + parent_ordinal] = high;
                }
                let processed_work_unit_count =
                    u64::try_from(end - self.next_equality_parent_ordinal)
                        .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_equality_parent_ordinal = end;
                if end == parent_count {
                    self.completed_equality_coordinate_count += 1;
                    self.next_equality_parent_ordinal = 0;
                    if self.completed_equality_coordinate_count == coordinate_count {
                        self.phase =
                            CompactWhirPreChallengeRelationPreparationPhase::VerifyRelation;
                    }
                }
                Ok(
                    CompactWhirPreChallengeRelationPreparationPoll::StepCompleted {
                        step: CompactWhirPreChallengeRelationPreparationStep::BuildEqualityCovector,
                        processed_work_unit_count,
                    },
                )
            }
            CompactWhirPreChallengeRelationPreparationPhase::VerifyRelation => {
                if self.source_evaluations.len() != self.source_covector.len() {
                    return Err(CompactWhirError::InvalidRelation);
                }
                let end = self
                    .next_relation_element
                    .saturating_add(maximum_work_unit_count)
                    .min(self.source_evaluations.len());
                for element_ordinal in self.next_relation_element..end {
                    self.accumulated_source_claim += self.source_evaluations[element_ordinal]
                        * self.source_covector[element_ordinal];
                }
                let processed_work_unit_count = u64::try_from(end - self.next_relation_element)
                    .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_relation_element = end;
                if end == self.source_evaluations.len() {
                    if self.masked_pre_challenge_evaluation
                        - self.masked_main_evaluation
                        - self.mask_difference
                        != CompactChallengeField::ZERO
                        || self.pre_challenge_mask - self.main_mask != self.mask_difference
                        || self.accumulated_source_claim + self.pre_challenge_mask
                            != self.masked_pre_challenge_evaluation
                        || self.accumulated_source_claim + self.main_mask
                            != self.masked_main_evaluation
                    {
                        return Err(CompactWhirError::InvalidRelation);
                    }
                    self.phase = CompactWhirPreChallengeRelationPreparationPhase::Complete;
                }
                Ok(
                    CompactWhirPreChallengeRelationPreparationPoll::StepCompleted {
                        step: CompactWhirPreChallengeRelationPreparationStep::VerifyRelation,
                        processed_work_unit_count,
                    },
                )
            }
            CompactWhirPreChallengeRelationPreparationPhase::Complete => {
                Ok(CompactWhirPreChallengeRelationPreparationPoll::Complete)
            }
        }
    }

    pub(crate) fn finish(mut self) -> Result<CompactWhirPreChallengeRelation, CompactWhirError> {
        if self.phase != CompactWhirPreChallengeRelationPreparationPhase::Complete
            || self.source_evaluations.len() != self.source_covector.len()
        {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(CompactWhirPreChallengeRelation {
            source_evaluations: core::mem::take(&mut self.source_evaluations),
            source_covector: core::mem::take(&mut self.source_covector),
            source_claim: self.accumulated_source_claim,
            masked_target: self.masked_pre_challenge_evaluation,
            pre_challenge_mask: self.pre_challenge_mask,
            opening_batching_challenge: self.opening_batching_challenge,
        })
    }
}

impl Drop for CompactWhirPreChallengeRelationPreparation {
    fn drop(&mut self) {
        if let Some(base_source) = self.base_source.as_mut() {
            base_source.fill(Goldilocks::ZERO);
        }
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.accumulated_source_claim = CompactChallengeField::ZERO;
        self.pre_challenge_mask = CompactChallengeField::ZERO;
        self.main_mask = CompactChallengeField::ZERO;
    }
}

impl Drop for CompactWhirPreChallengeRelation {
    fn drop(&mut self) {
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.source_claim = CompactChallengeField::ZERO;
        self.pre_challenge_mask = CompactChallengeField::ZERO;
    }
}

impl CompactWhirInitialSumcheckState {
    pub(crate) fn new<R: Rng>(
        mut relation: CompactWhirPreChallengeRelation,
        configuration: &CompactWhirConfiguration,
        mask_group_contract: CompactWhirMaskGroupContract,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let folding_factor = configuration.round_folding_factor(0);
        let mask_group_shape = compact_whir_mask_group_shape(mask_group_contract)?;
        if relation.source_evaluations.len() != relation.source_covector.len()
            || relation.source_evaluations.is_empty()
            || !relation.source_evaluations.len().is_power_of_two()
            || relation.source_evaluations.len().ilog2() as usize != configuration.num_variables
            || folding_factor == 0
            || folding_factor > configuration.num_variables
            || mask_group_shape.width != folding_factor
            || mask_group_shape.shape.message_len != COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        if relation.source_claim + relation.pre_challenge_mask != relation.masked_target {
            return Err(CompactWhirError::InvalidRelation);
        }

        let mut sumcheck_mask_messages = Vec::new();
        sumcheck_mask_messages
            .try_reserve_exact(folding_factor)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        for _round_ordinal in 0..folding_factor {
            let mut message = Vec::new();
            message
                .try_reserve_exact(mask_group_shape.shape.message_len)
                .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
            for _coefficient_ordinal in 0..mask_group_shape.shape.message_len {
                message.push(random_source.random());
            }
            sumcheck_mask_messages.push(message);
        }

        let mut sumcheck_mask_encoding_randomness = Vec::new();
        sumcheck_mask_encoding_randomness
            .try_reserve_exact(folding_factor)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        for _round_ordinal in 0..folding_factor {
            let mut randomness = Vec::new();
            randomness
                .try_reserve_exact(mask_group_shape.shape.randomness_len)
                .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
            for _randomness_ordinal in 0..mask_group_shape.shape.randomness_len {
                randomness.push(random_source.random());
            }
            sumcheck_mask_encoding_randomness.push(randomness);
        }
        let sumcheck_mask_oracle = CompactWhirEncodedMaskGroup::encode(
            mask_group_shape,
            &sumcheck_mask_messages,
            &sumcheck_mask_encoding_randomness,
        )?;
        let remaining_mask_endpoint_sum = sumcheck_mask_messages
            .iter()
            .map(|message| mask_endpoint_sum(message))
            .sum::<CompactChallengeField>();
        let auxiliary_target = CompactChallengeField::TWO.exp_u64(
            u64::try_from(folding_factor - 1).map_err(|_| CompactWhirError::CountOverflow)?,
        ) * remaining_mask_endpoint_sum;

        Ok(Self {
            source_evaluations: core::mem::take(&mut relation.source_evaluations),
            source_covector: core::mem::take(&mut relation.source_covector),
            source_claim: relation.source_claim,
            masked_target: relation.masked_target,
            opening_batching_challenge: relation.opening_batching_challenge,
            sumcheck_mask_messages,
            sumcheck_mask_encoding_randomness,
            sumcheck_mask_oracle,
            auxiliary_target,
            remaining_mask_endpoint_sum,
            preceding_mask_carry: relation.pre_challenge_mask,
            combination_challenge: None,
            round_challenges: Vec::new(),
            past_mask_evaluations: Vec::new(),
            pending_round_wire: None,
            round_wires: Vec::new(),
            phase: CompactWhirInitialSumcheckPhase::AwaitingCombinationChallenge,
        })
    }

    pub(crate) const fn auxiliary_target(&self) -> CompactChallengeField {
        self.auxiliary_target
    }

    pub(crate) const fn mask_oracle(&self) -> &CompactWhirEncodedMaskGroup {
        &self.sumcheck_mask_oracle
    }

    pub(crate) const fn opening_batching_challenge(&self) -> CompactChallengeField {
        self.opening_batching_challenge
    }

    pub(crate) const fn masked_target(&self) -> CompactChallengeField {
        self.masked_target
    }

    pub(crate) fn bind_combination_challenge(
        &mut self,
        challenge: CompactChallengeField,
    ) -> Result<(), CompactWhirError> {
        if self.phase != CompactWhirInitialSumcheckPhase::AwaitingCombinationChallenge
            || self.combination_challenge.is_some()
        {
            return Err(CompactWhirError::WrongProverPhase);
        }
        self.combination_challenge = Some(challenge);
        self.begin_round_polynomial()
    }

    pub(crate) fn poll(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirInitialSumcheckPoll, CompactWhirError> {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirError::InvalidWorkBudget);
        }
        match self.phase {
            CompactWhirInitialSumcheckPhase::ComputingRoundPolynomial {
                next_pair_ordinal,
                mut constant_coefficient,
                mut leading_coefficient,
            } => {
                let half = self
                    .source_evaluations
                    .len()
                    .checked_div(2)
                    .filter(|count| *count != 0)
                    .ok_or(CompactWhirError::InvalidRelation)?;
                let end = next_pair_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(half);
                for pair_ordinal in next_pair_ordinal..end {
                    let evaluation_low = self.source_evaluations[pair_ordinal];
                    let evaluation_high = self.source_evaluations[half + pair_ordinal];
                    let weight_low = self.source_covector[pair_ordinal];
                    let weight_high = self.source_covector[half + pair_ordinal];
                    constant_coefficient += evaluation_low * weight_low;
                    leading_coefficient +=
                        (evaluation_high - evaluation_low) * (weight_high - weight_low);
                }
                let polynomial_ready = end == half;
                if polynomial_ready {
                    let wire =
                        self.assemble_round_wire(constant_coefficient, leading_coefficient)?;
                    self.round_wires.push(wire.clone());
                    self.pending_round_wire = Some(wire);
                    self.phase = CompactWhirInitialSumcheckPhase::RoundPolynomialReady {
                        constant_coefficient,
                        leading_coefficient,
                    };
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::ComputingRoundPolynomial {
                        next_pair_ordinal: end,
                        constant_coefficient,
                        leading_coefficient,
                    };
                }
                Ok(
                    CompactWhirInitialSumcheckPoll::RoundPolynomialStepCompleted {
                        round_ordinal: self.current_round_ordinal()?,
                        processed_work_unit_count: u64::try_from(end - next_pair_ordinal)
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                        polynomial_ready,
                    },
                )
            }
            CompactWhirInitialSumcheckPhase::FoldingRound {
                challenge,
                next_pair_ordinal,
                constant_coefficient,
                leading_coefficient,
            } => {
                let half = self
                    .source_evaluations
                    .len()
                    .checked_div(2)
                    .filter(|count| *count != 0)
                    .ok_or(CompactWhirError::InvalidRelation)?;
                let end = next_pair_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(half);
                for pair_ordinal in next_pair_ordinal..end {
                    let evaluation_low = self.source_evaluations[pair_ordinal];
                    let evaluation_high = self.source_evaluations[half + pair_ordinal];
                    self.source_evaluations[pair_ordinal] =
                        evaluation_low + challenge * (evaluation_high - evaluation_low);
                    let weight_low = self.source_covector[pair_ordinal];
                    let weight_high = self.source_covector[half + pair_ordinal];
                    self.source_covector[pair_ordinal] =
                        weight_low + challenge * (weight_high - weight_low);
                }
                let round_complete = end == half;
                if round_complete {
                    self.source_evaluations.truncate(half);
                    self.source_covector.truncate(half);
                    self.source_claim = extrapolate_quadratic_from_boolean_sum(
                        constant_coefficient,
                        self.source_claim,
                        leading_coefficient,
                        challenge,
                    );
                    if self.round_challenges.len() == self.sumcheck_mask_messages.len() {
                        self.phase = CompactWhirInitialSumcheckPhase::ScalingWeights {
                            next_element_ordinal: 0,
                        };
                    } else {
                        self.begin_round_polynomial()?;
                    }
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::FoldingRound {
                        challenge,
                        next_pair_ordinal: end,
                        constant_coefficient,
                        leading_coefficient,
                    };
                }
                Ok(CompactWhirInitialSumcheckPoll::BoundRoundStepCompleted {
                    round_ordinal: u32::try_from(
                        self.round_challenges
                            .len()
                            .checked_sub(1)
                            .ok_or(CompactWhirError::WrongProverPhase)?,
                    )
                    .map_err(|_| CompactWhirError::CountOverflow)?,
                    processed_work_unit_count: u64::try_from(end - next_pair_ordinal)
                        .map_err(|_| CompactWhirError::CountOverflow)?,
                    round_complete,
                })
            }
            CompactWhirInitialSumcheckPhase::ScalingWeights {
                next_element_ordinal,
            } => {
                let combination_challenge = self
                    .combination_challenge
                    .ok_or(CompactWhirError::WrongProverPhase)?;
                let end = next_element_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(self.source_covector.len());
                for weight in &mut self.source_covector[next_element_ordinal..end] {
                    *weight *= combination_challenge;
                }
                let scaling_complete = end == self.source_covector.len();
                if scaling_complete {
                    self.source_claim *= combination_challenge;
                    self.phase = CompactWhirInitialSumcheckPhase::Complete;
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::ScalingWeights {
                        next_element_ordinal: end,
                    };
                }
                Ok(CompactWhirInitialSumcheckPoll::WeightScalingStepCompleted {
                    processed_work_unit_count: u64::try_from(end - next_element_ordinal)
                        .map_err(|_| CompactWhirError::CountOverflow)?,
                    scaling_complete,
                })
            }
            CompactWhirInitialSumcheckPhase::AwaitingCombinationChallenge
            | CompactWhirInitialSumcheckPhase::RoundPolynomialReady { .. }
            | CompactWhirInitialSumcheckPhase::Complete => Err(CompactWhirError::WrongProverPhase),
        }
    }

    pub(crate) fn pending_round_wire(&self) -> Result<&[CompactChallengeField], CompactWhirError> {
        if !matches!(
            self.phase,
            CompactWhirInitialSumcheckPhase::RoundPolynomialReady { .. }
        ) {
            return Err(CompactWhirError::WrongProverPhase);
        }
        self.pending_round_wire
            .as_deref()
            .ok_or(CompactWhirError::WrongProverPhase)
    }

    pub(crate) fn round_wire(&self, round_ordinal: usize) -> Option<&[CompactChallengeField]> {
        self.round_wires.get(round_ordinal).map(Vec::as_slice)
    }

    pub(crate) fn bind_round_challenge(
        &mut self,
        challenge: CompactChallengeField,
    ) -> Result<(), CompactWhirError> {
        let CompactWhirInitialSumcheckPhase::RoundPolynomialReady {
            constant_coefficient,
            leading_coefficient,
        } = self.phase
        else {
            return Err(CompactWhirError::WrongProverPhase);
        };
        let round_index = self.round_challenges.len();
        let mask = self
            .sumcheck_mask_messages
            .get(round_index)
            .ok_or(CompactWhirError::WrongProverPhase)?;
        self.past_mask_evaluations
            .push(evaluate_univariate(mask, challenge));
        self.round_challenges.push(challenge);
        self.pending_round_wire = None;
        self.phase = CompactWhirInitialSumcheckPhase::FoldingRound {
            challenge,
            next_pair_ordinal: 0,
            constant_coefficient,
            leading_coefficient,
        };
        Ok(())
    }

    pub(crate) const fn is_complete(&self) -> bool {
        matches!(self.phase, CompactWhirInitialSumcheckPhase::Complete)
    }

    pub(crate) fn residual_source(&self) -> Result<&[CompactChallengeField], CompactWhirError> {
        if !self.is_complete() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(&self.source_evaluations)
    }

    pub(crate) fn take_residual_source(
        &mut self,
    ) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
        if !self.is_complete() || self.source_evaluations.is_empty() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(core::mem::take(&mut self.source_evaluations))
    }

    pub(crate) fn residual_covector(&self) -> Result<&[CompactChallengeField], CompactWhirError> {
        if !self.is_complete() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(&self.source_covector)
    }

    pub(crate) fn residual_source_claim(&self) -> Result<CompactChallengeField, CompactWhirError> {
        if !self.is_complete() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(self.source_claim)
    }

    pub(crate) fn residual_preceding_mask_claim(
        &self,
    ) -> Result<CompactChallengeField, CompactWhirError> {
        if !self.is_complete() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let combination_challenge = self
            .combination_challenge
            .ok_or(CompactWhirError::WrongProverPhase)?;
        Ok(combination_challenge * self.preceding_mask_carry)
    }

    pub(crate) fn round_challenges(&self) -> &[CompactChallengeField] {
        &self.round_challenges
    }

    pub(crate) fn mask_messages(&self) -> &[Vec<CompactChallengeField>] {
        &self.sumcheck_mask_messages
    }

    pub(crate) fn mask_encoding_randomness(&self) -> &[Vec<CompactChallengeField>] {
        &self.sumcheck_mask_encoding_randomness
    }

    fn begin_round_polynomial(&mut self) -> Result<(), CompactWhirError> {
        let round_index = self.round_challenges.len();
        let mask = self
            .sumcheck_mask_messages
            .get(round_index)
            .ok_or(CompactWhirError::WrongProverPhase)?;
        self.remaining_mask_endpoint_sum -= mask_endpoint_sum(mask);
        self.preceding_mask_carry *= CompactChallengeField::TWO.inverse();
        self.phase = CompactWhirInitialSumcheckPhase::ComputingRoundPolynomial {
            next_pair_ordinal: 0,
            constant_coefficient: CompactChallengeField::ZERO,
            leading_coefficient: CompactChallengeField::ZERO,
        };
        Ok(())
    }

    fn assemble_round_wire(
        &self,
        plain_constant_coefficient: CompactChallengeField,
        plain_leading_coefficient: CompactChallengeField,
    ) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
        let round_index = self.round_challenges.len();
        let round_number = round_index
            .checked_add(1)
            .ok_or(CompactWhirError::CountOverflow)?;
        let mask = self
            .sumcheck_mask_messages
            .get(round_index)
            .ok_or(CompactWhirError::WrongProverPhase)?;
        let combination_challenge = self
            .combination_challenge
            .ok_or(CompactWhirError::WrongProverPhase)?;
        let folding_factor = self.sumcheck_mask_messages.len();
        let live_multiplier = CompactChallengeField::TWO.exp_u64(
            u64::try_from(folding_factor - round_number)
                .map_err(|_| CompactWhirError::CountOverflow)?,
        );
        let mut full_coefficients =
            allocate_zero_extension_values(COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH.max(3))?;
        for (coefficient, mask_coefficient) in full_coefficients.iter_mut().zip(mask) {
            *coefficient += live_multiplier * *mask_coefficient;
        }
        full_coefficients[0] += self
            .past_mask_evaluations
            .iter()
            .copied()
            .sum::<CompactChallengeField>()
            * live_multiplier;
        if round_number < folding_factor {
            let future_multiplier = CompactChallengeField::TWO.exp_u64(
                u64::try_from(folding_factor - round_number - 1)
                    .map_err(|_| CompactWhirError::CountOverflow)?,
            );
            full_coefficients[0] += future_multiplier * self.remaining_mask_endpoint_sum;
        }
        full_coefficients[0] +=
            combination_challenge * (plain_constant_coefficient + self.preceding_mask_carry);
        full_coefficients[2] += combination_challenge * plain_leading_coefficient;

        let mut wire = Vec::new();
        wire.try_reserve_exact(full_coefficients.len() - 1)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        wire.push(full_coefficients[0]);
        wire.extend_from_slice(&full_coefficients[2..]);
        Ok(wire)
    }

    fn current_round_ordinal(&self) -> Result<u32, CompactWhirError> {
        u32::try_from(self.round_challenges.len()).map_err(|_| CompactWhirError::CountOverflow)
    }
}

impl Drop for CompactWhirInitialSumcheckState {
    fn drop(&mut self) {
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.source_claim = CompactChallengeField::ZERO;
        for mask_message in &mut self.sumcheck_mask_messages {
            mask_message.fill(CompactChallengeField::ZERO);
        }
        for randomness in &mut self.sumcheck_mask_encoding_randomness {
            randomness.fill(CompactChallengeField::ZERO);
        }
        self.remaining_mask_endpoint_sum = CompactChallengeField::ZERO;
        self.preceding_mask_carry = CompactChallengeField::ZERO;
        self.past_mask_evaluations.fill(CompactChallengeField::ZERO);
    }
}

impl CompactWhirCodeSwitchState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new<R: Rng>(
        source_evaluations: Vec<CompactChallengeField>,
        previous_encoding_randomness: Vec<Goldilocks>,
        folding_challenges: &[CompactChallengeField],
        previous_source_contract: CompactWhirFoldContract,
        next_source_contract: CompactWhirFoldContract,
        switch_mask_contract: CompactWhirMaskGroupContract,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let folding_width = 1_usize
            .checked_shl(
                u32::try_from(folding_challenges.len())
                    .map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .ok_or(CompactWhirError::CountOverflow)?;
        let previous_message_length = usize::try_from(previous_source_contract.message_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let previous_randomness_length =
            usize::try_from(previous_source_contract.hiding_randomness_length)
                .map_err(|_| CompactWhirError::CountOverflow)?;
        let previous_oracle_width = usize::try_from(previous_source_contract.oracle_width)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let previous_source_height = usize::try_from(previous_source_contract.block_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let expected_query_count = usize::try_from(previous_source_contract.query_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let next_source_element_count = usize::try_from(next_source_contract.message_length)
            .map_err(|_| CompactWhirError::CountOverflow)?
            .checked_mul(
                usize::try_from(next_source_contract.oracle_width)
                    .map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .ok_or(CompactWhirError::CountOverflow)?;
        let switch_mask_shape = compact_whir_mask_group_shape(switch_mask_contract)?;
        if source_evaluations.is_empty()
            || source_evaluations.len() != previous_message_length
            || source_evaluations.len() != next_source_element_count
            || previous_oracle_width != folding_width
            || previous_encoding_randomness.len()
                != previous_randomness_length
                    .checked_mul(folding_width)
                    .ok_or(CompactWhirError::CountOverflow)?
            || switch_mask_shape.width != 1
            || switch_mask_shape.shape.message_len != previous_randomness_length
            || expected_query_count != previous_randomness_length
        {
            return Err(CompactWhirError::InvalidConfiguration);
        }

        let source_oracle =
            CompactWhirRecomputableExtensionInitialOracle::sample_for_fold_contract(
                next_source_contract,
                random_source,
            )?;
        if source_oracle.source_element_count() != source_evaluations.len() {
            return Err(CompactWhirError::InvalidConfiguration);
        }
        let mut switch_mask_encoding_randomness = Vec::new();
        switch_mask_encoding_randomness
            .try_reserve_exact(switch_mask_shape.shape.randomness_len)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        for _randomness_ordinal in 0..switch_mask_shape.shape.randomness_len {
            switch_mask_encoding_randomness.push(random_source.random());
        }
        let folding_weights =
            Poly::new_from_point(folding_challenges, CompactChallengeField::ONE).into_evals();
        if folding_weights.len() != folding_width {
            return Err(CompactWhirError::InvalidConfiguration);
        }

        Ok(Self {
            source_evaluations,
            source_oracle,
            previous_encoding_randomness,
            folding_weights,
            folded_previous_randomness: allocate_zero_extension_values(previous_randomness_length)?,
            next_randomness_element_ordinal: 0,
            switch_mask_encoding_randomness,
            switch_mask_oracle: None,
            switch_mask_shape,
            previous_source_height,
            expected_query_count,
            query_positions: None,
            combination_challenge: None,
            phase: CompactWhirCodeSwitchPhase::FoldingPreviousRandomness,
        })
    }

    pub(crate) fn poll_preparation(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirCodeSwitchPreparationPoll, CompactWhirError> {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirError::InvalidWorkBudget);
        }
        match self.phase {
            CompactWhirCodeSwitchPhase::FoldingPreviousRandomness => {
                let end = self
                    .next_randomness_element_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(self.previous_encoding_randomness.len());
                let chunk_length = self.folded_previous_randomness.len();
                if chunk_length == 0 {
                    return Err(CompactWhirError::InvalidConfiguration);
                }
                for element_ordinal in self.next_randomness_element_ordinal..end {
                    let limb_ordinal = element_ordinal / chunk_length;
                    let coordinate_ordinal = element_ordinal % chunk_length;
                    let weight = *self
                        .folding_weights
                        .get(limb_ordinal)
                        .ok_or(CompactWhirError::InvalidConfiguration)?;
                    self.folded_previous_randomness[coordinate_ordinal] += weight
                        * CompactChallengeField::from(
                            self.previous_encoding_randomness[element_ordinal],
                        );
                }
                let processed_work_unit_count =
                    u64::try_from(end - self.next_randomness_element_ordinal)
                        .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_randomness_element_ordinal = end;
                let fold_complete = end == self.previous_encoding_randomness.len();
                if fold_complete {
                    self.previous_encoding_randomness.fill(Goldilocks::ZERO);
                    self.previous_encoding_randomness.clear();
                    self.folding_weights.fill(CompactChallengeField::ZERO);
                    self.folding_weights.clear();
                    self.switch_mask_oracle = Some(CompactWhirEncodedMaskGroup::encode(
                        self.switch_mask_shape.clone(),
                        core::slice::from_ref(&self.folded_previous_randomness),
                        core::slice::from_ref(&self.switch_mask_encoding_randomness),
                    )?);
                    self.phase = CompactWhirCodeSwitchPhase::Ready;
                }
                Ok(
                    CompactWhirCodeSwitchPreparationPoll::RandomnessFoldStepCompleted {
                        processed_work_unit_count,
                        fold_complete,
                    },
                )
            }
            CompactWhirCodeSwitchPhase::Ready => Ok(CompactWhirCodeSwitchPreparationPoll::Complete),
        }
    }

    pub(crate) const fn source_oracle(&self) -> &CompactWhirRecomputableExtensionInitialOracle {
        &self.source_oracle
    }

    pub(crate) fn poll_source_oracle(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirRecomputableExtensionPoll, CompactWhirError> {
        let source_evaluations = &self.source_evaluations;
        self.source_oracle
            .poll(maximum_work_unit_count, |source_ordinal| {
                source_evaluations
                    .get(
                        usize::try_from(source_ordinal)
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    )
                    .copied()
                    .ok_or(CompactWhirError::InvalidMessage)
            })
            .map_err(|error| match error {
                CompactWhirRecomputableExtensionError::Whir(error)
                | CompactWhirRecomputableExtensionError::Source(error) => error,
            })
    }

    pub(crate) fn source_row(
        &self,
        row_ordinal: usize,
    ) -> Result<&[CompactChallengeField], CompactWhirError> {
        self.source_oracle.response_row(row_ordinal)
    }

    pub(crate) fn mark_source_row_supplied(
        &mut self,
        row_ordinal: usize,
    ) -> Result<(), CompactWhirError> {
        self.source_oracle.mark_response_row_supplied(row_ordinal)
    }

    pub(crate) fn switch_mask_oracle(
        &self,
    ) -> Result<&CompactWhirEncodedMaskGroup, CompactWhirError> {
        if self.phase != CompactWhirCodeSwitchPhase::Ready {
            return Err(CompactWhirError::WrongProverPhase);
        }
        self.switch_mask_oracle
            .as_ref()
            .ok_or(CompactWhirError::WrongProverPhase)
    }

    pub(crate) fn folded_previous_randomness(
        &self,
    ) -> Result<&[CompactChallengeField], CompactWhirError> {
        if self.phase != CompactWhirCodeSwitchPhase::Ready {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(&self.folded_previous_randomness)
    }

    pub(crate) fn switch_mask_encoding_randomness(&self) -> &[CompactChallengeField] {
        &self.switch_mask_encoding_randomness
    }

    pub(crate) fn bind_verifier_move(
        &mut self,
        query_positions: &[u64],
        combination_challenge: CompactChallengeField,
    ) -> Result<(), CompactWhirError> {
        if self.phase != CompactWhirCodeSwitchPhase::Ready
            || self.query_positions.is_some()
            || self.combination_challenge.is_some()
            || query_positions.len() != self.expected_query_count
            || query_positions.windows(2).any(|pair| pair[0] >= pair[1])
            || query_positions.last().is_none_or(|position| {
                usize::try_from(*position)
                    .map_or(true, |position| position >= self.previous_source_height)
            })
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(query_positions.len())
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        for position in query_positions {
            positions
                .push(usize::try_from(*position).map_err(|_| CompactWhirError::CountOverflow)?);
        }
        self.query_positions = Some(positions);
        self.combination_challenge = Some(combination_challenge);
        Ok(())
    }

    pub(crate) fn verifier_move_is_bound(&self) -> bool {
        self.query_positions.is_some() && self.combination_challenge.is_some()
    }
}

impl Drop for CompactWhirCodeSwitchState {
    fn drop(&mut self) {
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.previous_encoding_randomness.fill(Goldilocks::ZERO);
        self.folding_weights.fill(CompactChallengeField::ZERO);
        self.folded_previous_randomness
            .fill(CompactChallengeField::ZERO);
        self.switch_mask_encoding_randomness
            .fill(CompactChallengeField::ZERO);
    }
}

fn mask_endpoint_sum(message: &[CompactChallengeField]) -> CompactChallengeField {
    message[0].double() + message[1..].iter().copied().sum::<CompactChallengeField>()
}

fn evaluate_univariate(
    coefficients: &[CompactChallengeField],
    point: CompactChallengeField,
) -> CompactChallengeField {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(CompactChallengeField::ZERO, |evaluation, coefficient| {
            evaluation * point + coefficient
        })
}

fn extrapolate_quadratic_from_boolean_sum(
    constant_coefficient: CompactChallengeField,
    boolean_sum: CompactChallengeField,
    leading_coefficient: CompactChallengeField,
    point: CompactChallengeField,
) -> CompactChallengeField {
    constant_coefficient
        + (boolean_sum - constant_coefficient.double()) * point
        + leading_coefficient * point * (point - CompactChallengeField::ONE)
}

#[cfg(test)]
impl CompactWhirEncodedExtensionInitialOracle {
    pub(crate) fn encode<R: Rng>(
        configuration: &CompactWhirConfiguration,
        message: Vec<CompactChallengeField>,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let expected_message_length = 1_usize
            .checked_shl(
                u32::try_from(configuration.num_variables)
                    .map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .ok_or(CompactWhirError::CountOverflow)?;
        if message.len() != expected_message_length {
            return Err(CompactWhirError::InvalidMessage);
        }
        let commitment_scheme = compact_whir_commitment_scheme();
        let transform = Radix2DFTSmallBatch::<Goldilocks>::default();
        let prover = HidingWhirProver::new(configuration, &transform, &commitment_scheme);
        let encoded = Self {
            encoded_oracle: prover
                .encode_extension_initial_oracle(Poly::new(message), random_source),
        };
        let (expected_width, expected_height) = initial_oracle_dimensions(configuration)?;
        let matrix = encoded.encoded_matrix();
        if matrix.width() != expected_width || matrix.height() != expected_height {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        Ok(encoded)
    }

    pub(crate) const fn encoded_matrix(&self) -> &DenseMatrix<CompactChallengeField> {
        &self.encoded_oracle.encoded
    }

    pub(crate) fn encoded_row(&self, row_ordinal: usize) -> Option<&[CompactChallengeField]> {
        self.encoded_matrix().row_slices().nth(row_ordinal)
    }
}

impl CompactWhirRecomputableExtensionInitialOracle {
    pub(crate) fn sample<R: Rng>(
        configuration: &CompactWhirConfiguration,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let (_, encoded_height) = initial_oracle_dimensions(configuration)?;
        Self::sample_with_maximum_stripe_row_count(
            configuration,
            random_source,
            COMPACT_WHIR_EXTENSION_RESPONSE_STRIPE_ROW_COUNT.min(encoded_height),
        )
    }

    pub(crate) fn sample_for_fold_contract<R: Rng>(
        contract: CompactWhirFoldContract,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let source_height = usize::try_from(contract.message_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let encoded_height =
            usize::try_from(contract.block_length).map_err(|_| CompactWhirError::CountOverflow)?;
        let width =
            usize::try_from(contract.oracle_width).map_err(|_| CompactWhirError::CountOverflow)?;
        let randomness_rows = usize::try_from(contract.hiding_randomness_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        Self::sample_with_dimensions(
            source_height,
            encoded_height,
            width,
            randomness_rows,
            random_source,
            COMPACT_WHIR_EXTENSION_RESPONSE_STRIPE_ROW_COUNT.min(encoded_height),
        )
    }

    fn sample_with_maximum_stripe_row_count<R: Rng>(
        configuration: &CompactWhirConfiguration,
        random_source: &mut R,
        maximum_stripe_row_count: usize,
    ) -> Result<Self, CompactWhirError> {
        let source_element_count = 1_usize
            .checked_shl(
                u32::try_from(configuration.num_variables)
                    .map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .ok_or(CompactWhirError::CountOverflow)?;
        let folding_factor = configuration.round_folding_factor(0);
        let (width, encoded_height) = initial_oracle_dimensions(configuration)?;
        let source_height = source_element_count
            .checked_div(width)
            .ok_or(CompactWhirError::InvalidConfiguration)?;
        let randomness_element_count = configuration
            .oracle_randomness
            .first()
            .copied()
            .ok_or(CompactWhirError::InvalidConfiguration)?
            .checked_shl(
                u32::try_from(folding_factor).map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .ok_or(CompactWhirError::CountOverflow)?;
        let randomness_rows = randomness_element_count
            .checked_div(width)
            .ok_or(CompactWhirError::InvalidConfiguration)?;
        Self::sample_with_dimensions(
            source_height,
            encoded_height,
            width,
            randomness_rows,
            random_source,
            maximum_stripe_row_count,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sample_with_dimensions<R: Rng>(
        source_height: usize,
        encoded_height: usize,
        width: usize,
        randomness_rows: usize,
        random_source: &mut R,
        maximum_stripe_row_count: usize,
    ) -> Result<Self, CompactWhirError> {
        let source_element_count = source_height
            .checked_mul(width)
            .ok_or(CompactWhirError::CountOverflow)?;
        let randomness_element_count = randomness_rows
            .checked_mul(width)
            .ok_or(CompactWhirError::CountOverflow)?;
        if maximum_stripe_row_count == 0
            || !maximum_stripe_row_count.is_power_of_two()
            || maximum_stripe_row_count > encoded_height
            || width == 0
            || !width.is_power_of_two()
            || source_height == 0
            || encoded_height == 0
            || !encoded_height.is_power_of_two()
            || source_height
                .checked_mul(width)
                .is_none_or(|count| count != source_element_count)
            || source_height
                .checked_add(randomness_rows)
                .is_none_or(|occupied_row_count| occupied_row_count > encoded_height)
            || randomness_rows
                .checked_mul(width)
                .is_none_or(|count| count != randomness_element_count)
        {
            return Err(CompactWhirError::InvalidConfiguration);
        }
        let mut randomness = Vec::new();
        randomness
            .try_reserve_exact(randomness_element_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        for _randomness_ordinal in 0..randomness_element_count {
            randomness.push(random_source.random());
        }
        Ok(Self {
            source_element_count,
            source_height,
            encoded_height,
            width,
            randomness_rows,
            randomness,
            maximum_stripe_row_count,
            stripe_first_row: 0,
            stripe_end_row: maximum_stripe_row_count.min(encoded_height),
            next_response_row: 0,
            stripe_values: Vec::new(),
            current_column_ordinal: 0,
            next_source_row: 0,
            active_transform: None,
            encoded_column_values: None,
            next_capture_row: 0,
            opening_row_ordinals: Vec::new(),
            next_opening_row_offset: 0,
            stage: CompactWhirRecomputableExtensionStage::PrepareStripe,
        })
    }

    pub(crate) const fn source_element_count(&self) -> usize {
        self.source_element_count
    }

    pub(crate) const fn encoded_height(&self) -> usize {
        self.encoded_height
    }

    pub(crate) const fn width(&self) -> usize {
        self.width
    }

    pub(crate) fn encoding_randomness(&self) -> &[CompactChallengeField] {
        &self.randomness
    }

    pub(crate) fn poll<SourceError>(
        &mut self,
        maximum_work_unit_count: u64,
        mut source_value: impl FnMut(u64) -> Result<CompactChallengeField, SourceError>,
    ) -> Result<
        CompactWhirRecomputableExtensionPoll,
        CompactWhirRecomputableExtensionError<SourceError>,
    > {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirError::InvalidConfiguration.into());
        }
        match self.stage {
            CompactWhirRecomputableExtensionStage::PrepareStripe => {
                if !self.stripe_values.is_empty()
                    || self.stripe_first_row >= self.stripe_end_row
                    || self.stripe_end_row > self.encoded_height
                    || self.current_column_ordinal != 0
                    || self.active_transform.is_some()
                    || self.encoded_column_values.is_some()
                {
                    return Err(CompactWhirError::InvalidEncodedMatrix.into());
                }
                let stripe_row_count = self.stripe_end_row - self.stripe_first_row;
                self.stripe_values = allocate_zero_extension_values(
                    stripe_row_count
                        .checked_mul(self.width)
                        .ok_or(CompactWhirError::CountOverflow)?,
                )?;
                if self.opening_row_ordinals.is_empty() {
                    self.next_response_row = self.stripe_first_row;
                } else if self
                    .opening_row_ordinals
                    .get(self.next_opening_row_offset)
                    .copied()
                    != Some(self.next_response_row)
                    || !(self.stripe_first_row..self.stripe_end_row)
                        .contains(&self.next_response_row)
                {
                    return Err(CompactWhirError::InvalidEncodedMatrix.into());
                }
                self.stage = CompactWhirRecomputableExtensionStage::PrepareColumn;
                Ok(
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count: 1,
                    },
                )
            }
            CompactWhirRecomputableExtensionStage::PrepareColumn => {
                if self.current_column_ordinal >= self.width
                    || self.active_transform.is_some()
                    || self.encoded_column_values.is_some()
                {
                    return Err(CompactWhirError::InvalidEncodedMatrix.into());
                }
                self.encoded_column_values =
                    Some(allocate_zero_extension_values(self.encoded_height)?);
                self.next_source_row = 0;
                self.stage = CompactWhirRecomputableExtensionStage::LoadSource;
                Ok(
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count: 1,
                    },
                )
            }
            CompactWhirRecomputableExtensionStage::LoadSource => {
                let end = self
                    .next_source_row
                    .saturating_add(maximum_work_unit_count)
                    .min(self.source_height);
                let source_first_ordinal = self
                    .current_column_ordinal
                    .checked_mul(self.source_height)
                    .ok_or(CompactWhirError::CountOverflow)?;
                let encoded_column_values = self
                    .encoded_column_values
                    .as_mut()
                    .ok_or(CompactWhirError::InvalidEncodedMatrix)?;
                for (source_row, encoded_value) in encoded_column_values
                    .iter_mut()
                    .enumerate()
                    .take(end)
                    .skip(self.next_source_row)
                {
                    let source_ordinal = source_first_ordinal
                        .checked_add(source_row)
                        .ok_or(CompactWhirError::CountOverflow)?;
                    *encoded_value = source_value(
                        u64::try_from(source_ordinal)
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    )
                    .map_err(CompactWhirRecomputableExtensionError::Source)?;
                }
                let processed_work_unit_count = u64::try_from(end - self.next_source_row)
                    .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_source_row = end;
                if end == self.source_height {
                    let randomness_start = self
                        .current_column_ordinal
                        .checked_mul(self.randomness_rows)
                        .ok_or(CompactWhirError::CountOverflow)?;
                    let randomness_end = randomness_start
                        .checked_add(self.randomness_rows)
                        .ok_or(CompactWhirError::CountOverflow)?;
                    let destination_end = self
                        .source_height
                        .checked_add(self.randomness_rows)
                        .ok_or(CompactWhirError::CountOverflow)?;
                    encoded_column_values[self.source_height..destination_end]
                        .copy_from_slice(&self.randomness[randomness_start..randomness_end]);
                    self.active_transform = Some(
                        BoundedRadix2Dft::new(
                            self.encoded_column_values
                                .take()
                                .ok_or(CompactWhirError::InvalidEncodedMatrix)?,
                        )
                        .map_err(|_| CompactWhirError::InvalidEncodedMatrix)?,
                    );
                    self.stage = CompactWhirRecomputableExtensionStage::Transform;
                }
                Ok(
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    },
                )
            }
            CompactWhirRecomputableExtensionStage::Transform => {
                let (complete, processed_work_unit_count) = self
                    .active_transform
                    .as_mut()
                    .ok_or(CompactWhirError::InvalidEncodedMatrix)?
                    .poll_with_maximum_work_unit_count(maximum_work_unit_count)
                    .map_err(|_| CompactWhirError::InvalidEncodedMatrix)?;
                if complete {
                    self.encoded_column_values = Some(
                        self.active_transform
                            .take()
                            .ok_or(CompactWhirError::InvalidEncodedMatrix)?
                            .into_values()
                            .map_err(|_| CompactWhirError::InvalidEncodedMatrix)?,
                    );
                    self.next_capture_row = self.stripe_first_row;
                    self.stage = CompactWhirRecomputableExtensionStage::CaptureStripe;
                }
                Ok(
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count: u64::try_from(processed_work_unit_count.max(1))
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    },
                )
            }
            CompactWhirRecomputableExtensionStage::CaptureStripe => {
                let end = self
                    .next_capture_row
                    .saturating_add(maximum_work_unit_count)
                    .min(self.stripe_end_row);
                let encoded_column_values = self
                    .encoded_column_values
                    .as_ref()
                    .ok_or(CompactWhirError::InvalidEncodedMatrix)?;
                for (encoded_row, encoded_value) in encoded_column_values
                    .iter()
                    .enumerate()
                    .take(end)
                    .skip(self.next_capture_row)
                {
                    let stripe_row = encoded_row - self.stripe_first_row;
                    let destination = stripe_row
                        .checked_mul(self.width)
                        .and_then(|offset| offset.checked_add(self.current_column_ordinal))
                        .ok_or(CompactWhirError::CountOverflow)?;
                    self.stripe_values[destination] = *encoded_value;
                }
                let processed_work_unit_count = u64::try_from(end - self.next_capture_row)
                    .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_capture_row = end;
                if end == self.stripe_end_row {
                    self.encoded_column_values
                        .as_mut()
                        .ok_or(CompactWhirError::InvalidEncodedMatrix)?
                        .fill(CompactChallengeField::ZERO);
                    self.encoded_column_values = None;
                    self.current_column_ordinal = self
                        .current_column_ordinal
                        .checked_add(1)
                        .ok_or(CompactWhirError::CountOverflow)?;
                    self.stage = if self.current_column_ordinal == self.width {
                        CompactWhirRecomputableExtensionStage::StripeReady
                    } else {
                        CompactWhirRecomputableExtensionStage::PrepareColumn
                    };
                }
                Ok(
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    },
                )
            }
            CompactWhirRecomputableExtensionStage::StripeReady => {
                Ok(CompactWhirRecomputableExtensionPoll::StripeReady {
                    first_row: u64::try_from(self.stripe_first_row)
                        .map_err(|_| CompactWhirError::CountOverflow)?,
                    row_count: u64::try_from(self.stripe_end_row - self.stripe_first_row)
                        .map_err(|_| CompactWhirError::CountOverflow)?,
                })
            }
            CompactWhirRecomputableExtensionStage::Complete
            | CompactWhirRecomputableExtensionStage::OpeningReplayComplete => {
                Err(CompactWhirError::InvalidEncodedMatrix.into())
            }
        }
    }

    pub(crate) fn response_row(
        &self,
        row_ordinal: usize,
    ) -> Result<&[CompactChallengeField], CompactWhirError> {
        if self.stage != CompactWhirRecomputableExtensionStage::StripeReady
            || row_ordinal != self.next_response_row
            || !(self.stripe_first_row..self.stripe_end_row).contains(&row_ordinal)
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        let first_value = (row_ordinal - self.stripe_first_row)
            .checked_mul(self.width)
            .ok_or(CompactWhirError::CountOverflow)?;
        let end_value = first_value
            .checked_add(self.width)
            .ok_or(CompactWhirError::CountOverflow)?;
        self.stripe_values
            .get(first_value..end_value)
            .ok_or(CompactWhirError::InvalidEncodedMatrix)
    }

    pub(crate) fn mark_response_row_supplied(
        &mut self,
        row_ordinal: usize,
    ) -> Result<(), CompactWhirError> {
        if self.stage != CompactWhirRecomputableExtensionStage::StripeReady
            || row_ordinal != self.next_response_row
            || row_ordinal >= self.stripe_end_row
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        self.next_response_row = self
            .next_response_row
            .checked_add(1)
            .ok_or(CompactWhirError::CountOverflow)?;
        if !self.opening_row_ordinals.is_empty() {
            self.next_opening_row_offset = self
                .next_opening_row_offset
                .checked_add(1)
                .ok_or(CompactWhirError::CountOverflow)?;
            let Some(next_opening_row) = self
                .opening_row_ordinals
                .get(self.next_opening_row_offset)
                .copied()
            else {
                self.clear_stripe_values();
                self.stage = CompactWhirRecomputableExtensionStage::OpeningReplayComplete;
                return Ok(());
            };
            if next_opening_row < self.stripe_end_row {
                self.next_response_row = next_opening_row;
                return Ok(());
            }
            self.clear_stripe_values();
            self.prepare_stripe_containing(next_opening_row)?;
            return Ok(());
        }
        if self.next_response_row == self.stripe_end_row {
            self.clear_stripe_values();
            self.stripe_first_row = self.stripe_end_row;
            if self.stripe_first_row == self.encoded_height {
                self.stage = CompactWhirRecomputableExtensionStage::Complete;
            } else {
                self.stripe_end_row = self
                    .stripe_first_row
                    .saturating_add(self.maximum_stripe_row_count)
                    .min(self.encoded_height);
                self.next_response_row = self.stripe_first_row;
                self.current_column_ordinal = 0;
                self.stage = CompactWhirRecomputableExtensionStage::PrepareStripe;
            }
        }
        Ok(())
    }

    /// Begins the sole delayed-opening replay after the sequential response has
    /// been committed. The rows come from the verifier-derived query schedule;
    /// they must be strictly increasing so each touched stripe is encoded once.
    pub(crate) fn begin_opening_replay(
        &mut self,
        row_ordinals: &[usize],
    ) -> Result<(), CompactWhirError> {
        if self.stage != CompactWhirRecomputableExtensionStage::Complete
            || row_ordinals.is_empty()
            || row_ordinals.windows(2).any(|pair| pair[0] >= pair[1])
            || row_ordinals
                .last()
                .is_none_or(|row_ordinal| *row_ordinal >= self.encoded_height)
            || !self.stripe_values.is_empty()
            || self.active_transform.is_some()
            || self.encoded_column_values.is_some()
            || !self.opening_row_ordinals.is_empty()
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        self.opening_row_ordinals
            .try_reserve_exact(row_ordinals.len())
            .map_err(|_| CompactWhirError::CountOverflow)?;
        self.opening_row_ordinals.extend_from_slice(row_ordinals);
        self.next_opening_row_offset = 0;
        self.prepare_stripe_containing(row_ordinals[0])
    }

    pub(crate) const fn can_begin_opening_replay(&self) -> bool {
        matches!(self.stage, CompactWhirRecomputableExtensionStage::Complete)
    }

    pub(crate) const fn is_complete(&self) -> bool {
        matches!(
            self.stage,
            CompactWhirRecomputableExtensionStage::Complete
                | CompactWhirRecomputableExtensionStage::OpeningReplayComplete
        )
    }

    fn prepare_stripe_containing(&mut self, row_ordinal: usize) -> Result<(), CompactWhirError> {
        if row_ordinal >= self.encoded_height
            || self.maximum_stripe_row_count == 0
            || !self.stripe_values.is_empty()
            || self.active_transform.is_some()
            || self.encoded_column_values.is_some()
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        self.stripe_first_row = row_ordinal
            .checked_div(self.maximum_stripe_row_count)
            .and_then(|stripe_ordinal| stripe_ordinal.checked_mul(self.maximum_stripe_row_count))
            .ok_or(CompactWhirError::CountOverflow)?;
        self.stripe_end_row = self
            .stripe_first_row
            .saturating_add(self.maximum_stripe_row_count)
            .min(self.encoded_height);
        self.next_response_row = row_ordinal;
        self.current_column_ordinal = 0;
        self.next_source_row = 0;
        self.next_capture_row = 0;
        self.stage = CompactWhirRecomputableExtensionStage::PrepareStripe;
        Ok(())
    }

    fn clear_stripe_values(&mut self) {
        self.stripe_values.fill(CompactChallengeField::ZERO);
        self.stripe_values.clear();
    }
}

impl Drop for CompactWhirRecomputableExtensionInitialOracle {
    fn drop(&mut self) {
        self.randomness.fill(CompactChallengeField::ZERO);
        self.stripe_values.fill(CompactChallengeField::ZERO);
        if let Some(values) = self.encoded_column_values.as_mut() {
            values.fill(CompactChallengeField::ZERO);
        }
    }
}

fn allocate_zero_extension_values(
    length: usize,
) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| CompactWhirError::CountOverflow)?;
    values.resize(length, CompactChallengeField::ZERO);
    Ok(values)
}

impl CompactWhirEncodedMaskGroup {
    pub(crate) fn encode(
        shape: MaskGroupShape,
        messages: &[Vec<CompactChallengeField>],
        randomness: &[Vec<CompactChallengeField>],
    ) -> Result<Self, CompactWhirError> {
        if messages.len() != shape.width
            || randomness.len() != shape.width
            || messages
                .iter()
                .any(|message| message.len() != shape.shape.message_len)
            || randomness
                .iter()
                .any(|values| values.len() != shape.shape.randomness_len)
        {
            return Err(CompactWhirError::InvalidMessage);
        }
        let value_count = shape
            .shape
            .domain_size
            .checked_mul(shape.width)
            .ok_or(CompactWhirError::CountOverflow)?;
        let mut encoded_values = allocate_zero_extension_values(value_count)?;
        for (column_ordinal, (message, values)) in messages.iter().zip(randomness).enumerate() {
            let codeword = shape.shape.encode_with_randomness(message, values);
            if codeword.width() != 1 || codeword.height() != shape.shape.domain_size {
                return Err(CompactWhirError::InvalidEncodedMatrix);
            }
            for (row_ordinal, value) in codeword.values.into_iter().enumerate() {
                let destination = row_ordinal
                    .checked_mul(shape.width)
                    .and_then(|offset| offset.checked_add(column_ordinal))
                    .ok_or(CompactWhirError::CountOverflow)?;
                encoded_values[destination] = value;
            }
        }
        let encoded_matrix = DenseMatrix::new(encoded_values, shape.width);
        if encoded_matrix.width() != shape.width
            || encoded_matrix.height() != shape.shape.domain_size
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        Ok(Self { encoded_matrix })
    }

    pub(crate) const fn encoded_matrix(&self) -> &DenseMatrix<CompactChallengeField> {
        &self.encoded_matrix
    }

    pub(crate) fn encoded_row(&self, row_ordinal: usize) -> Option<&[CompactChallengeField]> {
        self.encoded_matrix().row_slices().nth(row_ordinal)
    }
}

pub(crate) fn compact_whir_mask_group_shape(
    contract: CompactWhirMaskGroupContract,
) -> Result<MaskGroupShape, CompactWhirError> {
    let shape = MaskCodeShape::new(
        usize::try_from(contract.message_length).map_err(|_| CompactWhirError::CountOverflow)?,
        usize::try_from(contract.randomness_length).map_err(|_| CompactWhirError::CountOverflow)?,
        COMPACT_WHIR_MASK_LOG_INVERSE_RATE,
    );
    let width = usize::try_from(contract.width).map_err(|_| CompactWhirError::CountOverflow)?;
    if width == 0
        || u64::try_from(shape.domain_size).map_err(|_| CompactWhirError::CountOverflow)?
            != contract.domain_size
    {
        return Err(CompactWhirError::InvalidConfiguration);
    }
    Ok(MaskGroupShape { shape, width })
}

fn initial_oracle_dimensions(
    configuration: &CompactWhirConfiguration,
) -> Result<(usize, usize), CompactWhirError> {
    let first_folding_factor = configuration.round_folding_factor(0);
    let expected_width = 1_usize
        .checked_shl(
            u32::try_from(first_folding_factor).map_err(|_| CompactWhirError::CountOverflow)?,
        )
        .ok_or(CompactWhirError::CountOverflow)?;
    let expected_height = 1_usize
        .checked_shl(
            u32::try_from(
                configuration
                    .num_variables
                    .checked_sub(first_folding_factor)
                    .ok_or(CompactWhirError::InvalidConfiguration)?,
            )
            .map_err(|_| CompactWhirError::CountOverflow)?,
        )
        .and_then(|height| height.checked_shl(configuration.starting_log_inv_rate as u32))
        .ok_or(CompactWhirError::CountOverflow)?;
    Ok((expected_width, expected_height))
}

pub(crate) fn compact_whir_configuration_from_contract(
    contract: &CompactWhirEpochContract,
) -> Result<CompactWhirConfiguration, CompactWhirError> {
    let configuration = compact_whir_configuration(
        contract.polynomial_variable_count,
        contract.folding_schedule,
        contract.final_variable_count,
        contract.round_log_inverse_rates,
    )?;
    if u64::try_from(configuration.mask_queries).map_err(|_| CompactWhirError::CountOverflow)?
        != contract.mask_query_count
    {
        return Err(CompactWhirError::InvalidConfiguration);
    }
    Ok(configuration)
}

pub(crate) fn compact_whir_configuration(
    polynomial_variable_count: u32,
    folding_schedule: [u32; COMPACT_WHIR_FOLD_COUNT],
    final_variable_count: u32,
    round_log_inverse_rates: [u32; COMPACT_WHIR_ROUND_COUNT],
) -> Result<CompactWhirConfiguration, CompactWhirError> {
    let configuration = ZkWhirConfig::new(
        usize::try_from(polynomial_variable_count).map_err(|_| CompactWhirError::CountOverflow)?,
        ProtocolParameters {
            starting_log_inv_rate: COMPACT_WHIR_STARTING_LOG_INVERSE_RATE,
            round_log_inv_rates: round_log_inverse_rates
                .into_iter()
                .map(|rate| usize::try_from(rate).map_err(|_| CompactWhirError::CountOverflow))
                .collect::<Result<Vec<_>, _>>()?,
            folding_factor: FoldingFactor::PerRound(
                folding_schedule
                    .into_iter()
                    .map(|factor| {
                        usize::try_from(factor).map_err(|_| CompactWhirError::CountOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            soundness_type: SecurityAssumption::UniqueDecoding,
            security_level: COMPACT_WHIR_PROTOCOL_SECURITY_LEVEL,
            pow_bits: 0,
        },
        ZkParameters {
            ell_zk: COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH,
            mask_log_inv_rate: COMPACT_WHIR_MASK_LOG_INVERSE_RATE,
        },
    )
    .map_err(|_| CompactWhirError::InvalidConfiguration)?;
    let derived_folding_schedule = configuration
        .folding_schedule
        .iter()
        .copied()
        .map(u32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompactWhirError::CountOverflow)?;
    let derived_round_log_inverse_rates = configuration
        .params
        .round_log_inv_rates
        .iter()
        .copied()
        .map(u32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompactWhirError::CountOverflow)?;
    if derived_folding_schedule.as_slice() != folding_schedule {
        return Err(CompactWhirError::FoldingScheduleMismatch);
    }
    if derived_round_log_inverse_rates.as_slice() != round_log_inverse_rates {
        return Err(CompactWhirError::RoundRateMismatch);
    }
    if u32::try_from(configuration.final_sumcheck_rounds)
        .map_err(|_| CompactWhirError::CountOverflow)?
        != final_variable_count
    {
        return Err(CompactWhirError::FinalVariableCountMismatch);
    }
    if !configuration.check_pow_bits() {
        return Err(CompactWhirError::InvalidProofOfWorkGeometry);
    }
    Ok(configuration)
}

pub(crate) fn compact_whir_challenger(transcript_binding: [u8; 64]) -> CompactWhirChallenger {
    CompactWhirChallenger::new(CompactWhirInnerChallenger::new(
        transcript_binding.to_vec(),
        CompactWhirByteHasher,
    ))
}

pub(crate) fn compact_whir_commitment_scheme() -> CompactWhirCommitmentScheme {
    CompactWhirCommitmentScheme::new(
        CompactWhirGoldilocksLeafHasher,
        CompactWhirNodeCompressor::new(CompactWhirWordHasher),
        0,
    )
}

fn initialized_compact_whir_hash(domain: &[u8]) -> Shake256 {
    let mut state = Shake256::default();
    state.update(COMPACT_WHIR_HASH_DOMAIN);
    state.update(&(domain.len() as u64).to_le_bytes());
    state.update(domain);
    state
}

fn finish_compact_whir_hash(state: Shake256) -> [u8; COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH] {
    let mut output = [0_u8; COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH];
    state.finalize_xof().read(&mut output);
    output
}

fn compact_whir_digest_words(
    bytes: [u8; COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH],
) -> [u64; COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH] {
    core::array::from_fn(|word_ordinal| {
        let first_byte = word_ordinal * size_of::<u64>();
        u64::from_le_bytes(
            bytes[first_byte..first_byte + size_of::<u64>()]
                .try_into()
                .expect("one compact WHIR digest word has eight bytes"),
        )
    })
}

impl CryptographicHasher<u8, [u8; COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH]> for CompactWhirByteHasher {
    fn hash_iter<Input>(&self, input: Input) -> [u8; COMPACT_WHIR_HASH_OUTPUT_BYTE_LENGTH]
    where
        Input: IntoIterator<Item = u8>,
    {
        let mut state = initialized_compact_whir_hash(b"challenger");
        for byte in input {
            state.update(&[byte]);
        }
        finish_compact_whir_hash(state)
    }
}

impl CryptographicHasher<Goldilocks, [u64; COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH]>
    for CompactWhirGoldilocksLeafHasher
{
    fn hash_iter<Input>(&self, input: Input) -> [u64; COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH]
    where
        Input: IntoIterator<Item = Goldilocks>,
    {
        let mut state = initialized_compact_whir_hash(b"leaf");
        for value in input {
            state.update(&value.as_canonical_u64().to_le_bytes());
        }
        compact_whir_digest_words(finish_compact_whir_hash(state))
    }
}

impl CryptographicHasher<u64, [u64; COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH]>
    for CompactWhirWordHasher
{
    fn hash_iter<Input>(&self, input: Input) -> [u64; COMPACT_WHIR_HASH_OUTPUT_WORD_LENGTH]
    where
        Input: IntoIterator<Item = u64>,
    {
        let mut state = initialized_compact_whir_hash(b"node");
        for value in input {
            state.update(&value.to_le_bytes());
        }
        compact_whir_digest_words(finish_compact_whir_hash(state))
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use p3_sumcheck::strategy::sumcheck_coefficients_prefix;
    use rand::{TryCryptoRng, TryRng};

    use super::*;

    struct CountingRandomSource(u64);

    impl TryRng for CountingRandomSource {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self.0.wrapping_add(1);
            Ok(self.0 as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self.0.wrapping_add(1);
            Ok(self.0)
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in destination.chunks_mut(size_of::<u64>()) {
                self.0 = self.0.wrapping_add(1);
                let bytes = self.0.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for CountingRandomSource {}

    fn bounded_test_configuration() -> CompactWhirConfiguration {
        ZkWhirConfig::new(
            8,
            ProtocolParameters {
                starting_log_inv_rate: 2,
                round_log_inv_rates: Vec::new(),
                folding_factor: FoldingFactor::PerRound(vec![2]),
                soundness_type: SecurityAssumption::UniqueDecoding,
                security_level: 32,
                pow_bits: 32,
            },
            ZkParameters {
                ell_zk: COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH,
                mask_log_inv_rate: COMPACT_WHIR_MASK_LOG_INVERSE_RATE,
            },
        )
        .expect("the bounded WHIR test geometry configures")
    }

    fn initial_sumcheck_mask_contract(
        configuration: &CompactWhirConfiguration,
    ) -> CompactWhirMaskGroupContract {
        CompactWhirMaskGroupContract {
            role_tag: 4,
            coordinate: 0,
            width: configuration.round_folding_factor(0) as u64,
            message_length: configuration.sumcheck_mask.message_len as u64,
            randomness_length: configuration.sumcheck_mask.randomness_len as u64,
            domain_size: configuration.sumcheck_mask.domain_size as u64,
            committed_encoding_source: 1,
        }
    }

    fn prepared_test_relation(
        source: Vec<Goldilocks>,
        equality_point: Vec<CompactChallengeField>,
        pre_challenge_mask: CompactChallengeField,
        main_mask: CompactChallengeField,
        opening_batching_challenge: CompactChallengeField,
    ) -> CompactWhirPreChallengeRelation {
        let equality_covector =
            Poly::new_from_point(&equality_point, CompactChallengeField::ONE).into_evals();
        let source_claim = source
            .iter()
            .copied()
            .map(CompactChallengeField::from)
            .zip(&equality_covector)
            .map(|(source_value, weight)| source_value * *weight)
            .sum::<CompactChallengeField>();
        let mut preparation = CompactWhirPreChallengeRelationPreparation::new(
            source,
            equality_point,
            source_claim + pre_challenge_mask,
            source_claim + main_mask,
            pre_challenge_mask - main_mask,
            pre_challenge_mask,
            main_mask,
            opening_batching_challenge,
        )
        .expect("the test relation begins preparing");
        let work_budgets = [1_u64, 3, 17, 5, 64];
        let mut poll_ordinal = 0_usize;
        loop {
            let poll = preparation
                .poll(work_budgets[poll_ordinal % work_budgets.len()])
                .expect("the test relation advances");
            poll_ordinal += 1;
            if poll == CompactWhirPreChallengeRelationPreparationPoll::Complete {
                break;
            }
        }
        preparation.finish().expect("the test relation finishes")
    }

    #[test]
    fn selected_contract_builds_the_same_initial_oracle_geometry() {
        let contract =
            super::super::compact_proof_contract::selected_compact_public_key_proof_contract()
                .expect("the selected contract decodes");
        let inputs = contract.verifier_inputs();
        let mut selected_initial_oracle_dimensions = Vec::new();
        for epoch in inputs.whir_epochs {
            let configuration = compact_whir_configuration_from_contract(epoch)
                .expect("the selected WHIR epoch configures the production prover");
            selected_initial_oracle_dimensions.push(
                initial_oracle_dimensions(&configuration).expect("selected initial oracle shape"),
            );
            assert_eq!(
                configuration.num_variables,
                epoch.polynomial_variable_count as usize
            );
            assert_eq!(
                configuration.folding_schedule,
                epoch
                    .folding_schedule
                    .into_iter()
                    .map(|factor| factor as usize)
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(
            selected_initial_oracle_dimensions,
            [(64, 131_072), (128, 131_072)]
        );
        let post_lookup_component_dimensions = inputs.response_merkle_geometries[1]
            .components()
            .iter()
            .map(|component| {
                (
                    component.leaf_count(),
                    component.field_element_count_per_leaf(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            post_lookup_component_dimensions,
            [
                (2_048, 69),
                (131_072, 128),
                (2_048, 23),
                (4_096, 2),
                (122_880, 0),
            ]
        );
        assert_eq!(size_of::<CompactChallengeField>(), 40);
        let selected_main_oracle_byte_length = 131_072_u64 * 128 * 40;
        let selected_main_stripe_byte_length =
            u64::try_from(COMPACT_WHIR_EXTENSION_RESPONSE_STRIPE_ROW_COUNT).unwrap() * 128 * 40;
        let selected_main_column_byte_length = 131_072_u64 * 40;
        assert_eq!(selected_main_oracle_byte_length, 671_088_640);
        assert_eq!(selected_main_stripe_byte_length, 83_886_080);
        assert_eq!(
            selected_main_stripe_byte_length + selected_main_column_byte_length,
            89_128_960
        );

        let configuration = compact_whir_configuration(16, [1, 4, 4, 4], 3, [2, 4, 8])
            .expect("the bounded production-shaped WHIR geometry configures");
        let message = (0..1_usize << configuration.num_variables)
            .map(|ordinal| Goldilocks::from_u64((ordinal as u64).wrapping_mul(17)))
            .collect();
        let mut random_source = CountingRandomSource(0xA5);
        let mut encoded_oracle =
            CompactWhirEncodedInitialOracle::encode(&configuration, message, &mut random_source)
                .expect("the bounded initial oracle encodes");
        let matrix = encoded_oracle.encoded_matrix();
        assert_eq!(matrix.width(), 2);
        assert_eq!(matrix.height(), 1 << 17);
        assert_eq!(
            encoded_oracle.encoded_row(0).map(<[Goldilocks]>::len),
            Some(matrix.width())
        );
        assert!(encoded_oracle.encoded_row(matrix.height()).is_none());
        assert_eq!(
            encoded_oracle.encoding_randomness().len(),
            configuration.oracle_randomness[0] << configuration.round_folding_factor(0)
        );
        assert_eq!(
            encoded_oracle
                .take_source_message()
                .expect("the retained source transfers exactly")
                .len(),
            1 << configuration.num_variables
        );
        assert_eq!(
            encoded_oracle.take_source_message(),
            Err(CompactWhirError::WrongProverPhase)
        );
    }

    #[test]
    fn pre_challenge_relation_preparation_matches_the_canonical_equality_covector() {
        let source = (0..256)
            .map(|ordinal| Goldilocks::from_u64((ordinal * 37 + 11) as u64))
            .collect::<Vec<_>>();
        let equality_point = (0..8)
            .map(|coordinate_ordinal| {
                CompactChallengeField::from_u64((coordinate_ordinal * 19 + 7) as u64)
            })
            .collect::<Vec<_>>();
        let expected_source = source
            .iter()
            .copied()
            .map(CompactChallengeField::from)
            .collect::<Vec<_>>();
        let expected_covector =
            Poly::new_from_point(&equality_point, CompactChallengeField::ONE).into_evals();
        let pre_challenge_mask = CompactChallengeField::from_u64(701);
        let main_mask = CompactChallengeField::from_u64(809);
        let relation = prepared_test_relation(
            source,
            equality_point,
            pre_challenge_mask,
            main_mask,
            CompactChallengeField::from_u64(907),
        );

        assert_eq!(relation.source_evaluations, expected_source);
        assert_eq!(relation.source_covector, expected_covector);
        assert_eq!(
            relation.source_claim + pre_challenge_mask,
            relation.masked_target
        );

        let mut invalid_preparation = CompactWhirPreChallengeRelationPreparation::new(
            vec![Goldilocks::ONE; 8],
            vec![CompactChallengeField::ONE; 3],
            CompactChallengeField::from_u64(13),
            CompactChallengeField::from_u64(17),
            CompactChallengeField::from_u64(23),
            CompactChallengeField::from_u64(29),
            CompactChallengeField::from_u64(31),
            CompactChallengeField::from_u64(37),
        )
        .expect("the malformed relation has valid dimensions");
        assert_eq!(
            invalid_preparation.poll(0),
            Err(CompactWhirError::InvalidWorkBudget)
        );
        loop {
            match invalid_preparation.poll(64) {
                Err(error) => {
                    assert_eq!(error, CompactWhirError::InvalidRelation);
                    break;
                }
                Ok(CompactWhirPreChallengeRelationPreparationPoll::Complete) => {
                    panic!("an inconsistent masked relation must not complete")
                }
                Ok(CompactWhirPreChallengeRelationPreparationPoll::StepCompleted { .. }) => {}
            }
        }
    }

    #[test]
    fn quadratic_extrapolation_uses_the_boolean_sum_as_its_carried_claim() {
        let evaluation_at_zero = CompactChallengeField::from_u64(7);
        let evaluation_at_one = CompactChallengeField::from_u64(13);
        let leading_coefficient = CompactChallengeField::from_u64(3);
        let boolean_sum = evaluation_at_zero + evaluation_at_one;
        assert_eq!(
            extrapolate_quadratic_from_boolean_sum(
                evaluation_at_zero,
                boolean_sum,
                leading_coefficient,
                CompactChallengeField::ZERO,
            ),
            evaluation_at_zero
        );
        assert_eq!(
            extrapolate_quadratic_from_boolean_sum(
                evaluation_at_zero,
                boolean_sum,
                leading_coefficient,
                CompactChallengeField::ONE,
            ),
            evaluation_at_one
        );
        let point = CompactChallengeField::from_u64(5);
        assert_eq!(
            extrapolate_quadratic_from_boolean_sum(
                evaluation_at_zero,
                boolean_sum,
                leading_coefficient,
                point,
            ),
            evaluation_at_zero * (CompactChallengeField::ONE - point)
                + evaluation_at_one * point
                + leading_coefficient * point * (point - CompactChallengeField::ONE)
        );
    }

    #[test]
    fn pollable_initial_sumcheck_matches_the_scalar_prefix_reference() {
        let configuration = bounded_test_configuration();
        let source = (0..1_usize << configuration.num_variables)
            .map(|ordinal| Goldilocks::from_u64((ordinal as u64).wrapping_mul(41) + 5))
            .collect::<Vec<_>>();
        let equality_point = (0..configuration.num_variables)
            .map(|coordinate_ordinal| {
                CompactChallengeField::from_u64((coordinate_ordinal as u64) * 43 + 13)
            })
            .collect::<Vec<_>>();
        let pre_challenge_mask = CompactChallengeField::from_u64(1_009);
        let main_mask = CompactChallengeField::from_u64(1_103);
        let opening_batching_challenge = CompactChallengeField::from_u64(1_201);
        let relation = prepared_test_relation(
            source,
            equality_point,
            pre_challenge_mask,
            main_mask,
            opening_batching_challenge,
        );
        let mut random_source = CountingRandomSource(0xD7);
        let mut state = CompactWhirInitialSumcheckState::new(
            relation,
            &configuration,
            initial_sumcheck_mask_contract(&configuration),
            &mut random_source,
        )
        .expect("the pollable initial sumcheck starts");

        assert_eq!(state.poll(1), Err(CompactWhirError::WrongProverPhase));
        assert_eq!(
            state.bind_round_challenge(CompactChallengeField::ONE),
            Err(CompactWhirError::WrongProverPhase)
        );
        assert_eq!(
            state.opening_batching_challenge(),
            opening_batching_challenge
        );
        assert_eq!(
            state.masked_target(),
            state.source_claim + pre_challenge_mask
        );
        assert_eq!(
            state.auxiliary_target(),
            CompactChallengeField::TWO.exp_u64((configuration.round_folding_factor(0) - 1) as u64)
                * state
                    .mask_messages()
                    .iter()
                    .map(|message| mask_endpoint_sum(message))
                    .sum::<CompactChallengeField>()
        );
        assert_eq!(
            state.mask_oracle().encoded_matrix().width(),
            configuration.round_folding_factor(0)
        );
        assert_eq!(
            state.mask_encoding_randomness().len(),
            configuration.round_folding_factor(0)
        );

        let combination_challenge = CompactChallengeField::from_u64(1_303);
        state
            .bind_combination_challenge(combination_challenge)
            .expect("the exact combination challenge binds");
        assert_eq!(
            state.bind_combination_challenge(combination_challenge),
            Err(CompactWhirError::WrongProverPhase)
        );
        assert_eq!(state.poll(0), Err(CompactWhirError::InvalidWorkBudget));

        let mut reference_source = state.source_evaluations.clone();
        let mut reference_covector = state.source_covector.clone();
        let mut reference_claim = state.source_claim;
        let mut reference_future_endpoints = state
            .mask_messages()
            .iter()
            .map(|message| mask_endpoint_sum(message))
            .sum::<CompactChallengeField>();
        let mut reference_mask_carry = pre_challenge_mask;
        let mut reference_past_mask_evaluations = Vec::new();
        let folding_factor = configuration.round_folding_factor(0);
        let challenges = [
            CompactChallengeField::from_u64(1_409),
            CompactChallengeField::from_u64(1_501),
        ];
        let work_budgets = [1_u64, 7, 31, 3];
        let mut poll_ordinal = 0_usize;

        for (round_index, challenge) in challenges.into_iter().enumerate() {
            let mask = state.mask_messages()[round_index].clone();
            reference_future_endpoints -= mask_endpoint_sum(&mask);
            reference_mask_carry *= CompactChallengeField::TWO.inverse();
            let (plain_constant, plain_leading) =
                sumcheck_coefficients_prefix(&reference_source, &reference_covector);
            let round_number = round_index + 1;
            let live_multiplier =
                CompactChallengeField::TWO.exp_u64((folding_factor - round_number) as u64);
            let mut full = vec![CompactChallengeField::ZERO; 3];
            for (coefficient, mask_coefficient) in full.iter_mut().zip(&mask) {
                *coefficient += live_multiplier * *mask_coefficient;
            }
            full[0] += reference_past_mask_evaluations
                .iter()
                .copied()
                .sum::<CompactChallengeField>()
                * live_multiplier;
            if round_number < folding_factor {
                full[0] += CompactChallengeField::TWO
                    .exp_u64((folding_factor - round_number - 1) as u64)
                    * reference_future_endpoints;
            }
            full[0] += combination_challenge * (plain_constant + reference_mask_carry);
            full[2] += combination_challenge * plain_leading;
            let expected_wire = vec![full[0], full[2]];

            loop {
                let poll = state
                    .poll(work_budgets[poll_ordinal % work_budgets.len()])
                    .expect("the round polynomial advances");
                poll_ordinal += 1;
                if matches!(
                    poll,
                    CompactWhirInitialSumcheckPoll::RoundPolynomialStepCompleted {
                        polynomial_ready: true,
                        ..
                    }
                ) {
                    break;
                }
            }
            assert_eq!(state.pending_round_wire().unwrap(), expected_wire);
            assert_eq!(
                state.round_wire(round_index),
                Some(expected_wire.as_slice())
            );
            state
                .bind_round_challenge(challenge)
                .expect("the round challenge binds");
            reference_past_mask_evaluations.push(evaluate_univariate(&mask, challenge));
            reference_claim = extrapolate_quadratic_from_boolean_sum(
                plain_constant,
                reference_claim,
                plain_leading,
                challenge,
            );
            let half = reference_source.len() / 2;
            for pair_ordinal in 0..half {
                let source_low = reference_source[pair_ordinal];
                let source_high = reference_source[half + pair_ordinal];
                reference_source[pair_ordinal] =
                    source_low + challenge * (source_high - source_low);
                let weight_low = reference_covector[pair_ordinal];
                let weight_high = reference_covector[half + pair_ordinal];
                reference_covector[pair_ordinal] =
                    weight_low + challenge * (weight_high - weight_low);
            }
            reference_source.truncate(half);
            reference_covector.truncate(half);
            assert_eq!(
                reference_claim,
                reference_source
                    .iter()
                    .copied()
                    .zip(&reference_covector)
                    .map(|(source_value, weight)| source_value * *weight)
                    .sum::<CompactChallengeField>()
            );
            loop {
                let poll = state
                    .poll(work_budgets[poll_ordinal % work_budgets.len()])
                    .expect("the bound round advances");
                poll_ordinal += 1;
                if matches!(
                    poll,
                    CompactWhirInitialSumcheckPoll::BoundRoundStepCompleted {
                        round_complete: true,
                        ..
                    }
                ) {
                    break;
                }
            }
        }

        loop {
            let poll = state
                .poll(work_budgets[poll_ordinal % work_budgets.len()])
                .expect("residual scaling advances");
            poll_ordinal += 1;
            if matches!(
                poll,
                CompactWhirInitialSumcheckPoll::WeightScalingStepCompleted {
                    scaling_complete: true,
                    ..
                }
            ) {
                break;
            }
        }
        for weight in &mut reference_covector {
            *weight *= combination_challenge;
        }
        reference_claim *= combination_challenge;

        assert!(state.is_complete());
        assert_eq!(state.residual_source().unwrap(), reference_source);
        assert_eq!(state.residual_covector().unwrap(), reference_covector);
        assert_eq!(state.residual_source_claim().unwrap(), reference_claim);
        assert_eq!(
            state.residual_source_claim().unwrap(),
            state
                .residual_source()
                .unwrap()
                .iter()
                .copied()
                .zip(state.residual_covector().unwrap())
                .map(|(source_value, weight)| source_value * *weight)
                .sum::<CompactChallengeField>()
        );
        assert_eq!(
            state.residual_preceding_mask_claim().unwrap(),
            combination_challenge * reference_mask_carry
        );
        assert_eq!(state.round_challenges(), challenges);
        assert_eq!(state.poll(1), Err(CompactWhirError::WrongProverPhase));
    }

    #[test]
    fn extension_initial_oracle_split_matches_the_commit_adapter() {
        let configuration = compact_whir_configuration(16, [1, 4, 4, 4], 3, [2, 4, 8])
            .expect("the bounded extension-source geometry configures");
        let message = (0..1_usize << configuration.num_variables)
            .map(|ordinal| {
                CompactChallengeField::from(Goldilocks::from_u64((ordinal as u64).wrapping_mul(29)))
            })
            .collect::<Vec<_>>();
        let mut split_random_source = CountingRandomSource(0xB7);
        let split = CompactWhirEncodedExtensionInitialOracle::encode(
            &configuration,
            message.clone(),
            &mut split_random_source,
        )
        .expect("the extension initial oracle encodes without an inner commitment");

        let commitment_scheme = compact_whir_commitment_scheme();
        let transform = Radix2DFTSmallBatch::<Goldilocks>::default();
        let prover = HidingWhirProver::new(&configuration, &transform, &commitment_scheme);
        let mut adapter_random_source = CountingRandomSource(0xB7);
        let mut adapter_challenger = compact_whir_challenger([0x4D; 64]);
        let (adapter_commitment, _adapter_prover_data) = prover.commit_extension(
            Poly::new(message),
            &mut adapter_challenger,
            &mut adapter_random_source,
        );
        let extension_commitment_scheme =
            CompactWhirExtensionCommitmentScheme::new(commitment_scheme);
        let (split_commitment, _split_prover_data) =
            extension_commitment_scheme.commit_matrix(split.encoded_matrix().clone());

        assert_eq!(split_commitment, adapter_commitment);
        assert_eq!(split_random_source.0, adapter_random_source.0);
        assert_eq!(split.encoded_matrix().width(), 2);
        assert_eq!(split.encoded_matrix().height(), 1 << 17);
        assert_eq!(
            split.encoded_row(0).map(<[CompactChallengeField]>::len),
            Some(2)
        );
        assert!(split.encoded_row(split.encoded_matrix().height()).is_none());
    }

    #[test]
    fn streamed_mask_group_encoding_matches_the_canonical_stacked_codewords() {
        let shape = MaskGroupShape {
            shape: MaskCodeShape::new(4, 11, 2),
            width: 5,
        };
        let messages = (0..shape.width)
            .map(|column_ordinal| {
                (0..shape.shape.message_len)
                    .map(|coefficient_ordinal| {
                        CompactChallengeField::from_u64(
                            u64::try_from(column_ordinal * 31 + coefficient_ordinal * 7 + 1)
                                .unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let randomness = (0..shape.width)
            .map(|column_ordinal| {
                (0..shape.shape.randomness_len)
                    .map(|coefficient_ordinal| {
                        CompactChallengeField::from_u64(
                            u64::try_from(column_ordinal * 43 + coefficient_ordinal * 13 + 2)
                                .unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let canonical_codewords = messages
            .iter()
            .zip(&randomness)
            .map(|(message, values)| shape.shape.encode_with_randomness(message, values))
            .collect::<Vec<_>>();
        let expected = stack_codewords(&canonical_codewords);
        let actual = CompactWhirEncodedMaskGroup::encode(shape, &messages, &randomness)
            .expect("the streamed mask group encodes");

        assert_eq!(actual.encoded_matrix(), &expected);
        assert!(CompactWhirEncodedMaskGroup::encode(shape, &messages[..4], &randomness).is_err());
        assert!(CompactWhirEncodedMaskGroup::encode(shape, &messages, &randomness[..4]).is_err());
    }

    #[test]
    fn recomputable_extension_oracle_matches_the_eager_encoding_by_row() {
        let configuration = compact_whir_configuration(16, [1, 4, 4, 4], 3, [2, 4, 8])
            .expect("the bounded extension-source geometry configures");
        let message = (0..1_usize << configuration.num_variables)
            .map(|ordinal| {
                CompactChallengeField::from(Goldilocks::from_u64((ordinal as u64).wrapping_mul(31)))
            })
            .collect::<Vec<_>>();
        let mut eager_random_source = CountingRandomSource(0xC9);
        let eager = CompactWhirEncodedExtensionInitialOracle::encode(
            &configuration,
            message.clone(),
            &mut eager_random_source,
        )
        .expect("the eager reference oracle encodes");
        let mut recomputable_random_source = CountingRandomSource(0xC9);
        let mut recomputable =
            CompactWhirRecomputableExtensionInitialOracle::sample_with_maximum_stripe_row_count(
                &configuration,
                &mut recomputable_random_source,
                1 << 13,
            )
            .expect("the recomputable oracle samples exact encoding randomness");

        assert_eq!(eager_random_source.0, recomputable_random_source.0);
        assert_eq!(
            recomputable.encoding_randomness(),
            eager.encoded_oracle.randomness
        );
        assert_eq!(recomputable.width(), eager.encoded_matrix().width());
        assert_eq!(
            recomputable.encoded_height(),
            eager.encoded_matrix().height()
        );
        let mut arithmetic_poll_count = 0_u64;
        for row_ordinal in 0..recomputable.encoded_height() {
            loop {
                if let Ok(row) = recomputable.response_row(row_ordinal) {
                    assert_eq!(
                        row,
                        eager
                            .encoded_row(row_ordinal)
                            .expect("the eager row is present")
                    );
                    break;
                }
                match recomputable
                    .poll(4_096, |source_ordinal| {
                        Ok::<_, ()>(
                            message[usize::try_from(source_ordinal).expect("small source ordinal")],
                        )
                    })
                    .expect("the recomputable encoding advances")
                {
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    } => {
                        assert!((1..=4_096).contains(&processed_work_unit_count));
                        arithmetic_poll_count += 1;
                    }
                    CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {}
                }
            }
            recomputable
                .mark_response_row_supplied(row_ordinal)
                .expect("the exact next response row advances custody");
        }
        assert!(arithmetic_poll_count > 0);
        assert!(recomputable.is_complete());
        assert!(recomputable.response_row(0).is_err());
        assert!(recomputable.begin_opening_replay(&[]).is_err());
        assert!(recomputable.begin_opening_replay(&[1, 1]).is_err());
        assert!(
            recomputable
                .begin_opening_replay(&[recomputable.encoded_height()])
                .is_err()
        );

        let opening_rows = [
            1,
            recomputable.encoded_height() / 2 + 3,
            recomputable.encoded_height() - 1,
        ];
        recomputable
            .begin_opening_replay(&opening_rows)
            .expect("the verifier-derived rows begin one delayed replay");
        assert!(!recomputable.can_begin_opening_replay());
        assert!(!recomputable.is_complete());
        let mut opening_arithmetic_poll_count = 0_u64;
        for row_ordinal in opening_rows {
            loop {
                if let Ok(row) = recomputable.response_row(row_ordinal) {
                    assert_eq!(
                        row,
                        eager
                            .encoded_row(row_ordinal)
                            .expect("the delayed eager row is present")
                    );
                    break;
                }
                match recomputable
                    .poll(4_096, |source_ordinal| {
                        Ok::<_, ()>(
                            message[usize::try_from(source_ordinal)
                                .expect("small delayed source ordinal")],
                        )
                    })
                    .expect("the delayed opening encoding advances")
                {
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    } => {
                        assert!((1..=4_096).contains(&processed_work_unit_count));
                        opening_arithmetic_poll_count += 1;
                    }
                    CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {}
                }
            }
            recomputable
                .mark_response_row_supplied(row_ordinal)
                .expect("the exact delayed opening row advances custody");
        }
        assert!(opening_arithmetic_poll_count > 0);
        assert!(recomputable.is_complete());
        assert!(recomputable.response_row(opening_rows[0]).is_err());
        assert!(recomputable.begin_opening_replay(&opening_rows).is_err());
    }

    #[test]
    fn recomputable_extension_oracle_rejects_invalid_lifecycle_inputs() {
        let configuration = compact_whir_configuration(16, [1, 4, 4, 4], 3, [2, 4, 8])
            .expect("the bounded extension-source geometry configures");
        let mut invalid_stripe_random_source = CountingRandomSource(0xD3);
        assert!(
            CompactWhirRecomputableExtensionInitialOracle::sample_with_maximum_stripe_row_count(
                &configuration,
                &mut invalid_stripe_random_source,
                3,
            )
            .is_err()
        );
        let mut random_source = CountingRandomSource(0xD3);
        let mut oracle =
            CompactWhirRecomputableExtensionInitialOracle::sample_with_maximum_stripe_row_count(
                &configuration,
                &mut random_source,
                1 << 14,
            )
            .expect("valid recomputable oracle");
        assert!(oracle.response_row(0).is_err());
        assert!(oracle.mark_response_row_supplied(0).is_err());
        assert!(oracle.begin_opening_replay(&[0]).is_err());
        assert!(
            oracle
                .poll(0, |_source_ordinal| {
                    Ok::<_, ()>(CompactChallengeField::ZERO)
                })
                .is_err()
        );
    }

    #[test]
    fn first_selected_code_switch_folds_randomness_and_uses_contract_geometry() {
        let contract =
            super::super::compact_proof_contract::selected_compact_public_key_proof_contract()
                .expect("the selected contract decodes");
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("the selected contract has both WHIR epochs")
        };
        let previous_source_contract = inputs
            .whir_folds
            .iter()
            .copied()
            .find(|fold| fold.epoch == pre_challenge_epoch.epoch && fold.batch_ordinal == 0)
            .expect("the initial source fold exists");
        let next_source_contract = inputs
            .whir_folds
            .iter()
            .copied()
            .find(|fold| fold.epoch == pre_challenge_epoch.epoch && fold.batch_ordinal == 1)
            .expect("the next source fold exists");
        let switch_mask_contract = pre_challenge_epoch
            .internal_mask_groups
            .iter()
            .copied()
            .find(|group| group.role_tag == 5 && group.coordinate == 0)
            .expect("the first switch mask exists");
        let source_element_count = usize::try_from(previous_source_contract.message_length)
            .expect("the selected source length fits usize");
        let source = (0..source_element_count)
            .map(|ordinal| CompactChallengeField::from_u64((ordinal as u64) * 17 + 3))
            .collect::<Vec<_>>();
        let folding_challenges = (0..pre_challenge_epoch.folding_schedule[0])
            .map(|ordinal| CompactChallengeField::from_u64(u64::from(ordinal) * 19 + 5))
            .collect::<Vec<_>>();
        let folding_weights =
            Poly::new_from_point(&folding_challenges, CompactChallengeField::ONE).into_evals();
        let previous_randomness_chunk =
            usize::try_from(previous_source_contract.hiding_randomness_length)
                .expect("the selected randomness length fits usize");
        let previous_randomness = (0..previous_randomness_chunk * folding_weights.len())
            .map(|ordinal| Goldilocks::from_u64((ordinal as u64) * 23 + 7))
            .collect::<Vec<_>>();
        let expected_folded_randomness = (0..previous_randomness_chunk)
            .map(|coordinate_ordinal| {
                folding_weights
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(limb_ordinal, weight)| {
                        weight
                            * CompactChallengeField::from(
                                previous_randomness
                                    [limb_ordinal * previous_randomness_chunk + coordinate_ordinal],
                            )
                    })
                    .sum::<CompactChallengeField>()
            })
            .collect::<Vec<_>>();
        let mut random_source = CountingRandomSource(0xE5);
        let mut state = CompactWhirCodeSwitchState::new(
            source,
            previous_randomness,
            &folding_challenges,
            previous_source_contract,
            next_source_contract,
            switch_mask_contract,
            &mut random_source,
        )
        .expect("the first code switch starts");
        assert_eq!(
            state.poll_preparation(0),
            Err(CompactWhirError::InvalidWorkBudget)
        );
        let work_budgets = [1_u64, 17, 509, 4_096];
        let mut poll_ordinal = 0_usize;
        loop {
            match state
                .poll_preparation(work_budgets[poll_ordinal % work_budgets.len()])
                .expect("the switch-mask fold advances")
            {
                CompactWhirCodeSwitchPreparationPoll::RandomnessFoldStepCompleted {
                    processed_work_unit_count,
                    ..
                } => {
                    assert!(processed_work_unit_count > 0);
                }
                CompactWhirCodeSwitchPreparationPoll::Complete => break,
            }
            poll_ordinal += 1;
        }
        assert_eq!(
            state.folded_previous_randomness().unwrap(),
            expected_folded_randomness
        );
        assert_eq!(state.source_oracle().source_element_count(), 32_768);
        assert_eq!(state.source_oracle().encoded_height(), 8_192);
        assert_eq!(state.source_oracle().width(), 16);
        assert_eq!(state.source_oracle().encoding_randomness().len(), 6_912);
        assert_eq!(
            state
                .switch_mask_oracle()
                .unwrap()
                .encoded_matrix()
                .height(),
            4_096
        );
        assert_eq!(
            state.switch_mask_oracle().unwrap().encoded_matrix().width(),
            1
        );
        assert_eq!(state.switch_mask_encoding_randomness().len(), 399);
        assert_eq!(
            state.bind_verifier_move(&[0; 396], CompactChallengeField::from_u64(31)),
            Err(CompactWhirError::InvalidRelation)
        );
        assert_eq!(
            state.bind_verifier_move(
                &(0..395_u64).collect::<Vec<_>>(),
                CompactChallengeField::from_u64(33),
            ),
            Err(CompactWhirError::InvalidRelation)
        );
        let mut out_of_range_query_positions = (0..395_u64).collect::<Vec<_>>();
        out_of_range_query_positions.push(previous_source_contract.block_length);
        assert_eq!(
            state.bind_verifier_move(
                &out_of_range_query_positions,
                CompactChallengeField::from_u64(35),
            ),
            Err(CompactWhirError::InvalidRelation)
        );
        let query_positions = (0..396_u64)
            .map(|ordinal| ordinal * 331)
            .collect::<Vec<_>>();
        state
            .bind_verifier_move(&query_positions, CompactChallengeField::from_u64(37))
            .expect("the exact distinct query set and combination challenge bind");
        assert!(state.verifier_move_is_bound());
        assert_eq!(
            state.bind_verifier_move(&query_positions, CompactChallengeField::from_u64(41)),
            Err(CompactWhirError::InvalidRelation)
        );
    }
}
