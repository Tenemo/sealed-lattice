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
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
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
    compact_cfw::{
        COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
        CompactCfwPublicMainCovectors, CompactChallengeField,
    },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirMainRelationPreparationPoll {
    SourceStepCompleted {
        processed_work_unit_count: u64,
        relation_complete: bool,
    },
    Complete,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirMainRelationPreparationError<SourceError> {
    Whir(CompactWhirError),
    Source(SourceError),
}

impl<SourceError> From<CompactWhirError> for CompactWhirMainRelationPreparationError<SourceError> {
    fn from(error: CompactWhirError) -> Self {
        Self::Whir(error)
    }
}

/// Pollable construction of the verifier-determined main WHIR relation.
///
/// The structured transpose supplies only public coefficients. The prover
/// streams its authenticated witness into the committed source order and
/// evaluates the target from that source plus the already committed mask
/// messages. Independent verification derives the same target from the CFW
/// transcript and canonical public input; no prover-computed target is read
/// from proof bytes.
pub(crate) struct CompactWhirMainRelationPreparation {
    source_covector: Vec<CompactChallengeField>,
    next_source_element: usize,
    source_claim: CompactChallengeField,
    preceding_mask_claim: CompactChallengeField,
    input_binding_challenge: CompactChallengeField,
}

/// Opaque, checked relation handed to one masked WHIR sumcheck batch.
pub(crate) struct CompactWhirMaskedSumcheckRelation {
    source_evaluations: Vec<CompactChallengeField>,
    authenticated_source_replay_element_count: Option<usize>,
    source_covector: Vec<CompactChallengeField>,
    source_claim: CompactChallengeField,
    target: CompactChallengeField,
    preceding_mask_claim: CompactChallengeField,
    input_binding_challenge: CompactChallengeField,
}

#[cfg(test)]
impl CompactWhirMaskedSumcheckRelation {
    pub(crate) fn relation_parts_for_test(
        &self,
    ) -> (
        &[CompactChallengeField],
        &[CompactChallengeField],
        CompactChallengeField,
        CompactChallengeField,
        CompactChallengeField,
        CompactChallengeField,
    ) {
        (
            &self.source_evaluations,
            &self.source_covector,
            self.source_claim,
            self.target,
            self.preceding_mask_claim,
            self.input_binding_challenge,
        )
    }

    pub(crate) const fn authenticated_source_replay_element_count_for_test(&self) -> Option<usize> {
        self.authenticated_source_replay_element_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactWhirAuthenticatedSourceReplayState {
    current_element_count: usize,
    folded_weight_offset: Option<usize>,
    residual_source_taken: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirInitialSumcheckSourceReplayError<SourceError> {
    Whir(CompactWhirError),
    Source(SourceError),
}

impl<SourceError> From<CompactWhirError>
    for CompactWhirInitialSumcheckSourceReplayError<SourceError>
{
    fn from(error: CompactWhirError) -> Self {
        Self::Whir(error)
    }
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
    RoundPolynomial {
        round_ordinal: u32,
        processed_work_unit_count: u64,
        polynomial_ready: bool,
    },
    BoundRound {
        round_ordinal: u32,
        processed_work_unit_count: u64,
        round_complete: bool,
    },
    WeightScaling {
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
    authenticated_source_replay: Option<CompactWhirAuthenticatedSourceReplayState>,
    detached_replayed_source_covector: Option<Vec<CompactChallengeField>>,
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
    previous_encoding_randomness: Vec<CompactChallengeField>,
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
    folded_source_openings: Option<Vec<CompactChallengeField>>,
    phase: CompactWhirCodeSwitchPhase,
}

pub(crate) struct CompactWhirBoundCodeSwitchInputs {
    source_evaluations: Vec<CompactChallengeField>,
    switch_mask_message: Vec<CompactChallengeField>,
    query_positions: Vec<usize>,
    folded_source_openings: Vec<CompactChallengeField>,
    combination_challenge: CompactChallengeField,
    previous_source_height: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactWhirCodeSwitchRelationPreparationPhase {
    AccumulatingQueryRelations,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirCodeSwitchRelationPreparationPoll {
    QueryRelationStepCompleted {
        processed_work_unit_count: u64,
        relation_complete: bool,
    },
    Complete,
}

/// Pollable construction of the exact relation produced by one code switch.
/// Every query contributes the same canonical Reed–Solomon power run to the
/// source covector, switch-mask covector, and public target. Completion checks
/// the resulting witness identity before exposing the next sumcheck relation.
pub(crate) struct CompactWhirCodeSwitchRelationPreparation {
    source_evaluations: Vec<CompactChallengeField>,
    source_covector: Vec<CompactChallengeField>,
    source_claim: CompactChallengeField,
    preceding_mask_claim: CompactChallengeField,
    target: CompactChallengeField,
    switch_mask_message: Vec<CompactChallengeField>,
    query_positions: Vec<usize>,
    folded_source_openings: Vec<CompactChallengeField>,
    combination_challenge: CompactChallengeField,
    domain_generator: CompactChallengeField,
    query_ordinal: usize,
    next_query_coordinate_ordinal: usize,
    query_coefficient: CompactChallengeField,
    query_point: CompactChallengeField,
    query_power: CompactChallengeField,
    phase: CompactWhirCodeSwitchRelationPreparationPhase,
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
    CaptureOpeningRows,
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
    opening_values: Vec<CompactChallengeField>,
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

/// One carried mask group entering the terminal WHIR base case. The group
/// owns the exact committed message and encoding randomness together with the
/// independently replayed public covectors that consume those coordinates.
pub(crate) struct CompactWhirBaseMaskInput {
    contract: CompactWhirMaskGroupContract,
    messages: Vec<Vec<CompactChallengeField>>,
    randomness: Vec<Vec<CompactChallengeField>>,
    covectors: Vec<Vec<CompactChallengeField>>,
}

struct CompactWhirBaseMaskState {
    carried_messages: Vec<Vec<CompactChallengeField>>,
    carried_randomness: Vec<Vec<CompactChallengeField>>,
    covectors: Vec<Vec<CompactChallengeField>>,
    fresh_messages: Vec<Vec<CompactChallengeField>>,
    fresh_randomness: Vec<Vec<CompactChallengeField>>,
    fresh_oracle: CompactWhirEncodedMaskGroup,
}

pub(crate) struct CompactWhirBaseRelation {
    source_message: Vec<CompactChallengeField>,
    source_covector: Vec<CompactChallengeField>,
    target: CompactChallengeField,
}

impl CompactWhirBaseRelation {
    pub(crate) fn new(
        source_message: Vec<CompactChallengeField>,
        source_covector: Vec<CompactChallengeField>,
        target: CompactChallengeField,
    ) -> Self {
        Self {
            source_message,
            source_covector,
            target,
        }
    }
}

/// Production Construction 7.2 state after the last masked sumcheck. It folds
/// the last interleaved source randomness into the width-one base code,
/// samples every fresh pad, checks the carried relation, and emits the fresh
/// claim before accepting the combination challenge.
pub(crate) struct CompactWhirBaseCaseState {
    source_message: Vec<CompactChallengeField>,
    source_randomness: Vec<CompactChallengeField>,
    source_covector: Vec<CompactChallengeField>,
    target: CompactChallengeField,
    fresh_source_message: Vec<CompactChallengeField>,
    fresh_source_oracle: CompactWhirRecomputableExtensionInitialOracle,
    mask_groups: Vec<CompactWhirBaseMaskState>,
    fresh_claim: CompactChallengeField,
    combination_challenge: Option<CompactChallengeField>,
    blinded_response_values: Option<Vec<CompactChallengeField>>,
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

    pub(crate) fn finish(mut self) -> Result<CompactWhirMaskedSumcheckRelation, CompactWhirError> {
        if self.phase != CompactWhirPreChallengeRelationPreparationPhase::Complete
            || self.source_evaluations.len() != self.source_covector.len()
        {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(CompactWhirMaskedSumcheckRelation {
            source_evaluations: core::mem::take(&mut self.source_evaluations),
            authenticated_source_replay_element_count: None,
            source_covector: core::mem::take(&mut self.source_covector),
            source_claim: self.accumulated_source_claim,
            target: self.masked_pre_challenge_evaluation,
            preceding_mask_claim: self.pre_challenge_mask,
            input_binding_challenge: self.opening_batching_challenge,
        })
    }
}

impl CompactWhirMainRelationPreparation {
    pub(crate) fn new(
        public_covectors: CompactCfwPublicMainCovectors,
        inner_mask_messages: &[[CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH]],
        outer_mask_messages: &[[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]],
        cross_epoch_masks: [CompactChallengeField; 2],
        input_binding_challenge: CompactChallengeField,
    ) -> Result<Self, CompactWhirError> {
        let (source_covector, inner_mask_covectors, outer_mask_covectors, cross_covectors) =
            public_covectors.into_parts();
        if source_covector.is_empty()
            || !source_covector.len().is_power_of_two()
            || source_covector.capacity() != source_covector.len()
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        let mut preceding_mask_claim =
            checked_mask_group_claim(&inner_mask_covectors, inner_mask_messages)?
                + checked_mask_group_claim(&outer_mask_covectors, outer_mask_messages)?;
        if cross_covectors.len() != cross_epoch_masks.len()
            || cross_covectors
                .iter()
                .any(|covector| covector.as_slice().len() != 1)
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        for (covector, mask) in cross_covectors.iter().zip(cross_epoch_masks) {
            preceding_mask_claim += covector[0] * mask;
        }
        Ok(Self {
            source_covector,
            next_source_element: 0,
            source_claim: CompactChallengeField::ZERO,
            preceding_mask_claim,
            input_binding_challenge,
        })
    }

    pub(crate) fn poll<SourceError>(
        &mut self,
        maximum_work_unit_count: u64,
        mut source_value: impl FnMut(u64) -> Result<CompactChallengeField, SourceError>,
    ) -> Result<
        CompactWhirMainRelationPreparationPoll,
        CompactWhirMainRelationPreparationError<SourceError>,
    > {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirError::InvalidWorkBudget.into());
        }
        if self.next_source_element == self.source_covector.len() {
            return Ok(CompactWhirMainRelationPreparationPoll::Complete);
        }
        let first_source_element = self.next_source_element;
        let end = first_source_element
            .saturating_add(maximum_work_unit_count)
            .min(self.source_covector.len());
        for source_ordinal in first_source_element..end {
            let value = source_value(
                u64::try_from(source_ordinal).map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .map_err(CompactWhirMainRelationPreparationError::Source)?;
            self.source_claim += value * self.source_covector[source_ordinal];
            self.next_source_element = source_ordinal
                .checked_add(1)
                .ok_or(CompactWhirError::CountOverflow)?;
        }
        Ok(
            CompactWhirMainRelationPreparationPoll::SourceStepCompleted {
                processed_work_unit_count: u64::try_from(end - first_source_element)
                    .map_err(|_| CompactWhirError::CountOverflow)?,
                relation_complete: end == self.source_covector.len(),
            },
        )
    }

    pub(crate) fn finish(mut self) -> Result<CompactWhirMaskedSumcheckRelation, CompactWhirError> {
        if self.next_source_element != self.source_covector.len() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let target = self.source_claim + self.preceding_mask_claim;
        let authenticated_source_replay_element_count = self.source_covector.len();
        Ok(CompactWhirMaskedSumcheckRelation {
            source_evaluations: Vec::new(),
            authenticated_source_replay_element_count: Some(
                authenticated_source_replay_element_count,
            ),
            source_covector: core::mem::take(&mut self.source_covector),
            source_claim: self.source_claim,
            target,
            preceding_mask_claim: self.preceding_mask_claim,
            input_binding_challenge: self.input_binding_challenge,
        })
    }
}

impl Drop for CompactWhirMainRelationPreparation {
    fn drop(&mut self) {
        self.source_covector.fill(CompactChallengeField::ZERO);
        self.source_claim = CompactChallengeField::ZERO;
        self.preceding_mask_claim = CompactChallengeField::ZERO;
    }
}

fn checked_mask_group_claim<const MESSAGE_LENGTH: usize>(
    covectors: &[Vec<CompactChallengeField>],
    messages: &[[CompactChallengeField; MESSAGE_LENGTH]],
) -> Result<CompactChallengeField, CompactWhirError> {
    if covectors.len() != messages.len()
        || covectors
            .iter()
            .any(|covector| covector.len() != MESSAGE_LENGTH)
    {
        return Err(CompactWhirError::InvalidRelation);
    }
    Ok(covectors
        .iter()
        .zip(messages)
        .flat_map(|(covector, message)| covector.iter().zip(message))
        .map(|(coefficient, value)| *coefficient * *value)
        .sum())
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

impl Drop for CompactWhirMaskedSumcheckRelation {
    fn drop(&mut self) {
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.source_claim = CompactChallengeField::ZERO;
        self.preceding_mask_claim = CompactChallengeField::ZERO;
    }
}

impl CompactWhirInitialSumcheckState {
    pub(crate) fn new<R: Rng>(
        relation: CompactWhirMaskedSumcheckRelation,
        configuration: &CompactWhirConfiguration,
        batch_ordinal: usize,
        mask_group_contract: CompactWhirMaskGroupContract,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let folding_factor = configuration.round_folding_factor(batch_ordinal);
        Self::new_with_folding_factor(relation, folding_factor, mask_group_contract, random_source)
    }

    fn new_with_folding_factor<R: Rng>(
        mut relation: CompactWhirMaskedSumcheckRelation,
        folding_factor: usize,
        mask_group_contract: CompactWhirMaskGroupContract,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let mask_group_shape = compact_whir_mask_group_shape(mask_group_contract)?;
        let source_element_count = match relation.authenticated_source_replay_element_count {
            None if !relation.source_evaluations.is_empty()
                && relation.source_evaluations.len() == relation.source_covector.len() =>
            {
                relation.source_evaluations.len()
            }
            Some(element_count)
                if relation.source_evaluations.is_empty()
                    && element_count == relation.source_covector.len() =>
            {
                element_count
            }
            _ => return Err(CompactWhirError::InvalidRelation),
        };
        if source_element_count == 0
            || !source_element_count.is_power_of_two()
            || folding_factor == 0
            || folding_factor > source_element_count.ilog2() as usize
            || mask_group_shape.width != folding_factor
            || mask_group_shape.shape.message_len != COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        if relation.source_claim + relation.preceding_mask_claim != relation.target {
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

        let authenticated_source_replay =
            relation
                .authenticated_source_replay_element_count
                .map(
                    |current_element_count| CompactWhirAuthenticatedSourceReplayState {
                        current_element_count,
                        folded_weight_offset: None,
                        residual_source_taken: false,
                    },
                );
        Ok(Self {
            source_evaluations: core::mem::take(&mut relation.source_evaluations),
            source_covector: core::mem::take(&mut relation.source_covector),
            authenticated_source_replay,
            detached_replayed_source_covector: None,
            source_claim: relation.source_claim,
            masked_target: relation.target,
            opening_batching_challenge: relation.input_binding_challenge,
            sumcheck_mask_messages,
            sumcheck_mask_encoding_randomness,
            sumcheck_mask_oracle,
            auxiliary_target,
            remaining_mask_endpoint_sum,
            preceding_mask_carry: relation.preceding_mask_claim,
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

    pub(crate) const fn authenticated_source_replay_required(&self) -> bool {
        matches!(
            self.authenticated_source_replay,
            Some(CompactWhirAuthenticatedSourceReplayState {
                folded_weight_offset: None,
                ..
            })
        )
    }

    /// Replays the authenticated main source only until the first folding
    /// challenge has reduced it. The first fold overwrites the original public
    /// covector with disjoint folded-source and folded-weight regions, avoiding
    /// a second full-size allocation without changing any sumcheck arithmetic
    /// or transcript bytes.
    pub(crate) fn poll_replaying_authenticated_source<SourceError>(
        &mut self,
        maximum_work_unit_count: u64,
        mut source_value: impl FnMut(u64) -> Result<CompactChallengeField, SourceError>,
    ) -> Result<
        CompactWhirInitialSumcheckPoll,
        CompactWhirInitialSumcheckSourceReplayError<SourceError>,
    > {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirError::InvalidWorkBudget.into());
        }
        let source_element_count = self
            .authenticated_source_replay
            .filter(|replay| replay.folded_weight_offset.is_none())
            .map(|replay| replay.current_element_count)
            .ok_or(CompactWhirError::WrongProverPhase)?;
        let half = source_element_count
            .checked_div(2)
            .filter(|count| *count != 0)
            .ok_or(CompactWhirError::InvalidRelation)?;
        match self.phase {
            CompactWhirInitialSumcheckPhase::ComputingRoundPolynomial {
                next_pair_ordinal,
                mut constant_coefficient,
                mut leading_coefficient,
            } => {
                let end = next_pair_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(half);
                for pair_ordinal in next_pair_ordinal..end {
                    let high_pair_ordinal = half
                        .checked_add(pair_ordinal)
                        .ok_or(CompactWhirError::CountOverflow)?;
                    let evaluation_low = source_value(
                        u64::try_from(pair_ordinal).map_err(|_| CompactWhirError::CountOverflow)?,
                    )
                    .map_err(CompactWhirInitialSumcheckSourceReplayError::Source)?;
                    let evaluation_high = source_value(
                        u64::try_from(high_pair_ordinal)
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    )
                    .map_err(CompactWhirInitialSumcheckSourceReplayError::Source)?;
                    let weight_low = self.source_covector[pair_ordinal];
                    let weight_high = self.source_covector[high_pair_ordinal];
                    constant_coefficient += evaluation_low * weight_low;
                    leading_coefficient +=
                        (evaluation_high - evaluation_low) * (weight_high - weight_low);
                }
                let polynomial_ready = end == half;
                if polynomial_ready {
                    self.complete_round_polynomial(constant_coefficient, leading_coefficient)?;
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::ComputingRoundPolynomial {
                        next_pair_ordinal: end,
                        constant_coefficient,
                        leading_coefficient,
                    };
                }
                Ok(CompactWhirInitialSumcheckPoll::RoundPolynomial {
                    round_ordinal: self.current_round_ordinal()?,
                    processed_work_unit_count: u64::try_from(end - next_pair_ordinal)
                        .map_err(|_| CompactWhirError::CountOverflow)?,
                    polynomial_ready,
                })
            }
            CompactWhirInitialSumcheckPhase::FoldingRound {
                challenge,
                next_pair_ordinal,
                constant_coefficient,
                leading_coefficient,
            } => {
                let end = next_pair_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(half);
                for pair_ordinal in next_pair_ordinal..end {
                    let high_pair_ordinal = half
                        .checked_add(pair_ordinal)
                        .ok_or(CompactWhirError::CountOverflow)?;
                    let evaluation_low = source_value(
                        u64::try_from(pair_ordinal).map_err(|_| CompactWhirError::CountOverflow)?,
                    )
                    .map_err(CompactWhirInitialSumcheckSourceReplayError::Source)?;
                    let evaluation_high = source_value(
                        u64::try_from(high_pair_ordinal)
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    )
                    .map_err(CompactWhirInitialSumcheckSourceReplayError::Source)?;
                    let weight_low = self.source_covector[pair_ordinal];
                    let weight_high = self.source_covector[high_pair_ordinal];
                    self.source_covector[pair_ordinal] =
                        evaluation_low + challenge * (evaluation_high - evaluation_low);
                    self.source_covector[high_pair_ordinal] =
                        weight_low + challenge * (weight_high - weight_low);
                }
                let round_complete = end == half;
                if round_complete {
                    self.complete_folded_round(
                        half,
                        constant_coefficient,
                        leading_coefficient,
                        challenge,
                    )?;
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::FoldingRound {
                        challenge,
                        next_pair_ordinal: end,
                        constant_coefficient,
                        leading_coefficient,
                    };
                }
                Ok(CompactWhirInitialSumcheckPoll::BoundRound {
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
            CompactWhirInitialSumcheckPhase::AwaitingCombinationChallenge
            | CompactWhirInitialSumcheckPhase::RoundPolynomialReady { .. }
            | CompactWhirInitialSumcheckPhase::ScalingWeights { .. }
            | CompactWhirInitialSumcheckPhase::Complete => {
                Err(CompactWhirError::WrongProverPhase.into())
            }
        }
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
                let source_element_count = match self.authenticated_source_replay {
                    None => self.source_evaluations.len(),
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        current_element_count,
                        folded_weight_offset: Some(_),
                        ..
                    }) => current_element_count,
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        folded_weight_offset: None,
                        ..
                    }) => return Err(CompactWhirError::WrongProverPhase),
                };
                let half = source_element_count
                    .checked_div(2)
                    .filter(|count| *count != 0)
                    .ok_or(CompactWhirError::InvalidRelation)?;
                let end = next_pair_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(half);
                match self.authenticated_source_replay {
                    None => {
                        for pair_ordinal in next_pair_ordinal..end {
                            let evaluation_low = self.source_evaluations[pair_ordinal];
                            let evaluation_high = self.source_evaluations[half + pair_ordinal];
                            let weight_low = self.source_covector[pair_ordinal];
                            let weight_high = self.source_covector[half + pair_ordinal];
                            constant_coefficient += evaluation_low * weight_low;
                            leading_coefficient +=
                                (evaluation_high - evaluation_low) * (weight_high - weight_low);
                        }
                    }
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        folded_weight_offset: Some(weight_offset),
                        ..
                    }) => {
                        for pair_ordinal in next_pair_ordinal..end {
                            let evaluation_low = self.source_covector[pair_ordinal];
                            let evaluation_high = self.source_covector[half + pair_ordinal];
                            let weight_low = self.source_covector[weight_offset + pair_ordinal];
                            let weight_high =
                                self.source_covector[weight_offset + half + pair_ordinal];
                            constant_coefficient += evaluation_low * weight_low;
                            leading_coefficient +=
                                (evaluation_high - evaluation_low) * (weight_high - weight_low);
                        }
                    }
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        folded_weight_offset: None,
                        ..
                    }) => return Err(CompactWhirError::WrongProverPhase),
                }
                let polynomial_ready = end == half;
                if polynomial_ready {
                    self.complete_round_polynomial(constant_coefficient, leading_coefficient)?;
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::ComputingRoundPolynomial {
                        next_pair_ordinal: end,
                        constant_coefficient,
                        leading_coefficient,
                    };
                }
                Ok(CompactWhirInitialSumcheckPoll::RoundPolynomial {
                    round_ordinal: self.current_round_ordinal()?,
                    processed_work_unit_count: u64::try_from(end - next_pair_ordinal)
                        .map_err(|_| CompactWhirError::CountOverflow)?,
                    polynomial_ready,
                })
            }
            CompactWhirInitialSumcheckPhase::FoldingRound {
                challenge,
                next_pair_ordinal,
                constant_coefficient,
                leading_coefficient,
            } => {
                let source_element_count = match self.authenticated_source_replay {
                    None => self.source_evaluations.len(),
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        current_element_count,
                        folded_weight_offset: Some(_),
                        ..
                    }) => current_element_count,
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        folded_weight_offset: None,
                        ..
                    }) => return Err(CompactWhirError::WrongProverPhase),
                };
                let half = source_element_count
                    .checked_div(2)
                    .filter(|count| *count != 0)
                    .ok_or(CompactWhirError::InvalidRelation)?;
                let end = next_pair_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(half);
                match self.authenticated_source_replay {
                    None => {
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
                    }
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        folded_weight_offset: Some(weight_offset),
                        ..
                    }) => {
                        for pair_ordinal in next_pair_ordinal..end {
                            let evaluation_low = self.source_covector[pair_ordinal];
                            let evaluation_high = self.source_covector[half + pair_ordinal];
                            let weight_low = self.source_covector[weight_offset + pair_ordinal];
                            let weight_high =
                                self.source_covector[weight_offset + half + pair_ordinal];
                            self.source_covector[pair_ordinal] =
                                evaluation_low + challenge * (evaluation_high - evaluation_low);
                            self.source_covector[half + pair_ordinal] = CompactChallengeField::ZERO;
                            self.source_covector[weight_offset + pair_ordinal] =
                                weight_low + challenge * (weight_high - weight_low);
                        }
                    }
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        folded_weight_offset: None,
                        ..
                    }) => return Err(CompactWhirError::WrongProverPhase),
                }
                let round_complete = end == half;
                if round_complete {
                    self.complete_folded_round(
                        half,
                        constant_coefficient,
                        leading_coefficient,
                        challenge,
                    )?;
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::FoldingRound {
                        challenge,
                        next_pair_ordinal: end,
                        constant_coefficient,
                        leading_coefficient,
                    };
                }
                Ok(CompactWhirInitialSumcheckPoll::BoundRound {
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
                let (weight_offset, weight_count) = match self.authenticated_source_replay {
                    None => (0, self.source_covector.len()),
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        current_element_count,
                        folded_weight_offset: Some(weight_offset),
                        ..
                    }) => (weight_offset, current_element_count),
                    Some(CompactWhirAuthenticatedSourceReplayState {
                        folded_weight_offset: None,
                        ..
                    }) => return Err(CompactWhirError::WrongProverPhase),
                };
                let end = next_element_ordinal
                    .saturating_add(maximum_work_unit_count)
                    .min(weight_count);
                for weight in &mut self.source_covector
                    [weight_offset + next_element_ordinal..weight_offset + end]
                {
                    *weight *= combination_challenge;
                }
                let scaling_complete = end == weight_count;
                if scaling_complete {
                    self.source_claim *= combination_challenge;
                    self.phase = CompactWhirInitialSumcheckPhase::Complete;
                } else {
                    self.phase = CompactWhirInitialSumcheckPhase::ScalingWeights {
                        next_element_ordinal: end,
                    };
                }
                Ok(CompactWhirInitialSumcheckPoll::WeightScaling {
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
        match self.authenticated_source_replay {
            None => Ok(&self.source_evaluations),
            Some(CompactWhirAuthenticatedSourceReplayState {
                current_element_count,
                folded_weight_offset: Some(_),
                residual_source_taken: false,
            }) => self
                .source_covector
                .get(..current_element_count)
                .ok_or(CompactWhirError::InvalidRelation),
            Some(_) => Err(CompactWhirError::WrongProverPhase),
        }
    }

    pub(crate) fn take_residual_source(
        &mut self,
    ) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
        if !self.is_complete() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let Some(replay) = self.authenticated_source_replay else {
            if self.source_evaluations.is_empty() {
                return Err(CompactWhirError::WrongProverPhase);
            }
            return Ok(core::mem::take(&mut self.source_evaluations));
        };
        let weight_offset = replay
            .folded_weight_offset
            .filter(|_| !replay.residual_source_taken)
            .ok_or(CompactWhirError::WrongProverPhase)?;
        let source_end = replay.current_element_count;
        let covector_end = weight_offset
            .checked_add(replay.current_element_count)
            .ok_or(CompactWhirError::CountOverflow)?;
        let source = self
            .source_covector
            .get(..source_end)
            .ok_or(CompactWhirError::InvalidRelation)?;
        let covector = self
            .source_covector
            .get(weight_offset..covector_end)
            .ok_or(CompactWhirError::InvalidRelation)?;
        let mut detached_source = Vec::new();
        detached_source
            .try_reserve_exact(source.len())
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        let mut detached_covector = Vec::new();
        detached_covector
            .try_reserve_exact(covector.len())
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        detached_source.extend_from_slice(source);
        detached_covector.extend_from_slice(covector);
        self.source_covector[..source_end].fill(CompactChallengeField::ZERO);
        drop(core::mem::take(&mut self.source_covector));
        self.authenticated_source_replay
            .as_mut()
            .ok_or(CompactWhirError::WrongProverPhase)?
            .residual_source_taken = true;
        self.detached_replayed_source_covector = Some(detached_covector);
        Ok(detached_source)
    }

    pub(crate) fn residual_covector(&self) -> Result<&[CompactChallengeField], CompactWhirError> {
        if !self.is_complete() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let Some(replay) = self.authenticated_source_replay else {
            return Ok(&self.source_covector);
        };
        if replay.residual_source_taken {
            return self
                .detached_replayed_source_covector
                .as_deref()
                .ok_or(CompactWhirError::WrongProverPhase);
        }
        let weight_offset = replay
            .folded_weight_offset
            .ok_or(CompactWhirError::WrongProverPhase)?;
        let covector_end = weight_offset
            .checked_add(replay.current_element_count)
            .ok_or(CompactWhirError::CountOverflow)?;
        self.source_covector
            .get(weight_offset..covector_end)
            .ok_or(CompactWhirError::InvalidRelation)
    }

    pub(crate) fn take_residual_covector(
        &mut self,
    ) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
        if !self.is_complete() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        if self.authenticated_source_replay.is_none() {
            if self.source_covector.is_empty() {
                return Err(CompactWhirError::WrongProverPhase);
            }
            return Ok(core::mem::take(&mut self.source_covector));
        }
        if !self
            .authenticated_source_replay
            .is_some_and(|replay| replay.residual_source_taken)
        {
            return Err(CompactWhirError::WrongProverPhase);
        }
        self.detached_replayed_source_covector
            .take()
            .ok_or(CompactWhirError::WrongProverPhase)
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

    pub(crate) fn residual_mask_claim(&self) -> Result<CompactChallengeField, CompactWhirError> {
        Ok(self.residual_preceding_mask_claim()?
            + self
                .past_mask_evaluations
                .iter()
                .copied()
                .sum::<CompactChallengeField>())
    }

    pub(crate) fn residual_target(&self) -> Result<CompactChallengeField, CompactWhirError> {
        Ok(self.residual_source_claim()? + self.residual_mask_claim()?)
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

    fn complete_round_polynomial(
        &mut self,
        constant_coefficient: CompactChallengeField,
        leading_coefficient: CompactChallengeField,
    ) -> Result<(), CompactWhirError> {
        let wire = self.assemble_round_wire(constant_coefficient, leading_coefficient)?;
        self.round_wires.push(wire.clone());
        self.pending_round_wire = Some(wire);
        self.phase = CompactWhirInitialSumcheckPhase::RoundPolynomialReady {
            constant_coefficient,
            leading_coefficient,
        };
        Ok(())
    }

    fn complete_folded_round(
        &mut self,
        folded_element_count: usize,
        constant_coefficient: CompactChallengeField,
        leading_coefficient: CompactChallengeField,
        challenge: CompactChallengeField,
    ) -> Result<(), CompactWhirError> {
        match self.authenticated_source_replay.as_mut() {
            None => {
                self.source_evaluations.truncate(folded_element_count);
                self.source_covector.truncate(folded_element_count);
            }
            Some(replay) => {
                if replay.folded_weight_offset.is_none() {
                    replay.folded_weight_offset = Some(folded_element_count);
                }
                replay.current_element_count = folded_element_count;
            }
        }
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
        Ok(())
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
        if let Some(replay) = self.authenticated_source_replay {
            let retained_secret_element_count = if replay.folded_weight_offset.is_some() {
                replay.current_element_count
            } else if let CompactWhirInitialSumcheckPhase::FoldingRound {
                next_pair_ordinal, ..
            } = self.phase
            {
                next_pair_ordinal
            } else {
                0
            };
            let retained_secret_element_count =
                retained_secret_element_count.min(self.source_covector.len());
            self.source_covector[..retained_secret_element_count].fill(CompactChallengeField::ZERO);
        }
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
    pub(crate) fn new_from_base_source<R: Rng>(
        source_evaluations: Vec<CompactChallengeField>,
        mut previous_encoding_randomness: Vec<Goldilocks>,
        folding_challenges: &[CompactChallengeField],
        previous_source_contract: CompactWhirFoldContract,
        next_source_contract: CompactWhirFoldContract,
        switch_mask_contract: CompactWhirMaskGroupContract,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let mut promoted_randomness = Vec::new();
        promoted_randomness
            .try_reserve_exact(previous_encoding_randomness.len())
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        promoted_randomness.extend(
            previous_encoding_randomness
                .iter()
                .copied()
                .map(CompactChallengeField::from),
        );
        previous_encoding_randomness.fill(Goldilocks::ZERO);
        Self::new_from_extension_source(
            source_evaluations,
            promoted_randomness,
            folding_challenges,
            previous_source_contract,
            next_source_contract,
            switch_mask_contract,
            random_source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_from_extension_source<R: Rng>(
        source_evaluations: Vec<CompactChallengeField>,
        previous_encoding_randomness: Vec<CompactChallengeField>,
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
            folded_source_openings: None,
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
                    self.folded_previous_randomness[coordinate_ordinal] +=
                        weight * self.previous_encoding_randomness[element_ordinal];
                }
                let processed_work_unit_count =
                    u64::try_from(end - self.next_randomness_element_ordinal)
                        .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_randomness_element_ordinal = end;
                let fold_complete = end == self.previous_encoding_randomness.len();
                if fold_complete {
                    self.previous_encoding_randomness
                        .fill(CompactChallengeField::ZERO);
                    self.previous_encoding_randomness.clear();
                    self.folding_weights.fill(CompactChallengeField::ZERO);
                    self.folding_weights.clear();
                    self.switch_mask_oracle = Some(CompactWhirEncodedMaskGroup::encode(
                        self.switch_mask_shape,
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

    pub(crate) fn source_encoding_randomness(&self) -> &[CompactChallengeField] {
        self.source_oracle.encoding_randomness()
    }

    pub(crate) fn begin_source_opening_replay(
        &mut self,
        row_ordinals: &[usize],
    ) -> Result<(), CompactWhirError> {
        self.source_oracle.begin_opening_replay(row_ordinals)
    }

    pub(crate) const fn can_begin_source_opening_replay(&self) -> bool {
        self.source_oracle.can_begin_opening_replay()
    }

    pub(crate) const fn source_opening_replay_complete(&self) -> bool {
        self.source_oracle.opening_replay_complete()
    }

    pub(crate) fn finish_source_opening_replay(&mut self) -> Result<(), CompactWhirError> {
        if !self.source_opening_replay_complete() || self.source_evaluations.is_empty() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.source_evaluations.clear();
        self.source_oracle.finish_opening_replay()
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
        folded_source_openings: Vec<CompactChallengeField>,
    ) -> Result<(), CompactWhirError> {
        if self.phase != CompactWhirCodeSwitchPhase::Ready
            || self.query_positions.is_some()
            || self.combination_challenge.is_some()
            || self.folded_source_openings.is_some()
            || query_positions.len() != self.expected_query_count
            || folded_source_openings.len() != self.expected_query_count
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
        self.folded_source_openings = Some(folded_source_openings);
        Ok(())
    }

    pub(crate) fn verifier_move_is_bound(&self) -> bool {
        self.query_positions.is_some()
            && self.combination_challenge.is_some()
            && self.folded_source_openings.is_some()
    }

    pub(crate) fn take_relation_inputs(
        &mut self,
    ) -> Result<CompactWhirBoundCodeSwitchInputs, CompactWhirError> {
        if !self.verifier_move_is_bound() || self.source_evaluations.is_empty() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let mut source_evaluations = Vec::new();
        source_evaluations
            .try_reserve_exact(self.source_evaluations.len())
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        source_evaluations.extend_from_slice(&self.source_evaluations);
        Ok(CompactWhirBoundCodeSwitchInputs {
            source_evaluations,
            switch_mask_message: self.folded_previous_randomness.clone(),
            query_positions: self
                .query_positions
                .clone()
                .ok_or(CompactWhirError::WrongProverPhase)?,
            folded_source_openings: self
                .folded_source_openings
                .take()
                .ok_or(CompactWhirError::WrongProverPhase)?,
            combination_challenge: self
                .combination_challenge
                .ok_or(CompactWhirError::WrongProverPhase)?,
            previous_source_height: self.previous_source_height,
        })
    }
}

impl Drop for CompactWhirBoundCodeSwitchInputs {
    fn drop(&mut self) {
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.switch_mask_message.fill(CompactChallengeField::ZERO);
        self.folded_source_openings
            .fill(CompactChallengeField::ZERO);
        self.combination_challenge = CompactChallengeField::ZERO;
    }
}

impl CompactWhirCodeSwitchRelationPreparation {
    pub(crate) fn new(
        mut code_switch: CompactWhirBoundCodeSwitchInputs,
        source_covector: Vec<CompactChallengeField>,
        source_claim: CompactChallengeField,
        preceding_mask_claim: CompactChallengeField,
        target: CompactChallengeField,
    ) -> Result<Self, CompactWhirError> {
        if code_switch.source_evaluations.is_empty()
            || code_switch.source_evaluations.len() != source_covector.len()
            || code_switch.switch_mask_message.is_empty()
            || code_switch.query_positions.is_empty()
            || code_switch.query_positions.len() != code_switch.folded_source_openings.len()
            || code_switch.previous_source_height == 0
            || !code_switch.previous_source_height.is_power_of_two()
            || code_switch
                .query_positions
                .windows(2)
                .any(|positions| positions[0] >= positions[1])
            || code_switch
                .query_positions
                .last()
                .is_none_or(|position| *position >= code_switch.previous_source_height)
            || source_claim + preceding_mask_claim != target
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        let log_domain_size = usize::try_from(code_switch.previous_source_height.ilog2())
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let domain_generator =
            CompactChallengeField::from(Goldilocks::two_adic_generator(log_domain_size));
        let first_query_position = u64::try_from(code_switch.query_positions[0])
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let query_point = domain_generator.exp_u64(first_query_position);
        let combination_challenge = code_switch.combination_challenge;
        Ok(Self {
            source_evaluations: core::mem::take(&mut code_switch.source_evaluations),
            source_covector,
            source_claim,
            preceding_mask_claim,
            target,
            switch_mask_message: core::mem::take(&mut code_switch.switch_mask_message),
            query_positions: core::mem::take(&mut code_switch.query_positions),
            folded_source_openings: core::mem::take(&mut code_switch.folded_source_openings),
            combination_challenge,
            domain_generator,
            query_ordinal: 0,
            next_query_coordinate_ordinal: 0,
            query_coefficient: combination_challenge,
            query_point,
            query_power: CompactChallengeField::ONE,
            phase: CompactWhirCodeSwitchRelationPreparationPhase::AccumulatingQueryRelations,
        })
    }

    pub(crate) fn poll(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirCodeSwitchRelationPreparationPoll, CompactWhirError> {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirError::InvalidWorkBudget);
        }
        if self.phase == CompactWhirCodeSwitchRelationPreparationPhase::Complete {
            return Ok(CompactWhirCodeSwitchRelationPreparationPoll::Complete);
        }
        let coordinate_count_per_query = self
            .source_evaluations
            .len()
            .checked_add(self.switch_mask_message.len())
            .ok_or(CompactWhirError::CountOverflow)?;
        let mut processed_work_unit_count = 0_usize;
        while processed_work_unit_count < maximum_work_unit_count
            && self.query_ordinal < self.query_positions.len()
        {
            let coordinate_ordinal = self.next_query_coordinate_ordinal;
            let weighted_power = self.query_coefficient * self.query_power;
            if coordinate_ordinal < self.source_evaluations.len() {
                self.source_covector[coordinate_ordinal] += weighted_power;
                self.source_claim += weighted_power * self.source_evaluations[coordinate_ordinal];
            } else {
                let mask_coordinate_ordinal = coordinate_ordinal - self.source_evaluations.len();
                self.preceding_mask_claim +=
                    weighted_power * self.switch_mask_message[mask_coordinate_ordinal];
            }
            self.query_power *= self.query_point;
            self.next_query_coordinate_ordinal += 1;
            processed_work_unit_count += 1;

            if self.next_query_coordinate_ordinal == coordinate_count_per_query {
                self.target +=
                    self.query_coefficient * self.folded_source_openings[self.query_ordinal];
                self.query_ordinal += 1;
                self.next_query_coordinate_ordinal = 0;
                self.query_coefficient *= self.combination_challenge;
                self.query_power = CompactChallengeField::ONE;
                if self.query_ordinal < self.query_positions.len() {
                    self.query_point = self.domain_generator.exp_u64(
                        u64::try_from(self.query_positions[self.query_ordinal])
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    );
                }
            }
        }
        let relation_complete = self.query_ordinal == self.query_positions.len();
        if relation_complete {
            if self.next_query_coordinate_ordinal != 0
                || self.source_claim + self.preceding_mask_claim != self.target
            {
                return Err(CompactWhirError::InvalidRelation);
            }
            self.phase = CompactWhirCodeSwitchRelationPreparationPhase::Complete;
        }
        Ok(
            CompactWhirCodeSwitchRelationPreparationPoll::QueryRelationStepCompleted {
                processed_work_unit_count: u64::try_from(processed_work_unit_count)
                    .map_err(|_| CompactWhirError::CountOverflow)?,
                relation_complete,
            },
        )
    }

    pub(crate) fn finish(mut self) -> Result<CompactWhirMaskedSumcheckRelation, CompactWhirError> {
        if self.phase != CompactWhirCodeSwitchRelationPreparationPhase::Complete
            || self.source_evaluations.len() != self.source_covector.len()
            || self.source_claim + self.preceding_mask_claim != self.target
        {
            return Err(CompactWhirError::WrongProverPhase);
        }
        Ok(CompactWhirMaskedSumcheckRelation {
            source_evaluations: core::mem::take(&mut self.source_evaluations),
            authenticated_source_replay_element_count: None,
            source_covector: core::mem::take(&mut self.source_covector),
            source_claim: self.source_claim,
            target: self.target,
            preceding_mask_claim: self.preceding_mask_claim,
            input_binding_challenge: self.combination_challenge,
        })
    }
}

impl Drop for CompactWhirCodeSwitchRelationPreparation {
    fn drop(&mut self) {
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.source_covector.fill(CompactChallengeField::ZERO);
        self.source_claim = CompactChallengeField::ZERO;
        self.preceding_mask_claim = CompactChallengeField::ZERO;
        self.target = CompactChallengeField::ZERO;
        self.switch_mask_message.fill(CompactChallengeField::ZERO);
        self.folded_source_openings
            .fill(CompactChallengeField::ZERO);
        self.combination_challenge = CompactChallengeField::ZERO;
        self.query_coefficient = CompactChallengeField::ZERO;
        self.query_point = CompactChallengeField::ZERO;
        self.query_power = CompactChallengeField::ZERO;
    }
}

impl Drop for CompactWhirCodeSwitchState {
    fn drop(&mut self) {
        self.source_evaluations.fill(CompactChallengeField::ZERO);
        self.previous_encoding_randomness
            .fill(CompactChallengeField::ZERO);
        self.folding_weights.fill(CompactChallengeField::ZERO);
        self.folded_previous_randomness
            .fill(CompactChallengeField::ZERO);
        self.switch_mask_encoding_randomness
            .fill(CompactChallengeField::ZERO);
    }
}

impl CompactWhirBaseMaskInput {
    pub(crate) fn new(
        contract: CompactWhirMaskGroupContract,
        messages: Vec<Vec<CompactChallengeField>>,
        randomness: Vec<Vec<CompactChallengeField>>,
        covectors: Vec<Vec<CompactChallengeField>>,
    ) -> Result<Self, CompactWhirError> {
        let width = usize::try_from(contract.width).map_err(|_| CompactWhirError::CountOverflow)?;
        let message_length = usize::try_from(contract.message_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let randomness_length = usize::try_from(contract.randomness_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        if width == 0
            || messages.len() != width
            || randomness.len() != width
            || covectors.len() != width
            || messages
                .iter()
                .any(|message| message.len() != message_length)
            || randomness
                .iter()
                .any(|values| values.len() != randomness_length)
            || covectors
                .iter()
                .any(|covector| covector.len() != message_length)
        {
            return Err(CompactWhirError::InvalidRelation);
        }
        compact_whir_mask_group_shape(contract)?;
        Ok(Self {
            contract,
            messages,
            randomness,
            covectors,
        })
    }
}

impl CompactWhirBaseCaseState {
    pub(crate) fn new<R: Rng>(
        relation: CompactWhirBaseRelation,
        previous_source_randomness: &[CompactChallengeField],
        final_fold_contract: CompactWhirFoldContract,
        final_folding_challenges: &[CompactChallengeField],
        mask_inputs: Vec<CompactWhirBaseMaskInput>,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let CompactWhirBaseRelation {
            source_message,
            source_covector,
            target,
        } = relation;
        let source_message_length = usize::try_from(final_fold_contract.message_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let final_randomness_length = usize::try_from(final_fold_contract.hiding_randomness_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let expected_width = 1_usize
            .checked_shl(
                u32::try_from(final_folding_challenges.len())
                    .map_err(|_| CompactWhirError::CountOverflow)?,
            )
            .ok_or(CompactWhirError::CountOverflow)?;
        if source_message_length == 0
            || source_message.len() != source_message_length
            || source_covector.len() != source_message_length
            || usize::try_from(final_fold_contract.oracle_width).ok() != Some(expected_width)
            || previous_source_randomness.len()
                != final_randomness_length
                    .checked_mul(expected_width)
                    .ok_or(CompactWhirError::CountOverflow)?
            || final_fold_contract.query_count != final_fold_contract.hiding_randomness_length
            || final_fold_contract.batch_ordinal != 3
            || mask_inputs.is_empty()
        {
            return Err(CompactWhirError::InvalidRelation);
        }

        let source_randomness = fold_compact_whir_limb_major_values(
            previous_source_randomness,
            final_randomness_length,
            final_folding_challenges,
        )?;
        let mut carried_claim = compact_whir_dot_product(&source_message, &source_covector)?;
        for input in &mask_inputs {
            for (message, covector) in input.messages.iter().zip(&input.covectors) {
                carried_claim += compact_whir_dot_product(message, covector)?;
            }
        }
        if carried_claim != target {
            return Err(CompactWhirError::InvalidRelation);
        }

        let mut fresh_source_message = Vec::new();
        fresh_source_message
            .try_reserve_exact(source_message_length)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        for _coordinate_ordinal in 0..source_message_length {
            fresh_source_message.push(random_source.random());
        }
        let fresh_source_oracle =
            CompactWhirRecomputableExtensionInitialOracle::sample_for_base_case_contract(
                final_fold_contract,
                random_source,
            )?;

        let mut fresh_claim = compact_whir_dot_product(&fresh_source_message, &source_covector)?;
        let mut mask_groups = Vec::new();
        mask_groups
            .try_reserve_exact(mask_inputs.len())
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        for mut input in mask_inputs {
            let shape = compact_whir_mask_group_shape(input.contract)?;
            let mut fresh_messages = Vec::new();
            let mut fresh_randomness = Vec::new();
            fresh_messages
                .try_reserve_exact(shape.width)
                .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
            fresh_randomness
                .try_reserve_exact(shape.width)
                .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
            for _lane_ordinal in 0..shape.width {
                let mut message = Vec::new();
                message
                    .try_reserve_exact(shape.shape.message_len)
                    .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
                for _coordinate_ordinal in 0..shape.shape.message_len {
                    message.push(random_source.random());
                }
                let mut randomness = Vec::new();
                randomness
                    .try_reserve_exact(shape.shape.randomness_len)
                    .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
                for _coordinate_ordinal in 0..shape.shape.randomness_len {
                    randomness.push(random_source.random());
                }
                fresh_messages.push(message);
                fresh_randomness.push(randomness);
            }
            for (message, covector) in fresh_messages.iter().zip(&input.covectors) {
                fresh_claim += compact_whir_dot_product(message, covector)?;
            }
            let fresh_oracle =
                CompactWhirEncodedMaskGroup::encode(shape, &fresh_messages, &fresh_randomness)?;
            mask_groups.push(CompactWhirBaseMaskState {
                carried_messages: core::mem::take(&mut input.messages),
                carried_randomness: core::mem::take(&mut input.randomness),
                covectors: core::mem::take(&mut input.covectors),
                fresh_messages,
                fresh_randomness,
                fresh_oracle,
            });
        }

        Ok(Self {
            source_message,
            source_randomness,
            source_covector,
            target,
            fresh_source_message,
            fresh_source_oracle,
            mask_groups,
            fresh_claim,
            combination_challenge: None,
            blinded_response_values: None,
        })
    }

    pub(crate) const fn fresh_claim(&self) -> CompactChallengeField {
        self.fresh_claim
    }

    pub(crate) const fn fresh_source_oracle(
        &self,
    ) -> &CompactWhirRecomputableExtensionInitialOracle {
        &self.fresh_source_oracle
    }

    pub(crate) fn fresh_mask_oracle(
        &self,
        group_ordinal: usize,
    ) -> Option<&CompactWhirEncodedMaskGroup> {
        self.mask_groups
            .get(group_ordinal)
            .map(|group| &group.fresh_oracle)
    }

    pub(crate) const fn fresh_mask_group_count(&self) -> usize {
        self.mask_groups.len()
    }

    pub(crate) fn poll_fresh_source_oracle(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirRecomputableExtensionPoll, CompactWhirError> {
        let source = &self.fresh_source_message;
        self.fresh_source_oracle
            .poll(maximum_work_unit_count, |source_ordinal| {
                source
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

    pub(crate) fn fresh_source_row(
        &self,
        row_ordinal: usize,
    ) -> Result<&[CompactChallengeField], CompactWhirError> {
        self.fresh_source_oracle.response_row(row_ordinal)
    }

    pub(crate) fn mark_fresh_source_row_supplied(
        &mut self,
        row_ordinal: usize,
    ) -> Result<(), CompactWhirError> {
        self.fresh_source_oracle
            .mark_response_row_supplied(row_ordinal)
    }

    pub(crate) fn begin_fresh_source_opening_replay(
        &mut self,
        row_ordinals: &[usize],
    ) -> Result<(), CompactWhirError> {
        self.fresh_source_oracle.begin_opening_replay(row_ordinals)
    }

    pub(crate) const fn fresh_source_opening_replay_complete(&self) -> bool {
        self.fresh_source_oracle.opening_replay_complete()
    }

    pub(crate) fn bind_combination_challenge(
        &mut self,
        challenge: CompactChallengeField,
    ) -> Result<(), CompactWhirError> {
        if self.combination_challenge.is_some()
            || self.blinded_response_values.is_some()
            || !self.fresh_source_oracle.can_begin_opening_replay()
        {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let total_mask_reveal_count =
            self.mask_groups.iter().try_fold(0_usize, |count, group| {
                group
                    .fresh_messages
                    .iter()
                    .zip(&group.fresh_randomness)
                    .try_fold(count, |count, (message, randomness)| {
                        count
                            .checked_add(message.len())
                            .and_then(|count| count.checked_add(randomness.len()))
                            .ok_or(CompactWhirError::CountOverflow)
                    })
            })?;
        let total_reveal_count = self
            .source_message
            .len()
            .checked_add(self.source_randomness.len())
            .and_then(|count| count.checked_add(total_mask_reveal_count))
            .ok_or(CompactWhirError::CountOverflow)?;
        let mut blinded = Vec::new();
        blinded
            .try_reserve_exact(total_reveal_count)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;

        let mut combined_claim = CompactChallengeField::ZERO;
        for ((fresh, carried), coefficient) in self
            .fresh_source_message
            .iter()
            .zip(&self.source_message)
            .zip(&self.source_covector)
        {
            let value = *fresh + challenge * *carried;
            blinded.push(value);
            combined_claim += value * *coefficient;
        }
        for (fresh, carried) in self
            .fresh_source_oracle
            .encoding_randomness()
            .iter()
            .zip(&self.source_randomness)
        {
            blinded.push(*fresh + challenge * *carried);
        }
        for group in &self.mask_groups {
            for (
                ((fresh_message, fresh_randomness), carried_message),
                (carried_randomness, covector),
            ) in group
                .fresh_messages
                .iter()
                .zip(&group.fresh_randomness)
                .zip(&group.carried_messages)
                .zip(group.carried_randomness.iter().zip(&group.covectors))
            {
                for ((fresh, carried), coefficient) in
                    fresh_message.iter().zip(carried_message).zip(covector)
                {
                    let value = *fresh + challenge * *carried;
                    blinded.push(value);
                    combined_claim += value * *coefficient;
                }
                blinded.extend(
                    fresh_randomness
                        .iter()
                        .zip(carried_randomness)
                        .map(|(fresh, carried)| *fresh + challenge * *carried),
                );
            }
        }
        if blinded.len() != total_reveal_count
            || combined_claim != self.fresh_claim + challenge * self.target
        {
            blinded.fill(CompactChallengeField::ZERO);
            return Err(CompactWhirError::InvalidRelation);
        }

        self.source_message.fill(CompactChallengeField::ZERO);
        self.source_message.clear();
        self.source_randomness.fill(CompactChallengeField::ZERO);
        self.source_randomness.clear();
        self.target = CompactChallengeField::ZERO;
        for group in &mut self.mask_groups {
            for values in &mut group.carried_messages {
                values.fill(CompactChallengeField::ZERO);
            }
            group.carried_messages.clear();
            for values in &mut group.carried_randomness {
                values.fill(CompactChallengeField::ZERO);
            }
            group.carried_randomness.clear();
        }
        self.combination_challenge = Some(challenge);
        self.blinded_response_values = Some(blinded);
        Ok(())
    }

    pub(crate) fn blinded_response_values(
        &self,
    ) -> Result<&[CompactChallengeField], CompactWhirError> {
        self.blinded_response_values
            .as_deref()
            .ok_or(CompactWhirError::WrongProverPhase)
    }

    pub(crate) fn base_claim_coefficients(
        &self,
    ) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
        if self.source_covector.is_empty() || self.mask_groups.is_empty() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let coefficient_count =
            self.mask_groups
                .iter()
                .try_fold(self.source_covector.len(), |count, group| {
                    group.covectors.iter().try_fold(count, |count, covector| {
                        count
                            .checked_add(covector.len())
                            .ok_or(CompactWhirError::CountOverflow)
                    })
                })?;
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(coefficient_count)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        coefficients.extend_from_slice(&self.source_covector);
        for group in &self.mask_groups {
            for covector in &group.covectors {
                coefficients.extend_from_slice(covector);
            }
        }
        Ok(coefficients)
    }

    pub(crate) fn fresh_source_mirror_coefficients(
        &self,
    ) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
        if self.combination_challenge.is_none() || self.fresh_source_message.is_empty() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let coefficient_count = self
            .fresh_source_message
            .len()
            .checked_add(self.fresh_source_oracle.encoding_randomness().len())
            .ok_or(CompactWhirError::CountOverflow)?;
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(coefficient_count)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        coefficients.extend_from_slice(&self.fresh_source_message);
        coefficients.extend_from_slice(self.fresh_source_oracle.encoding_randomness());
        Ok(coefficients)
    }

    pub(crate) fn fresh_mask_mirror_coefficients(
        &self,
        group_ordinal: usize,
    ) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
        if self.combination_challenge.is_none() {
            return Err(CompactWhirError::WrongProverPhase);
        }
        let group = self
            .mask_groups
            .get(group_ordinal)
            .ok_or(CompactWhirError::InvalidRelation)?;
        let coefficient_count = group
            .fresh_messages
            .iter()
            .zip(&group.fresh_randomness)
            .try_fold(0_usize, |count, (message, randomness)| {
                count
                    .checked_add(message.len())
                    .and_then(|count| count.checked_add(randomness.len()))
                    .ok_or(CompactWhirError::CountOverflow)
            })?;
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(coefficient_count)
            .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
        for (message, randomness) in group.fresh_messages.iter().zip(&group.fresh_randomness) {
            coefficients.extend_from_slice(message);
            coefficients.extend_from_slice(randomness);
        }
        Ok(coefficients)
    }

    pub(crate) fn finish_final_query_opening_replay(&mut self) -> Result<(), CompactWhirError> {
        if !self.fresh_source_oracle.opening_replay_complete()
            || self.combination_challenge.is_none()
            || self.blinded_response_values.is_none()
        {
            return Err(CompactWhirError::WrongProverPhase);
        }
        self.fresh_source_oracle.finish_opening_replay()?;
        self.fresh_source_message.fill(CompactChallengeField::ZERO);
        self.fresh_source_message.clear();
        self.source_covector.fill(CompactChallengeField::ZERO);
        self.source_covector.clear();
        for group in &mut self.mask_groups {
            for values in &mut group.covectors {
                values.fill(CompactChallengeField::ZERO);
            }
            group.covectors.clear();
            for values in &mut group.fresh_messages {
                values.fill(CompactChallengeField::ZERO);
            }
            group.fresh_messages.clear();
            for values in &mut group.fresh_randomness {
                values.fill(CompactChallengeField::ZERO);
            }
            group.fresh_randomness.clear();
        }
        Ok(())
    }
}

impl Drop for CompactWhirBaseCaseState {
    fn drop(&mut self) {
        self.source_message.fill(CompactChallengeField::ZERO);
        self.source_randomness.fill(CompactChallengeField::ZERO);
        self.source_covector.fill(CompactChallengeField::ZERO);
        self.target = CompactChallengeField::ZERO;
        self.fresh_source_message.fill(CompactChallengeField::ZERO);
        for group in &mut self.mask_groups {
            for values in &mut group.carried_messages {
                values.fill(CompactChallengeField::ZERO);
            }
            for values in &mut group.carried_randomness {
                values.fill(CompactChallengeField::ZERO);
            }
            for values in &mut group.covectors {
                values.fill(CompactChallengeField::ZERO);
            }
            for values in &mut group.fresh_messages {
                values.fill(CompactChallengeField::ZERO);
            }
            for values in &mut group.fresh_randomness {
                values.fill(CompactChallengeField::ZERO);
            }
        }
        if let Some(values) = self.blinded_response_values.as_mut() {
            values.fill(CompactChallengeField::ZERO);
        }
        self.fresh_claim = CompactChallengeField::ZERO;
        self.combination_challenge = None;
    }
}

pub(crate) fn fold_compact_whir_limb_major_values(
    values: &[CompactChallengeField],
    folded_length: usize,
    folding_challenges: &[CompactChallengeField],
) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
    let limb_count = 1_usize
        .checked_shl(
            u32::try_from(folding_challenges.len()).map_err(|_| CompactWhirError::CountOverflow)?,
        )
        .ok_or(CompactWhirError::CountOverflow)?;
    if folded_length == 0
        || values.len()
            != folded_length
                .checked_mul(limb_count)
                .ok_or(CompactWhirError::CountOverflow)?
    {
        return Err(CompactWhirError::InvalidRelation);
    }
    let weights = Poly::new_from_point(folding_challenges, CompactChallengeField::ONE).into_evals();
    if weights.len() != limb_count {
        return Err(CompactWhirError::InvalidRelation);
    }
    let mut folded = allocate_zero_extension_values(folded_length)?;
    for (limb, weight) in values.chunks_exact(folded_length).zip(weights) {
        for (destination, source) in folded.iter_mut().zip(limb) {
            *destination += weight * *source;
        }
    }
    Ok(folded)
}

fn compact_whir_dot_product(
    left: &[CompactChallengeField],
    right: &[CompactChallengeField],
) -> Result<CompactChallengeField, CompactWhirError> {
    if left.len() != right.len() {
        return Err(CompactWhirError::InvalidRelation);
    }
    Ok(left
        .iter()
        .zip(right)
        .map(|(left, right)| *left * *right)
        .sum())
}

pub(crate) fn fold_compact_whir_query_major_source_openings(
    query_outputs: &[CompactChallengeField],
    query_count: usize,
    folding_challenges: &[CompactChallengeField],
) -> Result<Vec<CompactChallengeField>, CompactWhirError> {
    let opening_width = 1_usize
        .checked_shl(
            u32::try_from(folding_challenges.len()).map_err(|_| CompactWhirError::CountOverflow)?,
        )
        .ok_or(CompactWhirError::CountOverflow)?;
    if query_count == 0
        || opening_width == 0
        || query_outputs.len()
            != query_count
                .checked_mul(opening_width)
                .ok_or(CompactWhirError::CountOverflow)?
    {
        return Err(CompactWhirError::InvalidRelation);
    }
    let folding_weights =
        Poly::new_from_point(folding_challenges, CompactChallengeField::ONE).into_evals();
    if folding_weights.len() != opening_width {
        return Err(CompactWhirError::InvalidRelation);
    }
    let mut folded_openings = Vec::new();
    folded_openings
        .try_reserve_exact(query_count)
        .map_err(|_| CompactWhirError::AllocationLimitExceeded)?;
    for row in query_outputs.chunks_exact(opening_width) {
        folded_openings.push(
            row.iter()
                .copied()
                .zip(&folding_weights)
                .map(|(value, weight)| value * *weight)
                .sum(),
        );
    }
    Ok(folded_openings)
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

    pub(crate) fn sample_for_base_case_contract<R: Rng>(
        contract: CompactWhirFoldContract,
        random_source: &mut R,
    ) -> Result<Self, CompactWhirError> {
        let source_height = usize::try_from(contract.message_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        let encoded_height =
            usize::try_from(contract.block_length).map_err(|_| CompactWhirError::CountOverflow)?;
        let randomness_rows = usize::try_from(contract.hiding_randomness_length)
            .map_err(|_| CompactWhirError::CountOverflow)?;
        Self::sample_with_dimensions(
            source_height,
            encoded_height,
            1,
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
            opening_values: Vec::new(),
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
                    || !self.opening_row_ordinals.is_empty()
                    || !self.opening_values.is_empty()
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
                self.next_response_row = self.stripe_first_row;
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
                    if self.opening_row_ordinals.is_empty() {
                        self.next_capture_row = self.stripe_first_row;
                        self.stage = CompactWhirRecomputableExtensionStage::CaptureStripe;
                    } else {
                        self.next_capture_row = 0;
                        self.stage = CompactWhirRecomputableExtensionStage::CaptureOpeningRows;
                    }
                }
                Ok(
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                        processed_work_unit_count: u64::try_from(processed_work_unit_count.max(1))
                            .map_err(|_| CompactWhirError::CountOverflow)?,
                    },
                )
            }
            CompactWhirRecomputableExtensionStage::CaptureStripe => {
                if !self.opening_row_ordinals.is_empty() || !self.opening_values.is_empty() {
                    return Err(CompactWhirError::InvalidEncodedMatrix.into());
                }
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
            CompactWhirRecomputableExtensionStage::CaptureOpeningRows => {
                if self.opening_row_ordinals.is_empty()
                    || self.opening_values.len()
                        != self
                            .opening_row_ordinals
                            .len()
                            .checked_mul(self.width)
                            .ok_or(CompactWhirError::CountOverflow)?
                {
                    return Err(CompactWhirError::InvalidEncodedMatrix.into());
                }
                let end = self
                    .next_capture_row
                    .saturating_add(maximum_work_unit_count)
                    .min(self.opening_row_ordinals.len());
                let encoded_column_values = self
                    .encoded_column_values
                    .as_ref()
                    .ok_or(CompactWhirError::InvalidEncodedMatrix)?;
                for opening_row_offset in self.next_capture_row..end {
                    let encoded_row = self.opening_row_ordinals[opening_row_offset];
                    let destination = opening_row_offset
                        .checked_mul(self.width)
                        .and_then(|offset| offset.checked_add(self.current_column_ordinal))
                        .ok_or(CompactWhirError::CountOverflow)?;
                    self.opening_values[destination] = *encoded_column_values
                        .get(encoded_row)
                        .ok_or(CompactWhirError::InvalidEncodedMatrix)?;
                }
                let processed_work_unit_count = u64::try_from(end - self.next_capture_row)
                    .map_err(|_| CompactWhirError::CountOverflow)?;
                self.next_capture_row = end;
                if end == self.opening_row_ordinals.len() {
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
                        self.next_response_row = self.opening_row_ordinals[0];
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
                    first_row: u64::try_from(if self.opening_row_ordinals.is_empty() {
                        self.stripe_first_row
                    } else {
                        self.next_response_row
                    })
                    .map_err(|_| CompactWhirError::CountOverflow)?,
                    row_count: u64::try_from(if self.opening_row_ordinals.is_empty() {
                        self.stripe_end_row - self.stripe_first_row
                    } else {
                        1
                    })
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
        if self.stage == CompactWhirRecomputableExtensionStage::StripeReady
            && !self.opening_row_ordinals.is_empty()
        {
            if self
                .opening_row_ordinals
                .get(self.next_opening_row_offset)
                .copied()
                != Some(row_ordinal)
            {
                return Err(CompactWhirError::InvalidEncodedMatrix);
            }
            let first_value = self
                .next_opening_row_offset
                .checked_mul(self.width)
                .ok_or(CompactWhirError::CountOverflow)?;
            let end_value = first_value
                .checked_add(self.width)
                .ok_or(CompactWhirError::CountOverflow)?;
            return self
                .opening_values
                .get(first_value..end_value)
                .ok_or(CompactWhirError::InvalidEncodedMatrix);
        }
        if self.stage != CompactWhirRecomputableExtensionStage::StripeReady
            || row_ordinal != self.next_response_row
            || !(self.stripe_first_row..self.stripe_end_row).contains(&row_ordinal)
            || !self.opening_row_ordinals.is_empty()
            || !self.opening_values.is_empty()
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
        if self.stage == CompactWhirRecomputableExtensionStage::StripeReady
            && !self.opening_row_ordinals.is_empty()
        {
            if self
                .opening_row_ordinals
                .get(self.next_opening_row_offset)
                .copied()
                != Some(row_ordinal)
            {
                return Err(CompactWhirError::InvalidEncodedMatrix);
            }
            let first_value = self
                .next_opening_row_offset
                .checked_mul(self.width)
                .ok_or(CompactWhirError::CountOverflow)?;
            let end_value = first_value
                .checked_add(self.width)
                .ok_or(CompactWhirError::CountOverflow)?;
            self.opening_values
                .get_mut(first_value..end_value)
                .ok_or(CompactWhirError::InvalidEncodedMatrix)?
                .fill(CompactChallengeField::ZERO);
            self.next_opening_row_offset = self
                .next_opening_row_offset
                .checked_add(1)
                .ok_or(CompactWhirError::CountOverflow)?;
            if let Some(next_opening_row) = self
                .opening_row_ordinals
                .get(self.next_opening_row_offset)
                .copied()
            {
                self.next_response_row = next_opening_row;
            } else {
                self.opening_values.fill(CompactChallengeField::ZERO);
                self.opening_values.clear();
                self.stage = CompactWhirRecomputableExtensionStage::OpeningReplayComplete;
            }
            return Ok(());
        }
        if self.stage != CompactWhirRecomputableExtensionStage::StripeReady
            || row_ordinal != self.next_response_row
            || row_ordinal >= self.stripe_end_row
            || !self.opening_row_ordinals.is_empty()
            || !self.opening_values.is_empty()
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        self.next_response_row = self
            .next_response_row
            .checked_add(1)
            .ok_or(CompactWhirError::CountOverflow)?;
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
    /// been committed. The rows come from the verifier-derived query schedule.
    /// They must be strictly increasing; one column-major encoding pass retains
    /// only those rows, so query dispersion does not repeat a full transform.
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
            || !self.opening_values.is_empty()
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        let opening_value_count = row_ordinals
            .len()
            .checked_mul(self.width)
            .ok_or(CompactWhirError::CountOverflow)?;
        let opening_values = allocate_zero_extension_values(opening_value_count)?;
        self.opening_row_ordinals
            .try_reserve_exact(row_ordinals.len())
            .map_err(|_| CompactWhirError::CountOverflow)?;
        self.opening_row_ordinals.extend_from_slice(row_ordinals);
        self.opening_values = opening_values;
        self.next_opening_row_offset = 0;
        self.next_response_row = row_ordinals[0];
        self.current_column_ordinal = 0;
        self.next_source_row = 0;
        self.next_capture_row = 0;
        self.stage = CompactWhirRecomputableExtensionStage::PrepareColumn;
        Ok(())
    }

    pub(crate) const fn can_begin_opening_replay(&self) -> bool {
        matches!(self.stage, CompactWhirRecomputableExtensionStage::Complete)
    }

    pub(crate) const fn opening_replay_complete(&self) -> bool {
        matches!(
            self.stage,
            CompactWhirRecomputableExtensionStage::OpeningReplayComplete
        )
    }

    pub(crate) fn finish_opening_replay(&mut self) -> Result<(), CompactWhirError> {
        if !self.opening_replay_complete()
            || !self.stripe_values.is_empty()
            || !self.opening_values.is_empty()
            || self.active_transform.is_some()
            || self.encoded_column_values.is_some()
        {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        self.randomness.fill(CompactChallengeField::ZERO);
        self.randomness.clear();
        self.opening_row_ordinals.clear();
        self.next_opening_row_offset = 0;
        Ok(())
    }

    pub(crate) const fn is_complete(&self) -> bool {
        matches!(
            self.stage,
            CompactWhirRecomputableExtensionStage::Complete
                | CompactWhirRecomputableExtensionStage::OpeningReplayComplete
        )
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
        self.opening_values.fill(CompactChallengeField::ZERO);
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
    use crate::bgv::proof_suite::compact_whir_algebraic_verifier::{
        CompactWhirAlgebraicRelation, CompactWhirCodeSwitchTranscript,
        CompactWhirSumcheckTranscript, CompactWhirSumcheckVerificationPoll,
    };

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

    fn bounded_base_mask_contract(
        role_tag: u8,
        coordinate: u8,
        width: u64,
        message_length: u64,
        randomness_length: u64,
    ) -> CompactWhirMaskGroupContract {
        let shape = MaskCodeShape::new(
            usize::try_from(message_length).unwrap(),
            usize::try_from(randomness_length).unwrap(),
            COMPACT_WHIR_MASK_LOG_INVERSE_RATE,
        );
        CompactWhirMaskGroupContract {
            role_tag,
            coordinate,
            width,
            message_length,
            randomness_length,
            domain_size: u64::try_from(shape.domain_size).unwrap(),
            committed_encoding_source: 1,
        }
    }

    fn prepared_test_relation(
        source: Vec<Goldilocks>,
        equality_point: Vec<CompactChallengeField>,
        pre_challenge_mask: CompactChallengeField,
        main_mask: CompactChallengeField,
        opening_batching_challenge: CompactChallengeField,
    ) -> CompactWhirMaskedSumcheckRelation {
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
    fn base_case_folds_carried_randomness_and_binds_the_exact_blinded_reveal() {
        let final_fold_contract = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 3,
            message_length: 4,
            hiding_randomness_length: 4,
            block_length: 32,
            oracle_width: 4,
            query_count: 4,
            unique_decoding_radius: 11,
        };
        let folding_challenges = [
            CompactChallengeField::from_u64(5),
            CompactChallengeField::from_u64(7),
        ];
        let source_message = (1_u64..=4)
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let source_covector = (11_u64..=14)
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let previous_source_randomness = (21_u64..=36)
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let first_mask_messages = vec![
            vec![
                CompactChallengeField::from_u64(41),
                CompactChallengeField::from_u64(42),
                CompactChallengeField::from_u64(43),
            ],
            vec![
                CompactChallengeField::from_u64(44),
                CompactChallengeField::from_u64(45),
                CompactChallengeField::from_u64(46),
            ],
        ];
        let first_mask_randomness = vec![
            vec![
                CompactChallengeField::from_u64(47),
                CompactChallengeField::from_u64(48),
            ],
            vec![
                CompactChallengeField::from_u64(49),
                CompactChallengeField::from_u64(50),
            ],
        ];
        let first_mask_covectors = vec![
            vec![
                CompactChallengeField::from_u64(51),
                CompactChallengeField::from_u64(52),
                CompactChallengeField::from_u64(53),
            ],
            vec![
                CompactChallengeField::from_u64(54),
                CompactChallengeField::from_u64(55),
                CompactChallengeField::from_u64(56),
            ],
        ];
        let second_mask_messages = vec![vec![
            CompactChallengeField::from_u64(61),
            CompactChallengeField::from_u64(62),
        ]];
        let second_mask_randomness = vec![vec![
            CompactChallengeField::from_u64(63),
            CompactChallengeField::from_u64(64),
            CompactChallengeField::from_u64(65),
        ]];
        let second_mask_covectors = vec![vec![
            CompactChallengeField::from_u64(66),
            CompactChallengeField::from_u64(67),
        ]];
        let target = compact_whir_dot_product(&source_message, &source_covector).unwrap()
            + first_mask_messages
                .iter()
                .zip(&first_mask_covectors)
                .map(|(message, covector)| compact_whir_dot_product(message, covector).unwrap())
                .sum::<CompactChallengeField>()
            + second_mask_messages
                .iter()
                .zip(&second_mask_covectors)
                .map(|(message, covector)| compact_whir_dot_product(message, covector).unwrap())
                .sum::<CompactChallengeField>();
        let mask_inputs = vec![
            CompactWhirBaseMaskInput::new(
                bounded_base_mask_contract(1, 0, 2, 3, 2),
                first_mask_messages.clone(),
                first_mask_randomness.clone(),
                first_mask_covectors,
            )
            .unwrap(),
            CompactWhirBaseMaskInput::new(
                bounded_base_mask_contract(4, 0, 1, 2, 3),
                second_mask_messages.clone(),
                second_mask_randomness.clone(),
                second_mask_covectors,
            )
            .unwrap(),
        ];

        let folded_source_randomness = fold_compact_whir_limb_major_values(
            &previous_source_randomness,
            4,
            &folding_challenges,
        )
        .unwrap();
        let expected_weights = [
            (CompactChallengeField::ONE - folding_challenges[0])
                * (CompactChallengeField::ONE - folding_challenges[1]),
            (CompactChallengeField::ONE - folding_challenges[0]) * folding_challenges[1],
            folding_challenges[0] * (CompactChallengeField::ONE - folding_challenges[1]),
            folding_challenges[0] * folding_challenges[1],
        ];
        for coordinate_ordinal in 0..4 {
            let expected = expected_weights
                .iter()
                .enumerate()
                .map(|(limb_ordinal, weight)| {
                    *weight * previous_source_randomness[limb_ordinal * 4 + coordinate_ordinal]
                })
                .sum::<CompactChallengeField>();
            assert_eq!(folded_source_randomness[coordinate_ordinal], expected);
        }

        let mut random_source = CountingRandomSource(0xB5);
        let mut state = CompactWhirBaseCaseState::new(
            CompactWhirBaseRelation::new(source_message.clone(), source_covector, target),
            &previous_source_randomness,
            final_fold_contract,
            &folding_challenges,
            mask_inputs,
            &mut random_source,
        )
        .expect("the exact carried base relation prepares");
        assert_eq!(state.source_randomness, folded_source_randomness);
        assert_eq!(state.fresh_source_oracle().width(), 1);
        assert_eq!(state.fresh_source_oracle().encoded_height(), 32);
        assert_eq!(state.fresh_mask_group_count(), 2);
        assert_eq!(
            state.bind_combination_challenge(CompactChallengeField::from_u64(71)),
            Err(CompactWhirError::WrongProverPhase)
        );

        let work_budgets = [1_u64, 3, 11, 2, 19];
        let mut poll_ordinal = 0_usize;
        let mut next_row = 0_usize;
        while next_row < state.fresh_source_oracle().encoded_height() {
            match state
                .poll_fresh_source_oracle(work_budgets[poll_ordinal % work_budgets.len()])
                .expect("the fresh base source encoding advances")
            {
                CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                } => assert!((1..=19).contains(&processed_work_unit_count)),
                CompactWhirRecomputableExtensionPoll::StripeReady {
                    first_row,
                    row_count,
                } => {
                    assert!(
                        (first_row..first_row + row_count)
                            .contains(&u64::try_from(next_row).unwrap())
                    );
                    assert_eq!(state.fresh_source_row(next_row).unwrap().len(), 1);
                    state.mark_fresh_source_row_supplied(next_row).unwrap();
                    next_row += 1;
                }
            }
            poll_ordinal += 1;
        }

        let fresh_source_message = state.fresh_source_message.clone();
        let fresh_source_randomness = state.fresh_source_oracle.encoding_randomness().to_vec();
        let fresh_mask_messages = state
            .mask_groups
            .iter()
            .map(|group| group.fresh_messages.clone())
            .collect::<Vec<_>>();
        let fresh_mask_randomness = state
            .mask_groups
            .iter()
            .map(|group| group.fresh_randomness.clone())
            .collect::<Vec<_>>();
        let combination_challenge = CompactChallengeField::from_u64(73);
        state
            .bind_combination_challenge(combination_challenge)
            .expect("the transcript combination challenge binds once");
        let mut expected_blinded_values = fresh_source_message
            .iter()
            .zip(&source_message)
            .map(|(fresh, carried)| *fresh + combination_challenge * *carried)
            .collect::<Vec<_>>();
        expected_blinded_values.extend(
            fresh_source_randomness
                .iter()
                .zip(&folded_source_randomness)
                .map(|(fresh, carried)| *fresh + combination_challenge * *carried),
        );
        for (((fresh_messages, fresh_randomness), carried_messages), carried_randomness) in
            fresh_mask_messages
                .iter()
                .zip(&fresh_mask_randomness)
                .zip([&first_mask_messages, &second_mask_messages])
                .zip([&first_mask_randomness, &second_mask_randomness])
        {
            for (((fresh_message, fresh_randomness), carried_message), carried_randomness) in
                fresh_messages
                    .iter()
                    .zip(fresh_randomness)
                    .zip(carried_messages)
                    .zip(carried_randomness)
            {
                expected_blinded_values.extend(
                    fresh_message
                        .iter()
                        .zip(carried_message)
                        .map(|(fresh, carried)| *fresh + combination_challenge * *carried),
                );
                expected_blinded_values.extend(
                    fresh_randomness
                        .iter()
                        .zip(carried_randomness)
                        .map(|(fresh, carried)| *fresh + combination_challenge * *carried),
                );
            }
        }
        assert_eq!(
            state.blinded_response_values().unwrap(),
            expected_blinded_values
        );
        assert_eq!(
            state.bind_combination_challenge(combination_challenge),
            Err(CompactWhirError::WrongProverPhase)
        );

        let mut rejecting_random_source = CountingRandomSource(0xC5);
        assert!(matches!(
            CompactWhirBaseCaseState::new(
                CompactWhirBaseRelation::new(
                    source_message,
                    vec![CompactChallengeField::ONE; 4],
                    target + CompactChallengeField::ONE,
                ),
                &previous_source_randomness,
                final_fold_contract,
                &folding_challenges,
                vec![
                    CompactWhirBaseMaskInput::new(
                        bounded_base_mask_contract(4, 0, 1, 2, 3),
                        second_mask_messages,
                        second_mask_randomness,
                        vec![vec![CompactChallengeField::ONE; 2]],
                    )
                    .unwrap()
                ],
                &mut rejecting_random_source,
            ),
            Err(CompactWhirError::InvalidRelation)
        ));
        assert_eq!(
            fold_compact_whir_limb_major_values(
                &previous_source_randomness[..15],
                4,
                &folding_challenges,
            ),
            Err(CompactWhirError::InvalidRelation)
        );
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
        assert_eq!(relation.source_claim + pre_challenge_mask, relation.target);

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
    fn main_relation_preparation_streams_the_exact_source_and_rejects_wrong_geometry() {
        let source_evaluations = (1_u64..=8)
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let source_covector = (11_u64..=18)
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let inner_mask_covectors = vec![
            (21_u64..=24)
                .map(CompactChallengeField::from_u64)
                .collect::<Vec<_>>(),
            (25_u64..=28)
                .map(CompactChallengeField::from_u64)
                .collect::<Vec<_>>(),
        ];
        let outer_mask_covectors = vec![
            (31_u64..=38)
                .map(CompactChallengeField::from_u64)
                .collect::<Vec<_>>(),
        ];
        let cross_epoch_mask_covectors = vec![
            vec![CompactChallengeField::from_u64(41)],
            vec![CompactChallengeField::from_u64(43)],
        ];
        let inner_mask_messages = [
            [
                CompactChallengeField::from_u64(51),
                CompactChallengeField::from_u64(52),
                CompactChallengeField::from_u64(53),
                CompactChallengeField::from_u64(54),
            ],
            [
                CompactChallengeField::from_u64(55),
                CompactChallengeField::from_u64(56),
                CompactChallengeField::from_u64(57),
                CompactChallengeField::from_u64(58),
            ],
        ];
        let outer_mask_messages = [[
            CompactChallengeField::from_u64(61),
            CompactChallengeField::from_u64(62),
            CompactChallengeField::from_u64(63),
            CompactChallengeField::from_u64(64),
            CompactChallengeField::from_u64(65),
            CompactChallengeField::from_u64(66),
            CompactChallengeField::from_u64(67),
            CompactChallengeField::from_u64(68),
        ]];
        let cross_epoch_masks = [
            CompactChallengeField::from_u64(71),
            CompactChallengeField::from_u64(73),
        ];
        let input_binding_challenge = CompactChallengeField::from_u64(79);
        let public_covectors = || CompactCfwPublicMainCovectors {
            source: source_covector.clone(),
            inner_masks: inner_mask_covectors.clone(),
            outer_masks: outer_mask_covectors.clone(),
            cross_epoch_masks: cross_epoch_mask_covectors.clone(),
        };

        let mut incomplete = CompactWhirMainRelationPreparation::new(
            public_covectors(),
            &inner_mask_messages,
            &outer_mask_messages,
            cross_epoch_masks,
            input_binding_challenge,
        )
        .expect("valid main-relation geometry begins preparing");
        assert_eq!(
            incomplete.poll::<core::convert::Infallible>(0, |_| unreachable!()),
            Err(CompactWhirMainRelationPreparationError::Whir(
                CompactWhirError::InvalidWorkBudget
            ))
        );
        assert!(matches!(
            incomplete.finish(),
            Err(CompactWhirError::WrongProverPhase)
        ));

        let mut source_failure = CompactWhirMainRelationPreparation::new(
            public_covectors(),
            &inner_mask_messages,
            &outer_mask_messages,
            cross_epoch_masks,
            input_binding_challenge,
        )
        .expect("valid main-relation geometry begins preparing");
        assert_eq!(
            source_failure.poll(3, |source_ordinal| {
                if source_ordinal == 1 {
                    Err("authenticated source failure")
                } else {
                    Ok(source_evaluations[usize::try_from(source_ordinal).unwrap()])
                }
            }),
            Err(CompactWhirMainRelationPreparationError::Source(
                "authenticated source failure"
            ))
        );
        while let CompactWhirMainRelationPreparationPoll::SourceStepCompleted { .. } =
            source_failure
                .poll(3, |source_ordinal| {
                    Ok::<_, core::convert::Infallible>(
                        source_evaluations[usize::try_from(source_ordinal).unwrap()],
                    )
                })
                .expect("the authenticated source resumes at the failed ordinal")
        {}
        let resumed_relation = source_failure
            .finish()
            .expect("the resumed source produces one exact relation");
        assert!(resumed_relation.source_evaluations.is_empty());
        assert_eq!(
            resumed_relation.authenticated_source_replay_element_count,
            Some(source_evaluations.len())
        );
        assert_eq!(
            resumed_relation.source_claim,
            source_evaluations
                .iter()
                .zip(&source_covector)
                .map(|(value, coefficient)| *value * *coefficient)
                .sum::<CompactChallengeField>()
        );

        let mut preparation = CompactWhirMainRelationPreparation::new(
            public_covectors(),
            &inner_mask_messages,
            &outer_mask_messages,
            cross_epoch_masks,
            input_binding_challenge,
        )
        .expect("valid main-relation geometry begins preparing");
        let work_budgets = [1_u64, 3, 2];
        let mut poll_ordinal = 0_usize;
        let mut observed_source_ordinals = Vec::new();
        while let CompactWhirMainRelationPreparationPoll::SourceStepCompleted {
            processed_work_unit_count,
            relation_complete,
        } = preparation
            .poll(
                work_budgets[poll_ordinal % work_budgets.len()],
                |source_ordinal| {
                    observed_source_ordinals.push(source_ordinal);
                    Ok::<_, core::convert::Infallible>(
                        source_evaluations[usize::try_from(source_ordinal).unwrap()],
                    )
                },
            )
            .expect("the valid main relation advances")
        {
            assert!((1..=3).contains(&processed_work_unit_count));
            assert_eq!(
                relation_complete,
                observed_source_ordinals.len() == source_evaluations.len()
            );
            poll_ordinal += 1;
        }
        assert_eq!(observed_source_ordinals, (0_u64..8).collect::<Vec<_>>());
        let relation = preparation
            .finish()
            .expect("the complete main relation finishes");
        let expected_source_claim = source_evaluations
            .iter()
            .zip(&source_covector)
            .map(|(value, coefficient)| *value * *coefficient)
            .sum::<CompactChallengeField>();
        let expected_inner_mask_claim = inner_mask_covectors
            .iter()
            .zip(&inner_mask_messages)
            .flat_map(|(covector, message)| covector.iter().zip(message))
            .map(|(coefficient, value)| *coefficient * *value)
            .sum::<CompactChallengeField>();
        let expected_outer_mask_claim = outer_mask_covectors
            .iter()
            .zip(&outer_mask_messages)
            .flat_map(|(covector, message)| covector.iter().zip(message))
            .map(|(coefficient, value)| *coefficient * *value)
            .sum::<CompactChallengeField>();
        let expected_cross_epoch_mask_claim = cross_epoch_mask_covectors
            .iter()
            .zip(cross_epoch_masks)
            .map(|(covector, value)| covector[0] * value)
            .sum::<CompactChallengeField>();
        let expected_mask_claim =
            expected_inner_mask_claim + expected_outer_mask_claim + expected_cross_epoch_mask_claim;
        assert!(relation.source_evaluations.is_empty());
        assert_eq!(
            relation.authenticated_source_replay_element_count,
            Some(source_evaluations.len())
        );
        assert_eq!(relation.source_covector, source_covector);
        assert_eq!(relation.source_claim, expected_source_claim);
        assert_eq!(relation.preceding_mask_claim, expected_mask_claim);
        assert_eq!(relation.target, expected_source_claim + expected_mask_claim);
        assert_eq!(relation.input_binding_challenge, input_binding_challenge);

        let mut wrong_cross_epoch_geometry = public_covectors();
        wrong_cross_epoch_geometry.cross_epoch_masks[0].push(CompactChallengeField::ZERO);
        assert!(matches!(
            CompactWhirMainRelationPreparation::new(
                wrong_cross_epoch_geometry,
                &inner_mask_messages,
                &outer_mask_messages,
                cross_epoch_masks,
                input_binding_challenge,
            ),
            Err(CompactWhirError::InvalidRelation)
        ));
        let mut non_power_of_two_source = public_covectors();
        non_power_of_two_source.source.pop();
        assert!(matches!(
            CompactWhirMainRelationPreparation::new(
                non_power_of_two_source,
                &inner_mask_messages,
                &outer_mask_messages,
                cross_epoch_masks,
                input_binding_challenge,
            ),
            Err(CompactWhirError::InvalidRelation)
        ));
        assert!(matches!(
            CompactWhirMainRelationPreparation::new(
                public_covectors(),
                &inner_mask_messages[..1],
                &outer_mask_messages,
                cross_epoch_masks,
                input_binding_challenge,
            ),
            Err(CompactWhirError::InvalidRelation)
        ));
    }

    #[test]
    fn authenticated_source_replay_matches_materialized_sumcheck_and_resumes_source_failures() {
        let configuration = bounded_test_configuration();
        let source_evaluations = (0..1_usize << configuration.num_variables)
            .map(|source_ordinal| {
                CompactChallengeField::from_u64((source_ordinal as u64).wrapping_mul(41) + 7)
            })
            .collect::<Vec<_>>();
        let source_covector = (0..source_evaluations.len())
            .map(|source_ordinal| {
                CompactChallengeField::from_u64((source_ordinal as u64).wrapping_mul(53) + 11)
            })
            .collect::<Vec<_>>();
        let source_claim = source_evaluations
            .iter()
            .zip(&source_covector)
            .map(|(value, coefficient)| *value * *coefficient)
            .sum::<CompactChallengeField>();
        let preceding_mask_claim = CompactChallengeField::from_u64(1_009);
        let masked_target = source_claim + preceding_mask_claim;
        let input_binding_challenge = CompactChallengeField::from_u64(1_103);
        let materialized_relation = CompactWhirMaskedSumcheckRelation {
            source_evaluations: source_evaluations.clone(),
            authenticated_source_replay_element_count: None,
            source_covector: source_covector.clone(),
            source_claim,
            target: masked_target,
            preceding_mask_claim,
            input_binding_challenge,
        };
        let replayed_relation = || CompactWhirMaskedSumcheckRelation {
            source_evaluations: Vec::new(),
            authenticated_source_replay_element_count: Some(source_evaluations.len()),
            source_covector: source_covector.clone(),
            source_claim,
            target: masked_target,
            preceding_mask_claim,
            input_binding_challenge,
        };
        let mask_contract = initial_sumcheck_mask_contract(&configuration);
        let mut materialized_random_source = CountingRandomSource(0xD9);
        let mut replayed_random_source = CountingRandomSource(0xD9);
        let mut materialized_state = CompactWhirInitialSumcheckState::new(
            materialized_relation,
            &configuration,
            0,
            mask_contract,
            &mut materialized_random_source,
        )
        .expect("the materialized relation enters the sumcheck");
        let mut replayed_state = CompactWhirInitialSumcheckState::new(
            replayed_relation(),
            &configuration,
            0,
            mask_contract,
            &mut replayed_random_source,
        )
        .expect("the authenticated replay relation enters the same sumcheck");
        assert!(!materialized_state.authenticated_source_replay_required());
        assert!(replayed_state.authenticated_source_replay_required());
        let combination_challenge = CompactChallengeField::from_u64(1_201);
        materialized_state
            .bind_combination_challenge(combination_challenge)
            .expect("the materialized sumcheck binds its combination challenge");
        replayed_state
            .bind_combination_challenge(combination_challenge)
            .expect("the replayed sumcheck binds the same combination challenge");
        assert_eq!(
            replayed_state.poll(1),
            Err(CompactWhirError::WrongProverPhase)
        );
        assert_eq!(
            materialized_state.poll_replaying_authenticated_source::<core::convert::Infallible>(
                1,
                |_| unreachable!(),
            ),
            Err(CompactWhirInitialSumcheckSourceReplayError::Whir(
                CompactWhirError::WrongProverPhase,
            ))
        );

        let round_challenges = [
            CompactChallengeField::from_u64(1_303),
            CompactChallengeField::from_u64(1_409),
        ];
        let work_budgets = [1_u64, 7, 31, 3];
        let mut poll_ordinal = 0_usize;
        let mut replayed_source_ordinals = Vec::new();
        for (round_index, challenge) in round_challenges.into_iter().enumerate() {
            loop {
                let work_budget = work_budgets[poll_ordinal % work_budgets.len()];
                let materialized_poll = materialized_state
                    .poll(work_budget)
                    .expect("the materialized round polynomial advances");
                let replayed_poll = if replayed_state.authenticated_source_replay_required() {
                    replayed_state
                        .poll_replaying_authenticated_source(work_budget, |source_ordinal| {
                            replayed_source_ordinals.push(source_ordinal);
                            Ok::<_, core::convert::Infallible>(
                                source_evaluations[usize::try_from(source_ordinal).unwrap()],
                            )
                        })
                        .expect("the authenticated source replay advances")
                } else {
                    replayed_state
                        .poll(work_budget)
                        .expect("the in-place replay state advances")
                };
                assert_eq!(replayed_poll, materialized_poll);
                poll_ordinal += 1;
                if matches!(
                    materialized_poll,
                    CompactWhirInitialSumcheckPoll::RoundPolynomial {
                        polynomial_ready: true,
                        ..
                    }
                ) {
                    break;
                }
            }
            assert_eq!(
                replayed_state
                    .pending_round_wire()
                    .expect("the replayed round wire is ready"),
                materialized_state
                    .pending_round_wire()
                    .expect("the materialized round wire is ready")
            );
            materialized_state
                .bind_round_challenge(challenge)
                .expect("the materialized round challenge binds");
            replayed_state
                .bind_round_challenge(challenge)
                .expect("the replayed round challenge binds");
            loop {
                let work_budget = work_budgets[poll_ordinal % work_budgets.len()];
                let materialized_poll = materialized_state
                    .poll(work_budget)
                    .expect("the materialized fold advances");
                let replayed_poll = if replayed_state.authenticated_source_replay_required() {
                    replayed_state
                        .poll_replaying_authenticated_source(work_budget, |source_ordinal| {
                            replayed_source_ordinals.push(source_ordinal);
                            Ok::<_, core::convert::Infallible>(
                                source_evaluations[usize::try_from(source_ordinal).unwrap()],
                            )
                        })
                        .expect("the first replayed fold advances")
                } else {
                    replayed_state
                        .poll(work_budget)
                        .expect("the in-place replayed fold advances")
                };
                assert_eq!(replayed_poll, materialized_poll);
                poll_ordinal += 1;
                if matches!(
                    materialized_poll,
                    CompactWhirInitialSumcheckPoll::BoundRound {
                        round_complete: true,
                        ..
                    }
                ) {
                    break;
                }
            }
            if round_index == 0 {
                assert!(!replayed_state.authenticated_source_replay_required());
            }
        }
        loop {
            let work_budget = work_budgets[poll_ordinal % work_budgets.len()];
            let materialized_poll = materialized_state
                .poll(work_budget)
                .expect("the materialized weights scale");
            let replayed_poll = replayed_state
                .poll(work_budget)
                .expect("the replayed weights scale");
            assert_eq!(replayed_poll, materialized_poll);
            poll_ordinal += 1;
            if matches!(
                materialized_poll,
                CompactWhirInitialSumcheckPoll::WeightScaling {
                    scaling_complete: true,
                    ..
                }
            ) {
                break;
            }
        }
        assert!(materialized_state.is_complete());
        assert!(replayed_state.is_complete());
        assert_eq!(
            replayed_state.residual_source().unwrap(),
            materialized_state.residual_source().unwrap()
        );
        assert_eq!(
            replayed_state.residual_covector().unwrap(),
            materialized_state.residual_covector().unwrap()
        );
        assert_eq!(
            replayed_state.residual_source_claim().unwrap(),
            materialized_state.residual_source_claim().unwrap()
        );
        assert_eq!(
            replayed_state.residual_mask_claim().unwrap(),
            materialized_state.residual_mask_claim().unwrap()
        );
        let replay_storage = replayed_state
            .authenticated_source_replay
            .expect("the replay storage remains classified until extraction");
        let replay_weight_offset = replay_storage
            .folded_weight_offset
            .expect("the first fold established the weight region");
        assert!(
            replayed_state.source_covector
                [replay_storage.current_element_count..replay_weight_offset]
                .iter()
                .all(|value| *value == CompactChallengeField::ZERO)
        );
        assert_eq!(
            replayed_state.take_residual_covector(),
            Err(CompactWhirError::WrongProverPhase)
        );
        assert_eq!(
            replayed_state.take_residual_source().unwrap(),
            materialized_state.take_residual_source().unwrap()
        );
        assert!(replayed_state.source_covector.is_empty());
        assert_eq!(
            replayed_state.take_residual_covector().unwrap(),
            materialized_state.take_residual_covector().unwrap()
        );
        assert_eq!(
            replayed_state.take_residual_source(),
            Err(CompactWhirError::WrongProverPhase)
        );
        assert_eq!(
            replayed_state.take_residual_covector(),
            Err(CompactWhirError::WrongProverPhase)
        );

        let half = source_evaluations.len() / 2;
        let one_replay_pass = (0..half)
            .flat_map(|pair_ordinal| {
                [
                    u64::try_from(pair_ordinal).unwrap(),
                    u64::try_from(half + pair_ordinal).unwrap(),
                ]
            })
            .collect::<Vec<_>>();
        assert_eq!(
            replayed_source_ordinals,
            one_replay_pass
                .iter()
                .chain(&one_replay_pass)
                .copied()
                .collect::<Vec<_>>()
        );

        for failing_source_ordinal in [0_u64, u64::try_from(half).unwrap()] {
            let mut failure_random_source = CountingRandomSource(0xD9);
            let mut failure_state = CompactWhirInitialSumcheckState::new(
                replayed_relation(),
                &configuration,
                0,
                mask_contract,
                &mut failure_random_source,
            )
            .expect("the source-failure relation enters the sumcheck");
            failure_state
                .bind_combination_challenge(combination_challenge)
                .expect("the source-failure sumcheck binds its challenge");
            assert_eq!(
                failure_state.poll_replaying_authenticated_source(1, |source_ordinal| {
                    if source_ordinal == failing_source_ordinal {
                        Err("authenticated source failure")
                    } else {
                        Ok(source_evaluations[usize::try_from(source_ordinal).unwrap()])
                    }
                }),
                Err(CompactWhirInitialSumcheckSourceReplayError::Source(
                    "authenticated source failure"
                ))
            );
            assert_eq!(
                failure_state
                    .poll_replaying_authenticated_source(1, |source_ordinal| {
                        Ok::<_, core::convert::Infallible>(
                            source_evaluations[usize::try_from(source_ordinal).unwrap()],
                        )
                    })
                    .expect("the failed source pair restarts without retained arithmetic"),
                CompactWhirInitialSumcheckPoll::RoundPolynomial {
                    round_ordinal: 0,
                    processed_work_unit_count: 1,
                    polynomial_ready: false,
                }
            );
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
            equality_point.clone(),
            pre_challenge_mask,
            main_mask,
            opening_batching_challenge,
        );
        let mut random_source = CountingRandomSource(0xD7);
        let mut state = CompactWhirInitialSumcheckState::new(
            relation,
            &configuration,
            0,
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
        let sumcheck_mask_contract = initial_sumcheck_mask_contract(&configuration);
        let verifier_epoch_contract = CompactWhirEpochContract {
            epoch: 1,
            polynomial_variable_count: u32::try_from(configuration.num_variables).unwrap(),
            folding_schedule: [
                u32::try_from(configuration.round_folding_factor(0)).unwrap(),
                1,
                1,
                1,
            ],
            final_variable_count: 3,
            round_log_inverse_rates: [2, 4, 8],
            mask_query_count: sumcheck_mask_contract.randomness_length,
            internal_mask_groups: vec![sumcheck_mask_contract],
            external_mask_groups: vec![bounded_base_mask_contract(1, 0, 2, 1, 4)],
        };
        let verifier_fold_contract = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 0,
            message_length: u64::try_from(
                (1_usize << configuration.num_variables) >> configuration.round_folding_factor(0),
            )
            .unwrap(),
            hiding_randomness_length: 4,
            block_length: 256,
            oracle_width: 1_u64 << configuration.round_folding_factor(0),
            query_count: 4,
            unique_decoding_radius: 93,
        };
        let mut verifier_relation = CompactWhirAlgebraicRelation::pre_challenge(
            &verifier_epoch_contract,
            &equality_point,
            state.masked_target(),
        )
        .expect("the verifier derives the public pre-challenge relation");
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
            let mut full = [CompactChallengeField::ZERO; 3];
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
                    CompactWhirInitialSumcheckPoll::RoundPolynomial {
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
                    CompactWhirInitialSumcheckPoll::BoundRound {
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
                CompactWhirInitialSumcheckPoll::WeightScaling {
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
        let round_wires = (0..challenges.len())
            .map(|round_ordinal| state.round_wire(round_ordinal).unwrap().try_into().unwrap())
            .collect::<Vec<[CompactChallengeField; 2]>>();
        let expected_fold_work_unit_count = verifier_relation
            .source_covector()
            .len()
            .checked_sub(usize::try_from(verifier_fold_contract.message_length).unwrap())
            .unwrap();
        let mut sumcheck_verification = verifier_relation
            .begin_sumcheck_batch(
                &verifier_epoch_contract,
                verifier_fold_contract,
                0,
                false,
                CompactWhirSumcheckTranscript {
                    auxiliary_target: state.auxiliary_target(),
                    combination_challenge,
                    round_wires: &round_wires,
                    round_challenges: &challenges,
                },
            )
            .expect("the verifier independently begins the masked sumcheck");
        let work_budgets = [1_u64, 7, 3, 13];
        let mut poll_ordinal = 0_usize;
        let mut completed_fold_work_unit_count = 0_u64;
        loop {
            let work_budget = work_budgets[poll_ordinal % work_budgets.len()];
            poll_ordinal += 1;
            match sumcheck_verification
                .advance(
                    &mut verifier_relation,
                    &verifier_epoch_contract,
                    work_budget,
                )
                .expect("the bounded verifier sumcheck fold advances")
            {
                CompactWhirSumcheckVerificationPoll::WorkCompleted {
                    completed_work_unit_count,
                } => {
                    assert!((1..=work_budget).contains(&completed_work_unit_count));
                    completed_fold_work_unit_count += completed_work_unit_count;
                }
                CompactWhirSumcheckVerificationPoll::Complete {
                    completed_work_unit_count,
                } => {
                    assert!(completed_work_unit_count <= work_budget);
                    completed_fold_work_unit_count += completed_work_unit_count;
                    break;
                }
            }
        }
        assert_eq!(
            completed_fold_work_unit_count,
            u64::try_from(expected_fold_work_unit_count).unwrap()
        );
        assert_eq!(
            verifier_relation.source_covector(),
            state.residual_covector().unwrap()
        );
        assert_eq!(verifier_relation.target(), state.residual_target().unwrap());
        let carried_mask_claim = verifier_relation.mask_group_covectors()[0][0]
            * pre_challenge_mask
            + verifier_relation.mask_group_covectors()[0][1] * main_mask;
        let sumcheck_mask_claim = verifier_relation.mask_group_covectors()[1]
            .iter()
            .zip(state.mask_messages().iter().flatten())
            .map(|(coefficient, value)| *coefficient * *value)
            .sum::<CompactChallengeField>();
        assert_eq!(
            carried_mask_claim + sumcheck_mask_claim,
            state.residual_mask_claim().unwrap()
        );
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
        let mut opening_source_value_count = 0_usize;
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
                        opening_source_value_count += 1;
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
        assert_eq!(opening_source_value_count, message.len());
        assert!(recomputable.is_complete());
        assert!(recomputable.response_row(opening_rows[0]).is_err());
        assert!(recomputable.begin_opening_replay(&opening_rows).is_err());
        recomputable
            .finish_opening_replay()
            .expect("the one-pass opening replay releases its randomness");
        assert!(recomputable.encoding_randomness().is_empty());
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
        let mut state = CompactWhirCodeSwitchState::new_from_base_source(
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
        while let CompactWhirCodeSwitchPreparationPoll::RandomnessFoldStepCompleted {
            processed_work_unit_count,
            ..
        } = state
            .poll_preparation(work_budgets[poll_ordinal % work_budgets.len()])
            .expect("the switch-mask fold advances")
        {
            assert!(processed_work_unit_count > 0);
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
            state.bind_verifier_move(
                &[0; 396],
                CompactChallengeField::from_u64(31),
                vec![CompactChallengeField::ZERO; 396],
            ),
            Err(CompactWhirError::InvalidRelation)
        );
        assert_eq!(
            state.bind_verifier_move(
                &(0..395_u64).collect::<Vec<_>>(),
                CompactChallengeField::from_u64(33),
                vec![CompactChallengeField::ZERO; 395],
            ),
            Err(CompactWhirError::InvalidRelation)
        );
        let mut out_of_range_query_positions = (0..395_u64).collect::<Vec<_>>();
        out_of_range_query_positions.push(previous_source_contract.block_length);
        assert_eq!(
            state.bind_verifier_move(
                &out_of_range_query_positions,
                CompactChallengeField::from_u64(35),
                vec![CompactChallengeField::ZERO; 396],
            ),
            Err(CompactWhirError::InvalidRelation)
        );
        let query_positions = (0..396_u64)
            .map(|ordinal| ordinal * 331)
            .collect::<Vec<_>>();
        state
            .bind_verifier_move(
                &query_positions,
                CompactChallengeField::from_u64(37),
                vec![CompactChallengeField::ZERO; 396],
            )
            .expect("the exact distinct query set and combination challenge bind");
        assert!(state.verifier_move_is_bound());
        assert_eq!(
            state.bind_verifier_move(
                &query_positions,
                CompactChallengeField::from_u64(41),
                vec![CompactChallengeField::ZERO; 396],
            ),
            Err(CompactWhirError::InvalidRelation)
        );
    }

    #[test]
    fn code_switch_source_remains_replayable_after_relation_inputs_are_taken() {
        let previous_source_contract = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 0,
            message_length: 8,
            hiding_randomness_length: 2,
            block_length: 16,
            oracle_width: 2,
            query_count: 2,
            unique_decoding_radius: 2,
        };
        let next_source_contract = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 1,
            message_length: 4,
            hiding_randomness_length: 2,
            block_length: 8,
            oracle_width: 2,
            query_count: 2,
            unique_decoding_radius: 0,
        };
        let switch_mask_contract = CompactWhirMaskGroupContract {
            role_tag: 5,
            coordinate: 0,
            width: 1,
            message_length: 2,
            randomness_length: 2,
            domain_size: 16,
            committed_encoding_source: 0,
        };
        let source_evaluations = (0..8_u64)
            .map(|ordinal| CompactChallengeField::from_u64(ordinal * 17 + 3))
            .collect::<Vec<_>>();
        let previous_encoding_randomness = (0..4_u64)
            .map(|ordinal| CompactChallengeField::from_u64(ordinal * 19 + 5))
            .collect::<Vec<_>>();
        let mut random_source = CountingRandomSource(0xE7);
        let mut state = CompactWhirCodeSwitchState::new_from_extension_source(
            source_evaluations,
            previous_encoding_randomness,
            &[CompactChallengeField::from_u64(23)],
            previous_source_contract,
            next_source_contract,
            switch_mask_contract,
            &mut random_source,
        )
        .expect("the compact code switch starts");

        while !matches!(
            state
                .poll_preparation(8)
                .expect("the compact code-switch preparation advances"),
            CompactWhirCodeSwitchPreparationPoll::Complete
        ) {}
        for row_ordinal in 0..state.source_oracle().encoded_height() {
            loop {
                if state.source_row(row_ordinal).is_ok() {
                    break;
                }
                state
                    .poll_source_oracle(8)
                    .expect("the compact code-switch source advances");
            }
            state
                .mark_source_row_supplied(row_ordinal)
                .expect("the sequential response row advances custody");
        }
        assert!(state.can_begin_source_opening_replay());

        state
            .bind_verifier_move(
                &[1, 11],
                CompactChallengeField::from_u64(29),
                vec![CompactChallengeField::ZERO; 2],
            )
            .expect("the preceding-source verifier move binds");
        let _relation_inputs = state
            .take_relation_inputs()
            .expect("the code-switch relation inputs remain available");
        assert!(state.can_begin_source_opening_replay());

        let opening_rows = [1_usize, 7];
        state
            .begin_source_opening_replay(&opening_rows)
            .expect("the verifier-derived delayed replay starts");
        for row_ordinal in opening_rows {
            loop {
                if state.source_row(row_ordinal).is_ok() {
                    break;
                }
                state
                    .poll_source_oracle(8)
                    .expect("the delayed source replay advances");
            }
            state
                .mark_source_row_supplied(row_ordinal)
                .expect("the delayed response row advances custody");
        }
        assert!(state.source_opening_replay_complete());
        state
            .finish_source_opening_replay()
            .expect("the completed replay releases retained source secrets");
        assert!(state.source_evaluations.is_empty());
        assert!(state.source_encoding_randomness().is_empty());
    }

    #[test]
    fn code_switch_relation_preparation_matches_query_and_mask_power_runs() {
        let source_evaluations = [3_u64, 5, 7, 11]
            .into_iter()
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let initial_source_covector = [2_u64, 4, 6, 8]
            .into_iter()
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let switch_mask_message = [13_u64, 17]
            .into_iter()
            .map(CompactChallengeField::from_u64)
            .collect::<Vec<_>>();
        let source_claim = source_evaluations
            .iter()
            .copied()
            .zip(&initial_source_covector)
            .map(|(source, weight)| source * *weight)
            .sum::<CompactChallengeField>();
        let preceding_mask_claim = CompactChallengeField::from_u64(19);
        let input_target = source_claim + preceding_mask_claim;
        let query_positions = vec![1_usize, 5];
        let domain_generator = CompactChallengeField::from(Goldilocks::two_adic_generator(3));
        let query_points = query_positions
            .iter()
            .map(|position| domain_generator.exp_u64(*position as u64))
            .collect::<Vec<_>>();
        let folded_source_openings = query_points
            .iter()
            .map(|point| {
                let mut power = CompactChallengeField::ONE;
                let mut evaluation = CompactChallengeField::ZERO;
                for source in &source_evaluations {
                    evaluation += *source * power;
                    power *= *point;
                }
                for mask in &switch_mask_message {
                    evaluation += *mask * power;
                    power *= *point;
                }
                evaluation
            })
            .collect::<Vec<_>>();
        let combination_challenge = CompactChallengeField::from_u64(23);
        let inputs = CompactWhirBoundCodeSwitchInputs {
            source_evaluations: source_evaluations.clone(),
            switch_mask_message: switch_mask_message.clone(),
            query_positions: query_positions.clone(),
            folded_source_openings: folded_source_openings.clone(),
            combination_challenge,
            previous_source_height: 8,
        };
        let mut preparation = CompactWhirCodeSwitchRelationPreparation::new(
            inputs,
            initial_source_covector.clone(),
            source_claim,
            preceding_mask_claim,
            input_target,
        )
        .expect("the code-switch output relation starts");
        assert_eq!(
            preparation.poll(0),
            Err(CompactWhirError::InvalidWorkBudget)
        );
        let work_budgets = [1_u64, 3, 7];
        let mut poll_ordinal = 0_usize;
        let mut processed_work_unit_count = 0_u64;
        while let CompactWhirCodeSwitchRelationPreparationPoll::QueryRelationStepCompleted {
            processed_work_unit_count: processed,
            ..
        } = preparation
            .poll(work_budgets[poll_ordinal % work_budgets.len()])
            .expect("the code-switch output relation advances")
        {
            assert!(processed > 0);
            processed_work_unit_count += processed;
            poll_ordinal += 1;
        }
        assert_eq!(processed_work_unit_count, 12);
        let relation = preparation
            .finish()
            .expect("the exact code-switch output relation finishes");

        let mut expected_source_covector = initial_source_covector;
        let mut expected_source_claim = source_claim;
        let mut expected_mask_claim = preceding_mask_claim;
        let mut expected_target = input_target;
        let mut query_coefficient = combination_challenge;
        for (point, folded_opening) in query_points.iter().zip(&folded_source_openings) {
            let mut power = CompactChallengeField::ONE;
            for (source, destination) in
                source_evaluations.iter().zip(&mut expected_source_covector)
            {
                let weighted_power = query_coefficient * power;
                *destination += weighted_power;
                expected_source_claim += weighted_power * *source;
                power *= *point;
            }
            for mask in &switch_mask_message {
                expected_mask_claim += query_coefficient * power * *mask;
                power *= *point;
            }
            expected_target += query_coefficient * *folded_opening;
            query_coefficient *= combination_challenge;
        }
        assert_eq!(relation.source_covector, expected_source_covector);
        assert_eq!(relation.source_claim, expected_source_claim);
        assert_eq!(relation.preceding_mask_claim, expected_mask_claim);
        assert_eq!(relation.target, expected_target);
        assert_eq!(
            relation.source_claim + relation.preceding_mask_claim,
            relation.target
        );

        let external_mask_contract = bounded_base_mask_contract(1, 0, 1, 1, 1);
        let sumcheck_mask_contract = bounded_base_mask_contract(4, 0, 1, 1, 1);
        let switch_mask_contract = bounded_base_mask_contract(5, 0, 1, 2, 1);
        let verifier_epoch = CompactWhirEpochContract {
            epoch: 1,
            polynomial_variable_count: 6,
            folding_schedule: [1, 1, 1, 1],
            final_variable_count: 2,
            round_log_inverse_rates: [2, 2, 2],
            mask_query_count: 1,
            internal_mask_groups: vec![sumcheck_mask_contract, switch_mask_contract],
            external_mask_groups: vec![external_mask_contract],
        };
        let input_fold = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 0,
            message_length: 4,
            hiding_randomness_length: 2,
            block_length: 8,
            oracle_width: 2,
            query_count: 2,
            unique_decoding_radius: 0,
        };
        let output_fold = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 1,
            message_length: 2,
            hiding_randomness_length: 1,
            block_length: 8,
            oracle_width: 2,
            query_count: 1,
            unique_decoding_radius: 0,
        };
        let mut verifier_relation = CompactWhirAlgebraicRelation::from_parts_for_test(
            [2_u64, 4, 6, 8]
                .into_iter()
                .map(CompactChallengeField::from_u64)
                .collect(),
            vec![
                vec![CompactChallengeField::from_u64(29)],
                vec![CompactChallengeField::from_u64(31)],
            ],
            input_target,
        );
        let verifier_query_positions = query_positions
            .iter()
            .map(|position| u64::try_from(*position).unwrap())
            .collect::<Vec<_>>();
        verifier_relation
            .verify_code_switch(
                &verifier_epoch,
                input_fold,
                output_fold,
                0,
                CompactWhirCodeSwitchTranscript {
                    combination_challenge,
                    query_positions: &verifier_query_positions,
                    folded_source_openings: &folded_source_openings,
                },
            )
            .expect("the verifier replays the same code-switch relation");
        assert_eq!(
            verifier_relation.source_covector(),
            &expected_source_covector
        );
        assert_eq!(verifier_relation.target(), expected_target);
        let expected_switch_mask_covector = query_points.iter().enumerate().fold(
            vec![CompactChallengeField::ZERO; switch_mask_message.len()],
            |mut covector, (query_ordinal, point)| {
                let mut power = point.exp_u64(source_evaluations.len() as u64);
                let coefficient =
                    combination_challenge.exp_u64(u64::try_from(query_ordinal + 1).unwrap());
                for destination in &mut covector {
                    *destination += coefficient * power;
                    power *= *point;
                }
                covector
            },
        );
        assert_eq!(
            verifier_relation.mask_group_covectors().last().unwrap(),
            &expected_switch_mask_covector
        );

        let mut wrong_openings = folded_source_openings;
        wrong_openings[1] += CompactChallengeField::ONE;
        let hostile_inputs = CompactWhirBoundCodeSwitchInputs {
            source_evaluations,
            switch_mask_message,
            query_positions,
            folded_source_openings: wrong_openings,
            combination_challenge,
            previous_source_height: 8,
        };
        let mut hostile = CompactWhirCodeSwitchRelationPreparation::new(
            hostile_inputs,
            [2_u64, 4, 6, 8]
                .into_iter()
                .map(CompactChallengeField::from_u64)
                .collect(),
            source_claim,
            preceding_mask_claim,
            input_target,
        )
        .expect("the hostile opening has valid public geometry");
        assert_eq!(
            hostile.poll(u64::MAX),
            Err(CompactWhirError::InvalidRelation)
        );
    }
}
