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
use p3_field::{PrimeCharacteristicRing, PrimeField64};
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
    HidingWhirEncodedBaseOracle, HidingWhirProver, MaskCodeShape, MaskGroupShape, MaskProverData,
    ZkWhirConfig, ZkWhirProof,
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
    compact_proof_contract::{CompactWhirEpochContract, CompactWhirMaskGroupContract},
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
    InvalidConfiguration,
    FoldingScheduleMismatch,
    RoundRateMismatch,
    FinalVariableCountMismatch,
    InvalidProofOfWorkGeometry,
    InvalidMessage,
    InvalidEncodedMatrix,
}

pub(crate) struct CompactWhirEncodedInitialOracle {
    encoded_oracle: HidingWhirEncodedBaseOracle<Goldilocks, CompactChallengeField>,
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
        let encoded = Self {
            encoded_oracle: prover.encode_base_initial_oracle(Poly::new(message), random_source),
        };
        let (expected_width, expected_height) = initial_oracle_dimensions(configuration)?;
        let matrix = encoded.encoded_matrix();
        if matrix.width() != expected_width || matrix.height() != expected_height {
            return Err(CompactWhirError::InvalidEncodedMatrix);
        }
        Ok(encoded)
    }

    pub(crate) const fn encoded_matrix(&self) -> &DenseMatrix<Goldilocks> {
        &self.encoded_oracle.encoded
    }

    pub(crate) fn encoded_row(&self, row_ordinal: usize) -> Option<&[Goldilocks]> {
        self.encoded_matrix().row_slices().nth(row_ordinal)
    }
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
        if maximum_stripe_row_count == 0
            || !maximum_stripe_row_count.is_power_of_two()
            || maximum_stripe_row_count > encoded_height
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
            CompactWhirRecomputableExtensionStage::Complete => {
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
        if self.next_response_row == self.stripe_end_row {
            self.stripe_values.fill(CompactChallengeField::ZERO);
            self.stripe_values.clear();
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

    pub(crate) const fn is_complete(&self) -> bool {
        matches!(self.stage, CompactWhirRecomputableExtensionStage::Complete)
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
        let encoded_oracle =
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
                1 << 14,
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
        assert!(
            oracle
                .poll(0, |_source_ordinal| {
                    Ok::<_, ()>(CompactChallengeField::ZERO)
                })
                .is_err()
        );
    }
}
