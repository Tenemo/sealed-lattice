//! Streaming-interleaved row-code commitments with aggregate-wide masked WHIR.
//!
//! Witness rows use the candidate-specific selected rate and are committed
//! column-wise. The enclosing relation derives its out-of-domain points only
//! after those commitments are fixed. A precommitted private masking
//! polynomial hides the aggregate while the compact opening authenticates its
//! non-Boolean multilinear evaluations.

mod aggregate_source_storage;
mod aggregate_wide_hiding;
mod aggregate_wide_pcs;
mod aggregate_wide_prover;
mod aggregate_wide_verifier;
mod aggregate_wide_wire;
mod algebra;
mod bounded_dft;
mod column_commitment;
mod commitment_liveness;
mod compact_merkle_frontier;
pub(super) mod construction_plan;
mod coordinate_derived_hiding_mmcs;
mod exact_same_secret;
mod generation_state;
mod hiding_whir;
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
mod opening_claim_reduction;
mod opening_schedule;
mod oracle_geometry;
#[cfg(feature = "primitive-measurement-evidence")]
mod primitive_measurements;
mod private_leaf_salt;
mod quotient_transform_storage;
mod recomputable_oracle;
mod relation_materialization;
mod row_encoding;
mod same_secret_source_manifest;
mod source_compression;
mod verification;
#[cfg(test)]
mod verifier_oracle_accounting;

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(in crate::bgv::proof_suite) use construction_plan::ROW_CODE_WHIR_COMPACT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
pub(in crate::bgv::proof_suite) use construction_plan::RowCodeWhirConstructionPlan;
#[cfg(test)]
pub(in crate::bgv::proof_suite) use construction_plan::RowCodeWhirSelectedParameters;
pub(in crate::bgv::proof_suite) use construction_plan::{
    ROW_CODE_WHIR_BALLOT_OPENING_DEGREE_BOUND_EXCLUSIVE,
    ROW_CODE_WHIR_COMMITTED_MATERIAL_OPENING_DEGREE_BOUND_EXCLUSIVE,
    ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE, ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE,
    ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT,
    ROW_CODE_WHIR_TARGET_RELEASE_OPENING_DEGREE_BOUND_EXCLUSIVE,
    selected_row_code_whir_trace_mask_degree_bound_exclusive,
};

pub(in crate::bgv) use exact_same_secret::VerifiedSameSecretLowDegreePrerequisite;
#[cfg(test)]
pub(in crate::bgv::proof_suite) use exact_same_secret::canonical_row_code_whir_aggregate_opening_section_byte_ledger;
pub(in crate::bgv::proof_suite) use exact_same_secret::canonical_row_code_whir_family_body_byte_length_ceiling;
pub(in crate::bgv::proof_suite) use exact_same_secret::{
    ExactSameSecretAuthenticatedTranscriptPrefixRequest, ExactSameSecretFiatShamirBinding,
    ExactSameSecretTranscriptPrefixAuthorityBinding, PreparedExactSameSecretTranscriptPrefix,
};
pub(crate) use exact_same_secret::{
    ExactSameSecretFinalProofVerification, ExactSameSecretIncrementalVerification,
    PreparedExactSameSecretVerification, exact_same_secret_verification_resident_memory_accounting,
    exact_same_secret_verification_runtime_limits, prepare_exact_same_secret_verification,
};
#[cfg(all(test, feature = "theorem-evidence"))]
pub(in crate::bgv::proof_suite) use exact_same_secret::{
    ExactSameSecretTransportCorrespondenceCertificate,
    checked_exact_same_secret_transport_correspondence,
    checked_row_code_whir_transport_correspondence,
};
pub(in crate::bgv::proof_suite) use generation_state::{
    RowCodeWhirGenerationStateMachine, RowCodeWhirTranscriptPrefixAuthority,
    planned_row_code_whir_external_memory_requirement,
};
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) use primitive_measurements::run_primitive_measurement;
pub(in crate::bgv::proof_suite) use quotient_transform_storage::{
    RowCodeWhirQuotientColumnSourcePlan, RowCodeWhirQuotientColumnTransformPlan,
    RowCodeWhirQuotientTransformStoragePlan, RowCodeWhirQuotientTransformStorageRequest,
    plan_row_code_whir_quotient_transform_storage,
};
#[cfg(test)]
pub(crate) use verification::row_code_whir_verification_resident_memory_ceiling;
pub(crate) use verification::{
    PreparedRowCodeWhirVerification, RowCodeWhirFinalProofVerification,
    RowCodeWhirIncrementalVerification, prepare_evaluator_source_bound_row_code_whir_verification,
    prepare_row_code_whir_verification, prepare_setup_polynomial_bound_row_code_whir_verification,
};
#[cfg(test)]
pub(crate) const NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH: usize = 5_242_880;
#[cfg(test)]
pub(crate) const AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH: usize = 7_864_320;

use core::mem::size_of;

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{
    BasedVectorSpace, PrimeCharacteristicRing, PrimeField64, extension::BinomialExtensionField,
};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[cfg(test)]
use super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
use super::{
    ProofChallengeExtensionElement,
    transcript::{
        RowCodeWhirChallenge, RowCodeWhirProofStreamAbsorber, RowCodeWhirTranscript,
        RowCodeWhirTranscriptCheckpointCursor, RowCodeWhirTranscriptSummary, TranscriptError,
    },
};

const MERKLE_DIGEST_WORD_LENGTH: usize = 8;
const MERKLE_DIGEST_BYTE_LENGTH: usize = MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>();
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_MERKLE_DIGEST_BYTE_LENGTH: u16 =
    MERKLE_DIGEST_BYTE_LENGTH as u16;
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN: &[u8] =
    b"sealed-lattice/row-code-whir/shake256/v1";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN: &[u8; 32] =
    b"sealed-lattice/column-hash/v2\0\0\0";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN: &[u8] =
    b"sealed-lattice/column-merkle-node/v1";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN: &[u8] =
    b"aggregate-wide-pcs/merkle-leaf/v3";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN: &[u8] =
    b"aggregate-wide-pcs/merkle-node/v1";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS: [u8; 3] = [0, 1, 2];

type ChallengeField = BinomialExtensionField<Goldilocks, 5>;
type ExtensionFieldChallenger = RowCodeWhirChallenger;
type LeafHasher = ColumnStreamableLeafHasher;
type NodeCompressor =
    CompressionFunctionFromHasher<DomainSeparatedShake256, 2, MERKLE_DIGEST_WORD_LENGTH>;
type PlainCommitmentScheme =
    MerkleTreeMmcs<ChallengeField, u64, LeafHasher, NodeCompressor, 2, MERKLE_DIGEST_WORD_LENGTH>;
type CommitmentScheme = coordinate_derived_hiding_mmcs::CoordinateDerivedHidingMmcs;
type DiscreteFourierTransform = Radix2DFTSmallBatch<ChallengeField>;

const COLUMN_STREAMING_LEAF_STATE_WORD_LENGTH: usize = MERKLE_DIGEST_WORD_LENGTH;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_AGGREGATE_LEAF_STATE_BYTE_LENGTH: u16 =
    (COLUMN_STREAMING_LEAF_STATE_WORD_LENGTH * size_of::<u64>()) as u16;

#[derive(Clone)]
struct AuthenticatedColumn {
    persistent_salt: Option<private_leaf_salt::PrivateLeafSalt>,
    values: Vec<Goldilocks>,
}

#[derive(Clone, Copy, Debug)]
struct DomainSeparatedShake256 {
    domain: &'static [u8],
}

/// SHAKE256 leaf hashing with a 512-bit column-streaming chaining value.
///
/// The aggregate codeword is produced one complete DFT column at a time. A
/// conventional row hasher would retain one 200-byte Keccak state per encoded
/// row, which exceeds the browser memory ceiling at the selected domain. The
/// deployed chain instead retains one 64-byte value per row inside one bounded
/// row stripe. Every transition, final leaf, and Merkle parent therefore has
/// the uniform 512-bit output required by the selected collision ledger.
#[derive(Clone, Copy, Debug)]
struct ColumnStreamableLeafHasher {
    domain: &'static [u8],
    private_leaf_salt: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ColumnStreamableLeafState([u64; COLUMN_STREAMING_LEAF_STATE_WORD_LENGTH]);

impl ColumnStreamableLeafState {
    const ZERO: Self = Self([0_u64; COLUMN_STREAMING_LEAF_STATE_WORD_LENGTH]);
}

#[derive(Clone, Copy, Debug)]
enum ColumnStreamableLeafOracleInput {
    Initial {
        column_count: u64,
        private_leaf_salt: Option<private_leaf_salt::PrivateLeafSalt>,
    },
    Column {
        column_index: u64,
        predecessor: ColumnStreamableLeafState,
        value: ChallengeField,
    },
    Final {
        column_count: u64,
        predecessor: ColumnStreamableLeafState,
    },
}

impl ColumnStreamableLeafOracleInput {
    const fn frame(self) -> u8 {
        match self {
            Self::Initial { .. } => ColumnStreamableLeafHasher::INITIAL_FRAME,
            Self::Column { .. } => ColumnStreamableLeafHasher::COLUMN_FRAME,
            Self::Final { .. } => ColumnStreamableLeafHasher::FINAL_FRAME,
        }
    }

    fn visit_payload(self, mut visit: impl FnMut(&[u8])) {
        match self {
            Self::Initial {
                column_count,
                private_leaf_salt,
            } => {
                visit(&column_count.to_le_bytes());
                visit(
                    &u64::try_from(private_leaf_salt.as_ref().map_or(0, |salt| salt.len()))
                        .expect("private aggregate leaf salt length fits u64")
                        .to_le_bytes(),
                );
                if let Some(salt) = private_leaf_salt {
                    visit(&salt);
                }
            }
            Self::Column {
                column_index,
                predecessor,
                value,
            } => {
                visit(&column_index.to_le_bytes());
                for word in predecessor.0 {
                    visit(&word.to_le_bytes());
                }
                for coefficient in
                    <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                        &value,
                    )
                {
                    visit(&coefficient.as_canonical_u64().to_le_bytes());
                }
            }
            Self::Final {
                column_count,
                predecessor,
            } => {
                visit(&column_count.to_le_bytes());
                for word in predecessor.0 {
                    visit(&word.to_le_bytes());
                }
            }
        }
    }
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColumnStreamableLeafOracleFrame {
    Initial,
    Column,
    Final,
}

#[cfg(all(test, feature = "theorem-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ColumnStreamableLeafOracleFrameDescriptor {
    frame: ColumnStreamableLeafOracleFrame,
    frame_tag: u8,
    canonical_input_byte_length: usize,
    predecessor_digest_count: usize,
    extension_value_count: usize,
    output_bit_length: usize,
}

fn aggregate_leaf_hasher(
    privacy_mode: crate::bgv::proof_suite::relation_plan::ProofPrivacyMode,
) -> LeafHasher {
    LeafHasher::new(
        DomainSeparatedShake256 {
            domain: ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN,
        },
        privacy_mode == crate::bgv::proof_suite::relation_plan::ProofPrivacyMode::SecretBearing,
    )
}

fn aggregate_node_compressor() -> NodeCompressor {
    NodeCompressor::new(DomainSeparatedShake256 {
        domain: ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
    })
}

impl ColumnStreamableLeafHasher {
    const INITIAL_FRAME: u8 = ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[0];
    const COLUMN_FRAME: u8 = ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[1];
    const FINAL_FRAME: u8 = ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[2];

    const fn new(hasher: DomainSeparatedShake256, private_leaf_salt: bool) -> Self {
        Self {
            domain: hasher.domain,
            private_leaf_salt,
        }
    }

    #[cfg(test)]
    const fn intermediate_output_bit_length() -> usize {
        COLUMN_STREAMING_LEAF_STATE_WORD_LENGTH * u64::BITS as usize
    }

    #[cfg(test)]
    const fn final_output_bit_length() -> usize {
        MERKLE_DIGEST_WORD_LENGTH * u64::BITS as usize
    }

    fn hash_oracle_input(
        &self,
        input: ColumnStreamableLeafOracleInput,
    ) -> [u64; MERKLE_DIGEST_WORD_LENGTH] {
        let mut state = Shake256::default();
        state.update(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN);
        state.update(&(self.domain.len() as u64).to_le_bytes());
        state.update(self.domain);
        state.update(&[input.frame()]);
        input.visit_payload(|bytes| state.update(bytes));
        Self::finish_digest_words(state)
    }

    fn finish_digest_words(state: Shake256) -> [u64; MERKLE_DIGEST_WORD_LENGTH] {
        let mut bytes = [0_u8; MERKLE_DIGEST_BYTE_LENGTH];
        state.finalize_xof().read(&mut bytes);
        core::array::from_fn(|word_index| {
            let start = word_index * size_of::<u64>();
            u64::from_le_bytes(
                bytes[start..start + size_of::<u64>()]
                    .try_into()
                    .expect("one leaf-hash word has eight bytes"),
            )
        })
    }

    fn initial_state(
        &self,
        column_count: usize,
        private_leaf_salt: Option<&private_leaf_salt::PrivateLeafSalt>,
    ) -> ColumnStreamableLeafState {
        assert_eq!(
            private_leaf_salt.is_some(),
            self.private_leaf_salt,
            "aggregate leaf salt presence diverges from the construction"
        );
        ColumnStreamableLeafState(self.hash_oracle_input(
            ColumnStreamableLeafOracleInput::Initial {
                column_count: column_count as u64,
                private_leaf_salt: private_leaf_salt.copied(),
            },
        ))
    }

    fn absorb_column(
        &self,
        state: ColumnStreamableLeafState,
        column_index: usize,
        value: ChallengeField,
    ) -> ColumnStreamableLeafState {
        ColumnStreamableLeafState(
            self.hash_oracle_input(ColumnStreamableLeafOracleInput::Column {
                column_index: column_index as u64,
                predecessor: state,
                value,
            }),
        )
    }

    fn finish_leaf(
        &self,
        column_count: usize,
        state: ColumnStreamableLeafState,
    ) -> [u64; MERKLE_DIGEST_WORD_LENGTH] {
        self.hash_oracle_input(ColumnStreamableLeafOracleInput::Final {
            column_count: column_count as u64,
            predecessor: state,
        })
    }

    #[cfg(test)]
    fn canonical_oracle_input_bytes(&self, input: ColumnStreamableLeafOracleInput) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN);
        bytes.extend_from_slice(&(self.domain.len() as u64).to_le_bytes());
        bytes.extend_from_slice(self.domain);
        bytes.push(input.frame());
        input.visit_payload(|payload| bytes.extend_from_slice(payload));
        bytes
    }

    #[cfg(all(test, feature = "theorem-evidence"))]
    fn frame_descriptor(
        &self,
        frame: ColumnStreamableLeafOracleFrame,
    ) -> ColumnStreamableLeafOracleFrameDescriptor {
        let input = match frame {
            ColumnStreamableLeafOracleFrame::Initial => ColumnStreamableLeafOracleInput::Initial {
                column_count: 1,
                private_leaf_salt: if self.private_leaf_salt {
                    Some([0_u8; private_leaf_salt::PRIVATE_LEAF_SALT_BYTE_LENGTH])
                } else {
                    None
                },
            },
            ColumnStreamableLeafOracleFrame::Column => ColumnStreamableLeafOracleInput::Column {
                column_index: 0,
                predecessor: ColumnStreamableLeafState::ZERO,
                value: ChallengeField::ZERO,
            },
            ColumnStreamableLeafOracleFrame::Final => ColumnStreamableLeafOracleInput::Final {
                column_count: 1,
                predecessor: ColumnStreamableLeafState::ZERO,
            },
        };
        ColumnStreamableLeafOracleFrameDescriptor {
            frame,
            frame_tag: input.frame(),
            canonical_input_byte_length: self.canonical_oracle_input_bytes(input).len(),
            predecessor_digest_count: usize::from(!matches!(
                frame,
                ColumnStreamableLeafOracleFrame::Initial
            )),
            extension_value_count: usize::from(matches!(
                frame,
                ColumnStreamableLeafOracleFrame::Column
            )),
            output_bit_length: Self::intermediate_output_bit_length(),
        }
    }
}

impl CryptographicHasher<ChallengeField, [u64; MERKLE_DIGEST_WORD_LENGTH]>
    for ColumnStreamableLeafHasher
{
    fn hash_iter<Input>(&self, input: Input) -> [u64; MERKLE_DIGEST_WORD_LENGTH]
    where
        Input: IntoIterator<Item = ChallengeField>,
    {
        let mut values = input.into_iter().collect::<Vec<_>>();
        let private_leaf_salt = if self.private_leaf_salt {
            let suffix_start = values
                .len()
                .checked_sub(
                    coordinate_derived_hiding_mmcs::AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT,
                )
                .expect("secret-bearing aggregate leaf contains its salt suffix");
            let encoded_salt = values.split_off(suffix_start);
            Some(
                coordinate_derived_hiding_mmcs::decode_private_leaf_salt(&encoded_salt)
                    .expect("secret-bearing aggregate leaf salt is injectively encoded"),
            )
        } else {
            None
        };
        let column_count = values.len();
        let mut state = self.initial_state(column_count, private_leaf_salt.as_ref());
        for (column_index, value) in values.into_iter().enumerate() {
            state = self.absorb_column(state, column_index, value);
        }
        self.finish_leaf(column_count, state)
    }
}

impl DomainSeparatedShake256 {
    fn visit_preamble(self, mut visit: impl FnMut(&[u8])) {
        visit(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN);
        visit(&(self.domain.len() as u64).to_le_bytes());
        visit(self.domain);
    }

    fn initialized_state(self) -> Shake256 {
        let mut state = Shake256::default();
        self.visit_preamble(|bytes| state.update(bytes));
        state
    }

    #[cfg(all(test, feature = "theorem-evidence"))]
    fn canonical_u64_oracle_input_bytes(self, input: impl IntoIterator<Item = u64>) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.visit_preamble(|part| bytes.extend_from_slice(part));
        for word in input {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn finish(state: Shake256) -> [u8; MERKLE_DIGEST_BYTE_LENGTH] {
        let mut output = [0_u8; MERKLE_DIGEST_BYTE_LENGTH];
        state.finalize_xof().read(&mut output);
        output
    }
}

impl CryptographicHasher<u8, [u8; MERKLE_DIGEST_BYTE_LENGTH]> for DomainSeparatedShake256 {
    fn hash_iter<Input>(&self, input: Input) -> [u8; MERKLE_DIGEST_BYTE_LENGTH]
    where
        Input: IntoIterator<Item = u8>,
    {
        let mut state = self.initialized_state();
        let mut buffer = [0_u8; 4_096];
        let mut used_byte_length = 0_usize;
        for byte in input {
            buffer[used_byte_length] = byte;
            used_byte_length += 1;
            if used_byte_length == buffer.len() {
                state.update(&buffer);
                used_byte_length = 0;
            }
        }
        state.update(&buffer[..used_byte_length]);
        Self::finish(state)
    }
}

impl CryptographicHasher<u64, [u64; MERKLE_DIGEST_WORD_LENGTH]> for DomainSeparatedShake256 {
    fn hash_iter<Input>(&self, input: Input) -> [u64; MERKLE_DIGEST_WORD_LENGTH]
    where
        Input: IntoIterator<Item = u64>,
    {
        let bytes = <Self as CryptographicHasher<u8, [u8; MERKLE_DIGEST_BYTE_LENGTH]>>::hash_iter(
            self,
            input.into_iter().flat_map(u64::to_le_bytes),
        );
        core::array::from_fn(|word_index| {
            u64::from_le_bytes(
                bytes[word_index * 8..(word_index + 1) * 8]
                    .try_into()
                    .expect("each digest word has eight bytes"),
            )
        })
    }
}

/// Byte-backed Fiat-Shamir challenger for the degree-five field.
///
/// Plonky3's serializing challenger is restricted to prime fields, so the
/// canonical transcript samples one degree-five extension element from one
/// bounded 512-bit rejection-sampling stream.
#[derive(Clone, Debug)]
struct RowCodeWhirChallenger {
    transcript: RowCodeWhirTranscript,
    sampling_failure: Option<ChallengerSamplingFailure>,
    protocol_schedule_absorbed: bool,
    query_schedule: Vec<WhirQueryEpoch>,
    next_query_epoch: usize,
    active_query_indices: Vec<usize>,
    sampled_query_index_schedule: Vec<Vec<usize>>,
    next_active_query_index: usize,
    next_unscheduled_failure_query_index: usize,
}

pub(super) struct RowCodeWhirChallengerProofStreamAbsorber {
    transcript_absorber: RowCodeWhirProofStreamAbsorber,
}

impl RowCodeWhirChallengerProofStreamAbsorber {
    pub(super) fn absorb(&mut self, canonical_proof_byte_chunk: &[u8]) -> Result<(), String> {
        self.transcript_absorber
            .absorb(canonical_proof_byte_chunk)
            .map_err(|error| format!("absorb typed row-code WHIR proof stream: {error:?}"))
    }

    pub(super) fn finish(self) -> Result<RowCodeWhirTranscriptSummary, String> {
        self.transcript_absorber
            .finish()
            .map_err(|error| format!("finish typed row-code WHIR transcript: {error:?}"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChallengerSamplingFailure {
    ExtensionChallengeCandidateDrawsExhausted,
    DistinctQueryCandidateDrawsExhausted,
    TranscriptStateMismatch,
    QueryScheduleMismatch,
}

fn extension_sampling_failure_for_transcript_error(
    error: &TranscriptError,
) -> ChallengerSamplingFailure {
    match error {
        TranscriptError::CommonChallengeDrawsExhausted => {
            ChallengerSamplingFailure::ExtensionChallengeCandidateDrawsExhausted
        }
        _ => ChallengerSamplingFailure::TranscriptStateMismatch,
    }
}

fn query_sampling_failure_for_transcript_error(
    error: &TranscriptError,
) -> ChallengerSamplingFailure {
    match error {
        TranscriptError::CommonChallengeDrawsExhausted => {
            ChallengerSamplingFailure::DistinctQueryCandidateDrawsExhausted
        }
        _ => ChallengerSamplingFailure::TranscriptStateMismatch,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirQueryEpoch {
    bit_length: usize,
    query_count: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedSamplingError {
    InvalidUpperBound,
    CandidateDrawsExhausted,
}

#[cfg(test)]
fn sample_bounded_goldilocks_candidate(
    mut next_candidate: impl FnMut() -> u64,
) -> Result<Goldilocks, BoundedSamplingError> {
    for _ in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
        let candidate = next_candidate();
        if candidate < GOLDILOCKS_MODULUS {
            return Ok(Goldilocks::from_u64(candidate));
        }
    }
    Err(BoundedSamplingError::CandidateDrawsExhausted)
}

#[cfg(test)]
fn sample_bounded_residue_index(
    upper_bound: usize,
    mut is_acceptable: impl FnMut(usize) -> bool,
    mut next_candidate: impl FnMut() -> u64,
) -> Result<usize, BoundedSamplingError> {
    let upper_bound =
        u64::try_from(upper_bound).map_err(|_| BoundedSamplingError::InvalidUpperBound)?;
    if upper_bound == 0 {
        return Err(BoundedSamplingError::InvalidUpperBound);
    }
    let rejection_threshold = upper_bound.wrapping_neg() % upper_bound;
    for _ in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
        let candidate = next_candidate();
        if candidate >= rejection_threshold {
            let index = usize::try_from(candidate % upper_bound)
                .map_err(|_| BoundedSamplingError::InvalidUpperBound)?;
            if is_acceptable(index) {
                return Ok(index);
            }
        }
    }
    Err(BoundedSamplingError::CandidateDrawsExhausted)
}

impl RowCodeWhirChallenger {
    fn new(transcript: RowCodeWhirTranscript, query_schedule: Vec<WhirQueryEpoch>) -> Self {
        Self {
            transcript,
            sampling_failure: None,
            protocol_schedule_absorbed: false,
            query_schedule,
            next_query_epoch: 0,
            active_query_indices: Vec::new(),
            sampled_query_index_schedule: Vec::new(),
            next_active_query_index: 0,
            next_unscheduled_failure_query_index: 0,
        }
    }

    fn sample_exact_challenge(
        &mut self,
        challenge: RowCodeWhirChallenge,
    ) -> Result<ChallengeField, String> {
        let sampled = self
            .transcript
            .sample_direct_extension(challenge)
            .map_err(|error| format!("sample typed row-code challenge: {error:?}"))?;
        Ok(challenge_from_production(sampled))
    }

    fn sample_exact_distinct_indices(
        &mut self,
        challenge: RowCodeWhirChallenge,
        upper_bound: usize,
        output_count: usize,
    ) -> Result<Vec<usize>, String> {
        self.transcript
            .sample_direct_distinct_indices(challenge, upper_bound, output_count)
            .map_err(|error| format!("sample typed row-code query vector: {error:?}"))
    }

    fn record_sampling_failure(&mut self, failure: ChallengerSamplingFailure) {
        if self.sampling_failure.is_none() {
            self.sampling_failure = Some(failure);
        }
    }

    fn record_transcript_failure(&mut self) {
        self.record_sampling_failure(ChallengerSamplingFailure::TranscriptStateMismatch);
    }

    fn record_transcript_state_error(&mut self, _error: TranscriptError) {
        self.record_transcript_failure();
    }

    fn record_extension_transcript_error(&mut self, error: TranscriptError) {
        self.record_sampling_failure(extension_sampling_failure_for_transcript_error(&error));
    }

    fn record_query_transcript_error(&mut self, error: TranscriptError) {
        self.record_sampling_failure(query_sampling_failure_for_transcript_error(&error));
    }

    fn observe_production_values(&mut self, values: &[ProofChallengeExtensionElement]) {
        if values.is_empty() {
            return;
        }
        let result = if self.protocol_schedule_absorbed {
            match self.transcript.next_live_whir_observation_role() {
                Ok(Some(role)) => self.transcript.observe_whir_values(role, values),
                Ok(None) => {
                    #[cfg(test)]
                    {
                        self.transcript
                            .observe_whir_values_without_role_for_test(values)
                    }
                    #[cfg(not(test))]
                    {
                        Err(TranscriptError::UnexpectedRowCodeWhirRound)
                    }
                }
                Err(error) => Err(error),
            }
        } else {
            self.transcript.absorb_protocol_schedule(values)
        };
        match result {
            Ok(()) => self.protocol_schedule_absorbed = true,
            Err(error) => self.record_transcript_state_error(error),
        }
    }

    fn install_scheduled_failure_query_epoch(&mut self, bits: usize) -> bool {
        let Some(epoch) = self.query_schedule.get(self.next_query_epoch).copied() else {
            return false;
        };
        let domain_size = 1_usize
            .checked_shl(u32::try_from(bits).unwrap_or(u32::MAX))
            .unwrap_or(1);
        let placeholder_count = epoch.query_count.min(domain_size).max(1);
        self.active_query_indices = (0..placeholder_count).collect();
        self.next_active_query_index = 0;
        self.next_query_epoch += 1;
        true
    }

    fn next_unscheduled_failure_query_index(&mut self, bits: usize) -> usize {
        let domain_size = 1_usize
            .checked_shl(u32::try_from(bits).unwrap_or(u32::MAX))
            .unwrap_or(1);
        let sampled = self.next_unscheduled_failure_query_index % domain_size;
        self.next_unscheduled_failure_query_index =
            self.next_unscheduled_failure_query_index.wrapping_add(1);
        sampled
    }

    fn ensure_sampling_succeeded(&self) -> Result<(), String> {
        match self.sampling_failure {
            None => Ok(()),
            Some(ChallengerSamplingFailure::ExtensionChallengeCandidateDrawsExhausted) => Err(
                "aggregate-wide WHIR extension challenge sampling exhausted its candidate ceiling"
                    .to_owned(),
            ),
            Some(ChallengerSamplingFailure::DistinctQueryCandidateDrawsExhausted) => Err(
                "aggregate-wide WHIR distinct query sampling exhausted its candidate ceiling"
                    .to_owned(),
            ),
            Some(ChallengerSamplingFailure::TranscriptStateMismatch) => Err(
                "aggregate-wide WHIR transcript state did not match the typed protocol".to_owned(),
            ),
            Some(ChallengerSamplingFailure::QueryScheduleMismatch) => Err(
                "aggregate-wide WHIR query calls did not match the PCS-owned schedule".to_owned(),
            ),
        }
    }

    fn ensure_query_schedule_consumed(&self) -> Result<(), String> {
        if self.next_query_epoch != self.query_schedule.len()
            || self.next_active_query_index != self.active_query_indices.len()
        {
            return Err(
                "aggregate-wide WHIR query schedule was not completely consumed".to_owned(),
            );
        }
        Ok(())
    }

    fn sampled_query_index_schedule(&self) -> Result<Vec<Vec<usize>>, String> {
        self.ensure_sampling_succeeded()?;
        self.ensure_query_schedule_consumed()?;
        if self.sampled_query_index_schedule.len() != self.query_schedule.len() {
            return Err(
                "aggregate-wide WHIR sampled query schedule has the wrong shape".to_owned(),
            );
        }
        Ok(self.sampled_query_index_schedule.clone())
    }

    fn checkpoint_cursor(
        &self,
        construction_plan: &RowCodeWhirConstructionPlan,
    ) -> Result<RowCodeWhirTranscriptCheckpointCursor, TranscriptError> {
        self.transcript.checkpoint_cursor(construction_plan)
    }

    fn restore_checkpoint_cursor(
        &mut self,
        construction_plan: &RowCodeWhirConstructionPlan,
        cursor: &RowCodeWhirTranscriptCheckpointCursor,
    ) -> Result<(), TranscriptError> {
        self.transcript =
            RowCodeWhirTranscript::restore_checkpoint_cursor(construction_plan, cursor)?;
        Ok(())
    }

    pub(super) fn begin_final_proof_stream(
        self,
        canonical_proof_byte_length: usize,
    ) -> Result<RowCodeWhirChallengerProofStreamAbsorber, String> {
        self.ensure_sampling_succeeded()?;
        self.ensure_query_schedule_consumed()?;
        let transcript_absorber = self
            .transcript
            .begin_final_proof_stream(canonical_proof_byte_length)
            .map_err(|error| format!("begin typed row-code WHIR proof stream: {error:?}"))?;
        Ok(RowCodeWhirChallengerProofStreamAbsorber {
            transcript_absorber,
        })
    }

    #[cfg(test)]
    fn finish(self, canonical_proof_bytes: &[u8]) -> Result<RowCodeWhirTranscriptSummary, String> {
        self.ensure_sampling_succeeded()?;
        self.ensure_query_schedule_consumed()?;
        self.transcript
            .finish(canonical_proof_bytes)
            .map_err(|error| format!("finish typed row-code WHIR transcript: {error:?}"))
    }
}

fn challenge_from_production(value: ProofChallengeExtensionElement) -> ChallengeField {
    ChallengeField::new(value.canonical_coordinates().map(Goldilocks::from_u64))
}

fn challenge_to_production(value: ChallengeField) -> Result<ProofChallengeExtensionElement, ()> {
    let basis_coefficients: &[Goldilocks; 5] =
        <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value)
            .try_into()
            .map_err(|_| ())?;
    let coordinates = core::array::from_fn(|index| basis_coefficients[index].as_canonical_u64());
    ProofChallengeExtensionElement::from_canonical_coordinates(coordinates).map_err(|_| ())
}

impl CanObserve<ChallengeField> for RowCodeWhirChallenger {
    fn observe(&mut self, value: ChallengeField) {
        self.observe_slice(&[value]);
    }

    fn observe_slice(&mut self, values: &[ChallengeField]) {
        if values.is_empty() {
            return;
        }
        let converted = values
            .iter()
            .copied()
            .map(challenge_to_production)
            .collect::<Result<Vec<_>, _>>();
        let Ok(converted) = converted else {
            self.record_transcript_failure();
            return;
        };
        self.observe_production_values(&converted);
    }
}

impl CanObserve<MerkleCap<ChallengeField, [u64; MERKLE_DIGEST_WORD_LENGTH]>>
    for RowCodeWhirChallenger
{
    fn observe(&mut self, commitment: MerkleCap<ChallengeField, [u64; MERKLE_DIGEST_WORD_LENGTH]>) {
        let mut canonical_commitment_bytes = Vec::new();
        for digest in commitment.roots() {
            for word in digest {
                canonical_commitment_bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        if let Err(error) = self
            .transcript
            .observe_commitment(&canonical_commitment_bytes)
        {
            self.record_transcript_state_error(error);
        }
    }
}

impl CanSample<ChallengeField> for RowCodeWhirChallenger {
    fn sample(&mut self) -> ChallengeField {
        let sampled = match self.transcript.next_live_whir_extension_role() {
            Ok(Some(role)) => self.transcript.sample_whir_extension(role),
            Ok(None) => {
                #[cfg(test)]
                {
                    self.transcript
                        .sample_whir_extension_without_role_for_test()
                }
                #[cfg(not(test))]
                {
                    Err(TranscriptError::UnexpectedRowCodeWhirChallenge)
                }
            }
            Err(error) => Err(error),
        };
        match sampled {
            Ok(sampled) => challenge_from_production(sampled),
            Err(error) => {
                self.record_extension_transcript_error(error);
                ChallengeField::ZERO
            }
        }
    }
}

impl CanSampleBits<usize> for RowCodeWhirChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        match self.transcript.sample_whir_bits(bits) {
            Ok(sampled) => sampled,
            Err(error) => {
                self.record_transcript_state_error(error);
                0
            }
        }
    }
}

impl CanSampleUniformBits<ChallengeField> for RowCodeWhirChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        if self.sampling_failure.is_some()
            && self.next_active_query_index == self.active_query_indices.len()
            && !self.install_scheduled_failure_query_epoch(bits)
        {
            return Ok(self.next_unscheduled_failure_query_index(bits));
        }
        if self.next_active_query_index == self.active_query_indices.len() {
            let Some(epoch) = self.query_schedule.get(self.next_query_epoch).copied() else {
                self.record_sampling_failure(ChallengerSamplingFailure::QueryScheduleMismatch);
                return Ok(self.next_unscheduled_failure_query_index(bits));
            };
            if epoch.bit_length != bits {
                self.record_sampling_failure(ChallengerSamplingFailure::QueryScheduleMismatch);
                let installed = self.install_scheduled_failure_query_epoch(bits);
                debug_assert!(installed, "the mismatched epoch was just read");
                let sampled = self.active_query_indices[self.next_active_query_index];
                self.next_active_query_index += 1;
                return Ok(sampled);
            }
            let sampled = u32::try_from(self.next_query_epoch)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)
                .and_then(|epoch_ordinal| {
                    self.transcript
                        .sample_whir_query_vector(bits, epoch_ordinal, epoch.query_count)
                });
            match sampled {
                Ok(indices) => {
                    let mut canonical_indices = indices.clone();
                    canonical_indices.sort_unstable();
                    self.sampled_query_index_schedule.push(canonical_indices);
                    self.active_query_indices = indices;
                    self.next_active_query_index = 0;
                    self.next_query_epoch += 1;
                }
                Err(error) => {
                    self.record_query_transcript_error(error);
                    let installed = self.install_scheduled_failure_query_epoch(bits);
                    debug_assert!(installed, "the failed epoch was just read");
                }
            }
        }
        let sampled = self.active_query_indices[self.next_active_query_index];
        self.next_active_query_index += 1;
        Ok(sampled)
    }
}

impl GrindingChallenger for RowCodeWhirChallenger {
    type Witness = ChallengeField;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        if bits != 0 {
            self.record_transcript_failure();
        }
        ChallengeField::ZERO
    }
}

impl FieldChallenger<ChallengeField> for RowCodeWhirChallenger {
    fn observe_algebra_slice<AlgebraElement>(&mut self, algebra_elements: &[AlgebraElement])
    where
        AlgebraElement: BasedVectorSpace<ChallengeField> + Clone,
    {
        let converted = algebra_elements
            .iter()
            .flat_map(|element| element.as_basis_coefficients_slice().iter().copied())
            .map(challenge_to_production)
            .collect::<Result<Vec<_>, _>>();
        match converted {
            Ok(converted) => self.observe_production_values(&converted),
            Err(()) => self.record_transcript_failure(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_leaf_hash_matches_column_streaming_and_binds_order() {
        let hasher = aggregate_leaf_hasher(
            crate::bgv::proof_suite::relation_plan::ProofPrivacyMode::PublicOnly,
        );
        let values = (1_u64..=8)
            .map(ChallengeField::from_u64)
            .collect::<Vec<_>>();
        let direct = hasher.hash_iter(values.iter().copied());
        let mut state = hasher.initial_state(values.len(), None);
        for (column_index, value) in values.iter().copied().enumerate() {
            state = hasher.absorb_column(state, column_index, value);
        }
        assert_eq!(direct, hasher.finish_leaf(values.len(), state));

        let mut reversed = values;
        reversed.reverse();
        assert_ne!(direct, hasher.hash_iter(reversed));
    }

    #[test]
    fn aggregate_leaf_oracle_frames_bind_every_canonical_input_coordinate() {
        let hasher = aggregate_leaf_hasher(
            crate::bgv::proof_suite::relation_plan::ProofPrivacyMode::PublicOnly,
        );
        let column_index = 0x0102_0304_0506_0708_u64;
        let predecessor = ColumnStreamableLeafState([
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            0x3132_3334_3536_3738,
            0x4142_4344_4546_4748,
            0x5152_5354_5556_5758,
            0x6162_6364_6566_6768,
            0x7172_7374_7576_7778,
            0x8182_8384_8586_8788,
        ]);
        let coefficient_words = [
            0_u64,
            1,
            0x0102_0304_0506_0708,
            GOLDILOCKS_MODULUS - 2,
            GOLDILOCKS_MODULUS - 1,
        ];
        let value = ChallengeField::new(coefficient_words.map(Goldilocks::from_u64));
        let input = ColumnStreamableLeafOracleInput::Column {
            column_index,
            predecessor,
            value,
        };

        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN);
        expected_input.extend_from_slice(
            &u64::try_from(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len())
                .expect("the aggregate leaf domain length fits u64")
                .to_le_bytes(),
        );
        expected_input.extend_from_slice(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN);
        expected_input.push(ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[1]);
        expected_input.extend_from_slice(&column_index.to_le_bytes());
        for predecessor_word in predecessor.0 {
            expected_input.extend_from_slice(&predecessor_word.to_le_bytes());
        }
        for coefficient_word in coefficient_words {
            expected_input.extend_from_slice(&coefficient_word.to_le_bytes());
        }
        assert_eq!(expected_input.len(), 194);
        assert_eq!(hasher.canonical_oracle_input_bytes(input), expected_input);

        let mut independently_framed_state = Shake256::default();
        independently_framed_state.update(&expected_input);
        assert_eq!(
            hasher.hash_oracle_input(input),
            ColumnStreamableLeafHasher::finish_digest_words(independently_framed_state),
        );

        let mut changed_predecessor = predecessor;
        changed_predecessor.0[3] ^= 1;
        assert_ne!(
            hasher.hash_oracle_input(input),
            hasher.hash_oracle_input(ColumnStreamableLeafOracleInput::Column {
                column_index,
                predecessor: changed_predecessor,
                value,
            }),
        );
        assert_ne!(
            hasher.hash_oracle_input(input),
            hasher.hash_oracle_input(ColumnStreamableLeafOracleInput::Column {
                column_index: column_index + 1,
                predecessor,
                value,
            }),
        );
        assert_ne!(
            hasher.hash_oracle_input(input),
            hasher.hash_oracle_input(ColumnStreamableLeafOracleInput::Column {
                column_index,
                predecessor,
                value: value + ChallengeField::ONE,
            }),
        );

        let initial_input = ColumnStreamableLeafOracleInput::Initial {
            column_count: 8,
            private_leaf_salt: None,
        };
        let final_input = ColumnStreamableLeafOracleInput::Final {
            column_count: 8,
            predecessor,
        };
        assert_eq!(hasher.canonical_oracle_input_bytes(initial_input).len(), 98,);
        assert_eq!(hasher.canonical_oracle_input_bytes(final_input).len(), 154);
        assert_ne!(
            hasher.hash_oracle_input(initial_input),
            hasher.hash_oracle_input(ColumnStreamableLeafOracleInput::Initial {
                column_count: 7,
                private_leaf_salt: None,
            }),
        );
        assert_ne!(
            hasher.hash_oracle_input(final_input),
            hasher.hash_oracle_input(ColumnStreamableLeafOracleInput::Final {
                column_count: 7,
                predecessor,
            }),
        );
    }

    #[test]
    fn collision_free_aggregate_leaf_database_recovers_the_exact_ordered_trace() {
        fn read_word(bytes: &[u8], offset: usize) -> Option<u64> {
            Some(u64::from_le_bytes(
                bytes
                    .get(offset..offset.checked_add(size_of::<u64>())?)?
                    .try_into()
                    .ok()?,
            ))
        }

        fn read_predecessor(
            bytes: &[u8],
            offset: usize,
        ) -> Option<[u64; MERKLE_DIGEST_WORD_LENGTH]> {
            let mut predecessor = [0_u64; MERKLE_DIGEST_WORD_LENGTH];
            for (word_index, word) in predecessor.iter_mut().enumerate() {
                *word = read_word(
                    bytes,
                    offset.checked_add(word_index.checked_mul(size_of::<u64>())?)?,
                )?;
            }
            Some(predecessor)
        }

        fn has_canonical_prefix(bytes: &[u8]) -> bool {
            let domain_length_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN.len();
            let domain_offset = domain_length_offset + size_of::<u64>();
            bytes.get(..domain_length_offset) == Some(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN)
                && read_word(bytes, domain_length_offset)
                    == u64::try_from(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len()).ok()
                && bytes
                    .get(domain_offset..domain_offset + ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len())
                    == Some(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN)
        }

        fn recover_trace(
            database: &std::collections::BTreeMap<[u64; MERKLE_DIGEST_WORD_LENGTH], Vec<u8>>,
            final_digest: [u64; MERKLE_DIGEST_WORD_LENGTH],
        ) -> Option<Vec<[u64; 5]>> {
            let frame_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN
                .len()
                .checked_add(size_of::<u64>())?
                .checked_add(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len())?;
            let payload_offset = frame_offset.checked_add(size_of::<u8>())?;
            let counted_input_byte_length = payload_offset.checked_add(size_of::<u64>())?;
            let public_initial_input_byte_length =
                counted_input_byte_length.checked_add(size_of::<u64>())?;
            let final_input_byte_length =
                counted_input_byte_length.checked_add(MERKLE_DIGEST_BYTE_LENGTH)?;
            let column_input_byte_length =
                final_input_byte_length.checked_add(5_usize.checked_mul(size_of::<u64>())?)?;
            let final_input = database.get(&final_digest)?;
            if final_input.len() != final_input_byte_length
                || !has_canonical_prefix(final_input)
                || final_input.get(frame_offset)
                    != Some(&ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[2])
            {
                return None;
            }
            let column_count = usize::try_from(read_word(final_input, payload_offset)?).ok()?;
            let mut predecessor =
                read_predecessor(final_input, payload_offset.checked_add(size_of::<u64>())?)?;
            let mut reversed_coefficients = Vec::with_capacity(column_count);
            for expected_column_index in (0..column_count).rev() {
                let column_input = database.get(&predecessor)?;
                if column_input.len() != column_input_byte_length
                    || !has_canonical_prefix(column_input)
                    || column_input.get(frame_offset)
                        != Some(&ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[1])
                    || usize::try_from(read_word(column_input, payload_offset)?).ok()?
                        != expected_column_index
                {
                    return None;
                }
                predecessor =
                    read_predecessor(column_input, payload_offset.checked_add(size_of::<u64>())?)?;
                let coefficient_offset = payload_offset
                    .checked_add(size_of::<u64>())?
                    .checked_add(MERKLE_DIGEST_BYTE_LENGTH)?;
                let mut coefficients = [0_u64; 5];
                for (coefficient_index, coefficient) in coefficients.iter_mut().enumerate() {
                    *coefficient = read_word(
                        column_input,
                        coefficient_offset
                            .checked_add(coefficient_index.checked_mul(size_of::<u64>())?)?,
                    )?;
                    if *coefficient >= GOLDILOCKS_MODULUS {
                        return None;
                    }
                }
                reversed_coefficients.push(coefficients);
            }
            let initial_input = database.get(&predecessor)?;
            if initial_input.len() != public_initial_input_byte_length
                || !has_canonical_prefix(initial_input)
                || initial_input.get(frame_offset)
                    != Some(&ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[0])
                || usize::try_from(read_word(initial_input, payload_offset)?).ok()? != column_count
            {
                return None;
            }
            reversed_coefficients.reverse();
            Some(reversed_coefficients)
        }

        let coefficient_rows = [
            [1, 2, 3, 4, 5],
            [11, 12, 13, 14, 15],
            [21, 22, 23, 24, 25],
            [
                GOLDILOCKS_MODULUS - 5,
                GOLDILOCKS_MODULUS - 4,
                GOLDILOCKS_MODULUS - 3,
                GOLDILOCKS_MODULUS - 2,
                GOLDILOCKS_MODULUS - 1,
            ],
        ];
        let values = coefficient_rows
            .map(|coefficients| ChallengeField::new(coefficients.map(Goldilocks::from_u64)));
        let hasher = aggregate_leaf_hasher(
            crate::bgv::proof_suite::relation_plan::ProofPrivacyMode::PublicOnly,
        );
        let initial_input = ColumnStreamableLeafOracleInput::Initial {
            column_count: values.len() as u64,
            private_leaf_salt: None,
        };
        let mut database = std::collections::BTreeMap::new();
        let mut state = ColumnStreamableLeafState(hasher.hash_oracle_input(initial_input));
        assert!(
            database
                .insert(state.0, hasher.canonical_oracle_input_bytes(initial_input),)
                .is_none(),
        );
        let mut transition_digests = Vec::new();
        for (column_index, value) in values.into_iter().enumerate() {
            let input = ColumnStreamableLeafOracleInput::Column {
                column_index: column_index as u64,
                predecessor: state,
                value,
            };
            state = ColumnStreamableLeafState(hasher.hash_oracle_input(input));
            transition_digests.push(state.0);
            assert!(
                database
                    .insert(state.0, hasher.canonical_oracle_input_bytes(input))
                    .is_none(),
                "the representative production trace is collision-free",
            );
        }
        let final_input = ColumnStreamableLeafOracleInput::Final {
            column_count: values.len() as u64,
            predecessor: state,
        };
        let final_digest = hasher.hash_oracle_input(final_input);
        assert!(
            database
                .insert(
                    final_digest,
                    hasher.canonical_oracle_input_bytes(final_input),
                )
                .is_none(),
        );
        assert_eq!(
            recover_trace(&database, final_digest),
            Some(coefficient_rows.to_vec()),
        );

        let mut missing_predecessor = database.clone();
        missing_predecessor.remove(&transition_digests[1]);
        assert_eq!(recover_trace(&missing_predecessor, final_digest), None);

        let mut reordered_transition = database.clone();
        let reordered_bytes = reordered_transition
            .get_mut(&transition_digests[2])
            .expect("the third transition is present");
        let frame_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN.len()
            + size_of::<u64>()
            + ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len();
        reordered_bytes[frame_offset + size_of::<u8>()] ^= 1;
        assert_eq!(recover_trace(&reordered_transition, final_digest), None);

        let mut noncanonical_coefficient = database;
        let transition_bytes = noncanonical_coefficient
            .get_mut(&transition_digests[2])
            .expect("the third transition is present");
        let coefficient_offset =
            frame_offset + size_of::<u8>() + size_of::<u64>() + MERKLE_DIGEST_BYTE_LENGTH;
        transition_bytes[coefficient_offset..coefficient_offset + size_of::<u64>()]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert_eq!(recover_trace(&noncanonical_coefficient, final_digest), None,);
    }

    #[test]
    fn bounded_goldilocks_sampling_refuses_after_the_exact_candidate_ceiling() {
        let mut draw_count = 0_u32;
        let result = sample_bounded_goldilocks_candidate(|| {
            draw_count += 1;
            GOLDILOCKS_MODULUS
        });
        assert_eq!(result, Err(BoundedSamplingError::CandidateDrawsExhausted));
        assert_eq!(
            draw_count,
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
        );
    }

    #[test]
    fn bounded_goldilocks_sampling_accepts_the_last_permitted_candidate() {
        let mut draw_count = 0_u32;
        let result = sample_bounded_goldilocks_candidate(|| {
            draw_count += 1;
            if draw_count == PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
                17
            } else {
                GOLDILOCKS_MODULUS
            }
        })
        .expect("the final permitted candidate is accepted");
        assert_eq!(result, Goldilocks::from_u64(17));
        assert_eq!(
            draw_count,
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
        );
    }

    #[test]
    fn bounded_distinct_sampling_refuses_repeated_candidates_at_the_exact_ceiling() {
        let mut draw_count = 0_u32;
        let result = sample_bounded_residue_index(
            8,
            |candidate| candidate != 3,
            || {
                draw_count += 1;
                3
            },
        );
        assert_eq!(result, Err(BoundedSamplingError::CandidateDrawsExhausted));
        assert_eq!(
            draw_count,
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
        );
    }

    #[test]
    fn bounded_residue_sampling_rejects_out_of_range_bias_before_acceptance() {
        let mut candidates = [u64::MAX, 19].into_iter();
        let result = sample_bounded_residue_index(
            10,
            |candidate| candidate == 9,
            || {
                candidates
                    .next()
                    .expect("the test supplies enough candidates")
            },
        )
        .expect("the second candidate is uniform and accepted");
        assert_eq!(result, 9);
        assert!(candidates.next().is_none());
    }

    #[test]
    fn transcript_errors_preserve_call_site_specific_exhaustion_classification() {
        assert_eq!(
            extension_sampling_failure_for_transcript_error(
                &TranscriptError::CommonChallengeDrawsExhausted
            ),
            ChallengerSamplingFailure::ExtensionChallengeCandidateDrawsExhausted
        );
        assert_eq!(
            query_sampling_failure_for_transcript_error(
                &TranscriptError::CommonChallengeDrawsExhausted
            ),
            ChallengerSamplingFailure::DistinctQueryCandidateDrawsExhausted
        );
        assert_eq!(
            query_sampling_failure_for_transcript_error(
                &TranscriptError::UnexpectedRowCodeWhirChallenge
            ),
            ChallengerSamplingFailure::TranscriptStateMismatch
        );
    }

    #[test]
    fn missing_query_schedule_returns_a_bounded_distinct_placeholder_domain() {
        let transcript = RowCodeWhirTranscript::new_for_test(b"missing-query-schedule")
            .expect("the test transcript is valid");
        let mut challenger = RowCodeWhirChallenger::new(transcript, Vec::new());
        challenger.record_sampling_failure(ChallengerSamplingFailure::QueryScheduleMismatch);

        let first_domain = (0..8)
            .map(|_| {
                challenger
                    .sample_uniform_bits::<true>(3)
                    .expect("failure placeholders never use field rejection")
            })
            .collect::<Vec<_>>();
        assert_eq!(first_domain, (0..8).collect::<Vec<_>>());
        assert_eq!(
            challenger
                .sample_uniform_bits::<true>(3)
                .expect("the bounded placeholder sequence cycles after the full domain"),
            0
        );
    }

    #[test]
    fn algebra_slices_are_absorbed_as_single_typed_rounds() {
        let transcript = RowCodeWhirTranscript::new_for_test(b"algebra-slice-framing")
            .expect("the test transcript is valid");
        let mut challenger = RowCodeWhirChallenger::new(transcript, Vec::new());

        <RowCodeWhirChallenger as FieldChallenger<ChallengeField>>::observe_algebra_slice(
            &mut challenger,
            &[ChallengeField::ONE, ChallengeField::TWO],
        );
        challenger.observe(
            MerkleCap::<ChallengeField, [u64; MERKLE_DIGEST_WORD_LENGTH]>::new(vec![
                [0_u64; MERKLE_DIGEST_WORD_LENGTH],
            ]),
        );
        challenger.observe(
            MerkleCap::<ChallengeField, [u64; MERKLE_DIGEST_WORD_LENGTH]>::new(vec![
                [1_u64; MERKLE_DIGEST_WORD_LENGTH],
            ]),
        );
        <RowCodeWhirChallenger as FieldChallenger<ChallengeField>>::observe_algebra_slice(
            &mut challenger,
            &[
                ChallengeField::ZERO,
                ChallengeField::ONE,
                ChallengeField::NEG_ONE,
            ],
        );

        let summary = challenger
            .finish(&[1])
            .expect("each algebra slice is one valid typed observation round");
        // The canonical header root and edge cost two queries. The protocol
        // schedule, algebra observation, and final proof stream each cost a
        // recomputed response root plus two chain edges; the two commitments
        // each cost only their two chain edges.
        assert_eq!(summary.maximum_hash_query_count(), 2 + 3 * 3 + 2 * 2);
    }
}
