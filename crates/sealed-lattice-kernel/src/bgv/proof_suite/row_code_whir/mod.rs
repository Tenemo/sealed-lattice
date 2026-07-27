//! Streaming-interleaved row-code commitments with explicit-point WHIR.
//!
//! Witness rows are encoded at rate one quarter and committed column-wise.
//! The enclosing relation derives its out-of-domain points only after those
//! commitments are fixed. A plain WHIR opening then authenticates the
//! resulting non-Boolean multilinear evaluations. Witness secrecy is supplied
//! by the theorem-backed masks in the enclosing relation.

mod algebra;
mod column_commitment;
#[cfg(test)]
mod construction_correspondence;
pub(super) mod construction_plan;
mod exact_same_secret;
mod generation_state;
#[cfg(test)]
mod literal_bcs_merkle;
#[cfg(test)]
mod masking_rank_oracle;
mod plain_whir;
mod plain_whir_wire;
#[cfg(test)]
mod protocol;
mod quotient_transform_storage;
mod relation_materialization;
mod retained_oracle;
mod retained_oracle_codec;
mod row_encoding;
mod same_secret_source_manifest;
mod streaming_whir_prover;

pub(in crate::bgv::proof_suite) use construction_plan::RowCodeWhirConstructionPlan;
pub(in crate::bgv::proof_suite) use construction_plan::RowCodeWhirSelectedParameters;
pub(in crate::bgv::proof_suite) use construction_plan::RowCodeWhirSoundnessAssumption;
pub(in crate::bgv::proof_suite) use construction_plan::{
    ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE, ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE,
    ROW_CODE_WHIR_PHASE_COLUMN_QUERY_COORDINATE_COUNT,
    selected_row_code_whir_trace_mask_degree_bound_exclusive,
};

pub(in crate::bgv) use exact_same_secret::VerifiedSameSecretLowDegreePrerequisite;
pub(in crate::bgv::proof_suite) use exact_same_secret::{
    ExactSameSecretAuthenticatedTranscriptPrefixRequest, ExactSameSecretFiatShamirBinding,
    ExactSameSecretTranscriptPrefixAuthorityBinding, PreparedExactSameSecretTranscriptPrefix,
};
pub(crate) use exact_same_secret::{
    ExactSameSecretFinalProofVerification, ExactSameSecretIncrementalVerification,
    PreparedExactSameSecretVerification, exact_same_secret_verification_resident_memory_accounting,
    exact_same_secret_verification_runtime_limits, prepare_exact_same_secret_verification,
};
pub(in crate::bgv::proof_suite) use generation_state::{
    RowCodeWhirGenerationStateMachine, planned_row_code_whir_external_memory_requirement,
};
pub(in crate::bgv::proof_suite) use quotient_transform_storage::{
    RowCodeWhirQuotientTransformStoragePlan, plan_row_code_whir_quotient_transform_storage,
};
#[cfg(test)]
pub(in crate::bgv::proof_suite) use retained_oracle::{
    RetainedPlainWhirExternalMemoryAccounting,
    selected_plain_whir_retained_oracle_external_memory_accounting,
};
#[cfg(test)]
pub(crate) const MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH: usize = 5_242_880;

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
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
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
        RowCodeWhirTranscriptSummary, TranscriptError,
    },
};

const MERKLE_DIGEST_WORD_LENGTH: usize = 8;
const MERKLE_DIGEST_BYTE_LENGTH: usize = MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>();
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
#[cfg(test)]
const PROTOCOL_SECURITY_LEVEL: usize = 260;
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN: &[u8] =
    b"sealed-lattice/row-code-whir/shake256/v1";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN: &[u8; 32] =
    b"sealed-lattice/column-hash/v1\0\0\0";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN: &[u8] =
    b"sealed-lattice/column-merkle-node/v1";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN: &[u8] =
    b"aggregate-plain-pcs/merkle-leaf/v1";
pub(in crate::bgv::proof_suite) const ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN: &[u8] =
    b"aggregate-plain-pcs/merkle-node/v1";

type ChallengeField = BinomialExtensionField<Goldilocks, 5>;
type ExtensionFieldChallenger = RowCodeWhirChallenger;
type LeafHasher = SerializingHasher<DomainSeparatedShake256>;
type NodeCompressor =
    CompressionFunctionFromHasher<DomainSeparatedShake256, 2, MERKLE_DIGEST_WORD_LENGTH>;
type CommitmentScheme =
    MerkleTreeMmcs<ChallengeField, u64, LeafHasher, NodeCompressor, 2, MERKLE_DIGEST_WORD_LENGTH>;
type DiscreteFourierTransform = Radix2DFTSmallBatch<ChallengeField>;

#[derive(Clone)]
struct AuthenticatedColumn {
    values: Vec<Goldilocks>,
}

#[derive(Clone, Copy, Debug)]
struct DomainSeparatedShake256 {
    domain: &'static [u8],
}

impl DomainSeparatedShake256 {
    fn initialized_state(self) -> Shake256 {
        let mut state = Shake256::default();
        state.update(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN);
        state.update(&(self.domain.len() as u64).to_le_bytes());
        state.update(self.domain);
        state
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
                "plain WHIR extension challenge sampling exhausted its candidate ceiling"
                    .to_owned(),
            ),
            Some(ChallengerSamplingFailure::DistinctQueryCandidateDrawsExhausted) => {
                Err("plain WHIR distinct query sampling exhausted its candidate ceiling".to_owned())
            }
            Some(ChallengerSamplingFailure::TranscriptStateMismatch) => {
                Err("plain WHIR transcript state did not match the typed protocol".to_owned())
            }
            Some(ChallengerSamplingFailure::QueryScheduleMismatch) => {
                Err("plain WHIR query calls did not match the PCS-owned schedule".to_owned())
            }
        }
    }

    fn ensure_query_schedule_consumed(&self) -> Result<(), String> {
        if self.next_query_epoch != self.query_schedule.len()
            || self.next_active_query_index != self.active_query_indices.len()
        {
            return Err("plain WHIR query schedule was not completely consumed".to_owned());
        }
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
        // Initial state plus four response rounds with virtual challenge
        // binding: 1 + 4 * 2.
        assert_eq!(summary.maximum_hash_query_count(), 9);
    }
}
