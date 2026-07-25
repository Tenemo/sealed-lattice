//! Streaming-interleaved row-code commitments with explicit-point WHIR.
//!
//! Witness rows are encoded at rate one quarter and committed column-wise.
//! The enclosing relation derives its out-of-domain points only after those
//! commitments are fixed. A plain WHIR opening then authenticates the
//! resulting non-Boolean multilinear evaluations. Witness secrecy is supplied
//! by the theorem-backed masks in the enclosing relation.

mod algebra;
mod column_commitment;
mod exact_same_secret;
mod plain_whir;
mod plain_whir_wire;
#[cfg(test)]
mod protocol;
mod row_encoding;
#[cfg(test)]
mod streaming_whir_prover;

pub(in crate::bgv) use exact_same_secret::VerifiedSameSecretLowDegreePrerequisite;
pub(crate) use exact_same_secret::{
    PreparedExactSameSecretVerification, prepare_exact_same_secret_verification,
};
pub(crate) const MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH: usize = 5_242_880;

use core::{marker::PhantomData, mem::size_of};

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError,
};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{PrimeCharacteristicRing, RawDataSerializable, extension::BinomialExtensionField};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;

const MERKLE_DIGEST_WORD_LENGTH: usize = 8;
const MERKLE_DIGEST_BYTE_LENGTH: usize = MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>();
const CHALLENGER_OUTPUT_BYTE_LENGTH: usize = 64;
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const PROTOCOL_SECURITY_LEVEL: usize = 260;
const SHAKE256_PROTOCOL_DOMAIN: &[u8] = b"sealed-lattice/row-code-whir/shake256/v1";

type ChallengeField = BinomialExtensionField<Goldilocks, 5>;
type InnerChallenger = HashChallenger<u8, DomainSeparatedShake256, CHALLENGER_OUTPUT_BYTE_LENGTH>;
type ExtensionFieldChallenger = ByteExtensionFieldChallenger<ChallengeField>;
type LeafHasher = SerializingHasher<DomainSeparatedShake256>;
type NodeCompressor =
    CompressionFunctionFromHasher<DomainSeparatedShake256, 2, MERKLE_DIGEST_WORD_LENGTH>;
type CommitmentScheme =
    MerkleTreeMmcs<ChallengeField, u64, LeafHasher, NodeCompressor, 2, MERKLE_DIGEST_WORD_LENGTH>;
type DiscreteFourierTransform = Radix2DFTSmallBatch<ChallengeField>;

#[derive(Clone)]
struct AuthenticatedColumn {
    column_index: usize,
    values: Vec<Goldilocks>,
}

#[derive(Clone, Copy, Debug)]
struct DomainSeparatedShake256 {
    domain: &'static [u8],
}

impl DomainSeparatedShake256 {
    fn initialized_state(self) -> Shake256 {
        let mut state = Shake256::default();
        state.update(SHAKE256_PROTOCOL_DOMAIN);
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
/// Plonky3's serializing challenger is restricted to prime fields, so every
/// Goldilocks coefficient is sampled independently with rejection sampling.
#[derive(Clone, Debug)]
struct ByteExtensionFieldChallenger<FieldElement> {
    inner: InnerChallenger,
    sampling_failure: Option<ChallengerSamplingFailure>,
    uniform_query_bit_length: Option<usize>,
    uniform_query_indices: Vec<usize>,
    marker: PhantomData<FieldElement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChallengerSamplingFailure {
    GoldilocksCandidateDrawsExhausted,
    DistinctQueryCandidateDrawsExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedSamplingError {
    InvalidUpperBound,
    CandidateDrawsExhausted,
}

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

impl ByteExtensionFieldChallenger<ChallengeField> {
    fn new(initial_state: Vec<u8>, domain: &'static [u8]) -> Self {
        Self {
            inner: HashChallenger::new(initial_state, DomainSeparatedShake256 { domain }),
            sampling_failure: None,
            uniform_query_bit_length: None,
            uniform_query_indices: Vec::new(),
            marker: PhantomData,
        }
    }

    fn sample_goldilocks(&mut self) -> Goldilocks {
        self.reset_uniform_query_epoch();
        match sample_bounded_goldilocks_candidate(|| u64::from_le_bytes(self.inner.sample_array()))
        {
            Ok(candidate) => candidate,
            Err(_) => {
                self.record_sampling_failure(
                    ChallengerSamplingFailure::GoldilocksCandidateDrawsExhausted,
                );
                Goldilocks::ZERO
            }
        }
    }

    fn sample_distinct_uniform_query_index(&mut self, bits: usize) -> usize {
        if self.uniform_query_bit_length != Some(bits) {
            self.uniform_query_bit_length = Some(bits);
            self.uniform_query_indices.clear();
        }
        if bits == 0 {
            if self.uniform_query_indices.is_empty() {
                self.uniform_query_indices.push(0);
            } else {
                self.record_sampling_failure(
                    ChallengerSamplingFailure::DistinctQueryCandidateDrawsExhausted,
                );
            }
            return 0;
        }
        assert!(bits < usize::BITS as usize);
        let domain_size = 1_usize << bits;
        let sampled = sample_bounded_residue_index(
            domain_size,
            |candidate| !self.uniform_query_indices.contains(&candidate),
            || u64::from_le_bytes(self.inner.sample_array()),
        );
        let index = match sampled {
            Ok(index) => index,
            Err(_) => {
                self.record_sampling_failure(
                    ChallengerSamplingFailure::DistinctQueryCandidateDrawsExhausted,
                );
                (0..domain_size)
                    .find(|candidate| !self.uniform_query_indices.contains(candidate))
                    .unwrap_or(0)
            }
        };
        self.uniform_query_indices.push(index);
        index
    }

    fn record_sampling_failure(&mut self, failure: ChallengerSamplingFailure) {
        if self.sampling_failure.is_none() {
            self.sampling_failure = Some(failure);
        }
    }

    fn reset_uniform_query_epoch(&mut self) {
        self.uniform_query_bit_length = None;
        self.uniform_query_indices.clear();
    }

    fn ensure_sampling_succeeded(&self) -> Result<(), String> {
        match self.sampling_failure {
            None => Ok(()),
            Some(ChallengerSamplingFailure::GoldilocksCandidateDrawsExhausted) => Err(
                "plain WHIR Goldilocks challenge sampling exhausted its candidate ceiling"
                    .to_owned(),
            ),
            Some(ChallengerSamplingFailure::DistinctQueryCandidateDrawsExhausted) => {
                Err("plain WHIR distinct query sampling exhausted its candidate ceiling".to_owned())
            }
        }
    }
}

impl CanObserve<ChallengeField> for ByteExtensionFieldChallenger<ChallengeField> {
    fn observe(&mut self, value: ChallengeField) {
        self.reset_uniform_query_epoch();
        self.inner.observe_slice(
            &<ChallengeField as RawDataSerializable>::into_bytes(value)
                .into_iter()
                .collect::<Vec<_>>(),
        );
    }
}

impl CanObserve<MerkleCap<ChallengeField, [u64; MERKLE_DIGEST_WORD_LENGTH]>>
    for ByteExtensionFieldChallenger<ChallengeField>
{
    fn observe(&mut self, commitment: MerkleCap<ChallengeField, [u64; MERKLE_DIGEST_WORD_LENGTH]>) {
        self.reset_uniform_query_epoch();
        for digest in commitment.roots() {
            for word in digest {
                self.inner.observe_slice(&word.to_le_bytes());
            }
        }
    }
}

impl CanSample<ChallengeField> for ByteExtensionFieldChallenger<ChallengeField> {
    fn sample(&mut self) -> ChallengeField {
        ChallengeField::new(core::array::from_fn(|_| self.sample_goldilocks()))
    }
}

impl CanSampleBits<usize> for ByteExtensionFieldChallenger<ChallengeField> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize);
        self.reset_uniform_query_epoch();
        if bits == 0 {
            return 0;
        }
        let sampled = u64::from_le_bytes(self.inner.sample_array());
        (sampled & ((1_u64 << bits) - 1)) as usize
    }
}

impl CanSampleUniformBits<ChallengeField> for ByteExtensionFieldChallenger<ChallengeField> {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_distinct_uniform_query_index(bits))
    }
}

impl GrindingChallenger for ByteExtensionFieldChallenger<ChallengeField> {
    type Witness = ChallengeField;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "the selected WHIR profile does not use grinding");
        ChallengeField::ZERO
    }
}

impl FieldChallenger<ChallengeField> for ByteExtensionFieldChallenger<ChallengeField> {}

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
}
