//! Binding polynomial-commitment prototype with bounded witness storage.
//!
//! This module is research code. The aggregate PCS uses explicit-point plain
//! WHIR; secrecy must come from the enclosing masked relation construction,
//! rather than from a second whole-witness hiding layer.

mod algebra;
mod column_commitment;
mod exact_same_secret;
mod plain_whir;
mod plain_whir_wire;
mod protocol;
mod row_encoding;

#[cfg(target_arch = "wasm32")]
pub(super) fn verify_exact_same_secret_proof_bytes(
    canonical_public_input: &[u8],
    canonical_proof: &[u8],
) -> Result<[usize; 4], String> {
    let metrics = exact_same_secret::verify_exact_same_secret_proof_bytes(
        canonical_public_input,
        canonical_proof,
    )?;
    Ok([
        metrics.public_input_byte_length,
        metrics.proof_byte_length,
        metrics.opening_claim_count,
        metrics.query_count,
    ])
}

use core::{marker::PhantomData, mem::size_of};

#[cfg(test)]
use core::{convert::Infallible, fmt};

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError,
};
#[cfg(test)]
use p3_commit::MultilinearPcs;
use p3_dft::Radix2DFTSmallBatch;
#[cfg(test)]
use p3_field::PrimeField64;
use p3_field::{PrimeCharacteristicRing, RawDataSerializable, extension::BinomialExtensionField};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multilinear_util::point::Point;
#[cfg(test)]
use p3_multilinear_util::poly::Poly;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
#[cfg(test)]
use p3_whir::pcs::zk::{HidingWhirPcs, ZkParameters, ZkWhirConfig};
#[cfg(test)]
use p3_whir::{DomainSeparator, FoldingFactor, ProtocolParameters, SecurityAssumption};
#[cfg(test)]
use rand::{SeedableRng, TryCryptoRng, TryRng};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const MERKLE_DIGEST_WORD_LENGTH: usize = 8;
const MERKLE_DIGEST_BYTE_LENGTH: usize = MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>();
const CHALLENGER_OUTPUT_BYTE_LENGTH: usize = 64;
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const PROTOCOL_SECURITY_LEVEL: usize = 260;
#[cfg(test)]
const AGGREGATE_STARTING_LOG_INV_RATE: usize = 3;
#[cfg(test)]
const AGGREGATE_FOLDING_FACTOR: usize = 7;

type ChallengeField = BinomialExtensionField<Goldilocks, 5>;
type InnerChallenger = HashChallenger<u8, DomainSeparatedShake256, CHALLENGER_OUTPUT_BYTE_LENGTH>;
type ExtensionFieldChallenger = ByteExtensionFieldChallenger<ChallengeField>;
type LeafHasher = SerializingHasher<DomainSeparatedShake256>;
type NodeCompressor =
    CompressionFunctionFromHasher<DomainSeparatedShake256, 2, MERKLE_DIGEST_WORD_LENGTH>;
type CommitmentScheme =
    MerkleTreeMmcs<ChallengeField, u64, LeafHasher, NodeCompressor, 2, MERKLE_DIGEST_WORD_LENGTH>;
type DiscreteFourierTransform = Radix2DFTSmallBatch<ChallengeField>;
#[cfg(test)]
type AggregatePcs = HidingWhirPcs<
    ChallengeField,
    ChallengeField,
    DiscreteFourierTransform,
    CommitmentScheme,
    ExtensionFieldChallenger,
    Shake256RandomNumberGenerator,
>;

#[cfg(test)]
type BaseCommitmentScheme =
    MerkleTreeMmcs<Goldilocks, u64, LeafHasher, NodeCompressor, 2, MERKLE_DIGEST_WORD_LENGTH>;

#[cfg(test)]
#[derive(Clone, Debug)]
struct GoldilocksFiatShamirChallenger {
    inner: InnerChallenger,
}

#[cfg(test)]
impl GoldilocksFiatShamirChallenger {
    fn sample_canonical_goldilocks(&mut self) -> Goldilocks {
        loop {
            let candidate = u64::from_le_bytes(self.inner.sample_array());
            if candidate < GOLDILOCKS_MODULUS {
                return Goldilocks::from_u64(candidate);
            }
        }
    }
}

#[cfg(test)]
impl CanObserve<Goldilocks> for GoldilocksFiatShamirChallenger {
    fn observe(&mut self, value: Goldilocks) {
        self.inner
            .observe_slice(&value.as_canonical_u64().to_le_bytes());
    }
}

#[cfg(test)]
impl CanObserve<MerkleCap<Goldilocks, [u64; MERKLE_DIGEST_WORD_LENGTH]>>
    for GoldilocksFiatShamirChallenger
{
    fn observe(&mut self, commitment: MerkleCap<Goldilocks, [u64; MERKLE_DIGEST_WORD_LENGTH]>) {
        for digest in commitment.roots() {
            for word in digest {
                self.inner.observe_slice(&word.to_le_bytes());
            }
        }
    }
}

#[cfg(test)]
impl CanSample<Goldilocks> for GoldilocksFiatShamirChallenger {
    fn sample(&mut self) -> Goldilocks {
        self.sample_canonical_goldilocks()
    }
}

#[cfg(test)]
impl CanSampleBits<usize> for GoldilocksFiatShamirChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize);
        if bits == 0 {
            return 0;
        }
        let sampled = u64::from_le_bytes(self.inner.sample_array());
        (sampled & ((1_u64 << bits) - 1)) as usize
    }
}

#[cfg(test)]
impl CanSampleUniformBits<Goldilocks> for GoldilocksFiatShamirChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

#[cfg(test)]
impl GrindingChallenger for GoldilocksFiatShamirChallenger {
    type Witness = Goldilocks;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "the prototype configuration does not use grinding");
        Goldilocks::ZERO
    }
}

#[cfg(test)]
impl FieldChallenger<Goldilocks> for GoldilocksFiatShamirChallenger {}

#[cfg(test)]
struct Shake256RandomNumberGenerator {
    seed: [u8; 32],
    next_block_index: u64,
    block: [u8; CHALLENGER_OUTPUT_BYTE_LENGTH],
    next_block_byte: usize,
}

#[cfg(test)]
impl fmt::Debug for Shake256RandomNumberGenerator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Shake256RandomNumberGenerator")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl Shake256RandomNumberGenerator {
    fn refill(&mut self) {
        let mut state = Shake256::default();
        state.update(b"sealed-lattice/hiding-randomness/v1");
        state.update(&self.seed);
        state.update(&self.next_block_index.to_le_bytes());
        state.finalize_xof().read(&mut self.block);
        self.next_block_index = self
            .next_block_index
            .checked_add(1)
            .expect("hiding randomness block counter exhausted");
        self.next_block_byte = 0;
    }
}

#[cfg(test)]
impl SeedableRng for Shake256RandomNumberGenerator {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            seed,
            next_block_index: 0,
            block: [0; CHALLENGER_OUTPUT_BYTE_LENGTH],
            next_block_byte: CHALLENGER_OUTPUT_BYTE_LENGTH,
        }
    }
}

#[cfg(test)]
impl TryRng for Shake256RandomNumberGenerator {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        let mut written = 0_usize;
        while written < destination.len() {
            if self.next_block_byte == self.block.len() {
                self.refill();
            }
            let available = self.block.len() - self.next_block_byte;
            let copied = available.min(destination.len() - written);
            destination[written..written + copied]
                .copy_from_slice(&self.block[self.next_block_byte..self.next_block_byte + copied]);
            self.next_block_byte += copied;
            written += copied;
        }
        Ok(())
    }
}

#[cfg(test)]
impl TryCryptoRng for Shake256RandomNumberGenerator {}

#[derive(Clone, Copy, Debug)]
struct DomainSeparatedShake256 {
    domain: &'static [u8],
}

impl DomainSeparatedShake256 {
    fn initialized_state(self) -> Shake256 {
        let mut state = Shake256::default();
        state.update(b"sealed-lattice/streaming-polynomial-commitment/shake256/v1");
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

/// Byte-backed Fiat-Shamir challenger for a non-prime base field.
///
/// Plonky3's serializing challenger is restricted to prime fields. This
/// adapter samples every Goldilocks coefficient independently with rejection
/// sampling, then constructs one degree-five field element.
#[derive(Clone, Debug)]
struct ByteExtensionFieldChallenger<FieldElement> {
    inner: InnerChallenger,
    marker: PhantomData<FieldElement>,
}

impl ByteExtensionFieldChallenger<ChallengeField> {
    fn new(initial_state: Vec<u8>, domain: &'static [u8]) -> Self {
        Self {
            inner: HashChallenger::new(initial_state, DomainSeparatedShake256 { domain }),
            marker: PhantomData,
        }
    }

    fn sample_goldilocks(&mut self) -> Goldilocks {
        loop {
            let candidate = u64::from_le_bytes(self.inner.sample_array());
            if candidate < GOLDILOCKS_MODULUS {
                // SAFETY: the rejection test above establishes canonicality.
                return Goldilocks::from_u64(candidate);
            }
        }
    }
}

impl CanObserve<ChallengeField> for ByteExtensionFieldChallenger<ChallengeField> {
    fn observe(&mut self, value: ChallengeField) {
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
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for ByteExtensionFieldChallenger<ChallengeField> {
    type Witness = ChallengeField;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "the prototype configuration does not use grinding");
        ChallengeField::ZERO
    }
}

impl FieldChallenger<ChallengeField> for ByteExtensionFieldChallenger<ChallengeField> {}

#[cfg(test)]
fn aggregate_pcs(variable_count: usize, hiding_seed: [u8; 32]) -> Result<AggregatePcs, String> {
    let configuration =
        ZkWhirConfig::<ChallengeField, ChallengeField, ExtensionFieldChallenger>::new(
            variable_count,
            ProtocolParameters {
                starting_log_inv_rate: AGGREGATE_STARTING_LOG_INV_RATE,
                round_log_inv_rates: Vec::new(),
                folding_factor: FoldingFactor::Constant(AGGREGATE_FOLDING_FACTOR),
                soundness_type: SecurityAssumption::UniqueDecoding,
                security_level: PROTOCOL_SECURITY_LEVEL,
                pow_bits: 0,
            },
            ZkParameters {
                ell_zk: 46,
                mask_log_inv_rate: 5,
            },
        )
        .map_err(|error| format!("construct extension-base HidingWhir configuration: {error}"))?;
    let commitment_scheme = CommitmentScheme::new(
        LeafHasher::new(DomainSeparatedShake256 {
            domain: b"aggregate-pcs/merkle-leaf/v1",
        }),
        NodeCompressor::new(DomainSeparatedShake256 {
            domain: b"aggregate-pcs/merkle-node/v1",
        }),
        0,
    );
    Ok(AggregatePcs::new(
        configuration,
        DiscreteFourierTransform::default(),
        commitment_scheme,
        Shake256RandomNumberGenerator::from_seed(hiding_seed),
    ))
}

#[cfg(test)]
fn aggregate_challenger(pcs: &AggregatePcs, statement: &[u8]) -> ExtensionFieldChallenger {
    let mut initial_state = b"sealed-lattice/streaming-polynomial-commitment/aggregate/v1".to_vec();
    initial_state.extend_from_slice(&(statement.len() as u64).to_le_bytes());
    initial_state.extend_from_slice(statement);
    let mut challenger =
        ExtensionFieldChallenger::new(initial_state, b"aggregate-pcs/challenges/v1");
    let mut separator = DomainSeparator::<ChallengeField, ChallengeField>::new(Vec::new());
    pcs.add_domain_separator::<MERKLE_DIGEST_WORD_LENGTH>(&mut separator);
    separator.observe_domain_separator(&mut challenger);
    challenger
}

/// Runs the complete proof, canonical transport, and fresh verification path
/// over a deterministic non-secret geometry suitable for native/Wasm parity.
pub(crate) struct StreamingProtocolProbeResult {
    pub(crate) digest: [u8; 64],
    pub(crate) canonical_proof_byte_length: usize,
    pub(crate) aggregate_proof_byte_length: usize,
    pub(crate) aggregate_query_value_byte_length: usize,
    pub(crate) aggregate_round_query_value_byte_length: usize,
    pub(crate) aggregate_source_query_value_byte_length: usize,
    pub(crate) aggregate_fresh_main_query_value_byte_length: usize,
    pub(crate) aggregate_mask_query_value_byte_length: usize,
    pub(crate) aggregate_merkle_dictionary_byte_length: usize,
    pub(crate) aggregate_merkle_reference_byte_length: usize,
    pub(crate) aggregate_merkle_unique_node_count: usize,
    pub(crate) aggregate_merkle_reference_count: usize,
    pub(crate) aggregate_query_count: usize,
    pub(crate) outer_column_value_byte_length: usize,
    pub(crate) outer_merkle_frontier_byte_length: usize,
    pub(crate) outer_merkle_frontier_node_count: usize,
}

pub(crate) fn run_streaming_protocol_probe(
    row_count: usize,
    witness_variable_count_per_row: usize,
) -> Result<StreamingProtocolProbeResult, String> {
    let geometry =
        row_encoding::RowEncodingGeometry::new(row_count, witness_variable_count_per_row)?;
    if geometry.row_count < 4 {
        return Err("streaming protocol probe requires at least four rows".to_owned());
    }
    let source = |row_index: usize| {
        Ok((0..geometry.witness_values_per_row)
            .map(|value_index| {
                Goldilocks::from_u64(row_index as u64 * 1_000_003 + value_index as u64 * 97 + 41)
            })
            .collect::<Vec<_>>())
    };
    let row_pad_seed = [17; 32];
    let commitment = protocol::commit_streaming_witness(&source, geometry, &row_pad_seed)?;
    let commitment_bytes = commitment
        .column_root
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let mut point_challenger = ByteExtensionFieldChallenger::new(
        commitment_bytes,
        b"streaming-probe-post-commitment-points/v1",
    );
    let row_variable_count = geometry.row_count.ilog2() as usize;
    let shared_row_point = (0..row_variable_count)
        .map(|_| point_challenger.sample())
        .collect::<Vec<_>>();
    let statement = protocol::StreamingOpeningStatement {
        context: b"streaming polynomial commitment native/Wasm parity probe".to_vec(),
        row_points: (0..4)
            .map(|component_index| {
                let mut coordinates = shared_row_point.clone();
                coordinates[0] = ChallengeField::from_u64(((component_index >> 1) & 1) as u64);
                coordinates[1] = ChallengeField::from_u64((component_index & 1) as u64);
                Point::new(coordinates)
            })
            .collect(),
        within_row_point: Point::new(
            (0..witness_variable_count_per_row)
                .map(|_| point_challenger.sample())
                .collect(),
        ),
    };
    let claimed_evaluations = protocol::evaluate_streaming_witness(&source, geometry, &statement)?;
    let output = protocol::prove_streaming_opening_after_commitment(
        &source,
        geometry,
        &statement,
        commitment,
        claimed_evaluations,
        &row_pad_seed,
    )?;
    let canonical = protocol::encode_streaming_prover_output(geometry, &output)?;
    let decoded = protocol::decode_streaming_prover_output(geometry, &canonical)?;
    protocol::verify_streaming_opening(
        geometry,
        &statement,
        &decoded.commitment,
        &decoded.claimed_evaluations,
        &decoded.proof,
    )?;
    let aggregate_breakdown = plain_whir_wire::plain_whir_wire_breakdown(
        &plain_whir::plain_aggregate_pcs(geometry.coefficient_variable_count() + 1)?,
        &output.proof.aggregate_opening_proof,
        protocol::COLUMN_QUERY_COUNT + 1,
    )?;
    let outer_column_value_byte_length = output
        .proof
        .authenticated_columns
        .iter()
        .try_fold(0_usize, |total, column| {
            total.checked_add(column.values.len().checked_mul(size_of::<Goldilocks>())?)
        })
        .ok_or_else(|| "outer authenticated-column value byte count overflowed".to_owned())?;
    let outer_merkle_frontier_node_count = output.proof.column_frontier.len();
    let outer_merkle_frontier_byte_length = outer_merkle_frontier_node_count
        .checked_mul(MERKLE_DIGEST_BYTE_LENGTH)
        .ok_or_else(|| "outer Merkle-frontier byte count overflowed".to_owned())?;
    Ok(StreamingProtocolProbeResult {
        digest: crate::hashing::hash_framed_parts_512(
            "sealed-lattice/backend-research/streaming-protocol-probe/v1",
            &[canonical.as_slice()],
        ),
        canonical_proof_byte_length: canonical.len(),
        aggregate_proof_byte_length: aggregate_breakdown.complete_byte_length,
        aggregate_query_value_byte_length: aggregate_breakdown.query_value_byte_length,
        aggregate_round_query_value_byte_length: aggregate_breakdown.query_value_byte_length,
        aggregate_source_query_value_byte_length: 0,
        aggregate_fresh_main_query_value_byte_length: 0,
        aggregate_mask_query_value_byte_length: 0,
        aggregate_merkle_dictionary_byte_length: aggregate_breakdown.merkle_dictionary_byte_length,
        aggregate_merkle_reference_byte_length: aggregate_breakdown.merkle_reference_byte_length,
        aggregate_merkle_unique_node_count: aggregate_breakdown.merkle_unique_node_count,
        aggregate_merkle_reference_count: aggregate_breakdown.merkle_reference_count,
        aggregate_query_count: aggregate_breakdown.query_count,
        outer_column_value_byte_length,
        outer_merkle_frontier_byte_length,
        outer_merkle_frontier_node_count,
    })
}

#[cfg(test)]
mod tests {
    use p3_field::{BasedVectorSpace, PrimeField64};

    use super::*;
    use crate::bgv::proof_suite::backend_spike::{
        arena::{ArenaGeometry, stacked_value_at},
        bounded_relation_sumcheck::{
            RelationSumcheckContext, TerminalWitnessEvaluations, canonical_proof_bytes,
            evaluate_witness_columns_at, prove_bounded, terminal_point,
            verify_with_authenticated_terminal_evaluations,
        },
        field::ExtensionFieldElement,
    };

    fn to_pcs_field(value: ExtensionFieldElement) -> ChallengeField {
        ChallengeField::new(value.coefficients.map(Goldilocks::from_u64))
    }

    fn from_pcs_field(value: ChallengeField) -> ExtensionFieldElement {
        let coefficients =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value);
        ExtensionFieldElement {
            coefficients: core::array::from_fn(|index| coefficients[index].as_canonical_u64()),
        }
    }

    fn commitment_root_bytes(commitment: protocol::StreamingCommitment) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        for (word_index, word) in commitment.column_root.iter().enumerate() {
            bytes[word_index * 8..(word_index + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn extension_base_hiding_whir_roundtrip_has_a_fresh_verifier() {
        let variable_count = 16;
        let statement = b"extension-base HidingWhir compile and verification anchor";
        let pcs = aggregate_pcs(variable_count, [7; 32]).expect("valid test configuration");
        let message = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| {
                    ChallengeField::new(core::array::from_fn(|coefficient_index| {
                        Goldilocks::from_u64((index as u64 + 1) * (coefficient_index as u64 + 3))
                    }))
                })
                .collect(),
        );
        let points = vec![
            Point::new(
                (0..variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 + 2))
                    .collect(),
            ),
            Point::new(
                (0..variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 3 + 5))
                    .collect(),
            ),
        ];

        let mut prover_challenger = aggregate_challenger(&pcs, statement);
        let (commitment, prover_data) = pcs.commit(message, &mut prover_challenger);
        let proof = pcs.open(prover_data, points.clone(), &mut prover_challenger);
        let canonical_proof = postcard::to_allocvec(&proof).expect("canonical test proof");
        assert!(!canonical_proof.is_empty());

        let verifier_pcs =
            aggregate_pcs(variable_count, [99; 32]).expect("valid verifier configuration");
        let mut verifier_challenger = aggregate_challenger(&verifier_pcs, statement);
        verifier_pcs
            .verify(&commitment, &proof, &mut verifier_challenger, points)
            .expect("fresh verifier accepts the genuine proof");
    }

    #[test]
    fn affine_sumcheck_terminal_claims_open_the_same_streaming_commitment() {
        let affine_geometry = ArenaGeometry::new(2, 12);
        let pcs_geometry = row_encoding::RowEncodingGeometry::new(8, 13)
            .expect("compatible stacked-witness geometry");
        assert_eq!(
            pcs_geometry.row_count * pcs_geometry.witness_values_per_row,
            affine_geometry.stacked_evaluation_count()
        );
        let source = |row_index: usize| {
            Ok((0..pcs_geometry.witness_values_per_row)
                .map(|value_index| {
                    let stacked_index =
                        row_index * pcs_geometry.witness_values_per_row + value_index;
                    Goldilocks::from_u64(stacked_value_at(affine_geometry, stacked_index))
                })
                .collect::<Vec<_>>())
        };
        let row_pad_seed = [71; 32];
        let commitment = protocol::commit_streaming_witness(&source, pcs_geometry, &row_pad_seed)
            .expect("commit the stacked affine witness before sumcheck");
        let root_bytes = commitment_root_bytes(commitment);
        let canonical_statement = b"streaming PCS affine-sumcheck composition test";
        let sumcheck_context = RelationSumcheckContext {
            geometry: affine_geometry,
            canonical_statement,
            witness_commitment_root: &root_bytes,
        };
        let sumcheck_proof = prove_bounded(sumcheck_context, 10);
        let terminal_relation_point =
            terminal_point(sumcheck_context, &sumcheck_proof).expect("valid sumcheck transcript");
        let mut wrong_root_bytes = root_bytes;
        wrong_root_bytes[0] ^= 1;
        let wrong_root_context = RelationSumcheckContext {
            geometry: affine_geometry,
            canonical_statement,
            witness_commitment_root: &wrong_root_bytes,
        };
        let wrong_root_terminal_point = terminal_point(wrong_root_context, &sumcheck_proof)
            .expect("the zero relation remains a well-formed sumcheck transcript");
        assert_ne!(wrong_root_terminal_point, terminal_relation_point);
        let terminal_evaluations =
            evaluate_witness_columns_at(affine_geometry, &terminal_relation_point);

        let row_variable_count = pcs_geometry.row_count.ilog2() as usize;
        let relation_prefix_length = row_variable_count - 2;
        let terminal_point_in_pcs_field = terminal_relation_point
            .iter()
            .copied()
            .map(to_pcs_field)
            .collect::<Vec<_>>();
        let mut opening_context = canonical_statement.to_vec();
        opening_context.extend(canonical_proof_bytes(&sumcheck_proof));
        let opening_statement = protocol::StreamingOpeningStatement {
            context: opening_context,
            row_points: (0..4)
                .map(|component_index| {
                    let mut coordinates = vec![
                        ChallengeField::from_u64(((component_index >> 1) & 1) as u64),
                        ChallengeField::from_u64((component_index & 1) as u64),
                    ];
                    coordinates
                        .extend_from_slice(&terminal_point_in_pcs_field[..relation_prefix_length]);
                    Point::new(coordinates)
                })
                .collect(),
            within_row_point: Point::new(
                terminal_point_in_pcs_field[relation_prefix_length..].to_vec(),
            ),
        };
        let claimed_evaluations = vec![
            to_pcs_field(terminal_evaluations.low_digit),
            to_pcs_field(terminal_evaluations.high_digit),
            to_pcs_field(terminal_evaluations.shifted_secret),
            to_pcs_field(terminal_evaluations.negative_indicator),
        ];
        let output = protocol::prove_streaming_opening_after_commitment(
            &source,
            pcs_geometry,
            &opening_statement,
            commitment,
            claimed_evaluations,
            &row_pad_seed,
        )
        .expect("open the committed witness at the sumcheck terminal point");
        let canonical = protocol::encode_streaming_prover_output(pcs_geometry, &output)
            .expect("encode the composed streaming opening");
        let decoded = protocol::decode_streaming_prover_output(pcs_geometry, &canonical)
            .expect("decode the composed streaming opening");
        protocol::verify_streaming_opening(
            pcs_geometry,
            &opening_statement,
            &decoded.commitment,
            &decoded.claimed_evaluations,
            &decoded.proof,
        )
        .expect("fresh PCS verifier accepts the sumcheck terminal openings");

        let authenticated_terminal_evaluations = TerminalWitnessEvaluations {
            low_digit: from_pcs_field(decoded.claimed_evaluations[0]),
            high_digit: from_pcs_field(decoded.claimed_evaluations[1]),
            shifted_secret: from_pcs_field(decoded.claimed_evaluations[2]),
            negative_indicator: from_pcs_field(decoded.claimed_evaluations[3]),
        };
        assert_eq!(authenticated_terminal_evaluations, terminal_evaluations);
        verify_with_authenticated_terminal_evaluations(
            sumcheck_context,
            &sumcheck_proof,
            authenticated_terminal_evaluations,
        )
        .expect("sumcheck verifier consumes only PCS-authenticated terminal evaluations");
    }

    #[test]
    fn native_streaming_protocol_probe_is_stable_for_wasm_parity() {
        let result = run_streaming_protocol_probe(8, 14).expect("complete native protocol probe");
        assert_eq!(
            crate::hashing::to_hex(&result.digest),
            "b07f482f357649331efb4dbf654e2b77867fcb0cee13eaf5baedbdd76c4d75a17c94253685e1bcd30fc47a0e67cc2158a14d94391ad2b304d2e391fb162123cc"
        );
        assert!(result.canonical_proof_byte_length > 0);
        assert!(result.aggregate_proof_byte_length > 0);
        assert!(result.aggregate_query_value_byte_length > 0);
        assert_eq!(
            result.aggregate_query_value_byte_length,
            result.aggregate_round_query_value_byte_length
                + result.aggregate_source_query_value_byte_length
                + result.aggregate_fresh_main_query_value_byte_length
                + result.aggregate_mask_query_value_byte_length
        );
        assert!(result.aggregate_merkle_dictionary_byte_length > 0);
        assert!(result.aggregate_merkle_reference_byte_length > 0);
        assert!(result.aggregate_merkle_unique_node_count > 0);
        assert!(result.aggregate_merkle_reference_count > 0);
        assert!(result.aggregate_query_count > 0);
        assert!(result.outer_column_value_byte_length > 0);
        assert!(result.outer_merkle_frontier_byte_length > 0);
        assert!(result.outer_merkle_frontier_node_count > 0);
        assert!(result.aggregate_proof_byte_length < result.canonical_proof_byte_length);
    }

    #[test]
    fn target_hiding_whir_parameters_have_the_selected_exact_shape() {
        let candidate =
            ZkWhirConfig::<ChallengeField, ChallengeField, ExtensionFieldChallenger>::new(
                19,
                ProtocolParameters {
                    starting_log_inv_rate: AGGREGATE_STARTING_LOG_INV_RATE,
                    round_log_inv_rates: Vec::new(),
                    folding_factor: FoldingFactor::Constant(AGGREGATE_FOLDING_FACTOR),
                    soundness_type: SecurityAssumption::UniqueDecoding,
                    security_level: PROTOCOL_SECURITY_LEVEL,
                    pow_bits: 0,
                },
                ZkParameters {
                    ell_zk: 46,
                    mask_log_inv_rate: 5,
                },
            )
            .expect("selected target HidingWhir parameters");

        assert_eq!(candidate.folding_schedule, vec![7, 7]);
        assert_eq!(candidate.round_parameters.len(), 1);
        assert_eq!(candidate.round_parameters[0].num_queries, 314);
        assert_eq!(candidate.round_parameters[0].ood_samples, 0);
        assert_eq!(candidate.round_parameters[0].log_inv_rate, 9);
        assert_eq!(candidate.final_queries, 261);
        assert_eq!(candidate.mask_groups().len(), 3);
        assert_eq!(candidate.mask_queries, 275);
        assert_eq!(candidate.oracle_randomness, vec![314, 261]);
    }

    #[test]
    fn direct_base_field_hiding_whir_target_shape_is_explicit() {
        let candidate =
            ZkWhirConfig::<ChallengeField, Goldilocks, GoldilocksFiatShamirChallenger>::new(
                26,
                ProtocolParameters {
                    starting_log_inv_rate: AGGREGATE_STARTING_LOG_INV_RATE,
                    round_log_inv_rates: Vec::new(),
                    folding_factor: FoldingFactor::Constant(AGGREGATE_FOLDING_FACTOR),
                    soundness_type: SecurityAssumption::UniqueDecoding,
                    security_level: PROTOCOL_SECURITY_LEVEL,
                    pow_bits: 0,
                },
                ZkParameters {
                    ell_zk: 3,
                    mask_log_inv_rate: 5,
                },
            )
            .expect("direct base-field target HidingWhir parameters");

        let round_shape = candidate
            .round_parameters
            .iter()
            .map(|round| {
                (
                    round.num_variables,
                    round.num_queries,
                    round.ood_samples,
                    round.log_inv_rate,
                )
            })
            .collect::<Vec<_>>();
        let mask_group_shape = candidate
            .mask_groups()
            .iter()
            .map(|group| {
                (
                    group.width,
                    group.shape.message_len,
                    group.shape.randomness_len,
                    group.shape.domain_size,
                )
            })
            .collect::<Vec<_>>();
        eprintln!(
            "direct base-field HidingWhir folds={:?} rounds={round_shape:?} final_queries={} final_variables={} mask_queries={} oracle_randomness={:?} mask_groups={mask_group_shape:?}",
            candidate.folding_schedule,
            candidate.final_queries,
            candidate.final_round_config().num_variables,
            candidate.mask_queries,
            candidate.oracle_randomness,
        );

        assert_eq!(
            core::mem::size_of::<BaseCommitmentScheme>(),
            core::mem::size_of::<CommitmentScheme>()
        );
        assert_eq!(candidate.zk.ell_zk, 3);
        assert_eq!(candidate.num_variables, 26);
    }
}
