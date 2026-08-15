//! Canonical WHIR primitives for the compact factor-one proof.
//!
//! The same hash functions, commitment scheme, challenger, and protocol
//! configuration are used by generation and independent verification.
//! Initial-oracle custody retains the exact encoded matrix produced by WHIR so
//! the response writer cannot replace it with a separately encoded source or
//! construct a redundant inner Merkle tree.

use core::mem::size_of;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_matrix::{Matrix, dense::DenseMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::poly::Poly;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use p3_whir::pcs::zk::{
    HidingWhirEncodedBaseOracle, HidingWhirProver, MaskProverData, ZkWhirConfig, ZkWhirProof,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, ZkParameters};
use rand::Rng;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::{compact_cfw::CompactChallengeField, compact_proof_contract::CompactWhirEpochContract};

pub(super) const COMPACT_WHIR_FOLD_COUNT: usize = 4;
pub(super) const COMPACT_WHIR_ROUND_COUNT: usize = COMPACT_WHIR_FOLD_COUNT - 1;
pub(super) const COMPACT_WHIR_FINAL_VARIABLE_COUNT: u32 = 3;
pub(super) const COMPACT_WHIR_REPEATED_FOLDING_FACTOR: u32 = 4;
pub(super) const COMPACT_WHIR_STARTING_LOG_INVERSE_RATE: usize = 2;
pub(super) const COMPACT_WHIR_ROUND_LOG_INVERSE_RATES: [u32; COMPACT_WHIR_ROUND_COUNT] = [2, 4, 8];
pub(super) const COMPACT_WHIR_PROTOCOL_SECURITY_LEVEL: usize = 267;
pub(super) const COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH: usize = 3;
pub(super) const COMPACT_WHIR_MASK_LOG_INVERSE_RATE: usize = 2;

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
        for epoch in inputs.whir_epochs {
            let configuration = compact_whir_configuration_from_contract(epoch)
                .expect("the selected WHIR epoch configures the production prover");
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
}
