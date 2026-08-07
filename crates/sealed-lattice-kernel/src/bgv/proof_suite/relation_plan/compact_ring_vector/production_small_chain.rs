use std::{collections::BTreeMap, convert::Infallible, rc::Rc};

use p3_challenger::{CanObserve, HashChallenger, SerializingChallenger64};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::zk::stack_codewords;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use p3_whir::pcs::zk::{
    CombinedRelationProverInput, CombinedRelationVerifierInput, HidingWhirProver,
    HidingWhirVerifier, MaskCodeShape, MaskGroupShape, MaskProverData, PrecommittedMaskProverGroup,
    PrecommittedMaskVerifierGroup, ZkVerifierError, ZkWhirConfig, ZkWhirProof,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, ZkParameters};
use rand::{TryCryptoRng, TryRng};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use tiny_keccak::Kmac;
use zeroize::Zeroizing;

use super::super::authenticated_assignment::{
    CompactAuthenticatedAssignmentCatalog, CompactAuthenticatedAssignmentCursor,
    CompactAuthenticatedAssignmentPoll, CompactLookupInverseMaterializationPoll,
};
use super::super::{
    CompactPublicKeyRelationCatalog, CompactRingVectorReference, CompactStructuredLinearTerm,
    derive_compact_public_key_relation_catalog, selected_input_and_context,
};
use super::*;
use crate::bgv::proof_suite::prover::{
    CheckpointableCommonProofPrivateCoinSource, CommonProofAuthenticatedSourceReadRequest,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinCoordinateCapacity,
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    PrivateRandomnessCommonProofCoinError, PrivateRandomnessCommonProofCoinSource,
    ProvidedCommonProofSourcePolynomial,
};
use crate::bgv::proof_suite::relation_plan::{
    RelationPlanVariant, compile_public_key_share_relation_with_source_layout,
};
use crate::bgv::proof_suite::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofChallengeExtensionElement,
    compact_cfw::{
        COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwClaimBatch,
        CompactCfwError, CompactCfwGeometry, CompactCfwMaskMaterial,
        CompactCfwMaskedCrossEpochClaims, CompactCfwMatrixRole, CompactCfwR1csMatrices,
        CompactCfwTranscript, CompactChallengeField, PreparedCompactCfwProver,
        compact_challenge_from_production, compact_challenge_to_production,
        verify_compact_cfw_transcript,
    },
    compact_cfw_external_prover::{CompactCfwExternalProverState, CompactCfwExternalRowSource},
    compact_proof_wire::{
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireGeometry,
        CompactProofResponseWireInput, CompactProofWireError, CompactProofWireGeometry,
        CompactProofWireInput, CompactPublicInputBindings, CompactPublicInputWireGeometry,
        DecodedCompactProofWire, PROOF_FIXED_HEADER_BYTE_LENGTH, decode_compact_proof_wire,
        decode_compact_public_input, encode_compact_proof_wire, encode_compact_public_input,
    },
    compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValue, CompactResponseLeafValueKind,
        CompactResponseMerkleError, CompactResponseMerkleGeometry,
        CompactResponsePostorderMerkleWriter, CompactResponseQuerySelection,
        verify_decoded_compact_response_opening,
    },
    compact_transcript::{
        CompactProverTranscript, CompactTranscriptError,
        derive_compact_fiat_shamir_verifier_message,
    },
    external_memory::tests::TestStorage,
    fixed_uniform_verifier_message::{
        DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageGeometry,
    },
};
use crate::foundation::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessDerivationInput, ActionRandomnessRoot,
    Hash512, ParticipantIdentity, PersistentProofCoinInput, ProofApplicationSlot,
    ProofApplicationSlotCeilings, SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
};

#[path = "production_small_chain_canonical_transport.rs"]
mod production_small_chain_canonical_transport;

use production_small_chain_canonical_transport::{
    DecodedSmallChainCanonicalProof, SmallChainCanonicalSection, SmallChainCanonicalTransportError,
    SmallChainExternalCommitments, decode_small_chain_canonical_proof,
    encode_small_chain_canonical_proof, encode_small_chain_commitment,
    small_chain_canonical_section_payload_range,
};

const SMALL_CHAIN_RING_DEGREE: u64 = 2_048;
const SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH: usize = 64;
const SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH: usize =
    SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH / size_of::<u64>();
const SMALL_CHAIN_WHIR_SECURITY_LEVEL: usize = 267;
const SMALL_CHAIN_WHIR_MAIN_LOG_INVERSE_RATE: usize = 2;
const SMALL_CHAIN_WHIR_MASK_LOG_INVERSE_RATE: usize = 2;
const SMALL_CHAIN_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH: usize = 3;
const SMALL_CHAIN_DIGEST_BASE_FIELD_ELEMENT_COUNT: usize = Hash512::BYTE_LENGTH / size_of::<u32>();
const SMALL_CHAIN_PRE_CHALLENGE_COMMITMENT_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-small-chain/pre-challenge-commitment-binding/v1";
const SMALL_CHAIN_POST_LOOKUP_COMMITMENT_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-small-chain/post-lookup-commitment-binding/v1";
const SMALL_CHAIN_WHIR_HANDOFF_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-small-chain/whir-handoff-binding/v1";
const SMALL_CHAIN_PRIVATE_RANDOM_SEED_BYTE_LENGTH: usize = 64;
const SMALL_CHAIN_PRIVATE_RANDOM_SEED_BASE_ELEMENT_COUNT: usize =
    SMALL_CHAIN_PRIVATE_RANDOM_SEED_BYTE_LENGTH / size_of::<u64>();
const SMALL_CHAIN_WHIR_RANDOM_BLOCK_BYTE_LENGTH: usize = 64;
const SMALL_CHAIN_WHIR_RANDOM_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/compact-small-chain/whir-private-randomness/v1";
const SMALL_CHAIN_PRIVATE_LEAF_SALT_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/compact-small-chain/private-leaf-salt/v1";
const SMALL_CHAIN_FIAT_SHAMIR_ROUND_SALT_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/compact-small-chain/fiat-shamir-round-salt/v1";
const SMALL_CHAIN_PRIVATE_COIN_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-small-chain/private-coin-binding/v1";
const SMALL_CHAIN_PRIVATE_COIN_STATEMENT_DOMAIN: &str =
    "sealed-lattice/compact-small-chain/private-coin-statement/v1";
const SMALL_CHAIN_PRIVATE_RANDOMNESS_CURSOR_MAGIC: [u8; 8] = *b"SLCPRND1";
const SMALL_CHAIN_PRIVATE_RANDOMNESS_CURSOR_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug)]
struct SmallChainByteHasher;

#[derive(Clone, Copy, Debug)]
struct SmallChainGoldilocksLeafHasher;

#[derive(Clone, Copy, Debug)]
struct SmallChainWordHasher;

type SmallChainInnerChallenger =
    HashChallenger<u8, SmallChainByteHasher, SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH>;
type SmallChainChallenger = SerializingChallenger64<Goldilocks, SmallChainInnerChallenger>;
type SmallChainNodeCompressor =
    CompressionFunctionFromHasher<SmallChainWordHasher, 2, SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH>;
type SmallChainCommitmentScheme = MerkleTreeMmcs<
    Goldilocks,
    u64,
    SmallChainGoldilocksLeafHasher,
    SmallChainNodeCompressor,
    2,
    SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH,
>;
type SmallChainExtensionCommitmentScheme =
    ExtensionMmcs<Goldilocks, CompactChallengeField, SmallChainCommitmentScheme>;
type SmallChainCommitment = <SmallChainCommitmentScheme as Mmcs<Goldilocks>>::Commitment;
type SmallChainMaskProverData =
    MaskProverData<Goldilocks, CompactChallengeField, SmallChainCommitmentScheme>;
type SmallChainWhirProof =
    ZkWhirProof<Goldilocks, CompactChallengeField, SmallChainCommitmentScheme>;
type SmallChainWhirConfiguration =
    ZkWhirConfig<CompactChallengeField, Goldilocks, SmallChainChallenger>;

fn initialized_small_chain_hash(domain: &[u8]) -> Shake256 {
    let mut state = Shake256::default();
    state.update(b"sealed-lattice/test/production-small-chain-whir/v1");
    state.update(&(domain.len() as u64).to_le_bytes());
    state.update(domain);
    state
}

fn finish_small_chain_hash(state: Shake256) -> [u8; SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH] {
    let mut output = [0_u8; SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH];
    state.finalize_xof().read(&mut output);
    output
}

fn small_chain_digest_words(
    bytes: [u8; SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH],
) -> [u64; SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH] {
    core::array::from_fn(|word_ordinal| {
        let first_byte = word_ordinal * size_of::<u64>();
        u64::from_le_bytes(
            bytes[first_byte..first_byte + size_of::<u64>()]
                .try_into()
                .expect("one small-chain digest word has eight bytes"),
        )
    })
}

impl CryptographicHasher<u8, [u8; SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH]> for SmallChainByteHasher {
    fn hash_iter<Input>(&self, input: Input) -> [u8; SMALL_CHAIN_HASH_OUTPUT_BYTE_LENGTH]
    where
        Input: IntoIterator<Item = u8>,
    {
        let mut state = initialized_small_chain_hash(b"challenger");
        for byte in input {
            state.update(&[byte]);
        }
        finish_small_chain_hash(state)
    }
}

impl CryptographicHasher<Goldilocks, [u64; SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH]>
    for SmallChainGoldilocksLeafHasher
{
    fn hash_iter<Input>(&self, input: Input) -> [u64; SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH]
    where
        Input: IntoIterator<Item = Goldilocks>,
    {
        let mut state = initialized_small_chain_hash(b"leaf");
        for value in input {
            state.update(&value.as_canonical_u64().to_le_bytes());
        }
        small_chain_digest_words(finish_small_chain_hash(state))
    }
}

impl CryptographicHasher<u64, [u64; SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH]> for SmallChainWordHasher {
    fn hash_iter<Input>(&self, input: Input) -> [u64; SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH]
    where
        Input: IntoIterator<Item = u64>,
    {
        let mut state = initialized_small_chain_hash(b"node");
        for value in input {
            state.update(&value.to_le_bytes());
        }
        small_chain_digest_words(finish_small_chain_hash(state))
    }
}

fn small_chain_whir_configuration(
    variable_count: usize,
    first_folding_factor: usize,
) -> SmallChainWhirConfiguration {
    ZkWhirConfig::new(
        variable_count,
        ProtocolParameters {
            starting_log_inv_rate: SMALL_CHAIN_WHIR_MAIN_LOG_INVERSE_RATE,
            round_log_inv_rates: vec![2, 4, 8],
            folding_factor: FoldingFactor::PerRound(vec![first_folding_factor, 4, 4, 4]),
            soundness_type: SecurityAssumption::UniqueDecoding,
            security_level: SMALL_CHAIN_WHIR_SECURITY_LEVEL,
            pow_bits: 0,
        },
        ZkParameters {
            ell_zk: SMALL_CHAIN_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH,
            mask_log_inv_rate: SMALL_CHAIN_WHIR_MASK_LOG_INVERSE_RATE,
        },
    )
    .expect("the reduced production-family WHIR geometry is valid")
}

fn small_chain_whir_challenger(
    transcript_binding: [u8; Hash512::BYTE_LENGTH],
) -> SmallChainChallenger {
    SmallChainChallenger::new(SmallChainInnerChallenger::new(
        transcript_binding.to_vec(),
        SmallChainByteHasher,
    ))
}

fn fill_small_chain_kmac(
    key: &[u8],
    customization: &[u8],
    framed_parts: &[&[u8]],
    destination: &mut [u8],
) {
    let mut kmac = Kmac::v256(key, customization);
    for part in framed_parts {
        tiny_keccak::Hasher::update(&mut kmac, &(part.len() as u64).to_le_bytes());
        tiny_keccak::Hasher::update(&mut kmac, part);
    }
    tiny_keccak::Hasher::finalize(kmac, destination);
}

struct SmallChainKmacRandomSource {
    private_seed: Zeroizing<[u8; SMALL_CHAIN_PRIVATE_RANDOM_SEED_BYTE_LENGTH]>,
    next_block_ordinal: u64,
    buffered_block: Zeroizing<[u8; SMALL_CHAIN_WHIR_RANDOM_BLOCK_BYTE_LENGTH]>,
    next_buffered_byte_ordinal: usize,
}

impl SmallChainKmacRandomSource {
    fn new(private_seed: Zeroizing<[u8; SMALL_CHAIN_PRIVATE_RANDOM_SEED_BYTE_LENGTH]>) -> Self {
        Self {
            private_seed,
            next_block_ordinal: 0,
            buffered_block: Zeroizing::new([0_u8; SMALL_CHAIN_WHIR_RANDOM_BLOCK_BYTE_LENGTH]),
            next_buffered_byte_ordinal: SMALL_CHAIN_WHIR_RANDOM_BLOCK_BYTE_LENGTH,
        }
    }

    fn refill(&mut self) {
        let block_ordinal = self.next_block_ordinal;
        self.next_block_ordinal = self
            .next_block_ordinal
            .checked_add(1)
            .expect("the reduced WHIR random stream cannot exhaust its block ordinal");
        fill_small_chain_kmac(
            self.private_seed.as_ref(),
            SMALL_CHAIN_WHIR_RANDOM_CUSTOMIZATION,
            &[&block_ordinal.to_le_bytes()],
            self.buffered_block.as_mut(),
        );
        self.next_buffered_byte_ordinal = 0;
    }

    fn fill(&mut self, mut destination: &mut [u8]) {
        while !destination.is_empty() {
            if self.next_buffered_byte_ordinal == SMALL_CHAIN_WHIR_RANDOM_BLOCK_BYTE_LENGTH {
                self.refill();
            }
            let available_byte_count =
                SMALL_CHAIN_WHIR_RANDOM_BLOCK_BYTE_LENGTH - self.next_buffered_byte_ordinal;
            let copied_byte_count = available_byte_count.min(destination.len());
            let buffered_end = self.next_buffered_byte_ordinal + copied_byte_count;
            destination[..copied_byte_count].copy_from_slice(
                &self.buffered_block[self.next_buffered_byte_ordinal..buffered_end],
            );
            self.next_buffered_byte_ordinal = buffered_end;
            destination = &mut destination[copied_byte_count..];
        }
    }

    fn canonical_cursor_bytes(&self) -> [u8; 12] {
        let mut encoded = [0_u8; 12];
        encoded[..8].copy_from_slice(&self.next_block_ordinal.to_le_bytes());
        encoded[8..].copy_from_slice(
            &u32::try_from(self.next_buffered_byte_ordinal)
                .expect("the WHIR buffered-byte ordinal fits u32")
                .to_le_bytes(),
        );
        encoded
    }
}

impl TryRng for SmallChainKmacRandomSource {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; size_of::<u32>()];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; size_of::<u64>()];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(destination);
        Ok(())
    }
}

impl TryCryptoRng for SmallChainKmacRandomSource {}

struct SmallChainAttemptPrivateRandomness {
    private_coins: PrivateRandomnessCommonProofCoinSource,
    response_salt_seed: Zeroizing<[u8; SMALL_CHAIN_PRIVATE_RANDOM_SEED_BYTE_LENGTH]>,
    whir_random_source: SmallChainKmacRandomSource,
}

impl SmallChainAttemptPrivateRandomness {
    fn new(
        mut private_coins: PrivateRandomnessCommonProofCoinSource,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        let whir_random_seed = sample_small_chain_private_seed(&mut private_coins)?;
        let response_salt_seed = sample_small_chain_private_seed(&mut private_coins)?;
        Ok(Self {
            private_coins,
            response_salt_seed,
            whir_random_source: SmallChainKmacRandomSource::new(whir_random_seed),
        })
    }

    fn sample_extension_element(
        &mut self,
    ) -> Result<CompactChallengeField, PrivateRandomnessCommonProofCoinError> {
        let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = self.private_coins.sample_modulo(
                CommonProofPrivateCoinCoordinate::hiding_argument(),
                PROOF_BASE_FIELD_MODULUS,
                SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
            )?;
        }
        Ok(compact_challenge_from_production(
            ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                .expect("production-private samples are canonical base-field coordinates"),
        ))
    }

    fn sample_extension_vector(
        &mut self,
        element_count: usize,
    ) -> Result<Vec<CompactChallengeField>, PrivateRandomnessCommonProofCoinError> {
        (0..element_count)
            .map(|_| self.sample_extension_element())
            .collect()
    }

    fn private_leaf_salt(
        &self,
        response_ordinal: u32,
        leaf_count: usize,
        leaf_ordinal: usize,
        leaf: &OwnedResponseLeaf,
    ) -> [u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH] {
        let value_kind = match leaf {
            OwnedResponseLeaf::Base(_) => [0_u8],
            OwnedResponseLeaf::Extension(_) => [1_u8],
        };
        let leaf_count = u64::try_from(leaf_count)
            .expect("the reduced response leaf count fits u64")
            .to_le_bytes();
        let leaf_ordinal = u64::try_from(leaf_ordinal)
            .expect("the reduced response leaf ordinal fits u64")
            .to_le_bytes();
        let field_element_count = leaf.field_element_count().to_le_bytes();
        let mut salt = [0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
        fill_small_chain_kmac(
            self.response_salt_seed.as_ref(),
            SMALL_CHAIN_PRIVATE_LEAF_SALT_CUSTOMIZATION,
            &[
                &response_ordinal.to_le_bytes(),
                &leaf_count,
                &leaf_ordinal,
                &value_kind,
                &field_element_count,
            ],
            &mut salt,
        );
        salt
    }

    fn fiat_shamir_round_salt(
        &self,
        response_ordinal: u32,
    ) -> [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH] {
        let mut salt = [0_u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH];
        fill_small_chain_kmac(
            self.response_salt_seed.as_ref(),
            SMALL_CHAIN_FIAT_SHAMIR_ROUND_SALT_CUSTOMIZATION,
            &[&response_ordinal.to_le_bytes()],
            &mut salt,
        );
        salt
    }

    fn canonical_randomness_cursor_bytes(&self) -> Vec<u8> {
        let private_coin_cursor_manifest = self
            .private_coins
            .checkpoint_cursor_manifest()
            .expect("small-chain private-coin cursors encode canonically");
        let whir_cursor = self.whir_random_source.canonical_cursor_bytes();
        let mut encoded = Vec::with_capacity(
            SMALL_CHAIN_PRIVATE_RANDOMNESS_CURSOR_MAGIC.len()
                + size_of::<u16>()
                + size_of::<u32>()
                + private_coin_cursor_manifest.len()
                + whir_cursor.len(),
        );
        encoded.extend_from_slice(&SMALL_CHAIN_PRIVATE_RANDOMNESS_CURSOR_MAGIC);
        encoded.extend_from_slice(&SMALL_CHAIN_PRIVATE_RANDOMNESS_CURSOR_VERSION.to_le_bytes());
        encoded.extend_from_slice(
            &u32::try_from(private_coin_cursor_manifest.len())
                .expect("the private-coin cursor manifest length fits u32")
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&private_coin_cursor_manifest);
        encoded.extend_from_slice(&whir_cursor);
        encoded
    }
}

fn sample_small_chain_private_seed(
    private_coins: &mut PrivateRandomnessCommonProofCoinSource,
) -> Result<
    Zeroizing<[u8; SMALL_CHAIN_PRIVATE_RANDOM_SEED_BYTE_LENGTH]>,
    PrivateRandomnessCommonProofCoinError,
> {
    let mut seed = Zeroizing::new([0_u8; SMALL_CHAIN_PRIVATE_RANDOM_SEED_BYTE_LENGTH]);
    for destination in seed.chunks_exact_mut(size_of::<u64>()) {
        let value = private_coins.sample_modulo(
            CommonProofPrivateCoinCoordinate::hiding_argument(),
            PROOF_BASE_FIELD_MODULUS,
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        )?;
        destination.copy_from_slice(&value.to_le_bytes());
    }
    debug_assert_eq!(
        seed.len() / size_of::<u64>(),
        SMALL_CHAIN_PRIVATE_RANDOM_SEED_BASE_ELEMENT_COUNT
    );
    Ok(seed)
}

fn small_chain_commitment_scheme() -> SmallChainCommitmentScheme {
    SmallChainCommitmentScheme::new(
        SmallChainGoldilocksLeafHasher,
        SmallChainNodeCompressor::new(SmallChainWordHasher),
        0,
    )
}

struct SmallChainCommittedMaskGroup {
    shape: MaskGroupShape,
    messages: Vec<Vec<CompactChallengeField>>,
    randomness: Vec<Vec<CompactChallengeField>>,
    commitment: SmallChainCommitment,
    data: SmallChainMaskProverData,
}

fn commit_small_chain_mask_group(
    shape: MaskGroupShape,
    messages: Vec<Vec<CompactChallengeField>>,
    private_randomness: &mut SmallChainAttemptPrivateRandomness,
    commitment_scheme: &SmallChainExtensionCommitmentScheme,
    challenger: &mut SmallChainChallenger,
) -> Result<SmallChainCommittedMaskGroup, PrivateRandomnessCommonProofCoinError> {
    let randomness = (0..shape.width)
        .map(|_| private_randomness.sample_extension_vector(shape.shape.randomness_len))
        .collect::<Result<Vec<_>, _>>()?;
    let committed_group =
        build_small_chain_mask_group(shape, messages, randomness, commitment_scheme);
    challenger.observe(committed_group.commitment.clone());
    Ok(committed_group)
}

fn build_small_chain_mask_group(
    shape: MaskGroupShape,
    messages: Vec<Vec<CompactChallengeField>>,
    randomness: Vec<Vec<CompactChallengeField>>,
    commitment_scheme: &SmallChainExtensionCommitmentScheme,
) -> SmallChainCommittedMaskGroup {
    assert_eq!(messages.len(), shape.width);
    assert_eq!(randomness.len(), shape.width);
    assert!(
        randomness
            .iter()
            .all(|values| values.len() == shape.shape.randomness_len)
    );
    let codewords = messages
        .iter()
        .zip(&randomness)
        .map(|(message, encoding_randomness)| {
            shape
                .shape
                .encode_with_randomness(message, encoding_randomness)
        })
        .collect::<Vec<_>>();
    let (commitment, data) = commitment_scheme.commit_matrix(stack_codewords(&codewords));
    SmallChainCommittedMaskGroup {
        shape,
        messages,
        randomness,
        commitment,
        data,
    }
}

fn small_chain_multilinear_equality_covector(
    point: &[CompactChallengeField],
) -> Vec<CompactChallengeField> {
    Poly::new_from_point(point, CompactChallengeField::ONE)
        .as_slice()
        .to_vec()
}

fn small_chain_commitment_binding(
    domain: &str,
    commitments: &[&SmallChainCommitment],
) -> Result<[u8; Hash512::BYTE_LENGTH], SmallChainCanonicalTransportError> {
    let canonical_commitments = commitments
        .iter()
        .map(|commitment| encode_small_chain_commitment(commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let canonical_commitment_slices = canonical_commitments
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    Ok(crate::hashing::hash_framed_parts_512(
        domain,
        &canonical_commitment_slices,
    ))
}

fn small_chain_whir_handoff_binding(
    canonical_public_input_bytes: &[u8],
    canonical_cfw_proof_bytes: &[u8],
    commitments: &SmallChainExternalCommitments,
) -> Result<[u8; Hash512::BYTE_LENGTH], SmallChainCanonicalTransportError> {
    let canonical_commitments = [
        encode_small_chain_commitment(&commitments.pre_challenge_source)?,
        encode_small_chain_commitment(&commitments.inner_masks)?,
        encode_small_chain_commitment(&commitments.main_source)?,
        encode_small_chain_commitment(&commitments.outer_masks)?,
        encode_small_chain_commitment(&commitments.shared_masks)?,
    ];
    Ok(crate::hashing::hash_framed_parts_512(
        SMALL_CHAIN_WHIR_HANDOFF_BINDING_DOMAIN,
        &[
            canonical_public_input_bytes,
            canonical_cfw_proof_bytes,
            &canonical_commitments[0],
            &canonical_commitments[1],
            &canonical_commitments[2],
            &canonical_commitments[3],
            &canonical_commitments[4],
        ],
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SmallChainWhirVerificationMutation {
    None,
    PreChallengeTarget,
    PreChallengeSourceCovector,
    MainTarget,
    MainSourceCovector,
    InnerMaskCovector,
    SharedMaskCovector,
}

#[derive(Debug, PartialEq, Eq)]
enum SmallChainCommitmentBindingError {
    CanonicalTransport(SmallChainCanonicalTransportError),
    NonCanonicalDigestLimb,
    ProofWire(CompactProofWireError),
    WrongBinding,
}

impl From<SmallChainCanonicalTransportError> for SmallChainCommitmentBindingError {
    fn from(error: SmallChainCanonicalTransportError) -> Self {
        Self::CanonicalTransport(error)
    }
}

impl From<CompactProofWireError> for SmallChainCommitmentBindingError {
    fn from(error: CompactProofWireError) -> Self {
        Self::ProofWire(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SmallChainWhirVerificationError {
    CrossEpochClaimMismatch,
    Whir(ZkVerifierError),
    WrongCrossEpochPoint,
}

impl From<ZkVerifierError> for SmallChainWhirVerificationError {
    fn from(error: ZkVerifierError) -> Self {
        Self::Whir(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SmallChainFreshVerificationError {
    CanonicalTransport(SmallChainCanonicalTransportError),
    CommitmentBinding(SmallChainCommitmentBindingError),
    CompactCfw(CompactCfwError),
    CompactTranscript(CompactTranscriptError),
    ProofWire(CompactProofWireError),
    ResponseMerkle(CompactResponseMerkleError),
    Whir(SmallChainWhirVerificationError),
    WrongTranscriptShape,
}

impl From<SmallChainCanonicalTransportError> for SmallChainFreshVerificationError {
    fn from(error: SmallChainCanonicalTransportError) -> Self {
        Self::CanonicalTransport(error)
    }
}

impl From<SmallChainCommitmentBindingError> for SmallChainFreshVerificationError {
    fn from(error: SmallChainCommitmentBindingError) -> Self {
        Self::CommitmentBinding(error)
    }
}

impl From<CompactCfwError> for SmallChainFreshVerificationError {
    fn from(error: CompactCfwError) -> Self {
        Self::CompactCfw(error)
    }
}

impl From<CompactTranscriptError> for SmallChainFreshVerificationError {
    fn from(error: CompactTranscriptError) -> Self {
        Self::CompactTranscript(error)
    }
}

impl From<CompactProofWireError> for SmallChainFreshVerificationError {
    fn from(error: CompactProofWireError) -> Self {
        Self::ProofWire(error)
    }
}

impl From<CompactResponseMerkleError> for SmallChainFreshVerificationError {
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::ResponseMerkle(error)
    }
}

impl From<SmallChainWhirVerificationError> for SmallChainFreshVerificationError {
    fn from(error: SmallChainWhirVerificationError) -> Self {
        Self::Whir(error)
    }
}

struct SmallChainWhirExecution {
    pre_challenge_configuration: SmallChainWhirConfiguration,
    main_configuration: SmallChainWhirConfiguration,
    commitment_scheme: SmallChainCommitmentScheme,
    inner_mask_shape: MaskGroupShape,
    outer_mask_shape: MaskGroupShape,
    shared_mask_shape: MaskGroupShape,
    copied_main_source_element_count: usize,
    cross_epoch_variable_count: usize,
    expected_relation_claim_count: usize,
}

impl SmallChainWhirExecution {
    fn verify(
        &self,
        transcript_binding: [u8; Hash512::BYTE_LENGTH],
        commitments: &SmallChainExternalCommitments,
        cross_epoch_point: &[CompactChallengeField],
        expected_cross_epoch_claims: [CompactChallengeField; 3],
        pre_challenge_proof: &SmallChainWhirProof,
        main_proof: &SmallChainWhirProof,
        claim_batch: &CompactCfwClaimBatch,
        matrices: &impl CompactCfwR1csMatrices,
        mutation: SmallChainWhirVerificationMutation,
    ) -> Result<(), SmallChainWhirVerificationError> {
        if cross_epoch_point.len() != self.cross_epoch_variable_count {
            return Err(SmallChainWhirVerificationError::WrongCrossEpochPoint);
        }
        let [masked_pre_challenge_evaluation] = pre_challenge_proof.evals.as_slice() else {
            return Err(ZkVerifierError::EvalCountMismatch {
                expected: 1,
                actual: pre_challenge_proof.evals.len(),
            }
            .into());
        };
        let [masked_main_evaluation, mask_difference] = main_proof.evals.as_slice() else {
            return Err(ZkVerifierError::EvalCountMismatch {
                expected: 2,
                actual: main_proof.evals.len(),
            }
            .into());
        };
        let masked_pre_challenge_evaluation = *masked_pre_challenge_evaluation;
        let masked_main_evaluation = *masked_main_evaluation;
        let mask_difference = *mask_difference;
        if [
            masked_pre_challenge_evaluation,
            masked_main_evaluation,
            mask_difference,
        ] != expected_cross_epoch_claims
        {
            return Err(SmallChainWhirVerificationError::CrossEpochClaimMismatch);
        }
        let mut challenger = small_chain_whir_challenger(transcript_binding);

        let pre_challenge_verifier =
            HidingWhirVerifier::new(&self.pre_challenge_configuration, &self.commitment_scheme);
        let shared_mask_commitment = commitments.shared_masks.clone();
        pre_challenge_verifier.verify_base_source_relation(
            pre_challenge_proof,
            &commitments.pre_challenge_source,
            1,
            |_, revealed_values| {
                let mut source_covector =
                    small_chain_multilinear_equality_covector(cross_epoch_point);
                let mut target = revealed_values[0];
                let mut shared_mask_covectors = vec![
                    vec![CompactChallengeField::ONE],
                    vec![CompactChallengeField::ZERO],
                ];
                match mutation {
                    SmallChainWhirVerificationMutation::PreChallengeTarget => {
                        target += CompactChallengeField::ONE;
                    }
                    SmallChainWhirVerificationMutation::PreChallengeSourceCovector => {
                        source_covector[0] += CompactChallengeField::ONE;
                    }
                    SmallChainWhirVerificationMutation::SharedMaskCovector => {
                        shared_mask_covectors[0][0] += CompactChallengeField::ONE;
                    }
                    SmallChainWhirVerificationMutation::None
                    | SmallChainWhirVerificationMutation::MainTarget
                    | SmallChainWhirVerificationMutation::MainSourceCovector
                    | SmallChainWhirVerificationMutation::InnerMaskCovector => {}
                }
                Ok(CombinedRelationVerifierInput {
                    source_covector: Poly::new(source_covector),
                    target,
                    precommitted_mask_groups: vec![PrecommittedMaskVerifierGroup {
                        shape: self.shared_mask_shape,
                        covectors: shared_mask_covectors,
                        commitment: shared_mask_commitment,
                    }],
                })
            },
            &mut challenger,
        )?;

        let main_verifier =
            HidingWhirVerifier::new(&self.main_configuration, &self.commitment_scheme);
        let inner_mask_commitment = commitments.inner_masks.clone();
        let outer_mask_commitment = commitments.outer_masks.clone();
        let shared_mask_commitment = commitments.shared_masks.clone();
        main_verifier.verify_extension_relation(
            main_proof,
            &commitments.main_source,
            2,
            |batching_challenge, revealed_values| {
                let combination = claim_batch
                    .clone()
                    .begin_combining_with_masked_cross_epoch_claims(
                        CompactCfwMaskedCrossEpochClaims::new(
                            cross_epoch_point.to_vec(),
                            self.copied_main_source_element_count,
                            masked_pre_challenge_evaluation,
                            revealed_values[0],
                            revealed_values[1],
                        ),
                        batching_challenge,
                    )
                    .expect("fresh verifier rebuilds the masked cross-epoch CFW relation");
                let (continuation, mut source_covector) = combination.into_parts();
                matrices
                    .accumulate_weighted_witness_covector_at_row_point(
                        continuation.row_point(),
                        continuation.matrix_role_weights(),
                        &mut source_covector,
                    )
                    .expect("fresh verifier accumulates the structured matrix covector");
                let combined_relation = continuation
                    .finish_after_matrix_accumulation(source_covector)
                    .expect("fresh verifier finishes the masked cross-epoch CFW relation");
                let (
                    mut source_covector,
                    mut target,
                    mut preceding_mask_covectors,
                    mut inner_mask_covectors,
                    outer_mask_covectors,
                    relation_claim_count,
                ) = combined_relation.into_parts();
                assert_eq!(preceding_mask_covectors.len(), self.shared_mask_shape.width);
                assert_eq!(relation_claim_count, self.expected_relation_claim_count);
                match mutation {
                    SmallChainWhirVerificationMutation::None
                    | SmallChainWhirVerificationMutation::PreChallengeTarget
                    | SmallChainWhirVerificationMutation::PreChallengeSourceCovector => {}
                    SmallChainWhirVerificationMutation::MainTarget => {
                        target += CompactChallengeField::ONE;
                    }
                    SmallChainWhirVerificationMutation::MainSourceCovector => {
                        source_covector[0] += CompactChallengeField::ONE;
                    }
                    SmallChainWhirVerificationMutation::InnerMaskCovector => {
                        inner_mask_covectors[0][0] += CompactChallengeField::ONE;
                    }
                    SmallChainWhirVerificationMutation::SharedMaskCovector => {
                        preceding_mask_covectors[0][0] += CompactChallengeField::ONE;
                    }
                }
                Ok(CombinedRelationVerifierInput {
                    source_covector: Poly::new(source_covector),
                    target,
                    precommitted_mask_groups: vec![
                        PrecommittedMaskVerifierGroup {
                            shape: self.inner_mask_shape,
                            covectors: inner_mask_covectors,
                            commitment: inner_mask_commitment,
                        },
                        PrecommittedMaskVerifierGroup {
                            shape: self.outer_mask_shape,
                            covectors: outer_mask_covectors,
                            commitment: outer_mask_commitment,
                        },
                        PrecommittedMaskVerifierGroup {
                            shape: self.shared_mask_shape,
                            covectors: preceding_mask_covectors,
                            commitment: shared_mask_commitment,
                        },
                    ],
                })
            },
            &mut challenger,
        )?;
        Ok(())
    }
}

enum OwnedResponseLeaf {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

impl OwnedResponseLeaf {
    fn value_kind(&self) -> CompactResponseLeafValueKind {
        match self {
            Self::Base(_) => CompactResponseLeafValueKind::BaseField,
            Self::Extension(_) => CompactResponseLeafValueKind::ExtensionField,
        }
    }

    fn field_element_count(&self) -> u64 {
        match self {
            Self::Base(values) => u64::try_from(values.len()).expect("base leaf length fits u64"),
            Self::Extension(values) => {
                u64::try_from(values.len()).expect("extension leaf length fits u64")
            }
        }
    }

    fn borrowed(&self) -> CompactResponseLeafValue<'_> {
        match self {
            Self::Base(values) => CompactResponseLeafValue::BaseField(values),
            Self::Extension(values) => CompactResponseLeafValue::ExtensionField(values),
        }
    }
}

struct BuiltResponse {
    root: [u8; Hash512::BYTE_LENGTH],
    fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
    wire_input: CompactProofResponseWireInput,
    merkle_geometry: CompactResponseMerkleGeometry,
    query_leaf_ordinals: Vec<u64>,
    retained_tree_bytes: Vec<u8>,
}

fn response_wire_geometry(
    response_ordinal: u32,
    base_field_element_count: u64,
    extension_field_element_count: u64,
    leaf_count: u64,
    verifier_message_geometry: FixedUniformVerifierMessageGeometry,
) -> CompactProofResponseWireGeometry {
    CompactProofResponseWireGeometry::new(
        response_ordinal,
        base_field_element_count,
        extension_field_element_count,
        leaf_count,
        0,
        verifier_message_geometry,
    )
    .expect("small-chain response wire geometry is valid")
}

fn build_response(
    private_randomness: &SmallChainAttemptPrivateRandomness,
    response_ordinal: u32,
    leaves: Vec<OwnedResponseLeaf>,
) -> BuiltResponse {
    assert!(!leaves.is_empty());
    assert!(leaves.len().is_power_of_two());
    let components = leaves
        .iter()
        .enumerate()
        .map(|(leaf_ordinal, leaf)| {
            CompactResponseComponentGeometry::new(
                u64::try_from(leaf_ordinal).expect("leaf ordinal fits u64"),
                1,
                1,
                CompactResponseQuerySelection::EveryLeaf,
                leaf.value_kind(),
                leaf.field_element_count(),
            )
        })
        .collect::<Vec<_>>();
    let merkle_geometry = CompactResponseMerkleGeometry::new(response_ordinal, components)
        .expect("small-chain response Merkle geometry is valid");
    let leaf_salts = leaves
        .iter()
        .enumerate()
        .map(|(leaf_ordinal, leaf)| {
            private_randomness.private_leaf_salt(response_ordinal, leaves.len(), leaf_ordinal, leaf)
        })
        .collect::<Vec<_>>();
    let mut writer = CompactResponsePostorderMerkleWriter::new(&merkle_geometry)
        .expect("small-chain retained tree writer starts");
    let mut retained_tree_bytes = Vec::new();
    for (leaf, leaf_salt) in leaves.iter().zip(&leaf_salts) {
        writer
            .absorb_leaf(leaf.borrowed(), leaf_salt)
            .expect("small-chain retained tree accepts a canonical leaf");
        while let Some(output_chunk) = writer.output_chunk().map(<[u8]>::to_vec) {
            retained_tree_bytes.extend_from_slice(&output_chunk);
            writer
                .acknowledge_output_chunk()
                .expect("small-chain retained tree chunk is acknowledged");
        }
    }
    let root = writer
        .finish()
        .expect("small-chain retained response tree finishes");
    assert_eq!(retained_tree_bytes.last_chunk::<64>(), Some(&root));
    let mut base_field_values = Vec::new();
    let mut extension_field_values = Vec::new();
    for leaf in leaves {
        match leaf {
            OwnedResponseLeaf::Base(values) => base_field_values.extend(values),
            OwnedResponseLeaf::Extension(values) => extension_field_values.extend(values),
        }
    }
    let fiat_shamir_round_salt = private_randomness.fiat_shamir_round_salt(response_ordinal);
    let query_leaf_ordinals = (0..leaf_salts.len())
        .map(|ordinal| u64::try_from(ordinal).expect("query ordinal fits u64"))
        .collect();
    let wire_input = CompactProofResponseWireInput::new(
        root,
        fiat_shamir_round_salt,
        base_field_values,
        extension_field_values,
        leaf_salts,
        Vec::new(),
    );
    BuiltResponse {
        root,
        fiat_shamir_round_salt,
        wire_input,
        merkle_geometry,
        query_leaf_ordinals,
        retained_tree_bytes,
    }
}

fn digest_base_field_elements(digest: [u8; Hash512::BYTE_LENGTH]) -> Vec<ProofBaseFieldElement> {
    digest
        .chunks_exact(4)
        .map(|chunk| {
            ProofBaseFieldElement::from_canonical(u64::from(u32::from_le_bytes(
                chunk.try_into().expect("digest chunk has four bytes"),
            )))
            .expect("32-bit digest limb is a canonical base-field element")
        })
        .collect()
}

fn decoded_response_digest(
    decoded_proof: &DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    response_ordinal: usize,
    first_value_ordinal: usize,
) -> Result<[u8; Hash512::BYTE_LENGTH], SmallChainCommitmentBindingError> {
    let response = decoded_proof.responses().get(response_ordinal).ok_or(
        SmallChainCommitmentBindingError::ProofWire(CompactProofWireError::WrongResponseCount),
    )?;
    let mut digest = [0_u8; Hash512::BYTE_LENGTH];
    for digest_limb_ordinal in 0..SMALL_CHAIN_DIGEST_BASE_FIELD_ELEMENT_COUNT {
        let value_ordinal = first_value_ordinal.checked_add(digest_limb_ordinal).ok_or(
            SmallChainCommitmentBindingError::ProofWire(CompactProofWireError::LengthOverflow),
        )?;
        let digest_limb = u32::try_from(
            response
                .base_field_value(canonical_proof_bytes, value_ordinal)?
                .canonical(),
        )
        .map_err(|_| SmallChainCommitmentBindingError::NonCanonicalDigestLimb)?;
        let first_byte = digest_limb_ordinal * size_of::<u32>();
        digest[first_byte..first_byte + size_of::<u32>()]
            .copy_from_slice(&digest_limb.to_le_bytes());
    }
    Ok(digest)
}

fn verify_small_chain_commitment_bindings(
    decoded_proof: &DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    commitments: &SmallChainExternalCommitments,
) -> Result<(), SmallChainCommitmentBindingError> {
    let expected_pre_challenge_binding = small_chain_commitment_binding(
        SMALL_CHAIN_PRE_CHALLENGE_COMMITMENT_BINDING_DOMAIN,
        &[&commitments.pre_challenge_source],
    )?;
    let expected_post_lookup_binding = small_chain_commitment_binding(
        SMALL_CHAIN_POST_LOOKUP_COMMITMENT_BINDING_DOMAIN,
        &[
            &commitments.inner_masks,
            &commitments.main_source,
            &commitments.outer_masks,
            &commitments.shared_masks,
        ],
    )?;
    let decoded_pre_challenge_binding = decoded_response_digest(
        decoded_proof,
        canonical_proof_bytes,
        0,
        SMALL_CHAIN_DIGEST_BASE_FIELD_ELEMENT_COUNT,
    )?;
    let decoded_post_lookup_binding = decoded_response_digest(
        decoded_proof,
        canonical_proof_bytes,
        1,
        SMALL_CHAIN_DIGEST_BASE_FIELD_ELEMENT_COUNT,
    )?;
    if decoded_pre_challenge_binding != expected_pre_challenge_binding
        || decoded_post_lookup_binding != expected_post_lookup_binding
    {
        return Err(SmallChainCommitmentBindingError::WrongBinding);
    }
    Ok(())
}

fn compact_challenges(message: &DecodedFixedUniformVerifierMessage) -> Vec<CompactChallengeField> {
    message
        .extension_elements()
        .iter()
        .copied()
        .map(compact_challenge_from_production)
        .collect()
}

fn small_chain_proof_wire_geometry(
    cfw_geometry: CompactCfwGeometry,
    cross_epoch_variable_count: usize,
) -> CompactProofWireGeometry {
    let mut responses = Vec::new();
    responses.push(response_wire_geometry(
        0,
        2 * u64::try_from(SMALL_CHAIN_DIGEST_BASE_FIELD_ELEMENT_COUNT)
            .expect("small-chain digest field-element count fits u64"),
        0,
        1,
        FixedUniformVerifierMessageGeometry::new(1, PROOF_BASE_FIELD_MODULUS, 0, Vec::new())
            .expect("lookup challenge message geometry"),
    ));
    let committed_mask_element_count = 1_u64
        + u64::try_from(cfw_geometry.inner_mask_count() * 4)
            .expect("inner mask element count fits u64")
        + u64::try_from(cfw_geometry.outer_mask_count() * 8)
            .expect("outer mask element count fits u64");
    responses.push(response_wire_geometry(
        1,
        2 * u64::try_from(SMALL_CHAIN_DIGEST_BASE_FIELD_ELEMENT_COUNT)
            .expect("small-chain digest field-element count fits u64"),
        committed_mask_element_count,
        2,
        FixedUniformVerifierMessageGeometry::new(
            u64::try_from(cross_epoch_variable_count).expect("cross-epoch point length fits u64"),
            0,
            0,
            Vec::new(),
        )
        .expect("cross-epoch point verifier message geometry"),
    ));
    responses.push(response_wire_geometry(
        2,
        0,
        3,
        1,
        FixedUniformVerifierMessageGeometry::new(
            u64::try_from(cfw_geometry.sumcheck_round_count() + 1)
                .expect("CFW initial challenge count fits u64"),
            0,
            0,
            Vec::new(),
        )
        .expect("CFW initial verifier message geometry"),
    ));
    for round_ordinal in 0..cfw_geometry.sumcheck_round_count() {
        let response_ordinal =
            u32::try_from(round_ordinal + 3).expect("CFW response ordinal fits u32");
        responses.push(response_wire_geometry(
            response_ordinal,
            0,
            8,
            1,
            FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
                .expect("CFW round verifier message geometry"),
        ));
    }
    let final_response_ordinal = u32::try_from(cfw_geometry.sumcheck_round_count() + 3)
        .expect("CFW final response ordinal fits u32");
    responses.push(response_wire_geometry(
        final_response_ordinal,
        0,
        u64::try_from(cfw_geometry.outer_mask_count() + COMPACT_CFW_MATRIX_COUNT)
            .expect("CFW final message count fits u64"),
        1,
        FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
            .expect("CFW final verifier message geometry"),
    ));
    CompactProofWireGeometry::new(1, responses).expect("small-chain proof wire geometry")
}

struct ProductionRowSourceResidentMatrices<'source, 'assignment> {
    row_source: &'source CompactStructuredR1csRowSource<'assignment, CompactPublicKeyAssignment>,
    public_ring_vectors_are_zero: bool,
}

impl<'source, 'assignment> ProductionRowSourceResidentMatrices<'source, 'assignment> {
    fn new(
        row_source: &'source CompactStructuredR1csRowSource<
            'assignment,
            CompactPublicKeyAssignment,
        >,
        public_input: &[CompactChallengeField],
    ) -> Result<Self, CompactCfwError> {
        if u64::try_from(public_input.len()).ok() != Some(row_source.witness_length())
            || public_input.first() != Some(&CompactChallengeField::ONE)
            || public_input[1..]
                .iter()
                .any(|value| *value != CompactChallengeField::ZERO)
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        Ok(Self {
            row_source,
            public_ring_vectors_are_zero: true,
        })
    }

    fn form_for_role<'row>(
        row: &'row CompactStructuredR1csRow,
        matrix_role: CompactCfwMatrixRole,
    ) -> &'row CompactStructuredLinearForm {
        match matrix_role {
            CompactCfwMatrixRole::LeftMultiplicand => &row.left,
            CompactCfwMatrixRole::RightMultiplicand => &row.right,
            CompactCfwMatrixRole::Product => &row.output,
        }
    }

    fn little_endian_boolean_weight(
        point: &[CompactChallengeField],
        boolean_ordinal: u64,
    ) -> CompactChallengeField {
        point
            .iter()
            .enumerate()
            .map(|(coordinate_ordinal, coordinate)| {
                if (boolean_ordinal >> coordinate_ordinal) & 1 == 0 {
                    CompactChallengeField::ONE - *coordinate
                } else {
                    *coordinate
                }
            })
            .product()
    }

    fn public_form_contribution(
        &self,
        form: &CompactStructuredLinearForm,
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        let public_input_length = self.row_source.matrices.public_input_length;
        let lookup_challenge =
            compact_challenge_from_production(self.row_source.assignment.lookup_challenge());
        let mut contribution = CompactChallengeField::ZERO;
        for term in &form.ordered_terms {
            match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } if column_ordinal < public_input_length => {
                    contribution += public_input[column_ordinal as usize]
                        * compact_challenge_from_production(
                            ProofChallengeExtensionElement::from_base(
                                base_element_from_signed_integer(integer_coefficient)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                }
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal }
                    if column_ordinal < public_input_length =>
                {
                    contribution += public_input[column_ordinal as usize] * lookup_challenge;
                }
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_end = first_column_ordinal
                        .checked_add(element_count)
                        .ok_or(CompactCfwError::CountOverflow)?;
                    let public_range_end = range_end.min(public_input_length);
                    if first_column_ordinal < public_range_end {
                        let coefficient = compact_challenge_from_production(
                            ProofChallengeExtensionElement::from_base(
                                base_element_from_signed_integer(integer_coefficient)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                        for column_ordinal in first_column_ordinal..public_range_end {
                            contribution += public_input[column_ordinal as usize] * coefficient;
                        }
                    }
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    ..
                } if first_column_ordinal < public_input_length => {
                    return Err(CompactCfwError::InvalidMatrixSource);
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand { .. } => {
                    if !self.public_ring_vectors_are_zero {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                }
                _ => {}
            }
        }
        Ok(contribution)
    }

    fn accumulate_witness_form(
        &self,
        form: &CompactStructuredLinearForm,
        row_weight: CompactChallengeField,
        matrix_role_weight: CompactChallengeField,
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        let public_input_length = self.row_source.matrices.public_input_length;
        let matrix_dimension = self.row_source.matrices.matrix_dimension;
        let weighted_row = row_weight * matrix_role_weight;
        for term in &form.ordered_terms {
            match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } if column_ordinal >= public_input_length => {
                    add_witness_covector_entry(
                        destination,
                        public_input_length,
                        matrix_dimension,
                        column_ordinal,
                        weighted_row
                            * compact_challenge_from_production(
                                ProofChallengeExtensionElement::from_base(
                                    base_element_from_signed_integer(integer_coefficient)
                                        .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                                ),
                            ),
                    )?;
                }
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal }
                    if column_ordinal >= public_input_length =>
                {
                    add_witness_covector_entry(
                        destination,
                        public_input_length,
                        matrix_dimension,
                        column_ordinal,
                        weighted_row
                            * compact_challenge_from_production(
                                self.row_source.assignment.lookup_challenge(),
                            ),
                    )?;
                }
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_end = first_column_ordinal
                        .checked_add(element_count)
                        .ok_or(CompactCfwError::CountOverflow)?;
                    let first_witness_column = first_column_ordinal.max(public_input_length);
                    let coefficient = weighted_row
                        * compact_challenge_from_production(
                            ProofChallengeExtensionElement::from_base(
                                base_element_from_signed_integer(integer_coefficient)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                    for column_ordinal in first_witness_column..range_end {
                        add_witness_covector_entry(
                            destination,
                            public_input_length,
                            matrix_dimension,
                            column_ordinal,
                            coefficient,
                        )?;
                    }
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    table_value_count,
                } => {
                    if first_column_ordinal < public_input_length {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                    for table_value in 0..table_value_count {
                        let denominator = self.row_source.assignment.lookup_challenge().add(
                            ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                        let reciprocal = denominator
                            .inverse()
                            .map_err(|_| CompactCfwError::InvalidMatrixSource)?
                            .negate();
                        add_witness_covector_entry(
                            destination,
                            public_input_length,
                            matrix_dimension,
                            first_column_ordinal
                                .checked_add(table_value)
                                .ok_or(CompactCfwError::CountOverflow)?,
                            weighted_row * compact_challenge_from_production(reciprocal),
                        )?;
                    }
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand { .. } => {
                    if !self.public_ring_vectors_are_zero {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl CompactCfwR1csMatrices for ProductionRowSourceResidentMatrices<'_, '_> {
    fn witness_length(&self) -> usize {
        usize::try_from(self.row_source.witness_length())
            .expect("small-chain witness length fits usize")
    }

    fn evaluate_assignment_rows(
        &self,
        matrix_role: CompactCfwMatrixRole,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
        if public_input.len() != self.witness_length() || witness.len() != self.witness_length() {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let row_count = usize::try_from(self.row_source.row_count())
            .map_err(|_| CompactCfwError::CountOverflow)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(row_count)
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        for row_ordinal in 0..row_count {
            let evaluation = self
                .row_source
                .evaluate_row(
                    u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            rows.push(compact_challenge_from_production(match matrix_role {
                CompactCfwMatrixRole::LeftMultiplicand => evaluation.left,
                CompactCfwMatrixRole::RightMultiplicand => evaluation.right,
                CompactCfwMatrixRole::Product => evaluation.output,
            }));
        }
        Ok(rows)
    }

    fn public_contribution_at_row_point(
        &self,
        matrix_role: CompactCfwMatrixRole,
        row_point: &[CompactChallengeField],
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        if row_point.len() != self.row_source.row_count().ilog2() as usize
            || public_input.len() != self.witness_length()
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let mut result = CompactChallengeField::ZERO;
        for row_ordinal in 0..self.row_source.row_count() {
            let row = self
                .row_source
                .matrices
                .row(self.row_source.relation, row_ordinal)
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            let row_weight = Self::little_endian_boolean_weight(row_point, row_ordinal);
            result += row_weight
                * self.public_form_contribution(
                    Self::form_for_role(&row, matrix_role),
                    public_input,
                )?;
        }
        Ok(result)
    }

    fn accumulate_weighted_witness_covector_at_row_point(
        &self,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        if row_point.len() != self.row_source.row_count().ilog2() as usize
            || destination.len() != self.witness_length()
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        for row_ordinal in 0..self.row_source.row_count() {
            let row = self
                .row_source
                .matrices
                .row(self.row_source.relation, row_ordinal)
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            let row_weight = Self::little_endian_boolean_weight(row_point, row_ordinal);
            for matrix_role in CompactCfwMatrixRole::ALL {
                self.accumulate_witness_form(
                    Self::form_for_role(&row, matrix_role),
                    row_weight,
                    matrix_role_weights[matrix_role.ordinal()],
                    destination,
                )?;
            }
        }
        Ok(())
    }
}

fn add_witness_covector_entry(
    destination: &mut [CompactChallengeField],
    public_input_length: u64,
    matrix_dimension: u64,
    column_ordinal: u64,
    contribution: CompactChallengeField,
) -> Result<(), CompactCfwError> {
    if column_ordinal < public_input_length || column_ordinal >= matrix_dimension {
        return Err(CompactCfwError::InvalidMatrixSource);
    }
    let destination_ordinal = usize::try_from(column_ordinal - public_input_length)
        .map_err(|_| CompactCfwError::CountOverflow)?;
    *destination
        .get_mut(destination_ordinal)
        .ok_or(CompactCfwError::InvalidMatrixSource)? += contribution;
    Ok(())
}

struct AuthenticatedConstantSourceProvider {
    relation_plan_variant: RelationPlanVariant,
    request_context: CommonProofSourcePolynomialRequestContext,
    ordered_source_column_ordinals: Vec<u32>,
    canonical_values: BTreeMap<u32, u64>,
    next_source_index: usize,
    pending_authenticated_read: Option<CommonProofAuthenticatedSourceReadRequest>,
    first_authenticated_read_supplied: bool,
    finished: bool,
}

impl AuthenticatedConstantSourceProvider {
    fn new(
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: RelationPlanVariant,
        request_context: CommonProofSourcePolynomialRequestContext,
    ) -> Result<Self, CommonProofProverError> {
        let assignment_catalog =
            CompactAuthenticatedAssignmentCatalog::derive(relation, &relation_plan_variant)?;
        let ordered_source_column_ordinals = assignment_catalog.source_column_ordinals();
        let mut canonical_values = BTreeMap::new();
        for vector in &relation.ordered_public_vectors {
            insert_vector_source_value(&mut canonical_values, *vector, 0)?;
        }
        for compact_relation in &relation.ordered_relations {
            for term in &compact_relation.ordered_terms {
                if let CompactStructuredLinearTerm::ModulusQuotient {
                    quotient_vector, ..
                } = term
                {
                    insert_vector_source_value(&mut canonical_values, *quotient_vector, 0)?;
                }
            }
        }
        for descriptor in &relation.ordered_private_small_vectors {
            insert_vector_source_value(
                &mut canonical_values,
                descriptor.vector,
                descriptor.centered_offset,
            )?;
        }
        if canonical_values.keys().copied().collect::<Vec<_>>() != ordered_source_column_ordinals {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            relation_plan_variant,
            request_context,
            ordered_source_column_ordinals,
            canonical_values,
            next_source_index: 0,
            pending_authenticated_read: None,
            first_authenticated_read_supplied: false,
            finished: false,
        })
    }

    fn validate_request(
        &self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<(u32, u64), CommonProofProverError> {
        let expected_column_ordinal = *self
            .ordered_source_column_ordinals
            .get(self.next_source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.finished
            || request.request_context() != self.request_context
            || request.column_ordinal() != expected_column_ordinal
            || self.relation_plan_variant.ordered_columns().get(
                usize::try_from(expected_column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ) != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let canonical_value = *self
            .canonical_values
            .get(&expected_column_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        Ok((expected_column_ordinal, canonical_value))
    }
}

impl CommonProofSourcePolynomialProvider for AuthenticatedConstantSourceProvider {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        Ok(CommonProofSourceProviderMemoryAccounting::new(1, 1, 8, 8))
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let (column_ordinal, canonical_value) = self.validate_request(request)?;
        if self.next_source_index == 0 && !self.first_authenticated_read_supplied {
            if self.pending_authenticated_read.is_none() {
                self.pending_authenticated_read = Some(
                    CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
                        request,
                        [11_u8; 64],
                        [12_u8; 64],
                        [13_u8; 64],
                        [14_u8; 64],
                        8,
                        0,
                        0,
                        8,
                        0,
                    )?,
                );
            }
            return Ok(CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired);
        }
        let replay_identity = CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
            crate::hashing::hash_framed_parts_512(
                "sealed-lattice/test/production-small-chain-source/v1",
                &[
                    &column_ordinal.to_le_bytes(),
                    &canonical_value.to_le_bytes(),
                ],
            ),
        )?;
        self.next_source_index = self
            .next_source_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(
                CommonProofSourcePolynomial::from_base_coefficients(vec![
                    ProofBaseFieldElement::from_canonical(canonical_value)?,
                ]),
                replay_identity,
            ),
        ))
    }

    fn poll_replayed_source_polynomial(
        &mut self,
        _request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        Err(CommonProofProverError::InvalidColumn)
    }

    fn pending_authenticated_source_read_request(
        &self,
    ) -> Result<Option<CommonProofAuthenticatedSourceReadRequest>, CommonProofProverError> {
        Ok(self.pending_authenticated_read)
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        if self.pending_authenticated_read != Some(request)
            || authenticated_bytes.as_ref() != [0xa5_u8; 8]
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.pending_authenticated_read = None;
        self.first_authenticated_read_supplied = true;
        Ok(())
    }

    fn cancel_pending_authenticated_source_read(&mut self) {
        self.pending_authenticated_read = None;
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.finished
            || self.pending_authenticated_read.is_some()
            || self.next_source_index != self.ordered_source_column_ordinals.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.finished = true;
        Ok(())
    }
}

fn insert_vector_source_value(
    values: &mut BTreeMap<u32, u64>,
    vector: CompactRingVectorReference,
    canonical_value: u64,
) -> Result<(), CommonProofProverError> {
    for column_ordinal in vector.column_ordinals {
        match values.insert(column_ordinal, canonical_value) {
            None => {}
            Some(previous_value) if previous_value == canonical_value => {}
            Some(_) => return Err(CommonProofProverError::InvalidColumn),
        }
    }
    Ok(())
}

fn reduced_relation() -> (
    CompactPublicKeyRelationCatalog,
    RelationPlanVariant,
    CompactAuthenticatedAssignmentCatalog,
) {
    let (mut input, context) = selected_input_and_context().expect("selected relation inputs");
    input.ring_degree = SMALL_CHAIN_RING_DEGREE;
    input.public_polynomial_column_degree_bound_exclusive = SMALL_CHAIN_RING_DEGREE / 2;
    let compiled = compile_public_key_share_relation_with_source_layout(&input, &context)
        .expect("reduced production-family relation compiles");
    compiled
        .relation_plan
        .check(&context)
        .expect("reduced relation plan checks");
    let relation_plan_variant = compiled
        .relation_plan
        .select_variant(None, None)
        .expect("reduced relation variant")
        .clone();
    let relation = derive_compact_public_key_relation_catalog(
        &input,
        &relation_plan_variant,
        &compiled.source_layout,
    )
    .expect("reduced compact relation derives");
    let assignment_catalog =
        CompactAuthenticatedAssignmentCatalog::derive(&relation, &relation_plan_variant)
            .expect("reduced authenticated assignment derives");
    (relation, relation_plan_variant, assignment_catalog)
}

fn request_context(
    relation: &CompactPublicKeyRelationCatalog,
) -> CommonProofSourcePolynomialRequestContext {
    CommonProofSourcePolynomialRequestContext::new(
        1,
        [2_u8; 64],
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        [3_u8; 64],
        [4_u8; 64],
        relation.relation_plan_hash(),
        None,
        None,
    )
}

fn small_chain_attempt_private_randomness(
    relation_plan_variant: &RelationPlanVariant,
    canonical_public_input_bytes: &[u8],
    source_replay_binding: [u8; Hash512::BYTE_LENGTH],
    attempt_revision: u8,
) -> SmallChainAttemptPrivateRandomness {
    let suite_identifier = Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]);
    let ceremony_context_hash = Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]);
    let mut action_context_bytes = [0x23; Hash512::BYTE_LENGTH];
    action_context_bytes[Hash512::BYTE_LENGTH - 1] = attempt_revision;
    let action_context_hash = Hash512::from_bytes(action_context_bytes);
    let participant_identity = ParticipantIdentity::from_bytes([0x24; Hash512::BYTE_LENGTH]);
    let mut action_root_bytes = [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH];
    action_root_bytes[ACTION_RANDOMNESS_ROOT_BYTE_LENGTH - 1] = attempt_revision;
    let action_private_randomness = Rc::new(
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(action_root_bytes))
            .derive(ActionRandomnessDerivationInput::new(
                suite_identifier,
                ceremony_context_hash,
                action_context_hash,
                participant_identity,
            ))
            .expect("the reduced chain action-private randomness derives"),
    );
    let application_slot = ProofApplicationSlot::new(
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(0),
        None,
        None,
    )
    .expect("the reduced public-key application slot is canonical");
    let application_statement_hash = Hash512::from_bytes(crate::hashing::hash_framed_parts_512(
        SMALL_CHAIN_PRIVATE_COIN_STATEMENT_DOMAIN,
        &[canonical_public_input_bytes],
    ));
    let proof_coin_input =
        PersistentProofCoinInput::new(application_slot, application_statement_hash)
            .expect("the reduced public-key proof coin input is canonical");
    let mut witness_binding = action_private_randomness
        .begin_persistent_proof_witness_coin_binding(&proof_coin_input)
        .expect("the reduced public-key witness binding starts");
    witness_binding
        .absorb_canonical_bytes(canonical_public_input_bytes)
        .expect("the reduced canonical public input enters the witness binding");
    witness_binding
        .absorb_canonical_bytes(&source_replay_binding)
        .expect("the authenticated source replay binding enters the witness binding");
    let attempt_identifier = witness_binding
        .finish()
        .expect("the reduced public-key attempt identifier derives");
    let relation_plan_variant_hash = relation_plan_variant
        .canonical_hash()
        .expect("the reduced relation variant hashes canonically");
    let derivation_binding_hash = Hash512::from_bytes(crate::hashing::hash_framed_parts_512(
        SMALL_CHAIN_PRIVATE_COIN_BINDING_DOMAIN,
        &[
            canonical_public_input_bytes,
            &source_replay_binding,
            &relation_plan_variant_hash,
        ],
    ));
    let coordinate_capacity =
        CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(relation_plan_variant)
            .expect("the reduced relation private-coin capacity derives");
    let private_coins = PrivateRandomnessCommonProofCoinSource::new(
        action_private_randomness,
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        derivation_binding_hash,
        attempt_identifier,
        coordinate_capacity,
    )
    .expect("the reduced production-private coin source starts");
    SmallChainAttemptPrivateRandomness::new(private_coins)
        .expect("the reduced construction-private seeds derive")
}

#[test]
fn production_small_chain_private_randomness_binds_attempt_geometry_and_live_cursor() {
    let (_, relation_plan_variant, _) = reduced_relation();
    let canonical_public_input_bytes = b"canonical reduced public-key input fixture";
    let source_replay_binding = [0x71_u8; Hash512::BYTE_LENGTH];
    let mut first = small_chain_attempt_private_randomness(
        &relation_plan_variant,
        canonical_public_input_bytes,
        source_replay_binding,
        1,
    );
    let mut replayed = small_chain_attempt_private_randomness(
        &relation_plan_variant,
        canonical_public_input_bytes,
        source_replay_binding,
        1,
    );
    let mut changed_attempt = small_chain_attempt_private_randomness(
        &relation_plan_variant,
        canonical_public_input_bytes,
        source_replay_binding,
        2,
    );

    let initial_cursor = first.canonical_randomness_cursor_bytes();
    assert_eq!(initial_cursor, replayed.canonical_randomness_cursor_bytes());
    assert_ne!(
        initial_cursor,
        changed_attempt.canonical_randomness_cursor_bytes()
    );

    let first_extension = first
        .sample_extension_element()
        .expect("the first production-private extension element samples");
    let replayed_extension = replayed
        .sample_extension_element()
        .expect("the replayed production-private extension element samples");
    let changed_extension = changed_attempt
        .sample_extension_element()
        .expect("the changed-attempt extension element samples");
    assert_eq!(first_extension, replayed_extension);
    assert_ne!(first_extension, changed_extension);
    assert_ne!(initial_cursor, first.canonical_randomness_cursor_bytes());

    let leaf = OwnedResponseLeaf::Base(vec![
        ProofBaseFieldElement::from_canonical(7).expect("seven is canonical"),
        ProofBaseFieldElement::from_canonical(11).expect("eleven is canonical"),
    ]);
    let baseline_leaf_salt = first.private_leaf_salt(3, 2, 0, &leaf);
    assert_eq!(
        baseline_leaf_salt,
        replayed.private_leaf_salt(3, 2, 0, &leaf)
    );
    assert_ne!(baseline_leaf_salt, first.private_leaf_salt(4, 2, 0, &leaf));
    assert_ne!(baseline_leaf_salt, first.private_leaf_salt(3, 2, 1, &leaf));
    assert_ne!(
        baseline_leaf_salt,
        changed_attempt.private_leaf_salt(3, 2, 0, &leaf)
    );
    assert_ne!(
        baseline_leaf_salt[..COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
        first.fiat_shamir_round_salt(3)
    );

    let cursor_before_whir = first.canonical_randomness_cursor_bytes();
    let mut first_whir_bytes = [0_u8; 97];
    let mut replayed_whir_bytes = [0_u8; 97];
    first
        .whir_random_source
        .try_fill_bytes(&mut first_whir_bytes)
        .expect("the infallible private WHIR stream fills bytes");
    replayed
        .whir_random_source
        .try_fill_bytes(&mut replayed_whir_bytes)
        .expect("the replayed private WHIR stream fills bytes");
    assert_eq!(first_whir_bytes, replayed_whir_bytes);
    assert_ne!(
        cursor_before_whir,
        first.canonical_randomness_cursor_bytes()
    );
    assert_eq!(
        first.canonical_randomness_cursor_bytes(),
        replayed.canonical_randomness_cursor_bytes()
    );
}

fn replace_small_chain_canonical_section_payload(
    canonical: &[u8],
    section: SmallChainCanonicalSection,
    replacement_payload: &[u8],
) -> Vec<u8> {
    assert!(!replacement_payload.is_empty());
    let payload_range = small_chain_canonical_section_payload_range(canonical, section)
        .expect("the canonical small-chain section exists");
    let declared_length_start = payload_range
        .start
        .checked_sub(size_of::<u32>())
        .expect("the section payload follows its declared length");
    let replacement_length = u32::try_from(replacement_payload.len())
        .expect("the reduced replacement payload length fits u32");
    let resulting_length = canonical
        .len()
        .checked_sub(payload_range.len())
        .and_then(|length| length.checked_add(replacement_payload.len()))
        .expect("the reduced replacement length fits usize");
    let mut replaced = Vec::with_capacity(resulting_length);
    replaced.extend_from_slice(&canonical[..declared_length_start]);
    replaced.extend_from_slice(&replacement_length.to_le_bytes());
    replaced.extend_from_slice(replacement_payload);
    replaced.extend_from_slice(&canonical[payload_range.end..]);
    replaced
}

#[test]
fn production_small_chain_reconciles_authenticated_cfw_cross_epoch_and_sequential_whir() {
    let (relation, relation_plan_variant, assignment_catalog) = reduced_relation();
    assert_eq!(relation.ring_degree(), SMALL_CHAIN_RING_DEGREE);
    assert_eq!(relation.public_key_share_relation_count(), 23);
    assert_eq!(relation.ordinary_anchor_relation_count(), 3);
    assert_eq!(relation.final_anchor_relation_count(), 3);
    assert_eq!(relation.quotient_vector_count(), 29);
    assert_eq!(relation.public_input_ring_vector_count(), 61);
    assert_eq!(relation.quotient_lookup_table_ring_vector_count(), 64);
    assert_eq!(relation.witness_ring_vector_count(), 146);
    assert_eq!(relation.padded_witness_element_count(), 524_288);
    assert_eq!(relation.operative_constraint_count(), 167_937);
    assert_eq!(relation.padded_constraint_count(), 1_048_576);
    let cross_epoch_copy = relation
        .cross_epoch_copy_geometry()
        .expect("reduced two-epoch copy geometry");
    assert_eq!(cross_epoch_copy.copied_ring_vector_count(), 93);
    assert_eq!(cross_epoch_copy.copied_element_count(), 190_464);
    assert_eq!(
        cross_epoch_copy.pre_challenge_message_element_count(),
        262_144
    );
    assert_eq!(cross_epoch_copy.main_message_element_count(), 524_288);
    assert_eq!(cross_epoch_copy.point_coordinate_count(), 18);
    assert_eq!(assignment_catalog.source_column_ordinals().len(), 202);

    let request_context = request_context(&relation);
    let mut source_provider = AuthenticatedConstantSourceProvider::new(
        &relation,
        relation_plan_variant.clone(),
        request_context,
    )
    .expect("authenticated source provider derives from the reduced relation");
    let mut assignment_cursor = CompactAuthenticatedAssignmentCursor::new(
        &relation,
        &relation_plan_variant,
        request_context,
    )
    .expect("authenticated assignment loading starts");
    assert!(matches!(
        assignment_cursor
            .next_source(&relation, &relation_plan_variant, &mut source_provider,)
            .expect("first source requests authenticated bytes"),
        CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired,
    ));
    let authenticated_read = source_provider
        .pending_authenticated_source_read_request()
        .expect("authenticated read state")
        .expect("authenticated read request");
    source_provider
        .supply_authenticated_source_range(
            authenticated_read,
            Zeroizing::new(vec![0xa5_u8; 8].into_boxed_slice()),
        )
        .expect("authenticated source bytes bind the first read");

    let mut loaded_source_count = 0_usize;
    loop {
        match assignment_cursor
            .next_source(&relation, &relation_plan_variant, &mut source_provider)
            .expect("authenticated source loading advances")
        {
            CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired => {
                panic!("the authenticated source range was already supplied")
            }
            CompactAuthenticatedAssignmentPoll::SourceLoaded { .. } => {
                loaded_source_count += 1;
            }
            CompactAuthenticatedAssignmentPoll::Complete => break,
        }
    }
    assert_eq!(loaded_source_count, 202);
    let base_assignment = assignment_cursor
        .finish(&relation, &relation_plan_variant)
        .expect("authenticated assignment loading finishes");
    assert_ne!(base_assignment.source_replay_binding(), [0_u8; 64]);
    let source_replay_binding = base_assignment.source_replay_binding();
    let cfw_geometry = CompactCfwGeometry::derive(
        usize::try_from(relation.padded_witness_element_count())
            .expect("small-chain witness length fits usize"),
    )
    .expect("small-chain CFW geometry derives");
    assert_eq!(cfw_geometry.sumcheck_round_count(), 20);
    let proof_wire_geometry = small_chain_proof_wire_geometry(
        cfw_geometry,
        usize::try_from(cross_epoch_copy.point_coordinate_count())
            .expect("cross-epoch point length fits usize"),
    );
    let public_input_wire_geometry = CompactPublicInputWireGeometry::new(
        1,
        relation.public_input_ring_vector_count(),
        relation.ring_degree(),
    )
    .expect("small-chain public-input wire geometry");
    let public_input_field_elements =
        (0..u64::from(public_input_wire_geometry.field_element_count()))
            .map(|element_ordinal| {
                base_assignment
                    .public_input_base_value(element_ordinal + 1)
                    .expect("small-chain public ring-vector coefficient")
            })
            .collect::<Vec<_>>();
    let public_input_bindings = CompactPublicInputBindings::new(
        Hash512::from_bytes([0x21_u8; 64]),
        Hash512::from_bytes([0x22_u8; 64]),
        Hash512::from_bytes([0x23_u8; 64]),
        Hash512::from_bytes(relation.relation_plan_hash()),
    );
    let canonical_public_input_bytes = encode_compact_public_input(
        public_input_wire_geometry,
        public_input_bindings,
        &public_input_field_elements,
    )
    .expect("small-chain public input encodes canonically");
    let decoded_public_input = decode_compact_public_input(
        public_input_wire_geometry,
        public_input_bindings,
        &canonical_public_input_bytes,
    )
    .expect("fresh small-chain public-input decoder accepts transported bytes");
    let mut private_randomness = small_chain_attempt_private_randomness(
        &relation_plan_variant,
        &canonical_public_input_bytes,
        source_replay_binding,
        1,
    );

    let copied_main_source_element_count = usize::try_from(cross_epoch_copy.copied_element_count())
        .expect("reduced copied source length fits usize");
    let pre_challenge_source_element_count =
        usize::try_from(cross_epoch_copy.pre_challenge_message_element_count())
            .expect("reduced pre-challenge source length fits usize");
    let mut pre_challenge_source_values = Vec::with_capacity(pre_challenge_source_element_count);
    for element_ordinal in 0..copied_main_source_element_count {
        pre_challenge_source_values.push(Goldilocks::from_u64(
            base_assignment
                .witness_base_value(
                    u64::try_from(element_ordinal).expect("copied source ordinal fits u64"),
                )
                .expect("the copied quotient-and-multiplicity prefix is base-field material")
                .canonical(),
        ));
    }
    pre_challenge_source_values.resize(pre_challenge_source_element_count, Goldilocks::ZERO);
    assert!(pre_challenge_source_values.len().is_power_of_two());

    let pre_challenge_variable_count = pre_challenge_source_element_count.ilog2() as usize;
    let main_variable_count = usize::try_from(cross_epoch_copy.main_message_element_count())
        .expect("reduced main source length fits usize")
        .ilog2() as usize;
    let pre_challenge_whir_configuration =
        small_chain_whir_configuration(pre_challenge_variable_count, 2);
    let main_whir_configuration = small_chain_whir_configuration(main_variable_count, 3);
    assert_eq!(
        pre_challenge_whir_configuration.folding_schedule,
        [2, 4, 4, 4]
    );
    assert_eq!(main_whir_configuration.folding_schedule, [3, 4, 4, 4]);
    assert_eq!(
        pre_challenge_whir_configuration.final_sumcheck_rounds,
        main_whir_configuration.final_sumcheck_rounds
    );
    assert_eq!(
        pre_challenge_whir_configuration.params.security_level,
        SMALL_CHAIN_WHIR_SECURITY_LEVEL
    );
    assert_eq!(
        main_whir_configuration.params.security_level,
        SMALL_CHAIN_WHIR_SECURITY_LEVEL
    );
    let whir_commitment_scheme = small_chain_commitment_scheme();
    let whir_extension_commitment_scheme =
        SmallChainExtensionCommitmentScheme::new(whir_commitment_scheme.clone());
    let whir_discrete_fourier_transform = Radix2DFTSmallBatch::<Goldilocks>::default();
    let pre_challenge_whir_prover = HidingWhirProver::new(
        &pre_challenge_whir_configuration,
        &whir_discrete_fourier_transform,
        &whir_commitment_scheme,
    );
    let main_whir_prover = HidingWhirProver::new(
        &main_whir_configuration,
        &whir_discrete_fourier_transform,
        &whir_commitment_scheme,
    );
    let commitment_construction_binding = crate::hashing::hash_framed_parts_512(
        "sealed-lattice/test/production-small-chain-commitment-construction/v1",
        &[&canonical_public_input_bytes, &source_replay_binding],
    );
    let mut commitment_challenger = small_chain_whir_challenger(commitment_construction_binding);
    let (pre_challenge_source_commitment, pre_challenge_source_prover_data) =
        pre_challenge_whir_prover.commit(
            Poly::new(pre_challenge_source_values.clone()),
            &mut commitment_challenger,
            &mut private_randomness.whir_random_source,
        );

    let mut prover_transcript = CompactProverTranscript::new(
        &proof_wire_geometry,
        &decoded_public_input,
        &canonical_public_input_bytes,
    )
    .expect("small-chain compact transcript starts");
    let mut built_responses = Vec::with_capacity(proof_wire_geometry.responses().len());
    let mut prover_verifier_messages = Vec::with_capacity(proof_wire_geometry.responses().len());
    let pre_challenge_commitment_binding = small_chain_commitment_binding(
        SMALL_CHAIN_PRE_CHALLENGE_COMMITMENT_BINDING_DOMAIN,
        &[&pre_challenge_source_commitment],
    )
    .expect("pre-challenge source commitment has one canonical binding");
    let mut source_response_values = digest_base_field_elements(source_replay_binding);
    source_response_values.extend(digest_base_field_elements(pre_challenge_commitment_binding));
    let source_response = build_response(
        &private_randomness,
        0,
        vec![OwnedResponseLeaf::Base(source_response_values)],
    );
    prover_transcript
        .record_response_commitment(source_response.root, source_response.fiat_shamir_round_salt)
        .expect("authenticated source response enters the transcript");
    let lookup_message = prover_transcript
        .derive_verifier_message()
        .expect("lookup challenge derives from the committed source response");
    let [lookup_challenge] = lookup_message.extension_elements() else {
        panic!("lookup transcript move must contain one extension challenge")
    };
    assert!(
        lookup_challenge.canonical_coordinates()[1..]
            .iter()
            .any(|coordinate| *coordinate != 0)
    );
    let lookup_challenge = *lookup_challenge;
    prover_verifier_messages.push(lookup_message);
    built_responses.push(source_response);
    let mut lookup_materializer = base_assignment
        .begin_lookup_inverse_materialization(lookup_challenge)
        .expect("lookup inverse materialization starts");
    loop {
        match lookup_materializer
            .advance(8_192)
            .expect("lookup inverse materialization advances")
        {
            CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                processed_element_count,
            } => assert!((1..=8_192).contains(&processed_element_count)),
            CompactLookupInverseMaterializationPoll::Complete => break,
        }
    }
    let assignment = lookup_materializer
        .finish()
        .expect("lookup inverse materialization finishes");
    assert_eq!(
        assignment.memory_geometry().padded_witness_element_count(),
        524_288
    );

    let mut preparation = CompactStructuredR1csRowSourcePreparation::new(&relation, &assignment)
        .expect("structured row-source preparation starts");
    let row_source = loop {
        match preparation
            .advance(8_192)
            .expect("structured row-source preparation advances")
        {
            CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
                completed_work_unit_count,
                ..
            } => assert!(completed_work_unit_count > 0),
            CompactStructuredR1csRowSourcePreparationPoll::Complete(row_source) => {
                break row_source;
            }
        }
    };
    assert_eq!(row_source.witness_length(), 524_288);
    assert_eq!(row_source.row_count(), 1_048_576);
    for row_ordinal in [
        0,
        relation.operative_constraint_count() - 1,
        relation.operative_constraint_count(),
        relation.padded_constraint_count() - 1,
    ] {
        let evaluation = row_source
            .evaluate_row(row_ordinal)
            .expect("production-family row evaluates");
        assert_eq!(
            evaluation.left.multiply(evaluation.right),
            evaluation.output
        );
    }
    assert_eq!(
        CompactCfwExternalRowSource::witness_length(&row_source)
            .expect("row source exposes CFW witness geometry"),
        524_288
    );

    let witness_length = usize::try_from(row_source.witness_length())
        .expect("small-chain witness length fits usize");
    let public_input = (0..witness_length)
        .map(|element_ordinal| {
            assignment
                .public_input_value(
                    u64::try_from(element_ordinal).expect("public ordinal fits u64"),
                )
                .map(compact_challenge_from_production)
                .expect("small-chain public input value")
        })
        .collect::<Vec<_>>();
    let witness = (0..witness_length)
        .map(|element_ordinal| {
            assignment
                .witness_value(u64::try_from(element_ordinal).expect("witness ordinal fits u64"))
                .map(compact_challenge_from_production)
                .expect("small-chain witness value")
        })
        .collect::<Vec<_>>();
    let resident_matrices = ProductionRowSourceResidentMatrices::new(&row_source, &public_input)
        .expect("resident matrix view binds the structured row source");
    let cfw_private_extension_element_count = cfw_geometry
        .inner_mask_count()
        .checked_mul(2)
        .and_then(|count| {
            cfw_geometry
                .outer_mask_count()
                .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                .and_then(|outer_count| count.checked_add(outer_count))
        })
        .expect("the reduced CFW private sample count fits usize");
    let cfw_private_extension_elements = private_randomness
        .sample_extension_vector(cfw_private_extension_element_count)
        .expect("small-chain CFW masks derive from production-private coins");
    let mut cfw_private_extension_elements = cfw_private_extension_elements.into_iter();
    let mask_material = CompactCfwMaskMaterial::sample(cfw_geometry, || {
        cfw_private_extension_elements
            .next()
            .expect("the pre-sampled CFW mask stream is complete")
    })
    .expect("small-chain CFW masks derive");
    assert!(cfw_private_extension_elements.next().is_none());
    let whir_mask_material = mask_material.clone();
    let prepared_resident = PreparedCompactCfwProver::prepare(
        &resident_matrices,
        &public_input,
        &witness,
        mask_material.clone(),
    )
    .expect("resident CFW prepares from production-family rows");
    let auxiliary_target = prepared_resident.auxiliary_target();

    for element_ordinal in 0..copied_main_source_element_count {
        assert_eq!(
            witness[element_ordinal],
            CompactChallengeField::from(pre_challenge_source_values[element_ordinal]),
            "pre-challenge and main copied coefficients differ at ordinal {element_ordinal}"
        );
    }
    assert!(
        pre_challenge_source_values[copied_main_source_element_count..]
            .iter()
            .all(|value| *value == Goldilocks::ZERO)
    );

    let inner_mask_shape = MaskGroupShape {
        shape: MaskCodeShape::new(
            4,
            main_whir_configuration.mask_queries,
            SMALL_CHAIN_WHIR_MASK_LOG_INVERSE_RATE,
        ),
        width: whir_mask_material.inner_masks().len(),
    };
    let SmallChainCommittedMaskGroup {
        shape: committed_inner_mask_shape,
        messages: inner_mask_messages,
        randomness: inner_mask_randomness,
        commitment: inner_mask_commitment,
        data: inner_mask_prover_data,
    } = commit_small_chain_mask_group(
        inner_mask_shape,
        whir_mask_material
            .inner_masks()
            .iter()
            .map(|mask| mask.to_vec())
            .collect(),
        &mut private_randomness,
        &whir_extension_commitment_scheme,
        &mut commitment_challenger,
    )
    .expect("inner mask commitment randomness derives from production-private coins");
    let (main_source_commitment, main_source_prover_data) = main_whir_prover.commit_extension(
        Poly::new(witness.clone()),
        &mut commitment_challenger,
        &mut private_randomness.whir_random_source,
    );
    let outer_mask_shape = MaskGroupShape {
        shape: MaskCodeShape::new(
            8,
            main_whir_configuration.mask_queries,
            SMALL_CHAIN_WHIR_MASK_LOG_INVERSE_RATE,
        ),
        width: whir_mask_material.outer_masks().len(),
    };
    let SmallChainCommittedMaskGroup {
        shape: committed_outer_mask_shape,
        messages: outer_mask_messages,
        randomness: outer_mask_randomness,
        commitment: outer_mask_commitment,
        data: outer_mask_prover_data,
    } = commit_small_chain_mask_group(
        outer_mask_shape,
        whir_mask_material
            .outer_masks()
            .iter()
            .map(|mask| mask.to_vec())
            .collect(),
        &mut private_randomness,
        &whir_extension_commitment_scheme,
        &mut commitment_challenger,
    )
    .expect("outer mask commitment randomness derives from production-private coins");
    assert_eq!(committed_inner_mask_shape, inner_mask_shape);
    assert_eq!(committed_outer_mask_shape, outer_mask_shape);

    let pre_challenge_mask = private_randomness
        .sample_extension_element()
        .expect("the pre-challenge cross-epoch mask derives from production-private coins");
    let main_mask = private_randomness
        .sample_extension_element()
        .expect("the main cross-epoch mask derives from production-private coins");
    let shared_mask_shape = MaskGroupShape {
        shape: MaskCodeShape::new(
            1,
            pre_challenge_whir_configuration
                .mask_queries
                .checked_add(main_whir_configuration.mask_queries)
                .expect("combined mask query count fits usize"),
            SMALL_CHAIN_WHIR_MASK_LOG_INVERSE_RATE,
        ),
        width: 2,
    };
    let shared_mask_messages = vec![vec![pre_challenge_mask], vec![main_mask]];
    let SmallChainCommittedMaskGroup {
        shape: committed_shared_mask_shape,
        messages: pre_challenge_shared_mask_messages,
        randomness: pre_challenge_shared_mask_randomness,
        commitment: shared_mask_commitment,
        data: pre_challenge_shared_mask_prover_data,
    } = commit_small_chain_mask_group(
        shared_mask_shape,
        shared_mask_messages.clone(),
        &mut private_randomness,
        &whir_extension_commitment_scheme,
        &mut commitment_challenger,
    )
    .expect("shared mask commitment randomness derives from production-private coins");
    let SmallChainCommittedMaskGroup {
        shape: replayed_shared_mask_shape,
        messages: main_shared_mask_messages,
        randomness: main_shared_mask_randomness,
        commitment: replayed_shared_mask_commitment,
        data: main_shared_mask_prover_data,
    } = build_small_chain_mask_group(
        shared_mask_shape,
        shared_mask_messages,
        pre_challenge_shared_mask_randomness.clone(),
        &whir_extension_commitment_scheme,
    );
    assert_eq!(committed_shared_mask_shape, shared_mask_shape);
    assert_eq!(replayed_shared_mask_shape, shared_mask_shape);
    assert_eq!(replayed_shared_mask_commitment, shared_mask_commitment);

    let external_commitments = SmallChainExternalCommitments {
        pre_challenge_source: pre_challenge_source_commitment,
        inner_masks: inner_mask_commitment,
        main_source: main_source_commitment,
        outer_masks: outer_mask_commitment,
        shared_masks: shared_mask_commitment,
    };
    let post_lookup_commitment_binding = small_chain_commitment_binding(
        SMALL_CHAIN_POST_LOOKUP_COMMITMENT_BINDING_DOMAIN,
        &[
            &external_commitments.inner_masks,
            &external_commitments.main_source,
            &external_commitments.outer_masks,
            &external_commitments.shared_masks,
        ],
    )
    .expect("post-lookup commitments have one canonical binding");
    let mut lookup_challenge_bytes = Vec::with_capacity(40);
    for coordinate in lookup_challenge.canonical_coordinates() {
        lookup_challenge_bytes.extend_from_slice(&coordinate.to_le_bytes());
    }
    let assignment_commitment = crate::hashing::hash_framed_parts_512(
        "sealed-lattice/test/production-small-chain-assignment/v1",
        &[
            &source_replay_binding,
            &relation.relation_plan_hash(),
            &lookup_challenge_bytes,
        ],
    );
    let mut committed_mask_values = Vec::new();
    committed_mask_values.push(
        compact_challenge_to_production(auxiliary_target)
            .expect("auxiliary target uses production field coordinates"),
    );
    for mask in mask_material.inner_masks() {
        for value in mask {
            committed_mask_values.push(
                compact_challenge_to_production(*value)
                    .expect("inner mask uses production field coordinates"),
            );
        }
    }
    for mask in mask_material.outer_masks() {
        for value in mask {
            committed_mask_values.push(
                compact_challenge_to_production(*value)
                    .expect("outer mask uses production field coordinates"),
            );
        }
    }
    let mut mask_response_base_values = digest_base_field_elements(assignment_commitment);
    mask_response_base_values.extend(digest_base_field_elements(post_lookup_commitment_binding));
    let mask_response = build_response(
        &private_randomness,
        1,
        vec![
            OwnedResponseLeaf::Base(mask_response_base_values),
            OwnedResponseLeaf::Extension(committed_mask_values),
        ],
    );
    prover_transcript
        .record_response_commitment(mask_response.root, mask_response.fiat_shamir_round_salt)
        .expect("assignment, masks, and post-lookup roots enter the transcript");
    let cross_epoch_message = prover_transcript
        .derive_verifier_message()
        .expect("the cross-epoch point derives after every source commitment");
    let cross_epoch_point = compact_challenges(&cross_epoch_message);
    assert_eq!(
        cross_epoch_point.len(),
        usize::try_from(cross_epoch_copy.point_coordinate_count())
            .expect("cross-epoch point length fits usize")
    );
    prover_verifier_messages.push(cross_epoch_message);
    built_responses.push(mask_response);

    let cross_epoch_covector = small_chain_multilinear_equality_covector(&cross_epoch_point);
    assert_eq!(
        cross_epoch_covector.len(),
        pre_challenge_source_element_count
    );
    let copied_source_evaluation = pre_challenge_source_values
        .iter()
        .copied()
        .map(CompactChallengeField::from)
        .zip(cross_epoch_covector.iter().copied())
        .map(|(source_value, coefficient)| source_value * coefficient)
        .sum::<CompactChallengeField>();
    let masked_pre_challenge_evaluation = copied_source_evaluation + pre_challenge_mask;
    let masked_main_evaluation = copied_source_evaluation + main_mask;
    let mask_difference = pre_challenge_mask - main_mask;
    assert_eq!(
        masked_pre_challenge_evaluation - masked_main_evaluation - mask_difference,
        CompactChallengeField::ZERO
    );
    let cross_epoch_response = build_response(
        &private_randomness,
        2,
        vec![OwnedResponseLeaf::Extension(
            [
                masked_pre_challenge_evaluation,
                masked_main_evaluation,
                mask_difference,
            ]
            .into_iter()
            .map(|value| {
                compact_challenge_to_production(value)
                    .expect("cross-epoch claim uses production field coordinates")
            })
            .collect(),
        )],
    );
    prover_transcript
        .record_response_commitment(
            cross_epoch_response.root,
            cross_epoch_response.fiat_shamir_round_salt,
        )
        .expect("masked cross-epoch claims enter the transcript before CFW challenges");
    let initial_cfw_message = prover_transcript
        .derive_verifier_message()
        .expect("initial CFW challenges derive after the masked cross-epoch claims");
    let initial_cfw_challenges = compact_challenges(&initial_cfw_message);
    let constraint_combining_challenge = *initial_cfw_challenges
        .first()
        .expect("initial CFW message includes the combining challenge");
    let equality_point = initial_cfw_challenges[1..].to_vec();
    assert_eq!(equality_point.len(), cfw_geometry.sumcheck_round_count());
    prover_verifier_messages.push(initial_cfw_message);
    built_responses.push(cross_epoch_response);
    let mut resident_prover = prepared_resident
        .begin(constraint_combining_challenge, equality_point.clone())
        .expect("resident CFW begins");
    let mut external_prover = CompactCfwExternalProverState::prepare(
        &row_source,
        mask_material,
        constraint_combining_challenge,
        equality_point.clone(),
    )
    .expect("external CFW prepares from the same production-family rows");
    assert_eq!(external_prover.auxiliary_target(), auxiliary_target);
    let mut storage = TestStorage::default();
    let mut resident_round_polynomials = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    let mut external_round_polynomials = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    let mut round_challenges = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    for round_ordinal in 0..cfw_geometry.sumcheck_round_count() {
        let resident_round_polynomial = resident_prover
            .next_round_polynomial()
            .expect("resident CFW round polynomial");
        let external_round_polynomial = loop {
            if let Some(round_polynomial) = external_prover
                .advance_round_polynomial(&row_source, &mut storage)
                .expect("external CFW round derivation advances")
            {
                break round_polynomial;
            }
        };
        assert_eq!(external_round_polynomial, resident_round_polynomial);
        resident_round_polynomials.push(resident_round_polynomial);
        external_round_polynomials.push(external_round_polynomial);
        let round_response_ordinal =
            u32::try_from(round_ordinal + 3).expect("CFW round response ordinal fits u32");
        let round_response = build_response(
            &private_randomness,
            round_response_ordinal,
            vec![OwnedResponseLeaf::Extension(
                resident_round_polynomial
                    .into_iter()
                    .map(|value| {
                        compact_challenge_to_production(value)
                            .expect("CFW round polynomial uses production field coordinates")
                    })
                    .collect(),
            )],
        );
        let external_round_response = build_response(
            &private_randomness,
            round_response_ordinal,
            vec![OwnedResponseLeaf::Extension(
                external_round_polynomial
                    .into_iter()
                    .map(|value| {
                        compact_challenge_to_production(value)
                            .expect("external CFW round uses production field coordinates")
                    })
                    .collect(),
            )],
        );
        assert_eq!(external_round_response.root, round_response.root);
        assert_eq!(
            external_round_response.retained_tree_bytes,
            round_response.retained_tree_bytes
        );
        assert_eq!(
            external_round_response.wire_input,
            round_response.wire_input
        );
        prover_transcript
            .record_response_commitment(round_response.root, round_response.fiat_shamir_round_salt)
            .expect("CFW round polynomial enters the transcript");
        let round_message = prover_transcript
            .derive_verifier_message()
            .expect("CFW round challenge derives from the round commitment");
        let round_message_challenges = compact_challenges(&round_message);
        let [round_challenge] = round_message_challenges.as_slice() else {
            panic!("CFW round message must contain one challenge")
        };
        let round_challenge = *round_challenge;
        round_challenges.push(round_challenge);
        prover_verifier_messages.push(round_message);
        built_responses.push(round_response);
        resident_prover
            .bind_round_challenge(round_challenge)
            .expect("resident CFW round challenge binds");
        external_prover
            .bind_round_challenge(round_challenge)
            .expect("external CFW round challenge binds");
        while !external_prover
            .advance_bound_round(&row_source, &mut storage)
            .expect("external CFW bound round advances")
        {}
    }
    let resident_finish = resident_prover.finish().expect("resident CFW finishes");
    let external_output = external_prover.finish().expect("external CFW finishes");
    assert_eq!(external_round_polynomials, resident_round_polynomials);
    assert_eq!(
        external_output.finish().outer_evaluations(),
        resident_finish.outer_evaluations()
    );
    assert_eq!(
        external_output.finish().final_values(),
        resident_finish.final_values()
    );
    assert!(external_output.usage().total_written_byte_length() > 0);
    assert!(external_output.usage().total_read_byte_length() > 0);

    let final_response_values = resident_finish
        .outer_evaluations()
        .iter()
        .copied()
        .chain(resident_finish.final_values())
        .map(|value| {
            compact_challenge_to_production(value)
                .expect("CFW final response uses production field coordinates")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        final_response_values.len(),
        cfw_geometry.outer_mask_count() + COMPACT_CFW_MATRIX_COUNT
    );
    let final_response_ordinal =
        u32::try_from(cfw_geometry.sumcheck_round_count() + 3).expect("final ordinal fits u32");
    let final_response = build_response(
        &private_randomness,
        final_response_ordinal,
        vec![OwnedResponseLeaf::Extension(final_response_values.clone())],
    );
    let external_final_response_values = external_output
        .finish()
        .outer_evaluations()
        .iter()
        .copied()
        .chain(external_output.finish().final_values())
        .map(|value| {
            compact_challenge_to_production(value)
                .expect("external CFW final response uses production field coordinates")
        })
        .collect::<Vec<_>>();
    assert_eq!(external_final_response_values, final_response_values);
    let external_final_response = build_response(
        &private_randomness,
        final_response_ordinal,
        vec![OwnedResponseLeaf::Extension(external_final_response_values)],
    );
    assert_eq!(external_final_response.root, final_response.root);
    assert_eq!(
        external_final_response.retained_tree_bytes,
        final_response.retained_tree_bytes
    );
    assert_eq!(
        external_final_response.wire_input,
        final_response.wire_input
    );
    prover_transcript
        .record_response_commitment(final_response.root, final_response.fiat_shamir_round_salt)
        .expect("CFW final values enter the transcript");
    let final_verifier_message = prover_transcript
        .derive_verifier_message()
        .expect("post-CFW challenges derive from the final response");
    let final_challenges = compact_challenges(&final_verifier_message);
    let [joint_constraint_challenge] = final_challenges.as_slice() else {
        panic!("post-CFW message must contain one joint-constraint challenge")
    };
    let joint_constraint_challenge = *joint_constraint_challenge;
    prover_verifier_messages.push(final_verifier_message);
    built_responses.push(final_response);
    prover_transcript
        .finish()
        .expect("small-chain compact transcript consumes every response");
    assert_eq!(built_responses.len(), proof_wire_geometry.responses().len());
    assert_eq!(
        prover_verifier_messages.len(),
        proof_wire_geometry.responses().len()
    );

    let canonical_proof_bytes = encode_compact_proof_wire(
        &proof_wire_geometry,
        &CompactProofWireInput::new(
            built_responses
                .iter()
                .map(|response| response.wire_input.clone())
                .collect(),
        ),
    )
    .expect("small-chain proof responses encode canonically");
    let decoded_proof = decode_compact_proof_wire(
        &proof_wire_geometry,
        &canonical_proof_bytes,
        canonical_proof_bytes.len(),
    )
    .expect("fresh small-chain proof decoder accepts transported bytes");
    verify_small_chain_commitment_bindings(
        &decoded_proof,
        &canonical_proof_bytes,
        &external_commitments,
    )
    .expect("outer CFW responses bind every canonical WHIR commitment section");
    let mut fresh_verifier_messages = Vec::with_capacity(decoded_proof.responses().len());
    for (response_ordinal, ((built_response, wire_geometry), decoded_response)) in built_responses
        .iter()
        .zip(proof_wire_geometry.responses())
        .zip(decoded_proof.responses())
        .enumerate()
    {
        verify_decoded_compact_response_opening(
            &built_response.merkle_geometry,
            wire_geometry,
            decoded_response,
            &canonical_proof_bytes,
            &built_response.query_leaf_ordinals,
        )
        .unwrap_or_else(|error| {
            panic!("fresh response {response_ordinal} opening verification failed: {error:?}")
        });
        let verifier_message = derive_compact_fiat_shamir_verifier_message(
            &proof_wire_geometry,
            &decoded_proof,
            &canonical_proof_bytes,
            &decoded_public_input,
            &canonical_public_input_bytes,
            u32::try_from(response_ordinal).expect("response ordinal fits u32"),
        )
        .expect("fresh verifier derives the exact response message");
        assert_eq!(
            verifier_message, prover_verifier_messages[response_ordinal],
            "transcript message mismatch at response {response_ordinal}"
        );
        fresh_verifier_messages.push(verifier_message);
    }

    let mut fresh_public_input = Vec::with_capacity(witness_length);
    fresh_public_input.push(CompactChallengeField::ONE);
    for element_ordinal in 0..decoded_public_input.field_element_count() {
        fresh_public_input.push(compact_challenge_from_production(
            ProofChallengeExtensionElement::from_base(
                decoded_public_input
                    .field_element(&canonical_public_input_bytes, element_ordinal)
                    .expect("fresh public-input coefficient decodes"),
            ),
        ));
    }
    fresh_public_input.resize(witness_length, CompactChallengeField::ZERO);
    assert_eq!(fresh_public_input, public_input);

    let fresh_cross_epoch_point = compact_challenges(&fresh_verifier_messages[1]);
    assert_eq!(fresh_cross_epoch_point, cross_epoch_point);
    let fresh_initial_cfw_challenges = compact_challenges(&fresh_verifier_messages[2]);
    let fresh_constraint_combining_challenge = *fresh_initial_cfw_challenges
        .first()
        .expect("fresh initial CFW message includes the combining challenge");
    let fresh_equality_point = fresh_initial_cfw_challenges[1..].to_vec();
    assert_eq!(
        fresh_constraint_combining_challenge,
        constraint_combining_challenge
    );
    assert_eq!(fresh_equality_point, equality_point);
    let fresh_round_challenges = (0..cfw_geometry.sumcheck_round_count())
        .map(|round_ordinal| {
            let challenges = compact_challenges(&fresh_verifier_messages[round_ordinal + 3]);
            let [challenge] = challenges.as_slice() else {
                panic!("fresh CFW round message must contain one challenge")
            };
            *challenge
        })
        .collect::<Vec<_>>();
    assert_eq!(fresh_round_challenges, round_challenges);
    let fresh_final_challenges = compact_challenges(
        fresh_verifier_messages
            .last()
            .expect("fresh final CFW message exists"),
    );
    let [fresh_joint_constraint_challenge] = fresh_final_challenges.as_slice() else {
        panic!("fresh post-CFW message must contain one joint-constraint challenge")
    };
    let fresh_joint_constraint_challenge = *fresh_joint_constraint_challenge;
    assert_eq!(fresh_joint_constraint_challenge, joint_constraint_challenge);

    let decoded_cross_epoch_response = &decoded_proof.responses()[2];
    let decoded_cross_epoch_claims = core::array::from_fn(|claim_ordinal| {
        compact_challenge_from_production(
            decoded_cross_epoch_response
                .extension_field_value(&canonical_proof_bytes, claim_ordinal)
                .expect("transported cross-epoch claim decodes"),
        )
    });
    assert_eq!(
        decoded_cross_epoch_claims,
        [
            masked_pre_challenge_evaluation,
            masked_main_evaluation,
            mask_difference,
        ]
    );

    let decoded_mask_response = &decoded_proof.responses()[1];
    let decoded_auxiliary_target = compact_challenge_from_production(
        decoded_mask_response
            .extension_field_value(&canonical_proof_bytes, 0)
            .expect("transported auxiliary target decodes"),
    );
    assert_eq!(decoded_auxiliary_target, auxiliary_target);
    let mut decoded_round_polynomials = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    for round_ordinal in 0..cfw_geometry.sumcheck_round_count() {
        let decoded_response = &decoded_proof.responses()[round_ordinal + 3];
        let mut polynomial = [CompactChallengeField::ZERO; 8];
        for (coefficient_ordinal, coefficient) in polynomial.iter_mut().enumerate() {
            *coefficient = compact_challenge_from_production(
                decoded_response
                    .extension_field_value(&canonical_proof_bytes, coefficient_ordinal)
                    .expect("transported CFW round coefficient decodes"),
            );
        }
        decoded_round_polynomials.push(polynomial);
    }
    assert_eq!(decoded_round_polynomials, resident_round_polynomials);
    let decoded_final_response = decoded_proof
        .responses()
        .last()
        .expect("transported CFW final response exists");
    let decoded_outer_evaluations = (0..cfw_geometry.outer_mask_count())
        .map(|evaluation_ordinal| {
            compact_challenge_from_production(
                decoded_final_response
                    .extension_field_value(&canonical_proof_bytes, evaluation_ordinal)
                    .expect("transported outer evaluation decodes"),
            )
        })
        .collect::<Vec<_>>();
    let decoded_final_values = core::array::from_fn(|matrix_ordinal| {
        compact_challenge_from_production(
            decoded_final_response
                .extension_field_value(
                    &canonical_proof_bytes,
                    cfw_geometry.outer_mask_count() + matrix_ordinal,
                )
                .expect("transported final matrix value decodes"),
        )
    });
    let fresh_cfw_transcript = CompactCfwTranscript::new(
        decoded_auxiliary_target,
        decoded_round_polynomials.clone(),
        decoded_outer_evaluations,
        decoded_final_values,
    );
    let verified_claim_batch = verify_compact_cfw_transcript(
        &resident_matrices,
        &fresh_public_input,
        &fresh_cfw_transcript,
        fresh_constraint_combining_challenge,
        &fresh_equality_point,
        &fresh_round_challenges,
        fresh_joint_constraint_challenge,
    )
    .expect("fresh verifier accepts the transported CFW transcript");

    assert!(pre_challenge_whir_configuration.check_pow_bits());
    assert!(main_whir_configuration.check_pow_bits());
    let whir_handoff_binding = small_chain_whir_handoff_binding(
        &canonical_public_input_bytes,
        &canonical_proof_bytes,
        &external_commitments,
    )
    .expect("the exact outer bytes and commitment sections have one WHIR handoff binding");
    let mut whir_challenger = small_chain_whir_challenger(whir_handoff_binding);

    let pre_challenge_source_covector = cross_epoch_covector.clone();
    let pre_challenge_whir_proof = pre_challenge_whir_prover
        .prove_base_source_relation(
            pre_challenge_source_prover_data,
            vec![masked_pre_challenge_evaluation],
            |_| {
                Ok(CombinedRelationProverInput {
                    source_covector: Poly::new(pre_challenge_source_covector),
                    target: masked_pre_challenge_evaluation,
                    precommitted_mask_groups: vec![PrecommittedMaskProverGroup {
                        shape: shared_mask_shape,
                        messages: pre_challenge_shared_mask_messages,
                        randomness: pre_challenge_shared_mask_randomness,
                        covectors: vec![
                            vec![CompactChallengeField::ONE],
                            vec![CompactChallengeField::ZERO],
                        ],
                        data: pre_challenge_shared_mask_prover_data,
                    }],
                })
            },
            &mut whir_challenger,
            &mut private_randomness.whir_random_source,
        )
        .expect("the reduced base-field pre-challenge relation enters hiding WHIR");
    assert_eq!(
        pre_challenge_whir_proof.evals,
        vec![masked_pre_challenge_evaluation]
    );
    assert_eq!(
        pre_challenge_whir_proof.rounds.len(),
        pre_challenge_whir_configuration.n_rounds()
    );
    assert_eq!(
        pre_challenge_whir_proof.sumchecks.len(),
        pre_challenge_whir_configuration.n_rounds() + 1
    );

    let whir_prover_claim_batch = verified_claim_batch.clone();
    let main_cross_epoch_point = cross_epoch_point.clone();
    let expected_relation_claim_count = cfw_geometry
        .generalized_committed_relation_claim_count()
        .checked_add(2)
        .expect("cross-epoch relation claim count fits usize");
    let main_whir_proof = main_whir_prover
        .prove_extension_relation(
            main_source_prover_data,
            vec![masked_main_evaluation, mask_difference],
            |whir_batching_challenge| {
                let masked_cross_epoch_claims = || {
                    CompactCfwMaskedCrossEpochClaims::new(
                        main_cross_epoch_point.clone(),
                        copied_main_source_element_count,
                        masked_pre_challenge_evaluation,
                        masked_main_evaluation,
                        mask_difference,
                    )
                };
                let direct_combination = whir_prover_claim_batch
                    .clone()
                    .begin_combining_with_masked_cross_epoch_claims(
                        masked_cross_epoch_claims(),
                        whir_batching_challenge,
                    )
                    .expect("WHIR batching challenge starts the direct masked relation");
                let (direct_continuation, mut direct_source_covector) =
                    direct_combination.into_parts();
                resident_matrices
                    .accumulate_weighted_witness_covector_at_row_point(
                        direct_continuation.row_point(),
                        direct_continuation.matrix_role_weights(),
                        &mut direct_source_covector,
                    )
                    .expect("resident matrices accumulate the WHIR-bound direct covector");
                let direct_combined_relation = direct_continuation
                    .finish_after_matrix_accumulation(direct_source_covector)
                    .expect("resident matrices finish the WHIR-bound direct relation");
                let production_combination = whir_prover_claim_batch
                    .begin_combining_with_masked_cross_epoch_claims(
                        masked_cross_epoch_claims(),
                        whir_batching_challenge,
                    )
                    .expect("WHIR batching challenge starts the masked cross-epoch transpose");
                let mut production_handoff =
                    CompactStructuredWitnessCovectorHandoff::from_production_row_source(
                        &row_source,
                        production_combination,
                    )
                    .expect("WHIR batching challenge connects to the production row source");
                let combined_relation = loop {
                    match production_handoff
                        .advance(8_192)
                        .expect("WHIR-bound production transpose advances")
                    {
                        CompactStructuredWitnessCovectorHandoffPoll::StepCompleted { .. } => {}
                        CompactStructuredWitnessCovectorHandoffPoll::Complete(
                            combined_relation,
                        ) => {
                            break combined_relation;
                        }
                    }
                };
                assert_eq!(combined_relation, direct_combined_relation);
                let (
                    source_covector,
                    target,
                    preceding_mask_covectors,
                    inner_mask_covectors,
                    outer_mask_covectors,
                    relation_claim_count,
                ) = combined_relation.into_parts();
                assert_eq!(preceding_mask_covectors.len(), shared_mask_shape.width);
                assert_eq!(relation_claim_count, expected_relation_claim_count);
                assert_eq!(inner_mask_covectors.len(), inner_mask_shape.width);
                assert_eq!(outer_mask_covectors.len(), outer_mask_shape.width);
                let evaluated_relation = source_covector
                    .iter()
                    .zip(&witness)
                    .map(|(coefficient, value)| *coefficient * *value)
                    .sum::<CompactChallengeField>()
                    + preceding_mask_covectors
                        .iter()
                        .zip(&main_shared_mask_messages)
                        .map(|(covector, message)| {
                            covector
                                .iter()
                                .zip(message)
                                .map(|(coefficient, value)| *coefficient * *value)
                                .sum::<CompactChallengeField>()
                        })
                        .sum::<CompactChallengeField>()
                    + inner_mask_covectors
                        .iter()
                        .zip(&inner_mask_messages)
                        .map(|(covector, message)| {
                            covector
                                .iter()
                                .zip(message)
                                .map(|(coefficient, value)| *coefficient * *value)
                                .sum::<CompactChallengeField>()
                        })
                        .sum::<CompactChallengeField>()
                    + outer_mask_covectors
                        .iter()
                        .zip(&outer_mask_messages)
                        .map(|(covector, message)| {
                            covector
                                .iter()
                                .zip(message)
                                .map(|(coefficient, value)| *coefficient * *value)
                                .sum::<CompactChallengeField>()
                        })
                        .sum::<CompactChallengeField>();
                assert_eq!(evaluated_relation, target);
                Ok(CombinedRelationProverInput {
                    source_covector: Poly::new(source_covector),
                    target,
                    precommitted_mask_groups: vec![
                        PrecommittedMaskProverGroup {
                            shape: inner_mask_shape,
                            messages: inner_mask_messages,
                            randomness: inner_mask_randomness,
                            covectors: inner_mask_covectors,
                            data: inner_mask_prover_data,
                        },
                        PrecommittedMaskProverGroup {
                            shape: outer_mask_shape,
                            messages: outer_mask_messages,
                            randomness: outer_mask_randomness,
                            covectors: outer_mask_covectors,
                            data: outer_mask_prover_data,
                        },
                        PrecommittedMaskProverGroup {
                            shape: shared_mask_shape,
                            messages: main_shared_mask_messages,
                            randomness: main_shared_mask_randomness,
                            covectors: preceding_mask_covectors,
                            data: main_shared_mask_prover_data,
                        },
                    ],
                })
            },
            &mut whir_challenger,
            &mut private_randomness.whir_random_source,
        )
        .expect("the reduced masked cross-epoch CFW relation enters hiding WHIR");
    assert_eq!(
        main_whir_proof.evals,
        vec![masked_main_evaluation, mask_difference]
    );
    assert_eq!(
        main_whir_proof.rounds.len(),
        main_whir_configuration.n_rounds()
    );
    assert_eq!(
        main_whir_proof.sumchecks.len(),
        main_whir_configuration.n_rounds() + 1
    );
    let canonical_small_chain_proof_bytes = encode_small_chain_canonical_proof(
        &pre_challenge_whir_configuration,
        &main_whir_configuration,
        inner_mask_shape,
        outer_mask_shape,
        shared_mask_shape,
        &canonical_proof_bytes,
        &external_commitments,
        &pre_challenge_whir_proof,
        &main_whir_proof,
    )
    .expect("the complete reduced CFW and WHIR chain encodes canonically");
    let decoded_small_chain_proof = decode_small_chain_canonical_proof(
        &pre_challenge_whir_configuration,
        &main_whir_configuration,
        inner_mask_shape,
        outer_mask_shape,
        shared_mask_shape,
        &canonical_small_chain_proof_bytes,
    )
    .expect("a fresh decoder accepts the complete reduced CFW and WHIR chain");
    assert_eq!(
        decoded_small_chain_proof.canonical_cfw_proof_bytes,
        canonical_proof_bytes
    );
    assert_eq!(
        decoded_small_chain_proof.commitments.pre_challenge_source,
        external_commitments.pre_challenge_source
    );
    assert_eq!(
        decoded_small_chain_proof.commitments.inner_masks,
        external_commitments.inner_masks
    );
    assert_eq!(
        decoded_small_chain_proof.commitments.main_source,
        external_commitments.main_source
    );
    assert_eq!(
        decoded_small_chain_proof.commitments.outer_masks,
        external_commitments.outer_masks
    );
    assert_eq!(
        decoded_small_chain_proof.commitments.shared_masks,
        external_commitments.shared_masks
    );

    let transported_cfw_proof = decode_compact_proof_wire(
        &proof_wire_geometry,
        &decoded_small_chain_proof.canonical_cfw_proof_bytes,
        decoded_small_chain_proof.canonical_cfw_proof_bytes.len(),
    )
    .expect("the CFW section remains independently canonical after transport");
    for (response_ordinal, ((built_response, wire_geometry), decoded_response)) in built_responses
        .iter()
        .zip(proof_wire_geometry.responses())
        .zip(transported_cfw_proof.responses())
        .enumerate()
    {
        verify_decoded_compact_response_opening(
            &built_response.merkle_geometry,
            wire_geometry,
            decoded_response,
            &decoded_small_chain_proof.canonical_cfw_proof_bytes,
            &built_response.query_leaf_ordinals,
        )
        .unwrap_or_else(|error| {
            panic!("transported response {response_ordinal} opening failed: {error:?}")
        });
        let verifier_message = derive_compact_fiat_shamir_verifier_message(
            &proof_wire_geometry,
            &transported_cfw_proof,
            &decoded_small_chain_proof.canonical_cfw_proof_bytes,
            &decoded_public_input,
            &canonical_public_input_bytes,
            u32::try_from(response_ordinal).expect("response ordinal fits u32"),
        )
        .expect("the fresh verifier derives a message from the transported CFW section");
        assert_eq!(
            verifier_message, prover_verifier_messages[response_ordinal],
            "transported transcript message mismatch at response {response_ordinal}"
        );
    }

    let whir_execution = SmallChainWhirExecution {
        pre_challenge_configuration: pre_challenge_whir_configuration,
        main_configuration: main_whir_configuration,
        commitment_scheme: whir_commitment_scheme,
        inner_mask_shape,
        outer_mask_shape,
        shared_mask_shape,
        copied_main_source_element_count,
        cross_epoch_variable_count: cross_epoch_point.len(),
        expected_relation_claim_count,
    };
    let reencoded_small_chain_proof = encode_small_chain_canonical_proof(
        &whir_execution.pre_challenge_configuration,
        &whir_execution.main_configuration,
        whir_execution.inner_mask_shape,
        whir_execution.outer_mask_shape,
        whir_execution.shared_mask_shape,
        &decoded_small_chain_proof.canonical_cfw_proof_bytes,
        &decoded_small_chain_proof.commitments,
        &decoded_small_chain_proof.pre_challenge_whir_proof,
        &decoded_small_chain_proof.main_whir_proof,
    )
    .expect("decoded small-chain fields re-encode canonically");
    assert_eq!(
        reencoded_small_chain_proof,
        canonical_small_chain_proof_bytes
    );

    let decode_transported_small_chain = |canonical: &[u8]| {
        decode_small_chain_canonical_proof(
            &whir_execution.pre_challenge_configuration,
            &whir_execution.main_configuration,
            whir_execution.inner_mask_shape,
            whir_execution.outer_mask_shape,
            whir_execution.shared_mask_shape,
            canonical,
        )
    };
    let verify_transported_small_chain =
        |transported: &DecodedSmallChainCanonicalProof|
         -> Result<(), SmallChainFreshVerificationError> {
            let transported_cfw_proof = decode_compact_proof_wire(
                &proof_wire_geometry,
                &transported.canonical_cfw_proof_bytes,
                transported.canonical_cfw_proof_bytes.len(),
            )?;
            verify_small_chain_commitment_bindings(
                &transported_cfw_proof,
                &transported.canonical_cfw_proof_bytes,
                &transported.commitments,
            )?;
            let mut transported_verifier_messages =
                Vec::with_capacity(transported_cfw_proof.responses().len());
            for (response_ordinal, ((built_response, wire_geometry), decoded_response)) in
                built_responses
                    .iter()
                    .zip(proof_wire_geometry.responses())
                    .zip(transported_cfw_proof.responses())
                    .enumerate()
            {
                verify_decoded_compact_response_opening(
                    &built_response.merkle_geometry,
                    wire_geometry,
                    decoded_response,
                    &transported.canonical_cfw_proof_bytes,
                    &built_response.query_leaf_ordinals,
                )?;
                transported_verifier_messages.push(
                    derive_compact_fiat_shamir_verifier_message(
                        &proof_wire_geometry,
                        &transported_cfw_proof,
                        &transported.canonical_cfw_proof_bytes,
                        &decoded_public_input,
                        &canonical_public_input_bytes,
                        u32::try_from(response_ordinal)
                            .expect("transported response ordinal fits u32"),
                    )?,
                );
            }

            let cross_epoch_point = transported_verifier_messages
                .get(1)
                .map(compact_challenges)
                .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let initial_cfw_challenges = transported_verifier_messages
                .get(2)
                .map(compact_challenges)
                .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let (constraint_combining_challenge, equality_point) = initial_cfw_challenges
                .split_first()
                .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
            if equality_point.len() != cfw_geometry.sumcheck_round_count() {
                return Err(SmallChainFreshVerificationError::WrongTranscriptShape);
            }
            let final_challenges = transported_verifier_messages
                .last()
                .map(compact_challenges)
                .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let [joint_constraint_challenge] = final_challenges.as_slice() else {
                return Err(SmallChainFreshVerificationError::WrongTranscriptShape);
            };
            let round_challenges = (0..cfw_geometry.sumcheck_round_count())
                .map(|round_ordinal| {
                    let challenges = transported_verifier_messages
                        .get(round_ordinal + 3)
                        .map(compact_challenges)
                        .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
                    let [challenge] = challenges.as_slice() else {
                        return Err(SmallChainFreshVerificationError::WrongTranscriptShape);
                    };
                    Ok(*challenge)
                })
                .collect::<Result<Vec<_>, SmallChainFreshVerificationError>>()?;

            let mask_response = transported_cfw_proof
                .responses()
                .get(1)
                .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let auxiliary_target = compact_challenge_from_production(
                mask_response.extension_field_value(
                    &transported.canonical_cfw_proof_bytes,
                    0,
                )?,
            );
            let cross_epoch_response = transported_cfw_proof
                .responses()
                .get(2)
                .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let cross_epoch_claims = (0..3)
                .map(|claim_ordinal| {
                    cross_epoch_response
                        .extension_field_value(
                            &transported.canonical_cfw_proof_bytes,
                            claim_ordinal,
                        )
                        .map(compact_challenge_from_production)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let [masked_pre_challenge_evaluation, masked_main_evaluation, mask_difference] =
                cross_epoch_claims
                    .try_into()
                    .map_err(|_| SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let round_polynomials = (0..cfw_geometry.sumcheck_round_count())
                .map(|round_ordinal| {
                    let response = transported_cfw_proof
                        .responses()
                        .get(round_ordinal + 3)
                        .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
                    (0..8)
                        .map(|coefficient_ordinal| {
                            response
                                .extension_field_value(
                                    &transported.canonical_cfw_proof_bytes,
                                    coefficient_ordinal,
                                )
                                .map(compact_challenge_from_production)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .try_into()
                        .map_err(|_| SmallChainFreshVerificationError::WrongTranscriptShape)
                })
                .collect::<Result<Vec<[CompactChallengeField; 8]>, _>>()?;
            let final_response = transported_cfw_proof
                .responses()
                .last()
                .ok_or(SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let outer_evaluations = (0..cfw_geometry.outer_mask_count())
                .map(|evaluation_ordinal| {
                    final_response
                        .extension_field_value(
                            &transported.canonical_cfw_proof_bytes,
                            evaluation_ordinal,
                        )
                        .map(compact_challenge_from_production)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let final_values = (0..COMPACT_CFW_MATRIX_COUNT)
                .map(|matrix_ordinal| {
                    final_response
                        .extension_field_value(
                            &transported.canonical_cfw_proof_bytes,
                            cfw_geometry.outer_mask_count() + matrix_ordinal,
                        )
                        .map(compact_challenge_from_production)
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| SmallChainFreshVerificationError::WrongTranscriptShape)?;
            let cfw_transcript = CompactCfwTranscript::new(
                auxiliary_target,
                round_polynomials,
                outer_evaluations,
                final_values,
            );
            let claim_batch = verify_compact_cfw_transcript(
                &resident_matrices,
                &fresh_public_input,
                &cfw_transcript,
                *constraint_combining_challenge,
                equality_point,
                &round_challenges,
                *joint_constraint_challenge,
            )?;
            let whir_handoff_binding = small_chain_whir_handoff_binding(
                &canonical_public_input_bytes,
                &transported.canonical_cfw_proof_bytes,
                &transported.commitments,
            )?;
            whir_execution.verify(
                whir_handoff_binding,
                &transported.commitments,
                &cross_epoch_point,
                [
                    masked_pre_challenge_evaluation,
                    masked_main_evaluation,
                    mask_difference,
                ],
                &transported.pre_challenge_whir_proof,
                &transported.main_whir_proof,
                &claim_batch,
                &resident_matrices,
                SmallChainWhirVerificationMutation::None,
            )?;
            Ok(())
        };
    verify_transported_small_chain(&decoded_small_chain_proof)
        .expect("fresh verifier accepts the CFW-bound WHIR proof");
    for mutation in [
        SmallChainWhirVerificationMutation::PreChallengeTarget,
        SmallChainWhirVerificationMutation::PreChallengeSourceCovector,
        SmallChainWhirVerificationMutation::MainTarget,
        SmallChainWhirVerificationMutation::MainSourceCovector,
        SmallChainWhirVerificationMutation::InnerMaskCovector,
        SmallChainWhirVerificationMutation::SharedMaskCovector,
    ] {
        assert!(
            whir_execution
                .verify(
                    whir_handoff_binding,
                    &decoded_small_chain_proof.commitments,
                    &cross_epoch_point,
                    [
                        masked_pre_challenge_evaluation,
                        masked_main_evaluation,
                        mask_difference,
                    ],
                    &decoded_small_chain_proof.pre_challenge_whir_proof,
                    &decoded_small_chain_proof.main_whir_proof,
                    &verified_claim_batch,
                    &resident_matrices,
                    mutation,
                )
                .is_err()
        );
    }
    let mut mutated_pre_challenge_proof =
        decoded_small_chain_proof.pre_challenge_whir_proof.clone();
    mutated_pre_challenge_proof.base_case.masked_claim += CompactChallengeField::ONE;
    assert!(
        whir_execution
            .verify(
                whir_handoff_binding,
                &decoded_small_chain_proof.commitments,
                &cross_epoch_point,
                [
                    masked_pre_challenge_evaluation,
                    masked_main_evaluation,
                    mask_difference,
                ],
                &mutated_pre_challenge_proof,
                &decoded_small_chain_proof.main_whir_proof,
                &verified_claim_batch,
                &resident_matrices,
                SmallChainWhirVerificationMutation::None,
            )
            .is_err()
    );
    let mut mutated_main_proof = decoded_small_chain_proof.main_whir_proof.clone();
    mutated_main_proof.base_case.masked_claim += CompactChallengeField::ONE;
    assert!(
        whir_execution
            .verify(
                whir_handoff_binding,
                &decoded_small_chain_proof.commitments,
                &cross_epoch_point,
                [
                    masked_pre_challenge_evaluation,
                    masked_main_evaluation,
                    mask_difference,
                ],
                &decoded_small_chain_proof.pre_challenge_whir_proof,
                &mutated_main_proof,
                &verified_claim_batch,
                &resident_matrices,
                SmallChainWhirVerificationMutation::None,
            )
            .is_err()
    );
    let mut mutated_pre_challenge_opening =
        decoded_small_chain_proof.pre_challenge_whir_proof.clone();
    let mut mutated_main_opening = decoded_small_chain_proof.main_whir_proof.clone();
    mutated_pre_challenge_opening.evals[0] += CompactChallengeField::ONE;
    mutated_main_opening.evals[0] += CompactChallengeField::ONE;
    assert!(
        whir_execution
            .verify(
                whir_handoff_binding,
                &decoded_small_chain_proof.commitments,
                &cross_epoch_point,
                [
                    masked_pre_challenge_evaluation,
                    masked_main_evaluation,
                    mask_difference,
                ],
                &mutated_pre_challenge_opening,
                &mutated_main_opening,
                &verified_claim_batch,
                &resident_matrices,
                SmallChainWhirVerificationMutation::None,
            )
            .is_err()
    );
    let mut mutated_main_openings = decoded_small_chain_proof.main_whir_proof.clone();
    mutated_main_openings.evals[0] += CompactChallengeField::ONE;
    mutated_main_openings.evals[1] -= CompactChallengeField::ONE;
    assert!(
        whir_execution
            .verify(
                whir_handoff_binding,
                &decoded_small_chain_proof.commitments,
                &cross_epoch_point,
                [
                    masked_pre_challenge_evaluation,
                    masked_main_evaluation,
                    mask_difference,
                ],
                &decoded_small_chain_proof.pre_challenge_whir_proof,
                &mutated_main_openings,
                &verified_claim_batch,
                &resident_matrices,
                SmallChainWhirVerificationMutation::None,
            )
            .is_err()
    );
    let mut missing_pre_challenge_opening =
        decoded_small_chain_proof.pre_challenge_whir_proof.clone();
    missing_pre_challenge_opening.evals.clear();
    assert!(matches!(
        whir_execution.verify(
            whir_handoff_binding,
            &decoded_small_chain_proof.commitments,
            &cross_epoch_point,
            [
                masked_pre_challenge_evaluation,
                masked_main_evaluation,
                mask_difference,
            ],
            &missing_pre_challenge_opening,
            &decoded_small_chain_proof.main_whir_proof,
            &verified_claim_batch,
            &resident_matrices,
            SmallChainWhirVerificationMutation::None,
        ),
        Err(SmallChainWhirVerificationError::Whir(
            ZkVerifierError::EvalCountMismatch {
                expected: 1,
                actual: 0
            }
        ))
    ));

    let mut noncanonical_pre_challenge_proof =
        decoded_small_chain_proof.pre_challenge_whir_proof.clone();
    noncanonical_pre_challenge_proof.evals.clear();
    assert_eq!(
        encode_small_chain_canonical_proof(
            &whir_execution.pre_challenge_configuration,
            &whir_execution.main_configuration,
            whir_execution.inner_mask_shape,
            whir_execution.outer_mask_shape,
            whir_execution.shared_mask_shape,
            &decoded_small_chain_proof.canonical_cfw_proof_bytes,
            &decoded_small_chain_proof.commitments,
            &noncanonical_pre_challenge_proof,
            &decoded_small_chain_proof.main_whir_proof,
        )
        .err(),
        Some(SmallChainCanonicalTransportError::NonCanonicalProofShape)
    );

    let mut wrong_magic = canonical_small_chain_proof_bytes.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        decode_transported_small_chain(&wrong_magic).err(),
        Some(SmallChainCanonicalTransportError::WrongMagic)
    );
    let mut wrong_section_count = canonical_small_chain_proof_bytes.clone();
    wrong_section_count[size_of::<u64>()..size_of::<u64>() + size_of::<u16>()]
        .copy_from_slice(&7_u16.to_le_bytes());
    assert_eq!(
        decode_transported_small_chain(&wrong_section_count).err(),
        Some(SmallChainCanonicalTransportError::WrongSectionCount)
    );

    let outer_cfw_payload_range = small_chain_canonical_section_payload_range(
        &canonical_small_chain_proof_bytes,
        SmallChainCanonicalSection::OuterCfwProof,
    )
    .expect("the outer CFW payload range derives");
    let pre_challenge_source_payload_range = small_chain_canonical_section_payload_range(
        &canonical_small_chain_proof_bytes,
        SmallChainCanonicalSection::PreChallengeSourceRoot,
    )
    .expect("the pre-challenge source-root payload range derives");
    let inner_mask_payload_range = small_chain_canonical_section_payload_range(
        &canonical_small_chain_proof_bytes,
        SmallChainCanonicalSection::InnerMaskRoot,
    )
    .expect("the inner-mask-root payload range derives");

    let mut duplicate_section = canonical_small_chain_proof_bytes.clone();
    let outer_cfw_tag_range = outer_cfw_payload_range.start - size_of::<u16>() - size_of::<u32>()
        ..outer_cfw_payload_range.start - size_of::<u32>();
    let pre_challenge_source_tag_range =
        pre_challenge_source_payload_range.start - size_of::<u16>() - size_of::<u32>()
            ..pre_challenge_source_payload_range.start - size_of::<u32>();
    duplicate_section[pre_challenge_source_tag_range.clone()]
        .copy_from_slice(&canonical_small_chain_proof_bytes[outer_cfw_tag_range]);
    assert_eq!(
        decode_transported_small_chain(&duplicate_section).err(),
        Some(SmallChainCanonicalTransportError::WrongSectionOrder)
    );

    let pre_challenge_source_record_range =
        pre_challenge_source_payload_range.start - size_of::<u16>() - size_of::<u32>()
            ..pre_challenge_source_payload_range.end;
    let inner_mask_record_range = inner_mask_payload_range.start
        - size_of::<u16>()
        - size_of::<u32>()..inner_mask_payload_range.end;
    assert_eq!(
        pre_challenge_source_record_range.len(),
        inner_mask_record_range.len()
    );
    let mut reordered_sections = canonical_small_chain_proof_bytes.clone();
    reordered_sections[pre_challenge_source_record_range.clone()]
        .copy_from_slice(&canonical_small_chain_proof_bytes[inner_mask_record_range.clone()]);
    reordered_sections[inner_mask_record_range]
        .copy_from_slice(&canonical_small_chain_proof_bytes[pre_challenge_source_record_range]);
    assert_eq!(
        decode_transported_small_chain(&reordered_sections).err(),
        Some(SmallChainCanonicalTransportError::WrongSectionOrder)
    );

    let outer_cfw_declared_length_range =
        outer_cfw_payload_range.start - size_of::<u32>()..outer_cfw_payload_range.start;
    let mut empty_section = canonical_small_chain_proof_bytes.clone();
    empty_section[outer_cfw_declared_length_range.clone()].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        decode_transported_small_chain(&empty_section).err(),
        Some(SmallChainCanonicalTransportError::EmptySection)
    );
    let mut oversized_section = canonical_small_chain_proof_bytes.clone();
    oversized_section[outer_cfw_declared_length_range].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        decode_transported_small_chain(&oversized_section).err(),
        Some(SmallChainCanonicalTransportError::ByteLengthExceeded)
    );
    assert_eq!(
        decode_transported_small_chain(
            &canonical_small_chain_proof_bytes[..canonical_small_chain_proof_bytes.len() - 1]
        )
        .err(),
        Some(SmallChainCanonicalTransportError::Truncated)
    );
    let mut trailing_small_chain_bytes = canonical_small_chain_proof_bytes.clone();
    trailing_small_chain_bytes.push(0);
    assert_eq!(
        decode_transported_small_chain(&trailing_small_chain_bytes).err(),
        Some(SmallChainCanonicalTransportError::TrailingBytes)
    );

    let main_whir_payload_range = small_chain_canonical_section_payload_range(
        &canonical_small_chain_proof_bytes,
        SmallChainCanonicalSection::MainWhirProof,
    )
    .expect("the main WHIR payload range derives");
    let main_whir_payload =
        canonical_small_chain_proof_bytes[main_whir_payload_range.clone()].to_vec();
    let missing_main_whir_bytes = replace_small_chain_canonical_section_payload(
        &canonical_small_chain_proof_bytes,
        SmallChainCanonicalSection::MainWhirProof,
        &main_whir_payload[..main_whir_payload.len() - size_of::<u64>()],
    );
    assert_eq!(
        decode_transported_small_chain(&missing_main_whir_bytes).err(),
        Some(SmallChainCanonicalTransportError::Truncated)
    );
    let mut extended_main_whir_payload = main_whir_payload;
    extended_main_whir_payload.extend_from_slice(&0_u64.to_le_bytes());
    let unused_main_whir_bytes = replace_small_chain_canonical_section_payload(
        &canonical_small_chain_proof_bytes,
        SmallChainCanonicalSection::MainWhirProof,
        &extended_main_whir_payload,
    );
    assert_eq!(
        decode_transported_small_chain(&unused_main_whir_bytes).err(),
        Some(SmallChainCanonicalTransportError::TrailingBytes)
    );

    for section in [
        SmallChainCanonicalSection::PreChallengeSourceRoot,
        SmallChainCanonicalSection::InnerMaskRoot,
        SmallChainCanonicalSection::MainSourceRoot,
        SmallChainCanonicalSection::OuterMaskRoot,
        SmallChainCanonicalSection::SharedMaskRoot,
    ] {
        let payload_range = small_chain_canonical_section_payload_range(
            &canonical_small_chain_proof_bytes,
            section,
        )
        .expect("each external commitment has one canonical payload");
        let mut mutated_commitment = canonical_small_chain_proof_bytes.clone();
        mutated_commitment[payload_range.start] ^= 1;
        let decoded_mutated_commitment = decode_transported_small_chain(&mutated_commitment)
            .expect("a hash-root mutation remains structurally canonical");
        assert_eq!(
            verify_transported_small_chain(&decoded_mutated_commitment),
            Err(SmallChainFreshVerificationError::CommitmentBinding(
                SmallChainCommitmentBindingError::WrongBinding,
            ))
        );
    }

    let extension_field_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE * size_of::<u64>();
    for (section, evaluation_count) in [
        (SmallChainCanonicalSection::PreChallengeWhirProof, 1_usize),
        (SmallChainCanonicalSection::MainWhirProof, 2_usize),
    ] {
        let payload_range = small_chain_canonical_section_payload_range(
            &canonical_small_chain_proof_bytes,
            section,
        )
        .expect("each WHIR proof has one canonical payload");

        let mut noncanonical_field = canonical_small_chain_proof_bytes.clone();
        noncanonical_field[payload_range.start..payload_range.start + size_of::<u64>()]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        assert_eq!(
            decode_transported_small_chain(&noncanonical_field).err(),
            Some(SmallChainCanonicalTransportError::NonCanonicalField)
        );

        let mut mutated_revealed_value = canonical_small_chain_proof_bytes.clone();
        mutated_revealed_value[payload_range.start] ^= 1;
        let decoded_mutated_revealed_value =
            decode_transported_small_chain(&mutated_revealed_value)
                .expect("a canonical WHIR field mutation decodes");
        assert!(verify_transported_small_chain(&decoded_mutated_revealed_value).is_err());

        let initial_sumcheck_mask_root_start = payload_range.start
            + evaluation_count
                .checked_mul(extension_field_byte_length)
                .expect("the reduced evaluation prefix length fits usize");
        let mut mutated_internal_root = canonical_small_chain_proof_bytes.clone();
        mutated_internal_root[initial_sumcheck_mask_root_start] ^= 1;
        let decoded_mutated_internal_root = decode_transported_small_chain(&mutated_internal_root)
            .expect("a WHIR root mutation remains structurally canonical");
        assert!(verify_transported_small_chain(&decoded_mutated_internal_root).is_err());
    }

    let mut mutated_outer_cfw_section = canonical_small_chain_proof_bytes.clone();
    let outer_cfw_first_root_byte =
        outer_cfw_payload_range.start + PROOF_FIXED_HEADER_BYTE_LENGTH + size_of::<u32>();
    mutated_outer_cfw_section[outer_cfw_first_root_byte] ^= 1;
    let decoded_mutated_outer_cfw = decode_transported_small_chain(&mutated_outer_cfw_section)
        .expect("an embedded CFW root mutation remains structurally canonical");
    let mutated_outer_cfw_proof = decode_compact_proof_wire(
        &proof_wire_geometry,
        &decoded_mutated_outer_cfw.canonical_cfw_proof_bytes,
        decoded_mutated_outer_cfw.canonical_cfw_proof_bytes.len(),
    )
    .expect("the embedded CFW decoder accepts the mutated root bytes");
    assert!(
        verify_decoded_compact_response_opening(
            &built_responses[0].merkle_geometry,
            &proof_wire_geometry.responses()[0],
            &mutated_outer_cfw_proof.responses()[0],
            &decoded_mutated_outer_cfw.canonical_cfw_proof_bytes,
            &built_responses[0].query_leaf_ordinals,
        )
        .is_err()
    );
    assert!(verify_transported_small_chain(&decoded_mutated_outer_cfw).is_err());

    decoded_round_polynomials[0][0] += CompactChallengeField::ONE;
    let mutated_cfw_transcript = CompactCfwTranscript::new(
        decoded_auxiliary_target,
        decoded_round_polynomials,
        resident_finish.outer_evaluations().to_vec(),
        resident_finish.final_values(),
    );
    assert!(
        verify_compact_cfw_transcript(
            &resident_matrices,
            &fresh_public_input,
            &mutated_cfw_transcript,
            constraint_combining_challenge,
            &equality_point,
            &round_challenges,
            joint_constraint_challenge,
        )
        .is_err()
    );

    assert!(
        decode_compact_proof_wire(
            &proof_wire_geometry,
            &canonical_proof_bytes[..canonical_proof_bytes.len() - 1],
            canonical_proof_bytes.len() - 1,
        )
        .is_err()
    );
    let mut trailing_proof_bytes = canonical_proof_bytes.clone();
    trailing_proof_bytes.push(0);
    assert!(
        decode_compact_proof_wire(
            &proof_wire_geometry,
            &trailing_proof_bytes,
            trailing_proof_bytes.len(),
        )
        .is_err()
    );
    let mut wrong_public_input_binding = canonical_public_input_bytes.clone();
    wrong_public_input_binding[10] ^= 1;
    assert!(
        decode_compact_public_input(
            public_input_wire_geometry,
            public_input_bindings,
            &wrong_public_input_binding,
        )
        .is_err()
    );
}
