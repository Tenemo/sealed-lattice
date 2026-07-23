//! Deterministic non-secret sumcheck-class arm for the manual backend bakeoff.
//!
//! The fixed RNG seed is intentional measurement scaffolding. It is not a
//! cryptographically secure hiding source and this module is compiled only for
//! native tests behind the manual `proof-backend-bakeoff` feature.
//!
//! The query ledger uses the theorem-backed unique-decoding regime and a
//! classical ideal-XOF Fiat-Shamir bound. Plonky3 does not provide a complete
//! theorem for the masking/code-switch composition, the adversarial grinding
//! work model, the `ell_zk` hiding choice, or the outer relation/PCS composition,
//! and this module makes no QROM claim. This arm is performance-only and must
//! never receive a secret witness.

use num_bigint::BigUint;
use p3_challenger::{CanObserve, FieldChallenger, HashChallenger, SerializingChallenger64};
use p3_commit::{Mmcs, MultilinearPcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{PrimeCharacteristicRing, PrimeField64, extension::BinomialExtensionField};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    generic_degree::{GenericDegreeProof, RoundProver},
    zk::ZkSumcheckData,
};
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use p3_whir::pcs::zk::{HidingWhirPcs, ZkParameters, ZkWhirConfig};
use p3_whir::{
    BaseCaseZkProof, BlindedMask, DomainSeparator, FoldingFactor, MaskOpeningPair,
    ProtocolParameters, QueryOpening, SecurityAssumption, ZkRoundProof, ZkWhirProof,
};
use rand::{SeedableRng, rngs::SmallRng};
use serde::{
    Deserialize, Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct, SerializeStructVariant},
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::proof_backend_bakeoff::{
    ProofBackendBakeoffArmOutput, ProofBackendBakeoffFixture, ProofBackendBakeoffResult,
    canonical_frozen_sumcheck_public_statement, frozen_fixture, recompute_frozen_input_identity,
    validated_frozen_sumcheck_public_statement,
};
use super::prover::canonical_proof_object_header_bytes;

const RELATION_VARIABLE_COUNT: usize = 14;
const COLUMN_SELECTOR_VARIABLE_COUNT: usize = 3;
const COMMITTED_VARIABLE_COUNT: usize = RELATION_VARIABLE_COUNT + COLUMN_SELECTOR_VARIABLE_COUNT;
const RELATION_ROW_COUNT: usize = 1 << RELATION_VARIABLE_COUNT;
const RELATION_COLUMN_COUNT: usize = 1 << COLUMN_SELECTOR_VARIABLE_COUNT;
const CIPHERTEXT_MODULUS: u64 = 1_953_759_233;
const MATERIAL_RADIX: u64 = 129_140_163;
const MATERIAL_HIGH_DIGIT_MAXIMUM: u64 = 15;
const EXTERNAL_HIDING_SECURITY_BIT_TARGET: usize = 128;
const CLASSICAL_RANDOM_ORACLE_QUERY_BOUND_EXPONENT: usize = 128;
const FIAT_SHAMIR_XOF_OUTPUT_BIT_LENGTH: usize = 512;
const INTERNAL_BRANCH_SECURITY_PARAMETER: usize = 260;
const CONSERVATIVE_RBR_AGGREGATE_SOUNDNESS_BIT_BOUND: usize = 258;
const GRINDING_BIT_CEILING: usize = 20;
// Separated 128-bit hiding heuristic for this non-secret performance arm only.
const MASK_MESSAGE_LENGTH: usize = 46;
const MASK_LOG_INVERSE_RATE: usize = 5;
const STARTING_LOG_INVERSE_RATE: usize = 1;
const CONSTANT_FOLDING_FACTOR: usize = 4;
const ORDINARY_QUERY_BRANCH_COUNT: usize = 3;
const MASK_BRANCH_COUNT: usize = 6;
const PROXIMITY_BRANCH_COUNT: usize = 3;
const MASK_UNION_SECURITY_PARAMETER: usize = 261;
const UNIQUE_DECODING_ALGEBRAIC_SECURITY_PARAMETER: usize = 301;
const OUTER_RELATION_SECURITY_PARAMETER: usize = 309;
const OUTER_RELATION_FAILURE_NUMERATOR: usize = 43;
const UNIQUE_DECODING_FOLD_FAILURE_NUMERATORS: [u64; PROXIMITY_BRANCH_COUNT] =
    [262_146, 131_074, 65_538];
const UNIQUE_DECODING_QUERY_COMBINATION_FAILURE_NUMERATOR: u64 = 1_686;
const UNIQUE_DECODING_FINAL_FOLDING_FAILURE_NUMERATOR: u64 = 2;
const UNIQUE_DECODING_AGGREGATE_ALGEBRAIC_FAILURE_NUMERATOR: u64 = 460_489;
const EXPECTED_FOLDING_SCHEDULE: [usize; 3] = [4, 4, 4];
const EXPECTED_ORACLE_RANDOMNESS_LENGTHS: [usize; 3] = [579, 264, 243];
const EXPECTED_ROUND_QUERY_COUNTS: [usize; 2] = [579, 264];
const EXPECTED_ROUND_POW_BITS: [usize; 2] = [20, 20];
const EXPECTED_ROUND_VARIABLE_COUNTS: [usize; 2] = [13, 9];
const EXPECTED_ROUND_LOG_INVERSE_RATES: [usize; 2] = [4, 7];
const EXPECTED_ROUND_DOMAIN_SIZES: [usize; 2] = [262_144, 131_072];
const EXPECTED_ROUND_QUERY_VALUE_LENGTHS: [usize; 2] = [16, 16];
const EXPECTED_ROUND_QUERY_PATH_LENGTHS: [usize; 2] = [14, 13];
const EXPECTED_FINAL_QUERY_COUNT: usize = 243;
const EXPECTED_FINAL_POW_BITS: usize = 20;
const EXPECTED_FINAL_SUMCHECK_ROUND_COUNT: usize = 5;
const EXPECTED_MASK_QUERY_COUNT: usize = 276;
const EXPECTED_SOURCE_QUERY_VALUE_LENGTH: usize = 16;
const EXPECTED_SOURCE_QUERY_PATH_LENGTH: usize = 12;
const EXPECTED_FRESH_MAIN_QUERY_VALUE_LENGTH: usize = 1;
const EXPECTED_FRESH_MAIN_QUERY_PATH_LENGTH: usize = 12;
const EXPECTED_MASK_GROUP_WIDTHS: [usize; 5] = [4, 1, 4, 1, 4];
const EXPECTED_MASK_GROUP_PATH_LENGTHS: [usize; 5] = [14, 15, 14, 15, 14];
const EXPECTED_BLINDED_MASK_MESSAGE_LENGTHS: [usize; 14] = [
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    EXPECTED_ORACLE_RANDOMNESS_LENGTHS[0],
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    EXPECTED_ORACLE_RANDOMNESS_LENGTHS[1],
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
    MASK_MESSAGE_LENGTH,
];
const CLASSICAL_MERKLE_COLLISION_SECURITY_BITS: usize = 256;
const GENERIC_QUANTUM_COLLISION_QUERY_EXPONENT_DENOMINATOR: usize = 3;
const MERKLE_DIGEST_WORD_LENGTH: usize = 8;
const MERKLE_DIGEST_BYTE_LENGTH: usize = MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>();
const CHALLENGER_OUTPUT_BYTE_LENGTH: usize = 64;
const MERKLE_TREE_ARITY: usize = 2;
const MERKLE_MINIMUM_HEIGHT: usize = 0;
const OUTER_SUMCHECK_DEGREE: usize = 2;
const SYNTHETIC_HIDING_RANDOMNESS_SEED: u64 = 0x534c_5748_4952_0001;
const CANONICAL_ARTIFACT_WIRE_SCHEMA_VERSION: u8 = 1;
const MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH: usize = 10;
const MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH: usize =
    5 * MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH;
const MAXIMUM_MERKLE_DIGEST_BYTE_LENGTH: usize =
    MERKLE_DIGEST_WORD_LENGTH * MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH;
const MAXIMUM_SINGLE_DIGEST_CAP_BYTE_LENGTH: usize =
    maximum_vector_byte_length(1, MAXIMUM_MERKLE_DIGEST_BYTE_LENGTH);
const QUERY_OPENING_BASE_TAG: u32 = 0;
const QUERY_OPENING_EXTENSION_TAG: u32 = 1;

const fn postcard_varint_byte_length(mut value: usize) -> usize {
    let mut byte_length = 1;
    while value >= 128 {
        value >>= 7;
        byte_length += 1;
    }
    byte_length
}

const fn maximum_vector_byte_length(element_count: usize, element_byte_length: usize) -> usize {
    postcard_varint_byte_length(element_count) + element_count * element_byte_length
}

const fn maximum_query_opening_byte_length(
    value_count: usize,
    value_byte_length: usize,
    merkle_path_length: usize,
) -> usize {
    postcard_varint_byte_length(QUERY_OPENING_EXTENSION_TAG as usize)
        + maximum_vector_byte_length(value_count, value_byte_length)
        + maximum_vector_byte_length(merkle_path_length, MAXIMUM_MERKLE_DIGEST_BYTE_LENGTH)
}

const fn maximum_blinded_masks_byte_length() -> usize {
    let mut byte_length = postcard_varint_byte_length(EXPECTED_BLINDED_MASK_MESSAGE_LENGTHS.len());
    let mut mask_index = 0;
    while mask_index < EXPECTED_BLINDED_MASK_MESSAGE_LENGTHS.len() {
        byte_length += maximum_vector_byte_length(
            EXPECTED_BLINDED_MASK_MESSAGE_LENGTHS[mask_index],
            MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
        );
        byte_length += maximum_vector_byte_length(
            EXPECTED_MASK_QUERY_COUNT,
            MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
        );
        mask_index += 1;
    }
    byte_length
}

const fn maximum_mask_query_groups_byte_length() -> usize {
    let mut byte_length = postcard_varint_byte_length(EXPECTED_MASK_GROUP_WIDTHS.len());
    let mut group_index = 0;
    while group_index < EXPECTED_MASK_GROUP_WIDTHS.len() {
        let query_byte_length = maximum_query_opening_byte_length(
            EXPECTED_MASK_GROUP_WIDTHS[group_index],
            MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
            EXPECTED_MASK_GROUP_PATH_LENGTHS[group_index],
        );
        byte_length += maximum_vector_byte_length(EXPECTED_MASK_QUERY_COUNT, 2 * query_byte_length);
        group_index += 1;
    }
    byte_length
}

const MAXIMUM_OUTER_SUMCHECK_PROOF_BYTE_LENGTH: usize = MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH
    + maximum_vector_byte_length(
        RELATION_VARIABLE_COUNT,
        maximum_vector_byte_length(
            OUTER_SUMCHECK_DEGREE,
            MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
        ),
    )
    + maximum_vector_byte_length(0, MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH);
const MAXIMUM_MASKED_SUMCHECK_BYTE_LENGTH: usize = MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH
    + postcard_varint_byte_length(MASK_MESSAGE_LENGTH)
    + maximum_vector_byte_length(
        CONSTANT_FOLDING_FACTOR,
        maximum_vector_byte_length(
            MASK_MESSAGE_LENGTH - 1,
            MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
        ),
    )
    + maximum_vector_byte_length(0, MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH);
const MAXIMUM_FIRST_ROUND_QUERY_BYTE_LENGTH: usize = maximum_query_opening_byte_length(
    EXPECTED_ROUND_QUERY_VALUE_LENGTHS[0],
    MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH,
    EXPECTED_ROUND_QUERY_PATH_LENGTHS[0],
);
const MAXIMUM_SECOND_ROUND_QUERY_BYTE_LENGTH: usize = maximum_query_opening_byte_length(
    EXPECTED_ROUND_QUERY_VALUE_LENGTHS[1],
    MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
    EXPECTED_ROUND_QUERY_PATH_LENGTHS[1],
);
const MAXIMUM_FIRST_ROUND_BYTE_LENGTH: usize = 2 * MAXIMUM_SINGLE_DIGEST_CAP_BYTE_LENGTH
    + maximum_vector_byte_length(0, MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH)
    + MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH
    + maximum_vector_byte_length(
        EXPECTED_ROUND_QUERY_COUNTS[0],
        MAXIMUM_FIRST_ROUND_QUERY_BYTE_LENGTH,
    );
const MAXIMUM_SECOND_ROUND_BYTE_LENGTH: usize = 2 * MAXIMUM_SINGLE_DIGEST_CAP_BYTE_LENGTH
    + maximum_vector_byte_length(0, MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH)
    + MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH
    + maximum_vector_byte_length(
        EXPECTED_ROUND_QUERY_COUNTS[1],
        MAXIMUM_SECOND_ROUND_QUERY_BYTE_LENGTH,
    );
const MAXIMUM_BLINDED_MASKS_BYTE_LENGTH: usize = maximum_blinded_masks_byte_length();
const MAXIMUM_SOURCE_QUERY_BYTE_LENGTH: usize = maximum_query_opening_byte_length(
    EXPECTED_SOURCE_QUERY_VALUE_LENGTH,
    MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
    EXPECTED_SOURCE_QUERY_PATH_LENGTH,
);
const MAXIMUM_FRESH_MAIN_QUERY_BYTE_LENGTH: usize = maximum_query_opening_byte_length(
    EXPECTED_FRESH_MAIN_QUERY_VALUE_LENGTH,
    MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
    EXPECTED_FRESH_MAIN_QUERY_PATH_LENGTH,
);
const MAXIMUM_MASK_QUERY_GROUPS_BYTE_LENGTH: usize = maximum_mask_query_groups_byte_length();
const MAXIMUM_BASE_CASE_BYTE_LENGTH: usize = MAXIMUM_SINGLE_DIGEST_CAP_BYTE_LENGTH
    + maximum_vector_byte_length(
        EXPECTED_MASK_GROUP_WIDTHS.len(),
        MAXIMUM_SINGLE_DIGEST_CAP_BYTE_LENGTH,
    )
    + MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH
    + maximum_vector_byte_length(32, MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH)
    + maximum_vector_byte_length(
        EXPECTED_FINAL_QUERY_COUNT,
        MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
    )
    + MAXIMUM_BLINDED_MASKS_BYTE_LENGTH
    + MAXIMUM_BASE_FIELD_ELEMENT_BYTE_LENGTH
    + maximum_vector_byte_length(EXPECTED_FINAL_QUERY_COUNT, MAXIMUM_SOURCE_QUERY_BYTE_LENGTH)
    + maximum_vector_byte_length(
        EXPECTED_FINAL_QUERY_COUNT,
        MAXIMUM_FRESH_MAIN_QUERY_BYTE_LENGTH,
    )
    + MAXIMUM_MASK_QUERY_GROUPS_BYTE_LENGTH;
const MAXIMUM_OPENING_PROOF_BYTE_LENGTH: usize = maximum_vector_byte_length(
    RELATION_COLUMN_COUNT,
    MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
) + maximum_vector_byte_length(
    EXPECTED_FOLDING_SCHEDULE.len(),
    MAXIMUM_MASKED_SUMCHECK_BYTE_LENGTH,
) + maximum_vector_byte_length(
    EXPECTED_FOLDING_SCHEDULE.len(),
    MAXIMUM_SINGLE_DIGEST_CAP_BYTE_LENGTH,
) + postcard_varint_byte_length(
    EXPECTED_ROUND_QUERY_COUNTS.len(),
) + MAXIMUM_FIRST_ROUND_BYTE_LENGTH
    + MAXIMUM_SECOND_ROUND_BYTE_LENGTH
    + MAXIMUM_BASE_CASE_BYTE_LENGTH;
// Exact maximum for schema byte + outer sumcheck + the checked fixed-profile
// opening proof. The canonical proof-object header is outside this body cap.
const MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH: usize =
    size_of::<u8>() + MAXIMUM_OUTER_SUMCHECK_PROOF_BYTE_LENGTH + MAXIMUM_OPENING_PROOF_BYTE_LENGTH;
const _: () = assert!(
    EXPECTED_FOLDING_SCHEDULE[0] == CONSTANT_FOLDING_FACTOR
        && EXPECTED_FOLDING_SCHEDULE[1] == CONSTANT_FOLDING_FACTOR
        && EXPECTED_FOLDING_SCHEDULE[2] == CONSTANT_FOLDING_FACTOR
);
const _: () = assert!(
    EXPECTED_MASK_GROUP_WIDTHS[0] == EXPECTED_FOLDING_SCHEDULE[0]
        && EXPECTED_MASK_GROUP_WIDTHS[1] == 1
        && EXPECTED_MASK_GROUP_WIDTHS[2] == EXPECTED_FOLDING_SCHEDULE[1]
        && EXPECTED_MASK_GROUP_WIDTHS[3] == 1
        && EXPECTED_MASK_GROUP_WIDTHS[4] == EXPECTED_FOLDING_SCHEDULE[2]
        && EXPECTED_MASK_GROUP_WIDTHS.len() == EXPECTED_MASK_GROUP_PATH_LENGTHS.len()
        && EXPECTED_ROUND_QUERY_COUNTS.len() == EXPECTED_ROUND_QUERY_VALUE_LENGTHS.len()
        && EXPECTED_ROUND_QUERY_COUNTS.len() == EXPECTED_ROUND_QUERY_PATH_LENGTHS.len()
);
const _: () = assert!(MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH == 5_785_122);

type BaseField = Goldilocks;
type ChallengeField = BinomialExtensionField<BaseField, 5>;
type InnerChallenger = HashChallenger<u8, DomainSeparatedShake256, CHALLENGER_OUTPUT_BYTE_LENGTH>;
type Challenger = SerializingChallenger64<BaseField, InnerChallenger>;
type LeafHasher = SerializingHasher<DomainSeparatedShake256>;
type NodeCompressor =
    CompressionFunctionFromHasher<DomainSeparatedShake256, 2, MERKLE_DIGEST_WORD_LENGTH>;
type CommitmentScheme =
    MerkleTreeMmcs<BaseField, u64, LeafHasher, NodeCompressor, 2, MERKLE_DIGEST_WORD_LENGTH>;
type DiscreteFourierTransform = Radix2DFTSmallBatch<BaseField>;
type SumcheckClassConfiguration = ZkWhirConfig<ChallengeField, BaseField, Challenger>;
type SumcheckClassPcs = HidingWhirPcs<
    ChallengeField,
    BaseField,
    DiscreteFourierTransform,
    CommitmentScheme,
    Challenger,
    SmallRng,
>;
type SumcheckClassCommitment =
    <SumcheckClassPcs as MultilinearPcs<ChallengeField, Challenger>>::Commitment;
type SumcheckClassOpeningProof =
    <SumcheckClassPcs as MultilinearPcs<ChallengeField, Challenger>>::Proof;
type SumcheckClassMerkleProof = <CommitmentScheme as Mmcs<BaseField>>::Proof;
type SumcheckClassQueryOpening = QueryOpening<BaseField, ChallengeField, SumcheckClassMerkleProof>;
type SumcheckClassRoundProof = ZkRoundProof<BaseField, ChallengeField, CommitmentScheme>;
type SumcheckClassBaseCaseProof = BaseCaseZkProof<BaseField, ChallengeField, CommitmentScheme>;
type SumcheckClassMaskOpeningPair = MaskOpeningPair<BaseField, ChallengeField, CommitmentScheme>;

#[derive(Clone, Copy, Debug)]
struct DomainSeparatedShake256 {
    domain: &'static [u8],
}

impl DomainSeparatedShake256 {
    fn initialized_state(self) -> Shake256 {
        let mut state = Shake256::default();
        state.update(b"sealed-lattice/proof-backend-bakeoff/shake256/v1");
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

    fn hash_iter_slices<'input, Input>(&self, input: Input) -> [u8; MERKLE_DIGEST_BYTE_LENGTH]
    where
        Input: IntoIterator<Item = &'input [u8]>,
    {
        let mut state = self.initialized_state();
        for bytes in input {
            state.update(bytes);
        }
        Self::finish(state)
    }
}

impl CryptographicHasher<u64, [u64; MERKLE_DIGEST_WORD_LENGTH]> for DomainSeparatedShake256 {
    fn hash_iter<Input>(&self, input: Input) -> [u64; MERKLE_DIGEST_WORD_LENGTH]
    where
        Input: IntoIterator<Item = u64>,
    {
        let mut state = self.initialized_state();
        for word in input {
            state.update(&word.to_le_bytes());
        }
        let bytes = Self::finish(state);
        core::array::from_fn(|word_index| {
            let first_byte = word_index * size_of::<u64>();
            u64::from_le_bytes(
                bytes[first_byte..first_byte + size_of::<u64>()]
                    .try_into()
                    .expect("one SHAKE256 digest word"),
            )
        })
    }
}

#[derive(Clone)]
struct SumcheckClassArtifact {
    outer_sumcheck_proof: GenericDegreeProof<BaseField, ChallengeField>,
    opening_proof: SumcheckClassOpeningProof,
}

struct SumcheckClassArtifactWireReference<'artifact> {
    artifact: &'artifact SumcheckClassArtifact,
}

impl Serialize for SumcheckClassArtifactWireReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let mut artifact = serializer.serialize_struct("SumcheckClassArtifactWire", 3)?;
        artifact.serialize_field("schema_version", &CANONICAL_ARTIFACT_WIRE_SCHEMA_VERSION)?;
        artifact.serialize_field("outer_sumcheck_proof", &self.artifact.outer_sumcheck_proof)?;
        artifact.serialize_field(
            "opening_proof",
            &SumcheckClassOpeningProofWireReference {
                opening_proof: &self.artifact.opening_proof,
            },
        )?;
        artifact.end()
    }
}

#[derive(Deserialize)]
struct SumcheckClassArtifactWire {
    schema_version: u8,
    outer_sumcheck_proof: GenericDegreeProof<BaseField, ChallengeField>,
    opening_proof: SumcheckClassOpeningProofWire,
}

struct SumcheckClassOpeningProofWireReference<'proof> {
    opening_proof: &'proof SumcheckClassOpeningProof,
}

impl Serialize for SumcheckClassOpeningProofWireReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let proof = self.opening_proof;
        let mut opening_proof = serializer.serialize_struct("SumcheckClassOpeningProofWire", 5)?;
        opening_proof.serialize_field("evals", &proof.evals)?;
        opening_proof.serialize_field("sumchecks", &proof.sumchecks)?;
        opening_proof.serialize_field(
            "sumcheck_mask_commitments",
            &proof.sumcheck_mask_commitments,
        )?;
        opening_proof.serialize_field(
            "rounds",
            &SumcheckClassRoundProofSequenceReference {
                rounds: &proof.rounds,
            },
        )?;
        opening_proof.serialize_field(
            "base_case",
            &SumcheckClassBaseCaseProofWireReference {
                base_case: &proof.base_case,
            },
        )?;
        opening_proof.end()
    }
}

#[derive(Deserialize)]
struct SumcheckClassOpeningProofWire {
    evals: Vec<ChallengeField>,
    sumchecks: Vec<ZkSumcheckData<BaseField, ChallengeField>>,
    sumcheck_mask_commitments: Vec<SumcheckClassCommitment>,
    rounds: Vec<SumcheckClassRoundProofWire>,
    base_case: SumcheckClassBaseCaseProofWire,
}

struct SumcheckClassRoundProofSequenceReference<'proof> {
    rounds: &'proof [SumcheckClassRoundProof],
}

impl Serialize for SumcheckClassRoundProofSequenceReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let mut rounds = serializer.serialize_seq(Some(self.rounds.len()))?;
        for round in self.rounds {
            rounds.serialize_element(&SumcheckClassRoundProofWireReference { round })?;
        }
        rounds.end()
    }
}

struct SumcheckClassRoundProofWireReference<'proof> {
    round: &'proof SumcheckClassRoundProof,
}

impl Serialize for SumcheckClassRoundProofWireReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let round = self.round;
        let mut round_proof = serializer.serialize_struct("SumcheckClassRoundProofWire", 5)?;
        round_proof.serialize_field("commitment", &round.commitment)?;
        round_proof.serialize_field("mask_commitment", &round.mask_commitment)?;
        round_proof.serialize_field("ood_answers", &round.ood_answers)?;
        round_proof.serialize_field("pow_witness", &round.pow_witness)?;
        round_proof.serialize_field(
            "queries",
            &SumcheckClassQueryOpeningSequenceReference {
                queries: &round.queries,
            },
        )?;
        round_proof.end()
    }
}

#[derive(Deserialize)]
struct SumcheckClassRoundProofWire {
    commitment: SumcheckClassCommitment,
    mask_commitment: SumcheckClassCommitment,
    ood_answers: Vec<ChallengeField>,
    pow_witness: BaseField,
    queries: Vec<SumcheckClassQueryOpeningWire>,
}

struct SumcheckClassBaseCaseProofWireReference<'proof> {
    base_case: &'proof SumcheckClassBaseCaseProof,
}

impl Serialize for SumcheckClassBaseCaseProofWireReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let proof = self.base_case;
        let mut base_case = serializer.serialize_struct("SumcheckClassBaseCaseProofWire", 10)?;
        base_case.serialize_field("fresh_main_commitment", &proof.fresh_main_commitment)?;
        base_case.serialize_field("fresh_mask_commitments", &proof.fresh_mask_commitments)?;
        base_case.serialize_field("masked_claim", &proof.masked_claim)?;
        base_case.serialize_field("blinded_message", &proof.blinded_message)?;
        base_case.serialize_field("blinded_randomness", &proof.blinded_randomness)?;
        base_case.serialize_field("blinded_masks", &proof.blinded_masks)?;
        base_case.serialize_field("pow_witness", &proof.pow_witness)?;
        base_case.serialize_field(
            "source_queries",
            &SumcheckClassQueryOpeningSequenceReference {
                queries: &proof.source_queries,
            },
        )?;
        base_case.serialize_field(
            "fresh_main_queries",
            &SumcheckClassQueryOpeningSequenceReference {
                queries: &proof.fresh_main_queries,
            },
        )?;
        base_case.serialize_field(
            "mask_queries",
            &SumcheckClassMaskQueryGroupSequenceReference {
                mask_query_groups: &proof.mask_queries,
            },
        )?;
        base_case.end()
    }
}

#[derive(Deserialize)]
struct SumcheckClassBaseCaseProofWire {
    fresh_main_commitment: SumcheckClassCommitment,
    fresh_mask_commitments: Vec<SumcheckClassCommitment>,
    masked_claim: ChallengeField,
    blinded_message: Vec<ChallengeField>,
    blinded_randomness: Vec<ChallengeField>,
    blinded_masks: Vec<BlindedMask<ChallengeField>>,
    pow_witness: BaseField,
    source_queries: Vec<SumcheckClassQueryOpeningWire>,
    fresh_main_queries: Vec<SumcheckClassQueryOpeningWire>,
    mask_queries: Vec<Vec<SumcheckClassMaskOpeningPairWire>>,
}

struct SumcheckClassQueryOpeningSequenceReference<'proof> {
    queries: &'proof [SumcheckClassQueryOpening],
}

impl Serialize for SumcheckClassQueryOpeningSequenceReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let mut queries = serializer.serialize_seq(Some(self.queries.len()))?;
        for query in self.queries {
            queries.serialize_element(&SumcheckClassQueryOpeningWireReference { query })?;
        }
        queries.end()
    }
}

struct SumcheckClassQueryOpeningWireReference<'proof> {
    query: &'proof SumcheckClassQueryOpening,
}

impl Serialize for SumcheckClassQueryOpeningWireReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        match self.query {
            QueryOpening::Base { values, proof } => {
                let mut opening = serializer.serialize_struct_variant(
                    "SumcheckClassQueryOpeningWire",
                    QUERY_OPENING_BASE_TAG,
                    "Base",
                    2,
                )?;
                opening.serialize_field("values", values)?;
                opening.serialize_field("proof", proof)?;
                opening.end()
            }
            QueryOpening::Extension { values, proof } => {
                let mut opening = serializer.serialize_struct_variant(
                    "SumcheckClassQueryOpeningWire",
                    QUERY_OPENING_EXTENSION_TAG,
                    "Extension",
                    2,
                )?;
                opening.serialize_field("values", values)?;
                opening.serialize_field("proof", proof)?;
                opening.end()
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[repr(u8)]
enum SumcheckClassQueryOpeningWire {
    Base {
        values: Vec<BaseField>,
        proof: SumcheckClassMerkleProof,
    } = 0,
    Extension {
        values: Vec<ChallengeField>,
        proof: SumcheckClassMerkleProof,
    } = 1,
}

struct SumcheckClassMaskQueryGroupSequenceReference<'proof> {
    mask_query_groups: &'proof [Vec<SumcheckClassMaskOpeningPair>],
}

impl Serialize for SumcheckClassMaskQueryGroupSequenceReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let mut groups = serializer.serialize_seq(Some(self.mask_query_groups.len()))?;
        for group in self.mask_query_groups {
            groups.serialize_element(&SumcheckClassMaskOpeningPairSequenceReference {
                opening_pairs: group,
            })?;
        }
        groups.end()
    }
}

struct SumcheckClassMaskOpeningPairSequenceReference<'proof> {
    opening_pairs: &'proof [SumcheckClassMaskOpeningPair],
}

impl Serialize for SumcheckClassMaskOpeningPairSequenceReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let mut opening_pairs = serializer.serialize_seq(Some(self.opening_pairs.len()))?;
        for opening_pair in self.opening_pairs {
            opening_pairs
                .serialize_element(&SumcheckClassMaskOpeningPairWireReference { opening_pair })?;
        }
        opening_pairs.end()
    }
}

struct SumcheckClassMaskOpeningPairWireReference<'proof> {
    opening_pair: &'proof SumcheckClassMaskOpeningPair,
}

impl Serialize for SumcheckClassMaskOpeningPairWireReference<'_> {
    fn serialize<WireSerializer>(
        &self,
        serializer: WireSerializer,
    ) -> Result<WireSerializer::Ok, WireSerializer::Error>
    where
        WireSerializer: Serializer,
    {
        let mut opening_pair =
            serializer.serialize_struct("SumcheckClassMaskOpeningPairWire", 2)?;
        opening_pair.serialize_field(
            "carried",
            &SumcheckClassQueryOpeningWireReference {
                query: &self.opening_pair.carried,
            },
        )?;
        opening_pair.serialize_field(
            "fresh",
            &SumcheckClassQueryOpeningWireReference {
                query: &self.opening_pair.fresh,
            },
        )?;
        opening_pair.end()
    }
}

#[derive(Deserialize)]
struct SumcheckClassMaskOpeningPairWire {
    carried: SumcheckClassQueryOpeningWire,
    fresh: SumcheckClassQueryOpeningWire,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SumcheckClassQueryOpeningKind {
    Base,
    Extension,
}

impl SumcheckClassQueryOpeningKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Extension => "extension",
        }
    }
}

impl SumcheckClassQueryOpeningWire {
    const fn kind(&self) -> SumcheckClassQueryOpeningKind {
        match self {
            Self::Base { .. } => SumcheckClassQueryOpeningKind::Base,
            Self::Extension { .. } => SumcheckClassQueryOpeningKind::Extension,
        }
    }

    fn into_query_opening(self) -> SumcheckClassQueryOpening {
        match self {
            Self::Base { values, proof } => QueryOpening::Base { values, proof },
            Self::Extension { values, proof } => QueryOpening::Extension { values, proof },
        }
    }
}

impl SumcheckClassRoundProofWire {
    fn into_round_proof(self) -> SumcheckClassRoundProof {
        SumcheckClassRoundProof {
            commitment: self.commitment,
            mask_commitment: self.mask_commitment,
            ood_answers: self.ood_answers,
            pow_witness: self.pow_witness,
            queries: self
                .queries
                .into_iter()
                .map(SumcheckClassQueryOpeningWire::into_query_opening)
                .collect(),
        }
    }
}

impl SumcheckClassMaskOpeningPairWire {
    fn into_mask_opening_pair(self) -> SumcheckClassMaskOpeningPair {
        SumcheckClassMaskOpeningPair {
            carried: self.carried.into_query_opening(),
            fresh: self.fresh.into_query_opening(),
        }
    }
}

impl SumcheckClassBaseCaseProofWire {
    fn into_base_case_proof(self) -> SumcheckClassBaseCaseProof {
        SumcheckClassBaseCaseProof {
            fresh_main_commitment: self.fresh_main_commitment,
            fresh_mask_commitments: self.fresh_mask_commitments,
            masked_claim: self.masked_claim,
            blinded_message: self.blinded_message,
            blinded_randomness: self.blinded_randomness,
            blinded_masks: self.blinded_masks,
            pow_witness: self.pow_witness,
            source_queries: self
                .source_queries
                .into_iter()
                .map(SumcheckClassQueryOpeningWire::into_query_opening)
                .collect(),
            fresh_main_queries: self
                .fresh_main_queries
                .into_iter()
                .map(SumcheckClassQueryOpeningWire::into_query_opening)
                .collect(),
            mask_queries: self
                .mask_queries
                .into_iter()
                .map(|group| {
                    group
                        .into_iter()
                        .map(SumcheckClassMaskOpeningPairWire::into_mask_opening_pair)
                        .collect()
                })
                .collect(),
        }
    }
}

impl SumcheckClassOpeningProofWire {
    fn into_opening_proof(self) -> SumcheckClassOpeningProof {
        ZkWhirProof {
            evals: self.evals,
            sumchecks: self.sumchecks,
            sumcheck_mask_commitments: self.sumcheck_mask_commitments,
            rounds: self
                .rounds
                .into_iter()
                .map(SumcheckClassRoundProofWire::into_round_proof)
                .collect(),
            base_case: self.base_case.into_base_case_proof(),
        }
    }
}

impl SumcheckClassArtifactWire {
    fn into_artifact(self) -> SumcheckClassArtifact {
        SumcheckClassArtifact {
            outer_sumcheck_proof: self.outer_sumcheck_proof,
            opening_proof: self.opening_proof.into_opening_proof(),
        }
    }

    fn validate_exact_shape(&self) -> ProofBackendBakeoffResult<()> {
        if self.schema_version != CANONICAL_ARTIFACT_WIRE_SCHEMA_VERSION {
            return Err(format!(
                "sumcheck-class artifact wire schema version is {}, expected {}",
                self.schema_version, CANONICAL_ARTIFACT_WIRE_SCHEMA_VERSION
            ));
        }

        require_exact_wire_length(
            "outer sumcheck rounds",
            self.outer_sumcheck_proof.round_polys.len(),
            RELATION_VARIABLE_COUNT,
        )?;
        for (round_index, round_polynomial) in
            self.outer_sumcheck_proof.round_polys.iter().enumerate()
        {
            require_exact_wire_length(
                &format!("outer sumcheck round {round_index} evaluations"),
                round_polynomial.len(),
                OUTER_SUMCHECK_DEGREE,
            )?;
        }
        require_exact_wire_length(
            "outer sumcheck proof-of-work witnesses",
            self.outer_sumcheck_proof.pow_witnesses.len(),
            0,
        )?;

        let opening_proof = &self.opening_proof;
        require_exact_wire_length(
            "opening evaluations",
            opening_proof.evals.len(),
            RELATION_COLUMN_COUNT,
        )?;
        require_exact_wire_length(
            "masked sumcheck transcripts",
            opening_proof.sumchecks.len(),
            EXPECTED_FOLDING_SCHEDULE.len(),
        )?;
        require_exact_wire_length(
            "masked sumcheck commitments",
            opening_proof.sumcheck_mask_commitments.len(),
            EXPECTED_FOLDING_SCHEDULE.len(),
        )?;
        for (commitment_index, commitment) in
            opening_proof.sumcheck_mask_commitments.iter().enumerate()
        {
            require_single_digest_cap(
                commitment,
                &format!("masked sumcheck commitment {commitment_index}"),
            )?;
        }
        for (batch_index, (sumcheck, expected_round_count)) in opening_proof
            .sumchecks
            .iter()
            .zip(EXPECTED_FOLDING_SCHEDULE)
            .enumerate()
        {
            if sumcheck.ell_zk != MASK_MESSAGE_LENGTH {
                return Err(format!(
                    "masked sumcheck batch {batch_index} mask message length is {}, expected {MASK_MESSAGE_LENGTH}",
                    sumcheck.ell_zk
                ));
            }
            require_exact_wire_length(
                &format!("masked sumcheck batch {batch_index} rounds"),
                sumcheck.round_coefficients.len(),
                expected_round_count,
            )?;
            for (round_index, coefficients) in sumcheck.round_coefficients.iter().enumerate() {
                require_exact_wire_length(
                    &format!(
                        "masked sumcheck batch {batch_index} round {round_index} coefficients"
                    ),
                    coefficients.len(),
                    MASK_MESSAGE_LENGTH - 1,
                )?;
            }
            require_exact_wire_length(
                &format!("masked sumcheck batch {batch_index} proof-of-work witnesses"),
                sumcheck.pow_witnesses.len(),
                0,
            )?;
        }

        require_exact_wire_length(
            "code-switch rounds",
            opening_proof.rounds.len(),
            EXPECTED_ROUND_QUERY_COUNTS.len(),
        )?;
        for (round_index, (round, expected_query_count)) in opening_proof
            .rounds
            .iter()
            .zip(EXPECTED_ROUND_QUERY_COUNTS)
            .enumerate()
        {
            require_single_digest_cap(
                &round.commitment,
                &format!("code-switch round {round_index} commitment"),
            )?;
            require_single_digest_cap(
                &round.mask_commitment,
                &format!("code-switch round {round_index} mask commitment"),
            )?;
            require_exact_wire_length(
                &format!("code-switch round {round_index} out-of-domain answers"),
                round.ood_answers.len(),
                0,
            )?;
            require_exact_wire_length(
                &format!("code-switch round {round_index} query openings"),
                round.queries.len(),
                expected_query_count,
            )?;
            let expected_kind = if round_index == 0 {
                SumcheckClassQueryOpeningKind::Base
            } else {
                SumcheckClassQueryOpeningKind::Extension
            };
            for (query_index, query) in round.queries.iter().enumerate() {
                require_query_opening_shape(
                    query,
                    expected_kind,
                    EXPECTED_ROUND_QUERY_VALUE_LENGTHS[round_index],
                    EXPECTED_ROUND_QUERY_PATH_LENGTHS[round_index],
                    &format!("code-switch round {round_index} query {query_index}"),
                )?;
            }
        }

        let base_case = &opening_proof.base_case;
        require_exact_wire_length(
            "fresh mask commitments",
            base_case.fresh_mask_commitments.len(),
            EXPECTED_MASK_GROUP_WIDTHS.len(),
        )?;
        require_single_digest_cap(
            &base_case.fresh_main_commitment,
            "base-case fresh-main commitment",
        )?;
        for (commitment_index, commitment) in base_case.fresh_mask_commitments.iter().enumerate() {
            require_single_digest_cap(
                commitment,
                &format!("base-case fresh mask commitment {commitment_index}"),
            )?;
        }
        let final_source_message_length =
            1_usize << (COMMITTED_VARIABLE_COUNT - EXPECTED_FOLDING_SCHEDULE.iter().sum::<usize>());
        require_exact_wire_length(
            "base-case blinded source message",
            base_case.blinded_message.len(),
            final_source_message_length,
        )?;
        require_exact_wire_length(
            "base-case blinded source randomness",
            base_case.blinded_randomness.len(),
            EXPECTED_FINAL_QUERY_COUNT,
        )?;
        require_exact_wire_length(
            "base-case blinded masks",
            base_case.blinded_masks.len(),
            EXPECTED_MASK_GROUP_WIDTHS.iter().sum(),
        )?;
        for (mask_index, (mask, expected_message_length)) in base_case
            .blinded_masks
            .iter()
            .zip(EXPECTED_BLINDED_MASK_MESSAGE_LENGTHS)
            .enumerate()
        {
            require_exact_wire_length(
                &format!("base-case blinded mask {mask_index} message"),
                mask.message.len(),
                expected_message_length,
            )?;
            require_exact_wire_length(
                &format!("base-case blinded mask {mask_index} randomness"),
                mask.randomness.len(),
                EXPECTED_MASK_QUERY_COUNT,
            )?;
        }

        require_exact_wire_length(
            "base-case source query openings",
            base_case.source_queries.len(),
            EXPECTED_FINAL_QUERY_COUNT,
        )?;
        for (query_index, query) in base_case.source_queries.iter().enumerate() {
            require_query_opening_shape(
                query,
                SumcheckClassQueryOpeningKind::Extension,
                EXPECTED_SOURCE_QUERY_VALUE_LENGTH,
                EXPECTED_SOURCE_QUERY_PATH_LENGTH,
                &format!("base-case source query {query_index}"),
            )?;
        }
        require_exact_wire_length(
            "base-case fresh-main query openings",
            base_case.fresh_main_queries.len(),
            EXPECTED_FINAL_QUERY_COUNT,
        )?;
        for (query_index, query) in base_case.fresh_main_queries.iter().enumerate() {
            require_query_opening_shape(
                query,
                SumcheckClassQueryOpeningKind::Extension,
                EXPECTED_FRESH_MAIN_QUERY_VALUE_LENGTH,
                EXPECTED_FRESH_MAIN_QUERY_PATH_LENGTH,
                &format!("base-case fresh-main query {query_index}"),
            )?;
        }
        require_exact_wire_length(
            "base-case mask query groups",
            base_case.mask_queries.len(),
            EXPECTED_MASK_GROUP_WIDTHS.len(),
        )?;
        for (group_index, group) in base_case.mask_queries.iter().enumerate() {
            require_exact_wire_length(
                &format!("base-case mask query group {group_index} opening pairs"),
                group.len(),
                EXPECTED_MASK_QUERY_COUNT,
            )?;
            for (pair_index, pair) in group.iter().enumerate() {
                for (opening_role, query) in [("carried", &pair.carried), ("fresh", &pair.fresh)] {
                    require_query_opening_shape(
                        query,
                        SumcheckClassQueryOpeningKind::Extension,
                        EXPECTED_MASK_GROUP_WIDTHS[group_index],
                        EXPECTED_MASK_GROUP_PATH_LENGTHS[group_index],
                        &format!(
                            "base-case mask query group {group_index} pair {pair_index} {opening_role}"
                        ),
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn require_exact_wire_length(
    field: &str,
    actual: usize,
    expected: usize,
) -> ProofBackendBakeoffResult<()> {
    if actual != expected {
        return Err(format!(
            "sumcheck-class artifact {field} length is {actual}, expected {expected}"
        ));
    }
    Ok(())
}

fn require_query_opening_shape(
    query: &SumcheckClassQueryOpeningWire,
    expected: SumcheckClassQueryOpeningKind,
    expected_value_length: usize,
    expected_path_length: usize,
    context: &str,
) -> ProofBackendBakeoffResult<()> {
    if query.kind() != expected {
        return Err(format!(
            "sumcheck-class artifact {context} uses the {} tag, expected {}",
            query.kind().name(),
            expected.name()
        ));
    }
    let (actual_value_length, actual_path_length) = match query {
        SumcheckClassQueryOpeningWire::Base { values, proof } => (values.len(), proof.len()),
        SumcheckClassQueryOpeningWire::Extension { values, proof } => (values.len(), proof.len()),
    };
    require_exact_wire_length(
        &format!("{context} opened values"),
        actual_value_length,
        expected_value_length,
    )?;
    require_exact_wire_length(
        &format!("{context} Merkle path"),
        actual_path_length,
        expected_path_length,
    )?;
    Ok(())
}

fn require_single_digest_cap(
    commitment: &SumcheckClassCommitment,
    context: &str,
) -> ProofBackendBakeoffResult<()> {
    require_exact_wire_length(&format!("{context} Merkle cap"), commitment.num_roots(), 1)
}

fn require_canonical_artifact_body_within_ceiling(
    body_byte_length: usize,
) -> ProofBackendBakeoffResult<()> {
    if body_byte_length > MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH {
        return Err(format!(
            "sumcheck-class artifact body is {body_byte_length} bytes, above the {}-byte codec ceiling",
            MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SumcheckClassParameterRecord {
    schema_version: u8,
    relation_variable_count: u8,
    column_selector_variable_count: u8,
    relation_row_count: u32,
    relation_column_count: u8,
    ciphertext_modulus: u64,
    material_radix: u64,
    material_high_digit_maximum: u8,
    base_field_modulus: u64,
    challenge_extension_degree: u8,
    discrete_fourier_transform: u8,
    cryptographic_hash: u8,
    challenger_encoding: u8,
    starting_log_inverse_rate: u8,
    configured_round_log_inverse_rates: Vec<u8>,
    folding_strategy: u8,
    constant_folding_factor: u8,
    mask_message_length: u8,
    mask_log_inverse_rate: u8,
    merkle_digest_byte_length: u8,
    challenger_output_byte_length: u8,
    merkle_tree_arity: u8,
    merkle_minimum_height: u8,
    outer_sumcheck_degree: u8,
    derived_folding_schedule: Vec<u8>,
    commitment_out_of_domain_sample_count: u16,
    starting_folding_pow_bits: u8,
    rounds: Vec<SumcheckClassRoundParameterRecord>,
    final_query_count: u16,
    final_pow_bits: u8,
    final_sumcheck_round_count: u8,
    final_folding_pow_bits: u8,
    mask_query_count: u16,
    oracle_randomness_lengths: Vec<u16>,
    sumcheck_mask: SumcheckClassMaskParameterRecord,
    switch_masks: Vec<SumcheckClassMaskParameterRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SumcheckClassRoundParameterRecord {
    pow_bits: u8,
    folding_pow_bits: u8,
    query_count: u16,
    out_of_domain_sample_count: u16,
    variable_count: u8,
    folding_factor: u8,
    log_inverse_rate: u8,
    domain_size: u32,
    folded_domain_generator: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SumcheckClassMaskParameterRecord {
    message_length: u16,
    randomness_length: u16,
    domain_size: u32,
}

#[derive(Clone, Copy, Debug)]
struct SumcheckClassSecurityBudget {
    maximum_pow_bits: usize,
}

#[derive(Debug)]
enum SumcheckClassConfigurationError {
    Upstream(String),
    ParameterDoesNotFit {
        parameter: &'static str,
    },
    GrindingBudget {
        required_bits: usize,
        ceiling_bits: usize,
    },
    DerivedValueMismatch {
        parameter: &'static str,
        expected: usize,
        actual: usize,
    },
    DerivedSequenceMismatch {
        parameter: &'static str,
        expected: Vec<usize>,
        actual: Vec<usize>,
    },
    SecurityInequality {
        invariant: &'static str,
    },
}

impl core::fmt::Display for SumcheckClassConfigurationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Upstream(message) => formatter.write_str(message),
            Self::ParameterDoesNotFit { parameter } => {
                write!(
                    formatter,
                    "parameter {parameter} does not fit its canonical field"
                )
            }
            Self::GrindingBudget {
                required_bits,
                ceiling_bits,
            } => write!(
                formatter,
                "derived proof-of-work requires {required_bits} bits above the {ceiling_bits}-bit ceiling"
            ),
            Self::DerivedValueMismatch {
                parameter,
                expected,
                actual,
            } => write!(
                formatter,
                "derived {parameter} is {actual}, expected the frozen value {expected}"
            ),
            Self::DerivedSequenceMismatch {
                parameter,
                expected,
                actual,
            } => write!(
                formatter,
                "derived {parameter} is {actual:?}, expected the frozen sequence {expected:?}"
            ),
            Self::SecurityInequality { invariant } => {
                write!(formatter, "exact security inequality failed: {invariant}")
            }
        }
    }
}

struct DegreeTwoRelationProver {
    equality_polynomial: Poly<ChallengeField>,
    combined_residual_polynomial: Poly<ChallengeField>,
}

impl DegreeTwoRelationProver {
    fn product_sum_at(&self, node: ChallengeField) -> ChallengeField {
        debug_assert_eq!(
            self.equality_polynomial.num_evals(),
            self.combined_residual_polynomial.num_evals()
        );
        let half_length = self.equality_polynomial.num_evals() / 2;
        let (equality_at_zero, equality_at_one) =
            self.equality_polynomial.as_slice().split_at(half_length);
        let (residual_at_zero, residual_at_one) = self
            .combined_residual_polynomial
            .as_slice()
            .split_at(half_length);
        let mut sum = ChallengeField::ZERO;
        for row_index in 0..half_length {
            let equality_at_node = equality_at_zero[row_index]
                + (equality_at_one[row_index] - equality_at_zero[row_index]) * node;
            let residual_at_node = residual_at_zero[row_index]
                + (residual_at_one[row_index] - residual_at_zero[row_index]) * node;
            sum += equality_at_node * residual_at_node;
        }
        sum
    }
}

impl RoundProver<ChallengeField> for DegreeTwoRelationProver {
    fn fold(&mut self, challenge: ChallengeField) {
        self.equality_polynomial.fix_prefix_var_mut(challenge);
        self.combined_residual_polynomial
            .fix_prefix_var_mut(challenge);
    }

    fn round_poly(&self) -> Vec<ChallengeField> {
        vec![
            self.product_sum_at(ChallengeField::ZERO),
            self.product_sum_at(ChallengeField::from_u64(2)),
        ]
    }
}

pub(super) fn execute_sumcheck_class(
    fixture: &ProofBackendBakeoffFixture,
) -> ProofBackendBakeoffResult<ProofBackendBakeoffArmOutput> {
    validate_fixture(fixture)?;
    let (pcs, parameters) = build_pcs()?;
    let witness = stacked_witness(fixture);
    let mut pcs_challenger = fresh_pcs_challenger(&pcs, &parameters)?;
    let (commitment, prover_data) = pcs.commit(witness, &mut pcs_challenger);
    if canonical_sumcheck_commitment(&commitment)? != fixture.expected_sumcheck_commitment {
        return Err(
            "sumcheck-class commitment does not match the exact frozen input binding".to_owned(),
        );
    }

    let mut relation_challenger =
        fresh_relation_challenger(&fixture.canonical_sumcheck_statement, &parameters)?;
    relation_challenger.observe(commitment.clone());
    let constraint_batching_challenge: ChallengeField =
        relation_challenger.sample_algebra_element();
    let equality_random_point = Point::new(
        (0..RELATION_VARIABLE_COUNT)
            .map(|_| relation_challenger.sample_algebra_element::<ChallengeField>())
            .collect(),
    );
    let equality_polynomial = Poly::<ChallengeField>::new_from_point(
        equality_random_point.as_slice(),
        ChallengeField::ONE,
    );
    let combined_residual_polynomial =
        combined_residual_polynomial(fixture, constraint_batching_challenge);
    let mut sumcheck_prover = DegreeTwoRelationProver {
        equality_polynomial,
        combined_residual_polynomial,
    };
    let (outer_sumcheck_proof, terminal_relation_point) = sumcheck_prover.prove::<BaseField, _>(
        &mut relation_challenger,
        RELATION_VARIABLE_COUNT,
        OUTER_SUMCHECK_DEGREE,
        0,
        ChallengeField::ZERO,
    );
    let opening_points = chosen_column_points(&terminal_relation_point);
    let opening_proof = pcs.open(prover_data, opening_points, &mut pcs_challenger);
    let artifact = SumcheckClassArtifact {
        outer_sumcheck_proof,
        opening_proof,
    };
    let canonical_artifact =
        encode_canonical_artifact(&artifact, &fixture.canonical_sumcheck_statement)?;

    Ok(ProofBackendBakeoffArmOutput { canonical_artifact })
}

fn build_pcs() -> ProofBackendBakeoffResult<(SumcheckClassPcs, SumcheckClassParameterRecord)> {
    let config = build_configuration().map_err(configuration_blocker)?;
    validate_security_budgets(&config).map_err(configuration_blocker)?;
    let parameters = parameter_record(&config).map_err(configuration_blocker)?;
    let commitment_scheme = CommitmentScheme::new(
        LeafHasher::new(DomainSeparatedShake256 {
            domain: b"proof-backend-bakeoff/sumcheck-class/merkle-leaf/v1",
        }),
        NodeCompressor::new(DomainSeparatedShake256 {
            domain: b"proof-backend-bakeoff/sumcheck-class/merkle-node/v1",
        }),
        MERKLE_MINIMUM_HEIGHT,
    );
    Ok((
        SumcheckClassPcs::new(
            config,
            DiscreteFourierTransform::default(),
            commitment_scheme,
            SmallRng::seed_from_u64(SYNTHETIC_HIDING_RANDOMNESS_SEED),
        ),
        parameters,
    ))
}

fn canonical_sumcheck_commitment(
    commitment: &SumcheckClassCommitment,
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let canonical = postcard::to_allocvec(commitment)
        .map_err(|error| format!("encode canonical sumcheck-class commitment: {error}"))?;
    if canonical.is_empty() {
        return Err("canonical sumcheck-class commitment is empty".to_owned());
    }
    Ok(canonical)
}

fn decode_canonical_sumcheck_commitment(
    canonical_commitment: &[u8],
) -> ProofBackendBakeoffResult<SumcheckClassCommitment> {
    let (commitment, trailing_bytes) =
        postcard::take_from_bytes::<SumcheckClassCommitment>(canonical_commitment)
            .map_err(|error| format!("decode canonical sumcheck-class commitment: {error}"))?;
    if !trailing_bytes.is_empty() {
        return Err("canonical sumcheck-class commitment has trailing bytes".to_owned());
    }
    if canonical_sumcheck_commitment(&commitment)? != canonical_commitment {
        return Err("sumcheck-class commitment encoding is not canonical".to_owned());
    }
    require_single_digest_cap(&commitment, "public sumcheck-class commitment")?;
    Ok(commitment)
}

pub(super) fn validate_canonical_sumcheck_commitment(
    canonical_commitment: &[u8],
) -> ProofBackendBakeoffResult<()> {
    decode_canonical_sumcheck_commitment(canonical_commitment).map(drop)
}

pub(super) fn derive_frozen_sumcheck_commitment(
    columns: &[Vec<u64>; RELATION_COLUMN_COUNT],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let (pcs, parameters) = build_pcs()?;
    let witness = stacked_witness_columns(columns);
    let mut pcs_challenger = fresh_pcs_challenger(&pcs, &parameters)?;
    let (commitment, prover_data) = pcs.commit(witness, &mut pcs_challenger);
    let canonical = canonical_sumcheck_commitment(&commitment)?;
    drop(prover_data);
    Ok(canonical)
}

fn build_configuration() -> Result<SumcheckClassConfiguration, SumcheckClassConfigurationError> {
    ZkWhirConfig::<ChallengeField, BaseField, Challenger>::new(
        COMMITTED_VARIABLE_COUNT,
        ProtocolParameters {
            starting_log_inv_rate: STARTING_LOG_INVERSE_RATE,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::Constant(CONSTANT_FOLDING_FACTOR),
            soundness_type: SecurityAssumption::UniqueDecoding,
            security_level: INTERNAL_BRANCH_SECURITY_PARAMETER,
            pow_bits: GRINDING_BIT_CEILING,
        },
        ZkParameters {
            ell_zk: MASK_MESSAGE_LENGTH,
            mask_log_inv_rate: MASK_LOG_INVERSE_RATE,
        },
    )
    .map_err(|error| {
        SumcheckClassConfigurationError::Upstream(format!(
            "construct conservative HidingWhir configuration: {error}"
        ))
    })
}

fn configuration_blocker(error: SumcheckClassConfigurationError) -> String {
    format!("sumcheck-class configuration blocker: {error}")
}

fn require_derived_value(
    parameter: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), SumcheckClassConfigurationError> {
    if actual != expected {
        return Err(SumcheckClassConfigurationError::DerivedValueMismatch {
            parameter,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_derived_sequence(
    parameter: &'static str,
    expected: &[usize],
    actual: Vec<usize>,
) -> Result<(), SumcheckClassConfigurationError> {
    if actual != expected {
        return Err(SumcheckClassConfigurationError::DerivedSequenceMismatch {
            parameter,
            expected: expected.to_vec(),
            actual,
        });
    }
    Ok(())
}

fn validate_frozen_configuration_profile(
    config: &SumcheckClassConfiguration,
) -> Result<(), SumcheckClassConfigurationError> {
    require_derived_value(
        "committed variable count",
        COMMITTED_VARIABLE_COUNT,
        config.num_variables,
    )?;
    require_derived_value(
        "internal branch security parameter",
        INTERNAL_BRANCH_SECURITY_PARAMETER,
        config.params.security_level,
    )?;
    require_derived_value(
        "configured grinding ceiling",
        GRINDING_BIT_CEILING,
        config.params.pow_bits,
    )?;
    require_derived_value(
        "starting log inverse rate",
        STARTING_LOG_INVERSE_RATE,
        config.params.starting_log_inv_rate,
    )?;
    require_derived_value(
        "unique-decoding assumption selector",
        1,
        usize::from(config.params.soundness_type == SecurityAssumption::UniqueDecoding),
    )?;
    require_derived_sequence(
        "explicit round log inverse rates",
        &[],
        config.params.round_log_inv_rates.clone(),
    )?;
    require_derived_value("mask message length", MASK_MESSAGE_LENGTH, config.zk.ell_zk)?;
    require_derived_value(
        "mask log inverse rate",
        MASK_LOG_INVERSE_RATE,
        config.zk.mask_log_inv_rate,
    )?;
    require_derived_sequence(
        "folding schedule",
        &EXPECTED_FOLDING_SCHEDULE,
        config.folding_schedule.clone(),
    )?;
    require_derived_value("intermediate round count", 2, config.n_rounds())?;
    require_derived_value(
        "commitment out-of-domain sample count",
        0,
        config.commitment_ood_samples,
    )?;
    require_derived_value(
        "starting folding proof-of-work bits",
        0,
        config.starting_folding_pow_bits,
    )?;
    require_derived_sequence(
        "round query counts",
        &EXPECTED_ROUND_QUERY_COUNTS,
        config
            .round_parameters
            .iter()
            .map(|round| round.num_queries)
            .collect(),
    )?;
    require_derived_sequence(
        "round query proof-of-work bits",
        &EXPECTED_ROUND_POW_BITS,
        config
            .round_parameters
            .iter()
            .map(|round| round.pow_bits)
            .collect(),
    )?;
    require_derived_sequence(
        "round folding proof-of-work bits",
        &[0, 0],
        config
            .round_parameters
            .iter()
            .map(|round| round.folding_pow_bits)
            .collect(),
    )?;
    require_derived_sequence(
        "round out-of-domain sample counts",
        &[0, 0],
        config
            .round_parameters
            .iter()
            .map(|round| round.ood_samples)
            .collect(),
    )?;
    require_derived_sequence(
        "round variable counts",
        &EXPECTED_ROUND_VARIABLE_COUNTS,
        config
            .round_parameters
            .iter()
            .map(|round| round.num_variables)
            .collect(),
    )?;
    require_derived_sequence(
        "round folding factors",
        &[4, 4],
        config
            .round_parameters
            .iter()
            .map(|round| round.folding_factor)
            .collect(),
    )?;
    require_derived_sequence(
        "round log inverse rates",
        &EXPECTED_ROUND_LOG_INVERSE_RATES,
        config
            .round_parameters
            .iter()
            .map(|round| round.log_inv_rate)
            .collect(),
    )?;
    require_derived_sequence(
        "round domain sizes",
        &EXPECTED_ROUND_DOMAIN_SIZES,
        config
            .round_parameters
            .iter()
            .map(|round| round.domain_size)
            .collect(),
    )?;
    require_derived_value(
        "final query count",
        EXPECTED_FINAL_QUERY_COUNT,
        config.final_queries,
    )?;
    require_derived_value(
        "final query proof-of-work bits",
        EXPECTED_FINAL_POW_BITS,
        config.final_pow_bits,
    )?;
    require_derived_value(
        "final sumcheck round count",
        EXPECTED_FINAL_SUMCHECK_ROUND_COUNT,
        config.final_sumcheck_rounds,
    )?;
    require_derived_value(
        "final folding proof-of-work bits",
        0,
        config.final_folding_pow_bits,
    )?;
    require_derived_sequence(
        "oracle randomness lengths",
        &EXPECTED_ORACLE_RANDOMNESS_LENGTHS,
        config.oracle_randomness.clone(),
    )?;
    require_derived_value("mask query count", 276, config.mask_queries)?;
    require_derived_sequence(
        "sumcheck mask shape",
        &[46, 276, 16_384],
        vec![
            config.sumcheck_mask.message_len,
            config.sumcheck_mask.randomness_len,
            config.sumcheck_mask.domain_size,
        ],
    )?;
    require_derived_sequence(
        "code-switch mask shapes",
        &[579, 276, 32_768, 264, 276, 32_768],
        config
            .switch_masks
            .iter()
            .flat_map(|shape| [shape.message_len, shape.randomness_len, shape.domain_size])
            .collect(),
    )
}

fn unique_decoding_query_failure_fraction(
    log_inverse_rate: usize,
    query_count: usize,
    grinding_bits: usize,
) -> Result<(BigUint, usize), SumcheckClassConfigurationError> {
    let numerator_base = 1_usize
        .checked_shl(u32::try_from(log_inverse_rate).map_err(|_| {
            SumcheckClassConfigurationError::ParameterDoesNotFit {
                parameter: "unique-decoding inverse-rate exponent",
            }
        })?)
        .and_then(|value| value.checked_add(1))
        .ok_or(SumcheckClassConfigurationError::ParameterDoesNotFit {
            parameter: "unique-decoding query numerator base",
        })?;
    let power = u32::try_from(query_count).map_err(|_| {
        SumcheckClassConfigurationError::ParameterDoesNotFit {
            parameter: "unique-decoding query exponent",
        }
    })?;
    let denominator_exponent = log_inverse_rate
        .checked_add(1)
        .and_then(|value| value.checked_mul(query_count))
        .and_then(|value| value.checked_add(grinding_bits))
        .ok_or(SumcheckClassConfigurationError::ParameterDoesNotFit {
            parameter: "unique-decoding query denominator exponent",
        })?;
    Ok((
        BigUint::from(numerator_base).pow(power),
        denominator_exponent,
    ))
}

fn exact_unique_decoding_query_bound_holds(
    log_inverse_rate: usize,
    query_count: usize,
    grinding_bits: usize,
    security_parameter: usize,
) -> Result<bool, SumcheckClassConfigurationError> {
    let (numerator, denominator_exponent) =
        unique_decoding_query_failure_fraction(log_inverse_rate, query_count, grinding_bits)?;
    Ok((numerator << security_parameter) <= (BigUint::from(1_u8) << denominator_exponent))
}

fn exact_unique_decoding_mask_union_bound_holds(
    mask_branch_count: usize,
    query_count: usize,
    security_parameter: usize,
) -> Result<bool, SumcheckClassConfigurationError> {
    let (branch_numerator, denominator_exponent) =
        unique_decoding_query_failure_fraction(MASK_LOG_INVERSE_RATE, query_count, 0)?;
    let numerator = BigUint::from(mask_branch_count) * branch_numerator;
    Ok((numerator << security_parameter) <= (BigUint::from(1_u8) << denominator_exponent))
}

fn exact_unique_decoding_rbr_aggregate_bound_holds(
    query_branches: &[(usize, usize, usize)],
    mask_query_count: usize,
    aggregate_security_parameter: usize,
) -> Result<bool, SumcheckClassConfigurationError> {
    // This exact comparison ledger covers the unique-decoding query, mask-query, folding,
    // query-combination, terminal, and outer-relation terms of the frozen synthetic arm. Its
    // non-claims are stated in the module documentation.
    if query_branches.len() != ORDINARY_QUERY_BRANCH_COUNT {
        return Ok(false);
    }
    let mut binary_denominator_terms = query_branches
        .iter()
        .map(|&(log_inverse_rate, query_count, grinding_bits)| {
            unique_decoding_query_failure_fraction(log_inverse_rate, query_count, grinding_bits)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (mask_branch_numerator, mask_denominator_exponent) =
        unique_decoding_query_failure_fraction(MASK_LOG_INVERSE_RATE, mask_query_count, 0)?;
    binary_denominator_terms.push((
        BigUint::from(MASK_BRANCH_COUNT) * mask_branch_numerator,
        mask_denominator_exponent,
    ));
    let common_binary_denominator_exponent = binary_denominator_terms
        .iter()
        .map(|(_, denominator_exponent)| *denominator_exponent)
        .max()
        .ok_or(SumcheckClassConfigurationError::ParameterDoesNotFit {
            parameter: "unique-decoding aggregate binary denominator",
        })?;
    let binary_numerator = binary_denominator_terms.into_iter().fold(
        BigUint::from(0_u8),
        |sum, (numerator, denominator_exponent)| {
            sum + (numerator << (common_binary_denominator_exponent - denominator_exponent))
        },
    );
    let field_order = challenge_field_order();
    let aggregate_numerator = binary_numerator * &field_order
        + (BigUint::from(UNIQUE_DECODING_AGGREGATE_ALGEBRAIC_FAILURE_NUMERATOR)
            << common_binary_denominator_exponent);
    let aggregate_denominator = field_order << common_binary_denominator_exponent;
    Ok((aggregate_numerator << aggregate_security_parameter) < aggregate_denominator)
}

fn exact_classical_fiat_shamir_work_factor_bound_holds() -> bool {
    // The classical BCS/BT24 round-by-round compiler ledger is
    // Q * epsilon_RBR + 3 * (Q^2 + 1) / 2^kappa. Evaluate its worst admitted
    // Q = 2^128 directly over the frozen kappa = 512 denominator.
    let random_oracle_query_bound =
        BigUint::from(1_u8) << CLASSICAL_RANDOM_ORACLE_QUERY_BOUND_EXPONENT;
    let rbr_term_numerator = &random_oracle_query_bound
        << (FIAT_SHAMIR_XOF_OUTPUT_BIT_LENGTH - CONSERVATIVE_RBR_AGGREGATE_SOUNDNESS_BIT_BOUND);
    let compiler_term_numerator = BigUint::from(3_u8)
        * (&random_oracle_query_bound * &random_oracle_query_bound + BigUint::from(1_u8));
    let target_numerator = BigUint::from(1_u8)
        << (FIAT_SHAMIR_XOF_OUTPUT_BIT_LENGTH - CLASSICAL_RANDOM_ORACLE_QUERY_BOUND_EXPONENT);
    rbr_term_numerator + compiler_term_numerator < target_numerator
}

fn challenge_field_order() -> BigUint {
    BigUint::from(BaseField::ORDER_U64).pow(5)
}

/*
    The unique-decoding query term is

        ((2^r + 1) / 2^(r + 1))^q * 2^-w,

    so every synthetic checked gate above is an integer comparison. No floating-point
    Johnson-bound approximation or list-decoding conjecture enters the record.
*/

fn validate_security_budgets(
    config: &SumcheckClassConfiguration,
) -> Result<SumcheckClassSecurityBudget, SumcheckClassConfigurationError> {
    validate_frozen_configuration_profile(config)?;
    let maximum_pow_bits = config.max_pow_bits();
    if !config.check_pow_bits() || maximum_pow_bits > GRINDING_BIT_CEILING {
        return Err(SumcheckClassConfigurationError::GrindingBudget {
            required_bits: maximum_pow_bits,
            ceiling_bits: GRINDING_BIT_CEILING,
        });
    }

    let query_branches = [
        (1_usize, 579_usize, 20_usize),
        (4_usize, 264_usize, 20_usize),
        (7_usize, 243_usize, 20_usize),
    ];
    for &(log_inverse_rate, query_count, grinding_bits) in &query_branches {
        if !exact_unique_decoding_query_bound_holds(
            log_inverse_rate,
            query_count,
            grinding_bits,
            INTERNAL_BRANCH_SECURITY_PARAMETER,
        )? {
            return Err(SumcheckClassConfigurationError::SecurityInequality {
                invariant: "each ordinary unique-decoding query branch reaches 260 bits with its configured grinding",
            });
        }
        if exact_unique_decoding_query_bound_holds(
            log_inverse_rate,
            query_count,
            grinding_bits - 1,
            INTERNAL_BRANCH_SECURITY_PARAMETER,
        )? {
            return Err(SumcheckClassConfigurationError::SecurityInequality {
                invariant: "each ordinary unique-decoding branch uses the minimum whole grinding count at 260 bits",
            });
        }
        let algebraic_security_parameter =
            INTERNAL_BRANCH_SECURITY_PARAMETER - GRINDING_BIT_CEILING;
        if !exact_unique_decoding_query_bound_holds(
            log_inverse_rate,
            query_count,
            0,
            algebraic_security_parameter,
        )? || exact_unique_decoding_query_bound_holds(
            log_inverse_rate,
            query_count - 1,
            0,
            algebraic_security_parameter,
        )? {
            return Err(SumcheckClassConfigurationError::SecurityInequality {
                invariant: "each ordinary unique-decoding branch uses the minimum query count at the 240-bit algebraic floor",
            });
        }
    }

    let mask_branch_count = 2 * config.n_rounds() + 2;
    require_derived_value("mask branch count", MASK_BRANCH_COUNT, mask_branch_count)?;
    if !exact_unique_decoding_mask_union_bound_holds(
        mask_branch_count,
        config.mask_queries,
        MASK_UNION_SECURITY_PARAMETER,
    )? || exact_unique_decoding_mask_union_bound_holds(
        mask_branch_count,
        config.mask_queries,
        MASK_UNION_SECURITY_PARAMETER + 1,
    )? {
        return Err(SumcheckClassConfigurationError::SecurityInequality {
            invariant: "the exact six-mask union reaches 261 bits but not 262 bits",
        });
    }
    if !exact_unique_decoding_rbr_aggregate_bound_holds(
        &query_branches,
        config.mask_queries,
        CONSERVATIVE_RBR_AGGREGATE_SOUNDNESS_BIT_BOUND,
    )? {
        return Err(SumcheckClassConfigurationError::SecurityInequality {
            invariant: "the exact unique-decoding RBR aggregate is strictly below 2^-258",
        });
    }

    let field_order = challenge_field_order();
    let derived_algebraic_failure_numerator = UNIQUE_DECODING_FOLD_FAILURE_NUMERATORS
        .iter()
        .try_fold(0_u64, |sum, &value| sum.checked_add(value))
        .and_then(|sum| sum.checked_add(UNIQUE_DECODING_QUERY_COMBINATION_FAILURE_NUMERATOR))
        .and_then(|sum| sum.checked_add(UNIQUE_DECODING_FINAL_FOLDING_FAILURE_NUMERATOR))
        .and_then(|sum| sum.checked_add(OUTER_RELATION_FAILURE_NUMERATOR as u64))
        .ok_or(SumcheckClassConfigurationError::ParameterDoesNotFit {
            parameter: "aggregate unique-decoding algebraic failure numerator",
        })?;
    require_derived_value(
        "aggregate unique-decoding algebraic failure numerator",
        UNIQUE_DECODING_AGGREGATE_ALGEBRAIC_FAILURE_NUMERATOR as usize,
        derived_algebraic_failure_numerator as usize,
    )?;
    if (BigUint::from(derived_algebraic_failure_numerator)
        << UNIQUE_DECODING_ALGEBRAIC_SECURITY_PARAMETER)
        >= field_order.clone()
    {
        return Err(SumcheckClassConfigurationError::SecurityInequality {
            invariant: "the complete unique-decoding algebraic aggregate is below 2^-301",
        });
    }
    if (BigUint::from(OUTER_RELATION_FAILURE_NUMERATOR) << OUTER_RELATION_SECURITY_PARAMETER)
        >= field_order
    {
        return Err(SumcheckClassConfigurationError::SecurityInequality {
            invariant: "the composed 43/q outer relation error is below 2^-309",
        });
    }

    let digest_bit_length = MERKLE_DIGEST_BYTE_LENGTH * 8;
    require_derived_value(
        "Fiat-Shamir XOF output bit length",
        FIAT_SHAMIR_XOF_OUTPUT_BIT_LENGTH,
        CHALLENGER_OUTPUT_BYTE_LENGTH * 8,
    )?;
    require_derived_value(
        "classical Merkle collision security bits",
        CLASSICAL_MERKLE_COLLISION_SECURITY_BITS,
        digest_bit_length / 2,
    )?;
    if CLASSICAL_MERKLE_COLLISION_SECURITY_BITS <= EXTERNAL_HIDING_SECURITY_BIT_TARGET
        || digest_bit_length
            <= GENERIC_QUANTUM_COLLISION_QUERY_EXPONENT_DENOMINATOR
                * EXTERNAL_HIDING_SECURITY_BIT_TARGET
    {
        return Err(SumcheckClassConfigurationError::SecurityInequality {
            invariant: "the 512-bit digest has more than 128 bits of classical and generic quantum collision-query work",
        });
    }
    if !exact_classical_fiat_shamir_work_factor_bound_holds() {
        return Err(SumcheckClassConfigurationError::SecurityInequality {
            invariant: "the ideal-XOF Fiat-Shamir ledger exceeds 128 classical bits for at most 2^128 random-oracle queries",
        });
    }

    Ok(SumcheckClassSecurityBudget { maximum_pow_bits })
}

fn parameter_record(
    config: &SumcheckClassConfiguration,
) -> Result<SumcheckClassParameterRecord, SumcheckClassConfigurationError> {
    let rounds = config
        .round_parameters
        .iter()
        .map(|round| {
            Ok(SumcheckClassRoundParameterRecord {
                pow_bits: canonical_u8(round.pow_bits, "round pow bits")?,
                folding_pow_bits: canonical_u8(round.folding_pow_bits, "round folding pow bits")?,
                query_count: canonical_u16(round.num_queries, "round query count")?,
                out_of_domain_sample_count: canonical_u16(
                    round.ood_samples,
                    "round out-of-domain sample count",
                )?,
                variable_count: canonical_u8(round.num_variables, "round variable count")?,
                folding_factor: canonical_u8(round.folding_factor, "round folding factor")?,
                log_inverse_rate: canonical_u8(round.log_inv_rate, "round log inverse rate")?,
                domain_size: canonical_u32(round.domain_size, "round domain size")?,
                folded_domain_generator: round.folded_domain_gen.as_canonical_u64(),
            })
        })
        .collect::<Result<Vec<_>, SumcheckClassConfigurationError>>()?;
    Ok(SumcheckClassParameterRecord {
        schema_version: 5,
        relation_variable_count: canonical_u8(RELATION_VARIABLE_COUNT, "relation variable count")?,
        column_selector_variable_count: canonical_u8(
            COLUMN_SELECTOR_VARIABLE_COUNT,
            "column selector variable count",
        )?,
        relation_row_count: canonical_u32(RELATION_ROW_COUNT, "relation row count")?,
        relation_column_count: canonical_u8(RELATION_COLUMN_COUNT, "relation column count")?,
        ciphertext_modulus: CIPHERTEXT_MODULUS,
        material_radix: MATERIAL_RADIX,
        material_high_digit_maximum: canonical_u8(
            MATERIAL_HIGH_DIGIT_MAXIMUM as usize,
            "material high digit maximum",
        )?,
        base_field_modulus: BaseField::ORDER_U64,
        challenge_extension_degree: 5,
        discrete_fourier_transform: 1,
        cryptographic_hash: 1,
        challenger_encoding: 1,
        starting_log_inverse_rate: canonical_u8(
            config.params.starting_log_inv_rate,
            "starting log inverse rate",
        )?,
        configured_round_log_inverse_rates: config
            .params
            .round_log_inv_rates
            .iter()
            .map(|&rate| canonical_u8(rate, "configured round log inverse rate"))
            .collect::<Result<Vec<_>, _>>()?,
        folding_strategy: 0,
        constant_folding_factor: canonical_u8(CONSTANT_FOLDING_FACTOR, "constant folding factor")?,
        mask_message_length: canonical_u8(MASK_MESSAGE_LENGTH, "mask message length")?,
        mask_log_inverse_rate: canonical_u8(MASK_LOG_INVERSE_RATE, "mask log inverse rate")?,
        merkle_digest_byte_length: canonical_u8(
            MERKLE_DIGEST_BYTE_LENGTH,
            "Merkle digest byte length",
        )?,
        challenger_output_byte_length: canonical_u8(
            CHALLENGER_OUTPUT_BYTE_LENGTH,
            "challenger output byte length",
        )?,
        merkle_tree_arity: canonical_u8(MERKLE_TREE_ARITY, "Merkle tree arity")?,
        merkle_minimum_height: canonical_u8(MERKLE_MINIMUM_HEIGHT, "Merkle minimum height")?,
        outer_sumcheck_degree: canonical_u8(OUTER_SUMCHECK_DEGREE, "outer sumcheck degree")?,
        derived_folding_schedule: config
            .folding_schedule
            .iter()
            .map(|&factor| canonical_u8(factor, "derived folding factor"))
            .collect::<Result<Vec<_>, _>>()?,
        commitment_out_of_domain_sample_count: canonical_u16(
            config.commitment_ood_samples,
            "commitment out-of-domain sample count",
        )?,
        starting_folding_pow_bits: canonical_u8(
            config.starting_folding_pow_bits,
            "starting folding pow bits",
        )?,
        rounds,
        final_query_count: canonical_u16(config.final_queries, "final query count")?,
        final_pow_bits: canonical_u8(config.final_pow_bits, "final pow bits")?,
        final_sumcheck_round_count: canonical_u8(
            config.final_sumcheck_rounds,
            "final sumcheck round count",
        )?,
        final_folding_pow_bits: canonical_u8(
            config.final_folding_pow_bits,
            "final folding pow bits",
        )?,
        mask_query_count: canonical_u16(config.mask_queries, "mask query count")?,
        oracle_randomness_lengths: config
            .oracle_randomness
            .iter()
            .map(|&length| canonical_u16(length, "oracle randomness length"))
            .collect::<Result<Vec<_>, _>>()?,
        sumcheck_mask: mask_parameter_record(config.sumcheck_mask)?,
        switch_masks: config
            .switch_masks
            .iter()
            .copied()
            .map(mask_parameter_record)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn mask_parameter_record(
    shape: p3_whir::pcs::zk::MaskCodeShape,
) -> Result<SumcheckClassMaskParameterRecord, SumcheckClassConfigurationError> {
    Ok(SumcheckClassMaskParameterRecord {
        message_length: canonical_u16(shape.message_len, "mask message length")?,
        randomness_length: canonical_u16(shape.randomness_len, "mask randomness length")?,
        domain_size: canonical_u32(shape.domain_size, "mask domain size")?,
    })
}

fn canonical_u8(
    value: usize,
    parameter: &'static str,
) -> Result<u8, SumcheckClassConfigurationError> {
    u8::try_from(value)
        .map_err(|_| SumcheckClassConfigurationError::ParameterDoesNotFit { parameter })
}

fn canonical_u16(
    value: usize,
    parameter: &'static str,
) -> Result<u16, SumcheckClassConfigurationError> {
    u16::try_from(value)
        .map_err(|_| SumcheckClassConfigurationError::ParameterDoesNotFit { parameter })
}

fn canonical_u32(
    value: usize,
    parameter: &'static str,
) -> Result<u32, SumcheckClassConfigurationError> {
    u32::try_from(value)
        .map_err(|_| SumcheckClassConfigurationError::ParameterDoesNotFit { parameter })
}

fn append_parameter_record(
    initial_state: &mut Vec<u8>,
    parameters: &SumcheckClassParameterRecord,
) -> ProofBackendBakeoffResult<()> {
    let bytes = postcard::to_allocvec(parameters)
        .map_err(|error| format!("encode sumcheck-class parameter record: {error}"))?;
    let byte_length = u64::try_from(bytes.len())
        .map_err(|_| "sumcheck-class parameter record byte length does not fit u64".to_owned())?;
    initial_state.extend_from_slice(&byte_length.to_le_bytes());
    initial_state.extend_from_slice(&bytes);
    Ok(())
}

fn fresh_pcs_challenger(
    pcs: &SumcheckClassPcs,
    parameters: &SumcheckClassParameterRecord,
) -> ProofBackendBakeoffResult<Challenger> {
    let mut initial_state = b"proof-backend-bakeoff/sumcheck-class/pcs-transcript/v1".to_vec();
    append_parameter_record(&mut initial_state, parameters)?;
    let mut challenger = Challenger::new(HashChallenger::new(
        initial_state,
        DomainSeparatedShake256 {
            domain: b"proof-backend-bakeoff/sumcheck-class/pcs-challenges/v1",
        },
    ));
    let mut separator = DomainSeparator::<ChallengeField, BaseField>::new(Vec::new());
    pcs.add_domain_separator::<MERKLE_DIGEST_WORD_LENGTH>(&mut separator);
    separator.observe_domain_separator(&mut challenger);
    Ok(challenger)
}

fn fresh_relation_challenger(
    canonical_statement: &[u8],
    parameters: &SumcheckClassParameterRecord,
) -> ProofBackendBakeoffResult<Challenger> {
    let initial_state = relation_transcript_initial_state(canonical_statement, parameters)?;
    Ok(Challenger::new(HashChallenger::new(
        initial_state,
        DomainSeparatedShake256 {
            domain: b"proof-backend-bakeoff/sumcheck-class/outer-challenges/v1",
        },
    )))
}

fn relation_transcript_initial_state(
    canonical_statement: &[u8],
    parameters: &SumcheckClassParameterRecord,
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let statement_byte_length = u64::try_from(canonical_statement.len())
        .map_err(|_| "sumcheck-class statement byte length does not fit u64".to_owned())?;
    let mut initial_state = b"proof-backend-bakeoff/sumcheck-class/outer-sumcheck/v1".to_vec();
    append_parameter_record(&mut initial_state, parameters)?;
    initial_state.extend_from_slice(&statement_byte_length.to_le_bytes());
    initial_state.extend_from_slice(canonical_statement);
    Ok(initial_state)
}

fn stacked_witness_columns(columns: &[Vec<u64>; RELATION_COLUMN_COUNT]) -> Poly<BaseField> {
    let mut evaluations = Vec::with_capacity(RELATION_COLUMN_COUNT * RELATION_ROW_COUNT);
    for column in columns {
        evaluations.extend(column.iter().copied().map(BaseField::from_u64));
    }
    Poly::new(evaluations)
}

fn stacked_witness(fixture: &ProofBackendBakeoffFixture) -> Poly<BaseField> {
    stacked_witness_columns(&fixture.columns)
}

fn combined_residual_polynomial(
    fixture: &ProofBackendBakeoffFixture,
    constraint_batching_challenge: ChallengeField,
) -> Poly<ChallengeField> {
    Poly::new(
        (0..RELATION_ROW_COUNT)
            .map(|row_index| {
                let first_residual = affine_residual_from_fixture(fixture, row_index, 0);
                let second_residual = affine_residual_from_fixture(fixture, row_index, 4);
                ChallengeField::from(first_residual)
                    + constraint_batching_challenge * ChallengeField::from(second_residual)
            })
            .collect(),
    )
}

fn affine_residual_from_fixture(
    fixture: &ProofBackendBakeoffFixture,
    row_index: usize,
    first_column_index: usize,
) -> BaseField {
    affine_residual(
        BaseField::from_u64(fixture.columns[first_column_index][row_index]),
        BaseField::from_u64(fixture.columns[first_column_index + 1][row_index]),
        BaseField::from_u64(fixture.columns[first_column_index + 2][row_index]),
        BaseField::from_u64(fixture.columns[first_column_index + 3][row_index]),
    )
}

fn affine_residual<Field: PrimeCharacteristicRing>(
    low_digit: Field,
    high_digit: Field,
    shifted_secret: Field,
    negative_indicator: Field,
) -> Field {
    low_digit + high_digit * Field::from_u64(MATERIAL_RADIX) - shifted_secret + Field::ONE
        - negative_indicator * Field::from_u64(CIPHERTEXT_MODULUS)
}

fn chosen_column_points(
    terminal_relation_point: &Point<ChallengeField>,
) -> Vec<Point<ChallengeField>> {
    (0..RELATION_COLUMN_COUNT)
        .map(|column_index| {
            let mut point =
                Point::<ChallengeField>::hypercube(column_index, COLUMN_SELECTOR_VARIABLE_COUNT);
            point.extend(terminal_relation_point);
            point
        })
        .collect()
}

fn verify_canonical_artifact(
    canonical_artifact: &[u8],
    canonical_sumcheck_statement: &[u8],
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<()> {
    let statement_bindings = validated_frozen_sumcheck_public_statement(
        canonical_sumcheck_statement,
        input_identity_shake256_hex,
    )?;
    let commitment =
        decode_canonical_sumcheck_commitment(&statement_bindings.expected_sumcheck_commitment)?;
    let artifact = decode_canonical_artifact(canonical_artifact, canonical_sumcheck_statement)?;
    verify_decoded_artifact(&artifact, canonical_sumcheck_statement, &commitment)
}

fn encode_canonical_artifact(
    artifact: &SumcheckClassArtifact,
    canonical_statement: &[u8],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let canonical_body = postcard::to_allocvec(&SumcheckClassArtifactWireReference { artifact })
        .map_err(|error| format!("encode sumcheck-class artifact: {error}"))?;
    require_canonical_artifact_body_within_ceiling(canonical_body.len())?;
    let mut canonical_artifact = canonical_proof_object_header_bytes(canonical_statement)
        .map_err(|error| format!("construct sumcheck-class proof header: {error:?}"))?;
    canonical_artifact.extend_from_slice(&canonical_body);
    Ok(canonical_artifact)
}

fn decode_canonical_artifact(
    canonical_artifact: &[u8],
    canonical_statement: &[u8],
) -> ProofBackendBakeoffResult<SumcheckClassArtifact> {
    let expected_header = canonical_proof_object_header_bytes(canonical_statement)
        .map_err(|error| format!("construct expected sumcheck-class proof header: {error:?}"))?;
    let canonical_body = canonical_artifact
        .strip_prefix(expected_header.as_slice())
        .ok_or_else(|| "sumcheck-class artifact has the wrong canonical proof header".to_owned())?;
    require_canonical_artifact_body_within_ceiling(canonical_body.len())?;
    let (artifact_wire, trailing_bytes) =
        postcard::take_from_bytes::<SumcheckClassArtifactWire>(canonical_body)
            .map_err(|error| format!("decode sumcheck-class artifact: {error}"))?;
    if !trailing_bytes.is_empty() {
        return Err("sumcheck-class artifact has trailing bytes".to_owned());
    }
    artifact_wire.validate_exact_shape()?;
    let artifact = artifact_wire.into_artifact();
    let reencoded = postcard::to_allocvec(&SumcheckClassArtifactWireReference {
        artifact: &artifact,
    })
    .map_err(|error| format!("re-encode sumcheck-class artifact: {error}"))?;
    if reencoded != canonical_body {
        return Err("sumcheck-class artifact encoding is not canonical".to_owned());
    }
    Ok(artifact)
}

fn require_verification_refusal(
    result: ProofBackendBakeoffResult<()>,
    mutation: &'static str,
) -> ProofBackendBakeoffResult<()> {
    if result.is_ok() {
        return Err(format!(
            "fresh sumcheck-class verifier accepted the {mutation} mutation"
        ));
    }
    Ok(())
}

pub(super) fn verify_sumcheck_class_mutations(
    canonical_sumcheck_statement: &[u8],
    input_identity_shake256_hex: &str,
    canonical_artifact: &[u8],
) -> ProofBackendBakeoffResult<()> {
    verify_canonical_artifact(
        canonical_artifact,
        canonical_sumcheck_statement,
        input_identity_shake256_hex,
    )?;

    let mut changed_header = canonical_artifact.to_vec();
    let first_header_byte = changed_header
        .first_mut()
        .ok_or_else(|| "sumcheck-class artifact is empty".to_owned())?;
    *first_header_byte ^= 1;
    require_verification_refusal(
        verify_canonical_artifact(
            &changed_header,
            canonical_sumcheck_statement,
            input_identity_shake256_hex,
        ),
        "canonical proof header",
    )?;

    let mut trailing = canonical_artifact.to_vec();
    trailing.push(0);
    require_verification_refusal(
        verify_canonical_artifact(
            &trailing,
            canonical_sumcheck_statement,
            input_identity_shake256_hex,
        ),
        "trailing byte",
    )?;

    let artifact = decode_canonical_artifact(canonical_artifact, canonical_sumcheck_statement)?;
    let mut changed_claim = artifact.clone();
    changed_claim.outer_sumcheck_proof.claimed_sum = ChallengeField::ONE;
    let changed_claim_bytes =
        encode_canonical_artifact(&changed_claim, canonical_sumcheck_statement)?;
    require_verification_refusal(
        verify_canonical_artifact(
            &changed_claim_bytes,
            canonical_sumcheck_statement,
            input_identity_shake256_hex,
        ),
        "outer sumcheck claim",
    )?;

    let alternate_affine_valid_columns: [Vec<u64>; RELATION_COLUMN_COUNT] =
        std::array::from_fn(|column_index| {
            let constant_value = if column_index == 2 || column_index == 6 {
                1
            } else {
                0
            };
            vec![constant_value; RELATION_ROW_COUNT]
        });
    let alternate_commitment_bytes =
        derive_frozen_sumcheck_commitment(&alternate_affine_valid_columns)?;
    let expected_commitment_bytes = validated_frozen_sumcheck_public_statement(
        canonical_sumcheck_statement,
        input_identity_shake256_hex,
    )?
    .expected_sumcheck_commitment;
    if alternate_commitment_bytes == expected_commitment_bytes {
        return Err(
            "alternate affine-valid columns unexpectedly share the frozen commitment".to_owned(),
        );
    }
    let alternate_sumcheck_statement = canonical_frozen_sumcheck_public_statement(
        input_identity_shake256_hex,
        &alternate_commitment_bytes,
    )?;
    let alternate_statement_artifact =
        encode_canonical_artifact(&artifact, &alternate_sumcheck_statement)?;
    require_verification_refusal(
        verify_canonical_artifact(
            &alternate_statement_artifact,
            &alternate_sumcheck_statement,
            input_identity_shake256_hex,
        ),
        "alternate affine-valid commitment statement",
    )?;

    let mut changed_evaluation = artifact;
    let first_evaluation = changed_evaluation
        .opening_proof
        .evals
        .first_mut()
        .ok_or_else(|| "sumcheck-class artifact contains no opening evaluation".to_owned())?;
    *first_evaluation += ChallengeField::ONE;
    let changed_evaluation_bytes =
        encode_canonical_artifact(&changed_evaluation, canonical_sumcheck_statement)?;
    require_verification_refusal(
        verify_canonical_artifact(
            &changed_evaluation_bytes,
            canonical_sumcheck_statement,
            input_identity_shake256_hex,
        ),
        "authenticated opening evaluation",
    )?;

    let mut changed_identity_bytes = input_identity_shake256_hex.as_bytes().to_vec();
    let first_identity_byte = changed_identity_bytes
        .first_mut()
        .ok_or_else(|| "sumcheck-class public input identity is empty".to_owned())?;
    *first_identity_byte = if *first_identity_byte == b'0' {
        b'1'
    } else {
        b'0'
    };
    let changed_identity = String::from_utf8(changed_identity_bytes)
        .map_err(|error| format!("mutated public input identity is not UTF-8: {error}"))?;
    require_verification_refusal(
        verify_canonical_artifact(
            canonical_artifact,
            canonical_sumcheck_statement,
            &changed_identity,
        ),
        "public input identity",
    )?;

    let mut changed_statement = canonical_sumcheck_statement.to_vec();
    changed_statement.push(0);
    require_verification_refusal(
        verify_canonical_artifact(
            canonical_artifact,
            &changed_statement,
            input_identity_shake256_hex,
        ),
        "canonical public statement",
    )
}

fn verify_decoded_artifact(
    artifact: &SumcheckClassArtifact,
    canonical_sumcheck_statement: &[u8],
    commitment: &SumcheckClassCommitment,
) -> ProofBackendBakeoffResult<()> {
    let (pcs, parameters) = build_pcs()?;
    if artifact.outer_sumcheck_proof.claimed_sum != ChallengeField::ZERO {
        return Err("outer sumcheck claimed sum is not zero".to_owned());
    }
    let mut relation_challenger =
        fresh_relation_challenger(canonical_sumcheck_statement, &parameters)?;
    relation_challenger.observe(commitment.clone());
    let constraint_batching_challenge: ChallengeField =
        relation_challenger.sample_algebra_element();
    let equality_random_point = Point::new(
        (0..RELATION_VARIABLE_COUNT)
            .map(|_| relation_challenger.sample_algebra_element::<ChallengeField>())
            .collect(),
    );
    let (terminal_relation_point, terminal_sum) = artifact
        .outer_sumcheck_proof
        .verify(
            &mut relation_challenger,
            RELATION_VARIABLE_COUNT,
            OUTER_SUMCHECK_DEGREE,
            0,
        )
        .map_err(|error| format!("verify outer degree-two sumcheck: {error}"))?;
    let opening_points = chosen_column_points(&terminal_relation_point);

    let mut pcs_challenger = fresh_pcs_challenger(&pcs, &parameters)?;
    pcs.verify(
        commitment,
        &artifact.opening_proof,
        &mut pcs_challenger,
        opening_points,
    )
    .map_err(|error| format!("verify HidingWhir chosen openings: {error}"))?;
    if artifact.opening_proof.evals.len() != RELATION_COLUMN_COUNT {
        return Err("HidingWhir proof does not contain exactly eight evaluations".to_owned());
    }

    let first_residual = affine_residual(
        artifact.opening_proof.evals[0],
        artifact.opening_proof.evals[1],
        artifact.opening_proof.evals[2],
        artifact.opening_proof.evals[3],
    );
    let second_residual = affine_residual(
        artifact.opening_proof.evals[4],
        artifact.opening_proof.evals[5],
        artifact.opening_proof.evals[6],
        artifact.opening_proof.evals[7],
    );
    let terminal_residual = first_residual + constraint_batching_challenge * second_residual;
    let equality_at_terminal = equality_random_point
        .iter()
        .zip(terminal_relation_point.iter())
        .map(|(&left, &right)| {
            left * right + (ChallengeField::ONE - left) * (ChallengeField::ONE - right)
        })
        .product::<ChallengeField>();
    if terminal_sum != equality_at_terminal * terminal_residual {
        return Err("outer sumcheck terminal residual is not authenticated".to_owned());
    }
    Ok(())
}

fn validate_fixture(fixture: &ProofBackendBakeoffFixture) -> ProofBackendBakeoffResult<()> {
    let recomputed_identity = recompute_frozen_input_identity(&fixture.columns)?;
    if recomputed_identity != fixture.input_identity_shake256_hex {
        return Err(
            "sumcheck-class input identity does not match the exact eight columns".to_owned(),
        );
    }
    let bindings = validated_frozen_sumcheck_public_statement(
        &fixture.canonical_sumcheck_statement,
        &fixture.input_identity_shake256_hex,
    )?;
    if bindings.canonical_core_statement != fixture.canonical_core_statement
        || bindings.expected_sumcheck_commitment != fixture.expected_sumcheck_commitment
    {
        return Err("sumcheck-class fixture binding fields are stale".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_query_opening_wire(
        query: &SumcheckClassQueryOpening,
    ) -> ProofBackendBakeoffResult<Vec<u8>> {
        postcard::to_allocvec(&SumcheckClassQueryOpeningWireReference { query })
            .map_err(|error| format!("encode test query opening wire: {error}"))
    }

    fn decode_canonical_query_opening_wire(
        canonical: &[u8],
    ) -> ProofBackendBakeoffResult<SumcheckClassQueryOpeningWire> {
        let (query, trailing_bytes) =
            postcard::take_from_bytes::<SumcheckClassQueryOpeningWire>(canonical)
                .map_err(|error| format!("decode test query opening wire: {error}"))?;
        if !trailing_bytes.is_empty() {
            return Err("test query opening wire has trailing bytes".to_owned());
        }
        let reencoded = postcard::to_allocvec(&query)
            .map_err(|error| format!("re-encode test query opening wire: {error}"))?;
        if reencoded != canonical {
            return Err("test query opening wire is not canonical".to_owned());
        }
        Ok(query)
    }

    fn single_digest_cap(digest_word: u64) -> SumcheckClassCommitment {
        vec![[digest_word; MERKLE_DIGEST_WORD_LENGTH]].into()
    }

    fn merkle_path(path_length: usize, digest_word: u64) -> SumcheckClassMerkleProof {
        vec![[digest_word; MERKLE_DIGEST_WORD_LENGTH]; path_length]
    }

    fn base_query_opening(
        value_length: usize,
        path_length: usize,
        value: u64,
    ) -> SumcheckClassQueryOpening {
        QueryOpening::Base {
            values: vec![BaseField::from_u64(value); value_length],
            proof: merkle_path(path_length, value),
        }
    }

    fn extension_query_opening(
        value_length: usize,
        path_length: usize,
        value: u64,
    ) -> SumcheckClassQueryOpening {
        QueryOpening::Extension {
            values: vec![ChallengeField::from_u64(value); value_length],
            proof: merkle_path(path_length, value),
        }
    }

    fn synthetic_canonical_artifact_shape() -> SumcheckClassArtifact {
        let outer_sumcheck_proof = GenericDegreeProof {
            claimed_sum: ChallengeField::ZERO,
            round_polys: vec![
                vec![ChallengeField::ZERO; OUTER_SUMCHECK_DEGREE];
                RELATION_VARIABLE_COUNT
            ],
            pow_witnesses: Vec::new(),
        };
        let sumchecks = EXPECTED_FOLDING_SCHEDULE
            .iter()
            .map(|&round_count| ZkSumcheckData {
                mu_tilde: ChallengeField::ZERO,
                ell_zk: MASK_MESSAGE_LENGTH,
                round_coefficients: vec![
                    vec![ChallengeField::ZERO; MASK_MESSAGE_LENGTH - 1];
                    round_count
                ],
                pow_witnesses: Vec::new(),
            })
            .collect();
        let sumcheck_mask_commitments = (0..EXPECTED_FOLDING_SCHEDULE.len())
            .map(|commitment_index| single_digest_cap(commitment_index as u64 + 1))
            .collect();
        let rounds = vec![
            SumcheckClassRoundProof {
                commitment: single_digest_cap(11),
                mask_commitment: single_digest_cap(12),
                ood_answers: Vec::new(),
                pow_witness: BaseField::ZERO,
                queries: vec![
                    base_query_opening(
                        EXPECTED_ROUND_QUERY_VALUE_LENGTHS[0],
                        EXPECTED_ROUND_QUERY_PATH_LENGTHS[0],
                        13,
                    );
                    EXPECTED_ROUND_QUERY_COUNTS[0]
                ],
            },
            SumcheckClassRoundProof {
                commitment: single_digest_cap(21),
                mask_commitment: single_digest_cap(22),
                ood_answers: Vec::new(),
                pow_witness: BaseField::ZERO,
                queries: vec![
                    extension_query_opening(
                        EXPECTED_ROUND_QUERY_VALUE_LENGTHS[1],
                        EXPECTED_ROUND_QUERY_PATH_LENGTHS[1],
                        23,
                    );
                    EXPECTED_ROUND_QUERY_COUNTS[1]
                ],
            },
        ];
        let blinded_masks = EXPECTED_BLINDED_MASK_MESSAGE_LENGTHS
            .into_iter()
            .map(|message_length| BlindedMask {
                message: vec![ChallengeField::ZERO; message_length],
                randomness: vec![ChallengeField::ZERO; EXPECTED_MASK_QUERY_COUNT],
            })
            .collect();
        let mask_queries = EXPECTED_MASK_GROUP_WIDTHS
            .into_iter()
            .zip(EXPECTED_MASK_GROUP_PATH_LENGTHS)
            .enumerate()
            .map(|(group_index, (value_length, path_length))| {
                let opening_pair = SumcheckClassMaskOpeningPair {
                    carried: extension_query_opening(
                        value_length,
                        path_length,
                        31 + group_index as u64,
                    ),
                    fresh: extension_query_opening(
                        value_length,
                        path_length,
                        41 + group_index as u64,
                    ),
                };
                vec![opening_pair; EXPECTED_MASK_QUERY_COUNT]
            })
            .collect();
        let base_case = SumcheckClassBaseCaseProof {
            fresh_main_commitment: single_digest_cap(51),
            fresh_mask_commitments: (0..EXPECTED_MASK_GROUP_WIDTHS.len())
                .map(|commitment_index| single_digest_cap(52 + commitment_index as u64))
                .collect(),
            masked_claim: ChallengeField::ZERO,
            blinded_message: vec![ChallengeField::ZERO; 32],
            blinded_randomness: vec![ChallengeField::ZERO; EXPECTED_FINAL_QUERY_COUNT],
            blinded_masks,
            pow_witness: BaseField::ZERO,
            source_queries: vec![
                extension_query_opening(
                    EXPECTED_SOURCE_QUERY_VALUE_LENGTH,
                    EXPECTED_SOURCE_QUERY_PATH_LENGTH,
                    61,
                );
                EXPECTED_FINAL_QUERY_COUNT
            ],
            fresh_main_queries: vec![
                extension_query_opening(
                    EXPECTED_FRESH_MAIN_QUERY_VALUE_LENGTH,
                    EXPECTED_FRESH_MAIN_QUERY_PATH_LENGTH,
                    62,
                );
                EXPECTED_FINAL_QUERY_COUNT
            ],
            mask_queries,
        };
        SumcheckClassArtifact {
            outer_sumcheck_proof,
            opening_proof: ZkWhirProof {
                evals: vec![ChallengeField::ZERO; RELATION_COLUMN_COUNT],
                sumchecks,
                sumcheck_mask_commitments,
                rounds,
                base_case,
            },
        }
    }

    fn decode_synthetic_artifact_wire() -> SumcheckClassArtifactWire {
        let artifact = synthetic_canonical_artifact_shape();
        let bytes = postcard::to_allocvec(&SumcheckClassArtifactWireReference {
            artifact: &artifact,
        })
        .expect("encode synthetic canonical artifact wire");
        let (wire, trailing_bytes) = postcard::take_from_bytes::<SumcheckClassArtifactWire>(&bytes)
            .expect("decode synthetic canonical artifact wire");
        assert!(trailing_bytes.is_empty());
        wire
    }

    #[derive(Clone, Copy)]
    enum ArtifactQueryLocation {
        CodeSwitchRound,
        BaseCaseSource,
        BaseCaseFreshMain,
        BaseCaseMaskCarried,
        BaseCaseMaskFresh,
    }

    fn artifact_query_at_location(
        wire: &mut SumcheckClassArtifactWire,
        location: ArtifactQueryLocation,
    ) -> &mut SumcheckClassQueryOpeningWire {
        match location {
            ArtifactQueryLocation::CodeSwitchRound => &mut wire.opening_proof.rounds[0].queries[0],
            ArtifactQueryLocation::BaseCaseSource => {
                &mut wire.opening_proof.base_case.source_queries[0]
            }
            ArtifactQueryLocation::BaseCaseFreshMain => {
                &mut wire.opening_proof.base_case.fresh_main_queries[0]
            }
            ArtifactQueryLocation::BaseCaseMaskCarried => {
                &mut wire.opening_proof.base_case.mask_queries[0][0].carried
            }
            ArtifactQueryLocation::BaseCaseMaskFresh => {
                &mut wire.opening_proof.base_case.mask_queries[0][0].fresh
            }
        }
    }

    fn query_with_opposite_tag(
        query: &SumcheckClassQueryOpeningWire,
    ) -> SumcheckClassQueryOpeningWire {
        match query {
            SumcheckClassQueryOpeningWire::Base { values, proof } => {
                SumcheckClassQueryOpeningWire::Extension {
                    values: vec![ChallengeField::ZERO; values.len()],
                    proof: proof.clone(),
                }
            }
            SumcheckClassQueryOpeningWire::Extension { values, proof } => {
                SumcheckClassQueryOpeningWire::Base {
                    values: vec![BaseField::ZERO; values.len()],
                    proof: proof.clone(),
                }
            }
        }
    }

    fn remove_one_opened_value(query: &mut SumcheckClassQueryOpeningWire) {
        match query {
            SumcheckClassQueryOpeningWire::Base { values, .. } => {
                values.pop();
            }
            SumcheckClassQueryOpeningWire::Extension { values, .. } => {
                values.pop();
            }
        }
    }

    fn remove_one_merkle_path_digest(query: &mut SumcheckClassQueryOpeningWire) {
        match query {
            SumcheckClassQueryOpeningWire::Base { proof, .. }
            | SumcheckClassQueryOpeningWire::Extension { proof, .. } => {
                proof.pop();
            }
        }
    }

    fn decoded_cap_with_root_count(root_count: usize) -> SumcheckClassCommitment {
        let roots = vec![[91; MERKLE_DIGEST_WORD_LENGTH]; root_count];
        let wire = postcard::to_allocvec(&roots).expect("encode test Merkle roots");
        postcard::from_bytes(&wire).expect("decode test Merkle cap without constructor checks")
    }

    fn synthetic_fixture() -> ProofBackendBakeoffFixture {
        frozen_fixture().expect("exact frozen backend-bakeoff fixture")
    }

    #[test]
    fn query_opening_wire_uses_stable_external_numeric_tags() {
        let base_proof = vec![[0, 1, u32::MAX as u64, u64::MAX, 5, 8, 13, 21]];
        let base_query: SumcheckClassQueryOpening = QueryOpening::Base {
            values: vec![BaseField::ZERO, BaseField::ONE, BaseField::from_u64(257)],
            proof: base_proof.clone(),
        };
        let base_bytes = encode_query_opening_wire(&base_query).expect("encode base query tag");
        assert_eq!(
            base_bytes.first().copied(),
            Some(QUERY_OPENING_BASE_TAG as u8)
        );
        let decoded_base =
            decode_canonical_query_opening_wire(&base_bytes).expect("decode base query tag");
        let SumcheckClassQueryOpeningWire::Base { values, proof } = decoded_base else {
            panic!("base query tag decoded as extension");
        };
        assert_eq!(
            values,
            [BaseField::ZERO, BaseField::ONE, BaseField::from_u64(257)]
        );
        assert_eq!(proof, base_proof);

        let extension_proof = vec![[34, 55, 89, 144, 233, 377, 610, 987]];
        let extension_query: SumcheckClassQueryOpening = QueryOpening::Extension {
            values: vec![
                ChallengeField::ZERO,
                ChallengeField::ONE,
                ChallengeField::from_u64(65_537),
            ],
            proof: extension_proof.clone(),
        };
        let extension_bytes =
            encode_query_opening_wire(&extension_query).expect("encode extension query tag");
        assert_eq!(
            extension_bytes.first().copied(),
            Some(QUERY_OPENING_EXTENSION_TAG as u8)
        );
        let decoded_extension = decode_canonical_query_opening_wire(&extension_bytes)
            .expect("decode extension query tag");
        let SumcheckClassQueryOpeningWire::Extension { values, proof } = decoded_extension else {
            panic!("extension query tag decoded as base");
        };
        assert_eq!(
            values,
            [
                ChallengeField::ZERO,
                ChallengeField::ONE,
                ChallengeField::from_u64(65_537),
            ]
        );
        assert_eq!(proof, extension_proof);
    }

    #[test]
    fn query_opening_wire_rejects_malformed_trailing_and_noncanonical_bytes() {
        assert!(decode_canonical_query_opening_wire(&[2]).is_err());
        assert!(decode_canonical_query_opening_wire(&[QUERY_OPENING_BASE_TAG as u8]).is_err());

        let empty_base_query: SumcheckClassQueryOpening = QueryOpening::Base {
            values: Vec::new(),
            proof: Vec::new(),
        };
        let canonical =
            encode_query_opening_wire(&empty_base_query).expect("encode empty base query");
        assert_eq!(canonical, [0, 0, 0]);

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(decode_canonical_query_opening_wire(&trailing).is_err());

        let noncanonical = [0x80, 0x00, 0x00, 0x00];
        let (decoded_noncanonical, trailing_bytes) =
            postcard::take_from_bytes::<SumcheckClassQueryOpeningWire>(&noncanonical)
                .expect("postcard accepts an overlong zero tag before the canonicality gate");
        assert!(trailing_bytes.is_empty());
        assert_ne!(
            postcard::to_allocvec(&decoded_noncanonical)
                .expect("re-encode overlong zero query tag"),
            noncanonical
        );
        assert!(decode_canonical_query_opening_wire(&noncanonical).is_err());
    }

    #[test]
    fn canonical_artifact_body_ceiling_matches_the_checked_profile_formula() {
        assert_eq!(
            EXPECTED_FOLDING_SCHEDULE,
            [CONSTANT_FOLDING_FACTOR; EXPECTED_FOLDING_SCHEDULE.len()]
        );
        assert_eq!(MAXIMUM_SINGLE_DIGEST_CAP_BYTE_LENGTH, 81);
        assert_eq!(MAXIMUM_OUTER_SUMCHECK_PROOF_BYTE_LENGTH, 1_466);
        assert_eq!(MAXIMUM_MASKED_SUMCHECK_BYTE_LENGTH, 9_057);
        assert_eq!(MAXIMUM_FIRST_ROUND_QUERY_BYTE_LENGTH, 1_283);
        assert_eq!(MAXIMUM_SECOND_ROUND_QUERY_BYTE_LENGTH, 1_843);
        assert_eq!(MAXIMUM_FIRST_ROUND_BYTE_LENGTH, 743_032);
        assert_eq!(MAXIMUM_SECOND_ROUND_BYTE_LENGTH, 486_727);
        assert_eq!(MAXIMUM_BLINDED_MASKS_BYTE_LENGTH, 262_995);
        assert_eq!(MAXIMUM_SOURCE_QUERY_BYTE_LENGTH, 1_763);
        assert_eq!(MAXIMUM_FRESH_MAIN_QUERY_BYTE_LENGTH, 1_013);
        assert_eq!(
            maximum_query_opening_byte_length(
                EXPECTED_MASK_GROUP_WIDTHS[0],
                MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
                EXPECTED_MASK_GROUP_PATH_LENGTHS[0],
            ),
            1_323
        );
        assert_eq!(
            maximum_query_opening_byte_length(
                EXPECTED_MASK_GROUP_WIDTHS[1],
                MAXIMUM_CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH,
                EXPECTED_MASK_GROUP_PATH_LENGTHS[1],
            ),
            1_253
        );
        assert_eq!(MAXIMUM_MASK_QUERY_GROUPS_BYTE_LENGTH, 3_574_211);
        assert_eq!(MAXIMUM_BASE_CASE_BYTE_LENGTH, 4_526_078);
        assert_eq!(MAXIMUM_OPENING_PROOF_BYTE_LENGTH, 5_783_655);
        assert_eq!(MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH, 5_785_122);
        require_canonical_artifact_body_within_ceiling(MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH)
            .expect("the exact ceiling is accepted");
        assert!(
            require_canonical_artifact_body_within_ceiling(
                MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn query_opening_shape_gate_checks_base_and_extension_widths_and_paths() {
        let honest_base = base_query_opening(
            EXPECTED_ROUND_QUERY_VALUE_LENGTHS[0],
            EXPECTED_ROUND_QUERY_PATH_LENGTHS[0],
            71,
        );
        let honest_base_bytes =
            encode_query_opening_wire(&honest_base).expect("encode honest base opening");
        let mut base_wire = decode_canonical_query_opening_wire(&honest_base_bytes)
            .expect("decode honest base opening");
        require_query_opening_shape(
            &base_wire,
            SumcheckClassQueryOpeningKind::Base,
            EXPECTED_ROUND_QUERY_VALUE_LENGTHS[0],
            EXPECTED_ROUND_QUERY_PATH_LENGTHS[0],
            "test base opening",
        )
        .expect("honest base opening shape");
        match &mut base_wire {
            SumcheckClassQueryOpeningWire::Base { values, .. } => {
                values.pop();
            }
            SumcheckClassQueryOpeningWire::Extension { .. } => {
                panic!("base opening decoded as extension");
            }
        }
        assert!(
            require_query_opening_shape(
                &base_wire,
                SumcheckClassQueryOpeningKind::Base,
                EXPECTED_ROUND_QUERY_VALUE_LENGTHS[0],
                EXPECTED_ROUND_QUERY_PATH_LENGTHS[0],
                "short base opening",
            )
            .is_err()
        );
        match &mut base_wire {
            SumcheckClassQueryOpeningWire::Base { values, proof } => {
                values.push(BaseField::ZERO);
                proof.pop();
            }
            SumcheckClassQueryOpeningWire::Extension { .. } => {
                panic!("base opening decoded as extension");
            }
        }
        assert!(
            require_query_opening_shape(
                &base_wire,
                SumcheckClassQueryOpeningKind::Base,
                EXPECTED_ROUND_QUERY_VALUE_LENGTHS[0],
                EXPECTED_ROUND_QUERY_PATH_LENGTHS[0],
                "short base path",
            )
            .is_err()
        );

        let honest_extension = extension_query_opening(
            EXPECTED_ROUND_QUERY_VALUE_LENGTHS[1],
            EXPECTED_ROUND_QUERY_PATH_LENGTHS[1],
            72,
        );
        let honest_extension_bytes =
            encode_query_opening_wire(&honest_extension).expect("encode honest extension opening");
        let mut extension_wire = decode_canonical_query_opening_wire(&honest_extension_bytes)
            .expect("decode honest extension opening");
        require_query_opening_shape(
            &extension_wire,
            SumcheckClassQueryOpeningKind::Extension,
            EXPECTED_ROUND_QUERY_VALUE_LENGTHS[1],
            EXPECTED_ROUND_QUERY_PATH_LENGTHS[1],
            "test extension opening",
        )
        .expect("honest extension opening shape");
        match &mut extension_wire {
            SumcheckClassQueryOpeningWire::Extension { values, .. } => {
                values.push(ChallengeField::ZERO);
            }
            SumcheckClassQueryOpeningWire::Base { .. } => {
                panic!("extension opening decoded as base");
            }
        }
        assert!(
            require_query_opening_shape(
                &extension_wire,
                SumcheckClassQueryOpeningKind::Extension,
                EXPECTED_ROUND_QUERY_VALUE_LENGTHS[1],
                EXPECTED_ROUND_QUERY_PATH_LENGTHS[1],
                "long extension opening",
            )
            .is_err()
        );
        match &mut extension_wire {
            SumcheckClassQueryOpeningWire::Extension { values, proof } => {
                values.pop();
                proof.push([0; MERKLE_DIGEST_WORD_LENGTH]);
            }
            SumcheckClassQueryOpeningWire::Base { .. } => {
                panic!("extension opening decoded as base");
            }
        }
        assert!(
            require_query_opening_shape(
                &extension_wire,
                SumcheckClassQueryOpeningKind::Extension,
                EXPECTED_ROUND_QUERY_VALUE_LENGTHS[1],
                EXPECTED_ROUND_QUERY_PATH_LENGTHS[1],
                "long extension path",
            )
            .is_err()
        );
    }

    #[test]
    fn complete_artifact_wire_roundtrips_into_fresh_verifier_types() {
        let artifact = synthetic_canonical_artifact_shape();
        let canonical = postcard::to_allocvec(&SumcheckClassArtifactWireReference {
            artifact: &artifact,
        })
        .expect("encode complete artifact wire");
        assert!(canonical.len() < MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH);
        let (wire, trailing_bytes) =
            postcard::take_from_bytes::<SumcheckClassArtifactWire>(&canonical)
                .expect("decode complete artifact wire");
        assert!(trailing_bytes.is_empty());
        wire.validate_exact_shape()
            .expect("validate complete artifact wire shape");
        let decoded_artifact = wire.into_artifact();
        let reencoded = postcard::to_allocvec(&SumcheckClassArtifactWireReference {
            artifact: &decoded_artifact,
        })
        .expect("re-encode complete artifact wire");
        assert_eq!(reencoded, canonical);
    }

    #[test]
    fn complete_artifact_wire_rejects_each_query_location_shape_mutation() {
        let locations = [
            ArtifactQueryLocation::CodeSwitchRound,
            ArtifactQueryLocation::BaseCaseSource,
            ArtifactQueryLocation::BaseCaseFreshMain,
            ArtifactQueryLocation::BaseCaseMaskCarried,
            ArtifactQueryLocation::BaseCaseMaskFresh,
        ];
        for location in locations {
            let mut wire = decode_synthetic_artifact_wire();
            let original = artifact_query_at_location(&mut wire, location).clone();

            *artifact_query_at_location(&mut wire, location) = query_with_opposite_tag(&original);
            assert!(wire.validate_exact_shape().is_err());

            *artifact_query_at_location(&mut wire, location) = original.clone();
            remove_one_opened_value(artifact_query_at_location(&mut wire, location));
            assert!(wire.validate_exact_shape().is_err());

            *artifact_query_at_location(&mut wire, location) = original.clone();
            remove_one_merkle_path_digest(artifact_query_at_location(&mut wire, location));
            assert!(wire.validate_exact_shape().is_err());

            *artifact_query_at_location(&mut wire, location) = original;
            wire.validate_exact_shape()
                .expect("restored query location shape");
        }
    }

    #[test]
    fn complete_artifact_wire_rejects_wrong_size_caps_at_every_location() {
        for invalid_root_count in [0, 2] {
            for cap_location in 0..5 {
                let mut wire = decode_synthetic_artifact_wire();
                let invalid_cap = decoded_cap_with_root_count(invalid_root_count);
                match cap_location {
                    0 => wire.opening_proof.sumcheck_mask_commitments[0] = invalid_cap,
                    1 => wire.opening_proof.rounds[0].commitment = invalid_cap,
                    2 => wire.opening_proof.rounds[0].mask_commitment = invalid_cap,
                    3 => wire.opening_proof.base_case.fresh_main_commitment = invalid_cap,
                    4 => wire.opening_proof.base_case.fresh_mask_commitments[0] = invalid_cap,
                    _ => unreachable!("five cap locations"),
                }
                assert!(wire.validate_exact_shape().is_err());
            }

            let public_commitment = decoded_cap_with_root_count(invalid_root_count);
            let public_commitment_bytes = postcard::to_allocvec(&public_commitment)
                .expect("encode invalid public commitment cap");
            assert!(decode_canonical_sumcheck_commitment(&public_commitment_bytes).is_err());
        }
    }

    #[test]
    fn complete_artifact_wire_rejects_schema_and_container_count_mutations() {
        let mut wrong_schema = decode_synthetic_artifact_wire();
        wrong_schema.schema_version = CANONICAL_ARTIFACT_WIRE_SCHEMA_VERSION + 1;
        assert!(wrong_schema.validate_exact_shape().is_err());

        for container_location in 0..3 {
            let mut wire = decode_synthetic_artifact_wire();
            match container_location {
                0 => {
                    wire.opening_proof.sumchecks.pop();
                }
                1 => {
                    wire.opening_proof.rounds.pop();
                }
                2 => {
                    wire.opening_proof.base_case.mask_queries.pop();
                }
                _ => unreachable!("three representative container locations"),
            }
            assert!(wire.validate_exact_shape().is_err());
        }
    }

    #[test]
    fn complete_artifact_decoder_rejects_oversized_truncated_and_noncanonical_bodies() {
        let fixture = synthetic_fixture();
        let canonical_statement = fixture.canonical_sumcheck_statement.as_slice();
        let artifact = synthetic_canonical_artifact_shape();
        let canonical = encode_canonical_artifact(&artifact, canonical_statement)
            .expect("encode synthetic complete canonical artifact");
        let header = canonical_proof_object_header_bytes(canonical_statement)
            .expect("encode synthetic canonical proof header");

        let mut oversized = header.clone();
        oversized.resize(
            header.len() + MAXIMUM_CANONICAL_ARTIFACT_BODY_BYTE_LENGTH + 1,
            0,
        );
        let Err(oversized_error) = decode_canonical_artifact(&oversized, canonical_statement)
        else {
            panic!("oversized complete artifact body was accepted");
        };
        assert!(
            oversized_error.contains("codec ceiling"),
            "{oversized_error}"
        );

        let mut truncated = canonical.clone();
        truncated.pop();
        assert!(decode_canonical_artifact(&truncated, canonical_statement).is_err());

        let first_claimed_sum_limb_offset = header.len() + 1;
        assert_eq!(canonical[first_claimed_sum_limb_offset], 0);
        let mut noncanonical = canonical;
        noncanonical.splice(
            first_claimed_sum_limb_offset..first_claimed_sum_limb_offset + 1,
            [0x80, 0x00],
        );
        let Err(noncanonical_error) = decode_canonical_artifact(&noncanonical, canonical_statement)
        else {
            panic!("overlong complete artifact scalar encoding was accepted");
        };
        assert!(
            noncanonical_error.contains("not canonical"),
            "{noncanonical_error}"
        );
    }

    #[test]
    fn degree_two_round_polynomial_matches_direct_hypercube_sum() {
        let equality_polynomial = Poly::new(vec![
            ChallengeField::from_u64(2),
            ChallengeField::from_u64(3),
            ChallengeField::from_u64(5),
            ChallengeField::from_u64(7),
        ]);
        let combined_residual_polynomial = Poly::new(vec![
            ChallengeField::from_u64(11),
            ChallengeField::from_u64(13),
            ChallengeField::from_u64(17),
            ChallengeField::from_u64(19),
        ]);
        let prover = DegreeTwoRelationProver {
            equality_polynomial,
            combined_residual_polynomial,
        };
        let evaluations = prover.round_poly();
        assert_eq!(evaluations.len(), 2);
        assert_eq!(evaluations[0], ChallengeField::from_u64(61));
        assert_eq!(
            evaluations[1],
            (ChallengeField::from_u64(8) * ChallengeField::from_u64(23))
                + (ChallengeField::from_u64(11) * ChallengeField::from_u64(25))
        );
    }

    #[test]
    fn fixture_validation_rejects_each_affine_half_mutation() {
        let fixture = synthetic_fixture();
        validate_fixture(&fixture).expect("honest synthetic fixture");
        for column_index in 0..RELATION_COLUMN_COUNT {
            let mut mutated = fixture.clone();
            mutated.columns[column_index][9] += 1;
            assert!(validate_fixture(&mutated).is_err());
        }

        let mut relation_preserving_mutation = fixture.clone();
        for (column_index, value) in [0_u64, 0, 1, 0].into_iter().enumerate() {
            relation_preserving_mutation.columns[column_index][0] = value;
        }
        assert!(
            recompute_frozen_input_identity(&relation_preserving_mutation.columns).is_ok(),
            "the mutation must preserve all public relation checks"
        );
        assert!(validate_fixture(&relation_preserving_mutation).is_err());

        let mut wrong_identity = fixture.clone();
        wrong_identity
            .input_identity_shake256_hex
            .replace_range(..1, "0");
        if wrong_identity.input_identity_shake256_hex == fixture.input_identity_shake256_hex {
            wrong_identity
                .input_identity_shake256_hex
                .replace_range(..1, "1");
        }
        assert!(validate_fixture(&wrong_identity).is_err());

        let mut stale_sumcheck_binding = fixture.clone();
        stale_sumcheck_binding.expected_sumcheck_commitment[0] ^= 1;
        assert!(validate_fixture(&stale_sumcheck_binding).is_err());

        let mut stale_core_statement_binding = fixture.clone();
        stale_core_statement_binding
            .canonical_core_statement
            .push(0);
        assert!(validate_fixture(&stale_core_statement_binding).is_err());

        let mut wrong_statement = fixture;
        wrong_statement.canonical_sumcheck_statement.push(0);
        assert!(validate_fixture(&wrong_statement).is_err());
    }

    #[test]
    fn hiding_whir_configuration_matches_the_exact_conservative_profile() {
        let config = build_configuration().expect("frozen HidingWhir configuration");
        let budget =
            validate_security_budgets(&config).expect("frozen HidingWhir security budgets");

        assert_eq!(
            config.params.security_level,
            INTERNAL_BRANCH_SECURITY_PARAMETER
        );
        assert_eq!(config.params.pow_bits, GRINDING_BIT_CEILING);
        assert_eq!(
            config.params.soundness_type,
            SecurityAssumption::UniqueDecoding
        );
        assert_eq!(config.zk.ell_zk, MASK_MESSAGE_LENGTH);
        assert_eq!(budget.maximum_pow_bits, GRINDING_BIT_CEILING);
        assert_eq!(config.folding_schedule, EXPECTED_FOLDING_SCHEDULE);
        assert_eq!(
            config
                .round_parameters
                .iter()
                .map(|round| round.num_queries)
                .collect::<Vec<_>>(),
            EXPECTED_ROUND_QUERY_COUNTS
        );
        assert_eq!(config.final_queries, EXPECTED_FINAL_QUERY_COUNT);
        assert_eq!(config.oracle_randomness, EXPECTED_ORACLE_RANDOMNESS_LENGTHS);
        assert_eq!(config.commitment_ood_samples, 0);
        assert_eq!(config.mask_queries, 276);
        assert_eq!(
            (
                config.sumcheck_mask.message_len,
                config.sumcheck_mask.randomness_len,
                config.sumcheck_mask.domain_size,
            ),
            (46, 276, 16_384)
        );
        assert_eq!(
            config
                .switch_masks
                .iter()
                .map(|shape| (shape.message_len, shape.randomness_len, shape.domain_size))
                .collect::<Vec<_>>(),
            [(579, 276, 32_768), (264, 276, 32_768)]
        );
        assert_eq!(MERKLE_DIGEST_BYTE_LENGTH, 64);

        let parameters = parameter_record(&config).expect("operative parameter record");
        assert_eq!(parameters.schema_version, 5);
        assert_eq!(
            parameters.merkle_digest_byte_length,
            MERKLE_DIGEST_BYTE_LENGTH as u8
        );
        assert_eq!(
            parameters.challenger_output_byte_length,
            CHALLENGER_OUTPUT_BYTE_LENGTH as u8
        );
        assert_eq!(parameters.mask_query_count, config.mask_queries as u16);
        assert_eq!(parameters.commitment_out_of_domain_sample_count, 0);
        assert_eq!(parameters.derived_folding_schedule, [4, 4, 4]);
        assert_eq!(
            parameters
                .rounds
                .iter()
                .map(|round| (
                    round.variable_count,
                    round.log_inverse_rate,
                    round.domain_size,
                    round.query_count,
                    round.pow_bits,
                    round.out_of_domain_sample_count,
                    round.folding_pow_bits,
                ))
                .collect::<Vec<_>>(),
            [
                (13, 4, 262_144, 579, 20, 0, 0),
                (9, 7, 131_072, 264, 20, 0, 0),
            ]
        );
    }

    #[test]
    fn altered_local_operative_profile_changes_the_transcript() {
        let config = build_configuration().expect("frozen HidingWhir configuration");
        let parameters = parameter_record(&config).expect("frozen operative parameter record");
        let mut altered_parameters = parameters.clone();
        altered_parameters.final_query_count = altered_parameters
            .final_query_count
            .checked_sub(1)
            .expect("the frozen final query count is positive");
        assert_ne!(altered_parameters, parameters);

        let canonical_statement = b"sumcheck-class local profile transcript test";
        let transcript = relation_transcript_initial_state(canonical_statement, &parameters)
            .expect("frozen relation transcript");
        let altered_transcript =
            relation_transcript_initial_state(canonical_statement, &altered_parameters)
                .expect("altered relation transcript");
        assert_ne!(transcript, altered_transcript);
    }

    #[test]
    fn exact_unique_decoding_query_mask_and_aggregate_bounds_are_minimal() {
        for (log_inverse_rate, query_count, grinding_bits) in
            [(1, 579, 20), (4, 264, 20), (7, 243, 20)]
        {
            assert!(
                exact_unique_decoding_query_bound_holds(
                    log_inverse_rate,
                    query_count,
                    grinding_bits,
                    260,
                )
                .expect("exact unique-decoding inequality")
            );
            assert!(
                !exact_unique_decoding_query_bound_holds(
                    log_inverse_rate,
                    query_count,
                    grinding_bits - 1,
                    260,
                )
                .expect("exact unique-decoding grinding minimality")
            );
            assert!(
                exact_unique_decoding_query_bound_holds(log_inverse_rate, query_count, 0, 240,)
                    .expect("exact algebraic unique-decoding inequality")
            );
            assert!(!exact_unique_decoding_query_bound_holds(
                log_inverse_rate,
                query_count - 1,
                0,
                240,
            )
            .expect("exact unique-decoding query minimality"));
        }
        assert!(
            exact_unique_decoding_mask_union_bound_holds(6, 276, 261)
                .expect("exact mask union inequality")
        );
        assert!(
            !exact_unique_decoding_mask_union_bound_holds(6, 276, 262)
                .expect("exact mask union minimality")
        );
        assert!(
            exact_unique_decoding_rbr_aggregate_bound_holds(
                &[(1, 579, 20), (4, 264, 20), (7, 243, 20)],
                276,
                258,
            )
            .expect("exact unique-decoding RBR aggregate gate")
        );
        assert!(
            !exact_unique_decoding_rbr_aggregate_bound_holds(
                &[(1, 576, 20), (4, 262, 20), (7, 242, 20)],
                275,
                258,
            )
            .expect("lower internal parameter RBR aggregate gate")
        );
    }

    #[test]
    fn unique_decoding_algebraic_outer_hash_and_fiat_shamir_bounds_clear_the_floor() {
        let challenge_field_order = challenge_field_order();
        let fold_failure_numerator: u64 = UNIQUE_DECODING_FOLD_FAILURE_NUMERATORS.iter().sum();
        assert_eq!(fold_failure_numerator, 458_758);
        assert_eq!(
            fold_failure_numerator
                + UNIQUE_DECODING_QUERY_COMBINATION_FAILURE_NUMERATOR
                + UNIQUE_DECODING_FINAL_FOLDING_FAILURE_NUMERATOR
                + OUTER_RELATION_FAILURE_NUMERATOR as u64,
            UNIQUE_DECODING_AGGREGATE_ALGEBRAIC_FAILURE_NUMERATOR
        );
        assert!(
            (BigUint::from(UNIQUE_DECODING_AGGREGATE_ALGEBRAIC_FAILURE_NUMERATOR)
                << UNIQUE_DECODING_ALGEBRAIC_SECURITY_PARAMETER)
                < challenge_field_order
        );

        assert!(
            (BigUint::from(OUTER_RELATION_FAILURE_NUMERATOR) << 309_usize) < challenge_field_order,
            "43 / |Goldilocks^5| must be strictly below 2^-309"
        );
        assert!(exact_classical_fiat_shamir_work_factor_bound_holds());
    }

    #[test]
    fn merkle_word_encoding_preserves_all_64_shake256_bytes() {
        let hasher = DomainSeparatedShake256 {
            domain: b"proof-backend-bakeoff/sumcheck-class/digest-encoding-test/v1",
        };
        let input_words = [0_u64, 1, u32::MAX as u64, u64::MAX, 0x0123_4567_89ab_cdef];
        let byte_digest = <DomainSeparatedShake256 as CryptographicHasher<
            u8,
            [u8; MERKLE_DIGEST_BYTE_LENGTH],
        >>::hash_iter(
            &hasher, input_words.into_iter().flat_map(u64::to_le_bytes)
        );
        let word_digest = <DomainSeparatedShake256 as CryptographicHasher<
            u64,
            [u64; MERKLE_DIGEST_WORD_LENGTH],
        >>::hash_iter(&hasher, input_words);
        let reencoded_word_digest: Vec<u8> =
            word_digest.into_iter().flat_map(u64::to_le_bytes).collect();

        assert_eq!(byte_digest.len(), 64);
        assert_eq!(reencoded_word_digest, byte_digest);
    }
}
