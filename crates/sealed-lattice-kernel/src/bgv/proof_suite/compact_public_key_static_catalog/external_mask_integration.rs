//! Focused owner for the outer CFW relation handoff into hiding WHIR.
//!
//! The fixture is deliberately small, but it uses the production quintic
//! Goldilocks challenge field and the same generic WHIR path as the compact
//! catalog. It checks the load-bearing chronology:
//!
//! ```text
//! inner mask root -> extension-source root -> outer mask root
//!                 -> disclosed relation values -> batching challenge
//! ```

use p3_challenger::{CanObserve, FieldChallenger, HashChallenger, SerializingChallenger64};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{PrimeCharacteristicRing, PrimeField64, dot_product};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::zk::stack_codewords;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use p3_whir::pcs::zk::{
    CombinedRelationProverInput, CombinedRelationVerifierInput, HidingWhirProver,
    HidingWhirRelationInputError, HidingWhirVerifier, MaskCodeShape, MaskGroupShape,
    MaskProverData, PrecommittedMaskProverGroup, PrecommittedMaskVerifierGroup, ZkVerifierError,
    ZkWhirConfig, ZkWhirProof,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, ZkParameters};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::ChallengeField;

const TEST_HASH_OUTPUT_BYTE_LENGTH: usize = 64;
const TEST_HASH_OUTPUT_WORD_LENGTH: usize = TEST_HASH_OUTPUT_BYTE_LENGTH / size_of::<u64>();
const TEST_MAIN_LOG_INVERSE_RATE: usize = 2;
const TEST_MASK_LOG_INVERSE_RATE: usize = 2;
const TEST_VARIABLE_COUNT: usize = 10;
const TEST_RELATION_COUNT: usize = 2;

#[derive(Clone, Copy, Debug)]
struct TestByteHasher;

#[derive(Clone, Copy, Debug)]
struct TestGoldilocksLeafHasher;

#[derive(Clone, Copy, Debug)]
struct TestWordHasher;

fn initialized_test_hash(domain: &[u8]) -> Shake256 {
    let mut state = Shake256::default();
    state.update(b"sealed-lattice/compact-relation-integration/v1");
    state.update(&(domain.len() as u64).to_le_bytes());
    state.update(domain);
    state
}

fn finish_test_hash(state: Shake256) -> [u8; TEST_HASH_OUTPUT_BYTE_LENGTH] {
    let mut output = [0_u8; TEST_HASH_OUTPUT_BYTE_LENGTH];
    state.finalize_xof().read(&mut output);
    output
}

fn digest_bytes_to_words(
    bytes: [u8; TEST_HASH_OUTPUT_BYTE_LENGTH],
) -> [u64; TEST_HASH_OUTPUT_WORD_LENGTH] {
    core::array::from_fn(|word_ordinal| {
        let start = word_ordinal * size_of::<u64>();
        u64::from_le_bytes(
            bytes[start..start + size_of::<u64>()]
                .try_into()
                .expect("one test digest word has eight bytes"),
        )
    })
}

impl CryptographicHasher<u8, [u8; TEST_HASH_OUTPUT_BYTE_LENGTH]> for TestByteHasher {
    fn hash_iter<Input>(&self, input: Input) -> [u8; TEST_HASH_OUTPUT_BYTE_LENGTH]
    where
        Input: IntoIterator<Item = u8>,
    {
        let mut state = initialized_test_hash(b"challenger");
        for byte in input {
            state.update(&[byte]);
        }
        finish_test_hash(state)
    }
}

impl CryptographicHasher<Goldilocks, [u64; TEST_HASH_OUTPUT_WORD_LENGTH]>
    for TestGoldilocksLeafHasher
{
    fn hash_iter<Input>(&self, input: Input) -> [u64; TEST_HASH_OUTPUT_WORD_LENGTH]
    where
        Input: IntoIterator<Item = Goldilocks>,
    {
        let mut state = initialized_test_hash(b"leaf");
        for value in input {
            state.update(&value.as_canonical_u64().to_le_bytes());
        }
        digest_bytes_to_words(finish_test_hash(state))
    }
}

impl CryptographicHasher<u64, [u64; TEST_HASH_OUTPUT_WORD_LENGTH]> for TestWordHasher {
    fn hash_iter<Input>(&self, input: Input) -> [u64; TEST_HASH_OUTPUT_WORD_LENGTH]
    where
        Input: IntoIterator<Item = u64>,
    {
        let mut state = initialized_test_hash(b"node");
        for value in input {
            state.update(&value.to_le_bytes());
        }
        digest_bytes_to_words(finish_test_hash(state))
    }
}

type TestInnerChallenger = HashChallenger<u8, TestByteHasher, TEST_HASH_OUTPUT_BYTE_LENGTH>;
type TestChallenger = SerializingChallenger64<Goldilocks, TestInnerChallenger>;
type TestNodeCompressor =
    CompressionFunctionFromHasher<TestWordHasher, 2, TEST_HASH_OUTPUT_WORD_LENGTH>;
type TestCommitmentScheme = MerkleTreeMmcs<
    Goldilocks,
    u64,
    TestGoldilocksLeafHasher,
    TestNodeCompressor,
    2,
    TEST_HASH_OUTPUT_WORD_LENGTH,
>;
type TestExtensionCommitmentScheme =
    ExtensionMmcs<Goldilocks, ChallengeField, TestCommitmentScheme>;
type TestCommitment = <TestCommitmentScheme as Mmcs<Goldilocks>>::Commitment;
type TestMaskProverData = MaskProverData<Goldilocks, ChallengeField, TestCommitmentScheme>;
type TestProof = ZkWhirProof<Goldilocks, ChallengeField, TestCommitmentScheme>;
type TestConfiguration = ZkWhirConfig<ChallengeField, Goldilocks, TestChallenger>;

fn test_challenger() -> TestChallenger {
    TestChallenger::new(TestInnerChallenger::new(
        b"compact-relation-integration".to_vec(),
        TestByteHasher,
    ))
}

fn test_commitment_scheme() -> TestCommitmentScheme {
    TestCommitmentScheme::new(
        TestGoldilocksLeafHasher,
        TestNodeCompressor::new(TestWordHasher),
        0,
    )
}

fn test_configuration() -> TestConfiguration {
    ZkWhirConfig::<ChallengeField, Goldilocks, TestChallenger>::new(
        TEST_VARIABLE_COUNT,
        ProtocolParameters {
            starting_log_inv_rate: TEST_MAIN_LOG_INVERSE_RATE,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::Constant(3),
            soundness_type: SecurityAssumption::UniqueDecoding,
            security_level: 16,
            pow_bits: 0,
        },
        ZkParameters {
            ell_zk: 3,
            mask_log_inv_rate: TEST_MASK_LOG_INVERSE_RATE,
        },
    )
    .expect("the focused extension-relation fixture has valid WHIR geometry")
}

fn extension_value(seed: u64) -> ChallengeField {
    ChallengeField::new(core::array::from_fn(|coordinate_ordinal| {
        Goldilocks::from_u64(
            seed.wrapping_mul(97)
                .wrapping_add((coordinate_ordinal as u64 + 1) * 31),
        )
    }))
}

fn extension_vector(length: usize, seed: u64) -> Vec<ChallengeField> {
    (0..length)
        .map(|value_ordinal| extension_value(seed.wrapping_add(value_ordinal as u64 * 17)))
        .collect()
}

fn dot(left: &[ChallengeField], right: &[ChallengeField]) -> ChallengeField {
    assert_eq!(left.len(), right.len());
    dot_product::<ChallengeField, _, _>(left.iter().copied(), right.iter().copied())
}

struct CommittedMaskGroup {
    shape: MaskGroupShape,
    messages: Vec<Vec<ChallengeField>>,
    randomness: Vec<Vec<ChallengeField>>,
    commitment: TestCommitment,
    data: TestMaskProverData,
}

fn commit_mask_group(
    shape: MaskGroupShape,
    messages: Vec<Vec<ChallengeField>>,
    randomness: Vec<Vec<ChallengeField>>,
    commitment_scheme: &TestExtensionCommitmentScheme,
    challenger: &mut TestChallenger,
) -> CommittedMaskGroup {
    assert_eq!(messages.len(), shape.width);
    assert_eq!(randomness.len(), shape.width);
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
    challenger.observe(commitment.clone());
    CommittedMaskGroup {
        shape,
        messages,
        randomness,
        commitment,
        data,
    }
}

#[derive(Clone)]
struct TwoClaimRelation {
    source_covectors: [Vec<ChallengeField>; TEST_RELATION_COUNT],
    inner_mask_covectors: [Vec<Vec<ChallengeField>>; TEST_RELATION_COUNT],
    outer_mask_covectors: [Vec<Vec<ChallengeField>>; TEST_RELATION_COUNT],
    values: [ChallengeField; TEST_RELATION_COUNT],
}

impl TwoClaimRelation {
    fn new(
        source_message: &Poly<ChallengeField>,
        inner_mask_messages: &[Vec<ChallengeField>],
        outer_mask_messages: &[Vec<ChallengeField>],
    ) -> Self {
        assert_eq!(inner_mask_messages.len(), 2);
        assert_eq!(outer_mask_messages.len(), 1);
        let source_covectors = [
            extension_vector(source_message.num_evals(), 301),
            extension_vector(source_message.num_evals(), 701),
        ];
        let inner_mask_covectors = [
            vec![extension_vector(4, 1_101), extension_vector(4, 1_301)],
            vec![extension_vector(4, 1_501), extension_vector(4, 1_701)],
        ];
        let outer_mask_covectors = [
            vec![extension_vector(8, 1_901)],
            vec![extension_vector(8, 2_101)],
        ];
        let mut relation = Self {
            source_covectors,
            inner_mask_covectors,
            outer_mask_covectors,
            values: [ChallengeField::ZERO; TEST_RELATION_COUNT],
        };
        relation.values = core::array::from_fn(|relation_ordinal| {
            dot(
                source_message.as_slice(),
                &relation.source_covectors[relation_ordinal],
            ) + relation.inner_mask_covectors[relation_ordinal]
                .iter()
                .zip(inner_mask_messages)
                .map(|(covector, message)| dot(message, covector))
                .sum::<ChallengeField>()
                + relation.outer_mask_covectors[relation_ordinal]
                    .iter()
                    .zip(outer_mask_messages)
                    .map(|(covector, message)| dot(message, covector))
                    .sum::<ChallengeField>()
        });
        relation
    }

    fn combined_covector(
        first: &[ChallengeField],
        second: &[ChallengeField],
        batching_challenge: ChallengeField,
    ) -> Vec<ChallengeField> {
        assert_eq!(first.len(), second.len());
        first
            .iter()
            .zip(second)
            .map(|(&first_value, &second_value)| first_value + batching_challenge * second_value)
            .collect()
    }

    fn combined_source_covector(&self, batching_challenge: ChallengeField) -> Poly<ChallengeField> {
        Poly::new(Self::combined_covector(
            &self.source_covectors[0],
            &self.source_covectors[1],
            batching_challenge,
        ))
    }

    fn combined_mask_covectors(
        relation_covectors: &[Vec<Vec<ChallengeField>>; TEST_RELATION_COUNT],
        batching_challenge: ChallengeField,
    ) -> Vec<Vec<ChallengeField>> {
        relation_covectors[0]
            .iter()
            .zip(&relation_covectors[1])
            .map(|(first, second)| Self::combined_covector(first, second, batching_challenge))
            .collect()
    }

    fn combined_target(
        batching_challenge: ChallengeField,
        disclosed_values: &[ChallengeField],
    ) -> ChallengeField {
        assert_eq!(disclosed_values.len(), TEST_RELATION_COUNT);
        disclosed_values[0] + batching_challenge * disclosed_values[1]
    }

    fn prover_input(
        &self,
        batching_challenge: ChallengeField,
        disclosed_values: &[ChallengeField],
        inner_mask_group: CommittedMaskGroup,
        outer_mask_group: CommittedMaskGroup,
    ) -> CombinedRelationProverInput<Goldilocks, ChallengeField, TestCommitmentScheme> {
        CombinedRelationProverInput {
            source_covector: self.combined_source_covector(batching_challenge),
            target: Self::combined_target(batching_challenge, disclosed_values),
            precommitted_mask_groups: vec![
                PrecommittedMaskProverGroup {
                    shape: inner_mask_group.shape,
                    messages: inner_mask_group.messages,
                    randomness: inner_mask_group.randomness,
                    covectors: Self::combined_mask_covectors(
                        &self.inner_mask_covectors,
                        batching_challenge,
                    ),
                    data: inner_mask_group.data,
                },
                PrecommittedMaskProverGroup {
                    shape: outer_mask_group.shape,
                    messages: outer_mask_group.messages,
                    randomness: outer_mask_group.randomness,
                    covectors: Self::combined_mask_covectors(
                        &self.outer_mask_covectors,
                        batching_challenge,
                    ),
                    data: outer_mask_group.data,
                },
            ],
        }
    }

    fn verifier_input(
        &self,
        batching_challenge: ChallengeField,
        disclosed_values: &[ChallengeField],
        inner_mask_shape: MaskGroupShape,
        inner_mask_commitment: TestCommitment,
        outer_mask_shape: MaskGroupShape,
        outer_mask_commitment: TestCommitment,
    ) -> CombinedRelationVerifierInput<ChallengeField, TestCommitment> {
        CombinedRelationVerifierInput {
            source_covector: self.combined_source_covector(batching_challenge),
            target: Self::combined_target(batching_challenge, disclosed_values),
            precommitted_mask_groups: vec![
                PrecommittedMaskVerifierGroup {
                    shape: inner_mask_shape,
                    covectors: Self::combined_mask_covectors(
                        &self.inner_mask_covectors,
                        batching_challenge,
                    ),
                    commitment: inner_mask_commitment,
                },
                PrecommittedMaskVerifierGroup {
                    shape: outer_mask_shape,
                    covectors: Self::combined_mask_covectors(
                        &self.outer_mask_covectors,
                        batching_challenge,
                    ),
                    commitment: outer_mask_commitment,
                },
            ],
        }
    }
}

struct PreparedExtensionRelation {
    configuration: TestConfiguration,
    commitment_scheme: TestCommitmentScheme,
    source_commitment: TestCommitment,
    inner_mask_shape: MaskGroupShape,
    inner_mask_commitment: TestCommitment,
    outer_mask_shape: MaskGroupShape,
    outer_mask_commitment: TestCommitment,
    relation: TwoClaimRelation,
    proof: TestProof,
}

fn prepare_extension_relation_proof() -> PreparedExtensionRelation {
    let configuration = test_configuration();
    assert!(
        configuration.n_rounds() >= 1,
        "the fixture must exercise at least one WHIR code switch",
    );
    let commitment_scheme = test_commitment_scheme();
    let extension_commitment_scheme = TestExtensionCommitmentScheme::new(commitment_scheme.clone());
    let discrete_fourier_transform = Radix2DFTSmallBatch::<Goldilocks>::default();
    let prover = HidingWhirProver::new(
        &configuration,
        &discrete_fourier_transform,
        &commitment_scheme,
    );
    let mut challenger = test_challenger();
    let mut random_source = SmallRng::seed_from_u64(0x51_71_C0_DE);

    let inner_mask_shape = MaskGroupShape {
        shape: MaskCodeShape::new(4, configuration.mask_queries, TEST_MASK_LOG_INVERSE_RATE),
        width: 2,
    };
    let inner_mask_group = commit_mask_group(
        inner_mask_shape,
        vec![extension_vector(4, 11), extension_vector(4, 29)],
        vec![
            extension_vector(inner_mask_shape.shape.randomness_len, 47),
            extension_vector(inner_mask_shape.shape.randomness_len, 71),
        ],
        &extension_commitment_scheme,
        &mut challenger,
    );

    let source_message = Poly::new(extension_vector(1 << TEST_VARIABLE_COUNT, 101));
    let (source_commitment, source_prover_data) =
        prover.commit_extension(source_message.clone(), &mut challenger, &mut random_source);

    let outer_mask_shape = MaskGroupShape {
        shape: MaskCodeShape::new(8, configuration.mask_queries, TEST_MASK_LOG_INVERSE_RATE),
        width: 1,
    };
    let outer_mask_group = commit_mask_group(
        outer_mask_shape,
        vec![extension_vector(8, 131)],
        vec![extension_vector(outer_mask_shape.shape.randomness_len, 151)],
        &extension_commitment_scheme,
        &mut challenger,
    );

    let relation = TwoClaimRelation::new(
        &source_message,
        &inner_mask_group.messages,
        &outer_mask_group.messages,
    );
    let disclosed_values = relation.values.to_vec();
    for &value in &disclosed_values {
        challenger.observe_algebra_element(value);
    }

    let inner_mask_commitment = inner_mask_group.commitment.clone();
    let outer_mask_commitment = outer_mask_group.commitment.clone();
    let relation_for_prover = relation.clone();
    let disclosed_values_for_prover = disclosed_values.clone();
    let proof = prover
        .prove_extension_relation(
            source_prover_data,
            disclosed_values,
            move |batching_challenge| {
                Ok(relation_for_prover.prover_input(
                    batching_challenge,
                    &disclosed_values_for_prover,
                    inner_mask_group,
                    outer_mask_group,
                ))
            },
            &mut challenger,
            &mut random_source,
        )
        .expect("the complete focused extension relation is well formed");

    PreparedExtensionRelation {
        configuration,
        commitment_scheme,
        source_commitment,
        inner_mask_shape,
        inner_mask_commitment,
        outer_mask_shape,
        outer_mask_commitment,
        relation,
        proof,
    }
}

#[derive(Clone, Copy)]
enum VerificationMutation {
    None,
    Target,
    SourceCovector,
    InnerMaskCovector,
    GroupChronology,
    ShortSourceCovector,
    MissingInnerMaskCovector,
}

impl PreparedExtensionRelation {
    fn verify(&self, mutation: VerificationMutation) -> Result<(), ZkVerifierError> {
        let mut challenger = test_challenger();
        if matches!(mutation, VerificationMutation::GroupChronology) {
            challenger.observe(self.outer_mask_commitment.clone());
            challenger.observe(self.source_commitment.clone());
            challenger.observe(self.inner_mask_commitment.clone());
        } else {
            challenger.observe(self.inner_mask_commitment.clone());
            challenger.observe(self.source_commitment.clone());
            challenger.observe(self.outer_mask_commitment.clone());
        }
        for &value in &self.proof.evals {
            challenger.observe_algebra_element(value);
        }

        let verifier = HidingWhirVerifier::new(&self.configuration, &self.commitment_scheme);
        let relation = self.relation.clone();
        let inner_mask_commitment = self.inner_mask_commitment.clone();
        let outer_mask_commitment = self.outer_mask_commitment.clone();
        verifier.verify_extension_relation(
            &self.proof,
            &self.source_commitment,
            TEST_RELATION_COUNT,
            move |batching_challenge, disclosed_values| {
                let mut input = relation.verifier_input(
                    batching_challenge,
                    disclosed_values,
                    self.inner_mask_shape,
                    inner_mask_commitment,
                    self.outer_mask_shape,
                    outer_mask_commitment,
                );
                match mutation {
                    VerificationMutation::None => {}
                    VerificationMutation::Target => input.target += ChallengeField::ONE,
                    VerificationMutation::SourceCovector => {
                        input.source_covector.as_mut_slice()[0] += ChallengeField::ONE;
                    }
                    VerificationMutation::InnerMaskCovector => {
                        input.precommitted_mask_groups[0].covectors[0][0] += ChallengeField::ONE;
                    }
                    VerificationMutation::GroupChronology => {
                        input.precommitted_mask_groups.swap(0, 1);
                    }
                    VerificationMutation::ShortSourceCovector => {
                        input.source_covector =
                            Poly::new(vec![ChallengeField::ZERO; 1 << (TEST_VARIABLE_COUNT - 1)]);
                    }
                    VerificationMutation::MissingInnerMaskCovector => {
                        input.precommitted_mask_groups[0].covectors.pop();
                    }
                }
                Ok(input)
            },
            &mut challenger,
        )
    }
}

#[test]
fn extension_relation_carries_precommitted_masks_in_outer_commit_order() {
    let prepared = prepare_extension_relation_proof();
    assert_eq!(prepared.proof.evals, prepared.relation.values);
    prepared
        .verify(VerificationMutation::None)
        .expect("the independently replayed extension relation must verify");
}

#[test]
fn extension_relation_refuses_changed_relation_terms_and_group_chronology() {
    let prepared = prepare_extension_relation_proof();
    for mutation in [
        VerificationMutation::Target,
        VerificationMutation::SourceCovector,
        VerificationMutation::InnerMaskCovector,
        VerificationMutation::GroupChronology,
    ] {
        assert!(prepared.verify(mutation).is_err());
    }
}

#[test]
fn extension_relation_verifier_refuses_malformed_caller_owned_dimensions() {
    let prepared = prepare_extension_relation_proof();
    assert_eq!(
        prepared
            .verify(VerificationMutation::ShortSourceCovector)
            .expect_err("a short dense source covector must be refused"),
        ZkVerifierError::RelationInput(
            HidingWhirRelationInputError::SourceCovectorLengthMismatch {
                expected: 1 << TEST_VARIABLE_COUNT,
                actual: 1 << (TEST_VARIABLE_COUNT - 1),
            },
        ),
    );
    assert_eq!(
        prepared
            .verify(VerificationMutation::MissingInnerMaskCovector)
            .expect_err("a missing mask covector must be refused"),
        ZkVerifierError::RelationInput(
            HidingWhirRelationInputError::VerifierMaskGroupWidthMismatch {
                group: 0,
                expected: 2,
                actual: 1,
            },
        ),
    );
}

#[test]
fn extension_relation_prover_refuses_malformed_caller_owned_dimensions() {
    let configuration = test_configuration();
    let commitment_scheme = test_commitment_scheme();
    let extension_commitment_scheme = TestExtensionCommitmentScheme::new(commitment_scheme.clone());
    let discrete_fourier_transform = Radix2DFTSmallBatch::<Goldilocks>::default();
    let prover = HidingWhirProver::new(
        &configuration,
        &discrete_fourier_transform,
        &commitment_scheme,
    );

    let mut short_source_challenger = test_challenger();
    let mut short_source_randomness = SmallRng::seed_from_u64(0x5A_0C_E);
    let (_, short_source_prover_data) = prover.commit_extension(
        Poly::new(extension_vector(1 << TEST_VARIABLE_COUNT, 2_501)),
        &mut short_source_challenger,
        &mut short_source_randomness,
    );
    let short_source_result = prover.prove_extension_relation(
        short_source_prover_data,
        Vec::new(),
        |_| {
            Ok(CombinedRelationProverInput {
                source_covector: Poly::new(vec![
                    ChallengeField::ZERO;
                    1 << (TEST_VARIABLE_COUNT - 1)
                ]),
                target: ChallengeField::ZERO,
                precommitted_mask_groups: Vec::new(),
            })
        },
        &mut short_source_challenger,
        &mut short_source_randomness,
    );
    assert!(matches!(
        short_source_result,
        Err(HidingWhirRelationInputError::SourceCovectorLengthMismatch {
            expected,
            actual,
        }) if expected == 1 << TEST_VARIABLE_COUNT && actual == 1 << (TEST_VARIABLE_COUNT - 1)
    ));

    let mut mask_width_challenger = test_challenger();
    let mut mask_width_randomness = SmallRng::seed_from_u64(0xBA_D5_1E);
    let mask_shape = MaskGroupShape {
        shape: MaskCodeShape::new(4, configuration.mask_queries, TEST_MASK_LOG_INVERSE_RATE),
        width: 2,
    };
    let mut mask_group = commit_mask_group(
        mask_shape,
        vec![extension_vector(4, 2_701), extension_vector(4, 2_901)],
        vec![
            extension_vector(mask_shape.shape.randomness_len, 3_101),
            extension_vector(mask_shape.shape.randomness_len, 3_301),
        ],
        &extension_commitment_scheme,
        &mut mask_width_challenger,
    );
    let (_, mask_width_source_prover_data) = prover.commit_extension(
        Poly::new(extension_vector(1 << TEST_VARIABLE_COUNT, 3_501)),
        &mut mask_width_challenger,
        &mut mask_width_randomness,
    );
    mask_group.messages.pop();
    let mask_width_result = prover.prove_extension_relation(
        mask_width_source_prover_data,
        Vec::new(),
        move |_| {
            Ok(CombinedRelationProverInput {
                source_covector: Poly::new(vec![ChallengeField::ZERO; 1 << TEST_VARIABLE_COUNT]),
                target: ChallengeField::ZERO,
                precommitted_mask_groups: vec![PrecommittedMaskProverGroup {
                    shape: mask_group.shape,
                    messages: mask_group.messages,
                    randomness: mask_group.randomness,
                    covectors: vec![vec![ChallengeField::ZERO; 4], vec![ChallengeField::ZERO; 4]],
                    data: mask_group.data,
                }],
            })
        },
        &mut mask_width_challenger,
        &mut mask_width_randomness,
    );
    assert!(matches!(
        mask_width_result,
        Err(HidingWhirRelationInputError::ProverMaskGroupWidthMismatch {
            group: 0,
            expected: 2,
            message_count: 1,
            randomness_count: 2,
            covector_count: 2,
        })
    ));
}
