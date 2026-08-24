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
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, dot_product};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::{
    product_polynomial::ProductPolynomial,
    strategy::{SumcheckProver, VariableOrder},
    zk::{ZkSumcheckData, stack_codewords},
};
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use p3_whir::pcs::zk::{
    BaseCaseFreshMaskGroup, BaseCaseFreshMaterial, BaseCaseZkConfig, BaseCaseZkProver,
    CombinedRelationProverInput, CombinedRelationVerifierInput, FoldedRsCode, HidingWhirProver,
    HidingWhirRelationInputError, HidingWhirVerifier, MaskCodeShape, MaskGroupShape,
    MaskGroupWitness, MaskProverData, PrecommittedMaskProverGroup, PrecommittedMaskVerifierGroup,
    ZkVerifierError, ZkWhirConfig, ZkWhirProof,
};
use p3_whir::{FoldingFactor, ProtocolParameters, QueryOpening, SecurityAssumption, ZkParameters};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::ChallengeField;
use crate::bgv::proof_suite::{
    compact_masking_coefficient_maps::{
        CompactCoefficientProjection, CompactMaskingViewRole, apply_affine_mirror,
        apply_whir_base_case_claim_view, apply_whir_sumcheck_mask_view,
        derive_selected_compact_masking_coefficient_map_certificate,
    },
    compact_proof_contract::{
        CompactWhirMaskGroupContract, selected_compact_public_key_proof_contract,
    },
};

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

fn selected_mask_group_shape(group: CompactWhirMaskGroupContract) -> MaskGroupShape {
    let populated_length = usize::try_from(group.message_length + group.randomness_length)
        .expect("selected mask dimension fits usize");
    let domain_size = usize::try_from(group.domain_size).expect("selected mask domain fits usize");
    let padded_populated_length = populated_length.next_power_of_two();
    assert!(domain_size.is_multiple_of(padded_populated_length));
    let inverse_rate = domain_size / padded_populated_length;
    assert!(inverse_rate.is_power_of_two());
    MaskGroupShape {
        shape: MaskCodeShape::new(
            usize::try_from(group.message_length).expect("selected mask message fits usize"),
            usize::try_from(group.randomness_length).expect("selected mask randomness fits usize"),
            usize::try_from(inverse_rate.ilog2()).expect("selected mask inverse rate fits usize"),
        ),
        width: usize::try_from(group.width).expect("selected mask width fits usize"),
    }
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
    let committed_group =
        build_committed_mask_group(shape, messages, randomness, commitment_scheme);
    challenger.observe(committed_group.commitment.clone());
    committed_group
}

fn build_committed_mask_group(
    shape: MaskGroupShape,
    messages: Vec<Vec<ChallengeField>>,
    randomness: Vec<Vec<ChallengeField>>,
    commitment_scheme: &TestExtensionCommitmentScheme,
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
    CommittedMaskGroup {
        shape,
        messages,
        randomness,
        commitment,
        data,
    }
}

pub(in crate::bgv::proof_suite) fn assert_selected_masking_producer_differentials() {
    let contract = selected_compact_public_key_proof_contract()
        .expect("selected compact proof contract decodes");
    let certificate = derive_selected_compact_masking_coefficient_map_certificate()
        .expect("selected coefficient maps derive");
    let inputs = contract.verifier_inputs();

    let commitment_scheme = test_commitment_scheme();
    let extension_commitment_scheme = TestExtensionCommitmentScheme::new(commitment_scheme);
    let sumcheck_maps = certificate
        .maps()
        .iter()
        .enumerate()
        .filter(|(_, map)| {
            matches!(
                map.projection,
                CompactCoefficientProjection::WhirSumcheckTranscript { .. }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(sumcheck_maps.len(), 8);
    for (map_ordinal, map) in sumcheck_maps {
        let CompactCoefficientProjection::WhirSumcheckTranscript {
            round_count,
            mask_message_length,
        } = map.projection
        else {
            unreachable!("filtered sumcheck map")
        };
        let round_count = usize::try_from(round_count).expect("selected round count fits usize");
        let evaluations = Poly::new(vec![ChallengeField::ZERO; 1 << round_count]);
        let weights = Poly::new(extension_vector(
            1 << round_count,
            13_000 + map_ordinal as u64,
        ));
        let product = ProductPolynomial::<Goldilocks, ChallengeField>::new_unpacked(
            VariableOrder::Prefix,
            evaluations,
            weights,
        );
        let prover = SumcheckProver::new(product, ChallengeField::ZERO);
        let mut data = ZkSumcheckData::default();
        let mut challenger = test_challenger();
        let mut random_source = SmallRng::seed_from_u64(0x5100_0000 + map_ordinal as u64);
        let epoch = &inputs.whir_epochs[usize::from(map.coordinate.epoch - 1)];
        let group = epoch
            .internal_mask_groups
            .iter()
            .find(|group| group.role_tag == 4 && group.coordinate == map.coordinate.batch_ordinal)
            .copied()
            .expect("selected sumcheck group exists");
        let selected_sumcheck_group = selected_mask_group_shape(group);
        assert_eq!(selected_sumcheck_group.width, round_count);
        assert_eq!(
            selected_sumcheck_group.shape.message_len,
            usize::try_from(mask_message_length)
                .expect("selected sumcheck mask message length fits usize"),
        );
        let selected_sumcheck_encoding = selected_sumcheck_group.shape;
        let handoff = prover.into_zk_sumcheck(
            &mut data,
            &selected_sumcheck_encoding.encoding::<ChallengeField>(),
            &extension_commitment_scheme,
            round_count,
            0,
            ChallengeField::ZERO,
            &mut challenger,
            &mut random_source,
        );
        let challenges = handoff.randomness.iter().copied().collect::<Vec<_>>();
        let expected = apply_whir_sumcheck_mask_view(&handoff.mask_messages, &challenges)
            .expect("coefficient map accepts the real p3 masks");
        let actual = core::iter::once(data.mu_tilde)
            .chain(data.round_coefficients.into_iter().flatten())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "selected WHIR sumcheck map {map_ordinal}");
    }

    assert_eq!(inputs.whir_epochs.len(), 2);
    let cross_epoch_groups = inputs
        .whir_epochs
        .iter()
        .flat_map(|epoch| &epoch.external_mask_groups)
        .filter(|group| group.role_tag == 1)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(cross_epoch_groups.len(), 2);
    assert_eq!(cross_epoch_groups[0].committed_encoding_source, 1);
    assert_eq!(cross_epoch_groups[1].committed_encoding_source, 2);
    let shared_cross_epoch_shape = selected_mask_group_shape(cross_epoch_groups[0]);
    assert_eq!(
        selected_mask_group_shape(cross_epoch_groups[1]),
        shared_cross_epoch_shape,
    );
    let shared_cross_epoch_messages = (0..shared_cross_epoch_shape.width)
        .map(|member| {
            extension_vector(
                shared_cross_epoch_shape.shape.message_len,
                18_000 + member as u64,
            )
        })
        .collect::<Vec<_>>();
    let shared_cross_epoch_randomness = (0..shared_cross_epoch_shape.width)
        .map(|member| {
            extension_vector(
                shared_cross_epoch_shape.shape.randomness_len,
                19_000 + member as u64,
            )
        })
        .collect::<Vec<_>>();
    let shared_cross_epoch_group = build_committed_mask_group(
        shared_cross_epoch_shape,
        shared_cross_epoch_messages,
        shared_cross_epoch_randomness,
        &extension_commitment_scheme,
    );

    let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
    for (epoch_index, epoch) in inputs.whir_epochs.iter().enumerate() {
        let base_claim_map = certificate
            .maps()
            .iter()
            .find(|map| {
                map.coordinate.role == CompactMaskingViewRole::Terminal
                    && usize::from(map.coordinate.epoch) == epoch_index + 1
                    && matches!(
                        map.projection,
                        CompactCoefficientProjection::WhirBaseCaseClaim { .. }
                    )
            })
            .expect("selected base-claim map exists");
        let CompactCoefficientProjection::WhirBaseCaseClaim { dependencies } =
            &base_claim_map.projection
        else {
            unreachable!("selected base-claim map")
        };
        let final_fold = &inputs.whir_folds[epoch_index * 4 + 3];
        let source_message_length = usize::try_from(final_fold.message_length)
            .expect("selected final source message fits usize");
        let source_randomness_length = usize::try_from(final_fold.hiding_randomness_length)
            .expect("selected final source randomness fits usize");
        let source_code = FoldedRsCode::<Goldilocks>::new(
            source_message_length,
            source_randomness_length,
            usize::try_from(final_fold.block_length).expect("selected final domain fits usize"),
        );
        let group_contracts = epoch
            .external_mask_groups
            .iter()
            .chain(&epoch.internal_mask_groups)
            .copied()
            .collect::<Vec<_>>();
        let groups = group_contracts
            .iter()
            .copied()
            .map(selected_mask_group_shape)
            .collect::<Vec<_>>();
        assert_eq!(groups.len() + 1, dependencies.len());
        let source_dependency = dependencies
            .first()
            .expect("selected base-case source dependency exists");
        assert_eq!(source_dependency.lane_count, 1);
        assert_eq!(
            usize::try_from(source_dependency.message_length_per_lane)
                .expect("selected source dependency message length fits usize"),
            source_message_length,
        );
        assert_eq!(
            usize::try_from(source_dependency.randomness_length_per_lane)
                .expect("selected source dependency randomness length fits usize"),
            source_randomness_length,
        );
        for (shape, dependency) in groups.iter().zip(dependencies.iter().skip(1)) {
            assert_eq!(
                usize::try_from(dependency.lane_count)
                    .expect("selected mask dependency lane count fits usize"),
                shape.width,
            );
            assert_eq!(
                usize::try_from(dependency.message_length_per_lane)
                    .expect("selected mask dependency message length fits usize"),
                shape.shape.message_len,
            );
            assert_eq!(
                usize::try_from(dependency.randomness_length_per_lane)
                    .expect("selected mask dependency randomness length fits usize"),
                shape.shape.randomness_len,
            );
        }

        let source_message = extension_vector(source_message_length, 20_000 + epoch_index as u64);
        let source_randomness =
            extension_vector(source_randomness_length, 21_000 + epoch_index as u64);
        let source_covector = extension_vector(source_message_length, 22_000 + epoch_index as u64);
        let source_codeword = source_code.encode_column(&dft, &source_message, &source_randomness);
        let (_, source_data) = extension_commitment_scheme.commit_matrix(source_codeword);

        let mut owned_groups = Vec::new();
        let mut group_covectors = Vec::new();
        for (group_ordinal, (group_contract, shape)) in group_contracts
            .iter()
            .zip(groups.iter().copied())
            .enumerate()
        {
            let covectors = (0..shape.width)
                .map(|member| {
                    extension_vector(
                        shape.shape.message_len,
                        25_000 + 101 * group_ordinal as u64 + member as u64,
                    )
                })
                .collect::<Vec<_>>();
            group_covectors.push(covectors);
            if group_contract.role_tag == 1 {
                assert_eq!(shape, shared_cross_epoch_group.shape);
                owned_groups.push(None);
                continue;
            }
            let messages = (0..shape.width)
                .map(|member| {
                    extension_vector(
                        shape.shape.message_len,
                        23_000 + 101 * group_ordinal as u64 + member as u64,
                    )
                })
                .collect::<Vec<_>>();
            let randomness = (0..shape.width)
                .map(|member| {
                    extension_vector(
                        shape.shape.randomness_len,
                        24_000 + 101 * group_ordinal as u64 + member as u64,
                    )
                })
                .collect::<Vec<_>>();
            owned_groups.push(Some(build_committed_mask_group(
                shape,
                messages,
                randomness,
                &extension_commitment_scheme,
            )));
        }

        let carried_groups = group_contracts
            .iter()
            .enumerate()
            .map(|(group_ordinal, group_contract)| {
                if group_contract.role_tag == 1 {
                    &shared_cross_epoch_group
                } else {
                    owned_groups[group_ordinal]
                        .as_ref()
                        .expect("non-shared selected group is committed once")
                }
            })
            .collect::<Vec<_>>();
        let witnesses = carried_groups
            .iter()
            .enumerate()
            .map(|(group_ordinal, group)| MaskGroupWitness {
                messages: &group.messages,
                randomness: &group.randomness,
                covectors: &group_covectors[group_ordinal],
                data: &group.data,
            })
            .collect::<Vec<_>>();
        let fresh_source_message =
            extension_vector(source_message_length, 26_000 + epoch_index as u64);
        let fresh_source_randomness =
            extension_vector(source_randomness_length, 27_000 + epoch_index as u64);
        let fresh_groups = groups
            .iter()
            .enumerate()
            .map(|(group_ordinal, shape)| BaseCaseFreshMaskGroup {
                messages: (0..shape.width)
                    .map(|member| {
                        extension_vector(
                            shape.shape.message_len,
                            28_000 + 101 * group_ordinal as u64 + member as u64,
                        )
                    })
                    .collect(),
                randomness: (0..shape.width)
                    .map(|member| {
                        extension_vector(
                            shape.shape.randomness_len,
                            29_000 + 101 * group_ordinal as u64 + member as u64,
                        )
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        let fresh_material = BaseCaseFreshMaterial {
            source_message: fresh_source_message.clone(),
            source_randomness: fresh_source_randomness,
            mask_groups: fresh_groups.clone(),
        };
        let config = BaseCaseZkConfig {
            code: source_code,
            mask_groups: groups,
            num_queries: 1,
            mask_queries: 1,
            pow_bits: 0,
        };
        let prover = BaseCaseZkProver {
            config: &config,
            extension_mmcs: &extension_commitment_scheme,
        };
        let mut challenger = test_challenger();
        let prepared = prover.prepare_with_material(
            &dft,
            &source_message,
            &source_randomness,
            &source_covector,
            &witnesses,
            &fresh_material,
            &mut challenger,
        );

        let mut fresh_coordinates = fresh_source_message;
        let mut fresh_claim_covector = source_covector;
        for ((fresh_group, covectors), dependency) in fresh_groups
            .iter()
            .zip(&group_covectors)
            .zip(dependencies.iter().skip(1))
        {
            assert_eq!(
                fresh_group.messages.len(),
                usize::try_from(dependency.lane_count).expect("selected lane count fits usize"),
            );
            for (message, covector) in fresh_group.messages.iter().zip(covectors) {
                fresh_coordinates.extend_from_slice(message);
                fresh_claim_covector.extend_from_slice(covector);
            }
        }
        let source_positions = prepared.source_positions().to_vec();
        let source_queries = source_positions
            .iter()
            .map(|position| {
                let opening = extension_commitment_scheme.open_batch(*position, &source_data);
                QueryOpening::Extension {
                    values: opening.opened_values.into_iter().next().unwrap(),
                    proof: opening.opening_proof,
                }
            })
            .collect();
        let proof = prepared
            .finish(source_queries)
            .expect("prepared base-case source openings are complete");
        assert_eq!(
            proof.masked_claim,
            apply_whir_base_case_claim_view(&fresh_coordinates, &fresh_claim_covector)
                .expect("base-claim coefficient map accepts production fresh coordinates"),
            "selected base-case map for epoch {}",
            epoch_index + 1,
        );

        let challenge = (proof.blinded_message[0] - fresh_material.source_message[0])
            * source_message[0].inverse();
        let mut carried_source_coordinates = source_message.clone();
        carried_source_coordinates.extend_from_slice(&source_randomness);
        let mut fresh_source_coordinates = fresh_material.source_message.clone();
        fresh_source_coordinates.extend_from_slice(&fresh_material.source_randomness);
        let mut actual_source_reveal = proof.blinded_message.clone();
        actual_source_reveal.extend_from_slice(&proof.blinded_randomness);
        assert_eq!(
            apply_affine_mirror(
                &carried_source_coordinates,
                &fresh_source_coordinates,
                challenge,
            )
            .expect("source affine-mirror map accepts production coordinates"),
            actual_source_reveal,
        );
        let mut blinded_mask_ordinal = 0;
        for (group_ordinal, carried_group) in carried_groups.iter().enumerate() {
            for member_ordinal in 0..carried_group.messages.len() {
                let mut carried = carried_group.messages[member_ordinal].clone();
                carried.extend_from_slice(&carried_group.randomness[member_ordinal]);
                let mut fresh =
                    fresh_material.mask_groups[group_ordinal].messages[member_ordinal].clone();
                fresh.extend_from_slice(
                    &fresh_material.mask_groups[group_ordinal].randomness[member_ordinal],
                );
                let mut actual = proof.blinded_masks[blinded_mask_ordinal].message.clone();
                actual.extend_from_slice(&proof.blinded_masks[blinded_mask_ordinal].randomness);
                assert_eq!(
                    apply_affine_mirror(&carried, &fresh, challenge)
                        .expect("mask affine-mirror map accepts production coordinates"),
                    actual,
                    "selected base-case mirror for epoch {}, group {group_ordinal}, member {member_ordinal}",
                    epoch_index + 1,
                );
                blinded_mask_ordinal += 1;
            }
        }
        assert_eq!(blinded_mask_ordinal, proof.blinded_masks.len());
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
    let mut short_source_randomness = SmallRng::seed_from_u64(0x0005_A0CE);
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

#[test]
fn base_and_extension_relations_reuse_one_two_mask_commitment_without_revealing_the_copy_value() {
    let configuration = test_configuration();
    let commitment_scheme = test_commitment_scheme();
    let extension_commitment_scheme = TestExtensionCommitmentScheme::new(commitment_scheme.clone());
    let discrete_fourier_transform = Radix2DFTSmallBatch::<Goldilocks>::default();
    let prover = HidingWhirProver::new(
        &configuration,
        &discrete_fourier_transform,
        &commitment_scheme,
    );
    let verifier = HidingWhirVerifier::new(&configuration, &commitment_scheme);
    let mut prover_challenger = test_challenger();
    let mut random_source = SmallRng::seed_from_u64(0xC0_55_E0_21);

    let base_source_values = (0..1 << TEST_VARIABLE_COUNT)
        .map(|value_ordinal| {
            Goldilocks::from_u64(
                7_001_u64
                    .wrapping_add(value_ordinal as u64 * 43)
                    .wrapping_mul(59),
            )
        })
        .collect::<Vec<_>>();
    let pre_challenge_source = Poly::new(base_source_values.clone());
    let main_source = Poly::new(
        base_source_values
            .iter()
            .copied()
            .map(ChallengeField::from)
            .collect::<Vec<_>>(),
    );
    let source_covector = extension_vector(1 << TEST_VARIABLE_COUNT, 9_001);
    let copied_source_value = main_source
        .as_slice()
        .iter()
        .copied()
        .zip(source_covector.iter().copied())
        .map(|(source_value, coefficient)| source_value * coefficient)
        .sum::<ChallengeField>();

    let (pre_challenge_source_commitment, pre_challenge_source_data) = prover.commit(
        pre_challenge_source,
        &mut prover_challenger,
        &mut random_source,
    );
    let (main_source_commitment, main_source_data) =
        prover.commit_extension(main_source, &mut prover_challenger, &mut random_source);

    let pre_challenge_mask = extension_value(9_401);
    let main_mask = extension_value(9_701);
    let shared_mask_shape = MaskGroupShape {
        shape: MaskCodeShape::new(
            1,
            configuration.mask_queries * 2,
            TEST_MASK_LOG_INVERSE_RATE,
        ),
        width: 2,
    };
    let shared_mask_messages = vec![vec![pre_challenge_mask], vec![main_mask]];
    let shared_mask_randomness = vec![
        extension_vector(shared_mask_shape.shape.randomness_len, 10_001),
        extension_vector(shared_mask_shape.shape.randomness_len, 10_301),
    ];
    let shared_mask_group_for_pre_challenge = commit_mask_group(
        shared_mask_shape,
        shared_mask_messages.clone(),
        shared_mask_randomness.clone(),
        &extension_commitment_scheme,
        &mut prover_challenger,
    );
    let shared_mask_group_for_main = build_committed_mask_group(
        shared_mask_shape,
        shared_mask_messages,
        shared_mask_randomness,
        &extension_commitment_scheme,
    );
    assert_eq!(
        shared_mask_group_for_pre_challenge.commitment, shared_mask_group_for_main.commitment,
        "deterministic replay must reconstruct the one shared mask root",
    );

    let masked_pre_challenge_value = copied_source_value + pre_challenge_mask;
    let masked_main_value = copied_source_value + main_mask;
    let mask_difference = pre_challenge_mask - main_mask;
    assert_eq!(
        masked_pre_challenge_value - masked_main_value - mask_difference,
        ChallengeField::ZERO,
    );
    for value in [
        masked_pre_challenge_value,
        masked_main_value,
        mask_difference,
    ] {
        prover_challenger.observe_algebra_element(value);
    }

    let pre_challenge_covector_for_prover = source_covector.clone();
    let pre_challenge_proof = prover
        .prove_base_source_relation(
            pre_challenge_source_data,
            vec![masked_pre_challenge_value],
            move |_| {
                Ok(CombinedRelationProverInput {
                    source_covector: Poly::new(pre_challenge_covector_for_prover),
                    target: masked_pre_challenge_value,
                    precommitted_mask_groups: vec![PrecommittedMaskProverGroup {
                        shape: shared_mask_group_for_pre_challenge.shape,
                        messages: shared_mask_group_for_pre_challenge.messages,
                        randomness: shared_mask_group_for_pre_challenge.randomness,
                        covectors: vec![vec![ChallengeField::ONE], vec![ChallengeField::ZERO]],
                        data: shared_mask_group_for_pre_challenge.data,
                    }],
                })
            },
            &mut prover_challenger,
            &mut random_source,
        )
        .expect("the base-source masked relation is well formed");

    let main_covector_for_prover = source_covector.clone();
    let main_proof = prover
        .prove_extension_relation(
            main_source_data,
            vec![masked_main_value, mask_difference],
            move |batching_challenge| {
                Ok(CombinedRelationProverInput {
                    source_covector: Poly::new(main_covector_for_prover),
                    target: masked_main_value + batching_challenge * mask_difference,
                    precommitted_mask_groups: vec![PrecommittedMaskProverGroup {
                        shape: shared_mask_group_for_main.shape,
                        messages: shared_mask_group_for_main.messages,
                        randomness: shared_mask_group_for_main.randomness,
                        covectors: vec![
                            vec![batching_challenge],
                            vec![ChallengeField::ONE - batching_challenge],
                        ],
                        data: shared_mask_group_for_main.data,
                    }],
                })
            },
            &mut prover_challenger,
            &mut random_source,
        )
        .expect("the extension-source masked relation is well formed");

    assert_eq!(pre_challenge_proof.evals, vec![masked_pre_challenge_value]);
    assert_eq!(main_proof.evals, vec![masked_main_value, mask_difference]);

    let mut verifier_challenger = test_challenger();
    verifier_challenger.observe(pre_challenge_source_commitment.clone());
    verifier_challenger.observe(main_source_commitment.clone());
    verifier_challenger.observe(shared_mask_group_for_main.commitment.clone());
    for value in [
        masked_pre_challenge_value,
        masked_main_value,
        mask_difference,
    ] {
        verifier_challenger.observe_algebra_element(value);
    }

    let pre_challenge_covector_for_verifier = source_covector.clone();
    verifier
        .verify_base_source_relation(
            &pre_challenge_proof,
            &pre_challenge_source_commitment,
            1,
            |_, disclosed_values| {
                Ok(CombinedRelationVerifierInput {
                    source_covector: Poly::new(pre_challenge_covector_for_verifier),
                    target: disclosed_values[0],
                    precommitted_mask_groups: vec![PrecommittedMaskVerifierGroup {
                        shape: shared_mask_shape,
                        covectors: vec![vec![ChallengeField::ONE], vec![ChallengeField::ZERO]],
                        commitment: shared_mask_group_for_main.commitment.clone(),
                    }],
                })
            },
            &mut verifier_challenger,
        )
        .expect("the independently reconstructed base-source relation must verify");

    let main_covector_for_verifier = source_covector;
    verifier
        .verify_extension_relation(
            &main_proof,
            &main_source_commitment,
            2,
            |batching_challenge, disclosed_values| {
                Ok(CombinedRelationVerifierInput {
                    source_covector: Poly::new(main_covector_for_verifier),
                    target: disclosed_values[0] + batching_challenge * disclosed_values[1],
                    precommitted_mask_groups: vec![PrecommittedMaskVerifierGroup {
                        shape: shared_mask_shape,
                        covectors: vec![
                            vec![batching_challenge],
                            vec![ChallengeField::ONE - batching_challenge],
                        ],
                        commitment: shared_mask_group_for_main.commitment,
                    }],
                })
            },
            &mut verifier_challenger,
        )
        .expect("the independently reconstructed extension relation must verify");
}
