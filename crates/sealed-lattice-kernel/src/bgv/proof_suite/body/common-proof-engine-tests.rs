use std::collections::BTreeMap;

use crate::bgv::{
    parameters::POLYNOMIAL_DEGREE,
    setup::{
        LatticeAnchorCommitment, SETUP_COMMITMENT_MODULE_RANK,
        lattice_anchor_commitment_canonical_bytes,
    },
};
use crate::foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple};

use super::super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationTreeDescriptor,
};
use super::super::{
    BoundedCommonProofByteSink, CollectivePublicKeyAggregatePlanInput,
    CommittedMaterialBoundOpeningProvider, CommittedMaterialProfile, CommittedMaterialTree,
    CommittedMaterialTreeInput, CommonProofGenerationInput, CommonProofPrivateCoinSource,
    CommonProofSourcePolynomial, CommonProofVerificationInput, CommonProofVerificationPoll,
    CommonProofVerificationStateMachine, CommonProofVerifierError, CompiledRelationPlan,
    CompiledTargetReleaseRelation, EvaluatorKeyAggregateEntryPlanInput,
    EvaluatorKeyAggregatePlanInput, EvaluatorKeyAggregateVariantInput, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR,
    PROOF_EVALUATION_COSET_OFFSET, PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT, ProofBaseFieldElement,
    ProofEvaluationDomain, ProofExternalMemory, ProofExternalMemoryObject,
    ProofExternalMemoryProtection, ProofLeafVisibility, ProofTreeRole,
    PollableCommonProofVerificationInput, PublicAggregateRelationGeometry,
    RelationPlanCheckContext, RelationProofTreeInput, ResidentCommonProofByteSource,
    ResidentCommonProofInputChunk, ResolvedSuiteModulus, RkgRoundOneAggregatePlanInput,
    RkgRoundOneAggregateVariantInput,
    SameSecretRelationPlanInput, SetupPublicPolynomialBoundOpeningProvider,
    SetupPublicPolynomialContext, SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput,
    StatementOwnedProofTreeInput, SuiteModulusReference, TargetReleaseModulusWitness,
    TargetReleaseRelationPlanInput, TargetReleaseRoleWitness, TargetReleaseWitness,
    VerifiedCommonProof, VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree,
    VerifiedTargetReleaseModulusInput, VerifiedTargetReleaseProof,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    canonical_proof_object_header_bytes, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_target_release_relation, generate_common_proof,
    verify_common_proof,
};
use super::SCHEMA_VERSION;

const APPLICATION_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
const RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1215;
const EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1218;
const TARGET_RELEASE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1621;
const EVALUATION_DOMAIN_SIZE: u64 = 4_096;
const TARGET_TEST_EVALUATION_DOMAIN_SIZE: u64 = 1_024;
const TARGET_TEST_RING_DEGREE: usize = 8;
const OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 258;
const MAXIMUM_PROOF_BYTE_LENGTH: usize = 16 * 1_024 * 1_024;
const MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH: usize = 64 * 1_024 * 1_024;
const MAXIMUM_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH: u32 = 1_024 * 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestExternalMemoryError {
    DuplicateTransaction,
    MissingTransaction,
    DuplicateObject,
    MissingObject,
    UnsupportedProtection,
    OperationLimitExceeded,
    PayloadLimitExceeded,
    StorageLimitExceeded,
    WrongOffsetOrLength,
}

struct TestExternalMemoryObject {
    bytes: Vec<u8>,
    exact_byte_length: usize,
    sealed: bool,
}

enum TestExternalMemoryUndo {
    RemoveCreated(ProofExternalMemoryObject),
    TruncateAppended {
        object: ProofExternalMemoryObject,
        previous_byte_length: usize,
    },
    RestoreSeal {
        object: ProofExternalMemoryObject,
        previous_sealed: bool,
    },
    RestoreDeleted {
        object: ProofExternalMemoryObject,
        value: TestExternalMemoryObject,
    },
}

struct TestExternalMemoryTransaction {
    objects: BTreeMap<ProofExternalMemoryObject, TestExternalMemoryObject>,
    undo: Vec<TestExternalMemoryUndo>,
    remaining_payload_byte_length: usize,
    remaining_operation_count: u32,
}

struct BoundedInMemoryExternalMemory {
    maximum_byte_length: usize,
    committed: BTreeMap<ProofExternalMemoryObject, TestExternalMemoryObject>,
    transaction: Option<TestExternalMemoryTransaction>,
}

impl BoundedInMemoryExternalMemory {
    fn new(maximum_byte_length: usize) -> Self {
        Self {
            maximum_byte_length,
            committed: BTreeMap::new(),
            transaction: None,
        }
    }

    fn transaction_for_operation(
        &mut self,
        payload_byte_length: usize,
    ) -> Result<&mut TestExternalMemoryTransaction, TestExternalMemoryError> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(TestExternalMemoryError::MissingTransaction)?;
        transaction.remaining_operation_count = transaction
            .remaining_operation_count
            .checked_sub(1)
            .ok_or(TestExternalMemoryError::OperationLimitExceeded)?;
        transaction.remaining_payload_byte_length = transaction
            .remaining_payload_byte_length
            .checked_sub(payload_byte_length)
            .ok_or(TestExternalMemoryError::PayloadLimitExceeded)?;
        Ok(transaction)
    }
}

impl ProofExternalMemory for BoundedInMemoryExternalMemory {
    type Error = TestExternalMemoryError;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error> {
        if self.transaction.is_some() {
            return Err(TestExternalMemoryError::DuplicateTransaction);
        }
        let mut undo = Vec::new();
        undo.try_reserve_exact(
            usize::try_from(maximum_operation_count)
                .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?,
        )
        .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?;
        self.transaction = Some(TestExternalMemoryTransaction {
            objects: std::mem::take(&mut self.committed),
            undo,
            remaining_payload_byte_length: usize::try_from(maximum_payload_byte_length)
                .map_err(|_| TestExternalMemoryError::PayloadLimitExceeded)?,
            remaining_operation_count: maximum_operation_count,
        });
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        if protection != ProofExternalMemoryProtection::PublicIntegrity {
            return Err(TestExternalMemoryError::UnsupportedProtection);
        }
        let maximum_byte_length = self.maximum_byte_length;
        let exact_byte_length = usize::try_from(exact_byte_length)
            .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?;
        let transaction = self.transaction_for_operation(0)?;
        if transaction.objects.contains_key(&object) {
            return Err(TestExternalMemoryError::DuplicateObject);
        }
        transaction
            .objects
            .values()
            .try_fold(0_usize, |total, object| {
                total.checked_add(object.exact_byte_length)
            })
            .and_then(|total| total.checked_add(exact_byte_length))
            .filter(|total| *total <= maximum_byte_length)
            .ok_or(TestExternalMemoryError::StorageLimitExceeded)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(exact_byte_length)
            .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?;
        transaction.objects.insert(
            object,
            TestExternalMemoryObject {
                bytes,
                exact_byte_length,
                sealed: false,
            },
        );
        transaction
            .undo
            .push(TestExternalMemoryUndo::RemoveCreated(object));
        Ok(())
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(bytes.len())?;
        let expected_offset = usize::try_from(expected_offset)
            .map_err(|_| TestExternalMemoryError::WrongOffsetOrLength)?;
        let previous_byte_length = {
            let stored = transaction
                .objects
                .get_mut(&object)
                .ok_or(TestExternalMemoryError::MissingObject)?;
            stored
                .bytes
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= stored.exact_byte_length)
                .ok_or(TestExternalMemoryError::WrongOffsetOrLength)?;
            if stored.sealed || stored.bytes.len() != expected_offset {
                return Err(TestExternalMemoryError::WrongOffsetOrLength);
            }
            stored.bytes.len()
        };
        transaction
            .undo
            .push(TestExternalMemoryUndo::TruncateAppended {
                object,
                previous_byte_length,
            });
        transaction
            .objects
            .get_mut(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?
            .bytes
            .extend_from_slice(bytes);
        Ok(())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(0)?;
        let previous_sealed = {
            let stored = transaction
                .objects
                .get(&object)
                .ok_or(TestExternalMemoryError::MissingObject)?;
            if stored.sealed || stored.bytes.len() != stored.exact_byte_length {
                return Err(TestExternalMemoryError::WrongOffsetOrLength);
            }
            stored.sealed
        };
        transaction.undo.push(TestExternalMemoryUndo::RestoreSeal {
            object,
            previous_sealed,
        });
        transaction
            .objects
            .get_mut(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?
            .sealed = true;
        Ok(())
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let stored = self
            .transaction_for_operation(destination.len())?
            .objects
            .get(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?;
        let offset =
            usize::try_from(offset).map_err(|_| TestExternalMemoryError::WrongOffsetOrLength)?;
        let end = offset
            .checked_add(destination.len())
            .ok_or(TestExternalMemoryError::WrongOffsetOrLength)?;
        if !stored.sealed {
            return Err(TestExternalMemoryError::WrongOffsetOrLength);
        }
        destination.copy_from_slice(
            stored
                .bytes
                .get(offset..end)
                .ok_or(TestExternalMemoryError::WrongOffsetOrLength)?,
        );
        Ok(())
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(0)?;
        let value = transaction
            .objects
            .remove(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?;
        transaction
            .undo
            .push(TestExternalMemoryUndo::RestoreDeleted { object, value });
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .take()
            .ok_or(TestExternalMemoryError::MissingTransaction)?;
        self.committed = transaction.objects;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        let mut transaction = self
            .transaction
            .take()
            .ok_or(TestExternalMemoryError::MissingTransaction)?;
        while let Some(undo) = transaction.undo.pop() {
            match undo {
                TestExternalMemoryUndo::RemoveCreated(object) => {
                    transaction
                        .objects
                        .remove(&object)
                        .ok_or(TestExternalMemoryError::MissingObject)?;
                }
                TestExternalMemoryUndo::TruncateAppended {
                    object,
                    previous_byte_length,
                } => {
                    let stored = transaction
                        .objects
                        .get_mut(&object)
                        .ok_or(TestExternalMemoryError::MissingObject)?;
                    if previous_byte_length > stored.bytes.len() {
                        return Err(TestExternalMemoryError::WrongOffsetOrLength);
                    }
                    stored.bytes.truncate(previous_byte_length);
                }
                TestExternalMemoryUndo::RestoreSeal {
                    object,
                    previous_sealed,
                } => {
                    transaction
                        .objects
                        .get_mut(&object)
                        .ok_or(TestExternalMemoryError::MissingObject)?
                        .sealed = previous_sealed;
                }
                TestExternalMemoryUndo::RestoreDeleted { object, value } => {
                    if transaction.objects.insert(object, value).is_some() {
                        return Err(TestExternalMemoryError::DuplicateObject);
                    }
                }
            }
        }
        self.committed = transaction.objects;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestPrivateCoinError {
    CallLimitExceeded,
    ByteLimitExceeded,
    InvalidModulus,
}

struct BoundedDeterministicTestPrivateCoins {
    next_value: u64,
    remaining_call_count: u32,
    remaining_byte_count: usize,
}

impl BoundedDeterministicTestPrivateCoins {
    fn new(maximum_call_count: u32, maximum_byte_count: usize) -> Self {
        Self {
            next_value: 1,
            remaining_call_count: maximum_call_count,
            remaining_byte_count: maximum_byte_count,
        }
    }

    fn consume_call(&mut self) -> Result<(), TestPrivateCoinError> {
        self.remaining_call_count = self
            .remaining_call_count
            .checked_sub(1)
            .ok_or(TestPrivateCoinError::CallLimitExceeded)?;
        Ok(())
    }
}

impl CommonProofPrivateCoinSource for BoundedDeterministicTestPrivateCoins {
    type Error = TestPrivateCoinError;

    fn sample_modulo(
        &mut self,
        _purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        self.consume_call()?;
        if modulus < 2 || maximum_candidate_draws_per_output == 0 {
            return Err(TestPrivateCoinError::InvalidModulus);
        }
        let value = self.next_value % modulus;
        self.next_value = self.next_value.wrapping_add(1);
        Ok(value)
    }

    fn fill_raw_bytes(&mut self, _purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.consume_call()?;
        self.remaining_byte_count = self
            .remaining_byte_count
            .checked_sub(destination.len())
            .ok_or(TestPrivateCoinError::ByteLimitExceeded)?;
        for (offset, byte) in destination.iter_mut().enumerate() {
            *byte = self.next_value.wrapping_add(offset as u64) as u8;
        }
        self.next_value = self
            .next_value
            .wrapping_add(u64::try_from(destination.len()).unwrap_or(u64::MAX));
        Ok(())
    }
}

fn test_setup_polynomial_tree(
    tree_catalog_index: usize,
    constant_value: u64,
) -> SetupPublicPolynomialTree {
    let context = SetupPublicPolynomialContext::public_key_share(
        [0x31_u8.wrapping_add(tree_catalog_index as u8); 64],
        [0x71_u8.wrapping_add(tree_catalog_index as u8); 64],
        u16::try_from(tree_catalog_index).expect("the toy owner position fits u16"),
    )
    .expect("the public-key-share polynomial context is canonical");
    let ordered_coefficient_columns = vec![vec![
        ProofBaseFieldElement::from_canonical(constant_value)
            .expect("the toy source coefficient is canonical"),
    ]];
    SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
        context: &context,
        evaluation_domain_size: EVALUATION_DOMAIN_SIZE as usize,
        source_polynomial_degree_bound_exclusive: OPENING_DEGREE_BOUND_EXCLUSIVE as usize,
        ordered_coefficient_columns: &ordered_coefficient_columns,
    })
    .expect("the public-polynomial LDE tree is canonical")
}

struct NoVerifiedSequenceColumns;

impl VerifiedRelationColumnEvaluator for NoVerifiedSequenceColumns {
    fn evaluate_at_extension_point(
        &mut self,
        _column_ordinal: u32,
        _point: super::super::ProofChallengeExtensionElement,
    ) -> Option<super::super::ProofChallengeExtensionElement> {
        None
    }
}

struct CommonProofEngineFixture {
    relation_context: RelationPlanCheckContext,
    relation_plan: CompiledRelationPlan,
    canonical_application_statement_bytes: Vec<u8>,
    relation_trees: Vec<RelationProofTreeInput>,
    provided_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
    setup_polynomial_trees: Vec<SetupPublicPolynomialTree>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

fn relation_context() -> RelationPlanCheckContext {
    let evaluation_domain = ProofEvaluationDomain::new(
        usize::try_from(EVALUATION_DOMAIN_SIZE).expect("the toy domain fits usize"),
        PROOF_EVALUATION_COSET_OFFSET,
    )
    .expect("the toy evaluation domain is valid");
    RelationPlanCheckContext {
        base_field_modulus: PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
        evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
        evaluation_domain_generator: evaluation_domain.generator().canonical(),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        deep_point_count: PROOF_DEEP_POINT_COUNT,
        quotient_component_count: 2,
        quotient_component_degree_bound_exclusive: 2,
        fri_fold_count: 1,
        final_polynomial_degree_bound_exclusive: PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
        unique_query_count: PROOF_UNIQUE_QUERY_COUNT,
        non_native_modular_identity_challenge_count: PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT,
        maximum_fiat_shamir_candidate_draws_per_output:
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        resolved_moduli: vec![ResolvedSuiteModulus::new(
            SuiteModulusReference::data(0),
            97,
        )],
    }
}

fn target_relation_context() -> RelationPlanCheckContext {
    let evaluation_domain = ProofEvaluationDomain::new(
        TARGET_TEST_EVALUATION_DOMAIN_SIZE as usize,
        PROOF_EVALUATION_COSET_OFFSET,
    )
    .expect("the target test evaluation domain is valid");
    RelationPlanCheckContext {
        base_field_modulus: PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
        evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
        evaluation_domain_generator: evaluation_domain.generator().canonical(),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        deep_point_count: 1,
        quotient_component_count: 4,
        quotient_component_degree_bound_exclusive: 128,
        fri_fold_count: 5,
        final_polynomial_degree_bound_exclusive: 8,
        unique_query_count: 8,
        non_native_modular_identity_challenge_count: 1,
        maximum_fiat_shamir_candidate_draws_per_output:
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        resolved_moduli: vec![ResolvedSuiteModulus::new(
            SuiteModulusReference::target(0),
            97,
        )],
    }
}

fn canonical_collective_public_key_statement(roots: &[[u8; 64]]) -> Vec<u8> {
    let source_roots = roots[..2]
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512([0x21; 64]),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &source_roots)
                .expect("the source-root list encodes"),
            CanonicalItem::hash512(roots[2]),
        ],
    )
    .encode()
    .expect("the toy application statement encodes")
}

fn canonical_rkg_round_one_aggregate_statement(roots: &[[u8; 64]]) -> Vec<u8> {
    assert_eq!(roots.len(), 6);
    let source_pairs = (0..2)
        .map(|participant_ordinal| {
            CanonicalItem::nested_tuple(&CanonicalTuple::new(
                0x3101,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::hash512(roots[participant_ordinal]),
                    CanonicalItem::hash512(roots[3 + participant_ordinal]),
                ],
            ))
            .expect("the aggregate source pair encodes")
        })
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512([0x22; 64]),
            CanonicalItem::unsigned32(7),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &source_pairs)
                .expect("the aggregate source-pair list encodes"),
            CanonicalItem::hash512(roots[2]),
            CanonicalItem::hash512(roots[5]),
        ],
    )
    .encode()
    .expect("the round-one aggregate statement encodes")
}

fn canonical_evaluator_key_aggregate_statement(roots: &[[u8; 64]]) -> Vec<u8> {
    assert_eq!(roots.len(), 3);
    let source_roots = roots[..2]
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    let aggregate_roots = vec![CanonicalItem::hash512(roots[2])];
    let entry = CanonicalItem::nested_tuple(&CanonicalTuple::new(
        0x3102,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned32(3),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &source_roots)
                .expect("the evaluator source-root list encodes"),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &aggregate_roots)
                .expect("the evaluator aggregate-root list encodes"),
        ],
    ))
    .expect("the evaluator entry encodes");
    CanonicalTuple::new(
        EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512([0x23; 64]),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &[entry])
                .expect("the evaluator entry list encodes"),
        ],
    )
    .encode()
    .expect("the evaluator aggregate statement encodes")
}

fn canonical_target_stream_descriptor(stream_hash: [u8; 64]) -> CanonicalItem {
    CanonicalItem::nested_tuple(&CanonicalTuple::new(
        0x3201,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(stream_hash),
            CanonicalItem::unsigned64(TARGET_TEST_RING_DEGREE as u64),
        ],
    ))
    .expect("the target stream descriptor encodes")
}

fn canonical_target_release_statement(material_root: [u8; 64]) -> Vec<u8> {
    CanonicalTuple::new(
        TARGET_RELEASE_STATEMENT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(1),
            CanonicalItem::hash512([0x11; 64]),
            CanonicalItem::hash512([0x41; 64]),
            CanonicalItem::hash512([0x42; 64]),
            CanonicalItem::hash512([0x43; 64]),
            CanonicalItem::hash512([0x44; 64]),
            CanonicalItem::hash512([0x45; 64]),
            CanonicalItem::hash512([0x46; 64]),
            CanonicalItem::participant_identity([0x47; 64]),
            CanonicalItem::unsigned16(0),
            CanonicalItem::homogeneous_list(
                CanonicalItemType::Hash512,
                &[CanonicalItem::hash512(material_root)],
            )
            .expect("the material-root list encodes"),
            canonical_target_stream_descriptor([0x48; 64]),
            canonical_target_stream_descriptor([0x49; 64]),
        ],
    )
    .encode()
    .expect("the target release statement encodes")
}

fn verified_statement_trees(
    relation_plan: &CompiledRelationPlan,
    trees: &[SetupPublicPolynomialTree],
    first_tree_override: Option<&SetupPublicPolynomialTree>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
) -> Vec<VerifiedStatementOwnedTree> {
    let variant = relation_plan
        .select_variant(schedule_position, top_count)
        .expect("the toy relation variant exists");
    variant
        .ordered_trees()
        .iter()
        .enumerate()
        .map(|(tree_index, descriptor)| {
            let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } = descriptor
            else {
                panic!("the public aggregate relation contains only bound trees");
            };
            let tree = if tree_index == 0 {
                first_tree_override.unwrap_or_else(|| {
                    trees
                        .get(tree_index)
                        .expect("the toy bound tree set is complete")
                })
            } else {
                trees
                    .get(tree_index)
                    .expect("the toy bound tree set is complete")
            };
            let ordered_canonical_residue_moduli = ordered_column_ordinals
                .iter()
                .map(|column_ordinal| {
                    variant
                        .ordered_columns()
                        .get(*column_ordinal as usize)
                        .expect("the checked tree column exists")
                        .canonical_residue_modulus()
                })
                .collect();
            VerifiedStatementOwnedTree::from_setup_public_polynomial_tree(
                u32::try_from(tree_index).expect("the toy tree index fits u32"),
                *expected_root_source_ordinal,
                tree,
                ordered_canonical_residue_moduli,
            )
        })
        .collect()
}

fn target_relation_tree_inputs(
    compilation: &CompiledTargetReleaseRelation,
    committed_material: &CommittedMaterialTree,
) -> (
    Vec<RelationProofTreeInput>,
    Vec<VerifiedStatementOwnedTree>,
    u16,
) {
    let variant = compilation
        .relation_plan()
        .select_variant(None, None)
        .expect("the target relation variant exists");
    let mut relation_trees = Vec::with_capacity(variant.ordered_trees().len());
    let mut verified_trees = Vec::new();
    let mut bound_tree_catalog_index = None;
    for (tree_index, descriptor) in variant.ordered_trees().iter().enumerate() {
        match descriptor {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => panic!("the checked target plan uses a known tree role"),
                };
                let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    variant
                        .ordered_columns()
                        .get(*column_ordinal as usize)
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::Prover)
                        })
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                relation_trees.push(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .expect("the target tree width fits u32"),
                    leaf_visibility,
                });
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind,
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } => {
                assert_eq!(
                    *construction_kind,
                    BoundTreeConstructionKind::CommittedMaterial
                );
                assert!(bound_tree_catalog_index.is_none());
                let tree_catalog_index =
                    u16::try_from(tree_index).expect("the target tree index fits u16");
                bound_tree_catalog_index = Some(tree_catalog_index);
                let tree_input = StatementOwnedProofTreeInput::CommittedMaterial {
                    material_context_hash: committed_material.material_context_hash(),
                    expected_root: committed_material.root(),
                };
                relation_trees.push(RelationProofTreeInput::BoundPublic(tree_input.clone()));
                verified_trees.push(VerifiedStatementOwnedTree::from_committed_material_tree(
                    u32::try_from(tree_index).expect("the target tree index fits u32"),
                    *expected_root_source_ordinal,
                    committed_material,
                    ordered_column_ordinals
                        .iter()
                        .map(|column_ordinal| {
                            variant
                                .ordered_columns()
                                .get(*column_ordinal as usize)
                                .expect("the checked target tree column exists")
                                .canonical_residue_modulus()
                        })
                        .collect(),
                ));
            }
        }
    }
    (
        relation_trees,
        verified_trees,
        bound_tree_catalog_index.expect("the target plan has one committed-material tree"),
    )
}

fn public_aggregate_geometry() -> PublicAggregateRelationGeometry {
    PublicAggregateRelationGeometry {
        ring_degree: 4,
        evaluation_domain_size: EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: OPENING_DEGREE_BOUND_EXCLUSIVE,
        public_polynomial_column_degree_bound_exclusive: 1,
        participant_count: 2,
    }
}

fn public_aggregate_common_proof_fixture(
    relation_context: RelationPlanCheckContext,
    relation_plan: CompiledRelationPlan,
    constant_values: &[u64],
    encode_statement: fn(&[[u8; 64]]) -> Vec<u8>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
) -> CommonProofEngineFixture {
    let variant = relation_plan
        .select_variant(schedule_position, top_count)
        .expect("the selected public aggregate variant exists");
    assert_eq!(variant.ordered_columns().len(), constant_values.len());
    assert_eq!(variant.ordered_trees().len(), constant_values.len());
    let trees = constant_values
        .iter()
        .copied()
        .enumerate()
        .map(|(tree_index, constant_value)| test_setup_polynomial_tree(tree_index, constant_value))
        .collect::<Vec<_>>();
    let roots = trees
        .iter()
        .map(SetupPublicPolynomialTree::root)
        .collect::<Vec<_>>();
    let relation_trees = trees
        .iter()
        .map(|tree| {
            RelationProofTreeInput::BoundPublic(StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash: tree.public_polynomial_context_hash(),
                row_width: tree.row_width(),
                expected_root: tree.root(),
            })
        })
        .collect();
    let provided_columns = constant_values
        .iter()
        .copied()
        .enumerate()
        .map(|(column_index, value)| {
            (
                u32::try_from(column_index).expect("the toy column index fits u32"),
                CommonProofSourcePolynomial::Base(vec![
                    ProofBaseFieldElement::from_canonical(value)
                        .expect("the toy source coefficient is canonical"),
                ]),
            )
        })
        .collect();
    CommonProofEngineFixture {
        relation_context,
        relation_plan,
        canonical_application_statement_bytes: encode_statement(&roots),
        relation_trees,
        provided_columns,
        setup_polynomial_trees: trees,
        schedule_position,
        top_count,
    }
}

fn common_proof_engine_fixture() -> CommonProofEngineFixture {
    let relation_context = relation_context();
    let relation_plan = compile_collective_public_key_aggregate_relation_plan(
        &CollectivePublicKeyAggregatePlanInput {
            geometry: public_aggregate_geometry(),
            ordered_component_moduli: vec![SuiteModulusReference::data(0)],
        },
        &relation_context,
    )
    .expect("the smallest production-schedule public aggregate plan compiles");
    public_aggregate_common_proof_fixture(
        relation_context,
        relation_plan,
        &[7, 11, 18],
        canonical_collective_public_key_statement,
        None,
        None,
    )
}

fn verify_fixture_proof_capability(
    fixture: &CommonProofEngineFixture,
    proof_bytes: &[u8],
    canonical_application_statement_bytes: &[u8],
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<VerifiedCommonProof, CommonProofVerifierError> {
    verify_common_proof(
        CommonProofVerificationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes,
            relation_plan: &fixture.relation_plan,
            relation_context: &fixture.relation_context,
            schedule_position: fixture.schedule_position,
            top_count: fixture.top_count,
            statement_owned_trees,
            proof_source: proof_bytes,
            declared_proof_byte_length: proof_bytes.len(),
            proof_byte_ceiling: MAXIMUM_PROOF_BYTE_LENGTH,
        },
        &mut NoVerifiedSequenceColumns,
    )
}

fn verify_fixture_proof_incrementally(
    fixture: &CommonProofEngineFixture,
    proof_bytes: &[u8],
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<VerifiedCommonProof, CommonProofVerifierError> {
    let maximum_resident_window_byte_length =
        2 * MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH;
    let mut verifier = CommonProofVerificationStateMachine::new(
        PollableCommonProofVerificationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &fixture
                .canonical_application_statement_bytes,
            relation_plan: &fixture.relation_plan,
            relation_context: &fixture.relation_context,
            schedule_position: fixture.schedule_position,
            top_count: fixture.top_count,
            statement_owned_trees,
            declared_proof_byte_length: proof_bytes.len(),
            proof_byte_ceiling: MAXIMUM_PROOF_BYTE_LENGTH,
            maximum_resident_window_byte_length,
        },
    )?;
    let mut poll_ordinal = 0_usize;
    loop {
        assert!(
            verifier.take_verified_common_proof().is_none(),
            "verification must not mint a capability before its terminal poll",
        );
        let required_range = verifier
            .required_byte_range()
            .expect("a nonterminal verifier requests one exact resident range");
        assert!(required_range.byte_length() <= maximum_resident_window_byte_length);
        let range_end = required_range
            .offset()
            .checked_add(required_range.byte_length())
            .expect("the checked proof range fits usize");
        let requested_bytes = proof_bytes
            .get(required_range.offset()..range_end)
            .expect("the verifier never requests beyond the declared proof");
        let minimum_first_chunk_byte_length = requested_bytes
            .len()
            .saturating_sub(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
        let maximum_first_chunk_byte_length = requested_bytes
            .len()
            .min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
        let split_byte_length = if requested_bytes.len() <= 1 {
            requested_bytes.len()
        } else {
            let rotating_boundary = 1 + (poll_ordinal.wrapping_mul(7_919) % (requested_bytes.len() - 1));
            rotating_boundary
                .max(minimum_first_chunk_byte_length)
                .min(maximum_first_chunk_byte_length)
                .min(requested_bytes.len() - 1)
        };
        let mut chunks = vec![ResidentCommonProofInputChunk::new(
            required_range.offset(),
            &requested_bytes[..split_byte_length],
        )];
        if split_byte_length < requested_bytes.len() {
            chunks.push(ResidentCommonProofInputChunk::new(
                required_range.offset() + split_byte_length,
                &requested_bytes[split_byte_length..],
            ));
        }
        let source = ResidentCommonProofByteSource::new(proof_bytes.len(), chunks)
            .expect("the required range fits the two-chunk resident window");
        let progress = verifier.poll(&source, &mut NoVerifiedSequenceColumns)?;
        poll_ordinal += 1;
        if progress == CommonProofVerificationPoll::Complete {
            break;
        }
    }
    let verified = verifier
        .take_verified_common_proof()
        .expect("only the terminal poll mints the verified capability");
    assert!(verifier.take_verified_common_proof().is_none());
    Ok(verified)
}

fn verify_fixture_proof(
    fixture: &CommonProofEngineFixture,
    proof_bytes: &[u8],
    canonical_application_statement_bytes: &[u8],
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<(), CommonProofVerifierError> {
    verify_fixture_proof_capability(
        fixture,
        proof_bytes,
        canonical_application_statement_bytes,
        statement_owned_trees,
    )
    .map(|_| ())
}

fn generate_fixture_proof(fixture: &mut CommonProofEngineFixture) -> Vec<u8> {
    let mut external_memory =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let mut private_coins = BoundedDeterministicTestPrivateCoins::new(1_024, 1_024 * 1_024);
    let mut sink = BoundedCommonProofByteSink::new(MAXIMUM_PROOF_BYTE_LENGTH)
        .expect("the bounded proof sink initializes");
    let mut bound_openings = SetupPublicPolynomialBoundOpeningProvider::new(
        fixture
            .setup_polynomial_trees
            .iter()
            .enumerate()
            .map(|(tree_index, tree)| {
                (
                    u16::try_from(tree_index).expect("the toy tree index fits u16"),
                    tree,
                )
            }),
    )
    .expect("the public-polynomial trees have one opening adapter");
    generate_common_proof(
        CommonProofGenerationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
            relation_plan: &fixture.relation_plan,
            relation_context: &fixture.relation_context,
            schedule_position: fixture.schedule_position,
            top_count: fixture.top_count,
            relation_trees: fixture.relation_trees.clone(),
            provided_pre_challenge_columns: fixture.provided_columns.clone(),
            maximum_external_memory_chunk_byte_length: MAXIMUM_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: MAXIMUM_PROOF_BYTE_LENGTH as u64,
        },
        &mut external_memory,
        &mut private_coins,
        &mut sink,
        &mut bound_openings,
    )
    .expect("the checked public aggregate relation produces one complete canonical proof");
    sink.finish()
}

#[test]
fn complete_common_proof_engine_round_trip_binds_proof_statement_and_verified_source_root() {
    let mut fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let proof_bytes = generate_fixture_proof(&mut fixture);

    let verified_proof = verify_fixture_proof_capability(
        &fixture,
        &proof_bytes,
        &fixture.canonical_application_statement_bytes,
        &verified_trees,
    )
    .expect("the complete generated proof verifies");
    assert_eq!(
        verified_proof.application_statement_schema_identifier(),
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER
    );
    assert_eq!(verified_proof.schedule_position(), None);
    assert_eq!(verified_proof.top_count(), None);
    assert_ne!(verified_proof.application_statement_hash(), [0_u8; 64]);
    assert_ne!(verified_proof.relation_plan_variant_hash(), [0_u8; 64]);

    let incrementally_verified_proof =
        verify_fixture_proof_incrementally(&fixture, &proof_bytes, &verified_trees)
            .expect("the same proof verifies across changing two-chunk resident windows");
    assert_eq!(
        incrementally_verified_proof.application_statement_hash(),
        verified_proof.application_statement_hash(),
    );
    assert_eq!(
        incrementally_verified_proof.relation_plan_variant_hash(),
        verified_proof.relation_plan_variant_hash(),
    );

    let header_byte_length =
        canonical_proof_object_header_bytes(&fixture.canonical_application_statement_bytes)
            .expect("the canonical proof header encodes")
            .len();
    let mut changed_proof_bytes = proof_bytes.clone();
    changed_proof_bytes[header_byte_length] ^= 1;
    assert!(
        verify_fixture_proof(
            &fixture,
            &changed_proof_bytes,
            &fixture.canonical_application_statement_bytes,
            &verified_trees,
        )
        .is_err(),
        "a changed proof-body root must fail closed",
    );

    let mut changed_statement_roots = fixture
        .setup_polynomial_trees
        .iter()
        .map(SetupPublicPolynomialTree::root)
        .collect::<Vec<_>>();
    changed_statement_roots[0][0] ^= 1;
    let changed_statement = canonical_collective_public_key_statement(&changed_statement_roots);
    assert_eq!(
        verify_fixture_proof(&fixture, &proof_bytes, &changed_statement, &verified_trees,),
        Err(CommonProofVerifierError::InvalidProofHeader),
    );

    let changed_source_tree = test_setup_polynomial_tree(0, 8);
    assert_ne!(
        changed_source_tree.root(),
        fixture.setup_polynomial_trees[0].root(),
        "a changed public-polynomial body must recompute a different LDE root",
    );
    let changed_verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        Some(&changed_source_tree),
        fixture.schedule_position,
        fixture.top_count,
    );
    assert!(
        verify_fixture_proof(
            &fixture,
            &proof_bytes,
            &fixture.canonical_application_statement_bytes,
            &changed_verified_trees,
        )
        .is_err(),
        "a public-polynomial body/root mismatch must fail the statement binding",
    );
}

#[test]
fn every_public_aggregate_family_uses_the_generated_prover_and_capability_verifier() {
    let rkg_context = relation_context();
    let rkg_plan = compile_rkg_round_one_aggregate_relation_plan(
        &RkgRoundOneAggregatePlanInput {
            geometry: public_aggregate_geometry(),
            ordered_variants: vec![RkgRoundOneAggregateVariantInput {
                schedule_position: 7,
                ordered_left_component_moduli: vec![SuiteModulusReference::data(0)],
                ordered_right_component_moduli: vec![SuiteModulusReference::data(0)],
            }],
        },
        &rkg_context,
    )
    .expect("the round-one aggregate relation compiles");
    let mut rkg_fixture = public_aggregate_common_proof_fixture(
        rkg_context,
        rkg_plan,
        &[7, 11, 18, 13, 17, 30],
        canonical_rkg_round_one_aggregate_statement,
        Some(7),
        None,
    );
    let rkg_trees = verified_statement_trees(
        &rkg_fixture.relation_plan,
        &rkg_fixture.setup_polynomial_trees,
        None,
        rkg_fixture.schedule_position,
        rkg_fixture.top_count,
    );
    let rkg_proof = generate_fixture_proof(&mut rkg_fixture);
    let verified_rkg = verify_fixture_proof_capability(
        &rkg_fixture,
        &rkg_proof,
        &rkg_fixture.canonical_application_statement_bytes,
        &rkg_trees,
    )
    .expect("the round-one aggregate common proof verifies");
    assert_eq!(
        verified_rkg.application_statement_schema_identifier(),
        RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    );
    assert_eq!(verified_rkg.schedule_position(), Some(7));
    assert_eq!(verified_rkg.top_count(), None);

    let evaluator_context = relation_context();
    let evaluator_plan = compile_evaluator_key_aggregate_relation_plan(
        &EvaluatorKeyAggregatePlanInput {
            geometry: public_aggregate_geometry(),
            ordered_variants: (1..=20)
                .map(|top_count| EvaluatorKeyAggregateVariantInput {
                    top_count,
                    relinearization_entry_count: 1,
                    ordered_entries: vec![EvaluatorKeyAggregateEntryPlanInput {
                        schedule_position: 3,
                        ordered_runtime_component_moduli: vec![SuiteModulusReference::data(0)],
                    }],
                })
                .collect(),
        },
        &evaluator_context,
    )
    .expect("the evaluator aggregate relation compiles");
    let mut evaluator_fixture = public_aggregate_common_proof_fixture(
        evaluator_context,
        evaluator_plan,
        &[5, 9, 14],
        canonical_evaluator_key_aggregate_statement,
        None,
        Some(1),
    );
    let evaluator_trees = verified_statement_trees(
        &evaluator_fixture.relation_plan,
        &evaluator_fixture.setup_polynomial_trees,
        None,
        evaluator_fixture.schedule_position,
        evaluator_fixture.top_count,
    );
    let evaluator_proof = generate_fixture_proof(&mut evaluator_fixture);
    let verified_evaluator = verify_fixture_proof_capability(
        &evaluator_fixture,
        &evaluator_proof,
        &evaluator_fixture.canonical_application_statement_bytes,
        &evaluator_trees,
    )
    .expect("the evaluator aggregate common proof verifies");
    assert_eq!(
        verified_evaluator.application_statement_schema_identifier(),
        EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    );
    assert_eq!(verified_evaluator.schedule_position(), None);
    assert_eq!(verified_evaluator.top_count(), Some(1));
    assert_ne!(
        verified_rkg.application_statement_hash(),
        verified_evaluator.application_statement_hash()
    );
}

#[test]
fn target_release_uses_the_same_generated_engine_and_public_only_verifier_adapter() {
    let relation_context = target_relation_context();
    let material_profile = CommittedMaterialProfile::for_common_proof_evaluation_domain(
        TARGET_TEST_RING_DEGREE,
        TARGET_TEST_EVALUATION_DOMAIN_SIZE as usize,
    )
    .expect("the target material profile matches the common-proof domain");
    let zero_share = vec![0_u64; TARGET_TEST_RING_DEGREE];
    let material_digits = vec![zero_share.clone(), vec![0_u64; TARGET_TEST_RING_DEGREE]];
    let committed_material = CommittedMaterialTree::construct(CommittedMaterialTreeInput {
        profile: material_profile,
        material_context_hash: [0x51; 64],
        material_seed: [0x52; 64],
        message_digit_columns: &material_digits,
    })
    .expect("the target committed material constructs on the proof domain");
    let compilation = compile_target_release_relation(
        &TargetReleaseRelationPlanInput {
            ring_degree: TARGET_TEST_RING_DEGREE as u64,
            evaluation_domain_size: TARGET_TEST_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: 512,
            material_column_degree_bound_exclusive: material_profile
                .material_column_degree_bound_exclusive()
                as u64,
            public_polynomial_column_degree_bound_exclusive: TARGET_TEST_RING_DEGREE as u64,
            target_modulus_indices: vec![0],
            decryption_scale: 4,
            simulation_scale: 4,
            flooding_bound: 3,
            first_mask_purpose: 43,
        },
        &relation_context,
    )
    .expect("the compact target relation compiles for the bounded engine fixture");
    let converted_identifier = vec![1, 3, 5, 7, 9, 11, 13, 15];
    let converted_order = vec![2, 4, 6, 8, 10, 12, 14, 16];
    let partial_identifier = vec![0_u64; TARGET_TEST_RING_DEGREE];
    let partial_order = vec![0_u64; TARGET_TEST_RING_DEGREE];
    let flooding_identifier = vec![0_i64; TARGET_TEST_RING_DEGREE];
    let flooding_order = vec![0_i64; TARGET_TEST_RING_DEGREE];
    let roles = [
        TargetReleaseRoleWitness {
            converted_a: &converted_identifier,
            partial_decryption: &partial_identifier,
        },
        TargetReleaseRoleWitness {
            converted_a: &converted_order,
            partial_decryption: &partial_order,
        },
    ];
    let modulus_witness = TargetReleaseModulusWitness {
        committed_share: &committed_material,
        threshold_share: &zero_share,
        roles,
    };
    let provided_columns = compilation
        .provided_pre_challenge_columns(TargetReleaseWitness {
            flooding_errors_by_role: [&flooding_identifier, &flooding_order],
            moduli: std::slice::from_ref(&modulus_witness),
        })
        .expect("the typed target witness supplies the common prover");
    let mut verified_column_evaluator = compilation
        .verified_column_evaluator(&[VerifiedTargetReleaseModulusInput { roles }])
        .expect("the verifier independently rebuilds only public target columns");
    let (relation_trees, verified_trees, bound_tree_catalog_index) =
        target_relation_tree_inputs(&compilation, &committed_material);
    let canonical_statement = canonical_target_release_statement(committed_material.root());
    let mut bound_openings = CommittedMaterialBoundOpeningProvider::new([(
        bound_tree_catalog_index,
        &committed_material,
    )])
    .expect("the persistent material tree has one catalog-indexed opening adapter");
    let maximum_proof_byte_length = 64 * 1_024 * 1_024;
    let mut external_memory = BoundedInMemoryExternalMemory::new(512 * 1_024 * 1_024);
    let mut private_coins =
        BoundedDeterministicTestPrivateCoins::new(1_000_000, 64 * 1_024 * 1_024);
    let mut sink = BoundedCommonProofByteSink::new(maximum_proof_byte_length)
        .expect("the target proof sink initializes");
    generate_common_proof(
        CommonProofGenerationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &canonical_statement,
            relation_plan: compilation.relation_plan(),
            relation_context: &relation_context,
            schedule_position: None,
            top_count: None,
            relation_trees,
            provided_pre_challenge_columns: provided_columns,
            maximum_external_memory_chunk_byte_length: MAXIMUM_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: maximum_proof_byte_length as u64,
        },
        &mut external_memory,
        &mut private_coins,
        &mut sink,
        &mut bound_openings,
    )
    .expect("the target relation uses the generated common prover");
    let proof_bytes = sink.finish();
    let verified_common_proof = verify_common_proof(
        CommonProofVerificationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &canonical_statement,
            relation_plan: compilation.relation_plan(),
            relation_context: &relation_context,
            schedule_position: None,
            top_count: None,
            statement_owned_trees: &verified_trees,
            proof_source: proof_bytes.as_slice(),
            declared_proof_byte_length: proof_bytes.len(),
            proof_byte_ceiling: maximum_proof_byte_length,
        },
        &mut verified_column_evaluator,
    )
    .expect("the generated target proof verifies through the common verifier");
    let verified_target = VerifiedTargetReleaseProof::from_common_proof(verified_common_proof)
        .expect("the common verifier capability has the target family and selector shape");
    assert_ne!(verified_target.application_statement_hash(), [0_u8; 64]);
    assert_ne!(verified_target.relation_plan_variant_hash(), [0_u8; 64]);

    let mut changed_converted_identifier = converted_identifier.clone();
    changed_converted_identifier[0] += 1;
    let mut changed_verified_column_evaluator = compilation
        .verified_column_evaluator(&[VerifiedTargetReleaseModulusInput {
            roles: [
                TargetReleaseRoleWitness {
                    converted_a: &changed_converted_identifier,
                    partial_decryption: &partial_identifier,
                },
                roles[1],
            ],
        }])
        .expect("the changed public target still has a canonical shape");
    assert!(
        verify_common_proof(
            CommonProofVerificationInput {
                protocol_version: 1,
                suite_identifier: [0x11; 64],
                canonical_application_statement_bytes: &canonical_statement,
                relation_plan: compilation.relation_plan(),
                relation_context: &relation_context,
                schedule_position: None,
                top_count: None,
                statement_owned_trees: &verified_trees,
                proof_source: proof_bytes.as_slice(),
                declared_proof_byte_length: proof_bytes.len(),
                proof_byte_ceiling: maximum_proof_byte_length,
            },
            &mut changed_verified_column_evaluator,
        )
        .is_err(),
        "changing a verifier-owned target stream must invalidate the proof",
    );
}
