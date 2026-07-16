use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::bgv::{
    parameters::POLYNOMIAL_DEGREE,
    setup::{
        LatticeAnchorCommitment, SETUP_COMMITMENT_MODULE_RANK,
        lattice_anchor_commitment_canonical_bytes,
    },
};
use crate::foundation::{
    BrowserWorkerAuthenticatedStorageHeadSource, BrowserWorkerAuthenticatedStorageTransitionSource,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalStreamDomain,
    CanonicalStreamVerifier, CanonicalTuple, FOUNDATION_PROFILE, Hash512, LocalStorageBinding,
    ParticipantIdentity, PrivateRandomCursor, ProofApplicationSlotCeilings, ProofObjectHeader,
    RefusalReason, StreamDescriptor, VerifiedCanonicalStreamSummary,
    derive_canonical_stream_descriptor,
};

use super::super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationTreeDescriptor,
};
use super::super::{
    BoundedCommonProofByteSink, CheckpointableCommonProofPrivateCoinSource,
    CollectivePublicKeyAggregatePlanInput, CommittedMaterialBoundOpeningProvider,
    CommittedMaterialProfile, CommittedMaterialTree, CommittedMaterialTreeInput,
    CommonProofApplicationBinding, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationOperationHandle, CommonProofGenerationSources,
    CommonProofGenerationStateMachine, CommonProofGenerationWorkerError,
    CommonProofGenerationWorkerPoll, CommonProofPrivateCoinSource, CommonProofProverError,
    CommonProofRelationPlanCapability, CommonProofResidentMemoryPhase, CommonProofRuntimeError,
    CommonProofRuntimeLimits, CommonProofRuntimeRegistry, CommonProofSourcePolynomial,
    CommonProofUpstreamInputRegistry, CommonProofVerificationBinding, CommonProofVerificationInput,
    CommonProofVerificationPoll, CommonProofVerificationStateMachine,
    CommonProofVerificationWorkerError, CommonProofVerificationWorkerPoll,
    CommonProofVerifierError, CompiledRelationPlan, CompiledTargetReleaseRelation,
    EvaluatorKeyAggregateEntryPlanInput, EvaluatorKeyAggregatePlanInput,
    EvaluatorKeyAggregateVariantInput, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR,
    PROOF_EVALUATION_COSET_OFFSET, PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT,
    PollableCommonProofVerificationInput, PreparedCommonProofGeneration,
    PreparedCommonProofVerification, ProofBaseFieldElement, ProofBodyError, ProofDecodeError,
    ProofEvaluationDomain, ProofExternalMemory, ProofExternalMemoryObject,
    ProofExternalMemoryProtection, ProofExternalMemoryTransactionOperation,
    ProofExternalMemoryTransactionRequest, ProofLeafVisibility, ProofProfileError, ProofTreeRole,
    PublicAggregateRelationGeometry, RelationPlanCheckContext, RelationProofTreeInput,
    ResidentCommonProofByteSource, ResidentCommonProofInputChunk, ResolvedSuiteModulus,
    RkgRoundOneAggregatePlanInput, RkgRoundOneAggregateVariantInput, SameSecretRelationPlanInput,
    SetupPublicPolynomialBoundOpeningProvider, SetupPublicPolynomialContext,
    SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput, StatementOwnedProofTreeInput,
    SuiteModulusReference, TargetReleaseModulusWitness, TargetReleaseRelationPlanInput,
    TargetReleaseRoleWitness, TargetReleaseWitness, VerifiedCommonProof,
    VerifiedCommonProofCapabilityHandle, VerifiedRelationColumnEvaluator,
    VerifiedStatementOwnedTree, VerifiedTargetReleaseModulusInput,
    canonical_proof_object_header_bytes, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_target_release_relation,
    durable_authorization_frame_digest, generate_common_proof, verified_application_statement_hash,
    verify_common_proof,
};
use super::SCHEMA_VERSION;

const APPLICATION_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
const RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1215;
const EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1218;
const TARGET_RELEASE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1621;
const EVALUATION_DOMAIN_SIZE: u64 = 4_096;
const TARGET_TEST_EVALUATION_DOMAIN_SIZE: u64 = 2_048;
const TARGET_TEST_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 256;
const TARGET_TEST_RING_DEGREE: usize = 64;
const OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 258;
const MAXIMUM_PROOF_BYTE_LENGTH: usize = 16 * 1_024 * 1_024;
const MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH: usize = 64 * 1_024 * 1_024;

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
    calls_by_purpose: BTreeMap<u16, u64>,
    checkpoint_cursor_family_schema_identifier: u16,
}

impl BoundedDeterministicTestPrivateCoins {
    fn new(maximum_call_count: u32, maximum_byte_count: usize) -> Self {
        Self {
            next_value: 1,
            remaining_call_count: maximum_call_count,
            remaining_byte_count: maximum_byte_count,
            calls_by_purpose: BTreeMap::new(),
            checkpoint_cursor_family_schema_identifier: APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        }
    }

    fn with_checkpoint_cursor_counter_delta(mut self, counter_delta: u64) -> Self {
        if counter_delta != 0 {
            self.checkpoint_cursor_family_schema_identifier =
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
            self.calls_by_purpose.insert(41, counter_delta);
        }
        self
    }

    fn consume_call(&mut self, purpose: u16) -> Result<(), TestPrivateCoinError> {
        self.remaining_call_count = self
            .remaining_call_count
            .checked_sub(1)
            .ok_or(TestPrivateCoinError::CallLimitExceeded)?;
        let call_count = self.calls_by_purpose.entry(purpose).or_default();
        *call_count = call_count
            .checked_add(1)
            .ok_or(TestPrivateCoinError::CallLimitExceeded)?;
        Ok(())
    }
}

impl CommonProofPrivateCoinSource for BoundedDeterministicTestPrivateCoins {
    type Error = TestPrivateCoinError;

    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        self.consume_call(purpose)?;
        if modulus < 2 || maximum_candidate_draws_per_output == 0 {
            return Err(TestPrivateCoinError::InvalidModulus);
        }
        let value = self.next_value % modulus;
        self.next_value = self.next_value.wrapping_add(1);
        Ok(value)
    }

    fn fill_raw_bytes(&mut self, purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.consume_call(purpose)?;
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

impl CheckpointableCommonProofPrivateCoinSource for BoundedDeterministicTestPrivateCoins {
    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor> {
        self.calls_by_purpose
            .iter()
            .map(|(purpose, call_count)| {
                PrivateRandomCursor::new(
                    self.checkpoint_cursor_family_schema_identifier,
                    *purpose,
                    Hash512::from_bytes([0x51; 64]),
                    [0x52; 32],
                    *call_count,
                    None,
                )
                .expect("the common-proof test purpose is assigned")
            })
            .collect()
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
        unique_query_count: 5,
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
            evaluator_auxiliary_roots: &[],
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
    let maximum_resident_window_byte_length = 2 * MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH;
    let verifier = fixture_incremental_verifier(
        fixture,
        statement_owned_trees,
        proof_bytes.len(),
        maximum_resident_window_byte_length,
    )?;
    complete_incremental_verification(verifier, proof_bytes)
}

fn complete_incremental_verification(
    mut verifier: CommonProofVerificationStateMachine,
    proof_bytes: &[u8],
) -> Result<VerifiedCommonProof, CommonProofVerifierError> {
    let maximum_resident_window_byte_length = 2 * MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH;
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
            let rotating_boundary =
                1 + (poll_ordinal.wrapping_mul(7_919) % (requested_bytes.len() - 1));
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

fn fixture_incremental_verifier(
    fixture: &CommonProofEngineFixture,
    statement_owned_trees: &[VerifiedStatementOwnedTree],
    declared_proof_byte_length: usize,
    maximum_resident_window_byte_length: usize,
) -> Result<CommonProofVerificationStateMachine, CommonProofVerifierError> {
    CommonProofVerificationStateMachine::new(PollableCommonProofVerificationInput {
        protocol_version: 1,
        suite_identifier: [0x11; 64],
        canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
        relation_plan: &fixture.relation_plan,
        relation_context: &fixture.relation_context,
        schedule_position: fixture.schedule_position,
        top_count: fixture.top_count,
        statement_owned_trees,
        evaluator_auxiliary_roots: &[],
        declared_proof_byte_length,
        proof_byte_ceiling: MAXIMUM_PROOF_BYTE_LENGTH,
        maximum_resident_window_byte_length,
    })
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
            maximum_external_memory_chunk_byte_length:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
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

fn prepared_generation_worker_fixture() -> (PreparedCommonProofGeneration, Vec<u8>) {
    prepared_generation_worker_fixture_for_checkpoint(None, 0)
        .expect("the fresh genuine generation fixture starts at checkpoint genesis")
}

fn prepared_verification_worker_fixture() -> PreparedCommonProofVerification {
    let fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let runtime_limits = CommonProofRuntimeLimits::new(
        super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
    )
    .expect("the fixed worker limits are valid");
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &fixture.relation_plan,
        &fixture.relation_context,
        fixture.schedule_position,
        fixture.top_count,
    )
    .expect("the checked relation plan mints an application capability");
    let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
        fixture.canonical_application_statement_bytes.clone(),
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.proof_header_hash())
    .expect("the fixture statement has one canonical proof header")
    .into_bytes();
    let stream_domain = CanonicalStreamDomain::CollectivePublicKeyAggregateProof;
    let proof_stream_descriptor = StreamDescriptor {
        total_byte_length: super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        ordered_chunk_digests: vec![Hash512::from_bytes([0x45; 64]); 5],
        full_object_digest: Hash512::from_bytes([0x44; 64]),
    };
    let proof_application = CommonProofApplicationBinding::new(
        [0x41; 64],
        [0x42; 64],
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        proof_header_hash,
        stream_domain,
        proof_stream_descriptor.full_object_digest.into_bytes(),
        super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        PROOF_UNIQUE_QUERY_COUNT,
    )
    .expect("the fixture application fits the worker ceiling");
    let verification_binding = CommonProofVerificationBinding::new(
        [0x11; 64],
        [0x32; 64],
        [0x31; 64],
        [0x33; 64],
        proof_application,
        relation_plan_capability.relation_plan_hash(),
    );
    let mut upstream_registry = CommonProofUpstreamInputRegistry::default();
    let application_handle = upstream_registry
        .install_test_application_fixture(
            verification_binding,
            relation_plan_capability,
            1,
            &fixture.canonical_application_statement_bytes,
            proof_stream_descriptor,
            runtime_limits,
        )
        .expect("the positively constructed application is retained");
    let statement_tree_handles = verified_trees
        .into_iter()
        .map(|tree| {
            upstream_registry
                .mint_statement_tree(&application_handle, tree)
                .expect("the verified statement tree is retained")
        })
        .collect::<Vec<_>>();
    upstream_registry
        .consume_verification_inputs(
            &application_handle,
            &statement_tree_handles.iter().collect::<Vec<_>>(),
            &[],
            None,
        )
        .expect("the exact verifier capability set is consumed")
        .prepare()
        .expect("the owned verifier initializes")
}

#[test]
fn wasm_family_adapters_derive_bindings_and_discard_unstarted_preparations_once() {
    let (prepared_generation, _) = prepared_generation_worker_fixture();
    let expected_runtime_binding_hash = prepared_generation.runtime_binding_hash();
    let expected_verification_binding_hash = prepared_generation.verification_binding_hash();
    let expected_lineage_identifier = prepared_generation.proof_attempt_lineage_identifier();
    let generation_adapter =
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::fresh(prepared_generation);
    let generation_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(
            generation_adapter,
        )
        .expect("the exact-family prover adapter is retained");
    let mut described_runtime_binding_hash = [0_u8; 64];
    let mut described_verification_binding_hash = [0_u8; 64];
    let mut described_lineage_identifier = [0_u8; 32];
    let mut status = u32::MAX;
    assert_eq!(
        unsafe {
            super::super::runtime_ffi::sealed_lattice_common_proof_describe_generation_family_adapter(
                generation_adapter_handle,
                described_runtime_binding_hash.as_mut_ptr(),
                described_verification_binding_hash.as_mut_ptr(),
                described_lineage_identifier.as_mut_ptr(),
                &mut status,
            )
        },
        0,
    );
    assert_eq!(status, 0);
    assert_eq!(
        described_runtime_binding_hash,
        expected_runtime_binding_hash
    );
    assert_eq!(
        described_verification_binding_hash,
        expected_verification_binding_hash
    );
    assert_eq!(described_lineage_identifier, expected_lineage_identifier);
    let generation_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            generation_adapter_handle,
            core::ptr::null(),
            0,
            &mut status,
        )
    };
    assert_ne!(generation_handle, 0);
    assert_eq!(status, 0);
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_generation(
            generation_handle,
        ),
        0,
    );
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_generation(
            generation_handle,
        ),
        RefusalReason::ConsumedState.canonical_code() as u32,
        "a discarded prover preparation remains permanently stale",
    );

    let prepared_verification = prepared_verification_worker_fixture();
    let expected_verification_binding_hash = prepared_verification.verification_binding_hash();
    let verification_adapter =
        super::super::runtime_ffi::CommonProofVerificationFamilyAdapter::new(prepared_verification);
    let verification_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_verification_family_adapter(
            verification_adapter,
        )
        .expect("the exact-family verifier adapter is retained");
    let mut described_verification_binding_hash = [0_u8; 64];
    assert_eq!(
        unsafe {
            super::super::runtime_ffi::sealed_lattice_common_proof_describe_verification_family_adapter(
                verification_adapter_handle,
                described_verification_binding_hash.as_mut_ptr(),
                &mut status,
            )
        },
        0,
    );
    assert_eq!(status, 0);
    assert_eq!(
        described_verification_binding_hash,
        expected_verification_binding_hash
    );
    let verification_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_verification_family_adapter(
            verification_adapter_handle,
            &mut status,
        )
    };
    assert_ne!(verification_handle, 0);
    assert_eq!(status, 0);
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_verification(
            verification_handle,
        ),
        0,
    );
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_verification(
            verification_handle,
        ),
        RefusalReason::ConsumedState.canonical_code() as u32,
        "a discarded verifier preparation remains permanently stale",
    );
}

#[test]
fn family_terminal_consumer_refuses_before_positive_verification() {
    let mut consumer_called = false;
    let result = super::super::runtime_ffi::consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(0),
        |_capability| {
            consumer_called = true;
            Ok(())
        },
    );
    assert_eq!(result, Err(CommonProofRuntimeError::UnknownOrStaleHandle));
    assert!(
        !consumer_called,
        "decoded bytes cannot invoke a family consumer"
    );
}

#[test]
fn resume_family_adapter_authenticates_checkpoint_before_invoking_family_preparation() {
    let refused_callback_count = Rc::new(Cell::new(0_u32));
    let refused_callback_observation = Rc::clone(&refused_callback_count);
    let refused_adapter = super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::resume(
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapterDescription::new(
            [0x11; 64], [0x22; 64], [0x33; 32],
        ),
        [0x44; 32],
        Hash512::from_bytes([0x55; 64]),
        Box::new(move |_continuation| {
            refused_callback_observation.set(refused_callback_observation.get() + 1);
            Err(CommonProofRuntimeError::WrongVerificationBinding.into())
        }),
    );
    let refused_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(refused_adapter)
            .expect("the malformed-checkpoint adapter is retained");
    let malformed_checkpoint_state = [0x91_u8; 7];
    let mut status = u32::MAX;
    let prepared_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            refused_adapter_handle,
            malformed_checkpoint_state.as_ptr(),
            malformed_checkpoint_state.len(),
            &mut status,
        )
    };
    assert_eq!(prepared_handle, 0);
    assert_ne!(status, 0);
    assert_eq!(
        refused_callback_count.get(),
        0,
        "canonical checkpoint decoding precedes exact-family continuation authority"
    );

    let (authenticated_checkpoint_state, _, _, _) = capture_first_generation_checkpoint();
    let (prepared, _) =
        prepared_generation_worker_fixture_for_checkpoint(Some(&authenticated_checkpoint_state), 0)
            .expect("the authenticated checkpoint prepares the exact resumed attempt");
    let expected_runtime_binding_hash = prepared.runtime_binding_hash();
    let expected_verification_binding_hash = prepared.verification_binding_hash();
    let expected_lineage_identifier = prepared.proof_attempt_lineage_identifier();
    let checkpoint_lineage_identifier = prepared.checkpoint_lineage_identifier();
    let checkpoint_schedule_digest = prepared.checkpoint_schedule_digest();

    let wrong_binding_callback_count = Rc::new(Cell::new(0_u32));
    let wrong_binding_callback_observation = Rc::clone(&wrong_binding_callback_count);
    let wrong_binding_adapter =
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::resume(
            super::super::runtime_ffi::CommonProofGenerationFamilyAdapterDescription::new(
                expected_runtime_binding_hash,
                expected_verification_binding_hash,
                expected_lineage_identifier,
            ),
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
            Box::new(move |_continuation| {
                wrong_binding_callback_observation
                    .set(wrong_binding_callback_observation.get() + 1);
                Err(CommonProofRuntimeError::WrongVerificationBinding.into())
            }),
        );
    let wrong_binding_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(
            wrong_binding_adapter,
        )
        .expect("the wrong-binding resume adapter is retained");
    let mut wrong_binding_checkpoint_state = authenticated_checkpoint_state.clone();
    wrong_binding_checkpoint_state[12] ^= 1;
    status = u32::MAX;
    let wrong_binding_prepared_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            wrong_binding_adapter_handle,
            wrong_binding_checkpoint_state.as_ptr(),
            wrong_binding_checkpoint_state.len(),
            &mut status,
        )
    };
    assert_eq!(wrong_binding_prepared_handle, 0);
    assert_ne!(status, 0);
    assert_eq!(
        wrong_binding_callback_count.get(),
        0,
        "the authenticated stable-attempt binding is checked before exact-family continuation authority"
    );

    let callback_count = Rc::new(Cell::new(0_u32));
    let callback_observation = Rc::clone(&callback_count);
    let adapter = super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::resume(
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapterDescription::new(
            expected_runtime_binding_hash,
            expected_verification_binding_hash,
            expected_lineage_identifier,
        ),
        checkpoint_lineage_identifier,
        checkpoint_schedule_digest,
        Box::new(move |continuation| {
            assert_eq!(
                continuation.checkpoint_lineage_identifier(),
                checkpoint_lineage_identifier
            );
            assert_eq!(
                continuation.checkpoint_schedule_digest(),
                checkpoint_schedule_digest
            );
            assert!(continuation.next_event_index() > 0);
            callback_observation.set(callback_observation.get() + 1);
            Ok(prepared)
        }),
    );
    let adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(adapter)
            .expect("the authenticated resume adapter is retained");
    let prepared_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            adapter_handle,
            authenticated_checkpoint_state.as_ptr(),
            authenticated_checkpoint_state.len(),
            &mut status,
        )
    };
    assert_ne!(prepared_handle, 0);
    assert_eq!(status, 0);
    assert_eq!(callback_count.get(), 1);
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_generation(
            prepared_handle,
        ),
        0
    );
}

fn prepared_generation_worker_fixture_for_checkpoint(
    authenticated_checkpoint_state: Option<&[u8]>,
    checkpoint_cursor_counter_delta: u64,
) -> Result<(PreparedCommonProofGeneration, Vec<u8>), CommonProofRuntimeError> {
    let mut fixture = common_proof_engine_fixture();
    let expected_proof_bytes = generate_fixture_proof(&mut fixture);
    let stream_domain = CanonicalStreamDomain::CollectivePublicKeyAggregateProof;
    let stream_descriptor =
        derive_canonical_stream_descriptor(stream_domain, &expected_proof_bytes)
            .expect("the genuine generated proof has one canonical descriptor");
    let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
        fixture.canonical_application_statement_bytes.clone(),
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.proof_header_hash())
    .expect("the genuine fixture statement has one canonical proof header");
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &fixture.relation_plan,
        &fixture.relation_context,
        fixture.schedule_position,
        fixture.top_count,
    )
    .expect("the genuine fixture relation plan is checked");
    let proof_application = CommonProofApplicationBinding::new(
        [0x81; 64],
        [0x82; 64],
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        proof_header_hash.into_bytes(),
        stream_domain,
        stream_descriptor.full_object_digest.into_bytes(),
        stream_descriptor.total_byte_length,
        fixture.relation_context.unique_query_count,
    )
    .expect("the genuine proof application has bounded coordinates");
    let verification_binding = CommonProofVerificationBinding::new(
        [0x11; 64],
        [0x83; 64],
        [0x84; 64],
        [0x85; 64],
        proof_application,
        relation_plan.relation_plan_hash(),
    );
    let limits = CommonProofRuntimeLimits::new(
        expected_proof_bytes.len(),
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        u64::try_from(
            expected_proof_bytes
                .len()
                .min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH),
        )
        .expect("the prefetch window fits u64"),
    )
    .expect("the genuine proof fits the browser worker limits");
    let state = CommonProofGenerationStateMachine::new(CommonProofGenerationInput {
        protocol_version: 1,
        suite_identifier: [0x11; 64],
        canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
        relation_plan: &fixture.relation_plan,
        relation_context: &fixture.relation_context,
        schedule_position: fixture.schedule_position,
        top_count: fixture.top_count,
        relation_trees: fixture.relation_trees,
        provided_pre_challenge_columns: fixture.provided_columns,
        maximum_external_memory_chunk_byte_length:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        maximum_prefetched_query_byte_length: limits.prefetched_query_byte_length(),
    })
    .expect("the genuine generation state owns the checked relation inputs");
    let bound_openings = SetupPublicPolynomialBoundOpeningProvider::from_owned(
        fixture
            .setup_polynomial_trees
            .into_iter()
            .enumerate()
            .map(|(tree_index, tree)| {
                (
                    u16::try_from(tree_index).expect("the fixture tree index fits u16"),
                    tree,
                )
            }),
    )
    .expect("the worker owns the genuine public-polynomial opening trees");
    let sources = CommonProofGenerationSources::new(
        BoundedDeterministicTestPrivateCoins::new(1_024, 1_024 * 1_024)
            .with_checkpoint_cursor_counter_delta(checkpoint_cursor_counter_delta),
        bound_openings,
    );
    let prepared = match authenticated_checkpoint_state {
        Some(checkpoint_state_bytes) => {
            PreparedCommonProofGeneration::from_genuine_test_sources_for_authenticated_checkpoint(
                verification_binding,
                relation_plan,
                state,
                sources,
                limits,
                checkpoint_state_bytes,
            )?
        }
        None => PreparedCommonProofGeneration::from_genuine_test_sources(
            verification_binding,
            relation_plan,
            state,
            sources,
            limits,
        ),
    };
    Ok((prepared, expected_proof_bytes))
}

fn execute_generation_storage_request(
    request: &ProofExternalMemoryTransactionRequest,
    storage: &mut BoundedInMemoryExternalMemory,
) -> Vec<u8> {
    storage
        .begin_transaction(
            request.maximum_payload_byte_length(),
            request.maximum_operation_count(),
        )
        .expect("the browser storage transaction starts within its declared limits");
    let mut read_results = Vec::new();
    for operation in request.operations() {
        match operation {
            ProofExternalMemoryTransactionOperation::Create {
                object,
                protection,
                exact_byte_length,
            } => storage
                .create_object(*object, *protection, *exact_byte_length)
                .expect("the requested external object is created"),
            ProofExternalMemoryTransactionOperation::Append {
                object,
                expected_offset,
                bytes,
            } => storage
                .append_object_bytes(*object, *expected_offset, bytes)
                .expect("the requested external bytes append at the exact offset"),
            ProofExternalMemoryTransactionOperation::Seal { object } => storage
                .seal_object(*object)
                .expect("the requested external object seals"),
            ProofExternalMemoryTransactionOperation::Read {
                object,
                offset,
                byte_length,
            } => {
                let mut bytes = vec![
                    0_u8;
                    usize::try_from(*byte_length)
                        .expect("the bounded read length fits usize")
                ];
                storage
                    .read_object_bytes(*object, *offset, &mut bytes)
                    .expect("the requested sealed bytes are reread");
                read_results.push(bytes);
            }
            ProofExternalMemoryTransactionOperation::Delete { object } => storage
                .delete_object(*object)
                .expect("the requested exhausted object is deleted"),
        }
    }
    storage
        .commit_transaction()
        .expect("the browser storage transaction commits atomically");
    request
        .encode_test_worker_response(&read_results)
        .expect("the browser response binds every exact requested read")
}

fn drive_generation_worker_to_complete(
    registry: &mut CommonProofRuntimeRegistry,
    operation: CommonProofGenerationOperationHandle,
    browser_storage: &mut BoundedInMemoryExternalMemory,
) -> (Vec<u8>, usize) {
    let mut output_chunks = BTreeMap::<usize, Vec<u8>>::new();
    let mut resume_complete_count = 0_usize;
    loop {
        match registry
            .poll_owned_generation(operation)
            .expect("the generation worker advances through bounded operations")
        {
            CommonProofGenerationWorkerPoll::Progress {
                checkpoint_ready, ..
            } => {
                if checkpoint_ready {
                    registry
                        .discard_generation_checkpoint(operation)
                        .expect("an unpersisted later checkpoint is explicitly discarded");
                }
            }
            CommonProofGenerationWorkerPoll::ResumeComplete { .. } => {
                resume_complete_count += 1;
            }
            CommonProofGenerationWorkerPoll::StorageRequestReady { .. } => {
                let response = {
                    let request = registry
                        .generation_storage_transaction_request(operation)
                        .expect("one exact generation storage request is pending");
                    execute_generation_storage_request(request, browser_storage)
                };
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the exact storage response replays the Rust transaction");
            }
            CommonProofGenerationWorkerPoll::OutputChunkReady {
                chunk_index,
                chunk_byte_length,
            } => {
                let (pending_index, bytes) = registry
                    .generation_output_chunk(operation)
                    .expect("one canonical generation output chunk is pending");
                assert_eq!(pending_index, chunk_index as usize);
                assert_eq!(bytes.len(), chunk_byte_length as usize);
                assert!(
                    output_chunks
                        .insert(pending_index, bytes.to_vec())
                        .is_none(),
                    "one output chunk cannot be committed twice",
                );
                registry
                    .acknowledge_generation_output_chunk(operation)
                    .expect("the exact output commit is acknowledged");
            }
            CommonProofGenerationWorkerPoll::OutputReadbackRequired { chunk_index } => {
                let readback_bytes = output_chunks
                    .get(&(chunk_index as usize))
                    .expect("the exact committed output chunk is available");
                registry
                    .confirm_generation_output_readback(
                        operation,
                        chunk_index as usize,
                        readback_bytes,
                    )
                    .expect("the exact output reread advances the descriptor");
            }
            CommonProofGenerationWorkerPoll::Complete => break,
            CommonProofGenerationWorkerPoll::Cancelled => {
                panic!("an active genuine generation cannot cancel")
            }
        }
    }
    (
        output_chunks.into_values().flatten().collect(),
        resume_complete_count,
    )
}

fn capture_first_generation_checkpoint() -> (Vec<u8>, Vec<Vec<u8>>, [u8; 64], Vec<u8>) {
    let (prepared, expected_proof_bytes) = prepared_generation_worker_fixture();
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .begin_owned_generation(prepared)
        .expect("the fresh generation attempt starts");
    let mut browser_storage =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    loop {
        match registry
            .poll_owned_generation(operation)
            .expect("the fresh attempt advances to its first safe checkpoint")
        {
            CommonProofGenerationWorkerPoll::Progress {
                checkpoint_ready: true,
                ..
            } => {
                let checkpoint_state = registry
                    .generation_checkpoint_state(operation)
                    .expect("the pending checkpoint owns fixed canonical state")
                    .to_vec();
                let cursor_count = registry
                    .generation_checkpoint_cursor_count(operation)
                    .expect("the checkpoint describes its ordered cursor count");
                let ordered_cursor_bytes = (0..cursor_count)
                    .map(|cursor_index| {
                        registry
                            .generation_checkpoint_cursor(operation, cursor_index)
                            .expect("every ordered checkpoint cursor is available")
                            .to_vec()
                    })
                    .collect::<Vec<_>>();
                let stable_attempt_binding_hash = registry
                    .generation_checkpoint_stable_attempt_binding_hash(operation)
                    .expect("the checkpoint exposes its stable attempt binding");
                assert!(
                    registry
                        .generation_checkpoint_safe_boundary_ordinal(operation)
                        .expect("the checkpoint boundary ordinal is available")
                        > 0,
                );
                registry
                    .retire_failed_generation(operation)
                    .expect("a lost checkpoint response permanently retires the old operation");
                return (
                    checkpoint_state,
                    ordered_cursor_bytes,
                    stable_attempt_binding_hash,
                    expected_proof_bytes,
                );
            }
            CommonProofGenerationWorkerPoll::Progress { .. } => {}
            CommonProofGenerationWorkerPoll::StorageRequestReady { .. } => {
                let response = {
                    let request = registry
                        .generation_storage_transaction_request(operation)
                        .expect("the prefix storage request is exact");
                    execute_generation_storage_request(request, &mut browser_storage)
                };
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the prefix transaction response replays exactly");
            }
            unexpected => panic!("generation reached {unexpected:?} before its first checkpoint"),
        }
    }
}

#[test]
fn owned_generation_worker_replays_storage_and_authenticates_every_output_chunk() {
    let (prepared, expected_proof_bytes) = prepared_generation_worker_fixture();
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .begin_owned_generation(prepared)
        .expect("the opaque genuine generation source starts");
    let mut browser_storage =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let mut output_chunks = BTreeMap::<usize, Vec<u8>>::new();
    let mut observed_checkpoint_boundary = false;

    loop {
        match registry
            .poll_owned_generation(operation)
            .expect("the bounded generation worker advances")
        {
            CommonProofGenerationWorkerPoll::Progress {
                checkpoint_ready, ..
            } => {
                observed_checkpoint_boundary |= checkpoint_ready;
                if checkpoint_ready {
                    registry
                        .discard_generation_checkpoint(operation)
                        .expect("the unpersisted test checkpoint is explicitly discarded");
                }
            }
            CommonProofGenerationWorkerPoll::ResumeComplete { .. } => {
                panic!("an uninterrupted generation cannot report checkpoint replay")
            }
            CommonProofGenerationWorkerPoll::StorageRequestReady { .. } => {
                let response = {
                    let request = registry
                        .generation_storage_transaction_request(operation)
                        .expect("one exact storage request is pending");
                    execute_generation_storage_request(request, &mut browser_storage)
                };
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the exact response changes recording into replay");
            }
            CommonProofGenerationWorkerPoll::OutputChunkReady {
                chunk_index,
                chunk_byte_length,
            } => {
                let (pending_index, bytes) = registry
                    .generation_output_chunk(operation)
                    .expect("one canonical output chunk is pending");
                assert_eq!(pending_index, chunk_index as usize);
                assert_eq!(bytes.len(), chunk_byte_length as usize);
                assert!(
                    output_chunks
                        .insert(pending_index, bytes.to_vec())
                        .is_none(),
                    "a canonical output chunk is committed once",
                );
                registry
                    .acknowledge_generation_output_chunk(operation)
                    .expect("the exact pending chunk commit is acknowledged");
            }
            CommonProofGenerationWorkerPoll::OutputReadbackRequired { chunk_index } => {
                let bytes = output_chunks
                    .get(&(chunk_index as usize))
                    .expect("the committed chunk is available for exact reread");
                registry
                    .confirm_generation_output_readback(operation, chunk_index as usize, bytes)
                    .expect("the exact reread advances the canonical descriptor");
            }
            CommonProofGenerationWorkerPoll::Complete => break,
            CommonProofGenerationWorkerPoll::Cancelled => {
                panic!("an uninterrupted genuine generation cannot cancel")
            }
        }
    }

    let generated_proof_bytes = output_chunks.into_values().flatten().collect::<Vec<_>>();
    assert_eq!(generated_proof_bytes, expected_proof_bytes);
    assert!(observed_checkpoint_boundary);
    let generated_capability = registry
        .finish_owned_generation(operation)
        .expect("only the cryptographic terminal state mints generation authority");
    registry
        .release_generated_proof(generated_capability)
        .expect("the opaque generated capability is linear");
}

#[test]
fn owned_generation_worker_replays_from_zero_and_produces_byte_identical_output() {
    let (
        authenticated_checkpoint_state,
        _ordered_cursor_bytes,
        stable_attempt_binding_hash,
        expected_proof_bytes,
    ) = capture_first_generation_checkpoint();
    assert_ne!(stable_attempt_binding_hash, [0_u8; 64]);
    let (prepared, independently_generated_proof_bytes) =
        prepared_generation_worker_fixture_for_checkpoint(Some(&authenticated_checkpoint_state), 0)
            .expect("authenticated checkpoint coordinates prepare the same exact attempt");
    assert_eq!(independently_generated_proof_bytes, expected_proof_bytes);
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .resume_owned_generation(prepared, &authenticated_checkpoint_state)
        .expect("the authenticated checkpoint starts deterministic prefix replay");
    let mut replay_storage =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let (resumed_proof_bytes, resume_complete_count) =
        drive_generation_worker_to_complete(&mut registry, operation, &mut replay_storage);

    assert_eq!(resume_complete_count, 1);
    assert_eq!(resumed_proof_bytes, expected_proof_bytes);
    let generated_capability = registry
        .finish_owned_generation(operation)
        .expect("only the byte-identical terminal proof mints generation authority");
    registry
        .release_generated_proof(generated_capability)
        .expect("the resumed generated capability remains linear");
}

#[test]
fn owned_generation_worker_rejects_changed_checkpoint_bindings_and_replayed_state() {
    let (authenticated_checkpoint_state, _, _, _) = capture_first_generation_checkpoint();

    for changed_offset in [12_usize, 108] {
        let (prepared, _) = prepared_generation_worker_fixture_for_checkpoint(
            Some(&authenticated_checkpoint_state),
            0,
        )
        .expect("the genuine checkpoint prepares the expected attempt binding");
        let mut changed_state = authenticated_checkpoint_state.clone();
        changed_state[changed_offset] ^= 1;
        let error = CommonProofRuntimeRegistry::default()
            .resume_owned_generation(prepared, &changed_state)
            .expect_err("changed attempt or schedule binding cannot open replay");
        assert!(matches!(
            error,
            CommonProofGenerationWorkerError::Runtime(
                CommonProofRuntimeError::WrongVerificationBinding
            )
        ));
    }

    let (prepared, _) =
        prepared_generation_worker_fixture_for_checkpoint(Some(&authenticated_checkpoint_state), 0)
            .expect("the genuine checkpoint prepares the expected replay target");
    let missing_state_error = CommonProofRuntimeRegistry::default()
        .resume_owned_generation(prepared, &[])
        .expect_err("missing checkpoint state permanently prevents replay");
    assert!(matches!(
        missing_state_error,
        CommonProofGenerationWorkerError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding
        )
    ));

    let mut changed_committed_state = authenticated_checkpoint_state.clone();
    changed_committed_state[264] ^= 1;
    for (bound_checkpoint_state, replay_target, cursor_counter_delta) in [
        (
            authenticated_checkpoint_state.clone(),
            changed_committed_state,
            0_u64,
        ),
        (
            authenticated_checkpoint_state.clone(),
            authenticated_checkpoint_state.clone(),
            1_u64,
        ),
    ] {
        let (prepared, _) = prepared_generation_worker_fixture_for_checkpoint(
            Some(&bound_checkpoint_state),
            cursor_counter_delta,
        )
        .expect("the authenticated checkpoint prepares a replay attempt");
        let mut registry = CommonProofRuntimeRegistry::default();
        let operation = registry
            .resume_owned_generation(prepared, &replay_target)
            .expect("hostile committed-state or cursor input reaches deterministic replay");
        let mut replay_storage =
            BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
        loop {
            let poll = registry.poll_owned_generation(operation);
            match poll {
                Err(CommonProofGenerationWorkerError::Runtime(
                    CommonProofRuntimeError::WrongVerificationBinding,
                )) => break,
                Err(error) => panic!("replay failed with the wrong refusal: {error:?}"),
                Ok(CommonProofGenerationWorkerPoll::Progress {
                    checkpoint_ready: false,
                    ..
                }) => {}
                Ok(CommonProofGenerationWorkerPoll::StorageRequestReady { .. }) => {
                    let response = {
                        let request = registry
                            .generation_storage_transaction_request(operation)
                            .expect("hostile replay still issues exact deterministic requests");
                        execute_generation_storage_request(request, &mut replay_storage)
                    };
                    registry
                        .supply_generation_storage_response(operation, &response)
                        .expect("the exact replay response is accepted before target comparison");
                }
                Ok(unexpected) => {
                    panic!("hostile replay reached {unexpected:?} instead of refusing")
                }
            }
        }
        registry
            .retire_failed_generation(operation)
            .expect("the mismatched replay operation is permanently retired");
    }
}

#[test]
fn owned_generation_worker_replays_an_in_flight_transaction_before_cancellation_cleanup() {
    let (prepared, _) = prepared_generation_worker_fixture();
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .begin_owned_generation(prepared)
        .expect("the opaque genuine generation source starts");
    let mut browser_storage =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);

    loop {
        match registry
            .poll_owned_generation(operation)
            .expect("generation reaches one bounded storage request")
        {
            CommonProofGenerationWorkerPoll::Progress {
                checkpoint_ready, ..
            } => {
                if checkpoint_ready {
                    registry.discard_generation_checkpoint(operation).expect(
                        "an unpersisted checkpoint is explicitly discarded before cancellation",
                    );
                }
            }
            CommonProofGenerationWorkerPoll::StorageRequestReady { .. } => break,
            unexpected => {
                panic!("generation yielded {unexpected:?} before its first storage request")
            }
        }
    }
    registry
        .request_generation_cancellation(operation)
        .expect("the live generation operation accepts cancellation");
    registry
        .request_generation_cancellation(operation)
        .expect("a repeated cancellation request is idempotent");
    assert!(matches!(
        registry
            .poll_owned_generation(operation)
            .expect("cancellation preserves the exact in-flight request"),
        CommonProofGenerationWorkerPoll::StorageRequestReady { .. }
    ));
    let response = {
        let request = registry
            .generation_storage_transaction_request(operation)
            .expect("the original generation transaction remains pending");
        execute_generation_storage_request(request, &mut browser_storage)
    };
    registry
        .supply_generation_storage_response(operation, &response)
        .expect("the exact original response enables deterministic replay");

    loop {
        match registry
            .poll_owned_generation(operation)
            .expect("cancellation replays generation before cleanup")
        {
            CommonProofGenerationWorkerPoll::StorageRequestReady { .. } => {
                registry
                    .request_generation_cancellation(operation)
                    .expect("cancellation remains idempotent during cleanup");
                let response = {
                    let request = registry
                        .generation_storage_transaction_request(operation)
                        .expect("one exact cleanup transaction is pending");
                    execute_generation_storage_request(request, &mut browser_storage)
                };
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the exact cleanup response enables replay");
            }
            CommonProofGenerationWorkerPoll::Cancelled => break,
            unexpected => panic!("cancellation yielded an unexpected state: {unexpected:?}"),
        }
    }

    assert!(
        browser_storage.committed.is_empty(),
        "cancellation removes every committed scratch object",
    );
    registry
        .release_cancelled_generation(operation)
        .expect("the cancelled operation is released once");
    assert_eq!(
        registry.release_cancelled_generation(operation),
        Err(CommonProofRuntimeError::UnknownOrStaleHandle),
    );
}

#[test]
fn failed_owned_generation_retirement_is_linear() {
    let (prepared, _) = prepared_generation_worker_fixture();
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .begin_owned_generation(prepared)
        .expect("the opaque generation source starts");

    registry
        .retire_failed_generation(operation)
        .expect("one failed attempt permanently retires its local authority");
    assert_eq!(
        registry.retire_failed_generation(operation),
        Err(CommonProofRuntimeError::UnknownOrStaleHandle),
        "failed-attempt retirement cannot be replayed",
    );
}

#[test]
fn generation_state_enforces_reports_and_releases_its_complete_resident_live_set() {
    let fixture = common_proof_engine_fixture();
    let mut state = CommonProofGenerationStateMachine::new(CommonProofGenerationInput {
        protocol_version: 1,
        suite_identifier: [0x11; 64],
        canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
        relation_plan: &fixture.relation_plan,
        relation_context: &fixture.relation_context,
        schedule_position: fixture.schedule_position,
        top_count: fixture.top_count,
        relation_trees: fixture.relation_trees.clone(),
        provided_pre_challenge_columns: fixture.provided_columns.clone(),
        maximum_external_memory_chunk_byte_length:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        maximum_prefetched_query_byte_length: MAXIMUM_PROOF_BYTE_LENGTH as u64,
    })
    .expect("the compact fixture fits the browser resident-memory ceiling");
    let resident_memory_plan = state.resident_memory_plan();
    assert_eq!(resident_memory_plan.phases().len(), 10);
    assert_eq!(
        resident_memory_plan.peak_byte_length(),
        resident_memory_plan
            .phases()
            .iter()
            .map(|phase| phase.total_byte_length())
            .max()
            .expect("the liveness plan has phases")
    );
    assert!(
        resident_memory_plan.peak_byte_length() <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    );

    let preparing_inputs = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::PreparingInputs)
        .expect("the source-column and integer-lift phase is explicit");
    assert!(preparing_inputs.relation_column_catalog_byte_length() > 0);
    assert!(preparing_inputs.trace_row_cache_byte_length() > 0);
    assert!(preparing_inputs.trace_synthesis_scratch_byte_length() > 0);

    let constructing_quotient = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::ConstructingQuotient)
        .expect("the quotient replay phase is explicit");
    assert!(constructing_quotient.replay_source_byte_length() > 0);
    assert!(constructing_quotient.primary_vector_byte_length() > 0);
    assert!(constructing_quotient.secondary_vector_byte_length() > 0);
    assert!(constructing_quotient.relation_rotation_block_byte_length() > 0);

    let persisting_relation_columns = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::PersistingRelationColumns)
        .expect("the external relation-column persistence phase is explicit");
    let external_memory_chunk_byte_length =
        u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
    let extension_value_byte_length = u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
        .expect("the extension degree fits u64")
        .checked_mul(
            u64::try_from(core::mem::size_of::<u64>()).expect("the limb byte length fits u64"),
        )
        .expect("the extension value byte length fits u64");
    let aligned_extension_scan_byte_length = external_memory_chunk_byte_length
        .checked_div(extension_value_byte_length)
        .expect("the extension value byte length is nonzero")
        .checked_mul(extension_value_byte_length)
        .expect("the aligned scan byte length fits u64");
    let stockham_working_set_byte_length = aligned_extension_scan_byte_length
        .checked_mul(3)
        .and_then(|byte_length| byte_length.checked_add(external_memory_chunk_byte_length))
        .expect("the Stockham working set byte length fits u64");
    let replay_writer_working_set_byte_length = external_memory_chunk_byte_length
        .checked_add(extension_value_byte_length)
        .expect("the replay writer working set byte length fits u64");
    assert!(
        persisting_relation_columns.external_working_set_byte_length()
            >= stockham_working_set_byte_length.max(replay_writer_working_set_byte_length),
        "the relation persistence live set includes its transform and replay-writer buffers",
    );

    let maximum_external_working_set_byte_length = resident_memory_plan
        .phases()
        .iter()
        .map(|phase| phase.external_working_set_byte_length())
        .max()
        .expect("the resident plan has materialization phases");
    assert!(
        maximum_external_working_set_byte_length
            >= 2 * u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
        "canonical external-memory working buffers are included in the live set",
    );

    let emitting_queries = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::EmittingQueries)
        .expect("the query extraction phase is explicit");
    assert_eq!(
        emitting_queries.query_prefetch_byte_length(),
        MAXIMUM_PROOF_BYTE_LENGTH as u64
    );
    assert_eq!(
        emitting_queries.stream_window_byte_length(),
        MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH as u64
    );
    assert!(emitting_queries.claim_and_query_metadata_byte_length() > 0);

    let mut external_memory =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    state
        .cancel(&mut external_memory)
        .expect("cancellation aborts the storage executor");
    assert!(state.resident_payload_is_empty());
}

#[test]
fn generation_state_rejects_an_unattainable_resident_live_set_before_proving() {
    let fixture = common_proof_engine_fixture();
    let result = CommonProofGenerationStateMachine::new(CommonProofGenerationInput {
        protocol_version: 1,
        suite_identifier: [0x11; 64],
        canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
        relation_plan: &fixture.relation_plan,
        relation_context: &fixture.relation_context,
        schedule_position: fixture.schedule_position,
        top_count: fixture.top_count,
        relation_trees: fixture.relation_trees,
        provided_pre_challenge_columns: fixture.provided_columns,
        maximum_external_memory_chunk_byte_length:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        maximum_prefetched_query_byte_length: MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    });
    assert!(matches!(
        result,
        Err(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::ResidentMemoryLimitExceeded
        ))
    ));
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

fn verified_fixture_proof_stream(proof_bytes: &[u8]) -> VerifiedCanonicalStreamSummary {
    let stream_domain = CanonicalStreamDomain::CollectivePublicKeyAggregateProof;
    let descriptor = derive_canonical_stream_descriptor(stream_domain, proof_bytes)
        .expect("the complete fixture proof derives a canonical descriptor");
    let mut verifier = CanonicalStreamVerifier::new(stream_domain, descriptor)
        .expect("the fixture descriptor starts a stream verifier");
    for (chunk_index, chunk) in proof_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        assert!(
            verifier.absorb_chunk(chunk_index, chunk).is_valid(),
            "every fixture chunk must match the derived descriptor",
        );
    }
    verifier
        .finish_with_summary()
        .into_result()
        .expect("the complete fixture stream mints its terminal summary")
}

fn authenticated_storage_head_source(
    namespace_sequence: u64,
    authenticated_head_digest: [u8; 64],
    storage_instance_identity: [u8; 64],
) -> BrowserWorkerAuthenticatedStorageHeadSource {
    authenticated_storage_head_source_with_binding(
        LocalStorageBinding::new(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x32; 64]),
            Hash512::from_bytes([0x31; 64]),
            ParticipantIdentity::from_bytes([0x91; 64]),
        ),
        [0x92; 64],
        namespace_sequence,
        authenticated_head_digest,
        storage_instance_identity,
    )
}

fn authenticated_storage_head_source_with_binding(
    local_storage_binding: LocalStorageBinding,
    storage_root_commitment: [u8; 64],
    namespace_sequence: u64,
    authenticated_head_digest: [u8; 64],
    storage_instance_identity: [u8; 64],
) -> BrowserWorkerAuthenticatedStorageHeadSource {
    BrowserWorkerAuthenticatedStorageHeadSource::from_test_fixture(
        local_storage_binding,
        Hash512::from_bytes(storage_root_commitment),
        namespace_sequence,
        Hash512::from_bytes(authenticated_head_digest),
        Hash512::from_bytes(storage_instance_identity),
    )
}

#[allow(clippy::too_many_arguments)]
fn authenticated_storage_transition_source(
    local_storage_binding: LocalStorageBinding,
    storage_root_commitment: [u8; 64],
    predecessor_namespace_sequence: u64,
    predecessor_authenticated_head_digest: [u8; 64],
    successor_namespace_sequence: u64,
    successor_authenticated_head_digest: [u8; 64],
    storage_instance_identity: [u8; 64],
    authenticated_record_digest: [u8; 64],
) -> BrowserWorkerAuthenticatedStorageTransitionSource {
    BrowserWorkerAuthenticatedStorageTransitionSource::from_test_fixture(
        local_storage_binding,
        Hash512::from_bytes(storage_root_commitment),
        predecessor_namespace_sequence,
        Hash512::from_bytes(predecessor_authenticated_head_digest),
        successor_namespace_sequence,
        Hash512::from_bytes(successor_authenticated_head_digest),
        Hash512::from_bytes(storage_instance_identity),
        Hash512::from_bytes(authenticated_record_digest),
    )
}

#[test]
fn runtime_registry_accepts_only_terminal_verifier_tokens_and_retires_stale_handles() {
    let mut fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let proof_bytes = generate_fixture_proof(&mut fixture);
    let verified_proof =
        verify_fixture_proof_incrementally(&fixture, &proof_bytes, &verified_trees)
            .expect("the terminal verifier poll mints its opaque token");
    let verified_stream = verified_fixture_proof_stream(&proof_bytes);
    let expected_application_statement_hash = verified_proof.application_statement_hash();
    let expected_proof_header_hash = verified_proof.proof_header_hash();
    let expected_proof_stream_full_object_digest =
        verified_stream.full_object_digest().into_bytes();
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &fixture.relation_plan,
        &fixture.relation_context,
        fixture.schedule_position,
        fixture.top_count,
    )
    .expect("the checked relation plan mints a runtime capability");
    let proof_application = CommonProofApplicationBinding::new(
        [0x41; 64],
        [0x42; 64],
        verified_proof.application_statement_schema_identifier(),
        verified_proof.proof_header_hash(),
        verified_stream.stream_domain(),
        verified_stream.full_object_digest().into_bytes(),
        verified_proof.proof_byte_length(),
        verified_proof.verified_query_count(),
    )
    .expect("the verified proof fits the exact application reservation");
    let binding = CommonProofVerificationBinding::new(
        [0x11; 64],
        [0x32; 64],
        [0x31; 64],
        [0x33; 64],
        proof_application,
        relation_plan_capability.relation_plan_hash(),
    );
    let runtime_limits = CommonProofRuntimeLimits::new(
        proof_bytes.len(),
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        proof_bytes.len() as u64,
    )
    .expect("the generated proof fits the worker limits");
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation_handle = registry
        .begin_verification(binding, &relation_plan_capability, runtime_limits)
        .expect("the bound verification operation starts");
    let mut substituted_stream_bytes = proof_bytes.clone();
    let final_byte = substituted_stream_bytes
        .last_mut()
        .expect("the complete proof is nonempty");
    *final_byte ^= 1;
    let substituted_verified_stream = verified_fixture_proof_stream(&substituted_stream_bytes);
    assert_eq!(
        registry
            .register_verified_proof(
                operation_handle,
                &relation_plan_capability,
                verified_proof,
                substituted_verified_stream,
            )
            .err(),
        Some(CommonProofRuntimeError::WrongVerificationBinding),
        "a terminal stream summary for different bytes cannot mint authority",
    );
    let verified_proof =
        verify_fixture_proof_incrementally(&fixture, &proof_bytes, &verified_trees)
            .expect("stream-binding refusal leaves the verification operation retryable");
    let capability_handle = registry
        .register_verified_proof(
            operation_handle,
            &relation_plan_capability,
            verified_proof,
            verified_stream,
        )
        .expect("only the terminal verifier token enters the capability registry");
    assert_eq!(
        registry.request_cancellation(operation_handle),
        Err(CommonProofRuntimeError::UnknownOrStaleHandle),
        "terminal registration permanently retires the operation handle",
    );
    let predecessor_source = authenticated_storage_head_source(14, [0xa5; 64], [0xb6; 64]);
    let wrong_context_predecessor_source = authenticated_storage_head_source_with_binding(
        LocalStorageBinding::new(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x33; 64]),
            Hash512::from_bytes([0x31; 64]),
            ParticipantIdentity::from_bytes([0x91; 64]),
        ),
        [0x92; 64],
        14,
        [0xa5; 64],
        [0xb6; 64],
    );
    assert_eq!(
        registry.retain_authenticated_ledger_head(
            &capability_handle,
            &wrong_context_predecessor_source,
        ),
        Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch),
        "a browser head for another ceremony cannot bind terminal proof authority",
    );
    let prepared = registry
        .prepare_verified_proof_application_from_authenticated_head(
            &capability_handle,
            &predecessor_source,
        )
        .expect("the terminal verifier capability enters retained pending state");
    assert_eq!(prepared.proof_application_slot_hash(), [0x41; 64]);
    assert_eq!(
        prepared.application_statement_schema_identifier(),
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
    );
    assert_eq!(
        (
            prepared.proof_byte_length(),
            prepared.verified_query_count()
        ),
        (proof_bytes.len() as u64, PROOF_UNIQUE_QUERY_COUNT),
    );
    let durable_frame = prepared.durable_authorization_frame();
    let durable_frame_digest = prepared.durable_authorization_frame_digest();
    assert_eq!(
        durable_authorization_frame_digest(durable_frame),
        durable_frame_digest,
        "the transition digest is recomputed from the exact durable frame",
    );
    let mut changed_durable_frame = durable_frame.to_vec();
    let changed_frame_byte_index = changed_durable_frame.len() / 2;
    changed_durable_frame[changed_frame_byte_index] ^= 1;
    assert_ne!(
        durable_authorization_frame_digest(&changed_durable_frame),
        durable_frame_digest,
        "changed durable bytes cannot authenticate the pending transition",
    );
    assert_eq!(&durable_frame[0..8], b"SLCPA001");
    assert_eq!(u16::from_le_bytes([durable_frame[8], durable_frame[9]]), 1);
    assert_eq!(
        u32::from_le_bytes(
            durable_frame[10..14]
                .try_into()
                .expect("frame length bytes")
        ),
        durable_frame.len() as u32,
    );
    assert_eq!(&durable_frame[14..78], &[0x11; 64]);
    assert_eq!(&durable_frame[78..142], &[0x32; 64]);
    assert_eq!(&durable_frame[142..206], &[0x31; 64]);
    assert_eq!(&durable_frame[206..270], &[0x33; 64]);
    assert_eq!(&durable_frame[270..334], &[0x41; 64]);
    assert_eq!(&durable_frame[334..398], &[0x42; 64]);
    assert_eq!(
        &durable_frame[398..462],
        &relation_plan_capability.relation_plan_hash(),
    );
    assert_eq!(
        u16::from_le_bytes(durable_frame[462..464].try_into().unwrap()),
        1
    );
    assert_eq!(
        u16::from_le_bytes(durable_frame[464..466].try_into().unwrap()),
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
    );
    assert_eq!(
        &durable_frame[466..530],
        &expected_application_statement_hash
    );
    assert_eq!(&durable_frame[530..594], &expected_proof_header_hash);
    assert_eq!(
        u32::from_le_bytes(durable_frame[594..598].try_into().unwrap()),
        CanonicalStreamDomain::CollectivePublicKeyAggregateProof.canonical_code(),
    );
    assert_eq!(
        &durable_frame[598..662],
        &expected_proof_stream_full_object_digest,
    );
    assert_eq!(
        u64::from_le_bytes(durable_frame[662..670].try_into().unwrap()),
        proof_bytes.len() as u64,
    );
    assert_eq!(
        u32::from_le_bytes(durable_frame[670..674].try_into().unwrap()),
        PROOF_UNIQUE_QUERY_COUNT,
    );
    assert_eq!(
        &durable_frame[674..738],
        &relation_plan_capability.relation_plan_variant_hash(),
    );
    assert_eq!(durable_frame[738], 0);
    assert_eq!(
        u32::from_le_bytes(durable_frame[739..743].try_into().unwrap()),
        0,
    );
    assert_eq!(durable_frame[743], 0);
    assert_eq!(
        u16::from_le_bytes(durable_frame[744..746].try_into().unwrap()),
        0,
    );
    let first_pending_handle_identifier = prepared.pending_handle().get();
    let wrong_instance_source = authenticated_storage_transition_source(
        predecessor_source.local_storage_binding(),
        [0x92; 64],
        14,
        [0xa5; 64],
        15,
        [0xc7; 64],
        [0xd8; 64],
        durable_frame_digest,
    );
    assert_eq!(
        registry.retain_authenticated_ledger_transition(
            prepared.pending_handle(),
            &wrong_instance_source,
        ),
        Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch),
        "a successor from another storage instance cannot consume the pending capability",
    );
    let wrong_storage_root_source = authenticated_storage_transition_source(
        predecessor_source.local_storage_binding(),
        [0x93; 64],
        14,
        [0xa5; 64],
        15,
        [0xc7; 64],
        [0xb6; 64],
        durable_frame_digest,
    );
    assert_eq!(
        registry.retain_authenticated_ledger_transition(
            prepared.pending_handle(),
            &wrong_storage_root_source,
        ),
        Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch),
        "a successor under another storage root cannot consume pending authority",
    );
    let unchanged_head_source = authenticated_storage_transition_source(
        predecessor_source.local_storage_binding(),
        [0x92; 64],
        14,
        [0xa5; 64],
        14,
        [0xa5; 64],
        [0xb6; 64],
        durable_frame_digest,
    );
    assert_eq!(
        registry.retain_authenticated_ledger_transition(
            prepared.pending_handle(),
            &unchanged_head_source,
        ),
        Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch),
        "an unchanged predecessor cannot masquerade as durable confirmation",
    );
    let forged_record_source = authenticated_storage_transition_source(
        predecessor_source.local_storage_binding(),
        [0x92; 64],
        14,
        [0xa5; 64],
        15,
        [0xc7; 64],
        [0xb6; 64],
        [0xee; 64],
    );
    assert_eq!(
        registry.retain_authenticated_ledger_transition(
            prepared.pending_handle(),
            &forged_record_source,
        ),
        Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch),
        "a transition for different durable record bytes cannot consume proof authority",
    );
    let exact_transition_source = authenticated_storage_transition_source(
        predecessor_source.local_storage_binding(),
        [0x92; 64],
        14,
        [0xa5; 64],
        15,
        [0xc7; 64],
        [0xb6; 64],
        durable_frame_digest,
    );
    let transition_handle = registry
        .retain_authenticated_ledger_transition(prepared.pending_handle(), &exact_transition_source)
        .expect("an exact compare-and-apply readback mints one transition capability");
    assert!(transition_handle.get() > 0);
    assert_eq!(
        registry.retain_authenticated_ledger_transition(
            prepared.pending_handle(),
            &exact_transition_source,
        ),
        Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch),
        "one durable transition cannot mint duplicate authority",
    );
    let restored_capability_handle = registry
        .abort_verified_proof_application(prepared.pending_handle())
        .expect("abort restores the exact terminal verifier capability");
    assert_eq!(
        registry.confirm_verified_proof_application(prepared.pending_handle(), &transition_handle,),
        Err(CommonProofRuntimeError::UnknownOrStaleHandle),
        "abort retires both the pending and transition capabilities",
    );
    let prepared_again = registry
        .prepare_verified_proof_application_from_authenticated_head(
            &restored_capability_handle,
            &predecessor_source,
        )
        .expect("the restored verifier capability can prepare one fresh transition");
    assert_ne!(
        prepared_again.pending_handle().get(),
        first_pending_handle_identifier,
        "aborted pending handles are never reused",
    );
    assert_eq!(
        prepared_again.durable_authorization_frame(),
        durable_frame,
        "retrying the same verified proof yields byte-identical durable facts",
    );
    assert_eq!(
        prepared_again.durable_authorization_frame_digest(),
        durable_frame_digest,
        "retrying the same verified proof yields the identical authenticated record digest",
    );
    assert_eq!(
        registry.confirm_verified_proof_application_from_authenticated_transition(
            prepared_again.pending_handle(),
            &forged_record_source,
        ),
        Err(CommonProofRuntimeError::AuthenticatedStorageHeadMismatch),
        "a changed durable readback leaves the pending authority available",
    );
    registry
        .confirm_verified_proof_application_from_authenticated_transition(
            prepared_again.pending_handle(),
            &exact_transition_source,
        )
        .expect("the exact changed successor and record digest consume proof authority");
    assert_eq!(
        registry.confirm_verified_proof_application_from_authenticated_transition(
            prepared_again.pending_handle(),
            &exact_transition_source,
        ),
        Err(CommonProofRuntimeError::UnknownOrStaleHandle),
        "successful confirmation permanently retires the pending capability",
    );

    let cancelled_proof =
        verify_fixture_proof_incrementally(&fixture, &proof_bytes, &verified_trees)
            .expect("a separate terminal token is available for cancellation coverage");
    let cancelled_verified_stream = verified_fixture_proof_stream(&proof_bytes);
    let cancelled_operation_handle = registry
        .begin_verification(binding, &relation_plan_capability, runtime_limits)
        .expect("the second verification operation starts");
    registry
        .request_cancellation(cancelled_operation_handle)
        .expect("cancellation is recorded");
    assert_eq!(
        registry.register_verified_proof(
            cancelled_operation_handle,
            &relation_plan_capability,
            cancelled_proof,
            cancelled_verified_stream,
        ),
        Err(CommonProofRuntimeError::CancellationRequested),
    );
    registry
        .cancel_operation(cancelled_operation_handle)
        .expect("the cancelled operation is explicitly retired");
}

#[test]
fn upstream_input_registry_consumes_only_one_complete_application_owned_capability_set() {
    let fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let runtime_limits = CommonProofRuntimeLimits::new(
        super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
    )
    .expect("the fixed worker limits are valid");
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &fixture.relation_plan,
        &fixture.relation_context,
        fixture.schedule_position,
        fixture.top_count,
    )
    .expect("the checked relation plan mints an application capability");
    let expected_relation_plan_hash = relation_plan_capability.relation_plan_hash();
    let proof_application = CommonProofApplicationBinding::new(
        [0x41; 64],
        [0x42; 64],
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        [0x43; 64],
        CanonicalStreamDomain::CollectivePublicKeyAggregateProof,
        [0x44; 64],
        super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        PROOF_UNIQUE_QUERY_COUNT,
    )
    .expect("the application reservation fits the worker ceiling");
    let binding = CommonProofVerificationBinding::new(
        [0x11; 64],
        [0x32; 64],
        [0x31; 64],
        [0x33; 64],
        proof_application,
        expected_relation_plan_hash,
    );
    let proof_stream_descriptor = StreamDescriptor {
        total_byte_length: super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        ordered_chunk_digests: vec![Hash512::from_bytes([0x45; 64]); 5],
        full_object_digest: Hash512::from_bytes([0x44; 64]),
    };
    let mut registry = CommonProofUpstreamInputRegistry::default();
    let application_handle = registry
        .install_test_application_fixture(
            binding,
            relation_plan_capability,
            1,
            &fixture.canonical_application_statement_bytes,
            proof_stream_descriptor.clone(),
            runtime_limits,
        )
        .expect("the positively constructed fixture application is retained");
    let statement_tree_handles = verified_trees
        .iter()
        .cloned()
        .map(|tree| {
            registry
                .mint_statement_tree(&application_handle, tree)
                .expect("the verified tree is retained for the exact application")
        })
        .collect::<Vec<_>>();
    let mut duplicate_statement_tree_handles = statement_tree_handles.iter().collect::<Vec<_>>();
    duplicate_statement_tree_handles[1] = duplicate_statement_tree_handles[0];
    assert_eq!(
        registry
            .consume_verification_inputs(
                &application_handle,
                &duplicate_statement_tree_handles,
                &[],
                None,
            )
            .err(),
        Some(CommonProofRuntimeError::WrongVerificationBinding),
        "a duplicate handle cannot stand in for a missing verified tree",
    );

    let incomplete_statement_tree_handles = statement_tree_handles[..2].iter().collect::<Vec<_>>();
    assert_eq!(
        registry
            .consume_verification_inputs(
                &application_handle,
                &incomplete_statement_tree_handles,
                &[],
                None,
            )
            .err(),
        Some(CommonProofRuntimeError::WrongVerificationBinding),
        "an incomplete tree set fails before consuming any capability",
    );

    let second_relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &fixture.relation_plan,
        &fixture.relation_context,
        fixture.schedule_position,
        fixture.top_count,
    )
    .expect("the same checked plan can back an independent application");
    let second_application_handle = registry
        .install_test_application_fixture(
            binding,
            second_relation_plan_capability,
            1,
            &fixture.canonical_application_statement_bytes,
            proof_stream_descriptor,
            runtime_limits,
        )
        .expect("the independent application is retained");
    let cross_application_tree_handle = registry
        .mint_statement_tree(&second_application_handle, verified_trees[0].clone())
        .expect("the second application's verified tree is retained");
    let mut cross_application_tree_handles = statement_tree_handles.iter().collect::<Vec<_>>();
    cross_application_tree_handles[0] = &cross_application_tree_handle;
    assert_eq!(
        registry
            .consume_verification_inputs(
                &application_handle,
                &cross_application_tree_handles,
                &[],
                None,
            )
            .err(),
        Some(CommonProofRuntimeError::WrongVerificationBinding),
        "a verified tree cannot cross application ownership boundaries",
    );

    let complete_statement_tree_handles = statement_tree_handles.iter().collect::<Vec<_>>();
    let consumed = registry
        .consume_verification_inputs(
            &application_handle,
            &complete_statement_tree_handles,
            &[],
            None,
        )
        .expect("the exact complete capability set initializes and transfers once");
    assert_eq!(consumed.verification_binding(), binding);
    assert_eq!(
        consumed.relation_plan().relation_plan_hash(),
        expected_relation_plan_hash,
    );
    let verification_input = consumed.pollable_verification_input();
    assert_eq!(
        verification_input.statement_owned_trees.len(),
        verified_trees.len(),
    );
    assert_eq!(
        verification_input.canonical_application_statement_bytes,
        fixture.canonical_application_statement_bytes,
    );
    assert_eq!(
        registry
            .consume_verification_inputs(
                &application_handle,
                &complete_statement_tree_handles,
                &[],
                None,
            )
            .err(),
        Some(CommonProofRuntimeError::UnknownOrStaleHandle),
        "the application handle is permanently stale after transfer",
    );
    registry
        .cancel_application(&second_application_handle)
        .expect("cancellation retires the second application and all attached inputs");
    assert_eq!(
        registry
            .consume_verification_inputs(
                &second_application_handle,
                &[&cross_application_tree_handle],
                &[],
                None,
            )
            .err(),
        Some(CommonProofRuntimeError::UnknownOrStaleHandle),
    );
}

#[test]
fn owned_verification_worker_authenticates_external_readback_before_minting_authority() {
    let mut fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let proof_bytes = generate_fixture_proof(&mut fixture);
    let stream_domain = CanonicalStreamDomain::CollectivePublicKeyAggregateProof;
    let proof_stream_descriptor = derive_canonical_stream_descriptor(stream_domain, &proof_bytes)
        .expect("the generated proof has a canonical stream descriptor");
    let expected_proof_stream_full_object_digest =
        proof_stream_descriptor.full_object_digest.into_bytes();
    let runtime_limits = CommonProofRuntimeLimits::new(
        proof_bytes.len(),
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        proof_bytes
            .len()
            .min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH) as u64,
    )
    .expect("the generated proof fits the worker profile");
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &fixture.relation_plan,
        &fixture.relation_context,
        fixture.schedule_position,
        fixture.top_count,
    )
    .expect("the checked relation plan mints an application capability");
    let expected_relation_plan_hash = relation_plan_capability.relation_plan_hash();
    let expected_relation_plan_variant_hash = relation_plan_capability.relation_plan_variant_hash();
    let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
        fixture.canonical_application_statement_bytes.clone(),
        &crate::foundation::CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.proof_header_hash())
    .expect("the proof header is canonical")
    .into_bytes();
    let proof_application = CommonProofApplicationBinding::new(
        [0x41; 64],
        [0x42; 64],
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        proof_header_hash,
        stream_domain,
        proof_stream_descriptor.full_object_digest.into_bytes(),
        proof_bytes.len() as u64,
        PROOF_UNIQUE_QUERY_COUNT,
    )
    .expect("the generated proof fits the exact application reservation");
    let binding = CommonProofVerificationBinding::new(
        [0x11; 64],
        [0x32; 64],
        [0x31; 64],
        [0x33; 64],
        proof_application,
        relation_plan_capability.relation_plan_hash(),
    );
    let mut upstream_registry = CommonProofUpstreamInputRegistry::default();
    let application_handle = upstream_registry
        .install_test_application_fixture(
            binding,
            relation_plan_capability,
            1,
            &fixture.canonical_application_statement_bytes,
            proof_stream_descriptor,
            runtime_limits,
        )
        .expect("the exact fixture application is retained");
    let statement_tree_handles = verified_trees
        .into_iter()
        .map(|tree| {
            upstream_registry
                .mint_statement_tree(&application_handle, tree)
                .expect("the verified statement tree is retained")
        })
        .collect::<Vec<_>>();
    let prepared = upstream_registry
        .consume_verification_inputs(
            &application_handle,
            &statement_tree_handles.iter().collect::<Vec<_>>(),
            &[],
            None,
        )
        .expect("the exact capability set is consumed")
        .prepare()
        .expect("the owned verifier initializes");
    let mut runtime_registry = CommonProofRuntimeRegistry::default();
    let operation_handle = runtime_registry
        .begin_owned_verification(prepared)
        .expect("the owned operation begins");
    let chunks = proof_bytes
        .chunks(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
        .collect::<Vec<_>>();
    for (chunk_index, chunk) in chunks.iter().copied().enumerate() {
        runtime_registry
            .absorb_verification_input_chunk(operation_handle, chunk_index, chunk)
            .expect("sequential canonical ingress accepts the exact chunk");
    }
    runtime_registry
        .finish_verification_input(operation_handle)
        .expect("complete canonical ingress mints readback authority");
    loop {
        match runtime_registry
            .poll_owned_verification(operation_handle)
            .expect("the bounded verifier advances")
        {
            CommonProofVerificationWorkerPoll::NeedsReadback {
                first_chunk_index,
                second_chunk_index,
            } => {
                for chunk_index in [Some(first_chunk_index), second_chunk_index]
                    .into_iter()
                    .flatten()
                {
                    runtime_registry
                        .supply_verification_readback_chunk(
                            operation_handle,
                            chunk_index as usize,
                            chunks[chunk_index as usize],
                        )
                        .expect("descriptor-authenticated readback accepts the exact chunk");
                }
            }
            CommonProofVerificationWorkerPoll::PrefixAccepted
            | CommonProofVerificationWorkerPoll::QueryHeaderAccepted
            | CommonProofVerificationWorkerPoll::QueryTreeAccepted { .. } => {}
            CommonProofVerificationWorkerPoll::Complete => break,
        }
    }
    let terminal_capability = runtime_registry
        .finish_owned_verification(operation_handle)
        .expect("only terminal proof and stream tokens mint authority");
    assert!(matches!(
        runtime_registry.poll_owned_verification(operation_handle),
        Err(CommonProofVerificationWorkerError::Runtime(
            CommonProofRuntimeError::UnknownOrStaleHandle
        ))
    ));
    let authenticated_head = runtime_registry
        .retain_authenticated_ledger_head(
            &terminal_capability,
            &authenticated_storage_head_source(7, [0xa5; 64], [0xb6; 64]),
        )
        .expect("the terminal capability can bind one browser-owned predecessor head");
    let consumed = runtime_registry
        .consume_verified_proof_for_protocol(&terminal_capability)
        .expect("an exact family adapter consumes terminal verifier authority once");
    assert_eq!(consumed.protocol_version(), 1);
    assert_eq!(consumed.suite_identifier(), [0x11; 64]);
    assert_eq!(consumed.ceremony_context_hash(), [0x32; 64]);
    assert_eq!(consumed.action_context_hash(), [0x31; 64]);
    assert_eq!(consumed.board_object_hash(), [0x33; 64]);
    assert_ne!(consumed.verification_binding_hash(), [0; 64]);
    assert_eq!(consumed.proof_application_slot_hash(), [0x41; 64]);
    assert_eq!(
        consumed.canonical_proof_application_binding_hash(),
        [0x42; 64]
    );
    assert_eq!(
        consumed.application_statement_schema_identifier(),
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
    );
    assert_eq!(
        consumed.application_statement_hash(),
        verified_application_statement_hash(
            1,
            [0x11; 64],
            APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
            &fixture.canonical_application_statement_bytes,
        ),
    );
    assert_eq!(consumed.proof_header_hash(), proof_header_hash);
    assert_eq!(consumed.proof_stream_domain(), stream_domain);
    assert_eq!(
        consumed.proof_stream_full_object_digest(),
        expected_proof_stream_full_object_digest,
    );
    assert_eq!(consumed.proof_byte_length(), proof_bytes.len() as u64);
    assert_eq!(consumed.verified_query_count(), PROOF_UNIQUE_QUERY_COUNT);
    assert_eq!(consumed.relation_plan_hash(), expected_relation_plan_hash);
    assert_eq!(
        consumed.relation_plan_variant_hash(),
        expected_relation_plan_variant_hash,
    );
    assert_eq!(consumed.schedule_position(), fixture.schedule_position);
    assert_eq!(consumed.top_count(), fixture.top_count);
    assert_eq!(
        runtime_registry
            .consume_verified_proof_for_protocol(&terminal_capability)
            .err(),
        Some(CommonProofRuntimeError::UnknownOrStaleHandle),
        "a consumed terminal verifier handle is permanently stale",
    );
    assert_eq!(
        runtime_registry
            .prepare_verified_proof_application(&terminal_capability, &authenticated_head)
            .err(),
        Some(CommonProofRuntimeError::UnknownOrStaleHandle),
        "family transfer also retires any incompatible ledger-head reservation",
    );
}

#[test]
fn incremental_verifier_retains_only_owned_initialization_material_across_yields() {
    let (verifier, proof_bytes) = {
        let mut fixture = common_proof_engine_fixture();
        let verified_trees = verified_statement_trees(
            &fixture.relation_plan,
            &fixture.setup_polynomial_trees,
            None,
            fixture.schedule_position,
            fixture.top_count,
        );
        let proof_bytes = generate_fixture_proof(&mut fixture);
        let verifier = fixture_incremental_verifier(
            &fixture,
            &verified_trees,
            proof_bytes.len(),
            2 * MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        )
        .expect("the verifier initializes from verified upstream material");
        (verifier, proof_bytes)
    };

    let verified = complete_incremental_verification(verifier, &proof_bytes)
        .expect("verification continues after every borrowed initializer is released");
    assert_eq!(verified.proof_byte_length(), proof_bytes.len() as u64);
    assert_eq!(verified.verified_query_count(), PROOF_UNIQUE_QUERY_COUNT);
}

#[test]
fn incremental_verifier_refuses_missing_reordered_short_trailing_and_cancelled_input() {
    let mut fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let proof_bytes = generate_fixture_proof(&mut fixture);
    let maximum_resident_window_byte_length = 2 * MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH;

    let mut cancelled = fixture_incremental_verifier(
        &fixture,
        &verified_trees,
        proof_bytes.len(),
        maximum_resident_window_byte_length,
    )
    .expect("the verifier initializes");
    let prefix_range = cancelled
        .required_byte_range()
        .expect("the prefix is the first required range");
    let prefix_end = prefix_range.offset() + prefix_range.byte_length();
    let prefix_source = ResidentCommonProofByteSource::new(
        proof_bytes.len(),
        vec![ResidentCommonProofInputChunk::new(
            prefix_range.offset(),
            &proof_bytes[prefix_range.offset()..prefix_end],
        )],
    )
    .expect("the prefix fits one resident chunk");
    assert_eq!(
        cancelled
            .poll(&prefix_source, &mut NoVerifiedSequenceColumns)
            .expect("the exact prefix is accepted"),
        CommonProofVerificationPoll::PrefixAccepted,
    );
    assert!(cancelled.take_verified_common_proof().is_none());
    cancelled.cancel();
    assert_eq!(
        cancelled.poll(proof_bytes.as_slice(), &mut NoVerifiedSequenceColumns),
        Err(CommonProofVerifierError::Cancelled),
    );
    assert!(cancelled.take_verified_common_proof().is_none());

    let mut short = fixture_incremental_verifier(
        &fixture,
        &verified_trees,
        proof_bytes.len(),
        maximum_resident_window_byte_length,
    )
    .expect("the short-window verifier initializes");
    let short_range = short.required_byte_range().expect("the prefix is required");
    let short_end = short_range.offset() + short_range.byte_length() - 1;
    let short_source = ResidentCommonProofByteSource::new(
        proof_bytes.len(),
        vec![ResidentCommonProofInputChunk::new(
            short_range.offset(),
            &proof_bytes[short_range.offset()..short_end],
        )],
    )
    .expect("a short resident window is representable");
    assert_eq!(
        short.poll(&short_source, &mut NoVerifiedSequenceColumns),
        Err(CommonProofVerifierError::Body(ProofBodyError::Decode(
            ProofDecodeError::Truncated,
        ))),
    );
    assert_eq!(
        short.poll(proof_bytes.as_slice(), &mut NoVerifiedSequenceColumns),
        Err(CommonProofVerifierError::Cancelled),
        "a failed poll permanently retires its partially consumed verifier state",
    );

    let split_offset = prefix_range.byte_length() / 2;
    assert_eq!(
        ResidentCommonProofByteSource::new(
            proof_bytes.len(),
            vec![
                ResidentCommonProofInputChunk::new(
                    prefix_range.offset() + split_offset,
                    &proof_bytes[prefix_range.offset() + split_offset..prefix_end],
                ),
                ResidentCommonProofInputChunk::new(
                    prefix_range.offset(),
                    &proof_bytes[prefix_range.offset()..prefix_range.offset() + split_offset],
                ),
            ],
        )
        .map(|_| ()),
        Err(super::super::CommonProofRuntimeError::InvalidLimits),
        "reordered chunks never become a byte source",
    );

    let mut missing = fixture_incremental_verifier(
        &fixture,
        &verified_trees,
        proof_bytes.len(),
        maximum_resident_window_byte_length,
    )
    .expect("the gapped-window verifier initializes");
    let gap_offset = prefix_range.offset() + split_offset;
    let missing_source = ResidentCommonProofByteSource::new(
        proof_bytes.len(),
        vec![
            ResidentCommonProofInputChunk::new(
                prefix_range.offset(),
                &proof_bytes[prefix_range.offset()..gap_offset],
            ),
            ResidentCommonProofInputChunk::new(
                gap_offset + 1,
                &proof_bytes[gap_offset + 1..prefix_end],
            ),
        ],
    )
    .expect("a sparse range is represented but cannot be decoded");
    assert!(matches!(
        missing.poll(&missing_source, &mut NoVerifiedSequenceColumns),
        Err(CommonProofVerifierError::Body(ProofBodyError::Decode(
            ProofDecodeError::Truncated,
        )))
    ));
    assert!(missing.take_verified_common_proof().is_none());

    let mut proof_with_trailing_byte = proof_bytes.clone();
    proof_with_trailing_byte.push(0);
    assert!(matches!(
        verify_fixture_proof_incrementally(&fixture, &proof_with_trailing_byte, &verified_trees,),
        Err(CommonProofVerifierError::Body(ProofBodyError::Decode(
            ProofDecodeError::TrailingBytes,
        )))
    ));
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
                    entry_ordinal: 0,
                    entry: EvaluatorKeyAggregateEntryPlanInput {
                        schedule_position: 3,
                        ordered_runtime_component_moduli: vec![SuiteModulusReference::data(0)],
                    },
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
        Some(0),
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
    assert_eq!(verified_evaluator.schedule_position(), Some(0));
    assert_eq!(verified_evaluator.top_count(), Some(1));
    assert_ne!(
        verified_rkg.application_statement_hash(),
        verified_evaluator.application_statement_hash()
    );
}

#[test]
fn compiled_compact_target_relation_is_refused_before_proving() {
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
            opening_degree_bound_exclusive: TARGET_TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
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
    let target_modulus = relation_context
        .resolved_modulus(SuiteModulusReference::target(0))
        .expect("the compact target modulus is resolved");
    let converted_identifier = (0..TARGET_TEST_RING_DEGREE)
        .map(|coefficient_index| {
            (u64::try_from(coefficient_index).expect("the coefficient index fits u64") * 2 + 1)
                % target_modulus
        })
        .collect::<Vec<_>>();
    let converted_order = (0..TARGET_TEST_RING_DEGREE)
        .map(|coefficient_index| {
            (u64::try_from(coefficient_index).expect("the coefficient index fits u64") * 2 + 2)
                % target_modulus
        })
        .collect::<Vec<_>>();
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
    let _verified_column_evaluator = compilation
        .verified_column_evaluator(&[VerifiedTargetReleaseModulusInput { roles }])
        .expect("the verifier independently rebuilds only public target columns");
    let (relation_trees, _verified_trees, bound_tree_catalog_index) =
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
    let generation_error = generate_common_proof(
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
            maximum_external_memory_chunk_byte_length:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: maximum_proof_byte_length as u64,
        },
        &mut external_memory,
        &mut private_coins,
        &mut sink,
        &mut bound_openings,
    )
    .expect_err("the compact target relation must not bypass the selected proof profile");
    assert!(matches!(
        generation_error,
        CommonProofGenerationError::Profile(ProofProfileError::InvalidSchedule)
    ));
    assert!(sink.finish().is_empty());
    assert!(external_memory.transaction.is_none());
    assert!(external_memory.committed.is_empty());
}
