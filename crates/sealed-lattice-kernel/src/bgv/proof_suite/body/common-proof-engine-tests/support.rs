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
    ParticipantIdentity, PrivateRandomCursor, ProofApplicationSlot, ProofApplicationSlotCeilings,
    ProofObjectHeader, RefusalReason, StreamDescriptor, VerifiedCanonicalStreamSummary,
    derive_canonical_stream_descriptor,
};

use super::super::super::prover::{
    CommonProofPrivateCoinReplayCursor, CommonProofPrivateCoinReplaySpan,
    CommonProofPrivateCoinReplaySpanStart, ReplayableCommonProofPrivateCoinCatalogSource,
    ReplayableCommonProofPrivateCoinSource,
};
use super::super::super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationTreeDescriptor,
};
use super::super::super::{
    BoundedCommonProofByteSink, CheckpointableCommonProofPrivateCoinSource,
    CollectivePublicKeyAggregatePlanInput, CommittedMaterialProfile, CommittedMaterialTree,
    CommittedMaterialTreeInput, CommonProofApplicationBinding,
    CommonProofCheckpointCursorManifestError, CommonProofGenerationAuthorization,
    CommonProofGenerationError, CommonProofGenerationInitializationError,
    CommonProofGenerationInput, CommonProofGenerationOperationHandle, CommonProofGenerationSources,
    CommonProofGenerationStateMachine, CommonProofGenerationWorkerError,
    CommonProofGenerationWorkerPoll, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofRelationPlanCapability,
    CommonProofResidentMemoryPhase, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofRuntimeRegistry, CommonProofSourcePolynomial, CommonProofUpstreamInputRegistry,
    CommonProofVerificationBinding, CommonProofVerificationInput, CommonProofVerificationPoll,
    CommonProofVerificationStateMachine, CommonProofVerificationWorkerError,
    CommonProofVerificationWorkerPoll, CommonProofVerifierError, CompiledRelationPlan,
    CompiledTargetReleaseRelation, EvaluatorKeyAggregateEntryPlanInput,
    EvaluatorKeyAggregatePlanInput, EvaluatorKeyAggregateVariantInput,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR,
    PROOF_EVALUATION_COSET_OFFSET, PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT,
    PollableCommonProofVerificationInput, PreparedCommonProofGeneration,
    PreparedCommonProofVerification, ProofBaseFieldElement, ProofBodyError,
    ProofChallengeExtensionElement, ProofDecodeError, ProofEvaluationDomain, ProofExternalMemory,
    ProofExternalMemoryObject, ProofExternalMemoryProtection,
    ProofExternalMemoryTransactionOperation, ProofExternalMemoryTransactionRequest,
    ProofLeafVisibility, ProofProfileError, ProofTreeRole, PublicAggregateRelationGeometry,
    PublicOnlyCommonProofCoinSource, RelationPlanCheckContext, RelationProofTreeInput,
    ResidentCommonProofByteSource, ResidentCommonProofInputChunk,
    ResidentCommonProofSourcePolynomialProvider, ResolvedSuiteModulus,
    RkgRoundOneAggregatePlanInput, RkgRoundOneAggregateVariantInput, SameSecretRelationPlanInput,
    SetupPublicPolynomialContext, SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput,
    StatementOwnedProofTreeInput, SuiteModulusReference, TargetReleaseModulusWitness,
    TargetReleaseRelationPlanInput, TargetReleaseRoleWitness, TargetReleaseWitness,
    VerifiedCommonProof, VerifiedCommonProofCapabilityHandle, VerifiedRelationColumnEvaluator,
    VerifiedRelationColumnEvaluatorMemoryAccounting, VerifiedStatementOwnedTree,
    VerifiedTargetReleaseModulusInput, canonical_proof_object_header_bytes,
    common_proof_private_coin_coordinate_derivation_context_hash,
    compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_target_release_relation,
    construct_composed_quotient_polynomial,
    construct_constraint_stream_composed_quotient_polynomial, durable_authorization_frame_digest,
    encode_common_proof_checkpoint_cursor_manifest, generate_common_proof,
    selected_relation_plan_check_context, selected_relation_plans,
    verified_application_statement_hash, verify_common_proof,
};
use super::super::SCHEMA_VERSION;

const APPLICATION_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
const RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1215;
const EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1218;
const TARGET_RELEASE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1621;
const PUBLIC_AGGREGATE_TEST_EVALUATION_DOMAIN_SIZE: u64 = 2_048;
const PUBLIC_AGGREGATE_TEST_EVALUATION_BLOWUP_FACTOR: u32 = 4;
const PUBLIC_AGGREGATE_TEST_RING_DEGREE: u64 = 4;
const PUBLIC_AGGREGATE_TEST_COLUMN_DEGREE_BOUND_EXCLUSIVE: usize =
    PUBLIC_AGGREGATE_TEST_RING_DEGREE as usize / 2;
const PUBLIC_AGGREGATE_TEST_UNIQUE_QUERY_COUNT: u32 = PROOF_UNIQUE_QUERY_COUNT;
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
    ReplaySourceMismatch,
    ReplayCursorMismatch,
    ReplaySpanAlreadyActive,
    ReplaySpanNotActive,
    ReplayAttemptInvalidated,
}

struct BoundedDeterministicTestPrivateCoins {
    remaining_call_count: u32,
    remaining_byte_count: usize,
    calls_by_coordinate: BTreeMap<CommonProofPrivateCoinCoordinate, u64>,
    checkpoint_cursor_family_schema_identifier: u16,
    replay_instance_binding: Rc<()>,
    replay_reset_epoch: u64,
    next_replay_span_identifier: u64,
    active_replay_span: Option<(bool, u64)>,
    replay_invalidated: bool,
}

impl BoundedDeterministicTestPrivateCoins {
    fn new(maximum_call_count: u32, maximum_byte_count: usize) -> Self {
        Self {
            remaining_call_count: maximum_call_count,
            remaining_byte_count: maximum_byte_count,
            calls_by_coordinate: BTreeMap::new(),
            checkpoint_cursor_family_schema_identifier: APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
            replay_instance_binding: Rc::new(()),
            replay_reset_epoch: 0,
            next_replay_span_identifier: 1,
            active_replay_span: None,
            replay_invalidated: false,
        }
    }

    fn with_checkpoint_cursor_counter_delta(mut self, counter_delta: u64) -> Self {
        if counter_delta != 0 {
            self.checkpoint_cursor_family_schema_identifier =
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
            self.calls_by_coordinate.insert(
                CommonProofPrivateCoinCoordinate::mask(1, 0)
                    .expect("trace private-coin class is assigned"),
                counter_delta,
            );
        }
        self
    }

    fn consume_call(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Result<u64, TestPrivateCoinError> {
        self.remaining_call_count = self
            .remaining_call_count
            .checked_sub(1)
            .ok_or(TestPrivateCoinError::CallLimitExceeded)?;
        let call_count = self.calls_by_coordinate.entry(coordinate).or_default();
        let call_ordinal = *call_count;
        *call_count = call_count
            .checked_add(1)
            .ok_or(TestPrivateCoinError::CallLimitExceeded)?;
        Ok(call_ordinal)
    }

    fn proof_salt_replay_cursor(&self) -> PrivateRandomCursor {
        let coordinate = CommonProofPrivateCoinCoordinate::proof_salt();
        PrivateRandomCursor::new(
            self.checkpoint_cursor_family_schema_identifier,
            coordinate.purpose_class(),
            common_proof_private_coin_coordinate_derivation_context_hash(
                Hash512::from_bytes([0x51; 64]),
                coordinate,
            ),
            [0x52; 32],
            self.calls_by_coordinate
                .get(&coordinate)
                .copied()
                .unwrap_or(0),
            None,
        )
        .expect("the common-proof test salt coordinate is assigned")
    }

    fn replay_cursor(
        &self,
        coordinate: CommonProofPrivateCoinCoordinate,
        call_count: u64,
    ) -> PrivateRandomCursor {
        PrivateRandomCursor::new(
            self.checkpoint_cursor_family_schema_identifier,
            coordinate.purpose_class(),
            common_proof_private_coin_coordinate_derivation_context_hash(
                Hash512::from_bytes([0x51; 64]),
                coordinate,
            ),
            [0x52; 32],
            call_count,
            None,
        )
        .expect("the common-proof test coordinate is assigned")
    }

    fn replay_cursor_catalog(
        &self,
    ) -> Box<[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)]> {
        self.calls_by_coordinate
            .iter()
            .map(|(coordinate, call_count)| {
                (*coordinate, self.replay_cursor(*coordinate, *call_count))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    fn validate_replay_cursor_catalog(
        &self,
        cursors: &[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)],
    ) -> Result<(), TestPrivateCoinError> {
        let mut previous_coordinate = None;
        for (coordinate, cursor) in cursors {
            if previous_coordinate.is_some_and(|previous| previous >= *coordinate)
                || *cursor != self.replay_cursor(*coordinate, cursor.next_counter())
            {
                return Err(TestPrivateCoinError::ReplayCursorMismatch);
            }
            previous_coordinate = Some(*coordinate);
        }
        Ok(())
    }
}

impl CommonProofPrivateCoinSource for BoundedDeterministicTestPrivateCoins {
    type Error = TestPrivateCoinError;

    fn sample_modulo(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        let call_ordinal = self.consume_call(coordinate)?;
        if modulus < 2 || maximum_candidate_draws_per_output == 0 {
            return Err(TestPrivateCoinError::InvalidModulus);
        }
        Ok(call_ordinal
            .wrapping_add(u64::from(coordinate.purpose_class()) << 32)
            .wrapping_add(u64::from(coordinate.ordinal()))
            % modulus)
    }

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let call_ordinal = self.consume_call(coordinate)?;
        self.remaining_byte_count = self
            .remaining_byte_count
            .checked_sub(destination.len())
            .ok_or(TestPrivateCoinError::ByteLimitExceeded)?;
        let byte_stream_start = call_ordinal
            .wrapping_mul(u64::try_from(destination.len()).unwrap_or(u64::MAX))
            .wrapping_add(u64::from(coordinate.purpose_class()) << 32)
            .wrapping_add(u64::from(coordinate.ordinal()));
        for (offset, byte) in destination.iter_mut().enumerate() {
            *byte = byte_stream_start.wrapping_add(offset as u64) as u8;
        }
        Ok(())
    }
}

impl ReplayableCommonProofPrivateCoinSource for BoundedDeterministicTestPrivateCoins {
    fn capture_proof_salt_replay_cursor(
        &self,
    ) -> Result<CommonProofPrivateCoinReplayCursor, Self::Error> {
        Ok(CommonProofPrivateCoinReplayCursor::new(
            &self.replay_instance_binding,
            self.proof_salt_replay_cursor(),
        ))
    }

    fn restore_proof_salt_replay_cursor(
        &mut self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<(), Self::Error> {
        if !replay_cursor.belongs_to(&self.replay_instance_binding) {
            return Err(TestPrivateCoinError::ReplaySourceMismatch);
        }
        let expected_cursor = self.proof_salt_replay_cursor();
        let cursor = replay_cursor.cursor();
        if cursor.family() != expected_cursor.family()
            || cursor.purpose() != expected_cursor.purpose()
            || cursor.derivation_context_hash() != expected_cursor.derivation_context_hash()
            || cursor.stream_attempt_identifier() != expected_cursor.stream_attempt_identifier()
            || cursor.next_unread_bit_offset_in_buffered_block().is_some()
        {
            return Err(TestPrivateCoinError::ReplayCursorMismatch);
        }
        self.calls_by_coordinate.insert(
            CommonProofPrivateCoinCoordinate::proof_salt(),
            cursor.next_counter(),
        );
        Ok(())
    }

    fn proof_salt_replay_cursor_matches(
        &self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<bool, Self::Error> {
        if !replay_cursor.belongs_to(&self.replay_instance_binding) {
            return Err(TestPrivateCoinError::ReplaySourceMismatch);
        }
        Ok(replay_cursor.cursor() == self.proof_salt_replay_cursor())
    }
}

impl ReplayableCommonProofPrivateCoinCatalogSource for BoundedDeterministicTestPrivateCoins {
    fn begin_all_coordinate_replay_span(
        &mut self,
    ) -> Result<CommonProofPrivateCoinReplaySpanStart, Self::Error> {
        if self.replay_invalidated {
            return Err(TestPrivateCoinError::ReplayAttemptInvalidated);
        }
        if self.active_replay_span.is_some() {
            return Err(TestPrivateCoinError::ReplaySpanAlreadyActive);
        }
        let span_identifier = self.next_replay_span_identifier;
        self.next_replay_span_identifier = self
            .next_replay_span_identifier
            .checked_add(1)
            .ok_or(TestPrivateCoinError::ReplayAttemptInvalidated)?;
        let start = CommonProofPrivateCoinReplaySpanStart::new(
            &self.replay_instance_binding,
            self.checkpoint_cursor_family_schema_identifier,
            Hash512::from_bytes([0x51; 64]),
            [0x52; 32],
            self.replay_reset_epoch,
            span_identifier,
            self.replay_cursor_catalog(),
        )
        .map_err(|_| TestPrivateCoinError::ReplayCursorMismatch)?;
        self.active_replay_span = Some((false, span_identifier));
        Ok(start)
    }

    fn finish_all_coordinate_replay_span(
        &mut self,
        start: CommonProofPrivateCoinReplaySpanStart,
    ) -> Result<CommonProofPrivateCoinReplaySpan, Self::Error> {
        if self.replay_invalidated {
            return Err(TestPrivateCoinError::ReplayAttemptInvalidated);
        }
        if self.active_replay_span != Some((false, start.span_identifier())) {
            return Err(TestPrivateCoinError::ReplaySpanNotActive);
        }
        if !start.belongs_to(
            &self.replay_instance_binding,
            self.checkpoint_cursor_family_schema_identifier,
            Hash512::from_bytes([0x51; 64]),
            [0x52; 32],
            self.replay_reset_epoch,
        ) {
            return Err(TestPrivateCoinError::ReplaySourceMismatch);
        }
        let span = CommonProofPrivateCoinReplaySpan::from_completed_capture(
            start,
            self.replay_cursor_catalog(),
        )
        .map_err(|_| TestPrivateCoinError::ReplayCursorMismatch)?;
        self.active_replay_span = None;
        Ok(span)
    }

    fn restore_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        if self.replay_invalidated {
            return Err(TestPrivateCoinError::ReplayAttemptInvalidated);
        }
        if self.active_replay_span.is_some() {
            return Err(TestPrivateCoinError::ReplaySpanAlreadyActive);
        }
        if !span.belongs_to(
            &self.replay_instance_binding,
            self.checkpoint_cursor_family_schema_identifier,
            Hash512::from_bytes([0x51; 64]),
            [0x52; 32],
            self.replay_reset_epoch,
        ) {
            return Err(TestPrivateCoinError::ReplaySourceMismatch);
        }
        self.validate_replay_cursor_catalog(span.start_cursors())?;
        self.calls_by_coordinate = span
            .start_cursors()
            .iter()
            .map(|(coordinate, cursor)| (*coordinate, cursor.next_counter()))
            .collect();
        self.active_replay_span = Some((true, span.span_identifier()));
        Ok(())
    }

    fn complete_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        if self.replay_invalidated {
            return Err(TestPrivateCoinError::ReplayAttemptInvalidated);
        }
        if self.active_replay_span != Some((true, span.span_identifier())) {
            return Err(TestPrivateCoinError::ReplaySpanNotActive);
        }
        if !span.belongs_to(
            &self.replay_instance_binding,
            self.checkpoint_cursor_family_schema_identifier,
            Hash512::from_bytes([0x51; 64]),
            [0x52; 32],
            self.replay_reset_epoch,
        ) || self.replay_cursor_catalog().as_ref() != span.end_cursors()
        {
            self.invalidate_all_coordinate_replay_state();
            return Err(TestPrivateCoinError::ReplayCursorMismatch);
        }
        self.active_replay_span = None;
        Ok(())
    }

    fn invalidate_all_coordinate_replay_state(&mut self) {
        self.replay_invalidated = true;
        self.replay_reset_epoch = self.replay_reset_epoch.wrapping_add(1);
        self.active_replay_span = None;
        self.calls_by_coordinate.clear();
    }
}

impl CheckpointableCommonProofPrivateCoinSource for BoundedDeterministicTestPrivateCoins {
    fn checkpoint_cursor_manifest(
        &self,
    ) -> Result<Vec<u8>, CommonProofCheckpointCursorManifestError> {
        let derivation_binding_hash = Hash512::from_bytes([0x51; 64]);
        let stream_attempt_identifier = [0x52; 32];
        let ordered_cursors = self
            .calls_by_coordinate
            .iter()
            .map(|(coordinate, call_count)| {
                PrivateRandomCursor::new(
                    self.checkpoint_cursor_family_schema_identifier,
                    coordinate.purpose_class(),
                    common_proof_private_coin_coordinate_derivation_context_hash(
                        derivation_binding_hash,
                        *coordinate,
                    ),
                    stream_attempt_identifier,
                    *call_count,
                    None,
                )
                .map(|cursor| (*coordinate, cursor))
                .expect("the common-proof test coordinate is assigned")
            })
            .collect::<Vec<_>>();
        encode_common_proof_checkpoint_cursor_manifest(
            self.checkpoint_cursor_family_schema_identifier,
            derivation_binding_hash,
            stream_attempt_identifier,
            ordered_cursors.iter().copied(),
        )
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
    let ordered_trace_rows = vec![vec![
        ProofBaseFieldElement::from_canonical(constant_value)
            .expect("the toy source coefficient is canonical");
        PUBLIC_AGGREGATE_TEST_COLUMN_DEGREE_BOUND_EXCLUSIVE
    ]];
    SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
        context: &context,
        evaluation_domain_size: PUBLIC_AGGREGATE_TEST_EVALUATION_DOMAIN_SIZE as usize,
        source_polynomial_degree_bound_exclusive:
            PUBLIC_AGGREGATE_TEST_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        ordered_trace_rows: &ordered_trace_rows,
    })
    .expect("the public-polynomial LDE tree is canonical")
}

struct NoVerifiedSequenceColumns;

impl VerifiedRelationColumnEvaluator for NoVerifiedSequenceColumns {
    fn memory_accounting(
        &self,
    ) -> Result<VerifiedRelationColumnEvaluatorMemoryAccounting, CommonProofVerifierError> {
        VerifiedRelationColumnEvaluatorMemoryAccounting::new(
            core::mem::size_of::<Self>() as u64,
            0,
            0,
        )
    }

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
        usize::try_from(PUBLIC_AGGREGATE_TEST_EVALUATION_DOMAIN_SIZE)
            .expect("the toy domain fits usize"),
        PROOF_EVALUATION_COSET_OFFSET,
    )
    .expect("the toy evaluation domain is valid");
    RelationPlanCheckContext {
        base_field_modulus: PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
        evaluation_blowup_factor: PUBLIC_AGGREGATE_TEST_EVALUATION_BLOWUP_FACTOR,
        evaluation_domain_generator: evaluation_domain.generator().canonical(),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        deep_point_count: PROOF_DEEP_POINT_COUNT,
        quotient_component_count: 2,
        quotient_component_degree_bound_exclusive: 2,
        fri_fold_count: 1,
        final_polynomial_degree_bound_exclusive: PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
        unique_query_count: PUBLIC_AGGREGATE_TEST_UNIQUE_QUERY_COUNT,
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
        ring_degree: PUBLIC_AGGREGATE_TEST_RING_DEGREE,
        evaluation_domain_size: PUBLIC_AGGREGATE_TEST_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: OPENING_DEGREE_BOUND_EXCLUSIVE,
        public_polynomial_column_degree_bound_exclusive:
            PUBLIC_AGGREGATE_TEST_COLUMN_DEGREE_BOUND_EXCLUSIVE as u64,
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
                CommonProofSourcePolynomial::from_base_coefficients(vec![
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
    let family_schema_identifier = CanonicalTuple::decode(
        &fixture.canonical_application_statement_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .expect("the public aggregate statement is canonical")
    .schema_identifier;
    let mut public_only_source = PublicOnlyCommonProofCoinSource::new(
        family_schema_identifier,
        Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]),
        [0x52; 32],
    )
    .expect("the public aggregate fixture has no private proof-coin domain");
    let mut sink = BoundedCommonProofByteSink::new(MAXIMUM_PROOF_BYTE_LENGTH)
        .expect("the bounded proof sink initializes");
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
            source_polynomial_provider: Box::new(ResidentCommonProofSourcePolynomialProvider::new(
                fixture.provided_columns.clone(),
            )),
            maximum_external_memory_chunk_byte_length:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: MAXIMUM_PROOF_BYTE_LENGTH as u64,
        },
        &mut external_memory,
        &mut public_only_source,
        &mut sink,
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
        super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
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
        total_byte_length: super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        ordered_chunk_digests: vec![Hash512::from_bytes([0x45; 64]); 5].into(),
        full_object_digest: Hash512::from_bytes([0x44; 64]),
    };
    let proof_application = CommonProofApplicationBinding::new(
        [0x41; 64],
        [0x42; 64],
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        proof_header_hash,
        stream_domain,
        proof_stream_descriptor.full_object_digest.into_bytes(),
        super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        PUBLIC_AGGREGATE_TEST_UNIQUE_QUERY_COUNT,
    )
    .expect("the fixture application fits the worker safety bound");
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
    upstream_registry
        .attach_statement_owned_tree_batch(&application_handle, verified_trees)
        .expect("the verified statement-tree batch is retained");
    upstream_registry
        .consume_verification_inputs(&application_handle, &[], None)
        .expect("the exact verifier capability set is consumed")
        .prepare()
}

#[path = "support/adapters.rs"]
mod adapters;
#[path = "support/generation.rs"]
mod generation;
#[path = "support/proof_families.rs"]
mod proof_families;
#[path = "support/proof_round_trip.rs"]
mod proof_round_trip;
#[path = "support/runtime_registry.rs"]
mod runtime_registry;
#[path = "support/verification.rs"]
mod verification;

use generation::prepared_generation_worker_fixture_for_checkpoint;
