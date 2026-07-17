use super::*;
use crate::bgv::proof_suite::{
    ProofByteSource, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
    ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
    ProofExternalMemoryTransactionOperation,
};
fn limits() -> CommonProofRuntimeLimits {
    CommonProofRuntimeLimits::new(
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
    )
    .expect("the fixed worker limits are valid")
}

fn registry_test_verification_binding() -> CommonProofVerificationBinding {
    let proof_application = CommonProofApplicationBinding::new(
        [0x11; HASH_BYTE_LENGTH],
        [0x12; HASH_BYTE_LENGTH],
        1,
        [0x13; HASH_BYTE_LENGTH],
        CanonicalStreamDomain::BallotValidityProof,
        [0x14; HASH_BYTE_LENGTH],
        1,
        1,
    )
    .expect("the registry test proof application is bounded");
    CommonProofVerificationBinding::new(
        [0x21; HASH_BYTE_LENGTH],
        [0x22; HASH_BYTE_LENGTH],
        [0x23; HASH_BYTE_LENGTH],
        [0x24; HASH_BYTE_LENGTH],
        proof_application,
        [0x25; HASH_BYTE_LENGTH],
    )
}

#[test]
fn aggregate_registry_capacity_counts_every_entry_family_and_retries_after_release() {
    assert_eq!(
        require_common_proof_registry_entry_capacity(&[32, 32]),
        Err(CommonProofRuntimeError::AllocationLimitExceeded),
    );
    assert_eq!(
        require_common_proof_registry_entry_capacity(&[usize::MAX, 1]),
        Err(CommonProofRuntimeError::AllocationLimitExceeded),
    );
    require_common_proof_registry_entry_capacity(&[32, 31])
        .expect("releasing one aggregate slot permits an exact retry");

    let mut registry = CommonProofRuntimeRegistry::default();
    let verification_binding = registry_test_verification_binding();
    for identifier in 1..=32 {
        registry.insert_test_verification_operation(identifier, verification_binding, limits());
        registry.insert_test_authenticated_ledger_transition(identifier);
    }
    assert_eq!(
        registry.require_entry_capacity(),
        Err(CommonProofRuntimeError::AllocationLimitExceeded),
    );
    registry.remove_test_authenticated_ledger_transition(32);
    registry
        .require_entry_capacity()
        .expect("the runtime registry retries after one entry family releases a slot");
}

#[test]
fn worker_process_refuses_the_sixty_fifth_mixed_registry_admission() {
    let mut runtime_registry = CommonProofRuntimeRegistry::default();
    let mut upstream_registry = CommonProofUpstreamInputRegistry::default();
    for identifier in 1..=21 {
        runtime_registry.insert_test_authenticated_ledger_transition(identifier);
        upstream_registry.insert_test_refusing_verified_column_evaluator(identifier);
    }
    let runtime_entry_count = runtime_registry
        .entry_count()
        .expect("the runtime fixture entry count is bounded");
    let upstream_entry_count = upstream_registry
        .entry_count()
        .expect("the upstream fixture entry count is bounded");

    require_common_proof_worker_process_ownership_limits(
        &[22, runtime_entry_count, upstream_entry_count],
        &[0, 0, 0],
    )
    .expect("an exact 64-owner state remains valid for a neutral transfer");
    assert_eq!(
        require_common_proof_worker_process_admission_capacity(
            &[22, runtime_entry_count, upstream_entry_count],
            &[0, 0, 0],
            false,
        ),
        Err(CommonProofRuntimeError::AllocationLimitExceeded),
        "the next owner is refused across FFI, runtime, and upstream categories",
    );
    require_common_proof_worker_process_admission_capacity(
        &[21, runtime_entry_count, upstream_entry_count],
        &[0, 0, 0],
        false,
    )
    .expect("releasing any one mixed-category owner permits the exact retry");
}

#[test]
fn worker_process_allows_only_one_heavy_proof_attempt() {
    require_common_proof_worker_process_admission_capacity(&[0, 0, 0], &[0, 0, 0], true)
        .expect("the first heavy proof attempt is admitted");
    assert_eq!(
        require_common_proof_worker_process_admission_capacity(&[1, 0, 0], &[1, 0, 0], true,),
        Err(CommonProofRuntimeError::AllocationLimitExceeded),
    );
    require_common_proof_worker_process_admission_capacity(&[1, 0, 0], &[1, 0, 0], false)
        .expect("lightweight ownership may coexist with the one heavy proof attempt");
}

#[test]
fn destination_handle_exhaustion_preserves_the_live_source_for_retry() {
    let source_entries = BTreeMap::from([(7_u32, ())]);
    let mut exhausted_destination_handle = 0;
    assert_eq!(
        take_replacement_handle_before_consuming_source(
            &source_entries,
            &7,
            &mut exhausted_destination_handle,
        ),
        Err(CommonProofRuntimeError::AllocationLimitExceeded),
    );
    assert!(source_entries.contains_key(&7));

    let mut retry_destination_handle = 19;
    assert_eq!(
        take_replacement_handle_before_consuming_source(
            &source_entries,
            &7,
            &mut retry_destination_handle,
        ),
        Ok(19),
    );
    assert!(source_entries.contains_key(&7));
}

#[test]
fn output_sink_yields_exact_chunks_and_retries_only_the_same_write() {
    let declared_byte_length = MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH + 17;
    let mut sink = PollableCommonProofByteSink::new(
        CanonicalStreamDomain::BallotValidityProof,
        declared_byte_length,
        limits(),
    )
    .expect("the bounded stream sink starts");
    let bytes = vec![0x5a; declared_byte_length];
    assert_eq!(
        sink.write_bytes(&bytes),
        Err(PollableCommonProofByteSinkError::ChunkReady)
    );
    let (chunk_index, first_chunk) = sink.pending_chunk().expect("the first chunk is ready");
    assert_eq!(chunk_index, 0);
    assert_eq!(first_chunk.len(), MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
    let first_chunk_readback = first_chunk.to_vec();
    assert_eq!(
        sink.write_bytes(&bytes),
        Err(PollableCommonProofByteSinkError::ChunkAwaitingCommit)
    );
    sink.acknowledge_pending_chunk()
        .expect("the first browser transaction commits");
    assert_eq!(
        sink.write_bytes(&bytes),
        Err(PollableCommonProofByteSinkError::ChunkAwaitingReadback)
    );
    let mut substituted_readback = first_chunk_readback.clone();
    substituted_readback[0] ^= 1;
    assert_eq!(
        sink.confirm_pending_chunk_readback(0, &substituted_readback),
        Err(CommonProofRuntimeError::OutputWriteReplayMismatch)
    );
    sink.confirm_pending_chunk_readback(0, &first_chunk_readback)
        .expect("the exact first staged chunk rereads");

    let changed = vec![0x6b; declared_byte_length];
    assert_eq!(
        sink.write_bytes(&changed),
        Err(PollableCommonProofByteSinkError::ReplayMismatch)
    );
    assert_eq!(
        sink.write_bytes(&bytes),
        Err(PollableCommonProofByteSinkError::ChunkReady)
    );
    let (chunk_index, final_chunk) = sink.pending_chunk().expect("the final chunk is ready");
    assert_eq!(chunk_index, 1);
    assert_eq!(
        final_chunk,
        &bytes[MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH..]
    );
    let final_chunk_readback = final_chunk.to_vec();
    sink.acknowledge_pending_chunk()
        .expect("the final browser transaction commits");
    assert_eq!(
        sink.confirm_pending_chunk_readback(0, &final_chunk_readback),
        Err(CommonProofRuntimeError::OutputWriteReplayMismatch)
    );
    sink.confirm_pending_chunk_readback(1, &final_chunk_readback)
        .expect("the exact final staged chunk rereads");
    assert_eq!(sink.write_bytes(&bytes), Ok(()));
    let descriptor = sink.finish().expect("the exact stream seals");
    assert_eq!(descriptor.total_byte_length, declared_byte_length as u64);
    assert_eq!(descriptor.ordered_chunk_digests.len(), 2);
}

#[test]
fn output_sink_refuses_overrun_and_uncommitted_completion() {
    let mut sink =
        PollableCommonProofByteSink::new(CanonicalStreamDomain::PublicKeyShareProof, 4, limits())
            .expect("small stream starts");
    assert_eq!(
        sink.write_bytes(&[1, 2, 3, 4, 5]),
        Err(PollableCommonProofByteSinkError::ByteLengthExceeded)
    );

    let mut exact =
        PollableCommonProofByteSink::new(CanonicalStreamDomain::PublicKeyShareProof, 4, limits())
            .expect("exact stream starts");
    assert_eq!(
        exact.write_bytes(&[1, 2, 3, 4]),
        Err(PollableCommonProofByteSinkError::ChunkReady)
    );
    assert_eq!(
        exact.finish(),
        Err(CommonProofRuntimeError::OutputChunkNotReady)
    );

    let mut cancelled =
        PollableCommonProofByteSink::new(CanonicalStreamDomain::PublicKeyShareProof, 4, limits())
            .expect("cancelled stream starts");
    assert_eq!(
        cancelled.write_bytes(&[1, 2, 3, 4]),
        Err(PollableCommonProofByteSinkError::ChunkReady)
    );
    cancelled.cancel();
    assert!(cancelled.pending_chunk().is_none());
    assert_eq!(
        cancelled.write_bytes(&[1, 2, 3, 4]),
        Err(PollableCommonProofByteSinkError::ByteLengthExceeded)
    );
}

#[test]
fn resident_source_spans_two_chunks_and_fails_closed_on_a_gap() {
    let first = [1_u8, 2, 3, 4];
    let second = [5_u8, 6, 7, 8];
    let source = ResidentCommonProofByteSource::new(
        8,
        vec![
            ResidentCommonProofInputChunk::new(0, &first),
            ResidentCommonProofInputChunk::new(4, &second),
        ],
    )
    .expect("two adjacent chunks form one window");
    let mut destination = [0_u8; 6];
    assert!(source.copy_bytes(1, &mut destination));
    assert_eq!(destination, [2, 3, 4, 5, 6, 7]);

    let gapped = ResidentCommonProofByteSource::new(
        9,
        vec![
            ResidentCommonProofInputChunk::new(0, &first),
            ResidentCommonProofInputChunk::new(5, &second),
        ],
    )
    .expect("a sparse window is representable");
    let mut through_gap = [0xff; 3];
    assert!(!gapped.copy_bytes(3, &mut through_gap));
    assert_eq!(through_gap[0], 4);
}

#[test]
fn storage_transaction_requires_exact_replay_before_state_advances() {
    let object = ProofExternalMemoryObject::new(0);
    let plan = ProofExternalMemoryPlan::new(
        1,
        4,
        4,
        1,
        4,
        4,
        4,
        8,
        vec![ProofExternalMemoryObjectPlan::new(
            object,
            ProofExternalMemoryProtection::PublicIntegrity,
            4,
            0,
            0,
            0,
        )],
    )
    .expect("the one-object test plan is valid");
    let mut executor = ProofExternalMemoryExecutor::new(plan).expect("executor starts");
    let mut runtime = CommonProofStorageTransactionRuntime::default();
    assert_eq!(
        executor.begin_object(runtime.storage(), object),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded
        ))
    );
    assert_eq!(executor.usage().transaction_count, 0);
    let request = runtime
        .capture_yielded_request()
        .expect("the create request is captured");
    assert!(matches!(
        request.operations(),
        [ProofExternalMemoryTransactionOperation::Create { .. }]
    ));
    let request_sequence = request.request_sequence();
    let encoded_request = runtime
        .encode_pending_worker_request()
        .expect("the pending request has a bounded binary encoding");
    let request_digest = encoded_request
        .get(92..156)
        .expect("the request digest occupies its fixed header field");
    let mut encoded_response = Vec::new();
    encoded_response.extend_from_slice(&1_u16.to_le_bytes());
    encoded_response.extend_from_slice(&2_u16.to_le_bytes());
    encoded_response.extend_from_slice(&request_sequence.to_le_bytes());
    encoded_response.extend_from_slice(request_digest);
    encoded_response.extend_from_slice(&0_u32.to_le_bytes());
    runtime
        .supply_worker_response(&encoded_response)
        .expect("create has no read response");

    runtime
        .begin_transaction(4, 1)
        .expect("the replay transaction header matches");
    assert_eq!(
        runtime.create_object(
            ProofExternalMemoryObject::new(1),
            ProofExternalMemoryProtection::PublicIntegrity,
            4,
        ),
        Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay),
        "a different retried request must be refused"
    );
    assert_eq!(executor.usage().transaction_count, 0);
}

#[test]
fn storage_transaction_cancellation_invalidates_an_inflight_request() {
    let object = ProofExternalMemoryObject::new(0);
    let mut runtime = CommonProofStorageTransactionRuntime::for_runtime_binding([0x55; 64]);
    runtime
        .begin_transaction(4, 1)
        .expect("the bounded transaction begins");
    runtime
        .append_object_bytes(object, 0, &[1, 2, 3, 4])
        .expect("the inflight payload records");
    assert_eq!(
        runtime.commit_transaction(),
        Err(ProofExternalMemoryTransactionAdapterError::Yielded),
    );
    runtime
        .capture_yielded_request()
        .expect("the inflight request is captured");
    let encoded_request = runtime
        .encode_pending_worker_request()
        .expect("the inflight request is visible before cancellation");
    runtime.cancel();
    assert_eq!(
        runtime.encode_pending_worker_request(),
        Err(CommonProofRuntimeError::TransactionResponseMissing),
    );
    assert_eq!(
        runtime.supply_worker_response(&encoded_request),
        Err(CommonProofRuntimeError::TransactionResponseMissing),
    );
    assert_eq!(
        runtime.begin_transaction(4, 1),
        Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle),
    );
}

#[test]
fn runtime_limits_bind_the_fixed_external_memory_chunk_profile_and_reject_overruns() {
    assert_eq!(MAXIMUM_COMMON_PROOF_BYTE_LENGTH, 5_242_880);
    assert_eq!(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, 1_048_576);
    assert_eq!(
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        49_152
    );
    let exact_limits = CommonProofRuntimeLimits::new(
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
    )
    .expect("the exact fixed worker ceilings are accepted");
    assert_eq!(
        exact_limits.proof_byte_length(),
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH
    );
    assert_eq!(
        exact_limits.external_memory_chunk_byte_length(),
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
    );
    assert_eq!(
        exact_limits.prefetched_query_byte_length(),
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64
    );
    assert_eq!(
        CommonProofRuntimeLimits::new(
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            1,
        ),
        Err(CommonProofRuntimeError::InvalidLimits)
    );
    assert_eq!(
        CommonProofRuntimeLimits::new(
            1,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH - 1,
            1,
        ),
        Err(CommonProofRuntimeError::InvalidLimits)
    );
    assert_eq!(
        CommonProofRuntimeLimits::new(
            1,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH + 1,
            1,
        ),
        Err(CommonProofRuntimeError::InvalidLimits)
    );
    assert_eq!(
        CommonProofRuntimeLimits::new(1, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, 2,),
        Err(CommonProofRuntimeError::InvalidLimits)
    );
    assert_eq!(
        CommonProofRuntimeLimits::new(0, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, 1,),
        Err(CommonProofRuntimeError::InvalidLimits)
    );
    assert_eq!(
        CommonProofRuntimeLimits::new(1, 0, 1),
        Err(CommonProofRuntimeError::InvalidLimits)
    );
    assert_eq!(
        CommonProofRuntimeLimits::new(1, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, 0,),
        Err(CommonProofRuntimeError::InvalidLimits)
    );
}
