use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestStorageError {
    NoTransaction,
    Duplicate,
    Missing,
    WrongLength,
}

#[derive(Clone)]
struct TestObject {
    bytes: Vec<u8>,
    exact_byte_length: usize,
    sealed: bool,
    protection: ProofExternalMemoryProtection,
}

#[derive(Default)]
struct TestStorage {
    committed: BTreeMap<ProofExternalMemoryObject, TestObject>,
    transaction: Option<BTreeMap<ProofExternalMemoryObject, TestObject>>,
}

impl ProofExternalMemory for TestStorage {
    type Error = TestStorageError;

    fn begin_transaction(&mut self, _: u64, _: u32) -> Result<(), Self::Error> {
        if self.transaction.is_some() {
            return Err(TestStorageError::Duplicate);
        }
        self.transaction = Some(self.committed.clone());
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?;
        if transaction.contains_key(&object) {
            return Err(TestStorageError::Duplicate);
        }
        transaction.insert(
            object,
            TestObject {
                bytes: Vec::new(),
                exact_byte_length: usize::try_from(exact_byte_length)
                    .map_err(|_| TestStorageError::WrongLength)?,
                sealed: false,
                protection,
            },
        );
        Ok(())
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let object = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .get_mut(&object)
            .ok_or(TestStorageError::Missing)?;
        if object.sealed
            || usize::try_from(expected_offset).ok() != Some(object.bytes.len())
            || object.bytes.len() + bytes.len() > object.exact_byte_length
        {
            return Err(TestStorageError::WrongLength);
        }
        object.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let object = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .get_mut(&object)
            .ok_or(TestStorageError::Missing)?;
        if object.bytes.len() != object.exact_byte_length {
            return Err(TestStorageError::WrongLength);
        }
        object.sealed = true;
        Ok(())
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let object = self
            .transaction
            .as_ref()
            .ok_or(TestStorageError::NoTransaction)?
            .get(&object)
            .ok_or(TestStorageError::Missing)?;
        let offset = usize::try_from(offset).map_err(|_| TestStorageError::WrongLength)?;
        let source = object
            .bytes
            .get(offset..offset + destination.len())
            .ok_or(TestStorageError::WrongLength)?;
        destination.copy_from_slice(source);
        Ok(())
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        self.transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .remove(&object)
            .ok_or(TestStorageError::Missing)?;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        self.committed = self
            .transaction
            .take()
            .ok_or(TestStorageError::NoTransaction)?;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        self.transaction
            .take()
            .ok_or(TestStorageError::NoTransaction)?;
        Ok(())
    }
}

fn plan() -> ProofExternalMemoryPlan {
    ProofExternalMemoryPlan::new(
        3,
        4,
        4,
        2,
        12,
        16,
        24,
        32,
        vec![
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                8,
                0,
                0,
                2,
            ),
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(1),
                ProofExternalMemoryProtection::PublicIntegrity,
                4,
                1,
                1,
                1,
            ),
        ],
    )
    .expect("valid external-memory plan")
}

fn single_object_write_plan(
    maximum_chunk_byte_length: u32,
    exact_byte_length: u64,
) -> ProofExternalMemoryPlan {
    let maximum_transaction_count = exact_byte_length
        .div_ceil(u64::from(maximum_chunk_byte_length))
        .checked_add(3)
        .expect("the test transaction ceiling fits u64");
    ProofExternalMemoryPlan::new(
        1,
        maximum_chunk_byte_length,
        u64::from(maximum_chunk_byte_length),
        1,
        exact_byte_length,
        exact_byte_length,
        1,
        maximum_transaction_count,
        vec![ProofExternalMemoryObjectPlan::new(
            ProofExternalMemoryObject::new(0),
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            exact_byte_length,
            0,
            0,
            0,
        )],
    )
    .expect("the single-object write plan is valid")
}

#[test]
fn executor_enforces_chunked_writes_random_reads_and_exact_last_use() {
    let first = ProofExternalMemoryObject::new(0);
    let second = ProofExternalMemoryObject::new(1);
    let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
    let mut storage = TestStorage::default();

    executor
        .begin_object(&mut storage, first)
        .expect("first starts");
    executor
        .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
        .expect("first chunk writes");
    executor
        .append_object_bytes(&mut storage, first, &[5, 6, 7, 8])
        .expect("second chunk writes");
    executor
        .seal_object(&mut storage, first)
        .expect("first seals");
    executor
        .complete_step(&mut storage)
        .expect("step zero completes");

    executor
        .begin_object(&mut storage, second)
        .expect("second starts");
    executor
        .append_object_bytes(&mut storage, second, &[9, 10, 11, 12])
        .expect("second writes");
    executor
        .seal_object(&mut storage, second)
        .expect("second seals");
    let mut suffix = [0_u8; 3];
    executor
        .read_object_bytes(&mut storage, first, 5, &mut suffix)
        .expect("random suffix read");
    assert_eq!(suffix, [6, 7, 8]);
    executor
        .complete_step(&mut storage)
        .expect("second is deleted");
    assert!(!storage.committed.contains_key(&second));
    assert_eq!(
        storage.committed.get(&first).map(|entry| entry.protection),
        Some(ProofExternalMemoryProtection::SecretAuthenticatedEncryption),
    );

    let mut prefix = [0_u8; 2];
    executor
        .read_object_bytes(&mut storage, first, 0, &mut prefix)
        .expect("first remains through last use");
    assert_eq!(prefix, [1, 2]);
    executor
        .complete_step(&mut storage)
        .expect("final deletion commits");
    let usage = executor.finish().expect("executor finishes");
    assert_eq!(usage.total_written_byte_length, 12);
    assert_eq!(usage.total_read_byte_length, 5);
    assert_eq!(usage.peak_stored_byte_length, 12);
    assert_eq!(usage.deleted_object_count, 2);
    assert!(storage.committed.is_empty());
}

#[test]
fn executor_accepts_only_full_intermediate_chunks_and_the_exact_declared_tail() {
    let object = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 10))
        .expect("the exact-chunk executor starts");
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, object)
        .expect("the object begins");

    executor
        .append_object_bytes(&mut storage, object, &[1, 2, 3, 4])
        .expect("the first full intermediate chunk appends");
    executor
        .append_object_bytes(&mut storage, object, &[5, 6, 7, 8])
        .expect("the second full intermediate chunk appends");
    executor
        .append_object_bytes(&mut storage, object, &[9, 10])
        .expect("the exact declared tail appends");
    executor
        .seal_object(&mut storage, object)
        .expect("the canonically chunked object seals");

    assert_eq!(
        storage
            .committed
            .get(&object)
            .map(|entry| entry.bytes.as_slice()),
        Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..]),
    );
}

#[test]
fn executor_rejects_zero_short_and_oversized_appends_without_advancing() {
    let object = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 6))
        .expect("the hostile-shape executor starts");
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, object)
        .expect("the object begins");
    let transaction_count_after_create = executor.usage().transaction_count;

    for rejected_bytes in [&[][..], &[1, 2, 3][..], &[1, 2, 3, 4, 5][..]] {
        assert_eq!(
            executor.append_object_bytes(&mut storage, object, rejected_bytes),
            Err(ProofExternalMemoryExecutorError::Execution(
                ProofExternalMemoryError::WrongOffsetOrLength,
            )),
        );
        assert_eq!(
            storage
                .committed
                .get(&object)
                .map(|entry| entry.bytes.len()),
            Some(0),
        );
        assert_eq!(
            executor.usage().transaction_count,
            transaction_count_after_create,
        );
    }

    executor
        .append_object_bytes(&mut storage, object, &[1, 2, 3, 4])
        .expect("the exact intermediate chunk still appends after refusals");
    let transaction_count_after_intermediate_chunk = executor.usage().transaction_count;
    assert_eq!(
        executor.append_object_bytes(&mut storage, object, &[5]),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::WrongOffsetOrLength,
        )),
        "a one-byte-short tail is rejected",
    );
    assert_eq!(
        storage
            .committed
            .get(&object)
            .map(|entry| entry.bytes.as_slice()),
        Some(&[1, 2, 3, 4][..]),
    );
    assert_eq!(
        executor.usage().transaction_count,
        transaction_count_after_intermediate_chunk,
    );
    executor
        .append_object_bytes(&mut storage, object, &[5, 6])
        .expect("the exact tail still appends after refusal");
}

#[test]
fn executor_accepts_a_short_object_as_one_exact_chunk() {
    let object = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 3))
        .expect("the one-chunk executor starts");
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, object)
        .expect("the short object begins");
    assert_eq!(
        executor.append_object_bytes(&mut storage, object, &[1, 2]),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::WrongOffsetOrLength,
        )),
        "a one-byte-short one-chunk object is rejected",
    );
    executor
        .append_object_bytes(&mut storage, object, &[1, 2, 3])
        .expect("the complete one-chunk object appends");
    executor
        .seal_object(&mut storage, object)
        .expect("the complete one-chunk object seals");
}

#[test]
fn plan_and_executor_reject_overrun_incomplete_seal_and_late_use() {
    assert_eq!(
        ProofExternalMemoryPlan::new(
            1,
            8,
            4,
            1,
            8,
            8,
            8,
            8,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::PublicIntegrity,
                8,
                0,
                0,
                0,
            )],
        ),
        Err(ProofExternalMemoryError::InvalidPlan),
    );

    let first = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, first)
        .expect("first starts");
    executor
        .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
        .expect("partial write succeeds");
    assert!(matches!(
        executor.complete_step(&mut storage),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::Incomplete
        )),
    ));
    assert!(matches!(
        executor.append_object_bytes(&mut storage, first, &[0; 5]),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::WrongOffsetOrLength
        )),
    ));
}

#[test]
fn plan_validation_work_is_bounded_by_object_count_not_step_count() {
    let plan = ProofExternalMemoryPlan::new(
        u32::MAX,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        vec![ProofExternalMemoryObjectPlan::new(
            ProofExternalMemoryObject::new(0),
            ProofExternalMemoryProtection::PublicIntegrity,
            1,
            0,
            0,
            u32::MAX - 1,
        )],
    )
    .expect("large step identifiers do not expand validation work");
    assert_eq!(plan.step_count(), u32::MAX);
}

#[test]
fn browser_scratch_plan_accepts_exact_object_and_byte_ceilings_and_refuses_one_over() {
    assert_eq!(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT, 4_096);
    assert_eq!(
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        268_435_456
    );
    let exact_object_count = u32::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
        .expect("the fixed object ceiling fits u32");
    let exact_object_plan = (0..exact_object_count)
        .map(|object_ordinal| {
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(object_ordinal),
                ProofExternalMemoryProtection::PublicIntegrity,
                1,
                0,
                0,
                0,
            )
        })
        .collect::<Vec<_>>();
    ProofExternalMemoryPlan::new(
        1,
        1,
        1,
        exact_object_count,
        u64::from(exact_object_count),
        u64::from(exact_object_count),
        1,
        1,
        exact_object_plan,
    )
    .expect("the exact browser object ceiling is accepted");

    let one_over_object_count = exact_object_count + 1;
    let one_over_object_plan = (0..one_over_object_count)
        .map(|object_ordinal| {
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(object_ordinal),
                ProofExternalMemoryProtection::PublicIntegrity,
                1,
                0,
                0,
                0,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ProofExternalMemoryPlan::new(
            1,
            1,
            1,
            one_over_object_count,
            u64::from(one_over_object_count),
            u64::from(one_over_object_count),
            1,
            1,
            one_over_object_plan,
        ),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
    );

    assert_eq!(
        ProofExternalMemoryPlan::new(
            1,
            1,
            1,
            one_over_object_count,
            1,
            1,
            1,
            1,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::PublicIntegrity,
                1,
                0,
                0,
                0,
            )],
        ),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
        "a caller cannot raise the per-transaction operation ceiling",
    );

    let plan_at_byte_ceiling = |stored_byte_length| {
        ProofExternalMemoryPlan::new(
            1,
            1,
            1,
            1,
            stored_byte_length,
            stored_byte_length,
            1,
            1,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                stored_byte_length,
                0,
                0,
                0,
            )],
        )
    };
    plan_at_byte_ceiling(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH)
        .expect("the exact browser scratch-byte ceiling is accepted");
    assert_eq!(
        plan_at_byte_ceiling(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH + 1),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
    );
}

#[test]
fn browser_transaction_yield_and_exact_replay_change_state_only_after_replay() {
    let first = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
    let mut recorder = ProofExternalMemoryTransactionRecorder::new();

    assert_eq!(
        executor.begin_object(&mut recorder, first),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    assert_eq!(executor.usage().transaction_count, 0);
    let request = recorder
        .take_yielded_request()
        .expect("create transaction yielded");
    assert_eq!(
        request.operations(),
        &[ProofExternalMemoryTransactionOperation::Create {
            object: first,
            protection: ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            exact_byte_length: 8,
        }]
    );
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("create response has no reads");
    executor
        .begin_object(&mut replay, first)
        .expect("successful IndexedDB create replays");
    assert_eq!(executor.usage().transaction_count, 1);

    assert_eq!(
        executor.append_object_bytes(&mut recorder, first, &[1, 2, 3, 4]),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    let request = recorder
        .take_yielded_request()
        .expect("append transaction yielded");
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("append response has no reads");
    executor
        .append_object_bytes(&mut replay, first, &[1, 2, 3, 4])
        .expect("successful IndexedDB append replays");

    assert_eq!(
        executor.append_object_bytes(&mut recorder, first, &[5, 6, 7, 8]),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    let request = recorder
        .take_yielded_request()
        .expect("second append transaction yielded");
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("second append response has no reads");
    executor
        .append_object_bytes(&mut replay, first, &[5, 6, 7, 8])
        .expect("successful second IndexedDB append replays");

    assert_eq!(
        executor.seal_object(&mut recorder, first),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    let request = recorder
        .take_yielded_request()
        .expect("seal transaction yielded");
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("seal response has no reads");
    executor
        .seal_object(&mut replay, first)
        .expect("successful IndexedDB seal replays");
    executor
        .complete_step(&mut recorder)
        .expect("first liveness step has no deletion");

    let mut destination = [0_u8; 4];
    assert_eq!(
        executor.read_object_bytes(&mut recorder, first, 0, &mut destination),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    assert_eq!(destination, [0; 4]);
    let request = recorder
        .take_yielded_request()
        .expect("read transaction yielded");
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, vec![vec![1, 2, 3, 4]])
        .expect("read response has the exact requested length");
    executor
        .read_object_bytes(&mut replay, first, 0, &mut destination)
        .expect("successful IndexedDB read replays");
    assert_eq!(destination, [1, 2, 3, 4]);
}

fn record_worker_response_test_request(
    recorder: &mut ProofExternalMemoryTransactionRecorder,
) -> ProofExternalMemoryTransactionRequest {
    let append_object = ProofExternalMemoryObject::new(2);
    let first_read_object = ProofExternalMemoryObject::new(7);
    let second_read_object = ProofExternalMemoryObject::new(9);
    recorder
        .begin_transaction(64, 4)
        .expect("worker response transaction starts");
    recorder
        .append_object_bytes(append_object, 0, &[9, 8, 7])
        .expect("worker response append records");
    let mut first_read = [0_u8; 4];
    recorder
        .read_object_bytes(first_read_object, 3, &mut first_read)
        .expect("first worker response read records");
    recorder
        .seal_object(append_object)
        .expect("worker response seal records");
    let mut second_read = [0_u8; 3];
    recorder
        .read_object_bytes(second_read_object, 11, &mut second_read)
        .expect("second worker response read records");
    assert_eq!(
        recorder.commit_transaction(),
        Err(ProofExternalMemoryTransactionAdapterError::Yielded),
    );
    recorder
        .take_yielded_request()
        .expect("worker response request yielded")
}

fn encode_worker_test_response(
    request: &ProofExternalMemoryTransactionRequest,
    ordered_results: &[(u32, ProofExternalMemoryObject, u64, &[u8])],
) -> Vec<u8> {
    let operation_bytes = request
        .encode_operation_bytes()
        .expect("test request operations encode");
    let request_digest = request
        .request_digest(&operation_bytes)
        .expect("test request digest derives");
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND.to_le_bytes());
    encoded.extend_from_slice(&request.request_sequence().to_le_bytes());
    encoded.extend_from_slice(&request_digest);
    encoded.extend_from_slice(
        &u32::try_from(ordered_results.len())
            .expect("test response result count fits u32")
            .to_le_bytes(),
    );
    for (operation_index, object, offset, bytes) in ordered_results {
        encoded.extend_from_slice(&operation_index.to_le_bytes());
        encoded.extend_from_slice(&object.ordinal().to_le_bytes());
        encoded.extend_from_slice(&offset.to_le_bytes());
        encoded.extend_from_slice(
            &u32::try_from(bytes.len())
                .expect("test response byte length fits u32")
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&0_u32.to_le_bytes());
        encoded.extend_from_slice(&external_memory_read_digest(
            &request_digest,
            *operation_index,
            *object,
            *offset,
            bytes,
        ));
        encoded.extend_from_slice(bytes);
    }
    encoded
}

#[test]
fn worker_response_decoder_binds_sequence_operation_object_range_and_digest() {
    let mut recorder = ProofExternalMemoryTransactionRecorder::for_runtime_binding([0x41; 64], 7);
    let request = record_worker_response_test_request(&mut recorder);
    let first_read_object = ProofExternalMemoryObject::new(7);
    let second_read_object = ProofExternalMemoryObject::new(9);
    let ordered_results = [
        (1, first_read_object, 3, &[1, 2, 3, 4][..]),
        (3, second_read_object, 11, &[5, 6, 7][..]),
    ];
    let valid_response = encode_worker_test_response(&request, &ordered_results);
    assert_eq!(
        request
            .decode_worker_response(&valid_response)
            .expect("exact worker response decodes"),
        vec![vec![1, 2, 3, 4], vec![5, 6, 7]],
    );

    let mut wrong_sequence = valid_response.clone();
    wrong_sequence[4] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_sequence),
        Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
    );

    let mut wrong_request_digest = valid_response.clone();
    wrong_request_digest[12] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_request_digest),
        Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
    );

    let first_result_offset = EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH;
    let mut wrong_operation_ordinal = valid_response.clone();
    wrong_operation_ordinal[first_result_offset] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_operation_ordinal),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let mut wrong_object = valid_response.clone();
    wrong_object[first_result_offset + 4] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_object),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let mut wrong_range = valid_response.clone();
    wrong_range[first_result_offset + 8] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_range),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let mut wrong_read_digest = valid_response.clone();
    wrong_read_digest[first_result_offset + 24] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_read_digest),
        Err(ProofExternalMemoryTransactionAdapterError::WrongReadDigest),
    );

    let reordered_response = encode_worker_test_response(
        &request,
        &[
            (3, second_read_object, 11, &[5, 6, 7]),
            (1, first_read_object, 3, &[1, 2, 3, 4]),
        ],
    );
    assert_eq!(
        request.decode_worker_response(&reordered_response),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let next_request = record_worker_response_test_request(&mut recorder);
    assert_eq!(next_request.request_sequence(), 8);
    assert_eq!(
        next_request.decode_worker_response(&valid_response),
        Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
    );
}

#[test]
fn browser_transaction_boundary_enforces_both_resource_ceilings_and_redacts_payloads() {
    let object = ProofExternalMemoryObject::new(7);
    let mut recorder = ProofExternalMemoryTransactionRecorder::new();
    recorder
        .begin_transaction(4, 1)
        .expect("bounded transaction starts");
    recorder
        .append_object_bytes(object, 0, &[0x11, 0x22, 0x33, 0x44])
        .expect("payload at the exact ceiling is accepted");
    assert_eq!(
        recorder.seal_object(object),
        Err(ProofExternalMemoryTransactionAdapterError::OperationCountExceeded),
    );
    recorder
        .abort_transaction()
        .expect("rejected transaction aborts");

    recorder
        .begin_transaction(3, 2)
        .expect("second bounded transaction starts");
    assert_eq!(
        recorder.append_object_bytes(object, 0, &[0x11, 0x22, 0x33, 0x44]),
        Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded),
    );
    recorder
        .abort_transaction()
        .expect("overlong payload transaction aborts");

    recorder
        .begin_transaction(3, 1)
        .expect("bounded read transaction starts");
    let mut oversized_read = [0xff; 4];
    assert_eq!(
        recorder.read_object_bytes(object, 0, &mut oversized_read),
        Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded),
    );
    assert_eq!(oversized_read, [0; 4]);
    recorder
        .abort_transaction()
        .expect("overlong read transaction aborts");

    let operation = ProofExternalMemoryTransactionOperation::Append {
        object,
        expected_offset: 0,
        bytes: Zeroizing::new(vec![0xde, 0xad, 0xbe, 0xef]),
    };
    let debug_output = format!("{operation:?}");
    assert!(debug_output.contains("[REDACTED]"));
    assert!(debug_output.contains("byte_length: 4"));
}

struct RequestedCancellation;

impl ProofCancellation for RequestedCancellation {
    fn cancellation_requested(&self) -> bool {
        true
    }
}

#[test]
fn cancellation_transactionally_removes_secret_scratch() {
    let first = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, first)
        .expect("first starts");
    executor
        .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
        .expect("partial secret scratch writes");
    assert!(matches!(
        executor.check_cancellation(&mut storage, &RequestedCancellation),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::Cancelled
        )),
    ));
    assert!(storage.committed.is_empty());
}
