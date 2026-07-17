use super::*;

pub(super) fn prepared_generation_worker_fixture_for_checkpoint(
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

pub(super) fn capture_first_generation_checkpoint() -> (Vec<u8>, Vec<Vec<u8>>, [u8; 64], Vec<u8>) {
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
    .expect("the compact fixture fits the resident-memory safety bound");
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
