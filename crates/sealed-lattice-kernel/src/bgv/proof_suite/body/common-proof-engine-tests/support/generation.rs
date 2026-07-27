use super::*;

pub(super) fn prepared_generation_worker_fixture_for_checkpoint(
    authenticated_checkpoint_state: Option<&[u8]>,
    checkpoint_source_lineage_delta: u64,
) -> Result<(PreparedCommonProofGeneration, Vec<u8>), CommonProofRuntimeError> {
    prepared_generation_worker_fixture_for_public_family(
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        authenticated_checkpoint_state,
        checkpoint_source_lineage_delta,
    )
}

fn prepared_generation_worker_fixture_for_public_family(
    family_schema_identifier: u16,
    authenticated_checkpoint_state: Option<&[u8]>,
    checkpoint_source_lineage_delta: u64,
) -> Result<(PreparedCommonProofGeneration, Vec<u8>), CommonProofRuntimeError> {
    let mut fixture = common_proof_engine_fixture_for_public_family(family_schema_identifier);
    let expected_proof_bytes = generate_fixture_proof(&mut fixture);
    let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
        fixture.canonical_application_statement_bytes.clone(),
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.proof_header_hash())
    .expect("the genuine fixture statement has one canonical proof header");
    let relation_plan = CommonProofRelationPlanCapability::from_checked_fixture_plan(
        &fixture.relation_plan,
        &fixture.relation_context,
        fixture.schedule_position,
        fixture.top_count,
    )
    .expect("the genuine fixture relation plan is checked");
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes([0x11; 64]),
        Hash512::from_bytes([0x83; 64]),
        Hash512::from_bytes([0x84; 64]),
        family_schema_identifier,
        None,
        fixture.schedule_position,
        None,
    )
    .expect("the aggregate proof application has one exact slot");
    let generation_authorization =
        CommonProofGenerationAuthorization::from_genuine_test_application(
            1,
            application_slot,
            verified_application_statement_hash(
                1,
                [0x11; 64],
                family_schema_identifier,
                &fixture.canonical_application_statement_bytes,
            ),
            proof_header_hash.into_bytes(),
            relation_plan.relation_plan_hash(),
            relation_plan.row_code_whir_construction_plan_identity_hash(),
        )
        .expect("the genuine generation fixture has one pre-output authorization");
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
    let state =
        CommonProofGenerationStateMachine::new_for_checked_fixture(CommonProofGenerationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
            relation_plan: &fixture.relation_plan,
            relation_context: &fixture.relation_context,
            schedule_position: fixture.schedule_position,
            top_count: fixture.top_count,
            relation_trees: fixture.relation_trees,
            source_polynomial_provider: Box::new(ResidentCommonProofSourcePolynomialProvider::new(
                fixture.provided_columns,
            )),
            maximum_external_memory_chunk_byte_length:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: limits.prefetched_query_byte_length(),
        })
        .expect("the genuine generation state owns the checked relation inputs");
    let mut source_attempt_lineage = [0x52_u8; 32];
    source_attempt_lineage[31] = source_attempt_lineage[31].wrapping_add(
        u8::try_from(checkpoint_source_lineage_delta)
            .expect("the test source-lineage delta fits u8"),
    );
    let sources = CommonProofGenerationSources::new(
        PublicOnlyCommonProofCoinSource::new(
            family_schema_identifier,
            Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]),
            source_attempt_lineage,
        )
        .expect("the public aggregate worker fixture has no private proof-coin domain"),
        ResidentCommonProofSourcePolynomialProvider::new(BTreeMap::new()),
    );
    let prepared = match authenticated_checkpoint_state {
        Some(checkpoint_state_bytes) => {
            PreparedCommonProofGeneration::from_genuine_test_sources_for_authenticated_checkpoint(
                generation_authorization,
                relation_plan,
                state,
                sources,
                limits,
                checkpoint_state_bytes,
            )?
        }
        None => PreparedCommonProofGeneration::from_genuine_test_sources(
            generation_authorization,
            relation_plan,
            state,
            sources,
            limits,
        ),
    };
    Ok((prepared, expected_proof_bytes))
}

fn common_proof_engine_fixture_for_public_family(
    family_schema_identifier: u16,
) -> CommonProofEngineFixture {
    match family_schema_identifier {
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER => common_proof_engine_fixture(),
        RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            let context = relation_context();
            let relation_plan = compile_rkg_round_one_aggregate_relation_plan(
                &RkgRoundOneAggregatePlanInput {
                    geometry: public_aggregate_geometry(),
                    ordered_variants: vec![RkgRoundOneAggregateVariantInput {
                        schedule_position: 7,
                        ordered_left_component_moduli: vec![SuiteModulusReference::data(0)],
                        ordered_right_component_moduli: vec![SuiteModulusReference::data(0)],
                    }],
                },
                &context,
            )
            .expect("the round-one aggregate relation compiles");
            public_aggregate_common_proof_fixture(
                context,
                relation_plan,
                &[7, 11, 18, 13, 17, 30],
                canonical_rkg_round_one_aggregate_statement,
                Some(7),
                None,
            )
        }
        EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            let context = relation_context();
            let relation_plan = compile_evaluator_key_aggregate_relation_plan(
                &EvaluatorKeyAggregatePlanInput {
                    geometry: public_aggregate_geometry(),
                    ordered_variants: (1..=FOUNDATION_PROFILE.option_count)
                        .map(|top_count| EvaluatorKeyAggregateVariantInput {
                            top_count,
                            ordered_entries: vec![EvaluatorKeyAggregateEntryPlanInput {
                                schedule_position: 3,
                                ordered_runtime_component_moduli: vec![
                                    SuiteModulusReference::data(0),
                                ],
                            }],
                        })
                        .collect(),
                },
                &context,
            )
            .expect("the evaluator aggregate relation compiles");
            public_aggregate_common_proof_fixture(
                context,
                relation_plan,
                &[5, 9, 14],
                canonical_evaluator_key_aggregate_statement,
                None,
                Some(FOUNDATION_PROFILE.option_count),
            )
        }
        _ => panic!("the generation worker fixture requires a public-only proof family"),
    }
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

fn export_pending_generation_storage_request(
    registry: &mut CommonProofRuntimeRegistry,
    operation: CommonProofGenerationOperationHandle,
) {
    let encoded_byte_length = registry
        .generation_storage_request_byte_length(operation)
        .expect("the pending generation storage request has one canonical byte length");
    let mut encoded_request = vec![0_u8; encoded_byte_length];
    registry
        .encode_generation_storage_request_into(operation, &mut encoded_request)
        .expect("the pending generation storage request exports canonically");
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
                export_pending_generation_storage_request(registry, operation);
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the exact storage response replays the Rust transaction");
            }
            CommonProofGenerationWorkerPoll::AuthenticatedSourceReadReady { .. } => {
                panic!("the resident generation fixture cannot request an authenticated source")
            }
            CommonProofGenerationWorkerPoll::AuthenticatedTranscriptPrefixRequired => {
                panic!(
                    "the public-only generation fixture cannot request exact transcript authority"
                )
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

pub(super) fn capture_first_generation_checkpoint() -> (Vec<u8>, Vec<u8>, [u8; 64], Vec<u8>) {
    capture_first_generation_checkpoint_for_public_family(APPLICATION_STATEMENT_SCHEMA_IDENTIFIER)
}

fn capture_first_generation_checkpoint_for_public_family(
    family_schema_identifier: u16,
) -> (Vec<u8>, Vec<u8>, [u8; 64], Vec<u8>) {
    let (prepared, expected_proof_bytes) =
        prepared_generation_worker_fixture_for_public_family(family_schema_identifier, None, 0)
            .expect("the fresh public-only generation fixture starts at checkpoint genesis");
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
                let cursor_manifest_bytes = registry
                    .generation_checkpoint_cursor_manifest(operation)
                    .expect("the checkpoint exposes one compact cursor manifest")
                    .to_vec();
                let stable_attempt_binding_hash = registry
                    .generation_checkpoint_stable_attempt_binding_hash(operation)
                    .expect("the checkpoint exposes its stable attempt binding");
                assert_eq!(
                    registry
                        .generation_checkpoint_safe_boundary_ordinal(operation)
                        .expect("the checkpoint boundary ordinal is available"),
                    0,
                );
                registry
                    .retire_failed_generation(operation)
                    .expect("a lost checkpoint response permanently retires the old operation");
                return (
                    checkpoint_state,
                    cursor_manifest_bytes,
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
                export_pending_generation_storage_request(&mut registry, operation);
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the prefix transaction response replays exactly");
            }
            unexpected => panic!("generation reached {unexpected:?} before its first checkpoint"),
        }
    }
}

#[test]
fn owned_generation_worker_replays_resumable_append_for_final_partial_and_authenticates_every_output_chunk()
 {
    let (prepared, expected_proof_bytes) = prepared_generation_worker_fixture();
    let canonical_external_memory_chunk_byte_length =
        usize::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            .expect("the canonical external-memory chunk length fits usize");
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .begin_owned_generation(prepared)
        .expect("the opaque genuine generation source starts");
    let mut browser_storage =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let mut output_chunks = BTreeMap::<usize, Vec<u8>>::new();
    let mut observed_checkpoint_boundary = false;
    let mut observed_partial_append = false;

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
                    observed_partial_append |= request.operations().iter().any(|operation| {
                        matches!(
                            operation,
                            ProofExternalMemoryTransactionOperation::Append { bytes, .. }
                                if !bytes.is_empty()
                                    && bytes.len() < canonical_external_memory_chunk_byte_length
                        )
                    });
                    execute_generation_storage_request(request, &mut browser_storage)
                };
                export_pending_generation_storage_request(&mut registry, operation);
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the exact response changes recording into replay");
            }
            CommonProofGenerationWorkerPoll::AuthenticatedSourceReadReady { .. } => {
                panic!("the resident generation fixture cannot request an authenticated source")
            }
            CommonProofGenerationWorkerPoll::AuthenticatedTranscriptPrefixRequired => {
                panic!(
                    "the public-only generation fixture cannot request exact transcript authority"
                )
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
    assert!(
        observed_partial_append,
        "the real worker must replay at least one final partial append",
    );
    let generated_capability = registry
        .finish_owned_generation(operation)
        .expect("only the cryptographic terminal state mints generation authority");
    registry
        .release_generated_proof(generated_capability)
        .expect("the opaque generated capability is linear");
}

#[test]
fn owned_generation_worker_replays_every_public_family_from_zero_with_byte_identical_output() {
    for family_schema_identifier in
        ProofApplicationSlotCeilings::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS
    {
        let (
            authenticated_checkpoint_state,
            generation_cursor_manifest_bytes,
            stable_attempt_binding_hash,
            expected_proof_bytes,
        ) = capture_first_generation_checkpoint_for_public_family(family_schema_identifier);
        assert_ne!(stable_attempt_binding_hash, [0_u8; 64]);
        let (prepared, independently_generated_proof_bytes) =
            prepared_generation_worker_fixture_for_public_family(
                family_schema_identifier,
                Some(&authenticated_checkpoint_state),
                0,
            )
            .expect("authenticated checkpoint coordinates prepare the same exact attempt");
        assert_eq!(prepared.runtime_binding_hash(), stable_attempt_binding_hash);
        assert_eq!(independently_generated_proof_bytes, expected_proof_bytes);
        let mut registry = CommonProofRuntimeRegistry::default();
        let operation = registry
            .resume_owned_generation(
                prepared,
                &authenticated_checkpoint_state,
                &generation_cursor_manifest_bytes,
            )
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
}

#[test]
fn owned_generation_worker_rejects_changed_checkpoint_bindings_and_replayed_state() {
    let (authenticated_checkpoint_state, generation_cursor_manifest_bytes, _, _) =
        capture_first_generation_checkpoint();

    for changed_offset in [12_usize, 108] {
        let (prepared, _) = prepared_generation_worker_fixture_for_checkpoint(
            Some(&authenticated_checkpoint_state),
            0,
        )
        .expect("the genuine checkpoint prepares the expected attempt binding");
        let mut changed_state = authenticated_checkpoint_state.clone();
        changed_state[changed_offset] ^= 1;
        let error = CommonProofRuntimeRegistry::default()
            .resume_owned_generation(prepared, &changed_state, &generation_cursor_manifest_bytes)
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
        .resume_owned_generation(prepared, &[], &generation_cursor_manifest_bytes)
        .expect_err("missing checkpoint state permanently prevents replay");
    assert!(matches!(
        missing_state_error,
        CommonProofGenerationWorkerError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding
        )
    ));

    let (prepared, _) =
        prepared_generation_worker_fixture_for_checkpoint(Some(&authenticated_checkpoint_state), 0)
            .expect("the genuine checkpoint prepares the expected replay target");
    let missing_manifest_error = CommonProofRuntimeRegistry::default()
        .resume_owned_generation(prepared, &authenticated_checkpoint_state, &[])
        .expect_err("missing cursor manifest permanently prevents replay");
    assert!(matches!(
        missing_manifest_error,
        CommonProofGenerationWorkerError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding
        )
    ));

    let mut changed_generation_cursor_manifest_bytes = generation_cursor_manifest_bytes.clone();
    let changed_manifest_offset = changed_generation_cursor_manifest_bytes
        .len()
        .checked_sub(1)
        .expect("the authenticated generation cursor manifest is nonempty");
    changed_generation_cursor_manifest_bytes[changed_manifest_offset] ^= 1;
    let (prepared, _) =
        prepared_generation_worker_fixture_for_checkpoint(Some(&authenticated_checkpoint_state), 0)
            .expect("the genuine checkpoint prepares the expected replay target");
    let changed_manifest_error = CommonProofRuntimeRegistry::default()
        .resume_owned_generation(
            prepared,
            &authenticated_checkpoint_state,
            &changed_generation_cursor_manifest_bytes,
        )
        .expect_err("a changed cursor manifest cannot authenticate against the checkpoint state");
    assert!(matches!(
        changed_manifest_error,
        CommonProofGenerationWorkerError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding
        )
    ));

    let mut changed_committed_state = authenticated_checkpoint_state.clone();
    changed_committed_state[264] ^= 1;
    for (bound_checkpoint_state, replay_target, source_lineage_delta) in [
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
            source_lineage_delta,
        )
        .expect("the authenticated checkpoint prepares a replay attempt");
        let mut registry = CommonProofRuntimeRegistry::default();
        let operation = registry
            .resume_owned_generation(prepared, &replay_target, &generation_cursor_manifest_bytes)
            .expect("hostile committed-state or source-lineage input reaches deterministic replay");
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
                    export_pending_generation_storage_request(&mut registry, operation);
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
fn owned_generation_worker_replays_resumable_append_for_final_partial_before_cancellation_cleanup()
{
    let (prepared, _) = prepared_generation_worker_fixture();
    let canonical_external_memory_chunk_byte_length =
        usize::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            .expect("the canonical external-memory chunk length fits usize");
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
            CommonProofGenerationWorkerPoll::StorageRequestReady { .. } => {
                let request_contains_partial_append = registry
                    .generation_storage_transaction_request(operation)
                    .expect("one exact storage request is pending")
                    .operations()
                    .iter()
                    .any(|operation| {
                        matches!(
                            operation,
                            ProofExternalMemoryTransactionOperation::Append { bytes, .. }
                                if !bytes.is_empty()
                                    && bytes.len() < canonical_external_memory_chunk_byte_length
                        )
                    });
                if request_contains_partial_append {
                    break;
                }
                let response = {
                    let request = registry
                        .generation_storage_transaction_request(operation)
                        .expect("the non-append prefix request remains pending");
                    execute_generation_storage_request(request, &mut browser_storage)
                };
                export_pending_generation_storage_request(&mut registry, operation);
                registry
                    .supply_generation_storage_response(operation, &response)
                    .expect("the exact prefix response enables deterministic replay");
            }
            unexpected => {
                panic!("generation yielded {unexpected:?} before its first partial append")
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
            .expect("the original partial append transaction remains pending");
        execute_generation_storage_request(request, &mut browser_storage)
    };
    export_pending_generation_storage_request(&mut registry, operation);
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
                export_pending_generation_storage_request(&mut registry, operation);
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
fn constraint_stream_quotient_is_byte_identical_to_the_whole_matrix_oracle() {
    let fixture = common_proof_engine_fixture();
    let variant = fixture
        .relation_plan
        .select_variant(fixture.schedule_position, fixture.top_count)
        .expect("the aggregate fixture variant exists");
    let mut columns = (0..variant.ordered_columns().len())
        .map(|column_index| {
            fixture
                .provided_columns
                .get(&u32::try_from(column_index).expect("the column ordinal fits u32"))
                .cloned()
                .expect("the aggregate fixture provides every source column")
        })
        .collect::<Vec<_>>();
    columns[2] = CommonProofSourcePolynomial::from_base_coefficients(vec![
        ProofBaseFieldElement::from_canonical(19).expect("the mutated value is canonical"),
    ]);
    let evaluation_domain = ProofEvaluationDomain::new(
        usize::try_from(variant.evaluation_domain_size())
            .expect("the fixture evaluation domain fits usize"),
        fixture.relation_context.evaluation_coset_offset,
    )
    .expect("the fixture evaluation domain is valid");
    let composition_challenges = (0..variant.constraint_count())
        .map(|constraint_ordinal| {
            ProofChallengeExtensionElement::from_base(
                ProofBaseFieldElement::from_canonical(
                    u64::try_from(constraint_ordinal).expect("the constraint ordinal fits u64") + 2,
                )
                .expect("the composition challenge is canonical"),
            )
        })
        .collect::<Vec<_>>();
    let whole_matrix = construct_composed_quotient_polynomial(
        variant,
        &fixture.relation_context,
        evaluation_domain,
        &columns,
        &[],
        &composition_challenges,
    )
    .expect("the whole-matrix quotient oracle accepts the mutated witness");
    let constraint_stream = construct_constraint_stream_composed_quotient_polynomial(
        variant,
        &fixture.relation_context,
        evaluation_domain,
        &columns,
        &[],
        &composition_challenges,
    )
    .expect("the constraint-stream quotient oracle accepts the mutated witness");
    assert!(
        whole_matrix
            .iter()
            .any(|coefficient| *coefficient != ProofChallengeExtensionElement::ZERO),
        "the deliberately inconsistent aggregate exercises a nonzero quotient",
    );
    let canonical_bytes = |polynomial: &[ProofChallengeExtensionElement]| {
        polynomial
            .iter()
            .flat_map(|coefficient| coefficient.canonical_coordinates())
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        canonical_bytes(&constraint_stream),
        canonical_bytes(&whole_matrix)
    );
}

#[test]
fn generation_state_enforces_reports_and_releases_its_complete_resident_live_set() {
    let fixture = common_proof_engine_fixture();
    let mut state =
        CommonProofGenerationStateMachine::new_for_checked_fixture(CommonProofGenerationInput {
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
        })
        .expect("the compact fixture fits the resident-memory safety bound");
    let resident_memory_plan = state.resident_memory_plan();
    assert_eq!(resident_memory_plan.phases().len(), 14);
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

    let loading_source_polynomials = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials)
        .expect("the source-polynomial construction phase is explicit");
    let infrastructure = loading_source_polynomials.infrastructure_payload_accounting();
    assert!(infrastructure.state_machine_inline_byte_length() > 0);
    assert!(infrastructure.canonical_header_payload_byte_length() > 0);
    assert!(infrastructure.relation_plan_catalog_payload_byte_length() > 0);
    assert!(infrastructure.relation_context_catalog_payload_byte_length() > 0);
    assert!(infrastructure.proof_tree_catalog_payload_byte_length() > 0);
    assert!(infrastructure.storage_plan_catalog_payload_byte_length() > 0);
    assert!(infrastructure.executor_catalog_payload_byte_length() > 0);
    assert!(infrastructure.generation_catalog_payload_byte_length() > 0);
    assert!(infrastructure.resident_phase_catalog_payload_byte_length() > 0);
    assert!(infrastructure.transcript_persistent_payload_byte_length() > 0);
    assert!(infrastructure.transcript_transient_payload_byte_length() > 0);
    assert_eq!(
        infrastructure.total_byte_length(),
        infrastructure
            .state_machine_inline_byte_length()
            .checked_add(infrastructure.canonical_header_payload_byte_length())
            .and_then(|total| {
                total.checked_add(infrastructure.relation_plan_catalog_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.relation_context_catalog_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.proof_tree_catalog_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.storage_plan_catalog_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.executor_catalog_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.generation_catalog_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.resident_phase_catalog_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.transcript_persistent_payload_byte_length())
            })
            .and_then(|total| {
                total.checked_add(infrastructure.transcript_transient_payload_byte_length())
            })
            .expect("the named infrastructure payload sum fits u64"),
    );
    assert!(
        resident_memory_plan
            .phases()
            .iter()
            .all(|phase| { phase.infrastructure_payload_accounting() == infrastructure })
    );
    assert!(loading_source_polynomials.relation_polynomial_working_set_byte_length() > 0);

    let deriving_auxiliary_columns = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns)
        .expect("the descriptor-local auxiliary-column phase is explicit");
    assert!(deriving_auxiliary_columns.relation_polynomial_working_set_byte_length() > 0);
    assert_eq!(
        deriving_auxiliary_columns.auxiliary_trace_workspace_byte_length(),
        0,
        "the maskless public-aggregate fixture has no auxiliary trace columns",
    );

    let constructing_quotient = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::ConstructingQuotient)
        .expect("the quotient constraint-stream phase is explicit");
    assert!(
        constructing_quotient.replay_polynomial_byte_length() > 0,
        "compact setup root-pass records remain live until query emission",
    );
    assert!(constructing_quotient.primary_vector_byte_length() > 0);
    assert_eq!(constructing_quotient.secondary_vector_byte_length(), 0);
    assert!(constructing_quotient.relation_rotation_block_byte_length() > 0);
    assert!(constructing_quotient.external_working_set_byte_length() > 0);
    assert!(constructing_quotient.external_transaction_overlap_peak_byte_length() > 0);
    assert!(
        constructing_quotient.subphase_transient_peak_byte_length()
            >= constructing_quotient.relation_rotation_block_byte_length()
    );
    assert!(
        constructing_quotient.subphase_transient_peak_byte_length()
            >= constructing_quotient
                .external_working_set_byte_length()
                .max(constructing_quotient.external_transaction_overlap_peak_byte_length())
    );

    let transforming_auxiliary_columns = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::TransformingAuxiliaryColumns)
        .expect("the auxiliary-column transform phase is explicit");
    let external_memory_chunk_byte_length =
        u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
    let extension_value_byte_length = u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
        .expect("the extension degree fits u64")
        .checked_mul(
            u64::try_from(core::mem::size_of::<u64>()).expect("the limb byte length fits u64"),
        )
        .expect("the extension value byte length fits u64");
    let base_value_byte_length =
        u64::try_from(core::mem::size_of::<u64>()).expect("the base value byte length fits u64");
    let aligned_extension_scan_byte_length = external_memory_chunk_byte_length
        .checked_div(extension_value_byte_length)
        .expect("the extension value byte length is nonzero")
        .checked_mul(extension_value_byte_length)
        .expect("the aligned scan byte length fits u64");
    let stockham_working_set_byte_length = aligned_extension_scan_byte_length
        .checked_mul(4)
        .and_then(|byte_length| byte_length.checked_add(external_memory_chunk_byte_length))
        .expect("the Stockham working set byte length fits u64");
    let replay_writer_working_set_byte_length = external_memory_chunk_byte_length
        .checked_add(base_value_byte_length)
        .expect("the replay writer working set byte length fits u64");
    assert!(
        transforming_auxiliary_columns.external_working_set_byte_length()
            >= stockham_working_set_byte_length,
        "the auxiliary transform live set includes its Stockham buffers",
    );
    assert!(
        transforming_auxiliary_columns.external_transaction_overlap_peak_byte_length()
            > transforming_auxiliary_columns.external_working_set_byte_length(),
        "the auxiliary transform live set includes request encoding and replay copies",
    );
    assert!(
        loading_source_polynomials.external_working_set_byte_length()
            >= replay_writer_working_set_byte_length,
        "the source-polynomial live set includes its replay-writer buffers",
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
    assert!(emitting_queries.query_prefetch_byte_length() > 0);
    assert!(
        emitting_queries.query_prefetch_byte_length() < MAXIMUM_PROOF_BYTE_LENGTH as u64,
        "the resident plan charges retained query allocations, not the caller's upper cap",
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
fn generation_state_rejects_a_noncanonical_transport_chunk_before_proving() {
    let fixture = common_proof_engine_fixture();
    let result =
        CommonProofGenerationStateMachine::new_for_checked_fixture(CommonProofGenerationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
            relation_plan: &fixture.relation_plan,
            relation_context: &fixture.relation_context,
            schedule_position: fixture.schedule_position,
            top_count: fixture.top_count,
            relation_trees: fixture.relation_trees,
            source_polynomial_provider: Box::new(ResidentCommonProofSourcePolynomialProvider::new(
                fixture.provided_columns,
            )),
            maximum_external_memory_chunk_byte_length:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_proof_transport_chunk_byte_length: usize::MAX,
            maximum_prefetched_query_byte_length: MAXIMUM_PROOF_BYTE_LENGTH as u64,
        });
    assert!(matches!(
        result,
        Err(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::InvalidInput
        ))
    ));
}
