use super::proof_round_trip::authenticated_storage_head_source;
use super::*;

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
        Err(CommonProofRuntimeError::InvalidLimits),
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
