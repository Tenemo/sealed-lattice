use super::proof_round_trip::{
    authenticated_storage_head_source, authenticated_storage_head_source_with_binding,
    authenticated_storage_transition_source, verified_fixture_proof_stream,
};
use super::*;
use crate::foundation::ParticipantIdentity;

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
        (
            proof_bytes.len() as u64,
            PUBLIC_AGGREGATE_TEST_UNIQUE_QUERY_COUNT,
        ),
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
        PUBLIC_AGGREGATE_TEST_UNIQUE_QUERY_COUNT,
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
        super::super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        super::super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
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
        super::super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        PUBLIC_AGGREGATE_TEST_UNIQUE_QUERY_COUNT,
    )
    .expect("the application reservation fits the worker safety bound");
    let binding = CommonProofVerificationBinding::new(
        [0x11; 64],
        [0x32; 64],
        [0x31; 64],
        [0x33; 64],
        proof_application,
        expected_relation_plan_hash,
    );
    let proof_stream_descriptor =
        maximum_length_test_proof_stream_descriptor([0x45; 64], [0x44; 64]);
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
    let incomplete_statement_tree_batch = verified_trees[..2].to_vec();
    assert_eq!(
        registry.attach_statement_owned_tree_batch(
            &application_handle,
            incomplete_statement_tree_batch,
        ),
        Err(CommonProofRuntimeError::WrongVerificationBinding),
        "an incomplete tree batch fails without mutating the application",
    );
    registry
        .attach_statement_owned_tree_batch(&application_handle, verified_trees.clone())
        .expect("the exact ordered tree batch attaches once");
    assert_eq!(
        registry.attach_statement_owned_tree_batch(&application_handle, verified_trees.clone()),
        Err(CommonProofRuntimeError::WrongVerificationBinding),
        "a second batch cannot replace the application-owned catalog",
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
    let mut wrong_coordinate_batch = verified_trees.clone();
    wrong_coordinate_batch[0] =
        wrong_coordinate_batch[0].with_relation_coordinates(u32::MAX, u32::MAX);
    registry
        .attach_statement_owned_tree_batch(&second_application_handle, wrong_coordinate_batch)
        .expect("the complete batch is retained until its per-tree validation runs");
    assert_eq!(
        registry
            .consume_verification_inputs(&second_application_handle, &[], None)
            .err(),
        Some(CommonProofRuntimeError::WrongVerificationBinding),
        "the complete batch still receives exact per-tree coordinate validation",
    );
    registry
        .cancel_application(&second_application_handle)
        .expect("cancellation atomically drops the rejected application-owned batch");

    let consumed = registry
        .consume_verification_inputs(&application_handle, &[], None)
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
            .consume_verification_inputs(&application_handle, &[], None)
            .err(),
        Some(CommonProofRuntimeError::UnknownOrStaleHandle),
        "the application handle is permanently stale after transfer",
    );
    assert_eq!(
        registry
            .consume_verification_inputs(&second_application_handle, &[], None)
            .err(),
        Some(CommonProofRuntimeError::UnknownOrStaleHandle),
    );
}

#[test]
fn application_owned_statement_tree_batch_does_not_spend_one_registry_entry_per_tree() {
    let fixture = common_proof_engine_fixture();
    let fixture_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let schema_identifier =
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_plan_artifact = selected_relation_plans()
        .expect("selected relation plans")
        .into_iter()
        .find(|artifact| artifact.application_statement_schema_identifier() == schema_identifier)
        .expect("selected VSS relation plan");
    let relation_context = selected_relation_plan_check_context(schema_identifier)
        .expect("selected VSS relation context");
    let statement_tree_count = relation_plan_artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("selected VSS relation variant")
        .ordered_trees()
        .iter()
        .filter(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
        .count();
    assert!(
        statement_tree_count > 64,
        "the regression must cover a catalog larger than the registry ceiling",
    );
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        relation_plan_artifact.compiled_plan(),
        &relation_context,
        None,
        None,
    )
    .expect("checked selected VSS plan capability");
    let runtime_limits = CommonProofRuntimeLimits::new(
        super::super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        super::super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
    )
    .expect("fixed worker limits");
    let proof_stream_digest = [0x64; 64];
    let proof_application = CommonProofApplicationBinding::new(
        [0x61; 64],
        [0x62; 64],
        schema_identifier,
        [0x63; 64],
        CanonicalStreamDomain::DealerVssShareLinkageProof,
        proof_stream_digest,
        super::super::super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64,
        relation_plan_capability
            .proof_query_count()
            .expect("selected VSS query count"),
    )
    .expect("VSS application binding");
    let verification_binding = CommonProofVerificationBinding::new(
        [0x11; 64],
        [0x32; 64],
        [0x31; 64],
        [0x33; 64],
        proof_application,
        relation_plan_capability.relation_plan_hash(),
    );
    let proof_stream_descriptor =
        maximum_length_test_proof_stream_descriptor([0x65; 64], proof_stream_digest);
    let mut registry = CommonProofUpstreamInputRegistry::default();
    let application_handle = registry
        .install_test_application_fixture(
            verification_binding,
            relation_plan_capability,
            1,
            &fixture.canonical_application_statement_bytes,
            proof_stream_descriptor,
            runtime_limits,
        )
        .expect("VSS application retained");
    let entry_count_before_batch = registry.entry_count().expect("entry count");
    registry
        .attach_statement_owned_tree_batch(
            &application_handle,
            vec![fixture_trees[0].clone(); statement_tree_count],
        )
        .expect("one application-owned large tree batch");
    assert_eq!(
        registry.entry_count().expect("entry count after batch"),
        entry_count_before_batch,
        "tree count must not be registry entry count",
    );
    registry
        .cancel_application(&application_handle)
        .expect("cancellation drops the whole application-owned batch");
    assert_eq!(registry.entry_count().expect("empty registry"), 0);
}
