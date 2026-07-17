use super::*;

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
