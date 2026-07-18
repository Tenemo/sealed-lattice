use super::*;
use crate::bgv::proof_suite::application_statement::SelectedApplicationStatementError;
use crate::bgv::proof_suite::{
    ProofBaseFieldElement, SelectedEvaluatorAggregateEntryInput, SetupPublicPolynomialContext,
    SetupPublicPolynomialTreeInput, canonical_selected_application_statement_for_ceiling,
    canonical_selected_evaluator_aggregate_statement,
};
use crate::foundation::{
    CanonicalStreamDomain, CanonicalStreamVerifier, VerifiedCanonicalStreamSummary,
    derive_canonical_stream_descriptor,
};
use std::sync::OnceLock;

#[test]
fn proof_header_is_consumed_before_the_body_source_is_exposed() {
    let mut complete_proof = b"canonical-proof-header".to_vec();
    complete_proof.extend_from_slice(b"streamed-proof-body");
    let body = verify_and_slice_proof_header(
        &complete_proof,
        complete_proof.len(),
        complete_proof.len(),
        b"canonical-proof-header",
    )
    .expect("the exact header must be accepted");

    assert_eq!(body.byte_length(), b"streamed-proof-body".len());
    let mut copied_body = vec![0_u8; body.byte_length()];
    assert!(body.copy_bytes(0, &mut copied_body));
    assert_eq!(copied_body, b"streamed-proof-body");
    assert!(!body.copy_bytes(body.byte_length(), &mut [0_u8; 1]));
}

#[test]
fn proof_header_mismatch_and_header_only_stream_fail_closed() {
    let proof = b"canonical-proof-headerstreamed-proof-body".to_vec();
    assert_eq!(
        verify_and_slice_proof_header(&proof, proof.len(), proof.len(), b"canonical-proof-headeR",)
            .err(),
        Some(CommonProofVerifierError::InvalidProofHeader),
    );

    let header_only = b"canonical-proof-header".to_vec();
    assert_eq!(
        verify_and_slice_proof_header(
            &header_only,
            header_only.len(),
            header_only.len(),
            &header_only,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidProofHeader),
    );
}

#[test]
fn proof_header_preflight_enforces_declared_and_profile_lengths() {
    let proof = b"headerbody".to_vec();
    assert_eq!(
        verify_and_slice_proof_header(&proof, proof.len() - 1, proof.len(), b"header").err(),
        Some(CommonProofVerifierError::Body(ProofBodyError::Decode(
            super::super::ProofDecodeError::DeclaredLengthMismatch,
        ))),
    );
    assert_eq!(
        verify_and_slice_proof_header(&proof, proof.len(), proof.len() - 1, b"header").err(),
        Some(CommonProofVerifierError::Body(ProofBodyError::Decode(
            super::super::ProofDecodeError::ProofByteCeilingExceeded,
        ))),
    );
}

#[test]
fn evaluator_linkage_rejects_relinearization_auxiliary_root_mutation() {
    let capabilities = selected_evaluator_auxiliary_capabilities();
    let runtime_capabilities = selected_evaluator_runtime_capabilities();
    let evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"canonical evaluator key store",
    );
    let canonical_statement = selected_evaluator_statement(
        &capabilities,
        &runtime_capabilities,
        None,
        evaluator_store_stream.full_object_digest().into_bytes(),
    );
    assert_selected_evaluator_linkage(&canonical_statement, &capabilities, true);

    let mutated_statement = selected_evaluator_statement(
        &capabilities,
        &runtime_capabilities,
        Some(0),
        evaluator_store_stream.full_object_digest().into_bytes(),
    );
    assert_selected_evaluator_linkage(&mutated_statement, &capabilities, false);
    assert_selected_evaluator_linkage(
        &canonical_statement,
        &capabilities[..capabilities.len() - 1],
        false,
    );
}

#[test]
fn evaluator_linkage_rejects_galois_auxiliary_root_mutation() {
    let capabilities = selected_evaluator_auxiliary_capabilities();
    let runtime_capabilities = selected_evaluator_runtime_capabilities();
    let evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"canonical evaluator key store",
    );
    let canonical_statement = selected_evaluator_statement(
        &capabilities,
        &runtime_capabilities,
        None,
        evaluator_store_stream.full_object_digest().into_bytes(),
    );
    assert_selected_evaluator_linkage(&canonical_statement, &capabilities, true);

    let mutated_statement = selected_evaluator_statement(
        &capabilities,
        &runtime_capabilities,
        Some(1),
        evaluator_store_stream.full_object_digest().into_bytes(),
    );
    assert_selected_evaluator_linkage(&mutated_statement, &capabilities, false);
}

#[test]
fn evaluator_key_store_is_minted_from_one_complete_canonical_list_proof() {
    let auxiliary_capabilities = selected_evaluator_auxiliary_capabilities();
    let runtime_capabilities = selected_evaluator_runtime_capabilities();
    let evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"canonical evaluator key store",
    );
    let statement = selected_evaluator_statement(
        &auxiliary_capabilities,
        &runtime_capabilities,
        None,
        evaluator_store_stream.full_object_digest().into_bytes(),
    );
    let verified_proof = selected_evaluator_verified_proof(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    );
    let complete = VerifiedEvaluatorKeyStore::from_verified_common_proof(
        &verified_proof,
        &statement,
        &evaluator_store_stream,
        &runtime_capabilities,
    )
    .expect("one complete ordered-list proof mints the evaluator store capability");
    assert_eq!(
        complete.protocol_version(),
        FOUNDATION_PROFILE.protocol_version
    );
    assert_eq!(complete.suite_identifier(), [0x64; 64]);
    assert_eq!(complete.setup_proof_context_hash(), [0x62; 64]);
    assert_eq!(complete.top_count(), FOUNDATION_PROFILE.option_count);
    assert_eq!(complete.ordered_runtime_roots(), runtime_capabilities);
    assert_eq!(
        complete
            .verified_evaluator_key_store_stream()
            .full_object_digest(),
        evaluator_store_stream.full_object_digest()
    );
    assert_eq!(
        complete.evaluator_key_store_digest(),
        evaluator_store_stream.full_object_digest().into_bytes()
    );
    assert_eq!(
        complete.into_replay_material().err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
        "the summary-only verifier fixture never upgrades into replay material"
    );
}

#[test]
fn evaluator_key_store_statement_requires_the_complete_selected_list() {
    let auxiliary_capabilities = selected_evaluator_auxiliary_capabilities();
    let runtime_capabilities = selected_evaluator_runtime_capabilities();
    let evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"canonical evaluator key store",
    );
    let entry_count = selected_evaluator_entry_positions(1)
        .expect("selected top-count-one positions")
        .len();
    let source_roots = [[0x61; 64]; FOUNDATION_PROFILE.participant_count as usize];
    let entries = auxiliary_capabilities[..entry_count]
        .iter()
        .zip(&runtime_capabilities[..entry_count])
        .map(|(auxiliary, runtime)| {
            SelectedEvaluatorAggregateEntryInput::new(
                &source_roots,
                runtime.runtime_component_root(),
                auxiliary.auxiliary_component_root(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        canonical_selected_evaluator_aggregate_statement(
            [0x62; 64],
            FOUNDATION_PROFILE.option_count,
            &entries,
            evaluator_store_stream.full_object_digest().into_bytes(),
        ),
        Err(SelectedApplicationStatementError::WrongTypeOrLength)
    );
}

#[test]
fn evaluator_key_store_requires_every_ordered_verifier_owned_runtime_root() {
    let auxiliary_capabilities = selected_evaluator_auxiliary_capabilities();
    let runtime_capabilities = selected_evaluator_runtime_capabilities();
    assert_eq!(
        runtime_capabilities.len(),
        selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .expect("selected complete evaluator position list")
            .len()
    );
    let evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"canonical evaluator key store",
    );
    let statement = selected_evaluator_statement(
        &auxiliary_capabilities,
        &runtime_capabilities,
        None,
        evaluator_store_stream.full_object_digest().into_bytes(),
    );
    let verified_proof = selected_evaluator_verified_proof(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    );
    let assert_rejected = |candidate_runtime_roots: &[VerifiedEvaluatorRuntimeRoot]| {
        assert_eq!(
            VerifiedEvaluatorKeyStore::from_verified_common_proof(
                &verified_proof,
                &statement,
                &evaluator_store_stream,
                candidate_runtime_roots,
            )
            .err(),
            Some(CommonProofVerifierError::InvalidApplicationStatement),
        );
    };

    assert_rejected(&runtime_capabilities[..runtime_capabilities.len() - 1]);

    let mut reordered_runtime_capabilities = runtime_capabilities.clone();
    reordered_runtime_capabilities.swap(0, 1);
    assert_rejected(&reordered_runtime_capabilities);

    let mismatched_root_ordinal = runtime_capabilities.len() - 1;
    let mut mismatched_runtime_capabilities = runtime_capabilities.clone();
    let mismatched_runtime_root = recomputed_evaluator_runtime_root(
        runtime_capabilities[mismatched_root_ordinal].position(),
        1,
    );
    assert_ne!(
        mismatched_runtime_root.runtime_component_root(),
        runtime_capabilities[mismatched_root_ordinal].runtime_component_root(),
    );
    mismatched_runtime_capabilities[mismatched_root_ordinal] = mismatched_runtime_root;
    assert_rejected(&mismatched_runtime_capabilities);

    let galois_position = runtime_capabilities
        .iter()
        .map(|capability| capability.position())
        .find(|position| {
            matches!(
                position.key_kind(),
                SelectedEvaluatorEntryKind::Galois { .. }
            )
        })
        .expect("the selected evaluator list contains Galois entries");
    let wrong_role_tree = evaluator_public_polynomial_tree(
        galois_position,
        SetupPublicPolynomialRootRole::GaloisCommon,
        0,
    );
    assert_eq!(
        VerifiedEvaluatorRuntimeRoot::from_recomputed_public_polynomial_tree(
            &wrong_role_tree,
            FOUNDATION_PROFILE.option_count,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );
}

#[test]
fn evaluator_key_store_rejects_mismatched_proof_metadata_and_statement_binding() {
    let auxiliary_capabilities = selected_evaluator_auxiliary_capabilities();
    let runtime_capabilities = selected_evaluator_runtime_capabilities();
    let evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"canonical evaluator key store",
    );
    let statement = selected_evaluator_statement(
        &auxiliary_capabilities,
        &runtime_capabilities,
        None,
        evaluator_store_stream.full_object_digest().into_bytes(),
    );

    let scheduled_proof = selected_evaluator_verified_proof(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(0),
        Some(FOUNDATION_PROFILE.option_count),
    );
    assert_eq!(
        VerifiedEvaluatorKeyStore::from_verified_common_proof(
            &scheduled_proof,
            &statement,
            &evaluator_store_stream,
            &runtime_capabilities,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );

    let missing_top_count_proof = selected_evaluator_verified_proof(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        None,
    );
    assert_eq!(
        VerifiedEvaluatorKeyStore::from_verified_common_proof(
            &missing_top_count_proof,
            &statement,
            &evaluator_store_stream,
            &runtime_capabilities,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );

    let wrong_schema_proof = selected_evaluator_verified_proof(
        &statement,
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        None,
    );
    assert_eq!(
        VerifiedEvaluatorKeyStore::from_verified_common_proof(
            &wrong_schema_proof,
            &statement,
            &evaluator_store_stream,
            &runtime_capabilities,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );

    let mut wrong_statement_hash_proof = selected_evaluator_verified_proof(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    );
    wrong_statement_hash_proof.application_statement_hash[0] ^= 1;
    assert_eq!(
        VerifiedEvaluatorKeyStore::from_verified_common_proof(
            &wrong_statement_hash_proof,
            &statement,
            &evaluator_store_stream,
            &runtime_capabilities,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );

    let truncated_statement = &statement[..statement.len() - 1];
    let truncated_statement_proof = selected_evaluator_verified_proof(
        truncated_statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    );
    assert_eq!(
        VerifiedEvaluatorKeyStore::from_verified_common_proof(
            &truncated_statement_proof,
            truncated_statement,
            &evaluator_store_stream,
            &runtime_capabilities,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );
}

#[test]
fn evaluator_key_store_requires_the_verified_store_stream_digest_and_domain() {
    let auxiliary_capabilities = selected_evaluator_auxiliary_capabilities();
    let runtime_capabilities = selected_evaluator_runtime_capabilities();
    let evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"canonical evaluator key store",
    );
    let statement = selected_evaluator_statement(
        &auxiliary_capabilities,
        &runtime_capabilities,
        None,
        evaluator_store_stream.full_object_digest().into_bytes(),
    );
    let verified_proof = selected_evaluator_verified_proof(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    );

    let different_evaluator_store_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::EvaluatorKeyStore,
        b"different canonical evaluator key store",
    );
    assert_eq!(
        VerifiedEvaluatorKeyStore::from_verified_common_proof(
            &verified_proof,
            &statement,
            &different_evaluator_store_stream,
            &runtime_capabilities,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );

    let wrong_domain_stream = verified_canonical_stream_summary(
        CanonicalStreamDomain::BallotCiphertext,
        b"canonical evaluator key store",
    );
    let wrong_domain_statement = selected_evaluator_statement(
        &auxiliary_capabilities,
        &runtime_capabilities,
        None,
        wrong_domain_stream.full_object_digest().into_bytes(),
    );
    let wrong_domain_proof = selected_evaluator_verified_proof(
        &wrong_domain_statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    );
    assert_eq!(
        VerifiedEvaluatorKeyStore::from_verified_common_proof(
            &wrong_domain_proof,
            &wrong_domain_statement,
            &wrong_domain_stream,
            &runtime_capabilities,
        )
        .err(),
        Some(CommonProofVerifierError::InvalidApplicationStatement),
    );
}

fn selected_evaluator_auxiliary_capabilities() -> Vec<VerifiedEvaluatorAuxiliaryRoot> {
    static CAPABILITIES: OnceLock<Vec<VerifiedEvaluatorAuxiliaryRoot>> = OnceLock::new();
    CAPABILITIES
        .get_or_init(build_selected_evaluator_auxiliary_capabilities)
        .clone()
}

fn build_selected_evaluator_auxiliary_capabilities() -> Vec<VerifiedEvaluatorAuxiliaryRoot> {
    let suite_identifier = [0x51; 64];
    let round_one_statement = canonical_selected_application_statement_for_ceiling(
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            Some(0),
            None,
        ),
    )
    .expect("round-one aggregate statement");
    let verified_round_one = VerifiedCommonProof {
        protocol_version: FOUNDATION_PROFILE.protocol_version,
        suite_identifier,
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        application_statement_hash: verified_application_statement_hash(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            &round_one_statement,
        ),
        proof_header_hash: verified_proof_header_hash(
            &CanonicalTuple::new(
                PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
                PROOF_OBJECT_HEADER_SCHEMA_VERSION,
                vec![
                    CanonicalItem::variable_bytes(&round_one_statement)
                        .expect("round-one statement fits the proof header"),
                ],
            )
            .encode()
            .expect("round-one proof header encodes"),
        )
        .expect("round-one proof header hashes"),
        proof_byte_length: 1,
        verified_query_count: 1,
        relation_plan_variant_hash: [0x52; 64],
        schedule_position: Some(0),
        top_count: None,
    };
    let mut capabilities = vec![
        VerifiedEvaluatorAuxiliaryRoot::from_verified_relinearization_round_one_aggregate(
            &verified_round_one,
            &round_one_statement,
        )
        .expect("verified round-one aggregate mints the RKG linkage"),
    ];

    for position in selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .expect("selected evaluator positions")
        .into_iter()
        .skip(1)
    {
        let SelectedEvaluatorEntryKind::Galois {
            galois_element,
            catalog_level,
        } = position.key_kind()
        else {
            panic!("only the first selected entry is an RKG entry");
        };
        let context =
            SetupPublicPolynomialContext::galois_common([0x53; 64], position.schedule_position())
                .expect("Galois common context");
        let coefficients = vec![vec![
            ProofBaseFieldElement::from_canonical(
                u64::try_from(galois_element)
                    .expect("Galois element fits")
                    .wrapping_add(u64::try_from(catalog_level).expect("level fits")),
            )
            .expect("small coefficient is canonical"),
        ]];
        let tree = SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &context,
            evaluation_domain_size: 8,
            source_polynomial_degree_bound_exclusive: 4,
            ordered_coefficient_columns: &coefficients,
        })
        .expect("verifier-derived Galois public-polynomial tree");
        capabilities.push(
            VerifiedEvaluatorAuxiliaryRoot::from_galois_common_public_polynomial_tree(
                position.schedule_position(),
                galois_element,
                catalog_level,
                &tree,
            )
            .expect("Galois public-polynomial tree mints the exact linkage"),
        );
    }
    capabilities
}

fn selected_evaluator_runtime_capabilities() -> Vec<VerifiedEvaluatorRuntimeRoot> {
    static CAPABILITIES: OnceLock<Vec<VerifiedEvaluatorRuntimeRoot>> = OnceLock::new();
    CAPABILITIES
        .get_or_init(|| {
            selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
                .expect("selected evaluator positions")
                .into_iter()
                .map(|position| recomputed_evaluator_runtime_root(position, 0))
                .collect()
        })
        .clone()
}

fn recomputed_evaluator_runtime_root(
    position: SelectedEvaluatorEntryPosition,
    coefficient_delta: u64,
) -> VerifiedEvaluatorRuntimeRoot {
    let root_role = match position.key_kind() {
        SelectedEvaluatorEntryKind::Relinearization { .. } => {
            SetupPublicPolynomialRootRole::RelinearizationRuntime
        }
        SelectedEvaluatorEntryKind::Galois { .. } => SetupPublicPolynomialRootRole::GaloisRuntime,
    };
    let tree = evaluator_public_polynomial_tree(position, root_role, coefficient_delta);
    VerifiedEvaluatorRuntimeRoot::from_recomputed_public_polynomial_tree(
        &tree,
        FOUNDATION_PROFILE.option_count,
    )
    .expect("the recomputed runtime tree mints the exact selected root")
}

fn evaluator_public_polynomial_tree(
    position: SelectedEvaluatorEntryPosition,
    root_role: SetupPublicPolynomialRootRole,
    coefficient_delta: u64,
) -> SetupPublicPolynomialTree {
    let context = SetupPublicPolynomialContext::new(
        [0x54; 64],
        root_role,
        None,
        None,
        Some(position.schedule_position()),
        None,
    )
    .expect("evaluator runtime context");
    let coefficient_value = u64::from(position.schedule_position())
        .checked_add(coefficient_delta)
        .and_then(|value| value.checked_add(1))
        .expect("test coefficient fits");
    let coefficients = vec![vec![
        ProofBaseFieldElement::from_canonical(coefficient_value)
            .expect("small test coefficient is canonical"),
    ]];
    SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
        context: &context,
        evaluation_domain_size: 8,
        source_polynomial_degree_bound_exclusive: 4,
        ordered_coefficient_columns: &coefficients,
    })
    .expect("verifier-recomputed evaluator public-polynomial tree")
}

fn selected_evaluator_statement(
    capabilities: &[VerifiedEvaluatorAuxiliaryRoot],
    runtime_capabilities: &[VerifiedEvaluatorRuntimeRoot],
    mutated_auxiliary_root_entry_ordinal: Option<usize>,
    evaluator_key_store_digest: [u8; 64],
) -> Vec<u8> {
    assert_eq!(capabilities.len(), runtime_capabilities.len());
    let source_roots = [[0x61; 64]; FOUNDATION_PROFILE.participant_count as usize];
    let entries = capabilities
        .iter()
        .zip(runtime_capabilities)
        .enumerate()
        .map(|(entry_ordinal, (capability, runtime_capability))| {
            let mut auxiliary_root = capability.auxiliary_component_root();
            if mutated_auxiliary_root_entry_ordinal == Some(entry_ordinal) {
                auxiliary_root[0] ^= 1;
            }
            SelectedEvaluatorAggregateEntryInput::new(
                &source_roots,
                runtime_capability.runtime_component_root(),
                auxiliary_root,
            )
        })
        .collect::<Vec<_>>();
    canonical_selected_evaluator_aggregate_statement(
        [0x62; 64],
        FOUNDATION_PROFILE.option_count,
        &entries,
        evaluator_key_store_digest,
    )
    .expect("selected evaluator statement")
}

fn selected_evaluator_verified_proof(
    statement: &[u8],
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
) -> VerifiedCommonProof {
    let suite_identifier = [0x64; 64];
    VerifiedCommonProof {
        protocol_version: FOUNDATION_PROFILE.protocol_version,
        suite_identifier,
        application_statement_schema_identifier,
        application_statement_hash: verified_application_statement_hash(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            application_statement_schema_identifier,
            statement,
        ),
        proof_header_hash: [0x65; 64],
        proof_byte_length: 1,
        verified_query_count: 1,
        relation_plan_variant_hash: [0x66; 64],
        schedule_position,
        top_count,
    }
}

fn verified_canonical_stream_summary(
    stream_domain: CanonicalStreamDomain,
    stream_bytes: &[u8],
) -> VerifiedCanonicalStreamSummary {
    let descriptor = derive_canonical_stream_descriptor(stream_domain, stream_bytes)
        .expect("canonical stream descriptor");
    let mut verifier =
        CanonicalStreamVerifier::new(stream_domain, descriptor).expect("canonical stream verifier");
    for (chunk_index, chunk_bytes) in stream_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        verifier
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .expect("canonical stream chunk verifies");
    }
    verifier
        .finish_with_summary()
        .into_result()
        .expect("canonical stream summary verifies")
}

fn assert_selected_evaluator_linkage(
    canonical_statement: &[u8],
    capabilities: &[VerifiedEvaluatorAuxiliaryRoot],
    expected_to_pass: bool,
) {
    let statement = decode_selected_application_statement(
        canonical_statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; 64],
            None,
            Some(FOUNDATION_PROFILE.option_count),
        ),
    )
    .expect("selected evaluator statement decodes");
    let result = validate_evaluator_auxiliary_root_linkage(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(FOUNDATION_PROFILE.option_count),
        capabilities,
        &selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected evaluator-key aggregate context"),
    );
    assert_eq!(result.is_ok(), expected_to_pass);
}
