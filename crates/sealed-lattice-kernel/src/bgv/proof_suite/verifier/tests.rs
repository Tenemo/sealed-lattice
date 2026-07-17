use super::*;
use crate::bgv::proof_suite::{
    ProofBaseFieldElement, SelectedEvaluatorAggregateEntryInput, SetupPublicPolynomialContext,
    SetupPublicPolynomialTreeInput, canonical_selected_application_statement_for_ceiling,
    canonical_selected_evaluator_aggregate_statement,
};

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
    let canonical_statement = selected_evaluator_statement(&capabilities, 0, false);
    assert_selected_evaluator_linkage(&canonical_statement, 0, &capabilities[..1], true);

    let mutated_statement = selected_evaluator_statement(&capabilities, 0, true);
    assert_selected_evaluator_linkage(&mutated_statement, 0, &capabilities[..1], false);
    assert_selected_evaluator_linkage(&canonical_statement, 0, &capabilities, false);
}

#[test]
fn evaluator_linkage_rejects_galois_auxiliary_root_mutation() {
    let capabilities = selected_evaluator_auxiliary_capabilities();
    let canonical_statement = selected_evaluator_statement(&capabilities, 1, false);
    assert_selected_evaluator_linkage(&canonical_statement, 1, &capabilities[1..2], true);

    let mutated_statement = selected_evaluator_statement(&capabilities, 1, true);
    assert_selected_evaluator_linkage(&mutated_statement, 1, &capabilities[1..2], false);
}

#[test]
fn evaluator_key_store_requires_the_complete_ordered_verified_entry_set() {
    let auxiliary_capabilities = selected_evaluator_auxiliary_capabilities();
    let mut verified_entries = (0..auxiliary_capabilities.len())
        .map(|entry_ordinal| {
            selected_verified_evaluator_entry(&auxiliary_capabilities, entry_ordinal)
        })
        .collect::<Vec<_>>();
    let complete = VerifiedEvaluatorKeyStore::from_ordered_verified_entries(
        FOUNDATION_PROFILE.option_count,
        &verified_entries,
    )
    .expect("the complete ordered proof set mints the evaluator store capability");
    assert_eq!(complete.top_count(), FOUNDATION_PROFILE.option_count);
    assert_eq!(complete.evaluator_key_store_digest(), [0x63; 64]);

    assert!(
        VerifiedEvaluatorKeyStore::from_ordered_verified_entries(
            FOUNDATION_PROFILE.option_count,
            &verified_entries[..verified_entries.len() - 1],
        )
        .is_err()
    );
    verified_entries.swap(0, 1);
    assert!(
        VerifiedEvaluatorKeyStore::from_ordered_verified_entries(
            FOUNDATION_PROFILE.option_count,
            &verified_entries,
        )
        .is_err()
    );
    verified_entries.swap(0, 1);
    verified_entries[1].corrupt_evaluator_key_store_digest_for_test();
    assert!(
        VerifiedEvaluatorKeyStore::from_ordered_verified_entries(
            FOUNDATION_PROFILE.option_count,
            &verified_entries,
        )
        .is_err()
    );
}

fn selected_evaluator_auxiliary_capabilities() -> Vec<VerifiedEvaluatorAuxiliaryRoot> {
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

fn selected_evaluator_statement(
    capabilities: &[VerifiedEvaluatorAuxiliaryRoot],
    entry_ordinal: usize,
    mutate_auxiliary_root: bool,
) -> Vec<u8> {
    let source_roots = [[0x61; 64]; FOUNDATION_PROFILE.participant_count as usize];
    let mut auxiliary_root = capabilities[entry_ordinal].auxiliary_component_root();
    if mutate_auxiliary_root {
        auxiliary_root[0] ^= 1;
    }
    let entry = SelectedEvaluatorAggregateEntryInput::new(
        &source_roots,
        [0x70_u8.wrapping_add(entry_ordinal as u8); 64],
        auxiliary_root,
    );
    canonical_selected_evaluator_aggregate_statement(
        [0x62; 64],
        FOUNDATION_PROFILE.option_count,
        u32::try_from(entry_ordinal).expect("entry ordinal fits u32"),
        &entry,
        [0x63; 64],
    )
    .expect("selected evaluator statement")
}

fn selected_verified_evaluator_entry(
    capabilities: &[VerifiedEvaluatorAuxiliaryRoot],
    entry_ordinal: usize,
) -> VerifiedEvaluatorAggregateEntry {
    let statement = selected_evaluator_statement(capabilities, entry_ordinal, false);
    let suite_identifier = [0x64; 64];
    let verified_proof = VerifiedCommonProof {
        protocol_version: FOUNDATION_PROFILE.protocol_version,
        suite_identifier,
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        application_statement_hash: verified_application_statement_hash(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            &statement,
        ),
        proof_header_hash: [0x65; 64],
        proof_byte_length: 1,
        verified_query_count: 1,
        relation_plan_variant_hash: [0x66; 64],
        schedule_position: Some(u32::try_from(entry_ordinal).expect("entry ordinal fits u32")),
        top_count: Some(FOUNDATION_PROFILE.option_count),
    };
    VerifiedEvaluatorAggregateEntry::from_verified_common_proof(&verified_proof, &statement)
        .expect("a verified per-entry proof mints one evaluator entry capability")
}

fn assert_selected_evaluator_linkage(
    canonical_statement: &[u8],
    entry_ordinal: u32,
    capabilities: &[VerifiedEvaluatorAuxiliaryRoot],
    expected_to_pass: bool,
) {
    let statement = decode_selected_application_statement(
        canonical_statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; 64],
            Some(entry_ordinal),
            Some(FOUNDATION_PROFILE.option_count),
        ),
    )
    .expect("selected evaluator statement decodes");
    let result = validate_evaluator_auxiliary_root_linkage(
        &statement,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(entry_ordinal),
        Some(FOUNDATION_PROFILE.option_count),
        capabilities,
        &selected_relation_plan_check_context(),
    );
    assert_eq!(result.is_ok(), expected_to_pass);
}
