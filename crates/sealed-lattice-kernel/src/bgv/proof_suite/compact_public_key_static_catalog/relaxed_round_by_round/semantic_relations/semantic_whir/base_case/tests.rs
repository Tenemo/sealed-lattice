use super::super::super::super::TranscriptEpoch;
use super::super::super::semantic_composition::{
    SemanticCompositionError, SemanticPreWhirFinalAndMainOpeningPrefix,
    SemanticPreWhirFinalAndMainOpeningStatement, SemanticPreWhirFinalAndMainOpeningWitness,
    semantic_pre_whir_final_and_main_opening_bad_transition,
    semantic_pre_whir_final_and_main_opening_errbr,
    semantic_pre_whir_final_and_main_opening_kstate,
};
use super::super::super::semantic_execution::{
    SemanticFactorOneMoveDescriptor, SemanticKnowledgeWitness, SemanticUnusedCfwMatrices,
    SemanticVerifierMoveOwner, SemanticVerifierMovePrefix, SemanticVerifierMoveStatement,
    semantic_factor_one_bad_transition, semantic_factor_one_errbr, semantic_factor_one_kstate,
};
use super::super::SemanticWhirOpeningBatchingStatement;
use super::*;
use crate::bgv::proof_suite::ProofBaseFieldElement;
use crate::bgv::proof_suite::compact_public_key_static_catalog::relaxed_round_by_round::MaskGroupRole;

fn field(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(value).expect("small canonical field value"),
    )
}

fn relation(
    message_length: u64,
    hiding_randomness_length: u64,
    block_length: u64,
    interleaving_width: u64,
) -> CommittedCodeRelation {
    CommittedCodeRelation {
        message_length,
        hiding_randomness_length,
        block_length,
        interleaving_width,
    }
}

fn code_fixture(
    relation: &CommittedCodeRelation,
    message_columns: Vec<Vec<ProofChallengeExtensionElement>>,
    randomness_columns: Vec<Vec<ProofChallengeExtensionElement>>,
) -> (SemanticCommittedCodeInstance, SemanticCommittedCodeWitness) {
    let witness = SemanticCommittedCodeWitness {
        message_columns,
        hiding_randomness_columns: randomness_columns,
    };
    let rows = encode_canonical_interleaved_reed_solomon(
        semantic_code_geometry(relation).expect("small code geometry derives"),
        &witness
            .coefficient_columns(relation)
            .expect("fixture witness has the exact geometry"),
    )
    .expect("fixture witness encodes");
    (
        SemanticCommittedCodeInstance {
            received_rows: rows,
        },
        witness,
    )
}

struct BaseFixture {
    statement: SemanticWhirBaseStatement,
    fresh_message: SemanticWhirBaseFreshMessage,
    input_witness: SemanticGeneralizedRelationWitness,
    fresh_witness: SemanticGeneralizedRelationWitness,
    blinded_witness: SemanticGeneralizedRelationWitness,
    combination_challenge: ProofChallengeExtensionElement,
}

fn base_fixture() -> BaseFixture {
    let source_relation = relation(2, 1, 8, 1);
    let mask_relation = relation(2, 1, 8, 2);
    let (input_source_instance, input_source_witness) = code_fixture(
        &source_relation,
        vec![vec![field(2), field(3)]],
        vec![vec![field(5)]],
    );
    let (fresh_source_instance, fresh_source_witness) = code_fixture(
        &source_relation,
        vec![vec![field(7), field(11)]],
        vec![vec![field(13)]],
    );
    let (input_mask_instance, input_mask_witness) = code_fixture(
        &mask_relation,
        vec![vec![field(17), field(19)], vec![field(23), field(29)]],
        vec![vec![field(31)], vec![field(37)]],
    );
    let (fresh_mask_instance, fresh_mask_witness) = code_fixture(
        &mask_relation,
        vec![vec![field(41), field(43)], vec![field(47), field(53)]],
        vec![vec![field(59)], vec![field(61)]],
    );
    let input_witness = SemanticGeneralizedRelationWitness {
        source: input_source_witness,
        masks: vec![input_mask_witness],
    };
    let fresh_witness = SemanticGeneralizedRelationWitness {
        source: fresh_source_witness,
        masks: vec![fresh_mask_witness],
    };
    let mut claim = SemanticGeneralizedLinearClaim {
        source_covector: vec![field(67), field(71)],
        mask_covectors: vec![vec![field(73), field(79), field(83), field(89)]],
        target: ProofChallengeExtensionElement::ZERO,
    };
    claim.target = evaluate_claim(&claim, &input_witness).expect("input claim evaluates");
    let input_relation = GeneralizedCommittedRelation {
        source_code: source_relation,
        mask_codes: vec![CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirSumcheck { batch_ordinal: 0 },
            code: mask_relation,
        }],
        source_message_element_count: 2,
        source_hiding_element_count: 1,
        mask_message_element_count: 4,
        covector_extension_element_count: 7,
        opening_evaluation_claim_count: 0,
        carried_reduction_claim_count: 1,
        claim_count: 1,
    };
    let input_instance = SemanticGeneralizedRelationInstance {
        source: input_source_instance,
        masks: vec![input_mask_instance],
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![claim.clone()],
    };
    let masked_claim = evaluate_claim(&claim, &fresh_witness).expect("fresh claim evaluates");
    let fresh_message = SemanticWhirBaseFreshMessage {
        source: fresh_source_instance,
        masks: vec![fresh_mask_instance],
        masked_claim,
    };
    let statement = SemanticWhirBaseStatement::new(input_relation, input_instance, 2, 2)
        .expect("small base statement derives");
    let combination_challenge = field(97);
    let blinded_witness =
        combine_generalized_witnesses(&fresh_witness, &input_witness, combination_challenge)
            .expect("fixture witnesses combine");
    BaseFixture {
        statement,
        fresh_message,
        input_witness,
        fresh_witness,
        blinded_witness,
        combination_challenge,
    }
}

fn fresh_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        fresh_message: Some(fixture.fresh_message.clone()),
        combination_challenge: None,
        revealed_witness: None,
        query_challenges: None,
    }
}

fn combination_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        combination_challenge: Some(fixture.combination_challenge),
        ..fresh_prefix(fixture)
    }
}

fn reveal_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        revealed_witness: Some(fixture.blinded_witness.clone()),
        ..combination_prefix(fixture)
    }
}

fn full_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        query_challenges: Some(SemanticWhirBaseQueryChallenges {
            source_positions: vec![0, 4],
            mask_group_positions: vec![vec![1, 5]],
        }),
        ..reveal_prefix(fixture)
    }
}

#[test]
fn base_kstate_and_extractors_execute_every_prover_and_verifier_prefix() {
    let fixture = base_fixture();
    let pre_combination = SemanticWhirBasePreCombinationWitness {
        input: fixture.input_witness.clone(),
        fresh: fixture.fresh_witness.clone(),
    };
    assert!(
        semantic_whir_base_kstate(
            &fixture.statement,
            None,
            &SemanticWhirBaseKnowledgeWitness::Input(fixture.input_witness.clone()),
        )
        .unwrap()
    );
    assert!(
        semantic_whir_base_kstate(
            &fixture.statement,
            Some(&fresh_prefix(&fixture)),
            &SemanticWhirBaseKnowledgeWitness::PreCombination(pre_combination.clone()),
        )
        .unwrap()
    );
    let combination_prefix = combination_prefix(&fixture);
    assert!(
        semantic_whir_base_kstate(
            &fixture.statement,
            Some(&combination_prefix),
            &SemanticWhirBaseKnowledgeWitness::Blinded(fixture.blinded_witness.clone()),
        )
        .unwrap()
    );
    let combination_extraction = semantic_whir_base_combination_errbr(
        &fixture.statement,
        &combination_prefix,
        &fixture.blinded_witness,
    )
    .expect("combination extractor executes");
    assert_eq!(
        combination_extraction.witness,
        Some(pre_combination.clone())
    );
    assert!(combination_extraction.field_operation_count > 0);
    assert_eq!(
        semantic_whir_base_combination_bad_transition(
            &fixture.statement,
            &combination_prefix,
            &fixture.blinded_witness,
        )
        .unwrap(),
        None
    );

    let dispatcher_base_statement: SemanticVerifierMoveStatement<
        '_,
        '_,
        SemanticUnusedCfwMatrices,
    > = SemanticVerifierMoveStatement::WhirBase(&fixture.statement);
    let base_combination_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::WhirBaseCombination {
            epoch: TranscriptEpoch::PreChallenge,
        },
    );
    let dispatcher_base_predecessor = SemanticVerifierMovePrefix::WhirBase(fresh_prefix(&fixture));
    let dispatcher_base_extended = SemanticVerifierMovePrefix::WhirBase(combination_prefix.clone());
    let dispatcher_pre_combination_witness = SemanticKnowledgeWitness::WhirBase(
        SemanticWhirBaseKnowledgeWitness::PreCombination(pre_combination),
    );
    let dispatcher_blinded_witness = SemanticKnowledgeWitness::WhirBase(
        SemanticWhirBaseKnowledgeWitness::Blinded(fixture.blinded_witness.clone()),
    );
    assert!(
        semantic_factor_one_kstate(
            &base_combination_descriptor,
            &dispatcher_base_statement,
            &dispatcher_base_predecessor,
            &dispatcher_pre_combination_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_factor_one_kstate(
            &base_combination_descriptor,
            &dispatcher_base_statement,
            &dispatcher_base_extended,
            &dispatcher_blinded_witness,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_factor_one_errbr(
            &base_combination_descriptor,
            &dispatcher_base_statement,
            &dispatcher_base_extended,
            &dispatcher_blinded_witness,
        )
        .unwrap()
        .witness,
        Some(dispatcher_pre_combination_witness)
    );
    assert_eq!(
        semantic_factor_one_bad_transition(
            &base_combination_descriptor,
            &dispatcher_base_statement,
            &dispatcher_base_extended,
            &dispatcher_blinded_witness,
        )
        .unwrap(),
        None
    );

    let revealed_prefix = reveal_prefix(&fixture);
    assert!(
        semantic_whir_base_kstate(
            &fixture.statement,
            Some(&revealed_prefix),
            &SemanticWhirBaseKnowledgeWitness::Blinded(fixture.blinded_witness.clone()),
        )
        .unwrap()
    );
    let full_prefix = full_prefix(&fixture);
    assert!(
        semantic_whir_base_kstate(
            &fixture.statement,
            Some(&full_prefix),
            &SemanticWhirBaseKnowledgeWitness::Terminal,
        )
        .unwrap()
    );
    let final_extraction = semantic_whir_base_final_errbr(&fixture.statement, &full_prefix)
        .expect("terminal extractor executes");
    assert_eq!(
        final_extraction.witness,
        Some(fixture.blinded_witness.clone())
    );
    assert!(final_extraction.field_operation_count > 0);
    assert_eq!(
        semantic_whir_base_final_bad_transition(&fixture.statement, &full_prefix).unwrap(),
        None
    );
    let final_queries_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::MainWhirFinalQueries,
    );
    let dispatcher_final_predecessor =
        SemanticVerifierMovePrefix::WhirBase(revealed_prefix.clone());
    let dispatcher_final_extended = SemanticVerifierMovePrefix::WhirBase(full_prefix.clone());
    let dispatcher_final_predecessor_witness = SemanticKnowledgeWitness::WhirBase(
        SemanticWhirBaseKnowledgeWitness::Blinded(fixture.blinded_witness.clone()),
    );
    let dispatcher_terminal_witness =
        SemanticKnowledgeWitness::WhirBase(SemanticWhirBaseKnowledgeWitness::Terminal);
    assert!(
        semantic_factor_one_kstate(
            &final_queries_descriptor,
            &dispatcher_base_statement,
            &dispatcher_final_predecessor,
            &dispatcher_final_predecessor_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_factor_one_kstate(
            &final_queries_descriptor,
            &dispatcher_base_statement,
            &dispatcher_final_extended,
            &dispatcher_terminal_witness,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_factor_one_errbr(
            &final_queries_descriptor,
            &dispatcher_base_statement,
            &dispatcher_final_extended,
            &dispatcher_terminal_witness,
        )
        .unwrap()
        .witness,
        Some(dispatcher_final_predecessor_witness)
    );
    assert_eq!(
        semantic_factor_one_bad_transition(
            &final_queries_descriptor,
            &dispatcher_base_statement,
            &dispatcher_final_extended,
            &dispatcher_terminal_witness,
        )
        .unwrap(),
        None
    );

    let main_opening_statement = SemanticWhirOpeningBatchingStatement::new(
        fixture.statement.input_relation.clone(),
        fixture.statement.input_instance.clone(),
    )
    .expect("the simultaneous main opening statement derives");
    let combined_statement = SemanticPreWhirFinalAndMainOpeningStatement::new(
        &fixture.statement,
        &main_opening_statement,
    );
    let combined_predecessor_prefix = SemanticPreWhirFinalAndMainOpeningPrefix {
        pre_challenge_base: reveal_prefix(&fixture),
        main_opening: SemanticWhirOpeningBatchingPrefix {
            batching_challenge: None,
        },
    };
    let main_opening_challenge = field(103);
    let combined_extended_prefix = SemanticPreWhirFinalAndMainOpeningPrefix {
        pre_challenge_base: full_prefix.clone(),
        main_opening: SemanticWhirOpeningBatchingPrefix {
            batching_challenge: Some(main_opening_challenge),
        },
    };
    let combined_predecessor_witness =
        SemanticPreWhirFinalAndMainOpeningWitness::BeforeVerifierMove {
            pre_challenge_whir: fixture.blinded_witness.clone(),
            main_whir: fixture.input_witness.clone(),
        };
    let combined_post_challenge_witness =
        SemanticPreWhirFinalAndMainOpeningWitness::AfterVerifierMove {
            main_whir: fixture.input_witness.clone(),
        };
    assert!(
        semantic_pre_whir_final_and_main_opening_kstate(
            &combined_statement,
            &combined_predecessor_prefix,
            &combined_predecessor_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_pre_whir_final_and_main_opening_kstate(
            &combined_statement,
            &combined_extended_prefix,
            &combined_post_challenge_witness,
        )
        .unwrap()
    );
    let combined_extraction = semantic_pre_whir_final_and_main_opening_errbr(
        &combined_statement,
        &combined_extended_prefix,
        &combined_post_challenge_witness,
    )
    .expect("both backward extractors execute for the atomic verifier move");
    assert_eq!(
        combined_extraction.witness,
        Some(combined_predecessor_witness.clone())
    );
    assert!(combined_extraction.field_operation_count > 0);
    assert_eq!(
        semantic_pre_whir_final_and_main_opening_bad_transition(
            &combined_statement,
            &combined_extended_prefix,
            &combined_post_challenge_witness,
        )
        .unwrap(),
        None
    );
    let combined_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
    );
    let dispatcher_combined_statement: SemanticVerifierMoveStatement<
        '_,
        '_,
        SemanticUnusedCfwMatrices,
    > = SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
        pre_challenge_base: &fixture.statement,
        main_opening: &main_opening_statement,
    };
    let dispatcher_combined_predecessor =
        SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(
            combined_predecessor_prefix.clone(),
        );
    let dispatcher_combined_extended = SemanticVerifierMovePrefix::PreWhirFinalAndMainWhirOpening(
        combined_extended_prefix.clone(),
    );
    let dispatcher_combined_predecessor_witness =
        SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(combined_predecessor_witness);
    let dispatcher_combined_post_witness = SemanticKnowledgeWitness::PreWhirFinalAndMainWhirOpening(
        combined_post_challenge_witness.clone(),
    );
    assert!(
        semantic_factor_one_kstate(
            &combined_descriptor,
            &dispatcher_combined_statement,
            &dispatcher_combined_predecessor,
            &dispatcher_combined_predecessor_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_factor_one_kstate(
            &combined_descriptor,
            &dispatcher_combined_statement,
            &dispatcher_combined_extended,
            &dispatcher_combined_post_witness,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_factor_one_errbr(
            &combined_descriptor,
            &dispatcher_combined_statement,
            &dispatcher_combined_extended,
            &dispatcher_combined_post_witness,
        )
        .unwrap()
        .witness,
        Some(dispatcher_combined_predecessor_witness)
    );
    assert_eq!(
        semantic_factor_one_bad_transition(
            &combined_descriptor,
            &dispatcher_combined_statement,
            &dispatcher_combined_extended,
            &dispatcher_combined_post_witness,
        )
        .unwrap(),
        None
    );
    let mixed_combined_prefix = SemanticPreWhirFinalAndMainOpeningPrefix {
        pre_challenge_base: full_prefix,
        main_opening: SemanticWhirOpeningBatchingPrefix {
            batching_challenge: None,
        },
    };
    assert_eq!(
        semantic_pre_whir_final_and_main_opening_kstate(
            &combined_statement,
            &mixed_combined_prefix,
            &combined_post_challenge_witness,
        ),
        Err(SemanticCompositionError::MalformedCombinedPrefix)
    );
}

#[test]
fn base_prefix_refuses_changed_reveals_and_noncanonical_query_sets() {
    let fixture = base_fixture();
    let mut changed_reveal = reveal_prefix(&fixture);
    changed_reveal
        .revealed_witness
        .as_mut()
        .unwrap()
        .source
        .message_columns[0][0] = changed_reveal
        .revealed_witness
        .as_ref()
        .unwrap()
        .source
        .message_columns[0][0]
        .add(field(1));
    assert!(
        !semantic_whir_base_kstate(
            &fixture.statement,
            Some(&changed_reveal),
            &SemanticWhirBaseKnowledgeWitness::Blinded(fixture.blinded_witness.clone()),
        )
        .unwrap()
    );

    for source_positions in [vec![0, 0], vec![4, 0], vec![0, 8]] {
        let mut malformed = full_prefix(&fixture);
        malformed
            .query_challenges
            .as_mut()
            .unwrap()
            .source_positions = source_positions;
        assert_eq!(
            semantic_whir_base_kstate(
                &fixture.statement,
                Some(&malformed),
                &SemanticWhirBaseKnowledgeWitness::Terminal,
            ),
            Err(SemanticWhirError::MalformedPrefix)
        );
    }
}

#[test]
fn base_combination_bad_transition_derives_the_nonzero_linear_root() {
    let fixture = base_fixture();
    let target_delta = field(101);
    let mut changed_input_instance = fixture.statement.input_instance.clone();
    changed_input_instance.carried_reduction_claims[0].target = changed_input_instance
        .carried_reduction_claims[0]
        .target
        .add(target_delta);
    let changed_statement = SemanticWhirBaseStatement::new(
        fixture.statement.input_relation.clone(),
        changed_input_instance,
        fixture.statement.source_query_count,
        fixture.statement.mask_query_count,
    )
    .expect("changed statement remains well formed");
    let mut changed_prefix = combination_prefix(&fixture);
    changed_prefix.fresh_message.as_mut().unwrap().masked_claim = changed_prefix
        .fresh_message
        .as_ref()
        .unwrap()
        .masked_claim
        .subtract(fixture.combination_challenge.multiply(target_delta));
    assert!(
        semantic_whir_base_kstate(
            &changed_statement,
            Some(&changed_prefix),
            &SemanticWhirBaseKnowledgeWitness::Blinded(fixture.blinded_witness.clone()),
        )
        .unwrap()
    );
    let Some(SemanticWhirBaseCombinationBadTransition::NonzeroPolynomialRoot {
        coefficients,
        challenge,
    }) = semantic_whir_base_combination_bad_transition(
        &changed_statement,
        &changed_prefix,
        &fixture.blinded_witness,
    )
    .expect("bad transition derives")
    else {
        panic!("combination transition must derive the nonzero root")
    };
    assert_eq!(challenge, fixture.combination_challenge);
    assert!(
        coefficients
            .iter()
            .any(|coefficient| !coefficient.is_zero())
    );
    assert!(evaluate_polynomial(&coefficients, challenge).is_zero());
}

#[test]
fn base_combination_bad_transition_derives_exact_mca_certificate() {
    let fixture = base_fixture();
    let changed_position = 2;
    let cancellation = field(103);
    let mut changed_input_instance = fixture.statement.input_instance.clone();
    changed_input_instance.source.received_rows[changed_position][0] =
        changed_input_instance.source.received_rows[changed_position][0].add(cancellation);
    let changed_statement = SemanticWhirBaseStatement::new(
        fixture.statement.input_relation.clone(),
        changed_input_instance,
        fixture.statement.source_query_count,
        fixture.statement.mask_query_count,
    )
    .expect("changed statement remains well formed");
    let mut changed_prefix = combination_prefix(&fixture);
    changed_prefix
        .fresh_message
        .as_mut()
        .unwrap()
        .source
        .received_rows[changed_position][0] = changed_prefix
        .fresh_message
        .as_ref()
        .unwrap()
        .source
        .received_rows[changed_position][0]
        .subtract(fixture.combination_challenge.multiply(cancellation));
    assert!(
        semantic_whir_base_kstate(
            &changed_statement,
            Some(&changed_prefix),
            &SemanticWhirBaseKnowledgeWitness::Blinded(fixture.blinded_witness.clone()),
        )
        .unwrap()
    );
    let Some(SemanticWhirBaseCombinationBadTransition::MutualCorrelatedAgreement {
        role,
        certificate,
    }) = semantic_whir_base_combination_bad_transition(
        &changed_statement,
        &changed_prefix,
        &fixture.blinded_witness,
    )
    .unwrap()
    else {
        panic!("combination transition must derive an MCA certificate")
    };
    assert_eq!(role, SemanticWhirBaseOracleRole::Source);
    assert_eq!(
        certificate.combination,
        SemanticWhirMcaCombination::AdditiveCombination
    );
    assert_eq!(certificate.challenge, fixture.combination_challenge);
    assert_eq!(certificate.agreement_positions, (0..8).collect::<Vec<_>>());
    assert_eq!(certificate.target_domain_size, 8);
    assert_eq!(certificate.selected_decoding_error_count, 2);
    assert_eq!(
        certificate.uncorrectable_component,
        SemanticWhirMcaUncorrectableComponent::First
    );
    assert_eq!(certificate.correlated_function_count(), 2);
    assert_eq!(certificate.exact_error_numerator().unwrap(), 8);
}

#[test]
fn base_final_bad_transition_derives_exact_distinct_query_escape() {
    let fixture = base_fixture();
    let mut changed_full_prefix = full_prefix(&fixture);
    for (offset, position) in [1_usize, 2, 3].into_iter().enumerate() {
        changed_full_prefix
            .fresh_message
            .as_mut()
            .unwrap()
            .source
            .received_rows[position][0] = changed_full_prefix
            .fresh_message
            .as_ref()
            .unwrap()
            .source
            .received_rows[position][0]
            .add(field(107 + u64::try_from(offset).unwrap()));
    }
    assert!(
        semantic_whir_base_kstate(
            &fixture.statement,
            Some(&changed_full_prefix),
            &SemanticWhirBaseKnowledgeWitness::Terminal,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_whir_base_final_bad_transition(&fixture.statement, &changed_full_prefix).unwrap(),
        Some(vec![SemanticWhirBaseQueryEscape {
            role: SemanticWhirBaseOracleRole::Source,
            differing_row_count: 3,
            query_positions: vec![0, 4],
        }])
    );
}
