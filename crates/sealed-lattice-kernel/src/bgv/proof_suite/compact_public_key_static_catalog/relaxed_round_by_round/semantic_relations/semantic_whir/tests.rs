use super::super::super::TranscriptEpoch;
use super::super::semantic_execution::{
    SemanticFactorOneMoveDescriptor, SemanticKnowledgeWitness, SemanticUnusedCfwMatrices,
    SemanticVerifierMoveOwner, SemanticVerifierMovePrefix, SemanticVerifierMoveStatement,
    semantic_factor_one_bad_transition, semantic_factor_one_errbr, semantic_factor_one_kstate,
};
use super::*;
use crate::bgv::proof_suite::ProofBaseFieldElement;
use crate::bgv::proof_suite::compact_public_key_static_catalog::relaxed_round_by_round::MaskGroupRole;

fn field(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(value).expect("small canonical field value"),
    )
}

fn committed_code_relation(
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
    first_randomness_value: u64,
) -> (SemanticCommittedCodeInstance, SemanticCommittedCodeWitness) {
    let width = usize::try_from(relation.interleaving_width).unwrap();
    let randomness_length = usize::try_from(relation.hiding_randomness_length).unwrap();
    assert_eq!(message_columns.len(), width);
    let hiding_randomness_columns = (0..width)
        .map(|column_ordinal| {
            (0..randomness_length)
                .map(|coefficient_ordinal| {
                    field(
                        first_randomness_value
                            + u64::try_from(column_ordinal * 17 + coefficient_ordinal).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let witness = SemanticCommittedCodeWitness {
        message_columns,
        hiding_randomness_columns,
    };
    let received_rows = encode_canonical_interleaved_reed_solomon(
        semantic_code_geometry(relation).unwrap(),
        &witness.coefficient_columns(relation).unwrap(),
    )
    .unwrap();
    (SemanticCommittedCodeInstance { received_rows }, witness)
}

struct MaskedSumcheckFixture {
    statement: SemanticWhirMaskedSumcheckStatement,
    input_witness: SemanticGeneralizedRelationWitness,
    sumcheck_mask_witness: SemanticCommittedCodeWitness,
}

fn masked_sumcheck_fixture(
    input_target_delta: ProofChallengeExtensionElement,
) -> MaskedSumcheckFixture {
    let source_relation = committed_code_relation(2, 1, 8, 4);
    let carried_mask_code = committed_code_relation(2, 1, 8, 1);
    let sumcheck_mask_code = committed_code_relation(4, 1, 8, 2);
    let (source_instance, source_witness) = code_fixture(
        &source_relation,
        vec![
            vec![field(2), field(3)],
            vec![field(5), field(7)],
            vec![field(11), field(13)],
            vec![field(17), field(19)],
        ],
        101,
    );
    let (carried_mask_instance, carried_mask_witness) =
        code_fixture(&carried_mask_code, vec![vec![field(23), field(29)]], 151);
    let (sumcheck_mask_instance, sumcheck_mask_witness) = code_fixture(
        &sumcheck_mask_code,
        vec![
            vec![field(31), field(37), field(41), field(43)],
            vec![field(47), field(53), field(59), field(61)],
        ],
        211,
    );
    let input_witness = SemanticGeneralizedRelationWitness {
        source: source_witness,
        masks: vec![carried_mask_witness],
    };
    let source_covector = (0..8_u64)
        .map(|ordinal| field(67 + ordinal))
        .collect::<Vec<_>>();
    let carried_mask_covector = vec![field(79), field(83)];
    let mut input_claim = SemanticGeneralizedLinearClaim {
        source_covector,
        mask_covectors: vec![carried_mask_covector],
        target: ProofChallengeExtensionElement::ZERO,
    };
    input_claim.target = evaluate_claim(&input_claim, &input_witness)
        .unwrap()
        .add(input_target_delta);
    let input_relation = GeneralizedCommittedRelation {
        source_code: source_relation,
        mask_codes: vec![CommittedMaskCodeRelation {
            role: MaskGroupRole::CrossEpochOpening,
            code: carried_mask_code,
        }],
        source_message_element_count: 8,
        source_hiding_element_count: 4,
        mask_message_element_count: 2,
        covector_extension_element_count: 11,
        opening_evaluation_claim_count: 0,
        carried_reduction_claim_count: 1,
        claim_count: 1,
    };
    let input_instance = SemanticGeneralizedRelationInstance {
        source: source_instance,
        masks: vec![carried_mask_instance],
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![input_claim],
    };
    let statement = SemanticWhirMaskedSumcheckStatement::new(
        input_relation,
        input_instance,
        CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirSumcheck { batch_ordinal: 0 },
            code: sumcheck_mask_code,
        },
        sumcheck_mask_instance,
    )
    .expect("small masked-sumcheck statement derives");
    MaskedSumcheckFixture {
        statement,
        input_witness,
        sumcheck_mask_witness,
    }
}

fn stage_zero_witness(fixture: &MaskedSumcheckFixture) -> SemanticGeneralizedRelationWitness {
    let mut masks = fixture.input_witness.masks.clone();
    masks.push(fixture.sumcheck_mask_witness.clone());
    SemanticGeneralizedRelationWitness {
        source: fixture.input_witness.source.clone(),
        masks,
    }
}

fn wire_from_polynomial(
    polynomial: &[ProofChallengeExtensionElement],
) -> Vec<ProofChallengeExtensionElement> {
    core::iter::once(polynomial[0])
        .chain(polynomial[2..].iter().copied())
        .collect()
}

#[test]
fn masked_sumcheck_kstate_and_errbr_execute_every_prover_and_verifier_prefix() {
    let fixture = masked_sumcheck_fixture(ProofChallengeExtensionElement::ZERO);
    let statement = &fixture.statement;
    assert_eq!(statement.folding_factor(), 2);
    assert_eq!(statement.wire_coefficient_count(), 3);
    assert!(
        semantic_whir_masked_sumcheck_kstate(statement, None, &fixture.input_witness,).unwrap()
    );

    let mask_hypercube_sum =
        sumcheck_mask_hypercube_sum(&fixture.sumcheck_mask_witness, 2).unwrap();
    let prover_mask_prefix = SemanticWhirMaskedSumcheckPrefix {
        mask_hypercube_sum,
        combining_challenge: None,
        round_wires: Vec::new(),
        round_challenges: Vec::new(),
    };
    assert!(
        semantic_whir_masked_sumcheck_kstate(
            statement,
            Some(&prover_mask_prefix),
            &fixture.input_witness,
        )
        .unwrap()
    );

    let mut prefix = SemanticWhirMaskedSumcheckPrefix {
        combining_challenge: Some(field(89)),
        ..prover_mask_prefix.clone()
    };
    let mut current_witness = stage_zero_witness(&fixture);
    assert!(
        semantic_whir_masked_sumcheck_kstate(statement, Some(&prefix), &current_witness,).unwrap()
    );
    let combining_extraction =
        semantic_whir_masked_sumcheck_errbr(statement, &prefix, &current_witness)
            .expect("combining extractor executes");
    assert_eq!(
        combining_extraction.witness,
        Some(fixture.input_witness.clone())
    );
    assert!(combining_extraction.field_operation_count > 0);
    let dispatcher_statement: SemanticVerifierMoveStatement<'_, '_, SemanticUnusedCfwMatrices> =
        SemanticVerifierMoveStatement::WhirMaskedSumcheck(statement);
    let combining_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
            epoch: TranscriptEpoch::PreChallenge,
            batch_ordinal: 0,
        },
    );
    let dispatcher_combining_predecessor =
        SemanticVerifierMovePrefix::WhirMaskedSumcheck(prover_mask_prefix);
    let dispatcher_combining_extended =
        SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix.clone());
    let dispatcher_input_witness =
        SemanticKnowledgeWitness::Generalized(fixture.input_witness.clone());
    let dispatcher_current_witness = SemanticKnowledgeWitness::Generalized(current_witness.clone());
    assert!(
        semantic_factor_one_kstate(
            &combining_descriptor,
            &dispatcher_statement,
            &dispatcher_combining_predecessor,
            &dispatcher_input_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_factor_one_kstate(
            &combining_descriptor,
            &dispatcher_statement,
            &dispatcher_combining_extended,
            &dispatcher_current_witness,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_factor_one_errbr(
            &combining_descriptor,
            &dispatcher_statement,
            &dispatcher_combining_extended,
            &dispatcher_current_witness,
        )
        .unwrap()
        .witness,
        Some(dispatcher_input_witness)
    );
    assert_eq!(
        semantic_factor_one_bad_transition(
            &combining_descriptor,
            &dispatcher_statement,
            &dispatcher_combining_extended,
            &dispatcher_current_witness,
        )
        .unwrap(),
        None
    );

    for challenge in [field(97), field(103)] {
        let round_ordinal = prefix.round_challenges.len();
        let (preceding_relation, preceding_instance) = relation_after_challenges(
            statement,
            &prefix,
            prefix.combining_challenge.unwrap(),
            round_ordinal,
        )
        .unwrap();
        let polynomial = expected_round_polynomial(
            statement,
            &preceding_relation,
            &preceding_instance,
            &current_witness,
            round_ordinal,
        )
        .unwrap();
        prefix.round_wires.push(wire_from_polynomial(&polynomial));
        assert!(
            semantic_whir_masked_sumcheck_kstate(statement, Some(&prefix), &current_witness,)
                .unwrap()
        );

        let preceding_witness = current_witness.clone();
        let dispatcher_round_predecessor =
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix.clone());
        let dispatcher_preceding_witness =
            SemanticKnowledgeWitness::Generalized(preceding_witness.clone());
        prefix.round_challenges.push(challenge);
        current_witness = fold_generalized_witness_once(&current_witness, challenge).unwrap();
        assert!(
            semantic_whir_masked_sumcheck_kstate(statement, Some(&prefix), &current_witness,)
                .unwrap()
        );
        let extraction = semantic_whir_masked_sumcheck_errbr(statement, &prefix, &current_witness)
            .expect("round extractor executes");
        assert_eq!(extraction.witness, Some(preceding_witness));
        assert!(extraction.field_operation_count > 0);
        assert_eq!(
            semantic_whir_masked_sumcheck_bad_transition(statement, &prefix, &current_witness)
                .unwrap(),
            None
        );
        let round_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
            SemanticVerifierMoveOwner::WhirFolding {
                epoch: TranscriptEpoch::PreChallenge,
                batch_ordinal: 0,
                round_ordinal: u8::try_from(round_ordinal).unwrap(),
            },
        );
        let dispatcher_round_extended =
            SemanticVerifierMovePrefix::WhirMaskedSumcheck(prefix.clone());
        let dispatcher_folded_witness =
            SemanticKnowledgeWitness::Generalized(current_witness.clone());
        assert!(
            semantic_factor_one_kstate(
                &round_descriptor,
                &dispatcher_statement,
                &dispatcher_round_predecessor,
                &dispatcher_preceding_witness,
            )
            .unwrap()
        );
        assert!(
            semantic_factor_one_kstate(
                &round_descriptor,
                &dispatcher_statement,
                &dispatcher_round_extended,
                &dispatcher_folded_witness,
            )
            .unwrap()
        );
        assert_eq!(
            semantic_factor_one_errbr(
                &round_descriptor,
                &dispatcher_statement,
                &dispatcher_round_extended,
                &dispatcher_folded_witness,
            )
            .unwrap()
            .witness,
            Some(dispatcher_preceding_witness)
        );
        assert_eq!(
            semantic_factor_one_bad_transition(
                &round_descriptor,
                &dispatcher_statement,
                &dispatcher_round_extended,
                &dispatcher_folded_witness,
            )
            .unwrap(),
            None
        );
    }

    let (output_relation, output_instance) = relation_after_challenges(
        statement,
        &prefix,
        prefix.combining_challenge.unwrap(),
        statement.folding_factor(),
    )
    .unwrap();
    assert_eq!(output_relation.source_code.interleaving_width, 1);
    assert_eq!(output_relation.mask_codes.len(), 2);
    assert_eq!(output_relation.claim_count, 1);
    assert!(
        semantic_generalized_relation_holds(&output_relation, &output_instance, &current_witness,)
            .unwrap()
    );

    let mut changed_wire = prefix.clone();
    changed_wire.round_wires[1][2] = changed_wire.round_wires[1][2].add(field(1));
    assert!(
        !semantic_whir_masked_sumcheck_kstate(statement, Some(&changed_wire), &current_witness,)
            .unwrap()
    );

    let mut malformed = prefix;
    malformed.round_challenges.push(field(107));
    assert_eq!(
        semantic_whir_masked_sumcheck_kstate(statement, Some(&malformed), &current_witness),
        Err(SemanticWhirError::MalformedPrefix)
    );
}

#[test]
fn combining_bad_transition_derives_the_nonzero_root_polynomial() {
    let target_delta = field(109);
    let fixture = masked_sumcheck_fixture(target_delta);
    assert!(
        !semantic_whir_masked_sumcheck_kstate(&fixture.statement, None, &fixture.input_witness,)
            .unwrap()
    );
    let challenge = field(113);
    let actual_mask_sum = sumcheck_mask_hypercube_sum(&fixture.sumcheck_mask_witness, 2).unwrap();
    let mask_hypercube_sum = actual_mask_sum.subtract(challenge.multiply(target_delta));
    let prefix = SemanticWhirMaskedSumcheckPrefix {
        mask_hypercube_sum,
        combining_challenge: Some(challenge),
        round_wires: Vec::new(),
        round_challenges: Vec::new(),
    };
    let post_witness = stage_zero_witness(&fixture);
    assert!(
        semantic_whir_masked_sumcheck_kstate(&fixture.statement, Some(&prefix), &post_witness,)
            .unwrap()
    );
    assert_eq!(
        semantic_whir_masked_sumcheck_errbr(&fixture.statement, &prefix, &post_witness)
            .unwrap()
            .witness,
        Some(fixture.input_witness.clone())
    );
    let Some(SemanticWhirBadTransition::NonzeroPolynomialRoot {
        transition,
        coefficients,
        challenge: derived_challenge,
    }) = semantic_whir_masked_sumcheck_bad_transition(&fixture.statement, &prefix, &post_witness)
        .unwrap()
    else {
        panic!("combining bad transition must derive a root polynomial");
    };
    assert_eq!(
        transition,
        SemanticWhirVerifierTransition::CombiningChallenge
    );
    assert_eq!(derived_challenge, challenge);
    assert!(
        coefficients
            .iter()
            .any(|coefficient| !coefficient.is_zero())
    );
    assert!(evaluate_polynomial(&coefficients, challenge).is_zero());
}

#[test]
fn round_bad_transition_derives_the_nonzero_root_polynomial() {
    let fixture = masked_sumcheck_fixture(ProofChallengeExtensionElement::ZERO);
    let statement = &fixture.statement;
    let combining_challenge = field(127);
    let honest_mask_sum = sumcheck_mask_hypercube_sum(&fixture.sumcheck_mask_witness, 2).unwrap();
    let mut prefix = SemanticWhirMaskedSumcheckPrefix {
        mask_hypercube_sum: honest_mask_sum.add(field(131)),
        combining_challenge: Some(combining_challenge),
        round_wires: Vec::new(),
        round_challenges: Vec::new(),
    };
    let preceding_witness = stage_zero_witness(&fixture);
    assert!(
        !semantic_whir_masked_sumcheck_kstate(statement, Some(&prefix), &preceding_witness,)
            .unwrap()
    );
    let (preceding_relation, preceding_instance) =
        relation_after_challenges(statement, &prefix, combining_challenge, 0).unwrap();
    let actual_polynomial = expected_round_polynomial(
        statement,
        &preceding_relation,
        &preceding_instance,
        &preceding_witness,
        0,
    )
    .unwrap();
    let challenge = field(137);
    let desired_target = evaluate_polynomial(&actual_polynomial, challenge);
    let prior_target = replay_target(statement, &prefix, 0).unwrap();
    let denominator = ProofChallengeExtensionElement::ONE.subtract(challenge.add(challenge));
    let constant = desired_target
        .subtract(prior_target.multiply(challenge))
        .multiply(
            denominator
                .inverse()
                .expect("selected challenge is not one half"),
        );
    prefix.round_wires.push(vec![
        constant,
        ProofChallengeExtensionElement::ZERO,
        ProofChallengeExtensionElement::ZERO,
    ]);
    prefix.round_challenges.push(challenge);
    let post_witness = fold_generalized_witness_once(&preceding_witness, challenge).unwrap();
    assert!(
        semantic_whir_masked_sumcheck_kstate(statement, Some(&prefix), &post_witness,).unwrap()
    );
    let Some(SemanticWhirBadTransition::NonzeroPolynomialRoot {
        transition,
        coefficients,
        challenge: derived_challenge,
    }) = semantic_whir_masked_sumcheck_bad_transition(statement, &prefix, &post_witness).unwrap()
    else {
        panic!("round bad transition must derive a root polynomial");
    };
    assert_eq!(
        transition,
        SemanticWhirVerifierTransition::SumcheckRound { round_ordinal: 0 }
    );
    assert_eq!(derived_challenge, challenge);
    assert!(
        coefficients
            .iter()
            .any(|coefficient| !coefficient.is_zero())
    );
    assert!(evaluate_polynomial(&coefficients, challenge).is_zero());
}

#[test]
fn round_bad_transition_derives_exact_binary_fold_mca_certificate() {
    let fixture = masked_sumcheck_fixture(ProofChallengeExtensionElement::ZERO);
    let folding_challenge = field(149);
    let inverse_folding_challenge = folding_challenge
        .inverse()
        .expect("selected folding challenge is nonzero");
    let first_scale = ProofChallengeExtensionElement::ONE.subtract(folding_challenge);
    let mut changed_input_instance = fixture.statement.input_instance.clone();
    for (offset, row_position) in [0_usize, 1, 2].into_iter().enumerate() {
        let first_error = field(151 + u64::try_from(offset).unwrap());
        let second_error = ProofChallengeExtensionElement::ZERO.subtract(
            first_scale
                .multiply(first_error)
                .multiply(inverse_folding_challenge),
        );
        changed_input_instance.source.received_rows[row_position][0] =
            changed_input_instance.source.received_rows[row_position][0].add(first_error);
        changed_input_instance.source.received_rows[row_position][2] =
            changed_input_instance.source.received_rows[row_position][2].add(second_error);
    }
    let statement = SemanticWhirMaskedSumcheckStatement::new(
        fixture.statement.input_relation.clone(),
        changed_input_instance,
        fixture.statement.sumcheck_mask_relation.clone(),
        fixture.statement.sumcheck_mask_instance.clone(),
    )
    .expect("changed statement remains well formed");
    let combining_challenge = field(157);
    let mut prefix = SemanticWhirMaskedSumcheckPrefix {
        mask_hypercube_sum: sumcheck_mask_hypercube_sum(&fixture.sumcheck_mask_witness, 2).unwrap(),
        combining_challenge: Some(combining_challenge),
        round_wires: Vec::new(),
        round_challenges: Vec::new(),
    };
    let preceding_witness = stage_zero_witness(&fixture);
    let (preceding_relation, preceding_instance) =
        relation_after_challenges(&statement, &prefix, combining_challenge, 0).unwrap();
    let round_polynomial = expected_round_polynomial(
        &statement,
        &preceding_relation,
        &preceding_instance,
        &preceding_witness,
        0,
    )
    .unwrap();
    prefix
        .round_wires
        .push(wire_from_polynomial(&round_polynomial));
    prefix.round_challenges.push(folding_challenge);
    let post_witness =
        fold_generalized_witness_once(&preceding_witness, folding_challenge).unwrap();
    assert!(
        semantic_whir_masked_sumcheck_kstate(&statement, Some(&prefix), &post_witness).unwrap()
    );
    assert_eq!(
        semantic_whir_masked_sumcheck_errbr(&statement, &prefix, &post_witness)
            .unwrap()
            .witness,
        None
    );
    let Some(SemanticWhirBadTransition::MutualCorrelatedAgreement {
        transition,
        certificate,
    }) = semantic_whir_masked_sumcheck_bad_transition(&statement, &prefix, &post_witness).unwrap()
    else {
        panic!("fold transition must derive an MCA certificate")
    };
    assert_eq!(
        transition,
        SemanticWhirVerifierTransition::SumcheckRound { round_ordinal: 0 }
    );
    assert_eq!(
        certificate.combination,
        SemanticWhirMcaCombination::AffineFold
    );
    assert_eq!(certificate.challenge, folding_challenge);
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

struct CodeSwitchFixture {
    statement: SemanticWhirCodeSwitchStatement,
    input_witness: SemanticGeneralizedRelationWitness,
    output_witness: SemanticGeneralizedRelationWitness,
}

fn code_switch_fixture() -> CodeSwitchFixture {
    let input_source_relation = committed_code_relation(4, 2, 16, 1);
    let carried_mask_code = committed_code_relation(1, 1, 8, 1);
    let output_source_relation = committed_code_relation(2, 2, 8, 2);
    let switch_mask_code = committed_code_relation(2, 1, 8, 1);
    let source_message = vec![field(2), field(3), field(5), field(7)];
    let (input_source_instance, input_source_witness) =
        code_fixture(&input_source_relation, vec![source_message.clone()], 101);
    let (carried_mask_instance, carried_mask_witness) =
        code_fixture(&carried_mask_code, vec![vec![field(11)]], 131);
    let (output_source_instance, output_source_witness) = code_fixture(
        &output_source_relation,
        vec![source_message[..2].to_vec(), source_message[2..].to_vec()],
        151,
    );
    let (switch_mask_instance, switch_mask_witness) = code_fixture(
        &switch_mask_code,
        vec![input_source_witness.hiding_randomness_columns[0].clone()],
        181,
    );
    let input_witness = SemanticGeneralizedRelationWitness {
        source: input_source_witness,
        masks: vec![carried_mask_witness.clone()],
    };
    let mut input_claim = SemanticGeneralizedLinearClaim {
        source_covector: vec![field(191), field(193), field(197), field(199)],
        mask_covectors: vec![vec![field(211)]],
        target: ProofChallengeExtensionElement::ZERO,
    };
    input_claim.target = evaluate_claim(&input_claim, &input_witness).unwrap();
    let input_relation = GeneralizedCommittedRelation {
        source_code: input_source_relation,
        mask_codes: vec![CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirSumcheck { batch_ordinal: 0 },
            code: carried_mask_code,
        }],
        source_message_element_count: 4,
        source_hiding_element_count: 2,
        mask_message_element_count: 1,
        covector_extension_element_count: 6,
        opening_evaluation_claim_count: 0,
        carried_reduction_claim_count: 1,
        claim_count: 1,
    };
    let input_instance = SemanticGeneralizedRelationInstance {
        source: input_source_instance,
        masks: vec![carried_mask_instance],
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![input_claim],
    };
    let statement = SemanticWhirCodeSwitchStatement::new(
        input_relation,
        input_instance,
        output_source_relation,
        output_source_instance,
        CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirCodeSwitch { round_ordinal: 0 },
            code: switch_mask_code,
        },
        switch_mask_instance,
        2,
    )
    .expect("small code-switch statement derives");
    let output_witness = SemanticGeneralizedRelationWitness {
        source: output_source_witness,
        masks: vec![carried_mask_witness, switch_mask_witness],
    };
    CodeSwitchFixture {
        statement,
        input_witness,
        output_witness,
    }
}

fn rebuild_code_switch_statement(
    statement: &SemanticWhirCodeSwitchStatement,
    input_instance: SemanticGeneralizedRelationInstance,
) -> SemanticWhirCodeSwitchStatement {
    SemanticWhirCodeSwitchStatement::new(
        statement.input_relation.clone(),
        input_instance,
        statement.output_source_relation.clone(),
        statement.output_source_instance.clone(),
        statement.switch_mask_relation.clone(),
        statement.switch_mask_instance.clone(),
        statement.query_count,
    )
    .expect("mutated code-switch statement remains well formed")
}

#[test]
fn code_switch_kstate_and_errbr_reencode_the_preceding_source() {
    let fixture = code_switch_fixture();
    assert!(
        semantic_whir_code_switch_kstate(&fixture.statement, None, &fixture.input_witness,)
            .unwrap()
    );
    let prover_prefix = SemanticWhirCodeSwitchPrefix {
        query_positions: None,
        combination_challenge: None,
    };
    assert!(
        semantic_whir_code_switch_kstate(
            &fixture.statement,
            Some(&prover_prefix),
            &fixture.input_witness,
        )
        .unwrap()
    );
    let prefix = SemanticWhirCodeSwitchPrefix {
        query_positions: Some(vec![1, 6]),
        combination_challenge: Some(field(223)),
    };
    assert!(
        semantic_whir_code_switch_kstate(
            &fixture.statement,
            Some(&prefix),
            &fixture.output_witness,
        )
        .unwrap()
    );
    let extraction =
        semantic_whir_code_switch_errbr(&fixture.statement, &prefix, &fixture.output_witness)
            .expect("code-switch extractor executes");
    assert_eq!(extraction.witness, Some(fixture.input_witness.clone()));
    assert!(extraction.field_operation_count > 0);
    assert_eq!(
        semantic_whir_code_switch_bad_transition(
            &fixture.statement,
            &prefix,
            &fixture.output_witness,
        )
        .unwrap(),
        None
    );

    let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::WhirCodeSwitch {
            epoch: TranscriptEpoch::PreChallenge,
            round_ordinal: 0,
        },
    );
    let dispatcher_statement: SemanticVerifierMoveStatement<'_, '_, SemanticUnusedCfwMatrices> =
        SemanticVerifierMoveStatement::WhirCodeSwitch(&fixture.statement);
    let dispatcher_predecessor = SemanticVerifierMovePrefix::WhirCodeSwitch(prover_prefix);
    let dispatcher_extended = SemanticVerifierMovePrefix::WhirCodeSwitch(prefix.clone());
    let dispatcher_input_witness =
        SemanticKnowledgeWitness::Generalized(fixture.input_witness.clone());
    let dispatcher_output_witness =
        SemanticKnowledgeWitness::Generalized(fixture.output_witness.clone());
    assert!(
        semantic_factor_one_kstate(
            &descriptor,
            &dispatcher_statement,
            &dispatcher_predecessor,
            &dispatcher_input_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_factor_one_kstate(
            &descriptor,
            &dispatcher_statement,
            &dispatcher_extended,
            &dispatcher_output_witness,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_factor_one_errbr(
            &descriptor,
            &dispatcher_statement,
            &dispatcher_extended,
            &dispatcher_output_witness,
        )
        .unwrap()
        .witness,
        Some(dispatcher_input_witness)
    );
    assert_eq!(
        semantic_factor_one_bad_transition(
            &descriptor,
            &dispatcher_statement,
            &dispatcher_extended,
            &dispatcher_output_witness,
        )
        .unwrap(),
        None
    );

    let duplicate_queries = SemanticWhirCodeSwitchPrefix {
        query_positions: Some(vec![1, 1]),
        combination_challenge: Some(field(227)),
    };
    assert_eq!(
        semantic_whir_code_switch_kstate(
            &fixture.statement,
            Some(&duplicate_queries),
            &fixture.output_witness,
        ),
        Err(SemanticWhirError::MalformedPrefix)
    );
}

#[test]
fn code_switch_bad_transition_derives_exact_query_escape() {
    let fixture = code_switch_fixture();
    let mut changed_input_instance = fixture.statement.input_instance.clone();
    for position in [0_usize, 2, 3, 4, 5] {
        changed_input_instance.source.received_rows[position][0] =
            changed_input_instance.source.received_rows[position][0]
                .add(field(1 + u64::try_from(position).unwrap()));
    }
    let statement = rebuild_code_switch_statement(&fixture.statement, changed_input_instance);
    assert!(!semantic_whir_code_switch_kstate(&statement, None, &fixture.input_witness,).unwrap());
    let prefix = SemanticWhirCodeSwitchPrefix {
        query_positions: Some(vec![1, 6]),
        combination_challenge: Some(field(229)),
    };
    assert!(
        semantic_whir_code_switch_kstate(&statement, Some(&prefix), &fixture.output_witness,)
            .unwrap()
    );
    assert_eq!(
        semantic_whir_code_switch_bad_transition(&statement, &prefix, &fixture.output_witness)
            .unwrap(),
        Some(SemanticWhirCodeSwitchBadTransition::QueryEscape {
            differing_row_count: 5,
            query_positions: vec![1, 6],
        })
    );
}

#[test]
fn code_switch_bad_transition_derives_combination_root() {
    let fixture = code_switch_fixture();
    let combination_challenge = field(233);
    let target_delta = field(239);
    let query_error = target_delta.multiply(
        combination_challenge
            .inverse()
            .expect("combination challenge is nonzero"),
    );
    let mut changed_input_instance = fixture.statement.input_instance.clone();
    changed_input_instance.carried_reduction_claims[0].target = changed_input_instance
        .carried_reduction_claims[0]
        .target
        .add(target_delta);
    changed_input_instance.source.received_rows[1][0] =
        changed_input_instance.source.received_rows[1][0].subtract(query_error);
    let statement = rebuild_code_switch_statement(&fixture.statement, changed_input_instance);
    assert!(!semantic_whir_code_switch_kstate(&statement, None, &fixture.input_witness,).unwrap());
    let prefix = SemanticWhirCodeSwitchPrefix {
        query_positions: Some(vec![1, 6]),
        combination_challenge: Some(combination_challenge),
    };
    assert!(
        semantic_whir_code_switch_kstate(&statement, Some(&prefix), &fixture.output_witness,)
            .unwrap()
    );
    let Some(SemanticWhirCodeSwitchBadTransition::NonzeroCombinationPolynomialRoot {
        coefficients,
        challenge,
    }) = semantic_whir_code_switch_bad_transition(&statement, &prefix, &fixture.output_witness)
        .unwrap()
    else {
        panic!("code-switch bad transition must derive a combination root");
    };
    assert_eq!(challenge, combination_challenge);
    assert!(
        coefficients
            .iter()
            .any(|coefficient| !coefficient.is_zero())
    );
    assert!(evaluate_polynomial(&coefficients, challenge).is_zero());
}

fn epoch_input_pair(
    external_mask_roles: &[MaskGroupRole],
    first_value: u64,
) -> (
    GeneralizedCommittedRelation,
    SemanticGeneralizedRelationInstance,
    SemanticGeneralizedRelationWitness,
) {
    let source_relation = committed_code_relation(64, 2, 128, 8);
    let source_messages = (0..8_usize)
        .map(|column_ordinal| {
            (0..64_usize)
                .map(|coefficient_ordinal| {
                    field(
                        first_value
                            + u64::try_from(column_ordinal * 71 + coefficient_ordinal).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let (source_instance, source_witness) =
        code_fixture(&source_relation, source_messages, first_value + 1_000);

    let mut mask_relations = Vec::new();
    let mut mask_instances = Vec::new();
    let mut mask_witnesses = Vec::new();
    for (group_ordinal, role) in external_mask_roles.iter().copied().enumerate() {
        let (message_length, width, block_length) = match role {
            MaskGroupRole::CfwInner => (4_u64, 2_u64, 16_u64),
            MaskGroupRole::CfwOuter => (8_u64, 1_u64, 32_u64),
            MaskGroupRole::CrossEpochOpening => (1_u64, 2_u64, 8_u64),
            _ => panic!("epoch inputs accept only production external mask roles"),
        };
        let code = committed_code_relation(message_length, 1, block_length, width);
        let messages = (0..usize::try_from(width).unwrap())
            .map(|column_ordinal| {
                (0..usize::try_from(message_length).unwrap())
                    .map(|coefficient_ordinal| {
                        field(
                            first_value
                                + 2_000
                                + u64::try_from(
                                    group_ordinal * 101 + column_ordinal * 17 + coefficient_ordinal,
                                )
                                .unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let (instance, witness) = code_fixture(
            &code,
            messages,
            first_value + 3_000 + u64::try_from(group_ordinal * 31).unwrap(),
        );
        mask_relations.push(CommittedMaskCodeRelation { role, code });
        mask_instances.push(instance);
        mask_witnesses.push(witness);
    }

    let witness = SemanticGeneralizedRelationWitness {
        source: source_witness,
        masks: mask_witnesses,
    };
    let mut claim = SemanticGeneralizedLinearClaim {
        source_covector: (0..512_usize)
            .map(|ordinal| field(first_value + 4_000 + u64::try_from(ordinal).unwrap()))
            .collect(),
        mask_covectors: witness
            .masks
            .iter()
            .enumerate()
            .map(|(group_ordinal, mask)| {
                vec![
                    field(first_value + 5_000 + u64::try_from(group_ordinal).unwrap());
                    mask.flattened_messages().len()
                ]
            })
            .collect(),
        target: ProofChallengeExtensionElement::ZERO,
    };
    claim.target = evaluate_claim(&claim, &witness).expect("epoch input claim evaluates");
    let mask_message_element_count = mask_relations
        .iter()
        .map(|mask| mask.code.message_length * mask.code.interleaving_width)
        .sum::<u64>();
    let relation = GeneralizedCommittedRelation {
        source_code: source_relation,
        mask_codes: mask_relations,
        source_message_element_count: 512,
        source_hiding_element_count: 16,
        mask_message_element_count,
        covector_extension_element_count: 513 + mask_message_element_count,
        opening_evaluation_claim_count: 0,
        carried_reduction_claim_count: 1,
        claim_count: 1,
    };
    let instance = SemanticGeneralizedRelationInstance {
        source: source_instance,
        masks: mask_instances,
        opening_claims: Vec::new(),
        carried_reduction_claims: vec![claim],
    };
    assert!(semantic_generalized_relation_holds(&relation, &instance, &witness).unwrap());
    (relation, instance, witness)
}

fn execute_masked_sumcheck_boundary(
    input_relation: GeneralizedCommittedRelation,
    input_instance: SemanticGeneralizedRelationInstance,
    input_witness: SemanticGeneralizedRelationWitness,
    batch_ordinal: u8,
) -> (
    GeneralizedCommittedRelation,
    SemanticGeneralizedRelationInstance,
    SemanticGeneralizedRelationWitness,
) {
    let source_width = usize::try_from(input_relation.source_code.interleaving_width).unwrap();
    let folding_factor = source_width.ilog2() as usize;
    let sumcheck_mask_code =
        committed_code_relation(4, 1, 16, u64::try_from(folding_factor).unwrap());
    let sumcheck_mask_messages = (0..folding_factor)
        .map(|mask_ordinal| {
            (0..4_usize)
                .map(|coefficient_ordinal| {
                    field(
                        10_000
                            + u64::from(batch_ordinal) * 101
                            + u64::try_from(mask_ordinal * 11 + coefficient_ordinal).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let (sumcheck_mask_instance, sumcheck_mask_witness) = code_fixture(
        &sumcheck_mask_code,
        sumcheck_mask_messages,
        11_000 + u64::from(batch_ordinal) * 101,
    );
    let statement = SemanticWhirMaskedSumcheckStatement::new(
        input_relation.clone(),
        input_instance.clone(),
        CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirSumcheck { batch_ordinal },
            code: sumcheck_mask_code,
        },
        sumcheck_mask_instance,
    )
    .expect("masked-sumcheck component derives from the preceding output pair");
    assert_eq!(statement.input_relation, input_relation);
    assert_eq!(statement.input_instance, input_instance);
    assert!(semantic_whir_masked_sumcheck_kstate(&statement, None, &input_witness).unwrap());

    let mut prefix = SemanticWhirMaskedSumcheckPrefix {
        mask_hypercube_sum: sumcheck_mask_hypercube_sum(&sumcheck_mask_witness, folding_factor)
            .unwrap(),
        combining_challenge: Some(field(12_001 + u64::from(batch_ordinal) * 101)),
        round_wires: Vec::new(),
        round_challenges: Vec::new(),
    };
    let mut output_witness = SemanticGeneralizedRelationWitness {
        source: input_witness.source,
        masks: input_witness
            .masks
            .into_iter()
            .chain(core::iter::once(sumcheck_mask_witness))
            .collect(),
    };
    assert!(
        semantic_whir_masked_sumcheck_kstate(&statement, Some(&prefix), &output_witness).unwrap()
    );
    for round_ordinal in 0..folding_factor {
        let (preceding_relation, preceding_instance) = relation_after_challenges(
            &statement,
            &prefix,
            prefix.combining_challenge.unwrap(),
            round_ordinal,
        )
        .unwrap();
        let polynomial = expected_round_polynomial(
            &statement,
            &preceding_relation,
            &preceding_instance,
            &output_witness,
            round_ordinal,
        )
        .unwrap();
        prefix.round_wires.push(wire_from_polynomial(&polynomial));
        let challenge =
            field(13_001 + u64::from(batch_ordinal) * 101 + u64::try_from(round_ordinal).unwrap());
        prefix.round_challenges.push(challenge);
        output_witness = fold_generalized_witness_once(&output_witness, challenge).unwrap();
        assert!(
            semantic_whir_masked_sumcheck_kstate(&statement, Some(&prefix), &output_witness)
                .unwrap()
        );
    }
    let (output_relation, output_instance) = relation_after_challenges(
        &statement,
        &prefix,
        prefix.combining_challenge.unwrap(),
        folding_factor,
    )
    .unwrap();
    assert!(
        semantic_generalized_relation_holds(&output_relation, &output_instance, &output_witness)
            .unwrap()
    );
    (output_relation, output_instance, output_witness)
}

fn execute_code_switch_boundary(
    input_relation: GeneralizedCommittedRelation,
    input_instance: SemanticGeneralizedRelationInstance,
    input_witness: SemanticGeneralizedRelationWitness,
    round_ordinal: u8,
    output_width: u64,
    output_block_length: u64,
) -> (
    GeneralizedCommittedRelation,
    SemanticGeneralizedRelationInstance,
    SemanticGeneralizedRelationWitness,
) {
    let logical_message = input_witness.source.flattened_messages();
    let output_message_length = u64::try_from(logical_message.len()).unwrap() / output_width;
    let output_source_relation =
        committed_code_relation(output_message_length, 2, output_block_length, output_width);
    let output_messages = logical_message
        .chunks_exact(usize::try_from(output_message_length).unwrap())
        .map(<[ProofChallengeExtensionElement]>::to_vec)
        .collect::<Vec<_>>();
    let (output_source_instance, output_source_witness) = code_fixture(
        &output_source_relation,
        output_messages,
        20_000 + u64::from(round_ordinal) * 101,
    );
    let switch_mask_code =
        committed_code_relation(input_relation.source_code.hiding_randomness_length, 1, 8, 1);
    let (switch_mask_instance, switch_mask_witness) = code_fixture(
        &switch_mask_code,
        vec![input_witness.source.hiding_randomness_columns[0].clone()],
        21_000 + u64::from(round_ordinal) * 101,
    );
    let statement = SemanticWhirCodeSwitchStatement::new(
        input_relation.clone(),
        input_instance.clone(),
        output_source_relation,
        output_source_instance,
        CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirCodeSwitch { round_ordinal },
            code: switch_mask_code,
        },
        switch_mask_instance,
        2,
    )
    .expect("code-switch component derives from the masked-sumcheck output pair");
    assert_eq!(statement.input_relation, input_relation);
    assert_eq!(statement.input_instance, input_instance);
    assert!(semantic_whir_code_switch_kstate(&statement, None, &input_witness).unwrap());
    let output_witness = SemanticGeneralizedRelationWitness {
        source: output_source_witness,
        masks: input_witness
            .masks
            .into_iter()
            .chain(core::iter::once(switch_mask_witness))
            .collect(),
    };
    let prefix = SemanticWhirCodeSwitchPrefix {
        query_positions: Some(vec![1, 3]),
        combination_challenge: Some(field(22_001 + u64::from(round_ordinal) * 101)),
    };
    assert!(semantic_whir_code_switch_kstate(&statement, Some(&prefix), &output_witness).unwrap());
    let extraction = semantic_whir_code_switch_errbr(&statement, &prefix, &output_witness)
        .expect("code-switch extractor executes at the composed boundary");
    assert!(extraction.witness.is_some());
    let (output_relation, output_instance) = code_switch_output_relation_and_instance(
        &statement,
        prefix.query_positions.as_ref().unwrap(),
        prefix.combination_challenge.unwrap(),
    )
    .unwrap();
    assert!(
        semantic_generalized_relation_holds(&output_relation, &output_instance, &output_witness)
            .unwrap()
    );
    (output_relation, output_instance, output_witness)
}

#[test]
fn both_whir_epochs_compose_exact_relation_and_instance_pairs_at_every_boundary() {
    let epoch_external_roles = [
        vec![MaskGroupRole::CrossEpochOpening],
        vec![
            MaskGroupRole::CfwInner,
            MaskGroupRole::CfwOuter,
            MaskGroupRole::CrossEpochOpening,
        ],
    ];
    for (epoch_ordinal, external_roles) in epoch_external_roles.iter().enumerate() {
        let (mut relation, mut instance, mut witness) = epoch_input_pair(
            external_roles,
            30_000 + u64::try_from(epoch_ordinal).unwrap() * 10_000,
        );
        for batch_ordinal in 0..4_u8 {
            (relation, instance, witness) =
                execute_masked_sumcheck_boundary(relation, instance, witness, batch_ordinal);
            if batch_ordinal < 3 {
                let (output_width, output_block_length) = match batch_ordinal {
                    0 => (4, 64),
                    1 => (2, 32),
                    2 => (2, 16),
                    _ => unreachable!(),
                };
                (relation, instance, witness) = execute_code_switch_boundary(
                    relation,
                    instance,
                    witness,
                    batch_ordinal,
                    output_width,
                    output_block_length,
                );
            }
        }
        let base_statement =
            base_case::SemanticWhirBaseStatement::new(relation.clone(), instance.clone(), 2, 2)
                .expect("base component accepts the exact final masked-sumcheck output pair");
        assert!(
            base_case::semantic_whir_base_kstate(
                &base_statement,
                None,
                &base_case::SemanticWhirBaseKnowledgeWitness::Input(witness),
            )
            .unwrap()
        );

        let mut reordered_relation = relation;
        let mut reordered_instance = instance;
        reordered_relation.mask_codes.swap(0, 1);
        reordered_instance.masks.swap(0, 1);
        assert_ne!(reordered_relation, base_statement.input_relation);
        assert_ne!(reordered_instance, base_statement.input_instance);
    }
}
