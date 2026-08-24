use super::super::semantic_execution::{
    SemanticFactorOneMoveDescriptor, SemanticKnowledgeWitness, SemanticUnusedCfwMatrices,
    SemanticVerifierMoveOwner, SemanticVerifierMovePrefix, SemanticVerifierMoveStatement,
    semantic_factor_one_bad_transition, semantic_factor_one_errbr, semantic_factor_one_kstate,
};
use super::*;

fn base(value: u64) -> ProofBaseFieldElement {
    ProofBaseFieldElement::from_canonical(value).expect("small base-field value is canonical")
}

fn extension(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_base(base(value))
}

fn extension_indeterminate() -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
        .expect("the extension indeterminate is canonical")
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
                    extension(
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

fn expected_decoding_operation_count(
    relation: &CommittedCodeRelation,
    instance: &SemanticCommittedCodeInstance,
) -> u128 {
    decode_canonical_interleaved_reed_solomon(
        semantic_code_geometry(relation).unwrap(),
        &instance.received_rows,
    )
    .unwrap()
    .field_operation_count()
}

fn honest_lookup_fixture() -> (SemanticLookupStatement, SemanticLookupWitness) {
    let relation = committed_code_relation(8, 1, 16, 1);
    let (instance, pre_challenge_source) = code_fixture(
        &relation,
        vec![vec![
            extension(0),
            extension(1),
            extension(1),
            extension(3),
            extension(1),
            extension(2),
            extension(0),
            extension(1),
        ]],
        101,
    );
    let statement = SemanticLookupStatement::new(relation, instance, 4, 4)
        .expect("small lookup statement derives");
    let witness = SemanticLookupWitness {
        pre_challenge_source,
        source_inverse_values: Vec::new(),
    };
    (statement, witness)
}

fn lookup_post_witness(
    mut witness: SemanticLookupWitness,
    source_element_count: usize,
    challenge: ProofChallengeExtensionElement,
) -> SemanticLookupWitness {
    witness.source_inverse_values = witness.pre_challenge_source.flattened_messages()
        [..source_element_count]
        .iter()
        .map(|&value| {
            challenge
                .add(value)
                .inverse()
                .expect("challenge outside the base subfield avoids every denominator")
        })
        .collect();
    witness
}

#[test]
fn lookup_kstate_and_errbr_decode_the_committed_production_layout() {
    let (statement, witness) = honest_lookup_fixture();
    assert!(semantic_lookup_kstate(&statement, None, &witness).unwrap());
    assert!(
        semantic_lookup_kstate(
            &statement,
            Some(&SemanticLookupPrefix {
                lookup_challenge: None,
            }),
            &witness,
        )
        .unwrap()
    );
    let challenge = extension_indeterminate().add(extension(7));
    let post_witness = lookup_post_witness(witness.clone(), 4, challenge);
    let prefix = SemanticLookupPrefix {
        lookup_challenge: Some(challenge),
    };
    assert!(semantic_lookup_kstate(&statement, Some(&prefix), &post_witness).unwrap());
    let mut short_inverse_witness = post_witness.clone();
    short_inverse_witness.source_inverse_values.pop();
    assert_eq!(
        semantic_lookup_kstate(&statement, Some(&prefix), &short_inverse_witness),
        Ok(false)
    );
    let extraction = semantic_lookup_errbr(&statement, &prefix, &post_witness).unwrap();
    assert_eq!(extraction.witness, Some(witness));
    assert_eq!(
        extraction.field_operation_count,
        expected_decoding_operation_count(&statement.source_relation, &statement.source_instance)
    );
    assert_eq!(
        semantic_lookup_bad_transition(&statement, &prefix, &post_witness).unwrap(),
        None
    );

    let base_subfield_prefix = SemanticLookupPrefix {
        lookup_challenge: Some(extension(9)),
    };
    assert_eq!(
        semantic_lookup_kstate(&statement, Some(&base_subfield_prefix), &post_witness),
        Err(SemanticOuterError::MalformedPrefix)
    );

    let mut substituted_source = post_witness;
    substituted_source.pre_challenge_source.message_columns[0][0] = extension(9);
    assert_eq!(
        semantic_lookup_kstate(&statement, Some(&prefix), &substituted_source),
        Ok(false)
    );

    let malformed_relation = committed_code_relation(8, 1, 16, 1);
    let (malformed_instance, mut malformed_source) =
        code_fixture(&malformed_relation, vec![vec![extension(0); 8]], 131);
    malformed_source.message_columns[0].pop();
    let malformed_statement =
        SemanticLookupStatement::new(malformed_relation, malformed_instance, 4, 4).unwrap();
    assert_eq!(
        semantic_lookup_kstate(
            &malformed_statement,
            None,
            &SemanticLookupWitness {
                pre_challenge_source: malformed_source,
                source_inverse_values: Vec::new(),
            },
        ),
        Ok(false)
    );
}

#[test]
fn lookup_kstate_rejects_committed_nonbase_values_and_nonzero_padding() {
    let nonbase_relation = committed_code_relation(8, 1, 16, 1);
    let mut nonbase_message = vec![extension(0); 8];
    nonbase_message[0] = extension_indeterminate();
    let (nonbase_instance, nonbase_source) =
        code_fixture(&nonbase_relation, vec![nonbase_message], 137);
    let nonbase_statement =
        SemanticLookupStatement::new(nonbase_relation, nonbase_instance, 4, 4).unwrap();
    assert_eq!(
        semantic_lookup_kstate(
            &nonbase_statement,
            None,
            &SemanticLookupWitness {
                pre_challenge_source: nonbase_source,
                source_inverse_values: Vec::new(),
            },
        ),
        Ok(false)
    );

    let padded_relation = committed_code_relation(9, 1, 16, 1);
    let mut padded_message = vec![extension(0); 9];
    padded_message[8] = extension(1);
    let (padded_instance, padded_source) =
        code_fixture(&padded_relation, vec![padded_message], 139);
    let padded_statement =
        SemanticLookupStatement::new(padded_relation, padded_instance, 4, 4).unwrap();
    assert_eq!(
        semantic_lookup_kstate(
            &padded_statement,
            None,
            &SemanticLookupWitness {
                pre_challenge_source: padded_source,
                source_inverse_values: Vec::new(),
            },
        ),
        Ok(false)
    );
}

#[test]
fn lookup_bad_transition_derives_nonzero_log_derivative_certificate() {
    let table_value_count = 6_usize;
    let challenge = extension_indeterminate();
    let source_values = (0..table_value_count)
        .map(|value| base(u64::try_from(value).unwrap()))
        .collect::<Vec<_>>();
    let claimed_table_multiplicities = (0..table_value_count)
        .map(|table_value| {
            let negated_table_value = base(u64::try_from(table_value).unwrap()).negate();
            let polynomial_at_pole = negated_table_value.power(5).subtract(base(3));
            let denominator_derivative = (0..table_value_count)
                .filter(|other| *other != table_value)
                .fold(ProofBaseFieldElement::ONE, |product, other| {
                    product.multiply(negated_table_value.add(base(u64::try_from(other).unwrap())))
                });
            let residue = polynomial_at_pole.multiply(
                denominator_derivative
                    .inverse()
                    .expect("distinct table poles give a nonzero derivative"),
            );
            ProofBaseFieldElement::ONE.subtract(residue)
        })
        .collect::<Vec<_>>();
    let relation = committed_code_relation(12, 1, 16, 1);
    let message = source_values
        .iter()
        .chain(&claimed_table_multiplicities)
        .map(|&value| ProofChallengeExtensionElement::from_base(value))
        .collect::<Vec<_>>();
    let (instance, pre_challenge_source) = code_fixture(&relation, vec![message], 151);
    let statement =
        SemanticLookupStatement::new(relation, instance, table_value_count, table_value_count)
            .expect("small lookup statement derives");
    let preceding_witness = SemanticLookupWitness {
        pre_challenge_source,
        source_inverse_values: Vec::new(),
    };
    assert!(!semantic_lookup_kstate(&statement, None, &preceding_witness).unwrap());
    let post_witness = lookup_post_witness(preceding_witness.clone(), table_value_count, challenge);
    let prefix = SemanticLookupPrefix {
        lookup_challenge: Some(challenge),
    };
    assert!(semantic_lookup_kstate(&statement, Some(&prefix), &post_witness).unwrap());
    assert_eq!(
        semantic_lookup_errbr(&statement, &prefix, &post_witness)
            .unwrap()
            .witness,
        Some(preceding_witness)
    );
    let certificate = semantic_lookup_bad_transition(&statement, &prefix, &post_witness)
        .unwrap()
        .expect("false multiset at an accepting challenge derives a certificate");
    assert_eq!(certificate.lookup_challenge, challenge);
    assert_eq!(certificate.source_element_count, 6);
    assert_eq!(certificate.table_entry_count, 6);
    assert!(matches!(
        certificate.first_multiplicity_difference,
        SemanticLookupMultiplicityDifference::TableMultiplicity { .. }
    ));
    assert_eq!(certificate.exact_error_numerator().unwrap(), 11);
}

fn cross_epoch_fixture(
    pre_challenge_coefficients: Vec<ProofChallengeExtensionElement>,
    main_copied_prefix: Vec<ProofChallengeExtensionElement>,
) -> (SemanticCrossEpochStatement, SemanticCrossEpochWitness) {
    assert_eq!(pre_challenge_coefficients.len(), 4);
    assert_eq!(main_copied_prefix.len(), 4);
    let pre_challenge_source_relation = committed_code_relation(4, 1, 8, 1);
    let main_source_relation = committed_code_relation(8, 1, 16, 1);
    let mask_code = committed_code_relation(1, 1, 8, 2);
    let (pre_challenge_source_instance, pre_challenge_source) = code_fixture(
        &pre_challenge_source_relation,
        vec![pre_challenge_coefficients],
        201,
    );
    let mut main_message = main_copied_prefix;
    main_message.extend([extension(11), extension(13), extension(17), extension(19)]);
    let (main_source_instance, main_source) =
        code_fixture(&main_source_relation, vec![main_message], 301);
    let (mask_instance, shared_masks) = code_fixture(
        &mask_code,
        vec![vec![extension(23)], vec![extension(29)]],
        401,
    );
    let statement = SemanticCrossEpochStatement::new(
        pre_challenge_source_relation,
        pre_challenge_source_instance,
        main_source_relation,
        main_source_instance,
        CommittedMaskCodeRelation {
            role: MaskGroupRole::CrossEpochOpening,
            code: mask_code,
        },
        mask_instance,
        SemanticProductionOuterLayout::new(0, 2, 2, 2, 4, 2, 4, 8, 3)
            .expect("small cross-epoch layout derives"),
    )
    .expect("small cross-epoch statement derives");
    (
        statement,
        SemanticCrossEpochWitness {
            pre_challenge_source,
            main_source,
            shared_masks,
        },
    )
}

fn padded_cross_epoch_fixture(
    pre_challenge_message: Vec<ProofChallengeExtensionElement>,
    main_message: Vec<ProofChallengeExtensionElement>,
) -> (SemanticCrossEpochStatement, SemanticCrossEpochWitness) {
    assert_eq!(pre_challenge_message.len(), 8);
    assert_eq!(main_message.len(), 16);
    let pre_challenge_source_relation = committed_code_relation(8, 1, 16, 1);
    let main_source_relation = committed_code_relation(16, 1, 32, 1);
    let mask_code = committed_code_relation(1, 1, 8, 2);
    let (pre_challenge_source_instance, pre_challenge_source) = code_fixture(
        &pre_challenge_source_relation,
        vec![pre_challenge_message],
        451,
    );
    let (main_source_instance, main_source) =
        code_fixture(&main_source_relation, vec![main_message], 551);
    let (mask_instance, shared_masks) = code_fixture(
        &mask_code,
        vec![vec![extension(23)], vec![extension(29)]],
        651,
    );
    let statement = SemanticCrossEpochStatement::new(
        pre_challenge_source_relation,
        pre_challenge_source_instance,
        main_source_relation,
        main_source_instance,
        CommittedMaskCodeRelation {
            role: MaskGroupRole::CrossEpochOpening,
            code: mask_code,
        },
        mask_instance,
        SemanticProductionOuterLayout::new(0, 2, 2, 2, 8, 2, 8, 16, 3)
            .expect("padded cross-epoch layout derives"),
    )
    .expect("padded cross-epoch statement derives");
    (
        statement,
        SemanticCrossEpochWitness {
            pre_challenge_source,
            main_source,
            shared_masks,
        },
    )
}

fn cross_epoch_disclosures(
    witness: &SemanticCrossEpochWitness,
    point: &[ProofChallengeExtensionElement],
) -> SemanticCrossEpochDisclosures {
    let pre_challenge_evaluation =
        multilinear_evaluation(&witness.pre_challenge_source.flattened_messages(), point).unwrap();
    let main_evaluation =
        multilinear_evaluation(&witness.main_source.flattened_messages()[..4], point).unwrap();
    let masks = witness.shared_masks.flattened_messages();
    SemanticCrossEpochDisclosures {
        masked_pre_challenge_evaluation: pre_challenge_evaluation.add(masks[0]),
        masked_main_evaluation: main_evaluation.add(masks[1]),
        mask_difference: masks[0].subtract(masks[1]),
    }
}

fn production_outer_fixture() -> (
    SemanticProductionOuterStatement,
    SemanticProductionOuterCommitments,
    SemanticProductionOuterWitness,
    ProofChallengeExtensionElement,
) {
    let layout = SemanticProductionOuterLayout::new(0, 4, 4, 4, 12, 4, 8, 16, 7)
        .expect("small production outer layout");
    let pre_challenge_source_relation = committed_code_relation(8, 1, 16, 1);
    let main_source_relation = committed_code_relation(16, 1, 32, 1);
    let shared_mask_code = committed_code_relation(1, 1, 8, 2);
    let shared_mask_relation = CommittedMaskCodeRelation {
        role: MaskGroupRole::CrossEpochOpening,
        code: shared_mask_code.clone(),
    };
    let statement = SemanticProductionOuterStatement::new(
        layout,
        pre_challenge_source_relation.clone(),
        main_source_relation.clone(),
        shared_mask_relation,
    )
    .expect("small production outer statement");
    let pre_challenge_message = vec![
        extension(0),
        extension(1),
        extension(1),
        extension(3),
        extension(1),
        extension(2),
        extension(0),
        extension(1),
    ];
    let (pre_challenge_source, pre_challenge_source_witness) = code_fixture(
        &pre_challenge_source_relation,
        vec![pre_challenge_message.clone()],
        501,
    );
    let lookup_challenge = extension_indeterminate().add(extension(7));
    let source_inverses = pre_challenge_message[..4]
        .iter()
        .map(|&source| {
            lookup_challenge
                .add(source)
                .inverse()
                .expect("lookup denominator is nonzero")
        })
        .collect::<Vec<_>>();
    let mut main_message = pre_challenge_message;
    main_message.extend([extension(11), extension(13), extension(17), extension(19)]);
    main_message.extend(source_inverses);
    let (main_source, main_source_witness) =
        code_fixture(&main_source_relation, vec![main_message], 601);
    let (shared_masks, shared_mask_witness) = code_fixture(
        &shared_mask_code,
        vec![vec![extension(23)], vec![extension(29)]],
        701,
    );
    (
        statement,
        SemanticProductionOuterCommitments {
            pre_challenge_source,
            main_source,
            shared_masks,
        },
        SemanticProductionOuterWitness {
            pre_challenge_source: pre_challenge_source_witness,
            main_source: main_source_witness,
            shared_masks: shared_mask_witness,
        },
        lookup_challenge,
    )
}

#[test]
fn production_outer_layout_is_derived_from_the_compiled_relation() {
    let relation =
        crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog()
            .expect("selected compact relation catalog");
    let layout = SemanticProductionOuterLayout::from_relation(&relation)
        .expect("semantic production layout derives from the compiled relation");
    assert_eq!(layout.source_element_count(), 950_272);
    assert_eq!(layout.table_value_count(), 131_072);
    assert_eq!(layout.soundness_numerator(), 1_081_343);
    assert_eq!(layout.pre_challenge_message_element_count, 2_097_152);
    assert_eq!(layout.main_message_element_count, 4_194_304);
    assert_eq!(layout.copied_main_source_element_count, 1_081_344);
    assert_eq!(layout.inverse_first_element, 1_867_776);
    assert_eq!(layout.inverse_element_count, 950_272);
    assert!(layout.copied_main_source_element_count < layout.inverse_first_element);
}

#[test]
fn production_outer_kstate_uses_one_witness_across_every_actual_prefix() {
    let (statement, commitments, witness, lookup_challenge) = production_outer_fixture();
    let empty = SemanticProductionOuterPrefix::Empty;
    let pre_challenge_committed = SemanticProductionOuterPrefix::PreChallengeSourceCommitted {
        pre_challenge_source: commitments.pre_challenge_source.clone(),
    };
    let lookup_sampled = SemanticProductionOuterPrefix::LookupChallengeSampled {
        pre_challenge_source: commitments.pre_challenge_source.clone(),
        lookup_challenge,
    };
    let post_lookup = SemanticProductionOuterPrefix::PostLookupCommitments {
        commitments: commitments.clone(),
        lookup_challenge,
    };
    let point = vec![extension(31), extension(37), extension(41)];
    let cross_sampled = SemanticProductionOuterPrefix::CrossEpochPointSampled {
        commitments: commitments.clone(),
        lookup_challenge,
        point: point.clone(),
    };
    let cross_witness = production_cross_epoch_witness(&witness);
    let pre_challenge_evaluation = multilinear_evaluation(
        &cross_witness.pre_challenge_source.flattened_messages(),
        &point,
    )
    .unwrap();
    let main_evaluation =
        multilinear_evaluation(&cross_witness.main_source.flattened_messages()[..8], &point)
            .unwrap();
    let mask_values = cross_witness.shared_masks.flattened_messages();
    let disclosures = SemanticCrossEpochDisclosures {
        masked_pre_challenge_evaluation: pre_challenge_evaluation.add(mask_values[0]),
        masked_main_evaluation: main_evaluation.add(mask_values[1]),
        mask_difference: mask_values[0].subtract(mask_values[1]),
    };
    let disclosures_sent = SemanticProductionOuterPrefix::CrossEpochDisclosuresSent {
        commitments: commitments.clone(),
        lookup_challenge,
        point,
        disclosures,
    };

    for prefix in [
        &empty,
        &pre_challenge_committed,
        &lookup_sampled,
        &post_lookup,
        &cross_sampled,
        &disclosures_sent,
    ] {
        assert!(semantic_production_outer_kstate(&statement, prefix, &witness).unwrap());
    }

    let lookup_extraction =
        semantic_production_outer_errbr(&statement, &lookup_sampled, &witness).unwrap();
    assert_eq!(lookup_extraction.witness, Some(witness.clone()));
    assert_eq!(
        lookup_extraction.field_operation_count,
        expected_decoding_operation_count(
            &statement.pre_challenge_source_relation,
            &commitments.pre_challenge_source,
        )
    );
    let cross_extraction =
        semantic_production_outer_errbr(&statement, &cross_sampled, &witness).unwrap();
    assert_eq!(cross_extraction.witness, Some(witness.clone()));
    assert_eq!(
        cross_extraction.field_operation_count,
        expected_decoding_operation_count(
            &statement.pre_challenge_source_relation,
            &commitments.pre_challenge_source,
        ) + expected_decoding_operation_count(
            &statement.main_source_relation,
            &commitments.main_source,
        ) + expected_decoding_operation_count(
            &statement.shared_mask_relation.code,
            &commitments.shared_masks,
        )
    );
    assert_eq!(
        semantic_production_outer_bad_transition(&statement, &lookup_sampled, &witness).unwrap(),
        None
    );
    assert_eq!(
        semantic_production_outer_bad_transition(&statement, &cross_sampled, &witness).unwrap(),
        None
    );

    let dispatcher_statement: SemanticVerifierMoveStatement<'_, '_, SemanticUnusedCfwMatrices> =
        SemanticVerifierMoveStatement::ProductionOuter(&statement);
    let dispatcher_witness = SemanticKnowledgeWitness::ProductionOuter(witness.clone());
    let lookup_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::LookupChallenge,
    );
    let dispatcher_lookup_predecessor =
        SemanticVerifierMovePrefix::ProductionOuter(pre_challenge_committed.clone());
    let dispatcher_lookup_extended =
        SemanticVerifierMovePrefix::ProductionOuter(lookup_sampled.clone());
    assert!(
        semantic_factor_one_kstate(
            &lookup_descriptor,
            &dispatcher_statement,
            &dispatcher_lookup_predecessor,
            &dispatcher_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_factor_one_kstate(
            &lookup_descriptor,
            &dispatcher_statement,
            &dispatcher_lookup_extended,
            &dispatcher_witness,
        )
        .unwrap()
    );
    let dispatcher_lookup_extraction = semantic_factor_one_errbr(
        &lookup_descriptor,
        &dispatcher_statement,
        &dispatcher_lookup_extended,
        &dispatcher_witness,
    )
    .unwrap();
    assert_eq!(
        dispatcher_lookup_extraction.witness,
        Some(dispatcher_witness.clone())
    );
    assert_eq!(
        dispatcher_lookup_extraction.field_operation_count,
        lookup_extraction.field_operation_count
    );
    assert_eq!(
        semantic_factor_one_bad_transition(
            &lookup_descriptor,
            &dispatcher_statement,
            &dispatcher_lookup_extended,
            &dispatcher_witness,
        )
        .unwrap(),
        None
    );

    let cross_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::CrossEpochPoint,
    );
    let dispatcher_cross_predecessor =
        SemanticVerifierMovePrefix::ProductionOuter(post_lookup.clone());
    let dispatcher_cross_extended =
        SemanticVerifierMovePrefix::ProductionOuter(cross_sampled.clone());
    assert!(
        semantic_factor_one_kstate(
            &cross_descriptor,
            &dispatcher_statement,
            &dispatcher_cross_predecessor,
            &dispatcher_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_factor_one_kstate(
            &cross_descriptor,
            &dispatcher_statement,
            &dispatcher_cross_extended,
            &dispatcher_witness,
        )
        .unwrap()
    );
    let dispatcher_cross_extraction = semantic_factor_one_errbr(
        &cross_descriptor,
        &dispatcher_statement,
        &dispatcher_cross_extended,
        &dispatcher_witness,
    )
    .unwrap();
    assert_eq!(
        dispatcher_cross_extraction.witness,
        Some(dispatcher_witness.clone())
    );
    assert_eq!(
        dispatcher_cross_extraction.field_operation_count,
        cross_extraction.field_operation_count
    );
    assert_eq!(
        semantic_factor_one_bad_transition(
            &cross_descriptor,
            &dispatcher_statement,
            &dispatcher_cross_extended,
            &dispatcher_witness,
        )
        .unwrap(),
        None
    );

    let mut substituted_inverse = witness.clone();
    substituted_inverse.main_source.message_columns[0][12] = extension(47);
    assert!(
        !semantic_production_outer_kstate(&statement, &lookup_sampled, &substituted_inverse,)
            .unwrap()
    );
    let mut malformed_main_message = witness.clone();
    malformed_main_message.main_source.message_columns[0].pop();
    assert_eq!(
        semantic_production_outer_kstate(&statement, &lookup_sampled, &malformed_main_message),
        Ok(false)
    );

    let mut substituted_main_prefix = witness.clone();
    substituted_main_prefix.main_source.message_columns[0][0] = extension(53);
    assert!(
        semantic_production_outer_kstate(&statement, &lookup_sampled, &substituted_main_prefix,)
            .unwrap()
    );
    assert!(
        !semantic_production_outer_kstate(&statement, &post_lookup, &substituted_main_prefix,)
            .unwrap()
    );

    let mut substituted_commitment = commitments;
    let excessive_error_count = semantic_code_geometry(&statement.main_source_relation)
        .unwrap()
        .selected_decoding_error_count()
        + 1;
    for row in substituted_commitment
        .main_source
        .received_rows
        .iter_mut()
        .take(excessive_error_count)
    {
        row[0] = row[0].add(extension(1));
    }
    let substituted_post_lookup = SemanticProductionOuterPrefix::PostLookupCommitments {
        commitments: substituted_commitment,
        lookup_challenge,
    };
    assert!(
        !semantic_production_outer_kstate(&statement, &substituted_post_lookup, &witness,).unwrap()
    );
}

#[test]
fn cross_epoch_kstate_and_errbr_decode_all_three_committed_sources() {
    let coefficients = vec![extension(2), extension(3), extension(5), extension(7)];
    let (statement, witness) = cross_epoch_fixture(coefficients.clone(), coefficients);
    assert!(semantic_cross_epoch_kstate(&statement, None, &witness).unwrap());
    let empty_prefix = SemanticCrossEpochPrefix {
        point: None,
        disclosures: None,
    };
    assert!(semantic_cross_epoch_kstate(&statement, Some(&empty_prefix), &witness).unwrap());
    let point = vec![extension(31), extension(37)];
    let verifier_prefix = SemanticCrossEpochPrefix {
        disclosures: None,
        point: Some(point.clone()),
    };
    assert!(semantic_cross_epoch_kstate(&statement, Some(&verifier_prefix), &witness).unwrap());
    let extraction = semantic_cross_epoch_errbr(&statement, &verifier_prefix, &witness).unwrap();
    assert_eq!(extraction.witness, Some(witness.clone()));
    let expected_operation_count = expected_decoding_operation_count(
        &statement.pre_challenge_source_relation,
        &statement.pre_challenge_source_instance,
    ) + expected_decoding_operation_count(
        &statement.main_source_relation,
        &statement.main_source_instance,
    ) + expected_decoding_operation_count(
        &statement.mask_relation.code,
        &statement.mask_instance,
    );
    assert_eq!(extraction.field_operation_count, expected_operation_count);
    assert_eq!(
        semantic_cross_epoch_bad_transition(&statement, &verifier_prefix, &witness).unwrap(),
        None
    );

    let prover_prefix = SemanticCrossEpochPrefix {
        disclosures: Some(cross_epoch_disclosures(&witness, &point)),
        point: Some(point),
    };
    assert!(semantic_cross_epoch_kstate(&statement, Some(&prover_prefix), &witness).unwrap());
    assert_eq!(
        semantic_cross_epoch_errbr(&statement, &prover_prefix, &witness),
        Err(SemanticOuterError::MalformedPrefix)
    );
    let malformed_prefix = SemanticCrossEpochPrefix {
        point: None,
        disclosures: prover_prefix.disclosures,
    };
    assert_eq!(
        semantic_cross_epoch_kstate(&statement, Some(&malformed_prefix), &witness),
        Err(SemanticOuterError::MalformedPrefix)
    );

    let mut malformed_main = witness.clone();
    malformed_main.main_source.message_columns[0].pop();
    assert_eq!(
        semantic_cross_epoch_kstate(&statement, Some(&prover_prefix), &malformed_main),
        Ok(false)
    );

    let mut substituted_main = witness;
    substituted_main.main_source.message_columns[0][0] = extension(47);
    assert_eq!(
        semantic_cross_epoch_kstate(&statement, Some(&prover_prefix), &substituted_main),
        Ok(false)
    );
}

#[test]
fn cross_epoch_bad_transition_derives_nonzero_committed_multilinear_root() {
    let first_coordinate = extension(31);
    let second_coordinate = extension(37);
    let cancelling_value = ProofChallengeExtensionElement::ZERO.subtract(
        ProofChallengeExtensionElement::ONE
            .subtract(first_coordinate)
            .multiply(
                first_coordinate
                    .inverse()
                    .expect("selected coordinate is nonzero"),
            ),
    );
    let (statement, witness) = cross_epoch_fixture(
        vec![
            ProofChallengeExtensionElement::ONE,
            ProofChallengeExtensionElement::ONE,
            cancelling_value,
            cancelling_value,
        ],
        vec![ProofChallengeExtensionElement::ZERO; 4],
    );
    assert!(!semantic_cross_epoch_kstate(&statement, None, &witness).unwrap());
    let point = vec![first_coordinate, second_coordinate];
    let prefix = SemanticCrossEpochPrefix {
        disclosures: None,
        point: Some(point.clone()),
    };
    assert!(semantic_cross_epoch_kstate(&statement, Some(&prefix), &witness).unwrap());
    assert_eq!(
        semantic_cross_epoch_errbr(&statement, &prefix, &witness)
            .unwrap()
            .witness,
        Some(witness.clone())
    );
    let certificate = semantic_cross_epoch_bad_transition(&statement, &prefix, &witness)
        .unwrap()
        .expect("unequal committed vectors at an accepting point derive a root certificate");
    assert_eq!(certificate.point, point);
    assert!(
        certificate
            .nonzero_difference_evaluations
            .iter()
            .any(|difference| !difference.is_zero())
    );
    assert!(
        multilinear_evaluation(
            &certificate.nonzero_difference_evaluations,
            &certificate.point,
        )
        .unwrap()
        .is_zero()
    );
    assert_eq!(certificate.exact_error_numerator().unwrap(), 2);
}

#[test]
fn cross_epoch_copied_prefix_mutation_derives_the_expected_bad_transition() {
    let pre_challenge_message = vec![
        extension(0),
        extension(1),
        extension(0),
        extension(0),
        extension(0),
        extension(0),
        extension(0),
        extension(0),
    ];
    let main_message = vec![extension(0); 16];
    let (statement, witness) = padded_cross_epoch_fixture(pre_challenge_message, main_message);
    assert!(!semantic_cross_epoch_kstate(&statement, None, &witness).unwrap());

    let point = vec![extension(0); 3];
    let prefix = SemanticCrossEpochPrefix {
        point: Some(point.clone()),
        disclosures: None,
    };
    assert!(semantic_cross_epoch_kstate(&statement, Some(&prefix), &witness).unwrap());
    let certificate = semantic_cross_epoch_bad_transition(&statement, &prefix, &witness)
        .unwrap()
        .expect("a copied-prefix difference at an accepting point is a bad transition");
    assert_eq!(certificate.point, point);
    assert_eq!(
        certificate.nonzero_difference_evaluations,
        vec![
            extension(0),
            extension(1),
            extension(0),
            extension(0),
            extension(0),
            extension(0),
            extension(0),
            extension(0),
        ]
    );
    assert_eq!(certificate.exact_error_numerator().unwrap(), 3);
}

#[test]
fn cross_epoch_rejects_nonzero_pre_challenge_padding() {
    let mut pre_challenge_message = vec![extension(0); 8];
    pre_challenge_message[..4].copy_from_slice(&[
        extension(2),
        extension(3),
        extension(5),
        extension(7),
    ]);
    pre_challenge_message[4] = extension(11);
    let mut main_message = vec![extension(0); 16];
    main_message[..4].copy_from_slice(&[extension(2), extension(3), extension(5), extension(7)]);
    let (statement, witness) = padded_cross_epoch_fixture(pre_challenge_message, main_message);

    assert_eq!(
        semantic_cross_epoch_kstate(&statement, None, &witness),
        Ok(false)
    );
}

#[test]
fn cross_epoch_copy_ignores_later_main_witness_coordinates() {
    let mut pre_challenge_message = vec![extension(0); 8];
    pre_challenge_message[..4].copy_from_slice(&[
        extension(2),
        extension(3),
        extension(5),
        extension(7),
    ]);
    let mut first_main_message = vec![extension(0); 16];
    first_main_message[..4].copy_from_slice(&[
        extension(2),
        extension(3),
        extension(5),
        extension(7),
    ]);
    first_main_message[4..].copy_from_slice(&[
        extension(11),
        extension(13),
        extension(17),
        extension(19),
        extension(23),
        extension(29),
        extension(31),
        extension(37),
        extension(41),
        extension(43),
        extension(47),
        extension(53),
    ]);
    let mut second_main_message = first_main_message.clone();
    second_main_message[4..].copy_from_slice(&[
        extension(59),
        extension(61),
        extension(67),
        extension(71),
        extension(73),
        extension(79),
        extension(83),
        extension(89),
        extension(97),
        extension(101),
        extension(103),
        extension(107),
    ]);

    let (first_statement, first_witness) =
        padded_cross_epoch_fixture(pre_challenge_message.clone(), first_main_message);
    let (second_statement, second_witness) =
        padded_cross_epoch_fixture(pre_challenge_message, second_main_message);
    assert!(semantic_cross_epoch_kstate(&first_statement, None, &first_witness).unwrap());
    assert!(semantic_cross_epoch_kstate(&second_statement, None, &second_witness).unwrap());

    let first_parts = cross_epoch_message_parts(&first_statement, &first_witness).unwrap();
    let second_parts = cross_epoch_message_parts(&second_statement, &second_witness).unwrap();
    assert_eq!(first_parts.0, second_parts.0);
    assert_eq!(first_parts.1, second_parts.1);
}
