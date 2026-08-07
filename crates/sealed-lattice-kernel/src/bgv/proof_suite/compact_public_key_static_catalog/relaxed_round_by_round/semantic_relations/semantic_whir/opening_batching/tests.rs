use super::*;
use crate::bgv::proof_suite::ProofBaseFieldElement;
use crate::bgv::proof_suite::compact_public_key_static_catalog::relaxed_round_by_round::MaskGroupRole;

fn field(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(value).expect("small canonical field value"),
    )
}

fn fixture(
    target_deltas: [ProofChallengeExtensionElement; 3],
) -> (
    SemanticWhirOpeningBatchingStatement,
    SemanticGeneralizedRelationWitness,
) {
    let source_code = CommittedCodeRelation {
        message_length: 2,
        hiding_randomness_length: 1,
        block_length: 8,
        interleaving_width: 1,
    };
    let mask_code = CommittedCodeRelation {
        message_length: 1,
        hiding_randomness_length: 1,
        block_length: 8,
        interleaving_width: 1,
    };
    let source_witness = SemanticCommittedCodeWitness {
        message_columns: vec![vec![field(2), field(3)]],
        hiding_randomness_columns: vec![vec![field(5)]],
    };
    let mask_witness = SemanticCommittedCodeWitness {
        message_columns: vec![vec![field(7)]],
        hiding_randomness_columns: vec![vec![field(11)]],
    };
    let witness = SemanticGeneralizedRelationWitness {
        source: source_witness,
        masks: vec![mask_witness],
    };
    let source_instance = SemanticCommittedCodeInstance {
        received_rows: encode_canonical_interleaved_reed_solomon(
            semantic_code_geometry(&source_code).unwrap(),
            &witness.source.coefficient_columns(&source_code).unwrap(),
        )
        .unwrap(),
    };
    let mask_instance = SemanticCommittedCodeInstance {
        received_rows: encode_canonical_interleaved_reed_solomon(
            semantic_code_geometry(&mask_code).unwrap(),
            &witness.masks[0].coefficient_columns(&mask_code).unwrap(),
        )
        .unwrap(),
    };
    let mut claims = [
        SemanticGeneralizedLinearClaim {
            source_covector: vec![field(13), field(17)],
            mask_covectors: vec![vec![field(19)]],
            target: ProofChallengeExtensionElement::ZERO,
        },
        SemanticGeneralizedLinearClaim {
            source_covector: vec![field(23), field(29)],
            mask_covectors: vec![vec![field(31)]],
            target: ProofChallengeExtensionElement::ZERO,
        },
        SemanticGeneralizedLinearClaim {
            source_covector: vec![field(37), field(41)],
            mask_covectors: vec![vec![field(43)]],
            target: ProofChallengeExtensionElement::ZERO,
        },
    ];
    for (claim, target_delta) in claims.iter_mut().zip(target_deltas) {
        claim.target = evaluate_claim(claim, &witness).unwrap().add(target_delta);
    }
    let relation = GeneralizedCommittedRelation {
        source_code,
        mask_codes: vec![CommittedMaskCodeRelation {
            role: MaskGroupRole::CrossEpochOpening,
            code: mask_code,
        }],
        source_message_element_count: 2,
        source_hiding_element_count: 1,
        mask_message_element_count: 1,
        covector_extension_element_count: 4,
        opening_evaluation_claim_count: 2,
        carried_reduction_claim_count: 1,
        claim_count: 3,
    };
    let instance = SemanticGeneralizedRelationInstance {
        source: source_instance,
        masks: vec![mask_instance],
        opening_claims: claims[..2].to_vec(),
        carried_reduction_claims: vec![claims[2].clone()],
    };
    (
        SemanticWhirOpeningBatchingStatement::new(relation, instance).unwrap(),
        witness,
    )
}

#[test]
fn opening_batching_carries_the_witness_across_empty_prover_and_verifier_prefixes() {
    let (statement, witness) = fixture([ProofChallengeExtensionElement::ZERO; 3]);
    assert!(semantic_whir_opening_batching_kstate(&statement, None, &witness).unwrap());
    let prover_prefix = SemanticWhirOpeningBatchingPrefix {
        batching_challenge: None,
    };
    assert!(
        semantic_whir_opening_batching_kstate(&statement, Some(&prover_prefix), &witness).unwrap()
    );
    let verifier_prefix = SemanticWhirOpeningBatchingPrefix {
        batching_challenge: Some(field(47)),
    };
    assert!(
        semantic_whir_opening_batching_kstate(&statement, Some(&verifier_prefix), &witness)
            .unwrap()
    );
    assert_eq!(
        semantic_whir_opening_batching_errbr(&statement, &verifier_prefix, &witness)
            .unwrap()
            .witness,
        Some(witness.clone())
    );
    assert_eq!(
        semantic_whir_opening_batching_bad_transition(&statement, &verifier_prefix, &witness)
            .unwrap(),
        None
    );
}

#[test]
fn opening_batching_bad_transition_derives_the_exact_residual_polynomial() {
    let challenge = field(53);
    let first_delta = field(59);
    let second_delta = field(61);
    let third_delta = first_delta
        .add(challenge.multiply(second_delta))
        .negate()
        .multiply(
            challenge
                .multiply(challenge)
                .inverse()
                .expect("nonzero challenge square"),
        );
    let (statement, witness) = fixture([first_delta, second_delta, third_delta]);
    assert!(!semantic_whir_opening_batching_kstate(&statement, None, &witness).unwrap());
    let prefix = SemanticWhirOpeningBatchingPrefix {
        batching_challenge: Some(challenge),
    };
    assert!(semantic_whir_opening_batching_kstate(&statement, Some(&prefix), &witness).unwrap());
    let Some(SemanticWhirOpeningBatchingBadTransition {
        coefficients,
        challenge: derived_challenge,
    }) = semantic_whir_opening_batching_bad_transition(&statement, &prefix, &witness).unwrap()
    else {
        panic!("opening batching must derive a nonzero residual polynomial")
    };
    assert_eq!(derived_challenge, challenge);
    assert_eq!(
        coefficients,
        vec![
            first_delta.negate(),
            second_delta.negate(),
            third_delta.negate()
        ]
    );
    assert!(evaluate_polynomial(&coefficients, challenge).is_zero());
}
