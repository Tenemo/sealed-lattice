use super::super::super::super::CompactPublicKeyStaticCatalog;
use super::*;

fn factor_one_catalog() -> super::super::super::RelaxedRoundByRoundCatalog {
    CompactPublicKeyStaticCatalog::derive()
        .expect("compact public-key static catalog derives")
        .selected
        .relaxed_round_by_round
}

#[test]
fn factor_one_schedule_binds_all_82_moves_to_executable_semantic_owners() {
    let catalog = factor_one_catalog();
    let schedule = SemanticFactorOneSchedule::from_catalog(&catalog)
        .expect("all factor-one transitions have semantic owners");
    assert_eq!(schedule.moves().len(), FACTOR_ONE_VERIFIER_MOVE_COUNT);
    assert_eq!(
        schedule.move_at(0).unwrap().owner(),
        SemanticVerifierMoveOwner::LookupChallenge
    );
    assert_eq!(
        schedule.move_at(1).unwrap().owner(),
        SemanticVerifierMoveOwner::CrossEpochPoint
    );
    assert_eq!(
        schedule.move_at(2).unwrap().owner(),
        SemanticVerifierMoveOwner::CfwInitialRandomness
    );
    assert_eq!(
        schedule.move_at(26).unwrap().owner(),
        SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening
    );
    assert_eq!(
        schedule.move_at(81).unwrap().owner(),
        SemanticVerifierMoveOwner::MainWhirFinalQueries
    );
    for ((expected_ordinal, descriptor), transition) in schedule
        .moves()
        .iter()
        .enumerate()
        .zip(&catalog.transitions)
    {
        assert_eq!(
            usize::try_from(descriptor.verifier_move_ordinal()).unwrap(),
            expected_ordinal
        );
        assert!(descriptor.preceding_prover_response_ordinal() > 0);
        assert!(descriptor.preceding_commitment_count() > 0);
        assert_eq!(
            descriptor.extraction_field_operation_bound(),
            transition.extraction_field_operation_bound
        );
        assert_eq!(descriptor.extraction_error(), &transition.extraction_error);
        assert_eq!(
            descriptor.extraction_non_field_operation_bound(),
            transition.extraction_non_field_operation_bound
        );
        assert_eq!(
            descriptor.extraction_operation_bound(),
            transition.extraction_operation_bound
        );
        assert_eq!(
            descriptor.extraction_operation_bound(),
            descriptor.extraction_field_operation_bound()
                + descriptor.extraction_non_field_operation_bound()
        );
        assert!(matches!(
            descriptor.challenge_space(),
            ExactChallengeSpace::ExtensionVector { .. }
                | ExactChallengeSpace::BaseElementExtensionVectorAndDistinctQueries { .. }
                | ExactChallengeSpace::ExtensionVectorAndDistinctQueries { .. }
                | ExactChallengeSpace::DistinctQueries { .. }
        ));
    }
}

#[test]
fn factor_one_schedule_refuses_changed_move_count_and_challenge_distribution() {
    let catalog = factor_one_catalog();

    let mut missing_move = catalog.clone();
    missing_move.transitions.pop();
    assert_eq!(
        SemanticFactorOneSchedule::from_catalog(&missing_move),
        Err(SemanticExecutionError::InvalidFactorOneSchedule)
    );

    let mut changed_lookup_distribution = catalog.clone();
    changed_lookup_distribution.transitions[0].challenge_space =
        ExactChallengeSpace::ExtensionVector {
            element_count: 1,
            excluded_element_count: 0,
        };
    assert_eq!(
        SemanticFactorOneSchedule::from_catalog(&changed_lookup_distribution),
        Err(SemanticExecutionError::InvalidFactorOneSchedule)
    );

    let mut changed_last_round_exclusion = catalog.clone();
    let last_cfw_round = changed_last_round_exclusion
        .transitions
        .iter_mut()
        .find(|transition| {
            transition.roles == [VerifierMoveRole::CfwSumcheckRound { round_ordinal: 22 }]
        })
        .expect("last CFW round exists");
    last_cfw_round.challenge_space = ExactChallengeSpace::ExtensionVector {
        element_count: 1,
        excluded_element_count: 0,
    };
    assert_eq!(
        SemanticFactorOneSchedule::from_catalog(&changed_last_round_exclusion),
        Err(SemanticExecutionError::InvalidFactorOneSchedule)
    );

    let mut changed_code_switch_queries = catalog.clone();
    let first_code_switch = changed_code_switch_queries
        .transitions
        .iter_mut()
        .find(|transition| {
            matches!(
                transition.roles.as_slice(),
                [VerifierMoveRole::WhirRoundQueryAndCombination { .. }]
            )
        })
        .expect("a WHIR code-switch move exists");
    match &mut first_code_switch.challenge_space {
        ExactChallengeSpace::BaseElementExtensionVectorAndDistinctQueries { groups, .. } => {
            groups[0].query_count += 1;
        }
        _ => panic!("code-switch challenge space has its canonical variant"),
    }
    assert_eq!(
        SemanticFactorOneSchedule::from_catalog(&changed_code_switch_queries),
        Err(SemanticExecutionError::InvalidFactorOneSchedule)
    );

    let mut changed_final_query_order = catalog.clone();
    let main_final_queries = changed_final_query_order
        .transitions
        .iter_mut()
        .find(|transition| {
            transition.roles
                == [VerifierMoveRole::WhirFinalQueries {
                    epoch: TranscriptEpoch::Main,
                }]
        })
        .expect("main WHIR final-query move exists");
    match &mut main_final_queries.challenge_space {
        ExactChallengeSpace::DistinctQueries { groups } => groups.swap(0, 1),
        _ => panic!("final-query challenge space has its canonical variant"),
    }
    assert_eq!(
        SemanticFactorOneSchedule::from_catalog(&changed_final_query_order),
        Err(SemanticExecutionError::InvalidFactorOneSchedule)
    );

    let mut split_combined_move = catalog;
    split_combined_move.transitions[26].roles = vec![VerifierMoveRole::CfwJointConstraint];
    assert_eq!(
        SemanticFactorOneSchedule::from_catalog(&split_combined_move),
        Err(SemanticExecutionError::InvalidFactorOneSchedule)
    );
}

#[test]
fn factor_one_schedule_refuses_reordered_whir_semantic_owners() {
    let mut catalog = factor_one_catalog();
    let folding_positions = catalog
        .transitions
        .iter()
        .enumerate()
        .filter_map(|(position, transition)| match transition.roles.as_slice() {
            [
                VerifierMoveRole::WhirFolding {
                    epoch: TranscriptEpoch::PreChallenge,
                    batch_ordinal: 0,
                    round_ordinal: 0 | 1,
                },
            ] => Some(position),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [first, second] = folding_positions.as_slice() else {
        panic!("the first pre-challenge batch must have two folding moves")
    };
    let first_roles = catalog.transitions[*first].roles.clone();
    catalog.transitions[*first].roles = catalog.transitions[*second].roles.clone();
    catalog.transitions[*second].roles = first_roles;

    assert_eq!(
        SemanticFactorOneSchedule::from_catalog(&catalog),
        Err(SemanticExecutionError::InvalidFactorOneSchedule)
    );
}
