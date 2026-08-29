use std::collections::BTreeSet;

use crate::{
    foundation::FOUNDATION_PROFILE,
    tally_circuit::{
        TallyBallotInput, TallyCircuitError, TallyCircuitProfile, TallyEvaluationInput,
        evaluate_tally_directly,
    },
};

use super::{
    direct_mpc_candidate_compiler::{
        DIRECT_MPC_FAULT_DISPOSITIONS, DIRECT_MPC_SCORE_BIT_COUNT,
        DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH,
        DIRECT_MPC_VALIDATION_REPETITION_COUNT, DirectMpcArithmeticOperation,
        DirectMpcCandidateError, DirectMpcFaultClass, DirectMpcFaultDisposition,
        DirectMpcInputRole, DirectMpcOperationRole, DirectMpcRoundKind,
        compile_direct_mpc_candidate, derive_validation_coefficients,
    },
    direct_mpc_prime_field::DirectMpcPrimeFieldElement,
};

const VALIDATION_CHALLENGE_CONTEXT: [u8; DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH] =
    [0x5a; DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH];

fn completion_profile(top_count: u16) -> TallyCircuitProfile {
    TallyCircuitProfile::new(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        top_count,
    )
    .unwrap()
}

fn ballot(is_present: bool, score_encodings: Vec<u8>) -> TallyBallotInput {
    TallyBallotInput::new(is_present, score_encodings)
}

fn empty_input() -> TallyEvaluationInput {
    TallyEvaluationInput::new(empty_ballots())
}

fn empty_ballots() -> Vec<TallyBallotInput> {
    (0..usize::from(FOUNDATION_PROFILE.participant_count))
        .map(|_| ballot(false, vec![0; usize::from(FOUNDATION_PROFILE.option_count)]))
        .collect()
}

#[test]
fn completion_graph_has_exact_validation_evaluation_and_resource_geometry() {
    let compiled = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    assert_eq!(compiled.profile(), completion_profile(10));
    let geometry = compiled.geometry();
    assert_eq!(geometry.input_field_count, 410);
    assert_eq!(geometry.public_input_field_count, 10);
    assert_eq!(geometry.private_score_bit_field_count, 400);
    assert_eq!(geometry.score_bitness_constraint_count, 400);
    assert_eq!(geometry.comparison_pair_count, 45);
    assert_eq!(geometry.comparison_polynomial_degree, 200);
    assert_eq!(geometry.rank_polynomial_degree, 9);
    assert_eq!(
        geometry.validation_multiplication_layer_counts.as_ref(),
        &[500, 200, 100, 50, 20, 10, 10]
    );
    assert_eq!(
        geometry.evaluation_multiplication_layer_counts.as_ref(),
        &[45, 90, 180, 360, 720, 1_440, 2_880, 3_240, 10, 20, 40, 10]
    );
    assert_eq!(geometry.beaver_triple_count, 9_925);
    assert_eq!(geometry.public_scale_operation_count, 110);

    let multiplication_records = compiled
        .operations()
        .iter()
        .filter(|record| {
            matches!(
                record.operation,
                DirectMpcArithmeticOperation::Multiply { .. }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(multiplication_records.len(), 9_925);
    assert!(
        multiplication_records
            .iter()
            .enumerate()
            .all(|(ordinal, record)| {
                record.multiplication_ordinal == u32::try_from(ordinal).ok()
            })
    );
    assert!(compiled.operations().iter().all(|record| {
        usize::try_from(record.output_wire).unwrap() < geometry.total_wire_count
            && match &record.operation {
                DirectMpcArithmeticOperation::Affine { terms, .. } => {
                    terms.iter().all(|(wire, _)| *wire < record.output_wire)
                }
                DirectMpcArithmeticOperation::Multiply {
                    left_wire,
                    right_wire,
                } => *left_wire < record.output_wire && *right_wire < record.output_wire,
                DirectMpcArithmeticOperation::MultiplyByPublic {
                    value_wire,
                    public_wire,
                } => *value_wire < record.output_wire && *public_wire < record.output_wire,
            }
    }));

    let bitness_multiplication_count = multiplication_records
        .iter()
        .filter(|record| {
            matches!(
                record.role,
                DirectMpcOperationRole::ScoreBitnessConstraint { .. }
            )
        })
        .count();
    let score_validity_multiplication_count = multiplication_records
        .iter()
        .filter(|record| matches!(record.role, DirectMpcOperationRole::ScoreValidity { .. }))
        .count();
    let ballot_validity_multiplication_count = multiplication_records
        .iter()
        .filter(|record| {
            matches!(
                record.role,
                DirectMpcOperationRole::BallotValidityProduct { .. }
            )
        })
        .count();
    let comparison_power_count = multiplication_records
        .iter()
        .filter(|record| matches!(record.role, DirectMpcOperationRole::ComparisonPower { .. }))
        .count();
    let rank_power_count = multiplication_records
        .iter()
        .filter(|record| matches!(record.role, DirectMpcOperationRole::RankPower { .. }))
        .count();
    assert_eq!(bitness_multiplication_count, 400);
    assert_eq!(score_validity_multiplication_count, 400);
    assert_eq!(ballot_validity_multiplication_count, 90);
    assert_eq!(comparison_power_count, 8_955);
    assert_eq!(rank_power_count, 80);

    let resource = compiled.resource_model().unwrap();
    assert_eq!(resource.participant_count, 10);
    assert_eq!(resource.active_fault_bound, 3);
    assert_eq!(resource.reconstruction_threshold, 4);
    assert_eq!(resource.finality_quorum, 7);
    assert_eq!(resource.field_canonical_byte_length, 3);
    assert_eq!(resource.field_sample_byte_length, 16);
    assert_eq!(resource.beaver_triple_count, 9_925);
    assert_eq!(resource.random_degree_three_sharing_count, 30_175);
    assert_eq!(resource.random_degree_six_zero_sharing_count, 9_925);
    assert_eq!(resource.source_consistency_mask_count, 400);
    assert_eq!(resource.validation_challenge_coefficient_count, 3_200);
    assert_eq!(resource.authorized_subset_count, 120);
    assert_eq!(resource.authorized_subset_size, 7);
    assert_eq!(resource.authorized_subset_count_per_participant, 84);
    assert_eq!(resource.subset_seed_contribution_count, 840);
    assert_eq!(
        resource.private_subset_seed_contribution_delivery_count,
        5_040
    );
    assert_eq!(resource.seed_mailbox_message_count, 90);
    assert_eq!(resource.ballot_source_mailbox_message_count, 90);
    assert_eq!(resource.private_ballot_share_field_element_count, 3_600);
    assert_eq!(
        resource.persistent_ballot_share_field_count_per_participant,
        400
    );
    assert_eq!(
        resource.ordinary_prss_field_output_count_per_participant,
        2_534_700
    );
    assert_eq!(
        resource.zero_prss_field_output_count_per_participant,
        2_501_100
    );
    assert_eq!(
        resource.total_prss_field_output_count_per_participant,
        5_035_800
    );
    assert_eq!(
        resource.total_prss_source_byte_length_per_participant,
        80_572_800
    );
    assert_eq!(resource.prss_kmacxof256_query_count_per_participant, 336);
    assert_eq!(resource.prss_work_checkpoint_count_per_participant, 336);
    assert_eq!(
        resource.validation_xof_field_output_count_per_participant,
        3_200
    );
    assert_eq!(
        resource.maximum_prss_xof_output_allocation_byte_length,
        482_800
    );
    assert_eq!(
        resource.maximum_prss_accumulator_allocation_byte_length,
        90_525
    );
    assert_eq!(
        resource.persistent_secret_field_count_per_participant,
        30_575
    );
    assert_eq!(
        resource.persistent_secret_field_byte_length_per_participant,
        91_725
    );
    assert_eq!(
        resource.joined_subset_master_byte_length_per_participant,
        3_360
    );
    assert_eq!(resource.public_raw_field_element_count, 302_030);
    assert_eq!(resource.public_raw_field_byte_length, 906_090);
    assert_eq!(resource.public_signed_message_count, 291);
    assert_eq!(resource.private_signed_message_count, 180);
    assert_eq!(resource.total_signature_generation_count, 471);
    assert_eq!(resource.private_kem_encapsulation_count, 180);
    assert_eq!(resource.private_aead_seal_count, 180);
}

#[test]
fn interaction_graph_fixes_every_success_and_no_result_dependency() {
    let compiled = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let graph = compiled.interaction_graph().unwrap();
    assert_eq!(graph.success_rounds.len(), 31);
    assert_eq!(graph.success_maximum_sequential_visit_count, 301);
    assert_eq!(graph.success_minimum_visit_count_with_boundary_overlap, 271);
    assert_eq!(graph.all_abstention_rounds.len(), 6);
    assert_eq!(graph.all_abstention_maximum_sequential_visit_count, 57);
    assert_eq!(
        graph.all_abstention_minimum_visit_count_with_boundary_overlap,
        52
    );
    assert!(
        graph
            .success_rounds
            .iter()
            .enumerate()
            .all(|(position, round)| {
                usize::from(round.ordinal) == position + 1
                    && round.requires_durable_checkpoint_before_emit
            })
    );
    assert!(matches!(
        graph.success_rounds[15].kind,
        DirectMpcRoundKind::SelectedSetAuthorization
    ));
    assert!(matches!(
        graph.success_rounds[16].kind,
        DirectMpcRoundKind::TargetFinality
    ));
    assert!(matches!(
        graph.success_rounds[17].kind,
        DirectMpcRoundKind::EvaluationMultiplicationOpenings { layer: 1, .. }
    ));
    assert!(matches!(
        graph.success_rounds[30].kind,
        DirectMpcRoundKind::ResultWitnesses
    ));
    assert!(matches!(
        graph.all_abstention_rounds[4].kind,
        DirectMpcRoundKind::BallotDeclarations
    ));
    assert_eq!(graph.all_abstention_rounds[4].private_message_count, 0);
    assert!(matches!(
        graph.all_abstention_rounds[5].kind,
        DirectMpcRoundKind::NoResultWitnesses
    ));
    assert_eq!(
        graph
            .all_abstention_rounds
            .iter()
            .map(|round| round.public_message_count)
            .sum::<u64>(),
        47
    );
    assert_eq!(
        graph
            .all_abstention_rounds
            .iter()
            .map(|round| round.private_message_count)
            .sum::<u64>(),
        90
    );
    assert_eq!(
        graph
            .all_abstention_rounds
            .iter()
            .map(|round| round.public_field_element_count)
            .sum::<u64>(),
        99_250
    );
    assert_eq!(
        DIRECT_MPC_FAULT_DISPOSITIONS,
        &[
            (
                DirectMpcFaultClass::MissingRequiredMessage,
                DirectMpcFaultDisposition::Pending,
            ),
            (
                DirectMpcFaultClass::UnauthenticatedMalformedMessage,
                DirectMpcFaultDisposition::Pending,
            ),
            (
                DirectMpcFaultClass::AuthenticatedAlgebraicInconsistency,
                DirectMpcFaultDisposition::TerminalBurn,
            ),
            (
                DirectMpcFaultClass::ForkedAuthenticatedTranscript,
                DirectMpcFaultDisposition::TerminalBurn,
            ),
            (
                DirectMpcFaultClass::ReplayAfterTerminal,
                DirectMpcFaultDisposition::RefusedConsumedState,
            ),
            (
                DirectMpcFaultClass::RollbackDetected,
                DirectMpcFaultDisposition::ParticipantRetiredAndPending,
            ),
            (
                DirectMpcFaultClass::ParticipantStateLost,
                DirectMpcFaultDisposition::ParticipantRetiredAndPending,
            ),
        ]
    );
}

#[test]
fn every_completion_top_count_matches_the_independent_tally_semantics() {
    let mut cases = Vec::new();
    cases.push(empty_input());

    let mut one_submission = empty_ballots();
    one_submission[4] = ballot(true, vec![1, 10, 3, 9, 5, 8, 7, 6, 4, 2]);
    cases.push(TallyEvaluationInput::new(one_submission));

    cases.push(TallyEvaluationInput::new(
        (0..10)
            .map(|participant_position| {
                let score = if participant_position % 2 == 0 { 1 } else { 10 };
                ballot(true, vec![score; 10])
            })
            .collect(),
    ));

    let mut invalid_and_valid = empty_ballots();
    invalid_and_valid[0] = ballot(true, vec![0; 10]);
    invalid_and_valid[1] = ballot(true, vec![11; 10]);
    invalid_and_valid[2] = ballot(true, vec![5; 10]);
    invalid_and_valid[3] = ballot(true, vec![10, 1, 9, 2, 8, 3, 7, 4, 6, 5]);
    cases.push(TallyEvaluationInput::new(invalid_and_valid));

    cases.push(TallyEvaluationInput::new(
        (0..10)
            .map(|participant_position| {
                ballot(
                    participant_position % 3 != 0,
                    (0..10)
                        .map(|option_position| {
                            (((participant_position * 7 + option_position * 3) % 15) + 1) as u8
                        })
                        .collect(),
                )
            })
            .collect(),
    ));

    let mut generator_state = 0xd6e8_feb8_6659_fd93_u64;
    for _case_position in 0..24 {
        cases.push(TallyEvaluationInput::new(
            (0..10)
                .map(|_| {
                    generator_state ^= generator_state << 13;
                    generator_state ^= generator_state >> 7;
                    generator_state ^= generator_state << 17;
                    let is_present = generator_state & 1 == 1;
                    let scores = (0..10)
                        .map(|_| {
                            generator_state ^= generator_state << 13;
                            generator_state ^= generator_state >> 7;
                            generator_state ^= generator_state << 17;
                            (generator_state & 15) as u8
                        })
                        .collect();
                    ballot(is_present, scores)
                })
                .collect(),
        ));
    }

    for top_count in 1..=FOUNDATION_PROFILE.option_count {
        let profile = completion_profile(top_count);
        let compiled = compile_direct_mpc_candidate(profile).unwrap();
        for input in &cases {
            let candidate = compiled
                .evaluate(input, &VALIDATION_CHALLENGE_CONTEXT)
                .unwrap();
            let direct = evaluate_tally_directly(profile, input).unwrap();
            assert_eq!(
                candidate.ordered_option_positions(),
                direct.accepted_ordered_option_positions()
            );
            let expected_authorship = input
                .participant_ballots()
                .iter()
                .map(|ballot| {
                    ballot.is_present()
                        && ballot
                            .score_encodings()
                            .iter()
                            .all(|score| (1..=10).contains(score))
                })
                .collect::<Vec<_>>();
            assert_eq!(candidate.accepted_ballot_authorship(), expected_authorship);
        }

        let resource = compiled.resource_model().unwrap();
        assert_eq!(
            resource.public_raw_field_element_count,
            301_930 + u64::from(top_count) * 10
        );
        assert_eq!(
            compiled.ordered_option_position_wires().len(),
            usize::from(top_count)
        );
    }
}

#[test]
fn score_validity_matches_all_four_bit_encodings_in_every_option_position() {
    let compiled = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    for participant_position in [0, 5, 9] {
        for option_position in 0..10 {
            for score_encoding in 0_u8..16 {
                let mut ballots = empty_ballots();
                let mut scores = vec![5; 10];
                scores[option_position] = score_encoding;
                ballots[participant_position] = ballot(true, scores);
                let input = TallyEvaluationInput::new(ballots);
                let outcome = compiled
                    .evaluate(&input, &VALIDATION_CHALLENGE_CONTEXT)
                    .unwrap();
                assert_eq!(
                    outcome.accepted_ballot_authorship()[participant_position],
                    (1..=10).contains(&score_encoding)
                );
            }
        }
    }
}

#[test]
fn hostile_nonboolean_sources_and_malformed_inputs_refuse() {
    let compiled = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let mut input_fields = compiled.encode_tally_input(&empty_input()).unwrap();
    let first_score_bit_wire = compiled
        .input_wires()
        .iter()
        .find_map(|record| match record.role {
            DirectMpcInputRole::PrivateScoreBit { .. } => Some(record.wire),
            DirectMpcInputRole::PublicBallotPresence { .. } => None,
        })
        .unwrap();
    input_fields[usize::try_from(first_score_bit_wire).unwrap()] =
        DirectMpcPrimeFieldElement::from_u16(2);
    assert_eq!(
        compiled.evaluate_input_fields(&input_fields, &VALIDATION_CHALLENGE_CONTEXT),
        Err(DirectMpcCandidateError::ScoreBitnessCheckFailed)
    );
    assert_eq!(
        compiled.evaluate_input_fields(
            &input_fields,
            &[0; DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH - 1],
        ),
        Err(
            DirectMpcCandidateError::ValidationChallengeContextByteLength {
                expected: DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH,
                actual: DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH - 1,
            }
        )
    );

    let mut oversized_ballots = empty_ballots();
    let mut oversized_scores = vec![0; 10];
    oversized_scores[7] = 16;
    oversized_ballots[3] = ballot(false, oversized_scores);
    let oversized_score = TallyEvaluationInput::new(oversized_ballots);
    assert!(matches!(
        compiled.evaluate(&oversized_score, &VALIDATION_CHALLENGE_CONTEXT),
        Err(DirectMpcCandidateError::TallyCircuit(
            TallyCircuitError::ScoreEncodingOutOfRange {
                participant_position: 3,
                option_position: 7,
                score_encoding: 16,
            }
        ))
    ));

    let wrong_profile = TallyCircuitProfile::new(9, 10, 10).unwrap();
    assert_eq!(
        compile_direct_mpc_candidate(wrong_profile),
        Err(DirectMpcCandidateError::CompletionProfileRequired {
            participant_count: 9,
            option_count: 10,
        })
    );
}

#[test]
fn validation_coefficients_bind_each_predecessor_context_component() {
    let profile = completion_profile(10);
    let baseline = derive_validation_coefficients(
        profile,
        &VALIDATION_CHALLENGE_CONTEXT,
        DIRECT_MPC_VALIDATION_REPETITION_COUNT,
    )
    .unwrap();

    for changed_position in [0, 64, 128] {
        let mut changed_context = VALIDATION_CHALLENGE_CONTEXT;
        changed_context[changed_position] ^= 1;
        assert_ne!(
            derive_validation_coefficients(
                profile,
                &changed_context,
                DIRECT_MPC_VALIDATION_REPETITION_COUNT,
            )
            .unwrap(),
            baseline,
        );
    }
}

#[test]
fn every_input_and_output_role_is_unique_and_complete() {
    let compiled = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let input_wire_set = compiled
        .input_wires()
        .iter()
        .map(|record| record.wire)
        .collect::<BTreeSet<_>>();
    assert_eq!(input_wire_set.len(), 410);
    assert_eq!(compiled.score_bitness_constraint_wires().len(), 400);
    assert_eq!(compiled.accepted_ballot_authorship_wires().len(), 10);
    assert_eq!(compiled.ordered_option_position_wires().len(), 10);
    assert!(
        compiled
            .accepted_ballot_authorship_wires()
            .iter()
            .all(|wire| !input_wire_set.contains(wire))
    );
    assert_eq!(DIRECT_MPC_SCORE_BIT_COUNT, 4);
}
