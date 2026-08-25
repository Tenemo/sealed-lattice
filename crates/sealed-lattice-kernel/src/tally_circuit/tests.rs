use std::collections::BTreeSet;

use super::{
    BooleanOperation, TALLY_CANDIDATE_ATTEMPT_COUNT, TALLY_CIRCUIT_ARTIFACT_MAGIC,
    TallyCandidateAttemptInput, TallyCircuitError, TallyCircuitProfile, TallyEvaluationInput,
    codec::{decode_canonical_tally_circuit, encode_canonical_tally_circuit},
    compiler::{compile_tally_circuit, tally_circuit_compiler_identity},
    direct_evaluator::{evaluate_tally_directly, tally_direct_evaluator_identity},
    interpreter::{evaluate_compiled_tally_circuit, interpret_boolean_operations},
};
use crate::foundation::{
    FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_OPTION_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
};

fn profile(participant_count: u16, option_count: u16, top_count: u16) -> TallyCircuitProfile {
    TallyCircuitProfile::new(participant_count, option_count, top_count)
        .expect("test profile must be admitted")
}

fn candidate_attempt(is_present: bool, score_encodings: Vec<u8>) -> TallyCandidateAttemptInput {
    TallyCandidateAttemptInput::new(is_present, score_encodings)
}

fn absent_candidate_attempt(option_count: usize) -> TallyCandidateAttemptInput {
    candidate_attempt(false, vec![0; option_count])
}

fn participant_with_first_attempt(
    is_present: bool,
    score_encodings: Vec<u8>,
) -> Vec<TallyCandidateAttemptInput> {
    let option_count = score_encodings.len();
    vec![
        candidate_attempt(is_present, score_encodings),
        absent_candidate_attempt(option_count),
        absent_candidate_attempt(option_count),
    ]
}

fn empty_election_input(participant_count: usize, option_count: usize) -> TallyEvaluationInput {
    TallyEvaluationInput::new(
        (0..participant_count)
            .map(|_| {
                (0..TALLY_CANDIDATE_ATTEMPT_COUNT)
                    .map(|_| absent_candidate_attempt(option_count))
                    .collect()
            })
            .collect(),
    )
}

fn compare_interpreter_and_direct_evaluator(
    selected_profile: TallyCircuitProfile,
    input: &TallyEvaluationInput,
) {
    let compiled_circuit = compile_tally_circuit(selected_profile).expect("circuit must compile");
    compare_compiled_circuit_and_direct_evaluator(&compiled_circuit, input);
}

fn compare_compiled_circuit_and_direct_evaluator(
    compiled_circuit: &super::CompiledTallyCircuit,
    input: &TallyEvaluationInput,
) {
    let interpreted = evaluate_compiled_tally_circuit(compiled_circuit, input)
        .expect("compiled circuit must evaluate");
    let direct = evaluate_tally_directly(compiled_circuit.profile(), input)
        .expect("direct semantics must evaluate");
    assert_eq!(interpreted, direct);
}

#[test]
fn completion_profile_full_ranking_reproduces_corrected_reference_geometry() {
    let compiled_circuit = compile_tally_circuit(profile(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        FOUNDATION_PROFILE.option_count,
    ))
    .expect("completion-profile circuit must compile");
    let geometry = compiled_circuit.geometry();

    assert_eq!(geometry.input_bit_count, 1_230);
    assert_eq!(geometry.candidate_attempt_presence_input_bit_count, 30);
    assert_eq!(geometry.private_score_input_bit_count, 1_200);
    assert_eq!(geometry.candidate_attempt_count, 3);
    assert_eq!(geometry.constant_operation_count, 2);
    assert_eq!(geometry.conjunction_gate_count, 5_422);
    assert_eq!(geometry.exclusive_or_gate_count, 6_283);
    assert_eq!(geometry.negation_gate_count, 976);
    assert_eq!(
        geometry.fresh_input_and_conjunction_output_wire_count,
        6_652
    );
    assert_eq!(geometry.folded_conjunction_count, 153);
    assert_eq!(geometry.folded_exclusive_or_count, 652);
    assert_eq!(geometry.folded_negation_count, 14);
    assert_eq!(geometry.duplicate_input_conjunction_count, 0);
    assert_eq!(geometry.public_output_bit_count, 1);
    assert_eq!(geometry.private_result_bit_count, 40);
    assert_eq!(geometry.score_bit_width, 4);
    assert_eq!(geometry.aggregate_score_bit_width, 7);
    assert_eq!(geometry.option_position_bit_width, 4);
    assert_eq!(geometry.total_wire_count, 13_913);
}

#[test]
fn randomized_elections_match_for_every_admitted_structural_profile() {
    let mut generator = DeterministicGenerator::new(0x77d4_f058_196b_2c31);
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let selected_profile = profile(participant_count, option_count, top_count);
                let compiled_circuit = compile_tally_circuit(selected_profile)
                    .expect("every admitted structural profile must compile");
                let geometry = compiled_circuit.geometry();
                let participant_count = usize::from(participant_count);
                let option_count = usize::from(option_count);
                assert_eq!(
                    geometry.input_bit_count,
                    participant_count * TALLY_CANDIDATE_ATTEMPT_COUNT * (1 + option_count * 4)
                );
                assert_eq!(
                    compiled_circuit.candidate_attempt_presence_wires().len(),
                    participant_count
                );
                assert_eq!(
                    compiled_circuit.ordered_option_position_wires().len(),
                    usize::from(top_count)
                );
                assert!(compiled_circuit.operations().iter().enumerate().all(
                    |(operation_position, operation)| operation.referenced_wires().all(|wire| {
                        usize::try_from(wire).expect("wire index fits usize")
                            < geometry.input_bit_count + operation_position
                    })
                ));
                assert!(compiled_circuit.operations().iter().all(|operation| {
                    !matches!(
                        operation,
                        BooleanOperation::Conjunction {
                            left_wire,
                            right_wire
                        } if left_wire == right_wire
                    )
                }));

                let input = random_election_input(&mut generator, participant_count, option_count);
                compare_compiled_circuit_and_direct_evaluator(&compiled_circuit, &input);
            }
        }
    }
}

#[test]
fn every_completion_profile_top_count_has_canonical_distinct_bytes() {
    let mut circuit_identities = BTreeSet::new();
    for top_count in 1..=FOUNDATION_PROFILE.option_count {
        let compiled_circuit = compile_tally_circuit(profile(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            top_count,
        ))
        .expect("each completion-profile top count must compile");
        let bytes = encode_canonical_tally_circuit(&compiled_circuit)
            .expect("each circuit must encode canonically");
        let decoded =
            decode_canonical_tally_circuit(&bytes).expect("each circuit must decode canonically");
        assert_eq!(decoded, compiled_circuit);
        assert!(
            circuit_identities.insert(
                compiled_circuit
                    .circuit_identity()
                    .expect("circuit identity must derive")
            ),
            "each top count must have a distinct circuit identity"
        );
    }
}

#[test]
fn source_bound_identities_and_artifact_bytes_are_reproducible() {
    let compiler_source = include_bytes!("compiler.rs");
    let direct_evaluator_source = include_bytes!("direct_evaluator.rs");
    for source in [
        compiler_source.as_slice(),
        direct_evaluator_source.as_slice(),
    ] {
        assert!(core::str::from_utf8(source).is_ok());
        assert!(!source.contains(&b'\r'));
        assert!(source.ends_with(b"\n"));
    }
    assert_ne!(
        tally_circuit_compiler_identity().expect("compiler identity must derive"),
        tally_direct_evaluator_identity().expect("semantic oracle identity must derive")
    );

    let selected_profile = profile(10, 10, 10);
    let first = compile_tally_circuit(selected_profile).expect("first circuit must compile");
    let second = compile_tally_circuit(selected_profile).expect("second circuit must compile");
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap()
    );
    assert_eq!(
        first.circuit_identity().unwrap(),
        second.circuit_identity().unwrap()
    );
}

#[test]
fn every_four_bit_score_encoding_is_checked_in_every_attempt_and_option_position() {
    let selected_profile = profile(3, 2, 2);
    for attempt_position in 0..TALLY_CANDIDATE_ATTEMPT_COUNT {
        for option_position in 0..2 {
            for score_encoding in 0_u8..16 {
                let mut input = empty_election_input(3, 2);
                let participant_attempts = &mut input.participant_candidate_attempts[0];
                participant_attempts[attempt_position] = candidate_attempt(true, vec![7, 7]);
                participant_attempts[attempt_position].score_encodings[option_position] =
                    score_encoding;
                if attempt_position + 1 < TALLY_CANDIDATE_ATTEMPT_COUNT {
                    participant_attempts[attempt_position + 1] =
                        candidate_attempt(true, vec![10, 1]);
                }
                compare_interpreter_and_direct_evaluator(selected_profile, &input);
            }
        }
    }
}

#[test]
fn every_presence_and_private_validity_retry_pattern_selects_the_first_valid_attempt() {
    let selected_profile = profile(3, 3, 3);
    let distinct_valid_scores = [vec![10, 5, 1], vec![1, 10, 5], vec![5, 1, 10]];
    for presence_pattern in 0_u8..8 {
        for validity_pattern in 0_u8..8 {
            let mut input = empty_election_input(3, 3);
            for attempt_position in 0..TALLY_CANDIDATE_ATTEMPT_COUNT {
                let is_present = (presence_pattern >> attempt_position) & 1 == 1;
                let is_valid = (validity_pattern >> attempt_position) & 1 == 1;
                let scores = if is_valid {
                    distinct_valid_scores[attempt_position].clone()
                } else {
                    let mut invalid_scores = distinct_valid_scores[attempt_position].clone();
                    invalid_scores[attempt_position] = 15;
                    invalid_scores
                };
                input.participant_candidate_attempts[0][attempt_position] =
                    candidate_attempt(is_present, scores);
            }

            compare_interpreter_and_direct_evaluator(selected_profile, &input);
            let outcome = evaluate_tally_directly(selected_profile, &input).unwrap();
            let selected_attempt = (0..TALLY_CANDIDATE_ATTEMPT_COUNT).find(|attempt_position| {
                (presence_pattern >> attempt_position) & 1 == 1
                    && (validity_pattern >> attempt_position) & 1 == 1
            });
            assert_eq!(outcome.has_selected_ballot(), selected_attempt.is_some());
            if let Some(selected_attempt) = selected_attempt {
                let expected_order = match selected_attempt {
                    0 => [0, 1, 2],
                    1 => [1, 2, 0],
                    2 => [2, 0, 1],
                    _ => unreachable!(),
                };
                assert_eq!(
                    outcome.accepted_ordered_option_positions(),
                    Some(expected_order.as_slice())
                );
            } else {
                assert_eq!(outcome.accepted_ordered_option_positions(), None);
            }
        }
    }
}

#[test]
fn invalid_first_attempt_does_not_block_a_later_valid_attempt() {
    let selected_profile = profile(10, 3, 3);
    let mut input = empty_election_input(10, 3);
    input.participant_candidate_attempts[0] = vec![
        candidate_attempt(true, vec![15, 1, 1]),
        candidate_attempt(true, vec![10, 9, 1]),
        candidate_attempt(false, vec![0, 0, 0]),
    ];
    for participant_position in 1..10 {
        input.participant_candidate_attempts[participant_position][0] =
            candidate_attempt(true, vec![1, 1, 1]);
    }

    compare_interpreter_and_direct_evaluator(selected_profile, &input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2].as_slice())
    );
}

#[test]
fn empty_submission_and_all_invalid_attempts_both_produce_no_result() {
    let selected_profile = profile(3, 3, 3);
    let no_submissions = empty_election_input(3, 3);
    compare_interpreter_and_direct_evaluator(selected_profile, &no_submissions);
    let no_submission_outcome = evaluate_tally_directly(selected_profile, &no_submissions).unwrap();
    assert!(!no_submission_outcome.has_selected_ballot());
    assert_eq!(no_submission_outcome.ordered_option_positions(), &[0, 1, 2]);
    assert_eq!(
        no_submission_outcome.accepted_ordered_option_positions(),
        None
    );

    let all_invalid = TallyEvaluationInput::new(
        (0..3)
            .map(|participant_position| {
                vec![
                    candidate_attempt(true, vec![0, 1, 2]),
                    candidate_attempt(true, vec![11, 3, 4]),
                    candidate_attempt(true, vec![5, 15, participant_position as u8]),
                ]
            })
            .collect(),
    );
    compare_interpreter_and_direct_evaluator(selected_profile, &all_invalid);
    let all_invalid_outcome = evaluate_tally_directly(selected_profile, &all_invalid).unwrap();
    assert!(!all_invalid_outcome.has_selected_ballot());
    assert_eq!(
        all_invalid_outcome.accepted_ordered_option_positions(),
        None
    );
}

#[test]
fn one_ballot_maximum_sums_and_complete_ties_have_stable_ordering() {
    let selected_profile = profile(10, 10, 10);

    let mut one_ballot_input = empty_election_input(10, 10);
    one_ballot_input.participant_candidate_attempts[4] =
        participant_with_first_attempt(true, vec![1, 10, 3, 9, 5, 8, 7, 6, 4, 2]);
    compare_interpreter_and_direct_evaluator(selected_profile, &one_ballot_input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &one_ballot_input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([1, 3, 5, 6, 7, 4, 8, 2, 9, 0].as_slice())
    );

    let maximum_sum_input = TallyEvaluationInput::new(
        (0..10)
            .map(|_| participant_with_first_attempt(true, vec![10; 10]))
            .collect(),
    );
    compare_interpreter_and_direct_evaluator(selected_profile, &maximum_sum_input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &maximum_sum_input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );

    let complete_tie_input = TallyEvaluationInput::new(
        (0..10)
            .map(|_| participant_with_first_attempt(true, vec![6; 10]))
            .collect(),
    );
    compare_interpreter_and_direct_evaluator(selected_profile, &complete_tie_input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &complete_tie_input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );
}

#[test]
fn canonical_verifier_rejects_operation_wiring_constant_input_retry_and_output_mutations() {
    let selected_profile = profile(10, 10, 10);
    let canonical_circuit = compile_tally_circuit(selected_profile).unwrap();

    let mut operation_mutation = canonical_circuit.clone();
    let operation = operation_mutation
        .operations
        .iter_mut()
        .find(|operation| matches!(operation, BooleanOperation::ExclusiveOr { .. }))
        .expect("circuit contains an exclusive-or gate");
    if let BooleanOperation::ExclusiveOr {
        left_wire,
        right_wire,
    } = *operation
    {
        *operation = BooleanOperation::Conjunction {
            left_wire,
            right_wire,
        };
    }
    assert_canonical_mutation_refuses(&operation_mutation);

    let mut wiring_mutation = canonical_circuit.clone();
    let operation = wiring_mutation
        .operations
        .iter_mut()
        .find(|operation| matches!(operation, BooleanOperation::Conjunction { .. }))
        .expect("circuit contains a conjunction gate");
    if let BooleanOperation::Conjunction { left_wire, .. } = operation {
        *left_wire = if *left_wire == 0 { 1 } else { 0 };
    }
    assert_canonical_mutation_refuses(&wiring_mutation);

    let mut constant_mutation = canonical_circuit.clone();
    let constant = constant_mutation
        .operations
        .iter_mut()
        .find_map(|operation| match operation {
            BooleanOperation::Constant(value) => Some(value),
            _ => None,
        })
        .expect("circuit contains a constant operation");
    *constant = !*constant;
    assert_canonical_mutation_refuses(&constant_mutation);

    let mut input_mapping_mutation = canonical_circuit.clone();
    input_mapping_mutation.candidate_attempt_score_wires[0][0][0].swap(0, 1);
    assert_canonical_mutation_refuses(&input_mapping_mutation);

    let mut retry_order_mutation = canonical_circuit.clone();
    retry_order_mutation.candidate_attempt_presence_wires[0].swap(0, 1);
    retry_order_mutation.candidate_attempt_score_wires[0].swap(0, 1);
    assert_canonical_mutation_refuses(&retry_order_mutation);

    let mut public_output_mutation = canonical_circuit.clone();
    public_output_mutation.nonempty_output_wire = 0;
    assert_canonical_mutation_refuses(&public_output_mutation);

    let mut private_output_mutation = canonical_circuit.clone();
    private_output_mutation.ordered_option_position_wires[0][0] = 0;
    assert_canonical_mutation_refuses(&private_output_mutation);
}

#[test]
fn canonical_decoder_rejects_framing_compiler_semantic_oracle_and_length_mutations() {
    let canonical_bytes = compile_tally_circuit(profile(3, 2, 2))
        .unwrap()
        .canonical_bytes()
        .unwrap();

    let mut magic_mutation = canonical_bytes.clone();
    magic_mutation[1] ^= 1;
    assert_eq!(
        decode_canonical_tally_circuit(&magic_mutation),
        Err(TallyCircuitError::ArtifactMagicMismatch)
    );

    let version_position = 1 + TALLY_CIRCUIT_ARTIFACT_MAGIC.len();
    let mut version_mutation = canonical_bytes.clone();
    version_mutation[version_position] = 3;
    assert_eq!(
        decode_canonical_tally_circuit(&version_mutation),
        Err(TallyCircuitError::UnsupportedArtifactVersion { version: 3 })
    );

    let compiler_identity_position = version_position + 2;
    let mut compiler_identity_mutation = canonical_bytes.clone();
    compiler_identity_mutation[compiler_identity_position] ^= 1;
    assert_eq!(
        decode_canonical_tally_circuit(&compiler_identity_mutation),
        Err(TallyCircuitError::CompilerIdentityMismatch)
    );

    let direct_evaluator_identity_position = compiler_identity_position + 64 + 1;
    let mut direct_evaluator_identity_mutation = canonical_bytes.clone();
    direct_evaluator_identity_mutation[direct_evaluator_identity_position] ^= 1;
    assert_eq!(
        decode_canonical_tally_circuit(&direct_evaluator_identity_mutation),
        Err(TallyCircuitError::DirectEvaluatorIdentityMismatch)
    );

    let mut trailing_mutation = canonical_bytes.clone();
    trailing_mutation.push(0);
    assert!(matches!(
        decode_canonical_tally_circuit(&trailing_mutation),
        Err(TallyCircuitError::CircuitMismatch)
    ));

    assert!(decode_canonical_tally_circuit(&canonical_bytes[..canonical_bytes.len() - 1]).is_err());

    let mut noncanonical_length = Vec::with_capacity(canonical_bytes.len() + 1);
    noncanonical_length.push(canonical_bytes[0] | 0x80);
    noncanonical_length.push(0);
    noncanonical_length.extend_from_slice(&canonical_bytes[1..]);
    assert!(decode_canonical_tally_circuit(&noncanonical_length).is_err());
}

#[test]
fn input_mapping_is_participant_attempt_option_and_little_endian_bit_order() {
    let selected_profile = profile(3, 2, 2);
    let compiled_circuit = compile_tally_circuit(selected_profile).unwrap();
    assert_eq!(
        compiled_circuit.candidate_attempt_presence_wires[0],
        [0, 9, 18]
    );
    assert_eq!(
        compiled_circuit.candidate_attempt_presence_wires[1],
        [27, 36, 45]
    );
    assert_eq!(
        compiled_circuit.candidate_attempt_score_wires[0][0],
        [vec![1, 2, 3, 4], vec![5, 6, 7, 8]]
    );

    let mut input_bits = vec![false; compiled_circuit.geometry().input_bit_count];
    input_bits[0] = true;
    set_little_endian_score_bits(&mut input_bits, &[1, 2, 3, 4], 2);
    set_little_endian_score_bits(&mut input_bits, &[5, 6, 7, 8], 5);
    let canonical_wire_values =
        interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    let canonical_first_position = decode_position(
        &canonical_wire_values,
        &compiled_circuit.ordered_option_position_wires()[0],
    );
    assert_eq!(canonical_first_position, 1);

    input_bits.swap(2, 4);
    let mutated_wire_values = interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    let mutated_first_position = decode_position(
        &mutated_wire_values,
        &compiled_circuit.ordered_option_position_wires()[0],
    );
    assert_eq!(mutated_first_position, 0);
}

#[test]
fn malformed_profiles_and_transport_shapes_refuse_with_typed_errors() {
    assert!(matches!(
        TallyCircuitProfile::new(2, 2, 1),
        Err(TallyCircuitError::ParticipantCountOutOfRange { .. })
    ));
    assert!(matches!(
        TallyCircuitProfile::new(21, 2, 1),
        Err(TallyCircuitError::ParticipantCountOutOfRange { .. })
    ));
    assert!(matches!(
        TallyCircuitProfile::new(3, 1, 1),
        Err(TallyCircuitError::OptionCountOutOfRange { .. })
    ));
    assert!(matches!(
        TallyCircuitProfile::new(3, 21, 1),
        Err(TallyCircuitError::OptionCountOutOfRange { .. })
    ));
    assert!(matches!(
        TallyCircuitProfile::new(3, 2, 0),
        Err(TallyCircuitError::TopCountOutOfRange { .. })
    ));
    assert!(matches!(
        TallyCircuitProfile::new(3, 2, 3),
        Err(TallyCircuitError::TopCountOutOfRange { .. })
    ));

    let selected_profile = profile(3, 2, 1);
    assert!(matches!(
        evaluate_tally_directly(selected_profile, &empty_election_input(2, 2)),
        Err(TallyCircuitError::InputParticipantCountMismatch { .. })
    ));

    let mut wrong_attempt_count = empty_election_input(3, 2);
    wrong_attempt_count.participant_candidate_attempts[1].pop();
    assert!(matches!(
        evaluate_tally_directly(selected_profile, &wrong_attempt_count),
        Err(TallyCircuitError::InputAttemptCountMismatch {
            participant_position: 1,
            ..
        })
    ));

    let mut wrong_option_count = empty_election_input(3, 2);
    wrong_option_count.participant_candidate_attempts[1][2]
        .score_encodings
        .pop();
    assert!(matches!(
        evaluate_tally_directly(selected_profile, &wrong_option_count),
        Err(TallyCircuitError::InputOptionCountMismatch {
            participant_position: 1,
            attempt_position: 2,
            ..
        })
    ));

    let mut out_of_range_encoding = empty_election_input(3, 2);
    out_of_range_encoding.participant_candidate_attempts[2][1].score_encodings[0] = 16;
    assert!(matches!(
        evaluate_tally_directly(selected_profile, &out_of_range_encoding),
        Err(TallyCircuitError::ScoreEncodingOutOfRange {
            participant_position: 2,
            attempt_position: 1,
            option_position: 0,
            ..
        })
    ));
}

fn random_election_input(
    generator: &mut DeterministicGenerator,
    participant_count: usize,
    option_count: usize,
) -> TallyEvaluationInput {
    TallyEvaluationInput::new(
        (0..participant_count)
            .map(|_| {
                (0..TALLY_CANDIDATE_ATTEMPT_COUNT)
                    .map(|_| {
                        let is_present = generator.next_bool();
                        let score_encodings = (0..option_count)
                            .map(|_| generator.next_bounded(16) as u8)
                            .collect();
                        candidate_attempt(is_present, score_encodings)
                    })
                    .collect()
            })
            .collect(),
    )
}

fn assert_canonical_mutation_refuses(mutated_circuit: &super::CompiledTallyCircuit) {
    let mutated_bytes = encode_canonical_tally_circuit(mutated_circuit)
        .expect("structurally encodable mutation must encode");
    assert!(matches!(
        decode_canonical_tally_circuit(&mutated_bytes),
        Err(TallyCircuitError::CircuitMismatch)
    ));
}

fn set_little_endian_score_bits(input_bits: &mut [bool], wires: &[u32], score_encoding: u8) {
    for (bit_position, wire) in wires.iter().copied().enumerate() {
        input_bits[usize::try_from(wire).unwrap()] = (score_encoding >> bit_position) & 1 == 1;
    }
}

fn decode_position(wire_values: &[bool], position_wires: &[u32]) -> u16 {
    position_wires
        .iter()
        .copied()
        .enumerate()
        .fold(0_u16, |position, (bit_position, wire)| {
            if wire_values[usize::try_from(wire).unwrap()] {
                position | (1_u16 << bit_position)
            } else {
                position
            }
        })
}

struct DeterministicGenerator {
    state: u64,
}

impl DeterministicGenerator {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn next_bounded(&mut self, exclusive_upper_bound: u64) -> u64 {
        self.next_u64() % exclusive_upper_bound
    }
}
