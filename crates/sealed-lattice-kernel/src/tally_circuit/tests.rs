use std::collections::BTreeSet;

use super::{
    BooleanOperation, TALLY_CIRCUIT_ARTIFACT_MAGIC, TallyBallotInput, TallyCircuitError,
    TallyCircuitProfile, TallyEvaluationInput,
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

fn ballot(is_present: bool, score_encodings: Vec<u8>) -> TallyBallotInput {
    TallyBallotInput::new(is_present, score_encodings)
}

fn absent_ballot(option_count: usize) -> TallyBallotInput {
    ballot(false, vec![0; option_count])
}

fn empty_election_input(participant_count: usize, option_count: usize) -> TallyEvaluationInput {
    TallyEvaluationInput::new(
        (0..participant_count)
            .map(|_| absent_ballot(option_count))
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
fn completion_profile_full_ranking_has_one_slot_geometry() {
    let compiled_circuit = compile_tally_circuit(profile(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        FOUNDATION_PROFILE.option_count,
    ))
    .expect("completion-profile circuit must compile");
    let geometry = compiled_circuit.geometry();

    assert_eq!(geometry.input_bit_count, 410);
    assert_eq!(geometry.ballot_presence_input_bit_count, 10);
    assert_eq!(geometry.private_score_input_bit_count, 400);
    assert_eq!(geometry.constant_operation_count, 2);
    assert_eq!(geometry.conjunction_gate_count, 2_962);
    assert_eq!(geometry.exclusive_or_gate_count, 3_803);
    assert_eq!(geometry.negation_gate_count, 756);
    assert_eq!(
        geometry.fresh_input_and_conjunction_output_wire_count,
        3_372
    );
    assert_eq!(geometry.folded_conjunction_count, 103);
    assert_eq!(geometry.folded_exclusive_or_count, 212);
    assert_eq!(geometry.folded_negation_count, 4);
    assert_eq!(geometry.duplicate_input_conjunction_count, 0);
    assert_eq!(geometry.public_output_bit_count, 1);
    assert_eq!(geometry.private_result_bit_count, 40);
    assert_eq!(geometry.score_bit_width, 4);
    assert_eq!(geometry.aggregate_score_bit_width, 7);
    assert_eq!(geometry.option_position_bit_width, 4);
    assert_eq!(geometry.total_wire_count, 7_933);
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
                    participant_count * (1 + option_count * 4)
                );
                assert_eq!(
                    compiled_circuit.ballot_presence_wires().len(),
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

                for _case_position in 0..2 {
                    let input =
                        random_election_input(&mut generator, participant_count, option_count);
                    compare_compiled_circuit_and_direct_evaluator(&compiled_circuit, &input);
                }
            }
        }
    }
}

#[test]
fn every_completion_profile_top_count_has_canonical_distinct_bytes_and_semantics() {
    let mut circuit_identities = BTreeSet::new();
    let scores = vec![10, 1, 9, 2, 8, 3, 7, 4, 6, 5];
    for top_count in 1..=FOUNDATION_PROFILE.option_count {
        let selected_profile = profile(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            top_count,
        );
        let compiled_circuit = compile_tally_circuit(selected_profile)
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

        let mut input = empty_election_input(10, 10);
        input.participant_ballots[3] = ballot(true, scores.clone());
        compare_compiled_circuit_and_direct_evaluator(&compiled_circuit, &input);
        let expected_order = [0, 2, 4, 6, 8, 9, 7, 5, 3, 1];
        assert_eq!(
            evaluate_tally_directly(selected_profile, &input)
                .unwrap()
                .accepted_ordered_option_positions(),
            Some(&expected_order[..usize::from(top_count)])
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
fn every_four_bit_score_encoding_is_checked_in_every_option_position() {
    let selected_profile = profile(3, 3, 3);
    for is_present in [false, true] {
        for option_position in 0..3 {
            for score_encoding in 0_u8..16 {
                let mut input = empty_election_input(3, 3);
                input.participant_ballots[0] = ballot(is_present, vec![7, 7, 7]);
                input.participant_ballots[0].score_encodings[option_position] = score_encoding;
                compare_interpreter_and_direct_evaluator(selected_profile, &input);

                let expected_selection = is_present && (1..=10).contains(&score_encoding);
                assert_eq!(
                    evaluate_tally_directly(selected_profile, &input)
                        .unwrap()
                        .has_selected_ballot(),
                    expected_selection
                );
            }
        }
    }
}

#[test]
fn all_abstentions_and_invalid_ballots_produce_no_result() {
    let selected_profile = profile(3, 3, 3);
    let all_abstentions = empty_election_input(3, 3);
    compare_interpreter_and_direct_evaluator(selected_profile, &all_abstentions);
    let abstention_outcome = evaluate_tally_directly(selected_profile, &all_abstentions).unwrap();
    assert!(!abstention_outcome.has_selected_ballot());
    assert_eq!(abstention_outcome.ordered_option_positions(), &[0, 1, 2]);
    assert_eq!(abstention_outcome.accepted_ordered_option_positions(), None);

    let invalid_ballots = TallyEvaluationInput::new(vec![
        ballot(true, vec![0, 1, 2]),
        ballot(true, vec![11, 3, 4]),
        ballot(true, vec![5, 15, 6]),
    ]);
    compare_interpreter_and_direct_evaluator(selected_profile, &invalid_ballots);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &invalid_ballots)
            .unwrap()
            .accepted_ordered_option_positions(),
        None
    );
}

#[test]
fn one_valid_ballot_uses_its_exact_scores() {
    let selected_profile = profile(10, 10, 10);
    let mut input = empty_election_input(10, 10);
    input.participant_ballots[4] = ballot(true, vec![1, 10, 3, 9, 5, 8, 7, 6, 4, 2]);

    compare_interpreter_and_direct_evaluator(selected_profile, &input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([1, 3, 5, 6, 7, 4, 8, 2, 9, 0].as_slice())
    );
}

#[test]
fn all_valid_minimum_maximum_and_tied_scores_have_stable_ordering() {
    let selected_profile = profile(10, 10, 10);
    let input = TallyEvaluationInput::new(
        (0..10)
            .map(|participant_position| {
                let score = if participant_position % 2 == 0 { 1 } else { 10 };
                ballot(true, vec![score; 10])
            })
            .collect(),
    );
    compare_interpreter_and_direct_evaluator(selected_profile, &input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );

    let maximum_input =
        TallyEvaluationInput::new((0..10).map(|_| ballot(true, vec![10; 10])).collect());
    compare_interpreter_and_direct_evaluator(selected_profile, &maximum_input);
    let maximum_outcome = evaluate_tally_directly(selected_profile, &maximum_input).unwrap();
    assert!(maximum_outcome.has_selected_ballot());
    assert_eq!(
        maximum_outcome.accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );
}

#[test]
fn tied_totals_use_lower_canonical_option_positions() {
    let selected_profile = profile(3, 4, 4);
    let input = TallyEvaluationInput::new(vec![
        ballot(true, vec![10, 1, 8, 3]),
        ballot(true, vec![1, 10, 3, 8]),
        ballot(true, vec![5, 5, 5, 5]),
    ]);
    compare_interpreter_and_direct_evaluator(selected_profile, &input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3].as_slice())
    );
}

#[test]
fn canonical_verifier_rejects_operation_wiring_input_and_output_mutations() {
    let canonical_circuit = compile_tally_circuit(profile(10, 10, 10)).unwrap();

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
    input_mapping_mutation.ballot_score_wires[0][0].swap(0, 1);
    assert_canonical_mutation_refuses(&input_mapping_mutation);

    let mut participant_order_mutation = canonical_circuit.clone();
    participant_order_mutation.ballot_presence_wires.swap(0, 1);
    participant_order_mutation.ballot_score_wires.swap(0, 1);
    assert_canonical_mutation_refuses(&participant_order_mutation);

    let mut public_output_mutation = canonical_circuit.clone();
    public_output_mutation.nonempty_output_wire = 0;
    assert_canonical_mutation_refuses(&public_output_mutation);

    let mut private_output_mutation = canonical_circuit.clone();
    private_output_mutation.ordered_option_position_wires[0][0] = 0;
    assert_canonical_mutation_refuses(&private_output_mutation);
}

#[test]
fn canonical_decoder_rejects_framing_identity_and_length_mutations() {
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
    version_mutation[version_position] = 4;
    assert_eq!(
        decode_canonical_tally_circuit(&version_mutation),
        Err(TallyCircuitError::UnsupportedArtifactVersion { version: 4 })
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
fn input_mapping_is_participant_option_and_little_endian_bit_order() {
    let compiled_circuit = compile_tally_circuit(profile(3, 2, 2)).unwrap();
    assert_eq!(compiled_circuit.ballot_presence_wires, [0, 9, 18]);
    assert_eq!(
        compiled_circuit.ballot_score_wires[0],
        [vec![1, 2, 3, 4], vec![5, 6, 7, 8]]
    );

    let mut input_bits = vec![false; compiled_circuit.geometry().input_bit_count];
    input_bits[0] = true;
    set_little_endian_score_bits(&mut input_bits, &[1, 2, 3, 4], 2);
    set_little_endian_score_bits(&mut input_bits, &[5, 6, 7, 8], 5);
    let canonical_wire_values =
        interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    assert_eq!(
        decode_position(
            &canonical_wire_values,
            &compiled_circuit.ordered_option_position_wires()[0]
        ),
        1
    );

    input_bits.swap(2, 4);
    let mutated_wire_values = interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    assert_eq!(
        decode_position(
            &mutated_wire_values,
            &compiled_circuit.ordered_option_position_wires()[0]
        ),
        0
    );
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

    let mut wrong_option_count = empty_election_input(3, 2);
    wrong_option_count.participant_ballots[1]
        .score_encodings
        .pop();
    assert!(matches!(
        evaluate_tally_directly(selected_profile, &wrong_option_count),
        Err(TallyCircuitError::InputOptionCountMismatch {
            participant_position: 1,
            ..
        })
    ));

    let mut out_of_range_encoding = empty_election_input(3, 2);
    out_of_range_encoding.participant_ballots[2].score_encodings[0] = 16;
    assert!(matches!(
        evaluate_tally_directly(selected_profile, &out_of_range_encoding),
        Err(TallyCircuitError::ScoreEncodingOutOfRange {
            participant_position: 2,
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
                let is_present = generator.next_bool();
                let score_encodings = (0..option_count)
                    .map(|_| generator.next_bounded(16) as u8)
                    .collect();
                ballot(is_present, score_encodings)
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
