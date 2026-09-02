use super::{
    BooleanOperation, TallyBallotInput, TallyCircuitError, TallyCircuitProfile,
    TallyEvaluationInput,
    compiler::compile_tally_circuit,
    direct_evaluator::evaluate_tally_directly,
    interpreter::{evaluate_compiled_tally_circuit, interpret_boolean_operations},
};
use crate::foundation::{
    MAXIMUM_CONFIGURABLE_OPTION_COUNT, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_OPTION_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    PROTOTYPE_OPTION_COUNT, PROTOTYPE_PARTICIPANT_COUNT,
};

fn profile(participant_count: u16, option_count: u16, top_count: u16) -> TallyCircuitProfile {
    TallyCircuitProfile::new(participant_count, option_count, top_count)
        .expect("test profile must be admitted")
}

fn ballot(is_present: bool, score_encodings: Vec<u8>) -> TallyBallotInput {
    TallyBallotInput {
        is_present,
        score_encodings,
    }
}

fn absent_ballot(option_count: usize) -> TallyBallotInput {
    ballot(false, vec![0; option_count])
}

fn empty_election_input(participant_count: usize, option_count: usize) -> TallyEvaluationInput {
    TallyEvaluationInput {
        participant_ballots: (0..participant_count)
            .map(|_| absent_ballot(option_count))
            .collect(),
    }
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
    let direct = evaluate_tally_directly(compiled_circuit.profile, input)
        .expect("direct semantics must evaluate");
    assert_eq!(interpreted, direct);
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
                let participant_count = usize::from(participant_count);
                let option_count = usize::from(option_count);

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
fn every_prototype_top_count_matches_the_direct_tally() {
    let scores = vec![10, 1, 9, 2, 8, 3, 7, 4, 6, 5];
    for top_count in 1..=PROTOTYPE_OPTION_COUNT {
        let selected_profile = profile(
            PROTOTYPE_PARTICIPANT_COUNT,
            PROTOTYPE_OPTION_COUNT,
            top_count,
        );
        let compiled_circuit = compile_tally_circuit(selected_profile)
            .expect("each completion-profile top count must compile");

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
fn completion_profile_circuit_geometry_is_derived_for_every_top_count() {
    const EXPECTED_GATE_COUNTS: [(usize, usize, usize); 10] = [
        (2153, 2098, 250),
        (2515, 2290, 364),
        (2837, 2458, 462),
        (3113, 2602, 546),
        (3343, 2722, 616),
        (3527, 2818, 672),
        (3665, 2890, 714),
        (3757, 2938, 742),
        (3803, 2962, 756),
        (3803, 2962, 756),
    ];
    const EXPECTED_CIRCUIT_DEPTHS: [(usize, usize); 10] = [
        (217, 87),
        (233, 95),
        (249, 103),
        (265, 111),
        (281, 119),
        (297, 127),
        (313, 135),
        (329, 143),
        (345, 151),
        (345, 151),
    ];

    for top_count in 1..=PROTOTYPE_OPTION_COUNT {
        let circuit = compile_tally_circuit(profile(
            PROTOTYPE_PARTICIPANT_COUNT,
            PROTOTYPE_OPTION_COUNT,
            top_count,
        ))
        .unwrap();
        let gate_counts = circuit.operations.iter().fold(
            (0_usize, 0_usize, 0_usize),
            |(exclusive_or_count, conjunction_count, negation_count), operation| match operation {
                BooleanOperation::Constant(_) => {
                    (exclusive_or_count, conjunction_count, negation_count)
                }
                BooleanOperation::ExclusiveOr { .. } => {
                    (exclusive_or_count + 1, conjunction_count, negation_count)
                }
                BooleanOperation::Conjunction { .. } => {
                    (exclusive_or_count, conjunction_count + 1, negation_count)
                }
                BooleanOperation::Negation { .. } => {
                    (exclusive_or_count, conjunction_count, negation_count + 1)
                }
            },
        );
        let circuit_depths = independently_derive_circuit_depths(&circuit);
        let output_bit_count = circuit.participant_selected_wires.len()
            + 1
            + circuit
                .ordered_option_position_wires
                .iter()
                .map(Vec::len)
                .sum::<usize>();

        assert_eq!(circuit.input_bit_count, 410);
        assert_eq!(circuit.participant_selected_wires.len(), 10);
        assert_eq!(
            circuit
                .ordered_option_position_wires
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
            usize::from(top_count) * 4
        );
        assert_eq!(
            gate_counts,
            EXPECTED_GATE_COUNTS[usize::from(top_count - 1)]
        );
        assert_eq!(
            circuit_depths,
            EXPECTED_CIRCUIT_DEPTHS[usize::from(top_count - 1)]
        );
        assert_eq!(output_bit_count, 11 + usize::from(top_count) * 4);
    }
}

fn independently_derive_circuit_depths(circuit: &super::CompiledTallyCircuit) -> (usize, usize) {
    let mut ordinary_depth_by_wire = vec![0_usize; circuit.input_bit_count];
    let mut multiplicative_depth_by_wire = vec![0_usize; circuit.input_bit_count];

    for operation in &circuit.operations {
        let (ordinary_depth, multiplicative_depth) = match operation {
            BooleanOperation::Constant(_) => (0, 0),
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            } => {
                let left_position = usize::try_from(*left_wire).unwrap();
                let right_position = usize::try_from(*right_wire).unwrap();
                (
                    ordinary_depth_by_wire[left_position]
                        .max(ordinary_depth_by_wire[right_position])
                        + 1,
                    multiplicative_depth_by_wire[left_position]
                        .max(multiplicative_depth_by_wire[right_position]),
                )
            }
            BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => {
                let left_position = usize::try_from(*left_wire).unwrap();
                let right_position = usize::try_from(*right_wire).unwrap();
                (
                    ordinary_depth_by_wire[left_position]
                        .max(ordinary_depth_by_wire[right_position])
                        + 1,
                    multiplicative_depth_by_wire[left_position]
                        .max(multiplicative_depth_by_wire[right_position])
                        + 1,
                )
            }
            BooleanOperation::Negation { input_wire } => {
                let input_position = usize::try_from(*input_wire).unwrap();
                (
                    ordinary_depth_by_wire[input_position] + 1,
                    multiplicative_depth_by_wire[input_position],
                )
            }
        };
        ordinary_depth_by_wire.push(ordinary_depth);
        multiplicative_depth_by_wire.push(multiplicative_depth);
    }

    (
        *ordinary_depth_by_wire.iter().max().unwrap(),
        *multiplicative_depth_by_wire.iter().max().unwrap(),
    )
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
                let outcome = evaluate_tally_directly(selected_profile, &input).unwrap();
                assert_eq!(outcome.has_selected_ballot, expected_selection);
                assert_eq!(
                    outcome.accepted_ballot_authorship,
                    [expected_selection, false, false]
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
    assert!(!abstention_outcome.has_selected_ballot);
    assert_eq!(abstention_outcome.accepted_ballot_authorship, [false; 3]);
    assert_eq!(abstention_outcome.ordered_option_positions, [0, 1, 2]);
    assert_eq!(abstention_outcome.accepted_ordered_option_positions(), None);

    let invalid_ballots = TallyEvaluationInput {
        participant_ballots: vec![
            ballot(true, vec![0, 1, 2]),
            ballot(true, vec![11, 3, 4]),
            ballot(true, vec![5, 15, 6]),
        ],
    };
    compare_interpreter_and_direct_evaluator(selected_profile, &invalid_ballots);
    let invalid_outcome = evaluate_tally_directly(selected_profile, &invalid_ballots).unwrap();
    assert_eq!(invalid_outcome.accepted_ballot_authorship, [false; 3]);
    assert_eq!(invalid_outcome.accepted_ordered_option_positions(), None);
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
    let input = TallyEvaluationInput {
        participant_ballots: (0..10)
            .map(|participant_position| {
                let score = if participant_position % 2 == 0 { 1 } else { 10 };
                ballot(true, vec![score; 10])
            })
            .collect(),
    };
    compare_interpreter_and_direct_evaluator(selected_profile, &input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );

    let maximum_input = TallyEvaluationInput {
        participant_ballots: (0..10).map(|_| ballot(true, vec![10; 10])).collect(),
    };
    compare_interpreter_and_direct_evaluator(selected_profile, &maximum_input);
    let maximum_outcome = evaluate_tally_directly(selected_profile, &maximum_input).unwrap();
    assert!(maximum_outcome.has_selected_ballot);
    assert_eq!(
        maximum_outcome.accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );
}

#[test]
fn tied_totals_use_lower_canonical_option_positions() {
    let selected_profile = profile(3, 4, 4);
    let input = TallyEvaluationInput {
        participant_ballots: vec![
            ballot(true, vec![10, 1, 8, 3]),
            ballot(true, vec![1, 10, 3, 8]),
            ballot(true, vec![5, 5, 5, 5]),
        ],
    };
    compare_interpreter_and_direct_evaluator(selected_profile, &input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3].as_slice())
    );
}

#[test]
fn input_mapping_is_participant_option_and_little_endian_bit_order() {
    let compiled_circuit = compile_tally_circuit(profile(3, 2, 2)).unwrap();
    let mut input_bits = vec![false; compiled_circuit.input_bit_count];
    input_bits[0] = true;
    set_little_endian_score_bits(&mut input_bits, &[1, 2, 3, 4], 2);
    set_little_endian_score_bits(&mut input_bits, &[5, 6, 7, 8], 5);
    let canonical_wire_values =
        interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    assert_eq!(
        decode_position(
            &canonical_wire_values,
            &compiled_circuit.ordered_option_position_wires[0]
        ),
        1
    );

    input_bits.swap(2, 4);
    let mutated_wire_values = interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    assert_eq!(
        decode_position(
            &mutated_wire_values,
            &compiled_circuit.ordered_option_position_wires[0]
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
    TallyEvaluationInput {
        participant_ballots: (0..participant_count)
            .map(|_| {
                let is_present = generator.next_bool();
                let score_encodings = (0..option_count)
                    .map(|_| generator.next_bounded(16) as u8)
                    .collect();
                ballot(is_present, score_encodings)
            })
            .collect(),
    }
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
