use std::collections::BTreeSet;

use super::{
    BooleanOperation, TALLY_CIRCUIT_ARTIFACT_MAGIC, TallyCircuitError, TallyCircuitProfile,
    TallyEvaluationInput,
    codec::{decode_canonical_tally_circuit, encode_canonical_tally_circuit},
    compiler::{compile_tally_circuit, tally_circuit_compiler_identity},
    direct_evaluator::evaluate_tally_directly,
    interpreter::evaluate_compiled_tally_circuit,
};
use crate::foundation::{
    FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_OPTION_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
};

fn profile(participant_count: u16, option_count: u16, top_count: u16) -> TallyCircuitProfile {
    TallyCircuitProfile::new(participant_count, option_count, top_count)
        .expect("test profile must be admitted")
}

fn compare_interpreter_and_direct_evaluator(
    profile: TallyCircuitProfile,
    input: &TallyEvaluationInput,
) {
    let compiled_circuit = compile_tally_circuit(profile).expect("circuit must compile");
    let canonical_bytes = compiled_circuit
        .canonical_bytes()
        .expect("circuit must encode canonically");
    let decoded_circuit =
        decode_canonical_tally_circuit(&canonical_bytes).expect("circuit must decode canonically");
    let interpreted = evaluate_compiled_tally_circuit(&decoded_circuit, input)
        .expect("compiled circuit must evaluate");
    let direct = evaluate_tally_directly(profile, input).expect("direct semantics must evaluate");
    assert_eq!(interpreted, direct);
}

fn zero_scores(participant_count: usize, option_count: usize) -> Vec<Vec<u8>> {
    vec![vec![0; option_count]; participant_count]
}

#[test]
fn completion_profile_full_ranking_reproduces_reference_geometry() {
    let compiled_circuit = compile_tally_circuit(profile(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        FOUNDATION_PROFILE.option_count,
    ))
    .expect("completion-profile circuit must compile");
    let geometry = compiled_circuit.geometry();

    assert_eq!(geometry.input_bit_count, 410);
    assert_eq!(geometry.conjunction_gate_count, 3_465);
    assert_eq!(geometry.exclusive_or_gate_count, 4_005);
    assert_eq!(geometry.negation_gate_count, 1_140);
    assert_eq!(geometry.participant_validity_bit_count, 10);
    assert_eq!(geometry.result_bit_count, 40);
    assert_eq!(geometry.score_bit_width, 4);
    assert_eq!(geometry.aggregate_score_bit_width, 7);
    assert_eq!(geometry.option_position_bit_width, 4);
}

#[test]
fn compiler_supports_every_admitted_structural_profile() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let selected_profile = profile(participant_count, option_count, top_count);
                let compiled_circuit = compile_tally_circuit(selected_profile)
                    .expect("every admitted structural profile must compile");
                let geometry = compiled_circuit.geometry();
                assert_eq!(
                    geometry.input_bit_count,
                    usize::from(participant_count)
                        + usize::from(participant_count) * usize::from(option_count) * 4
                );
                assert_eq!(
                    compiled_circuit.participant_validity_wires().len(),
                    usize::from(participant_count)
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
fn compiler_identity_and_circuit_identity_are_deterministic() {
    assert_eq!(
        tally_circuit_compiler_identity().expect("compiler identity must derive"),
        tally_circuit_compiler_identity().expect("compiler identity must rederive")
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
fn all_four_bit_score_encodings_have_exact_present_validity() {
    let selected_profile = profile(3, 2, 2);
    for score_encoding in 0_u8..16 {
        let input = TallyEvaluationInput::new(
            vec![true, false, false],
            vec![vec![score_encoding, 1], vec![0, 0], vec![0, 0]],
        );
        compare_interpreter_and_direct_evaluator(selected_profile, &input);
        let direct = evaluate_tally_directly(selected_profile, &input).unwrap();
        assert_eq!(
            direct.participant_validity(),
            &[(1..=10).contains(&score_encoding), true, true]
        );
    }
}

#[test]
fn all_four_bit_score_encodings_have_exact_absent_validity() {
    let selected_profile = profile(3, 2, 2);
    for score_encoding in 0_u8..16 {
        let input = TallyEvaluationInput::new(
            vec![false, true, false],
            vec![vec![score_encoding, 0], vec![4, 7], vec![0, 0]],
        );
        compare_interpreter_and_direct_evaluator(selected_profile, &input);
        let direct = evaluate_tally_directly(selected_profile, &input).unwrap();
        assert_eq!(
            direct.participant_validity(),
            &[score_encoding == 0, true, true]
        );
    }
}

#[test]
fn empty_selected_ballot_set_has_no_accepted_result() {
    let selected_profile = profile(3, 3, 3);
    let input = TallyEvaluationInput::new(vec![false; 3], zero_scores(3, 3));
    compare_interpreter_and_direct_evaluator(selected_profile, &input);
    let outcome = evaluate_tally_directly(selected_profile, &input).unwrap();
    assert!(!outcome.has_selected_ballot());
    assert_eq!(outcome.participant_validity(), &[true, true, true]);
    assert_eq!(outcome.ordered_option_positions(), &[0, 1, 2]);
    assert_eq!(outcome.accepted_ordered_option_positions(), None);
}

#[test]
fn one_ballot_maximal_totals_and_stable_ties_match_direct_semantics() {
    let selected_profile = profile(10, 10, 10);

    let mut one_ballot_scores = zero_scores(10, 10);
    one_ballot_scores[4] = vec![1, 10, 3, 9, 5, 8, 7, 6, 4, 2];
    let mut one_ballot_presence = vec![false; 10];
    one_ballot_presence[4] = true;
    let one_ballot_input = TallyEvaluationInput::new(one_ballot_presence, one_ballot_scores);
    compare_interpreter_and_direct_evaluator(selected_profile, &one_ballot_input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &one_ballot_input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([1, 3, 5, 6, 7, 4, 8, 2, 9, 0].as_slice())
    );

    let maximal_input = TallyEvaluationInput::new(vec![true; 10], vec![vec![10; 10]; 10]);
    compare_interpreter_and_direct_evaluator(selected_profile, &maximal_input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &maximal_input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );

    let tied_input = TallyEvaluationInput::new(vec![true; 10], vec![vec![6; 10]; 10]);
    compare_interpreter_and_direct_evaluator(selected_profile, &tied_input);
    assert_eq!(
        evaluate_tally_directly(selected_profile, &tied_input)
            .unwrap()
            .accepted_ordered_option_positions(),
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );
}

#[test]
fn randomized_elections_match_for_every_completion_top_count() {
    let mut generator = DeterministicGenerator::new(0x8c67_21f0_d3a4_b509);
    for top_count in 1..=FOUNDATION_PROFILE.option_count {
        let selected_profile = profile(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            top_count,
        );
        let compiled_circuit =
            compile_tally_circuit(selected_profile).expect("circuit must compile");
        for case_position in 0..96 {
            let use_only_valid_inputs = case_position % 2 == 0;
            let mut participant_presence = Vec::with_capacity(10);
            let mut participant_scores = Vec::with_capacity(10);
            for _participant_position in 0..10 {
                let is_present = generator.next_bool();
                participant_presence.push(is_present);
                let scores = if use_only_valid_inputs {
                    if is_present {
                        (0..10)
                            .map(|_| 1 + generator.next_bounded(10) as u8)
                            .collect()
                    } else {
                        vec![0; 10]
                    }
                } else {
                    (0..10).map(|_| generator.next_bounded(16) as u8).collect()
                };
                participant_scores.push(scores);
            }
            let input = TallyEvaluationInput::new(participant_presence, participant_scores);
            let interpreted = evaluate_compiled_tally_circuit(&compiled_circuit, &input)
                .expect("compiled circuit must evaluate");
            let direct = evaluate_tally_directly(selected_profile, &input)
                .expect("direct semantics must evaluate");
            assert_eq!(interpreted, direct, "case {case_position}, top {top_count}");
        }
    }
}

#[test]
fn canonical_verifier_rejects_gate_wire_constant_order_and_output_mutations() {
    let selected_profile = profile(10, 10, 10);
    let canonical_circuit = compile_tally_circuit(selected_profile).unwrap();

    let mut gate_mutation = canonical_circuit.clone();
    let operation = gate_mutation
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
    assert_canonical_mutation_refuses(&gate_mutation);

    let mut wire_mutation = canonical_circuit.clone();
    let operation = wire_mutation
        .operations
        .iter_mut()
        .find(|operation| matches!(operation, BooleanOperation::Conjunction { .. }))
        .expect("circuit contains a conjunction gate");
    if let BooleanOperation::Conjunction { left_wire, .. } = operation {
        *left_wire = if *left_wire == 0 { 1 } else { 0 };
    }
    assert_canonical_mutation_refuses(&wire_mutation);

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

    let mut ordering_mutation = canonical_circuit.clone();
    let first_constant_position = ordering_mutation
        .operations
        .iter()
        .position(|operation| matches!(operation, BooleanOperation::Constant(false)))
        .expect("circuit contains a false constant");
    let second_constant_position = ordering_mutation
        .operations
        .iter()
        .enumerate()
        .find_map(|(position, operation)| {
            matches!(operation, BooleanOperation::Constant(true)).then_some(position)
        })
        .expect("circuit contains a true constant");
    ordering_mutation
        .operations
        .swap(first_constant_position, second_constant_position);
    assert_canonical_mutation_refuses(&ordering_mutation);

    let mut output_mutation = canonical_circuit.clone();
    output_mutation.ordered_option_position_wires[0][0] = 0;
    assert_canonical_mutation_refuses(&output_mutation);
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
    version_mutation[version_position] = 2;
    assert_eq!(
        decode_canonical_tally_circuit(&version_mutation),
        Err(TallyCircuitError::UnsupportedArtifactVersion { version: 2 })
    );

    let compiler_identity_position = version_position + 2;
    let mut compiler_identity_mutation = canonical_bytes.clone();
    compiler_identity_mutation[compiler_identity_position] ^= 1;
    assert_eq!(
        decode_canonical_tally_circuit(&compiler_identity_mutation),
        Err(TallyCircuitError::CompilerIdentityMismatch)
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
fn presence_and_input_bit_order_mutations_are_detected_semantically() {
    use super::interpreter::interpret_boolean_operations;

    let selected_profile = profile(3, 2, 2);
    let compiled_circuit = compile_tally_circuit(selected_profile).unwrap();

    let presence_mutation_input = TallyEvaluationInput::new(
        vec![false, false, false],
        vec![vec![1, 1], vec![0, 0], vec![0, 0]],
    );
    let presence_outcome =
        evaluate_compiled_tally_circuit(&compiled_circuit, &presence_mutation_input).unwrap();
    assert_eq!(
        presence_outcome.participant_validity(),
        &[false, true, true]
    );
    assert_eq!(presence_outcome.accepted_ordered_option_positions(), None);

    // Canonical input: presence bits, then participant-major and option-major
    // four-bit little-endian scores. Participant zero scores are 2 and 5.
    let mut input_bits = vec![true, false, false];
    input_bits.extend([false, true, false, false]);
    input_bits.extend([true, false, true, false]);
    input_bits.extend([false; 16]);
    let canonical_wire_values =
        interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    let canonical_first_position = decode_position(
        &canonical_wire_values,
        &compiled_circuit.ordered_option_position_wires()[0],
    );
    assert_eq!(canonical_first_position, 1);

    input_bits.swap(4, 6); // score 2 becomes score 8 under a bit-order mutation.
    let mutated_wire_values = interpret_boolean_operations(&compiled_circuit, &input_bits).unwrap();
    let mutated_first_position = decode_position(
        &mutated_wire_values,
        &compiled_circuit.ordered_option_position_wires()[0],
    );
    assert_eq!(mutated_first_position, 0);
}

#[test]
fn malformed_profiles_and_inputs_refuse_with_typed_errors() {
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
        evaluate_tally_directly(
            selected_profile,
            &TallyEvaluationInput::new(vec![true; 2], vec![vec![1, 2]; 2])
        ),
        Err(TallyCircuitError::InputParticipantCountMismatch { .. })
    ));
    assert!(matches!(
        evaluate_tally_directly(
            selected_profile,
            &TallyEvaluationInput::new(vec![true; 3], vec![vec![1], vec![1, 2], vec![1, 2]])
        ),
        Err(TallyCircuitError::InputOptionCountMismatch { .. })
    ));
    assert!(matches!(
        evaluate_tally_directly(
            selected_profile,
            &TallyEvaluationInput::new(vec![true; 3], vec![vec![16, 1], vec![1, 2], vec![1, 2]])
        ),
        Err(TallyCircuitError::ScoreEncodingOutOfRange { .. })
    ));
}

fn assert_canonical_mutation_refuses(mutated_circuit: &super::CompiledTallyCircuit) {
    let mutated_bytes = encode_canonical_tally_circuit(mutated_circuit)
        .expect("structurally encodable mutation must encode");
    assert!(matches!(
        decode_canonical_tally_circuit(&mutated_bytes),
        Err(TallyCircuitError::CircuitMismatch)
    ));
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
