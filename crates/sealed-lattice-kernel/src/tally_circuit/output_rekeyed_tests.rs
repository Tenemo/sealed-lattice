use std::collections::BTreeSet;

use super::{
    TALLY_BALLOT_ATTEMPT_COUNT, TallyBallotAttemptInput, TallyCircuitProfile, TallyEvaluationInput,
    output_rekeyed::{
        OutputRekeyedTallyCircuit, evaluate_output_rekeyed_tally_circuit,
        evaluate_output_rekeyed_tally_directly,
    },
};

#[test]
fn completion_profile_has_exact_authorship_nonempty_ranking_and_rekey_geometry() {
    let circuit = OutputRekeyedTallyCircuit::compile(profile(10, 10, 10)).unwrap();
    let geometry = circuit.geometry();

    assert_eq!(geometry.input_bit_count, 1_230);
    assert_eq!(geometry.conjunction_gate_count, 5_422);
    assert_eq!(geometry.exclusive_or_gate_count, 6_283);
    assert_eq!(geometry.negation_gate_count, 976);
    assert_eq!(geometry.output_rekey_operation_count, 51);
    assert_eq!(geometry.active_gate_count, 12_732);
    assert_eq!(geometry.public_output_bit_count, 11);
    assert_eq!(geometry.private_result_bit_count, 40);
    assert_eq!(geometry.total_wire_count, 13_964);

    let operations = circuit.output_rekey_operations();
    let expected_first_output_wire = circuit.core_circuit().geometry().total_wire_count;
    for (operation_position, operation) in operations.iter().copied().enumerate() {
        assert_eq!(
            usize::try_from(operation.output_wire()).unwrap(),
            expected_first_output_wire + operation_position
        );
        assert!(operation.input_wire() < operation.output_wire());
    }

    let output_wires = circuit
        .accepted_ballot_authorship_output_wires()
        .iter()
        .copied()
        .chain(core::iter::once(circuit.nonempty_output_wire()))
        .chain(
            circuit
                .ordered_option_position_wires()
                .iter()
                .flatten()
                .copied(),
        )
        .collect::<Vec<_>>();
    assert_eq!(
        output_wires,
        operations
            .iter()
            .copied()
            .map(|operation| operation.output_wire())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        output_wires.iter().copied().collect::<BTreeSet<_>>().len(),
        output_wires.len()
    );
}

#[test]
fn every_completion_result_length_has_derived_output_rekey_geometry() {
    for top_count in 1_u16..=10 {
        let circuit = OutputRekeyedTallyCircuit::compile(profile(10, 10, top_count)).unwrap();
        let geometry = circuit.geometry();
        let expected_private_result_bit_count = usize::from(top_count) * 4;
        let expected_output_rekey_operation_count = 11 + expected_private_result_bit_count;

        assert_eq!(circuit.profile().top_count(), top_count);
        assert_eq!(geometry.public_output_bit_count, 11);
        assert_eq!(
            geometry.private_result_bit_count,
            expected_private_result_bit_count
        );
        assert_eq!(
            geometry.output_rekey_operation_count,
            expected_output_rekey_operation_count
        );
        assert_eq!(
            geometry.total_wire_count,
            circuit.core_circuit().geometry().total_wire_count
                + expected_output_rekey_operation_count
        );
        assert_eq!(
            circuit.ordered_option_position_wires().len(),
            usize::from(top_count)
        );
        assert!(
            circuit
                .ordered_option_position_wires()
                .iter()
                .all(|position_wires| position_wires.len() == 4)
        );
    }
}

#[test]
fn accepted_ballot_authorship_uses_first_valid_retry_semantics() {
    let selected_profile = profile(10, 3, 3);
    let mut input = empty_election_input(10, 3);
    input.participant_ballot_attempts[0] = vec![
        ballot_attempt(true, vec![15, 1, 1]),
        ballot_attempt(true, vec![10, 9, 1]),
        ballot_attempt(true, vec![1, 10, 10]),
    ];
    input.participant_ballot_attempts[1] = vec![
        ballot_attempt(true, vec![0, 1, 1]),
        ballot_attempt(true, vec![1, 11, 1]),
        ballot_attempt(false, vec![10, 10, 10]),
    ];
    input.participant_ballot_attempts[2] = vec![
        ballot_attempt(false, vec![10, 10, 10]),
        ballot_attempt(true, vec![3, 4, 5]),
        ballot_attempt(false, vec![0, 0, 0]),
    ];
    input.participant_ballot_attempts[9][2] = ballot_attempt(true, vec![1, 1, 10]);

    let circuit = OutputRekeyedTallyCircuit::compile(selected_profile).unwrap();
    let interpreted = evaluate_output_rekeyed_tally_circuit(&circuit, &input).unwrap();
    let direct = evaluate_output_rekeyed_tally_directly(selected_profile, &input).unwrap();

    assert_eq!(interpreted, direct);
    assert_eq!(
        interpreted.accepted_ballot_authorship(),
        [
            true, false, true, false, false, false, false, false, false, true
        ]
    );
    assert!(interpreted.has_selected_ballot());
    assert_eq!(interpreted.ordered_option_positions(), [2, 0, 1]);
    assert_eq!(
        interpreted.accepted_ordered_option_positions(),
        Some([2_u16, 0, 1].as_slice())
    );
}

#[test]
fn all_absent_authorship_mints_no_accepted_result() {
    let selected_profile = profile(10, 10, 10);
    let input = empty_election_input(10, 10);
    let circuit = OutputRekeyedTallyCircuit::compile(selected_profile).unwrap();

    let interpreted = evaluate_output_rekeyed_tally_circuit(&circuit, &input).unwrap();
    let direct = evaluate_output_rekeyed_tally_directly(selected_profile, &input).unwrap();

    assert_eq!(interpreted, direct);
    assert_eq!(interpreted.accepted_ballot_authorship(), [false; 10]);
    assert!(!interpreted.has_selected_ballot());
    assert_eq!(interpreted.accepted_ordered_option_positions(), None);
}

#[test]
fn rekeyed_interpreter_matches_independent_semantics_across_profiles_and_hostile_scores() {
    let mut generator = DeterministicGenerator::new(0x8cb9_2baa_d4f1_c643);
    for participant_count in [3_u16, 6, 10] {
        for option_count in [2_u16, 5, 10] {
            for top_count in [1_u16, option_count] {
                let selected_profile = profile(participant_count, option_count, top_count);
                let circuit = OutputRekeyedTallyCircuit::compile(selected_profile).unwrap();
                for _case_position in 0..80 {
                    let input = random_election_input(
                        usize::from(participant_count),
                        usize::from(option_count),
                        &mut generator,
                    );
                    assert_eq!(
                        evaluate_output_rekeyed_tally_circuit(&circuit, &input),
                        evaluate_output_rekeyed_tally_directly(selected_profile, &input)
                    );
                }
            }
        }
    }
}

fn profile(participant_count: u16, option_count: u16, top_count: u16) -> TallyCircuitProfile {
    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap()
}

fn ballot_attempt(is_present: bool, score_encodings: Vec<u8>) -> TallyBallotAttemptInput {
    TallyBallotAttemptInput::new(is_present, score_encodings)
}

fn empty_election_input(participant_count: usize, option_count: usize) -> TallyEvaluationInput {
    TallyEvaluationInput::new(
        (0..participant_count)
            .map(|_| {
                (0..TALLY_BALLOT_ATTEMPT_COUNT)
                    .map(|_| ballot_attempt(false, vec![0; option_count]))
                    .collect()
            })
            .collect(),
    )
}

fn random_election_input(
    participant_count: usize,
    option_count: usize,
    generator: &mut DeterministicGenerator,
) -> TallyEvaluationInput {
    TallyEvaluationInput::new(
        (0..participant_count)
            .map(|_| {
                (0..TALLY_BALLOT_ATTEMPT_COUNT)
                    .map(|_| {
                        let is_present = generator.next_bool();
                        let score_encodings = (0..option_count)
                            .map(|_| generator.next_bounded(16) as u8)
                            .collect();
                        ballot_attempt(is_present, score_encodings)
                    })
                    .collect()
            })
            .collect(),
    )
}

struct DeterministicGenerator {
    state: u64,
}

impl DeterministicGenerator {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn next_bounded(&mut self, upper_bound: u64) -> u64 {
        self.next_u64() % upper_bound
    }
}
