use std::collections::{BTreeMap, BTreeSet};

use crate::bgv::{
    direct_ballots::{
        PAIR_CHARACTER_CIPHERTEXT_COUNT, PAIR_CHARACTER_LANE_COUNT, PAIR_CHARACTER_LANE_DEGREE,
        selected_pair_character_lane_assignments,
    },
    encoding::{
        decode_plaintext_coefficients_to_extension_lanes,
        encode_extension_lanes_to_plaintext_coefficients,
    },
    evaluator::semantic_oracle::{
        self, ORACLE_BANK_LANE_COUNT, ORACLE_CIPHERTEXT_COUNT, ORACLE_LANE_COUNT,
        ORACLE_OPTION_COUNT, ORACLE_PLAINTEXT_MODULUS, OracleRingValue,
    },
    parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
};

use super::{SCATTER_ROUTES, TRACE_GALOIS_PATHS, selected_plaintext_topology};
use crate::bgv::evaluator::program::{
    EvaluatorInstructionStream, EvaluatorOpcode, EvaluatorProgramSet,
};

#[test]
fn compiled_scatter_routes_strictly_increasing_scores_to_direct_stable_ranks() {
    let assignments =
        selected_pair_character_lane_assignments().expect("selected pair-character catalog");
    let mut traced_lanes = vec![
        vec![[0_u64; PAIR_CHARACTER_LANE_DEGREE]; PAIR_CHARACTER_LANE_COUNT];
        PAIR_CHARACTER_CIPHERTEXT_COUNT
    ];
    for assignment in assignments {
        traced_lanes[usize::from(assignment.ciphertext_ordinal())]
            [usize::from(assignment.lane_ordinal())][0] = 1;
    }
    let traced_ciphertexts = traced_lanes
        .iter()
        .map(|lanes| {
            encode_extension_lanes_to_plaintext_coefficients(lanes)
                .expect("traced lanes encode into the complete plaintext ring")
        })
        .collect::<Vec<_>>();

    let topology = selected_plaintext_topology().expect("selected plaintext topology");
    let mut rank_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    for (route, source_masks) in SCATTER_ROUTES
        .iter()
        .copied()
        .zip(&topology.route_source_masks)
    {
        let mut routed_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        for source_mask in source_masks {
            let mask_coefficients = source_mask
                .coefficients
                .iter()
                .copied()
                .map(u64::from)
                .collect::<Vec<_>>();
            let masked = negacyclic_product_mod_plaintext(
                &traced_ciphertexts[source_mask.ciphertext_ordinal],
                &mask_coefficients,
            );
            add_ring_assign(&mut routed_coefficients, &masked);
        }
        for galois_element in route.galois_path() {
            routed_coefficients =
                apply_negacyclic_galois_action(&routed_coefficients, *galois_element);
        }
        add_ring_assign(&mut rank_coefficients, &routed_coefficients);
    }
    add_ring_assign(
        &mut rank_coefficients,
        &topology
            .rank_base
            .iter()
            .copied()
            .map(u64::from)
            .collect::<Vec<_>>(),
    );

    let observed_lanes = decode_plaintext_coefficients_to_extension_lanes(&rank_coefficients)
        .expect("scattered rank ring decodes");
    let observed_ranks = observed_lanes[..20]
        .iter()
        .map(|lane| {
            assert!(lane[1..].iter().all(|coefficient| *coefficient == 0));
            lane[0]
        })
        .collect::<Vec<_>>();
    let expected_ranks = (0_u64..20).rev().collect::<Vec<_>>();
    assert_eq!(observed_ranks, expected_ranks);
}

#[test]
fn independent_pair_catalog_matches_every_production_orientation_lane_and_bank() {
    let observed = selected_pair_character_lane_assignments()
        .expect("selected pair-character catalog")
        .into_iter()
        .map(|assignment| {
            (
                usize::from(assignment.ciphertext_ordinal()),
                usize::from(assignment.lane_ordinal()),
                usize::from(assignment.lower_option_ordinal()),
                usize::from(assignment.higher_option_ordinal()),
            )
        })
        .collect::<Vec<_>>();
    let expected = semantic_oracle::pair_assignments()
        .into_iter()
        .map(|assignment| {
            (
                assignment.ciphertext_ordinal,
                assignment.lane_ordinal,
                assignment.lower_option_ordinal,
                assignment.higher_option_ordinal,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(observed, expected);
}

#[test]
fn compiled_comparison_trace_matches_every_reachable_exponent_in_both_banks() {
    let topology = selected_plaintext_topology().expect("selected plaintext topology");
    let comparison_mask = decode_u32_coefficients(&topology.comparison_trace_mask);
    let assignments = semantic_oracle::pair_assignments();
    assert_eq!(assignments.len(), 190);
    for ciphertext_ordinal in 0..ORACLE_CIPHERTEXT_COUNT {
        let active_lanes = assignments
            .iter()
            .filter(|assignment| assignment.ciphertext_ordinal == ciphertext_ordinal)
            .map(|assignment| assignment.lane_ordinal)
            .collect::<BTreeSet<_>>();
        assert!(
            active_lanes
                .iter()
                .any(|lane_ordinal| *lane_ordinal < ORACLE_BANK_LANE_COUNT)
        );
        assert!(
            active_lanes
                .iter()
                .any(|lane_ordinal| *lane_ordinal >= ORACLE_BANK_LANE_COUNT)
        );
        for character_exponent in 0..=180 {
            let mut input = semantic_oracle::zero_ring_value();
            for lane_ordinal in &active_lanes {
                input[*lane_ordinal][character_exponent] = 1;
            }
            let traced = execute_compiled_trace(&input, &comparison_mask);
            for (observed_lane_ordinal, lane) in traced.iter().enumerate() {
                for (coefficient_ordinal, coefficient) in lane.iter().copied().enumerate() {
                    let expected = if active_lanes.contains(&observed_lane_ordinal)
                        && coefficient_ordinal == 0
                    {
                        semantic_oracle::comparison_value(character_exponent)
                    } else {
                        0
                    };
                    assert_eq!(
                        coefficient, expected,
                        "trace drifted for ciphertext {ciphertext_ordinal}, exponent {character_exponent}, output lane {observed_lane_ordinal}, coefficient {coefficient_ordinal}",
                    );
                }
            }
        }
    }
}

#[test]
fn compiled_scatter_routes_every_pair_sign_from_its_actual_source_bank() {
    let topology = selected_plaintext_topology().expect("selected plaintext topology");
    let mut observed_contributions = BTreeMap::<(usize, usize), Vec<(usize, u64)>>::new();
    for (route, source_masks) in SCATTER_ROUTES
        .iter()
        .copied()
        .zip(&topology.route_source_masks)
    {
        let composed_galois_element = route
            .galois_path()
            .iter()
            .copied()
            .fold(1_usize, |composed, element| {
                composed * element % (2 * POLYNOMIAL_DEGREE)
            });
        for source_mask in source_masks {
            let decoded_mask = decode_u32_coefficients(&source_mask.coefficients);
            for (source_lane_ordinal, lane) in decoded_mask.iter().enumerate() {
                assert!(lane[1..].iter().all(|coefficient| *coefficient == 0));
                if lane[0] == 0 {
                    continue;
                }
                assert!(matches!(lane[0], 1 | 256));
                observed_contributions
                    .entry((source_mask.ciphertext_ordinal, source_lane_ordinal))
                    .or_default()
                    .push((
                        semantic_oracle::destination_lane_for_galois_action(
                            source_lane_ordinal,
                            composed_galois_element,
                        ),
                        lane[0],
                    ));
            }
        }
    }
    for contributions in observed_contributions.values_mut() {
        contributions.sort_unstable();
    }

    let mut expected_contributions = BTreeMap::new();
    for assignment in semantic_oracle::pair_assignments() {
        let mut contributions = vec![
            (assignment.lower_option_ordinal, 1),
            (
                assignment.higher_option_ordinal,
                ORACLE_PLAINTEXT_MODULUS - 1,
            ),
        ];
        contributions.sort_unstable();
        assert!(
            expected_contributions
                .insert(
                    (assignment.ciphertext_ordinal, assignment.lane_ordinal),
                    contributions,
                )
                .is_none()
        );
    }
    assert_eq!(observed_contributions, expected_contributions);
}

#[test]
fn compiled_trace_and_scatter_match_direct_stable_ranks_for_the_complete_fast_matrix() {
    let topology = selected_plaintext_topology().expect("selected plaintext topology");
    for (case_name, scores) in fast_semantic_score_vectors() {
        let inputs = semantic_oracle::aggregate_character_inputs(&scores);
        let traced = inputs.map(|input| {
            execute_compiled_trace(
                &input,
                &decode_u32_coefficients(&topology.comparison_trace_mask),
            )
        });
        let ranks = execute_compiled_scatter(&traced, &topology);
        let expected_ranks = semantic_oracle::stable_ranks(&scores);
        for (lane_ordinal, lane) in ranks.iter().enumerate() {
            let expected = if lane_ordinal < ORACLE_OPTION_COUNT {
                expected_ranks[lane_ordinal]
            } else {
                0
            };
            assert_eq!(
                lane[0], expected,
                "rank drifted for {case_name} at option {lane_ordinal}",
            );
            assert!(
                lane[1..].iter().all(|coefficient| *coefficient == 0),
                "rank stopped being scalar for {case_name} at lane {lane_ordinal}",
            );
        }
    }
}

#[test]
fn compiled_plaintext_program_matches_both_direct_targets_for_every_top_count() {
    let scores = vec![
        90, 0, 45, 45, 12, 78, 12, 78, 1, 89, 30, 60, 30, 60, 44, 46, 44, 46, 23, 67,
    ];
    let inputs = semantic_oracle::aggregate_character_inputs(&scores);
    let program = super::selected_evaluator_program_set().expect("selected evaluator program");
    let interpreter = PlaintextProgramInterpreter::new(&program);

    for stream in program.streams() {
        let [identifier, order] = interpreter.execute(stream, inputs.clone());
        let [expected_identifiers, expected_order] =
            semantic_oracle::target_values(&scores, usize::from(stream.top_count()));
        assert_scalar_target(
            &identifier,
            &expected_identifiers,
            stream.top_count(),
            "identifier",
        );
        assert_scalar_target(&order, &expected_order, stream.top_count(), "order");
    }
}

fn execute_compiled_trace(
    input: &OracleRingValue,
    comparison_mask: &OracleRingValue,
) -> OracleRingValue {
    let mut trace = semantic_oracle::multiply(input, comparison_mask);
    for path in TRACE_GALOIS_PATHS {
        let mut rotated = trace.clone();
        for galois_element in path {
            rotated = semantic_oracle::apply_galois_action(&rotated, *galois_element);
        }
        trace = semantic_oracle::add(&trace, &rotated);
    }
    trace
}

fn execute_compiled_scatter(
    traced_inputs: &[OracleRingValue; ORACLE_CIPHERTEXT_COUNT],
    topology: &super::SelectedPlaintextTopology,
) -> OracleRingValue {
    let mut ranks = semantic_oracle::zero_ring_value();
    for (route, source_masks) in SCATTER_ROUTES
        .iter()
        .copied()
        .zip(&topology.route_source_masks)
    {
        let mut routed = semantic_oracle::zero_ring_value();
        for source_mask in source_masks {
            routed = semantic_oracle::add(
                &routed,
                &semantic_oracle::multiply(
                    &traced_inputs[source_mask.ciphertext_ordinal],
                    &decode_u32_coefficients(&source_mask.coefficients),
                ),
            );
        }
        for galois_element in route.galois_path() {
            routed = semantic_oracle::apply_galois_action(&routed, *galois_element);
        }
        ranks = semantic_oracle::add(&ranks, &routed);
    }
    semantic_oracle::add(&ranks, &decode_u32_coefficients(&topology.rank_base))
}

fn fast_semantic_score_vectors() -> Vec<(String, Vec<u64>)> {
    let mut cases = vec![
        ("all equal".to_owned(), vec![45; ORACLE_OPTION_COUNT]),
        (
            "strict increasing".to_owned(),
            (0..ORACLE_OPTION_COUNT)
                .map(|value| u64::try_from(value).unwrap())
                .collect(),
        ),
        (
            "strict decreasing".to_owned(),
            (0..ORACLE_OPTION_COUNT)
                .rev()
                .map(|value| u64::try_from(value).unwrap())
                .collect(),
        ),
        (
            "zero and ninety".to_owned(),
            (0..ORACLE_OPTION_COUNT)
                .map(|option_ordinal| if option_ordinal % 2 == 0 { 0 } else { 90 })
                .collect(),
        ),
    ];
    for option_ordinal in 0..ORACLE_OPTION_COUNT {
        let mut unique_winner = vec![45; ORACLE_OPTION_COUNT];
        unique_winner[option_ordinal] = 90;
        cases.push((format!("unique winner {option_ordinal}"), unique_winner));
        let mut unique_loser = vec![45; ORACLE_OPTION_COUNT];
        unique_loser[option_ordinal] = 0;
        cases.push((format!("unique loser {option_ordinal}"), unique_loser));
    }
    for tie_count in 2..=ORACLE_OPTION_COUNT {
        let mut scores = (0..ORACLE_OPTION_COUNT)
            .map(|option_ordinal| u64::try_from(ORACLE_OPTION_COUNT - option_ordinal).unwrap())
            .collect::<Vec<_>>();
        scores[..tie_count].fill(60);
        cases.push((format!("tie multiplicity {tie_count}"), scores));
    }
    let mut seed = 0x5eed_5eed_cafe_babe_u64;
    for case_ordinal in 0..8 {
        let scores = (0..ORACLE_OPTION_COUNT)
            .map(|_| {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                seed % 91
            })
            .collect();
        cases.push((format!("seeded adversarial {case_ordinal}"), scores));
    }
    cases
}

struct PlaintextProgramInterpreter {
    constants: BTreeMap<[u8; 64], OracleRingValue>,
}

impl PlaintextProgramInterpreter {
    fn new(program: &EvaluatorProgramSet) -> Self {
        let constants = program
            .constants()
            .iter()
            .map(|constant| {
                (
                    *constant
                        .constant_hash()
                        .expect("validated evaluator constant hashes")
                        .as_bytes(),
                    decode_u32_coefficients(constant.values()),
                )
            })
            .collect();
        Self { constants }
    }

    fn execute(
        &self,
        stream: &EvaluatorInstructionStream,
        inputs: [OracleRingValue; ORACLE_CIPHERTEXT_COUNT],
    ) -> [OracleRingValue; 2] {
        let mut registers = inputs.into_iter().map(Some).collect::<Vec<_>>();
        let mut outputs: [Option<OracleRingValue>; 2] = [None, None];
        for instruction in stream.instructions() {
            match instruction.opcode() {
                EvaluatorOpcode::DropRegister => {
                    let register_ordinal =
                        usize::try_from(instruction.input_registers()[0]).unwrap();
                    assert!(registers[register_ordinal].take().is_some());
                }
                EvaluatorOpcode::DeclareOutput => {
                    let register_ordinal =
                        usize::try_from(instruction.input_registers()[0]).unwrap();
                    let output_ordinal = usize::try_from(instruction.immediate0() - 1).unwrap();
                    assert!(
                        outputs[output_ordinal]
                            .replace(
                                registers[register_ordinal]
                                    .as_ref()
                                    .expect("declared plaintext register is live")
                                    .clone(),
                            )
                            .is_none()
                    );
                }
                opcode => {
                    let input_values = instruction
                        .input_registers()
                        .iter()
                        .map(|register_ordinal| {
                            registers[usize::try_from(*register_ordinal).unwrap()]
                                .as_ref()
                                .expect("plaintext instruction input is live")
                                .clone()
                        })
                        .collect::<Vec<_>>();
                    let output = match opcode {
                        EvaluatorOpcode::ModulusSwitchToLevel
                        | EvaluatorOpcode::NormalizeDecryptionMultiplier => input_values[0].clone(),
                        EvaluatorOpcode::CiphertextAdd => {
                            semantic_oracle::add(&input_values[0], &input_values[1])
                        }
                        EvaluatorOpcode::PlaintextAdd => {
                            semantic_oracle::add(&input_values[0], self.constant(instruction))
                        }
                        EvaluatorOpcode::PlaintextMultiply => {
                            semantic_oracle::multiply(&input_values[0], self.constant(instruction))
                        }
                        EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                        | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                            semantic_oracle::multiply(&input_values[0], &input_values[1])
                        }
                        EvaluatorOpcode::GaloisRotate => semantic_oracle::apply_galois_action(
                            &input_values[0],
                            usize::try_from(instruction.immediate0())
                                .expect("selected Galois element fits usize"),
                        ),
                        EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput => {
                            unreachable!()
                        }
                    };
                    let output_register =
                        usize::try_from(instruction.output_register().unwrap()).unwrap();
                    assert_eq!(output_register, registers.len());
                    registers.push(Some(output));
                }
            }
        }
        outputs.map(|output| output.expect("plaintext program declared both outputs"))
    }

    fn constant(&self, instruction: &super::super::EvaluatorInstruction) -> &OracleRingValue {
        self.constants
            .get(
                instruction
                    .constant_hash()
                    .expect("plaintext instruction has one constant")
                    .as_bytes(),
            )
            .expect("plaintext instruction constant is in the validated catalog")
    }
}

fn assert_scalar_target(
    target: &OracleRingValue,
    expected_values: &[u64],
    top_count: u16,
    target_name: &str,
) {
    assert_eq!(target.len(), ORACLE_LANE_COUNT);
    assert_eq!(expected_values.len(), ORACLE_OPTION_COUNT);
    for (lane_ordinal, lane) in target.iter().enumerate() {
        let expected = expected_values.get(lane_ordinal).copied().unwrap_or(0);
        assert_eq!(
            lane[0], expected,
            "{target_name} target drifted for top count {top_count} at lane {lane_ordinal}",
        );
        assert!(lane[1..].iter().all(|coefficient| *coefficient == 0));
    }
}

fn decode_u32_coefficients(coefficients: &[u32]) -> OracleRingValue {
    assert!(!coefficients.is_empty());
    assert!(coefficients.len() <= POLYNOMIAL_DEGREE);
    let mut coefficients = coefficients
        .iter()
        .copied()
        .map(u64::from)
        .collect::<Vec<_>>();
    coefficients.resize(POLYNOMIAL_DEGREE, 0);
    let decoded = decode_plaintext_coefficients_to_extension_lanes(&coefficients)
        .expect("selected plaintext coefficients decode into extension lanes");
    assert_eq!(decoded.len(), ORACLE_LANE_COUNT);
    decoded
}

fn negacyclic_product_mod_plaintext(left: &[u64], right: &[u64]) -> Vec<u64> {
    assert_eq!(left.len(), POLYNOMIAL_DEGREE);
    assert_eq!(right.len(), POLYNOMIAL_DEGREE);
    let mut product = vec![0_u64; POLYNOMIAL_DEGREE];
    for (left_exponent, left_coefficient) in left
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, coefficient)| *coefficient != 0)
    {
        for (right_exponent, right_coefficient) in right
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, coefficient)| *coefficient != 0)
        {
            let exponent = left_exponent + right_exponent;
            let destination = exponent % POLYNOMIAL_DEGREE;
            let contribution = (u128::from(left_coefficient) * u128::from(right_coefficient)
                % u128::from(PLAINTEXT_MODULUS)) as u64;
            product[destination] = if exponent < POLYNOMIAL_DEGREE {
                (product[destination] + contribution) % PLAINTEXT_MODULUS
            } else {
                (product[destination] + PLAINTEXT_MODULUS - contribution) % PLAINTEXT_MODULUS
            };
        }
    }
    product
}

fn apply_negacyclic_galois_action(coefficients: &[u64], galois_element: usize) -> Vec<u64> {
    assert_eq!(coefficients.len(), POLYNOMIAL_DEGREE);
    assert_ne!(galois_element % 2, 0);
    let automorphism_modulus = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_u64; POLYNOMIAL_DEGREE];
    for (source_exponent, coefficient) in coefficients.iter().copied().enumerate() {
        let mapped_exponent = source_exponent * galois_element % automorphism_modulus;
        let destination = mapped_exponent % POLYNOMIAL_DEGREE;
        output[destination] = if mapped_exponent < POLYNOMIAL_DEGREE || coefficient == 0 {
            coefficient
        } else {
            PLAINTEXT_MODULUS - coefficient
        };
    }
    output
}

fn add_ring_assign(accumulated: &mut [u64], contribution: &[u64]) {
    assert_eq!(accumulated.len(), contribution.len());
    for (accumulated_coefficient, contribution_coefficient) in
        accumulated.iter_mut().zip(contribution)
    {
        *accumulated_coefficient =
            (*accumulated_coefficient + contribution_coefficient) % PLAINTEXT_MODULUS;
    }
}
