//! Guarded encrypted semantic evidence for the selected evaluator program.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;

use crate::bgv::{
    direct_ballots::pair_character_plaintexts,
    encoding::{
        decode_plaintext_coefficients_to_extension_lanes,
        encode_extension_lanes_to_plaintext_coefficients,
    },
    evaluator::{
        engine::{
            Ciphertext, DevelopmentBgvKey, ExactDecryptionErrorObserver,
            add_plaintext_coefficients, ciphertext_add, ciphertext_tensor, modulus_switch,
            modulus_switch_to, normalize_scaling, plaintext_mul,
        },
        key_switch::{
            KeySwitchKey, generate_galois_key, generate_relinearization_key, relinearize, rotate,
        },
        pair_character_product::{
            PairCharacterProductMerge, canonical_pair_character_product_schedule,
        },
        semantic_oracle::{
            self, ORACLE_CIPHERTEXT_COUNT, ORACLE_LANE_COUNT, ORACLE_OPTION_COUNT, OracleRingValue,
        },
        top_k::{
            CHARACTER_OUTPUT_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL,
            selected_evaluator_rotation_key_schedule,
        },
    },
    parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
};

use super::super::{
    EvaluatorInstruction, EvaluatorOpcode, EvaluatorProgramSet,
    compiler::{
        EvaluatorCompilerStage, EvaluatorCompilerStreamStageRegisters,
        selected_evaluator_program_set_with_stage_registers,
    },
};
use super::{encode_constant_coefficients, zeroize_ciphertext};

const DEVELOPMENT_KEY_SEED: &str = "selected-encrypted-evaluator-semantic-development-key";

struct EncryptedSemanticCase {
    name: String,
    aggregate_scores: Vec<u64>,
    ballot_count: usize,
    top_counts: Vec<usize>,
    calibrate_product_error: bool,
    calibrate_evaluator_error: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvaluatorErrorObservationMode {
    None,
    Complete,
    TopCountTail,
}

struct EncryptedEvaluatorExecution<'a> {
    aggregate_ciphertexts: [Ciphertext; ORACLE_CIPHERTEXT_COUNT],
    expected_inputs: [OracleRingValue; ORACLE_CIPHERTEXT_COUNT],
    aggregate_scores: &'a [u64],
    top_count: usize,
    case_name: &'a str,
    error_observation_mode: EvaluatorErrorObservationMode,
}

struct TestConstant {
    coefficients: Vec<u64>,
    lanes: OracleRingValue,
}

struct EncryptedEvaluatorHarness {
    development_key: DevelopmentBgvKey,
    error_observer: ExactDecryptionErrorObserver,
    relinearization_key: KeySwitchKey,
    galois_keys: BTreeMap<usize, KeySwitchKey>,
    program: EvaluatorProgramSet,
    stage_registers: Vec<EvaluatorCompilerStreamStageRegisters>,
    constants: BTreeMap<[u8; 64], TestConstant>,
}

struct ExactErrorLedger {
    expected_observation_counts: BTreeMap<&'static str, usize>,
    observation_counts: BTreeMap<&'static str, usize>,
    maximum_norms: BTreeMap<&'static str, BigUint>,
    observed_stages: BTreeSet<EvaluatorCompilerStage>,
    observed_ballot_counts: BTreeSet<usize>,
}

impl ExactErrorLedger {
    fn new(expected_observation_counts: BTreeMap<&'static str, usize>) -> Self {
        assert!(
            expected_observation_counts
                .values()
                .all(|expected_count| *expected_count > 0),
            "every exact-error observation category must have a positive expected count"
        );
        Self {
            expected_observation_counts,
            observation_counts: BTreeMap::new(),
            maximum_norms: BTreeMap::new(),
            observed_stages: BTreeSet::new(),
            observed_ballot_counts: BTreeSet::new(),
        }
    }

    fn observe(
        &mut self,
        observer: &ExactDecryptionErrorObserver,
        ciphertext: &Ciphertext,
        expected_lanes: &OracleRingValue,
        categories: &[&'static str],
        stages: &[EvaluatorCompilerStage],
        case_name: &str,
    ) {
        let expected_coefficients =
            encode_extension_lanes_to_plaintext_coefficients(expected_lanes)
                .expect("expected encrypted semantic lanes encode");
        let infinity_norm = observer
            .measure_infinity_norm(ciphertext, &expected_coefficients)
            .unwrap_or_else(|error| {
                panic!(
                    "exact encrypted error observation failed for {case_name} at level {} for categories {categories:?} and stages {stages:?}: {error}",
                    ciphertext.level,
                )
            });
        for category in categories.iter().copied() {
            let expected_count = *self
                .expected_observation_counts
                .get(&category)
                .unwrap_or_else(|| {
                    panic!("unexpected exact-error observation category {category}")
                });
            let observed_count = self.observation_counts.entry(category).or_default();
            *observed_count += 1;
            assert!(
                *observed_count <= expected_count,
                "exact-error observation category {category} exceeded its expected count {expected_count}"
            );
            self.maximum_norms
                .entry(category)
                .and_modify(|maximum| *maximum = maximum.clone().max(infinity_norm.clone()))
                .or_insert_with(|| infinity_norm.clone());
        }
        self.observed_stages.extend(stages.iter().copied());
    }

    fn assert_complete(&self, expected_stages: &BTreeSet<EvaluatorCompilerStage>) {
        assert_eq!(
            &self.observation_counts, &self.expected_observation_counts,
            "the exact encrypted error ledger did not observe every scheduled operation count"
        );
        assert_eq!(
            self.maximum_norms.keys().copied().collect::<BTreeSet<_>>(),
            self.expected_observation_counts
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            self.observed_ballot_counts,
            (1..=10).collect::<BTreeSet<_>>()
        );
        assert_eq!(&self.observed_stages, expected_stages);
    }
}

#[test]
#[ignore = "guarded selected-suite encrypted evaluator semantic and exact-error evidence"]
fn heavy_rust_kernel_encrypted_evaluator_matches_direct_stable_top_k_across_covering_matrix() {
    let harness = EncryptedEvaluatorHarness::new();
    let cases = encrypted_semantic_cases();
    let mut exact_error_ledger =
        ExactErrorLedger::new(harness.expected_exact_error_observation_counts());
    let expected_stages = harness
        .stage_registers
        .iter()
        .flat_map(|stream| stream.stage_registers().iter().map(|entry| entry.stage()))
        .collect::<BTreeSet<_>>();

    assert_active_lane_boundaries_across_both_ciphertexts();
    for case in cases {
        assert_eq!(case.aggregate_scores.len(), ORACLE_OPTION_COUNT);
        assert!((1..=10).contains(&case.ballot_count));
        assert!(
            case.aggregate_scores
                .iter()
                .all(|score| *score <= u64::try_from(9 * case.ballot_count).unwrap()),
            "{} cannot be decomposed into its selected ballot count",
            case.name
        );
        let expected_inputs = semantic_oracle::aggregate_character_inputs(&case.aggregate_scores);
        let aggregate_ciphertexts = if case.calibrate_product_error {
            let calibrated_products = harness.build_pair_character_products(
                &case.aggregate_scores,
                case.ballot_count,
                &case.name,
                true,
                &mut exact_error_ledger,
            );
            assert!(
                exact_error_ledger
                    .observed_ballot_counts
                    .insert(case.ballot_count),
                "ballot count {} has more than one product calibration case",
                case.ballot_count
            );
            calibrated_products
        } else {
            harness.encrypt_aggregate_character_inputs(&expected_inputs, &case.name)
        };

        for top_count in case.top_counts {
            let error_observation_mode = if case.calibrate_evaluator_error && top_count == 1 {
                EvaluatorErrorObservationMode::Complete
            } else if case.calibrate_evaluator_error {
                EvaluatorErrorObservationMode::TopCountTail
            } else {
                EvaluatorErrorObservationMode::None
            };
            harness.execute_and_assert_case(
                EncryptedEvaluatorExecution {
                    aggregate_ciphertexts: aggregate_ciphertexts.clone(),
                    expected_inputs: expected_inputs.clone(),
                    aggregate_scores: &case.aggregate_scores,
                    top_count,
                    case_name: &case.name,
                    error_observation_mode,
                },
                &mut exact_error_ledger,
            );
        }
    }
    exact_error_ledger.assert_complete(&expected_stages);
}

impl EncryptedEvaluatorHarness {
    fn new() -> Self {
        let development_key = DevelopmentBgvKey::generate(DEVELOPMENT_KEY_SEED)
            .expect("selected development BGV key generates");
        let error_observer = development_key
            .exact_decryption_error_observer()
            .expect("selected exact decryption-error observer initializes");
        let relinearization_key = generate_relinearization_key(
            &development_key,
            SELECTED_RELINEARIZATION_KEY_LEVEL,
            "selected-encrypted-evaluator-semantic-relinearization-key",
        )
        .expect("selected relinearization key generates");
        let galois_keys = selected_evaluator_rotation_key_schedule(ORACLE_OPTION_COUNT)
            .expect("selected evaluator rotation catalog")
            .into_iter()
            .map(|(galois_element, catalog_level)| {
                let seed = format!(
                    "selected-encrypted-evaluator-semantic-galois-{galois_element}-{catalog_level}"
                );
                let key =
                    generate_galois_key(&development_key, galois_element, catalog_level, &seed)
                        .expect("selected Galois key generates");
                (galois_element, key)
            })
            .collect();
        let (program, stage_registers) = selected_evaluator_program_set_with_stage_registers()
            .expect("selected evaluator program and stage registers compile");
        assert_eq!(program.streams().len(), ORACLE_OPTION_COUNT);
        assert_eq!(stage_registers.len(), ORACLE_OPTION_COUNT);
        assert_eq!(
            program
                .streams()
                .iter()
                .flat_map(|stream| stream.instructions())
                .filter(|instruction| {
                    instruction.opcode() == EvaluatorOpcode::NormalizeDecryptionMultiplier
                })
                .count(),
            0,
            "the selected evaluator emits no decryption-multiplier normalization opcode"
        );
        let constants = program
            .constants()
            .iter()
            .map(|constant| {
                let hash = *constant
                    .constant_hash()
                    .expect("selected evaluator constant hashes")
                    .as_bytes();
                let coefficients = encode_constant_coefficients(constant)
                    .expect("selected evaluator constant encodes");
                let lanes = decode_plaintext_coefficients_to_extension_lanes(&coefficients)
                    .expect("selected evaluator constant decodes into extension lanes");
                (
                    hash,
                    TestConstant {
                        coefficients,
                        lanes,
                    },
                )
            })
            .collect();
        Self {
            development_key,
            error_observer,
            relinearization_key,
            galois_keys,
            program,
            stage_registers,
            constants,
        }
    }

    fn expected_exact_error_observation_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut expected_counts = BTreeMap::new();
        for ballot_count in 1..=10 {
            let schedule = canonical_pair_character_product_schedule(ballot_count)
                .expect("selected product calibration schedule");
            add_expected_observation_count(
                &mut expected_counts,
                "fresh character",
                2 * ballot_count,
            );
            add_expected_observation_count(
                &mut expected_counts,
                "product multiplication",
                2 * (ballot_count - 1),
            );
            add_expected_observation_count(
                &mut expected_counts,
                "product relinearization",
                2 * (ballot_count - 1),
            );
            add_expected_observation_count(
                &mut expected_counts,
                "product modulus switch",
                2 * schedule.accounting.modulus_drop_count(),
            );
            if schedule.normalization.requires_plaintext_multiplication() {
                add_expected_observation_count(&mut expected_counts, "product normalization", 2);
            }
        }

        let stream = &self.program.streams()[0];
        let mut register_levels = vec![Some(CHARACTER_OUTPUT_LEVEL), Some(CHARACTER_OUTPUT_LEVEL)];
        for instruction in stream.instructions() {
            let output_level = match instruction.opcode() {
                EvaluatorOpcode::DropRegister => {
                    let register_ordinal =
                        usize::try_from(instruction.input_registers()[0]).unwrap();
                    assert!(register_levels[register_ordinal].take().is_some());
                    None
                }
                EvaluatorOpcode::DeclareOutput => None,
                EvaluatorOpcode::ModulusSwitchToLevel => {
                    let source_level = expected_register_level(&register_levels, instruction, 0);
                    let target_level = usize::try_from(instruction.immediate0()).unwrap();
                    assert!(target_level < source_level);
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator modulus switch",
                        source_level - target_level,
                    );
                    Some(target_level)
                }
                EvaluatorOpcode::NormalizeDecryptionMultiplier => {
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
                EvaluatorOpcode::CiphertextAdd => {
                    let level = expected_register_level(&register_levels, instruction, 0);
                    assert_eq!(
                        expected_register_level(&register_levels, instruction, 1),
                        level
                    );
                    Some(level)
                }
                EvaluatorOpcode::PlaintextAdd => {
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
                EvaluatorOpcode::PlaintextMultiply => {
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator plaintext multiplication",
                        1,
                    );
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                    let level = expected_register_level(&register_levels, instruction, 0);
                    assert_eq!(
                        expected_register_level(&register_levels, instruction, 1),
                        level
                    );
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator ciphertext multiplication",
                        1,
                    );
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator relinearization",
                        1,
                    );
                    if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                    {
                        add_expected_observation_count(
                            &mut expected_counts,
                            "evaluator modulus switch",
                            1,
                        );
                        Some(level.checked_sub(1).expect("selected product level drops"))
                    } else {
                        Some(level)
                    }
                }
                EvaluatorOpcode::GaloisRotate => {
                    add_expected_observation_count(&mut expected_counts, "evaluator rotation", 1);
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
            };
            if let Some(output_level) = output_level {
                assert_eq!(
                    usize::try_from(instruction.output_register().unwrap()).unwrap(),
                    register_levels.len()
                );
                register_levels.push(Some(output_level));
            }
        }

        let complete_stage_register_count = self.stage_registers[0]
            .stage_registers()
            .iter()
            .map(|entry| entry.register_ordinal())
            .collect::<BTreeSet<_>>()
            .len();
        add_expected_observation_count(
            &mut expected_counts,
            "compiler stage",
            complete_stage_register_count,
        );
        for stage_registers in &self.stage_registers[1..] {
            let tail_stage_register_count = stage_registers
                .stage_registers()
                .iter()
                .filter(|entry| {
                    should_observe_stage(EvaluatorErrorObservationMode::TopCountTail, entry.stage())
                })
                .map(|entry| entry.register_ordinal())
                .collect::<BTreeSet<_>>()
                .len();
            add_expected_observation_count(
                &mut expected_counts,
                "compiler stage",
                tail_stage_register_count,
            );
        }
        expected_counts
    }

    fn build_pair_character_products(
        &self,
        aggregate_scores: &[u64],
        ballot_count: usize,
        case_name: &str,
        calibrate_exact_error: bool,
        exact_error_ledger: &mut ExactErrorLedger,
    ) -> [Ciphertext; ORACLE_CIPHERTEXT_COUNT] {
        core::array::from_fn(|ciphertext_ordinal| {
            self.build_pair_character_product(
                aggregate_scores,
                ballot_count,
                ciphertext_ordinal,
                case_name,
                calibrate_exact_error,
                exact_error_ledger,
            )
        })
    }

    fn encrypt_aggregate_character_inputs(
        &self,
        expected_inputs: &[OracleRingValue; ORACLE_CIPHERTEXT_COUNT],
        case_name: &str,
    ) -> [Ciphertext; ORACLE_CIPHERTEXT_COUNT] {
        core::array::from_fn(|ciphertext_ordinal| {
            let coefficients = encode_extension_lanes_to_plaintext_coefficients(
                &expected_inputs[ciphertext_ordinal],
            )
            .expect("independent aggregate pair-character lanes encode");
            let fresh = self
                .development_key
                .encrypt_coefficients(
                    &coefficients,
                    &format!(
                        "encrypted-evaluator-semantic-aggregate-{case_name}-{ciphertext_ordinal}"
                    ),
                )
                .expect("independent aggregate pair-character input encrypts");
            modulus_switch_to(&fresh, CHARACTER_OUTPUT_LEVEL)
                .expect("independent aggregate pair-character input reaches evaluator level")
        })
    }

    fn build_pair_character_product(
        &self,
        aggregate_scores: &[u64],
        ballot_count: usize,
        ciphertext_ordinal: usize,
        case_name: &str,
        calibrate_exact_error: bool,
        exact_error_ledger: &mut ExactErrorLedger,
    ) -> Ciphertext {
        let schedule = canonical_pair_character_product_schedule(ballot_count)
            .expect("selected pair-character product schedule");
        let mut states = (0..schedule.nodes.len())
            .map(|_| None)
            .collect::<Vec<Option<EncryptedProductState>>>();
        let mut next_merge_ordinal = 0_usize;

        for ballot_ordinal in 0..ballot_count {
            let ballot_scores =
                ballot_scores_for_aggregate(aggregate_scores, ballot_count, ballot_ordinal);
            let plaintexts =
                pair_character_plaintexts(&ballot_scores, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE)
                    .expect("selected pair-character plaintexts encode");
            let plaintext_coefficients = plaintexts[ciphertext_ordinal]
                .message_coefficients()
                .to_vec();
            let expected_lanes =
                decode_plaintext_coefficients_to_extension_lanes(&plaintext_coefficients)
                    .expect("fresh pair-character plaintext decodes");
            let encryption_seed = format!(
                "encrypted-evaluator-semantic-{case_name}-{ballot_count}-{ciphertext_ordinal}-{ballot_ordinal}"
            );
            let ciphertext = self
                .development_key
                .encrypt_coefficients(&plaintext_coefficients, &encryption_seed)
                .expect("fresh pair-character ciphertext encrypts");
            if calibrate_exact_error {
                exact_error_ledger.observe(
                    &self.error_observer,
                    &ciphertext,
                    &expected_lanes,
                    &["fresh character"],
                    &[],
                    case_name,
                );
            }
            let leaf = schedule
                .nodes
                .iter()
                .find(|node| {
                    node.ballot_span.first_ballot_ordinal == ballot_ordinal
                        && node.ballot_span.ballot_count == 1
                })
                .expect("selected schedule contains each fresh leaf");
            assert!(
                states[leaf.node_ordinal]
                    .replace(EncryptedProductState {
                        ciphertext,
                        expected_lanes,
                    })
                    .is_none()
            );
            while schedule
                .merges
                .get(next_merge_ordinal)
                .is_some_and(|merge| {
                    states[merge.left_node_ordinal].is_some()
                        && states[merge.right_node_ordinal].is_some()
                })
            {
                self.execute_product_merge(
                    &schedule.merges[next_merge_ordinal],
                    &schedule,
                    &mut states,
                    exact_error_ledger,
                    case_name,
                    calibrate_exact_error,
                );
                next_merge_ordinal += 1;
            }
        }
        while next_merge_ordinal < schedule.merges.len() {
            self.execute_product_merge(
                &schedule.merges[next_merge_ordinal],
                &schedule,
                &mut states,
                exact_error_ledger,
                case_name,
                calibrate_exact_error,
            );
            next_merge_ordinal += 1;
        }

        let mut root = states[schedule.root_node_ordinal]
            .take()
            .expect("selected pair-character root exists");
        assert!(states.iter().all(Option::is_none));
        if schedule.normalization.requires_plaintext_multiplication() {
            let normalization_coefficients = schedule.normalization.plaintext_coefficients();
            let normalization_lanes =
                decode_plaintext_coefficients_to_extension_lanes(&normalization_coefficients)
                    .expect("selected product normalization decodes");
            root.expected_lanes =
                semantic_oracle::multiply(&root.expected_lanes, &normalization_lanes);
            root.ciphertext = plaintext_mul(&root.ciphertext, &normalization_coefficients)
                .expect("selected pair-character product normalizes");
            if calibrate_exact_error {
                exact_error_ledger.observe(
                    &self.error_observer,
                    &root.ciphertext,
                    &root.expected_lanes,
                    &["product normalization"],
                    &[],
                    case_name,
                );
            }
        }
        switch_product_state_to_level(
            &mut root,
            schedule.terminal_output_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        assert_eq!(root.ciphertext.level, CHARACTER_OUTPUT_LEVEL);
        root.ciphertext
    }

    fn execute_and_assert_case(
        &self,
        execution: EncryptedEvaluatorExecution<'_>,
        exact_error_ledger: &mut ExactErrorLedger,
    ) {
        let EncryptedEvaluatorExecution {
            aggregate_ciphertexts,
            expected_inputs,
            aggregate_scores,
            top_count,
            case_name,
            error_observation_mode,
        } = execution;
        assert!((1..=ORACLE_OPTION_COUNT).contains(&top_count));
        let stream = &self.program.streams()[top_count - 1];
        let stage_registers = &self.stage_registers[top_count - 1];
        assert_eq!(usize::from(stream.top_count()), top_count);
        assert_eq!(usize::from(stage_registers.top_count()), top_count);
        let stages_by_register = stage_registers.stage_registers().iter().fold(
            BTreeMap::<u32, Vec<EvaluatorCompilerStage>>::new(),
            |mut stages, entry| {
                stages
                    .entry(entry.register_ordinal())
                    .or_default()
                    .push(entry.stage());
                stages
            },
        );
        let expected_observed_stage_registers = stages_by_register
            .iter()
            .filter(|(_, stages)| {
                stages
                    .iter()
                    .copied()
                    .any(|stage| should_observe_stage(error_observation_mode, stage))
            })
            .map(|(register_ordinal, _)| *register_ordinal)
            .collect::<BTreeSet<_>>();
        let mut encountered_stage_registers = BTreeSet::new();
        let mut ciphertext_registers = aggregate_ciphertexts
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let mut expected_registers = expected_inputs.into_iter().map(Some).collect::<Vec<_>>();
        for register_ordinal in 0..ORACLE_CIPHERTEXT_COUNT {
            let register_ordinal_u32 = u32::try_from(register_ordinal).unwrap();
            let stages = stages_by_register
                .get(&register_ordinal_u32)
                .into_iter()
                .flatten()
                .copied()
                .filter(|stage| should_observe_stage(error_observation_mode, *stage))
                .collect::<Vec<_>>();
            if !stages.is_empty() {
                encountered_stage_registers.insert(register_ordinal_u32);
                exact_error_ledger.observe(
                    &self.error_observer,
                    ciphertext_registers[register_ordinal]
                        .as_ref()
                        .expect("selected input ciphertext is live"),
                    expected_registers[register_ordinal]
                        .as_ref()
                        .expect("selected input shadow is live"),
                    &["compiler stage"],
                    &stages,
                    case_name,
                );
            }
        }

        let mut target_registers = [None, None];
        for instruction in stream.instructions() {
            match instruction.opcode() {
                EvaluatorOpcode::DropRegister => {
                    let register_ordinal = usize::try_from(instruction.input_registers()[0])
                        .expect("selected register ordinal fits usize");
                    let mut ciphertext = ciphertext_registers[register_ordinal]
                        .take()
                        .expect("selected dropped ciphertext register is live");
                    assert!(expected_registers[register_ordinal].take().is_some());
                    zeroize_ciphertext(&mut ciphertext);
                }
                EvaluatorOpcode::DeclareOutput => {
                    let register_ordinal = instruction.input_registers()[0];
                    let target_ordinal = usize::try_from(instruction.immediate0() - 1)
                        .expect("selected target ordinal fits usize");
                    assert!(
                        ciphertext_registers[usize::try_from(register_ordinal).unwrap()].is_some()
                    );
                    assert!(
                        target_registers[target_ordinal]
                            .replace(register_ordinal)
                            .is_none()
                    );
                }
                opcode => {
                    let expected_output =
                        self.expected_instruction_output(instruction, &expected_registers);
                    let (ciphertext_output, operation_categories) = self.execute_test_instruction(
                        instruction,
                        &ciphertext_registers,
                        &expected_output,
                        case_name,
                        error_observation_mode == EvaluatorErrorObservationMode::Complete,
                        exact_error_ledger,
                    );
                    let output_register = usize::try_from(
                        instruction
                            .output_register()
                            .expect("selected evaluator operation produces a register"),
                    )
                    .expect("selected output register fits usize");
                    assert_eq!(output_register, ciphertext_registers.len());
                    assert_eq!(output_register, expected_registers.len());
                    let output_register_u32 = u32::try_from(output_register).unwrap();
                    let stages = stages_by_register
                        .get(&output_register_u32)
                        .into_iter()
                        .flatten()
                        .copied()
                        .filter(|stage| should_observe_stage(error_observation_mode, *stage))
                        .collect::<Vec<_>>();
                    if !stages.is_empty() {
                        encountered_stage_registers.insert(output_register_u32);
                    }
                    let mut operation_categories =
                        if error_observation_mode == EvaluatorErrorObservationMode::Complete {
                            operation_categories
                        } else {
                            Vec::new()
                        };
                    if !operation_categories.is_empty() || !stages.is_empty() {
                        if !stages.is_empty() {
                            operation_categories.push("compiler stage");
                        }
                        exact_error_ledger.observe(
                            &self.error_observer,
                            &ciphertext_output,
                            &expected_output,
                            &operation_categories,
                            &stages,
                            case_name,
                        );
                    }
                    ciphertext_registers.push(Some(ciphertext_output));
                    expected_registers.push(Some(expected_output));
                    assert!(!matches!(
                        opcode,
                        EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput
                    ));
                }
            }
        }
        assert_eq!(
            encountered_stage_registers, expected_observed_stage_registers,
            "compiler stage register was not observed for {case_name} at top count {top_count}"
        );

        let target_identifier_register =
            usize::try_from(target_registers[0].expect("identifier target register is declared"))
                .unwrap();
        let target_order_register =
            usize::try_from(target_registers[1].expect("order target register is declared"))
                .unwrap();
        let target_identifier = ciphertext_registers[target_identifier_register]
            .take()
            .expect("identifier target remains live");
        let target_order = ciphertext_registers[target_order_register]
            .take()
            .expect("order target remains live");
        let expected_identifier = expected_registers[target_identifier_register]
            .take()
            .expect("identifier target shadow remains live");
        let expected_order = expected_registers[target_order_register]
            .take()
            .expect("order target shadow remains live");
        assert!(ciphertext_registers.iter().all(Option::is_none));
        assert!(expected_registers.iter().all(Option::is_none));

        let [expected_identifier_values, expected_order_values] =
            independent_stable_target_values(aggregate_scores, top_count);
        assert_scalar_target(
            &expected_identifier,
            &expected_identifier_values,
            case_name,
            top_count,
            "identifier plaintext shadow",
        );
        assert_scalar_target(
            &expected_order,
            &expected_order_values,
            case_name,
            top_count,
            "order plaintext shadow",
        );
        if error_observation_mode == EvaluatorErrorObservationMode::None {
            let expected_identifier_coefficients =
                encode_extension_lanes_to_plaintext_coefficients(&expected_identifier)
                    .expect("expected identifier target encodes");
            let expected_order_coefficients =
                encode_extension_lanes_to_plaintext_coefficients(&expected_order)
                    .expect("expected order target encodes");
            self.error_observer
                .measure_infinity_norm(&target_identifier, &expected_identifier_coefficients)
                .unwrap_or_else(|error| {
                    panic!(
                        "encrypted identifier target failed exact error observation for {case_name}, top count {top_count}: {error}"
                    )
                });
            self.error_observer
                .measure_infinity_norm(&target_order, &expected_order_coefficients)
                .unwrap_or_else(|error| {
                    panic!(
                        "encrypted order target failed exact error observation for {case_name}, top count {top_count}: {error}"
                    )
                });
        }
    }

    fn execute_test_instruction(
        &self,
        instruction: &EvaluatorInstruction,
        ciphertext_registers: &[Option<Ciphertext>],
        expected_output: &OracleRingValue,
        case_name: &str,
        calibrate_exact_error: bool,
        exact_error_ledger: &mut ExactErrorLedger,
    ) -> (Ciphertext, Vec<&'static str>) {
        let input = |input_ordinal: usize| {
            let register_ordinal =
                usize::try_from(instruction.input_registers()[input_ordinal]).unwrap();
            ciphertext_registers[register_ordinal]
                .as_ref()
                .expect("selected encrypted instruction input is live")
        };
        match instruction.opcode() {
            EvaluatorOpcode::ModulusSwitchToLevel => {
                let target_level = usize::try_from(instruction.immediate0())
                    .expect("selected target level fits usize");
                assert!(target_level < input(0).level);
                let mut switched =
                    modulus_switch(input(0)).expect("selected evaluator modulus switch executes");
                if calibrate_exact_error {
                    exact_error_ledger.observe(
                        &self.error_observer,
                        &switched,
                        expected_output,
                        &["evaluator modulus switch"],
                        &[],
                        case_name,
                    );
                }
                while switched.level > target_level {
                    switched = modulus_switch(&switched)
                        .expect("selected evaluator modulus switch step executes");
                    if calibrate_exact_error {
                        exact_error_ledger.observe(
                            &self.error_observer,
                            &switched,
                            expected_output,
                            &["evaluator modulus switch"],
                            &[],
                            case_name,
                        );
                    }
                }
                assert_eq!(switched.level, target_level);
                (switched, Vec::new())
            }
            EvaluatorOpcode::NormalizeDecryptionMultiplier => (
                normalize_scaling(input(0)).expect("selected evaluator normalization executes"),
                vec!["evaluator normalization"],
            ),
            EvaluatorOpcode::CiphertextAdd => (
                ciphertext_add(input(0), input(1)).expect("selected evaluator addition executes"),
                Vec::new(),
            ),
            EvaluatorOpcode::PlaintextAdd => (
                add_plaintext_coefficients(input(0), &self.constant(instruction).coefficients)
                    .expect("selected evaluator plaintext addition executes"),
                Vec::new(),
            ),
            EvaluatorOpcode::PlaintextMultiply => (
                plaintext_mul(input(0), &self.constant(instruction).coefficients)
                    .expect("selected evaluator plaintext multiplication executes"),
                vec!["evaluator plaintext multiplication"],
            ),
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                let tensor = ciphertext_tensor(input(0), input(1))
                    .expect("selected evaluator ciphertext multiplication executes");
                if calibrate_exact_error {
                    exact_error_ledger.observe(
                        &self.error_observer,
                        &tensor,
                        expected_output,
                        &["evaluator ciphertext multiplication"],
                        &[],
                        case_name,
                    );
                }
                let relinearized = relinearize(&tensor, &self.relinearization_key)
                    .expect("selected evaluator ciphertext product relinearizes");
                if calibrate_exact_error {
                    exact_error_ledger.observe(
                        &self.error_observer,
                        &relinearized,
                        expected_output,
                        &["evaluator relinearization"],
                        &[],
                        case_name,
                    );
                }
                if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop {
                    (
                        modulus_switch(&relinearized)
                            .expect("selected evaluator product modulus switches"),
                        vec!["evaluator modulus switch"],
                    )
                } else {
                    (relinearized, Vec::new())
                }
            }
            EvaluatorOpcode::GaloisRotate => {
                let galois_element = usize::try_from(instruction.immediate0())
                    .expect("selected Galois element fits usize");
                let galois_key = self
                    .galois_keys
                    .get(&galois_element)
                    .expect("selected Galois key is generated");
                (
                    rotate(input(0), galois_element, galois_key)
                        .expect("selected evaluator rotation executes"),
                    vec!["evaluator rotation"],
                )
            }
            EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput => {
                unreachable!("non-producing instructions are handled before the test driver")
            }
        }
    }

    fn expected_instruction_output(
        &self,
        instruction: &EvaluatorInstruction,
        expected_registers: &[Option<OracleRingValue>],
    ) -> OracleRingValue {
        let input = |input_ordinal: usize| {
            let register_ordinal =
                usize::try_from(instruction.input_registers()[input_ordinal]).unwrap();
            expected_registers[register_ordinal]
                .as_ref()
                .expect("selected plaintext-shadow input is live")
        };
        match instruction.opcode() {
            EvaluatorOpcode::ModulusSwitchToLevel
            | EvaluatorOpcode::NormalizeDecryptionMultiplier => input(0).clone(),
            EvaluatorOpcode::CiphertextAdd => semantic_oracle::add(input(0), input(1)),
            EvaluatorOpcode::PlaintextAdd => {
                semantic_oracle::add(input(0), &self.constant(instruction).lanes)
            }
            EvaluatorOpcode::PlaintextMultiply => {
                semantic_oracle::multiply(input(0), &self.constant(instruction).lanes)
            }
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                semantic_oracle::multiply(input(0), input(1))
            }
            EvaluatorOpcode::GaloisRotate => semantic_oracle::apply_galois_action(
                input(0),
                usize::try_from(instruction.immediate0())
                    .expect("selected Galois element fits usize"),
            ),
            EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput => {
                unreachable!("non-producing instructions have no plaintext shadow output")
            }
        }
    }

    fn constant(&self, instruction: &EvaluatorInstruction) -> &TestConstant {
        self.constants
            .get(
                instruction
                    .constant_hash()
                    .expect("selected plaintext instruction has a constant")
                    .as_bytes(),
            )
            .expect("selected plaintext instruction constant is cataloged")
    }
}

struct EncryptedProductState {
    ciphertext: Ciphertext,
    expected_lanes: OracleRingValue,
}

impl EncryptedEvaluatorHarness {
    fn execute_product_merge(
        &self,
        merge: &PairCharacterProductMerge,
        schedule: &crate::bgv::evaluator::pair_character_product::PairCharacterProductSchedule,
        states: &mut [Option<EncryptedProductState>],
        exact_error_ledger: &mut ExactErrorLedger,
        case_name: &str,
        calibrate_exact_error: bool,
    ) {
        let mut left = states[merge.left_node_ordinal]
            .take()
            .expect("selected product merge has its left input");
        let mut right = states[merge.right_node_ordinal]
            .take()
            .expect("selected product merge has its right input");
        switch_product_state_to_level(
            &mut left,
            merge.alignment_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        switch_product_state_to_level(
            &mut right,
            merge.alignment_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        let expected_lanes = semantic_oracle::multiply(&left.expected_lanes, &right.expected_lanes);
        let tensor = ciphertext_tensor(&left.ciphertext, &right.ciphertext)
            .expect("selected pair-character ciphertexts multiply");
        if calibrate_exact_error {
            exact_error_ledger.observe(
                &self.error_observer,
                &tensor,
                &expected_lanes,
                &["product multiplication"],
                &[],
                case_name,
            );
        }
        let relinearized = relinearize(&tensor, &self.relinearization_key)
            .expect("selected pair-character product relinearizes");
        if calibrate_exact_error {
            exact_error_ledger.observe(
                &self.error_observer,
                &relinearized,
                &expected_lanes,
                &["product relinearization"],
                &[],
                case_name,
            );
        }
        let mut output = EncryptedProductState {
            ciphertext: relinearized,
            expected_lanes,
        };
        let output_level = schedule.nodes[merge.output_node_ordinal].level;
        switch_product_state_to_level(
            &mut output,
            output_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        assert!(states[merge.output_node_ordinal].replace(output).is_none());
    }
}

fn switch_product_state_to_level(
    state: &mut EncryptedProductState,
    target_level: usize,
    error_observer: &ExactDecryptionErrorObserver,
    exact_error_ledger: &mut ExactErrorLedger,
    case_name: &str,
    calibrate_exact_error: bool,
) {
    assert!(target_level <= state.ciphertext.level);
    while state.ciphertext.level > target_level {
        state.ciphertext = modulus_switch(&state.ciphertext)
            .expect("selected pair-character ciphertext modulus switches");
        if calibrate_exact_error {
            exact_error_ledger.observe(
                error_observer,
                &state.ciphertext,
                &state.expected_lanes,
                &["product modulus switch"],
                &[],
                case_name,
            );
        }
    }
}

fn ballot_scores_for_aggregate(
    aggregate_scores: &[u64],
    ballot_count: usize,
    ballot_ordinal: usize,
) -> Vec<u64> {
    let ballot_count_u64 = u64::try_from(ballot_count).expect("selected ballot count fits u64");
    aggregate_scores
        .iter()
        .map(|aggregate_score| {
            let quotient = aggregate_score / ballot_count_u64;
            let remainder = aggregate_score % ballot_count_u64;
            let zero_based_score =
                quotient + u64::from(u64::try_from(ballot_ordinal).unwrap() < remainder);
            assert!(zero_based_score <= 9);
            zero_based_score + 1
        })
        .collect()
}

fn should_observe_stage(
    mode: EvaluatorErrorObservationMode,
    stage: EvaluatorCompilerStage,
) -> bool {
    match mode {
        EvaluatorErrorObservationMode::None => false,
        EvaluatorErrorObservationMode::Complete => true,
        EvaluatorErrorObservationMode::TopCountTail => matches!(
            stage,
            EvaluatorCompilerStage::IdentifierPolynomialBeforeSelector
                | EvaluatorCompilerStage::OrderPolynomialBeforeSelector
                | EvaluatorCompilerStage::FinalIdentifierTarget
                | EvaluatorCompilerStage::FinalOrderTarget
        ),
    }
}

fn add_expected_observation_count(
    expected_counts: &mut BTreeMap<&'static str, usize>,
    category: &'static str,
    additional_count: usize,
) {
    if additional_count == 0 {
        return;
    }
    let expected_count = expected_counts.entry(category).or_default();
    *expected_count = expected_count
        .checked_add(additional_count)
        .expect("exact-error expected observation count fits usize");
}

fn expected_register_level(
    register_levels: &[Option<usize>],
    instruction: &EvaluatorInstruction,
    input_ordinal: usize,
) -> usize {
    let register_ordinal = usize::try_from(instruction.input_registers()[input_ordinal]).unwrap();
    register_levels[register_ordinal].expect("expected evaluator input register is live")
}

fn independent_stable_target_values(aggregate_scores: &[u64], top_count: usize) -> [Vec<u64>; 2] {
    assert_eq!(aggregate_scores.len(), ORACLE_OPTION_COUNT);
    assert!((1..=ORACLE_OPTION_COUNT).contains(&top_count));
    let mut option_ordinals = (0..ORACLE_OPTION_COUNT).collect::<Vec<_>>();
    option_ordinals.sort_by(|left_ordinal, right_ordinal| {
        aggregate_scores[*right_ordinal].cmp(&aggregate_scores[*left_ordinal])
    });
    for adjacent in option_ordinals.windows(2) {
        let left_ordinal = adjacent[0];
        let right_ordinal = adjacent[1];
        assert!(aggregate_scores[left_ordinal] >= aggregate_scores[right_ordinal]);
        if aggregate_scores[left_ordinal] == aggregate_scores[right_ordinal] {
            assert!(left_ordinal < right_ordinal, "stable tie order changed");
        }
    }

    let mut identifiers = vec![0_u64; ORACLE_OPTION_COUNT];
    let mut order = vec![0_u64; ORACLE_OPTION_COUNT];
    for (rank_ordinal, option_ordinal) in option_ordinals.into_iter().enumerate() {
        if rank_ordinal >= top_count {
            continue;
        }
        identifiers[option_ordinal] =
            u64::try_from(option_ordinal + 1).expect("selected option identifier fits u64");
        order[option_ordinal] =
            u64::try_from(rank_ordinal + 1).expect("selected stable rank fits u64");
    }
    [identifiers, order]
}

fn encrypted_semantic_cases() -> Vec<EncryptedSemanticCase> {
    let mut cases = vec![
        EncryptedSemanticCase {
            name: "all equal".to_owned(),
            aggregate_scores: vec![7; ORACLE_OPTION_COUNT],
            ballot_count: 1,
            top_counts: (1..=ORACLE_OPTION_COUNT).collect(),
            calibrate_product_error: true,
            calibrate_evaluator_error: true,
        },
        EncryptedSemanticCase {
            name: "strict increasing".to_owned(),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .map(|score| u64::try_from(score).unwrap())
                .collect(),
            ballot_count: 9,
            top_counts: vec![7],
            calibrate_product_error: true,
            calibrate_evaluator_error: false,
        },
        EncryptedSemanticCase {
            name: "strict decreasing".to_owned(),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .rev()
                .map(|score| u64::try_from(score).unwrap())
                .collect(),
            ballot_count: 9,
            top_counts: vec![13],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        },
        EncryptedSemanticCase {
            name: "zero and ninety boundary".to_owned(),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .map(|option_ordinal| if option_ordinal % 2 == 0 { 0 } else { 90 })
                .collect(),
            ballot_count: 10,
            top_counts: vec![10],
            calibrate_product_error: true,
            calibrate_evaluator_error: false,
        },
    ];

    for ballot_count in 2..=8 {
        let aggregate_score_modulus = 9 * ballot_count + 1;
        cases.push(EncryptedSemanticCase {
            name: format!("product composition with {ballot_count} ballots"),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .map(|option_ordinal| {
                    u64::try_from(option_ordinal * (ballot_count + 1) % aggregate_score_modulus)
                        .unwrap()
                })
                .collect(),
            ballot_count,
            top_counts: vec![2 * ballot_count],
            calibrate_product_error: true,
            calibrate_evaluator_error: false,
        });
    }

    for winner_ordinal in 1..ORACLE_OPTION_COUNT - 1 {
        let loser_ordinal = if winner_ordinal + 1 == ORACLE_OPTION_COUNT - 1 {
            1
        } else {
            winner_ordinal + 1
        };
        let mut unique_extremes = vec![45; ORACLE_OPTION_COUNT];
        unique_extremes[winner_ordinal] = 90;
        unique_extremes[loser_ordinal] = 0;
        cases.push(EncryptedSemanticCase {
            name: format!("unique winner {winner_ordinal} and loser {loser_ordinal}"),
            aggregate_scores: unique_extremes,
            ballot_count: 10,
            top_counts: vec![winner_ordinal + 1],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        });
    }

    for top_count in 1..ORACLE_OPTION_COUNT {
        let tie_count = top_count + 1;
        let mut aggregate_scores = (0..ORACLE_OPTION_COUNT)
            .map(|option_ordinal| u64::try_from(ORACLE_OPTION_COUNT - option_ordinal).unwrap())
            .collect::<Vec<_>>();
        aggregate_scores[..tie_count].fill(60);
        cases.push(EncryptedSemanticCase {
            name: format!("tie at top count {top_count} with multiplicity {tie_count}"),
            aggregate_scores,
            ballot_count: 10,
            top_counts: vec![top_count],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        });
    }

    let mut seed = 0x5eed_5eed_cafe_babe_u64;
    for case_ordinal in 0..8 {
        let aggregate_scores = (0..ORACLE_OPTION_COUNT)
            .map(|_| {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                seed % 91
            })
            .collect();
        cases.push(EncryptedSemanticCase {
            name: format!("seeded adversarial {case_ordinal}"),
            aggregate_scores,
            ballot_count: 10,
            top_counts: vec![case_ordinal * 2 + 3],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        });
    }
    cases
}

fn assert_active_lane_boundaries_across_both_ciphertexts() {
    let aggregate_inputs = semantic_oracle::aggregate_character_inputs(&[0; ORACLE_OPTION_COUNT]);
    let assignments = semantic_oracle::pair_assignments();
    for (ciphertext_ordinal, aggregate_input) in aggregate_inputs.iter().enumerate() {
        let occupied_lanes = assignments
            .iter()
            .filter(|assignment| assignment.ciphertext_ordinal == ciphertext_ordinal)
            .map(|assignment| assignment.lane_ordinal)
            .collect::<BTreeSet<_>>();
        let first_lane = *occupied_lanes
            .first()
            .expect("each pair-character ciphertext has an active first lane");
        let last_lane = *occupied_lanes
            .last()
            .expect("each pair-character ciphertext has an active last lane");
        for lane_ordinal in [first_lane, last_lane] {
            assert!(
                aggregate_input[lane_ordinal]
                    .iter()
                    .any(|coordinate| *coordinate != 0),
                "pair-character ciphertext {ciphertext_ordinal} boundary lane {lane_ordinal} is inactive"
            );
        }
    }
}

fn assert_scalar_target(
    target: &OracleRingValue,
    expected_values: &[u64],
    case_name: &str,
    top_count: usize,
    target_name: &str,
) {
    assert_eq!(target.len(), ORACLE_LANE_COUNT);
    assert_eq!(expected_values.len(), ORACLE_OPTION_COUNT);
    for (lane_ordinal, lane) in target.iter().enumerate() {
        let expected_value = expected_values.get(lane_ordinal).copied().unwrap_or(0);
        assert_eq!(
            lane[0], expected_value,
            "{target_name} drifted for {case_name}, top count {top_count}, lane {lane_ordinal}"
        );
        assert!(
            lane[1..].iter().all(|coordinate| *coordinate == 0),
            "{target_name} stopped being scalar for {case_name}, top count {top_count}, lane {lane_ordinal}"
        );
    }
}
