use super::*;
use crate::{
    bgv::{
        direct_ballots::direct_ballot_slots,
        evaluator::{
            engine::{DevelopmentBgvKey, modulus_switch_to, normalize_scaling},
            key_switch::generate_relinearization_key,
            top_k::DIRECT_COMPARISON_OUTPUT_LEVEL,
        },
        proof_suite::{
            ComponentMaterialOwnershipBinding, KeySwitchComponentMaterialTopology,
            SelectedEvaluatorEntryKind, SelectedEvaluatorEntryPosition, VerifiedEvaluatorKeyStore,
            VerifiedEvaluatorKeyStoreMaterial, VerifiedEvaluatorKeyStoreMaterialStream,
            selected_evaluator_entry_positions,
        },
        setup::{
            deterministic_galois_runtime_component_bytes_for_tests,
            release_verified_accepted_setup_authority,
            retain_evaluator_execution_authority_for_tests,
        },
    },
    foundation::{
        CanonicalStreamDomain, FOUNDATION_PROFILE, SelectedSuiteCapability, StreamDescriptor,
        derive_canonical_stream_descriptor, selected_suite_capability_for_tests,
    },
};

struct EvaluatorStoreFixture {
    bytes: Vec<u8>,
    ordered_component_descriptors: Vec<StreamDescriptor>,
}

#[derive(Clone, Copy)]
struct ExecutorTestContext {
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    manifest_hash: [u8; 64],
    roster_hash: [u8; 64],
    setup_proof_context_hash: [u8; 64],
    verified_setup_source_hash: [u8; 64],
    verified_aggregate_source_hash: [u8; 64],
    public_setup_seed: [u8; 64],
}

impl ExecutorTestContext {
    const fn new(suite_identifier: [u8; 64]) -> Self {
        Self {
            suite_identifier,
            ceremony_context_hash: [0x22; 64],
            action_context_hash: [0x33; 64],
            manifest_hash: [0x34; 64],
            roster_hash: [0x44; 64],
            setup_proof_context_hash: [0x45; 64],
            verified_setup_source_hash: [0x55; 64],
            verified_aggregate_source_hash: [0x66; 64],
            public_setup_seed: [0x77; 64],
        }
    }
}

fn selected_catalog_level(position: SelectedEvaluatorEntryPosition) -> usize {
    match position.key_kind() {
        SelectedEvaluatorEntryKind::Relinearization { catalog_level }
        | SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
    }
}

fn append_evaluator_store_component(
    store_bytes: &mut Vec<u8>,
    ordered_component_descriptors: &mut Vec<StreamDescriptor>,
    component_bytes: Vec<u8>,
) {
    ordered_component_descriptors.push(
        derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyStore,
            &component_bytes,
        )
        .expect("evaluator-store component descriptor derives"),
    );
    store_bytes.extend_from_slice(&component_bytes);
}

fn evaluator_store_fixture(
    selected_suite: &SelectedSuiteCapability,
    development_key: &DevelopmentBgvKey,
    public_setup_seed: &[u8; 64],
) -> EvaluatorStoreFixture {
    let positions = selected_evaluator_entry_positions(1)
        .expect("selected evaluator positions derive for the suite-fixed catalog");
    let expected_store_byte_length = positions
        .iter()
        .try_fold(0_u64, |total_byte_length, position| {
            let component_byte_length =
                KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                    selected_suite,
                    selected_catalog_level(*position),
                )
                .expect("selected component topology derives")
                .expected_byte_length();
            let physical_component_count = if matches!(
                position.key_kind(),
                SelectedEvaluatorEntryKind::Relinearization { .. }
            ) {
                2_u64
            } else {
                1_u64
            };
            total_byte_length.checked_add(
                component_byte_length
                    .checked_mul(physical_component_count)
                    .expect("selected physical component length fits u64"),
            )
        })
        .expect("selected evaluator store length fits u64");
    let mut store_bytes = Vec::with_capacity(
        usize::try_from(expected_store_byte_length)
            .expect("selected evaluator store length fits usize"),
    );
    let mut ordered_component_descriptors = Vec::with_capacity(positions.len() + 1);
    let relinearization_key = generate_relinearization_key(
        development_key,
        SELECTED_RELINEARIZATION_KEY_LEVEL,
        "production-executor-relinearization-key",
    )
    .expect("development relinearization key derives");
    let mut observed_relinearization_position = false;
    for position in positions {
        match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { .. } => {
                assert!(
                    !core::mem::replace(&mut observed_relinearization_position, true),
                    "the selected store contains one relinearization position"
                );
                append_evaluator_store_component(
                    &mut store_bytes,
                    &mut ordered_component_descriptors,
                    relinearization_key
                        .runtime_component_canonical_bytes()
                        .expect("relinearization runtime bytes encode canonically"),
                );
                append_evaluator_store_component(
                    &mut store_bytes,
                    &mut ordered_component_descriptors,
                    relinearization_key
                        .auxiliary_component_canonical_bytes()
                        .expect("relinearization auxiliary bytes encode canonically"),
                );
            }
            SelectedEvaluatorEntryKind::Galois { .. } => {
                append_evaluator_store_component(
                    &mut store_bytes,
                    &mut ordered_component_descriptors,
                    deterministic_galois_runtime_component_bytes_for_tests(
                        selected_suite,
                        position,
                        development_key.secret(),
                        public_setup_seed,
                    )
                    .expect("suite-derived Galois runtime bytes construct"),
                );
            }
        }
    }
    assert!(observed_relinearization_position);
    assert_eq!(
        store_bytes.len(),
        usize::try_from(expected_store_byte_length).expect("store length fits usize")
    );
    assert_eq!(ordered_component_descriptors.len(), 5);
    EvaluatorStoreFixture {
        bytes: store_bytes,
        ordered_component_descriptors,
    }
}

fn authenticated_evaluator_store_material(
    selected_suite: &SelectedSuiteCapability,
    context: ExecutorTestContext,
    top_count: u16,
    fixture: &EvaluatorStoreFixture,
) -> VerifiedEvaluatorKeyStoreMaterial {
    let store_descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::EvaluatorKeyStore,
        &fixture.bytes,
    )
    .expect("complete evaluator-store descriptor derives");
    let ownership_binding = ComponentMaterialOwnershipBinding::from_verified_application(
        context.suite_identifier,
        context.action_context_hash,
        [0x88; 64],
    );
    let mut material_stream = VerifiedEvaluatorKeyStoreMaterialStream::begin(
        selected_suite,
        ownership_binding,
        top_count,
        store_descriptor,
        fixture.ordered_component_descriptors.clone(),
    )
    .expect("selected evaluator-store material stream begins");
    for (chunk_index, chunk_bytes) in fixture
        .bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        material_stream
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .expect("evaluator-store chunk authenticates");
    }
    material_stream
        .finish()
        .into_result()
        .expect("complete evaluator-store material authenticates")
}

fn expected_sparse_targets(
    aggregate_scores: &[u64; SELECTED_OPTION_COUNT],
    top_count: u16,
) -> ([u64; SELECTED_OPTION_COUNT], [u64; SELECTED_OPTION_COUNT]) {
    let mut ranked_option_indices = (0..SELECTED_OPTION_COUNT).collect::<Vec<_>>();
    ranked_option_indices.sort_by(|left_option_index, right_option_index| {
        aggregate_scores[*right_option_index]
            .cmp(&aggregate_scores[*left_option_index])
            .then_with(|| left_option_index.cmp(right_option_index))
    });
    let mut option_ranks = [0_usize; SELECTED_OPTION_COUNT];
    for (rank, option_index) in ranked_option_indices.into_iter().enumerate() {
        option_ranks[option_index] = rank;
    }
    let mut target_identifiers = [0_u64; SELECTED_OPTION_COUNT];
    let mut target_orders = [0_u64; SELECTED_OPTION_COUNT];
    for (option_index, rank) in option_ranks.into_iter().enumerate() {
        if rank < usize::from(top_count) {
            target_identifiers[option_index] =
                u64::try_from(option_index + 1).expect("option identifier fits u64");
            target_orders[option_index] = u64::try_from(rank + 1).expect("target order fits u64");
        }
    }
    (target_identifiers, target_orders)
}

fn small_valid_program_set() -> EvaluatorProgramSet {
    let constant = EvaluatorConstant::new(EvaluatorConstantKind::CoefficientVector, vec![1])
        .expect("small coefficient constant");
    let constant_hash = constant.constant_hash().expect("constant hash");
    let instructions = vec![
        EvaluatorInstruction::new(
            EvaluatorOpcode::ModulusSwitchToLevel,
            Some(1),
            vec![0],
            u64::try_from(CANONICAL_TARGET_CIPHERTEXT_LEVEL).expect("target level fits u64"),
            0,
            None,
        )
        .expect("switch instruction"),
        EvaluatorInstruction::new(EvaluatorOpcode::DropRegister, None, vec![0], 0, 0, None)
            .expect("input drop"),
        EvaluatorInstruction::new(
            EvaluatorOpcode::PlaintextMultiply,
            Some(2),
            vec![1],
            0,
            0,
            Some(constant_hash),
        )
        .expect("identifier copy"),
        EvaluatorInstruction::new(
            EvaluatorOpcode::PlaintextMultiply,
            Some(3),
            vec![1],
            0,
            0,
            Some(constant_hash),
        )
        .expect("order copy"),
        EvaluatorInstruction::new(EvaluatorOpcode::DropRegister, None, vec![1], 0, 0, None)
            .expect("switched input drop"),
        EvaluatorInstruction::new(EvaluatorOpcode::DeclareOutput, None, vec![2], 1, 0, None)
            .expect("identifier declaration"),
        EvaluatorInstruction::new(EvaluatorOpcode::DeclareOutput, None, vec![3], 2, 0, None)
            .expect("order declaration"),
    ];
    let streams = (1..=SELECTED_STREAM_COUNT)
        .map(|top_count| {
            EvaluatorInstructionStream::new(
                u16::try_from(top_count).expect("top count fits u16"),
                instructions.clone(),
            )
            .expect("small stream")
        })
        .collect();
    EvaluatorProgramSet::new(vec![constant], streams).expect("small valid program")
}

#[test]
fn selected_program_round_trips_and_uses_the_exact_compact_key_catalog() {
    let program = selected_evaluator_program_set().expect("selected evaluator program");
    let encoded = program.encode().expect("selected program bytes");
    let decoded = EvaluatorProgramSet::decode(&encoded).expect("selected program decodes");
    assert_eq!(decoded, program);
    assert_eq!(decoded.streams().len(), 20);
    assert_eq!(decoded.streams()[0].top_count(), 1);
    assert_eq!(decoded.streams()[19].top_count(), 20);
    assert!(
        decoded
            .constants()
            .iter()
            .any(|constant| constant.kind() == EvaluatorConstantKind::SlotVector)
    );
    assert!(decoded.constants().iter().all(|constant| {
        constant.kind() != EvaluatorConstantKind::SlotVector
            || constant.values().len() == POLYNOMIAL_DEGREE
    }));

    let positions = decoded.key_positions().expect("validated key positions");
    assert_eq!(
        positions.relinearization_catalog_levels(),
        &[SELECTED_RELINEARIZATION_KEY_LEVEL]
    );
    let expected_galois_positions = selected_evaluator_rotation_key_schedule(20)
        .expect("selected rotation schedule")
        .into_iter()
        .map(
            |(galois_element, catalog_level)| EvaluatorGaloisKeyPosition {
                galois_element,
                catalog_level,
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(expected_galois_positions.len(), 3);
    assert_eq!(
        positions.galois_catalog_positions(),
        expected_galois_positions
    );
    assert_eq!(positions.streams().len(), 20);
    for (stream_index, stream_positions) in positions.streams().iter().enumerate() {
        assert_eq!(usize::from(stream_positions.top_count()), stream_index + 1);
        assert_eq!(
            stream_positions.relinearization_catalog_levels(),
            &[SELECTED_RELINEARIZATION_KEY_LEVEL]
        );
        assert_eq!(
            stream_positions.galois_catalog_positions(),
            expected_galois_positions
        );
    }
}

#[test]
fn selected_streams_use_canonical_pair_differences_and_the_exact_directed_rotations() {
    const PAIR_COUNT: usize = SELECTED_OPTION_COUNT * (SELECTED_OPTION_COUNT - 1) / 2;

    let program = selected_evaluator_program_set().expect("selected evaluator program");
    let constant_kinds_by_hash = program
        .validated_constant_catalog()
        .expect("selected constant catalog validates");
    let scheduled_galois_levels = selected_evaluator_rotation_key_schedule(SELECTED_OPTION_COUNT)
        .expect("selected Galois schedule")
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    for stream in program.streams() {
        let operative_instructions = stream
            .instructions()
            .iter()
            .filter(|instruction| instruction.opcode != EvaluatorOpcode::DropRegister)
            .collect::<Vec<_>>();
        let pair_shift_instruction = operative_instructions[0];
        assert_eq!(pair_shift_instruction.opcode, EvaluatorOpcode::PlaintextAdd);
        let pair_shift = program
            .constants()
            .iter()
            .find(|constant| {
                Some(constant.constant_hash().expect("constant hash"))
                    == pair_shift_instruction.constant_hash
            })
            .expect("pair shift constant");
        assert!(
            pair_shift.values()[..PAIR_COUNT]
                .iter()
                .all(|value| *value == 90)
        );
        assert!(
            pair_shift.values()[PAIR_COUNT..]
                .iter()
                .all(|value| *value == 0)
        );
        assert!(
            stream
                .instructions()
                .iter()
                .all(|instruction| instruction.opcode != EvaluatorOpcode::CiphertextSubtract)
        );

        let galois_instructions = stream
            .instructions()
            .iter()
            .filter(|instruction| instruction.opcode == EvaluatorOpcode::GaloisRotate)
            .collect::<Vec<_>>();
        assert_eq!(galois_instructions.len(), 211);
        assert_eq!(
            galois_instructions
                .iter()
                .map(|instruction| instruction.immediate0)
                .collect::<BTreeSet<_>>(),
            [7_971_u64, 43_691, 130_393].into_iter().collect()
        );

        let mut register_states = vec![Some(RegisterState {
            level: SELECTED_EVALUATOR_WORKING_LEVEL,
            decryption_multiplier: 1,
        })];
        for instruction in stream.instructions() {
            if instruction.opcode == EvaluatorOpcode::DropRegister {
                let register_index = usize::try_from(instruction.input_registers[0])
                    .expect("register number fits usize");
                register_states[register_index] = None;
                continue;
            }
            let input_states = instruction
                .input_registers
                .iter()
                .map(|register| read_live_register(&register_states, *register))
                .collect::<CanonicalResult<Vec<_>>>()
                .expect("compiled input states remain live");
            if instruction.opcode == EvaluatorOpcode::GaloisRotate {
                assert_eq!(input_states[0].level, DIRECT_COMPARISON_OUTPUT_LEVEL);
            }
            let output_state = evaluate_instruction_transition(
                instruction,
                &input_states,
                &constant_kinds_by_hash,
                &scheduled_galois_levels,
            )
            .expect("compiled transition validates");
            if instruction.opcode.produces_register() {
                register_states.push(output_state);
            }
        }
    }
}

#[test]
fn prepared_execution_schedules_keep_canonical_order_and_account_every_top_count() {
    let program = selected_evaluator_program_set().expect("selected evaluator program");
    let canonical_program_bytes = program.encode().expect("selected program encodes");
    let mut observed_accounting = Vec::with_capacity(program.streams().len());

    for stream in program.streams() {
        let schedule = PreparedEvaluatorExecutionSchedule::derive(stream.instructions())
            .expect("prepared evaluator schedule derives from canonical instructions");
        let accounting = schedule.accounting();
        let expected_key_operation_count = stream
            .instructions()
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction.opcode(),
                    EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                        | EvaluatorOpcode::CiphertextMultiplyAndRelinearize
                        | EvaluatorOpcode::GaloisRotate
                )
            })
            .count();
        assert_eq!(
            accounting.key_operation_count(),
            expected_key_operation_count
        );
        assert!(accounting.key_load_count() < accounting.key_operation_count());
        assert!(accounting.key_store_read_byte_count() > 0);
        assert!(accounting.key_store_reread_byte_count() > 0);
        assert!(accounting.key_ntt_transform_count() > 0);
        assert!(accounting.maximum_live_ciphertext_count() <= MAXIMUM_LIVE_REGISTER_COUNT);

        for (instruction_ordinal, instruction) in stream.instructions().iter().enumerate() {
            let required_key = schedule
                .required_key(instruction_ordinal)
                .expect("canonical instruction has a prepared key entry");
            match instruction.opcode() {
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => assert_eq!(
                    required_key,
                    Some(PreparedEvaluatorKeyIdentity::Relinearization {
                        catalog_level: SELECTED_RELINEARIZATION_KEY_LEVEL,
                    })
                ),
                EvaluatorOpcode::GaloisRotate => {
                    let PreparedEvaluatorKeyIdentity::Galois {
                        galois_element,
                        catalog_level,
                    } = required_key.expect("rotation has a prepared Galois key")
                    else {
                        panic!("rotation prepared the wrong evaluator-key role");
                    };
                    assert_eq!(
                        galois_element,
                        usize::try_from(instruction.immediate0())
                            .expect("Galois element fits usize")
                    );
                    assert_eq!(catalog_level, DIRECT_COMPARISON_OUTPUT_LEVEL);
                }
                _ => assert_eq!(required_key, None),
            }
        }
        observed_accounting.push(accounting);
    }

    println!("prepared evaluator accounting: {observed_accounting:#?}");
    assert_eq!(
        program.encode().expect("selected program re-encodes"),
        canonical_program_bytes,
        "the prepared schedule must remain an internal derivative of canonical bytes"
    );
}

#[test]
fn pair_window_tile_width_screen_reports_exact_prepared_schedule_costs() {
    for pair_window_tile_width in 1..=10 {
        let program =
            selected_evaluator_program_set_with_pair_window_tile_width(pair_window_tile_width)
                .expect("candidate pair-window program compiles");
        let mut minimum_instruction_count = usize::MAX;
        let mut maximum_instruction_count = 0_usize;
        let mut maximum_accounting = SelectedEvaluatorExecutionAccounting::default();
        let mut maximum_peak = None;
        let mut maximum_peak_top_count = 0_u16;

        for stream in program.streams() {
            minimum_instruction_count = minimum_instruction_count.min(stream.instructions().len());
            maximum_instruction_count = maximum_instruction_count.max(stream.instructions().len());
            let schedule = PreparedEvaluatorExecutionSchedule::derive(stream.instructions())
                .expect("candidate prepared schedule derives");
            let accounting = schedule.accounting();
            if accounting.maximum_live_ciphertext_coefficient_byte_count()
                > maximum_accounting.maximum_live_ciphertext_coefficient_byte_count()
            {
                maximum_accounting = accounting;
                maximum_peak = Some(schedule.liveness_peak());
                maximum_peak_top_count = stream.top_count();
            }
        }

        let maximum_peak = maximum_peak.expect("candidate program has a liveness peak");
        let maximum_peak_stream = program
            .streams()
            .iter()
            .find(|stream| stream.top_count() == maximum_peak_top_count)
            .expect("peak stream is present");
        println!(
            "pair-window width {pair_window_tile_width}: instructions={minimum_instruction_count}..={maximum_instruction_count}, accounting={maximum_accounting:?}, peak_top_count={maximum_peak_top_count}, peak={maximum_peak:?}, peak_instruction={:?}",
            maximum_peak_stream.instructions()[maximum_peak.instruction_ordinal]
        );
    }
}

#[test]
fn codec_round_trips_a_small_program_and_refuses_schema_and_count_mutations() {
    let program = small_valid_program_set();
    let encoded = program.encode().expect("small program bytes");
    assert_eq!(
        EvaluatorProgramSet::decode(&encoded).expect("small program decodes"),
        program
    );

    let mut wrong_schema = encoded.clone();
    wrong_schema[..2].copy_from_slice(&0x1505_u16.to_le_bytes());
    assert!(EvaluatorProgramSet::decode(&wrong_schema).is_err());

    let mut impossible_constant_count = encoded;
    let constants_list_count_offset = 8 + 6 + 2;
    impossible_constant_count[constants_list_count_offset..constants_list_count_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(EvaluatorProgramSet::decode(&impossible_constant_count).is_err());
}

#[test]
fn validation_refuses_missing_drops_register_gaps_and_wrong_output_order() {
    let mut missing_drop = small_valid_program_set();
    for stream in &mut missing_drop.streams {
        stream.instructions.remove(1);
    }
    assert!(missing_drop.validate().is_err());

    let mut register_gap = small_valid_program_set();
    for stream in &mut register_gap.streams {
        stream.instructions[0].output_register = Some(2);
    }
    assert!(register_gap.validate().is_err());

    let mut reversed_outputs = small_valid_program_set();
    for stream in &mut reversed_outputs.streams {
        let instruction_count = stream.instructions.len();
        stream.instructions[instruction_count - 2].immediate0 = 2;
        stream.instructions[instruction_count - 1].immediate0 = 1;
    }
    assert!(reversed_outputs.validate().is_err());
}

#[test]
fn validation_refuses_unknown_or_wrong_kind_constants_and_unsupported_rotations() {
    let mut unknown_constant = small_valid_program_set();
    for stream in &mut unknown_constant.streams {
        stream.instructions[2].constant_hash = Some(Hash512::from_bytes([0x5a; 64]));
    }
    assert!(unknown_constant.validate().is_err());

    let mut wrong_constant_kind = small_valid_program_set();
    for stream in &mut wrong_constant_kind.streams {
        stream.instructions[2].opcode = EvaluatorOpcode::PlaintextAdd;
    }
    assert!(wrong_constant_kind.validate().is_err());

    let mut unsupported_rotation = small_valid_program_set();
    for stream in &mut unsupported_rotation.streams {
        stream.instructions[2].opcode = EvaluatorOpcode::GaloisRotate;
        stream.instructions[2].immediate0 = 2;
        stream.instructions[2].constant_hash = None;
    }
    assert!(unsupported_rotation.validate().is_err());
}

#[test]
fn validation_maps_a_lower_level_rotation_to_its_exact_catalog_level() {
    assert!(CANONICAL_TARGET_CIPHERTEXT_LEVEL <= DIRECT_COMPARISON_OUTPUT_LEVEL);
    let mut lower_level_rotation = small_valid_program_set();
    for stream in &mut lower_level_rotation.streams {
        stream.instructions[2].opcode = EvaluatorOpcode::GaloisRotate;
        stream.instructions[2].immediate0 = 7_971;
        stream.instructions[2].constant_hash = None;
    }
    lower_level_rotation
        .validate()
        .expect("a lower CRT prefix can consume the selected catalog key");
    assert_eq!(
        lower_level_rotation
            .key_positions()
            .expect("lower-level rotation positions validate")
            .galois_catalog_positions(),
        &[EvaluatorGaloisKeyPosition {
            galois_element: 7_971,
            catalog_level: DIRECT_COMPARISON_OUTPUT_LEVEL,
        }]
    );
}

#[test]
fn validation_refuses_noncanonical_constants_and_terminal_state_drift() {
    let mut noncanonical_constant = small_valid_program_set();
    noncanonical_constant.constants[0].values[0] =
        u32::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits u32");
    assert!(noncanonical_constant.validate().is_err());

    let mut terminal_level_drift = small_valid_program_set();
    for stream in &mut terminal_level_drift.streams {
        stream.instructions[0].immediate0 = u64::try_from(
            CANONICAL_TARGET_CIPHERTEXT_LEVEL
                .checked_add(1)
                .expect("terminal drift level fits usize"),
        )
        .expect("terminal drift level fits u64");
    }
    assert!(terminal_level_drift.validate().is_err());
}

#[test]
#[ignore = "heavy Rust kernel evaluator test; run pnpm run test:rust:kernel:heavy"]
fn heavy_rust_kernel_production_executor_preserves_pairwise_tie_order_and_sparse_targets() {
    let selected_suite = selected_suite_capability_for_tests();
    let context = ExecutorTestContext::new(selected_suite.suite_identifier());
    let development_key = DevelopmentBgvKey::generate("production-executor-development-key")
        .expect("development key derives");
    let evaluator_store = evaluator_store_fixture(
        &selected_suite,
        &development_key,
        &context.public_setup_seed,
    );
    let cases = [
        (
            "one ballot with all ties and one retained target",
            [5_u64; 20],
            1_u16,
            1_u16,
        ),
        (
            "ten ballots with modular negatives and ties crossing a sparse cutoff",
            [7, 10, 4, 9, 7, 2, 8, 9, 1, 6, 7, 3, 9, 8, 6, 7, 4, 2, 1, 3],
            10,
            7,
        ),
        (
            "ten ballots at score extremes with one excluded target",
            [1, 10, 2, 9, 3, 8, 4, 7, 5, 6, 6, 5, 7, 4, 8, 3, 9, 2, 10, 1],
            10,
            19,
        ),
        (
            "one ballot with all ties and every retained target",
            [5_u64; 20],
            1,
            20,
        ),
    ];

    for (case_description, ballot_scores, ballot_count, top_count) in cases {
        let aggregate_scores = ballot_scores.map(|score| score * u64::from(ballot_count));
        let aggregate_pair_differences =
            direct_ballot_slots(&aggregate_scores, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE)
                .expect("aggregate pair-difference slots derive");
        let store_material = authenticated_evaluator_store_material(
            &selected_suite,
            context,
            top_count,
            &evaluator_store,
        );
        let proof_stream_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyAggregateProof,
            b"production executor authenticated-store fixture",
        )
        .expect("evaluator aggregate proof descriptor derives");
        let verified_store =
            VerifiedEvaluatorKeyStore::from_authenticated_material_for_executor_tests(
                context.suite_identifier,
                context.ceremony_context_hash,
                context.action_context_hash,
                context.manifest_hash,
                context.roster_hash,
                context.setup_proof_context_hash,
                proof_stream_descriptor,
                store_material,
            )
            .expect("authenticated evaluator store mints its post-proof test carrier");
        let accepted_setup_handle = retain_evaluator_execution_authority_for_tests(
            context.suite_identifier,
            context.ceremony_context_hash,
            context.action_context_hash,
            context.manifest_hash,
            context.roster_hash,
            context.setup_proof_context_hash,
            context.verified_setup_source_hash,
            context.public_setup_seed,
            development_key.public_key_components().0,
            verified_store,
        )
        .expect("accepted-setup executor authority retains authenticated store material");

        let full_level_aggregate = development_key
            .encrypt_slots(
                &aggregate_pair_differences,
                &format!("production-executor-aggregate-{top_count}"),
            )
            .expect("aggregate pair differences encrypt");
        let working_level_aggregate =
            modulus_switch_to(&full_level_aggregate, SELECTED_EVALUATOR_WORKING_LEVEL)
                .expect("aggregate reaches the selected evaluator level");
        let aggregate_ciphertext = normalize_scaling(&working_level_aggregate)
            .expect("aggregate decryption scaling normalizes");
        let aggregate_slots = development_key
            .decrypt_to_slots(&aggregate_ciphertext)
            .expect("working aggregate decrypts");
        assert_eq!(
            &aggregate_slots[..190],
            &aggregate_pair_differences[..190],
            "input pair-difference packing drifted for {case_description}"
        );
        assert!(
            aggregate_slots[190..].iter().all(|slot| *slot == 0),
            "input packing leaked outside the pair-difference slots for {case_description}"
        );
        let verified_aggregate = VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
            FOUNDATION_PROFILE.protocol_version,
            context.suite_identifier,
            context.ceremony_context_hash,
            context.action_context_hash,
            context.roster_hash,
            context.verified_setup_source_hash,
            context.verified_aggregate_source_hash,
            ballot_count,
            top_count,
            aggregate_ciphertext,
        )
        .expect("working aggregate mints verifier-owned evaluator input");
        let mut execution =
            SelectedEvaluatorProgramExecution::begin(verified_aggregate, &accepted_setup_handle)
                .expect("production evaluator execution begins");
        loop {
            match execution.advance().expect("production executor advances") {
                SelectedEvaluatorExecutionProgress::StoreReadRequired(request) => {
                    let store_byte_offset = usize::try_from(request.store_byte_offset())
                        .expect("store offset fits usize");
                    let store_byte_end = store_byte_offset
                        .checked_add(request.byte_length())
                        .expect("store range fits usize");
                    let requested_bytes = evaluator_store
                        .bytes
                        .get(store_byte_offset..store_byte_end)
                        .expect("executor requests an in-range authenticated store slice");
                    execution
                        .absorb_next_store_chunk(request.store_byte_offset(), requested_bytes)
                        .expect("executor authenticates and absorbs its requested store slice");
                }
                SelectedEvaluatorExecutionProgress::Complete => break,
            }
        }
        let observed_accounting = execution.execution_accounting();
        let (
            expected_key_operation_count,
            expected_key_load_count,
            expected_store_read_byte_count,
            expected_store_reread_byte_count,
            expected_ntt_transform_count,
        ) = if top_count == 20 {
            (247, 11, 325_320_704, 163_315_712, 1_198)
        } else {
            (259, 12, 417_333_248, 255_328_256, 1_396)
        };
        assert_eq!(
            observed_accounting.key_operation_count(),
            expected_key_operation_count,
            "key-operation accounting drifted for {case_description}"
        );
        assert_eq!(
            observed_accounting.key_load_count(),
            expected_key_load_count,
            "key-load accounting drifted for {case_description}"
        );
        assert_eq!(
            observed_accounting.key_store_read_byte_count(),
            expected_store_read_byte_count,
            "key-store traffic drifted for {case_description}"
        );
        assert_eq!(
            observed_accounting.key_store_reread_byte_count(),
            expected_store_reread_byte_count,
            "key-store reread traffic drifted for {case_description}"
        );
        assert_eq!(
            observed_accounting.key_ntt_transform_count(),
            expected_ntt_transform_count,
            "key NTT accounting drifted for {case_description}"
        );
        assert!(
            observed_accounting.maximum_live_ciphertext_count() <= MAXIMUM_LIVE_REGISTER_COUNT,
            "live ciphertext bound drifted for {case_description}"
        );
        let verified_execution = execution
            .finish()
            .expect("production evaluator execution finishes");
        assert_eq!(verified_execution.ballot_count(), ballot_count);
        assert_eq!(verified_execution.top_count(), top_count);
        let target_identifier_slots = development_key
            .decrypt_to_slots(verified_execution.target_identifier())
            .expect("target identifiers decrypt");
        let target_order_slots = development_key
            .decrypt_to_slots(verified_execution.target_order())
            .expect("target orders decrypt");
        release_verified_accepted_setup_authority(accepted_setup_handle)
            .expect("accepted-setup executor authority releases");

        let (expected_target_identifiers, expected_target_orders) =
            expected_sparse_targets(&aggregate_scores, top_count);
        assert_eq!(
            &target_identifier_slots[..SELECTED_OPTION_COUNT],
            expected_target_identifiers.as_slice(),
            "target identifiers drifted for {case_description}"
        );
        assert_eq!(
            &target_order_slots[..SELECTED_OPTION_COUNT],
            expected_target_orders.as_slice(),
            "target orders drifted for {case_description}"
        );
        assert!(
            target_identifier_slots[SELECTED_OPTION_COUNT..]
                .iter()
                .all(|slot| *slot == 0),
            "target identifiers leaked outside the option slots for {case_description}"
        );
        assert!(
            target_order_slots[SELECTED_OPTION_COUNT..]
                .iter()
                .all(|slot| *slot == 0),
            "target orders leaked outside the option slots for {case_description}"
        );
    }
}
