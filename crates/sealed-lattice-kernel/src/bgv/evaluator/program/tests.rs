use super::*;

fn small_valid_program_set() -> EvaluatorProgramSet {
    let constant = EvaluatorConstant::new(EvaluatorConstantKind::CoefficientVector, vec![1])
        .expect("small coefficient constant");
    let constant_hash = constant.constant_hash().expect("constant hash");
    let instructions = vec![
        EvaluatorInstruction::new(
            EvaluatorOpcode::ModulusSwitchToLevel,
            Some(1),
            vec![0],
            1,
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
        &[SELECTED_EVALUATOR_WORKING_LEVEL]
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
    assert_eq!(expected_galois_positions.len(), 16);
    assert_eq!(
        positions.galois_catalog_positions(),
        expected_galois_positions
    );
    assert_eq!(positions.streams().len(), 20);
    for (stream_index, stream_positions) in positions.streams().iter().enumerate() {
        assert_eq!(usize::from(stream_positions.top_count()), stream_index + 1);
        assert_eq!(
            stream_positions.relinearization_catalog_levels(),
            &[SELECTED_EVALUATOR_WORKING_LEVEL]
        );
        assert_eq!(
            stream_positions.galois_catalog_positions(),
            expected_galois_positions
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
fn validation_refuses_noncanonical_constants_and_terminal_state_drift() {
    let mut noncanonical_constant = small_valid_program_set();
    noncanonical_constant.constants[0].values[0] =
        u32::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits u32");
    assert!(noncanonical_constant.validate().is_err());

    let mut terminal_level_drift = small_valid_program_set();
    for stream in &mut terminal_level_drift.streams {
        stream.instructions[0].immediate0 = 2;
    }
    assert!(terminal_level_drift.validate().is_err());
}
