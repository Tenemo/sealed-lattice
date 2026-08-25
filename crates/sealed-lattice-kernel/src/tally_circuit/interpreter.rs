use super::{
    BooleanOperation, CompiledTallyCircuit, TALLY_BALLOT_ATTEMPT_COUNT, TallyCircuitError,
    TallyEvaluationInput, TallyEvaluationOutcome, WireIndex,
};

/// Evaluates the emitted sequential gate artifact without invoking the
/// compiler or direct evaluator.
pub(crate) fn evaluate_compiled_tally_circuit(
    circuit: &CompiledTallyCircuit,
    input: &TallyEvaluationInput,
) -> Result<TallyEvaluationOutcome, TallyCircuitError> {
    let input_bits = encode_tally_input_bits(circuit, input)?;
    let wire_values = interpret_boolean_operations(circuit, &input_bits)?;

    let ordered_option_positions = circuit
        .ordered_option_position_wires()
        .iter()
        .map(|position_wires| {
            position_wires.iter().copied().enumerate().try_fold(
                0_u16,
                |position, (bit_position, wire)| {
                    let bit_is_set = read_wire(&wire_values, wire)?;
                    if bit_is_set {
                        let bit_value = 1_u16
                            .checked_shl(
                                u32::try_from(bit_position)
                                    .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
                            )
                            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
                        position
                            .checked_add(bit_value)
                            .ok_or(TallyCircuitError::ArithmeticOverflow)
                    } else {
                        Ok(position)
                    }
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(TallyEvaluationOutcome {
        ordered_option_positions,
        has_selected_ballot: read_wire(&wire_values, circuit.nonempty_output_wire())?,
    })
}

pub(crate) fn interpret_boolean_operations(
    circuit: &CompiledTallyCircuit,
    input_bits: &[bool],
) -> Result<Vec<bool>, TallyCircuitError> {
    let expected_input_bit_count = circuit.geometry().input_bit_count;
    if input_bits.len() != expected_input_bit_count {
        return Err(TallyCircuitError::InputBitCountMismatch {
            expected: expected_input_bit_count,
            actual: input_bits.len(),
        });
    }

    let mut wire_values = Vec::with_capacity(circuit.geometry().total_wire_count);
    wire_values.extend_from_slice(input_bits);
    for operation in circuit.operations() {
        let output_value = match operation {
            BooleanOperation::Constant(value) => *value,
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            } => read_wire(&wire_values, *left_wire)? ^ read_wire(&wire_values, *right_wire)?,
            BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => read_wire(&wire_values, *left_wire)? & read_wire(&wire_values, *right_wire)?,
            BooleanOperation::Negation { input_wire } => !read_wire(&wire_values, *input_wire)?,
        };
        wire_values.push(output_value);
    }
    Ok(wire_values)
}

pub(super) fn encode_tally_input_bits(
    circuit: &CompiledTallyCircuit,
    input: &TallyEvaluationInput,
) -> Result<Vec<bool>, TallyCircuitError> {
    let participant_count = usize::from(circuit.profile().participant_count());
    let option_count = usize::from(circuit.profile().option_count());
    let participant_ballot_attempts = input.participant_ballot_attempts();
    if participant_ballot_attempts.len() != participant_count {
        return Err(TallyCircuitError::InputParticipantCountMismatch {
            expected: participant_count,
            actual: participant_ballot_attempts.len(),
        });
    }

    let score_bit_width = circuit.geometry().score_bit_width;
    let maximum_score_encoding = (1_usize << score_bit_width) - 1;
    let mut input_bits = Vec::with_capacity(circuit.geometry().input_bit_count);
    for (participant_position, ballot_attempts) in participant_ballot_attempts.iter().enumerate() {
        if ballot_attempts.len() != TALLY_BALLOT_ATTEMPT_COUNT {
            return Err(TallyCircuitError::InputBallotAttemptCountMismatch {
                participant_position,
                expected: TALLY_BALLOT_ATTEMPT_COUNT,
                actual: ballot_attempts.len(),
            });
        }
        for (attempt_position, ballot_attempt) in ballot_attempts.iter().enumerate() {
            if ballot_attempt.score_encodings().len() != option_count {
                return Err(TallyCircuitError::InputOptionCountMismatch {
                    participant_position,
                    attempt_position,
                    expected: option_count,
                    actual: ballot_attempt.score_encodings().len(),
                });
            }
            input_bits.push(ballot_attempt.is_present());
            for (option_position, score_encoding) in
                ballot_attempt.score_encodings().iter().copied().enumerate()
            {
                if usize::from(score_encoding) > maximum_score_encoding {
                    return Err(TallyCircuitError::ScoreEncodingOutOfRange {
                        participant_position,
                        attempt_position,
                        option_position,
                        score_encoding,
                    });
                }
                for bit_position in 0..score_bit_width {
                    input_bits.push(((usize::from(score_encoding) >> bit_position) & 1) == 1);
                }
            }
        }
    }
    Ok(input_bits)
}

pub(super) fn read_wire(wire_values: &[bool], wire: WireIndex) -> Result<bool, TallyCircuitError> {
    let wire_position =
        usize::try_from(wire).map_err(|_| TallyCircuitError::InvalidWireReference {
            wire,
            available_wire_count: wire_values.len(),
        })?;
    wire_values
        .get(wire_position)
        .copied()
        .ok_or(TallyCircuitError::InvalidWireReference {
            wire,
            available_wire_count: wire_values.len(),
        })
}
