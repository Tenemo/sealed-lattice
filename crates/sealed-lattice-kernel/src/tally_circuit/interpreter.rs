use super::{
    BooleanOperation, CompiledTallyCircuit, TallyCircuitError, TallyEvaluationInput,
    TallyEvaluationOutcome, WireIndex,
};

/// Evaluates the emitted sequential gate artifact without invoking the
/// compiler or direct evaluator.
pub(crate) fn evaluate_compiled_tally_circuit(
    circuit: &CompiledTallyCircuit,
    input: &TallyEvaluationInput,
) -> Result<TallyEvaluationOutcome, TallyCircuitError> {
    let input_bits = encode_tally_input_bits(circuit, input)?;
    let wire_values = interpret_boolean_operations(circuit, &input_bits)?;

    let participant_validity = circuit
        .participant_validity_wires()
        .iter()
        .map(|wire| read_wire(&wire_values, *wire))
        .collect::<Result<Vec<_>, _>>()?;
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
        participant_validity,
        ordered_option_positions,
        has_selected_ballot: input
            .participant_presence()
            .iter()
            .any(|is_present| *is_present),
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

fn encode_tally_input_bits(
    circuit: &CompiledTallyCircuit,
    input: &TallyEvaluationInput,
) -> Result<Vec<bool>, TallyCircuitError> {
    let participant_count = usize::from(circuit.profile().participant_count());
    let option_count = usize::from(circuit.profile().option_count());
    if input.participant_presence().len() != participant_count {
        return Err(TallyCircuitError::InputParticipantCountMismatch {
            expected: participant_count,
            actual: input.participant_presence().len(),
        });
    }
    if input.participant_scores().len() != participant_count {
        return Err(TallyCircuitError::InputParticipantCountMismatch {
            expected: participant_count,
            actual: input.participant_scores().len(),
        });
    }

    let score_bit_width = circuit.geometry().score_bit_width;
    let maximum_score_encoding = (1_usize << score_bit_width) - 1;
    let mut input_bits = Vec::with_capacity(circuit.geometry().input_bit_count);
    input_bits.extend_from_slice(input.participant_presence());

    for (participant_position, participant_scores) in input.participant_scores().iter().enumerate()
    {
        if participant_scores.len() != option_count {
            return Err(TallyCircuitError::InputOptionCountMismatch {
                participant_position,
                expected: option_count,
                actual: participant_scores.len(),
            });
        }
        for (option_position, score_encoding) in participant_scores.iter().copied().enumerate() {
            if usize::from(score_encoding) > maximum_score_encoding {
                return Err(TallyCircuitError::ScoreEncodingOutOfRange {
                    participant_position,
                    option_position,
                    score_encoding,
                });
            }
            for bit_position in 0..score_bit_width {
                input_bits.push(((usize::from(score_encoding) >> bit_position) & 1) == 1);
            }
        }
    }
    Ok(input_bits)
}

fn read_wire(wire_values: &[bool], wire: WireIndex) -> Result<bool, TallyCircuitError> {
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
