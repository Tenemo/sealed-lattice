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

    let ordered_option_positions = circuit
        .ordered_option_position_wires
        .iter()
        .map(|position_wires| {
            position_wires.iter().copied().enumerate().try_fold(
                0_u16,
                |position, (bit_position, wire)| {
                    Ok(position | u16::from(read_wire(&wire_values, wire)?) << bit_position)
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let accepted_ballot_authorship = circuit
        .participant_selected_wires
        .iter()
        .copied()
        .map(|wire| read_wire(&wire_values, wire))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(TallyEvaluationOutcome {
        accepted_ballot_authorship,
        ordered_option_positions,
        has_selected_ballot: read_wire(&wire_values, circuit.nonempty_output_wire)?,
    })
}

pub(crate) fn interpret_boolean_operations(
    circuit: &CompiledTallyCircuit,
    input_bits: &[bool],
) -> Result<Vec<bool>, TallyCircuitError> {
    let expected_input_bit_count = circuit.input_bit_count;
    if input_bits.len() != expected_input_bit_count {
        return Err(TallyCircuitError::InputBitCountMismatch {
            expected: expected_input_bit_count,
            actual: input_bits.len(),
        });
    }

    let mut wire_values = Vec::with_capacity(circuit.input_bit_count + circuit.operations.len());
    wire_values.extend_from_slice(input_bits);
    for operation in &circuit.operations {
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
    let participant_count = usize::from(circuit.profile.participant_count);
    let participant_ballots = &input.participant_ballots;
    if participant_ballots.len() != participant_count {
        return Err(TallyCircuitError::InputParticipantCountMismatch {
            expected: participant_count,
            actual: participant_ballots.len(),
        });
    }

    let option_count = usize::from(circuit.profile.option_count);
    let score_bit_width = circuit.score_bit_width;
    let maximum_score_encoding = (1_usize << score_bit_width) - 1;
    let mut input_bits = Vec::with_capacity(circuit.input_bit_count);
    for (participant_position, ballot) in participant_ballots.iter().enumerate() {
        if ballot.score_encodings.len() != option_count {
            return Err(TallyCircuitError::InputOptionCountMismatch {
                participant_position,
                expected: option_count,
                actual: ballot.score_encodings.len(),
            });
        }
        input_bits.push(ballot.is_present);
        for (option_position, score_encoding) in ballot.score_encodings.iter().copied().enumerate()
        {
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
