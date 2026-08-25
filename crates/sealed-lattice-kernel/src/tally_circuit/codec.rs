use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    foundation::FOUNDATION_PROFILE,
};

use super::{
    BooleanOperation, CompiledTallyCircuit, TALLY_BALLOT_ATTEMPT_COUNT,
    TALLY_CIRCUIT_ARTIFACT_MAGIC, TallyCircuitError, TallyCircuitProfile, WireIndex,
    compiler::{compile_tally_circuit, tally_circuit_compiler_identity},
    direct_evaluator::tally_direct_evaluator_identity,
};

pub(crate) const TALLY_CIRCUIT_ARTIFACT_VERSION: u64 = 2;

const CONSTANT_OPERATION_CODE: u8 = 0;
const EXCLUSIVE_OR_OPERATION_CODE: u8 = 1;
const CONJUNCTION_OPERATION_CODE: u8 = 2;
const NEGATION_OPERATION_CODE: u8 = 3;

pub(crate) fn encode_canonical_tally_circuit(
    circuit: &CompiledTallyCircuit,
) -> Result<Vec<u8>, TallyCircuitError> {
    validate_circuit_structure(circuit)?;
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, TALLY_CIRCUIT_ARTIFACT_MAGIC);
    append_varuint(&mut bytes, TALLY_CIRCUIT_ARTIFACT_VERSION);
    append_bytes(&mut bytes, &tally_circuit_compiler_identity()?);
    append_bytes(&mut bytes, &tally_direct_evaluator_identity()?);
    append_varuint(&mut bytes, u64::from(circuit.profile().participant_count()));
    append_varuint(&mut bytes, u64::from(circuit.profile().option_count()));
    append_varuint(&mut bytes, u64::from(circuit.profile().top_count()));
    append_varuint(
        &mut bytes,
        u64::try_from(TALLY_BALLOT_ATTEMPT_COUNT)
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    append_varuint(
        &mut bytes,
        u64::try_from(circuit.geometry().score_bit_width)
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    append_varuint(
        &mut bytes,
        u64::try_from(circuit.geometry().aggregate_score_bit_width)
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    append_varuint(
        &mut bytes,
        u64::try_from(circuit.geometry().option_position_bit_width)
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    encode_input_mapping(&mut bytes, circuit)?;

    append_varuint(
        &mut bytes,
        u64::try_from(circuit.operations().len())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    for operation in circuit.operations() {
        encode_operation(&mut bytes, operation);
    }

    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, u64::from(circuit.nonempty_output_wire()));
    append_varuint(
        &mut bytes,
        u64::try_from(circuit.ordered_option_position_wires().len())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    for position_wires in circuit.ordered_option_position_wires() {
        append_varuint(
            &mut bytes,
            u64::try_from(position_wires.len())
                .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
        );
        for wire in position_wires {
            append_varuint(&mut bytes, u64::from(*wire));
        }
    }

    enforce_artifact_byte_length(bytes.len())?;
    Ok(bytes)
}

pub(crate) fn decode_canonical_tally_circuit(
    bytes: &[u8],
) -> Result<CompiledTallyCircuit, TallyCircuitError> {
    enforce_artifact_byte_length(bytes.len())?;
    let mut reader = CanonicalReader::new(bytes);
    if reader.read_bytes()?.as_slice() != TALLY_CIRCUIT_ARTIFACT_MAGIC {
        return Err(TallyCircuitError::ArtifactMagicMismatch);
    }
    let version = reader.read_varuint()?;
    if version != TALLY_CIRCUIT_ARTIFACT_VERSION {
        return Err(TallyCircuitError::UnsupportedArtifactVersion { version });
    }
    if reader.read_bytes()?.as_slice() != tally_circuit_compiler_identity()? {
        return Err(TallyCircuitError::CompilerIdentityMismatch);
    }
    if reader.read_bytes()?.as_slice() != tally_direct_evaluator_identity()? {
        return Err(TallyCircuitError::DirectEvaluatorIdentityMismatch);
    }

    let profile = TallyCircuitProfile::new(
        read_u16(&mut reader)?,
        read_u16(&mut reader)?,
        read_u16(&mut reader)?,
    )?;
    let expected_circuit = compile_tally_circuit(profile)?;
    if read_usize(&mut reader)? != TALLY_BALLOT_ATTEMPT_COUNT {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    let score_bit_width = read_usize(&mut reader)?;
    let aggregate_score_bit_width = read_usize(&mut reader)?;
    let option_position_bit_width = read_usize(&mut reader)?;
    if score_bit_width != expected_circuit.geometry().score_bit_width
        || aggregate_score_bit_width != expected_circuit.geometry().aggregate_score_bit_width
        || option_position_bit_width != expected_circuit.geometry().option_position_bit_width
    {
        return Err(TallyCircuitError::CircuitMismatch);
    }

    let (ballot_attempt_presence_wires, ballot_attempt_score_wires) =
        decode_input_mapping(&mut reader, &expected_circuit)?;
    let operation_count = read_usize(&mut reader)?;
    if operation_count != expected_circuit.operations().len() {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    let mut operations = Vec::new();
    operations
        .try_reserve_exact(operation_count)
        .map_err(|_| TallyCircuitError::ArithmeticOverflow)?;
    for _operation_position in 0..operation_count {
        operations.push(decode_operation(&mut reader)?);
    }

    if read_usize(&mut reader)? != 1 {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    let nonempty_output_wire = read_wire_index(&mut reader)?;
    let result_position_count = read_usize(&mut reader)?;
    if result_position_count != expected_circuit.ordered_option_position_wires().len() {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    let mut ordered_option_position_wires = Vec::with_capacity(result_position_count);
    for _result_position in 0..result_position_count {
        let result_bit_count = read_usize(&mut reader)?;
        if result_bit_count != expected_circuit.geometry().option_position_bit_width {
            return Err(TallyCircuitError::CircuitMismatch);
        }
        ordered_option_position_wires.push(
            (0..result_bit_count)
                .map(|_| read_wire_index(&mut reader))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    if !reader.is_finished() {
        return Err(TallyCircuitError::CircuitMismatch);
    }

    let decoded_circuit = CompiledTallyCircuit {
        profile,
        geometry: expected_circuit.geometry(),
        operations,
        ballot_attempt_presence_wires,
        ballot_attempt_score_wires,
        nonempty_output_wire,
        ordered_option_position_wires,
    };
    validate_circuit_structure(&decoded_circuit)?;
    if decoded_circuit != expected_circuit {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    Ok(decoded_circuit)
}

fn encode_input_mapping(
    bytes: &mut Vec<u8>,
    circuit: &CompiledTallyCircuit,
) -> Result<(), TallyCircuitError> {
    append_varuint(
        bytes,
        u64::try_from(circuit.ballot_attempt_presence_wires().len())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    for (participant_presence_wires, participant_score_wires) in circuit
        .ballot_attempt_presence_wires()
        .iter()
        .zip(circuit.ballot_attempt_score_wires())
    {
        append_varuint(
            bytes,
            u64::try_from(participant_presence_wires.len())
                .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
        );
        for (presence_wire, attempt_score_wires) in participant_presence_wires
            .iter()
            .zip(participant_score_wires)
        {
            append_varuint(bytes, u64::from(*presence_wire));
            append_varuint(
                bytes,
                u64::try_from(attempt_score_wires.len())
                    .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
            );
            for score_wires in attempt_score_wires {
                append_varuint(
                    bytes,
                    u64::try_from(score_wires.len())
                        .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
                );
                for wire in score_wires {
                    append_varuint(bytes, u64::from(*wire));
                }
            }
        }
    }
    Ok(())
}

type BallotAttemptPresenceWires = Vec<Vec<WireIndex>>;
type BallotAttemptScoreWires = Vec<Vec<Vec<Vec<WireIndex>>>>;

fn decode_input_mapping(
    reader: &mut CanonicalReader<'_>,
    expected_circuit: &CompiledTallyCircuit,
) -> Result<(BallotAttemptPresenceWires, BallotAttemptScoreWires), TallyCircuitError> {
    let participant_count = read_usize(reader)?;
    if participant_count != expected_circuit.ballot_attempt_presence_wires().len() {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    let option_count = usize::from(expected_circuit.profile().option_count());
    let score_bit_width = expected_circuit.geometry().score_bit_width;
    let mut ballot_attempt_presence_wires = Vec::with_capacity(participant_count);
    let mut ballot_attempt_score_wires = Vec::with_capacity(participant_count);
    for _participant_position in 0..participant_count {
        let attempt_count = read_usize(reader)?;
        if attempt_count != TALLY_BALLOT_ATTEMPT_COUNT {
            return Err(TallyCircuitError::CircuitMismatch);
        }
        let mut participant_presence_wires = Vec::with_capacity(attempt_count);
        let mut participant_score_wires = Vec::with_capacity(attempt_count);
        for _attempt_position in 0..attempt_count {
            participant_presence_wires.push(read_wire_index(reader)?);
            if read_usize(reader)? != option_count {
                return Err(TallyCircuitError::CircuitMismatch);
            }
            let mut attempt_score_wires = Vec::with_capacity(option_count);
            for _option_position in 0..option_count {
                if read_usize(reader)? != score_bit_width {
                    return Err(TallyCircuitError::CircuitMismatch);
                }
                attempt_score_wires.push(
                    (0..score_bit_width)
                        .map(|_| read_wire_index(reader))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            participant_score_wires.push(attempt_score_wires);
        }
        ballot_attempt_presence_wires.push(participant_presence_wires);
        ballot_attempt_score_wires.push(participant_score_wires);
    }
    Ok((ballot_attempt_presence_wires, ballot_attempt_score_wires))
}

fn encode_operation(bytes: &mut Vec<u8>, operation: &BooleanOperation) {
    match operation {
        BooleanOperation::Constant(value) => {
            bytes.push(CONSTANT_OPERATION_CODE);
            bytes.push(u8::from(*value));
        }
        BooleanOperation::ExclusiveOr {
            left_wire,
            right_wire,
        } => {
            bytes.push(EXCLUSIVE_OR_OPERATION_CODE);
            append_varuint(bytes, u64::from(*left_wire));
            append_varuint(bytes, u64::from(*right_wire));
        }
        BooleanOperation::Conjunction {
            left_wire,
            right_wire,
        } => {
            bytes.push(CONJUNCTION_OPERATION_CODE);
            append_varuint(bytes, u64::from(*left_wire));
            append_varuint(bytes, u64::from(*right_wire));
        }
        BooleanOperation::Negation { input_wire } => {
            bytes.push(NEGATION_OPERATION_CODE);
            append_varuint(bytes, u64::from(*input_wire));
        }
    }
}

fn decode_operation(
    reader: &mut CanonicalReader<'_>,
) -> Result<BooleanOperation, TallyCircuitError> {
    let operation_code = reader.read_exact(1)?[0];
    match operation_code {
        CONSTANT_OPERATION_CODE => match reader.read_exact(1)?[0] {
            0 => Ok(BooleanOperation::Constant(false)),
            1 => Ok(BooleanOperation::Constant(true)),
            _ => Err(TallyCircuitError::CircuitMismatch),
        },
        EXCLUSIVE_OR_OPERATION_CODE => Ok(BooleanOperation::ExclusiveOr {
            left_wire: read_wire_index(reader)?,
            right_wire: read_wire_index(reader)?,
        }),
        CONJUNCTION_OPERATION_CODE => Ok(BooleanOperation::Conjunction {
            left_wire: read_wire_index(reader)?,
            right_wire: read_wire_index(reader)?,
        }),
        NEGATION_OPERATION_CODE => Ok(BooleanOperation::Negation {
            input_wire: read_wire_index(reader)?,
        }),
        _ => Err(TallyCircuitError::CircuitMismatch),
    }
}

fn validate_circuit_structure(circuit: &CompiledTallyCircuit) -> Result<(), TallyCircuitError> {
    let input_bit_count = circuit.geometry().input_bit_count;
    let participant_count = usize::from(circuit.profile().participant_count());
    let option_count = usize::from(circuit.profile().option_count());
    let score_bit_width = circuit.geometry().score_bit_width;
    if circuit.ballot_attempt_presence_wires().len() != participant_count
        || circuit.ballot_attempt_score_wires().len() != participant_count
    {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    for (participant_presence_wires, participant_score_wires) in circuit
        .ballot_attempt_presence_wires()
        .iter()
        .zip(circuit.ballot_attempt_score_wires())
    {
        if participant_presence_wires.len() != TALLY_BALLOT_ATTEMPT_COUNT
            || participant_score_wires.len() != TALLY_BALLOT_ATTEMPT_COUNT
            || participant_score_wires.iter().any(|attempt_score_wires| {
                attempt_score_wires.len() != option_count
                    || attempt_score_wires
                        .iter()
                        .any(|score_wires| score_wires.len() != score_bit_width)
            })
        {
            return Err(TallyCircuitError::CircuitMismatch);
        }
    }
    let mut mapped_input_wires = vec![false; input_bit_count];
    for input_wire in circuit
        .ballot_attempt_presence_wires()
        .iter()
        .flatten()
        .copied()
        .chain(circuit.private_score_input_wires())
    {
        let input_position =
            usize::try_from(input_wire).map_err(|_| TallyCircuitError::CircuitMismatch)?;
        let was_mapped = mapped_input_wires
            .get_mut(input_position)
            .ok_or(TallyCircuitError::CircuitMismatch)?;
        if *was_mapped {
            return Err(TallyCircuitError::CircuitMismatch);
        }
        *was_mapped = true;
    }
    if mapped_input_wires.iter().any(|was_mapped| !was_mapped) {
        return Err(TallyCircuitError::CircuitMismatch);
    }

    if circuit.ordered_option_position_wires().len() != usize::from(circuit.profile().top_count())
        || circuit
            .ordered_option_position_wires()
            .iter()
            .any(|position_wires| {
                position_wires.len() != circuit.geometry().option_position_bit_width
            })
    {
        return Err(TallyCircuitError::CircuitMismatch);
    }

    for (operation_position, operation) in circuit.operations().iter().enumerate() {
        let available_wire_count = input_bit_count
            .checked_add(operation_position)
            .ok_or(TallyCircuitError::ArithmeticOverflow)?;
        for wire in operation.referenced_wires() {
            if usize::try_from(wire).map_or(true, |wire| wire >= available_wire_count) {
                return Err(TallyCircuitError::InvalidWireReference {
                    wire,
                    available_wire_count,
                });
            }
        }
        if matches!(
            operation,
            BooleanOperation::Conjunction {
                left_wire,
                right_wire
            } if left_wire == right_wire
        ) {
            return Err(TallyCircuitError::CircuitMismatch);
        }
    }
    let total_wire_count = circuit.geometry().total_wire_count;
    for wire in core::iter::once(circuit.nonempty_output_wire()).chain(
        circuit
            .ordered_option_position_wires()
            .iter()
            .flatten()
            .copied(),
    ) {
        if usize::try_from(wire).map_or(true, |wire| wire >= total_wire_count) {
            return Err(TallyCircuitError::InvalidOutputWire {
                wire,
                total_wire_count,
            });
        }
    }
    Ok(())
}

fn enforce_artifact_byte_length(byte_length: usize) -> Result<(), TallyCircuitError> {
    let maximum_byte_length = FOUNDATION_PROFILE.maximum_copied_buffer_byte_length;
    if byte_length == 0 || byte_length > maximum_byte_length {
        return Err(TallyCircuitError::ArtifactTooLarge {
            byte_length,
            maximum_byte_length,
        });
    }
    Ok(())
}

fn read_u16(reader: &mut CanonicalReader<'_>) -> Result<u16, TallyCircuitError> {
    u16::try_from(reader.read_varuint()?).map_err(|_| TallyCircuitError::CircuitMismatch)
}

fn read_usize(reader: &mut CanonicalReader<'_>) -> Result<usize, TallyCircuitError> {
    usize::try_from(reader.read_varuint()?).map_err(|_| TallyCircuitError::ArithmeticOverflow)
}

fn read_wire_index(reader: &mut CanonicalReader<'_>) -> Result<WireIndex, TallyCircuitError> {
    WireIndex::try_from(reader.read_varuint()?).map_err(|_| TallyCircuitError::WireIndexOverflow)
}
