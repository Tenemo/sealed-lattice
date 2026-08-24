use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    foundation::FOUNDATION_PROFILE,
};

use super::{
    BooleanOperation, CompiledTallyCircuit, TALLY_CIRCUIT_ARTIFACT_MAGIC, TallyCircuitError,
    TallyCircuitProfile, WireIndex,
    compiler::{compile_tally_circuit, tally_circuit_compiler_identity},
};

pub(crate) const TALLY_CIRCUIT_ARTIFACT_VERSION: u64 = 1;

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
    append_varuint(&mut bytes, u64::from(circuit.profile().participant_count()));
    append_varuint(&mut bytes, u64::from(circuit.profile().option_count()));
    append_varuint(&mut bytes, u64::from(circuit.profile().top_count()));
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
    append_varuint(
        &mut bytes,
        u64::try_from(circuit.operations().len())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    for operation in circuit.operations() {
        encode_operation(&mut bytes, operation);
    }

    append_varuint(
        &mut bytes,
        u64::try_from(circuit.participant_validity_wires().len())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?,
    );
    for wire in circuit.participant_validity_wires() {
        append_varuint(&mut bytes, u64::from(*wire));
    }
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

    let profile = TallyCircuitProfile::new(
        read_u16(&mut reader)?,
        read_u16(&mut reader)?,
        read_u16(&mut reader)?,
    )?;
    let expected_circuit = compile_tally_circuit(profile)?;
    let score_bit_width = read_usize(&mut reader)?;
    let aggregate_score_bit_width = read_usize(&mut reader)?;
    let option_position_bit_width = read_usize(&mut reader)?;
    if score_bit_width != expected_circuit.geometry().score_bit_width
        || aggregate_score_bit_width != expected_circuit.geometry().aggregate_score_bit_width
        || option_position_bit_width != expected_circuit.geometry().option_position_bit_width
    {
        return Err(TallyCircuitError::CircuitMismatch);
    }

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

    let participant_validity_wire_count = read_usize(&mut reader)?;
    if participant_validity_wire_count != expected_circuit.participant_validity_wires().len() {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    let participant_validity_wires = (0..participant_validity_wire_count)
        .map(|_| read_wire_index(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;

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
        participant_validity_wires,
        ordered_option_position_wires,
    };
    validate_circuit_structure(&decoded_circuit)?;
    if decoded_circuit != expected_circuit {
        return Err(TallyCircuitError::CircuitMismatch);
    }
    Ok(decoded_circuit)
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
    }
    let total_wire_count = circuit.geometry().total_wire_count;
    for wire in circuit.participant_validity_wires().iter().copied().chain(
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
