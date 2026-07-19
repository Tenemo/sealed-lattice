use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem,
        CanonicalItemType, CanonicalTuple, Hash512, hash_foundation_tuple_512,
    },
};

use super::{
    EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER, EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER,
    EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER, EVALUATOR_PROGRAM_SCHEMA_VERSION,
    EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER, EvaluatorConstant, EvaluatorConstantKind,
    EvaluatorInstruction, EvaluatorInstructionStream, EvaluatorOpcode, EvaluatorProgramSet,
    MAXIMUM_EVALUATOR_CONSTANT_COUNT, MAXIMUM_INSTRUCTIONS_PER_STREAM, SELECTED_STREAM_COUNT,
    program_error,
};

const PLAINTEXT_FIELD_ELEMENT_BYTE_LENGTH: usize = 3;
const MAXIMUM_EVALUATOR_PROGRAM_BYTE_LENGTH: usize = 64 * 1024 * 1024;
const MAXIMUM_EVALUATOR_PROGRAM_ITEM_BYTE_LENGTH: usize = 48 * 1024 * 1024;
const MAXIMUM_EVALUATOR_PROGRAM_CUMULATIVE_WORK_BYTE_LENGTH: usize = 128 * 1024 * 1024;
const MAXIMUM_EVALUATOR_PROGRAM_CUMULATIVE_ALLOCATION_BYTE_LENGTH: usize = 96 * 1024 * 1024;
// A selected slot-vector constant contains one canonical plaintext residue
// for every ring slot. Keep the decoder bound exact to that largest list;
// instruction and catalog lists retain their narrower checks at their owners.
const MAXIMUM_EVALUATOR_CANONICAL_LIST_COUNT: usize = crate::bgv::parameters::POLYNOMIAL_DEGREE;

pub(super) fn encode_program_set(program_set: &EvaluatorProgramSet) -> CanonicalResult<Vec<u8>> {
    program_set.validate()?;
    encode_program_components(&program_set.constants, &program_set.streams)
}

#[cfg(test)]
pub(super) fn encode_candidate_recurrence_trace(
    constants: &[EvaluatorConstant],
    streams: &[EvaluatorInstructionStream],
) -> CanonicalResult<Vec<u8>> {
    encode_program_components(constants, streams)
}

fn encode_program_components(
    constants: &[EvaluatorConstant],
    streams: &[EvaluatorInstructionStream],
) -> CanonicalResult<Vec<u8>> {
    let limits = evaluator_program_decode_limits();
    let constant_items = constants
        .iter()
        .map(|constant| nested_tuple_item(constant_tuple(constant)?, &limits))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let stream_items = streams
        .iter()
        .map(|stream| nested_tuple_item(instruction_stream_tuple(stream, &limits)?, &limits))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let constants = CanonicalItem::homogeneous_list_with_limits(
        CanonicalItemType::NestedTuple,
        &constant_items,
        &limits,
    )
    .map_err(map_codec_error)?;
    let streams = CanonicalItem::homogeneous_list_with_limits(
        CanonicalItemType::NestedTuple,
        &stream_items,
        &limits,
    )
    .map_err(map_codec_error)?;

    CanonicalTuple::new(
        EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        vec![constants, streams],
    )
    .encode_with_limits(&limits)
    .map_err(map_codec_error)
}

pub(super) fn decode_program_set(bytes: &[u8]) -> CanonicalResult<EvaluatorProgramSet> {
    let (constants, streams) = decode_program_components(bytes)?;
    EvaluatorProgramSet::new(constants, streams)
}

#[cfg(test)]
pub(super) fn decode_candidate_recurrence_trace(
    bytes: &[u8],
) -> CanonicalResult<(Vec<EvaluatorConstant>, Vec<EvaluatorInstructionStream>)> {
    decode_program_components(bytes)
}

fn decode_program_components(
    bytes: &[u8],
) -> CanonicalResult<(Vec<EvaluatorConstant>, Vec<EvaluatorInstructionStream>)> {
    let limits = evaluator_program_decode_limits();
    let tuple = CanonicalTuple::decode(bytes, &limits).map_err(map_codec_error)?;
    require_header(&tuple, EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER, 2)?;
    let constant_tuples = read_nested_tuple_list(
        &tuple.items[0],
        &limits,
        MAXIMUM_EVALUATOR_CONSTANT_COUNT,
        "evaluator constant catalog",
    )?;
    let stream_tuples = read_nested_tuple_list(
        &tuple.items[1],
        &limits,
        SELECTED_STREAM_COUNT,
        "evaluator instruction-stream catalog",
    )?;
    let constants = constant_tuples
        .iter()
        .map(decode_constant_tuple)
        .collect::<CanonicalResult<Vec<_>>>()?;
    let streams = stream_tuples
        .iter()
        .map(|stream| decode_instruction_stream_tuple(stream, &limits))
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok((constants, streams))
}

pub(super) fn hash_constant(
    constant: &EvaluatorConstant,
    domain: &str,
) -> CanonicalResult<Hash512> {
    let limits = evaluator_program_decode_limits();
    let bytes = constant_tuple(constant)?
        .encode_with_limits(&limits)
        .map_err(map_codec_error)?;
    let item = CanonicalItem::variable_bytes(bytes).map_err(map_codec_error)?;
    hash_foundation_tuple_512(domain, &[item]).map_err(map_codec_error)
}

fn constant_tuple(constant: &EvaluatorConstant) -> CanonicalResult<CanonicalTuple> {
    constant.validate()?;
    Ok(CanonicalTuple::new(
        EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(constant.kind.canonical_code()),
            field_element_list(&constant.values)?,
        ],
    ))
}

fn decode_constant_tuple(tuple: &CanonicalTuple) -> CanonicalResult<EvaluatorConstant> {
    require_header(tuple, EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER, 2)?;
    let kind = EvaluatorConstantKind::from_canonical_code(read_u16(&tuple.items[0])?)?;
    let values = read_field_element_list(&tuple.items[1])?;
    EvaluatorConstant::new(kind, values)
}

fn instruction_stream_tuple(
    stream: &EvaluatorInstructionStream,
    limits: &CanonicalDecodeLimits,
) -> CanonicalResult<CanonicalTuple> {
    let instruction_items = stream
        .instructions
        .iter()
        .map(|instruction| nested_tuple_item(instruction_tuple(instruction)?, limits))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let instructions = CanonicalItem::homogeneous_list_with_limits(
        CanonicalItemType::NestedTuple,
        &instruction_items,
        limits,
    )
    .map_err(map_codec_error)?;
    Ok(CanonicalTuple::new(
        EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        vec![CanonicalItem::unsigned16(stream.top_count), instructions],
    ))
}

fn decode_instruction_stream_tuple(
    tuple: &CanonicalTuple,
    limits: &CanonicalDecodeLimits,
) -> CanonicalResult<EvaluatorInstructionStream> {
    require_header(tuple, EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER, 2)?;
    let top_count = read_u16(&tuple.items[0])?;
    let instruction_tuples = read_nested_tuple_list(
        &tuple.items[1],
        limits,
        MAXIMUM_INSTRUCTIONS_PER_STREAM,
        "evaluator instruction stream",
    )?;
    let instructions = instruction_tuples
        .iter()
        .map(decode_instruction_tuple)
        .collect::<CanonicalResult<Vec<_>>>()?;
    EvaluatorInstructionStream::new(top_count, instructions)
}

fn instruction_tuple(instruction: &EvaluatorInstruction) -> CanonicalResult<CanonicalTuple> {
    instruction.validate_shape()?;
    let output_register = instruction.output_register.map(CanonicalItem::unsigned32);
    let input_registers = instruction
        .input_registers
        .iter()
        .copied()
        .map(CanonicalItem::unsigned32)
        .collect::<Vec<_>>();
    let constant_hash = instruction
        .constant_hash
        .map(|hash| CanonicalItem::hash512(hash.into_bytes()));
    Ok(CanonicalTuple::new(
        EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(instruction.opcode.canonical_code()),
            CanonicalItem::optional(CanonicalItemType::Unsigned32, output_register.as_ref())
                .map_err(map_codec_error)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::Unsigned32, &input_registers)
                .map_err(map_codec_error)?,
            CanonicalItem::unsigned64(instruction.immediate0),
            CanonicalItem::unsigned64(instruction.immediate1),
            CanonicalItem::optional(CanonicalItemType::Hash512, constant_hash.as_ref())
                .map_err(map_codec_error)?,
        ],
    ))
}

fn decode_instruction_tuple(tuple: &CanonicalTuple) -> CanonicalResult<EvaluatorInstruction> {
    require_header(tuple, EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER, 6)?;
    EvaluatorInstruction::new(
        EvaluatorOpcode::from_canonical_code(read_u16(&tuple.items[0])?)?,
        read_optional_u32(&tuple.items[1])?,
        read_u32_list(&tuple.items[2])?,
        read_u64(&tuple.items[3])?,
        read_u64(&tuple.items[4])?,
        read_optional_hash(&tuple.items[5])?,
    )
}

fn field_element_list(values: &[u32]) -> CanonicalResult<CanonicalItem> {
    let count = u32::try_from(values.len())
        .map_err(|_| program_error("evaluator field-element count does not fit u32"))?;
    let payload_byte_length = values
        .len()
        .checked_mul(PLAINTEXT_FIELD_ELEMENT_BYTE_LENGTH)
        .and_then(|length| length.checked_add(6))
        .ok_or_else(|| program_error("evaluator field-element list length overflowed"))?;
    let mut bytes = Vec::with_capacity(payload_byte_length);
    bytes.extend_from_slice(
        &CanonicalItemType::FieldElement
            .canonical_code()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&count.to_le_bytes());
    for value in values {
        let encoded = value.to_le_bytes();
        bytes.extend_from_slice(&encoded[..PLAINTEXT_FIELD_ELEMENT_BYTE_LENGTH]);
    }
    CanonicalItem::from_canonical_bytes(
        CanonicalItemType::HomogeneousList,
        bytes,
        &evaluator_program_decode_limits(),
    )
    .map_err(map_codec_error)
}

fn read_field_element_list(item: &CanonicalItem) -> CanonicalResult<Vec<u32>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::FieldElement)?;
    let expected_byte_length = count
        .checked_mul(PLAINTEXT_FIELD_ELEMENT_BYTE_LENGTH)
        .ok_or_else(|| program_error("evaluator field-element list length overflowed"))?;
    if bytes.len() != expected_byte_length {
        return Err(program_error(
            "evaluator field-element list has the wrong fixed-width payload length",
        ));
    }
    bytes
        .chunks_exact(PLAINTEXT_FIELD_ELEMENT_BYTE_LENGTH)
        .map(|encoded| {
            let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], 0]);
            if u64::from(value) >= crate::bgv::parameters::PLAINTEXT_MODULUS {
                return Err(program_error(
                    "evaluator field element is not a canonical plaintext residue",
                ));
            }
            Ok(value)
        })
        .collect()
}

fn nested_tuple_item(
    tuple: CanonicalTuple,
    limits: &CanonicalDecodeLimits,
) -> CanonicalResult<CanonicalItem> {
    let bytes = tuple.encode_with_limits(limits).map_err(map_codec_error)?;
    CanonicalItem::from_canonical_bytes(CanonicalItemType::NestedTuple, bytes, limits)
        .map_err(map_codec_error)
}

fn read_nested_tuple_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    maximum_count: usize,
    list_name: &'static str,
) -> CanonicalResult<Vec<CanonicalTuple>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count > maximum_count {
        return Err(program_error(format!(
            "{list_name} exceeds its selected count bound"
        )));
    }
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0_usize;
    for _ in 0..count {
        let byte_length = canonical_tuple_prefix_byte_length(&bytes[offset..])?;
        let end = offset
            .checked_add(byte_length)
            .ok_or_else(|| program_error("evaluator nested-tuple list offset overflowed"))?;
        let tuple = CanonicalTuple::decode(&bytes[offset..end], limits).map_err(map_codec_error)?;
        tuples.push(tuple);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(program_error(
            "evaluator nested-tuple list contains trailing bytes",
        ));
    }
    Ok(tuples)
}

fn canonical_tuple_prefix_byte_length(bytes: &[u8]) -> CanonicalResult<usize> {
    if bytes.len() < 8 {
        return Err(program_error("evaluator nested tuple header is truncated"));
    }
    let item_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if item_count > MAXIMUM_EVALUATOR_CANONICAL_LIST_COUNT {
        return Err(program_error(
            "evaluator nested tuple item count exceeds the fixed decoder bound",
        ));
    }
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header_end = offset
            .checked_add(6)
            .ok_or_else(|| program_error("evaluator nested tuple item offset overflowed"))?;
        if header_end > bytes.len() {
            return Err(program_error(
                "evaluator nested tuple item header is truncated",
            ));
        }
        let byte_length = u32::from_le_bytes([
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        ]) as usize;
        offset = header_end
            .checked_add(byte_length)
            .ok_or_else(|| program_error("evaluator nested tuple item length overflowed"))?;
        if offset > bytes.len() {
            return Err(program_error("evaluator nested tuple item is truncated"));
        }
    }
    Ok(offset)
}

fn read_u16(item: &CanonicalItem) -> CanonicalResult<u16> {
    let bytes = read_fixed_item(item, CanonicalItemType::Unsigned16, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u64(item: &CanonicalItem) -> CanonicalResult<u64> {
    let bytes = read_fixed_item(item, CanonicalItemType::Unsigned64, 8)?;
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .expect("fixed-width validation produced eight bytes"),
    ))
}

fn read_optional_u32(item: &CanonicalItem) -> CanonicalResult<Option<u32>> {
    let bytes = read_optional(item, CanonicalItemType::Unsigned32, 4)?;
    Ok(bytes.map(|value| {
        u32::from_le_bytes(
            value
                .try_into()
                .expect("fixed-width validation produced four bytes"),
        )
    }))
}

fn read_optional_hash(item: &CanonicalItem) -> CanonicalResult<Option<Hash512>> {
    let bytes = read_optional(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
    Ok(bytes.map(|value| {
        Hash512::from_bytes(
            value
                .try_into()
                .expect("fixed-width validation produced a 64-byte hash"),
        )
    }))
}

fn read_optional(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    expected_byte_length: usize,
) -> CanonicalResult<Option<&[u8]>> {
    if item.item_type() != CanonicalItemType::Optional {
        return Err(program_error("evaluator optional item has the wrong type"));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_type.canonical_code()
    {
        return Err(program_error(
            "evaluator optional item has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 3 + expected_byte_length => Ok(Some(&bytes[3..])),
        _ => Err(program_error("evaluator optional item is malformed")),
    }
}

fn read_u32_list(item: &CanonicalItem) -> CanonicalResult<Vec<u32>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned32)?;
    if count > 2 || bytes.len() != count.saturating_mul(4) {
        return Err(program_error(
            "evaluator input-register list has an invalid count or byte length",
        ));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|value| {
            u32::from_le_bytes(
                value
                    .try_into()
                    .expect("four-byte chunks produce canonical u32 values"),
            )
        })
        .collect())
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
) -> CanonicalResult<(usize, &[u8])> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(program_error("evaluator list item has the wrong type"));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(program_error(
            "evaluator list has the wrong canonical element type",
        ));
    }
    Ok((
        u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize,
        &bytes[6..],
    ))
}

fn read_fixed_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    expected_byte_length: usize,
) -> CanonicalResult<&[u8]> {
    if item.item_type() != expected_type || item.canonical_bytes().len() != expected_byte_length {
        return Err(program_error(
            "evaluator tuple item has the wrong type or fixed byte length",
        ));
    }
    Ok(item.canonical_bytes())
}

fn require_header(
    tuple: &CanonicalTuple,
    expected_schema_identifier: u16,
    expected_item_count: usize,
) -> CanonicalResult<()> {
    if tuple.schema_identifier != expected_schema_identifier
        || tuple.schema_version != EVALUATOR_PROGRAM_SCHEMA_VERSION
        || tuple.items.len() != expected_item_count
    {
        return Err(program_error(
            "evaluator canonical tuple has the wrong schema, version, or field count",
        ));
    }
    Ok(())
}

fn evaluator_program_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_EVALUATOR_PROGRAM_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_EVALUATOR_CANONICAL_LIST_COUNT,
        maximum_item_byte_length: MAXIMUM_EVALUATOR_PROGRAM_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 4,
        maximum_cumulative_work_byte_length: MAXIMUM_EVALUATOR_PROGRAM_CUMULATIVE_WORK_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_EVALUATOR_PROGRAM_CUMULATIVE_ALLOCATION_BYTE_LENGTH,
    }
}

fn map_codec_error(error: CanonicalCodecError) -> CanonicalError {
    let code = match error.kind {
        CanonicalCodecErrorKind::Truncated
        | CanonicalCodecErrorKind::TrailingBytes
        | CanonicalCodecErrorKind::LimitExceeded
        | CanonicalCodecErrorKind::LengthOverflow => CanonicalErrorCode::MalformedLength,
        CanonicalCodecErrorKind::UnknownItemType | CanonicalCodecErrorKind::InvalidItem => {
            CanonicalErrorCode::InvalidProtocolObject
        }
    };
    CanonicalError::new(
        code,
        format!("evaluator canonical codec refused input: {error}"),
    )
}
