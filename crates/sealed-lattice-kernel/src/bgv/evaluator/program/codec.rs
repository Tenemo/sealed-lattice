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
// for every ring slot. Keep the codec bound exact to that largest list;
// instruction and catalog lists retain their narrower checks at their owners.
const MAXIMUM_EVALUATOR_CANONICAL_LIST_COUNT: usize = crate::bgv::parameters::POLYNOMIAL_DEGREE;

pub(super) fn encode_program_set(program_set: &EvaluatorProgramSet) -> CanonicalResult<Vec<u8>> {
    program_set.validate()?;
    encode_program_components(&program_set.constants, &program_set.streams)
}

fn encode_program_components(
    constants: &[EvaluatorConstant],
    streams: &[EvaluatorInstructionStream],
) -> CanonicalResult<Vec<u8>> {
    let limits = evaluator_program_codec_limits();
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

pub(crate) fn verify_canonical_program_set(canonical_bytes: &[u8]) -> CanonicalResult<()> {
    let limits = evaluator_program_codec_limits();
    let tuple = CanonicalTuple::decode(canonical_bytes, &limits).map_err(map_codec_error)?;
    require_tuple_header(
        &tuple,
        EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        2,
    )?;
    let constants = decode_nested_tuple_list(
        tuple
            .items
            .first()
            .ok_or_else(|| program_error("missing constants"))?,
        &limits,
        MAXIMUM_EVALUATOR_CONSTANT_COUNT,
    )?
    .iter()
    .map(decode_constant)
    .collect::<CanonicalResult<Vec<_>>>()?;
    let streams = decode_nested_tuple_list(
        tuple
            .items
            .get(1)
            .ok_or_else(|| program_error("missing streams"))?,
        &limits,
        SELECTED_STREAM_COUNT,
    )?
    .iter()
    .map(|stream| decode_instruction_stream(stream, &limits))
    .collect::<CanonicalResult<Vec<_>>>()?;
    let program_set = EvaluatorProgramSet::new(constants, streams)?;
    let reencoded = encode_program_set(&program_set)?;
    if reencoded != canonical_bytes {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "evaluator program artifact is not the exact canonical encoding",
        ));
    }
    Ok(())
}

fn decode_constant(tuple: &CanonicalTuple) -> CanonicalResult<EvaluatorConstant> {
    require_tuple_header(
        tuple,
        EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        2,
    )?;
    EvaluatorConstant::new(
        EvaluatorConstantKind::from_canonical_code(read_u16(&tuple.items[0])?)?,
        read_field_element_list(&tuple.items[1])?,
    )
}

fn decode_instruction_stream(
    tuple: &CanonicalTuple,
    limits: &CanonicalDecodeLimits,
) -> CanonicalResult<EvaluatorInstructionStream> {
    require_tuple_header(
        tuple,
        EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        2,
    )?;
    let instructions =
        decode_nested_tuple_list(&tuple.items[1], limits, MAXIMUM_INSTRUCTIONS_PER_STREAM)?
            .iter()
            .map(decode_instruction)
            .collect::<CanonicalResult<Vec<_>>>()?;
    EvaluatorInstructionStream::new(read_u16(&tuple.items[0])?, instructions)
}

fn decode_instruction(tuple: &CanonicalTuple) -> CanonicalResult<EvaluatorInstruction> {
    require_tuple_header(
        tuple,
        EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER,
        EVALUATOR_PROGRAM_SCHEMA_VERSION,
        6,
    )?;
    EvaluatorInstruction::new(
        EvaluatorOpcode::from_canonical_code(read_u16(&tuple.items[0])?)?,
        read_optional_u32(&tuple.items[1])?,
        read_u32_list(&tuple.items[2])?,
        read_u64(&tuple.items[3])?,
        read_u64(&tuple.items[4])?,
        read_optional_hash(&tuple.items[5])?,
    )
}

fn require_tuple_header(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    schema_version: u16,
    item_count: usize,
) -> CanonicalResult<()> {
    if tuple.schema_version != schema_version {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "evaluator program tuple version is unsupported",
        ));
    }
    if tuple.schema_identifier != schema_identifier || tuple.items.len() != item_count {
        return Err(program_error(
            "evaluator program tuple has the wrong schema or shape",
        ));
    }
    Ok(())
}

fn decode_nested_tuple_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    maximum_count: usize,
) -> CanonicalResult<Vec<CanonicalTuple>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count > maximum_count {
        return Err(program_error(
            "evaluator nested-tuple list exceeds its semantic count bound",
        ));
    }
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0_usize;
    for _ in 0..count {
        let tuple_byte_length = canonical_tuple_prefix_byte_length(&bytes[offset..])?;
        let end = offset
            .checked_add(tuple_byte_length)
            .ok_or_else(|| program_error("evaluator tuple-list offset overflowed"))?;
        let tuple_bytes = bytes
            .get(offset..end)
            .ok_or_else(|| program_error("evaluator nested tuple is truncated"))?;
        tuples.push(CanonicalTuple::decode(tuple_bytes, limits).map_err(map_codec_error)?);
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
    let item_count = read_raw_u32(bytes, 4)
        .ok_or_else(|| program_error("evaluator nested-tuple header is truncated"))?;
    let item_count = usize::try_from(item_count)
        .map_err(|_| program_error("evaluator nested-tuple item count overflowed"))?;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let item_byte_length = read_raw_u32(
            bytes,
            offset
                .checked_add(2)
                .ok_or_else(|| program_error("evaluator nested-tuple item offset overflowed"))?,
        )
        .ok_or_else(|| program_error("evaluator nested-tuple item header is truncated"))?;
        offset = offset
            .checked_add(6)
            .and_then(|value| value.checked_add(item_byte_length as usize))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| program_error("evaluator nested-tuple item is truncated"))?;
    }
    Ok(offset)
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
) -> CanonicalResult<(usize, &[u8])> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(program_error("evaluator value is not a homogeneous list"));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 6 || read_raw_u16(bytes, 0) != Some(expected_element_type.canonical_code()) {
        return Err(program_error(
            "evaluator homogeneous list has the wrong element type",
        ));
    }
    let count = read_raw_u32(bytes, 2)
        .ok_or_else(|| program_error("evaluator homogeneous-list header is truncated"))?;
    Ok((count as usize, &bytes[6..]))
}

fn read_field_element_list(item: &CanonicalItem) -> CanonicalResult<Vec<u32>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::FieldElement)?;
    let expected_byte_length = count
        .checked_mul(PLAINTEXT_FIELD_ELEMENT_BYTE_LENGTH)
        .ok_or_else(|| program_error("evaluator field-element list length overflowed"))?;
    if bytes.len() != expected_byte_length {
        return Err(program_error(
            "evaluator field-element list has the wrong byte length",
        ));
    }
    Ok(bytes
        .chunks_exact(PLAINTEXT_FIELD_ELEMENT_BYTE_LENGTH)
        .map(|bytes| u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16))
        .collect())
}

fn read_u32_list(item: &CanonicalItem) -> CanonicalResult<Vec<u32>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned32)?;
    let expected_byte_length = count
        .checked_mul(4)
        .ok_or_else(|| program_error("evaluator u32 list length overflowed"))?;
    if bytes.len() != expected_byte_length {
        return Err(program_error(
            "evaluator u32 list has the wrong byte length",
        ));
    }
    bytes
        .chunks_exact(4)
        .map(|bytes| {
            <[u8; 4]>::try_from(bytes)
                .map(u32::from_le_bytes)
                .map_err(|_| program_error("evaluator u32 list element is malformed"))
        })
        .collect()
}

fn read_u16(item: &CanonicalItem) -> CanonicalResult<u16> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(program_error("evaluator value has the wrong u16 type"));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| program_error("evaluator u16 value has the wrong length"))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u64(item: &CanonicalItem) -> CanonicalResult<u64> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(program_error("evaluator value has the wrong u64 type"));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| program_error("evaluator u64 value has the wrong length"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_optional_u32(item: &CanonicalItem) -> CanonicalResult<Option<u32>> {
    let value = read_optional_bytes(item, CanonicalItemType::Unsigned32, 4)?;
    value
        .map(|bytes| {
            <[u8; 4]>::try_from(bytes)
                .map(u32::from_le_bytes)
                .map_err(|_| program_error("evaluator optional u32 is malformed"))
        })
        .transpose()
}

fn read_optional_hash(item: &CanonicalItem) -> CanonicalResult<Option<Hash512>> {
    let value = read_optional_bytes(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
    value
        .map(|bytes| {
            <[u8; Hash512::BYTE_LENGTH]>::try_from(bytes)
                .map(Hash512::from_bytes)
                .map_err(|_| program_error("evaluator optional hash is malformed"))
        })
        .transpose()
}

fn read_optional_bytes(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    expected_value_byte_length: usize,
) -> CanonicalResult<Option<&[u8]>> {
    if item.item_type() != CanonicalItemType::Optional {
        return Err(program_error("evaluator value is not an optional"));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 3 || read_raw_u16(bytes, 0) != Some(expected_type.canonical_code()) {
        return Err(program_error(
            "evaluator optional has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 3 + expected_value_byte_length => Ok(Some(&bytes[3..])),
        _ => Err(program_error("evaluator optional encoding is malformed")),
    }
}

fn read_raw_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_raw_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

pub(super) fn hash_constant(
    constant: &EvaluatorConstant,
    domain: &str,
) -> CanonicalResult<Hash512> {
    let limits = evaluator_program_codec_limits();
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
        &evaluator_program_codec_limits(),
    )
    .map_err(map_codec_error)
}

fn nested_tuple_item(
    tuple: CanonicalTuple,
    limits: &CanonicalDecodeLimits,
) -> CanonicalResult<CanonicalItem> {
    let bytes = tuple.encode_with_limits(limits).map_err(map_codec_error)?;
    CanonicalItem::from_canonical_bytes(CanonicalItemType::NestedTuple, bytes, limits)
        .map_err(map_codec_error)
}

fn evaluator_program_codec_limits() -> CanonicalDecodeLimits {
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
