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
    EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER, EvaluatorConstant, EvaluatorInstruction,
    EvaluatorInstructionStream, EvaluatorProgramSet, program_error,
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
