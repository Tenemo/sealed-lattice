use std::collections::BTreeSet;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::*;
use crate::protocol::finality::{FinalityDerivationContext, derive_finality_target};
use crate::protocol::preparation_plaintext::{
    PAIRWISE_MASTER_INVENTORY_BYTE_LENGTH, PairwiseMasterInventory, sender_subset_slots,
};
use crate::protocol::source::{
    HELD_SUBSET_KEY_VECTOR_BYTE_LENGTH, SOURCE_ORDINAL, SourceContext, SourceDeclaration,
    decode_held_subset_keys, derive_source_coordinate_shares, encode_held_subset_keys,
};
use crate::tally_circuit::{
    BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile, compiler::compile_tally_circuit,
};

pub const PADDED_TALLY_MAXIMUM_CHUNK_BYTE_LENGTH: usize = 480_000;

const COMPLETION_PROFILE_OPTION_COUNT: u16 = 10;
const INITIAL_WIRE_PAYLOAD_BYTE_LENGTH: usize = FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH;
const CONSTANT_PAYLOAD_BYTE_LENGTH: usize = FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH;
const LINEAR_PAYLOAD_BYTE_LENGTH: usize = FIELD_BIT_WIDTH * 4 * PADDED_TOKEN_BYTE_LENGTH;
const GENERATION_CHECKPOINT_MAGIC: [u8; 4] = *b"SLPG";
const GENERATION_CHECKPOINT_VERSION: u16 = 1;
const GENERATION_CHECKPOINT_KEY_BYTE_LENGTH: usize = 32;
const GENERATION_CHECKPOINT_TAG_BYTE_LENGTH: usize = 40;
const GENERATION_CHECKPOINT_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/padded-continuation/generation-checkpoint/v1";
const EVALUATION_CHECKPOINT_MAGIC: [u8; 4] = *b"SLPE";
const EVALUATION_CHECKPOINT_VERSION: u16 = 1;
const EVALUATION_CHECKPOINT_TAG_BYTE_LENGTH: usize = 40;
const EVALUATION_CHECKPOINT_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/padded-continuation/evaluation-checkpoint/v1";
const EVALUATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH: usize = 4
    + 2
    + 3 * Hash512::BYTE_LENGTH
    + 2
    + 2
    + 2
    + 4
    + Hash512::BYTE_LENGTH
    + COMPLETION_PROFILE_PARTICIPANT_COUNT as usize * Hash512::BYTE_LENGTH
    + COMPLETION_PROFILE_PARTICIPANT_COUNT as usize * PADDED_ALLOCATION_NONCE_BYTE_LENGTH
    + 2
    + 2;
const RESULT_MAGIC: [u8; 4] = *b"SLPR";
const RESULT_VERSION: u16 = 1;
const RESULT_KIND_RESULT: u8 = 1;
const RESULT_KIND_NO_RESULT: u8 = 2;
const RESULT_IDENTITY_DOMAIN: &str = "sealed-lattice/padded-continuation/result/v1";
const RESULT_FIXED_HEADER_BYTE_LENGTH: usize =
    4 + 2 + 2 * Hash512::BYTE_LENGTH + 2 + 1 + COMPLETION_PROFILE_PARTICIPANT_COUNT as usize + 2;
const CHECKPOINT_TOKEN_PAIR_BYTE_LENGTH: usize = TOKEN_PAIR_ENTROPY_BYTE_LENGTH;
const CHECKPOINT_FIELD_PAIRS_BYTE_LENGTH: usize =
    FIELD_BIT_WIDTH * CHECKPOINT_TOKEN_PAIR_BYTE_LENGTH;
const GENERATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH: usize = 4
    + 2
    + 2 * Hash512::BYTE_LENGTH
    + 2
    + 2
    + PADDED_ALLOCATION_NONCE_BYTE_LENGTH
    + 4
    + HELD_SUBSET_KEY_VECTOR_BYTE_LENGTH
    + PAIRWISE_MASTER_INVENTORY_BYTE_LENGTH
    + 2
    + 2
    + 4
    + 2;

type ParticipantFieldTokens = [FieldTokens; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaddedTallyPlanSummary {
    pub participant_count: u16,
    pub option_count: u16,
    pub top_count: u16,
    pub input_wire_count: u32,
    pub operation_count: u32,
    pub constant_count: u32,
    pub linear_count: u32,
    pub conjunction_count: u32,
    pub negation_count: u32,
    pub output_count: u32,
    pub wire_count: u32,
    pub logical_payload_byte_length: u32,
    pub label_entropy_byte_length: u32,
    pub manifest_byte_length: u32,
    pub maximum_live_wire_count: u32,
    pub live_wire_counts_after_chunks: Vec<u32>,
    pub chunk_byte_lengths: Vec<u32>,
    pub chunk_label_entropy_byte_lengths: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlannedOperationKind {
    Constant,
    Linear {
        operation_ordinal: u32,
    },
    Conjunction {
        operation_ordinal: u32,
        conjunction_ordinal: u32,
    },
    Negation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlannedOperation {
    kind: PlannedOperationKind,
    payload_offset: usize,
    payload_byte_length: usize,
    entropy_offset: usize,
    entropy_byte_length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChunkDescriptor {
    first_operation: usize,
    operation_end: usize,
    includes_initial: bool,
    includes_terminal: bool,
    logical_payload_start: usize,
    logical_payload_end: usize,
}

impl ChunkDescriptor {
    fn payload_byte_length(self) -> Result<usize, PaddedContinuationError> {
        self.logical_payload_end
            .checked_sub(self.logical_payload_start)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)
    }

    fn chunk_byte_length(self) -> Result<usize, PaddedContinuationError> {
        PADDED_CHUNK_HEADER_BYTE_LENGTH
            .checked_add(self.payload_byte_length()?)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)
    }
}

struct PaddedTallyPlan {
    circuit: CompiledTallyCircuit,
    operations: Vec<PlannedOperation>,
    output_wires: Vec<u32>,
    terminal_payload_offset: usize,
    logical_payload_byte_length: usize,
    terminal_entropy_offset: usize,
    label_entropy_byte_length: usize,
    constant_count: usize,
    linear_count: usize,
    conjunction_count: usize,
    negation_count: usize,
    descriptors: Vec<ChunkDescriptor>,
    last_wire_uses: Vec<usize>,
    maximum_live_wire_count: usize,
    live_wire_counts_after_chunks: Vec<usize>,
}

impl PaddedTallyPlan {
    fn compile(top_count: u16) -> Result<Self, PaddedContinuationError> {
        let profile = TallyCircuitProfile::new(
            COMPLETION_PROFILE_PARTICIPANT_COUNT,
            COMPLETION_PROFILE_OPTION_COUNT,
            top_count,
        )
        .map_err(|_| PaddedContinuationError::InvalidPlan)?;
        let circuit =
            compile_tally_circuit(profile).map_err(|_| PaddedContinuationError::InvalidPlan)?;
        let input_payload_byte_length = circuit
            .input_bit_count()
            .checked_mul(INITIAL_WIRE_PAYLOAD_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let mut logical_payload_byte_length = input_payload_byte_length;
        let mut label_entropy_byte_length = circuit
            .input_bit_count()
            .checked_mul(FIELD_BIT_WIDTH)
            .and_then(|count| count.checked_mul(TOKEN_PAIR_ENTROPY_BYTE_LENGTH))
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let mut operations = Vec::with_capacity(circuit.operations().len());
        let mut constant_count = 0_usize;
        let mut linear_count = 0_usize;
        let mut conjunction_count = 0_usize;
        let mut negation_count = 0_usize;
        for (operation_index, operation) in circuit.operations().iter().enumerate() {
            let operation_ordinal = u32::try_from(operation_index)
                .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
            let (kind, payload_byte_length, entropy_pair_count) = match operation {
                BooleanOperation::Constant(_) => {
                    constant_count += 1;
                    (
                        PlannedOperationKind::Constant,
                        CONSTANT_PAYLOAD_BYTE_LENGTH,
                        FIELD_BIT_WIDTH,
                    )
                }
                BooleanOperation::ExclusiveOr { .. } => {
                    linear_count += 1;
                    (
                        PlannedOperationKind::Linear { operation_ordinal },
                        LINEAR_PAYLOAD_BYTE_LENGTH,
                        FIELD_BIT_WIDTH,
                    )
                }
                BooleanOperation::Conjunction { .. } => {
                    let conjunction_ordinal = u32::try_from(conjunction_count)
                        .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
                    conjunction_count += 1;
                    (
                        PlannedOperationKind::Conjunction {
                            operation_ordinal,
                            conjunction_ordinal,
                        },
                        PADDED_GATE_PAYLOAD_BYTE_LENGTH,
                        43,
                    )
                }
                BooleanOperation::Negation { .. } => {
                    negation_count += 1;
                    (PlannedOperationKind::Negation, 0, 0)
                }
            };
            let entropy_byte_length = entropy_pair_count
                .checked_mul(TOKEN_PAIR_ENTROPY_BYTE_LENGTH)
                .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
            operations.push(PlannedOperation {
                kind,
                payload_offset: logical_payload_byte_length,
                payload_byte_length,
                entropy_offset: label_entropy_byte_length,
                entropy_byte_length,
            });
            logical_payload_byte_length = logical_payload_byte_length
                .checked_add(payload_byte_length)
                .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
            label_entropy_byte_length = label_entropy_byte_length
                .checked_add(entropy_byte_length)
                .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        }
        let output_wires = circuit.output_wires();
        let terminal_payload_offset = logical_payload_byte_length;
        logical_payload_byte_length = logical_payload_byte_length
            .checked_add(
                output_wires
                    .len()
                    .checked_mul(PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH)
                    .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
            )
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let terminal_entropy_offset = label_entropy_byte_length;
        label_entropy_byte_length = label_entropy_byte_length
            .checked_add(
                output_wires
                    .len()
                    .checked_mul(8)
                    .and_then(|count| count.checked_mul(TOKEN_PAIR_ENTROPY_BYTE_LENGTH))
                    .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
            )
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let descriptors = compile_chunk_descriptors(
            input_payload_byte_length,
            &operations,
            terminal_payload_offset,
            logical_payload_byte_length,
        )?;
        let (last_wire_uses, maximum_live_wire_count, live_wire_counts_after_chunks) =
            compile_wire_liveness(&circuit, &descriptors)?;
        Ok(Self {
            circuit,
            operations,
            output_wires,
            terminal_payload_offset,
            logical_payload_byte_length,
            terminal_entropy_offset,
            label_entropy_byte_length,
            constant_count,
            linear_count,
            conjunction_count,
            negation_count,
            descriptors,
            last_wire_uses,
            maximum_live_wire_count,
            live_wire_counts_after_chunks,
        })
    }

    fn summary(&self, top_count: u16) -> Result<PaddedTallyPlanSummary, PaddedContinuationError> {
        let operation_count = self.operations.len();
        let wire_count = self
            .circuit
            .input_bit_count()
            .checked_add(operation_count)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let chunk_byte_lengths = self
            .descriptors
            .iter()
            .copied()
            .map(ChunkDescriptor::chunk_byte_length)
            .map(|length| {
                u32::try_from(length?).map_err(|_| PaddedContinuationError::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let chunk_label_entropy_byte_lengths = (0..self.descriptors.len())
            .map(|chunk_ordinal| checked_u32(self.chunk_entropy_range(chunk_ordinal)?.len()))
            .collect::<Result<Vec<_>, _>>()?;
        let manifest_byte_length = PADDED_MANIFEST_HEADER_BYTE_LENGTH
            .checked_add(
                self.descriptors
                    .len()
                    .checked_mul(PADDED_MANIFEST_DESCRIPTOR_BYTE_LENGTH)
                    .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
            )
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        Ok(PaddedTallyPlanSummary {
            participant_count: COMPLETION_PROFILE_PARTICIPANT_COUNT,
            option_count: COMPLETION_PROFILE_OPTION_COUNT,
            top_count,
            input_wire_count: checked_u32(self.circuit.input_bit_count())?,
            operation_count: checked_u32(operation_count)?,
            constant_count: checked_u32(self.constant_count)?,
            linear_count: checked_u32(self.linear_count)?,
            conjunction_count: checked_u32(self.conjunction_count)?,
            negation_count: checked_u32(self.negation_count)?,
            output_count: checked_u32(self.output_wires.len())?,
            wire_count: checked_u32(wire_count)?,
            logical_payload_byte_length: checked_u32(self.logical_payload_byte_length)?,
            label_entropy_byte_length: checked_u32(self.label_entropy_byte_length)?,
            manifest_byte_length: checked_u32(manifest_byte_length)?,
            maximum_live_wire_count: checked_u32(self.maximum_live_wire_count)?,
            live_wire_counts_after_chunks: self
                .live_wire_counts_after_chunks
                .iter()
                .copied()
                .map(checked_u32)
                .collect::<Result<Vec<_>, _>>()?,
            chunk_byte_lengths,
            chunk_label_entropy_byte_lengths,
        })
    }

    fn chunk_entropy_range(
        &self,
        chunk_ordinal: usize,
    ) -> Result<std::ops::Range<usize>, PaddedContinuationError> {
        let descriptor = *self
            .descriptors
            .get(chunk_ordinal)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        let start = if descriptor.includes_initial {
            0
        } else if descriptor.first_operation == self.operations.len() {
            self.terminal_entropy_offset
        } else {
            self.operations
                .get(descriptor.first_operation)
                .ok_or(PaddedContinuationError::InvalidPlan)?
                .entropy_offset
        };
        let end = if descriptor.includes_terminal {
            self.label_entropy_byte_length
        } else if descriptor.operation_end == self.operations.len() {
            self.terminal_entropy_offset
        } else {
            self.operations
                .get(descriptor.operation_end)
                .ok_or(PaddedContinuationError::InvalidPlan)?
                .entropy_offset
        };
        if start > end
            || self.operations[descriptor.first_operation..descriptor.operation_end]
                .iter()
                .map(|operation| operation.entropy_byte_length)
                .sum::<usize>()
                .checked_add(if descriptor.includes_initial {
                    self.circuit.input_bit_count()
                        * FIELD_BIT_WIDTH
                        * TOKEN_PAIR_ENTROPY_BYTE_LENGTH
                } else {
                    0
                })
                .and_then(|length| {
                    length.checked_add(if descriptor.includes_terminal {
                        self.output_wires.len() * 8 * TOKEN_PAIR_ENTROPY_BYTE_LENGTH
                    } else {
                        0
                    })
                })
                != end.checked_sub(start)
        {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        Ok(start..end)
    }

    fn live_wires_after_chunk(
        &self,
        chunk_ordinal: usize,
    ) -> Result<Vec<usize>, PaddedContinuationError> {
        let descriptor = *self
            .descriptors
            .get(chunk_ordinal)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        if descriptor.includes_terminal {
            return Ok(Vec::new());
        }
        let available_wire_count = self
            .circuit
            .input_bit_count()
            .checked_add(descriptor.operation_end)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let wires = (0..available_wire_count)
            .filter(|wire| {
                self.last_wire_uses[*wire] != usize::MAX
                    && self.last_wire_uses[*wire] >= descriptor.operation_end
            })
            .collect::<Vec<_>>();
        if wires.len()
            != *self
                .live_wire_counts_after_chunks
                .get(chunk_ordinal)
                .ok_or(PaddedContinuationError::InvalidPlan)?
        {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        Ok(wires)
    }
}

fn compile_wire_liveness(
    circuit: &CompiledTallyCircuit,
    descriptors: &[ChunkDescriptor],
) -> Result<(Vec<usize>, usize, Vec<usize>), PaddedContinuationError> {
    let input_wire_count = circuit.input_bit_count();
    let operation_count = circuit.operations().len();
    let wire_count = input_wire_count
        .checked_add(operation_count)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let terminal_use = operation_count;
    let mut last_wire_uses = vec![None; wire_count];
    for (operation_index, operation) in circuit.operations().iter().enumerate() {
        let mut record_use = |wire: u32| -> Result<(), PaddedContinuationError> {
            let wire =
                usize::try_from(wire).map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
            if wire >= input_wire_count + operation_index {
                return Err(PaddedContinuationError::InvalidPlan);
            }
            last_wire_uses[wire] = Some(operation_index);
            Ok(())
        };
        match operation {
            BooleanOperation::Constant(_) => {}
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            }
            | BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => {
                record_use(*left_wire)?;
                record_use(*right_wire)?;
            }
            BooleanOperation::Negation { input_wire } => record_use(*input_wire)?,
        }
    }
    for wire in circuit.output_wires() {
        let wire =
            usize::try_from(wire).map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
        if wire >= wire_count {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        last_wire_uses[wire] = Some(terminal_use);
    }
    let last_wire_uses = last_wire_uses
        .into_iter()
        .map(|last_use| last_use.unwrap_or(usize::MAX))
        .collect::<Vec<_>>();
    let mut live = vec![false; wire_count];
    for wire in 0..input_wire_count {
        live[wire] = last_wire_uses[wire] != usize::MAX;
    }
    let mut live_count = live.iter().filter(|value| **value).count();
    let mut maximum_live_wire_count = live_count;
    let mut chunk_boundary_index = 0_usize;
    let mut live_wire_counts_after_chunks = Vec::with_capacity(descriptors.len());
    for operation_index in 0..operation_count {
        let output_wire = input_wire_count
            .checked_add(operation_index)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        if last_wire_uses[output_wire] != usize::MAX
            && last_wire_uses[output_wire] > operation_index
        {
            live[output_wire] = true;
            live_count += 1;
            maximum_live_wire_count = maximum_live_wire_count.max(live_count);
        }
        for (wire, is_live) in live.iter_mut().enumerate() {
            if *is_live && last_wire_uses[wire] == operation_index {
                *is_live = false;
                live_count = live_count
                    .checked_sub(1)
                    .ok_or(PaddedContinuationError::InvalidPlan)?;
            }
        }
        while descriptors
            .get(chunk_boundary_index)
            .is_some_and(|descriptor| descriptor.operation_end == operation_index + 1)
        {
            live_wire_counts_after_chunks.push(
                if descriptors[chunk_boundary_index].includes_terminal {
                    0
                } else {
                    live_count
                },
            );
            chunk_boundary_index += 1;
        }
    }
    while chunk_boundary_index < descriptors.len() {
        let descriptor = descriptors[chunk_boundary_index];
        if descriptor.operation_end != operation_count {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        live_wire_counts_after_chunks.push(if descriptor.includes_terminal {
            0
        } else {
            live_count
        });
        chunk_boundary_index += 1;
    }
    if live_wire_counts_after_chunks.len() != descriptors.len() {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    Ok((
        last_wire_uses,
        maximum_live_wire_count,
        live_wire_counts_after_chunks,
    ))
}

fn compile_chunk_descriptors(
    input_payload_byte_length: usize,
    operations: &[PlannedOperation],
    terminal_payload_offset: usize,
    logical_payload_byte_length: usize,
) -> Result<Vec<ChunkDescriptor>, PaddedContinuationError> {
    let payload_limit = PADDED_TALLY_MAXIMUM_CHUNK_BYTE_LENGTH
        .checked_sub(PADDED_CHUNK_HEADER_BYTE_LENGTH)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    if input_payload_byte_length > payload_limit {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    let mut descriptors = Vec::new();
    let mut first_operation = 0_usize;
    let mut logical_payload_start = 0_usize;
    let mut current_payload_byte_length = input_payload_byte_length;
    for (operation_index, operation) in operations.iter().enumerate() {
        if current_payload_byte_length
            .checked_add(operation.payload_byte_length)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?
            > payload_limit
        {
            descriptors.push(ChunkDescriptor {
                first_operation,
                operation_end: operation_index,
                includes_initial: descriptors.is_empty(),
                includes_terminal: false,
                logical_payload_start,
                logical_payload_end: operation.payload_offset,
            });
            first_operation = operation_index;
            logical_payload_start = operation.payload_offset;
            current_payload_byte_length = 0;
        }
        current_payload_byte_length = current_payload_byte_length
            .checked_add(operation.payload_byte_length)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    }
    let terminal_payload_byte_length = logical_payload_byte_length
        .checked_sub(terminal_payload_offset)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    if terminal_payload_byte_length > payload_limit {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    if current_payload_byte_length
        .checked_add(terminal_payload_byte_length)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?
        > payload_limit
    {
        descriptors.push(ChunkDescriptor {
            first_operation,
            operation_end: operations.len(),
            includes_initial: descriptors.is_empty(),
            includes_terminal: false,
            logical_payload_start,
            logical_payload_end: terminal_payload_offset,
        });
        descriptors.push(ChunkDescriptor {
            first_operation: operations.len(),
            operation_end: operations.len(),
            includes_initial: false,
            includes_terminal: true,
            logical_payload_start: terminal_payload_offset,
            logical_payload_end: logical_payload_byte_length,
        });
    } else {
        descriptors.push(ChunkDescriptor {
            first_operation,
            operation_end: operations.len(),
            includes_initial: descriptors.is_empty(),
            includes_terminal: true,
            logical_payload_start,
            logical_payload_end: logical_payload_byte_length,
        });
    }
    if descriptors.is_empty()
        || !descriptors[0].includes_initial
        || !descriptors
            .last()
            .is_some_and(|descriptor| descriptor.includes_terminal)
        || descriptors
            .iter()
            .any(|descriptor| match descriptor.chunk_byte_length() {
                Ok(length) => length > PADDED_TALLY_MAXIMUM_CHUNK_BYTE_LENGTH,
                Err(_) => true,
            })
    {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    Ok(descriptors)
}

pub fn compile_padded_tally_plan_summary(
    top_count: u16,
) -> Result<PaddedTallyPlanSummary, PaddedContinuationError> {
    PaddedTallyPlan::compile(top_count)?.summary(top_count)
}

#[derive(Zeroize)]
struct MatchedMaskStreamKeys {
    subset: u16,
    low: [u8; 32],
    high_zero: [u8; 32],
}

#[derive(Zeroize)]
struct TerminalMaskStreamKey {
    subset: u16,
    zero: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct MaskStreamInventory {
    matched: Vec<MatchedMaskStreamKeys>,
    terminal: Vec<TerminalMaskStreamKey>,
}

#[derive(Zeroize)]
struct ReceiverBStreamKey {
    subset: u16,
    key: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct GateStreamInventory {
    participant_position: u16,
    receiver_b_streams: [Vec<ReceiverBStreamKey>; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
    own_receiver_pad_keys: [[u8; 32]; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
    local_garbler_pad_keys: [[u8; 32]; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
}

impl GateStreamInventory {
    fn derive(
        context: &EvaluationContext,
        participant_position: u16,
        held_subset_keys: &[HeldSubsetKey],
        pairwise_masters: &PairwiseMasterInventory,
    ) -> Result<Self, PaddedContinuationError> {
        validate_position(participant_position)?;
        let expected_slots = sender_subset_slots(participant_position);
        if held_subset_keys.len() != expected_slots.len()
            || held_subset_keys
                .iter()
                .zip(expected_slots)
                .any(|(key, (family, subset))| key.family != family || key.subset != subset)
        {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        let mut inventory = Self {
            participant_position,
            receiver_b_streams: core::array::from_fn(|receiver| {
                Vec::with_capacity(if receiver as u16 == participant_position {
                    84
                } else {
                    56
                })
            }),
            own_receiver_pad_keys: [[0_u8; 32]; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
            local_garbler_pad_keys: [[0_u8; 32]; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
        };
        for held_key in held_subset_keys {
            if held_key.family != SUBSET_FAMILY_SIZE_SEVEN {
                continue;
            }
            for receiver_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
                if held_key.subset & (1_u16 << receiver_position) == 0 {
                    continue;
                }
                inventory.receiver_b_streams[usize::from(receiver_position)].push(
                    ReceiverBStreamKey {
                        subset: held_key.subset,
                        key: derived_subkey(
                            &held_key.key,
                            context,
                            DerivedStreamScope {
                                family: DERIVED_STREAM_FAMILY_JOINT_B,
                                subset: held_key.subset,
                                receiver_position,
                                garbler_position: ABSENT_U16,
                            },
                        ),
                    },
                );
            }
        }
        for (receiver_position, streams) in inventory.receiver_b_streams.iter().enumerate() {
            let expected = if receiver_position as u16 == participant_position {
                84
            } else {
                56
            };
            if streams.len() != expected {
                return Err(PaddedContinuationError::InvalidGateMaterial);
            }
        }
        for other_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            inventory.own_receiver_pad_keys[usize::from(other_position)] = derived_subkey(
                pairwise_masters
                    .outgoing_to(other_position)
                    .ok_or(PaddedContinuationError::InvalidGateMaterial)?,
                context,
                DerivedStreamScope {
                    family: DERIVED_STREAM_FAMILY_JOINT_PAD,
                    subset: 0,
                    receiver_position: participant_position,
                    garbler_position: other_position,
                },
            );
            inventory.local_garbler_pad_keys[usize::from(other_position)] = derived_subkey(
                pairwise_masters
                    .incoming_from(other_position)
                    .ok_or(PaddedContinuationError::InvalidGateMaterial)?,
                context,
                DerivedStreamScope {
                    family: DERIVED_STREAM_FAMILY_JOINT_PAD,
                    subset: 0,
                    receiver_position: other_position,
                    garbler_position: participant_position,
                },
            );
        }
        Ok(inventory)
    }

    fn gate_material(
        &self,
        operation_ordinal: u32,
    ) -> Result<GateMaterial, PaddedContinuationError> {
        let own_position = self.participant_position;
        let mut material = GateMaterial {
            own_affine_a_constant: [0; PADDED_MODULE_VALUE_BYTE_LENGTH],
            own_affine_b_constant: [0; PADDED_MODULE_VALUE_BYTE_LENGTH],
            receivers: [ReceiverGateMaterial {
                affine_b_evaluation: [0; PADDED_MODULE_VALUE_BYTE_LENGTH],
                basis_pads: [[0; PADDED_MODULE_VALUE_BYTE_LENGTH]; FIELD_BIT_WIDTH],
            }; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
        };
        material.own_affine_b_constant =
            self.b_value(own_position, Gf16::ZERO, operation_ordinal)?;
        if material.own_affine_b_constant.iter().all(|byte| *byte == 0) {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        for garbler_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            let interpolation_weight = coordinate_interpolation_weight_at_zero(garbler_position)?;
            for basis in 0..FIELD_BIT_WIDTH {
                let mut pad = derived_module_value_from_subkey(
                    &self.own_receiver_pad_keys[usize::from(garbler_position)],
                    DerivedStreamAddress {
                        scope: DerivedStreamScope {
                            family: DERIVED_STREAM_FAMILY_JOINT_PAD,
                            subset: 0,
                            receiver_position: own_position,
                            garbler_position,
                        },
                        gate_ordinal: operation_ordinal,
                        basis: basis as u8,
                    },
                )?;
                module_add_scaled(
                    &mut material.own_affine_a_constant,
                    &pad,
                    interpolation_weight,
                );
                pad.zeroize();
            }
        }
        let point = Gf16::new((own_position + 1) as u8);
        for (receiver_position, receiver_material) in material.receivers.iter_mut().enumerate() {
            let receiver_position = receiver_position as u16;
            receiver_material.affine_b_evaluation =
                self.b_value(receiver_position, point, operation_ordinal)?;
            for (basis, pad) in receiver_material.basis_pads.iter_mut().enumerate() {
                *pad = derived_module_value_from_subkey(
                    &self.local_garbler_pad_keys[usize::from(receiver_position)],
                    DerivedStreamAddress {
                        scope: DerivedStreamScope {
                            family: DERIVED_STREAM_FAMILY_JOINT_PAD,
                            subset: 0,
                            receiver_position,
                            garbler_position: own_position,
                        },
                        gate_ordinal: operation_ordinal,
                        basis: basis as u8,
                    },
                )?;
            }
        }
        Ok(material)
    }

    fn b_value(
        &self,
        receiver_position: u16,
        point: Gf16,
        operation_ordinal: u32,
    ) -> Result<ModuleValue, PaddedContinuationError> {
        let streams = self
            .receiver_b_streams
            .get(usize::from(receiver_position))
            .ok_or(PaddedContinuationError::InvalidGateMaterial)?;
        let mut value = Zeroizing::new([0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH]);
        for stream in streams {
            let scalar = normalized_subset_basis(stream.subset, point)?;
            let mut module = derived_module_value_from_subkey(
                &stream.key,
                DerivedStreamAddress {
                    scope: DerivedStreamScope {
                        family: DERIVED_STREAM_FAMILY_JOINT_B,
                        subset: stream.subset,
                        receiver_position,
                        garbler_position: ABSENT_U16,
                    },
                    gate_ordinal: operation_ordinal,
                    basis: ABSENT_U8,
                },
            )?;
            module_add_scaled(&mut value, &module, scalar);
            module.zeroize();
        }
        Ok(*value)
    }
}

impl MaskStreamInventory {
    fn derive(
        context: &EvaluationContext,
        participant_position: u16,
        held_subset_keys: &[HeldSubsetKey],
    ) -> Result<Self, PaddedContinuationError> {
        validate_position(participant_position)?;
        let expected_slots = sender_subset_slots(participant_position);
        if held_subset_keys.len() != expected_slots.len()
            || held_subset_keys
                .iter()
                .zip(expected_slots)
                .any(|(key, (family, subset))| key.family != family || key.subset != subset)
        {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        let mut inventory = Self {
            matched: Vec::with_capacity(84),
            terminal: Vec::with_capacity(36),
        };
        for held_key in held_subset_keys {
            match held_key.family {
                SUBSET_FAMILY_SIZE_SEVEN => {
                    inventory.matched.push(MatchedMaskStreamKeys {
                        subset: held_key.subset,
                        low: derive_mask_subkey(
                            &held_key.key,
                            context,
                            DERIVED_STREAM_FAMILY_MATCHED_LOW,
                            held_key.subset,
                        ),
                        high_zero: derive_mask_subkey(
                            &held_key.key,
                            context,
                            DERIVED_STREAM_FAMILY_MATCHED_HIGH_ZERO,
                            held_key.subset,
                        ),
                    });
                }
                SUBSET_FAMILY_SIZE_EIGHT => {
                    inventory.terminal.push(TerminalMaskStreamKey {
                        subset: held_key.subset,
                        zero: derive_mask_subkey(
                            &held_key.key,
                            context,
                            DERIVED_STREAM_FAMILY_TERMINAL_ZERO,
                            held_key.subset,
                        ),
                    });
                }
                _ => return Err(PaddedContinuationError::InvalidGateMaterial),
            }
        }
        if inventory.matched.len() != 84 || inventory.terminal.len() != 36 {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        Ok(inventory)
    }

    fn matched_share(
        &self,
        participant_position: u16,
        conjunction_ordinal: u32,
    ) -> Result<(Gf16, Gf16), PaddedContinuationError> {
        validate_position(participant_position)?;
        let point = Gf16::new((participant_position + 1) as u8);
        let mut low = Gf16::ZERO;
        let mut high_zero = Gf16::ZERO;
        let high_first_bit = usize::try_from(conjunction_ordinal)
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .checked_mul(3 * FIELD_BIT_WIDTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        for streams in &self.matched {
            if read_packed_bits(
                &streams.low,
                DERIVED_STREAM_FAMILY_MATCHED_LOW,
                usize::try_from(conjunction_ordinal)
                    .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?,
                1,
            )? != 0
            {
                low = low.add(normalized_subset_basis(streams.subset, point)?);
            }
            let coefficients = read_packed_bits(
                &streams.high_zero,
                DERIVED_STREAM_FAMILY_MATCHED_HIGH_ZERO,
                high_first_bit,
                3 * FIELD_BIT_WIDTH,
            )?;
            let outside = outside_subset_product(streams.subset, point, SUBSET_FAMILY_SIZE_SEVEN)?;
            for degree in 1..=3_u8 {
                let shift = usize::from(degree - 1) * FIELD_BIT_WIDTH;
                let coefficient = Gf16::new(((coefficients >> shift) & 0x0f) as u8);
                high_zero =
                    high_zero.add(coefficient.multiply(point.power(degree)).multiply(outside));
            }
        }
        Ok((low, low.add(high_zero)))
    }

    fn terminal_share(
        &self,
        participant_position: u16,
        output_ordinal: u32,
    ) -> Result<Gf16, PaddedContinuationError> {
        validate_position(participant_position)?;
        let point = Gf16::new((participant_position + 1) as u8);
        let first_bit = usize::try_from(output_ordinal)
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .checked_mul(FIELD_BIT_WIDTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let mut share = Gf16::ZERO;
        for stream in &self.terminal {
            let coefficient = Gf16::new(read_packed_bits(
                &stream.zero,
                DERIVED_STREAM_FAMILY_TERMINAL_ZERO,
                first_bit,
                FIELD_BIT_WIDTH,
            )? as u8);
            let outside = outside_subset_product(stream.subset, point, SUBSET_FAMILY_SIZE_EIGHT)?;
            share = share.add(coefficient.multiply(point).multiply(outside));
        }
        Ok(share)
    }
}

fn derive_mask_subkey(
    master: &[u8; 32],
    context: &EvaluationContext,
    family: u8,
    subset: u16,
) -> [u8; 32] {
    derived_subkey(
        master,
        context,
        DerivedStreamScope {
            family,
            subset,
            receiver_position: ABSENT_U16,
            garbler_position: ABSENT_U16,
        },
    )
}

fn read_packed_bits(
    subkey: &[u8; 32],
    family: u8,
    first_bit: usize,
    bit_count: usize,
) -> Result<u16, PaddedContinuationError> {
    if bit_count == 0 || bit_count > 16 {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    let cipher =
        Aes256::new_from_slice(subkey).map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    let end_bit = first_bit
        .checked_add(bit_count)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let first_block = first_bit / 128;
    let last_block = (end_bit - 1) / 128;
    let mut result = 0_u16;
    for block_index in first_block..=last_block {
        let mut block = Block::<Aes256>::default();
        block[0] = DERIVED_STREAM_ADDRESS_VERSION;
        block[1] = family;
        block[2..6].copy_from_slice(
            &u32::try_from(block_index)
                .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        cipher.encrypt_block(&mut block);
        let block_start = block_index * 128;
        let overlap_start = first_bit.max(block_start);
        let overlap_end = end_bit.min(block_start + 128);
        for linear_bit in overlap_start..overlap_end {
            let source_offset = linear_bit - block_start;
            let target_offset = linear_bit - first_bit;
            result |=
                u16::from((block[source_offset / 8] >> (source_offset % 8)) & 1) << target_offset;
        }
        block.as_mut_slice().zeroize();
    }
    Ok(result)
}

fn outside_subset_product(
    subset: u16,
    point: Gf16,
    expected_size: u16,
) -> Result<Gf16, PaddedContinuationError> {
    let admitted_mask = (1_u16 << COMPLETION_PROFILE_PARTICIPANT_COUNT) - 1;
    if subset & !admitted_mask != 0 || subset.count_ones() != u32::from(expected_size) {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    Ok((0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
        .filter(|position| subset & (1_u16 << position) == 0)
        .fold(Gf16::ONE, |product, position| {
            product.multiply(point.add(Gf16::new((position + 1) as u8)))
        }))
}

pub struct PaddedTallyGenerationInitializationInput<'a> {
    pub participant_position: u16,
    pub source_bodies: &'a [Vec<u8>],
    pub source_signatures: &'a [Vec<u8>],
    pub allocation_nonce: &'a [u8],
    pub checkpoint_key: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedPaddedTallyChunkStep {
    pub chunk_ordinal: u32,
    pub chunk: Vec<u8>,
    pub chunk_identity: Hash512,
    pub next_checkpoint: Option<Vec<u8>>,
    pub manifest: Option<Vec<u8>>,
    pub manifest_identity: Option<Hash512>,
}

pub struct PaddedTallyEvaluationInitializationInput<'a> {
    pub manifests: &'a [Vec<u8>],
    pub signatures: &'a [Vec<u8>],
    pub checkpoint_key: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedPaddedTallyChunkStep {
    pub chunk_ordinal: u32,
    pub next_checkpoint: Option<Vec<u8>>,
    pub evaluated: Option<EvaluatedPaddedTallyBatch>,
}

struct PaddedTallyGenerationCheckpoint {
    context: EvaluationContext,
    participant_position: u16,
    allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    next_chunk_ordinal: usize,
    held_subset_keys: Vec<HeldSubsetKey>,
    pairwise_masters: PairwiseMasterInventory,
    initial_wire_values: Vec<u8>,
    live_wire_pairs: Vec<(usize, FieldPairs)>,
    continuation_keys: BTreeSet<ModuleValue>,
    chunk_identities: Vec<Hash512>,
}

struct PaddedTallyEvaluationCheckpoint {
    context: EvaluationContext,
    output_schema_identity: Hash512,
    next_chunk_ordinal: usize,
    batch_identity: Hash512,
    manifest_identities: [Hash512; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
    allocation_nonces:
        [[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH]; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
    expected_chunk_identities: Vec<Hash512>,
    active_wire_tokens: Vec<(usize, ParticipantFieldTokens)>,
}

impl Drop for PaddedTallyGenerationCheckpoint {
    fn drop(&mut self) {
        self.initial_wire_values.zeroize();
        for (_, pairs) in &mut self.live_wire_pairs {
            pairs.zeroize();
        }
        while let Some(mut key) = self.continuation_keys.pop_first() {
            key.zeroize();
        }
    }
}

impl Drop for PaddedTallyEvaluationCheckpoint {
    fn drop(&mut self) {
        for (_, participant_tokens) in &mut self.active_wire_tokens {
            participant_tokens.zeroize();
        }
    }
}

pub fn initialize_padded_tally_generation(
    capability: &VerifiedFinalityCapability,
    roster: &Roster,
    preparation: &VerifiedCompletePreparation,
    input: PaddedTallyGenerationInitializationInput<'_>,
) -> Result<Vec<u8>, PaddedContinuationError> {
    validate_capability(capability)?;
    validate_preparation_context(capability, preparation, input.participant_position)?;
    validate_checkpoint_key(input.checkpoint_key)?;
    let allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH] = input
        .allocation_nonce
        .try_into()
        .map_err(|_| PaddedContinuationError::InvalidBody)?;
    let target = capability.target.context();
    let context = EvaluationContext {
        target_identity: capability.target_identity,
        circuit_identity: target.circuit_identity,
        top_count: target.top_count,
    };
    let plan = PaddedTallyPlan::compile(target.top_count)?;
    let mut initial_wire_values = Zeroizing::new(derive_initial_wire_values(
        capability,
        roster,
        preparation,
        input.participant_position,
        input.source_bodies,
        input.source_signatures,
    )?);
    if initial_wire_values.len() != plan.circuit.input_bit_count() {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    let mut held_subset_key_bytes =
        encode_held_subset_keys(input.participant_position, &preparation.held_subset_keys)
            .map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    let held_subset_keys =
        decode_held_subset_keys(input.participant_position, &held_subset_key_bytes)
            .map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    held_subset_key_bytes.zeroize();
    let mut pairwise_master_bytes = preparation.pairwise_masters.encode_position_ordered();
    let pairwise_masters = PairwiseMasterInventory::decode_position_ordered(
        input.participant_position,
        &pairwise_master_bytes,
    )
    .map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    pairwise_master_bytes.zeroize();
    let checkpoint = PaddedTallyGenerationCheckpoint {
        context,
        participant_position: input.participant_position,
        allocation_nonce,
        next_chunk_ordinal: 0,
        held_subset_keys,
        pairwise_masters,
        initial_wire_values: core::mem::take(&mut *initial_wire_values),
        live_wire_pairs: Vec::new(),
        continuation_keys: BTreeSet::new(),
        chunk_identities: Vec::new(),
    };
    encode_generation_checkpoint(&checkpoint, &plan, input.checkpoint_key)
}

pub fn generate_next_padded_tally_chunk(
    checkpoint_key: &[u8],
    checkpoint_bytes: &[u8],
    label_entropy: &[u8],
) -> Result<GeneratedPaddedTallyChunkStep, PaddedContinuationError> {
    validate_checkpoint_key(checkpoint_key)?;
    let mut checkpoint = decode_generation_checkpoint(checkpoint_bytes, checkpoint_key)?;
    let plan = PaddedTallyPlan::compile(checkpoint.context.top_count)?;
    validate_generation_checkpoint(&checkpoint, &plan)?;
    let chunk_ordinal = checkpoint.next_chunk_ordinal;
    let entropy_range = plan.chunk_entropy_range(chunk_ordinal)?;
    if label_entropy.len() != entropy_range.len() {
        return Err(PaddedContinuationError::InvalidLabelEntropy);
    }
    let descriptor = *plan
        .descriptors
        .get(chunk_ordinal)
        .ok_or(PaddedContinuationError::InvalidPlan)?;
    let operation_ordinals = plan.operations[descriptor.first_operation..descriptor.operation_end]
        .iter()
        .filter_map(|operation| match operation.kind {
            PlannedOperationKind::Conjunction {
                operation_ordinal, ..
            } => Some(operation_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut gate_streams = GateStreamInventory::derive(
        &checkpoint.context,
        checkpoint.participant_position,
        &checkpoint.held_subset_keys,
        &checkpoint.pairwise_masters,
    )?;
    let mut gate_material = operation_ordinals
        .iter()
        .map(|operation_ordinal| gate_streams.gate_material(*operation_ordinal))
        .collect::<Result<Vec<_>, _>>()?;
    gate_streams.zeroize();
    validate_operation_fresh_gate_material(&gate_material)?;
    for material in &gate_material {
        let mut first = material.own_affine_a_constant;
        let mut second = first;
        module_xor(&mut second, &material.own_affine_b_constant);
        if !checkpoint.continuation_keys.insert(first)
            || !checkpoint.continuation_keys.insert(second)
        {
            first.zeroize();
            gate_material.zeroize();
            second.zeroize();
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        first.zeroize();
        second.zeroize();
    }
    let mut mask_streams = MaskStreamInventory::derive(
        &checkpoint.context,
        checkpoint.participant_position,
        &checkpoint.held_subset_keys,
    )?;
    let generated = generate_one_chunk(
        &plan,
        &mut checkpoint,
        descriptor,
        label_entropy,
        &gate_material,
        &mask_streams,
    );
    gate_material.zeroize();
    mask_streams.zeroize();
    let (chunk, chunk_identity) = generated?;
    checkpoint.chunk_identities.push(chunk_identity);
    checkpoint.next_chunk_ordinal += 1;
    let finished = checkpoint.next_chunk_ordinal == plan.descriptors.len();
    let (next_checkpoint, manifest, manifest_identity) = if finished {
        let manifest = encode_manifest(
            &checkpoint.context,
            checkpoint.participant_position,
            &checkpoint.allocation_nonce,
            &plan,
            &checkpoint.chunk_identities,
        )?;
        let manifest_identity = hash_bytes(MANIFEST_IDENTITY_DOMAIN, &manifest)?;
        (None, Some(manifest), Some(manifest_identity))
    } else {
        (
            Some(encode_generation_checkpoint(
                &checkpoint,
                &plan,
                checkpoint_key,
            )?),
            None,
            None,
        )
    };
    Ok(GeneratedPaddedTallyChunkStep {
        chunk_ordinal: checked_u32(chunk_ordinal)?,
        chunk,
        chunk_identity,
        next_checkpoint,
        manifest,
        manifest_identity,
    })
}

pub fn initialize_padded_tally_evaluation(
    capability: &VerifiedFinalityCapability,
    roster: &Roster,
    input: PaddedTallyEvaluationInitializationInput<'_>,
) -> Result<Vec<u8>, PaddedContinuationError> {
    validate_capability(capability)?;
    require_roster_identity(roster, capability.target.context().roster_identity)
        .map_err(|_| PaddedContinuationError::InvalidContext)?;
    validate_checkpoint_key(input.checkpoint_key)?;
    let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
    if input.manifests.len() != participant_count || input.signatures.len() != participant_count {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    let target = capability.target.context();
    let context = EvaluationContext {
        target_identity: capability.target_identity,
        circuit_identity: target.circuit_identity,
        top_count: target.top_count,
    };
    let plan = PaddedTallyPlan::compile(context.top_count)?;
    let mut manifest_identities = Vec::with_capacity(participant_count);
    let mut allocation_nonces = Vec::with_capacity(participant_count);
    let mut expected_chunk_identities = Vec::with_capacity(
        participant_count
            .checked_mul(plan.descriptors.len())
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
    );
    let mut seen_manifest_identities = BTreeSet::new();
    let mut seen_allocation_nonces = BTreeSet::new();
    let mut seen_chunk_identities = BTreeSet::new();
    for participant_position in 0..participant_count {
        let manifest_identity = hash_bytes(
            MANIFEST_IDENTITY_DOMAIN,
            &input.manifests[participant_position],
        )?;
        if !seen_manifest_identities.insert(*manifest_identity.as_bytes()) {
            return Err(PaddedContinuationError::InvalidManifest);
        }
        let carrier = ActionSignatureCarrier::decode(
            COMPLETION_PROFILE_PARTICIPANT_COUNT,
            &input.signatures[participant_position],
        )
        .map_err(|_| PaddedContinuationError::InvalidSignature)?;
        let verification_key = signing_verification_key(roster, participant_position as u16)
            .map_err(|_| PaddedContinuationError::InvalidSignature)?;
        carrier
            .verify(
                participant_position as u16,
                ActionSignaturePurpose::Activation,
                manifest_identity,
                verification_key,
            )
            .map_err(|_| PaddedContinuationError::InvalidSignature)?;
        let parsed =
            ParsedTallyManifest::new(&input.manifests[participant_position], &context, &plan)?;
        if parsed.participant_position != participant_position as u16 {
            return Err(PaddedContinuationError::DuplicateParticipant);
        }
        if !seen_allocation_nonces.insert(parsed.allocation_nonce) {
            return Err(PaddedContinuationError::DuplicateAllocationNonce);
        }
        for chunk_identity in &parsed.chunk_identities {
            if !seen_chunk_identities.insert(*chunk_identity.as_bytes()) {
                return Err(PaddedContinuationError::InvalidChunk);
            }
        }
        manifest_identities.push(manifest_identity);
        allocation_nonces.push(parsed.allocation_nonce);
        expected_chunk_identities.extend(parsed.chunk_identities);
    }
    let manifest_identities: [Hash512; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize] =
        manifest_identities
            .try_into()
            .map_err(|_| PaddedContinuationError::WrongParticipantCount)?;
    let allocation_nonces: [[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH];
        COMPLETION_PROFILE_PARTICIPANT_COUNT as usize] = allocation_nonces
        .try_into()
        .map_err(|_| PaddedContinuationError::WrongParticipantCount)?;
    let checkpoint = PaddedTallyEvaluationCheckpoint {
        context,
        output_schema_identity: target.output_schema_identity,
        next_chunk_ordinal: 0,
        batch_identity: padded_tally_batch_identity(&context, &manifest_identities)?,
        manifest_identities,
        allocation_nonces,
        expected_chunk_identities,
        active_wire_tokens: Vec::new(),
    };
    encode_evaluation_checkpoint(&checkpoint, &plan, input.checkpoint_key)
}

fn validate_checkpoint_key(key: &[u8]) -> Result<(), PaddedContinuationError> {
    if key.len() != GENERATION_CHECKPOINT_KEY_BYTE_LENGTH || key.iter().all(|byte| *byte == 0) {
        return Err(PaddedContinuationError::InvalidBody);
    }
    Ok(())
}

fn validate_generation_checkpoint(
    checkpoint: &PaddedTallyGenerationCheckpoint,
    plan: &PaddedTallyPlan,
) -> Result<(), PaddedContinuationError> {
    validate_position(checkpoint.participant_position)?;
    if checkpoint.next_chunk_ordinal >= plan.descriptors.len()
        || checkpoint.chunk_identities.len() != checkpoint.next_chunk_ordinal
    {
        return Err(PaddedContinuationError::InvalidChunk);
    }
    let expected_initial_count = if checkpoint.next_chunk_ordinal == 0 {
        plan.circuit.input_bit_count()
    } else {
        0
    };
    if checkpoint.initial_wire_values.len() != expected_initial_count
        || checkpoint
            .initial_wire_values
            .iter()
            .any(|value| *value > 0x0f)
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let expected_live_wires = if checkpoint.next_chunk_ordinal == 0 {
        Vec::new()
    } else {
        plan.live_wires_after_chunk(checkpoint.next_chunk_ordinal - 1)?
    };
    if checkpoint.live_wire_pairs.len() != expected_live_wires.len()
        || checkpoint
            .live_wire_pairs
            .iter()
            .zip(expected_live_wires)
            .any(|((wire, _), expected)| *wire != expected)
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let processed_operation_end = if checkpoint.next_chunk_ordinal == 0 {
        0
    } else {
        plan.descriptors[checkpoint.next_chunk_ordinal - 1].operation_end
    };
    let expected_continuation_key_count = plan.operations[..processed_operation_end]
        .iter()
        .filter(|operation| matches!(operation.kind, PlannedOperationKind::Conjunction { .. }))
        .count()
        .checked_mul(2)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    if checkpoint.continuation_keys.len() != expected_continuation_key_count {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    let mut held_bytes = Zeroizing::new(
        encode_held_subset_keys(
            checkpoint.participant_position,
            &checkpoint.held_subset_keys,
        )
        .map_err(|_| PaddedContinuationError::InvalidGateMaterial)?,
    );
    let mut pairwise_bytes = Zeroizing::new(checkpoint.pairwise_masters.encode_position_ordered());
    if held_bytes.len() != HELD_SUBSET_KEY_VECTOR_BYTE_LENGTH
        || pairwise_bytes.len() != PAIRWISE_MASTER_INVENTORY_BYTE_LENGTH
    {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    held_bytes.zeroize();
    pairwise_bytes.zeroize();
    Ok(())
}

fn encode_generation_checkpoint(
    checkpoint: &PaddedTallyGenerationCheckpoint,
    plan: &PaddedTallyPlan,
    checkpoint_key: &[u8],
) -> Result<Vec<u8>, PaddedContinuationError> {
    validate_checkpoint_key(checkpoint_key)?;
    validate_generation_checkpoint(checkpoint, plan)?;
    let expected_length = GENERATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH
        .checked_add(checkpoint.initial_wire_values.len())
        .and_then(|length| {
            length.checked_add(
                checkpoint
                    .live_wire_pairs
                    .len()
                    .checked_mul(4 + CHECKPOINT_FIELD_PAIRS_BYTE_LENGTH)?,
            )
        })
        .and_then(|length| {
            length.checked_add(
                checkpoint
                    .continuation_keys
                    .len()
                    .checked_mul(PADDED_MODULE_VALUE_BYTE_LENGTH)?,
            )
        })
        .and_then(|length| {
            length.checked_add(
                checkpoint
                    .chunk_identities
                    .len()
                    .checked_mul(Hash512::BYTE_LENGTH)?,
            )
        })
        .and_then(|length| length.checked_add(GENERATION_CHECKPOINT_TAG_BYTE_LENGTH))
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected_length));
    bytes.extend_from_slice(&GENERATION_CHECKPOINT_MAGIC);
    bytes.extend_from_slice(&GENERATION_CHECKPOINT_VERSION.to_le_bytes());
    bytes.extend_from_slice(checkpoint.context.target_identity.as_bytes());
    bytes.extend_from_slice(checkpoint.context.circuit_identity.as_bytes());
    bytes.extend_from_slice(&checkpoint.participant_position.to_le_bytes());
    bytes.extend_from_slice(&checkpoint.context.top_count.to_le_bytes());
    bytes.extend_from_slice(&checkpoint.allocation_nonce);
    bytes.extend_from_slice(&checked_u32(checkpoint.next_chunk_ordinal)?.to_le_bytes());
    let mut held_subset_key_bytes = encode_held_subset_keys(
        checkpoint.participant_position,
        &checkpoint.held_subset_keys,
    )
    .map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    bytes.extend_from_slice(&held_subset_key_bytes);
    held_subset_key_bytes.zeroize();
    let mut pairwise_master_bytes = checkpoint.pairwise_masters.encode_position_ordered();
    bytes.extend_from_slice(&pairwise_master_bytes);
    pairwise_master_bytes.zeroize();
    bytes.extend_from_slice(
        &u16::try_from(checkpoint.initial_wire_values.len())
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u16::try_from(checkpoint.live_wire_pairs.len())
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&checked_u32(checkpoint.continuation_keys.len())?.to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(checkpoint.chunk_identities.len())
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    if bytes.len() != GENERATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH {
        bytes.zeroize();
        return Err(PaddedContinuationError::InvalidBody);
    }
    bytes.extend_from_slice(&checkpoint.initial_wire_values);
    for (wire, pairs) in &checkpoint.live_wire_pairs {
        bytes.extend_from_slice(&checked_u32(*wire)?.to_le_bytes());
        encode_checkpoint_field_pairs(&mut bytes, pairs)?;
    }
    for key in &checkpoint.continuation_keys {
        bytes.extend_from_slice(key);
    }
    for identity in &checkpoint.chunk_identities {
        bytes.extend_from_slice(identity.as_bytes());
    }
    let tag = kmac256::<GENERATION_CHECKPOINT_TAG_BYTE_LENGTH>(
        checkpoint_key,
        &bytes,
        GENERATION_CHECKPOINT_CUSTOMIZATION,
    );
    bytes.extend_from_slice(&tag);
    if bytes.len() != expected_length {
        bytes.zeroize();
        return Err(PaddedContinuationError::InvalidBody);
    }
    Ok(core::mem::take(&mut *bytes))
}

fn decode_generation_checkpoint(
    bytes: &[u8],
    checkpoint_key: &[u8],
) -> Result<PaddedTallyGenerationCheckpoint, PaddedContinuationError> {
    validate_checkpoint_key(checkpoint_key)?;
    if bytes.len()
        < GENERATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH + GENERATION_CHECKPOINT_TAG_BYTE_LENGTH
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let body_length = bytes.len() - GENERATION_CHECKPOINT_TAG_BYTE_LENGTH;
    let (body, supplied_tag) = bytes.split_at(body_length);
    let mut expected_tag = kmac256::<GENERATION_CHECKPOINT_TAG_BYTE_LENGTH>(
        checkpoint_key,
        body,
        GENERATION_CHECKPOINT_CUSTOMIZATION,
    );
    let tag_is_valid = constant_time_equal(&expected_tag, supplied_tag);
    expected_tag.zeroize();
    if !tag_is_valid {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let mut reader = ByteReader::new(body);
    if reader.read_array::<4>()? != GENERATION_CHECKPOINT_MAGIC
        || reader.read_u16()? != GENERATION_CHECKPOINT_VERSION
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let context = EvaluationContext {
        target_identity: Hash512::from_bytes(reader.read_array()?),
        circuit_identity: Hash512::from_bytes(reader.read_array()?),
        top_count: 0,
    };
    let participant_position = reader.read_u16()?;
    validate_position(participant_position)?;
    let context = EvaluationContext {
        top_count: reader.read_u16()?,
        ..context
    };
    let allocation_nonce = reader.read_array()?;
    let next_chunk_ordinal = usize::try_from(reader.read_u32()?)
        .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
    let mut held_subset_key_bytes = reader
        .read_exact(HELD_SUBSET_KEY_VECTOR_BYTE_LENGTH)?
        .to_vec();
    let held_subset_keys = decode_held_subset_keys(participant_position, &held_subset_key_bytes)
        .map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    held_subset_key_bytes.zeroize();
    let mut pairwise_master_bytes = reader
        .read_exact(PAIRWISE_MASTER_INVENTORY_BYTE_LENGTH)?
        .to_vec();
    let pairwise_masters = PairwiseMasterInventory::decode_position_ordered(
        participant_position,
        &pairwise_master_bytes,
    )
    .map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    pairwise_master_bytes.zeroize();
    let initial_count = usize::from(reader.read_u16()?);
    let live_count = usize::from(reader.read_u16()?);
    let continuation_count = usize::try_from(reader.read_u32()?)
        .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
    let chunk_identity_count = usize::from(reader.read_u16()?);
    let plan = PaddedTallyPlan::compile(context.top_count)?;
    if initial_count > plan.circuit.input_bit_count()
        || live_count > plan.maximum_live_wire_count
        || continuation_count > plan.conjunction_count * 2
        || chunk_identity_count > plan.descriptors.len()
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let mut initial_wire_values = Zeroizing::new(reader.read_exact(initial_count)?.to_vec());
    let mut live_wire_pairs = Zeroizing::new(Vec::with_capacity(live_count));
    let mut previous_wire = None;
    for _ in 0..live_count {
        let wire = usize::try_from(reader.read_u32()?)
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
        if previous_wire.is_some_and(|previous| wire <= previous) {
            return Err(PaddedContinuationError::InvalidBody);
        }
        live_wire_pairs.push((wire, decode_checkpoint_field_pairs(&mut reader)?));
        previous_wire = Some(wire);
    }
    let mut continuation_keys = BTreeSet::new();
    let mut previous_key = None;
    for _ in 0..continuation_count {
        let key = reader.read_array::<PADDED_MODULE_VALUE_BYTE_LENGTH>()?;
        if previous_key.is_some_and(|previous: ModuleValue| key <= previous)
            || !continuation_keys.insert(key)
        {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        previous_key = Some(key);
    }
    let chunk_identities = (0..chunk_identity_count)
        .map(|_| Ok(Hash512::from_bytes(reader.read_array()?)))
        .collect::<Result<Vec<_>, PaddedContinuationError>>()?;
    reader.finish()?;
    let checkpoint = PaddedTallyGenerationCheckpoint {
        context,
        participant_position,
        allocation_nonce,
        next_chunk_ordinal,
        held_subset_keys,
        pairwise_masters,
        initial_wire_values: core::mem::take(&mut *initial_wire_values),
        live_wire_pairs: core::mem::take(&mut *live_wire_pairs),
        continuation_keys,
        chunk_identities,
    };
    validate_generation_checkpoint(&checkpoint, &plan)?;
    Ok(checkpoint)
}

fn validate_evaluation_checkpoint(
    checkpoint: &PaddedTallyEvaluationCheckpoint,
    plan: &PaddedTallyPlan,
) -> Result<(), PaddedContinuationError> {
    let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
    if checkpoint.next_chunk_ordinal >= plan.descriptors.len()
        || checkpoint.expected_chunk_identities.len()
            != participant_count
                .checked_mul(plan.descriptors.len())
                .ok_or(PaddedContinuationError::ArithmeticOverflow)?
    {
        return Err(PaddedContinuationError::InvalidChunk);
    }
    let mut seen_manifests = BTreeSet::new();
    let mut seen_nonces = BTreeSet::new();
    let mut seen_chunks = BTreeSet::new();
    if checkpoint
        .manifest_identities
        .iter()
        .any(|identity| !seen_manifests.insert(*identity.as_bytes()))
        || checkpoint
            .allocation_nonces
            .iter()
            .any(|nonce| !seen_nonces.insert(*nonce))
        || checkpoint
            .expected_chunk_identities
            .iter()
            .any(|identity| !seen_chunks.insert(*identity.as_bytes()))
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    if checkpoint.batch_identity
        != padded_tally_batch_identity(&checkpoint.context, &checkpoint.manifest_identities)?
    {
        return Err(PaddedContinuationError::InvalidContext);
    }
    let expected_live_wires = if checkpoint.next_chunk_ordinal == 0 {
        Vec::new()
    } else {
        plan.live_wires_after_chunk(checkpoint.next_chunk_ordinal - 1)?
    };
    if checkpoint.active_wire_tokens.len() != expected_live_wires.len()
        || checkpoint
            .active_wire_tokens
            .iter()
            .zip(expected_live_wires)
            .any(|((wire, participant_tokens), expected_wire)| {
                *wire != expected_wire
                    || participant_tokens
                        .iter()
                        .flatten()
                        .any(|token| token.color > 1)
            })
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    Ok(())
}

fn encode_evaluation_checkpoint(
    checkpoint: &PaddedTallyEvaluationCheckpoint,
    plan: &PaddedTallyPlan,
    checkpoint_key: &[u8],
) -> Result<Vec<u8>, PaddedContinuationError> {
    validate_checkpoint_key(checkpoint_key)?;
    validate_evaluation_checkpoint(checkpoint, plan)?;
    let active_wire_byte_length = checkpoint
        .active_wire_tokens
        .len()
        .checked_mul(
            4 + usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
                * FIELD_BIT_WIDTH
                * PADDED_TOKEN_BYTE_LENGTH,
        )
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let expected_length = EVALUATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH
        .checked_add(
            checkpoint
                .expected_chunk_identities
                .len()
                .checked_mul(Hash512::BYTE_LENGTH)
                .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
        )
        .and_then(|length| length.checked_add(active_wire_byte_length))
        .and_then(|length| length.checked_add(EVALUATION_CHECKPOINT_TAG_BYTE_LENGTH))
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected_length));
    bytes.extend_from_slice(&EVALUATION_CHECKPOINT_MAGIC);
    bytes.extend_from_slice(&EVALUATION_CHECKPOINT_VERSION.to_le_bytes());
    bytes.extend_from_slice(checkpoint.context.target_identity.as_bytes());
    bytes.extend_from_slice(checkpoint.context.circuit_identity.as_bytes());
    bytes.extend_from_slice(checkpoint.output_schema_identity.as_bytes());
    bytes.extend_from_slice(&COMPLETION_PROFILE_PARTICIPANT_COUNT.to_le_bytes());
    bytes.extend_from_slice(&COMPLETION_PROFILE_OPTION_COUNT.to_le_bytes());
    bytes.extend_from_slice(&checkpoint.context.top_count.to_le_bytes());
    bytes.extend_from_slice(&checked_u32(checkpoint.next_chunk_ordinal)?.to_le_bytes());
    bytes.extend_from_slice(checkpoint.batch_identity.as_bytes());
    for identity in &checkpoint.manifest_identities {
        bytes.extend_from_slice(identity.as_bytes());
    }
    for nonce in &checkpoint.allocation_nonces {
        bytes.extend_from_slice(nonce);
    }
    bytes.extend_from_slice(
        &u16::try_from(plan.descriptors.len())
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u16::try_from(checkpoint.active_wire_tokens.len())
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    if bytes.len() != EVALUATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH {
        return Err(PaddedContinuationError::InvalidBody);
    }
    for identity in &checkpoint.expected_chunk_identities {
        bytes.extend_from_slice(identity.as_bytes());
    }
    for (wire, participant_tokens) in &checkpoint.active_wire_tokens {
        bytes.extend_from_slice(&checked_u32(*wire)?.to_le_bytes());
        for field_tokens in participant_tokens {
            for token in field_tokens {
                write_token(&mut bytes, *token);
            }
        }
    }
    let tag = kmac256::<EVALUATION_CHECKPOINT_TAG_BYTE_LENGTH>(
        checkpoint_key,
        &bytes,
        EVALUATION_CHECKPOINT_CUSTOMIZATION,
    );
    bytes.extend_from_slice(&tag);
    if bytes.len() != expected_length {
        return Err(PaddedContinuationError::InvalidBody);
    }
    Ok(core::mem::take(&mut *bytes))
}

fn decode_evaluation_checkpoint(
    bytes: &[u8],
    checkpoint_key: &[u8],
) -> Result<PaddedTallyEvaluationCheckpoint, PaddedContinuationError> {
    validate_checkpoint_key(checkpoint_key)?;
    if bytes.len()
        < EVALUATION_CHECKPOINT_FIXED_HEADER_BYTE_LENGTH + EVALUATION_CHECKPOINT_TAG_BYTE_LENGTH
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let body_length = bytes.len() - EVALUATION_CHECKPOINT_TAG_BYTE_LENGTH;
    let (body, supplied_tag) = bytes.split_at(body_length);
    let mut expected_tag = kmac256::<EVALUATION_CHECKPOINT_TAG_BYTE_LENGTH>(
        checkpoint_key,
        body,
        EVALUATION_CHECKPOINT_CUSTOMIZATION,
    );
    let tag_is_valid = constant_time_equal(&expected_tag, supplied_tag);
    expected_tag.zeroize();
    if !tag_is_valid {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let mut reader = ByteReader::new(body);
    if reader.read_array::<4>()? != EVALUATION_CHECKPOINT_MAGIC
        || reader.read_u16()? != EVALUATION_CHECKPOINT_VERSION
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let context = EvaluationContext {
        target_identity: Hash512::from_bytes(reader.read_array()?),
        circuit_identity: Hash512::from_bytes(reader.read_array()?),
        top_count: 0,
    };
    let output_schema_identity = Hash512::from_bytes(reader.read_array()?);
    if reader.read_u16()? != COMPLETION_PROFILE_PARTICIPANT_COUNT
        || reader.read_u16()? != COMPLETION_PROFILE_OPTION_COUNT
    {
        return Err(PaddedContinuationError::InvalidContext);
    }
    let context = EvaluationContext {
        top_count: reader.read_u16()?,
        ..context
    };
    let next_chunk_ordinal = usize::try_from(reader.read_u32()?)
        .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
    let batch_identity = Hash512::from_bytes(reader.read_array()?);
    let mut manifest_identities = [Hash512::from_bytes([0; Hash512::BYTE_LENGTH]);
        COMPLETION_PROFILE_PARTICIPANT_COUNT as usize];
    for identity in &mut manifest_identities {
        *identity = Hash512::from_bytes(reader.read_array()?);
    }
    let mut allocation_nonces = [[0_u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH];
        COMPLETION_PROFILE_PARTICIPANT_COUNT as usize];
    for nonce in &mut allocation_nonces {
        *nonce = reader.read_array()?;
    }
    let chunk_count = usize::from(reader.read_u16()?);
    let live_count = usize::from(reader.read_u16()?);
    let plan = PaddedTallyPlan::compile(context.top_count)?;
    if chunk_count != plan.descriptors.len() || live_count > plan.maximum_live_wire_count {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let expected_identity_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        .checked_mul(chunk_count)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let expected_chunk_identities = (0..expected_identity_count)
        .map(|_| Ok(Hash512::from_bytes(reader.read_array()?)))
        .collect::<Result<Vec<_>, PaddedContinuationError>>()?;
    let mut active_wire_tokens = Zeroizing::new(Vec::with_capacity(live_count));
    let mut previous_wire = None;
    for _ in 0..live_count {
        let wire = usize::try_from(reader.read_u32()?)
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?;
        if previous_wire.is_some_and(|previous| wire <= previous) {
            return Err(PaddedContinuationError::InvalidBody);
        }
        let mut participant_tokens = [[Token {
            label: [0; PADDED_LABEL_BYTE_LENGTH],
            color: 0,
        }; FIELD_BIT_WIDTH];
            COMPLETION_PROFILE_PARTICIPANT_COUNT as usize];
        for field_tokens in &mut participant_tokens {
            *field_tokens = read_field_tokens(&mut reader)?;
        }
        active_wire_tokens.push((wire, participant_tokens));
        previous_wire = Some(wire);
    }
    reader.finish()?;
    let checkpoint = PaddedTallyEvaluationCheckpoint {
        context,
        output_schema_identity,
        next_chunk_ordinal,
        batch_identity,
        manifest_identities,
        allocation_nonces,
        expected_chunk_identities,
        active_wire_tokens: core::mem::take(&mut *active_wire_tokens),
    };
    validate_evaluation_checkpoint(&checkpoint, &plan)?;
    Ok(checkpoint)
}

fn encode_checkpoint_field_pairs(
    bytes: &mut Vec<u8>,
    pairs: &FieldPairs,
) -> Result<(), PaddedContinuationError> {
    for pair in pairs {
        if pair.tokens[0].color > 1
            || pair.tokens[1].color != pair.tokens[0].color ^ 1
            || pair.tokens[0].label == pair.tokens[1].label
        {
            return Err(PaddedContinuationError::InvalidLabelEntropy);
        }
        bytes.extend_from_slice(&pair.tokens[0].label);
        bytes.extend_from_slice(&pair.tokens[1].label);
        bytes.push(pair.tokens[0].color);
    }
    Ok(())
}

fn decode_checkpoint_field_pairs(
    reader: &mut ByteReader<'_>,
) -> Result<FieldPairs, PaddedContinuationError> {
    let mut pairs = [TokenPair {
        tokens: [
            Token {
                label: [0; PADDED_LABEL_BYTE_LENGTH],
                color: 0,
            },
            Token {
                label: [0; PADDED_LABEL_BYTE_LENGTH],
                color: 1,
            },
        ],
    }; FIELD_BIT_WIDTH];
    for pair in &mut pairs {
        let first_label = reader.read_array()?;
        let second_label = reader.read_array()?;
        let first_color = reader.read_u8()?;
        if first_label == second_label || first_color > 1 {
            pairs.zeroize();
            return Err(PaddedContinuationError::InvalidLabelEntropy);
        }
        *pair = TokenPair {
            tokens: [
                Token {
                    label: first_label,
                    color: first_color,
                },
                Token {
                    label: second_label,
                    color: first_color ^ 1,
                },
            ],
        };
    }
    Ok(pairs)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn generate_one_chunk(
    plan: &PaddedTallyPlan,
    checkpoint: &mut PaddedTallyGenerationCheckpoint,
    descriptor: ChunkDescriptor,
    label_entropy: &[u8],
    gate_material: &[GateMaterial],
    mask_streams: &MaskStreamInventory,
) -> Result<(Vec<u8>, Hash512), PaddedContinuationError> {
    let wire_count = plan
        .circuit
        .input_bit_count()
        .checked_add(plan.operations.len())
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let mut wire_pairs = Zeroizing::new(vec![None; wire_count]);
    for (wire, pairs) in &checkpoint.live_wire_pairs {
        *wire_pairs
            .get_mut(*wire)
            .ok_or(PaddedContinuationError::InvalidBody)? = Some(*pairs);
    }
    let previous_chunk_identity = checkpoint
        .chunk_identities
        .last()
        .copied()
        .unwrap_or(Hash512::from_bytes([0; Hash512::BYTE_LENGTH]));
    let mut chunk = Vec::with_capacity(descriptor.chunk_byte_length()?);
    write_chunk_header(
        &mut chunk,
        &checkpoint.context,
        checkpoint.participant_position,
        &checkpoint.allocation_nonce,
        checkpoint.next_chunk_ordinal,
        descriptor,
        previous_chunk_identity,
    )?;
    let mut entropy = LabelEntropyCursor::new(label_entropy);
    if descriptor.includes_initial {
        if checkpoint.next_chunk_ordinal != 0
            || checkpoint.initial_wire_values.len() != plan.circuit.input_bit_count()
        {
            return Err(PaddedContinuationError::InvalidBody);
        }
        for (wire_index, value) in checkpoint.initial_wire_values.iter().copied().enumerate() {
            let pairs = entropy.read_field_pairs()?;
            for (basis, pair) in pairs.iter().enumerate() {
                write_token(&mut chunk, pair.tokens[usize::from((value >> basis) & 1)]);
            }
            wire_pairs[wire_index] = Some(pairs);
        }
    }
    let mut gate_material_index = 0_usize;
    for operation_index in descriptor.first_operation..descriptor.operation_end {
        let operation = plan
            .circuit
            .operations()
            .get(operation_index)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        let planned = plan.operations[operation_index];
        let output_wire = plan
            .circuit
            .input_bit_count()
            .checked_add(operation_index)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let output_pairs = match (operation, planned.kind) {
            (BooleanOperation::Constant(value), PlannedOperationKind::Constant) => {
                let pairs = entropy.read_field_pairs()?;
                let field_value = u8::from(*value);
                for (basis, pair) in pairs.iter().enumerate() {
                    write_token(
                        &mut chunk,
                        pair.tokens[usize::from((field_value >> basis) & 1)],
                    );
                }
                pairs
            }
            (
                BooleanOperation::ExclusiveOr {
                    left_wire,
                    right_wire,
                },
                PlannedOperationKind::Linear { operation_ordinal },
            ) => generate_linear_payload(
                &mut chunk,
                &checkpoint.context,
                &checkpoint.allocation_nonce,
                checkpoint.participant_position,
                operation_ordinal,
                required_wire_pairs(&wire_pairs, *left_wire)?,
                required_wire_pairs(&wire_pairs, *right_wire)?,
                &mut entropy,
            )?,
            (
                BooleanOperation::Conjunction {
                    left_wire,
                    right_wire,
                },
                PlannedOperationKind::Conjunction {
                    operation_ordinal,
                    conjunction_ordinal,
                },
            ) => {
                let material = gate_material
                    .get(gate_material_index)
                    .ok_or(PaddedContinuationError::InvalidGateMaterial)?;
                gate_material_index += 1;
                let (low_mask_share, high_mask_share) = mask_streams
                    .matched_share(checkpoint.participant_position, conjunction_ordinal)?;
                generate_gate_payload(
                    &mut chunk,
                    &checkpoint.context,
                    &checkpoint.allocation_nonce,
                    checkpoint.participant_position,
                    operation_ordinal,
                    required_wire_pairs(&wire_pairs, *left_wire)?,
                    required_wire_pairs(&wire_pairs, *right_wire)?,
                    low_mask_share,
                    high_mask_share,
                    material,
                    &mut entropy,
                )?
            }
            (BooleanOperation::Negation { input_wire }, PlannedOperationKind::Negation) => {
                let mut pairs = required_wire_pairs(&wire_pairs, *input_wire)?;
                pairs[0].tokens.swap(0, 1);
                pairs
            }
            _ => return Err(PaddedContinuationError::InvalidPlan),
        };
        wire_pairs[output_wire] = Some(output_pairs);
    }
    if gate_material_index != gate_material.len() {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    if descriptor.includes_terminal {
        for (output_index, output_wire) in plan.output_wires.iter().copied().enumerate() {
            generate_terminal_payload(
                &mut chunk,
                &checkpoint.context,
                &checkpoint.allocation_nonce,
                checkpoint.participant_position,
                output_index as u32,
                required_wire_pairs(&wire_pairs, output_wire)?,
                mask_streams
                    .terminal_share(checkpoint.participant_position, output_index as u32)?,
                &mut entropy,
            )?;
        }
    }
    entropy.finish()?;
    if chunk.len() != descriptor.chunk_byte_length()? {
        chunk.zeroize();
        return Err(PaddedContinuationError::InvalidChunk);
    }
    let next_live_wires = plan.live_wires_after_chunk(checkpoint.next_chunk_ordinal)?;
    let mut next_live_pairs = Zeroizing::new(Vec::with_capacity(next_live_wires.len()));
    for wire in next_live_wires {
        next_live_pairs.push((wire, required_wire_pairs(&wire_pairs, wire as u32)?));
    }
    for pairs in wire_pairs.iter_mut().flatten() {
        pairs.zeroize();
    }
    for (_, pairs) in &mut checkpoint.live_wire_pairs {
        pairs.zeroize();
    }
    checkpoint.live_wire_pairs = core::mem::take(&mut *next_live_pairs);
    checkpoint.initial_wire_values.zeroize();
    checkpoint.initial_wire_values.clear();
    let chunk_identity = hash_bytes(CHUNK_IDENTITY_DOMAIN, &chunk)?;
    Ok((chunk, chunk_identity))
}

fn derive_initial_wire_values(
    capability: &VerifiedFinalityCapability,
    roster: &Roster,
    preparation: &VerifiedCompletePreparation,
    participant_position: u16,
    source_bodies: &[Vec<u8>],
    source_signatures: &[Vec<u8>],
) -> Result<Vec<u8>, PaddedContinuationError> {
    let target = capability.target.context();
    let source_declarations = (0..target.participant_count)
        .map(|source_position| {
            if target.source_submission_bitmap & (1_u16 << source_position) == 0 {
                SourceDeclaration::Abstain
            } else {
                SourceDeclaration::Submit
            }
        })
        .collect::<Vec<_>>();
    let verified = derive_finality_target(
        FinalityDerivationContext {
            participant_count: target.participant_count,
            runtime_identity: target.runtime_identity,
            candidate_build_identity: target.candidate_build_identity,
            action_proposal_identity: target.action_proposal_identity,
            action_definition_identity: target.action_definition_identity,
            roster_identity: target.roster_identity,
            preparation_attempt: target.preparation_attempt,
            predecessor_identity: target.predecessor_identity,
            verified_preparation_root: target.verified_preparation_root,
            top_count: target.top_count,
        },
        roster,
        &source_declarations,
        source_bodies,
        source_signatures,
    )
    .map_err(|_| PaddedContinuationError::InvalidContext)?;
    if verified.target != capability.target
        || verified.target_identity != capability.target_identity
        || verified.verified_sources.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
    {
        return Err(PaddedContinuationError::InvalidContext);
    }
    let mut values = Vec::with_capacity(10 * 41);
    for source in verified.verified_sources {
        values.push(u8::from(source.declaration == SourceDeclaration::Submit));
        if let Some(correction) = source.correction {
            let coordinates = derive_source_coordinate_shares(
                &SourceContext {
                    participant_count: target.participant_count,
                    action_proposal_identity: target.action_proposal_identity,
                    roster_identity: target.roster_identity,
                    preparation_attempt: target.preparation_attempt,
                    predecessor_identity: target.predecessor_identity,
                    verified_preparation_root: target.verified_preparation_root,
                    sender_position: source.sender_position,
                    source_ordinal: SOURCE_ORDINAL,
                },
                participant_position,
                Some(&correction),
                &preparation.held_subset_keys,
            )
            .map_err(|_| PaddedContinuationError::InvalidContext)?;
            values.extend_from_slice(&coordinates);
        } else {
            values.extend_from_slice(&[0_u8; 40]);
        }
    }
    if values.len() != 410 || values.iter().any(|value| *value > 0x0f) {
        values.zeroize();
        return Err(PaddedContinuationError::InvalidBody);
    }
    Ok(values)
}

fn required_wire_pairs(
    wire_pairs: &[Option<FieldPairs>],
    wire: u32,
) -> Result<FieldPairs, PaddedContinuationError> {
    wire_pairs
        .get(usize::try_from(wire).map_err(|_| PaddedContinuationError::InvalidPlan)?)
        .and_then(|pairs| *pairs)
        .ok_or(PaddedContinuationError::InvalidPlan)
}

#[allow(clippy::too_many_arguments)]
fn generate_linear_payload(
    chunk: &mut Vec<u8>,
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    linear_ordinal: u32,
    left: FieldPairs,
    right: FieldPairs,
    entropy: &mut LabelEntropyCursor<'_>,
) -> Result<FieldPairs, PaddedContinuationError> {
    let output = entropy.read_field_pairs()?;
    for basis in 0..FIELD_BIT_WIDTH {
        for row in garble_binary_gate(
            context,
            allocation_nonce,
            participant_position,
            OPERATION_KIND_LINEAR_XOR,
            linear_ordinal,
            basis as u16,
            left[basis],
            right[basis],
            output[basis],
            false,
        ) {
            chunk.extend_from_slice(&row);
        }
    }
    Ok(output)
}

fn write_chunk_header(
    chunk: &mut Vec<u8>,
    context: &EvaluationContext,
    participant_position: u16,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    chunk_ordinal: usize,
    descriptor: ChunkDescriptor,
    previous_chunk_identity: Hash512,
) -> Result<(), PaddedContinuationError> {
    chunk.extend_from_slice(&CHUNK_MAGIC);
    chunk.extend_from_slice(&CHUNK_VERSION.to_le_bytes());
    chunk.extend_from_slice(context.target_identity.as_bytes());
    chunk.extend_from_slice(context.circuit_identity.as_bytes());
    chunk.extend_from_slice(&COMPLETION_PROFILE_PARTICIPANT_COUNT.to_le_bytes());
    chunk.extend_from_slice(&participant_position.to_le_bytes());
    chunk.extend_from_slice(&context.top_count.to_le_bytes());
    chunk.extend_from_slice(allocation_nonce);
    chunk.extend_from_slice(&checked_u32(chunk_ordinal)?.to_le_bytes());
    chunk.extend_from_slice(&checked_u32(descriptor.first_operation)?.to_le_bytes());
    chunk.extend_from_slice(&checked_u32(descriptor.operation_end)?.to_le_bytes());
    chunk.push(u8::from(descriptor.includes_initial));
    chunk.push(u8::from(descriptor.includes_terminal));
    chunk.extend_from_slice(previous_chunk_identity.as_bytes());
    if chunk.len() != PADDED_CHUNK_HEADER_BYTE_LENGTH {
        return Err(PaddedContinuationError::InvalidChunk);
    }
    Ok(())
}

fn encode_manifest(
    context: &EvaluationContext,
    participant_position: u16,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    plan: &PaddedTallyPlan,
    chunk_identities: &[Hash512],
) -> Result<Vec<u8>, PaddedContinuationError> {
    if chunk_identities.len() != plan.descriptors.len() {
        return Err(PaddedContinuationError::InvalidManifest);
    }
    let expected_length = PADDED_MANIFEST_HEADER_BYTE_LENGTH
        .checked_add(
            plan.descriptors
                .len()
                .checked_mul(PADDED_MANIFEST_DESCRIPTOR_BYTE_LENGTH)
                .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
        )
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let mut manifest = Vec::with_capacity(expected_length);
    manifest.extend_from_slice(&MANIFEST_MAGIC);
    manifest.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
    manifest.extend_from_slice(context.target_identity.as_bytes());
    manifest.extend_from_slice(context.circuit_identity.as_bytes());
    manifest.extend_from_slice(&COMPLETION_PROFILE_PARTICIPANT_COUNT.to_le_bytes());
    manifest.extend_from_slice(&participant_position.to_le_bytes());
    manifest.extend_from_slice(&context.top_count.to_le_bytes());
    manifest.extend_from_slice(allocation_nonce);
    manifest.extend_from_slice(&checked_u32(plan.descriptors.len())?.to_le_bytes());
    for (descriptor, identity) in plan.descriptors.iter().zip(chunk_identities) {
        manifest.extend_from_slice(&checked_u32(descriptor.first_operation)?.to_le_bytes());
        manifest.extend_from_slice(&checked_u32(descriptor.operation_end)?.to_le_bytes());
        manifest.push(u8::from(descriptor.includes_initial));
        manifest.push(u8::from(descriptor.includes_terminal));
        manifest.extend_from_slice(&checked_u32(descriptor.chunk_byte_length()?)?.to_le_bytes());
        manifest.extend_from_slice(identity.as_bytes());
    }
    if manifest.len() != expected_length {
        manifest.zeroize();
        return Err(PaddedContinuationError::InvalidManifest);
    }
    Ok(manifest)
}

fn checked_u32(value: usize) -> Result<u32, PaddedContinuationError> {
    u32::try_from(value).map_err(|_| PaddedContinuationError::ArithmeticOverflow)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedPaddedTallyBatch {
    pub batch_identity: Hash512,
    pub accepted_ballot_authorship: Vec<bool>,
    pub ordered_option_positions: Option<Vec<u16>>,
    pub terminal_body: Vec<u8>,
    pub terminal_identity: Hash512,
}

fn padded_tally_batch_identity(
    context: &EvaluationContext,
    manifest_identities: &[Hash512],
) -> Result<Hash512, PaddedContinuationError> {
    if manifest_identities.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    let identity_bytes = manifest_identities
        .iter()
        .flat_map(|identity| identity.as_bytes().iter().copied())
        .collect::<Vec<_>>();
    hash_foundation_tuple_512(
        BATCH_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(context.target_identity.into_bytes()),
            CanonicalItem::hash512(context.circuit_identity.into_bytes()),
            CanonicalItem::unsigned16(context.top_count),
            CanonicalItem::fixed_bytes(identity_bytes)
                .map_err(|_| PaddedContinuationError::InvalidManifest)?,
        ],
    )
    .map_err(|_| PaddedContinuationError::InvalidManifest)
}

fn evaluated_tally_from_terminal_bits(
    batch_identity: Hash512,
    context: &EvaluationContext,
    output_schema_identity: Hash512,
    terminal_bits: &[bool],
) -> Result<EvaluatedPaddedTallyBatch, PaddedContinuationError> {
    let result_bit_count = usize::from(context.top_count)
        .checked_mul(FIELD_BIT_WIDTH)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let expected_bit_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        .checked_add(1)
        .and_then(|count| count.checked_add(result_bit_count))
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    if terminal_bits.len() != expected_bit_count {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    let accepted_ballot_authorship =
        terminal_bits[..usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)].to_vec();
    let has_usable_ballot = terminal_bits[usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)];
    let mut ordered_option_positions = Vec::with_capacity(usize::from(context.top_count));
    let mut seen_positions = BTreeSet::new();
    for position_bits in terminal_bits[usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) + 1..]
        .chunks_exact(FIELD_BIT_WIDTH)
    {
        let position = position_bits
            .iter()
            .enumerate()
            .fold(0_u16, |value, (bit, is_set)| {
                value | (u16::from(*is_set) << bit)
            });
        if position >= COMPLETION_PROFILE_OPTION_COUNT || !seen_positions.insert(position) {
            return Err(PaddedContinuationError::InvalidCodeword);
        }
        ordered_option_positions.push(position);
    }
    if ordered_option_positions.len() != usize::from(context.top_count) {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    let ordered_option_positions = has_usable_ballot.then_some(ordered_option_positions);
    let terminal_body = encode_computation_terminal(
        context,
        output_schema_identity,
        &accepted_ballot_authorship,
        ordered_option_positions.as_deref(),
    )?;
    let terminal_identity = hash_bytes(RESULT_IDENTITY_DOMAIN, &terminal_body)?;
    Ok(EvaluatedPaddedTallyBatch {
        batch_identity,
        accepted_ballot_authorship,
        ordered_option_positions,
        terminal_body,
        terminal_identity,
    })
}

fn encode_computation_terminal(
    context: &EvaluationContext,
    output_schema_identity: Hash512,
    accepted_ballot_authorship: &[bool],
    ordered_option_positions: Option<&[u16]>,
) -> Result<Vec<u8>, PaddedContinuationError> {
    if accepted_ballot_authorship.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    let result_count = ordered_option_positions.map_or(0, <[u16]>::len);
    if ordered_option_positions.is_some() && result_count != usize::from(context.top_count) {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let mut seen_positions = BTreeSet::new();
    if ordered_option_positions.is_some_and(|positions| {
        positions.iter().any(|position| {
            *position >= COMPLETION_PROFILE_OPTION_COUNT || !seen_positions.insert(*position)
        })
    }) {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let expected_length = RESULT_FIXED_HEADER_BYTE_LENGTH
        .checked_add(
            result_count
                .checked_mul(2)
                .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
        )
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let mut body = Vec::with_capacity(expected_length);
    body.extend_from_slice(&RESULT_MAGIC);
    body.extend_from_slice(&RESULT_VERSION.to_le_bytes());
    body.extend_from_slice(context.target_identity.as_bytes());
    body.extend_from_slice(output_schema_identity.as_bytes());
    body.extend_from_slice(&context.top_count.to_le_bytes());
    body.push(if ordered_option_positions.is_some() {
        RESULT_KIND_RESULT
    } else {
        RESULT_KIND_NO_RESULT
    });
    body.extend(
        accepted_ballot_authorship
            .iter()
            .map(|value| u8::from(*value)),
    );
    body.extend_from_slice(
        &u16::try_from(result_count)
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    if let Some(positions) = ordered_option_positions {
        for position in positions {
            body.extend_from_slice(&position.to_le_bytes());
        }
    }
    if body.len() != expected_length {
        return Err(PaddedContinuationError::InvalidBody);
    }
    Ok(body)
}

pub fn evaluate_next_padded_tally_chunk(
    checkpoint_key: &[u8],
    checkpoint_bytes: &[u8],
    participant_chunks: &[Vec<u8>],
) -> Result<EvaluatedPaddedTallyChunkStep, PaddedContinuationError> {
    validate_checkpoint_key(checkpoint_key)?;
    let mut checkpoint = decode_evaluation_checkpoint(checkpoint_bytes, checkpoint_key)?;
    let plan = PaddedTallyPlan::compile(checkpoint.context.top_count)?;
    validate_evaluation_checkpoint(&checkpoint, &plan)?;
    let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
    if participant_chunks.len() != participant_count {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    let chunk_ordinal = checkpoint.next_chunk_ordinal;
    let descriptor = *plan
        .descriptors
        .get(chunk_ordinal)
        .ok_or(PaddedContinuationError::InvalidChunk)?;
    let mut bodies = Vec::with_capacity(participant_count);
    for (participant_position, participant_chunk) in participant_chunks.iter().enumerate() {
        let identity_index = participant_position
            .checked_mul(plan.descriptors.len())
            .and_then(|index| index.checked_add(chunk_ordinal))
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let identity = hash_bytes(CHUNK_IDENTITY_DOMAIN, participant_chunk)?;
        if checkpoint.expected_chunk_identities.get(identity_index) != Some(&identity) {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        let previous_chunk_identity = if chunk_ordinal == 0 {
            Hash512::from_bytes([0; Hash512::BYTE_LENGTH])
        } else {
            checkpoint.expected_chunk_identities[identity_index - 1]
        };
        let parsed = ParsedTallyChunk::new(
            participant_chunk,
            &checkpoint.context,
            participant_position as u16,
            checkpoint.allocation_nonces[participant_position],
            chunk_ordinal,
            descriptor,
            previous_chunk_identity,
        )?;
        bodies.push(ParsedTallyBody {
            participant_position: participant_position as u16,
            allocation_nonce: checkpoint.allocation_nonces[participant_position],
            chunks: vec![parsed],
        });
    }
    let evaluated = evaluate_one_tally_chunk(&plan, &mut checkpoint, descriptor, &bodies)?;
    if descriptor.includes_terminal != evaluated.is_some() {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    checkpoint.next_chunk_ordinal = checkpoint
        .next_chunk_ordinal
        .checked_add(1)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let next_checkpoint = if descriptor.includes_terminal {
        if checkpoint.next_chunk_ordinal != plan.descriptors.len()
            || !checkpoint.active_wire_tokens.is_empty()
        {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        None
    } else {
        Some(encode_evaluation_checkpoint(
            &checkpoint,
            &plan,
            checkpoint_key,
        )?)
    };
    Ok(EvaluatedPaddedTallyChunkStep {
        chunk_ordinal: checked_u32(chunk_ordinal)?,
        next_checkpoint,
        evaluated,
    })
}

fn evaluate_one_tally_chunk(
    plan: &PaddedTallyPlan,
    checkpoint: &mut PaddedTallyEvaluationCheckpoint,
    descriptor: ChunkDescriptor,
    bodies: &[ParsedTallyBody<'_>],
) -> Result<Option<EvaluatedPaddedTallyBatch>, PaddedContinuationError> {
    let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
    if bodies.len() != participant_count {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    if descriptor.includes_initial {
        if checkpoint.next_chunk_ordinal != 0 || !checkpoint.active_wire_tokens.is_empty() {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        let mut participant_initial_tokens = Zeroizing::new(Vec::with_capacity(participant_count));
        for body in bodies {
            participant_initial_tokens.push(body.initial_tokens(plan)?);
        }
        for wire in 0..plan.circuit.input_bit_count() {
            if plan.last_wire_uses[wire] == usize::MAX {
                continue;
            }
            let mut tokens = empty_participant_field_tokens();
            for participant_position in 0..participant_count {
                tokens[participant_position] = participant_initial_tokens[participant_position]
                    .get(wire)
                    .copied()
                    .ok_or(PaddedContinuationError::InvalidChunk)?;
            }
            checkpoint.active_wire_tokens.push((wire, tokens));
        }
    }
    for operation_index in descriptor.first_operation..descriptor.operation_end {
        let operation = plan
            .circuit
            .operations()
            .get(operation_index)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        let planned = plan.operations[operation_index];
        let output_wire = plan
            .circuit
            .input_bit_count()
            .checked_add(operation_index)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let output_tokens = match (operation, planned.kind) {
            (BooleanOperation::Constant(_), PlannedOperationKind::Constant) => {
                let mut tokens = empty_participant_field_tokens();
                for (participant_position, body) in bodies.iter().enumerate() {
                    let mut reader =
                        ByteReader::new(body.operation_payload(plan, operation_index)?);
                    tokens[participant_position] = read_field_tokens(&mut reader)?;
                    reader.finish()?;
                }
                tokens
            }
            (
                BooleanOperation::ExclusiveOr {
                    left_wire,
                    right_wire,
                },
                PlannedOperationKind::Linear { operation_ordinal },
            ) => {
                let left = required_participant_tokens(
                    &checkpoint.active_wire_tokens,
                    usize::try_from(*left_wire)
                        .map_err(|_| PaddedContinuationError::InvalidPlan)?,
                )?;
                let right = required_participant_tokens(
                    &checkpoint.active_wire_tokens,
                    usize::try_from(*right_wire)
                        .map_err(|_| PaddedContinuationError::InvalidPlan)?,
                )?;
                let mut tokens = empty_participant_field_tokens();
                for (participant_position, body) in bodies.iter().enumerate() {
                    tokens[participant_position] = evaluate_linear_payload(
                        body.operation_payload(plan, operation_index)?,
                        &checkpoint.context,
                        &body.allocation_nonce,
                        body.participant_position,
                        operation_ordinal,
                        left[participant_position],
                        right[participant_position],
                    )?;
                }
                tokens
            }
            (
                BooleanOperation::Conjunction {
                    left_wire,
                    right_wire,
                },
                PlannedOperationKind::Conjunction {
                    operation_ordinal, ..
                },
            ) => {
                let left = required_participant_tokens(
                    &checkpoint.active_wire_tokens,
                    usize::try_from(*left_wire)
                        .map_err(|_| PaddedContinuationError::InvalidPlan)?,
                )?;
                let right = required_participant_tokens(
                    &checkpoint.active_wire_tokens,
                    usize::try_from(*right_wire)
                        .map_err(|_| PaddedContinuationError::InvalidPlan)?,
                )?;
                evaluate_conjunction_with_inputs(
                    plan,
                    bodies,
                    &checkpoint.context,
                    operation_index,
                    operation_ordinal,
                    &left,
                    &right,
                )?
            }
            (BooleanOperation::Negation { input_wire }, PlannedOperationKind::Negation) => {
                required_participant_tokens(
                    &checkpoint.active_wire_tokens,
                    usize::try_from(*input_wire)
                        .map_err(|_| PaddedContinuationError::InvalidPlan)?,
                )?
            }
            _ => return Err(PaddedContinuationError::InvalidPlan),
        };
        if plan.last_wire_uses[output_wire] != usize::MAX
            && plan.last_wire_uses[output_wire] > operation_index
        {
            if checkpoint
                .active_wire_tokens
                .last()
                .is_some_and(|(wire, _)| *wire >= output_wire)
            {
                return Err(PaddedContinuationError::InvalidPlan);
            }
            checkpoint
                .active_wire_tokens
                .push((output_wire, output_tokens));
        }
        checkpoint
            .active_wire_tokens
            .retain(|(wire, _)| plan.last_wire_uses[*wire] != operation_index);
    }
    if descriptor.includes_terminal {
        let terminal_bits = evaluate_tally_terminal_bits(
            plan,
            bodies,
            &checkpoint.context,
            &checkpoint.active_wire_tokens,
        )?;
        for (_, tokens) in &mut checkpoint.active_wire_tokens {
            tokens.zeroize();
        }
        checkpoint.active_wire_tokens.clear();
        return Ok(Some(evaluated_tally_from_terminal_bits(
            checkpoint.batch_identity,
            &checkpoint.context,
            checkpoint.output_schema_identity,
            &terminal_bits,
        )?));
    }
    let expected_live_wires = plan.live_wires_after_chunk(checkpoint.next_chunk_ordinal)?;
    if checkpoint
        .active_wire_tokens
        .iter()
        .map(|(wire, _)| *wire)
        .ne(expected_live_wires.iter().copied())
    {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    Ok(None)
}

fn empty_participant_field_tokens() -> ParticipantFieldTokens {
    [[Token {
        label: [0; PADDED_LABEL_BYTE_LENGTH],
        color: 0,
    }; FIELD_BIT_WIDTH]; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize]
}

fn required_participant_tokens(
    active_wire_tokens: &[(usize, ParticipantFieldTokens)],
    wire: usize,
) -> Result<ParticipantFieldTokens, PaddedContinuationError> {
    active_wire_tokens
        .binary_search_by_key(&wire, |(active_wire, _)| *active_wire)
        .ok()
        .and_then(|index| active_wire_tokens.get(index))
        .map(|(_, tokens)| *tokens)
        .ok_or(PaddedContinuationError::InvalidBody)
}

fn evaluate_conjunction_with_inputs(
    plan: &PaddedTallyPlan,
    bodies: &[ParsedTallyBody<'_>],
    context: &EvaluationContext,
    operation_index: usize,
    operation_ordinal: u32,
    left: &ParticipantFieldTokens,
    right: &ParticipantFieldTokens,
) -> Result<ParticipantFieldTokens, PaddedContinuationError> {
    let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
    if bodies.len() != participant_count {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    let mut evaluated_gates = Vec::with_capacity(participant_count);
    let mut masked_values = Vec::with_capacity(participant_count);
    for (participant_position, body) in bodies.iter().enumerate() {
        let evaluated = evaluate_gate_payload(
            body.operation_payload(plan, operation_index)?,
            context,
            &body.allocation_nonce,
            body.participant_position,
            usize::try_from(operation_ordinal)
                .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?,
            left[participant_position],
            right[participant_position],
        )?;
        masked_values.push(evaluated.masked_value);
        evaluated_gates.push(evaluated);
    }
    let selector = verify_codeword(&masked_values, 6)?;
    if selector.as_u8() > 1 {
        return Err(PaddedContinuationError::InvalidCodeword);
    }
    let mut refreshed = empty_participant_field_tokens();
    for receiver_position in 0..participant_count {
        let mut aggregate_evaluations = Zeroizing::new(Vec::with_capacity(participant_count));
        for (garbler_position, evaluated) in evaluated_gates.iter().enumerate() {
            let mut aggregate = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
            for (basis, active_token) in evaluated.masked_tokens.iter().copied().enumerate() {
                let mut plaintext =
                    evaluated.padded_row(receiver_position, basis, active_token.color)?;
                let pad = joint_row_pad(
                    context,
                    &bodies[garbler_position].allocation_nonce,
                    garbler_position as u16,
                    receiver_position as u16,
                    operation_ordinal,
                    basis as u8,
                    active_token.color,
                    &active_token.label,
                );
                module_xor(&mut plaintext, &pad);
                module_xor(&mut aggregate, &plaintext);
                plaintext.zeroize();
            }
            aggregate_evaluations.push(aggregate);
        }
        let mut selected_key = interpolate_module_at_zero(&aggregate_evaluations)?;
        let receiver_gate = &evaluated_gates[receiver_position];
        let mut plaintext = receiver_gate.continuation_rows[usize::from(selector.as_u8())];
        let pad = continuation_row_pad(
            context,
            &bodies[receiver_position].allocation_nonce,
            receiver_position as u16,
            operation_ordinal,
            selector.as_u8(),
            &selected_key,
        );
        xor_bytes(&mut plaintext, &pad);
        if plaintext[PADDED_TOKEN_BYTE_LENGTH..]
            .iter()
            .any(|byte| *byte != 0)
        {
            plaintext.zeroize();
            selected_key.zeroize();
            return Err(PaddedContinuationError::ContinuationAuthenticationFailed);
        }
        let low_token = Token::decode(&plaintext[..PADDED_TOKEN_BYTE_LENGTH])?;
        refreshed[receiver_position] = [
            low_token,
            receiver_gate.direct_output_tokens[0],
            receiver_gate.direct_output_tokens[1],
            receiver_gate.direct_output_tokens[2],
        ];
        plaintext.zeroize();
        selected_key.zeroize();
    }
    Ok(refreshed)
}

fn evaluate_tally_terminal_bits(
    plan: &PaddedTallyPlan,
    bodies: &[ParsedTallyBody<'_>],
    context: &EvaluationContext,
    active_wire_tokens: &[(usize, ParticipantFieldTokens)],
) -> Result<Vec<bool>, PaddedContinuationError> {
    let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
    if bodies.len() != participant_count {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    let mut terminal_bits = Vec::with_capacity(plan.output_wires.len());
    for (output_index, output_wire) in plan.output_wires.iter().copied().enumerate() {
        let participant_tokens = required_participant_tokens(
            active_wire_tokens,
            usize::try_from(output_wire).map_err(|_| PaddedContinuationError::InvalidPlan)?,
        )?;
        let mut values = Vec::with_capacity(participant_count);
        for (participant_position, body) in bodies.iter().enumerate() {
            values.push(evaluate_terminal_payload(
                body.terminal_payload(plan, output_index)?,
                context,
                &body.allocation_nonce,
                body.participant_position,
                output_index,
                participant_tokens[participant_position],
            )?);
        }
        let terminal = verify_codeword(&values, 3)?;
        if terminal.as_u8() > 1 {
            return Err(PaddedContinuationError::InvalidCodeword);
        }
        terminal_bits.push(terminal == Gf16::ONE);
    }
    Ok(terminal_bits)
}

fn evaluate_linear_payload(
    bytes: &[u8],
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    linear_ordinal: u32,
    left: FieldTokens,
    right: FieldTokens,
) -> Result<FieldTokens, PaddedContinuationError> {
    let mut reader = ByteReader::new(bytes);
    let mut output = [Token {
        label: [0; PADDED_LABEL_BYTE_LENGTH],
        color: 0,
    }; FIELD_BIT_WIDTH];
    for basis in 0..FIELD_BIT_WIDTH {
        let rows = [
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
        ];
        output[basis] = evaluate_binary_gate(
            context,
            allocation_nonce,
            participant_position,
            OPERATION_KIND_LINEAR_XOR,
            linear_ordinal,
            basis as u16,
            left[basis],
            right[basis],
            &rows,
        )?;
    }
    reader.finish()?;
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
struct ParsedTallyManifest {
    participant_position: u16,
    allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    chunk_identities: Vec<Hash512>,
}

impl ParsedTallyManifest {
    fn new(
        bytes: &[u8],
        context: &EvaluationContext,
        plan: &PaddedTallyPlan,
    ) -> Result<Self, PaddedContinuationError> {
        let expected_length = PADDED_MANIFEST_HEADER_BYTE_LENGTH
            .checked_add(
                plan.descriptors
                    .len()
                    .checked_mul(PADDED_MANIFEST_DESCRIPTOR_BYTE_LENGTH)
                    .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
            )
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        if bytes.len() != expected_length {
            return Err(PaddedContinuationError::InvalidManifest);
        }
        let mut reader = ByteReader::new(bytes);
        if reader.read_array::<4>()? != MANIFEST_MAGIC
            || reader.read_u16()? != MANIFEST_VERSION
            || Hash512::from_bytes(reader.read_array()?) != context.target_identity
            || Hash512::from_bytes(reader.read_array()?) != context.circuit_identity
            || reader.read_u16()? != COMPLETION_PROFILE_PARTICIPANT_COUNT
        {
            return Err(PaddedContinuationError::InvalidContext);
        }
        let participant_position = reader.read_u16()?;
        validate_position(participant_position)?;
        if reader.read_u16()? != context.top_count {
            return Err(PaddedContinuationError::InvalidContext);
        }
        let allocation_nonce = reader.read_array()?;
        if reader.read_u32()? != checked_u32(plan.descriptors.len())? {
            return Err(PaddedContinuationError::InvalidManifest);
        }
        let mut chunk_identities = Vec::with_capacity(plan.descriptors.len());
        for descriptor in plan.descriptors.iter().copied() {
            if reader.read_u32()? != checked_u32(descriptor.first_operation)?
                || reader.read_u32()? != checked_u32(descriptor.operation_end)?
                || reader.read_u8()? != u8::from(descriptor.includes_initial)
                || reader.read_u8()? != u8::from(descriptor.includes_terminal)
                || reader.read_u32()? != checked_u32(descriptor.chunk_byte_length()?)?
            {
                return Err(PaddedContinuationError::InvalidManifest);
            }
            chunk_identities.push(Hash512::from_bytes(reader.read_array()?));
        }
        reader.finish()?;
        Ok(Self {
            participant_position,
            allocation_nonce,
            chunk_identities,
        })
    }
}

struct ParsedTallyChunk<'a> {
    bytes: &'a [u8],
    descriptor: ChunkDescriptor,
}

impl<'a> ParsedTallyChunk<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        bytes: &'a [u8],
        context: &EvaluationContext,
        participant_position: u16,
        allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
        chunk_ordinal: usize,
        descriptor: ChunkDescriptor,
        previous_chunk_identity: Hash512,
    ) -> Result<Self, PaddedContinuationError> {
        if bytes.len() != descriptor.chunk_byte_length()? {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        let mut reader = ByteReader::new(bytes);
        if reader.read_array::<4>()? != CHUNK_MAGIC
            || reader.read_u16()? != CHUNK_VERSION
            || Hash512::from_bytes(reader.read_array()?) != context.target_identity
            || Hash512::from_bytes(reader.read_array()?) != context.circuit_identity
            || reader.read_u16()? != COMPLETION_PROFILE_PARTICIPANT_COUNT
            || reader.read_u16()? != participant_position
            || reader.read_u16()? != context.top_count
            || reader.read_array::<PADDED_ALLOCATION_NONCE_BYTE_LENGTH>()? != allocation_nonce
            || reader.read_u32()? != checked_u32(chunk_ordinal)?
            || reader.read_u32()? != checked_u32(descriptor.first_operation)?
            || reader.read_u32()? != checked_u32(descriptor.operation_end)?
            || reader.read_u8()? != u8::from(descriptor.includes_initial)
            || reader.read_u8()? != u8::from(descriptor.includes_terminal)
            || Hash512::from_bytes(reader.read_array()?) != previous_chunk_identity
            || reader.offset != PADDED_CHUNK_HEADER_BYTE_LENGTH
        {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        Ok(Self { bytes, descriptor })
    }

    fn payload_slice(
        &self,
        logical_offset: usize,
        byte_length: usize,
    ) -> Result<&'a [u8], PaddedContinuationError> {
        let logical_end = logical_offset
            .checked_add(byte_length)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        if logical_offset < self.descriptor.logical_payload_start
            || logical_end > self.descriptor.logical_payload_end
        {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        let start = PADDED_CHUNK_HEADER_BYTE_LENGTH
            .checked_add(
                logical_offset
                    .checked_sub(self.descriptor.logical_payload_start)
                    .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
            )
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        self.bytes
            .get(start..start + byte_length)
            .ok_or(PaddedContinuationError::InvalidChunk)
    }
}

struct ParsedTallyBody<'a> {
    participant_position: u16,
    allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    chunks: Vec<ParsedTallyChunk<'a>>,
}

impl ParsedTallyBody<'_> {
    fn initial_tokens(
        &self,
        plan: &PaddedTallyPlan,
    ) -> Result<Vec<FieldTokens>, PaddedContinuationError> {
        let byte_length = plan
            .circuit
            .input_bit_count()
            .checked_mul(INITIAL_WIRE_PAYLOAD_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let bytes = self
            .chunks
            .first()
            .ok_or(PaddedContinuationError::InvalidChunk)?
            .payload_slice(0, byte_length)?;
        let mut reader = ByteReader::new(bytes);
        let mut tokens = Vec::with_capacity(plan.circuit.input_bit_count());
        for _ in 0..plan.circuit.input_bit_count() {
            tokens.push(read_field_tokens(&mut reader)?);
        }
        reader.finish()?;
        Ok(tokens)
    }

    fn operation_payload(
        &self,
        plan: &PaddedTallyPlan,
        operation_index: usize,
    ) -> Result<&[u8], PaddedContinuationError> {
        let operation = *plan
            .operations
            .get(operation_index)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        let chunk = self
            .chunks
            .iter()
            .find(|chunk| {
                operation_index >= chunk.descriptor.first_operation
                    && operation_index < chunk.descriptor.operation_end
            })
            .ok_or(PaddedContinuationError::InvalidChunk)?;
        chunk.payload_slice(operation.payload_offset, operation.payload_byte_length)
    }

    fn terminal_payload(
        &self,
        plan: &PaddedTallyPlan,
        output_index: usize,
    ) -> Result<&[u8], PaddedContinuationError> {
        if output_index >= plan.output_wires.len() {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        let logical_offset = plan
            .terminal_payload_offset
            .checked_add(
                output_index
                    .checked_mul(PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH)
                    .ok_or(PaddedContinuationError::ArithmeticOverflow)?,
            )
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        self.chunks
            .last()
            .ok_or(PaddedContinuationError::InvalidChunk)?
            .payload_slice(logical_offset, PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Default)]
    struct SymbolicLabelCensus {
        output_count_per_label: Vec<usize>,
    }

    impl SymbolicLabelCensus {
        fn new_pair(&mut self) -> usize {
            let identifier = self.output_count_per_label.len();
            self.output_count_per_label.push(0);
            identifier
        }

        fn append_gate(&mut self, left: usize, right: usize, output: Option<usize>) -> usize {
            self.output_count_per_label[left] += 2;
            self.output_count_per_label[right] += 2;
            output.unwrap_or_else(|| self.new_pair())
        }

        fn new_field_pairs(&mut self) -> [usize; FIELD_BIT_WIDTH] {
            core::array::from_fn(|_| self.new_pair())
        }

        fn multiply_fields(
            &mut self,
            left: [usize; FIELD_BIT_WIDTH],
            right: [usize; FIELD_BIT_WIDTH],
        ) -> [usize; FIELD_BIT_WIDTH] {
            let mut products = Vec::with_capacity(16);
            for position in 0..16 {
                products.push(self.append_gate(
                    left[position / FIELD_BIT_WIDTH],
                    right[position % FIELD_BIT_WIDTH],
                    None,
                ));
            }
            let c0 = products[0];
            let c1 = self.append_gate(products[1], products[4], None);
            let c2_left = self.append_gate(products[2], products[5], None);
            let c2 = self.append_gate(c2_left, products[8], None);
            let c3_left = self.append_gate(products[3], products[6], None);
            let c3_right = self.append_gate(products[9], products[12], None);
            let c3 = self.append_gate(c3_left, c3_right, None);
            let c4_left = self.append_gate(products[7], products[10], None);
            let c4 = self.append_gate(c4_left, products[13], None);
            let c5 = self.append_gate(products[11], products[14], None);
            let c6 = products[15];
            let d0 = self.append_gate(c0, c4, None);
            let d1_left = self.append_gate(c1, c4, None);
            let d1 = self.append_gate(d1_left, c5, None);
            let d2_left = self.append_gate(c2, c5, None);
            let d2 = self.append_gate(d2_left, c6, None);
            let d3 = self.append_gate(c3, c6, None);
            [d0, d1, d2, d3]
        }
    }

    fn symbolic_full_tally_label_census(plan: &PaddedTallyPlan) -> Vec<usize> {
        let wire_count = plan
            .circuit
            .input_bit_count()
            .checked_add(plan.operations.len())
            .expect("symbolic wire count");
        let mut census = SymbolicLabelCensus::default();
        let mut wire_pairs = vec![None; wire_count];
        for pair in wire_pairs.iter_mut().take(plan.circuit.input_bit_count()) {
            *pair = Some(census.new_field_pairs());
        }
        for (operation_index, (operation, planned)) in plan
            .circuit
            .operations()
            .iter()
            .zip(&plan.operations)
            .enumerate()
        {
            let output_wire = plan.circuit.input_bit_count() + operation_index;
            let output_pairs = match (operation, planned.kind) {
                (BooleanOperation::Constant(_), PlannedOperationKind::Constant) => {
                    census.new_field_pairs()
                }
                (
                    BooleanOperation::ExclusiveOr {
                        left_wire,
                        right_wire,
                    },
                    PlannedOperationKind::Linear { .. },
                ) => {
                    let left = wire_pairs[*left_wire as usize].expect("live symbolic left wire");
                    let right = wire_pairs[*right_wire as usize].expect("live symbolic right wire");
                    core::array::from_fn(|basis| {
                        census.append_gate(left[basis], right[basis], None)
                    })
                }
                (
                    BooleanOperation::Conjunction {
                        left_wire,
                        right_wire,
                    },
                    PlannedOperationKind::Conjunction { .. },
                ) => {
                    let left = wire_pairs[*left_wire as usize].expect("live symbolic left wire");
                    let right = wire_pairs[*right_wire as usize].expect("live symbolic right wire");
                    let product = census.multiply_fields(left, right);
                    let mask = census.new_field_pairs();
                    let masked = census.new_field_pairs();
                    for basis in 0..FIELD_BIT_WIDTH {
                        census.append_gate(product[basis], mask[basis], Some(masked[basis]));
                        census.output_count_per_label[masked[basis]] +=
                            usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
                    }
                    census.new_field_pairs()
                }
                (BooleanOperation::Negation { input_wire }, PlannedOperationKind::Negation) => {
                    wire_pairs[*input_wire as usize].expect("live symbolic negated wire")
                }
                _ => panic!("symbolic census encountered a compiler mismatch"),
            };
            wire_pairs[output_wire] = Some(output_pairs);
        }
        for output_wire in &plan.output_wires {
            let input = wire_pairs[*output_wire as usize].expect("live symbolic output wire");
            let mask = census.new_field_pairs();
            let output = census.new_field_pairs();
            for basis in 0..FIELD_BIT_WIDTH {
                census.append_gate(input[basis], mask[basis], Some(output[basis]));
            }
        }
        census.output_count_per_label
    }

    fn deterministic_held_subset_keys(participant_position: u16) -> Vec<HeldSubsetKey> {
        sender_subset_slots(participant_position)
            .into_iter()
            .map(|(family, subset)| HeldSubsetKey {
                family,
                subset,
                key: core::array::from_fn(|byte| {
                    (u32::from(family) * 17
                        + u32::from(subset) * 31
                        + u32::try_from(byte).expect("byte index") * 13) as u8
                }),
            })
            .collect()
    }

    fn evaluation_context() -> EvaluationContext {
        EvaluationContext {
            target_identity: Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]),
            circuit_identity: Hash512::from_bytes([0x92; Hash512::BYTE_LENGTH]),
            top_count: 10,
        }
    }

    fn deterministic_pairwise_master(sender: u16, recipient: u16) -> [u8; 32] {
        core::array::from_fn(|byte| {
            (u32::from(sender) * 53
                + u32::from(recipient) * 29
                + u32::try_from(byte).expect("byte index") * 11) as u8
        })
    }

    fn deterministic_pairwise_inventory(participant_position: u16) -> PairwiseMasterInventory {
        let outgoing = core::array::from_fn(|recipient| {
            deterministic_pairwise_master(participant_position, recipient as u16)
        });
        let remote_incoming = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .filter(|sender| *sender != participant_position)
            .map(|sender| deterministic_pairwise_master(sender, participant_position))
            .collect::<Vec<_>>()
            .try_into()
            .expect("nine incoming masters");
        PairwiseMasterInventory::from_position_ordered(
            participant_position,
            outgoing,
            remote_incoming,
        )
    }

    fn deterministic_label_entropy(length: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut entropy = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect::<Vec<_>>();
        for pair in entropy.chunks_exact_mut(TOKEN_PAIR_ENTROPY_BYTE_LENGTH) {
            pair[2 * PADDED_LABEL_BYTE_LENGTH] &= 1;
            if pair[..PADDED_LABEL_BYTE_LENGTH]
                == pair[PADDED_LABEL_BYTE_LENGTH..2 * PADDED_LABEL_BYTE_LENGTH]
            {
                pair[PADDED_LABEL_BYTE_LENGTH] ^= 1;
            }
        }
        entropy
    }

    #[test]
    fn every_completion_width_has_the_exact_compiler_derived_layout() {
        const EXPECTED: [(u32, u32, u32, u32, u32, u32, u32); 10] = [
            (2_153, 2_098, 250, 15, 21_192_471, 8_148_114, 45),
            (2_515, 2_290, 364, 19, 23_236_107, 8_936_730, 49),
            (2_837, 2_458, 462, 23, 25_028_143, 9_628_794, 53),
            (3_113, 2_602, 546, 27, 26_564_643, 10_222_362, 56),
            (3_343, 2_722, 616, 31, 27_845_607, 10_717_434, 59),
            (3_527, 2_818, 672, 35, 28_871_035, 11_114_010, 61),
            (3_665, 2_890, 714, 39, 29_640_927, 11_412_090, 63),
            (3_757, 2_938, 742, 43, 30_155_283, 11_611_674, 64),
            (3_803, 2_962, 756, 47, 30_414_103, 11_712_762, 65),
            (3_803, 2_962, 756, 51, 30_417_387, 11_715_354, 65),
        ];
        for top_count in 1..=10_u16 {
            let plan = PaddedTallyPlan::compile(top_count).expect("plan compiles");
            if top_count == 1 {
                assert_eq!(
                    plan.output_wires,
                    vec![
                        581, 791, 1_001, 1_211, 1_421, 1_631, 1_841, 2_051, 2_261, 2_471, 2_538,
                        4_905, 4_907, 4_909, 4_911,
                    ],
                    "independent top-one output-wire topology",
                );
            }
            for chunk_ordinal in 0..plan.descriptors.len() {
                assert!(
                    plan.live_wires_after_chunk(chunk_ordinal)
                        .expect("live wires compile")
                        .into_iter()
                        .all(|wire| plan.last_wire_uses[wire] != usize::MAX),
                    "dead operation outputs are never checkpointed",
                );
            }
            let summary = plan.summary(top_count).expect("summary compiles");
            let expected = EXPECTED[usize::from(top_count - 1)];
            assert_eq!(summary.input_wire_count, 410);
            assert_eq!(summary.constant_count, 2);
            assert_eq!(
                (
                    summary.linear_count,
                    summary.conjunction_count,
                    summary.negation_count,
                    summary.output_count,
                    summary.logical_payload_byte_length,
                    summary.label_entropy_byte_length,
                    summary.chunk_byte_lengths.len() as u32,
                ),
                expected,
            );
            assert_eq!(summary.output_count, 11 + 4 * u32::from(top_count));
            assert_eq!(summary.maximum_live_wire_count, 415);
            assert_eq!(
                summary.live_wire_counts_after_chunks.len(),
                summary.chunk_byte_lengths.len()
            );
            assert_eq!(summary.live_wire_counts_after_chunks.last(), Some(&0));
            assert!(
                summary
                    .chunk_byte_lengths
                    .iter()
                    .all(|length| *length <= PADDED_TALLY_MAXIMUM_CHUNK_BYTE_LENGTH as u32)
            );
            assert_eq!(
                summary.manifest_byte_length,
                (PADDED_MANIFEST_HEADER_BYTE_LENGTH
                    + summary.chunk_byte_lengths.len() * PADDED_MANIFEST_DESCRIPTOR_BYTE_LENGTH)
                    as u32,
            );
        }
    }

    #[test]
    fn every_tally_width_has_an_emitted_label_key_and_call_census() {
        let mut maximum_fan_out_distribution = None;
        for top_count in 1..=COMPLETION_PROFILE_OPTION_COUNT {
            let plan = PaddedTallyPlan::compile(top_count).expect("tally plan compiles");
            let output_count_per_label = symbolic_full_tally_label_census(&plan);
            let expected_pair_count = 4 * plan.circuit.input_bit_count()
                + 4 * plan.constant_count
                + 4 * plan.linear_count
                + 43 * plan.conjunction_count
                + 8 * plan.output_wires.len();
            assert_eq!(output_count_per_label.len(), expected_pair_count);

            let mut fan_out_distribution = BTreeMap::<usize, usize>::new();
            for output_count in output_count_per_label {
                *fan_out_distribution.entry(output_count).or_default() += 20;
            }
            let label_key_count = fan_out_distribution.values().sum::<usize>();
            let label_output_count = fan_out_distribution
                .iter()
                .map(|(output_count, key_count)| output_count * key_count)
                .sum::<usize>();
            let continuation_key_count = 20 * plan.conjunction_count;
            let continuation_output_count = continuation_key_count;
            let selected_recomputation_count = 1_110 * plan.conjunction_count
                + 80 * plan.linear_count
                + 80 * plan.output_wires.len();
            let hidden_replacement_count = (label_output_count + continuation_output_count) / 2;

            assert_eq!(label_key_count, 20 * expected_pair_count);
            assert_eq!(
                label_output_count,
                10 * (360 * plan.conjunction_count
                    + 32 * plan.linear_count
                    + 32 * plan.output_wires.len())
            );
            assert_eq!(
                hidden_replacement_count * 2,
                label_output_count + continuation_output_count
            );
            assert!(selected_recomputation_count > 0);
            if top_count == COMPLETION_PROFILE_OPTION_COUNT {
                assert_eq!(label_key_count, 2_892_680);
                assert_eq!(continuation_key_count, 59_240);
                assert_eq!(label_output_count, 11_896_480);
                assert_eq!(continuation_output_count, 59_240);
                assert_eq!(selected_recomputation_count, 3_596_140);
                assert_eq!(hidden_replacement_count, 5_977_860);
                maximum_fan_out_distribution = Some(fan_out_distribution);
            }
        }
        assert_eq!(
            maximum_fan_out_distribution.expect("maximum census was reached"),
            BTreeMap::from([
                (0, 14_240),
                (2, 2_062_560),
                (4, 236_760),
                (6, 240),
                (8, 119_680),
                (10, 370_400),
                (12, 2_000),
                (14, 50_400),
                (26, 24_000),
                (28, 8_000),
                (70, 80),
                (88, 3_440),
                (124, 80),
                (332, 800),
            ])
        );
    }

    #[test]
    fn maximum_width_preparation_and_stream_census_matches_the_independent_ledger() {
        let choose = |element_count: usize, selection_count: usize| {
            let reduced_selection = selection_count.min(element_count - selection_count);
            (0..reduced_selection).fold(1_usize, |value, offset| {
                value * (element_count - offset) / (offset + 1)
            })
        };
        let packed_read_count = |item_count: usize, item_bit_width: usize| {
            (0..item_count)
                .map(|ordinal| {
                    let first_bit = ordinal * item_bit_width;
                    let final_bit = first_bit + item_bit_width - 1;
                    final_bit / 128 - first_bit / 128 + 1
                })
                .sum::<usize>()
        };
        let packed_block_count =
            |item_count: usize, item_bit_width: usize| (item_count * item_bit_width).div_ceil(128);

        let plan = PaddedTallyPlan::compile(COMPLETION_PROFILE_OPTION_COUNT)
            .expect("maximum-width tally plan compiles");
        let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
        let low_subset_size = 7_usize;
        let terminal_subset_size = 8_usize;
        let low_subset_count = choose(participant_count, low_subset_size);
        let terminal_subset_count = choose(participant_count, terminal_subset_size);
        let low_slots_per_sender = choose(participant_count - 1, low_subset_size - 1);
        let terminal_slots_per_sender = choose(participant_count - 1, terminal_subset_size - 1);
        let low_slots_per_sender_recipient = choose(participant_count - 2, low_subset_size - 2);
        let terminal_slots_per_sender_recipient =
            choose(participant_count - 2, terminal_subset_size - 2);
        let openings_per_remote_plaintext =
            low_slots_per_sender_recipient + terminal_slots_per_sender_recipient;
        let remote_pair_count = participant_count * (participant_count - 1);

        assert_eq!(low_subset_count, 120);
        assert_eq!(terminal_subset_count, 45);
        assert_eq!(low_subset_count + terminal_subset_count, 165);
        assert_eq!(
            participant_count * (low_slots_per_sender + terminal_slots_per_sender),
            1_200
        );
        assert_eq!(remote_pair_count * openings_per_remote_plaintext, 7_560);
        assert_eq!(participant_count * participant_count, 100);

        let distinct_subkey_count = low_subset_count
            + low_subset_count
            + terminal_subset_count
            + low_subset_count * low_subset_size
            + low_subset_count * low_subset_size
            + participant_count * participant_count;
        assert_eq!(distinct_subkey_count, 2_065);

        let source_subkey_calls = participant_count * low_slots_per_sender
            + participant_count
                * (low_slots_per_sender + (participant_count - 1) * low_slots_per_sender_recipient);
        let subkey_calls_per_chunk = participant_count
            * (2 * low_slots_per_sender
                + terminal_slots_per_sender
                + low_slots_per_sender
                + (participant_count - 1) * low_slots_per_sender_recipient
                + 2 * participant_count);
        assert_eq!(source_subkey_calls, 6_720);
        assert_eq!(subkey_calls_per_chunk, 8_120);
        assert_eq!(
            source_subkey_calls + plan.descriptors.len() * subkey_calls_per_chunk,
            534_520
        );

        let conjunction_count = plan.conjunction_count;
        let output_count = plan.output_wires.len();
        let source_blocks_per_subset = (0..low_subset_size)
            .map(|rank| {
                let first_bit = rank * 40;
                let final_bit = first_bit + 39;
                final_bit / 128 - first_bit / 128 + 1
            })
            .sum::<usize>();
        let distinct_matched_low_blocks =
            low_subset_count * packed_block_count(conjunction_count, 1);
        let distinct_matched_high_blocks =
            low_subset_count * packed_block_count(conjunction_count, 12);
        let distinct_terminal_blocks = terminal_subset_count * packed_block_count(output_count, 4);
        let distinct_source_blocks = low_subset_count * source_blocks_per_subset;
        let distinct_receiver_b_blocks = low_subset_count * low_subset_size * conjunction_count * 3;
        let distinct_pairwise_p_blocks =
            participant_count * participant_count * 4 * conjunction_count * 3;
        assert_eq!(
            distinct_matched_low_blocks
                + distinct_matched_high_blocks
                + distinct_terminal_blocks
                + distinct_source_blocks
                + distinct_receiver_b_blocks
                + distinct_pairwise_p_blocks,
            11_056_050
        );

        let scalar_matched_low_blocks =
            participant_count * low_slots_per_sender * packed_read_count(conjunction_count, 1);
        let scalar_matched_high_blocks =
            participant_count * low_slots_per_sender * packed_read_count(conjunction_count, 12);
        let scalar_terminal_blocks =
            participant_count * terminal_slots_per_sender * packed_read_count(output_count, 4);
        let scalar_source_blocks = distinct_source_blocks * (1 + low_subset_size);
        let scalar_receiver_b_blocks = participant_count
            * (2 * low_slots_per_sender + (participant_count - 1) * low_slots_per_sender_recipient)
            * conjunction_count
            * 3;
        let scalar_pairwise_p_blocks =
            participant_count * 2 * participant_count * 4 * conjunction_count * 3;
        assert_eq!(
            scalar_matched_low_blocks
                + scalar_matched_high_blocks
                + scalar_terminal_blocks
                + scalar_source_blocks
                + scalar_receiver_b_blocks
                + scalar_pairwise_p_blocks,
            71_981_280
        );

        let maximum_query_count = (1_u128 << 80) - 1;
        let minimum_honest_kmac_calls = 11_955_720_u128 + 534_520 + 360;
        let selected_evaluation_kmac_calls = 3_596_140_u128;
        let maximum_verified_inventory_count =
            (maximum_query_count - minimum_honest_kmac_calls) / selected_evaluation_kmac_calls;
        let remaining_query_count =
            (maximum_query_count - minimum_honest_kmac_calls) % selected_evaluation_kmac_calls;
        let wrong_key_target_count = maximum_verified_inventory_count * 29_620;
        assert_eq!(maximum_verified_inventory_count, 336_173_180_024_868_098);
        assert_eq!(remaining_query_count, 273_855);
        assert_eq!(wrong_key_target_count, 9_957_449_592_336_593_062_760);

        let operation_key_count = 2_951_920_u128;
        let operation_key_collision_numerator = operation_key_count * (operation_key_count - 1) / 2;
        let local_record_seal_count = 2_920_u128;
        let local_record_collision_numerator =
            local_record_seal_count * (local_record_seal_count - 1) / 2;
        let aggregate_finite_numerator_at_denominator_352 = (operation_key_collision_numerator
            << 32)
            + (29_620_u128 << 32)
            + (wrong_key_target_count << 32)
            + (45_u128 << 96)
            + local_record_collision_numerator;
        assert_eq!(operation_key_collision_numerator, 4_356_914_367_240);
        assert_eq!(local_record_collision_numerator, 4_261_740);
        assert_eq!(
            aggregate_finite_numerator_at_denominator_352,
            46_332_187_682_508_899_466_309_422_614_380
        );
    }

    #[test]
    fn every_completion_mask_coordinate_has_the_required_matched_codeword() {
        let context = evaluation_context();
        let inventories = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|participant_position| {
                MaskStreamInventory::derive(
                    &context,
                    participant_position,
                    &deterministic_held_subset_keys(participant_position),
                )
                .expect("mask inventory derives")
            })
            .collect::<Vec<_>>();
        for conjunction_ordinal in 0..2_962_u32 {
            let shares = inventories
                .iter()
                .enumerate()
                .map(|(participant_position, inventory)| {
                    inventory
                        .matched_share(participant_position as u16, conjunction_ordinal)
                        .expect("matched share derives")
                })
                .collect::<Vec<_>>();
            let low = shares.iter().map(|shares| shares.0).collect::<Vec<_>>();
            let high = shares.iter().map(|shares| shares.1).collect::<Vec<_>>();
            let low_constant = verify_codeword(&low, 3).expect("low codeword verifies");
            let high_constant = verify_codeword(&high, 6).expect("high codeword verifies");
            assert_eq!(low_constant, high_constant);
            assert!(low_constant == Gf16::ZERO || low_constant == Gf16::ONE);
        }
        for output_ordinal in 0..51_u32 {
            let shares = inventories
                .iter()
                .enumerate()
                .map(|(participant_position, inventory)| {
                    inventory
                        .terminal_share(participant_position as u16, output_ordinal)
                        .expect("terminal share derives")
                })
                .collect::<Vec<_>>();
            assert_eq!(
                verify_codeword(&shares, 3).expect("terminal codeword verifies"),
                Gf16::ZERO
            );
        }
    }

    #[test]
    fn cached_gate_streams_match_the_reviewed_direct_derivation() {
        let context = evaluation_context();
        for participant_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            let held_subset_keys = deterministic_held_subset_keys(participant_position);
            let pairwise_masters = deterministic_pairwise_inventory(participant_position);
            let ordinals = [2_u32, 99, 4_321];
            let expected = derive_gate_material_for_ordinals(
                &context,
                participant_position,
                &held_subset_keys,
                &pairwise_masters,
                &ordinals,
            )
            .expect("direct material derives");
            let inventory = GateStreamInventory::derive(
                &context,
                participant_position,
                &held_subset_keys,
                &pairwise_masters,
            )
            .expect("cached streams derive");
            let actual = ordinals
                .iter()
                .map(|ordinal| inventory.gate_material(*ordinal))
                .collect::<Result<Vec<_>, _>>()
                .expect("cached material derives");
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn first_full_tally_chunk_round_trips_the_authenticated_generation_checkpoint() {
        let context = EvaluationContext {
            top_count: 1,
            ..evaluation_context()
        };
        let plan = PaddedTallyPlan::compile(1).expect("plan compiles");
        let participant_position = 0_u16;
        let checkpoint_key = [0x5a_u8; GENERATION_CHECKPOINT_KEY_BYTE_LENGTH];
        let checkpoint = PaddedTallyGenerationCheckpoint {
            context,
            participant_position,
            allocation_nonce: [0x39; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
            next_chunk_ordinal: 0,
            held_subset_keys: deterministic_held_subset_keys(participant_position),
            pairwise_masters: deterministic_pairwise_inventory(participant_position),
            initial_wire_values: vec![0; plan.circuit.input_bit_count()],
            live_wire_pairs: Vec::new(),
            continuation_keys: BTreeSet::new(),
            chunk_identities: Vec::new(),
        };
        let encoded =
            encode_generation_checkpoint(&checkpoint, &plan, &checkpoint_key).expect("encodes");
        let decoded = decode_generation_checkpoint(&encoded, &checkpoint_key).expect("decodes");
        assert_eq!(decoded.next_chunk_ordinal, 0);
        assert_eq!(decoded.initial_wire_values.len(), 410);

        let entropy_range = plan.chunk_entropy_range(0).expect("entropy range");
        let entropy = deterministic_label_entropy(entropy_range.len(), 0x91_000);
        let first = generate_next_padded_tally_chunk(&checkpoint_key, &encoded, &entropy)
            .expect("first chunk generates");
        let replay = generate_next_padded_tally_chunk(&checkpoint_key, &encoded, &entropy)
            .expect("exact replay generates");
        assert_eq!(first, replay);
        assert_eq!(first.chunk_ordinal, 0);
        assert_eq!(
            first.chunk.len(),
            plan.descriptors[0].chunk_byte_length().unwrap()
        );
        assert!(first.manifest.is_none());
        let next_bytes = first.next_checkpoint.expect("next checkpoint");
        let next = decode_generation_checkpoint(&next_bytes, &checkpoint_key)
            .expect("next checkpoint decodes");
        assert_eq!(next.next_chunk_ordinal, 1);
        assert!(next.initial_wire_values.is_empty());
        assert_eq!(
            next.live_wire_pairs.len(),
            plan.live_wire_counts_after_chunks[0]
        );
        assert_eq!(next.chunk_identities, vec![first.chunk_identity]);

        let mut mutated = encoded.clone();
        let mutation_index = mutated.len() / 2;
        mutated[mutation_index] ^= 1;
        assert!(matches!(
            decode_generation_checkpoint(&mutated, &checkpoint_key),
            Err(PaddedContinuationError::InvalidBody)
        ));
        let mut wrong_key = checkpoint_key;
        wrong_key[0] ^= 1;
        assert!(matches!(
            decode_generation_checkpoint(&encoded, &wrong_key),
            Err(PaddedContinuationError::InvalidBody)
        ));
        assert_eq!(
            generate_next_padded_tally_chunk(
                &checkpoint_key,
                &encoded,
                &entropy[..entropy.len() - 1],
            ),
            Err(PaddedContinuationError::InvalidLabelEntropy)
        );
    }

    #[test]
    fn first_full_tally_chunk_streams_through_all_ten_participants() {
        let context = EvaluationContext {
            top_count: 1,
            ..evaluation_context()
        };
        let plan = PaddedTallyPlan::compile(1).expect("plan compiles");
        assert!(
            plan.operations[..plan.descriptors[0].operation_end]
                .iter()
                .filter(|operation| matches!(
                    operation.kind,
                    PlannedOperationKind::Conjunction { .. }
                ))
                .count()
                > 1
        );
        let generation_key = [0x5a_u8; GENERATION_CHECKPOINT_KEY_BYTE_LENGTH];
        let evaluation_key = [0x8c_u8; GENERATION_CHECKPOINT_KEY_BYTE_LENGTH];
        let entropy_range = plan.chunk_entropy_range(0).expect("entropy range");
        let mut chunks = Vec::new();
        let mut first_identities = Vec::new();
        let mut allocation_nonces = [[0_u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH];
            COMPLETION_PROFILE_PARTICIPANT_COUNT as usize];
        for participant_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            allocation_nonces[usize::from(participant_position)] =
                [u8::try_from(participant_position + 1).expect("completion position");
                    PADDED_ALLOCATION_NONCE_BYTE_LENGTH];
            let checkpoint = PaddedTallyGenerationCheckpoint {
                context,
                participant_position,
                allocation_nonce: allocation_nonces[usize::from(participant_position)],
                next_chunk_ordinal: 0,
                held_subset_keys: deterministic_held_subset_keys(participant_position),
                pairwise_masters: deterministic_pairwise_inventory(participant_position),
                initial_wire_values: vec![0; plan.circuit.input_bit_count()],
                live_wire_pairs: Vec::new(),
                continuation_keys: BTreeSet::new(),
                chunk_identities: Vec::new(),
            };
            let encoded = encode_generation_checkpoint(&checkpoint, &plan, &generation_key)
                .expect("generation checkpoint encodes");
            let entropy = deterministic_label_entropy(
                entropy_range.len(),
                0x91_000 + u64::from(participant_position),
            );
            let step = generate_next_padded_tally_chunk(&generation_key, &encoded, &entropy)
                .expect("first participant chunk generates");
            first_identities.push(step.chunk_identity);
            chunks.push(step.chunk);
        }
        let checkpoint_for_chunks = |candidate_chunks: &[Vec<u8>]| {
            let first_identities = candidate_chunks
                .iter()
                .map(|chunk| hash_bytes(CHUNK_IDENTITY_DOMAIN, chunk).expect("test chunk identity"))
                .collect::<Vec<_>>();
            let manifest_identities = core::array::from_fn(|participant_position| {
                let mut address = Vec::with_capacity(2 + Hash512::BYTE_LENGTH);
                address.extend_from_slice(&(participant_position as u16).to_le_bytes());
                address.extend_from_slice(first_identities[participant_position].as_bytes());
                hash_bytes("sealed-lattice/test/full-tally-manifest/v1", &address)
                    .expect("test manifest identity")
            });
            let mut expected_chunk_identities = Vec::with_capacity(
                usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) * plan.descriptors.len(),
            );
            for participant_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
                for chunk_ordinal in 0..plan.descriptors.len() {
                    let identity = if chunk_ordinal == 0 {
                        first_identities[usize::from(participant_position)]
                    } else {
                        let mut address = Vec::new();
                        address.extend_from_slice(&participant_position.to_le_bytes());
                        address.extend_from_slice(&(chunk_ordinal as u32).to_le_bytes());
                        hash_bytes("sealed-lattice/test/full-tally-chunk/v1", &address)
                            .expect("test chunk identity")
                    };
                    expected_chunk_identities.push(identity);
                }
            }
            PaddedTallyEvaluationCheckpoint {
                context,
                output_schema_identity: Hash512::from_bytes([0xa7; Hash512::BYTE_LENGTH]),
                next_chunk_ordinal: 0,
                batch_identity: padded_tally_batch_identity(&context, &manifest_identities)
                    .expect("batch identity"),
                manifest_identities,
                allocation_nonces,
                expected_chunk_identities,
                active_wire_tokens: Vec::new(),
            }
        };
        let checkpoint = checkpoint_for_chunks(&chunks);
        let encoded = encode_evaluation_checkpoint(&checkpoint, &plan, &evaluation_key)
            .expect("evaluation checkpoint encodes");
        let first = evaluate_next_padded_tally_chunk(&evaluation_key, &encoded, &chunks)
            .expect("first chunk evaluates");
        let replay = evaluate_next_padded_tally_chunk(&evaluation_key, &encoded, &chunks)
            .expect("exact replay evaluates");
        assert_eq!(first, replay);
        assert_eq!(first.chunk_ordinal, 0);
        assert!(first.evaluated.is_none());
        let next_checkpoint = first.next_checkpoint.expect("next checkpoint");
        let next = decode_evaluation_checkpoint(&next_checkpoint, &evaluation_key)
            .expect("next checkpoint decodes");
        assert_eq!(next.next_chunk_ordinal, 1);
        assert_eq!(
            next.active_wire_tokens.len(),
            plan.live_wire_counts_after_chunks[0]
        );

        let first_conjunction = plan
            .operations
            .iter()
            .find(|operation| matches!(operation.kind, PlannedOperationKind::Conjunction { .. }))
            .expect("the first chunk contains a conjunction");
        assert!(
            first_conjunction.payload_offset + PADDED_GATE_PAYLOAD_BYTE_LENGTH
                <= plan.descriptors[0].logical_payload_end
        );
        let gate_start = PADDED_CHUNK_HEADER_BYTE_LENGTH + first_conjunction.payload_offset;
        let padded_rows_start = gate_start
            + LOCAL_MULTIPLICATION_ROW_COUNT * PADDED_TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH
            + 1;
        let continuation_rows_start = padded_rows_start
            + PADDED_TRANSLATION_ROW_COUNT_PER_GARBLER * PADDED_MODULE_VALUE_BYTE_LENGTH;
        let mutate_receiver_zero_basis_zero_rows =
            |candidate_chunks: &mut [Vec<u8>], errors: [Gf16; 3]| {
                for (participant_position, error) in errors.into_iter().enumerate() {
                    for physical_color in 0..=1_usize {
                        let row_offset =
                            padded_rows_start + physical_color * PADDED_MODULE_VALUE_BYTE_LENGTH;
                        candidate_chunks[participant_position][row_offset] ^= error.as_u8();
                    }
                }
            };

        let weights = [
            coordinate_interpolation_weight_at_zero(0).expect("first weight"),
            coordinate_interpolation_weight_at_zero(1).expect("second weight"),
            coordinate_interpolation_weight_at_zero(2).expect("third weight"),
        ];
        let first_error = Gf16::ONE;
        let second_error = Gf16::new(2);
        let third_error = weights[0]
            .multiply(first_error)
            .add(weights[1].multiply(second_error))
            .multiply(weights[2].inverse().expect("nonzero interpolation weight"));
        assert_ne!(third_error, Gf16::ZERO);
        assert_eq!(
            weights[0]
                .multiply(first_error)
                .add(weights[1].multiply(second_error))
                .add(weights[2].multiply(third_error)),
            Gf16::ZERO
        );
        let mut harmless_corrupt_chunks = chunks.clone();
        mutate_receiver_zero_basis_zero_rows(
            &mut harmless_corrupt_chunks,
            [first_error, second_error, third_error],
        );
        let harmless_checkpoint = checkpoint_for_chunks(&harmless_corrupt_chunks);
        let harmless_checkpoint_bytes =
            encode_evaluation_checkpoint(&harmless_checkpoint, &plan, &evaluation_key)
                .expect("harmless corrupt checkpoint encodes");
        let harmless = evaluate_next_padded_tally_chunk(
            &evaluation_key,
            &harmless_checkpoint_bytes,
            &harmless_corrupt_chunks,
        )
        .expect("zero-constant corrupt padded rows remain confluent");
        let harmless_next = decode_evaluation_checkpoint(
            &harmless.next_checkpoint.expect("harmless next checkpoint"),
            &evaluation_key,
        )
        .expect("harmless next checkpoint decodes");
        assert_eq!(harmless_next.active_wire_tokens, next.active_wire_tokens);

        let mut nonzero_corrupt_chunks = chunks.clone();
        mutate_receiver_zero_basis_zero_rows(
            &mut nonzero_corrupt_chunks,
            [Gf16::ONE, Gf16::ONE, Gf16::ONE],
        );
        if weights.iter().copied().fold(Gf16::ZERO, Gf16::add) == Gf16::ZERO {
            let row_offset = padded_rows_start;
            nonzero_corrupt_chunks[2][row_offset] ^= Gf16::new(2).as_u8();
            nonzero_corrupt_chunks[2][row_offset + PADDED_MODULE_VALUE_BYTE_LENGTH] ^=
                Gf16::new(2).as_u8();
        }
        let nonzero_checkpoint = checkpoint_for_chunks(&nonzero_corrupt_chunks);
        let nonzero_checkpoint_bytes =
            encode_evaluation_checkpoint(&nonzero_checkpoint, &plan, &evaluation_key)
                .expect("nonzero corrupt checkpoint encodes");
        assert_eq!(
            evaluate_next_padded_tally_chunk(
                &evaluation_key,
                &nonzero_checkpoint_bytes,
                &nonzero_corrupt_chunks,
            ),
            Err(PaddedContinuationError::ContinuationAuthenticationFailed)
        );

        let mut corrupt_continuation_chunks = chunks.clone();
        for selector in 0..=1_usize {
            corrupt_continuation_chunks[0]
                [continuation_rows_start + selector * CONTINUATION_ROW_BYTE_LENGTH] ^= 1;
        }
        let corrupt_continuation_checkpoint = checkpoint_for_chunks(&corrupt_continuation_chunks);
        let corrupt_continuation_checkpoint_bytes =
            encode_evaluation_checkpoint(&corrupt_continuation_checkpoint, &plan, &evaluation_key)
                .expect("corrupt continuation checkpoint encodes");
        assert!(
            evaluate_next_padded_tally_chunk(
                &evaluation_key,
                &corrupt_continuation_checkpoint_bytes,
                &corrupt_continuation_chunks,
            )
            .is_err()
        );

        let mut corrupt_local_rows = chunks.clone();
        for physical_row in 0..4_usize {
            corrupt_local_rows[0][gate_start + physical_row * PADDED_TOKEN_BYTE_LENGTH] ^= 1;
        }
        let corrupt_local_checkpoint = checkpoint_for_chunks(&corrupt_local_rows);
        let corrupt_local_checkpoint_bytes =
            encode_evaluation_checkpoint(&corrupt_local_checkpoint, &plan, &evaluation_key)
                .expect("corrupt local-row checkpoint encodes");
        assert!(
            evaluate_next_padded_tally_chunk(
                &evaluation_key,
                &corrupt_local_checkpoint_bytes,
                &corrupt_local_rows,
            )
            .is_err()
        );

        let mut corrupt_chunks = chunks.clone();
        corrupt_chunks[3][PADDED_CHUNK_HEADER_BYTE_LENGTH] ^= 1;
        assert_eq!(
            evaluate_next_padded_tally_chunk(&evaluation_key, &encoded, &corrupt_chunks),
            Err(PaddedContinuationError::InvalidChunk)
        );
        let mut corrupt_checkpoint = encoded.clone();
        let mutation_index = corrupt_checkpoint.len() / 2;
        corrupt_checkpoint[mutation_index] ^= 1;
        assert!(matches!(
            decode_evaluation_checkpoint(&corrupt_checkpoint, &evaluation_key),
            Err(PaddedContinuationError::InvalidBody)
        ));
    }

    #[test]
    fn every_admitted_result_width_is_derived_from_top_count() {
        for top_count in 1..=COMPLETION_PROFILE_OPTION_COUNT {
            let mut terminal_bits = vec![false; usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)];
            terminal_bits[0] = true;
            terminal_bits.push(true);
            for option_position in 0..top_count {
                for bit in 0..FIELD_BIT_WIDTH {
                    terminal_bits.push((option_position >> bit) & 1 == 1);
                }
            }
            assert_eq!(
                terminal_bits.len(),
                usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) + 1 + 4 * usize::from(top_count)
            );
            let evaluated = evaluated_tally_from_terminal_bits(
                Hash512::from_bytes([top_count as u8; Hash512::BYTE_LENGTH]),
                &EvaluationContext {
                    top_count,
                    ..evaluation_context()
                },
                Hash512::from_bytes([0xa7; Hash512::BYTE_LENGTH]),
                &terminal_bits,
            )
            .expect("terminal decodes");
            assert!(evaluated.accepted_ballot_authorship[0]);
            assert_eq!(
                evaluated.ordered_option_positions,
                Some((0..top_count).collect())
            );

            terminal_bits[usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)] = false;
            let no_result = evaluated_tally_from_terminal_bits(
                Hash512::from_bytes([top_count as u8; Hash512::BYTE_LENGTH]),
                &EvaluationContext {
                    top_count,
                    ..evaluation_context()
                },
                Hash512::from_bytes([0xa7; Hash512::BYTE_LENGTH]),
                &terminal_bits,
            )
            .expect("empty usable ballot terminal decodes");
            assert_eq!(no_result.ordered_option_positions, None);
        }
    }
}
