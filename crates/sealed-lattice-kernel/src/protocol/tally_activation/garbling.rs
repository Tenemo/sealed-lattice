use std::collections::BTreeSet;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

use crate::tally_circuit::{BooleanOperation, CompiledTallyCircuit, WireIndex};

use super::{
    COMPLETION_PROFILE_PARTICIPANT_COUNT, FIELD_BIT_WIDTH, Gf16, LABEL_BYTE_LENGTH,
    TallyActivationError, compile_completion_tally, derive_local_input_shares,
    derive_matched_mask_shares, derive_output_mask_share, participant_point, verify_codeword,
};
use crate::protocol::preparation_plaintext::{
    AFFINE_MODULE_VALUE_BYTE_LENGTH, HeldAffineEvaluation, HeldSubsetKey,
};
use crate::protocol::source::{SOURCE_BIT_COUNT, SOURCE_CORRECTION_BYTE_LENGTH};

const ACTIVATION_CHUNK_MAGIC: [u8; 4] = *b"SLTA";
const ACTIVATION_CHUNK_VERSION: u16 = 1;
const ACTIVATION_SEED_BYTE_LENGTH: usize = 32;
const MAXIMUM_PARTICIPANT_CHUNK_BYTE_LENGTH: usize = 480_000;
const INITIAL_LABEL_BYTE_LENGTH: usize = COMPLETION_PROFILE_PARTICIPANT_COUNT
    * (1 + SOURCE_BIT_COUNT)
    * FIELD_BIT_WIDTH
    * LABEL_BYTE_LENGTH;
const CONSTANT_OPERATION_BYTE_LENGTH: usize = FIELD_BIT_WIDTH * LABEL_BYTE_LENGTH;
const EXCLUSIVE_OR_OPERATION_BYTE_LENGTH: usize = FIELD_BIT_WIDTH * 4 * LABEL_BYTE_LENGTH;
const CONJUNCTION_OPERATION_BYTE_LENGTH: usize = 35 * 4 * LABEL_BYTE_LENGTH
    + FIELD_BIT_WIDTH * LABEL_BYTE_LENGTH
    + 1
    + COMPLETION_PROFILE_PARTICIPANT_COUNT * FIELD_BIT_WIDTH * 2 * LABEL_BYTE_LENGTH
    + 2 * 2 * LABEL_BYTE_LENGTH
    + (FIELD_BIT_WIDTH - 1) * LABEL_BYTE_LENGTH
    + 1;
const OUTPUT_REKEY_BYTE_LENGTH: usize =
    FIELD_BIT_WIDTH * LABEL_BYTE_LENGTH + FIELD_BIT_WIDTH * 4 * LABEL_BYTE_LENGTH + 1;
const CHUNK_HEADER_BYTE_LENGTH: usize = 4 + 2 + 64 + 2 + 2 + 2 + 4 + 4 + 1;
const EVALUATION_CHECKPOINT_MAGIC: [u8; 4] = *b"SLTE";
const EVALUATION_CHECKPOINT_VERSION: u16 = 1;

const LABEL_DOMAIN: &[u8] = b"sealed-lattice/evaluation/wire-label/v1";
const GARBLED_ROW_DOMAIN: &[u8] = b"sealed-lattice/evaluation/garbled-row/v1";
const TRANSLATION_DOMAIN: &[u8] = b"sealed-lattice/evaluation/share-translation/v1";
const CONTINUATION_DOMAIN: &[u8] = b"sealed-lattice/evaluation/continuation-mask/v2";

type Label = [u8; LABEL_BYTE_LENGTH];
type LabelPair = [Label; 2];
type FieldLabels = [Label; FIELD_BIT_WIDTH];
type ModuleValue = [u8; AFFINE_MODULE_VALUE_BYTE_LENGTH];

#[derive(Clone, Copy)]
struct GarblingIndex {
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
}

impl GarblingIndex {
    fn new(participant_position: u16, kind: u8, major_ordinal: u32, minor_ordinal: u16) -> Self {
        Self {
            participant_position,
            kind,
            major_ordinal,
            minor_ordinal,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ActivationContext {
    pub(crate) target_identity: [u8; 64],
    pub(crate) top_count: u16,
    pub(crate) source_submission_bitmap: u16,
    pub(crate) source_corrections:
        [Option<[u8; SOURCE_CORRECTION_BYTE_LENGTH]>; COMPLETION_PROFILE_PARTICIPANT_COUNT],
}

impl ActivationContext {
    pub(crate) fn new(
        target_identity: [u8; 64],
        top_count: u16,
        source_submission_bitmap: u16,
        source_corrections: [Option<[u8; SOURCE_CORRECTION_BYTE_LENGTH]>;
            COMPLETION_PROFILE_PARTICIPANT_COUNT],
    ) -> Result<Self, TallyActivationError> {
        compile_completion_tally(top_count)?;
        super::validate_source_inventory(source_submission_bitmap, &source_corrections)?;
        if source_submission_bitmap == 0 {
            return Err(TallyActivationError::InvalidSourceSubmissionBitmap);
        }
        Ok(Self {
            target_identity,
            top_count,
            source_submission_bitmap,
            source_corrections,
        })
    }
}

pub(crate) struct LocalActivationMaterial {
    pub(crate) participant_position: u16,
    pub(crate) activation_seed: [u8; ACTIVATION_SEED_BYTE_LENGTH],
    pub(crate) held_subset_keys: Vec<HeldSubsetKey>,
    pub(crate) held_affine_evaluations: Vec<HeldAffineEvaluation>,
    pub(crate) local_affine_constants: [u8; 2 * AFFINE_MODULE_VALUE_BYTE_LENGTH],
}

impl Drop for LocalActivationMaterial {
    fn drop(&mut self) {
        self.activation_seed.zeroize();
        self.local_affine_constants.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivationChunkRange {
    pub(crate) first_operation: u32,
    pub(crate) operation_end: u32,
    pub(crate) includes_terminal_rekey: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifiedTallyTerminal {
    NoResult {
        accepted_ballot_authorship: [bool; COMPLETION_PROFILE_PARTICIPANT_COUNT],
    },
    Result {
        accepted_ballot_authorship: [bool; COMPLETION_PROFILE_PARTICIPANT_COUNT],
        ordered_option_positions: Vec<u16>,
    },
}

#[derive(Clone, Copy)]
struct WireAlias {
    base_wire: WireIndex,
    invert_low_basis: bool,
}

struct LocalActivationGenerator<'a> {
    context: &'a ActivationContext,
    circuit: &'a CompiledTallyCircuit,
    material: &'a LocalActivationMaterial,
    wire_aliases: Vec<WireAlias>,
    conjunction_ordinals: Vec<Option<usize>>,
}

pub(crate) fn activation_chunk_ranges(
    circuit: &CompiledTallyCircuit,
) -> Result<Vec<ActivationChunkRange>, TallyActivationError> {
    let operation_count = circuit.operations().len();
    let terminal_byte_length = circuit
        .output_wires()
        .len()
        .checked_mul(OUTPUT_REKEY_BYTE_LENGTH)
        .ok_or(TallyActivationError::ArithmeticOverflow)?;
    let mut ranges = Vec::new();
    let mut first_operation = 0_usize;
    while first_operation < operation_count {
        let mut byte_length = CHUNK_HEADER_BYTE_LENGTH;
        if first_operation == 0 {
            byte_length = byte_length
                .checked_add(INITIAL_LABEL_BYTE_LENGTH)
                .ok_or(TallyActivationError::ArithmeticOverflow)?;
        }
        let mut operation_end = first_operation;
        while operation_end < operation_count {
            let operation_byte_length = operation_byte_length(&circuit.operations()[operation_end]);
            if operation_end > first_operation
                && byte_length
                    .checked_add(operation_byte_length)
                    .is_none_or(|length| length > MAXIMUM_PARTICIPANT_CHUNK_BYTE_LENGTH)
            {
                break;
            }
            byte_length = byte_length
                .checked_add(operation_byte_length)
                .ok_or(TallyActivationError::ArithmeticOverflow)?;
            operation_end += 1;
        }
        let includes_terminal_rekey = operation_end == operation_count
            && byte_length
                .checked_add(terminal_byte_length)
                .is_some_and(|length| length <= MAXIMUM_PARTICIPANT_CHUNK_BYTE_LENGTH);
        ranges.push(ActivationChunkRange {
            first_operation: u32::try_from(first_operation)
                .map_err(|_| TallyActivationError::ArithmeticOverflow)?,
            operation_end: u32::try_from(operation_end)
                .map_err(|_| TallyActivationError::ArithmeticOverflow)?,
            includes_terminal_rekey,
        });
        first_operation = operation_end;
    }
    if ranges
        .last()
        .is_none_or(|range| !range.includes_terminal_rekey)
    {
        let operation_count =
            u32::try_from(operation_count).map_err(|_| TallyActivationError::ArithmeticOverflow)?;
        ranges.push(ActivationChunkRange {
            first_operation: operation_count,
            operation_end: operation_count,
            includes_terminal_rekey: true,
        });
    }
    Ok(ranges)
}

fn operation_byte_length(operation: &BooleanOperation) -> usize {
    match operation {
        BooleanOperation::Constant(_) => CONSTANT_OPERATION_BYTE_LENGTH,
        BooleanOperation::ExclusiveOr { .. } => EXCLUSIVE_OR_OPERATION_BYTE_LENGTH,
        BooleanOperation::Conjunction { .. } => CONJUNCTION_OPERATION_BYTE_LENGTH,
        BooleanOperation::Negation { .. } => 0,
    }
}

pub(crate) fn generate_activation_chunk(
    context: &ActivationContext,
    material: &LocalActivationMaterial,
    range: ActivationChunkRange,
) -> Result<Vec<u8>, TallyActivationError> {
    let circuit = compile_completion_tally(context.top_count)?;
    LocalActivationGenerator::new(context, &circuit, material)?.generate(range)
}

impl<'a> LocalActivationGenerator<'a> {
    fn new(
        context: &'a ActivationContext,
        circuit: &'a CompiledTallyCircuit,
        material: &'a LocalActivationMaterial,
    ) -> Result<Self, TallyActivationError> {
        super::validate_local_material(material.participant_position, &material.held_subset_keys)?;
        if material.held_affine_evaluations.len() != COMPLETION_PROFILE_PARTICIPANT_COUNT
            || material
                .held_affine_evaluations
                .iter()
                .enumerate()
                .any(|(position, evaluation)| usize::from(evaluation.receiver_position) != position)
        {
            return Err(TallyActivationError::InvalidSubsetKeyVector);
        }
        let mut wire_aliases = (0..circuit.input_bit_count())
            .map(|wire| {
                Ok(WireAlias {
                    base_wire: u32::try_from(wire)
                        .map_err(|_| TallyActivationError::ArithmeticOverflow)?,
                    invert_low_basis: false,
                })
            })
            .collect::<Result<Vec<_>, TallyActivationError>>()?;
        let mut conjunction_ordinals = Vec::with_capacity(circuit.operations().len());
        let mut next_conjunction_ordinal = 0_usize;
        for (operation_index, operation) in circuit.operations().iter().enumerate() {
            let output_wire = operation_output_wire(circuit, operation_index)?;
            match operation {
                BooleanOperation::Negation { input_wire } => {
                    let mut alias = *wire_aliases
                        .get(
                            usize::try_from(*input_wire)
                                .map_err(|_| TallyActivationError::ArithmeticOverflow)?,
                        )
                        .ok_or(TallyActivationError::TallyCircuit)?;
                    alias.invert_low_basis = !alias.invert_low_basis;
                    wire_aliases.push(alias);
                    conjunction_ordinals.push(None);
                }
                BooleanOperation::Conjunction { .. } => {
                    wire_aliases.push(WireAlias {
                        base_wire: output_wire,
                        invert_low_basis: false,
                    });
                    conjunction_ordinals.push(Some(next_conjunction_ordinal));
                    next_conjunction_ordinal += 1;
                }
                _ => {
                    wire_aliases.push(WireAlias {
                        base_wire: output_wire,
                        invert_low_basis: false,
                    });
                    conjunction_ordinals.push(None);
                }
            }
        }
        if wire_aliases.len() != circuit.wire_count() {
            return Err(TallyActivationError::TallyCircuit);
        }
        Ok(Self {
            context,
            circuit,
            material,
            wire_aliases,
            conjunction_ordinals,
        })
    }

    fn generate(&self, range: ActivationChunkRange) -> Result<Vec<u8>, TallyActivationError> {
        let first_operation = usize::try_from(range.first_operation)
            .map_err(|_| TallyActivationError::MalformedActivationChunk)?;
        let operation_end = usize::try_from(range.operation_end)
            .map_err(|_| TallyActivationError::MalformedActivationChunk)?;
        if first_operation > operation_end || operation_end > self.circuit.operations().len() {
            return Err(TallyActivationError::MalformedActivationChunk);
        }
        if range.includes_terminal_rekey && operation_end != self.circuit.operations().len() {
            return Err(TallyActivationError::MalformedActivationChunk);
        }
        let mut writer = ChunkWriter::new();
        write_chunk_header(
            &mut writer,
            self.context,
            self.material.participant_position,
            range,
        );
        if first_operation == 0 {
            self.write_initial_labels(&mut writer)?;
        }
        for operation_index in first_operation..operation_end {
            self.write_operation(&mut writer, operation_index)?;
        }
        if range.includes_terminal_rekey {
            self.write_terminal_rekey(&mut writer)?;
        }
        if writer.bytes.len() > MAXIMUM_PARTICIPANT_CHUNK_BYTE_LENGTH {
            return Err(TallyActivationError::ArithmeticOverflow);
        }
        Ok(writer.bytes)
    }

    fn write_initial_labels(&self, writer: &mut ChunkWriter) -> Result<(), TallyActivationError> {
        let shares = derive_local_input_shares(
            self.material.participant_position,
            self.context.source_submission_bitmap,
            &self.context.source_corrections,
            &self.material.held_subset_keys,
        )?;
        if shares.len() != self.circuit.input_bit_count() {
            return Err(TallyActivationError::TallyCircuit);
        }
        for (wire, share) in shares.into_iter().enumerate() {
            for basis in 0..FIELD_BIT_WIDTH {
                let pair = self.logical_label_pair(wire as u32, basis)?;
                writer.write_fixed(&pair[usize::from((share.as_u8() >> basis) & 1)]);
            }
        }
        Ok(())
    }

    fn write_operation(
        &self,
        writer: &mut ChunkWriter,
        operation_index: usize,
    ) -> Result<(), TallyActivationError> {
        let operation = self
            .circuit
            .operations()
            .get(operation_index)
            .ok_or(TallyActivationError::TallyCircuit)?;
        let output_wire = operation_output_wire(self.circuit, operation_index)?;
        match operation {
            BooleanOperation::Constant(value) => {
                for basis in 0..FIELD_BIT_WIDTH {
                    let pair = self.logical_label_pair(output_wire, basis)?;
                    writer.write_fixed(&pair[usize::from(basis == 0 && *value)]);
                }
            }
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            } => {
                for basis in 0..FIELD_BIT_WIDTH {
                    let left = self.logical_label_pair(*left_wire, basis)?;
                    let right = self.logical_label_pair(*right_wire, basis)?;
                    let output = self.logical_label_pair(output_wire, basis)?;
                    let rows = garble_gate(
                        self.context,
                        GarblingIndex::new(
                            self.material.participant_position,
                            1,
                            operation_index as u32,
                            basis as u16,
                        ),
                        &left,
                        &right,
                        &output,
                        false,
                    );
                    writer.write_labels(&rows);
                }
            }
            BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => self.write_conjunction(
                writer,
                operation_index,
                output_wire,
                *left_wire,
                *right_wire,
            )?,
            BooleanOperation::Negation { .. } => {}
        }
        Ok(())
    }

    fn write_conjunction(
        &self,
        writer: &mut ChunkWriter,
        operation_index: usize,
        output_wire: WireIndex,
        left_wire: WireIndex,
        right_wire: WireIndex,
    ) -> Result<(), TallyActivationError> {
        let conjunction_ordinal = self
            .conjunction_ordinals
            .get(operation_index)
            .copied()
            .flatten()
            .ok_or(TallyActivationError::TallyCircuit)?;
        let (low_mask_share, high_mask_share) = derive_matched_mask_shares(
            self.material.participant_position,
            conjunction_ordinal,
            &self.material.held_subset_keys,
        )?;
        let left_pairs = self.logical_field_pairs(left_wire)?;
        let right_pairs = self.logical_field_pairs(right_wire)?;
        let mask_pairs: [LabelPair; FIELD_BIT_WIDTH] = core::array::from_fn(|basis| {
            derive_label_pair(
                self.context,
                &self.material.activation_seed,
                self.material.participant_position,
                2,
                operation_index as u32,
                basis as u16,
            )
        });
        let mut builder = GarblingGateBuilder::new(self.context, self.material, operation_index);
        let product_pairs = builder.multiply_fields(&left_pairs, &right_pairs);
        let mut masked_output_pairs = Vec::with_capacity(FIELD_BIT_WIDTH);
        for (basis, (product_pair, mask_pair)) in
            product_pairs.iter().zip(mask_pairs.iter()).enumerate()
        {
            let output_pair = derive_label_pair(
                self.context,
                &self.material.activation_seed,
                self.material.participant_position,
                3,
                operation_index as u32,
                basis as u16,
            );
            builder.append_gate(*product_pair, *mask_pair, output_pair, false);
            masked_output_pairs.push(output_pair);
        }
        if builder.next_gate_ordinal != 35 {
            return Err(TallyActivationError::TallyCircuit);
        }
        writer.write_labels(&builder.rows);
        for (basis, mask_pair) in mask_pairs.iter().enumerate() {
            writer.write_fixed(&mask_pair[usize::from((high_mask_share.as_u8() >> basis) & 1)]);
        }
        writer.write_u8(semantic_map(&masked_output_pairs));

        for evaluation in &self.material.held_affine_evaluations {
            for (basis, masked_output_pair) in masked_output_pairs.iter().enumerate() {
                let mut rows = [[0_u8; AFFINE_MODULE_VALUE_BYTE_LENGTH]; 2];
                for semantic in 0..=1_u8 {
                    let mut plaintext = if basis == 0 {
                        evaluation.affine_a_evaluation
                    } else {
                        [0_u8; AFFINE_MODULE_VALUE_BYTE_LENGTH]
                    };
                    if semantic != 0 {
                        module_add_scaled(
                            &mut plaintext,
                            &evaluation.affine_b_evaluation,
                            Gf16::new(1_u8 << basis),
                        );
                    }
                    let label = &masked_output_pair[usize::from(semantic)];
                    let physical_row = label[0] & 1;
                    let mask = translation_mask(
                        self.context,
                        self.material.participant_position,
                        evaluation.receiver_position,
                        operation_index,
                        basis as u16,
                        physical_row,
                        label,
                    );
                    module_xor(&mut plaintext, &mask);
                    rows[usize::from(physical_row)] = plaintext;
                    plaintext.zeroize();
                }
                writer.write_fixed(&rows[0]);
                writer.write_fixed(&rows[1]);
                rows.zeroize();
            }
        }

        let output_pairs = self.logical_field_pairs(output_wire)?;
        let affine_a_constant: ModuleValue = self.material.local_affine_constants
            [..AFFINE_MODULE_VALUE_BYTE_LENGTH]
            .try_into()
            .map_err(|_| TallyActivationError::InvalidSubsetKeyVector)?;
        let affine_b_constant: ModuleValue = self.material.local_affine_constants
            [AFFINE_MODULE_VALUE_BYTE_LENGTH..]
            .try_into()
            .map_err(|_| TallyActivationError::InvalidSubsetKeyVector)?;
        for candidate in 0..=1_u8 {
            let mut key = affine_a_constant;
            if candidate != 0 {
                module_xor(&mut key, &affine_b_constant);
            }
            let candidate_share = low_mask_share.add(Gf16::new(candidate));
            let selected_label = output_pairs[0][usize::from(candidate_share.as_u8() & 1)];
            let mask = continuation_mask(
                self.context,
                self.material.participant_position,
                operation_index,
                candidate,
                &key,
            );
            let mut row = mask;
            for (row_byte, label_byte) in row[..LABEL_BYTE_LENGTH].iter_mut().zip(selected_label) {
                *row_byte ^= label_byte;
            }
            writer.write_fixed(&row);
            row.zeroize();
            key.zeroize();
        }
        for (basis, output_pair) in output_pairs.iter().enumerate().skip(1) {
            writer.write_fixed(&output_pair[usize::from((low_mask_share.as_u8() >> basis) & 1)]);
        }
        writer.write_u8(semantic_map(&output_pairs));
        Ok(())
    }

    fn write_terminal_rekey(&self, writer: &mut ChunkWriter) -> Result<(), TallyActivationError> {
        for (output_bit_ordinal, wire) in self.circuit.output_wires().into_iter().enumerate() {
            let output_mask_share = derive_output_mask_share(
                self.material.participant_position,
                output_bit_ordinal,
                &self.material.held_subset_keys,
            )?;
            let input_pairs = self.logical_field_pairs(wire)?;
            let mask_pairs: [LabelPair; FIELD_BIT_WIDTH] = core::array::from_fn(|basis| {
                derive_label_pair(
                    self.context,
                    &self.material.activation_seed,
                    self.material.participant_position,
                    4,
                    output_bit_ordinal as u32,
                    basis as u16,
                )
            });
            let output_pairs: [LabelPair; FIELD_BIT_WIDTH] = core::array::from_fn(|basis| {
                derive_label_pair(
                    self.context,
                    &self.material.activation_seed,
                    self.material.participant_position,
                    5,
                    output_bit_ordinal as u32,
                    basis as u16,
                )
            });
            for (basis, mask_pair) in mask_pairs.iter().enumerate() {
                writer
                    .write_fixed(&mask_pair[usize::from((output_mask_share.as_u8() >> basis) & 1)]);
            }
            for basis in 0..FIELD_BIT_WIDTH {
                let rows = garble_gate(
                    self.context,
                    GarblingIndex::new(
                        self.material.participant_position,
                        3,
                        output_bit_ordinal as u32,
                        basis as u16,
                    ),
                    &input_pairs[basis],
                    &mask_pairs[basis],
                    &output_pairs[basis],
                    false,
                );
                writer.write_labels(&rows);
            }
            writer.write_u8(semantic_map(&output_pairs));
        }
        Ok(())
    }

    fn logical_field_pairs(
        &self,
        wire: WireIndex,
    ) -> Result<[LabelPair; FIELD_BIT_WIDTH], TallyActivationError> {
        (0..FIELD_BIT_WIDTH)
            .map(|basis| self.logical_label_pair(wire, basis))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| TallyActivationError::TallyCircuit)
    }

    fn logical_label_pair(
        &self,
        wire: WireIndex,
        basis: usize,
    ) -> Result<LabelPair, TallyActivationError> {
        let alias = self
            .wire_aliases
            .get(usize::try_from(wire).map_err(|_| TallyActivationError::ArithmeticOverflow)?)
            .ok_or(TallyActivationError::TallyCircuit)?;
        let mut pair = derive_label_pair(
            self.context,
            &self.material.activation_seed,
            self.material.participant_position,
            1,
            alias.base_wire,
            basis as u16,
        );
        if basis == 0 && alias.invert_low_basis {
            pair.swap(0, 1);
        }
        Ok(pair)
    }
}

struct GarblingGateBuilder<'a> {
    context: &'a ActivationContext,
    material: &'a LocalActivationMaterial,
    operation_index: usize,
    next_gate_ordinal: u16,
    rows: Vec<Label>,
}

impl<'a> GarblingGateBuilder<'a> {
    fn new(
        context: &'a ActivationContext,
        material: &'a LocalActivationMaterial,
        operation_index: usize,
    ) -> Self {
        Self {
            context,
            material,
            operation_index,
            next_gate_ordinal: 0,
            rows: Vec::with_capacity(35 * 4),
        }
    }

    fn append_derived_gate(
        &mut self,
        left: LabelPair,
        right: LabelPair,
        conjunction: bool,
    ) -> LabelPair {
        let output = derive_label_pair(
            self.context,
            &self.material.activation_seed,
            self.material.participant_position,
            6,
            self.operation_index as u32,
            self.next_gate_ordinal,
        );
        self.append_gate(left, right, output, conjunction);
        output
    }

    fn append_gate(
        &mut self,
        left: LabelPair,
        right: LabelPair,
        output: LabelPair,
        conjunction: bool,
    ) {
        let rows = garble_gate(
            self.context,
            GarblingIndex::new(
                self.material.participant_position,
                2,
                self.operation_index as u32,
                self.next_gate_ordinal,
            ),
            &left,
            &right,
            &output,
            conjunction,
        );
        self.rows.extend(rows);
        self.next_gate_ordinal += 1;
    }

    fn multiply_fields(
        &mut self,
        left: &[LabelPair; FIELD_BIT_WIDTH],
        right: &[LabelPair; FIELD_BIT_WIDTH],
    ) -> [LabelPair; FIELD_BIT_WIDTH] {
        let products: [LabelPair; 16] = core::array::from_fn(|position| {
            self.append_derived_gate(left[position / 4], right[position % 4], true)
        });
        let c0 = products[0];
        let c1 = self.append_derived_gate(products[1], products[4], false);
        let c2_left = self.append_derived_gate(products[2], products[5], false);
        let c2 = self.append_derived_gate(c2_left, products[8], false);
        let c3_left = self.append_derived_gate(products[3], products[6], false);
        let c3_right = self.append_derived_gate(products[9], products[12], false);
        let c3 = self.append_derived_gate(c3_left, c3_right, false);
        let c4_left = self.append_derived_gate(products[7], products[10], false);
        let c4 = self.append_derived_gate(c4_left, products[13], false);
        let c5 = self.append_derived_gate(products[11], products[14], false);
        let c6 = products[15];
        let d0 = self.append_derived_gate(c0, c4, false);
        let d1_left = self.append_derived_gate(c1, c4, false);
        let d1 = self.append_derived_gate(d1_left, c5, false);
        let d2_left = self.append_derived_gate(c2, c5, false);
        let d2 = self.append_derived_gate(d2_left, c6, false);
        let d3 = self.append_derived_gate(c3, c6, false);
        [d0, d1, d2, d3]
    }
}

fn operation_output_wire(
    circuit: &CompiledTallyCircuit,
    operation_index: usize,
) -> Result<WireIndex, TallyActivationError> {
    u32::try_from(
        circuit
            .input_bit_count()
            .checked_add(operation_index)
            .ok_or(TallyActivationError::ArithmeticOverflow)?,
    )
    .map_err(|_| TallyActivationError::ArithmeticOverflow)
}

fn last_wire_uses(circuit: &CompiledTallyCircuit) -> Result<Vec<usize>, TallyActivationError> {
    let mut last_uses = vec![0_usize; circuit.wire_count()];
    for (operation_index, operation) in circuit.operations().iter().enumerate() {
        let inputs: &[WireIndex] = match operation {
            BooleanOperation::Constant(_) => &[],
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            }
            | BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => &[*left_wire, *right_wire],
            BooleanOperation::Negation { input_wire } => &[*input_wire],
        };
        for wire in inputs {
            let wire =
                usize::try_from(*wire).map_err(|_| TallyActivationError::ArithmeticOverflow)?;
            let last_use = last_uses
                .get_mut(wire)
                .ok_or(TallyActivationError::TallyCircuit)?;
            *last_use = (*last_use).max(operation_index);
        }
    }
    let terminal_use = circuit.operations().len();
    for wire in circuit.output_wires() {
        let wire = usize::try_from(wire).map_err(|_| TallyActivationError::ArithmeticOverflow)?;
        *last_uses
            .get_mut(wire)
            .ok_or(TallyActivationError::TallyCircuit)? = terminal_use;
    }
    Ok(last_uses)
}

fn derive_label_pair(
    context: &ActivationContext,
    activation_seed: &[u8; ACTIVATION_SEED_BYTE_LENGTH],
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
) -> LabelPair {
    let index = GarblingIndex::new(participant_position, kind, major_ordinal, minor_ordinal);
    let permutation_bit =
        indexed_xof::<1>(LABEL_DOMAIN, context, index, 2, &[activation_seed])[0] & 1;
    core::array::from_fn(|semantic| {
        let mut label = indexed_xof::<LABEL_BYTE_LENGTH>(
            LABEL_DOMAIN,
            context,
            index,
            semantic as u8,
            &[activation_seed],
        );
        label[0] = (label[0] & 0xfe) | (permutation_bit ^ semantic as u8);
        label
    })
}

fn garble_gate(
    context: &ActivationContext,
    index: GarblingIndex,
    left: &LabelPair,
    right: &LabelPair,
    output: &LabelPair,
    conjunction: bool,
) -> [Label; 4] {
    let mut rows = [[0_u8; LABEL_BYTE_LENGTH]; 4];
    for (left_semantic, left_label) in left.iter().enumerate() {
        for (right_semantic, right_label) in right.iter().enumerate() {
            let physical_row = usize::from((left_label[0] & 1) | ((right_label[0] & 1) << 1));
            let semantic_output = if conjunction {
                left_semantic & right_semantic
            } else {
                left_semantic ^ right_semantic
            };
            let mut row = indexed_xof::<LABEL_BYTE_LENGTH>(
                GARBLED_ROW_DOMAIN,
                context,
                index,
                physical_row as u8,
                &[left_label, right_label],
            );
            xor_label(&mut row, &output[semantic_output]);
            rows[physical_row] = row;
        }
    }
    rows
}

fn translation_mask(
    context: &ActivationContext,
    garbler_position: u16,
    receiver_position: u16,
    operation_index: usize,
    basis: u16,
    physical_row: u8,
    label: &Label,
) -> ModuleValue {
    let mut hasher = common_xof(TRANSLATION_DOMAIN, context);
    hasher.update(&garbler_position.to_le_bytes());
    hasher.update(&receiver_position.to_le_bytes());
    hasher.update(&(operation_index as u32).to_le_bytes());
    hasher.update(&basis.to_le_bytes());
    hasher.update(&[physical_row]);
    hasher.update(label);
    read_xof(hasher)
}

fn continuation_mask(
    context: &ActivationContext,
    receiver_position: u16,
    operation_index: usize,
    candidate: u8,
    key: &ModuleValue,
) -> [u8; 2 * LABEL_BYTE_LENGTH] {
    let mut hasher = common_xof(CONTINUATION_DOMAIN, context);
    hasher.update(&receiver_position.to_le_bytes());
    hasher.update(&(operation_index as u32).to_le_bytes());
    hasher.update(&[candidate]);
    hasher.update(key);
    read_xof(hasher)
}

fn indexed_xof<const LENGTH: usize>(
    domain: &[u8],
    context: &ActivationContext,
    index: GarblingIndex,
    row: u8,
    secret_items: &[&[u8]],
) -> [u8; LENGTH] {
    let mut hasher = common_xof(domain, context);
    hasher.update(&index.participant_position.to_le_bytes());
    hasher.update(&[index.kind]);
    hasher.update(&index.major_ordinal.to_le_bytes());
    hasher.update(&index.minor_ordinal.to_le_bytes());
    hasher.update(&[row]);
    for item in secret_items {
        hasher.update(&(item.len() as u32).to_le_bytes());
        hasher.update(item);
    }
    read_xof(hasher)
}

fn common_xof(domain: &[u8], context: &ActivationContext) -> Shake256 {
    let mut hasher = Shake256::default();
    hasher.update(&(domain.len() as u16).to_le_bytes());
    hasher.update(domain);
    hasher.update(&context.target_identity);
    hasher.update(&context.top_count.to_le_bytes());
    hasher.update(&context.source_submission_bitmap.to_le_bytes());
    hasher
}

fn read_xof<const LENGTH: usize>(hasher: Shake256) -> [u8; LENGTH] {
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; LENGTH];
    reader.read(&mut output);
    output
}

fn semantic_map(pairs: &[LabelPair]) -> u8 {
    pairs
        .iter()
        .enumerate()
        .fold(0_u8, |map, (basis, pair)| map | ((pair[0][0] & 1) << basis))
}

fn module_add_scaled(output: &mut ModuleValue, input: &ModuleValue, scalar: Gf16) {
    for (output_byte, input_byte) in output.iter_mut().zip(input) {
        let low = Gf16::new(*input_byte & 0x0f).multiply(scalar).as_u8();
        let high = Gf16::new(*input_byte >> 4).multiply(scalar).as_u8();
        *output_byte ^= low | (high << 4);
    }
}

fn module_xor(output: &mut ModuleValue, input: &ModuleValue) {
    for (output_byte, input_byte) in output.iter_mut().zip(input) {
        *output_byte ^= input_byte;
    }
}

fn xor_label(output: &mut Label, input: &Label) {
    for (output_byte, input_byte) in output.iter_mut().zip(input) {
        *output_byte ^= input_byte;
    }
}

struct ChunkWriter {
    bytes: Vec<u8>,
}

impl ChunkWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(MAXIMUM_PARTICIPANT_CHUNK_BYTE_LENGTH),
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn write_labels(&mut self, labels: &[Label]) {
        for label in labels {
            self.write_fixed(label);
        }
    }
}

fn write_chunk_header(
    writer: &mut ChunkWriter,
    context: &ActivationContext,
    participant_position: u16,
    range: ActivationChunkRange,
) {
    writer.write_fixed(&ACTIVATION_CHUNK_MAGIC);
    writer.write_u16(ACTIVATION_CHUNK_VERSION);
    writer.write_fixed(&context.target_identity);
    writer.write_u16(context.top_count);
    writer.write_u16(context.source_submission_bitmap);
    writer.write_u16(participant_position);
    writer.write_u32(range.first_operation);
    writer.write_u32(range.operation_end);
    writer.write_u8(u8::from(range.includes_terminal_rekey));
}

struct ChunkReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ChunkReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_fixed(&mut self, length: usize) -> Result<&'a [u8], TallyActivationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TallyActivationError::MalformedActivationChunk)?;
        if end > self.bytes.len() {
            return Err(TallyActivationError::MalformedActivationChunk);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, TallyActivationError> {
        Ok(self.read_fixed(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, TallyActivationError> {
        let bytes = self.read_fixed(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, TallyActivationError> {
        let bytes = self.read_fixed(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            TallyActivationError::MalformedActivationChunk
        })?))
    }

    fn read_label(&mut self) -> Result<Label, TallyActivationError> {
        self.read_fixed(LABEL_BYTE_LENGTH)?
            .try_into()
            .map_err(|_| TallyActivationError::MalformedActivationChunk)
    }

    fn finish(self) -> Result<(), TallyActivationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(TallyActivationError::MalformedActivationChunk)
        }
    }
}

fn read_and_verify_header(
    reader: &mut ChunkReader<'_>,
    context: &ActivationContext,
    participant_position: u16,
    range: ActivationChunkRange,
) -> Result<(), TallyActivationError> {
    if reader.read_fixed(4)? != ACTIVATION_CHUNK_MAGIC
        || reader.read_u16()? != ACTIVATION_CHUNK_VERSION
        || reader.read_fixed(64)? != context.target_identity
        || reader.read_u16()? != context.top_count
        || reader.read_u16()? != context.source_submission_bitmap
        || reader.read_u16()? != participant_position
        || reader.read_u32()? != range.first_operation
        || reader.read_u32()? != range.operation_end
        || reader.read_u8()? != u8::from(range.includes_terminal_rekey)
    {
        return Err(TallyActivationError::MismatchedActivationChunk);
    }
    Ok(())
}

struct ParsedConjunction {
    masked_output_labels: FieldLabels,
    masked_output_value: Gf16,
    translation_rows: Vec<Label>,
    continuation_rows: [[u8; 2 * LABEL_BYTE_LENGTH]; 2],
    direct_output_labels: [Label; FIELD_BIT_WIDTH - 1],
    output_semantic_map: u8,
}

pub(crate) struct ActivationEvaluator {
    context: ActivationContext,
    circuit: CompiledTallyCircuit,
    active_labels: Vec<Vec<Option<FieldLabels>>>,
    last_wire_uses: Vec<usize>,
    next_operation: usize,
    terminal: Option<VerifiedTallyTerminal>,
}

impl ActivationEvaluator {
    pub(crate) fn new(context: ActivationContext) -> Result<Self, TallyActivationError> {
        let circuit = compile_completion_tally(context.top_count)?;
        let last_wire_uses = last_wire_uses(&circuit)?;
        let active_labels = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|_| vec![None; circuit.wire_count()])
            .collect();
        Ok(Self {
            context,
            circuit,
            active_labels,
            last_wire_uses,
            next_operation: 0,
            terminal: None,
        })
    }

    pub(crate) fn absorb(
        &mut self,
        range: ActivationChunkRange,
        chunks: &[Vec<u8>],
    ) -> Result<Option<&VerifiedTallyTerminal>, TallyActivationError> {
        if self.terminal.is_some()
            || chunks.len() != COMPLETION_PROFILE_PARTICIPANT_COUNT
            || usize::try_from(range.first_operation)
                .map_err(|_| TallyActivationError::MismatchedActivationChunk)?
                != self.next_operation
        {
            return Err(TallyActivationError::MismatchedActivationChunk);
        }
        let operation_end = usize::try_from(range.operation_end)
            .map_err(|_| TallyActivationError::MismatchedActivationChunk)?;
        if operation_end < self.next_operation || operation_end > self.circuit.operations().len() {
            return Err(TallyActivationError::MismatchedActivationChunk);
        }
        let mut readers = chunks
            .iter()
            .enumerate()
            .map(|(position, chunk)| {
                let mut reader = ChunkReader::new(chunk);
                read_and_verify_header(&mut reader, &self.context, position as u16, range)?;
                Ok(reader)
            })
            .collect::<Result<Vec<_>, TallyActivationError>>()?;
        if self.next_operation == 0 {
            self.read_initial_labels(&mut readers)?;
        }
        while self.next_operation < operation_end {
            self.evaluate_next_operation(&mut readers)?;
            self.next_operation += 1;
        }
        if range.includes_terminal_rekey {
            if operation_end != self.circuit.operations().len() {
                return Err(TallyActivationError::MismatchedActivationChunk);
            }
            let terminal = self.evaluate_terminal_rekey(&mut readers)?;
            self.terminal = Some(terminal);
        } else {
            self.prune_consumed_labels();
        }
        for reader in readers {
            reader.finish()?;
        }
        Ok(self.terminal.as_ref())
    }

    pub(crate) fn terminal(&self) -> Option<&VerifiedTallyTerminal> {
        self.terminal.as_ref()
    }

    pub(crate) const fn context(&self) -> &ActivationContext {
        &self.context
    }

    pub(crate) fn encode_checkpoint(&self) -> Result<Vec<u8>, TallyActivationError> {
        if self.terminal.is_some() {
            return Err(TallyActivationError::MismatchedActivationChunk);
        }
        let live_wires = self
            .active_labels
            .first()
            .ok_or(TallyActivationError::MalformedActivationChunk)?
            .iter()
            .enumerate()
            .filter_map(|(wire, labels)| labels.is_some().then_some(wire))
            .collect::<Vec<_>>();
        for participant_labels in &self.active_labels {
            if participant_labels
                .iter()
                .enumerate()
                .filter_map(|(wire, labels)| labels.is_some().then_some(wire))
                .ne(live_wires.iter().copied())
            {
                return Err(TallyActivationError::MalformedActivationChunk);
            }
        }
        let mut writer = ChunkWriter::new();
        writer.write_fixed(&EVALUATION_CHECKPOINT_MAGIC);
        writer.write_u16(EVALUATION_CHECKPOINT_VERSION);
        writer.write_fixed(&self.context.target_identity);
        writer.write_u16(self.context.top_count);
        writer.write_u16(self.context.source_submission_bitmap);
        for correction in &self.context.source_corrections {
            writer.write_u8(u8::from(correction.is_some()));
            writer.write_fixed(&correction.unwrap_or_default());
        }
        writer.write_u32(
            u32::try_from(self.next_operation)
                .map_err(|_| TallyActivationError::ArithmeticOverflow)?,
        );
        writer.write_u32(
            u32::try_from(live_wires.len())
                .map_err(|_| TallyActivationError::ArithmeticOverflow)?,
        );
        for wire in live_wires {
            writer.write_u32(
                u32::try_from(wire).map_err(|_| TallyActivationError::ArithmeticOverflow)?,
            );
            for participant_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
                let labels = self.active_labels[participant_position][wire]
                    .ok_or(TallyActivationError::MalformedActivationChunk)?;
                for label in labels {
                    writer.write_fixed(&label);
                }
            }
        }
        Ok(writer.bytes)
    }

    pub(crate) fn decode_checkpoint(bytes: &[u8]) -> Result<Self, TallyActivationError> {
        let mut reader = ChunkReader::new(bytes);
        if reader.read_fixed(4)? != EVALUATION_CHECKPOINT_MAGIC
            || reader.read_u16()? != EVALUATION_CHECKPOINT_VERSION
        {
            return Err(TallyActivationError::MalformedActivationChunk);
        }
        let target_identity = reader
            .read_fixed(64)?
            .try_into()
            .map_err(|_| TallyActivationError::MalformedActivationChunk)?;
        let top_count = reader.read_u16()?;
        let source_submission_bitmap = reader.read_u16()?;
        let mut source_corrections = [None; COMPLETION_PROFILE_PARTICIPANT_COUNT];
        for correction in &mut source_corrections {
            let is_present = reader.read_u8()?;
            if is_present > 1 {
                return Err(TallyActivationError::MalformedActivationChunk);
            }
            let bytes: [u8; SOURCE_CORRECTION_BYTE_LENGTH] = reader
                .read_fixed(SOURCE_CORRECTION_BYTE_LENGTH)?
                .try_into()
                .map_err(|_| TallyActivationError::MalformedActivationChunk)?;
            if is_present == 1 {
                *correction = Some(bytes);
            } else if bytes.iter().any(|byte| *byte != 0) {
                return Err(TallyActivationError::MalformedActivationChunk);
            }
        }
        let context = ActivationContext::new(
            target_identity,
            top_count,
            source_submission_bitmap,
            source_corrections,
        )?;
        let mut evaluator = Self::new(context)?;
        evaluator.next_operation = usize::try_from(reader.read_u32()?)
            .map_err(|_| TallyActivationError::MalformedActivationChunk)?;
        if evaluator.next_operation > evaluator.circuit.operations().len() {
            return Err(TallyActivationError::MalformedActivationChunk);
        }
        let live_wire_count = usize::try_from(reader.read_u32()?)
            .map_err(|_| TallyActivationError::MalformedActivationChunk)?;
        let mut previous_wire = None;
        for _ in 0..live_wire_count {
            let wire = usize::try_from(reader.read_u32()?)
                .map_err(|_| TallyActivationError::MalformedActivationChunk)?;
            if wire >= evaluator.circuit.wire_count()
                || previous_wire.is_some_and(|previous| previous >= wire)
                || evaluator.last_wire_uses[wire] < evaluator.next_operation
            {
                return Err(TallyActivationError::MalformedActivationChunk);
            }
            previous_wire = Some(wire);
            for participant_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
                evaluator.active_labels[participant_position][wire] =
                    Some(read_field_labels(&mut reader)?);
            }
        }
        reader.finish()?;
        Ok(evaluator)
    }

    fn prune_consumed_labels(&mut self) {
        for participant_labels in &mut self.active_labels {
            for (wire, labels) in participant_labels.iter_mut().enumerate() {
                if self.last_wire_uses[wire] >= self.next_operation {
                    continue;
                }
                if let Some(mut labels) = labels.take() {
                    labels.zeroize();
                }
            }
        }
    }

    fn read_initial_labels(
        &mut self,
        readers: &mut [ChunkReader<'_>],
    ) -> Result<(), TallyActivationError> {
        for (participant_position, reader) in readers.iter_mut().enumerate() {
            for wire in 0..self.circuit.input_bit_count() {
                let labels = read_field_labels(reader)?;
                self.active_labels[participant_position][wire] = Some(labels);
            }
        }
        Ok(())
    }

    fn evaluate_next_operation(
        &mut self,
        readers: &mut [ChunkReader<'_>],
    ) -> Result<(), TallyActivationError> {
        let operation_index = self.next_operation;
        let operation = self
            .circuit
            .operations()
            .get(operation_index)
            .cloned()
            .ok_or(TallyActivationError::TallyCircuit)?;
        let output_wire = operation_output_wire(&self.circuit, operation_index)?;
        match operation {
            BooleanOperation::Constant(_) => {
                for (position, reader) in readers.iter_mut().enumerate() {
                    self.set_active(position, output_wire, read_field_labels(reader)?)?;
                }
            }
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            } => {
                for (position, reader) in readers.iter_mut().enumerate() {
                    let left = self.active(position, left_wire)?;
                    let right = self.active(position, right_wire)?;
                    let mut output = [[0_u8; LABEL_BYTE_LENGTH]; FIELD_BIT_WIDTH];
                    for basis in 0..FIELD_BIT_WIDTH {
                        let rows = read_gate_rows(reader)?;
                        output[basis] = evaluate_gate(
                            &self.context,
                            GarblingIndex::new(
                                position as u16,
                                1,
                                operation_index as u32,
                                basis as u16,
                            ),
                            &left[basis],
                            &right[basis],
                            &rows,
                        );
                    }
                    self.set_active(position, output_wire, output)?;
                }
            }
            BooleanOperation::Negation { input_wire } => {
                for position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
                    let input = self.active(position, input_wire)?;
                    self.set_active(position, output_wire, input)?;
                }
            }
            BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => self.evaluate_conjunction(
                readers,
                operation_index,
                output_wire,
                left_wire,
                right_wire,
            )?,
        }
        Ok(())
    }

    fn evaluate_conjunction(
        &mut self,
        readers: &mut [ChunkReader<'_>],
        operation_index: usize,
        output_wire: WireIndex,
        left_wire: WireIndex,
        right_wire: WireIndex,
    ) -> Result<(), TallyActivationError> {
        let mut parsed = Vec::with_capacity(COMPLETION_PROFILE_PARTICIPANT_COUNT);
        for (position, reader) in readers.iter_mut().enumerate() {
            let left = self.active(position, left_wire)?;
            let right = self.active(position, right_wire)?;
            parsed.push(parse_and_evaluate_conjunction(
                reader,
                &self.context,
                position as u16,
                operation_index,
                &left,
                &right,
            )?);
        }
        let masked_values = parsed
            .iter()
            .map(|entry| entry.masked_output_value)
            .collect::<Vec<_>>();
        let selector = verify_codeword(&masked_values, 6)?;
        if selector.as_u8() > 1 {
            return Err(TallyActivationError::InvalidCodeword);
        }
        let selector = selector.as_u8();
        let mut refreshed_values = Vec::with_capacity(COMPLETION_PROFILE_PARTICIPANT_COUNT);
        let mut refreshed_labels = Vec::with_capacity(COMPLETION_PROFILE_PARTICIPANT_COUNT);
        for receiver_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            let mut translation_values = Vec::with_capacity(COMPLETION_PROFILE_PARTICIPANT_COUNT);
            for (garbler_position, garbler) in parsed.iter().enumerate() {
                let mut translation_value = [0_u8; AFFINE_MODULE_VALUE_BYTE_LENGTH];
                for basis in 0..FIELD_BIT_WIDTH {
                    let label = &garbler.masked_output_labels[basis];
                    let physical_row = label[0] & 1;
                    let row_index = (receiver_position * FIELD_BIT_WIDTH + basis) * 2
                        + usize::from(physical_row);
                    let mut plaintext = *garbler
                        .translation_rows
                        .get(row_index)
                        .ok_or(TallyActivationError::MalformedActivationChunk)?;
                    let mask = translation_mask(
                        &self.context,
                        garbler_position as u16,
                        receiver_position as u16,
                        operation_index,
                        basis as u16,
                        physical_row,
                        label,
                    );
                    module_xor(&mut plaintext, &mask);
                    module_xor(&mut translation_value, &plaintext);
                    plaintext.zeroize();
                }
                translation_values.push(translation_value);
            }
            let mut continuation_key = interpolate_module_at_zero(&translation_values)?;
            let mask = continuation_mask(
                &self.context,
                receiver_position as u16,
                operation_index,
                selector,
                &continuation_key,
            );
            let mut plaintext = parsed[receiver_position].continuation_rows[usize::from(selector)];
            for (plaintext_byte, mask_byte) in plaintext.iter_mut().zip(mask) {
                *plaintext_byte ^= mask_byte;
            }
            if plaintext[LABEL_BYTE_LENGTH..].iter().any(|byte| *byte != 0) {
                plaintext.zeroize();
                continuation_key.zeroize();
                return Err(TallyActivationError::ContinuationAuthenticationFailed);
            }
            let mut labels = [[0_u8; LABEL_BYTE_LENGTH]; FIELD_BIT_WIDTH];
            labels[0].copy_from_slice(&plaintext[..LABEL_BYTE_LENGTH]);
            labels[1..].copy_from_slice(&parsed[receiver_position].direct_output_labels);
            let value =
                decode_field_labels(&labels, parsed[receiver_position].output_semantic_map)?;
            refreshed_values.push(value);
            refreshed_labels.push(labels);
            plaintext.zeroize();
            continuation_key.zeroize();
        }
        let product = verify_codeword(&refreshed_values, 3)?;
        if product.as_u8() > 1 {
            return Err(TallyActivationError::InvalidCodeword);
        }
        for (position, labels) in refreshed_labels.into_iter().enumerate() {
            self.set_active(position, output_wire, labels)?;
        }
        Ok(())
    }

    fn evaluate_terminal_rekey(
        &mut self,
        readers: &mut [ChunkReader<'_>],
    ) -> Result<VerifiedTallyTerminal, TallyActivationError> {
        let mut terminal_bits = Vec::with_capacity(self.circuit.output_wires().len());
        for (output_bit_ordinal, wire) in self.circuit.output_wires().into_iter().enumerate() {
            let mut values = Vec::with_capacity(COMPLETION_PROFILE_PARTICIPANT_COUNT);
            for (position, reader) in readers.iter_mut().enumerate() {
                let input = self.active(position, wire)?;
                let mask_labels = read_field_labels(reader)?;
                let mut masked_labels = [[0_u8; LABEL_BYTE_LENGTH]; FIELD_BIT_WIDTH];
                for basis in 0..FIELD_BIT_WIDTH {
                    let rows = read_gate_rows(reader)?;
                    masked_labels[basis] = evaluate_gate(
                        &self.context,
                        GarblingIndex::new(
                            position as u16,
                            3,
                            output_bit_ordinal as u32,
                            basis as u16,
                        ),
                        &input[basis],
                        &mask_labels[basis],
                        &rows,
                    );
                }
                values.push(decode_field_labels(&masked_labels, reader.read_u8()?)?);
            }
            let value = verify_codeword(&values, 3)?;
            if value.as_u8() > 1 {
                return Err(TallyActivationError::InvalidTerminalOutput);
            }
            terminal_bits.push(value.as_u8() != 0);
        }
        decode_terminal(self.context.top_count, &terminal_bits)
    }

    fn active(
        &self,
        participant_position: usize,
        wire: WireIndex,
    ) -> Result<FieldLabels, TallyActivationError> {
        self.active_labels
            .get(participant_position)
            .and_then(|wires| wires.get(usize::try_from(wire).ok()?))
            .and_then(|labels| *labels)
            .ok_or(TallyActivationError::MalformedActivationChunk)
    }

    fn set_active(
        &mut self,
        participant_position: usize,
        wire: WireIndex,
        labels: FieldLabels,
    ) -> Result<(), TallyActivationError> {
        let slot = self
            .active_labels
            .get_mut(participant_position)
            .and_then(|wires| wires.get_mut(usize::try_from(wire).ok()?))
            .ok_or(TallyActivationError::MalformedActivationChunk)?;
        *slot = Some(labels);
        Ok(())
    }
}

fn parse_and_evaluate_conjunction(
    reader: &mut ChunkReader<'_>,
    context: &ActivationContext,
    participant_position: u16,
    operation_index: usize,
    left: &FieldLabels,
    right: &FieldLabels,
) -> Result<ParsedConjunction, TallyActivationError> {
    let rows = (0..35)
        .map(|_| read_gate_rows(reader))
        .collect::<Result<Vec<_>, _>>()?;
    let mask_labels = read_field_labels(reader)?;
    let masked_output_semantic_map = reader.read_u8()?;
    if masked_output_semantic_map & 0xf0 != 0 {
        return Err(TallyActivationError::MalformedActivationChunk);
    }
    let mut builder =
        EvaluationGateBuilder::new(context, participant_position, operation_index, &rows);
    let product = builder.multiply_fields(left, right)?;
    let mut masked_output_labels = [[0_u8; LABEL_BYTE_LENGTH]; FIELD_BIT_WIDTH];
    for basis in 0..FIELD_BIT_WIDTH {
        masked_output_labels[basis] = builder.append_gate(&product[basis], &mask_labels[basis])?;
    }
    if builder.next_gate_ordinal != 35 {
        return Err(TallyActivationError::TallyCircuit);
    }
    let masked_output_value =
        decode_field_labels(&masked_output_labels, masked_output_semantic_map)?;
    let translation_rows = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT * FIELD_BIT_WIDTH * 2)
        .map(|_| reader.read_label())
        .collect::<Result<Vec<_>, _>>()?;
    let continuation_rows = [
        reader
            .read_fixed(2 * LABEL_BYTE_LENGTH)?
            .try_into()
            .map_err(|_| TallyActivationError::MalformedActivationChunk)?,
        reader
            .read_fixed(2 * LABEL_BYTE_LENGTH)?
            .try_into()
            .map_err(|_| TallyActivationError::MalformedActivationChunk)?,
    ];
    let direct_output_labels = [
        reader.read_label()?,
        reader.read_label()?,
        reader.read_label()?,
    ];
    let output_semantic_map = reader.read_u8()?;
    if output_semantic_map & 0xf0 != 0 {
        return Err(TallyActivationError::MalformedActivationChunk);
    }
    Ok(ParsedConjunction {
        masked_output_labels,
        masked_output_value,
        translation_rows,
        continuation_rows,
        direct_output_labels,
        output_semantic_map,
    })
}

struct EvaluationGateBuilder<'a> {
    context: &'a ActivationContext,
    participant_position: u16,
    operation_index: usize,
    rows: &'a [[Label; 4]],
    next_gate_ordinal: u16,
}

impl<'a> EvaluationGateBuilder<'a> {
    fn new(
        context: &'a ActivationContext,
        participant_position: u16,
        operation_index: usize,
        rows: &'a [[Label; 4]],
    ) -> Self {
        Self {
            context,
            participant_position,
            operation_index,
            rows,
            next_gate_ordinal: 0,
        }
    }

    fn append_gate(&mut self, left: &Label, right: &Label) -> Result<Label, TallyActivationError> {
        let rows = self
            .rows
            .get(usize::from(self.next_gate_ordinal))
            .ok_or(TallyActivationError::MalformedActivationChunk)?;
        let output = evaluate_gate(
            self.context,
            GarblingIndex::new(
                self.participant_position,
                2,
                self.operation_index as u32,
                self.next_gate_ordinal,
            ),
            left,
            right,
            rows,
        );
        self.next_gate_ordinal += 1;
        Ok(output)
    }

    fn multiply_fields(
        &mut self,
        left: &FieldLabels,
        right: &FieldLabels,
    ) -> Result<FieldLabels, TallyActivationError> {
        let products = (0..16)
            .map(|position| self.append_gate(&left[position / 4], &right[position % 4]))
            .collect::<Result<Vec<_>, _>>()?;
        let c0 = products[0];
        let c1 = self.append_gate(&products[1], &products[4])?;
        let c2_left = self.append_gate(&products[2], &products[5])?;
        let c2 = self.append_gate(&c2_left, &products[8])?;
        let c3_left = self.append_gate(&products[3], &products[6])?;
        let c3_right = self.append_gate(&products[9], &products[12])?;
        let c3 = self.append_gate(&c3_left, &c3_right)?;
        let c4_left = self.append_gate(&products[7], &products[10])?;
        let c4 = self.append_gate(&c4_left, &products[13])?;
        let c5 = self.append_gate(&products[11], &products[14])?;
        let c6 = products[15];
        let d0 = self.append_gate(&c0, &c4)?;
        let d1_left = self.append_gate(&c1, &c4)?;
        let d1 = self.append_gate(&d1_left, &c5)?;
        let d2_left = self.append_gate(&c2, &c5)?;
        let d2 = self.append_gate(&d2_left, &c6)?;
        let d3 = self.append_gate(&c3, &c6)?;
        Ok([d0, d1, d2, d3])
    }
}

fn evaluate_gate(
    context: &ActivationContext,
    index: GarblingIndex,
    left: &Label,
    right: &Label,
    rows: &[Label; 4],
) -> Label {
    let physical_row = usize::from((left[0] & 1) | ((right[0] & 1) << 1));
    let mut output = rows[physical_row];
    let mask = indexed_xof::<LABEL_BYTE_LENGTH>(
        GARBLED_ROW_DOMAIN,
        context,
        index,
        physical_row as u8,
        &[left, right],
    );
    xor_label(&mut output, &mask);
    output
}

fn read_gate_rows(reader: &mut ChunkReader<'_>) -> Result<[Label; 4], TallyActivationError> {
    Ok([
        reader.read_label()?,
        reader.read_label()?,
        reader.read_label()?,
        reader.read_label()?,
    ])
}

fn read_field_labels(reader: &mut ChunkReader<'_>) -> Result<FieldLabels, TallyActivationError> {
    Ok([
        reader.read_label()?,
        reader.read_label()?,
        reader.read_label()?,
        reader.read_label()?,
    ])
}

fn decode_field_labels(
    labels: &FieldLabels,
    semantic_map: u8,
) -> Result<Gf16, TallyActivationError> {
    if semantic_map & 0xf0 != 0 {
        return Err(TallyActivationError::MalformedActivationChunk);
    }
    Ok(Gf16::new(
        labels
            .iter()
            .enumerate()
            .fold(0_u8, |value, (basis, label)| {
                value | (((label[0] & 1) ^ ((semantic_map >> basis) & 1)) << basis)
            }),
    ))
}

fn interpolate_module_at_zero(values: &[ModuleValue]) -> Result<ModuleValue, TallyActivationError> {
    if values.len() != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(TallyActivationError::InvalidCodeword);
    }
    let mut result = [0_u8; AFFINE_MODULE_VALUE_BYTE_LENGTH];
    for (position, value) in values.iter().enumerate() {
        let point = participant_point(position as u16)?;
        let mut numerator = Gf16::ONE;
        let mut denominator = Gf16::ONE;
        for other_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            if position == other_position {
                continue;
            }
            let other_point = participant_point(other_position as u16)?;
            numerator = numerator.multiply(other_point);
            denominator = denominator.multiply(point.add(other_point));
        }
        let weight = numerator.multiply(
            denominator
                .inverse()
                .ok_or(TallyActivationError::InvalidCodeword)?,
        );
        module_add_scaled(&mut result, value, weight);
    }
    Ok(result)
}

fn decode_terminal(
    top_count: u16,
    bits: &[bool],
) -> Result<VerifiedTallyTerminal, TallyActivationError> {
    let expected_bit_count = COMPLETION_PROFILE_PARTICIPANT_COUNT
        .checked_add(1)
        .and_then(|count| count.checked_add(4 * usize::from(top_count)))
        .ok_or(TallyActivationError::ArithmeticOverflow)?;
    if bits.len() != expected_bit_count {
        return Err(TallyActivationError::InvalidTerminalOutput);
    }
    let accepted_ballot_authorship: [bool; COMPLETION_PROFILE_PARTICIPANT_COUNT] = bits
        [..COMPLETION_PROFILE_PARTICIPANT_COUNT]
        .try_into()
        .map_err(|_| TallyActivationError::InvalidTerminalOutput)?;
    if !bits[COMPLETION_PROFILE_PARTICIPANT_COUNT] {
        return Ok(VerifiedTallyTerminal::NoResult {
            accepted_ballot_authorship,
        });
    }
    let mut ordered_option_positions = Vec::with_capacity(usize::from(top_count));
    let mut unique_positions = BTreeSet::new();
    for output_position in 0..usize::from(top_count) {
        let first_bit = COMPLETION_PROFILE_PARTICIPANT_COUNT + 1 + output_position * 4;
        let position = (0..4).fold(0_u16, |value, bit_position| {
            value | (u16::from(bits[first_bit + bit_position]) << bit_position)
        });
        if usize::from(position) >= COMPLETION_PROFILE_PARTICIPANT_COUNT {
            return Err(TallyActivationError::InvalidTerminalOutput);
        }
        if !unique_positions.insert(position) {
            return Err(TallyActivationError::DuplicateResultPosition);
        }
        ordered_option_positions.push(position);
    }
    Ok(VerifiedTallyTerminal::Result {
        accepted_ballot_authorship,
        ordered_option_positions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::preparation_plaintext::sender_subset_slots;
    use crate::protocol::source::derive_honest_source_correction;
    use crate::tally_circuit::direct_evaluator::evaluate_tally_directly;
    use crate::tally_circuit::{TallyBallotInput, TallyEvaluationInput};

    fn subset_key(family: u16, subset: u16) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(b"sealed-lattice/test/full-tally/garbling-subset-key/v1");
        hasher.update(&family.to_le_bytes());
        hasher.update(&subset.to_le_bytes());
        read_xof(hasher)
    }

    fn held_keys(participant_position: u16) -> Vec<HeldSubsetKey> {
        sender_subset_slots(participant_position)
            .into_iter()
            .map(|(family, subset)| HeldSubsetKey {
                family,
                subset,
                key: subset_key(family, subset),
            })
            .collect()
    }

    fn module_polynomial(owner: usize, degree: usize, nonzero_constant: bool) -> Vec<ModuleValue> {
        (0..=degree)
            .map(|coefficient| {
                let mut hasher = Shake256::default();
                hasher.update(b"sealed-lattice/test/full-tally/affine/v1");
                hasher.update(&(owner as u16).to_le_bytes());
                hasher.update(&(coefficient as u16).to_le_bytes());
                let mut value: ModuleValue = read_xof(hasher);
                if coefficient == 0 && nonzero_constant && value.iter().all(|byte| *byte == 0) {
                    value[0] = 1;
                }
                value
            })
            .collect()
    }

    fn evaluate_module(coefficients: &[ModuleValue], point: Gf16) -> ModuleValue {
        let mut result = [0_u8; AFFINE_MODULE_VALUE_BYTE_LENGTH];
        for coefficient in coefficients.iter().rev() {
            let previous = result;
            result = *coefficient;
            module_add_scaled(&mut result, &previous, point);
        }
        result
    }

    fn materials() -> Vec<LocalActivationMaterial> {
        let affine_polynomials = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|owner| {
                (
                    module_polynomial(owner, 9, false),
                    module_polynomial(owner + 100, 3, true),
                )
            })
            .collect::<Vec<_>>();
        (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|participant_position| {
                let point = participant_point(participant_position as u16).expect("point");
                let held_affine_evaluations = affine_polynomials
                    .iter()
                    .enumerate()
                    .map(
                        |(receiver_position, (affine_a, affine_b))| HeldAffineEvaluation {
                            receiver_position: receiver_position as u16,
                            affine_a_evaluation: evaluate_module(affine_a, point),
                            affine_b_evaluation: evaluate_module(affine_b, point),
                        },
                    )
                    .collect();
                let (own_affine_a, own_affine_b) = &affine_polynomials[participant_position];
                let mut local_affine_constants = [0_u8; 2 * AFFINE_MODULE_VALUE_BYTE_LENGTH];
                local_affine_constants[..AFFINE_MODULE_VALUE_BYTE_LENGTH]
                    .copy_from_slice(&own_affine_a[0]);
                local_affine_constants[AFFINE_MODULE_VALUE_BYTE_LENGTH..]
                    .copy_from_slice(&own_affine_b[0]);
                LocalActivationMaterial {
                    participant_position: participant_position as u16,
                    activation_seed: [participant_position as u8 + 17; ACTIVATION_SEED_BYTE_LENGTH],
                    held_subset_keys: held_keys(participant_position as u16),
                    held_affine_evaluations,
                    local_affine_constants,
                }
            })
            .collect()
    }

    fn score_inventory() -> [[u8; 10]; COMPLETION_PROFILE_PARTICIPANT_COUNT] {
        core::array::from_fn(|position| [1 + (position % 10) as u8, 10, 9, 8, 7, 6, 5, 4, 3, 2])
    }

    fn context_for(
        top_count: u16,
        source_submission_bitmap: u16,
        scores: &[[u8; 10]; COMPLETION_PROFILE_PARTICIPANT_COUNT],
    ) -> ActivationContext {
        let materials = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|position| held_keys(position as u16))
            .collect::<Vec<_>>();
        let mut corrections = [None; COMPLETION_PROFILE_PARTICIPANT_COUNT];
        for position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            if source_submission_bitmap & (1_u16 << position) != 0 {
                corrections[position] = Some(
                    derive_honest_source_correction(
                        position as u16,
                        &scores[position],
                        &materials[position],
                    )
                    .expect("correction"),
                );
            }
        }
        ActivationContext::new([0x5a; 64], top_count, source_submission_bitmap, corrections)
            .expect("context")
    }

    fn context(top_count: u16) -> ActivationContext {
        context_for(top_count, 0x03ff, &score_inventory())
    }

    fn execute_complete_ceremony(
        context: &ActivationContext,
        materials: &[LocalActivationMaterial],
    ) -> (VerifiedTallyTerminal, usize, usize) {
        let circuit = compile_completion_tally(context.top_count).expect("circuit");
        let ranges = activation_chunk_ranges(&circuit).expect("ranges");
        let generators = materials
            .iter()
            .map(|material| {
                LocalActivationGenerator::new(context, &circuit, material).expect("local generator")
            })
            .collect::<Vec<_>>();
        let mut evaluator = ActivationEvaluator::new(context.clone()).expect("evaluator");
        let mut emitted_bytes = 0_usize;
        let mut peak_checkpoint_bytes = 0_usize;
        for range in ranges {
            let chunks = generators
                .iter()
                .map(|generator| generator.generate(range).expect("activation chunk"))
                .collect::<Vec<_>>();
            emitted_bytes += chunks.iter().map(Vec::len).sum::<usize>();
            evaluator.absorb(range, &chunks).expect("chunk accepts");
            if evaluator.terminal().is_none() {
                let checkpoint = evaluator.encode_checkpoint().expect("checkpoint encodes");
                peak_checkpoint_bytes = peak_checkpoint_bytes.max(checkpoint.len());
                evaluator = ActivationEvaluator::decode_checkpoint(&checkpoint)
                    .expect("checkpoint restores");
            }
        }
        (
            evaluator.terminal().expect("terminal").clone(),
            emitted_bytes,
            peak_checkpoint_bytes,
        )
    }

    #[test]
    fn chunk_plan_respects_the_copied_buffer_envelope_and_covers_every_operation() {
        for top_count in 1..=10 {
            let circuit = compile_completion_tally(top_count).expect("circuit");
            let ranges = activation_chunk_ranges(&circuit).expect("ranges");
            assert_eq!(ranges[0].first_operation, 0);
            assert!(ranges.last().expect("last").includes_terminal_rekey);
            for pair in ranges.windows(2) {
                assert_eq!(pair[0].operation_end, pair[1].first_operation);
            }
            assert_eq!(
                ranges.last().expect("last").operation_end as usize,
                circuit.operations().len(),
            );
        }
    }

    #[test]
    fn one_real_chunk_round_trips_and_corruption_refuses() {
        let context = context(1);
        let circuit = compile_completion_tally(1).expect("circuit");
        let range = activation_chunk_ranges(&circuit).expect("ranges")[0];
        let materials = materials();
        let chunks = materials
            .iter()
            .map(|material| generate_activation_chunk(&context, material, range).expect("chunk"))
            .collect::<Vec<_>>();
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.len() <= MAXIMUM_PARTICIPANT_CHUNK_BYTE_LENGTH)
        );
        let mut evaluator = ActivationEvaluator::new(context.clone()).expect("evaluator");
        evaluator
            .absorb(range, &chunks)
            .expect("first chunk accepts");

        let mut corrupt_chunks = chunks;
        corrupt_chunks[0][6] ^= 1;
        let mut corrupt_evaluator = ActivationEvaluator::new(context).expect("evaluator");
        assert!(corrupt_evaluator.absorb(range, &corrupt_chunks).is_err());
    }

    #[test]
    fn complete_top_one_ceremony_matches_the_independent_direct_evaluator() {
        let context = context(1);
        let circuit = compile_completion_tally(1).expect("circuit");
        let materials = materials();
        let (terminal, emitted_bytes, peak_checkpoint_bytes) =
            execute_complete_ceremony(&context, &materials);
        assert!(emitted_bytes > 200_000_000);
        assert!(peak_checkpoint_bytes < 8_388_608);
        let expected = evaluate_tally_directly(
            circuit.profile(),
            &TallyEvaluationInput::new(
                score_inventory()
                    .into_iter()
                    .map(|scores| TallyBallotInput::new(true, scores.to_vec()))
                    .collect(),
            ),
        )
        .expect("direct tally evaluates");
        match terminal {
            VerifiedTallyTerminal::Result {
                accepted_ballot_authorship,
                ordered_option_positions,
            } => {
                assert_eq!(
                    accepted_ballot_authorship,
                    expected.accepted_ballot_authorship(),
                );
                assert_eq!(
                    ordered_option_positions.as_slice(),
                    expected
                        .accepted_ordered_option_positions()
                        .expect("nonempty direct result"),
                );
            }
            VerifiedTallyTerminal::NoResult { .. } => panic!("submitted tally has a result"),
        }
    }

    #[test]
    fn complete_top_ten_ceremony_handles_abstentions_and_unusable_ballots() {
        let mut scores = score_inventory();
        scores[2][4] = 0;
        scores[5][8] = 15;
        let source_submission_bitmap = 0x03ff & !(1 << 1) & !(1 << 7);
        let context = context_for(10, source_submission_bitmap, &scores);
        let circuit = compile_completion_tally(10).expect("circuit");
        let materials = materials();
        let (terminal, emitted_bytes, peak_checkpoint_bytes) =
            execute_complete_ceremony(&context, &materials);
        assert!(emitted_bytes > 300_000_000);
        assert!(peak_checkpoint_bytes < 8_388_608);
        let expected = evaluate_tally_directly(
            circuit.profile(),
            &TallyEvaluationInput::new(
                scores
                    .into_iter()
                    .enumerate()
                    .map(|(position, scores)| {
                        TallyBallotInput::new(
                            source_submission_bitmap & (1 << position) != 0,
                            scores.to_vec(),
                        )
                    })
                    .collect(),
            ),
        )
        .expect("direct tally evaluates");
        match terminal {
            VerifiedTallyTerminal::Result {
                accepted_ballot_authorship,
                ordered_option_positions,
            } => {
                assert_eq!(
                    accepted_ballot_authorship,
                    expected.accepted_ballot_authorship(),
                );
                assert_eq!(
                    ordered_option_positions,
                    expected
                        .accepted_ordered_option_positions()
                        .expect("nonempty direct result"),
                );
                assert!(!accepted_ballot_authorship[1]);
                assert!(!accepted_ballot_authorship[2]);
                assert!(!accepted_ballot_authorship[5]);
                assert!(!accepted_ballot_authorship[7]);
            }
            VerifiedTallyTerminal::NoResult { .. } => panic!("usable ballots remain"),
        }
    }

    #[test]
    fn complete_nonempty_source_inventory_can_verify_no_result() {
        let scores = [[0_u8; 10]; COMPLETION_PROFILE_PARTICIPANT_COUNT];
        let context = context_for(1, 0x03ff, &scores);
        let materials = materials();
        let (terminal, _, _) = execute_complete_ceremony(&context, &materials);
        assert_eq!(
            terminal,
            VerifiedTallyTerminal::NoResult {
                accepted_ballot_authorship: [false; COMPLETION_PROFILE_PARTICIPANT_COUNT],
            },
        );
    }
}
