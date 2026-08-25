use crate::{
    encoding::{append_bytes, append_varuint},
    foundation::Hash512,
    hashing::{StreamingHash512, hash_framed_parts_512},
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile, WireIndex},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    label_encoding::LABEL_BODY_FIELD_LIMB_COUNT,
    preparation_arithmetic_graph::{PreparationArithmeticGraph, PreparationMultiplicationFamily},
};

const PREPARATION_MULTIPLICATION_CATALOG_SOURCE: &[u8] =
    include_bytes!("preparation_multiplication_catalog.rs");
const PREPARATION_MULTIPLICATION_CATALOG_MAGIC: &[u8] =
    b"sealed-lattice/preparation-multiplication-catalog";
const PREPARATION_MULTIPLICATION_CATALOG_VERSION: u64 = 1;
const PREPARATION_MULTIPLICATION_CATALOG_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/preparation-multiplication-catalog-compiler-identity/v1";
const PREPARATION_MULTIPLICATION_CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/preparation-multiplication-catalog-identity/v1";
const AND_ROW_COUNT_PER_CONJUNCTION: u64 = 4;

const SEMANTIC_MASK_BITNESS_FAMILY_CODE: u64 = 1;
const CONJUNCTION_MASK_PRODUCT_FAMILY_CODE: u64 = 2;
const LABEL_SHARE_TAG_LIMB_PRODUCT_FAMILY_CODE: u64 = 3;
const INPUT_MASK_SHARE_TAG_PRODUCT_FAMILY_CODE: u64 = 4;
const OUTPUT_MASK_SHARE_TAG_PRODUCT_FAMILY_CODE: u64 = 5;
const ROW_OFFSET_LIMB_PRODUCT_FAMILY_CODE: u64 = 6;
const ROW_BIT_SHARE_TAG_PRODUCT_FAMILY_CODE: u64 = 7;
const PUBLIC_NONEMPTY_OUTPUT_CODE: u64 = 1;
const PRIVATE_RESULT_OUTPUT_CODE: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparationOutputKind {
    PublicNonempty,
    PrivateResult { result_bit_position: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparationMultiplicationCoordinate {
    SemanticMaskBitness {
        wire_index: WireIndex,
    },
    ConjunctionMaskProduct {
        conjunction_ordinal: u64,
        circuit_operation_position: u64,
        output_wire: WireIndex,
        left_wire: WireIndex,
        right_wire: WireIndex,
    },
    LabelShareTagLimbProduct {
        input_wire: WireIndex,
        label_alternative: u8,
        label_component_position: u16,
        holder_position: u16,
        limb_position: u8,
    },
    InputMaskShareTagProduct {
        input_wire: WireIndex,
        holder_position: u16,
    },
    OutputMaskShareTagProduct {
        output_position: u64,
        output_kind: PreparationOutputKind,
        output_wire: WireIndex,
        holder_position: u16,
    },
    RowOffsetLimbProduct {
        conjunction_ordinal: u64,
        input_value_code: u8,
        garbling_contributor_position: u16,
        limb_position: u8,
        conjunction_mask_product_ordinal: u64,
    },
    RowBitShareTagProduct {
        conjunction_ordinal: u64,
        input_value_code: u8,
        holder_position: u16,
        conjunction_mask_product_ordinal: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationMultiplicationOperation {
    pub(crate) global_ordinal: u64,
    pub(crate) multiplicative_layer: u8,
    pub(crate) position_within_layer: u64,
    pub(crate) coordinate: PreparationMultiplicationCoordinate,
}

impl PreparationMultiplicationOperation {
    pub(crate) const fn family(self) -> PreparationMultiplicationFamily {
        match self.coordinate {
            PreparationMultiplicationCoordinate::SemanticMaskBitness { .. } => {
                PreparationMultiplicationFamily::SemanticMaskBitness
            }
            PreparationMultiplicationCoordinate::ConjunctionMaskProduct { .. } => {
                PreparationMultiplicationFamily::ConjunctionMaskProduct
            }
            PreparationMultiplicationCoordinate::LabelShareTagLimbProduct { .. } => {
                PreparationMultiplicationFamily::LabelShareTagLimbProduct
            }
            PreparationMultiplicationCoordinate::InputMaskShareTagProduct { .. } => {
                PreparationMultiplicationFamily::InputMaskShareTagProduct
            }
            PreparationMultiplicationCoordinate::OutputMaskShareTagProduct { .. } => {
                PreparationMultiplicationFamily::OutputMaskShareTagProduct
            }
            PreparationMultiplicationCoordinate::RowOffsetLimbProduct { .. } => {
                PreparationMultiplicationFamily::RowOffsetLimbProduct
            }
            PreparationMultiplicationCoordinate::RowBitShareTagProduct { .. } => {
                PreparationMultiplicationFamily::RowBitShareTagProduct
            }
        }
    }

    fn append_canonical_bytes(self, bytes: &mut Vec<u8>) {
        append_varuint(bytes, family_code(self.family()));
        append_varuint(bytes, self.global_ordinal);
        append_varuint(bytes, u64::from(self.multiplicative_layer));
        append_varuint(bytes, self.position_within_layer);
        match self.coordinate {
            PreparationMultiplicationCoordinate::SemanticMaskBitness { wire_index } => {
                append_varuint(bytes, u64::from(wire_index));
            }
            PreparationMultiplicationCoordinate::ConjunctionMaskProduct {
                conjunction_ordinal,
                circuit_operation_position,
                output_wire,
                left_wire,
                right_wire,
            } => {
                append_varuint(bytes, conjunction_ordinal);
                append_varuint(bytes, circuit_operation_position);
                append_varuint(bytes, u64::from(output_wire));
                append_varuint(bytes, u64::from(left_wire));
                append_varuint(bytes, u64::from(right_wire));
            }
            PreparationMultiplicationCoordinate::LabelShareTagLimbProduct {
                input_wire,
                label_alternative,
                label_component_position,
                holder_position,
                limb_position,
            } => {
                append_varuint(bytes, u64::from(input_wire));
                append_varuint(bytes, u64::from(label_alternative));
                append_varuint(bytes, u64::from(label_component_position));
                append_varuint(bytes, u64::from(holder_position));
                append_varuint(bytes, u64::from(limb_position));
            }
            PreparationMultiplicationCoordinate::InputMaskShareTagProduct {
                input_wire,
                holder_position,
            } => {
                append_varuint(bytes, u64::from(input_wire));
                append_varuint(bytes, u64::from(holder_position));
            }
            PreparationMultiplicationCoordinate::OutputMaskShareTagProduct {
                output_position,
                output_kind,
                output_wire,
                holder_position,
            } => {
                append_varuint(bytes, output_position);
                match output_kind {
                    PreparationOutputKind::PublicNonempty => {
                        append_varuint(bytes, PUBLIC_NONEMPTY_OUTPUT_CODE);
                        append_varuint(bytes, 0);
                    }
                    PreparationOutputKind::PrivateResult {
                        result_bit_position,
                    } => {
                        append_varuint(bytes, PRIVATE_RESULT_OUTPUT_CODE);
                        append_varuint(bytes, result_bit_position);
                    }
                }
                append_varuint(bytes, u64::from(output_wire));
                append_varuint(bytes, u64::from(holder_position));
            }
            PreparationMultiplicationCoordinate::RowOffsetLimbProduct {
                conjunction_ordinal,
                input_value_code,
                garbling_contributor_position,
                limb_position,
                conjunction_mask_product_ordinal,
            } => {
                append_varuint(bytes, conjunction_ordinal);
                append_varuint(bytes, u64::from(input_value_code));
                append_varuint(bytes, u64::from(garbling_contributor_position));
                append_varuint(bytes, u64::from(limb_position));
                append_varuint(bytes, conjunction_mask_product_ordinal);
            }
            PreparationMultiplicationCoordinate::RowBitShareTagProduct {
                conjunction_ordinal,
                input_value_code,
                holder_position,
                conjunction_mask_product_ordinal,
            } => {
                append_varuint(bytes, conjunction_ordinal);
                append_varuint(bytes, u64::from(input_value_code));
                append_varuint(bytes, u64::from(holder_position));
                append_varuint(bytes, conjunction_mask_product_ordinal);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.append_canonical_bytes(&mut bytes);
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConjunctionInventoryEntry {
    circuit_operation_position: u64,
    output_wire: WireIndex,
    left_wire: WireIndex,
    right_wire: WireIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutputInventoryEntry {
    output_kind: PreparationOutputKind,
    output_wire: WireIndex,
}

/// Small authoritative inventory from which the complete operation stream is
/// generated. It retains wires and conjunction dependencies, not one record
/// per multiplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparationMultiplicationInventory {
    context_identity: Hash512,
    circuit_identity: Hash512,
    circuit_compiler_identity: Hash512,
    catalog_compiler_identity: Hash512,
    profile: TallyCircuitProfile,
    graph: PreparationArithmeticGraph,
    input_wire_count: u64,
    semantic_mask_wires: Box<[WireIndex]>,
    conjunctions: Box<[ConjunctionInventoryEntry]>,
    outputs: Box<[OutputInventoryEntry]>,
    operation_count_usize: usize,
}

impl PreparationMultiplicationInventory {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        if !context.is_bound_to_circuit(circuit)? {
            return Err(TallyPreparationError::PreparationContextCircuitMismatch);
        }
        let graph = PreparationArithmeticGraph::derive(circuit)?;
        let input_wire_count = u64::try_from(circuit.geometry().input_bit_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mut semantic_mask_wires = Vec::with_capacity(
            usize::try_from(graph.fresh_semantic_mask_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for input_wire in 0..input_wire_count {
            semantic_mask_wires.push(
                WireIndex::try_from(input_wire)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            );
        }
        let mut conjunctions = Vec::with_capacity(
            usize::try_from(graph.conjunction_gate_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for (operation_position, operation) in circuit.operations().iter().enumerate() {
            if let BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } = operation
            {
                let circuit_operation_position = u64::try_from(operation_position)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?;
                let output_wire =
                    WireIndex::try_from(checked_add(input_wire_count, circuit_operation_position)?)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?;
                semantic_mask_wires.push(output_wire);
                conjunctions.push(ConjunctionInventoryEntry {
                    circuit_operation_position,
                    output_wire,
                    left_wire: *left_wire,
                    right_wire: *right_wire,
                });
            }
        }
        if u64_from_usize(semantic_mask_wires.len())? != graph.fresh_semantic_mask_count
            || u64_from_usize(conjunctions.len())? != graph.conjunction_gate_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let mut outputs = Vec::with_capacity(
            usize::try_from(graph.output_mask_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        outputs.push(OutputInventoryEntry {
            output_kind: PreparationOutputKind::PublicNonempty,
            output_wire: circuit.nonempty_output_wire(),
        });
        for (result_bit_position, output_wire) in circuit
            .ordered_option_position_wires()
            .iter()
            .flatten()
            .copied()
            .enumerate()
        {
            outputs.push(OutputInventoryEntry {
                output_kind: PreparationOutputKind::PrivateResult {
                    result_bit_position: u64::try_from(result_bit_position)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                },
                output_wire,
            });
        }
        if u64_from_usize(outputs.len())? != graph.output_mask_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let operation_count_usize = usize::try_from(graph.total_multiplication_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        Ok(Self {
            context_identity: context.identity(),
            circuit_identity: Hash512::from_bytes(circuit.circuit_identity()?),
            circuit_compiler_identity: Hash512::from_bytes(
                CompiledTallyCircuit::compiler_identity()?,
            ),
            catalog_compiler_identity: preparation_multiplication_catalog_compiler_identity()?,
            profile: circuit.profile(),
            graph,
            input_wire_count,
            semantic_mask_wires: semantic_mask_wires.into_boxed_slice(),
            conjunctions: conjunctions.into_boxed_slice(),
            outputs: outputs.into_boxed_slice(),
            operation_count_usize,
        })
    }

    pub(crate) const fn graph(&self) -> PreparationArithmeticGraph {
        self.graph
    }

    pub(crate) const fn operation_count(&self) -> u64 {
        self.graph.total_multiplication_count
    }

    pub(crate) fn operations(&self) -> PreparationMultiplicationOperationIter<'_> {
        PreparationMultiplicationOperationIter {
            inventory: self,
            next_global_ordinal: 0,
            remaining: self.operation_count_usize,
        }
    }

    pub(crate) fn operation(
        &self,
        global_ordinal: u64,
    ) -> Result<PreparationMultiplicationOperation, TallyPreparationError> {
        if global_ordinal >= self.operation_count() {
            return Err(
                TallyPreparationError::PreparationMultiplicationIndexOutOfRange {
                    operation_index: global_ordinal,
                    operation_count: self.operation_count(),
                },
            );
        }
        let mut relative_ordinal = global_ordinal;
        if relative_ordinal < self.graph.mask_bitness_multiplication_count {
            let wire_index = self.semantic_mask_wire(relative_ordinal)?;
            return Ok(self.operation_record(
                global_ordinal,
                1,
                PreparationMultiplicationCoordinate::SemanticMaskBitness { wire_index },
            ));
        }
        relative_ordinal = checked_subtract(
            relative_ordinal,
            self.graph.mask_bitness_multiplication_count,
        )?;
        if relative_ordinal < self.graph.mask_product_multiplication_count {
            let conjunction = self.conjunction(relative_ordinal)?;
            return Ok(self.operation_record(
                global_ordinal,
                1,
                PreparationMultiplicationCoordinate::ConjunctionMaskProduct {
                    conjunction_ordinal: relative_ordinal,
                    circuit_operation_position: conjunction.circuit_operation_position,
                    output_wire: conjunction.output_wire,
                    left_wire: conjunction.left_wire,
                    right_wire: conjunction.right_wire,
                },
            ));
        }
        relative_ordinal = checked_subtract(
            relative_ordinal,
            self.graph.mask_product_multiplication_count,
        )?;
        if relative_ordinal < self.graph.label_share_tag_multiplication_count {
            return Ok(self.operation_record(
                global_ordinal,
                1,
                self.label_share_tag_coordinate(relative_ordinal)?,
            ));
        }
        relative_ordinal = checked_subtract(
            relative_ordinal,
            self.graph.label_share_tag_multiplication_count,
        )?;
        if relative_ordinal < self.graph.input_mask_share_tag_multiplication_count {
            return Ok(self.operation_record(
                global_ordinal,
                1,
                self.input_mask_share_tag_coordinate(relative_ordinal)?,
            ));
        }
        relative_ordinal = checked_subtract(
            relative_ordinal,
            self.graph.input_mask_share_tag_multiplication_count,
        )?;
        if relative_ordinal < self.graph.output_mask_share_tag_multiplication_count {
            return Ok(self.operation_record(
                global_ordinal,
                1,
                self.output_mask_share_tag_coordinate(relative_ordinal)?,
            ));
        }
        relative_ordinal = checked_subtract(
            relative_ordinal,
            self.graph.output_mask_share_tag_multiplication_count,
        )?;
        if relative_ordinal < self.graph.row_offset_limb_multiplication_count {
            return Ok(self.operation_record(
                global_ordinal,
                2,
                self.row_offset_coordinate(relative_ordinal)?,
            ));
        }
        relative_ordinal = checked_subtract(
            relative_ordinal,
            self.graph.row_offset_limb_multiplication_count,
        )?;
        if relative_ordinal < self.graph.row_bit_share_tag_multiplication_count {
            return Ok(self.operation_record(
                global_ordinal,
                2,
                self.row_bit_share_tag_coordinate(relative_ordinal)?,
            ));
        }
        Err(TallyPreparationError::GeometryMismatch)
    }

    fn operation_record(
        &self,
        global_ordinal: u64,
        multiplicative_layer: u8,
        coordinate: PreparationMultiplicationCoordinate,
    ) -> PreparationMultiplicationOperation {
        let position_within_layer = if multiplicative_layer == 1 {
            global_ordinal
        } else {
            global_ordinal - self.graph.first_layer_multiplication_count
        };
        PreparationMultiplicationOperation {
            global_ordinal,
            multiplicative_layer,
            position_within_layer,
            coordinate,
        }
    }

    fn semantic_mask_wire(&self, ordinal: u64) -> Result<WireIndex, TallyPreparationError> {
        self.semantic_mask_wires
            .get(usize_from_u64(ordinal)?)
            .copied()
            .ok_or(TallyPreparationError::GeometryMismatch)
    }

    fn conjunction(
        &self,
        conjunction_ordinal: u64,
    ) -> Result<ConjunctionInventoryEntry, TallyPreparationError> {
        self.conjunctions
            .get(usize_from_u64(conjunction_ordinal)?)
            .copied()
            .ok_or(TallyPreparationError::GeometryMismatch)
    }

    fn conjunction_mask_product_ordinal(
        &self,
        conjunction_ordinal: u64,
    ) -> Result<u64, TallyPreparationError> {
        checked_add(
            self.graph.mask_bitness_multiplication_count,
            conjunction_ordinal,
        )
    }

    fn label_share_tag_coordinate(
        &self,
        mut relative_ordinal: u64,
    ) -> Result<PreparationMultiplicationCoordinate, TallyPreparationError> {
        let limb_count = u64_from_usize(LABEL_BODY_FIELD_LIMB_COUNT)?;
        let limb_position = u8_from_u64(relative_ordinal % limb_count)?;
        relative_ordinal /= limb_count;
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        relative_ordinal /= participant_count;
        let label_component_position = u16_from_u64(relative_ordinal % participant_count)?;
        relative_ordinal /= participant_count;
        let label_alternative = u8_from_u64(relative_ordinal % 2)?;
        let input_wire = WireIndex::try_from(relative_ordinal / 2)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if u64::from(input_wire) >= self.input_wire_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        Ok(
            PreparationMultiplicationCoordinate::LabelShareTagLimbProduct {
                input_wire,
                label_alternative,
                label_component_position,
                holder_position,
                limb_position,
            },
        )
    }

    fn input_mask_share_tag_coordinate(
        &self,
        relative_ordinal: u64,
    ) -> Result<PreparationMultiplicationCoordinate, TallyPreparationError> {
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        let input_wire = WireIndex::try_from(relative_ordinal / participant_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if u64::from(input_wire) >= self.input_wire_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        Ok(
            PreparationMultiplicationCoordinate::InputMaskShareTagProduct {
                input_wire,
                holder_position,
            },
        )
    }

    fn output_mask_share_tag_coordinate(
        &self,
        relative_ordinal: u64,
    ) -> Result<PreparationMultiplicationCoordinate, TallyPreparationError> {
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        let output_position = relative_ordinal / participant_count;
        let output = self
            .outputs
            .get(usize_from_u64(output_position)?)
            .copied()
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        Ok(
            PreparationMultiplicationCoordinate::OutputMaskShareTagProduct {
                output_position,
                output_kind: output.output_kind,
                output_wire: output.output_wire,
                holder_position,
            },
        )
    }

    fn row_offset_coordinate(
        &self,
        mut relative_ordinal: u64,
    ) -> Result<PreparationMultiplicationCoordinate, TallyPreparationError> {
        let limb_count = u64_from_usize(LABEL_BODY_FIELD_LIMB_COUNT)?;
        let limb_position = u8_from_u64(relative_ordinal % limb_count)?;
        relative_ordinal /= limb_count;
        let participant_count = u64::from(self.profile.participant_count());
        let garbling_contributor_position = u16_from_u64(relative_ordinal % participant_count)?;
        relative_ordinal /= participant_count;
        let input_value_code = u8_from_u64(relative_ordinal % AND_ROW_COUNT_PER_CONJUNCTION)?;
        let conjunction_ordinal = relative_ordinal / AND_ROW_COUNT_PER_CONJUNCTION;
        self.conjunction(conjunction_ordinal)?;
        Ok(PreparationMultiplicationCoordinate::RowOffsetLimbProduct {
            conjunction_ordinal,
            input_value_code,
            garbling_contributor_position,
            limb_position,
            conjunction_mask_product_ordinal: self
                .conjunction_mask_product_ordinal(conjunction_ordinal)?,
        })
    }

    fn row_bit_share_tag_coordinate(
        &self,
        mut relative_ordinal: u64,
    ) -> Result<PreparationMultiplicationCoordinate, TallyPreparationError> {
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        relative_ordinal /= participant_count;
        let input_value_code = u8_from_u64(relative_ordinal % AND_ROW_COUNT_PER_CONJUNCTION)?;
        let conjunction_ordinal = relative_ordinal / AND_ROW_COUNT_PER_CONJUNCTION;
        self.conjunction(conjunction_ordinal)?;
        Ok(PreparationMultiplicationCoordinate::RowBitShareTagProduct {
            conjunction_ordinal,
            input_value_code,
            holder_position,
            conjunction_mask_product_ordinal: self
                .conjunction_mask_product_ordinal(conjunction_ordinal)?,
        })
    }

    fn canonical_header_bytes(&self, operation_stream_byte_length: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, PREPARATION_MULTIPLICATION_CATALOG_MAGIC);
        append_varuint(&mut bytes, PREPARATION_MULTIPLICATION_CATALOG_VERSION);
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_bytes(&mut bytes, self.circuit_identity.as_bytes());
        append_bytes(&mut bytes, self.circuit_compiler_identity.as_bytes());
        append_bytes(&mut bytes, self.catalog_compiler_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.profile.participant_count()));
        append_varuint(&mut bytes, u64::from(self.profile.option_count()));
        append_varuint(&mut bytes, u64::from(self.profile.top_count()));
        append_varuint(&mut bytes, self.input_wire_count);
        append_varuint(&mut bytes, self.graph.fresh_semantic_mask_count);
        append_varuint(&mut bytes, self.graph.conjunction_gate_count);
        append_varuint(&mut bytes, self.graph.and_row_count);
        append_varuint(&mut bytes, self.graph.output_mask_count);
        append_varuint(&mut bytes, self.graph.first_layer_multiplication_count);
        append_varuint(&mut bytes, self.graph.second_layer_multiplication_count);
        append_varuint(&mut bytes, self.graph.total_multiplication_count);
        append_varuint(&mut bytes, operation_stream_byte_length);
        bytes
    }
}

pub(crate) struct PreparationMultiplicationOperationIter<'inventory> {
    inventory: &'inventory PreparationMultiplicationInventory,
    next_global_ordinal: u64,
    remaining: usize,
}

impl Iterator for PreparationMultiplicationOperationIter<'_> {
    type Item = Result<PreparationMultiplicationOperation, TallyPreparationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let operation = self.inventory.operation(self.next_global_ordinal);
        self.next_global_ordinal += 1;
        self.remaining -= 1;
        Some(operation)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for PreparationMultiplicationOperationIter<'_> {}

/// Canonical identity and streamed operation owner for the unactivated
/// preparation arithmetic. The identity directly absorbs every operation in
/// order; compiler and circuit digests are additional bindings rather than a
/// substitute for the emitted list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparationMultiplicationCatalog {
    inventory: PreparationMultiplicationInventory,
    identity: Hash512,
    operation_stream_byte_length: u64,
    artifact_byte_length: u64,
}

impl PreparationMultiplicationCatalog {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        let inventory = PreparationMultiplicationInventory::derive(context, circuit)?;
        let operation_stream_byte_length = operation_stream_byte_length(&inventory)?;
        let header = inventory.canonical_header_bytes(operation_stream_byte_length);
        let header_byte_length = u64_from_usize(header.len())?;
        let artifact_byte_length = checked_add(header_byte_length, operation_stream_byte_length)?;
        let mut hasher =
            StreamingHash512::new(PREPARATION_MULTIPLICATION_CATALOG_IDENTITY_DOMAIN, 1);
        hasher.begin_part(artifact_byte_length);
        hasher.absorb_raw(&header);
        let mut operation_bytes = Vec::with_capacity(64);
        for operation in inventory.operations() {
            operation_bytes.clear();
            operation?.append_canonical_bytes(&mut operation_bytes);
            hasher.absorb_raw(&operation_bytes);
        }
        let identity = Hash512::from_bytes(hasher.finalize());
        Ok(Self {
            inventory,
            identity,
            operation_stream_byte_length,
            artifact_byte_length,
        })
    }

    pub(crate) const fn identity(&self) -> Hash512 {
        self.identity
    }

    pub(crate) const fn context_identity(&self) -> Hash512 {
        self.inventory.context_identity
    }

    pub(crate) const fn operation_stream_byte_length(&self) -> u64 {
        self.operation_stream_byte_length
    }

    pub(crate) const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub(crate) const fn operation_count(&self) -> u64 {
        self.inventory.operation_count()
    }

    pub(crate) fn operations(&self) -> PreparationMultiplicationOperationIter<'_> {
        self.inventory.operations()
    }

    pub(crate) fn operation(
        &self,
        global_ordinal: u64,
    ) -> Result<PreparationMultiplicationOperation, TallyPreparationError> {
        self.inventory.operation(global_ordinal)
    }

    #[cfg(test)]
    pub(crate) fn canonical_header_bytes(&self) -> Vec<u8> {
        self.inventory
            .canonical_header_bytes(self.operation_stream_byte_length)
    }
}

fn operation_stream_byte_length(
    inventory: &PreparationMultiplicationInventory,
) -> Result<u64, TallyPreparationError> {
    let mut total_byte_length = 0_u64;
    let mut operation_bytes = Vec::with_capacity(64);
    for operation in inventory.operations() {
        operation_bytes.clear();
        operation?.append_canonical_bytes(&mut operation_bytes);
        total_byte_length = checked_add(total_byte_length, u64_from_usize(operation_bytes.len())?)?;
    }
    Ok(total_byte_length)
}

pub(crate) fn preparation_multiplication_catalog_compiler_identity()
-> Result<Hash512, TallyPreparationError> {
    preparation_multiplication_catalog_compiler_identity_from_source(
        PREPARATION_MULTIPLICATION_CATALOG_SOURCE,
    )
}

fn preparation_multiplication_catalog_compiler_identity_from_source(
    source: &[u8],
) -> Result<Hash512, TallyPreparationError> {
    if core::str::from_utf8(source).is_err()
        || source.starts_with(&[0xef, 0xbb, 0xbf])
        || source.contains(&b'\r')
        || !source.ends_with(b"\n")
    {
        return Err(TallyPreparationError::NonCanonicalPreparationSourceEncoding);
    }
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        PREPARATION_MULTIPLICATION_CATALOG_COMPILER_IDENTITY_DOMAIN,
        &[
            source,
            &PREPARATION_MULTIPLICATION_CATALOG_VERSION.to_le_bytes(),
        ],
    )))
}

fn family_code(family: PreparationMultiplicationFamily) -> u64 {
    match family {
        PreparationMultiplicationFamily::SemanticMaskBitness => SEMANTIC_MASK_BITNESS_FAMILY_CODE,
        PreparationMultiplicationFamily::ConjunctionMaskProduct => {
            CONJUNCTION_MASK_PRODUCT_FAMILY_CODE
        }
        PreparationMultiplicationFamily::LabelShareTagLimbProduct => {
            LABEL_SHARE_TAG_LIMB_PRODUCT_FAMILY_CODE
        }
        PreparationMultiplicationFamily::InputMaskShareTagProduct => {
            INPUT_MASK_SHARE_TAG_PRODUCT_FAMILY_CODE
        }
        PreparationMultiplicationFamily::OutputMaskShareTagProduct => {
            OUTPUT_MASK_SHARE_TAG_PRODUCT_FAMILY_CODE
        }
        PreparationMultiplicationFamily::RowOffsetLimbProduct => {
            ROW_OFFSET_LIMB_PRODUCT_FAMILY_CODE
        }
        PreparationMultiplicationFamily::RowBitShareTagProduct => {
            ROW_BIT_SHARE_TAG_PRODUCT_FAMILY_CODE
        }
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_subtract(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_sub(right)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn u64_from_usize(value: usize) -> Result<u64, TallyPreparationError> {
    u64::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn usize_from_u64(value: u64) -> Result<usize, TallyPreparationError> {
    usize::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn u16_from_u64(value: u64) -> Result<u16, TallyPreparationError> {
    u16::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn u8_from_u64(value: u64) -> Result<u8, TallyPreparationError> {
    u8::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
}

#[cfg(test)]
pub(crate) fn compiler_identity_from_source_for_test(
    source: &[u8],
) -> Result<Hash512, TallyPreparationError> {
    preparation_multiplication_catalog_compiler_identity_from_source(source)
}
