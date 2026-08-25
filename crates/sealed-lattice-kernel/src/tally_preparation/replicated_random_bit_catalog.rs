use crate::{
    encoding::{append_bytes, append_varuint},
    foundation::Hash512,
    hashing::hash_framed_parts_512,
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, WireIndex},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    preparation_arithmetic_graph::PreparationArithmeticGraph,
};

pub(super) const REPLICATED_RANDOM_BIT_CATALOG_MAGIC: &[u8] =
    b"sealed-lattice/replicated-random-bit-catalog";
pub(super) const REPLICATED_RANDOM_BIT_CATALOG_VERSION: u64 = 1;
pub(super) const REPLICATED_RANDOM_BIT_CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/replicated-random-bit-catalog-identity/v1";

const BITS_PER_BYTE: u64 = 8;
const AND_ROW_COUNT_PER_CONJUNCTION: u64 = 4;
const SEMANTIC_MASK_FAMILY_CODE: u64 = 1;
const ADDITIVE_CORRELATION_FREE_POINT_FAMILY_CODE: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicatedRandomBitCoordinate {
    SemanticMask {
        wire_index: WireIndex,
    },
    AdditiveCorrelationFreePoint {
        conjunction_ordinal: u64,
        input_value_code: u8,
        output_component_position: u16,
        free_garbling_contributor_position: u16,
    },
}

/// Canonical logical-bit inventory for the replicated random-bit stream.
///
/// Semantic masks are ordered first by their authoritative wire indices:
/// every input wire followed by conjunction-output wires in operation order.
/// Correlation point bits follow in conjunction, truth-table row, output
/// component, and free-garbling-contributor order. The catalog identity hashes
/// that full wire inventory and the exact ordering geometry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicatedRandomBitCatalog {
    context_identity: Hash512,
    identity: Hash512,
    participant_count: u16,
    input_wire_count: u64,
    semantic_mask_bit_count: u64,
    semantic_mask_wire_indices: Box<[WireIndex]>,
    conjunction_gate_count: u64,
    free_contributor_count: u64,
    additive_correlation_free_point_bit_count: u64,
    total_bit_count: u64,
    output_byte_length_per_key: u64,
    unused_high_bit_count: u8,
}

impl ReplicatedRandomBitCatalog {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        if !context.is_bound_to_circuit(circuit)? {
            return Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch);
        }
        let graph = PreparationArithmeticGraph::derive(circuit)?;
        let input_wire_count = u64::try_from(circuit.geometry().input_bit_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let conjunction_gate_count = u64::try_from(circuit.geometry().conjunction_gate_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mut semantic_mask_wire_indices = Vec::with_capacity(
            usize::try_from(graph.fresh_semantic_mask_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for input_wire_index in 0..input_wire_count {
            semantic_mask_wire_indices.push(
                WireIndex::try_from(input_wire_index)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            );
        }
        for (operation_position, operation) in circuit.operations().iter().enumerate() {
            if matches!(operation, BooleanOperation::Conjunction { .. }) {
                let output_wire_index = circuit
                    .geometry()
                    .input_bit_count
                    .checked_add(operation_position)
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?;
                semantic_mask_wire_indices.push(
                    WireIndex::try_from(output_wire_index)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                );
            }
        }
        if u64::try_from(semantic_mask_wire_indices.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?
            != graph.fresh_semantic_mask_count
            || conjunction_gate_count != graph.conjunction_gate_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let total_bit_count = checked_add(
            graph.fresh_semantic_mask_count,
            graph.additive_correlation_free_point_bit_count,
        )?;
        if total_bit_count == 0 {
            return Err(TallyPreparationError::ReplicatedRandomBitCountZero);
        }
        let output_byte_length_per_key = checked_ceiling_divide(total_bit_count, BITS_PER_BYTE)?;
        let used_final_byte_bit_count = total_bit_count % BITS_PER_BYTE;
        let unused_high_bit_count = if used_final_byte_bit_count == 0 {
            0
        } else {
            u8::try_from(BITS_PER_BYTE - used_final_byte_bit_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?
        };
        let free_contributor_count = u64::from(circuit.profile().participant_count())
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let mut catalog = Self {
            context_identity: context.identity(),
            identity: Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
            participant_count: circuit.profile().participant_count(),
            input_wire_count,
            semantic_mask_bit_count: graph.fresh_semantic_mask_count,
            semantic_mask_wire_indices: semantic_mask_wire_indices.into_boxed_slice(),
            conjunction_gate_count,
            free_contributor_count,
            additive_correlation_free_point_bit_count: graph
                .additive_correlation_free_point_bit_count,
            total_bit_count,
            output_byte_length_per_key,
            unused_high_bit_count,
        };
        catalog.identity = Hash512::from_bytes(hash_framed_parts_512(
            REPLICATED_RANDOM_BIT_CATALOG_IDENTITY_DOMAIN,
            &[&catalog.canonical_bytes()],
        ));
        Ok(catalog)
    }

    pub(crate) const fn identity(&self) -> Hash512 {
        self.identity
    }

    pub(crate) const fn context_identity(&self) -> Hash512 {
        self.context_identity
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn semantic_mask_bit_count(&self) -> u64 {
        self.semantic_mask_bit_count
    }

    pub(crate) const fn additive_correlation_free_point_bit_count(&self) -> u64 {
        self.additive_correlation_free_point_bit_count
    }

    pub(crate) const fn total_bit_count(&self) -> u64 {
        self.total_bit_count
    }

    pub(crate) const fn output_byte_length_per_key(&self) -> u64 {
        self.output_byte_length_per_key
    }

    pub(crate) const fn unused_high_bit_count(&self) -> u8 {
        self.unused_high_bit_count
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, REPLICATED_RANDOM_BIT_CATALOG_MAGIC);
        append_varuint(&mut bytes, REPLICATED_RANDOM_BIT_CATALOG_VERSION);
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, self.input_wire_count);
        append_varuint(&mut bytes, SEMANTIC_MASK_FAMILY_CODE);
        append_varuint(&mut bytes, self.semantic_mask_bit_count());
        for wire_index in &self.semantic_mask_wire_indices {
            append_varuint(&mut bytes, u64::from(*wire_index));
        }
        append_varuint(&mut bytes, ADDITIVE_CORRELATION_FREE_POINT_FAMILY_CODE);
        append_varuint(&mut bytes, self.conjunction_gate_count);
        append_varuint(&mut bytes, AND_ROW_COUNT_PER_CONJUNCTION);
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, self.free_contributor_count);
        append_varuint(&mut bytes, self.additive_correlation_free_point_bit_count);
        append_varuint(&mut bytes, self.total_bit_count);
        bytes
    }

    pub(crate) fn coordinate(
        &self,
        bit_index: u64,
    ) -> Result<ReplicatedRandomBitCoordinate, TallyPreparationError> {
        if bit_index >= self.total_bit_count {
            return Err(TallyPreparationError::ReplicatedRandomBitIndexOutOfRange {
                bit_index,
                total_bit_count: self.total_bit_count,
            });
        }
        let semantic_mask_bit_count = self.semantic_mask_bit_count();
        if bit_index < semantic_mask_bit_count {
            let wire_index = *self
                .semantic_mask_wire_indices
                .get(
                    usize::try_from(bit_index)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                )
                .ok_or(TallyPreparationError::GeometryMismatch)?;
            return Ok(ReplicatedRandomBitCoordinate::SemanticMask { wire_index });
        }

        let relative_index = bit_index
            .checked_sub(semantic_mask_bit_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let participant_count = u64::from(self.participant_count);
        let free_contributor_count = participant_count
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let components_per_row = checked_multiply(participant_count, free_contributor_count)?;
        let components_per_conjunction =
            checked_multiply(AND_ROW_COUNT_PER_CONJUNCTION, components_per_row)?;
        let conjunction_ordinal = relative_index / components_per_conjunction;
        let within_conjunction = relative_index % components_per_conjunction;
        let input_value_code = u8::try_from(within_conjunction / components_per_row)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let within_row = within_conjunction % components_per_row;
        let output_component_position = u16::try_from(within_row / free_contributor_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let free_contributor_rank = u16::try_from(within_row % free_contributor_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let free_garbling_contributor_position =
            if free_contributor_rank >= output_component_position {
                free_contributor_rank
                    .checked_add(1)
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?
            } else {
                free_contributor_rank
            };
        Ok(
            ReplicatedRandomBitCoordinate::AdditiveCorrelationFreePoint {
                conjunction_ordinal,
                input_value_code,
                output_component_position,
                free_garbling_contributor_position,
            },
        )
    }

    pub(crate) fn bit_index(
        &self,
        coordinate: ReplicatedRandomBitCoordinate,
    ) -> Result<u64, TallyPreparationError> {
        match coordinate {
            ReplicatedRandomBitCoordinate::SemanticMask { wire_index } => self
                .semantic_mask_wire_indices
                .binary_search(&wire_index)
                .map_err(|_| TallyPreparationError::ReplicatedRandomBitCoordinateMismatch)
                .and_then(|position| {
                    u64::try_from(position).map_err(|_| TallyPreparationError::IntegerConversion)
                }),
            ReplicatedRandomBitCoordinate::AdditiveCorrelationFreePoint {
                conjunction_ordinal,
                input_value_code,
                output_component_position,
                free_garbling_contributor_position,
            } => {
                if conjunction_ordinal >= self.conjunction_gate_count
                    || u64::from(input_value_code) >= AND_ROW_COUNT_PER_CONJUNCTION
                    || output_component_position >= self.participant_count
                    || free_garbling_contributor_position >= self.participant_count
                    || output_component_position == free_garbling_contributor_position
                {
                    return Err(TallyPreparationError::ReplicatedRandomBitCoordinateMismatch);
                }
                let participant_count = u64::from(self.participant_count);
                let free_contributor_count = participant_count
                    .checked_sub(1)
                    .ok_or(TallyPreparationError::GeometryMismatch)?;
                let free_contributor_rank =
                    if free_garbling_contributor_position < output_component_position {
                        u64::from(free_garbling_contributor_position)
                    } else {
                        u64::from(
                            free_garbling_contributor_position
                                .checked_sub(1)
                                .ok_or(TallyPreparationError::GeometryMismatch)?,
                        )
                    };
                let components_per_row =
                    checked_multiply(participant_count, free_contributor_count)?;
                let components_per_conjunction =
                    checked_multiply(AND_ROW_COUNT_PER_CONJUNCTION, components_per_row)?;
                let within_row = checked_add(
                    checked_multiply(u64::from(output_component_position), free_contributor_count)?,
                    free_contributor_rank,
                )?;
                let within_conjunction = checked_add(
                    checked_multiply(u64::from(input_value_code), components_per_row)?,
                    within_row,
                )?;
                checked_add(
                    self.semantic_mask_bit_count(),
                    checked_add(
                        checked_multiply(conjunction_ordinal, components_per_conjunction)?,
                        within_conjunction,
                    )?,
                )
            }
        }
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    (dividend / divisor)
        .checked_add(u64::from(!dividend.is_multiple_of(divisor)))
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
