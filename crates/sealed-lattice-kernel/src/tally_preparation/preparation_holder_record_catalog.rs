use crate::{
    encoding::{append_bytes, append_varuint},
    foundation::Hash512,
    hashing::{StreamingHash512, hash_framed_parts_512},
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile, WireIndex},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    garbled_resource_model::GarbledTallyResourceLowerBound,
    label_encoding::LABEL_BODY_FIELD_LIMB_COUNT,
};

const PREPARATION_HOLDER_RECORD_CATALOG_SOURCE: &[u8] =
    include_bytes!("preparation_holder_record_catalog.rs");
const PREPARATION_HOLDER_RECORD_CATALOG_MAGIC: &[u8] =
    b"sealed-lattice/preparation-holder-record-catalog";
const PREPARATION_HOLDER_RECORD_CATALOG_VERSION: u64 = 1;
const PREPARATION_HOLDER_RECORD_CATALOG_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/preparation-holder-record-catalog-compiler-identity/v1";
const PREPARATION_HOLDER_RECORD_CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/preparation-holder-record-catalog-identity/v1";

const INPUT_MASK_RECORD_CLASS_CODE: u64 = 1;
const INPUT_LABEL_BODY_RECORD_CLASS_CODE: u64 = 2;
const CONJUNCTION_ROW_BIT_RECORD_CLASS_CODE: u64 = 3;
const PUBLIC_OUTPUT_MASK_RECORD_CLASS_CODE: u64 = 4;
const PRIVATE_OUTPUT_MASK_RECORD_CLASS_CODE: u64 = 5;
const PUBLIC_NONEMPTY_OUTPUT_KIND_CODE: u64 = 1;
const PRIVATE_RESULT_OUTPUT_KIND_CODE: u64 = 2;
const AND_ROW_COUNT_PER_CONJUNCTION: u64 = 4;
const LABEL_ALTERNATIVE_COUNT: u64 = 2;
const SCALAR_VALUE_FIELD_ELEMENT_COUNT: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparationHolderRecordClass {
    InputMask,
    InputLabelBody,
    ConjunctionRowBit,
    PublicOutputMask,
    PrivateOutputMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparationHolderOutputKind {
    PublicNonempty,
    PrivateResult { result_bit_position: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparationHolderRecordCoordinate {
    InputMask {
        input_wire: WireIndex,
        holder_position: u16,
    },
    InputLabelBody {
        input_wire: WireIndex,
        label_alternative: u8,
        label_component_position: u16,
        holder_position: u16,
    },
    ConjunctionRowBit {
        conjunction_ordinal: u64,
        circuit_operation_position: u64,
        output_wire: WireIndex,
        left_wire: WireIndex,
        right_wire: WireIndex,
        input_value_code: u8,
        holder_position: u16,
    },
    OutputMask {
        output_position: u64,
        output_kind: PreparationHolderOutputKind,
        output_wire: WireIndex,
        holder_position: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationHolderRecord {
    pub(crate) global_ordinal: u64,
    pub(crate) coordinate: PreparationHolderRecordCoordinate,
}

impl PreparationHolderRecord {
    pub(crate) const fn class(self) -> PreparationHolderRecordClass {
        match self.coordinate {
            PreparationHolderRecordCoordinate::InputMask { .. } => {
                PreparationHolderRecordClass::InputMask
            }
            PreparationHolderRecordCoordinate::InputLabelBody { .. } => {
                PreparationHolderRecordClass::InputLabelBody
            }
            PreparationHolderRecordCoordinate::ConjunctionRowBit { .. } => {
                PreparationHolderRecordClass::ConjunctionRowBit
            }
            PreparationHolderRecordCoordinate::OutputMask {
                output_kind: PreparationHolderOutputKind::PublicNonempty,
                ..
            } => PreparationHolderRecordClass::PublicOutputMask,
            PreparationHolderRecordCoordinate::OutputMask {
                output_kind: PreparationHolderOutputKind::PrivateResult { .. },
                ..
            } => PreparationHolderRecordClass::PrivateOutputMask,
        }
    }

    pub(crate) const fn value_field_element_count(self) -> u64 {
        match self.coordinate {
            PreparationHolderRecordCoordinate::InputLabelBody { .. } => {
                LABEL_BODY_FIELD_LIMB_COUNT as u64
            }
            _ => SCALAR_VALUE_FIELD_ELEMENT_COUNT,
        }
    }

    pub(crate) const fn verification_key_field_element_count(self) -> u64 {
        self.value_field_element_count() + 1
    }

    fn append_canonical_bytes(self, bytes: &mut Vec<u8>) {
        append_varuint(bytes, record_class_code(self.class()));
        append_varuint(bytes, self.global_ordinal);
        append_varuint(bytes, self.value_field_element_count());
        append_varuint(bytes, self.verification_key_field_element_count());
        match self.coordinate {
            PreparationHolderRecordCoordinate::InputMask {
                input_wire,
                holder_position,
            } => {
                append_varuint(bytes, u64::from(input_wire));
                append_varuint(bytes, u64::from(holder_position));
            }
            PreparationHolderRecordCoordinate::InputLabelBody {
                input_wire,
                label_alternative,
                label_component_position,
                holder_position,
            } => {
                append_varuint(bytes, u64::from(input_wire));
                append_varuint(bytes, u64::from(label_alternative));
                append_varuint(bytes, u64::from(label_component_position));
                append_varuint(bytes, u64::from(holder_position));
            }
            PreparationHolderRecordCoordinate::ConjunctionRowBit {
                conjunction_ordinal,
                circuit_operation_position,
                output_wire,
                left_wire,
                right_wire,
                input_value_code,
                holder_position,
            } => {
                append_varuint(bytes, conjunction_ordinal);
                append_varuint(bytes, circuit_operation_position);
                append_varuint(bytes, u64::from(output_wire));
                append_varuint(bytes, u64::from(left_wire));
                append_varuint(bytes, u64::from(right_wire));
                append_varuint(bytes, u64::from(input_value_code));
                append_varuint(bytes, u64::from(holder_position));
            }
            PreparationHolderRecordCoordinate::OutputMask {
                output_position,
                output_kind,
                output_wire,
                holder_position,
            } => {
                append_varuint(bytes, output_position);
                match output_kind {
                    PreparationHolderOutputKind::PublicNonempty => {
                        append_varuint(bytes, PUBLIC_NONEMPTY_OUTPUT_KIND_CODE);
                        append_varuint(bytes, 0);
                    }
                    PreparationHolderOutputKind::PrivateResult {
                        result_bit_position,
                    } => {
                        append_varuint(bytes, PRIVATE_RESULT_OUTPUT_KIND_CODE);
                        append_varuint(bytes, result_bit_position);
                    }
                }
                append_varuint(bytes, u64::from(output_wire));
                append_varuint(bytes, u64::from(holder_position));
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
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
    output_kind: PreparationHolderOutputKind,
    output_wire: WireIndex,
}

/// Small authoritative inventory from which the complete holder-record stream
/// is generated. It retains circuit sources and family geometry rather than
/// materializing one record per holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparationHolderRecordInventory {
    context_identity: Hash512,
    circuit_identity: Hash512,
    circuit_compiler_identity: Hash512,
    catalog_compiler_identity: Hash512,
    profile: TallyCircuitProfile,
    resources: GarbledTallyResourceLowerBound,
    input_wire_count: u64,
    conjunctions: Box<[ConjunctionInventoryEntry]>,
    outputs: Box<[OutputInventoryEntry]>,
    output_count: u64,
    record_class_counts: [u64; 5],
    record_count_usize: usize,
}

impl PreparationHolderRecordInventory {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        if !context.is_bound_to_circuit(circuit)? {
            return Err(TallyPreparationError::PreparationContextCircuitMismatch);
        }
        let resources = GarbledTallyResourceLowerBound::derive(circuit)?;
        let input_wire_count = u64_from_usize(circuit.geometry().input_bit_count)?;
        let participant_count = u64::from(circuit.profile().participant_count());

        let mut conjunctions = Vec::with_capacity(
            usize::try_from(resources.conjunction_gate_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for (operation_position, operation) in circuit.operations().iter().enumerate() {
            if let BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } = operation
            {
                let circuit_operation_position = u64_from_usize(operation_position)?;
                conjunctions.push(ConjunctionInventoryEntry {
                    circuit_operation_position,
                    output_wire: WireIndex::try_from(checked_add(
                        input_wire_count,
                        circuit_operation_position,
                    )?)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
                    left_wire: *left_wire,
                    right_wire: *right_wire,
                });
            }
        }
        if u64_from_usize(conjunctions.len())? != resources.conjunction_gate_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let mut outputs = Vec::with_capacity(
            circuit
                .geometry()
                .public_output_bit_count
                .checked_add(circuit.geometry().private_result_bit_count)
                .ok_or(TallyPreparationError::ArithmeticOverflow)?,
        );
        outputs.push(OutputInventoryEntry {
            output_kind: PreparationHolderOutputKind::PublicNonempty,
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
                output_kind: PreparationHolderOutputKind::PrivateResult {
                    result_bit_position: u64_from_usize(result_bit_position)?,
                },
                output_wire,
            });
        }
        if outputs.len()
            != circuit
                .geometry()
                .public_output_bit_count
                .checked_add(circuit.geometry().private_result_bit_count)
                .ok_or(TallyPreparationError::ArithmeticOverflow)?
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let output_count = u64_from_usize(outputs.len())?;

        let input_mask_record_count = checked_multiply(input_wire_count, participant_count)?;
        let input_label_body_record_count = checked_multiply(
            checked_multiply(
                checked_multiply(input_wire_count, LABEL_ALTERNATIVE_COUNT)?,
                participant_count,
            )?,
            participant_count,
        )?;
        let conjunction_row_bit_record_count = checked_multiply(
            checked_multiply(
                resources.conjunction_gate_count,
                AND_ROW_COUNT_PER_CONJUNCTION,
            )?,
            participant_count,
        )?;
        let public_output_mask_record_count = checked_multiply(
            u64_from_usize(circuit.geometry().public_output_bit_count)?,
            participant_count,
        )?;
        let private_output_mask_record_count = checked_multiply(
            u64_from_usize(circuit.geometry().private_result_bit_count)?,
            participant_count,
        )?;
        let record_class_counts = [
            input_mask_record_count,
            input_label_body_record_count,
            conjunction_row_bit_record_count,
            public_output_mask_record_count,
            private_output_mask_record_count,
        ];
        let record_count = checked_sum(&record_class_counts)?;
        let scalar_record_count = checked_sum(&[
            input_mask_record_count,
            conjunction_row_bit_record_count,
            public_output_mask_record_count,
            private_output_mask_record_count,
        ])?;
        let value_field_element_count = checked_add(
            checked_multiply(
                input_label_body_record_count,
                u64_from_usize(LABEL_BODY_FIELD_LIMB_COUNT)?,
            )?,
            scalar_record_count,
        )?;
        let verification_key_field_element_count =
            checked_add(value_field_element_count, record_count)?;
        if input_label_body_record_count != resources.label_share_record_count
            || scalar_record_count != resources.scalar_share_record_count
            || record_count != resources.total_share_record_count
            || value_field_element_count != resources.total_share_value_field_element_count
            || verification_key_field_element_count
                != resources.dkac_verification_key_field_element_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        Ok(Self {
            context_identity: context.identity(),
            circuit_identity: Hash512::from_bytes(circuit.circuit_identity()?),
            circuit_compiler_identity: Hash512::from_bytes(
                CompiledTallyCircuit::compiler_identity()?,
            ),
            catalog_compiler_identity: preparation_holder_record_catalog_compiler_identity()?,
            profile: circuit.profile(),
            resources,
            input_wire_count,
            conjunctions: conjunctions.into_boxed_slice(),
            outputs: outputs.into_boxed_slice(),
            output_count,
            record_class_counts,
            record_count_usize: usize_from_u64(record_count)?,
        })
    }

    pub(crate) const fn record_count(&self) -> u64 {
        self.resources.total_share_record_count
    }

    pub(crate) const fn value_field_element_count(&self) -> u64 {
        self.resources.total_share_value_field_element_count
    }

    pub(crate) const fn verification_key_field_element_count(&self) -> u64 {
        self.resources.dkac_verification_key_field_element_count
    }

    pub(crate) const fn record_class_counts(&self) -> [u64; 5] {
        self.record_class_counts
    }

    pub(crate) fn records(&self) -> PreparationHolderRecordIter<'_> {
        PreparationHolderRecordIter {
            inventory: self,
            next_global_ordinal: 0,
            remaining: self.record_count_usize,
        }
    }

    pub(crate) fn record(
        &self,
        global_ordinal: u64,
    ) -> Result<PreparationHolderRecord, TallyPreparationError> {
        if global_ordinal >= self.record_count() {
            return Err(
                TallyPreparationError::PreparationHolderRecordIndexOutOfRange {
                    record_index: global_ordinal,
                    record_count: self.record_count(),
                },
            );
        }
        let mut relative_ordinal = global_ordinal;
        if relative_ordinal < self.record_class_counts[0] {
            return Ok(PreparationHolderRecord {
                global_ordinal,
                coordinate: self.input_mask_coordinate(relative_ordinal)?,
            });
        }
        relative_ordinal = checked_subtract(relative_ordinal, self.record_class_counts[0])?;
        if relative_ordinal < self.record_class_counts[1] {
            return Ok(PreparationHolderRecord {
                global_ordinal,
                coordinate: self.input_label_body_coordinate(relative_ordinal)?,
            });
        }
        relative_ordinal = checked_subtract(relative_ordinal, self.record_class_counts[1])?;
        if relative_ordinal < self.record_class_counts[2] {
            return Ok(PreparationHolderRecord {
                global_ordinal,
                coordinate: self.conjunction_row_bit_coordinate(relative_ordinal)?,
            });
        }
        relative_ordinal = checked_subtract(relative_ordinal, self.record_class_counts[2])?;
        if relative_ordinal < self.record_class_counts[3] {
            return Ok(PreparationHolderRecord {
                global_ordinal,
                coordinate: self.output_mask_coordinate(relative_ordinal, 0)?,
            });
        }
        relative_ordinal = checked_subtract(relative_ordinal, self.record_class_counts[3])?;
        if relative_ordinal < self.record_class_counts[4] {
            return Ok(PreparationHolderRecord {
                global_ordinal,
                coordinate: self.output_mask_coordinate(relative_ordinal, 1)?,
            });
        }
        Err(TallyPreparationError::GeometryMismatch)
    }

    fn input_mask_coordinate(
        &self,
        relative_ordinal: u64,
    ) -> Result<PreparationHolderRecordCoordinate, TallyPreparationError> {
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        let input_wire = WireIndex::try_from(relative_ordinal / participant_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if u64::from(input_wire) >= self.input_wire_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        Ok(PreparationHolderRecordCoordinate::InputMask {
            input_wire,
            holder_position,
        })
    }

    fn input_label_body_coordinate(
        &self,
        mut relative_ordinal: u64,
    ) -> Result<PreparationHolderRecordCoordinate, TallyPreparationError> {
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        relative_ordinal /= participant_count;
        let label_component_position = u16_from_u64(relative_ordinal % participant_count)?;
        relative_ordinal /= participant_count;
        let label_alternative = u8_from_u64(relative_ordinal % LABEL_ALTERNATIVE_COUNT)?;
        let input_wire = WireIndex::try_from(relative_ordinal / LABEL_ALTERNATIVE_COUNT)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if u64::from(input_wire) >= self.input_wire_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        Ok(PreparationHolderRecordCoordinate::InputLabelBody {
            input_wire,
            label_alternative,
            label_component_position,
            holder_position,
        })
    }

    fn conjunction_row_bit_coordinate(
        &self,
        mut relative_ordinal: u64,
    ) -> Result<PreparationHolderRecordCoordinate, TallyPreparationError> {
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        relative_ordinal /= participant_count;
        let input_value_code = u8_from_u64(relative_ordinal % AND_ROW_COUNT_PER_CONJUNCTION)?;
        let conjunction_ordinal = relative_ordinal / AND_ROW_COUNT_PER_CONJUNCTION;
        let conjunction = self
            .conjunctions
            .get(usize_from_u64(conjunction_ordinal)?)
            .copied()
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        Ok(PreparationHolderRecordCoordinate::ConjunctionRowBit {
            conjunction_ordinal,
            circuit_operation_position: conjunction.circuit_operation_position,
            output_wire: conjunction.output_wire,
            left_wire: conjunction.left_wire,
            right_wire: conjunction.right_wire,
            input_value_code,
            holder_position,
        })
    }

    fn output_mask_coordinate(
        &self,
        relative_ordinal: u64,
        first_output_position: u64,
    ) -> Result<PreparationHolderRecordCoordinate, TallyPreparationError> {
        let participant_count = u64::from(self.profile.participant_count());
        let holder_position = u16_from_u64(relative_ordinal % participant_count)?;
        let output_position =
            checked_add(first_output_position, relative_ordinal / participant_count)?;
        let output = self
            .outputs
            .get(usize_from_u64(output_position)?)
            .copied()
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        Ok(PreparationHolderRecordCoordinate::OutputMask {
            output_position,
            output_kind: output.output_kind,
            output_wire: output.output_wire,
            holder_position,
        })
    }

    fn canonical_header_bytes(&self, record_stream_byte_length: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, PREPARATION_HOLDER_RECORD_CATALOG_MAGIC);
        append_varuint(&mut bytes, PREPARATION_HOLDER_RECORD_CATALOG_VERSION);
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_bytes(&mut bytes, self.circuit_identity.as_bytes());
        append_bytes(&mut bytes, self.circuit_compiler_identity.as_bytes());
        append_bytes(&mut bytes, self.catalog_compiler_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.profile.participant_count()));
        append_varuint(&mut bytes, u64::from(self.profile.option_count()));
        append_varuint(&mut bytes, u64::from(self.profile.top_count()));
        append_varuint(&mut bytes, self.input_wire_count);
        append_varuint(&mut bytes, self.resources.conjunction_gate_count);
        append_varuint(&mut bytes, self.output_count);
        for record_class_count in self.record_class_counts {
            append_varuint(&mut bytes, record_class_count);
        }
        append_varuint(&mut bytes, self.record_count());
        append_varuint(&mut bytes, self.value_field_element_count());
        append_varuint(&mut bytes, self.verification_key_field_element_count());
        append_varuint(&mut bytes, record_stream_byte_length);
        bytes
    }
}

pub(crate) struct PreparationHolderRecordIter<'inventory> {
    inventory: &'inventory PreparationHolderRecordInventory,
    next_global_ordinal: u64,
    remaining: usize,
}

impl Iterator for PreparationHolderRecordIter<'_> {
    type Item = Result<PreparationHolderRecord, TallyPreparationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let record = self.inventory.record(self.next_global_ordinal);
        self.next_global_ordinal += 1;
        self.remaining -= 1;
        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for PreparationHolderRecordIter<'_> {}

/// Canonical identity and streamed coordinate owner for every authenticated
/// holder record. The identity directly absorbs the complete record stream;
/// circuit and compiler identities are additional bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparationHolderRecordCatalog {
    inventory: PreparationHolderRecordInventory,
    identity: Hash512,
    record_stream_byte_length: u64,
    artifact_byte_length: u64,
}

impl PreparationHolderRecordCatalog {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        let inventory = PreparationHolderRecordInventory::derive(context, circuit)?;
        let record_stream_byte_length = record_stream_byte_length(&inventory)?;
        let header = inventory.canonical_header_bytes(record_stream_byte_length);
        let artifact_byte_length =
            checked_add(u64_from_usize(header.len())?, record_stream_byte_length)?;
        let mut hasher =
            StreamingHash512::new(PREPARATION_HOLDER_RECORD_CATALOG_IDENTITY_DOMAIN, 1);
        hasher.begin_part(artifact_byte_length);
        hasher.absorb_raw(&header);
        let mut record_bytes = Vec::with_capacity(32);
        for record in inventory.records() {
            record_bytes.clear();
            record?.append_canonical_bytes(&mut record_bytes);
            hasher.absorb_raw(&record_bytes);
        }
        let identity = Hash512::from_bytes(hasher.finalize());
        Ok(Self {
            inventory,
            identity,
            record_stream_byte_length,
            artifact_byte_length,
        })
    }

    pub(crate) const fn identity(&self) -> Hash512 {
        self.identity
    }

    pub(crate) const fn record_count(&self) -> u64 {
        self.inventory.record_count()
    }

    pub(crate) const fn value_field_element_count(&self) -> u64 {
        self.inventory.value_field_element_count()
    }

    pub(crate) const fn verification_key_field_element_count(&self) -> u64 {
        self.inventory.verification_key_field_element_count()
    }

    pub(crate) const fn record_stream_byte_length(&self) -> u64 {
        self.record_stream_byte_length
    }

    pub(crate) const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub(crate) fn records(&self) -> PreparationHolderRecordIter<'_> {
        self.inventory.records()
    }

    pub(crate) fn record(
        &self,
        global_ordinal: u64,
    ) -> Result<PreparationHolderRecord, TallyPreparationError> {
        self.inventory.record(global_ordinal)
    }

    #[cfg(test)]
    pub(crate) fn canonical_header_bytes(&self) -> Vec<u8> {
        self.inventory
            .canonical_header_bytes(self.record_stream_byte_length)
    }
}

fn record_stream_byte_length(
    inventory: &PreparationHolderRecordInventory,
) -> Result<u64, TallyPreparationError> {
    let mut total_byte_length = 0_u64;
    let mut record_bytes = Vec::with_capacity(32);
    for record in inventory.records() {
        record_bytes.clear();
        record?.append_canonical_bytes(&mut record_bytes);
        total_byte_length = checked_add(total_byte_length, u64_from_usize(record_bytes.len())?)?;
    }
    Ok(total_byte_length)
}

pub(crate) fn preparation_holder_record_catalog_compiler_identity()
-> Result<Hash512, TallyPreparationError> {
    preparation_holder_record_catalog_compiler_identity_from_source(
        PREPARATION_HOLDER_RECORD_CATALOG_SOURCE,
    )
}

fn preparation_holder_record_catalog_compiler_identity_from_source(
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
        PREPARATION_HOLDER_RECORD_CATALOG_COMPILER_IDENTITY_DOMAIN,
        &[
            source,
            &PREPARATION_HOLDER_RECORD_CATALOG_VERSION.to_le_bytes(),
        ],
    )))
}

fn record_class_code(record_class: PreparationHolderRecordClass) -> u64 {
    match record_class {
        PreparationHolderRecordClass::InputMask => INPUT_MASK_RECORD_CLASS_CODE,
        PreparationHolderRecordClass::InputLabelBody => INPUT_LABEL_BODY_RECORD_CLASS_CODE,
        PreparationHolderRecordClass::ConjunctionRowBit => CONJUNCTION_ROW_BIT_RECORD_CLASS_CODE,
        PreparationHolderRecordClass::PublicOutputMask => PUBLIC_OUTPUT_MASK_RECORD_CLASS_CODE,
        PreparationHolderRecordClass::PrivateOutputMask => PRIVATE_OUTPUT_MASK_RECORD_CLASS_CODE,
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

fn checked_subtract(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_sub(right)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn checked_sum(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
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
    preparation_holder_record_catalog_compiler_identity_from_source(source)
}
