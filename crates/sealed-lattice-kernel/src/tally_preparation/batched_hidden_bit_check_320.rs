use core::fmt;

use crate::{
    encoding::{append_bytes, append_varuint},
    foundation::{Hash512, derive_foundation_roster_parameters},
    hashing::{StreamingHash512, hash_framed_parts_512},
    tally_circuit::{
        BooleanOperation, CompiledTallyCircuit, OutputRekeyedTallyCircuit, TallyCircuitError,
        TallyCircuitProfile, WireIndex,
    },
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_320::{
        PerBitPseudorandomZeroSharingWorkload320, PseudorandomZeroSharingResourceInput,
        PseudorandomZeroSharingResourceModel, canonical_evaluation_point_320,
    },
    pseudorandom_zero_sharing_participant_cursor_320::{
        PseudorandomZeroSharingCursorError320, PseudorandomZeroSharingCursorResourceModel320,
    },
};

const BATCHED_HIDDEN_BIT_CHECK_SOURCE: &[u8] = include_bytes!("batched_hidden_bit_check_320.rs");
const OUTPUT_REKEYED_TALLY_CIRCUIT_SOURCE: &[u8] =
    include_bytes!("../tally_circuit/output_rekeyed.rs");
const BATCHED_HIDDEN_BIT_CHECK_CATALOG_MAGIC: &[u8] =
    b"sealed-lattice/batched-hidden-bit-check-catalog";
const BATCHED_HIDDEN_BIT_CHECK_CATALOG_VERSION: u64 = 1;
pub(crate) const BATCHED_HIDDEN_BIT_CHECK_CATALOG_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/batched-hidden-bit-check-catalog-compiler-identity/v1";
pub(crate) const BATCHED_HIDDEN_BIT_CHECK_CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/batched-hidden-bit-check-catalog-identity/v1";
pub(crate) const BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE: u64 = 4_096;

const CORE_WIRE_SOURCE_CODE: u64 = 1;
const ACCEPTED_AUTHORSHIP_OUTPUT_SOURCE_CODE: u64 = 2;
const PUBLIC_NONEMPTY_OUTPUT_SOURCE_CODE: u64 = 3;
const PRIVATE_RESULT_OUTPUT_SOURCE_CODE: u64 = 4;
const BATCH_ZERO_SHARING_CODE: u64 = 1;
const CONJUNCTION_ZERO_SHARING_CODE: u64 = 2;
const FIELD_BIT_LENGTH: u64 = 320;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BatchedHiddenBitCheckError320 {
    Preparation(TallyPreparationError),
    Circuit(TallyCircuitError),
    Cursor(PseudorandomZeroSharingCursorError320),
    ContextCircuitMismatch,
    OutputRekeyedCircuitMismatch,
    HiddenBitOrdinalOutOfRange {
        hidden_bit_ordinal: u64,
        hidden_bit_count: u64,
    },
    BatchOrdinalOutOfRange {
        batch_ordinal: u64,
        batch_count: u64,
    },
    ZeroSharingOrdinalOutOfRange {
        zero_sharing_ordinal: u64,
        zero_sharing_count: u64,
    },
    HiddenBitEvaluationCountMismatch {
        expected: usize,
        actual: usize,
    },
    CorruptPositionCountMismatch {
        expected: usize,
        actual: usize,
    },
    CorruptPositionsNotCanonical,
    PolynomialDegreeOutOfRange {
        maximum_degree: usize,
        actual_degree: usize,
    },
    PolynomialVisibleAtFixedPoint {
        roster_position: Option<u16>,
    },
    AffineFiberDecompositionFailure,
    NonCanonicalCompilerSource,
    ArithmeticOverflow,
    IntegerConversion,
    GeometryMismatch,
}

impl fmt::Display for BatchedHiddenBitCheckError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(error) => error.fmt(formatter),
            Self::Circuit(error) => error.fmt(formatter),
            Self::Cursor(error) => error.fmt(formatter),
            Self::ContextCircuitMismatch => {
                formatter.write_str("hidden-bit catalog context does not match the tally circuit")
            }
            Self::OutputRekeyedCircuitMismatch => formatter
                .write_str("hidden-bit catalog does not match the output-rekeyed tally circuit"),
            Self::HiddenBitOrdinalOutOfRange {
                hidden_bit_ordinal,
                hidden_bit_count,
            } => write!(
                formatter,
                "hidden-bit ordinal {hidden_bit_ordinal} is outside {hidden_bit_count} entries"
            ),
            Self::BatchOrdinalOutOfRange {
                batch_ordinal,
                batch_count,
            } => write!(
                formatter,
                "hidden-bit batch ordinal {batch_ordinal} is outside {batch_count} batches"
            ),
            Self::ZeroSharingOrdinalOutOfRange {
                zero_sharing_ordinal,
                zero_sharing_count,
            } => write!(
                formatter,
                "zero-sharing ordinal {zero_sharing_ordinal} is outside {zero_sharing_count} entries"
            ),
            Self::HiddenBitEvaluationCountMismatch { expected, actual } => write!(
                formatter,
                "hidden-bit batch has {actual} evaluations; expected {expected}"
            ),
            Self::CorruptPositionCountMismatch { expected, actual } => write!(
                formatter,
                "affine-fiber basis has {actual} corrupt positions; expected {expected}"
            ),
            Self::CorruptPositionsNotCanonical => {
                formatter.write_str("affine-fiber corrupt positions are not canonical")
            }
            Self::PolynomialDegreeOutOfRange {
                maximum_degree,
                actual_degree,
            } => write!(
                formatter,
                "affine-fiber polynomial degree {actual_degree} exceeds {maximum_degree}"
            ),
            Self::PolynomialVisibleAtFixedPoint { roster_position } => match roster_position {
                Some(roster_position) => write!(
                    formatter,
                    "affine-fiber polynomial is visible at corrupt roster position {roster_position}"
                ),
                None => formatter.write_str("affine-fiber polynomial has a nonzero constant"),
            },
            Self::AffineFiberDecompositionFailure => {
                formatter.write_str("affine-fiber polynomial is outside the hidden kernel")
            }
            Self::NonCanonicalCompilerSource => {
                formatter.write_str("hidden-bit compiler source is not canonical LF UTF-8")
            }
            Self::ArithmeticOverflow => formatter.write_str("hidden-bit arithmetic overflow"),
            Self::IntegerConversion => formatter.write_str("hidden-bit integer conversion failed"),
            Self::GeometryMismatch => formatter.write_str("hidden-bit geometry does not match"),
        }
    }
}

impl std::error::Error for BatchedHiddenBitCheckError320 {}

impl From<TallyPreparationError> for BatchedHiddenBitCheckError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<TallyCircuitError> for BatchedHiddenBitCheckError320 {
    fn from(error: TallyCircuitError) -> Self {
        Self::Circuit(error)
    }
}

impl From<PseudorandomZeroSharingCursorError320> for BatchedHiddenBitCheckError320 {
    fn from(error: PseudorandomZeroSharingCursorError320) -> Self {
        Self::Cursor(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchedHiddenBitSourceCoordinate320 {
    CoreWire {
        wire_index: WireIndex,
    },
    AcceptedAuthorshipOutput {
        participant_position: u16,
        source_wire: WireIndex,
        output_wire: WireIndex,
    },
    PublicNonemptyOutput {
        source_wire: WireIndex,
        output_wire: WireIndex,
    },
    PrivateResultOutput {
        result_bit_position: u64,
        source_wire: WireIndex,
        output_wire: WireIndex,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchedHiddenBitSource320 {
    pub(crate) hidden_bit_ordinal: u64,
    pub(crate) coordinate: BatchedHiddenBitSourceCoordinate320,
}

impl BatchedHiddenBitSource320 {
    fn append_canonical_bytes(self, bytes: &mut Vec<u8>) {
        match self.coordinate {
            BatchedHiddenBitSourceCoordinate320::CoreWire { wire_index } => {
                append_varuint(bytes, CORE_WIRE_SOURCE_CODE);
                append_varuint(bytes, self.hidden_bit_ordinal);
                append_varuint(bytes, u64::from(wire_index));
            }
            BatchedHiddenBitSourceCoordinate320::AcceptedAuthorshipOutput {
                participant_position,
                source_wire,
                output_wire,
            } => {
                append_varuint(bytes, ACCEPTED_AUTHORSHIP_OUTPUT_SOURCE_CODE);
                append_varuint(bytes, self.hidden_bit_ordinal);
                append_varuint(bytes, u64::from(participant_position));
                append_varuint(bytes, u64::from(source_wire));
                append_varuint(bytes, u64::from(output_wire));
            }
            BatchedHiddenBitSourceCoordinate320::PublicNonemptyOutput {
                source_wire,
                output_wire,
            } => {
                append_varuint(bytes, PUBLIC_NONEMPTY_OUTPUT_SOURCE_CODE);
                append_varuint(bytes, self.hidden_bit_ordinal);
                append_varuint(bytes, u64::from(source_wire));
                append_varuint(bytes, u64::from(output_wire));
            }
            BatchedHiddenBitSourceCoordinate320::PrivateResultOutput {
                result_bit_position,
                source_wire,
                output_wire,
            } => {
                append_varuint(bytes, PRIVATE_RESULT_OUTPUT_SOURCE_CODE);
                append_varuint(bytes, self.hidden_bit_ordinal);
                append_varuint(bytes, result_bit_position);
                append_varuint(bytes, u64::from(source_wire));
                append_varuint(bytes, u64::from(output_wire));
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        self.append_canonical_bytes(&mut bytes);
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchedHiddenBitBatch320 {
    pub(crate) batch_ordinal: u64,
    pub(crate) first_hidden_bit_ordinal: u64,
    pub(crate) hidden_bit_count: u64,
    pub(crate) zero_sharing_ordinal: u64,
}

impl BatchedHiddenBitBatch320 {
    fn append_canonical_bytes(self, bytes: &mut Vec<u8>) {
        append_varuint(bytes, self.batch_ordinal);
        append_varuint(bytes, self.first_hidden_bit_ordinal);
        append_varuint(bytes, self.hidden_bit_count);
        append_varuint(bytes, self.zero_sharing_ordinal);
    }

    #[cfg(test)]
    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        self.append_canonical_bytes(&mut bytes);
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchedHiddenBitZeroSharingCoordinate320 {
    BatchMask {
        batch_ordinal: u64,
        first_hidden_bit_ordinal: u64,
        hidden_bit_count: u64,
    },
    ConjunctionProductMask {
        conjunction_ordinal: u64,
        circuit_operation_position: u64,
        output_wire: WireIndex,
        left_wire: WireIndex,
        right_wire: WireIndex,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchedHiddenBitZeroSharing320 {
    pub(crate) zero_sharing_ordinal: u64,
    pub(crate) coordinate: BatchedHiddenBitZeroSharingCoordinate320,
}

impl BatchedHiddenBitZeroSharing320 {
    fn append_canonical_bytes(self, bytes: &mut Vec<u8>) {
        match self.coordinate {
            BatchedHiddenBitZeroSharingCoordinate320::BatchMask {
                batch_ordinal,
                first_hidden_bit_ordinal,
                hidden_bit_count,
            } => {
                append_varuint(bytes, BATCH_ZERO_SHARING_CODE);
                append_varuint(bytes, self.zero_sharing_ordinal);
                append_varuint(bytes, batch_ordinal);
                append_varuint(bytes, first_hidden_bit_ordinal);
                append_varuint(bytes, hidden_bit_count);
            }
            BatchedHiddenBitZeroSharingCoordinate320::ConjunctionProductMask {
                conjunction_ordinal,
                circuit_operation_position,
                output_wire,
                left_wire,
                right_wire,
            } => {
                append_varuint(bytes, CONJUNCTION_ZERO_SHARING_CODE);
                append_varuint(bytes, self.zero_sharing_ordinal);
                append_varuint(bytes, conjunction_ordinal);
                append_varuint(bytes, circuit_operation_position);
                append_varuint(bytes, u64::from(output_wire));
                append_varuint(bytes, u64::from(left_wire));
                append_varuint(bytes, u64::from(right_wire));
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
struct ConjunctionSource320 {
    conjunction_ordinal: u64,
    circuit_operation_position: u64,
    output_wire: WireIndex,
    left_wire: WireIndex,
    right_wire: WireIndex,
}

/// Canonical candidate catalog for every hidden bit, batch, and zero-sharing
/// coordinate consumed by the bounded characteristic-two check.
///
/// The catalog is compiler output only. It authenticates no root, supplies no
/// challenge entropy, and grants no preparation or continuation capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchedHiddenBitCheckCatalog320 {
    parameter_identity: Hash512,
    context_identity: Hash512,
    circuit_identity: Hash512,
    circuit_compiler_identity: Hash512,
    catalog_compiler_identity: Hash512,
    profile: TallyCircuitProfile,
    hidden_bits: Box<[BatchedHiddenBitSource320]>,
    batches: Box<[BatchedHiddenBitBatch320]>,
    conjunctions: Box<[ConjunctionSource320]>,
    zero_sharing_count: u64,
    soundness_union_numerator: u64,
    hidden_bit_stream_byte_length: u64,
    batch_stream_byte_length: u64,
    zero_sharing_stream_byte_length: u64,
    artifact_byte_length: u64,
    identity: Hash512,
}

impl BatchedHiddenBitCheckCatalog320 {
    pub(crate) fn derive(
        parameter_identity: Hash512,
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, BatchedHiddenBitCheckError320> {
        if !context.is_bound_to_circuit(circuit)? {
            return Err(BatchedHiddenBitCheckError320::ContextCircuitMismatch);
        }
        let output_rekeyed = OutputRekeyedTallyCircuit::compile(circuit.profile())?;
        if output_rekeyed.core_circuit().circuit_identity()? != circuit.circuit_identity()? {
            return Err(BatchedHiddenBitCheckError320::OutputRekeyedCircuitMismatch);
        }

        let hidden_bits = derive_hidden_bits(circuit, &output_rekeyed)?;
        let per_bit_workload = PerBitPseudorandomZeroSharingWorkload320::derive(circuit)?;
        if u64_from_usize(hidden_bits.len())? != per_bit_workload.hidden_value_count {
            return Err(BatchedHiddenBitCheckError320::GeometryMismatch);
        }
        let batches = derive_batches(u64_from_usize(hidden_bits.len())?)?;
        let conjunctions = derive_conjunctions(circuit)?;
        if u64_from_usize(conjunctions.len())? != per_bit_workload.conjunction_product_count {
            return Err(BatchedHiddenBitCheckError320::GeometryMismatch);
        }
        let zero_sharing_count = checked_add(
            u64_from_usize(batches.len())?,
            u64_from_usize(conjunctions.len())?,
        )?;
        let soundness_union_numerator = batches.iter().try_fold(0_u64, |sum, batch| {
            checked_add(
                sum,
                batch
                    .hidden_bit_count
                    .checked_sub(1)
                    .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?,
            )
        })?;
        let catalog_compiler_identity = batched_hidden_bit_check_compiler_identity()?;
        let mut catalog = Self {
            parameter_identity,
            context_identity: context.identity(),
            circuit_identity: Hash512::from_bytes(circuit.circuit_identity()?),
            circuit_compiler_identity: Hash512::from_bytes(
                CompiledTallyCircuit::compiler_identity()?,
            ),
            catalog_compiler_identity,
            profile: circuit.profile(),
            hidden_bits: hidden_bits.into_boxed_slice(),
            batches: batches.into_boxed_slice(),
            conjunctions: conjunctions.into_boxed_slice(),
            zero_sharing_count,
            soundness_union_numerator,
            hidden_bit_stream_byte_length: 0,
            batch_stream_byte_length: 0,
            zero_sharing_stream_byte_length: 0,
            artifact_byte_length: 0,
            identity: Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
        };
        catalog.hidden_bit_stream_byte_length = catalog.hidden_bit_stream_byte_length()?;
        catalog.batch_stream_byte_length = catalog.batch_stream_byte_length()?;
        catalog.zero_sharing_stream_byte_length = catalog.zero_sharing_stream_byte_length()?;
        let header = catalog.canonical_header_bytes();
        catalog.artifact_byte_length = checked_sum(&[
            u64_from_usize(header.len())?,
            catalog.hidden_bit_stream_byte_length,
            catalog.batch_stream_byte_length,
            catalog.zero_sharing_stream_byte_length,
        ])?;
        let mut hasher = StreamingHash512::new(BATCHED_HIDDEN_BIT_CHECK_CATALOG_IDENTITY_DOMAIN, 1);
        hasher.begin_part(catalog.artifact_byte_length);
        hasher.absorb_raw(&header);
        catalog.absorb_record_streams(&mut hasher);
        catalog.identity = Hash512::from_bytes(hasher.finalize());
        Ok(catalog)
    }

    pub(crate) const fn identity(&self) -> Hash512 {
        self.identity
    }

    pub(crate) const fn profile(&self) -> TallyCircuitProfile {
        self.profile
    }

    pub(crate) fn hidden_bit_count(&self) -> u64 {
        self.hidden_bits.len() as u64
    }

    pub(crate) fn batch_count(&self) -> u64 {
        self.batches.len() as u64
    }

    pub(crate) fn conjunction_product_count(&self) -> u64 {
        self.conjunctions.len() as u64
    }

    pub(crate) const fn zero_sharing_count(&self) -> u64 {
        self.zero_sharing_count
    }

    pub(crate) const fn soundness_union_numerator(&self) -> u64 {
        self.soundness_union_numerator
    }

    pub(crate) const fn soundness_field_bit_length(&self) -> u64 {
        FIELD_BIT_LENGTH
    }

    pub(crate) const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub(crate) fn hidden_bit(
        &self,
        hidden_bit_ordinal: u64,
    ) -> Result<BatchedHiddenBitSource320, BatchedHiddenBitCheckError320> {
        self.hidden_bits
            .get(usize_from_u64(hidden_bit_ordinal)?)
            .copied()
            .ok_or(BatchedHiddenBitCheckError320::HiddenBitOrdinalOutOfRange {
                hidden_bit_ordinal,
                hidden_bit_count: self.hidden_bit_count(),
            })
    }

    pub(crate) fn hidden_bits(
        &self,
    ) -> impl ExactSizeIterator<Item = BatchedHiddenBitSource320> + '_ {
        self.hidden_bits.iter().copied()
    }

    pub(crate) fn batch(
        &self,
        batch_ordinal: u64,
    ) -> Result<BatchedHiddenBitBatch320, BatchedHiddenBitCheckError320> {
        self.batches
            .get(usize_from_u64(batch_ordinal)?)
            .copied()
            .ok_or(BatchedHiddenBitCheckError320::BatchOrdinalOutOfRange {
                batch_ordinal,
                batch_count: self.batch_count(),
            })
    }

    pub(crate) fn batches(&self) -> impl ExactSizeIterator<Item = BatchedHiddenBitBatch320> + '_ {
        self.batches.iter().copied()
    }

    pub(crate) fn zero_sharing(
        &self,
        zero_sharing_ordinal: u64,
    ) -> Result<BatchedHiddenBitZeroSharing320, BatchedHiddenBitCheckError320> {
        if zero_sharing_ordinal >= self.zero_sharing_count {
            return Err(
                BatchedHiddenBitCheckError320::ZeroSharingOrdinalOutOfRange {
                    zero_sharing_ordinal,
                    zero_sharing_count: self.zero_sharing_count,
                },
            );
        }
        let batch_count = self.batch_count();
        if zero_sharing_ordinal < batch_count {
            let batch = self.batch(zero_sharing_ordinal)?;
            return Ok(BatchedHiddenBitZeroSharing320 {
                zero_sharing_ordinal,
                coordinate: BatchedHiddenBitZeroSharingCoordinate320::BatchMask {
                    batch_ordinal: batch.batch_ordinal,
                    first_hidden_bit_ordinal: batch.first_hidden_bit_ordinal,
                    hidden_bit_count: batch.hidden_bit_count,
                },
            });
        }
        let conjunction_ordinal = zero_sharing_ordinal
            .checked_sub(batch_count)
            .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;
        let conjunction = self
            .conjunctions
            .get(usize_from_u64(conjunction_ordinal)?)
            .copied()
            .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;
        Ok(BatchedHiddenBitZeroSharing320 {
            zero_sharing_ordinal,
            coordinate: BatchedHiddenBitZeroSharingCoordinate320::ConjunctionProductMask {
                conjunction_ordinal: conjunction.conjunction_ordinal,
                circuit_operation_position: conjunction.circuit_operation_position,
                output_wire: conjunction.output_wire,
                left_wire: conjunction.left_wire,
                right_wire: conjunction.right_wire,
            },
        })
    }

    pub(crate) fn zero_sharings(
        &self,
    ) -> impl Iterator<Item = BatchedHiddenBitZeroSharing320> + '_ {
        let batch_masks =
            self.batches
                .iter()
                .copied()
                .map(|batch| BatchedHiddenBitZeroSharing320 {
                    zero_sharing_ordinal: batch.zero_sharing_ordinal,
                    coordinate: BatchedHiddenBitZeroSharingCoordinate320::BatchMask {
                        batch_ordinal: batch.batch_ordinal,
                        first_hidden_bit_ordinal: batch.first_hidden_bit_ordinal,
                        hidden_bit_count: batch.hidden_bit_count,
                    },
                });
        let first_conjunction_ordinal = self.batch_count();
        let conjunction_masks = (first_conjunction_ordinal..self.zero_sharing_count)
            .zip(self.conjunctions.iter().copied())
            .map(
                |(zero_sharing_ordinal, conjunction)| BatchedHiddenBitZeroSharing320 {
                    zero_sharing_ordinal,
                    coordinate: BatchedHiddenBitZeroSharingCoordinate320::ConjunctionProductMask {
                        conjunction_ordinal: conjunction.conjunction_ordinal,
                        circuit_operation_position: conjunction.circuit_operation_position,
                        output_wire: conjunction.output_wire,
                        left_wire: conjunction.left_wire,
                        right_wire: conjunction.right_wire,
                    },
                },
            );
        batch_masks.chain(conjunction_masks)
    }

    pub(crate) const fn resource_input(&self) -> PseudorandomZeroSharingResourceInput {
        PseudorandomZeroSharingResourceInput {
            participant_count: self.profile.participant_count(),
            zero_sharing_count: self.zero_sharing_count,
        }
    }

    fn canonical_header_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);
        append_bytes(&mut bytes, BATCHED_HIDDEN_BIT_CHECK_CATALOG_MAGIC);
        append_varuint(&mut bytes, BATCHED_HIDDEN_BIT_CHECK_CATALOG_VERSION);
        append_bytes(&mut bytes, self.parameter_identity.as_bytes());
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_bytes(&mut bytes, self.circuit_identity.as_bytes());
        append_bytes(&mut bytes, self.circuit_compiler_identity.as_bytes());
        append_bytes(&mut bytes, self.catalog_compiler_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.profile.participant_count()));
        append_varuint(&mut bytes, u64::from(self.profile.option_count()));
        append_varuint(&mut bytes, u64::from(self.profile.top_count()));
        append_varuint(&mut bytes, BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE);
        append_varuint(&mut bytes, self.hidden_bit_count());
        append_varuint(&mut bytes, self.batch_count());
        append_varuint(&mut bytes, self.conjunction_product_count());
        append_varuint(&mut bytes, self.zero_sharing_count);
        append_varuint(&mut bytes, self.soundness_union_numerator);
        append_varuint(&mut bytes, FIELD_BIT_LENGTH);
        append_varuint(&mut bytes, self.hidden_bit_stream_byte_length);
        append_varuint(&mut bytes, self.batch_stream_byte_length);
        append_varuint(&mut bytes, self.zero_sharing_stream_byte_length);
        bytes
    }

    fn hidden_bit_stream_byte_length(&self) -> Result<u64, BatchedHiddenBitCheckError320> {
        sum_encoded_lengths(self.hidden_bits(), |record, bytes| {
            record.append_canonical_bytes(bytes)
        })
    }

    fn batch_stream_byte_length(&self) -> Result<u64, BatchedHiddenBitCheckError320> {
        sum_encoded_lengths(self.batches(), |batch, bytes| {
            batch.append_canonical_bytes(bytes)
        })
    }

    fn zero_sharing_stream_byte_length(&self) -> Result<u64, BatchedHiddenBitCheckError320> {
        sum_encoded_lengths(self.zero_sharings(), |record, bytes| {
            record.append_canonical_bytes(bytes)
        })
    }

    fn absorb_record_streams(&self, hasher: &mut StreamingHash512) {
        let mut record_bytes = Vec::with_capacity(32);
        for record in self.hidden_bits() {
            record_bytes.clear();
            record.append_canonical_bytes(&mut record_bytes);
            hasher.absorb_raw(&record_bytes);
        }
        for batch in self.batches() {
            record_bytes.clear();
            batch.append_canonical_bytes(&mut record_bytes);
            hasher.absorb_raw(&record_bytes);
        }
        for record in self.zero_sharings() {
            record_bytes.clear();
            record.append_canonical_bytes(&mut record_bytes);
            hasher.absorb_raw(&record_bytes);
        }
    }

    #[cfg(test)]
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.canonical_header_bytes();
        for record in self.hidden_bits() {
            record.append_canonical_bytes(&mut bytes);
        }
        for batch in self.batches() {
            batch.append_canonical_bytes(&mut bytes);
        }
        for record in self.zero_sharings() {
            record.append_canonical_bytes(&mut bytes);
        }
        bytes
    }
}

/// Exact scalar and zero-source comparison for the bounded four-batch
/// candidate and the retained per-bit route.
///
/// This is a production-derived resource compiler, not an admission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchedHiddenBitCheckResourceModel320 {
    pub(crate) hidden_bit_count: u64,
    pub(crate) batch_count: u64,
    pub(crate) maximum_batch_size: u64,
    pub(crate) final_batch_size: u64,
    pub(crate) conjunction_product_count: u64,
    pub(crate) zero_sharing_count: u64,
    pub(crate) hidden_bit_square_count_per_participant: u64,
    pub(crate) challenge_multiplication_count_per_participant: u64,
    pub(crate) batch_evaluation_multiplication_count_per_participant: u64,
    pub(crate) batch_evaluation_addition_count_per_participant: u64,
    pub(crate) soundness_union_numerator: u64,
    pub(crate) soundness_field_bit_length: u64,
    pub(crate) single_batch_zero_sharing_count: u64,
    pub(crate) single_batch_field_output_count_per_participant: u64,
    pub(crate) bounded_batch_additional_field_output_count_per_participant: u64,
    pub(crate) per_bit_zero_sharing_count: u64,
    pub(crate) zero_sharing_count_reduction: u64,
    pub(crate) per_bit_field_output_count_per_participant: u64,
    pub(crate) field_output_count_reduction_per_participant: u64,
    pub(crate) field_output_byte_length_reduction_per_participant: u64,
    pub(crate) selected_cursor: PseudorandomZeroSharingCursorResourceModel320,
}

impl BatchedHiddenBitCheckResourceModel320 {
    pub(crate) fn derive(
        catalog: &BatchedHiddenBitCheckCatalog320,
        circuit: &CompiledTallyCircuit,
        participant_position: u16,
    ) -> Result<Self, BatchedHiddenBitCheckError320> {
        if circuit.profile() != catalog.profile
            || Hash512::from_bytes(circuit.circuit_identity()?) != catalog.circuit_identity
        {
            return Err(BatchedHiddenBitCheckError320::ContextCircuitMismatch);
        }
        let selected_source =
            PseudorandomZeroSharingResourceModel::derive(catalog.resource_input())?;
        let selected_cursor = PseudorandomZeroSharingCursorResourceModel320::derive(
            catalog.profile.participant_count(),
            participant_position,
            catalog.zero_sharing_count,
        )?;
        if selected_source.field_output_count_per_participant != selected_cursor.field_output_count
        {
            return Err(BatchedHiddenBitCheckError320::GeometryMismatch);
        }
        let per_bit = PerBitPseudorandomZeroSharingWorkload320::derive(circuit)?;
        let per_bit_source = PseudorandomZeroSharingResourceModel::derive(
            per_bit.resource_input(circuit.profile().participant_count()),
        )?;
        let batch_count = catalog.batch_count();
        let hidden_bit_square_count_per_participant = catalog.hidden_bit_count();
        let challenge_multiplication_count_per_participant = catalog
            .hidden_bit_count()
            .checked_sub(batch_count)
            .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;
        let batch_evaluation_multiplication_count_per_participant = checked_add(
            hidden_bit_square_count_per_participant,
            challenge_multiplication_count_per_participant,
        )?;
        let batch_evaluation_addition_count_per_participant = checked_add(
            checked_add(
                catalog.hidden_bit_count(),
                challenge_multiplication_count_per_participant,
            )?,
            batch_count,
        )?;
        let single_batch_zero_sharing_count = checked_add(catalog.conjunction_product_count(), 1)?;
        let subset_basis_stream_count = selected_source.subset_basis_stream_count_per_participant;
        let single_batch_field_output_count_per_participant =
            checked_multiply(single_batch_zero_sharing_count, subset_basis_stream_count)?;
        let bounded_batch_additional_field_output_count_per_participant = selected_source
            .field_output_count_per_participant
            .checked_sub(single_batch_field_output_count_per_participant)
            .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;

        Ok(Self {
            hidden_bit_count: catalog.hidden_bit_count(),
            batch_count,
            maximum_batch_size: BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE,
            final_batch_size: catalog
                .batches
                .last()
                .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?
                .hidden_bit_count,
            conjunction_product_count: catalog.conjunction_product_count(),
            zero_sharing_count: catalog.zero_sharing_count,
            hidden_bit_square_count_per_participant,
            challenge_multiplication_count_per_participant,
            batch_evaluation_multiplication_count_per_participant,
            batch_evaluation_addition_count_per_participant,
            soundness_union_numerator: catalog.soundness_union_numerator,
            soundness_field_bit_length: FIELD_BIT_LENGTH,
            single_batch_zero_sharing_count,
            single_batch_field_output_count_per_participant,
            bounded_batch_additional_field_output_count_per_participant,
            per_bit_zero_sharing_count: per_bit.zero_sharing_count,
            zero_sharing_count_reduction: per_bit
                .zero_sharing_count
                .checked_sub(catalog.zero_sharing_count)
                .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?,
            per_bit_field_output_count_per_participant: per_bit_source
                .field_output_count_per_participant,
            field_output_count_reduction_per_participant: per_bit_source
                .field_output_count_per_participant
                .checked_sub(selected_source.field_output_count_per_participant)
                .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?,
            field_output_byte_length_reduction_per_participant: per_bit_source
                .field_output_byte_length_per_participant
                .checked_sub(selected_source.field_output_byte_length_per_participant)
                .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?,
            selected_cursor,
        })
    }
}

/// Evaluates one participant's masked batch point with Horner's rule.
///
/// The caller supplies exactly the batch's retained degree-three evaluations
/// and its fresh source-derived zero-mask evaluation. This algebraic result is
/// not authenticated and cannot authorize preparation.
pub(crate) fn evaluate_batched_hidden_bit_check_share_320(
    batch: BatchedHiddenBitBatch320,
    challenge: BinaryFieldElement320,
    hidden_bit_evaluations: &[BinaryFieldElement320],
    zero_mask_evaluation: BinaryFieldElement320,
) -> Result<BinaryFieldElement320, BatchedHiddenBitCheckError320> {
    let expected = usize_from_u64(batch.hidden_bit_count)?;
    if hidden_bit_evaluations.len() != expected {
        return Err(
            BatchedHiddenBitCheckError320::HiddenBitEvaluationCountMismatch {
                expected,
                actual: hidden_bit_evaluations.len(),
            },
        );
    }
    let mut reversed = hidden_bit_evaluations.iter().rev().copied();
    let last = reversed
        .next()
        .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;
    let mut evaluated = last.square().add(last);
    for hidden_bit_evaluation in reversed {
        evaluated = evaluated
            .multiply(challenge)
            .add(hidden_bit_evaluation.square().add(hidden_bit_evaluation));
    }
    Ok(evaluated.add(zero_mask_evaluation))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchedHiddenBitPolynomial320 {
    coefficients: Vec<BinaryFieldElement320>,
}

impl BatchedHiddenBitPolynomial320 {
    pub(crate) fn from_coefficients(mut coefficients: Vec<BinaryFieldElement320>) -> Self {
        trim_trailing_zero_coefficients(&mut coefficients);
        Self { coefficients }
    }

    pub(crate) fn zero() -> Self {
        Self::from_coefficients(vec![BinaryFieldElement320::ZERO])
    }

    pub(crate) fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }

    pub(crate) fn coefficient(&self, degree: usize) -> BinaryFieldElement320 {
        self.coefficients
            .get(degree)
            .copied()
            .unwrap_or(BinaryFieldElement320::ZERO)
    }

    pub(crate) fn evaluate(&self, point: BinaryFieldElement320) -> BinaryFieldElement320 {
        self.coefficients
            .iter()
            .rev()
            .copied()
            .fold(BinaryFieldElement320::ZERO, |value, coefficient| {
                value.multiply(point).add(coefficient)
            })
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let coefficient_count = self.coefficients.len().max(other.coefficients.len());
        Self::from_coefficients(
            (0..coefficient_count)
                .map(|degree| self.coefficient(degree).add(other.coefficient(degree)))
                .collect(),
        )
    }

    pub(crate) fn scale(&self, scalar: BinaryFieldElement320) -> Self {
        Self::from_coefficients(
            self.coefficients
                .iter()
                .copied()
                .map(|coefficient| coefficient.multiply(scalar))
                .collect(),
        )
    }

    fn multiply_by_linear_root(&self, root: BinaryFieldElement320) -> Self {
        let mut coefficients = vec![BinaryFieldElement320::ZERO; self.coefficients.len() + 1];
        for (degree, coefficient) in self.coefficients.iter().copied().enumerate() {
            coefficients[degree] = coefficients[degree].add(coefficient.multiply(root));
            coefficients[degree + 1] = coefficients[degree + 1].add(coefficient);
        }
        Self::from_coefficients(coefficients)
    }

    fn multiply_by_power_of_x(&self, exponent: usize) -> Self {
        let mut coefficients = vec![BinaryFieldElement320::ZERO; exponent];
        coefficients.extend_from_slice(&self.coefficients);
        Self::from_coefficients(coefficients)
    }
}

/// Exact hidden kernel for a degree-`2t` zero-constant codeword after the
/// adversary's `t` evaluations are fixed.
///
/// Its `t` bases are `X^k * product_c (X + alpha_c)` for `k = 1..=t`.
/// This is theorem machinery only; it neither samples a mask nor verifies an
/// emitted source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchedHiddenBitAffineFiberBasis320 {
    participant_count: u16,
    corrupt_positions: Box<[u16]>,
    maximum_degree: usize,
    bases: Box<[BatchedHiddenBitPolynomial320]>,
}

impl BatchedHiddenBitAffineFiberBasis320 {
    pub(crate) fn derive(
        participant_count: u16,
        corrupt_positions: &[u16],
    ) -> Result<Self, BatchedHiddenBitCheckError320> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;
        let active_fault_bound = usize::from(roster_parameters.active_fault_bound);
        if corrupt_positions.len() != active_fault_bound {
            return Err(
                BatchedHiddenBitCheckError320::CorruptPositionCountMismatch {
                    expected: active_fault_bound,
                    actual: corrupt_positions.len(),
                },
            );
        }
        if corrupt_positions
            .windows(2)
            .any(|positions| positions[0] >= positions[1])
            || corrupt_positions
                .iter()
                .copied()
                .any(|position| position >= participant_count)
        {
            return Err(BatchedHiddenBitCheckError320::CorruptPositionsNotCanonical);
        }
        let root_polynomial = corrupt_positions.iter().copied().try_fold(
            BatchedHiddenBitPolynomial320::from_coefficients(vec![BinaryFieldElement320::ONE]),
            |polynomial, roster_position| {
                Ok::<_, BatchedHiddenBitCheckError320>(polynomial.multiply_by_linear_root(
                    canonical_evaluation_point_320(participant_count, roster_position)?,
                ))
            },
        )?;
        let bases = (1..=active_fault_bound)
            .map(|power| root_polynomial.multiply_by_power_of_x(power))
            .collect::<Vec<_>>();
        let maximum_degree = active_fault_bound
            .checked_mul(2)
            .ok_or(BatchedHiddenBitCheckError320::ArithmeticOverflow)?;
        if bases.last().map(BatchedHiddenBitPolynomial320::degree) != Some(maximum_degree) {
            return Err(BatchedHiddenBitCheckError320::GeometryMismatch);
        }
        Ok(Self {
            participant_count,
            corrupt_positions: corrupt_positions.into(),
            maximum_degree,
            bases: bases.into_boxed_slice(),
        })
    }

    pub(crate) const fn maximum_degree(&self) -> usize {
        self.maximum_degree
    }

    pub(crate) fn dimension(&self) -> usize {
        self.bases.len()
    }

    pub(crate) fn bases(&self) -> &[BatchedHiddenBitPolynomial320] {
        &self.bases
    }

    pub(crate) fn reassemble(
        &self,
        components: &[BinaryFieldElement320],
    ) -> Result<BatchedHiddenBitPolynomial320, BatchedHiddenBitCheckError320> {
        if components.len() != self.bases.len() {
            return Err(BatchedHiddenBitCheckError320::AffineFiberDecompositionFailure);
        }
        Ok(self.bases.iter().zip(components.iter().copied()).fold(
            BatchedHiddenBitPolynomial320::zero(),
            |polynomial, (basis, component)| polynomial.add(&basis.scale(component)),
        ))
    }

    pub(crate) fn decompose(
        &self,
        polynomial: &BatchedHiddenBitPolynomial320,
    ) -> Result<Vec<BinaryFieldElement320>, BatchedHiddenBitCheckError320> {
        if polynomial.degree() > self.maximum_degree {
            return Err(BatchedHiddenBitCheckError320::PolynomialDegreeOutOfRange {
                maximum_degree: self.maximum_degree,
                actual_degree: polynomial.degree(),
            });
        }
        if !polynomial.evaluate(BinaryFieldElement320::ZERO).is_zero() {
            return Err(
                BatchedHiddenBitCheckError320::PolynomialVisibleAtFixedPoint {
                    roster_position: None,
                },
            );
        }
        for roster_position in self.corrupt_positions.iter().copied() {
            if !polynomial
                .evaluate(canonical_evaluation_point_320(
                    self.participant_count,
                    roster_position,
                )?)
                .is_zero()
            {
                return Err(
                    BatchedHiddenBitCheckError320::PolynomialVisibleAtFixedPoint {
                        roster_position: Some(roster_position),
                    },
                );
            }
        }

        let mut remainder = polynomial.clone();
        let mut components = vec![BinaryFieldElement320::ZERO; self.bases.len()];
        for basis_position in (0..self.bases.len()).rev() {
            let basis = &self.bases[basis_position];
            let leading_degree = basis.degree();
            let leading_coefficient = basis.coefficient(leading_degree);
            let component = remainder
                .coefficient(leading_degree)
                .divide(leading_coefficient)?;
            components[basis_position] = component;
            remainder = remainder.add(&basis.scale(component));
        }
        if (0..=self.maximum_degree).any(|degree| !remainder.coefficient(degree).is_zero()) {
            return Err(BatchedHiddenBitCheckError320::AffineFiberDecompositionFailure);
        }
        Ok(components)
    }
}

fn derive_hidden_bits(
    circuit: &CompiledTallyCircuit,
    output_rekeyed: &OutputRekeyedTallyCircuit,
) -> Result<Vec<BatchedHiddenBitSource320>, BatchedHiddenBitCheckError320> {
    let mut hidden_bits = Vec::new();
    for input_wire in 0..circuit.geometry().input_bit_count {
        push_hidden_bit(
            &mut hidden_bits,
            BatchedHiddenBitSourceCoordinate320::CoreWire {
                wire_index: WireIndex::try_from(input_wire)
                    .map_err(|_| BatchedHiddenBitCheckError320::IntegerConversion)?,
            },
        )?;
    }
    for (operation_position, operation) in circuit.operations().iter().enumerate() {
        if matches!(operation, BooleanOperation::Constant(_)) {
            continue;
        }
        let wire_index = circuit
            .geometry()
            .input_bit_count
            .checked_add(operation_position)
            .ok_or(BatchedHiddenBitCheckError320::ArithmeticOverflow)?;
        push_hidden_bit(
            &mut hidden_bits,
            BatchedHiddenBitSourceCoordinate320::CoreWire {
                wire_index: WireIndex::try_from(wire_index)
                    .map_err(|_| BatchedHiddenBitCheckError320::IntegerConversion)?,
            },
        )?;
    }

    let operations = output_rekeyed.output_rekey_operations();
    let participant_count = usize::from(circuit.profile().participant_count());
    if operations.len()
        != participant_count
            .checked_add(1)
            .and_then(|count| count.checked_add(circuit.geometry().private_result_bit_count))
            .ok_or(BatchedHiddenBitCheckError320::ArithmeticOverflow)?
    {
        return Err(BatchedHiddenBitCheckError320::OutputRekeyedCircuitMismatch);
    }
    for (participant_position, operation) in operations
        .iter()
        .copied()
        .take(participant_count)
        .enumerate()
    {
        if operation.output_wire()
            != output_rekeyed.accepted_ballot_authorship_output_wires()[participant_position]
        {
            return Err(BatchedHiddenBitCheckError320::OutputRekeyedCircuitMismatch);
        }
        push_hidden_bit(
            &mut hidden_bits,
            BatchedHiddenBitSourceCoordinate320::AcceptedAuthorshipOutput {
                participant_position: u16::try_from(participant_position)
                    .map_err(|_| BatchedHiddenBitCheckError320::IntegerConversion)?,
                source_wire: operation.input_wire(),
                output_wire: operation.output_wire(),
            },
        )?;
    }
    let nonempty_operation = operations[participant_count];
    if nonempty_operation.output_wire() != output_rekeyed.nonempty_output_wire() {
        return Err(BatchedHiddenBitCheckError320::OutputRekeyedCircuitMismatch);
    }
    push_hidden_bit(
        &mut hidden_bits,
        BatchedHiddenBitSourceCoordinate320::PublicNonemptyOutput {
            source_wire: nonempty_operation.input_wire(),
            output_wire: nonempty_operation.output_wire(),
        },
    )?;
    for (result_bit_position, (operation, output_wire)) in operations[participant_count + 1..]
        .iter()
        .copied()
        .zip(
            output_rekeyed
                .ordered_option_position_wires()
                .iter()
                .flatten()
                .copied(),
        )
        .enumerate()
    {
        if operation.output_wire() != output_wire {
            return Err(BatchedHiddenBitCheckError320::OutputRekeyedCircuitMismatch);
        }
        push_hidden_bit(
            &mut hidden_bits,
            BatchedHiddenBitSourceCoordinate320::PrivateResultOutput {
                result_bit_position: u64_from_usize(result_bit_position)?,
                source_wire: operation.input_wire(),
                output_wire: operation.output_wire(),
            },
        )?;
    }
    let expected_count = output_rekeyed
        .geometry()
        .total_wire_count
        .checked_sub(circuit.geometry().constant_operation_count)
        .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;
    if hidden_bits.len() != expected_count {
        return Err(BatchedHiddenBitCheckError320::GeometryMismatch);
    }
    Ok(hidden_bits)
}

fn push_hidden_bit(
    hidden_bits: &mut Vec<BatchedHiddenBitSource320>,
    coordinate: BatchedHiddenBitSourceCoordinate320,
) -> Result<(), BatchedHiddenBitCheckError320> {
    hidden_bits.push(BatchedHiddenBitSource320 {
        hidden_bit_ordinal: u64_from_usize(hidden_bits.len())?,
        coordinate,
    });
    Ok(())
}

fn derive_batches(
    hidden_bit_count: u64,
) -> Result<Vec<BatchedHiddenBitBatch320>, BatchedHiddenBitCheckError320> {
    if hidden_bit_count == 0 {
        return Err(BatchedHiddenBitCheckError320::GeometryMismatch);
    }
    let batch_count = checked_ceiling_divide(
        hidden_bit_count,
        BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE,
    )?;
    (0..batch_count)
        .map(|batch_ordinal| {
            let first_hidden_bit_ordinal =
                checked_multiply(batch_ordinal, BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE)?;
            let remaining = hidden_bit_count
                .checked_sub(first_hidden_bit_ordinal)
                .ok_or(BatchedHiddenBitCheckError320::GeometryMismatch)?;
            Ok(BatchedHiddenBitBatch320 {
                batch_ordinal,
                first_hidden_bit_ordinal,
                hidden_bit_count: remaining.min(BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE),
                zero_sharing_ordinal: batch_ordinal,
            })
        })
        .collect()
}

fn derive_conjunctions(
    circuit: &CompiledTallyCircuit,
) -> Result<Vec<ConjunctionSource320>, BatchedHiddenBitCheckError320> {
    let mut conjunctions = Vec::with_capacity(circuit.geometry().conjunction_gate_count);
    for (operation_position, operation) in circuit.operations().iter().enumerate() {
        let BooleanOperation::Conjunction {
            left_wire,
            right_wire,
        } = operation
        else {
            continue;
        };
        conjunctions.push(ConjunctionSource320 {
            conjunction_ordinal: u64_from_usize(conjunctions.len())?,
            circuit_operation_position: u64_from_usize(operation_position)?,
            output_wire: WireIndex::try_from(
                circuit
                    .geometry()
                    .input_bit_count
                    .checked_add(operation_position)
                    .ok_or(BatchedHiddenBitCheckError320::ArithmeticOverflow)?,
            )
            .map_err(|_| BatchedHiddenBitCheckError320::IntegerConversion)?,
            left_wire: *left_wire,
            right_wire: *right_wire,
        });
    }
    Ok(conjunctions)
}

pub(crate) fn batched_hidden_bit_check_compiler_identity()
-> Result<Hash512, BatchedHiddenBitCheckError320> {
    for source in [
        BATCHED_HIDDEN_BIT_CHECK_SOURCE,
        OUTPUT_REKEYED_TALLY_CIRCUIT_SOURCE,
    ] {
        if core::str::from_utf8(source).is_err()
            || source.starts_with(&[0xef, 0xbb, 0xbf])
            || source.contains(&b'\r')
            || !source.ends_with(b"\n")
        {
            return Err(BatchedHiddenBitCheckError320::NonCanonicalCompilerSource);
        }
    }
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        BATCHED_HIDDEN_BIT_CHECK_CATALOG_COMPILER_IDENTITY_DOMAIN,
        &[
            BATCHED_HIDDEN_BIT_CHECK_SOURCE,
            OUTPUT_REKEYED_TALLY_CIRCUIT_SOURCE,
            &BATCHED_HIDDEN_BIT_CHECK_CATALOG_VERSION.to_le_bytes(),
            &BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE.to_le_bytes(),
        ],
    )))
}

fn sum_encoded_lengths<T: Copy>(
    records: impl Iterator<Item = T>,
    append_record: impl Fn(T, &mut Vec<u8>),
) -> Result<u64, BatchedHiddenBitCheckError320> {
    let mut total = 0_u64;
    let mut bytes = Vec::with_capacity(32);
    for record in records {
        bytes.clear();
        append_record(record, &mut bytes);
        total = checked_add(total, u64_from_usize(bytes.len())?)?;
    }
    Ok(total)
}

fn trim_trailing_zero_coefficients(coefficients: &mut Vec<BinaryFieldElement320>) {
    while coefficients.len() > 1 && coefficients.last().is_some_and(|value| value.is_zero()) {
        coefficients.pop();
    }
    if coefficients.is_empty() {
        coefficients.push(BinaryFieldElement320::ZERO);
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, BatchedHiddenBitCheckError320> {
    left.checked_add(right)
        .ok_or(BatchedHiddenBitCheckError320::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, BatchedHiddenBitCheckError320> {
    left.checked_mul(right)
        .ok_or(BatchedHiddenBitCheckError320::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, BatchedHiddenBitCheckError320> {
    values.iter().copied().try_fold(0_u64, checked_add)
}

fn checked_ceiling_divide(
    dividend: u64,
    divisor: u64,
) -> Result<u64, BatchedHiddenBitCheckError320> {
    if divisor == 0 {
        return Err(BatchedHiddenBitCheckError320::GeometryMismatch);
    }
    checked_add(
        dividend / divisor,
        u64::from(!dividend.is_multiple_of(divisor)),
    )
}

fn u64_from_usize(value: usize) -> Result<u64, BatchedHiddenBitCheckError320> {
    u64::try_from(value).map_err(|_| BatchedHiddenBitCheckError320::IntegerConversion)
}

fn usize_from_u64(value: u64) -> Result<usize, BatchedHiddenBitCheckError320> {
    usize::try_from(value).map_err(|_| BatchedHiddenBitCheckError320::IntegerConversion)
}
