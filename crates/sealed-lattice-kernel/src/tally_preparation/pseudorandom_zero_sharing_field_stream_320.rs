use core::fmt;

use tiny_keccak::{Hasher, IntoXof, Kmac, Xof};
use zeroize::Zeroizing;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    FOUNDATION_PROFILE, Hash512,
};

use super::{
    TallyPreparationContext, TallyPreparationError, binary_field_320::BinaryFieldElement320,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

pub(crate) const PSEUDORANDOM_FIELD_STREAM_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/v1/preparation/pseudorandom-field-stream";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH: usize =
    BinaryFieldElement320::CANONICAL_BYTE_LENGTH;

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const ZERO_SHARING_BASIS_STREAM_KIND_CODE: u16 = 1;
const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement320::CANONICAL_BYTE_LENGTH as u64;

/// Public coordinate for one independently reproducible KMACXOF256 field stream.
///
/// A coordinate binds the candidate parameter identity, complete preparation
/// context, subset, zero-sharing catalog, basis position, total field count,
/// and chunk geometry. It carries no key authority and cannot establish that
/// callers agreed on the supplied subset master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingFieldStreamCoordinate320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    zero_sharing_catalog_identity: Hash512,
    subset: ReplicatedRandomSharingSubset,
    basis_position: u16,
    total_field_count: u64,
}

impl PseudorandomZeroSharingFieldStreamCoordinate320 {
    pub(crate) fn new(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        zero_sharing_catalog_identity: Hash512,
        subset: ReplicatedRandomSharingSubset,
        basis_position: u16,
        total_field_count: u64,
    ) -> Result<Self, TallyPreparationError> {
        if subset.participant_count() != preparation_context.participant_count() {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingFieldStreamSubsetParticipantCountMismatch {
                    subset_participant_count: subset.participant_count(),
                    context_participant_count: preparation_context.participant_count(),
                },
            );
        }
        if basis_position >= subset.active_fault_bound() {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingFieldStreamBasisPositionOutOfRange {
                    basis_position,
                    active_fault_bound: subset.active_fault_bound(),
                },
            );
        }
        if total_field_count == 0 {
            return Err(TallyPreparationError::PseudorandomZeroSharingFieldCountZero);
        }

        Ok(Self {
            parameter_identity,
            preparation_context_identity: preparation_context.identity(),
            zero_sharing_catalog_identity,
            subset,
            basis_position,
            total_field_count,
        })
    }

    pub(crate) fn chunk_count(self) -> Result<u64, TallyPreparationError> {
        pseudorandom_zero_sharing_field_chunk_count(self.total_field_count)
    }

    pub(crate) fn canonical_query_bytes(
        self,
        chunk_index: u64,
    ) -> Result<Vec<u8>, TallyPreparationError> {
        let geometry = derive_field_chunk_geometry(self.total_field_count, chunk_index)?;
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::hash512(self.parameter_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::unsigned16(ZERO_SHARING_BASIS_STREAM_KIND_CODE),
                CanonicalItem::unsigned16(self.subset.participant_count()),
                CanonicalItem::unsigned32(self.subset.excluded_position_mask()),
                CanonicalItem::hash512(self.zero_sharing_catalog_identity.into_bytes()),
                CanonicalItem::unsigned16(self.basis_position),
                CanonicalItem::unsigned64(self.total_field_count),
                CanonicalItem::unsigned64(chunk_index),
                CanonicalItem::unsigned64(geometry.field_count),
            ],
        )
        .encode()?)
    }
}

pub(crate) struct PseudorandomZeroSharingFieldChunk320 {
    first_field_index: u64,
    field_count: u64,
    bytes: Zeroizing<Vec<u8>>,
}

impl PseudorandomZeroSharingFieldChunk320 {
    pub(crate) const fn first_field_index(&self) -> u64 {
        self.first_field_index
    }

    pub(crate) const fn field_count(&self) -> u64 {
        self.field_count
    }

    pub(crate) fn byte_length(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn field_element(
        &self,
        position_within_chunk: u64,
    ) -> Result<BinaryFieldElement320, TallyPreparationError> {
        if position_within_chunk >= self.field_count {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingFieldStreamPositionOutOfRange {
                    position_within_chunk,
                    field_count: self.field_count,
                },
            );
        }
        let start = usize::try_from(checked_multiply(
            position_within_chunk,
            FIELD_ELEMENT_BYTE_LENGTH,
        )?)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let end = start
            .checked_add(BinaryFieldElement320::CANONICAL_BYTE_LENGTH)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        BinaryFieldElement320::from_canonical_bytes(&self.bytes[start..end])
    }
}

impl fmt::Debug for PseudorandomZeroSharingFieldChunk320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingFieldChunk320")
            .field("first_field_index", &self.first_field_index)
            .field("field_count", &self.field_count)
            .field("bytes", &"[redacted]")
            .finish()
    }
}

pub(crate) fn generate_pseudorandom_zero_sharing_field_chunk_320(
    subset_master: &[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH],
    coordinate: PseudorandomZeroSharingFieldStreamCoordinate320,
    chunk_index: u64,
) -> Result<PseudorandomZeroSharingFieldChunk320, TallyPreparationError> {
    let geometry = derive_field_chunk_geometry(coordinate.total_field_count, chunk_index)?;
    let query_bytes = coordinate.canonical_query_bytes(chunk_index)?;
    let output_byte_length = usize::try_from(geometry.output_byte_length)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    let bytes =
        expand_pseudorandom_field_kmacxof256(subset_master, &query_bytes, output_byte_length);
    Ok(PseudorandomZeroSharingFieldChunk320 {
        first_field_index: geometry.first_field_index,
        field_count: geometry.field_count,
        bytes,
    })
}

pub(crate) fn expand_pseudorandom_field_kmacxof256(
    key: &[u8],
    message: &[u8],
    output_byte_length: usize,
) -> Zeroizing<Vec<u8>> {
    let mut kmac = Kmac::v256(key, PSEUDORANDOM_FIELD_STREAM_CUSTOMIZATION);
    kmac.update(message);
    let mut output = Zeroizing::new(vec![0_u8; output_byte_length]);
    kmac.into_xof().squeeze(&mut output);
    output
}

pub(crate) fn pseudorandom_zero_sharing_field_chunk_count(
    total_field_count: u64,
) -> Result<u64, TallyPreparationError> {
    if total_field_count == 0 {
        return Err(TallyPreparationError::PseudorandomZeroSharingFieldCountZero);
    }
    checked_ceiling_divide(
        total_field_count,
        pseudorandom_zero_sharing_field_elements_per_chunk()?,
    )
}

pub(crate) fn pseudorandom_zero_sharing_field_elements_per_chunk()
-> Result<u64, TallyPreparationError> {
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    chunk_byte_length
        .checked_div(FIELD_ELEMENT_BYTE_LENGTH)
        .filter(|field_count| *field_count > 0)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

#[derive(Debug, Clone, Copy)]
struct FieldChunkGeometry {
    first_field_index: u64,
    field_count: u64,
    output_byte_length: u64,
}

fn derive_field_chunk_geometry(
    total_field_count: u64,
    chunk_index: u64,
) -> Result<FieldChunkGeometry, TallyPreparationError> {
    let field_elements_per_chunk = pseudorandom_zero_sharing_field_elements_per_chunk()?;
    let chunk_count = pseudorandom_zero_sharing_field_chunk_count(total_field_count)?;
    if chunk_index >= chunk_count {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingFieldStreamChunkOutOfRange {
                chunk_index,
                chunk_count,
            },
        );
    }
    let first_field_index = checked_multiply(chunk_index, field_elements_per_chunk)?;
    let remaining_field_count = total_field_count
        .checked_sub(first_field_index)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    let field_count = remaining_field_count.min(field_elements_per_chunk);
    let output_byte_length = checked_multiply(field_count, FIELD_ELEMENT_BYTE_LENGTH)?;
    Ok(FieldChunkGeometry {
        first_field_index,
        field_count,
        output_byte_length,
    })
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    quotient
        .checked_add(u64::from(remainder != 0))
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
