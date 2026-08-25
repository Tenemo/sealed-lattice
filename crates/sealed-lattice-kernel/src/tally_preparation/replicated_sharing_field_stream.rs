use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    FOUNDATION_PROFILE, xof_foundation_tuple,
};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    replicated_key_ceremony::{
        ReplicatedRandomSharingKey, ReplicatedRandomSharingKeyCoordinate,
        ReplicatedRandomSharingKeyPurpose,
    },
};

pub(super) const REPLICATED_SHARING_FIELD_STREAM_DOMAIN: &str =
    "sealed-lattice/tally-preparation/replicated-sharing-field-stream/v1";

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ReplicatedSharingFieldStreamPurpose {
    IndependentTripleLeft = 1,
    IndependentTripleRight = 2,
    IndependentTripleReductionMask = 3,
    IndependentTripleDegreeDoubleZeroMask = 4,
    OrdinaryTripleLeft = 5,
    OrdinaryTripleRight = 6,
    OrdinaryTripleReductionMask = 7,
    OrdinaryTripleDegreeDoubleZeroMask = 8,
    AuthenticationCommonCoefficient = 9,
    AuthenticationTripleRight = 10,
    AuthenticationTripleReductionMask = 11,
    AuthenticationTripleDegreeDoubleZeroMask = 12,
}

impl ReplicatedSharingFieldStreamPurpose {
    const fn canonical_code(self) -> u16 {
        self as u16
    }

    const fn requires_zero_sharing_key(self) -> bool {
        matches!(
            self,
            Self::IndependentTripleDegreeDoubleZeroMask
                | Self::OrdinaryTripleDegreeDoubleZeroMask
                | Self::AuthenticationTripleDegreeDoubleZeroMask
        )
    }
}

pub(crate) struct ReplicatedSharingFieldChunk {
    first_field_index: u64,
    field_count: u64,
    bytes: Zeroizing<Vec<u8>>,
}

impl ReplicatedSharingFieldChunk {
    pub(crate) const fn first_field_index(&self) -> u64 {
        self.first_field_index
    }

    pub(crate) const fn field_count(&self) -> u64 {
        self.field_count
    }

    pub(crate) fn byte_length(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn field_element(
        &self,
        position_within_chunk: u64,
    ) -> Result<BinaryFieldElement256, TallyPreparationError> {
        if position_within_chunk >= self.field_count {
            return Err(
                TallyPreparationError::ReplicatedSharingFieldPositionOutOfRange {
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
            .checked_add(BinaryFieldElement256::CANONICAL_BYTE_LENGTH)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        BinaryFieldElement256::from_canonical_bytes(&self.bytes[start..end])
    }
}

impl fmt::Debug for ReplicatedSharingFieldChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicatedSharingFieldChunk")
            .field("first_field_index", &self.first_field_index)
            .field("field_count", &self.field_count)
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct FieldChunkGeometry {
    first_field_index: u64,
    field_count: u64,
    output_byte_length: u64,
}

pub(crate) fn generate_replicated_sharing_field_chunk(
    key: &ReplicatedRandomSharingKey,
    purpose: ReplicatedSharingFieldStreamPurpose,
    total_field_count: u64,
    chunk_index: u64,
) -> Result<ReplicatedSharingFieldChunk, TallyPreparationError> {
    validate_key_purpose(key.coordinate(), purpose)?;
    let geometry = derive_field_chunk_geometry(total_field_count, chunk_index)?;
    let mut items = field_chunk_query_items(
        key.as_bytes(),
        key.coordinate(),
        purpose,
        total_field_count,
        chunk_index,
        geometry,
    )?;
    let output_result = xof_foundation_tuple(
        REPLICATED_SHARING_FIELD_STREAM_DOMAIN,
        &items,
        usize::try_from(geometry.output_byte_length)
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    );
    items.zeroize();
    let output = output_result?;
    Ok(ReplicatedSharingFieldChunk {
        first_field_index: geometry.first_field_index,
        field_count: geometry.field_count,
        bytes: Zeroizing::new(output),
    })
}

pub(crate) fn replicated_sharing_field_chunk_count(
    total_field_count: u64,
) -> Result<u64, TallyPreparationError> {
    if total_field_count == 0 {
        return Err(TallyPreparationError::ReplicatedSharingFieldCountZero);
    }
    let field_elements_per_chunk = field_elements_per_chunk()?;
    checked_ceiling_divide(total_field_count, field_elements_per_chunk)
}

pub(crate) fn replicated_sharing_field_chunk_preimage_byte_length(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    purpose: ReplicatedSharingFieldStreamPurpose,
    total_field_count: u64,
    chunk_index: u64,
) -> Result<u64, TallyPreparationError> {
    validate_key_purpose(coordinate, purpose)?;
    let geometry = derive_field_chunk_geometry(total_field_count, chunk_index)?;
    let mut items = field_chunk_query_items(
        &[0_u8; 64],
        coordinate,
        purpose,
        total_field_count,
        chunk_index,
        geometry,
    )?;
    let preimage_result = encode_field_stream_query_preimage(&items);
    items.zeroize();
    let preimage = preimage_result?;
    u64::try_from(preimage.len()).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn encode_field_stream_query_preimage(
    items: &[CanonicalItem],
) -> Result<Zeroizing<Vec<u8>>, TallyPreparationError> {
    let mut framed_items = Vec::with_capacity(items.len().saturating_add(1));
    framed_items.push(CanonicalItem::nonempty_ascii(
        REPLICATED_SHARING_FIELD_STREAM_DOMAIN,
    )?);
    framed_items.extend_from_slice(items);
    let mut tuple = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        framed_items,
    );
    let encoded_result = tuple.encode();
    tuple.zeroize();
    Ok(Zeroizing::new(encoded_result?))
}

fn field_chunk_query_items(
    key_bytes: &[u8; 64],
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    purpose: ReplicatedSharingFieldStreamPurpose,
    total_field_count: u64,
    chunk_index: u64,
    geometry: FieldChunkGeometry,
) -> Result<Vec<CanonicalItem>, TallyPreparationError> {
    let coordinate_item = CanonicalItem::variable_bytes(coordinate.canonical_bytes())?;
    let key_item = CanonicalItem::fixed_bytes(key_bytes)?;
    Ok(vec![
        key_item,
        coordinate_item,
        CanonicalItem::unsigned16(purpose.canonical_code()),
        CanonicalItem::unsigned64(total_field_count),
        CanonicalItem::unsigned64(chunk_index),
        CanonicalItem::unsigned64(geometry.first_field_index),
        CanonicalItem::unsigned64(geometry.field_count),
        CanonicalItem::unsigned64(FIELD_ELEMENT_BYTE_LENGTH),
        CanonicalItem::unsigned64(geometry.output_byte_length),
    ])
}

fn validate_key_purpose(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    purpose: ReplicatedSharingFieldStreamPurpose,
) -> Result<(), TallyPreparationError> {
    let coordinate_uses_zero_sharing_key = matches!(
        coordinate.purpose(),
        ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { .. }
    );
    if coordinate_uses_zero_sharing_key != purpose.requires_zero_sharing_key() {
        return Err(TallyPreparationError::ReplicatedSharingFieldPurposeMismatch);
    }
    Ok(())
}

fn derive_field_chunk_geometry(
    total_field_count: u64,
    chunk_index: u64,
) -> Result<FieldChunkGeometry, TallyPreparationError> {
    let field_elements_per_chunk = field_elements_per_chunk()?;
    let chunk_count = replicated_sharing_field_chunk_count(total_field_count)?;
    if chunk_index >= chunk_count {
        return Err(
            TallyPreparationError::ReplicatedSharingFieldChunkOutOfRange {
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

fn field_elements_per_chunk() -> Result<u64, TallyPreparationError> {
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    if !chunk_byte_length.is_multiple_of(FIELD_ELEMENT_BYTE_LENGTH) {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    chunk_byte_length
        .checked_div(FIELD_ELEMENT_BYTE_LENGTH)
        .filter(|field_count| *field_count > 0)
        .ok_or(TallyPreparationError::GeometryMismatch)
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
