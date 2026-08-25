use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    FOUNDATION_PROFILE, xof_foundation_tuple,
};

use super::{
    TallyPreparationError,
    replicated_key_ceremony::{
        ReplicatedRandomSharingKey, ReplicatedRandomSharingKeyCoordinate,
        ReplicatedRandomSharingKeyPurpose,
    },
    replicated_random_bit_catalog::ReplicatedRandomBitCatalog,
};

pub(super) const REPLICATED_RANDOM_BIT_STREAM_DOMAIN: &str =
    "sealed-lattice/tally-preparation/replicated-random-bit-stream/v1";

const BITS_PER_BYTE: u64 = 8;

pub(crate) struct ReplicatedRandomBitChunk {
    first_bit_index: u64,
    bit_count: u64,
    bytes: Zeroizing<Vec<u8>>,
}

impl ReplicatedRandomBitChunk {
    pub(crate) const fn first_bit_index(&self) -> u64 {
        self.first_bit_index
    }

    pub(crate) const fn bit_count(&self) -> u64 {
        self.bit_count
    }

    pub(crate) fn byte_length(&self) -> usize {
        self.bytes.len()
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn bit(&self, position_within_chunk: u64) -> Result<u8, TallyPreparationError> {
        if position_within_chunk >= self.bit_count {
            return Err(
                TallyPreparationError::ReplicatedRandomBitPositionOutOfRange {
                    position_within_chunk,
                    bit_count: self.bit_count,
                },
            );
        }
        let byte_position = usize::try_from(position_within_chunk / BITS_PER_BYTE)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let bit_position = u32::try_from(position_within_chunk % BITS_PER_BYTE)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        self.bytes
            .get(byte_position)
            .map(|byte| (byte >> bit_position) & 1)
            .ok_or(TallyPreparationError::GeometryMismatch)
    }
}

impl fmt::Debug for ReplicatedRandomBitChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicatedRandomBitChunk")
            .field("first_bit_index", &self.first_bit_index)
            .field("bit_count", &self.bit_count)
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct BitChunkGeometry {
    first_bit_index: u64,
    bit_count: u64,
    output_byte_length: u64,
    unused_high_bit_count: u8,
}

pub(crate) fn generate_replicated_random_bit_chunk(
    key: &ReplicatedRandomSharingKey,
    catalog: &ReplicatedRandomBitCatalog,
    chunk_index: u64,
) -> Result<ReplicatedRandomBitChunk, TallyPreparationError> {
    validate_key(key.coordinate(), catalog)?;
    let geometry = derive_bit_chunk_geometry(catalog.total_bit_count(), chunk_index)?;
    let mut items = bit_chunk_query_items(
        key.as_bytes(),
        key.coordinate(),
        catalog,
        chunk_index,
        geometry,
    )?;
    let output_result = xof_foundation_tuple(
        REPLICATED_RANDOM_BIT_STREAM_DOMAIN,
        &items,
        usize::try_from(geometry.output_byte_length)
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    );
    items.zeroize();
    let mut output = Zeroizing::new(output_result?);
    mask_unused_high_bits(&mut output, geometry.unused_high_bit_count)?;
    Ok(ReplicatedRandomBitChunk {
        first_bit_index: geometry.first_bit_index,
        bit_count: geometry.bit_count,
        bytes: output,
    })
}

pub(crate) fn replicated_random_bit_chunk_count(
    catalog: &ReplicatedRandomBitCatalog,
) -> Result<u64, TallyPreparationError> {
    let bits_per_chunk = bits_per_chunk()?;
    checked_ceiling_divide(catalog.total_bit_count(), bits_per_chunk)
}

pub(crate) fn replicated_random_bit_chunk_preimage_byte_length(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    catalog: &ReplicatedRandomBitCatalog,
    chunk_index: u64,
) -> Result<u64, TallyPreparationError> {
    validate_coordinate(coordinate, catalog)?;
    let geometry = derive_bit_chunk_geometry(catalog.total_bit_count(), chunk_index)?;
    let mut items = bit_chunk_query_items(&[0_u8; 64], coordinate, catalog, chunk_index, geometry)?;
    let preimage_result = encode_bit_stream_query_preimage(&items);
    items.zeroize();
    let preimage = preimage_result?;
    u64::try_from(preimage.len()).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn validate_key(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    catalog: &ReplicatedRandomBitCatalog,
) -> Result<(), TallyPreparationError> {
    validate_coordinate(coordinate, catalog)
}

fn validate_coordinate(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    catalog: &ReplicatedRandomBitCatalog,
) -> Result<(), TallyPreparationError> {
    if !matches!(
        coordinate.purpose(),
        ReplicatedRandomSharingKeyPurpose::RandomSharing
    ) {
        return Err(TallyPreparationError::ReplicatedRandomBitKeyPurposeMismatch);
    }
    if coordinate.participant_count() != catalog.participant_count() {
        return Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch);
    }
    if coordinate.context_identity() != catalog.context_identity() {
        return Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch);
    }
    Ok(())
}

fn encode_bit_stream_query_preimage(
    items: &[CanonicalItem],
) -> Result<Zeroizing<Vec<u8>>, TallyPreparationError> {
    let mut framed_items = Vec::with_capacity(items.len().saturating_add(1));
    framed_items.push(CanonicalItem::nonempty_ascii(
        REPLICATED_RANDOM_BIT_STREAM_DOMAIN,
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

fn bit_chunk_query_items(
    key_bytes: &[u8; 64],
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    catalog: &ReplicatedRandomBitCatalog,
    chunk_index: u64,
    geometry: BitChunkGeometry,
) -> Result<Vec<CanonicalItem>, TallyPreparationError> {
    Ok(vec![
        CanonicalItem::fixed_bytes(key_bytes)?,
        CanonicalItem::variable_bytes(coordinate.canonical_bytes())?,
        CanonicalItem::fixed_bytes(catalog.identity().as_bytes())?,
        CanonicalItem::unsigned16(catalog.participant_count()),
        CanonicalItem::unsigned64(catalog.semantic_mask_bit_count()),
        CanonicalItem::unsigned64(catalog.additive_correlation_free_point_bit_count()),
        CanonicalItem::unsigned64(catalog.total_bit_count()),
        CanonicalItem::unsigned64(chunk_index),
        CanonicalItem::unsigned64(geometry.first_bit_index),
        CanonicalItem::unsigned64(geometry.bit_count),
        CanonicalItem::unsigned64(geometry.output_byte_length),
        CanonicalItem::unsigned16(u16::from(geometry.unused_high_bit_count)),
    ])
}

fn derive_bit_chunk_geometry(
    total_bit_count: u64,
    chunk_index: u64,
) -> Result<BitChunkGeometry, TallyPreparationError> {
    if total_bit_count == 0 {
        return Err(TallyPreparationError::ReplicatedRandomBitCountZero);
    }
    let bits_per_chunk = bits_per_chunk()?;
    let chunk_count = checked_ceiling_divide(total_bit_count, bits_per_chunk)?;
    if chunk_index >= chunk_count {
        return Err(TallyPreparationError::ReplicatedRandomBitChunkOutOfRange {
            chunk_index,
            chunk_count,
        });
    }
    let first_bit_index = checked_multiply(chunk_index, bits_per_chunk)?;
    let bit_count = total_bit_count
        .checked_sub(first_bit_index)
        .ok_or(TallyPreparationError::GeometryMismatch)?
        .min(bits_per_chunk);
    let output_byte_length = checked_ceiling_divide(bit_count, BITS_PER_BYTE)?;
    let used_final_byte_bit_count = bit_count % BITS_PER_BYTE;
    let unused_high_bit_count = if used_final_byte_bit_count == 0 {
        0
    } else {
        u8::try_from(BITS_PER_BYTE - used_final_byte_bit_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?
    };
    Ok(BitChunkGeometry {
        first_bit_index,
        bit_count,
        output_byte_length,
        unused_high_bit_count,
    })
}

fn bits_per_chunk() -> Result<u64, TallyPreparationError> {
    checked_multiply(
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
        BITS_PER_BYTE,
    )
}

fn mask_unused_high_bits(
    bytes: &mut [u8],
    unused_high_bit_count: u8,
) -> Result<(), TallyPreparationError> {
    if unused_high_bit_count == 0 {
        return Ok(());
    }
    let used_bit_count = u32::from(8_u8 - unused_high_bit_count);
    let mask = (1_u8 << used_bit_count) - 1;
    let final_byte = bytes
        .last_mut()
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    *final_byte &= mask;
    Ok(())
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
