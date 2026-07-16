/// Random-access byte reads over a retained canonical proof stream.
///
/// Implementations expose only length-checked copies. The common decoder owns
/// all cursor movement and never requires the source to join its chunks.
pub(crate) trait ProofByteSource {
    fn byte_length(&self) -> usize;
    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool;
}

impl ProofByteSource for [u8] {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        let Some(source) = self.get(offset..end) else {
            return false;
        };
        destination.copy_from_slice(source);
        true
    }
}

impl ProofByteSource for Vec<u8> {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        self.as_slice().copy_bytes(offset, destination)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofDecodeError {
    EmptyProof,
    ProofByteCeilingExceeded,
    DeclaredLengthMismatch,
    Truncated,
    OffsetOverflow,
    IntegerOverflow,
    BoundedLengthExceeded,
    InvalidBitWidth,
    NonCanonicalFieldElement,
    NonCanonicalPackedPadding,
    TrailingBytes,
}

/// A forward-only bounded parser over contiguous or canonical chunked bytes.
///
/// It copies only the requested field into caller-owned fixed storage. Large
/// openings can therefore be checked and discarded without joining the proof
/// stream into one allocation.
pub(crate) struct BoundedProofDecoder<'source, Source: ProofByteSource + ?Sized> {
    source: &'source Source,
    total_byte_length: usize,
    offset: usize,
}

impl<'source, Source: ProofByteSource + ?Sized> BoundedProofDecoder<'source, Source> {
    pub(crate) fn new(
        source: &'source Source,
        declared_byte_length: usize,
        proof_byte_ceiling: usize,
    ) -> Result<Self, ProofDecodeError> {
        if declared_byte_length == 0 {
            return Err(ProofDecodeError::EmptyProof);
        }
        if declared_byte_length > proof_byte_ceiling {
            return Err(ProofDecodeError::ProofByteCeilingExceeded);
        }
        if source.byte_length() != declared_byte_length {
            return Err(ProofDecodeError::DeclaredLengthMismatch);
        }
        Ok(Self {
            source,
            total_byte_length: declared_byte_length,
            offset: 0,
        })
    }

    pub(crate) const fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn read_exact(&mut self, destination: &mut [u8]) -> Result<(), ProofDecodeError> {
        let end = self
            .offset
            .checked_add(destination.len())
            .ok_or(ProofDecodeError::OffsetOverflow)?;
        if end > self.total_byte_length || !self.source.copy_bytes(self.offset, destination) {
            return Err(ProofDecodeError::Truncated);
        }
        self.offset = end;
        Ok(())
    }

    pub(crate) fn read_array<const BYTE_COUNT: usize>(
        &mut self,
    ) -> Result<[u8; BYTE_COUNT], ProofDecodeError> {
        let mut bytes = [0_u8; BYTE_COUNT];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    pub(crate) fn read_bytes(&mut self, byte_count: usize) -> Result<Vec<u8>, ProofDecodeError> {
        let end = self
            .offset
            .checked_add(byte_count)
            .ok_or(ProofDecodeError::OffsetOverflow)?;
        if end > self.total_byte_length {
            return Err(ProofDecodeError::Truncated);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_count)
            .map_err(|_| ProofDecodeError::BoundedLengthExceeded)?;
        bytes.resize(byte_count, 0);
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, ProofDecodeError> {
        let mut bytes = [0_u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, ProofDecodeError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, ProofDecodeError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    pub(crate) fn read_hash512(&mut self) -> Result<[u8; 64], ProofDecodeError> {
        self.read_array()
    }

    pub(crate) fn read_base_field_element(
        &mut self,
    ) -> Result<super::ProofBaseFieldElement, ProofDecodeError> {
        super::ProofBaseFieldElement::from_canonical(self.read_u64()?)
            .map_err(|_| ProofDecodeError::NonCanonicalFieldElement)
    }

    pub(crate) fn read_challenge_extension_element(
        &mut self,
    ) -> Result<super::ProofChallengeExtensionElement, ProofDecodeError> {
        let mut coordinates = [0_u64; super::PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = self.read_u64()?;
        }
        super::ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
            .map_err(|_| ProofDecodeError::NonCanonicalFieldElement)
    }

    /// Reads little-endian fixed-width values packed consecutively into bytes.
    ///
    /// The final byte must have zeroes in every unused high bit. The decoder
    /// copies input through a fixed scratch buffer, so even a large statement-
    /// derived field vector does not require a second proof-sized allocation.
    pub(crate) fn read_packed_u64_values(
        &mut self,
        value_count: usize,
        bit_width: usize,
    ) -> Result<Vec<u64>, ProofDecodeError> {
        if bit_width > u64::BITS as usize {
            return Err(ProofDecodeError::InvalidBitWidth);
        }
        let bit_count = value_count
            .checked_mul(bit_width)
            .ok_or(ProofDecodeError::IntegerOverflow)?;
        let byte_count = bit_count.div_ceil(u8::BITS as usize);
        let end = self
            .offset
            .checked_add(byte_count)
            .ok_or(ProofDecodeError::OffsetOverflow)?;
        if end > self.total_byte_length {
            return Err(ProofDecodeError::Truncated);
        }

        let mut values = Vec::new();
        values
            .try_reserve_exact(value_count)
            .map_err(|_| ProofDecodeError::BoundedLengthExceeded)?;
        if bit_width == 0 {
            values.resize(value_count, 0);
            return Ok(values);
        }

        const SCRATCH_BYTE_COUNT: usize = 4096;
        let mut scratch = [0_u8; SCRATCH_BYTE_COUNT];
        let mut copied_byte_count = 0_usize;
        let mut scratch_byte_count = 0_usize;
        let mut scratch_offset = 0_usize;
        let mut accumulator = 0_u128;
        let mut accumulator_bit_count = 0_usize;
        let value_mask = if bit_width == u64::BITS as usize {
            u128::from(u64::MAX)
        } else {
            (1_u128 << bit_width) - 1
        };

        for _ in 0..value_count {
            while accumulator_bit_count < bit_width {
                if scratch_offset == scratch_byte_count {
                    let remaining_byte_count = byte_count - copied_byte_count;
                    if remaining_byte_count == 0 {
                        return Err(ProofDecodeError::Truncated);
                    }
                    scratch_byte_count = remaining_byte_count.min(SCRATCH_BYTE_COUNT);
                    scratch_offset = 0;
                    let source_offset = self
                        .offset
                        .checked_add(copied_byte_count)
                        .ok_or(ProofDecodeError::OffsetOverflow)?;
                    if !self
                        .source
                        .copy_bytes(source_offset, &mut scratch[..scratch_byte_count])
                    {
                        return Err(ProofDecodeError::Truncated);
                    }
                    copied_byte_count += scratch_byte_count;
                }
                accumulator |= u128::from(scratch[scratch_offset]) << accumulator_bit_count;
                scratch_offset += 1;
                accumulator_bit_count += u8::BITS as usize;
            }
            values.push((accumulator & value_mask) as u64);
            accumulator >>= bit_width;
            accumulator_bit_count -= bit_width;
        }

        if accumulator != 0 {
            return Err(ProofDecodeError::NonCanonicalPackedPadding);
        }
        self.offset = end;
        Ok(values)
    }

    pub(crate) fn finish(self) -> Result<(), ProofDecodeError> {
        if self.offset != self.total_byte_length {
            return Err(ProofDecodeError::TrailingBytes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_values(values: &[u64], bit_width: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; values.len().saturating_mul(bit_width).div_ceil(8)];
        let mut bit_offset = 0_usize;
        for value in values {
            for value_bit_offset in 0..bit_width {
                let bit = ((*value >> value_bit_offset) & 1) as u8;
                bytes[bit_offset / 8] |= bit << (bit_offset % 8);
                bit_offset += 1;
            }
        }
        bytes
    }

    #[test]
    fn packed_value_reader_matches_the_canonical_little_endian_bit_order() {
        let bytes = [0xd1_u8, 0x00];
        let mut decoder = BoundedProofDecoder::new(&bytes[..], bytes.len(), bytes.len())
            .expect("bounded packed source");
        assert_eq!(
            decoder
                .read_packed_u64_values(3, 3)
                .expect("canonical packed values"),
            [1, 2, 3]
        );
        decoder.finish().expect("packed input is exhausted");

        let values = [0_u64, 1, u64::MAX, 0x0123_4567_89ab_cdef];
        let bytes = pack_values(&values, 64);
        let mut decoder = BoundedProofDecoder::new(&bytes, bytes.len(), bytes.len())
            .expect("bounded full-width source");
        assert_eq!(
            decoder
                .read_packed_u64_values(values.len(), 64)
                .expect("full-width values"),
            values
        );
        decoder.finish().expect("full-width input is exhausted");
    }

    #[test]
    fn packed_value_reader_crosses_its_fixed_scratch_boundary() {
        let values = (0_u64..703)
            .map(|index| (index * 0x1f_1234_5678) & ((1_u64 << 47) - 1))
            .collect::<Vec<_>>();
        let bytes = pack_values(&values, 47);
        assert!(bytes.len() > 4096);
        let mut decoder = BoundedProofDecoder::new(&bytes, bytes.len(), bytes.len())
            .expect("bounded field-vector source");
        assert_eq!(
            decoder
                .read_packed_u64_values(values.len(), 47)
                .expect("field vector spanning the scratch boundary"),
            values
        );
        decoder.finish().expect("field-vector input is exhausted");
    }

    #[test]
    fn packed_value_reader_rejects_padding_truncation_and_impossible_widths() {
        let noncanonical_padding = [0xd1_u8, 0x02];
        let mut decoder = BoundedProofDecoder::new(
            &noncanonical_padding[..],
            noncanonical_padding.len(),
            noncanonical_padding.len(),
        )
        .expect("bounded noncanonical source");
        assert_eq!(
            decoder.read_packed_u64_values(3, 3),
            Err(ProofDecodeError::NonCanonicalPackedPadding)
        );
        assert_eq!(decoder.offset(), 0, "a rejected field must not advance");

        let truncated = [0xff_u8];
        let mut decoder =
            BoundedProofDecoder::new(&truncated[..], 1, 1).expect("bounded truncated source");
        assert_eq!(
            decoder.read_packed_u64_values(2, 8),
            Err(ProofDecodeError::Truncated)
        );
        assert_eq!(
            decoder.read_packed_u64_values(1, 65),
            Err(ProofDecodeError::InvalidBitWidth)
        );
        assert_eq!(
            decoder.read_packed_u64_values(usize::MAX, 2),
            Err(ProofDecodeError::IntegerOverflow)
        );
    }

    #[test]
    fn byte_reader_rejects_a_truncated_length_before_reserving() {
        let bytes = [0x51_u8];
        let mut decoder = BoundedProofDecoder::new(&bytes[..], bytes.len(), bytes.len())
            .expect("bounded byte source");

        assert_eq!(
            decoder.read_bytes(usize::MAX),
            Err(ProofDecodeError::Truncated)
        );
        assert_eq!(decoder.offset(), 0, "a rejected field must not advance");
    }
}
