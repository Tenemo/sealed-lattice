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
    BoundedLengthExceeded,
    NonCanonicalFieldElement,
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
