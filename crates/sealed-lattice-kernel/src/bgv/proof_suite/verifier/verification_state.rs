use super::CommonProofVerifierError;
use crate::bgv::proof_suite::{ProofBodyError, ProofByteSource, ProofDecodeError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofRequiredByteRange {
    offset: usize,
    byte_length: usize,
}

impl CommonProofRequiredByteRange {
    pub(crate) const fn new(offset: usize, byte_length: usize) -> Option<Self> {
        if byte_length == 0 || offset.checked_add(byte_length).is_none() {
            None
        } else {
            Some(Self {
                offset,
                byte_length,
            })
        }
    }

    pub(crate) const fn offset(self) -> usize {
        self.offset
    }

    pub(crate) const fn byte_length(self) -> usize {
        self.byte_length
    }
}

pub(crate) struct ProofBodyByteSource<'source, Source: ProofByteSource + ?Sized> {
    source: &'source Source,
    body_offset: usize,
    body_byte_length: usize,
}

impl<Source: ProofByteSource + ?Sized> ProofByteSource for ProofBodyByteSource<'_, Source> {
    fn byte_length(&self) -> usize {
        self.body_byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(relative_end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if relative_end > self.body_byte_length {
            return false;
        }
        let Some(absolute_offset) = self.body_offset.checked_add(offset) else {
            return false;
        };
        self.source.copy_bytes(absolute_offset, destination)
    }
}

/// Progressively compares a transported proof-object prefix with the exact
/// canonical header derived from the authenticated application. The expected
/// header length is local authority; proof bytes never supply a length to
/// parse or allocate from.
#[derive(Debug)]
pub(crate) struct IncrementalExpectedProofObjectHeaderComparator {
    expected_header_bytes: Box<[u8]>,
    declared_complete_proof_byte_length: usize,
    family_body_byte_length: usize,
    compared_header_byte_length: usize,
}

impl IncrementalExpectedProofObjectHeaderComparator {
    pub(crate) fn new(
        expected_header_bytes: Vec<u8>,
        declared_complete_proof_byte_length: usize,
        proof_byte_ceiling: usize,
    ) -> Result<Self, CommonProofVerifierError> {
        let family_body_byte_length = validate_expected_proof_object_layout(
            declared_complete_proof_byte_length,
            proof_byte_ceiling,
            &expected_header_bytes,
        )?;
        Ok(Self {
            expected_header_bytes: expected_header_bytes.into_boxed_slice(),
            declared_complete_proof_byte_length,
            family_body_byte_length,
            compared_header_byte_length: 0,
        })
    }

    pub(crate) const fn expected_header_byte_length(&self) -> usize {
        self.expected_header_bytes.len()
    }

    pub(crate) const fn declared_complete_proof_byte_length(&self) -> usize {
        self.declared_complete_proof_byte_length
    }

    pub(crate) const fn family_body_byte_length(&self) -> usize {
        self.family_body_byte_length
    }

    pub(crate) const fn compared_header_byte_length(&self) -> usize {
        self.compared_header_byte_length
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.compared_header_byte_length == self.expected_header_bytes.len()
    }

    pub(crate) fn compare_available<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<(), CommonProofVerifierError> {
        if source.byte_length() != self.declared_complete_proof_byte_length {
            return Err(ProofBodyError::Decode(ProofDecodeError::DeclaredLengthMismatch).into());
        }
        if available_end_offset < self.compared_header_byte_length
            || available_end_offset > self.declared_complete_proof_byte_length
        {
            return Err(CommonProofVerifierError::InvalidProofHeader);
        }
        let comparison_end_offset = available_end_offset.min(self.expected_header_bytes.len());
        compare_expected_proof_object_header_range(
            source,
            &self.expected_header_bytes,
            self.compared_header_byte_length,
            comparison_end_offset,
        )?;
        self.compared_header_byte_length = comparison_end_offset;
        Ok(())
    }

    pub(crate) fn body_source<'source, Source: ProofByteSource + ?Sized>(
        &self,
        source: &'source Source,
    ) -> Result<ProofBodyByteSource<'source, Source>, CommonProofVerifierError> {
        if !self.is_complete() || source.byte_length() != self.declared_complete_proof_byte_length {
            return Err(CommonProofVerifierError::InvalidProofHeader);
        }
        Ok(ProofBodyByteSource {
            source,
            body_offset: self.expected_header_bytes.len(),
            body_byte_length: self.family_body_byte_length,
        })
    }
}

fn validate_expected_proof_object_layout(
    declared_proof_byte_length: usize,
    proof_byte_ceiling: usize,
    expected_header: &[u8],
) -> Result<usize, CommonProofVerifierError> {
    if declared_proof_byte_length == 0 {
        return Err(ProofBodyError::Decode(ProofDecodeError::EmptyProof).into());
    }
    if declared_proof_byte_length > proof_byte_ceiling {
        return Err(ProofBodyError::Decode(ProofDecodeError::ProofByteCeilingExceeded).into());
    }
    if expected_header.is_empty() {
        return Err(CommonProofVerifierError::InvalidProofHeader);
    }
    declared_proof_byte_length
        .checked_sub(expected_header.len())
        .filter(|length| *length > 0)
        .ok_or(CommonProofVerifierError::InvalidProofHeader)
}

fn compare_expected_proof_object_header_range<Source: ProofByteSource + ?Sized>(
    source: &Source,
    expected_header: &[u8],
    comparison_start_offset: usize,
    comparison_end_offset: usize,
) -> Result<(), CommonProofVerifierError> {
    if comparison_start_offset > comparison_end_offset
        || comparison_end_offset > expected_header.len()
    {
        return Err(CommonProofVerifierError::InvalidProofHeader);
    }
    let mut compared_byte_length = comparison_start_offset;
    let mut scratch = [0_u8; 256];
    while compared_byte_length < comparison_end_offset {
        let chunk_byte_length = scratch
            .len()
            .min(comparison_end_offset - compared_byte_length);
        let chunk = &mut scratch[..chunk_byte_length];
        if !source.copy_bytes(compared_byte_length, chunk) {
            return Err(ProofBodyError::Decode(ProofDecodeError::Truncated).into());
        }
        if chunk
            != expected_header
                .get(compared_byte_length..compared_byte_length + chunk_byte_length)
                .ok_or(CommonProofVerifierError::InvalidProofHeader)?
        {
            return Err(CommonProofVerifierError::InvalidProofHeader);
        }
        compared_byte_length += chunk_byte_length;
    }
    Ok(())
}
