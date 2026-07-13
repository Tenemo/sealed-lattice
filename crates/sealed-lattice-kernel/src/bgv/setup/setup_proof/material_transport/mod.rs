use super::*;

use std::sync::Arc;
use crate::foundation::FOUNDATION_PROFILE;

enum CanonicalProofMaterialBacking {
    Contiguous(Vec<u8>),
    StreamChunks(Vec<Vec<u8>>),
}

/// Authenticated proof bytes retained in the same canonical chunks that crossed
/// the stream boundary. Locally generated material may keep its original
/// contiguous allocation, but every read is exposed through the same bounded
/// chunk and range interface.
pub(crate) struct CanonicalProofMaterialBytes {
    backing: CanonicalProofMaterialBacking,
    total_byte_length: usize,
}

pub(crate) trait ProofByteSource {
    fn byte_length(&self) -> usize;
    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool;
    fn byte_at(&self, offset: usize) -> Option<u8>;
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

    fn byte_at(&self, offset: usize) -> Option<u8> {
        self.get(offset).copied()
    }
}

impl ProofByteSource for Vec<u8> {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        self.as_slice().copy_bytes(offset, destination)
    }

    fn byte_at(&self, offset: usize) -> Option<u8> {
        self.as_slice().byte_at(offset)
    }
}

impl CanonicalProofMaterialBytes {
    pub(crate) fn from_contiguous(bytes: Vec<u8>) -> CanonicalResult<Self> {
        if bytes.is_empty() {
            return Err(setup_proof_error(
                "canonical proof material must contain at least one byte",
            ));
        }
        Ok(Self {
            total_byte_length: bytes.len(),
            backing: CanonicalProofMaterialBacking::Contiguous(bytes),
        })
    }

    pub(crate) fn from_stream_chunks(chunks: Vec<Vec<u8>>) -> CanonicalResult<Self> {
        if chunks.is_empty() {
            return Err(setup_proof_error(
                "canonical proof material must contain at least one stream chunk",
            ));
        }
        let canonical_chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let mut total_byte_length = 0_usize;
        for (chunk_index, chunk) in chunks.iter().enumerate() {
            let is_final_chunk = chunk_index + 1 == chunks.len();
            if chunk.is_empty()
                || chunk.len() > canonical_chunk_byte_length
                || (!is_final_chunk && chunk.len() != canonical_chunk_byte_length)
            {
                return Err(setup_proof_error(
                    "canonical proof material chunks do not match the stream chunk profile",
                ));
            }
            total_byte_length = total_byte_length.checked_add(chunk.len()).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "canonical proof material byte length overflowed usize",
                )
            })?;
        }
        Ok(Self {
            backing: CanonicalProofMaterialBacking::StreamChunks(chunks),
            total_byte_length,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.total_byte_length
    }

    pub(crate) fn chunk_count(&self) -> usize {
        self.total_byte_length
            .div_ceil(FOUNDATION_PROFILE.stream_chunk_byte_length)
    }

    pub(crate) fn chunk(&self, chunk_index: usize) -> Option<&[u8]> {
        match &self.backing {
            CanonicalProofMaterialBacking::Contiguous(bytes) => bytes
                .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .nth(chunk_index),
            CanonicalProofMaterialBacking::StreamChunks(chunks) => {
                chunks.get(chunk_index).map(Vec::as_slice)
            }
        }
    }

    pub(crate) fn copy_range(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if end > self.total_byte_length {
            return false;
        }
        if destination.is_empty() {
            return true;
        }

        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let mut source_offset = offset;
        let mut destination_offset = 0_usize;
        while destination_offset < destination.len() {
            let chunk_index = source_offset / chunk_byte_length;
            let offset_in_chunk = source_offset % chunk_byte_length;
            let Some(chunk) = self.chunk(chunk_index) else {
                return false;
            };
            let copy_byte_length =
                (chunk.len() - offset_in_chunk).min(destination.len() - destination_offset);
            if copy_byte_length == 0 {
                return false;
            }
            destination[destination_offset..destination_offset + copy_byte_length]
                .copy_from_slice(&chunk[offset_in_chunk..offset_in_chunk + copy_byte_length]);
            source_offset += copy_byte_length;
            destination_offset += copy_byte_length;
        }

        true
    }

    pub(crate) fn byte_at(&self, offset: usize) -> Option<u8> {
        if offset >= self.total_byte_length {
            return None;
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        self.chunk(offset / chunk_byte_length)
            .and_then(|chunk| chunk.get(offset % chunk_byte_length))
            .copied()
    }

    pub(crate) fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.chunk_count()).map(|chunk_index| {
            self.chunk(chunk_index)
                .expect("canonical proof material chunk count matches its backing")
        })
    }

    #[cfg(test)]
    pub(crate) fn into_contiguous(self) -> Vec<u8> {
        match self.backing {
            CanonicalProofMaterialBacking::Contiguous(bytes) => bytes,
            CanonicalProofMaterialBacking::StreamChunks(chunks) => {
                let mut bytes = Vec::with_capacity(self.total_byte_length);
                for chunk in chunks {
                    bytes.extend_from_slice(&chunk);
                }
                bytes
            }
        }
    }

    pub(crate) fn hash512_hex(&self, domain: &str) -> CanonicalResult<String> {
        crate::hashing::hash512_hex_streamed_part(domain, self.len(), self.chunks())
    }
}

impl ProofByteSource for CanonicalProofMaterialBytes {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        self.copy_range(offset, destination)
    }

    fn byte_at(&self, offset: usize) -> Option<u8> {
        self.byte_at(offset)
    }
}

pub(crate) type BgvProofMaterialBytes = Arc<CanonicalProofMaterialBytes>;
pub(in crate::bgv::setup) type SetupProofMaterialBytes = BgvProofMaterialBytes;

pub(in crate::bgv::setup) fn take_verified_setup_proof_material_bytes(
    proof_family: &str,
    expected_proof_material_root: &str,
    proof_material_path: &str,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<SetupProofMaterialBytes> {
    validate_hash_string(expected_proof_material_root, proof_material_path)?;
    // A proof-material root is an owned, single-use lease for one setup
    // verification call. Remove it from the canonical store before decoding so
    // the store cannot retain the complete corpus while the verifier advances
    // through later records. The returned Arc keeps only the proof currently
    // being checked alive. A retry must authenticate the source again, matching
    // the disposable-kernel setup verification boundary.
    match proof_binding_session {
        Some(proof_binding_session) => crate::bgv::setup::take_accepted_setup_proof_material_bytes(
            proof_binding_session.session_handle,
            proof_family,
            expected_proof_material_root,
        ),
        None => crate::bgv::setup::take_verified_canonical_proof_material_bytes(
            proof_family,
            expected_proof_material_root,
        ),
    }?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{proof_material_path} has no canonical stream-authenticated proof material"
            ),
        )
    })
}

#[cfg(test)]
mod verification;

#[cfg(test)]
pub(crate) use verification::{
    authenticate_setup_proof_material_stream_for_test,
    authenticate_setup_proof_material_stream_in_session_for_test,
};
