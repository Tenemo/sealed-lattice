use super::*;

use std::{collections::BTreeSet, sync::Arc};

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct SetupProofMaterialTransportHashes {
    pub(crate) full_object_hash: String,
    pub(crate) chunk_hashes: Vec<String>,
    pub(crate) chunk_root: String,
    pub(crate) total_byte_length: u64,
}

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
        let canonical_chunk_byte_length = SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES as usize;
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
            .div_ceil(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES as usize)
    }

    pub(crate) fn chunk(&self, chunk_index: usize) -> Option<&[u8]> {
        match &self.backing {
            CanonicalProofMaterialBacking::Contiguous(bytes) => bytes
                .chunks(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES as usize)
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

        let chunk_byte_length = SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES as usize;
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
        let chunk_byte_length = SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES as usize;
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

pub(in crate::bgv::setup) fn setup_proof_record_binding_value(
    setup_parameters_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofRecordBinding",
        "setupParametersHash": setup_parameters_hash,
        "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
        "proofSerialization": SETUP_PROOF_SERIALIZATION,
        "proofByteDecoder": SETUP_PROOF_BYTE_DECODER,
    }))
}

pub(in crate::bgv::setup) fn verified_setup_proof_material_bytes_from_request(
    _request: &Value,
    proof_family: &str,
    expected_proof_material_root: &str,
    _transported_proof_material: &Value,
    transported_material_path: &str,
) -> CanonicalResult<SetupProofMaterialBytes> {
    if !SETUP_PROOF_TRANSPORT_FAMILIES.contains(&proof_family) {
        return Err(setup_proof_error(
            "setup proof material proof family is not in the fixed setup-proof parameters",
        ));
    }
    validate_hash_string(
        expected_proof_material_root,
        &format!("{transported_material_path}.proofMaterialRoot"),
    )?;
    crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        proof_family,
        expected_proof_material_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{transported_material_path} is missing canonical stream-authenticated proof material"
            ),
        )
    })
}

fn request_verified_canonical_setup_proof_material_roots(request: &Value) -> Vec<String> {
    let mut material_roots = BTreeSet::new();
    for field_name in [
        "transportedPrivateVssShareProofMaterial",
        "transportedPublicKeyShareProofMaterial",
        "transportedVssShareLinkageProofMaterial",
        "transportedSameSecretBridgeProofMaterial",
        "transportedEvaluationKeyShareProofMaterial",
    ] {
        if let Some(sidecar) = request.get(field_name) {
            collect_request_material_roots(sidecar, "proofMaterialRoot", &mut material_roots);
        }
    }
    if let Some(sidecar) = request.get("transportedPublicEvaluationKeyMaterial") {
        collect_request_material_roots(
            sidecar,
            "publicEvaluationKeyMaterialRoot",
            &mut material_roots,
        );
    }

    material_roots.into_iter().collect()
}

fn collect_request_material_roots(
    value: &Value,
    root_field_name: &str,
    material_roots: &mut BTreeSet<String>,
) {
    let mut pending_values = vec![value];
    while let Some(current_value) = pending_values.pop() {
        match current_value {
            Value::Object(fields) => {
                if let Some(root) = fields.get(root_field_name).and_then(Value::as_str) {
                    material_roots.insert(root.to_string());
                }
                pending_values.extend(fields.values());
            }
            Value::Array(items) => pending_values.extend(items),
            _ => {}
        }
    }
}

pub(in crate::bgv::setup) struct VerifiedSetupProofMaterialEvictionGuard {
    canonical_proof_material_roots: Vec<String>,
    canonical_public_key_share_material_roots: Vec<String>,
}

impl VerifiedSetupProofMaterialEvictionGuard {
    pub(in crate::bgv::setup) fn for_request(request: &Value) -> Self {
        Self {
            canonical_proof_material_roots: request_verified_canonical_setup_proof_material_roots(
                request,
            ),
            canonical_public_key_share_material_roots: request
                .get("transportedPublicKeyShareMaterial")
                .map(|material| {
                    let mut roots = BTreeSet::new();
                    collect_request_material_roots(
                        material,
                        "publicKeyShareMaterialSetRoot",
                        &mut roots,
                    );
                    roots.into_iter().collect()
                })
                .unwrap_or_default(),
        }
    }
}

impl Drop for VerifiedSetupProofMaterialEvictionGuard {
    fn drop(&mut self) {
        crate::bgv::setup::evict_verified_canonical_setup_proof_materials(
            &self.canonical_proof_material_roots,
        );
        crate::bgv::setup::evict_verified_canonical_public_key_share_materials(
            &self.canonical_public_key_share_material_roots,
        );
    }
}

#[cfg(test)]
mod verification;

#[cfg(test)]
pub(crate) use verification::{
    authenticate_setup_proof_material_stream_for_test,
    canonical_setup_proof_material_transport_accounting,
};
