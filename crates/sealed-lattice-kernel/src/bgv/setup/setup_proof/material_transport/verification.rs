use super::helpers::*;
use super::*;

// Recompute the transport manifest over a contiguous proof-byte buffer. The only
// valid chunking binds every non-final chunk to exactly `chunk_size_bytes`, so
// the canonical chunk windows are fully determined by the total length and are
// recovered here with `proof_bytes.chunks(chunk_size)`. Every hash is therefore
// byte-for-byte identical to the per-chunk form this replaced.
pub(crate) fn setup_proof_material_transport_hashes(
    proof_family: &str,
    proof_bytes: &[u8],
    chunk_size_bytes: u64,
) -> CanonicalResult<SetupProofMaterialTransportHashes> {
    if !SETUP_PROOF_TRANSPORT_FAMILIES.contains(&proof_family) {
        return Err(setup_proof_error(
            "setup proof material proof family is not in the fixed setup-proof parameters",
        ));
    }
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size must be positive",
        ));
    }
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material transport requires at least one chunk",
        ));
    }
    let chunk_size_usize = usize::try_from(chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size does not fit usize",
        )
    })?;
    let total_byte_length = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material byte length does not fit u64",
        )
    })?;

    let full_object_hash =
        setup_proof_material_full_object_hash(proof_family, total_byte_length, proof_bytes)?;
    let mut chunk_hashes = Vec::with_capacity(proof_bytes.len().div_ceil(chunk_size_usize));
    for (chunk_index, chunk) in proof_bytes.chunks(chunk_size_usize).enumerate() {
        chunk_hashes.push(setup_proof_material_chunk_hash(
            proof_family,
            &full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_root = setup_proof_material_chunk_manifest_root(
        proof_family,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(SetupProofMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}
