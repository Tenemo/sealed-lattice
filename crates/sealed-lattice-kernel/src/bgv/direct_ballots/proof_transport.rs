use super::*;

pub(super) fn chunk_count_for_bytes(
    byte_count: usize,
    chunk_size_bytes: usize,
) -> CanonicalResult<usize> {
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proof transport chunk size must be positive",
        ));
    }
    byte_count
        .checked_add(chunk_size_bytes - 1)
        .map(|rounded| rounded / chunk_size_bytes)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "proof transport chunk count overflowed",
            )
        })
}

pub(super) fn transport_direct_ballot_binary_proof(
    setup_package: &Value,
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    statement_hash: &str,
    proof_bytes: &[u8],
    expected_proof_bytes_hash: &str,
    proof_bytes_hash: fn(&[u8]) -> String,
) -> CanonicalResult<DirectBallotBinaryProofTransport> {
    let label = "direct ballot relation proof";
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} transport requires non-empty binary proof bytes"),
        ));
    }
    let chunk_count =
        chunk_count_for_bytes(proof_bytes.len(), DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)?;
    let mut transported_proof_bytes = Vec::with_capacity(proof_bytes.len());
    let mut chunk_hashes = Vec::with_capacity(chunk_count);
    let mut proof_chunks = Vec::with_capacity(chunk_count);
    let mut observed_chunk_count = 0_usize;
    for (chunk_index, chunk) in proof_bytes
        .chunks(DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)
        .enumerate()
    {
        if chunk.is_empty() || chunk.len() > DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} transport produced a malformed chunk"),
            ));
        }
        if chunk_index + 1 < chunk_count && chunk.len() != DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} transport has a short non-final chunk"),
            ));
        }
        transported_proof_bytes.extend_from_slice(chunk);
        observed_chunk_count = observed_chunk_count.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} transport chunk count overflowed"),
            )
        })?;
        let chunk_hash =
            direct_ballot_proof_chunk_hash(expected_proof_bytes_hash, chunk_index, chunk)?;
        chunk_hashes.push(chunk_hash.clone());
        proof_chunks.push(json!({
            "chunkIndex": chunk_index,
            "byteLength": chunk.len(),
            "chunkHash": chunk_hash,
            "bytesHex": to_hex(chunk),
        }));
    }
    if observed_chunk_count != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} transport chunk count does not match the byte length"),
        ));
    }
    let transported_proof_bytes_hash = proof_bytes_hash(&transported_proof_bytes);
    if transported_proof_bytes_hash != expected_proof_bytes_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} transported proof bytes do not match the proof hash"),
        ));
    }
    let chunk_merkle_root = chunk_root(
        &transported_proof_bytes,
        DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
    )?;
    let proof_chunk_manifest =
        direct_ballot_proof_chunk_manifest(DirectBallotProofChunkManifestInput {
            setup_package,
            ballot,
            proof_statement_hash: statement_hash,
            proof_full_bytes_hash: expected_proof_bytes_hash,
            proof_byte_length: proof_bytes.len(),
            chunk_size_bytes: DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
            chunk_count,
            chunk_hashes: &chunk_hashes,
            chunk_merkle_root: &chunk_merkle_root,
        })?;
    verify_direct_ballot_proof_chunk_manifest(
        &proof_chunk_manifest.value,
        &transported_proof_bytes,
    )?;
    let proof_statement = direct_ballot_validity_statement(setup_package, public_key, ballot)?;
    let encrypted_ballot_package = direct_ballot_encrypted_package(
        setup_package,
        ballot,
        &proof_statement,
        &proof_chunk_manifest,
    )?;

    Ok(DirectBallotBinaryProofTransport {
        proof_size_bytes: transported_proof_bytes.len(),
        proof_bytes: transported_proof_bytes,
        proof_bytes_hash: transported_proof_bytes_hash,
        chunk_count,
        chunk_merkle_root,
        chunk_hashes,
        proof_chunks,
        proof_chunk_manifest_root: proof_chunk_manifest.root,
        proof_chunk_manifest: proof_chunk_manifest.value,
        encrypted_ballot_package_root: encrypted_ballot_package.root,
        encrypted_ballot_package: encrypted_ballot_package.value,
        voter_signature_signed_root: encrypted_ballot_package.voter_signature_signed_root,
    })
}

pub(super) fn direct_ballot_proof_chunk_hash(
    proof_bytes_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    validate_direct_ballot_hash_hex(proof_bytes_hash, "proofBytesHash")?;
    Ok(hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/proof-chunk-v1",
        &[
            proof_bytes_hash.as_bytes(),
            &usize_to_u64(chunk_index, "proof chunk index")?.to_le_bytes(),
            chunk,
        ],
    ))
}

pub(super) fn verify_direct_ballot_public_proof_transport(
    proof_bytes: &[u8],
    expected_proof_bytes_hash: &str,
    expected_chunk_hashes: &[String],
    chunk_size_bytes: usize,
    expected_chunk_merkle_root: &str,
) -> CanonicalResult<()> {
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public proof transport requires non-empty proof bytes",
        ));
    }
    validate_direct_ballot_hash_hex(expected_proof_bytes_hash, "proofBytesHash")?;
    validate_direct_ballot_hash_hex(expected_chunk_merkle_root, "proofChunkMerkleRoot")?;
    let expected_chunk_count = chunk_count_for_bytes(proof_bytes.len(), chunk_size_bytes)?;
    if expected_chunk_hashes.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public proof transport chunk hash count does not match proof length",
        ));
    }
    validate_unique_strings(
        expected_chunk_hashes,
        "proofTransport.chunkHashes",
        "contains a duplicate chunk hash",
    )?;
    for (chunk_index, chunk) in proof_bytes.chunks(chunk_size_bytes).enumerate() {
        if chunk.is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public proof transport contains an empty chunk",
            ));
        }
        if chunk_index + 1 < expected_chunk_count && chunk.len() != chunk_size_bytes {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public proof transport contains a truncated non-final chunk",
            ));
        }
        let expected_chunk_hash = &expected_chunk_hashes[chunk_index];
        validate_direct_ballot_hash_hex(
            expected_chunk_hash,
            &format!("proofTransport.chunkHashes[{chunk_index}]"),
        )?;
        let actual_chunk_hash =
            direct_ballot_proof_chunk_hash(expected_proof_bytes_hash, chunk_index, chunk)?;
        if actual_chunk_hash != *expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("public proof transport chunk {chunk_index} hash does not match"),
            ));
        }
    }
    let actual_proof_bytes_hash = direct_ballot_relation_proof_bytes_hash(proof_bytes);
    if actual_proof_bytes_hash != expected_proof_bytes_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public proof transport full proof hash does not match",
        ));
    }
    let actual_chunk_merkle_root = chunk_root(proof_bytes, chunk_size_bytes)?;
    if actual_chunk_merkle_root != expected_chunk_merkle_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public proof transport chunk Merkle root does not match",
        ));
    }

    Ok(())
}
