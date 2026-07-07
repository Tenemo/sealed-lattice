use super::*;

use crate::hashing::derive_canonical_object_hash;

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
    ballot: &DirectEncryptedBallot,
    statement_hash: &str,
    proof_bytes: &[u8],
    expected_proof_bytes_hash: &str,
    proof_bytes_hash: fn(&[u8]) -> String,
    label: &str,
) -> CanonicalResult<DirectBallotBinaryProofTransport> {
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} transport requires non-empty binary proof bytes"),
        ));
    }
    let chunk_count = chunk_count_for_bytes(proof_bytes.len(), PROTOTYPE_PROOF_CHUNK_BYTES)?;
    let mut transported_proof_bytes = Vec::with_capacity(proof_bytes.len());
    let mut chunk_hashes = Vec::with_capacity(chunk_count);
    let mut observed_chunk_count = 0_usize;
    for (chunk_index, chunk) in proof_bytes.chunks(PROTOTYPE_PROOF_CHUNK_BYTES).enumerate() {
        if chunk.is_empty() || chunk.len() > PROTOTYPE_PROOF_CHUNK_BYTES {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} transport produced a malformed chunk"),
            ));
        }
        if chunk_index + 1 < chunk_count && chunk.len() != PROTOTYPE_PROOF_CHUNK_BYTES {
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
        chunk_hashes.push(direct_ballot_proof_chunk_hash(
            expected_proof_bytes_hash,
            chunk_index,
            chunk,
        )?);
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
    let chunk_merkle_root = chunk_root(&transported_proof_bytes, PROTOTYPE_PROOF_CHUNK_BYTES)?;
    verify_direct_ballot_public_proof_transport(
        &transported_proof_bytes,
        expected_proof_bytes_hash,
        &chunk_hashes,
        PROTOTYPE_PROOF_CHUNK_BYTES,
        &chunk_merkle_root,
    )?;
    let public_transport_hash =
        direct_ballot_public_proof_transport_hash(DirectBallotPublicProofTransportHashInput {
            setup_package,
            ballot,
            statement_hash,
            proof_bytes_hash: expected_proof_bytes_hash,
            proof_byte_length: proof_bytes.len(),
            chunk_count,
            chunk_hashes: &chunk_hashes,
            chunk_merkle_root: &chunk_merkle_root,
        })?;

    Ok(DirectBallotBinaryProofTransport {
        proof_size_bytes: transported_proof_bytes.len(),
        proof_bytes: transported_proof_bytes,
        proof_bytes_hash: transported_proof_bytes_hash,
        chunk_count,
        chunk_merkle_root,
        chunk_hashes,
        public_transport_hash,
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

pub(super) struct DirectBallotPublicProofTransportHashInput<'a> {
    setup_package: &'a Value,
    ballot: &'a DirectEncryptedBallot,
    statement_hash: &'a str,
    proof_bytes_hash: &'a str,
    proof_byte_length: usize,
    chunk_count: usize,
    chunk_hashes: &'a [String],
    chunk_merkle_root: &'a str,
}

pub(super) fn direct_ballot_public_proof_transport_hash(
    input: DirectBallotPublicProofTransportHashInput<'_>,
) -> CanonicalResult<String> {
    validate_direct_ballot_hash_hex(input.statement_hash, "statementHash")?;
    validate_direct_ballot_hash_hex(input.proof_bytes_hash, "proofBytesHash")?;
    validate_direct_ballot_hash_hex(input.chunk_merkle_root, "proofChunkMerkleRoot")?;
    let collective_public_key_root = required_string_path(
        input.setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?;
    let proof_parameters_hash = direct_ballot_relation_proof_parameters_hash()?;

    derive_canonical_object_hash(&json!({
        "objectType": "DirectEncryptedBallotProofTransport",
        "proofByteLength": input.proof_byte_length,
        "chunkCount": input.chunk_count,
        "chunkHashes": input.chunk_hashes,
        "chunkMerkleRoot": input.chunk_merkle_root,
        "fullProofHash": input.proof_bytes_hash,
        "statementHash": input.statement_hash,
        "ciphertextRoot": input.ballot.ciphertext_root,
        "voterIdentity": input.ballot.input.voter_identity,
        "actionContextHash": input.ballot.input.action_context_hash,
        "bgvParametersHash": bgv_parameters_hash()?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "proofParametersHash": proof_parameters_hash,
    }))
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
