use super::*;

#[test]
fn direct_ballot_public_proof_transport_rejects_wrong_chunk_hash() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
        "direct ballot relation proof",
    )
    .expect("proof transport");
    let mut chunk_hashes = transport.chunk_hashes.clone();
    chunk_hashes[0] = "0".repeat(128);

    let error = verify_direct_ballot_public_proof_transport(
        &transport.proof_bytes,
        &transport.proof_bytes_hash,
        &chunk_hashes,
        PROTOTYPE_PROOF_CHUNK_BYTES,
        &transport.chunk_merkle_root,
    )
    .expect_err("wrong chunk hash must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("chunk 0 hash does not match"));
}

#[test]
fn direct_ballot_public_proof_transport_rejects_duplicate_chunk_hash() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
        "direct ballot relation proof",
    )
    .expect("proof transport");
    let mut chunk_hashes = transport.chunk_hashes.clone();
    chunk_hashes[1] = chunk_hashes[0].clone();

    let error = verify_direct_ballot_public_proof_transport(
        &transport.proof_bytes,
        &transport.proof_bytes_hash,
        &chunk_hashes,
        PROTOTYPE_PROOF_CHUNK_BYTES,
        &transport.chunk_merkle_root,
    )
    .expect_err("duplicate chunk hash must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("contains a duplicate chunk hash"));
}

#[test]
fn direct_ballot_public_proof_transport_rejects_truncated_proof_bytes() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
        "direct ballot relation proof",
    )
    .expect("proof transport");
    let truncated_len = transport
        .proof_bytes
        .len()
        .checked_sub(1)
        .expect("proof has bytes");

    let error = verify_direct_ballot_public_proof_transport(
        &transport.proof_bytes[..truncated_len],
        &transport.proof_bytes_hash,
        &transport.chunk_hashes,
        PROTOTYPE_PROOF_CHUNK_BYTES,
        &transport.chunk_merkle_root,
    )
    .expect_err("truncated proof bytes must reject");

    assert!(
        error
            .message
            .contains("chunk hash count does not match proof length")
            || error.message.contains("chunk 17 hash does not match")
            || error.message.contains("full proof hash does not match")
            || error.message.contains("chunk Merkle root does not match")
    );
}
