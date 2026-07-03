use super::*;

pub(super) struct DirectBallotRelationProofSummary {
    pub(super) proof_size_bytes: usize,
    pub(super) proof_bytes_hash: String,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: String,
    pub(super) relation_commitment_bytes: usize,
    pub(super) response_bytes: usize,
    pub(super) transported_proof_size_bytes: usize,
    pub(super) transported_proof_bytes_hash: String,
    pub(super) proof_chunk_count: usize,
    pub(super) proof_chunk_merkle_root: String,
    pub(super) proof_chunk_hashes: Vec<String>,
    pub(super) public_proof_transport_hash: String,
}

pub(super) struct DirectBallotBinaryProofTransport {
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_size_bytes: usize,
    pub(super) proof_bytes_hash: String,
    pub(super) chunk_count: usize,
    pub(super) chunk_merkle_root: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) public_transport_hash: String,
}

impl DirectBallotRelationProofSummary {
    pub(super) fn from_verified_proof(
        proof_generation: DirectBallotRelationProofGeneration,
        proof_transport: DirectBallotBinaryProofTransport,
    ) -> Self {
        Self {
            proof_size_bytes: proof_generation.proof_size_bytes,
            proof_bytes_hash: proof_generation.proof_bytes_hash,
            statement_hash_hex: proof_generation.statement_hash_hex,
            relation_commitment_hash_hex: proof_generation.relation_commitment_hash_hex,
            challenge: proof_generation.challenge,
            relation_commitment_bytes: proof_generation.relation_commitment_bytes,
            response_bytes: proof_generation.response_bytes,
            transported_proof_size_bytes: proof_transport.proof_size_bytes,
            transported_proof_bytes_hash: proof_transport.proof_bytes_hash,
            proof_chunk_count: proof_transport.chunk_count,
            proof_chunk_merkle_root: proof_transport.chunk_merkle_root,
            proof_chunk_hashes: proof_transport.chunk_hashes,
            public_proof_transport_hash: proof_transport.public_transport_hash,
        }
    }
}
