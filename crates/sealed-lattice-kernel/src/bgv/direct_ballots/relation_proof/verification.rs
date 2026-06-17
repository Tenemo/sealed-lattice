use super::*;

pub(in crate::bgv::direct_ballots) fn verify_direct_ballot_relation_proof(
    setup_package: &Value,
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    proof_bytes: &[u8],
) -> CanonicalResult<DirectBallotRelationProofVerification> {
    let expected_statement_hash =
        direct_ballot_relation_statement_hash(setup_package, public_key, ballot)?;
    let parsed_proof = parse_direct_ballot_relation_proof(proof_bytes, &expected_statement_hash)?;
    verify_direct_ballot_relation_response(DirectBallotRelationResponseVerificationInput {
        statement_hash: &expected_statement_hash,
        public_key,
        ballot,
        challenge: &parsed_proof.challenge,
        bgv_relation_commitments: &parsed_proof.bgv_relation_commitments,
        score_linear_commitment: &parsed_proof.score_linear_commitment,
        response_vector: &parsed_proof.response_vector,
    })?;
    verify_direct_ballot_committed_trace_proof_bytes(
        &expected_statement_hash,
        public_key,
        ballot,
        &parsed_proof.committed_trace_proof_bytes,
    )?;

    Ok(DirectBallotRelationProofVerification {
        proof_size_bytes: proof_bytes.len(),
        statement_hash_hex: to_hex(&expected_statement_hash),
        relation_commitment_hash_hex: to_hex(&parsed_proof.relation_commitment_hash),
        challenge: parsed_proof.challenge.to_string(),
    })
}
