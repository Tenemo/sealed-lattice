use super::*;

pub(in crate::bgv::direct_ballots) fn verify_direct_ballot_relation_proof(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
    proof_bytes: &[u8],
) -> CanonicalResult<DirectBallotRelationProofVerification> {
    let expected_statement_hash =
        direct_ballot_relation_statement_hash(setup_package, evaluator_key, ballot)?;
    let parsed_proof = parse_direct_ballot_relation_proof(proof_bytes, &expected_statement_hash)?;
    verify_direct_ballot_relation_response(
        evaluator_key,
        ballot,
        &parsed_proof.challenge,
        &parsed_proof.bgv_relation_commitments,
        &parsed_proof.score_linear_commitment,
        &parsed_proof.support_commitment,
        &parsed_proof.response_vector,
    )?;

    Ok(DirectBallotRelationProofVerification {
        proof_size_bytes: proof_bytes.len(),
        statement_hash_hex: to_hex(&expected_statement_hash),
        relation_commitment_hash_hex: to_hex(&parsed_proof.relation_commitment_hash),
        challenge: parsed_proof.challenge.to_string(),
    })
}
