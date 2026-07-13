use super::*;

pub(in crate::bgv::direct_ballots) fn generate_direct_ballot_relation_proof(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotRelationProofGeneration> {
    let statement_hash =
        direct_ballot_relation_statement_hash(setup_package, evaluator_key, ballot)?;
    let witness_vector = direct_ballot_witness_vector(ballot)?;
    let mask_vector = sample_direct_ballot_relation_mask_vector(
        &statement_hash,
        &ballot.ciphertext_root,
        proof_randomness_seed_hex,
    )?;
    let bgv_relation_commitments =
        evaluate_direct_ballot_bgv_relation_commitments(evaluator_key, &mask_vector)?;
    let score_linear_commitment = evaluate_direct_ballot_score_linear_commitment(&mask_vector)?;
    let support_commitment =
        evaluate_direct_ballot_support_commitment(&mask_vector, &witness_vector)?;
    let encoded_commitments = encode_direct_ballot_relation_commitments(
        &bgv_relation_commitments,
        &score_linear_commitment,
        &support_commitment,
    )?;
    let relation_commitment_hash =
        direct_ballot_relation_commitment_hash(&statement_hash, &encoded_commitments);
    let challenge = direct_ballot_relation_challenge(&statement_hash, &relation_commitment_hash)?;
    let response_vector =
        direct_ballot_relation_response_vector(&mask_vector, &witness_vector, &challenge)?;
    let proof_bytes = encode_direct_ballot_relation_proof(
        &statement_hash,
        &challenge,
        &encoded_commitments,
        &response_vector,
    )?;
    Ok(DirectBallotRelationProofGeneration { proof_bytes })
}
