use super::*;

pub(in crate::bgv::direct_ballots) fn generate_direct_ballot_relation_proof(
    setup_package: &Value,
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotRelationProofGeneration> {
    let statement_hash = direct_ballot_relation_statement_hash(setup_package, public_key, ballot)?;
    let witness_vector = direct_ballot_witness_vector(&statement_hash, public_key, ballot)?;
    verify_direct_ballot_committed_support_witness(&witness_vector, DATA_PRIMES[0])?;
    verify_direct_ballot_committed_linear_witness(
        &statement_hash,
        public_key,
        ballot,
        &witness_vector,
    )?;
    verify_direct_ballot_projected_bgv_relation_witness(
        &statement_hash,
        public_key,
        ballot,
        &witness_vector,
        DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
    )?;
    let committed_trace_proof_bytes = generate_direct_ballot_committed_trace_proof_bytes(
        &statement_hash,
        public_key,
        ballot,
        &witness_vector,
        proof_randomness_seed_hex,
    )?;
    let mask_vector = sample_direct_ballot_relation_mask_vector(
        &statement_hash,
        public_key,
        ballot,
        proof_randomness_seed_hex,
    )?;
    let bgv_relation_commitments = evaluate_direct_ballot_bgv_relation_commitments(
        &statement_hash,
        public_key,
        ballot,
        &mask_vector,
    )?;
    let score_linear_commitment = evaluate_direct_ballot_score_linear_commitment(&mask_vector)?;
    let encoded_commitments = encode_direct_ballot_relation_commitments(
        &bgv_relation_commitments,
        &score_linear_commitment,
    )?;
    let relation_commitment_bytes = encoded_commitments.len();
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
        &committed_trace_proof_bytes,
    )?;
    let proof_size_bytes = proof_bytes.len();
    let proof_bytes_hash = direct_ballot_relation_proof_bytes_hash(&proof_bytes);

    Ok(DirectBallotRelationProofGeneration {
        proof_bytes,
        proof_size_bytes,
        proof_bytes_hash,
        statement_hash_hex: to_hex(&statement_hash),
        relation_commitment_hash_hex: to_hex(&relation_commitment_hash),
        challenge: challenge.to_string(),
        relation_commitment_bytes,
        response_bytes: direct_ballot_relation_response_bytes(),
        relation_commitment_scalar_count: direct_ballot_projected_bgv_commitment_scalar_count()
            + direct_ballot_score_linear_commitment_scalar_count(),
        shared_response_polynomial_count: DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS,
        shared_response_scalar_count: direct_ballot_relation_response_scalar_count(),
        proof_gate: direct_ballot_relation_proof_gate(proof_size_bytes),
    })
}
