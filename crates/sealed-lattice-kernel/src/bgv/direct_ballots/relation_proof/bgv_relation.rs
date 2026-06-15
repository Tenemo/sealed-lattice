use super::*;

pub(super) struct DirectBallotRelationResponseVerificationInput<'a> {
    pub(super) statement_hash: &'a [u8; 64],
    pub(super) public_key: &'a BgvPublicKey,
    pub(super) ballot: &'a DirectEncryptedBallot,
    pub(super) challenge: &'a BigInt,
    pub(super) bgv_relation_commitments: &'a [DirectBallotBgvRelationCommitment],
    pub(super) score_linear_commitment: &'a DirectBallotScoreLinearCommitment,
    pub(super) support_commitment: &'a DirectBallotSupportCommitment,
    pub(super) response_vector: &'a DirectBallotWitnessVector,
}

pub(super) fn evaluate_direct_ballot_bgv_relation_commitments(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<DirectBallotBgvRelationCommitment>> {
    evaluate_direct_ballot_projected_bgv_relation_commitments(
        statement_hash,
        public_key,
        ballot,
        witness_vector,
    )
}

pub(super) fn verify_direct_ballot_relation_response(
    input: DirectBallotRelationResponseVerificationInput<'_>,
) -> CanonicalResult<()> {
    verify_direct_ballot_score_linear_response(
        input.challenge,
        input.score_linear_commitment,
        input.response_vector,
    )?;
    verify_direct_ballot_support_response(
        input.statement_hash,
        input.challenge,
        input.support_commitment,
        input.response_vector,
    )?;
    verify_direct_ballot_projected_bgv_relation_response(
        input.statement_hash,
        input.public_key,
        input.ballot,
        input.challenge,
        input.bgv_relation_commitments,
        input.response_vector,
    )
}
