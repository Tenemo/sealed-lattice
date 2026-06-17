use super::*;

pub(super) fn evaluate_direct_ballot_score_linear_commitment(
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<DirectBallotScoreLinearCommitment> {
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let mut bucket_sums = Vec::with_capacity(DIRECT_BALLOT_OPTION_COUNT);
    let mut weighted_differences = Vec::with_capacity(DIRECT_BALLOT_OPTION_COUNT);
    for option_index in 0..DIRECT_BALLOT_OPTION_COUNT {
        let mut bucket_sum = BigInt::zero();
        let mut weighted_sum = BigInt::zero();
        for bucket_index in 0..DIRECT_BALLOT_SCORE_BUCKET_COUNT {
            let bucket_value = &witness_vector.one_hot_coefficients[option_index][bucket_index];
            bucket_sum += bucket_value;
            weighted_sum += BigInt::from(bucket_index + 1) * bucket_value;
        }
        let score_value = &witness_vector.score_coefficients[option_index];
        bucket_sums.push(bucket_sum);
        weighted_differences.push(score_value - weighted_sum);
    }

    Ok(DirectBallotScoreLinearCommitment {
        bucket_sums,
        weighted_differences,
    })
}

pub(super) fn verify_direct_ballot_score_linear_response(
    challenge: &BigInt,
    score_linear_commitment: &DirectBallotScoreLinearCommitment,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    let response_commitment = evaluate_direct_ballot_score_linear_commitment(response_vector)?;
    if score_linear_commitment.bucket_sums.len() != DIRECT_BALLOT_OPTION_COUNT
        || score_linear_commitment.weighted_differences.len() != DIRECT_BALLOT_OPTION_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot score linear commitment has the wrong option count",
        ));
    }
    for option_index in 0..DIRECT_BALLOT_OPTION_COUNT {
        let checked_bucket_sum = &response_commitment.bucket_sums[option_index] - challenge;
        if checked_bucket_sum != score_linear_commitment.bucket_sums[option_index] {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot score proof option {option_index} exact one-hot sum response does not match the committed mask"
            )));
        }
        if response_commitment.weighted_differences[option_index]
            != score_linear_commitment.weighted_differences[option_index]
        {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot score proof option {option_index} exact weighted score response does not match the committed mask"
            )));
        }
    }

    Ok(())
}
