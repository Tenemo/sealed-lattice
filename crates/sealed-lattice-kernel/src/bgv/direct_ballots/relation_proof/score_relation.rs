use super::*;

pub(super) fn evaluate_direct_ballot_score_linear_commitment(
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<DirectBallotScoreLinearCommitment> {
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let mut bucket_sums = Vec::with_capacity(OPTION_COUNT);
    let mut weighted_differences = Vec::with_capacity(OPTION_COUNT);
    for option_index in 0..OPTION_COUNT {
        let mut bucket_sum = 0_u64;
        let mut weighted_sum = 0_u64;
        for bucket_index in 0..SCORE_BUCKET_COUNT {
            let bucket_residue = signed_bigint_residue(
                &witness_vector.one_hot_coefficients[option_index][bucket_index],
                PLAINTEXT_MODULUS,
            )?;
            bucket_sum = add_mod(bucket_sum, bucket_residue, PLAINTEXT_MODULUS)?;
            let bucket_weight = u64::try_from(bucket_index + 1)
                .expect("score bucket weight fits u64")
                % PLAINTEXT_MODULUS;
            weighted_sum = add_mod(
                weighted_sum,
                mul_mod(bucket_weight, bucket_residue, PLAINTEXT_MODULUS)?,
                PLAINTEXT_MODULUS,
            )?;
        }
        let score_residue = signed_bigint_residue(
            &witness_vector.score_coefficients[option_index],
            PLAINTEXT_MODULUS,
        )?;
        bucket_sums.push(bucket_sum);
        weighted_differences.push(sub_mod(score_residue, weighted_sum, PLAINTEXT_MODULUS)?);
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
    if score_linear_commitment.bucket_sums.len() != OPTION_COUNT
        || score_linear_commitment.weighted_differences.len() != OPTION_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot score linear commitment has the wrong option count",
        ));
    }
    let challenge_residue = challenge_residue(challenge, PLAINTEXT_MODULUS)?;
    for option_index in 0..OPTION_COUNT {
        let checked_bucket_sum = sub_mod(
            response_commitment.bucket_sums[option_index],
            challenge_residue,
            PLAINTEXT_MODULUS,
        )?;
        if checked_bucket_sum != score_linear_commitment.bucket_sums[option_index] {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot score proof option {option_index} one-hot sum response does not match the public statement"
            )));
        }
        if response_commitment.weighted_differences[option_index]
            != score_linear_commitment.weighted_differences[option_index]
        {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot score proof option {option_index} weighted score response does not match the public statement"
            )));
        }
    }

    Ok(())
}
