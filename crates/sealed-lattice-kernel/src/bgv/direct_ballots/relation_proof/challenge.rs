use super::*;

pub(super) fn direct_ballot_relation_response_vector(
    mask_vector: &DirectBallotWitnessVector,
    witness_vector: &DirectBallotWitnessVector,
    challenge: &BigInt,
) -> CanonicalResult<DirectBallotWitnessVector> {
    validate_direct_ballot_witness_vector_shape(mask_vector)?;
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: response_polynomial(
            &mask_vector.randomizer_coefficients,
            &witness_vector.randomizer_coefficients,
            challenge,
            "direct ballot relation randomizer response",
        )?,
        error_zero_coefficients: response_polynomial(
            &mask_vector.error_zero_coefficients,
            &witness_vector.error_zero_coefficients,
            challenge,
            "direct ballot relation first error response",
        )?,
        error_one_coefficients: response_polynomial(
            &mask_vector.error_one_coefficients,
            &witness_vector.error_one_coefficients,
            challenge,
            "direct ballot relation second error response",
        )?,
        encoding_carry_coefficients: response_polynomial(
            &mask_vector.encoding_carry_coefficients,
            &witness_vector.encoding_carry_coefficients,
            challenge,
            "direct ballot relation encoding carry response",
        )?,
        score_coefficients: response_polynomial(
            &mask_vector.score_coefficients,
            &witness_vector.score_coefficients,
            challenge,
            "direct ballot relation score response",
        )?,
        one_hot_coefficients: mask_vector
            .one_hot_coefficients
            .iter()
            .zip(witness_vector.one_hot_coefficients.iter())
            .enumerate()
            .map(|(option_index, (mask_row, witness_row))| {
                response_polynomial(
                    mask_row,
                    witness_row,
                    challenge,
                    &format!("direct ballot relation option {option_index} one-hot response"),
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

pub(super) fn response_polynomial(
    mask_polynomial: &[BigInt],
    witness_polynomial: &[BigInt],
    challenge: &BigInt,
    label: &str,
) -> CanonicalResult<Vec<BigInt>> {
    if mask_polynomial.len() != witness_polynomial.len() {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} mask and witness lengths must match"
        )));
    }
    if mask_polynomial.is_empty() {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must not be empty"
        )));
    }
    mask_polynomial
        .iter()
        .zip(witness_polynomial.iter())
        .map(|(mask_coefficient, witness_coefficient)| {
            let response = mask_coefficient + challenge * witness_coefficient;
            validate_signed_bigint_fixed_width(&response, label)?;
            Ok(response)
        })
        .collect()
}

pub(super) fn direct_ballot_relation_challenge(
    statement_hash: &[u8; 64],
    relation_commitment_hash: &[u8; 64],
) -> CanonicalResult<BigInt> {
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            "sealed-lattice/direct-encrypted-ballot/relation-challenge",
            &[statement_hash, relation_commitment_hash, &block_index_bytes],
        );
        let challenge_bytes = &block[..RELATION_PROOF_CHALLENGE_BYTES];
        let challenge = BigInt::from_bytes_le(Sign::Plus, challenge_bytes);
        if !challenge.is_zero() {
            return Ok(challenge);
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot relation challenge block index overflowed",
            )
        })?;
    }
}
