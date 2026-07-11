use super::*;

pub(super) fn evaluate_direct_ballot_support_commitment(
    mask_vector: &DirectBallotWitnessVector,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<DirectBallotSupportCommitment> {
    validate_direct_ballot_witness_vector_shape(mask_vector)?;
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let modulus = direct_ballot_support_modulus();
    let mut one_hot_booleanity = Vec::with_capacity(
        OPTION_COUNT * SCORE_BUCKET_COUNT * ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS,
    );
    for (mask_row, witness_row) in mask_vector
        .one_hot_coefficients
        .iter()
        .zip(witness_vector.one_hot_coefficients.iter())
    {
        for (mask, witness) in mask_row.iter().zip(witness_row.iter()) {
            one_hot_booleanity.extend(support_expansion_coefficients(
                DirectBallotSupportKind::OneHot,
                signed_bigint_residue(mask, modulus)?,
                signed_bigint_residue(witness, modulus)?,
                modulus,
            )?);
        }
    }

    Ok(DirectBallotSupportCommitment {
        one_hot_booleanity,
        randomizer_support: support_expansion_commitments_for_polynomial(
            DirectBallotSupportKind::Randomizer,
            &mask_vector.randomizer_coefficients,
            &witness_vector.randomizer_coefficients,
            modulus,
        )?,
        error_zero_support: support_expansion_commitments_for_polynomial(
            DirectBallotSupportKind::Error,
            &mask_vector.error_zero_coefficients,
            &witness_vector.error_zero_coefficients,
            modulus,
        )?,
        error_one_support: support_expansion_commitments_for_polynomial(
            DirectBallotSupportKind::Error,
            &mask_vector.error_one_coefficients,
            &witness_vector.error_one_coefficients,
            modulus,
        )?,
    })
}

pub(super) fn support_expansion_commitments_for_polynomial(
    support_kind: DirectBallotSupportKind,
    mask_polynomial: &[BigInt],
    witness_polynomial: &[BigInt],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if mask_polynomial.len() != POLYNOMIAL_DEGREE || witness_polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment polynomials must match the BGV degree",
        ));
    }
    let mut commitments =
        Vec::with_capacity(POLYNOMIAL_DEGREE * support_kind.expansion_coefficient_count());
    for (mask, witness) in mask_polynomial.iter().zip(witness_polynomial.iter()) {
        commitments.extend(support_expansion_coefficients(
            support_kind,
            signed_bigint_residue(mask, modulus)?,
            signed_bigint_residue(witness, modulus)?,
            modulus,
        )?);
    }

    Ok(commitments)
}

pub(super) fn verify_direct_ballot_support_response(
    challenge: &BigInt,
    support_commitment: &DirectBallotSupportCommitment,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    validate_direct_ballot_witness_vector_shape(response_vector)?;
    validate_direct_ballot_support_commitment_shape(support_commitment)?;
    let modulus = direct_ballot_support_modulus();
    let challenge_residue = challenge_residue(challenge, modulus)?;
    for (option_index, row) in response_vector.one_hot_coefficients.iter().enumerate() {
        let commitment_offset = option_index
            .checked_mul(SCORE_BUCKET_COUNT)
            .and_then(|offset| offset.checked_mul(ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS))
            .ok_or_else(|| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot one-hot support commitment offset overflowed",
                )
            })?;
        verify_support_response_polynomial(
            &format!("one-hot Booleanity option {option_index}"),
            DirectBallotSupportKind::OneHot,
            row,
            &support_commitment.one_hot_booleanity[commitment_offset
                ..commitment_offset + SCORE_BUCKET_COUNT * ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS],
            challenge_residue,
            modulus,
        )?;
    }
    verify_support_response_polynomial(
        "randomizer",
        DirectBallotSupportKind::Randomizer,
        &response_vector.randomizer_coefficients,
        &support_commitment.randomizer_support,
        challenge_residue,
        modulus,
    )?;
    verify_support_response_polynomial(
        "first error",
        DirectBallotSupportKind::Error,
        &response_vector.error_zero_coefficients,
        &support_commitment.error_zero_support,
        challenge_residue,
        modulus,
    )?;
    verify_support_response_polynomial(
        "second error",
        DirectBallotSupportKind::Error,
        &response_vector.error_one_coefficients,
        &support_commitment.error_one_support,
        challenge_residue,
        modulus,
    )
}

pub(super) fn verify_support_response_polynomial(
    label: &str,
    support_kind: DirectBallotSupportKind,
    response_coefficients: &[BigInt],
    expansion_commitments: &[u64],
    challenge_residue: u64,
    modulus: u64,
) -> CanonicalResult<()> {
    let expansion_coefficient_count = support_kind.expansion_coefficient_count();
    if expansion_commitments.len() != response_coefficients.len() * expansion_coefficient_count {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot {label} commitment has the wrong length"
        )));
    }
    for (coefficient_index, (response, expansion)) in response_coefficients
        .iter()
        .zip(expansion_commitments.chunks_exact(expansion_coefficient_count))
        .enumerate()
    {
        let response_residue = signed_bigint_residue(response, modulus)?;
        let support_value =
            support_polynomial_value(support_kind, response_residue, challenge_residue, modulus)?;
        let mut expanded_support_value = 0_u64;
        let mut challenge_power = 1_u64;
        for commitment in expansion {
            expanded_support_value = add_mod(
                expanded_support_value,
                mul_mod(*commitment, challenge_power, modulus)?,
                modulus,
            )?;
            challenge_power = mul_mod(challenge_power, challenge_residue, modulus)?;
        }
        if support_value != expanded_support_value {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot {label} support check failed at coefficient {coefficient_index}"
            )));
        }
    }

    Ok(())
}

pub(super) fn support_expansion_coefficients(
    support_kind: DirectBallotSupportKind,
    mask: u64,
    witness: u64,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mask_power = powers(mask, 5, modulus)?;
    let witness_power = powers(witness, 5, modulus)?;
    match support_kind {
        DirectBallotSupportKind::OneHot => Ok(vec![
            mask_power[2],
            sub_mod(
                mul_mod(2 % modulus, mul_mod(mask, witness, modulus)?, modulus)?,
                mask,
                modulus,
            )?,
        ]),
        DirectBallotSupportKind::Randomizer => Ok(vec![
            mask_power[3],
            mul_mod(
                3 % modulus,
                mul_mod(mask_power[2], witness, modulus)?,
                modulus,
            )?,
            sub_mod(
                mul_mod(
                    3 % modulus,
                    mul_mod(mask, witness_power[2], modulus)?,
                    modulus,
                )?,
                mask,
                modulus,
            )?,
        ]),
        DirectBallotSupportKind::Error => Ok(vec![
            mask_power[5],
            mul_mod(
                5 % modulus,
                mul_mod(mask_power[4], witness, modulus)?,
                modulus,
            )?,
            sub_mod(
                mul_mod(
                    10 % modulus,
                    mul_mod(mask_power[3], witness_power[2], modulus)?,
                    modulus,
                )?,
                mul_mod(5 % modulus, mask_power[3], modulus)?,
                modulus,
            )?,
            sub_mod(
                mul_mod(
                    10 % modulus,
                    mul_mod(mask_power[2], witness_power[3], modulus)?,
                    modulus,
                )?,
                mul_mod(
                    15 % modulus,
                    mul_mod(mask_power[2], witness, modulus)?,
                    modulus,
                )?,
                modulus,
            )?,
            add_mod(
                sub_mod(
                    mul_mod(
                        5 % modulus,
                        mul_mod(mask, witness_power[4], modulus)?,
                        modulus,
                    )?,
                    mul_mod(
                        15 % modulus,
                        mul_mod(mask, witness_power[2], modulus)?,
                        modulus,
                    )?,
                    modulus,
                )?,
                mul_mod(4 % modulus, mask, modulus)?,
                modulus,
            )?,
        ]),
    }
}

pub(super) fn support_polynomial_value(
    support_kind: DirectBallotSupportKind,
    value: u64,
    homogenizing_value: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    let value_power = powers(value, 5, modulus)?;
    let homogenizing_power = powers(homogenizing_value, 5, modulus)?;
    match support_kind {
        DirectBallotSupportKind::OneHot => sub_mod(
            value_power[2],
            mul_mod(value, homogenizing_value, modulus)?,
            modulus,
        ),
        DirectBallotSupportKind::Randomizer => sub_mod(
            value_power[3],
            mul_mod(value, homogenizing_power[2], modulus)?,
            modulus,
        ),
        DirectBallotSupportKind::Error => add_mod(
            sub_mod(
                value_power[5],
                mul_mod(
                    mul_mod(5 % modulus, value_power[3], modulus)?,
                    homogenizing_power[2],
                    modulus,
                )?,
                modulus,
            )?,
            mul_mod(
                mul_mod(4 % modulus, value, modulus)?,
                homogenizing_power[4],
                modulus,
            )?,
            modulus,
        ),
    }
}

pub(super) fn powers(value: u64, highest_power: usize, modulus: u64) -> CanonicalResult<Vec<u64>> {
    let mut powers = vec![1_u64; highest_power + 1];
    for power_index in 1..=highest_power {
        powers[power_index] = mul_mod(powers[power_index - 1], value, modulus)?;
    }

    Ok(powers)
}

impl DirectBallotSupportKind {
    fn expansion_coefficient_count(self) -> usize {
        match self {
            Self::OneHot => ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS,
            Self::Randomizer => RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS,
            Self::Error => ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        }
    }
}

pub(super) fn direct_ballot_support_modulus() -> u64 {
    DATA_PRIMES[0]
}
