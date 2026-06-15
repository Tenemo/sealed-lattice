use super::*;

const DIRECT_BALLOT_SUPPORT_PROJECTION_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/support-projection-v1";

pub(super) fn evaluate_direct_ballot_support_commitment(
    statement_hash: &[u8; 64],
    mask_vector: &DirectBallotWitnessVector,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<DirectBallotSupportCommitment> {
    validate_direct_ballot_witness_vector_shape(mask_vector)?;
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let mask_one_hot_entries = flattened_one_hot_entries(&mask_vector.one_hot_coefficients);
    let witness_one_hot_entries = flattened_one_hot_entries(&witness_vector.one_hot_coefficients);

    Ok(DirectBallotSupportCommitment {
        one_hot_booleanity: projected_support_commitments_for_entries(
            statement_hash,
            DirectBallotSupportPartition::OneHotBooleanity,
            DirectBallotSupportKind::OneHot,
            &mask_one_hot_entries,
            &witness_one_hot_entries,
        )?,
        randomizer_support: projected_support_commitments_for_polynomial(
            statement_hash,
            DirectBallotSupportPartition::Randomizer,
            DirectBallotSupportKind::Randomizer,
            &mask_vector.randomizer_coefficients,
            &witness_vector.randomizer_coefficients,
        )?,
        error_zero_support: projected_support_commitments_for_polynomial(
            statement_hash,
            DirectBallotSupportPartition::ErrorZero,
            DirectBallotSupportKind::Error,
            &mask_vector.error_zero_coefficients,
            &witness_vector.error_zero_coefficients,
        )?,
        error_one_support: projected_support_commitments_for_polynomial(
            statement_hash,
            DirectBallotSupportPartition::ErrorOne,
            DirectBallotSupportKind::Error,
            &mask_vector.error_one_coefficients,
            &witness_vector.error_one_coefficients,
        )?,
    })
}

pub(super) fn projected_support_commitments_for_entries(
    statement_hash: &[u8; 64],
    support_partition: DirectBallotSupportPartition,
    support_kind: DirectBallotSupportKind,
    mask_entries: &[&BigInt],
    witness_entries: &[&BigInt],
) -> CanonicalResult<Vec<u64>> {
    if mask_entries.len() != witness_entries.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected support commitment entries must have matching lengths",
        ));
    }
    let expansion_coefficient_count = support_kind.expansion_coefficient_count();
    let mut commitments = Vec::with_capacity(
        direct_ballot_support_moduli().len()
            * DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION
            * expansion_coefficient_count,
    );
    for (support_modulus_index, modulus) in
        direct_ballot_support_moduli().iter().copied().enumerate()
    {
        for projection_index in 0..DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION {
            let mut projected_coefficients = vec![0_u64; expansion_coefficient_count];
            for (coefficient_index, (mask, witness)) in
                mask_entries.iter().zip(witness_entries.iter()).enumerate()
            {
                let projection_weight = sample_direct_ballot_support_projection_weight(
                    statement_hash,
                    support_partition,
                    support_modulus_index,
                    projection_index,
                    coefficient_index,
                    modulus,
                )?;
                let expansion = support_expansion_coefficients(
                    support_kind,
                    signed_bigint_residue(mask, modulus)?,
                    signed_bigint_residue(witness, modulus)?,
                    modulus,
                )?;
                for (projected_coefficient, expansion_coefficient) in
                    projected_coefficients.iter_mut().zip(expansion.iter())
                {
                    *projected_coefficient = add_mod(
                        *projected_coefficient,
                        mul_mod(projection_weight, *expansion_coefficient, modulus)?,
                        modulus,
                    )?;
                }
            }
            commitments.extend(projected_coefficients);
        }
    }

    Ok(commitments)
}

pub(super) fn projected_support_commitments_for_polynomial(
    statement_hash: &[u8; 64],
    support_partition: DirectBallotSupportPartition,
    support_kind: DirectBallotSupportKind,
    mask_polynomial: &[BigInt],
    witness_polynomial: &[BigInt],
) -> CanonicalResult<Vec<u64>> {
    if mask_polynomial.len() != POLYNOMIAL_DEGREE || witness_polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment polynomials must match the BGV degree",
        ));
    }
    let mask_entries = mask_polynomial.iter().collect::<Vec<_>>();
    let witness_entries = witness_polynomial.iter().collect::<Vec<_>>();
    projected_support_commitments_for_entries(
        statement_hash,
        support_partition,
        support_kind,
        &mask_entries,
        &witness_entries,
    )
}

pub(super) fn verify_direct_ballot_support_response(
    statement_hash: &[u8; 64],
    challenge: &BigInt,
    support_commitment: &DirectBallotSupportCommitment,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    validate_direct_ballot_witness_vector_shape(response_vector)?;
    validate_direct_ballot_support_commitment_shape(support_commitment)?;
    let response_one_hot_entries = flattened_one_hot_entries(&response_vector.one_hot_coefficients);
    verify_projected_support_response(
        statement_hash,
        "one-hot Booleanity",
        DirectBallotSupportPartition::OneHotBooleanity,
        DirectBallotSupportKind::OneHot,
        &response_one_hot_entries,
        &support_commitment.one_hot_booleanity,
        challenge,
    )?;
    verify_projected_support_response(
        statement_hash,
        "randomizer",
        DirectBallotSupportPartition::Randomizer,
        DirectBallotSupportKind::Randomizer,
        &response_vector
            .randomizer_coefficients
            .iter()
            .collect::<Vec<_>>(),
        &support_commitment.randomizer_support,
        challenge,
    )?;
    verify_projected_support_response(
        statement_hash,
        "first error",
        DirectBallotSupportPartition::ErrorZero,
        DirectBallotSupportKind::Error,
        &response_vector
            .error_zero_coefficients
            .iter()
            .collect::<Vec<_>>(),
        &support_commitment.error_zero_support,
        challenge,
    )?;
    verify_projected_support_response(
        statement_hash,
        "second error",
        DirectBallotSupportPartition::ErrorOne,
        DirectBallotSupportKind::Error,
        &response_vector
            .error_one_coefficients
            .iter()
            .collect::<Vec<_>>(),
        &support_commitment.error_one_support,
        challenge,
    )
}

pub(super) fn verify_projected_support_response(
    statement_hash: &[u8; 64],
    label: &str,
    support_partition: DirectBallotSupportPartition,
    support_kind: DirectBallotSupportKind,
    response_coefficients: &[&BigInt],
    projected_commitments: &[u64],
    challenge: &BigInt,
) -> CanonicalResult<()> {
    let expansion_coefficient_count = support_kind.expansion_coefficient_count();
    let expected_commitment_count = direct_ballot_support_moduli().len()
        * DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION
        * expansion_coefficient_count;
    if projected_commitments.len() != expected_commitment_count {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot {label} commitment has the wrong length"
        )));
    }
    for (support_modulus_index, modulus) in
        direct_ballot_support_moduli().iter().copied().enumerate()
    {
        let challenge_residue = challenge_residue(challenge, modulus)?;
        if challenge_residue == 0 {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot {label} support challenge is zero modulo support field {support_modulus_index}"
            )));
        }
        let modulus_offset = support_modulus_index
            * DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION
            * expansion_coefficient_count;
        let modulus_commitments = &projected_commitments[modulus_offset
            ..modulus_offset
                + DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION * expansion_coefficient_count];
        for (projection_index, projected_commitment) in modulus_commitments
            .chunks_exact(expansion_coefficient_count)
            .enumerate()
        {
            let mut projected_support_value = 0_u64;
            for (coefficient_index, response) in response_coefficients.iter().enumerate() {
                let projection_weight = sample_direct_ballot_support_projection_weight(
                    statement_hash,
                    support_partition,
                    support_modulus_index,
                    projection_index,
                    coefficient_index,
                    modulus,
                )?;
                let response_residue = signed_bigint_residue(response, modulus)?;
                let support_value = support_polynomial_value(
                    support_kind,
                    response_residue,
                    challenge_residue,
                    modulus,
                )?;
                projected_support_value = add_mod(
                    projected_support_value,
                    mul_mod(projection_weight, support_value, modulus)?,
                    modulus,
                )?;
            }
            let mut expanded_support_value = 0_u64;
            let mut challenge_power = 1_u64;
            for commitment in projected_commitment {
                expanded_support_value = add_mod(
                    expanded_support_value,
                    mul_mod(*commitment, challenge_power, modulus)?,
                    modulus,
                )?;
                challenge_power = mul_mod(challenge_power, challenge_residue, modulus)?;
            }
            if projected_support_value != expanded_support_value {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot {label} projected support check failed at support field {support_modulus_index} projection {projection_index}"
                )));
            }
        }
    }

    Ok(())
}

fn flattened_one_hot_entries(rows: &[Vec<BigInt>]) -> Vec<&BigInt> {
    rows.iter().flat_map(|row| row.iter()).collect()
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
    pub(super) fn expansion_coefficient_count(self) -> usize {
        match self {
            Self::OneHot => DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS,
            Self::Randomizer => DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS,
            Self::Error => DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        }
    }
}

impl DirectBallotSupportPartition {
    fn domain_tag(self) -> &'static [u8] {
        match self {
            Self::OneHotBooleanity => b"one-hot-booleanity",
            Self::Randomizer => b"randomizer",
            Self::ErrorZero => b"first-error",
            Self::ErrorOne => b"second-error",
        }
    }
}

fn sample_direct_ballot_support_projection_weight(
    statement_hash: &[u8; 64],
    support_partition: DirectBallotSupportPartition,
    support_modulus_index: usize,
    projection_index: usize,
    coefficient_index: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    if modulus <= 2 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support projection modulus must be greater than two",
        ));
    }
    let support_modulus_index_bytes = usize_to_u64_bytes(support_modulus_index)?;
    let projection_index_bytes = usize_to_u64_bytes(projection_index)?;
    let coefficient_index_bytes = usize_to_u64_bytes(coefficient_index)?;
    let modulus_bytes = modulus.to_le_bytes();
    let nonzero_residue_count = modulus - 1;
    let accepted_zone = (1_u128 << 64) - ((1_u128 << 64) % u128::from(nonzero_residue_count));

    for block_index in 0..usize::MAX {
        let block_index_bytes = usize_to_u64_bytes(block_index)?;
        let hash_block = hash512(
            DIRECT_BALLOT_SUPPORT_PROJECTION_DOMAIN,
            &[
                statement_hash,
                support_partition.domain_tag(),
                &support_modulus_index_bytes,
                &projection_index_bytes,
                &coefficient_index_bytes,
                &modulus_bytes,
                &block_index_bytes,
            ],
        );
        for candidate_bytes in hash_block.chunks_exact(8) {
            let mut candidate_array = [0_u8; 8];
            candidate_array.copy_from_slice(candidate_bytes);
            let candidate = u64::from_le_bytes(candidate_array);
            if u128::from(candidate) < accepted_zone {
                return Ok((u128::from(candidate) % u128::from(nonzero_residue_count)) as u64 + 1);
            }
        }
    }

    Err(invalid_direct_ballot_relation_proof(
        "direct ballot support projection sampler exhausted its counter space",
    ))
}

pub(super) fn direct_ballot_support_moduli() -> &'static [u64] {
    &DATA_PRIMES[..3]
}
