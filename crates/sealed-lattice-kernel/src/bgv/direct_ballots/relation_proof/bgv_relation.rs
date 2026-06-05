use super::*;

pub(super) fn evaluate_direct_ballot_bgv_relation_commitments(
    evaluator_key: &DevelopmentBgvKey,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<DirectBallotBgvRelationCommitment>> {
    let (public_component_zero, public_component_one) = evaluator_key.public_key_components();
    if public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof requires a full BGV public key",
        ));
    }
    let score_encoding_basis = direct_ballot_score_encoding_basis()?;
    DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(limb_index, modulus)| {
            evaluate_direct_ballot_bgv_relation_commitment(
                &public_component_zero[limb_index],
                &public_component_one[limb_index],
                witness_vector,
                score_encoding_basis,
                modulus,
            )
        })
        .collect()
}

pub(super) fn evaluate_direct_ballot_bgv_relation_commitment(
    public_component_zero: &[u64],
    public_component_one: &[u64],
    witness_vector: &DirectBallotWitnessVector,
    score_encoding_basis: &[Vec<u64>],
    modulus: u64,
) -> CanonicalResult<DirectBallotBgvRelationCommitment> {
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    if public_component_zero.len() != POLYNOMIAL_DEGREE
        || public_component_one.len() != POLYNOMIAL_DEGREE
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof public key limbs must match the polynomial degree",
        ));
    }
    let randomizer_residues = signed_polynomial_residues(
        &witness_vector.randomizer_coefficients,
        modulus,
        "direct ballot relation randomizer",
    )?;
    let public_key_product = negacyclic_mul(public_component_zero, &randomizer_residues, modulus)?;
    let public_sample_product =
        negacyclic_mul(public_component_one, &randomizer_residues, modulus)?;
    let mut component_zero = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut component_one = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let scaled_error_zero = scaled_signed_residue(
            &witness_vector.error_zero_coefficients[coefficient_index],
            PLAINTEXT_MODULUS,
            modulus,
        )?;
        let plaintext_residue = encoded_score_with_carry_residue(
            witness_vector,
            score_encoding_basis,
            coefficient_index,
            modulus,
        )?;
        component_zero.push(add_mod(
            add_mod(
                public_key_product[coefficient_index],
                scaled_error_zero,
                modulus,
            )?,
            plaintext_residue,
            modulus,
        )?);

        let scaled_error_one = scaled_signed_residue(
            &witness_vector.error_one_coefficients[coefficient_index],
            PLAINTEXT_MODULUS,
            modulus,
        )?;
        component_one.push(add_mod(
            public_sample_product[coefficient_index],
            scaled_error_one,
            modulus,
        )?);
    }

    Ok(DirectBallotBgvRelationCommitment {
        component_zero,
        component_one,
    })
}

pub(super) fn encoded_score_with_carry_residue(
    witness_vector: &DirectBallotWitnessVector,
    score_encoding_basis: &[Vec<u64>],
    coefficient_index: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    if score_encoding_basis.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot score encoding basis has the wrong option count",
        ));
    }
    let mut coefficient = -BigInt::from(PLAINTEXT_MODULUS)
        * &witness_vector.encoding_carry_coefficients[coefficient_index];
    for (score, basis_polynomial) in witness_vector
        .score_coefficients
        .iter()
        .zip(score_encoding_basis.iter())
    {
        if basis_polynomial.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot score encoding basis has the wrong polynomial degree",
            ));
        }
        coefficient += score * BigInt::from(basis_polynomial[coefficient_index]);
    }
    signed_bigint_residue(&coefficient, modulus)
}

pub(super) fn verify_direct_ballot_relation_response(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
    challenge: &BigInt,
    bgv_relation_commitments: &[DirectBallotBgvRelationCommitment],
    score_linear_commitment: &DirectBallotScoreLinearCommitment,
    support_commitment: &DirectBallotSupportCommitment,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    if bgv_relation_commitments.len() != DATA_PRIMES.len()
        || ballot.ciphertext.components.len() != 2
        || ballot.ciphertext.components[0].len() != DATA_PRIMES.len()
        || ballot.ciphertext.components[1].len() != DATA_PRIMES.len()
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof verification requires a full ciphertext and commitment set",
        ));
    }
    let response_relation =
        evaluate_direct_ballot_bgv_relation_commitments(evaluator_key, response_vector)?;
    verify_direct_ballot_score_linear_response(
        challenge,
        score_linear_commitment,
        response_vector,
    )?;
    verify_direct_ballot_support_response(challenge, support_commitment, response_vector)?;
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        if bgv_relation_commitments[limb_index].component_zero.len() != POLYNOMIAL_DEGREE
            || bgv_relation_commitments[limb_index].component_one.len() != POLYNOMIAL_DEGREE
            || response_relation[limb_index].component_zero.len() != POLYNOMIAL_DEGREE
            || response_relation[limb_index].component_one.len() != POLYNOMIAL_DEGREE
        {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot relation proof limb vectors must match the polynomial degree",
            ));
        }
        let challenge_residue = challenge_residue(challenge, modulus)?;
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            let scaled_ciphertext_zero = mul_mod(
                challenge_residue,
                ballot.ciphertext.components[0][limb_index][coefficient_index],
                modulus,
            )?;
            let checked_component_zero = sub_mod(
                response_relation[limb_index].component_zero[coefficient_index],
                scaled_ciphertext_zero,
                modulus,
            )?;
            if checked_component_zero
                != bgv_relation_commitments[limb_index].component_zero[coefficient_index]
            {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot relation proof limb {limb_index} c0 response does not match the public statement"
                )));
            }

            let scaled_ciphertext_one = mul_mod(
                challenge_residue,
                ballot.ciphertext.components[1][limb_index][coefficient_index],
                modulus,
            )?;
            let checked_component_one = sub_mod(
                response_relation[limb_index].component_one[coefficient_index],
                scaled_ciphertext_one,
                modulus,
            )?;
            if checked_component_one
                != bgv_relation_commitments[limb_index].component_one[coefficient_index]
            {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot relation proof limb {limb_index} c1 response does not match the public statement"
                )));
            }
        }
    }

    Ok(())
}
