use super::*;

pub(super) fn sample_direct_ballot_relation_mask_vector(
    statement_hash: &[u8; 64],
    ciphertext_root: &str,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotWitnessVector> {
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            0,
        )?,
        error_zero_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            1,
        )?,
        error_one_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            2,
        )?,
        encoding_carry_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            3,
        )?,
        score_coefficients: sample_direct_ballot_relation_mask_scalars(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            4,
            OPTION_COUNT,
        )?,
        one_hot_coefficients: (0..OPTION_COUNT)
            .map(|option_index| {
                sample_direct_ballot_relation_mask_scalars(
                    statement_hash,
                    ciphertext_root,
                    proof_randomness_seed_hex,
                    5 + option_index,
                    SCORE_BUCKET_COUNT,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

pub(super) fn sample_direct_ballot_relation_mask_scalars(
    statement_hash: &[u8; 64],
    ciphertext_root: &str,
    proof_randomness_seed_hex: &str,
    witness_vector_index: usize,
    scalar_count: usize,
) -> CanonicalResult<Vec<BigInt>> {
    let mut coefficients = Vec::with_capacity(scalar_count);
    let witness_vector_index_bytes = usize_to_u64_bytes(witness_vector_index)?;
    while coefficients.len() < scalar_count {
        let coefficient_index_bytes = usize_to_u64_bytes(coefficients.len())?;
        let block = hash512(
            "sealed-lattice/direct-encrypted-ballot/relation-mask-scalar-v1",
            &[
                statement_hash,
                ciphertext_root.as_bytes(),
                proof_randomness_seed_hex.as_bytes(),
                &witness_vector_index_bytes,
                &coefficient_index_bytes,
            ],
        );
        coefficients.push(direct_ballot_relation_mask_coefficient(&block)?);
    }

    Ok(coefficients)
}

pub(super) fn sample_direct_ballot_relation_mask_polynomial(
    statement_hash: &[u8; 64],
    ciphertext_root: &str,
    proof_randomness_seed_hex: &str,
    witness_polynomial_index: usize,
) -> CanonicalResult<Vec<BigInt>> {
    let mut coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let witness_polynomial_index_bytes = usize_to_u64_bytes(witness_polynomial_index)?;
    while coefficients.len() < POLYNOMIAL_DEGREE {
        let coefficient_index_bytes = usize_to_u64_bytes(coefficients.len())?;
        let block = hash512(
            "sealed-lattice/direct-encrypted-ballot/relation-mask-v1",
            &[
                statement_hash,
                ciphertext_root.as_bytes(),
                proof_randomness_seed_hex.as_bytes(),
                &witness_polynomial_index_bytes,
                &coefficient_index_bytes,
            ],
        );
        coefficients.push(direct_ballot_relation_mask_coefficient(&block)?);
    }

    Ok(coefficients)
}

pub(super) fn direct_ballot_relation_mask_coefficient(block: &[u8; 64]) -> CanonicalResult<BigInt> {
    let magnitude_byte_count = RELATION_MASK_COEFFICIENT_BITS.div_ceil(8);
    if magnitude_byte_count >= block.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation mask coefficient needs more hash material",
        ));
    }
    let mut magnitude_bytes = block[..magnitude_byte_count].to_vec();
    let excess_bits = magnitude_byte_count * 8 - RELATION_MASK_COEFFICIENT_BITS;
    if excess_bits > 0 {
        let kept_bits = 8 - excess_bits;
        let mask = (1_u16 << kept_bits) - 1;
        if let Some(last_byte) = magnitude_bytes.last_mut() {
            *last_byte &= u8::try_from(mask).expect("mask fits u8");
        }
    }
    let magnitude = BigInt::from_bytes_le(Sign::Plus, &magnitude_bytes);
    if block[magnitude_byte_count] & 1 == 1 {
        Ok(-magnitude)
    } else {
        Ok(magnitude)
    }
}
