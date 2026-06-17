use super::*;

pub(super) fn parse_direct_ballot_relation_proof(
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
) -> CanonicalResult<ParsedDirectBallotRelationProof> {
    let expected_size = DIRECT_BALLOT_RELATION_PROOF_MAGIC.len()
        + expected_statement_hash.len()
        + DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES
        + direct_ballot_relation_commitment_bytes()
        + direct_ballot_relation_response_bytes();
    if proof_bytes.len() != expected_size {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof bytes do not match the expected size",
        ));
    }
    let mut cursor = 0_usize;
    if &proof_bytes[..DIRECT_BALLOT_RELATION_PROOF_MAGIC.len()]
        != DIRECT_BALLOT_RELATION_PROOF_MAGIC
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof has the wrong format marker",
        ));
    }
    cursor += DIRECT_BALLOT_RELATION_PROOF_MAGIC.len();
    let statement_hash = read_hash(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof is not bound to this statement",
        ));
    }
    let challenge = read_challenge(proof_bytes, &mut cursor)?;
    if challenge.is_zero() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof challenge is outside the expected range",
        ));
    }
    let (bgv_relation_commitments, score_linear_commitment, support_commitment) =
        read_direct_ballot_relation_commitments(proof_bytes, &mut cursor)?;
    let encoded_commitments = encode_direct_ballot_relation_commitments(
        &bgv_relation_commitments,
        &score_linear_commitment,
        &support_commitment,
    )?;
    let relation_commitment_hash =
        direct_ballot_relation_commitment_hash(expected_statement_hash, &encoded_commitments);
    let recomputed_challenge =
        direct_ballot_relation_challenge(expected_statement_hash, &relation_commitment_hash)?;
    if challenge != recomputed_challenge {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof challenge does not match its commitment",
        ));
    }
    let response_vector = read_direct_ballot_relation_response(proof_bytes, &mut cursor)?;
    if cursor != proof_bytes.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof has trailing bytes",
        ));
    }

    Ok(ParsedDirectBallotRelationProof {
        challenge,
        bgv_relation_commitments,
        score_linear_commitment,
        support_commitment,
        response_vector,
        relation_commitment_hash,
    })
}

pub(super) fn encode_direct_ballot_relation_proof(
    statement_hash: &[u8; 64],
    challenge: &BigInt,
    encoded_commitments: &[u8],
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<u8>> {
    let mut proof_bytes = Vec::with_capacity(
        DIRECT_BALLOT_RELATION_PROOF_MAGIC.len()
            + statement_hash.len()
            + DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES
            + encoded_commitments.len()
            + direct_ballot_relation_response_bytes(),
    );
    proof_bytes.extend_from_slice(DIRECT_BALLOT_RELATION_PROOF_MAGIC);
    proof_bytes.extend_from_slice(statement_hash);
    append_challenge(&mut proof_bytes, challenge)?;
    proof_bytes.extend_from_slice(encoded_commitments);
    encode_direct_ballot_relation_response(&mut proof_bytes, response_vector)?;

    Ok(proof_bytes)
}

pub(super) fn encode_direct_ballot_relation_commitments(
    bgv_relation_commitments: &[DirectBallotBgvRelationCommitment],
    score_linear_commitment: &DirectBallotScoreLinearCommitment,
    support_commitment: &DirectBallotSupportCommitment,
) -> CanonicalResult<Vec<u8>> {
    if bgv_relation_commitments.len() != DATA_PRIMES.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof commitment count must match the data-prime count",
        ));
    }
    let mut encoded = Vec::with_capacity(direct_ballot_relation_commitment_bytes());
    for (limb_index, (commitment, modulus)) in bgv_relation_commitments
        .iter()
        .zip(DATA_PRIMES.iter())
        .enumerate()
    {
        encode_residue_polynomial(
            &mut encoded,
            &commitment.component_zero,
            *modulus,
            limb_index,
            "c0",
        )?;
        encode_residue_polynomial(
            &mut encoded,
            &commitment.component_one,
            *modulus,
            limb_index,
            "c1",
        )?;
    }
    encode_score_linear_commitment(&mut encoded, score_linear_commitment)?;
    encode_support_commitment(&mut encoded, support_commitment)?;

    Ok(encoded)
}

pub(super) fn encode_score_linear_commitment(
    output: &mut Vec<u8>,
    commitment: &DirectBallotScoreLinearCommitment,
) -> CanonicalResult<()> {
    if commitment.bucket_sums.len() != DIRECT_BALLOT_OPTION_COUNT
        || commitment.weighted_differences.len() != DIRECT_BALLOT_OPTION_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot score linear commitment has the wrong option count",
        ));
    }
    for value in commitment
        .bucket_sums
        .iter()
        .chain(commitment.weighted_differences.iter())
    {
        if *value >= PLAINTEXT_MODULUS {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot score linear commitment is not canonical",
            ));
        }
        append_u64(output, *value);
    }

    Ok(())
}

pub(super) fn encode_support_commitment(
    output: &mut Vec<u8>,
    commitment: &DirectBallotSupportCommitment,
) -> CanonicalResult<()> {
    validate_direct_ballot_support_commitment_shape(commitment)?;
    for value in commitment
        .one_hot_booleanity
        .iter()
        .chain(commitment.randomizer_support.iter())
        .chain(commitment.error_zero_support.iter())
        .chain(commitment.error_one_support.iter())
    {
        append_u64(output, *value);
    }

    Ok(())
}

pub(super) fn encode_residue_polynomial(
    output: &mut Vec<u8>,
    polynomial: &[u64],
    modulus: u64,
    limb_index: usize,
    component_label: &str,
) -> CanonicalResult<()> {
    if polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot relation proof commitment limb {limb_index} {component_label} has the wrong degree"
        )));
    }
    for coefficient in polynomial {
        if *coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot relation proof commitment limb {limb_index} {component_label} has a non-canonical coefficient"
            )));
        }
        append_u64(output, *coefficient);
    }

    Ok(())
}

pub(super) fn read_direct_ballot_relation_commitments(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<(
    Vec<DirectBallotBgvRelationCommitment>,
    DirectBallotScoreLinearCommitment,
    DirectBallotSupportCommitment,
)> {
    let bgv_commitments = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            Ok(DirectBallotBgvRelationCommitment {
                component_zero: read_residue_polynomial(proof_bytes, cursor, modulus)?,
                component_one: read_residue_polynomial(proof_bytes, cursor, modulus)?,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let score_linear_commitment = read_score_linear_commitment(proof_bytes, cursor)?;
    let support_commitment = read_support_commitment(proof_bytes, cursor)?;

    Ok((bgv_commitments, score_linear_commitment, support_commitment))
}

pub(super) fn read_score_linear_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotScoreLinearCommitment> {
    let bucket_sums = read_residue_scalars(
        proof_bytes,
        cursor,
        PLAINTEXT_MODULUS,
        DIRECT_BALLOT_OPTION_COUNT,
    )?;
    let weighted_differences = read_residue_scalars(
        proof_bytes,
        cursor,
        PLAINTEXT_MODULUS,
        DIRECT_BALLOT_OPTION_COUNT,
    )?;

    Ok(DirectBallotScoreLinearCommitment {
        bucket_sums,
        weighted_differences,
    })
}

pub(super) fn read_support_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotSupportCommitment> {
    let modulus = direct_ballot_support_modulus();
    Ok(DirectBallotSupportCommitment {
        one_hot_booleanity: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            DIRECT_BALLOT_OPTION_COUNT
                * DIRECT_BALLOT_SCORE_BUCKET_COUNT
                * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
        randomizer_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
        error_zero_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
        error_one_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
    })
}

pub(super) fn read_residue_scalars(
    proof_bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
    scalar_count: usize,
) -> CanonicalResult<Vec<u64>> {
    let mut scalars = Vec::with_capacity(scalar_count);
    for _ in 0..scalar_count {
        let scalar = read_u64(proof_bytes, cursor)?;
        if scalar >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot relation proof scalar commitment is not canonical",
            ));
        }
        scalars.push(scalar);
    }

    Ok(scalars)
}

pub(super) fn read_residue_polynomial(
    proof_bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut polynomial = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for _ in 0..POLYNOMIAL_DEGREE {
        let coefficient = read_u64(proof_bytes, cursor)?;
        if coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot relation proof commitment coefficient is not canonical",
            ));
        }
        polynomial.push(coefficient);
    }

    Ok(polynomial)
}

pub(super) fn encode_direct_ballot_relation_response(
    output: &mut Vec<u8>,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    validate_direct_ballot_witness_vector_shape(response_vector)?;
    for polynomial in direct_ballot_witness_polynomials(response_vector) {
        for coefficient in polynomial {
            append_signed_bigint_fixed(output, coefficient)?;
        }
    }
    for coefficient in &response_vector.score_coefficients {
        append_signed_bigint_fixed(output, coefficient)?;
    }
    for row in &response_vector.one_hot_coefficients {
        for coefficient in row {
            append_signed_bigint_fixed(output, coefficient)?;
        }
    }

    Ok(())
}

pub(super) fn read_direct_ballot_relation_response(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotWitnessVector> {
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        error_zero_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        error_one_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        encoding_carry_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        score_coefficients: read_signed_scalars(proof_bytes, cursor, DIRECT_BALLOT_OPTION_COUNT)?,
        one_hot_coefficients: (0..DIRECT_BALLOT_OPTION_COUNT)
            .map(|_| read_signed_scalars(proof_bytes, cursor, DIRECT_BALLOT_SCORE_BUCKET_COUNT))
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

pub(super) fn read_signed_polynomial(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<Vec<BigInt>> {
    let mut polynomial = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for _ in 0..POLYNOMIAL_DEGREE {
        polynomial.push(read_signed_bigint_fixed(proof_bytes, cursor)?);
    }

    Ok(polynomial)
}

pub(super) fn read_signed_scalars(
    proof_bytes: &[u8],
    cursor: &mut usize,
    scalar_count: usize,
) -> CanonicalResult<Vec<BigInt>> {
    let mut scalars = Vec::with_capacity(scalar_count);
    for _ in 0..scalar_count {
        scalars.push(read_signed_bigint_fixed(proof_bytes, cursor)?);
    }

    Ok(scalars)
}

pub(super) fn direct_ballot_relation_commitment_hash(
    statement_hash: &[u8; 64],
    encoded_commitments: &[u8],
) -> [u8; 64] {
    hash512(
        "sealed-lattice/direct-encrypted-ballot/relation-commitment-v1",
        &[statement_hash, encoded_commitments],
    )
}

pub(super) fn validate_direct_ballot_support_commitment_shape(
    commitment: &DirectBallotSupportCommitment,
) -> CanonicalResult<()> {
    let expected_one_hot_scalars = DIRECT_BALLOT_OPTION_COUNT
        * DIRECT_BALLOT_SCORE_BUCKET_COUNT
        * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS;
    let expected_randomizer_scalars =
        POLYNOMIAL_DEGREE * DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS;
    let expected_error_scalars =
        POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS;
    if commitment.one_hot_booleanity.len() != expected_one_hot_scalars
        || commitment.randomizer_support.len() != expected_randomizer_scalars
        || commitment.error_zero_support.len() != expected_error_scalars
        || commitment.error_one_support.len() != expected_error_scalars
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment has the wrong shape",
        ));
    }
    let modulus = direct_ballot_support_modulus();
    if commitment
        .one_hot_booleanity
        .iter()
        .chain(commitment.randomizer_support.iter())
        .chain(commitment.error_zero_support.iter())
        .chain(commitment.error_one_support.iter())
        .any(|coefficient| *coefficient >= modulus)
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment is not canonical",
        ));
    }

    Ok(())
}

pub(super) fn signed_polynomial_residues(
    polynomial: &[BigInt],
    modulus: u64,
    label: &str,
) -> CanonicalResult<Vec<u64>> {
    if polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must match the polynomial degree"
        )));
    }
    polynomial
        .iter()
        .map(|coefficient| signed_bigint_residue(coefficient, modulus))
        .collect()
}

pub(super) fn scaled_signed_residue(
    coefficient: &BigInt,
    scalar: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    mul_mod(
        signed_bigint_residue(coefficient, modulus)?,
        scalar % modulus,
        modulus,
    )
}

pub(super) fn signed_bigint_residue(coefficient: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_bigint = BigInt::from(modulus);
    let residue = ((coefficient % &modulus_bigint) + &modulus_bigint) % &modulus_bigint;
    let (_, bytes) = residue.to_bytes_le();
    let mut output = 0_u64;
    for (byte_index, byte) in bytes.iter().enumerate() {
        let shift = byte_index.checked_mul(8).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot signed residue byte shift overflowed",
            )
        })?;
        if shift >= 64 {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot signed residue does not fit in the modulus type",
            ));
        }
        output |= u64::from(*byte) << shift;
    }
    if output >= modulus {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot signed residue is not canonical",
        ));
    }
    Ok(output)
}

pub(super) fn challenge_residue(challenge: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    signed_bigint_residue(challenge, modulus)
}

pub(super) fn validate_signed_bigint_fixed_width(
    value: &BigInt,
    label: &str,
) -> CanonicalResult<()> {
    let bytes = value.to_signed_bytes_le();
    if bytes.len() > DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} does not fit in the fixed response encoding"
        )));
    }
    Ok(())
}

pub(super) fn append_signed_bigint_fixed(
    output: &mut Vec<u8>,
    value: &BigInt,
) -> CanonicalResult<()> {
    validate_signed_bigint_fixed_width(value, "direct ballot relation response coefficient")?;
    let mut bytes = value.to_signed_bytes_le();
    let sign_extension = if value.sign() == Sign::Minus {
        0xff
    } else {
        0x00
    };
    bytes.resize(
        DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
        sign_extension,
    );
    output.extend_from_slice(&bytes);
    Ok(())
}

pub(super) fn read_signed_bigint_fixed(
    input: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<BigInt> {
    let end = cursor
        .checked_add(DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES)
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof("direct ballot relation proof cursor overflowed")
        })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof ended early")
    })?;
    *cursor = end;
    Ok(BigInt::from_signed_bytes_le(bytes))
}

pub(super) fn append_challenge(output: &mut Vec<u8>, challenge: &BigInt) -> CanonicalResult<()> {
    if challenge.sign() == Sign::Minus || challenge.is_zero() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation challenge is outside the expected range",
        ));
    }
    let (_, mut bytes) = challenge.to_bytes_le();
    if bytes.len() > DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation challenge does not fit its encoding",
        ));
    }
    bytes.resize(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES, 0);
    output.extend_from_slice(&bytes);
    Ok(())
}

pub(super) fn read_challenge(input: &[u8], cursor: &mut usize) -> CanonicalResult<BigInt> {
    let end = cursor
        .checked_add(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES)
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof("direct ballot relation proof cursor overflowed")
        })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof ended early")
    })?;
    *cursor = end;
    Ok(BigInt::from_bytes_le(Sign::Plus, bytes))
}

pub(super) fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn read_hash(input: &[u8], cursor: &mut usize) -> CanonicalResult<[u8; 64]> {
    let end = cursor.checked_add(64).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof cursor overflowed")
    })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof ended early")
    })?;
    let mut hash = [0_u8; 64];
    hash.copy_from_slice(bytes);
    *cursor = end;
    Ok(hash)
}

pub(super) fn read_u64(input: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed_bytes::<8>(input, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn read_fixed_bytes<const LENGTH: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor.checked_add(LENGTH).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof cursor overflowed")
    })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof ended early")
    })?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

pub(super) fn usize_to_u64_bytes(value: usize) -> CanonicalResult<[u8; 8]> {
    Ok(u64::try_from(value)
        .map_err(|_| {
            invalid_direct_ballot_relation_proof(
                "direct ballot relation proof index does not fit in u64",
            )
        })?
        .to_le_bytes())
}

pub(super) fn ceil_log2_usize(value: usize) -> u32 {
    if value <= 1 {
        0
    } else {
        usize::BITS - (value - 1).leading_zeros()
    }
}

pub(super) fn invalid_direct_ballot_relation_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
