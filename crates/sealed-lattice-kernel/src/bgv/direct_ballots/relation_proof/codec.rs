use super::*;

pub(super) fn parse_direct_ballot_relation_proof(
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
) -> CanonicalResult<ParsedDirectBallotRelationProof> {
    let expected_size = DIRECT_BALLOT_RELATION_PROOF_MAGIC.len()
        + expected_statement_hash.len()
        + DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES
        + direct_ballot_relation_commitment_bytes()
        + direct_ballot_relation_response_bytes()
        + 8;
    if proof_bytes.len() < expected_size {
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
    let committed_trace_proof_length = usize::try_from(read_u64(proof_bytes, &mut cursor)?)
        .map_err(|_| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed trace proof length does not fit usize",
            )
        })?;
    let committed_trace_proof_end = cursor
        .checked_add(committed_trace_proof_length)
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed trace proof length overflowed",
            )
        })?;
    let committed_trace_proof_bytes = proof_bytes
        .get(cursor..committed_trace_proof_end)
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof("direct ballot relation proof ended early")
        })?
        .to_vec();
    cursor = committed_trace_proof_end;
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
        committed_trace_proof_bytes,
        relation_commitment_hash,
    })
}

pub(super) fn encode_direct_ballot_relation_proof(
    statement_hash: &[u8; 64],
    challenge: &BigInt,
    encoded_commitments: &[u8],
    response_vector: &DirectBallotWitnessVector,
    committed_trace_proof_bytes: &[u8],
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
    append_u64(
        &mut proof_bytes,
        u64::try_from(committed_trace_proof_bytes.len()).map_err(|_| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed trace proof length does not fit u64",
            )
        })?,
    );
    proof_bytes.extend_from_slice(committed_trace_proof_bytes);

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
        encode_projected_bgv_component_commitments(
            &mut encoded,
            &commitment.component_zero,
            *modulus,
            limb_index,
            DirectBallotProjectedBgvComponent::ComponentZero,
        )?;
        encode_projected_bgv_component_commitments(
            &mut encoded,
            &commitment.component_one,
            *modulus,
            limb_index,
            DirectBallotProjectedBgvComponent::ComponentOne,
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

pub(super) fn encode_projected_bgv_component_commitments(
    output: &mut Vec<u8>,
    commitments: &[u64],
    modulus: u64,
    limb_index: usize,
    component: DirectBallotProjectedBgvComponent,
) -> CanonicalResult<()> {
    if commitments.len() != DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot projected BGV commitment limb {limb_index} {} has the wrong projection count",
            component.label()
        )));
    }
    for commitment in commitments {
        if *commitment >= modulus {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot projected BGV commitment limb {limb_index} {} has a non-canonical residue",
                component.label()
            )));
        }
        append_u64(output, *commitment);
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
                component_zero: read_residue_scalars(
                    proof_bytes,
                    cursor,
                    modulus,
                    DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
                )?,
                component_one: read_residue_scalars(
                    proof_bytes,
                    cursor,
                    modulus,
                    DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
                )?,
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
    Ok(DirectBallotSupportCommitment {
        one_hot_booleanity: read_projected_support_commitment(
            proof_bytes,
            cursor,
            DirectBallotSupportKind::OneHot,
        )?,
        randomizer_support: read_projected_support_commitment(
            proof_bytes,
            cursor,
            DirectBallotSupportKind::Randomizer,
        )?,
        error_zero_support: read_projected_support_commitment(
            proof_bytes,
            cursor,
            DirectBallotSupportKind::Error,
        )?,
        error_one_support: read_projected_support_commitment(
            proof_bytes,
            cursor,
            DirectBallotSupportKind::Error,
        )?,
    })
}

fn read_projected_support_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
    support_kind: DirectBallotSupportKind,
) -> CanonicalResult<Vec<u64>> {
    let scalar_count_per_modulus = DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION
        * support_kind.expansion_coefficient_count();
    let mut scalars =
        Vec::with_capacity(direct_ballot_support_moduli().len() * scalar_count_per_modulus);
    for modulus in direct_ballot_support_moduli() {
        scalars.extend(read_residue_scalars(
            proof_bytes,
            cursor,
            *modulus,
            scalar_count_per_modulus,
        )?);
    }

    Ok(scalars)
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
    for coefficient in &response_vector.bgv_no_wrap_carry_scalars {
        append_signed_bigint_fixed_with_width(
            output,
            coefficient,
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
            "direct ballot projected BGV no-wrap carry response",
        )?;
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
        bgv_no_wrap_carry_scalars: read_signed_scalars_with_width(
            proof_bytes,
            cursor,
            direct_ballot_projected_bgv_no_wrap_carry_scalar_count(),
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
        )?,
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
    read_signed_scalars_with_width(
        proof_bytes,
        cursor,
        scalar_count,
        DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
    )
}

pub(super) fn read_signed_scalars_with_width(
    proof_bytes: &[u8],
    cursor: &mut usize,
    scalar_count: usize,
    byte_width: usize,
) -> CanonicalResult<Vec<BigInt>> {
    let mut scalars = Vec::with_capacity(scalar_count);
    for _ in 0..scalar_count {
        scalars.push(read_signed_bigint_fixed_with_width(
            proof_bytes,
            cursor,
            byte_width,
        )?);
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
    let expected_one_hot_scalars =
        projected_support_commitment_scalar_count_for_kind(DirectBallotSupportKind::OneHot);
    let expected_randomizer_scalars =
        projected_support_commitment_scalar_count_for_kind(DirectBallotSupportKind::Randomizer);
    let expected_error_scalars =
        projected_support_commitment_scalar_count_for_kind(DirectBallotSupportKind::Error);
    if commitment.one_hot_booleanity.len() != expected_one_hot_scalars
        || commitment.randomizer_support.len() != expected_randomizer_scalars
        || commitment.error_zero_support.len() != expected_error_scalars
        || commitment.error_one_support.len() != expected_error_scalars
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment has the wrong shape",
        ));
    }
    validate_projected_support_commitment_scalars(
        DirectBallotSupportKind::OneHot,
        &commitment.one_hot_booleanity,
    )?;
    validate_projected_support_commitment_scalars(
        DirectBallotSupportKind::Randomizer,
        &commitment.randomizer_support,
    )?;
    validate_projected_support_commitment_scalars(
        DirectBallotSupportKind::Error,
        &commitment.error_zero_support,
    )?;
    validate_projected_support_commitment_scalars(
        DirectBallotSupportKind::Error,
        &commitment.error_one_support,
    )?;

    Ok(())
}

fn projected_support_commitment_scalar_count_for_kind(
    support_kind: DirectBallotSupportKind,
) -> usize {
    direct_ballot_support_moduli().len()
        * DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION
        * support_kind.expansion_coefficient_count()
}

fn validate_projected_support_commitment_scalars(
    support_kind: DirectBallotSupportKind,
    scalars: &[u64],
) -> CanonicalResult<()> {
    let scalar_count_per_modulus = DIRECT_BALLOT_SUPPORT_PROJECTIONS_PER_PARTITION
        * support_kind.expansion_coefficient_count();
    if scalars.len() != direct_ballot_support_moduli().len() * scalar_count_per_modulus {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment has the wrong shape",
        ));
    }
    for (support_modulus_index, modulus) in direct_ballot_support_moduli().iter().enumerate() {
        let start = support_modulus_index * scalar_count_per_modulus;
        let end = start + scalar_count_per_modulus;
        if scalars[start..end]
            .iter()
            .any(|coefficient| *coefficient >= *modulus)
        {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot support commitment is not canonical",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
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
    byte_width: usize,
    label: &str,
) -> CanonicalResult<()> {
    let bytes = value.to_signed_bytes_le();
    if bytes.len() > byte_width {
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
    append_signed_bigint_fixed_with_width(
        output,
        value,
        DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
        "direct ballot relation response coefficient",
    )
}

pub(super) fn append_signed_bigint_fixed_with_width(
    output: &mut Vec<u8>,
    value: &BigInt,
    byte_width: usize,
    label: &str,
) -> CanonicalResult<()> {
    validate_signed_bigint_fixed_width(value, byte_width, label)?;
    let mut bytes = value.to_signed_bytes_le();
    let sign_extension = if value.sign() == Sign::Minus {
        0xff
    } else {
        0x00
    };
    bytes.resize(byte_width, sign_extension);
    output.extend_from_slice(&bytes);
    Ok(())
}

pub(super) fn read_signed_bigint_fixed(
    input: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<BigInt> {
    read_signed_bigint_fixed_with_width(
        input,
        cursor,
        DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES,
    )
}

pub(super) fn read_signed_bigint_fixed_with_width(
    input: &[u8],
    cursor: &mut usize,
    byte_width: usize,
) -> CanonicalResult<BigInt> {
    let end = cursor.checked_add(byte_width).ok_or_else(|| {
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

pub(super) fn checked_repeated_byte_count(
    byte_count: usize,
    repetitions: u32,
    label: &str,
) -> CanonicalResult<usize> {
    let repetitions = usize::try_from(repetitions).map_err(|_| {
        invalid_direct_ballot_relation_proof(format!("{label} repetition count does not fit usize"))
    })?;

    byte_count
        .checked_mul(repetitions)
        .ok_or_else(|| invalid_direct_ballot_relation_proof(format!("{label} overflowed")))
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
