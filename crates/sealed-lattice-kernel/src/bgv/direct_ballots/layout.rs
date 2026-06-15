use super::*;

const DIRECT_BALLOT_RESERVED_SLOT_RULE_OBJECT_TYPE: &str = "DirectBallotReservedSlotRule";
const DIRECT_BALLOT_ENCODER_MATRIX_OBJECT_TYPE: &str = "DirectBallotEncoderMatrix";
const DIRECT_BALLOT_ENCODER_BASIS_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/encoder-basis-vector-hash-v1";

pub(crate) fn direct_ballot_reserved_slot_rule_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": DIRECT_BALLOT_RESERVED_SLOT_RULE_OBJECT_TYPE,
        "objectVersion": 1,
        "slotRule": "score slots occupy the first twenty slots; every slot from optionCount through polynomialDegree minus one must be zero",
        "optionCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreSlotCount": DIRECT_BALLOT_OPTION_COUNT,
        "reservedSlotStartInclusive": DIRECT_BALLOT_OPTION_COUNT,
        "reservedSlotEndExclusive": POLYNOMIAL_DEGREE,
        "reservedSlotCount": POLYNOMIAL_DEGREE - DIRECT_BALLOT_OPTION_COUNT,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "polynomialDegree": POLYNOMIAL_DEGREE,
    }))
}

pub(crate) fn direct_ballot_reserved_slot_rule_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "DirectBallotReservedSlotRuleHash",
        &direct_ballot_reserved_slot_rule_value()?,
    )
}

pub(crate) fn direct_ballot_encoder_matrix_value() -> CanonicalResult<Value> {
    let basis_vector_hashes = (0..DIRECT_BALLOT_OPTION_COUNT)
        .map(|option_index| {
            let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
            slots[option_index] = 1;
            let basis_coefficients = encode_slots_to_coefficients(&slots)?;
            let basis_vector_hash =
                direct_ballot_encoder_basis_vector_hash(option_index, &basis_coefficients)?;
            Ok(json!({
                "optionIndex": option_index,
                "sourceSlotIndex": option_index,
                "basisVectorHash": basis_vector_hash,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "objectType": DIRECT_BALLOT_ENCODER_MATRIX_OBJECT_TYPE,
        "objectVersion": 1,
        "encoderId": BATCH_ENCODER_ID,
        "profileHash": profile_hash()?,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "optionCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreSlotCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreDomain": {
            "minimum": DIRECT_BALLOT_MINIMUM_SCORE,
            "maximum": DIRECT_BALLOT_MAXIMUM_SCORE,
            "bucketCount": DIRECT_BALLOT_SCORE_BUCKET_COUNT,
        },
        "reservedSlotRuleHash": direct_ballot_reserved_slot_rule_hash()?,
        "basisVectorHashDomain": DIRECT_BALLOT_ENCODER_BASIS_VECTOR_HASH_DOMAIN,
        "basisVectorHashes": basis_vector_hashes,
    }))
}

pub(crate) fn direct_ballot_encoder_matrix_root() -> CanonicalResult<String> {
    derive_protocol_hash(
        "DirectBallotEncoderMatrixRoot",
        &direct_ballot_encoder_matrix_value()?,
    )
}

fn direct_ballot_encoder_basis_vector_hash(
    option_index: usize,
    coefficients: &[u64],
) -> CanonicalResult<String> {
    if option_index >= DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct ballot encoder basis vector option index is outside the active option range",
        ));
    }
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct ballot encoder basis vector must match the polynomial degree",
        ));
    }
    let mut bytes = Vec::with_capacity(32 + coefficients.len() * 8);
    append_varuint(&mut bytes, usize_to_u64(option_index, "option index")?);
    append_varuint(
        &mut bytes,
        usize_to_u64(POLYNOMIAL_DEGREE, "polynomial degree")?,
    );
    append_varuint(&mut bytes, PLAINTEXT_MODULUS);
    for coefficient in coefficients {
        if *coefficient >= PLAINTEXT_MODULUS {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct ballot encoder basis vector has a coefficient outside the plaintext field",
            ));
        }
        bytes.extend_from_slice(&coefficient.to_le_bytes());
    }

    Ok(hash512_hex(
        DIRECT_BALLOT_ENCODER_BASIS_VECTOR_HASH_DOMAIN,
        &[bytes.as_slice()],
    ))
}
