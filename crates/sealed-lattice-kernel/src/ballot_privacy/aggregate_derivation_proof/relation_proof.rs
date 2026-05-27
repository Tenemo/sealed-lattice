use super::*;

pub(super) struct AggregateRelationProofGeneration {
    pub(super) proof_hex: String,
    pub(super) proof_size_bytes: usize,
    pub(super) challenge_hex: String,
    pub(super) relation_commitment_digest: String,
}

pub(crate) struct AggregateRelationProofVerification {
    pub(crate) proof_size_bytes: usize,
    pub(crate) challenge_hex: String,
    pub(crate) relation_commitment_digest: String,
}

pub(super) struct VerifyAggregateRelationProofInput<'a> {
    pub(super) proof_statement: &'a Value,
    pub(super) public_randomness_hex: &'a str,
    pub(super) proof_hex: &'a str,
    pub(super) source_statement_matrix: &'a SparsePolynomialMatrix,
    pub(super) target_vector_coefficients: &'a [Vec<u64>],
    pub(super) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(super) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
}

struct AggregateRelationProofCheck {
    check_index: usize,
    challenge: u64,
    relation_commitment_vector: PolynomialVector,
    response_vector: PolynomialVector,
}

struct ParsedAggregateRelationProof {
    checks: Vec<AggregateRelationProofCheck>,
    proof_size_bytes: usize,
}

pub(super) fn generate_aggregate_relation_proof(
    proof_input: &Value,
    secret_state: &Value,
    prover_randomness_hex: &str,
) -> crate::encoding::CanonicalResult<AggregateRelationProofGeneration> {
    let proof_statement = required_json_field(proof_input, "proofStatement", "proofInput")?;
    let public_randomness_hex =
        required_string_field(proof_input, "publicRandomnessHex", "proofInput")?;
    let statement_digest = required_string_field(
        proof_statement,
        "statementDigest",
        "proofInput.proofStatement",
    )?;
    let parsed_sparse_statement = sparse_matrix_from_sparse_component_statement(proof_statement)
        .map_err(|error| invalid_preflight(error.message))?;
    let source_ring = parsed_sparse_statement.source_statement_matrix.ring();
    let source_witness_coefficients = source_witness_coefficients(secret_state)?;
    let source_witness_vector =
        signed_witness_to_source_vector(source_ring, &source_witness_coefficients)?;
    let target_vector = PolynomialVector::new(
        source_ring,
        parsed_sparse_statement.target_vector_coefficients.clone(),
    )?;
    require_aggregate_relation_satisfied(
        &parsed_sparse_statement.source_statement_matrix,
        &target_vector,
        &source_witness_vector,
    )?;

    let proof_checks = (0..AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT)
        .map(|check_index| {
            let mask_vector = sample_aggregate_mask_vector(
                source_ring,
                parsed_sparse_statement.source_statement_matrix.columns(),
                statement_digest,
                public_randomness_hex,
                prover_randomness_hex,
                check_index,
            )?;
            let relation_commitment_vector = parsed_sparse_statement
                .source_statement_matrix
                .multiply_vector(&mask_vector)?;
            let challenge = aggregate_relation_challenge_scalar(
                statement_digest,
                public_randomness_hex,
                relation_commitment_vector.entries(),
                source_ring.modulus(),
                check_index,
            )?;
            let response_vector = mask_plus_scaled_witness(
                source_ring,
                &mask_vector,
                &source_witness_vector,
                challenge,
            )?;

            Ok(AggregateRelationProofCheck {
                check_index,
                challenge,
                relation_commitment_vector,
                response_vector,
            })
        })
        .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;
    let proof_value =
        aggregate_relation_proof_value(statement_digest, public_randomness_hex, &proof_checks);
    let proof_json = canonical_json(&proof_value)?;
    let relation_commitment_digest = aggregate_relation_commitment_digest(&proof_checks)?;

    Ok(AggregateRelationProofGeneration {
        proof_hex: to_hex(proof_json.as_bytes()),
        proof_size_bytes: proof_json.len(),
        challenge_hex: aggregate_relation_challenge_hex(&proof_checks),
        relation_commitment_digest,
    })
}

pub(super) fn verify_aggregate_relation_proof(
    input: VerifyAggregateRelationProofInput<'_>,
) -> crate::encoding::CanonicalResult<AggregateRelationProofVerification> {
    if input.matrix_coefficient_representation
        != LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus
        || input.target_coefficient_representation
            != LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus
    {
        return Err(invalid_preflight(
            "aggregate derivation proof must use centered source-modulus coefficient representations",
        ));
    }
    let statement_digest = required_string_field(
        input.proof_statement,
        "statementDigest",
        "proofInput.proofStatement",
    )?;
    let source_ring = input.source_statement_matrix.ring();
    let target_vector =
        PolynomialVector::new(source_ring, input.target_vector_coefficients.to_vec())?;
    let parsed_proof = parse_aggregate_relation_proof(
        input.proof_hex,
        statement_digest,
        input.public_randomness_hex,
        source_ring,
        input.source_statement_matrix.rows(),
        input.source_statement_matrix.columns(),
    )?;
    for proof_check in &parsed_proof.checks {
        let recomputed_challenge = aggregate_relation_challenge_scalar(
            statement_digest,
            input.public_randomness_hex,
            proof_check.relation_commitment_vector.entries(),
            source_ring.modulus(),
            proof_check.check_index,
        )?;
        if recomputed_challenge != proof_check.challenge {
            return Err(invalid_preflight(
                "aggregate derivation proof challenge does not match its relation commitment",
            ));
        }
        let response_relation_output = input
            .source_statement_matrix
            .multiply_vector(&proof_check.response_vector)?;
        let scaled_target_vector =
            scale_polynomial_vector(source_ring, &target_vector, proof_check.challenge)?;
        let verification_left = response_relation_output.add(&scaled_target_vector)?;
        if verification_left.entries() != proof_check.relation_commitment_vector.entries() {
            return Err(invalid_preflight(
                "aggregate derivation relation proof response does not satisfy the public statement",
            ));
        }
    }

    Ok(AggregateRelationProofVerification {
        proof_size_bytes: parsed_proof.proof_size_bytes,
        challenge_hex: aggregate_relation_challenge_hex(&parsed_proof.checks),
        relation_commitment_digest: aggregate_relation_commitment_digest(&parsed_proof.checks)?,
    })
}

fn require_aggregate_relation_satisfied(
    source_statement_matrix: &SparsePolynomialMatrix,
    target_vector: &PolynomialVector,
    source_witness_vector: &PolynomialVector,
) -> crate::encoding::CanonicalResult<()> {
    let relation_output = source_statement_matrix
        .multiply_vector(source_witness_vector)?
        .add(target_vector)?;
    if relation_output
        .entries()
        .iter()
        .any(|polynomial| polynomial.iter().any(|coefficient| *coefficient != 0))
    {
        return Err(invalid_preflight(
            "aggregate derivation witness does not satisfy the public relation",
        ));
    }

    Ok(())
}

fn signed_witness_to_source_vector(
    source_ring: PolynomialRing,
    source_witness_coefficients: &[Vec<i64>],
) -> crate::encoding::CanonicalResult<PolynomialVector> {
    let entries = source_witness_coefficients
        .iter()
        .map(|polynomial| {
            if polynomial.len() != source_ring.degree() {
                return Err(invalid_preflight(
                    "aggregate derivation witness polynomial degree does not match the source ring",
                ));
            }
            polynomial
                .iter()
                .map(|coefficient| {
                    positive_mod_i128_local(i128::from(*coefficient), source_ring.modulus())
                })
                .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
        })
        .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(source_ring, entries)
}

fn sample_aggregate_mask_vector(
    source_ring: PolynomialRing,
    vector_length: usize,
    statement_digest: &str,
    public_randomness_hex: &str,
    prover_randomness_hex: &str,
    check_index: usize,
) -> crate::encoding::CanonicalResult<PolynomialVector> {
    let entries = (0..vector_length)
        .map(|column_index| {
            sample_aggregate_mask_polynomial(
                source_ring,
                statement_digest,
                public_randomness_hex,
                prover_randomness_hex,
                check_index,
                column_index,
            )
        })
        .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(source_ring, entries)
}

fn sample_aggregate_mask_polynomial(
    source_ring: PolynomialRing,
    statement_digest: &str,
    public_randomness_hex: &str,
    prover_randomness_hex: &str,
    check_index: usize,
    column_index: usize,
) -> crate::encoding::CanonicalResult<Vec<u64>> {
    let mut coefficients = Vec::with_capacity(source_ring.degree());
    let check_index_bytes = u64_bytes(check_index)?;
    let column_index_bytes = u64_bytes(column_index)?;
    let mut block_index = 0_u64;
    while coefficients.len() < source_ring.degree() {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            "sealed-lattice-root/aggregate-derivation-mask-v1",
            &[
                statement_digest.as_bytes(),
                public_randomness_hex.as_bytes(),
                prover_randomness_hex.as_bytes(),
                &check_index_bytes,
                &column_index_bytes,
                &block_index_bytes,
            ],
        );
        for chunk in block.chunks_exact(8) {
            let mut value_bytes = [0_u8; 8];
            value_bytes.copy_from_slice(chunk);
            if let Some(coefficient) =
                reduce_unbiased_u64(u64::from_le_bytes(value_bytes), source_ring.modulus())
            {
                coefficients.push(coefficient);
            }
            if coefficients.len() == source_ring.degree() {
                break;
            }
        }
        block_index = block_index
            .checked_add(1)
            .ok_or_else(|| invalid_preflight("aggregate derivation mask block index overflowed"))?;
    }

    Ok(coefficients)
}

pub(super) fn aggregate_relation_challenge_scalar(
    statement_digest: &str,
    public_randomness_hex: &str,
    relation_commitment_vector: &[Vec<u64>],
    modulus: u64,
    check_index: usize,
) -> crate::encoding::CanonicalResult<u64> {
    let commitment_value = canonical_polynomial_vector_value(relation_commitment_vector);
    let commitment_json = canonical_json(&commitment_value)?;
    let nonzero_challenge_range = modulus.checked_sub(1).ok_or_else(|| {
        invalid_preflight("aggregate derivation challenge modulus must be greater than one")
    })?;
    let check_index_bytes = u64_bytes(check_index)?;
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let challenge_block = hash512(
            "sealed-lattice-root/aggregate-derivation-proof-challenge-v1",
            &[
                statement_digest.as_bytes(),
                public_randomness_hex.as_bytes(),
                commitment_json.as_bytes(),
                &check_index_bytes,
                &block_index_bytes,
            ],
        );
        for chunk in challenge_block.chunks_exact(8) {
            let mut challenge_bytes = [0_u8; 8];
            challenge_bytes.copy_from_slice(chunk);
            if let Some(challenge) =
                reduce_unbiased_u64(u64::from_le_bytes(challenge_bytes), nonzero_challenge_range)
            {
                return Ok(challenge + 1);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_preflight("aggregate derivation challenge block index overflowed")
        })?;
    }
}

pub(super) fn reduce_unbiased_u64(candidate: u64, modulus: u64) -> Option<u64> {
    if modulus == 0 {
        return None;
    }
    let sample_space_size = u128::from(u64::MAX) + 1;
    let modulus = u128::from(modulus);
    let rejection_threshold = sample_space_size - (sample_space_size % modulus);
    let candidate = u128::from(candidate);
    if candidate >= rejection_threshold {
        return None;
    }

    Some(
        u64::try_from(candidate % modulus)
            .expect("reduced aggregate derivation sample must fit in u64"),
    )
}

fn mask_plus_scaled_witness(
    source_ring: PolynomialRing,
    mask_vector: &PolynomialVector,
    source_witness_vector: &PolynomialVector,
    challenge: u64,
) -> crate::encoding::CanonicalResult<PolynomialVector> {
    if mask_vector.len() != source_witness_vector.len() {
        return Err(invalid_preflight(
            "aggregate derivation mask and witness lengths do not match",
        ));
    }
    let modulus = u128::from(source_ring.modulus());
    let entries = mask_vector
        .entries()
        .iter()
        .zip(source_witness_vector.entries())
        .map(|(mask_polynomial, witness_polynomial)| {
            mask_polynomial
                .iter()
                .zip(witness_polynomial)
                .map(|(mask_coefficient, witness_coefficient)| {
                    let scaled =
                        (u128::from(challenge) * u128::from(*witness_coefficient)) % modulus;
                    u64::try_from((u128::from(*mask_coefficient) + scaled) % modulus).map_err(
                        |_| {
                            invalid_preflight(
                                "aggregate derivation response coefficient overflowed",
                            )
                        },
                    )
                })
                .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
        })
        .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(source_ring, entries)
}

fn scale_polynomial_vector(
    source_ring: PolynomialRing,
    vector: &PolynomialVector,
    scalar: u64,
) -> crate::encoding::CanonicalResult<PolynomialVector> {
    let entries = vector
        .entries()
        .iter()
        .map(|polynomial| source_ring.scale(scalar, polynomial))
        .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(source_ring, entries)
}

fn aggregate_relation_proof_value(
    statement_digest: &str,
    public_randomness_hex: &str,
    proof_checks: &[AggregateRelationProofCheck],
) -> Value {
    json!({
        "objectType": "AggregateDerivationRelationProof",
        "objectVersion": 2,
        "challengeRepetitionCount": AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT,
        "challengeSoundnessBits": AGGREGATE_DERIVATION_CHALLENGE_SOUNDNESS_BITS,
        "publicRandomnessHex": public_randomness_hex,
        "relationChecks": proof_checks.iter().map(|check| json!({
            "challenge": check.challenge.to_string(),
            "checkIndex": check.check_index,
            "relationCommitmentVector": canonical_polynomial_vector_value(check.relation_commitment_vector.entries()),
            "responseVector": canonical_polynomial_vector_value(check.response_vector.entries()),
        })).collect::<Vec<_>>(),
        "statementDigest": statement_digest
    })
}

fn aggregate_relation_challenge_hex(proof_checks: &[AggregateRelationProofCheck]) -> String {
    proof_checks
        .iter()
        .map(|check| format!("{:016x}", check.challenge))
        .collect::<Vec<_>>()
        .join("")
}

fn aggregate_relation_commitment_digest(
    proof_checks: &[AggregateRelationProofCheck],
) -> crate::encoding::CanonicalResult<String> {
    let relation_commitment_vectors = proof_checks
        .iter()
        .map(|check| canonical_polynomial_vector_value(check.relation_commitment_vector.entries()))
        .collect::<Vec<_>>();

    derive_digest(
        "AggregateDerivationComponentDigest",
        &json!({
            "purpose": "aggregate-derivation-relation-commitment-v1",
            "challengeRepetitionCount": AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT,
            "challengeSoundnessBits": AGGREGATE_DERIVATION_CHALLENGE_SOUNDNESS_BITS,
            "relationCommitmentVectors": relation_commitment_vectors
        }),
    )
    .ok_or_else(|| invalid_preflight("aggregate relation commitment digest did not derive"))
}

fn canonical_polynomial_vector_value(entries: &[Vec<u64>]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|polynomial| {
                Value::Array(
                    polynomial
                        .iter()
                        .map(|coefficient| Value::String(coefficient.to_string()))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn parse_aggregate_relation_proof(
    proof_hex: &str,
    statement_digest: &str,
    public_randomness_hex: &str,
    source_ring: PolynomialRing,
    expected_rows: usize,
    expected_columns: usize,
) -> crate::encoding::CanonicalResult<ParsedAggregateRelationProof> {
    if proof_hex.len() / 2 > MAX_AGGREGATE_DERIVATION_RELATION_PROOF_BYTES {
        return Err(invalid_preflight(
            "aggregate derivation proof bytes exceed the supported byte limit",
        ));
    }
    let proof_bytes = decode_hex(proof_hex)?;
    let proof_json = std::str::from_utf8(&proof_bytes)
        .map_err(|_| invalid_preflight("aggregate derivation proof bytes are not UTF-8 JSON"))?;
    let proof_value: Value = serde_json::from_str(proof_json).map_err(|error| {
        invalid_preflight(format!(
            "aggregate derivation proof JSON is malformed: {error}"
        ))
    })?;
    if canonical_json(&proof_value)? != proof_json {
        return Err(invalid_preflight(
            "aggregate derivation proof JSON must use canonical serialization",
        ));
    }
    if string_field(&proof_value, "objectType") != Some("AggregateDerivationRelationProof")
        || u64_object_field(&proof_value, "objectVersion") != Some(2)
        || u64_object_field(&proof_value, "challengeRepetitionCount")
            != Some(AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT as u64)
        || u64_object_field(&proof_value, "challengeSoundnessBits")
            != Some(AGGREGATE_DERIVATION_CHALLENGE_SOUNDNESS_BITS)
        || string_field(&proof_value, "statementDigest") != Some(statement_digest)
        || string_field(&proof_value, "publicRandomnessHex") != Some(public_randomness_hex)
    {
        return Err(invalid_preflight(
            "aggregate derivation proof shell is not bound to the statement",
        ));
    }
    let relation_checks = required_json_field(
        &proof_value,
        "relationChecks",
        "AggregateDerivationRelationProof",
    )?
    .as_array()
    .ok_or_else(|| invalid_preflight("aggregate derivation relationChecks must be an array"))?;
    if relation_checks.len() != AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT {
        return Err(invalid_preflight(
            "aggregate derivation proof relation check count does not match its soundness profile",
        ));
    }
    let checks = relation_checks
        .iter()
        .enumerate()
        .map(|(expected_check_index, proof_check)| {
            if u64_object_field(proof_check, "checkIndex")
                != Some(
                    u64::try_from(expected_check_index)
                        .expect("aggregate derivation check index fits u64"),
                )
            {
                return Err(invalid_preflight(
                    "aggregate derivation proof check index is not canonical",
                ));
            }
            let challenge = parse_canonical_u64_decimal(
                string_field(proof_check, "challenge").ok_or_else(|| {
                    invalid_preflight("aggregate derivation proof challenge is required")
                })?,
                source_ring.modulus(),
            )?;
            if challenge == 0 {
                return Err(invalid_preflight(
                    "aggregate derivation proof challenge must be nonzero",
                ));
            }
            let relation_commitment_vector = parse_polynomial_vector_value(
                required_json_field(
                    proof_check,
                    "relationCommitmentVector",
                    "AggregateDerivationRelationProof.relationChecks",
                )?,
                source_ring,
                expected_rows,
                "aggregate derivation relation commitment",
            )?;
            let response_vector = parse_polynomial_vector_value(
                required_json_field(
                    proof_check,
                    "responseVector",
                    "AggregateDerivationRelationProof.relationChecks",
                )?,
                source_ring,
                expected_columns,
                "aggregate derivation response",
            )?;

            Ok(AggregateRelationProofCheck {
                check_index: expected_check_index,
                challenge,
                relation_commitment_vector,
                response_vector,
            })
        })
        .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;

    Ok(ParsedAggregateRelationProof {
        checks,
        proof_size_bytes: proof_bytes.len(),
    })
}

fn parse_polynomial_vector_value(
    value: &Value,
    source_ring: PolynomialRing,
    expected_length: usize,
    label: &str,
) -> crate::encoding::CanonicalResult<PolynomialVector> {
    let array = value
        .as_array()
        .ok_or_else(|| invalid_preflight(format!("{label} must be an array")))?;
    if array.len() != expected_length {
        return Err(invalid_preflight(format!(
            "{label} length does not match the statement"
        )));
    }
    let entries = array
        .iter()
        .map(|polynomial_value| {
            let polynomial_array = polynomial_value
                .as_array()
                .ok_or_else(|| invalid_preflight(format!("{label} polynomial must be an array")))?;
            if polynomial_array.len() != source_ring.degree() {
                return Err(invalid_preflight(format!(
                    "{label} polynomial degree does not match the source ring"
                )));
            }
            polynomial_array
                .iter()
                .map(|coefficient_value| {
                    let coefficient = coefficient_value.as_str().ok_or_else(|| {
                        invalid_preflight(format!("{label} coefficient must be a decimal string"))
                    })?;
                    parse_canonical_u64_decimal(coefficient, source_ring.modulus())
                })
                .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
        })
        .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(source_ring, entries)
}

fn parse_canonical_u64_decimal(value: &str, modulus: u64) -> crate::encoding::CanonicalResult<u64> {
    if !unsigned_decimal_string(value) {
        return Err(invalid_preflight(
            "aggregate derivation proof coefficient is not a canonical decimal string",
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_| {
        invalid_preflight("aggregate derivation proof coefficient does not fit in u64")
    })?;
    if parsed >= modulus {
        return Err(invalid_preflight(
            "aggregate derivation proof coefficient is outside the source modulus",
        ));
    }

    Ok(parsed)
}

fn positive_mod_i128_local(value: i128, modulus: u64) -> crate::encoding::CanonicalResult<u64> {
    let modulus_value = i128::from(modulus);
    let mut reduced = value % modulus_value;
    if reduced < 0 {
        reduced += modulus_value;
    }

    u64::try_from(reduced)
        .map_err(|_| invalid_preflight("aggregate derivation reduced coefficient overflowed"))
}

fn u64_bytes(value: usize) -> crate::encoding::CanonicalResult<[u8; 8]> {
    Ok(u64::try_from(value)
        .map_err(|_| invalid_preflight("aggregate derivation index does not fit in u64"))?
        .to_le_bytes())
}
